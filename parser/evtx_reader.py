"""Offline EVTX file parser."""

from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
import logging
import os
from time import monotonic
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Callable, Dict, List, Optional

from models.event_model import NormalizedEvent

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

try:
    import Evtx.Evtx as evtx
    HAS_EVTX = True
except ImportError:
    HAS_EVTX = False


FIELD_ALIASES = {
    "SubjectUserName": ("SubjectUserName",),
    "SubjectDomainName": ("SubjectDomainName",),
    "TargetUserName": ("TargetUserName",),
    "TargetDomainName": ("TargetDomainName",),
    "AccountName": ("AccountName", "ServiceAccount"),
    "LogonUser": ("LogonUser", "TargetOutboundUserName"),
    "IpAddress": ("IpAddress", "ClientAddress", "SourceAddress", "SourceIp"),
    "DestinationIp": ("DestinationIp", "DestinationAddress", "DestAddress"),
    "LogonType": ("LogonType",),
    "Status": ("Status",),
    "SubStatus": ("SubStatus",),
    "ShareName": ("ShareName",),
    "CommandLine": ("CommandLine",),
    "NewProcessName": ("NewProcessName",),
    "ProcessName": ("ProcessName", "Image"),
    "ParentProcessName": ("ParentProcessName", "ParentImage"),
    "ServiceName": ("ServiceName",),
    "ImagePath": ("ImagePath", "ServiceFileName"),
    "TaskName": ("TaskName",),
    "TargetServerName": ("TargetServerName",),
}
DEFAULT_PARSE_WORKERS = 4
PARSE_WORKERS_ENV = "TRIAGE_PARSE_WORKERS"
PARSE_EXECUTOR_ENV = "TRIAGE_PARSE_EXECUTOR"
DEFAULT_PARSE_EXECUTOR = "serial"
RAW_XML_MODE_ENV = "TRIAGE_RAW_XML_MODE"
SQL_RAW_XML_EVENT_IDS = {15281, 15457, 18454, 33205}
ADCS_RAW_XML_EVENT_IDS = {4886, 4887, 4888, 4898, 4899, 4900}
FILE_PROGRESS_RECORD_INTERVAL = 5000
FILE_PROGRESS_SECONDS = 15.0
CHANNEL_PARSE_PRIORITY = (
    ("security.evtx", 0),
    ("sysmon", 1),
    ("powershell", 2),
    ("windowspowershell.evtx", 3),
    ("system.evtx", 4),
    ("defender", 5),
    ("taskscheduler", 6),
    ("wmi", 7),
    ("forwardedevents.evtx", 8),
    ("application.evtx", 99),
)


def _normalize_ip(value: str) -> str:
    text = (value or "").strip()
    if text.lower().startswith("::ffff:"):
        return text[7:]
    return text


def _normalize_event_data(event_data: Dict[str, str]) -> Dict[str, str]:
    normalized = dict(event_data)
    for canonical, aliases in FIELD_ALIASES.items():
        if normalized.get(canonical):
            continue
        for alias in aliases:
            value = (normalized.get(alias) or "").strip()
            if value:
                normalized[canonical] = value
                break

    if normalized.get("IpAddress"):
        normalized["IpAddress"] = _normalize_ip(normalized["IpAddress"])
    if normalized.get("DestinationIp"):
        normalized["DestinationIp"] = _normalize_ip(normalized["DestinationIp"])
    return normalized


def _raw_xml_mode() -> str:
    configured = (os.environ.get(RAW_XML_MODE_ENV, "") or "").strip().lower()
    if configured in {"", "auto"}:
        return "auto"
    if configured in {"all", "none"}:
        return configured
    logging.warning("Ignoring invalid %s=%r", RAW_XML_MODE_ENV, configured)
    return "auto"


def _should_preserve_raw_xml(event_id: int, provider: str) -> bool:
    mode = _raw_xml_mode()
    if mode == "all":
        return True
    if mode == "none":
        return False

    provider_name = (provider or "").lower()
    if event_id in SQL_RAW_XML_EVENT_IDS and "mssql" in provider_name:
        return True
    if event_id in ADCS_RAW_XML_EVENT_IDS:
        return True
    return False


def _file_priority(filepath: str) -> tuple[int, str, str]:
    basename = os.path.basename(filepath).lower()
    priority = 50
    for marker, marker_priority in CHANNEL_PARSE_PRIORITY:
        if basename == marker or marker in basename:
            priority = marker_priority
            break
    return priority, basename, filepath.lower()


def _parse_record(record_xml: str) -> Optional[NormalizedEvent]:
    """Parse a single EVTX XML record into a NormalizedEvent."""
    try:
        root = ET.fromstring(record_xml)
    except ET.ParseError:
        return None

    system = root.find(f"{NS}System")
    if system is None:
        return None

    eid_el = system.find(f"{NS}EventID")
    if eid_el is None:
        return None
    try:
        event_id = int(eid_el.text)
    except (ValueError, TypeError):
        return None

    tc = system.find(f"{NS}TimeCreated")
    ts_str = tc.get("SystemTime", "") if tc is not None else ""
    timestamp = None
    try:
        if ts_str.endswith("Z"):
            timestamp = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        elif ts_str:
            timestamp = datetime.fromisoformat(ts_str)
    except (ValueError, TypeError):
        pass

    comp_el = system.find(f"{NS}Computer")
    computer = comp_el.text if comp_el is not None and comp_el.text else ""

    chan_el = system.find(f"{NS}Channel")
    channel = chan_el.text if chan_el is not None and chan_el.text else ""

    prov_el = system.find(f"{NS}Provider")
    provider = prov_el.get("Name", "") if prov_el is not None else ""

    event_data = {}
    ed_el = root.find(f"{NS}EventData")
    if ed_el is not None:
        unnamed_values = []
        for d in ed_el.findall(f"{NS}Data"):
            name = d.get("Name", "")
            val = d.text or ""
            if name:
                event_data[name] = val
            elif val:
                unnamed_values.append(val)
        if unnamed_values:
            event_data["EventDataText"] = "\n".join(unnamed_values)
            for index, value in enumerate(unnamed_values, start=1):
                event_data[f"Data_{index}"] = value

    ud_el = root.find(f"{NS}UserData")
    if ud_el is not None:
        for child in ud_el:
            for f_el in child:
                tag = f_el.tag.split("}", 1)[-1] if "}" in f_el.tag else f_el.tag
                if f_el.text:
                    event_data[tag] = f_el.text

    event_data = _normalize_event_data(event_data)
    preserved_raw_xml = record_xml if _should_preserve_raw_xml(event_id, provider) else ""

    return NormalizedEvent(
        event_id=event_id,
        timestamp=timestamp,
        computer=computer,
        channel=channel,
        provider=provider,
        target_user=event_data.get("TargetUserName", ""),
        target_domain=event_data.get("TargetDomainName", ""),
        subject_user=event_data.get("SubjectUserName", ""),
        subject_domain=event_data.get("SubjectDomainName", ""),
        account_name=event_data.get("AccountName", ""),
        logon_user=event_data.get("LogonUser", ""),
        source_ip=event_data.get("IpAddress", ""),
        destination_ip=event_data.get("DestinationIp", ""),
        logon_type=event_data.get("LogonType", ""),
        status=event_data.get("Status", ""),
        sub_status=event_data.get("SubStatus", ""),
        share_name_value=event_data.get("ShareName", ""),
        command_line_value=event_data.get("CommandLine", "") or event_data.get("ScriptBlockText", ""),
        process_name_value=event_data.get("NewProcessName", "") or event_data.get("ProcessName", ""),
        parent_process_value=event_data.get("ParentProcessName", ""),
        service_name_value=event_data.get("ServiceName", ""),
        event_data=event_data,
        raw_xml=preserved_raw_xml,
    )


def read_evtx(filepath: str, start_date=None, end_date=None, progress_callback: Optional[Callable[[Dict[str, object]], None]] = None) -> List[NormalizedEvent]:
    """Parse a single .evtx file."""
    if not HAS_EVTX:
        print("Error: python-evtx required. Install: pip install python-evtx")
        return []

    events = []
    total, skipped = 0, 0
    last_progress_emit = monotonic()
    if progress_callback:
        progress_callback({"status": "file_started", "file_path": filepath})
    with evtx.Evtx(filepath) as log:
        for record in log.records():
            total += 1
            try:
                xml_str = record.xml()
            except Exception:
                skipped += 1
                continue
            ev = _parse_record(xml_str)
            if ev is None:
                continue
            if ev.timestamp:
                if start_date and ev.timestamp.date() < start_date:
                    continue
                if end_date and ev.timestamp.date() > end_date:
                    continue
            events.append(ev)
            should_emit = total == 1 or total % FILE_PROGRESS_RECORD_INTERVAL == 0
            if progress_callback and (should_emit or (monotonic() - last_progress_emit) >= FILE_PROGRESS_SECONDS):
                progress_callback(
                    {
                        "status": "file_progress",
                        "file_path": filepath,
                        "records_scanned": total,
                        "parsed_events": len(events),
                        "skipped_records": skipped,
                    }
                )
                last_progress_emit = monotonic()

    print(f"  {os.path.basename(filepath)}: {total} records, {len(events)} parsed, {skipped} skipped")
    return events


def _list_evtx_files(path: str) -> List[str]:
    files: List[str] = []
    for root_dir, _, names in os.walk(path):
        for fname in names:
            if fname.lower().endswith(".evtx"):
                files.append(os.path.join(root_dir, fname))
    return sorted(files, key=_file_priority)


def _parse_worker_count(file_count: int) -> int:
    if file_count <= 1:
        return 1

    configured = (os.environ.get(PARSE_WORKERS_ENV, "") or "").strip()
    if configured:
        try:
            return max(1, min(file_count, int(configured)))
        except ValueError:
            logging.warning("Ignoring invalid %s=%r", PARSE_WORKERS_ENV, configured)

    cpu_bound = os.cpu_count() or 1
    return max(1, min(DEFAULT_PARSE_WORKERS, file_count, cpu_bound))


def _parse_executor_kind(file_count: int) -> str:
    if file_count <= 1:
        return "serial"

    configured = (os.environ.get(PARSE_EXECUTOR_ENV, "") or "").strip().lower()
    if not configured:
        return DEFAULT_PARSE_EXECUTOR
    if configured in {"serial", "thread", "process"}:
        return configured
    logging.warning("Ignoring invalid %s=%r", PARSE_EXECUTOR_ENV, configured)
    return DEFAULT_PARSE_EXECUTOR


def _read_evtx_job(args) -> List[NormalizedEvent]:
    filepath, start_date, end_date = args
    return read_evtx(filepath, start_date, end_date)


def _emit_file_error(
    progress_callback: Optional[Callable[[Dict[str, object]], None]],
    *,
    file_path: str,
    file_index: int,
    completed_files: int,
    file_count: int,
    error: str,
    fallback: bool = False,
) -> None:
    if not progress_callback:
        return
    progress_callback(
        {
            "status": "file_error",
            "file_path": file_path,
            "file_index": file_index,
            "completed_files": completed_files,
            "file_count": file_count,
            "parsed_events": 0,
            "error": error,
            "fallback": fallback,
        }
    )


def describe_evtx_path(path: str) -> Dict[str, object]:
    abs_path = os.path.abspath(path)
    if os.path.isfile(path):
        return {
            "path": abs_path,
            "mode": "file",
            "files": [abs_path],
            "file_count": 1,
            "worker_count": 1,
            "executor_kind": "serial",
        }
    if os.path.isdir(path):
        files = _list_evtx_files(path)
        executor_kind = _parse_executor_kind(len(files))
        return {
            "path": abs_path,
            "mode": "directory",
            "files": files,
            "file_count": len(files),
            "worker_count": 1 if executor_kind == "serial" else _parse_worker_count(len(files)),
            "executor_kind": executor_kind,
        }
    return {
        "path": abs_path,
        "mode": "missing",
        "files": [],
        "file_count": 0,
        "worker_count": 0,
        "executor_kind": "serial",
    }


def read_evtx_path(
    path: str,
    start_date=None,
    end_date=None,
    progress_callback: Optional[Callable[[Dict[str, object]], None]] = None,
) -> List[NormalizedEvent]:
    """Parse a file or directory of .evtx files."""
    all_events = []
    profile = describe_evtx_path(path)
    if progress_callback:
        progress_callback({"status": "start", **profile})

    if os.path.isfile(path):
        file_path = str(profile["files"][0]) if profile.get("files") else os.path.abspath(path)
        try:
            all_events = read_evtx(path, start_date, end_date, progress_callback=progress_callback)
        except Exception as exc:
            logging.exception("Failed parsing EVTX file: %s", file_path)
            all_events = []
            _emit_file_error(
                progress_callback,
                file_path=file_path,
                file_index=1,
                completed_files=1,
                file_count=1,
                error=str(exc),
            )
        else:
            if progress_callback:
                progress_callback(
                    {
                        "status": "file_complete",
                        "file_path": file_path,
                        "file_index": 1,
                        "completed_files": 1,
                        "file_count": 1,
                        "parsed_events": len(all_events),
                    }
                )
    elif os.path.isdir(path):
        files = list(profile["files"])
        worker_count = int(profile["worker_count"])
        executor_kind = str(profile["executor_kind"])
        if worker_count <= 1 or executor_kind == "serial":
            for index, fpath in enumerate(files, start=1):
                try:
                    parsed = read_evtx(fpath, start_date, end_date, progress_callback=progress_callback)
                    all_events.extend(parsed)
                except Exception as exc:
                    logging.exception("Failed parsing EVTX file: %s", fpath)
                    _emit_file_error(
                        progress_callback,
                        file_path=fpath,
                        file_index=index,
                        completed_files=index,
                        file_count=len(files),
                        error=str(exc),
                    )
                    continue
                if progress_callback:
                    progress_callback(
                        {
                            "status": "file_complete",
                            "file_path": fpath,
                            "file_index": index,
                            "completed_files": index,
                            "file_count": len(files),
                            "parsed_events": len(parsed),
                        }
                    )
        else:
            try:
                executor_cls = ProcessPoolExecutor if executor_kind == "process" else ThreadPoolExecutor
                executor_kwargs = {"max_workers": worker_count}
                if executor_cls is ThreadPoolExecutor:
                    executor_kwargs["thread_name_prefix"] = "evtx"
                with executor_cls(**executor_kwargs) as executor:
                    if executor_kind == "thread":
                        future_to_index = {
                            executor.submit(read_evtx, fpath, start_date, end_date, progress_callback): index
                            for index, fpath in enumerate(files)
                        }
                    else:
                        future_to_index = {
                            executor.submit(_read_evtx_job, (fpath, start_date, end_date)): index
                            for index, fpath in enumerate(files)
                        }
                    parsed_by_index: Dict[int, List[NormalizedEvent]] = {}
                    completed_files = 0
                    for future in as_completed(future_to_index):
                        index = future_to_index[future]
                        completed_files += 1
                        try:
                            events = future.result()
                            parsed_by_index[index] = events
                        except Exception as exc:
                            logging.exception("Failed parsing EVTX file: %s", files[index])
                            _emit_file_error(
                                progress_callback,
                                file_path=files[index],
                                file_index=index + 1,
                                completed_files=completed_files,
                                file_count=len(files),
                                error=str(exc),
                            )
                            continue
                        if progress_callback:
                            progress_callback(
                                {
                                    "status": "file_complete",
                                    "file_path": files[index],
                                    "file_index": index + 1,
                                    "completed_files": completed_files,
                                    "file_count": len(files),
                                    "parsed_events": len(events),
                                }
                            )
                    for index in sorted(parsed_by_index):
                        all_events.extend(parsed_by_index[index])
            except Exception:
                logging.exception("%s EVTX parsing failed; falling back to serial mode.", executor_kind.title())
                all_events = []
                for index, fpath in enumerate(files, start=1):
                    try:
                        parsed = read_evtx(fpath, start_date, end_date)
                        all_events.extend(parsed)
                    except Exception as exc:
                        logging.exception("Failed parsing EVTX file during fallback parse: %s", fpath)
                        _emit_file_error(
                            progress_callback,
                            file_path=fpath,
                            file_index=index,
                            completed_files=index,
                            file_count=len(files),
                            error=str(exc),
                            fallback=True,
                        )
                        continue
                    if progress_callback:
                        progress_callback(
                            {
                                "status": "file_complete",
                                "file_path": fpath,
                                "file_index": index,
                                "completed_files": index,
                                "file_count": len(files),
                                "parsed_events": len(parsed),
                                "fallback": True,
                            }
                        )
    else:
        print(f"Error: Path not found: {path}")
    if progress_callback:
        progress_callback({"status": "complete", "event_count": len(all_events), **profile})
    return all_events
