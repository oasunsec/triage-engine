"""Offline EVTX file parser."""

from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
import logging
import os
import queue
import shutil
import subprocess
from threading import Event, Thread
from time import monotonic
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Sequence

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
PARSE_WORKERS_ENV = "CORROBORA_PARSE_WORKERS"
PARSE_EXECUTOR_ENV = "CORROBORA_PARSE_EXECUTOR"
DEFAULT_PARSE_EXECUTOR = "serial"
RAW_XML_MODE_ENV = "CORROBORA_RAW_XML_MODE"
SQL_RAW_XML_EVENT_IDS = {15281, 15457, 18454, 33205}
ADCS_RAW_XML_EVENT_IDS = {4886, 4887, 4888, 4898, 4899, 4900}
FILE_PROGRESS_RECORD_INTERVAL = 5000
FILE_PROGRESS_SECONDS = 15.0
WEVTUTIL_FALLBACK_MAX_RECORDS = 10000
WEVTUTIL_FALLBACK_TIMEOUT_SECONDS = 60
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
    # EVTX SystemTime is defined as UTC, but exports and test fixtures can
    # omit the trailing ``Z`` or carry an explicit offset.  Normalize every
    # parsed timestamp to an aware UTC value so correlation never compares
    # naive and aware datetimes (or mixes local offsets) and silently loses a
    # chain.
    if timestamp is not None:
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        else:
            timestamp = timestamp.astimezone(timezone.utc)

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
        # Operational channels often encode useful fields as nested attributes
        # rather than Data elements (for example CAPI2 EventAuxInfo
        # ProcessName="mimikatz.exe"). Preserve both a convenient unprefixed
        # key and a collision-resistant element-prefixed key.
        for element in ud_el.iter():
            if element is ud_el:
                continue
            tag = element.tag.split("}", 1)[-1] if "}" in element.tag else element.tag
            text = (element.text or "").strip()
            if text:
                event_data[tag] = text
            for attr_name, attr_value in element.attrib.items():
                clean_name = attr_name.split("}", 1)[-1] if "}" in attr_name else attr_name
                if attr_value:
                    event_data.setdefault(clean_name, attr_value)
                    event_data[f"{tag}_{clean_name}"] = attr_value

    event_data = _normalize_event_data(event_data)
    preserved_raw_xml = record_xml if _should_preserve_raw_xml(event_id, provider) else ""
    record_id_el = system.find(f"{NS}EventRecordID")

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
        record_id=(record_id_el.text or "").strip() if record_id_el is not None else "",
    )


WEVTUTIL_LARGE_FILE_THRESHOLD_BYTES = 5 * 1024 * 1024
WEVTUTIL_STREAM_MAX_RECORDS = 100000
WEVTUTIL_STREAM_TIMEOUT_SECONDS = 300
WEVTUTIL_STREAM_CHUNK_BYTES = 64 * 1024


def _read_evtx_with_wevtutil_streaming(
    filepath: str,
    start_date=None,
    end_date=None,
    progress_callback: Optional[Callable[[Dict[str, object]], None]] = None,
) -> tuple[List[NormalizedEvent], int, int, bool]:
    """Stream native XML for large EVTX files without record-sized buffering."""

    executable = shutil.which("wevtutil")
    if not executable:
        return [], 0, 0, False
    command = [
        executable,
        "qe",
        os.path.abspath(filepath),
        "/lf:true",
        "/f:xml",
    ]
    process = None
    events: List[NormalizedEvent] = []
    records = 0
    skipped = 0
    truncated = False
    buffer = b""
    started = monotonic()
    stop_reader = Event()
    stdout_queue: "queue.Queue[tuple[str, bytes]]" = queue.Queue(maxsize=8)
    stream_errors: List[str] = []
    stderr_holder: Dict[str, bytes] = {}

    def _queue_stdout() -> None:
        """Drain the native process without letting a blocking pipe defeat the deadline."""
        try:
            assert process is not None and process.stdout is not None
            while not stop_reader.is_set():
                chunk = process.stdout.read(WEVTUTIL_STREAM_CHUNK_BYTES)
                if not chunk:
                    break
                if isinstance(chunk, str):
                    chunk = chunk.encode("utf-8", errors="replace")
                while not stop_reader.is_set():
                    try:
                        stdout_queue.put(("chunk", chunk), timeout=0.2)
                        break
                    except queue.Full:
                        continue
        except Exception as exc:  # pragma: no cover - platform pipe failure
            stream_errors.append(str(exc) or exc.__class__.__name__)
        finally:
            try:
                stdout_queue.put_nowait(("eof", b""))
            except queue.Full:
                pass

    def _drain_stderr() -> None:
        try:
            assert process is not None and process.stderr is not None
            stderr_holder["data"] = process.stderr.read()
        except Exception as exc:  # pragma: no cover - platform pipe failure
            stream_errors.append(str(exc) or exc.__class__.__name__)

    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
        )
        assert process.stdout is not None
        stdout_reader = Thread(target=_queue_stdout, name="wevtutil-stdout", daemon=True)
        stderr_reader = Thread(target=_drain_stderr, name="wevtutil-stderr", daemon=True)
        stdout_reader.start()
        stderr_reader.start()
        while True:
            remaining = WEVTUTIL_STREAM_TIMEOUT_SECONDS - (monotonic() - started)
            if remaining <= 0:
                stop_reader.set()
                process.kill()
                truncated = True
                logging.warning("Native EVTX fallback timed out for %s", filepath)
                break
            try:
                _kind, chunk = stdout_queue.get(timeout=min(remaining, 1.0))
            except queue.Empty:
                # The reader may be blocked in an OS pipe read. The bounded
                # queue timeout lets us re-check the deadline independently.
                if not stdout_reader.is_alive():
                    break
                continue
            if _kind == "eof":
                break
            buffer += chunk
            while b"</Event>" in buffer:
                fragment, buffer = buffer.split(b"</Event>", 1)
                records += 1
                start = fragment.find(b"<Event")
                if start < 0:
                    skipped += 1
                    continue
                try:
                    xml = (fragment[start:] + b"</Event>").decode("utf-8", errors="replace")
                    event = _parse_record(xml)
                except Exception:
                    event = None
                if event is None:
                    skipped += 1
                elif (
                    (not start_date or not event.timestamp or event.timestamp.date() >= start_date)
                    and (not end_date or not event.timestamp or event.timestamp.date() <= end_date)
                ):
                    events.append(event)
                if progress_callback and (records == 1 or records % FILE_PROGRESS_RECORD_INTERVAL == 0):
                    progress_callback(
                        {
                            "status": "file_progress",
                            "file_path": filepath,
                            "records_scanned": records,
                            "parsed_events": len(events),
                            "skipped_records": skipped,
                            "fallback": True,
                        }
                    )
                if records >= WEVTUTIL_STREAM_MAX_RECORDS:
                    truncated = True
                    stop_reader.set()
                    process.kill()
                    break
            if truncated:
                break
            # A malformed stream must not grow without bound while waiting for
            # a closing element. Keep enough context for the next event marker.
            if len(buffer) > 2 * WEVTUTIL_STREAM_CHUNK_BYTES:
                skipped += 1
                marker = buffer.rfind(b"<Event")
                buffer = buffer[marker:] if marker >= 0 else b""
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        stop_reader.set()
        stdout_reader.join(timeout=1.0)
        stderr_reader.join(timeout=1.0)
        stderr = stderr_holder.get("data", b"")
        if process.returncode not in (0, None):
            truncated = True
            logging.warning(
                "Native EVTX fallback returned %s for %s: %s",
                process.returncode,
                filepath,
                stderr.decode("utf-8", errors="replace")[:500] if isinstance(stderr, bytes) else str(stderr)[:500],
            )
    except (OSError, subprocess.SubprocessError) as exc:
        logging.warning("Native EVTX streaming fallback failed for %s: %s", filepath, exc)
        if process is not None:
            try:
                process.kill()
                process.wait(timeout=5)
            except Exception:
                pass
        return [], records, skipped, True
    finally:
        if process is not None:
            for stream in (process.stdout, process.stderr):
                try:
                    if stream is not None:
                        stream.close()
                except Exception:
                    pass
    if stream_errors:
        truncated = True
        logging.debug("Native EVTX stream diagnostics for %s: %s", filepath, "; ".join(stream_errors[:3]))
    return events, records, skipped, truncated

def _read_evtx_with_wevtutil(filepath: str) -> List[NormalizedEvent]:
    """Use Windows' native renderer when python-evtx cannot render any record.

    The fallback is deliberately bounded and never uses a shell. It is not used
    for partially parsed files, which avoids duplicates and keeps the normal
    cross-platform path authoritative.
    """

    executable = shutil.which("wevtutil")
    if not executable:
        return []
    try:
        completed = subprocess.run(
            [
                executable,
                "qe",
                os.path.abspath(filepath),
                "/lf:true",
                "/f:xml",
                f"/c:{WEVTUTIL_FALLBACK_MAX_RECORDS}",
            ],
            capture_output=True,
            text=True,
            timeout=WEVTUTIL_FALLBACK_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logging.warning("Native EVTX fallback failed for %s: %s", filepath, exc)
        return []
    if completed.returncode != 0 or not completed.stdout.strip():
        logging.warning(
            "Native EVTX fallback returned %s for %s: %s",
            completed.returncode,
            filepath,
            (completed.stderr or "").strip()[:500],
        )
        return []

    events: List[NormalizedEvent] = []
    # wevtutil emits one Event element per line in current Windows versions.
    # Splitting on the closing tag also handles output without line breaks.
    for fragment in completed.stdout.split("</Event>"):
        fragment = fragment.strip()
        event_start = fragment.find("<Event")
        if event_start < 0:
            continue
        parsed = _parse_record(fragment[event_start:] + "</Event>")
        if parsed is not None:
            events.append(parsed)
    return events


def read_evtx(filepath: str, start_date=None, end_date=None, progress_callback: Optional[Callable[[Dict[str, object]], None]] = None) -> List[NormalizedEvent]:
    """Parse a single .evtx file, using native streaming for large exports."""

    try:
        large_file = os.path.getsize(filepath) >= WEVTUTIL_LARGE_FILE_THRESHOLD_BYTES
    except OSError:
        large_file = False
    if large_file and shutil.which("wevtutil"):
        if progress_callback:
            progress_callback({"status": "file_started", "file_path": filepath, "fallback": True})
        native_events, native_total, native_skipped, truncated = _read_evtx_with_wevtutil_streaming(
            filepath,
            start_date,
            end_date,
            progress_callback,
        )
        if native_total or native_events:
            if native_skipped and progress_callback:
                progress_callback({"status": "file_warning", "file_path": filepath,
                                   "warning": f"Native EVTX reader skipped {native_skipped} unreadable record(s)."})
            if truncated and progress_callback:
                progress_callback(
                    {
                        "status": "file_warning",
                        "file_path": filepath,
                        "warning": "Native EVTX streaming result is incomplete (record cap, timeout, or reader failure).",
                        "records_scanned": native_total,
                        "parsed_events": len(native_events),
                    }
                )
            print(
                f"  {os.path.basename(filepath)}: {native_total} records, "
                f"{len(native_events)} parsed, {native_skipped} skipped"
                + (" (native streaming)" if not truncated else " (native streaming, incomplete)")
            )
            return native_events

    if not HAS_EVTX:
        raise RuntimeError("EVTX parser unavailable. Install python-evtx before investigating event log files.")

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
                skipped += 1
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

    if not events and skipped and total <= WEVTUTIL_FALLBACK_MAX_RECORDS:
        fallback_events = _read_evtx_with_wevtutil(filepath)
        if fallback_events:
            events = [
                item
                for item in fallback_events
                if (not start_date or not item.timestamp or item.timestamp.date() >= start_date)
                and (not end_date or not item.timestamp or item.timestamp.date() <= end_date)
            ]
            logging.info("Recovered %d event(s) with native EVTX fallback: %s", len(events), filepath)

    if skipped and progress_callback:
        progress_callback({"status": "file_warning", "file_path": filepath, "skipped_records": skipped,
                           "warning": f"Python EVTX reader skipped {skipped} unreadable record(s); native fallback may have recovered some records."})
    if total and skipped == total and not events:
        raise RuntimeError("No EVTX records could be normalized; input is unreadable")

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


def _read_evtx_job(args):
    filepath, start_date, end_date = args
    warnings = []
    def record_warning(update):
        if update.get("status") == "file_warning":
            warnings.append(update)
    return read_evtx(filepath, start_date, end_date, progress_callback=record_warning), warnings


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


def _bind_source_file(events: List[NormalizedEvent], filepath: str) -> None:
    """Attach the parsed source path without assuming mocked events are models."""
    source_file = os.path.abspath(filepath)
    for event in events:
        if isinstance(event, str):
            continue
        try:
            event.source_file = source_file
        except (AttributeError, TypeError):
            continue


def read_evtx_path(
    path: str,
    start_date=None,
    end_date=None,
    progress_callback: Optional[Callable[[Dict[str, object]], None]] = None,
    source_files: Optional[Sequence[str]] = None,
) -> List[NormalizedEvent]:
    """Parse a file or directory of .evtx files."""
    all_events = []
    profile = describe_evtx_path(path)
    files_to_parse = [os.path.abspath(str(item)) for item in source_files] if source_files is not None else list(profile["files"])
    progress_profile = {**profile, "files": files_to_parse, "file_count": len(files_to_parse)}
    if progress_callback:
        progress_callback({"status": "start", **progress_profile})

    if profile["mode"] == "file":
        if len(files_to_parse) != 1:
            raise ValueError("Single-file input requires exactly one retained source")
        file_path = files_to_parse[0]
        try:
            all_events = read_evtx(file_path, start_date, end_date, progress_callback=progress_callback)
            _bind_source_file(all_events, file_path)
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
    elif profile["mode"] == "directory":
        files = list(files_to_parse)
        worker_count = int(profile["worker_count"])
        executor_kind = str(profile["executor_kind"])
        if worker_count <= 1 or executor_kind == "serial":
            for index, fpath in enumerate(files, start=1):
                try:
                    parsed = read_evtx(fpath, start_date, end_date, progress_callback=progress_callback)
                    _bind_source_file(parsed, fpath)
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
                            result = future.result()
                            if executor_kind == "process":
                                events, warnings = result
                                if progress_callback:
                                    for warning in warnings:
                                        progress_callback(warning)
                            else:
                                events = result
                            _bind_source_file(events, files[index])
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
                        parsed = read_evtx(fpath, start_date, end_date, progress_callback=progress_callback)
                        _bind_source_file(parsed, fpath)
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
        progress_callback({"status": "complete", "event_count": len(all_events), **progress_profile})
    return all_events
