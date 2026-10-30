"""Live Windows Event Log reader using modern EvtQuery API.

Uses win32evtlog.EvtQuery which returns structured XML -- the same format
as EVTX files. This means the same XML parser handles both modes, so
field normalization (TargetUserName, IpAddress, etc.) works identically.

Fallback: legacy ReadEventLog with positional field mapping for known event IDs.
"""

import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, List, Optional
from models.event_model import NormalizedEvent
from parser.evtx_reader import _normalize_event_data, _parse_record

try:
    import win32evtlog
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False


_ACCESS_DENIED_TOKENS = (
    "access is denied",
    "access denied",
    "required privilege is not held",
    "required privilege",
    "not held by the client",
    "privilege not held",
    "error_access_denied",
    "privilege is not held",
)

_NOT_FOUND_TOKENS = (
    "could not be found",
    "no matching logs found",
    "not recognized as valid",
    "cannot find",
    "channel not found",
    "not found",
    "error_file_not_found",
    "error_path_not_found",
)


def _numeric_win32_code(error: object) -> Optional[int]:
    # pywintypes.error and OSError commonly carry (code, function, message),
    # so avoid relying on localized message text for access classification.
    if isinstance(error, int) and not isinstance(error, bool):
        return int(error)
    if isinstance(error, OSError) and error.winerror:
        return int(error.winerror)
    args = getattr(error, "args", ()) or ()
    for value in args:
        if isinstance(value, int):
            return value
        if isinstance(value, (list, tuple)) and value and isinstance(value[0], int):
            return int(value[0])
    return None


def _classify_numeric_win32_code(code: Optional[int]) -> Optional[str]:
    if code == 5 or code == 0x5:
        return "access_denied"
    if code == 2 or code == 0x2:
        return "not_found"
    return None


def classify_live_channel_error(error: object) -> str:
    """Classify a live channel failure for user-facing collection-quality views.

    Win32 log access failures can surface as pywintypes.error tuples, message
    text, or formatted ``WinError`` strings. Keeping this classification in one
    place prevents the service and the live-health probe from disagreeing about
    whether a channel is blocked by permissions or simply unavailable.
    """
    message = str(error or "").strip() or (error.__class__.__name__ if error is not None else "")
    lowered = re.sub(r"\s+", " ", message.lower())
    numeric_status = _classify_numeric_win32_code(_numeric_win32_code(error))
    if numeric_status:
        return numeric_status
    if any(token in lowered for token in _ACCESS_DENIED_TOKENS):
        return "access_denied"
    if re.search(r"\b(?:winerror|error)\s*(?:code\s*)?(?:0x)?0*5\b", lowered):
        return "access_denied"
    if re.search(r"\b0x0*5\b", lowered):
        return "access_denied"
    if any(token in lowered for token in _NOT_FOUND_TOKENS):
        return "not_found"
    if re.search(r"\b(?:winerror|error)\s*(?:code\s*)?(?:0x)?0*2\b", lowered):
        return "not_found"
    if re.search(r"\b0x0*2\b", lowered):
        return "not_found"
    return "error"


def read_live(
    channels: List[str],
    since_minutes: Optional[int] = 30,
    progress_callback: Optional[Callable[[Dict[str, object]], None]] = None,
) -> List[NormalizedEvent]:
    """Read events from live Windows Event Log channels."""
    if not HAS_WIN32:
        raise RuntimeError("Live mode requires pywin32 and only works on Windows.")

    window_minutes = max(1, int(since_minutes or 30))
    normalized_channels = [c.strip() for c in channels if c and c.strip()]
    events = []
    completed_channels = 0
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
    cutoff_str = cutoff.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    if progress_callback:
        progress_callback(
            {
                "status": "start",
                "channel_count": len(normalized_channels),
                "channels": list(normalized_channels),
                "since_minutes": window_minutes,
            }
        )

    for index, channel in enumerate(normalized_channels, start=1):
        print(f"  Reading live: {channel} (last {window_minutes} min)")
        if progress_callback:
            progress_callback(
                {
                    "status": "channel_started",
                    "channel": channel,
                    "channel_index": index,
                    "channel_count": len(normalized_channels),
                    "since_minutes": window_minutes,
                }
            )
        total = 0
        used_legacy = False
        channel_failed = False
        channel_succeeded = False
        channel_partial = False
        first_poll_done = False
        try:
            query = f"*[System[TimeCreated[@SystemTime>='{cutoff_str}']]]"
            qh = win32evtlog.EvtQuery(
                channel,
                win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
                query, None)
            while True:
                try:
                    batch = win32evtlog.EvtNext(qh, 100, -1, 0)
                except Exception as poll_exc:
                    if not first_poll_done:
                        raise
                    channel_partial = True
                    logging.warning(
                        "EvtNext stopped early for %s after %d parsed event(s)",
                        channel,
                        total,
                    )
                    logging.debug("EvtNext early stop: %s", poll_exc)
                    if progress_callback:
                        progress_callback(
                            {
                                "status": "channel_warning",
                                "channel": channel,
                                "message": f"Live channel '{channel}' stopped early after {total} parsed event(s): {poll_exc}",
                            }
                        )
                    break
                if not batch:
                    break
                first_poll_done = True
                for eh in batch:
                    try:
                        xml_str = win32evtlog.EvtRender(eh, win32evtlog.EvtRenderEventXml)
                        ev = _parse_record(xml_str)
                        if ev:
                            events.append(ev)
                            total += 1
                    except Exception as e:
                        logging.debug(f"Render failed: {e}")
                    finally:
                        try: win32evtlog.EvtClose(eh)
                        except Exception: pass
            try: win32evtlog.EvtClose(qh)
            except Exception: pass
            print(f"    {total} events parsed")
            channel_succeeded = True
        except Exception as e:
            warning_message = f"EvtQuery failed for '{channel}', trying legacy API: {e}"
            logging.warning("  %s", warning_message)
            if progress_callback:
                progress_callback(
                        {
                            "status": "channel_warning",
                            "channel": channel,
                            "message": warning_message,
                            "win32_code": _numeric_win32_code(e),
                        }
                )
            used_legacy = True
            try:
                fb = _read_legacy(channel, cutoff, progress_callback=progress_callback)
                events.extend(fb)
                total = len(fb)
                channel_succeeded = True
                print(f"    {total} events (legacy API)")
            except Exception as legacy_exc:
                # Both the modern and legacy APIs failed; this channel is
                # genuinely unreadable and must not be reported as present-but-
                # quiet telemetry. Emit a terminal failure signal so the service
                # can exclude it from telemetry accounting.
                terminal_message = f"Event log channel '{channel}' could not be read ({legacy_exc})"
                logging.warning(terminal_message)
                if progress_callback:
                    progress_callback(
                        {
                            "status": "channel_error",
                            "channel": channel,
                            "message": terminal_message,
                            "error": str(legacy_exc),
                            "win32_code": _numeric_win32_code(legacy_exc),
                        }
                    )
                channel_failed = True
        if channel_succeeded:
            completed_channels += 1
        if progress_callback:
            progress_callback(
                {
                    "status": "channel_complete",
                    "channel": channel,
                    "channel_index": index,
                    "completed_channels": completed_channels,
                    "channel_count": len(normalized_channels),
                    "parsed_events": total,
                    "fallback": bool(used_legacy and channel_succeeded),
                    "partial": bool(channel_partial),
                    "failed": bool(channel_failed),
                }
            )

    if progress_callback:
        progress_callback(
            {
                "status": "complete",
                "event_count": len(events),
                "channel_count": len(normalized_channels),
                "channels": list(normalized_channels),
                "since_minutes": window_minutes,
            }
        )
    return events


# --- Legacy fallback with structured field mapping ---

_FIELD_MAPS = {
    4624: {5:"TargetUserName",6:"TargetDomainName",1:"SubjectUserName",
           2:"SubjectDomainName",8:"LogonType",11:"ProcessName",18:"IpAddress"},
    4625: {5:"TargetUserName",6:"TargetDomainName",1:"SubjectUserName",
           2:"SubjectDomainName",7:"Status",9:"SubStatus",10:"LogonType",11:"ProcessName",19:"IpAddress"},
    4648: {1:"SubjectUserName",2:"SubjectDomainName",5:"TargetUserName",
           6:"TargetDomainName",8:"TargetServerName",10:"ProcessName",12:"IpAddress"},
    4672: {1:"SubjectUserName",2:"SubjectDomainName",4:"PrivilegeList"},
    1102: {1:"SubjectUserName",2:"SubjectDomainName"},
    4616: {1:"SubjectUserName",2:"SubjectDomainName",5:"ProcessName"},
    4688: {1:"SubjectUserName",2:"SubjectDomainName",5:"NewProcessName",8:"CommandLine",13:"ParentProcessName"},
    4720: {0:"TargetUserName",1:"TargetDomainName",4:"SubjectUserName",5:"SubjectDomainName"},
    4740: {0:"TargetUserName",1:"TargetDomainName",4:"SubjectUserName"},
    7045: {0:"ServiceName",1:"ImagePath",4:"AccountName"},
    4698: {0:"SubjectUserName",1:"SubjectDomainName",2:"SubjectLogonId",4:"TaskName"},
}


def _read_legacy(
    channel: str,
    cutoff: datetime,
    progress_callback: Optional[Callable[[Dict[str, object]], None]] = None,
) -> List[NormalizedEvent]:
    events = []
    try:
        hand = win32evtlog.OpenEventLog(None, channel)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        while True:
            raw_events = win32evtlog.ReadEventLog(hand, flags, 0)
            if not raw_events:
                break
            for raw in raw_events:
                ts = raw.TimeGenerated
                event_time = ts.replace(tzinfo=timezone.utc) if hasattr(ts, 'replace') \
                    else datetime.fromtimestamp(int(ts), tz=timezone.utc)
                if event_time < cutoff:
                    break
                eid = raw.EventID & 0xFFFF
                ed = {}
                if raw.StringInserts:
                    fmap = _FIELD_MAPS.get(eid, {})
                    for i, val in enumerate(raw.StringInserts):
                        ed[fmap.get(i, f"param{i}")] = val or ""
                ed = _normalize_event_data(ed)
                events.append(NormalizedEvent(
                    event_id=eid, timestamp=event_time,
                    computer=raw.ComputerName or "", channel=channel,
                    provider=raw.SourceName or "",
                    target_user=ed.get("TargetUserName",""),
                    target_domain=ed.get("TargetDomainName",""),
                    subject_user=ed.get("SubjectUserName",""),
                    subject_domain=ed.get("SubjectDomainName",""),
                    account_name=ed.get("AccountName", ""),
                    logon_user=ed.get("LogonUser", ""),
                    source_ip=ed.get("IpAddress",""),
                    destination_ip=ed.get("DestinationIp", ""),
                    logon_type=ed.get("LogonType",""),
                    status=ed.get("Status",""),
                    sub_status=ed.get("SubStatus",""),
                    share_name_value=ed.get("ShareName", ""),
                    command_line_value=ed.get("CommandLine", "") or ed.get("ScriptBlockText", ""),
                    process_name_value=ed.get("NewProcessName", "") or ed.get("ProcessName", ""),
                    parent_process_value=ed.get("ParentProcessName", ""),
                    service_name_value=ed.get("ServiceName", ""),
                    event_data=ed))
            else:
                continue
            break
        win32evtlog.CloseEventLog(hand)
    except Exception as e:
        logging.warning("Legacy API failed for %s: %s", channel, e)
        raise
    return events
