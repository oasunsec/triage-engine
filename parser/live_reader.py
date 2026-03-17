"""Live Windows Event Log reader using modern EvtQuery API.

Uses win32evtlog.EvtQuery which returns structured XML -- the same format
as EVTX files. This means the same XML parser handles both modes, so
field normalization (TargetUserName, IpAddress, etc.) works identically.

Fallback: legacy ReadEventLog with positional field mapping for known event IDs.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, List, Optional
from models.event_model import NormalizedEvent
from parser.evtx_reader import _normalize_event_data, _parse_record

try:
    import win32evtlog
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False


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
        try:
            query = f"*[System[TimeCreated[@SystemTime>='{cutoff_str}']]]"
            qh = win32evtlog.EvtQuery(
                channel,
                win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
                query, None)
            while True:
                try:
                    batch = win32evtlog.EvtNext(qh, 100, -1, 0)
                except Exception:
                    break
                if not batch:
                    break
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
        except Exception as e:
            warning_message = f"EvtQuery failed for '{channel}', trying legacy API: {e}"
            logging.warning("  %s", warning_message)
            if progress_callback:
                progress_callback(
                    {
                        "status": "channel_warning",
                        "channel": channel,
                        "message": warning_message,
                    }
                )
            used_legacy = True
            fb = _read_legacy(channel, cutoff, progress_callback=progress_callback)
            events.extend(fb)
            total = len(fb)
            print(f"    {total} events (legacy API)")
        if progress_callback:
            progress_callback(
                {
                    "status": "channel_complete",
                    "channel": channel,
                    "channel_index": index,
                    "completed_channels": index,
                    "channel_count": len(normalized_channels),
                    "parsed_events": total,
                    "fallback": used_legacy,
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
        warning_message = f"Legacy API failed for '{channel}': {e}"
        logging.warning(warning_message)
        if progress_callback:
            progress_callback(
                {
                    "status": "channel_warning",
                    "channel": channel,
                    "message": warning_message,
                }
            )
    return events
