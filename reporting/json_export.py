"""JSON exports for legacy and case-based workflows."""

from __future__ import annotations

import json
import os
import re
from collections import Counter
from typing import Any, Dict, List, Optional

from models.event_model import Alert, AttackChain, Finding, Incident, NormalizedEvent, Signal
from triage_engine.export_sanitizer import sanitize_export_data
from triage_engine.user_utils import add_user_identity_fields, normalize_user_identity


URL_RE = re.compile(r"https?://[^\s'\"`]+", re.IGNORECASE)
TASK_NAME_RE = re.compile(r"-TaskName\s+[\"']([^\"']+)[\"']", re.IGNORECASE)
NEW_LOCAL_USER_RE = re.compile(r"New-LocalUser\b.*?-Name\s+['\"]([^'\"]+)['\"]", re.IGNORECASE | re.DOTALL)
RAW_EVENT_PREVIEW_LIMIT = 1500


def _iso(ts):
    return ts.isoformat() if ts else None


def _raw_event_to_dict(ev: NormalizedEvent) -> Dict[str, Any]:
    payload = {
        "event_id": ev.event_id,
        "timestamp": _iso(ev.timestamp),
        "computer": ev.computer,
        "channel": ev.channel,
        "provider": ev.provider,
        "user": ev.domain_user,
        "subject_domain_user": ev.subject_domain_user,
        "target_domain_user": ev.target_domain_user,
        "target_user": ev.target_user,
        "target_domain": ev.target_domain,
        "subject_user": ev.subject_user,
        "subject_domain": ev.subject_domain,
        "account_name": ev.account_name,
        "logon_user": ev.logon_user,
        "source_ip": ev.source_ip,
        "destination_ip": ev.destination_ip,
        "logon_type": ev.logon_type,
        "process_name": ev.process_name,
        "parent_process": ev.parent_process,
        "command_line": ev.command_line,
        "service_name": ev.service_name,
        "share_name": ev.share_name,
        "status": ev.status,
        "sub_status": ev.sub_status,
        "event_data": dict(ev.event_data),
    }
    add_user_identity_fields(payload, "user", ev.domain_user, ev.computer)
    add_user_identity_fields(payload, "subject_domain_user", ev.subject_domain_user, ev.computer)
    add_user_identity_fields(payload, "target_domain_user", ev.target_domain_user, ev.computer)
    add_user_identity_fields(payload, "account_name", ev.account_name, ev.computer)

    if ev.event_id == 4104:
        script_text = ev.event_data.get("ScriptBlockText", "") or ev.command_line
        payload["script_excerpt"] = _summarize_script(script_text, 220)
        payload["remote_url"] = _first_match(URL_RE, script_text)
        payload["remote_ip"] = _remote_host(payload["remote_url"])
        payload["task_name"] = _first_match(TASK_NAME_RE, script_text)
        payload["created_username"] = _first_match(NEW_LOCAL_USER_RE, script_text)
        payload["raw_summary"] = _powershell_raw_summary(ev, payload)
    else:
        payload["raw_summary"] = _default_raw_summary(ev)

    return payload


def _normalize_script_text(text: str) -> str:
    return " ".join((text or "").split())


def _summarize_script(text: str, limit: int) -> str:
    collapsed = _normalize_script_text(text)
    return collapsed if len(collapsed) <= limit else f"{collapsed[: limit - 3]}..."


def _first_match(pattern, text: str) -> str:
    match = pattern.search(text or "")
    if not match:
        return ""
    try:
        value = match.group(1)
    except IndexError:
        value = match.group(0)
    return (value or "").strip()


def _remote_host(url: str) -> str:
    if not url:
        return ""
    host = url.split("://", 1)[-1].split("/", 1)[0]
    return host.split(":", 1)[0]


def _is_suspicious_4104(script_text: str) -> bool:
    low = (script_text or "").lower()
    suspicious_markers = (
        "iex(",
        "invoke-expression",
        "downloadstring",
        "downloadfile",
        "invoke-webrequest",
        "net.webclient",
        "register-scheduledtask",
        "new-localuser",
        "add-localgroupmember",
        "administrators",
        "function rot13",
        "backdoor",
        "http://",
        "https://",
    )
    return any(marker in low for marker in suspicious_markers)


def _is_benign_duplicate_4104(script_text: str) -> bool:
    low = (script_text or "").lower()
    benign_markers = (
        "scheduledtasks",
        "cmdletization",
        "cimcmdlets",
        "psmodulepath",
        "import-localizeddata",
        "microsoft.powershell",
        "proxycommand",
        "set-strictmode",
        "get-scriptcmdlet",
    )
    return any(marker in low for marker in benign_markers)


def _powershell_raw_summary(ev: NormalizedEvent, payload: Dict[str, Any]) -> str:
    script_excerpt = payload.get("script_excerpt", "")
    remote_url = payload.get("remote_url", "")
    task_name = payload.get("task_name", "")
    created_username = payload.get("created_username", "")
    parts = ["PowerShell script block"]
    if remote_url:
        parts.append(f"remote fetch {remote_url}")
    if task_name:
        parts.append(f"task {task_name}")
    if created_username:
        parts.append(f"local user {created_username}")
    if script_excerpt and not remote_url and not task_name and not created_username:
        parts.append(script_excerpt)
    return " | ".join(parts)


def _default_raw_summary(ev: NormalizedEvent) -> str:
    user_identity = normalize_user_identity(ev.domain_user or ev.subject_domain_user or ev.target_domain_user, ev.computer)
    user_display = user_identity["display"] or "unknown"
    if ev.event_id == 4624:
        return f"Successful logon by {user_display} from {ev.source_ip or 'unknown'}"
    if ev.event_id == 4625:
        return f"Failed logon for {user_display} from {ev.source_ip or 'unknown'}"
    if ev.event_id in (7045, 4697):
        return f"Service install {ev.service_name or 'unknown'}"
    if ev.event_id in (4688, 1):
        return (ev.command_line or ev.process_name or "Process execution")[:220]
    return f"Event {ev.event_id}"


def _collapsed_4104_entry(events: List[NormalizedEvent], script_text: str) -> Dict[str, Any]:
    first = events[0]
    base = _raw_event_to_dict(first)
    base["timestamp_last"] = _iso(events[-1].timestamp)
    base["collapsed_count"] = len(events)
    base["raw_event_kind"] = "powershell_noise_summary"
    base["script_excerpt"] = _summarize_script(script_text, 180)
    base["raw_summary"] = (
        f"Collapsed benign PowerShell module/scriptblock noise ({len(events)} similar events)"
    )
    return base


def _iter_raw_event_entries(raw_events: List[NormalizedEvent]):
    collapse_groups: Dict[tuple, List[NormalizedEvent]] = {}

    for ev in raw_events:
        if ev.event_id == 4104:
            script_text = ev.event_data.get("ScriptBlockText", "") or ev.command_line
            normalized_script = _normalize_script_text(script_text)
            if (
                normalized_script
                and not _is_suspicious_4104(normalized_script)
                and _is_benign_duplicate_4104(normalized_script)
            ):
                user_identity = normalize_user_identity(ev.domain_user or ev.subject_domain_user or ev.target_domain_user, ev.computer)
                group_key = (
                    ev.computer,
                    user_identity["canonical"] or user_identity["raw"],
                    normalized_script,
                )
                collapse_groups.setdefault(group_key, []).append(ev)
                continue

        yield _raw_event_to_dict(ev)

    ordered_groups = sorted(
        collapse_groups.values(),
        key=lambda group_events: (
            (group_events[0].timestamp is None),
            group_events[0].timestamp.isoformat() if group_events[0].timestamp else "",
            group_events[0].event_id,
        ),
    )
    for group_events in ordered_groups:
        if len(group_events) == 1:
            yield _raw_event_to_dict(group_events[0])
            continue
        script_text = group_events[0].event_data.get("ScriptBlockText", "") or group_events[0].command_line
        yield _collapsed_4104_entry(group_events, script_text)


def _build_raw_event_preview(
    raw_events: List[NormalizedEvent],
    *,
    preview_limit: int = RAW_EVENT_PREVIEW_LIMIT,
) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
    preview: List[Dict[str, Any]] = []
    total_count = 0

    for entry in _iter_raw_event_entries(raw_events):
        total_count += 1
        if len(preview) < preview_limit:
            preview.append(entry)

    preview.sort(key=lambda item: ((item.get("timestamp") or "") == "", item.get("timestamp") or "", item.get("event_id") or 0))
    summary = {
        "total_count": total_count,
        "preview_count": len(preview),
        "preview_limit": preview_limit,
        "truncated": total_count > len(preview),
    }
    return preview, summary


def export_raw_events_stream(raw_events: List[NormalizedEvent], filepath: str) -> Dict[str, Any]:
    total_count = 0
    with open(filepath, "w", encoding="utf-8") as handle:
        for entry in _iter_raw_event_entries(raw_events):
            total_count += 1
            handle.write(json.dumps(sanitize_export_data(entry), separators=(",", ":")))
            handle.write("\n")
    return {
        "path": filepath,
        "basename": os.path.basename(filepath),
        "format": "jsonl",
        "total_count": total_count,
    }


def export_case(
    signals: List[Signal],
    findings: List[Finding],
    incidents: List[Incident],
    filepath: str,
    legacy_alerts: Optional[List[Alert]] = None,
    legacy_chains: Optional[List[AttackChain]] = None,
    raw_events: Optional[List[NormalizedEvent]] = None,
    case_meta: Optional[Dict[str, Any]] = None,
    raw_event_preview_limit: int = RAW_EVENT_PREVIEW_LIMIT,
    raw_event_artifact_path: Optional[str] = None,
) -> Dict[str, Any]:
    legacy_alerts = legacy_alerts or []
    legacy_chains = legacy_chains or []
    raw_events = raw_events or []
    case_meta = case_meta or {}

    sev = Counter([f.severity for f in findings] + [i.severity for i in incidents])
    tac = Counter([s.mitre_tactic for s in signals])
    case_metrics = case_meta.get("case_metrics", {}) or {}
    raw_event_preview, raw_event_summary = _build_raw_event_preview(raw_events, preview_limit=raw_event_preview_limit)
    if raw_event_artifact_path:
        raw_event_summary["artifact_path"] = os.path.basename(raw_event_artifact_path)
        raw_event_summary["artifact_format"] = "jsonl"

    data: Dict[str, Any] = {
        "case": case_meta,
        "signals": [s.to_dict() for s in signals],
        "findings": [f.to_dict() for f in findings],
        "incidents": [i.to_dict() for i in incidents],
        "summary": {
            "signal_count": len(signals),
            "finding_count": len(findings),
            "incident_count": len(incidents),
            "by_severity": dict(sev),
            "by_tactic": dict(tac),
            "raw_alert_count": case_metrics.get("raw_alert_count", case_meta.get("raw_alert_count", len(legacy_alerts))),
            "suppressed_alert_count": case_metrics.get("suppressed_alert_count", case_meta.get("suppressed_alert_count", 0)),
            "post_filter_alert_count": case_metrics.get("post_filter_alert_count", case_meta.get("post_filter_alert_count", len(legacy_alerts))),
            "deduplicated_alert_count": case_metrics.get("deduplicated_alert_count", case_meta.get("deduplicated_alert_count", 0)),
            "post_dedup_alert_count": case_metrics.get("post_dedup_alert_count", case_meta.get("post_dedup_alert_count", len(legacy_alerts))),
            "finding_promotion_rate": case_metrics.get("finding_promotion_rate", 0.0),
            "incident_promotion_rate": case_metrics.get("incident_promotion_rate", 0.0),
            "response_priority": case_meta.get("response_priority", "P4"),
            "suppression_summary": case_meta.get("suppression_summary", {}),
            "telemetry_gap_summary": case_meta.get("telemetry_gap_summary", {}),
            "sigma_summary": case_meta.get("sigma_summary", {}),
            "rule_metrics": case_meta.get("rule_metrics", []),
            "tuning_recommendations": case_meta.get("tuning_recommendations", []),
            "campaign_summary": case_meta.get("campaign_summary", []),
            "collection_quality_summary": case_meta.get("collection_quality_summary", {}),
            "live_collection_summary": case_meta.get("live_collection_summary", {}),
            "raw_event_summary": raw_event_summary,
        },
        "legacy": {
            "alerts": [a.to_dict() for a in legacy_alerts],
            "attack_chains": [c.to_dict() for c in legacy_chains],
        },
        "raw_events": raw_event_preview,
    }
    data = sanitize_export_data(data)

    with open(filepath, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
    return data


def export(*args, **kwargs):
    """Backward-compatible export wrapper.

    Legacy mode: export(alerts, chains, filepath)
    Case mode: export_case(...) via keyword args or explicit lists.
    """
    if len(args) == 3 and isinstance(args[0], list) and isinstance(args[1], list) and isinstance(args[2], str):
        alerts: List[Alert] = args[0]
        chains: List[AttackChain] = args[1]
        filepath: str = args[2]
        data = {
            "findings": [a.to_dict() for a in alerts],
            "attack_chains": [c.to_dict() for c in chains],
            "summary": {
                "total_alerts": len(alerts),
                "total_chains": len(chains),
                "by_severity": dict(Counter(a.severity for a in alerts)),
                "by_tactic": dict(Counter(a.mitre_tactic for a in alerts)),
            },
        }
        data = sanitize_export_data(data)
        with open(filepath, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)
        return data

    return export_case(**kwargs)
