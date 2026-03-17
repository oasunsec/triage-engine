"""Timeline export for signals, findings, and incidents."""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Dict, List

from models.event_model import Finding, Incident, Signal
from triage_engine.export_sanitizer import sanitize_export_data
from triage_engine.user_utils import normalize_user_identity


def _iso(ts):
    return ts.isoformat() if ts else None


def _display(value: str) -> str:
    return value or "unknown"


def _user_fields(value: str, host: str) -> Dict[str, str]:
    identity = normalize_user_identity(value, host)
    return {
        "raw": identity["raw"],
        "canonical": identity["canonical"],
        "display": identity["display"] or _display(identity["raw"]),
    }


def _timeline_row_from_signal(signal: Signal) -> Dict:
    script_excerpt = signal.evidence.get("script_excerpt", "")
    user = _user_fields(signal.user, signal.host)
    subject_user = _user_fields(signal.subject_user, signal.host)
    target_user = _user_fields(signal.target_user, signal.host)
    account_name = _user_fields(signal.account_name, signal.host)
    return {
        "type": "signal",
        "id": signal.id,
        "display_label": signal.display_label,
        "timestamp": _iso(signal.timestamp),
        "title": signal.source_rule,
        "severity": signal.severity,
        "confidence": signal.confidence,
        "host": signal.host,
        "host_display": _display(signal.host),
        "user": signal.user,
        "user_raw": user["raw"],
        "user_canonical": user["canonical"],
        "user_display": _display(user["display"]),
        "subject_user": signal.subject_user,
        "subject_user_raw": subject_user["raw"],
        "subject_user_canonical": subject_user["canonical"],
        "subject_user_display": _display(subject_user["display"]),
        "target_user": signal.target_user,
        "target_user_raw": target_user["raw"],
        "target_user_canonical": target_user["canonical"],
        "target_user_display": _display(target_user["display"]),
        "account_name": signal.account_name,
        "account_name_raw": account_name["raw"],
        "account_name_canonical": account_name["canonical"],
        "account_name_display": _display(account_name["display"]),
        "source_ip": signal.source_ip,
        "source_ip_display": _display(signal.source_ip),
        "process": signal.process,
        "process_display": _display(signal.process),
        "parent_process": signal.parent_process,
        "command_line": signal.command_line,
        "service": signal.service,
        "share_name": signal.share_name,
        "script_excerpt": script_excerpt,
        "remote_url": signal.evidence.get("remote_url", ""),
        "task_name": signal.evidence.get("task_name", ""),
        "created_username": signal.evidence.get("created_username", ""),
        "technique": signal.mitre_technique,
        "tactic": signal.mitre_tactic,
        "summary": signal.description,
        "recommended_next": signal.recommended_next,
        "context": {
            **signal.evidence,
            "confidence_factors": list(signal.confidence_factors),
            "telemetry_gaps": list(signal.telemetry_gaps),
            "promotion_policy": signal.promotion_policy,
            "rule_source": signal.rule_source,
        },
        "related_ids": {
            "finding_ids": [],
            "incident_ids": [],
        },
    }


def _timeline_row_from_finding(finding: Finding) -> Dict:
    script_excerpt = finding.evidence.get("script_excerpt", "")
    user = _user_fields(finding.user, finding.host)
    subject_user = _user_fields(finding.subject_user, finding.host)
    target_user = _user_fields(finding.target_user, finding.host)
    account_name = _user_fields(finding.account_name, finding.host)
    return {
        "type": "finding",
        "id": finding.id,
        "display_label": finding.display_label,
        "timestamp": _iso(finding.first_seen),
        "end_timestamp": _iso(finding.last_seen),
        "title": finding.title,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "host": finding.host,
        "host_display": _display(finding.host),
        "user": finding.user,
        "user_raw": user["raw"],
        "user_canonical": user["canonical"],
        "user_display": _display(user["display"]),
        "subject_user": finding.subject_user,
        "subject_user_raw": subject_user["raw"],
        "subject_user_canonical": subject_user["canonical"],
        "subject_user_display": _display(subject_user["display"]),
        "target_user": finding.target_user,
        "target_user_raw": target_user["raw"],
        "target_user_canonical": target_user["canonical"],
        "target_user_display": _display(target_user["display"]),
        "account_name": finding.account_name,
        "account_name_raw": account_name["raw"],
        "account_name_canonical": account_name["canonical"],
        "account_name_display": _display(account_name["display"]),
        "source_ip": finding.source_ip,
        "source_ip_display": _display(finding.source_ip),
        "process": finding.process,
        "process_display": _display(finding.process),
        "parent_process": finding.parent_process,
        "command_line": finding.command_line,
        "service": finding.service,
        "share_name": finding.share_name,
        "script_excerpt": script_excerpt,
        "remote_url": finding.evidence.get("remote_url", ""),
        "task_name": finding.evidence.get("task_name", ""),
        "created_username": finding.evidence.get("created_username", ""),
        "summary": finding.description or finding.summary,
        "recommended_next": finding.recommended_next,
        "context": {
            **finding.evidence,
            "confidence_factors": list(finding.confidence_factors),
            "promotion_reasons": list(finding.promotion_reasons),
            "telemetry_gaps": list(finding.telemetry_gaps),
            "recommended_pivots": list(finding.recommended_pivots),
        },
        "related_ids": {
            "signal_ids": list(finding.signal_ids),
            "incident_ids": [],
        },
    }


def _timeline_row_from_incident(incident: Incident) -> Dict:
    script_excerpt = ""
    evidence_chain = incident.evidence_chain or []
    for step in evidence_chain:
        excerpt = step.get("script_excerpt", "")
        if excerpt:
            script_excerpt = excerpt
            break
    user = _user_fields(incident.user, incident.host)
    subject_user = _user_fields(incident.subject_user, incident.host)
    target_user = _user_fields(incident.target_user, incident.host)
    account_name = _user_fields(incident.account_name, incident.host)
    return {
        "type": "incident",
        "id": incident.id,
        "display_label": incident.display_label,
        "timestamp": _iso(incident.first_seen),
        "end_timestamp": _iso(incident.last_seen),
        "title": incident.title,
        "severity": incident.severity,
        "confidence": incident.confidence,
        "host": incident.host,
        "host_display": _display(incident.host),
        "user": incident.user,
        "user_raw": user["raw"],
        "user_canonical": user["canonical"],
        "user_display": _display(user["display"]),
        "subject_user": incident.subject_user,
        "subject_user_raw": subject_user["raw"],
        "subject_user_canonical": subject_user["canonical"],
        "subject_user_display": _display(subject_user["display"]),
        "target_user": incident.target_user,
        "target_user_raw": target_user["raw"],
        "target_user_canonical": target_user["canonical"],
        "target_user_display": _display(target_user["display"]),
        "account_name": incident.account_name,
        "account_name_raw": account_name["raw"],
        "account_name_canonical": account_name["canonical"],
        "account_name_display": _display(account_name["display"]),
        "source_ip": incident.source_ip,
        "source_ip_display": _display(incident.source_ip),
        "process": incident.process,
        "process_display": _display(incident.process),
        "parent_process": incident.parent_process,
        "command_line": incident.command_line,
        "service": incident.service,
        "share_name": incident.share_name,
        "script_excerpt": script_excerpt,
        "remote_url": next((step.get("remote_url", "") for step in evidence_chain if step.get("remote_url")), ""),
        "task_name": next((step.get("task_name", "") for step in evidence_chain if step.get("task_name")), ""),
        "created_username": next((step.get("created_username", "") for step in evidence_chain if step.get("created_username")), ""),
        "technique": incident.technique_summary,
        "summary": incident.summary,
        "recommended_next": incident.recommended_next,
        "context": {
            "evidence_chain": incident.evidence_chain,
            "confidence_factors": list(incident.confidence_factors),
            "promotion_reasons": list(incident.promotion_reasons),
            "telemetry_gaps": list(incident.telemetry_gaps),
            "recommended_pivots": list(incident.recommended_pivots),
            "why_flagged": incident.why_flagged,
        },
        "related_ids": {
            "signal_ids": list(incident.signal_ids),
            "finding_ids": list(incident.finding_ids),
        },
    }


def export(signals: List[Signal], findings: List[Finding], incidents: List[Incident], filepath: str) -> Dict:
    signal_to_findings = defaultdict(list)
    signal_to_incidents = defaultdict(list)
    finding_to_incidents = defaultdict(list)
    finding_by_id = {finding.id: finding for finding in findings}
    findings_by_signal = defaultdict(list)

    for finding in findings:
        for sid in finding.signal_ids:
            signal_to_findings[sid].append(finding.id)
            findings_by_signal[sid].append(finding)

    for incident in incidents:
        for sid in incident.signal_ids:
            signal_to_incidents[sid].append(incident.id)
        for fid in incident.finding_ids:
            finding_to_incidents[fid].append(incident.id)

    hidden_signal_ids = set()
    for signal in signals:
        related_findings = findings_by_signal.get(signal.id, [])
        if len(related_findings) != 1:
            continue
        if _same_activity(signal, related_findings[0]):
            hidden_signal_ids.add(signal.id)

    rows = []
    for signal in signals:
        if signal.id in hidden_signal_ids:
            continue
        row = _timeline_row_from_signal(signal)
        row["related_ids"]["finding_ids"] = sorted(set(signal_to_findings.get(signal.id, [])))
        row["related_ids"]["incident_ids"] = sorted(set(signal_to_incidents.get(signal.id, [])))
        rows.append(row)

    for finding in findings:
        row = _timeline_row_from_finding(finding)
        row["related_ids"]["incident_ids"] = sorted(set(finding_to_incidents.get(finding.id, [])))
        row["related_ids"]["suppressed_signal_ids"] = [
            sid for sid in finding.signal_ids if sid in hidden_signal_ids
        ]
        rows.append(row)

    rows.extend(_timeline_row_from_incident(i) for i in incidents)
    rows.sort(key=lambda r: (r.get("timestamp") is None, r.get("timestamp") or "", r.get("id", "")))

    data = {
        "timeline": rows,
        "summary": {
            "signals": len(signals),
            "findings": len(findings),
            "incidents": len(incidents),
            "total_rows": len(rows),
            "suppressed_signal_rows": len(hidden_signal_ids),
        },
    }
    data = sanitize_export_data(data)

    with open(filepath, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)

    return data


def _same_activity(signal: Signal, finding: Finding) -> bool:
    if finding.signal_ids != [signal.id]:
        return False
    return (
        (signal.source_rule or "") == (finding.title or "")
        and (_iso(signal.timestamp) == _iso(finding.first_seen))
        and (signal.host or "") == (finding.host or "")
        and (signal.user or "") == (finding.user or "")
        and (signal.source_ip or "") == (finding.source_ip or "")
        and (signal.process or "") == (finding.process or "")
        and (signal.command_line or "") == (finding.command_line or "")
    )
