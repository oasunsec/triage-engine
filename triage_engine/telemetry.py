"""Telemetry availability and response-priority helpers."""

from __future__ import annotations

from collections import Counter
from typing import Dict, Iterable, List

from models.event_model import Incident, NormalizedEvent


REQUIRED_TELEMETRY = {
    "security": "Security",
    "sysmon": "Sysmon",
    "powershell": "PowerShell",
}

SUPPLEMENTAL_TELEMETRY = {
    "windows defender": "Windows Defender",
    "wmi-activity": "WMI-Activity",
    "codeintegrity": "CodeIntegrity",
    "terminalservices": "TerminalServices",
    "taskscheduler": "TaskScheduler",
}


def summarize_telemetry(events: Iterable[NormalizedEvent]) -> Dict[str, object]:
    channels = Counter()
    providers = Counter()
    present = {key: False for key in REQUIRED_TELEMETRY}
    supplemental_present: List[str] = []

    for event in events:
        channel = (event.channel or "").strip()
        provider = (event.provider or "").strip()
        if channel:
            channels[channel] += 1
        if provider:
            providers[provider] += 1
        channel_lower = channel.lower()
        provider_lower = provider.lower()
        if channel_lower == "security" or "security-auditing" in provider_lower:
            present["security"] = True
        if "sysmon" in channel_lower or "sysmon" in provider_lower:
            present["sysmon"] = True
        if "powershell" in channel_lower or "powershell" in provider_lower or event.event_id in {400, 403, 600, 800, 4103, 4104}:
            present["powershell"] = True
        for marker, label in SUPPLEMENTAL_TELEMETRY.items():
            if marker in channel_lower or marker in provider_lower:
                if label not in supplemental_present:
                    supplemental_present.append(label)

    missing = [label for key, label in REQUIRED_TELEMETRY.items() if not present[key]]
    core_present = [label for key, label in REQUIRED_TELEMETRY.items() if present[key]]
    return {
        "present": core_present,
        "missing": missing,
        "supplemental_present": supplemental_present,
        "observed": core_present + [label for label in supplemental_present if label not in core_present],
        "channels": dict(channels.most_common()),
        "providers": dict(providers.most_common()),
    }


def response_priority(incidents: List[Incident], case_meta: Dict[str, object]) -> str:
    if not incidents:
        return "P4"
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    score = max(
        severity_rank.get((incident.severity or "").lower(), 1) * 25 + int(incident.confidence_score or 0)
        for incident in incidents
    )
    host_count = len(case_meta.get("hosts", []) or [])
    if host_count >= 2:
        score += 10
    tactic_count = max(
        (
            len({step.get("tactic", "") for step in (incident.evidence_chain or []) if step.get("tactic", "")})
            for incident in incidents
        ),
        default=0,
    )
    if tactic_count >= 2:
        score += 5
    if score >= 170:
        return "P1"
    if score >= 130:
        return "P2"
    if score >= 90:
        return "P3"
    return "P4"
