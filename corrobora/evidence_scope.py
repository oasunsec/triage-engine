"""Per-host evidence scope for a case.

A single upload can mix unrelated hosts or archives collected months apart.
Correlation will still join them into one case, so every consumer (API,
report, bundle) needs the same explicit statement of what the evidence covers
and a per-host breakdown to judge whether the verdict applies to each host.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

from corrobora.product import derive_disposition
from corrobora.telemetry import response_priority

SCOPE_SCHEMA_VERSION = "1.1"
LONG_WINDOW_DAYS = 7
_SEVERITY_RANK = {"informational": 0, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _host_key(value: str) -> str:
    return str(value or "").strip().lower()


def _short_name(value: str) -> str:
    return _host_key(value).split(".", 1)[0]


def _iso(value: Optional[datetime]) -> str:
    return value.isoformat() if value else ""


def _span_days(first: Optional[datetime], last: Optional[datetime]) -> float:
    if not first or not last:
        return 0.0
    try:
        return round(max(0.0, (last - first).total_seconds() / 86400.0), 2)
    except TypeError:
        # Mixed naive/aware timestamps cannot be compared reliably.
        return 0.0


def _max_severity(current: str, candidate: str) -> str:
    cand = str(candidate or "").strip().lower()
    if _SEVERITY_RANK.get(cand, -1) > _SEVERITY_RANK.get(current, -1):
        return cand
    return current


def _host_verdict(host: str, findings: List[Any], incidents: List[Any], telemetry_gaps: List[str]) -> Dict[str, Any]:
    """Score one host on its own evidence; no multi-host bonus leaks in from the case."""
    priority = response_priority(incidents, {"hosts": [host]})
    confidence = max(
        [int(getattr(item, "confidence_score", 0) or 0) for item in list(incidents) + list(findings)] + [0]
    )
    reasons: List[str] = []
    if incidents:
        titles = [str(getattr(item, "title", "") or "").strip() for item in incidents]
        top = next((title for title in titles if title), "")
        reasons.append(f"{len(incidents)} incident(s) on this host" + (f", including: {top}" if top else ""))
    if findings:
        reasons.append(f"{len(findings)} finding(s) on this host")
    triage = derive_disposition(
        incident_count=len(incidents),
        finding_count=len(findings),
        response_priority=priority,
        confidence_score=confidence,
        telemetry_gaps=telemetry_gaps,
        reasons=reasons or ["No findings attributed to this host"],
    )
    return {
        "disposition": triage.disposition,
        "response_priority": priority,
        "confidence": triage.confidence,
        "confidence_score": triage.confidence_score,
        "reasons": triage.reasons,
    }


def build_evidence_scope(
    events: Iterable[Any],
    findings: Iterable[Any] = (),
    incidents: Iterable[Any] = (),
    *,
    telemetry_gaps: Optional[Iterable[str]] = None,
    long_window_days: int = LONG_WINDOW_DAYS,
) -> Dict[str, Any]:
    """Summarize which hosts and time ranges the case evidence covers, with a verdict per host."""
    gaps = list(telemetry_gaps or [])
    hosts: Dict[str, Dict[str, Any]] = {}
    short_index: Dict[str, str] = {}

    def entry_for(raw_host: str) -> Dict[str, Any]:
        key = _host_key(raw_host) or "(unknown host)"
        if key not in hosts:
            # Findings often carry a short hostname while events carry the FQDN.
            alias = short_index.get(_short_name(key))
            if alias:
                return hosts[alias]
            hosts[key] = {
                "host": str(raw_host or "").strip() or "(unknown host)",
                "event_count": 0,
                "finding_count": 0,
                "incident_count": 0,
                "max_severity": "",
                "_first": None,
                "_last": None,
                "_findings": [],
                "_incidents": [],
            }
            short_index.setdefault(_short_name(key), key)
        return hosts[key]

    all_first: Optional[datetime] = None
    all_last: Optional[datetime] = None
    for event in events:
        entry = entry_for(getattr(event, "computer", "") or "")
        entry["event_count"] += 1
        stamp = getattr(event, "timestamp", None)
        if not stamp:
            continue
        try:
            if entry["_first"] is None or stamp < entry["_first"]:
                entry["_first"] = stamp
            if entry["_last"] is None or stamp > entry["_last"]:
                entry["_last"] = stamp
            if all_first is None or stamp < all_first:
                all_first = stamp
            if all_last is None or stamp > all_last:
                all_last = stamp
        except TypeError:
            continue

    for kind, items in (("finding_count", findings), ("incident_count", incidents)):
        for item in items:
            host = getattr(item, "host", "") or ""
            if not host:
                continue
            entry = entry_for(host)
            entry[kind] += 1
            entry["_findings" if kind == "finding_count" else "_incidents"].append(item)
            entry["max_severity"] = _max_severity(entry["max_severity"], getattr(item, "severity", ""))

    rows: List[Dict[str, Any]] = []
    for entry in hosts.values():
        first, last = entry.pop("_first"), entry.pop("_last")
        host_findings, host_incidents = entry.pop("_findings"), entry.pop("_incidents")
        entry["verdict"] = _host_verdict(entry["host"], host_findings, host_incidents, gaps)
        entry["first_seen"] = _iso(first)
        entry["last_seen"] = _iso(last)
        entry["span_days"] = _span_days(first, last)
        rows.append(entry)
    priority_rank = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
    rows.sort(key=lambda row: (
        priority_rank.get(row["verdict"]["response_priority"], 4),
        -row["incident_count"], -row["finding_count"], -row["event_count"], row["host"].lower(),
    ))

    named_hosts = [row for row in rows if row["host"] != "(unknown host)"]
    span_days = _span_days(all_first, all_last)
    mixed_hosts = len(named_hosts) > 1
    long_window = span_days > long_window_days
    warnings: List[str] = []
    if mixed_hosts:
        with_detections = [row["host"] for row in named_hosts if row["finding_count"] or row["incident_count"]]
        warnings.append(
            f"Evidence comes from {len(named_hosts)} hosts"
            + (f"; detections on {len(with_detections)} of them." if with_detections else ".")
            + " Confirm they belong to the same investigation before treating correlated activity as one incident."
        )
    verdict_counts = Counter(row["verdict"]["disposition"] for row in named_hosts)
    split_verdict = mixed_hosts and len(verdict_counts) > 1
    if split_verdict:
        escalate = [row["host"] for row in named_hosts if row["verdict"]["disposition"] == "Escalate"]
        if escalate:
            warnings.append(
                f"Escalation applies to {', '.join(escalate[:5])}"
                + (f" and {len(escalate) - 5} more" if len(escalate) > 5 else "")
                + "; review the other hosts on their own verdicts."
            )
    if long_window:
        warnings.append(
            f"Evidence spans {span_days:.0f} days. Older activity may be unrelated to the reported issue."
        )

    return {
        "schema_version": SCOPE_SCHEMA_VERSION,
        "host_count": len(named_hosts),
        "first_seen": _iso(all_first),
        "last_seen": _iso(all_last),
        "span_days": span_days,
        "mixed_hosts": mixed_hosts,
        "long_window": long_window,
        "long_window_threshold_days": long_window_days,
        "needs_scope_review": mixed_hosts or long_window,
        "split_verdict": split_verdict,
        "host_verdict_counts": dict(verdict_counts),
        "warnings": warnings,
        "hosts": rows,
    }
