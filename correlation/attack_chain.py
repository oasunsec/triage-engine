"""Attack chain correlation with deduplication and incident narratives."""

import uuid
from datetime import timedelta
from collections import defaultdict, Counter
from typing import List, Dict, Tuple
from models.event_model import Alert, AttackChain

TACTIC_ORDER = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery",
    "Lateral Movement", "Collection", "Exfiltration", "Impact",
]


def deduplicate(alerts: List[Alert], window_seconds: int = 30) -> List[Alert]:
    """Merge duplicate alerts: same rule + same user + same host within window."""
    if not alerts:
        return []

    alerts_sorted = sorted(
        [a for a in alerts if a.timestamp],
        key=lambda a: (a.rule_name, a.host, a.user, a.timestamp)
    )

    merged = []
    skip = set()

    for i, a in enumerate(alerts_sorted):
        if i in skip:
            continue
        count = 1
        # Look ahead for duplicates
        for j in range(i + 1, len(alerts_sorted)):
            b = alerts_sorted[j]
            if j in skip:
                continue
            if (b.rule_name == a.rule_name and b.host == a.host
                    and b.user == a.user
                    and abs((b.timestamp - a.timestamp).total_seconds()) <= window_seconds):
                count += 1
                skip.add(j)
            elif b.rule_name != a.rule_name or b.host != a.host:
                break

        if count > 1:
            a.description += f" [{count} occurrences]"
            a.evidence["deduplicated_count"] = count
        merged.append(a)

    # Add back alerts without timestamps
    merged.extend(a for a in alerts if a.timestamp is None)
    return merged


def correlate(alerts: List[Alert], window_minutes: int = 60) -> List[AttackChain]:
    """Group alerts into attack chains by host and temporal proximity."""
    if not alerts:
        return []

    window = timedelta(minutes=window_minutes)
    chains = []

    by_host: Dict[str, List[Alert]] = defaultdict(list)
    for a in alerts:
        by_host[a.host or "unknown"].append(a)

    for host, host_alerts in by_host.items():
        sorted_alerts = sorted(
            [a for a in host_alerts if a.timestamp],
            key=lambda a: a.timestamp
        )
        if not sorted_alerts:
            continue

        current = [sorted_alerts[0]]
        for i in range(1, len(sorted_alerts)):
            a = sorted_alerts[i]
            if (a.timestamp - current[-1].timestamp) <= window:
                current.append(a)
            else:
                if len(current) >= 2:
                    chains.append(_build_chain(host, current))
                current = [a]

        if len(current) >= 2:
            chains.append(_build_chain(host, current))

    chains.sort(key=lambda c: c.risk_score, reverse=True)
    return chains


def _build_chain(host: str, alerts: List[Alert]) -> AttackChain:
    tactics = list(dict.fromkeys(a.mitre_tactic for a in alerts))

    tactic_positions = [TACTIC_ORDER.index(t) for t in tactics if t in TACTIC_ORDER]
    risk = min(100, len(alerts) * 10 + len(set(a.mitre_tactic for a in alerts)) * 15)
    if len(tactic_positions) >= 2 and sorted(tactic_positions) == tactic_positions:
        risk = min(100, risk + 20)  # progression bonus

    narrative = _build_narrative(host, alerts, tactics)

    return AttackChain(
        chain_id=str(uuid.uuid4())[:8],
        host=host, alerts=alerts, tactics=tactics,
        risk_score=risk,
        start_time=alerts[0].timestamp,
        end_time=alerts[-1].timestamp,
        summary=narrative,
    )


def _build_narrative(host: str, alerts: List[Alert], tactics: List[str]) -> str:
    """Generate a human-readable incident narrative from the chain."""
    parts = []
    users = set(a.user for a in alerts if a.user)
    ips = set(a.source_ip for a in alerts if a.source_ip and a.source_ip != "-")
    duration = ""
    if alerts[0].timestamp and alerts[-1].timestamp:
        secs = (alerts[-1].timestamp - alerts[0].timestamp).total_seconds()
        if secs < 60:
            duration = f"{int(secs)}s"
        elif secs < 3600:
            duration = f"{int(secs/60)}m"
        else:
            duration = f"{secs/3600:.1f}h"

    parts.append(f"Incident on {host}")
    if duration:
        parts.append(f"spanning {duration}")
    if users:
        parts.append(f"involving {', '.join(list(users)[:3])}")

    # Build tactic-specific narrative segments
    tactic_alerts: Dict[str, List[Alert]] = defaultdict(list)
    for a in alerts:
        tactic_alerts[a.mitre_tactic].append(a)

    segments = []
    if "Credential Access" in tactic_alerts:
        ca = tactic_alerts["Credential Access"]
        segments.append(f"credential attack ({len(ca)} alerts: {ca[0].rule_name})")
    if "Defense Evasion" in tactic_alerts:
        de = tactic_alerts["Defense Evasion"]
        segments.append(f"evasion activity ({de[0].rule_name})")
    if "Persistence" in tactic_alerts:
        p = tactic_alerts["Persistence"]
        segments.append(f"persistence via {p[0].rule_name}")
    if "Lateral Movement" in tactic_alerts:
        lm = tactic_alerts["Lateral Movement"]
        src_ips = set()
        dst_hosts = set()
        for a in lm:
            if a.source_ip and a.source_ip != "-":
                src_ips.add(a.source_ip)
            dst = a.evidence.get("destination_host", "")
            if dst:
                dst_hosts.add(dst)
        seg = f"lateral movement ({len(lm)} events"
        if src_ips:
            seg += f" from {', '.join(list(src_ips)[:2])}"
        if dst_hosts:
            seg += f" to {', '.join(list(dst_hosts)[:2])}"
        seg += ")"
        segments.append(seg)

    if segments:
        parts.append("— " + " → ".join(segments))

    return " ".join(parts) + f" [{len(alerts)} total alerts across {len(tactics)} tactics]"
