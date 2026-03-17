"""Case-level multi-host campaign summaries for analyst context."""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, Iterable, List, Tuple

from triage_engine.user_utils import normalize_user_identity

BENIGN_IPS = {"", "-", "127.0.0.1", "::1", "0.0.0.0", "fe80::1", "::ffff:127.0.0.1"}


def _iso(ts) -> str:
    return ts.isoformat() if ts else ""


def _host(item) -> str:
    return str(getattr(item, "host", "") or "").strip()


def _title(item) -> str:
    return str(getattr(item, "title", "") or getattr(item, "source_rule", "") or "").strip()


def _item_time(item):
    return getattr(item, "first_seen", None) or getattr(item, "timestamp", None) or getattr(item, "last_seen", None)


def _collect_rows(items: Iterable, key_type: str) -> List[dict]:
    buckets: Dict[str, List] = defaultdict(list)
    display_map: Dict[str, str] = {}
    for item in items:
        host = _host(item)
        if key_type == "user":
            identity = normalize_user_identity(getattr(item, "user", ""), host)
            key = identity["canonical"]
            display = identity["display"] or identity["canonical"]
        else:
            key = str(getattr(item, "source_ip", "") or "").strip()
            display = key
            if key in BENIGN_IPS:
                key = ""
        if not key:
            continue
        buckets[key].append(item)
        display_map[key] = display

    rows: List[dict] = []
    for key, grouped in buckets.items():
        hosts = sorted({_host(item) for item in grouped if _host(item)})
        if len(hosts) < 2:
            continue
        findings = sorted(
            {
                getattr(item, "id", "")
                for item in grouped
                if getattr(item, "id", "") and hasattr(item, "signal_ids") and not hasattr(item, "finding_ids")
            }
        )
        incidents = sorted(
            {
                getattr(item, "id", "")
                for item in grouped
                if getattr(item, "id", "") and hasattr(item, "finding_ids")
            }
        )
        titles = []
        seen_titles = set()
        for item in grouped:
            title = _title(item)
            if title and title not in seen_titles:
                seen_titles.add(title)
                titles.append(title)
        times = [value for value in (_item_time(item) for item in grouped) if value]
        rows.append(
            {
                "key_type": key_type,
                "key_value": key,
                "display_value": display_map.get(key, key),
                "host_count": len(hosts),
                "hosts": hosts,
                "artifact_count": len(grouped),
                "finding_count": len(findings),
                "incident_count": len(incidents),
                "finding_ids": findings,
                "incident_ids": incidents,
                "titles": titles[:5],
                "first_seen": _iso(min(times) if times else None),
                "last_seen": _iso(max(times) if times else None),
                "summary": _campaign_summary_text(key_type, display_map.get(key, key), hosts, grouped, titles),
            }
        )
    return rows


def _campaign_summary_text(key_type: str, value: str, hosts: List[str], grouped: List, titles: List[str]) -> str:
    actor = "Shared user" if key_type == "user" else "Shared source IP"
    title_text = ", ".join(titles[:3]) if titles else "related suspicious activity"
    return f"{actor} {value} appears across {len(hosts)} hosts with {len(grouped)} related artifacts, including {title_text}."


def build_campaign_summary(signals, findings, incidents) -> List[dict]:
    rows = []
    rows.extend(_collect_rows(incidents or findings or signals, "user"))
    rows.extend(_collect_rows(incidents or findings or signals, "ip"))
    rows.sort(
        key=lambda row: (
            -int(row["host_count"]),
            -int(row["artifact_count"]),
            -int(row["incident_count"]),
            str(row["display_value"]).lower(),
        )
    )
    return rows
