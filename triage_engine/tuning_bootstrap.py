"""Helpers for bootstrapping a reviewable local tuning profile from a case."""

from __future__ import annotations

import copy
import json
import os
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List

from triage_engine.tuning import DEFAULT_TUNING


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _top_counts(mapping: Dict[str, int] | None, limit: int = 10) -> List[Dict[str, int | str]]:
    if not isinstance(mapping, dict):
        return []
    ordered = sorted(mapping.items(), key=lambda item: (-int(item[1]), str(item[0]).lower()))
    return [{"name": name, "count": int(count)} for name, count in ordered[:limit] if name]


def _top_rules(case_data: Dict[str, Any], limit: int = 15) -> List[Dict[str, int | str]]:
    counts: Counter[str] = Counter()
    for alert in (case_data.get("legacy", {}) or {}).get("alerts", []) or []:
        rule_name = str(alert.get("rule_name") or alert.get("title") or "").strip()
        if rule_name:
            counts[rule_name] += 1
    return [{"rule": rule, "count": count} for rule, count in counts.most_common(limit)]


def build_local_tuning_profile(case_data: Dict[str, Any], source_path: str = "") -> Dict[str, Any]:
    case = (case_data or {}).get("case", {}) or {}
    summary = (case_data or {}).get("summary", {}) or {}
    suppression = summary.get("suppression_summary", {}) or case.get("suppression_summary", {}) or {}
    telemetry = case.get("telemetry_summary", {}) or {}
    sigma = summary.get("sigma_summary", {}) or case.get("sigma_summary", {}) or {}

    profile = {
        "metadata": {
            "profile_name": "local",
            "generated_at": _utc_now(),
            "generated_from_case": case.get("case_name", ""),
            "source_findings_path": os.path.abspath(source_path) if source_path else "",
            "response_priority": summary.get("response_priority", case.get("response_priority", "P4")),
            "primary_host": case.get("primary_host", ""),
            "primary_user": case.get("primary_user", ""),
            "primary_source_ip": case.get("primary_source_ip", ""),
            "telemetry_missing": telemetry.get("missing", []),
            "sigma_enabled": bool(sigma.get("enabled")),
            "review_notes": [
                "Keep allowlists as narrow as possible and prefer exact matches.",
                "Prefer full process paths and exact service/task names over broad user allowlists.",
                "Do not suppress high-confidence rules globally without confirming benign ownership.",
            ],
        },
        "allowlists": copy.deepcopy(DEFAULT_TUNING["allowlists"]),
        "rule_suppressions": [],
        "promotion_overrides": {
            "standalone": [],
            "correlate": [],
            "signal_only": [],
        },
        "observed_context": {
            "hosts": list(case.get("hosts", []) or []),
            "users": list(case.get("users", []) or []),
            "ips": list(case.get("ips", []) or []),
            "suppression_reasons": _top_counts(suppression.get("by_reason", {})),
            "suppressed_rules": _top_counts(suppression.get("by_rule", {})),
            "rules_seen": _top_rules(case_data),
        },
        "operator_checklist": [
            "Review the top rules seen before adding any per-rule suppression.",
            "Use allowlists only for tooling and identities you can tie to approved admin workflows.",
            "Re-run the benign benchmark and your own representative cases after each tuning change.",
        ],
    }
    return profile


def write_local_tuning_profile(output_path: str, profile: Dict[str, Any], force: bool = False) -> str:
    abs_path = os.path.abspath(output_path)
    if os.path.exists(abs_path) and not force:
        raise FileExistsError(f"Refusing to overwrite existing tuning file: {abs_path}")
    os.makedirs(os.path.dirname(abs_path), exist_ok=True)
    with open(abs_path, "w", encoding="utf-8") as handle:
        json.dump(profile, handle, indent=2)
        handle.write("\n")
    return abs_path
