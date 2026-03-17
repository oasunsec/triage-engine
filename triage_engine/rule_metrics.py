"""Per-rule case metrics and tuning hints."""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Dict, Iterable, List


def _safe_ratio(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round(float(numerator) / float(denominator), 4)


def build_rule_metrics(raw_alerts, filtered_alerts, deduped_alerts, signals, findings, incidents) -> List[dict]:
    raw_by_rule = Counter(alert.rule_name for alert in raw_alerts)
    filtered_by_rule = Counter(alert.rule_name for alert in filtered_alerts)
    deduped_by_rule = Counter(alert.rule_name for alert in deduped_alerts)
    signals_by_rule = Counter(signal.source_rule for signal in signals)
    findings_by_rule = Counter(finding.title for finding in findings)

    finding_by_id = {finding.id: finding for finding in findings}
    incidents_by_rule = defaultdict(int)
    for incident in incidents:
        matched_rules = {
            finding_by_id[finding_id].title
            for finding_id in (incident.finding_ids or [])
            if finding_id in finding_by_id
        }
        for rule_name in matched_rules:
            incidents_by_rule[rule_name] += 1

    all_rules = (
        set(raw_by_rule)
        | set(filtered_by_rule)
        | set(deduped_by_rule)
        | set(signals_by_rule)
        | set(findings_by_rule)
        | set(incidents_by_rule)
    )
    rows: List[dict] = []
    for rule_name in sorted(all_rules):
        raw = int(raw_by_rule.get(rule_name, 0))
        filtered = int(filtered_by_rule.get(rule_name, 0))
        deduped = int(deduped_by_rule.get(rule_name, 0))
        suppressed = max(0, raw - filtered)
        deduplicated = max(0, filtered - deduped)
        signal_count = int(signals_by_rule.get(rule_name, 0))
        finding_count = int(findings_by_rule.get(rule_name, 0))
        incident_count = int(incidents_by_rule.get(rule_name, 0))
        rows.append(
            {
                "rule": rule_name,
                "raw_alert_count": raw,
                "suppressed_alert_count": suppressed,
                "post_filter_alert_count": filtered,
                "deduplicated_alert_count": deduplicated,
                "post_dedup_alert_count": deduped,
                "signal_count": signal_count,
                "finding_count": finding_count,
                "incident_count": incident_count,
                "suppression_rate": _safe_ratio(suppressed, raw),
                "deduplication_rate": _safe_ratio(deduplicated, filtered),
                "finding_promotion_rate": _safe_ratio(finding_count, signal_count),
                "incident_promotion_rate": _safe_ratio(incident_count, finding_count),
            }
        )
    rows.sort(
        key=lambda row: (
            -int(row["raw_alert_count"]),
            -int(row["finding_count"]),
            -int(row["incident_count"]),
            str(row["rule"]).lower(),
        )
    )
    return rows


def build_tuning_recommendations(rule_metrics: Iterable[dict], limit: int = 8) -> List[dict]:
    recommendations: List[dict] = []
    for row in rule_metrics:
        raw = int(row.get("raw_alert_count", 0) or 0)
        suppressed = int(row.get("suppressed_alert_count", 0) or 0)
        post = int(row.get("post_filter_alert_count", 0) or 0)
        finding_count = int(row.get("finding_count", 0) or 0)
        incident_count = int(row.get("incident_count", 0) or 0)
        suppression_rate = float(row.get("suppression_rate", 0.0) or 0.0)
        finding_rate = float(row.get("finding_promotion_rate", 0.0) or 0.0)

        suggestion = ""
        reason = ""
        if raw >= 3 and suppressed >= 2 and finding_count == 0:
            suggestion = "review_allowlist_or_rule_suppression"
            reason = "Most hits for this rule were suppressed and none promoted into findings."
        elif raw >= 2 and post >= 2 and finding_count == 0:
            suggestion = "review_signal_only_or_correlate_policy"
            reason = "This rule kept generating post-filter alerts but did not promote into findings."
        elif finding_count >= 2 and incident_count == 0 and finding_rate >= 0.8:
            suggestion = "review_incident_correlation_coverage"
            reason = "This rule promotes strongly into findings but rarely contributes to an incident narrative."
        elif suppression_rate >= 0.75 and raw >= 2:
            suggestion = "verify_existing_suppression_is_environment_safe"
            reason = "Suppression is doing most of the work for this rule; confirm the behavior is consistently benign."

        if suggestion:
            recommendations.append(
                {
                    "rule": row.get("rule", ""),
                    "suggestion": suggestion,
                    "reason": reason,
                    "metrics": {
                        "raw_alert_count": raw,
                        "suppressed_alert_count": suppressed,
                        "post_filter_alert_count": post,
                        "finding_count": finding_count,
                        "incident_count": incident_count,
                    },
                }
            )
        if len(recommendations) >= limit:
            break
    return recommendations
