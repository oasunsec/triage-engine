"""Adapters from legacy Alert/AttackChain objects to Signal/Finding/Incident models."""

from __future__ import annotations

import json
import os
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Sequence, Tuple

from models.event_model import Alert, Signal, Finding, Incident
from triage_engine.confidence import infer_promotion_policy, score_finding, score_signal, score_to_confidence, suspicious_context_factors
from triage_engine.id_utils import stable_id
from triage_engine.user_utils import normalize_user_identity, safe_user_displays


FINDING_SEVERITIES = {"critical", "high"}
SUSPICIOUS_SERVICE_MARKERS = (
    "psexe",
    "paexec",
    "remcom",
    "csexec",
    "\\users\\",
    "\\programdata\\",
    "\\temp\\",
    "\\appdata\\",
    "powershell",
    "cmd.exe",
    "rundll32",
    "regsvr32",
    "mshta",
    "wscript",
    "cscript",
)
STRICT_CORRELATION_RULES = {
    "Local Account Enumeration",
}
CORROBORATING_RULE_GROUPS = {
    "Local Account Enumeration": {"Local Account Enumeration", "Local Group Enumeration"},
    "Local Group Enumeration": {"Local Account Enumeration", "Local Group Enumeration"},
}


def _event_payload(alert: Alert) -> dict:
    event = alert.event
    return {
        "rule_name": alert.rule_name,
        "severity": alert.severity,
        "mitre_tactic": alert.mitre_tactic,
        "mitre_technique": alert.mitre_technique,
        "description": alert.description,
        "timestamp": alert.timestamp,
        "host": alert.host,
        "user": alert.user,
        "source_ip": alert.source_ip,
        "destination_ip": alert.destination_ip,
        "subject_user": alert.subject_user,
        "target_user": alert.target_user,
        "account_name": alert.account_name,
        "process": alert.process,
        "parent_process": alert.parent_process,
        "service": alert.service,
        "share_name": alert.share_name,
        "command_line": event.command_line if event else "",
        "event_id": event.event_id if event else None,
        "event_data": dict(sorted((event.event_data or {}).items())) if event else {},
    }


def _finding_candidate(alert: Alert, related_alert_count: int, promote_overrides: dict[str, Sequence[str]] | None = None) -> tuple[bool, List[str], str]:
    promotion_policy = infer_promotion_policy(alert, promote_overrides=promote_overrides)
    reasons: List[str] = [f"promotion_policy:{promotion_policy}"]
    evidence_strength = str((alert.evidence or {}).get("evidence_strength", "")).lower().strip()
    if evidence_strength in {"weak", "low"}:
        return False, reasons + ["weak_evidence"], promotion_policy
    if (alert.rule_name or "") == "Service Installed" and not _suspicious_service_install(alert):
        return False, reasons + ["service_not_suspicious"], promotion_policy
    if promotion_policy == "signal_only":
        return False, reasons + ["signal_only_policy"], promotion_policy
    if (alert.confidence or "").lower() == "low" and (alert.severity or "").lower() not in {"critical"}:
        return False, reasons + ["low_confidence"], promotion_policy

    if promotion_policy == "standalone":
        reasons.append("standalone_rule")
        return True, reasons, promotion_policy

    suspicious_factors = suspicious_context_factors(alert)
    if related_alert_count >= 2:
        reasons.append("corroborated_by_related_alerts")
    if suspicious_factors:
        reasons.extend(suspicious_factors)
    if (alert.evidence or {}).get("deduplicated_count", 0):
        reasons.append("time_clustered")
    if evidence_strength == "high":
        reasons.append("high_evidence_strength")
    high_confidence_source = (alert.confidence or "").lower() == "high"
    if high_confidence_source:
        reasons.append("high_confidence_source")
    high_confidence_autopromote = high_confidence_source and (alert.rule_name or "") not in STRICT_CORRELATION_RULES

    if (
        related_alert_count >= 2
        or evidence_strength == "high"
        or high_confidence_autopromote
        or bool(suspicious_factors)
        or (alert.severity or "").lower() == "critical"
        or (alert.rule_name or "") in set(promote_overrides.get("standalone", []) if promote_overrides else [])
    ):
        return True, reasons, promotion_policy

    return False, reasons + ["insufficient_corroboration"], promotion_policy


def _suspicious_service_install(alert: Alert) -> bool:
    service_name = str((alert.evidence or {}).get("service_name", "")).lower()
    binary = str((alert.evidence or {}).get("binary", "")).lower()
    account = str((alert.evidence or {}).get("account", "")).lower()

    if any(marker in service_name or marker in binary for marker in SUSPICIOUS_SERVICE_MARKERS):
        return True

    if account and account not in {"localsystem", "localservice", "networkservice"}:
        return True

    return False


def _related_alert_counts(alerts: List[Alert], window_minutes: int = 30) -> Dict[int, int]:
    counts: Dict[int, int] = {}
    window = timedelta(minutes=window_minutes)
    for idx, alert in enumerate(alerts):
        correlated_rules = CORROBORATING_RULE_GROUPS.get(alert.rule_name, {alert.rule_name})
        if not alert.timestamp:
            counts[idx] = 1
            continue
        count = 0
        for candidate in alerts:
            if candidate.rule_name not in correlated_rules:
                continue
            if (candidate.host or "") != (alert.host or ""):
                continue
            if candidate.user and alert.user and candidate.user != alert.user:
                continue
            if not candidate.timestamp:
                continue
            if abs(candidate.timestamp - alert.timestamp) <= window:
                count += 1
        counts[idx] = max(count, 1)
    return counts


def _alert_source_image(alert: Alert) -> str:
    event = alert.event
    evidence = dict(alert.evidence or {})
    return (
        str(evidence.get("source_image") or "")
        or str(evidence.get("source") or "")
        or str(alert.process or "")
        or str((event.event_data or {}).get("SourceImage") if event else "")
    )


def _alert_target_image(alert: Alert) -> str:
    event = alert.event
    evidence = dict(alert.evidence or {})
    return (
        str(evidence.get("target_image") or "")
        or str(evidence.get("target") or "")
        or str((event.event_data or {}).get("TargetImage") if event else "")
    )


def _contextual_signal_only_alerts(alerts: List[Alert]) -> set[int]:
    """Keep generic overlapping alerts visible as signals without duplicating a richer finding."""
    keepass_contexts: List[tuple[str, str, str, datetime]] = []
    mimikatz_contexts: List[tuple[str, str, str, datetime]] = []
    unmanaged_powershell_contexts: List[tuple[str, str, str, datetime]] = []
    for alert in alerts:
        rule_name = alert.rule_name or ""
        if not alert.timestamp:
            continue
        if rule_name == "KeePass Master Key Theft":
            keepass_contexts.append(
                (
                    (alert.host or "").lower(),
                    _alert_source_image(alert).lower(),
                    _alert_target_image(alert).lower(),
                    alert.timestamp,
                )
            )
        if rule_name == "Mimikatz LSASS Access":
            mimikatz_contexts.append(
                (
                    (alert.host or "").lower(),
                    _alert_source_image(alert).lower(),
                    _alert_target_image(alert).lower(),
                    alert.timestamp,
                )
            )
        if rule_name == "Unmanaged PowerShell Injection":
            unmanaged_powershell_contexts.append(
                (
                    (alert.host or "").lower(),
                    _alert_source_image(alert).lower(),
                    _alert_target_image(alert).lower(),
                    alert.timestamp,
                )
            )

    if not keepass_contexts and not mimikatz_contexts and not unmanaged_powershell_contexts:
        return set()

    signal_only_indices: set[int] = set()
    for idx, alert in enumerate(alerts):
        rule_name = alert.rule_name or ""
        if not alert.timestamp:
            continue
        host = (alert.host or "").lower()
        source = _alert_source_image(alert).lower()
        target = _alert_target_image(alert).lower()

        if rule_name == "Remote Thread Injection" and "keepass.exe" in target:
            for ctx_host, ctx_source, ctx_target, ctx_time in keepass_contexts:
                if host != ctx_host:
                    continue
                if source and ctx_source and source != ctx_source:
                    continue
                if target and ctx_target and target != ctx_target:
                    continue
                if abs(alert.timestamp - ctx_time) <= timedelta(seconds=5):
                    signal_only_indices.add(idx)
                    break

        if rule_name == "LSASS Memory Access":
            for ctx_host, ctx_source, ctx_target, ctx_time in mimikatz_contexts:
                if host != ctx_host:
                    continue
                if source and ctx_source and source != ctx_source:
                    continue
                if target and ctx_target and target != ctx_target:
                    continue
                if abs(alert.timestamp - ctx_time) <= timedelta(seconds=5):
                    signal_only_indices.add(idx)
                    break

        if rule_name == "Remote Thread Injection":
            for ctx_host, ctx_source, ctx_target, ctx_time in unmanaged_powershell_contexts:
                if host != ctx_host:
                    continue
                if source and ctx_source and source != ctx_source:
                    continue
                if target and ctx_target and target != ctx_target:
                    continue
                if abs(alert.timestamp - ctx_time) <= timedelta(seconds=30):
                    signal_only_indices.add(idx)
                    break
    return signal_only_indices


def alerts_to_signals_findings(
    alerts: List[Alert],
    *,
    telemetry_gaps: Sequence[str] | None = None,
    promotion_overrides: dict[str, Sequence[str]] | None = None,
) -> Tuple[List[Signal], List[Finding], Dict[int, str]]:
    """Create signal/finding objects from legacy alerts while keeping deterministic IDs."""
    signals_by_id: Dict[str, Signal] = {}
    findings_by_id: Dict[str, Finding] = {}
    signal_by_alert_index: Dict[int, str] = {}
    related_counts = _related_alert_counts(alerts)
    contextual_signal_only_indices = _contextual_signal_only_alerts(alerts)

    for idx, alert in enumerate(alerts):
        alert.promotion_policy = infer_promotion_policy(alert, promote_overrides=promotion_overrides)
        if idx in contextual_signal_only_indices:
            alert.promotion_policy = "signal_only"
            alert.evidence = {
                **dict(alert.evidence or {}),
                "contextual_signal_only": (
                    "keepass_master_key_theft_overlap"
                    if (alert.rule_name or "") == "Remote Thread Injection"
                    and "keepass" in _alert_target_image(alert).lower()
                    else (
                        "unmanaged_powershell_injection_overlap"
                        if (alert.rule_name or "") == "Remote Thread Injection"
                        else "mimikatz_lsass_access_overlap"
                    )
                ),
            }
        payload = _event_payload(alert)
        signal_id = stable_id("sig", payload)
        signal_by_alert_index[idx] = signal_id

        if signal_id not in signals_by_id:
            event = alert.event
            signal_ioc_matches = list((alert.evidence or {}).get("ioc_matches", []))
            score, factors = score_signal(alert, telemetry_gaps=telemetry_gaps, ioc_matches=signal_ioc_matches)
            signal_confidence = score_to_confidence(score)
            signals_by_id[signal_id] = Signal(
                id=signal_id,
                display_label="",
                source_rule=alert.rule_name,
                severity=alert.severity,
                mitre_tactic=alert.mitre_tactic,
                mitre_technique=alert.mitre_technique,
                description=alert.description,
                confidence=signal_confidence,
                confidence_score=score,
                confidence_factors=factors,
                timestamp=alert.timestamp,
                host=alert.host,
                user=alert.user,
                source_ip=alert.source_ip,
                destination_ip=alert.destination_ip,
                subject_user=alert.subject_user,
                target_user=alert.target_user,
                account_name=alert.account_name,
                process=alert.process,
                parent_process=alert.parent_process,
                service=alert.service,
                share_name=alert.share_name,
                command_line=event.command_line if event else "",
                recommended_next=alert.investigate_next,
                promotion_policy=alert.promotion_policy,
                evidence={**dict(alert.evidence), "promotion_policy": alert.promotion_policy},
                raw_event_data=dict(event.event_data) if event else {},
                ioc_matches=signal_ioc_matches,
                telemetry_gaps=list(telemetry_gaps or []),
                rule_source=alert.rule_source,
            )

        should_promote, promotion_reasons, promotion_policy = _finding_candidate(
            alert,
            related_counts.get(idx, 1),
            promote_overrides=promotion_overrides,
        )
        if not should_promote:
            continue

        finding_payload = {
            "title": alert.rule_name,
            "severity": alert.severity,
            "confidence": alert.confidence,
            "signal_ids": [signal_id],
            "host": alert.host,
            "user": alert.user,
            "source_ip": alert.source_ip,
            "destination_ip": alert.destination_ip,
            "subject_user": alert.subject_user,
            "target_user": alert.target_user,
            "account_name": alert.account_name,
            "process": alert.process,
            "parent_process": alert.parent_process,
            "service": alert.service,
            "share_name": alert.share_name,
            "timestamp": alert.timestamp,
            "description": alert.description,
        }
        finding_id = stable_id("fnd", finding_payload)
        if finding_id in findings_by_id:
            continue

        event = alert.event
        signal_ref = signals_by_id[signal_id]
        ioc_matches = list(signal_ref.ioc_matches)
        score, finding_confidence, factors = score_finding(
            base_score=signal_ref.confidence_score,
            signal_count=max(related_counts.get(idx, 1), 1),
            telemetry_gaps=telemetry_gaps,
            ioc_matches=ioc_matches,
            extra_factors=signal_ref.confidence_factors,
        )
        findings_by_id[finding_id] = Finding(
            id=finding_id,
            display_label="",
            title=alert.rule_name,
            severity=alert.severity,
            confidence=finding_confidence,
            confidence_score=score,
            confidence_factors=factors,
            description=alert.description,
            summary=alert.explanation,
            first_seen=alert.timestamp,
            last_seen=alert.timestamp,
            signal_ids=[signal_id],
            host=alert.host,
            user=alert.user,
            source_ip=alert.source_ip,
            destination_ip=alert.destination_ip,
            subject_user=alert.subject_user,
            target_user=alert.target_user,
            account_name=alert.account_name,
            process=alert.process,
            parent_process=alert.parent_process,
            service=alert.service,
            share_name=alert.share_name,
            command_line=event.command_line if event else "",
            recommended_next=alert.investigate_next,
            recommended_pivots=list(alert.recommended_pivots),
            promotion_reasons=promotion_reasons,
            telemetry_gaps=list(telemetry_gaps or []),
            evidence={
                "source_rule": alert.rule_name,
                "investigate_next": alert.investigate_next,
                "recommended_pivots": alert.recommended_pivots,
                "promotion_policy": promotion_policy,
                **dict(alert.evidence),
            },
            ioc_matches=ioc_matches,
        )

    signals = list(signals_by_id.values())
    findings = list(findings_by_id.values())
    return signals, findings, signal_by_alert_index


def apply_ioc_enrichment(
    signals: List[Signal], findings: List[Finding], incidents: List[Incident], ioc_path: str
) -> None:
    """Optional IOC enrichment that increases confidence if an entity matches IOC intel."""
    if not os.path.isfile(ioc_path):
        return

    try:
        with open(ioc_path, "r", encoding="utf-8") as handle:
            iocs = json.load(handle)
    except Exception:
        return

    ip_iocs = {str(v).strip().lower() for v in iocs.get("ip", [])}
    domain_iocs = {str(v).strip().lower() for v in iocs.get("domain", [])}
    hash_iocs = {str(v).strip().lower() for v in iocs.get("hash", [])}
    path_iocs = {str(v).strip().lower() for v in iocs.get("file_path", [])}

    def enrich_object(obj) -> None:
        matches = set(getattr(obj, "ioc_matches", []) or [])
        source_ip = (getattr(obj, "source_ip", "") or "").strip().lower()
        command = (getattr(obj, "command_line", "") or "").strip().lower()

        if source_ip and source_ip in ip_iocs:
            matches.add(f"ip:{source_ip}")

        for indicator in domain_iocs:
            if indicator and indicator in command:
                matches.add(f"domain:{indicator}")

        for indicator in hash_iocs:
            if indicator and indicator in command:
                matches.add(f"hash:{indicator}")

        for indicator in path_iocs:
            if indicator and indicator in command:
                matches.add(f"file_path:{indicator}")

        if not matches:
            return

        obj.ioc_matches = sorted(matches)
        current = int(getattr(obj, "confidence_score", 50) or 50)
        obj.confidence_score = min(100, current + 10)
        obj.confidence = score_to_confidence(obj.confidence_score)
        factors = list(getattr(obj, "confidence_factors", []) or [])
        if "ioc_match" not in factors:
            factors.append("ioc_match")
        obj.confidence_factors = factors

    for item in signals:
        enrich_object(item)
    for item in findings:
        enrich_object(item)
    for item in incidents:
        enrich_object(item)


def summarize_case_entities(signals: List[Signal], findings: List[Finding], incidents: List[Incident]) -> dict:
    """Return high-level entity aggregates used by summary and incident brief outputs."""
    hosts = defaultdict(int)
    users = defaultdict(int)
    ips = defaultdict(int)
    user_hosts: Dict[str, str] = {}

    for collection in (signals, findings, incidents):
        for item in collection:
            if item.host:
                hosts[item.host] += 1
            if item.user:
                identity = normalize_user_identity(item.user, item.host)
                canonical_user = identity["canonical"] or identity["raw"]
                if canonical_user:
                    users[canonical_user] += 1
                    if item.host:
                        user_hosts.setdefault(canonical_user, item.host)
            if item.source_ip and item.source_ip != "-":
                ips[item.source_ip] += 1

    user_display_map = safe_user_displays(users.keys(), user_hosts)
    primary_user_key = max(users, key=users.get) if users else ""

    return {
        "primary_host": max(hosts, key=hosts.get) if hosts else "",
        "primary_user": user_display_map.get(primary_user_key, primary_user_key) if primary_user_key else "",
        "primary_user_canonical": primary_user_key,
        "primary_source_ip": max(ips, key=ips.get) if ips else "",
        "hosts": sorted(hosts.keys()),
        "users": [user_display_map.get(user, user) for user in sorted(users.keys())],
        "users_canonical": sorted(users.keys()),
        "ips": sorted(ips.keys()),
    }
