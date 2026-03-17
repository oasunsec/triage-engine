"""Confidence and promotion helpers for signals, findings, and incidents."""

from __future__ import annotations

from typing import Iterable, List, Sequence

from models.event_model import Alert


SUSPICIOUS_PROCESS_MARKERS = (
    "powershell",
    "pwsh",
    "cmd.exe",
    "rundll32",
    "regsvr32",
    "mshta",
    "wscript",
    "cscript",
    "installutil",
    "certutil",
    "wmic",
    "mimikatz",
    "psexec",
    "remcom",
    "paexec",
    "winrm",
    "schtasks",
)
SUSPICIOUS_PARENT_MARKERS = (
    "services.exe",
    "wmiprvse.exe",
    "winlogon.exe",
    "svchost.exe",
    "taskeng.exe",
    "taskhost",
    "mmc.exe",
    "explorer.exe",
)
RARE_PATH_MARKERS = (
    "\\users\\",
    "\\appdata\\",
    "\\programdata\\",
    "\\temp\\",
    "\\windows\\tasks\\",
    "\\windows\\installer\\",
)


def _unique(values: Iterable[str]) -> List[str]:
    seen = set()
    ordered: List[str] = []
    for value in values:
        clean = str(value or "").strip()
        if not clean or clean in seen:
            continue
        seen.add(clean)
        ordered.append(clean)
    return ordered


def score_to_confidence(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 75:
        return "high"
    if score >= 55:
        return "medium"
    return "low"


def evidence_strength_from_alert(alert: Alert) -> str:
    return str((alert.evidence or {}).get("evidence_strength", "")).strip().lower()


def infer_promotion_policy(alert: Alert, promote_overrides: dict[str, Sequence[str]] | None = None) -> str:
    overrides = promote_overrides or {}
    rule_name = (alert.rule_name or "").strip()
    if rule_name in set(overrides.get("signal_only", []) or []):
        return "signal_only"
    if rule_name in set(overrides.get("standalone", []) or []):
        return "standalone"
    if rule_name in set(overrides.get("correlate", []) or []):
        return "correlate"

    explicit = str(getattr(alert, "promotion_policy", "") or "").strip().lower()
    if explicit in {"standalone", "correlate", "signal_only"}:
        return explicit

    evidence_strength = evidence_strength_from_alert(alert)
    confidence = (alert.confidence or "").strip().lower()
    severity = (alert.severity or "").strip().lower()
    if evidence_strength == "high" and confidence in {"high", "critical"}:
        return "standalone"
    if severity == "critical" and evidence_strength in {"high", "medium"}:
        return "standalone"
    if evidence_strength in {"high", "medium"} or confidence == "high" or severity in {"high", "critical"}:
        return "correlate"
    return "signal_only"


def suspicious_context_factors(alert: Alert) -> List[str]:
    factors: List[str] = []
    process = (alert.process or "").lower()
    parent = (alert.parent_process or "").lower()
    command = (alert.event.command_line if alert.event else "") or ""
    registry_key = (alert.registry_key or "").lower()
    service = (alert.service or "").lower()

    if any(marker in process for marker in SUSPICIOUS_PROCESS_MARKERS):
        factors.append("rare_process")
    if any(marker in parent for marker in SUSPICIOUS_PARENT_MARKERS):
        factors.append("suspicious_parent")
    lowered_command = command.lower()
    if any(marker in lowered_command for marker in RARE_PATH_MARKERS):
        factors.append("suspicious_path")
    if service and any(marker in service for marker in ("psexe", "remcom", "paexec", "ssh", "winrm")):
        factors.append("suspicious_service")
    if registry_key and any(marker in registry_key for marker in ("\\run", "\\runonce", "\\image file execution options", "\\app paths", "\\sam\\")):
        factors.append("sensitive_registry")
    return _unique(factors)


def alert_confidence_factors(alert: Alert, telemetry_gaps: Sequence[str] | None = None, ioc_matches: Sequence[str] | None = None) -> List[str]:
    factors: List[str] = []
    strength = evidence_strength_from_alert(alert)
    if strength == "high":
        factors.append("high_evidence_strength")
    if strength == "medium":
        factors.append("moderate_evidence_strength")
    factors.extend(suspicious_context_factors(alert))
    if (alert.evidence or {}).get("deduplicated_count", 0):
        factors.append("time_clustered")
    if ioc_matches:
        factors.append("ioc_match")
    if telemetry_gaps:
        factors.append("missing_required_telemetry")
    return _unique(factors)


def score_signal(alert: Alert, telemetry_gaps: Sequence[str] | None = None, ioc_matches: Sequence[str] | None = None) -> tuple[int, List[str]]:
    confidence = (alert.confidence or "medium").lower()
    severity = (alert.severity or "medium").lower()
    score = {"low": 35, "medium": 52, "high": 70, "critical": 82}.get(confidence, 52)
    score += {"low": 0, "medium": 4, "high": 8, "critical": 12}.get(severity, 4)
    factors = alert_confidence_factors(alert, telemetry_gaps=telemetry_gaps, ioc_matches=ioc_matches)
    if "high_evidence_strength" in factors:
        score += 10
    if "moderate_evidence_strength" in factors:
        score += 5
    if "ioc_match" in factors:
        score += 12
    if "time_clustered" in factors:
        score += 6
    if "rare_process" in factors:
        score += 5
    if "suspicious_parent" in factors:
        score += 5
    if "suspicious_service" in factors:
        score += 4
    if "sensitive_registry" in factors:
        score += 4
    if "missing_required_telemetry" in factors:
        score -= 8
    return max(1, min(100, score)), factors


def score_finding(
    *,
    base_score: int,
    signal_count: int,
    telemetry_gaps: Sequence[str] | None = None,
    ioc_matches: Sequence[str] | None = None,
    extra_factors: Sequence[str] | None = None,
) -> tuple[int, str, List[str]]:
    factors = _unique(list(extra_factors or []))
    score = int(base_score)
    if signal_count >= 2:
        score += 10
        factors.append("multi_signal")
    if signal_count >= 3:
        score += 4
    if ioc_matches:
        score += 8
        factors.append("ioc_match")
    if telemetry_gaps:
        score -= 10
        factors.append("missing_required_telemetry")
    score = max(1, min(100, score))
    return score, score_to_confidence(score), _unique(factors)


def score_incident(
    *,
    base_score: int,
    signal_count: int,
    finding_count: int,
    host_count: int = 1,
    tactic_count: int = 1,
    telemetry_gaps: Sequence[str] | None = None,
    ioc_matches: Sequence[str] | None = None,
    extra_factors: Sequence[str] | None = None,
) -> tuple[int, str, List[str]]:
    factors = _unique(list(extra_factors or []))
    score = int(base_score)
    if signal_count >= 2:
        score += 8
        factors.append("multi_signal")
    if finding_count >= 2:
        score += 8
    if host_count >= 2:
        score += 8
        factors.append("cross_host")
    if tactic_count >= 2:
        score += 6
    if ioc_matches:
        score += 8
        factors.append("ioc_match")
    if telemetry_gaps:
        score -= 10
        factors.append("missing_required_telemetry")
    score = max(1, min(100, score))
    return score, score_to_confidence(score), _unique(factors)

