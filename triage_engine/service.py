"""Shared investigation service — the single source of truth for the investigation pipeline.

Both the CLI and the API server call this module.  Neither should duplicate
pipeline logic.  The contract is:

    result = run_investigation(request, reporter)

Where *request* describes what to investigate and *reporter* receives
progress callbacks so the caller (CLI or server) can display or persist
status updates however it wants.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import traceback
from collections import Counter
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from threading import Lock, Thread
from time import monotonic
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

# ---------------------------------------------------------------------------
# Path bootstrap — keeps the module usable from a source checkout
# ---------------------------------------------------------------------------
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from correlation.attack_chain import correlate, deduplicate
from correlation.entity_graph import build_entity_graph
from correlation.incident_builder import build_incidents
from detectors import (
    behavioral,
    credential_access,
    defense_evasion,
    lateral_movement,
    persistence,
    powershell_script,
)
from detectors.fp_filter import FPFilter
from parser.evtx_reader import describe_evtx_path, read_evtx_path
from parser.live_reader import read_live
from reporting.graph_export import export as export_graph
from reporting.html_report import generate_from_artifacts
from reporting.json_export import export_case, export_raw_events_stream
from reporting.timeline_export import export as export_timeline
from triage_engine.adapters import (
    alerts_to_signals_findings,
    apply_ioc_enrichment,
    summarize_case_entities,
)
from triage_engine.campaigns import build_campaign_summary
from triage_engine.case_utils import auto_case_name, ensure_case_dir
from triage_engine.confidence import score_incident
from triage_engine.display import display_input_source, sanitize_display_values
from triage_engine.export_sanitizer import apply_demo_redaction_text
from triage_engine.id_utils import assign_display_labels
from triage_engine.playbooks import apply_playbook
from triage_engine.rule_metrics import build_rule_metrics, build_tuning_recommendations
from triage_engine.status import RunStatus
from triage_engine.telemetry import response_priority, summarize_telemetry
from triage_engine.tuning import load_tuning

# Optional sigma — tolerate missing PyYAML gracefully
try:
    from triage_engine.sigma_loader import load_rules as load_sigma_rules
    from triage_engine.sigma_runner import evaluate_rules as run_sigma_rules

    SIGMA_AVAILABLE = True
except Exception:
    SIGMA_AVAILABLE = False


INVESTIGATION_TIMEOUT_ENV = "TRIAGE_INVESTIGATION_TIMEOUT_SECONDS"
DETECTOR_TIMEOUT_ENV = "TRIAGE_DETECTOR_TIMEOUT_SECONDS"
DEFAULT_INVESTIGATION_TIMEOUT_SECONDS = 1800
DEFAULT_DETECTOR_TIMEOUT_SECONDS = 30
SERVICE_LOGGER = logging.getLogger("triage.service")


# ---------------------------------------------------------------------------
# Public contract dataclasses
# ---------------------------------------------------------------------------

@dataclass
class InvestigationRequest:
    """Everything the caller needs to specify to kick off an investigation."""

    input_source: str
    input_mode: str = "evtx_path"  # "evtx_path" | "live"
    case_name: Optional[str] = None
    cases_dir: Optional[str] = None
    request_id: str = ""
    requested_by: str = ""
    overwrite: bool = False
    resume: bool = False

    # EVTX filtering
    start_date: Optional[date] = None
    end_date: Optional[date] = None

    # Live-mode settings
    channels: Optional[List[str]] = None
    since_minutes: Optional[int] = None

    # Sigma
    enable_sigma: bool = False
    sigma_rule_paths: List[str] = field(default_factory=list)

    # Tuning / FP
    tuning_paths: List[str] = field(default_factory=list)
    no_fp_filter: bool = False


@runtime_checkable
class ProgressReporter(Protocol):
    """Callback protocol so CLI/server can track progress in their own way."""

    def on_stage(self, stage: str, message: str) -> None: ...
    def on_metadata(self, key: str, value: Any) -> None: ...
    def on_artifact(self, path: str) -> None: ...
    def on_diagnostic(self, message: str) -> None: ...
    def on_complete(self, message: str) -> None: ...
    def on_failed(self, stage: str, error: str, traceback_text: Optional[str] = None) -> None: ...
    def on_parse_progress(self, update: dict) -> None: ...


@dataclass
class InvestigationResult:
    """Returned after a successful investigation."""

    case_name: str
    case_path: str
    input_source: str

    signal_count: int = 0
    finding_count: int = 0
    incident_count: int = 0

    case_metrics: Dict[str, Any] = field(default_factory=dict)
    suppression_summary: Dict[str, Any] = field(default_factory=dict)
    telemetry_summary: Dict[str, Any] = field(default_factory=dict)
    sigma_summary: Dict[str, Any] = field(default_factory=dict)
    collection_quality_summary: Dict[str, Any] = field(default_factory=dict)
    response_priority: str = "P4"

    artifacts: Dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Null reporter — used when caller doesn't care about progress
# ---------------------------------------------------------------------------

class NullReporter:
    """Silent reporter — satisfies the protocol but does nothing."""

    def on_stage(self, stage: str, message: str) -> None:
        pass

    def on_metadata(self, key: str, value: Any) -> None:
        pass

    def on_artifact(self, path: str) -> None:
        pass

    def on_diagnostic(self, message: str) -> None:
        pass

    def on_complete(self, message: str) -> None:
        pass

    def on_failed(self, stage: str, error: str, traceback_text: Optional[str] = None) -> None:
        pass

    def on_parse_progress(self, update: dict) -> None:
        pass


# ---------------------------------------------------------------------------
# RunStatus adapter — bridges ProgressReporter into the existing RunStatus
# ---------------------------------------------------------------------------

class _RunStatusReporter:
    """Wraps RunStatus as a ProgressReporter, forwarding calls to both
    the RunStatus file writer and an optional external reporter."""

    def __init__(self, run_status: RunStatus, external: Optional[ProgressReporter] = None):
        self._rs = run_status
        self._ext = external

    def on_stage(self, stage: str, message: str) -> None:
        self._rs.stage(stage, message)
        if self._ext:
            self._ext.on_stage(stage, message)

    def on_metadata(self, key: str, value: Any) -> None:
        self._rs.set_metadata(key, value)
        if self._ext:
            self._ext.on_metadata(key, value)

    def on_artifact(self, path: str) -> None:
        self._rs.add_artifact(path)
        if self._ext:
            self._ext.on_artifact(path)

    def on_diagnostic(self, message: str) -> None:
        self._rs.add_diagnostic(message)
        if self._ext:
            self._ext.on_diagnostic(message)

    def on_complete(self, message: str) -> None:
        self._rs.complete(message)
        if self._ext:
            self._ext.on_complete(message)

    def on_failed(self, stage: str, error: str, traceback_text: Optional[str] = None) -> None:
        self._rs.fail(stage, error, traceback_text)
        if self._ext:
            self._ext.on_failed(stage, error, traceback_text)

    def on_parse_progress(self, update: dict) -> None:
        if self._ext:
            self._ext.on_parse_progress(update)


# ---------------------------------------------------------------------------
# Internal helpers — moved here from cli.py (single copy)
# ---------------------------------------------------------------------------

def _int_env(name: str, default: int, *, minimum: int = 1, maximum: int = 24 * 60 * 60) -> int:
    raw = (os.environ.get(name, "") or "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return max(minimum, min(value, maximum))


def _append_partial_failure(
    partial_failures: List[Dict[str, Any]],
    *,
    component: str,
    name: str,
    reason: str,
    detail: str = "",
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    entry = {
        "component": component,
        "name": name,
        "reason": reason,
        "detail": detail,
    }
    if extra:
        entry.update(extra)
    partial_failures.append(entry)
    return entry


def _run_detector_with_timeout(
    detector_name: str,
    detector_fn,
    events: list,
    timeout_seconds: int,
) -> Dict[str, Any]:
    alerts_holder: Dict[str, Any] = {}
    error_holder: Dict[str, Any] = {}

    def _target() -> None:
        try:
            alerts_holder["alerts"] = detector_fn(events)
        except Exception as exc:  # pragma: no cover - error path
            error_holder["error"] = str(exc)
            error_holder["traceback"] = traceback.format_exc()

    started = monotonic()
    worker = Thread(target=_target, name=f"detector-{detector_name}", daemon=True)
    worker.start()
    worker.join(timeout=max(1, timeout_seconds))
    elapsed_seconds = round(monotonic() - started, 3)

    if worker.is_alive():
        return {
            "status": "timeout",
            "alerts": [],
            "runtime_seconds": elapsed_seconds,
            "error": f"Detector '{detector_name}' exceeded timeout ({timeout_seconds}s).",
        }

    if "error" in error_holder:
        return {
            "status": "error",
            "alerts": [],
            "runtime_seconds": elapsed_seconds,
            "error": str(error_holder.get("error", "")),
            "traceback": str(error_holder.get("traceback", "")),
        }

    alerts = alerts_holder.get("alerts", [])
    if not isinstance(alerts, list):
        return {
            "status": "error",
            "alerts": [],
            "runtime_seconds": elapsed_seconds,
            "error": f"Detector '{detector_name}' returned unexpected payload type.",
        }

    return {
        "status": "ok",
        "alerts": alerts,
        "runtime_seconds": elapsed_seconds,
    }


def _run_detectors(
    events: list,
    *,
    timeout_seconds: int,
    partial_failures: List[Dict[str, Any]],
    diagnostic_callback=None,
) -> tuple[list, Dict[str, int]]:
    all_alerts: list = []
    detector_timings: Dict[str, int] = {}
    for detector_name, detector_fn in [
        ("credential_access", credential_access.detect),
        ("persistence", persistence.detect),
        ("lateral_movement", lateral_movement.detect),
        ("defense_evasion", defense_evasion.detect),
        ("powershell_script", powershell_script.detect),
        ("behavioral", behavioral.detect),
    ]:
        result = _run_detector_with_timeout(detector_name, detector_fn, events, timeout_seconds)
        detector_timings[f"{detector_name}_ms"] = int(float(result.get("runtime_seconds", 0.0)) * 1000)
        if result.get("status") == "ok":
            all_alerts.extend(result.get("alerts", []))
            continue

        reason = "timeout" if result.get("status") == "timeout" else "error"
        detail = str(result.get("error", "") or "")
        _append_partial_failure(
            partial_failures,
            component="detector",
            name=detector_name,
            reason=reason,
            detail=detail,
            extra={
                "timeout_seconds": timeout_seconds,
                "runtime_seconds": float(result.get("runtime_seconds", 0.0)),
            },
        )
        if diagnostic_callback:
            diagnostic_callback(f"detector_{reason}:{detector_name}:{detail}")
    return all_alerts, detector_timings


def _event_time_bounds(events) -> tuple[Optional[datetime], Optional[datetime]]:
    timed = [e.timestamp for e in events if e.timestamp]
    if not timed:
        return None, None
    return min(timed), max(timed)


def _safe_ratio(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round(float(numerator) / float(denominator), 4)


def _fallback_case_entities(events: list) -> dict:
    hosts: Counter = Counter()
    users: Counter = Counter()
    ips: Counter = Counter()
    for event in events:
        if event.computer:
            hosts[event.computer] += 1
        actor = (
            event.domain_user
            or event.target_domain_user
            or event.subject_domain_user
            or event.account_name
            or event.logon_user
        )
        if actor and actor not in {"-", "unknown"}:
            users[actor] += 1
        ip = event.source_ip or event.destination_ip
        if ip and ip not in {"-", "unknown"}:
            ips[ip] += 1
    return {
        "primary_host": max(hosts, key=hosts.get) if hosts else "",
        "primary_user": max(users, key=users.get) if users else "",
        "primary_source_ip": max(ips, key=ips.get) if ips else "",
        "hosts": sorted(hosts, key=hosts.get, reverse=True),
        "users": sorted(users, key=users.get, reverse=True),
        "users_canonical": sorted(users, key=users.get, reverse=True),
        "ips": sorted(ips, key=ips.get, reverse=True),
    }


def _enrich_incidents(incidents, signals, findings, telemetry_gaps) -> None:
    signals_by_id = {s.id: s for s in signals}
    findings_by_id = {f.id: f for f in findings}
    for incident in incidents:
        related_signals = [signals_by_id[sid] for sid in incident.signal_ids if sid in signals_by_id]
        related_findings = [findings_by_id[fid] for fid in incident.finding_ids if fid in findings_by_id]
        hosts = {
            item.host
            for item in [incident] + related_signals + related_findings
            if getattr(item, "host", "")
        }
        tactics = {s.mitre_tactic for s in related_signals if getattr(s, "mitre_tactic", "")}
        tactics.update(
            step.get("tactic", "")
            for step in (incident.evidence_chain or [])
            if step.get("tactic", "")
        )
        ioc_matches = set(incident.ioc_matches or [])
        factor_seed = list(incident.confidence_factors or [])
        for item in related_signals + related_findings:
            ioc_matches.update(getattr(item, "ioc_matches", []) or [])
            factor_seed.extend(getattr(item, "confidence_factors", []) or [])
        signal_count = len(related_signals)
        finding_count = len(related_findings)
        host_count = max(1, len(hosts))
        tactic_count = max(1, len(tactics))

        score, confidence, factors = score_incident(
            base_score=int(incident.confidence_score or 50),
            signal_count=signal_count,
            finding_count=finding_count,
            host_count=host_count,
            tactic_count=tactic_count,
            telemetry_gaps=telemetry_gaps,
            ioc_matches=sorted(ioc_matches),
            extra_factors=factor_seed,
        )
        incident.confidence_score = score
        incident.confidence = confidence
        incident.confidence_factors = factors
        incident.telemetry_gaps = list(telemetry_gaps or [])
        incident.ioc_matches = sorted(ioc_matches)

        reasons = list(incident.promotion_reasons or [])
        if finding_count:
            reasons.append(f"correlated_findings:{finding_count}")
        if signal_count:
            reasons.append(f"correlated_signals:{signal_count}")
        if host_count >= 2:
            reasons.append("cross_host_correlation")
        if tactic_count >= 2:
            reasons.append("multi_tactic_sequence")
        if incident.evidence_chain:
            reasons.append(f"evidence_chain_steps:{len(incident.evidence_chain)}")
        if ioc_matches:
            reasons.append("ioc_enriched")
        if telemetry_gaps:
            reasons.append("telemetry_gaps_present")
        incident.promotion_reasons = list(dict.fromkeys(reasons))
        apply_playbook(incident)


def _resolve_sigma_paths(explicit_paths: List[str]) -> List[str]:
    paths = [os.path.abspath(p) for p in explicit_paths if p]
    default_dir = os.path.join(ROOT_DIR, "rules", "sigma")
    if not paths and os.path.isdir(default_dir):
        paths.append(default_dir)
    return paths


def _public_parse_progress(parse_progress: dict) -> dict:
    return {k: v for k, v in parse_progress.items() if k != "_completed_parsed_events"}


def _apply_parse_progress_update(parse_progress: dict, update: dict) -> str:
    status_name = str(update.get("status") or "")
    parse_progress.setdefault("failed_files", [])
    parse_progress.setdefault("warning_count", 0)
    parse_progress.setdefault("last_error", "")
    if status_name == "complete":
        parse_progress["parsed_event_count"] = int(
            update.get("event_count", parse_progress.get("parsed_event_count", 0))
        )
        return status_name

    if status_name == "file_started":
        parse_progress["active_file"] = os.path.basename(update.get("file_path", "") or "")
        parse_progress["active_records_scanned"] = 0
        parse_progress["active_parsed_events"] = 0
        parse_progress["active_skipped_records"] = 0
    elif status_name == "file_progress":
        parse_progress["active_file"] = os.path.basename(update.get("file_path", "") or "")
        parse_progress["active_records_scanned"] = int(
            update.get("records_scanned", parse_progress.get("active_records_scanned", 0))
        )
        parse_progress["active_parsed_events"] = int(
            update.get("parsed_events", parse_progress.get("active_parsed_events", 0))
        )
        parse_progress["active_skipped_records"] = int(
            update.get("skipped_records", parse_progress.get("active_skipped_records", 0))
        )
    elif status_name == "file_complete":
        parse_progress["completed_files"] = int(
            update.get("completed_files", update.get("file_index", parse_progress.get("completed_files", 0)))
        )
        parse_progress["file_count"] = int(update.get("file_count", parse_progress.get("file_count", 0)))
        parse_progress["_completed_parsed_events"] = int(
            parse_progress.get("_completed_parsed_events", 0)
        ) + int(update.get("parsed_events", 0))
        parse_progress["last_file"] = os.path.basename(update.get("file_path", "") or "")
        parse_progress["active_file"] = ""
        parse_progress["active_records_scanned"] = 0
        parse_progress["active_parsed_events"] = 0
        parse_progress["active_skipped_records"] = 0
        parse_progress["fallback_used"] = bool(
            parse_progress.get("fallback_used") or update.get("fallback")
        )
    elif status_name == "file_error":
        parse_progress["completed_files"] = int(
            update.get("completed_files", update.get("file_index", parse_progress.get("completed_files", 0)))
        )
        parse_progress["file_count"] = int(update.get("file_count", parse_progress.get("file_count", 0)))
        parse_progress["last_file"] = os.path.basename(update.get("file_path", "") or "")
        parse_progress["active_file"] = ""
        parse_progress["active_records_scanned"] = 0
        parse_progress["active_parsed_events"] = 0
        parse_progress["active_skipped_records"] = 0
        parse_progress["last_error"] = str(update.get("error", "") or "")
        parse_progress["warning_count"] = int(parse_progress.get("warning_count", 0)) + 1
        failed_file = os.path.basename(update.get("file_path", "") or "")
        if failed_file:
            failed_files = list(parse_progress.get("failed_files", []) or [])
            if failed_file not in failed_files:
                failed_files.append(failed_file)
            parse_progress["failed_files"] = failed_files
        parse_progress["fallback_used"] = bool(
            parse_progress.get("fallback_used") or update.get("fallback")
        )
    else:
        return status_name

    parse_progress["parsed_event_count"] = int(
        parse_progress.get("_completed_parsed_events", 0)
    ) + int(parse_progress.get("active_parsed_events", 0))
    return status_name


def _public_live_progress(live_progress: dict) -> dict:
    return dict(live_progress)


def _apply_live_progress_update(live_progress: dict, update: dict) -> str:
    status_name = str(update.get("status") or "")
    if status_name == "start":
        live_progress["channel_count"] = int(update.get("channel_count", live_progress.get("channel_count", 0)))
        live_progress["channels"] = list(update.get("channels", live_progress.get("channels", [])) or [])
        live_progress["since_minutes"] = int(update.get("since_minutes", live_progress.get("since_minutes", 30)))
        return status_name

    if status_name == "channel_started":
        live_progress["active_channel"] = str(update.get("channel") or "")
    elif status_name == "channel_warning":
        live_progress["warning_count"] = int(live_progress.get("warning_count", 0)) + 1
        channel = str(update.get("channel") or "").strip()
        if channel:
            warning_channels = list(live_progress.get("warning_channels", []) or [])
            if channel not in warning_channels:
                warning_channels.append(channel)
            live_progress["warning_channels"] = warning_channels
        live_progress["last_warning"] = str(update.get("message") or live_progress.get("last_warning", ""))
    elif status_name == "channel_complete":
        live_progress["completed_channels"] = int(
            update.get("completed_channels", update.get("channel_index", live_progress.get("completed_channels", 0)))
        )
        live_progress["channel_count"] = int(update.get("channel_count", live_progress.get("channel_count", 0)))
        live_progress["parsed_event_count"] = int(live_progress.get("parsed_event_count", 0)) + int(
            update.get("parsed_events", 0)
        )
        live_progress["last_channel"] = str(update.get("channel") or "")
        live_progress["active_channel"] = ""
        if update.get("fallback"):
            live_progress["fallback_channels"] = int(live_progress.get("fallback_channels", 0)) + 1
    elif status_name == "complete":
        live_progress["parsed_event_count"] = int(
            update.get("event_count", live_progress.get("parsed_event_count", 0))
        )
        live_progress["channel_count"] = int(update.get("channel_count", live_progress.get("channel_count", 0)))
        live_progress["channels"] = list(update.get("channels", live_progress.get("channels", [])) or [])
        live_progress["since_minutes"] = int(update.get("since_minutes", live_progress.get("since_minutes", 30)))
        live_progress["active_channel"] = ""
    else:
        return status_name

    return status_name


def _build_live_collection_summary(
    live_progress: dict,
    warnings: List[str],
    telemetry_gaps: Optional[List[str]] = None,
) -> dict:
    channels = list(live_progress.get("channels", []) or [])
    warning_channels = list(live_progress.get("warning_channels", []) or [])
    permission_denied_channels: List[str] = []
    recommendations: List[str] = []
    for message in warnings:
        lowered = str(message or "").lower()
        if "access is denied" in lowered or "required privilege is not held" in lowered:
            for channel in warning_channels:
                if channel not in permission_denied_channels:
                    permission_denied_channels.append(channel)

    if permission_denied_channels:
        recommendations.append(
            f"Rerun the live scan with elevated privileges to read: {', '.join(permission_denied_channels)}."
        )
    remaining_telemetry_gaps = [
        gap for gap in list(telemetry_gaps or [])
        if not (gap == "Security" and permission_denied_channels)
    ]
    recommendations.extend(_telemetry_gap_recommendations(remaining_telemetry_gaps))
    if not int(live_progress.get("parsed_event_count", 0)) and not permission_denied_channels:
        recommendations.append("If you expected activity in this window, widen the live lookback and include additional channels.")

    summary_bits = [
        f"Live collection scanned {int(live_progress.get('channel_count', len(channels) or 0))} channel(s)",
        f"over the last {int(live_progress.get('since_minutes', 30))} minute(s)",
        f"and parsed {int(live_progress.get('parsed_event_count', 0))} event(s).",
    ]
    if warning_channels:
        summary_bits.append(f"Warnings affected: {', '.join(warning_channels)}.")
    if permission_denied_channels:
        summary_bits.append(f"Permission issues detected on: {', '.join(permission_denied_channels)}.")

    return {
        "mode": "live",
        "channel_count": int(live_progress.get("channel_count", len(channels) or 0)),
        "completed_channels": int(live_progress.get("completed_channels", 0)),
        "channels": channels,
        "since_minutes": int(live_progress.get("since_minutes", 30)),
        "parsed_event_count": int(live_progress.get("parsed_event_count", 0)),
        "fallback_channels": int(live_progress.get("fallback_channels", 0)),
        "warning_count": int(live_progress.get("warning_count", 0)),
        "warning_channels": warning_channels,
        "permission_denied_channels": permission_denied_channels,
        "warnings": list(warnings[:10]),
        "recommendations": recommendations,
        "summary": " ".join(summary_bits).strip(),
    }


def _telemetry_gap_recommendations(telemetry_gaps: Optional[List[str]]) -> List[str]:
    recommendations: List[str] = []
    missing = list(telemetry_gaps or [])
    if "Security" in missing:
        recommendations.append("Collect Security telemetry for stronger authentication, privilege, and account-management coverage.")
    if "Sysmon" in missing:
        recommendations.append("Enable or collect Sysmon telemetry for stronger process, network, and image-load context.")
    if "PowerShell" in missing:
        recommendations.append("Include PowerShell Operational logging for better script-based detection coverage.")
    return recommendations


def _telemetry_present_display(telemetry_summary: Dict[str, Any]) -> List[str]:
    observed = list(telemetry_summary.get("observed", []) or [])
    if observed:
        return observed
    return list(telemetry_summary.get("present", []) or [])


def _build_collection_quality_summary(
    *,
    input_mode: str,
    telemetry_summary: Dict[str, Any],
    telemetry_gaps: List[str],
    parse_profile: Optional[Dict[str, Any]] = None,
    parse_progress: Optional[Dict[str, Any]] = None,
    live_collection_summary: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    if input_mode == "live":
        live_summary = dict(live_collection_summary or {})
        remaining_telemetry_gaps = [
            gap for gap in list(telemetry_gaps or [])
            if not (gap == "Security" and list(live_summary.get("permission_denied_channels", []) or []))
        ]
        merged_recommendations = list(dict.fromkeys(
            list(live_summary.get("recommendations", []) or []) + _telemetry_gap_recommendations(remaining_telemetry_gaps)
        ))
        return {
            "mode": "live",
            "source_kind": "channels",
            "source_count": int(live_summary.get("channel_count", len(live_summary.get("channels", []) or []))),
            "completed_source_count": int(live_summary.get("completed_channels", 0)),
            "source_names": list(live_summary.get("channels", []) or []),
            "parsed_event_count": int(live_summary.get("parsed_event_count", 0)),
            "warning_count": int(live_summary.get("warning_count", 0)),
            "warning_sources": list(live_summary.get("warning_channels", []) or []),
            "permission_denied_sources": list(live_summary.get("permission_denied_channels", []) or []),
            "fallback_used": bool(live_summary.get("fallback_channels", 0)),
            "telemetry_present": _telemetry_present_display(telemetry_summary),
            "telemetry_missing": list(telemetry_gaps or []),
            "recommendations": merged_recommendations,
            "summary": str(live_summary.get("summary") or "").strip(),
        }

    parse_profile = parse_profile or {}
    parse_progress = parse_progress or {}
    file_paths = list(parse_profile.get("files", []) or [])
    file_names = [os.path.basename(path) for path in file_paths]
    file_count = int(parse_profile.get("file_count", len(file_names)))
    completed_files = int(parse_progress.get("completed_files", file_count))
    parsed_event_count = int(parse_progress.get("parsed_event_count", 0))
    fallback_used = bool(parse_progress.get("fallback_used", False))
    warning_sources = list(parse_progress.get("failed_files", []) or [])
    warning_count = int(parse_progress.get("warning_count", len(warning_sources)))
    recommendations = _telemetry_gap_recommendations(telemetry_gaps)
    if fallback_used:
        recommendations.append("Review parser diagnostics and rerun the collection if EVTX parsing fell back unexpectedly.")
    if warning_sources:
        recommendations.append(
            f"One or more EVTX files could not be parsed cleanly: {', '.join(warning_sources)}."
        )
    if not parsed_event_count:
        recommendations.append("Verify the EVTX path and date filters if you expected activity in this collection.")

    summary_bits = [
        f"Offline collection parsed {file_count} EVTX file(s)",
        f"and produced {parsed_event_count} normalized event(s).",
    ]
    if fallback_used:
        summary_bits.append("Parser fallback was used during collection.")
    if warning_sources:
        summary_bits.append(f"Parser warnings affected: {', '.join(warning_sources)}.")
    if telemetry_gaps:
        summary_bits.append(f"Missing telemetry: {', '.join(telemetry_gaps)}.")

    return {
        "mode": "offline",
        "source_kind": "files",
        "source_count": file_count,
        "completed_source_count": completed_files,
        "source_names": file_names,
        "parsed_event_count": parsed_event_count,
        "warning_count": warning_count,
        "warning_sources": warning_sources,
        "permission_denied_sources": [],
        "fallback_used": fallback_used,
        "telemetry_present": _telemetry_present_display(telemetry_summary),
        "telemetry_missing": list(telemetry_gaps or []),
        "recommendations": recommendations,
        "summary": " ".join(summary_bits).strip(),
    }


# ---------------------------------------------------------------------------
# Summary / brief writers — moved from cli.py (single copy)
# ---------------------------------------------------------------------------

def write_summary_txt(case_path: str, case_meta: dict, signals, findings, incidents) -> str:
    summary_path = os.path.join(case_path, "summary.txt")
    suppression = case_meta.get("suppression_summary", {}) or {}
    telemetry = case_meta.get("telemetry_summary", {}) or {}
    collection_summary = case_meta.get("collection_quality_summary", {}) or {}
    metrics = case_meta.get("case_metrics", {}) or {}
    campaign_lines = [
        entry.get("summary", "")
        for entry in (case_meta.get("campaign_summary", []) or [])[:5]
        if entry.get("summary", "")
    ]
    rule_metric_lines = [
        f"{row.get('rule', '')}: raw {row.get('raw_alert_count', 0)}, suppressed {row.get('suppressed_alert_count', 0)}, findings {row.get('finding_count', 0)}, incidents {row.get('incident_count', 0)}"
        for row in (case_meta.get("rule_metrics", []) or [])[:5]
        if row.get("rule", "")
    ]
    tuning_lines = [
        f"{entry.get('rule', '')}: {entry.get('suggestion', '')} ({entry.get('reason', '')})"
        for entry in (case_meta.get("tuning_recommendations", []) or [])[:5]
        if entry.get("rule", "") and entry.get("suggestion", "")
    ]
    display_source = case_meta.get("input_source_display") or display_input_source(case_meta.get("input_source", ""))
    warning_sources = sanitize_display_values(collection_summary.get("warning_sources", []))
    permission_denied_sources = sanitize_display_values(collection_summary.get("permission_denied_sources", []))

    lines = [
        f"Case: {case_meta.get('case_name', '')}",
        f"Input Source: {display_source}",
        f"Primary Host: {case_meta.get('primary_host', '')}",
        f"Primary User: {case_meta.get('primary_user', '')}",
        f"Primary Source IP: {case_meta.get('primary_source_ip', '')}",
        f"Response Priority: {case_meta.get('response_priority', 'P4')}",
        f"First Seen: {case_meta.get('first_seen', '')}",
        f"Last Seen: {case_meta.get('last_seen', '')}",
        f"Signal Count: {len(signals)}",
        f"Finding Count: {len(findings)}",
        f"Incident Count: {len(incidents)}",
        f"Raw Alert Count: {metrics.get('raw_alert_count', case_meta.get('raw_alert_count', 0))}",
        f"Suppressed Alert Count: {metrics.get('suppressed_alert_count', case_meta.get('suppressed_alert_count', 0))}",
        f"Post-Filter Alert Count: {metrics.get('post_filter_alert_count', case_meta.get('post_filter_alert_count', 0))}",
        f"Deduplicated Alert Count: {metrics.get('deduplicated_alert_count', case_meta.get('deduplicated_alert_count', 0))}",
        f"Post-Dedup Alert Count: {metrics.get('post_dedup_alert_count', case_meta.get('post_dedup_alert_count', 0))}",
        f"Finding Promotion Rate: {metrics.get('finding_promotion_rate', 0.0)}",
        f"Incident Promotion Rate: {metrics.get('incident_promotion_rate', 0.0)}",
        f"Telemetry Present: {', '.join(collection_summary.get('telemetry_present', []) or telemetry.get('observed', []) or telemetry.get('present', [])) or 'None'}",
        f"Telemetry Missing: {', '.join(telemetry.get('missing', [])) or 'None'}",
        f"Suppressed Reasons: {json.dumps(suppression.get('by_reason', {}), sort_keys=True)}",
    ]
    if collection_summary:
        lines.extend(
            [
                f"Collection Quality Summary: {collection_summary.get('summary', '')}",
                f"Collection Source Kind: {collection_summary.get('source_kind', 'unknown')}",
                f"Collection Source Count: {collection_summary.get('source_count', 0)}",
                f"Collection Parsed Event Count: {collection_summary.get('parsed_event_count', 0)}",
                f"Collection Warning Count: {collection_summary.get('warning_count', 0)}",
                f"Collection Warning Sources: {', '.join(warning_sources) or 'None'}",
                f"Collection Permission Denied Sources: {', '.join(permission_denied_sources) or 'None'}",
                f"Collection Fallback Used: {'Yes' if collection_summary.get('fallback_used') else 'No'}",
            ]
        )
        recommendations = list(collection_summary.get("recommendations", []) or [])
        if recommendations:
            lines.append(f"Collection Recommendations: {' | '.join(recommendations)}")
    if campaign_lines:
        lines.extend(["", "Campaign Summary:"])
        lines.extend([f"- {line}" for line in campaign_lines])
    if rule_metric_lines:
        lines.extend(["", "Top Rule Metrics:"])
        lines.extend([f"- {line}" for line in rule_metric_lines])
    if tuning_lines:
        lines.extend(["", "Tuning Recommendations:"])
        lines.extend([f"- {line}" for line in tuning_lines])
    summary_text = apply_demo_redaction_text("\n".join(lines) + "\n")
    with open(summary_path, "w", encoding="utf-8") as handle:
        handle.write(summary_text)
    return summary_path


def write_incident_brief(case_path: str, case_meta: dict, incidents, timeline_rows) -> str:
    brief_path = os.path.join(case_path, "incident_brief.md")
    top_incidents = sorted(
        incidents,
        key=lambda i: ((i.severity or ""), i.confidence_score, i.first_seen or datetime.min),
        reverse=True,
    )[:10]

    timeline_preview = timeline_rows[:25]
    campaign_lines = [
        entry.get("summary", "")
        for entry in (case_meta.get("campaign_summary", []) or [])[:5]
        if entry.get("summary", "")
    ]
    collection_summary = case_meta.get("collection_quality_summary", {}) or {}
    rule_metric_lines = [
        f"{row.get('rule', '')}: raw {row.get('raw_alert_count', 0)}, suppressed {row.get('suppressed_alert_count', 0)}, findings {row.get('finding_count', 0)}, incidents {row.get('incident_count', 0)}"
        for row in (case_meta.get("rule_metrics", []) or [])[:5]
        if row.get("rule", "")
    ]
    tuning_lines = [
        f"{entry.get('rule', '')}: {entry.get('suggestion', '')} ({entry.get('reason', '')})"
        for entry in (case_meta.get("tuning_recommendations", []) or [])[:5]
        if entry.get("rule", "") and entry.get("suggestion", "")
    ]
    display_source = case_meta.get("input_source_display") or display_input_source(case_meta.get("input_source", ""))
    warning_sources = sanitize_display_values(collection_summary.get("warning_sources", []))
    permission_denied_sources = sanitize_display_values(collection_summary.get("permission_denied_sources", []))

    lines = [
        f"# Incident Brief: {case_meta.get('case_name', '')}",
        "",
        "## Case Overview",
        f"- Input source: {display_source}",
        f"- Primary host: {case_meta.get('primary_host', '')}",
        f"- Primary user: {case_meta.get('primary_user', '')}",
        f"- Primary source IP: {case_meta.get('primary_source_ip', '')}",
        f"- Response priority: {case_meta.get('response_priority', 'P4')}",
        f"- First seen: {case_meta.get('first_seen', '')}",
        f"- Last seen: {case_meta.get('last_seen', '')}",
        f"- Telemetry present: {', '.join(collection_summary.get('telemetry_present', []) or (case_meta.get('telemetry_summary', {}) or {}).get('observed', []) or (case_meta.get('telemetry_summary', {}) or {}).get('present', [])) or 'None'}",
        f"- Telemetry missing: {', '.join((case_meta.get('telemetry_summary', {}) or {}).get('missing', [])) or 'None'}",
        "",
        "## Collection Quality",
    ]

    if collection_summary:
        lines.extend(
            [
                f"- {collection_summary.get('summary', '')}",
                f"- Source kind: {collection_summary.get('source_kind', 'unknown')}",
                f"- Source count: {collection_summary.get('source_count', 0)}",
                f"- Parsed events: {collection_summary.get('parsed_event_count', 0)}",
                f"- Warning count: {collection_summary.get('warning_count', 0)}",
                f"- Warning sources: {', '.join(warning_sources) or 'None'}",
                f"- Permission denied sources: {', '.join(permission_denied_sources) or 'None'}",
                f"- Fallback used: {'Yes' if collection_summary.get('fallback_used') else 'No'}",
            ]
        )
        lines.extend([f"- Recommendation: {item}" for item in (collection_summary.get("recommendations", []) or [])])
    else:
        lines.append("- Collection quality metadata was not available for this case.")

    lines.extend([
        "",
        "## Campaign Summary",
    ])

    if campaign_lines:
        lines.extend([f"- {line}" for line in campaign_lines])
    else:
        lines.append("- No multi-host campaign overlaps identified.")

    lines.extend(["", "## Detection Quality Notes"])

    if rule_metric_lines:
        lines.extend([f"- {line}" for line in rule_metric_lines])
    else:
        lines.append("- No per-rule metrics available.")

    if tuning_lines:
        lines.extend([f"- Tune: {line}" for line in tuning_lines])

    lines.extend([
        "",
        f"- Raw alerts: {(case_meta.get('case_metrics', {}) or {}).get('raw_alert_count', case_meta.get('raw_alert_count', 0))}",
        f"- Suppressed alerts: {(case_meta.get('case_metrics', {}) or {}).get('suppressed_alert_count', case_meta.get('suppressed_alert_count', 0))}",
        f"- Post-filter alerts: {(case_meta.get('case_metrics', {}) or {}).get('post_filter_alert_count', case_meta.get('post_filter_alert_count', 0))}",
        f"- Deduplicated alerts: {(case_meta.get('case_metrics', {}) or {}).get('deduplicated_alert_count', case_meta.get('deduplicated_alert_count', 0))}",
        f"- Post-dedup alerts: {(case_meta.get('case_metrics', {}) or {}).get('post_dedup_alert_count', case_meta.get('post_dedup_alert_count', 0))}",
        f"- Suppression reasons: {json.dumps((case_meta.get('suppression_summary', {}) or {}).get('by_reason', {}), sort_keys=True)}",
        "",
        "## Key Incidents",
    ])

    if top_incidents:
        for incident in top_incidents:
            lines.extend([
                f"- {incident.display_label} ({incident.severity}/{incident.confidence}) {incident.title}: {incident.summary}",
                f"  Why flagged: {incident.why_flagged or 'Correlated suspicious behavior in the case.'}",
                f"  Confidence factors: {', '.join(incident.confidence_factors or []) or 'None'}",
                f"  Recommended pivots: {', '.join(incident.recommended_pivots or []) or 'None'}",
            ])
    else:
        lines.append("- No incidents identified.")

    lines.extend([
        "",
        "## Affected Hosts",
        *([f"- {h}" for h in case_meta.get("hosts", [])] or ["- None"]),
        "",
        "## Affected Users",
        *([f"- {u}" for u in case_meta.get("users", [])] or ["- None"]),
        "",
        "## Observed IPs",
        *([f"- {ip}" for ip in case_meta.get("ips", [])] or ["- None"]),
        "",
        "## Attack Timeline",
    ])

    if timeline_preview:
        for row in timeline_preview:
            lines.append(
                f"- {row.get('timestamp', '')} {row.get('display_label', row.get('id', ''))} {row.get('title', '')} ({row.get('type', '')})"
            )
    else:
        lines.append("- No timeline entries.")

    lines.extend(["", "## Recommended Next Actions"])

    if top_incidents:
        top = top_incidents[0]
        lines.extend(
            [f"- {step}" for step in (top.containment_guidance or [])]
            or ["- Isolate impacted hosts and preserve volatile evidence."]
        )
        lines.extend([f"- Scope next: {step}" for step in (top.scope_next or [])])
        lines.extend([f"- Validate: {step}" for step in (top.validation_steps or [])])
    else:
        recommendations = list(collection_summary.get("recommendations", []) or [])
        if recommendations:
            lines.extend([f"- {step}" for step in recommendations])
        else:
            telemetry_missing = list(collection_summary.get("telemetry_missing", []) or [])
            warning_sources = list(collection_summary.get("warning_sources", []) or [])
            permission_denied_sources = list(collection_summary.get("permission_denied_sources", []) or [])
            if telemetry_missing or warning_sources or permission_denied_sources or collection_summary.get("fallback_used"):
                lines.extend([
                    "- Review collection quality before treating the window as fully clean.",
                    "- Expand the lookback window or include additional channels if you expected more activity in this period.",
                    "- Re-run the collection with stronger telemetry sources or permissions if important coverage is still missing.",
                ])
            else:
                lines.extend([
                    "- Collection coverage looked healthy for this window, and no detections were promoted into findings or incidents.",
                    "- If you expected suspicious activity, widen the lookback window and review the raw events for additional context.",
                    "- Keep Sysmon, Security, and PowerShell logging enabled so future live scans stay high-confidence.",
                ])
        if not timeline_preview and int(collection_summary.get("parsed_event_count", 0)) > 0:
            lines.append("- No detections were promoted into the timeline; review raw events only if you expected suspicious activity in this window.")

    brief_text = apply_demo_redaction_text("\n".join(lines) + "\n")
    with open(brief_path, "w", encoding="utf-8") as handle:
        handle.write(brief_text)
    return brief_path


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_investigation(
    request: InvestigationRequest,
    reporter: Optional[ProgressReporter] = None,
) -> InvestigationResult:
    """Execute the full investigation pipeline.

    This is the single source of truth.  Both `cli.py` and `server.py`
    call this function rather than duplicating the pipeline.
    """

    cases_root = os.path.abspath(request.cases_dir or os.path.join(ROOT_DIR, "cases"))
    case_name = request.case_name or auto_case_name(
        request.input_source if request.input_mode == "evtx_path" else None,
        request.input_mode == "live",
        ",".join(request.channels or []),
    )
    case_path = ensure_case_dir(
        cases_root, case_name, overwrite=request.overwrite, resume=request.resume,
    )
    resolved_case_name = os.path.basename(case_path)
    input_source = (
        request.input_source
        if request.input_mode == "evtx_path"
        else f"live:{','.join(request.channels or [])}"
    )
    log_context = {"request_id": request.request_id or "", "user": request.requested_by or ""}

    # RunStatus writes run_status.json; the reporter adapter forwards to both
    run_status = RunStatus(resolved_case_name, case_path, input_source)
    rpt = _RunStatusReporter(run_status, reporter)

    timeout_seconds = _int_env(INVESTIGATION_TIMEOUT_ENV, DEFAULT_INVESTIGATION_TIMEOUT_SECONDS)
    detector_timeout_seconds = _int_env(DETECTOR_TIMEOUT_ENV, DEFAULT_DETECTOR_TIMEOUT_SECONDS, maximum=3600)
    started_at = monotonic()
    partial_failures: List[Dict[str, Any]] = []
    stage_runtime_seconds: Dict[str, float] = {}
    active_fine_stage = "init"
    active_fine_stage_started_at = started_at
    stage_windows: Dict[str, Dict[str, str]] = {
        "parse": {"started_at": "", "completed_at": ""},
        "detect": {"started_at": "", "completed_at": ""},
        "suppress": {"started_at": "", "completed_at": ""},
        "correlate": {"started_at": "", "completed_at": ""},
        "report": {"started_at": "", "completed_at": ""},
    }
    active_stage_window: str = ""

    def _utc_iso() -> str:
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    def _window_name_for_stage(stage_name: str) -> str:
        if stage_name == "parse":
            return "parse"
        if stage_name in {"detect", "sigma"}:
            return "detect"
        if stage_name == "filter":
            return "suppress"
        if stage_name in {"correlate", "model"}:
            return "correlate"
        if stage_name in {"timeline_export", "graph_export", "findings_export", "summary", "html_render", "raw_export"}:
            return "report"
        return ""

    def _stage_timing_snapshot(*, include_active: bool) -> Dict[str, Any]:
        stage_seconds = dict(stage_runtime_seconds)
        if include_active and active_fine_stage:
            stage_seconds[active_fine_stage] = stage_seconds.get(active_fine_stage, 0.0) + max(
                0.0,
                monotonic() - active_fine_stage_started_at,
            )
        stage_ms_by_name = {
            f"{name}_ms": int(round(seconds * 1000))
            for name, seconds in stage_seconds.items()
        }
        parse_ms = stage_ms_by_name.get("parse_ms", 0)
        detect_ms = stage_ms_by_name.get("detect_ms", 0) + stage_ms_by_name.get("sigma_ms", 0)
        suppress_ms = stage_ms_by_name.get("filter_ms", 0)
        correlate_ms = stage_ms_by_name.get("correlate_ms", 0) + stage_ms_by_name.get("model_ms", 0)
        report_ms = sum(
            stage_ms_by_name.get(key, 0)
            for key in (
                "timeline_export_ms",
                "graph_export_ms",
                "findings_export_ms",
                "summary_ms",
                "html_render_ms",
                "raw_export_ms",
            )
        )
        return {
            "parse_ms": int(parse_ms),
            "detect_ms": int(detect_ms),
            "suppress_ms": int(suppress_ms),
            "correlate_ms": int(correlate_ms),
            "report_ms": int(report_ms),
            "total_ms": int(max(0, round((monotonic() - started_at) * 1000))),
            "by_stage": {
                key: stage_ms_by_name[key]
                for key in sorted(stage_ms_by_name.keys())
            },
        }

    def _flush_stage_timing(next_stage: str = "") -> None:
        nonlocal active_fine_stage, active_fine_stage_started_at, active_stage_window
        now_mono = monotonic()
        now_utc = _utc_iso()
        if active_fine_stage:
            elapsed = max(0.0, now_mono - active_fine_stage_started_at)
            stage_runtime_seconds[active_fine_stage] = stage_runtime_seconds.get(active_fine_stage, 0.0) + elapsed
        if next_stage:
            next_window = _window_name_for_stage(next_stage)
            if next_window != active_stage_window:
                if active_stage_window and not stage_windows[active_stage_window].get("completed_at"):
                    stage_windows[active_stage_window]["completed_at"] = now_utc
                if next_window:
                    if not stage_windows[next_window].get("started_at"):
                        stage_windows[next_window]["started_at"] = now_utc
                    stage_windows[next_window]["completed_at"] = ""
                active_stage_window = next_window
            active_fine_stage = next_stage
            active_fine_stage_started_at = now_mono
        else:
            if active_stage_window and not stage_windows[active_stage_window].get("completed_at"):
                stage_windows[active_stage_window]["completed_at"] = now_utc
            active_fine_stage = ""
            active_fine_stage_started_at = now_mono
            active_stage_window = ""
        rpt.on_metadata("stage_windows", {k: dict(v) for k, v in stage_windows.items()})
        rpt.on_metadata("stage_timings", _stage_timing_snapshot(include_active=bool(active_fine_stage)))

    SERVICE_LOGGER.info(
        "investigation_started",
        extra={
            **log_context,
            "case_name": resolved_case_name,
            "input_mode": request.input_mode,
            "input_source": input_source,
            "enable_sigma": bool(request.enable_sigma),
        },
    )

    def _check_timeout(active_stage: str) -> None:
        elapsed = monotonic() - started_at
        if elapsed > timeout_seconds:
            raise TimeoutError(
                f"Investigation exceeded timeout ({timeout_seconds}s) during stage '{active_stage}'."
            )

    if request.request_id:
        rpt.on_metadata("request_id", request.request_id)
    if request.requested_by:
        rpt.on_metadata("requested_by", request.requested_by)
    rpt.on_metadata(
        "timeout_policy",
        {
            "investigation_timeout_seconds": timeout_seconds,
            "detector_timeout_seconds": detector_timeout_seconds,
        },
    )
    rpt.on_metadata("partial_failures", [])
    _flush_stage_timing("init")

    stage = "init"
    try:
        # ---- tuning ----
        stage = "tuning"
        _flush_stage_timing(stage)
        _check_timeout(stage)
        rpt.on_stage(stage, "Loading tuning configuration")
        tuning_config, tuning_diagnostics, tuning_paths = load_tuning(
            ROOT_DIR, request.tuning_paths,
        )
        for diag in tuning_diagnostics:
            rpt.on_diagnostic(diag)
        rpt.on_metadata("tuning_files", tuning_paths)

        # ---- parse ----
        stage = "parse"
        _flush_stage_timing(stage)
        _check_timeout(stage)
        rpt.on_stage(stage, "Parsing events")

        if request.input_mode == "evtx_path":
            parse_profile = describe_evtx_path(request.input_source)
            rpt.on_metadata("parse_profile", {
                "mode": parse_profile.get("mode"),
                "file_count": parse_profile.get("file_count"),
                "worker_count": parse_profile.get("worker_count"),
                "executor_kind": parse_profile.get("executor_kind"),
                "files": [os.path.basename(p) for p in parse_profile.get("files", [])],
            })

            parse_progress: Dict[str, Any] = {
                "completed_files": 0,
                "file_count": parse_profile.get("file_count", 0),
                "parsed_event_count": 0,
                "_completed_parsed_events": 0,
                "last_file": "",
                "active_file": "",
                "active_records_scanned": 0,
                "active_parsed_events": 0,
                "active_skipped_records": 0,
                "fallback_used": False,
                "warning_count": 0,
                "failed_files": [],
                "last_error": "",
            }
            prog_lock = Lock()

            def _on_parse(update: dict) -> None:
                with prog_lock:
                    _check_timeout(stage)
                    status_name = _apply_parse_progress_update(parse_progress, update)
                    rpt.on_metadata("parse_progress", _public_parse_progress(parse_progress))
                    rpt.on_parse_progress(update)
                    if status_name == "file_error":
                        failed_file = os.path.basename(update.get("file_path", "") or "")
                        error_text = str(update.get("error", "") or "")
                        _append_partial_failure(
                            partial_failures,
                            component="parser",
                            name=failed_file or "unknown_file",
                            reason="file_error",
                            detail=error_text,
                        )
                        rpt.on_metadata("partial_failures", list(partial_failures))
                        rpt.on_diagnostic(f"parse_file_error:{failed_file}:{error_text}")
                    if status_name in ("file_progress", "file_complete") and parse_progress["file_count"]:
                        detail = parse_progress["active_file"] or parse_progress["last_file"]
                        rpt.on_stage(
                            stage,
                            f"Parsing events ({parse_progress['completed_files']}/{parse_progress['file_count']}) - {detail}",
                        )

            events = read_evtx_path(
                request.input_source,
                request.start_date,
                request.end_date,
                progress_callback=_on_parse,
            )
        else:
            channels = request.channels or ["Security"]
            since_minutes = int(request.since_minutes or 30)
            rpt.on_metadata(
                "live_profile",
                {
                    "mode": "live",
                    "channel_count": len(channels),
                    "channels": list(channels),
                    "since_minutes": since_minutes,
                },
            )
            live_warnings: List[str] = []
            live_progress: Dict[str, Any] = {
                "completed_channels": 0,
                "channel_count": len(channels),
                "parsed_event_count": 0,
                "last_channel": "",
                "active_channel": "",
                "fallback_channels": 0,
                "warning_count": 0,
                "warning_channels": [],
                "last_warning": "",
                "channels": list(channels),
                "since_minutes": since_minutes,
            }
            prog_lock = Lock()

            def _on_live(update: dict) -> None:
                with prog_lock:
                    _check_timeout(stage)
                    status_name = _apply_live_progress_update(live_progress, update)
                    rpt.on_metadata("live_progress", _public_live_progress(live_progress))
                    rpt.on_parse_progress(update)
                    if status_name == "channel_warning":
                        message = str(update.get("message") or "").strip()
                        if message:
                            live_warnings.append(message)
                            rpt.on_diagnostic(message)
                    if status_name in ("channel_started", "channel_complete") and live_progress["channel_count"]:
                        detail = live_progress["active_channel"] or live_progress["last_channel"]
                        rpt.on_stage(
                            stage,
                            f"Reading live events ({live_progress['completed_channels']}/{live_progress['channel_count']}) - {detail}",
                        )

            events = read_live(channels, since_minutes, progress_callback=_on_live)

        _check_timeout(stage)
        telemetry_summary = summarize_telemetry(events)
        telemetry_gaps = list(telemetry_summary.get("missing", []))
        rpt.on_metadata("telemetry_summary", telemetry_summary)

        # ---- detect ----
        stage = "detect"
        _flush_stage_timing(stage)
        _check_timeout(stage)
        rpt.on_stage(stage, "Running detectors")
        raw_alerts, detector_timings = _run_detectors(
            events,
            timeout_seconds=detector_timeout_seconds,
            partial_failures=partial_failures,
            diagnostic_callback=rpt.on_diagnostic,
        )
        rpt.on_metadata("detector_timings", detector_timings)
        rpt.on_metadata("partial_failures", list(partial_failures))

        sigma_alerts: list = []
        sigma_rules_list: list = []
        sigma_diagnostics: list = []
        sigma_paths = _resolve_sigma_paths(request.sigma_rule_paths)

        if request.enable_sigma and SIGMA_AVAILABLE:
            stage = "sigma"
            _flush_stage_timing(stage)
            _check_timeout(stage)
            rpt.on_stage(stage, "Evaluating optional Sigma rules")
            sigma_rules_list, sigma_diagnostics = load_sigma_rules(sigma_paths)
            for diag in sigma_diagnostics:
                rpt.on_diagnostic(diag)
            sigma_alerts, rt_diag = run_sigma_rules(events, sigma_rules_list)
            sigma_diagnostics.extend(rt_diag)
            for diag in rt_diag:
                rpt.on_diagnostic(diag)
            raw_alerts.extend(sigma_alerts)

        rpt.on_metadata("sigma_summary", {
            "enabled": request.enable_sigma,
            "rule_paths": sigma_paths,
            "rules_loaded": len(sigma_rules_list),
            "alerts_emitted": len(sigma_alerts),
        })

        # ---- filter ----
        stage = "filter"
        _flush_stage_timing(stage)
        _check_timeout(stage)
        rpt.on_stage(stage, "Applying false-positive suppression")
        fp = FPFilter(tuning=tuning_config)
        if request.no_fp_filter:
            filtered_alerts = list(raw_alerts)
            suppression_summary: Dict[str, Any] = {
                "suppressed_total": 0, "by_rule": {}, "by_reason": {}, "samples": [],
            }
        else:
            filtered_alerts = fp.apply(raw_alerts)
            suppression_summary = fp.summary_dict()

        # ---- correlate ----
        stage = "correlate"
        _flush_stage_timing(stage)
        _check_timeout(stage)
        rpt.on_stage(stage, "Deduplicating and correlating alerts")
        alerts = deduplicate(filtered_alerts)
        chains = correlate(alerts)

        # ---- model ----
        stage = "model"
        _flush_stage_timing(stage)
        _check_timeout(stage)
        rpt.on_stage(stage, "Building signals/findings/incidents")
        signals, findings, _ = alerts_to_signals_findings(
            alerts,
            telemetry_gaps=telemetry_gaps,
            promotion_overrides=(tuning_config or {}).get("promotion_overrides", {}),
        )
        incidents = build_incidents(events, signals, findings, chains)

        ioc_path = os.path.join(ROOT_DIR, "intel", "iocs.json")
        apply_ioc_enrichment(signals, findings, incidents, ioc_path)
        _enrich_incidents(incidents, signals, findings, telemetry_gaps)

        assign_display_labels(signals, "SIG")
        assign_display_labels(findings, "FND")
        assign_display_labels(incidents, "INC")

        # ---- entities / metrics ----
        entities = summarize_case_entities(signals, findings, incidents)
        fallback = _fallback_case_entities(events)
        for key in ("primary_host", "primary_user", "primary_source_ip"):
            if not entities.get(key):
                entities[key] = fallback.get(key, "")
        for key in ("hosts", "users", "users_canonical", "ips"):
            if not entities.get(key):
                entities[key] = fallback.get(key, [])

        first_seen, last_seen = _event_time_bounds(events)
        dedup_count = max(0, len(filtered_alerts) - len(alerts))
        case_metrics = {
            "raw_alert_count": len(raw_alerts),
            "suppressed_alert_count": suppression_summary.get("suppressed_total", 0),
            "post_filter_alert_count": len(filtered_alerts),
            "deduplicated_alert_count": dedup_count,
            "post_dedup_alert_count": len(alerts),
            "signal_count": len(signals),
            "finding_count": len(findings),
            "incident_count": len(incidents),
            "finding_promotion_rate": _safe_ratio(len(findings), len(signals)),
            "incident_promotion_rate": _safe_ratio(len(incidents), len(findings)),
        }
        rule_metrics = build_rule_metrics(raw_alerts, filtered_alerts, alerts, signals, findings, incidents)
        tuning_recommendations = build_tuning_recommendations(rule_metrics)
        campaign_summary = build_campaign_summary(signals, findings, incidents)

        case_meta: Dict[str, Any] = {
            "case_name": resolved_case_name,
            "input_source": input_source,
            "input_source_display": display_input_source(input_source),
            "primary_host": entities.get("primary_host", ""),
            "primary_user": entities.get("primary_user", ""),
            "primary_user_canonical": entities.get("primary_user_canonical", ""),
            "primary_source_ip": entities.get("primary_source_ip", ""),
            "first_seen": first_seen.isoformat() if first_seen else "",
            "last_seen": last_seen.isoformat() if last_seen else "",
            "hosts": entities.get("hosts", []),
            "users": entities.get("users", []),
            "users_canonical": entities.get("users_canonical", []),
            "ips": entities.get("ips", []),
            "suppressed_alerts": fp.suppressed,
            "suppressed_alert_count": suppression_summary.get("suppressed_total", 0),
            "raw_alert_count": len(raw_alerts),
            "post_filter_alert_count": len(filtered_alerts),
            "deduplicated_alert_count": dedup_count,
            "post_dedup_alert_count": len(alerts),
            "chain_count": len(chains),
            "case_metrics": case_metrics,
            "suppression_summary": suppression_summary,
            "telemetry_summary": telemetry_summary,
            "telemetry_gap_summary": {
                "present": telemetry_summary.get("present", []),
                "missing": telemetry_gaps,
            },
            "rule_metrics": rule_metrics,
            "tuning_recommendations": tuning_recommendations,
            "campaign_summary": campaign_summary,
            "partial_failures": list(partial_failures),
            "tuning_summary": {"loaded_paths": tuning_paths, "diagnostics": tuning_diagnostics},
            "sigma_summary": {
                "enabled": request.enable_sigma,
                "rule_paths": sigma_paths,
                "rules_loaded": len(sigma_rules_list),
                "alerts_emitted": len(sigma_alerts),
                "diagnostic_count": len(sigma_diagnostics),
            },
        }
        if request.input_mode == "live":
            live_collection_summary = _build_live_collection_summary(
                live_progress,
                live_warnings,
                telemetry_gaps,
            )
            case_meta["live_collection_summary"] = live_collection_summary
            rpt.on_metadata("live_collection_summary", live_collection_summary)
        collection_quality_summary = _build_collection_quality_summary(
            input_mode=request.input_mode,
            telemetry_summary=telemetry_summary,
            telemetry_gaps=telemetry_gaps,
            parse_profile=parse_profile if request.input_mode == "evtx_path" else None,
            parse_progress=parse_progress if request.input_mode == "evtx_path" else None,
            live_collection_summary=case_meta.get("live_collection_summary", {}),
        )
        case_meta["collection_quality_summary"] = collection_quality_summary
        rpt.on_metadata("collection_quality_summary", collection_quality_summary)
        case_meta["response_priority"] = response_priority(incidents, case_meta)

        rpt.on_metadata("case_metrics", case_metrics)
        rpt.on_metadata("response_priority", case_meta["response_priority"])
        rpt.on_metadata("suppression_summary", suppression_summary)
        rpt.on_metadata("rule_metrics", rule_metrics[:25])
        rpt.on_metadata("tuning_recommendations", tuning_recommendations)
        rpt.on_metadata("campaign_summary", campaign_summary)

        # ---- export artifacts ----
        artifacts: Dict[str, str] = {}

        stage = "timeline_export"
        _flush_stage_timing(stage)
        _check_timeout(stage)
        rpt.on_stage(stage, "Exporting timeline.json")
        timeline_path = os.path.join(case_path, "timeline.json")
        timeline_data = export_timeline(signals, findings, incidents, timeline_path)
        rpt.on_artifact(timeline_path)
        artifacts["timeline"] = timeline_path

        stage = "graph_export"
        _flush_stage_timing(stage)
        _check_timeout(stage)
        rpt.on_stage(stage, "Exporting graph.json")
        graph_path = os.path.join(case_path, "graph.json")
        graph = build_entity_graph(signals, findings, incidents)
        export_graph(graph, graph_path)
        rpt.on_artifact(graph_path)
        artifacts["graph"] = graph_path

        stage = "findings_export"
        _flush_stage_timing(stage)
        _check_timeout(stage)
        rpt.on_stage(stage, "Exporting findings.json")
        findings_path = os.path.join(case_path, "findings.json")
        raw_events_path = os.path.join(case_path, "raw_events.jsonl")
        export_case(
            signals=signals,
            findings=findings,
            incidents=incidents,
            filepath=findings_path,
            legacy_alerts=alerts,
            legacy_chains=chains,
            raw_events=events,
            case_meta=case_meta,
            raw_event_artifact_path=raw_events_path,
        )
        rpt.on_artifact(findings_path)
        artifacts["findings"] = findings_path

        stage = "summary"
        _flush_stage_timing(stage)
        _check_timeout(stage)
        rpt.on_stage(stage, "Writing summary and incident brief")
        summary_path = write_summary_txt(case_path, case_meta, signals, findings, incidents)
        rpt.on_artifact(summary_path)
        artifacts["summary"] = summary_path

        brief_path = write_incident_brief(
            case_path, case_meta, incidents, timeline_data.get("timeline", []),
        )
        rpt.on_artifact(brief_path)
        artifacts["brief"] = brief_path

        stage = "html_render"
        _flush_stage_timing(stage)
        _check_timeout(stage)
        rpt.on_stage(stage, "Rendering report.html")
        report_path = os.path.join(case_path, "report.html")
        generate_from_artifacts(findings_path, timeline_path, graph_path, report_path)
        rpt.on_artifact(report_path)
        artifacts["report"] = report_path

        stage = "raw_export"
        _flush_stage_timing(stage)
        _check_timeout(stage)
        rpt.on_stage(stage, "Streaming raw_events.jsonl")
        try:
            raw_export = export_raw_events_stream(events, raw_events_path)
            if raw_export.get("total_count", 0):
                rpt.on_artifact(raw_events_path)
                artifacts["raw_events"] = raw_events_path
        except Exception as raw_exc:
            rpt.on_diagnostic(f"raw_event_export_failed:{raw_exc}")

        _flush_stage_timing()
        rpt.on_complete("Investigation completed successfully")
        duration_ms = int((monotonic() - started_at) * 1000)
        SERVICE_LOGGER.info(
            "investigation_completed",
            extra={
                **log_context,
                "duration_ms": duration_ms,
                "case_name": resolved_case_name,
                "signal_count": len(signals),
                "finding_count": len(findings),
                "incident_count": len(incidents),
                "partial_failure_count": len(partial_failures),
            },
        )

        return InvestigationResult(
            case_name=resolved_case_name,
            case_path=case_path,
            input_source=input_source,
            signal_count=len(signals),
            finding_count=len(findings),
            incident_count=len(incidents),
            case_metrics=case_metrics,
            suppression_summary=suppression_summary,
            telemetry_summary=telemetry_summary,
            sigma_summary=case_meta["sigma_summary"],
            collection_quality_summary=case_meta["collection_quality_summary"],
            response_priority=case_meta["response_priority"],
            artifacts=artifacts,
        )

    except Exception as exc:
        _flush_stage_timing()
        duration_ms = int((monotonic() - started_at) * 1000)
        SERVICE_LOGGER.error(
            "investigation_failed",
            extra={
                **log_context,
                "duration_ms": duration_ms,
                "case_name": resolved_case_name,
                "stage": stage,
                "error": str(exc),
            },
            exc_info=True,
        )
        rpt.on_failed(stage, str(exc), traceback.format_exc())
        raise
