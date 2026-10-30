"""Shared investigation service — the single source of truth for the investigation pipeline.

Both the CLI and the API server call this module.  Neither should duplicate
pipeline logic.  The contract is:

    result = run_investigation(request, reporter)

Where *request* describes what to investigate and *reporter* receives
progress callbacks so the caller (CLI or server) can display or persist
status updates however it wants.
"""

from __future__ import annotations

import importlib
from concurrent.futures import ProcessPoolExecutor, TimeoutError
from concurrent.futures.process import BrokenProcessPool
import json
import multiprocessing
import logging
import os
import sys
import traceback
import uuid
from pathlib import Path
from collections import Counter, defaultdict
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
    execution_impact,
    lateral_movement,
    persistence,
    powershell_script,
    telemetry_context,
)
from detectors.fp_filter import FPFilter
from parser.evtx_reader import describe_evtx_path, read_evtx_path
from parser.live_reader import classify_live_channel_error, read_live
from reporting.graph_export import export as export_graph
from reporting.html_report import generate_from_data
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
from triage_engine.export_sanitizer import sanitize_export_data
from triage_engine.evidence import atomic_json, bind_event_sources, capture_evidence, case_identity, public_sources, write_analysis_manifest
from triage_engine.forensic_artifacts import read_forensic_bundle
from triage_engine.forensic_correlation import correlate_evidence, cross_source_alerts
from triage_engine import __version__
from triage_engine.evidence_scope import build_evidence_scope
from triage_engine.id_utils import assign_display_labels
from triage_engine.playbooks import apply_playbook
from triage_engine.rule_metrics import build_rule_metrics, build_tuning_recommendations
from triage_engine.status import RunStatus
from triage_engine.telemetry import response_priority, summarize_telemetry
from triage_engine.tuning import load_tuning
from triage_engine.product import (
    CaseMetadata,
    CollectionManifest,
    ClientStore,
    derive_disposition,
)

# Optional sigma — tolerate missing PyYAML gracefully
try:
    from triage_engine.sigma_loader import load_rules as load_sigma_rules
    from triage_engine.sigma_runner import evaluate_rules as run_sigma_rules

    SIGMA_AVAILABLE = True
except Exception:
    SIGMA_AVAILABLE = False


INVESTIGATION_TIMEOUT_ENV = "TRIAGE_INVESTIGATION_TIMEOUT_SECONDS"
DETECTOR_TIMEOUT_ENV = "TRIAGE_DETECTOR_TIMEOUT_SECONDS"
DETECTOR_EXECUTOR_ENV = "TRIAGE_DETECTOR_EXECUTOR"
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
    input_mode: str = "evtx_path"  # "evtx_path" | "live" | "artifact_bundle"
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

    # MSP workflow metadata (optional for backwards compatibility)
    client_id: str = "default"
    acquisition_method: str = "upload"
    collection_manifest: Optional[Dict[str, Any]] = None
    artifact_bundle: Optional[str] = None
    allow_large_ntfs: bool = False  # explicit opt-in for $MFT/$J members above 64 MiB


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
    client_id: str = "default"
    triage_disposition: Dict[str, Any] = field(default_factory=dict)

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



def _detector_process_entry(module_name: str, function_name: str, events: list, connection) -> None:
    """Run one detector in a spawn-safe child and return a pickled payload."""

    try:
        module = importlib.import_module(module_name)
        detector_fn = getattr(module, function_name)
        alerts = detector_fn(events)
        connection.send({"status": "ok", "alerts": alerts})
    except BaseException as exc:  # pragma: no cover - exercised in child process
        try:
            connection.send(
                {
                    "status": "error",
                    "error": str(exc) or exc.__class__.__name__,
                    "traceback": traceback.format_exc(),
                }
            )
        except Exception:
            # If result serialization itself fails there is no safe payload to
            # send; the parent will report the non-zero/empty child result.
            pass
    finally:
        try:
            connection.close()
        except Exception:
            pass


def _detector_process_spec(detector_fn) -> Optional[tuple[str, str]]:
    """Return a stable import target for a module-level detector callable.

    Test doubles, closures, and decorated callables are intentionally routed
    through the compatibility thread path because they cannot be reconstructed
    safely in a fresh Windows spawn process.  All built-in detectors are plain
    module-level functions and therefore take the cancellable process path.
    """

    module_name = str(getattr(detector_fn, "__module__", "") or "")
    function_name = str(getattr(detector_fn, "__name__", "") or "")
    qualname = str(getattr(detector_fn, "__qualname__", "") or "")
    if not module_name or not function_name or "<locals>" in qualname:
        return None
    try:
        module = importlib.import_module(module_name)
        resolved = getattr(module, function_name)
    except (ImportError, AttributeError, ValueError):
        return None
    if resolved is not detector_fn:
        return None
    return module_name, function_name


def _run_detector_in_thread(
    detector_name: str,
    detector_fn,
    events: list,
    timeout_seconds: int,
) -> Dict[str, Any]:
    """Compatibility path for non-importable callables (for example mocks)."""

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
            "executor": "thread",
            "isolation_fallback": True,
        }

    if "error" in error_holder:
        return {
            "status": "error",
            "alerts": [],
            "runtime_seconds": elapsed_seconds,
            "error": str(error_holder.get("error", "")),
            "traceback": str(error_holder.get("traceback", "")),
            "executor": "thread",
            "isolation_fallback": True,
        }

    alerts = alerts_holder.get("alerts", [])
    if not isinstance(alerts, list):
        return {
            "status": "error",
            "alerts": [],
            "runtime_seconds": elapsed_seconds,
            "error": f"Detector '{detector_name}' returned unexpected payload type.",
            "executor": "thread",
            "isolation_fallback": True,
        }

    return {
        "status": "ok",
        "alerts": alerts,
        "runtime_seconds": elapsed_seconds,
        "executor": "thread",
        "isolation_fallback": True,
    }


def _run_detector_in_process(
    detector_name: str,
    module_name: str,
    function_name: str,
    events: list,
    timeout_seconds: int,
) -> Dict[str, Any]:
    """Run an importable detector in a killable Windows spawn process."""

    context = multiprocessing.get_context("spawn")
    parent_connection, child_connection = context.Pipe(duplex=False)
    received: Dict[str, Any] = {}
    receive_errors: Dict[str, str] = {}

    def _receive_result() -> None:
        try:
            received["payload"] = parent_connection.recv()
        except (EOFError, OSError) as exc:
            receive_errors["error"] = str(exc) or exc.__class__.__name__

    reader = Thread(target=_receive_result, name=f"detector-result-{detector_name}", daemon=True)
    process = context.Process(
        target=_detector_process_entry,
        args=(module_name, function_name, events, child_connection),
        name=f"detector-{detector_name}",
    )
    # A detector must never keep the application alive if its parent exits.
    process.daemon = True
    started = monotonic()
    try:
        process.start()
    except Exception as exc:
        try:
            child_connection.close()
            parent_connection.close()
        except Exception:
            pass
        return {
            "status": "error",
            "alerts": [],
            "runtime_seconds": round(monotonic() - started, 3),
            "error": f"Detector '{detector_name}' process could not start: {exc}",
            "executor": "process",
        }
    finally:
        # The child owns its endpoint after start; the parent must close its
        # duplicate or EOF can never be observed by the reader.
        try:
            child_connection.close()
        except Exception:
            pass

    reader.start()
    timeout = max(1, timeout_seconds)
    process.join(timeout=timeout)
    terminated = False
    if process.is_alive():
        terminated = True
        try:
            process.terminate()
        except (OSError, AttributeError):
            pass
        process.join(timeout=2.0)
        if process.is_alive() and hasattr(process, "kill"):
            try:
                process.kill()
            except OSError:
                pass
            process.join(timeout=2.0)

    # Give a child that exited normally (or was terminated) a short opportunity
    # to finish transferring its payload.  The reader is daemonized so a broken
    # child pipe can never strand the investigation thread.
    if terminated:
        # Closing the parent endpoint unblocks a reader waiting on a killed
        # child, keeping timeout cleanup bounded as well as the detector work.
        try:
            parent_connection.close()
        except Exception:
            pass
    reader.join(timeout=1.0 if not terminated else 0.25)
    elapsed_seconds = round(monotonic() - started, 3)
    exitcode = process.exitcode
    try:
        parent_connection.close()
    except Exception:
        pass
    try:
        process.close()
    except Exception:
        pass

    if terminated:
        return {
            "status": "timeout",
            "alerts": [],
            "runtime_seconds": elapsed_seconds,
            "error": f"Detector '{detector_name}' exceeded timeout ({timeout_seconds}s).",
            "executor": "process",
            "terminated": True,
        }

    payload = received.get("payload")
    if not isinstance(payload, dict):
        detail = receive_errors.get("error") or f"child exited with code {exitcode} without a result"
        return {
            "status": "error",
            "alerts": [],
            "runtime_seconds": elapsed_seconds,
            "error": f"Detector '{detector_name}' process returned no result: {detail}",
            "executor": "process",
        }
    if payload.get("status") == "error":
        return {
            "status": "error",
            "alerts": [],
            "runtime_seconds": elapsed_seconds,
            "error": str(payload.get("error", "detector child failed")),
            "traceback": str(payload.get("traceback", "")),
            "executor": "process",
        }

    alerts = payload.get("alerts", [])
    if not isinstance(alerts, list):
        return {
            "status": "error",
            "alerts": [],
            "runtime_seconds": elapsed_seconds,
            "error": f"Detector '{detector_name}' returned unexpected payload type.",
            "executor": "process",
        }
    return {
        "status": "ok",
        "alerts": alerts,
        "runtime_seconds": elapsed_seconds,
        "executor": "process",
    }


_DETECTOR_POOL_EVENTS = None


def _detector_pool_entry(module_name: str, function_name: str, events: Optional[list] = None):
    """Import and execute one detector inside a reusable spawn worker.

    The first task transfers the parsed event list into the worker. Later tasks
    reuse that immutable snapshot, avoiding seven repeated pickles and keeping
    large EVTX bundles bounded to one child-side copy.
    """

    global _DETECTOR_POOL_EVENTS
    if events is not None:
        _DETECTOR_POOL_EVENTS = events
    if _DETECTOR_POOL_EVENTS is None:
        raise RuntimeError("detector process received no event snapshot")
    module = importlib.import_module(module_name)
    detector_fn = getattr(module, function_name)
    return detector_fn(_DETECTOR_POOL_EVENTS)


def _new_detector_process_pool():
    """Create a one-worker spawn pool shared by one investigation."""

    return ProcessPoolExecutor(
        max_workers=1,
        mp_context=multiprocessing.get_context("spawn"),
    )


def _terminate_detector_process_pool(pool) -> None:
    """Best-effort hard stop for a pool whose task exceeded its deadline."""

    workers = list(getattr(pool, "_processes", {}).values())
    for worker in workers:
        try:
            if worker.is_alive():
                worker.terminate()
        except (OSError, AttributeError):
            pass
    try:
        pool.shutdown(wait=False, cancel_futures=True)
    except Exception:
        pass
    for worker in workers:
        try:
            worker.join(timeout=2.0)
        except (OSError, AttributeError):
            pass
        try:
            if worker.is_alive() and hasattr(worker, "kill"):
                worker.kill()
                worker.join(timeout=2.0)
        except (OSError, AttributeError):
            pass


def _close_detector_process_pool(pool) -> None:
    try:
        pool.shutdown(wait=True, cancel_futures=True)
    except Exception:
        _terminate_detector_process_pool(pool)


def _run_detector_in_process_pool(
    detector_name: str,
    module_name: str,
    function_name: str,
    events: list,
    timeout_seconds: int,
    pool,
    *,
    load_events: bool = True,
) -> Dict[str, Any]:
    """Submit a detector to a reusable process and enforce a hard deadline."""

    started = monotonic()
    try:
        future = pool.submit(
            _detector_pool_entry,
            module_name,
            function_name,
            events if load_events else None,
        )
        alerts = future.result(timeout=max(1, timeout_seconds))
    except TimeoutError:
        return {
            "status": "timeout",
            "alerts": [],
            "runtime_seconds": round(monotonic() - started, 3),
            "error": f"Detector '{detector_name}' exceeded timeout ({timeout_seconds}s).",
            "executor": "process_pool",
            "terminated": True,
            "terminate_pool": True,
        }
    except BrokenProcessPool as exc:
        return {
            "status": "error",
            "alerts": [],
            "runtime_seconds": round(monotonic() - started, 3),
            "error": f"Detector '{detector_name}' process pool failed: {exc}",
            "executor": "process_pool",
            "terminate_pool": True,
        }
    except Exception as exc:
        return {
            "status": "error",
            "alerts": [],
            "runtime_seconds": round(monotonic() - started, 3),
            "error": str(exc) or exc.__class__.__name__,
            "traceback": traceback.format_exc(),
            "executor": "process_pool",
        }

    elapsed_seconds = round(monotonic() - started, 3)
    if not isinstance(alerts, list):
        return {
            "status": "error",
            "alerts": [],
            "runtime_seconds": elapsed_seconds,
            "error": f"Detector '{detector_name}' returned unexpected payload type.",
            "executor": "process_pool",
        }
    return {
        "status": "ok",
        "alerts": alerts,
        "runtime_seconds": elapsed_seconds,
        "executor": "process_pool",
    }

def _run_detector_with_timeout(
    detector_name: str,
    detector_fn,
    events: list,
    timeout_seconds: int,
) -> Dict[str, Any]:
    """Run a detector with a hard process timeout when it is importable.

    The process boundary is the production default and is required for a real
    timeout: terminating a child cannot leave detector code running in the
    server.  A thread fallback keeps tests and embedding callers that provide
    closures/mocks compatible; those callables are explicitly marked in the
    returned metadata.
    """

    configured = (os.environ.get(DETECTOR_EXECUTOR_ENV, "") or "").strip().lower()
    if configured in {"thread", "threads"}:
        return _run_detector_in_thread(detector_name, detector_fn, events, timeout_seconds)
    if configured not in {"", "process", "processes"}:
        logging.warning("Ignoring invalid %s=%r; using process", DETECTOR_EXECUTOR_ENV, configured)

    spec = _detector_process_spec(detector_fn)
    if spec is None:
        return _run_detector_in_thread(detector_name, detector_fn, events, timeout_seconds)
    # Built-in detectors are pure functions over the event list.  Avoid
    # creating seven child processes for an empty/fully filtered input while
    # retaining process semantics in the returned execution metadata.
    if not events:
        return {
            "status": "ok",
            "alerts": [],
            "runtime_seconds": 0.0,
            "executor": "process",
            "short_circuit": "empty_input",
        }
    module_name, function_name = spec
    return _run_detector_in_process(
        detector_name,
        module_name,
        function_name,
        events,
        timeout_seconds,
    )

def _run_detectors(
    events: list,
    *,
    timeout_seconds: int,
    partial_failures: List[Dict[str, Any]],
    diagnostic_callback=None,
) -> tuple[list, Dict[str, int]]:
    all_alerts: list = []
    detector_timings: Dict[str, int] = {}
    detector_functions = [
        ("credential_access", credential_access.detect),
        ("persistence", persistence.detect),
        ("lateral_movement", lateral_movement.detect),
        ("defense_evasion", defense_evasion.detect),
        ("execution_impact", execution_impact.detect),
        ("powershell_script", powershell_script.detect),
        ("behavioral", behavioral.detect),
        # Partial/under-covered EVTX patterns live in a separate detector so
        # they can be timed, isolated, and terminated just like the core rules.
        ("telemetry_context", telemetry_context.detect),
    ]

    configured = (os.environ.get(DETECTOR_EXECUTOR_ENV, "") or "").strip().lower()
    use_process_pool = configured not in {"thread", "threads"}
    if configured not in {"", "process", "processes", "thread", "threads"}:
        logging.warning("Ignoring invalid %s=%r; using process", DETECTOR_EXECUTOR_ENV, configured)
    process_pool = None
    pool_has_events = False
    pool_disabled = False
    try:
        for detector_name, detector_fn in detector_functions:
            result: Optional[Dict[str, Any]] = None
            spec = _detector_process_spec(detector_fn) if use_process_pool else None
            if spec and events and not pool_disabled:
                module_name, function_name = spec
                if process_pool is None:
                    try:
                        process_pool = _new_detector_process_pool()
                        pool_has_events = False
                    except Exception as exc:
                        pool_disabled = True
                        if diagnostic_callback:
                            diagnostic_callback(f"detector_process_pool_start_error:{detector_name}:{exc}")
                if process_pool is not None:
                    result = _run_detector_in_process_pool(
                        detector_name,
                        module_name,
                        function_name,
                        events,
                        timeout_seconds,
                        process_pool,
                        load_events=not pool_has_events,
                    )
                    if result.get("terminate_pool"):
                        _terminate_detector_process_pool(process_pool)
                        process_pool = None
                        pool_has_events = False
                    elif process_pool is not None:
                        # A completed task (including a detector-level error)
                        # means the child has loaded this investigation's
                        # event snapshot and can reuse it for the next rule.
                        pool_has_events = True

            if result is None:
                # Empty inputs use the zero-work fast path for built-ins; mocks
                # and embedding callables retain the compatibility timeout path.
                result = _run_detector_with_timeout(detector_name, detector_fn, events, timeout_seconds)

            detector_timings[f"{detector_name}_ms"] = int(float(result.get("runtime_seconds", 0.0)) * 1000)
            if result.get("status") == "ok":
                all_alerts.extend(result.get("alerts", []))
                continue

            reason = "timeout" if result.get("status") == "timeout" else "error"
            detail = str(result.get("error", "") or "")
            extra = {
                "timeout_seconds": timeout_seconds,
                "runtime_seconds": float(result.get("runtime_seconds", 0.0)),
                "executor": str(result.get("executor", "") or ""),
            }
            if result.get("terminated"):
                extra["terminated"] = True
            _append_partial_failure(
                partial_failures,
                component="detector",
                name=detector_name,
                reason=reason,
                detail=detail,
                extra=extra,
            )
            if diagnostic_callback:
                diagnostic_callback(f"detector_{reason}:{detector_name}:{detail}")
    finally:
        if process_pool is not None:
            _close_detector_process_pool(process_pool)
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
    elif status_name == "file_warning":
        parse_progress["warning_count"] = int(parse_progress.get("warning_count", 0)) + 1
        file_name = os.path.basename(str(update.get("file_path", "")))
        if file_name and file_name not in parse_progress["failed_files"]:
            parse_progress["failed_files"].append(file_name)
    else:
        return status_name

    parse_progress["parsed_event_count"] = int(
        parse_progress.get("_completed_parsed_events", 0)
    ) + int(parse_progress.get("active_parsed_events", 0))
    return status_name


def _public_live_progress(live_progress: dict) -> dict:
    public = dict(live_progress)
    # Do not expose raw exception text through the live progress endpoint;
    # the collection summary already carries safe, human-readable guidance.
    public.pop("failed_errors", None)
    public.pop("failed_codes", None)
    public.pop("fallback_failed_codes", None)
    return public


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
            fallback_codes = dict(live_progress.get("fallback_failed_codes", {}) or {})
            raw_code = update.get("win32_code")
            if raw_code is not None:
                try:
                    fallback_codes[channel] = int(raw_code)
                except (TypeError, ValueError):
                    pass
                live_progress["fallback_failed_codes"] = fallback_codes
        live_progress["last_warning"] = str(update.get("message") or live_progress.get("last_warning", ""))
    elif status_name == "channel_error":
        # A channel that failed both the modern and legacy APIs is genuinely
        # unreadable. Track it separately from recoverable fallback warnings so
        # telemetry accounting can exclude it without parsing warning strings.
        channel = str(update.get("channel") or "").strip()
        if channel:
            failed_channels = list(live_progress.get("failed_channels", []) or [])
            if channel not in failed_channels:
                failed_channels.append(channel)
            live_progress["failed_channels"] = failed_channels
            failed_errors = dict(live_progress.get("failed_errors", {}) or {})
            failed_errors[channel] = str(update.get("error") or "")
            live_progress["failed_errors"] = failed_errors
            failed_codes = dict(live_progress.get("failed_codes", {}) or {})
            raw_code = update.get("win32_code")
            if raw_code is not None:
                try:
                    failed_codes[channel] = int(raw_code)
                except (TypeError, ValueError):
                    pass
            live_progress["failed_codes"] = failed_codes
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
        if update.get("fallback") and not update.get("failed"):
            live_progress["fallback_channels"] = int(live_progress.get("fallback_channels", 0)) + 1
        if update.get("partial") and not update.get("failed"):
            partial_channels = list(live_progress.get("partial_channels", []) or [])
            channel = str(update.get("channel") or "").strip()
            if channel and channel not in partial_channels:
                partial_channels.append(channel)
            live_progress["partial_channels"] = partial_channels
        if update.get("failed"):
            channel = str(update.get("channel") or "").strip()
            if channel:
                failed_channels = list(live_progress.get("failed_channels", []) or [])
                if channel not in failed_channels:
                    failed_channels.append(channel)
                live_progress["failed_channels"] = failed_channels
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
    partial_channels = list(live_progress.get("partial_channels", []) or [])
    failed_channels = list(live_progress.get("failed_channels", []) or [])
    failed_errors = dict(live_progress.get("failed_errors", {}) or {})
    failed_codes = dict(live_progress.get("failed_codes", {}) or {})
    fallback_failed_codes = dict(live_progress.get("fallback_failed_codes", {}) or {})
    permission_denied_channels: List[str] = []
    unavailable_channels: List[str] = []
    for channel in failed_channels:
        error_text = failed_errors.get(channel) or ""
        numeric_code = failed_codes.get(channel)
        classification_source = numeric_code if numeric_code is not None else error_text
        if classify_live_channel_error(classification_source) == "access_denied":
            permission_denied_channels.append(channel)
        else:
            unavailable_channels.append(channel)
    fallback_permission_channels = [
        channel
        for channel in warning_channels
        if classify_live_channel_error(fallback_failed_codes.get(channel, "")) == "access_denied"
    ]
    recommendations: List[str] = []

    if permission_denied_channels:
        recommendations.append(
            f"Rerun the live scan with elevated privileges to read: {', '.join(permission_denied_channels)}."
        )
    if unavailable_channels:
        recommendations.append(
            f"Event log channels could not be read: {', '.join(unavailable_channels)}."
        )
    if fallback_permission_channels:
        recommendations.append(
            f"The modern Event Log API required elevation, so legacy fallback read succeeded with reduced fidelity on: {', '.join(fallback_permission_channels)}. "
            "Rerun elevated for full-precision event details."
        )
    remaining_telemetry_gaps = [
        gap for gap in list(telemetry_gaps or [])
        if not (gap == "Security" and permission_denied_channels)
    ]
    recommendations.extend(_telemetry_gap_recommendations(remaining_telemetry_gaps))
    failed_any = bool(permission_denied_channels or unavailable_channels)
    if not int(live_progress.get("parsed_event_count", 0)) and not failed_any:
        recommendations.append("If you expected activity in this window, widen the live lookback and include additional channels.")

    summary_bits = [
        f"Live collection scanned {int(live_progress.get('channel_count', len(channels) or 0))} channel(s)",
        f"over the last {int(live_progress.get('since_minutes', 30))} minute(s)",
        f"and parsed {int(live_progress.get('parsed_event_count', 0))} event(s).",
    ]
    if warning_channels:
        summary_bits.append(f"Warnings affected: {', '.join(warning_channels)}.")
    if partial_channels:
        summary_bits.append(f"Partial reads: {', '.join(partial_channels)}.")
    if permission_denied_channels:
        summary_bits.append(f"Permission issues detected on: {', '.join(permission_denied_channels)}.")
    if unavailable_channels:
        summary_bits.append(f"Unreadable channels: {', '.join(unavailable_channels)}.")
    if fallback_permission_channels:
        summary_bits.append(f"Legacy fallback used after denied API access on: {', '.join(fallback_permission_channels)}.")

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
        "partial_channels": partial_channels,
        "permission_denied_channels": permission_denied_channels,
        "unavailable_channels": unavailable_channels,
        "fallback_permission_channels": fallback_permission_channels,
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
        partial_sources = list(live_summary.get("partial_channels", []) or [])
        warning_sources = list(dict.fromkeys(
            list(live_summary.get("warning_channels", []) or []) + partial_sources
        ))
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
            "warning_sources": warning_sources,
            "partial_sources": partial_sources,
            "permission_denied_sources": list(live_summary.get("permission_denied_channels", []) or []),
            "unavailable_sources": list(live_summary.get("unavailable_channels", []) or []),
            "fallback_permission_sources": list(live_summary.get("fallback_permission_channels", []) or []),
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
        "partial_sources": [],
        "permission_denied_sources": [],
        "unavailable_sources": [],
        "fallback_used": fallback_used,
        "telemetry_present": _telemetry_present_display(telemetry_summary),
        "telemetry_missing": list(telemetry_gaps or []),
        "recommendations": recommendations,
        "summary": " ".join(summary_bits).strip(),
    }


# ---------------------------------------------------------------------------
# Summary / brief writers — moved from cli.py (single copy)
# ---------------------------------------------------------------------------

def _host_verdict_lines(case_meta: dict, limit: int = 25) -> List[str]:
    scope = case_meta.get("evidence_scope", {}) or {}
    lines = []
    for row in (scope.get("hosts", []) or [])[:limit]:
        verdict = row.get("verdict", {}) or {}
        lines.append(
            f"{row.get('host', '')}: {verdict.get('disposition', 'Not determined')} "
            f"({verdict.get('response_priority', 'P4')}) - {row.get('finding_count', 0)} finding(s), "
            f"{row.get('incident_count', 0)} incident(s), {row.get('event_count', 0)} event(s)"
        )
    return lines


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
    partial_sources = sanitize_display_values(collection_summary.get("partial_sources", []))
    permission_denied_sources = sanitize_display_values(collection_summary.get("permission_denied_sources", []))
    unavailable_sources = sanitize_display_values(collection_summary.get("unavailable_sources", []))

    lines = [
        f"Case: {case_meta.get('case_name', '')}",
        f"Input Source: {display_source}",
        f"Primary Host: {case_meta.get('primary_host', '')}",
        f"Primary User: {case_meta.get('primary_user', '')}",
        f"Primary Source IP: {case_meta.get('primary_source_ip', '')}",
        f"Response Priority: {case_meta.get('response_priority', 'P4')}",
        f"Triage Disposition: {(case_meta.get('triage_disposition', {}) or {}).get('disposition', 'Not determined')}",
        f"Triage Confidence: {(case_meta.get('triage_disposition', {}) or {}).get('confidence', 'unknown')} ({(case_meta.get('triage_disposition', {}) or {}).get('confidence_score', 0)}%)",
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
    if case_meta.get("forensic_summary"):
        snapshot = case_meta["forensic_summary"]
        lines.extend([f"Forensic Observations: {snapshot['observation_count']} ({snapshot['completeness']} supplied-input processing)",
                      f"Artifact Collection Time: {snapshot['observed_at']}",
                      f"Artifact Interpretation: {snapshot['interpretation']}",
                      "Complete display observations: forensic_observations.json; original records: evidence_manifest.json."])
    if collection_summary:
        lines.extend(
            [
                f"Collection Quality Summary: {collection_summary.get('summary', '')}",
                f"Collection Source Kind: {collection_summary.get('source_kind', 'unknown')}",
                f"Collection Source Count: {collection_summary.get('source_count', 0)}",
                f"Collection Parsed Event Count: {collection_summary.get('parsed_event_count', 0)}",
                f"Collection Warning Count: {collection_summary.get('warning_count', 0)}",
                f"Collection Warning Sources: {', '.join(warning_sources) or 'None'}",
                f"Collection Partial Sources: {', '.join(partial_sources) or 'None'}",
                f"Collection Permission Denied Sources: {', '.join(permission_denied_sources) or 'None'}",
                f"Collection Unavailable Sources: {', '.join(unavailable_sources) or 'None'}",
                f"Collection Fallback Used: {'Yes' if collection_summary.get('fallback_used') else 'No'}",
            ]
        )
        recommendations = list(collection_summary.get("recommendations", []) or [])
        if recommendations:
            lines.append(f"Collection Recommendations: {' | '.join(recommendations)}")
    scope = case_meta.get("evidence_scope", {}) or {}
    if scope.get("warnings"):
        lines.append(f"Evidence Scope Warnings: {' | '.join(scope['warnings'])}")
    host_lines = _host_verdict_lines(case_meta)
    if len(host_lines) > 1:
        lines.extend(["", "Per-Host Verdicts:"])
        lines.extend([f"- {line}" for line in host_lines])
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
    partial_sources = sanitize_display_values(collection_summary.get("partial_sources", []))
    permission_denied_sources = sanitize_display_values(collection_summary.get("permission_denied_sources", []))
    unavailable_sources = sanitize_display_values(collection_summary.get("unavailable_sources", []))

    lines = [
        f"# Incident Brief: {case_meta.get('case_name', '')}",
        "",
        "## Case Overview",
        f"- Input source: {display_source}",
        f"- Primary host: {case_meta.get('primary_host', '')}",
        f"- Primary user: {case_meta.get('primary_user', '')}",
        f"- Primary source IP: {case_meta.get('primary_source_ip', '')}",
        f"- Response priority: {case_meta.get('response_priority', 'P4')}",
        f"- Triage disposition: {(case_meta.get('triage_disposition', {}) or {}).get('disposition', 'Not determined')}",
        f"- Triage confidence: {(case_meta.get('triage_disposition', {}) or {}).get('confidence', 'unknown')} ({(case_meta.get('triage_disposition', {}) or {}).get('confidence_score', 0)}%)",
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
                f"- Partial sources: {', '.join(partial_sources) or 'None'}",
                f"- Permission denied sources: {', '.join(permission_denied_sources) or 'None'}",
                f"- Unavailable sources: {', '.join(unavailable_sources) or 'None'}",
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
        *([f"- {line}" for line in _host_verdict_lines(case_meta)]
          or [f"- {h}" for h in case_meta.get("hosts", [])] or ["- None"]),
        "",
        "## Affected Users",
        *([f"- {u}" for u in case_meta.get("users", [])] or ["- None"]),
        "",
        "## Observed IPs",
        *([f"- {ip}" for ip in case_meta.get("ips", [])] or ["- None"]),
        "",
        "## Evidence Timeline",
    ])

    if timeline_preview:
        for row in timeline_preview:
            lines.append(
                f"- {row.get('timestamp', '')} {row.get('display_label', row.get('id', ''))} {row.get('title', '')} ({row.get('type', '')}; {row.get('time_semantics', 'event_timestamp')})"
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
            unavailable_sources = list(collection_summary.get("unavailable_sources", []) or [])
            if (
                telemetry_missing
                or warning_sources
                or permission_denied_sources
                or unavailable_sources
                or collection_summary.get("fallback_used")
            ):
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

    if request.input_mode not in {"evtx_path", "live", "artifact_bundle"}:
        raise ValueError("Unsupported investigation input_mode")
    cases_root = os.path.abspath(request.cases_dir or os.path.join(ROOT_DIR, "cases"))
    case_name = request.case_name or auto_case_name(
        request.input_source if request.input_mode != "live" else None,
        request.input_mode == "live",
        ",".join(request.channels or []),
    )
    if request.input_mode == "artifact_bundle" and request.case_name is None:
        case_name = case_name.replace("case-evtx-", "case-artifact-", 1)
    if case_name in {".", ".."} or os.path.basename(case_name) != case_name or ":" in case_name or "\\" in case_name or "/" in case_name:
        raise ValueError("Case name must be a directory name within the cases root")
    case_path = ensure_case_dir(
        cases_root, case_name, overwrite=request.overwrite, resume=request.resume,
    )
    resolved_case_name = os.path.basename(case_path)
    input_source = (
        request.input_source
        if request.input_mode != "live"
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
    sources: list[dict] = []
    forensic = None
    collection_warnings: list[str] = []
    run_id = str(uuid.uuid4())
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
        identity = case_identity(case_path)
        rpt.on_metadata("case_id", identity["case_id"])
        rpt.on_metadata("run_id", run_id)
        def publish_sources():
            atomic_json(os.path.join(case_path, "evidence_manifest.json"), {"schema_version": "1.0", "case_id": identity["case_id"],
                        "run_id": run_id, "sources": public_sources(sources), "original_sources_redacted": False})
        publish_sources()
        bundle_path = request.artifact_bundle or (request.input_source if request.input_mode == "artifact_bundle" else None)
        if bundle_path:
            rpt.on_stage("acquire", "Verifying and retaining forensic artifact sources")
            artifact_sources = []

            def retain_artifact_sources(files, verified_hashes):
                captured = capture_evidence(case_path, files)
                for source in captured:
                    if source["sha256"] != verified_hashes[source["_source_path"]]:
                        raise ValueError("Artifact changed between verification and evidence capture")
                artifact_sources.extend(captured)
                sources.extend(captured)
                publish_sources()

            forensic = read_forensic_bundle(bundle_path, retain_verified_sources=retain_artifact_sources,
                                            allow_large_ntfs=request.allow_large_ntfs)
            retained_by_hash = {entry["sha256"]: entry for entry in artifact_sources}
            if forensic.ntfs is not None:
                forensic.ntfs.bind_retained_paths({sha: entry["path"] for sha, entry in retained_by_hash.items()})
            for observation in forensic.observations:
                observation["source_file"] = retained_by_hash[observation["source_sha256"]]["path"]
            for alert in forensic.alerts:
                alert.evidence["source_file"] = retained_by_hash[alert.evidence["source_sha256"]]["path"]
            collection_warnings.extend(forensic.manifest.get("warnings", []))
            if forensic.manifest["completeness"] == "partial" and not collection_warnings:
                collection_warnings.append("Artifact collector declared partial coverage.")
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
        rpt.on_stage(stage, "Normalizing forensic observations" if request.input_mode == "artifact_bundle" else "Parsing events")

        if request.input_mode == "evtx_path":
            parse_profile = describe_evtx_path(request.input_source)
            evtx_sources = capture_evidence(case_path, [(path, "evtx") for path in parse_profile.get("files", [])])
            if not evtx_sources:
                raise ValueError("No EVTX evidence files were supplied")
            sources.extend(evtx_sources)
            publish_sources()
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
            failed_input_paths: set[str] = set()
            retained_paths = {
                os.path.normcase(os.path.abspath(entry["_retained_path"])) for entry in evtx_sources
            }
            source_by_path = {
                os.path.normcase(os.path.abspath(entry["_retained_path"])): entry for entry in evtx_sources
            }

            def _on_parse(update: dict) -> None:
                with prog_lock:
                    _check_timeout(stage)
                    retained_path = str(update.get("file_path", "") or "")
                    path_key = os.path.normcase(os.path.abspath(retained_path)) if retained_path else ""
                    source = source_by_path.get(path_key)
                    index = update.get("file_index")
                    if isinstance(index, int) and 1 <= index <= len(evtx_sources):
                        source = evtx_sources[index - 1]
                    display_update = dict(update)
                    if source:
                        display_update["file_path"] = source["original_name"]
                        display_update["retained_file_path"] = retained_path
                    status_name = _apply_parse_progress_update(parse_progress, display_update)
                    rpt.on_metadata("parse_progress", _public_parse_progress(parse_progress))
                    rpt.on_parse_progress(display_update)
                    if status_name == "file_error":
                        if path_key:
                            failed_input_paths.add(path_key)
                        failed_file = os.path.basename(display_update.get("file_path", "") or "")
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
                    elif status_name == "file_warning":
                        warning = str(update.get("warning") or update.get("message") or "Parser reported partial data.")
                        _append_partial_failure(partial_failures, component="parser",
                                                name=os.path.basename(str(display_update.get("file_path", ""))),
                                                reason="partial_records", detail=warning)
                        rpt.on_metadata("partial_failures", list(partial_failures))
                        rpt.on_diagnostic(warning)
                    elif status_name == "file_complete":
                        failed_input_paths.discard(path_key)
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
                source_files=[entry["_retained_path"] for entry in evtx_sources],
            )
            bind_event_sources(events, evtx_sources)
            # Identical inputs share one retained path. Count the retained byte
            # sources, not original filenames, when deciding whether any input
            # was readable. A successful fallback clears an earlier failure.
            if retained_paths and retained_paths.issubset(failed_input_paths):
                raise RuntimeError(
                    "No EVTX files could be read. Investigation stopped without producing a verdict. "
                    + str(parse_progress.get("last_error", "Check the parser and input files."))
                )
        elif request.input_mode == "live":
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
                "partial_channels": [],
                "failed_channels": [],
                "failed_errors": {},
                "fallback_failed_codes": {},
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
            collection_warnings.extend(live_warnings)
            collection_warnings.append("Live API records have no retained native EVTX acquisition file.")
        else:
            events = []

        _check_timeout(stage)
        # In live mode, a successfully-read channel counts as present even if
        # the lookback window was quiet. Only channels that failed both the
        # modern and legacy APIs are genuinely unreadable and should remain
        # missing. Recoverable fallback warnings are not failures.
        readable_channels_for_telemetry = None
        if request.input_mode == "live":
            failed_channels = set(live_progress.get("failed_channels", []) or [])
            readable_channels_for_telemetry = [
                channel for channel in (channels or []) if channel not in failed_channels
            ]
        telemetry_summary = summarize_telemetry(
            events,
            readable_channels=readable_channels_for_telemetry,
        )
        telemetry_gaps = list(telemetry_summary.get("missing", []))
        rpt.on_metadata("telemetry_summary", telemetry_summary)

        # ---- detect ----
        stage = "detect"
        _flush_stage_timing(stage)
        _check_timeout(stage)
        rpt.on_stage(stage, "Evaluating artifact configuration" if request.input_mode == "artifact_bundle" else "Running detectors")
        raw_alerts, detector_timings = _run_detectors(
            events,
            timeout_seconds=detector_timeout_seconds,
            partial_failures=partial_failures,
            diagnostic_callback=rpt.on_diagnostic,
        ) if request.input_mode != "artifact_bundle" else ([], {})
        if forensic:
            raw_alerts.extend(forensic.alerts)
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
            for diag in sigma_diagnostics:
                _append_partial_failure(partial_failures, component="sigma", name="Sigma", reason="rule_skipped", detail=str(diag))
        elif request.enable_sigma:
            _append_partial_failure(partial_failures, component="sigma", name="Sigma", reason="unavailable", detail="Install the sigma extra to enable evaluation.")

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
        native_alerts = deduplicate([alert for alert in filtered_alerts if alert.rule_source != "forensic_artifact"])
        alerts = native_alerts + [alert for alert in filtered_alerts if alert.rule_source == "forensic_artifact"]
        chains = correlate(native_alerts)
        # Cross-source links need both event records and artifact observations.
        # EVTX-only and artifact-only cases are unchanged.
        relationships: list = []
        relationship_coverage: Dict[str, Any] = {}
        correlation_enabled = os.environ.get("TRIAGE_FORENSIC_CORRELATION", "1").strip() != "0"
        if forensic and events and correlation_enabled:
            relationships, relationship_coverage = correlate_evidence(events, forensic.observations, ntfs=forensic.ntfs)
            alerts.extend(cross_source_alerts(relationships, events, alerts))

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
        # Snapshot configuration has a collection timestamp, not an execution
        # timestamp. It must not participate in temporal execution chains.
        # Cross-source findings restate already-scored activity with artifact
        # links; keeping them out avoids promoting incidents from the links alone.
        non_execution = {"collection_snapshot", "cross_source_correlation"}
        execution_signals = [signal for signal in signals if signal.evidence.get("time_semantics") not in non_execution]
        execution_findings = [finding for finding in findings if finding.evidence.get("time_semantics") not in non_execution]
        incidents = build_incidents(events, execution_signals, execution_findings, chains)

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
        if forensic:
            artifact_host = forensic.manifest["host"]
            entities["hosts"] = sorted(set(entities.get("hosts", []) + [artifact_host]))
            if not entities.get("primary_host"):
                entities["primary_host"] = artifact_host

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
        campaign_summary = build_campaign_summary(execution_signals, execution_findings, incidents)

        case_meta: Dict[str, Any] = {
            "case_id": identity["case_id"],
            "run_id": run_id,
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
        if forensic:
            artifact_times = sorted(observation["timestamp"] for observation in forensic.observations
                                    if observation.get("timestamp"))
            persistence_only = forensic.manifest["kind"] == "windows_persistence_snapshot"
            case_meta["forensic_summary"] = {
                "kind": forensic.manifest["kind"], "host": forensic.manifest["host"],
                "observed_at": forensic.manifest["observed_at"],
                "observation_count": len(forensic.observations),
                "by_kind": dict(Counter(observation["kind"] for observation in forensic.observations)),
                "completeness": forensic.manifest["completeness"],
                "warnings": collection_warnings,
                "time_semantics": "collection_snapshot" if persistence_only else "source_specific_artifact_times",
                "by_time_semantics": dict(Counter(observation["time_semantics"] for observation in forensic.observations)),
                "first_recorded_activity": artifact_times[0] if artifact_times else "",
                "last_recorded_activity": artifact_times[-1] if artifact_times else "",
                "interpretation": ("Current configuration observed; execution and historical creation times are unconfirmed."
                                   if persistence_only else "Download, Prefetch run, and collection times retain their source meaning; identity and malicious intent require corroboration."),
                "artifact_path": "forensic_observations.json",
            }
            relationship_ids = defaultdict(list)
            for relationship in relationships:
                relationship_ids[relationship["target"]["observation_id"]].append(relationship["relationship_id"])
            for observation in forensic.observations:
                observation["relationship_ids"] = relationship_ids.get(observation["id"], [])
            case_meta["forensic_correlation"] = {
                "enabled": correlation_enabled, "evaluated": bool(events) and correlation_enabled,
                "relationship_count": len(relationships),
                "by_link_class": dict(Counter(item["link_class"] for item in relationships)),
                "by_rule": dict(Counter(item["rule"]["name"] for item in relationships)),
                "cross_source_finding_count": sum(1 for alert in alerts if alert.rule_source == "forensic_correlation"),
                "coverage": relationship_coverage,
                "artifact_path": "evidence_relationships.json",
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
        if request.input_mode == "artifact_bundle":
            collection_quality_summary = {
                "mode": "offline", "source_kind": "persistence_snapshot" if persistence_only else "forensic_artifacts",
                "source_count": len(sources), "completed_source_count": len(sources),
                "source_names": [entry["original_name"] for entry in sources],
                "parsed_event_count": 0, "observed_artifact_count": len(forensic.observations),
                "warning_count": len(collection_warnings), "warning_sources": collection_warnings,
                "telemetry_present": [], "telemetry_missing": telemetry_gaps,
                "recommendations": ["Corroborate source identity and reported activity with independent event and filesystem evidence."],
                "summary": f"Observed {len(forensic.observations)} forensic artifact record(s); no Windows event telemetry was supplied.",
            }
        case_meta["collection_quality_summary"] = collection_quality_summary
        rpt.on_metadata("collection_quality_summary", collection_quality_summary)
        case_meta["response_priority"] = response_priority(incidents, case_meta)
        triage = derive_disposition(
            incident_count=len(incidents),
            finding_count=len(findings),
            response_priority=case_meta["response_priority"],
            confidence_score=max([int(getattr(i, "confidence_score", 0) or 0) for i in incidents] +
                                 [int(getattr(f, "confidence_score", 0) or 0) for f in findings] + [0]),
            telemetry_gaps=telemetry_gaps,
        )
        evidence_scope = build_evidence_scope(events, findings, incidents, telemetry_gaps=telemetry_gaps)
        if forensic:
            evidence_scope["artifact_scope"] = case_meta["forensic_summary"]
            triage.recommended_next.insert(0,
                "Persistence snapshot times describe collection. Validate execution using independent event or filesystem evidence."
                if persistence_only else "Validate browser downloads and Prefetch run records using independent evidence; collection time is separate from recorded activity.")
        case_meta["evidence_scope"] = evidence_scope
        if evidence_scope["needs_scope_review"]:
            triage.recommended_next.insert(0, "Confirm the evidence scope: " + " ".join(evidence_scope["warnings"]))
        case_meta["triage_disposition"] = triage.to_dict()
        case_meta["client_id"] = request.client_id or "default"
        case_meta["acquisition_method"] = request.acquisition_method or ("local_live" if request.input_mode == "live" else "upload")
        manifest = request.collection_manifest or {
            "method": case_meta["acquisition_method"],
            "source_host": entities.get("primary_host", ""),
            "channels": request.channels or [],
            "tool_version": __version__ if "__version__" in globals() else "",
        }
        case_meta["collection_manifest"] = manifest
        case_meta["schema_version"] = "1.0"
        try:
            # Keep product metadata beside the selected case root. This makes
            # isolated CLI/test workspaces self-contained and avoids leaking
            # customer metadata into the source checkout's default data dir.
            store = ClientStore(data_dir=os.path.join(os.path.dirname(cases_root), "data"))
            metadata = store.save_case_metadata(CaseMetadata(
                case_name=resolved_case_name,
                client_id=request.client_id or "default",
                acquisition_method=case_meta["acquisition_method"],
                collection_manifest=manifest,
            ))
            case_meta["client_id"] = metadata.client_id
            case_meta["retention_until"] = metadata.retention_until
            with open(os.path.join(case_path, "case_metadata.json"), "w", encoding="utf-8") as fh:
                json.dump(metadata.to_dict(), fh, indent=2, sort_keys=True)
        except Exception as metadata_exc:
            partial_failures.append({"component": "metadata", "reason": "persist_failed", "detail": str(metadata_exc)})
        rpt.on_metadata("triage_disposition", case_meta["triage_disposition"])

        rpt.on_metadata("case_metrics", case_metrics)
        rpt.on_metadata("evidence_scope", {k: v for k, v in evidence_scope.items() if k != "hosts"})
        rpt.on_metadata("response_priority", case_meta["response_priority"])
        rpt.on_metadata("suppression_summary", suppression_summary)
        rpt.on_metadata("rule_metrics", rule_metrics[:25])
        rpt.on_metadata("tuning_recommendations", tuning_recommendations)
        rpt.on_metadata("campaign_summary", campaign_summary)
        # Keep a compact, deterministic summary available to local callers
        # even when endpoint protection blocks a subsequent read of the full
        # findings artifact.  The corpus scanner uses this as an in-memory
        # fallback; it intentionally contains no raw commands or event data.
        rpt.on_metadata(
            "analysis_summary",
            {
                "schema_version": "1.0",
                "signal_count": len(signals),
                "finding_count": len(findings),
                "incident_count": len(incidents),
                "signal_techniques": sorted(
                    {str(item.mitre_technique).strip() for item in signals if item.mitre_technique}
                ),
                "finding_techniques": sorted(
                    {str(item.mitre_technique).strip() for item in findings if item.mitre_technique}
                ),
                "severity_counter": dict(
                    Counter(
                        [str(item.severity).strip().lower() for item in signals + findings if item.severity]
                    )
                ),
                "parsed_event_count": int(
                    (collection_quality_summary or {}).get("parsed_event_count", 0) or 0
                ),
            },
        )

        # ---- export artifacts ----
        artifacts: Dict[str, str] = {}
        evidence_manifest_path = os.path.join(case_path, "evidence_manifest.json")
        atomic_json(evidence_manifest_path, {"schema_version": "1.0", "case_id": identity["case_id"], "run_id": run_id,
                                           "sources": public_sources(sources), "original_sources_redacted": False})
        artifacts["evidence_manifest"] = evidence_manifest_path
        artifacts["case_identity"] = os.path.join(case_path, "case_identity.json")
        observations_path = os.path.join(case_path, "forensic_observations.json")
        atomic_json(observations_path, sanitize_export_data({"schema_version": "1.0", "case_id": identity["case_id"], "run_id": run_id,
                                                            "summary": case_meta.get("forensic_summary", {}),
                                                            "representation": "display_projection", "observations": forensic.observations if forensic else []}))
        artifacts["forensic_observations"] = observations_path
        rpt.on_artifact(observations_path)
        relationships_path = os.path.join(case_path, "evidence_relationships.json")
        atomic_json(relationships_path, sanitize_export_data({"schema_version": "1.0", "case_id": identity["case_id"], "run_id": run_id,
                                                             "representation": "derived_relationships",
                                                             "link_classes": ["observed_field_match", "supported_inference",
                                                                              "weak_temporal_association", "analyst_hypothesis"],
                                                             "summary": case_meta.get("forensic_correlation", {}),
                                                             "relationships": relationships}))
        artifacts["evidence_relationships"] = relationships_path
        rpt.on_artifact(relationships_path)

        stage = "timeline_export"
        _flush_stage_timing(stage)
        _check_timeout(stage)
        rpt.on_stage(stage, "Exporting timeline.json")
        timeline_path = os.path.join(case_path, "timeline.json")
        timeline_data = export_timeline(signals, findings, incidents, timeline_path,
                                        forensic_observations=forensic.observations if forensic else None)
        rpt.on_artifact(timeline_path)
        artifacts["timeline"] = timeline_path

        stage = "graph_export"
        _flush_stage_timing(stage)
        _check_timeout(stage)
        rpt.on_stage(stage, "Exporting graph.json")
        graph_path = os.path.join(case_path, "graph.json")
        graph = build_entity_graph(signals, findings, incidents)
        graph_data = export_graph(graph, graph_path)
        rpt.on_artifact(graph_path)
        artifacts["graph"] = graph_path

        stage = "findings_export"
        _flush_stage_timing(stage)
        _check_timeout(stage)
        rpt.on_stage(stage, "Exporting findings.json")
        findings_path = os.path.join(case_path, "findings.json")
        raw_events_path = os.path.join(case_path, "raw_events.jsonl")
        findings_data = export_case(
            signals=signals,
            findings=findings,
            incidents=incidents,
            filepath=findings_path,
            legacy_alerts=alerts,
            legacy_chains=chains,
            raw_events=events,
            case_meta=case_meta,
            raw_event_artifact_path=raw_events_path,
            forensic_observations=forensic.observations if forensic else None,
            evidence_relationships=relationships if forensic else None,
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
        # Use the in-memory payloads produced immediately above.  Endpoint
        # protection may deny a second read of JSON containing malware-like
        # evidence strings even though the write succeeded.
        generate_from_data(findings_data, timeline_data, graph_data, report_path)
        rpt.on_artifact(report_path)
        artifacts["report"] = report_path

        stage = "raw_export"
        _flush_stage_timing(stage)
        _check_timeout(stage)
        rpt.on_stage(stage, "Streaming raw_events.jsonl")
        try:
            raw_export = export_raw_events_stream(events, raw_events_path)
            rpt.on_artifact(raw_events_path)
            artifacts["raw_events"] = raw_events_path
        except Exception as raw_exc:
            rpt.on_diagnostic(f"raw_event_export_failed:{raw_exc}")
            _append_partial_failure(partial_failures, component="export", name="raw_events", reason="write_failed", detail=str(raw_exc))
            rpt.on_metadata("partial_failures", list(partial_failures))
            raise RuntimeError("Lossless normalized record export failed; analysis was not completed") from raw_exc

        stage = "analysis_manifest"
        _check_timeout(stage)
        component_paths = [str(path) for package in ("detectors", "parser", "models", "correlation", "reporting", "triage_engine")
                           for path in (Path(ROOT_DIR) / package).glob("*.py")]
        component_paths.extend(tuning_paths)
        component_paths.append(ioc_path)
        if request.enable_sigma:
            for path in sigma_paths:
                candidate = Path(path)
                if candidate.is_dir():
                    component_paths.extend(str(item) for item in candidate.rglob("*") if item.is_file() and item.suffix.lower() in {".yml", ".yaml"})
                else:
                    component_paths.append(path)
        analysis_manifest = write_analysis_manifest(
            case_path, run_id=run_id, sources=sources, artifacts=artifacts,
            configuration={"input_mode": request.input_mode, "start_date": str(request.start_date or ""),
                           "end_date": str(request.end_date or ""), "enable_sigma": request.enable_sigma,
                           "no_fp_filter": request.no_fp_filter, "tuning": tuning_config,
                           "live_channels": request.channels or [], "since_minutes": request.since_minutes,
                           "detector_timeout_seconds": detector_timeout_seconds,
                           "demo_redaction": os.environ.get("TRIAGE_DEMO_REDACTION", "")},
            component_files=component_paths, engine_version=__version__, partial_failures=partial_failures,
            collection_warnings=collection_warnings)
        artifacts["analysis_manifest"] = os.path.join(case_path, "analysis_manifest.json")
        rpt.on_artifact(artifacts["analysis_manifest"])
        rpt.on_metadata("analysis_completeness", analysis_manifest["completeness"])
        rpt.on_metadata("partial_failures", list(partial_failures))

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
            client_id=case_meta.get("client_id", request.client_id or "default"),
            triage_disposition=case_meta.get("triage_disposition", {}),
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
