"""Triage Engine — REST API and Web Dashboard.

Start with:
    python server.py

Then open http://localhost:8000 in your browser.

Architecture: this file is a thin HTTP adapter.  All investigation logic
lives in ``triage_engine.service``.  Jobs are persisted in SQLite via
``triage_engine.job_store``.
"""

from __future__ import annotations

from collections import deque
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
import csv
import hashlib
import hmac
import io
import json
import logging
import multiprocessing
import os
import re
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from sqlite3 import IntegrityError
from threading import BoundedSemaphore, Lock, Thread
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

# ---------------------------------------------------------------------------
# Path bootstrap
# ---------------------------------------------------------------------------
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from triage_engine.env_loader import load_project_env
load_project_env(ROOT_DIR, explicit=os.environ.get("TRIAGE_ENV_FILE"))

from fastapi import FastAPI, File, HTTPException, Query, Request, Response, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
from starlette.background import BackgroundTask
from starlette.middleware.trustedhost import TrustedHostMiddleware
import uvicorn

from triage_engine import __version__
from triage_engine.case_utils import resolve_case_path
from triage_engine.export_sanitizer import apply_demo_redaction_data, apply_demo_redaction_text
from triage_engine.forensic_api import build_forensics_router
from triage_engine.logging_config import configure_logging
from parser.live_reader import classify_live_channel_error
from triage_engine.service import InvestigationRequest, ProgressReporter, run_investigation
from triage_engine.webhooks import (
    WEBHOOK_SCHEMA_VERSION,
    build_event_id,
    dispatch_webhook_event,
    resolve_webhook_config_path,
)
from triage_engine.job_store import (
    create_job,
    update_job,
    get_job,
    list_jobs as db_list_jobs,
    delete_job,
    get_jobs_with_uploads,
    clear_upload_path,
    reconcile_interrupted_jobs,
)
from triage_engine.jev import DEFAULT_JEV_MODEL, JevIntegrationError, review_case as request_jev_review
from triage_engine.product import (
    ACQUISITION_METHODS,
    CaseMetadata,
    ClientProfile,
    ClientStore,
    CollectionManifest,
    AIProvider,
    capabilities,
    load_license_file,
    export_case_bundle,
)
from triage_engine.review_store import (
    get_finding_review,
    upsert_finding_review,
    get_incident_review,
    upsert_incident_review,
    add_note,
    get_notes,
    get_history,
    get_all_history,
    get_review_queue,
    carry_forward_reviews,
    materialize_reviews_for_completed_cases,
    materialize_queue_index_for_completed_cases,
    sync_queue_index_from_case_payload,
    get_all_finding_reviews,
    get_all_incident_reviews,
    delete_case_review_state,
    VALID_STATUSES,
    VALID_DISPOSITIONS,
)
from triage_engine.auth_store import (
    VALID_ROLES,
    authenticate_user,
    bootstrap_admin,
    change_password,
    cleanup_expired_sessions,
    create_session,
    list_active_sessions,
    create_user,
    delete_sessions_for_user,
    delete_session,
    get_session,
    get_user_preferences,
    has_users,
    list_users,
    list_audit_events,
    record_audit_event,
    session_max_age_seconds,
    update_user,
    update_user_preferences,
)
from scripts.backup_restore import create_backup as create_state_backup, list_backups as list_state_backups

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_SERVER_HOST = "127.0.0.1"
DEFAULT_SERVER_PORT = 8000
DEFAULT_DATA_DIR = "data"
DEFAULT_CASES_DIR = "cases"
DEFAULT_CORS_ORIGINS = "localhost"
DEFAULT_TRUSTED_HOSTS = "localhost,127.0.0.1,[::1],testserver"
DEFAULT_AI_ALLOWED_HOSTS = "api.openai.com,api.groq.com,api.anthropic.com,localhost,127.0.0.1,[::1]"
DEFAULT_MAX_UPLOAD_MB = 500
DEFAULT_MAX_CONCURRENT_JOBS = 2
DEFAULT_MAX_QUEUED_JOBS = 8
DEFAULT_RUNTIME_MODE = "local"


def _resolve_runtime_dir(env_name: str, default_relative: str) -> str:
    configured = str(os.environ.get(env_name, "") or "").strip()
    if not configured and getattr(sys, "frozen", False):
        local_app_data = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~/AppData/Local")
        return os.path.abspath(os.path.join(local_app_data, "TriageEngine", default_relative))
    value = configured or default_relative
    expanded = os.path.expanduser(value)
    if os.path.isabs(expanded):
        return os.path.abspath(expanded)
    return os.path.abspath(os.path.join(ROOT_DIR, expanded))


def _env_int(name: str, *, default: int, minimum: Optional[int] = None, maximum: Optional[int] = None) -> int:
    raw = str(os.environ.get(name, "") or "").strip()
    if not raw:
        value = int(default)
    else:
        try:
            value = int(raw)
        except ValueError:
            value = int(default)
    if minimum is not None:
        value = max(int(minimum), value)
    if maximum is not None:
        value = min(int(maximum), value)
    return value


def _runtime_mode_from_env(raw_value: str) -> str:
    normalized = str(raw_value or "").strip().lower()
    if normalized in {"local", "docker"}:
        return normalized
    return DEFAULT_RUNTIME_MODE


def _normalize_cors_origin(token: str, *, default_port: int) -> List[str]:
    normalized = str(token or "").strip()
    if not normalized:
        return []
    lowered = normalized.lower()
    if lowered == "localhost":
        return [f"http://localhost:{default_port}", f"http://127.0.0.1:{default_port}"]
    if "://" in normalized:
        return [normalized]
    if lowered.startswith("localhost") or lowered.startswith("127.0.0.1"):
        return [f"http://{normalized}"]
    return [f"https://{normalized}"]


def _cors_origins_from_env(raw_value: str, *, default_port: int) -> List[str]:
    configured = (raw_value or "").strip() or DEFAULT_CORS_ORIGINS
    origins: List[str] = []
    for token in configured.split(","):
        origins.extend(_normalize_cors_origin(token, default_port=default_port))
    deduped: List[str] = []
    seen = set()
    for origin in origins:
        if origin in seen:
            continue
        seen.add(origin)
        deduped.append(origin)
    if deduped:
        return deduped
    return [f"http://localhost:{default_port}", f"http://127.0.0.1:{default_port}"]


SERVER_HOST = str(os.environ.get("TRIAGE_HOST", DEFAULT_SERVER_HOST) or DEFAULT_SERVER_HOST).strip() or DEFAULT_SERVER_HOST
SERVER_PORT = _env_int("TRIAGE_PORT", default=DEFAULT_SERVER_PORT, minimum=1, maximum=65535)
DATA_ROOT = _resolve_runtime_dir("TRIAGE_DATA_DIR", DEFAULT_DATA_DIR)
CASES_ROOT = _resolve_runtime_dir("TRIAGE_CASES_DIR", DEFAULT_CASES_DIR)
UPLOAD_ROOT = _resolve_runtime_dir("TRIAGE_UPLOAD_DIR", (
    os.path.join(DATA_ROOT, "uploads")
    if getattr(sys, "frozen", False)
    else os.path.join(ROOT_DIR, "uploads")
))
STATIC_DIR = os.path.join(ROOT_DIR, "static")
BACKUPS_ROOT = os.path.join(DATA_ROOT, "backups")
os.makedirs(DATA_ROOT, exist_ok=True)
os.makedirs(CASES_ROOT, exist_ok=True)
os.makedirs(UPLOAD_ROOT, exist_ok=True)

# Max upload size per file: configurable via TRIAGE_MAX_UPLOAD_MB (default 500 MB)
MAX_UPLOAD_MB = _env_int("TRIAGE_MAX_UPLOAD_MB", default=DEFAULT_MAX_UPLOAD_MB, minimum=1)
MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024
# The aggregate limit protects disk and request handling when many individually
# valid files are submitted in a single investigation request.
MAX_AGGREGATE_UPLOAD_MB = _env_int(
    "TRIAGE_MAX_AGGREGATE_UPLOAD_MB", default=MAX_UPLOAD_MB, minimum=1
)
MAX_AGGREGATE_UPLOAD_BYTES = MAX_AGGREGATE_UPLOAD_MB * 1024 * 1024
UPLOAD_CHUNK_BYTES = 1024 * 1024
MAX_CONCURRENT_JOBS = _env_int(
    "TRIAGE_MAX_CONCURRENT_JOBS", default=DEFAULT_MAX_CONCURRENT_JOBS, minimum=1, maximum=32
)
MAX_QUEUED_JOBS = _env_int(
    "TRIAGE_MAX_QUEUED_JOBS", default=DEFAULT_MAX_QUEUED_JOBS, minimum=0, maximum=256
)
SESSION_COOKIE = "triage_session"
QUEUE_SYNC_INTERVAL_SECONDS = int(os.environ.get("TRIAGE_QUEUE_SYNC_INTERVAL_SECONDS", "30"))
CSRF_HEADER = "X-CSRF-Token"
CSRF_EXEMPT_PATHS = {"/api/auth/login", "/api/auth/bootstrap"}
STATE_CHANGING_METHODS = {"POST", "PATCH", "DELETE"}
RATE_LIMIT_WINDOW_SECONDS = 60
_CSRF_SECRET = os.environ.get("TRIAGE_CSRF_SECRET", "").strip() or secrets.token_urlsafe(32)
_WINDOWS_PATH_RE = re.compile(r"[A-Za-z]:[\\/][^\s\"']+")
_RATE_LIMIT_BUCKETS: Dict[str, deque[float]] = {}
_RATE_LIMIT_LOCK = Lock()
_RATE_LIMIT_MAX_KEYS = 10_000
_CURRENT_USER_UNSET = object()
_SERVER_STARTED_AT = time.monotonic()
STARTUP_DISK_HARD_MIN_BYTES = 100 * 1024 * 1024
STARTUP_DISK_WARN_BYTES = 1024 * 1024 * 1024
CORS_ORIGINS = _cors_origins_from_env(
    os.environ.get("TRIAGE_CORS_ORIGINS", DEFAULT_CORS_ORIGINS),
    default_port=SERVER_PORT,
)
TRUSTED_HOSTS = [
    value.strip()
    for value in str(os.environ.get("TRIAGE_TRUSTED_HOSTS", DEFAULT_TRUSTED_HOSTS) or "").split(",")
    if value.strip()
] or ["localhost", "127.0.0.1", "[::1]"]
AI_ALLOWED_HOSTS = {
    value.strip().lower().strip("[]")
    for value in str(os.environ.get("TRIAGE_AI_ALLOWED_HOSTS", DEFAULT_AI_ALLOWED_HOSTS) or "").split(",")
    if value.strip()
}
# X-Forwarded-For is only honored from these reverse-proxy peers; otherwise any
# client could spoof its address to evade per-IP login throttling.
TRUSTED_PROXIES = {
    value.strip().lower().strip("[]")
    for value in str(os.environ.get("TRIAGE_TRUSTED_PROXIES", "") or "").split(",")
    if value.strip()
}
REPORT_CSP = (
    "sandbox allow-scripts allow-popups allow-popups-to-escape-sandbox; "
    "frame-ancestors 'none'; object-src 'none'; base-uri 'none'; form-action 'none'"
)
BOOTSTRAP_TOKEN = str(os.environ.get("TRIAGE_BOOTSTRAP_TOKEN", "") or "").strip()
RUNTIME_MODE = _runtime_mode_from_env(os.environ.get("TRIAGE_RUNTIME_MODE", DEFAULT_RUNTIME_MODE))
RUNTIME_LABEL = "Docker" if RUNTIME_MODE == "docker" else "Local Python"

def _allowed_path_roots_from_env(raw_value: str) -> List[str]:
    """Resolve configured local-investigation roots without following prefixes."""
    roots: List[str] = []
    for value in str(raw_value or "").split(os.pathsep):
        candidate = value.strip()
        if not candidate:
            continue
        roots.append(os.path.realpath(os.path.abspath(os.path.expanduser(candidate))))
    return list(dict.fromkeys(roots))


# Empty remains backwards compatible for localhost deployments. Set
# TRIAGE_ALLOWED_PATH_ROOTS (semicolon-separated on Windows) to confine path
# investigations to explicit evidence directories.
ALLOWED_PATH_ROOTS = _allowed_path_roots_from_env(os.environ.get("TRIAGE_ALLOWED_PATH_ROOTS", ""))

# Jobs are admitted before execution so a burst cannot create unbounded native
# worker threads. Keep the imported Thread fallback for existing unit tests
# that replace ``server.Thread`` to inspect the submitted request.
_NATIVE_THREAD = Thread
_JOB_EXECUTOR = ThreadPoolExecutor(max_workers=MAX_CONCURRENT_JOBS, thread_name_prefix="triage-job")
_JOB_ADMISSION = BoundedSemaphore(MAX_CONCURRENT_JOBS + MAX_QUEUED_JOBS)

# Quick Check deliberately has a much narrower unauthenticated surface than
# the analyst API. A browser must first obtain a short-lived, process-local
# nonce over loopback, then present it on every state-changing quick endpoint.
# This permits a fresh portable install to run a check without creating an
# analyst account while keeping all generic cases, jobs, and review routes
# behind normal authentication.
QUICK_CHECK_HEADER = "X-Triage-Quick-Token"
QUICK_CHECK_SESSION_TTL_SECONDS = 30 * 60
_QUICK_CHECK_LOCK = Lock()
_QUICK_CHECK_SESSIONS: Dict[str, float] = {}
_QUICK_CHECK_JOBS: Dict[str, Dict[str, str]] = {}

OPENAPI_TAGS = [
    {"name": "Auth", "description": "Authentication, users, sessions, and audit operations."},
    {"name": "Cases", "description": "Case listing, artifact retrieval, and case lifecycle operations."},
    {"name": "Investigate", "description": "Start new investigations from upload, local path, or live channels."},
    {"name": "Jobs", "description": "Background investigation job status and lifecycle endpoints."},
    {"name": "Reviews", "description": "Review state, notes, queue, and history endpoints."},
    {"name": "Admin", "description": "Operational admin endpoints such as metrics and backup controls."},
]

CASE_EXPORT_FIELDNAMES = [
    "name",
    "status",
    "response_priority",
    "signal_count",
    "finding_count",
    "incident_count",
    "started_at",
    "completed_at",
    "stage",
    "message",
    "has_report",
    "has_findings",
]

REVIEW_QUEUE_EXPORT_FIELDNAMES = [
    "case_name",
    "item_type",
    "item_id",
    "item_title",
    "response_priority",
    "status",
    "disposition",
    "owner",
    "priority",
    "last_seen_at",
    "updated_at",
]

def _client_ip(request: Request) -> str:
    peer = str(request.client.host) if request.client and request.client.host else ""
    if peer and peer.lower() in TRUSTED_PROXIES:
        # Walk right-to-left past our own proxies; the first untrusted hop is
        # the real client. Left-most entries are client-controlled.
        hops = [hop.strip() for hop in (request.headers.get("x-forwarded-for", "") or "").split(",") if hop.strip()]
        for hop in reversed(hops):
            if hop.lower().strip("[]") not in TRUSTED_PROXIES:
                return hop[:64]
    return peer or "unknown"


def _csrf_token_for_session(session_id: str) -> str:
    if not session_id:
        return ""
    return hmac.new(_CSRF_SECRET.encode("utf-8"), session_id.encode("utf-8"), hashlib.sha256).hexdigest()


def _sanitize_error_message(detail: Any) -> str:
    message = str(detail or "").strip()
    if not message:
        return "Request failed"
    return _WINDOWS_PATH_RE.sub("[redacted-path]", message)


configure_logging(DATA_ROOT)
ACCESS_LOGGER = logging.getLogger("triage.access")
SERVER_LOGGER = logging.getLogger("triage.server")


def _request_id_from_header(raw_header: str) -> str:
    candidate = str(raw_header or "").strip()
    if candidate:
        return candidate[:128]
    return uuid.uuid4().hex


def _request_id_for_log(request: Request) -> str:
    return str(getattr(request.state, "request_id", "") or "")


def _attach_request_id_header(request: Request, response: Response) -> Response:
    request_id = _request_id_for_log(request)
    if request_id:
        response.headers["X-Request-ID"] = request_id
    # Evidence and authenticated responses must not survive in shared caches.
    response.headers.setdefault("Cache-Control", "no-store")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("Content-Security-Policy", "frame-ancestors 'none'; object-src 'none'; base-uri 'self'")
    return response


def _log_access(request: Request, user: Optional[Dict[str, Any]], status_code: int, duration_ms: int) -> None:
    ACCESS_LOGGER.info(
        "request_complete",
        extra={
            "request_id": _request_id_for_log(request),
            "user": user.get("username", "") if user else "",
            "duration_ms": int(duration_ms),
            "method": request.method,
            "path": request.url.path,
            "status": int(status_code),
            "client_ip": _client_ip(request),
        },
    )


def _consume_rate_limit(key: str, *, limit: int, now: float) -> tuple[bool, int]:
    with _RATE_LIMIT_LOCK:
        cutoff = now - RATE_LIMIT_WINDOW_SECONDS
        if len(_RATE_LIMIT_BUCKETS) > _RATE_LIMIT_MAX_KEYS:
            # Drop idle identities so distinct usernames/IPs cannot grow memory without bound.
            for stale in [k for k, b in _RATE_LIMIT_BUCKETS.items() if not b or b[-1] <= cutoff]:
                del _RATE_LIMIT_BUCKETS[stale]
        bucket = _RATE_LIMIT_BUCKETS.setdefault(key, deque())
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()
        if len(bucket) >= limit:
            retry_after = max(1, int((bucket[0] + RATE_LIMIT_WINDOW_SECONDS) - now) + 1)
            return False, retry_after
        bucket.append(now)
    return True, 0


async def _rate_limit_result(
    request: Request,
    user: Optional[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    path = request.url.path
    if not path.startswith("/api/"):
        return None

    method = request.method.upper()
    now = time.monotonic()
    ip = _client_ip(request)

    checks: List[tuple[str, int, str]] = []
    if method == "POST" and path == "/api/auth/login":
        username = ""
        try:
            raw = await request.body()
            if raw:
                payload = json.loads(raw.decode("utf-8"))
                username = str(payload.get("username") or "").strip().lower()
        except Exception:
            username = ""
        user_key = username or "__unknown__"
        checks.append((f"login-user:{user_key}", 5, "Too many login attempts for this username"))
        checks.append((f"login-ip:{ip}", 20, "Too many login attempts from this IP"))
    elif method == "POST" and path.startswith("/api/investigate"):
        identity = (user or {}).get("username") or ip
        checks.append((f"investigate:{identity}", 10, "Rate limit exceeded for investigation starts"))
    elif method == "POST" and path.endswith("/jev-review"):
        identity = (user or {}).get("username") or ip
        checks.append((f"jev-review:{identity}", 10, "Rate limit exceeded for Jev reviews"))
    elif method == "POST" and path.startswith("/api/quick/"):
        checks.append((f"quick-write:{ip}", 8, "Too many Quick Check requests"))
    elif method == "GET" and path.startswith("/api/quick/jobs/"):
        checks.append((f"quick-job-status:{ip}", 300, "Rate limit exceeded for Quick Check status polling"))
    elif method == "GET" and path.startswith("/api/jobs/"):
        # The dashboard polls job progress while a long EVTX run is active;
        # use a bounded but higher bucket for status reads only.
        identity = (user or {}).get("username") or ip
        checks.append((f"job-status:{identity}", 300, "Rate limit exceeded for job status polling"))
    else:
        identity = (user or {}).get("username") or ip
        checks.append((f"api:{identity}", 60, "Rate limit exceeded"))

    for key, limit, message in checks:
        allowed, retry_after = _consume_rate_limit(key, limit=limit, now=now)
        if not allowed:
            return {"detail": message, "retry_after": retry_after}
    return None


def _reset_security_state_for_tests() -> None:
    """Test hook for clearing in-memory security counters between test cases."""
    with _RATE_LIMIT_LOCK:
        _RATE_LIMIT_BUCKETS.clear()
    with _QUICK_CHECK_LOCK:
        _QUICK_CHECK_SESSIONS.clear()
        _QUICK_CHECK_JOBS.clear()


# ---------------------------------------------------------------------------
# Job-aware progress reporter — bridges service callbacks into SQLite
# ---------------------------------------------------------------------------

class _JobReporter:
    """Implements ProgressReporter, writing updates to the SQLite job store."""

    def __init__(self, job_id: str):
        self._job_id = job_id

    def on_stage(self, stage: str, message: str) -> None:
        update_job(self._job_id, stage=stage, message=message, status="running")

    def on_metadata(self, key: str, value: Any) -> None:
        pass  # metadata goes to run_status.json via RunStatus inside the service

    def on_artifact(self, path: str) -> None:
        pass

    def on_diagnostic(self, message: str) -> None:
        pass

    def on_complete(self, message: str) -> None:
        pass  # handled after run_investigation returns

    def on_failed(self, stage: str, error: str, traceback_text: Optional[str] = None) -> None:
        pass  # handled in the worker's except clause

    def on_parse_progress(self, update: dict) -> None:
        pass


# ---------------------------------------------------------------------------
# Background investigation worker
# ---------------------------------------------------------------------------

def _emit_completion_webhooks(
    *,
    job_id: str,
    request: InvestigationRequest,
    result: Any,
    incident_ids: Optional[List[str]] = None,
) -> None:
    disposition = dict(getattr(result, "triage_disposition", {}) or {})
    disposition_value = str(disposition.get("disposition") or "No promoted incident")
    confidence = str(disposition.get("confidence") or "unknown")
    try:
        confidence_score = int(disposition.get("confidence_score") or 0)
    except (TypeError, ValueError):
        confidence_score = 0
    artifact_ref = _case_artifact_ref(result)
    summary = _webhook_case_summary(result, disposition)
    payload: Dict[str, Any] = {
        "schema_version": WEBHOOK_SCHEMA_VERSION,
        "event_id": build_event_id("case.completed", {
            "case_name": result.case_name,
            "job_id": job_id,
        }),
        "client_id": str(getattr(result, "client_id", "") or request.client_id or "default"),
        "case_id": result.case_name,
        "case_name": result.case_name,
        "job_id": job_id,
        "requested_by": request.requested_by or "",
        "input_mode": request.input_mode,
        "input_source": request.input_source,
        "response_priority": str(getattr(result, "response_priority", "P4") or "P4"),
        "triage_disposition": disposition_value,
        "confidence": confidence,
        "confidence_score": confidence_score,
        "summary": summary,
        "artifact_ref": artifact_ref,
        "signal_count": int(getattr(result, "signal_count", 0) or 0),
        "finding_count": int(getattr(result, "finding_count", 0) or 0),
        "incident_count": int(getattr(result, "incident_count", 0) or 0),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if incident_ids:
        payload["incident_ids"] = [incident_id for incident_id in incident_ids if incident_id]

    completed_stats = dispatch_webhook_event(
        "case.completed",
        payload,
        root_dir=ROOT_DIR,
        config_path=resolve_webhook_config_path(ROOT_DIR),
        logger=SERVER_LOGGER,
    )
    SERVER_LOGGER.info(
        "webhook_dispatch_result",
        extra={
            "request_id": request.request_id or "",
            "user": request.requested_by or "",
            "job_id": job_id,
            "case_name": result.case_name,
            "event": "case.completed",
            "attempted": int(completed_stats.get("attempted", 0)),
            "sent": int(completed_stats.get("sent", 0)),
            "failed": int(completed_stats.get("failed", 0)),
        },
    )

    response_priority = str(payload.get("response_priority", "P4")).upper()
    disposition_should_escalate = (
        disposition_value == "Escalate"
        or (response_priority in {"P1", "P2"} and int(payload.get("incident_count", 0)) > 0)
    )
    if not disposition_should_escalate:
        return
    escalated_payload = dict(payload)
    escalated_payload["schema_version"] = WEBHOOK_SCHEMA_VERSION
    escalated_payload["event_id"] = build_event_id("case.escalated", {
        "case_name": result.case_name,
        "job_id": job_id,
    })
    escalated_stats = dispatch_webhook_event(
        "case.escalated",
        escalated_payload,
        root_dir=ROOT_DIR,
        config_path=resolve_webhook_config_path(ROOT_DIR),
        logger=SERVER_LOGGER,
    )
    SERVER_LOGGER.info(
        "webhook_dispatch_result",
        extra={
            "request_id": request.request_id or "",
            "user": request.requested_by or "",
            "job_id": job_id,
            "case_name": result.case_name,
            "event": "case.escalated",
            "attempted": int(escalated_stats.get("attempted", 0)),
            "sent": int(escalated_stats.get("sent", 0)),
            "failed": int(escalated_stats.get("failed", 0)),
        },
    )


def _webhook_case_summary(result: Any, disposition: Dict[str, Any]) -> str:
    """Build a concise, deterministic operational summary without raw evidence."""
    case_name = str(getattr(result, "case_name", "") or "")
    priority = str(getattr(result, "response_priority", "P4") or "P4")
    incidents = int(getattr(result, "incident_count", 0) or 0)
    findings = int(getattr(result, "finding_count", 0) or 0)
    signals = int(getattr(result, "signal_count", 0) or 0)
    disposition_value = str(disposition.get("disposition") or "No promoted incident")
    confidence = str(disposition.get("confidence") or "unknown")
    try:
        confidence_score = int(disposition.get("confidence_score") or 0)
    except (TypeError, ValueError):
        confidence_score = 0
    reasons = [str(item) for item in (disposition.get("reasons") or []) if str(item)]
    summary = (
        f"Case {case_name} completed with response priority {priority}, "
        f"{signals} signal(s), {findings} finding(s), and {incidents} promoted incident(s). "
        f"Deterministic disposition: {disposition_value} ({confidence}, {confidence_score}% confidence)."
    )
    if reasons:
        summary += " Factors: " + "; ".join(reasons[:5]) + "."
    return summary


def _case_artifact_ref(result: Any) -> str:
    """Return a stable case-relative artifact reference without exposing a local path."""
    return _case_artifact_ref_from_name(getattr(result, "case_name", ""))


def _case_artifact_ref_from_name(case_name: Any) -> str:
    """Return a stable case-relative report reference without exposing a local path."""
    case_name = str(case_name or "").strip()
    if not case_name:
        return ""
    return os.path.join(case_name, "report.html").replace(os.sep, "/")


def _sha256_file(path: str) -> str:
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return ""


def _emit_bundle_webhook(*, case_name: str, client_id: str, output_path: str) -> None:
    """Record a canonical bundle.exported event when a portable ZIP is created."""
    if not os.path.isfile(output_path):
        return
    try:
        file_size = int(os.path.getsize(output_path) or 0)
    except OSError:
        file_size = 0
    # The export bundle filename is intentionally random for download safety,
    # so idempotency must use a stable export-operation ID rather than the
    # temporary filename. Retrying one dispatch keeps the same ID; exporting
    # the same case again is a distinct operation.
    bundle_event_id = build_event_id("bundle.exported", {
        "case_name": case_name,
        "job_id": uuid.uuid4().hex,
    })
    payload: Dict[str, Any] = {
        "schema_version": WEBHOOK_SCHEMA_VERSION,
        "event_id": bundle_event_id,
        "client_id": client_id,
        "case_id": case_name,
        "case_name": case_name,
        "artifact_ref": _case_artifact_ref_from_name(case_name),
        "artifact_name": os.path.basename(output_path),
        "artifact_size": file_size,
        "artifact_bundle_hash": _sha256_file(output_path),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    stats = dispatch_webhook_event(
        "bundle.exported",
        payload,
        root_dir=ROOT_DIR,
        config_path=resolve_webhook_config_path(ROOT_DIR),
        logger=SERVER_LOGGER,
    )
    SERVER_LOGGER.info(
        "webhook_dispatch_result",
        extra={
            "user": "",
            "job_id": payload["event_id"],
            "case_name": case_name,
            "event": "bundle.exported",
            "attempted": int(stats.get("attempted", 0)),
            "sent": int(stats.get("sent", 0)),
            "failed": int(stats.get("failed", 0)),
        },
    )


def _investigate_worker(
    job_id: str,
    request: InvestigationRequest,
    upload_dir: Optional[str] = None,
) -> None:
    """Run the shared investigation service in a background thread."""
    started_at = time.perf_counter()
    SERVER_LOGGER.info(
        "investigation_worker_started",
        extra={
            "request_id": request.request_id or "",
            "user": request.requested_by or "",
            "job_id": job_id,
            "case_name": request.case_name or "",
            "input_mode": request.input_mode,
            "input_source": request.input_source,
        },
    )
    reporter = _JobReporter(job_id)
    try:
        result = run_investigation(request, reporter)
        duration_ms = int((time.perf_counter() - started_at) * 1000)
        update_job(
            job_id,
            status="completed",
            stage="done",
            message="Investigation completed",
            case_name=result.case_name,
            case_path=result.case_path,
            results=result.case_metrics,
        )
        SERVER_LOGGER.info(
            "investigation_worker_completed",
            extra={
                "request_id": request.request_id or "",
                "user": request.requested_by or "",
                "duration_ms": duration_ms,
                "job_id": job_id,
                "case_name": result.case_name,
                "signal_count": int(result.signal_count),
                "finding_count": int(result.finding_count),
                "incident_count": int(result.incident_count),
            },
        )
        incident_ids: List[str] = []
        # Carry forward review state for stable IDs after successful run
        try:
            findings_path = os.path.join(result.case_path, "findings.json")
            if os.path.isfile(findings_path):
                with open(findings_path, "r", encoding="utf-8") as fh:
                    fd = json.load(fh)
                sync_queue_index_from_case_payload(fd)
                fids = [f["id"] for f in fd.get("findings", []) if f.get("id")]
                iids = [i["id"] for i in fd.get("incidents", []) if i.get("id")]
                incident_ids = iids
                carry_forward_reviews(result.case_name, fids, iids)
        except Exception:
            pass  # review carry-forward is best-effort
        try:
            _emit_completion_webhooks(
                job_id=job_id,
                request=request,
                result=result,
                incident_ids=incident_ids,
            )
        except Exception:
            # Webhook dispatch is always best-effort and must never fail the job.
            SERVER_LOGGER.warning(
                "webhook_dispatch_unexpected_error",
                extra={
                    "request_id": request.request_id or "",
                    "user": request.requested_by or "",
                    "job_id": job_id,
                    "case_name": result.case_name,
                },
                exc_info=True,
            )
    except Exception as exc:
        duration_ms = int((time.perf_counter() - started_at) * 1000)
        update_job(
            job_id,
            status="failed",
            message=str(exc),
        )
        SERVER_LOGGER.error(
            "investigation_worker_failed",
            extra={
                "request_id": request.request_id or "",
                "user": request.requested_by or "",
                "duration_ms": duration_ms,
                "job_id": job_id,
                "case_name": request.case_name or "",
                "error": str(exc),
            },
            exc_info=True,
        )
    finally:
        # Clean up uploaded files after investigation
        if upload_dir and os.path.isdir(upload_dir):
            shutil.rmtree(upload_dir, ignore_errors=True)
            clear_upload_path(job_id)


def _run_admitted_investigation(
    job_id: str,
    investigation_request: InvestigationRequest,
    upload_dir: Optional[str],
) -> None:
    try:
        _investigate_worker(job_id, investigation_request, upload_dir)
    finally:
        _JOB_ADMISSION.release()


def _submit_investigation_job(
    job_id: str,
    investigation_request: InvestigationRequest,
    upload_dir: Optional[str],
) -> None:
    """Submit a bounded investigation job or reject once the queue is full."""
    # Test suites historically patch this symbol to capture request context.
    # Preserve that contract without imposing executor internals on those tests.
    if Thread is not _NATIVE_THREAD:
        thread = Thread(
            target=_investigate_worker,
            args=(job_id, investigation_request, upload_dir),
            daemon=True,
        )
        thread.start()
        return

    if not _JOB_ADMISSION.acquire(blocking=False):
        raise HTTPException(429, "Investigation queue is full; retry after active jobs complete")
    try:
        _JOB_EXECUTOR.submit(_run_admitted_investigation, job_id, investigation_request, upload_dir)
    except Exception:
        _JOB_ADMISSION.release()
        raise HTTPException(503, "Investigation queue is unavailable")


# ---------------------------------------------------------------------------
# Input validation helpers
# ---------------------------------------------------------------------------

_SAFE_CASE_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$")
_SAFE_CLIENT_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$")


def _validate_case_name(name: Optional[str]) -> Optional[str]:
    if name is None:
        return None
    name = name.strip()
    if not name:
        return None
    if not _SAFE_CASE_NAME_RE.match(name):
        raise HTTPException(400, "Case name must be 1-128 alphanumeric/dash/dot/underscore characters")
    return name


def _validate_client_id(client_id: Optional[str]) -> str:
    value = str(client_id or "default").strip() or "default"
    if not _SAFE_CLIENT_ID_RE.match(value):
        raise HTTPException(400, "client_id must be 1-64 alphanumeric/dash/underscore characters")
    return value


def _validate_evtx_path(path: str) -> str:
    """Ensure the path exists and is confined to allowed roots."""
    path = os.path.realpath(os.path.abspath(os.path.expanduser(path)))
    if not os.path.exists(path):
        raise HTTPException(400, "Path does not exist")
    # Only allow .evtx files or directories
    if os.path.isfile(path) and not path.lower().endswith(".evtx"):
        raise HTTPException(400, "File must have .evtx extension")
    # A network-bound server must never accept arbitrary host paths. Configure
    # explicit evidence roots before exposing the API beyond localhost.
    if not ALLOWED_PATH_ROOTS and str(SERVER_HOST).strip().lower() not in {"127.0.0.1", "localhost", "::1"}:
        raise HTTPException(403, "Local path investigations require TRIAGE_ALLOWED_PATH_ROOTS when server is network-bound")
    if ALLOWED_PATH_ROOTS:
        allowed = False
        for root in ALLOWED_PATH_ROOTS:
            resolved_root = os.path.realpath(os.path.abspath(os.path.expanduser(root)))
            try:
                if os.path.commonpath((path, resolved_root)) == resolved_root:
                    allowed = True
                    break
            except ValueError:
                # Different Windows drives are never contained within one another.
                continue
        if not allowed:
            raise HTTPException(403, "Path is outside allowed directories")
    return path


def _parse_collection_manifest(
    raw_manifest: Optional[Any], acquisition_method: str,
) -> Optional[Dict[str, Any]]:
    """Normalize a JSON request value into the product manifest contract."""
    if raw_manifest is None or raw_manifest == "":
        return None
    value = raw_manifest
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            raise HTTPException(400, "collection_manifest must be a JSON object")
    if not isinstance(value, dict):
        raise HTTPException(400, "collection_manifest must be a JSON object")
    manifest = dict(value)
    manifest.setdefault("method", acquisition_method)
    try:
        return CollectionManifest(**manifest).to_dict()
    except (TypeError, ValueError) as exc:
        raise HTTPException(400, f"Invalid collection_manifest: {exc}")


def _validate_acquisition_method(value: Optional[str], *, default: str) -> str:
    method = str(value or default).strip() or default
    if method not in ACQUISITION_METHODS:
        raise HTTPException(400, f"Invalid acquisition_method. Must be one of: {', '.join(ACQUISITION_METHODS)}")
    return method


def _validate_ai_endpoint(value: str) -> str:
    """Constrain AI connectors to explicit hosts and loopback-only HTTP."""
    endpoint = str(value or "").strip().rstrip("/")
    try:
        parsed = urlsplit(endpoint)
    except ValueError:
        raise HTTPException(400, "AI endpoint is invalid")
    host = str(parsed.hostname or "").strip().lower().strip("[]")
    if parsed.scheme not in {"http", "https"} or not host:
        raise HTTPException(400, "AI endpoint must be an absolute http or https URL")
    if parsed.username or parsed.password:
        raise HTTPException(400, "AI endpoint must not contain embedded credentials")
    if host not in AI_ALLOWED_HOSTS:
        raise HTTPException(400, "AI endpoint host is not allowed; configure TRIAGE_AI_ALLOWED_HOSTS")
    if parsed.scheme == "http" and host not in {"localhost", "127.0.0.1", "::1"}:
        raise HTTPException(400, "Non-loopback AI endpoints must use https")
    return endpoint


def _product_store() -> ClientStore:
    """Construct against the active API data root (also makes test isolation simple)."""
    return ClientStore(data_dir=DATA_ROOT)


def _require_client_id(client_id: Optional[str]) -> str:
    """Validate and resolve a client profile before accepting evidence."""
    resolved = _validate_client_id(client_id)
    profile = _product_store().get_client(resolved)
    if not profile or not profile.active:
        raise HTTPException(400, "Unknown or inactive client profile")
    return resolved


def _metadata_from_case_artifact(case_path: str, case_name: str) -> Optional[CaseMetadata]:
    artifact = os.path.join(case_path, "case_metadata.json")
    if not os.path.isfile(artifact):
        return None
    try:
        with open(artifact, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        return CaseMetadata(
            case_name=case_name,
            client_id=str(raw.get("client_id") or "default"),
            acquisition_method=str(raw.get("acquisition_method") or "upload"),
            created_at=str(raw.get("created_at") or ""),
            retention_until=str(raw.get("retention_until") or ""),
            collection_manifest=dict(raw.get("collection_manifest") or {}),
        )
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return None


def _get_case_metadata(case_path: str, case_name: str) -> Optional[CaseMetadata]:
    try:
        return _product_store().get_case_metadata(case_name) or _metadata_from_case_artifact(case_path, case_name)
    except (OSError, sqlite3.Error):
        return _metadata_from_case_artifact(case_path, case_name)


def _write_case_metadata_artifact(case_path: str, metadata: CaseMetadata) -> None:
    with open(os.path.join(case_path, "case_metadata.json"), "w", encoding="utf-8") as fh:
        json.dump(metadata.to_dict(), fh, indent=2, sort_keys=True)


_last_queue_sync_at = 0.0


def _dashboard_path() -> str:
    return os.path.join(STATIC_DIR, "dashboard.html")


def _probe_directory_writable(path: str) -> bool:
    try:
        os.makedirs(path, exist_ok=True)
        probe_path = os.path.join(path, f".health-{uuid.uuid4().hex}.tmp")
        with open(probe_path, "w", encoding="utf-8") as fh:
            fh.write("ok")
        os.remove(probe_path)
        return True
    except Exception:
        return False


def _collect_startup_validation() -> Dict[str, Any]:
    errors: List[str] = []
    warnings: List[str] = []

    data_dir_writable = _probe_directory_writable(DATA_ROOT)
    if not data_dir_writable:
        errors.append(f"Data directory is not writable: {DATA_ROOT}")

    cases_dir_writable = _probe_directory_writable(CASES_ROOT)
    if not cases_dir_writable:
        errors.append(f"Cases directory is not writable: {CASES_ROOT}")

    db_paths = _state_db_paths()
    db_writable = {name: _probe_sqlite_writable(path) for name, path in db_paths.items()}
    for db_name, writable in db_writable.items():
        if writable:
            continue
        errors.append(f"Database is not writable/queryable ({db_name}): {db_paths.get(db_name, '')}")

    dashboard_path = _dashboard_path()
    if not os.path.isfile(dashboard_path):
        errors.append(f"Dashboard HTML not found: {dashboard_path}")

    disk_free = _disk_free_bytes(DATA_ROOT)
    if disk_free < 0:
        warnings.append(f"Unable to determine free disk space for path: {DATA_ROOT}")
    elif disk_free < STARTUP_DISK_HARD_MIN_BYTES:
        errors.append(
            f"Free disk below required minimum (100MB): {disk_free} bytes available at {DATA_ROOT}"
        )
    elif disk_free < STARTUP_DISK_WARN_BYTES:
        warnings.append(
            f"Free disk below recommended threshold (1GB): {disk_free} bytes available at {DATA_ROOT}"
        )

    network_bound = str(SERVER_HOST).strip().lower() not in {"127.0.0.1", "localhost", "::1"}
    if network_bound and not BOOTSTRAP_TOKEN:
        try:
            unclaimed = not has_users()
        except Exception:
            unclaimed = False
        if unclaimed:
            warnings.append(
                "Server is network-bound with no admin account; anyone who reaches it first can create one. "
                "Set TRIAGE_BOOTSTRAP_TOKEN or complete bootstrap before exposing the port."
            )

    return {
        "errors": errors,
        "warnings": warnings,
        "data_dir_writable": data_dir_writable,
        "cases_dir_writable": cases_dir_writable,
        "db_writable": db_writable,
        "db_paths": db_paths,
        "dashboard_path": dashboard_path,
        "disk_free_bytes": disk_free,
    }


def _validate_startup_or_raise() -> Dict[str, Any]:
    validation = _collect_startup_validation()
    for warning in validation.get("warnings", []):
        SERVER_LOGGER.warning(
            "startup_validation_warning",
            extra={"warning": warning},
        )
    errors: List[str] = list(validation.get("errors", []))
    if errors:
        for error in errors:
            SERVER_LOGGER.error(
                "startup_validation_error",
                extra={"error": error},
            )
        raise RuntimeError("Startup validation failed: " + "; ".join(errors))
    SERVER_LOGGER.info(
        "startup_validation_passed",
        extra={
            "data_root": DATA_ROOT,
            "cases_root": CASES_ROOT,
            "disk_free_bytes": int(validation.get("disk_free_bytes", -1)),
        },
    )
    return validation


@asynccontextmanager
async def _lifespan(_: FastAPI):
    global _last_queue_sync_at
    _validate_startup_or_raise()
    for interrupted in reconcile_interrupted_jobs():
        _reconcile_interrupted_case_status(interrupted)
    for job in get_jobs_with_uploads():
        upload_path = job.get("upload_path", "")
        if upload_path and os.path.isdir(upload_path):
            shutil.rmtree(upload_path, ignore_errors=True)
        clear_upload_path(job["job_id"])
    cleanup_expired_sessions()
    materialize_queue_index_for_completed_cases(CASES_ROOT)
    try:
        _last_queue_sync_at = os.path.getmtime(CASES_ROOT) if os.path.isdir(CASES_ROOT) else 0.0
    except OSError:
        _last_queue_sync_at = 0.0
    yield


def _reconcile_interrupted_case_status(job: dict) -> None:
    """Update an interrupted case projection without changing completed output."""
    from triage_engine.evidence import atomic_json

    supplied = str(job.get("case_path") or "")
    if not supplied:
        return
    try:
        case_path = resolve_case_path(CASES_ROOT, supplied)
        status_path = os.path.join(case_path, "run_status.json")
        if os.path.islink(status_path) or not os.path.isfile(status_path):
            return
        with open(status_path, encoding="utf-8") as handle:
            status = json.load(handle)
        if not isinstance(status, dict) or not isinstance(status.get("metadata", {}), dict):
            raise ValueError("Invalid interrupted case status")
        if status.get("status") not in {"queued", "running"}:
            return
        now = datetime.now(timezone.utc).isoformat()
        status.update(status="failed", current_stage="interrupted", message=job["message"], updated_at=now, completed_at=now)
        status.setdefault("metadata", {})["recovery"] = job["results"]["recovery"]
        atomic_json(status_path, status)
    except (OSError, ValueError, TypeError, KeyError):
        SERVER_LOGGER.warning("interrupted_case_status_update_failed", extra={"job_id": job.get("job_id", "")})


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Triage Engine",
    version=__version__,
    description="Windows incident investigation platform — REST API and Web Dashboard",
    lifespan=_lifespan,
    openapi_tags=OPENAPI_TAGS,
)

# CORS: localhost-only by default. Tighten or widen via TRIAGE_CORS_ORIGINS.
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["*"],
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=TRUSTED_HOSTS)


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    request.state.request_id = _request_id_from_header(request.headers.get("X-Request-ID", ""))
    started_at = time.perf_counter()
    user = _current_user(request)
    method = request.method.upper()
    path = request.url.path

    if method in STATE_CHANGING_METHODS and path.startswith("/api/") and path not in CSRF_EXEMPT_PATHS:
        session_id = request.cookies.get(SESSION_COOKIE, "")
        if session_id:
            provided = (request.headers.get(CSRF_HEADER, "") or "").strip()
            expected = _csrf_token_for_session(session_id)
            if not provided or not hmac.compare_digest(provided, expected):
                response = JSONResponse(status_code=403, content={"detail": "CSRF token missing or invalid"})
                duration_ms = int((time.perf_counter() - started_at) * 1000)
                _log_access(request, user, response.status_code, duration_ms)
                return _attach_request_id_header(request, response)

    limit = await _rate_limit_result(request, user)
    if limit:
        response = JSONResponse(
            status_code=429,
            content={"detail": limit["detail"]},
            headers={"Retry-After": str(limit["retry_after"])},
        )
        duration_ms = int((time.perf_counter() - started_at) * 1000)
        _log_access(request, user, response.status_code, duration_ms)
        return _attach_request_id_header(request, response)

    try:
        response = await call_next(request)
    except Exception:
        duration_ms = int((time.perf_counter() - started_at) * 1000)
        _log_access(request, user, 500, duration_ms)
        SERVER_LOGGER.error(
            "request_unhandled_exception",
            extra={
                "request_id": _request_id_for_log(request),
                "user": user.get("username", "") if user else "",
                "duration_ms": duration_ms,
                "method": request.method,
                "path": request.url.path,
            },
            exc_info=True,
        )
        raise

    duration_ms = int((time.perf_counter() - started_at) * 1000)
    _log_access(request, user, response.status_code, duration_ms)
    return _attach_request_id_header(request, response)


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    response = JSONResponse(
        status_code=exc.status_code,
        content={"detail": _sanitize_error_message(exc.detail)},
        headers=exc.headers,
    )
    return _attach_request_id_header(request, response)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    SERVER_LOGGER.error(
        "unhandled_server_error",
        extra={
            "request_id": _request_id_for_log(request),
            "method": request.method,
            "path": request.url.path,
            "error": str(exc),
        },
        exc_info=True,
    )
    response = JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "error_code": "internal_error"},
    )
    return _attach_request_id_header(request, response)


def _public_user(user: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not user:
        return None
    return {
        "username": user.get("username", ""),
        "role": user.get("role", ""),
        "expires_at": user.get("expires_at", ""),
    }


def _audit_case_access(user: Dict[str, Any], *, case_name: str, endpoint: str) -> None:
    try:
        record_audit_event(
            actor_username=user.get("username", ""),
            action="access_case_detail",
            target_username=case_name,
            details={"case_name": case_name, "endpoint": endpoint},
        )
    except Exception:
        # Case-read paths should not fail due to best-effort audit write issues.
        return


def _job_case_availability(case_name: str) -> Dict[str, Any]:
    if not case_name:
        return {"case_available": False, "case_missing_reason": "No case linked to this job yet"}
    try:
        case_path = resolve_case_path(CASES_ROOT, case_name)
    except FileNotFoundError:
        return {"case_available": False, "case_missing_reason": "Case artifacts are no longer available"}
    findings_path = os.path.join(case_path, "findings.json")
    report_path = os.path.join(case_path, "report.html")
    if not os.path.isfile(findings_path) and not os.path.isfile(report_path):
        return {"case_available": False, "case_missing_reason": "Case folder exists but artifacts are incomplete"}
    return {"case_available": True, "case_missing_reason": ""}


def _request_is_secure(request: Request) -> bool:
    force_secure = os.environ.get("TRIAGE_SECURE_COOKIES", "").lower() in {"1", "true", "yes"}
    if force_secure:
        return True
    forwarded_proto = (request.headers.get("x-forwarded-proto", "") or "").split(",")[0].strip().lower()
    if forwarded_proto == "https":
        return True
    if str(request.scope.get("scheme", "")).lower() == "https":
        return True
    return request.url.scheme.lower() == "https"


def _set_session_cookie(request: Request, response: Response, session: Dict[str, Any]) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        session["session_id"],
        httponly=True,
        samesite="lax",
        secure=_request_is_secure(request),
        max_age=session_max_age_seconds(),
        path="/",
    )


def _clear_session_cookie(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/")


def _current_user(request: Request) -> Optional[Dict[str, Any]]:
    cached = getattr(request.state, "_current_user_cache", _CURRENT_USER_UNSET)
    if cached is not _CURRENT_USER_UNSET:
        return cached
    session_id = request.cookies.get(SESSION_COOKIE, "")
    if not session_id:
        request.state._current_user_cache = None
        return None
    user = get_session(session_id, client_ip=_client_ip(request))
    request.state._current_user_cache = user
    return user


def _require_user(request: Request, roles: Optional[tuple[str, ...]] = None) -> Dict[str, Any]:
    user = _current_user(request)
    if not user:
        raise HTTPException(401, "Authentication required")
    if roles and user.get("role") not in roles:
        raise HTTPException(403, "You do not have permission to perform this action")
    return user


def _sync_queue_index_if_stale() -> int:
    global _last_queue_sync_at
    try:
        marker = os.path.getmtime(CASES_ROOT) if os.path.isdir(CASES_ROOT) else 0.0
    except OSError:
        marker = 0.0
    if marker <= _last_queue_sync_at:
        return 0
    processed = materialize_queue_index_for_completed_cases(CASES_ROOT)
    _last_queue_sync_at = marker
    return processed


def _state_db_paths() -> Dict[str, str]:
    import triage_engine.auth_store as auth_store_module
    import triage_engine.review_store as review_store_module
    import triage_engine.job_store as job_store_module

    return {
        "auth_db": os.path.abspath(getattr(auth_store_module, "_DB_PATH", os.path.join(DATA_ROOT, "auth.db"))),
        "reviews_db": os.path.abspath(getattr(review_store_module, "_DB_PATH", os.path.join(DATA_ROOT, "reviews.db"))),
        "jobs_db": os.path.abspath(getattr(job_store_module, "_DB_PATH", os.path.join(DATA_ROOT, "jobs.db"))),
        "product_db": os.path.abspath(os.path.join(DATA_ROOT, "product.db")),
    }


def _probe_sqlite_writable(path: str) -> bool:
    directory = os.path.dirname(os.path.abspath(path))
    con: Optional[sqlite3.Connection] = None
    try:
        if directory:
            os.makedirs(directory, exist_ok=True)
        con = sqlite3.connect(path)
        con.execute(
            "CREATE TABLE IF NOT EXISTS __triage_health_probe (id INTEGER PRIMARY KEY, marker TEXT NOT NULL)"
        )
        con.execute("INSERT INTO __triage_health_probe (marker) VALUES (?)", (uuid.uuid4().hex,))
        con.execute("DELETE FROM __triage_health_probe WHERE id = last_insert_rowid()")
        con.commit()
        return True
    except Exception:
        return False
    finally:
        if con is not None:
            try:
                con.close()
            except Exception:
                pass


def _probe_cases_dir_writable() -> bool:
    return _probe_directory_writable(CASES_ROOT)


def _disk_free_bytes(path: str) -> int:
    target = path if os.path.isdir(path) else os.path.dirname(path) or path
    try:
        return int(shutil.disk_usage(target).free)
    except Exception:
        return -1


def _count_case_directories() -> int:
    if not os.path.isdir(CASES_ROOT):
        return 0
    try:
        return sum(1 for entry in os.scandir(CASES_ROOT) if entry.is_dir())
    except Exception:
        return 0


def _count_queue_open_or_in_review() -> int:
    try:
        open_items = get_review_queue(status="Open", limit=100000)
        in_review_items = get_review_queue(status="In Review", limit=100000)
        return len(open_items) + len(in_review_items)
    except Exception:
        return 0


def _safe_download_filename(stem: str, extension: str) -> str:
    sanitized_stem = re.sub(r"[^A-Za-z0-9._-]+", "-", str(stem or "").strip()).strip("-._")
    if not sanitized_stem:
        sanitized_stem = "triage-export"
    sanitized_ext = re.sub(r"[^A-Za-z0-9]+", "", str(extension or "").strip().lower())
    if not sanitized_ext:
        sanitized_ext = "txt"
    return f"{sanitized_stem}.{sanitized_ext}"


def _csv_attachment(rows: List[Dict[str, Any]], *, fieldnames: List[str], filename: str) -> Response:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow({key: row.get(key, "") for key in fieldnames})
    return Response(
        content=buffer.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
@app.get(
    "/",
    response_class=HTMLResponse,
    tags=["Admin"],
    summary="Dashboard UI",
    description="Serve the static dashboard HTML for the web operator console.",
)
async def dashboard():
    """Serve the web dashboard from `static/dashboard.html`."""
    html_path = _dashboard_path()
    if not os.path.isfile(html_path):
        raise HTTPException(500, "Dashboard HTML not found — expected at static/dashboard.html")
    with open(html_path, "r", encoding="utf-8") as fh:
        return HTMLResponse(fh.read())


@app.get("/assets/{asset_name}", include_in_schema=False)
async def dashboard_asset(asset_name: str):
    """Serve only the shipped workspace assets; never expose the static directory."""
    asset_types = {
        "dashboard.css": "text/css",
        "workspace.css": "text/css",
        "dashboard.js": "text/javascript",
        "workspace.js": "text/javascript",
        "forensics.js": "text/javascript",
    }
    media_type = asset_types.get(asset_name)
    if media_type is None:
        raise HTTPException(404, "Asset not found")
    path = os.path.join(STATIC_DIR, asset_name)
    if not os.path.isfile(path):
        raise HTTPException(404, "Asset not found")
    return FileResponse(path, media_type=media_type, headers={"Cache-Control": "no-cache"})


# ---------------------------------------------------------------------------
# API: Health
# ---------------------------------------------------------------------------
@app.get(
    "/api/health",
    tags=["Admin"],
    summary="Health Check",
    description="Return server health and writable-state probes for data stores and case output path.",
    responses={
        200: {
            "description": "Current service health snapshot.",
            "content": {
                "application/json": {
                    "example": {
                        "status": "ok",
                        "version": "0.1.0",
                        "engine": "triage-engine",
                        "runtime": {"mode": "local", "label": "Local Python"},
                        "db_writable": {"all": True, "by_db": {"auth_db": True, "reviews_db": True, "jobs_db": True}},
                        "cases_dir_writable": True,
                        "disk_free_bytes": 1234567890,
                    }
                }
            },
        }
    },
)
async def health():
    """Return health indicators for readiness/liveness style checks."""
    db_paths = _state_db_paths()
    per_db_writable = {name: _probe_sqlite_writable(path) for name, path in db_paths.items()}
    return {
        "status": "ok",
        "version": __version__,
        "engine": "triage-engine",
        "runtime": {"mode": RUNTIME_MODE, "label": RUNTIME_LABEL},
        "db_writable": {
            "all": all(per_db_writable.values()),
            "by_db": per_db_writable,
        },
        "cases_dir_writable": _probe_cases_dir_writable(),
        "disk_free_bytes": _disk_free_bytes(CASES_ROOT),
    }


@app.get(
    "/api/metrics",
    tags=["Admin"],
    summary="Operational Metrics",
    description="Return an admin-only operational metrics snapshot for jobs, queue depth, and database sizes.",
    response_model=Dict[str, Any],
    responses={
        200: {
            "description": "Current operational metrics snapshot.",
            "content": {
                "application/json": {
                    "example": {
                        "uptime_seconds": 4213,
                        "total_jobs": 182,
                        "active_jobs": 1,
                        "completed_jobs": 177,
                        "failed_jobs": 4,
                        "total_cases": 75,
                        "total_users": 3,
                        "active_sessions": 2,
                        "queue_size": 11,
                        "db_sizes": {"auth_db": 65536, "reviews_db": 212992, "jobs_db": 98304},
                    }
                }
            },
        }
    },
)
async def metrics(request: Request):
    """Operational metrics snapshot (admin only)."""
    _require_user(request, ("admin",))
    _sync_queue_index_if_stale()

    jobs = db_list_jobs(limit=1_000_000)
    total_jobs = len(jobs)
    active_jobs = sum(1 for job in jobs if str(job.get("status", "")).lower() in {"queued", "running"})
    completed_jobs = sum(1 for job in jobs if str(job.get("status", "")).lower() == "completed")
    failed_jobs = sum(1 for job in jobs if str(job.get("status", "")).lower() == "failed")

    db_sizes: Dict[str, int] = {}
    for name, path in _state_db_paths().items():
        try:
            db_sizes[name] = int(os.path.getsize(path)) if os.path.isfile(path) else 0
        except OSError:
            db_sizes[name] = 0

    return {
        "uptime_seconds": int(max(0, time.monotonic() - _SERVER_STARTED_AT)),
        "total_jobs": total_jobs,
        "active_jobs": active_jobs,
        "completed_jobs": completed_jobs,
        "failed_jobs": failed_jobs,
        "total_cases": _count_case_directories(),
        "total_users": len(list_users()),
        "active_sessions": len(list_active_sessions()),
        "queue_size": _count_queue_open_or_in_review(),
        "db_sizes": db_sizes,
    }


class BootstrapRequest(BaseModel):
    username: str
    password: str
    bootstrap_token: Optional[str] = None


class LoginRequest(BaseModel):
    username: str
    password: str


class UserCreateRequest(BaseModel):
    username: str
    password: str
    role: str = "analyst"


class UserUpdateRequest(BaseModel):
    password: Optional[str] = None
    role: Optional[str] = None
    active: Optional[bool] = None


class PreferencesPatchRequest(BaseModel):
    preferences: Dict[str, Any]


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class LiveInvestigateRequest(BaseModel):
    case_name: Optional[str] = None
    enable_sigma: bool = False
    since_minutes: int = 30
    channels: List[str] = []
    client_id: str = "default"
    acquisition_method: str = "local_live"
    collection_manifest: Optional[Dict[str, Any]] = None


class ClientCreateRequest(BaseModel):
    client_id: str
    display_name: str
    report_name: str = ""
    contact: str = ""
    logo: str = ""
    accent_color: str = "#2563eb"
    retention_days: int = Field(90, ge=1, le=3650)
    active: bool = True


class ClientPatchRequest(BaseModel):
    display_name: Optional[str] = None
    report_name: Optional[str] = None
    contact: Optional[str] = None
    logo: Optional[str] = None
    accent_color: Optional[str] = None
    retention_days: Optional[int] = Field(None, ge=1, le=3650)
    active: Optional[bool] = None


class ClientUpdateRequest(ClientPatchRequest):
    client_id: str


class ClientResponse(BaseModel):
    client_id: str
    display_name: str
    report_name: str = ""
    contact: str = ""
    logo: str = ""
    accent_color: str = "#2563eb"
    retention_days: int = 90
    active: bool = True
    created_at: str
    updated_at: str


class CaseMetadataPatchRequest(BaseModel):
    client_id: Optional[str] = None
    acquisition_method: Optional[str] = None
    collection_manifest: Optional[Dict[str, Any]] = None
    retention_until: Optional[str] = None


class CaseMetadataResponse(BaseModel):
    case_name: str
    client_id: str
    acquisition_method: str
    created_at: str
    retention_until: str = ""
    collection_manifest: Dict[str, Any] = Field(default_factory=dict)
    schema_version: str = "1.0"


class PurgeCaseResponse(BaseModel):
    purged: str


class AISummaryRequest(BaseModel):
    endpoint: str
    model: str = "gpt-4o-mini"
    api_key: str = ""
    consent: bool = False


class JevReviewRequest(BaseModel):
    consent: bool = False


class JobDeleteRequest(BaseModel):
    job_ids: List[str]


class ApiErrorResponse(BaseModel):
    detail: str
    error_code: Optional[str] = None


class HealthDbWritableResponse(BaseModel):
    all: bool
    by_db: Dict[str, bool]


class HealthResponse(BaseModel):
    status: str
    version: str
    engine: str
    db_writable: HealthDbWritableResponse
    cases_dir_writable: bool
    disk_free_bytes: int


class MetricsResponse(BaseModel):
    uptime_seconds: int
    total_jobs: int
    active_jobs: int
    completed_jobs: int
    failed_jobs: int
    total_cases: int
    total_users: int
    active_sessions: int
    queue_size: int
    db_sizes: Dict[str, int]


class PublicUserResponse(BaseModel):
    username: str
    role: str
    expires_at: str


class AuthMeResponse(BaseModel):
    authenticated: bool
    bootstrap_required: bool
    bootstrap_token_required: bool = False
    user: Optional[PublicUserResponse]
    roles: List[str]
    csrf_token: str


class AuthBootstrapResponse(BaseModel):
    bootstrap_required: bool
    user: PublicUserResponse
    csrf_token: str


class AuthLoginResponse(BaseModel):
    user: PublicUserResponse
    csrf_token: str


class AuthSessionResponse(BaseModel):
    session_id: str
    username: str
    role: str
    created_at: str
    last_active_at: str
    ip: str
    expires_at: str
    is_current: bool


class AuthSessionsResponse(BaseModel):
    sessions: List[AuthSessionResponse]


class UserRecordResponse(BaseModel):
    username: str
    role: str
    active: bool
    created_at: str
    updated_at: str
    last_login_at: str


class AuthUsersResponse(BaseModel):
    users: List[UserRecordResponse]


class AuthUserMutationResponse(BaseModel):
    updated_by: Optional[str] = None
    created_by: Optional[str] = None
    revoked_sessions: Optional[int] = None
    user: UserRecordResponse


class AuthLogoutResponse(BaseModel):
    logged_out: bool


class AuthRevokeSessionResponse(BaseModel):
    revoked: bool
    session_id: str


class AuthAuditEventsResponse(BaseModel):
    events: List[Dict[str, Any]]


class UserPreferencesResponse(BaseModel):
    username: str
    preferences: Dict[str, Any]
    updated_at: str


class AuthChangePasswordResponse(BaseModel):
    changed: bool
    revoked_sessions: int
    user: PublicUserResponse
    csrf_token: str


class BackupFileResponse(BaseModel):
    name: str
    size_bytes: int
    sha256: str


class BackupCreateResponse(BaseModel):
    backup_id: str
    created_at: str
    data_dir: str
    backup_path: str
    total_bytes: int
    files: List[BackupFileResponse]


class BackupListItemResponse(BaseModel):
    backup_id: str
    created_at: str
    backup_path: str
    total_bytes: int
    file_count: int


class BackupListResponse(BaseModel):
    backups: List[BackupListItemResponse]


class CaseListItemResponse(BaseModel):
    name: str
    status: str = "unknown"
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    stage: Optional[str] = None
    message: Optional[str] = None
    signal_count: int = 0
    finding_count: int = 0
    incident_count: int = 0
    response_priority: Optional[str] = None
    client_id: str = "default"
    acquisition_method: str = ""
    retention_until: str = ""
    disposition: Optional[Dict[str, Any]] = None
    scope: Optional[Dict[str, Any]] = None
    has_report: bool = False
    has_findings: bool = False


class CaseTextResponse(BaseModel):
    summary: Optional[str] = None
    brief: Optional[str] = None


class DeleteCaseResponse(BaseModel):
    deleted: str


class InvestigationQueuedResponse(BaseModel):
    job_id: str
    case_name: str
    status: str


class LiveInvestigationQueuedResponse(InvestigationQueuedResponse):
    input_mode: str
    channels: List[str]
    since_minutes: int


class JobResponse(BaseModel):
    job_id: str
    case_name: str
    case_path: str = ""
    status: str
    stage: str
    message: str = ""
    error: str = ""
    results: Dict[str, Any] = Field(default_factory=dict)
    created_at: str
    updated_at: str
    upload_path: str = ""
    case_available: Optional[bool] = None
    case_missing_reason: Optional[str] = None


class JobsDeleteResponse(BaseModel):
    deleted: List[str]
    skipped: List[Dict[str, str]]


class ReviewRecordResponse(BaseModel):
    case_name: str
    finding_id: Optional[str] = None
    incident_id: Optional[str] = None
    status: str
    disposition: str = ""
    owner: str = ""
    priority: str = ""
    recommended_tuning_action: str = ""
    notes: List[Dict[str, Any]] = Field(default_factory=list)
    history: List[Dict[str, Any]] = Field(default_factory=list)


class ReviewHistoryResponse(BaseModel):
    history: List[Dict[str, Any]]


class ReviewEnumsResponse(BaseModel):
    statuses: List[str]
    dispositions: List[str]


class ReviewNoteResponse(BaseModel):
    id: int
    case_name: str
    item_type: str
    item_id: str
    author: str
    content: str
    created_at: str


class ReviewQueueItemResponse(BaseModel):
    case_name: str
    item_type: str
    item_id: str
    item_title: str
    response_priority: str
    last_seen_at: str
    status: str
    disposition: str
    owner: str
    priority: str
    updated_at: str


class ReviewHistoryItemResponse(BaseModel):
    id: int
    case_name: str
    item_type: str
    item_id: str
    field: str
    old_value: str
    new_value: str
    changed_by: str
    changed_at: str


class CarryForwardResponse(BaseModel):
    case_name: str
    findings_carried: int
    findings_created: int
    incidents_carried: int
    incidents_created: int


class LiveChannelHealthResponse(BaseModel):
    channel: str
    readable: bool
    status: str
    message: str


class LiveHealthResponse(BaseModel):
    os_name: str
    is_windows: bool
    pywin32_available: bool
    is_elevated: bool
    readiness: str
    recommended_channels: List[str]
    readable_channel_count: int
    channels: List[LiveChannelHealthResponse]
    guidance: List[str]


class LiveElevationResponse(BaseModel):
    """Result of requesting a separate elevated localhost server session."""

    elevation_requested: bool
    already_elevated: bool = False
    redirect_url: str = ""
    message: str


class QuickCheckSessionResponse(BaseModel):
    token: str
    expires_in_seconds: int


class QuickCheckCaseResponse(BaseModel):
    case_name: str
    triage_disposition: Dict[str, Any] = Field(default_factory=dict)


_COMMON_PASSWORDS_TOP_100 = {
    "123456",
    "123456789",
    "12345",
    "qwerty",
    "password",
    "12345678",
    "111111",
    "123123",
    "1234567890",
    "1234567",
    "qwerty123",
    "000000",
    "1q2w3e",
    "aa12345678",
    "abc123",
    "password1",
    "1234",
    "qwertyuiop",
    "123321",
    "password123",
    "1q2w3e4r5t",
    "iloveyou",
    "654321",
    "666666",
    "987654321",
    "123",
    "123456a",
    "qwe123",
    "1q2w3e4r",
    "7777777",
    "1qaz2wsx",
    "zxcvbnm",
    "121212",
    "asdasd",
    "a123456",
    "555555",
    "dragon",
    "112233",
    "123qwe",
    "159753",
    "147258369",
    "asdfghjkl",
    "password!",
    "qazwsx",
    "qwerty1",
    "123654",
    "qwertyui",
    "qwer1234",
    "superman",
    "hello123",
    "football",
    "monkey",
    "letmein",
    "sunshine",
    "master",
    "welcome",
    "welcome123",
    "shadow",
    "ashley",
    "michael",
    "baseball",
    "jesus",
    "ninja",
    "mustang",
    "password12",
    "passw0rd",
    "p@ssw0rd",
    "passw0rd123",
    "password1!",
    "admin123",
    "admin1234",
    "admin123!",
    "administrator",
    "root123",
    "root1234",
    "trustno1",
    "freedom",
    "whatever",
    "q1w2e3r4",
    "q1w2e3r4t5",
    "zaq12wsx",
    "zaq1zaq1",
    "qwerty!@#",
    "qweasdzxc",
    "batman",
    "starwars",
    "charlie",
    "donald",
    "hottie",
    "loveme",
    "killer",
    "cookie",
    "nicole",
    "jordan",
    "princess",
    "hunter",
    "ginger",
    "snoopy",
    "maggie",
    "bailey",
    "michelle",
    "pepper",
    "jessica",
    "thomas",
    "joshua",
    "cheese",
    "internet",
}


def _validate_username(username: str) -> str:
    username = username.strip()
    if not re.fullmatch(r"[A-Za-z0-9._-]{3,64}", username):
        raise HTTPException(400, "Username must be 3-64 characters using letters, numbers, dot, dash, or underscore")
    return username


def _validate_password(password: str, *, username: str = "") -> str:
    candidate = str(password or "")
    if len(candidate) < 10:
        raise HTTPException(400, "Password must be at least 10 characters long")
    if not re.search(r"[A-Z]", candidate):
        raise HTTPException(400, "Password must include at least one uppercase letter")
    if not re.search(r"[a-z]", candidate):
        raise HTTPException(400, "Password must include at least one lowercase letter")
    if not re.search(r"\d", candidate):
        raise HTTPException(400, "Password must include at least one digit")
    if not re.search(r"[^A-Za-z0-9]", candidate):
        raise HTTPException(400, "Password must include at least one special character")

    normalized_username = str(username or "").strip().lower()
    lowered = candidate.lower()
    if normalized_username and normalized_username in lowered:
        raise HTTPException(400, "Password cannot contain the username")
    if lowered in _COMMON_PASSWORDS_TOP_100:
        raise HTTPException(400, "Password is too common. Choose a more unique password")
    return candidate


def _validate_live_channels(channels: List[str]) -> List[str]:
    cleaned: List[str] = []
    for raw in channels or []:
        channel = str(raw or "").strip()
        if not channel:
            continue
        if len(channel) > 160 or not re.fullmatch(r"[A-Za-z0-9 ._/\-]+", channel):
            raise HTTPException(400, f"Invalid live channel name: {channel}")
        cleaned.append(channel)
    if not cleaned:
        cleaned = ["Security", "System", "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-Sysmon/Operational"]
    return cleaned


def _is_windows_admin() -> bool:
    if os.name != "nt":
        return False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _find_available_loopback_port() -> int:
    """Reserve no state: return a currently available loopback TCP port.

    The elevation flow uses another localhost server rather than changing the
    token of the running process. The OS owns the final bind decision, so the
    caller must still handle a rare launch race gracefully.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _powershell_quote(value: str) -> str:
    """Quote a value for a PowerShell single-quoted literal."""
    return "'" + str(value).replace("'", "''") + "'"


def _launch_elevated_local_server(port: int) -> str:
    """Request UAC and launch a second, elevated localhost server instance.

    This intentionally does not stop or modify the original standard-user
    process. If UAC is declined, no investigation begins and upload analysis
    remains available in the existing session.
    """
    if os.name != "nt":
        raise RuntimeError("Elevation is only available on Windows")
    if not 1 <= int(port) <= 65535:
        raise ValueError("Invalid local elevation port")

    executable = os.path.abspath(sys.executable)
    arguments: List[str] = []
    if not getattr(sys, "frozen", False):
        arguments.append(os.path.abspath(__file__))

    ps_arguments = "@(" + ", ".join(_powershell_quote(arg) for arg in arguments) + ")"
    working_directory = ROOT_DIR
    script = (
        "$ErrorActionPreference = 'Stop'; "
        "$env:TRIAGE_HOST = '127.0.0.1'; "
        f"$env:TRIAGE_PORT = '{int(port)}'; "
        f"Start-Process -FilePath {_powershell_quote(executable)} "
        f"-ArgumentList {ps_arguments} -WorkingDirectory {_powershell_quote(working_directory)} -Verb RunAs"
    )
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    subprocess.Popen(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
        cwd=working_directory,
        close_fds=False,
        creationflags=creationflags,
    )
    return f"http://127.0.0.1:{int(port)}"


def _is_loopback_client(request: Request) -> bool:
    client = request.client
    if client is None:
        return False
    return str(client.host or "").strip().lower() in {"127.0.0.1", "::1", "localhost"}


def _is_local_dashboard_request(request: Request) -> bool:
    """Reject DNS-rebinding and cross-origin Quick Check requests."""
    if not _is_loopback_client(request):
        return False
    local_hosts = {"127.0.0.1", "::1", "localhost"}
    if str(request.url.hostname or "").strip().lower() not in local_hosts:
        return False
    origin = str(request.headers.get("Origin", "") or "").strip()
    if not origin:
        return True
    try:
        parsed = urlsplit(origin)
    except ValueError:
        return False
    return (
        parsed.scheme in {"http", "https"}
        and str(parsed.hostname or "").strip().lower() in local_hosts
    )


def _issue_quick_check_token(request: Request) -> str:
    if not _is_local_dashboard_request(request):
        raise HTTPException(403, "Quick Check is available only from the local dashboard")
    now = time.monotonic()
    token = secrets.token_urlsafe(32)
    with _QUICK_CHECK_LOCK:
        expired = [value for value, expiry in _QUICK_CHECK_SESSIONS.items() if expiry <= now]
        for value in expired:
            _QUICK_CHECK_SESSIONS.pop(value, None)
        _QUICK_CHECK_SESSIONS[token] = now + QUICK_CHECK_SESSION_TTL_SECONDS
    return token


def _require_quick_check_token(request: Request) -> str:
    if not _is_local_dashboard_request(request):
        raise HTTPException(403, "Quick Check is available only from the local dashboard")
    candidate = (request.headers.get(QUICK_CHECK_HEADER, "") or "").strip()
    if not candidate:
        raise HTTPException(403, "Quick Check token is required")
    now = time.monotonic()
    with _QUICK_CHECK_LOCK:
        expiry = _QUICK_CHECK_SESSIONS.get(candidate, 0.0)
        if expiry <= now:
            _QUICK_CHECK_SESSIONS.pop(candidate, None)
            raise HTTPException(403, "Quick Check token is invalid or expired")
    return candidate


def _quick_check_job_for_token(job_id: str, token: str) -> Dict[str, str]:
    with _QUICK_CHECK_LOCK:
        record = dict(_QUICK_CHECK_JOBS.get(job_id, {}))
    if not record or not hmac.compare_digest(record.get("token", ""), token):
        raise HTTPException(404, "Quick Check job not found")
    return record


def _queue_quick_check_live(request: Request, token: str) -> Dict[str, Any]:
    """Queue only the fixed, low-risk guided live collection profile."""
    if os.name != "nt":
        raise HTTPException(400, "Live checks are only supported when Triage Engine runs on Windows")
    channels = [
        "Security",
        "System",
        "Microsoft-Windows-PowerShell/Operational",
        "Microsoft-Windows-Sysmon/Operational",
    ]
    job_id = uuid.uuid4().hex[:12]
    from triage_engine.case_utils import auto_case_name as _auto_name

    resolved_name = _auto_name(None, True, ",".join(channels))
    investigation_request = InvestigationRequest(
        input_source=f"live:{','.join(channels)}",
        input_mode="live",
        case_name=resolved_name,
        cases_dir=CASES_ROOT,
        enable_sigma=True,
        channels=channels,
        since_minutes=30,
        request_id=_request_id_for_log(request),
        requested_by="quick-check",
        client_id="default",
        acquisition_method="local_live",
        collection_manifest={"method": "local_live", "profile": "quick_check", "channels": channels, "since_minutes": 30},
    )
    create_job(job_id, case_name=resolved_name)
    with _QUICK_CHECK_LOCK:
        _QUICK_CHECK_JOBS[job_id] = {"token": token, "case_name": resolved_name}
    try:
        _submit_investigation_job(job_id, investigation_request, None)
    except HTTPException:
        with _QUICK_CHECK_LOCK:
            _QUICK_CHECK_JOBS.pop(job_id, None)
        delete_job(job_id)
        raise
    record_audit_event(
        actor_username="quick-check",
        action="start_quick_check_live",
        target_username=resolved_name,
        details={"job_id": job_id, "profile": "quick_check"},
    )
    return {"job_id": job_id, "case_name": resolved_name, "status": "queued", "input_mode": "live", "channels": channels, "since_minutes": 30}


def _probe_live_channel(channel: str) -> Dict[str, Any]:
    result = {
        "channel": channel,
        "readable": False,
        "status": "unknown",
        "message": "",
    }
    if os.name != "nt":
        result.update(status="unsupported", message="Live channel probing is only supported on Windows")
        return result

    try:
        import win32evtlog  # type: ignore
    except ImportError:
        result.update(status="pywin32_missing", message="pywin32 is not installed for this server runtime")
        return result

    query = "*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]"
    flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection
    handle = None
    try:
        handle = win32evtlog.EvtQuery(channel, flags, query, None)
        result.update(readable=True, status="ready", message="Channel query succeeded")
        return result
    except Exception as exc:
        message = str(exc or "").strip() or exc.__class__.__name__
        status = classify_live_channel_error(exc)
        result.update(status=status, message=message)
        return result
    finally:
        if handle is not None:
            try:
                win32evtlog.EvtClose(handle)
            except Exception:
                pass


def _collect_live_health(channels: Optional[List[str]] = None) -> Dict[str, Any]:
    recommended_channels = _validate_live_channels(channels or [])
    is_windows = os.name == "nt"
    is_elevated = _is_windows_admin()
    try:
        import win32evtlog  # type: ignore  # noqa: F401

        pywin32_available = True
    except ImportError:
        pywin32_available = False

    channel_results = [_probe_live_channel(channel) for channel in recommended_channels]
    readable_count = sum(1 for item in channel_results if item["readable"])
    unreadable = [item for item in channel_results if not item["readable"]]
    readiness = "unsupported"
    if is_windows and pywin32_available:
        readiness = "ready" if is_elevated and not unreadable else "degraded"

    guidance: List[str] = []
    if not is_windows:
        guidance.append("Live investigations require the server to run on Windows.")
    elif not pywin32_available:
        guidance.append("Install pywin32 for this Python environment to enable live Windows event collection.")
    else:
        if not is_elevated:
            guidance.append("Restart the server from an Administrator PowerShell for full Security and Sysmon coverage.")
        denied = [item["channel"] for item in channel_results if item["status"] == "access_denied"]
        if denied:
            guidance.append(f"Current server privileges cannot read: {', '.join(denied)}.")
        missing = [item["channel"] for item in channel_results if item["status"] == "not_found"]
        if missing:
            guidance.append(f"Some channels are not present on this machine: {', '.join(missing)}.")
        if is_elevated and not unreadable:
            guidance.append("Server is ready for the recommended live forensic channel set.")

    return {
        "os_name": os.name,
        "is_windows": is_windows,
        "pywin32_available": pywin32_available,
        "is_elevated": is_elevated,
        "readiness": readiness,
        "recommended_channels": recommended_channels,
        "readable_channel_count": readable_count,
        "channels": channel_results,
        "guidance": guidance,
    }


# ---------------------------------------------------------------------------
# API: Auth
# ---------------------------------------------------------------------------
@app.get(
    "/api/auth/me",
    tags=["Auth"],
    summary="Get Auth Session State",
    description="Return current authentication status, bootstrap requirement, role options, and CSRF token.",
    response_model=AuthMeResponse,
    responses={
        200: {
            "description": "Authentication/session state for the current request.",
            "content": {
                "application/json": {
                    "example": {
                        "authenticated": True,
                        "bootstrap_required": False,
                        "user": {"username": "admin", "role": "admin", "expires_at": "2026-03-16T23:59:59+00:00"},
                        "roles": ["admin", "analyst", "viewer"],
                        "csrf_token": "9a4b3d...",
                    }
                }
            },
        }
    },
)
async def auth_me(request: Request):
    """Return session/bootstrap state for dashboard and API clients."""
    user = _current_user(request)
    csrf_token = _csrf_token_for_session(user.get("session_id", "")) if user else ""
    bootstrap_required = not has_users()
    return {
        "authenticated": bool(user),
        "bootstrap_required": bootstrap_required,
        "bootstrap_token_required": bool(bootstrap_required and BOOTSTRAP_TOKEN),
        "user": _public_user(user),
        "roles": list(VALID_ROLES),
        "csrf_token": csrf_token,
    }


@app.post(
    "/api/auth/bootstrap",
    tags=["Auth"],
    summary="Bootstrap Admin User",
    description="Create the initial admin user when no users exist and establish an authenticated session.",
    response_model=AuthBootstrapResponse,
    responses={
        200: {
            "description": "Bootstrap completed and admin session issued.",
            "content": {
                "application/json": {
                    "example": {
                        "bootstrap_required": False,
                        "user": {"username": "admin", "role": "admin", "expires_at": "2026-03-16T23:59:59+00:00"},
                        "csrf_token": "9a4b3d...",
                    }
                }
            },
        },
        409: {"model": ApiErrorResponse, "description": "Bootstrap already completed."},
    },
)
async def auth_bootstrap(body: BootstrapRequest, request: Request, response: Response):
    """Create the first admin account when no users exist yet."""
    if has_users():
        raise HTTPException(409, "Bootstrap is already complete")
    if BOOTSTRAP_TOKEN and not hmac.compare_digest(
        (body.bootstrap_token or "").strip().encode("utf-8"), BOOTSTRAP_TOKEN.encode("utf-8")
    ):
        raise HTTPException(403, "A valid bootstrap token is required to create the first admin")
    username = _validate_username(body.username)
    password = _validate_password(body.password, username=username)
    try:
        user = bootstrap_admin(username, password)
    except ValueError:
        # Another request may have completed bootstrap after the optimistic
        # pre-check above.  Keep that race a normal conflict, never a 500.
        raise HTTPException(409, "Bootstrap is already complete")
    record_audit_event(
        actor_username=username,
        action="bootstrap_admin",
        target_username=username,
        details={"role": "admin"},
    )
    session = create_session(user, client_ip=_client_ip(request))
    _set_session_cookie(request, response, session)
    return {
        "bootstrap_required": False,
        "user": _public_user(session),
        "csrf_token": _csrf_token_for_session(session.get("session_id", "")),
    }


@app.post(
    "/api/auth/login",
    tags=["Auth"],
    summary="Login",
    description="Authenticate with username/password and create a session cookie with CSRF token.",
    response_model=AuthLoginResponse,
    responses={
        200: {
            "description": "Authenticated session details.",
            "content": {
                "application/json": {
                    "example": {
                        "user": {"username": "analyst-1", "role": "analyst", "expires_at": "2026-03-16T23:59:59+00:00"},
                        "csrf_token": "9a4b3d...",
                    }
                }
            },
        },
        401: {"model": ApiErrorResponse, "description": "Invalid credentials."},
    },
)
async def auth_login(body: LoginRequest, request: Request, response: Response):
    """Authenticate a user and issue a new session cookie."""
    username = _validate_username(body.username)
    user = authenticate_user(username, body.password)
    if not user:
        raise HTTPException(401, "Invalid username or password")
    record_audit_event(
        actor_username=username,
        action="login",
        target_username=username,
        details={"role": user["role"]},
    )
    session = create_session(user, client_ip=_client_ip(request))
    _set_session_cookie(request, response, session)
    return {
        "user": _public_user(session),
        "csrf_token": _csrf_token_for_session(session.get("session_id", "")),
    }


@app.post(
    "/api/auth/logout",
    tags=["Auth"],
    summary="Logout",
    description="Delete current session and clear authentication cookie.",
    response_model=AuthLogoutResponse,
)
async def auth_logout(request: Request, response: Response):
    """Terminate the current session and clear session cookies."""
    session_id = request.cookies.get(SESSION_COOKIE, "")
    user = _current_user(request)
    if session_id:
        delete_session(session_id)
    if user:
        record_audit_event(
            actor_username=user["username"],
            action="logout",
            target_username=user["username"],
            details={"role": user["role"]},
        )
    _clear_session_cookie(response)
    return {"logged_out": True}


@app.get(
    "/api/auth/users",
    tags=["Auth"],
    summary="List Users",
    description="List users in the auth store (admin only).",
    response_model=AuthUsersResponse,
)
async def auth_list_users(request: Request):
    """List registered users with role and activity metadata."""
    _require_user(request, ("admin",))
    return {"users": list_users()}


@app.post(
    "/api/auth/users",
    tags=["Auth"],
    summary="Create User",
    description="Create a new platform user with a role and password (admin only).",
    response_model=AuthUserMutationResponse,
    responses={
        400: {"model": ApiErrorResponse, "description": "Validation failure."},
        409: {"model": ApiErrorResponse, "description": "Username conflict."},
    },
)
async def auth_create_user(request: Request, body: UserCreateRequest):
    """Create a new user account as an admin operation."""
    actor = _require_user(request, ("admin",))
    username = _validate_username(body.username)
    password = _validate_password(body.password, username=username)
    if body.role not in VALID_ROLES:
        raise HTTPException(400, f"Invalid role. Must be one of: {', '.join(VALID_ROLES)}")
    try:
        user = create_user(username, password, role=body.role)
    except IntegrityError:
        raise HTTPException(409, "A user with that username already exists")
    record_audit_event(
        actor_username=actor["username"],
        action="create_user",
        target_username=username,
        details={"role": body.role},
    )
    return {
        "created_by": actor["username"],
        "user": {
            "username": user["username"],
            "role": user["role"],
            "active": user["active"],
            "created_at": user["created_at"],
            "updated_at": user["updated_at"],
            "last_login_at": user["last_login_at"],
        },
    }


@app.patch(
    "/api/auth/users/{username}",
    tags=["Auth"],
    summary="Update User",
    description="Update user role/active state/password and revoke affected sessions when needed.",
    response_model=AuthUserMutationResponse,
    responses={404: {"model": ApiErrorResponse, "description": "User not found."}},
)
async def auth_update_user(request: Request, username: str, body: UserUpdateRequest):
    """Update user role, activation state, or password as an admin."""
    actor = _require_user(request, ("admin",))
    username = _validate_username(username)
    if body.password is None and body.role is None and body.active is None:
        raise HTTPException(400, "No user changes were provided")
    if body.password is not None:
        _validate_password(body.password, username=username)
    if body.role is not None and body.role not in VALID_ROLES:
        raise HTTPException(400, f"Invalid role. Must be one of: {', '.join(VALID_ROLES)}")
    if actor["username"] == username:
        if body.active is False:
            raise HTTPException(400, "You cannot deactivate your own active session")
        if body.role is not None and body.role != actor["role"]:
            raise HTTPException(400, "You cannot change your own role from this session")
    try:
        user = update_user(username, password=body.password, role=body.role, active=body.active)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    if not user:
        raise HTTPException(404, f"User not found: {username}")
    should_revoke = body.password is not None or body.role is not None or body.active is False
    revoked = delete_sessions_for_user(username) if should_revoke else 0
    changed_fields: Dict[str, Any] = {}
    if body.role is not None:
        changed_fields["role"] = body.role
    if body.active is not None:
        changed_fields["active"] = body.active
    if body.password is not None:
        changed_fields["password_reset"] = True
    changed_fields["revoked_sessions"] = revoked
    record_audit_event(
        actor_username=actor["username"],
        action="update_user",
        target_username=username,
        details=changed_fields,
    )
    return {
        "updated_by": actor["username"],
        "revoked_sessions": revoked,
        "user": {
            "username": user["username"],
            "role": user["role"],
            "active": user["active"],
            "created_at": user["created_at"],
            "updated_at": user["updated_at"],
            "last_login_at": user["last_login_at"],
        },
    }


@app.get(
    "/api/auth/sessions",
    tags=["Auth"],
    summary="List Active Sessions",
    description="List active sessions and indicate which session is current (admin only).",
    response_model=AuthSessionsResponse,
)
async def auth_sessions(request: Request):
    """Return active sessions and mark the current requester session."""
    _require_user(request, ("admin",))
    current_session_id = request.cookies.get(SESSION_COOKIE, "")
    sessions = []
    for session in list_active_sessions():
        sessions.append(
            {
                "session_id": session.get("session_id", ""),
                "username": session.get("username", ""),
                "role": session.get("role", ""),
                "created_at": session.get("created_at", ""),
                "last_active_at": session.get("last_active_at", ""),
                "ip": session.get("last_ip", ""),
                "expires_at": session.get("expires_at", ""),
                "is_current": session.get("session_id", "") == current_session_id,
            }
        )
    return {"sessions": sessions}


@app.delete(
    "/api/auth/sessions/{session_id}",
    tags=["Auth"],
    summary="Revoke Session",
    description="Revoke a specific active session by id (admin only).",
    response_model=AuthRevokeSessionResponse,
    responses={404: {"model": ApiErrorResponse, "description": "Session not found."}},
)
async def auth_revoke_session(request: Request, response: Response, session_id: str):
    """Revoke an active session token by session id."""
    actor = _require_user(request, ("admin",))
    if not session_id.strip():
        raise HTTPException(400, "Session id is required")
    session = next((row for row in list_active_sessions() if row.get("session_id") == session_id), None)
    revoked = delete_session(session_id)
    if not revoked:
        raise HTTPException(404, "Session not found")
    if request.cookies.get(SESSION_COOKIE, "") == session_id:
        _clear_session_cookie(response)
    record_audit_event(
        actor_username=actor["username"],
        action="revoke_session",
        target_username=str((session or {}).get("username", "") or ""),
        details={
            "session_id": session_id,
            "target_role": str((session or {}).get("role", "") or ""),
            "target_ip": str((session or {}).get("last_ip", "") or ""),
        },
    )
    return {"revoked": True, "session_id": session_id}


@app.get(
    "/api/auth/audit",
    tags=["Auth"],
    summary="List Auth Audit Events",
    description="Return authentication and identity-management audit records (admin only).",
    response_model=AuthAuditEventsResponse,
)
async def auth_audit(
    request: Request,
    limit: int = Query(100, ge=1, le=500),
    target_username: str = Query(""),
    actor_username: str = Query(""),
    action: str = Query(""),
    search: str = Query(""),
):
    """List authentication and identity-management audit events."""
    _require_user(request, ("admin",))
    return {
        "events": list_audit_events(
            limit=limit,
            target_username=target_username.strip(),
            actor_username=actor_username.strip(),
            action=action.strip(),
            search=search.strip(),
        )
    }


@app.get(
    "/api/auth/preferences",
    tags=["Auth"],
    summary="Get User Preferences",
    description="Return current user's persisted dashboard/application preferences.",
    response_model=UserPreferencesResponse,
)
async def auth_preferences(request: Request):
    """Return current user's persisted dashboard preferences."""
    user = _require_user(request, ("viewer", "analyst", "admin"))
    return get_user_preferences(user["username"])


@app.patch(
    "/api/auth/preferences",
    tags=["Auth"],
    summary="Update User Preferences",
    description="Apply a partial preference update for the current authenticated user.",
    response_model=UserPreferencesResponse,
)
async def auth_update_preferences(request: Request, body: PreferencesPatchRequest):
    """Apply a partial update to the current user's preferences."""
    user = _require_user(request, ("viewer", "analyst", "admin"))
    if not isinstance(body.preferences, dict):
        raise HTTPException(400, "Preferences payload must be an object")
    updated = update_user_preferences(user["username"], body.preferences)
    record_audit_event(
        actor_username=user["username"],
        action="update_preferences",
        target_username=user["username"],
        details={"keys": sorted(list(body.preferences.keys()))[:20]},
    )
    return updated


@app.post(
    "/api/auth/change-password",
    tags=["Auth"],
    summary="Change Password",
    description="Change current user's password and rotate all existing sessions.",
    response_model=AuthChangePasswordResponse,
)
async def auth_change_password(request: Request, response: Response, body: ChangePasswordRequest):
    """Change password and rotate all active sessions for current user."""
    user = _require_user(request, ("viewer", "analyst", "admin"))
    current_password = body.current_password or ""
    new_password = _validate_password(body.new_password or "", username=user["username"])
    if current_password == new_password:
        raise HTTPException(400, "New password must be different from the current password")
    updated_user = change_password(user["username"], current_password, new_password)
    if not updated_user:
        raise HTTPException(401, "Current password is incorrect")
    revoked = delete_sessions_for_user(user["username"])
    record_audit_event(
        actor_username=user["username"],
        action="change_password",
        target_username=user["username"],
        details={"self_service": True, "revoked_sessions": revoked},
    )
    session = create_session(updated_user, client_ip=_client_ip(request))
    _set_session_cookie(request, response, session)
    return {
        "changed": True,
        "revoked_sessions": revoked,
        "user": _public_user(session),
        "csrf_token": _csrf_token_for_session(session.get("session_id", "")),
    }


@app.get(
    "/api/auth/audit/export",
    tags=["Auth"],
    summary="Export Auth Audit",
    description="Export auth audit records as CSV or JSON attachment (admin only).",
)
async def auth_audit_export(
    request: Request,
    limit: int = Query(500, ge=1, le=5000),
    target_username: str = Query(""),
    actor_username: str = Query(""),
    action: str = Query(""),
    search: str = Query(""),
    format: str = Query("csv"),
):
    """Export auth audit records as CSV or JSON attachment."""
    user = _require_user(request, ("admin",))
    events = list_audit_events(
        limit=limit,
        target_username=target_username.strip(),
        actor_username=actor_username.strip(),
        action=action.strip(),
        search=search.strip(),
    )
    record_audit_event(
        actor_username=user["username"],
        action="export_auth_audit",
        details={
            "format": (format or "csv").strip().lower(),
            "limit": limit,
            "target_username": target_username.strip(),
            "actor_username": actor_username.strip(),
            "action_filter": action.strip(),
            "search": search.strip(),
        },
    )
    export_format = (format or "csv").strip().lower()
    if export_format == "json":
        return Response(
            content=json.dumps({"events": events}, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=triage-auth-audit.json"},
        )
    if export_format != "csv":
        raise HTTPException(400, "Export format must be csv or json")
    buf = io.StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=["id", "created_at", "actor_username", "action", "target_username", "details_json"],
    )
    writer.writeheader()
    for event in events:
        writer.writerow(
            {
                "id": event.get("id", ""),
                "created_at": event.get("created_at", ""),
                "actor_username": event.get("actor_username", ""),
                "action": event.get("action", ""),
                "target_username": event.get("target_username", ""),
                "details_json": json.dumps(event.get("details", {}), sort_keys=True),
            }
        )
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=triage-auth-audit.csv"},
    )


# ---------------------------------------------------------------------------
# API: Admin backups
# ---------------------------------------------------------------------------
@app.post(
    "/api/admin/backup",
    tags=["Admin"],
    summary="Create Backup",
    description="Create a filesystem backup snapshot for state databases (admin only).",
    response_model=BackupCreateResponse,
    responses={
        200: {
            "description": "Backup snapshot metadata.",
            "content": {
                "application/json": {
                    "example": {
                        "backup_id": "20260316-173500",
                        "created_at": "2026-03-16T17:35:00+00:00",
                        "data_dir": "C:/triage-engine/data",
                        "backup_path": "C:/triage-engine/data/backups/20260316-173500",
                        "total_bytes": 173824,
                        "files": [
                            {"name": "auth.db", "size_bytes": 65536, "sha256": "abc..."},
                            {"name": "reviews.db", "size_bytes": 98304, "sha256": "def..."},
                            {"name": "jobs.db", "size_bytes": 9984, "sha256": "ghi..."},
                        ],
                    }
                }
            },
        }
    },
)
async def admin_create_backup(request: Request):
    """Create a backup snapshot of auth/review/job state databases."""
    actor = _require_user(request, ("admin",))
    try:
        backup = create_state_backup(data_dir=DATA_ROOT, backups_dir=BACKUPS_ROOT)
    except Exception as exc:
        raise HTTPException(500, f"Backup failed: {exc}")
    record_audit_event(
        actor_username=actor["username"],
        action="create_backup",
        details={
            "backup_id": backup.get("backup_id", ""),
            "backup_path": backup.get("backup_path", ""),
            "total_bytes": backup.get("total_bytes", 0),
        },
    )
    return backup


@app.get(
    "/api/admin/backups",
    tags=["Admin"],
    summary="List Backups",
    description="List available backup snapshots with metadata (admin only).",
    response_model=BackupListResponse,
)
async def admin_list_backups(request: Request):
    """List available backup snapshots with size and file-count metadata."""
    _require_user(request, ("admin",))
    try:
        backups = list_state_backups(data_dir=DATA_ROOT, backups_dir=BACKUPS_ROOT)
    except Exception as exc:
        raise HTTPException(500, f"Backup listing failed: {exc}")
    return {"backups": backups}


# ---------------------------------------------------------------------------
# API: Client profiles
# ---------------------------------------------------------------------------
@app.get("/api/capabilities", tags=["Admin"])
async def get_capabilities(request: Request):
    """Report local entitlement capabilities; no telemetry or license upload."""
    _require_user(request, ("viewer", "analyst", "admin"))
    edition = "community"
    license_path = os.environ.get("TRIAGE_LICENSE_PATH", "").strip()
    license_secret = os.environ.get("TRIAGE_LICENSE_SECRET", "")
    license_info = {"valid": False, "edition": edition, "features": []}
    if license_path:
        license_info = load_license_file(license_path, license_secret)
        if license_info.get("valid"):
            edition = str(license_info.get("edition") or edition)
    return {"schema_version": "1.0", "edition": edition, "license": license_info, "capabilities": capabilities(edition)}


@app.get("/api/clients", tags=["Cases"], response_model=List[ClientResponse])
async def list_client_profiles(request: Request, active_only: bool = Query(False)):
    """List MSP client profiles available for case attribution."""
    _require_user(request, ("viewer", "analyst", "admin"))
    return [profile.to_dict() for profile in _product_store().list_clients(active_only=active_only)]


@app.get("/api/clients/{client_id}", tags=["Cases"], response_model=ClientResponse)
async def get_client_profile(client_id: str, request: Request):
    _require_user(request, ("viewer", "analyst", "admin"))
    profile = _product_store().get_client(client_id)
    if not profile:
        raise HTTPException(404, f"Client not found: {client_id}")
    return profile.to_dict()


@app.post("/api/clients", tags=["Cases"], response_model=ClientResponse)
async def create_client_profile(request: Request, body: ClientCreateRequest):
    actor = _require_user(request, ("analyst", "admin"))
    try:
        profile = _product_store().upsert_client(ClientProfile(**body.model_dump()))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    record_audit_event(actor_username=actor["username"], action="create_client", target_username=profile.client_id)
    return profile.to_dict()


@app.patch("/api/clients/{client_id}", tags=["Cases"], response_model=ClientResponse)
async def patch_client_profile(client_id: str, request: Request, body: ClientPatchRequest):
    actor = _require_user(request, ("analyst", "admin"))
    store = _product_store()
    profile = store.get_client(client_id)
    if not profile:
        raise HTTPException(404, f"Client not found: {client_id}")
    for field, value in body.dict(exclude_unset=True).items():
        setattr(profile, field, value)
    try:
        profile = store.upsert_client(profile)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    record_audit_event(actor_username=actor["username"], action="update_client", target_username=client_id)
    return profile.to_dict()


@app.patch("/api/clients", tags=["Cases"], response_model=ClientResponse)
async def patch_client_profile_by_body(request: Request, body: ClientUpdateRequest):
    """Compatibility form of the profile update endpoint using a body client_id."""
    patch_body = ClientPatchRequest(**body.dict(exclude={"client_id"}, exclude_unset=True))
    return await patch_client_profile(body.client_id, request, patch_body)


@app.delete("/api/clients/{client_id}", tags=["Cases"])
async def delete_client_profile(client_id: str, request: Request):
    actor = _require_user(request, ("admin",))
    if not _product_store().delete_client(client_id):
        raise HTTPException(404, f"Client not found or protected: {client_id}")
    record_audit_event(actor_username=actor["username"], action="delete_client", target_username=client_id)
    return {"deleted": client_id}


@app.delete("/api/clients", tags=["Cases"])
async def delete_client_profile_by_query(request: Request, client_id: str = Query(...)):
    """Compatibility form of profile deletion using a query client_id."""
    return await delete_client_profile(client_id, request)


# ---------------------------------------------------------------------------
# API: Cases
# ---------------------------------------------------------------------------
def _collect_case_summaries() -> List[Dict[str, Any]]:
    if not os.path.isdir(CASES_ROOT):
        return []
    cases: List[Dict[str, Any]] = []
    try:
        stored_metadata = _product_store().all_case_metadata()
    except (OSError, sqlite3.Error):
        stored_metadata = {}
    for name in sorted(os.listdir(CASES_ROOT), reverse=True):
        case_dir = os.path.join(CASES_ROOT, name)
        if not os.path.isdir(case_dir):
            continue
        info: Dict[str, Any] = {"name": name}

        # Read run_status.json
        rs_path = os.path.join(case_dir, "run_status.json")
        if os.path.isfile(rs_path):
            try:
                with open(rs_path, "r", encoding="utf-8") as fh:
                    rs = json.load(fh)
                info["status"] = rs.get("status", "unknown")
                info["started_at"] = rs.get("started_at")
                info["completed_at"] = rs.get("completed_at")
                info["stage"] = rs.get("current_stage")
                info["message"] = rs.get("message")
                meta = rs.get("metadata", {})
                cm = meta.get("case_metrics", {})
                info["signal_count"] = cm.get("signal_count", 0)
                info["finding_count"] = cm.get("finding_count", 0)
                info["incident_count"] = cm.get("incident_count", 0)
                info["response_priority"] = meta.get("response_priority", "")
                if isinstance(meta.get("triage_disposition"), dict):
                    info["disposition"] = meta["triage_disposition"]
                scope = meta.get("evidence_scope")
                if isinstance(scope, dict):
                    info["scope"] = {
                        key: scope.get(key)
                        for key in ("host_count", "span_days", "needs_scope_review", "split_verdict", "host_verdict_counts")
                    }
            except Exception:
                info["status"] = "unknown"
        else:
            info["status"] = "unknown"

        # Fall back to findings.json for older cases without metadata
        findings_file = os.path.join(case_dir, "findings.json")
        if not info.get("signal_count") and os.path.isfile(findings_file):
            try:
                with open(findings_file, "r", encoding="utf-8") as fh:
                    fd = json.load(fh)
                sm = fd.get("summary", {})
                info["signal_count"] = sm.get("signal_count", len(fd.get("signals", [])))
                info["finding_count"] = sm.get("finding_count", len(fd.get("findings", [])))
                info["incident_count"] = sm.get("incident_count", len(fd.get("incidents", [])))
                cs = fd.get("case", {})
                if not info.get("response_priority"):
                    info["response_priority"] = cs.get("response_priority", "")
                if not info.get("started_at"):
                    info["started_at"] = cs.get("first_seen", "")
                if info.get("status") == "unknown":
                    info["status"] = "completed"
                if not info.get("disposition") and isinstance(cs.get("triage_disposition"), dict):
                    info["disposition"] = cs["triage_disposition"]
            except Exception:
                pass

        metadata = stored_metadata.get(name) or _metadata_from_case_artifact(case_dir, name)
        if metadata:
            info["client_id"] = metadata.client_id
            info["acquisition_method"] = metadata.acquisition_method
            info["retention_until"] = metadata.retention_until
        else:
            info.setdefault("client_id", "default")
            info.setdefault("acquisition_method", "")
            info.setdefault("retention_until", "")

        info["has_report"] = os.path.isfile(os.path.join(case_dir, "report.html"))
        info["has_findings"] = os.path.isfile(os.path.join(case_dir, "findings.json"))
        cases.append(info)
    return cases


@app.get(
    "/api/cases",
    tags=["Cases"],
    summary="List Cases",
    description="List known cases with summary counts, status metadata, and artifact availability flags.",
    response_model=List[CaseListItemResponse],
    responses={
        200: {
            "description": "Case inventory payload.",
            "content": {
                "application/json": {
                    "example": [
                        {
                            "name": "case-20260316-1730",
                            "status": "completed",
                            "started_at": "2026-03-16T17:30:01+00:00",
                            "completed_at": "2026-03-16T17:31:19+00:00",
                            "stage": "done",
                            "message": "Investigation completed",
                            "signal_count": 11,
                            "finding_count": 3,
                            "incident_count": 1,
                            "response_priority": "P2",
                            "has_report": True,
                            "has_findings": True,
                        }
                    ]
                }
            },
        }
    },
)
async def list_cases(request: Request):
    """List all case folders with summary metadata."""
    _require_user(request, ("viewer", "analyst", "admin"))
    return apply_demo_redaction_data(_collect_case_summaries())


@app.get("/api/cases/{case_name}/metadata", tags=["Cases"], response_model=CaseMetadataResponse)
async def get_case_metadata(case_name: str, request: Request):
    user = _require_user(request, ("viewer", "analyst", "admin"))
    try:
        case_path = resolve_case_path(CASES_ROOT, case_name)
    except FileNotFoundError:
        raise HTTPException(404, f"Case not found: {case_name}")
    metadata = _get_case_metadata(case_path, os.path.basename(case_path))
    if not metadata:
        raise HTTPException(404, "Case metadata not found")
    _audit_case_access(user, case_name=os.path.basename(case_path), endpoint="/api/cases/{case_name}/metadata")
    return metadata.to_dict()


@app.patch("/api/cases/{case_name}/metadata", tags=["Cases"], response_model=CaseMetadataResponse)
async def patch_case_metadata(case_name: str, request: Request, body: CaseMetadataPatchRequest):
    actor = _require_user(request, ("analyst", "admin"))
    try:
        case_path = resolve_case_path(CASES_ROOT, case_name)
    except FileNotFoundError:
        raise HTTPException(404, f"Case not found: {case_name}")
    resolved_name = os.path.basename(case_path)
    existing = _get_case_metadata(case_path, resolved_name)
    method = _validate_acquisition_method(
        body.acquisition_method,
        default=existing.acquisition_method if existing else "upload",
    )
    manifest = _parse_collection_manifest(
        body.collection_manifest,
        method,
    ) if body.collection_manifest is not None else (existing.collection_manifest if existing else {})
    metadata = CaseMetadata(
        case_name=resolved_name,
        client_id=_require_client_id(body.client_id or (existing.client_id if existing else "default")),
        acquisition_method=method,
        created_at=existing.created_at if existing else datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        retention_until=body.retention_until if body.retention_until is not None else (existing.retention_until if existing else ""),
        collection_manifest=manifest or {},
    )
    try:
        metadata = _product_store().save_case_metadata(metadata)
        _write_case_metadata_artifact(case_path, metadata)
    except (OSError, sqlite3.Error, ValueError) as exc:
        raise HTTPException(400, f"Unable to save case metadata: {exc}")
    record_audit_event(actor_username=actor["username"], action="update_case_metadata", target_username=resolved_name)
    return metadata.to_dict()


@app.post("/api/cases/{case_name}/bundle", tags=["Cases"])
async def create_case_bundle(case_name: str, request: Request):
    """Create a sanitized-by-scope ZIP of the case artifacts for download."""
    user = _require_user(request, ("viewer", "analyst", "admin"))
    try:
        case_path = resolve_case_path(CASES_ROOT, case_name)
    except FileNotFoundError:
        raise HTTPException(404, f"Case not found: {case_name}")
    resolved_name = os.path.basename(case_path)
    metadata = _get_case_metadata(case_path, resolved_name)
    export_dir = os.path.join(DATA_ROOT, "exports")
    os.makedirs(export_dir, exist_ok=True)
    output_path = os.path.join(export_dir, f"triage-{resolved_name}-{uuid.uuid4().hex[:10]}.zip")
    try:
        review_snapshot = {
            "schema_version": "1.0",
            "case_name": resolved_name,
            "findings": get_all_finding_reviews(resolved_name),
            "incidents": get_all_incident_reviews(resolved_name),
            "history": get_all_history(case_name=resolved_name),
        }
        export_case_bundle(
            case_path,
            output_path,
            client_id=metadata.client_id if metadata else "default",
            extra_payloads={"review_state.json": json.dumps(review_snapshot, indent=2, sort_keys=True).encode("utf-8")},
        )
    except (OSError, ValueError) as exc:
        raise HTTPException(500, f"Case bundle creation failed: {exc}")
    try:
        _emit_bundle_webhook(
            case_name=resolved_name,
            client_id=str(metadata.client_id if metadata else "default"),
            output_path=output_path,
        )
    except Exception:
        SERVER_LOGGER.warning(
            "webhook_dispatch_unexpected_error",
            extra={"case_name": resolved_name, "event": "bundle.exported"},
            exc_info=True,
        )
    _audit_case_access(user, case_name=resolved_name, endpoint="/api/cases/{case_name}/bundle")
    record_audit_event(actor_username=user["username"], action="export_case_bundle", target_username=resolved_name)
    filename = _safe_download_filename(f"triage-{resolved_name}-bundle", "zip")
    return FileResponse(
        output_path,
        media_type="application/zip",
        filename=filename,
        background=BackgroundTask(lambda: os.path.exists(output_path) and os.remove(output_path)),
    )


@app.post("/api/cases/{case_name}/ai-summary", tags=["Cases"])
async def create_ai_summary(case_name: str, request: Request, body: AISummaryRequest):
    """Optionally rewrite a deterministic summary through an OpenAI-compatible endpoint."""
    user = _require_user(request, ("analyst", "admin"))
    if not body.consent:
        raise HTTPException(400, "Explicit consent is required before sending case data to an AI endpoint")
    endpoint = _validate_ai_endpoint(body.endpoint)
    try:
        case_path = resolve_case_path(CASES_ROOT, case_name)
    except FileNotFoundError:
        raise HTTPException(404, f"Case not found: {case_name}")
    findings_path = os.path.join(case_path, "findings.json")
    if not os.path.isfile(findings_path):
        raise HTTPException(404, "findings.json not found for this case")
    with open(findings_path, "r", encoding="utf-8") as fh:
        payload = json.load(fh)
    deterministic = {
        "schema_version": "1.0",
        "case": payload.get("case", {}),
        "summary": payload.get("summary", {}),
        "incidents": payload.get("incidents", []),
        "findings": payload.get("findings", []),
    }
    # Never transmit raw_events.jsonl, collection payloads, credentials, or
    # review notes through this endpoint.
    endpoint_lower = endpoint.lower()
    env_key_name = "GROQ_API_KEY" if "groq" in endpoint_lower else "ANTHROPIC_API_KEY" if "anthropic" in endpoint_lower else "OPENAI_API_KEY"
    api_key = body.api_key or os.environ.get(env_key_name, "")
    try:
        summary = AIProvider(endpoint, enabled=True, api_key=api_key, model=body.model).summarize(deterministic)
    except RuntimeError as exc:
        raise HTTPException(502, str(exc))
    record_audit_event(actor_username=user["username"], action="ai_summary", target_username=os.path.basename(case_path), details={"endpoint": endpoint, "model": body.model, "consent": True})
    return {"schema_version": "1.0", "assisted": True, "deterministic": True, "summary": summary or ""}


@app.post("/api/cases/{case_name}/jev-review", tags=["Cases"])
def create_jev_review(case_name: str, request: Request, body: JevReviewRequest):
    """Return an opt-in, advisory TypeSafe Jev judgment on a bounded case summary."""
    user = _require_user(request, ("analyst", "admin"))
    if not body.consent:
        raise HTTPException(400, "Explicit consent is required before sending case data to Jev")
    api_key = os.environ.get("TYPESAFE_API_KEY", "").strip()
    if not api_key:
        raise HTTPException(503, "TYPESAFE_API_KEY is not configured on the server")
    try:
        case_path = resolve_case_path(CASES_ROOT, case_name)
    except FileNotFoundError:
        raise HTTPException(404, f"Case not found: {case_name}")
    findings_path = os.path.join(case_path, "findings.json")
    if not os.path.isfile(findings_path):
        raise HTTPException(404, "findings.json not found for this case")
    with open(findings_path, "r", encoding="utf-8") as fh:
        payload = json.load(fh)
    model = os.environ.get("TRIAGE_JEV_MODEL", DEFAULT_JEV_MODEL).strip()
    record_audit_event(
        actor_username=user["username"],
        action="jev_review_requested",
        target_username=os.path.basename(case_path),
        details={"provider": "typesafe_jev", "model": model, "consent": True},
    )
    try:
        return request_jev_review(payload, api_key=api_key, model=model)
    except (JevIntegrationError, ValueError) as exc:
        raise HTTPException(502, str(exc)) from exc


@app.get(
    "/api/cases/export",
    tags=["Cases"],
    summary="Export Case List",
    description="Export case inventory as CSV for external triage and ticketing workflows.",
    responses={
        200: {"description": "CSV attachment of case inventory."},
        400: {"model": ApiErrorResponse, "description": "Unsupported export format."},
    },
)
async def export_cases(request: Request, format: str = Query("csv")):
    """Export case list as CSV attachment."""
    user = _require_user(request, ("viewer", "analyst", "admin"))
    export_format = (format or "csv").strip().lower()
    if export_format != "csv":
        raise HTTPException(400, "Export format must be csv")
    rows = _collect_case_summaries()
    rows = apply_demo_redaction_data(rows)
    record_audit_event(
        actor_username=user["username"],
        action="export_cases",
        details={"format": export_format, "row_count": len(rows)},
    )
    filename = _safe_download_filename("triage-cases", "csv")
    return _csv_attachment(rows, fieldnames=CASE_EXPORT_FIELDNAMES, filename=filename)


@app.get(
    "/api/cases/{case_name}",
    tags=["Cases"],
    summary="Get Case Payload",
    description="Return `findings.json` for a case with review-state overlays on findings and incidents.",
    response_model=Dict[str, Any],
)
async def get_case(case_name: str, request: Request):
    """Get full case details from findings.json with review state overlay."""
    user = _require_user(request, ("viewer", "analyst", "admin"))
    try:
        case_path = resolve_case_path(CASES_ROOT, case_name)
    except FileNotFoundError:
        raise HTTPException(404, f"Case not found: {case_name}")
    findings_path = os.path.join(case_path, "findings.json")
    if not os.path.isfile(findings_path):
        raise HTTPException(404, "findings.json not found for this case")
    with open(findings_path, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    # Overlay review state onto findings and incidents at read time
    resolved_name = os.path.basename(case_path)
    finding_reviews = get_all_finding_reviews(resolved_name)
    incident_reviews = get_all_incident_reviews(resolved_name)

    for f in data.get("findings", []):
        fid = f.get("id", "")
        if fid in finding_reviews:
            f["review"] = finding_reviews[fid]
    for inc in data.get("incidents", []):
        iid = inc.get("id", "")
        if iid in incident_reviews:
            inc["review"] = incident_reviews[iid]

    metadata = _get_case_metadata(case_path, resolved_name)
    if metadata:
        metadata_payload = metadata.to_dict()
        data["case_metadata"] = metadata_payload
        case_payload = data.setdefault("case", {})
        case_payload.setdefault("client_id", metadata.client_id)
        case_payload.setdefault("acquisition_method", metadata.acquisition_method)
        case_payload.setdefault("retention_until", metadata.retention_until)
        case_payload.setdefault("collection_manifest", metadata.collection_manifest)
    case_payload = data.get("case", {})
    if isinstance(case_payload, dict) and isinstance(case_payload.get("triage_disposition"), dict):
        data.setdefault("triage_disposition", case_payload["triage_disposition"])

    _audit_case_access(user, case_name=resolved_name, endpoint="/api/cases/{case_name}")
    return apply_demo_redaction_data(data)


@app.get(
    "/api/cases/{case_name}/export",
    tags=["Cases"],
    summary="Export Case JSON",
    description="Download the full `findings.json` payload for a case as a JSON attachment.",
    responses={200: {"description": "JSON attachment of case findings payload."}},
)
async def export_case(case_name: str, request: Request):
    """Export a case findings payload as downloadable JSON."""
    user = _require_user(request, ("viewer", "analyst", "admin"))
    try:
        case_path = resolve_case_path(CASES_ROOT, case_name)
    except FileNotFoundError:
        raise HTTPException(404, f"Case not found: {case_name}")
    findings_path = os.path.join(case_path, "findings.json")
    if not os.path.isfile(findings_path):
        raise HTTPException(404, "findings.json not found for this case")
    with open(findings_path, "r", encoding="utf-8") as fh:
        payload = json.load(fh)
    resolved_name = os.path.basename(case_path)
    metadata = _get_case_metadata(case_path, resolved_name)
    if metadata:
        payload["case_metadata"] = metadata.to_dict()
        case_payload = payload.setdefault("case", {})
        case_payload.setdefault("client_id", metadata.client_id)
        case_payload.setdefault("acquisition_method", metadata.acquisition_method)
        case_payload.setdefault("retention_until", metadata.retention_until)
        case_payload.setdefault("collection_manifest", metadata.collection_manifest)
    case_payload = payload.get("case", {})
    if isinstance(case_payload, dict) and isinstance(case_payload.get("triage_disposition"), dict):
        payload.setdefault("triage_disposition", case_payload["triage_disposition"])
    payload = apply_demo_redaction_data(payload)
    _audit_case_access(user, case_name=resolved_name, endpoint="/api/cases/{case_name}/export")
    record_audit_event(
        actor_username=user["username"],
        action="export_case_payload",
        target_username=resolved_name,
        details={"case_name": resolved_name, "format": "json"},
    )
    filename = _safe_download_filename(f"triage-{resolved_name}", "json")
    return Response(
        content=json.dumps(payload, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get(
    "/api/cases/{case_name}/status",
    tags=["Cases"],
    summary="Get Case Run Status",
    description="Return `run_status.json` metadata for a case including stage and timing data.",
    response_model=Dict[str, Any],
)
async def get_case_status(case_name: str, request: Request):
    """Get run_status.json for a case."""
    user = _require_user(request, ("viewer", "analyst", "admin"))
    try:
        case_path = resolve_case_path(CASES_ROOT, case_name)
    except FileNotFoundError:
        raise HTTPException(404, f"Case not found: {case_name}")
    rs_path = os.path.join(case_path, "run_status.json")
    if not os.path.isfile(rs_path):
        raise HTTPException(404, "run_status.json not found")
    with open(rs_path, "r", encoding="utf-8") as fh:
        payload = json.load(fh)
    _audit_case_access(user, case_name=os.path.basename(case_path), endpoint="/api/cases/{case_name}/status")
    return apply_demo_redaction_data(payload)


@app.get(
    "/api/cases/{case_name}/timeline",
    tags=["Cases"],
    summary="Get Case Timeline",
    description="Return case `timeline.json` event timeline artifact.",
    response_model=Dict[str, Any],
)
async def get_timeline(case_name: str, request: Request):
    """Get timeline.json for a case."""
    user = _require_user(request, ("viewer", "analyst", "admin"))
    try:
        case_path = resolve_case_path(CASES_ROOT, case_name)
    except FileNotFoundError:
        raise HTTPException(404, f"Case not found: {case_name}")
    path = os.path.join(case_path, "timeline.json")
    if not os.path.isfile(path):
        raise HTTPException(404, "timeline.json not found")
    with open(path, "r", encoding="utf-8") as fh:
        payload = json.load(fh)
    _audit_case_access(user, case_name=os.path.basename(case_path), endpoint="/api/cases/{case_name}/timeline")
    return apply_demo_redaction_data(payload)


@app.get(
    "/api/cases/{case_name}/graph",
    tags=["Cases"],
    summary="Get Case Entity Graph",
    description="Return case `graph.json` entity/relationship artifact.",
    response_model=Dict[str, Any],
)
async def get_graph(case_name: str, request: Request):
    """Get graph.json for a case."""
    user = _require_user(request, ("viewer", "analyst", "admin"))
    try:
        case_path = resolve_case_path(CASES_ROOT, case_name)
    except FileNotFoundError:
        raise HTTPException(404, f"Case not found: {case_name}")
    path = os.path.join(case_path, "graph.json")
    if not os.path.isfile(path):
        raise HTTPException(404, "graph.json not found")
    with open(path, "r", encoding="utf-8") as fh:
        payload = json.load(fh)
    _audit_case_access(user, case_name=os.path.basename(case_path), endpoint="/api/cases/{case_name}/graph")
    return apply_demo_redaction_data(payload)


@app.get(
    "/api/cases/{case_name}/report",
    tags=["Cases"],
    summary="Get Case HTML Report",
    description="Download or render `report.html` for a case.",
)
async def get_report(case_name: str, request: Request):
    """Serve the HTML report for a case."""
    user = _require_user(request, ("viewer", "analyst", "admin"))
    try:
        case_path = resolve_case_path(CASES_ROOT, case_name)
    except FileNotFoundError:
        raise HTTPException(404, f"Case not found: {case_name}")
    path = os.path.join(case_path, "report.html")
    if not os.path.isfile(path):
        raise HTTPException(404, "report.html not found")
    _audit_case_access(user, case_name=os.path.basename(case_path), endpoint="/api/cases/{case_name}/report")
    # Reports embed attacker-controlled evidence and a third-party graph script;
    # sandboxing gives them an opaque origin so they cannot call the API as the analyst.
    return FileResponse(
        path,
        media_type="text/html",
        headers={"Content-Security-Policy": REPORT_CSP},
    )


@app.get(
    "/api/cases/{case_name}/summary",
    tags=["Cases"],
    summary="Get Case Summary Text",
    description="Return plain-text `summary.txt` content in JSON wrapper.",
    response_model=CaseTextResponse,
)
async def get_summary(case_name: str, request: Request):
    """Return summary.txt content."""
    user = _require_user(request, ("viewer", "analyst", "admin"))
    try:
        case_path = resolve_case_path(CASES_ROOT, case_name)
    except FileNotFoundError:
        raise HTTPException(404, f"Case not found: {case_name}")
    path = os.path.join(case_path, "summary.txt")
    if not os.path.isfile(path):
        raise HTTPException(404, "summary.txt not found")
    with open(path, "r", encoding="utf-8") as fh:
        payload = {"summary": apply_demo_redaction_text(fh.read())}
    _audit_case_access(user, case_name=os.path.basename(case_path), endpoint="/api/cases/{case_name}/summary")
    return payload


@app.get(
    "/api/cases/{case_name}/brief",
    tags=["Cases"],
    summary="Get Incident Brief",
    description="Return Markdown `incident_brief.md` content in JSON wrapper.",
    response_model=CaseTextResponse,
)
async def get_brief(case_name: str, request: Request):
    """Return incident_brief.md content."""
    user = _require_user(request, ("viewer", "analyst", "admin"))
    try:
        case_path = resolve_case_path(CASES_ROOT, case_name)
    except FileNotFoundError:
        raise HTTPException(404, f"Case not found: {case_name}")
    path = os.path.join(case_path, "incident_brief.md")
    if not os.path.isfile(path):
        raise HTTPException(404, "incident_brief.md not found")
    with open(path, "r", encoding="utf-8") as fh:
        payload = {"brief": apply_demo_redaction_text(fh.read())}
    _audit_case_access(user, case_name=os.path.basename(case_path), endpoint="/api/cases/{case_name}/brief")
    return payload


@app.delete(
    "/api/cases/{case_name}/purge",
    tags=["Cases"],
    summary="Purge Expired Case",
    description="Permanently remove an expired case and its workflow metadata (admin only).",
    response_model=PurgeCaseResponse,
)
async def purge_expired_case(case_name: str, request: Request):
    """Purge only after the case's configured retention period has elapsed."""
    actor = _require_user(request, ("admin",))
    try:
        case_path = resolve_case_path(CASES_ROOT, case_name)
    except FileNotFoundError:
        raise HTTPException(404, f"Case not found: {case_name}")
    resolved_name = os.path.basename(case_path)
    metadata = _get_case_metadata(case_path, resolved_name)
    if not metadata or not metadata.retention_until:
        raise HTTPException(409, "Case retention metadata is required before purge")
    try:
        retention_until = datetime.fromisoformat(metadata.retention_until.replace("Z", "+00:00"))
        if retention_until.tzinfo is None:
            retention_until = retention_until.replace(tzinfo=timezone.utc)
    except ValueError:
        raise HTTPException(409, "Case retention metadata is invalid; refusing purge")
    if retention_until > datetime.now(timezone.utc):
        raise HTTPException(409, "Case retention period has not elapsed")
    shutil.rmtree(case_path, ignore_errors=True)
    delete_case_review_state(resolved_name)
    try:
        _product_store().purge_case_metadata(resolved_name)
    except (OSError, sqlite3.Error):
        # Artifacts are already removed; audit the partial cleanup for follow-up.
        SERVER_LOGGER.warning("case_metadata_purge_failed", extra={"case_name": resolved_name}, exc_info=True)
    record_audit_event(
        actor_username=actor["username"],
        action="purge_expired_case",
        target_username=resolved_name,
        details={"case_name": resolved_name, "retention_until": metadata.retention_until},
    )
    return {"purged": resolved_name}


@app.delete(
    "/api/cases/{case_name}",
    tags=["Cases"],
    summary="Delete Case",
    description="Delete case artifacts and associated review state (admin only).",
    response_model=DeleteCaseResponse,
)
async def delete_case(case_name: str, request: Request):
    """Delete a case folder."""
    actor = _require_user(request, ("admin",))
    try:
        case_path = resolve_case_path(CASES_ROOT, case_name)
    except FileNotFoundError:
        raise HTTPException(404, f"Case not found: {case_name}")
    resolved_name = os.path.basename(case_path)
    shutil.rmtree(case_path, ignore_errors=True)
    delete_case_review_state(resolved_name)
    record_audit_event(
        actor_username=actor["username"],
        action="delete_case",
        target_username=resolved_name,
        details={"case_name": resolved_name},
    )
    return {"deleted": resolved_name}


# ---------------------------------------------------------------------------
# API: Investigate
# ---------------------------------------------------------------------------
@app.post(
    "/api/investigate",
    tags=["Investigate"],
    summary="Start Investigation From Upload",
    description="Upload one or more EVTX files and enqueue background investigation job.",
    response_model=InvestigationQueuedResponse,
    responses={
        200: {
            "description": "Background job accepted.",
            "content": {"application/json": {"example": {"job_id": "a1b2c3d4e5f6", "case_name": "case-evtx-sample", "status": "queued"}}},
        }
    },
)
async def start_investigation(
    request: Request,
    files: List[UploadFile] = File(...),
    case_name: Optional[str] = Query(None),
    enable_sigma: bool = Query(False),
    client_id: str = Query("default"),
    acquisition_method: str = Query("upload"),
    collection_manifest: Optional[str] = Query(None),
):
    """Upload EVTX files and start an investigation in the background."""
    actor = _require_user(request, ("analyst", "admin"))
    request_id = _request_id_for_log(request)
    case_name = _validate_case_name(case_name)
    client_id = _require_client_id(client_id)
    acquisition_method = _validate_acquisition_method(acquisition_method, default="upload")
    manifest = _parse_collection_manifest(collection_manifest, acquisition_method)

    job_id = uuid.uuid4().hex[:12]
    upload_dir = os.path.join(UPLOAD_ROOT, job_id)
    os.makedirs(upload_dir, exist_ok=True)

    aggregate_bytes = 0
    try:
        for index, f in enumerate(files):
            filename = os.path.basename(f.filename or "upload.evtx")
            if not filename.lower().endswith(".evtx"):
                raise HTTPException(400, f"Only .evtx files are accepted, got: {filename}")
            # Avoid silently replacing another uploaded evidence file with the
            # same basename while keeping the original filename recognizable.
            dest = os.path.join(upload_dir, filename)
            if os.path.exists(dest):
                stem, extension = os.path.splitext(filename)
                dest = os.path.join(upload_dir, f"{stem}-{index}{extension}")
            file_bytes = 0
            with open(dest, "wb") as out:
                while True:
                    chunk = await f.read(UPLOAD_CHUNK_BYTES)
                    if not chunk:
                        break
                    file_bytes += len(chunk)
                    aggregate_bytes += len(chunk)
                    if file_bytes > MAX_UPLOAD_BYTES:
                        raise HTTPException(413, f"File too large: {filename} (max {MAX_UPLOAD_BYTES} bytes)")
                    if aggregate_bytes > MAX_AGGREGATE_UPLOAD_BYTES:
                        raise HTTPException(413, f"Total upload too large (max {MAX_AGGREGATE_UPLOAD_BYTES} bytes)")
                    out.write(chunk)
    except Exception:
        shutil.rmtree(upload_dir, ignore_errors=True)
        raise

    uploaded = [os.path.join(upload_dir, n) for n in os.listdir(upload_dir)]
    if not uploaded:
        shutil.rmtree(upload_dir, ignore_errors=True)
        raise HTTPException(400, "At least one EVTX file is required")
    evtx_path = uploaded[0] if len(uploaded) == 1 else upload_dir

    investigation_request = InvestigationRequest(
        input_source=evtx_path,
        input_mode="evtx_path",
        case_name=case_name,
        cases_dir=CASES_ROOT,
        enable_sigma=enable_sigma,
        request_id=request_id,
        requested_by=actor["username"],
        client_id=client_id,
        acquisition_method=acquisition_method,
        collection_manifest=manifest,
    )

    from triage_engine.case_utils import auto_case_name as _auto_name
    resolved_name = case_name or _auto_name(evtx_path, False, "")
    create_job(job_id, case_name=resolved_name, upload_path=upload_dir)
    record_audit_event(
        actor_username=actor["username"],
        action="start_investigation_upload",
        target_username=resolved_name,
        details={"job_id": job_id, "file_count": len(uploaded), "enable_sigma": enable_sigma, "client_id": client_id},
    )

    SERVER_LOGGER.info(
        "investigation_queued",
        extra={
            "request_id": request_id,
            "user": actor["username"],
            "job_id": job_id,
            "case_name": resolved_name,
            "input_mode": "evtx_path",
            "file_count": len(uploaded),
            "enable_sigma": bool(enable_sigma),
        },
    )
    try:
        _submit_investigation_job(job_id, investigation_request, upload_dir)
    except HTTPException:
        delete_job(job_id)
        shutil.rmtree(upload_dir, ignore_errors=True)
        raise

    return {"job_id": job_id, "case_name": resolved_name, "status": "queued"}


@app.post(
    "/api/investigate/path",
    tags=["Investigate"],
    summary="Start Investigation From Local Path",
    description="Enqueue investigation for a local EVTX file or directory path accessible to the server host.",
    response_model=InvestigationQueuedResponse,
)
async def start_investigation_from_path(
    request: Request,
    evtx_path: str = Query(..., description="Local path to EVTX file or directory"),
    case_name: Optional[str] = Query(None),
    enable_sigma: bool = Query(False),
    client_id: str = Query("default"),
    acquisition_method: str = Query("portable_collector"),
    collection_manifest: Optional[str] = Query(None),
):
    """Start investigation using a local file path (no upload needed)."""
    actor = _require_user(request, ("analyst", "admin"))
    request_id = _request_id_for_log(request)
    evtx_path = _validate_evtx_path(evtx_path)
    case_name = _validate_case_name(case_name)
    client_id = _require_client_id(client_id)
    acquisition_method = _validate_acquisition_method(acquisition_method, default="portable_collector")
    manifest = _parse_collection_manifest(collection_manifest, acquisition_method)

    job_id = uuid.uuid4().hex[:12]

    investigation_request = InvestigationRequest(
        input_source=evtx_path,
        input_mode="evtx_path",
        case_name=case_name,
        cases_dir=CASES_ROOT,
        enable_sigma=enable_sigma,
        request_id=request_id,
        requested_by=actor["username"],
        client_id=client_id,
        acquisition_method=acquisition_method,
        collection_manifest=manifest,
    )

    from triage_engine.case_utils import auto_case_name as _auto_name
    resolved_name = case_name or _auto_name(evtx_path, False, "")
    create_job(job_id, case_name=resolved_name)
    record_audit_event(
        actor_username=actor["username"],
        action="start_investigation_path",
        target_username=resolved_name,
        details={"job_id": job_id, "input_path": evtx_path, "enable_sigma": enable_sigma, "client_id": client_id},
    )

    SERVER_LOGGER.info(
        "investigation_queued",
        extra={
            "request_id": request_id,
            "user": actor["username"],
            "job_id": job_id,
            "case_name": resolved_name,
            "input_mode": "evtx_path",
            "input_path": evtx_path,
            "enable_sigma": bool(enable_sigma),
        },
    )
    try:
        _submit_investigation_job(job_id, investigation_request, None)
    except HTTPException:
        delete_job(job_id)
        raise

    return {"job_id": job_id, "case_name": resolved_name, "status": "queued"}


@app.post(
    "/api/investigate/live",
    tags=["Investigate"],
    summary="Start Live Investigation",
    description="Enqueue live Windows event-channel collection and investigation.",
    response_model=LiveInvestigationQueuedResponse,
)
async def start_live_investigation(request: Request, body: LiveInvestigateRequest):
    """Start a live Windows event investigation in the background."""
    actor = _require_user(request, ("analyst", "admin"))
    request_id = _request_id_for_log(request)
    if os.name != "nt":
        raise HTTPException(400, "Live investigations are only supported when the server is running on Windows")

    case_name = _validate_case_name(body.case_name)
    channels = _validate_live_channels(body.channels)
    client_id = _require_client_id(body.client_id)
    acquisition_method = _validate_acquisition_method(body.acquisition_method, default="local_live")
    manifest = _parse_collection_manifest(body.collection_manifest, acquisition_method)
    since_minutes = int(body.since_minutes or 30)
    if since_minutes < 1 or since_minutes > 24 * 60:
        raise HTTPException(400, "Live lookback must be between 1 and 1440 minutes")

    job_id = uuid.uuid4().hex[:12]
    live_request = InvestigationRequest(
        input_source=f"live:{','.join(channels)}",
        input_mode="live",
        case_name=case_name,
        cases_dir=CASES_ROOT,
        enable_sigma=bool(body.enable_sigma),
        channels=channels,
        since_minutes=since_minutes,
        request_id=request_id,
        requested_by=actor["username"],
        client_id=client_id,
        acquisition_method=acquisition_method,
        collection_manifest=manifest,
    )

    from triage_engine.case_utils import auto_case_name as _auto_name
    resolved_name = case_name or _auto_name(None, True, ",".join(channels))
    create_job(job_id, case_name=resolved_name)
    record_audit_event(
        actor_username=actor["username"],
        action="start_investigation_live",
        target_username=resolved_name,
        details={
            "job_id": job_id,
            "channels": channels,
            "since_minutes": since_minutes,
            "enable_sigma": bool(body.enable_sigma),
            "client_id": client_id,
        },
    )

    SERVER_LOGGER.info(
        "investigation_queued",
        extra={
            "request_id": request_id,
            "user": actor["username"],
            "job_id": job_id,
            "case_name": resolved_name,
            "input_mode": "live",
            "channels": list(channels),
            "since_minutes": since_minutes,
            "enable_sigma": bool(body.enable_sigma),
        },
    )
    try:
        _submit_investigation_job(job_id, live_request, None)
    except HTTPException:
        delete_job(job_id)
        raise

    return {
        "job_id": job_id,
        "case_name": resolved_name,
        "status": "queued",
        "input_mode": "live",
        "channels": channels,
        "since_minutes": since_minutes,
    }


@app.get(
    "/api/live/health",
    tags=["Investigate"],
    summary="Live Collection Readiness",
    description="Return live collection readiness and channel accessibility diagnostics.",
    response_model=LiveHealthResponse,
    responses={
        200: {
            "description": "Live collection capability snapshot.",
            "content": {
                "application/json": {
                    "example": {
                        "os_name": "nt",
                        "is_windows": True,
                        "pywin32_available": True,
                        "is_elevated": True,
                        "readiness": "ready",
                        "recommended_channels": ["Security", "System", "Microsoft-Windows-Sysmon/Operational"],
                        "readable_channel_count": 3,
                        "channels": [
                            {"channel": "Security", "readable": True, "status": "ready", "message": "Channel query succeeded"}
                        ],
                        "guidance": ["Server is ready for the recommended live forensic channel set."],
                    }
                }
            },
        }
    },
)
async def live_health(request: Request):
    """Return current host readiness for live event-channel investigations."""
    _require_user(request, ("viewer", "analyst", "admin"))
    return _collect_live_health()


@app.post(
    "/api/live/elevate",
    tags=["Investigate"],
    summary="Request Elevated Local Live Collection",
    description="Request a UAC-approved elevated localhost session for protected Windows event logs.",
    response_model=LiveElevationResponse,
)
async def request_live_elevation(request: Request):
    """Start a separate elevated localhost server after an authenticated request.

    Never accept a remote request here, even if an administrator deliberately
    changes the primary server bind configuration. The original normal-user
    server keeps running, so declining UAC has no impact on EVTX upload use.
    """
    actor = _require_user(request, ("analyst", "admin"))
    if os.name != "nt":
        raise HTTPException(400, "Administrator elevation is only available on Windows")
    if not _is_loopback_client(request):
        raise HTTPException(403, "Administrator elevation can only be requested from the local dashboard")
    if SERVER_HOST not in {"127.0.0.1", "localhost", "::1"}:
        raise HTTPException(409, "Administrator elevation is disabled when the server is not bound to localhost")
    if _is_windows_admin():
        return LiveElevationResponse(
            elevation_requested=False,
            already_elevated=True,
            message="This Triage Engine session already has administrator permission.",
        )

    port = _find_available_loopback_port()
    try:
        redirect_url = _launch_elevated_local_server(port)
    except (OSError, RuntimeError, ValueError) as exc:
        raise HTTPException(500, f"Could not request administrator permission: {exc}")

    record_audit_event(
        actor_username=actor["username"],
        action="request_live_elevation",
        target_username="localhost",
        details={"redirect_url": redirect_url},
    )
    return LiveElevationResponse(
        elevation_requested=True,
        redirect_url=redirect_url,
        message="Windows will request administrator permission for a separate local Triage Engine session.",
    )


@app.get(
    "/api/quick/session",
    tags=["Quick Check"],
    summary="Create Local Quick Check Session",
    response_model=QuickCheckSessionResponse,
)
async def create_quick_check_session(request: Request):
    """Issue a short-lived capability token only to the loopback dashboard."""
    token = _issue_quick_check_token(request)
    return QuickCheckSessionResponse(token=token, expires_in_seconds=QUICK_CHECK_SESSION_TTL_SECONDS)


@app.get(
    "/api/quick/live/health",
    tags=["Quick Check"],
    summary="Quick Check Live Collection Readiness",
    response_model=LiveHealthResponse,
)
async def quick_check_live_health(request: Request):
    _require_quick_check_token(request)
    return _collect_live_health()


@app.post(
    "/api/quick/live/elevate",
    tags=["Quick Check"],
    summary="Request Quick Check Administrator Permission",
    response_model=LiveElevationResponse,
)
async def quick_check_request_elevation(request: Request):
    _require_quick_check_token(request)
    if os.name != "nt":
        raise HTTPException(400, "Administrator elevation is only available on Windows")
    if SERVER_HOST not in {"127.0.0.1", "localhost", "::1"}:
        raise HTTPException(409, "Administrator elevation is disabled when the server is not bound to localhost")
    if _is_windows_admin():
        return LiveElevationResponse(
            elevation_requested=False,
            already_elevated=True,
            message="This Triage Engine session already has administrator permission.",
        )
    port = _find_available_loopback_port()
    try:
        redirect_url = _launch_elevated_local_server(port)
    except (OSError, RuntimeError, ValueError) as exc:
        raise HTTPException(500, f"Could not request administrator permission: {exc}")
    record_audit_event(
        actor_username="quick-check",
        action="request_quick_check_elevation",
        target_username="localhost",
        details={"redirect_url": redirect_url},
    )
    return LiveElevationResponse(
        elevation_requested=True,
        redirect_url=redirect_url,
        message="Windows will request administrator permission for a separate local Triage Engine session.",
    )


@app.post(
    "/api/quick/investigate/live",
    tags=["Quick Check"],
    summary="Start Guided Quick Check",
    response_model=LiveInvestigationQueuedResponse,
)
async def start_quick_check_live(request: Request):
    token = _require_quick_check_token(request)
    return _queue_quick_check_live(request, token)


@app.get(
    "/api/quick/jobs/{job_id}",
    tags=["Quick Check"],
    summary="Get Guided Quick Check Status",
    response_model=JobResponse,
)
async def get_quick_check_job(job_id: str, request: Request):
    token = _require_quick_check_token(request)
    _quick_check_job_for_token(job_id, token)
    job = get_job(job_id)
    if not job:
        raise HTTPException(404, "Quick Check job not found")
    job.update(_job_case_availability(job.get("case_name", "")))
    return job


@app.get(
    "/api/quick/cases/{case_name}",
    tags=["Quick Check"],
    summary="Get Guided Quick Check Result",
    response_model=QuickCheckCaseResponse,
)
async def get_quick_check_case(case_name: str, request: Request):
    token = _require_quick_check_token(request)
    matching = False
    with _QUICK_CHECK_LOCK:
        for record in _QUICK_CHECK_JOBS.values():
            if record.get("case_name") == case_name and hmac.compare_digest(record.get("token", ""), token):
                matching = True
                break
    if not matching:
        raise HTTPException(404, "Quick Check case not found")
    try:
        case_path = resolve_case_path(CASES_ROOT, case_name)
        with open(os.path.join(case_path, "findings.json"), "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except FileNotFoundError:
        raise HTTPException(404, "Quick Check results are not available yet")
    except (OSError, json.JSONDecodeError):
        raise HTTPException(500, "Quick Check results could not be read")
    case_data = payload.get("case", {}) if isinstance(payload, dict) else {}
    return QuickCheckCaseResponse(case_name=case_name, triage_disposition=dict(case_data.get("triage_disposition") or {}))


@app.post(
    "/api/quick/cases/{case_name}/bundle",
    tags=["Quick Check"],
    summary="Export Guided Quick Check Bundle",
)
async def export_quick_check_bundle(case_name: str, request: Request):
    token = _require_quick_check_token(request)
    matching = False
    with _QUICK_CHECK_LOCK:
        for record in _QUICK_CHECK_JOBS.values():
            if record.get("case_name") == case_name and hmac.compare_digest(record.get("token", ""), token):
                matching = True
                break
    if not matching:
        raise HTTPException(404, "Quick Check case not found")
    try:
        case_path = resolve_case_path(CASES_ROOT, case_name)
    except FileNotFoundError:
        raise HTTPException(404, "Quick Check results are not available yet")
    export_dir = os.path.join(DATA_ROOT, "exports")
    os.makedirs(export_dir, exist_ok=True)
    output_path = os.path.join(export_dir, f"triage-{os.path.basename(case_path)}-{uuid.uuid4().hex[:10]}.zip")
    try:
        export_case_bundle(case_path, output_path, client_id="default")
    except (OSError, ValueError) as exc:
        raise HTTPException(500, f"Quick Check export failed: {exc}")
    try:
        _emit_bundle_webhook(
            case_name=os.path.basename(case_path),
            client_id="default",
            output_path=output_path,
        )
    except Exception:
        SERVER_LOGGER.warning(
            "webhook_dispatch_unexpected_error",
            extra={"case_name": os.path.basename(case_path), "event": "bundle.exported"},
            exc_info=True,
        )
    filename = _safe_download_filename(f"triage-{os.path.basename(case_path)}-bundle", "zip")
    return FileResponse(
        output_path,
        media_type="application/zip",
        filename=filename,
        background=BackgroundTask(lambda: os.path.exists(output_path) and os.remove(output_path)),
    )


# ---------------------------------------------------------------------------
# API: Jobs
# ---------------------------------------------------------------------------
@app.get(
    "/api/jobs",
    tags=["Jobs"],
    summary="List Jobs",
    description="List persisted background investigation jobs.",
    response_model=List[JobResponse],
)
async def list_jobs(request: Request):
    """List all investigation jobs (persisted in SQLite)."""
    _require_user(request, ("viewer", "analyst", "admin"))
    jobs = db_list_jobs()
    for job in jobs:
        job.update(_job_case_availability(job.get("case_name", "")))
    return jobs


@app.get(
    "/api/jobs/{job_id}",
    tags=["Jobs"],
    summary="Get Job",
    description="Fetch a single investigation job status and case availability metadata.",
    response_model=JobResponse,
    responses={
        200: {
            "description": "Investigation job state.",
            "content": {
                "application/json": {
                    "example": {
                        "job_id": "a1b2c3d4e5f6",
                        "case_name": "case-evtx-sample",
                        "case_path": "",
                        "status": "running",
                        "stage": "detect",
                        "message": "Running detector modules",
                        "error": "",
                        "results": {},
                        "created_at": "2026-03-16T17:30:01+00:00",
                        "updated_at": "2026-03-16T17:30:42+00:00",
                        "upload_path": "",
                        "case_available": False,
                        "case_missing_reason": "No case linked to this job yet",
                    }
                }
            },
        },
        404: {"model": ApiErrorResponse, "description": "Job not found."},
    },
)
async def get_job_status(job_id: str, request: Request):
    """Poll investigation job progress."""
    _require_user(request, ("viewer", "analyst", "admin"))
    job = get_job(job_id)
    if not job:
        raise HTTPException(404, f"Job not found: {job_id}")
    job.update(_job_case_availability(job.get("case_name", "")))
    return job


@app.post(
    "/api/jobs/delete",
    tags=["Jobs"],
    summary="Delete Jobs",
    description="Delete selected completed/failed jobs while keeping case artifacts intact.",
    response_model=JobsDeleteResponse,
)
async def delete_jobs_bulk(request: Request, body: JobDeleteRequest):
    """Delete selected historical jobs from the jobs store.

    This only removes job records and any lingering upload staging path.
    Case artifacts remain untouched.
    """
    actor = _require_user(request, ("analyst", "admin"))
    requested_ids = [str(job_id or "").strip() for job_id in (body.job_ids or []) if str(job_id or "").strip()]
    if not requested_ids:
        raise HTTPException(400, "Provide at least one job_id to delete")

    deleted: List[str] = []
    skipped: List[Dict[str, str]] = []
    for job_id in requested_ids[:200]:
        job = get_job(job_id)
        if not job:
            skipped.append({"job_id": job_id, "reason": "not_found"})
            continue
        if job.get("status") in {"queued", "running"}:
            skipped.append({"job_id": job_id, "reason": "active_job"})
            continue
        upload_path = str(job.get("upload_path") or "").strip()
        if upload_path and os.path.isdir(upload_path):
            shutil.rmtree(upload_path, ignore_errors=True)
        if delete_job(job_id):
            deleted.append(job_id)
        else:
            skipped.append({"job_id": job_id, "reason": "delete_failed"})

    record_audit_event(
        actor_username=actor["username"],
        action="delete_jobs",
        details={
            "deleted_count": len(deleted),
            "deleted_job_ids": deleted[:50],
            "skipped": skipped[:50],
        },
    )
    return {"deleted": deleted, "skipped": skipped}


# ---------------------------------------------------------------------------
# API: Reviews
# ---------------------------------------------------------------------------

class ReviewUpdate(BaseModel):
    status: Optional[str] = None
    disposition: Optional[str] = None
    owner: Optional[str] = None
    priority: Optional[str] = None
    recommended_tuning_action: Optional[str] = None
    changed_by: str = ""


class NoteCreate(BaseModel):
    content: str
    author: str = ""


def _require_case(case_name: str) -> str:
    """Resolve a case name to its path, raising 404 if not found."""
    try:
        return resolve_case_path(CASES_ROOT, case_name)
    except FileNotFoundError:
        raise HTTPException(404, f"Case not found: {case_name}")


@app.get(
    "/api/cases/{case_name}/findings/{finding_id}/review",
    tags=["Reviews"],
    summary="Get Finding Review",
    description="Return review state, notes, and change history for a specific finding id.",
    response_model=ReviewRecordResponse,
)
async def get_finding_review_endpoint(case_name: str, finding_id: str, request: Request):
    """Fetch review state, notes, and history for a finding."""
    user = _require_user(request, ("viewer", "analyst", "admin"))
    resolved_case = os.path.basename(_require_case(case_name))
    review = get_finding_review(resolved_case, finding_id)
    _audit_case_access(user, case_name=resolved_case, endpoint="/api/cases/{case_name}/findings/{finding_id}/review")
    if not review:
        return {"case_name": resolved_case, "finding_id": finding_id, "status": "Open",
                "disposition": "", "owner": "", "priority": "",
                "recommended_tuning_action": "", "notes": [], "history": []}
    review["notes"] = get_notes(resolved_case, "finding", finding_id)
    review["history"] = get_history(resolved_case, "finding", finding_id)
    return review


@app.get(
    "/api/cases/{case_name}/incidents/{incident_id}/review",
    tags=["Reviews"],
    summary="Get Incident Review",
    description="Return review state, notes, and change history for a specific incident id.",
    response_model=ReviewRecordResponse,
)
async def get_incident_review_endpoint(case_name: str, incident_id: str, request: Request):
    """Fetch review state, notes, and history for an incident."""
    user = _require_user(request, ("viewer", "analyst", "admin"))
    resolved_case = os.path.basename(_require_case(case_name))
    review = get_incident_review(resolved_case, incident_id)
    _audit_case_access(user, case_name=resolved_case, endpoint="/api/cases/{case_name}/incidents/{incident_id}/review")
    if not review:
        return {"case_name": resolved_case, "incident_id": incident_id, "status": "Open",
                "disposition": "", "owner": "", "priority": "",
                "recommended_tuning_action": "", "notes": [], "history": []}
    review["notes"] = get_notes(resolved_case, "incident", incident_id)
    review["history"] = get_history(resolved_case, "incident", incident_id)
    return review


@app.patch(
    "/api/cases/{case_name}/findings/{finding_id}/review",
    tags=["Reviews"],
    summary="Update Finding Review",
    description="Update review workflow status, owner, priority, and disposition for a finding.",
    response_model=ReviewRecordResponse,
)
async def update_finding_review_endpoint(case_name: str, finding_id: str, body: ReviewUpdate, request: Request):
    """Update workflow metadata for a finding review record."""
    user = _require_user(request, ("analyst", "admin"))
    resolved_case = os.path.basename(_require_case(case_name))
    if body.status and body.status not in VALID_STATUSES:
        raise HTTPException(400, f"Invalid status. Must be one of: {', '.join(VALID_STATUSES)}")
    if body.disposition and body.disposition not in VALID_DISPOSITIONS:
        raise HTTPException(400, f"Invalid disposition. Must be one of: {', '.join(VALID_DISPOSITIONS)}")
    # Attribution is security-sensitive audit data. Never trust a caller-
    # supplied display value when an authenticated identity is available.
    changed_by = user["username"]
    review = upsert_finding_review(
        resolved_case, finding_id,
        status=body.status, disposition=body.disposition,
        owner=body.owner, priority=body.priority,
        recommended_tuning_action=body.recommended_tuning_action,
        changed_by=changed_by,
    )
    details: Dict[str, Any] = {"case_name": resolved_case, "item_type": "finding", "item_id": finding_id, "changed_by": changed_by}
    changes = {
        "status": body.status,
        "disposition": body.disposition,
        "owner": body.owner,
        "priority": body.priority,
        "recommended_tuning_action": body.recommended_tuning_action,
    }
    details["changes"] = {k: v for k, v in changes.items() if v is not None}
    record_audit_event(
        actor_username=user["username"],
        action="update_review",
        target_username=resolved_case,
        details=details,
    )
    return review


@app.patch(
    "/api/cases/{case_name}/incidents/{incident_id}/review",
    tags=["Reviews"],
    summary="Update Incident Review",
    description="Update review workflow status, owner, priority, and disposition for an incident.",
    response_model=ReviewRecordResponse,
)
async def update_incident_review_endpoint(case_name: str, incident_id: str, body: ReviewUpdate, request: Request):
    """Update workflow metadata for an incident review record."""
    user = _require_user(request, ("analyst", "admin"))
    resolved_case = os.path.basename(_require_case(case_name))
    if body.status and body.status not in VALID_STATUSES:
        raise HTTPException(400, f"Invalid status. Must be one of: {', '.join(VALID_STATUSES)}")
    if body.disposition and body.disposition not in VALID_DISPOSITIONS:
        raise HTTPException(400, f"Invalid disposition. Must be one of: {', '.join(VALID_DISPOSITIONS)}")
    changed_by = user["username"]
    review = upsert_incident_review(
        resolved_case, incident_id,
        status=body.status, disposition=body.disposition,
        owner=body.owner, priority=body.priority,
        recommended_tuning_action=body.recommended_tuning_action,
        changed_by=changed_by,
    )
    details: Dict[str, Any] = {"case_name": resolved_case, "item_type": "incident", "item_id": incident_id, "changed_by": changed_by}
    changes = {
        "status": body.status,
        "disposition": body.disposition,
        "owner": body.owner,
        "priority": body.priority,
        "recommended_tuning_action": body.recommended_tuning_action,
    }
    details["changes"] = {k: v for k, v in changes.items() if v is not None}
    record_audit_event(
        actor_username=user["username"],
        action="update_review",
        target_username=resolved_case,
        details=details,
    )
    return review


@app.post(
    "/api/cases/{case_name}/findings/{finding_id}/notes",
    tags=["Reviews"],
    summary="Add Finding Note",
    description="Append analyst note to a finding review timeline.",
    response_model=ReviewNoteResponse,
    responses={
        200: {
            "description": "Created note record.",
            "content": {
                "application/json": {
                    "example": {
                        "id": 41,
                        "case_name": "case-20260316-1730",
                        "item_type": "finding",
                        "item_id": "fnd-0",
                        "author": "analyst-1",
                        "content": "Needs escalation due to repeated execution path.",
                        "created_at": "2026-03-16T17:35:00+00:00",
                    }
                }
            },
        },
        400: {"model": ApiErrorResponse, "description": "Invalid or empty note content."},
    },
)
async def add_finding_note(case_name: str, finding_id: str, body: NoteCreate, request: Request):
    """Add an analyst note to a finding review timeline."""
    user = _require_user(request, ("analyst", "admin"))
    resolved_case = os.path.basename(_require_case(case_name))
    if not body.content.strip():
        raise HTTPException(400, "Note content cannot be empty")
    author = user["username"]
    note = add_note(resolved_case, "finding", finding_id, body.content.strip(), author)
    record_audit_event(
        actor_username=user["username"],
        action="add_review_note",
        target_username=resolved_case,
        details={
            "case_name": resolved_case,
            "item_type": "finding",
            "item_id": finding_id,
            "note_id": note.get("id", ""),
            "author": author,
            "content_length": len(body.content.strip()),
        },
    )
    return note


@app.post(
    "/api/cases/{case_name}/incidents/{incident_id}/notes",
    tags=["Reviews"],
    summary="Add Incident Note",
    description="Append analyst note to an incident review timeline.",
    response_model=ReviewNoteResponse,
    responses={400: {"model": ApiErrorResponse, "description": "Invalid or empty note content."}},
)
async def add_incident_note(case_name: str, incident_id: str, body: NoteCreate, request: Request):
    """Add an analyst note to an incident review timeline."""
    user = _require_user(request, ("analyst", "admin"))
    resolved_case = os.path.basename(_require_case(case_name))
    if not body.content.strip():
        raise HTTPException(400, "Note content cannot be empty")
    author = user["username"]
    note = add_note(resolved_case, "incident", incident_id, body.content.strip(), author)
    record_audit_event(
        actor_username=user["username"],
        action="add_review_note",
        target_username=resolved_case,
        details={
            "case_name": resolved_case,
            "item_type": "incident",
            "item_id": incident_id,
            "note_id": note.get("id", ""),
            "author": author,
            "content_length": len(body.content.strip()),
        },
    )
    return note


@app.get(
    "/api/review/queue",
    tags=["Reviews"],
    summary="Get Review Queue",
    description="Return review queue items with optional workflow filters.",
    response_model=List[ReviewQueueItemResponse],
    responses={
        200: {
            "description": "Filtered review queue rows.",
            "content": {
                "application/json": {
                    "example": [
                        {
                            "case_name": "case-20260316-1730",
                            "item_type": "incident",
                            "item_id": "inc-0",
                            "item_title": "Credential Access Chain",
                            "response_priority": "P1",
                            "last_seen_at": "2026-03-16T17:31:19+00:00",
                            "status": "Open",
                            "disposition": "",
                            "owner": "",
                            "priority": "P1",
                            "updated_at": "2026-03-16T17:31:19+00:00",
                        }
                    ]
                }
            },
        }
    },
)
async def review_queue(
    request: Request,
    status: Optional[str] = Query(None),
    disposition: Optional[str] = Query(None),
    owner: Optional[str] = Query(None),
    priority: Optional[str] = Query(None),
    case_name: Optional[str] = Query(None),
    item_type: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=1000),
):
    """List queue items with optional status/owner/priority filters."""
    _require_user(request, ("viewer", "analyst", "admin"))
    _sync_queue_index_if_stale()
    return apply_demo_redaction_data(get_review_queue(
        status=status, disposition=disposition, owner=owner,
        priority=priority, case_name=case_name, item_type=item_type,
        limit=limit,
    ))


@app.get(
    "/api/review/queue/export",
    tags=["Reviews"],
    summary="Export Review Queue",
    description="Export filtered review queue rows as CSV attachment.",
    responses={
        200: {"description": "CSV attachment for review queue export."},
        400: {"model": ApiErrorResponse, "description": "Unsupported export format."},
    },
)
async def review_queue_export(
    request: Request,
    status: Optional[str] = Query(None),
    disposition: Optional[str] = Query(None),
    owner: Optional[str] = Query(None),
    priority: Optional[str] = Query(None),
    case_name: Optional[str] = Query(None),
    item_type: Optional[str] = Query(None),
    limit: int = Query(5000, ge=1, le=10000),
    format: str = Query("csv"),
):
    """Export review queue rows using current filter constraints."""
    user = _require_user(request, ("viewer", "analyst", "admin"))
    export_format = (format or "csv").strip().lower()
    if export_format != "csv":
        raise HTTPException(400, "Export format must be csv")
    _sync_queue_index_if_stale()
    rows = get_review_queue(
        status=status,
        disposition=disposition,
        owner=owner,
        priority=priority,
        case_name=case_name,
        item_type=item_type,
        limit=limit,
    )
    rows = apply_demo_redaction_data(rows)
    record_audit_event(
        actor_username=user["username"],
        action="export_review_queue",
        details={
            "format": export_format,
            "status": status or "",
            "disposition": disposition or "",
            "owner": owner or "",
            "priority": priority or "",
            "case_name": case_name or "",
            "item_type": item_type or "",
            "limit": limit,
            "row_count": len(rows),
        },
    )
    filename = _safe_download_filename("triage-review-queue", "csv")
    return _csv_attachment(rows, fieldnames=REVIEW_QUEUE_EXPORT_FIELDNAMES, filename=filename)


@app.get(
    "/api/review/history",
    tags=["Reviews"],
    summary="Get Review History",
    description="Return review change history records with optional filter criteria.",
    response_model=List[ReviewHistoryItemResponse],
)
async def review_history(
    request: Request,
    case_name: Optional[str] = Query(None),
    item_type: str = Query(""),
    item_id: str = Query(""),
    changed_by: str = Query(""),
    field: str = Query(""),
    search: str = Query(""),
    limit: int = Query(200, ge=1, le=1000),
):
    """List review history events across findings and incidents."""
    _require_user(request, ("viewer", "analyst", "admin"))
    if case_name:
        _require_case(case_name)
    return get_all_history(
        limit=limit,
        case_name=(case_name or "").strip(),
        item_type=item_type.strip(),
        item_id=item_id.strip(),
        changed_by=changed_by.strip(),
        field=field.strip(),
        search=search.strip(),
    )


@app.get(
    "/api/review/history/export",
    tags=["Reviews"],
    summary="Export Review History",
    description="Export review history records as CSV or JSON attachment.",
)
async def review_history_export(
    request: Request,
    case_name: str = Query(""),
    item_type: str = Query(""),
    item_id: str = Query(""),
    changed_by: str = Query(""),
    field: str = Query(""),
    search: str = Query(""),
    limit: int = Query(500, ge=1, le=5000),
    format: str = Query("csv"),
):
    """Export filtered review history records as CSV or JSON."""
    user = _require_user(request, ("viewer", "analyst", "admin"))
    normalized_case = case_name.strip()
    if normalized_case:
        _require_case(normalized_case)
    rows = get_all_history(
        limit=limit,
        case_name=normalized_case,
        item_type=item_type.strip(),
        item_id=item_id.strip(),
        changed_by=changed_by.strip(),
        field=field.strip(),
        search=search.strip(),
    )
    export_format = (format or "csv").strip().lower()
    record_audit_event(
        actor_username=user["username"],
        action="export_review_history",
        details={
            "format": export_format,
            "limit": limit,
            "case_name": normalized_case,
            "item_type": item_type.strip(),
            "item_id": item_id.strip(),
            "changed_by": changed_by.strip(),
            "field": field.strip(),
            "search": search.strip(),
        },
    )
    if export_format == "json":
        return Response(
            content=json.dumps({"history": rows}, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=triage-review-history.json"},
        )
    if export_format != "csv":
        raise HTTPException(400, "Export format must be csv or json")
    buf = io.StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=["id", "case_name", "item_type", "item_id", "field", "old_value", "new_value", "changed_by", "changed_at"],
    )
    writer.writeheader()
    for row in rows:
        writer.writerow({
            "id": row.get("id", ""),
            "case_name": row.get("case_name", ""),
            "item_type": row.get("item_type", ""),
            "item_id": row.get("item_id", ""),
            "field": row.get("field", ""),
            "old_value": row.get("old_value", ""),
            "new_value": row.get("new_value", ""),
            "changed_by": row.get("changed_by", ""),
            "changed_at": row.get("changed_at", ""),
        })
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=triage-review-history.csv"},
    )


@app.post(
    "/api/cases/{case_name}/reviews/carry-forward",
    tags=["Reviews"],
    summary="Carry Forward Reviews",
    description="Ensure review records exist for current findings/incidents in a rerun case.",
    response_model=CarryForwardResponse,
    responses={
        200: {
            "description": "Carry-forward record counts.",
            "content": {
                "application/json": {
                    "example": {
                        "case_name": "case-20260316-1730",
                        "findings_carried": 5,
                        "findings_created": 1,
                        "incidents_carried": 1,
                        "incidents_created": 0,
                    }
                }
            },
        }
    },
)
async def carry_forward(case_name: str, request: Request):
    """Carry forward review state for a case after rerun.

    Reads current findings/incidents from findings.json and ensures
    review records exist for each stable ID.
    """
    _require_user(request, ("analyst", "admin"))
    try:
        case_path = resolve_case_path(CASES_ROOT, case_name)
    except FileNotFoundError:
        raise HTTPException(404, f"Case not found: {case_name}")
    findings_path = os.path.join(case_path, "findings.json")
    if not os.path.isfile(findings_path):
        raise HTTPException(404, "findings.json not found for this case")
    with open(findings_path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    finding_ids = [f["id"] for f in data.get("findings", []) if f.get("id")]
    incident_ids = [i["id"] for i in data.get("incidents", []) if i.get("id")]
    resolved_name = os.path.basename(case_path)
    return carry_forward_reviews(resolved_name, finding_ids, incident_ids)


@app.get(
    "/api/review/enums",
    tags=["Reviews"],
    summary="Get Review Enumerations",
    description="Return allowed status and disposition values used by review workflows.",
    response_model=ReviewEnumsResponse,
)
async def review_enums(request: Request):
    """Return allowed status and disposition values for the review UI."""
    _require_user(request, ("viewer", "analyst", "admin"))
    return {"statuses": list(VALID_STATUSES), "dispositions": list(VALID_DISPOSITIONS)}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
# Evidence explorer and evidence-link review routes live in their own module.
app.include_router(build_forensics_router(
    require_user=_require_user, require_case=_require_case, audit_case_access=_audit_case_access,
    record_audit_event=record_audit_event, redact=apply_demo_redaction_data,
))

if __name__ == "__main__":
    multiprocessing.freeze_support()
    import argparse

    parser = argparse.ArgumentParser(description="Triage Engine API Server")
    parser.add_argument("--host", default=SERVER_HOST, help=f"Bind address (default: {SERVER_HOST})")
    parser.add_argument("--port", type=int, default=SERVER_PORT, help=f"Port (default: {SERVER_PORT})")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload for development")
    args = parser.parse_args()

    try:
        _validate_startup_or_raise()
    except RuntimeError:
        raise SystemExit(1)

    SERVER_LOGGER.info(
        "server_starting",
        extra={
            "version": __version__,
            "host": args.host,
            "port": int(args.port),
            "reload": bool(args.reload),
            "url": f"http://{args.host}:{args.port}",
            "runtime_mode": RUNTIME_MODE,
            "runtime_label": RUNTIME_LABEL,
        },
    )

    # Pass the loaded ASGI object directly so frozen PyInstaller builds do not
    # depend on importing a source module named ``server`` from disk.
    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info",
    )
