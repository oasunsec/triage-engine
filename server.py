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
from contextlib import asynccontextmanager
import csv
import hashlib
import hmac
import io
import json
import logging
import os
import re
import secrets
import shutil
import sqlite3
import sys
import time
import uuid
from datetime import datetime, timezone
from sqlite3 import IntegrityError
from threading import Lock, Thread
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Path bootstrap
# ---------------------------------------------------------------------------
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from fastapi import FastAPI, File, HTTPException, Query, Request, Response, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
import uvicorn

from triage_engine import __version__
from triage_engine.case_utils import resolve_case_path
from triage_engine.export_sanitizer import apply_demo_redaction_data, apply_demo_redaction_text
from triage_engine.logging_config import configure_logging
from triage_engine.service import InvestigationRequest, ProgressReporter, run_investigation
from triage_engine.webhooks import dispatch_webhook_event
from triage_engine.job_store import (
    create_job,
    update_job,
    get_job,
    list_jobs as db_list_jobs,
    delete_job,
    get_jobs_with_uploads,
    clear_upload_path,
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
DEFAULT_MAX_UPLOAD_MB = 500
DEFAULT_RUNTIME_MODE = "local"


def _resolve_runtime_dir(env_name: str, default_relative: str) -> str:
    configured = str(os.environ.get(env_name, "") or "").strip()
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
UPLOAD_ROOT = os.path.join(ROOT_DIR, "uploads")
STATIC_DIR = os.path.join(ROOT_DIR, "static")
BACKUPS_ROOT = os.path.join(DATA_ROOT, "backups")
WEBHOOK_CONFIG_PATH = os.path.join(ROOT_DIR, "config", "webhooks.json")
os.makedirs(DATA_ROOT, exist_ok=True)
os.makedirs(CASES_ROOT, exist_ok=True)
os.makedirs(UPLOAD_ROOT, exist_ok=True)

# Max upload size per file: configurable via TRIAGE_MAX_UPLOAD_MB (default 500 MB)
MAX_UPLOAD_MB = _env_int("TRIAGE_MAX_UPLOAD_MB", default=DEFAULT_MAX_UPLOAD_MB, minimum=1)
MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024
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
_CURRENT_USER_UNSET = object()
_SERVER_STARTED_AT = time.monotonic()
STARTUP_DISK_HARD_MIN_BYTES = 100 * 1024 * 1024
STARTUP_DISK_WARN_BYTES = 1024 * 1024 * 1024
CORS_ORIGINS = _cors_origins_from_env(
    os.environ.get("TRIAGE_CORS_ORIGINS", DEFAULT_CORS_ORIGINS),
    default_port=SERVER_PORT,
)
RUNTIME_MODE = _runtime_mode_from_env(os.environ.get("TRIAGE_RUNTIME_MODE", DEFAULT_RUNTIME_MODE))
RUNTIME_LABEL = "Docker" if RUNTIME_MODE == "docker" else "Local Python"

# Allowed path roots for local-path investigations (security: confine access)
ALLOWED_PATH_ROOTS: List[str] = []  # empty = allow any local path (localhost-only is safe)

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
    forwarded = (request.headers.get("x-forwarded-for", "") or "").split(",")[0].strip()
    if forwarded:
        return forwarded
    if request.client and request.client.host:
        return str(request.client.host)
    return "unknown"


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
        bucket = _RATE_LIMIT_BUCKETS.setdefault(key, deque())
        cutoff = now - RATE_LIMIT_WINDOW_SECONDS
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
    payload: Dict[str, Any] = {
        "case_name": result.case_name,
        "job_id": job_id,
        "requested_by": request.requested_by or "",
        "input_mode": request.input_mode,
        "input_source": request.input_source,
        "response_priority": str(getattr(result, "response_priority", "P4") or "P4"),
        "signal_count": int(getattr(result, "signal_count", 0) or 0),
        "finding_count": int(getattr(result, "finding_count", 0) or 0),
        "incident_count": int(getattr(result, "incident_count", 0) or 0),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if incident_ids:
        payload["incident_ids"] = [incident_id for incident_id in incident_ids if incident_id]

    completed_stats = dispatch_webhook_event(
        "investigation_completed",
        payload,
        root_dir=ROOT_DIR,
        config_path=WEBHOOK_CONFIG_PATH,
        logger=SERVER_LOGGER,
    )
    SERVER_LOGGER.info(
        "webhook_dispatch_result",
        extra={
            "request_id": request.request_id or "",
            "user": request.requested_by or "",
            "job_id": job_id,
            "case_name": result.case_name,
            "event": "investigation_completed",
            "attempted": int(completed_stats.get("attempted", 0)),
            "sent": int(completed_stats.get("sent", 0)),
            "failed": int(completed_stats.get("failed", 0)),
        },
    )

    response_priority = str(payload.get("response_priority", "P4")).upper()
    incident_count = int(payload.get("incident_count", 0))
    if incident_count > 0 and response_priority in {"P1", "P2"}:
        incident_event = f"incident_{response_priority.lower()}"
        incident_stats = dispatch_webhook_event(
            incident_event,
            payload,
            root_dir=ROOT_DIR,
            config_path=WEBHOOK_CONFIG_PATH,
            logger=SERVER_LOGGER,
        )
        SERVER_LOGGER.info(
            "webhook_dispatch_result",
            extra={
                "request_id": request.request_id or "",
                "user": request.requested_by or "",
                "job_id": job_id,
                "case_name": result.case_name,
                "event": incident_event,
                "attempted": int(incident_stats.get("attempted", 0)),
                "sent": int(incident_stats.get("sent", 0)),
                "failed": int(incident_stats.get("failed", 0)),
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


# ---------------------------------------------------------------------------
# Input validation helpers
# ---------------------------------------------------------------------------

_SAFE_CASE_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$")


def _validate_case_name(name: Optional[str]) -> Optional[str]:
    if name is None:
        return None
    name = name.strip()
    if not name:
        return None
    if not _SAFE_CASE_NAME_RE.match(name):
        raise HTTPException(400, "Case name must be 1-128 alphanumeric/dash/dot/underscore characters")
    return name


def _validate_evtx_path(path: str) -> str:
    """Ensure the path exists and is confined to allowed roots."""
    path = os.path.abspath(path)
    if not os.path.exists(path):
        raise HTTPException(400, "Path does not exist")
    # Only allow .evtx files or directories
    if os.path.isfile(path) and not path.lower().endswith(".evtx"):
        raise HTTPException(400, "File must have .evtx extension")
    # If allowed roots are configured, enforce them
    if ALLOWED_PATH_ROOTS:
        if not any(path.startswith(os.path.abspath(root)) for root in ALLOWED_PATH_ROOTS):
            raise HTTPException(403, "Path is outside allowed directories")
    return path


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
        lowered = message.lower()
        status = "error"
        if "access is denied" in lowered or "required privilege" in lowered or "not held by the client" in lowered:
            status = "access_denied"
        elif "could not be found" in lowered or "no matching logs found" in lowered or "not recognized as valid" in lowered:
            status = "not_found"
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
    return {
        "authenticated": bool(user),
        "bootstrap_required": not has_users(),
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
    username = _validate_username(body.username)
    password = _validate_password(body.password, username=username)
    user = bootstrap_admin(username, password)
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
# API: Cases
# ---------------------------------------------------------------------------
def _collect_case_summaries() -> List[Dict[str, Any]]:
    if not os.path.isdir(CASES_ROOT):
        return []
    cases: List[Dict[str, Any]] = []
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
            except Exception:
                pass

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
    payload = apply_demo_redaction_data(payload)
    resolved_name = os.path.basename(case_path)
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
    return FileResponse(path, media_type="text/html")


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
    shutil.rmtree(case_path, ignore_errors=True)
    delete_case_review_state(case_name)
    record_audit_event(
        actor_username=actor["username"],
        action="delete_case",
        target_username=case_name,
        details={"case_name": case_name},
    )
    return {"deleted": case_name}


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
):
    """Upload EVTX files and start an investigation in the background."""
    actor = _require_user(request, ("analyst", "admin"))
    request_id = _request_id_for_log(request)
    case_name = _validate_case_name(case_name)

    job_id = uuid.uuid4().hex[:12]
    upload_dir = os.path.join(UPLOAD_ROOT, job_id)
    os.makedirs(upload_dir, exist_ok=True)

    for f in files:
        filename = os.path.basename(f.filename or "upload.evtx")
        if not filename.lower().endswith(".evtx"):
            shutil.rmtree(upload_dir, ignore_errors=True)
            raise HTTPException(400, f"Only .evtx files are accepted, got: {filename}")
        content = await f.read()
        if len(content) > MAX_UPLOAD_BYTES:
            shutil.rmtree(upload_dir, ignore_errors=True)
            raise HTTPException(413, f"File too large: {filename} ({len(content)} bytes, max {MAX_UPLOAD_BYTES})")
        dest = os.path.join(upload_dir, filename)
        with open(dest, "wb") as out:
            out.write(content)

    uploaded = [os.path.join(upload_dir, n) for n in os.listdir(upload_dir)]
    evtx_path = uploaded[0] if len(uploaded) == 1 else upload_dir

    investigation_request = InvestigationRequest(
        input_source=evtx_path,
        input_mode="evtx_path",
        case_name=case_name,
        cases_dir=CASES_ROOT,
        enable_sigma=enable_sigma,
        request_id=request_id,
        requested_by=actor["username"],
    )

    from triage_engine.case_utils import auto_case_name as _auto_name
    resolved_name = case_name or _auto_name(evtx_path, False, "")
    create_job(job_id, case_name=resolved_name, upload_path=upload_dir)
    record_audit_event(
        actor_username=actor["username"],
        action="start_investigation_upload",
        target_username=resolved_name,
        details={"job_id": job_id, "file_count": len(uploaded), "enable_sigma": enable_sigma},
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
    thread = Thread(target=_investigate_worker, args=(job_id, investigation_request, upload_dir), daemon=True)
    thread.start()

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
):
    """Start investigation using a local file path (no upload needed)."""
    actor = _require_user(request, ("analyst", "admin"))
    request_id = _request_id_for_log(request)
    evtx_path = _validate_evtx_path(evtx_path)
    case_name = _validate_case_name(case_name)

    job_id = uuid.uuid4().hex[:12]

    investigation_request = InvestigationRequest(
        input_source=evtx_path,
        input_mode="evtx_path",
        case_name=case_name,
        cases_dir=CASES_ROOT,
        enable_sigma=enable_sigma,
        request_id=request_id,
        requested_by=actor["username"],
    )

    from triage_engine.case_utils import auto_case_name as _auto_name
    resolved_name = case_name or _auto_name(evtx_path, False, "")
    create_job(job_id, case_name=resolved_name)
    record_audit_event(
        actor_username=actor["username"],
        action="start_investigation_path",
        target_username=resolved_name,
        details={"job_id": job_id, "input_path": evtx_path, "enable_sigma": enable_sigma},
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
    thread = Thread(target=_investigate_worker, args=(job_id, investigation_request, None), daemon=True)
    thread.start()

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
    thread = Thread(target=_investigate_worker, args=(job_id, live_request, None), daemon=True)
    thread.start()

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
    review = get_finding_review(case_name, finding_id)
    _audit_case_access(user, case_name=resolved_case, endpoint="/api/cases/{case_name}/findings/{finding_id}/review")
    if not review:
        return {"case_name": case_name, "finding_id": finding_id, "status": "Open",
                "disposition": "", "owner": "", "priority": "",
                "recommended_tuning_action": "", "notes": [], "history": []}
    review["notes"] = get_notes(case_name, "finding", finding_id)
    review["history"] = get_history(case_name, "finding", finding_id)
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
    review = get_incident_review(case_name, incident_id)
    _audit_case_access(user, case_name=resolved_case, endpoint="/api/cases/{case_name}/incidents/{incident_id}/review")
    if not review:
        return {"case_name": case_name, "incident_id": incident_id, "status": "Open",
                "disposition": "", "owner": "", "priority": "",
                "recommended_tuning_action": "", "notes": [], "history": []}
    review["notes"] = get_notes(case_name, "incident", incident_id)
    review["history"] = get_history(case_name, "incident", incident_id)
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
    changed_by = body.changed_by or user["username"]
    review = upsert_finding_review(
        case_name, finding_id,
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
    changed_by = body.changed_by or user["username"]
    review = upsert_incident_review(
        case_name, incident_id,
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
    author = body.author or user["username"]
    note = add_note(case_name, "finding", finding_id, body.content.strip(), author)
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
    author = body.author or user["username"]
    note = add_note(case_name, "incident", incident_id, body.content.strip(), author)
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
if __name__ == "__main__":
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

    uvicorn.run(
        "server:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info",
    )
