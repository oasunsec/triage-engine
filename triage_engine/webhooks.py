"""Bounded, best-effort webhook delivery for investigation and export events."""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional
from urllib import error as urllib_error
from urllib.parse import urlsplit
from urllib import request as urllib_request


DEFAULT_TIMEOUT_SECONDS = 5
MAX_CONFIGURED_TIMEOUT_SECONDS = 30
DEFAULT_CONFIG_RELATIVE_PATH = os.path.join("config", "webhooks.json")
WEBHOOK_SCHEMA_VERSION = "1.0"
DEFAULT_MAX_ATTEMPTS = 1
MAX_CONFIGURED_ATTEMPTS = 5
DEFAULT_RETRY_DELAY_SECONDS = 0
MAX_CONFIGURED_RETRY_DELAY_SECONDS = 30
MAX_TOTAL_RETRY_DELAY_SECONDS = 15
MAX_TOTAL_WEBHOOK_DISPATCH_SECONDS = 45
EVENT_ALIASES = {
    "case.completed": {"investigation_completed"},
    "case.escalated": {"incident_p1", "incident_p2"},
    "bundle.exported": {"case_bundle_exported"},
}
RESERVED_WEBHOOK_HEADERS = {
    "Content-Type",
    "User-Agent",
    "X-Triage-Event",
    "X-Triage-Event-ID",
    "X-Triage-Schema-Version",
}
_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+\-.^_\x60|~]+$")


def _coerce_headers(value: Any) -> Dict[str, str]:
    if not isinstance(value, dict):
        return {}
    output: Dict[str, str] = {}
    for key, raw in value.items():
        k = str(key or "").strip()
        raw_value = str(raw if raw is not None else "")
        if (
            not k
            or not _HEADER_NAME_RE.fullmatch(k)
            or any(ord(char) < 0x20 or ord(char) == 0x7F for char in raw_value)
        ):
            continue
        output[k] = raw_value
    return output


def _normalize_webhook_url(value: Any) -> str:
    """Return a safe absolute http(s) URL or an empty string when invalid."""
    raw = str(value or "").strip()
    if not raw:
        return ""
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in raw):
        return ""
    try:
        parsed = urlsplit(raw)
        # Accessing ``port`` validates the numeric range and can raise for
        # malformed or out-of-range ports; treat those as invalid entries too.
        parsed.port
    except ValueError:
        # urlsplit() can reject malformed IPv6 literals. Treat them as invalid
        # configuration entries instead of crashing every webhook dispatch.
        return ""
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ""
    if parsed.username is not None or parsed.password is not None:
        return ""
    return raw


def resolve_webhook_config_path(root_dir: str, config_path: Optional[str] = None) -> str:
    """Resolve the endpoint config path, honoring the documented env override.

    Explicit API callers take precedence, then ``TRIAGE_WEBHOOK_CONFIG``, then
    the repository default. Relative paths resolve against ``root_dir`` so a
    packaged or portable deployment keeps a consistent, contained location.
    """
    configured = str(
        config_path or os.environ.get("TRIAGE_WEBHOOK_CONFIG", "").strip()
    ).strip()
    if not configured:
        return os.path.abspath(os.path.join(root_dir, DEFAULT_CONFIG_RELATIVE_PATH))
    expanded = os.path.expanduser(configured)
    if os.path.isabs(expanded):
        return os.path.abspath(expanded)
    return os.path.abspath(os.path.join(os.path.abspath(root_dir), expanded))


def _coerce_events(value: Any) -> List[str]:
    if not isinstance(value, list):
        return []
    events = []
    for item in value:
        name = str(item or "").strip()
        if name:
            events.append(name)
    return events


def _coerce_timeout(value: Any) -> int:
    try:
        timeout = int(value)
    except (TypeError, ValueError, OverflowError):
        return DEFAULT_TIMEOUT_SECONDS
    # ``int()`` already rejects non-finite floats and NaN; avoid converting a
    # valid but astronomically large integer to float, which can overflow and
    # crash configuration loading. Clamping first keeps the bounded contract.
    if timeout < 1:
        return DEFAULT_TIMEOUT_SECONDS
    return min(MAX_CONFIGURED_TIMEOUT_SECONDS, timeout)


def _coerce_retries(value: Any) -> int:
    """Normalize a configured retry count to a bounded positive value."""
    try:
        attempts = int(value)
    except (TypeError, ValueError, OverflowError):
        return DEFAULT_MAX_ATTEMPTS
    return max(1, min(MAX_CONFIGURED_ATTEMPTS, attempts))


def _coerce_retry_delay(value: Any) -> float:
    try:
        delay = float(value)
    except (TypeError, ValueError, OverflowError):
        return DEFAULT_RETRY_DELAY_SECONDS
    if delay < 0 or not math.isfinite(delay):
        return DEFAULT_RETRY_DELAY_SECONDS
    return min(MAX_CONFIGURED_RETRY_DELAY_SECONDS, delay)


def _normalize_retry_delay(value: Any, max_attempts: int) -> float:
    """Keep total sleep across one endpoint bounded so webhooks never stall jobs."""
    delay = _coerce_retry_delay(value)
    if max_attempts <= 1 or delay <= 0:
        return 0
    sleep_slots = max(1, max_attempts - 1)
    return min(delay, MAX_TOTAL_RETRY_DELAY_SECONDS / sleep_slots)


def _sanitize_identifier(value: str, *, fallback: str) -> str:
    """Return a deterministic header-safe identifier component."""
    text = str(value or "").strip()
    if text and all(ord(char) >= 0x20 and ord(char) != 0x7F for char in text):
        return text
    digest = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:16]
    return f"{fallback}-{digest}"


def build_event_id(event: str, payload: Dict[str, Any]) -> str:
    """Return a stable identifier consumers can use for idempotency."""
    supplied = str(payload.get("event_id") or "").strip()
    if supplied:
        return _sanitize_identifier(supplied, fallback=event)
    case_name = str(payload.get("case_name") or payload.get("case_id") or "").strip()
    job_id = str(payload.get("job_id") or "").strip()
    safe_event = _sanitize_identifier(event, fallback="event")
    safe_case = _sanitize_identifier(case_name, fallback="case") if case_name else ""
    safe_job = _sanitize_identifier(job_id, fallback="job") if job_id else ""
    if case_name and job_id:
        return f"{safe_case}:{safe_job}:{safe_event}"
    if case_name:
        return f"{safe_case}:{safe_event}"
    return f"{safe_event}:{uuid.uuid4().hex}"


def matches_event(event: str, subscribed_events: Iterable[str], payload: Dict[str, Any]) -> bool:
    """Match canonical events while honoring legacy subscriptions without duplicates."""
    subscribed = set(subscribed_events)
    if event in subscribed:
        return True
    if event not in EVENT_ALIASES:
        return False
    priority = str(payload.get("response_priority") or "").upper()
    for alias in EVENT_ALIASES[event]:
        if alias not in subscribed:
            continue
        if event == "case.escalated" and alias == "incident_p1" and priority != "P1":
            continue
        if event == "case.escalated" and alias == "incident_p2" and priority != "P2":
            continue
        return True
    return False


def _post_once(
    req: Any,
    timeout_seconds: int,
    active_logger: logging.Logger,
    event: str,
    url: str,
    config_path: str,
) -> bool:
    """Deliver one attempt and report whether the endpoint accepted it."""
    try:
        with urllib_request.urlopen(req, timeout=timeout_seconds) as response:  # noqa: S310
            status = int(getattr(response, "status", 0) or response.getcode() or 0)
    except (urllib_error.HTTPError, urllib_error.URLError, TimeoutError, ValueError) as exc:
        active_logger.warning(
            "webhook_delivery_failed",
            extra={"event": event, "url": url, "error": str(exc), "config_path": config_path},
        )
        return False
    except Exception as exc:  # pragma: no cover - defensive best-effort guard
        active_logger.warning(
            "webhook_delivery_failed",
            extra={"event": event, "url": url, "error": str(exc), "config_path": config_path},
        )
        return False
    if status >= 400:
        active_logger.warning(
            "webhook_delivery_failed",
            extra={"event": event, "url": url, "status": status, "config_path": config_path},
        )
        return False
    return True


def load_webhook_endpoints(
    root_dir: str,
    *,
    config_path: Optional[str] = None,
) -> tuple[List[Dict[str, Any]], List[str], str]:
    """Load configured endpoints from JSON; invalid entries are skipped."""
    resolved_path = resolve_webhook_config_path(root_dir, config_path=config_path)
    diagnostics: List[str] = []
    endpoints: List[Dict[str, Any]] = []

    if not os.path.isfile(resolved_path):
        return endpoints, diagnostics, resolved_path

    try:
        with open(resolved_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except Exception as exc:
        diagnostics.append(f"Failed to load webhook config {resolved_path}: {exc}")
        return endpoints, diagnostics, resolved_path

    if not isinstance(payload, dict):
        diagnostics.append(f"Webhook config {resolved_path} must contain an object")
        return endpoints, diagnostics, resolved_path

    items = payload.get("endpoints", [])
    if not isinstance(items, list):
        diagnostics.append(f"Webhook config {resolved_path} must define endpoints as a list")
        return endpoints, diagnostics, resolved_path

    for idx, item in enumerate(items):
        if not isinstance(item, dict):
            diagnostics.append(f"endpoints[{idx}] must be an object")
            continue
        raw_url = str(item.get("url") or "").strip()
        url = _normalize_webhook_url(raw_url)
        if not url:
            diagnostics.append(f"endpoints[{idx}] invalid or missing required field 'url'")
            continue
        events = _coerce_events(item.get("events", []))
        if not events:
            diagnostics.append(f"endpoints[{idx}] has no subscribed events")
            continue
        max_attempts = _coerce_retries(item.get("max_attempts", DEFAULT_MAX_ATTEMPTS))
        endpoints.append(
            {
                "url": url,
                "events": events,
                "headers": _coerce_headers(item.get("headers", {})),
                "timeout_seconds": _coerce_timeout(item.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)),
                "max_attempts": max_attempts,
                "retry_delay_seconds": _normalize_retry_delay(
                    item.get("retry_delay_seconds", DEFAULT_RETRY_DELAY_SECONDS),
                    max_attempts,
                ),
            }
        )
    return endpoints, diagnostics, resolved_path


def dispatch_webhook_event(
    event: str,
    payload: Dict[str, Any],
    *,
    root_dir: str,
    config_path: Optional[str] = None,
    logger: Optional[logging.Logger] = None,
) -> Dict[str, Any]:
    """Send a webhook event to subscribed endpoints with bounded retries.

    Delivery is best-effort: an unavailable endpoint is logged and never
    changes the investigation result. Per-endpoint retries are bounded by the
    normalized configuration (at most five attempts and fifteen seconds of
    total backoff), so a misconfigured integration cannot stall a job.
    """
    endpoints, diagnostics, resolved_path = load_webhook_endpoints(root_dir, config_path=config_path)
    active_logger = logger or logging.getLogger("triage.webhooks")

    for message in diagnostics:
        active_logger.warning(
            "webhook_config_warning",
            extra={"event": event, "config_path": resolved_path, "warning": message},
        )

    envelope = dict(payload or {})
    envelope["event"] = event
    envelope["schema_version"] = str(envelope.get("schema_version") or WEBHOOK_SCHEMA_VERSION)
    envelope["event_id"] = build_event_id(event, envelope)
    envelope.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
    encoded = json.dumps(envelope).encode("utf-8")

    attempted = 0
    sent = 0
    failed = 0
    skipped = 0
    total_sleep_seconds = 0.0
    deadline = time.monotonic() + MAX_TOTAL_WEBHOOK_DISPATCH_SECONDS
    for endpoint in endpoints:
        if not matches_event(event, endpoint.get("events", []), envelope):
            continue
        if time.monotonic() >= deadline:
            skipped += 1
            active_logger.warning(
                "webhook_dispatch_budget_expired",
                extra={"event": event, "url": endpoint["url"], "config_path": resolved_path},
            )
            continue
        attempted += 1
        headers = dict(endpoint.get("headers", {}))
        reserved_lower = {name.lower() for name in RESERVED_WEBHOOK_HEADERS}
        for name in list(headers):
            if name.lower() in reserved_lower:
                del headers[name]
        headers.update({
            "Content-Type": "application/json",
            "User-Agent": "triage-engine-webhook/1.0",
            "X-Triage-Event": event,
            "X-Triage-Event-ID": envelope["event_id"],
            "X-Triage-Schema-Version": envelope["schema_version"],
        })
        timeout_seconds = int(endpoint.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS) or DEFAULT_TIMEOUT_SECONDS)
        max_attempts = int(endpoint.get("max_attempts", DEFAULT_MAX_ATTEMPTS) or DEFAULT_MAX_ATTEMPTS)
        retry_delay_seconds = float(endpoint.get("retry_delay_seconds", DEFAULT_RETRY_DELAY_SECONDS) or 0)
        delivered = False
        for attempt_index in range(max_attempts):
            if time.monotonic() >= deadline:
                break
            # A configured timeout is only the ceiling. Cap each attempt to the
            # remaining event-wide budget so a single slow endpoint cannot stall
            # the investigation beyond the documented dispatch deadline.
            effective_timeout_seconds = max(
                0.0,
                min(timeout_seconds, MAX_TOTAL_WEBHOOK_DISPATCH_SECONDS, deadline - time.monotonic()),
            )
            if effective_timeout_seconds <= 0:
                break
            req = urllib_request.Request(
                endpoint["url"],
                data=encoded,
                headers=headers,
                method="POST",
            )
            if _post_once(req, effective_timeout_seconds, active_logger, event, endpoint["url"], resolved_path):
                sent += 1
                delivered = True
                break
            if attempt_index + 1 < max_attempts and retry_delay_seconds:
                # Keep total backoff across every subscribed endpoint within the
                # same budget so a long endpoint list cannot stall a job.
                remaining_budget = max(0.0, MAX_TOTAL_RETRY_DELAY_SECONDS - total_sleep_seconds)
                allowed_delay = min(retry_delay_seconds, remaining_budget, max(0.0, deadline - time.monotonic()))
                if allowed_delay > 0:
                    time.sleep(allowed_delay)
                    total_sleep_seconds += allowed_delay
        if not delivered:
            failed += 1

    return {
        "event": event,
        "event_id": envelope["event_id"],
        "schema_version": envelope["schema_version"],
        "attempted": attempted,
        "sent": sent,
        "failed": failed,
        "skipped": skipped,
        "configured_endpoints": len(endpoints),
        "config_path": resolved_path,
    }
