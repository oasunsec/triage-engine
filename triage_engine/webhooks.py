"""Best-effort webhook delivery for investigation events."""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib import error as urllib_error
from urllib import request as urllib_request


DEFAULT_TIMEOUT_SECONDS = 5
DEFAULT_CONFIG_RELATIVE_PATH = os.path.join("config", "webhooks.json")


def _coerce_headers(value: Any) -> Dict[str, str]:
    if not isinstance(value, dict):
        return {}
    output: Dict[str, str] = {}
    for key, raw in value.items():
        k = str(key or "").strip()
        if not k:
            continue
        output[k] = str(raw or "")
    return output


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
    except (TypeError, ValueError):
        return DEFAULT_TIMEOUT_SECONDS
    if timeout < 1:
        return DEFAULT_TIMEOUT_SECONDS
    return timeout


def load_webhook_endpoints(
    root_dir: str,
    *,
    config_path: Optional[str] = None,
) -> tuple[List[Dict[str, Any]], List[str], str]:
    """Load configured endpoints from JSON; invalid entries are skipped."""
    resolved_path = os.path.abspath(
        config_path
        or os.environ.get("TRIAGE_WEBHOOK_CONFIG", "").strip()
        or os.path.join(root_dir, DEFAULT_CONFIG_RELATIVE_PATH)
    )
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
        url = str(item.get("url") or "").strip()
        if not url:
            diagnostics.append(f"endpoints[{idx}] missing required field 'url'")
            continue
        events = _coerce_events(item.get("events", []))
        if not events:
            diagnostics.append(f"endpoints[{idx}] has no subscribed events")
            continue
        endpoints.append(
            {
                "url": url,
                "events": events,
                "headers": _coerce_headers(item.get("headers", {})),
                "timeout_seconds": _coerce_timeout(item.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)),
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
    """Send a webhook event to subscribed endpoints (best-effort, no retries)."""
    endpoints, diagnostics, resolved_path = load_webhook_endpoints(root_dir, config_path=config_path)
    active_logger = logger or logging.getLogger("triage.webhooks")

    for message in diagnostics:
        active_logger.warning(
            "webhook_config_warning",
            extra={"event": event, "config_path": resolved_path, "warning": message},
        )

    envelope = dict(payload or {})
    envelope["event"] = event
    envelope.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
    encoded = json.dumps(envelope).encode("utf-8")

    attempted = 0
    sent = 0
    failed = 0
    for endpoint in endpoints:
        if event not in endpoint.get("events", []):
            continue
        attempted += 1
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "triage-engine-webhook/1.0",
        }
        headers.update(endpoint.get("headers", {}))
        req = urllib_request.Request(
            endpoint["url"],
            data=encoded,
            headers=headers,
            method="POST",
        )
        timeout_seconds = int(endpoint.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS) or DEFAULT_TIMEOUT_SECONDS)
        try:
            with urllib_request.urlopen(req, timeout=timeout_seconds) as response:  # noqa: S310
                status = int(getattr(response, "status", 0) or response.getcode() or 0)
            if status >= 400:
                failed += 1
                active_logger.warning(
                    "webhook_delivery_failed",
                    extra={
                        "event": event,
                        "url": endpoint["url"],
                        "status": status,
                        "config_path": resolved_path,
                    },
                )
                continue
            sent += 1
        except (urllib_error.HTTPError, urllib_error.URLError, TimeoutError, ValueError) as exc:
            failed += 1
            active_logger.warning(
                "webhook_delivery_failed",
                extra={
                    "event": event,
                    "url": endpoint["url"],
                    "error": str(exc),
                    "config_path": resolved_path,
                },
            )
        except Exception as exc:  # pragma: no cover - defensive best-effort guard
            failed += 1
            active_logger.warning(
                "webhook_delivery_failed",
                extra={
                    "event": event,
                    "url": endpoint["url"],
                    "error": str(exc),
                    "config_path": resolved_path,
                },
            )

    return {
        "event": event,
        "attempted": attempted,
        "sent": sent,
        "failed": failed,
        "configured_endpoints": len(endpoints),
        "config_path": resolved_path,
    }
