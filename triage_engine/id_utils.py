"""Deterministic ID and display-label helpers."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Callable, Iterable


def _normalize(value: Any) -> Any:
    if isinstance(value, datetime):
        dt = value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return dt.replace(microsecond=0).isoformat()
    if isinstance(value, str):
        return " ".join(value.strip().lower().split())
    if isinstance(value, dict):
        return {str(k): _normalize(v) for k, v in sorted(value.items(), key=lambda item: str(item[0]))}
    if isinstance(value, (list, tuple, set)):
        items = [_normalize(v) for v in value]
        return sorted(items, key=lambda x: json.dumps(x, sort_keys=True, separators=(",", ":")))
    return value


def stable_id(prefix: str, payload: dict[str, Any], length: int = 16) -> str:
    """Create stable IDs like sig_xxx, fnd_xxx, inc_xxx from canonical payloads."""
    canonical = json.dumps(_normalize(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:length]
    return f"{prefix}_{digest}"


def assign_display_labels(
    items: Iterable[Any],
    label_prefix: str,
    time_getter: Callable[[Any], Any] | None = None,
) -> None:
    """Assign analyst-facing labels such as SIG-0001 in deterministic order."""
    item_list = list(items)
    if not item_list:
        return

    if time_getter is None:

        def time_getter(item: Any) -> Any:
            return getattr(item, "first_seen", None) or getattr(item, "timestamp", None)

    def sortable_time(value: Any) -> tuple[int, float]:
        if value is None:
            return (1, float("inf"))
        if isinstance(value, str):
            try:
                value = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                return (1, float("inf"))
        if isinstance(value, datetime):
            dt = value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)
            return (0, dt.timestamp())
        return (1, float("inf"))

    def key_fn(item: Any) -> tuple[Any, Any, str]:
        ts = time_getter(item)
        is_none, stamp = sortable_time(ts)
        return (is_none, stamp, getattr(item, "id", ""))

    for idx, item in enumerate(sorted(item_list, key=key_fn), start=1):
        setattr(item, "display_label", f"{label_prefix}-{idx:04d}")


def confidence_to_score(confidence: str, severity: str) -> int:
    base = {"low": 35, "medium": 55, "high": 75}.get((confidence or "medium").lower(), 55)
    sev_boost = {"low": 0, "medium": 5, "high": 10, "critical": 15}.get((severity or "medium").lower(), 5)
    return max(1, min(100, base + sev_boost))
