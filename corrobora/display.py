"""Helpers for public-facing path and input-source display."""

from __future__ import annotations

import os
import re
from typing import Iterable, List

_WINDOWS_ABS_RE = re.compile(r"^[A-Za-z]:[\\/]")


def sanitize_display_path(value: str) -> str:
    """Return a safe display form for path-like values without changing internals."""
    text = str(value or "").strip()
    if not text:
        return ""

    lowered = text.lower()
    if lowered.startswith("live:"):
        channels = [item.strip() for item in text[5:].split(",") if item.strip()]
        return f"Live Windows ({', '.join(channels)})" if channels else "Live Windows"

    normalized = text.replace("\\", "/").rstrip("/")
    if _WINDOWS_ABS_RE.match(text) or normalized.startswith("./") or normalized.startswith("../") or "/" in normalized:
        base = os.path.basename(normalized)
        return base or normalized

    return text


def sanitize_display_values(values: Iterable[str]) -> List[str]:
    return [sanitize_display_path(value) for value in (values or []) if str(value or "").strip()]


def display_input_source(value: str) -> str:
    return sanitize_display_path(value)
