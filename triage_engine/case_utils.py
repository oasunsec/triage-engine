"""Case naming and resolution helpers."""

from __future__ import annotations

import os
import re
from datetime import datetime
from typing import Optional


def slugify(value: str, fallback: str = "case") -> str:
    text = re.sub(r"[^a-zA-Z0-9._-]+", "-", (value or "").strip())
    text = text.strip("-._").lower()
    return text[:64] or fallback


def auto_case_name(evtx: Optional[str], live: bool, channels: str, now: Optional[datetime] = None) -> str:
    now = now or datetime.now()
    stamp = now.strftime("%Y%m%d-%H%M%S")
    if live:
        ch = slugify(channels.replace(",", "-"), fallback="security")
        return f"case-live-{ch}-{stamp}"
    source = slugify(os.path.basename(evtx or "evtx"), fallback="evtx")
    return f"case-evtx-{source}-{stamp}"


def _latest_matching_case(cases_root: str, case_ref: str) -> Optional[str]:
    if not os.path.isdir(cases_root):
        return None
    candidates = []
    prefix = case_ref.lower()
    for name in os.listdir(cases_root):
        full = os.path.join(cases_root, name)
        if not os.path.isdir(full):
            continue
        if name.lower() == prefix or name.lower().startswith(prefix + "-"):
            candidates.append(full)
    if not candidates:
        return None
    return max(candidates, key=lambda p: os.path.getmtime(p))


def ensure_case_dir(cases_root: str, case_name: str, overwrite: bool = False, resume: bool = False) -> str:
    os.makedirs(cases_root, exist_ok=True)
    base_path = os.path.join(cases_root, case_name)

    if overwrite:
        os.makedirs(base_path, exist_ok=True)
        return base_path

    if resume:
        if os.path.isdir(base_path):
            return base_path
        latest = _latest_matching_case(cases_root, case_name)
        if latest:
            return latest
        os.makedirs(base_path, exist_ok=True)
        return base_path

    if not os.path.exists(base_path):
        os.makedirs(base_path, exist_ok=True)
        return base_path

    # Default safe behavior: versioned run if case already exists.
    stamp = datetime.now().strftime("%Y%m%d-%H%M")
    candidate = f"{base_path}-{stamp}"
    count = 1
    while os.path.exists(candidate):
        count += 1
        candidate = f"{base_path}-{stamp}-{count}"
    os.makedirs(candidate, exist_ok=True)
    return candidate


def resolve_case_path(cases_root: str, case_ref: str) -> str:
    if os.path.isabs(case_ref) and os.path.isdir(case_ref):
        return case_ref

    exact = os.path.join(cases_root, case_ref)
    if os.path.isdir(exact):
        return exact

    latest = _latest_matching_case(cases_root, case_ref)
    if latest:
        return latest

    raise FileNotFoundError(f"Case not found: {case_ref}")
