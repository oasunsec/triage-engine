"""Minimal, dependency-free environment file loader."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional


def load_env_file(path: str) -> int:
    """Load simple KEY=VALUE entries without overwriting process variables."""
    candidate = Path(path)
    if not candidate.is_file():
        return 0
    try:
        lines = candidate.read_text(encoding="utf-8").splitlines()
    except OSError:
        return 0
    loaded = 0
    for line in lines:
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        if text.startswith("export "):
            text = text[7:].lstrip()
        if "=" not in text:
            continue
        key, value = text.split("=", 1)
        key = key.strip()
        if not key or not key.replace("_", "").isalnum() or key[0].isdigit() or key in os.environ:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        os.environ[key] = value
        loaded += 1
    return loaded


def load_project_env(root_dir: str, explicit: Optional[str] = None) -> int:
    """Load .env, falling back to the user's existing .env.txt file."""
    if explicit:
        paths = [explicit]
    else:
        # In a PyInstaller build ``root_dir`` points inside ``_internal``;
        # include the launcher's working directory for portable deployments.
        root = Path(root_dir)
        paths = [str(root / ".env"), str(root / ".env.txt")]
        # Only fall back to the launcher's working directory when the bundle
        # has no project-local environment file. This prevents an unrelated
        # cwd .env.txt (and its secrets) from being merged into a case run.
        if not (root / ".env").is_file() and not (root / ".env.txt").is_file():
            paths.extend([str(Path.cwd() / ".env"), str(Path.cwd() / ".env.txt")])
    seen = set()
    total = 0
    for path in paths:
        if path and path not in seen:
            seen.add(path)
            total += load_env_file(path)
    from corrobora import adopt_legacy_environment
    adopt_legacy_environment()  # .env files written before the rename use TRIAGE_*
    return total
