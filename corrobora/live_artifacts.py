"""Read-only artifact collection from the machine the server runs on, for live scans.

A live scan reads event-log channels through the Windows API; that alone gives
the Evidence tab nothing to show. When the server is elevated, this copies the
same artifacts scripts/collect-windows-evidence.ps1 does, except $MFT/USN
(several GiB, left to the collector): Prefetch, scheduled-task definitions and
the SYSTEM, SOFTWARE, Amcache and NTUSER hives with their transaction logs.
Locked hives are copied through a temporary shadow copy (esentutl removes it).
Nothing on the system is changed. Every step is recorded, including failures.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Callable, Optional

HIVES = (
    ("SYSTEM", ("System32", "config", "SYSTEM"), "system"),
    ("SOFTWARE", ("System32", "config", "SOFTWARE"), "software"),
    ("Amcache.hve", ("appcompat", "Programs", "Amcache.hve"), "amcache"),
)
ESENTUTL_TIMEOUT_SECONDS = 180


def is_elevated() -> bool:
    if os.name != "nt":
        return False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _esentutl_copy(source: Path, destination: Path) -> None:
    result = subprocess.run(["esentutl.exe", "/y", str(source), "/vss", "/d", str(destination)],
                            capture_output=True, text=True, timeout=ESENTUTL_TIMEOUT_SECONDS,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if result.returncode != 0 or not destination.is_file():
        raise OSError(f"esentutl exited {result.returncode}")


def _files_under(folder: Path) -> list[Path]:
    found = []
    for root, dirs, files in os.walk(folder, followlinks=False):
        dirs[:] = sorted(name for name in dirs if not os.path.islink(os.path.join(root, name)))
        found.extend(Path(root) / name for name in sorted(files))
    return found


def collect_live_artifacts(
    staging: Path, *, host: str, observed_at: str,
    system_root: Optional[Path] = None, user_profile: Optional[Path] = None,
    copy_locked: Callable[[Path, Path], None] = _esentutl_copy,
) -> tuple[Optional[Path], list[dict]]:
    """Collect into ``staging`` (new) and package a bundle; return (bundle or None, steps)."""
    from corrobora.artifact_packager import pack_artifacts

    system_root = Path(system_root or os.environ.get("SystemRoot", r"C:\Windows"))
    user_profile = Path(user_profile or os.path.expanduser("~"))
    staging.mkdir(parents=True, exist_ok=False)
    steps: list[dict] = []

    def step(name: str, action: Callable[[], None]) -> None:
        try:
            action()
            steps.append({"step": name, "status": "ok"})
        except Exception as exc:  # Recorded; one missing source never stops the scan.
            steps.append({"step": name, "status": "failed", "error": str(exc)[:300]})

    prefetch_dir = staging / "prefetch"

    def copy_prefetch() -> None:
        prefetch_dir.mkdir()
        files = sorted((system_root / "Prefetch").glob("*.pf"))
        if not files:
            raise FileNotFoundError("no Prefetch files (Prefetch may be disabled)")
        for source in files:
            shutil.copy2(source, prefetch_dir / source.name)

    tasks_dir = staging / "tasks"

    def copy_tasks() -> None:
        shutil.copytree(system_root / "System32" / "Tasks", tasks_dir, symlinks=True)

    hives_dir = staging / "hives"
    hives_dir.mkdir()
    hive_sources = [(name, system_root.joinpath(*parts), kind) for name, parts, kind in HIVES]
    hive_sources.append(("NTUSER.DAT", user_profile / "NTUSER.DAT", "ntuser"))
    collected_hives: list[tuple[str, str]] = []

    def hive_copier(name: str, source: Path, kind: str) -> Callable[[], None]:
        def copy() -> None:
            copy_locked(source, hives_dir / name)
            for suffix in (".LOG1", ".LOG2"):
                log = Path(str(source) + suffix)
                if log.is_file():
                    copy_locked(log, hives_dir / (name + suffix))
            collected_hives.append((str(hives_dir / name), kind))
        return copy

    step("prefetch", copy_prefetch)
    step("tasks", copy_tasks)
    for name, source, kind in hive_sources:
        step(f"hive:{name}", hive_copier(name, source, kind))

    from corrobora.forensic_artifacts import MAX_BUNDLE_MEMBERS

    tasks = [str(path) for path in _files_under(tasks_dir) if not path.is_symlink()] if tasks_dir.is_dir() else []
    prefetch_files = sorted(prefetch_dir.glob("*.pf"), key=lambda path: path.stat().st_mtime, reverse=True) \
        if prefetch_dir.is_dir() else []
    # Hive transaction logs are packaged beside each hive: up to three members per hive.
    room = max(0, MAX_BUNDLE_MEMBERS - len(tasks) - 3 * len(collected_hives))
    if len(prefetch_files) > room:
        steps.append({"step": "prefetch", "status": "partial",
                      "error": f"kept the newest {room} of {len(prefetch_files)} Prefetch files to fit one bundle"})
    prefetch = sorted(str(path) for path in prefetch_files[:room])
    if not (prefetch or tasks or collected_hives):
        return None, steps
    bundle = staging / "bundle"
    try:
        pack_artifacts(bundle, host=host, observed_at=observed_at, prefetch_source=prefetch,
                       scheduled_task_xml=tasks, registry_hives=collected_hives)
    except (ValueError, OSError) as exc:
        steps.append({"step": "package", "status": "failed", "error": str(exc)[:300]})
        return None, steps
    steps.append({"step": "package", "status": "ok"})
    return bundle, steps
