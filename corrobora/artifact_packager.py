"""Package explicitly supplied offline Windows forensic artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from datetime import datetime
from pathlib import Path

from corrobora import __version__
from corrobora.path_safety import is_link_or_reparse

_LIMIT = 64 * 1024 * 1024
_NTFS_KINDS = {"ntfs_mft", "ntfs_usn_journal"}
_NTFS_LARGE_LIMIT = 8 * 1024**3


def _is_link(path: Path) -> bool:
    return is_link_or_reparse(path)


def _safe_path(path: Path, label: str) -> Path:
    absolute = Path(os.path.abspath(path))
    for part in (absolute, *absolute.parents):
        if _is_link(part):
            raise ValueError(f"{label} path cannot contain links or junctions")
    return absolute


def _validate_text(value: str, label: str, maximum: int, *, required: bool = True) -> str:
    if not isinstance(value, str) or len(value) > maximum or "\x00" in value or (required and not value.strip()):
        raise ValueError(f"Invalid {label}")
    return value


def _stable_bytes(source: Path, limit: int = _LIMIT) -> bytes:
    if not source.is_file():
        raise ValueError(f"Artifact source is not a regular file: {source.name}")
    before = source.stat()
    if before.st_size > limit:
        raise ValueError(f"Artifact input exceeds its {limit} byte limit: {source.name}")
    # Windows reports path creation time as st_ctime but can expose a different
    # value for the same open file handle, so compare stable identity/size/mtime.
    signature = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)
    with source.open("rb") as handle:
        opened = os.fstat(handle.fileno())
        data = handle.read(before.st_size + 1)
        after_open = os.fstat(handle.fileno())
    after_path = source.stat()
    if (signature(before) != signature(opened) or signature(before) != signature(after_open)
            or signature(before) != signature(after_path) or len(data) != before.st_size):
        raise ValueError(f"Artifact changed while being read: {source.name}")
    return data


def _stream_copy(source: Path, target, limit: int) -> tuple[int, str]:
    """Copy a large source in blocks with hashing, rejecting change during the copy."""
    signature = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)
    before = source.stat()
    if before.st_size > limit:
        raise ValueError(f"Artifact source exceeds its size limit: {source.name}")
    digest, written = hashlib.sha256(), 0
    with source.open("rb") as handle:
        opened = os.fstat(handle.fileno())
        for block in iter(lambda: handle.read(4 * 1024 * 1024), b""):
            written += len(block)
            if written > before.st_size:
                break
            digest.update(block)
            target.write(block)
        after_open = os.fstat(handle.fileno())
    if (written != before.st_size or signature(before) != signature(opened)
            or signature(before) != signature(after_open) or signature(before) != signature(source.stat())):
        raise ValueError(f"Artifact changed while being read: {source.name}")
    return written, digest.hexdigest()


def pack_artifacts(
    output_dir: str | Path, *, host: str, observed_at: str,
    chromium_history: list[str | Path] = (), pecmd_jsonl: list[str | Path] = (),
    prefetch_source: list[str | Path] = (), persistence_records: list[str | Path] = (),
    pecmd_version: str = "", scheduled_task_xml: list[str | Path] = (),
    registry_hives: list[tuple[str | Path, str]] = (),
    ntfs_mft: list[str | Path] = (), ntfs_usn_journal: list[str | Path] = (), ntfs_volume: str = "",
    allow_large_ntfs: bool = False, whole_task_folder: bool = False,
) -> Path:
    """Copy validated, caller-selected artifact files into a new bundle."""
    host = _validate_text(host, "host", 256)
    observed_at = _validate_text(observed_at, "observed_at", 64)
    try:
        parsed_time = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("observed_at must be an ISO-8601 timestamp") from exc
    if parsed_time.tzinfo is None or parsed_time.utcoffset() is None:
        raise ValueError("observed_at must include a timezone")
    if pecmd_jsonl:
        pecmd_version = _validate_text(pecmd_version, "PECmd version", 128)
    elif pecmd_version:
        _validate_text(pecmd_version, "PECmd version", 128)

    if len(ntfs_mft) > 1 or len(ntfs_usn_journal) > 1:
        raise ValueError("Provide at most one $MFT and one USN journal (one volume per bundle)")
    if ntfs_volume and not re.fullmatch(r"[A-Za-z]:", ntfs_volume):
        raise ValueError("NTFS volume must be a drive letter such as C:")
    member_count = sum(len(paths) for paths in
                       (chromium_history, pecmd_jsonl, prefetch_source, persistence_records, scheduled_task_xml,
                        registry_hives, ntfs_mft, ntfs_usn_journal))
    from corrobora.forensic_artifacts import MAX_BUNDLE_MEMBERS
    if not 1 <= member_count <= MAX_BUNDLE_MEMBERS:
        raise ValueError(f"Provide between 1 and {MAX_BUNDLE_MEMBERS} artifact files")
    requested = []
    aggregate_size = 0
    for paths, kind, extension in ((chromium_history, "chromium_history", ".sqlite"),
                                   (pecmd_jsonl, "pecmd_jsonl", ".jsonl"),
                                   (prefetch_source, "prefetch_source", ".pf"),
                                   (persistence_records, "persistence_records", ".json"),
                                   (scheduled_task_xml, "scheduled_task_xml", ".xml"),
                                   (ntfs_mft, "ntfs_mft", ".mft"),
                                   (ntfs_usn_journal, "ntfs_usn_journal", ".usnjrnl")):
        for supplied in paths:
            source = _safe_path(Path(supplied), "Source")
            if not source.exists() or not source.is_file():
                raise ValueError(f"Artifact source must be an existing regular file: {source.name}")
            if len(source.name) > 512:
                raise ValueError("Artifact original filename exceeds 512 characters")
            if kind in _NTFS_KINDS:
                # Streamed during copy; never read into memory.
                size = source.stat().st_size
                if allow_large_ntfs:
                    if size > _NTFS_LARGE_LIMIT:
                        raise ValueError("NTFS artifact exceeds the 8 GiB member limit")
                else:
                    aggregate_size += size
                    if aggregate_size > _LIMIT:
                        raise ValueError("Artifact inputs exceed the 64 MiB aggregate limit; "
                                         "use the allow-large-NTFS option for large $MFT/$J copies")
                requested.append((kind, extension, source, None))
                continue
            aggregate_size += source.stat().st_size
            if aggregate_size > _LIMIT:
                raise ValueError("Artifact inputs exceed the 64 MiB aggregate limit")
            data = _stable_bytes(source)
            requested.append((kind, extension, source, data))
    hive_types: dict[int, str] = {}
    hive_logs: dict[int, tuple[int, str]] = {}  # log position -> (hive position, LOG1/LOG2)
    if registry_hives:
        from corrobora.forensic_artifacts import MAX_HIVE_BUNDLE_BYTES
        from corrobora.registry_hive_artifacts import HIVE_TYPES, max_hive_bytes
        hive_total = 0
        for supplied, hive_type in registry_hives:
            if hive_type not in HIVE_TYPES:
                raise ValueError("Hive type must be ntuser, software, system or amcache")
            source = _safe_path(Path(supplied), "Source")
            if not source.exists() or not source.is_file() or len(source.name) > 512:
                raise ValueError(f"Registry hive must be an existing regular file: {source.name}")
            data = _stable_bytes(source, max_hive_bytes())
            hive_total += len(data)
            if hive_total > MAX_HIVE_BUNDLE_BYTES:
                raise ValueError("Registry hive inputs exceed the 1 GiB aggregate limit")
            if not data.startswith(b"regf"):
                raise ValueError(f"Not a registry hive (missing regf signature): {source.name}")
            hive_types[len(requested)] = hive_type
            hive_index = len(requested)
            requested.append(("registry_hive", ".hive", source, data))
            for slot in ("LOG1", "LOG2"):
                log_source = Path(str(source) + "." + slot)
                if log_source.is_file() and not _is_link(log_source):
                    log_data = _stable_bytes(log_source, max_hive_bytes())
                    hive_total += len(log_data)
                    if hive_total > MAX_HIVE_BUNDLE_BYTES:
                        raise ValueError("Registry hive inputs exceed the 1 GiB aggregate limit")
                    hive_logs[len(requested)] = (hive_index, slot)
                    requested.append(("registry_hive_log", "." + slot.lower(), log_source, log_data))
    # Every supported member kind is now parsed (including native .pf), and at
    # least one member is required above, so no separate analytical check.
    if sum(len(data) for kind, _, _, data in requested
          if kind not in {"registry_hive", "registry_hive_log"} and data is not None) > _LIMIT:
        raise ValueError("Artifact inputs exceed the 64 MiB aggregate limit")
    for kind, _, source, data in requested:
        if kind == "chromium_history":
            if any(Path(str(source) + suffix).exists() for suffix in ("-wal", "-journal")):
                raise ValueError("Chromium History has WAL/journal sidecars; supply a standalone SQLite snapshot")
            if data.startswith(b"SQLite format 3\x00") and len(data) >= 20 and (data[18] == 2 or data[19] == 2):
                raise ValueError("Chromium History uses SQLite WAL mode; supply a standalone SQLite snapshot")

    destination = _safe_path(Path(output_dir), "Output")
    project_root = Path(__file__).resolve().parents[1]
    forbidden = {project_root, project_root.parent, Path.home(), Path(destination.anchor)}
    if destination in forbidden:
        raise ValueError("Output directory must be a new project-owned child directory")
    if destination.exists():
        raise FileExistsError(f"Output directory already exists: {destination}")
    parent = destination.parent
    if not parent.is_dir():
        raise ValueError("Output parent directory must already exist")
    if _is_link(destination):
        raise ValueError("Output directory cannot be a link or junction")

    # Create all bundle bytes in an isolated sibling, then publish with a no-replace rename.
    stage = Path(tempfile.mkdtemp(prefix=".triage-artifacts-", dir=parent))
    known_files: list[Path] = []
    try:
        entries = []
        counters: dict[str, int] = {}
        for position, (kind, extension, source, data) in enumerate(requested):
            counters[kind] = counters.get(kind, 0) + 1
            output_name = f"{kind}-{counters[kind]}{extension}"
            target = stage / output_name
            with target.open("xb") as handle:
                known_files.append(target)
                if data is None:
                    size, digest = _stream_copy(source, handle, _NTFS_LARGE_LIMIT if allow_large_ntfs else _LIMIT)
                else:
                    handle.write(data)
                    size, digest = len(data), hashlib.sha256(data).hexdigest()
                handle.flush()
                os.fsync(handle.fileno())
            item = {"path": output_name, "kind": kind, "size_bytes": size,
                    "sha256": digest, "original_name": source.name}
            if kind in _NTFS_KINDS and ntfs_volume:
                item["volume"] = ntfs_volume.upper()
            if kind == "pecmd_jsonl":
                item["exporter"] = {"name": "PECmd", "version": pecmd_version}
            if kind == "registry_hive":
                item["hive_type"] = hive_types[position]
            if kind == "registry_hive_log":
                hive_position, slot = hive_logs[position]
                item["hive_member"], item["log_slot"] = entries[hive_position]["path"], slot
            entries.append(item)
        warnings = ([] if not persistence_records else [
            "Persistence records supplied without their acquisition manifest; collector scope and failures are unknown."])
        if scheduled_task_xml and not whole_task_folder:
            # Selected task files are not a full Tasks directory; absent tasks prove nothing.
            warnings.append("Scheduled task XML files were selected individually; other tasks on the host may exist.")
        if registry_hives:
            # A selected hive is not the whole registry: other users' NTUSER.DAT files may exist.
            warnings.append("Registry hives were selected individually; other hives, including other users' NTUSER.DAT, may exist.")
            unlogged = sorted(source.name for position, (kind, _, source, _) in enumerate(requested)
                              if kind == "registry_hive" and not any(hive == position for hive, _ in hive_logs.values()))
            if unlogged:
                warnings.append("No transaction logs were found beside " + ", ".join(unlogged)
                                + "; if those hives were copied from a running system, recent changes may be missing.")
        manifest = {"schema_version": "1.1", "kind": "windows_forensic_artifacts",
                    "host": host, "observed_at": observed_at,
                    "collector": {"name": "triage-artifact-packager", "version": __version__},
                    "completeness": "partial" if warnings else "complete",
                    "warnings": warnings, "files": entries}
        manifest_path = stage / "manifest.json"
        with manifest_path.open("x", encoding="utf-8", newline="\n") as handle:
            known_files.append(manifest_path)
            json.dump(manifest, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        # os.rename on Windows does not replace an existing non-empty directory;
        # the existence check also avoids replacing an empty destination.
        if destination.exists():
            raise FileExistsError(f"Output directory already exists: {destination}")
        stage.rename(destination)
        return destination
    except BaseException:
        for path in known_files:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        try:
            stage.rmdir()
        except FileNotFoundError:
            pass
        raise
