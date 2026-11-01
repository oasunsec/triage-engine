"""Local evidence capture and versioned, verifiable analysis manifests."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from corrobora.path_safety import is_link_or_reparse, reject_path_links


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def atomic_json(path: str | Path, payload: Any) -> None:
    path = Path(path)
    reject_path_links(path, "Manifest output cannot use links or junctions")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".partial")
    try:
        with temporary.open("x", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _contained(path: Path, root: Path) -> Path:
    path, root = path.absolute(), root.absolute()
    reject_path_links(root, "Evidence paths cannot use links or junctions")
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("Evidence path escapes its case directory")
    # Reject junction/symlink ancestors as well as the final path.
    current = path
    while True:
        if is_link_or_reparse(current):
            raise ValueError("Evidence paths cannot use links or junctions")
        if current == root:
            break
        if current.parent == current:
            raise ValueError("Evidence path escapes its case directory")
        current = current.parent
    return path


def case_identity(case_path: str) -> dict:
    root = Path(case_path).absolute()
    identity_path = _contained(root / "case_identity.json", root)
    if identity_path.exists():
        identity = json.loads(identity_path.read_text(encoding="utf-8"))
        uuid.UUID(identity["case_id"])
        return identity
    identity = {"schema_version": "1.0", "case_id": str(uuid.uuid4())}
    atomic_json(identity_path, identity)
    return identity


def capture_evidence(case_path: str, files: Iterable[tuple[str, str]]) -> list[dict]:
    """Capture exact bytes before analysis; deduplicate by content inside a case.

    files contains (source path, source kind). Original absolute paths are not
    exported. Sources must be regular files, with bounded count/size and stable
    size/mtime through capture. Recorded hashes describe bytes, not authenticity.
    """
    root = Path(case_path).absolute()
    _contained(root, root)
    sources = [(Path(path), kind) for path, kind in files]
    if len(sources) > 1024:
        raise ValueError("Evidence input exceeds 1024 files")
    total = 0
    for source, kind in sources:
        if kind not in {"evtx", "artifact_manifest", "persistence_records", "chromium_history", "pecmd_jsonl", "prefetch_source",
                        "scheduled_task_xml", "registry_hive", "registry_hive_log", "ntfs_mft", "ntfs_usn_journal"}:
            raise ValueError("Unsupported evidence source kind")
        if is_link_or_reparse(source) or not source.is_file():
            raise ValueError(f"Evidence input must be a regular file: {source.name}")
        for ancestor in source.absolute().parents:
            if is_link_or_reparse(ancestor):
                raise ValueError("Evidence input cannot use links or junctions")
        total += source.stat().st_size
    max_bytes = int(os.environ.get("CORROBORA_MAX_EVIDENCE_BYTES", str(4 * 1024**3)))
    if total > max_bytes:
        raise ValueError("Evidence input exceeds CORROBORA_MAX_EVIDENCE_BYTES")
    if shutil.disk_usage(root).free < total + 16 * 1024**2:
        raise ValueError("Insufficient free space to retain original evidence")
    evidence_root = _contained(root / "evidence", root)
    evidence_root.mkdir(exist_ok=True)
    entries = []
    for source, kind in sources:
        before = source.stat()
        temporary = evidence_root / (uuid.uuid4().hex + ".partial")
        digest = hashlib.sha256()
        try:
            with source.open("rb") as reader, temporary.open("xb") as writer:
                for block in iter(lambda: reader.read(1024 * 1024), b""):
                    digest.update(block)
                    writer.write(block)
                writer.flush()
                os.fsync(writer.fileno())
            after = source.stat()
            if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise ValueError(f"Evidence changed during acquisition: {source.name}")
            checksum = digest.hexdigest()
            extension = {"evtx": ".evtx", "chromium_history": ".sqlite", "pecmd_jsonl": ".jsonl", "prefetch_source": ".pf",
                         "scheduled_task_xml": ".xml", "registry_hive": ".hive", "registry_hive_log": ".hivelog", "ntfs_mft": ".mft",
                         "ntfs_usn_journal": ".usnjrnl"}.get(kind, ".json")
            destination = _contained(evidence_root / (checksum + extension), root)
            if destination.exists():
                if sha256_file(destination) != checksum:
                    raise ValueError("Previously retained evidence failed its hash check")
                temporary.unlink()
            else:
                os.replace(temporary, destination)
            entries.append({"id": "evi_" + checksum, "kind": kind, "original_name": source.name,
                            "sha256": checksum, "size_bytes": before.st_size,
                            "path": destination.relative_to(root).as_posix(),
                            "captured_at": datetime.now(timezone.utc).isoformat(),
                            "_source_path": str(source.resolve()), "_retained_path": str(destination)})
        finally:
            if temporary.exists():
                temporary.unlink()
    return entries


def public_sources(entries: list[dict]) -> list[dict]:
    return [{key: value for key, value in entry.items() if not key.startswith("_")} for entry in entries]


def bind_event_sources(events: list, entries: list[dict]) -> None:
    by_path = {os.path.normcase(entry["_retained_path"]): entry for entry in entries if entry["kind"] == "evtx"}
    ordinal_by_source: dict[str, int] = {}
    for event in events:
        entry = by_path.get(os.path.normcase(event.source_file))
        if entry is None and len(by_path) == 1 and not event.source_file:
            entry = next(iter(by_path.values()))
        if entry is None:
            continue
        event.source_file = entry["path"]
        event.source_sha256 = entry["sha256"]
        ordinal = ordinal_by_source.get(entry["id"], 0)
        ordinal_by_source[entry["id"]] = ordinal + 1
        locator = [entry["id"], event.channel, event.provider, event.record_id or f"parsed_index:{ordinal}"]
        event.observation_id = "obs_" + hashlib.sha256(json.dumps(locator).encode()).hexdigest()


def write_analysis_manifest(case_path: str, *, run_id: str, sources: list[dict], artifacts: dict[str, str],
                            configuration: dict, component_files: Iterable[str], engine_version: str,
                            partial_failures: list, collection_warnings: list) -> dict:
    root = Path(case_path).absolute()
    uuid.UUID(run_id)
    identity = case_identity(case_path)
    run_root = _contained(root / "runs" / run_id, root)
    if run_root.exists():
        raise ValueError("Analysis run identity already exists")
    run_root.mkdir(parents=True)
    outputs = []
    for kind, value in artifacts.items():
        path = _contained(Path(value), root)
        if path.is_file():
            snapshot = _contained(run_root / "outputs" / path.name, root)
            snapshot.parent.mkdir(exist_ok=True)
            shutil.copyfile(path, snapshot)
            digest = sha256_file(snapshot)
            if digest != sha256_file(path):
                raise ValueError("Case output changed while retaining analysis run")
            outputs.append({"kind": kind, "path": path.relative_to(root).as_posix(),
                            "snapshot_path": snapshot.relative_to(root).as_posix(),
                            "sha256": digest, "size_bytes": snapshot.stat().st_size})
    project_root = Path(__file__).resolve().parents[1]
    components = [{"name": Path(path).name,
                   "path": Path(path).relative_to(project_root).as_posix() if Path(path).is_relative_to(project_root) else Path(path).name,
                   "sha256": sha256_file(path)}
                  for path in sorted(set(component_files)) if Path(path).is_file()]
    payload = {**identity, "run_id": run_id, "engine_version": engine_version,
               "completed_at": datetime.now(timezone.utc).isoformat(), "status": "completed",
               "completeness": "partial" if partial_failures or collection_warnings else "complete",
               "sources": public_sources(sources), "configuration": configuration,
               "components": components, "outputs": outputs, "partial_failures": partial_failures,
               "collection_warnings": collection_warnings,
               "limitations": ["Hashes establish byte consistency, not source authenticity.",
                               "Live event acquisition has no retained native EVTX source file.",
                               "Original sources and lossless normalized records are unredacted; derived snapshots preserve stored display sanitization.",
                               "Normalized records preserve model fields; raw XML is present only when retained by the parser."]}
    destination = _contained(root / "runs" / run_id / "analysis_manifest.json", root)
    if destination.exists():
        raise ValueError("Analysis run identity already exists")
    atomic_json(destination, payload)
    atomic_json(_contained(root / "analysis_manifest.json", root), payload)
    return payload
