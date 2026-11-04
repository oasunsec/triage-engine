"""Safe intake of a collector archive (scripts/collect-windows-evidence.ps1 output, zipped).

The archive is untrusted input from another host. Extraction refuses absolute
paths, parent references, links and unexpected top-level folders; enforces
member-count and size budgets; and re-verifies every file the collection
manifest lists against its SHA-256 before anything is analysed.
"""

from __future__ import annotations

import hashlib
import json
import stat
import zipfile
from pathlib import Path, PurePosixPath

ALLOWED_TOP = {"logs", "prefetch", "hives", "tasks", "ntfs", "bundle", "collection_manifest.json"}
MAX_MEMBERS = 20_000
COPY_BLOCK = 4 * 1024 * 1024


class IngestError(ValueError):
    """The archive cannot be accepted; the message is safe to show the uploader."""


def extract_collection(archive: Path, destination: Path, *, max_bytes: int) -> dict:
    """Extract ``archive`` into ``destination`` (new); return a summary for queueing."""
    destination.mkdir(parents=True, exist_ok=False)
    try:
        bundle = zipfile.ZipFile(archive)
    except zipfile.BadZipFile as exc:
        raise IngestError("Upload is not a ZIP archive") from exc
    with bundle:
        members = bundle.infolist()
        if not members or len(members) > MAX_MEMBERS:
            raise IngestError(f"Archive must hold 1-{MAX_MEMBERS} entries")
        total = 0
        for info in members:
            name = PurePosixPath(info.filename.replace("\\", "/"))
            if info.filename.startswith(("/", "\\")) or ".." in name.parts or (name.parts and ":" in name.parts[0]):
                raise IngestError(f"Unsafe path in archive: {info.filename}")
            if stat.S_ISLNK(info.external_attr >> 16):
                raise IngestError(f"Links are not accepted: {info.filename}")
            if not name.parts or name.parts[0] not in ALLOWED_TOP:
                raise IngestError(f"Unexpected entry in archive: {info.filename}")
            total += info.file_size
            if total > max_bytes:
                raise IngestError("Archive expands beyond the ingest size limit")
        for info in members:
            target = destination.joinpath(*PurePosixPath(info.filename.replace("\\", "/")).parts)
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            written = 0
            with bundle.open(info) as source, open(target, "xb") as out:
                for block in iter(lambda: source.read(COPY_BLOCK), b""):
                    written += len(block)
                    if written > info.file_size:
                        raise IngestError(f"Entry larger than declared: {info.filename}")
                    out.write(block)
    return verify_collection(destination)


def verify_collection(root: Path) -> dict:
    manifest_path = root / "collection_manifest.json"
    if not manifest_path.is_file():
        raise IngestError("collection_manifest.json is missing")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    except ValueError as exc:
        raise IngestError("collection_manifest.json is not valid JSON") from exc
    if manifest.get("kind") != "windows_evidence_collection" or not isinstance(manifest.get("files"), list):
        raise IngestError("collection_manifest.json is not a Windows evidence collection")
    checked = 0
    for entry in manifest["files"]:
        relative = PurePosixPath(str(entry.get("path", "")).replace("\\", "/"))
        if not relative.parts or ".." in relative.parts or relative.parts[0] not in ALLOWED_TOP:
            raise IngestError(f"Manifest lists an unexpected path: {entry.get('path')}")
        path = root.joinpath(*relative.parts)
        if not path.is_file():
            raise IngestError(f"Collected file missing from archive: {relative}")
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for block in iter(lambda: handle.read(COPY_BLOCK), b""):
                digest.update(block)
        if digest.hexdigest() != str(entry.get("sha256", "")).lower():
            raise IngestError(f"SHA-256 mismatch for {relative}")
        checked += 1
    logs = root / "logs"
    bundle = root / "bundle"
    has_logs = logs.is_dir() and any(logs.glob("*.evtx"))
    has_bundle = (bundle / "manifest.json").is_file()
    if not has_logs and not has_bundle:
        raise IngestError("Collection holds neither event logs nor an artifact bundle")
    return {"host": str(manifest.get("host") or ""), "collected_at": str(manifest.get("collected_at") or ""),
            "files_verified": checked, "logs": str(logs) if has_logs else "",
            "bundle": str(bundle) if has_bundle else "",
            "failed_steps": [step for step in manifest.get("steps", []) if step.get("status") == "failed"],
            "files": [{"path": str(entry.get("path", "")).replace("\\", "/"), "sha256": str(entry.get("sha256", "")).lower(),
                       "bytes": entry.get("size_bytes")} for entry in manifest["files"]]}
