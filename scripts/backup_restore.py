"""Backup and restore utility for triage platform state databases."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATA_DIR = ROOT / "data"
DEFAULT_BACKUPS_DIR = DEFAULT_DATA_DIR / "backups"
DB_FILENAMES = ("auth.db", "reviews.db", "jobs.db")


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _resolve_data_dir(data_dir: str | Path | None) -> Path:
    return Path(data_dir).resolve() if data_dir is not None else DEFAULT_DATA_DIR.resolve()


def _resolve_backups_dir(backups_dir: str | Path | None, data_dir: Path) -> Path:
    if backups_dir is None:
        return (data_dir / "backups").resolve()
    return Path(backups_dir).resolve()


def _next_backup_id(backups_dir: Path) -> str:
    base = datetime.now(timezone.utc).strftime("backup-%Y%m%d-%H%M%S")
    candidate = base
    counter = 1
    while (backups_dir / candidate).exists():
        candidate = f"{base}-{counter:02d}"
        counter += 1
    return candidate


def _load_manifest(backup_dir: Path) -> Dict[str, Any]:
    manifest_path = backup_dir / "manifest.json"
    if not manifest_path.is_file():
        raise FileNotFoundError(f"Backup manifest missing: {manifest_path}")
    return json.loads(manifest_path.read_text(encoding="utf-8"))


def create_backup(
    *,
    data_dir: str | Path | None = None,
    backups_dir: str | Path | None = None,
) -> Dict[str, Any]:
    resolved_data_dir = _resolve_data_dir(data_dir)
    resolved_backups_dir = _resolve_backups_dir(backups_dir, resolved_data_dir)
    resolved_data_dir.mkdir(parents=True, exist_ok=True)
    resolved_backups_dir.mkdir(parents=True, exist_ok=True)

    missing = [name for name in DB_FILENAMES if not (resolved_data_dir / name).is_file()]
    if missing:
        raise FileNotFoundError(
            "Cannot create backup because required database files are missing: " + ", ".join(missing)
        )

    backup_id = _next_backup_id(resolved_backups_dir)
    backup_dir = resolved_backups_dir / backup_id
    backup_dir.mkdir(parents=True, exist_ok=False)

    files: List[Dict[str, Any]] = []
    total_bytes = 0
    for filename in DB_FILENAMES:
        source = resolved_data_dir / filename
        destination = backup_dir / filename
        shutil.copy2(source, destination)
        size_bytes = int(destination.stat().st_size)
        checksum = _sha256(destination)
        total_bytes += size_bytes
        files.append(
            {
                "name": filename,
                "size_bytes": size_bytes,
                "sha256": checksum,
            }
        )

    manifest = {
        "backup_id": backup_id,
        "created_at": _utc_now(),
        "data_dir": str(resolved_data_dir),
        "backup_path": str(backup_dir),
        "total_bytes": total_bytes,
        "files": files,
    }
    (backup_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def list_backups(*, backups_dir: str | Path | None = None, data_dir: str | Path | None = None) -> List[Dict[str, Any]]:
    resolved_data_dir = _resolve_data_dir(data_dir)
    resolved_backups_dir = _resolve_backups_dir(backups_dir, resolved_data_dir)
    if not resolved_backups_dir.is_dir():
        return []

    backups: List[Dict[str, Any]] = []
    for backup_dir in sorted((entry for entry in resolved_backups_dir.iterdir() if entry.is_dir()), reverse=True):
        manifest_path = backup_dir / "manifest.json"
        if not manifest_path.is_file():
            continue
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            files = manifest.get("files", [])
            backups.append(
                {
                    "backup_id": str(manifest.get("backup_id") or backup_dir.name),
                    "created_at": str(manifest.get("created_at") or ""),
                    "backup_path": str(backup_dir),
                    "total_bytes": int(manifest.get("total_bytes") or 0),
                    "file_count": len(files) if isinstance(files, list) else 0,
                }
            )
        except Exception:
            continue
    return backups


def verify_backup(backup_dir: str | Path) -> Dict[str, Any]:
    resolved_backup_dir = Path(backup_dir).resolve()
    if not resolved_backup_dir.is_dir():
        raise FileNotFoundError(f"Backup directory not found: {resolved_backup_dir}")
    manifest = _load_manifest(resolved_backup_dir)
    files = manifest.get("files", [])
    if not isinstance(files, list) or not files:
        raise ValueError("Backup manifest is missing file entries")

    verified_files: List[Dict[str, Any]] = []
    for file_info in files:
        filename = str(file_info.get("name") or "").strip()
        expected_sha = str(file_info.get("sha256") or "").strip().lower()
        expected_size = int(file_info.get("size_bytes") or 0)
        if not filename or not expected_sha:
            raise ValueError("Backup manifest contains invalid file metadata")
        path = resolved_backup_dir / filename
        if not path.is_file():
            raise FileNotFoundError(f"Backup file missing: {path}")
        actual_sha = _sha256(path).lower()
        if actual_sha != expected_sha:
            raise ValueError(f"Checksum mismatch for {filename}")
        actual_size = int(path.stat().st_size)
        if expected_size != actual_size:
            raise ValueError(f"Size mismatch for {filename}")
        verified_files.append({"name": filename, "size_bytes": actual_size, "sha256": actual_sha})

    return {
        "backup_id": str(manifest.get("backup_id") or resolved_backup_dir.name),
        "backup_path": str(resolved_backup_dir),
        "created_at": str(manifest.get("created_at") or ""),
        "total_bytes": int(manifest.get("total_bytes") or 0),
        "files": verified_files,
    }


def restore_backup(backup_dir: str | Path, *, data_dir: str | Path | None = None) -> Dict[str, Any]:
    verified = verify_backup(backup_dir)
    resolved_data_dir = _resolve_data_dir(data_dir)
    resolved_data_dir.mkdir(parents=True, exist_ok=True)

    restored_files: List[Dict[str, Any]] = []
    for file_info in verified["files"]:
        filename = file_info["name"]
        source = Path(verified["backup_path"]) / filename
        destination = resolved_data_dir / filename
        temp_destination = resolved_data_dir / f".restore-{filename}.{os.getpid()}"
        shutil.copy2(source, temp_destination)
        os.replace(temp_destination, destination)
        restored_files.append(
            {
                "name": filename,
                "size_bytes": int(destination.stat().st_size),
                "sha256": _sha256(destination),
            }
        )

    return {
        "backup_id": verified["backup_id"],
        "backup_path": verified["backup_path"],
        "restored_at": _utc_now(),
        "data_dir": str(resolved_data_dir),
        "files": restored_files,
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Backup and restore triage platform state databases.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    backup_cmd = subparsers.add_parser("backup", help="Create a timestamped backup under data/backups.")
    backup_cmd.add_argument("--data-dir", default=None, help="Path to the data directory (default: ./data)")
    backup_cmd.add_argument("--backups-dir", default=None, help="Path to backups directory (default: <data>/backups)")

    list_cmd = subparsers.add_parser("list", help="List available backups.")
    list_cmd.add_argument("--data-dir", default=None, help="Path to the data directory (default: ./data)")
    list_cmd.add_argument("--backups-dir", default=None, help="Path to backups directory (default: <data>/backups)")

    restore_cmd = subparsers.add_parser("restore", help="Restore databases from a backup directory.")
    restore_cmd.add_argument("backup_dir", help="Path to a backup directory containing manifest.json")
    restore_cmd.add_argument("--data-dir", default=None, help="Path to the data directory (default: ./data)")

    return parser


def main(argv: List[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "backup":
            result = create_backup(data_dir=args.data_dir, backups_dir=args.backups_dir)
            print("Backup created")
            print(f"Backup ID: {result['backup_id']}")
            print(f"Backup path: {result['backup_path']}")
            print(f"Total bytes: {result['total_bytes']}")
            return 0

        if args.command == "list":
            backups = list_backups(data_dir=args.data_dir, backups_dir=args.backups_dir)
            if not backups:
                print("No backups found")
                return 0
            print("Available backups")
            for item in backups:
                print(
                    f"{item['backup_id']} | {item['created_at']} | {item['total_bytes']} bytes | {item['backup_path']}"
                )
            return 0

        if args.command == "restore":
            restored = restore_backup(args.backup_dir, data_dir=args.data_dir)
            print("Restore completed")
            print(f"Backup ID: {restored['backup_id']}")
            print(f"Data dir: {restored['data_dir']}")
            print(f"Files restored: {len(restored['files'])}")
            return 0
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
