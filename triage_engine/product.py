"""Low-cost MSP workflow primitives.

This module deliberately keeps customer metadata and workflow state separate
from immutable investigation artifacts.  It is usable by the CLI, API, and
future packaged desktop launcher without requiring a cloud service.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sqlite3
import sys
import tempfile
import uuid
import zipfile
import urllib.error
import urllib.request
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from triage_engine.db_migrate import run_migrations

SCHEMA_VERSION = "1.0"
ACQUISITION_METHODS = ("upload", "local_live", "portable_collector", "remote_collection")
DISPOSITIONS = ("Escalate", "Investigate", "Monitor", "No promoted incident")


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _data_dir() -> str:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    configured = os.environ.get("TRIAGE_DATA_DIR", "").strip()
    if not configured and getattr(sys, "frozen", False):
        local_app_data = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~/AppData/Local")
        return os.path.abspath(os.path.join(local_app_data, "TriageEngine", "data"))
    return os.path.abspath(configured or os.path.join(root, "data"))


@dataclass
class ClientProfile:
    client_id: str
    display_name: str
    report_name: str = ""
    contact: str = ""
    logo: str = ""
    accent_color: str = "#2563eb"
    retention_days: int = 90
    active: bool = True
    schema_version: str = SCHEMA_VERSION
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CollectionManifest:
    method: str
    source_host: str = ""
    collected_at: str = field(default_factory=utc_now)
    timezone: str = "UTC"
    channels: List[str] = field(default_factory=list)
    failures: List[Dict[str, Any]] = field(default_factory=list)
    tool_version: str = ""
    files: List[Dict[str, Any]] = field(default_factory=list)
    schema_version: str = SCHEMA_VERSION

    def validate(self) -> None:
        if self.method not in ACQUISITION_METHODS:
            raise ValueError(f"Unsupported acquisition method: {self.method}")
        for item in self.files:
            if not isinstance(item, dict):
                raise ValueError("Collection manifest files must be objects")
            path_value = str(item.get("path", ""))
            path_obj = Path(path_value)
            if item.get("path") and (path_obj.is_absolute() or path_obj.drive or path_value.startswith(("/", "\\")) or ".." in path_obj.parts):
                raise ValueError("Collection manifest paths cannot escape their bundle")

    def to_dict(self) -> Dict[str, Any]:
        self.validate()
        return asdict(self)


@dataclass
class CaseMetadata:
    case_name: str
    client_id: str = "default"
    acquisition_method: str = "upload"
    created_at: str = field(default_factory=utc_now)
    retention_until: str = ""
    collection_manifest: Dict[str, Any] = field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> Dict[str, Any]:
        if self.acquisition_method not in ACQUISITION_METHODS:
            raise ValueError(f"Unsupported acquisition method: {self.acquisition_method}")
        return asdict(self)


@dataclass
class TriageDisposition:
    disposition: str
    confidence: str
    confidence_score: int
    reasons: List[str] = field(default_factory=list)
    telemetry_gaps: List[str] = field(default_factory=list)
    recommended_next: List[str] = field(default_factory=list)
    source: str = "deterministic"
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> Dict[str, Any]:
        if self.disposition not in DISPOSITIONS:
            raise ValueError(f"Unsupported disposition: {self.disposition}")
        return asdict(self)


@dataclass
class ExportManifest:
    case_name: str
    client_id: str
    created_at: str
    files: List[Dict[str, Any]]
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def derive_disposition(*, incident_count: int, finding_count: int, response_priority: str,
                       confidence_score: int = 0, telemetry_gaps: Optional[Iterable[str]] = None,
                       reasons: Optional[Iterable[str]] = None) -> TriageDisposition:
    """Return an explainable conclusion without pretending to prove compromise."""
    gaps = list(telemetry_gaps or [])
    why = list(reasons or [])
    priority = str(response_priority or "P4").upper()
    if incident_count and (priority in {"P1", "P2"} or confidence_score >= 75):
        disposition = "Escalate"
    elif incident_count or finding_count:
        disposition = "Investigate"
    elif gaps:
        disposition = "Monitor"
    else:
        disposition = "No promoted incident"
    if not why:
        why = [f"{incident_count} promoted incident(s)", f"{finding_count} finding(s)"]
    next_steps = ["Validate scope across affected hosts and users"] if disposition != "No promoted incident" else []
    return TriageDisposition(disposition, "high" if confidence_score >= 75 else "medium" if finding_count else "low",
                             max(0, min(100, int(confidence_score or 0))), why, gaps, next_steps)


class ClientStore:
    def __init__(self, data_dir: Optional[str] = None):
        self.data_dir = os.path.abspath(data_dir or _data_dir())
        self.db_path = os.path.join(self.data_dir, "product.db")
        self._init()

    @contextmanager
    def _conn(self):
        os.makedirs(self.data_dir, exist_ok=True)
        con = sqlite3.connect(self.db_path, timeout=10)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA journal_mode=WAL")
        try:
            yield con
            con.commit()
        finally:
            con.close()

    def _init(self):
        def initial(con):
            con.executescript("""
            CREATE TABLE IF NOT EXISTS client_profiles (
              client_id TEXT PRIMARY KEY, display_name TEXT NOT NULL, report_name TEXT NOT NULL DEFAULT '',
              contact TEXT NOT NULL DEFAULT '', logo TEXT NOT NULL DEFAULT '', accent_color TEXT NOT NULL DEFAULT '#2563eb',
              retention_days INTEGER NOT NULL DEFAULT 90, active INTEGER NOT NULL DEFAULT 1,
              created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS case_metadata (
              case_name TEXT PRIMARY KEY, client_id TEXT NOT NULL, acquisition_method TEXT NOT NULL,
              created_at TEXT NOT NULL, retention_until TEXT NOT NULL DEFAULT '', manifest_json TEXT NOT NULL DEFAULT '{}'
            );
            """)
        with self._conn() as con:
            run_migrations(con, (("001_product", initial),), namespace="product")
            row = con.execute("SELECT client_id FROM client_profiles WHERE client_id='default'").fetchone()
            if not row:
                now = utc_now()
                con.execute("INSERT INTO client_profiles(client_id,display_name,report_name,created_at,updated_at) VALUES(?,?,?,?,?)",
                            ("default", "Default Client", "Triage Engine Investigation", now, now))

    def upsert_client(self, profile: ClientProfile) -> ClientProfile:
        if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$", profile.client_id):
            raise ValueError("client_id must be 1-64 alphanumeric characters, dash, or underscore")
        profile.retention_days = max(1, min(3650, int(profile.retention_days)))
        profile.updated_at = utc_now()
        with self._conn() as con:
            con.execute("""INSERT INTO client_profiles VALUES(?,?,?,?,?,?,?,?,?,?)
              ON CONFLICT(client_id) DO UPDATE SET display_name=excluded.display_name,report_name=excluded.report_name,
              contact=excluded.contact,logo=excluded.logo,accent_color=excluded.accent_color,retention_days=excluded.retention_days,
              active=excluded.active,updated_at=excluded.updated_at""",
              (profile.client_id, profile.display_name, profile.report_name, profile.contact, profile.logo,
               profile.accent_color, profile.retention_days, int(profile.active), profile.created_at, profile.updated_at))
        return profile

    def get_client(self, client_id: str) -> Optional[ClientProfile]:
        with self._conn() as con:
            row = con.execute("SELECT * FROM client_profiles WHERE client_id=?", (client_id,)).fetchone()
        if not row: return None
        return ClientProfile(**{**dict(row), "active": bool(row["active"])})

    def list_clients(self, active_only: bool = False) -> List[ClientProfile]:
        q = "SELECT * FROM client_profiles" + (" WHERE active=1" if active_only else "") + " ORDER BY display_name"
        with self._conn() as con: rows = con.execute(q).fetchall()
        return [ClientProfile(**{**dict(r), "active": bool(r["active"])}) for r in rows]

    def delete_client(self, client_id: str) -> bool:
        if client_id == "default": return False
        with self._conn() as con:
            cur = con.execute("UPDATE client_profiles SET active=0,updated_at=? WHERE client_id=?", (utc_now(), client_id))
        return cur.rowcount > 0

    def save_case_metadata(self, metadata: CaseMetadata) -> CaseMetadata:
        metadata.to_dict()
        client = self.get_client(metadata.client_id) or self.get_client("default")
        if client is None: raise ValueError("Default client profile is missing")
        metadata.client_id = client.client_id
        metadata.retention_until = metadata.retention_until or (datetime.now(timezone.utc) + timedelta(days=client.retention_days)).replace(microsecond=0).isoformat()
        with self._conn() as con:
            con.execute("""INSERT INTO case_metadata VALUES(?,?,?,?,?,?) ON CONFLICT(case_name) DO UPDATE SET
              client_id=excluded.client_id,acquisition_method=excluded.acquisition_method,retention_until=excluded.retention_until,manifest_json=excluded.manifest_json""",
              (metadata.case_name, metadata.client_id, metadata.acquisition_method, metadata.created_at, metadata.retention_until, json.dumps(metadata.collection_manifest)))
        return metadata

    @staticmethod
    def _metadata_from_row(row: sqlite3.Row) -> CaseMetadata:
        return CaseMetadata(row["case_name"], row["client_id"], row["acquisition_method"], row["created_at"], row["retention_until"], json.loads(row["manifest_json"] or "{}"))

    def get_case_metadata(self, case_name: str) -> Optional[CaseMetadata]:
        with self._conn() as con: row = con.execute("SELECT * FROM case_metadata WHERE case_name=?", (case_name,)).fetchone()
        if not row: return None
        return self._metadata_from_row(row)

    def all_case_metadata(self) -> Dict[str, CaseMetadata]:
        """Bulk lookup for list views; one query instead of one connection per case."""
        with self._conn() as con: rows = con.execute("SELECT * FROM case_metadata").fetchall()
        result: Dict[str, CaseMetadata] = {}
        for row in rows:
            try:
                result[row["case_name"]] = self._metadata_from_row(row)
            except (TypeError, ValueError):
                continue
        return result

    def purge_case_metadata(self, case_name: str) -> bool:
        with self._conn() as con: cur = con.execute("DELETE FROM case_metadata WHERE case_name=?", (case_name,))
        return cur.rowcount > 0



def _bundle_member_name(value: Any) -> str:
    """Return a strict relative POSIX ZIP member name or raise."""

    text = str(value or "").replace("\\", "/")
    if not text or "\x00" in text or text.startswith("/") or re.match(r"^[A-Za-z]:", text):
        raise ValueError("Bundle member paths must be relative and NUL-free")
    parts = text.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError("Bundle member paths cannot contain empty, dot, or parent components")
    return "/".join(parts)


def _realpath_within(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([os.path.realpath(path), os.path.realpath(root)]) == os.path.realpath(root)
    except ValueError:
        return False


def _zipinfo_is_link(info: zipfile.ZipInfo) -> bool:
    mode = (int(info.external_attr) >> 16) & 0xFFFF
    return (mode & 0o170000) == 0o120000


def _checked_case_artifact(case_dir: str, member: str) -> Path:
    path = Path(case_dir).joinpath(*member.split("/"))
    current = path
    root = Path(case_dir)
    while current != root:
        if current.is_symlink() or getattr(current, "is_junction", lambda: False)():
            raise ValueError(f"Case artifact cannot use links or junctions: {member}")
        current = current.parent
    if not path.is_file() or not _realpath_within(str(path), case_dir):
        raise ValueError(f"Case artifact must be a regular file within the case: {member}")
    return path


def export_case_bundle(
    case_path: str,
    output_path: Optional[str] = None,
    *,
    client_id: str = "default",
    extra_files: Optional[Iterable[str]] = None,
    extra_payloads: Optional[Dict[str, bytes]] = None,
    include_sources: bool = False,
) -> str:
    """Create a deterministic, scope-confined ZIP evidence package."""

    case_dir = os.path.realpath(os.path.abspath(case_path))
    if not os.path.isdir(case_dir):
        raise FileNotFoundError(case_dir)
    output = os.path.abspath(output_path or os.path.join(case_dir, f"{os.path.basename(case_dir)}-bundle.zip"))
    if os.path.islink(output):
        raise ValueError("Bundle output cannot be a symbolic link")
    if _realpath_within(output, case_dir):
        relative_output = Path(os.path.realpath(output)).relative_to(case_dir)
        default_output = os.path.join(case_dir, f"{os.path.basename(case_dir)}-bundle.zip")
        if (relative_output.parts[0].casefold() in {"evidence", "runs"}
                or (os.path.exists(output) and os.path.normcase(output) != os.path.normcase(default_output))):
            raise ValueError("Bundle output cannot overwrite case evidence or retained outputs")
    os.makedirs(os.path.dirname(output) or ".", exist_ok=True)

    selected: list[tuple[str, str]] = []
    selected_names: set[str] = set()
    standard_names = (
        "report.html",
        "summary.txt",
        "incident_brief.md",
        "findings.json",
        "timeline.json",
        "graph.json",
        "run_status.json",
        "case_metadata.json",
        "case_identity.json",
        "evidence_manifest.json",
        "analysis_manifest.json",
        "forensic_observations.json",
        "evidence_relationships.json",
    )
    for name in standard_names:
        path = os.path.join(case_dir, name)
        if not os.path.exists(path) and not os.path.islink(path):
            continue
        path = str(_checked_case_artifact(case_dir, name))
        member = _bundle_member_name(name)
        selected.append((member, path))
        selected_names.add(member.casefold())

    source_metadata: Dict[str, Dict[str, Any]] = {}
    output_metadata: Dict[str, Dict[str, Any]] = {}
    captured_metadata: Dict[str, bytes] = {}
    current_run = None
    # New forensic cases publish a run identity. Do not package a failed/running
    # rerun's mutable outputs with the previous completed analysis manifest.
    analysis_path = Path(case_dir) / "analysis_manifest.json"
    identity_path = Path(case_dir) / "case_identity.json"
    if identity_path.exists() and not analysis_path.exists():
        identity = json.loads(_checked_case_artifact(case_dir, "case_identity.json").read_text(encoding="utf-8"))
        if isinstance(identity, dict) and identity.get("case_id"):
            raise ValueError("Case has no completed analysis manifest")
    if analysis_path.exists():
        analysis_bytes = _checked_case_artifact(case_dir, "analysis_manifest.json").read_bytes()
        captured_metadata["analysis_manifest.json"] = analysis_bytes
        analysis = json.loads(analysis_bytes)
        current_run = analysis.get("run_id") if isinstance(analysis, dict) else None
        if current_run:
            status = json.loads(_checked_case_artifact(case_dir, "run_status.json").read_text(encoding="utf-8"))
            if status.get("status") != "completed" or status.get("metadata", {}).get("run_id") != current_run:
                raise ValueError("Case outputs do not belong to a completed current analysis run")
            for metadata_name in ("evidence_manifest.json", "forensic_observations.json", "evidence_relationships.json"):
                if metadata_name == "evidence_relationships.json" and not (Path(case_dir) / metadata_name).exists():
                    continue  # Written by later versions; earlier completed cases remain exportable.
                metadata = json.loads(_checked_case_artifact(case_dir, metadata_name).read_text(encoding="utf-8"))
                if metadata.get("run_id") != current_run:
                    raise ValueError("Case contains output from a different analysis run")
            findings = json.loads(_checked_case_artifact(case_dir, "findings.json").read_text(encoding="utf-8"))
            if findings.get("case", {}).get("run_id") != current_run:
                raise ValueError("Findings belong to a different analysis run")
            for artifact in analysis.get("outputs", []):
                if not isinstance(artifact, dict):
                    raise ValueError("Invalid analysis output metadata")
                member = _bundle_member_name(artifact.get("path", ""))
                path = _checked_case_artifact(case_dir, member)
                data = path.read_bytes()
                if len(data) != artifact.get("size_bytes") or hashlib.sha256(data).hexdigest() != artifact.get("sha256"):
                    raise ValueError("Case output hash differs from the completed analysis run")
                output_metadata[member] = artifact
    if include_sources is True:
        manifest_path = _checked_case_artifact(case_dir, "evidence_manifest.json")
        evidence_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(evidence_manifest, dict) or not isinstance(evidence_manifest.get("sources"), list):
            raise ValueError("Evidence manifest must contain a sources list")
        for entry in evidence_manifest["sources"]:
            if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
                raise ValueError("Invalid evidence source metadata")
            member = _bundle_member_name(entry["path"])
            if not member.casefold().startswith("evidence/"):
                raise ValueError("Original evidence sources must be inside evidence/")
            checksum, size = entry.get("sha256"), entry.get("size_bytes")
            if (not isinstance(checksum, str) or len(checksum) != 64
                    or any(char not in "0123456789abcdef" for char in checksum)
                    or type(size) is not int or size < 0):
                raise ValueError("Invalid evidence source hash or size")
            path = _checked_case_artifact(case_dir, member)
            data = path.read_bytes()
            if len(data) != size or hashlib.sha256(data).hexdigest() != checksum:
                raise ValueError(f"Evidence source hash or size mismatch: {member}")
            if member in source_metadata:
                if source_metadata[member] != {"sha256": checksum, "size_bytes": size}:
                    raise ValueError(f"Conflicting evidence source metadata: {member}")
                continue  # Capture may reference identical bytes more than once.
            source_metadata[member] = {"sha256": checksum, "size_bytes": size}
            selected.append((member, str(path)))
            selected_names.add(member.casefold())
        raw_path = Path(case_dir) / "raw_events.jsonl"
        if raw_path.exists() or raw_path.is_symlink():
            selected.append(("raw_events.jsonl", str(_checked_case_artifact(case_dir, "raw_events.jsonl"))))
            selected_names.add("raw_events.jsonl")

    for item in extra_files or []:
        candidate = os.path.abspath(str(item))
        resolved = os.path.realpath(candidate)
        if not os.path.isfile(candidate) or not _realpath_within(resolved, case_dir):
            continue
        member = _bundle_member_name(os.path.relpath(candidate, case_dir))
        _checked_case_artifact(case_dir, member)
        if member.casefold().startswith("runs/"):
            raise ValueError("Historical run outputs cannot be supplied through extra_files")
        if Path(member).name.casefold() == "raw_events.jsonl" or member.casefold().startswith("evidence/"):
            if member.casefold() not in selected_names:
                raise ValueError("Raw evidence requires include_sources=True and validated source metadata")
        if member.casefold() in selected_names:
            continue
        selected.append((member, resolved))
        selected_names.add(member.casefold())

    payloads: list[tuple[str, bytes]] = []
    for rel, data in (extra_payloads or {}).items():
        member = _bundle_member_name(rel)
        if member.casefold() == "export_manifest.json":
            raise ValueError("export_manifest.json is reserved")
        if member.casefold().startswith("runs/"):
            raise ValueError("Historical run outputs cannot be supplied through extra_payloads")
        if Path(member).name.casefold() == "raw_events.jsonl" or member.casefold().startswith("evidence/"):
            raise ValueError("Raw evidence cannot be supplied through extra_payloads")
        if member.casefold() in selected_names or any(existing.casefold() == member.casefold() for existing, _ in payloads):
            raise ValueError(f"Duplicate bundle member: {member}")
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError(f"Bundle payload must be bytes: {member}")
        payloads.append((member, bytes(data)))

    entries: list[Dict[str, Any]] = []
    if any(os.path.realpath(path) == os.path.realpath(output) for _, path in selected):
        raise ValueError("Bundle output cannot overwrite a selected case artifact")

    def write_bundle(destination):
        with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
            for member, path in selected:
                data = captured_metadata.get(member)
                if data is None:
                    data = _checked_case_artifact(case_dir, member).read_bytes()
                if member in output_metadata:
                    expected = output_metadata[member]
                    if len(data) != expected["size_bytes"] or hashlib.sha256(data).hexdigest() != expected["sha256"]:
                        raise ValueError(f"Case output changed during export: {member}")
                if member in source_metadata:
                    expected = source_metadata[member]
                    if len(data) != expected["size_bytes"] or hashlib.sha256(data).hexdigest() != expected["sha256"]:
                        raise ValueError(f"Evidence source changed during export: {member}")
                zf.writestr(member, data)
                entries.append({"path": member, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
            for member, data in payloads:
                zf.writestr(member, data)
                entries.append({"path": member, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
            manifest = ExportManifest(os.path.basename(case_dir), str(client_id or "default"), utc_now(), entries)
            export_metadata = manifest.to_dict()
            export_metadata["source_policy"] = {
                "include_sources": include_sources is True,
                "original_sources": "unredacted" if include_sources is True else "excluded",
                "raw_events": "unredacted" if "raw_events.jsonl" in selected_names else "excluded",
                "derived_artifacts": "as stored, with existing pipeline demo sanitization",
                "provenance_manifests": "as stored; recorded source hashes are preserved",
            }
            zf.writestr("export_manifest.json", json.dumps(export_metadata, indent=2, sort_keys=True).encode("utf-8"))

    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=os.path.dirname(output), prefix=".bundle-", suffix=".partial", delete=False) as handle:
            temporary = handle.name
        write_bundle(temporary)
        if current_run:
            status = json.loads(_checked_case_artifact(case_dir, "run_status.json").read_text(encoding="utf-8"))
            if status.get("status") != "completed" or status.get("metadata", {}).get("run_id") != current_run:
                raise ValueError("Case changed to a different analysis run during export")
        os.replace(temporary, output)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)
    return output


def verify_case_bundle(bundle_path: str) -> Dict[str, Any]:
    """Verify a bundle's schema, paths, membership, and every artifact hash."""

    try:
        archive = zipfile.ZipFile(bundle_path, "r", allowZip64=True)
    except (OSError, zipfile.BadZipFile) as exc:
        raise ValueError(f"Invalid case bundle: {exc}") from exc

    with archive as zf:
        infos = zf.infolist()
        names = [info.filename for info in infos]
        failures: list[Dict[str, Any]] = []
        if len(names) != len(set(names)):
            failures.append({"path": "", "reason": "duplicate_archive_member"})
        info_by_name: Dict[str, zipfile.ZipInfo] = {}
        safe_names: set[str] = set()
        for info in infos:
            name = info.filename
            try:
                safe_name = _bundle_member_name(name)
            except ValueError:
                failures.append({"path": name, "reason": "unsafe_archive_member"})
                continue
            if name != safe_name:
                failures.append({"path": name, "reason": "noncanonical_archive_member"})
                continue
            if name.endswith("/") or _zipinfo_is_link(info):
                failures.append({"path": name, "reason": "non_file_archive_member"})
                continue
            safe_names.add(safe_name)
            info_by_name[safe_name] = info

        manifest_info = info_by_name.get("export_manifest.json")
        if manifest_info is None:
            raise ValueError("Bundle is missing a valid export_manifest.json")
        if manifest_info.file_size > 1024 * 1024:
            raise ValueError("Bundle manifest is too large")
        try:
            manifest = json.loads(zf.read(manifest_info))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Bundle is missing a valid export_manifest.json") from exc
        if not isinstance(manifest, dict):
            raise ValueError("Bundle manifest must be an object")

        schema_version = str(manifest.get("schema_version", "") or "")
        if schema_version != SCHEMA_VERSION:
            failures.append({"path": "export_manifest.json", "reason": "unsupported_schema_version"})
        raw_entries = manifest.get("files")
        if not isinstance(raw_entries, list):
            raise ValueError("Bundle manifest files must be a list")

        listed_names: set[str] = set()
        for entry in raw_entries:
            if not isinstance(entry, dict):
                failures.append({"path": "", "reason": "invalid_manifest_entry"})
                continue
            raw_path = str(entry.get("path", "") or "")
            try:
                member = _bundle_member_name(raw_path)
            except ValueError:
                failures.append({"path": raw_path, "reason": "unsafe_manifest_path"})
                continue
            if member == "export_manifest.json":
                failures.append({"path": member, "reason": "manifest_self_reference"})
                continue
            if member in listed_names:
                failures.append({"path": member, "reason": "duplicate_manifest_entry"})
                continue
            listed_names.add(member)
            info = info_by_name.get(member)
            if info is None:
                failures.append({"path": member, "reason": "missing"})
                continue
            expected_size = entry.get("size")
            digest = str(entry.get("sha256", "") or "").lower()
            if isinstance(expected_size, bool) or not isinstance(expected_size, int) or expected_size < 0:
                failures.append({"path": member, "reason": "invalid_size"})
                continue
            if not re.fullmatch(r"[0-9a-f]{64}", digest):
                failures.append({"path": member, "reason": "invalid_sha256"})
                continue
            data = zf.read(info)
            actual_digest = hashlib.sha256(data).hexdigest()
            if len(data) != expected_size or not hmac.compare_digest(actual_digest, digest):
                failures.append({"path": member, "reason": "hash_or_size_mismatch"})

        expected_names = listed_names | {"export_manifest.json"}
        for name in sorted(safe_names - expected_names):
            failures.append({"path": name, "reason": "unlisted_archive_member"})
        return {
            "valid": not failures,
            "schema_version": schema_version,
            "files_checked": len(raw_entries),
            "failures": failures,
        }

class LicenseRecord:
    edition: str
    licensee: str = ""
    expires_at: str = ""
    features: List[str] = field(default_factory=list)
    signature: str = ""
    schema_version: str = SCHEMA_VERSION


def sign_license(record: Dict[str, Any], secret: str) -> Dict[str, Any]:
    """Create an offline HMAC-signed license payload for controlled deployments."""
    import hmac
    payload = dict(record)
    payload.pop("signature", None)
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload["signature"] = hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
    return payload


def verify_license(record: Dict[str, Any], secret: str, *, now: Optional[datetime] = None) -> Dict[str, Any]:
    import hmac
    payload = dict(record or {})
    signature = str(payload.pop("signature", ""))
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    valid = bool(secret) and bool(signature) and hmac.compare_digest(signature, hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest())
    expiry = str(payload.get("expires_at", "") or "")
    if expiry:
        try:
            dt = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
            valid = valid and dt.replace(tzinfo=dt.tzinfo or timezone.utc) >= (now or datetime.now(timezone.utc))
        except ValueError:
            valid = False
    return {"valid": valid, "edition": str(payload.get("edition", "community")), "features": list(payload.get("features", []) or []), "licensee": str(payload.get("licensee", "")), "expires_at": expiry}


def load_license_file(path: str, secret: str) -> Dict[str, Any]:
    """Load and verify an offline license without network calls or telemetry."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            record = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {"valid": False, "edition": "community", "features": [], "licensee": "", "expires_at": ""}
    return verify_license(record, secret)


def capabilities(edition: str = "community") -> Dict[str, bool]:
    pro = str(edition).lower() == "pro"
    return {"analysis": True, "dashboard": True, "live_local": True, "client_profiles": pro, "bundle_export": pro, "webhooks": pro, "ai": pro, "remote_collection": pro}
