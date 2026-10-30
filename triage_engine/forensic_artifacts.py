"""Verified offline forensic artifacts, separate from Windows event records."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Callable

from models.event_model import Alert
from triage_engine.path_safety import is_link_or_reparse, reject_path_links

KINDS = {"registry_run": "T1547.001", "scheduled_task": "T1053.005", "service": "T1543.003"}
NTFS_KINDS = {"ntfs_mft", "ntfs_usn_journal"}
ARTIFACT_FILE_KINDS = {"persistence_records", "chromium_history", "pecmd_jsonl", "prefetch_source", "scheduled_task_xml",
                       "registry_hive", *NTFS_KINDS}
# Registry hives have their own per-file and aggregate budget; other members share 64 MiB.
MAX_HIVE_BUNDLE_BYTES = 1024**3
# Members per bundle: one host's full System32\Tasks folder can hold hundreds of files.
# Memory and disk are bounded by the byte budgets, not by this count.
MAX_BUNDLE_MEMBERS = 1024
# NTFS members are streamed, never held in memory. Above the shared 64 MiB
# budget they need the operator's explicit allow_large_ntfs option.
NTFS_LARGE_LIMIT = 8 * 1024**3
ARTIFACT_BYTE_BUDGET = 64 * 1024**2


def _text(value, name: str, *, required: bool = False, limit: int = 65536) -> str:
    if not isinstance(value, str) or len(value) > limit or "\x00" in value:
        raise ValueError(f"Invalid {name}")
    if required and not value.strip():
        raise ValueError(f"Missing {name}")
    return value


def _json(content: bytes) -> dict:
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate artifact JSON key")
            result[key] = value
        return result

    def reject_constant(value):
        raise ValueError("Non-finite artifact JSON value")

    try:
        value = json.loads(content.decode("utf-8-sig"), object_pairs_hook=unique_object,
                           parse_constant=reject_constant)
    except (UnicodeError, RecursionError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid artifact JSON") from exc
    if not isinstance(value, dict) or value.get("schema_version") not in ("1.0", "1.1"):
        raise ValueError("Unsupported artifact schema_version")
    return value


@dataclass
class ForensicBundle:
    manifest: dict
    observations: list[dict]
    alerts: list[Alert]
    files: list[tuple[str, str]]
    file_hashes: dict[str, str]
    ntfs: object | None = None  # ntfs_artifacts.NtfsEvidence when $MFT/$J members are present


def _suspicious_configuration(command: str) -> str:
    # Indicators only concern configured launch behavior; no execution is inferred.
    if re.search(r"\b(?:powershell|pwsh)(?:\.exe)?\b", command, re.I):
        if re.search(r"(?:^|\s)-(?:enc|encodedcommand|e)(?:\s|:)", command, re.I):
            return "Encoded PowerShell launch configured"
        if re.search(r"https?://", command, re.I) and re.search(r"DownloadString|Invoke-WebRequest|\biwr\b|\biex\b|Invoke-Expression", command, re.I):
            return "PowerShell remote-content launch configured"
    if re.search(r"\b(?:mshta|regsvr32)(?:\.exe)?\b", command, re.I) and re.search(r"https?://", command, re.I):
        return "Remote script launcher configured"
    return ""


def read_forensic_bundle(
    bundle_path: str, *,
    retain_verified_sources: Callable[[list[tuple[str, str]], dict[str, str]], None] | None = None,
    temp_dir: str | Path | None = None, allow_large_ntfs: bool = False,
) -> ForensicBundle:
    supplied_root = Path(bundle_path).absolute()
    reject_path_links(supplied_root, "Artifact bundle root cannot use links or junctions")
    root = supplied_root.resolve()
    manifest_path = root / "manifest.json"
    if not root.is_dir() or is_link_or_reparse(manifest_path) or not manifest_path.is_file():
        raise ValueError("Artifact bundle requires a regular manifest.json")
    if manifest_path.stat().st_size > 1024 * 1024:
        raise ValueError("Artifact manifest exceeds 1 MiB")
    manifest_bytes = manifest_path.read_bytes()
    if len(manifest_bytes) > 1024 * 1024:
        raise ValueError("Artifact manifest exceeds 1 MiB")
    manifest = _json(manifest_bytes)
    file_hashes = {str(manifest_path): hashlib.sha256(manifest_bytes).hexdigest()}
    bundle_kind = manifest.get("kind")
    if (bundle_kind not in {"windows_persistence_snapshot", "windows_forensic_artifacts"}
            or (bundle_kind == "windows_forensic_artifacts" and manifest["schema_version"] != "1.1")):
        raise ValueError("Unsupported artifact bundle kind")
    host = _text(manifest.get("host"), "host", required=True, limit=256)
    observed_text = _text(manifest.get("observed_at"), "observed_at", required=True, limit=64)
    observed_at = datetime.fromisoformat(observed_text.replace("Z", "+00:00"))
    if observed_at.tzinfo is None:
        raise ValueError("Artifact observed_at must include a timezone")
    observed_at = observed_at.astimezone(timezone.utc)
    if manifest.get("completeness") not in {"complete", "partial"}:
        raise ValueError("Artifact completeness must be complete or partial")
    warnings = manifest.get("warnings", [])
    if not isinstance(warnings, list) or len(warnings) > 1024:
        raise ValueError("Invalid artifact collection warnings")
    for warning in warnings:
        _text(warning, "warning", limit=4096)
    if warnings and manifest["completeness"] == "complete":
        raise ValueError("Collection with warnings cannot claim complete")
    collector = manifest.get("collector")
    if not isinstance(collector, dict):
        raise ValueError("Artifact collector identity is required")
    _text(collector.get("name"), "collector name", required=True, limit=128)
    _text(collector.get("version"), "collector version", required=True, limit=128)
    files = manifest.get("files")
    if not isinstance(files, list) or not 1 <= len(files) <= MAX_BUNDLE_MEMBERS:
        raise ValueError(f"Artifact bundle must contain 1–{MAX_BUNDLE_MEMBERS} files")
    verified = []
    names = set()
    total = 0
    hive_total = 0
    for item in files:
        if not isinstance(item, dict) or item.get("kind") not in ARTIFACT_FILE_KINDS:
            raise ValueError("Unsupported artifact file kind")
        if bundle_kind == "windows_persistence_snapshot" and item["kind"] != "persistence_records":
            raise ValueError("Persistence snapshots accept persistence records only")
        name = _text(item.get("path"), "artifact path", required=True, limit=512)
        relative = PurePosixPath(name)
        if relative.is_absolute() or "\\" in name or ":" in name or any(part in {".", ".."} for part in name.split("/")) or "//" in name:
            raise ValueError("Unsafe artifact path")
        if name.casefold() in names or name.casefold() == "manifest.json":
            raise ValueError("Duplicate or reserved artifact path")
        names.add(name.casefold())
        path = root / relative
        current = path
        while current != root:
            if is_link_or_reparse(current):
                raise ValueError("Artifact path cannot use links or junctions")
            current = current.parent
        if not path.resolve().is_relative_to(root) or not path.is_file():
            raise ValueError("Artifact file missing or outside bundle")
        size = item.get("size_bytes")
        digest = item.get("sha256")
        if type(size) is not int or size < 0 or not isinstance(digest, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", digest):
            raise ValueError("Invalid artifact hash or size")
        large_ntfs = allow_large_ntfs and item["kind"] in NTFS_KINDS
        if large_ntfs and size > NTFS_LARGE_LIMIT:
            raise ValueError("NTFS artifact exceeds the 8 GiB member limit")
        if item["kind"] == "registry_hive":
            from triage_engine.registry_hive_artifacts import HIVE_TYPES, max_hive_bytes
            if item.get("hive_type") not in HIVE_TYPES:
                raise ValueError("Registry hive member requires hive_type ntuser, software, system or amcache")
            hive_total += size
            if size > max_hive_bytes() or hive_total > MAX_HIVE_BUNDLE_BYTES:
                raise ValueError("Registry hive byte budget exceeded")
        elif not large_ntfs:
            total += size
        if total > ARTIFACT_BYTE_BUDGET or path.stat().st_size != size:
            raise ValueError("Artifact byte budget or size mismatch"
                             + ("; large $MFT/$J members need the allow-large-NTFS option" if item["kind"] in NTFS_KINDS else ""))
        if item["kind"] in NTFS_KINDS:
            if "volume" in item and not (isinstance(item["volume"], str) and re.fullmatch(r"[A-Za-z]:", item["volume"])):
                raise ValueError("NTFS volume must be a drive letter such as C:")
            if any(other[4]["kind"] == item["kind"] for other in verified):
                raise ValueError("A bundle accepts one $MFT and one USN journal (one volume)")
            content_bytes = None  # Streamed: hashed here, re-hashed while parsing.
            hasher, read = hashlib.sha256(), 0
            with path.open("rb") as handle:
                for block in iter(lambda: handle.read(4 * 1024 * 1024), b""):
                    hasher.update(block)
                    read += len(block)
            if read != size or hasher.hexdigest() != digest.lower():
                raise ValueError("Artifact SHA-256 mismatch")
        else:
            with path.open("rb") as handle:
                content_bytes = handle.read(size + 1)
            if len(content_bytes) != size or hashlib.sha256(content_bytes).hexdigest() != digest.lower():
                raise ValueError("Artifact SHA-256 mismatch")
        if item["kind"] == "chromium_history":
            # A main-file-only copy must not silently omit uncheckpointed rows.
            for suffix in ("-wal", "-journal"):
                if Path(str(path) + suffix).exists():
                    raise ValueError("Browser History must be a standalone SQLite snapshot without WAL/journal sidecars")
        file_hashes[str(path)] = digest.lower()
        verified.append((path, name, digest.lower(), content_bytes, item))
    source_files = [(str(manifest_path), "artifact_manifest")] + [
        (str(path), item["kind"]) for path, _, _, _, item in verified
    ]
    # Validate the bounded acquisition envelope first; retain verified source
    # bytes before interpreting record JSON or constructing findings.
    if retain_verified_sources is not None:
        retain_verified_sources(source_files, file_hashes)
    observations = []
    alerts = []
    adapter_warnings = []
    ntfs = None
    ntfs_members = {item["kind"]: (path, name, digest, item) for path, name, digest, _, item in verified
                    if item["kind"] in NTFS_KINDS}
    if ntfs_members:
        volumes = {member[3]["volume"].upper() for member in ntfs_members.values() if "volume" in member[3]}
        if len(volumes) > 1:
            raise ValueError("$MFT and USN journal members name different volumes")
        from triage_engine.ntfs_artifacts import read_ntfs_members
        selected = {kind: member[:3] for kind, member in ntfs_members.items()}
        ntfs, parsed, warnings = read_ntfs_members(
            host=host, observed_at=observed_at.isoformat(), collector=collector, volume=next(iter(volumes), ""),
            mft=selected.get("ntfs_mft"), usn=selected.get("ntfs_usn_journal"))
        observations.extend(parsed)
        adapter_warnings.extend(warnings)
    for path, name, digest, content_bytes, item in verified:
        context = {"source_name": name, "source_sha256": digest, "host": host,
                   "observed_at": observed_at.isoformat(), "collector": collector}
        if item["kind"] in NTFS_KINDS:
            continue  # Parsed above from the streamed members.
        if item["kind"] == "prefetch_source":
            from triage_engine.prefetch_binary import parse_prefetch_binary
            # A damaged or unsupported .pf stays retained and makes the analysis partial.
            try:
                parsed, warnings = parse_prefetch_binary(
                    content_bytes, original_name=str(item.get("original_name", ""))[:512],
                    **{key: value for key, value in context.items() if key != "collector"})
            except ValueError as exc:
                parsed, warnings = [], [f"Prefetch binary {name} not parsed: {exc}"]
            observations.extend(parsed)
            adapter_warnings.extend(warnings)
        elif item["kind"] == "chromium_history":
            from triage_engine.browser_artifacts import parse_chromium_downloads
            parse_temp = Path(temp_dir) if temp_dir is not None else Path(__file__).resolve().parents[1] / "runtime" / "temp" / "artifact-parsers"
            reject_path_links(parse_temp, "Artifact parser temporary path cannot use links or junctions")
            parse_temp.mkdir(parents=True, exist_ok=True)
            observations.extend(parse_chromium_downloads(content_bytes, temp_dir=parse_temp, **context))
        elif item["kind"] == "scheduled_task_xml":
            from triage_engine.task_xml_artifacts import parse_task_xml
            parsed, warnings = parse_task_xml(content_bytes, original_name=str(item.get("original_name", "")), **context)
            observations.extend(parsed)
            adapter_warnings.extend(warnings)
            for observation in parsed:
                alert = _configuration_alert(observation)
                if alert is not None:
                    alerts.append(alert)
        elif item["kind"] == "registry_hive":
            from triage_engine.registry_hive_artifacts import parse_registry_hive
            parsed, warnings = parse_registry_hive(content_bytes, hive_type=item["hive_type"],
                                                   original_name=str(item.get("original_name", "")), **context)
            observations.extend(parsed)
            adapter_warnings.extend(warnings)
            alerts.extend(alert for alert in map(_configuration_alert, parsed) if alert is not None)
        elif item["kind"] == "pecmd_jsonl":
            from triage_engine.prefetch_artifacts import parse_pecmd_jsonl
            exporter = item.get("exporter")
            if not isinstance(exporter, dict):
                raise ValueError("PECmd input requires exporter name and version")
            parsed, warnings = parse_pecmd_jsonl(content_bytes, **{**context, "collector": exporter})
            observations.extend(parsed)
            adapter_warnings.extend(warnings)
        else:
            _read_persistence_records(content_bytes, name, digest, host, observed_text,
                                      observed_at, collector, observations, alerts)
        if len(observations) > 50000:
            raise ValueError("Artifact records exceed 50000 observations")
    _note_shared_prefetch_sources(observations)
    if adapter_warnings:
        manifest = {**manifest, "completeness": "partial", "warnings": [*manifest.get("warnings", []), *adapter_warnings]}
    return ForensicBundle(manifest, observations, alerts, source_files, file_hashes, ntfs)


SHARED_PREFETCH_NOTE = (" The same Prefetch file appears to be read by both PECmd and the native parser; two tools "
                        "reading one file are not independent corroboration.")


def _note_shared_prefetch_sources(observations: list[dict]) -> None:
    """Flag exporter and native observations that describe the same Prefetch name and hash."""
    keys: dict[str, set] = {"PECmd": set(), "triage-prefetch-binary": set()}
    prefetch = [o for o in observations if o["kind"] in {"prefetch_run", "prefetch_record"}]
    for observation in prefetch:
        details = observation["details"]
        key = (str(details.get("name", "")).casefold(), str(details.get("prefetch_hash", "")).upper())
        keys.get(observation["collector"].get("name"), set()).add(key)
    shared = keys["PECmd"] & keys["triage-prefetch-binary"]
    for observation in prefetch:
        details = observation["details"]
        if (str(details.get("name", "")).casefold(), str(details.get("prefetch_hash", "")).upper()) in shared:
            observation["interpretation"] += SHARED_PREFETCH_NOTE
            details["shared_source_parsers"] = ["PECmd", "triage-prefetch-binary"]


def _read_persistence_records(content_bytes, name, digest, host, observed_text,
                              observed_at, collector, observations, alerts):
    content = _json(content_bytes)
    records = content.get("records")
    if not isinstance(records, list) or len(records) + len(observations) > 50000:
        raise ValueError("Artifact records must be a bounded list")
    for index, record in enumerate(records):
        if not isinstance(record, dict) or record.get("kind") not in KINDS:
            raise ValueError("Unsupported persistence record kind")
        if set(record) - {"kind", "name", "location", "command", "user", "state", "enabled"}:
            raise ValueError("Unsupported persistence record field")
        for key in ("name", "location", "command"):
            _text(record.get(key), key, required=key != "command")
        for key in ("user", "state"):
            if key in record:
                _text(record[key], key)
        if "enabled" in record and type(record["enabled"]) is not bool:
            raise ValueError("Artifact enabled must be boolean")
        identity = json.dumps([digest, index, host, observed_text], separators=(",", ":"))
        observation_id = "obs_" + hashlib.sha256(identity.encode()).hexdigest()
        observation = {"id": observation_id, "kind": record["kind"], "host": host,
                       "observed_at": observed_at.isoformat(), "time_semantics": "collection_snapshot",
                       "interpretation": "observed_configuration; execution_unconfirmed",
                       "source_id": "evi_" + digest, "source_file": name, "source_record": index,
                       "source_sha256": digest, "collector": collector, "details": record}
        observations.append(observation)
        alert = _configuration_alert(observation)
        if alert is not None:
            alerts.append(alert)


def _configuration_alert(observation: dict) -> Alert | None:
    if observation["kind"] not in KINDS:
        return None
    record = observation["details"]
    reason = _suspicious_configuration(record.get("command", ""))
    if not reason:
        return None
    index, digest, host = observation["source_record"], observation["source_sha256"], observation["host"]
    observation_id = observation["id"]
    observed_at = datetime.fromisoformat(observation["observed_at"])
    return Alert(
            rule_name=f"Persistence Snapshot: {reason}", severity="medium", mitre_tactic="Persistence",
            mitre_technique=KINDS[observation["kind"]], description=f"{record['name']}: {reason}.",
            explanation="Suspicious persisted launch configuration observed; execution and malicious intent require validation.",
            event=None, timestamp=observed_at, host=host, user=record.get("user", ""),
            service=record["name"] if observation["kind"] == "service" else "",
            scheduled_task=record["name"] if observation["kind"] == "scheduled_task" else "",
            registry_key=record["location"] if observation["kind"] == "registry_run" else "",
            process=record["command"], rule_source="forensic_artifact", confidence="medium",
            confidence_factors=["observed_persistence_configuration", "execution_unconfirmed"],
            promotion_policy="standalone",
            investigate_next="Validate ownership and intended configuration; seek independent evidence of execution.",
            evidence={"observation_id": observation_id, "source_id": "evi_" + digest,
                      "source_record": index, "source_sha256": digest, "command_line": record["command"],
                      "artifact_kind": observation["kind"], "time_semantics": "collection_snapshot",
                      "execution_confirmed": False, "evidence_strength": "medium"})
