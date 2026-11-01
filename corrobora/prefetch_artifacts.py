"""Bounded parser for PECmd's line-delimited JSON Prefetch export."""

from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import datetime, timezone


MAX_CONTENT = 64 * 1024 * 1024
MAX_OBSERVATIONS = 50_000
MAX_RECORD = 64 * 1024
MAX_STRING = 64 * 1024
RUN_FIELDS = ("LastRun", *(f"PreviousRun{i}" for i in range(7)))
REQUIRED = ("SourceFilename", "ExecutableName", "RunCount", "LastRun", "Version", "ParsingError")
OFFICIAL_FIELDS = {
    "Note", "SourceFilename", "SourceCreated", "SourceModified", "SourceAccessed",
    "ExecutableName", "Hash", "Size", "Version", "RunCount", *RUN_FIELDS,
    "Volume0Name", "Volume0Serial", "Volume0Created", "Volume1Name", "Volume1Serial",
    "Volume1Created", "Directories", "FilesLoaded", "ParsingError",
}
_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
_PE_TIMESTAMP = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})[ T]"
    r"(?P<clock>\d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<fraction>\d{1,7}))?"
    r"(?P<offset>Z|[+-]\d{2}:\d{2})$"
)


def _reject_constant(value: str):
    raise ValueError(f"Invalid JSON constant: {value}")


def _finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("Non-finite JSON number")
    return parsed


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _timestamp(value: str) -> tuple[str, str]:
    if not isinstance(value, str) or not value or len(value) > MAX_STRING:
        raise ValueError("Invalid PECmd run timestamp")
    # Supported PECmd --dt output has an ISO date/time, optional
    # 1-7 digit fractional seconds, and an explicit UTC offset. Defaults are naive.
    # Python 3.10 only
    # accepts up to six fractional digits, so retain the source and normalize
    # only the value passed to fromisoformat.
    match = _PE_TIMESTAMP.fullmatch(value)
    if not match:
        raise ValueError("Invalid PECmd run timestamp")
    fraction = match.group("fraction")
    fraction = ("." + fraction[:6].ljust(6, "0")) if fraction is not None else ""
    offset = "+00:00" if match.group("offset") == "Z" else match.group("offset")
    normalized_input = f"{match.group('date')}T{match.group('clock')}{fraction}{offset}"
    try:
        parsed = datetime.fromisoformat(normalized_input)
    except ValueError as exc:
        raise ValueError("Invalid PECmd run timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("PECmd run timestamp must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat(), value


def parse_pecmd_jsonl(
    content: bytes, *, source_name: str, source_sha256: str, host: str,
    observed_at: str, collector: dict,
) -> tuple[list[dict], list[str]]:
    """Parse PECmd JSONL into execution-time observations and bounded warnings."""
    if not isinstance(content, bytes) or len(content) > MAX_CONTENT:
        raise ValueError("PECmd export exceeds 64 MiB")
    if not isinstance(collector, dict) or collector.get("name") != "PECmd":
        raise ValueError("PECmd exporter identity is required")
    version = collector.get("version")
    if not isinstance(version, str) or not version.strip() or len(version) > 128:
        raise ValueError("PECmd exporter version is required")
    for value, label, limit in ((source_name, "source name", 512), (host, "host", 256)):
        if not isinstance(value, str) or not value.strip() or len(value) > limit or "\x00" in value:
            raise ValueError(f"Invalid {label}")
    if not isinstance(source_sha256, str) or not _SHA256.fullmatch(source_sha256):
        raise ValueError("Invalid source SHA-256")
    if not isinstance(observed_at, str):
        raise ValueError("Invalid observed_at")
    try:
        observed_dt = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Invalid observed_at") from exc
    if observed_dt.tzinfo is None or observed_dt.utcoffset() is None:
        raise ValueError("observed_at must include a timezone")
    observed_iso = observed_dt.astimezone(timezone.utc).isoformat()

    observations: list[dict] = []
    warnings: list[str] = []
    if not content:
        return observations, warnings
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("PECmd export must be UTF-8 JSONL") from exc
    lines = text.splitlines()
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        if len(line.encode("utf-8")) > MAX_RECORD:
            raise ValueError("PECmd record exceeds 64 KiB")
        try:
            record = json.loads(line, object_pairs_hook=_unique_object, parse_constant=_reject_constant,
                                parse_float=_finite_float)
        except (json.JSONDecodeError, ValueError) as exc:
            raise ValueError(f"Invalid PECmd JSONL record at line {line_number}: {exc}") from exc
        if not isinstance(record, dict) or not set(REQUIRED).issubset(record):
            raise ValueError(f"Incomplete PECmd record at line {line_number}")
        for key, value in record.items():
            if key not in OFFICIAL_FIELDS and not isinstance(value, (str, int, float, bool, type(None))):
                raise ValueError(f"Unsupported nested PECmd field at line {line_number}: {key}")
            if isinstance(value, (dict, list)):
                raise ValueError(f"Unsupported nested PECmd field at line {line_number}: {key}")
            if isinstance(value, str) and (len(value) > MAX_STRING or "\x00" in value):
                raise ValueError(f"Oversized PECmd string at line {line_number}: {key}")
        for key in ("SourceFilename", "ExecutableName", "RunCount", "LastRun", "Version"):
            if not isinstance(record[key], str):
                raise ValueError(f"Invalid PECmd field type at line {line_number}: {key}")
        if not record["SourceFilename"].strip() or not record["ExecutableName"].strip():
            raise ValueError(f"Missing PECmd filename at line {line_number}")
        if type(record["ParsingError"]) is not bool:
            raise ValueError(f"Invalid PECmd field type at line {line_number}: ParsingError")
        if not record["Version"].strip():
            raise ValueError(f"Missing PECmd version at line {line_number}")
        if not re.fullmatch(r"\d{1,10}", record["RunCount"]):
            raise ValueError(f"Invalid PECmd RunCount at line {line_number}")
        run_count = int(record["RunCount"])
        if record["ParsingError"]:
            warnings.append(f"PECmd partially parsed record at line {line_number}")
        runs = [(field, record.get(field)) for field in RUN_FIELDS]
        runs = [(field, value) for field, value in runs if value not in (None, "")]
        if not runs and run_count > 0 and not record["ParsingError"]:
            raise ValueError(f"PECmd record at line {line_number} reports runs but has no run timestamp")
        if not runs:
            runs = [(None, None)]
        if len(observations) + len(runs) > MAX_OBSERVATIONS:
            raise ValueError("PECmd export exceeds 50000 observations")
        for field, raw_time in runs:
            timestamp, timestamp_raw = _timestamp(raw_time) if raw_time is not None else (None, None)
            identity = json.dumps([source_sha256.lower(), line_number, field, host], separators=(",", ":"))
            observation_id = "obs_" + hashlib.sha256(identity.encode("utf-8")).hexdigest()
            details = {
                "name": record["ExecutableName"], "location": record["SourceFilename"],
                "run_count": run_count, "prefetch_hash": record.get("Hash", ""),
                "version": record["Version"], "export_record": record,
            }
            observations.append({
                "id": observation_id, "kind": "prefetch_run" if raw_time is not None else "prefetch_record",
                "host": host, "timestamp": timestamp, "timestamp_raw": timestamp_raw,
                "observed_at": observed_iso,
                "time_semantics": "prefetch_recorded_run" if raw_time is not None else "artifact_metadata",
                "interpretation": "Prefetch records an execution trace; malicious intent, user and full executable path are unconfirmed.",
                "source_id": "evi_" + source_sha256.lower(), "source_file": source_name,
                "source_record": line_number, "source_sha256": source_sha256.lower(),
                "collector": collector,
                "native_locator": {"SourceFilename": record["SourceFilename"], "lineNumber": line_number, "runField": field},
                "details": details,
            })
    return observations, warnings
