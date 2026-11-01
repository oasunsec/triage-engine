"""Bounded, offline parsing of retained Chromium History database bytes.

Schema and time representation: Chromium download_database.cc; persisted states:
components/history/core/browser/download_constants.h. No browser collection or
schema migration is performed here. ``opened`` does not establish execution.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import time
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

MAX_BYTES = 64 * 1024 * 1024
MAX_RECORDS = 50_000  # Downloads and URL-chain rows combined.
MAX_CHAIN_ENTRIES = 64
MAX_FIELD_LENGTH = 65_536  # UTF-8 bytes, checked inside SQLite before fetching.
MAX_SQL_STEPS = 10_000_000
MAX_SECONDS = 5.0
_FIELDS = (
    "id", "current_path", "target_path", "start_time", "end_time",
    "received_bytes", "total_bytes", "state", "opened", "danger_type",
    "interrupt_reason",
)
_STATES = {0: "in_progress", 1: "complete", 2: "cancelled", 4: "interrupted"}
_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_MAX_TIME = ((datetime.max.replace(tzinfo=timezone.utc) - _EPOCH).days * 86400
             + 86399) * 1_000_000 + 999999


def _integer(value: object, name: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise ValueError(f"Invalid Chromium download {name}")
    return value


def _timestamp(value: object) -> str:
    microseconds = _integer(value, "time")
    if microseconds > _MAX_TIME:
        raise ValueError("Chromium download time is out of range")
    if microseconds == 0:
        return ""
    return (_EPOCH + timedelta(microseconds=microseconds)).isoformat()


def _schema(connection: sqlite3.Connection) -> None:
    # Python 3.10 lacks Connection.setlimit. Enforce bounded metadata before
    # transferring it to Python, independent of SQLite's runtime-limit API.
    if connection.execute(
        "SELECT 1 FROM sqlite_schema WHERE length(CAST(name AS BLOB)) > ? OR "
        "length(CAST(sql AS BLOB)) > ? LIMIT 1",
        (MAX_FIELD_LENGTH, MAX_FIELD_LENGTH),
    ).fetchone():
        raise ValueError("Chromium database schema field exceeds budget")
    objects = connection.execute(
        "SELECT type, name, sql FROM sqlite_schema LIMIT 257"
    ).fetchall()
    if len(objects) > 256:
        raise ValueError("Chromium database schema exceeds budget")
    tables = {}
    for kind, name, sql in objects:
        if kind == "view" or (sql and "VIRTUAL TABLE" in sql.upper()):
            raise ValueError("Unsupported Chromium database views or virtual tables")
        if kind == "table":
            tables[name] = sql
    for table, pragma, required in (
        ("downloads", "PRAGMA table_xinfo('downloads')", _FIELDS),
        ("downloads_url_chains", "PRAGMA table_xinfo('downloads_url_chains')",
         ("id", "chain_index", "url")),
    ):
        if table not in tables:
            raise ValueError("Unsupported Chromium downloads schema")
        columns = connection.execute(pragma).fetchall()
        by_name = {column[1]: column for column in columns}
        if len(columns) > 64 or not set(required).issubset(by_name):
            raise ValueError("Unsupported Chromium downloads schema")
        # Reject generated/hidden columns, even when their names look authentic.
        if any(column[6] != 0 for column in columns):
            raise ValueError("Unsupported Chromium generated columns")
        integer_names = set(required) - {"current_path", "target_path", "url"}
        if any(by_name[name][2].upper() != "INTEGER" for name in integer_names):
            raise ValueError("Unsupported Chromium integer column declarations")
        if any(by_name[name][2].upper() not in ("LONGVARCHAR", "VARCHAR", "TEXT")
               for name in set(required) - integer_names):
            raise ValueError("Unsupported Chromium text column declarations")
        if table == "downloads":
            if by_name["id"][5] != 1 or any(c[5] for c in columns if c[1] != "id"):
                raise ValueError("Unsupported Chromium downloads primary key")
        elif (by_name["id"][5] != 1 or by_name["chain_index"][5] != 2
              or any(c[5] for c in columns if c[1] not in ("id", "chain_index"))):
            raise ValueError("Unsupported Chromium URL-chain primary key")


def _read(connection: sqlite3.Connection, *, source_name: str, source_sha256: str,
          host: str, observed_at: str, collector: dict) -> list[dict]:
    _schema(connection)
    # Validate the complete supplied database, including pages outside the two
    # queried tables. The existing VM-step/deadline budget applies to this check.
    integrity = connection.execute("PRAGMA quick_check(1)").fetchall()
    if integrity != [("ok",)]:
        raise ValueError("Chromium database failed SQLite integrity validation")
    count = connection.execute(
        "SELECT (SELECT count(*) FROM downloads NOT INDEXED) + "
        "(SELECT count(*) FROM downloads_url_chains NOT INDEXED)"
    ).fetchone()[0]
    if count > MAX_RECORDS:
        raise ValueError("Chromium download records exceed budget")
    # Fixed SQL excludes attacker-supplied identifiers and avoids custom indexes.
    for sql in (
        "SELECT 1 FROM downloads NOT INDEXED WHERE "
        "typeof(id) != 'integer' OR typeof(start_time) != 'integer' OR "
        "typeof(end_time) != 'integer' OR typeof(received_bytes) != 'integer' OR "
        "typeof(total_bytes) != 'integer' OR typeof(state) != 'integer' OR "
        "typeof(opened) != 'integer' OR typeof(danger_type) != 'integer' OR "
        "typeof(interrupt_reason) != 'integer' OR "
        "typeof(current_path) != 'text' OR typeof(target_path) != 'text' OR "
        "length(CAST(current_path AS BLOB)) > ? OR "
        "length(CAST(target_path AS BLOB)) > ? LIMIT 1",
        "SELECT 1 FROM downloads_url_chains NOT INDEXED WHERE "
        "typeof(id) != 'integer' OR typeof(chain_index) != 'integer' OR "
        "typeof(url) != 'text' OR length(CAST(url AS BLOB)) > ? LIMIT 1",
    ):
        parameters = (MAX_FIELD_LENGTH,) * sql.count("?")
        if connection.execute(sql, parameters).fetchone():
            raise ValueError("Invalid or oversized Chromium download field")
    chains: dict[int, dict[int, str]] = {}
    for download_id, index, url in connection.execute(
        "SELECT id, chain_index, url FROM downloads_url_chains NOT INDEXED"
    ):
        _integer(download_id, "URL-chain id", 1)
        _integer(index, "chain_index")
        chain = chains.setdefault(download_id, {})
        if index in chain or len(chain) >= MAX_CHAIN_ENTRIES:
            raise ValueError("Chromium URL chain exceeds budget or contains duplicates")
        chain[index] = url
    observations = []
    seen = set()
    for row in connection.execute(
        "SELECT id,current_path,target_path,start_time,end_time,received_bytes,"
        "total_bytes,state,opened,danger_type,interrupt_reason FROM downloads NOT INDEXED"
    ):
        details = dict(zip(_FIELDS, row))
        for name in set(_FIELDS) - {"current_path", "target_path"}:
            _integer(details[name], name, -1 if name == "total_bytes" else 0)
        download_id = _integer(details["id"], "id", 1)
        if download_id in seen or details["state"] not in _STATES or details["opened"] not in (0, 1):
            raise ValueError("Invalid Chromium download id, state, or opened flag")
        seen.add(download_id)
        start_at, end_at = _timestamp(details["start_time"]), _timestamp(details["end_time"])
        if start_at and end_at and details["end_time"] < details["start_time"]:
            raise ValueError("Chromium download end precedes start")
        chain = chains.pop(download_id, {})
        if sorted(chain) != list(range(len(chain))):
            raise ValueError("Invalid Chromium URL-chain ordering")
        details.update(start_at=start_at, end_at=end_at,
                       download_state=_STATES[details["state"]],
                       url_chain=[chain[index] for index in sorted(chain)])
        identity = json.dumps([source_sha256, "downloads", download_id, host], separators=(",", ":"))
        observations.append({
            "id": "obs_" + hashlib.sha256(identity.encode("utf-8")).hexdigest(),
            "kind": "browser_download", "host": host, "observed_at": observed_at,
            "timestamp": start_at, "time_semantics": "browser_download_start",
            "interpretation": "browser_recorded_download", "execution_unconfirmed": True,
            "execution_confirmed": False, "source_id": "evi_" + source_sha256,
            "source_file": source_name, "source_sha256": source_sha256,
            "source_record": download_id,
            "native_locator": {"table": "downloads", "primary_key": {"id": download_id}},
            "collector": dict(collector), "details": details,
        })
    if chains:
        raise ValueError("Orphaned Chromium URL-chain records")
    return sorted(observations, key=lambda item: item["source_record"])


def parse_chromium_downloads(content: bytes, *, source_name: str, source_sha256: str,
                             host: str, observed_at: str, collector: dict,
                             temp_dir: str | Path) -> list[dict]:
    """Parse the exact retained bytes; callers supply a project-owned temp directory.

    A database declaring WAL journal format is rejected: its separate WAL bytes
    are absent from this contract, so immutable reading could lose evidence.
    """
    if type(content) is not bytes or len(content) > MAX_BYTES:
        raise ValueError("Chromium database exceeds byte budget or is not bytes")
    if len(content) < 100 or content[:16] != b"SQLite format 3\0":
        raise ValueError("Invalid Chromium SQLite header")
    if content[18:20] != b"\x01\x01":
        raise ValueError("Unsupported Chromium SQLite WAL or journal format")
    try:
        with tempfile.TemporaryDirectory(prefix="chromium-downloads-", dir=Path(temp_dir)) as folder:
            database = Path(folder) / "History"
            database.write_bytes(content)
            with closing(sqlite3.connect(database.as_uri() + "?mode=ro&immutable=1", uri=True)) as connection:
                # Defense in depth on 3.11+. Every supported runtime still uses
                # fixed SQL, prefetch field/type caps, schema and record bounds,
                # immutable/query-only mode, and the VM/deadline interrupt.
                if hasattr(connection, "setlimit"):
                    for category, limit in (
                        (sqlite3.SQLITE_LIMIT_LENGTH, 1024 * 1024),
                        (sqlite3.SQLITE_LIMIT_SQL_LENGTH, 65536),
                        (sqlite3.SQLITE_LIMIT_COLUMN, 64),
                        (sqlite3.SQLITE_LIMIT_EXPR_DEPTH, 50),
                        (sqlite3.SQLITE_LIMIT_ATTACHED, 0),
                        (sqlite3.SQLITE_LIMIT_VDBE_OP, 10000),
                    ):
                        connection.setlimit(category, limit)
                deadline = time.monotonic() + MAX_SECONDS
                steps = 0

                def progress() -> int:
                    nonlocal steps
                    steps += 1000
                    return int(steps > MAX_SQL_STEPS or time.monotonic() > deadline)

                connection.set_progress_handler(progress, 1000)
                connection.execute("PRAGMA query_only=ON")
                connection.execute("PRAGMA trusted_schema=OFF")
                return _read(connection, source_name=source_name, source_sha256=source_sha256,
                             host=host, observed_at=observed_at, collector=collector)
    except (sqlite3.Error, OSError, UnicodeError, OverflowError, MemoryError) as exc:
        raise ValueError("Invalid or over-budget Chromium downloads database") from exc
