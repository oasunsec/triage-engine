"""Durable job persistence backed by SQLite.

Jobs survive server restarts.  The database file lives at
``<TRIAGE_DATA_DIR>/jobs.db`` (default ``<project_root>/data/jobs.db``) and is
auto-created on first use.
"""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from triage_engine.db_migrate import add_column_if_missing, run_migrations

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _resolve_data_dir() -> str:
    configured = str(os.environ.get("TRIAGE_DATA_DIR", "") or "").strip()
    if not configured:
        return os.path.join(_PROJECT_ROOT, "data")
    expanded = os.path.expanduser(configured)
    if os.path.isabs(expanded):
        return os.path.abspath(expanded)
    return os.path.abspath(os.path.join(_PROJECT_ROOT, expanded))


_DB_DIR = _resolve_data_dir()
_DB_PATH = os.path.join(_DB_DIR, "jobs.db")

_MIGRATION_001_SQL = """
CREATE TABLE IF NOT EXISTS jobs (
    job_id      TEXT PRIMARY KEY,
    case_name   TEXT NOT NULL DEFAULT '',
    case_path   TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'queued',
    stage       TEXT NOT NULL DEFAULT 'init',
    message     TEXT NOT NULL DEFAULT '',
    error       TEXT NOT NULL DEFAULT '',
    results     TEXT NOT NULL DEFAULT '{}',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    upload_path TEXT NOT NULL DEFAULT ''
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@contextmanager
def _conn():
    os.makedirs(_DB_DIR, exist_ok=True)
    con = sqlite3.connect(_DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    try:
        yield con
        con.commit()
    finally:
        con.close()


def _init_db() -> None:
    with _conn() as con:
        run_migrations(
            con,
            (
                ("001_initial_schema", _migration_001_initial_schema),
                ("002_add_missing_columns", _migration_002_add_missing_columns),
            ),
            namespace="job_store",
        )


def _migration_001_initial_schema(con: sqlite3.Connection) -> None:
    con.executescript(_MIGRATION_001_SQL)


def _migration_002_add_missing_columns(con: sqlite3.Connection) -> None:
    add_column_if_missing(con, table_name="jobs", column_name="case_name", column_sql="TEXT NOT NULL DEFAULT ''")
    add_column_if_missing(con, table_name="jobs", column_name="case_path", column_sql="TEXT NOT NULL DEFAULT ''")
    add_column_if_missing(con, table_name="jobs", column_name="status", column_sql="TEXT NOT NULL DEFAULT 'queued'")
    add_column_if_missing(con, table_name="jobs", column_name="stage", column_sql="TEXT NOT NULL DEFAULT 'init'")
    add_column_if_missing(con, table_name="jobs", column_name="message", column_sql="TEXT NOT NULL DEFAULT ''")
    add_column_if_missing(con, table_name="jobs", column_name="error", column_sql="TEXT NOT NULL DEFAULT ''")
    add_column_if_missing(con, table_name="jobs", column_name="results", column_sql="TEXT NOT NULL DEFAULT '{}'")
    add_column_if_missing(con, table_name="jobs", column_name="created_at", column_sql="TEXT NOT NULL DEFAULT ''")
    add_column_if_missing(con, table_name="jobs", column_name="updated_at", column_sql="TEXT NOT NULL DEFAULT ''")
    add_column_if_missing(con, table_name="jobs", column_name="upload_path", column_sql="TEXT NOT NULL DEFAULT ''")


# Auto-init on import
_init_db()


def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    d = dict(row)
    # Deserialize JSON fields
    try:
        d["results"] = json.loads(d.get("results") or "{}")
    except (json.JSONDecodeError, TypeError):
        d["results"] = {}
    return d


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def create_job(
    job_id: str,
    case_name: str = "",
    upload_path: str = "",
) -> Dict[str, Any]:
    now = _now()
    with _conn() as con:
        con.execute(
            "INSERT INTO jobs (job_id, case_name, status, stage, message, created_at, updated_at, upload_path) "
            "VALUES (?, ?, 'queued', 'init', 'Starting investigation', ?, ?, ?)",
            (job_id, case_name, now, now, upload_path),
        )
    return get_job(job_id)  # type: ignore[return-value]


def update_job(job_id: str, **fields: Any) -> None:
    if not fields:
        return
    # Serialize results dict to JSON string for storage
    if "results" in fields and isinstance(fields["results"], dict):
        fields["results"] = json.dumps(fields["results"])
    fields["updated_at"] = _now()
    set_clause = ", ".join(f"{k} = ?" for k in fields)
    values = list(fields.values()) + [job_id]
    with _conn() as con:
        con.execute(f"UPDATE jobs SET {set_clause} WHERE job_id = ?", values)


def get_job(job_id: str) -> Optional[Dict[str, Any]]:
    with _conn() as con:
        row = con.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
    return _row_to_dict(row) if row else None


def list_jobs(limit: int = 100) -> List[Dict[str, Any]]:
    with _conn() as con:
        rows = con.execute(
            "SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [_row_to_dict(r) for r in rows]


def delete_job(job_id: str) -> bool:
    with _conn() as con:
        cur = con.execute("DELETE FROM jobs WHERE job_id = ?", (job_id,))
    return cur.rowcount > 0


def get_jobs_with_uploads() -> List[Dict[str, Any]]:
    """Return completed/failed jobs that still have an upload_path set."""
    with _conn() as con:
        rows = con.execute(
            "SELECT * FROM jobs WHERE upload_path != '' AND status IN ('completed', 'failed')"
        ).fetchall()
    return [_row_to_dict(r) for r in rows]


def clear_upload_path(job_id: str) -> None:
    update_job(job_id, upload_path="")
