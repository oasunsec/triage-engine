"""Analyst review and disposition persistence backed by SQLite.

Stores review state for findings and incidents separately from engine
artifacts.  Keyed by stable ``finding_id`` / ``incident_id``, never by
display labels like FND-0001 or INC-0001.

The database lives alongside the job store at ``<TRIAGE_DATA_DIR>/reviews.db``
(default ``<project_root>/data/reviews.db``).
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
_DB_PATH = os.path.join(_DB_DIR, "reviews.db")

# Allowed enum values
VALID_STATUSES = ("Open", "In Review", "Escalated", "Closed", "Suppressed")
VALID_DISPOSITIONS = (
    "True Positive",
    "False Positive",
    "Benign Expected Activity",
    "Suspicious - Needs More Investigation",
    "Test / Lab Activity",
    "Duplicate",
)

_MIGRATION_001_SQL = """
CREATE TABLE IF NOT EXISTS finding_reviews (
    case_name   TEXT NOT NULL,
    finding_id  TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'Open',
    disposition TEXT NOT NULL DEFAULT '',
    owner       TEXT NOT NULL DEFAULT '',
    priority    TEXT NOT NULL DEFAULT '',
    recommended_tuning_action TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    reviewed_at TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (case_name, finding_id)
);

CREATE TABLE IF NOT EXISTS incident_reviews (
    case_name   TEXT NOT NULL,
    incident_id TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'Open',
    disposition TEXT NOT NULL DEFAULT '',
    owner       TEXT NOT NULL DEFAULT '',
    priority    TEXT NOT NULL DEFAULT '',
    recommended_tuning_action TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    reviewed_at TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (case_name, incident_id)
);

CREATE TABLE IF NOT EXISTS review_notes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    case_name   TEXT NOT NULL,
    item_type   TEXT NOT NULL,
    item_id     TEXT NOT NULL,
    author      TEXT NOT NULL DEFAULT '',
    content     TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS review_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    case_name   TEXT NOT NULL,
    item_type   TEXT NOT NULL,
    item_id     TEXT NOT NULL,
    field       TEXT NOT NULL,
    old_value   TEXT NOT NULL DEFAULT '',
    new_value   TEXT NOT NULL DEFAULT '',
    changed_by  TEXT NOT NULL DEFAULT '',
    changed_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS review_queue_index (
    case_name   TEXT NOT NULL,
    item_type   TEXT NOT NULL,
    item_id     TEXT NOT NULL,
    item_title  TEXT NOT NULL DEFAULT '',
    response_priority TEXT NOT NULL DEFAULT '',
    last_seen_at TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    PRIMARY KEY (case_name, item_type, item_id)
);

CREATE TABLE IF NOT EXISTS queue_materialization_state (
    case_name   TEXT PRIMARY KEY,
    findings_mtime REAL NOT NULL DEFAULT 0,
    synced_at   TEXT NOT NULL
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


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
            namespace="review_store",
        )


def _migration_001_initial_schema(con: sqlite3.Connection) -> None:
    con.executescript(_MIGRATION_001_SQL)


def _migration_002_add_missing_columns(con: sqlite3.Connection) -> None:
    add_column_if_missing(
        con, table_name="finding_reviews", column_name="status", column_sql="TEXT NOT NULL DEFAULT 'Open'"
    )
    add_column_if_missing(
        con, table_name="finding_reviews", column_name="disposition", column_sql="TEXT NOT NULL DEFAULT ''"
    )
    add_column_if_missing(
        con, table_name="finding_reviews", column_name="owner", column_sql="TEXT NOT NULL DEFAULT ''"
    )
    add_column_if_missing(
        con, table_name="finding_reviews", column_name="priority", column_sql="TEXT NOT NULL DEFAULT ''"
    )
    add_column_if_missing(
        con,
        table_name="finding_reviews",
        column_name="recommended_tuning_action",
        column_sql="TEXT NOT NULL DEFAULT ''",
    )
    add_column_if_missing(
        con, table_name="finding_reviews", column_name="created_at", column_sql="TEXT NOT NULL DEFAULT ''"
    )
    add_column_if_missing(
        con, table_name="finding_reviews", column_name="updated_at", column_sql="TEXT NOT NULL DEFAULT ''"
    )
    add_column_if_missing(
        con, table_name="finding_reviews", column_name="reviewed_at", column_sql="TEXT NOT NULL DEFAULT ''"
    )

    add_column_if_missing(
        con, table_name="incident_reviews", column_name="status", column_sql="TEXT NOT NULL DEFAULT 'Open'"
    )
    add_column_if_missing(
        con, table_name="incident_reviews", column_name="disposition", column_sql="TEXT NOT NULL DEFAULT ''"
    )
    add_column_if_missing(
        con, table_name="incident_reviews", column_name="owner", column_sql="TEXT NOT NULL DEFAULT ''"
    )
    add_column_if_missing(
        con, table_name="incident_reviews", column_name="priority", column_sql="TEXT NOT NULL DEFAULT ''"
    )
    add_column_if_missing(
        con,
        table_name="incident_reviews",
        column_name="recommended_tuning_action",
        column_sql="TEXT NOT NULL DEFAULT ''",
    )
    add_column_if_missing(
        con, table_name="incident_reviews", column_name="created_at", column_sql="TEXT NOT NULL DEFAULT ''"
    )
    add_column_if_missing(
        con, table_name="incident_reviews", column_name="updated_at", column_sql="TEXT NOT NULL DEFAULT ''"
    )
    add_column_if_missing(
        con, table_name="incident_reviews", column_name="reviewed_at", column_sql="TEXT NOT NULL DEFAULT ''"
    )

    add_column_if_missing(
        con, table_name="review_notes", column_name="case_name", column_sql="TEXT NOT NULL DEFAULT ''"
    )
    add_column_if_missing(
        con, table_name="review_notes", column_name="item_type", column_sql="TEXT NOT NULL DEFAULT ''"
    )
    add_column_if_missing(
        con, table_name="review_notes", column_name="item_id", column_sql="TEXT NOT NULL DEFAULT ''"
    )
    add_column_if_missing(
        con, table_name="review_notes", column_name="author", column_sql="TEXT NOT NULL DEFAULT ''"
    )
    add_column_if_missing(
        con, table_name="review_notes", column_name="content", column_sql="TEXT NOT NULL DEFAULT ''"
    )
    add_column_if_missing(
        con, table_name="review_notes", column_name="created_at", column_sql="TEXT NOT NULL DEFAULT ''"
    )

    add_column_if_missing(
        con, table_name="review_history", column_name="case_name", column_sql="TEXT NOT NULL DEFAULT ''"
    )
    add_column_if_missing(
        con, table_name="review_history", column_name="item_type", column_sql="TEXT NOT NULL DEFAULT ''"
    )
    add_column_if_missing(
        con, table_name="review_history", column_name="item_id", column_sql="TEXT NOT NULL DEFAULT ''"
    )
    add_column_if_missing(
        con, table_name="review_history", column_name="field", column_sql="TEXT NOT NULL DEFAULT ''"
    )
    add_column_if_missing(
        con, table_name="review_history", column_name="old_value", column_sql="TEXT NOT NULL DEFAULT ''"
    )
    add_column_if_missing(
        con, table_name="review_history", column_name="new_value", column_sql="TEXT NOT NULL DEFAULT ''"
    )
    add_column_if_missing(
        con, table_name="review_history", column_name="changed_by", column_sql="TEXT NOT NULL DEFAULT ''"
    )
    add_column_if_missing(
        con, table_name="review_history", column_name="changed_at", column_sql="TEXT NOT NULL DEFAULT ''"
    )

    add_column_if_missing(
        con, table_name="review_queue_index", column_name="item_title", column_sql="TEXT NOT NULL DEFAULT ''"
    )
    add_column_if_missing(
        con,
        table_name="review_queue_index",
        column_name="response_priority",
        column_sql="TEXT NOT NULL DEFAULT ''",
    )
    add_column_if_missing(
        con, table_name="review_queue_index", column_name="last_seen_at", column_sql="TEXT NOT NULL DEFAULT ''"
    )
    add_column_if_missing(
        con, table_name="review_queue_index", column_name="created_at", column_sql="TEXT NOT NULL DEFAULT ''"
    )
    add_column_if_missing(
        con, table_name="review_queue_index", column_name="updated_at", column_sql="TEXT NOT NULL DEFAULT ''"
    )

    add_column_if_missing(
        con,
        table_name="queue_materialization_state",
        column_name="findings_mtime",
        column_sql="REAL NOT NULL DEFAULT 0",
    )
    add_column_if_missing(
        con, table_name="queue_materialization_state", column_name="synced_at", column_sql="TEXT NOT NULL DEFAULT ''"
    )


# Auto-init on import
_init_db()


def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    return dict(row)


def _upsert_queue_index_item(
    case_name: str,
    item_type: str,
    item_id: str,
    *,
    item_title: str = "",
    response_priority: str = "",
    last_seen_at: str = "",
    timestamp: Optional[str] = None,
) -> None:
    now = timestamp or _now()
    with _conn() as con:
        existing = con.execute(
            "SELECT 1 FROM review_queue_index WHERE case_name = ? AND item_type = ? AND item_id = ?",
            (case_name, item_type, item_id),
        ).fetchone()
        if existing is None:
            con.execute(
                "INSERT INTO review_queue_index "
                "(case_name, item_type, item_id, item_title, response_priority, last_seen_at, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (case_name, item_type, item_id, item_title, response_priority, last_seen_at, now, now),
            )
        else:
            con.execute(
                "UPDATE review_queue_index SET item_title = ?, response_priority = ?, last_seen_at = ?, updated_at = ? "
                "WHERE case_name = ? AND item_type = ? AND item_id = ?",
                (item_title, response_priority, last_seen_at, now, case_name, item_type, item_id),
            )


# ---------------------------------------------------------------------------
# Finding reviews
# ---------------------------------------------------------------------------

def get_finding_review(case_name: str, finding_id: str) -> Optional[Dict[str, Any]]:
    with _conn() as con:
        row = con.execute(
            "SELECT * FROM finding_reviews WHERE case_name = ? AND finding_id = ?",
            (case_name, finding_id),
        ).fetchone()
    return _row_to_dict(row) if row else None


def upsert_finding_review(
    case_name: str,
    finding_id: str,
    *,
    status: Optional[str] = None,
    disposition: Optional[str] = None,
    owner: Optional[str] = None,
    priority: Optional[str] = None,
    recommended_tuning_action: Optional[str] = None,
    changed_by: str = "",
) -> Dict[str, Any]:
    now = _now()
    existing = get_finding_review(case_name, finding_id)

    if existing is None:
        with _conn() as con:
            con.execute(
                "INSERT INTO finding_reviews "
                "(case_name, finding_id, status, disposition, owner, priority, "
                "recommended_tuning_action, created_at, updated_at, reviewed_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    case_name, finding_id,
                    status or "Open",
                    disposition or "",
                    owner or "",
                    priority or "",
                    recommended_tuning_action or "",
                    now, now, now if status and status != "Open" else "",
                ),
            )
    else:
        updates: Dict[str, str] = {}
        if status is not None and status != existing["status"]:
            _record_history(case_name, "finding", finding_id, "status", existing["status"], status, changed_by, now)
            updates["status"] = status
        if disposition is not None and disposition != existing["disposition"]:
            _record_history(case_name, "finding", finding_id, "disposition", existing["disposition"], disposition, changed_by, now)
            updates["disposition"] = disposition
        if owner is not None and owner != existing["owner"]:
            _record_history(case_name, "finding", finding_id, "owner", existing["owner"], owner, changed_by, now)
            updates["owner"] = owner
        if priority is not None and priority != existing["priority"]:
            _record_history(case_name, "finding", finding_id, "priority", existing["priority"], priority, changed_by, now)
            updates["priority"] = priority
        if recommended_tuning_action is not None and recommended_tuning_action != existing["recommended_tuning_action"]:
            _record_history(case_name, "finding", finding_id, "recommended_tuning_action", existing["recommended_tuning_action"], recommended_tuning_action, changed_by, now)
            updates["recommended_tuning_action"] = recommended_tuning_action

        if updates:
            updates["updated_at"] = now
            if any(k in updates for k in ("status", "disposition")):
                updates["reviewed_at"] = now
            set_clause = ", ".join(f"{k} = ?" for k in updates)
            values = list(updates.values()) + [case_name, finding_id]
            with _conn() as con:
                con.execute(
                    f"UPDATE finding_reviews SET {set_clause} WHERE case_name = ? AND finding_id = ?",
                    values,
                )

    _upsert_queue_index_item(
        case_name,
        "finding",
        finding_id,
        response_priority=priority or (existing["priority"] if existing else ""),
        timestamp=now,
    )
    return get_finding_review(case_name, finding_id)  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Incident reviews
# ---------------------------------------------------------------------------

def get_incident_review(case_name: str, incident_id: str) -> Optional[Dict[str, Any]]:
    with _conn() as con:
        row = con.execute(
            "SELECT * FROM incident_reviews WHERE case_name = ? AND incident_id = ?",
            (case_name, incident_id),
        ).fetchone()
    return _row_to_dict(row) if row else None


def upsert_incident_review(
    case_name: str,
    incident_id: str,
    *,
    status: Optional[str] = None,
    disposition: Optional[str] = None,
    owner: Optional[str] = None,
    priority: Optional[str] = None,
    recommended_tuning_action: Optional[str] = None,
    changed_by: str = "",
) -> Dict[str, Any]:
    now = _now()
    existing = get_incident_review(case_name, incident_id)

    if existing is None:
        with _conn() as con:
            con.execute(
                "INSERT INTO incident_reviews "
                "(case_name, incident_id, status, disposition, owner, priority, "
                "recommended_tuning_action, created_at, updated_at, reviewed_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    case_name, incident_id,
                    status or "Open",
                    disposition or "",
                    owner or "",
                    priority or "",
                    recommended_tuning_action or "",
                    now, now, now if status and status != "Open" else "",
                ),
            )
    else:
        updates: Dict[str, str] = {}
        if status is not None and status != existing["status"]:
            _record_history(case_name, "incident", incident_id, "status", existing["status"], status, changed_by, now)
            updates["status"] = status
        if disposition is not None and disposition != existing["disposition"]:
            _record_history(case_name, "incident", incident_id, "disposition", existing["disposition"], disposition, changed_by, now)
            updates["disposition"] = disposition
        if owner is not None and owner != existing["owner"]:
            _record_history(case_name, "incident", incident_id, "owner", existing["owner"], owner, changed_by, now)
            updates["owner"] = owner
        if priority is not None and priority != existing["priority"]:
            _record_history(case_name, "incident", incident_id, "priority", existing["priority"], priority, changed_by, now)
            updates["priority"] = priority
        if recommended_tuning_action is not None and recommended_tuning_action != existing["recommended_tuning_action"]:
            _record_history(case_name, "incident", incident_id, "recommended_tuning_action", existing["recommended_tuning_action"], recommended_tuning_action, changed_by, now)
            updates["recommended_tuning_action"] = recommended_tuning_action

        if updates:
            updates["updated_at"] = now
            if any(k in updates for k in ("status", "disposition")):
                updates["reviewed_at"] = now
            set_clause = ", ".join(f"{k} = ?" for k in updates)
            values = list(updates.values()) + [case_name, incident_id]
            with _conn() as con:
                con.execute(
                    f"UPDATE incident_reviews SET {set_clause} WHERE case_name = ? AND incident_id = ?",
                    values,
                )

    _upsert_queue_index_item(
        case_name,
        "incident",
        incident_id,
        response_priority=priority or (existing["priority"] if existing else ""),
        timestamp=now,
    )
    return get_incident_review(case_name, incident_id)  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Notes
# ---------------------------------------------------------------------------

def add_note(
    case_name: str,
    item_type: str,
    item_id: str,
    content: str,
    author: str = "",
) -> Dict[str, Any]:
    now = _now()
    with _conn() as con:
        cur = con.execute(
            "INSERT INTO review_notes (case_name, item_type, item_id, author, content, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (case_name, item_type, item_id, author, content, now),
        )
        note_id = cur.lastrowid
    _record_history(case_name, item_type, item_id, "note_added", "", content, author, now)
    _upsert_queue_index_item(case_name, item_type, item_id, timestamp=now)
    return {"id": note_id, "case_name": case_name, "item_type": item_type,
            "item_id": item_id, "author": author, "content": content, "created_at": now}


def get_notes(case_name: str, item_type: str, item_id: str) -> List[Dict[str, Any]]:
    with _conn() as con:
        rows = con.execute(
            "SELECT * FROM review_notes WHERE case_name = ? AND item_type = ? AND item_id = ? "
            "ORDER BY created_at ASC",
            (case_name, item_type, item_id),
        ).fetchall()
    return [_row_to_dict(r) for r in rows]


# ---------------------------------------------------------------------------
# History
# ---------------------------------------------------------------------------

def _record_history(
    case_name: str,
    item_type: str,
    item_id: str,
    field: str,
    old_value: str,
    new_value: str,
    changed_by: str,
    timestamp: str,
) -> None:
    with _conn() as con:
        con.execute(
            "INSERT INTO review_history "
            "(case_name, item_type, item_id, field, old_value, new_value, changed_by, changed_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (case_name, item_type, item_id, field, old_value, new_value, changed_by, timestamp),
        )


def get_history(
    case_name: str,
    item_type: Optional[str] = None,
    item_id: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    query = "SELECT * FROM review_history WHERE case_name = ?"
    params: list = [case_name]
    if item_type:
        query += " AND item_type = ?"
        params.append(item_type)
    if item_id:
        query += " AND item_id = ?"
        params.append(item_id)
    query += " ORDER BY changed_at DESC, id DESC LIMIT ?"
    params.append(limit)
    with _conn() as con:
        rows = con.execute(query, params).fetchall()
    return [_row_to_dict(r) for r in rows]


def get_all_history(
    limit: int = 200,
    *,
    case_name: str = "",
    item_type: str = "",
    item_id: str = "",
    changed_by: str = "",
    field: str = "",
    search: str = "",
) -> List[Dict[str, Any]]:
    query = "SELECT * FROM review_history WHERE 1=1"
    params: list[Any] = []
    if case_name:
        query += " AND case_name = ?"
        params.append(case_name)
    if item_type:
        query += " AND item_type = ?"
        params.append(item_type)
    if item_id:
        query += " AND item_id = ?"
        params.append(item_id)
    if changed_by:
        query += " AND changed_by = ?"
        params.append(changed_by)
    if field:
        query += " AND field = ?"
        params.append(field)
    if search:
        like = f"%{search}%"
        query += " AND (case_name LIKE ? OR item_id LIKE ? OR changed_by LIKE ? OR field LIKE ? OR old_value LIKE ? OR new_value LIKE ?)"
        params.extend([like, like, like, like, like, like])
    query += " ORDER BY changed_at DESC, id DESC LIMIT ?"
    params.append(limit)
    with _conn() as con:
        rows = con.execute(query, params).fetchall()
    return [_row_to_dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Queue
# ---------------------------------------------------------------------------

def get_review_queue(
    *,
    status: Optional[str] = None,
    disposition: Optional[str] = None,
    owner: Optional[str] = None,
    priority: Optional[str] = None,
    case_name: Optional[str] = None,
    item_type: Optional[str] = None,
    limit: int = 200,
) -> List[Dict[str, Any]]:
    """Return a unified queue from the persistent queue index joined with review state."""
    query = """
    SELECT
        q.case_name,
        q.item_type,
        q.item_id,
        q.item_title,
        q.response_priority,
        q.last_seen_at,
        COALESCE(fr.status, ir.status, 'Open') AS status,
        COALESCE(fr.disposition, ir.disposition, '') AS disposition,
        COALESCE(fr.owner, ir.owner, '') AS owner,
        COALESCE(NULLIF(fr.priority, ''), NULLIF(ir.priority, ''), NULLIF(q.response_priority, ''), '') AS priority,
        COALESCE(fr.updated_at, ir.updated_at, q.updated_at) AS updated_at
    FROM review_queue_index q
    LEFT JOIN finding_reviews fr
      ON q.item_type = 'finding' AND q.case_name = fr.case_name AND q.item_id = fr.finding_id
    LEFT JOIN incident_reviews ir
      ON q.item_type = 'incident' AND q.case_name = ir.case_name AND q.item_id = ir.incident_id
    WHERE 1=1
    """
    params: list = []
    if item_type:
        query += " AND q.item_type = ?"
        params.append(item_type)
    if case_name:
        query += " AND q.case_name = ?"
        params.append(case_name)
    if status:
        query += " AND COALESCE(fr.status, ir.status, 'Open') = ?"
        params.append(status)
    if disposition:
        query += " AND COALESCE(fr.disposition, ir.disposition, '') = ?"
        params.append(disposition)
    if owner:
        if owner == "__unassigned__":
            query += " AND COALESCE(fr.owner, ir.owner, '') = ''"
        else:
            query += " AND COALESCE(fr.owner, ir.owner, '') = ?"
            params.append(owner)
    if priority:
        query += " AND COALESCE(NULLIF(fr.priority, ''), NULLIF(ir.priority, ''), NULLIF(q.response_priority, ''), '') = ?"
        params.append(priority)

    query += " ORDER BY updated_at DESC, q.case_name ASC LIMIT ?"
    params.append(limit)
    with _conn() as con:
        rows = con.execute(query, params).fetchall()
    return [_row_to_dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Rerun carry-forward
# ---------------------------------------------------------------------------

def carry_forward_reviews(case_name: str, finding_ids: List[str], incident_ids: List[str]) -> Dict[str, Any]:
    """Ensure review records exist for current findings/incidents.

    - If a finding/incident already has a review, keep it as-is.
    - If it's new, create a default Open review.
    - If a previously reviewed item is missing from the new run, keep
      the old review record (historical/stale) — do not delete.
    """
    now = _now()
    created_findings = 0
    created_incidents = 0
    indexed_findings: List[str] = []
    indexed_incidents: List[str] = []

    with _conn() as con:
        for fid in finding_ids:
            row = con.execute(
                "SELECT 1 FROM finding_reviews WHERE case_name = ? AND finding_id = ?",
                (case_name, fid),
            ).fetchone()
            if row is None:
                con.execute(
                    "INSERT INTO finding_reviews "
                    "(case_name, finding_id, status, disposition, owner, priority, "
                    "recommended_tuning_action, created_at, updated_at) "
                    "VALUES (?, ?, 'Open', '', '', '', '', ?, ?)",
                    (case_name, fid, now, now),
                )
                created_findings += 1
            indexed_findings.append(fid)

        for iid in incident_ids:
            row = con.execute(
                "SELECT 1 FROM incident_reviews WHERE case_name = ? AND incident_id = ?",
                (case_name, iid),
            ).fetchone()
            if row is None:
                con.execute(
                    "INSERT INTO incident_reviews "
                    "(case_name, incident_id, status, disposition, owner, priority, "
                    "recommended_tuning_action, created_at, updated_at) "
                    "VALUES (?, ?, 'Open', '', '', '', '', ?, ?)",
                    (case_name, iid, now, now),
                )
                created_incidents += 1
            indexed_incidents.append(iid)

    for fid in indexed_findings:
        _upsert_queue_index_item(case_name, "finding", fid, timestamp=now)
    for iid in indexed_incidents:
        _upsert_queue_index_item(case_name, "incident", iid, timestamp=now)

    return {
        "case_name": case_name,
        "findings_carried": len(finding_ids) - created_findings,
        "findings_created": created_findings,
        "incidents_carried": len(incident_ids) - created_incidents,
        "incidents_created": created_incidents,
    }


# ---------------------------------------------------------------------------
# Bulk review overlay — used by case detail APIs
# ---------------------------------------------------------------------------

def materialize_reviews_for_completed_cases(cases_root: str) -> int:
    """Scan completed case directories and ensure review records exist.

    Reads findings.json from each case folder and calls carry_forward_reviews
    for any case that has findings/incidents without corresponding review rows.
    Returns the total number of new review records created.
    """
    if not os.path.isdir(cases_root):
        return 0
    total_created = 0
    for name in os.listdir(cases_root):
        case_dir = os.path.join(cases_root, name)
        if not os.path.isdir(case_dir):
            continue
        findings_path = os.path.join(case_dir, "findings.json")
        if not os.path.isfile(findings_path):
            continue
        try:
            with open(findings_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            fids = [f["id"] for f in data.get("findings", []) if f.get("id")]
            iids = [i["id"] for i in data.get("incidents", []) if i.get("id")]
            if not fids and not iids:
                continue
            result = carry_forward_reviews(name, fids, iids)
            total_created += result["findings_created"] + result["incidents_created"]
        except Exception:
            continue
    return total_created


def sync_queue_index_from_case_payload(payload: Dict[str, Any]) -> int:
    case = payload.get("case", {})
    case_name = case.get("case_name", "")
    if not case_name:
        return 0
    response_priority = case.get("response_priority", "")
    last_seen_at = case.get("last_seen", "")
    created = 0
    for item_type, items in (("finding", payload.get("findings", [])), ("incident", payload.get("incidents", []))):
        for item in items:
            item_id = item.get("id", "")
            if not item_id:
                continue
            _upsert_queue_index_item(
                case_name,
                item_type,
                item_id,
                item_title=item.get("title", ""),
                response_priority=response_priority,
                last_seen_at=last_seen_at,
            )
            created += 1
    return created


def materialize_queue_index_for_completed_cases(cases_root: str) -> int:
    """Backfill or refresh the queue index from completed case artifacts.

    Uses findings.json mtime tracking so repeated calls do not repeatedly parse
    unchanged cases.
    """
    if not os.path.isdir(cases_root):
        return 0
    processed = 0
    now = _now()
    for name in os.listdir(cases_root):
        case_dir = os.path.join(cases_root, name)
        if not os.path.isdir(case_dir):
            continue
        findings_path = os.path.join(case_dir, "findings.json")
        if not os.path.isfile(findings_path):
            continue
        try:
            findings_mtime = os.path.getmtime(findings_path)
            with _conn() as con:
                state = con.execute(
                    "SELECT findings_mtime FROM queue_materialization_state WHERE case_name = ?",
                    (name,),
                ).fetchone()
            if state and abs(float(state["findings_mtime"]) - float(findings_mtime)) < 0.000001:
                continue
            with open(findings_path, "r", encoding="utf-8") as fh:
                payload = json.load(fh)
            sync_queue_index_from_case_payload(payload)
            fids = [f["id"] for f in payload.get("findings", []) if f.get("id")]
            iids = [i["id"] for i in payload.get("incidents", []) if i.get("id")]
            carry_forward_reviews(name, fids, iids)
            with _conn() as con:
                con.execute(
                    "INSERT INTO queue_materialization_state (case_name, findings_mtime, synced_at) VALUES (?, ?, ?) "
                    "ON CONFLICT(case_name) DO UPDATE SET findings_mtime = excluded.findings_mtime, synced_at = excluded.synced_at",
                    (name, findings_mtime, now),
                )
            processed += 1
        except Exception:
            continue
    return processed


def delete_case_review_state(case_name: str) -> None:
    with _conn() as con:
        con.execute("DELETE FROM finding_reviews WHERE case_name = ?", (case_name,))
        con.execute("DELETE FROM incident_reviews WHERE case_name = ?", (case_name,))
        con.execute("DELETE FROM review_notes WHERE case_name = ?", (case_name,))
        con.execute("DELETE FROM review_history WHERE case_name = ?", (case_name,))
        con.execute("DELETE FROM review_queue_index WHERE case_name = ?", (case_name,))
        con.execute("DELETE FROM queue_materialization_state WHERE case_name = ?", (case_name,))


def get_all_finding_reviews(case_name: str) -> Dict[str, Dict[str, Any]]:
    with _conn() as con:
        rows = con.execute(
            "SELECT * FROM finding_reviews WHERE case_name = ?", (case_name,)
        ).fetchall()
    return {r["finding_id"]: _row_to_dict(r) for r in rows}


def get_all_incident_reviews(case_name: str) -> Dict[str, Dict[str, Any]]:
    with _conn() as con:
        rows = con.execute(
            "SELECT * FROM incident_reviews WHERE case_name = ?", (case_name,)
        ).fetchall()
    return {r["incident_id"]: _row_to_dict(r) for r in rows}
