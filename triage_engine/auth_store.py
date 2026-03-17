"""Lightweight user and session persistence for the platform layer."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

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
_DB_PATH = os.path.join(_DB_DIR, "auth.db")

VALID_ROLES = ("admin", "analyst", "viewer")
DEFAULT_SESSION_TTL_HOURS = 12
DEFAULT_SESSION_IDLE_HOURS = 2
SESSION_TTL_MIN_HOURS = 1
SESSION_TTL_MAX_HOURS = 72
SESSION_IDLE_MIN_HOURS = 1
SESSION_IDLE_MAX_HOURS = 72
SESSION_ACTIVITY_DEBOUNCE_SECONDS = 60

_MIGRATION_001_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    last_login_at TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    last_active_at TEXT NOT NULL,
    last_ip TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS auth_audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_username TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,
    target_username TEXT NOT NULL DEFAULT '',
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS user_preferences (
    username TEXT PRIMARY KEY,
    preferences_json TEXT NOT NULL DEFAULT '{}',
    updated_at TEXT NOT NULL
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
                ("003_session_activity_columns", _migration_003_session_activity_columns),
            ),
            namespace="auth_store",
        )


def _migration_001_initial_schema(con: sqlite3.Connection) -> None:
    con.executescript(_MIGRATION_001_SQL)


def _migration_002_add_missing_columns(con: sqlite3.Connection) -> None:
    add_column_if_missing(con, table_name="users", column_name="last_login_at", column_sql="TEXT NOT NULL DEFAULT ''")

    add_column_if_missing(con, table_name="sessions", column_name="user_id", column_sql="INTEGER NOT NULL DEFAULT 0")
    add_column_if_missing(con, table_name="sessions", column_name="username", column_sql="TEXT NOT NULL DEFAULT ''")
    add_column_if_missing(con, table_name="sessions", column_name="role", column_sql="TEXT NOT NULL DEFAULT 'viewer'")
    add_column_if_missing(con, table_name="sessions", column_name="created_at", column_sql="TEXT NOT NULL DEFAULT ''")
    add_column_if_missing(con, table_name="sessions", column_name="expires_at", column_sql="TEXT NOT NULL DEFAULT ''")

    add_column_if_missing(con, table_name="auth_audit_events", column_name="actor_username", column_sql="TEXT NOT NULL DEFAULT ''")
    add_column_if_missing(con, table_name="auth_audit_events", column_name="target_username", column_sql="TEXT NOT NULL DEFAULT ''")
    add_column_if_missing(con, table_name="auth_audit_events", column_name="details_json", column_sql="TEXT NOT NULL DEFAULT '{}'")
    add_column_if_missing(con, table_name="auth_audit_events", column_name="created_at", column_sql="TEXT NOT NULL DEFAULT ''")

    add_column_if_missing(con, table_name="user_preferences", column_name="preferences_json", column_sql="TEXT NOT NULL DEFAULT '{}'")
    add_column_if_missing(con, table_name="user_preferences", column_name="updated_at", column_sql="TEXT NOT NULL DEFAULT ''")


def _migration_003_session_activity_columns(con: sqlite3.Connection) -> None:
    add_column_if_missing(con, table_name="sessions", column_name="last_active_at", column_sql="TEXT NOT NULL DEFAULT ''")
    add_column_if_missing(con, table_name="sessions", column_name="last_ip", column_sql="TEXT NOT NULL DEFAULT ''")


_init_db()


def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    return dict(row)


def _json_loads(value: str, fallback: Any):
    try:
        return json.loads(value or "")
    except Exception:
        return fallback


def _clamp(value: int, minimum: int, maximum: int) -> int:
    return max(minimum, min(maximum, value))


def _env_hours(name: str, *, default: int, minimum: int, maximum: int) -> int:
    raw = str(os.environ.get(name, "")).strip()
    if not raw:
        return default
    try:
        parsed = int(raw)
    except ValueError:
        return default
    return _clamp(parsed, minimum, maximum)


def session_ttl_hours() -> int:
    return _env_hours(
        "TRIAGE_SESSION_TTL_HOURS",
        default=DEFAULT_SESSION_TTL_HOURS,
        minimum=SESSION_TTL_MIN_HOURS,
        maximum=SESSION_TTL_MAX_HOURS,
    )


def session_idle_hours() -> int:
    return _env_hours(
        "TRIAGE_SESSION_IDLE_HOURS",
        default=DEFAULT_SESSION_IDLE_HOURS,
        minimum=SESSION_IDLE_MIN_HOURS,
        maximum=SESSION_IDLE_MAX_HOURS,
    )


def session_max_age_seconds() -> int:
    return int(session_ttl_hours() * 60 * 60)


def _parse_timestamp(value: str) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _session_expired(session: Dict[str, Any], *, now: datetime) -> bool:
    expires_at = _parse_timestamp(str(session.get("expires_at", "")))
    if not expires_at:
        return True
    return expires_at <= now


def _session_idle_expired(session: Dict[str, Any], *, now: datetime) -> bool:
    idle_limit = timedelta(hours=session_idle_hours())
    last_active_raw = str(session.get("last_active_at", "") or "")
    created_raw = str(session.get("created_at", "") or "")
    anchor = _parse_timestamp(last_active_raw) or _parse_timestamp(created_raw)
    if not anchor:
        return True
    return (now - anchor) >= idle_limit


def _touch_session_if_needed(
    con: sqlite3.Connection,
    session: Dict[str, Any],
    *,
    now: datetime,
    client_ip: str = "",
) -> Dict[str, Any]:
    last_active = _parse_timestamp(str(session.get("last_active_at", "") or ""))
    last_ip = str(session.get("last_ip", "") or "")
    should_touch = False
    if last_active is None:
        should_touch = True
    else:
        elapsed = (now - last_active).total_seconds()
        should_touch = elapsed >= SESSION_ACTIVITY_DEBOUNCE_SECONDS
    if client_ip and client_ip != last_ip:
        should_touch = True
    if not should_touch:
        return session

    now_iso = now.isoformat()
    updated_ip = client_ip if client_ip else last_ip
    con.execute(
        "UPDATE sessions SET last_active_at = ?, last_ip = ? WHERE session_id = ?",
        (now_iso, updated_ip, session["session_id"]),
    )
    session["last_active_at"] = now_iso
    session["last_ip"] = updated_ip
    return session


def _hash_password(password: str, *, salt: Optional[bytes] = None) -> str:
    salt = salt or secrets.token_bytes(16)
    iterations = 240000
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "pbkdf2_sha256${}${}${}".format(
        iterations,
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(digest).decode("ascii"),
    )


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        scheme, iterations, salt_b64, digest_b64 = stored_hash.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64.encode("ascii"))
        expected = base64.b64decode(digest_b64.encode("ascii"))
        candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iterations))
        return hmac.compare_digest(candidate, expected)
    except Exception:
        return False


def has_users() -> bool:
    with _conn() as con:
        row = con.execute("SELECT COUNT(*) AS c FROM users").fetchone()
    return bool(row and row["c"] > 0)


def get_user(username: str) -> Optional[Dict[str, Any]]:
    with _conn() as con:
        row = con.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    return _row_to_dict(row) if row else None


def list_users() -> list[Dict[str, Any]]:
    with _conn() as con:
        rows = con.execute(
            "SELECT id, username, role, active, created_at, updated_at, last_login_at "
            "FROM users ORDER BY username ASC"
        ).fetchall()
    return [_row_to_dict(row) for row in rows]


def create_user(username: str, password: str, *, role: str = "analyst") -> Dict[str, Any]:
    if role not in VALID_ROLES:
        raise ValueError(f"Invalid role: {role}")
    now = _now()
    password_hash = _hash_password(password)
    with _conn() as con:
        con.execute(
            "INSERT INTO users (username, password_hash, role, active, created_at, updated_at, last_login_at) "
            "VALUES (?, ?, ?, 1, ?, ?, '')",
            (username, password_hash, role, now, now),
        )
    user = get_user(username)
    if not user:
        raise RuntimeError("User creation failed")
    return user


def update_user(
    username: str,
    *,
    password: Optional[str] = None,
    role: Optional[str] = None,
    active: Optional[bool] = None,
) -> Optional[Dict[str, Any]]:
    user = get_user(username)
    if not user:
        return None
    updates: Dict[str, Any] = {"updated_at": _now()}
    if password is not None:
        updates["password_hash"] = _hash_password(password)
    if role is not None:
        if role not in VALID_ROLES:
            raise ValueError(f"Invalid role: {role}")
        updates["role"] = role
    if active is not None:
        updates["active"] = 1 if active else 0
    set_clause = ", ".join(f"{k} = ?" for k in updates)
    values = list(updates.values()) + [username]
    with _conn() as con:
        con.execute(f"UPDATE users SET {set_clause} WHERE username = ?", values)
    return get_user(username)


def bootstrap_admin(username: str, password: str) -> Dict[str, Any]:
    if has_users():
        raise ValueError("Bootstrap is only allowed when no users exist")
    return create_user(username, password, role="admin")


def authenticate_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    user = get_user(username)
    if not user or not user.get("active"):
        return None
    if not verify_password(password, user["password_hash"]):
        return None
    now = _now()
    with _conn() as con:
        con.execute("UPDATE users SET last_login_at = ?, updated_at = ? WHERE id = ?", (now, now, user["id"]))
    return get_user(username)


def change_password(username: str, current_password: str, new_password: str) -> Optional[Dict[str, Any]]:
    user = get_user(username)
    if not user or not user.get("active"):
        return None
    if not verify_password(current_password, user["password_hash"]):
        return None
    return update_user(username, password=new_password)


def create_session(user: Dict[str, Any], *, client_ip: str = "") -> Dict[str, Any]:
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    expires = now + timedelta(hours=session_ttl_hours())
    expires_iso = expires.isoformat()
    session_id = secrets.token_urlsafe(32)
    with _conn() as con:
        con.execute(
            "INSERT INTO sessions (session_id, user_id, username, role, created_at, expires_at, last_active_at, last_ip) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (session_id, user["id"], user["username"], user["role"], now_iso, expires_iso, now_iso, client_ip),
        )
    return {
        "session_id": session_id,
        "user_id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "created_at": now_iso,
        "expires_at": expires_iso,
        "last_active_at": now_iso,
        "last_ip": client_ip,
    }


def get_session(session_id: str, *, client_ip: str = "") -> Optional[Dict[str, Any]]:
    if not session_id:
        return None
    with _conn() as con:
        row = con.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
        if not row:
            return None
        session = _row_to_dict(row)
        now = datetime.now(timezone.utc)
        if _session_expired(session, now=now) or _session_idle_expired(session, now=now):
            con.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
            return None
        return _touch_session_if_needed(con, session, now=now, client_ip=client_ip)


def delete_session(session_id: str) -> bool:
    with _conn() as con:
        cur = con.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
        return cur.rowcount > 0


def delete_sessions_for_user(username: str) -> int:
    with _conn() as con:
        cur = con.execute("DELETE FROM sessions WHERE username = ?", (username,))
        return cur.rowcount


def cleanup_expired_sessions() -> int:
    now = _now()
    with _conn() as con:
        cur = con.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
        return cur.rowcount


def list_active_sessions() -> list[Dict[str, Any]]:
    with _conn() as con:
        rows = con.execute(
            "SELECT session_id, user_id, username, role, created_at, expires_at, last_active_at, last_ip "
            "FROM sessions ORDER BY created_at DESC"
        ).fetchall()
        now = datetime.now(timezone.utc)
        active: list[Dict[str, Any]] = []
        for row in rows:
            session = _row_to_dict(row)
            if _session_expired(session, now=now) or _session_idle_expired(session, now=now):
                con.execute("DELETE FROM sessions WHERE session_id = ?", (session["session_id"],))
                continue
            active.append(session)
        return active


def record_audit_event(
    *,
    actor_username: str,
    action: str,
    target_username: str = "",
    details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    created_at = _now()
    payload = json.dumps(details or {}, sort_keys=True)
    with _conn() as con:
        cur = con.execute(
            "INSERT INTO auth_audit_events (actor_username, action, target_username, details_json, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (actor_username, action, target_username, payload, created_at),
        )
        event_id = cur.lastrowid
    return {
        "id": event_id,
        "actor_username": actor_username,
        "action": action,
        "target_username": target_username,
        "details": details or {},
        "created_at": created_at,
    }


def list_audit_events(
    limit: int = 100,
    *,
    target_username: str = "",
    actor_username: str = "",
    action: str = "",
    search: str = "",
) -> list[Dict[str, Any]]:
    with _conn() as con:
        query = "SELECT * FROM auth_audit_events WHERE 1=1"
        params: list[Any] = []
        if target_username:
            query += " AND target_username = ?"
            params.append(target_username)
        if actor_username:
            query += " AND actor_username = ?"
            params.append(actor_username)
        if action:
            query += " AND action = ?"
            params.append(action)
        if search:
            query += " AND (actor_username LIKE ? OR target_username LIKE ? OR action LIKE ? OR details_json LIKE ?)"
            like = f"%{search}%"
            params.extend([like, like, like, like])
        query += " ORDER BY created_at DESC, id DESC LIMIT ?"
        params.append(limit)
        rows = con.execute(query, params).fetchall()
    events = []
    for row in rows:
        item = _row_to_dict(row)
        item["details"] = _json_loads(item.pop("details_json", "{}"), {})
        events.append(item)
    return events


def get_user_preferences(username: str) -> Dict[str, Any]:
    with _conn() as con:
        row = con.execute(
            "SELECT preferences_json, updated_at FROM user_preferences WHERE username = ?",
            (username,),
        ).fetchone()
    if not row:
        return {"username": username, "preferences": {}, "updated_at": ""}
    return {
        "username": username,
        "preferences": _json_loads(row["preferences_json"], {}),
        "updated_at": row["updated_at"],
    }


def update_user_preferences(username: str, patch: Dict[str, Any]) -> Dict[str, Any]:
    current = get_user_preferences(username)
    preferences = current.get("preferences", {}) or {}
    preferences.update(patch or {})
    updated_at = _now()
    with _conn() as con:
        con.execute(
            "INSERT INTO user_preferences (username, preferences_json, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(username) DO UPDATE SET preferences_json = excluded.preferences_json, updated_at = excluded.updated_at",
            (username, json.dumps(preferences, sort_keys=True), updated_at),
        )
    return {"username": username, "preferences": preferences, "updated_at": updated_at}
