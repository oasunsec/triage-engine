"""Minimal SQLite schema migration helpers for triage engine stores."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Callable, Iterable, Sequence, Tuple


Migration = Tuple[str, Callable[[sqlite3.Connection], None]]


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def ensure_migrations_table(con: sqlite3.Connection) -> None:
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS migrations (
            name TEXT PRIMARY KEY,
            applied_at TEXT NOT NULL
        )
        """
    )


def table_exists(con: sqlite3.Connection, table_name: str) -> bool:
    row = con.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table_name,),
    ).fetchone()
    return bool(row)


def table_columns(con: sqlite3.Connection, table_name: str) -> set[str]:
    if not table_exists(con, table_name):
        return set()
    rows = con.execute(f"PRAGMA table_info({table_name})").fetchall()
    return {str(row[1]) for row in rows}


def add_column_if_missing(
    con: sqlite3.Connection,
    *,
    table_name: str,
    column_name: str,
    column_sql: str,
) -> bool:
    columns = table_columns(con, table_name)
    if column_name in columns:
        return False
    con.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_sql}")
    return True


def run_migrations(
    con: sqlite3.Connection,
    migrations: Sequence[Migration] | Iterable[Migration],
    *,
    namespace: str,
) -> list[str]:
    ensure_migrations_table(con)
    applied_rows = con.execute("SELECT name FROM migrations").fetchall()
    applied = {str(row[0]) for row in applied_rows}
    ran: list[str] = []

    for name, migration in migrations:
        migration_name = f"{namespace}:{name}"
        if migration_name in applied:
            continue
        migration(con)
        con.execute(
            "INSERT INTO migrations (name, applied_at) VALUES (?, ?)",
            (migration_name, _utc_now()),
        )
        ran.append(migration_name)

    return ran
