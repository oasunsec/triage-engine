"""Synthetic native SQLite fixtures only; never access a user's browser profile."""

import hashlib
import sqlite3

import pytest

from corrobora import browser_artifacts as browser


SCHEMA = """
CREATE TABLE downloads (
 id INTEGER PRIMARY KEY, current_path LONGVARCHAR NOT NULL,
 target_path LONGVARCHAR NOT NULL, start_time INTEGER NOT NULL,
 end_time INTEGER NOT NULL, received_bytes INTEGER NOT NULL,
 total_bytes INTEGER NOT NULL, state INTEGER NOT NULL, opened INTEGER NOT NULL,
 danger_type INTEGER NOT NULL, interrupt_reason INTEGER NOT NULL);
CREATE TABLE downloads_url_chains (
 id INTEGER NOT NULL, chain_index INTEGER NOT NULL, url LONGVARCHAR NOT NULL,
 PRIMARY KEY (id, chain_index));
"""
START = 11644473600000000  # 1970-01-01 UTC in Chromium microseconds.


def database(tmp_path, *, rows=None, chains=None, schema=SCHEMA, extra_sql=""):
    path = tmp_path / "synthetic-History"
    with sqlite3.connect(path) as connection:
        connection.executescript(schema)
        if rows is None:
            rows = [(7, "C:/Downloads/report.pdf", "C:/Downloads/report.pdf", START,
                     START + 1_000_001, 100, 100, 1, 1, 0, 0)]
        if chains is None:
            chains = [(7, 1, "https://example.test/report.pdf"),
                      (7, 0, "https://example.test/redirect")]
        connection.executemany("INSERT INTO downloads VALUES (?,?,?,?,?,?,?,?,?,?,?)", rows)
        connection.executemany("INSERT INTO downloads_url_chains VALUES (?,?,?)", chains)
        if extra_sql:
            connection.executescript(extra_sql)
    return path.read_bytes()


def parse(content, tmp_path, **overrides):
    metadata = dict(source_name="Browser/History", source_sha256=hashlib.sha256(content).hexdigest(),
                    host="TEST-HOST", observed_at="2026-10-02T12:00:00Z",
                    collector={"name": "synthetic", "version": "1"}, temp_dir=tmp_path)
    metadata.update(overrides)
    return browser.parse_chromium_downloads(content, **metadata)


def test_native_record_time_redirects_and_provenance(tmp_path):
    content = database(tmp_path)
    observation, = parse(content, tmp_path)
    assert observation["kind"] == "browser_download"
    assert observation["timestamp"] == "1970-01-01T00:00:00+00:00"
    assert observation["observed_at"] == "2026-10-02T12:00:00Z"
    assert observation["time_semantics"] == "browser_download_start"
    assert observation["source_record"] == 7
    assert observation["native_locator"] == {"table": "downloads", "primary_key": {"id": 7}}
    assert observation["source_sha256"] == hashlib.sha256(content).hexdigest()
    assert observation["source_id"] == "evi_" + observation["source_sha256"]
    assert observation["collector"] == {"name": "synthetic", "version": "1"}
    details = observation["details"]
    assert details["start_time"] == START
    assert details["end_at"] == "1970-01-01T00:00:01.000001+00:00"
    assert details["download_state"] == "complete"
    assert details["url_chain"] == ["https://example.test/redirect", "https://example.test/report.pdf"]
    assert details["opened"] == 1
    assert observation["interpretation"] == "browser_recorded_download"
    assert observation["execution_unconfirmed"] is True
    assert observation["execution_confirmed"] is False
    assert "alerts" not in observation
    assert "suspicious" not in str(observation)
    assert (tmp_path / "synthetic-History").read_bytes() == content
    assert not list(tmp_path.glob("chromium-downloads-*"))


@pytest.mark.parametrize("state,label", [(0, "in_progress"), (1, "complete"),
                                         (2, "cancelled"), (4, "interrupted")])
def test_states_and_unknown_time(tmp_path, state, label):
    rows = [(7, "file.txt", "file.txt", 0, 0, 0, -1, state, 0, 0, 0)]
    observation, = parse(database(tmp_path, rows=rows), tmp_path)
    assert observation["timestamp"] == ""
    assert observation["details"]["start_at"] == observation["details"]["end_at"] == ""
    assert observation["details"]["download_state"] == label


def test_exact_epoch_math_and_maximum_time(tmp_path):
    rows = [(7, "file", "file", 1, browser._MAX_TIME, 0, 0, 1, 0, 0, 0)]
    observation, = parse(database(tmp_path, rows=rows), tmp_path)
    assert observation["timestamp"] == "1601-01-01T00:00:00.000001+00:00"
    assert observation["details"]["end_at"] == "9999-12-31T23:59:59.999999+00:00"


def test_identity_is_stable_and_native_key_based(tmp_path):
    content = database(tmp_path)
    first, = parse(content, tmp_path)
    second, = parse(content, tmp_path, source_name="Renamed/History", observed_at="2030-01-01T00:00:00Z")
    assert first["id"] == second["id"]
    changed, = parse(content, tmp_path, source_sha256="a" * 64)
    assert changed["id"] != first["id"]
    changed_host, = parse(content, tmp_path, host="OTHER")
    assert changed_host["id"] != first["id"]


def test_connection_is_read_only_and_immutable(tmp_path, monkeypatch):
    content = database(tmp_path)
    original = sqlite3.connect
    traces = []
    opened = []

    def connect(database_uri, **kwargs):
        opened.append((database_uri, kwargs))
        connection = original(database_uri, **kwargs)
        connection.set_trace_callback(traces.append)
        with pytest.raises(sqlite3.OperationalError):
            connection.execute("CREATE TABLE forbidden (id INTEGER)")
        return connection

    monkeypatch.setattr(browser.sqlite3, "connect", connect)
    parse(content, tmp_path)
    assert "mode=ro&immutable=1" in opened[0][0]
    assert opened[0][1] == {"uri": True}
    assert "PRAGMA query_only=ON" in traces
    assert "PRAGMA trusted_schema=OFF" in traces
    assert (tmp_path / "synthetic-History").read_bytes() == content


@pytest.mark.parametrize("field,value", [
    ("start_time", -1), ("start_time", browser._MAX_TIME + 1),
    ("start_time", "invalid"), ("start_time", 1.5), ("end_time", START - 1),
    ("state", 3), ("opened", 2), ("received_bytes", -1), ("total_bytes", -2),
    ("danger_type", -1), ("interrupt_reason", "invalid"), ("id", 0),
    ("current_path", b"blob"), ("target_path", "x" * 65537),
], ids=["negative-time", "overflow-time", "text-time", "real-time", "reverse-time",
        "old-state", "opened-enum", "negative-received", "negative-total", "negative-danger",
        "text-interrupt", "zero-id", "blob-path", "oversized-path"])
def test_malformed_rows_are_rejected(tmp_path, field, value):
    row = dict(zip(browser._FIELDS, (7, "file", "file", START, START + 1, 0, 0, 1, 0, 0, 0)))
    row[field] = value
    with pytest.raises(ValueError):
        parse(database(tmp_path, rows=[tuple(row.values())]), tmp_path)
    assert not list(tmp_path.glob("chromium-downloads-*"))


@pytest.mark.parametrize("chains", [
    [(7, 0, b"blob")], [(7, 0, "x" * 65537)], [(7, -1, "url")],
    [(7, 1, "url")], [(8, 0, "url")], [(7, "bad", "url")],
    [(7, index, "url") for index in range(65)],
])
def test_malformed_and_oversized_chains(tmp_path, chains):
    with pytest.raises(ValueError):
        parse(database(tmp_path, chains=chains), tmp_path)


def test_unsupported_schema_and_views(tmp_path):
    content = database(tmp_path, extra_sql="CREATE VIEW fake AS SELECT * FROM downloads;")
    with pytest.raises(ValueError, match="views"):
        parse(content, tmp_path)
    path = tmp_path / "synthetic-History"
    with sqlite3.connect(path) as connection:
        connection.executescript("DROP VIEW fake; ALTER TABLE downloads RENAME COLUMN current_path TO full_path;")
    with pytest.raises(ValueError, match="schema"):
        parse(path.read_bytes(), tmp_path)


def test_fake_view_and_generated_schema(tmp_path):
    content = database(tmp_path)
    path = tmp_path / "synthetic-History"
    with sqlite3.connect(path) as connection:
        connection.executescript("ALTER TABLE downloads RENAME TO native_downloads; "
                                 "CREATE VIEW downloads AS SELECT * FROM native_downloads;")
    with pytest.raises(ValueError, match="views"):
        parse(path.read_bytes(), tmp_path)
    with sqlite3.connect(path) as connection:
        connection.executescript("DROP VIEW downloads; ALTER TABLE native_downloads RENAME TO downloads; "
                                 "ALTER TABLE downloads ADD COLUMN derived INTEGER GENERATED ALWAYS AS (id + 1);")
    with pytest.raises(ValueError, match="generated"):
        parse(path.read_bytes(), tmp_path)


def test_wal_and_bad_header_rejected(tmp_path):
    content = bytearray(database(tmp_path))
    content[18:20] = b"\x02\x02"
    with pytest.raises(ValueError, match="WAL"):
        parse(bytes(content), tmp_path)
    with pytest.raises(ValueError, match="header"):
        parse(b"not SQLite", tmp_path)
    with pytest.raises(ValueError):
        parse(bytes(content[:100]), tmp_path)


def test_record_and_byte_budgets(tmp_path, monkeypatch):
    content = database(tmp_path)
    monkeypatch.setattr(browser, "MAX_RECORDS", 2)
    with pytest.raises(ValueError, match="records exceed"):
        parse(content, tmp_path)
    monkeypatch.setattr(browser, "MAX_BYTES", len(content) - 1)
    with pytest.raises(ValueError, match="byte budget"):
        parse(content, tmp_path)


def test_progress_budget_interrupts_database_work(tmp_path, monkeypatch):
    rows = [(index, "file", "file", 0, 0, 0, 0, 1, 0, 0, 0) for index in range(1, 1001)]
    content = database(tmp_path, rows=rows, chains=[])
    monkeypatch.setattr(browser, "MAX_SQL_STEPS", 0)
    with pytest.raises(ValueError, match="over-budget"):
        parse(content, tmp_path)
    assert not list(tmp_path.glob("chromium-downloads-*"))


def test_strict_integer_validator_rejects_boolean():
    with pytest.raises(ValueError):
        browser._integer(True, "id")


def test_empty_native_tables(tmp_path):
    assert parse(database(tmp_path, rows=[], chains=[]), tmp_path) == []


def test_native_ids_are_sorted_independently_of_chain_order(tmp_path):
    rows = [(index, "file", "file", 0, 0, 0, 0, 1, 0, 0, 0) for index in (20, 3)]
    content = database(tmp_path, rows=rows, chains=[(20, 0, "url20"), (3, 0, "url3")])
    observations = parse(content, tmp_path)
    assert [item["source_record"] for item in observations] == [3, 20]
    assert len({item["id"] for item in observations}) == 2


def test_virtual_tables_and_corrupt_database(tmp_path):
    database(tmp_path)
    path = tmp_path / "synthetic-History"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE VIRTUAL TABLE fake USING fts5(value)")
    with pytest.raises(ValueError, match="virtual tables"):
        parse(path.read_bytes(), tmp_path)
    corrupt = path.read_bytes()[:100] + b"\0" * 4096
    with pytest.raises(ValueError):
        parse(corrupt, tmp_path)


@pytest.fixture
def without_sqlite_runtime_limits(monkeypatch):
    """Expose the Python 3.10 connection API on the installed SQLite runtime."""
    original = sqlite3.connect

    class LegacyConnection:
        def __init__(self, connection):
            self.connection = connection

        def __enter__(self):
            self.connection.__enter__()
            return self

        def __exit__(self, *args):
            return self.connection.__exit__(*args)

        def __getattr__(self, name):
            if name == "setlimit":
                raise AttributeError(name)
            return getattr(self.connection, name)

    def connect(*args, **kwargs):
        return LegacyConnection(original(*args, **kwargs))

    monkeypatch.setattr(browser.sqlite3, "connect", connect)


def test_python310_fallback_preserves_records(tmp_path, without_sqlite_runtime_limits):
    observation, = parse(database(tmp_path), tmp_path)
    assert observation["details"]["download_state"] == "complete"
    assert observation["execution_confirmed"] is False


def test_python310_fallback_field_and_record_bounds(tmp_path, monkeypatch, without_sqlite_runtime_limits):
    content = database(tmp_path)
    monkeypatch.setattr(browser, "MAX_RECORDS", 2)
    with pytest.raises(ValueError, match="records exceed"):
        parse(content, tmp_path)
    monkeypatch.setattr(browser, "MAX_RECORDS", 50000)
    path = tmp_path / "synthetic-History"
    # Legacy proxy supports ordinary SQLite context-manager use through its
    # wrapped connection; fixtures deliberately keep this outside the parser.
    connection = browser.sqlite3.connect(path)
    try:
        connection.execute("UPDATE downloads SET interrupt_reason=?", (b"x" * 65537,))
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(ValueError, match="field"):
        parse(path.read_bytes(), tmp_path)


def test_python310_fallback_rejects_views_before_download_query(tmp_path, monkeypatch):
    content = database(tmp_path, extra_sql="CREATE VIEW fake AS SELECT * FROM downloads;")
    original = sqlite3.connect
    traces = []

    class LegacyConnection:
        def __init__(self, connection):
            self.connection = connection

        def __getattr__(self, name):
            if name == "setlimit":
                raise AttributeError(name)
            return getattr(self.connection, name)

    def connect(*args, **kwargs):
        connection = original(*args, **kwargs)
        connection.set_trace_callback(traces.append)
        return LegacyConnection(connection)

    monkeypatch.setattr(browser.sqlite3, "connect", connect)
    with pytest.raises(ValueError, match="views"):
        parse(content, tmp_path)
    assert not any("FROM downloads " in sql for sql in traces)
    assert "PRAGMA query_only=ON" in traces
    assert "PRAGMA trusted_schema=OFF" in traces


def test_python310_fallback_progress_bound(tmp_path, monkeypatch, without_sqlite_runtime_limits):
    # Build fixture through the underlying native connection, outside parser.
    path = tmp_path / "synthetic-History"
    connection = browser.sqlite3.connect(path)
    try:
        connection.executescript(SCHEMA)
        connection.executemany("INSERT INTO downloads VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                               [(index, "file", "file", 0, 0, 0, 0, 1, 0, 0, 0)
                                for index in range(1, 1001)])
        connection.commit()
    finally:
        connection.close()
    monkeypatch.setattr(browser, "MAX_SQL_STEPS", 0)
    with pytest.raises(ValueError, match="over-budget"):
        parse(path.read_bytes(), tmp_path)


def test_python310_fallback_caps_schema_fields(tmp_path, without_sqlite_runtime_limits):
    content = database(tmp_path, extra_sql='CREATE TABLE extra ("' + "x" * 65537 + '" TEXT);')
    with pytest.raises(ValueError, match="schema field"):
        parse(content, tmp_path)


def test_corrupt_unused_table_is_rejected(tmp_path):
    content = database(tmp_path, extra_sql="CREATE TABLE unused(a TEXT); INSERT INTO unused VALUES ('x');")
    connection = sqlite3.connect(tmp_path / "synthetic-History")
    try:
        root_page = connection.execute("SELECT rootpage FROM sqlite_schema WHERE name='unused'").fetchone()[0]
    finally:
        connection.close()
    page_size = int.from_bytes(content[16:18], "big")
    damaged = bytearray(content)
    damaged[(root_page - 1) * page_size] = 0xFF
    with pytest.raises(ValueError, match="integrity|Invalid or over-budget"):
        parse(bytes(damaged), tmp_path)
