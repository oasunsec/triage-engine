import hashlib
import json
import sqlite3

import pytest

from corrobora.artifact_packager import pack_artifacts


def test_packager_copies_exact_bytes_and_writes_manifest(tmp_path):
    browser = tmp_path / "History"
    browser.write_bytes(b"caller selected offline sqlite bytes")
    pecmd = tmp_path / "export.jsonl"
    pecmd.write_bytes(b'{"SourceFile":"example.pf"}\n')
    prefetch = tmp_path / "original.pf"
    prefetch.write_bytes(b"native PF provenance")
    persistence = tmp_path / "records.json"
    persistence.write_bytes(b'{"records":[]}')

    output = pack_artifacts(tmp_path / "bundle", host="host-01", observed_at="2026-10-02T12:30:00-05:00",
                            chromium_history=[browser], pecmd_jsonl=[pecmd], prefetch_source=[prefetch],
                            persistence_records=[persistence], pecmd_version="2.3.4")

    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema_version"] == "1.1"
    assert manifest["kind"] == "windows_forensic_artifacts"
    assert manifest["collector"] == {"name": "triage-artifact-packager", "version": "3.0.0"}
    assert manifest["completeness"] == "partial"
    assert manifest["warnings"] == [
        "Persistence records supplied without their acquisition manifest; collector scope and failures are unknown."]
    assert [item["path"] for item in manifest["files"]] == [
        "chromium_history-1.sqlite", "pecmd_jsonl-1.jsonl", "prefetch_source-1.pf", "persistence_records-1.json"]
    for item in manifest["files"]:
        payload = (output / item["path"]).read_bytes()
        assert payload == {"chromium_history": browser, "pecmd_jsonl": pecmd,
                          "prefetch_source": prefetch, "persistence_records": persistence}[item["kind"]].read_bytes()
        assert item["size_bytes"] == len(payload)
        assert item["sha256"] == hashlib.sha256(payload).hexdigest()
        assert item["original_name"] in {browser.name, pecmd.name, prefetch.name, persistence.name}
        assert str(tmp_path) not in json.dumps(item)
    assert manifest["files"][1]["exporter"] == {"name": "PECmd", "version": "2.3.4"}


def test_prefetch_only_bundle_is_packed_and_empty_request_rejected(tmp_path):
    # Prefetch binaries are parsed natively, so a .pf-only bundle is now analytical.
    pf = tmp_path / "only.pf"
    pf.write_bytes(b"pf")
    output = pack_artifacts(tmp_path / "bundle", host="host", observed_at="2026-10-02T00:00:00Z", prefetch_source=[pf])
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    assert [item["kind"] for item in manifest["files"]] == ["prefetch_source"]
    empty = tmp_path / "empty"
    with pytest.raises(ValueError, match="between 1 and 1024"):
        pack_artifacts(empty, host="host", observed_at="2026-10-02T00:00:00Z")
    assert not empty.exists()


@pytest.mark.parametrize("observed_at", ["2026-10-02T00:00:00", "nope", ""])
def test_observed_at_requires_bounded_aware_iso_value(tmp_path, observed_at):
    src = tmp_path / "persist.json"
    src.write_text('{"records":[]}', encoding="utf-8")
    with pytest.raises(ValueError):
        pack_artifacts(tmp_path / "bundle", host="host", observed_at=observed_at, persistence_records=[src])
    assert not (tmp_path / "bundle").exists()


def test_rejects_existing_output_and_chromium_wal_sidecar(tmp_path):
    src = tmp_path / "History"
    src.write_bytes(b"standalone-ish")
    output = tmp_path / "existing"
    output.mkdir()
    with pytest.raises(FileExistsError):
        pack_artifacts(output, host="host", observed_at="2026-10-02T00:00:00Z", chromium_history=[src])

    sidecar_output = tmp_path / "sidecar-bundle"
    (tmp_path / "History-wal").write_bytes(b"wal")
    with pytest.raises(ValueError, match="standalone SQLite snapshot"):
        pack_artifacts(sidecar_output, host="host", observed_at="2026-10-02T00:00:00Z", chromium_history=[src])
    assert not sidecar_output.exists()


@pytest.mark.parametrize("version_bytes", [b"\x02\x00", b"\x00\x02", b"\x02\x02"])
def test_rejects_sqlite_wal_header(tmp_path, version_bytes):
    src = tmp_path / "History"
    db = sqlite3.connect(src)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("CREATE TABLE sample (value TEXT)")
    db.commit()
    db.close()
    # SQLite can checkpoint during close, so synthesize the documented header marker.
    content = bytearray(src.read_bytes())
    content[18:20] = version_bytes
    src.write_bytes(content)
    with pytest.raises(ValueError, match="WAL mode"):
        pack_artifacts(tmp_path / "bundle", host="host", observed_at="2026-10-02T00:00:00Z", chromium_history=[src])


def test_rejects_oversized_source_before_reading(tmp_path):
    src = tmp_path / "large.json"
    with src.open("wb") as handle:
        handle.truncate(64 * 1024 * 1024 + 1)
    with pytest.raises(ValueError, match="64 MiB"):
        pack_artifacts(tmp_path / "bundle", host="host", observed_at="2026-10-02T00:00:00Z", persistence_records=[src])
    assert not (tmp_path / "bundle").exists()


def test_rejects_member_count_before_source_access(tmp_path):
    with pytest.raises(ValueError, match="between 1 and 1024"):
        pack_artifacts(tmp_path / "bundle", host="host", observed_at="2026-10-02T00:00:00Z",
                       persistence_records=[tmp_path / f"missing-{index}.json" for index in range(1025)])
    assert not (tmp_path / "bundle").exists()


def test_rejects_pecmd_without_explicit_version(tmp_path):
    source = tmp_path / "export.jsonl"
    source.write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="PECmd version"):
        pack_artifacts(tmp_path / "bundle", host="host", observed_at="2026-10-02T00:00:00Z", pecmd_jsonl=[source])
    assert not (tmp_path / "bundle").exists()
