"""Cross-adapter cases use synthetic offline evidence, never host collection."""

import hashlib
import json
import sqlite3
import stat
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from corrobora import cli, service
from corrobora.artifact_packager import pack_artifacts
from corrobora.forensic_artifacts import read_forensic_bundle
from corrobora.product import export_case_bundle, verify_case_bundle
from corrobora.path_safety import is_link_or_reparse


def synthetic_sources(folder, *, parsing_error=False):
    folder.mkdir()
    history = folder / "synthetic-History"
    epoch = 11644473600000000
    with sqlite3.connect(history) as database:
        database.executescript("""
          CREATE TABLE downloads(id INTEGER PRIMARY KEY, current_path TEXT, target_path TEXT,
            start_time INTEGER, end_time INTEGER, received_bytes INTEGER, total_bytes INTEGER,
            state INTEGER, opened INTEGER, danger_type INTEGER, interrupt_reason INTEGER);
          CREATE TABLE downloads_url_chains(id INTEGER, chain_index INTEGER, url TEXT, PRIMARY KEY(id,chain_index));
        """)
        database.execute("INSERT INTO downloads VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                         (17, "C:/Evidence/report.exe", "C:/Evidence/report.exe", epoch + 1_000_000,
                          epoch + 2_000_000, 1024, 1024, 1, 1, 0, 0))
        database.executemany("INSERT INTO downloads_url_chains VALUES (?,?,?)",
                             [(17, 0, "https://example.test/start"), (17, 1, "https://example.test/report.exe")])
    export = folder / "synthetic-prefetch.jsonl"
    export.write_text(json.dumps({"SourceFilename": "C:/Evidence/REPORT.EXE-12AB3456.pf",
        "ExecutableName": "REPORT.EXE", "RunCount": "2", "Version": "30", "Hash": "12AB3456",
        "LastRun": "1970-01-01T00:00:01.5000000+00:00", "PreviousRun0": "1970-01-01T00:00:00+00:00",
        "ParsingError": parsing_error}) + "\n", encoding="utf-8")
    native = folder / "synthetic.pf"
    native.write_bytes(b"synthetic native provenance; no binary parsing")
    return history, export, native


def bundle(tmp_path, *, parsing_error=False):
    history, export, native = synthetic_sources(tmp_path / "sources", parsing_error=parsing_error)
    result = pack_artifacts(tmp_path / "bundle", host="LAB-HOST", observed_at="2026-10-02T12:00:00Z",
                            chromium_history=[history], pecmd_jsonl=[export], prefetch_source=[native],
                            pecmd_version="synthetic-test-version")
    return result


def test_mixed_sources_keep_activity_collection_and_provenance_separate(tmp_path):
    result = read_forensic_bundle(str(bundle(tmp_path)), temp_dir=tmp_path)
    assert result.alerts == []
    assert len(result.observations) == 3
    download = next(o for o in result.observations if o["kind"] == "browser_download")
    assert download["details"]["download_state"] == "complete"
    assert download["details"]["url_chain"][-1] == "https://example.test/report.exe"
    assert download["execution_confirmed"] is False
    assert download["timestamp"] == "1970-01-01T00:00:01+00:00"
    assert download["observed_at"] == "2026-10-02T12:00:00+00:00"
    runs = [o for o in result.observations if o["kind"] == "prefetch_run"]
    assert {o["native_locator"]["runField"] for o in runs} == {"LastRun", "PreviousRun0"}
    assert all(o["collector"]["version"] == "synthetic-test-version" for o in runs)
    assert {kind for _, kind in result.files} == {"artifact_manifest", "chromium_history", "pecmd_jsonl", "prefetch_source"}


def test_cli_pack_and_full_artifact_case_zip_and_rerun(tmp_path):
    history, export, native = synthetic_sources(tmp_path / "sources")
    packed = tmp_path / "bundle"
    assert cli.main(["pack-artifacts", "--host", "LAB-HOST", "--observed-at", "2026-10-02T12:00:00Z",
                     "--output-dir", str(packed), "--chromium-history", str(history),
                     "--pecmd-jsonl", str(export), "--pecmd-version", "test", "--prefetch-source", str(native)]) == 0
    request = service.InvestigationRequest(str(packed), input_mode="artifact_bundle", case_name="expanded",
                                          cases_dir=str(tmp_path / "cases"))
    with patch.object(service, "read_live", side_effect=AssertionError("host collection forbidden")), \
         patch.object(service, "_run_detectors", side_effect=AssertionError("event detectors forbidden")):
        first = service.run_investigation(request)
        assert first.finding_count == first.incident_count == 0
        first_manifest = json.loads(Path(first.artifacts["analysis_manifest"]).read_text())
        timeline = json.loads(Path(first.artifacts["timeline"]).read_text())
        findings = json.loads(Path(first.artifacts["findings"]).read_text())
        assert findings["case"]["chain_count"] == 0
        assert findings["case"]["first_seen"] == ""
        summary = findings["case"]["forensic_summary"]
        assert summary["first_recorded_activity"] == "1970-01-01T00:00:00+00:00"
        assert summary["last_recorded_activity"] == "1970-01-01T00:00:01.500000+00:00"
        assert summary["by_time_semantics"] == {"browser_download_start": 1, "prefetch_recorded_run": 2}
        assert len(timeline["timeline"]) == 3
        assert [row["time_semantics"] for row in timeline["timeline"]] == ["prefetch_recorded_run", "browser_download_start", "prefetch_recorded_run"]
        assert all(row["type"] == "artifact" and row["severity"] == "" for row in timeline["timeline"])
        assert all(o["source_file"].startswith("evidence/") for o in findings["forensic_observations"])
        assert Path(first.artifacts["raw_events"]).read_text() == ""
        html = Path(first.artifacts["report"]).read_text()
        assert "Recorded Forensic Activity" in html and "Observation; unscored" in html
        for source in first_manifest["sources"]:
            assert hashlib.sha256((Path(first.case_path) / source["path"]).read_bytes()).hexdigest() == source["sha256"]
        archive = export_case_bundle(first.case_path, str(tmp_path / "evidence.zip"), include_sources=True)
        assert verify_case_bundle(archive)["valid"]
        request.resume = True
        second = service.run_investigation(request)
    latest = json.loads(Path(second.artifacts["analysis_manifest"]).read_text())
    assert first_manifest["case_id"] == latest["case_id"]
    assert first_manifest["run_id"] != latest["run_id"]
    assert len(list((Path(first.case_path) / "runs").glob("*/analysis_manifest.json"))) == 2


def test_partial_prefetch_export_marks_analysis_partial_without_incident(tmp_path):
    source = bundle(tmp_path, parsing_error=True)
    result = service.run_investigation(service.InvestigationRequest(str(source), input_mode="artifact_bundle",
                                      case_name="partial", cases_dir=str(tmp_path / "cases")))
    manifest = json.loads(Path(result.artifacts["analysis_manifest"]).read_text())
    assert manifest["completeness"] == "partial"
    assert result.incident_count == result.finding_count == 0
    assert any("PECmd" in warning for warning in manifest["collection_warnings"])


def test_invalid_parser_input_is_retained_before_failure(tmp_path):
    source = bundle(tmp_path)
    manifest = json.loads((source / "manifest.json").read_text())
    member = next(item for item in manifest["files"] if item["kind"] == "pecmd_jsonl")
    content = b'{"SourceFilename":"incomplete"}\n'
    (source / member["path"]).write_bytes(content)
    member.update(sha256=hashlib.sha256(content).hexdigest(), size_bytes=len(content))
    (source / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="Incomplete PECmd"):
        service.run_investigation(service.InvestigationRequest(str(source), input_mode="artifact_bundle",
                                  case_name="invalid", cases_dir=str(tmp_path / "cases")))
    case = tmp_path / "cases" / "invalid"
    retained = json.loads((case / "evidence_manifest.json").read_text())
    assert any(s["sha256"] == member["sha256"] and (case / s["path"]).read_bytes() == content for s in retained["sources"])
    assert not (case / "analysis_manifest.json").exists()


def test_member_wal_sidecar_rejected_before_acquisition(tmp_path):
    source = bundle(tmp_path)
    member = next(item for item in json.loads((source / "manifest.json").read_text())["files"] if item["kind"] == "chromium_history")
    (source / (member["path"] + "-wal")).write_bytes(b"uncheckpointed")
    with pytest.raises(ValueError, match="standalone SQLite"):
        read_forensic_bundle(str(source), temp_dir=tmp_path)


def test_windows_reparse_attributes_detected_without_junction_api(tmp_path):
    # lstat exposes junction attributes on Python 3.10, which lacks is_junction.
    metadata = SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0x400)
    with patch.object(Path, "lstat", return_value=metadata):
        assert is_link_or_reparse(tmp_path / "junction")
        with pytest.raises(ValueError, match="links or junctions"):
            read_forensic_bundle(str(tmp_path / "junction"))


def test_manifest_duplicate_keys_are_rejected(tmp_path):
    source = bundle(tmp_path)
    manifest = source / "manifest.json"
    manifest.write_text(manifest.read_text().replace('"host": "LAB-HOST"', '"host": "OTHER", "host": "LAB-HOST"'))
    with pytest.raises(ValueError, match="Duplicate artifact JSON key"):
        read_forensic_bundle(str(source), temp_dir=tmp_path)


def test_mixed_persistence_scope_stays_partial_and_out_of_execution_incidents(tmp_path):
    history, export, _ = synthetic_sources(tmp_path / "sources")
    records = tmp_path / "sources" / "configuration.json"
    records.write_text(json.dumps({"schema_version": "1.0", "records": [{"kind": "registry_run",
        "name": "Updater", "location": "HKCU/Software/Microsoft/Windows/CurrentVersion/Run",
        "command": "powershell.exe -enc QQ=="}]}))
    packed = pack_artifacts(tmp_path / "bundle", host="LAB-HOST", observed_at="2026-10-02T12:00:00Z",
                           chromium_history=[history], pecmd_jsonl=[export], pecmd_version="test",
                           persistence_records=[records])
    result = service.run_investigation(service.InvestigationRequest(str(packed), input_mode="artifact_bundle",
                                      case_name="mixed", cases_dir=str(tmp_path / "cases")))
    findings = json.loads(Path(result.artifacts["findings"]).read_text())
    assert result.finding_count == 1
    assert result.incident_count == findings["case"]["chain_count"] == 0
    assert findings["case"]["forensic_summary"]["completeness"] == "partial"
    assert any("acquisition manifest" in warning for warning in findings["case"]["forensic_summary"]["warnings"])
    assert len(findings["forensic_observations"]) == 4
