"""Synthetic evidence checks; never query the development host."""

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from models.event_model import NormalizedEvent
from reporting.json_export import export_raw_events_stream
from corrobora import cli, service
from corrobora.evidence import bind_event_sources, capture_evidence, sha256_file, write_analysis_manifest
from corrobora.forensic_artifacts import read_forensic_bundle


def make_bundle(folder, command="C:\\Windows\\System32\\notepad.exe", **overrides):
    folder.mkdir(parents=True, exist_ok=True)
    records = {"schema_version": "1.0", "records": [
        {"kind": "registry_run", "name": "Example", "location": "HKCU\\Run", "command": command},
        {"kind": "service", "name": "NormalService", "location": "Win32_Service", "command": "service.exe", "enabled": True},
        {"kind": "scheduled_task", "name": "NormalTask", "location": "\\", "command": "task.exe", "enabled": False},
    ]}
    payload = json.dumps(records).encode()
    (folder / "persistence.json").write_bytes(payload)
    manifest = {"schema_version": "1.0", "kind": "windows_persistence_snapshot", "host": "LAB-HOST",
                "observed_at": "2026-10-02T12:00:00Z", "collector": {"name": "synthetic-test", "version": "1"},
                "completeness": "complete", "warnings": [],
                "files": [{"path": "persistence.json", "kind": "persistence_records", "size_bytes": len(payload),
                           "sha256": hashlib.sha256(payload).hexdigest()}]}
    manifest.update(overrides)
    (folder / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return folder, manifest


def test_snapshot_observations_have_no_event_or_execution_claim(tmp_path):
    folder, _ = make_bundle(tmp_path / "snapshot", "powershell.exe -EncodedCommand QQ==")
    result = read_forensic_bundle(str(folder))
    assert len(result.observations) == 3
    assert len(result.alerts) == 1
    alert = result.alerts[0]
    assert alert.event is None
    assert alert.severity == "medium"
    assert alert.evidence["execution_confirmed"] is False
    assert alert.evidence["time_semantics"] == "collection_snapshot"
    assert len(result.file_hashes) == 2
    assert all(observation["source_record"] == index for index, observation in enumerate(result.observations))


def test_benign_snapshot_is_not_inherently_malicious(tmp_path):
    folder, _ = make_bundle(tmp_path / "snapshot")
    result = read_forensic_bundle(str(folder))
    assert len(result.observations) == 3
    assert result.alerts == []


def test_verified_artifact_bytes_survive_record_schema_failure(tmp_path):
    folder, manifest = make_bundle(tmp_path / "input")
    records_path = folder / "persistence.json"
    records = json.loads(records_path.read_bytes())
    records["records"][0]["kind"] = "unknown_artifact"
    payload = json.dumps(records).encode()
    records_path.write_bytes(payload)
    manifest["files"][0].update(size_bytes=len(payload), sha256=hashlib.sha256(payload).hexdigest())
    (folder / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    cases = tmp_path / "cases"
    request = service.InvestigationRequest(input_source=str(folder), input_mode="artifact_bundle",
                                          case_name="malformed-records", cases_dir=str(cases))
    with pytest.raises(ValueError, match="Unsupported persistence record kind"):
        service.run_investigation(request)
    case = cases / "malformed-records"
    catalog = json.loads((case / "evidence_manifest.json").read_bytes())
    assert len(catalog["sources"]) == 2
    for source in catalog["sources"]:
        assert sha256_file(case / source["path"]) == source["sha256"]
    assert (case / "evidence" / (hashlib.sha256(payload).hexdigest() + ".json")).read_bytes() == payload
    assert json.loads((case / "run_status.json").read_bytes())["status"] == "failed"
    assert not (case / "analysis_manifest.json").exists()
    assert not (case / "report.html").exists()


@pytest.mark.parametrize("changes, message", [
    ({"schema_version": "9"}, "schema_version"),
    ({"observed_at": "2026-10-02T12:00:00"}, "timezone"),
    ({"warnings": ["failed"]}, "cannot claim complete"),
    ({"files": [{"kind": "persistence_records", "path": "../outside.json"}]}, "Unsafe artifact path"),
    ({"files": [{"kind": "persistence_records", "path": "C:/outside.json"}]}, "Unsafe artifact path"),
    ({"files": []}, "1–1024"),
])
def test_invalid_manifest_fails_closed(tmp_path, changes, message):
    folder, _ = make_bundle(tmp_path / "snapshot", **changes)
    with pytest.raises(ValueError, match=message):
        read_forensic_bundle(str(folder))


def test_tampered_source_and_unsupported_record_fail_closed(tmp_path):
    folder, manifest = make_bundle(tmp_path / "snapshot")
    path = folder / "persistence.json"
    path.write_bytes(path.read_bytes().replace(b"Example", b"Changed"))
    with pytest.raises(ValueError, match="SHA-256"):
        read_forensic_bundle(str(folder))
    data = json.loads(path.read_text())
    data["records"][0]["arbitrary_object"] = {"unbounded": []}
    payload = json.dumps(data).encode()
    path.write_bytes(payload)
    manifest["files"][0].update(size_bytes=len(payload), sha256=hashlib.sha256(payload).hexdigest())
    (folder / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="Unsupported persistence record field"):
        read_forensic_bundle(str(folder))


def test_evidence_capture_retains_exact_bytes_and_stable_event_locator(tmp_path):
    case = tmp_path / "case"
    case.mkdir()
    original = tmp_path / "Security.evtx"
    original.write_bytes(b"synthetic evidence bytes")
    sources = capture_evidence(str(case), [(str(original), "evtx")])
    original.write_bytes(b"changed after acquisition")
    assert Path(sources[0]["_retained_path"]).read_bytes() == b"synthetic evidence bytes"
    event = NormalizedEvent(4688, datetime.now(timezone.utc), channel="Security", provider="Windows", record_id="42",
                            source_file=sources[0]["_retained_path"])
    bind_event_sources([event], sources)
    assert event.source_file == sources[0]["path"]
    assert event.source_sha256 == sources[0]["sha256"]
    assert event.observation_id.startswith("obs_")
    retained = Path(sources[0]["_retained_path"])
    retained.write_bytes(b"tampered")
    original.write_bytes(b"synthetic evidence bytes")
    with pytest.raises(ValueError, match="Previously retained evidence"):
        capture_evidence(str(case), [(str(original), "evtx")])


def test_lossless_stream_keeps_repeated_script_records_and_xml(tmp_path, monkeypatch):
    monkeypatch.setenv("CORROBORA_DEMO_REDACTION", "1")
    events = [NormalizedEvent(4104, datetime.now(timezone.utc), computer="CodexSandboxPrivate",
                              event_data={"ScriptBlockText": "Write-Output hello", "ScriptBlockId": "same"},
                              command_line_value="  exact command  ", share_name_value="  exact share  ",
                              record_id=str(index), raw_xml=f"<Event>{index}</Event>") for index in (1, 2)]
    path = tmp_path / "raw_events.jsonl"
    summary = export_raw_events_stream(events, str(path))
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    assert len(rows) == summary["total_count"] == 2
    assert summary["redacted"] is False
    assert [row["record_id"] for row in rows] == ["1", "2"]
    assert rows[0]["raw_xml"] == "<Event>1</Event>"
    assert rows[0]["computer"] == "CodexSandboxPrivate"
    assert rows[0]["command_line_value"] == "  exact command  "
    assert rows[0]["share_name_value"] == "  exact share  "


def test_run_snapshots_keep_prior_output_when_projection_changes(tmp_path):
    case = tmp_path / "case"
    case.mkdir()
    output = case / "findings.json"
    output.write_text('{"version":1}')
    run_id = str(uuid.uuid4())
    manifest = write_analysis_manifest(str(case), run_id=run_id, sources=[], artifacts={"findings": str(output)},
                                       configuration={}, component_files=[], engine_version="test",
                                       partial_failures=[], collection_warnings=[])
    output.write_text('{"version":2}')
    snapshot = case / manifest["outputs"][0]["snapshot_path"]
    assert snapshot.read_text() == '{"version":1}'
    assert sha256_file(snapshot) == manifest["outputs"][0]["sha256"]
    with pytest.raises(ValueError, match="already exists"):
        write_analysis_manifest(str(case), run_id=run_id, sources=[], artifacts={}, configuration={},
                                component_files=[], engine_version="test", partial_failures=[], collection_warnings=[])


def test_artifact_only_pipeline_and_resume_preserve_sources_and_runs(tmp_path):
    bundle, _ = make_bundle(tmp_path / "input", "powershell.exe -enc QQ==")
    request = service.InvestigationRequest(str(bundle), input_mode="artifact_bundle", case_name="forensic-case",
                                          cases_dir=str(tmp_path / "cases"))
    with patch.object(service, "read_live", side_effect=AssertionError("live collection forbidden")), \
         patch.object(service, "_run_detectors", side_effect=AssertionError("event detectors forbidden")):
        result = service.run_investigation(request)
        first_manifest = json.loads(Path(result.artifacts["analysis_manifest"]).read_text())
        request.resume = True
        resumed = service.run_investigation(request)
    case = Path(result.case_path)
    findings = json.loads(Path(resumed.artifacts["findings"]).read_text())
    assert result.incident_count == 0
    assert result.finding_count == 1
    assert findings["case"]["chain_count"] == 0
    assert findings["case"]["first_seen"] == ""
    assert findings["case"]["primary_host"] == "LAB-HOST"
    assert findings["case"]["collection_quality_summary"]["parsed_event_count"] == 0
    assert findings["forensic_observations"][0]["source_file"].startswith("evidence/")
    assert findings["signals"][0]["evidence"]["execution_confirmed"] is False
    assert Path(result.artifacts["raw_events"]).read_text() == ""
    second_manifest = json.loads(Path(resumed.artifacts["analysis_manifest"]).read_text())
    assert first_manifest["case_id"] == second_manifest["case_id"]
    assert first_manifest["run_id"] != second_manifest["run_id"]
    assert len(list((case / "runs").glob("*/analysis_manifest.json"))) == 2
    for source in first_manifest["sources"]:
        assert sha256_file(case / source["path"]) == source["sha256"]
    for output in first_manifest["outputs"]:
        assert sha256_file(case / output["snapshot_path"]) == output["sha256"]
    assert "Observed Persistence Configuration" in Path(result.artifacts["report"]).read_text()
    from corrobora.product import export_case_bundle, verify_case_bundle
    archive = export_case_bundle(result.case_path, str(tmp_path / "evidence.zip"), include_sources=True)
    assert verify_case_bundle(archive)["valid"]


def test_combined_event_pipeline_reads_retained_input_and_keeps_snapshot_out_of_chains(tmp_path):
    bundle, _ = make_bundle(tmp_path / "input", "powershell.exe -enc QQ==")
    evtx = tmp_path / "events.evtx"
    evtx.write_bytes(b"synthetic evtx")
    request = service.InvestigationRequest(str(evtx), artifact_bundle=str(bundle), case_name="combined",
                                          cases_dir=str(tmp_path / "cases"))
    def parse(path, *args, source_files, **kwargs):
        assert path == str(evtx)
        assert source_files[0] != str(evtx)
        assert Path(source_files[0]).read_bytes() == b"synthetic evtx"
        return [NormalizedEvent(1, datetime.now(timezone.utc), computer="LAB-HOST", source_file=source_files[0], record_id="9")]
    with patch.object(service, "read_evtx_path", side_effect=parse), patch.object(service, "_run_detectors", return_value=([], {})), \
         patch.object(service, "correlate", return_value=[]) as correlate:
        result = service.run_investigation(request)
    assert correlate.call_args.args[0] == []
    rows = [json.loads(line) for line in Path(result.artifacts["raw_events"]).read_text().splitlines()]
    assert rows[0]["source_file"].startswith("evidence/")
    assert rows[0]["record_id"] == "9"
    assert rows[0]["observation_id"].startswith("obs_")
    assert result.incident_count == 0


def test_cli_artifact_only_does_not_select_automatic_live(tmp_path):
    bundle, _ = make_bundle(tmp_path / "input")
    args = cli.build_parser().parse_args(["investigate", "--artifacts", str(bundle)])
    with patch.object(cli, "_is_windows_host", return_value=True):
        assert cli._resolve_investigation_input(args) == (str(bundle), "artifact_bundle", None, None, False)


def test_event_only_rerun_clears_current_snapshot_projection(tmp_path):
    bundle, _ = make_bundle(tmp_path / "input")
    cases = tmp_path / "cases"
    first = service.run_investigation(service.InvestigationRequest(str(bundle), input_mode="artifact_bundle", case_name="same", cases_dir=str(cases)))
    evtx = tmp_path / "events.evtx"
    evtx.write_bytes(b"synthetic")
    with patch.object(service, "read_evtx_path", return_value=[]), patch.object(service, "_run_detectors", return_value=([], {})):
        second = service.run_investigation(service.InvestigationRequest(str(evtx), case_name="same", cases_dir=str(cases), resume=True))
    projection = json.loads(Path(second.artifacts["forensic_observations"]).read_text())
    assert projection["observations"] == []
    assert first.case_path == second.case_path
    manifests = list((Path(second.case_path) / "runs").glob("*/outputs/forensic_observations.json"))
    assert sorted(len(json.loads(path.read_text())["observations"]) for path in manifests) == [0, 3]


def test_parser_warning_and_skipped_sigma_rule_make_analysis_partial(tmp_path):
    evtx = tmp_path / "events.evtx"
    evtx.write_bytes(b"synthetic")
    def parse(path, *args, progress_callback, **kwargs):
        progress_callback({"status": "file_warning", "file_path": path, "warning": "record cap reached"})
        return []
    with patch.object(service, "read_evtx_path", side_effect=parse), patch.object(service, "_run_detectors", return_value=([], {})), \
         patch.object(service, "load_sigma_rules", return_value=([], ["unsupported modifier"])), \
         patch.object(service, "run_sigma_rules", return_value=([], [])):
        result = service.run_investigation(service.InvestigationRequest(str(evtx), cases_dir=str(tmp_path / "cases"), enable_sigma=True))
    manifest = json.loads(Path(result.artifacts["analysis_manifest"]).read_text())
    assert manifest["completeness"] == "partial"
    assert {item["component"] for item in manifest["partial_failures"]} == {"parser", "sigma"}
    assert any(item["name"] == "iocs.json" for item in manifest["components"])


def test_job_startup_reconciles_running_case_and_preserves_input(tmp_path, monkeypatch):
    import asyncio
    import server
    from corrobora import job_store
    data = tmp_path / "state"
    data.mkdir()
    monkeypatch.setattr(job_store, "_DB_DIR", str(data))
    monkeypatch.setattr(job_store, "_DB_PATH", str(data / "jobs.db"))
    job_store._init_db()
    cases = tmp_path / "cases"
    case = cases / "interrupted"
    case.mkdir(parents=True)
    status_path = case / "run_status.json"
    status_path.write_text(json.dumps({"status": "running", "current_stage": "parse", "metadata": {}}))
    upload = tmp_path / "uploads" / "input"
    upload.mkdir(parents=True)
    (upload / "source.evtx").write_bytes(b"preserve me")
    job_store.create_job("running", upload_path=str(upload))
    job_store.update_job("running", status="running", stage="parse", case_path=str(case))
    job_store.create_job("queued", upload_path=str(upload))
    job_store.create_job("done")
    job_store.update_job("done", status="completed")
    monkeypatch.setattr(server, "CASES_ROOT", str(cases))
    async def start():
        with patch.object(server, "_validate_startup_or_raise"), patch.object(server, "cleanup_expired_sessions"), \
             patch.object(server, "materialize_queue_index_for_completed_cases"):
            async with server._lifespan(server.app):
                assert job_store.get_job("running")["stage"] == "interrupted"
                assert job_store.get_job("queued")["status"] == "failed"
    asyncio.run(start())
    assert job_store.get_job("done")["status"] == "completed"
    assert job_store.get_job("running")["upload_path"] == str(upload)
    assert (upload / "source.evtx").read_bytes() == b"preserve me"
    assert json.loads(status_path.read_text())["status"] == "failed"
    assert job_store.reconcile_interrupted_jobs() == []


def test_deduplicated_alert_retains_each_source_locator():
    from correlation.attack_chain import deduplicate
    from models.event_model import Alert
    now = datetime.now(timezone.utc)
    events = [NormalizedEvent(1, now, source_file="evidence/a.evtx", record_id=str(index), observation_id=f"obs_{index}") for index in (1, 2)]
    alerts = [Alert("Example", "high", "Execution", "T1059", "description", "explanation", event) for event in events]
    merged = deduplicate(alerts)
    assert len(merged) == 1
    assert [item["record_id"] for item in merged[0].evidence["source_observations"]] == ["1", "2"]


def test_separate_snapshot_records_retain_separate_signal_identity(tmp_path):
    from corrobora.adapters import alerts_to_signals_findings
    folder, manifest = make_bundle(tmp_path / "snapshot", "powershell.exe -enc QQ==")
    path = folder / "persistence.json"
    data = json.loads(path.read_text())
    data["records"] = [data["records"][0], data["records"][0]]
    payload = json.dumps(data).encode()
    path.write_bytes(payload)
    manifest["files"][0].update(size_bytes=len(payload), sha256=hashlib.sha256(payload).hexdigest())
    (folder / "manifest.json").write_text(json.dumps(manifest))
    bundle = read_forensic_bundle(str(folder))
    signals, _, _ = alerts_to_signals_findings(bundle.alerts)
    assert len(signals) == 2
    assert {item.evidence["source_record"] for item in signals} == {0, 1}


def test_failed_rerun_cannot_export_mixed_outputs(tmp_path):
    from corrobora.product import export_case_bundle
    bundle, _ = make_bundle(tmp_path / "input")
    request = service.InvestigationRequest(str(bundle), input_mode="artifact_bundle", case_name="same", cases_dir=str(tmp_path / "cases"))
    result = service.run_investigation(request)
    request.resume = True
    with patch.object(service, "export_raw_events_stream", side_effect=OSError("synthetic disk failure")):
        with pytest.raises(RuntimeError, match="not completed"):
            service.run_investigation(request)
    status = json.loads((Path(result.case_path) / "run_status.json").read_text())
    assert status["status"] == "failed"
    with pytest.raises(ValueError, match="completed current analysis"):
        export_case_bundle(result.case_path, str(tmp_path / "mixed.zip"), include_sources=True)
