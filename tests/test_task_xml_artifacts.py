"""Raw Task Scheduler XML: synthetic task files only, never read from this host."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from triage_engine import cli, service
from triage_engine.artifact_packager import pack_artifacts
from triage_engine.forensic_artifacts import read_forensic_bundle
from triage_engine.task_xml_artifacts import parse_task_xml

CONTEXT = {"source_name": "scheduled_task_xml-1.xml", "source_sha256": "d" * 64, "host": "WS-LAB-01",
           "observed_at": "2026-10-02T12:00:00Z", "collector": {"name": "test", "version": "1"}}
NS = 'xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"'


def task_xml(actions='<Exec><Command>C:\\Program Files\\Example\\upd.exe</Command><Arguments>/quiet</Arguments></Exec>',
             uri="<URI>\\Vendor\\Updater</URI>", date="2026-09-30T08:15:00", extra=""):
    return (f'<?xml version="1.0" encoding="UTF-16"?>\n{extra}<Task version="1.2" {NS}>'
            f'<RegistrationInfo><Date>{date}</Date><Author>CORP\\admin</Author>{uri}</RegistrationInfo>'
            '<Triggers><LogonTrigger><Enabled>true</Enabled><StartBoundary>2026-09-30T08:15:00</StartBoundary></LogonTrigger></Triggers>'
            '<Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>'
            '<Settings><Enabled>true</Enabled><Hidden>true</Hidden></Settings>'
            f'<Actions Context="Author">{actions}</Actions></Task>')


def utf16(text):
    return b"\xff\xfe" + text.encode("utf-16-le")


def test_utf16_task_produces_typed_observation_with_unverified_registration_date():
    observations, warnings = parse_task_xml(utf16(task_xml()), **CONTEXT)
    assert warnings == [] and len(observations) == 1
    item = observations[0]
    details = item["details"]
    assert item["kind"] == "scheduled_task" and item["time_semantics"] == "collection_snapshot"
    assert details["name"] == "Updater" and details["location"] == "\\Vendor" and details["task_path"] == "\\Vendor\\Updater"
    assert details["command"] == '"C:\\Program Files\\Example\\upd.exe" /quiet'
    assert details["action"]["executable"] == "C:\\Program Files\\Example\\upd.exe"
    assert details["registration_date"] == {"raw": "2026-09-30T08:15:00", "utc": None, "timezone": "unspecified"}
    assert details["hidden"] is True and details["run_level"] == "HighestAvailable" and details["user"] == "S-1-5-18"
    assert details["triggers"][0]["type"] == "LogonTrigger"
    assert "timestamp" not in item  # no activity timestamp is invented
    assert "unverified" in item["interpretation"]


def test_utf8_and_bomless_utf16_are_accepted_and_explicit_offsets_normalized():
    observations, _ = parse_task_xml(task_xml(date="2026-09-30T08:15:00-04:00").encode("utf-8"), **CONTEXT)
    assert observations[0]["details"]["registration_date"]["utc"] == "2026-09-30T12:15:00+00:00"
    observations, _ = parse_task_xml(task_xml().encode("utf-16-le"), **CONTEXT)
    assert observations[0]["details"]["name"] == "Updater"


def test_multiple_and_non_exec_actions_have_distinct_stable_ids():
    actions = ('<Exec><Command>C:\\a.exe</Command></Exec><ComHandler><ClassId>{0000-1}</ClassId></ComHandler>'
               '<Exec><Command>C:\\b.exe</Command></Exec>')
    first, _ = parse_task_xml(utf16(task_xml(actions)), **CONTEXT)
    second, _ = parse_task_xml(utf16(task_xml(actions)), **CONTEXT)
    assert [item["id"] for item in first] == [item["id"] for item in second]
    assert len({item["id"] for item in first}) == 3
    assert [item["details"]["action"]["type"] for item in first] == ["Exec", "ComHandler", "Exec"]
    assert first[1]["details"]["command"] == ""


def test_missing_uri_uses_file_name_with_warning():
    observations, warnings = parse_task_xml(utf16(task_xml(uri="")), original_name="elevator", **CONTEXT)
    assert observations[0]["details"]["task_path"] == "\\elevator" and warnings


@pytest.mark.parametrize("content, message", [
    (utf16(task_xml(extra='<!DOCTYPE Task [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;">]>')), "DOCTYPE"),
    (utf16(task_xml(extra='<!ENTITY x SYSTEM "file:///c:/windows/win.ini">')), "DOCTYPE"),
    (utf16("<Task " + NS + "><Actions>"), "Malformed"),
    (utf16(f"<Job {NS}></Job>"), "root element"),
    (b"\xff\xfe" + b"\x00\xd8", "UTF-16"),
    (b"", "1 byte"),
    (b"<" + b"a" * (1024 * 1024), "1 MiB"),
    (utf16(task_xml("<Exec><Command>C:\\a.exe</Command></Exec>" * 33)), "more than 32 actions"),
], ids=["entity-expansion", "external-entity", "truncated", "wrong-root", "bad-utf16", "empty", "oversized", "too-many-actions"])
def test_hostile_or_malformed_task_files_fail_closed(content, message):
    with pytest.raises(ValueError, match=message):
        parse_task_xml(content, **CONTEXT)


def write_task(folder, name, text):
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / name
    path.write_bytes(utf16(text))
    return path


def test_packaged_task_xml_is_retained_and_suspicious_action_is_flagged(tmp_path):
    benign = write_task(tmp_path / "Tasks", "Updater", task_xml())
    encoded = write_task(tmp_path / "Tasks", "Sync", task_xml(
        '<Exec><Command>powershell.exe</Command><Arguments>-enc QQBCAEMA</Arguments></Exec>', uri="<URI>\\Sync</URI>"))
    bundle = pack_artifacts(tmp_path / "bundle", host="WS-LAB-01", observed_at="2026-10-02T12:00:00Z",
                            scheduled_task_xml=[benign, encoded])
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    assert {item["kind"] for item in manifest["files"]} == {"scheduled_task_xml"}
    assert manifest["completeness"] == "partial"  # individually selected files are not a full Tasks directory
    result = read_forensic_bundle(str(bundle), temp_dir=tmp_path)
    assert len(result.observations) == 2
    assert [alert.rule_name for alert in result.alerts] == ["Persistence Snapshot: Encoded PowerShell launch configured"]
    assert result.alerts[0].scheduled_task == "Sync"


def test_cli_pack_accepts_task_xml(tmp_path):
    task = write_task(tmp_path / "Tasks", "Updater", task_xml())
    args = cli.build_parser().parse_args(["pack-artifacts", "--task-xml", str(task), "--host", "WS-LAB-01",
                                          "--observed-at", "2026-10-02T12:00:00Z", "--output-dir", str(tmp_path / "out")])
    assert cli.cmd_pack_artifacts(args) == 0
    assert (tmp_path / "out" / "scheduled_task_xml-1.xml").read_bytes() == task.read_bytes()


SAMPLE_EVTX = Path(__file__).resolve().parents[1] / "repo_cache" / "sbousseaden_EVTX-ATTACK-SAMPLES" / \
    "Privilege Escalation" / "sysmon_1_11_exec_as_system_via_schedtask.evtx"


@pytest.mark.skipif(not SAMPLE_EVTX.is_file(), reason="public EVTX-ATTACK-SAMPLES corpus not present in repo_cache")
def test_public_sysmon_sample_links_to_raw_task_definition(tmp_path):
    task = write_task(tmp_path / "Tasks", "elevator", task_xml(
        "<Exec><Command>c:\\Windows\\System32\\cmd.exe</Command></Exec>", uri="<URI>\\elevator</URI>"))
    bundle = pack_artifacts(tmp_path / "bundle", host="IEWIN7", observed_at="2019-05-12T00:32:38Z", scheduled_task_xml=[task])
    result = service.run_investigation(service.InvestigationRequest(
        str(SAMPLE_EVTX), artifact_bundle=str(bundle), case_name="raw-task", cases_dir=str(tmp_path / "cases")))
    links = json.loads((Path(result.case_path) / "evidence_relationships.json").read_text(encoding="utf-8"))["relationships"]
    assert [link["rule"]["name"] for link in links] == ["configured_action_matches_process_image"]
    assert links[0]["target"]["source_file"].endswith(".xml")
    findings = json.loads((Path(result.case_path) / "findings.json").read_text(encoding="utf-8"))
    assert any("Cross-Source" in finding["title"] for finding in findings["findings"])


def test_cli_pack_accepts_tasks_and_prefetch_folders(tmp_path):
    # A real Tasks folder held 293 files: too many paths for one Windows command line.
    tasks = tmp_path / "Tasks"
    (tasks / "Vendor" / "Nested").mkdir(parents=True)
    (tasks / "Top").write_bytes(utf16(task_xml(uri="<URI>\\Top</URI>")))
    (tasks / "Vendor" / "Nested" / "Deep").write_bytes(utf16(task_xml(uri="<URI>\\Vendor\\Nested\\Deep</URI>")))
    prefetch = tmp_path / "Prefetch"
    prefetch.mkdir()
    (prefetch / "TOOL.EXE-12345678.pf").write_bytes(b"MAM\x04" + b"\x00" * 16)
    (prefetch / "Layout.ini").write_bytes(b"not prefetch")
    args = cli.build_parser().parse_args([
        "pack-artifacts", "--host", "WS-LAB-01", "--observed-at", "2026-10-02T12:00:00Z",
        "--task-xml", str(tasks), "--prefetch-source", str(prefetch), "--output-dir", str(tmp_path / "out")])
    assert cli.cmd_pack_artifacts(args) == 0
    manifest = json.loads((tmp_path / "out" / "manifest.json").read_text(encoding="utf-8"))
    assert sorted((item["kind"], item["original_name"]) for item in manifest["files"]) == [
        ("prefetch_source", "TOOL.EXE-12345678.pf"), ("scheduled_task_xml", "Deep"), ("scheduled_task_xml", "Top")]
    empty = tmp_path / "Empty"
    empty.mkdir()
    args = cli.build_parser().parse_args([
        "pack-artifacts", "--host", "WS-LAB-01", "--observed-at", "2026-10-02T12:00:00Z",
        "--task-xml", str(empty), "--output-dir", str(tmp_path / "out2")])
    assert cli.cmd_pack_artifacts(args) == 1 and not (tmp_path / "out2").exists()
