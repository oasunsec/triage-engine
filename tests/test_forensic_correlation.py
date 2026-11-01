"""Cross-source evidence links: synthetic records only, never host collection."""

import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from models.event_model import Alert, NormalizedEvent
from corrobora import service
from corrobora.artifact_packager import pack_artifacts
from corrobora.forensic_correlation import command_image, correlate_evidence, cross_source_alerts
from corrobora.product import export_case_bundle, verify_case_bundle

T0 = datetime(2026, 10, 1, 13, 20, tzinfo=timezone.utc)
SAMPLE_EVTX = Path(__file__).resolve().parents[1] / "repo_cache" / "sbousseaden_EVTX-ATTACK-SAMPLES" / \
    "Privilege Escalation" / "sysmon_1_11_exec_as_system_via_schedtask.evtx"


def process_event(image="C:\\Users\\Public\\upd.exe", *, host="WS-LAB-01", at=T0, parent="C:\\Windows\\System32\\taskeng.exe",
                  record="7", event_id=1, channel="Microsoft-Windows-Sysmon/Operational"):
    return NormalizedEvent(event_id, at, computer=host, channel=channel, provider="Microsoft-Windows-Sysmon",
                           process_name_value=image, parent_process_value=parent, record_id=record,
                           source_file="evidence/a.evtx", source_sha256="a" * 64, observation_id=f"obs_evt_{record}")


def task(command="C:\\Users\\Public\\upd.exe /quiet", *, host="WS-LAB-01", oid="obs_task"):
    return {"id": oid, "kind": "scheduled_task", "host": host, "observed_at": "2026-10-02T12:00:00+00:00",
            "time_semantics": "collection_snapshot", "source_file": "evidence/b.json", "source_record": 0,
            "source_sha256": "b" * 64, "details": {"name": "Updater", "location": "\\", "command": command}}


def prefetch(name="UPD.EXE", *, host="WS-LAB-01", at=T0 + timedelta(seconds=9), oid="obs_pf", files_loaded=""):
    return {"id": oid, "kind": "prefetch_run", "host": host, "timestamp": at.isoformat(),
            "observed_at": "2026-10-02T12:00:00+00:00", "time_semantics": "prefetch_recorded_run",
            "source_file": "evidence/c.jsonl", "source_record": 1, "source_sha256": "c" * 64,
            "details": {"name": name, "export_record": {"FilesLoaded": files_loaded}}}


def native_alert(event, severity="high"):
    return Alert("Suspicious Task Child", severity, "Execution", "T1053.005", "d", "e", event)


@pytest.mark.parametrize("command, expected", [
    ('"C:\\Program Files\\App\\app.exe" --run', ("c:\\program files\\app\\app.exe", "")),
    ("C:/Users/Public/upd.exe /quiet", ("c:\\users\\public\\upd.exe", "")),
    ("\\??\\C:\\Windows\\x.exe", ("c:\\windows\\x.exe", "")),
    ("%SystemRoot%\\System32\\svchost.exe -k netsvcs", ("", "environment_relative_path")),
    ("\\SystemRoot\\System32\\drivers\\x.sys", ("", "environment_relative_path")),
    ("powershell.exe -enc QQ==", ("", "not_a_full_path")),
    ("", ("", "empty_command")),
])
def test_command_image_resolution_is_conservative(command, expected):
    assert command_image(command) == expected


def test_exact_path_match_is_observed_with_launcher_inference_and_limits():
    relationships, coverage = correlate_evidence([process_event()], [task()])
    assert len(relationships) == 1
    link = relationships[0]
    assert link["link_class"] == "observed_field_match"
    assert link["source"]["observation_id"] == "obs_evt_7" and link["target"]["observation_id"] == "obs_task"
    assert link["source"]["source_sha256"] == "a" * 64 and link["target"]["source_record"] == 0
    assert link["inferred_claims"][0]["class"] == "supported_inference"
    assert link["time_relation"]["ordering_meaningful"] is False
    assert any("launched this process" in item for item in link["does_not_establish"])
    assert coverage["families"]["persistence_configuration"]["status"] == "observed"
    assert coverage["families"]["browser_download"]["status"] == "not_supplied"


def test_parent_not_a_launcher_keeps_field_match_without_inference():
    relationships, _ = correlate_evidence([process_event(parent="C:\\Windows\\explorer.exe")], [task()])
    assert relationships[0]["link_class"] == "observed_field_match"
    assert relationships[0]["inferred_claims"] == []


@pytest.mark.parametrize("event, observation", [
    (process_event(host="OTHER-HOST"), task()),                                     # wrong host
    (process_event(image="C:\\Temp\\upd.exe"), task()),                             # shared file name, other path
    (process_event(), task("%PUBLIC%\\upd.exe")),                                   # unresolved environment path
    (process_event(event_id=4663, channel="Security"), task()),                     # not a process creation
    (process_event(at=T0.replace(tzinfo=None)), task()),                            # naive time cannot be compared
])
def test_non_matching_or_unresolvable_inputs_produce_no_link(event, observation):
    relationships, _ = correlate_evidence([event], [observation])
    assert relationships == []


def test_fqdn_and_netbios_host_forms_match_and_retain_raw_values():
    relationships, _ = correlate_evidence([process_event(host="ws-lab-01.corp.example")], [task()])
    host_field = relationships[0]["matched_fields"][1]
    assert host_field["event_value"] == "ws-lab-01.corp.example" and host_field["artifact_value"] == "WS-LAB-01"


def test_prefetch_unique_run_in_window_is_supported_inference():
    relationships, coverage = correlate_evidence([process_event()], [prefetch(files_loaded="\\VOLUME{x}\\USERS\\PUBLIC\\UPD.EXE")])
    link = relationships[0]
    assert link["link_class"] == "supported_inference"
    assert link["time_relation"]["artifact_minus_event_seconds"] == 9
    assert any(field["artifact_field"] == "export_record.FilesLoaded" for field in link["matched_fields"])
    assert any("user" in item for item in link["does_not_establish"])
    assert coverage["families"]["prefetch"]["run_observations"] == 1


@pytest.mark.parametrize("offset", [timedelta(seconds=-6), timedelta(seconds=61), timedelta(days=1)])
def test_prefetch_outside_window_is_not_linked(offset):
    assert correlate_evidence([process_event()], [prefetch(at=T0 + offset)])[0] == []


def test_prefetch_with_reused_name_is_only_weak_association():
    events = [process_event(record="1"), process_event(image="C:\\Temp\\upd.exe", record="2", at=T0 + timedelta(seconds=3))]
    relationships, _ = correlate_evidence(events, [prefetch()])
    assert len(relationships) == 2
    assert {link["link_class"] for link in relationships} == {"weak_temporal_association"}
    assert all(link["ambiguity"]["candidate_events"] == 2 for link in relationships)


def test_prefetch_wrong_host_is_not_linked():
    assert correlate_evidence([process_event()], [prefetch(host="OTHER")])[0] == []


def test_relationships_are_deterministic_across_input_order():
    events = [process_event(record=str(i), at=T0 + timedelta(minutes=i)) for i in range(5)]
    observations = [task(), prefetch(at=T0 + timedelta(minutes=2, seconds=4))]
    first, _ = correlate_evidence(events, observations)
    second, _ = correlate_evidence(list(reversed(events)), list(reversed(observations)))
    assert first == second and len(first) == 6


def test_benign_links_never_raise_findings():
    event = process_event()
    relationships, _ = correlate_evidence([event], [task(), prefetch()])
    assert cross_source_alerts(relationships, [event], []) == []


def test_suspicious_event_with_links_raises_bounded_finding():
    event = process_event()
    relationships, _ = correlate_evidence([event], [task(), prefetch()])
    alerts = cross_source_alerts(relationships, [event], [native_alert(event, "medium")])
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_source == "forensic_correlation" and alert.event is event
    assert alert.severity == "medium"  # never above the contributing alert
    assert alert.confidence == "high"  # two independent artifact families
    assert set(alert.evidence["supporting_observation_ids"]) == {"obs_evt_7", "obs_task", "obs_pf"}
    assert alert.evidence["not_established"] and alert.evidence["alternate_explanations"]


def test_suspicious_configuration_alone_can_raise_finding_through_exact_link():
    event = process_event()
    relationships, _ = correlate_evidence([event], [task()])
    artifact_alert = Alert("Persistence Snapshot: x", "medium", "Persistence", "T1053.005", "d", "e", None,
                           evidence={"observation_id": "obs_task"})
    alerts = cross_source_alerts(relationships, [event], [artifact_alert])
    assert len(alerts) == 1 and alerts[0].confidence == "medium"


def test_weak_associations_alone_do_not_raise_findings():
    events = [process_event(record="1"), process_event(image="C:\\Temp\\upd.exe", record="2", at=T0 + timedelta(seconds=3))]
    relationships, _ = correlate_evidence(events, [prefetch()])
    assert cross_source_alerts(relationships, events, [native_alert(events[0])]) == []


def test_indexed_matching_is_bounded_for_large_inputs():
    events = [process_event(image=f"C:\\Apps\\tool{i % 500}.exe", record=str(i), at=T0 + timedelta(seconds=i * 7))
              for i in range(20000)]
    observations = [prefetch(name=f"TOOL{i % 500}.EXE", oid=f"obs_pf_{i}", at=T0 + timedelta(seconds=i * 7 + 2))
                    for i in range(20000)]
    started = time.perf_counter()
    relationships, _ = correlate_evidence(events, observations)
    assert time.perf_counter() - started < 20
    assert len(relationships) == 20000
    assert all(link["link_class"] == "supported_inference" for link in relationships)


# ---- pipeline integration ----

def mixed_bundle(tmp_path, *, command="C:\\Users\\Public\\upd.exe /quiet", host="WS-LAB-01"):
    sources = tmp_path / "sources"
    sources.mkdir()
    records = sources / "persistence.json"
    records.write_text(json.dumps({"schema_version": "1.0", "records": [
        {"kind": "scheduled_task", "name": "Updater", "location": "\\", "command": command, "enabled": True}]}), encoding="utf-8")
    export = sources / "prefetch.jsonl"
    export.write_text(json.dumps({"SourceFilename": "C:\\Windows\\Prefetch\\UPD.EXE-11223344.pf", "ExecutableName": "UPD.EXE",
                                  "RunCount": "1", "Version": "30", "Hash": "11223344",
                                  "LastRun": "2026-10-01T13:20:09.0000000+00:00", "ParsingError": False}) + "\n", encoding="utf-8")
    return pack_artifacts(tmp_path / "bundle", host=host, observed_at="2026-10-02T12:00:00Z",
                          persistence_records=[records], pecmd_jsonl=[export], pecmd_version="synthetic-test-version")


def run_mixed(tmp_path, *, detector_alerts=None, case="mixed", bundle=None, env=None, resume=False):
    bundle = bundle or mixed_bundle(tmp_path)
    evtx = tmp_path / "events.evtx"
    evtx.write_bytes(b"synthetic evtx")
    captured = {}

    def parse(path, *args, source_files, **kwargs):
        event = process_event()
        # Evidence binding assigns the retained source and its locator.
        event.source_file, event.observation_id, event.source_sha256 = source_files[0], "", ""
        captured["event"] = event
        return [event]

    def detect(events, **kwargs):
        return ([native_alert(captured["event"])] if detector_alerts else []), {}

    with patch.object(service, "read_evtx_path", side_effect=parse), patch.object(service, "_run_detectors", side_effect=detect),          patch.dict("os.environ", env or {}):
        return service.run_investigation(service.InvestigationRequest(
            str(evtx), artifact_bundle=str(bundle), case_name=case, cases_dir=str(tmp_path / "cases"), resume=resume))


def test_mixed_case_links_retained_sources_and_exports_relationships(tmp_path):
    result = run_mixed(tmp_path, detector_alerts=True)
    case = Path(result.case_path)
    links = json.loads((case / "evidence_relationships.json").read_text(encoding="utf-8"))
    assert links["schema_version"] == "1.0" and len(links["relationships"]) == 2
    manifest = json.loads((case / "evidence_manifest.json").read_text(encoding="utf-8"))
    retained = {source["sha256"] for source in manifest["sources"]}
    for link in links["relationships"]:
        assert link["source"]["source_sha256"] in retained and link["target"]["source_sha256"] in retained
        assert link["source"]["source_file"].startswith("evidence/") and link["target"]["source_file"].startswith("evidence/")
    findings = json.loads((case / "findings.json").read_text(encoding="utf-8"))
    cross = [f for f in findings["findings"] if "Cross-Source" in str(f.get("title", ""))]
    assert len(cross) == 1
    assert findings["case"]["forensic_correlation"]["cross_source_finding_count"] == 1
    assert len(findings["evidence_relationships"]) == 2
    observations = json.loads((case / "forensic_observations.json").read_text(encoding="utf-8"))["observations"]
    assert all(observation["relationship_ids"] for observation in observations)
    timeline = json.loads((case / "timeline.json").read_text(encoding="utf-8"))["timeline"]
    prefetch_rows = [row for row in timeline if row["type"] == "artifact"]
    assert prefetch_rows and prefetch_rows[0]["related_ids"]["relationship_ids"]
    assert "Evidence Links" in Path(result.artifacts["report"]).read_text(encoding="utf-8")
    archive = export_case_bundle(result.case_path, str(tmp_path / "case.zip"))
    assert verify_case_bundle(archive)["valid"]
    analysis = json.loads((case / "analysis_manifest.json").read_text(encoding="utf-8"))
    assert "evidence_relationships" in {output["kind"] for output in analysis["outputs"]}


def test_mixed_case_is_deterministic_across_reruns(tmp_path):
    first = run_mixed(tmp_path, detector_alerts=True, case="repeat")
    path = Path(first.case_path) / "evidence_relationships.json"
    first_links = json.loads(path.read_text(encoding="utf-8"))["relationships"]
    first_findings = json.loads((Path(first.case_path) / "findings.json").read_text(encoding="utf-8"))["findings"]
    rerun = run_mixed(tmp_path, detector_alerts=True, case="repeat", bundle=tmp_path / "bundle", resume=True)
    rerun_links = json.loads((Path(rerun.case_path) / "evidence_relationships.json").read_text(encoding="utf-8"))["relationships"]
    rerun_findings = json.loads((Path(rerun.case_path) / "findings.json").read_text(encoding="utf-8"))["findings"]
    assert first_links == rerun_links
    assert [finding["id"] for finding in first_findings] == [finding["id"] for finding in rerun_findings]


def test_mixed_case_without_suspicious_context_keeps_links_unscored(tmp_path):
    result = run_mixed(tmp_path, detector_alerts=False)
    findings = json.loads((Path(result.case_path) / "findings.json").read_text(encoding="utf-8"))
    assert findings["case"]["forensic_correlation"]["relationship_count"] == 2
    assert findings["case"]["forensic_correlation"]["cross_source_finding_count"] == 0
    assert findings["findings"] == [] and result.incident_count == 0


def test_mixed_case_wrong_host_produces_no_links(tmp_path):
    result = run_mixed(tmp_path, detector_alerts=True, bundle=mixed_bundle(tmp_path, host="OTHER-HOST"))
    findings = json.loads((Path(result.case_path) / "findings.json").read_text(encoding="utf-8"))
    assert findings["case"]["forensic_correlation"]["relationship_count"] == 0


def test_correlation_feature_flag_disables_links(tmp_path):
    result = run_mixed(tmp_path, detector_alerts=True, env={"CORROBORA_FORENSIC_CORRELATION": "0"})
    findings = json.loads((Path(result.case_path) / "findings.json").read_text(encoding="utf-8"))
    assert findings["case"]["forensic_correlation"]["enabled"] is False
    assert findings["evidence_relationships"] == []


def test_evtx_only_case_has_no_correlation_sections(tmp_path):
    evtx = tmp_path / "events.evtx"
    evtx.write_bytes(b"synthetic")
    with patch.object(service, "read_evtx_path", return_value=[process_event()]), \
         patch.object(service, "_run_detectors", return_value=([], {})):
        result = service.run_investigation(service.InvestigationRequest(str(evtx), cases_dir=str(tmp_path / "cases")))
    findings = json.loads((Path(result.case_path) / "findings.json").read_text(encoding="utf-8"))
    assert "evidence_relationships" not in findings and "forensic_correlation" not in findings["case"]
    links = json.loads((Path(result.case_path) / "evidence_relationships.json").read_text(encoding="utf-8"))
    assert links["relationships"] == []


@pytest.mark.skipif(not SAMPLE_EVTX.is_file(), reason="public EVTX-ATTACK-SAMPLES corpus not present in repo_cache")
def test_public_sysmon_scheduled_task_sample_links_to_synthetic_artifacts(tmp_path):
    sources = tmp_path / "sources"
    sources.mkdir()
    records = sources / "persistence.json"
    records.write_text(json.dumps({"schema_version": "1.0", "records": [
        {"kind": "scheduled_task", "name": "elevator", "location": "\\", "command": "c:\\Windows\\System32\\cmd.exe"}]}), encoding="utf-8")
    export = sources / "prefetch.jsonl"
    export.write_text(json.dumps({"SourceFilename": "C:\\Windows\\Prefetch\\CMD.EXE-4A81B364.pf", "ExecutableName": "CMD.EXE",
                                  "RunCount": "3", "Version": "17", "LastRun": "2019-05-12T00:32:40.0000000+00:00",
                                  "ParsingError": False}) + "\n", encoding="utf-8")
    bundle = pack_artifacts(tmp_path / "bundle", host="IEWIN7", observed_at="2019-05-12T01:00:00Z",
                            persistence_records=[records], pecmd_jsonl=[export], pecmd_version="synthetic-test-version")
    result = service.run_investigation(service.InvestigationRequest(
        str(SAMPLE_EVTX), artifact_bundle=str(bundle), case_name="public-sample", cases_dir=str(tmp_path / "cases")))
    links = json.loads((Path(result.case_path) / "evidence_relationships.json").read_text(encoding="utf-8"))["relationships"]
    task_links = [link for link in links if link["rule"]["name"] == "configured_action_matches_process_image"]
    assert len(task_links) == 1
    assert task_links[0]["source"]["parent_process"].lower().endswith("taskeng.exe")
    assert task_links[0]["inferred_claims"][0]["class"] == "supported_inference"
    prefetch_links = [link for link in links if link["rule"]["name"] == "prefetch_run_matches_process_creation"]
    assert [link["link_class"] for link in prefetch_links] == ["supported_inference"]


def test_markup_in_linked_evidence_is_not_rendered_as_html(tmp_path):
    image = r"C:\Users\Public\</script><img src=x onerror=alert(1)>.exe"
    bundle = mixed_bundle(tmp_path, command=f'"{image}"')
    evtx = tmp_path / "events.evtx"
    evtx.write_bytes(b"synthetic evtx")
    with patch.object(service, "read_evtx_path", side_effect=lambda *a, source_files, **k: [
            _bound(process_event(image=image), source_files[0])]), patch.object(service, "_run_detectors", return_value=([], {})):
        result = service.run_investigation(service.InvestigationRequest(
            str(evtx), artifact_bundle=str(bundle), case_name="markup", cases_dir=str(tmp_path / "cases")))
    links = json.loads((Path(result.case_path) / "evidence_relationships.json").read_text(encoding="utf-8"))["relationships"]
    assert links, "markup path should still link as plain text"
    html = Path(result.artifacts["report"]).read_text(encoding="utf-8")
    # Evidence text is embedded as JSON inside <script>; it must not be able to close that element.
    assert "</script><img" not in html
    assert r"<\/script><img src=x onerror" in html


def _bound(event, source_file):
    event.source_file, event.observation_id, event.source_sha256 = source_file, "", ""
    return event


# ---- configuration-change events against snapshot records ----

TASK_XML = ('<?xml version="1.0" encoding="UTF-16"?><Task><Actions Context="Author"><Exec>'
            '<Command>C:\\Users\\Public\\upd.exe</Command><Arguments>/quiet</Arguments></Exec></Actions></Task>')


def config_event(event_id, data, *, host="WS-LAB-01", at=T0, record="40", channel="Security", provider="Microsoft-Windows-Security-Auditing"):
    return NormalizedEvent(event_id, at, computer=host, channel=channel, provider=provider, event_data=data,
                           record_id=record, source_file="evidence/a.evtx", source_sha256="a" * 64,
                           observation_id=f"obs_cfg_{record}")


def test_task_created_event_matches_snapshot_name_and_command():
    event = config_event(4698, {"TaskName": "\\Updater", "TaskContent": TASK_XML})
    relationships, coverage = correlate_evidence([event], [task()])
    assert len(relationships) == 1
    link = relationships[0]
    assert link["rule"]["name"] == "configuration_event_matches_record" and link["link_class"] == "observed_field_match"
    assert link["source"]["configuration_change"] == "created"
    assert any(field["event_field"] == "configured command" for field in link["matched_fields"])
    assert link["contradictions"] == [] and link["inferred_claims"][0]["class"] == "supported_inference"
    assert link["time_relation"]["event_before_collection"] is True
    assert coverage["families"]["windows_configuration_change"]["count"] == 1


def test_task_command_difference_is_a_contradiction_without_inference():
    xml = TASK_XML.replace("upd.exe", "other.exe")
    relationships, _ = correlate_evidence([config_event(4702, {"TaskName": "\\Updater", "TaskContent": xml})], [task()])
    link = relationships[0]
    assert link["contradictions"][0]["field"] == "command" and link["inferred_claims"] == []


def test_task_deleted_before_collection_but_present_is_contradiction():
    relationships, _ = correlate_evidence([config_event(4699, {"TaskName": "\\Updater", "TaskContent": TASK_XML})], [task()])
    assert {item["field"] for item in relationships[0]["contradictions"]} == {"existence"}


def test_task_in_other_folder_or_host_is_not_linked():
    assert correlate_evidence([config_event(4698, {"TaskName": "\\Vendor\\Updater", "TaskContent": TASK_XML})], [task()])[0] == []
    assert correlate_evidence([config_event(4698, {"TaskName": "\\Updater"}, host="OTHER")], [task()])[0] == []


def test_service_install_matches_by_name_and_image_path():
    service_record = {**task(), "kind": "service", "id": "obs_svc",
                      "details": {"name": "ExampleSvc", "location": "Win32_Service", "command": "C:\\Svc\\svc.exe"}}
    event = config_event(7045, {"ServiceName": "ExampleSvc", "ImagePath": "C:\\Svc\\svc.exe"}, channel="System",
                         provider="Service Control Manager")
    relationships, _ = correlate_evidence([event], [service_record])
    names = {link["rule"]["name"] for link in relationships}
    assert names == {"configuration_event_matches_record"}
    assert len(relationships[0]["matched_fields"]) == 3


def test_sysmon_run_key_write_matches_hive_independent_path():
    run_record = {**task(), "kind": "registry_run", "id": "obs_run",
                  "details": {"name": "Updater", "location": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                              "command": "C:\\Users\\Public\\upd.exe"}}
    event = config_event(13, {"TargetObject": "HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
                              "Details": "C:\\Users\\Public\\upd.exe"},
                         channel="Microsoft-Windows-Sysmon/Operational", provider="Microsoft-Windows-Sysmon")
    relationships, _ = correlate_evidence([event], [run_record])
    assert len(relationships) == 1 and relationships[0]["contradictions"] == []
    # A non-Sysmon event 13 is a different event and must not be treated as a registry write.
    event.channel, event.provider = "System", "Other"
    assert correlate_evidence([event], [run_record])[0] == []


def test_suspicious_task_creation_with_snapshot_raises_configuration_finding():
    event = config_event(4698, {"TaskName": "\\Updater", "TaskContent": TASK_XML})
    relationships, _ = correlate_evidence([event], [task()])
    alerts = cross_source_alerts(relationships, [event], [native_alert(event)])
    assert len(alerts) == 1 and "configuration change" in alerts[0].rule_name
    assert alerts[0].evidence["contradictions"] == []


def test_routine_service_install_linked_to_hive_stays_a_relationship():
    # Real Windows 11 case: Defender's KslD driver reinstall (7045) linked to the SYSTEM hive.
    def linked(image):
        record = {**task(), "kind": "service", "id": "obs_svc",
                  "details": {"name": "KslD", "location": "HKLM\\SYSTEM\\ControlSet001\\Services", "command": image}}
        event = config_event(7045, {"ServiceName": "KslD", "ImagePath": image, "ServiceAccount": "LocalSystem"},
                             channel="System", provider="Service Control Manager")
        relationships, _ = correlate_evidence([event], [record])
        assert len(relationships) == 1
        return event, relationships

    from detectors import persistence
    event, relationships = linked("system32\\drivers\\wd\\KslD.sys")
    routine = [a for a in persistence.detect([event]) if a.rule_name == "Service Installed"]
    assert routine and cross_source_alerts(relationships, [event], routine) == []

    event, relationships = linked("C:\\Users\\Public\\KslD.exe")
    suspicious = persistence.detect([event])
    assert len(cross_source_alerts(relationships, [event], suspicious)) == 1


SAMPLE_4698 = Path(__file__).resolve().parents[1] / "repo_cache" / "sbousseaden_EVTX-ATTACK-SAMPLES" / "Execution" / \
    "temp_scheduled_task_4698_4699.evtx"


@pytest.mark.skipif(not SAMPLE_4698.is_file(), reason="public EVTX-ATTACK-SAMPLES corpus not present in repo_cache")
def test_public_task_create_delete_sample_reports_contradiction_for_present_task(tmp_path):
    from parser.evtx_reader import read_evtx_path
    from corrobora.evidence import bind_event_sources, capture_evidence
    sources = capture_evidence(str(tmp_path), [(str(SAMPLE_4698), "evtx")])
    events = read_evtx_path(str(SAMPLE_4698), source_files=[sources[0]["_retained_path"]])
    bind_event_sources(events, sources)
    record = {**task(host=events[0].computer), "details": {"name": "CYAlyNSS", "location": "\\", "command": ""},
              "observed_at": "2019-03-20T00:00:00+00:00"}  # events were recorded 2019-03-19
    relationships, _ = correlate_evidence(events, [record])
    changes = sorted(link["source"]["configuration_change"] for link in relationships)
    assert changes == ["created", "deleted"]
    deleted = next(link for link in relationships if link["source"]["configuration_change"] == "deleted")
    assert deleted["contradictions"][0]["field"] == "existence"
    # Collected before the deletion: the snapshot is consistent with the events.
    earlier = {**record, "observed_at": "2019-03-19T00:02:04.330000+00:00"}
    relationships, _ = correlate_evidence(events, [earlier])
    assert all(link["contradictions"] == [] for link in relationships)
