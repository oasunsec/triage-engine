"""Default-logged service and task events linked to the binaries they configure (no Sysmon needed)."""

from datetime import timedelta

from models.event_model import NormalizedEvent
from corrobora.forensic_correlation import configured_binary_links
from tests.test_ntfs_artifacts import FILE_TIME, HOST, T0, evidence

VOLUME = "\\VOLUME{01db0a051da1d5cd-801db9b9}"


def service_event(image, *, at=T0, record="9", host=HOST, event_id=7045):
    return NormalizedEvent(event_id, at, computer=host, channel="System", provider="Service Control Manager",
                           event_data={"ServiceName": "Updater", "ImagePath": image, "ServiceAccount": "LocalSystem"},
                           record_id=record, source_file="evidence/s.evtx", source_sha256="a" * 64,
                           observation_id=f"obs_evt_{record}")


def task_event(command, *, at=T0, record="20"):
    xml = (f'<Task><Actions Context="Author"><Exec><Command>{command}</Command></Exec></Actions></Task>')
    return NormalizedEvent(4698, at, computer=HOST, channel="Security", provider="Microsoft-Windows-Security-Auditing",
                           event_data={"TaskName": "\\Updater", "TaskContent": xml}, record_id=record,
                           source_file="evidence/s.evtx", source_sha256="a" * 64, observation_id=f"obs_evt_{record}")


def prefetch_run(path, at, oid, host=HOST):
    return {"id": oid, "kind": "prefetch_run", "host": host, "timestamp": at.isoformat(),
            "time_semantics": "prefetch_recorded_run", "source_file": "evidence/p.pf", "source_record": 1,
            "source_sha256": "b" * 64, "details": {"name": path.rsplit("\\", 1)[-1],
                                                    "export_record": {"FilesLoaded": f"{VOLUME}{path.upper()}"}}}


def amcache(path, oid="obs_am"):
    return {"id": oid, "kind": "amcache_file", "host": HOST, "timestamp": T0.isoformat(),
            "time_semantics": "registry_key_last_write", "source_file": "evidence/a.hive", "source_record": 1,
            "source_sha256": "c" * 64, "details": {"path": path, "sha1": "d" * 40, "publisher": ""}}


def by_type(links):
    return {link["type"]: link for link in links}


def test_service_install_links_to_file_record_amcache_and_later_run(tmp_path):
    ntfs, observations, _ = evidence(tmp_path)  # \Users\Public\upd.exe, created 10 minutes before T0
    observations = observations + [amcache("c:\\users\\public\\upd.exe"),
                                   prefetch_run("\\Users\\Public\\upd.exe", T0 + timedelta(seconds=40), "obs_pf_after"),
                                   prefetch_run("\\Users\\Public\\upd.exe", T0 - timedelta(hours=2), "obs_pf_before")]
    links, counts = configured_binary_links([service_event('"C:\\Users\\Public\\upd.exe" -run')], observations, ntfs=ntfs)
    links = by_type(links)
    assert set(links) == {"configured_binary_file_record", "configured_binary_amcache_entry", "configured_binary_ran_after_event"}
    record = links["configured_binary_file_record"]
    assert record["time_relation"]["file_created_relative_to_event"] == "written_before_event"
    assert record["time_relation"]["seconds_from_event_to_file_creation"] == -600.0
    assert record["link_class"] == "observed_field_match" and record["contradictions"] == []
    assert any(item["id"] == record["target"]["observation_id"] for item in observations)  # materialized
    run = links["configured_binary_ran_after_event"]
    assert run["target"]["observation_id"] == "obs_pf_after" and run["link_class"] == "supported_inference"
    assert run["time_relation"]["seconds_from_event_to_first_run"] == 40.0
    assert links["configured_binary_amcache_entry"]["matched_fields"][-1]["value"] == "d" * 40
    assert all(link["does_not_establish"] for link in links.values())
    assert counts == {"events": 1, "file_records": 1, "amcache_entries": 1, "runs_after_event": 1}


def test_binary_written_after_the_event_is_a_contradiction(tmp_path):
    ntfs, observations, _ = evidence(tmp_path)
    links, _ = configured_binary_links([service_event("C:\\Users\\Public\\upd.exe", at=FILE_TIME - timedelta(hours=1))],
                                       observations, ntfs=ntfs)
    record = by_type(links)["configured_binary_file_record"]
    assert record["time_relation"]["file_created_relative_to_event"] == "written_after_event"
    assert [item["field"] for item in record["contradictions"]] == ["created"]


def test_absent_binary_runs_before_event_and_other_hosts_are_not_linked(tmp_path):
    ntfs, observations, _ = evidence(tmp_path)
    observations = observations + [prefetch_run("\\Users\\Public\\gone.exe", T0 - timedelta(minutes=5), "obs_old"),
                                   prefetch_run("\\Users\\Public\\gone.exe", T0 + timedelta(minutes=5), "obs_other", host="OTHER")]
    links, counts = configured_binary_links([service_event("C:\\Users\\Public\\gone.exe")], observations, ntfs=ntfs)
    assert links == [] and counts == {"events": 1, "binary_absent_at_collection": 1}


def test_task_creation_and_default_path_expansion(tmp_path):
    ntfs, observations, _ = evidence(tmp_path)
    links, counts = configured_binary_links([task_event("C:\\Users\\Public\\upd.exe")], observations, ntfs=ntfs)
    assert [link["type"] for link in links] == ["configured_binary_file_record"]
    assert links[0]["source"]["configuration"] == "scheduled task \\Updater"
    expanded, counts = configured_binary_links([service_event("%SystemRoot%\\System32\\svchost.exe -k netsvcs")], [], ntfs=None)
    assert expanded == [] and counts == {"events": 1}
    unresolved, counts = configured_binary_links([service_event("%LOCALAPPDATA%\\x.exe")], [], ntfs=None)
    assert unresolved == [] and counts == {"events": 1, "unresolved_command": 1}
