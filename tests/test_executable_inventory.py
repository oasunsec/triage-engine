"""Executable inventory: artifacts joined per executable, with review reasons that never raise alerts."""

from datetime import timedelta

from triage_engine.executable_inventory import build_executable_inventory, command_target, volume_path
from tests.test_ntfs_artifacts import FILE_TIME, ROOT, T0, evidence, mft_record, ref, standard_records, times

VOLUME = "\\VOLUME{01db0a051da1d5cd-801db9b9}"


def prefetch(name, path, *, serial="801DB9B9", at=T0, oid=None, run_count=3):
    return {"id": oid or f"obs_pf_{name}_{serial}", "kind": "prefetch_run", "host": "WS-LAB-01",
            "timestamp": at.isoformat(), "details": {"name": name, "run_count": run_count, "export_record": {
                "FilesLoaded": f"{VOLUME}\\WINDOWS\\SYSTEM32\\NTDLL.DLL, {path}", "Volume0Serial": serial}}}


def config(kind, name, command, oid):
    return {"id": oid, "kind": kind, "host": "WS-LAB-01", "details": {"name": name, "location": "", "command": command}}


def amcache(path, publisher="", oid="obs_am"):
    return {"id": oid, "kind": "amcache_file", "host": "WS-LAB-01", "timestamp": T0.isoformat(),
            "details": {"path": path, "sha1": "a" * 40, "publisher": publisher, "product_name": ""}}


def by_path(inventory):
    return {entry["path"]: entry for entry in inventory["executables"]}


def codes(entry):
    return [reason["code"] for reason in entry["reasons"]]


def test_paths_are_volume_relative_and_default_expansions_are_recorded():
    assert volume_path(f"{VOLUME}\\PROGRAM FILES\\APP\\APP.EXE") == ("\\program files\\app\\app.exe", [])
    assert volume_path("C:\\Users\\Public\\upd.exe") == ("\\users\\public\\upd.exe", [])
    path, assumptions = command_target("%SystemRoot%\\System32\\svchost.exe -k netsvcs")
    assert path == "\\windows\\system32\\svchost.exe" and assumptions
    assert command_target("system32\\drivers\\wd\\KslD.sys")[0] == "\\windows\\system32\\drivers\\wd\\ksld.sys"
    assert command_target("%LOCALAPPDATA%\\x.exe") == ("", [])  # user-specific: not guessed
    assert command_target('"C:\\Program Files\\App\\app.exe" --run')[0] == "\\program files\\app\\app.exe"


def test_sources_join_on_one_executable_and_ordinary_software_has_no_reasons():
    observations = [
        prefetch("APP.EXE", f"{VOLUME}\\PROGRAM FILES\\APP\\APP.EXE"),
        config("service", "AppSvc", '"C:\\Program Files\\App\\app.exe" --service', "obs_svc"),
        amcache("c:\\program files\\app\\app.exe", publisher="Example Corp"),
        config("service", "netsvcs", "%SystemRoot%\\System32\\svchost.exe -k netsvcs", "obs_svchost"),
    ]
    inventory = build_executable_inventory(observations)
    app = by_path(inventory)["\\program files\\app\\app.exe"]
    assert len(app["runs"]) == 1 and len(app["persistence"]) == 1 and len(app["amcache"]) == 1
    assert sorted(app["observation_ids"]) == ["obs_am", "obs_pf_APP.EXE_801DB9B9", "obs_svc"]
    assert app["location"] == "program_files" and app["reasons"] == [] and app["file_system"] is None
    assert by_path(inventory)["\\windows\\system32\\svchost.exe"]["reasons"] == []
    assert inventory["summary"]["verdict_effect"] == "none" and inventory["summary"]["file_system_checked"] is False


def test_masquerading_temp_and_user_writable_reasons():
    observations = [
        config("service", "Updater", "C:\\Users\\Public\\svchost.exe", "obs_fake"),
        prefetch("SETUP.EXE", f"{VOLUME}\\USERS\\ANALYST\\APPDATA\\LOCAL\\TEMP\\SETUP.EXE"),
        prefetch("TOOL.EXE", f"{VOLUME}\\USERS\\ANALYST\\DOWNLOADS\\TOOL.EXE"),
        amcache("c:\\users\\analyst\\downloads\\tool.exe"),
    ]
    entries = by_path(build_executable_inventory(observations))
    assert codes(entries["\\users\\public\\svchost.exe"]) == [
        "system_name_outside_system_directory", "persists_from_user_writable_location"]
    assert codes(entries["\\users\\analyst\\appdata\\local\\temp\\setup.exe"]) == ["ran_from_temporary_directory"]
    assert codes(entries["\\users\\analyst\\downloads\\tool.exe"]) == [
        "ran_from_user_writable_location", "no_publisher_recorded"]
    assert all(reason["does_not_establish"] for entry in entries.values() for reason in entry["reasons"])
    ranked = [entry["path"] for entry in build_executable_inventory(observations)["executables"]]
    assert ranked[0] == "\\users\\public\\svchost.exe"


def test_file_system_facts_absence_and_recent_creation(tmp_path):
    ntfs, _, _ = evidence(tmp_path)  # $MFT holds \Users\Public\upd.exe, created 10 minutes before T0
    observations = [
        prefetch("UPD.EXE", f"{VOLUME}\\USERS\\PUBLIC\\UPD.EXE"),
        prefetch("GONE.EXE", f"{VOLUME}\\USERS\\PUBLIC\\GONE.EXE"),
        config("registry_run", "Stale", "C:\\Users\\Public\\stale.exe", "obs_run"),
    ]
    inventory = build_executable_inventory(observations, ntfs=ntfs, observed_at=(T0 + timedelta(days=1)).isoformat())
    entries = by_path(inventory)
    upd = entries["\\users\\public\\upd.exe"]
    assert upd["file_system"]["present"] is True and upd["file_system"]["size"] == 4096
    assert codes(upd) == ["ran_from_user_writable_location", "new_and_executed"]
    assert len(upd["file_system"]["observation_ids"]) == 2
    assert upd["display_path"] == "\\Users\\Public\\upd.exe"  # the $MFT's own spelling
    assert entries["\\users\\public\\stale.exe"]["display_path"] == "\\Users\\Public\\stale.exe"
    assert entries["\\users\\public\\gone.exe"]["display_path"] == "\\USERS\\PUBLIC\\GONE.EXE"
    assert codes(entries["\\users\\public\\gone.exe"]) == ["executed_but_absent", "ran_from_user_writable_location"]
    assert codes(entries["\\users\\public\\stale.exe"]) == [
        "persistence_target_absent", "persists_from_user_writable_location"]
    assert inventory["summary"]["file_system_checked"] is True
    # Older than the recent window: no longer "new".
    later = build_executable_inventory(observations, ntfs=ntfs, observed_at=(FILE_TIME + timedelta(days=30)).isoformat())
    assert "new_and_executed" not in codes(by_path(later)["\\users\\public\\upd.exe"])


def test_absence_is_not_claimed_when_prefetch_names_several_volumes(tmp_path):
    ntfs, _, _ = evidence(tmp_path)
    observations = [prefetch("GONE.EXE", f"{VOLUME}\\USERS\\PUBLIC\\GONE.EXE", serial="801DB9B9"),
                    prefetch("GONE.EXE", f"{VOLUME}\\USERS\\PUBLIC\\GONE.EXE", serial="12345678")]
    entry = by_path(build_executable_inventory(observations, ntfs=ntfs))["\\users\\public\\gone.exe"]
    assert entry["prefetch_volumes"] == ["12345678", "801DB9B9"]
    assert "executed_but_absent" not in codes(entry)


def test_unresolvable_inputs_are_counted_not_guessed():
    observations = [
        {"id": "obs_pf_x", "kind": "prefetch_run", "timestamp": T0.isoformat(),
         "details": {"name": "X.EXE", "export_record": {"FilesLoaded": ""}}},
        config("scheduled_task", "PerUser", "%LOCALAPPDATA%\\app\\x.exe", "obs_task"),
        amcache(""),
    ]
    inventory = build_executable_inventory(observations)
    assert inventory["executables"] == []
    assert inventory["summary"]["unresolved"] == {"prefetch_without_path": 1, "scheduled_task_unresolved_command": 1}


def versioned_records():
    records = standard_records()
    records[40] = mft_record(seq=1, directory=True, si=times(FILE_TIME), names=[(ref(31, 3), "1.2.0", times(FILE_TIME))])
    records[41] = mft_record(seq=1, si=times(FILE_TIME), data_size=10, names=[(ref(40, 1), "tool.exe", times(FILE_TIME))])
    return records


def test_absence_explained_by_a_newer_version_is_not_a_lead(tmp_path):
    # Real case: every "ran but gone" executable on one workstation was an updated program.
    ntfs, _, _ = evidence(tmp_path, versioned_records())
    observations = [prefetch("TOOL.EXE", f"{VOLUME}\\USERS\\PUBLIC\\1.1.0\\TOOL.EXE", oid="obs_old"),
                    prefetch("TOOL.EXE", f"{VOLUME}\\USERS\\PUBLIC\\SCRATCH\\TOOL.EXE", oid="obs_scratch")]
    entries = by_path(build_executable_inventory(observations, ntfs=ntfs))
    old = entries["\\users\\public\\1.1.0\\tool.exe"]
    assert "superseded_by_other_version" in codes(old) and "executed_but_absent" not in codes(old)
    assert old["other_version"] == "\\users\\public\\1.2.0\\tool.exe"
    # A folder that is not a version is not explained away.
    assert "executed_but_absent" in codes(entries["\\users\\public\\scratch\\tool.exe"])


def test_program_files_updates_and_missing_publishers_alone_are_not_leads(tmp_path):
    records = standard_records()
    records[50] = mft_record(seq=1, directory=True, si=times(FILE_TIME), names=[(ROOT, "Program Files", times(FILE_TIME))])
    records[51] = mft_record(seq=1, si=times(FILE_TIME), data_size=5, names=[(ref(50, 1), "browser.exe", times(FILE_TIME))])
    ntfs, _, _ = evidence(tmp_path, records)
    observations = [prefetch("BROWSER.EXE", f"{VOLUME}\\PROGRAM FILES\\BROWSER.EXE"),
                    amcache("c:\\users\\public\\devtool.exe", oid="obs_dev"),
                    config("service", "WinDefend",
                           '"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.1-0\\MsMpEng.exe"', "obs_def")]
    inventory = build_executable_inventory(observations, ntfs=ntfs, observed_at=(T0 + timedelta(days=1)).isoformat())
    entries = by_path(inventory)
    assert entries["\\program files\\browser.exe"]["file_system"]["present"] is True
    assert codes(entries["\\program files\\browser.exe"]) == []  # recently written, but admin-only location
    assert codes(entries["\\users\\public\\devtool.exe"]) == []
    defender = entries["\\programdata\\microsoft\\windows defender\\platform\\4.18.1-0\\msmpeng.exe"]
    assert defender["location"] == "windows" and "persists_from_user_writable_location" not in codes(defender)
    assert inventory["summary"]["with_reasons"] == sum(1 for entry in inventory["executables"] if entry["score"])


def test_empty_and_doubly_quoted_commands():
    assert command_target('""C:\\Windows\\System32\\DriverStore\\x.exe"" -run')[0] == \
        "\\windows\\system32\\driverstore\\x.exe"
    inventory = build_executable_inventory([config("scheduled_task", "ComHandler", "", "obs_com"),
                                            config("service", "Driver", "", "obs_drv")])
    assert inventory["summary"]["unresolved"] == {"scheduled_task_without_command": 1, "service_without_command": 1}
