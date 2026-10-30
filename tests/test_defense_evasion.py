from datetime import datetime, timezone

from detectors.defense_evasion import detect
from models.event_model import NormalizedEvent


TS = datetime(2026, 8, 27, 12, 0, tzinfo=timezone.utc)


def _event(event_id, *, process="", parent="", command="", data=None, computer="HOST-1"):
    return NormalizedEvent(
        event_id=event_id,
        timestamp=TS,
        computer=computer,
        provider="Microsoft-Windows-Sysmon",
        channel="Microsoft-Windows-Sysmon/Operational",
        process_name_value=process,
        parent_process_value=parent,
        command_line_value=command,
        event_data=data or {},
    )


def test_system_binary_from_user_directory_is_masquerading():
    event = _event(
        1,
        process="C:\\Users\\Public\\wermgr.exe",
        parent="C:\\Windows\\explorer.exe",
    )
    hit = next(item for item in detect([event]) if item.mitre_technique == "T1036.005")
    assert hit.rule_name == "System Binary Name Masquerading"
    assert hit.confidence == "high"
    assert hit.evidence["standard_path"] is False
    assert hit.evidence["masqueraded_name"] == "wermgr.exe"


def test_system_binary_spawned_by_unexpected_parent_is_masquerading():
    event = _event(
        1,
        process="C:\\Windows\\System32\\wermgr.exe",
        parent="C:\\Windows\\SysWOW64\\rundll32.exe",
    )
    hit = next(item for item in detect([event]) if item.mitre_technique == "T1036.005")
    assert hit.confidence == "medium"
    assert hit.evidence["standard_path"] is True
    assert "rundll32.exe" in hit.evidence["parent_process"]


def test_legitimate_svchost_from_services_is_not_masquerading():
    event = _event(1, process="C:\\Windows\\System32\\svchost.exe", parent="C:\\Windows\\System32\\services.exe")
    assert not any(item.mitre_technique == "T1036.005" for item in detect([event]))


def test_system_binary_masquerading_deduplicates():
    event = _event(1, process="C:\\Users\\Public\\lsass.exe", parent="C:\\Windows\\System32\\services.exe")
    hits = [item for item in detect([event, event]) if item.mitre_technique == "T1036.005"]
    assert len(hits) == 1


def test_conhost_from_cmd_is_not_parent_masquerading():
    event = _event(1, process="C:\\Windows\\System32\\conhost.exe", parent="C:\\Windows\\System32\\cmd.exe")
    assert not any(item.mitre_technique == "T1036.005" for item in detect([event]))


def test_unsigned_hijack_marked_module_correlates_to_loader_command():
    guid = "{11111111-2222-3333-4444-555555555555}"
    process = _event(
        1,
        process="C:\\Windows\\System32\\rundll32.exe",
        parent="C:\\Windows\\System32\\svchost.exe",
        command="rundll32 windowscoredeviceinfo.dll,CreateBackdoor",
        data={"ProcessGuid": guid},
    )
    module_load = _event(
        7,
        process="C:\\Windows\\System32\\rundll32.exe",
        data={
            "ProcessGuid": guid,
            "ImageLoaded": "C:\\Windows\\System32\\WindowsCoreDeviceInfo.dll",
            "Signed": "false",
            "SignatureStatus": "Unavailable",
            "RuleName": "DLL Hijack - Update Session Orchestrator svc",
        },
    )

    hits = [item for item in detect([process, module_load]) if item.mitre_technique == "T1574.002"]
    assert len(hits) == 1
    hit = hits[0]
    assert hit.rule_name == "DLL Side-Loading / Hijack"
    assert hit.evidence["loaded_module"].endswith("WindowsCoreDeviceInfo.dll")
    assert hit.evidence["linked_commands"] == ["rundll32 windowscoredeviceinfo.dll,CreateBackdoor"]
    assert hit.evidence["evidence_strength"] == "high"


def test_signed_standard_module_without_hijack_context_is_ignored():
    module_load = _event(
        7,
        process="C:\\Windows\\System32\\svchost.exe",
        data={
            "ProcessGuid": "{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}",
            "ImageLoaded": "C:\\Windows\\System32\\taskschd.dll",
            "Signed": "true",
            "SignatureStatus": "Valid",
            "RuleName": "Persistence - Suspicious Schedule.Service Module Load",
        },
    )
    assert not any(item.mitre_technique == "T1574.002" for item in detect([module_load]))


def test_sip_registry_only_telemetry_is_detected():
    target = r"HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllPutSignedDataMsg\{11111111-2222-3333-4444-555555555555}\Dll"
    create_key = _event(
        12,
        process=r"C:\Windows\System32\regsvr32.exe",
        data={
            "TargetObject": target.rsplit("\\", 1)[0],
            "EventType": "CreateKey",
            "RuleName": "technique_id=T1553.003,technique_name=SIP and Trust Provider Hijacking",
        },
    )
    set_value = _event(
        13,
        process=r"C:\Windows\System32\regsvr32.exe",
        data={
            "TargetObject": target,
            "Details": r"C:\Users\Analyst\MySIP.dll",
            "EventType": "SetValue",
            "RuleName": "technique_id=T1553.003,technique_name=SIP and Trust Provider Hijacking",
        },
    )

    hits = [item for item in detect([create_key, set_value]) if item.rule_name == "SIP Trust Provider Registration"]
    assert len(hits) == 1
    assert hits[0].mitre_technique == "T1553.003"
    assert hits[0].evidence["event_ids"] == [13]
    assert hits[0].evidence["dll_path"].endswith("MySIP.dll")
