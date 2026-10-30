from datetime import datetime, timedelta, timezone

from detectors.telemetry_context import detect
from detectors.credential_access import detect as credential_detect
from models.event_model import NormalizedEvent
from triage_engine.adapters import alerts_to_signals_findings
from detectors.fp_filter import FPFilter


TS = datetime(2026, 8, 31, 12, 0, tzinfo=timezone.utc)


def _event(
    event_id,
    *,
    provider="Microsoft-Windows-Sysmon",
    channel="Microsoft-Windows-Sysmon/Operational",
    computer="HOST-1",
    process="",
    parent="",
    command="",
    source_ip="",
    destination_ip="",
    logon_type="",
    data=None,
    timestamp=TS,
):
    return NormalizedEvent(
        event_id=event_id,
        timestamp=timestamp,
        computer=computer,
        provider=provider,
        channel=channel,
        process_name_value=process,
        parent_process_value=parent,
        command_line_value=command,
        source_ip=source_ip,
        destination_ip=destination_ip,
        logon_type=logon_type,
        event_data=data or {},
    )


def _rules(alerts, name):
    return [alert for alert in alerts if alert.rule_name == name]


def test_eventlog_104_is_detected_and_promoted():
    event = _event(
        104,
        provider="Microsoft-Windows-Eventlog",
        channel="System",
        data={"SubjectUserName": "admin", "SubjectDomainName": "CORP", "Channel": "System"},
    )
    alerts = _rules(detect([event]), "Windows Event Log Cleared")
    assert len(alerts) == 1
    assert alerts[0].mitre_technique == "T1070.001"
    _, findings, _ = alerts_to_signals_findings(alerts)
    assert len(findings) == 1


def test_eventlog_104_ignores_unrelated_provider():
    event = _event(104, provider="Example-Application", channel="Application")
    assert not _rules(detect([event]), "Windows Event Log Cleared")


def test_attrib_hidden_executable_is_detected():
    event = _event(
        1,
        process=r"C:\Windows\System32\attrib.exe",
        parent=r"C:\Windows\System32\cmd.exe",
        command="attrib +h nbtscan.exe",
        data={"Image": r"C:\Windows\System32\attrib.exe", "RuleName": "technique_id=T1158"},
    )
    alert = _rules(detect([event]), "Hidden Executable Attribute Set")[0]
    assert alert.mitre_technique == "T1564.001"
    assert alert.evidence["target"] == "nbtscan.exe"


def test_attrib_normal_text_file_is_not_promoted():
    event = _event(1, process="attrib.exe", command="attrib +h readme.txt")
    assert not _rules(detect([event]), "Hidden Executable Attribute Set")


def test_uac_enablelua_zero_is_detected_from_registry_event():
    event = _event(
        13,
        process=r"C:\Windows\System32\reg.exe",
        data={
            "TargetObject": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA",
            "Details": "DWORD (0x00000000)",
            "EventType": "SetValue",
        },
    )
    alert = _rules(detect([event]), "UAC Protections Disabled")[0]
    assert alert.mitre_technique == "T1548.002"
    assert alert.evidence["enablelua_disabled"] is True


def test_uac_enablelua_one_is_not_detected():
    event = _event(
        13,
        data={
            "TargetObject": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA",
            "Details": "DWORD (0x00000001)",
            "EventType": "SetValue",
        },
    )
    assert not _rules(detect([event]), "UAC Protections Disabled")


def test_kernel_debug_settings_are_collapsed_to_one_alert():
    events = [
        _event(
            4826,
            provider="Microsoft-Windows-Security-Auditing",
            channel="Security",
            data={"KernelDebug": "%%1842", "TestSigning": "%%1843"},
            timestamp=TS + timedelta(seconds=index),
        )
        for index in range(4)
    ]
    alerts = _rules(detect(events), "Kernel Debug or Test Signing Enabled")
    assert len(alerts) == 1
    assert alerts[0].evidence["enabled_fields"] == ["KernelDebug"]


def test_process_herpaderping_chain_is_detected():
    target = r"C:\Users\Public\samir.exe"
    events = [
        _event(11, process=r"C:\Users\Public\ProcessHerpaderping.exe", data={"Image": r"C:\Users\Public\ProcessHerpaderping.exe", "TargetFilename": target}),
        _event(1, process=target, parent=r"C:\Users\Public\ProcessHerpaderping.exe", data={"Image": target, "ParentImage": r"C:\Users\Public\ProcessHerpaderping.exe"}, timestamp=TS + timedelta(seconds=2)),
        _event(7, process=target, data={"Image": target, "ImageLoaded": target}, timestamp=TS + timedelta(seconds=3)),
    ]
    alert = _rules(detect(events), "Process Image Replacement Pattern")[0]
    assert alert.mitre_technique == "T1055.013"
    assert alert.evidence["event_ids"] == [11, 1, 7]


def test_byovd_chain_requires_driver_and_service_context():
    events = [
        _event(1, process=r"C:\Users\Public\BYOV\loader.exe", data={"Image": r"C:\Users\Public\BYOV\loader.exe"}),
        _event(13, process=r"C:\Windows\System32\services.exe", data={"TargetObject": r"HKLM\System\CurrentControlSet\Services\VulnDrv\ImagePath", "Details": r"C:\Users\Public\BYOV\vuln.sys"}, timestamp=TS + timedelta(seconds=1)),
        _event(6, data={"ImageLoaded": r"C:\Windows\System32\drivers\vuln.sys"}, timestamp=TS + timedelta(seconds=2)),
    ]
    alert = _rules(detect(events), "User-Controlled Driver Load")[0]
    assert alert.mitre_technique == "T1068"


def test_process_access_is_signal_only_until_injection_is_confirmed():
    event = _event(
        10,
        data={
            "SourceImage": r"C:\Users\Public\za3bollo.exe",
            "TargetImage": r"C:\Windows\System32\notepad.exe",
            "GrantedAccess": "0x001fffff",
            "RuleName": "Evasion Suspicious NtOpenProcess Call",
            "CallTrace": "UNKNOWN(1234)",
        },
    )
    alert = _rules(detect([event]), "Suspicious Process Access")[0]
    assert alert.promotion_policy == "signal_only"
    _, findings, _ = alerts_to_signals_findings([alert])
    assert findings == []


def test_silent_process_exit_pair_is_detected():
    events = [
        _event(13, data={"TargetObject": r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe\GlobalFlag", "Details": "DWORD (0x00000200)"}),
        _event(13, data={"TargetObject": r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe\MonitorProcess", "Details": r"C:\Windows\Temp\evil.exe"}, timestamp=TS + timedelta(seconds=2)),
    ]
    alert = _rules(detect(events), "SilentProcessExit Image Hijack")[0]
    assert alert.mitre_technique == "T1546.012"
    assert alert.evidence["monitor_process"].endswith("evil.exe")


def test_winlogon_shell_extra_payload_is_detected():
    event = _event(
        13,
        data={
            "TargetObject": r"HKU\S-1-5-21-1\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
            "Details": r'"C:\Users\Public\shell.exe",explorer.exe',
        },
    )
    alert = _rules(detect([event]), "Winlogon Shell Persistence")[0]
    assert alert.mitre_technique == "T1547.004"


def test_pending_gpo_is_visible_but_signal_only():
    event = _event(
        13,
        data={
            "TargetObject": r"HKU\S-1-5-21-1\Software\Microsoft\IEAK\GroupPolicy\PendingGPOs\Path1",
            "Details": r"C:\ProgramData\gpo.inf",
        },
    )
    alert = _rules(detect([event]), "Pending Group Policy Registry Change")[0]
    assert alert.promotion_policy == "signal_only"


def test_sam_force_password_reset_is_signal_only():
    event = _event(
        13,
        data={
            "TargetObject": r"HKLM\SAM\SAM\Domains\Account\Users\000001F4\ForcePasswordReset",
            "Details": "Binary Data",
        },
    )
    alert = _rules(detect([event]), "Local SAM Password Reset Flag Changed")[0]
    assert alert.mitre_technique == "T1098"
    assert alert.promotion_policy == "signal_only"


def test_named_pipe_burst_is_signal_only():
    events = [
        _event(18, data={"PipeName": "\\lsass"}, timestamp=TS),
        _event(18, data={"PipeName": "\\srvsvc"}, timestamp=TS + timedelta(seconds=1)),
        _event(18, data={"PipeName": "\\atsvc"}, timestamp=TS + timedelta(seconds=2)),
    ]
    alert = _rules(detect(events), "Named Pipe Service Discovery")[0]
    assert alert.mitre_technique == "T1018"
    assert alert.promotion_policy == "signal_only"


def test_partial_wmi_tree_is_visible_after_remote_logon():
    events = [
        _event(4624, provider="Microsoft-Windows-Security-Auditing", channel="Security", source_ip="10.0.0.8", logon_type="3"),
        _event(4688, process=r"C:\Windows\System32\wbem\WmiPrvSE.exe", data={"Image": r"C:\Windows\System32\wbem\WmiPrvSE.exe"}, timestamp=TS + timedelta(seconds=10)),
    ]
    alert = _rules(detect(events), "WMI Remote Activity (Partial Process Tree)")[0]
    assert alert.promotion_policy == "signal_only"
    assert alert.evidence["source_ip"] == "10.0.0.8"


def test_winrm_lifecycle_without_process_tree_is_visible():
    event = _event(91, provider="Microsoft-Windows-WinRM", channel="Microsoft-Windows-WinRM/Operational")
    alert = _rules(detect([event]), "WinRM Shell Lifecycle Activity")[0]
    assert alert.mitre_technique == "T1021.006"
    assert alert.promotion_policy == "signal_only"


def test_srvsvc_pipe_and_remote_network_are_signal_only():
    events = [
        _event(18, data={"PipeName": "\\srvsvc"}),
        _event(3, data={"SourceIp": "10.0.0.4", "DestinationIp": "10.0.0.8"}, source_ip="10.0.0.4", destination_ip="10.0.0.8", timestamp=TS + timedelta(seconds=2)),
    ]
    alert = _rules(detect(events), "Remote Share Service Discovery")[0]
    assert alert.mitre_technique == "T1135"
    assert alert.promotion_policy == "signal_only"


def test_sysmon_file_delete_is_visible_but_signal_only():
    event = _event(
        23,
        data={
            "Image": r"C:\Users\Analyst\wiper.exe",
            "TargetFilename": r"C:\Users\Analyst\staged.evtx",
            "RuleName": "technique_id=T1070.004",
        },
    )
    alert = _rules(detect([event]), "File Deletion Activity")[0]
    assert alert.mitre_technique == "T1070.004"
    assert alert.promotion_policy == "signal_only"
    assert alert.evidence["target"].endswith("staged.evtx")


def test_security_delete_access_is_visible_when_object_access_is_enabled():
    event = _event(
        4663,
        provider="Microsoft-Windows-Security-Auditing",
        channel="Security",
        data={
            "ObjectName": r"C:\Users\Analyst\cleanup.ps1",
            "ObjectType": "File",
            "AccessMask": "0x00010000",
            "SubjectUserName": "analyst",
            "SubjectDomainName": "CORP",
        },
    )
    alert = _rules(detect([event]), "File Deletion Activity")[0]
    assert alert.mitre_technique == "T1070.004"
    assert alert.evidence["event_id"] == 4663


def test_directory_audit_bursts_map_domain_group_and_account_subtechniques():
    events = [
        _event(
            4661,
            provider="Microsoft-Windows-Security-Auditing",
            channel="Security",
            data={
                "ObjectServer": "Security Account Manager",
                "ObjectType": "SAM_GROUP",
                "ObjectName": f"S-1-5-21-1-{index}",
                "SubjectUserName": "operator",
                "SubjectDomainName": "CORP",
            },
            timestamp=TS + timedelta(seconds=index),
        )
        for index in range(3)
    ] + [
        _event(
            4661,
            provider="Microsoft-Windows-Security-Auditing",
            channel="Security",
            data={
                "ObjectServer": "Security Account Manager",
                "ObjectType": "SAM_DOMAIN",
                "ObjectName": f"DC=corp,DC=local,{index}",
                "SubjectUserName": "operator",
                "SubjectDomainName": "CORP",
            },
            timestamp=TS + timedelta(seconds=10 + index),
        )
        for index in range(3)
    ]
    alerts = detect(events)
    assert any(alert.mitre_technique == "T1069.002" for alert in alerts)
    assert any(alert.mitre_technique == "T1087.002" for alert in alerts)
    filtered = FPFilter().apply(alerts)
    assert {alert.rule_name for alert in filtered} >= {
        "Domain Group Enumeration (Directory Audit)",
        "Domain Account Enumeration (Directory Audit)",
    }


def test_directory_audit_sam_alias_maps_local_group_subtechnique():
    events = [
        _event(
            4661,
            provider="Microsoft-Windows-Security-Auditing",
            channel="Security",
            data={
                "ObjectServer": "Security Account Manager",
                "ObjectType": "SAM_ALIAS",
                "ObjectName": f"S-1-5-21-1-{index}",
                "Properties": "{bf967a9c-0de6-11d0-a285-00aa003049e2}",
                "SubjectUserName": "operator",
                "SubjectDomainName": "CORP",
            },
            timestamp=TS + timedelta(seconds=index),
        )
        for index in range(3)
    ]
    alerts = detect(events)
    alert = _rules(alerts, "Local Group Enumeration (Directory Audit)")[0]
    assert alert.mitre_technique == "T1069.001"
    assert alert.promotion_policy == "signal_only"
    assert _rules(FPFilter().apply(alerts), "Local Group Enumeration (Directory Audit)")


def test_explicit_domain_discovery_commands_use_subtechniques():
    events = [
        _event(
            4688,
            provider="Microsoft-Windows-Security-Auditing",
            channel="Security",
            process=r"C:\Windows\System32\net.exe",
            command="net group /domain",
            data={"SubjectUserName": "operator", "SubjectDomainName": "CORP"},
        ),
        _event(
            4104,
            provider="Microsoft-Windows-PowerShell",
            channel="Microsoft-Windows-PowerShell/Operational",
            command="Get-ADUser -Filter *",
            data={"ScriptBlockText": "Get-ADUser -Filter *", "ContextInfo": "User = CORP\\operator"},
        ),
    ]
    alerts = credential_detect(events)
    assert any(alert.rule_name == "Group Discovery" and alert.mitre_technique == "T1069.002" for alert in alerts)
    assert any(alert.rule_name == "User Account Discovery" and alert.mitre_technique == "T1087.002" for alert in alerts)
