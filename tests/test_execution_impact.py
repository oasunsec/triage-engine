from datetime import datetime, timedelta, timezone

from detectors.execution_impact import detect
from models.event_model import NormalizedEvent
from triage_engine.adapters import alerts_to_signals_findings
from correlation.incident_builder import build_incidents


TS = datetime(2026, 8, 27, 12, 0, tzinfo=timezone.utc)


def _event(event_id, *, provider="Microsoft-Windows-Sysmon", channel="", process="", parent="", command="", data=None, computer="HOST-1", timestamp=TS):
    return NormalizedEvent(
        event_id=event_id,
        timestamp=timestamp,
        computer=computer,
        provider=provider,
        channel=channel,
        process_name_value=process,
        parent_process_value=parent,
        command_line_value=command,
        event_data=data or {},
    )


def test_sqlservr_shell_spawn_is_high_confidence_execution_signal():
    alerts = detect([_event(1, process="C:\\Windows\\System32\\cmd.exe", parent="C:\\Program Files\\Microsoft SQL Server\\sqlservr.exe", command="cmd.exe /c whoami")])
    assert len(alerts) == 1
    assert alerts[0].mitre_technique == "T1059.003"
    assert alerts[0].confidence == "high"
    assert alerts[0].evidence["server_abuse"] is True


def test_promoted_finding_preserves_attack_mapping():
    alerts = detect([_event(1, process="cmd.exe", parent="sqlservr.exe", command="cmd.exe /c whoami")])
    signals, findings, _ = alerts_to_signals_findings(alerts)
    assert findings[0].mitre_tactic == "Execution"
    assert findings[0].mitre_technique == "T1059.003"
    assert findings[0].to_dict()["technique_summary"] == "T1059.003"
    incidents = build_incidents([], signals, findings, [])
    assert any("T1059.003" in incident.technique_summary for incident in incidents)


def test_special_group_domain_logon_is_supporting_only():
    event = _event(
        4964,
        provider="Microsoft-Windows-Security-Auditing",
        channel="Security",
        data={
            "TargetUserName": "admin-user",
            "TargetDomainName": "CORP",
            "TargetLogonId": "0x1234",
            "SidList": "%{S-1-5-21-1-512}",
        },
    )
    alert = next(item for item in detect([event]) if item.mitre_technique == "T1078.002")
    assert alert.promotion_policy == "signal_only"
    signals, findings, _ = alerts_to_signals_findings([alert])
    assert len(signals) == 1
    assert findings == []


def test_special_group_machine_account_or_missing_sid_is_ignored():
    machine = _event(4964, provider="Microsoft-Windows-Security-Auditing", channel="Security", data={"TargetUserName": "HOST$", "TargetDomainName": "CORP", "SidList": "%{S-1-5-21-1-512}"})
    missing_sid = _event(4964, provider="Microsoft-Windows-Security-Auditing", channel="Security", data={"TargetUserName": "admin-user", "TargetDomainName": "CORP"})
    assert not any(item.mitre_technique == "T1078.002" for item in detect([machine, missing_sid]))


def test_sqlservr_normal_child_is_not_promoted():
    assert detect([_event(1, process="sqlmin.dll", parent="sqlservr.exe")]) == []


def test_repeated_service_creation_and_failures_maps_service_execution():
    events = [
        _event(7045, data={"ServiceName": "stage-a"}, timestamp=TS),
        _event(7009, data={"param1": "stage-a"}, timestamp=TS + timedelta(seconds=2)),
        _event(7045, data={"ServiceName": "stage-b"}, timestamp=TS + timedelta(seconds=4)),
        _event(7000, data={"param1": "stage-b"}, timestamp=TS + timedelta(seconds=6)),
    ]
    alerts = detect(events)
    burst = next(alert for alert in alerts if alert.rule_name == "Repeated Service Execution Failures")
    assert burst.mitre_technique == "T1569.002"
    assert burst.confidence == "high"
    assert burst.evidence["install_count"] == 2


def test_single_failed_service_install_is_not_service_execution_burst():
    events = [
        _event(7045, data={"ServiceName": "ordinary-service"}),
        _event(7009, data={"param1": "ordinary-service"}, timestamp=TS + timedelta(seconds=2)),
    ]
    assert not any(alert.rule_name == "Repeated Service Execution Failures" for alert in detect(events))


def test_cross_host_rdp_valid_account_activity_requires_three_hosts():
    events = [
        _event(1149, provider="Microsoft-Windows-TerminalServices-RemoteConnectionManager", computer=f"HOST-{index}", data={"Param1": "admin", "Param3": "10.0.0.8"}, timestamp=TS + timedelta(minutes=index))
        for index in range(3)
    ]
    alerts = detect(events)
    cross_host = next(alert for alert in alerts if alert.rule_name == "Cross-Host RDP Valid Account Activity")
    assert cross_host.mitre_technique == "T1078"
    assert cross_host.evidence["destination_host_count"] == 3
    assert detect(events[:2]) == []


def test_pktmon_capture_is_medium_confidence_and_deduplicated():
    event = _event(1, process="pktmon.exe", command="pktmon start --etw -c 0")
    alerts = detect([event, event])
    assert len(alerts) == 1
    assert alerts[0].mitre_technique == "T1040"
    assert alerts[0].confidence == "medium"


def test_pktmon_without_capture_action_is_benign_control():
    assert detect([_event(1, process="pktmon.exe", command="pktmon counters")]) == []


def test_share_descriptor_only_alerts_when_old_and_new_differ():
    same = {"OldSD": "D:(A;;FA;;;SY)", "NewSD": "D:(A;;FA;;;SY)"}
    assert detect([_event(5143, provider="Microsoft-Windows-Security-Auditing", data=same)]) == []
    alerts = detect([_event(5143, provider="Microsoft-Windows-Security-Auditing", data={"ShareName": "\\\\HOST-1\\Public", "OldSD": "D:(A;;FA;;;SY)", "NewSD": "D:(A;;FA;;;WD)"})])
    assert len(alerts) == 1
    assert alerts[0].mitre_technique == "T1222.001"
    assert alerts[0].evidence["broad_full_access"] is True


def test_capi_private_key_access_by_mimikatz_is_critical():
    alerts = detect([
        _event(
            70,
            provider="Microsoft-Windows-CAPI2",
            data={
                "EventAuxInfo_ProcessName": "mimikatz.exe",
                "Certificate_subjectName": "host.example",
                "Certificate_fileRef": "certificate.cer",
            },
        )
    ])
    assert len(alerts) == 1
    assert alerts[0].mitre_technique == "T1552.004"
    assert alerts[0].confidence == "high"


def test_capi_private_key_access_by_normal_process_is_not_promoted():
    assert detect([_event(70, provider="Microsoft-Windows-CAPI2", data={"EventAuxInfo_ProcessName": "lsass.exe"})]) == []


def test_wininet_proxy_requires_nonempty_configuration():
    empty = _event(5600, provider="Microsoft-Windows-WinINet-Config", data={"Proxy": ""})
    assert detect([empty]) == []
    alerts = detect([_event(5600, provider="Microsoft-Windows-WinINet-Config", data={"AutoConfigURL": "https://proxy.example/pac"})])
    assert len(alerts) == 1
    assert alerts[0].mitre_technique == "T1090"
    assert alerts[0].confidence == "medium"


def test_wininet_proxy_accepts_native_event_field_names():
    alerts = detect([_event(5600, provider="Microsoft-Windows-WinINet-Config", data={"pwszProxy": "http://proxy.example:8080"})])
    assert len(alerts) == 1
    assert alerts[0].evidence["proxy_configuration"] == "http://proxy.example:8080"


def test_bitlocker_encryption_is_supporting_evidence_not_verdict():
    alerts = detect([_event(768, provider="Microsoft-Windows-BitLocker-API", data={"VolumeMountPoint": "C:"})])
    assert len(alerts) == 1
    assert alerts[0].mitre_technique == "T1486"
    assert alerts[0].confidence == "medium"
    assert alerts[0].evidence["supporting_evidence_only"] is True
    assert alerts[0].evidence["volume"] == "C:"


def test_unrelated_bitlocker_provider_does_not_trigger():
    assert detect([_event(768, provider="Microsoft-Windows-Kernel-General", data={"Volume": "C:"})]) == []


def test_inhibit_system_recovery_matches_exact_destructive_commands():
    commands = [
        (4688, "vssadmin.exe delete shadows /all /quiet"),
        (1, "wmic shadowcopy delete"),
        (4104, "Get-WmiObject Win32_ShadowCopy | Remove-WmiObject"),
        (4103, "wbadmin delete catalog -quiet"),
        (4688, "diskshadow.exe /s cleanup.txt delete shadows all"),
        (4104, "bcdedit /set {default} recoveryenabled no"),
    ]
    for event_id, command in commands:
        alerts = detect([_event(event_id, command=command, data={"ScriptBlockText": command})])
        alert = next(item for item in alerts if item.mitre_technique == "T1490")
        assert alert.confidence == "high"
        assert alert.evidence["evidence_strength"] == "high"


def test_inhibit_system_recovery_deduplicates_same_event_and_ignores_generic_backup():
    event = _event(4688, command="vssadmin delete shadows /all")
    alerts = detect([event, event])
    assert len([item for item in alerts if item.mitre_technique == "T1490"]) == 1
    assert detect([_event(4688, command="wbadmin start backup -backuptarget:D:")]) == []
    assert detect([_event(4104, command="Get-WmiObject Win32_ShadowCopy")]) == []


def test_domain_trust_creation_is_medium_until_matching_4865_confirmation():
    trust = _event(4706, provider="Microsoft-Windows-Security-Auditing", data={
        "TrustPartner": "child.example",
        "SubjectUserName": "admin",
        "SubjectLogonId": "0x123",
    })
    isolated = next(item for item in detect([trust]) if item.mitre_technique == "T1484")
    assert isolated.confidence == "medium"
    assert isolated.evidence["confirmation_event_id"] is None

    confirmation = _event(4865, provider="Microsoft-Windows-Security-Auditing", data={
        "DomainName": "child.example",
        "SubjectUserName": "admin",
        "SubjectLogonId": "0x123",
    }, timestamp=TS + timedelta(minutes=3))
    paired = next(item for item in detect([trust, confirmation]) if item.mitre_technique == "T1484")
    assert paired.confidence == "high"
    assert paired.evidence["confirmation_event_id"] == 4865
    assert "0x123" in paired.evidence["paired_event_identity"]


def test_domain_trust_confirmation_requires_same_host_identity_and_window():
    trust = _event(4706, data={"TrustPartner": "child.example", "SubjectUserName": "admin", "SubjectLogonId": "0x123"})
    other_host = _event(4865, data={"DomainName": "child.example", "SubjectUserName": "admin", "SubjectLogonId": "0x123"}, computer="HOST-2")
    late = _event(4865, data={"DomainName": "child.example", "SubjectUserName": "admin", "SubjectLogonId": "0x123"}, timestamp=TS + timedelta(minutes=11))
    assert next(item for item in detect([trust, other_host]) if item.mitre_technique == "T1484").confidence == "medium"
    assert next(item for item in detect([trust, late]) if item.mitre_technique == "T1484").confidence == "medium"


def test_unrelated_directory_event_is_not_domain_trust_creation():
    assert detect([_event(5136, provider="Microsoft-Windows-Security-Auditing", data={"AttributeLDAPDisplayName": "description"})]) == []


def test_cmd_exe_scheduled_task_spawn_co_tags_t1059_003():
    event = _event(
        4688,
        process="C:\\Windows\\SysWOW64\\cmd.exe",
        parent="C:\\Windows\\SysWOW64\\rundll32.exe",
        command='"C:\\Windows\\System32\\cmd.exe" /C schtasks /Create /f /XML C:\\Users\\IEUser\\AppData\\Local\\Temp\\sduchxll.tmp /TN DataUsageHandlers',
    )
    alerts = detect([event])
    cotag = next(item for item in alerts if item.mitre_technique == "T1059.003")
    assert cotag.rule_name == "Interpreter Executed Administrative or Proxy Command"
    assert cotag.severity == "high"
    assert cotag.evidence["matched_context"] == "scheduled-task"


def test_cmd_exe_co_tag_keeps_persistence_technique_available():
    from detectors.execution_impact import detect
    event = _event(4688, process="cmd.exe", parent="rundll32.exe", command="cmd.exe /c schtasks /create /tn X /tr cmd.exe")
    alerts = [item for item in detect([event]) if item.mitre_technique in ("T1059.003", "T1053.005")]
    assert any(item.mitre_technique == "T1059.003" for item in alerts)


def test_plain_cmd_interactive_console_is_not_co_tagged():
    event = _event(1, process="C:\\Windows\\System32\\cmd.exe", parent="C:\\Windows\\explorer.exe", command="cmd.exe")
    assert not any(item.mitre_technique == "T1059.003" for item in detect([event]))


def test_powershell_encoded_command_co_tags_t1059_001():
    event = _event(1, process="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", parent="C:\\Windows\\System32\\wmic.exe", command="powershell.exe -enc SQBFAFgA")
    alerts = detect([event])
    assert any(item.mitre_technique == "T1059.001" for item in alerts)


def test_interpreter_co_tag_deduplicates_identical_context():
    event = _event(1, process="cmd.exe", parent="rundll32.exe", command="cmd.exe /c schtasks /create /tn X /tr cmd.exe")
    alerts = detect([event, event])
    cotags = [item for item in alerts if item.mitre_technique == "T1059.003"]
    assert len(cotags) == 1




def _bitlocker_lifecycle_alert(alerts):
    matches = [a for a in alerts if a.rule_name == "BitLocker Volume Encryption Lifecycle"]
    return matches[0] if matches else None


def test_bitlocker_lifecycle_cluster_is_supporting_evidence():
    events = [
        _event(768, provider="Microsoft-Windows-BitLocker-API", data={"VolumeMountPoint": "C:"}),
        _event(775, provider="Microsoft-Windows-BitLocker-API", data={"VolumeMountPoint": "C:"}),
        _event(780, provider="Microsoft-Windows-BitLocker-API", data={"VolumeMountPoint": "C:"}),
        _event(840, provider="Microsoft-Windows-BitLocker-API", data={"VolumeMountPoint": "C:"}),
    ]
    alerts = detect(events)
    lifecycle = _bitlocker_lifecycle_alert(alerts)
    assert lifecycle is not None
    assert lifecycle.mitre_technique == "T1486"
    assert lifecycle.evidence["phase_count"] == 4
    assert lifecycle.evidence["lifecycle_phases"] == [768, 775, 780, 840]
    assert lifecycle.evidence["supporting_evidence_only"] is True
    assert lifecycle.evidence["evidence_strength"] == "medium"
    # the individual 768 start event still surfaces as its own supporting signal
    assert any(a.rule_name == "BitLocker Volume Encryption Started" for a in alerts)


def test_bitlocker_single_start_has_no_lifecycle_cluster():
    alerts = detect([_event(768, provider="Microsoft-Windows-BitLocker-API", data={"VolumeMountPoint": "C:"})])
    assert _bitlocker_lifecycle_alert(alerts) is None
    assert any(a.rule_name == "BitLocker Volume Encryption Started" for a in alerts)


def test_bitlocker_lifecycle_is_per_volume():
    events = [
        _event(768, provider="Microsoft-Windows-BitLocker-API", data={"VolumeMountPoint": "C:"}),
        _event(775, provider="Microsoft-Windows-BitLocker-API", data={"VolumeMountPoint": "C:"}),
        _event(780, provider="Microsoft-Windows-BitLocker-API", data={"VolumeMountPoint": "C:"}),
        _event(840, provider="Microsoft-Windows-BitLocker-API", data={"VolumeMountPoint": "D:"}),
        _event(817, provider="Microsoft-Windows-BitLocker-API", data={"VolumeMountPoint": "D:"}),
    ]
    alerts = detect(events)
    lifecycle = _bitlocker_lifecycle_alert(alerts)
    assert lifecycle is not None
    # only C: reaches three distinct phases; the cluster is scoped to (host, volume)
    assert lifecycle.evidence["volume"] == "C:"
    assert lifecycle.evidence["phase_count"] == 3
    assert lifecycle.evidence["lifecycle_phases"] == [768, 775, 780]
    assert lifecycle.evidence["supporting_evidence_only"] is True

