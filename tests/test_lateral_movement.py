from datetime import datetime, timezone

from detectors.lateral_movement import detect
from models.event_model import NormalizedEvent

TS = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)


def _event(event_id, *, provider="Microsoft-Windows-Sysmon", channel="", process="", parent="", command="", data=None):
    return NormalizedEvent(
        event_id=event_id,
        timestamp=TS,
        computer="FS01",
        provider=provider,
        channel=channel,
        process_name_value=process,
        parent_process_value=parent,
        command_line_value=command,
        event_data=data or {},
    )


def _hijack_rules(alerts):
    return [a for a in alerts if a.rule_name == "RDP Session Hijack (tscon)"]


def test_tscon_session_hijack_fires_critical_t1021_001():
    ev = _event(
        4688,
        process="C:\\Windows\\System32\\cmd.exe",
        parent="C:\\Windows\\System32\\cmd.exe",
        command="cmd /k tscon 2 /dest:rdp-tcp#8",
    )
    alerts = _hijack_rules(detect([ev]))
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.mitre_technique == "T1021.001"
    assert alert.mitre_tactic == "Lateral Movement"
    assert alert.severity == "critical"
    assert alert.confidence == "high"
    assert alert.evidence["target_session"] == "2"
    assert alert.evidence["evidence_strength"] == "high"


def test_tscon_without_dest_does_not_fire():
    ev = _event(
        4688,
        process="C:\\Windows\\System32\\tscon.exe",
        command="tscon 2",
    )
    assert _hijack_rules(detect([ev])) == []


def test_tscon_query_is_not_hijack():
    ev = _event(
        4688,
        process="C:\\Windows\\System32\\query.exe",
        command="query session",
    )
    assert _hijack_rules(detect([ev])) == []


def test_tscon_hijack_other_user_dest_style():
    ev = _event(
        4688,
        process="C:\\Windows\\System32\\tscon.exe",
        command="tscon.exe 3 /DEST:rdp-tcp#4",
    )
    alerts = _hijack_rules(detect([ev]))
    assert len(alerts) == 1
    assert alerts[0].evidence["target_session"] == "3"


def test_tscon_hijack_duplicate_events_deduplicated():
    ev1 = _event(
        4688,
        process="C:\\Windows\\System32\\cmd.exe",
        command="cmd /k tscon 2 /dest:rdp-tcp#8",
    )
    ev2 = _event(
        4688,
        process="C:\\Windows\\System32\\cmd.exe",
        command="cmd /k tscon 2 /dest:rdp-tcp#8",
    )
    assert len(_hijack_rules(detect([ev1, ev2]))) == 1


def _shadow_rules(alerts):
    return [a for a in alerts if a.rule_name == "RDP Shadowing Enabled"]


def test_rdp_shadow_command_line_confirmed_is_critical():
    ev = _event(
        4688,
        channel="Microsoft-Windows-Sysmon/Operational",
        process="C:\\Windows\\System32\\cmd.exe",
        command=(
            'netsh advfirewall firewall set rule group="remote desktop - shadow (tcp-in)" new enable=Yes; '
            r"Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name Shadow -Value 2"
        ),
    )
    alerts = _shadow_rules(detect([ev]))
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.severity == "critical"
    assert alert.confidence == "high"
    assert alert.evidence["evidence_strength"] == "high"
    assert alert.evidence["supporting_evidence_only"] is False


def test_rdp_shadow_registry_value_confirms_shadowing():
    ev = _event(
        13,
        channel="Microsoft-Windows-Sysmon/Operational",
        data={
            "EventType": "SetValue",
            "TargetObject": r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Shadow",
            "Details": "0x2",
        },
    )
    alerts = _shadow_rules(detect([ev]))
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.severity == "critical"
    assert alert.confidence == "high"
    assert alert.evidence["shadow_value"] == "2"
    assert alert.evidence["supporting_evidence_only"] is False


def test_rdp_shadow_registry_key_without_value_is_pivot_not_confirmed():
    ev = _event(
        12,
        channel="Microsoft-Windows-Sysmon/Operational",
        data={
            "EventType": "CreateKey",
            "TargetObject": r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",
            "RuleName": "technique_id=T1076,technique_name=Remote Desktop Protocol",
        },
    )
    alerts = _shadow_rules(detect([ev]))
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.severity == "high"
    assert alert.confidence == "medium"
    assert alert.evidence["shadow_key_seen"] is False
    assert alert.evidence["shadow_value"] == ""
    assert alert.evidence["supporting_evidence_only"] is True


def test_rdp_shadow_generic_untagged_ts_write_is_low_context():
    ev = _event(
        13,
        channel="Microsoft-Windows-Sysmon/Operational",
        data={
            "EventType": "SetValue",
            "TargetObject": r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDenyTSConnections",
            "Details": "0x1",
        },
    )
    alerts = _shadow_rules(detect([ev]))
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.severity == "low"
    assert alert.evidence["shadow_key_seen"] is False
    assert alert.evidence["supporting_evidence_only"] is True
