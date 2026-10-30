from datetime import datetime, timezone

from detectors import persistence
from models.event_model import NormalizedEvent


DNS_TS = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)


def _dns_cmd_event(command):
    return NormalizedEvent(
        event_id=4688,
        timestamp=DNS_TS,
        computer="DNS01",
        provider="Microsoft-Windows-Security-Auditing",
        channel="Security",
        process_name_value=r"C:\\Windows\\System32\\dnscmd.exe",
        command_line_value=command,
        event_data={},
    )


def test_dns_serverlevelplugindll_hijack_to_user_path_fires():
    cmd = r'dnscmd.exe  /config /serverlevelplugindll "C:\\TOOLS\\Mimikatz-fev-2020\\mimilib.dll"'
    alert = next(
        item
        for item in persistence.detect([_dns_cmd_event(cmd)])
        if item.rule_name == "DNS ServerLevelPluginDll Hijack"
    )
    assert alert.mitre_technique == "T1574.011"
    assert alert.mitre_tactic == "Persistence"
    assert alert.severity == "critical"
    assert alert.confidence == "high"
    assert alert.evidence["dll_path"].endswith("mimilib.dll")
    assert alert.evidence["evidence_strength"] == "high"


def test_dns_serverlevelplugindll_system_path_is_benign():
    cmd = r'dnscmd.exe /config /serverlevelplugindll "C:\\Windows\\System32\\dns\\builtin.dll"'
    ev = _dns_cmd_event(cmd)
    assert not any(item.rule_name == "DNS ServerLevelPluginDll Hijack" for item in persistence.detect([ev]))


def test_dns_serverlevelplugindll_programdata_path_fires():
    cmd = r'dnscmd.exe /config /serverlevelplugindll "C:\\ProgramData\\evil.dll"'
    ev = _dns_cmd_event(cmd)
    assert any(item.rule_name == "DNS ServerLevelPluginDll Hijack" for item in persistence.detect([ev]))
