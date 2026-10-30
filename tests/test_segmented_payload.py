from datetime import datetime, timezone

from detectors.defense_evasion import detect
from models.event_model import NormalizedEvent

TS = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)


def _cmd_event(command):
    return NormalizedEvent(
        event_id=4688,
        timestamp=TS,
        computer="HOST-1",
        provider="Microsoft-Windows-Security-Auditing",
        channel="Security",
        process_name_value=r"C:\Windows\System32\cmd.exe",
        command_line_value=command,
        event_data={},
    )


def _seg_events(count=5):
    return [
        _cmd_event('cmd /c powershell -command "Get-Service "seg%d" | select -Expand DisplayName |out-file -append tmp_payload.txt"' % i)
        for i in range(1, count + 1)
    ]


def test_segmented_payload_reassembly_fires_on_three_plus_segments():
    alerts = [a for a in detect(_seg_events(5)) if a.rule_name == "Segmented Payload Reassembly"]
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.mitre_technique == "T1027"
    assert alert.mitre_tactic == "Defense Evasion"
    assert alert.severity == "high"
    assert alert.confidence == "high"
    assert alert.evidence["segment_count"] == 5
    assert alert.evidence["output_file"] == "tmp_payload.txt"


def test_single_or_two_segments_do_not_fire():
    assert not any(a.rule_name == "Segmented Payload Reassembly" for a in detect(_seg_events(1)))
    assert not any(a.rule_name == "Segmented Payload Reassembly" for a in detect(_seg_events(2)))


def test_plain_get_service_query_does_not_fire():
    ev = _cmd_event('powershell -command "Get-Service"')
    assert not any(a.rule_name == "Segmented Payload Reassembly" for a in detect([ev]))


def test_get_service_without_outfile_append_does_not_fire():
    ev = _cmd_event('powershell -command "Get-Service seg1 | select -Expand DisplayName"')
    assert not any(a.rule_name == "Segmented Payload Reassembly" for a in detect([ev]))
