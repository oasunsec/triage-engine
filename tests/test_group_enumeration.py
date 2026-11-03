"""Local group enumeration (4799) versus shadow-copy privilege checks."""

from datetime import datetime, timezone

from detectors.credential_access import detect
from models.event_model import NormalizedEvent

AT = datetime(2026, 11, 1, 14, 10, tzinfo=timezone.utc)


def lookup(caller: str, group: str, sid: str) -> NormalizedEvent:
    return NormalizedEvent(
        4799, AT, computer="WS-LAB-01", channel="Security", provider="Microsoft-Windows-Security-Auditing",
        target_user=group, target_domain="Builtin", subject_user="analyst", subject_domain="WS-LAB-01",
        event_data={"TargetUserName": group, "TargetDomainName": "Builtin", "TargetSid": sid,
                    "SubjectUserName": "analyst", "CallerProcessName": caller})


def group_alerts(events):
    return [alert for alert in detect(events) if alert.rule_name == "Local Group Enumeration"]


def test_shadow_copy_privilege_checks_are_not_group_discovery():
    events = [lookup(caller, group, sid)
              for caller in ("C:\\Windows\\System32\\esentutl.exe", "C:\\Windows\\System32\\VSSVC.exe")
              for group, sid in (("Administrators", "S-1-5-32-544"), ("Backup Operators", "S-1-5-32-551"))]
    assert group_alerts(events) == []


def test_other_callers_and_groups_still_alert():
    events = [lookup("C:\\Windows\\System32\\net1.exe", "Administrators", "S-1-5-32-544"),
              lookup("C:\\Windows\\System32\\esentutl.exe", "Remote Desktop Users", "S-1-5-32-555"),
              lookup("C:\\Users\\Public\\esentutl.exe", "Administrators", "S-1-5-32-544")]
    alerts = group_alerts(events)
    assert len(alerts) == 1
    assert alerts[0].evidence["event_count"] == 3
