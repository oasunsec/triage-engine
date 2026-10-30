from datetime import datetime, timezone

from detectors import credential_access
from models.event_model import NormalizedEvent


def _ticket(encryption: str, service: str = "Svc-SQL-DB01") -> NormalizedEvent:
    return NormalizedEvent(
        event_id=4769,
        timestamp=datetime(2026, 8, 27, tzinfo=timezone.utc),
        computer="DC01",
        provider="Microsoft-Windows-Security-Auditing",
        channel="Security",
        target_user="analyst",
        event_data={
            "TicketEncryptionType": encryption,
            "ServiceName": service,
            "TargetUserName": "analyst",
        },
    )


def test_kerberoasting_accepts_zero_padded_windows_hex_encoding():
    alerts = credential_access.detect([_ticket("0x00000017")])
    match = next(alert for alert in alerts if alert.rule_name == "Kerberoasting")
    assert match.mitre_technique == "T1558.003"
    assert match.evidence["encryption"] == "0x17"


def test_kerberoasting_ignores_aes_and_krbtgt_requests():
    alerts = credential_access.detect([
        _ticket("0x00000012"),
        _ticket("0x00000017", service="krbtgt"),
    ])
    assert not any(alert.rule_name == "Kerberoasting" for alert in alerts)
