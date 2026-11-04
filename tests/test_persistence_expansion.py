from datetime import datetime, timezone

from detectors import persistence
from models.event_model import NormalizedEvent


def _registry_event(target: str, value: str) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=13,
        timestamp=datetime(2026, 8, 27, tzinfo=timezone.utc),
        computer="HOST-1",
        provider="Microsoft-Windows-Sysmon",
        channel="Microsoft-Windows-Sysmon/Operational",
        process_name_value=r"C:\Windows\System32\reg.exe",
        event_data={"TargetObject": target, "Details": value, "Image": r"C:\Windows\System32\reg.exe"},
    )


def test_nonstandard_startup_folder_redirect_is_persistence_evidence():
    event = _registry_event(
        r"HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\Startup",
        r"C:\ProgramData\StartupNewHomeAddress",
    )
    alert = next(item for item in persistence.detect([event]) if item.rule_name == "Startup Folder Path Redirected")
    assert alert.mitre_technique == "T1547.001"
    assert alert.confidence == "medium"
    assert alert.evidence["redirected_startup_path"] == r"C:\ProgramData\StartupNewHomeAddress"


def test_default_startup_folder_path_is_not_flagged():
    event = _registry_event(
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\Startup",
        r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup",
    )
    assert not any(item.rule_name == "Startup Folder Path Redirected" for item in persistence.detect([event]))
