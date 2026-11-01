import os
import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COLLECTOR = ROOT / "scripts" / "collect-windows-artifacts.ps1"
EVIDENCE_COLLECTOR = ROOT / "scripts" / "collect-windows-evidence.ps1"


class WindowsArtifactCollectorAssetTests(unittest.TestCase):
    def test_collector_asset_is_available_in_scripts_directory(self):
        self.assertTrue(COLLECTOR.is_file())
        self.assertEqual(COLLECTOR.parent, ROOT / "scripts")

    def test_collector_has_valid_powershell_syntax_without_running_it(self):
        self._assert_parses(COLLECTOR)

    def test_evidence_collector_parses_requires_admin_and_only_reads_the_system(self):
        self._assert_parses(EVIDENCE_COLLECTOR)
        script = EVIDENCE_COLLECTOR.read_text(encoding="utf-8")
        self.assertIn("WindowsBuiltInRole]::Administrator", script)
        self.assertIn("OutputDirectory already exists", script)
        for writes_to_system in ("Remove-Item", "Set-ItemProperty", "New-ItemProperty", "reg add", "reg delete",
                                 "wevtutil cl", "wevtutil.exe cl", "Stop-Service", "fsutil usn deletejournal"):
            self.assertNotIn(writes_to_system, script)
        for collected in ("Microsoft-Windows-Windows Defender/Operational", ".LOG1", "corrobora.raw_ntfs",
                          "pack-artifacts", "collection_manifest.json"):
            self.assertIn(collected, script)

    def _assert_parses(self, collector):
        shell = shutil.which("pwsh") or shutil.which("powershell")
        if not shell:
            self.skipTest("PowerShell parser is unavailable on this host")

        parser_check = (
            "$tokens = $null; $errors = $null; "
            "[System.Management.Automation.Language.Parser]::ParseFile(" 
            "$env:CORROBORA_COLLECTOR_SCRIPT, [ref]$tokens, [ref]$errors) | Out-Null; "
            "if ($errors.Count -gt 0) { $errors | ForEach-Object { Write-Error $_.Message }; exit 1 }"
        )
        environment = os.environ.copy()
        environment["CORROBORA_COLLECTOR_SCRIPT"] = str(collector)
        result = subprocess.run(
            [shell, "-NoProfile", "-NonInteractive", "-Command", parser_check],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)


if __name__ == "__main__":
    unittest.main()
