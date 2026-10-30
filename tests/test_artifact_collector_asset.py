import os
import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COLLECTOR = ROOT / "scripts" / "collect-windows-artifacts.ps1"


class WindowsArtifactCollectorAssetTests(unittest.TestCase):
    def test_collector_asset_is_available_in_scripts_directory(self):
        self.assertTrue(COLLECTOR.is_file())
        self.assertEqual(COLLECTOR.parent, ROOT / "scripts")

    def test_collector_has_valid_powershell_syntax_without_running_it(self):
        shell = shutil.which("pwsh") or shutil.which("powershell")
        if not shell:
            self.skipTest("PowerShell parser is unavailable on this host")

        parser_check = (
            "$tokens = $null; $errors = $null; "
            "[System.Management.Automation.Language.Parser]::ParseFile(" 
            "$env:TRIAGE_COLLECTOR_SCRIPT, [ref]$tokens, [ref]$errors) | Out-Null; "
            "if ($errors.Count -gt 0) { $errors | ForEach-Object { Write-Error $_.Message }; exit 1 }"
        )
        environment = os.environ.copy()
        environment["TRIAGE_COLLECTOR_SCRIPT"] = str(COLLECTOR)
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
