import shutil
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from triage_engine.adapters import alerts_to_signals_findings
from triage_engine.sigma_loader import load_rules
from triage_engine.sigma_runner import evaluate_rules

from tests.test_regressions import make_event


ROOT = Path(__file__).resolve().parents[1]
STARTER_SIGMA_DIR = ROOT / "rules" / "sigma"


class SigmaSupportTests(unittest.TestCase):
    def test_starter_sigma_pack_loads_cleanly(self):
        rules, diagnostics = load_rules([str(STARTER_SIGMA_DIR)])
        self.assertGreaterEqual(len(rules), 4)
        self.assertEqual(diagnostics, [])

    def test_sigma_rule_matches_as_signal_only(self):
        sigma_rule = """
title: Suspicious Encoded PowerShell
id: sigma-unit-001
level: high
tags:
  - attack.execution
  - attack.t1059.001
detection:
  selection:
    Image|endswith: powershell.exe
    CommandLine|contains: -enc
  condition: selection
"""
        temp_dir = tempfile.mkdtemp(prefix="triage-sigma-")
        self.addCleanup(shutil.rmtree, temp_dir, True)
        rule_path = Path(temp_dir) / "sigma-rule.yml"
        rule_path.write_text(sigma_rule.strip(), encoding="utf-8")

        rules, load_diagnostics = load_rules([str(rule_path)])
        self.assertEqual(load_diagnostics, [])
        self.assertEqual(len(rules), 1)

        event = make_event(
            1,
            timestamp=datetime(2026, 3, 11, 16, 0, tzinfo=timezone.utc),
            computer="host1",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line_value="powershell.exe -enc ZQBjAGgAbwA=",
            event_data={
                "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "CommandLine": "powershell.exe -enc ZQBjAGgAbwA=",
            },
        )

        alerts, runtime_diagnostics = evaluate_rules([event], rules)
        self.assertEqual(runtime_diagnostics, [])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].promotion_policy, "signal_only")
        self.assertEqual(alerts[0].rule_source, "sigma")

        signals, findings, _ = alerts_to_signals_findings(alerts)
        self.assertEqual(len(signals), 1)
        self.assertEqual(len(findings), 0)
        self.assertEqual(signals[0].promotion_policy, "signal_only")
        self.assertEqual(signals[0].rule_source, "sigma")


if __name__ == "__main__":
    unittest.main()
