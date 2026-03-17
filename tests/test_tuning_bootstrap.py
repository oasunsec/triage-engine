import json
import shutil
import tempfile
import unittest
from pathlib import Path

from triage_engine.cli import main
from triage_engine.tuning import load_tuning


class TuningBootstrapTests(unittest.TestCase):
    def test_local_tuning_merges_additively(self):
        temp_root = Path(tempfile.mkdtemp(prefix="triage-tuning-root-"))
        self.addCleanup(shutil.rmtree, temp_root, True)

        tuning_dir = temp_root / "config" / "tuning"
        tuning_dir.mkdir(parents=True, exist_ok=True)
        (tuning_dir / "default.json").write_text(
            json.dumps(
                {
                    "promotion_overrides": {
                        "standalone": ["BuiltIn Rule"],
                    },
                    "allowlists": {
                        "processes": [r"C:\Program Files\BuiltIn\agent.exe"],
                    },
                }
            ),
            encoding="utf-8",
        )
        (tuning_dir / "local.json").write_text(
            json.dumps(
                {
                    "metadata": {
                        "profile_name": "local",
                    },
                    "allowlists": {
                        "processes": [r"C:\Program Files\CorpAdmin\agent.exe"],
                    },
                    "promotion_overrides": {
                        "correlate": ["Local Review Rule"],
                    },
                }
            ),
            encoding="utf-8",
        )

        config, diagnostics, loaded_paths = load_tuning(str(temp_root))

        self.assertEqual(diagnostics, [])
        self.assertEqual(len(loaded_paths), 2)
        self.assertIn("BuiltIn Rule", config["promotion_overrides"]["standalone"])
        self.assertIn("Local Review Rule", config["promotion_overrides"]["correlate"])
        self.assertIn(r"C:\Program Files\BuiltIn\agent.exe", config["allowlists"]["processes"])
        self.assertIn(r"C:\Program Files\CorpAdmin\agent.exe", config["allowlists"]["processes"])

    def test_tuning_init_writes_reviewable_profile(self):
        temp_root = Path(tempfile.mkdtemp(prefix="triage-tuning-init-"))
        self.addCleanup(shutil.rmtree, temp_root, True)

        case_dir = temp_root / "cases" / "case-alpha"
        case_dir.mkdir(parents=True, exist_ok=True)
        findings_path = case_dir / "findings.json"
        findings_path.write_text(
            json.dumps(
                {
                    "case": {
                        "case_name": "case-alpha",
                        "primary_host": "HOST-01",
                        "primary_user": r"corp\alice",
                        "primary_source_ip": "10.10.10.10",
                        "hosts": ["HOST-01"],
                        "users": [r"corp\alice"],
                        "ips": ["10.10.10.10"],
                        "telemetry_summary": {
                            "present": ["Security"],
                            "missing": ["Sysmon"],
                        },
                    },
                    "summary": {
                        "response_priority": "P2",
                        "suppression_summary": {
                            "suppressed_total": 2,
                            "by_reason": {"allowlist_processes": 1, "benign_task": 1},
                            "by_rule": {"Environment Inventory Tool": 1},
                        },
                        "sigma_summary": {
                            "enabled": True,
                        },
                    },
                    "legacy": {
                        "alerts": [
                            {"rule_name": "Encoded PowerShell"},
                            {"rule_name": "Encoded PowerShell"},
                            {"rule_name": "Suspicious Service Install"},
                        ]
                    },
                }
            ),
            encoding="utf-8",
        )

        output_path = temp_root / "generated-local.json"
        rc = main(
            [
                "tuning-init",
                "--case",
                str(case_dir),
                "--cases-dir",
                str(temp_root / "cases"),
                "--output",
                str(output_path),
            ]
        )
        self.assertEqual(rc, 0)
        self.assertTrue(output_path.is_file())

        profile = json.loads(output_path.read_text(encoding="utf-8"))
        self.assertEqual(profile["metadata"]["generated_from_case"], "case-alpha")
        self.assertEqual(profile["metadata"]["response_priority"], "P2")
        self.assertEqual(profile["metadata"]["telemetry_missing"], ["Sysmon"])
        self.assertEqual(profile["allowlists"]["hosts"], [])
        self.assertEqual(profile["rule_suppressions"], [])
        self.assertEqual(profile["observed_context"]["hosts"], ["HOST-01"])
        self.assertEqual(profile["observed_context"]["users"], [r"corp\alice"])
        self.assertEqual(profile["observed_context"]["ips"], ["10.10.10.10"])
        self.assertEqual(profile["observed_context"]["rules_seen"][0]["rule"], "Encoded PowerShell")
        self.assertTrue(profile["operator_checklist"])


if __name__ == "__main__":
    unittest.main()
