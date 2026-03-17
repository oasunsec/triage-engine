import json
import shutil
import tempfile
import unittest
from pathlib import Path

from triage_engine.cli import main


ROOT = Path(__file__).resolve().parents[1]
STARTER_SIGMA_DIR = ROOT / "rules" / "sigma"
REGSVR32_SAMPLE = ROOT / "sample_cache" / "hayabusa_regsvr32_sct.evtx"


class SigmaCliE2ETests(unittest.TestCase):
    def test_cli_investigate_emits_sigma_artifacts(self):
        if not REGSVR32_SAMPLE.is_file():
            self.skipTest(f"Missing Sigma smoke sample: {REGSVR32_SAMPLE}")

        temp_root = Path(tempfile.mkdtemp(prefix="triage-sigma-cli-"))
        self.addCleanup(shutil.rmtree, temp_root, True)

        rc = main(
            [
                "investigate",
                "--evtx",
                str(REGSVR32_SAMPLE),
                "--case",
                "sigma-smoke",
                "--cases-dir",
                str(temp_root),
                "--enable-sigma",
                "--sigma-rules",
                str(STARTER_SIGMA_DIR),
            ]
        )
        self.assertEqual(rc, 0)

        findings_path = temp_root / "sigma-smoke" / "findings.json"
        self.assertTrue(findings_path.is_file())

        data = json.loads(findings_path.read_text(encoding="utf-8"))
        sigma_summary = data["summary"]["sigma_summary"]
        self.assertTrue(sigma_summary["enabled"])
        self.assertGreaterEqual(sigma_summary["rules_loaded"], 4)
        self.assertGreaterEqual(sigma_summary["alerts_emitted"], 1)

        sigma_signals = [signal for signal in data["signals"] if signal.get("rule_source") == "sigma"]
        self.assertGreaterEqual(len(sigma_signals), 1)
        self.assertTrue(all(signal.get("promotion_policy") == "signal_only" for signal in sigma_signals))


if __name__ == "__main__":
    unittest.main()
