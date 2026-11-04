"""Tests for the dependency-free external rule gap audit."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "external_rule_gap_audit.py"
SPEC = importlib.util.spec_from_file_location("external_rule_gap_audit", MODULE_PATH)
assert SPEC and SPEC.loader
rule_audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rule_audit)


class ExternalRuleGapAuditTests(unittest.TestCase):
    def _fixture(self) -> tuple[tempfile.TemporaryDirectory[str], Path, Path, Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        rules = root / "repo_cache" / "sigma"
        rules.mkdir(parents=True)
        (rules / "shell.yml").write_text(
            """
title: PowerShell command execution
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID:
      - 4688
      - 1
tags:
  - attack.execution
  - attack.t1059.001
  - attack.T1059.001
""".strip(),
            encoding="utf-8",
        )
        (rules / "lateral.toml").write_text(
            """
name = "Remote service logon"
os_list = ["windows"]
event.code = [4624, 5140]
tags = ["attack.t1021.001"]
""".strip(),
            encoding="utf-8",
        )
        coverage = root / "coverage.json"
        coverage.write_text(
            json.dumps(
                {
                    "techniques": [
                        {
                            "technique": "T1059.001",
                            "states": {
                                "mapped": True,
                                "validated_public_EVTX": True,
                            },
                        },
                        {
                            "technique": "T1021.001",
                            "states": {
                                "mapped": True,
                                "validated_public_EVTX": False,
                            },
                        },
                        {
                            "technique": "T1003",
                            "states": {
                                "mapped": False,
                                "validated_public_EVTX": False,
                            },
                        },
                        {
                            "technique": "T1003.001",
                            "states": {
                                "mapped": True,
                                "validated_public_EVTX": False,
                            },
                        },
                    ]
                }
            ),
            encoding="utf-8",
        )
        return temporary, root, rules, coverage

    def test_normalization_and_metadata_deduplication(self) -> None:
        temporary, root, rules, coverage = self._fixture()
        self.addCleanup(temporary.cleanup)
        self.assertEqual(rule_audit.normalize_technique("t1059.001"), "T1059.001")
        self.assertEqual(rule_audit.technique_ids("T1059.001 and t1059.001"), ["T1059.001"])
        report = rule_audit.build_report(
            root=root,
            sources=[("Sigma", rules)],
            engine_coverage_path=coverage,
        )
        shell = next(item for item in report["references"] if item["source_file"].endswith("shell.yml"))
        self.assertEqual(shell["techniques"], ["T1059.001"])
        self.assertEqual(shell["event_ids"], [1, 4688])
        self.assertEqual(shell["title"], "PowerShell command execution")
        self.assertIn("product=windows", shell["logsource_hints"])

    def test_comparison_classifies_unvalidated_and_unmapped_references(self) -> None:
        temporary, root, rules, coverage = self._fixture()
        self.addCleanup(temporary.cleanup)
        (rules / "unmapped.rule").write_text(
            """
title: Credential theft reference
channel: Microsoft-Windows-Sysmon/Operational
EventCode: 10
tags: attack.t1003
""".strip(),
            encoding="utf-8",
        )
        report = rule_audit.build_report(
            root=root,
            sources=[("rules", rules)],
            engine_coverage_path=coverage,
        )
        comparisons = {item["technique"]: item for item in report["technique_comparison"]}
        self.assertEqual(
            comparisons["T1059.001"]["classification"],
            "mapped_with_public_EVTX_validation",
        )
        self.assertEqual(comparisons["T1059.001"]["priority"], "low")
        self.assertEqual(
            comparisons["T1021.001"]["classification"],
            "mapped_without_public_EVTX_validation",
        )
        self.assertEqual(comparisons["T1021.001"]["priority"], "medium")
        self.assertEqual(comparisons["T1003"]["classification"], "mapped_without_public_EVTX_validation")
        self.assertEqual(comparisons["T1003"]["priority"], "medium")
        self.assertEqual(report["summary"]["high_priority_gaps"], 0)

        second_rules = root / "repo_cache" / "elastic"
        second_rules.mkdir()
        (second_rules / "credential.yml").write_text(
            "title: Credential access\nproduct: windows\nEventID: 10\ntags: attack.t1003",
            encoding="utf-8",
        )
        corroborated = rule_audit.build_report(
            root=root,
            sources=[("Sigma", rules), ("Elastic", second_rules)],
            engine_coverage_path=coverage,
        )
        comparison = next(item for item in corroborated["technique_comparison"] if item["technique"] == "T1003")
        self.assertEqual(comparison["priority"], "medium")
        self.assertEqual(comparison["external_repository_count"], 2)
        self.assertEqual(comparison["external_source_family_count"], 2)
        self.assertTrue(comparison["engine_states"]["mapped_via_subtechnique"])

    def test_missing_optional_source_is_reported_but_not_strict_failure(self) -> None:
        temporary, root, _rules, coverage = self._fixture()
        self.addCleanup(temporary.cleanup)
        result = rule_audit.main(
            [
                "--root",
                str(root),
                "--engine-coverage",
                str(coverage),
                "--source",
                "missing=repo_cache/missing",
                "--json-out",
                "out/audit.json",
                "--markdown-out",
                "out/audit.md",
                "--strict",
            ]
        )
        self.assertEqual(result, 0)
        output = json.loads((root / "out" / "audit.json").read_text(encoding="utf-8"))
        self.assertEqual(output["summary"]["missing_optional_sources"], 1)

    def test_missing_required_source_fails_strict_mode(self) -> None:
        temporary, root, _rules, coverage = self._fixture()
        self.addCleanup(temporary.cleanup)
        result = rule_audit.main(
            [
                "--root",
                str(root),
                "--engine-coverage",
                str(coverage),
                "--required-source",
                "hayabusa=repo_cache/hayabusa",
                "--json-out",
                "out/audit.json",
                "--markdown-out",
                "out/audit.md",
                "--strict",
            ]
        )
        self.assertEqual(result, 2)
        self.assertTrue((root / "out" / "audit.md").is_file())


if __name__ == "__main__":
    unittest.main()
