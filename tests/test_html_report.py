import json
import tempfile
import unittest
from pathlib import Path

from reporting.html_report import generate_from_artifacts


class HtmlReportPhase42Tests(unittest.TestCase):
    def _write_json(self, path: Path, payload):
        path.write_text(json.dumps(payload), encoding="utf-8")

    def test_phase_42_report_sections_are_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            findings_path = root / "findings.json"
            timeline_path = root / "timeline.json"
            graph_path = root / "graph.json"
            output_path = root / "report.html"

            self._write_json(
                findings_path,
                {
                    "case": {
                        "case_name": "phase-42",
                        "input_source": "evtx",
                        "response_priority": "P2",
                        "hosts": ["host-a"],
                        "users": ["alice"],
                        "first_seen": "2026-03-16T10:00:00Z",
                        "last_seen": "2026-03-16T11:00:00Z",
                        "collection_quality_summary": {
                            "summary": "Security + Sysmon present, PowerShell missing",
                            "telemetry_missing": ["PowerShell"],
                        },
                        "telemetry_summary": {"present": ["Security", "Sysmon"], "missing": ["PowerShell"]},
                    },
                    "summary": {
                        "signal_count": 2,
                        "finding_count": 1,
                        "incident_count": 1,
                        "response_priority": "P2",
                        "by_tactic": {"execution": 2, "credential_access": 1},
                    },
                    "signals": [
                        {
                            "id": "s-1",
                            "mitre_tactic": "execution",
                            "mitre_technique": "T1059.001 PowerShell",
                            "host": "host-a",
                            "user": "alice",
                        },
                        {
                            "id": "s-2",
                            "mitre_tactic": "credential_access",
                            "mitre_technique": "T1003 OS Credential Dumping",
                            "host": "host-a",
                            "user": "alice",
                        },
                    ],
                    "findings": [],
                    "incidents": [
                        {
                            "id": "i-1",
                            "title": "PowerShell Download Cradle",
                            "severity": "high",
                            "confidence": "high",
                            "confidence_score": 0.91,
                            "host": "host-a",
                            "user": "alice",
                            "recommended_next": "Contain host and validate parent process chain.",
                            "containment_guidance": ["Isolate host-a from network"],
                            "scope_next": ["Review related logons for alice"],
                            "validation_steps": ["Check unsigned script execution chain"],
                        }
                    ],
                    "raw_events": [],
                },
            )
            self._write_json(
                timeline_path,
                {
                    "summary": {"total_rows": 2},
                    "timeline": [
                        {"timestamp": "2026-03-16T10:01:00Z", "host": "host-a", "user": "alice", "source_ip": "10.0.0.5"},
                        {"timestamp": "2026-03-16T10:20:00Z", "host": "host-a", "user": "alice", "source_ip": "10.0.0.5"},
                    ],
                },
            )
            self._write_json(graph_path, {"nodes": [], "edges": []})

            generate_from_artifacts(
                str(findings_path),
                str(timeline_path),
                str(graph_path),
                str(output_path),
            )

            html = output_path.read_text(encoding="utf-8")
            self.assertIn("Download PDF hint", html)
            self.assertIn("Executive Summary", html)
            self.assertIn("MITRE ATT&CK Coverage Matrix", html)
            self.assertIn("@media print", html)
            self.assertIn("@page { size: auto; margin: 12mm; }", html)
            self.assertIn("renderExecutiveSummary", html)
            self.assertIn("renderMitreMatrix", html)

    def test_phase_42_template_has_priority_and_mitre_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            findings = root / "findings.json"
            timeline = root / "timeline.json"
            graph = root / "graph.json"
            report = root / "report.html"

            self._write_json(
                findings,
                {
                    "case": {"case_name": "hook-check", "input_source": "evtx"},
                    "summary": {"signal_count": 0, "finding_count": 0, "incident_count": 0, "by_tactic": {}},
                    "signals": [],
                    "findings": [],
                    "incidents": [],
                    "raw_events": [],
                },
            )
            self._write_json(timeline, {"summary": {"total_rows": 0}, "timeline": []})
            self._write_json(graph, {"nodes": [], "edges": []})

            generate_from_artifacts(str(findings), str(timeline), str(graph), str(report))

            html = report.read_text(encoding="utf-8")
            self.assertIn('id="executive-priority-badge"', html)
            self.assertIn("priority-p1", html)
            self.assertIn("priority-p4", html)
            self.assertIn('id="mitre-matrix"', html)
            self.assertIn("MITRE_TACTIC_ORDER", html)
            self.assertIn("text.replace(/\\\\/g, '/')", html)

    def test_inline_json_is_escaped_for_script_safety(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            findings = root / "findings.json"
            timeline = root / "timeline.json"
            graph = root / "graph.json"
            report = root / "report.html"

            self._write_json(
                findings,
                {
                    "case": {
                        "case_name": "escape-check",
                        "input_source": "evtx",
                        "response_priority": "P1",
                    },
                    "summary": {
                        "signal_count": 1,
                        "finding_count": 1,
                        "incident_count": 1,
                    },
                    "signals": [],
                    "findings": [
                        {
                            "id": "f-1",
                            "title": "PowerShell string with closing tag",
                            "summary": "contains </script> and line separators",
                        }
                    ],
                    "incidents": [],
                    "raw_events": [],
                },
            )
            self._write_json(
                timeline,
                {
                    "summary": {"total_rows": 1},
                    "timeline": [
                        {
                            "timestamp": "2026-03-16T10:01:00Z",
                            "summary": "bad </script> marker \u2028 \u2029",
                        }
                    ],
                },
            )
            self._write_json(graph, {"nodes": [], "edges": []})

            generate_from_artifacts(str(findings), str(timeline), str(graph), str(report))

            html = report.read_text(encoding="utf-8")
            self.assertIn("<\\/script>", html)
            self.assertNotIn("</script> and line separators", html)
            self.assertIn("\\u2028", html)
            self.assertIn("\\u2029", html)


if __name__ == "__main__":
    unittest.main()
