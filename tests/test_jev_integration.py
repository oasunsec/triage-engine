"""Contract and data-minimization checks for the optional Jev connector."""

from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from triage_engine.jev import JevIntegrationError, build_jev_state, review_case


class _Response:
    def __init__(self, payload):
        self.payload = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _limit):
        return self.payload


class JevIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.case_payload = {
            "case": {
                "case_name": "private-case",
                "primary_host": "private-host",
                "primary_user": "private-user",
                "response_priority": "P2",
                "triage_disposition": {"disposition": "Investigate"},
                "collection_quality_summary": {"telemetry_missing": ["Sysmon"]},
            },
            "summary": {"finding_count": 2, "incident_count": 1},
            "incidents": [{
                "title": "Suspicious persistence", "summary": "New autorun entry",
                "severity": "high", "mitre_technique": "T1547",
                "command_line": "secret-command", "host": "private-host",
            }],
            "findings": [{"title": "Autorun change", "severity": "medium"}],
            "raw_events": [{"message": "private-raw-event"}],
            "review_notes": [{"text": "private-review-note"}],
        }

    def test_state_excludes_raw_evidence_and_identifiers(self):
        state = build_jev_state(self.case_payload)
        serialized = json.dumps(state)
        for secret in ("private-case", "private-host", "private-user", "secret-command", "private-raw-event", "private-review-note"):
            self.assertNotIn(secret, serialized)
        self.assertEqual(state["response_priority"], "P2")
        self.assertEqual(state["missing_telemetry"], ["Sysmon"])

    def test_review_posts_to_fixed_endpoint_and_validates_typed_response(self):
        response = {
            "model": "jev-1.13.0",
            "answers": {
                "review_focus": {
                    "type": "choice", "choice": "validate_detection", "confidence": 0.83,
                    "probabilities": {
                        "validate_detection": 0.7, "expand_scope": 0.1,
                        "collect_telemetry": 0.1, "routine_review": 0.1,
                    },
                },
                "prompt_review": {"type": "noul", "noul": 0.91},
            },
        }
        with patch("triage_engine.jev.urllib.request.urlopen", return_value=_Response(response)) as post:
            result = review_case(self.case_payload, api_key="test-only-key")
        request = post.call_args.args[0]
        sent = json.loads(request.data)
        self.assertEqual(request.full_url, "https://api.typesafe.ai/v1/systemone")
        self.assertEqual(request.get_header("Authorization"), "Bearer test-only-key")
        self.assertEqual(sent["model"], "jev-latest")
        self.assertNotIn("raw_events", sent["state"])
        self.assertEqual(result["review_focus"]["choice"], "validate_detection")
        self.assertEqual(result["prompt_review_probability"], 0.91)
        self.assertTrue(result["advisory_only"])

    def test_malformed_response_is_rejected(self):
        with patch("triage_engine.jev.urllib.request.urlopen", return_value=_Response({"answers": {}})):
            with self.assertRaises(JevIntegrationError):
                review_case(self.case_payload, api_key="test-only-key")

    def test_invalid_case_counts_are_rejected_before_network_call(self):
        self.case_payload["summary"]["finding_count"] = -1
        with patch("triage_engine.jev.urllib.request.urlopen") as post:
            with self.assertRaises(ValueError):
                review_case(self.case_payload, api_key="test-only-key")
        post.assert_not_called()


if __name__ == "__main__":
    unittest.main()
