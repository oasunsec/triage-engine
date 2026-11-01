"""Evidence explorer and evidence-link review API: roles, CSRF, validation, persistence."""

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from test_forensic_correlation import run_mixed

PASSWORD = "Password123!"


class ForensicAPITests(unittest.TestCase):
    def setUp(self):
        self._root = Path(tempfile.mkdtemp(prefix="triage-forensic-api-test-",
                                           dir=os.environ.get("TEMP") or None))
        (self._root / "build").mkdir()
        self.result = run_mixed(self._root / "build", detector_alerts=True, case="mixed-case")
        self.cases = Path(self.result.case_path).parent

        import server
        import corrobora.auth_store as auth
        import corrobora.review_store as rs
        self._orig = (server.CASES_ROOT, rs._DB_PATH, auth._DB_PATH)
        server.CASES_ROOT = str(self.cases)
        rs._DB_PATH = str(self._root / "reviews.db")
        rs._init_db()
        auth._DB_PATH = str(self._root / "auth.db")
        auth._init_db()
        server._reset_security_state_for_tests()
        self.server = server
        self.admin = self._client()
        self.assertEqual(self.admin.post("/api/auth/bootstrap", json={"username": "admin", "password": PASSWORD}).status_code, 200)
        self._csrf(self.admin)
        for role in ("analyst", "viewer"):
            created = self.admin.post("/api/auth/users", json={"username": role, "password": PASSWORD, "role": role})
            self.assertEqual(created.status_code, 200)
        self.analyst = self._login("analyst")
        self.viewer = self._login("viewer")
        links = json.loads((Path(self.result.case_path) / "evidence_relationships.json").read_text(encoding="utf-8"))
        self.relationship_id = links["relationships"][0]["relationship_id"]
        self.event_obs = links["relationships"][0]["source"]["observation_id"]
        self.artifact_obs = links["relationships"][0]["target"]["observation_id"]

    def tearDown(self):
        import corrobora.auth_store as auth
        import corrobora.review_store as rs
        for client in (self.admin, self.analyst, self.viewer):
            client.close()
        self.server.CASES_ROOT, rs._DB_PATH, auth._DB_PATH = self._orig
        shutil.rmtree(self._root, ignore_errors=True)

    def _client(self):
        return TestClient(self.server.app, raise_server_exceptions=False)

    def _csrf(self, client):
        client.headers["X-CSRF-Token"] = client.get("/api/auth/me").json()["csrf_token"]

    def _login(self, username):
        client = self._client()
        self.assertEqual(client.post("/api/auth/login", json={"username": username, "password": PASSWORD}).status_code, 200)
        self._csrf(client)
        return client

    def test_viewer_reads_links_coverage_and_observations(self):
        links = self.viewer.get("/api/cases/mixed-case/evidence-links")
        self.assertEqual(links.status_code, 200)
        body = links.json()
        self.assertEqual(body["total"], 2)
        self.assertEqual(body["relationships"][0]["review"]["decision"], "unreviewed")
        self.assertIn("families", body["summary"]["coverage"])
        observations = self.viewer.get("/api/cases/mixed-case/forensic-observations?kind=prefetch_run")
        self.assertEqual(observations.status_code, 200)
        self.assertEqual({item["kind"] for item in observations.json()["observations"]}, {"prefetch_run"})

    def test_executable_inventory_is_written_and_served_without_verdict_effect(self):
        stored = json.loads((Path(self.result.case_path) / "executable_inventory.json").read_text(encoding="utf-8"))
        self.assertEqual(stored["summary"]["verdict_effect"], "none")
        everything = self.viewer.get("/api/cases/mixed-case/executable-inventory?reasons_only=false")
        self.assertEqual(everything.status_code, 200)
        body = everything.json()
        self.assertTrue(body["available"])
        self.assertIn("\\users\\public\\upd.exe", [item["path"] for item in body["executables"]])
        self.assertIn("executed_but_absent", body["reasons"])
        flagged = self.viewer.get("/api/cases/mixed-case/executable-inventory").json()
        self.assertTrue(all(item["score"] > 0 and item["reasons"] for item in flagged["executables"]))
        self.assertEqual(self._client().get("/api/cases/mixed-case/executable-inventory").status_code, 401)

    def test_unauthenticated_and_viewer_cannot_mutate(self):
        anonymous = self._client()
        self.assertEqual(anonymous.get("/api/cases/mixed-case/evidence-links").status_code, 401)
        anonymous.close()
        denied = self.viewer.patch(f"/api/cases/mixed-case/evidence-links/{self.relationship_id}/review",
                                   json={"decision": "confirmed"})
        self.assertEqual(denied.status_code, 403)

    def test_missing_csrf_token_is_rejected(self):
        self.analyst.headers.pop("X-CSRF-Token")
        response = self.analyst.patch(f"/api/cases/mixed-case/evidence-links/{self.relationship_id}/review",
                                      json={"decision": "confirmed"})
        self.assertEqual(response.status_code, 403)
        self.assertIn("CSRF", response.json()["detail"])

    def test_analyst_decision_is_attributed_audited_and_kept_out_of_engine_output(self):
        path = Path(self.result.case_path) / "evidence_relationships.json"
        before = path.read_bytes()
        response = self.analyst.patch(f"/api/cases/mixed-case/evidence-links/{self.relationship_id}/review",
                                      json={"decision": "confirmed", "rationale": "Hash matches vendor build", "reviewed_by": "someone-else"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["reviewed_by"], "analyst")
        self.assertEqual(path.read_bytes(), before)
        listed = self.viewer.get("/api/cases/mixed-case/evidence-links").json()
        reviewed = next(item for item in listed["relationships"] if item["relationship_id"] == self.relationship_id)
        self.assertEqual(reviewed["review"]["decision"], "confirmed")
        history = self.viewer.get(f"/api/cases/mixed-case/evidence-links/{self.relationship_id}/history").json()["history"]
        self.assertEqual({row["field"] for row in history}, {"decision", "rationale"})

    def test_exported_bundle_carries_link_decisions_and_a_readable_review(self):
        import io
        import zipfile
        from unittest.mock import patch
        self.analyst.patch(f"/api/cases/mixed-case/evidence-links/{self.relationship_id}/review",
                           json={"decision": "confirmed", "rationale": "Hash matches vendor build"})
        with patch.object(self.server, "DATA_ROOT", str(self._root / "data")):
            response = self.analyst.post("/api/cases/mixed-case/bundle")
        self.assertEqual(response.status_code, 200)
        with zipfile.ZipFile(io.BytesIO(response.content)) as bundle:
            state = json.loads(bundle.read("review_state.json"))
            summary = bundle.read("analyst_review.md").decode("utf-8")
        self.assertEqual(state["schema_version"], "1.1")
        self.assertEqual(state["evidence_links"][self.relationship_id]["decision"], "confirmed")
        self.assertIn(f"`{self.relationship_id}`: confirmed by analyst (Hash matches vendor build)", summary)

    def test_invalid_and_unknown_link_ids_and_decisions_are_rejected(self):
        base = "/api/cases/mixed-case/evidence-links"
        self.assertEqual(self.analyst.patch(f"{base}/..%2F..%2Fx/review", json={"decision": "confirmed"}).status_code, 404)
        self.assertEqual(self.analyst.patch(f"{base}/rel_NOT-HEX/review", json={"decision": "confirmed"}).status_code, 400)
        self.assertEqual(self.analyst.patch(f"{base}/rel_{'0' * 64}/review", json={"decision": "confirmed"}).status_code, 404)
        self.assertEqual(self.analyst.patch(f"{base}/{self.relationship_id}/review", json={"decision": "proven"}).status_code, 400)
        self.assertEqual(self.analyst.get("/api/cases/..%2F..%2Fetc/evidence-links").status_code, 404)

    def test_hypothesis_requires_existing_distinct_observations(self):
        base = "/api/cases/mixed-case/evidence-links/hypotheses"
        created = self.analyst.post(base, json={"source_observation_id": self.event_obs, "target_observation_id": self.artifact_obs,
                                                "claim": "Same updater build"})
        self.assertEqual(created.status_code, 200)
        link = created.json()
        self.assertEqual(link["link_class"], "analyst_hypothesis")
        self.assertEqual(link["created_by"], "analyst")
        self.assertEqual(self.analyst.post(base, json={"source_observation_id": self.event_obs, "target_observation_id": self.event_obs,
                                                       "claim": "x"}).status_code, 400)
        self.assertEqual(self.analyst.post(base, json={"source_observation_id": self.event_obs, "target_observation_id": "obs_" + "f" * 64,
                                                       "claim": "x"}).status_code, 404)
        self.assertEqual(self.analyst.post(base, json={"source_observation_id": self.event_obs, "target_observation_id": self.artifact_obs,
                                                       "claim": ""}).status_code, 422)
        reviewed = self.admin.patch(f"{base}/{link['link_id']}", json={"decision": "rejected", "rationale": "Different build"})
        self.assertEqual(reviewed.status_code, 200)
        self.assertEqual(reviewed.json()["updated_by"], "admin")
        listed = self.viewer.get("/api/cases/mixed-case/evidence-links").json()["analyst_links"]
        self.assertEqual([(item["link_id"], item["decision"]) for item in listed], [(link["link_id"], "rejected")])

    def test_decisions_survive_a_rerun_with_the_same_link_ids(self):
        self.analyst.patch(f"/api/cases/mixed-case/evidence-links/{self.relationship_id}/review", json={"decision": "rejected"})
        run_mixed(self._root / "build", detector_alerts=True, case="mixed-case", bundle=self._root / "build" / "bundle", resume=True)
        listed = self.viewer.get("/api/cases/mixed-case/evidence-links").json()
        reviewed = next(item for item in listed["relationships"] if item["relationship_id"] == self.relationship_id)
        self.assertEqual(reviewed["review"]["decision"], "rejected")
        self.assertEqual(listed["orphaned_reviews"], [])


if __name__ == "__main__":
    unittest.main()
