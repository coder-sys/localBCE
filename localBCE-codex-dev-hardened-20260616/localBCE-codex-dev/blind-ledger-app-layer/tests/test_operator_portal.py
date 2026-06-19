import os
import unittest

from fastapi.testclient import TestClient

from app.operator_portal import create_app


class OperatorPortalTests(unittest.TestCase):
    def setUp(self):
        os.environ.setdefault("BL_DEV", "1")
        os.environ.setdefault("BL_PROVIDER_ALIAS_KEY", "BL_TEST_PROVIDER_ALIAS_KEY")
        os.environ.setdefault("BL_FORCE_PYTHON_RULES_ENGINE", "1")
        self.client = TestClient(create_app())

    def test_portal_serves_operator_shell_and_readiness(self):
        page = self.client.get("/")
        self.assertEqual(page.status_code, 200)
        self.assertIn("Medi-Cal Settlement Desk", page.text)
        self.assertIn("Operator", page.text)
        self.assertIn("Auditor", page.text)
        self.assertIn("Nullifier root", page.text)
        self.assertIn("STARK-native", page.text)
        self.assertIn("Claim Intake", page.text)
        self.assertIn("Claims Waiting", page.text)
        self.assertIn("Decision History", page.text)
        self.assertIn("All cases", page.text)
        self.assertNotIn("Claims JSON", page.text)

        readiness = self.client.get("/api/readiness")
        self.assertEqual(readiness.status_code, 200)
        payload = readiness.json()
        self.assertEqual(payload["portal_mode"], "local_operator_pilot")
        self.assertEqual(payload["proof_lane"], "CAIRO_STARK_NATIVE")
        self.assertFalse(payload["production_ready"])

    def test_operator_can_submit_sample_batch(self):
        sample = self.client.get("/api/sample-claim").json()
        response = self.client.post(
            "/api/batches",
            json={
                "actor": "operator@example.gov",
                "claims": [sample],
                "strict_oracle_attestations": True,
                "enforce_nullifier_proofs": True,
            },
        )

        self.assertEqual(response.status_code, 200)
        batch = response.json()["batches"][0]
        self.assertEqual(batch["claim_count"], 1)
        self.assertEqual(batch["quarantine_count"], 0)
        self.assertEqual(batch["payment_count"], 1)
        self.assertEqual(batch["claims"][0]["decision"], "approved")
        self.assertEqual(batch["payments"][0]["amount_cents"], 12500)
        self.assertFalse(batch["accepted_by_real_verifier"])
        events = response.json()["audit_log"]
        self.assertTrue(any(event["event_type"] == "claim_approved" for event in events))
        self.assertTrue(any(event["event_type"] == "payment_record_prepared" for event in events))

    def test_missing_authorization_routes_to_human_review_with_actions(self):
        sample = self.client.get("/api/sample-claim").json()
        sample["edi"] = sample["edi"].replace("BL-CLAIM-0001", "BL-CLAIM-MISSING-AUTH")
        sample["edi"] = sample["edi"].replace("SV1*HC:99213", "SV1*HC:T1019").replace("~REF*G1*PA-OK-123", "")
        response = self.client.post(
            "/api/batches",
            json={
                "actor": "operator@example.gov",
                "claims": [sample],
                "strict_oracle_attestations": True,
                "enforce_nullifier_proofs": True,
            },
        )

        self.assertEqual(response.status_code, 200)
        review_items = response.json()["review_items"]
        self.assertEqual(len(review_items), 1)
        item = review_items[0]
        self.assertEqual(item["reason"], "prior_authorization_required")
        self.assertEqual(item["category"], "Missing authorization")
        self.assertIn("Prior authorization number", item["required_items"])
        self.assertTrue(any(action["id"] == "request_prior_auth" for action in item["next_actions"]))
        self.assertTrue(any(event["event_type"] == "claim_routed_to_review" for event in response.json()["audit_log"]))

        action_response = self.client.post(
            f"/api/review-items/{item['id']}/actions",
            json={
                "actor": "operator@example.gov",
                "action_id": "request_prior_auth",
                "note": "Requested authorization packet from provider.",
            },
        )
        self.assertEqual(action_response.status_code, 200)
        updated = action_response.json()["item"]
        self.assertEqual(updated["status"], "waiting_on_documents")
        self.assertEqual(updated["assigned_to"], "operator@example.gov")
        self.assertTrue(any(event["event_type"] == "review_action" for event in action_response.json()["audit_log"]))

    def test_bad_file_routes_to_review_with_plain_language_reason(self):
        response = self.client.post(
            "/api/batches",
            json={
                "actor": "operator@example.gov",
                "claims": [{"claim_id": "BAD-FILE-0001", "edi": "", "flags": {}}],
                "strict_oracle_attestations": True,
                "enforce_nullifier_proofs": True,
            },
        )

        self.assertEqual(response.status_code, 200)
        item = response.json()["review_items"][0]
        self.assertEqual(item["source"], "quarantined_input")
        self.assertEqual(item["category"], "Unreadable claim file")
        self.assertIn("837 file", item["summary"])

    def test_unauthorized_actor_is_rejected(self):
        sample = self.client.get("/api/sample-claim").json()
        response = self.client.post(
            "/api/batches",
            json={
                "actor": "auditor@example.gov",
                "claims": [sample],
                "strict_oracle_attestations": True,
                "enforce_nullifier_proofs": True,
            },
        )

        self.assertEqual(response.status_code, 403)


if __name__ == "__main__":
    unittest.main()
