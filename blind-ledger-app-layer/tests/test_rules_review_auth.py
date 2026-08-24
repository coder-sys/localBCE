from __future__ import annotations

import os
import unittest
from pathlib import Path
from unittest.mock import patch

from app.rules_review_api import _review_error_status
from app.rules_review_auth import RulesAuthError, authenticate_rules_request


class RulesReviewAuthTests(unittest.TestCase):
    def test_local_mock_identity_is_loopback_only(self) -> None:
        env = {"RULES_REVIEW_LOCAL_MOCK": "1", "RULES_REVIEW_BIND_HOST": "127.0.0.1"}
        with patch.dict(os.environ, env, clear=True):
            principal = authenticate_rules_request(
                client_host="127.0.0.1",
                authorization=None,
                local_subject="policy-1",
                local_roles="policy_reviewer",
            )
            self.assertEqual(principal.subject, "policy-1")
            principal.require("policy_reviewer")
            with self.assertRaisesRegex(RulesAuthError, "loopback"):
                authenticate_rules_request(
                    client_host="192.0.2.1",
                    authorization=None,
                    local_subject="policy-1",
                    local_roles="policy_reviewer",
                )

    def test_local_mock_rejects_unknown_roles(self) -> None:
        env = {"RULES_REVIEW_LOCAL_MOCK": "1", "RULES_REVIEW_BIND_HOST": "localhost"}
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaisesRegex(RulesAuthError, "valid local reviewer"):
                authenticate_rules_request(
                    client_host="::1",
                    authorization=None,
                    local_subject="admin",
                    local_roles="claims_admin",
                )

    def test_production_mode_fails_closed_without_oidc(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(RulesAuthError, "OIDC bearer"):
                authenticate_rules_request(client_host="127.0.0.1", authorization=None)

    def test_review_error_status_separates_authorization_from_conflicts(self) -> None:
        self.assertEqual(_review_error_status(RulesAuthError("role required")), 403)
        self.assertEqual(_review_error_status(ValueError("invalid decision")), 409)

    def test_review_ui_uses_safe_text_rendering(self) -> None:
        root = Path(__file__).resolve().parents[1]
        html = (root / "dashboard" / "rules-review.html").read_text(encoding="utf-8")
        self.assertIn("textContent", html)
        self.assertNotIn("innerHTML", html)
        self.assertIn("/rules/quality/tasks/", html)
        self.assertIn("/rules/sources/tasks/", html)
        self.assertIn("approve_for_registry", html)
        self.assertIn('id="sourceProgram"', html)
        self.assertIn('id="sourceMilestone"', html)
        self.assertIn("target_count=", html)
        self.assertIn("source_review_priority_programs", html)
        self.assertIn("?program=", html)
        self.assertIn("renewClaim", html)
        self.assertIn("releaseClaim", html)

    def test_review_api_exposes_isolated_rules_routes(self) -> None:
        from app.rules_review_api import router

        if router is None:
            self.skipTest("FastAPI review dependencies are not installed")
        paths = {route.path for route in router.routes}
        self.assertIn("/rules/tasks", paths)
        self.assertIn("/rules/tasks/claim", paths)
        self.assertIn("/rules/tasks/{task_id}/renew", paths)
        self.assertIn("/rules/tasks/{task_id}/release", paths)
        self.assertIn("/rules/quality", paths)
        self.assertIn("/rules/quality/tasks/claim", paths)
        self.assertIn("/rules/quality/tasks/{sample_id}/review", paths)
        self.assertIn("/rules/quality/tasks/{sample_id}/renew", paths)
        self.assertIn("/rules/quality/tasks/{sample_id}/release", paths)
        self.assertIn("/rules/sources/tasks/claim", paths)
        self.assertIn("/rules/sources/preflight", paths)
        self.assertIn(
            "/rules/sources/candidates/{source_candidate_id}", paths
        )
        self.assertIn(
            "/rules/sources/tasks/{source_candidate_id}/decision", paths
        )
        self.assertIn(
            "/rules/sources/tasks/{source_candidate_id}/renew", paths
        )
        self.assertIn(
            "/rules/sources/tasks/{source_candidate_id}/release", paths
        )

    def test_rule_claim_lease_actions_preserve_owner_and_role(self) -> None:
        try:
            from fastapi import FastAPI
            from fastapi.testclient import TestClient

            from app.rules_review_api import router, store
        except ImportError:
            self.skipTest("FastAPI review dependencies are not installed")
        if router is None:
            self.skipTest("FastAPI review dependencies are not installed")

        class FakeStore:
            def renew_review_task_claim(self, task_id, **kwargs):
                return {"task_id": task_id, "action": "renew", **kwargs}

            def release_review_task_claim(self, task_id, **kwargs):
                return {"task_id": task_id, "action": "release", **kwargs}

        app = FastAPI()
        app.include_router(router)
        app.dependency_overrides[store] = lambda: FakeStore()
        client = TestClient(app, client=("127.0.0.1", 50000))
        headers = {
            "x-local-reviewer-id": "policy-1",
            "x-local-reviewer-roles": "policy_reviewer",
        }
        env = {"RULES_REVIEW_LOCAL_MOCK": "1", "RULES_REVIEW_BIND_HOST": "127.0.0.1"}
        with patch.dict(os.environ, env, clear=True):
            renewed = client.post("/rules/tasks/task-fixture/renew", headers=headers)
            released = client.post("/rules/tasks/task-fixture/release", headers=headers)
        self.assertEqual(renewed.status_code, 200)
        self.assertEqual(released.status_code, 200)
        self.assertEqual(renewed.json()["reviewer_id"], "policy-1")
        self.assertEqual(renewed.json()["reviewer_role"], "policy_reviewer")
        self.assertEqual(released.json()["action"], "release")

    def test_source_review_requires_admin_and_never_activates_registry(self) -> None:
        try:
            from fastapi import FastAPI
            from fastapi.testclient import TestClient

            from app.rules_review_api import router, store
        except ImportError:
            self.skipTest("FastAPI review dependencies are not installed")
        if router is None:
            self.skipTest("FastAPI review dependencies are not installed")

        class FakeStore:
            def source_registry_preflight_summary(self, *, target_count):
                return {
                    "assessed_candidate_count": 1,
                    "source_review_milestone_target": target_count,
                    "human_review_required": True,
                    "automatic_registry_activation": False,
                }

            def claim_source_registry_candidate(self, **kwargs):
                return {"source_candidate_id": "source-candidate-fixture", **kwargs}

            def renew_source_registry_candidate_claim(self, source_candidate_id, **kwargs):
                return {"source_candidate_id": source_candidate_id, "action": "renew", **kwargs}

            def release_source_registry_candidate_claim(self, source_candidate_id, **kwargs):
                return {"source_candidate_id": source_candidate_id, "action": "release", **kwargs}

            def record_source_registry_candidate_decision(self, **kwargs):
                return {
                    "source_decision_id": "source-decision-fixture",
                    "registry_activation": False,
                    "runtime_activation": False,
                    "proof_binding": False,
                    **kwargs,
                }

        app = FastAPI()
        app.include_router(router)
        app.dependency_overrides[store] = lambda: FakeStore()
        client = TestClient(app, client=("127.0.0.1", 50000))
        env = {"RULES_REVIEW_LOCAL_MOCK": "1", "RULES_REVIEW_BIND_HOST": "127.0.0.1"}
        policy_headers = {
            "x-local-reviewer-id": "policy-1",
            "x-local-reviewer-roles": "policy_reviewer",
        }
        admin_headers = {
            "x-local-reviewer-id": "admin-1",
            "x-local-reviewer-roles": "rules_admin",
        }
        with patch.dict(os.environ, env, clear=True):
            forbidden_summary = client.get(
                "/rules/sources/preflight", headers=policy_headers
            )
            summary = client.get(
                "/rules/sources/preflight?target_count=600000", headers=admin_headers
            )
            forbidden = client.post("/rules/sources/tasks/claim", headers=policy_headers)
            claimed = client.post(
                "/rules/sources/tasks/claim?program=medicaid", headers=admin_headers
            )
            renewed = client.post(
                "/rules/sources/tasks/source-candidate-fixture/renew",
                headers=admin_headers,
            )
            released = client.post(
                "/rules/sources/tasks/source-candidate-fixture/release",
                headers=admin_headers,
            )
            reviewed = client.post(
                "/rules/sources/tasks/source-candidate-fixture/decision",
                headers=admin_headers,
                json={
                    "decision": "approve_for_registry",
                    "rationale": "official link and lineage checked",
                },
            )
        self.assertEqual(forbidden_summary.status_code, 403)
        self.assertEqual(summary.status_code, 200)
        self.assertTrue(summary.json()["human_review_required"])
        self.assertEqual(
            summary.json()["source_review_milestone_target"], 600_000
        )
        self.assertEqual(forbidden.status_code, 403)
        self.assertEqual(claimed.status_code, 200)
        self.assertEqual(claimed.json()["task"]["program"], "medicaid")
        self.assertEqual(renewed.status_code, 200)
        self.assertEqual(released.status_code, 200)
        self.assertEqual(renewed.json()["reviewer_id"], "admin-1")
        self.assertEqual(reviewed.status_code, 200)
        self.assertFalse(reviewed.json()["registry_activation"])
        self.assertFalse(reviewed.json()["runtime_activation"])
        self.assertFalse(reviewed.json()["proof_binding"])

    def test_quality_review_route_preserves_role_and_nonbinding_flags(self) -> None:
        try:
            from fastapi import FastAPI
            from fastapi.testclient import TestClient

            from app.rules_review_api import router, store
        except ImportError:
            self.skipTest("FastAPI review dependencies are not installed")
        if router is None:
            self.skipTest("FastAPI review dependencies are not installed")

        class FakeStore:
            def __init__(self) -> None:
                self.submission = None

            def claim_quality_sample(self, **kwargs):
                return {"sample_id": "sample_fixture", **kwargs}

            def renew_quality_sample_claim(self, sample_id, **kwargs):
                return {"sample_id": sample_id, "action": "renew", **kwargs}

            def release_quality_sample_claim(self, sample_id, **kwargs):
                return {"sample_id": sample_id, "action": "release", **kwargs}

            def record_quality_review(self, submission):
                self.submission = submission
                return {"submission_id": "quality-review-fixture", "completed": False}

        fake = FakeStore()
        app = FastAPI()
        app.include_router(router)
        app.dependency_overrides[store] = lambda: fake
        client = TestClient(app, client=("127.0.0.1", 50000))
        headers = {
            "x-local-reviewer-id": "policy-1",
            "x-local-reviewer-roles": "policy_reviewer",
        }
        env = {"RULES_REVIEW_LOCAL_MOCK": "1", "RULES_REVIEW_BIND_HOST": "127.0.0.1"}
        with patch.dict(os.environ, env, clear=True):
            claimed = client.post(
                "/rules/quality/tasks/claim?release_id=federal-5100-v1",
                headers=headers,
            )
            self.assertEqual(claimed.status_code, 200)
            renewed = client.post(
                "/rules/quality/tasks/sample_fixture/renew", headers=headers
            )
            released = client.post(
                "/rules/quality/tasks/sample_fixture/release", headers=headers
            )
            reviewed = client.post(
                "/rules/quality/tasks/sample_fixture/review",
                headers=headers,
                json={
                    "candidate_id": "cand_" + "a" * 32,
                    "draft_hash": "b" * 64,
                    "rationale": "checked against the captured source",
                    "measurements": {
                        "evidence_span_precise": True,
                        "typed_mapping_correct": True,
                        "program_classification_correct": True,
                        "deterministic_rerun_match": True,
                    },
                },
            )
        self.assertEqual(reviewed.status_code, 200)
        self.assertEqual(renewed.status_code, 200)
        self.assertEqual(released.status_code, 200)
        self.assertEqual(renewed.json()["reviewer_role"], "policy_reviewer")
        self.assertEqual(fake.submission["reviewer_role"], "policy_reviewer")
        self.assertFalse(fake.submission["runtime_activation"])
        self.assertFalse(fake.submission["proof_binding"])


if __name__ == "__main__":
    unittest.main()
