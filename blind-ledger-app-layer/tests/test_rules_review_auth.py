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

    def test_review_api_exposes_isolated_rules_routes(self) -> None:
        from app.rules_review_api import router

        if router is None:
            self.skipTest("FastAPI review dependencies are not installed")
        paths = {route.path for route in router.routes}
        self.assertIn("/rules/tasks", paths)
        self.assertIn("/rules/tasks/claim", paths)
        self.assertIn("/rules/quality", paths)


if __name__ == "__main__":
    unittest.main()
