import base64
import concurrent.futures
import hashlib
import json
import os
import re
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import app.operator_portal as operator_portal
from fastapi.testclient import TestClient

from app.batch.batch_orchestrator import BatchConfig, _claim_source_commitment_for_oracle
from app.batch.leaf import current_duplicate_pepper
from app.ingestion import parse_837
from app.operator_portal import assert_dashboard_metrics_match, create_app
from app.oracle_attestation import make_test_attestation
from app.shared_context import build_shared_context, tar_authorization_commitment_for_context


DECISION_FACTS = (
    "eligibility_active",
    "provider_enrolled",
    "provider_not_suspended",
    "not_deceased",
    "duplicate_claim",
    "program_integrity_hold",
)


def _claim_id_from_edi(edi: str) -> str:
    match = re.search(r"(?:^|~)CLM\*([^*~]+)", str(edi or ""))
    return match.group(1) if match else "BL-CLAIM-0001"


def _attach_signed_attestations(claim: dict) -> dict:
    claim_id = str(claim.get("claim_id") or _claim_id_from_edi(str(claim.get("edi", ""))))
    parsed = parse_837(str(claim.get("edi", "")))
    if not parsed.accepted:
        raise AssertionError(parsed.errors)
    ctx = build_shared_context(parsed, claim["flags"], strict_oracle=False)
    claim_source_commitment = _claim_source_commitment_for_oracle(
        ctx,
        config=BatchConfig(),
        frequency_type="original",
        duplicate_pepper=current_duplicate_pepper(),
    )
    tar_authorization_commitment = tar_authorization_commitment_for_context(
        ctx,
        BatchConfig().tar_required_procedure_codes,
    )
    claim["oracle_attestations"] = [
        make_test_attestation(
            fact,
            bool(claim["flags"][fact]),
            source_id=f"TEST-{fact}",
            claim_id=claim_id,
            claim_source_commitment=claim_source_commitment,
            tar_authorization_commitment=tar_authorization_commitment,
        ).to_dict()
        for fact in DECISION_FACTS
    ]
    return claim


class OperatorPortalTests(unittest.TestCase):
    def setUp(self):
        self._state_dir = tempfile.TemporaryDirectory()
        self._state_path = Path(self._state_dir.name) / "portal_state.json"
        self._packet_root = Path(self._state_dir.name) / "provider_packets"
        self._env_patch = patch.dict(
            os.environ,
            {
                "BL_ENV": "test",
                "BL_DEV": "1",
                "BL_PROVIDER_ALIAS_KEY": "BL_TEST_PROVIDER_ALIAS_KEY",
                "BL_FORCE_PYTHON_RULES_ENGINE": "1",
                "BL_ADMIN_OPERATOR_PORTAL_TOKEN": "local-admin-portal-token",
                "BL_LOCAL_OPERATOR_PORTAL_TOKEN": "local-operator-token",
                "BL_AUDITOR_OPERATOR_PORTAL_TOKEN": "local-auditor-portal-token",
                "BL_PROVIDER_PORTAL_TOKEN": "local-provider-token",
                "BL_OPERATOR_PORTAL_STATE_PATH": str(self._state_path),
            },
            clear=False,
        )
        self._env_patch.start()
        os.environ.pop("BL_PROVIDER_PORTAL_TENANTS_JSON", None)
        self._storage_patch = patch.object(operator_portal, "PROVIDER_PACKET_STORAGE_ROOT", self._packet_root)
        self._storage_patch.start()
        self.client = TestClient(create_app())
        self.operator_headers = {
            "Authorization": "Bearer local-operator-token",
            "X-BL-Principal": "operator@example.gov",
        }
        self.auditor_headers = {
            "Authorization": "Bearer local-auditor-portal-token",
            "X-BL-Principal": "auditor@example.gov",
        }
        self.provider_headers = {
            "Authorization": "Bearer local-provider-token",
            "X-BL-Principal": "provider@example.org",
        }
        self.east_bay_provider_headers = {
            "Authorization": "Bearer local-east-bay-provider-token",
            "X-BL-Principal": "east-bay@example.org",
        }

    def tearDown(self):
        self.client.close()
        self._storage_patch.stop()
        self._env_patch.stop()
        self._state_dir.cleanup()

    def provider_packet_payload(self, attachments=None):
        packet_bytes = b"Synthetic signed PA packet for BL-CLAIM-AUTH-042"
        return {
            "request_id": "DOC-REQ-042",
            "claim_id": "BL-CLAIM-AUTH-042",
            "action": "submit_packet",
            "pa_number": "PA-T1019-2026-042",
            "effective_from": "2026-06-01",
            "effective_through": "2026-06-30",
            "date_covers": True,
            "procedure_match": True,
            "signed_document": True,
            "attachments": attachments
            if attachments is not None
            else [
                {
                    "filename": "signed-pa.txt",
                    "content_base64": base64.b64encode(packet_bytes).decode("ascii"),
                    "mime_type": "text/plain",
                    "size_bytes": len(packet_bytes),
                }
            ],
        }

    def test_portal_serves_operator_shell_and_readiness(self):
        page = self.client.get("/")
        self.assertEqual(page.status_code, 200)
        self.assertIn("Medi-Cal Claims Inbox", page.text)
        self.assertIn("Work queue", page.text)
        self.assertIn("My queue", page.text)
        self.assertIn("Missing auth", page.text)
        self.assertIn("SLA risk", page.text)
        self.assertIn("Ready for release", page.text)
        self.assertIn("Case record", page.text)
        self.assertNotIn("Medi-Cal Settlement Desk", page.text)
        self.assertNotIn("Claim Intake", page.text)
        self.assertNotIn("Batch Evidence", page.text)
        self.assertNotIn("Claims JSON", page.text)

        readiness = self.client.get("/api/readiness")
        self.assertEqual(readiness.status_code, 200)
        payload = readiness.json()
        self.assertEqual(payload["portal_mode"], "local_operator_pilot")
        self.assertEqual(payload["proof_lane"], "BL_PQ512_NATIVE")
        self.assertFalse(payload["production_ready"])

    def test_operator_can_submit_sample_batch(self):
        sample = self.client.get("/api/sample-claim").json()
        _attach_signed_attestations(sample)
        response = self.client.post(
            "/api/batches",
            headers=self.operator_headers,
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
        self.assertEqual(response.json()["dashboard_metrics"]["approved"], 1)
        self.assertEqual(response.json()["dashboard_metrics"]["dollars_to_settle_cents"], 12500)

    def test_demo_batch_returns_real_computed_metrics_and_public_inputs(self):
        original_sample_claim = operator_portal._sample_claim

        def signed_sample_claim(*args, **kwargs):
            claim = original_sample_claim(*args, **kwargs)
            try:
                return _attach_signed_attestations(claim)
            except ValueError:
                return claim

        with patch("app.operator_portal._sample_claim", side_effect=signed_sample_claim):
            response = self.client.post(
                "/api/demo-batch",
                headers=self.operator_headers,
                json={"actor": "operator@example.gov"},
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        metrics = payload["dashboard_metrics"]
        self.assertEqual(metrics["claims_processed"], 6)
        self.assertEqual(metrics["approved"], 1)
        self.assertEqual(metrics["denied"], 4)
        self.assertEqual(metrics["quarantined"], 1)
        self.assertEqual(metrics["dollars_to_settle_cents"], 12500)
        self.assertEqual(metrics["dollars_prevented_cents"], 62500)
        self.assertEqual(metrics["caught_by_layer_gate"]["G2_ELIGIBILITY_ACTIVE"], 1)
        self.assertEqual(metrics["caught_by_layer_gate"]["G3_PROVIDER_NPI_PRESENT"], 1)
        self.assertEqual(metrics["caught_by_layer_gate"]["G9_NOT_DUPLICATE"], 1)
        self.assertEqual(metrics["caught_by_layer_gate"]["G10_NO_PROGRAM_INTEGRITY_HOLD"], 1)
        self.assertEqual(metrics["caught_by_layer_gate"]["dirty_claim_prefilter"], 1)
        self.assertEqual(len(payload["public_inputs"]), 21)
        self.assertFalse(payload["batches"][0]["accepted_by_real_verifier"])
        self.assertIn("native STARK proof generation and verifier acceptance", payload["real_vs_stubbed"]["stubbed"])
        self.assertEqual([row["decision"] for row in payload["claim_readout"]], ["approved", "denied", "denied", "denied", "denied", "quarantined"])
        self.assertEqual(payload["claim_readout"][-1]["denial_reason"], "dirty_claim_prefilter_rejected")

    def test_demo_batch_seeds_defaults_only_in_explicit_test_mode(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("BL_DEV", None)
            os.environ.pop("BL_DUPLICATE_CHECK_PEPPER", None)
            os.environ["BL_ENV"] = "test"
            client = TestClient(create_app())

            response = client.post(
                "/api/demo-batch",
                headers=self.operator_headers,
                json={"actor": "operator@example.gov"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["dashboard_metrics"]["claims_processed"], 6)

    def test_local_tokens_fail_closed_outside_explicit_local_modes(self):
        configured_tokens = {
            "BL_ADMIN_OPERATOR_PORTAL_TOKEN": "configured-admin-token",
            "BL_LOCAL_OPERATOR_PORTAL_TOKEN": "configured-operator-token",
            "BL_AUDITOR_OPERATOR_PORTAL_TOKEN": "configured-auditor-token",
            "BL_PROVIDER_PORTAL_TOKEN": "configured-provider-token",
        }
        for environment in ("", "staging", "unknown", "prod"):
            with self.subTest(environment=environment or "blank"):
                with patch.dict(os.environ, {**configured_tokens, "BL_ENV": environment}, clear=False):
                    client = TestClient(create_app())
                    response = client.get("/api/batches", headers=self.operator_headers)
                    client.close()
                self.assertEqual(response.status_code, 403)

    def test_published_local_token_is_configuration_error_outside_local_mode(self):
        with patch.dict(
            os.environ,
            {
                "BL_ENV": "staging",
                "BL_ADMIN_OPERATOR_PORTAL_TOKEN": "configured-admin-token",
                "BL_LOCAL_OPERATOR_PORTAL_TOKEN": "local-operator-token",
                "BL_AUDITOR_OPERATOR_PORTAL_TOKEN": "configured-auditor-token",
                "BL_PROVIDER_PORTAL_TOKEN": "configured-provider-token",
            },
            clear=False,
        ):
            client = TestClient(create_app())
            response = client.get("/api/batches", headers={"Authorization": "Bearer configured-admin-token"})
            client.close()

        self.assertEqual(response.status_code, 500)
        self.assertIn("published local portal token is forbidden", response.json()["detail"])

    def test_credentials_must_be_unique_across_every_portal_principal(self):
        duplicate_provider_tenants = json.dumps(
            {
                "one@example.org": {"token": "shared-provider-token", "name": "One", "npi": "1111111111"},
                "two@example.org": {"token": "shared-provider-token", "name": "Two", "npi": "2222222222"},
            }
        )
        cases = (
            {
                "BL_PROVIDER_PORTAL_TOKEN": "local-operator-token",
                "BL_PROVIDER_PORTAL_TENANTS_JSON": "",
            },
            {
                "BL_PROVIDER_PORTAL_TENANTS_JSON": duplicate_provider_tenants,
            },
        )
        for configuration in cases:
            with self.subTest(configuration=configuration):
                with patch.dict(os.environ, configuration, clear=False):
                    if not configuration.get("BL_PROVIDER_PORTAL_TENANTS_JSON"):
                        os.environ.pop("BL_PROVIDER_PORTAL_TENANTS_JSON", None)
                    client = TestClient(create_app())
                    response = client.get("/api/batches", headers=self.operator_headers)
                    client.close()
                self.assertEqual(response.status_code, 500)
                self.assertIn("globally unique", response.json()["detail"])

    def test_dashboard_metric_divergence_guard_rejects_tampered_metrics(self):
        payload = self.client.post("/api/demo-batch", headers=self.operator_headers, json={"actor": "operator@example.gov"}).json()
        tampered = dict(payload["dashboard_metrics"])
        tampered["claims_processed"] += 1

        with self.assertRaisesRegex(ValueError, "dashboard_metrics_divergence"):
            assert_dashboard_metrics_match(
                tampered,
                payload["batches"],
                payload["review_items"],
                list(reversed(payload["audit_log"])),
            )

    def test_missing_authorization_routes_to_human_review_with_actions(self):
        sample = self.client.get("/api/sample-claim").json()
        sample["edi"] = sample["edi"].replace("BL-CLAIM-0001", "BL-CLAIM-MISSING-AUTH")
        sample["edi"] = sample["edi"].replace("SV1*HC:99213", "SV1*HC:T1019").replace("~REF*G1*PA-OK-123", "")
        _attach_signed_attestations(sample)
        response = self.client.post(
            "/api/batches",
            headers=self.operator_headers,
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
            headers=self.operator_headers,
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

    def test_operator_portal_actions_record_backend_audit_events(self):
        response = self.client.post(
            "/api/operator-events",
            headers=self.operator_headers,
            json={
                "claim_id": "BL-CLAIM-AUTH-042",
                "action": "prepare_request",
                "status": "documentation_requested",
                "payment_state": "Held",
                "description": "Documentation request recorded from the claim workstation.",
                "outcome": "Documentation request sent",
                "amount_cents": None,
            },
        )

        self.assertEqual(response.status_code, 200)
        event = response.json()["event"]
        self.assertEqual(event["event_type"], "operator_portal_action")
        self.assertEqual(event["actor"], "operator@example.gov")
        self.assertEqual(event["claim_id"], "BL-CLAIM-AUTH-042")
        self.assertEqual(event["metadata"]["source"], "operator_portal_claim_workstation")
        audit_log = self.client.get("/api/audit-log", headers=self.operator_headers).json()["events"]
        self.assertEqual(audit_log[0]["id"], event["id"])

    def test_operator_actions_reject_claims_missing_from_authoritative_records(self):
        before = self.client.get("/api/audit-log", headers=self.operator_headers).json()["events"]
        response = self.client.post(
            "/api/operator-events",
            headers=self.operator_headers,
            json={
                "claim_id": "BL-NOT-A-REAL-CLAIM",
                "action": "prepare_request",
                "status": "documentation_requested",
                "payment_state": "Held",
            },
        )

        self.assertEqual(response.status_code, 404)
        self.assertIn("authoritative portal records", response.json()["detail"])
        after = self.client.get("/api/audit-log", headers=self.operator_headers).json()["events"]
        self.assertEqual(after, before)

    def test_operator_cannot_mark_or_verify_documents_without_a_provider_packet(self):
        prepare = self.client.post(
            "/api/operator-events",
            headers=self.operator_headers,
            json={"claim_id": "BL-CLAIM-AUTH-042", "action": "prepare_request"},
        )
        self.assertEqual(prepare.status_code, 200)

        for action in ("mark_docs_received", "verify_authorization"):
            with self.subTest(action=action):
                response = self.client.post(
                    "/api/operator-events",
                    headers=self.operator_headers,
                    json={"claim_id": "BL-CLAIM-AUTH-042", "action": action},
                )
                self.assertEqual(response.status_code, 409)
                self.assertEqual(response.json()["detail"], "provider_packet_required")
        state = self.client.get("/api/workspace", headers=self.operator_headers).json()["operator_claim_states"]["BL-CLAIM-AUTH-042"]
        self.assertEqual(state["workflow_state"], "documentation_requested")

    def test_server_ignores_forged_claim_state_payment_and_amount(self):
        response = self.client.post(
            "/api/operator-events",
            headers=self.operator_headers,
            json={
                "claim_id": "BL-CLAIM-AUTH-042",
                "action": "prepare_request",
                "status": "released",
                "payment_state": "Released",
                "description": "Synthetic operator note.",
                "outcome": "payment_released",
                "amount_cents": 1,
                "metadata": {
                    "request_id": "DOC-REQ-FORGED",
                    "provider_npi": "0000000000",
                    "workflow_state": "released",
                    "status": "released",
                    "payment_state": "Released",
                    "amount_cents": 2,
                    "proof_verified": True,
                    "settlement_verified": True,
                },
            },
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        event = payload["event"]
        claim_state = payload["operator_claim_states"]["BL-CLAIM-AUTH-042"]
        self.assertEqual(event["outcome"], "documentation_requested")
        self.assertEqual(event["amount_cents"], 125000)
        self.assertEqual(event["metadata"]["status"], "documentation_requested")
        self.assertEqual(event["metadata"]["payment_state"], "Held")
        self.assertEqual(event["metadata"]["amount_cents"], 125000)
        self.assertEqual(event["metadata"]["request_id"], "DOC-REQ-042")
        self.assertEqual(event["metadata"]["provider_npi"], "1999999984")
        self.assertNotIn("proof_verified", event["metadata"])
        self.assertNotIn("settlement_verified", event["metadata"])
        self.assertEqual(claim_state["workflow_state"], "documentation_requested")
        self.assertEqual(claim_state["payment_state"], "Held")
        self.assertEqual(claim_state["amount_cents"], 125000)
        provider_request = next(item for item in payload["provider_workspace"]["requests"] if item["request_id"] == "DOC-REQ-042")
        self.assertEqual(provider_request["amount_cents"], 125000)

    def test_release_stays_blocked_after_authorization_until_real_proof_and_settlement(self):
        prepare = self.client.post(
            "/api/operator-events",
            headers=self.operator_headers,
            json={"claim_id": "BL-CLAIM-AUTH-042", "action": "prepare_request"},
        )
        self.assertEqual(prepare.status_code, 200)
        packet = self.client.post(
            "/api/provider-packets",
            headers=self.provider_headers,
            json=self.provider_packet_payload(),
        )
        self.assertEqual(packet.status_code, 200)
        docs = self.client.post(
            "/api/operator-events",
            headers=self.operator_headers,
            json={"claim_id": "BL-CLAIM-AUTH-042", "action": "mark_docs_received"},
        )
        self.assertEqual(docs.status_code, 200)
        verified = self.client.post(
            "/api/operator-events",
            headers=self.operator_headers,
            json={"claim_id": "BL-CLAIM-AUTH-042", "action": "verify_authorization"},
        )
        self.assertEqual(verified.status_code, 200)
        self.assertEqual(verified.json()["operator_claim_states"]["BL-CLAIM-AUTH-042"]["workflow_state"], "ready_for_release")
        closed_packet = self.client.post(
            "/api/provider-packets",
            headers=self.provider_headers,
            json=self.provider_packet_payload(),
        )
        self.assertEqual(closed_packet.status_code, 409)
        self.assertEqual(closed_packet.json()["detail"], "provider_request_is_closed")
        before_events = self.client.get("/api/audit-log", headers=self.operator_headers).json()["events"]

        release = self.client.post(
            "/api/operator-events",
            headers=self.operator_headers,
            json={
                "claim_id": "BL-CLAIM-AUTH-042",
                "action": "release_payment",
                "status": "released",
                "payment_state": "Released",
                "amount_cents": 125000,
            },
        )

        self.assertEqual(release.status_code, 409)
        self.assertEqual(release.json()["detail"], "verified_proof_and_settlement_required")
        workspace = self.client.get("/api/workspace", headers=self.operator_headers).json()
        self.assertEqual(workspace["operator_claim_states"]["BL-CLAIM-AUTH-042"]["workflow_state"], "ready_for_release")
        self.assertEqual(workspace["operator_claim_states"]["BL-CLAIM-AUTH-042"]["payment_state"], "Ready")
        self.assertEqual(self.client.get("/api/audit-log", headers=self.operator_headers).json()["events"], before_events)
        self.assertFalse(any(event["event_type"] == "payer_payment_released" for event in workspace["provider_workspace"]["audit_log"]))

    def test_provider_request_release_decision_is_rejected_without_state_change(self):
        before = self.client.get("/api/workspace", headers=self.operator_headers).json()
        response = self.client.post(
            "/api/provider-requests/DOC-REQ-042/decision",
            headers=self.operator_headers,
            json={
                "decision": "release",
                "payment_state": "Released",
                "metadata": {"proof_verified": True, "settlement_verified": True},
            },
        )

        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["detail"], "verified_proof_and_settlement_required")
        after = self.client.get("/api/workspace", headers=self.operator_headers).json()
        self.assertEqual(after["operator_claim_states"], before["operator_claim_states"])
        self.assertEqual(after["provider_workspace"], before["provider_workspace"])
        self.assertEqual(after["audit_log"], before["audit_log"])

    def test_invalid_later_attachment_leaves_no_packet_files_or_state(self):
        first = b"synthetic first attachment"
        response = self.client.post(
            "/api/provider-packets",
            headers=self.provider_headers,
            json=self.provider_packet_payload(
                [
                    {
                        "filename": "first.txt",
                        "content_base64": base64.b64encode(first).decode("ascii"),
                        "size_bytes": len(first),
                    },
                    {
                        "filename": "invalid.txt",
                        "content_base64": "not-valid-base64!",
                    },
                ]
            ),
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("invalid attachment encoding", response.json()["detail"])
        self.assertFalse(self._packet_root.exists())
        workspace = self.client.get("/api/provider-workspace", headers=self.provider_headers).json()
        self.assertEqual(workspace["packets"], [])
        self.assertEqual(workspace["requests"][0]["status"], "needs_packet")

    def test_sanitized_attachment_names_are_still_unique(self):
        attachment_values = (b"first", b"second", b"third")
        response = self.client.post(
            "/api/provider-packets",
            headers=self.provider_headers,
            json=self.provider_packet_payload(
                [
                    {
                        "filename": filename,
                        "content_base64": base64.b64encode(value).decode("ascii"),
                        "size_bytes": len(value),
                    }
                    for filename, value in zip(("a?.txt", "a?.txt", "a__2.txt"), attachment_values)
                ]
            ),
        )

        self.assertEqual(response.status_code, 200)
        attachments = response.json()["packet"]["attachments"]
        self.assertEqual(len({attachment["filename"] for attachment in attachments}), 3)
        for attachment, expected in zip(attachments, attachment_values):
            stored_path = self._packet_root / attachment["storage_key"]
            self.assertEqual(stored_path.read_bytes(), expected)

    def test_forged_provider_status_cannot_withdraw_a_claim(self):
        response = self.client.post(
            "/api/provider-events",
            headers=self.provider_headers,
            json={
                "request_id": "DOC-REQ-042",
                "claim_id": "BL-CLAIM-AUTH-042",
                "action": "view_request",
                "status": "withdrawn",
                "outcome": "withdrawn",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["event"]["metadata"]["status"], "needs_packet")
        request = response.json()["workspace"]["requests"][0]
        self.assertEqual(request["status"], "needs_packet")

    def test_attachment_write_failure_rolls_back_staging_and_exchange_state(self):
        first = b"synthetic first attachment"
        second = b"synthetic second attachment"
        original_write_bytes = Path.write_bytes
        write_count = 0

        def fail_second_write(path, data):
            nonlocal write_count
            write_count += 1
            if write_count == 2:
                raise OSError("synthetic attachment write failure")
            return original_write_bytes(path, data)

        with patch.object(Path, "write_bytes", new=fail_second_write):
            with self.assertRaisesRegex(OSError, "synthetic attachment write failure"):
                self.client.post(
                    "/api/provider-packets",
                    headers=self.provider_headers,
                    json=self.provider_packet_payload(
                        [
                            {
                                "filename": "first.txt",
                                "content_base64": base64.b64encode(first).decode("ascii"),
                                "size_bytes": len(first),
                            },
                            {
                                "filename": "second.txt",
                                "content_base64": base64.b64encode(second).decode("ascii"),
                                "size_bytes": len(second),
                            },
                        ]
                    ),
                )

        self.assertFalse(any(path.is_file() for path in self._packet_root.rglob("*")) if self._packet_root.exists() else False)
        workspace = self.client.get("/api/provider-workspace", headers=self.provider_headers).json()
        self.assertEqual(workspace["packets"], [])
        self.assertEqual(workspace["requests"][0]["status"], "needs_packet")

    def test_identifiers_advance_past_persisted_gaps(self):
        persisted = {
            "audit_log": [{"id": "audit-000001"}, {"id": "audit-000003"}],
            "provider_audit_log": [{"id": "audit-000001"}, {"id": "audit-000003"}],
            "provider_requests": operator_portal._default_provider_requests(),
            "provider_packets": [
                {"packet_id": "PROV-PACKET-000001", "receipt_id": "DOC-REC-000001", "request_id": "DOC-REQ-042", "claim_id": "BL-CLAIM-AUTH-042"},
                {"packet_id": "PROV-PACKET-000003", "receipt_id": "DOC-REC-000003", "request_id": "DOC-REQ-042", "claim_id": "BL-CLAIM-AUTH-042"},
            ],
            "provider_messages": [
                {"message_id": "PROV-MSG-000001", "request_id": "DOC-REQ-042", "claim_id": "BL-CLAIM-AUTH-042"},
                {"message_id": "PROV-MSG-000003", "request_id": "DOC-REQ-042", "claim_id": "BL-CLAIM-AUTH-042"},
            ],
            "operator_claim_states": {},
        }
        self._state_path.write_text(json.dumps(persisted), encoding="utf-8")
        client = TestClient(create_app())
        packet = client.post("/api/provider-packets", headers=self.provider_headers, json=self.provider_packet_payload())
        message = client.post(
            "/api/provider-messages",
            headers=self.provider_headers,
            json={"request_id": "DOC-REQ-042", "claim_id": "BL-CLAIM-AUTH-042", "message": "Synthetic question"},
        )
        client.close()

        self.assertEqual(packet.status_code, 200)
        self.assertEqual(packet.json()["packet"]["packet_id"], "PROV-PACKET-000004")
        self.assertEqual(packet.json()["packet"]["receipt_id"], "DOC-REC-000004")
        self.assertEqual(packet.json()["event"]["id"], "audit-000004")
        self.assertEqual(message.status_code, 200)
        self.assertEqual(message.json()["message"]["message_id"], "PROV-MSG-000004")

    def test_concurrent_messages_have_unique_ids_and_valid_persisted_state(self):
        barrier = threading.Barrier(2)
        original_next_message_id = operator_portal._next_message_id

        def synchronized_next_message_id(messages, prefix):
            try:
                barrier.wait(timeout=0.25)
            except threading.BrokenBarrierError:
                pass
            return original_next_message_id(messages, prefix)

        def send_message(index):
            return self.client.post(
                "/api/provider-messages",
                headers=self.provider_headers,
                json={
                    "request_id": "DOC-REQ-042",
                    "claim_id": "BL-CLAIM-AUTH-042",
                    "message": f"Synthetic concurrent message {index}",
                },
            )

        with patch.object(operator_portal, "_next_message_id", new=synchronized_next_message_id):
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                responses = list(executor.map(send_message, (1, 2)))

        self.assertEqual([response.status_code for response in responses], [200, 200])
        message_ids = [response.json()["message"]["message_id"] for response in responses]
        self.assertEqual(len(set(message_ids)), 2)
        persisted = json.loads(self._state_path.read_text(encoding="utf-8"))
        self.assertEqual(len(persisted["provider_messages"]), 2)
        self.assertEqual(len({item["message_id"] for item in persisted["provider_messages"]}), 2)
        self.assertEqual(list(self._state_path.parent.glob(f".{self._state_path.name}.*.tmp")), [])

    def test_browser_waits_for_server_and_offers_no_unverified_release(self):
        source = (operator_portal.APP_ROOT / "operator_portal" / "app.js").read_text(encoding="utf-8")
        transition_source = source.split("function transitionClaim", 1)[1].split("function prepareRequest", 1)[0]

        self.assertIn('ready_for_release: ["reopen_review", "route_clinical"]', source)
        self.assertNotIn('data-action="release_payment"', source)
        self.assertIn('SERVER_BLOCKED_ACTIONS = new Set(["release_payment"])', source)
        self.assertNotIn("Object.assign(claim", transition_source)
        self.assertIn("return recordOperatorAuditEvent", transition_source)
        self.assertIn("No local claim state was changed", transition_source)

    def test_provider_portal_serves_packet_desk_with_provider_only_events(self):
        page = self.client.get("/provider")
        self.assertEqual(page.status_code, 200)
        self.assertIn("Provider Packet Desk", page.text)
        self.assertIn("Packet queue", page.text)
        self.assertIn("Action needed", page.text)
        self.assertIn("Corrections", page.text)
        self.assertIn("Submitted", page.text)
        self.assertIn("Accepted", page.text)
        self.assertIn("Closed", page.text)
        self.assertNotIn("Medi-Cal Claims Inbox", page.text)
        self.assertNotIn("Batch Evidence", page.text)

        asset = self.client.get("/provider-static/styles.css")
        self.assertEqual(asset.status_code, 200)
        self.assertIn("/shared-static/foundation.css", asset.text)
        shared_asset = self.client.get("/shared-static/foundation.css")
        self.assertEqual(shared_asset.status_code, 200)
        self.assertIn("Source Serif 4", shared_asset.text)

        no_auth = self.client.get("/api/provider-workspace")
        self.assertEqual(no_auth.status_code, 401)

        workspace = self.client.get("/api/provider-workspace", headers=self.provider_headers)
        self.assertEqual(workspace.status_code, 200)
        self.assertEqual(workspace.json()["provider"]["principal"], "provider@example.org")
        self.assertEqual(len(workspace.json()["requests"]), 1)
        self.assertEqual(workspace.json()["requests"][0]["request_id"], "DOC-REQ-042")

        event_response = self.client.post(
            "/api/provider-events",
            headers=self.provider_headers,
            json={
                "request_id": "DOC-REQ-042",
                "claim_id": "BL-CLAIM-AUTH-042",
                "action": "submit_packet",
                "status": "submitted",
                "description": "Provider packet submitted.",
                "outcome": "submitted",
            },
        )
        self.assertEqual(event_response.status_code, 200)
        event = event_response.json()["event"]
        self.assertEqual(event["event_type"], "provider_portal_action")
        self.assertEqual(event["actor"], "provider@example.org")
        self.assertEqual(event["metadata"]["source"], "provider_packet_desk")
        self.assertEqual(event_response.json()["workspace"]["audit_log"][0]["id"], event["id"])

        operator_request = self.client.post(
            "/api/operator-events",
            headers=self.operator_headers,
            json={
                "claim_id": "BL-CLAIM-AUTH-144",
                "action": "prepare_request",
                "status": "documentation_requested",
                "payment_state": "Held",
                "description": "Documentation request sent to provider.",
                "outcome": "Documentation request sent",
                "metadata": {
                    "request_id": "DOC-REQ-144",
                    "message": "Please send PA number, effective dates, and T1019 match.",
                    "required_items": ["PA number", "Effective dates", "T1019 match"],
                    "provider": "East Bay Home Care",
                    "provider_npi": "1666666650",
                    "procedure_code": "T1019",
                    "service_date": "Jun 9, 2026",
                    "amount_cents": 70500,
                },
            },
        )
        self.assertEqual(operator_request.status_code, 200)
        self.assertEqual(operator_request.json()["provider_event"]["event_type"], "payer_document_request_sent")
        primary_workspace = self.client.get("/api/provider-workspace", headers=self.provider_headers).json()
        self.assertFalse(any(item["request_id"] == "DOC-REQ-144" for item in primary_workspace["requests"]))
        bridged_workspace = self.client.get("/api/provider-workspace", headers=self.east_bay_provider_headers).json()
        bridged_request = next(item for item in bridged_workspace["requests"] if item["request_id"] == "DOC-REQ-144")
        self.assertEqual(bridged_request["claim_id"], "BL-CLAIM-AUTH-144")
        self.assertEqual(bridged_request["procedure_code"], "T1019")
        self.assertIn("T1019 match", bridged_request["required_items"])
        self.assertEqual(bridged_workspace["messages"][0]["direction"], "payer_to_provider")
        self.assertEqual(bridged_workspace["audit_log"][0]["event_type"], "payer_document_request_sent")

        packet_bytes = b"Signed PA packet for BL-CLAIM-AUTH-042"
        packet_response = self.client.post(
            "/api/provider-packets",
            headers=self.provider_headers,
            json={
                "request_id": "DOC-REQ-042",
                "claim_id": "BL-CLAIM-AUTH-042",
                "action": "submit_packet",
                "pa_number": "PA-T1019-2026-042",
                "effective_from": "2026-06-01",
                "effective_through": "2026-06-30",
                "date_covers": True,
                "procedure_match": True,
                "signed_document": True,
                "attachments": [
                    {
                        "filename": "signed-pa.txt",
                        "content_base64": base64.b64encode(packet_bytes).decode("ascii"),
                        "mime_type": "text/plain",
                        "size_bytes": len(packet_bytes),
                    }
                ],
            },
        )
        self.assertEqual(packet_response.status_code, 200)
        packet_payload = packet_response.json()
        packet = packet_payload["packet"]
        attachment = packet["attachments"][0]
        self.assertEqual(packet["receipt_id"], "DOC-REC-000001")
        self.assertEqual(attachment["filename"], "signed-pa.txt")
        self.assertEqual(attachment["size_bytes"], len(packet_bytes))
        self.assertEqual(attachment["sha256"], hashlib.sha256(packet_bytes).hexdigest())
        self.assertEqual(packet_payload["event"]["event_type"], "provider_packet_submitted")
        self.assertEqual(packet_payload["payer_event"]["event_type"], "provider_packet_received")
        stored_path = operator_portal.PROVIDER_PACKET_STORAGE_ROOT / attachment["storage_key"]
        self.assertTrue(stored_path.exists())
        self.assertEqual(stored_path.read_bytes(), packet_bytes)
        self.assertEqual(packet_payload["workspace"]["packets"][0]["packet_id"], packet["packet_id"])
        workspace_after_packet = self.client.get("/api/provider-workspace", headers=self.provider_headers).json()
        request_after_packet = next(item for item in workspace_after_packet["requests"] if item["request_id"] == "DOC-REQ-042")
        self.assertEqual(request_after_packet["status"], "submitted")
        self.assertEqual(request_after_packet["packet_id"], packet["packet_id"])

        cross_tenant_response = self.client.post(
            "/api/provider-events",
            headers=self.provider_headers,
            json={
                "request_id": "DOC-REQ-144",
                "claim_id": "BL-CLAIM-AUTH-144",
                "action": "withdraw_claim",
                "status": "withdrawn",
            },
        )
        self.assertEqual(cross_tenant_response.status_code, 403)

        download_response = self.client.get(
            f"/api/provider-packets/{packet['packet_id']}/attachments/{attachment['filename']}",
            headers=self.operator_headers,
        )
        self.assertEqual(download_response.status_code, 200)
        self.assertEqual(download_response.content, packet_bytes)

        provider_download_response = self.client.get(
            f"/api/provider-packets/{packet['packet_id']}/attachments/{attachment['filename']}",
            headers=self.provider_headers,
        )
        self.assertEqual(provider_download_response.status_code, 403)

        message_response = self.client.post(
            "/api/provider-messages",
            headers=self.provider_headers,
            json={
                "request_id": "DOC-REQ-042",
                "claim_id": "BL-CLAIM-AUTH-042",
                "message": "Can you confirm whether the June authorization window is enough?",
            },
        )
        self.assertEqual(message_response.status_code, 200)
        message_payload = message_response.json()
        self.assertEqual(message_payload["message"]["message_id"], "PROV-MSG-000001")
        self.assertEqual(message_payload["event"]["event_type"], "provider_message_sent")
        self.assertEqual(message_payload["payer_event"]["event_type"], "provider_message_received")
        self.assertEqual(message_payload["workspace"]["messages"][0]["message_id"], "PROV-MSG-000001")

        withdraw_response = self.client.post(
            "/api/provider-events",
            headers=self.east_bay_provider_headers,
            json={
                "request_id": "DOC-REQ-144",
                "claim_id": "BL-CLAIM-AUTH-144",
                "action": "withdraw_claim",
                "status": "withdrawn",
                "description": "Claim withdrawn by provider after duplicate discovery.",
                "outcome": "withdrawn",
            },
        )
        self.assertEqual(withdraw_response.status_code, 200)
        self.assertEqual(withdraw_response.json()["payer_event"]["event_type"], "provider_claim_withdrawn")
        workspace_after_withdraw = self.client.get("/api/provider-workspace", headers=self.east_bay_provider_headers).json()
        withdrawn_request = next(item for item in workspace_after_withdraw["requests"] if item["request_id"] == "DOC-REQ-144")
        self.assertEqual(withdrawn_request["status"], "withdrawn")

        operator_audit_log = self.client.get("/api/audit-log", headers=self.operator_headers).json()["events"]
        self.assertTrue(any(event["event_type"] == "provider_packet_received" for event in operator_audit_log))
        self.assertTrue(any(event["event_type"] == "provider_message_received" for event in operator_audit_log))
        self.assertTrue(any(event["event_type"] == "provider_claim_withdrawn" for event in operator_audit_log))

        persisted_client = TestClient(create_app())
        persisted_workspace = persisted_client.get("/api/provider-workspace", headers=self.provider_headers).json()
        self.assertTrue(any(item["packet_id"] == packet["packet_id"] for item in persisted_workspace["packets"]))
        persisted_audit_log = persisted_client.get("/api/audit-log", headers=self.operator_headers).json()["events"]
        self.assertTrue(any(event["event_type"] == "provider_packet_received" for event in persisted_audit_log))

        provider_on_operator_api = self.client.get("/api/workspace", headers=self.provider_headers)
        self.assertEqual(provider_on_operator_api.status_code, 403)

        operator_on_provider_api = self.client.get("/api/provider-workspace", headers=self.operator_headers)
        self.assertEqual(operator_on_provider_api.status_code, 403)

    def test_bad_file_routes_to_review_with_plain_language_reason(self):
        response = self.client.post(
            "/api/batches",
            headers=self.operator_headers,
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

    def test_read_endpoints_require_authentication_and_accept_principal(self):
        for path in ("/api/batches", "/api/review-items", "/api/audit-log", "/api/workspace"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 401, path)

        for path in ("/api/batches", "/api/review-items", "/api/audit-log", "/api/workspace"):
            response = self.client.get(path, headers=self.auditor_headers)
            self.assertEqual(response.status_code, 200, path)

    def test_unauthorized_principal_is_rejected(self):
        sample = self.client.get("/api/sample-claim").json()
        response = self.client.post(
            "/api/batches",
            headers={
                "Authorization": "Bearer local-auditor-portal-token",
                "X-BL-Principal": "operator@example.gov",
            },
            json={
                "actor": "operator@example.gov",
                "claims": [sample],
                "strict_oracle_attestations": True,
                "enforce_nullifier_proofs": True,
            },
        )

        self.assertEqual(response.status_code, 403)

    def test_forged_actor_body_is_ignored_in_favor_of_authenticated_principal(self):
        original_sample_claim = operator_portal._sample_claim

        def signed_sample_claim(*args, **kwargs):
            claim = original_sample_claim(*args, **kwargs)
            claim["edi"] = claim["edi"].replace("SV1*HC:99213", "SV1*HC:T1019").replace("~REF*G1*PA-OK-123", "")
            claim["edi"] = claim["edi"].replace("BL-CLAIM-0001", "BL-FORGED-ACTOR-REVIEW")
            claim["claim_id"] = "BL-FORGED-ACTOR-REVIEW"
            try:
                return _attach_signed_attestations(claim)
            except ValueError:
                return claim

        with patch("app.operator_portal._sample_claim", side_effect=signed_sample_claim):
            demo = self.client.post(
                "/api/demo-batch",
                headers=self.operator_headers,
                json={"actor": "admin@example.gov"},
            ).json()
        item = demo["review_items"][0]

        no_auth = self.client.post(
            f"/api/review-items/{item['id']}/actions",
            json={"actor": "admin@example.gov", "action_id": item["next_actions"][0]["id"], "note": "forged"},
        )
        self.assertEqual(no_auth.status_code, 401)

        action = self.client.post(
            f"/api/review-items/{item['id']}/actions",
            headers=self.operator_headers,
            json={"actor": "admin@example.gov", "action_id": item["next_actions"][0]["id"], "note": "forged"},
        )
        self.assertEqual(action.status_code, 200)
        updated = action.json()["item"]
        self.assertEqual(updated["assigned_to"], "operator@example.gov")
        self.assertEqual(updated["history"][-1]["actor"], "operator@example.gov")


if __name__ == "__main__":
    unittest.main()
