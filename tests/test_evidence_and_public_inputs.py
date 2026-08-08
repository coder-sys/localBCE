import json
import os
import unittest
from pathlib import Path
from unittest.mock import patch

from app.batch.access_control import OPERATOR, RoleBook
from app.batch.batch_orchestrator import BatchConfig, LocalBatchRecorder, _claim_source_commitment_for_oracle, submit_batches
from app.batch.encrypted_da import (
    AUDIT_DATA_ENCRYPTION_KEY_ENV,
    decrypt_claim_data,
    encrypted_claim_data_root,
    generate_audit_key_b64,
)
from app.batch.leaf import current_duplicate_pepper
from app.batch.poseidon import FIELD_MODULUS
from app.fact_resolver import resolve_claim_facts
from app.ingestion import parse_837
from app.ingestion_boundary import PROTOTYPE_X12_BOUNDARY, Prototype837Ingestion
from app.oracle_attestation import make_test_attestation
from app.public_inputs import PUBLIC_INPUT_FIELD_NAMES_V2, build_native_stark_public_inputs
from app.shared_context import build_shared_context


APP_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = APP_ROOT
DECISION_FACTS = (
    "eligibility_active",
    "provider_enrolled",
    "provider_not_suspended",
    "not_deceased",
    "duplicate_claim",
    "program_integrity_hold",
)


def sample_payload(claim_id="BL-EVIDENCE-0001"):
    payload = json.loads((APP_ROOT / "sample_claim_input.json").read_text(encoding="utf-8"))
    payload["edi"] = payload["edi"].replace("BL-CLAIM-0001", claim_id)
    parsed = parse_837(payload["edi"])
    if not parsed.accepted:
        raise AssertionError(parsed.errors)
    config = BatchConfig()
    ctx = build_shared_context(parsed, payload["flags"], strict_oracle=False)
    claim_source_commitment = _claim_source_commitment_for_oracle(
        ctx,
        config=config,
        frequency_type="original",
        duplicate_pepper=current_duplicate_pepper(),
    )
    payload["oracle_attestations"] = [
        make_test_attestation(
            fact,
            bool(payload["flags"][fact]),
            source_id=f"TEST-{fact}",
            claim_id=claim_id,
            claim_source_commitment=claim_source_commitment,
        )
        for fact in DECISION_FACTS
    ]
    return payload


def role_book():
    roles = RoleBook()
    roles.grant(OPERATOR, "operator@example.gov")
    return roles


class EvidenceAndPublicInputTests(unittest.TestCase):
    def test_fact_resolver_builds_first_class_evidence_packet(self):
        payload = sample_payload()
        parsed = parse_837(payload["edi"])
        ctx = build_shared_context(parsed, payload["flags"], strict_oracle=False)
        resolved = resolve_claim_facts(ctx, flags=payload["flags"])

        self.assertEqual(resolved.flags["eligibility_active"], True)
        self.assertEqual(resolved.flags["provider_enrolled"], True)
        self.assertEqual(resolved.flags["provider_not_suspended"], True)
        self.assertEqual(resolved.flags["not_deceased"], True)
        self.assertRegex(resolved.evidence_packet.evidence_root, r"^[0-9a-f]{64}$")
        fields = resolved.evidence_packet.to_dict()["items"][0].keys()
        for required in (
            "fact_name",
            "fact_value",
            "source_system",
            "source_record_id",
            "source_type",
            "fetched_at",
            "valid_from",
            "valid_until",
            "service_date_coverage",
            "hash",
            "attestation",
            "verification_status",
            "reason_if_missing",
        ):
            self.assertIn(required, fields)

    def test_adverse_document_fact_is_not_dropped_as_missing(self):
        payload = sample_payload("BL-EVIDENCE-HOLD")
        payload["flags"]["program_integrity_hold"] = True
        parsed = parse_837(payload["edi"])
        ctx = build_shared_context(parsed, payload["flags"], strict_oracle=False)
        resolved = resolve_claim_facts(ctx, flags=payload["flags"])

        self.assertEqual(resolved.flags["program_integrity_hold"], True)
        self.assertNotIn("program_integrity_hold", resolved.evidence_packet.missing_reasons())

    def test_submitted_batch_carries_evidence_root_and_packet(self):
        batch = submit_batches(
            [sample_payload("BL-EVIDENCE-BATCH")],
            actor="operator@example.gov",
            access=role_book(),
            config=BatchConfig(enforce_nullifier_proofs=False),
            recorder=LocalBatchRecorder(),
        )[0]

        self.assertRegex(batch.claim_packets[0].evidence_root, r"^[0-9a-f]{64}$")
        self.assertEqual(batch.claim_packets[0].evidence_root, batch.claim_packets[0].evidence_packet["evidence_root"])
        self.assertIn(batch.claim_packets[0].evidence_root, batch.claim_packets[0].evidence_packet["evidence_root"])

    def test_aes_gcm_batch_emits_contract_ready_field_safe_payload(self):
        key = generate_audit_key_b64()
        with patch.dict(os.environ, {AUDIT_DATA_ENCRYPTION_KEY_ENV: key}, clear=False):
            batch = submit_batches(
                [sample_payload("BL-ENCRYPTED-DA")],
                actor="operator@example.gov",
                access=role_book(),
                config=BatchConfig(
                    enforce_nullifier_proofs=False,
                    encrypted_claim_data_mode="aes_gcm",
                    audit_data_key_epoch="epoch-2026-07",
                ),
                recorder=LocalBatchRecorder(),
            )[0]

        self.assertTrue(batch.encrypted_claim_payload)
        bundle = json.loads(batch.encrypted_claim_payload.decode("utf-8"))
        self.assertEqual(encrypted_claim_data_root(bundle), batch.encrypted_claim_data_root)
        self.assertLess(int(batch.encrypted_claim_data_root, 16), FIELD_MODULUS)
        self.assertEqual(batch.public_inputs[14], batch.encrypted_claim_data_root)
        plaintext = decrypt_claim_data(bundle, key_b64=key)
        self.assertEqual(plaintext["batch_id"], batch.batch_id)
        self.assertEqual(plaintext["data_availability_root"], batch.data_availability_root)
        self.assertEqual(plaintext["claims"][0]["claim_id"], "BL-ENCRYPTED-DA")
        self.assertIn("BL-ENCRYPTED-DA", plaintext["claims"][0]["raw_edi"])

    def test_v2_manifest_matches_direct_state_boundary(self):
        manifest = json.loads(
            (REPO_ROOT / "ops" / "native_stark_public_inputs_v2.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            tuple(field["name"] for field in manifest["fields"]),
            PUBLIC_INPUT_FIELD_NAMES_V2,
        )
        self.assertIn("atomic database transition", manifest["statement"])

    def test_batch_public_inputs_are_exactly_21_contract_ready_values(self):
        batch = submit_batches(
            [sample_payload("BL-PUBLIC-INPUTS")],
            actor="operator@example.gov",
            access=role_book(),
            config=BatchConfig(enforce_nullifier_proofs=False),
            recorder=LocalBatchRecorder(),
        )[0]

        self.assertEqual(batch.public_inputs, build_native_stark_public_inputs(batch))
        self.assertEqual(len(batch.public_inputs), 21)
        for value in batch.public_inputs:
            self.assertRegex(value, r"^[0-9a-f]{64}$")
        self.assertEqual(batch.public_inputs[19], f"{batch.approved_amount_cents:064x}")
        self.assertEqual(batch.public_inputs[20], f"{batch.payment_amount_cents:064x}")

    def test_x12_ingestion_is_isolated_behind_prototype_boundary(self):
        ingestion = Prototype837Ingestion()
        parsed = ingestion.parse(sample_payload("BL-INGESTION-BOUNDARY")["edi"])

        self.assertTrue(parsed.accepted)
        self.assertEqual(ingestion.boundary_status, PROTOTYPE_X12_BOUNDARY)


if __name__ == "__main__":
    unittest.main()
