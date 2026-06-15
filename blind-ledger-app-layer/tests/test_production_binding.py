import copy
import json
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from app.ingestion import parse_837
from app.oracle_attestation import make_test_attestation
from app.production_binding import (
    BINDING_STATUS,
    FeeScheduleRow,
    build_production_binding,
    verify_production_binding,
)
from app.rules_engine_fallback import adjudicate
from app.shared_context import build_shared_context


ROOT = Path(__file__).resolve().parents[1]
ENV = {"BL_DEV": "1", "BL_PROVIDER_ALIAS_KEY": "production-binding-test-key"}


def sample_payload(claim_id="BL-BINDING-0001", transform=None):
    payload = json.loads((ROOT / "sample_claim_input.json").read_text(encoding="utf-8"))
    payload["edi"] = payload["edi"].replace("BL-CLAIM-0001", claim_id)
    if transform:
        payload["edi"] = transform(payload["edi"])
    return payload


def attestations_for(claim_id: str):
    return [
        make_test_attestation("eligibility_active", True, source_id="CA-MMIS", claim_id=claim_id),
        make_test_attestation("provider_enrolled", True, source_id="DHCS-PROVIDER", claim_id=claim_id),
        make_test_attestation("provider_not_suspended", True, source_id="DHCS-SUSPENSION", claim_id=claim_id),
        make_test_attestation("not_deceased", True, source_id="DEATH-MASTER", claim_id=claim_id),
    ]


def fee_rows(max_charge_cents=500000, effective_from="20260101", effective_until="20261231"):
    return [
        FeeScheduleRow(
            procedure_code="99213",
            effective_from=effective_from,
            effective_until=effective_until,
            max_charge_cents=max_charge_cents,
            source_id="MEDI_CAL_FEE_SCHEDULE_TEST",
        )
    ]


def strict_ctx(payload, attestations):
    parsed = parse_837(payload["edi"])
    if not parsed.accepted:
        raise AssertionError(parsed.errors)
    return build_shared_context(parsed, payload["flags"], oracle_attestations=attestations, strict_oracle=True)


def binding_fixture():
    payload = sample_payload()
    attestations = attestations_for("BL-BINDING-0001")
    ctx = strict_ctx(payload, attestations)
    result = adjudicate(ctx)
    bundle = build_production_binding(
        ctx,
        result,
        attestations,
        fee_rows(),
        raw_edi=payload["edi"],
        batch_id="batch-prod-binding-1",
        ruleset_root="ruleset-root-v1",
        nullifier_root_before="11" * 32,
        nullifier_root_after="22" * 32,
        recipient_address="0x1111111111111111111111111111111111111111",
    )
    return payload, attestations, ctx, result, bundle


class ProductionBindingHarnessTests(unittest.TestCase):
    @patch.dict("os.environ", ENV, clear=True)
    def test_binding_accepts_signed_oracle_roots_fee_roots_and_payment_binding(self):
        payload, _, _, _, bundle = binding_fixture()

        self.assertIn("not a compiled ZK circuit", BINDING_STATUS)
        self.assertTrue(verify_production_binding(bundle, raw_edi=payload["edi"]))
        self.assertEqual(bundle.statement.claim_count, 1)
        self.assertEqual(bundle.statement.payment_count, 1)
        self.assertNotEqual(bundle.statement.payment_root, "00" * 32)
        self.assertNotEqual(bundle.witness.payment_record, bundle.witness.payee_record)
        self.assertEqual(bundle.witness.recipient_address, "0x1111111111111111111111111111111111111111")

    @patch.dict("os.environ", ENV, clear=True)
    def test_binding_rejects_missing_oracle_fact_even_if_context_was_previously_clean(self):
        payload, attestations, ctx, result, _ = binding_fixture()
        missing_provider_status = [att for att in attestations if att.fact != "provider_not_suspended"]

        with self.assertRaisesRegex(ValueError, "oracle_fact_missing:provider_not_suspended|oracle_attestation_required:provider_not_suspended"):
            build_production_binding(
                ctx,
                result,
                missing_provider_status,
                fee_rows(),
                raw_edi=payload["edi"],
                batch_id="batch-prod-binding-missing-oracle",
                ruleset_root="ruleset-root-v1",
                nullifier_root_before="11" * 32,
                nullifier_root_after="22" * 32,
                recipient_address="0x1111111111111111111111111111111111111111",
            )

    @patch.dict("os.environ", ENV, clear=True)
    def test_binding_rejects_oracle_value_that_disagrees_with_context_flags(self):
        payload, attestations, ctx, result, _ = binding_fixture()
        tampered = [
            make_test_attestation("eligibility_active", False, source_id="CA-MMIS", claim_id=ctx.claim_id)
            if att.fact == "eligibility_active"
            else att
            for att in attestations
        ]

        with self.assertRaisesRegex(ValueError, "raw_claim_derivation_mismatch|oracle_fact_mismatch:eligibility_active"):
            build_production_binding(
                ctx,
                result,
                tampered,
                fee_rows(),
                raw_edi=payload["edi"],
                batch_id="batch-prod-binding-bad-oracle-value",
                ruleset_root="ruleset-root-v1",
                nullifier_root_before="11" * 32,
                nullifier_root_after="22" * 32,
                recipient_address="0x1111111111111111111111111111111111111111",
            )

    @patch.dict("os.environ", ENV, clear=True)
    def test_binding_rejects_raw_edi_swap_against_same_normalized_context(self):
        payload, _, _, _, bundle = binding_fixture()
        swapped_payload = sample_payload(transform=lambda edi: edi.replace("125.00", "126.00"))

        with self.assertRaisesRegex(ValueError, "raw_claim_derivation_mismatch"):
            verify_production_binding(bundle, raw_edi=swapped_payload["edi"])

    @patch.dict("os.environ", ENV, clear=True)
    def test_binding_rejects_fee_schedule_that_changes_charge_gate(self):
        payload, attestations, ctx, result, _ = binding_fixture()

        with self.assertRaisesRegex(ValueError, "gate_vector_mismatch"):
            build_production_binding(
                ctx,
                result,
                attestations,
                fee_rows(max_charge_cents=1000),
                raw_edi=payload["edi"],
                batch_id="batch-prod-binding-fee-mismatch",
                ruleset_root="ruleset-root-v1",
                nullifier_root_before="11" * 32,
                nullifier_root_after="22" * 32,
                recipient_address="0x1111111111111111111111111111111111111111",
            )

    @patch.dict("os.environ", ENV, clear=True)
    def test_binding_rejects_fee_row_outside_service_date(self):
        payload, attestations, ctx, result, _ = binding_fixture()

        with self.assertRaisesRegex(ValueError, "fee_schedule_missing:99213"):
            build_production_binding(
                ctx,
                result,
                attestations,
                fee_rows(effective_from="20270101", effective_until="20271231"),
                raw_edi=payload["edi"],
                batch_id="batch-prod-binding-fee-date",
                ruleset_root="ruleset-root-v1",
                nullifier_root_before="11" * 32,
                nullifier_root_after="22" * 32,
                recipient_address="0x1111111111111111111111111111111111111111",
            )

    @patch.dict("os.environ", ENV, clear=True)
    def test_binding_rejects_tampered_result_amount(self):
        payload, attestations, ctx, result, _ = binding_fixture()
        tampered = copy.deepcopy(result)
        tampered.payable_amount = result.payable_amount + 1

        with self.assertRaisesRegex(ValueError, "payable_amount_mismatch"):
            build_production_binding(
                ctx,
                tampered,
                attestations,
                fee_rows(),
                raw_edi=payload["edi"],
                batch_id="batch-prod-binding-result-amount",
                ruleset_root="ruleset-root-v1",
                nullifier_root_before="11" * 32,
                nullifier_root_after="22" * 32,
                recipient_address="0x1111111111111111111111111111111111111111",
            )

    @patch.dict("os.environ", ENV, clear=True)
    def test_binding_rejects_public_oracle_root_swap(self):
        payload, _, _, _, bundle = binding_fixture()
        bad_statement = replace(bundle.statement, eligibility_root="00" * 32)
        bad_bundle = replace(bundle, statement=bad_statement)

        with self.assertRaisesRegex(ValueError, "public_statement_mismatch"):
            verify_production_binding(bad_bundle, raw_edi=payload["edi"])

    @patch.dict("os.environ", ENV, clear=True)
    def test_binding_rejects_settlement_recipient_swap(self):
        payload, _, _, _, bundle = binding_fixture()
        bad_witness = replace(bundle.witness, recipient_address="0x2222222222222222222222222222222222222222")
        bad_bundle = replace(bundle, witness=bad_witness)

        with self.assertRaisesRegex(ValueError, "public_statement_mismatch"):
            verify_production_binding(bad_bundle, raw_edi=payload["edi"])

    @patch.dict("os.environ", ENV, clear=True)
    def test_binding_rejects_approved_payment_without_nullifier_advance(self):
        payload, attestations, ctx, result, _ = binding_fixture()

        with self.assertRaisesRegex(ValueError, "approved_payment_requires_nullifier_advance"):
            build_production_binding(
                ctx,
                result,
                attestations,
                fee_rows(),
                raw_edi=payload["edi"],
                batch_id="batch-prod-binding-nullifier",
                ruleset_root="ruleset-root-v1",
                nullifier_root_before="11" * 32,
                nullifier_root_after="11" * 32,
                recipient_address="0x1111111111111111111111111111111111111111",
            )


if __name__ == "__main__":
    unittest.main()
