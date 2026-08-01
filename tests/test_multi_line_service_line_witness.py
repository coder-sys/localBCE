import json
import os
import unittest
from dataclasses import replace
from pathlib import Path

from app.batch.batch_orchestrator import BatchConfig, adjudicate_for_batch
from app.batch.stark_binding import build_multi_line_service_line_witness, validate_multi_line_claim_witness
from app.batch.tar_required import is_tar_required
from app.fact_resolver import resolve_claim_facts
from app.ingestion import parse_837
from app.models import Patient, Provider, ServiceLine, SharedContext
from app.service_line_canonical import canonical_service_line_identities
from app.shared_context import build_shared_context


ROOT = Path(__file__).resolve().parents[1]


def approved_claim_context():
    os.environ.setdefault("BL_DEV", "1")
    os.environ.setdefault("BL_FORCE_PYTHON_RULES_ENGINE", "1")
    payload = json.loads((ROOT / "sample_claim_input.json").read_text(encoding="utf-8"))
    parsed = parse_837(payload["edi"])
    if not parsed.accepted:
        raise AssertionError(parsed.errors)
    config = BatchConfig()
    ctx = build_shared_context(parsed, payload["flags"], strict_oracle=False)
    resolved = resolve_claim_facts(ctx, flags=payload["flags"], fee_schedule_cents=config.fee_schedule_cents)
    ctx = replace(
        ctx,
        flags=resolved.flags,
        fact_verification={**ctx.fact_verification, **resolved.fact_verification},
    )
    result, engine_mode = adjudicate_for_batch(ctx)
    if not result.approved:
        raise AssertionError(result.denial_reason)
    return ctx, result, resolved.evidence_packet.evidence_root, config, engine_mode


def claim_context_with_lines(service_lines: list[ServiceLine], total_charge: float | None = None) -> SharedContext:
    os.environ.setdefault("BL_DEV", "1")
    if total_charge is None:
        total_charge = round(sum(float(line.charge_amount) for line in service_lines), 2)
    required_tar_lines = [line for line in service_lines if is_tar_required(line.procedure_code)]
    tar_verified = bool(required_tar_lines) and all(line.prior_authorization for line in required_tar_lines)
    return SharedContext(
        claim_id="BL-MULTI-LINE-REF",
        transaction_set="837",
        payer_id="CA-MMIS",
        member_id="M123456789",
        patient=Patient(name="DOE JANE", id="M123456789"),
        provider=Provider(npi="1999999984", name="ADAMS ALICE"),
        service_date="20260601",
        diagnoses=["F840"],
        service_lines=service_lines,
        total_charge=total_charge,
        flags={
            "eligibility_active": True,
            "provider_enrolled": True,
            "provider_not_suspended": True,
            "not_deceased": True,
            "duplicate_claim": False,
            "program_integrity_hold": False,
        },
        fact_verification={"tar_authorization": "VERIFIED" if tar_verified else "UNVERIFIED"},
    )


class MultiLineServiceLineWitnessTests(unittest.TestCase):
    def test_single_line_multi_line_producer_uses_canonical_final_shape(self):
        ctx, result, evidence_root, config, engine_mode = approved_claim_context()
        _ = result, evidence_root, engine_mode
        multi = build_multi_line_service_line_witness(ctx, config=config)

        self.assertEqual(len(multi.service_lines), 1)
        line = multi.service_lines[0]
        inserted_nullifier = (multi.nullifier.inserted_nullifier_high << 128) + multi.nullifier.inserted_nullifier_low

        self.assertEqual(multi.claim.attempt_nullifier, inserted_nullifier)
        self.assertNotEqual(multi.nullifier.live_root_before, multi.nullifier.root_after)
        self.assertNotEqual(multi.policy_root, 0)
        self.assertNotEqual(multi.oracle_facts_root, 0)
        self.assertEqual(multi.sum_line_charge_cents, 12500)
        self.assertEqual(multi.allowed_total_cents, 12500)
        self.assertFalse(multi.requires_any_tar)

        self.assertEqual(line.procedure_code, "99213")
        policy_row = multi.policy_rows[line.policy_row_index]
        self.assertEqual(line.procedure_code_felt, policy_row.procedure_code_felt)
        self.assertFalse(policy_row.requires_tar)
        self.assertEqual(line.line_charge_cents, 12500)
        self.assertEqual(line.allowed_cents, 12500)
        self.assertFalse(line.tar_required)

    def test_two_line_claim_produces_one_witness_per_canonical_line(self):
        ctx = claim_context_with_lines(
            [
                ServiceLine("1", "T1019", 125.00, 1.0, None),
                ServiceLine("2", "99213", 125.00, 1.0, None),
            ]
        )
        witness = build_multi_line_service_line_witness(ctx, config=BatchConfig())

        self.assertEqual(len(witness.service_lines), 2)
        self.assertEqual(
            [line.procedure_code for line in witness.service_lines],
            [identity[0] for identity in canonical_service_line_identities(ctx.service_lines)],
        )
        self.assertEqual([line.procedure_code for line in witness.service_lines], ["99213", "T1019"])
        self.assertTrue(witness.requires_any_tar)
        self.assertEqual(witness.sum_line_charge_cents, 25000)
        self.assertEqual(witness.allowed_total_cents, 25000)

    def test_duplicate_identical_lines_are_preserved_as_two_entries(self):
        ctx = claim_context_with_lines(
            [
                ServiceLine("1", "99213", 125.00, 1.0, None),
                ServiceLine("2", "99213", 125.00, 1.0, None),
            ]
        )
        witness = build_multi_line_service_line_witness(ctx, config=BatchConfig())

        self.assertEqual(len(witness.service_lines), 2)
        self.assertEqual([line.procedure_code for line in witness.service_lines], ["99213", "99213"])
        self.assertEqual(witness.service_lines[0].fee_leaf, witness.service_lines[1].fee_leaf)
        self.assertEqual(witness.sum_line_charge_cents, 25000)
        self.assertEqual(witness.allowed_total_cents, 25000)

    def test_signed_prior_auth_commitment_mismatch_rejected_by_witness_validator(self):
        ctx = claim_context_with_lines([ServiceLine("1", "T1019", 125.00, 1.0, "PA-OK")])
        witness = build_multi_line_service_line_witness(ctx, config=BatchConfig())
        line = witness.service_lines[0]
        authorizations = list(witness.authorizations)
        authorizations[line.authorization_index] = replace(
            authorizations[line.authorization_index],
            signed_tar_authorization_commitment=authorizations[line.authorization_index].signed_tar_authorization_commitment + 1,
        )
        forged = replace(witness, authorizations=tuple(authorizations))

        with self.assertRaisesRegex(ValueError, "multi_line_auth_signed_authorization_mismatch"):
            validate_multi_line_claim_witness(forged)

    def test_authorization_text_must_match_its_service_line(self):
        ctx = claim_context_with_lines([ServiceLine("1", "T1019", 125.00, 1.0, "PA-OK")])
        witness = build_multi_line_service_line_witness(ctx, config=BatchConfig())
        forged_authorization = replace(witness.authorizations[0], prior_authorization="PA-FORGED")
        forged = replace(witness, authorizations=(forged_authorization,))

        with self.assertRaisesRegex(ValueError, "multi_line_auth_prior_authorization_mismatch"):
            validate_multi_line_claim_witness(forged)

    def test_reordered_input_lines_have_same_canonical_order_and_totals(self):
        first = claim_context_with_lines(
            [
                ServiceLine("1", "T1019", 125.00, 1.0, None),
                ServiceLine("2", "99213", 100.00, 1.0, None),
            ]
        )
        second = claim_context_with_lines(
            [
                ServiceLine("1", "99213", 100.00, 1.0, None),
                ServiceLine("2", "T1019", 125.00, 1.0, None),
            ]
        )

        first_witness = build_multi_line_service_line_witness(first, config=BatchConfig())
        second_witness = build_multi_line_service_line_witness(second, config=BatchConfig())

        self.assertEqual(
            [(line.procedure_code, line.line_charge_cents, line.units_cents) for line in first_witness.service_lines],
            [(line.procedure_code, line.line_charge_cents, line.units_cents) for line in second_witness.service_lines],
        )
        self.assertEqual(first_witness.sum_line_charge_cents, second_witness.sum_line_charge_cents)
        self.assertEqual(first_witness.allowed_total_cents, second_witness.allowed_total_cents)

    def test_sum_line_charge_must_match_claim_total(self):
        ctx = claim_context_with_lines(
            [
                ServiceLine("1", "99213", 125.00, 1.0, None),
                ServiceLine("2", "T1019", 125.00, 1.0, None),
            ],
            total_charge=249.00,
        )

        with self.assertRaisesRegex(ValueError, "multi_line_total_charge_mismatch"):
            build_multi_line_service_line_witness(ctx, config=BatchConfig())

    def test_service_line_capacity_rejects_51_and_accepts_50(self):
        fifty = claim_context_with_lines(
            [ServiceLine(str(index), "99213", 1.00, 1.0, None) for index in range(1, 51)]
        )
        fifty_one = claim_context_with_lines(
            [ServiceLine(str(index), "99213", 1.00, 1.0, None) for index in range(1, 52)]
        )

        accepted = build_multi_line_service_line_witness(fifty, config=BatchConfig())
        self.assertEqual(len(accepted.service_lines), 50)
        self.assertEqual(accepted.sum_line_charge_cents, 5000)

        with self.assertRaisesRegex(ValueError, "multi_line_service_line_count_out_of_range"):
            build_multi_line_service_line_witness(fifty_one, config=BatchConfig())


if __name__ == "__main__":
    unittest.main()
