import unittest
import os
from dataclasses import replace

from app.batch.batch_orchestrator import BatchConfig, _validate_batch_config, adjudicate_for_batch, fee_row_leaf
from app.batch.poseidon import FIELD_MODULUS
from app.batch.stark_encoding import pack_felt_text
from app.batch.tar_required import is_tar_required
from app.batch.stark_binding import (
    MULTI_LINE_CLAIM_WITNESS_SCHEMA,
    build_multi_line_service_line_witness,
    claim_output_for_multi_line_witness,
    flatten_multi_line_claim_witness,
    validate_multi_line_claim_witness,
)
from app.models import Patient, Provider, ServiceLine, SharedContext


def claim_context_with_lines(service_lines: list[ServiceLine], total_charge: float | None = None) -> SharedContext:
    os.environ.setdefault("BL_DEV", "1")
    if total_charge is None:
        total_charge = round(sum(float(line.charge_amount) for line in service_lines), 2)
    required_tar_lines = [line for line in service_lines if is_tar_required(line.procedure_code)]
    tar_verified = bool(required_tar_lines) and all(line.prior_authorization for line in required_tar_lines)
    return SharedContext(
        claim_id="BL-MULTI-LINE-VALIDATION",
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


def valid_two_line_bundle(*, charge: float = 125.00):
    ctx = claim_context_with_lines(
        [
            ServiceLine("1", "T1019", charge, 1.0, None),
            ServiceLine("2", "99213", charge, 1.0, None),
        ]
    )
    return build_multi_line_service_line_witness(ctx, config=BatchConfig())


def serialized_line_count_index(bundle) -> int:
    index = 1
    index += 17 + (1 + len(bundle.claim.claim_source_path_elements))
    index += 3 + (1 + len(bundle.claim_facts_path_elements))
    index += 3
    index += 9
    index += 3
    return index


def expected_serialized_length(bundle) -> int:
    return len(flatten_multi_line_claim_witness(bundle))


def bump_felt(value: int) -> int:
    return (int(value) + 1) % FIELD_MODULUS


class MultiLineWitnessValidationTests(unittest.TestCase):
    def test_valid_one_line_bundle_flattens_and_validates(self):
        ctx = claim_context_with_lines([ServiceLine("1", "99213", 125.00, 1.0, None)])
        bundle = build_multi_line_service_line_witness(ctx, config=BatchConfig())
        serialized = flatten_multi_line_claim_witness(bundle)

        self.assertEqual(MULTI_LINE_CLAIM_WITNESS_SCHEMA, "BL_MULTI_LINE_CLAIM_WITNESS_V3")
        self.assertEqual(serialized[serialized_line_count_index(bundle)], 1)
        self.assertEqual(len(serialized), expected_serialized_length(bundle))
        self.assertTrue(validate_multi_line_claim_witness(bundle, serialized_arguments=serialized))

    def test_valid_two_line_bundle_flattens_and_validates(self):
        bundle = valid_two_line_bundle()
        serialized = flatten_multi_line_claim_witness(bundle)

        self.assertEqual([line.procedure_code for line in bundle.service_lines], ["99213", "T1019"])
        self.assertEqual(serialized[serialized_line_count_index(bundle)], 2)
        self.assertEqual(len(serialized), expected_serialized_length(bundle))
        self.assertTrue(validate_multi_line_claim_witness(bundle, serialized_arguments=serialized))

    def test_declared_line_count_mismatch_rejected(self):
        bundle = valid_two_line_bundle()
        serialized = flatten_multi_line_claim_witness(bundle)
        serialized[serialized_line_count_index(bundle)] = 3

        with self.assertRaisesRegex(ValueError, "multi_line_serialized_arguments_mismatch"):
            validate_multi_line_claim_witness(bundle, serialized_arguments=serialized)

    def test_swapped_lines_out_of_canonical_order_rejected(self):
        bundle = valid_two_line_bundle()
        swapped = replace(bundle, service_lines=tuple(reversed(bundle.service_lines)))

        with self.assertRaisesRegex(ValueError, "multi_line_service_lines_not_canonical"):
            validate_multi_line_claim_witness(swapped)

    def test_dropped_line_with_claimed_sum_rejected(self):
        bundle = valid_two_line_bundle()
        dropped = replace(bundle, service_lines=bundle.service_lines[:1])

        with self.assertRaisesRegex(ValueError, "multi_line_claim_service_lines_mismatch"):
            validate_multi_line_claim_witness(dropped)

    def test_substituted_fee_leaf_for_different_procedure_is_not_serialized(self):
        bundle = valid_two_line_bundle()
        line = bundle.service_lines[0]
        forged_line = replace(line, fee_leaf=fee_row_leaf("T1019", line.allowed_cents))
        forged = replace(bundle, service_lines=(forged_line, *bundle.service_lines[1:]))

        self.assertEqual(flatten_multi_line_claim_witness(bundle), flatten_multi_line_claim_witness(forged))
        self.assertTrue(validate_multi_line_claim_witness(forged))

    def test_allowed_cents_above_fee_schedule_value_rejected(self):
        bundle = valid_two_line_bundle(charge=200.00)
        line = bundle.service_lines[0]
        forged_line = replace(line, allowed_cents=line.allowed_cents + 100)
        forged = replace(bundle, service_lines=(forged_line, *bundle.service_lines[1:]))

        with self.assertRaisesRegex(ValueError, "multi_line_policy_dictionary_allowed_mismatch"):
            validate_multi_line_claim_witness(forged)

    def test_line_charge_below_authenticated_fee_cap_uses_per_line_min(self):
        ctx = claim_context_with_lines([ServiceLine("1", "99213", 100.00, 1.0, None)])
        bundle = build_multi_line_service_line_witness(ctx, config=BatchConfig())
        output = claim_output_for_multi_line_witness(bundle)

        self.assertEqual(bundle.service_lines[0].allowed_cents, 12_500)
        self.assertEqual(bundle.allowed_total_cents, 10_000)
        self.assertEqual(output["decision"], 1)
        self.assertEqual(output["allowed_cents"], 10_000)
        self.assertEqual(output["payment_cents"], 10_000)

    def test_tar_required_line_forged_as_nonmember_rejected(self):
        bundle = valid_two_line_bundle()
        non_required = bundle.service_lines[0]
        required = bundle.service_lines[1]
        forged_required = replace(
            required,
            tar_required=False,
        )
        forged = replace(bundle, service_lines=(non_required, forged_required))

        with self.assertRaisesRegex(ValueError, "multi_line_policy_dictionary_flag_mismatch"):
            validate_multi_line_claim_witness(forged)

    def test_tampered_policy_path_rejected(self):
        bundle = valid_two_line_bundle()
        line = bundle.service_lines[0]
        policy_rows = list(bundle.policy_rows)
        row = policy_rows[line.policy_row_index]
        policy_rows[line.policy_row_index] = replace(
            row,
            policy_path_elements=(bump_felt(row.policy_path_elements[0]), *row.policy_path_elements[1:]),
        )
        forged = replace(bundle, policy_rows=tuple(policy_rows))

        with self.assertRaisesRegex(ValueError, "multi_line_policy_row_membership_mismatch"):
            validate_multi_line_claim_witness(forged)

    def test_tampered_policy_requires_tar_rejected(self):
        bundle = valid_two_line_bundle()
        required = bundle.service_lines[1]
        policy_rows = list(bundle.policy_rows)
        row = policy_rows[required.policy_row_index]
        policy_rows[required.policy_row_index] = replace(row, requires_tar=False)
        forged = replace(bundle, policy_rows=tuple(policy_rows))

        with self.assertRaisesRegex(ValueError, "multi_line_policy_dictionary_leaf_mismatch"):
            validate_multi_line_claim_witness(forged)

    def test_auth_procedure_mismatch_rejected(self):
        bundle = valid_two_line_bundle()
        required = bundle.service_lines[1]
        authorizations = list(bundle.authorizations)
        authorizations[required.authorization_index] = replace(
            authorizations[required.authorization_index],
            procedure_code=pack_felt_text("99213"),
        )
        forged = replace(bundle, authorizations=tuple(authorizations))

        with self.assertRaisesRegex(ValueError, "multi_line_auth_procedure_mismatch"):
            validate_multi_line_claim_witness(forged)

    def test_auth_line_index_mismatch_rejected(self):
        bundle = valid_two_line_bundle()
        required = bundle.service_lines[1]
        authorizations = list(bundle.authorizations)
        authorizations[required.authorization_index] = replace(
            authorizations[required.authorization_index],
            line_index=0,
        )
        forged = replace(bundle, authorizations=tuple(authorizations))

        with self.assertRaisesRegex(ValueError, "multi_line_auth_line_index_mismatch"):
            validate_multi_line_claim_witness(forged)

    def test_tampered_auth_path_rejected(self):
        bundle = valid_two_line_bundle()
        required = bundle.service_lines[1]
        authorizations = list(bundle.authorizations)
        auth = authorizations[required.authorization_index]
        authorizations[required.authorization_index] = replace(
            auth,
            auth_path_elements=(bump_felt(auth.auth_path_elements[0]), *auth.auth_path_elements[1:]),
        )
        forged = replace(bundle, authorizations=tuple(authorizations))

        with self.assertRaisesRegex(ValueError, "multi_line_auth_membership_mismatch"):
            validate_multi_line_claim_witness(forged)

    def test_tampered_nullifier_after_root_rejected(self):
        bundle = valid_two_line_bundle()
        forged_nullifier = replace(bundle.nullifier, root_after=bump_felt(bundle.nullifier.root_after), onchain_root_after=bump_felt(bundle.nullifier.root_after))
        forged = replace(bundle, nullifier=forged_nullifier)

        with self.assertRaisesRegex(ValueError, "nullifier_inserted_membership_mismatch"):
            validate_multi_line_claim_witness(forged)

    def test_nullifier_must_match_claim_duplicate_nullifier(self):
        bundle = valid_two_line_bundle()
        forged_nullifier = replace(bundle.nullifier, inserted_nullifier_low=bundle.nullifier.inserted_nullifier_low + 1)
        forged = replace(bundle, nullifier=forged_nullifier)

        with self.assertRaisesRegex(ValueError, "multi_line_nullifier_claim_mismatch"):
            validate_multi_line_claim_witness(forged)

    def test_line_charge_sum_mismatch_rejected(self):
        bundle = valid_two_line_bundle()
        line = bundle.service_lines[0]
        forged_line = replace(line, line_charge_cents=line.line_charge_cents + 100)
        forged = replace(bundle, service_lines=(forged_line, *bundle.service_lines[1:]))

        with self.assertRaisesRegex(ValueError, "multi_line_claim_service_lines_mismatch"):
            validate_multi_line_claim_witness(forged)

    def test_51_line_bundle_rejected(self):
        bundle = valid_two_line_bundle()
        over_capacity = replace(bundle, service_lines=tuple(bundle.service_lines[:1] * 51))

        with self.assertRaisesRegex(ValueError, "multi_line_service_line_count_out_of_range"):
            validate_multi_line_claim_witness(over_capacity)

    def test_authenticated_absence_below_between_after_and_empty_schedule_denies_at_gate_11(self):
        cases = [
            ("below", {"BB": 10_000, "DD": 10_000}, "AA"),
            ("between", {"BB": 10_000, "DD": 10_000}, "CC"),
            ("after", {"BB": 10_000, "DD": 10_000}, "EE"),
            ("empty", {}, "CC"),
        ]
        for label, schedule, procedure_code in cases:
            with self.subTest(label=label):
                ctx = claim_context_with_lines([ServiceLine("1", procedure_code, 100.00, 1.0, None)])
                bundle = build_multi_line_service_line_witness(
                    ctx,
                    config=BatchConfig(fee_schedule_cents=schedule),
                )
                output = claim_output_for_multi_line_witness(bundle)

                self.assertFalse(bundle.service_lines[0].policy_present)
                self.assertTrue(validate_multi_line_claim_witness(bundle))
                self.assertEqual(output["decision"], 0)
                self.assertEqual(output["failure_code"], 11)
                self.assertEqual(output["allowed_cents"], 0)
                self.assertEqual(output["payment_cents"], 0)

    def test_mixed_membership_and_absence_denies_without_payment(self):
        config = BatchConfig(fee_schedule_cents={"BB": 10_000, "DD": 10_000})
        ctx = claim_context_with_lines(
            [
                ServiceLine("1", "BB", 100.00, 1.0, None),
                ServiceLine("2", "CC", 100.00, 1.0, None),
            ]
        )
        bundle = build_multi_line_service_line_witness(ctx, config=config)
        output = claim_output_for_multi_line_witness(bundle)

        self.assertEqual([line.policy_present for line in bundle.service_lines], [True, False])
        self.assertEqual(output["decision"], 0)
        self.assertEqual(output["failure_code"], 11)
        self.assertEqual(output["allowed_cents"], 10_000)
        self.assertEqual(output["payment_cents"], 0)

    def test_earlier_denial_gate_outranks_authenticated_absence(self):
        ctx = claim_context_with_lines([ServiceLine("1", "CC", 100.00, 1.0, None)])
        ctx.flags["eligibility_active"] = False
        bundle = build_multi_line_service_line_witness(
            ctx,
            config=BatchConfig(fee_schedule_cents={"BB": 10_000, "DD": 10_000}),
        )
        output = claim_output_for_multi_line_witness(bundle)

        self.assertEqual(output["decision"], 0)
        self.assertEqual(output["failure_code"], 2)
        self.assertEqual(output["payment_cents"], 0)

    def test_unverified_prior_authorization_token_is_private_denial_gate_9(self):
        config = BatchConfig()
        ctx = claim_context_with_lines(
            [ServiceLine("1", "T1019", 125.00, 1.0, "PA-UNVERIFIED")]
        )
        ctx = replace(ctx, fact_verification={"tar_authorization": "UNVERIFIED"})
        ordinary, _engine_mode = adjudicate_for_batch(ctx, config)
        bundle = build_multi_line_service_line_witness(ctx, config=config)
        output = claim_output_for_multi_line_witness(bundle)

        self.assertFalse(ordinary.approved)
        self.assertEqual(ordinary.denial_reason, "prior_authorization_required")
        self.assertFalse(bundle.authorizations[0].authorization_present)
        self.assertEqual(bundle.authorizations[0].signed_tar_authorization_commitment, 0)
        self.assertEqual(output["decision"], 0)
        self.assertEqual(output["failure_code"], 9)
        self.assertEqual(output["payment_cents"], 0)

    def test_present_row_cannot_be_relabelled_as_absent(self):
        bundle = build_multi_line_service_line_witness(
            claim_context_with_lines([ServiceLine("1", "BB", 100.00, 1.0, None)]),
            config=BatchConfig(fee_schedule_cents={"BB": 10_000, "DD": 10_000}),
        )
        forged = replace(bundle, service_lines=(replace(bundle.service_lines[0], policy_present=False),))

        with self.assertRaisesRegex(ValueError, "multi_line_policy_nonmembership_range_mismatch"):
            validate_multi_line_claim_witness(forged)

    def test_absent_row_cannot_be_relabelled_as_present(self):
        bundle = build_multi_line_service_line_witness(
            claim_context_with_lines([ServiceLine("1", "CC", 100.00, 1.0, None)]),
            config=BatchConfig(fee_schedule_cents={"BB": 10_000, "DD": 10_000}),
        )
        forged = replace(bundle, service_lines=(replace(bundle.service_lines[0], policy_present=True),))

        with self.assertRaisesRegex(ValueError, "multi_line_policy_membership_mismatch"):
            validate_multi_line_claim_witness(forged)

    def test_omitted_or_mutated_absence_evidence_is_rejected(self):
        bundle = build_multi_line_service_line_witness(
            claim_context_with_lines([ServiceLine("1", "CC", 100.00, 1.0, None)]),
            config=BatchConfig(fee_schedule_cents={"BB": 10_000, "DD": 10_000}),
        )
        line = bundle.service_lines[0]
        row = bundle.policy_rows[line.policy_row_index]

        with self.assertRaisesRegex(ValueError, "multi_line_policy_dictionary_empty"):
            validate_multi_line_claim_witness(replace(bundle, policy_rows=()))

        mutated_rows = list(bundle.policy_rows)
        mutated_rows[line.policy_row_index] = replace(
            row,
            next_procedure_code_felt=row.next_procedure_code_felt + 1,
        )
        with self.assertRaisesRegex(ValueError, "multi_line_policy_dictionary_leaf_mismatch"):
            validate_multi_line_claim_witness(replace(bundle, policy_rows=tuple(mutated_rows)))

        shortened_rows = list(bundle.policy_rows)
        shortened_rows[line.policy_row_index] = replace(
            row,
            policy_path_elements=row.policy_path_elements[:-1],
        )
        with self.assertRaisesRegex(ValueError, "multi_line_policy_row_depth_mismatch"):
            validate_multi_line_claim_witness(replace(bundle, policy_rows=tuple(shortened_rows)))

        with self.assertRaisesRegex(ValueError, "multi_line_fee_policy_membership_mismatch"):
            validate_multi_line_claim_witness(replace(bundle, policy_root=bump_felt(bundle.policy_root)))

    def test_membership_and_absence_have_identical_serialized_shape(self):
        config = BatchConfig(fee_schedule_cents={"BB": 10_000, "DD": 10_000})
        present = build_multi_line_service_line_witness(
            claim_context_with_lines([ServiceLine("1", "BB", 100.00, 1.0, None)]),
            config=config,
        )
        absent = build_multi_line_service_line_witness(
            claim_context_with_lines([ServiceLine("1", "CC", 100.00, 1.0, None)]),
            config=config,
        )

        self.assertEqual(len(present.policy_rows), 1)
        self.assertEqual(len(absent.policy_rows), 1)
        self.assertEqual(len(flatten_multi_line_claim_witness(present)), len(flatten_multi_line_claim_witness(absent)))

    def test_policy_config_rejects_noncanonical_codes_and_full_tree_capacity_overflow(self):
        with self.assertRaisesRegex(ValueError, "policy_row_procedure_code_not_canonical"):
            _validate_batch_config(BatchConfig(fee_schedule_cents={"bad-code": 100}, max_claims=4, merkle_depth=2))

        with self.assertRaisesRegex(ValueError, "fee_schedule exceeds merkle capacity"):
            _validate_batch_config(
                BatchConfig(
                    fee_schedule_cents={"BB": 100, "DD": 100},
                    max_claims=4,
                    merkle_depth=2,
                )
            )

        for amount in (True, 12_500.9, "12500"):
            with self.subTest(non_integer_amount=amount):
                with self.assertRaisesRegex(ValueError, "policy_row_allowed_cents_not_integer"):
                    _validate_batch_config(BatchConfig(fee_schedule_cents={"BB": amount}))

        for tar_codes, error in [
            (("t1019",), "tar_required_procedure_codes invalid"),
            (("BAD-CODE",), "tar_required_procedure_codes invalid"),
            ((" T1019",), "tar_required_procedure_codes invalid"),
            (("T1019", "T1019"), "tar_required_procedure_codes duplicate"),
        ]:
            with self.subTest(tar_codes=tar_codes):
                with self.assertRaisesRegex(ValueError, error):
                    _validate_batch_config(BatchConfig(tar_required_procedure_codes=tar_codes))

    def test_ordinary_and_proof_paths_use_the_same_custom_or_empty_fee_schedule(self):
        cases = [
            ("custom", {"ZZ999": 10_000}, "ZZ999", True, 0, 10_000),
            ("empty", {}, "99213", False, 11, 0),
            ("absent_tar", {}, "T1019", False, 11, 0),
        ]
        for label, schedule, procedure_code, approved, failure_code, payment_cents in cases:
            with self.subTest(label=label):
                config = BatchConfig(fee_schedule_cents=schedule)
                ctx = claim_context_with_lines([ServiceLine("1", procedure_code, 100.00, 1.0, None)])
                ordinary, _engine_mode = adjudicate_for_batch(ctx, config)
                proof = claim_output_for_multi_line_witness(
                    build_multi_line_service_line_witness(ctx, config=config)
                )

                self.assertEqual(ordinary.approved, approved)
                self.assertEqual(proof["decision"], int(approved))
                self.assertEqual(proof["failure_code"], failure_code)
                self.assertEqual(int(round(ordinary.payable_amount * 100)), payment_cents)
                self.assertEqual(proof["payment_cents"], payment_cents)


if __name__ == "__main__":
    unittest.main()
