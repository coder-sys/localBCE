import json
import os
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from app.batch.poseidon import FIELD_MODULUS, domain_tag, ensure_helper_built, poseidon_hash, poseidon_many
from app.batch.accumulators import BenefitAccumulator, apply_benefit_claim
from app.batch.encrypted_da import decrypt_claim_data, encrypt_claim_data, encrypted_claim_data_root, generate_audit_key_b64
from app.batch.nullifier import IndexedNullifierTree
from app.batch.stark_binding import (
    AggregationWitness,
    BatchSlot,
    NullifierInsertWitness,
    ServiceLineBinding,
    StarkClaimWitness,
    claim_source_leaf_for,
    expected_path_index,
    fee_leaf_for,
    normalized_fact_commitment_for,
    verify_aggregation,
    verify_claim_binding,
)
from app.batch.stark_encoding import (
    canonical_cents,
    canonical_day_count,
    canonical_npi,
    encode_claim,
    government_prf_nullifier,
    pack_felt_text,
)
from app.ingestion import parse_837
from app.shared_context import build_shared_context


ROOT = Path(__file__).resolve().parents[1]


def sample_payload(claim_id: str = "BL-STARK-FOUNDATION"):
    payload = json.loads((ROOT / "sample_claim_input.json").read_text(encoding="utf-8"))
    payload["edi"] = payload["edi"].replace("BL-CLAIM-0001", claim_id)
    return payload


def sample_context():
    payload = sample_payload()
    parsed = parse_837(payload["edi"])
    if not parsed.accepted:
        raise AssertionError(parsed.errors)
    flags = {
        **payload["flags"],
        "provider_not_suspended": True,
        "not_deceased": True,
    }
    return build_shared_context(parsed, flags, strict_oracle=False)


def service_line_binding(ctx):
    line = ctx.service_lines[0]
    partial = ServiceLineBinding(
        line_id=line.line_id,
        procedure_code=line.procedure_code,
        charge_cents=canonical_cents(line.charge_amount),
        allowed_cents=canonical_cents(line.charge_amount),
        fee_leaf=0,
        fee_path_index=0,
    )
    leaf = fee_leaf_for(partial)
    fee_sorted_leaves = (leaf,)
    return replace(
        partial,
        fee_leaf=leaf,
        fee_path_index=expected_path_index(leaf, 1024, fee_sorted_leaves),
        fee_sorted_leaves=fee_sorted_leaves,
    )


def governed_roots():
    return {
        "claimSourceRoot": poseidon_hash([domain_tag("claim_source"), 1, 101]),
        "oracleFactsRoot": poseidon_hash([domain_tag("oracle"), 1, 202]),
        "feeScheduleRoot": poseidon_hash([domain_tag("fee"), 1, 303]),
        "addressBookRoot": poseidon_hash([domain_tag("address"), 1, 404]),
        "rulesetRoot": poseidon_hash([domain_tag("ruleset"), 1, 505]),
    }


def honest_claim_witness():
    ctx = sample_context()
    encoded = encode_claim(ctx)
    claim_leaf = claim_source_leaf_for(encoded)
    roots = governed_roots()
    line = service_line_binding(ctx)
    inserted_nullifier = government_prf_nullifier(ctx)
    non_membership = IndexedNullifierTree().prove_nonmembership(inserted_nullifier)
    claim_source_sorted_leaves = (claim_leaf,)
    nullifier = NullifierInsertWitness(
        root_before=non_membership.root,
        live_root=non_membership.root,
        inserted_nullifier=inserted_nullifier,
        non_membership=non_membership,
    )
    return StarkClaimWitness(
        ctx=ctx,
        governed_roots=roots,
        onchain_governed_roots=dict(roots),
        claim_source_leaf=claim_leaf,
        normalized_fact_commitment=normalized_fact_commitment_for(ctx),
        service_lines=[line],
        total_charge_cents=canonical_cents(ctx.total_charge),
        nullifier=nullifier,
        claim_leaf_path_index=expected_path_index(claim_leaf, 1024, claim_source_sorted_leaves),
        approved=True,
        allowed_amount_cents=line.allowed_cents,
        claim_source_sorted_leaves=claim_source_sorted_leaves,
    )


class StarkFieldFoundationTests(unittest.TestCase):
    def test_poseidon_domain_vectors_match_helper_and_do_not_collide(self):
        rows = [
            [domain_tag("claim_source"), 3, 1, 2, 3],
            [domain_tag("oracle"), 3, 1, 2, 3],
            [domain_tag("fee"), 3, 1, 2, 3],
            [domain_tag("address"), 3, 1, 2, 3],
            [domain_tag("nullifier"), 3, 1, 2, 3],
            [domain_tag("payment"), 3, 1, 2, 3],
        ]
        python_values = poseidon_many(rows)
        helper = ensure_helper_built()
        direct = subprocess.run(
            [str(helper)],
            input=json.dumps([[str(value) for value in row] for row in rows]),
            text=True,
            capture_output=True,
            check=True,
        )
        helper_values = [int(value) for value in json.loads(direct.stdout)]
        self.assertEqual(python_values, helper_values)
        self.assertEqual(len(set(python_values)), len(rows))
        self.assertGreater(domain_tag("claim_source"), 2**200)
        with self.assertRaisesRegex(ValueError, "arity mismatch"):
            poseidon_hash([domain_tag("claim_source"), 2, 1, 2, 3])

    def test_canonical_felt_encoding_rejects_out_of_range_values(self):
        self.assertEqual(canonical_cents("125.00"), 12500)
        self.assertGreater(canonical_day_count("2026-06-01"), 0)
        self.assertEqual(canonical_npi("1999999984"), 1999999984)
        self.assertGreater(pack_felt_text("99213"), 0)
        with self.assertRaisesRegex(ValueError, "amount_cents_out_of_range"):
            canonical_cents(2**59)
        with self.assertRaises(ValueError):
            canonical_day_count(2**32)
        with self.assertRaisesRegex(ValueError, "npi_must_be_10_decimal_digits"):
            canonical_npi("123")
        with self.assertRaisesRegex(ValueError, "npi_must_be_10_decimal_digits"):
            canonical_npi("10000000000")
        with self.assertRaisesRegex(ValueError, "packed_text_length_out_of_range"):
            pack_felt_text("x" * 32)
        with self.assertRaisesRegex(ValueError, "canonical field"):
            poseidon_hash([domain_tag("claim_source"), 1, FIELD_MODULUS])
        with self.assertRaisesRegex(ValueError, "domain tag"):
            poseidon_hash([123456, 0])

    def test_government_prf_nullifier_is_deterministic_and_secret_bound(self):
        ctx = sample_context()
        same_duplicate_different_claim_id = build_shared_context(
            parse_837(sample_payload("BL-STARK-DIFFERENT-ID")["edi"]),
            {**sample_payload()["flags"], "provider_not_suspended": True, "not_deceased": True},
            strict_oracle=False,
        )
        with patch.dict(os.environ, {"BL_NULLIFIER_PRF_SECRET": "secret-a"}, clear=False):
            first = government_prf_nullifier(ctx)
            second = government_prf_nullifier(ctx)
            duplicate_identity = government_prf_nullifier(same_duplicate_different_claim_id)
        with patch.dict(os.environ, {"BL_NULLIFIER_PRF_SECRET": "secret-b"}, clear=False):
            different_secret = government_prf_nullifier(ctx)
        self.assertEqual(first, second)
        self.assertEqual(first, duplicate_identity)
        self.assertNotEqual(first, different_secret)

        old_secret = os.environ.pop("BL_NULLIFIER_PRF_SECRET", None)
        old_dev = os.environ.pop("BL_DEV", None)
        try:
            with self.assertRaisesRegex(RuntimeError, "missing nullifier PRF secret"):
                government_prf_nullifier(ctx)
        finally:
            if old_secret is not None:
                os.environ["BL_NULLIFIER_PRF_SECRET"] = old_secret
            if old_dev is not None:
                os.environ["BL_DEV"] = old_dev

    def test_sorted_order_path_index_is_not_grindable_hash_mod(self):
        leaves = sorted(
            {
                poseidon_hash([domain_tag("claim_source"), 2, candidate, candidate + 17])
                for candidate in range(10_000)
            }
        )
        self.assertEqual(len(leaves), 10_000)
        indices = [expected_path_index(leaf, 16_384, leaves) for leaf in leaves]
        self.assertEqual(indices, list(range(10_000)))
        self.assertEqual(len(set(indices)), len(indices))
        for index, leaf in enumerate(leaves):
            self.assertEqual(expected_path_index(leaf, 16_384, tuple(leaves)), index)
        with self.assertRaisesRegex(ValueError, "sorted_leaf_order_required"):
            expected_path_index(leaves[0], 16_384)
        with self.assertRaisesRegex(ValueError, "not_sorted"):
            expected_path_index(leaves[0], 16_384, [leaves[1], leaves[0]])
        with self.assertRaisesRegex(ValueError, "contains_duplicate"):
            expected_path_index(leaves[0], 16_384, [leaves[0], leaves[0]])

    def test_binding_harness_rejects_adversarial_claim_witnesses(self):
        with patch.dict(os.environ, {"BL_NULLIFIER_PRF_SECRET": "binding-secret"}, clear=False):
            witness = honest_claim_witness()
        self.assertTrue(verify_claim_binding(witness, tree_capacity=1024))

        bad_roots = dict(witness.governed_roots)
        bad_roots["feeScheduleRoot"] += 1
        with self.assertRaisesRegex(ValueError, "governed_root_mismatch"):
            verify_claim_binding(replace(witness, governed_roots=bad_roots), tree_capacity=1024)

        with self.assertRaisesRegex(ValueError, "free_fact_commitment_mismatch"):
            verify_claim_binding(replace(witness, normalized_fact_commitment=witness.normalized_fact_commitment + 1), tree_capacity=1024)

        bad_fee = replace(witness.service_lines[0], fee_path_index=witness.service_lines[0].fee_path_index + 1)
        with self.assertRaisesRegex(ValueError, "fee_path_index_not_bound_to_sorted_order"):
            verify_claim_binding(replace(witness, service_lines=[bad_fee]), tree_capacity=1024)

        bad_fee_procedure = replace(witness.service_lines[0], fee_schedule_procedure_code="31299")
        with self.assertRaisesRegex(ValueError, "fee_procedure_not_bound_to_claim"):
            verify_claim_binding(replace(witness, service_lines=[bad_fee_procedure]), tree_capacity=1024)

        tampered_path = replace(
            witness.nullifier.non_membership,
            pathElements=[witness.nullifier.non_membership.pathElements[0] + 1]
            + witness.nullifier.non_membership.pathElements[1:],
        )
        with self.assertRaisesRegex(ValueError, "nullifier_predecessor_membership_mismatch"):
            verify_claim_binding(replace(witness, nullifier=replace(witness.nullifier, non_membership=tampered_path)), tree_capacity=1024)

        with self.assertRaisesRegex(ValueError, "stale_nullifier_root"):
            verify_claim_binding(replace(witness, nullifier=replace(witness.nullifier, live_root=456)), tree_capacity=1024)

        with self.assertRaisesRegex(ValueError, "multi_line_total_mismatch"):
            verify_claim_binding(replace(witness, total_charge_cents=witness.total_charge_cents + 1), tree_capacity=1024)

    def test_aggregation_harness_enforces_value_conservation_and_padding(self):
        honest = AggregationWitness(
            slots=[
                BatchSlot("claim-a", 11, True, 12500, 12500),
                BatchSlot("claim-b", 12, False, 0, 0),
                BatchSlot("", 0, False, 0, 0, padding=True),
            ],
            claimed_count=2,
            running_balance_before=100000,
            running_balance_after=100000,
            onchain_running_balance_before=100000,
            onchain_running_balance_after=100000,
        )
        self.assertTrue(verify_aggregation(honest))
        with self.assertRaisesRegex(ValueError, "running_balance_anchor_missing"):
            verify_aggregation(replace(honest, onchain_running_balance_before=None))
        with self.assertRaisesRegex(ValueError, "batch_value_conservation_violation"):
            verify_aggregation(replace(honest, slots=[replace(honest.slots[0], payment_amount_cents=12501), *honest.slots[1:]]))
        with self.assertRaisesRegex(ValueError, "padding_not_inert"):
            verify_aggregation(replace(honest, slots=[honest.slots[0], honest.slots[1], replace(honest.slots[2], inserted_nullifier=99)]))
        with self.assertRaisesRegex(ValueError, "claimed_count_mismatch"):
            verify_aggregation(replace(honest, claimed_count=3))

    def test_encrypted_claim_data_round_trip_and_no_plaintext(self):
        key = generate_audit_key_b64()
        payload = {"claim_id": "BL-STARK-FOUNDATION", "member_id": "M123456789", "total_charge": "125.00"}
        bundle = encrypt_claim_data(payload, key_b64=key, aad="batch-1", key_epoch="epoch-2026-06")
        encoded_bundle = json.dumps(bundle.to_dict(), sort_keys=True)
        self.assertNotIn("M123456789", encoded_bundle)
        self.assertEqual(decrypt_claim_data(bundle, key_b64=key), payload)
        self.assertEqual(len(encrypted_claim_data_root(bundle)), 64)
        rotated_epoch = encrypt_claim_data(payload, key_b64=key, aad="batch-1", key_epoch="epoch-2026-07")
        self.assertNotEqual(bundle.key_epoch, rotated_epoch.key_epoch)
        self.assertNotEqual(bundle.nonce_b64, rotated_epoch.nonce_b64)
        self.assertNotEqual(bundle.ciphertext_b64, rotated_epoch.ciphertext_b64)
        self.assertEqual(decrypt_claim_data(rotated_epoch, key_b64=key), payload)
        with self.assertRaisesRegex(ValueError, "aad_required"):
            encrypt_claim_data(payload, key_b64=key)
        tampered = {**bundle.to_dict(), "aad": "batch-2"}
        with self.assertRaises(Exception):
            decrypt_claim_data(tampered, key_b64=key)
        tampered_epoch = {**bundle.to_dict(), "key_epoch": "epoch-evil"}
        with self.assertRaises(Exception):
            decrypt_claim_data(tampered_epoch, key_b64=key)
        with self.assertRaises(Exception):
            decrypt_claim_data(bundle, key_b64=generate_audit_key_b64())

    def test_benefit_accumulator_enforces_caps_visits_deductibles_and_auth(self):
        accumulator = BenefitAccumulator(
            member_id="M123456789",
            benefit_year=2026,
            annual_cap_cents=1000,
            deductible_remaining_cents=250,
            visit_limit=2,
            prior_authorization_required=True,
            prior_authorizations=("PA-OK-123",),
        )
        expected_updated = replace(
            accumulator,
            paid_to_date_cents=150,
            deductible_remaining_cents=0,
            visits_used=1,
        )
        updated, payable = apply_benefit_claim(
            accumulator,
            allowed_cents=400,
            prior_authorization="PA-OK-123",
            onchain_accumulator_root_before=accumulator.root(),
            onchain_accumulator_root_after=expected_updated.root(),
        )
        self.assertEqual(payable, 150)
        self.assertEqual(updated.deductible_remaining_cents, 0)
        self.assertNotEqual(accumulator.root(), updated.root())
        with self.assertRaisesRegex(ValueError, "accumulator_anchor_missing"):
            apply_benefit_claim(accumulator, allowed_cents=100, prior_authorization="PA-OK-123")
        with self.assertRaisesRegex(ValueError, "prior_authorization"):
            apply_benefit_claim(
                accumulator,
                allowed_cents=100,
                onchain_accumulator_root_before=accumulator.root(),
                onchain_accumulator_root_after=accumulator.root(),
            )
        with self.assertRaisesRegex(ValueError, "visit_limit_exceeded"):
            apply_benefit_claim(
                updated,
                allowed_cents=100,
                visit_count=2,
                prior_authorization="PA-OK-123",
                onchain_accumulator_root_before=updated.root(),
                onchain_accumulator_root_after=updated.root(),
            )
        near_cap = replace(updated, paid_to_date_cents=950)
        with self.assertRaisesRegex(ValueError, "annual_benefit_cap_exceeded"):
            apply_benefit_claim(
                near_cap,
                allowed_cents=100,
                prior_authorization="PA-OK-123",
                onchain_accumulator_root_before=near_cap.root(),
                onchain_accumulator_root_after=near_cap.root(),
            )

    def test_accumulator_anchor_blocks_false_prior_paid_state(self):
        current = BenefitAccumulator(
            member_id="M-CAP-ANCHOR",
            benefit_year=2026,
            annual_cap_cents=100,
        )
        for _ in range(100):
            expected_next = replace(current, paid_to_date_cents=current.paid_to_date_cents + 1, visits_used=current.visits_used + 1)
            current, payable = apply_benefit_claim(
                current,
                allowed_cents=1,
                onchain_accumulator_root_before=current.root(),
                onchain_accumulator_root_after=expected_next.root(),
            )
            self.assertEqual(payable, 1)

        false_low_state = replace(current, paid_to_date_cents=0)
        with self.assertRaisesRegex(ValueError, "accumulator_root_before_not_onchain"):
            apply_benefit_claim(
                false_low_state,
                allowed_cents=1,
                onchain_accumulator_root_before=current.root(),
                onchain_accumulator_root_after=false_low_state.root(),
            )


if __name__ == "__main__":
    unittest.main()
