import json
import os
import unittest
from pathlib import Path
from unittest.mock import patch

from app.batch.access_control import ADMIN, AUDITOR, OPERATOR, AccessDenied, RoleBook
from app.batch.batch_orchestrator import BatchAuthority, BatchConfig, LocalBatchRecorder, submit_batches
from app.batch.leaf import duplicate_check_key, duplicate_check_nullifier, stable_private_hash
from app.batch.merkle import MerkleTree, verify_inclusion
from app.batch.nullifier import DuplicateNullifierError, IndexedNullifierTree
from app.ingestion import parse_837
from app.shared_context import build_shared_context


ROOT = Path(__file__).resolve().parents[2]


def sample_payload(claim_id="BL-ATTACK-0001", flags=None, edi_transform=None, frequency_type=None):
    payload = json.loads((ROOT / "sample_claim_input.json").read_text(encoding="utf-8"))
    payload["edi"] = payload["edi"].replace("BL-CLAIM-0001", claim_id)
    if flags:
        payload["flags"].update(flags)
    if edi_transform:
        payload["edi"] = edi_transform(payload["edi"])
    if frequency_type:
        payload["frequency_type"] = frequency_type
    return payload


def roles():
    book = RoleBook()
    book.grant(ADMIN, "admin@example.gov")
    book.grant(OPERATOR, "operator@example.gov")
    book.grant(AUDITOR, "auditor@example.gov")
    return book


def context(payload):
    parsed = parse_837(payload["edi"])
    if not parsed.accepted:
        raise AssertionError(parsed.errors)
    return build_shared_context(parsed, payload["flags"], strict_oracle=False)


def unique_charge(amount):
    amount_text = f"{amount:.2f}"
    return lambda edi: edi.replace("*125.00", f"*{amount_text}")


class PythonBatchAttackTests(unittest.TestCase):
    def test_a1_double_pay_same_claim_across_two_batches_fail_closed_no_payment_submission(self):
        payload_a = sample_payload("BL-A1-SAME")
        payload_b = [sample_payload("BL-A1-SAME"), sample_payload("BL-A1-FILLER")]
        first = submit_batches([payload_a], actor="operator@example.gov", access=roles(), recorder=LocalBatchRecorder())[0]
        second = submit_batches(payload_b, actor="operator@example.gov", access=roles(), recorder=LocalBatchRecorder())[0]
        self.assertEqual(first.payments[0].amount_cents, 12500)
        self.assertGreaterEqual(second.payments[0].amount_cents, 12500)
        self.assertFalse(first.accepted_by_real_verifier)
        self.assertFalse(second.accepted_by_real_verifier)
        self.assertEqual(first.payments[0].settlement["status"], "not_submitted_real_verifier_rejected")
        self.assertEqual(second.payments[0].settlement["status"], "not_submitted_real_verifier_rejected")
        self.assertEqual(first.claim_packets[0].claim_id, "BL-A1-SAME")
        self.assertEqual(second.claim_packets[0].claim_id, "BL-A1-SAME")

    def test_b1_exact_duplicate_across_shared_recorder_blocked(self):
        shared_recorder = LocalBatchRecorder()
        submit_batches([sample_payload("BL-B1-DUP")], actor="operator@example.gov", access=roles(), recorder=shared_recorder)
        second = submit_batches(
            [sample_payload("BL-B1-DUP"), sample_payload("BL-B1-FILLER", edi_transform=unique_charge(126))],
            actor="operator@example.gov",
            access=roles(),
            recorder=shared_recorder,
        )[0]
        self.assertEqual([item.reason for item in second.quarantined], ["duplicate_identity_key_already_recorded"])
        self.assertEqual([packet.claim_id for packet in second.claim_packets], ["BL-B1-FILLER"])

    def test_p1_within_batch_exact_duplicate_key_blocked(self):
        batch = submit_batches(
            [sample_payload("BL-P1-DUP"), sample_payload("BL-P1-DUP")],
            actor="operator@example.gov",
            access=roles(),
            recorder=LocalBatchRecorder(),
        )[0]
        self.assertEqual(batch.claim_count, 1)
        self.assertEqual(batch.quarantine_count, 1)
        self.assertEqual(batch.quarantined[0].reason, "duplicate_identity_key_already_recorded")

    def test_p1_ruleset_version_allowlist_blocks_unapproved_roots(self):
        book = roles()
        authority = BatchAuthority()
        authority.set_ruleset_approved("approved_ruleset", True, actor="admin@example.gov", access=book)
        normal = submit_batches(
            [sample_payload("BL-P1-RULESET")],
            actor="operator@example.gov",
            access=book,
            config=BatchConfig(ruleset_version="approved_ruleset"),
            recorder=LocalBatchRecorder(authority=authority),
        )[0]
        self.assertEqual(normal.claim_count, 1)
        with self.assertRaisesRegex(ValueError, "ruleset not approved"):
            submit_batches(
                [sample_payload("BL-P1-RULESET-FORGED")],
                actor="operator@example.gov",
                access=book,
                config=BatchConfig(ruleset_version="forged_or_stale_ruleset"),
                recorder=LocalBatchRecorder(authority=authority),
            )

    def test_p1_value_units_fractional_cent_rejected_before_payment(self):
        def fractional_charge(edi):
            return edi.replace("CLM*BL-P1-CENTS*125.00", "CLM*BL-P1-CENTS*125.005").replace("SV1*HC:99213*125.00", "SV1*HC:99213*125.005")

        batch = submit_batches(
            [sample_payload("BL-P1-CENTS", edi_transform=fractional_charge)],
            actor="operator@example.gov",
            access=roles(),
            recorder=LocalBatchRecorder(),
        )[0]
        self.assertEqual(batch.claim_count, 0)
        self.assertEqual(batch.quarantined[0].reason, "adjudication_failed")
        self.assertIn("noncanonical_money", batch.quarantined[0].errors[0])
        self.assertEqual(batch.payments, [])

    def test_b4_near_duplicate_trivial_claim_id_change_blocked_within_batch(self):
        payloads = [sample_payload("BL-B4-ORIGINAL"), sample_payload("BL-B4-TRIVIAL-CHANGE")]
        batch = submit_batches(payloads, actor="operator@example.gov", access=roles(), recorder=LocalBatchRecorder())[0]
        self.assertEqual([packet.claim_id for packet in batch.claim_packets], ["BL-B4-ORIGINAL"])
        self.assertEqual(batch.claim_count, 1)
        self.assertEqual(batch.quarantine_count, 1)
        self.assertEqual(batch.quarantined[0].reason, "duplicate_identity_key_already_recorded")

    def test_b5_frequency_type_abuse_blocked_pending_domain_review(self):
        ctx_original = context(sample_payload("BL-B5-SAME", frequency_type="original"))
        original_key = duplicate_check_key(ctx_original, "original")
        replacement_key = duplicate_check_key(ctx_original, "replacement")
        self.assertNotEqual(original_key, replacement_key)
        batch = submit_batches(
            [
                sample_payload("BL-B5-SAME", frequency_type="original"),
                sample_payload("BL-B5-SAME", frequency_type="replacement"),
            ],
            actor="operator@example.gov",
            access=roles(),
            recorder=LocalBatchRecorder(),
        )[0]
        self.assertEqual(batch.claim_count, 1)
        self.assertEqual(batch.quarantine_count, 1)
        self.assertEqual(batch.quarantined[0].reason, "frequency_type_pending_domain_review")

    def test_c1_forged_merkle_inclusion_for_absent_claim_blocked(self):
        leaves = [stable_private_hash("real-0"), stable_private_hash("real-1")]
        tree = MerkleTree(leaves, depth=10)
        proof = tree.prove(0)
        fake_leaf = stable_private_hash("never-in-batch")
        self.assertFalse(verify_inclusion(fake_leaf, proof.leaf_index, proof.siblings, tree.root))

    def test_c2_swap_approved_denied_result_leaf_blocked_against_fixed_root(self):
        approved_leaf = stable_private_hash("approved-result")
        denied_leaf = stable_private_hash("denied-result")
        tree = MerkleTree([approved_leaf], depth=10)
        proof = tree.prove(0)
        self.assertFalse(verify_inclusion(denied_leaf, proof.leaf_index, proof.siblings, tree.root))

    def test_c3_tampered_path_variants_blocked(self):
        leaves = [stable_private_hash(f"leaf-{idx}") for idx in range(8)]
        tree = MerkleTree(leaves, depth=10)
        proof = tree.prove(5)
        self.assertTrue(verify_inclusion(proof.leaf, proof.leaf_index, proof.siblings, proof.root))
        self.assertFalse(verify_inclusion(proof.leaf, 4, proof.siblings, proof.root))
        reversed_path = list(reversed(proof.siblings))
        self.assertFalse(verify_inclusion(proof.leaf, proof.leaf_index, reversed_path, proof.root))
        short_path = proof.siblings[:-1]
        self.assertFalse(verify_inclusion(proof.leaf, proof.leaf_index, short_path, proof.root))

    def test_c4_wrong_batch_inclusion_blocked(self):
        batch_x = MerkleTree([stable_private_hash("x-claim")], depth=10)
        batch_y = MerkleTree([stable_private_hash("y-claim")], depth=10)
        proof_x = batch_x.prove(0)
        self.assertFalse(verify_inclusion(proof_x.leaf, proof_x.leaf_index, proof_x.siblings, batch_y.root))

    def test_c6_app_and_contract_inclusion_hash_mismatch_blocked(self):
        py_source = (ROOT / "app" / "batch" / "merkle.py").read_text(encoding="utf-8")
        sol_source = (ROOT / "contracts" / "src" / "batch" / "BatchClaimsRegistry.sol").read_text(encoding="utf-8")
        self.assertIn("hashlib.sha256", py_source)
        self.assertIn("computed = sha256", sol_source)
        self.assertNotIn("computed = keccak256", sol_source)

    def test_d_role_checks_block_auditor_submit_and_role_escalation(self):
        book = roles()
        with self.assertRaises(AccessDenied):
            book.require_batch_submitter("auditor@example.gov")
        with self.assertRaises(ValueError):
            book.grant("SuperAdmin", "auditor@example.gov")

    def test_e1_on_chain_payment_surface_has_no_clear_amount_blocked(self):
        source = (ROOT / "contracts" / "src" / "batch" / "BatchPaymentTrigger.sol").read_text(encoding="utf-8")
        self.assertNotIn("uint256 amount", source)
        self.assertNotIn("totalAmount", source)
        self.assertIn("event ProviderPaymentSubmitted", source)

    def test_e2_dictionary_link_duplicate_check_key_requires_the_private_pepper(self):
        target_ctx = context(sample_payload("BL-E2-TARGET"))
        target_key = duplicate_check_key(target_ctx, "original")
        def wrong_npi(edi):
            return edi.replace("1999999984", "1888888876")

        candidates = [
            context(sample_payload("BL-E2-WRONG", edi_transform=wrong_npi)),
            target_ctx,
            context(sample_payload("BL-E2-OTHER", flags={"eligibility_active": False})),
        ]
        with patch.dict(os.environ, {"BL_DUPLICATE_CHECK_PEPPER": "attacker-does-not-know-real-pepper"}):
            matched = [candidate for candidate in candidates if duplicate_check_key(candidate, "original") == target_key]
        self.assertEqual(matched, [])

        matched_with_real_pepper = [candidate for candidate in candidates if duplicate_check_key(candidate, "original") == target_key]
        self.assertEqual(len(matched_with_real_pepper), 2)
        self.assertTrue(all(candidate.member_id == target_ctx.member_id for candidate in matched_with_real_pepper))
        self.assertTrue(all(candidate.provider.npi == target_ctx.provider.npi for candidate in matched_with_real_pepper))

    def test_native_stark_nullifier_tree_fresh_duplicate_and_tampered_paths(self):
        ctx = context(sample_payload("BL-NULLIFIER-REAL"))
        nullifier = duplicate_check_nullifier(ctx, "original")
        tree = IndexedNullifierTree()

        fresh = tree.prove_nonmembership(nullifier)
        self.assertEqual(fresh.root, tree.root)
        self.assertEqual(fresh.nullifier, nullifier)
        self.assertEqual(len(fresh.pathElements), 32)
        self.assertEqual(len(fresh.pathIndices), 32)

        tree.insert(nullifier)
        self.assertNotEqual(fresh.root, tree.root)
        with self.assertRaises(DuplicateNullifierError):
            tree.prove_nonmembership(nullifier)

        duplicate = tree.duplicate_rejection_witness(nullifier)
        self.assertEqual(duplicate.nullifier, nullifier)
        self.assertEqual(duplicate.root, tree.root)
        self.assertEqual(duplicate.nextValue, nullifier)

    def test_f2_reordered_claims_change_root_and_old_paths_fail(self):
        a = stable_private_hash("claim-a")
        b = stable_private_hash("claim-b")
        tree_ab = MerkleTree([a, b], depth=10)
        tree_ba = MerkleTree([b, a], depth=10)
        self.assertNotEqual(tree_ab.root, tree_ba.root)
        proof_ab = tree_ab.prove(0)
        self.assertFalse(verify_inclusion(proof_ab.leaf, proof_ab.leaf_index, proof_ab.siblings, tree_ba.root))

    def test_f3_mixed_malformed_claim_quarantined_without_corrupting_batch(self):
        def unique_charge(idx):
            amount = f"{125 + idx}.00"
            return lambda edi: edi.replace(f"CLM*BL-F3-GOOD-{idx}*125.00", f"CLM*BL-F3-GOOD-{idx}*{amount}").replace("SV1*HC:99213*125.00", f"SV1*HC:99213*{amount}")

        payloads = [sample_payload(f"BL-F3-GOOD-{idx}", edi_transform=unique_charge(idx)) for idx in range(6)]
        payloads.insert(3, {"edi": "", "flags": {}, "claim_id": "BL-F3-BAD"})
        batch = submit_batches(payloads, actor="operator@example.gov", access=roles(), recorder=LocalBatchRecorder())[0]
        self.assertEqual(batch.claim_count, 6)
        self.assertEqual(batch.quarantine_count, 1)
        self.assertEqual(batch.quarantined[0].reason, "ingestion_failed")
        self.assertFalse(batch.accepted_by_real_verifier)

    def test_f4_overlapping_claims_across_workers_blocked_by_authoritative_root(self):
        authority = BatchAuthority()
        first = submit_batches(
            [sample_payload("BL-F4-OVERLAP"), sample_payload("BL-F4-A", edi_transform=unique_charge(126))],
            actor="operator@example.gov",
            access=roles(),
            recorder=LocalBatchRecorder(authority=authority),
        )[0]
        second = submit_batches(
            [sample_payload("BL-F4-OVERLAP"), sample_payload("BL-F4-B", edi_transform=unique_charge(127))],
            actor="operator@example.gov",
            access=roles(),
            recorder=LocalBatchRecorder(authority=authority),
        )[0]
        self.assertEqual([packet.claim_id for packet in first.claim_packets], ["BL-F4-OVERLAP", "BL-F4-A"])
        self.assertEqual([packet.claim_id for packet in second.claim_packets], ["BL-F4-B"])
        self.assertEqual([item.reason for item in second.quarantined], ["duplicate_identity_key_already_recorded"])
        self.assertFalse(first.accepted_by_real_verifier)
        self.assertFalse(second.accepted_by_real_verifier)


if __name__ == "__main__":
    unittest.main()
