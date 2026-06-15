import json
import unittest
from pathlib import Path
from unittest.mock import patch

from app.batch.access_control import OPERATOR, RoleBook
from app.batch.batch_orchestrator import BatchConfig, LocalBatchRecorder, _submit_single_batch, ruleset_policy_record, submit_batches
from app.batch.leaf import stable_private_hash
from app.batch.merkle import MerkleTree, verify_inclusion
from app.batch.nullifier import IndexedNullifierTree
from app.ingestion import parse_837
from app.provider_alias import PROVIDER_ALIAS_KEY_ENV, provider_payment_alias
from app.shared_context import build_shared_context


ROOT = Path(__file__).resolve().parents[2]


def sample_payload(claim_id="BL-OPEN-0001", edi_transform=None):
    payload = json.loads((ROOT / "sample_claim_input.json").read_text(encoding="utf-8"))
    payload["edi"] = payload["edi"].replace("BL-CLAIM-0001", claim_id)
    if edi_transform:
        payload["edi"] = edi_transform(payload["edi"])
    return payload


def role_book():
    roles = RoleBook()
    roles.grant(OPERATOR, "operator@example.gov")
    return roles


class OpenEndedAdversarialHuntTests(unittest.TestCase):
    def test_provider_alias_missing_secret_fails_closed_blocked(self):
        """WHAT I TRIED: remove managed alias key and recompute provider alias from public NPI/name."""
        with patch.dict("os.environ", {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, PROVIDER_ALIAS_KEY_ENV):
                provider_payment_alias("1999999984", "Alice Adams")

    def test_ruleset_content_root_includes_python_fallback_engine_blocked(self):
        """WHAT I TRIED: check whether every executable policy path is content-addressed."""
        source = (ROOT / "app" / "batch" / "batch_orchestrator.py").read_text(encoding="utf-8")

        self.assertIn("rules-engine-rust", source)
        self.assertIn("rarc_mapping.tsv", source)
        self.assertIn("rules_engine_fallback.py", source)
        self.assertIn("rules_engine_adapter.py", source)

        original = ruleset_policy_record("manifest-test")
        from app.batch import batch_orchestrator

        real_hash = batch_orchestrator._file_sha256

        def changed_fallback(path):
            if str(path).replace("\\", "/").endswith("app/rules_engine_fallback.py"):
                return "00" * 32
            return real_hash(path)

        with patch.object(batch_orchestrator, "_file_sha256", side_effect=changed_fallback):
            changed = ruleset_policy_record("manifest-test")
        self.assertNotEqual(original, changed)

    def test_clm_sv1_amount_mismatch_rejected_before_payment_blocked(self):
        """WHAT I TRIED: make CLM total pass G8 while the service-line amount is excessive."""
        def mismatch(edi):
            return edi.replace("SV1*HC:99213*125.00", "SV1*HC:99213*6000.00")

        payload = sample_payload("BL-OPEN-AMOUNT-MISMATCH", mismatch)
        parsed = parse_837(payload["edi"])
        batch = submit_batches(
            [payload],
            actor="operator@example.gov",
            access=role_book(),
            config=BatchConfig(enforce_nullifier_proofs=False),
            recorder=LocalBatchRecorder(),
        )[0]

        self.assertTrue(parsed.accepted)
        with self.assertRaisesRegex(ValueError, "claim_total_mismatch"):
            build_shared_context(parsed, payload["flags"], strict_oracle=False)
        self.assertEqual(batch.claim_count, 0)
        self.assertEqual(batch.quarantined[0].reason, "adjudication_failed")
        self.assertIn("claim_total_mismatch", batch.quarantined[0].errors)
        self.assertEqual(batch.payments, [])

    def test_negative_service_line_amount_rejected_before_payment_blocked(self):
        """WHAT I TRIED: hide a negative service amount under a positive CLM total."""
        def negative_line(edi):
            return edi.replace("SV1*HC:99213*125.00", "SV1*HC:99213*-125.00")

        payload = sample_payload("BL-OPEN-NEGATIVE-LINE", negative_line)
        parsed = parse_837(payload["edi"])
        batch = submit_batches(
            [payload],
            actor="operator@example.gov",
            access=role_book(),
            config=BatchConfig(enforce_nullifier_proofs=False),
            recorder=LocalBatchRecorder(),
        )[0]

        self.assertTrue(parsed.accepted)
        with self.assertRaisesRegex(ValueError, "amount_out_of_range"):
            build_shared_context(parsed, payload["flags"], strict_oracle=False)
        self.assertEqual(batch.claim_count, 0)
        self.assertEqual(batch.quarantined[0].reason, "adjudication_failed")
        self.assertIn("amount_out_of_range", batch.quarantined[0].errors[0])
        self.assertEqual(batch.payments, [])

    def test_batch_id_includes_quarantined_payloads_blocked(self):
        """WHAT I TRIED: add bad payloads around the same valid claim and compare batch identity."""
        valid = sample_payload("BL-OPEN-BATCH-ID")
        config = BatchConfig(enforce_nullifier_proofs=False)
        empty_tree = IndexedNullifierTree()

        clean, _ = _submit_single_batch(0, [valid], config, empty_tree.root_hex, empty_tree)
        noisy, _ = _submit_single_batch(0, [valid, {"edi": "", "flags": {}, "claim_id": "BL-OPEN-BAD"}], config, empty_tree.root_hex, empty_tree)

        self.assertNotEqual(clean.batch_id, noisy.batch_id)
        self.assertEqual(clean.claim_count, noisy.claim_count)
        self.assertNotEqual(clean.quarantine_count, noisy.quarantine_count)

    def test_batch_path_non_mapping_flags_are_quarantined_not_crashed_blocked(self):
        """WHAT I TRIED: feed non-dict flags through the batch path instead of the per-claim path."""
        payload = sample_payload("BL-OPEN-BAD-FLAGS")
        payload["flags"] = ["eligibility_active"]
        batch = submit_batches(
            [payload],
            actor="operator@example.gov",
            access=role_book(),
            config=BatchConfig(enforce_nullifier_proofs=False),
            recorder=LocalBatchRecorder(),
        )[0]

        self.assertEqual(batch.claim_count, 0)
        self.assertEqual(batch.quarantine_count, 1)
        self.assertEqual(batch.quarantined[0].reason, "adjudication_failed")

    def test_payment_trigger_has_revoke_role_blocked(self):
        """WHAT I TRIED: look for an emergency off-ramp for a compromised payment operator."""
        source = (ROOT / "contracts" / "src" / "batch" / "BatchPaymentTrigger.sol").read_text(encoding="utf-8")

        self.assertIn("function grantRole", source)
        self.assertIn("function revokeRole", source)

    def test_zero_max_claims_config_rejected_with_domain_error_blocked(self):
        """WHAT I TRIED: push an invalid batch sizing config through the real submit path."""
        payload = sample_payload("BL-OPEN-ZERO-MAX-CLAIMS")
        with self.assertRaisesRegex(ValueError, "max_claims must be positive"):
            submit_batches(
                [payload],
                actor="operator@example.gov",
                access=role_book(),
                config=BatchConfig(max_claims=0, enforce_nullifier_proofs=False),
                recorder=LocalBatchRecorder(),
            )

    def test_python_merkle_verifier_rejects_high_index_bits_blocked(self):
        """WHAT I TRIED: replay a valid inclusion proof at index + tree_capacity."""
        leaves = [stable_private_hash("leaf-0"), stable_private_hash("leaf-1")]
        tree = MerkleTree(leaves, depth=2)
        proof = tree.prove(1)

        self.assertTrue(verify_inclusion(proof.leaf, proof.leaf_index, proof.siblings, proof.root))
        self.assertFalse(verify_inclusion(proof.leaf, proof.leaf_index + tree.capacity, proof.siblings, proof.root))

    def test_python_merkle_verifier_rejects_padding_leaf_past_claim_count_blocked(self):
        """WHAT I TRIED: verify a zero padding leaf as if it were a real claim result."""
        leaves = [stable_private_hash("real-result-leaf")]
        tree = MerkleTree(leaves, depth=2)
        padding_path = [tree.levels[0][0], tree.levels[1][1]]

        self.assertFalse(verify_inclusion("00" * 32, 1, padding_path, tree.root, leaf_count=1))

    def test_python_merkle_tree_rejects_over_capacity_clean(self):
        """WHAT I TRIED: overflow the app-side Merkle tree capacity."""
        leaves = [stable_private_hash(f"leaf-{idx}") for idx in range(5)]
        with self.assertRaisesRegex(ValueError, "too many leaves"):
            MerkleTree(leaves, depth=2)


if __name__ == "__main__":
    unittest.main()
