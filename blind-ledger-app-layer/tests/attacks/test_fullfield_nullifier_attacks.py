import json
import unittest
from pathlib import Path

from app.batch.access_control import OPERATOR, RoleBook
from app.batch.batch_orchestrator import BatchAuthority, BatchConfig, LocalBatchRecorder, submit_batches
from app.batch.nullifier import MAX_NULLIFIER, DuplicateNullifierError, IndexedNullifierTree
from app.batch.poseidon import FIELD_MODULUS, poseidon_many


ROOT = Path(__file__).resolve().parents[2]


def sample_payload(claim_id: str, amount: float = 125.0):
    payload = json.loads((ROOT / "sample_claim_input.json").read_text(encoding="utf-8"))
    amount_text = f"{amount:.2f}"
    payload["edi"] = (
        payload["edi"]
        .replace("BL-CLAIM-0001", claim_id)
        .replace(f"CLM*{claim_id}*125.00", f"CLM*{claim_id}*{amount_text}")
        .replace("SV1*HC:99213*125.00", f"SV1*HC:99213*{amount_text}")
    )
    return payload


def roles():
    book = RoleBook()
    book.grant(OPERATOR, "operator@example.gov")
    return book


class FullFieldNullifierAttackTests(unittest.TestCase):
    def test_full_field_collision_attempt_has_no_collision_in_sample(self):
        values = poseidon_many([[0xB11D, idx, 0xA11CE] for idx in range(2000)])
        self.assertEqual(len(values), 2000)
        self.assertEqual(len(set(values)), 2000)
        self.assertTrue(all(0 < value < MAX_NULLIFIER for value in values))

    def test_field_wraparound_and_sentinel_values_rejected(self):
        tree = IndexedNullifierTree()
        for value in [-1, 0, MAX_NULLIFIER, FIELD_MODULUS, FIELD_MODULUS + 1]:
            with self.assertRaises(ValueError):
                tree.prove_nonmembership(value)

    def test_exact_duplicate_is_blocked_by_full_field_tree(self):
        value = poseidon_many([[0xD00D, 1, 2, 3]])[0]
        tree = IndexedNullifierTree()
        tree.insert(value)
        with self.assertRaises(DuplicateNullifierError):
            tree.prove_nonmembership(value)

    def test_cross_worker_duplicate_blocked_by_authoritative_root(self):
        authority = BatchAuthority()
        first = submit_batches(
            [sample_payload("BL-FF-RACE-A", 144.0)],
            actor="operator@example.gov",
            access=roles(),
            recorder=LocalBatchRecorder(authority=authority),
            config=BatchConfig(enforce_nullifier_proofs=False),
        )[0]
        second = submit_batches(
            [sample_payload("BL-FF-RACE-B", 144.0)],
            actor="operator@example.gov",
            access=roles(),
            recorder=LocalBatchRecorder(authority=authority),
            config=BatchConfig(enforce_nullifier_proofs=False),
        )[0]

        self.assertEqual(first.claim_count, 1)
        self.assertEqual(second.claim_count, 0)
        self.assertEqual(second.quarantine_count, 1)
        self.assertEqual(second.quarantined[0].reason, "duplicate_identity_key_already_recorded")

    def test_shared_authoritative_root_blocks_cross_batch_duplicate(self):
        recorder = LocalBatchRecorder()
        first = submit_batches(
            [sample_payload("BL-FF-SHARED-A", 145.0)],
            actor="operator@example.gov",
            access=roles(),
            recorder=recorder,
            config=BatchConfig(enforce_nullifier_proofs=False),
        )[0]
        second = submit_batches(
            [sample_payload("BL-FF-SHARED-B", 145.0), sample_payload("BL-FF-SHARED-C", 146.0)],
            actor="operator@example.gov",
            access=roles(),
            recorder=recorder,
            config=BatchConfig(enforce_nullifier_proofs=False),
        )[0]

        self.assertEqual(first.claim_count, 1)
        self.assertEqual(second.claim_count, 1)
        self.assertEqual(second.quarantine_count, 1)
        self.assertEqual(second.quarantined[0].reason, "duplicate_identity_key_already_recorded")


if __name__ == "__main__":
    unittest.main()
