import unittest
from dataclasses import replace

from app.batch.merkle import PoseidonMerkleTree, verify_inclusion
from app.batch.nullifier import IndexedNullifierTree, verify_nonmembership_witness


class Phase1SecurityRegressionTests(unittest.TestCase):
    def test_nullifier_transition_requires_an_authenticated_after_root(self):
        witness = IndexedNullifierTree([10, 20, 40]).prove_nonmembership(30)

        with self.assertRaisesRegex(ValueError, "nullifier_root_after_required"):
            verify_nonmembership_witness(replace(witness, rootAfter=0))

    def test_poseidon_audit_proof_declares_raw_leaf_semantics(self):
        tree = PoseidonMerkleTree(["01" * 32, "02" * 32], depth=4, hash_domain="claim")
        proof = tree.prove(0)

        self.assertFalse(proof.leaf_is_hashed)
        self.assertTrue(
            verify_inclusion(
                proof.leaf,
                proof.leaf_index,
                proof.siblings,
                proof.root,
                leaf_count=2,
                hash_domain=proof.hash_domain,
                leaf_is_hashed=proof.leaf_is_hashed,
            )
        )


if __name__ == "__main__":
    unittest.main()
