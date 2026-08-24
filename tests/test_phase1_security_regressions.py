import unittest
from dataclasses import replace

from app.batch.nullifier import IndexedNullifierTree, verify_nonmembership_witness


class Phase1SecurityRegressionTests(unittest.TestCase):
    def test_nullifier_transition_requires_an_authenticated_after_root(self):
        witness = IndexedNullifierTree([10, 20, 40]).prove_nonmembership(30)

        with self.assertRaisesRegex(ValueError, "nullifier_root_after_required"):
            verify_nonmembership_witness(replace(witness, rootAfter=0))

if __name__ == "__main__":
    unittest.main()
