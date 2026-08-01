from __future__ import annotations

import unittest

from app.batch.epoch_nullifier import (
    assert_epoch_set_transition,
    build_epoch_set_transition,
    epoch_nullifier_set_root,
    nullifier_from_words,
    nullifier_words,
)
from app.batch.nullifier import DEPTH, MAX_NULLIFIER
from app.batch.poseidon import FIELD_MODULUS


class EpochNullifierReferenceTests(unittest.TestCase):
    def test_epoch_transition_merges_sorted_disjoint_batch(self) -> None:
        transition = build_epoch_set_transition([10, 50, 90], [20, 60])
        self.assertEqual(transition.merged_values, (10, 20, 50, 60, 90))
        self.assertEqual(transition.root_before, epoch_nullifier_set_root([10, 50, 90]).root)
        self.assertEqual(transition.root_after, epoch_nullifier_set_root([10, 20, 50, 60, 90]).root)
        self.assertEqual(assert_epoch_set_transition([10, 50, 90], [20, 60], transition.root_before, transition.root_after), transition)

    def test_epoch_transition_rejects_double_spend_and_bad_order(self) -> None:
        transition = build_epoch_set_transition([10, 50, 90], [20, 60])
        with self.assertRaisesRegex(ValueError, "epoch_nullifier_already_spent"):
            assert_epoch_set_transition([10, 50, 90], [50, 60], transition.root_before, transition.root_after)
        with self.assertRaisesRegex(ValueError, "batch_epoch_values_not_strictly_sorted"):
            build_epoch_set_transition([10, 50, 90], [60, 20])
        with self.assertRaisesRegex(ValueError, "batch_epoch_values_not_strictly_sorted"):
            build_epoch_set_transition([10, 50, 90], [20, 20])

    def test_epoch_transition_rejects_noncanonical_aliases_and_boundaries(self) -> None:
        for value in (0, MAX_NULLIFIER, FIELD_MODULUS, FIELD_MODULUS + 1):
            with self.assertRaises(ValueError):
                build_epoch_set_transition([], [value])
        value = 12345
        high, low = nullifier_words(value)
        self.assertEqual(nullifier_from_words(high, low), value)
        alias = value + FIELD_MODULUS
        with self.assertRaisesRegex(ValueError, "nullifier_word_out_of_range|nullifier_out_of_range"):
            nullifier_from_words(alias >> 128, alias & ((1 << 128) - 1))

    def test_hash_count_is_explicit(self) -> None:
        transition = build_epoch_set_transition([10, 50, 90], [20, 60], depth=DEPTH)
        self.assertEqual(transition.hash_count, DEPTH + 2 + 3 + 5)


if __name__ == "__main__":
    unittest.main()
