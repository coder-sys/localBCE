import unittest

from app.canonical_encoding import stable_private_hash
from app.money import MAX_AMOUNT_CENTS, canonical_source_money_cents
from app.service_line_canonical import cents


CANONICAL_CASES = {
    "0": 0,
    "0.00": 0,
    "1": 100,
    "1.2": 120,
    "1.23": 123,
    "42949672.94": MAX_AMOUNT_CENTS - 1,
    "42949672.95": MAX_AMOUNT_CENTS,
}

NONCANONICAL_CASES = (
    "0.145",
    "1.005",
    "+1",
    "-1",
    " 1",
    "1 ",
    "01",
    "1e2",
    "1,00",
    "1.",
)


class MoneyDeterminismTests(unittest.TestCase):
    def test_canonical_money_is_exact_across_surviving_decoders(self):
        for raw, expected in CANONICAL_CASES.items():
            with self.subTest(raw=raw):
                self.assertEqual(canonical_source_money_cents(raw), expected)
                self.assertEqual(cents(raw), expected)

    def test_noncanonical_money_is_rejected_without_rounding(self):
        for raw in NONCANONICAL_CASES:
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    canonical_source_money_cents(raw)
                with self.assertRaises(ValueError):
                    cents(raw)

    def test_max_plus_one_cent_is_rejected(self):
        raw = "42949672.96"
        with self.assertRaisesRegex(ValueError, "amount_out_of_range"):
            canonical_source_money_cents(raw)
        with self.assertRaisesRegex(ValueError, "amount_cents_out_of_range"):
            cents(raw)

    def test_raw_float_rejected_from_commitment_encoding(self):
        with self.assertRaisesRegex(ValueError, "float_not_canonical"):
            stable_private_hash(1.005)
        with self.assertRaisesRegex(ValueError, "float_not_canonical"):
            stable_private_hash({"amount": 1.005})
