import copy
import unittest
from decimal import Decimal

from app.canonical_encoding import stable_private_hash
from app.service_line_canonical import cents
from app.shared_context import MAX_AMOUNT_CENTS, _money
from tests.test_rules_engine_coverage import base_context, ensure_rust_binary, rust_adjudicate


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
    @classmethod
    def setUpClass(cls) -> None:
        ensure_rust_binary()

    def test_canonical_money_is_exact_and_agrees_across_ingestion_and_rust(self):
        for raw, expected in CANONICAL_CASES.items():
            with self.subTest(raw=raw):
                ctx = copy.deepcopy(base_context())
                ctx.claim_id = f"MONEY-{raw.replace('.', '-')}"
                ctx.service_lines[0].charge_amount = raw
                ctx.total_charge = raw

                result = rust_adjudicate(ctx)

                self.assertEqual(int(Decimal(str(_money(raw))) * 100), expected)
                self.assertEqual(cents(raw), expected)
                self.assertEqual(result["total_charge_cents"], expected)
                self.assertEqual(result["payable_amount_cents"], min(expected, 12_500))

    def test_noncanonical_money_is_rejected_without_rounding_in_python_and_rust(self):
        for raw in NONCANONICAL_CASES:
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    _money(raw)
                with self.assertRaises(ValueError):
                    cents(raw)

                ctx = copy.deepcopy(base_context())
                ctx.claim_id = "MONEY-NONCANONICAL"
                ctx.service_lines[0].charge_amount = raw
                ctx.total_charge = raw
                with self.assertRaises(ValueError):
                    rust_adjudicate(ctx)

    def test_max_plus_one_cent_is_rejected_in_python_and_rust(self):
        raw = "42949672.96"
        with self.assertRaisesRegex(ValueError, "amount_out_of_range"):
            _money(raw)
        with self.assertRaisesRegex(ValueError, "amount_cents_out_of_range"):
            cents(raw)

        ctx = copy.deepcopy(base_context())
        ctx.claim_id = "MONEY-OVER-MAX"
        ctx.service_lines[0].charge_amount = raw
        ctx.total_charge = raw
        with self.assertRaises(ValueError):
            rust_adjudicate(ctx)

    def test_raw_float_rejected_from_commitment_encoding(self):
        with self.assertRaisesRegex(ValueError, "float_not_canonical"):
            stable_private_hash(1.005)
        with self.assertRaisesRegex(ValueError, "float_not_canonical"):
            stable_private_hash({"amount": 1.005})
