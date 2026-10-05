"""The shared canonical-JSON helper: fixed expected bytes, and NaN/Infinity/duplicate refusal at every former copy."""

import unittest

from app import right_rail_financial_cash_file as cash
from app import right_rail_financial_custody as custody
from app import right_rail_financial_switch as switch
from app.right_rail_financial_canonical_json import decode, encode
from tools import right_rail_financial_cli as cli
from tools import right_rail_financial_service_kit as kit

EXPECTED = (
    ({}, b"{}"),
    ({"b": 1, "a": [True, None, "x"]}, b'{"a":[true,null,"x"],"b":1}'),
    ({"k": "\u00e9\u20ac\U0001f600\x00\x7f"}, b'{"k":"\u00e9\u20ac\ud83d\ude00\u0000\u007f"}'),
    ({"s": "\ud800", "q": '"\\/\n'}, b'{"q":"\\"\\\\/\\n","s":"\\ud800"}'),
    ([1, -0, 10**30, 1.5, 1e100, -2.5e-07, 0.1], b"[1,0,1000000000000000000000000000000,1.5,1e+100,-2.5e-07,0.1]"),
    ({"z": {"y": {"x": []}}, "\u00e9": 0}, b'{"z":{"y":{"x":[]}},"\u00e9":0}'),
)
CONSTANTS = (b"NaN", b"Infinity", b"-Infinity")


class CanonicalJsonTests(unittest.TestCase):
    def test_helper_bytes_are_fixed_and_round_trip(self) -> None:
        for value, raw in EXPECTED:
            self.assertEqual(encode(value), raw)
            self.assertEqual(encode(decode(raw, "ascii", self.fail, self.fail)), raw)
            self.assertEqual(switch._canonical_json(value, maximum=1000), raw)
            self.assertEqual(kit._canonical_json(value), raw)
            self.assertEqual(custody._encode(value), raw)
            self.assertEqual(cli._json(value).encode("ascii"), raw)

    def test_helper_refuses_nan_infinity_and_unsortable_keys(self) -> None:
        for bad in (float("nan"), float("inf"), -float("inf"), {"a": [float("nan")]}):
            with self.assertRaises(ValueError):
                encode(bad)
        with self.assertRaises(TypeError):
            encode({1: 0, "a": 0})

    def test_every_former_copy_refuses_nan_and_infinity(self) -> None:
        for bad in (float("nan"), float("inf"), -float("inf")):
            for call in (lambda: custody._encode(bad), lambda: kit._canonical_json(bad), lambda: cli._json(bad)):
                with self.assertRaises(ValueError):
                    call()
            with self.assertRaisesRegex(switch.FinancialSwitchError, "switch:canonical-json"):
                switch._canonical_json({"a": bad}, maximum=1000)
        for constant in CONSTANTS:
            raw = b'{"a":' + constant + b"}"
            with self.assertRaisesRegex(switch.FinancialSwitchError, "label:constant"):
                switch._decode_canonical_json(raw, maximum=100, label="label")
            with self.assertRaisesRegex(kit.KitError, "json_nonstandard_number:" + constant.decode()):
                kit._strict_canonical_json(raw, "label")
            with self.assertRaisesRegex(cash.CashFileError, "cash_file_format"):
                cash._propose(raw, b"x")

    def test_duplicate_keys_keep_each_modules_own_refusal(self) -> None:
        raw = b'{"a":1,"a":2}'
        with self.assertRaisesRegex(switch.FinancialSwitchError, "switch:duplicate-json-key"):
            switch._decode_canonical_json(raw, maximum=100, label="label")
        with self.assertRaisesRegex(kit.KitError, "json_duplicate_key:a"):
            kit._strict_canonical_json(raw, "label")
        with self.assertRaisesRegex(cash.CashFileError, "cash_file_format"):
            cash._propose(raw, b"x")

    def test_canonical_decoders_still_demand_canonical_bytes(self) -> None:
        with self.assertRaisesRegex(switch.FinancialSwitchError, "label:canonical"):
            switch._decode_canonical_json(b'{"b":1,"a":2}', maximum=100, label="label")
        with self.assertRaisesRegex(kit.KitError, "json_not_canonical:label"):
            kit._strict_canonical_json(b'{"a": 1}', "label")
        self.assertEqual(switch._decode_canonical_json(b'{"a":1}', maximum=100, label="label"), {"a": 1})
        for raw in (b'{"a":1e400}', b'{"a":-1E999}'):  # parse as +-inf: refused with the kit's own code, not a bare ValueError
            with self.assertRaisesRegex(kit.KitError, "json_not_canonical:label"):
                kit._strict_canonical_json(raw, "label")
        for raw in (b'{"a":' + b"1" * 4301 + b"}", b'{"a":' + b"[" * 1000 + b"]" * 1000 + b"}"):  # int too long, too deep
            with self.assertRaisesRegex(kit.KitError, "json_invalid:label"):
                kit._strict_json(raw, "label")

    def test_decode_refuses_even_when_a_callback_returns(self) -> None:
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}'):
            with self.assertRaises(ValueError):
                decode(raw, "ascii", lambda key: None, lambda name: 0)


if __name__ == "__main__":
    unittest.main()
