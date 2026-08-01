from __future__ import annotations

import json
from pathlib import Path
import unittest
from unittest import mock

from app import privacy_v2
from app.public_inputs import (
    PUBLIC_INPUT_FIELD_NAMES_V2,
    assert_public_input_names_v2,
    build_native_stark_public_inputs_v2,
    manifest_fields_v2,
)


ROOT = Path(__file__).resolve().parents[1]


class PrivacyV2AbiTests(unittest.TestCase):
    def _v1_bundle(self, *, allowed: int = 12500, payment: int = 12500) -> dict:
        return {
            "witness": {"placeholder": True},
            "expected_output": {
                "batch_root_before": 11,
                "batch_root_after": 12,
                "claim_source_root": 13,
                "oracle_facts_root": 14,
                "policy_root": 15,
                "ruleset_root": 16,
                "batch_commitment": 17,
                "total_allowed_cents": allowed,
                "total_payment_cents": payment,
            },
        }

    def _bundle(self, **changes: int) -> dict:
        values = {
            "settlement_domain": 1001,
            "batch_nonce": 1002,
            "private_data_commitment": 1003,
            "privacy_salt": 1004,
            "value_salt": 1005,
        }
        values.update(changes)
        with mock.patch.object(
            privacy_v2, "flatten_batch_claim_input_witness", return_value=[2001, 2002]
        ):
            return privacy_v2.build_privacy_v2_bundle(self._v1_bundle(), **values)

    def test_manifest_python_and_cairo_share_one_exact_twelve_field_order(self) -> None:
        manifest = json.loads(
            (ROOT / "ops" / "native_stark_public_inputs_v2.json").read_text(encoding="utf-8")
        )
        names = tuple(field["name"] for field in manifest["fields"])
        self.assertEqual(privacy_v2.PRIVACY_V2_PUBLIC_OUTPUT_NAMES, names)
        self.assertEqual(PUBLIC_INPUT_FIELD_NAMES_V2, names)
        assert_public_input_names_v2(names)
        self.assertEqual(list(manifest["fields"]), manifest_fields_v2())
        self.assertEqual(12, len(names))
        cairo = (ROOT / "zk-cairo-sharp" / "src" / "lib.cairo").read_text(encoding="utf-8")
        start = cairo.index("pub struct BatchOutputV2")
        end = cairo.index("}", start)
        cairo_fields = tuple(
            line.split("pub ", 1)[1].split(":", 1)[0].strip()
            for line in cairo[start:end].splitlines()
            if line.strip().startswith("pub ") and not line.strip().startswith("pub struct ")
        )
        expected_cairo_fields = (
            "protocol_version",
            "settlement_domain",
            "batch_nonce",
            "nullifier_root_before",
            "nullifier_root_after",
            "claim_source_root",
            "oracle_facts_root",
            "policy_root",
            "ruleset_root",
            "opaque_batch_commitment",
            "value_conservation_commitment",
            "settlement_commitment",
        )
        self.assertEqual(expected_cairo_fields, cairo_fields)

    def test_outputs_hide_amounts_counts_and_private_data(self) -> None:
        bundle = self._bundle()
        output = bundle["expected_output"]
        public_inputs = build_native_stark_public_inputs_v2(output)
        self.assertEqual(12, len(public_inputs))
        serialized = json.dumps(output, sort_keys=True)
        for forbidden in (
            "total_allowed_cents",
            "total_payment_cents",
            "approved_count",
            "denied_count",
            "claim_count",
            "private_data_commitment",
        ):
            self.assertNotIn(forbidden, serialized)
        self.assertNotIn(f"{1003:064x}", public_inputs)

    def test_context_nonce_private_data_and_salts_are_all_bound(self) -> None:
        baseline = self._bundle()["expected_output"]
        for field in (
            "settlement_domain",
            "batch_nonce",
            "private_data_commitment",
            "privacy_salt",
            "value_salt",
        ):
            changed = self._bundle(**{field: 9000})["expected_output"]
            self.assertNotEqual(baseline["settlement_commitment"], changed["settlement_commitment"])

    def test_value_mismatch_and_zero_security_inputs_fail_closed(self) -> None:
        with mock.patch.object(
            privacy_v2, "flatten_batch_claim_input_witness", return_value=[]
        ):
            with self.assertRaisesRegex(ValueError, "value_conservation_mismatch"):
                privacy_v2.build_privacy_v2_bundle(
                    self._v1_bundle(payment=12499),
                    settlement_domain=1,
                    batch_nonce=2,
                    private_data_commitment=3,
                    privacy_salt=4,
                    value_salt=5,
                )
            with self.assertRaisesRegex(ValueError, "privacy_salt_must_be_nonzero"):
                privacy_v2.build_privacy_v2_bundle(
                    self._v1_bundle(),
                    settlement_domain=1,
                    batch_nonce=2,
                    private_data_commitment=3,
                    privacy_salt=0,
                    value_salt=5,
                )

    def test_serialized_wrapper_order_matches_cairo_input_struct(self) -> None:
        bundle = self._bundle()
        self.assertEqual(
            ["0x3e9", "0x3ea", "0x3eb", "0x3ec", "0x3ed", "0x7d1", "0x7d2"],
            bundle["serialized_arguments_hex_json"],
        )

    def test_contract_has_no_amount_count_or_claim_payload_submission_fields(self) -> None:
        source = (ROOT / "contracts" / "src" / "stark" / "StarkBatchSettlementV2.sol").read_text(
            encoding="utf-8"
        )
        submission = source[source.index("struct Submission"):source.index("struct StoredBatch")]
        for forbidden in (
            "approvedAmountCents",
            "paymentAmountCents",
            "claimCount",
            "approvedCount",
            "deniedCount",
            "encryptedPayload",
        ):
            self.assertNotIn(forbidden, submission)
        self.assertIn("bytes32[12] memory outputs", source)

    def test_operating_system_csprng_generates_distinct_nonzero_salts(self) -> None:
        with mock.patch.object(privacy_v2.secrets, "randbelow", side_effect=[10, 10, 20]):
            privacy_salt, value_salt = privacy_v2.generate_privacy_v2_salts()
        self.assertEqual((11, 21), (privacy_salt, value_salt))

    def test_public_input_encoder_rejects_noncanonical_stark_field(self) -> None:
        output = self._bundle()["expected_output"]
        output["opaque_batch_commitment"] = privacy_v2.FIELD_MODULUS
        with self.assertRaisesRegex(ValueError, "public_input_v2_not_stark_field"):
            build_native_stark_public_inputs_v2(output)

    def test_public_input_encoder_rejects_coercible_noninteger_values(self) -> None:
        for value in (True, "2"):
            with self.subTest(value=value):
                output = self._bundle()["expected_output"]
                output["protocol_version"] = value
                with self.assertRaisesRegex(ValueError, "not_exact_integer"):
                    build_native_stark_public_inputs_v2(output)

    def test_v2_name_assertion_rejects_any_order_or_count_drift(self) -> None:
        for names in (
            PUBLIC_INPUT_FIELD_NAMES_V2[:-1],
            (*PUBLIC_INPUT_FIELD_NAMES_V2[1:], PUBLIC_INPUT_FIELD_NAMES_V2[0]),
        ):
            with self.subTest(names=names):
                with self.assertRaisesRegex(ValueError, "public_input_v2_schema_mismatch"):
                    assert_public_input_names_v2(names)


if __name__ == "__main__":
    unittest.main()
