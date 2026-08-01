import os
import unittest
from dataclasses import replace
from hashlib import sha3_512
from unittest.mock import patch

from app.batch.poseidon import FIELD_MODULUS
from app.batch.verifier_receipt import (
    PRIVACY_V2_PUBLIC_INPUT_SCHEMA,
    SYNTHETIC_TEST_PROFILE_ID,
    LocalSyntheticVerifierAdapter,
    VerificationRequest,
    VerifierReceiptIssuer,
    canonical_public_inputs_v2,
)


TEST_ENV = {
    "BL_ENV": "test",
    "BL_DEV": "1",
    "BL_ALLOW_LOCAL_ENFORCEMENT_DISABLE": "1",
}


def public_inputs_v2() -> tuple[str, ...]:
    return tuple(f"{value:064x}" for value in [2, 7001, 1, 3, 4, 5, 6, 7, 8, 9, 10, 11])


class VerifierReceiptTests(unittest.TestCase):
    @patch.dict(os.environ, TEST_ENV, clear=False)
    def test_local_issuer_binds_exact_statement_proof_artifact_and_authority(self):
        values = public_inputs_v2()
        adapter = LocalSyntheticVerifierAdapter(
            verifier_key_id="NATIVE_STARK_SETTLEMENT_V1",
            artifact_bytes=b"synthetic-verifier-artifact-v1",
        )
        issuer = VerifierReceiptIssuer(adapter)
        placeholder = VerificationRequest.create(
            batch_id="11" * 32,
            verifier_key_id="NATIVE_STARK_SETTLEMENT_V1",
            public_inputs=values,
            proof=b"placeholder",
        )
        proof = adapter.synthetic_proof(placeholder)
        request = VerificationRequest.create(
            batch_id=placeholder.batch_id,
            verifier_key_id=placeholder.verifier_key_id,
            public_inputs=values,
            proof=proof,
        )
        receipt = issuer.issue(request)

        issuer.validate(receipt)
        self.assertFalse(receipt.production_verified)
        self.assertEqual(receipt.public_input_schema, PRIVACY_V2_PUBLIC_INPUT_SCHEMA)
        self.assertEqual(receipt.profile_id, SYNTHETIC_TEST_PROFILE_ID)
        self.assertEqual(receipt.public_inputs, values)
        self.assertEqual(receipt.settlement_domain, values[1])
        self.assertEqual(receipt.batch_id, "11" * 32)
        self.assertEqual(receipt.proof_digest_sha3_512, sha3_512(proof).hexdigest())
        self.assertEqual(
            receipt.verifier_artifact_digest_sha3_512,
            sha3_512(b"synthetic-verifier-artifact-v1").hexdigest(),
        )

        with self.assertRaisesRegex(ValueError, "verifier_receipt_authority_mismatch"):
            issuer.validate(replace(receipt, batch_id="22" * 32))
        with self.assertRaisesRegex(ValueError, "verifier_receipt_authority_mismatch"):
            VerifierReceiptIssuer(adapter).validate(receipt)

    @patch.dict(os.environ, TEST_ENV, clear=False)
    def test_local_issuer_rejects_tampered_proof(self):
        values = public_inputs_v2()
        adapter = LocalSyntheticVerifierAdapter(
            verifier_key_id="NATIVE_STARK_SETTLEMENT_V1",
            artifact_bytes=b"synthetic-verifier-artifact-v1",
        )
        request = VerificationRequest.create(
            batch_id="33" * 32,
            verifier_key_id="NATIVE_STARK_SETTLEMENT_V1",
            public_inputs=values,
            proof=b"not-an-authenticated-synthetic-proof",
        )
        with self.assertRaisesRegex(ValueError, "synthetic_verifier_proof_invalid"):
            VerifierReceiptIssuer(adapter).issue(request)

    def test_missing_real_adapter_fails_closed(self):
        request = VerificationRequest.create(
            batch_id="44" * 32,
            verifier_key_id="NATIVE_STARK_SETTLEMENT_V1",
            public_inputs=public_inputs_v2(),
            proof=b"opaque-proof",
        )
        with self.assertRaisesRegex(RuntimeError, "production_verifier_adapter_unavailable"):
            VerifierReceiptIssuer().issue(request)

    def test_public_input_shape_and_canonical_field_rules_fail_closed(self):
        values = list(public_inputs_v2())
        with self.assertRaisesRegex(ValueError, "privacy_v2_public_input_count_mismatch"):
            canonical_public_inputs_v2(values[:-1])
        values = list(public_inputs_v2())
        values[3] = 3
        with self.assertRaisesRegex(ValueError, "privacy_v2_public_input_3_not_canonical_hex"):
            canonical_public_inputs_v2(values)
        values = list(public_inputs_v2())
        values[3] = "0X" + values[3][2:]
        with self.assertRaisesRegex(ValueError, "privacy_v2_public_input_3_not_canonical_hex"):
            canonical_public_inputs_v2(values)
        values = list(public_inputs_v2())
        values[4] = f"{FIELD_MODULUS:064x}"
        with self.assertRaisesRegex(ValueError, "privacy_v2_public_input_not_stark_field:4"):
            canonical_public_inputs_v2(values)
        with self.assertRaisesRegex(ValueError, "verifier_key_id_invalid"):
            VerificationRequest.create(
                batch_id="55" * 32,
                verifier_key_id=123,
                public_inputs=public_inputs_v2(),
                proof=b"opaque-proof",
            )

    def test_synthetic_verifier_cannot_activate_in_production(self):
        with patch.dict(
            os.environ,
            {
                "BL_ENV": "production",
                "BL_DEV": "1",
                "BL_ALLOW_LOCAL_ENFORCEMENT_DISABLE": "1",
            },
            clear=False,
        ):
            with self.assertRaisesRegex(RuntimeError, "synthetic_verifier_forbidden"):
                LocalSyntheticVerifierAdapter(
                    verifier_key_id="NATIVE_STARK_SETTLEMENT_V1",
                    artifact_bytes=b"synthetic-verifier-artifact-v1",
                )

    @patch.dict(os.environ, TEST_ENV, clear=False)
    def test_direct_request_construction_cannot_bypass_canonical_factory(self):
        adapter = LocalSyntheticVerifierAdapter(
            verifier_key_id="NATIVE_STARK_SETTLEMENT_V1",
            artifact_bytes=b"synthetic-verifier-artifact-v1",
        )
        issuer = VerifierReceiptIssuer(adapter)
        malformed_requests = (
            VerificationRequest(
                batch_id="66" * 32,
                verifier_key_id="NATIVE_STARK_SETTLEMENT_V1",
                public_inputs=list(public_inputs_v2()),  # type: ignore[arg-type]
                proof=b"proof",
            ),
            VerificationRequest(
                batch_id="66" * 32,
                verifier_key_id="NATIVE_STARK_SETTLEMENT_V1",
                public_inputs=public_inputs_v2(),
                proof=bytearray(b"proof"),  # type: ignore[arg-type]
            ),
            VerificationRequest(
                batch_id=66,  # type: ignore[arg-type]
                verifier_key_id="NATIVE_STARK_SETTLEMENT_V1",
                public_inputs=public_inputs_v2(),
                proof=b"proof",
            ),
        )
        for request in malformed_requests:
            with self.subTest(request=request):
                with self.assertRaises(ValueError):
                    issuer.issue(request)
                with self.assertRaises(ValueError):
                    adapter.synthetic_proof(request)


if __name__ == "__main__":
    unittest.main()
