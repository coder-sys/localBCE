import base64
import os
import unittest
from unittest.mock import patch

from pqcrypto.sign import sphincs_sha2_128f_simple as oracle_signature

from app.oracle_attestation import (
    LOCAL_TEST_ORACLE_KEYS_ENV,
    ORACLE_PUBLIC_KEY_ENV,
    ORACLE_TEST_PRIVATE_KEY_ENV,
    VERIFIED,
    make_test_attestation,
    resolve_attested_flags,
    verify_oracle_attestation,
)


class OracleAttestationTests(unittest.TestCase):
    def test_checked_in_dev_key_refused_in_staging_even_when_bl_dev_is_set(self):
        with patch.dict(os.environ, {"BL_ENV": "staging", "BL_DEV": "1"}, clear=False):
            os.environ.pop(LOCAL_TEST_ORACLE_KEYS_ENV, None)
            os.environ.pop(ORACLE_PUBLIC_KEY_ENV, None)
            os.environ.pop(ORACLE_TEST_PRIVATE_KEY_ENV, None)

            with self.assertRaisesRegex(RuntimeError, "missing oracle signing key outside dev mode"):
                make_test_attestation(
                    "eligibility_active",
                    True,
                    source_id="ATTACKER_CONTROLLED_DEV_KEY",
                    claim_id="BL-STAGING-DEV-KEY-REJECTED",
                )

    def test_local_test_dev_key_requires_explicit_opt_in_and_still_verifies(self):
        with patch.dict(os.environ, {"BL_DEV": "1", LOCAL_TEST_ORACLE_KEYS_ENV: "1"}, clear=False):
            os.environ.pop("BL_ENV", None)
            os.environ.pop(ORACLE_PUBLIC_KEY_ENV, None)
            os.environ.pop(ORACLE_TEST_PRIVATE_KEY_ENV, None)

            attestation = make_test_attestation(
                "eligibility_active",
                True,
                source_id="LOCAL-TEST-ORACLE",
                claim_id="BL-LOCAL-DEV-KEY-ALLOWED",
                claim_source_commitment=17,
            )
            flags, status = resolve_attested_flags(
                {"eligibility_active": False},
                [attestation],
                strict=True,
                required_facts=["eligibility_active"],
                claim_id="BL-LOCAL-DEV-KEY-ALLOWED",
                claim_source_commitment=17,
            )

        self.assertTrue(flags["eligibility_active"])
        self.assertEqual(status["eligibility_active"], VERIFIED)

    def test_wrong_key_signature_rejected_in_strict_mode(self):
        commitment = 17
        attestation = make_test_attestation(
            "eligibility_active",
            True,
            claim_id="BL-CLAIM-0001",
            claim_source_commitment=commitment,
        )
        _wrong_public_key, wrong_secret_key = oracle_signature.generate_keypair()
        wrong_signature = oracle_signature.sign(wrong_secret_key, attestation.signed_payload())
        wrong_key_attestation = {
            **attestation.to_dict(),
            "signature": base64.b64encode(wrong_signature).decode("ascii"),
        }

        self.assertFalse(
            verify_oracle_attestation(
                wrong_key_attestation,
                claim_id="BL-CLAIM-0001",
                claim_source_commitment=commitment,
            )
        )
        with self.assertRaisesRegex(ValueError, "oracle_attestation_invalid"):
            resolve_attested_flags(
                {"eligibility_active": False},
                [wrong_key_attestation],
                strict=True,
                required_facts=["eligibility_active"],
                claim_id="BL-CLAIM-0001",
                claim_source_commitment=commitment,
            )

    def test_future_validity_window_rejected_in_strict_mode(self):
        commitment = 17
        future = make_test_attestation(
            "eligibility_active",
            True,
            claim_id="BL-CLAIM-0001",
            valid_from="2999-01-01",
            valid_until="2999-12-31",
            claim_source_commitment=commitment,
        )

        self.assertFalse(
            verify_oracle_attestation(
                future,
                claim_id="BL-CLAIM-0001",
                claim_source_commitment=commitment,
            )
        )
        with self.assertRaisesRegex(ValueError, "oracle_attestation_invalid"):
            resolve_attested_flags(
                {"eligibility_active": False},
                [future],
                strict=True,
                required_facts=["eligibility_active"],
                claim_id="BL-CLAIM-0001",
                claim_source_commitment=commitment,
            )


if __name__ == "__main__":
    unittest.main()
