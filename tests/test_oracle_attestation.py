import base64
import json
import os
import unittest
from pathlib import Path
from unittest.mock import patch

from pqcrypto.sign import sphincs_sha2_128f_simple as oracle_signature

from app.ingestion import parse_837
from app.batch.batch_orchestrator import BatchConfig, _claim_source_commitment_for_oracle
from app.batch.leaf import current_duplicate_pepper
from app.oracle_attestation import (
    LOCAL_TEST_ORACLE_KEYS_ENV,
    ORACLE_PUBLIC_KEY_ENV,
    ORACLE_TEST_PRIVATE_KEY_ENV,
    VERIFIED,
    make_test_attestation,
    resolve_attested_flags,
    verify_oracle_attestation,
)
from app.shared_context import build_shared_context


ROOT = Path(__file__).resolve().parents[1]


def parsed_sample():
    payload = json.loads((ROOT / "sample_claim_input.json").read_text(encoding="utf-8"))
    parsed = parse_837(payload["edi"])
    if not parsed.accepted:
        raise AssertionError(parsed.errors)
    return parsed, payload


def claim_source_commitment_for(parsed, flags):
    ctx = build_shared_context(parsed, flags, strict_oracle=False)
    return _claim_source_commitment_for_oracle(
        ctx,
        config=BatchConfig(),
        frequency_type="original",
        duplicate_pepper=current_duplicate_pepper(),
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

    def test_signed_oracle_attestations_are_accepted_in_strict_mode(self):
        parsed, payload = parsed_sample()
        commitment = claim_source_commitment_for(parsed, payload["flags"])
        attestations = [
            make_test_attestation("eligibility_active", True, source_id="CA-MMIS-TEST", claim_source_commitment=commitment),
            make_test_attestation("provider_enrolled", True, source_id="PROVIDER-ENROLLMENT-TEST", claim_source_commitment=commitment),
            make_test_attestation("provider_not_suspended", True, source_id="SUSPENDED-PROVIDER-TEST", claim_source_commitment=commitment),
            make_test_attestation("not_deceased", True, source_id="DEATH-MASTER-TEST", claim_source_commitment=commitment),
            make_test_attestation("duplicate_claim", False, source_id="DUPLICATE-CLAIM-TEST", claim_source_commitment=commitment),
            make_test_attestation("program_integrity_hold", False, source_id="PROGRAM-INTEGRITY-TEST", claim_source_commitment=commitment),
        ]

        ctx = build_shared_context(
            parsed,
            payload["flags"],
            oracle_attestations=attestations,
            strict_oracle=True,
            claim_source_commitment=commitment,
        )

        self.assertTrue(ctx.flags["eligibility_active"])
        self.assertTrue(ctx.flags["provider_enrolled"])
        self.assertTrue(ctx.flags["provider_not_suspended"])
        self.assertTrue(ctx.flags["not_deceased"])
        self.assertEqual(ctx.fact_verification["eligibility_active"], VERIFIED)

    def test_unsigned_or_forged_oracle_attestation_rejected_in_strict_mode(self):
        parsed, payload = parsed_sample()
        commitment = claim_source_commitment_for(parsed, payload["flags"])
        forged = make_test_attestation("eligibility_active", True, claim_source_commitment=commitment)
        forged = {**forged.to_dict(), "signature": "00" * 32}

        with self.assertRaisesRegex(ValueError, "oracle_attestation_invalid"):
            build_shared_context(
                parsed,
                payload["flags"],
                oracle_attestations=[forged],
                strict_oracle=True,
                claim_source_commitment=commitment,
            )

    def test_wrong_key_signature_rejected_in_strict_mode(self):
        parsed, payload = parsed_sample()
        commitment = claim_source_commitment_for(parsed, payload["flags"])
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
        parsed, payload = parsed_sample()
        commitment = claim_source_commitment_for(parsed, payload["flags"])
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

    def test_raw_flags_fail_closed_by_default(self):
        parsed, payload = parsed_sample()

        with self.assertRaisesRegex(ValueError, "oracle_attestation_required"):
            build_shared_context(parsed, payload["flags"])

    def test_raw_flags_are_marked_unverified_when_non_strict_is_explicit(self):
        parsed, payload = parsed_sample()
        ctx = build_shared_context(parsed, payload["flags"], strict_oracle=False)

        self.assertTrue(ctx.flags["eligibility_active"])
        self.assertEqual(ctx.fact_verification["eligibility_active"], "UNVERIFIED")


if __name__ == "__main__":
    unittest.main()
