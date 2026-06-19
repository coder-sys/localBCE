import json
import unittest
from pathlib import Path

from app.ingestion import parse_837
from app.oracle_attestation import VERIFIED, make_test_attestation
from app.shared_context import build_shared_context


ROOT = Path(__file__).resolve().parents[1]


def parsed_sample():
    payload = json.loads((ROOT / "sample_claim_input.json").read_text(encoding="utf-8"))
    parsed = parse_837(payload["edi"])
    if not parsed.accepted:
        raise AssertionError(parsed.errors)
    return parsed, payload


class OracleAttestationTests(unittest.TestCase):
    def test_signed_oracle_attestations_are_accepted_in_strict_mode(self):
        parsed, payload = parsed_sample()
        attestations = [
            make_test_attestation("eligibility_active", True, source_id="CA-MMIS-TEST"),
            make_test_attestation("provider_enrolled", True, source_id="PROVIDER-ENROLLMENT-TEST"),
            make_test_attestation("provider_not_suspended", True, source_id="SUSPENDED-PROVIDER-TEST"),
            make_test_attestation("not_deceased", True, source_id="DEATH-MASTER-TEST"),
        ]

        ctx = build_shared_context(parsed, payload["flags"], oracle_attestations=attestations, strict_oracle=True)

        self.assertTrue(ctx.flags["eligibility_active"])
        self.assertTrue(ctx.flags["provider_enrolled"])
        self.assertTrue(ctx.flags["provider_not_suspended"])
        self.assertTrue(ctx.flags["not_deceased"])
        self.assertEqual(ctx.fact_verification["eligibility_active"], VERIFIED)

    def test_unsigned_or_forged_oracle_attestation_rejected_in_strict_mode(self):
        parsed, payload = parsed_sample()
        forged = make_test_attestation("eligibility_active", True)
        forged = {**forged.to_dict(), "signature": "00" * 32}

        with self.assertRaisesRegex(ValueError, "oracle_attestation_invalid"):
            build_shared_context(parsed, payload["flags"], oracle_attestations=[forged], strict_oracle=True)

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
