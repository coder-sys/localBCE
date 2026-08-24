import json
import os
import unittest
from pathlib import Path
from unittest.mock import patch

from app.batch.leaf import current_duplicate_pepper, stable_private_hash
from app.ingestion import MAX_EDI_CHARS, parse_837
from app.batch.stark_encoding import canonical_npi
from app.oracle_attestation import make_test_attestation, verify_oracle_attestation
from app.shared_context import build_shared_context


ROOT = Path(__file__).resolve().parents[1]


def sample_payload(claim_id="BL-HARDENING-0001", edi_transform=None):
    payload = json.loads((ROOT / "sample_claim_input.json").read_text(encoding="utf-8"))
    payload["edi"] = payload["edi"].replace("BL-CLAIM-0001", claim_id)
    if edi_transform:
        payload["edi"] = edi_transform(payload["edi"])
    return payload


class ConsolidatedHardeningTests(unittest.TestCase):
    def test_typed_length_prefixed_encoding_blocks_demonstrated_collisions(self):
        self.assertNotEqual(stable_private_hash(["A|B", "C"]), stable_private_hash(["A", "B|C"]))
        self.assertNotEqual(stable_private_hash(1), stable_private_hash(True))
        self.assertNotEqual(stable_private_hash(1), stable_private_hash("1"))
        self.assertNotEqual(stable_private_hash(True), stable_private_hash("1"))

    def test_noncanonical_member_id_rejected_before_nullifier_build(self):
        payload = sample_payload("BL-HARDEN-MEMBER", lambda edi: edi.replace("MI*M123456789", "MI* 1234"))
        parsed = parse_837(payload["edi"])
        self.assertTrue(parsed.accepted)
        with self.assertRaisesRegex(ValueError, "noncanonical_member_id"):
            build_shared_context(parsed, payload["flags"], strict_oracle=False)

    def test_noncanonical_npi_and_procedure_rejected(self):
        npi_payload = sample_payload("BL-HARDEN-NPI", lambda edi: edi.replace("XX*1999999984", "XX*199999998 "))
        with self.assertRaisesRegex(ValueError, "noncanonical_npi"):
            build_shared_context(parse_837(npi_payload["edi"]), npi_payload["flags"], strict_oracle=False)

        bad_digit_payload = sample_payload("BL-HARDEN-NPI-DIGIT", lambda edi: edi.replace("XX*1999999984", "XX*1999999987"))
        with self.assertRaisesRegex(ValueError, "invalid_npi_check_digit"):
            build_shared_context(parse_837(bad_digit_payload["edi"]), bad_digit_payload["flags"], strict_oracle=False)

        unicode_npi = "\u0661\u0669\u0669\u0669\u0669\u0669\u0669\u0669\u0668\u0664"
        unicode_payload = sample_payload("BL-HARDEN-NPI-UNICODE", lambda edi: edi.replace("XX*1999999984", f"XX*{unicode_npi}"))
        with self.assertRaisesRegex(ValueError, "noncanonical_npi"):
            build_shared_context(parse_837(unicode_payload["edi"]), unicode_payload["flags"], strict_oracle=False)
        with self.assertRaisesRegex(ValueError, "npi_must_be_10_decimal_digits"):
            canonical_npi(unicode_npi)

        proc_payload = sample_payload("BL-HARDEN-PROC", lambda edi: edi.replace("SV1*HC:99213", "SV1*HC:ab123"))
        with self.assertRaisesRegex(ValueError, "noncanonical_procedure_code"):
            build_shared_context(parse_837(proc_payload["edi"]), proc_payload["flags"], strict_oracle=False)

    def test_ingestion_rejects_oversized_and_over_50_line_claims_before_context_build(self):
        oversized = parse_837("X" * (MAX_EDI_CHARS + 1))
        self.assertFalse(oversized.accepted)
        self.assertEqual(oversized.errors, ["edi_size_exceeds_prototype_limit"])
        self.assertEqual(oversized.segments, [])

        payload = sample_payload("BL-HARDEN-LINE-CAP")
        service_line = "SV1*HC:99213*125.00*UN*1***1"
        over_limit_edi = payload["edi"].replace(service_line, "~".join([service_line] * 51))
        parsed = parse_837(over_limit_edi)
        self.assertFalse(parsed.accepted)
        self.assertIn("service_line_count_exceeds_proof_limit", parsed.errors)

    def test_unattested_required_facts_fail_closed_by_default(self):
        payload = sample_payload("BL-HARDEN-STRICT-DEFAULT")
        with self.assertRaisesRegex(ValueError, "oracle_attestation_required"):
            build_shared_context(parse_837(payload["edi"]), payload["flags"])

    def test_noncanonical_claim_hash_fields_rejected(self):
        claim_payload = sample_payload("bl-harden-claim")
        with self.assertRaisesRegex(ValueError, "noncanonical_claim_id"):
            build_shared_context(parse_837(claim_payload["edi"]), claim_payload["flags"], strict_oracle=False)

        prior_auth_payload = sample_payload(
            "BL-HARDEN-PRIOR-AUTH",
            lambda edi: edi.replace("REF*G1*PA-OK-123", "REF*G1*pa-ok-123"),
        )
        with self.assertRaisesRegex(ValueError, "noncanonical_prior_authorization"):
            build_shared_context(
                parse_837(prior_auth_payload["edi"]),
                prior_auth_payload["flags"],
                strict_oracle=False,
            )

        diagnosis_payload = sample_payload("BL-HARDEN-DIAG", lambda edi: edi.replace("HI*ABK:F840", "HI*ABK:f840"))
        with self.assertRaisesRegex(ValueError, "noncanonical_diagnosis"):
            build_shared_context(parse_837(diagnosis_payload["edi"]), diagnosis_payload["flags"], strict_oracle=False)

        payer_payload = sample_payload("BL-HARDEN-PAYER", lambda edi: edi.replace("PI*CA-MMIS", "PI*ca-mmis"))
        with self.assertRaisesRegex(ValueError, "noncanonical_payer_id"):
            build_shared_context(parse_837(payer_payload["edi"]), payer_payload["flags"], strict_oracle=False)

        patient_payload = sample_payload("BL-HARDEN-PATIENT", lambda edi: edi.replace("NM1*IL*1*DOE*JANE", "NM1*IL*1*DOE*Jane"))
        with self.assertRaisesRegex(ValueError, "noncanonical_patient_name"):
            build_shared_context(parse_837(patient_payload["edi"]), patient_payload["flags"], strict_oracle=False)

    def test_duplicate_pepper_missing_without_dev_fails_closed(self):
        env = {key: value for key, value in os.environ.items() if key not in {"BL_DEV", "BL_DUPLICATE_CHECK_PEPPER", "BL_ENV"}}
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaisesRegex(RuntimeError, "missing required duplicate pepper"):
                current_duplicate_pepper()

    def test_oracle_expired_forged_and_replayed_attestations_reject(self):
        good = make_test_attestation("eligibility_active", True, claim_id="BL-HARDEN-ORACLE", claim_source_commitment=17)
        self.assertTrue(verify_oracle_attestation(good, claim_id="BL-HARDEN-ORACLE", claim_source_commitment=17))
        self.assertFalse(verify_oracle_attestation(good, claim_id="OTHER-CLAIM", claim_source_commitment=17))

        expired = make_test_attestation(
            "eligibility_active",
            True,
            claim_id="BL-HARDEN-ORACLE",
            valid_from="2020-01-01",
            valid_until="2020-12-31",
            claim_source_commitment=17,
        )
        self.assertFalse(verify_oracle_attestation(expired, claim_id="BL-HARDEN-ORACLE", claim_source_commitment=17))

        replay_cache = set()
        self.assertTrue(verify_oracle_attestation(good, claim_id="BL-HARDEN-ORACLE", claim_source_commitment=17, replay_cache=replay_cache))
        self.assertFalse(verify_oracle_attestation(good, claim_id="BL-HARDEN-ORACLE", claim_source_commitment=17, replay_cache=replay_cache))

if __name__ == "__main__":
    unittest.main()
