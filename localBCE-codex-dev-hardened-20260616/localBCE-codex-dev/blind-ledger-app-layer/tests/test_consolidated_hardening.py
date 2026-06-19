import json
import os
import unittest
from pathlib import Path
from unittest.mock import patch

from app.batch.batch_orchestrator import _enforce_payment_reconciliation
from app.batch.leaf import current_duplicate_pepper, stable_private_hash
from app.ingestion import parse_837
from app.oracle_attestation import make_test_attestation, verify_oracle_attestation
from app.shared_context import MAX_AMOUNT_CENTS, build_shared_context


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

        proc_payload = sample_payload("BL-HARDEN-PROC", lambda edi: edi.replace("SV1*HC:99213", "SV1*HC:ab123"))
        with self.assertRaisesRegex(ValueError, "noncanonical_procedure_code"):
            build_shared_context(parse_837(proc_payload["edi"]), proc_payload["flags"], strict_oracle=False)

    def test_unattested_required_facts_fail_closed_by_default(self):
        payload = sample_payload("BL-HARDEN-STRICT-DEFAULT")
        with self.assertRaisesRegex(ValueError, "oracle_attestation_required"):
            build_shared_context(parse_837(payload["edi"]), payload["flags"])

    def test_noncanonical_claim_hash_fields_rejected(self):
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
        good = make_test_attestation("eligibility_active", True, claim_id="BL-HARDEN-ORACLE")
        self.assertTrue(verify_oracle_attestation(good, claim_id="BL-HARDEN-ORACLE"))
        self.assertFalse(verify_oracle_attestation(good, claim_id="OTHER-CLAIM"))

        expired = make_test_attestation(
            "eligibility_active",
            True,
            claim_id="BL-HARDEN-ORACLE",
            valid_from="2020-01-01",
            valid_until="2020-12-31",
        )
        self.assertFalse(verify_oracle_attestation(expired, claim_id="BL-HARDEN-ORACLE"))

        replay_cache = set()
        self.assertTrue(verify_oracle_attestation(good, claim_id="BL-HARDEN-ORACLE", replay_cache=replay_cache))
        self.assertFalse(verify_oracle_attestation(good, claim_id="BL-HARDEN-ORACLE", replay_cache=replay_cache))

    def test_amount_bounds_reject_underflow_and_overwidth(self):
        with self.assertRaisesRegex(ValueError, "payment_amount_out_of_range"):
            _enforce_payment_reconciliation("provider", [100], -1)
        with self.assertRaisesRegex(ValueError, "payment_amount_out_of_range"):
            _enforce_payment_reconciliation("provider", [MAX_AMOUNT_CENTS, 1], MAX_AMOUNT_CENTS + 1)

        payload = sample_payload(
            "BL-HARDEN-OVERWIDTH",
            lambda edi: edi.replace("CLM*BL-HARDEN-OVERWIDTH*125.00", "CLM*BL-HARDEN-OVERWIDTH*42949672.96").replace(
                "SV1*HC:99213*125.00", "SV1*HC:99213*42949672.96"
            ),
        )
        with self.assertRaisesRegex(ValueError, "amount_out_of_range"):
            build_shared_context(parse_837(payload["edi"]), payload["flags"], strict_oracle=False)


if __name__ == "__main__":
    unittest.main()
