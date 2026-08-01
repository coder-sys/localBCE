from __future__ import annotations

import unittest

from app.batch.claim_source_root import claim_source_diagnosis_commitment
from app.batch.stark_encoding import encode_claim, pack_felt_text
from app.canonical_order import canonical_diagnoses
from app.models import Patient, Provider, ServiceLine, SharedContext
from app.service_line_canonical import canonical_service_line_identities


def _context(*, diagnoses: list[str], service_lines: list[ServiceLine]) -> SharedContext:
    return SharedContext(
        claim_id="BL-SYNTH-FOUNDATION-ORDER",
        transaction_set="837",
        payer_id="CA-MMIS",
        member_id="SYNTH-MEMBER-001",
        patient=Patient(name="SYNTHETIC PATIENT", id="SYNTH-MEMBER-001"),
        provider=Provider(npi="1999999984", name="SYNTHETIC PROVIDER"),
        service_date="20260601",
        diagnoses=diagnoses,
        service_lines=service_lines,
        total_charge=sum(float(line.charge_amount) for line in service_lines),
    )


class FoundationSemanticReconciliationTests(unittest.TestCase):
    def test_length_prefixed_ascii_order_matches_felt_order(self) -> None:
        lines = [
            ServiceLine("2", "A10", 125.00, 1.0, None),
            ServiceLine("1", "Z9", 125.00, 1.0, None),
        ]
        ordered = canonical_service_line_identities(lines)
        self.assertEqual([identity[0] for identity in ordered], ["Z9", "A10"])
        self.assertLess(pack_felt_text("Z9"), pack_felt_text("A10"))

    def test_distinct_ids_allow_identical_economic_lines_but_repeated_id_rejects(self) -> None:
        distinct = [
            ServiceLine("1", "T1019", 125.00, 1.0, "PA-OK"),
            ServiceLine("2", "T1019", 125.00, 1.0, "PA-OK"),
        ]
        self.assertEqual(len(canonical_service_line_identities(distinct)), 2)
        repeated = [distinct[0], ServiceLine("1", "99213", 125.00, 1.0, None)]
        with self.assertRaisesRegex(ValueError, "service_line_id_duplicate"):
            canonical_service_line_identities(repeated)
        with self.assertRaisesRegex(ValueError, "service_line_id_not_canonical_ascii_token"):
            canonical_service_line_identities(
                [ServiceLine("line-1", "99213", 125.00, 1.0, None)]
            )

    def test_diagnosis_order_is_length_then_ascii_and_duplicates_reject(self) -> None:
        self.assertEqual(canonical_diagnoses(["A10", "Z9"]), ("Z9", "A10"))
        self.assertNotEqual(
            claim_source_diagnosis_commitment(["Z9", "A10"]),
            claim_source_diagnosis_commitment(["Z9", "B10"]),
        )
        with self.assertRaisesRegex(ValueError, "diagnoses_duplicate"):
            canonical_diagnoses(["Z9", "Z9"])

    def test_duplicate_diagnosis_rejects_before_claim_commitment(self) -> None:
        ctx = _context(
            diagnoses=["Z9", "Z9"],
            service_lines=[ServiceLine("1", "99213", 125.00, 1.0, None)],
        )
        with self.assertRaisesRegex(ValueError, "diagnoses_duplicate"):
            encode_claim(ctx)


if __name__ == "__main__":
    unittest.main()
