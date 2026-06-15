import copy
import csv
import unittest
from pathlib import Path

from app.generator_835 import generate_835
from app.rules_engine_fallback import adjudicate
from tests.test_rules_engine_coverage import (
    base_context,
    g1_fail,
    g2_fail,
    g3_fail,
    g4_fail,
    g5_fail,
    g6_fail,
    g7_fail,
    g8_fail_above_threshold,
    g8_fail_zero_total,
    g9_fail,
    g10_fail,
)


ROOT = Path(__file__).resolve().parents[1]


def load_mapping() -> dict[str, tuple[str, str]]:
    with (ROOT / "rarc_mapping.tsv").open(encoding="utf-8", newline="") as handle:
        return {
            row["reason"]: (row["carc"], row["rarc"])
            for row in csv.DictReader(handle, delimiter="\t")
        }


DENIAL_CASES = [
    ("g1_member_id_missing", g1_fail, "member_id_missing"),
    ("g2_eligibility_inactive", g2_fail, "eligibility_inactive"),
    ("g3_provider_npi_missing", g3_fail, "provider_npi_missing"),
    ("g4_provider_not_enrolled", g4_fail, "provider_not_enrolled"),
    ("g5_service_line_missing", g5_fail, "service_line_missing"),
    ("g6_diagnosis_missing", g6_fail, "diagnosis_missing"),
    ("g7_prior_auth_required", g7_fail, "prior_authorization_required"),
    ("g8_invalid_charge", g8_fail_zero_total, "invalid_charge"),
    ("g8_excessive_charge", g8_fail_above_threshold, "excessive_charge"),
    ("g9_duplicate_claim", g9_fail, "duplicate_claim"),
    ("g10_program_integrity_hold", g10_fail, "program_integrity_hold"),
]


def segment_count(edi: str) -> int:
    segments = [segment.strip() for segment in edi.split("~") if segment.strip()]
    st_index = next(index for index, segment in enumerate(segments) if segment.startswith("ST*"))
    se_index = next(index for index, segment in enumerate(segments) if segment.startswith("SE*"))
    return se_index - st_index + 1


class Generator835Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mapping = load_mapping()

    def test_approved_claim_has_payment_structure_and_dynamic_se_count(self):
        ctx = base_context()
        result = adjudicate(ctx)
        edi = generate_835(ctx, result)

        self.assertTrue(result.approved)
        self.assertIn("ISA*", edi)
        self.assertIn("GS*HP*", edi)
        self.assertIn("ST*835*0001~", edi)
        self.assertIn("BPR*I*125.00*C*CHK", edi)
        self.assertIn("CLP*TEST-CLAIM*1*125.00*125.00**MC*TEST-CLAIM*11~", edi)
        self.assertIn("SVC*HC:99213*125.00*125.00**1~", edi)
        self.assertNotIn("CAS*CO*", edi)
        self.assertNotIn("LQ*HE*", edi)
        self.assertIn(f"SE*{segment_count(edi)}*0001~", edi)

    def run_denial_case(self, _name, mutator, reason):
        ctx = copy.deepcopy(base_context())
        mutator(ctx)
        result = adjudicate(ctx)
        carc, rarc = self.mapping[reason]
        edi = generate_835(ctx, result)

        self.assertFalse(result.approved)
        self.assertEqual(result.denial_reason, reason)
        self.assertIn(f"CLP*{ctx.claim_id}*4*", edi)
        self.assertIn(f"CAS*CO*{carc}*{ctx.total_charge:.2f}~", edi)
        if rarc:
            self.assertIn(f"LQ*HE*{rarc}~", edi)
        else:
            self.assertNotIn("LQ*HE*", edi)
        self.assertIn(f"WO:{reason}", edi)
        self.assertIn(f"SE*{segment_count(edi)}*0001~", edi)

    def test_malformed_input_raises_graceful_error(self):
        with self.assertRaisesRegex(ValueError, "malformed_835_input"):
            generate_835(None, None)


def make_denial_test(case):
    def test(self):
        self.run_denial_case(*case)

    test.__name__ = f"test_denial_835_{case[0]}"
    return test


for denial_case in DENIAL_CASES:
    setattr(Generator835Tests, f"test_denial_835_{denial_case[0]}", make_denial_test(denial_case))


if __name__ == "__main__":
    unittest.main()
