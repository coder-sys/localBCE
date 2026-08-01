import json
import math
import unittest
from pathlib import Path

from app.appeal_router import route_appeal
from app.generator_835 import generate_835
from app.ingestion import parse_837
from app.models import AdjudicationResult, GateResult, Patient, Provider, ServiceLine, SharedContext
from app.rules_engine_adapter import adjudicate
from app.shared_context import build_shared_context


ROOT = Path(__file__).resolve().parents[2]


def sample_payload(claim_id="BL-FRESH-0001", flags=None, edi_transform=None):
    payload = json.loads((ROOT / "sample_claim_input.json").read_text(encoding="utf-8"))
    payload["edi"] = payload["edi"].replace("BL-CLAIM-0001", claim_id)
    if flags:
        payload["flags"].update(flags)
    if edi_transform:
        payload["edi"] = edi_transform(payload["edi"])
    return payload


def context_from_payload(payload):
    parsed = parse_837(payload["edi"])
    if not parsed.accepted:
        raise AssertionError(parsed.errors)
    return build_shared_context(parsed, payload["flags"], strict_oracle=False)


class FreshWholeAppAttackTests(unittest.TestCase):
    def test_fresh_835_segment_injection_via_claim_id_blocked(self):
        injected_claim = "BL-FRESH-INJECT~N1*EV*EVIL PAYEE"
        ctx = SharedContext(
            claim_id=injected_claim,
            transaction_set="837",
            payer_id="PAYER",
            member_id="MEM123",
            patient=Patient("Test Patient", "MEM123"),
            provider=Provider("1999999987", "ADAMS ALICE"),
            service_date="20260612",
            diagnoses=["Z0000"],
            service_lines=[ServiceLine("1", "99213", 125.0, 1.0)],
            total_charge=125.0,
        )
        result = AdjudicationResult(
            claim_id=injected_claim,
            approved=True,
            denial_reason="",
            gates=[],
            carc="",
            rarc="",
            total_charge=125.0,
            payable_amount=125.0,
        )

        with self.assertRaisesRegex(ValueError, "unsafe_835_field:claim_id"):
            generate_835(ctx, result)

    def test_fresh_string_false_flag_denies_instead_of_truthy_approval(self):
        ctx = context_from_payload(sample_payload("BL-FRESH-FLAG", flags={"eligibility_active": "False"}))
        result = adjudicate(ctx)

        self.assertFalse(ctx.flags["eligibility_active"])
        self.assertFalse(result.approved)
        self.assertEqual(result.denial_reason, "eligibility_inactive")

    def test_fresh_clm_sv1_amount_mismatch_rejected_before_835_blocked(self):
        def mismatch(edi):
            return edi.replace("SV1*HC:99213*125.00", "SV1*HC:99213*6000.00")

        with self.assertRaisesRegex(ValueError, "claim_total_mismatch"):
            context_from_payload(sample_payload("BL-FRESH-AMOUNT-MISMATCH", edi_transform=mismatch))

    def test_fresh_appeal_reason_trailing_space_routes_program_integrity(self):
        result = AdjudicationResult(
            claim_id="BL-FRESH-APPEAL",
            approved=False,
            denial_reason="program_integrity_hold ",
            gates=[GateResult("G10", False, "program_integrity_hold ")],
            carc="16",
            rarc="N770",
            total_charge=125.0,
            payable_amount=0.0,
        )

        self.assertEqual(route_appeal(result), "program_integrity")

    def test_fresh_duplicate_clm_segments_are_rejected(self):
        def duplicate_clm(edi):
            return edi.replace("CLM*BL-FRESH-DUPCLM*125.00", "CLM*BL-FRESH-DUPCLM*125.00~CLM*EVIL-SECOND-CLAIM*9999.00")

        payload = sample_payload("BL-FRESH-DUPCLM", edi_transform=duplicate_clm)
        parsed = parse_837(payload["edi"])

        self.assertFalse(parsed.accepted)
        self.assertIn("duplicate_CLM", parsed.errors)
        self.assertEqual(len([seg for seg in parsed.segments if seg and seg[0] == "CLM"]), 2)

    def test_fresh_nan_money_rejected_before_context_and_835(self):
        def nan_money(edi):
            return edi.replace("CLM*BL-FRESH-NAN*125.00", "CLM*BL-FRESH-NAN*NaN").replace("SV1*HC:99213*125.00", "SV1*HC:99213*NaN")

        parsed = parse_837(sample_payload("BL-FRESH-NAN", edi_transform=nan_money)["edi"])

        self.assertFalse(parsed.accepted)
        self.assertIn("invalid_CLM_amount", parsed.errors)
        self.assertIn("invalid_SV1_amount", parsed.errors)


if __name__ == "__main__":
    unittest.main()
