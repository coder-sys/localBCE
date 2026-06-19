import copy
import json
import unittest
from pathlib import Path

from app.batch.leaf import build_claim_leaf_set
from app.generator_835 import generate_835
from app.ingestion import parse_837
from app.models import AdjudicationResult, GateResult
from app.rules_engine_adapter import adjudicate
from app.shared_context import build_shared_context


ROOT = Path(__file__).resolve().parents[2]
RULESET = "rarc_mapping_v1_pending_domain_ratification"


def sample_payload(claim_id="BL-HANDOFF-0001", flags=None, edi_transform=None):
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


class HandoffFullFlowAttackTests(unittest.TestCase):
    def test_parser_context_bht_clm_claim_id_mismatch_is_rejected(self):
        def mismatch_bht(edi):
            return edi.replace("BHT*0019*00*BL-HANDOFF-BHT", "BHT*0019*00*OTHER-BHT-ID")

        payload = sample_payload("BL-HANDOFF-BHT", edi_transform=mismatch_bht)
        parsed = parse_837(payload["edi"])

        self.assertFalse(parsed.accepted)
        self.assertIn("claim_id_mismatch_BHT_CLM", parsed.errors)

    def test_context_rules_missing_service_date_is_rejected(self):
        def remove_service_date(edi):
            return edi.replace("DTP*472*D8*20260601~", "")

        parsed = parse_837(sample_payload("BL-HANDOFF-NODATE", edi_transform=remove_service_date)["edi"])

        self.assertFalse(parsed.accepted)
        self.assertIn("missing_service_date", parsed.errors)

    def test_context_rules_zero_unit_service_line_is_rejected_before_835(self):
        def zero_units(edi):
            return edi.replace("SV1*HC:99213*125.00*UN*1", "SV1*HC:99213*125.00*UN*0")

        parsed = parse_837(sample_payload("BL-HANDOFF-ZEROUNIT", edi_transform=zero_units)["edi"])

        self.assertFalse(parsed.accepted)
        self.assertIn("invalid_SV1_units", parsed.errors)

    def test_engine_to_835_claim_id_mismatch_is_rejected(self):
        ctx = context_from_payload(sample_payload("BL-HANDOFF-CTX"))
        foreign_result = AdjudicationResult(
            claim_id="BL-HANDOFF-FOREIGN",
            approved=False,
            denial_reason="eligibility_inactive",
            gates=[GateResult("G2_ELIGIBILITY_ACTIVE", False, "eligibility_inactive")],
            carc="27",
            rarc="N30",
            total_charge=125.0,
            payable_amount=0.0,
        )

        with self.assertRaisesRegex(ValueError, "claim_id_mismatch_835"):
            generate_835(ctx, foreign_result)

    def test_engine_to_leaf_builder_result_claim_id_mismatch_is_rejected(self):
        ctx = context_from_payload(sample_payload("BL-HANDOFF-LEAF"))
        result = adjudicate(ctx)
        foreign = copy.deepcopy(result)
        foreign.claim_id = "BL-HANDOFF-FOREIGN-LEAF"

        with self.assertRaisesRegex(ValueError, "claim_id_mismatch_result_leaf"):
            build_claim_leaf_set(ctx, foreign, RULESET, "original")

    def test_engine_to_leaf_builder_gate_evidence_is_bound_to_result_leaf(self):
        ctx = context_from_payload(sample_payload("BL-HANDOFF-GATES"))
        result = adjudicate(ctx)
        impossible = copy.deepcopy(result)
        impossible.gates = [GateResult("G2_ELIGIBILITY_ACTIVE", False, "eligibility_inactive")]

        normal_leaf = build_claim_leaf_set(ctx, result, RULESET, "original")
        impossible_leaf = build_claim_leaf_set(ctx, impossible, RULESET, "original")

        self.assertTrue(impossible.approved)
        self.assertNotEqual(normal_leaf.result_leaf, impossible_leaf.result_leaf)


if __name__ == "__main__":
    unittest.main()
