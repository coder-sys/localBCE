import unittest
from pathlib import Path

from app.models import Patient, Provider, ServiceLine, SharedContext
from app.policy_spec import load_policy_spec, policy_gate_ids
from app.rules_engine_fallback import evaluate_gates


APP_ROOT = Path(__file__).resolve().parents[1]


def base_context() -> SharedContext:
    return SharedContext(
        claim_id="POLICY-SPEC-CLAIM",
        transaction_set="837",
        payer_id="CA-MMIS",
        member_id="M123",
        patient=Patient(name="JANE DOE", id="M123"),
        provider=Provider(npi="1999999984", name="ALICE ADAMS"),
        service_date="20260601",
        diagnoses=["F840"],
        service_lines=[ServiceLine("1", "99213", 125.0, 1.0, "PA-OK")],
        total_charge=125.0,
        flags={
            "eligibility_active": True,
            "provider_enrolled": True,
            "provider_not_suspended": True,
            "not_deceased": True,
            "duplicate_claim": False,
            "program_integrity_hold": False,
        },
    )


class PolicySpecAlignmentTests(unittest.TestCase):
    def test_policy_spec_is_the_narrow_medi_cal_wedge(self):
        spec = load_policy_spec()

        self.assertEqual(spec["jurisdiction"], "CA")
        self.assertEqual(spec["program"], "Medi-Cal")
        self.assertEqual(spec["service_wedge"]["transaction"], "837P")
        self.assertIn("99213", spec["service_wedge"]["procedure_codes"])
        self.assertIn("official_source", spec["source_to_execution_flow"])
        self.assertIn("executable_policy_artifact", spec["source_to_execution_flow"])

    def test_python_gate_order_matches_policy_spec(self):
        self.assertEqual([gate.gate for gate in evaluate_gates(base_context())], policy_gate_ids())

    def test_rust_gate_names_match_policy_spec(self):
        source = (APP_ROOT / "rules-engine-rust" / "src" / "lib.rs").read_text(encoding="utf-8")
        for gate_id in policy_gate_ids():
            self.assertIn(gate_id, source)

    def test_cairo_gate_logic_exposes_policy_spec_splits(self):
        source = (APP_ROOT / "zk-cairo-sharp" / "src" / "lib.cairo").read_text(encoding="utf-8")

        for marker in ("let g2b", "let g4b", "let g8a", "let g8b", "diagnosis_count"):
            self.assertIn(marker, source)
        self.assertNotIn("provider_payable == 1 && input.facts.provider_not_suspended == 1", source)


if __name__ == "__main__":
    unittest.main()
