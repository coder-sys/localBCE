import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CAIRO_LIB = ROOT / "zk-cairo-sharp" / "src" / "lib.cairo"


class CairoBindingSourceGuardTests(unittest.TestCase):
    def source(self) -> str:
        return CAIRO_LIB.read_text(encoding="utf-8")

    def test_toy_cairo_regressions_are_absent(self):
        source = self.source()
        forbidden = (
            "update_with(input)",
            "spent_nullifier_",
            "nullifier_not_spent",
            "MAX_ALLOWABLE_LINE_CHARGE_CENTS",
            "member_id_present",
            "eligibility_active:",
            "provider_enrolled:",
            "prior_auth_ok:",
            "min_service_line_charge_cents",
            "max_service_line_charge_cents",
            "total_charge_cents: u32",
        )
        for marker in forbidden:
            self.assertNotIn(marker, source)

    def test_cairo_uses_domain_and_arity_bound_poseidon_surface(self):
        source = self.source()
        for tag in (
            "DOMAIN_TAG_CLAIM_SOURCE",
            "DOMAIN_TAG_ORACLE",
            "DOMAIN_TAG_NORMALIZED_FACTS",
            "DOMAIN_TAG_FEE",
            "DOMAIN_TAG_NULLIFIER",
            "DOMAIN_TAG_PAYMENT",
        ):
            self.assertIn(tag, source)
        self.assertRegex(source, re.compile(r"PoseidonTrait::new\(\)\s*\.update\(tag\)\s*\.update\(2\)", re.MULTILINE))
        self.assertRegex(source, re.compile(r"PoseidonTrait::new\(\)\s*\.update\(tag\)\s*\.update\(4\)", re.MULTILINE))
        self.assertNotIn("cube()", source)

    def test_cairo_source_names_the_required_adversarial_vectors(self):
        source = self.source()
        for vector in (
            "fabricated_facts_rejected",
            "duplicate_by_omission_rejected",
            "procedure_substitution_rejected",
            "free_ceiling_rejected",
            "non_empty_slot_insert_rejected",
            "stale_root_rejected",
            "commitment_equality_matches_python_and_rust_kat",
            "necessary_not_sufficient",
        ):
            self.assertIn(vector, source)

    def test_no_active_circom_or_groth16_sources_exist_in_release_tree(self):
        bad = []
        for path in ROOT.parent.rglob("*"):
            if not path.is_file():
                continue
            rel = path.relative_to(ROOT.parent).as_posix().lower()
            if rel.endswith(".circom") or "groth" in rel:
                bad.append(rel)
        self.assertEqual(bad, [])


if __name__ == "__main__":
    unittest.main()
