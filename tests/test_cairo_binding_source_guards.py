import os
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
            "verify_claim_source_merkle_path",
            "claim_source_flat_digest_from_words",
            "assert_claim_source_flat_digest",
            "oracle_facts_flat_digest_from_words",
            "assert_oracle_facts_flat_digest",
            "HardenedClaimInput",
            "OracleFactsWitness",
            "FeeWitness",
            "TarRuleWitness",
            "ClaimOutput",
            "adjudicate_without_nullifier_transition",
            "commitment_for_bound_claim",
            "assert_oracle_facts_membership",
            "assert_fee_schedule_membership",
            "assert_tar_required_membership",
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
            "DOMAIN_TAG_RULESET",
            "DOMAIN_TAG_CLAIM",
            "DOMAIN_TAG_RESULT",
        ):
            self.assertIn(tag, source)
        self.assertRegex(source, re.compile(r"PoseidonTrait::new\(\)\s*\.update\(tag\)\s*\.update\(2\)", re.MULTILINE))
        self.assertRegex(source, re.compile(r"PoseidonTrait::new\(\)\s*\.update\(tag\)\s*\.update\(4\)", re.MULTILINE))
        self.assertIn("assert_ruleset_policy_digest", source)
        self.assertIn("assert_batch_nullifier_commitment", source)
        self.assertIn("assert_claim_source_membership", source)
        self.assertIn("verify_multi_line_authorization", source)
        self.assertIn("verify_multi_line_policy_row", source)
        self.assertIn("verify_batch_policy_dictionary", source)
        self.assertIn("policy_root: felt252", source)
        self.assertIn("adjudicate(", source)
        self.assertIn("claim_source_root: felt252", source)
        self.assertIn("onchain_claim_source_root: felt252", source)
        self.assertIn("assert_claim_audit_tree_root", source)
        self.assertIn("assert_result_audit_tree_root", source)
        self.assertIn("assert_payment_audit_tree_root", source)
        self.assertIn("assert_epoch_nullifier_set_transition", source)
        self.assertIn("epoch_nullifier_set_root_from_words", source)
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

    def test_no_active_circom_or_groth16_sources_exist_in_governed_app_source(self):
        generated_directories = {
            ".git",
            ".mypy_cache",
            ".pytest_cache",
            ".ruff_cache",
            ".venv",
            "__pycache__",
            "cache",
            "node_modules",
            "out",
            "scratch",
            "target",
            "wsl-target",
        }
        bad = []
        for directory, child_directories, filenames in os.walk(ROOT):
            child_directories[:] = sorted(
                name for name in child_directories if name not in generated_directories
            )
            for filename in sorted(filenames):
                path = Path(directory) / filename
                rel = path.relative_to(ROOT).as_posix().lower()
                if rel.endswith(".circom") or "groth" in rel:
                    bad.append(rel)
        self.assertEqual(bad, [])


if __name__ == "__main__":
    unittest.main()
