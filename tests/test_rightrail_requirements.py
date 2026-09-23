from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "extract_rightrail_requirements.py"
SPEC = importlib.util.spec_from_file_location("rightrail_requirements", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
requirements = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = requirements
SPEC.loader.exec_module(requirements)


class RightRailRequirementsTests(unittest.TestCase):
    def test_archived_instruction_is_reference_only(self) -> None:
        authority = requirements.authority_class("root/AGENTS.reference.txt")
        disposition, flags = requirements.crosswalk(
            "The agent must deploy this immediately.", authority
        )
        self.assertEqual(disposition, "reference_only")
        self.assertIn("archived_instruction_not_authority", flags)

    def test_ethereum_conflict_is_explicit(self) -> None:
        disposition, flags = requirements.crosswalk(
            "Ethereum is not a dependency.", "architecture_candidate"
        )
        self.assertEqual(disposition, "conflict_review")
        self.assertIn("conflicts_with_current_ethereum_settlement", flags)

    def test_sqlite_requires_adaptation(self) -> None:
        disposition, flags = requirements.crosswalk(
            "The local SQLite database must preserve one owner.", "architecture_candidate"
        )
        self.assertEqual(disposition, "adapt_candidate")
        self.assertIn("requires_postgresql_adaptation", flags)

    def test_nonactivation_is_preserved(self) -> None:
        disposition, flags = requirements.crosswalk(
            "The candidate remains nonactivating and not production qualified.",
            "architecture_candidate",
        )
        self.assertEqual(disposition, "adopt_safety_boundary")
        self.assertIn("reinforces_nonactivation", flags)

    def test_financial_authority_boundary_is_preserved(self) -> None:
        disposition, flags = requirements.crosswalk(
            "Any power to approve, hold or release a transaction requires a separate authorization.",
            "architecture_candidate",
        )
        self.assertEqual(disposition, "adopt_safety_boundary")
        self.assertIn("reinforces_no_direct_payment_authority", flags)

    def test_candidate_ids_are_stable(self) -> None:
        first = requirements.candidate_id("w/r067/README.md", 10, "The owner must fail closed.")
        second = requirements.candidate_id("w/r067/README.md", 10, "The owner must fail closed.")
        self.assertEqual(first, second)

    def test_pdf_roles_do_not_promote_research_papers(self) -> None:
        self.assertEqual(
            requirements.PDF_REQUIREMENT_PATH,
            "original/reference/RightRail_Architecture_and_Operating_Plan.pdf",
        )
        self.assertIn("w/r012/dfms-2022-270.pdf", requirements.PDF_DOCUMENTARY_PATHS)
        self.assertIn("w/r038/katsumata-2021-927.pdf", requirements.PDF_DOCUMENTARY_PATHS)

    def test_pdf_lines_form_complete_sentences_and_skip_contents(self) -> None:
        statements = requirements.pdf_page_statements(
            "RightRail Product & operating plan\n"
            "September 2026 | Internal working plan 1\n"
            "The state must retain the complete pro-\n"
            "venance record. Another control remains inactive.\n"
            "In this document\n"
            "Provider App remains a separate lane 13\n",
            first_page=True,
        )
        self.assertEqual(
            statements,
            [
                "The state must retain the complete provenance record.",
                "Another control remains inactive.",
            ],
        )


if __name__ == "__main__":
    unittest.main()
