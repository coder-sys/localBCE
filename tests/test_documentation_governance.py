from __future__ import annotations

from pathlib import Path
import unittest

from tools import documentation_governance as governance


ROOT = Path(__file__).resolve().parents[1]


class DocumentationGovernanceTests(unittest.TestCase):
    def test_live_markdown_tree_is_registered_and_linked(self) -> None:
        result = governance.validate_markdown_tree(ROOT)
        self.assertEqual(32, result["markdown_count"])
        self.assertEqual(5, result["root_authority_count"])
        self.assertEqual(1, result["root_protected_compatibility_count"])
        self.assertEqual(32, result["registered_count"])

    def test_unregistered_markdown_is_rejected(self) -> None:
        current = list(governance._current_paths(ROOT))
        current.append("docs/new-unreviewed.md")
        with self.assertRaisesRegex(
            governance.DocumentationGovernanceError, "unregistered Markdown path"
        ):
            governance.validate_markdown_tree(ROOT, current_paths=current)

    def test_removed_markdown_names_are_not_live_references(self) -> None:
        current = governance._current_paths(ROOT)
        for removed in governance.REMOVED_MARKDOWN_PATHS:
            self.assertNotIn(removed, current)
        result = governance.validate_markdown_tree(ROOT, current_paths=current)
        self.assertEqual(32, result["markdown_count"])

    def test_design_ideology_remains_independent(self) -> None:
        registration = governance.MARKDOWN_REGISTRY["docs/DESIGN_IDEOLOGY.md"]
        self.assertTrue(registration.independent_authority)
        self.assertEqual("design-ideology", registration.role)


if __name__ == "__main__":
    unittest.main()
