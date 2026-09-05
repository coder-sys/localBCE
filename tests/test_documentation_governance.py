from __future__ import annotations

from pathlib import Path
import unittest

from tools import documentation_governance as governance


ROOT = Path(__file__).resolve().parents[1]


class DocumentationGovernanceTests(unittest.TestCase):
    def test_live_markdown_tree_is_registered_and_linked(self) -> None:
        result = governance.validate_markdown_tree(ROOT)
        self.assertEqual(21, len(governance.MARKDOWN_REGISTRY))
        self.assertEqual(len(governance.MARKDOWN_REGISTRY), result["markdown_count"])
        self.assertEqual(5, result["root_authority_count"])
        self.assertEqual(0, result["root_protected_compatibility_count"])
        self.assertEqual(len(governance.MARKDOWN_REGISTRY), result["registered_count"])

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
        self.assertEqual(len(governance.MARKDOWN_REGISTRY), result["markdown_count"])

    def test_design_ideology_remains_independent(self) -> None:
        registration = governance.MARKDOWN_REGISTRY["docs/DESIGN_IDEOLOGY.md"]
        self.assertTrue(registration.independent_authority)
        self.assertEqual("design-ideology", registration.role)

    def test_constructed_removed_paths_and_duplicate_ownership_fail_closed(self) -> None:
        self.assertTrue(
            governance._has_constructed_reference(
                "tools/example.py",
                'root / "docs" / "CURRENT_TECH_STACK.md"',
                "docs/CURRENT_TECH_STACK.md",
            )
        )
        roles = [registration.role for registration in governance.MARKDOWN_REGISTRY.values()]
        self.assertEqual(len(roles), len(set(roles)))

    def test_retired_markdown_lane_is_not_reintroduced(self) -> None:
        current = list(governance._current_paths(ROOT))
        current.append("experiments/README.md")
        with self.assertRaisesRegex(
            governance.DocumentationGovernanceError,
            "unregistered Markdown path",
        ):
            governance.validate_markdown_tree(ROOT, current_paths=current)

    def test_retired_status_structure_is_exactly_scoped(self) -> None:
        self.assertTrue(
            any(marker.search("Status: historical and differential evidence")
                for marker in governance._RETIRED_MARKDOWN_STRUCTURE)
        )
        self.assertFalse(
            any(marker.search("# Rejected architectures")
                for marker in governance._RETIRED_MARKDOWN_STRUCTURE)
        )

    def test_missing_documented_command_file_fails_closed(self) -> None:
        original = governance.DOCUMENTED_COMMAND_FILE_REFERENCES
        governance.DOCUMENTED_COMMAND_FILE_REFERENCES = {
            "README.md": frozenset({"does/not-exist.py"}),
        }
        try:
            with self.assertRaisesRegex(
                governance.DocumentationGovernanceError,
                "documented command references missing file",
            ):
                governance.validate_markdown_tree(ROOT)
        finally:
            governance.DOCUMENTED_COMMAND_FILE_REFERENCES = original

    def test_incompatible_active_instruction_fails_closed(self) -> None:
        original = governance._INCOMPATIBLE_ACTIVE_INSTRUCTIONS
        governance._INCOMPATIBLE_ACTIVE_INSTRUCTIONS = (
            ("README.md", governance.re.compile(r"(?m)^# Blind Ledger$")),
        )
        try:
            with self.assertRaisesRegex(
                governance.DocumentationGovernanceError,
                "incompatible active instruction remains",
            ):
                governance.validate_markdown_tree(ROOT)
        finally:
            governance._INCOMPATIBLE_ACTIVE_INSTRUCTIONS = original

    def test_current_task_requires_candidate_identity_and_next_action(self) -> None:
        original = governance._REQUIRED_CURRENT_TASK_MARKERS
        governance._REQUIRED_CURRENT_TASK_MARKERS = (*original, "missing active marker")
        try:
            with self.assertRaisesRegex(
                governance.DocumentationGovernanceError,
                "CURRENT_TASK.md is missing active marker",
            ):
                governance.validate_markdown_tree(ROOT)
        finally:
            governance._REQUIRED_CURRENT_TASK_MARKERS = original


if __name__ == "__main__":
    unittest.main()
