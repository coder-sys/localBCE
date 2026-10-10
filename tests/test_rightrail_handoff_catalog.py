from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "catalog_rightrail_handoff.py"
SPEC = importlib.util.spec_from_file_location("rightrail_handoff_catalog", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
catalog = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = catalog
SPEC.loader.exec_module(catalog)


class RightRailHandoffCatalogTests(unittest.TestCase):
    def test_path_validation_rejects_traversal_and_windows_paths(self) -> None:
        for value in ("../escape", "/absolute", "C:/drive", "a\\b", "./same"):
            with self.subTest(value=value):
                with self.assertRaises(catalog.HandoffCatalogError):
                    catalog.safe_relative_path(value, label="test")

    def test_classification_keeps_binaries_and_patches_quarantined(self) -> None:
        self.assertEqual(catalog.disposition("artifact.exe", surface="trunk_member")[0], "quarantine")
        self.assertEqual(
            catalog.disposition("work-in-progress/change.patch", surface="package_file")[0],
            "quarantine",
        )
        self.assertEqual(
            catalog.disposition("CONSTITUTION.md", surface="trunk_member")[0],
            "adopt_control",
        )

    def test_common_record_is_never_active(self) -> None:
        record = catalog.common_record(
            surface="trunk_member",
            locator="ARCHITECTURE.md",
            sha256="a" * 64,
            bytes_count=1,
            disposition_value="adapt_specification",
            rationale="test",
        )
        for field in (
            "execution_allowed",
            "runtime_eligible",
            "proof_binding",
            "human_approved",
            "legally_verified",
        ):
            self.assertFalse(record[field])

    def test_package_symlink_fails_closed_when_supported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.txt"
            target.write_text("data", encoding="ascii")
            link = root / "link.txt"
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("symbolic links are unavailable on this host")
            with self.assertRaisesRegex(catalog.HandoffCatalogError, "symbolic links"):
                catalog.package_records(root, {})

    def test_duplicate_zip_member_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("same.txt", "one")
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    archive.writestr("same.txt", "two")
            prior_count = catalog.EXPECTED_TRUNK_FILES
            catalog.EXPECTED_TRUNK_FILES = 2
            try:
                with self.assertRaisesRegex(catalog.HandoffCatalogError, "duplicate ZIP member"):
                    catalog.trunk_records(path, {})
            finally:
                catalog.EXPECTED_TRUNK_FILES = prior_count

    def test_catalog_summary_is_complete_and_inactive(self) -> None:
        summary = catalog.json.loads(
            (ROOT / "right-rail-integration" / "reports" / catalog.SUMMARY_NAME).read_text(
                encoding="ascii"
            )
        )
        self.assertEqual(summary["manifest_entry_count"], 322)
        self.assertEqual(summary["package_file_count"], 323)
        self.assertEqual(summary["trunk_file_count"], 637)
        self.assertEqual(summary["git_ref_count"], 148)
        self.assertEqual(summary["prior_catalog_content_match_count"], 178)
        self.assertEqual(summary["new_or_changed_trunk_file_count"], 459)
        self.assertEqual(summary["execution_allowed_count"], 0)
        self.assertEqual(summary["runtime_eligible_count"], 0)
        self.assertEqual(summary["proof_binding_count"], 0)


if __name__ == "__main__":
    unittest.main()
