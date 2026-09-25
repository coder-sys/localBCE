from __future__ import annotations

import unittest

from tools.right_rail_financial_service_kit import (
    EXPECTED_PYTHON_EXE_SHA256,
    KIT_CLAIMS,
    KIT_SCHEMA,
    RUNTIME_EXE,
    KitError,
    _check_names,
    _check_runtime_member,
    _manifest_files,
    _strict_canonical_json,
)

class FinancialServiceKitManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.interpreter_size = 1_234_567
        self.members = {RUNTIME_EXE: (self.interpreter_size, EXPECTED_PYTHON_EXE_SHA256)}

    def test_receipt_json_requires_canonical_bytes(self) -> None:
        self.assertEqual(_strict_canonical_json(b'{"schema":"v2"}', "receipt"), {"schema": "v2"})
        with self.assertRaisesRegex(KitError, "json_not_canonical:receipt"):
            _strict_canonical_json(b'{ "schema": "v2"}\n', "receipt")

    def test_manifest_binds_the_pinned_runtime_member(self) -> None:
        size, digest = _check_runtime_member(self.members)
        self.assertEqual(digest, EXPECTED_PYTHON_EXE_SHA256)
        self.assertEqual(size, self.interpreter_size)

    def test_manifest_rejects_a_self_consistent_unpinned_interpreter_member(self) -> None:
        self.members[RUNTIME_EXE] = (self.interpreter_size, "A" * 64)
        with self.assertRaisesRegex(KitError, "kit_python_executable_member_pin"):
            _check_runtime_member(self.members)

    def test_manifest_rejects_non_integer_interpreter_size(self) -> None:
        self.members[RUNTIME_EXE] = (True, EXPECTED_PYTHON_EXE_SHA256)
        with self.assertRaisesRegex(KitError, "kit_python_executable_member_pin"):
            _check_runtime_member(self.members)

    def test_manifest_rejects_missing_interpreter_member(self) -> None:
        with self.assertRaisesRegex(KitError, "kit_python_executable_member_pin"):
            _check_runtime_member({})

    def test_archive_names_reject_traversal_and_portable_collisions(self) -> None:
        for bad in ("../x", "/abs", "a/../b", "a\\b", "C:x", "aux.txt", "a/", "trail. "):
            with self.subTest(name=bad), self.assertRaises(KitError):
                _check_names([bad])
        with self.assertRaisesRegex(KitError, "archive_path_portable_collision"):
            _check_names(["README.md", "readme.md"])
        with self.assertRaisesRegex(KitError, "archive_file_directory_collision"):
            _check_names(["a", "a/b"])

    def test_manifest_claims_are_exact_including_json_types(self) -> None:
        entry = {"path": "a", "sha256": "0" * 64, "size_bytes": 1}
        self.assertEqual(
            _manifest_files({"claims": KIT_CLAIMS, "files": [entry], "schema": KIT_SCHEMA}),
            {"a": (1, "0" * 64)},
        )
        with self.assertRaisesRegex(KitError, "kit_claims_pin"):
            _manifest_files({"claims": {**KIT_CLAIMS, "activation": 0}, "files": [entry], "schema": KIT_SCHEMA})
        with self.assertRaisesRegex(KitError, "kit_manifest_entry_value"):
            _manifest_files({"claims": KIT_CLAIMS, "files": [{**entry, "size_bytes": True}], "schema": KIT_SCHEMA})

if __name__ == "__main__":
    unittest.main()
