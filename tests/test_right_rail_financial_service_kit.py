from __future__ import annotations

import unittest

from tools.right_rail_financial_service_kit import (
    EXPECTED_PYTHON_EXE_SHA256,
    EXPECTED_PYTHON_VERSION,
    KitError,
    _strict_canonical_json,
    _validate_runtime_metadata,
)


class FinancialServiceKitManifestTests(unittest.TestCase):
    def test_receipt_json_requires_canonical_bytes(self) -> None:
        self.assertEqual(_strict_canonical_json(b'{"schema":"v2"}', "receipt"), {"schema": "v2"})
        with self.assertRaisesRegex(KitError, "json_not_canonical:receipt"):
            _strict_canonical_json(b'{ "schema": "v2"}\n', "receipt")

    def setUp(self) -> None:
        self.interpreter_size = 1_234_567
        self.python_metadata = {
            "executable_path": "runtime/python311/python.exe",
            "executable_sha256": EXPECTED_PYTHON_EXE_SHA256,
            "executable_size_bytes": self.interpreter_size,
            "third_party_packages": [],
            "version": EXPECTED_PYTHON_VERSION,
        }
        self.file_map = {
            "runtime/python311/python.exe": {
                "kind": "python_runtime",
                "path": "runtime/python311/python.exe",
                "sha256": EXPECTED_PYTHON_EXE_SHA256,
                "size_bytes": self.interpreter_size,
            }
        }

    def test_manifest_binds_metadata_to_the_pinned_runtime_member(self) -> None:
        entry = _validate_runtime_metadata(self.python_metadata, self.file_map)
        self.assertEqual(entry["sha256"], EXPECTED_PYTHON_EXE_SHA256)
        self.assertEqual(entry["size_bytes"], self.interpreter_size)

    def test_manifest_rejects_a_self_consistent_unpinned_interpreter_member(self) -> None:
        self.file_map["runtime/python311/python.exe"]["sha256"] = "A" * 64
        with self.assertRaisesRegex(KitError, "kit_python_executable_member_pin"):
            _validate_runtime_metadata(self.python_metadata, self.file_map)

    def test_manifest_rejects_non_integer_interpreter_size(self) -> None:
        self.file_map["runtime/python311/python.exe"]["size_bytes"] = True
        with self.assertRaisesRegex(KitError, "kit_python_executable_member_pin"):
            _validate_runtime_metadata(self.python_metadata, self.file_map)


if __name__ == "__main__":
    unittest.main()
