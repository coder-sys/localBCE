from __future__ import annotations

import ast
import unittest
from pathlib import Path

from app.right_rail_financial_staff_server import _STATIC_FILES
from tools.right_rail_financial_service_kit import (
    EXPECTED_PYTHON_EXE_SHA256,
    KIT_CLAIMS,
    KIT_SCHEMA,
    RUNTIME_EXE,
    RETIRED_PIN_REGISTRY,
    STATE_FILES,
    KitError,
    _check_names,
    _check_contents,
    _check_guard_log,
    _check_retired_pins,
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

    def test_kit_ships_every_file_the_staff_server_serves(self) -> None:
        # staff.js boots from /interaction-model.json; a kit without it serves a broken UI.
        self.assertLessEqual({"app/" + path for path, _type in _STATIC_FILES.values()}, set(STATE_FILES))

    def test_kit_ships_every_module_its_python_files_import(self) -> None:
        root = Path(__file__).resolve().parents[1]

        def imported(path: str):
            for node in ast.walk(ast.parse((root / path).read_text(encoding="utf-8"))):
                if isinstance(node, ast.Import):
                    yield from (alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    yield node.module
                    yield from (f"{node.module}.{alias.name}" for alias in node.names)

        def missing(files: set[str]) -> list[str]:
            need = {name.replace(".", "/") + ".py" for path in files if path.endswith(".py") for name in imported(path) if name.startswith(("app.", "tools.", "tests."))}
            return sorted(path for path in need - files if (root / path).is_file())

        self.assertEqual(missing(set(STATE_FILES)), [])
        aac195b = set(STATE_FILES) - {"app/right_rail_financial_derived.py", "app/right_rail_financial_followthrough.py", "app/right_rail_financial_line_pack.py"}
        self.assertEqual(missing(aac195b), ["app/right_rail_financial_followthrough.py", "app/right_rail_financial_line_pack.py"])  # the list before the fix

    def test_kit_requires_the_exact_retired_engine_registry(self) -> None:
        root = Path(__file__).resolve().parents[1]
        self.assertIn(RETIRED_PIN_REGISTRY, STATE_FILES)
        files = {path: (root / path).read_bytes() for path in (RETIRED_PIN_REGISTRY, "app/right_rail_financial_owner_independent.py")}
        _check_retired_pins(files.__getitem__)
        files[RETIRED_PIN_REGISTRY] += b"\n"
        with self.assertRaisesRegex(KitError, "^kit_retired_pins_mismatch$"):
            _check_retired_pins(files.__getitem__)
        with self.assertRaisesRegex(KitError, "^kit_state_source_inventory$"):
            _check_contents({p: (0, "0" * 64) for p in STATE_FILES if p != RETIRED_PIN_REGISTRY}, files.__getitem__)

    @staticmethod
    def _guard_log() -> str:
        # Independent v4 record fixture: producer emits CRLF on Windows.
        records = [
            "RESOURCE_POLICY version=v4 owner_waiver_effective=2026-09-23 process_tree_memory_cap=WAIVED_UNTIL_REVOKED "
            "physical_reserve_bytes=3221225472 physical_free_floor_bytes=2190433321 target_start_floor_bytes=4190433321 "
            "effective_start_floor_bytes=4190433321 tolerance_percent=32 process_tree_sampling=ENABLED cleanup=ENABLED "
            r"mutex=Local\BlindLedgerDirectMaskBuild20260907 activation=NONE",
            "PHYSICAL_PREFLIGHT free_bytes=5000000000 reserve_bytes=3221225472 reserve_floor_bytes=2190433321 "
            "target_start_floor_bytes=4190433321 effective_start_floor_bytes=4190433321 tolerance_percent=32",
        ]
        for label, code in (("child-exit-7", 7), ("child-exit-0", 0), ("Command", 0)):
            records += [
                f"CHILD_EXIT_STATUS label={label} exit={code}",
                f"LIVE_PHYSICAL_SUMMARY label={label} samples=1 min_free_bytes=3000000000 reserve_bytes=3221225472 "
                "peak_working_set_bytes=1000000 peak_private_bytes=2000000 reserve_floor_bytes=2190433321 tolerance_percent=32",
                f"CLEANUP=PASS label={label} owned_process_tree=empty",
            ]
        records += ["CHILD_EXIT_CHECK exit7=7 exit0=0", r"MUTEX=RELEASED name=Local\BlindLedgerDirectMaskBuild20260907"]
        return "\n".join(records) + "\n"

    def test_guard_log_accepts_lf_and_crlf_without_changing_policy(self) -> None:
        for ending in ("\n", "\r\n"):
            with self.subTest(ending=repr(ending)):
                _check_guard_log(self._guard_log().replace("\n", ending).encode("ascii"), 4_190_433_321, 3_000_000_000)

    def test_guard_log_rejects_adverse_records_with_either_line_ending(self) -> None:
        valid = self._guard_log()
        mutations = (
            ("activation=NONE", "activation=YES", "policy_mismatch"),
            ("tolerance_percent=32", "tolerance_percent=33", "policy_mismatch"),
            ("free_bytes=5000000000", "free_bytes=4190433320", "preflight_mismatch"),
            ("CHILD_EXIT_CHECK exit7=7 exit0=0", "CHILD_EXIT_CHECK exit7=0 exit0=0", "self_test_check"),
            ("CHILD_EXIT_STATUS label=Command exit=0", "CHILD_EXIT_STATUS label=Command exit=1", "target_child_status"),
            ("CLEANUP=PASS label=Command owned_process_tree=empty\n", "", "cleanup_inventory"),
            ("owned_process_tree=empty", "owned_process_tree=remaining", "cleanup_inventory"),
            ("samples=1", "samples=0", "summary_invalid"),
            ("min_free_bytes=3000000000", "min_free_bytes=2190433320", "summary_invalid"),
            ("min_free_bytes=3000000000", "min_free_bytes=3000000001", "minimum_free_mismatch"),
            ("MUTEX=RELEASED", "MUTEX=UNKNOWN", "mutex_release"),
            ("RESOURCE_POLICY ", "RESOURCE_POLICY unknown=1 ", "policy_mismatch"),
        )
        for ending in ("\n", "\r\n"):
            for old, new, code in mutations:
                with self.subTest(ending=repr(ending), mutation=code, old=old):
                    raw = valid.replace(old, new).replace("\n", ending).encode("ascii")
                    with self.assertRaisesRegex(KitError, "^engine_guard_log_" + code + "$"):
                        _check_guard_log(raw, 4_190_433_321, 3_000_000_000)
            for marker in ("RUNNER_FAILURE reason=bad", "CLEANUP=FAIL label=Command", "MUTEX=HELD_UNTIL_PROCESS_EXIT"):
                with self.subTest(ending=repr(ending), marker=marker):
                    with self.assertRaisesRegex(KitError, "^engine_guard_log_failure_marker$"):
                        _check_guard_log((valid + marker + "\n").replace("\n", ending).encode("ascii"), 4_190_433_321, 3_000_000_000)
            with self.subTest(ending=repr(ending), duplicate="policy"):
                with self.assertRaisesRegex(KitError, "^engine_guard_log_policy_mismatch$"):
                    _check_guard_log((valid + valid.splitlines()[0] + "\n").replace("\n", ending).encode("ascii"), 4_190_433_321, 3_000_000_000)
        with self.assertRaisesRegex(KitError, "^engine_guard_log_policy_mismatch$"):
            _check_guard_log(valid.replace("\n", "\r\r\n").encode("ascii"), 4_190_433_321, 3_000_000_000)


if __name__ == "__main__":
    unittest.main()
