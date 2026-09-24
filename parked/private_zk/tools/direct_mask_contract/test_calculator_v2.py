from __future__ import annotations

import copy
import hashlib
import io
import json
import math
import os
import re
import subprocess
import tempfile
import unittest
from collections import Counter
from fractions import Fraction
from pathlib import Path
from unittest import mock

from .calculator_v2 import (
    ContractError,
    _availability_path_vectors,
    _conditional_collision_split_bound,
    _z_value,
    admission_ledger,
    availability_report,
    calculate_report_v2,
    certificate_constants,
    concrete_feasibility,
    load_manifest,
    row_bounds,
    _validate_manifest,
)
from . import lean_adapter
from .lean_adapter import run_formal_arguments


class IndependentCheckerIdentityTests(unittest.TestCase):
    @staticmethod
    def _identity(checker_hash: str = "b" * 64, receipt_hash: str = "a" * 64) -> tuple[object, ...]:
        return (
            receipt_hash,
            "build-id",
            "schema-id",
            "toolchain",
            "binary-hash",
            1,
            (),
            (),
            (("lean", "b" * 64), ("leanchecker", checker_hash)),
            "guard-hash",
            ("d" * 64, (), (), "e" * 64, "f" * 64),
        )

    def test_checker_execution_is_bound_to_stable_receipt_identity(self) -> None:
        identity = self._identity()
        lease = mock.MagicMock()
        lease.__enter__.side_effect = [
            115_200,
            lean_adapter.PINNED_LEAN.stat().st_size,
            1_000,
        ]
        module_lease = mock.MagicMock()
        module_lease.__enter__.return_value = None
        graph = {"BlindLedger.Theorems": ()}
        graph_paths = {"BlindLedger.Theorems": "C:/lean/BlindLedger/Theorems.olean"}
        graph_hash = "c" * 64
        inspector_run = {
            "run_suffix": "lean-security-import-graph-123",
            "executable_path": str(lean_adapter.PINNED_LEAN),
            "executable_sha256": "a" * 64,
            "executable_size": 2_000_000,
            "arguments": ["--run", "../../tools/direct_mask_contract/olean_imports.lean"],
            "working_directory": "formal/lean",
            "lean_path": "formal/lean/.lake/build-v2/lib/lean",
            "child_exit": 0,
            "outer_guard_exit": 0,
            "guard_cleanup": "PASS",
            "mutex_released": True,
            "guard_relative_path": lean_adapter.PROVENANCE_GUARD_RELATIVE_PATH,
            "guard_sha256": lean_adapter.PROVENANCE_GUARD_SHA256,
            "guard_policy_version": "v4",
            "guard_stdout_sha256": "d" * 64,
            "guard_stderr_sha256": "e" * 64,
            "graph_sha256": graph_hash,
            "minimum_start_free_bytes": lean_adapter.PROVENANCE_GUARD_MINIMUM_START_FREE_BYTES,
        }
        with (
            mock.patch.object(lean_adapter, "_hold_readonly_file_identity", return_value=lease) as lock,
            mock.patch.object(lean_adapter, "_hold_readonly_module_inputs", return_value=module_lease),
            mock.patch.object(
                lean_adapter, "_artifact_identity", side_effect=(identity, identity, identity, identity)
            ) as artifact,
            mock.patch.object(
                lean_adapter,
                "_provenance_guarded_power_shell",
                return_value=(0, b"", b""),
            ) as guarded,
            mock.patch.object(lean_adapter, "_guarded_evidence", return_value="guard-evidence"),
            mock.patch.object(
                lean_adapter,
                "_run_olean_import_inspector",
                return_value=(graph, graph_paths, graph_hash, inspector_run, "inspector-evidence"),
            ) as inspector,
        ):
            evidence = lean_adapter.run_independent_formal_checker_for_test()

        self.assertIn(f"executable_sha256={'b' * 64}", evidence)
        self.assertIn("executable_size=115200", evidence)
        self.assertIn(f"receipt_sha256={'a' * 64}", evidence)
        self.assertIn("child_exit=0 outer_guard_exit=0", evidence)
        self.assertIn("run_suffix=lean-security-independent-checker-", evidence)
        checker_run_line = next(
            line for line in evidence.splitlines() if line.startswith("CHECKER_RUN_JSON=")
        )
        checker_run = json.loads(checker_run_line.partition("=")[2])
        self.assertEqual(
            set(checker_run),
            {
                "run_suffix", "executable_path", "executable_sha256", "executable_size",
                "arguments", "working_directory", "lean_path", "child_exit",
                "outer_guard_exit", "guard_cleanup", "mutex_released",
                "guard_relative_path", "guard_sha256", "guard_policy_version",
                "guard_stdout_sha256", "guard_stderr_sha256",
                "input_manifest_sha256", "input_inventory_sha256", "import_graph_sha256",
                "minimum_start_free_bytes",
            },
        )
        self.assertRegex(
            checker_run["run_suffix"], r"^lean-security-independent-checker-[0-9]+$"
        )
        self.assertEqual(checker_run["executable_path"], str(lean_adapter.PINNED_LEANCHECKER))
        self.assertEqual(checker_run["executable_sha256"], "b" * 64)
        self.assertEqual(checker_run["executable_size"], 115_200)
        self.assertEqual(checker_run["arguments"], [lean_adapter.EXPECTED_CHECKER_MODULE])
        self.assertEqual(checker_run["working_directory"], "formal/lean")
        self.assertEqual(checker_run["lean_path"], "formal/lean/.lake/build-v2/lib/lean")
        self.assertEqual(checker_run["child_exit"], 0)
        self.assertEqual(checker_run["outer_guard_exit"], 0)
        self.assertEqual(checker_run["guard_cleanup"], "PASS")
        self.assertIs(checker_run["mutex_released"], True)
        self.assertEqual(checker_run["guard_stdout_sha256"], hashlib.sha256(b"").hexdigest())
        self.assertEqual(checker_run["guard_stderr_sha256"], hashlib.sha256(b"").hexdigest())
        self.assertEqual(checker_run["input_manifest_sha256"], "e" * 64)
        self.assertEqual(checker_run["input_inventory_sha256"], "f" * 64)
        self.assertEqual(checker_run["import_graph_sha256"], graph_hash)
        self.assertEqual(
            checker_run["minimum_start_free_bytes"],
            lean_adapter.PROVENANCE_GUARD_MINIMUM_START_FREE_BYTES,
        )
        self.assertIn("guard-evidence", evidence)
        self.assertEqual(artifact.call_count, 4)
        self.assertEqual(inspector.call_count, 1)
        self.assertEqual(guarded.call_count, 1)
        self.assertEqual(lock.call_count, 3)
        guarded.assert_called_once()
        self.assertEqual(lease.__exit__.call_count, 3)
        module_lease.__exit__.assert_called_once()

    def test_checker_identity_change_after_invocation_fails_closed(self) -> None:
        identity = self._identity()
        changed = self._identity(checker_hash="c" * 64)
        lease = mock.MagicMock()
        lease.__enter__.return_value = 115_200
        module_lease = mock.MagicMock()
        with (
            mock.patch.object(lean_adapter, "_hold_readonly_file_identity", return_value=lease),
            mock.patch.object(lean_adapter, "_hold_readonly_module_inputs", return_value=module_lease),
            mock.patch.object(
                lean_adapter, "_artifact_identity", side_effect=(identity, identity, changed)
            ),
            mock.patch.object(lean_adapter, "_guarded_power_shell", return_value=(0, b"", b"")),
            mock.patch.object(lean_adapter, "_guarded_evidence", return_value="guard-evidence"),
        ):
            with self.assertRaisesRegex(
                lean_adapter.FormalArithmeticError,
                "formal_artifact_identity_changed_during_independent_checker",
            ):
                lean_adapter.run_independent_formal_checker_for_test()
        lease.__exit__.assert_called_once()

    def test_module_identity_change_before_invocation_prevents_checker_launch(self) -> None:
        identity = self._identity()
        changed = self._identity(receipt_hash="f" * 64)
        lease = mock.MagicMock()
        lease.__enter__.return_value = 115_200
        with (
            mock.patch.object(lean_adapter, "_hold_readonly_file_identity", return_value=lease),
            mock.patch.object(lean_adapter, "_hold_readonly_module_inputs"),
            mock.patch.object(lean_adapter, "_artifact_identity", side_effect=(identity, changed)),
            mock.patch.object(lean_adapter, "_guarded_power_shell") as guarded,
        ):
            with self.assertRaisesRegex(
                lean_adapter.FormalArithmeticError,
                "formal_module_identity_changed_before_independent_checker",
            ):
                lean_adapter.run_independent_formal_checker_for_test()
        guarded.assert_not_called()

    def test_receipt_identity_failure_prevents_checker_launch(self) -> None:
        lease = mock.MagicMock()
        lease.__enter__.return_value = 115_200
        with (
            mock.patch.object(lean_adapter, "_hold_readonly_file_identity", return_value=lease),
            mock.patch.object(
                lean_adapter,
                "_artifact_identity",
                side_effect=lean_adapter.FormalArithmeticError("tool_hash_mismatch=leanchecker"),
            ),
            mock.patch.object(lean_adapter, "_guarded_power_shell") as guarded,
        ):
            with self.assertRaisesRegex(lean_adapter.FormalArithmeticError, "tool_hash_mismatch=leanchecker"):
                lean_adapter.run_independent_formal_checker_for_test()
        guarded.assert_not_called()
        lease.__exit__.assert_called_once()

    def test_provenance_checker_fails_closed_before_launch_without_sidecar(self) -> None:
        lease = mock.MagicMock()
        lease.__enter__.return_value = 115_200
        with (
            mock.patch.object(lean_adapter, "_hold_readonly_file_identity", return_value=lease),
            mock.patch.object(
                lean_adapter,
                "_artifact_identity",
                side_effect=lean_adapter.FormalArithmeticError(
                    "module_provenance_missing_or_link"
                ),
            ) as identity,
            mock.patch.object(lean_adapter, "_guarded_power_shell") as guarded,
        ):
            with self.assertRaisesRegex(
                lean_adapter.FormalArithmeticError, "module_provenance_missing_or_link"
            ):
                lean_adapter.run_independent_formal_checker_for_test()
        identity.assert_called_once_with(require_module_provenance=True)
        guarded.assert_not_called()
        lease.__exit__.assert_called_once()

    def test_checker_command_quotes_path_components(self) -> None:
        identity = self._identity()
        lease = mock.MagicMock()
        lease.__enter__.return_value = 115_200
        profile = Path("C:/Users/O'Connor")
        formal_root = profile / "formal" / "lean"
        checker_path = profile / ".elan" / "bin" / "leanchecker.exe"
        with (
            mock.patch.object(lean_adapter.Path, "home", return_value=profile),
            mock.patch.object(lean_adapter, "FORMAL_ROOT", formal_root),
            mock.patch.object(lean_adapter, "PINNED_LEANCHECKER", checker_path),
            mock.patch.object(lean_adapter, "_hold_readonly_file_identity", return_value=lease),
            mock.patch.object(lean_adapter, "_hold_readonly_module_inputs"),
            mock.patch.object(
                lean_adapter, "_artifact_identity", side_effect=(identity, identity, identity)
            ),
            mock.patch.object(lean_adapter, "_guarded_power_shell", return_value=(0, b"", b"")) as guarded,
            mock.patch.object(lean_adapter, "_guarded_evidence", return_value="guard-evidence"),
        ):
            lean_adapter.run_independent_formal_checker_for_test()

        inner = guarded.call_args.args[0]
        self.assertIn("Set-Location -LiteralPath 'C:\\Users\\O''Connor\\formal\\lean'", inner)
        self.assertIn("& 'C:\\Users\\O''Connor\\.elan\\bin\\leanchecker.exe'", inner)


@unittest.skipUnless(os.name == "nt", "Windows file sharing is required for the identity-lock test")
class NativeFileIdentityLockTests(unittest.TestCase):
    def test_read_lock_denies_write_and_replacement_until_closed(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            checker = root / "bin" / "leanchecker.exe"
            checker.parent.mkdir()
            checker.write_bytes(b"pinned-checker")
            replacement = root / "replacement.exe"
            replacement.write_bytes(b"replacement-checker")

            with lean_adapter._hold_readonly_file_identity(checker, root) as locked_size:
                self.assertEqual(locked_size, len(b"pinned-checker"))
                self.assertEqual(checker.read_bytes(), b"pinned-checker")
                with self.assertRaises(PermissionError):
                    checker.write_bytes(b"modified-checker")
                with self.assertRaises(OSError):
                    os.replace(replacement, checker)
                with self.assertRaises(OSError):
                    os.replace(checker.parent, root / "moved-bin")

            os.replace(replacement, checker)
            self.assertEqual(checker.read_bytes(), b"replacement-checker")

    def test_read_lock_denies_replacement_of_olean_module(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            module = root / "formal" / "lean" / ".lake" / "build-v2" / "lib" / "lean" / "BlindLedger" / "Theorems.olean"
            module.parent.mkdir(parents=True)
            module.write_bytes(b"reviewed-module")
            replacement = root / "replacement.olean"
            replacement.write_bytes(b"swapped-module")

            with lean_adapter._hold_readonly_file_identity(module, root, label="olean_input") as locked_size:
                self.assertEqual(locked_size, len(b"reviewed-module"))
                with self.assertRaises(PermissionError):
                    module.write_bytes(b"changed-module")
                with self.assertRaises(OSError):
                    os.replace(replacement, module)

            os.replace(replacement, module)
            self.assertEqual(module.read_bytes(), b"swapped-module")

    def test_formal_invoke_blocks_swap_restore_aba_during_launch(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            formal_root = root / "formal" / "lean"
            binary = formal_root / ".lake" / "build-v2" / "bin" / "blind_security_arithmetic_v2.exe"
            binary.parent.mkdir(parents=True)
            formal_root.mkdir(parents=True, exist_ok=True)
            binary.write_bytes(b"pinned-binary")
            attacker = root / "attacker.exe"
            attacker.write_bytes(b"attacker-binary")
            identity = (
                "receipt", "build", "schema", "toolchain", "binary-hash",
                len(b"pinned-binary"), (), (), (), "guard",
            )

            def fake_launch(command: list[str], **kwargs: Any) -> tuple[int, bytes, bytes]:
                self.assertEqual(command[0], str(binary))
                with self.assertRaises(PermissionError):
                    binary.write_bytes(b"attacker-binary")
                with self.assertRaises(OSError):
                    os.replace(attacker, binary)
                self.assertEqual(binary.read_bytes(), b"pinned-binary")
                return 0, b"", b""

            with (
                mock.patch.object(lean_adapter, "PRODUCT_ROOT", root),
                mock.patch.object(lean_adapter, "FORMAL_ROOT", formal_root),
                mock.patch.object(lean_adapter, "FORMAL_BINARY", binary),
                mock.patch.object(
                    lean_adapter, "_artifact_identity", side_effect=(identity, identity)
                ),
                mock.patch.object(lean_adapter, "_run_bounded", side_effect=fake_launch),
                mock.patch.object(lean_adapter, "_validate_result", return_value={}),
                mock.patch.object(lean_adapter, "_normalise_result", return_value={"ok": True}),
            ):
                result = lean_adapter._invoke(["cap"], "cap", identity=identity)

            self.assertEqual(result, {"ok": True})
            self.assertEqual(binary.read_bytes(), b"pinned-binary")


class ArtifactIdentityScopeTests(unittest.TestCase):
    def test_v2_identity_skips_missing_provenance_unless_explicitly_required(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            formal_root = root / "formal" / "lean"
            formal_root.mkdir(parents=True)
            (formal_root / "lean-toolchain").write_text(
                f"{lean_adapter.PINNED_TOOLCHAIN}\n", encoding="utf-8"
            )
            guard = root / "guard.ps1"
            guard.write_text("guard", encoding="utf-8")
            relative_binary = "formal/lean/.lake/build-v2/bin/fixture.exe"
            binary = root / Path(relative_binary)
            source_path = "formal/lean/Arithmetic.lean"
            source_hash = "a" * 64
            binary_hash = "b" * 64
            tool_hash = "c" * 64
            guard_hash = "d" * 64
            receipt_hash = "e" * 64
            receipt = {
                "binary": {"relative_path": relative_binary, "sha256": binary_hash, "size": 123},
                "source_sha256": {source_path: source_hash},
                "tools": {
                    name: {"sha256": tool_hash, "size": 1}
                    for name in ("lean", "lake", "leanchecker", "pwsh")
                },
                "guard": {"sha256": guard_hash},
            }

            def fake_hash_file(path: Path, label: str, *, expected_size: int | None = None) -> tuple[str, int]:
                if label == "formal_binary":
                    return binary_hash, 123
                if label.startswith("source."):
                    return source_hash, 1
                if label.startswith("tool."):
                    return tool_hash, 1
                if label == "guard":
                    return guard_hash, 1
                raise AssertionError(f"unexpected artifact hash request: {label}")

            with (
                mock.patch.multiple(
                    lean_adapter,
                    PRODUCT_ROOT=root,
                    FORMAL_ROOT=formal_root,
                    FORMAL_BINARY=binary,
                    EXPECTED_BINARY_RELATIVE_PATH=relative_binary,
                    EXPECTED_GUARD_RELATIVE_PATH="guard.ps1",
                    EXISTING_GUARD=guard,
                    RECEIPT_SOURCE_PATHS=(source_path,),
                    PINNED_LEAN=root / "lean.exe",
                    PINNED_LAKE=root / "lake.exe",
                    PINNED_LEANCHECKER=root / "leanchecker.exe",
                    PINNED_PWSH=root / "pwsh.exe",
                ),
                mock.patch.object(lean_adapter, "_path_is_link_or_reparse", return_value=False),
                mock.patch.object(
                    lean_adapter, "_load_artifact_receipt", return_value=(receipt, receipt_hash)
                ),
                mock.patch.object(
                    lean_adapter, "_resolve_product_path", side_effect=lambda relative: root / Path(relative)
                ),
                mock.patch.object(lean_adapter, "_hash_file", side_effect=fake_hash_file),
                mock.patch.object(
                    lean_adapter,
                    "_load_module_provenance",
                    side_effect=lean_adapter.FormalArithmeticError(
                        "module_provenance_missing_or_link"
                    ),
                ) as provenance_loader,
            ):
                runtime_identity = lean_adapter._artifact_identity()
                self.assertEqual(len(runtime_identity), 10)
                provenance_loader.assert_not_called()
                with self.assertRaisesRegex(
                    lean_adapter.FormalArithmeticError,
                    "module_provenance_missing_or_link",
                ):
                    lean_adapter._artifact_identity(require_module_provenance=True)
                provenance_loader.assert_called_once_with(
                    receipt,
                    receipt_hash,
                    verify_files=False,
                    derived_import_graph=None,
                    derived_import_paths=None,
                    derived_import_graph_sha256=None,
                )


class CompiledModuleProvenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.toolchain_root = self.root / "toolchain"
        (self.toolchain_root / "bin").mkdir(parents=True)
        (self.toolchain_root / "lib" / "lean").mkdir(parents=True)
        self.lean_path = self.toolchain_root / "bin" / "lean.exe"
        self.lean_path.write_bytes(b"synthetic lean")
        self.provenance_path = self.root / "formal" / "lean" / "module_provenance.v1.json"
        self.receipt_hash = "e" * 64
        self.binary_bytes = b"synthetic linked binary"
        self.receipt = {
            "build_id": lean_adapter.BUILD_ID,
            "schema_id": lean_adapter.SCHEMA_ID,
            "toolchain": lean_adapter.PINNED_TOOLCHAIN,
            "source_sha256": {
                path: ("a" * 64) for path in lean_adapter.RECEIPT_SOURCE_PATHS
            },
            "tools": {
                name: {"sha256": ("b" * 64), "size": 1}
                for name in ("lean", "lake", "leanchecker", "pwsh")
            },
            "binary": {
                "relative_path": lean_adapter.EXPECTED_BINARY_RELATIVE_PATH,
                "sha256": hashlib.sha256(self.binary_bytes).hexdigest(),
                "size": len(self.binary_bytes),
            },
        }
        self.provenance = self._make_provenance()

    @staticmethod
    def _write_artifact(root: Path, relative_path: str, contents: bytes) -> dict[str, object]:
        path = root / Path(relative_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(contents)
        return {
            "relative_path": relative_path,
            "sha256": hashlib.sha256(contents).hexdigest(),
            "size": len(contents),
        }

    def _make_provenance(self) -> dict[str, object]:
        rebuild_directory = (
            "formal/lean/.lake/module-provenance-test/workspace/.lake/build-v2"
        )
        modules: list[dict[str, object]] = []
        for module in lean_adapter.LINK_MODULE_ORDER:
            source_path = lean_adapter._module_source_relative_path(module)
            module_record: dict[str, object] = {
                "name": module,
                "source_path": source_path,
                "source_sha256": self.receipt["source_sha256"][source_path],
                "imports": list(lean_adapter.PROJECT_MODULE_IMPORTS[module]),
                "olean_imports": list(lean_adapter.PROJECT_MODULE_IMPORTS[module]),
            }
            module_stem = lean_adapter._module_output_relative_path(module, "olean")[:-6]
            olean_relative = module_stem + ".olean"
            module_record["olean_files"] = [
                {
                    "role": "olean",
                    **self._write_artifact(
                        self.root, olean_relative, f"{module}:olean".encode("ascii")
                    ),
                }
            ]
            reproduced_olean_path = lean_adapter._module_output_relative_path(
                module, "olean", build_directory=rebuild_directory
            )
            module_record["reproduced_olean_files"] = [
                {
                    "role": "olean",
                    **self._write_artifact(
                        self.root, reproduced_olean_path, f"{module}:olean".encode("ascii")
                    ),
                }
            ]
            for kind in ("generated_c", "native_object"):
                relative_path = lean_adapter._module_output_relative_path(module, kind)
                module_record[kind] = self._write_artifact(
                    self.root, relative_path, f"{module}:{kind}".encode("ascii")
                )
                reproduced_relative_path = lean_adapter._module_output_relative_path(
                    module, kind, build_directory=rebuild_directory
                )
                module_record[f"reproduced_{kind}"] = self._write_artifact(
                    self.root, reproduced_relative_path, f"{module}:{kind}".encode("ascii")
                )
            modules.append(module_record)

        def response_bytes(build_directory: str) -> bytes:
            tail: list[str] = []
            for index, argument in enumerate(lean_adapter.EXPECTED_LINK_RESPONSE_TAIL):
                if index == 5:
                    tail.append(str(self.toolchain_root / "lib" / "lean"))
                elif index == 7:
                    tail.append(str(self.toolchain_root))
                elif index == 9:
                    tail.append(str(self.toolchain_root / "lib"))
                else:
                    tail.append(argument)
            return (
                "\n".join(
                    json.dumps(
                        str(
                            self.root
                            / Path(
                                lean_adapter._module_output_relative_path(
                                    module, "native_object", build_directory=build_directory
                                )
                            )
                        )
                    )
                    for module in lean_adapter.LINK_MODULE_ORDER
                )
                + "\n"
                + "\n".join(json.dumps(argument) for argument in tail)
            ).encode("utf-8")


        response = self._write_artifact(
            self.root,
            lean_adapter._link_response_relative_path(lean_adapter.EXPECTED_BUILD_DIRECTORY),
            response_bytes(lean_adapter.EXPECTED_BUILD_DIRECTORY),
        )
        reproduced_response = self._write_artifact(
            self.root,
            lean_adapter._link_response_relative_path(rebuild_directory),
            response_bytes(rebuild_directory),
        )
        linker_driver = self._write_artifact(
            self.toolchain_root, lean_adapter.EXPECTED_LINKER_DRIVER_RELATIVE_PATH,
            b"synthetic clang",
        )
        linker = self._write_artifact(
            self.toolchain_root, lean_adapter.EXPECTED_LINKER_RELATIVE_PATH,
            b"synthetic lld",
        )
        inspector_script = self._write_artifact(
            self.root,
            lean_adapter.IMPORT_GRAPH_SCRIPT_RELATIVE_PATH,
            b"synthetic import graph inspector",
        )
        trace_linker_path = self.toolchain_root / Path(
            lean_adapter.EXPECTED_LINKER_DRIVER_RELATIVE_PATH
        )

        def link_trace(build_directory: str) -> dict[str, object]:
            trace_objects = [
                [
                    str(
                        self.root
                        / Path(
                            lean_adapter._module_output_relative_path(
                                module, "native_object", build_directory=build_directory
                            )
                        )
                    ),
                    f"{index:016x}",
                ]
                for index, module in enumerate(lean_adapter.LINK_MODULE_ORDER)
            ]
            trace_response_path = self.root / Path(
                lean_adapter._link_response_relative_path(build_directory)
            )
            trace_binary_path = self.root / Path(lean_adapter._binary_relative_path(build_directory))
            relative_trace = lean_adapter._link_trace_relative_path(build_directory)
            return self._write_artifact(
                self.root,
                relative_trace,
                json.dumps(
                    {
                        "log": [
                            {
                                "message": (
                                    f".> {trace_linker_path} -o {trace_binary_path} @{trace_response_path}"
                                ),
                                "level": "trace",
                            }
                        ],
                        "inputs": [
                            [
                                "BlindLedger.SecurityExecutable:linkInfo",
                                [
                                    ["Module.moreLinkObjs", trace_objects],
                                    [
                                        "Module.moreLinkLibs",
                                        lean_adapter.EXPECTED_MODULE_LINK_LIBRARIES_FINGERPRINT,
                                    ],
                                    [
                                        lean_adapter.EXPECTED_MODULE_LINK_ARGUMENT,
                                        lean_adapter.EXPECTED_MODULE_LINK_ARGUMENT_FINGERPRINT,
                                    ],
                                ],
                            ],
                            [
                                lean_adapter.EXPECTED_LINK_EXE_ARGUMENT,
                                lean_adapter.EXPECTED_LINK_EXE_ARGUMENT_FINGERPRINT,
                            ],
                            [
                                lean_adapter.EXPECTED_LINK_COMPILER_ID,
                                lean_adapter.EXPECTED_LINK_COMPILER_FINGERPRINT,
                            ],
                            [
                                lean_adapter.EXPECTED_LINK_TARGET_TRIPLE,
                                lean_adapter.EXPECTED_LINK_TARGET_FINGERPRINT,
                            ],
                        ],
                    }
                ).encode("utf-8"),
            )

        original_link_trace = link_trace(lean_adapter.EXPECTED_BUILD_DIRECTORY)
        reproduced_link_trace = link_trace(rebuild_directory)
        library = self._write_artifact(
            self.toolchain_root, "lib/lean/libLean.a", b"synthetic linked archive"
        )

        def resolved_inputs(build_directory: str) -> list[dict[str, object]]:
            object_field = (
                "native_object"
                if build_directory == lean_adapter.EXPECTED_BUILD_DIRECTORY
                else "reproduced_native_object"
            )
            inputs = [
                {"root": "product", **record[object_field]}
                for record in modules
            ]
            inputs.append({"root": "toolchain", **library})
            return inputs

        original_resolved_inputs = resolved_inputs(lean_adapter.EXPECTED_BUILD_DIRECTORY)
        reproduced_resolved_inputs = resolved_inputs(rebuild_directory)

        def link_input_trace_run(
            build_directory: str,
            suffix: str,
            inputs: list[dict[str, object]],
        ) -> dict[str, object]:
            return {
                "run_suffix": suffix,
                "driver_path": str(trace_linker_path),
                "driver_sha256": linker_driver["sha256"],
                "driver_size": linker_driver["size"],
                "linker_path": str(self.toolchain_root / Path(lean_adapter.EXPECTED_LINKER_RELATIVE_PATH)),
                "linker_sha256": linker["sha256"],
                "linker_size": linker["size"],
                "arguments": [
                    "-o", "<temporary-output>",
                    f"@{lean_adapter._link_response_relative_path(build_directory)}",
                    "-Wl,-t",
                ],
                "working_directory": lean_adapter._formal_working_directory_relative(build_directory),
                "child_exit": 0,
                "outer_guard_exit": 0,
                "guard_cleanup": "PASS",
                "mutex_released": True,
                "guard_relative_path": lean_adapter.PROVENANCE_GUARD_RELATIVE_PATH,
                "guard_sha256": lean_adapter.PROVENANCE_GUARD_SHA256,
                "guard_policy_version": "v4",
                "guard_stdout_sha256": "d" * 64,
                "guard_stderr_sha256": "f" * 64,
                "input_trace_sha256": lean_adapter._link_input_trace_hash(inputs),
                "minimum_start_free_bytes": lean_adapter.PROVENANCE_GUARD_MINIMUM_START_FREE_BYTES,
            }

        toolchain_modules: list[dict[str, object]] = []
        for module in sorted({*lean_adapter.TOOLCHAIN_IMPORT_ROOTS, "Lean"}):
            module_stem = "lib/lean/" + module.replace(".", "/")
            toolchain_modules.append(
                {
                    "name": module,
                    "imports": [],
                    "olean_files": [
                        {
                            "role": "olean",
                            **self._write_artifact(
                                self.toolchain_root, module_stem + ".olean",
                                f"toolchain:{module}".encode("ascii"),
                            ),
                        }
                    ],
                }
            )

        build_result: dict[str, object] = {
            "rebuild_mode": "isolated-empty-build-directory",
            "rebuild_directory": rebuild_directory,
            "lake_target": "blind_security_arithmetic_v2",
            "lake_rehash": True,
            "lake_exit": 0,
            "axiom_check_exit": 0,
            "checker_exit": 0,
            "guard_exit": 0,
            "guard_cleanup": "PASS",
            "mutex_released": True,
            "guard_relative_path": lean_adapter.PROVENANCE_GUARD_RELATIVE_PATH,
            "guard_sha256": lean_adapter.PROVENANCE_GUARD_SHA256,
            "guard_policy_version": "v4",
            "binary_reproduced": True,
            "all_outputs_reproduced": True,
            "reproduced_binary": self._write_artifact(
                self.root,
                lean_adapter._binary_relative_path(rebuild_directory),
                self.binary_bytes,
            ),
            "output_inventory_sha256": "0" * 64,
            "guard_run_suffix": "lean-security-module-provenance-123",
            "stdout_sha256": "d" * 64,
            "stderr_sha256": "f" * 64,
            "minimum_start_free_bytes": lean_adapter.PROVENANCE_GUARD_MINIMUM_START_FREE_BYTES,
        }
        provenance: dict[str, object] = {
            "receipt_version": lean_adapter.MODULE_PROVENANCE_VERSION,
            "schema_id": lean_adapter.MODULE_PROVENANCE_SCHEMA_ID,
            "build_id": lean_adapter.BUILD_ID,
            "artifact_receipt_sha256": self.receipt_hash,
            "toolchain": lean_adapter.PINNED_TOOLCHAIN,
            "source_sha256": self.receipt["source_sha256"],
            "tools": self.receipt["tools"],
            "binary": self.receipt["binary"],
            "build_result": build_result,
            "checker": {
                "target_module": lean_adapter.EXPECTED_CHECKER_MODULE,
                "replay_mode": "imported-environment-replay",
                "checked_modules": [lean_adapter.EXPECTED_CHECKER_MODULE],
                "loaded_project_modules": list(lean_adapter.CHECKER_PROJECT_MODULES),
                "loaded_toolchain_modules": list(lean_adapter.TOOLCHAIN_IMPORT_ROOTS),
                "toolchain_import_roots": list(lean_adapter.TOOLCHAIN_IMPORT_ROOTS),
                "inspection_roots": list(lean_adapter.IMPORT_GRAPH_ROOTS),
                "run": {
                    "run_suffix": "lean-security-independent-checker-123",
                    "executable_path": str(lean_adapter.PINNED_LEANCHECKER),
                    "executable_sha256": self.receipt["tools"]["leanchecker"]["sha256"],
                    "executable_size": self.receipt["tools"]["leanchecker"]["size"],
                    "arguments": [lean_adapter.EXPECTED_CHECKER_MODULE],
                    "working_directory": "formal/lean",
                    "lean_path": "formal/lean/.lake/build-v2/lib/lean",
                    "child_exit": 0,
                    "outer_guard_exit": 0,
                    "guard_cleanup": "PASS",
                    "mutex_released": True,
                    "guard_relative_path": lean_adapter.PROVENANCE_GUARD_RELATIVE_PATH,
                    "guard_sha256": lean_adapter.PROVENANCE_GUARD_SHA256,
                    "guard_policy_version": "v4",
                    "guard_stdout_sha256": "d" * 64,
                    "guard_stderr_sha256": "f" * 64,
                    "input_manifest_sha256": "0" * 64,
                    "input_inventory_sha256": "0" * 64,
                    "import_graph_sha256": "0" * 64,
                    "minimum_start_free_bytes": lean_adapter.PROVENANCE_GUARD_MINIMUM_START_FREE_BYTES,
                },
            },
            "inspector": {
                "script": inspector_script,
                "roots": list(lean_adapter.IMPORT_GRAPH_ROOTS),
                "run": {
                    "run_suffix": "lean-security-import-graph-123",
                    "executable_path": str(self.lean_path),
                    "executable_sha256": self.receipt["tools"]["lean"]["sha256"],
                    "executable_size": self.receipt["tools"]["lean"]["size"],
                    "arguments": ["--run", "../../tools/direct_mask_contract/olean_imports.lean"],
                    "working_directory": "formal/lean",
                    "lean_path": "formal/lean/.lake/build-v2/lib/lean",
                    "child_exit": 0,
                    "outer_guard_exit": 0,
                    "guard_cleanup": "PASS",
                    "mutex_released": True,
                    "guard_relative_path": lean_adapter.PROVENANCE_GUARD_RELATIVE_PATH,
                    "guard_sha256": lean_adapter.PROVENANCE_GUARD_SHA256,
                    "guard_policy_version": "v4",
                    "guard_stdout_sha256": "d" * 64,
                    "guard_stderr_sha256": "f" * 64,
                    "graph_sha256": "0" * 64,
                    "minimum_start_free_bytes": lean_adapter.PROVENANCE_GUARD_MINIMUM_START_FREE_BYTES,
                },
            },
            "link": {
            "entry_module": "BlindLedger.SecurityExecutable",
            "target_triple": lean_adapter.EXPECTED_LINK_TARGET_TRIPLE,
            "module_order": list(lean_adapter.LINK_MODULE_ORDER),
            "response_file": response,
            "response_arguments": list(
                lean_adapter._read_link_response_arguments(
                    self.root / Path(response["relative_path"])
                )
            ),
            "link_trace": original_link_trace,
            "reproduced_response_file": reproduced_response,
            "reproduced_response_arguments": list(
                lean_adapter._read_link_response_arguments(
                    self.root / Path(reproduced_response["relative_path"])
                )
            ),
            "reproduced_link_trace": reproduced_link_trace,
                "linker_driver": linker_driver,
                "linker": linker,
                "resolved_inputs": original_resolved_inputs,
                "reproduced_resolved_inputs": reproduced_resolved_inputs,
                "link_input_trace_run": link_input_trace_run(
                    lean_adapter.EXPECTED_BUILD_DIRECTORY,
                    "lean-security-link-input-trace-123-locked",
                    original_resolved_inputs,
                ),
                "reproduced_link_input_trace_run": link_input_trace_run(
                    rebuild_directory,
                    "lean-security-link-input-trace-124-locked",
                    reproduced_resolved_inputs,
                ),
            },
            "modules": modules,
            "toolchain_modules": toolchain_modules,
        }
        graph_paths: dict[str, str] = {}
        graph_modules: list[dict[str, object]] = []
        for module_record in modules:
            module = str(module_record["name"])
            olean_record = module_record["olean_files"][0]
            graph_paths[module] = str(self.root / Path(olean_record["relative_path"]))
            graph_modules.append(
                {
                    "name": module,
                    "path": graph_paths[module],
                    "imports": module_record["olean_imports"],
                }
            )
        for module_record in toolchain_modules:
            module = str(module_record["name"])
            olean_record = module_record["olean_files"][0]
            graph_paths[module] = str(self.toolchain_root / Path(olean_record["relative_path"]))
            graph_modules.append(
                {
                    "name": module,
                    "path": graph_paths[module],
                    "imports": module_record["imports"],
                }
            )
        graph_payload = {
            "format": lean_adapter.IMPORT_GRAPH_FORMAT,
            "roots": list(lean_adapter.IMPORT_GRAPH_ROOTS),
            "modules": sorted(graph_modules, key=lambda record: record["name"]),
        }
        graph_json = json.dumps(graph_payload, ensure_ascii=True, separators=(",", ":"))
        self.import_graph, self.import_paths = lean_adapter._parse_olean_import_graph(graph_json)
        self.import_graph_hash = hashlib.sha256(graph_json.encode("utf-8")).hexdigest()
        provenance["inspector"]["run"]["graph_sha256"] = self.import_graph_hash
        provenance["checker"]["run"]["import_graph_sha256"] = self.import_graph_hash
        build_result["output_inventory_sha256"] = lean_adapter._module_provenance_output_inventory_hash(
            provenance
        )
        provenance["checker"]["run"]["input_inventory_sha256"] = build_result[
            "output_inventory_sha256"
        ]
        provenance["checker"]["run"]["input_manifest_sha256"] = (
            lean_adapter._module_provenance_manifest_hash(provenance)
        )
        return provenance

    def _refresh_inventory_hashes(self) -> None:
        inventory_hash = lean_adapter._module_provenance_output_inventory_hash(self.provenance)
        self.provenance["build_result"]["output_inventory_sha256"] = inventory_hash
        self.provenance["checker"]["run"]["input_inventory_sha256"] = inventory_hash
        self.provenance["checker"]["run"]["input_manifest_sha256"] = (
            lean_adapter._module_provenance_manifest_hash(self.provenance)
        )

    def _load(self, provenance: dict[str, object] | None = None) -> tuple[object, ...]:
        payload = self.provenance if provenance is None else provenance
        self.provenance_path.parent.mkdir(parents=True, exist_ok=True)
        raw = (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")
        self.provenance_path.write_bytes(raw)
        with (
            mock.patch.object(lean_adapter, "MODULE_PROVENANCE_RECEIPT", self.provenance_path),
            mock.patch.object(lean_adapter, "EXPECTED_MODULE_PROVENANCE_SHA256", hashlib.sha256(raw).hexdigest()),
            mock.patch.object(lean_adapter, "PRODUCT_ROOT", self.root),
            mock.patch.object(lean_adapter, "PINNED_LEAN", self.lean_path),
        ):
            return lean_adapter._load_module_provenance(
                self.receipt,
                self.receipt_hash,
                verify_files=True,
                derived_import_graph=self.import_graph,
                derived_import_paths=self.import_paths,
                derived_import_graph_sha256=self.import_graph_hash,
            )

    def test_valid_provenance_binds_build_outputs_checker_scope_and_link_inputs(self) -> None:
        _, artifacts, checker_paths, manifest_hash, inventory_hash = self._load()
        self.assertEqual(
            len(artifacts),
            16 * 6
            + 1
            + 1
            + 2
            + 2
            + 2
            + len(self.provenance["link"]["resolved_inputs"])
            + len(self.provenance["link"]["reproduced_resolved_inputs"])
            + len(self.provenance["toolchain_modules"]),
        )
        self.assertEqual(
            len(checker_paths),
            len(lean_adapter.CHECKER_PROJECT_MODULES) + len(lean_adapter.TOOLCHAIN_IMPORT_ROOTS),
        )
        self.assertEqual(
            self.provenance["checker"]["run"]["input_manifest_sha256"], manifest_hash
        )
        self.assertEqual(
            self.provenance["checker"]["run"]["input_inventory_sha256"], inventory_hash
        )

    def test_pinned_project_import_graph_matches_sources_and_checker_scope(self) -> None:
        for module, expected_imports in lean_adapter.PROJECT_MODULE_IMPORTS.items():
            source = lean_adapter.FORMAL_ROOT / Path(lean_adapter._module_source_relative_path(module)).relative_to(
                "formal/lean"
            )
            text = source.read_text(encoding="utf-8")
            actual_imports = re.findall(r"(?m)^import\s+([A-Za-z][A-Za-z0-9_.]*)\s*$", text)
            self.assertEqual(tuple(actual_imports), expected_imports, module)
        self.assertEqual(len(lean_adapter.CHECKER_PROJECT_MODULES), 15)
        self.assertEqual(lean_adapter.EXPECTED_CHECKER_MODULE, "BlindLedger.Theorems")

    def test_sidecar_import_graph_must_match_inspected_olean_imports(self) -> None:
        altered = copy.deepcopy(self.provenance)
        executable_record = next(
            record for record in altered["modules"]
            if record["name"] == "BlindLedger.SecurityExecutable"
        )
        executable_record["olean_imports"].append("Lean")
        with self.assertRaisesRegex(
            lean_adapter.FormalArithmeticError,
            "module_provenance_actual_import_graph_mismatch",
        ):
            self._load(altered)

    def test_checker_and_inspector_runs_are_excluded_from_static_manifest(self) -> None:
        expected = lean_adapter._module_provenance_manifest_hash(self.provenance)
        altered = copy.deepcopy(self.provenance)
        altered["checker"]["run"]["run_suffix"] = "lean-security-independent-checker-999"
        altered["checker"]["run"]["guard_stdout_sha256"] = "a" * 64
        altered["inspector"]["run"]["run_suffix"] = "lean-security-import-graph-999"
        altered["inspector"]["run"]["guard_stdout_sha256"] = "b" * 64
        self.assertEqual(lean_adapter._module_provenance_manifest_hash(altered), expected)

    def test_missing_module_output_fails_closed(self) -> None:
        module = lean_adapter.LINK_MODULE_ORDER[0]
        relative = lean_adapter._module_output_relative_path(module, "olean")
        (self.root / Path(relative)).unlink()
        with self.assertRaisesRegex(lean_adapter.FormalArithmeticError, "module_provenance\.local_missing_or_link"):
            self._load()

    def test_swapped_module_output_fails_closed(self) -> None:
        first, second = "BlindLedger.RowBoundsFS1", "BlindLedger.RowBoundsFS2"
        first_path = self.root / Path(lean_adapter._module_output_relative_path(first, "olean"))
        second_path = self.root / Path(lean_adapter._module_output_relative_path(second, "olean"))
        first_bytes, second_bytes = first_path.read_bytes(), second_path.read_bytes()
        first_path.write_bytes(second_bytes)
        second_path.write_bytes(first_bytes)
        with self.assertRaisesRegex(lean_adapter.FormalArithmeticError, "module_provenance\.local\..*olean_hash_mismatch"):
            self._load()

    def test_reproduced_output_divergence_fails_closed(self) -> None:
        module = lean_adapter.LINK_MODULE_ORDER[0]
        record = next(item for item in self.provenance["modules"] if item["name"] == module)
        relative_path = record["reproduced_generated_c"]["relative_path"]
        record["reproduced_generated_c"] = self._write_artifact(
            self.root, relative_path, b"divergent generated C"
        )
        self._refresh_inventory_hashes()
        with self.assertRaisesRegex(
            lean_adapter.FormalArithmeticError,
            f"module_provenance_reproduced_output_mismatch={re.escape(module)}\\.generated_c",
        ):
            self._load()

    def test_reproduced_olean_divergence_fails_closed(self) -> None:
        module = lean_adapter.LINK_MODULE_ORDER[0]
        record = next(item for item in self.provenance["modules"] if item["name"] == module)
        olean_record = record["reproduced_olean_files"][0]
        record["reproduced_olean_files"][0] = {
            "role": olean_record["role"],
            **self._write_artifact(
                self.root, olean_record["relative_path"], b"divergent reproduced OLean"
            ),
        }
        self._refresh_inventory_hashes()
        with self.assertRaisesRegex(
            lean_adapter.FormalArithmeticError,
            f"module_provenance_reproduced_olean_mismatch={re.escape(module)}",
        ):
            self._load()

    def test_reproduced_link_response_mismatch_fails_closed(self) -> None:
        response_record = self.provenance["link"]["reproduced_response_file"]
        response_path = self.root / Path(response_record["relative_path"])
        response_lines = response_path.read_text(encoding="utf-8").splitlines()
        response_lines.append(json.dumps("-Wl,--gc-sections"))
        self.provenance["link"]["reproduced_response_file"] = self._write_artifact(
            self.root, response_record["relative_path"], "\n".join(response_lines).encode("utf-8")
        )
        self._refresh_inventory_hashes()
        with self.assertRaisesRegex(
            lean_adapter.FormalArithmeticError,
            "module_provenance_link_response_argument_count_mismatch",
        ):
            self._load()

    def test_link_response_argument_vector_is_explicit_and_exact(self) -> None:
        self.provenance["link"]["response_arguments"][-1] = "-Wl,--gc-sections"
        self._refresh_inventory_hashes()
        with self.assertRaisesRegex(
            lean_adapter.FormalArithmeticError,
            "module_provenance_link_response_argument_mismatch",
        ):
            self._load()

    def test_link_trace_run_must_record_the_target_specific_start_floor(self) -> None:
        self.provenance["link"]["link_input_trace_run"]["minimum_start_free_bytes"] = (
            lean_adapter.EXPECTED_EFFECTIVE_FREE_FLOOR_BYTES
        )
        self._refresh_inventory_hashes()
        with self.assertRaisesRegex(
            lean_adapter.FormalArithmeticError,
            "module_provenance\.link\.link_input_trace_run_minimum_start_free_bytes_mismatch",
        ):
            self._load()

    def test_private_olean_without_server_fails_closed(self) -> None:
        module = lean_adapter.LINK_MODULE_ORDER[0]
        relative = lean_adapter._module_output_relative_path(module, "olean") + ".private"
        self._write_artifact(self.root, relative, b"unexpected private OLean")
        with self.assertRaisesRegex(
            lean_adapter.FormalArithmeticError,
            "module_provenance.local_private_without_server",
        ):
            self._load()

    def test_malformed_link_trace_inputs_fail_closed(self) -> None:
        trace_record = self.provenance["link"]["reproduced_link_trace"]
        trace_path = self.root / Path(trace_record["relative_path"])
        trace = json.loads(trace_path.read_text(encoding="utf-8"))
        trace["inputs"] = {}
        trace_record.update(
            self._write_artifact(
                self.root, trace_record["relative_path"], json.dumps(trace).encode("utf-8")
            )
        )
        self._refresh_inventory_hashes()
        with self.assertRaisesRegex(
            lean_adapter.FormalArithmeticError,
            "module_provenance_link_trace_inputs_invalid",
        ):
            self._load()

    def test_link_trace_rejects_duplicate_json_keys(self) -> None:
        trace_record = self.provenance["link"]["reproduced_link_trace"]
        trace_path = self.root / Path(trace_record["relative_path"])
        raw_trace = trace_path.read_text(encoding="utf-8")
        duplicated = raw_trace.replace('"inputs":', '"inputs": [], "inputs":', 1)
        self.assertNotEqual(duplicated, raw_trace)
        trace_record.update(
            self._write_artifact(self.root, trace_record["relative_path"], duplicated.encode("utf-8"))
        )
        self._refresh_inventory_hashes()
        with self.assertRaisesRegex(
            lean_adapter.FormalArithmeticError,
            "module_provenance_link_trace_invalid=.*duplicate_json_key",
        ):
            self._load()

    def test_link_trace_target_hash_requires_canonical_lean_hash(self) -> None:
        trace_record = self.provenance["link"]["reproduced_link_trace"]
        trace_path = self.root / Path(trace_record["relative_path"])
        for target_hash in ("", "not-a-hash", "0" * 15, "g" * 16):
            with self.subTest(target_hash=target_hash):
                trace = json.loads(trace_path.read_text(encoding="utf-8"))
                target_input = next(
                    entry for entry in trace["inputs"]
                    if entry[0] == lean_adapter.EXPECTED_LINK_TARGET_TRIPLE
                )
                target_input[1] = target_hash
                trace_record.update(
                    self._write_artifact(
                        self.root,
                        trace_record["relative_path"],
                        json.dumps(trace).encode("utf-8"),
                    )
                )
                self._refresh_inventory_hashes()
                with self.assertRaisesRegex(
                    lean_adapter.FormalArithmeticError,
                    "module_provenance_link_trace_target_triple_mismatch",
                ):
                    self._load()

    def test_link_trace_rejects_different_compiler_toolchain_identity(self) -> None:
        trace_record = self.provenance["link"]["reproduced_link_trace"]
        trace_path = self.root / Path(trace_record["relative_path"])
        trace = json.loads(trace_path.read_text(encoding="utf-8"))
        compiler_input = next(
            entry for entry in trace["inputs"]
            if entry[0] == lean_adapter.EXPECTED_LINK_COMPILER_ID
        )
        compiler_input[0] = "Lean 4.32.0, commit obsolete"
        trace_record.update(
            self._write_artifact(
                self.root, trace_record["relative_path"], json.dumps(trace).encode("utf-8")
            )
        )
        self._refresh_inventory_hashes()
        with self.assertRaisesRegex(
            lean_adapter.FormalArithmeticError,
            "module_provenance_link_trace_input_set_mismatch",
        ):
            self._load()

    def test_malformed_link_trace_object_entry_is_not_silently_skipped(self) -> None:
        trace_record = self.provenance["link"]["reproduced_link_trace"]
        trace_path = self.root / Path(trace_record["relative_path"])
        trace = json.loads(trace_path.read_text(encoding="utf-8"))
        trace["inputs"][0][1][0][1] = ["malformed-object-record"]
        trace_record.update(
            self._write_artifact(
                self.root, trace_record["relative_path"], json.dumps(trace).encode("utf-8")
            )
        )
        self._refresh_inventory_hashes()
        with self.assertRaisesRegex(
            lean_adapter.FormalArithmeticError,
            "module_provenance_link_trace_object_entry_invalid",
        ):
            self._load()

    def test_checker_run_must_bind_the_validated_inventory_and_manifest(self) -> None:
        cases = (
            (
                "inventory",
                "input_inventory_sha256",
                "0" * 64,
                "module_provenance_checker_input_inventory_mismatch",
            ),
            (
                "manifest",
                "input_manifest_sha256",
                "0" * 64,
                "module_provenance_checker_input_manifest_mismatch",
            ),
        )
        for label, field, value, error in cases:
            with self.subTest(checker_run_field=label):
                altered = copy.deepcopy(self.provenance)
                altered["checker"]["run"][field] = value
                with self.assertRaisesRegex(lean_adapter.FormalArithmeticError, error):
                    self._load(altered)

    def test_stale_provenance_receipt_fails_closed(self) -> None:
        stale = copy.deepcopy(self.provenance)
        stale["artifact_receipt_sha256"] = "0" * 64
        with self.assertRaisesRegex(lean_adapter.FormalArithmeticError, "module_provenance_stale_receipt"):
            self._load(stale)

    def test_symlinked_module_output_fails_closed(self) -> None:
        module = lean_adapter.LINK_MODULE_ORDER[0]
        target = self.root / Path(lean_adapter._module_output_relative_path(module, "olean"))
        with mock.patch.object(
            lean_adapter,
            "_path_is_link_or_reparse",
            side_effect=lambda path: Path(path) == target,
        ):
            with self.assertRaisesRegex(lean_adapter.FormalArithmeticError, "module_provenance\.local_missing_or_link"):
                self._load()

    def test_provenance_version_mismatch_fails_closed(self) -> None:
        wrong_version = copy.deepcopy(self.provenance)
        wrong_version["receipt_version"] = 2
        with self.assertRaisesRegex(lean_adapter.FormalArithmeticError, "module_provenance_version_invalid=2"):
            self._load(wrong_version)

    def test_provenance_pin_must_be_explicit(self) -> None:
        raw = (json.dumps(self.provenance, separators=(",", ":")) + "\n").encode("utf-8")
        self.provenance_path.parent.mkdir(parents=True, exist_ok=True)
        self.provenance_path.write_bytes(raw)
        with (
            mock.patch.object(lean_adapter, "MODULE_PROVENANCE_RECEIPT", self.provenance_path),
            mock.patch.object(lean_adapter, "EXPECTED_MODULE_PROVENANCE_SHA256", None),
        ):
            with self.assertRaisesRegex(lean_adapter.FormalArithmeticError, "module_provenance_hash_unpinned"):
                lean_adapter._load_module_provenance(self.receipt, self.receipt_hash)


class FilteredContractV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = load_manifest()

    def test_v2_manifest_source_and_axiom_checker_share_exact_inventory(self) -> None:
        arithmetic = (lean_adapter.FORMAL_ROOT / "BlindLedger" / "Arithmetic.lean").read_text(
            encoding="utf-8"
        )
        inventory_match = re.search(
            r"def theoremManifest : List String :=\s*\[(.*?)\]\s*\n\n",
            arithmetic,
            re.DOTALL,
        )
        self.assertIsNotNone(inventory_match)
        manifest_names = re.findall(r'"([a-z][A-Za-z0-9_]*)"', inventory_match.group(1))
        axiom_checker = (lean_adapter.FORMAL_ROOT / "BlindLedger" / "AxiomCheck.lean").read_text(
            encoding="utf-8"
        )
        checker_names = re.findall(r"(?m)^#print axioms ([a-z][A-Za-z0-9_]*)$", axiom_checker)
        expected = list(lean_adapter.EXPECTED_THEOREM_MANIFEST)
        self.assertEqual(manifest_names, expected)
        self.assertEqual(checker_names, expected)
        self.assertEqual(len(manifest_names), 32)
        self.assertEqual(len(set(manifest_names)), 32)

    @staticmethod
    def _counters() -> dict[str, object]:
        return {
            "Q": 1,
            "A": 1,
            "V": 1,
            "M": 1,
            "E_U": 1,
            "S": 1,
            "R0": 2,
            "R2": 3,
            "R3": 4,
            "h0_first": 1,
            "h0_accepted": 1,
            "h0_rejected": 1,
            "h0_aborted": 0,
            "h0_oracle_evaluations": 2,
            "fs2_first": 1,
            "fs2_accepted": 1,
            "fs2_rejected": 1,
            "fs2_aborted": 1,
            "fs2_oracle_evaluations": 3,
            "fs3_first": 1,
            "fs3_accepted": 1,
            "fs3_rejected": 2,
            "fs3_aborted": 1,
            "fs3_oracle_evaluations": 4,
            "one_commitment_per_attempt": True,
            "source_generation_admitted": True,
            "U96_nonzero": True,
            "source_coins_independent": True,
            "source_cap_enforced": True,
        }

    @staticmethod
    def _fraction(payload: dict[str, str]) -> Fraction:
        return Fraction(int(payload["numerator"]), int(payload["denominator"]))

    def test_v2_manifest_is_versioned_and_v1_remains_accepted(self) -> None:
        self.assertEqual(self.manifest["manifest_version"], "direct-mask-contract/v2-filtered")
        self.assertTrue(self.manifest["v1_preservation"]["v2_does_not_qualify_or_replace_v1"])
        self.assertEqual(self.manifest["protocol"]["T_open"], 229)
        self.assertEqual(self.manifest["protocol"]["path_union_threshold_n_h"], 294)
        self.assertTrue(self.manifest["honest_algorithm"]["U_ownership"]["state_issued"])
        self.assertFalse(self.manifest["honest_algorithm"]["U_ownership"]["independent_of_public_statement"])
        from .calculator import load_manifest as load_v1_manifest

        v1 = load_v1_manifest()
        self.assertEqual(v1["manifest_version"], "direct-mask-contract/v1")
        self.assertFalse(v1["status"]["qualified"])

    def test_conditional_theorem_game_and_counter_reconciliation_are_explicit(self) -> None:
        theorem = self.manifest["certificate"]["theorem_application"]
        self.assertEqual(
            theorem["applicability"],
            "CONDITIONAL_ON_LITERAL_DMV2_FILTERED_GAME_AND_LOCAL_WITNESS_CORRESPONDENCE",
        )
        self.assertEqual(theorem["local_witness_predicate"]["qP"], 38)
        self.assertTrue(theorem["local_witness_predicate"]["replacement_stable"])
        self.assertEqual(theorem["filter_derivation"]["FS3"],
                         "For a fixed chain, B3 has at most three accepting 256-bit gamma3 payloads; an independent seven-bit suffix gives e3=(3/2^256)*2^-7=3/2^263. The whole v1 answer is not multiplied by 2^-7.")
        privacy = self.manifest["privacy"]
        self.assertFalse(privacy["H0_reprogrammed"])
        self.assertTrue(privacy["program_full_uniform_answer_before_filter"])
        self.assertTrue(privacy["FS3_opening_depends_on_payload"])
        reconciliation = self.manifest["candidate_accounting"]["counter_reconciliation"]
        self.assertTrue(reconciliation["state_101_reservations_unchanged"])
        self.assertIn("native enforcement is pending", reconciliation["caps"])

    def test_filtered_constants_are_exact_and_e3_dominates(self) -> None:
        constants = certificate_constants(self.manifest)
        exact = {name: self._fraction(payload) for name, payload in constants["exact"].items()}
        two = 1 << 256
        expected_e0 = Fraction(33 * math.comb(two, 2), 1 << 778)
        expected_ekos = Fraction(math.comb(1 << 248, 3), 1 << 1024) * (
            1 + Fraction(125049**5, 1 << 64)
        )
        expected_e2 = (1 + Fraction(172231**2, 1 << 64)) / (1 << 262)
        expected_e3 = Fraction(3, 1 << 263)
        self.assertEqual(exact, {"e0": expected_e0, "eKOS": expected_ekos, "e2": expected_e2, "e3": expected_e3})
        self.assertTrue(constants["max_is_e3"])
        self.assertTrue(constants["density_checks"]["a_lt_2^17"])
        self.assertTrue(constants["density_checks"]["m_minus_1_lt_2^18"])

    def test_row_bound_is_maximum_not_union_and_simplifies(self) -> None:
        for j in (0, 1, 2**32, 2**128):
            result = row_bounds(self.manifest, j)
            self.assertTrue(result["simplified_bound_holds"], j)
            self.assertTrue(result["single_typed_insertion_uses_maximum"])
            self.assertTrue(result["not_an_independent_union_sum"])
        zero = row_bounds(self.manifest, 0)
        self.assertEqual(self._fraction(zero["maximum_row_bound"]), Fraction(3, 1 << 263))

    def test_row_bound_input_is_fail_closed(self) -> None:
        for value, error in ((-1, "underflow"), (True, "integer_required"), (1.0, "integer_required"), (2**4096, "overflow")):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ContractError, error):
                    row_bounds(self.manifest, value)

    def test_qrom_cap_and_half_success_probe_are_exact(self) -> None:
        report = calculate_report_v2(self.manifest)
        self.assertEqual(report["formal_arithmetic"]["theorem_manifest_count"], 32)
        self.assertEqual(
            report["formal_arithmetic"]["theorem_manifest_names"],
            list(lean_adapter.EXPECTED_THEOREM_MANIFEST),
        )
        cap = report["qrom_soundness"]["cap_evaluation"]
        self.assertEqual(cap["q_overhead_at_declared_caps"], 4264009 * (1 << 32) + 38)
        self.assertTrue(cap["q_overhead_lt_2^55"])
        self.assertTrue(cap["bound_lt_one_quarter"])
        self.assertTrue(cap["half_success_probe_lt_one_half"])
        self.assertTrue(report["qrom_soundness"]["claim_limits"]["not_a_2^-128_false_acceptance_probability"])
        self.assertTrue(report["qrom_soundness"]["claim_limits"]["not_concrete_quantum_gate_or_work_bound"])

    def test_pinned_v2_operation_runs_without_module_provenance_sidecar(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            absent_sidecar = Path(scratch) / "module_provenance.v1.json"
            with (
                mock.patch.object(lean_adapter, "MODULE_PROVENANCE_RECEIPT", absent_sidecar),
                mock.patch.object(lean_adapter, "EXPECTED_MODULE_PROVENANCE_SHA256", None),
            ):
                result = run_formal_arguments(["cap"])
        self.assertEqual(result["header"]["result"], "PASS")
        self.assertEqual(result["theorems"]["manifest_count"], 32)

    def test_lean_batch_accepts_runtime_and_caps_and_rejects_invalid_counters(self) -> None:
        cap = run_formal_arguments(["cap"])
        self.assertEqual(cap["header"]["result"], "PASS")
        self.assertEqual(cap["theorems"]["manifest_count"], 32)
        self.assertEqual(cap["theorems"]["manifest_names"], list(lean_adapter.EXPECTED_THEOREM_MANIFEST))
        self.assertEqual(cap["theorems"]["manifest_count_proof"], "PROVED_THEOREM_TERM")
        self.assertEqual(cap["theorems"]["cap_bundle"], "PROVED_THEOREM_TERM")
        self.assertEqual(cap["theorems"]["width_bundle"], "PROVED_THEOREM_TERM")
        self.assertEqual(cap["theorems"]["completion_accounting"], "PROVED_THEOREM_TERM")
        self.assertEqual(cap["theorems"]["row_bounds_bundle"], "PROVED_THEOREM_TERM")
        self.assertEqual(cap["theorems"]["row_bounds_simplified"], "PROVED_THEOREM_TERM")
        self.assertEqual(cap["theorems"]["width384_delta_cap_all_k"], "PROVED_THEOREM_TERM")
        self.assertEqual(cap["theorems"]["width512_delta_cap_all_k"], "PROVED_THEOREM_TERM")
        self.assertEqual(cap["theorems"]["width_delta_all_k_bundle"], "PROVED_THEOREM_TERM")
        self.assertEqual(cap["theorems"]["crypto_primitives_custody_operations"], "EXTERNAL_PREMISES")
        self.assertEqual(cap["counters"]["Q"], 1 << 128)
        self.assertEqual(cap["qrom"]["q_overhead"], 4264009 * (1 << 32) + 38)
        self.assertEqual(set(cap["widths"]), {"384", "512"})

        counters = self._counters()
        runtime_arguments = [
            str(counters[key])
            for key in (
                "Q", "A", "V", "M", "E_U", "S", "R0", "R2", "R3",
                "h0_first", "h0_accepted", "h0_rejected", "h0_aborted", "h0_oracle_evaluations",
                "fs2_first", "fs2_accepted", "fs2_rejected", "fs2_aborted", "fs2_oracle_evaluations",
                "fs3_first", "fs3_accepted", "fs3_rejected", "fs3_aborted", "fs3_oracle_evaluations",
            )
        ] + [str(counters[key]).lower() for key in (
            "one_commitment_per_attempt", "source_generation_admitted", "U96_nonzero",
            "source_coins_independent", "source_cap_enforced",
        )]
        valid = run_formal_arguments(["runtime", *runtime_arguments])
        self.assertEqual(valid["header"]["result"], "PASS")
        self.assertEqual(valid["theorems"]["manifest_names"], list(lean_adapter.EXPECTED_THEOREM_MANIFEST))
        self.assertEqual(valid["qrom"]["q"], 121)
        row = run_formal_arguments(["row", "0"])
        self.assertEqual(row["header"]["result"], "PASS")
        self.assertEqual(row["theorems"]["manifest_names"], list(lean_adapter.EXPECTED_THEOREM_MANIFEST))
        self.assertEqual(row["row"]["j"], 0)
        self.assertEqual(row["row"]["maximum_row_bound"], (3, 1 << 263))
        self.assertTrue(row["row"]["simplified_bound_holds"])
        invalid_arguments = list(runtime_arguments)
        invalid_arguments[7] = str((1 << 12) + 1)
        invalid = run_formal_arguments(["runtime", *invalid_arguments])
        self.assertEqual(invalid["header"]["result"], "REJECT")
        self.assertEqual(invalid["header"]["error"], "counters-not-well-formed")

    def test_lean_adapter_cache_is_copy_safe_and_identity_checked(self) -> None:
        first = lean_adapter.run_formal_cap()
        first["counters"]["Q"] = -1
        first["widths"]["384"]["width"] = -1
        second = lean_adapter.run_formal_cap()
        self.assertEqual(second["counters"]["Q"], 1 << 128)
        self.assertEqual(second["widths"]["384"]["width"], 384)

        with mock.patch.object(
            lean_adapter,
            "_artifact_identity",
            side_effect=lean_adapter.FormalArithmeticError("identity-check"),
        ):
            with self.assertRaisesRegex(lean_adapter.FormalArithmeticError, "identity-check"):
                lean_adapter.run_formal_cap()

        identity = ("cache-test",)
        base = self._counters()

        def fake_runtime(identity_value: tuple[object, ...], key: tuple[int | bool, ...]) -> dict[str, object]:
            return {"identity": identity_value, "key": key}

        with mock.patch.object(lean_adapter, "_artifact_identity", return_value=identity), mock.patch.object(
            lean_adapter, "_run_formal_runtime_key", side_effect=fake_runtime
        ) as formal_call:
            lean_adapter._clear_caches()
            for index in range(lean_adapter.RUNTIME_CACHE_MAXSIZE):
                values = dict(base)
                values["Q"] = index + 1
                lean_adapter.run_formal_runtime(values)
            self.assertEqual(len(lean_adapter._RUNTIME_CACHE), lean_adapter.RUNTIME_CACHE_MAXSIZE)

            oldest = dict(base)
            oldest["Q"] = 1
            lean_adapter.run_formal_runtime(oldest)
            self.assertEqual(formal_call.call_count, lean_adapter.RUNTIME_CACHE_MAXSIZE)

            newest = dict(base)
            newest["Q"] = lean_adapter.RUNTIME_CACHE_MAXSIZE + 1
            lean_adapter.run_formal_runtime(newest)
            self.assertEqual(len(lean_adapter._RUNTIME_CACHE), lean_adapter.RUNTIME_CACHE_MAXSIZE)
            self.assertEqual(formal_call.call_count, lean_adapter.RUNTIME_CACHE_MAXSIZE + 1)

            evicted = dict(base)
            evicted["Q"] = 2
            lean_adapter.run_formal_runtime(evicted)
            self.assertEqual(formal_call.call_count, lean_adapter.RUNTIME_CACHE_MAXSIZE + 2)
            self.assertEqual(len(lean_adapter._RUNTIME_CACHE), lean_adapter.RUNTIME_CACHE_MAXSIZE)
        lean_adapter._clear_caches()

        identity = ("type-test",)
        valid = self._counters()
        malformed = (
            ("A", True, "runtime_counter_not_natural"),
            ("A", 1.0, "runtime_counter_not_natural"),
            ("one_commitment_per_attempt", 1, "runtime_flag_not_boolean"),
            ("one_commitment_per_attempt", 0, "runtime_flag_not_boolean"),
        )

        with mock.patch.object(lean_adapter, "_artifact_identity", return_value=identity), mock.patch.object(
            lean_adapter, "_run_formal_runtime_key", return_value={"ok": True}
        ) as formal_call:
            for field, bad_value, expected_error in malformed:
                lean_adapter._clear_caches()
                lean_adapter.run_formal_runtime(valid)
                warm = dict(valid)
                warm[field] = bad_value
                with self.assertRaisesRegex(lean_adapter.FormalArithmeticError, expected_error) as warm_context:
                    lean_adapter.run_formal_runtime(warm)

                lean_adapter._clear_caches()
                with self.assertRaisesRegex(lean_adapter.FormalArithmeticError, expected_error) as cold_context:
                    lean_adapter.run_formal_runtime(warm)
                self.assertEqual(str(warm_context.exception), str(cold_context.exception))
            self.assertEqual(formal_call.call_count, len(malformed))
        lean_adapter._clear_caches()

    @staticmethod
    def _normalise_row_manifest(names: list[str], manifest_count: int = 32) -> dict[str, object]:
        theorem_fields = [
            ("manifest_count", str(manifest_count)),
            ("manifest_names", ",".join(names)),
            ("manifest_count_proof", "PROVED_THEOREM_TERM"),
            ("cap_bundle", "PROVED_THEOREM_TERM"),
            ("width_bundle", "PROVED_THEOREM_TERM"),
            ("completion_accounting", "PROVED_THEOREM_TERM"),
            ("row_bounds_bundle", "PROVED_THEOREM_TERM"),
            ("row_bounds_simplified", "PROVED_THEOREM_TERM"),
            ("width384_delta_cap_all_k", "PROVED_THEOREM_TERM"),
            ("width512_delta_cap_all_k", "PROVED_THEOREM_TERM"),
            ("width_delta_all_k_bundle", "PROVED_THEOREM_TERM"),
            ("crypto_primitives_custody_operations", "EXTERNAL_PREMISES"),
        ]
        header = (
            f"{lean_adapter.HEADER_TAG};schema={lean_adapter.SCHEMA_ID};result=PASS;mode=row;"
            f"build_id={lean_adapter.BUILD_ID};toolchain={lean_adapter.PINNED_TOOLCHAIN}"
        )
        theorems = "THEOREMS" + "".join(f";{key}={value}" for key, value in theorem_fields)
        row = (
            "ROW;j=0;H0_leaf_bad_or_completion=0/1;H1_vector=0/1;H1_outer=0/1;"
            "FS1=0/1;FS2=0/1;FS3=0/1;other_typed_input=0/1;maximum_row_bound=0/1;"
            "simplified_replacement_bound=0/1;simplified_bound_holds=true"
        )
        parsed = lean_adapter._validate_result(f"{header}\n{theorems}\n{row}", "", "row")
        return lean_adapter._normalise_result(
            parsed, "row", require_pass=True, binary_sha256="a" * 64
        )

    def test_v2_manifest_consumer_rejects_identity_defects(self) -> None:
        expected = list(lean_adapter.EXPECTED_THEOREM_MANIFEST)
        reordered = [expected[1], expected[0], *expected[2:]]
        duplicated = [*expected[:-1], expected[0]]
        extra = [*expected, "unlisted_theorem"]
        wrong = ["cap_counters_well_formed_v2", *expected[1:]]
        cases = (
            ("omitted", expected[:-1], 32, "theorem_manifest_omitted_names"),
            ("reordered", reordered, 32, "theorem_manifest_order_mismatch"),
            ("duplicate", duplicated, 32, "theorem_manifest_duplicate_names"),
            ("extra", extra, 32, "theorem_manifest_extra_names"),
            ("wrong", wrong, 32, "theorem_manifest_extra_names"),
            ("wrong_count", expected, 31, "theorem_manifest_count_mismatch"),
        )
        for label, names, count, error in cases:
            with self.subTest(manifest_case=label):
                with self.assertRaisesRegex(lean_adapter.FormalArithmeticError, error):
                    self._normalise_row_manifest(names, count)

    def test_v2_consumer_rejects_v1_protocol_and_receipt_bytes(self) -> None:
        v1_header = (
            "BL-SECURITY-ARITHMETIC/1;schema=BLSECAR01/v1;result=PASS;mode=row;"
            "build_id=BL-SECURITY-ARITHMETIC-20260913-V1;toolchain=leanprover/lean4:v4.33.1"
        )
        with self.assertRaisesRegex(lean_adapter.FormalArithmeticError, "header_count=0"):
            lean_adapter._validate_result(v1_header, "", "row")

        with mock.patch.object(
            lean_adapter, "ARTIFACT_RECEIPT", lean_adapter.FORMAL_ROOT / "artifact_receipt.json"
        ), mock.patch.object(
            lean_adapter,
            "EXPECTED_RECEIPT_SHA256",
            "3a0094016d1e88285c821f7a81a745ac487f2800c1e04e537cd1339f25ea4455",
        ):
            with self.assertRaisesRegex(lean_adapter.FormalArithmeticError, "receipt_root_keys_mismatch"):
                lean_adapter._load_artifact_receipt()

    def test_lean_adapter_rejects_receipt_replacement_and_malformed_output(self) -> None:
        with mock.patch.object(lean_adapter, "EXPECTED_RECEIPT_SHA256", "0" * 64):
            with self.assertRaisesRegex(
                lean_adapter.FormalArithmeticError, "artifact_receipt_hash_mismatch"
            ):
                lean_adapter.run_formal_cap()

        identity = (
            "receipt", "build", "schema", "toolchain", "binary-hash",
            lean_adapter.FORMAL_BINARY.stat().st_size, (), (), (), "guard",
        )
        changed = (*identity[:-1], "changed-guard")
        with mock.patch.object(
            lean_adapter,
            "_artifact_identity",
            side_effect=[identity, identity, changed],
        ), mock.patch.object(lean_adapter, "_run_bounded", return_value=(0, b"", b"")):
            with self.assertRaisesRegex(
                lean_adapter.FormalArithmeticError, "formal_artifact_replaced_during_invocation"
            ):
                lean_adapter._invoke(["cap"], "cap")

        header = (
            f"{lean_adapter.HEADER_TAG};schema={lean_adapter.SCHEMA_ID};result=PASS;mode=row;"
            f"build_id={lean_adapter.BUILD_ID};toolchain={lean_adapter.PINNED_TOOLCHAIN}"
        )
        with self.assertRaisesRegex(lean_adapter.FormalArithmeticError, "record_tags_mismatch"):
            lean_adapter._validate_result(header + "\nUNKNOWN;x=1", "", "row")
        with self.assertRaisesRegex(lean_adapter.FormalArithmeticError, "blank_line"):
            lean_adapter._parse_records("TAG;x=1\n\n")
        with self.assertRaisesRegex(lean_adapter.FormalArithmeticError, "invalid_natural"):
            lean_adapter._parse_natural("01", "j")
        with self.assertRaisesRegex(lean_adapter.FormalArithmeticError, "invalid_natural"):
            lean_adapter._parse_natural("9" * 5000, "j")
        with self.assertRaisesRegex(lean_adapter.FormalArithmeticError, "invalid_fraction"):
            lean_adapter._parse_fraction("1/02", "bound")

        with mock.patch.object(lean_adapter, "_run_bounded", return_value=(0, b"", b"")) as bounded:
            lean_adapter._guarded_power_shell(
                "exit 0", "adapter-contract-test", timeout_seconds=1, output_limit=1024
            )
        self.assertTrue(bounded.call_args.kwargs["owned_process_tree"])
        self.assertIs(bounded.call_args.kwargs["owned_tree_cleanup_checker"], lean_adapter._guarded_cleanup_contract)
        cleanup_receipt = (
            b"CLEANUP=PASS label=Command owned_process_tree=empty\n"
            b"MUTEX=RELEASED name=Local\\BlindLedgerDirectMaskBuild20260907\n"
        )
        lean_adapter._guarded_cleanup_contract(cleanup_receipt, b"")
        with self.assertRaisesRegex(
            lean_adapter.FormalArithmeticError, "owned_process_tree_cleanup_unverified"
        ):
            lean_adapter._guarded_cleanup_contract(cleanup_receipt.replace(b"CLEANUP=PASS", b"CLEANUP=FAIL"), b"")

    def test_lean_adapter_bounded_output_and_finalization_faults(self) -> None:
        class FakeProcess:
            def __init__(
                self,
                *,
                stdout: bytes = b"",
                stderr: bytes = b"",
                poll_values: tuple[int | None, ...] = (0,),
                wait_values: tuple[object, ...] = (0,),
            ) -> None:
                self.pid = 4242
                self.stdout = io.BytesIO(stdout)
                self.stderr = io.BytesIO(stderr)
                self._poll_values = list(poll_values)
                self._wait_values = list(wait_values)
                self.wait_calls: list[float | None] = []
                self.kill_calls = 0

            def poll(self) -> int | None:
                if self._poll_values:
                    return self._poll_values.pop(0)
                return 0

            def wait(self, timeout: float | None = None) -> int:
                self.wait_calls.append(timeout)
                value = self._wait_values.pop(0) if self._wait_values else 0
                if isinstance(value, BaseException):
                    raise value
                return int(value)

            def kill(self) -> None:
                self.kill_calls += 1

        for stream, payload in (("stdout", b"abcd"), ("stderr", b"abcd")):
            with self.subTest(stream=stream):
                process = FakeProcess(**{stream: payload})
                with mock.patch.object(lean_adapter.subprocess, "Popen", return_value=process):
                    with self.assertRaisesRegex(
                        lean_adapter.FormalArithmeticError,
                        f"formal_output_too_large={stream};limit=3",
                    ):
                        lean_adapter._run_bounded(
                            ["fast-exit"], cwd=lean_adapter.FORMAL_ROOT, timeout_seconds=1, output_limit=3
                        )
                self.assertTrue(process.stdout.closed)
                self.assertTrue(process.stderr.closed)

        signal_process = FakeProcess()
        with mock.patch.object(
            lean_adapter, "_request_owned_process_stop", side_effect=OSError("signal-failure")
        ), mock.patch.object(
            lean_adapter,
            "_terminate_owned_process_tree",
            side_effect=OSError("cleanup-tool-failure"),
        ):
            stop_failure = lean_adapter._stop_process_for_limit(signal_process, True)
        self.assertIsNotNone(stop_failure)
        assert stop_failure is not None
        self.assertIn("owned_process_graceful_stop_failed", str(stop_failure))
        self.assertIn("owned_process_tree_cleanup_failed", str(stop_failure))
        self.assertIn("cleanup-tool-failure", str(stop_failure))

        exited_process = FakeProcess(poll_values=(0,))
        cleanup_failure = lean_adapter._terminate_owned_process_tree(exited_process)
        self.assertIsNotNone(cleanup_failure)
        assert cleanup_failure is not None
        self.assertIn("owned_process_tree_cleanup_unverified=root_exited", str(cleanup_failure))

        finalization_process = FakeProcess(
            poll_values=(None,),
            wait_values=(subprocess.TimeoutExpired(cmd="owned", timeout=1), 0),
        )
        with mock.patch.object(lean_adapter.subprocess, "Popen", return_value=finalization_process), mock.patch.object(
            lean_adapter.time, "monotonic", side_effect=(0.0, 2.0)
        ), mock.patch.object(lean_adapter.time, "sleep"), mock.patch.object(
            lean_adapter,
            "_stop_process_for_limit",
            return_value=lean_adapter.FormalArithmeticError("signal-failure"),
        ), mock.patch.object(
            lean_adapter,
            "_terminate_owned_process_tree",
            return_value=lean_adapter.FormalArithmeticError("escalation-failure"),
        ):
            with self.assertRaisesRegex(
                lean_adapter.FormalArithmeticError,
                "signal-failure.*escalation-failure",
            ):
                lean_adapter._run_bounded(
                    ["timeout"],
                    cwd=lean_adapter.FORMAL_ROOT,
                    timeout_seconds=1,
                    output_limit=1024,
                    owned_process_tree=True,
                    owned_tree_cleanup_checker=lambda _stdout, _stderr: None,
                )
        self.assertEqual(len(finalization_process.wait_calls), 2)
        self.assertTrue(finalization_process.stdout.closed)
        self.assertTrue(finalization_process.stderr.closed)

        wait_error_process = FakeProcess(
            poll_values=(None,),
            wait_values=(RuntimeError("wait-failure"), 0),
        )
        with mock.patch.object(lean_adapter.subprocess, "Popen", return_value=wait_error_process), mock.patch.object(
            lean_adapter.time, "monotonic", side_effect=(0.0, 2.0)
        ), mock.patch.object(lean_adapter.time, "sleep"), mock.patch.object(
            lean_adapter,
            "_stop_process_for_limit",
            return_value=lean_adapter.FormalArithmeticError("signal-failure"),
        ), mock.patch.object(
            lean_adapter,
            "_terminate_owned_process_tree",
            return_value=lean_adapter.FormalArithmeticError("wait-escalation-failure"),
        ):
            with self.assertRaisesRegex(
                lean_adapter.FormalArithmeticError,
                "formal_process_wait_failed=.*wait-failure.*wait-escalation-failure",
            ):
                lean_adapter._run_bounded(
                    ["wait-error"],
                    cwd=lean_adapter.FORMAL_ROOT,
                    timeout_seconds=1,
                    output_limit=1024,
                    owned_process_tree=True,
                    owned_tree_cleanup_checker=lambda _stdout, _stderr: None,
                )
        self.assertEqual(len(wait_error_process.wait_calls), 2)
        self.assertTrue(wait_error_process.stdout.closed)
        self.assertTrue(wait_error_process.stderr.closed)

    def test_concrete_feasibility_fails_closed_before_availability(self) -> None:
        result = concrete_feasibility(self.manifest)
        self.assertEqual(result["status"], "CONDITIONAL_PRIVACY_TARGET_COMPARISON_RECORDED")
        self.assertEqual(result["ledger_scope"]["statistical"]["target"], "2^-128")
        self.assertEqual(result["ledger_scope"]["computational"]["target"], "separate finite computational PQ work/query comparison; no universal epsilon_priv<=2^-128 requirement inferred")
        self.assertEqual(result["proof_trace"]["bit_hiding"]["numerator_identity"], "397*choose(4,2)+33*choose(2048,2)+33*choose(989,2)=85297284")
        self.assertEqual(result["proof_trace"]["source_hiding"]["switching_statement"], "1253=choose(8,2)+choose(50,2) for the source G0/G1 AES hybrids")
        switching = result["switching"]
        minimum = switching["minimum_nontrivial_deployment"]
        self.assertEqual(minimum["numerator"], 85298537)
        self.assertEqual(minimum["term"], {"numerator": "85298537", "denominator": str(1 << 128)})
        self.assertTrue(minimum["strictly_exceeds_target"])
        self.assertEqual(minimum["bound_exponent_floor_bits"], 101)
        declared = switching["declared_lifetime_caps"]
        self.assertEqual(declared["M"], 1 << 32)
        self.assertEqual(declared["S"], 1 << 32)
        self.assertEqual(declared["raw_numerator"], 85298537 * (1 << 32))
        self.assertEqual(declared["numerator"], 85298537)
        self.assertEqual(declared["term"], {"numerator": "85298537", "denominator": str(1 << 96)})
        self.assertTrue(declared["strictly_exceeds_target"])
        self.assertEqual(declared["bound_exponent_floor_bits"], 69)
        self.assertEqual(result["work_model"]["aes_block_counts"]["at_declared_A_V_S_caps"], 54889462999547904)
        work = result["constant_success_work_model"]
        self.assertEqual(work["alpha_weight_at_declared_caps"], 465 * (1 << 32))
        self.assertEqual(
            work["known_additive_terms_at_declared_caps"]["switching"],
            {"numerator": "85298537", "denominator": str(1 << 96)},
        )
        self.assertEqual(
            work["uniform_alpha_threshold_before_unknown_terms"],
            {
                "numerator": "87112285931760246646436326036005099405311",
                "denominator": "347954309815741366765933284973092661319684419831726080",
            },
        )
        search = work["generic_key_search_screen"]
        self.assertEqual(search["pair_requirements"]["chosen_for_screen"], 3)
        self.assertEqual(
            search["real_world_false_key_union_bound_lambda"],
            {
                "numerator": "340282366920938463463374607431768211457",
                "denominator": "115792089237316195423570985008687907852589419931798687112530834793049593217024",
            },
        )
        self.assertEqual(
            search["ideal_world_consistent_key_union_bound_lambda"],
            {
                "numerator": "170141183460469231731687303715884105728",
                "denominator": "57896044618658097711785492504343953926124568782438874324533730092808912502785",
            },
        )
        self.assertEqual(
            search["optimistic_zero_unknown_threshold"]["fraction"],
            {
                "numerator": "13204693752377389598895558877",
                "denominator": "52743766872745461836823064151924072775680",
            },
        )
        self.assertEqual(search["numerical_break_even_iterations_approx"], 85131060672178469145225451028192)
        self.assertEqual(search["rationally_certified_iterations"], 85131060672178469145225451128192)
        self.assertTrue(search["rational_sine_lower_bound_exceeds_optimistic_threshold"])
        self.assertEqual(search["work_convention"]["in_place_G_cost"], 1844106)
        self.assertEqual(search["work_convention"]["history_measurement_count"], 18768)
        self.assertEqual(search["work_convention"]["history_AES_operator_G_cost"], 611496)
        self.assertEqual(search["toffoli_decomposition"]["G_cost"], 16)
        self.assertEqual(search["grover_diffusion"]["G_cost"], 9185)
        self.assertEqual(search["primitive_game_algorithm"]["fixed_G_cost"], 1841913)
        self.assertEqual(search["primitive_game_algorithm"]["per_iteration_G_cost"], 1853291)
        self.assertEqual(search["known_history"]["known_history_G_cost_at_declared_caps"], 33564687066371545104384)
        self.assertEqual(search["at_work_cap_fully_counted_primitive"]["iteration_count"], 183609787626950362065846436113792)
        self.assertEqual(search["at_work_cap_fully_counted_primitive"]["total_G_cost"], 340282366920938463463374607431767531385)
        self.assertEqual(search["at_work_cap_fully_counted_primitive"]["remaining_G_slack_below_2^128"], 680071)
        self.assertTrue(search["at_work_cap_fully_counted_primitive"]["strictly_below_2^128"])
        self.assertTrue(search["at_work_cap_fully_counted_primitive"]["weighted_exceeds_known_residual"])
        self.assertTrue(search["product_history_auxiliary_screen"]["strictly_below_2^128"])
        self.assertEqual(search["hybrid_loss_analysis"]["maximum_effective_weight_at_fully_counted_primitive_cap"], 429335941335)
        self.assertEqual(search["hybrid_loss_analysis"]["break_even_certified_maximum_effective_weight"], 1997159792639)
        self.assertEqual(result["decision"]["known_attack_status"], "NO_APPLICABLE_ATTACK_ESTABLISHED_FROM_SWITCHING_TERMS_OR_RETAINED_TRANSCRIPT")
        self.assertEqual(result["decision"]["computational_work_status"], "FULLY_COUNTED_SINGLE_KEY_PRIMITIVE_SCREEN_OBSTRUCTS_CURRENT_CERTIFICATE_AT_STRICT_2^128_WORK_CAP; PRODUCT_Q1_MULTI_INSTANCE_GAP_REMAINS")
        self.assertEqual(result["decision"]["primitive_game_screen_status"], "FULLY_COUNTED_SINGLE_KEY_PRIMITIVE_ALGORITHM_REACHES_THE_ALPHA_THRESHOLD_BELOW_STRICT_2^128_G; THIS_IS_NOT_A_REAL_TRANSCRIPT_ATTACK")
        self.assertIn("429335941335", result["decision"]["smallest_justified_remedy"])
        self.assertIn("4.651741446173654", result["decision"]["smallest_justified_remedy"])
        self.assertFalse(result["decision"]["production_or_activation_allowed"])
        proposal_v3 = result["constant_success_work_model"]["bounded_generator_feasibility_proposal_v3"]
        self.assertEqual(proposal_v3["status"], "UNSELECTED_IDEAL_ORACLE_WIDE_SEED_V3_PROPOSAL")
        self.assertFalse(proposal_v3["selection"]["selected"])
        self.assertEqual(proposal_v3["privacy_reduction"]["status"], "CONDITIONAL_SINGLE_HOP_SXY_OPAQUE_HANDLE_PENDING_REVIEW")
        self.assertIsNone(proposal_v3["privacy_reduction"]["numeric_bound"])
        self.assertTrue(proposal_v3["privacy_reduction"]["privacy_claim_stopped"])

    def test_composed_privacy_keeps_literal_exposure_and_one_budget(self) -> None:
        result = concrete_feasibility(self.manifest)
        composed = result["constant_success_work_model"]["composed_privacy_analysis"]
        self.assertEqual(composed["status"], "NO_MODEL_MATCHED_STRUCTURED_GENERATOR_BOUND; RETAIN_HYBRID_CERTIFICATE")
        exposure = composed["exposure_map"]
        tree = exposure["tree_generator"]
        self.assertEqual(tree["leaf_count"], 6400)
        self.assertEqual(tree["hidden_leaf_count"], 33)
        self.assertEqual(tree["hidden_path_union_nodes"], 397)
        self.assertEqual(tree["leaf_expansion_AES_blocks"], 8)
        self.assertEqual(tree["hidden_stream_AES_blocks"], 989)
        opening = exposure["opening_and_transcript"]
        self.assertEqual(opening["frontier_seed_slots"], 229)
        self.assertEqual(opening["selected_commitment_count"], 33)
        self.assertEqual(opening["opening_bytes"], 10496)
        dependence = exposure["dependence_boundary"]
        self.assertFalse(dependence["root_descendants_are_independent"])
        self.assertFalse(dependence["stream_key_is_independent_before_hybrid"])
        self.assertFalse(dependence["source_G1_key_is_independent_before_G0_hybrid"])
        approaches = composed["approach_comparison"]
        self.assertEqual(approaches[0]["status"], "REJECTED_FOR_LITERAL_TRANSCRIPT")
        self.assertEqual(approaches[1]["status"], "SELECTED_CONDITIONAL_INTERFACE_NO_NUMERIC_THEOREM")
        selected = composed["selected_conditional_bound"]
        self.assertIn("beta_joint", selected["formula"])
        self.assertEqual(
            selected["safe_budget_before_unknown_terms"],
            {
                "numerator": "87112285931760246646436326036005099405311",
                "denominator": "174224571863520493293247799005065324265472",
            },
        )
        self.assertEqual(selected["current_proven_effective_weight_at_caps"], 465 * (1 << 32))
        self.assertEqual(selected["required_effective_weight_at_fully_counted_single_key_cap"], 429335941335)
        shared = composed["shared_work_ledger"]
        self.assertTrue(shared["one_total_budget"])
        self.assertTrue(shared["qrams_are_not_free"])
        self.assertTrue(shared["parallelism_does_not_reduce_total_G"])
        self.assertEqual(shared["known_history_G_cost_at_declared_caps"], 33564687066371545104384)
        self.assertIn("sum_i T_i<=T*", composed["obstruction"])
        proposal = result["constant_success_work_model"]["bounded_generator_feasibility_proposal"]
        self.assertEqual(proposal["status"], "UNSELECTED_IDEAL_ORACLE_WIDE_SEED_PROPOSAL")
        self.assertEqual(proposal["least_evaluated_width_bits"], 384)
        self.assertIsNone(proposal["least_sufficient_width_bits"])
        self.assertEqual(proposal["minimum_width_status"], "UNKNOWN_HIDDEN_LEAF_ROW_COMPLETION")
        self.assertEqual(proposal["opening_geometry"]["accepted_nh_max"], 294)
        self.assertEqual(proposal["opening_geometry"]["accepted_marked_internal_max"], 261)
        self.assertEqual(proposal["opening_geometry"]["accepted_hidden_seed_max"], 327)
        self.assertEqual(proposal["opening_geometry"]["full_retry_abort_hidden_seed_max"], 19199)
        self.assertEqual(
            proposal["coupling_lemma"]["status"],
            "CONDITIONAL_SINGLE_ANSWER_KEYED_PRIVACY_ROW_BINDING_UNPROVED",
        )
        self.assertEqual(proposal["cap_evaluation"]["P_cap"], 18031994990493696)
        self.assertEqual(proposal["cap_evaluation"]["q_hist_at_caps"], 340282366920938463463392921241037832192)
        self.assertEqual(proposal["cap_evaluation"]["Q_star_base_at_caps"], 680564733841876926926803874477066158080)
        width384 = proposal["width_evaluations"]["384"]
        self.assertEqual(width384["generator_H_queries_per_commitment"], 2131198)
        self.assertEqual(width384["generator_H_queries_at_caps"], 9153425711300608)
        self.assertEqual(width384["verifier_generator_H_queries_per_verification"], 2120275)
        self.assertEqual(width384["verifier_generator_H_queries_at_caps"], 9106511783526400)
        self.assertEqual(width384["candidate_qP"], 41)
        self.assertEqual(width384["soundness_status"], "CONDITIONAL_ROW_COMPLETE_ONLY_HIDDEN_LEAF_ROW_COMPLETION_UNPROVED")
        self.assertEqual(width384["soundness_row_complete_bound"], {"numerator": "1", "denominator": "1"})
        self.assertEqual(width384["secret_seed_count_at_caps"], 82459077115904)
        self.assertEqual(width384["candidate_total_public_RO_queries_at_caps"], 680564733841876926926822134414560985088)
        self.assertEqual(width384["candidate_q_hist_at_caps"], 340282366920938463463411181178532659200)
        self.assertEqual(width384["candidate_q_alg_at_caps"], 340282366920938463463411181148467888128)
        self.assertEqual(width384["candidate_q_eff_at_caps"], 340282366920938463463411181148467888169)
        self.assertEqual(width384["superseded_conditional_candidate_total_public_RO_queries_at_caps"], 680564733841876926926813110366149541888)
        self.assertEqual(width384["superseded_conditional_epsilon_seed_bound_decimal"], "4.3426941769355606e-22")
        self.assertIsNone(width384["constant_success_under_zero_remaining_unknowns"])
        self.assertEqual(width384["proof_status"], "CONDITIONAL_SINGLE_ANSWER_KEYED_PRIVACY_ROW_BINDING_UNPROVED")
        width512 = proposal["width_evaluations"]["512"]
        self.assertEqual(width512["generator_H_queries_per_commitment"], 1606398)
        self.assertEqual(width512["generator_H_queries_at_caps"], 6899426874359808)
        self.assertEqual(width512["verifier_generator_H_queries_per_verification"], 1598181)
        self.assertEqual(width512["verifier_generator_H_queries_at_caps"], 6864135128088576)
        self.assertEqual(width512["candidate_qP"], 41)
        self.assertEqual(width512["soundness_status"], "CONDITIONAL_ROW_COMPLETE_ONLY_HIDDEN_LEAF_ROW_COMPLETION_UNPROVED")
        self.assertEqual(width512["soundness_row_complete_bound"], {"numerator": "1", "denominator": "1"})
        self.assertEqual(width512["candidate_total_public_RO_queries_at_caps"], 680564733841876926926817638039068606464)
        self.assertEqual(width512["candidate_q_hist_at_caps"], 340282366920938463463406684803040280576)
        self.assertEqual(width512["candidate_q_alg_at_caps"], 340282366920938463463406684772975509504)
        self.assertEqual(width512["candidate_q_eff_at_caps"], 340282366920938463463406684772975509545)
        self.assertEqual(width512["superseded_conditional_candidate_total_public_RO_queries_at_caps"], 680564733841876926926810828879521906688)
        self.assertEqual(width512["superseded_conditional_epsilon_seed_bound_decimal"], "9.6095026892492341e-61")
        self.assertIsNone(width512["constant_success_under_zero_remaining_unknowns"])
        self.assertEqual(width384["frame_bytes_including_40_byte_header"], 538034)
        self.assertEqual(width512["frame_bytes_including_40_byte_header"], 541698)
        self.assertEqual(width384["keyed_o2h_privacy_bound_decimal"], "1.7880462110042572e-05")
        self.assertEqual(width512["keyed_o2h_privacy_bound_decimal"], "9.6930179323764516e-25")
        self.assertTrue(width384["privacy_only_threshold_positive"])
        self.assertTrue(width512["privacy_only_threshold_positive"])
        self.assertEqual(width384["proof_status"], "CONDITIONAL_SINGLE_ANSWER_KEYED_PRIVACY_ROW_BINDING_UNPROVED")
        self.assertEqual(width512["proof_status"], "CONDITIONAL_SINGLE_ANSWER_KEYED_PRIVACY_ROW_BINDING_UNPROVED")

        v3 = result["constant_success_work_model"]["bounded_generator_feasibility_proposal_v3"]
        self.assertEqual(v3["candidate_id"], "DMV-RO-WIDE-SEED-v3")
        self.assertIsNone(v3["least_sufficient_width_bits"])
        self.assertEqual(v3["minimum_width_status"], "UNKNOWN_PRIVACY_AND_CONCRETE_PRIMITIVE_SECURITY")
        self.assertFalse(v3["opening_geometry"]["selected_seed_disclosure"])
        stronger = v3["stronger_soundness_game"]
        self.assertTrue(stronger["given_to_soundness_adversary"])
        self.assertFalse(stronger["given_to_privacy_adversary"])
        self.assertTrue(stronger["actual_generator_evaluations_still_charged"])
        self.assertEqual(stronger["qP"], 38)
        self.assertEqual(stronger["leaf_index_context_count"], 6400)

        q_hist_base = (1 << 128) + 4264016 * (1 << 32)
        q_alg_base = (1 << 128) + 4264009 * (1 << 32)
        hidden_seed_count = 19199 * (1 << 32)
        e_kos = Fraction(math.comb(1 << 248, 3), 1 << 1024) * (1 + Fraction(125049**5, 1 << 64))
        e2 = (1 + Fraction(172231**2, 1 << 64)) / (1 << 262)
        e3 = Fraction(3, 1 << 263)
        for width, expected in (
            (384, (1056, 1439, 1449, 180, 132, 15348, 539306, 330, 2131198, 2120275)),
            (512, (1312, 1823, 1833, 228, 164, 20068, 544074, 248, 1606398, 1598181)),
        ):
            with self.subTest(width=width):
                (
                    r,
                    nu_bits,
                    active_h0_bits,
                    nu_bytes,
                    commitment_bytes,
                    m4_bytes,
                    frame_bytes,
                    stream_blocks,
                    generator_per_commitment,
                    verifier_per_verification,
                ) = expected
                row = v3["width_evaluations"][str(width)]
                self.assertEqual(row["r"], r)
                self.assertEqual(row["nu_bits"], nu_bits)
                self.assertEqual(row["active_h0_bits"], active_h0_bits)
                self.assertEqual(row["nu_serialized_bytes"], nu_bytes)
                self.assertEqual(row["commitment_bytes"], commitment_bytes)
                self.assertEqual(row["m4_bytes"], m4_bytes)
                self.assertEqual(row["frame_bytes_including_40_byte_header"], frame_bytes)
                self.assertEqual(row["h1_vector_128_input_bytes"], 28 + 128 * commitment_bytes)
                self.assertEqual(row["h1_vector_256_input_bytes"], 28 + 256 * commitment_bytes)
                self.assertEqual(row["fs_uhash_bytes"], nu_bytes)
                self.assertEqual(row["stream_blocks_per_row"], stream_blocks)
                self.assertEqual(row["generator_H_queries_per_commitment"], generator_per_commitment)
                self.assertEqual(row["verifier_generator_H_queries_per_verification"], verifier_per_verification)
                self.assertEqual(row["secret_seed_count_at_caps"], hidden_seed_count)
                generator_at_caps = generator_per_commitment * (1 << 32)
                verifier_at_caps = verifier_per_verification * (1 << 32)
                q_alg = q_alg_base + generator_at_caps + verifier_at_caps
                q_eff = q_alg + 38
                q_hist = q_hist_base + generator_at_caps + verifier_at_caps
                q_total = 2 * q_hist + 4198401 * (1 << 32)
                self.assertEqual(row["candidate_q_alg_at_caps"], q_alg)
                self.assertEqual(row["candidate_q_eff_at_caps"], q_eff)
                self.assertEqual(row["candidate_q_hist_at_caps"], q_hist)
                self.assertEqual(row["candidate_q_H_at_caps"], q_total)
                self.assertEqual(row["candidate_total_public_RO_queries_at_caps"], q_total)
                h0_completion = Fraction(1, 1 << nu_bits)
                self.assertEqual(self._fraction(row["h0_completion_term"]), h0_completion)
                e_leaf = Fraction(6400 * math.comb(1 << width, 2), 1 << (r + 10))
                self.assertEqual(self._fraction(row["e_leaf_v3"]), e_leaf)
                self.assertEqual(row["direct_constant_max_name"], "e3")
                self.assertTrue(row["direct_constant_comparisons"]["e3_ge_e_leaf_v3"])
                self.assertTrue(row["direct_constant_comparisons"]["e3_ge_eKOS"])
                self.assertTrue(row["direct_constant_comparisons"]["e3_ge_e2"])
                self.assertEqual(self._fraction(row["direct_constant_max"]), e3)
                expected_rows_at_cap = {
                    "H0": e_leaf + h0_completion * q_eff,
                    "H1_vector": Fraction(34 * q_eff, 1 << 512),
                    "H1_outer": Fraction(2 * q_eff, 1 << 512),
                    "FS1": Fraction(2 * q_eff, 1 << 2112) + e_kos,
                    "FS2": Fraction(2 * q_eff, 1 << 832) + e2,
                    "FS3": e3,
                }
                self.assertEqual(
                    {key: self._fraction(value) for key, value in row["row_bounds_at_cap"].items()},
                    expected_rows_at_cap,
                )
                self.assertEqual(row["delta_cap_name"], "FS3")
                self.assertTrue(row["delta_cap_is_constant_for_all_k"])
                self.assertEqual(self._fraction(row["delta_cap"]), e3)
                expected_soundness = min(
                    Fraction(1, 1),
                    10 * q_eff * (e3 * q_eff),
                )
                self.assertEqual(self._fraction(row["soundness_row_complete_bound"]), expected_soundness)
                self.assertEqual(row["soundness_status"], "CONDITIONAL_STRONGER_QUERY_ONLY_GAME_WITH_COMPLETE_FIXED_GENERATOR_TABLE")
                self.assertEqual(row["privacy_status"], "CONDITIONAL_SINGLE_HOP_SXY_OPAQUE_HANDLE_PENDING_REVIEW")
                self.assertIsNone(row["privacy_numeric_bound"])
                hybrid_count = 463 * (1 << 32)
                seed_collision = Fraction(0, 1)
                expected_generator = min(
                    Fraction(1, 1),
                    Fraction(2 * hybrid_count * q_total, 1 << (width // 2)),
                )
                self.assertEqual(self._fraction(row["seed_collision_term"]), seed_collision)
                self.assertEqual(self._fraction(row["generator_privacy_bound"]), expected_generator)
                self.assertEqual(row["hybrid_count_at_caps"], hybrid_count)
                self.assertEqual(row["proof_status"], "CONDITIONAL_SOUNDNESS_ONE_HOP_PRIVACY_PENDING_REVIEW")

    def test_v3_source_collision_game_is_admissible_bounded_and_not_double_charged(self) -> None:
        result = concrete_feasibility(self.manifest)
        v3 = result["constant_success_work_model"]["bounded_generator_feasibility_proposal_v3"]
        game = v3["source_collision_game"]
        computed = game["computed"]
        self.assertEqual(game["status"], "ADMISSIBLE_BOUNDED_SOURCE_COLLISION_GAME")
        self.assertEqual(computed["interval_size"], 14757394086155238333)
        self.assertTrue(computed["interval_acceptance_probability_ge_3/4"])
        self.assertEqual(computed["max_candidate_draws"], 12800)
        self.assertEqual(computed["d_128_bit_comparisons"], math.comb(50, 2))
        self.assertEqual(computed["world_0_collision_probability"], {"numerator": "0", "denominator": "1"})
        self.assertEqual(self._fraction(computed["word_xor_probability_lower_bound"]), Fraction(1, 1 << 65))
        self.assertEqual(self._fraction(computed["block_pair_probability_lower_bound"]), Fraction(1, 1 << 130))
        uniform_lower = 1 - (1 - Fraction(1, 1 << 130)) ** 25
        bounded_lower = (1 - Fraction(100, 1 << 256)) * uniform_lower
        self.assertEqual(self._fraction(computed["uniform_interval_collision_lower_bound"]), uniform_lower)
        self.assertEqual(self._fraction(computed["bounded_collision_lower_bound"]), bounded_lower)
        self.assertTrue(computed["uniform_lower_bound_strictly_greater_than_2^-127"])
        self.assertTrue(computed["bounded_lower_bound_strictly_greater_than_2^-128"])
        self.assertEqual(self._fraction(computed["delta_lr_lower_bound"]), bounded_lower)
        sampler = game["world_1"]["sampler"]
        self.assertEqual(sampler["candidates_per_word"], 128)
        self.assertEqual(sampler["word_count"], 100)
        self.assertTrue(computed["conditional_interval_words_independent_uniform"])
        self.assertTrue(computed["fallback_cannot_contribute_collision"])
        self.assertTrue(game["composition"]["collision_is_not_additional_privacy_loss"])
        self.assertEqual(game["composition"]["existing_source_switching_residual"], "S*(alpha8+alpha50+1253/2^128)")

    def test_v3_endpoint_residual_resources_and_shake_boundary_are_explicit(self) -> None:
        result = concrete_feasibility(self.manifest)
        v3 = result["constant_success_work_model"]["bounded_generator_feasibility_proposal_v3"]
        endpoint = v3["endpoint_normalization"]
        self.assertEqual(endpoint["delta_lr_definition"], "Delta_LR=abs(Pr[D(View0)=1]-Pr[D(View1)=1])")
        self.assertEqual(endpoint["conversion"], "Delta_LR<=min(1,E0+E1)<=min(1,2*E_one_sided)")
        self.assertEqual(endpoint["guessing_success"], "Pguess=(1+Delta_LR)/2")
        self.assertTrue(endpoint["common_ideal_premise"])
        self.assertEqual(v3["composition"]["full_privacy_endpoint_formula"], "E_one_sided <= epsilon_coins+epsilon_AR+epsilon_generator_v3(w)+epsilon_source+Adv_SHAKE_priv+epsilon_operational; source-U binding is a separate integrity/applicability premise")
        source_u = v3["composition"]["source_U_role_separation"]
        self.assertTrue(source_u["not_a_privacy_residual_term"])
        self.assertTrue(source_u["not_silently_dropped"])
        self.assertTrue(source_u["custody_and_independence_remain_open"])

        program_points = 4198401 * (1 << 32)
        fs_sizes = {
            "384": {"FS1": 507846, "FS2": 524073, "FS3": 524349},
            "512": {"FS1": 507894, "FS2": 524121, "FS3": 524397},
        }
        for width, expected_sizes in fs_sizes.items():
            with self.subTest(width=width):
                row = v3["width_evaluations"][width]
                self.assertEqual(row["ideal_qrom_vs_shake"]["status"], "CONDITIONAL_IDEAL_QROM_ONLY")
                self.assertEqual(row["ideal_qrom_vs_shake"]["concrete_shake_status"], "UNPROVED")
                self.assertFalse(row["ideal_qrom_vs_shake"]["generic_shake_to_qrom_bridge"])
                self.assertTrue(row["ideal_qrom_vs_shake"]["no_numerical_bridge"])
                linear = row["linear_scan_envelope"]
                self.assertEqual(linear["fs_input_bytes"], expected_sizes)
                self.assertEqual(linear["program_points_at_declared_caps"], program_points)
                self.assertTrue(linear["not_a_universal_lower_bound"])
                self.assertTrue(linear["not_measured"])
                fs3_bits = expected_sizes["FS3"] * 8
                per_forward = program_points * fs3_bits
                self.assertEqual(linear["flat_linear_scan_bit_comparison_units_per_forward_call_at_declared_caps"], per_forward)
                self.assertEqual(linear["flat_table_entry_bits"], fs3_bits + 2112)
                self.assertEqual(linear["flat_table_memory_bits_at_declared_caps"], program_points * (fs3_bits + 2112))
                self.assertEqual(linear["flat_linear_scan_bit_comparison_units_forward_history_at_declared_caps"], row["candidate_q_hist_at_caps"] * per_forward)
                self.assertEqual(linear["flat_linear_scan_bit_comparison_units_forward_and_reverse_at_declared_caps"], row["candidate_q_H_at_caps"] * per_forward)
                residual = row["source_residual"]
                source_alpha_sum_ceiling = self._fraction(
                    residual["source_alpha_sum_ceiling_at_zero_unallocated_losses"]
                )
                epsilon_ar = self._fraction(residual["epsilon_AR_safe_upper_bound"])
                epsilon_generator = self._fraction(row["generator_privacy_bound"])
                source_switching_at_cap = self._fraction(residual["source_switching_at_caps"])
                self.assertEqual(
                    (1 << 32) * source_alpha_sum_ceiling
                    + epsilon_ar
                    + epsilon_generator
                    + source_switching_at_cap,
                    Fraction(1, 4),
                )
                self.assertTrue(residual["source_alpha_sum_strict_condition_required"])
                self.assertEqual(residual["unallocated_loss_terms"], ["epsilon_coins", "Adv_SHAKE_priv", "epsilon_operational"])
                self.assertTrue(residual["zero_unknowns_is_diagnostic_only"])

    def test_privacy_cap_uses_exact_history_and_square_comparison(self) -> None:
        report = calculate_report_v2(self.manifest)
        cap = report["privacy"]["cap_evaluation"]["adaptive_reprogramming"]
        self.assertEqual(cap["P_upper_bound"], 4198401 * (1 << 32))
        self.assertEqual(cap["q_hist_overhead"], 4264016 * (1 << 32))
        self.assertTrue(cap["q_hist_lt_2^128_times_1_plus_2^-73"])
        self.assertTrue(cap["strictly_below_2^-137"])
        self.assertEqual(report["privacy"]["cap_evaluation"]["combined_switching"]["term"], {"numerator": "85298537", "denominator": str(1 << 96)})
        self.assertEqual(cap["sqrt_term"]["radicand"], cap["q_hist"])
        self.assertEqual(
            self._fraction(cap["linear_term"]),
            Fraction(cap["P_upper_bound"] * cap["q_hist"], 2 * (1 << 512)),
        )
        self.assertEqual(
            self._fraction(cap["remaining"]),
            Fraction(1, 1 << 137) - Fraction(cap["P_upper_bound"] * cap["q_hist"], 2 * (1 << 512)),
        )
        self.assertEqual(cap["target"], {"numerator": "1", "denominator": str(1 << 137)})
        privacy = report["privacy"]["cap_evaluation"]
        self.assertEqual(privacy["bit_hiding"]["switching_term_under_M_cap"], {"numerator": "85297284", "denominator": str(1 << 96)})
        self.assertEqual(privacy["source_binding"]["source_component_under_E_U_cap"], {"numerator": "1", "denominator": str(1 << 225)})

    def test_consistent_counters_do_not_attest_global_scope(self) -> None:
        result = admission_ledger(self.manifest, self._counters())
        self.assertFalse(result["runtime_admission"]["admitted"])
        self.assertTrue(result["runtime_admission"]["counter_input_validated"])
        self.assertTrue(result["runtime_admission"]["conditional_arithmetic_available"])
        self.assertEqual(result["runtime_admission"]["counter_scope_status"], "UNATTESTED_GLOBAL_LIFETIME")
        self.assertFalse(result["runtime_admission"]["global_lifetime_scope_verified"])
        self.assertFalse(result["runtime_admission"]["offline_Q_budget_enforced"])
        self.assertEqual(
            result["concrete_feasibility"]["opportunity_scope"]["counter_scope_status"],
            "UNATTESTED_GLOBAL_LIFETIME",
        )
        self.assertTrue(result["concrete_feasibility"]["opportunity_scope"]["global_lifetime_accounting_declared"])
        self.assertFalse(result["concrete_feasibility"]["opportunity_scope"]["global_lifetime_accounting_verified"])
        self.assertFalse(result["concrete_feasibility"]["opportunity_scope"]["rotation_refund_behavior_verified"])
        self.assertFalse(result["concrete_feasibility"]["opportunity_scope"]["clone_resistance_verified"])
        self.assertFalse(result["concrete_feasibility"]["opportunity_scope"]["multiple_instance_accounting_verified"])
        self.assertFalse(result["qrom_soundness"]["runtime_evaluation"]["global_lifetime_scope_verified"])
        self.assertEqual(result["qrom_soundness"]["runtime_evaluation"]["q"], 121)
        self.assertTrue(result["privacy"]["runtime_evaluation"]["combined_switching"]["available"])

        counters = self._counters()
        counters["source_cap_enforced"] = False
        counters["global_lifetime_accounting"] = True
        result = admission_ledger(self.manifest, counters)
        self.assertFalse(result["runtime_admission"]["admitted"])
        self.assertEqual(result["runtime_admission"]["counter_provenance"], "CALLER_SUPPLIED_UNVERIFIED")
        self.assertFalse(result["privacy"]["runtime_evaluation"]["combined_switching"]["available"])
        self.assertEqual(result["privacy"]["runtime_evaluation"]["combined_switching"]["term"], "UNKNOWN")

    def test_missing_negative_bool_float_unknown_and_overflow_fail_closed(self) -> None:
        cases: list[tuple[str, callable, str]] = []

        def missing(counters: dict[str, object]) -> None:
            del counters["R3"]

        def negative(counters: dict[str, object]) -> None:
            counters["R3"] = -1

        def boolean(counters: dict[str, object]) -> None:
            counters["Q"] = True

        def floating(counters: dict[str, object]) -> None:
            counters["A"] = 1.0

        def unknown(counters: dict[str, object]) -> None:
            counters["M"] = "UNKNOWN"

        def overflow(counters: dict[str, object]) -> None:
            counters["Q"] = (1 << 128) + 1

        cases.extend([
            ("missing", missing, "missing"),
            ("negative", negative, "underflow"),
            ("boolean", boolean, "integer_required"),
            ("floating", floating, "integer_required"),
            ("unknown", unknown, "unknown"),
            ("overflow", overflow, "overflow"),
        ])
        for label, mutate, error in cases:
            with self.subTest(label=label):
                counters = self._counters()
                mutate(counters)
                result = admission_ledger(self.manifest, counters)
                self.assertFalse(result["runtime_admission"] if "runtime_admission" in result else result["admitted"])
                self.assertIn(error, result["errors"][0])

    def test_counter_identities_caps_and_preconditions_fail_closed(self) -> None:
        counters = self._counters()
        counters["R2"] = 4
        counters["fs2_rejected"] = 3
        result = admission_ledger(self.manifest, counters)
        self.assertFalse(result["admitted"])
        self.assertIn("accepted_rejected_aborted_mismatch", result["errors"][0])

        counters = self._counters()
        counters["R2"] = (1 << 12) + 1
        counters["fs2_first"] = 1
        counters["fs2_rejected"] = (1 << 12)
        counters["fs2_aborted"] = 0
        result = admission_ledger(self.manifest, counters)
        self.assertFalse(result["admitted"])
        self.assertIn("cap_exceeded", result["errors"][0])

        counters = self._counters()
        counters["one_commitment_per_attempt"] = False
        result = admission_ledger(self.manifest, counters)
        self.assertFalse(result["admitted"])
        self.assertIn("required_precondition_false", result["errors"][0])

    def test_reservation_outcomes_and_oracle_evaluations_are_distinct(self) -> None:
        counters = self._counters()
        counters["R2"] = 4
        counters["fs2_accepted"] = 2
        result = admission_ledger(self.manifest, counters)
        self.assertFalse(result["admitted"])
        self.assertIn("fs2_accepted: exceeds_first", result["errors"][0])

        counters = self._counters()
        counters["fs3_oracle_evaluations"] = 5
        result = admission_ledger(self.manifest, counters)
        self.assertFalse(result["admitted"])
        self.assertIn("fs3_oracle_evaluations: exceeds_R3", result["errors"][0])

        counters = self._counters()
        counters["R2"] = 1
        counters["fs2_first"] = 0
        counters["fs2_accepted"] = 0
        counters["fs2_rejected"] = 1
        counters["fs2_aborted"] = 0
        counters["fs2_oracle_evaluations"] = 0
        result = admission_ledger(self.manifest, counters)
        self.assertFalse(result["admitted"])
        self.assertIn("R2: nonzero_without_fs2_first", result["errors"][0])

        self.assertEqual(
            self.manifest["candidate_accounting"]["reservation_examples"][1]["reservations"], 2
        )
        self.assertEqual(
            self.manifest["candidate_accounting"]["reservation_examples"][1]["accepted"], 1
        )

    def test_availability_preserves_small_exact_model_and_large_guard(self) -> None:
        lower = availability_report(self.manifest)["second_moment_path_union"]["g_lower_bound"]
        small = availability_report(self.manifest, g=lower, retry_count=3)
        p = Fraction(lower, 1 << 263)
        self.assertEqual(self._fraction(small["p_good"]), p)
        self.assertEqual(self._fraction(small["independent_fresh_challenge_abort"]), (1 - p) ** 3)
        self.assertEqual(small["exact_evaluation_status"], "EXACT_SMALL_R_ONLY")

        large = availability_report(self.manifest, g=lower, retry_count=2**54)
        self.assertEqual(large["independent_fresh_challenge_abort"], "UNKNOWN")
        self.assertEqual(large["collision_split_upper_bound"], "UNKNOWN")
        self.assertEqual(large["exact_evaluation_status"], "NOT_EVALUATED_RESOURCE_GUARD")
        self.assertTrue(large["adaptive_trials_not_geometric"])
        with self.assertRaisesRegex(ContractError, "below_conditional_lower_bound"):
            availability_report(self.manifest, g=lower - 1)

    def test_first_moment_path_union_is_exact_and_nonvacuous(self) -> None:
        result = availability_report(self.manifest)
        moment = result["first_moment_path_union"]
        self.assertEqual(moment["nodes_evaluated"], 12799)
        self.assertEqual(moment["groups_evaluated"], 33)
        self.assertEqual(moment["selectable_leaves"], 6400)
        self.assertTrue(moment["leaf_map_injective"])
        self.assertEqual(moment["decoded_choice_bits"], 248)
        self.assertEqual(moment["common_denominator_power"], "2^248")
        self.assertEqual(moment["group_choice_counts"][:17], [256] * 17)
        self.assertEqual(moment["group_choice_counts"][17:], [128] * 16)
        self.assertEqual(
            moment["expected_n_h"],
            {
                "numerator": "4056079686396258357959731046931203993723285108487866225520421144400144512907",
                "denominator": "14134776518227074636666380005943348126619871175004951664972849610340958208",
            },
        )
        self.assertEqual(moment["deterministic_lower_bound_n_h"], 33)
        self.assertEqual(moment["rejection_event"], "n_h >= 295")
        self.assertEqual(moment["g_lower_bound"], 13884505219020294333661197535521673725749848932958108781260395804633668208)
        self.assertEqual(result["g_status"], "UNKNOWN")
        self.assertTrue(result["conditional_lower_bound"]["g_is_still_unknown"])

    def test_grouped_second_moment_certificate_and_resource_guard(self) -> None:
        result = availability_report(self.manifest)
        moment = result["second_moment_path_union"]
        self.assertEqual(moment["status"], "COMPUTED_EXACT_GROUPED_SECOND_MOMENT")
        self.assertEqual(moment["signature_count"], 390)
        self.assertEqual(moment["signature_pairs_unordered"], 76245)
        self.assertEqual(moment["ancestor_pairs_one_orientation"], 150018)
        self.assertEqual(moment["proper_ancestor_descendant_ordered_pairs"], 300036)
        self.assertEqual(moment["disjoint_ordered_pairs"], 163501566)
        self.assertTrue(moment["pair_partition_reconciles"])
        self.assertEqual(moment["common_denominator"], str(1 << 248))
        self.assertTrue(moment["expectation_reconciles_with_first_moment"])
        self.assertEqual(
            moment["S"],
            "5659357599052546237335464532772406677724302273932816324302946592587320946921120",
        )
        self.assertEqual(
            moment["B_baseline"],
            "70809329022621126312654488267015680139361614768222667425222972991402743186647023776",
        )
        self.assertEqual(
            moment["self_correction"],
            "101118433472237148122782004415351158504788008179058446659583726311743426203296",
        )
        self.assertEqual(
            moment["ancestor_correction_both_orientations"],
            "715355992110525482649420903912955836336654366068198457131913015975259146225076",
        )
        self.assertEqual(
            moment["J_corrected"],
            "70810145497046709075285260469924008446356456210596914682126764488145030189219452148",
        )
        self.assertEqual(
            moment["second_moment"],
            {
                "numerator": "9317007942778131695375260099873683866092460460989235406824724222396944359582861",
                "denominator": "113078212145816597093331040047546785012958969400039613319782796882727665664",
            },
        )
        self.assertEqual(
            moment["variance"],
            {
                "numerator": "9945713818065422227350871485593668610084987260455612774864952288878339054239953439183566434980762610486060791720694959509455620772670081080949668487",
                "denominator": "199791907220223502808422222706762643567910281130558153654986045416023791284464999687699590596063486154228923591770023865308670443474450259602571264",
            },
        )
        self.assertEqual(moment["selected_tail"], moment["cantelli_tail"])
        self.assertLess(self._fraction(moment["cantelli_tail"]), self._fraction(moment["first_moment_tail"]))
        self.assertEqual(
            moment["g_lower_bound"],
            255599836584766103482634859835523518456497083189896055288886800712843385174,
        )
        self.assertTrue(moment["variance_nonnegative"])
        self.assertTrue(moment["resource_limits_hold"])
        self.assertEqual(moment["group_factor_multiplication_upper_bound"], 13262007)
        self.assertEqual(moment["working_array_upper_bound_bytes"], 8651416)
        self.assertEqual(moment["runtime_limit_seconds"], 60)
        self.assertTrue(result["runtime_guard"]["single_calculation_deadline"])
        self.assertTrue(result["runtime_guard"]["periodic_checks_include_path_vectors"])
        self.assertTrue(result["runtime_guard"]["periodic_checks_include_grouped_pair_phase"])
        self.assertTrue(result["runtime_guard"]["deadline_checked_before_grouped_pair_phase"])
        self.assertEqual(
            result["runtime_guard"]["checks_performed"],
            moment["resource_guard_semantics"]["checks_performed"],
        )
        self.assertGreater(result["runtime_guard"]["checks_performed"], 0)
        first_expectation = self._fraction(result["first_moment_path_union"]["expected_n_h"])
        second_expectation = Fraction(12799, 1) - Fraction(int(moment["S"]), 1 << 248)
        self.assertEqual(first_expectation, second_expectation)
        self.assertEqual(
            self._fraction(moment["variance"]),
            self._fraction(moment["second_moment"]) - first_expectation**2,
        )

    def test_injected_clock_stops_inside_path_vector_work_before_pair_phase(self) -> None:
        class AdvancingClock:
            def __init__(self) -> None:
                self.now = 0.0
                self.calls = 0

            def __call__(self) -> float:
                self.calls += 1
                self.now += 30.0
                return self.now

        clock = AdvancingClock()
        with self.assertRaisesRegex(ContractError, "availability.second_moment: runtime_resource_limit"):
            availability_report(self.manifest, clock=clock)
        self.assertLess(clock.calls, 10)
        self.assertLess(clock.now, 300.0)

    def test_grouped_pair_identity_matches_direct_small_actual_subset(self) -> None:
        data = _availability_path_vectors(self.manifest)
        vectors = data["vectors"]
        group_choice_counts = data["group_choice_counts"]
        selected_nodes = [0, 1, 2]

        def is_ancestor(ancestor: int, descendant: int) -> bool:
            while descendant:
                descendant = (descendant - 1) // 2
                if descendant == ancestor:
                    return True
            return False

        def z(signature: tuple[int, ...]) -> int:
            return _z_value(signature, group_choice_counts)

        def direct_unmarked_numerator(left: int, right: int) -> int:
            if left == right:
                return z(vectors[left])
            if is_ancestor(left, right):
                return z(vectors[left])
            if is_ancestor(right, left):
                return z(vectors[right])
            return z(tuple(a + b for a, b in zip(vectors[left], vectors[right])))

        direct = sum(
            direct_unmarked_numerator(left, right)
            for left in selected_nodes
            for right in selected_nodes
        )
        signatures = Counter(vectors[node] for node in selected_nodes)
        ordered_signatures = sorted(signatures.items())
        baseline = 0
        for left_index, (left, left_count) in enumerate(ordered_signatures):
            for right_index in range(left_index, len(ordered_signatures)):
                right, right_count = ordered_signatures[right_index]
                multiplicity = left_count * right_count * (1 if left_index == right_index else 2)
                baseline += multiplicity * z(tuple(a + b for a, b in zip(left, right)))
        self_correction = sum(
            count * (z(signature) - z(tuple(2 * value for value in signature)))
            for signature, count in signatures.items()
        )
        ancestor_correction = 0
        for ancestor in selected_nodes:
            for descendant in selected_nodes:
                if ancestor != descendant and is_ancestor(ancestor, descendant):
                    combined = tuple(a + b for a, b in zip(vectors[ancestor], vectors[descendant]))
                    ancestor_correction += 2 * (z(vectors[ancestor]) - z(combined))
        grouped = baseline + self_correction + ancestor_correction

        self.assertEqual(sum(left == right for left in selected_nodes for right in selected_nodes), 3)
        self.assertEqual(
            sum(
                left != right and is_ancestor(left, right)
                for left in selected_nodes
                for right in selected_nodes
            ),
            2,
        )
        self.assertEqual(
            sum(
                left != right
                and not is_ancestor(left, right)
                and not is_ancestor(right, left)
                for left in selected_nodes
                for right in selected_nodes
            ),
            2,
        )
        self.assertEqual(grouped, direct)

    def test_conditional_partial_sum_handles_zero_and_large_retry_counts(self) -> None:
        zero = _conditional_collision_split_bound(Fraction(0, 1), 0)
        self.assertEqual(zero["partial_sum_terms"], 1)
        self.assertEqual(self._fraction(zero["partial_sum"]), Fraction(1, 1))
        self.assertEqual(self._fraction(zero["fresh_abort_upper_bound"]), Fraction(1, 1))
        self.assertEqual(self._fraction(zero["collision_split_upper_bound"]), Fraction(1, 1))

        result = availability_report(self.manifest, retry_count=1 << 22)
        retry = result["conditional_lower_bound"]["retry_evaluation"]
        self.assertEqual(retry["partial_sum_terms"], 17)
        self.assertTrue(retry["exact_g_not_substituted"])
        self.assertLess(self._fraction(retry["fresh_abort_upper_bound"]), Fraction(1, 1))
        self.assertEqual(
            retry["inequality_used"],
            "(1-p_good_lower)^R <= 1/sum_{k=0..min(16,R)} binom(R,k)*p_good_lower^k",
        )

    def test_concrete_filter_mapping_and_opening_budget_fail_closed(self) -> None:
        mutations = [
            ("H0", "squeeze_bytes", 97),
            ("H0", "byte_rule", "payload=bytes[0:96]"),
            ("FS2", "acceptance", "bits[832,839) == 0"),
            ("FS3", "squeeze_bytes", 32),
            ("original_fs3_checks", "T_open", 294),
        ]
        for section, key, value in mutations:
            with self.subTest(section=section, key=key):
                bad = copy.deepcopy(self.manifest)
                if section == "original_fs3_checks":
                    bad["random_oracle"][section][key] = value
                else:
                    bad["random_oracle"]["filters"][section][key] = value
                with self.assertRaisesRegex(ContractError, "identity_mismatch"):
                    _validate_manifest(bad)

    def test_unknown_g_does_not_turn_into_zero(self) -> None:
        result = availability_report(self.manifest)
        self.assertEqual(result["g"], "UNKNOWN")
        self.assertEqual(result["g_status"], "UNKNOWN")
        report = calculate_report_v2(self.manifest)
        self.assertFalse(report["runtime_admission"]["admitted"])
        self.assertFalse(report["claim_limits"]["no_availability_claim_until_g_is_evaluated"] is False)

    def test_public_contract_errors_are_fail_closed(self) -> None:
        with self.assertRaisesRegex(ContractError, "identity_mismatch"):
            bad = copy.deepcopy(self.manifest)
            bad["manifest_version"] = "direct-mask-contract/v1"
            _validate_manifest(bad)


if __name__ == "__main__":
    unittest.main()
