from __future__ import annotations

from contextlib import redirect_stdout
import ctypes
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock
import uuid

import profile11_complete_path as screen
import app.minimal_clearance_source_auth_verifier_adapter as source_auth_adapter


class _Backend:
    def __init__(self, *, capability=(True, True, True, True), result=None) -> None:
        self._capability = capability
        self._result = result
        self.started_with: int | None = None

    def capability(self):
        return self._capability

    def start(self, root_pid: int) -> None:
        self.started_with = root_pid

    def stop(self):
        return self._result or screen.FileWriteObservation("observer_ready", True, True, True, False)


class Profile11CompletePathTests(unittest.TestCase):
    _SCRIPT = Path(screen.__file__).resolve()
    _QUEUE_ROOT = Path(screen.QUEUE_REPO).resolve()
    _BINDING_ERROR = json.dumps(
        {
            "activation": False,
            "error_code": "queue_source_binding",
            "mode": "error",
            "production_usable": False,
            "proofSuiteId": None,
            "schema": screen.PROFILE_SCHEMA,
        },
        sort_keys=True,
        separators=(",", ":"),
    ) + "\n"

    @classmethod
    def _run_direct(cls, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-B", str(cls._SCRIPT), *arguments],
            cwd=cls._SCRIPT.parent,
            capture_output=True,
            text=True,
            check=False,
        )

    @classmethod
    def _run_modified(cls, replacements: tuple[tuple[str, str], ...], *arguments: str) -> subprocess.CompletedProcess[str]:
        source = cls._SCRIPT.read_text(encoding="utf-8")
        for old, new in replacements:
            if source.count(old) != 1:
                raise AssertionError(f"replacement cardinality: {old!r}")
            source = source.replace(old, new)
        with tempfile.TemporaryDirectory(prefix="profile11-binding-script-") as directory:
            script = Path(directory) / cls._SCRIPT.name
            script.write_text(source, encoding="utf-8")
            return subprocess.run(
                [sys.executable, "-B", str(script), *arguments],
                cwd=cls._SCRIPT.parent,
                capture_output=True,
                text=True,
                check=False,
            )

    @classmethod
    def _run_bootstrap(cls, source: str, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-B", "-c", source, str(cls._SCRIPT), *arguments],
            cwd=cls._SCRIPT.parent,
            capture_output=True,
            text=True,
            check=False,
        )

    def _assert_binding_rejection(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertEqual(result.returncode, 2, (result.stdout, result.stderr))
        self.assertEqual(result.stdout, self._BINDING_ERROR)
        self.assertEqual(result.stderr, "")

    def test_execution_binding_rejects_missing_transitive_import_before_launch(self) -> None:
        bootstrap = r'''import importlib.abc, runpy, sys
class Missing(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "app.minimal_clearance_composition_independent":
            raise ModuleNotFoundError(fullname)
        return None
sys.meta_path.insert(0, Missing())
sys.argv = [sys.argv[1], "--prepare"]
runpy.run_path(sys.argv[0], run_name="__main__")
'''
        self._assert_binding_rejection(self._run_bootstrap(bootstrap))

    def test_execution_binding_rejects_wrong_fullname_source_inside_queue_before_launch(self) -> None:
        wrong_source = self._QUEUE_ROOT / "app" / "minimal_clearance_verification_queue_independent.py"
        bootstrap = r'''import importlib.abc, importlib.machinery, importlib.util, runpy, sys
class WrongSource(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "app.minimal_clearance_composition_independent":
            loader = importlib.machinery.SourceFileLoader(fullname, sys.argv[2])
            return importlib.util.spec_from_loader(fullname, loader)
        return None
sys.meta_path.insert(0, WrongSource())
sys.argv = [sys.argv[1], "--prepare"]
runpy.run_path(sys.argv[0], run_name="__main__")
'''
        self._assert_binding_rejection(self._run_bootstrap(bootstrap, str(wrong_source)))

    def test_execution_binding_rejects_manifest_policy_drift_before_launch(self) -> None:
        old = 'binding.get("git_clean_required") is not True'
        new = 'binding.get("git_clean_required") is True'
        self._assert_binding_rejection(self._run_modified(((old, new),), "--prepare"))

    def test_execution_binding_rejects_manifest_fallback_drift_before_launch(self) -> None:
        old = 'binding.get("fallback") is not False'
        new = 'binding.get("fallback") is False'
        self._assert_binding_rejection(self._run_modified(((old, new),), "--prepare"))

    def test_execution_binding_rejects_dirty_queue_before_launch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="profile11-dirty-queue-") as directory:
            clone = Path(directory) / "queue"
            cloned = subprocess.run(
                ["git", "clone", "--quiet", "--no-hardlinks", str(self._QUEUE_ROOT), str(clone)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(cloned.returncode, 0, cloned.stderr)
            (clone / "binding-dirty-sentinel").write_text("dirty", encoding="ascii")
            result = subprocess.run(
                [sys.executable, "-B", str(clone / self._SCRIPT.name), "--prepare"],
                cwd=clone,
                capture_output=True,
                text=True,
                check=False,
            )
            self._assert_binding_rejection(result)

    def test_execution_binding_rejects_preloaded_app_before_launch(self) -> None:
        bootstrap = r'''import app, runpy, sys
sys.argv = [sys.argv[1], "--prepare"]
runpy.run_path(sys.argv[0], run_name="__main__")
'''
        self._assert_binding_rejection(self._run_bootstrap(bootstrap))

    def test_execution_binding_rejects_split_class_identity_before_launch(self) -> None:
        runtime_source = self._QUEUE_ROOT / "app" / "minimal_clearance_verification_runtime.py"
        bootstrap = r'''import importlib.abc, importlib.machinery, importlib.util, runpy, sys
class SplitLoader(importlib.machinery.SourceFileLoader):
    def exec_module(self, module):
        super().exec_module(module)
        module.StateDispositionControl = object()
class SplitIdentity(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "app.minimal_clearance_verification_runtime":
            loader = SplitLoader(fullname, sys.argv[2])
            return importlib.util.spec_from_loader(fullname, loader)
        return None
sys.meta_path.insert(0, SplitIdentity())
sys.argv = [sys.argv[1], "--prepare"]
runpy.run_path(sys.argv[0], run_name="__main__")
'''
        self._assert_binding_rejection(self._run_bootstrap(bootstrap, str(runtime_source)))

    def test_execution_binding_has_exact_origins_loaders_caches_and_classes(self) -> None:
        bootstrap = r'''import contextlib, importlib.machinery, importlib.util, io, json, pathlib, runpy, sys
captured = io.StringIO()
sys.argv = [sys.argv[1], "--prepare"]
with contextlib.redirect_stdout(captured):
    try:
        runpy.run_path(sys.argv[0], run_name="__main__")
    except SystemExit as error:
        exit_code = error.code
names = (
    "app",
    "app.minimal_clearance_composition",
    "app.minimal_clearance_composition_independent",
    "app.minimal_clearance_resource_limits",
    "app.minimal_clearance_source_auth_verifier_adapter",
    "app.minimal_clearance_verification_queue",
    "app.minimal_clearance_verification_queue_independent",
    "app.minimal_clearance_verification_runtime",
    "app.minimal_clearance_verifier_process",
)
modules = {name: sys.modules[name] for name in names}
queue = modules["app.minimal_clearance_verification_queue"]
source = modules["app.minimal_clearance_source_auth_verifier_adapter"]
runtime = modules["app.minimal_clearance_verification_runtime"]
composition = modules["app.minimal_clearance_composition"]
prefix = pathlib.Path(sys.pycache_prefix).resolve()
payload = {
    "exit_code": exit_code,
    "prepare": json.loads(captured.getvalue()),
    "loaded": sorted(name for name in sys.modules if name == "app" or name.startswith("app.")),
    "prefix_exists": prefix.exists(),
    "modules": {
        name: {
            "file": str(pathlib.Path(module.__file__).resolve()),
            "origin": str(pathlib.Path(module.__spec__.origin).resolve()),
            "loader": isinstance(module.__spec__.loader, importlib.machinery.SourceFileLoader),
            "loader_path": str(pathlib.Path(module.__spec__.loader.path).resolve()),
            "cached": str(pathlib.Path(module.__cached__).resolve()),
            "expected_cache": str(pathlib.Path(importlib.util.cache_from_source(module.__file__)).resolve()),
            "cache_exists": pathlib.Path(module.__cached__).exists(),
            "cache_under_prefix": prefix in pathlib.Path(module.__cached__).resolve().parents,
        }
        for name, module in modules.items()
    },
    "classes": {
        "QueueConfig": queue.QueueConfig is source.QueueConfig is runtime.QueueConfig,
        "SourceAuthVerifierConfig": source.SourceAuthVerifierConfig is runtime.SourceAuthVerifierConfig,
        "CompositionConfigV2": composition.CompositionConfigV2 is runtime.CompositionConfigV2,
        "StateDispositionControl": composition.StateDispositionControl is runtime.StateDispositionControl,
        "IssuedVerificationBatch": queue.IssuedVerificationBatch is source.IssuedVerificationBatch is runtime.IssuedVerificationBatch,
        "VolatileProofHandoff": queue.VolatileProofHandoff is source.VolatileProofHandoff is runtime.VolatileProofHandoff,
    },
}
print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
'''
        result = self._run_bootstrap(bootstrap)
        self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        self.assertEqual(result.stderr, "")
        value = json.loads(result.stdout)
        self.assertEqual(value["exit_code"], 0)
        self._assert_prepare_shape(value["prepare"])
        expected_sources = {
            "app": "app/__init__.py",
            "app.minimal_clearance_composition": "app/minimal_clearance_composition.py",
            "app.minimal_clearance_composition_independent": "app/minimal_clearance_composition_independent.py",
            "app.minimal_clearance_resource_limits": "app/minimal_clearance_resource_limits.py",
            "app.minimal_clearance_source_auth_verifier_adapter": "app/minimal_clearance_source_auth_verifier_adapter.py",
            "app.minimal_clearance_verification_queue": "app/minimal_clearance_verification_queue.py",
            "app.minimal_clearance_verification_queue_independent": "app/minimal_clearance_verification_queue_independent.py",
            "app.minimal_clearance_verification_runtime": "app/minimal_clearance_verification_runtime.py",
            "app.minimal_clearance_verifier_process": "app/minimal_clearance_verifier_process.py",
        }
        self.assertEqual(value["loaded"], sorted(expected_sources))
        self.assertFalse(value["prefix_exists"])
        self.assertTrue(all(value["classes"].values()), value["classes"])
        for name, relative in expected_sources.items():
            facts = value["modules"][name]
            expected = str((self._QUEUE_ROOT / relative).resolve())
            self.assertEqual((facts["file"], facts["origin"], facts["loader_path"]), (expected, expected, expected))
            self.assertTrue(facts["loader"])
            self.assertEqual(facts["cached"], facts["expected_cache"])
            self.assertTrue(facts["cache_under_prefix"])
            self.assertFalse(facts["cache_exists"])

    def _assert_prepare_shape(self, value: dict[str, object]) -> None:
        self.assertEqual(value, {
            "activation": False,
            "full_mode": "fail_closed",
            "launches": 0,
            "mismatch_count": 0,
            "mismatched": [],
            "missing": ["source_workspace", "verifier_workspace", "state_workspace"],
            "missing_count": 3,
            "mode": "prepare",
            "production_usable": False,
            "proofSuiteId": None,
            "schema": "BL/NATIVE-V3/PROFILE11-COMPLETE-PATH/v1",
        })

    def test_library_import_remains_unbound_and_coordinator_rejects(self) -> None:
        bootstrap = r'''import json, pathlib, sys
import profile11_complete_path as candidate
try:
    candidate._run_coordinator(pathlib.Path(sys.argv[2]))
except candidate.CompletePathError as error:
    result = {"bound": candidate._QUEUE_SOURCE_BOUND, "error_code": str(error)}
else:
    result = {"bound": candidate._QUEUE_SOURCE_BOUND, "error_code": None}
print(json.dumps(result, sort_keys=True, separators=(",", ":")))
'''
        with tempfile.TemporaryDirectory(prefix="profile11-library-unbound-") as directory:
            result = self._run_bootstrap(bootstrap, directory)
        self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        self.assertEqual(result.stderr, "")
        self.assertEqual(json.loads(result.stdout), {"bound": False, "error_code": "queue_source_binding"})

    def test_direct_prepare_binds_fresh_and_preserves_non_readiness(self) -> None:
        result = self._run_direct("--prepare")
        self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        self.assertEqual(result.stderr, "")
        self._assert_prepare_shape(json.loads(result.stdout))

    def test_direct_prepare_loads_e2e_fixture_without_ambient_tests_import(self) -> None:
        bootstrap = r'''import json, pathlib, runpy, sys
sys.path.insert(0, str(pathlib.Path(sys.argv[1]).resolve().parent / "ambient-does-not-exist"))
sys.argv = [sys.argv[1], "--prepare"]
runpy.run_path(sys.argv[0], run_name="__main__")
'''
        result = self._run_bootstrap(bootstrap)
        self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        self.assertEqual(result.stderr, "")
        value = json.loads(result.stdout)
        self._assert_prepare_shape(value)
        self.assertNotIn("public_key_missing", value["mismatched"])

    def test_fixture_loader_ignores_preloaded_hostile_tests_module(self) -> None:
        bootstrap = r'''import json, pathlib, runpy, sys, types
sys.path.insert(0, str(pathlib.Path(sys.argv[1]).resolve().parent / "ambient-does-not-exist"))
package = types.ModuleType("tests")
package.__path__ = []
fixture = types.ModuleType("tests.test_profile11_source_boundary")
fixture.SOURCE_TEST_PUBLIC_KEY = b"hostile"
sys.modules["tests"] = package
sys.modules["tests.test_profile11_source_boundary"] = fixture
sys.argv = [sys.argv[1], "--prepare"]
runpy.run_path(sys.argv[0], run_name="__main__")
'''
        result = self._run_bootstrap(bootstrap)
        self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        self.assertEqual(result.stderr, "")
        self._assert_prepare_shape(json.loads(result.stdout))

    def test_fixture_loader_rejects_malformed_declarations_without_importing_fixture(self) -> None:
        fixture_source = (self._SCRIPT.parent / "tests" / "test_profile11_source_boundary.py").read_text(encoding="utf-8")
        valid_line = "SOURCE_TEST_PUBLIC_KEY = bytes.fromhex(\"00\")\n"
        cases = {
            "missing": "fromhex = bytes.fromhex\n",
            "dynamic": "SOURCE_TEST_PUBLIC_KEY = bytes.fromhex(get_value())\n",
            "duplicate": valid_line + valid_line,
            "wrong_shape": "SOURCE_TEST_PUBLIC_KEY = bytes.fromhex(1)\n",
            "identity": valid_line,
        }
        for name, declaration in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory(prefix="profile11-fixture-") as directory:
                root = Path(directory)
                (root / "tests").mkdir()
                script = root / "profile11_complete_path.py"
                script.write_text("# isolated loader path\n", encoding="utf-8")
                start = fixture_source.index("SOURCE_TEST_PUBLIC_KEY = bytes.fromhex(")
                end = fixture_source.index("\n\n\ndef _assert_pinned_file", start)
                mutated = fixture_source[:start] + declaration + fixture_source[end:]
                fixture = root / "tests" / "test_profile11_source_boundary.py"
                fixture.write_text(mutated, encoding="utf-8")
                with mock.patch.object(screen, "__file__", str(script)):
                    with self.assertRaisesRegex(screen.CompletePathError, "public_key_(missing|identity)"):
                        screen._load_synthetic_public_key()

    def test_fixture_loader_rejects_growth_after_metadata_check(self) -> None:
        fixture_source = (self._SCRIPT.parent / "tests" / "test_profile11_source_boundary.py").read_bytes()
        with tempfile.TemporaryDirectory(prefix="profile11-fixture-growth-") as directory:
            root = Path(directory)
            (root / "tests").mkdir()
            script = root / "profile11_complete_path.py"
            script.write_text("# isolated loader path\n", encoding="utf-8")
            fixture = root / "tests" / "test_profile11_source_boundary.py"
            fixture.write_bytes(fixture_source)
            original_stat = Path.stat
            grew = False

            def stat_then_grow(path: Path, *, follow_symlinks: bool = True):
                nonlocal grew
                result = original_stat(path, follow_symlinks=follow_symlinks)
                if path == fixture and not grew:
                    grew = True
                    with fixture.open("ab") as stream:
                        stream.write(b"# growth" * (screen._SYNTHETIC_FIXTURE_MAX_BYTES // 8))
                return result

            with mock.patch.object(screen, "__file__", str(script)), mock.patch.object(Path, "stat", stat_then_grow):
                with self.assertRaisesRegex(screen.CompletePathError, "public_key_missing"):
                    screen._load_synthetic_public_key()
            self.assertGreater(fixture.stat().st_size, screen._SYNTHETIC_FIXTURE_MAX_BYTES)

    @staticmethod
    def _timed_sample(index: int = 0) -> screen.StageSample:
        breakdown = screen.VerifyStateBreakdown(1.0 + index, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0)
        source = 1.0 + index
        verify_state = 2.0 + index
        ack = 3.0 + index
        total_unbucketed = 1.0
        total = source + verify_state + ack + total_unbucketed
        return screen.StageSample(source, verify_state, ack, total, breakdown, total_unbucketed)

    @staticmethod
    def _schema_facts() -> tuple[screen._EtwSchemaFact, ...]:
        return tuple(
            screen._EtwSchemaFact(
                spec.provider,
                spec.event_id,
                version,
                spec.task,
                spec.opcode,
                screen._ETW_SCHEMA_PROPERTIES[(spec.provider, spec.event_id, version)],
            )
            for spec in screen._ETW_SCHEMA_SPECS
            for version in sorted(spec.versions)
        )

    @staticmethod
    def _create_state_database(root: Path, journal_mode: str = "delete") -> str:
        database = root / "state.sqlite"
        connection = sqlite3.connect(database)
        try:
            actual = str(connection.execute(f"PRAGMA journal_mode={journal_mode.upper()}").fetchone()[0]).lower()
        finally:
            connection.close()
        return actual

    def test_manifest_and_exact_pins(self) -> None:
        manifest = json.loads(screen.MANIFEST_PATH.read_text(encoding="utf-8"))
        readme = (screen.MANIFEST_PATH.parent / "README.md").read_text(encoding="utf-8")
        self.assertEqual(manifest["schema"], "BL/NATIVE-V3/PROFILE11-COMPLETE-PATH-MANIFEST/v2")
        self.assertNotIn("queue", manifest["git_pins"])
        self.assertIn("python_source_binding.required_modules", readme)
        self.assertNotIn("queue-runtime-assembled-20260905", readme)
        self.assertNotIn("blind-queue-receiver-binding-v1", readme)
        for retired_pin in (
            "412b53e68091561657106345a22a772699761945",
            "72746eb68e667698fdb0a72c8aea7c9bf027076a",
        ):
            with self.subTest(retired_queue_pin=retired_pin):
                self.assertNotIn(retired_pin, readme)
        self.assertEqual(manifest["topology"], {"batch_operations": 100, "proofs": 1, "source_frames": 1, "verifier_batches": 1, "outbox_acks": 100})
        self.assertEqual(manifest["limits"]["component_admission_bytes"], 4_500_000_000)
        self.assertEqual(manifest["limits"]["complete_tree_hard_peak_bytes"], 4_999_999_999)
        self.assertEqual(manifest["disk_gate"]["sqlite"], {
            "live_journal_mode": "delete",
            "mode_allowlist": {
                "delete": ["state.sqlite", "state.sqlite-journal", "state.sqlite.runtime-lock"],
                "wal": ["state.sqlite", "state.sqlite-wal", "state.sqlite-shm", "state.sqlite.runtime-lock"],
            },
            "live_binding": "QueueConfig.as_json.database_journal_mode plus read-only PRAGMA journal_mode readback",
        })
        self.assertEqual(
            manifest["git_pins"],
            {
                "producer": {
                    "path": str(screen.PRODUCER_REPO),
                    "head": screen.PRODUCER_HEAD,
                    "tree": screen.PRODUCER_TREE,
                },
                "source": {
                    "path": str(screen.SOURCE_REPO),
                    "head": screen.SOURCE_HEAD,
                    "tree": screen.SOURCE_TREE,
                },
                "c": {
                    "path": str(screen.C_REPO),
                    "head": screen.C_HEAD,
                    "tree": screen.C_TREE,
                },
            },
        )
        required_modules = {
            "app": {"path": "app/__init__.py", "git_blob": "75bbf4ba2446feb54ba8516abe2a135925215320"},
            "app.minimal_clearance_composition": {"path": "app/minimal_clearance_composition.py", "git_blob": "131e6e9649483791b6799c0eefa48d54e5293cf5"},
            "app.minimal_clearance_composition_independent": {"path": "app/minimal_clearance_composition_independent.py", "git_blob": "466a27bbc9a3aee21333d210c824d938876b0072"},
            "app.minimal_clearance_resource_limits": {"path": "app/minimal_clearance_resource_limits.py", "git_blob": "56e57ebb3618b5ab090165f6a8ab93be70cd9c7c"},
            "app.minimal_clearance_source_auth_verifier_adapter": {"path": "app/minimal_clearance_source_auth_verifier_adapter.py", "git_blob": "f4ae20452717683c1182631c5b0c5850d9c78c6f"},
            "app.minimal_clearance_verification_queue": {"path": "app/minimal_clearance_verification_queue.py", "git_blob": "2f4475a6c40f53a4a28ec94045d08b97077afac2"},
            "app.minimal_clearance_verification_queue_independent": {"path": "app/minimal_clearance_verification_queue_independent.py", "git_blob": "f700e2036f851a98f77382bb08dda7e728403fea"},
            "app.minimal_clearance_verification_runtime": {"path": "app/minimal_clearance_verification_runtime.py", "git_blob": "6c48f2428ef5fe391eeb24ab566b4c2ecc680445"},
            "app.minimal_clearance_verifier_process": {"path": "app/minimal_clearance_verifier_process.py", "git_blob": "2002036f2e0be3266ff4827bb01a24b13657b2cd"},
        }
        self.assertEqual(
            manifest["python_source_binding"],
            {
                "canonical_package": "app",
                "content_hash": "git-blob-sha1",
                "source_root": {
                    "relative_to": "manifest_parent",
                    "relative_path": ".",
                    "max_depth": 0,
                },
                "git_clean_required": True,
                "source_only_cache_handling": True,
                "fallback": False,
                "required_modules": required_modules,
            },
        )
        self.assertEqual(
            manifest["file_pins"],
            {
                "producer_executable": {
                    "path": str(screen.PRODUCER_EXECUTABLE),
                    "bytes": screen.PRODUCER_EXECUTABLE_SIZE_BYTES,
                    "sha256": screen.PRODUCER_EXECUTABLE_SHA256,
                },
                "c_verifier": {
                    "path": str(screen.C_VERIFIER),
                    "bytes": source_auth_adapter.SOURCE_AUTH_EXECUTABLE_SIZE_BYTES,
                    "sha256": source_auth_adapter.SOURCE_AUTH_EXECUTABLE_SHA256.hex().upper(),
                },
                "c_source_library": {
                    "path": str(screen.C_SOURCE_LIBRARY),
                    "bytes": screen.C_SOURCE_LIBRARY_SIZE_BYTES,
                    "sha256": screen.C_SOURCE_LIBRARY_SHA256,
                },
                "c_range_library": {
                    "path": str(screen.C_RANGE_LIBRARY),
                    "bytes": screen.C_RANGE_LIBRARY_SIZE_BYTES,
                    "sha256": screen.C_RANGE_LIBRARY_SHA256,
                },
            },
        )
        self.assertEqual(
            manifest["resource_observation"],
            {
                "authority": "Windows Job Object",
                "api": "QueryInformationJobObject",
                "memory_metric": "JOBOBJECT_EXTENDED_LIMIT_INFORMATION.PeakJobMemoryUsed",
                "cap_metric": "JOBOBJECT_EXTENDED_LIMIT_INFORMATION.JobMemoryLimit",
                "process_metric": "JOBOBJECT_BASIC_ACCOUNTING_INFORMATION.ActiveProcesses_and_TotalProcesses",
                "active_process_metric_semantics": "sampled_maximum_lower_bound_not_exact_high_water_mark",
                "active_process_limit_semantics": "os_enforced_job_object_limit",
                "total_process_metric_semantics": "os_cumulative_total_processes",
                "enforcement": ["JobMemoryLimit", "ActiveProcessLimit"],
                "cap_strictly_less_than_bytes": 5_000_000_000,
                "missing_metric": "fail_closed",
                "process_tree_completion": "final ActiveProcesses equals zero after process-handle signal",
                "resource_only_report_is_nonactivating": True,
            },
        )
        self.assertIsNone(manifest["qualification"]["proofSuiteId"])
        self.assertFalse(manifest["qualification"]["production_usable"])
        self.assertFalse(manifest["qualification"]["activation"])

    def test_dependency_pins_and_empty_workspaces(self) -> None:
        with tempfile.TemporaryDirectory(prefix="profile11-preflight-") as directory:
            root = Path(directory)
            source = root / "source"
            verifier = root / "verifier"
            state = root / "state"
            source.mkdir()
            verifier.mkdir()
            state.mkdir()
            report = screen.validate_dependencies(source_workspace=source, verifier_workspace=verifier, state_workspace=state)
        self.assertTrue(report.ready, (report.missing, report.mismatched))
        self.assertEqual(report.failure_count, 0)

    def test_topology_is_exactly_one_proof_and_100_operations(self) -> None:
        screen.validate_topology(proof_count=1, operation_count=100, frame_count=1, verifier_batch_count=1, ack_count=100)
        for values in ((2, 100, 1, 1, 100), (1, 99, 1, 1, 100), (1, 100, 2, 1, 100), (1, 100, 1, 2, 100), (1, 100, 1, 1, 99)):
            with self.subTest(values=values):
                with self.assertRaisesRegex(screen.CompletePathError, "topology_mismatch"):
                    screen.validate_topology(proof_count=values[0], operation_count=values[1], frame_count=values[2], verifier_batch_count=values[3], ack_count=values[4])

    def test_state_port_advances_persisted_sequence_between_batches(self) -> None:
        port = screen._ScreenStatePort()
        first_refs = tuple(index.to_bytes(32, "big") for index in range(100))
        second_refs = tuple((100 + index).to_bytes(32, "big") for index in range(100))
        first = port.controls_for(batch_id=bytes(32), operation_refs=first_refs, verification_outcome=object())
        second = port.controls_for(batch_id=bytes([1]) * 32, operation_refs=second_refs, verification_outcome=object())
        self.assertEqual((first[first_refs[0]].sequence_before, first[first_refs[-1]].sequence_before), (0, 99))
        self.assertEqual((second[second_refs[0]].sequence_before, second[second_refs[-1]].sequence_before), (100, 199))
        self.assertEqual(second[second_refs[0]].predecessor_state_id, first[first_refs[-1]].state_after_id)
        self.assertEqual(second[second_refs[0]].predecessor_continuity_root, first[first_refs[-1]].state_after_continuity_root)

    def test_outer_cap_is_strict_and_readback_is_exact(self) -> None:
        effective = screen.effective_outer_cap(screen.PROCESS_TREE_PEAK_CAP_BYTES, 4096)
        self.assertLess(effective, screen.OUTER_HARD_CAP_BYTES)
        with self.assertRaisesRegex(screen.CompletePathError, "outer_cap_invalid"):
            screen.effective_outer_cap(screen.OUTER_HARD_CAP_BYTES, 4096)
        good = screen.JobObservation(1024, screen.PROCESS_TREE_PEAK_CAP_BYTES, effective, effective, screen.OUTER_ACTIVE_PROCESS_LIMIT, screen.OUTER_ACTIVE_PROCESS_LIMIT, 8, 8, True, True, True)
        screen.validate_job_observation(good)
        with self.assertRaisesRegex(screen.CompletePathError, "outer_measurement_missing"):
            screen.validate_job_observation(screen.JobObservation(0, screen.PROCESS_TREE_PEAK_CAP_BYTES, effective, effective, screen.OUTER_ACTIVE_PROCESS_LIMIT, screen.OUTER_ACTIVE_PROCESS_LIMIT, 1, 1, True, True, True))
        with self.assertRaisesRegex(screen.CompletePathError, "outer_measurement_incomplete"):
            screen.validate_job_observation(screen.JobObservation(1024, screen.PROCESS_TREE_PEAK_CAP_BYTES, effective, effective, screen.OUTER_ACTIVE_PROCESS_LIMIT, screen.OUTER_ACTIVE_PROCESS_LIMIT, 1, 1, True, False, True))
        with self.assertRaisesRegex(screen.CompletePathError, "outer_memory_cap"):
            screen.validate_job_observation(screen.JobObservation(effective + 1, screen.PROCESS_TREE_PEAK_CAP_BYTES, effective, effective, screen.OUTER_ACTIVE_PROCESS_LIMIT, screen.OUTER_ACTIVE_PROCESS_LIMIT, 1, 1, True, True, True))
        for bad, code in (
            (screen.JobObservation(1024, screen.PROCESS_TREE_PEAK_CAP_BYTES, effective, effective + 4096, screen.OUTER_ACTIVE_PROCESS_LIMIT, screen.OUTER_ACTIVE_PROCESS_LIMIT, 2, 3, True, True, True), "outer_cap_readback"),
            (screen.JobObservation(screen.OUTER_HARD_CAP_BYTES, screen.PROCESS_TREE_PEAK_CAP_BYTES, effective, effective, screen.OUTER_ACTIVE_PROCESS_LIMIT, screen.OUTER_ACTIVE_PROCESS_LIMIT, 2, 3, True, True, True), "outer_memory_cap"),
            (screen.JobObservation(1024, screen.PROCESS_TREE_PEAK_CAP_BYTES, effective, effective, screen.OUTER_ACTIVE_PROCESS_LIMIT, screen.OUTER_ACTIVE_PROCESS_LIMIT - 1, 2, 3, True, True, True), "outer_process_limit_readback"),
            (screen.JobObservation(1024, screen.PROCESS_TREE_PEAK_CAP_BYTES, effective, effective, screen.OUTER_ACTIVE_PROCESS_LIMIT, screen.OUTER_ACTIVE_PROCESS_LIMIT, 2, 0, True, True, True), "outer_process_lineage"),
            (screen.JobObservation(1024, screen.PROCESS_TREE_PEAK_CAP_BYTES, effective, effective, 9, 9, 1, 1, True, True, True), "outer_process_limit_configuration"),
            (screen.JobObservation(1024, screen.PROCESS_TREE_PEAK_CAP_BYTES, effective, effective, screen.OUTER_ACTIVE_PROCESS_LIMIT, screen.OUTER_ACTIVE_PROCESS_LIMIT, 9, 9, True, True, True), "outer_process_limit"),
            (screen.JobObservation(1024, screen.PROCESS_TREE_PEAK_CAP_BYTES, effective, effective, screen.OUTER_ACTIVE_PROCESS_LIMIT, screen.OUTER_ACTIVE_PROCESS_LIMIT, 8, 7, True, True, True), "outer_process_lineage"),
        ):
            with self.subTest(code=code):
                with self.assertRaisesRegex(screen.CompletePathError, code):
                    screen.validate_job_observation(bad)
        for bad_peak in (-1, "SYNTHETIC_UNTRUSTED_TEXT"):
            with self.subTest(bad_peak=bad_peak):
                with self.assertRaisesRegex(screen.CompletePathError, "aggregate_peak"):
                    screen.build_test_aggregate(peak_job_commit_bytes=bad_peak, error_code="outer_memory_cap")
        numeric_failure = screen.build_test_aggregate(peak_job_commit_bytes=screen.OUTER_HARD_CAP_BYTES, error_code="outer_memory_cap")
        self.assertEqual(numeric_failure["peak_job_commit_bytes"], screen.OUTER_HARD_CAP_BYTES)

    def test_outer_job_probe_contains_child_and_grandchild(self) -> None:
        if os.name != "nt":
            self.skipTest("Windows Job Object ABI is unavailable")
        for delay in ("0.15", "0.01"):
            with self.subTest(delay=delay), tempfile.TemporaryDirectory(prefix="profile11-job-") as directory:
                run = screen._launch_coordinator(Path(directory), timeout_seconds=5.0, arguments=("--probe-coordinator", delay))
            self.assertIsNone(run.error_code, run.error_code)
            self.assertIsNotNone(run.payload)
            self.assertGreater(run.observation.peak_job_commit_bytes, 0)
            self.assertEqual(run.observation.cap_readback_bytes, run.observation.effective_cap_bytes)
            self.assertTrue(run.observation.measurement_complete)
            self.assertGreaterEqual(run.observation.total_processes, 2)
            self.assertGreaterEqual(run.observation.peak_active_processes, 1)
            self.assertTrue(run.observation.process_tree_complete)
            self.assertTrue(run.observation.cleanup_complete)
            screen.validate_job_observation(run.observation)

    def test_outer_job_probe_reads_descendant_tail_allocation_after_coordinator_signal(self) -> None:
        if os.name != "nt":
            self.skipTest("Windows Job Object ABI is unavailable")
        tail_bytes = 96 * 1024 * 1024
        with tempfile.TemporaryDirectory(prefix="profile11-job-tail-") as directory:
            run = screen._launch_coordinator(
                Path(directory),
                timeout_seconds=10.0,
                arguments=(
                    "--probe-coordinator", "0.01",
                    "--probe-tail-bytes", str(tail_bytes),
                    "--probe-tail-delay", "0.25",
                ),
            )
        self.assertIsNone(run.error_code, run.error_code)
        self.assertIsNotNone(run.payload)
        self.assertGreaterEqual(run.observation.peak_job_commit_bytes, tail_bytes)
        self.assertTrue(run.observation.process_tree_complete)
        self.assertTrue(run.observation.measurement_complete)
        self.assertTrue(run.observation.cleanup_complete)
        screen.validate_job_observation(run.observation)

    def test_native_resource_release_closes_each_owned_path_once(self) -> None:
        class Kernel:
            def __init__(self) -> None:
                self.attribute_deletes = []
                self.handle_closes = []

            def DeleteProcThreadAttributeList(self, value) -> None:
                self.attribute_deletes.append(value)

            def CloseHandle(self, value) -> bool:
                self.handle_closes.append(value)
                return True

        kernel = Kernel()
        failures: list[str] = []
        attribute_list = object()
        with mock.patch.object(screen.os, "close") as close:
            screen._release_coordinator_resources(
                kernel32=kernel,
                stdout_read=11,
                stdout_write=12,
                stderr_read=13,
                stderr_write=14,
                attribute_list_initialized=True,
                attribute_list=attribute_list,
                thread_handle="thread",
                process_handle="process",
                job="job",
                cleanup_failures=failures,
            )
        self.assertEqual([call.args[0] for call in close.call_args_list], [11, 12, 13, 14])
        self.assertEqual(kernel.attribute_deletes, [attribute_list])
        self.assertEqual(kernel.handle_closes, ["thread", "process", "job"])
        self.assertEqual(failures, [])

    def test_native_resource_release_faults_and_partial_ownership_fail_closed_without_retry(self) -> None:
        class FaultingKernel:
            def __init__(self) -> None:
                self.attribute_deletes = 0
                self.handle_closes = []

            def DeleteProcThreadAttributeList(self, value) -> None:
                del value
                self.attribute_deletes += 1
                raise RuntimeError("attribute close fault")

            def CloseHandle(self, value) -> bool:
                self.handle_closes.append(value)
                return value != "process"

        kernel = FaultingKernel()
        failures: list[str] = []

        def close(fd: int) -> None:
            if fd == 12:
                raise OSError("descriptor close fault")

        with mock.patch.object(screen.os, "close", side_effect=close) as close_mock:
            screen._release_coordinator_resources(
                kernel32=kernel,
                stdout_read=11,
                stdout_write=12,
                stderr_read=None,
                stderr_write=None,
                attribute_list_initialized=True,
                attribute_list=object(),
                thread_handle="thread",
                process_handle="process",
                job="job",
                cleanup_failures=failures,
            )
        self.assertEqual([call.args[0] for call in close_mock.call_args_list], [11, 12])
        self.assertEqual(kernel.attribute_deletes, 1)
        self.assertEqual(kernel.handle_closes, ["thread", "process", "job"])
        self.assertEqual(
            set(failures),
            {"outer_stdout_write_close", "outer_attribute_list_close", "outer_process_handle_close"},
        )

        partial_failures: list[str] = []
        with mock.patch.object(screen.os, "close") as partial_close:
            screen._release_coordinator_resources(
                kernel32=None,
                stdout_read=21,
                stdout_write=22,
                stderr_read=None,
                stderr_write=None,
                attribute_list_initialized=False,
                attribute_list=None,
                thread_handle=None,
                process_handle=None,
                job=None,
                cleanup_failures=partial_failures,
            )
        self.assertEqual([call.args[0] for call in partial_close.call_args_list], [21, 22])
        self.assertEqual(partial_failures, [])

        class TerminationKernel:
            def __init__(self, result: bool) -> None:
                self.result = result
                self.termination_calls = 0
                self.wait_calls = 0

            def TerminateJobObject(self, job, code) -> bool:
                del job, code
                self.termination_calls += 1
                return self.result

            def WaitForSingleObject(self, handle, timeout) -> int:
                del handle, timeout
                self.wait_calls += 1
                return screen._WAIT_OBJECT_0

        termination_failures: list[str] = []
        failed_kernel = TerminationKernel(False)
        self.assertFalse(
            screen._terminate_coordinator_tree_once(
                kernel32=failed_kernel,
                job="job",
                process_handle="process",
                job_assigned=True,
                cleanup_failures=termination_failures,
            )
        )
        self.assertEqual((failed_kernel.termination_calls, failed_kernel.wait_calls), (1, 0))
        self.assertEqual(termination_failures, ["outer_process_terminate"])

    def test_native_reader_thread_close_failure_is_fail_closed(self) -> None:
        output: dict[str, bytes] = {}
        failed: dict[str, str] = {}
        cleanup_failures: list[str] = []
        with mock.patch.object(screen.os, "read", return_value=b""), mock.patch.object(screen.os, "close", side_effect=OSError("reader close fault")):
            screen._read_pipe(31, 64, output, "stdout", failed, cleanup_failures)
        self.assertEqual(output, {"stdout": b""})
        self.assertEqual(failed, {"code": "coordinator_output_close"})
        self.assertEqual(cleanup_failures, ["outer_stdout_close"])

    def test_launcher_reader_start_before_thread_releases_from_launcher_once(self) -> None:
        owners: list[screen._CoordinatorOwnedDescriptor] = []
        close_calls: list[int] = []

        class StartBeforeThread:
            ident = None

            def start(self) -> None:
                raise RuntimeError("start-before-thread")

            def join(self, *, timeout: float) -> None:
                del timeout
                raise RuntimeError("cannot join thread before it is started")

            def is_alive(self) -> bool:
                return False

        def factory(owner, cap, output, key, failed, cleanup_failures):
            del cap, output, key, failed, cleanup_failures
            owners.append(owner)
            return StartBeforeThread()

        real_close = screen.os.close

        def track_close(fd: int) -> None:
            close_calls.append(fd)
            real_close(fd)

        with tempfile.TemporaryDirectory(prefix="profile11-reader-start-before-") as directory:
            with mock.patch.object(screen, "_new_coordinator_reader_thread", side_effect=factory), mock.patch.object(screen.os, "close", side_effect=track_close):
                run = screen._launch_coordinator(Path(directory), timeout_seconds=5.0, arguments=("--probe-coordinator", "0.01"))
        self.assertEqual(run.error_code, "outer_reader_start")
        self.assertIsNone(run.payload)
        self.assertFalse(run.observation.cleanup_complete)
        self.assertEqual(len(owners), 2)
        self.assertTrue(all(owner.owner == "launcher" for owner in owners))
        self.assertTrue(all(owner.state == "closed" for owner in owners))
        self.assertEqual(len(close_calls), 4)
        self.assertEqual(len(set(close_calls)), 4)

    def test_launcher_reader_start_after_thread_transfers_once_without_double_close(self) -> None:
        owners: list[screen._CoordinatorOwnedDescriptor] = []
        close_calls: list[int] = []

        class StartAfterThread:
            def __init__(self, owner, cap, output, key, failed, cleanup_failures) -> None:
                self._owner = owner
                self._args = (owner.descriptor, cap, output, key, failed, cleanup_failures, owner)
                self.ident = None

            def start(self) -> None:
                self.ident = 1
                screen._read_pipe(*self._args)
                raise RuntimeError("start-after-thread")

            def join(self, *, timeout: float) -> None:
                del timeout

            def is_alive(self) -> bool:
                return False

        def factory(owner, cap, output, key, failed, cleanup_failures):
            owners.append(owner)
            return StartAfterThread(owner, cap, output, key, failed, cleanup_failures)

        real_close = screen.os.close

        def track_close(fd: int) -> None:
            close_calls.append(fd)
            real_close(fd)

        with tempfile.TemporaryDirectory(prefix="profile11-reader-start-after-") as directory:
            with mock.patch.object(screen, "_new_coordinator_reader_thread", side_effect=factory), mock.patch.object(screen.os, "close", side_effect=track_close):
                run = screen._launch_coordinator(Path(directory), timeout_seconds=5.0, arguments=("--probe-coordinator", "0.01"))
        self.assertEqual(run.error_code, "outer_reader_start")
        self.assertIsNone(run.payload)
        self.assertFalse(run.observation.cleanup_complete)
        self.assertEqual(len(owners), 2)
        self.assertEqual((owners[0].owner, owners[0].state), ("reader", "closed"))
        self.assertEqual((owners[1].owner, owners[1].state), ("launcher", "closed"))
        self.assertEqual(len(close_calls), 4)
        self.assertEqual(len(set(close_calls)), 4)

    def test_launcher_reader_join_exception_releases_everything_without_retry(self) -> None:
        owners: list[screen._CoordinatorOwnedDescriptor] = []
        join_calls = 0
        close_calls: list[int] = []

        class JoinFaultThread:
            def __init__(self, owner, cap, output, key, failed, cleanup_failures) -> None:
                self._args = (owner.descriptor, cap, output, key, failed, cleanup_failures, owner)
                self.ident = None

            def start(self) -> None:
                self.ident = 1
                screen._read_pipe(*self._args)

            def join(self, *, timeout: float) -> None:
                nonlocal join_calls
                del timeout
                join_calls += 1
                raise RuntimeError("join-fault")

            def is_alive(self) -> bool:
                return False

        def factory(owner, cap, output, key, failed, cleanup_failures):
            owners.append(owner)
            return JoinFaultThread(owner, cap, output, key, failed, cleanup_failures)

        real_close = screen.os.close

        def track_close(fd: int) -> None:
            close_calls.append(fd)
            real_close(fd)

        with tempfile.TemporaryDirectory(prefix="profile11-reader-join-fault-") as directory:
            with mock.patch.object(screen, "_new_coordinator_reader_thread", side_effect=factory), mock.patch.object(screen.os, "close", side_effect=track_close):
                run = screen._launch_coordinator(Path(directory), timeout_seconds=5.0, arguments=("--probe-coordinator", "0.01"))
        self.assertEqual(run.error_code, "outer_cleanup")
        self.assertIsNone(run.payload)
        self.assertFalse(run.observation.cleanup_complete)
        self.assertEqual(join_calls, 2)
        self.assertTrue(all(owner.state == "closed" for owner in owners))
        self.assertEqual(len(close_calls), 4)
        self.assertEqual(len(set(close_calls)), 4)

    def test_launcher_final_reader_close_failure_releases_handles_and_rejects_payload(self) -> None:
        owners: list[screen._CoordinatorOwnedDescriptor] = []
        close_calls: list[int] = []
        injected = False
        handle_labels: list[str] = []

        class FinalCloseFaultThread:
            def __init__(self, owner, cap, output, key, failed, cleanup_failures) -> None:
                self._args = (owner.descriptor, cap, output, key, failed, cleanup_failures, owner)
                self.ident = None

            def start(self) -> None:
                self.ident = 1
                screen._read_pipe(*self._args)

            def join(self, *, timeout: float) -> None:
                del timeout

            def is_alive(self) -> bool:
                return False

        def factory(owner, cap, output, key, failed, cleanup_failures):
            owners.append(owner)
            return FinalCloseFaultThread(owner, cap, output, key, failed, cleanup_failures)

        real_os_close = screen.os.close
        real_handle_close = screen._close_owned_handle_once

        def track_close(fd: int) -> None:
            nonlocal injected
            close_calls.append(fd)
            if owners and fd == owners[0].descriptor and not injected:
                injected = True
                real_os_close(fd)
                raise OSError("final-reader-close-fault")
            real_os_close(fd)

        def track_handle_close(kernel32, handle, *, label, cleanup_failures) -> None:
            handle_labels.append(label)
            real_handle_close(kernel32, handle, label=label, cleanup_failures=cleanup_failures)

        with tempfile.TemporaryDirectory(prefix="profile11-reader-final-close-") as directory:
            with mock.patch.object(screen, "_new_coordinator_reader_thread", side_effect=factory), mock.patch.object(screen.os, "close", side_effect=track_close), mock.patch.object(screen, "_close_owned_handle_once", side_effect=track_handle_close):
                run = screen._launch_coordinator(Path(directory), timeout_seconds=5.0, arguments=("--probe-coordinator", "0.01"))
        self.assertEqual(run.error_code, "coordinator_output_close")
        self.assertIsNone(run.payload)
        self.assertFalse(run.observation.cleanup_complete)
        self.assertTrue(injected)
        self.assertEqual(len(close_calls), 4)
        self.assertEqual(len(set(close_calls)), 4)
        self.assertEqual(set(handle_labels), {"outer_thread_handle_close", "outer_process_handle_close", "outer_job_handle_close"})

    def test_resource_report_is_measured_but_not_qualified(self) -> None:
        effective = screen.effective_outer_cap(screen.PROCESS_TREE_PEAK_CAP_BYTES, 4096)
        payload = screen.build_test_aggregate(
            completed_samples=5,
            timings=tuple(self._timed_sample(index + 1) for index in range(5)),
            warmup=self._timed_sample(),
        )
        run = screen.CoordinatorRun(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii"),
            screen.JobObservation(103956480, screen.PROCESS_TREE_PEAK_CAP_BYTES, effective, effective, 8, 8, 5, 27, True, True, True),
            None,
        )
        report = screen._resource_report_from_run(run=run, payload=payload)
        self.assertEqual(report["schema"], screen.RESOURCE_OBSERVATION_SCHEMA)
        self.assertEqual(report["status"], "measured")
        self.assertIsNone(report["error_code"])
        self.assertEqual(report["resource_observation"]["peak_job_commit_bytes"], 103956480)
        self.assertEqual(report["resource_observation"]["total_processes"], 27)
        self.assertEqual(
            report["resource_observation"]["active_process_metric_semantics"],
            "sampled_maximum_lower_bound_not_exact_high_water_mark",
        )
        self.assertEqual(
            report["resource_observation"]["active_process_limit_semantics"],
            "os_enforced_job_object_limit",
        )
        self.assertEqual(
            report["resource_observation"]["total_process_metric_semantics"],
            "os_cumulative_total_processes",
        )
        self.assertFalse(report["complete_profile_qualification"])
        self.assertEqual(report["observer_status"], "observer_unavailable")
        self.assertEqual(report["disk_gate"], "observer_unavailable")
        self.assertFalse(report["activation"])
        self.assertIsNone(report["proofSuiteId"])

    def test_resource_report_rejects_missing_metric_and_incomplete_cleanup(self) -> None:
        effective = screen.effective_outer_cap(screen.PROCESS_TREE_PEAK_CAP_BYTES, 4096)
        payload = screen.build_test_aggregate(
            completed_samples=5,
            timings=tuple(self._timed_sample(index + 1) for index in range(5)),
            warmup=self._timed_sample(),
        )
        for observation, error_code in (
            (screen.JobObservation(0, screen.PROCESS_TREE_PEAK_CAP_BYTES, effective, effective, 8, 8, 1, 1, True, True, True), "outer_measurement_missing"),
            (screen.JobObservation(1024, screen.PROCESS_TREE_PEAK_CAP_BYTES, effective, effective, 8, 8, 1, 1, True, False, True), "outer_measurement_incomplete"),
            (screen.JobObservation(1024, screen.PROCESS_TREE_PEAK_CAP_BYTES, effective, effective, 8, 8, 1, 1, False, True, False), "outer_cleanup"),
            (screen.JobObservation(effective + 1, screen.PROCESS_TREE_PEAK_CAP_BYTES, effective, effective, 8, 8, 1, 1, True, True, True), "outer_memory_cap"),
        ):
            with self.subTest(error_code=error_code):
                report = screen._resource_report_from_run(
                    run=screen.CoordinatorRun(None, observation, None),
                    payload=payload,
                )
                self.assertEqual(report["status"], "failed")
                self.assertEqual(report["error_code"], error_code)

    def test_outer_job_timeout_terminates_and_reaps(self) -> None:
        if os.name != "nt":
            self.skipTest("Windows Job Object ABI is unavailable")
        with tempfile.TemporaryDirectory(prefix="profile11-timeout-") as directory, mock.patch.object(screen, "validate_job_observation", wraps=screen.validate_job_observation) as validator:
            run = screen._launch_coordinator(Path(directory), timeout_seconds=0.2, arguments=("--probe-coordinator", "3.0"))
        self.assertEqual(run.error_code, "outer_timeout")
        validator.assert_called_once()
        self.assertTrue(run.observation.timed_out)
        self.assertTrue(run.observation.cleanup_complete)
        self.assertTrue(run.observation.process_tree_complete)

    def test_observer_fails_closed_with_explicit_unavailable_backend(self) -> None:
        observer = screen.WindowsEtwFileWriteObserver(_Backend(capability=(False, False, False, False)))
        result = observer.probe()
        self.assertEqual(result.status, "observer_unavailable")
        with tempfile.TemporaryDirectory(prefix="profile11-observer-") as directory:
            self.assertEqual(screen.evaluate_disk_gate(result, state_workspace=Path(directory)), "observer_unavailable")

    def test_default_observer_wires_native_backend_and_maps_capability(self) -> None:
        observer = screen.WindowsEtwFileWriteObserver()
        if os.name == "nt":
            self.assertIsInstance(observer._backend, screen.WindowsEtwWriteTraceBackend)
        ready = screen.WindowsEtwFileWriteObserver(_Backend(capability=(True, True, True, True)))
        unavailable = screen.WindowsEtwFileWriteObserver(_Backend(capability=(True, True, True, False)))
        with mock.patch.object(screen, "os", types.SimpleNamespace(name="nt")):
            self.assertEqual(ready.probe().status, "observer_ready")
            self.assertEqual(unavailable.probe().status, "observer_unavailable")
        with mock.patch.object(screen, "os", types.SimpleNamespace(name="posix")):
            self.assertEqual(ready.probe().status, "observer_unavailable")

    def test_native_etw_schema_and_abi_gate_is_exact(self) -> None:
        facts = self._schema_facts()
        self.assertTrue(screen._etw_schema_facts_complete(facts))
        self.assertEqual(len(facts), len(screen._ETW_SCHEMA_KEYS))
        self.assertEqual(screen._ETW_FILE_TASK_OPERATIONS[16], "write")
        self.assertEqual(screen._ETW_FILE_TASK_OPERATIONS[19], "rename")
        self.assertEqual(screen._ETW_FILE_TASK_OPERATIONS[26], "delete")
        self.assertEqual(screen._ETW_FILE_TASK_OPERATIONS[29], "link")
        for index, bad in (
            (0, screen._EtwSchemaFact(facts[0].provider, facts[0].event_id, facts[0].version, facts[0].task + 1, facts[0].opcode, facts[0].properties)),
            (1, screen._EtwSchemaFact(facts[1].provider, facts[1].event_id, facts[1].version, facts[1].task, facts[1].opcode, facts[1].properties + (("Unknown", screen._U32),))),
            (2, screen._EtwSchemaFact(facts[2].provider, facts[2].event_id, facts[2].version, facts[2].task, facts[2].opcode, ((facts[2].properties[0][0], screen._U32),) + facts[2].properties[1:])),
        ):
            with self.subTest(index=index):
                invalid = facts[:index] + (bad,) + facts[index + 1:]
                self.assertFalse(screen._etw_schema_facts_complete(invalid))
        self.assertFalse(screen._etw_schema_facts_complete(facts[:-1]))
        self.assertFalse(screen._etw_schema_facts_complete(facts + (facts[0],)))
        unknown = screen._EtwSchemaFact(b"unknown-provider", 999, 0, 999, 0, ())
        self.assertFalse(screen._etw_schema_fact_matches(unknown))
        if ctypes.sizeof(ctypes.c_void_p) == 8:
            self.assertEqual(ctypes.sizeof(screen._EtwEventTraceProperties), 120)
            self.assertEqual(ctypes.sizeof(screen._EtwEventRecord), 112)
            self.assertEqual(ctypes.sizeof(screen._EtwTraceLogfileHeader), 280)
            self.assertEqual(ctypes.sizeof(screen._EtwEventTraceLogfileW), 448)
        backend = screen.WindowsEtwWriteTraceBackend(schema_facts=facts)
        capability = backend.capability()
        if os.name == "nt":
            self.assertTrue(capability[0])
        else:
            self.assertFalse(capability[0])
        invalid_backend = screen.WindowsEtwWriteTraceBackend(schema_facts=facts[:-1])
        self.assertFalse(invalid_backend.capability()[0])

    def test_installed_tdh_schema_matches_every_allowlisted_descriptor(self) -> None:
        if os.name != "nt":
            self.skipTest("Windows TDH is unavailable")
        api = screen._EtwWindowsApi()
        facts = []
        for provider, table in (
            (screen._ETW_KERNEL_FILE_PROVIDER_GUID, screen._ETW_FILE_SCHEMA_PROPERTIES),
            (screen._ETW_KERNEL_PROCESS_PROVIDER_GUID, screen._ETW_PROCESS_SCHEMA_PROPERTIES),
        ):
            for event_id, version in sorted(table):
                spec = screen._ETW_SCHEMA_BY_PROVIDER_ID[(provider, event_id)]
                record = screen._EtwEventRecord()
                record.EventHeader.ProviderId = screen._EtwGuid.from_buffer_copy(provider)
                record.EventHeader.EventDescriptor = screen._EtwEventDescriptor(event_id, version, 16, 4, spec.opcode, spec.task, 0)
                facts.append(api.event_schema(record))
        self.assertEqual(len(facts), 54)
        self.assertTrue(screen._etw_schema_facts_complete(facts))

    def test_native_etw_realtime_session_has_no_logfile(self) -> None:
        backend = screen.WindowsEtwWriteTraceBackend()
        name = "BLProfile11Etw-self-test"
        storage, properties = backend._properties_for_session(name, uuid.uuid4())
        self.assertEqual(properties.contents.LogFileNameOffset, 0)
        self.assertEqual(properties.contents.LoggerNameOffset, ctypes.sizeof(screen._EtwEventTraceProperties))
        self.assertTrue(properties.contents.LogFileMode & screen._ETW_EVENT_TRACE_REAL_TIME_MODE)
        self.assertTrue(properties.contents.LogFileMode & screen._ETW_EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING)
        self.assertEqual(properties.contents.Wnode.Flags, screen._ETW_WNODE_FLAG_TRACED_GUID)
        self.assertEqual(
            ctypes.wstring_at(ctypes.addressof(storage) + properties.contents.LoggerNameOffset),
            name,
        )

    def test_etw_trace_state_requires_causal_lineage_and_generation(self) -> None:
        state = screen._EtwTraceState(100, 123)
        state.record_process(event_id=1, pid=100, key=1000, parent_pid=1, create_time=123)
        state.record_process(event_id=1, pid=101, key=1001, parent_pid=100, create_time=124)
        state.record_process(event_id=1, pid=102, key=1002, parent_pid=101, create_time=125)
        state.record_file(pid=101, key=1001, path=Path(r"C:\state\state.sqlite"), operation="write")
        state.record_process(event_id=2, pid=102, key=1002, parent_pid=101, create_time=125)
        state.record_process(event_id=2, pid=101, key=1001, parent_pid=100, create_time=124)
        state.record_process(event_id=2, pid=100, key=1000, parent_pid=1, create_time=123)
        self.assertTrue(state.complete_lineage())
        self.assertEqual(len(state.events), 1)
        self.assertTrue(state.root_observed.is_set())

        reused = screen._EtwTraceState(100, 123)
        reused.record_process(event_id=1, pid=100, key=1000, parent_pid=1, create_time=123)
        reused.record_process(event_id=1, pid=101, key=1001, parent_pid=100, create_time=124)
        reused.record_process(event_id=2, pid=101, key=1001, parent_pid=100, create_time=124)
        reused.record_process(event_id=1, pid=101, key=2001, parent_pid=100, create_time=124)
        reused.record_file(pid=101, key=1001, path=Path(r"C:\state\proof.bin"), operation="write")
        self.assertTrue(reused.malformed)
        self.assertFalse(reused.complete_lineage())

    def test_etw_trace_state_rejects_missing_termination_and_bad_paths(self) -> None:
        state = screen._EtwTraceState(100, 123)
        state.record_process(event_id=1, pid=100, key=1000, parent_pid=1, create_time=123)
        state.record_process(event_id=1, pid=101, key=1001, parent_pid=100, create_time=124)
        state.record_file(pid=101, key=1001, path=Path(r"relative.tmp"), operation="write")
        self.assertTrue(state.malformed)
        self.assertFalse(state.complete_lineage())

        missing_stop = screen._EtwTraceState(100, 123)
        missing_stop.record_process(event_id=1, pid=100, key=1000, parent_pid=1, create_time=123)
        missing_stop.record_process(event_id=1, pid=101, key=1001, parent_pid=100, create_time=124)
        missing_stop.record_process(event_id=2, pid=100, key=1000, parent_pid=1, create_time=123)
        self.assertFalse(missing_stop.complete_lineage())

        wrong_root_time = screen._EtwTraceState(100, 123)
        wrong_root_time.record_process(event_id=1, pid=100, key=1000, parent_pid=1, create_time=124)
        self.assertTrue(wrong_root_time.malformed)
        unrelated_parent = screen._EtwTraceState(100, 123)
        unrelated_parent.record_process(event_id=1, pid=100, key=1000, parent_pid=1, create_time=123)
        unrelated_parent.record_process(event_id=1, pid=101, key=1001, parent_pid=999, create_time=124)
        self.assertFalse(unrelated_parent.malformed)
        self.assertNotIn(101, unrelated_parent._active)

    def test_etw_device_path_mapping_fails_closed_for_unknown_devices(self) -> None:
        self.assertEqual(
            screen._etw_path_from_provider(r"\Device\HarddiskVolume3\state.sqlite", ((r"\Device\HarddiskVolume3", "C:"),)),
            Path(r"C:\state.sqlite"),
        )
        with self.assertRaises(screen._EtwMalformedEvent):
            screen._etw_path_from_provider(r"\Device\UnknownVolume\state.sqlite", ())
        with self.assertRaises(screen._EtwMalformedEvent):
            screen._etw_path_from_provider(r"relative\state.sqlite", ())

    def test_file_event_id_allowlist_and_pair_correlation_are_fail_closed(self) -> None:
        self.assertEqual(
            screen._ETW_FILE_NONMUTATION_IDS,
            frozenset({10, 11, 12, 13, 14, 15, 20, 22, 24, 25, 32, 34}),
        )
        self.assertEqual(
            screen._ETW_FILE_MUTATION_IDS,
            frozenset({16, 17, 18, 19, 21, 23, 26, 27, 28, 29, 30, 31, 33}),
        )
        self.assertEqual(screen._ETW_FILE_TASK_OPERATIONS[29], "link")
        state = screen._EtwTraceState(100, 123)
        state.record_process(event_id=1, pid=100, key=1000, parent_pid=1, create_time=123)
        source = Path(r"C:\state\source.sqlite")
        target = Path(r"C:\state\target.sqlite")
        state.update_file_correlation(file_object=7, file_key=8, path=source)
        state.record_paired_mutation(pid=100, key=1000, irp=9, operation="link", source_path=source, target_path=None)
        self.assertEqual(state.events, [])
        self.assertFalse(state.complete_lineage())
        state.record_paired_mutation(pid=100, key=1000, irp=9, operation="link", source_path=None, target_path=target)
        self.assertEqual(len(state.events), 1)
        self.assertEqual(state.events[0].operation, "link")
        self.assertEqual(state.events[0].source_path, source)
        self.assertEqual(state.events[0].target_path, target)
        state.record_paired_mutation(pid=100, key=1000, irp=9, operation="link", source_path=source, target_path=target)
        self.assertTrue(state.malformed)
        conflict = screen._EtwTraceState(100, 123)
        conflict.record_process(event_id=1, pid=100, key=1000, parent_pid=1, create_time=123)
        conflict.update_file_correlation(file_object=7, file_key=8, path=source)
        conflict.update_file_correlation(file_object=7, file_key=8, path=target)
        self.assertTrue(conflict.malformed)

    def test_event_id_first_dispatch_does_not_relabel_set_link(self) -> None:
        backend = screen.WindowsEtwWriteTraceBackend()
        backend._state = screen._EtwTraceState(100, 123)
        record = screen._EtwEventRecord()
        record.EventHeader.ProviderId = screen._EtwGuid.from_buffer_copy(screen._ETW_KERNEL_FILE_PROVIDER_GUID)
        record.EventHeader.EventDescriptor = screen._EtwEventDescriptor(29, 0, 16, 4, 0, 19, 0)
        with mock.patch.object(screen.WindowsEtwWriteTraceBackend, "_validate_record_schema", autospec=True, return_value=screen._ETW_SCHEMA_BY_PROVIDER_ID[(screen._ETW_KERNEL_FILE_PROVIDER_GUID, 29)]) as validate, mock.patch.object(screen.WindowsEtwWriteTraceBackend, "_on_file_event", autospec=True) as dispatch:
            backend._on_event(ctypes.pointer(record))
        validate.assert_called_once_with(backend, mock.ANY, screen._ETW_KERNEL_FILE_PROVIDER_GUID)
        dispatch.assert_called_once_with(backend, mock.ANY, 29)

    def test_capture_state_uses_process_start_key_and_waits_for_root_marker(self) -> None:
        backend = screen.WindowsEtwWriteTraceBackend()
        calls: list[tuple[int, int]] = []
        api = mock.Mock()
        api.advapi32.EnableTraceEx2.return_value = 0
        backend._api = api
        backend._session_id = 7
        backend._capture_process_state()
        args = api.advapi32.EnableTraceEx2.call_args.args
        calls.append((args[2], args[3]))
        self.assertEqual(calls, [(screen._ETW_EVENT_CONTROL_CAPTURE_STATE, screen._ETW_TRACE_LEVEL_VERBOSE)])
        parameters = ctypes.cast(args[7], ctypes.POINTER(screen._EtwEnableTraceParameters)).contents
        self.assertEqual(parameters.EnableProperty, screen._ETW_ENABLE_PROPERTY_PROCESS_START_KEY)

    def test_screen_does_not_launch_with_explicit_unavailable_observer(self) -> None:
        observer = screen.WindowsEtwFileWriteObserver(_Backend(capability=(False, False, False, False)))
        with mock.patch.object(screen, "_launch_coordinator", side_effect=AssertionError("screen launch must be gated")):
            result = screen.run_falsification_screen(observer=observer)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error_code"], "observer_unavailable")
        self.assertEqual(result["completed_samples"], 0)
        self.assertEqual(result["observer_status"], "observer_unavailable")
        self.assertEqual(result["disk_gate"], "observer_unavailable")

    def test_main_screen_failure_returns_nonzero_and_preserves_json(self) -> None:
        failed = screen.build_test_aggregate(completed_samples=0, error_code="observer_unavailable")
        output = io.StringIO()
        with mock.patch.object(screen, "run_falsification_screen", return_value=failed) as run_screen, redirect_stdout(output):
            code = screen.main(["--screen"])
        self.assertEqual(code, 1)
        run_screen.assert_called_once_with()
        self.assertEqual(json.loads(output.getvalue()), failed)

    def test_main_screen_complete_aggregate_returns_zero(self) -> None:
        warmup = self._timed_sample()
        timings = tuple(self._timed_sample(index + 1) for index in range(5))
        complete = screen.build_test_aggregate(completed_samples=5, timings=timings, warmup=warmup, observer_status="observer_ready", disk_gate="disk_gate_pass")
        output = io.StringIO()
        with mock.patch.object(screen, "run_falsification_screen", return_value=complete) as run_screen, redirect_stdout(output):
            code = screen.main(["--screen"])
        self.assertEqual(code, 0)
        run_screen.assert_called_once_with()
        self.assertEqual(json.loads(output.getvalue()), complete)

    def test_observer_capability_loss_and_lineage_fail_closed(self) -> None:
        observer = screen.WindowsEtwFileWriteObserver(_Backend(capability=(True, True, True, False)))
        self.assertEqual(observer.probe().status, "observer_unavailable")
        with tempfile.TemporaryDirectory(prefix="profile11-observer-") as directory:
            root = Path(directory)
            result = screen.FileWriteObservation("observer_ready", True, True, True, True)
            self.assertEqual(screen.evaluate_disk_gate(result, state_workspace=root), "observer_incomplete")
            result = screen.FileWriteObservation("observer_ready", True, True, False, False)
            self.assertEqual(screen.evaluate_disk_gate(result, state_workspace=root), "observer_incomplete")

    def test_disk_allowlist_allows_configured_state_durability_only(self) -> None:
        with tempfile.TemporaryDirectory(prefix="profile11-disk-") as directory:
            root = Path(directory)
            self.assertEqual(self._create_state_database(root), "delete")
            events = tuple(screen.FileWriteEvent(path, op, 100 + index, True, 1) for index, (path, op) in enumerate((
                (root / "state.sqlite", "write"),
                (root / "state.sqlite-journal", "create"),
                (root / "state.sqlite-journal", "delete"),
                (root / "state.sqlite.runtime-lock", "write"),
                (root / "state.sqlite", "metadata"),
                (root / "state.sqlite", "flush"),
                (root / "state.sqlite", "fsctl"),
                (root, "metadata"),
                (root, "directory_metadata"),
            )))
            ready = screen.FileWriteObservation("observer_ready", True, True, True, False, events)
            self.assertEqual(screen.evaluate_disk_gate(ready, state_workspace=root), "disk_gate_pass")
            forbidden = screen.FileWriteObservation("observer_ready", True, True, True, False, (screen.FileWriteEvent(root / "deleted-proof.tmp", "delete", 101, True, 1),))
            self.assertEqual(screen.evaluate_disk_gate(forbidden, state_workspace=root), "unauthorized_write")
            nonconfigured = screen.FileWriteObservation("observer_ready", True, True, True, False, (screen.FileWriteEvent(root / "state.sqlite-wal", "write", 101, True, 1),))
            self.assertEqual(screen.evaluate_disk_gate(nonconfigured, state_workspace=root), "unauthorized_write")
            for filename in (
                "proof.bin", "signature.bin", "frame.bin", "statement.bin", "digest.bin", "phi.bin",
                "temp.tmp", "spill.bin", "stdout.log", "stderr.log", "crash.dmp", "core",
            ):
                for operation in ("create", "write", "delete", "rename", "link", "metadata", "flush", "fsctl"):
                    with self.subTest(filename=filename, operation=operation):
                        path = root / filename
                        source_path = root / "state.sqlite" if operation in {"rename", "link"} else None
                        target_path = path if operation in {"rename", "link"} else None
                        event = screen.FileWriteEvent(path, operation, 101, True, 1, source_path, target_path)
                        self.assertEqual(
                            screen.evaluate_disk_gate(screen.FileWriteObservation("observer_ready", True, True, True, False, (event,)), state_workspace=root),
                            "unauthorized_write",
                        )

    def test_disk_allowlist_is_mode_aware_and_live_mode_is_bound(self) -> None:
        with tempfile.TemporaryDirectory(prefix="profile11-durability-") as directory:
            root = Path(directory)
            self.assertEqual(
                screen.configured_state_allowlist(root, journal_mode="delete"),
                frozenset((root.resolve() / "state.sqlite", root.resolve() / "state.sqlite-journal", root.resolve() / "state.sqlite.runtime-lock")),
            )
            self.assertEqual(
                screen.configured_state_allowlist(root, journal_mode="wal"),
                frozenset((root.resolve() / "state.sqlite", root.resolve() / "state.sqlite-wal", root.resolve() / "state.sqlite-shm", root.resolve() / "state.sqlite.runtime-lock")),
            )
            delete_events = tuple(screen.FileWriteEvent(root / name, "write", 100 + index, True, 1) for index, name in enumerate(("state.sqlite", "state.sqlite-journal", "state.sqlite.runtime-lock")))
            ready = screen.FileWriteObservation("observer_ready", True, True, True, False, delete_events)
            self.assertEqual(self._create_state_database(root, "delete"), "delete")
            self.assertEqual(screen.evaluate_disk_gate(ready, state_workspace=root), "disk_gate_pass")
            wal_events = tuple(screen.FileWriteEvent(root / name, "write", 200 + index, True, 1) for index, name in enumerate(("state.sqlite", "state.sqlite-wal", "state.sqlite-shm", "state.sqlite.runtime-lock")))
            wal_ready = screen.FileWriteObservation("observer_ready", True, True, True, False, wal_events)
            self.assertEqual(screen._evaluate_disk_gate_for_mode(wal_ready, state_workspace=root, journal_mode="wal"), "disk_gate_pass")
            self.assertEqual(screen._evaluate_disk_gate_for_mode(wal_ready, state_workspace=root, journal_mode="delete"), "unauthorized_write")
            self.assertEqual(self._create_state_database(root, "wal"), "wal")
            self.assertEqual(screen.evaluate_disk_gate(wal_ready, state_workspace=root), "state_durability_configuration")
            self.assertEqual(screen._evaluate_disk_gate_for_mode(ready, state_workspace=root, journal_mode="wal"), "unauthorized_write")
            outside = root.parent / "profile11-cross-directory-proof.tmp"
            cross_directory = screen.FileWriteObservation("observer_ready", True, True, True, False, (screen.FileWriteEvent(outside, "delete", 301, True, 1),))
            self.assertEqual(screen._evaluate_disk_gate_for_mode(cross_directory, state_workspace=root, journal_mode="delete"), "unauthorized_write")

    def test_observer_backend_stop_loss_becomes_incomplete(self) -> None:
        backend = _Backend(result=screen.FileWriteObservation("observer_ready", True, True, True, True))
        observer = screen.WindowsEtwFileWriteObserver(backend)
        with tempfile.TemporaryDirectory(prefix="profile11-observer-") as directory:
            started = observer.start(1234)
            self.assertEqual(started.status, "observer_ready")
            self.assertEqual(backend.started_with, 1234)
            stopped = observer.stop()
            self.assertEqual(stopped.status, "observer_incomplete")

    def test_measurement_schedule_is_one_warmup_and_five_measured(self) -> None:
        calls = 0
        def sample() -> screen.StageSample:
            nonlocal calls
            calls += 1
            return screen.StageSample(float(calls), float(calls + 1), float(calls + 2), float(calls + 3))
        schedule = screen.run_measurement_schedule_with_warmup(sample)
        self.assertEqual(calls, 6)
        self.assertEqual(schedule.warmup, screen.StageSample(1.0, 2.0, 3.0, 4.0))
        values = schedule.measured
        self.assertEqual(len(values), 5)
        p95 = screen.nearest_rank_p95(values)
        self.assertEqual(p95, screen.StageSample(6.0, 7.0, 8.0, 9.0))

    def test_measurement_schedule_does_not_silently_skip(self) -> None:
        calls = 0
        def sample():
            nonlocal calls
            calls += 1
            return None if calls == 4 else screen.StageSample(1.0, 1.0, 1.0, 1.0)
        with self.assertRaisesRegex(screen.CompletePathError, "sample_shape"):
            screen.run_measurement_schedule(sample)
        self.assertEqual(calls, 4)

    def test_complete_aggregate_enforces_p95_target_and_preserves_partial_failure(self) -> None:
        def sample_with_total(total_ms: float) -> screen.StageSample:
            return screen.StageSample(1.0, 2.0, 1.0, total_ms, screen.VerifyStateBreakdown(2.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0), total_ms - 4.0)

        for total_ms, expected_status, expected_error in (
            (screen.PRODUCT_TARGET_MS - 0.001, "complete", None),
            (screen.PRODUCT_TARGET_MS, "complete", None),
            (screen.PRODUCT_TARGET_MS + 0.001, "failed", "product_target_exceeded"),
        ):
            with self.subTest(total_ms=total_ms):
                value = screen.build_test_aggregate(
                    completed_samples=5,
                    timings=tuple(sample_with_total(total_ms) for _ in range(5)),
                    warmup=sample_with_total(4.0),
                    observer_status="observer_ready",
                    disk_gate="disk_gate_pass",
                )
                self.assertEqual(value["status"], expected_status)
                self.assertEqual(value["error_code"], expected_error)
                self.assertEqual(value["p95_timings_ms"]["total"], total_ms)

        sub_millisecond_overrun = screen.PRODUCT_TARGET_MS + 0.0001
        precise = screen.build_test_aggregate(
            completed_samples=5,
            timings=tuple(sample_with_total(sub_millisecond_overrun) for _ in range(5)),
            warmup=sample_with_total(4.0),
        )
        self.assertEqual(precise["status"], "failed")
        self.assertEqual(precise["error_code"], "product_target_exceeded")
        self.assertEqual(precise["p95_timings_ms"]["total"], sub_millisecond_overrun)
        screen._validate_aggregate_mapping(precise)

        explicit_failure = screen.build_test_aggregate(
            completed_samples=5,
            timings=tuple(sample_with_total(sub_millisecond_overrun) for _ in range(5)),
            warmup=sample_with_total(4.0),
            error_code="unauthorized_write",
        )
        self.assertEqual(explicit_failure["status"], "failed")
        self.assertEqual(explicit_failure["error_code"], "unauthorized_write")
        self.assertEqual(explicit_failure["p95_timings_ms"]["total"], sub_millisecond_overrun)
        screen._validate_aggregate_mapping(explicit_failure)

        partial = screen.build_test_aggregate(
            completed_samples=2,
            timings=tuple(self._timed_sample(index + 1) for index in range(2)),
            warmup=self._timed_sample(),
            error_code="coordinator_failure",
        )
        self.assertEqual(partial["status"], "failed")
        self.assertEqual(partial["completed_samples"], 2)
        self.assertEqual(len(partial["stage_timings_ms"]), 2)
        self.assertIsNone(partial["p95_timings_ms"])
        screen._validate_aggregate_mapping(partial)

    def test_outer_observer_failure_preserves_timing_overrun_evidence(self) -> None:
        def sample_with_total(total_ms: float) -> screen.StageSample:
            return screen.StageSample(1.0, 2.0, 1.0, total_ms, screen.VerifyStateBreakdown(2.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0), total_ms - 4.0)

        overrun = screen.PRODUCT_TARGET_MS + 0.0001
        aggregate = screen.build_test_aggregate(
            completed_samples=5,
            timings=tuple(sample_with_total(overrun) for _ in range(5)),
            warmup=sample_with_total(4.0),
        )
        payload = json.dumps(aggregate, sort_keys=True, separators=(",", ":")).encode("ascii")
        run = screen.CoordinatorRun(
            payload,
            screen.JobObservation(1024, screen.PROCESS_TREE_PEAK_CAP_BYTES, screen.PROCESS_TREE_PEAK_CAP_BYTES, screen.PROCESS_TREE_PEAK_CAP_BYTES, 8, 8, 1, 1, True, True, True),
            None,
        )
        observer = screen.WindowsEtwFileWriteObserver(_Backend(result=screen.FileWriteObservation("observer_ready", True, True, True, False)))
        with mock.patch.object(screen, "validate_dependencies", return_value=screen.DependencyReport((), ())), mock.patch.object(screen, "_launch_coordinator", return_value=run), mock.patch.object(screen, "evaluate_disk_gate", return_value="unauthorized_write"):
            result = screen.run_falsification_screen(observer=observer)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error_code"], "unauthorized_write")
        self.assertEqual(result["p95_timings_ms"]["total"], overrun)
        screen._validate_aggregate_mapping(result)

    def test_aggregate_rejects_missing_rows_and_status_inconsistency(self) -> None:
        complete = screen.build_test_aggregate(
            completed_samples=5,
            timings=tuple(self._timed_sample(index + 1) for index in range(5)),
            warmup=self._timed_sample(),
            observer_status="observer_ready",
            disk_gate="disk_gate_pass",
        )
        complete["stage_timings_ms"] = []
        complete["verify_state_substages_ms"] = []
        complete["total_unbucketed_ms"] = []
        with self.assertRaisesRegex(screen.CompletePathError, "aggregate_timing"):
            screen._validate_aggregate_mapping(complete)

        failed = screen.build_test_aggregate(completed_samples=0, error_code="observer_unavailable")
        failed["status"] = "complete"
        with self.assertRaisesRegex(screen.CompletePathError, "aggregate_status"):
            screen._validate_aggregate_mapping(failed)
        failed["status"] = "failed"
        failed["error_code"] = None
        with self.assertRaisesRegex(screen.CompletePathError, "aggregate_status"):
            screen._validate_aggregate_mapping(failed)

        below_target = screen.build_test_aggregate(
            completed_samples=5,
            timings=tuple(self._timed_sample(index + 1) for index in range(5)),
            warmup=self._timed_sample(),
        )
        below_target["status"] = "failed"
        below_target["error_code"] = "product_target_exceeded"
        with self.assertRaisesRegex(screen.CompletePathError, "aggregate_status"):
            screen._validate_aggregate_mapping(below_target)

        process_mismatch = screen.build_test_aggregate(error_code="coordinator_failure")
        process_mismatch["error_code"] = "outer_process_limit"
        with self.assertRaisesRegex(screen.CompletePathError, "aggregate_status"):
            screen._validate_aggregate_mapping(process_mismatch)

    def test_aggregate_is_zero_phi_and_nonactivating(self) -> None:
        warmup = self._timed_sample()
        timings = tuple(self._timed_sample(index + 1) for index in range(5))
        value = screen.build_test_aggregate(completed_samples=5, timings=timings, warmup=warmup, peak_job_commit_bytes=1024, effective_cap_bytes=screen.effective_outer_cap(screen.PROCESS_TREE_PEAK_CAP_BYTES, 4096), peak_active_processes=2, total_processes=7)
        encoded = screen._aggregate_json(value)
        self.assertNotIn("statement", encoded.lower())
        self.assertNotIn("operation_ref", encoded.lower())
        self.assertNotIn("stdout", encoded.lower())
        self.assertIsNone(value["proofSuiteId"])
        self.assertFalse(value["production_usable"])
        self.assertFalse(value["activation"])
        self.assertEqual(value["proof_count"], 1)
        self.assertEqual(value["operation_count"], 100)
        self.assertEqual(value["warmup_count"], 1)
        self.assertEqual(len(value["verify_state_substages_ms"]), 5)
        self.assertEqual(value["p95_verify_state_substages_ms"]["handoff"], 6.0)

    def test_verifier_timing_wrapper_restores_and_records_inclusive_scope(self) -> None:
        timing = screen._VerifierTiming()
        with mock.patch.object(source_auth_adapter, "_read_exact_frame", lambda *args, **kwargs: bytearray(b"frame")), mock.patch.object(source_auth_adapter, "_build_ipc_input", lambda *args, **kwargs: bytearray(b"ipc")), mock.patch.object(source_auth_adapter, "run_contained_verifier_stream", lambda *args, **kwargs: "result"):
            patched_read = source_auth_adapter._read_exact_frame
            with screen._timed_verifier_functions(timing):
                self.assertEqual(source_auth_adapter._read_exact_frame(None), bytearray(b"frame"))
                self.assertEqual(source_auth_adapter._build_ipc_input(None), bytearray(b"ipc"))
                self.assertEqual(source_auth_adapter.run_contained_verifier_stream(None), "result")
            self.assertIs(source_auth_adapter._read_exact_frame, patched_read)
        self.assertIsNotNone(timing.verifier_finished_at)
        self.assertGreaterEqual(timing.frame_read_ms, 0.0)
        self.assertGreaterEqual(timing.ipc_prepare_ms, 0.0)
        self.assertGreaterEqual(timing.contained_verifier_ms, 0.0)

    def test_aggregate_rejects_unreconciled_timing(self) -> None:
        value = screen.build_test_aggregate(completed_samples=5, timings=tuple(self._timed_sample(index + 1) for index in range(5)), warmup=self._timed_sample())
        value["verify_state_substages_ms"][0]["unbucketed"] += 1.0
        with self.assertRaisesRegex(screen.CompletePathError, "aggregate_timing_reconciliation"):
            screen._validate_aggregate_mapping(value)
        value = screen.build_test_aggregate(completed_samples=5, timings=tuple(self._timed_sample(index + 1) for index in range(5)), warmup=self._timed_sample())
        value["p95_timings_ms"]["total"] += 1.0
        with self.assertRaisesRegex(screen.CompletePathError, "aggregate_p95"):
            screen._validate_aggregate_mapping(value)

    def test_aggregate_rejects_sensitive_or_wrong_shape_fields(self) -> None:
        value = screen.build_test_aggregate(error_code="observer_unavailable")
        value["unexpected"] = 1
        with self.assertRaisesRegex(screen.CompletePathError, "aggregate_fields"):
            screen._validate_aggregate_mapping(value)
        value = screen.build_test_aggregate(error_code="observer_unavailable")
        value["proof_count"] = 2
        with self.assertRaisesRegex(screen.CompletePathError, "topology_mismatch"):
            screen._validate_aggregate_mapping(value)


if __name__ == "__main__":
    unittest.main()
