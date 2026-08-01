from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from tools import profile_cairo_execution as profiler


_GATE_KEYS = {
    "BL_ENV",
    "BL_DEV",
    profiler.SYNTHETIC_PROFILER_ENABLE_ENV,
}
_ALLOWED_FLAGS = {
    "BL_ENV": "test",
    "BL_DEV": "1",
    profiler.SYNTHETIC_PROFILER_ENABLE_ENV: "1",
}


class CairoExecutionProfilerTests(unittest.TestCase):
    def _invoke(
        self, argv: list[str], environment: dict[str, str]
    ) -> tuple[int, str, str]:
        isolated_environment = {
            key: value for key, value in os.environ.items() if key not in _GATE_KEYS
        }
        isolated_environment.update(environment)
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.dict(os.environ, isolated_environment, clear=True),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            result = profiler.main(argv)
        return result, stdout.getvalue(), stderr.getvalue()

    def test_gate_accepts_only_explicit_local_or_test_with_both_opt_ins(self) -> None:
        for environment in ("local", "test"):
            with self.subTest(environment=environment):
                flags = {**_ALLOWED_FLAGS, "BL_ENV": environment}
                isolated_environment = {
                    key: value for key, value in os.environ.items() if key not in _GATE_KEYS
                }
                isolated_environment.update(flags)
                with mock.patch.dict(os.environ, isolated_environment, clear=True):
                    self.assertTrue(profiler._synthetic_profiler_enabled())

    def test_blank_staging_and_production_environments_fail_closed(self) -> None:
        cases = {
            "blank": {},
            "staging": {**_ALLOWED_FLAGS, "BL_ENV": "staging"},
            "prod": {**_ALLOWED_FLAGS, "BL_ENV": "prod"},
            "production": {**_ALLOWED_FLAGS, "BL_ENV": "production"},
        }
        for label, environment in cases.items():
            with self.subTest(label=label):
                with mock.patch.object(profiler, "_profile_synthetic_fixture") as run:
                    result, stdout, stderr = self._invoke([], environment)
                self.assertEqual(result, 2)
                self.assertEqual(stdout, "")
                self.assertIn("requires an explicit local/test environment", stderr)
                run.assert_not_called()

    def test_missing_or_malformed_opt_in_flags_fail_closed(self) -> None:
        cases = (
            {"BL_ENV": "test", "BL_DEV": "1"},
            {
                "BL_ENV": "test",
                profiler.SYNTHETIC_PROFILER_ENABLE_ENV: "1",
            },
            {
                "BL_ENV": "test",
                "BL_DEV": "true",
                profiler.SYNTHETIC_PROFILER_ENABLE_ENV: "1",
            },
            {
                "BL_ENV": "test",
                "BL_DEV": "1",
                profiler.SYNTHETIC_PROFILER_ENABLE_ENV: "true",
            },
        )
        for environment in cases:
            with self.subTest(environment=environment):
                with mock.patch.object(profiler, "_profile_synthetic_fixture") as run:
                    result, _, _ = self._invoke([], environment)
                self.assertEqual(result, 2)
                run.assert_not_called()

    def test_arbitrary_caller_paths_and_inputs_are_rejected_without_echo(self) -> None:
        secret_path = r"C:\synthetic-private\fixture-0001.json"
        cases = (
            ["--arguments-file", secret_path],
            ["--output-profile", secret_path],
            ["--scarb", secret_path],
            [secret_path],
        )
        for argv in cases:
            with self.subTest(argv=argv):
                with mock.patch.object(profiler, "_profile_synthetic_fixture") as run:
                    result, stdout, stderr = self._invoke(argv, _ALLOWED_FLAGS)
                combined = stdout + stderr
                self.assertEqual(result, 2)
                self.assertIn("caller-supplied paths and profiling inputs are forbidden", stderr)
                self.assertNotIn(secret_path, combined)
                self.assertNotIn("fixture-0001", combined.lower())
                run.assert_not_called()

    def test_hash_pinned_internal_fixture_builds_one_canonical_claim(self) -> None:
        fixture_bytes = b"BLIND-LEDGER-INTERNAL-SYNTHETIC-FIXTURE"
        fixture_hash = hashlib.sha256(fixture_bytes).hexdigest()
        bundle = {
            "entrypoint": "blind_ledger_cairo_adjudication::batch_main",
            "metadata": {"claim_count": 1},
            "serialized_arguments_hex_json": ["0x0", "0x1", "0xabc"],
        }
        with tempfile.TemporaryDirectory() as temporary:
            fixture_path = Path(temporary) / "synthetic.json"
            fixture_path.write_bytes(fixture_bytes)
            with (
                mock.patch.object(profiler, "SYNTHETIC_SAMPLE", fixture_path),
                mock.patch.object(profiler, "SYNTHETIC_SAMPLE_SHA256", fixture_hash),
                mock.patch.object(
                    profiler, "_load_synthetic_bundle", return_value=bundle
                ) as load,
            ):
                arguments = profiler._build_synthetic_arguments()
        self.assertEqual(arguments, ["0x0", "0x1", "0xabc"])
        load.assert_called_once_with()

    def test_fixture_generation_scrubs_and_restores_all_bl_environment_data(self) -> None:
        original = {
            "BL_ENV": "local",
            "BL_DEV": "1",
            profiler.SYNTHETIC_PROFILER_ENABLE_ENV: "1",
            "BL_DUPLICATE_CHECK_PEPPER": "REAL_DUPLICATE_SECRET",
            "BL_NULLIFIER_PRF_SECRET": "REAL_NULLIFIER_SECRET",
            "BL_ORACLE_PUBLIC_KEY_SPHINCS_B64": "REAL_ORACLE_KEY",
            "BL_UNRELATED_PRIVATE_SETTING": "REAL_UNRELATED_SECRET",
            "BLIND_LEDGER_POSEIDON_TARGET_DIR": r"C:\private\poseidon",
            "CARGO_TARGET_DIR": r"C:\private\cargo",
        }
        isolated_environment = {
            key: value for key, value in os.environ.items() if not key.startswith("BL_")
        }
        isolated_environment.update(original)
        with mock.patch.dict(os.environ, isolated_environment, clear=True):
            with profiler._synthetic_generation_environment():
                self.assertEqual(os.environ["BL_ENV"], "test")
                self.assertEqual(os.environ["BL_DEV"], "1")
                self.assertEqual(os.environ["BL_FORCE_PYTHON_RULES_ENGINE"], "1")
                self.assertEqual(
                    os.environ["BL_ALLOW_LOCAL_TEST_ORACLE_KEYS"], "1"
                )
                for secret in (
                    "BL_DUPLICATE_CHECK_PEPPER",
                    "BL_NULLIFIER_PRF_SECRET",
                    "BL_ORACLE_PUBLIC_KEY_SPHINCS_B64",
                    "BL_UNRELATED_PRIVATE_SETTING",
                    "BLIND_LEDGER_POSEIDON_TARGET_DIR",
                    "CARGO_TARGET_DIR",
                    profiler.SYNTHETIC_PROFILER_ENABLE_ENV,
                ):
                    self.assertNotIn(secret, os.environ)
                os.environ["BL_GENERATOR_TEMPORARY_VALUE"] = "temporary"

            for key, value in original.items():
                self.assertEqual(os.environ[key], value)
            self.assertNotIn("BL_GENERATOR_TEMPORARY_VALUE", os.environ)

    def test_unidentified_or_noncanonical_fixture_data_is_rejected(self) -> None:
        fixture_bytes = b"KNOWN-SYNTHETIC-FIXTURE"
        fixture_hash = hashlib.sha256(fixture_bytes).hexdigest()
        valid_identity = {
            "entrypoint": "blind_ledger_cairo_adjudication::batch_main",
            "metadata": {"claim_count": 1},
            "serialized_arguments_hex_json": ["0x1"],
        }
        with tempfile.TemporaryDirectory() as temporary:
            fixture_path = Path(temporary) / "synthetic.json"
            fixture_path.write_bytes(fixture_bytes)
            with (
                mock.patch.object(profiler, "SYNTHETIC_SAMPLE", fixture_path),
                mock.patch.object(profiler, "SYNTHETIC_SAMPLE_SHA256", "0" * 64),
                mock.patch.object(
                    profiler, "_load_synthetic_bundle", return_value=valid_identity
                ) as load,
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "synthetic_fixture_identity_mismatch"
                ):
                    profiler._build_synthetic_arguments()
                load.assert_not_called()

            arbitrary_data = {
                **valid_identity,
                "serialized_arguments_hex_json": [
                    r"C:\synthetic-private\fixture-0001.json"
                ],
            }
            with (
                mock.patch.object(profiler, "SYNTHETIC_SAMPLE", fixture_path),
                mock.patch.object(profiler, "SYNTHETIC_SAMPLE_SHA256", fixture_hash),
                mock.patch.object(
                    profiler, "_load_synthetic_bundle", return_value=arbitrary_data
                ),
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "synthetic_fixture_arguments_invalid"
                ):
                    profiler._build_synthetic_arguments()

    def test_allowed_run_reports_only_aggregates_and_deletes_all_artifacts(self) -> None:
        source_manifest_text = """[package]
name = "synthetic_profile_test"
version = "0.1.0"

[[target.executable]]
name = "batch_main"
function = "synthetic_profile_test::batch_main"
"""
        synthetic_arguments = ["0xdeadbeef", "0x2"]
        observed: dict[str, object] = {}

        with tempfile.TemporaryDirectory() as source_temporary:
            cairo_dir = Path(source_temporary) / "zk-cairo-sharp"
            cairo_dir.mkdir()
            source_manifest = cairo_dir / "Scarb.toml"
            source_manifest.write_text(source_manifest_text, encoding="utf-8")

            def fake_child(
                command: list[str],
                *,
                cwd: Path,
                capture_output: bool,
                text: bool,
                check: bool,
            ) -> subprocess.CompletedProcess[str]:
                self.assertTrue(capture_output)
                self.assertTrue(text)
                self.assertFalse(check)
                calls = observed.setdefault("commands", [])
                assert isinstance(calls, list)
                calls.append(command)
                if command[1] == "execute":
                    arguments_path = Path(
                        command[command.index("--arguments-file") + 1]
                    )
                    observed["profile_root"] = arguments_path.parent
                    observed["arguments"] = json.loads(
                        arguments_path.read_text(encoding="utf-8")
                    )
                    trace_path = (
                        cwd
                        / "target"
                        / "execute"
                        / "synthetic"
                        / "cairo_profiler_trace.json"
                    )
                    trace_path.parent.mkdir(parents=True)
                    trace_path.write_text(
                        "TRACE_WITH_PRIVATE_WITNESS", encoding="utf-8"
                    )
                    return subprocess.CompletedProcess(
                        command,
                        0,
                        stdout="RAW_WITNESS_SECRET\n",
                        stderr=(
                            r"PRIVATE_PATH=C:\synthetic-private\fixture-0001.json"
                            + "\n"
                        ),
                    )
                if command[1] == "build-profile":
                    profile_path = Path(command[command.index("--output-path") + 1])
                    profile_path.write_bytes(b"PROFILE_WITH_PRIVATE_DERIVATION")
                    return subprocess.CompletedProcess(
                        command,
                        0,
                        stdout="RAW_FUNCTION_PROFILE\n",
                        stderr="RAW_PROFILER_DIAGNOSTIC\n",
                    )
                self.fail(f"unexpected child operation: {command[1]}")

            with (
                mock.patch.object(profiler, "CAIRO_DIR", cairo_dir),
                mock.patch.object(
                    profiler,
                    "_resolve_command",
                    side_effect=lambda name: name,
                ),
                mock.patch.object(
                    profiler,
                    "_build_synthetic_arguments",
                    return_value=synthetic_arguments,
                ) as build_fixture,
                mock.patch.object(profiler.subprocess, "run", side_effect=fake_child),
            ):
                result, stdout, stderr = self._invoke([], _ALLOWED_FLAGS)

            profile_root = observed["profile_root"]
            self.assertIsInstance(profile_root, Path)
            assert isinstance(profile_root, Path)
            self.assertFalse(profile_root.exists())
            self.assertEqual(source_manifest.read_text(encoding="utf-8"), source_manifest_text)

        self.assertEqual(result, 0)
        self.assertEqual(observed["arguments"], synthetic_arguments)
        self.assertEqual(len(observed["commands"]), 2)  # type: ignore[arg-type]
        build_fixture.assert_called_once_with()
        combined = stdout + stderr
        for forbidden in (
            "0xdeadbeef",
            "RAW_WITNESS_SECRET",
            "PRIVATE_PATH",
            "RAW_FUNCTION_PROFILE",
            "RAW_PROFILER_DIAGNOSTIC",
            "TRACE_WITH_PRIVATE_WITNESS",
            "PROFILE_WITH_PRIVATE_DERIVATION",
            "--arguments-file",
        ):
            self.assertNotIn(forbidden, combined)
        self.assertIn("fixture_id=blind-ledger-single-claim-v1", stdout)
        self.assertIn("synthetic_argument_count=2", stdout)
        self.assertIn("returncode[execute]=0", stdout)
        self.assertIn("stdout_bytes[execute]=", stdout)
        self.assertIn("stderr_lines[build_profile]=1", stdout)
        self.assertIn("trace_file_count=1", stdout)
        self.assertIn("trace_bytes=26", stdout)
        self.assertIn("profile_bytes=31", stdout)
        self.assertIn("source_manifest_unchanged=true", stdout)
        self.assertEqual(stderr, "")


if __name__ == "__main__":
    unittest.main()
