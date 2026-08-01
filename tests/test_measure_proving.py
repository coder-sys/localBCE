from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from tools import measure_proving as measure


class ExecutionArtifactSelectionTests(unittest.TestCase):
    def test_new_stdout_id_matches_the_only_new_directory(self) -> None:
        self.assertEqual(
            "8",
            measure._select_new_execution_id(
                '{"execution_id":"8"}',
                previous_ids={7},
                current_ids={7, 8},
            ),
        )

    def test_exactly_one_new_directory_is_a_valid_stdout_fallback(self) -> None:
        self.assertEqual(
            "8",
            measure._select_new_execution_id(
                '{"status":"finished"}',
                previous_ids={7},
                current_ids={7, 8},
            ),
        )

    def test_zero_multiple_old_and_mismatched_ids_fail_closed(self) -> None:
        cases = (
            ('{"status":"finished"}', {7}, {7}, "exactly one new"),
            ('{"status":"finished"}', {7}, {7, 8, 9}, "exactly one new"),
            ('{"execution_id":"7"}', {7}, {7}, "exactly one new"),
            ('{"execution_id":"7"}', {7}, {7, 8}, "old execution"),
            ('{"execution_id":"9"}', {7}, {7, 8}, "does not match"),
            (
                '{"execution_id":"8"}\n{"execution_id":"9"}',
                {7},
                {7, 8},
                "multiple execution ids",
            ),
            ('{"execution_id":"../8"}', {7}, {7, 8}, "non-canonical"),
        )
        for stdout, previous_ids, current_ids, message in cases:
            with self.subTest(
                stdout=stdout,
                previous_ids=previous_ids,
                current_ids=current_ids,
            ), self.assertRaisesRegex(RuntimeError, message):
                measure._select_new_execution_id(
                    stdout,
                    previous_ids=previous_ids,
                    current_ids=current_ids,
                )

    def test_staged_wsl_snapshot_reads_only_canonical_execution_directories(
        self,
    ) -> None:
        completed = subprocess.CompletedProcess(
            ["wsl"],
            0,
            stdout="execution7\nexecution8\nexecution09\nother\n",
            stderr="",
        )
        with mock.patch.object(
            measure.subprocess, "run", return_value=completed
        ) as run:
            self.assertEqual(
                {7, 8},
                measure._staged_wsl_execution_directory_ids(
                    "/tmp/blind-ledger-prove.ABC123"
                ),
            )
        command = run.call_args.args[0]
        self.assertEqual(["wsl", "bash", "-lc"], command[:3])

        with self.assertRaisesRegex(RuntimeError, "unexpected WSL staging path"):
            measure._staged_wsl_execution_directory_ids("/tmp/not-authorized")

    def test_staged_wsl_snapshot_failure_is_fail_closed(self) -> None:
        completed = subprocess.CompletedProcess(
            ["wsl"],
            41,
            stdout="",
            stderr="not a directory",
        )
        with mock.patch.object(measure.subprocess, "run", return_value=completed):
            with self.assertRaisesRegex(
                RuntimeError, "unable to inspect WSL Cairo execution artifacts"
            ):
                measure._staged_wsl_execution_directory_ids(
                    "/tmp/blind-ledger-prove.ABC123"
                )

    def test_run_refuses_stale_stdout_before_proving(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cairo_dir = Path(temporary)
            execution_root = (
                cairo_dir
                / "target"
                / "execute"
                / "blind_ledger_cairo_adjudication"
            )
            (execution_root / "execution7").mkdir(parents=True)
            calls: list[list[str]] = []

            def fake_run(command: list[str], **_kwargs: object):
                calls.append(command)
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout='{"execution_id":"7"}\n',
                    stderr="",
                )

            with (
                mock.patch.object(measure, "CAIRO_DIR", cairo_dir),
                mock.patch.object(measure.shutil, "which", return_value="scarb"),
                mock.patch.object(measure, "_has_wsl_scarb", return_value=False),
                mock.patch.object(measure.subprocess, "run", side_effect=fake_run),
            ):
                with self.assertRaisesRegex(RuntimeError, "exactly one new"):
                    measure._run_scarb_prove([], None, None, False)

            self.assertEqual(1, len(calls))
            self.assertIn("execute", calls[0])
            self.assertNotIn("prove", calls[0])

    def test_run_uses_the_single_fresh_directory_without_stdout_id(self) -> None:
        proof = b"synthetic proof bytes"
        with tempfile.TemporaryDirectory() as temporary:
            cairo_dir = Path(temporary)
            execution_root = (
                cairo_dir
                / "target"
                / "execute"
                / "blind_ledger_cairo_adjudication"
            )
            (execution_root / "execution7").mkdir(parents=True)
            calls: list[list[str]] = []

            def fake_run(command: list[str], **_kwargs: object):
                calls.append(command)
                if "execute" in command:
                    proof_path = execution_root / "execution8" / "proof" / "proof.json"
                    proof_path.parent.mkdir(parents=True)
                    proof_path.write_bytes(proof)
                    return subprocess.CompletedProcess(
                        command,
                        0,
                        stdout='{"status":"finished"}\n',
                        stderr="",
                    )
                return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

            with (
                mock.patch.object(measure, "CAIRO_DIR", cairo_dir),
                mock.patch.object(measure.shutil, "which", return_value="scarb"),
                mock.patch.object(measure, "_has_wsl_scarb", return_value=False),
                mock.patch.object(measure.subprocess, "run", side_effect=fake_run),
            ):
                result = measure._run_scarb_prove([], None, None, False)

            prove_call = next(command for command in calls if "prove" in command)
            verify_call = next(command for command in calls if "verify" in command)
            self.assertEqual("8", prove_call[prove_call.index("--execution-id") + 1])
            self.assertEqual("8", verify_call[verify_call.index("--execution-id") + 1])
            self.assertEqual(0, result[4])
            self.assertEqual(len(proof), result[8])
            self.assertEqual(hashlib.sha256(proof).hexdigest(), result[9])


if __name__ == "__main__":
    unittest.main()
