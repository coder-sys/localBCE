"""A Lean panic never becomes a result: it kills the worker, and stray stderr fails the request (test-only exe)."""

import hashlib
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from app import minimal_clearance_verifier_process as process

ROOT = Path(__file__).resolve().parent.parent
EXE = ROOT / "lean" / ".lake" / "build" / "bin" / "panic_probe.exe"
FRAME = b"\0\0\0\1"


@unittest.skipUnless(os.name == "nt" and EXE.is_file(), f"PANIC PROBE NOT RUN: {EXE} is missing; run `lake build panic_probe` in lean/")
class WorkerPanic(unittest.TestCase):
    def start(self):
        data = EXE.read_bytes()
        workspace = tempfile.mkdtemp(prefix="rr-panic-")
        worker = process.launch_contained_worker(
            EXE, workspace=Path(workspace), job_memory_cap_bytes=1_000_000_000,
            expected_executable_size_bytes=len(data), expected_executable_sha256=hashlib.sha256(data).digest(),
        )
        self.addCleanup(worker.close)
        return worker

    def call(self, mode: int, worker=None) -> bytes:
        worker = worker or self.start()
        try:
            return worker.exchange(bytes([mode]), response_cap_bytes=16, timeout_seconds=10.0)
        finally:
            self.assertEqual(worker.alive, mode == 0)

    def test_panic_without_the_switch_carries_on_with_a_default(self):
        env = {"SystemRoot": os.environ["SystemRoot"]}
        run = subprocess.run([EXE], input=FRAME + b"\1", env=env, capture_output=True, timeout=30)
        self.assertEqual((run.returncode, run.stdout, b"probe panic" in run.stderr), (0, b"\0\0\0\1\0", True))
        run = subprocess.run([EXE], input=FRAME + b"\1", env=env | {"LEAN_ABORT_ON_PANIC": "1"}, capture_output=True, timeout=30)
        self.assertEqual((run.stdout, run.returncode != 0), (b"", True))

    def test_launched_worker_fails_closed(self):
        self.assertEqual(self.call(0), b"\0")
        for mode, code in ((1, "worker_exchange"), (2, "worker_stderr")):
            with self.subTest(mode=mode), self.assertRaises(process.VerifierProcessError) as caught:
                self.call(mode)
            self.assertEqual(str(caught.exception), code)

    def test_stderr_after_a_response_never_lets_a_later_request_succeed(self):
        # The first answer may be refused (bytes already visible) or delivered (bytes not yet written);
        # either way the stray byte stays in the pipe, so the next request cannot return a result.
        worker = self.start()
        try:
            worker.exchange(bytes([3]), response_cap_bytes=16, timeout_seconds=10.0)
        except process.VerifierProcessError:
            pass
        with self.assertRaises(process.VerifierProcessError):
            worker.exchange(bytes([0]), response_cap_bytes=16, timeout_seconds=10.0)
