"""The resident ``gate_engine`` fails closed, and the decide layer survives its death (test-only exes).  What it answers on the
history index is in ``test_flat_host`` and ``test_flat_worker``."""

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from app import minimal_clearance_verifier_process as process
from app import right_rail_gate_decide as decider
from tests import _gate_shards as g
from tests import test_gate_rules_vectors as rules
from tests import test_right_rail_gate_formats as fx

WORKER = Path(rules.LEAN) / ".lake" / "build" / "bin" / "gate_engine.exe"


class RulesWorkerTests(fx.Scratch):
    def worker(self) -> decider.RulesWorker:
        w = decider.RulesWorker(WORKER)
        self.addCleanup(w.close)
        return w

    def test_a_worker_dead_between_batches_is_relaunched_and_logged(self):
        w = self.worker()
        with self.scratch() as tmp:
            w.run_frame(tmp, 0, b"x")
            w._worker._terminate()
            with self.assertLogs(decider.LOG, "WARNING") as log:
                w.run_frame(tmp, 0, b"x")
            w.close()
        self.assertIn("dead between batches", "".join(log.output))

    def test_killed_worker_is_logged_and_the_batch_is_decided_on_a_relaunch(self):
        real, deaths = process.ContainedWorker.exchange, []

        def killed(self, *args, **kw):
            if not deaths and self is w._worker:  # the rules worker's first launch dies before it answers (not the signer's)
                deaths.append(1)
                self._terminate()
            return real(self, *args, **kw)

        with self.scratch() as tmp:
            c = g.Cluster(tmp, fx.custody(tmp))
            c.send(0, {1: [10]})
            w = self.worker()
            prod = c.producer(0)
            try:
                tip = prod.tip()
                with mock.patch.object(process.ContainedWorker, "exchange", killed), self.assertLogs(decider.LOG, "WARNING"):
                    ans, leaves, status = g.decide_batch(c, prod, 0, {2: [11]}, worker=w)  # starts the worker, then it is killed once
                self.assertEqual((status, ans.attempts, w.gen), ({11: "ALLOW -"}, 2, 2))  # the relaunched worker decided it in full
                self.assertEqual(prod.tip(), tip)  # decide itself seals nothing
                ans, leaves, status = g.decide_batch(c, prod, 0, {2: [11]}, worker=w)  # the next call puts the index back to the signed head
                self.assertEqual(status, {11: "ALLOW -"})
                self.assertIsNotNone(w._worker)
            finally:
                w.close()  # it holds the index open
                prod.close()

    def test_out_of_memory_at_a_low_job_cap_is_the_batchs_and_is_not_retried(self):
        """Final review M1 on the real engine: under a 200 MB Job cap it starts and answers, then a frame of ten million short
        lines runs out of memory at the cap, which the same frame repeats on any launch: ``DataFault`` ``worker_stderr`` on
        the one launch, no relaunch, nothing counted as a lost worker."""
        w, seen = self.worker(), {}
        w.JOB_MEMORY_CAP_BYTES = 200_000_000
        tmp = self.enterContext(self.scratch())
        self.assertTrue(w.run_frame(tmp, 0, b"x"))
        big = decider.request_frame(g.feeds_of([]), 0, 1, 0, bytes(64), bytes(64), (0, 0), decider.Keys(b""), b"", b"", (), [b"x"] * 10_000_000)
        real_said, real_peak = process.ContainedWorker.diagnostic, process.ContainedWorker.peak_job_memory

        def said(worker):
            seen["said"] = real_said(worker)
            return seen["said"]

        def peak(worker):
            seen["peak"] = real_peak(worker)
            return seen["peak"]
        with mock.patch.object(process.ContainedWorker, "diagnostic", said), \
                mock.patch.object(process.ContainedWorker, "peak_job_memory", peak), \
                self.assertRaises(decider.DataFault) as caught:
            w.run_frame(tmp, 0, big)
        self.assertEqual((str(caught.exception), w.gen, w.lost), ("worker_stderr", 1, 0), seen)
        self.assertIn(b"out of memory", seen["said"])
        self.assertGreaterEqual(seen["peak"], w.JOB_MEMORY_CAP_BYTES * 9 // 10)

    def test_garbage_and_oversize_frames_are_refused(self):
        def run(raw: bytes):
            with self.scratch() as tmp:
                done = subprocess.run([WORKER, tmp, "0"], input=raw, capture_output=True, timeout=60)
            return done.returncode, done.stdout
        big = (process.WORKER_MAX_FRAME_BYTES + 1).to_bytes(4, "big")
        self.assertEqual(run(b""), (0, b""))  # clean end of input
        self.assertEqual(run(big), (65, b""))  # header past the cap
        self.assertEqual(run(b"\0\0"), (65, b""))  # short header
        self.assertEqual(run((10).to_bytes(4, "big") + b"abc"), (65, b""))  # short body
        self.assertEqual(run((3).to_bytes(4, "big") + b"\3\xff\xfe"), (65, b""))  # not UTF-8
        self.assertEqual(run((2).to_bytes(4, "big") + b"\5x"), (65, b""))  # no such tag: PUBLISH 0x01, request 0x04
        self.assertEqual(run((2).to_bytes(4, "big") + b"\3x"), (65, b""))  # the retired text tag
        self.assertEqual(subprocess.run([WORKER], input=b"", capture_output=True, timeout=60).returncode, 64)  # no store named
        self.assertEqual(run((2).to_bytes(4, "big") + b"\0x"), (65, b""))  # the retired row-list tags
        self.assertEqual(run((1).to_bytes(4, "big") + b"\2"), (65, b""))
        self.assertEqual(run((0).to_bytes(4, "big")), (65, b""))  # no tag
        w = self.worker()
        with self.scratch() as tmp:
            out = w.run_frame(tmp, 0, bytes([255, 254]))  # a request that is not one is refused in the answer, not by killing the worker
            self.assertEqual((out[:4], out[6]), (b"RRDA", 2))  # LENGTH
            self.assertTrue(w.run_frame(tmp, 0, b"x"))
            w.close()

class UnkillableWorkerTests(unittest.TestCase):
    """A child that survives its Job (``worker_reap``) ends the batch with the batch's own typed cause, is counted, and leaves no workspace."""

    def stuck(self, work: Path):
        w = decider.RulesWorker(WORKER)
        fake = mock.Mock()
        fake.alive = True
        fake.exchange.side_effect = OSError("pipe")
        fake.diagnostic.return_value = b""
        fake.close.side_effect = process.VerifierProcessError("worker_reap")
        w._worker, w._workspace, w._store = fake, work, ("store", 0)
        return w

    def test_run_frame_ends_with_the_typed_refusal_and_removes_the_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp) / "rr-rules-x"
            work.mkdir()
            w = self.stuck(work)
            with self.assertLogs(decider.LOG, "WARNING") as log, self.assertRaises(decider.WorkerDied) as caught:
                w.run_frame("store", 0, b"x")
            self.assertEqual((str(caught.exception), w.lost, w._worker, work.exists()), ("rules_refused", 1, None, False))
            self.assertIn("worker_reap", "".join(log.output))  # the cause is recorded, not swallowed

    def test_close_does_not_raise_and_removes_the_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp) / "rr-rules-x"
            work.mkdir()
            w = self.stuck(work)
            with self.assertLogs(decider.LOG, "WARNING"):
                w.close()
            self.assertFalse(work.exists())


if __name__ == "__main__":
    unittest.main()
