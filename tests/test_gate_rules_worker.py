"""The persistent ``gate_rules_worker`` answers exactly as the one-shot ``gate_rules`` and fails closed (test-only exes)."""

import os
import random
import subprocess
import unittest
from pathlib import Path
from unittest import mock

from app import minimal_clearance_verifier_process as process
from app import right_rail_gate_decide as decider
from app import right_rail_gate_idreg as idreg
from tests import _gate_shards as g
from tests import test_gate_rules_vectors as rules
from tests import test_right_rail_gate_formats as fx

WORKER = Path(rules.LEAN) / ".lake" / "build" / "bin" / "gate_rules_worker.exe"
VECTORS = Path(rules.ROOT) / "tests" / "gate_rules"


def one_shot(data: bytes, tmp: Path) -> list[str]:
    path = tmp / "frame.vectors"
    path.write_bytes(data)
    return subprocess.run([rules.EXE, str(path)], capture_output=True, text=True, timeout=600).stdout.splitlines()[1:]  # after RULES_SOURCE


def random_batch(seed: int, n: int) -> bytes:
    rng = random.Random(seed)
    lines = [f"line {i}:{i} FFS_CLAIM {rng.choice([1001, 1002, 1003, 1005, 9001, 7701, 504])} 7001 7001 {20270301 + rng.randrange(20)} "
             f"{rng.choice([99213, 99214])} {rng.randrange(1, 3)} {rng.randrange(1000, 90000)}" for i in range(1, n + 1)]
    return "\n".join([*g._HEAD, "case batch", "owners 0 " + " ".join(f"{i}:0:0" for i in range(1, n + 1)), *lines, "commit", "end 0"]).encode()


@unittest.skipUnless(os.name == "nt" and os.path.isfile(rules.EXE) and WORKER.is_file(),
                     f"GATE RULES WORKER NOT RUN: {WORKER} is missing; run `lake build gate_rules_worker` in lean/")
class RulesWorkerTests(fx.Scratch):
    def worker(self) -> decider.RulesWorker:
        w = decider.RulesWorker(WORKER)
        self.addCleanup(w.close)
        return w

    def test_worker_equals_one_shot_on_the_vectors_and_a_random_batch(self):
        w = self.worker()
        with self.scratch() as tmp:
            frames = [(VECTORS / name).read_bytes() for name in ("rules_v1.vectors", "demo_zz.vectors", "shards_v1.vectors")]
            for data in [*frames, random_batch(1, 300), random_batch(2, 40)]:
                got = w.run(data)
                self.assertEqual(got, one_shot(data, Path(tmp)))
                self.assertTrue(got[-1].startswith("RULES_VECTORS="))

    def test_resume_answers_as_the_full_load_across_frames(self):
        """A `resume D` after a commit on the same worker prints what `load ASOF ADDS D` prints on the one-shot, batch after batch."""
        def batch(base: int, n: int, first: str) -> bytes:
            rows = [f"line {i}:{i} FFS_CLAIM 1001 7001 7001 {20270301 + i % 20} 99213 1 {1000 + i}" for i in range(base, base + n)]
            return "\n".join([*g._HEAD, "case batch", first, "owners 0 " + " ".join(f"{i}:0:0" for i in range(base, base + n)),
                              *rows, "commit", "end 0"]).encode()

        def committed(out: list[str]) -> tuple[str, str]:
            digest = [r.split(" ")[1] for r in out if r.startswith("RULES_DIGEST ")]
            adds = "".join(r.split(" ")[1] for r in out if r.startswith("RULES_ADDS "))
            self.assertEqual(len(digest), 1, out[-6:])
            return digest[0], adds

        w = self.worker()
        with self.scratch() as tmp:
            first = w.run(batch(1, 30, "# genesis"))
            self.assertTrue(first[-1].startswith("RULES_VECTORS=PASS"), first[-3:])
            digest, adds = committed(first)
            for base in (100, 200):
                resumed = w.run(batch(base, 30, f"resume {digest}"))
                loaded = one_shot(batch(base, 30, f"load {g.ASOF} {adds or '-'} {digest}"), Path(tmp))
                self.assertEqual(resumed, loaded)
                self.assertTrue(resumed[-1].startswith("RULES_VECTORS=PASS"), resumed[-3:])
                self.assertFalse(any("MISMATCH" in r for r in resumed))
                new_digest, new_adds = committed(resumed)
                self.assertNotEqual(new_digest, digest)
                digest, adds = new_digest, adds + new_adds
            stale = w.run(batch(300, 5, f"resume {'0' * 128}"))
            self.assertIn("RULES_STATE_MISMATCH resume", stale)

    def test_killed_worker_is_a_typed_refusal_and_nothing_settles(self):
        real = process.ContainedWorker.exchange

        def killed(self, *args, **kw):
            self._terminate()  # the worker dies after the registry reserve and before it answers
            return real(self, *args, **kw)

        with self.scratch() as tmp:
            c = g.Cluster(tmp, fx.custody(tmp))
            c.boot()
            c.send(0, {1: [10]})
            w = self.worker()
            prod, reg = c.producer(0), idreg.IdRegistry(c.reg, boot=c.nonce)
            try:
                tip, settled = prod.tip(), reg.settled(0)
                with mock.patch.object(process.ContainedWorker, "exchange", killed):
                    g.decide_batch(c, prod, reg, 0, {2: [11]}, worker=w)  # first call starts the worker, then it is killed
                self.fail("the killed worker answered")
            except decider.GateDecideError as error:
                self.assertEqual(str(error), "rules_refused")
                self.assertEqual((prod.tip(), reg.settled(0)), (tip, settled))  # no commit was reached: no token left
                self.assertIsNone(w._worker)
                ans, leaves, status = g.decide_batch(c, prod, reg, 0, {2: [11]}, worker=w)  # the next call restarts it
                self.assertEqual(status, {11: "ALLOW -"})
                self.assertIsNotNone(w._worker)
            finally:
                prod.close()
                reg.close()

    def test_garbage_and_oversize_frames_are_refused(self):
        def run(raw: bytes):
            done = subprocess.run([WORKER], input=raw, capture_output=True, timeout=60)
            return done.returncode, done.stdout
        big = (process.WORKER_MAX_FRAME_BYTES + 1).to_bytes(4, "big")
        self.assertEqual(run(b""), (0, b""))  # clean end of input
        self.assertEqual(run(big), (65, b""))  # header past the cap
        self.assertEqual(run(b"\0\0"), (65, b""))  # short header
        self.assertEqual(run((10).to_bytes(4, "big") + b"abc"), (65, b""))  # short body
        self.assertEqual(run((2).to_bytes(4, "big") + b"\xff\xfe"), (65, b""))  # not UTF-8
        w = self.worker()
        with self.assertRaises(decider.GateDecideError) as caught:
            w.run(bytes([255, 254]))
        self.assertEqual((str(caught.exception), w._worker), ("rules_refused", None))
        self.assertEqual(w.run(b"x")[0], "RULES_VECTOR_MALFORMED line=1")  # the next call restarts it; a malformed text is answered, not killed

    def test_a_missing_or_malformed_reads_line_refuses_the_batch(self):
        h = "52522f474154452f524541442d5345542f763200"  # READ-SET/v2 and its 0 byte
        edits = [lambda r: [], lambda r: r * 2, lambda r: [r[0][:-2]], lambda r: [r[0][:-1] + "g"],
                 lambda r: [r[0].upper()], lambda r: [r[0].replace(h, h[:-4] + "33" + h[-2:])]]
        with self.scratch() as tmp:
            c = g.Cluster(tmp, fx.custody(tmp))
            c.boot()
            w = self.worker()
            prod, reg = c.producer(0), idreg.IdRegistry(c.reg, boot=c.nonce)
            real = w.run
            try:
                for i, edit in enumerate(edits):
                    def run(data, edit=edit):
                        out = real(data)
                        reads = [r.split(" ")[1] for r in out if r.startswith("RULES_READS ")]
                        return [r for r in out if not r.startswith("RULES_READS ")] + [f"RULES_READS {x}" for x in edit(reads)]
                    tip, settled = prod.tip(), reg.settled(0)
                    with self.subTest(i), mock.patch.object(w, "run", run), \
                            self.assertRaises(decider.GateDecideError) as caught:
                        g.decide_batch(c, prod, reg, 0, {1: [10]}, worker=w)
                    self.assertEqual((str(caught.exception), prod.tip(), reg.settled(0)), ("rules_refused", tip, settled))
                self.assertEqual(g.decide_batch(c, prod, reg, 0, {1: [10]}, worker=w)[2], {10: "ALLOW -"})
            finally:
                prod.close()
                reg.close()

    def test_a_frame_over_the_worker_cap_goes_to_the_one_shot_exe(self):
        with self.scratch() as tmp:
            c = g.Cluster(tmp, fx.custody(tmp))
            c.boot()
            w = self.worker()
            prod, reg = c.producer(0), idreg.IdRegistry(c.reg, boot=c.nonce)
            try:
                with mock.patch.object(decider, "FRAME_CAP", 100), mock.patch.object(w, "run", side_effect=AssertionError):
                    ans, leaves, status = g.decide_batch(c, prod, reg, 0, {1: [10]}, worker=w)
                self.assertEqual(status, {10: "ALLOW -"})
            finally:
                prod.close()
                reg.close()


if __name__ == "__main__":
    unittest.main()
