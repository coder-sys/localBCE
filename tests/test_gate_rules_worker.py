"""The resident ``gate_engine`` answers exactly as the one-shot ``gate_rules`` and fails closed (test-only exes)."""

import hashlib
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

WORKER = Path(rules.LEAN) / ".lake" / "build" / "bin" / "gate_engine.exe"
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


def rows(base: int, n: int) -> list[tuple[int, int]]:
    return [(i, i) for i in range(base, base + n)]


def frame(batch: list[tuple[int, int]], first: str, today: int | None = None, wrong: bool = False) -> bytes:
    """A batch frame over the shard head: `first` is a comment (genesis), a load or a resume line; `batch` is (line id, payment);
    `wrong` expects a wrong outcome on the first line, so the frame fails its vector check."""
    head = [f"today {today}", *g._HEAD[1:]] if today else g._HEAD
    lines = [f"line {i}:{p} FFS_CLAIM 1001 7001 7001 {20270301 + i % 20} 99213 1 {1000 + i}" + (" HOLD ALREADY_DECIDED" if wrong and n == 0 else "")
             for n, (i, p) in enumerate(batch)]
    return "\n".join([*head, "case batch", first, "owners 0 " + " ".join(f"{i}:0:0" for i, _ in batch), *lines, "commit", "end 0"]).encode()


def load_line(held: tuple[str, bytes]) -> str:
    return f"load {g.ASOF} {held[1].hex() or '-'} {held[0]}"


def resume_line(held: tuple[str, bytes]) -> str:
    return f"resume {held[0]} {hashlib.sha3_512(held[1]).hexdigest()}"


@unittest.skipUnless(os.name == "nt" and os.path.isfile(rules.EXE) and WORKER.is_file(),
                     f"GATE RULES WORKER NOT RUN: {WORKER} is missing; run `lake build gate_engine` in lean/")
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

    def committed(self, out: list[str]) -> tuple[str, bytes]:
        digest = [r.split(" ")[1] for r in out if r.startswith("RULES_DIGEST ")]
        adds = "".join(r.split(" ")[1] for r in out if r.startswith("RULES_ADDS "))
        self.assertEqual(len(digest), 1, out[-6:])
        return digest[0], bytes.fromhex("" if adds == "-" else adds)

    def start(self, w: decider.RulesWorker, tmp: str) -> tuple[str, bytes]:
        """Genesis, then a `load` of its adds (a genesis frame keeps no adds stream, so only a load makes the state resumable);
        returns the held (digest, adds)."""
        first = w.run(frame(rows(1, 30), "# genesis"))
        self.assertTrue(first[-1].startswith("RULES_VECTORS=PASS"), first[-3:])
        genesis = self.committed(first)
        data = frame(rows(100, 30), load_line(genesis))
        out = w.run(data)
        self.assertEqual(out, one_shot(data, Path(tmp)))
        digest, adds = self.committed(out)
        return digest, genesis[1] + adds

    def step(self, w, tmp: str, held, batch, today: int | None = None) -> tuple[tuple[str, bytes], list[str]]:
        """`resume` on `w` prints what the one-shot `load` of the same state prints; returns the new held state and the output."""
        resumed = w.run(frame(batch, resume_line(held), today))
        self.assertEqual(resumed, one_shot(frame(batch, load_line(held), today), Path(tmp)))
        self.assertTrue(resumed[-1].startswith("RULES_VECTORS=PASS"), resumed[-3:])
        self.assertFalse(any("MISMATCH" in r for r in resumed))
        digest, adds = self.committed(resumed)
        self.assertNotEqual(digest, held[0])
        return (digest, held[1] + adds), resumed

    def refused(self, w: decider.RulesWorker, line: str, kinds: tuple[str, ...] = ("RULES_STATE_MISMATCH resume",)) -> None:
        out = w.run(frame(rows(900, 5), line))
        self.assertTrue(any(r.startswith(kinds) for r in out), out)
        self.assertFalse(out[-1].startswith("RULES_VECTORS=PASS"), out[-3:])

    def test_resume_answers_as_the_full_load_across_frames(self):
        """A `resume D H` after a commit on the same worker prints what `load ASOF ADDS D` prints on the one-shot, batch after batch."""
        w = self.worker()
        with self.scratch() as tmp:
            held = self.start(w, tmp)
            for base in (200, 300):
                held, _ = self.step(w, tmp, held, rows(base, 30))
            self.refused(w, f"resume {'0' * 128} {'0' * 128}")

    def test_resume_decides_rows_that_match_history(self):
        """Line ids decided in the genesis, the load and a resumed frame come back ALREADY_DECIDED after a resume (the kept
        index holds every frame's rows)."""
        w = self.worker()
        with self.scratch() as tmp:
            held = self.start(w, tmp)
            held, _ = self.step(w, tmp, held, rows(200, 30))
            _, out = self.step(w, tmp, held, [(5, 501), (105, 502), (205, 503), *rows(400, 5)])
            self.assertEqual(sum(r.startswith("RULES_LINE") and "ALREADY_DECIDED" in r for r in out), 3, out)

    def test_resume_after_a_change_of_today_between_frames(self):
        w = self.worker()
        with self.scratch() as tmp:
            held = self.start(w, tmp)
            held, _ = self.step(w, tmp, held, rows(200, 30), today=20270320)
            held, _ = self.step(w, tmp, held, rows(300, 30))

    def test_resume_of_a_real_older_state_or_a_permuted_stream_is_refused(self):
        w = self.worker()
        with self.scratch() as tmp:
            old = self.start(w, tmp)
            new, _ = self.step(w, tmp, old, rows(200, 30))
            sha = lambda b: hashlib.sha3_512(b).hexdigest()
            self.refused(w, resume_line(old))  # a real digest and its own adds, but not the held state
            self.refused(w, f"resume {old[0]} {sha(new[1])}")
            self.refused(w, f"resume {new[0]} {sha(old[1])}")
            self.refused(w, resume_line((new[0], new[1][len(old[1]):] + new[1][:len(old[1])])))  # the same batches in another order
            self.step(w, tmp, new, rows(300, 30))  # the refusals left the held state alone

    def test_a_failed_frame_state_is_not_adopted(self):
        w = self.worker()
        with self.scratch() as tmp:
            held = self.start(w, tmp)
            failed = w.run(frame(rows(200, 30), resume_line(held), wrong=True))
            self.assertFalse(failed[-1].startswith("RULES_VECTORS=PASS"), failed[-3:])
            digests = [r.split(" ")[1] for r in failed if r.startswith("RULES_DIGEST ")]
            adds = "".join(r.split(" ")[1] for r in failed if r.startswith("RULES_ADDS "))
            for digest in digests:  # the failed frame may print what it built; it must not keep it
                self.refused(w, resume_line((digest, held[1] + bytes.fromhex("" if adds == "-" else adds))))
            self.step(w, tmp, held, rows(300, 30))  # the old state is still the held one

    def test_resume_anchor_must_be_lowercase_hex_of_full_length(self):
        w = self.worker()
        with self.scratch() as tmp:
            digest, adds = held = self.start(w, tmp)
            tag = hashlib.sha3_512(adds).hexdigest()
            for line in (f"resume {digest.upper()} {tag}", f"resume {digest[:-1]} {tag}", f"resume {digest}0 {tag}",
                         f"resume {digest} {tag.upper()}", f"resume {digest} {tag[:-1]}", f"resume {digest}"):
                with self.subTest(line=line[:30] + "..." + line[-3:]):
                    self.refused(w, line, ("RULES_STATE_MISMATCH", "RULES_VECTOR_MALFORMED", "RULES_VECTOR_FAIL"))
            self.step(w, tmp, held, rows(300, 30))

    def test_resume_on_a_fresh_or_recycled_worker_mismatches_and_the_load_answers(self):
        w = self.worker()
        with self.scratch() as tmp:
            held = self.start(w, tmp)
            fresh, data = self.worker(), frame(rows(200, 30), load_line(held))
            self.refused(fresh, resume_line(held))
            self.assertEqual(fresh.run(data), one_shot(data, Path(tmp)))
            w.RECYCLE_COMMIT_BYTES = -1  # the next answer recycles it
            held, _ = self.step(w, tmp, held, rows(300, 30))
            self.assertEqual((w._worker, w.holds), (None, None))
            self.refused(w, resume_line(held))  # restarted: it holds nothing
            data = frame(rows(400, 30), load_line(held))
            self.assertEqual(w.run(data), one_shot(data, Path(tmp)))

    def test_decide_sends_resume_after_the_first_load_and_falls_back_to_load(self):
        """The one call site: `decide` sends `resume` whenever the worker holds the anchor, and every batch after the first load
        is answered without a load; a mismatching resume (a worker that lost its state) falls back to one `load`; a held digest
        that is not the anchor closes the worker before the load."""
        sent, replies = [], []
        with self.scratch() as tmp:
            c = g.Cluster(tmp, fx.custody(tmp))
            c.boot()
            w = self.worker()
            prod, reg = c.producer(0), idreg.IdRegistry(c.reg, boot=c.nonce)
            real = w.run

            def run(data):
                out = real(data)
                sent.append(next((x.split(" ")[0] for x in data.decode().split("\n") if x.split(" ")[0] in ("load", "resume")), "genesis"))
                replies.append(out)
                return out

            def batch(b):
                ans, leaves, status = g.decide_batch(c, prod, reg, 0, {b: [b * 10, b * 10 + 1]}, worker=w)
                self.assertTrue(ans.digest)
                decider.commit(prod, reg, fx.PROGRAM, leaves, ans, fx.NOW)

            try:
                with mock.patch.object(w, "run", run):
                    for b in range(1, 6):
                        batch(b)
                    self.assertEqual(sent, ["genesis", "load", "resume", "resume", "resume"])
                    self.assertFalse(any("MISMATCH" in r for out in replies for r in out))
                    self.assertEqual(w.holds, prod.anchor())
                    w._close()
                    w.holds = prod.anchor()  # a worker that lost its state but is believed to hold it
                    batch(6)
                    self.assertEqual(sent[5:], ["resume", "load"])
                    self.assertTrue(any("RULES_STATE_MISMATCH" in r for r in replies[5]))
                    batch(7)
                    self.assertEqual(sent[7:], ["resume"])
                    old, w.holds = w._worker, bytes(64)  # holds something else: closed before the load
                    batch(8)
                    self.assertEqual(sent[8:], ["load"])
                    self.assertIsNot(w._worker, old)
                    self.assertEqual(w.holds, prod.anchor())
            finally:
                prod.close()
                reg.close()

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
        self.assertEqual(run((3).to_bytes(4, "big") + b"\0\xff\xfe"), (65, b""))  # not UTF-8
        self.assertEqual(run((2).to_bytes(4, "big") + b"\2x"), (65, b""))  # neither tag: rules 0x00, PUBLISH 0x01
        self.assertEqual(run((0).to_bytes(4, "big")), (65, b""))  # no tag
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
