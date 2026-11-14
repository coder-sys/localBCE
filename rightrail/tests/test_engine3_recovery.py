"""Crash, retry, and initial-head recovery for the unpinned rows-file engine `gate_hist3`.  A store whose log disagrees with its rows
files is refused on load with `flat_corrupt`; a changed request or answer byte of an earlier frame is not read on load, and the checker
catches it (tests/test_engine3_verify.py)."""

import os
import shutil
import struct
import subprocess
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from tests import engine3_compare as ec

D = 24  # the trailer's domain; then shard u32
P = D + 76 + 79  # the authority record; rq at P + 208, replaced at P + 336, prev at P + 400
PREV = 82 + 8  # the request's previous head: header, today, asOf


def request(batch, prev, bodies=(), asof=None, pin=None, release=None, floors=None):
    return ec.decider.request_frame(ec.g.HEAD, 0, batch, ec.g.ASOF if asof is None else asof, prev, pin or ec.g.PIN, floors or ec.fw.floors(prev),
                                    ec.g.KEYS, ec.g.GRANT, ec.RELEASE if release is None else release, (), bodies)


def frames(log: bytes):
    """(offset, request length, answer length, trailer offset) of each whole frame."""
    pos, out = 0, []
    while pos + 16 <= len(log):
        rq, an, tr = struct.unpack("<III", log[pos + 4 : pos + 16])
        if pos + 16 + rq + an + tr > len(log):
            break
        out.append((pos, rq, an, pos + 16 + rq + an))
        pos += 16 + rq + an + tr
    return out


def flip(path: Path, at: int) -> bytes:
    raw = bytearray(path.read_bytes())
    raw[at] ^= 1
    path.write_bytes(bytes(raw))
    return bytes(raw)


def changed_pin():
    return bytes([ec.g.PIN[0] ^ 1]) + ec.g.PIN[1:]


def other_genesis():
    """The head a first request under the changed pin names as its previous."""
    return ec.fw.chain.genesis(0, ec.g.ASOF, changed_pin())


def answer(data, output):
    assert output, "engine exited without an answer"
    return ec.fw.read(data, output)


def allowed_body():
    member = ec.g.member(1001, 0)
    line = ec.gate.encode_line("FFS_CLAIM", "L" + "0" * 30 + "1", member,
                              "P7001", "R7001", 20270301, "C99213", 1, 12500)
    return ec.gate.encode_decide_request(ec.gate.DecideRequest(
        ec.fx.TENANT, ec.fx.PROGRAM, "FFS_CLAIM", "cmd-recovery-1", "pay-recovery-1",
        member, "P7001", 12500, ec.fx.PERIOD, (line,), ec.EVIDENCE))


class Engine3Recovery(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="engine3-recovery-", dir=os.environ.get("E3_SCRATCH"))
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def engine(self, crash="", d=None):
        engine = ec.fw.Engine(d or self.dir, ec.NEW, {"RR_E3_CRASH": crash})
        self.addCleanup(engine.close)
        return engine

    def pending(self, data, d=None):
        """`data` decided and appended, then the process ends before anything is released: a pending frame."""
        eng = self.engine("after_append", d)
        self.assertEqual(eng.send(data), b"")
        eng.close()
        self.assertEqual(eng.p.returncode, 99)

    def commit(self, data, d=None):
        eng = self.engine(d=d)
        why, _, head, *_ = answer(data, eng.send(data))
        eng.close()
        self.assertIsNone(why)
        return head

    def test_pending_frame_with_edited_request_bytes_is_decided_again(self):
        # a body byte (the stored bytes no longer hash to the trailer's rq) and a header shard byte (outside the digest)
        for name, at in (("body", PREV), ("header", 6)):
            with self.subTest(edited=name):
                d = self.dir / name
                d.mkdir()
                head = self.commit(request(1, ec.fw.GENESIS), d)
                second = request(2, head)
                self.pending(second, d)
                pos, *_ = frames((d / "log").read_bytes())[1]
                edited = flip(d / "log", pos + 16 + at)
                eng = self.engine(d=d)
                why, _, head2, *_ = answer(second, eng.send(second))
                self.assertIsNone(why)
                log = (d / "log").read_bytes()
                self.assertNotEqual(log, edited)
                pos, _, _, t = frames(log)[1]
                self.assertEqual(log[pos + 16 : pos + 16 + len(second)], second)
                self.assertNotEqual(log[t + P + 336 : t + P + 400], bytes(64))  # the replaced frame is named
                eng.close()
                third = request(3, head2)
                self.assertIsNone(answer(third, self.engine(d=d).send(third))[0])

    def test_a_sealed_answer_altered_in_the_log_is_not_served_to_the_retry(self):
        first = request(1, ec.fw.GENESIS, [allowed_body()])
        eng = self.engine()
        self.assertIsNone(answer(first, eng.send(first))[0])
        pos, rq, _, _ = frames((self.dir / "log").read_bytes())[0]
        flip(self.dir / "log", pos + 16 + rq + 88)  # a byte of the stored answer's leaf, after the open store read the frame
        self.assertEqual(answer(first, eng.send(first))[0], "flat_corrupt")
        eng.close()

    def test_a_torn_log_tail_is_cut_on_open(self):
        for name, tail in (("zeroed", bytes(40)), ("garbage", bytes([0x5a, 0xa5]) * 30), ("short header", b"RRF4" + bytes(1))):
            with self.subTest(name):
                d = self.dir / name
                d.mkdir()
                head = self.commit(request(1, ec.fw.GENESIS), d)
                whole = (d / "log").read_bytes()
                (d / "log").write_bytes(whole + tail)
                second = request(2, head)
                why, *_ = answer(second, self.engine(d=d).send(second))
                self.assertIsNone(why)
                self.assertTrue((d / "log").read_bytes().startswith(whole))

    def test_pending_first_frame_with_corrupt_request(self):
        first = request(1, ec.fw.GENESIS)
        self.pending(first)
        edited = flip(self.dir / "log", 16 + PREV)
        eng = self.engine()
        why, _, head, *_ = answer(first, eng.send(first))
        self.assertIsNone(why)
        log = (self.dir / "log").read_bytes()
        self.assertNotEqual(log, edited)
        self.assertEqual(log[16 : 16 + len(first)], first)
        eng.close()
        second = request(2, head, [allowed_body()])
        why, records, *_ = answer(second, self.engine().send(second))
        self.assertIsNone(why)
        self.assertEqual([r.outcome for r in records], ["ALLOW"])

    def test_pending_first_frame_and_a_first_request_of_another_date(self):
        first = request(1, ec.fw.GENESIS)
        self.pending(first)
        pending = (self.dir / "log").read_bytes()
        later = ec.g.ASOF + 1
        other = request(1, ec.chain.genesis(0, later, ec.g.PIN), asof=later)
        eng = self.engine()
        self.assertEqual(answer(other, eng.send(other))[0], "flat_conflict")
        self.assertEqual((self.dir / "log").read_bytes(), pending)
        self.assertIsNone(answer(first, eng.send(first))[0])
        self.assertEqual((self.dir / "log").read_bytes(), pending)

    def test_committed_first_frame_trailer_must_match_its_request(self):
        base = self.dir / "base"
        base.mkdir()
        head = self.commit(request(1, ec.fw.GENESIS), base)
        head = self.commit(request(2, head), base)
        third = request(3, head)
        t = frames((base / "log").read_bytes())[0][3]
        for name, at in (("prev", P + 400), ("shard", D), ("rq", P + 208)):
            with self.subTest(field=name):
                d = self.dir / name
                shutil.copytree(base, d)
                flip(d / "log", t + at)
                self.assertEqual(answer(third, self.engine(d=d).send(third))[0], "flat_corrupt")

    def test_a_committed_frame_must_chain_to_the_signed_head(self):
        # the second of three committed frames: its trailer's prev, bd, root and head
        base = self.dir / "base"
        base.mkdir()
        head = self.commit(request(1, ec.fw.GENESIS), base)
        for n in (2, 3):
            bodies = [ec.line_body(i, t, False) for i, t in enumerate(ec.gate_corpus.lines(ec.gb.SEED, 20 * n, 20, 100), 20 * n)]
            head = self.commit(request(n, head, bodies), base)
        fourth = request(4, head)
        t = frames((base / "log").read_bytes())[1][3]
        for name, at in (("prev", t + P + 400), ("bd", t + P + 464), ("root", t + P + 528), ("head", t + P + 592)):
            with self.subTest(field=name):
                d = self.dir / name
                shutil.copytree(base, d)
                flip(d / "log", at)
                self.assertEqual(answer(fourth, self.engine(d=d).send(fourth))[0], "flat_corrupt")
        self.assertIsNone(answer(fourth, self.engine(d=base).send(fourth))[0])

    def test_a_store_logged_before_the_batch_identity_is_refused_as_corrupt(self):
        # a frame whose trailer holds the request frame digest (the `rq` of stores written before the batch identity, no
        # migration) is refused on load, the first frame too
        base = self.dir / "base"
        base.mkdir()
        head = self.commit(request(1, ec.fw.GENESIS), base)
        head = self.commit(request(2, head), base)
        third = request(3, head)
        log = (base / "log").read_bytes()
        for k in (0, 1):
            pos, rq, an, t = frames(log)[k]
            with self.subTest(frame=k + 1):
                d = self.dir / f"old{k}"
                shutil.copytree(base, d)
                raw = bytearray((d / "log").read_bytes())
                raw[t + P + 208 : t + P + 272] = log[pos + 16 + 18 : pos + 16 + 82]
                (d / "log").write_bytes(bytes(raw))
                self.assertEqual(answer(third, self.engine(d=d).send(third))[0], "flat_corrupt")

    def test_refused_first_request_does_not_choose_the_start(self):
        # a first request with another pin, refused before anything is written (lines without a release name)
        refused = request(1, other_genesis(), [allowed_body()], pin=changed_pin(), release=b"")
        first = request(1, ec.fw.GENESIS)
        eng = self.engine()
        self.assertEqual(answer(refused, eng.send(refused))[0], "flat_record")
        self.assertEqual((self.dir / "log").read_bytes(), b"")  # the store was opened for it
        why, _, head, *_ = answer(first, eng.send(first))
        self.assertIsNone(why)
        eng.close()
        second = request(2, head, [allowed_body()])
        why, records, *_ = answer(second, self.engine().send(second))  # a new process replays batch 1 from the log
        self.assertIsNone(why)
        self.assertEqual([r.outcome for r in records], ["ALLOW"])

    def test_a_key_set_floor_raised_between_batches_refuses_the_same_key_set(self):
        # the engine keeps its last admission for the next batch; the tenant's key-set epoch floor is part of what it was made from
        eng, head = self.engine(), ec.fw.GENESIS
        for batch in (1, 2):  # the second batch is the first one admitted from the same stored floor, so the third reuses it
            frame = request(batch, head, [allowed_body()])
            why, _, head, *_ = answer(frame, eng.send(frame))
            self.assertIsNone(why)
        stale = request(3, head, [allowed_body()], floors=(ec.fw.floors(head)[0], 1))
        self.assertEqual(answer(stale, eng.send(stale))[0], "grant_stale_keyset")
        again = request(3, head, [allowed_body()])
        self.assertIsNone(answer(again, eng.send(again))[0])
        eng.close()

    def test_before_append_empty_history_retry_and_wrong_head(self):
        first = request(1, ec.fw.GENESIS)
        eng = self.engine("before_append")
        self.assertEqual(eng.send(first), b"")
        eng.close()
        self.assertEqual(eng.p.returncode, 99)
        self.assertEqual((self.dir / "log").read_bytes(), b"")

        wrong = request(1, bytes(64))
        eng = self.engine()
        self.assertEqual(answer(wrong, eng.send(wrong))[0], "flat_head")
        self.assertEqual((self.dir / "log").read_bytes(), b"")
        result = answer(first, eng.send(first))
        self.assertIsNone(result[0])
        self.assertEqual(result[2], answer(first, eng.send(first))[2])
        eng.close()

    def test_after_append_exact_retry_and_changed_input(self):
        first = request(1, ec.fw.GENESIS)
        eng = self.engine("after_append")
        self.assertEqual(eng.send(first), b"")
        eng.close()
        self.assertEqual(eng.p.returncode, 99)
        pending = (self.dir / "log").read_bytes()
        self.assertTrue(pending.startswith(b"RRF4"))

        changed = request(1, ec.fw.GENESIS,
                          [ec.line_body(0, next(ec.gate_corpus.lines(ec.gb.SEED, 0, 1, 1)), False)])
        eng = self.engine()
        self.assertEqual(answer(changed, eng.send(changed))[0], "flat_conflict")
        self.assertEqual((self.dir / "log").read_bytes(), pending)
        self.assertIsNone(answer(first, eng.send(first))[0])
        eng.close()

    def test_reopen_nonzero_date(self):
        body = allowed_body()
        first = request(1, ec.fw.GENESIS, [body])
        eng = self.engine()
        why, records, head, *_ = answer(first, eng.send(first))
        self.assertIsNone(why)
        self.assertEqual([r.outcome for r in records], ["ALLOW"])
        self.assertNotEqual(ec.g.ASOF, 0)
        second = request(2, head)
        eng.close()
        eng = self.engine()
        why2, _, head2, *_ = answer(second, eng.send(second))
        self.assertIsNone(why2)
        third = request(3, head2)
        why3, *_ = answer(third, eng.send(third))
        self.assertIsNone(why3)
        eng.close()

    def test_rejected_changed_pin_does_not_poison_the_exact_pending_retry(self):
        first = request(1, ec.fw.GENESIS)
        eng = self.engine("after_append")
        self.assertEqual(eng.send(first), b"")
        eng.close()
        pending = (self.dir / "log").read_bytes()
        changed = request(1, other_genesis(), pin=changed_pin())
        eng = self.engine()
        self.assertEqual(answer(changed, eng.send(changed))[0], "flat_conflict")
        self.assertEqual((self.dir / "log").read_bytes(), pending)
        why, _, head, *_ = answer(first, eng.send(first))
        self.assertIsNone(why)
        self.assertEqual((self.dir / "log").read_bytes(), pending)
        second = request(2, head, [allowed_body()])
        why, records, *_ = answer(second, eng.send(second))
        self.assertIsNone(why)
        self.assertEqual([r.outcome for r in records], ["ALLOW"])
        eng.close()

    def test_a_resident_store_refuses_a_request_under_another_key_set_pin(self):
        eng, head = self.engine(), ec.fw.GENESIS
        first = request(1, head, [allowed_body()])
        why, _, head, *_ = answer(first, eng.send(first))
        self.assertIsNone(why)
        other = request(2, head, [allowed_body()], pin=changed_pin())
        self.assertEqual(answer(other, eng.send(other))[0], "flat_pin")
        second = request(2, head, [allowed_body()])
        self.assertIsNone(answer(second, eng.send(second))[0])
        eng.close()

    def test_verifier_refuses_skip_claim(self):
        first = request(1, ec.fw.GENESIS)
        eng = self.engine()
        self.assertIsNone(answer(first, eng.send(first))[0])
        eng.close()
        verify = ec.fw.BIN / "gate_verify3.exe"
        for skip in ("answer", "leaf", "file", "answer,leaf,file", "invalid", ",", ",,,", " "):
            with self.subTest(skip=skip):
                invalid = skip != "answer"
                run = subprocess.run([str(verify), str(self.dir), "0", "rows-offline"],
                                     env={**os.environ, "RR_V3_SKIP": skip},
                                     capture_output=True, text=True, timeout=30)
                self.assertEqual(run.returncode, 64 if invalid else 2, run.stdout + run.stderr)
                self.assertNotIn("VERIFIED", run.stdout + run.stderr)
                self.assertIn("VERIFY_BAD_SKIP" if invalid else "DIAGNOSTIC_INCOMPLETE", run.stdout + run.stderr)

    def test_a_copy_of_the_store_loads_after_every_batch(self):
        # the hot corpus has the same keys again and again; a copy of the store after each batch loads and answers the next, empty batch
        for kind in ("hot", "mixed"):
            with self.subTest(kind):
                d = self.dir / f"store-{kind}"
                d.mkdir()
                eng = ec.fw.Engine(d, ec.NEW)
                self.addCleanup(eng.close)
                first = request(1, ec.fw.GENESIS)
                why, _, head, *_ = answer(first, eng.send(first))
                self.assertIsNone(why)
                per, count = 20, 60
                span = per * count
                for n in range(2, count + 2):
                    start = (n - 2) * per
                    bodies = [ec.line_body(i, t, kind == "hot") for i, t in enumerate(ec.gate_corpus.lines(ec.gb.SEED, start, per, span), start)]
                    data = request(n, head, bodies)
                    why, _, head, *_ = answer(data, eng.send(data))
                    self.assertIsNone(why, f"batch {n}")
                    copy = self.dir / f"copy{n}"
                    shutil.copytree(d, copy, ignore=shutil.ignore_patterns("lock"))
                    loader = ec.fw.Engine(copy, ec.NEW)
                    empty = request(n + 1, head)
                    got = answer(empty, loader.send(empty))
                    loader.close()
                    shutil.rmtree(copy, ignore_errors=True)
                    self.assertIsNone(got[0], f"a copy after batch {n} does not load")
                eng.close()

    def test_decisions_equal_the_old_engine_on_golden_mixed_and_hot(self):
        with unittest.mock.patch.dict(os.environ, {"E3_SCRATCH": str(self.dir)}):
            results = {"golden": ec.golden(), "mixed": ec.bench("mixed", 6000, 500), "hot": ec.bench("hot", 6000, 500)}
        for kind, r in results.items():
            self.assertGreater(r["lines"], 0, kind)
            self.assertEqual((r["mismatch"], r["refused"]), (0, 0), (kind, r))

    def test_entry_slots_of_a_batch_equal_the_model_at_and_past_the_posting_cap(self):
        # the rules hold a line whose keys collide, so no corpus here passes 1,024 postings under one key: the slots a
        # batch writes are checked against the model's entry directly, below, at and past the cap
        run = subprocess.run([str(ec.fw.BIN / "engine3_bench.exe"), "puts"], capture_output=True, text=True, timeout=300)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn("0 mismatches over 720 cases", run.stdout)


if __name__ == "__main__":
    unittest.main()
