"""Fact admission at scale in `gate_hist3`, checked by `gate_verify3`: 100 fact frames of 1,000 rows (100,000 rows) in 25
rounds.  Each round has a source of its own and sends, in turn:
- a change file of 1,000 new member statements (ascending: each round's file is newer than the last);
- an older change file of the same source restating them (descending backfill: half the same, written as nothing,
  half changed, written and not in force), before the full file in even rounds and after it in odd rounds (a late
  receipt: its rows end the day before the full file's `cfrom`, so all are written);
- a newer full file of the same source restating them as in force (1,000 lifts, 23 to a lift record);
- a late reference file of one shared source, each older than the one before (descending `fseq`, so each goes first in
  its source's chain): 500 new excluded provider rows and 500 restating the last round's, written as nothing.
The checker verifies the whole log, and every answer, from its own replay.

Stated bound, in processor time (the engine's and the checker's own, so other work on the machine counts less): as the
store grows from nothing to 57,700 records, the engine's median time for each kind of frame in the last 5 rounds is at
most 3 times its median in the first 5, and the checker's time per row over the whole log is at most 3 times its time
per row over the first 7 rounds (a second store given the same frames, which must answer the same entries).  A scan of the store per row, or a re-sort of the reference
entries per row, grows with the store (5 times or more between those rounds) and fails the bound.  An open after a clean
stop and one after a stop that was not clean give the same answer and file; a checker resumed from its last state does
not replay the fact frames."""

import ctypes
import hashlib
import os
import shutil
import statistics
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

from app import right_rail_fact_frame as f
from tests import engine3_compare as ec
from tests import test_engine3_verify as v3
from tests.test_engine3_recovery import request
from tests.test_engine3_facts import R0, R2, fact_request, receipt

ROUNDS, N, BOUND = 25, 1000, 3.0
BASE, REF = 2026010000, 2025120000


def h(tag: bytes, *ns: int, n: int = 32) -> bytes:
    return hashlib.sha3_512(tag + b"".join(x.to_bytes(4, "little") for x in ns)).digest()[:n]


def member(r: int, i: int, status: int = 1) -> dict:
    return {**R0, "subject": h(b"subject", r, i), "sid": h(b"sid", r, i), "roff": i + 1,
            "value": {**R0["value"], "status": status}}


def excluded(r: int, i: int) -> dict:
    return {**R2, "sid": h(b"excluded", r, i), "roff": i + 1}


def cpu(p) -> float:
    """The processor seconds (kernel and user) process `p` (a `subprocess.Popen`) has used."""
    t = [ctypes.c_ulonglong() for _ in range(4)]
    if not ctypes.windll.kernel32.GetProcessTimes(ctypes.c_void_p(int(p._handle)), *map(ctypes.byref, t)):
        raise OSError("GetProcessTimes")
    return (t[2].value + t[3].value) / 1e7


def checker(d: Path) -> tuple[int, str, float]:
    """The checker on store `d`: its exit, output and processor seconds."""
    p = v3.verify(d, wait=False)
    out = p.communicate(timeout=1800)[0]
    return p.returncode, out, cpu(p)


class Engine3FactsScale(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="engine3-scale-", dir=os.environ.get("E3_SCRATCH"))
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name) / "store"

    def test_admission_time_does_not_grow_with_the_store(self):
        prefix = Path(self.tmp.name) / "prefix"
        eng, pre = ec.fw.Engine(self.dir, ec.NEW), ec.fw.Engine(prefix, ec.NEW)  # `pre` takes the first 7 rounds only
        self.addCleanup(eng.close)
        self.addCleanup(pre.close)
        heads = []
        for e in (eng, pre):
            why, _, h0, *_ = ec.fw.read(request(1, ec.fw.GENESIS), e.send(request(1, ec.fw.GENESIS)))
            self.assertIsNone(why)
            heads.append(h0)
        batch, times, rows, last = 1, {}, 0, None
        refs: list[bytes] = []
        new_refs: list[dict] = []

        def ask(e, k, kind, rcpt, ws):
            """The answer of engine `e` to the frame on its own head `heads[k]`, which it moves on."""
            data = fact_request(batch, heads[k], {**rcpt, "frows": len(ws)}, ws)
            out = e.send(data)
            try:
                a = f.decode_answer(out)
            except ValueError:
                self.fail(f"{kind} batch {batch}: " + (ec.decider._answer(out, data)[0] if out else "no answer"))
            heads[k] = a["head"]
            return a

        def send(kind, rcpt, ws, want):
            nonlocal batch, rows, last
            batch += 1
            ws = sorted(ws, key=f.key)  # a frame's rows in wire order
            t0 = cpu(eng.p)
            a = ask(eng, 0, kind, rcpt, ws)
            times.setdefault(kind, []).append(cpu(eng.p) - t0)
            self.assertEqual(sorted(d for d, _, _ in a["entries"]), sorted(want), (kind, batch))
            if r < 7:  # the other store answers the same entries and reference set
                b = ask(pre, 1, kind, rcpt, ws)
                self.assertEqual((b["entries"], b["rs"]), (a["entries"], a["rs"]), (kind, batch))
            rows, last = rows + len(ws), a

        for r in range(ROUNDS):
            src, fseq = 100 + r, BASE + 10 * r
            file = lambda k: h(b"file", r, k, n=64)  # noqa: E731
            asc = [member(r, i) for i in range(N)]
            back = [member(r, i, 1 if i % 2 == 0 else 2) for i in range(N)]
            send("ascending", receipt(src=src, cover=2, fseq=fseq, file=file(0)), asc, [1] * N)
            full = ("full", receipt(src=src, cover=1, fseq=fseq + 1, file=file(1)), asc, [2] * N)
            if r % 2:
                send(*full)
            # older than the source's full file, a backfilled row ends before its `cfrom`: every row differs, all written
            send("backfill", receipt(src=src, cover=2, fseq=fseq - 1, file=file(2)), back,
                 [1] * N if r % 2 else [2, 1] * (N // 2))
            if r % 2 == 0:
                send(*full)
            old = new_refs[:N // 2]
            new_refs = [excluded(r, i) for i in range(N - len(old))]
            ref = receipt(src=5, cover=2, fseq=REF - r, file=file(3))
            ws = sorted(({**w, "roff": i + 1} for i, w in enumerate(new_refs + old)), key=f.key)
            refs.append(f.ref_entry(ref, ws))
            send("late reference", ref, ws, [1] * len(new_refs) + [2] * len(old))
            if r == 6:
                prefix_rows, prefix_batches = rows, batch
                pre.close()
        self.assertEqual((rows, last["rs"]), (4 * ROUNDS * N, f.ref_set(refs)))
        eng.close()

        facts = (self.dir / "facts").read_bytes()
        tags = [facts[i] for i in range(0, len(facts), 256)]
        lift_records = tags.count(0x41)
        lifts = sum(facts[i + 6] for i in range(0, len(facts), 256) if facts[i] == 0x41)
        self.assertEqual((tags.count(0x40), lifts), (4 * ROUNDS, ROUNDS * N))
        print(f"SCALE rows {rows} records {len(tags)} facts bytes {len(facts)} lift records {lift_records} lifts {lifts} "
              f"bytes per lift {256 * lift_records / lifts:.2f}")
        for kind, ts in times.items():
            t0, t1 = statistics.median(ts[:5]), statistics.median(ts[-5:])
            print(f"SCALE engine {kind}: median first 5 rounds {t0 * 1e3:.1f} ms, last 5 {t1 * 1e3:.1f} ms, ratio {t1 / t0:.2f}")
            with self.subTest(kind):
                self.assertLessEqual(t1 / t0, BOUND)

        # the checker over the whole log and over its first 7 rounds
        rc, out, c1 = checker(self.dir)
        self.assertEqual((rc, f"VERIFIED shard 0 batches {batch} " in out), (0, True), out[-2000:])
        rc, out, c0 = checker(prefix)
        self.assertEqual((rc, f"VERIFIED shard 0 batches {prefix_batches} " in out), (0, True), out[-2000:])
        print(f"SCALE checker {c1:.2f} s for {rows} rows, {c0:.2f} s for {prefix_rows} rows, "
              f"per row ratio {c1 / rows / (c0 / prefix_rows):.2f}")
        self.assertLessEqual(c1 / rows / (c0 / prefix_rows), BOUND)
        rc, out, c2 = checker(self.dir)
        self.assertEqual((rc, "FACTS_REPLAYED" in out, f"VERIFIED shard 0 batches {batch} " in out), (0, False, True),
                         out[-2000:])
        print(f"SCALE checker resumed at the end of the log: {c2:.2f} s")

        # an open after the clean stop keeps the file; an open after a stop that was not clean admits every frame again
        nxt = fact_request(batch + 1, heads[0], receipt(src=5, cover=2, fseq=REF - ROUNDS, file=h(b"next", n=64)),
                           sorted([excluded(99, 0), {**new_refs[0], "roff": 2}], key=f.key))
        got = {}
        for name in ("clean", "not clean"):
            d = Path(self.tmp.name) / name.replace(" ", "-")
            shutil.copytree(self.dir, d)
            if name == "not clean":
                (d / "clean").write_bytes(b"\x00")
            e = ec.fw.Engine(d, ec.NEW)
            try:
                got[name] = (e.send(nxt), cpu(e.p))
            finally:
                e.close()
            got[name] += ((d / "facts").read_bytes(),)
        print(f"SCALE open and one frame: after a clean stop {got['clean'][1]:.2f} s, otherwise {got['not clean'][1]:.2f} s")
        self.assertEqual((got["clean"][0], got["clean"][2]), (got["not clean"][0], got["not clean"][2]))
        self.assertEqual(sorted(d for d, _, _ in f.decode_answer(got["clean"][0])["entries"]), [1, 2])

    def test_tail_checker_does_not_rework_the_facts_per_decision_frame(self):
        """A checker following the log (`rows-tail`) saves its last state after every run of frames.  After 20,000 fact
        rows, 150 decision frames arrive one by one (the facts do not change); the follower's processor time must stay
        within 1.6 times a checker over the finished log.  Flattening and hashing the whole fact store per saved state
        (about 5 MB each here) costs more than the rest of the check together."""
        batch, head = 1, ec.fw.GENESIS
        eng = ec.fw.Engine(self.dir, ec.NEW)
        self.addCleanup(eng.close)
        why, _, head, *_ = ec.fw.read(request(1, head), eng.send(request(1, head)))
        self.assertIsNone(why)
        for r in range(20):
            batch += 1
            ws = sorted((member(r, i) for i in range(N)), key=f.key)
            rcpt = receipt(src=100 + r, cover=2, fseq=BASE + 10 * r, file=h(b"file", r, 0, n=64))
            a = f.decode_answer(eng.send(fact_request(batch, head, {**rcpt, "frows": len(ws)}, ws)))
            head = a["head"]
        vdir = Path(self.tmp.name) / "tail.verify"
        p = subprocess.Popen([str(v3.VERIFY), str(self.dir), "0", "rows-tail", str(vdir), "4000"],
                             env={**os.environ, "RR_V3_SKIP": "", "RR_V3_PROGRESS": "1"}, stdout=subprocess.PIPE, text=True)
        lines, first = [], threading.Event()

        def drain():
            for row in p.stdout:
                lines.append(row)
                if row.startswith("PROGRESS"):
                    first.set()

        reader = threading.Thread(target=drain, daemon=True)
        reader.start()
        # the follower has checked the 20,000 fact rows once it reports its first saved state, and then waits for frames
        self.assertTrue(first.wait(300), "the follower reported no progress")
        for _ in range(150):
            batch += 1
            why, _, head, *_ = ec.fw.read(request(batch, head), eng.send(request(batch, head)))
            self.assertIsNone(why)
            time.sleep(0.02)
        eng.close()
        p.wait(timeout=1800)
        reader.join(60)
        out = "".join(lines)
        c_tail = cpu(p)
        self.assertEqual((p.returncode, f"VERIFIED shard 0 batches {batch} " in out), (0, True), out[-2000:])
        off = Path(self.tmp.name) / "off.verify"
        p = subprocess.Popen([str(v3.VERIFY), str(self.dir), "0", "rows-offline", str(off)], stdout=subprocess.PIPE, text=True)
        out = p.communicate(timeout=1800)[0]
        c_off = cpu(p)
        self.assertEqual((p.returncode, f"VERIFIED shard 0 batches {batch} " in out), (0, True), out[-2000:])
        print(f"SCALE tail checker {c_tail:.2f} s, offline checker {c_off:.2f} s, ratio {c_tail / c_off:.2f}")
        self.assertLessEqual(c_tail / c_off, 1.6)


if __name__ == "__main__":
    unittest.main()
