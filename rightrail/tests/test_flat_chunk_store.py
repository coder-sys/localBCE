"""The chunk store on disk, one append-only log of frames (conformance/FLAT_V1.md): a store reloaded after every batch is the
store of one resident engine; a flipped byte of any frame's header, metadata or trailer, a cut trailer, a missing or extra
file, a duplicated or missing frame and two frames past the signed head each refuse the open and leave the files alone; a
torn tail is cut and the next batch appends cleanly; a whole frame past the signed head is kept; a flipped page byte holds
the batch that reads it (test-only exes; synthetic, non-PHI)."""

import os
import random
import shutil
import struct
import tempfile
import unittest
from pathlib import Path

from tests import test_flat_worker as fw

N = 4  # batches of the store the tamper tests damage: with a directory of 8 buckets, the later batches grow it
CHECK = "RR_FLAT_CHECK"


def frames(log: bytes) -> list[tuple[int, int, int, int, int]]:
    """The whole frames of a log: (start, pages, metadata length, trailer length, size)."""
    out, o = [], 0
    while o + 16 <= len(log) and log[o:o + 4] == b"RRF2":
        np_, ml, tl = struct.unpack("<III", log[o + 4:o + 16])
        n = 16 + np_ * fw.PAGE + ml + tl
        if o + n > len(log):
            break
        out.append((o, np_, ml, tl, n))
        o += n
    return out


@unittest.skipUnless(os.name == "nt" and fw.ENGINE.is_file() and fw.ONE.is_file() and fw.CRASH.is_file(),
                     f"CHUNK STORE NOT RUN: {fw.ENGINE}, {fw.ONE} or {fw.CRASH} is missing")
class ChunkStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        rng = random.Random(21)
        self.reqs = [fw.batch(rng, k, 12)[0] for k in range(9)]  # batch 2's fixed rows repeat batch 0's keys

    def engine(self, d: Path, exe: Path = fw.ENGINE, env: dict | None = None) -> fw.Engine:
        eng = fw.Engine(d, exe, env)
        self.addCleanup(eng.close)
        return eng

    def chain(self, name: str, n: int, env: dict | None = None, upto: int | None = None):
        """Batches 0 to n-1, each in its own process (every one loads the store from disk): the heads after each and the answers."""
        d, heads, outs = self.tmp / name, [], []
        for k in range(upto if upto is not None else n):
            eng = fw.Engine(d, env=env)
            data, out = eng.ask(k, heads[-1] if heads else fw.GENESIS, self.reqs[k])
            eng.close()
            why, _, head, *_ = fw.read(data, out)
            self.assertIsNone(why)
            heads.append(head)
            outs.append(out)
        return d, heads, outs

    def test_a_store_reloaded_after_every_batch_is_the_store_of_one_resident_engine(self):
        chk = self.tmp / "check.txt"
        d, heads, outs = self.chain("each", 8, {**fw.NB, CHECK: str(chk)})
        r = self.tmp / "resident"
        eng = fw.Engine(r, env=fw.NB)
        for k in range(8):
            data, out = eng.ask(k, heads[k - 1] if k else fw.GENESIS, self.reqs[k])
            self.assertEqual(out, outs[k], f"batch {k}")  # decisions, duplicates of earlier keys included
        eng.close()
        self.assertEqual(fw.snap(r), fw.snap(d))
        lines = chk.read_text().splitlines()
        self.assertEqual(len([x for x in lines if x.startswith("batch ")]), 8)
        self.assertFalse([x for x in lines if " same false" in x or "roundtrip false" in x], lines)  # the fast codecs equal the model's
        self.assertEqual([x for x in lines if x.startswith("load frames")], [f"load frames {k} replayed {k}" for k in range(1, 8)])
        self.assertEqual(sorted(p.name for p in d.iterdir()), ["lock", "log"])  # nothing but the log and its lock

    def test_a_flipped_page_byte_holds_the_batch_that_reads_it(self):
        d, heads, _ = self.chain("p", 1)
        path = d / "log"
        good = path.read_bytes()
        pages = frames(good)[0][1]
        self.assertGreaterEqual(pages, 1)  # batch 1's reads of batch 0's keys read them
        bad = bytearray(good)
        for i in range(pages):
            bad[16 + i * fw.PAGE + 3] ^= 0x01
        path.write_bytes(bytes(bad))
        eng = fw.Engine(d)
        data, out = eng.ask(1, heads[0], self.reqs[1])
        eng.close()
        held = fw.read(data, out)
        self.assertEqual(held[0], "flat_corrupt")
        self.assertEqual((held[1], held[5], held[6]), ([], [], []))  # nothing is released
        path.write_bytes(good)  # nothing was written: the repaired store answers
        eng = self.engine(d)
        self.assertIsNone(fw.read(*eng.ask(1, heads[0], self.reqs[1]))[0])

    def refused(self, eng, head: bytes, n: int, why: str | None = None) -> None:
        data, out = eng.ask(n, head, self.reqs[N])
        got = fw.read(data, out)
        self.assertIsNotNone(got[0], got)
        if why:
            self.assertEqual(got[0], f"flat_{why.lower()}")
        self.assertEqual((got[1], got[5], got[6]), ([], [], []))

    def accepted(self, eng, head: bytes, n: int, reqs=None) -> None:
        data, out = eng.ask(n, head, self.reqs[n] if reqs is None else reqs)
        self.assertIsNone(fw.read(data, out)[0])

    def test_a_flipped_byte_of_any_frame_refuses_the_open(self):
        """Every frame's header, metadata and trailer is read at load, along the chain to the signed head: one flipped bit anywhere
        in them refuses the open and writes nothing (the pages are checked when a batch reads them, see the page test)."""
        d, heads, _ = self.chain("t", N, fw.NB)
        eng = self.engine(d)
        before = fw.snap(d)
        path = d / "log"
        good = before["log"]
        for k, (start, np_, ml, tl, size) in enumerate(frames(good)):
            md = start + 16 + np_ * fw.PAGE
            regions = {"header": range(start, start + 16), "metadata": range(md, md + ml, max(1, ml // 150)),
                       "trailer": range(md + ml, start + size, 3)}
            for region, offs in regions.items():
                for i in offs:
                    with self.subTest(frame=k, region=region, byte=i):
                        bad = bytearray(good)
                        bad[i] ^= 0x01
                        path.write_bytes(bytes(bad))
                        self.refused(eng, heads[-1], N)  # each refusal leaves no store open, so the next one reads the disk
        path.write_bytes(good)
        self.assertEqual(fw.snap(d), before)  # a refused open writes nothing
        self.accepted(eng, heads[-1], N)

    def test_a_cut_trailer_is_no_frame_and_the_signed_head_is_not_found(self):
        d, heads, _ = self.chain("c", N, fw.NB)
        eng = self.engine(d)
        before = fw.snap(d)
        start, np_, ml, tl, size = frames(before["log"])[-1]
        for cut in (1, 2, tl // 2, tl - 1, tl):
            with self.subTest(cut=cut):
                (d / "log").write_bytes(before["log"][:start + size - cut])
                self.refused(eng, heads[-1], N, "HEAD")
        (d / "log").write_bytes(before["log"])
        self.accepted(eng, heads[-1], N)

    def test_missing_extra_duplicated_and_surplus_files_are_refused(self):
        d, heads, _ = self.chain("f", N, fw.NB)
        before = fw.snap(d)
        eng = self.engine(d)
        fr = frames(before["log"])
        cases = {}
        cases["an extra file"] = ({"extra": b"x"}, heads[-1], N, "FILES")
        cases["an image of an older format"] = ({"img1": b"x"}, heads[-1], N, "FILES")
        cases["a v1 chunk file"] = ({"chunk0.dat": b"x"}, heads[-1], N, "FILES")
        mid = fr[-2][0] + fr[-2][4]
        cases["a frame twice"] = ({"log": before["log"][:mid] + before["log"][fr[-2][0]:]}, heads[-1], N, None)
        cases["a frame cut off"] = ({"log": before["log"][:fr[-1][0]]}, heads[-1], N, "HEAD")
        cases["the first frame cut off"] = ({"log": before["log"][fr[0][4]:]}, heads[-1], N, None)
        cases["two frames past the signed head"] = ({}, heads[N - 3], N - 2, "HEAD")
        cases["the signed head of another batch count"] = ({}, heads[-1], N + 1, "HEAD")
        for name, (change, head, n, why) in cases.items():
            with self.subTest(name):
                for fn, data in change.items():
                    (d / fn).write_bytes(data)
                self.refused(eng, head, n, why)
                for fn in ("extra", "img1", "chunk0.dat"):
                    (d / fn).unlink(missing_ok=True)
                for fn, data in before.items():
                    (d / fn).write_bytes(data)
                self.assertEqual(fw.snap(d), before)
        # one whole frame past the signed head is kept for a retry of its request, never refused and never cut
        self.accepted(eng, heads[N - 2], N - 1, self.reqs[N - 1])
        self.assertEqual(fw.snap(d)["log"], before["log"])
        self.accepted(eng, heads[-1], N)

    def test_a_store_with_no_buckets_is_refused_before_any_file_is_written(self):
        d = self.tmp / "nb0"
        eng = self.engine(d, env={"RR_FLAT_NB": "0"})
        got = fw.read(*eng.ask(0, fw.GENESIS, self.reqs[0]))
        self.assertEqual(got[0], "flat_init")
        self.assertEqual((got[1], got[5], got[6]), ([], [], []))
        self.assertEqual(fw.snap(d) if d.is_dir() else {}, {})

    def test_a_torn_tail_is_cut_and_the_next_batch_appends_as_without_it(self):
        d, heads, outs = self.chain("full", N, fw.NB)
        ref = fw.snap(d)
        start, size = frames(ref["log"])[-1][0], frames(ref["log"])[-1][4]
        torn = {f"cut {c}": (lambda b, c=c: b[:start + c]) for c in sorted({0, 1, 3, 15, 16, 17, 100, size // 2, size - 60, size - 1})}
        torn["4 KiB of zeros"] = lambda b: b[:start] + bytes(4096)
        torn["garbage after the frame"] = lambda b: b + bytes(range(1, 200))
        torn["whole frame and zeros"] = lambda b: b + bytes(4096)
        for name, damage in torn.items():
            with self.subTest(name):
                dd = self.tmp / "torn"
                shutil.rmtree(dd, ignore_errors=True)
                shutil.copytree(d, dd, ignore=shutil.ignore_patterns("lock"))
                (dd / "log").write_bytes(damage((dd / "log").read_bytes()))
                eng = fw.Engine(dd)
                data, out = eng.ask(N - 1, heads[N - 2], self.reqs[N - 1])
                eng.close()
                self.assertEqual(out, outs[N - 1])
                self.assertEqual(fw.snap(dd), ref)
        # a tail whose bytes follow the signed head's frame is cut when the signed head is the last one
        dd = self.tmp / "tail"
        shutil.copytree(d, dd, ignore=shutil.ignore_patterns("lock"))
        (dd / "log").write_bytes((dd / "log").read_bytes() + bytes(range(1, 200)))
        eng = self.engine(dd)
        self.accepted(eng, heads[-1], N)
        log = fw.snap(dd)["log"]
        self.assertEqual(log[:len(ref["log"])], ref["log"])  # the garbage is gone: the next frame follows the last one
        self.assertEqual(log[len(ref["log"]):len(ref["log"]) + 4], b"RRF2")

    def test_a_reload_after_a_kill_keeps_every_earlier_key_a_duplicate(self):
        """Batch 2 repeats batch 0's keys: after a reload and after a kill and recovery they are still found."""
        d, heads, _ = self.chain("k", 3, fw.NB, upto=2)
        eng = fw.Engine(d, fw.CRASH, {**fw.NB, "RR_FLAT_CRASH": "frame-write"})
        self.assertEqual(eng.ask(2, heads[1], self.reqs[2])[1], b"")
        self.assertEqual(eng.p.wait(timeout=60), 99)
        eng = fw.Engine(d, env=fw.NB)
        data, again = eng.ask(2, heads[1], self.reqs[2])
        eng.close()
        ref_d, _, ref_outs = self.chain("kref", 3, fw.NB)
        self.assertEqual(again, ref_outs[2])
        self.assertEqual(fw.snap(d), fw.snap(ref_d))


if __name__ == "__main__":
    unittest.main()
