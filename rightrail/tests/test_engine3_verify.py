"""Tamper tests of the engine v3 verifier `gate_verify3` (conformance/ENGINE_V3.md section 10), and its cost run.

One store is made by `gate_hist3` (rows files) over the mixed corpus of engine3_compare.  Each test copies it, tampers, and runs the
checker on its own history (the `rows-` modes).  Each tampering is caught by one check; `RR_V3_SKIP` (a test hook) turns that check
off and reaches a diagnostic-only completion (exit 2), never verification. This proves the check catches the tampering without
making an acceptance claim.

    python -m tests.test_engine3_verify cost mixed|hot [LINES [BATCH]]      (engine alone, verifier offline, both in tail mode)

Synthetic, nonpayment, non-PHI."""

import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from tests import engine3_compare as ec

VERIFY = ec.fw.BIN / "gate_verify3.exe"
LINES, BATCH = 50000, 2000


def drive(d: Path, kind: str, total: int, batch: int = BATCH, hook=None, exe: Path = ec.NEW) -> dict:
    """The engine `exe` on `d` over the corpus; `hook()` is called after the init batch (the key and the log exist then)."""
    bodies = []
    for built in range(0, total, batch):
        k = min(batch, total - built)
        bodies.append([ec.line_body(i, t, kind == "hot") for i, t in enumerate(ec.gate_corpus.lines(ec.gb.SEED, built, k, total), built)])
    eng = ec.fw.Engine(d, exe)
    head, n, lines, secs = ec.fw.GENESIS, 0, 0, 0.0
    t_all = time.perf_counter()
    for b in [[]] + bodies:
        n += 1
        data = ec.decider.request_frame(ec.g.HEAD, 0, n, ec.g.ASOF, head, ec.g.PIN, ec.fw.floors(head), ec.g.KEYS, ec.g.GRANT, ec.RELEASE, (), b)
        t = time.perf_counter()
        out = eng.send(data)
        secs += time.perf_counter() - t
        why, recs, head = ec.fw.read(data, out)[:3]
        if why is not None:
            raise RuntimeError(f"batch {n} refused: {why}")
        lines += len(recs)
        if n == 1 and hook:
            hook()
    eng.close()
    return {"lines": lines, "batches": n, "send_s": secs, "wall_s": time.perf_counter() - t_all}


def verify(d: Path, mode: str = "rows-offline", skip: str = "", idle: int = 3000, wait: bool = True, batches: int | None = None):
    env = {**os.environ, "RR_V3_SKIP": skip}
    cmd = [str(VERIFY), str(d), "0", mode, str(d) + ".verify", str(idle)] + ([] if batches is None else [str(batches)])
    if not wait:
        return subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, text=True)
    r = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=1800)
    return r.returncode, r.stdout


def frames(log: bytes):
    pos = 0
    while pos + 16 <= len(log) and log[pos : pos + 4] == b"RRF4":
        rq, an, tr = struct.unpack("<III", log[pos + 4 : pos + 16])
        if pos + 16 + rq + an + tr > len(log):
            break
        yield pos, rq, an, tr
        pos += 16 + rq + an + tr


class Verify3Rows(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(tempfile.mkdtemp(prefix="e3verh_", dir=os.environ.get("E3_SCRATCH")))
        cls.store = cls.root / "store"
        cls.store.mkdir()
        r = drive(cls.store, "mixed", LINES, exe=ec.NEW)
        cls.batches, cls.lines = r["batches"], r["lines"]

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root, ignore_errors=True)

    def test_clean_offline_and_tail(self):
        rc, out = verify(self.store, "rows-offline", batches=self.batches)
        self.assertEqual(rc, 0, out)
        self.assertIn(f"VERIFIED shard 0 batches {self.batches} lines {self.lines} ", out)
        rc, out = verify(self.store, "rows-tail", idle=300)
        self.assertEqual(rc, 0, out)

    def test_the_removed_chunk_store_modes_are_refused(self):
        for mode in ("offline", "tail", "rows-", "rows-other"):
            rc, out = verify(self.store, mode)
            self.assertEqual((rc, "VERIFIED" in out), (64, False), out)

    def test_flipped_request_byte(self):
        # a byte of the first request and of a later one (the engine does not read an earlier frame's request on load)
        for n in (1, 6):
            d = self.copy(f"request{n}")
            raw = bytearray((d / "log").read_bytes())
            pos, *_ = list(frames(bytes(raw)))[n - 1]
            raw[pos + 16 + 100] ^= 1
            (d / "log").write_bytes(bytes(raw))
            rc, out = verify(d)
            self.assertEqual((rc, f"batch {n} " in out, "VERIFIED" in out), (3, True, False), out)

    def copy(self, name: str) -> Path:
        d = self.root / name
        shutil.copytree(self.store, d)
        return d

    def assert_diagnostic(self, directory, skipped):
        rc, out = verify(directory, skip=skipped)
        self.assertEqual(rc, 2, out)
        self.assertIn("DIAGNOSTIC_INCOMPLETE shard 0", out)
        self.assertNotIn("VERIFIED", out)

    def test_expected_count(self):
        d = self.copy("count")
        rc, out = verify(d, batches=self.batches)
        self.assertEqual(rc, 0, out)
        self.assertIn(f"VERIFIED shard 0 batches {self.batches} ", out)
        rc, out = verify(d, batches=self.batches + 1)
        self.assertEqual((rc, "VERIFY_COUNT(0)" in out, "VERIFIED" in out), (3, True, False), out)

    def test_empty_and_cut_log(self):
        d = self.copy("cut")
        raw = (d / "log").read_bytes()
        pos, *_ = list(frames(raw))[3]
        (d / "log").write_bytes(raw[:pos])  # frames 1-3 kept, every later one cut
        rc, out = verify(d, batches=self.batches)
        self.assertEqual((rc, f"expected {self.batches} batches, log has 3" in out, "VERIFIED" in out), (3, True, False), out)
        (d / "log").write_bytes(b"")
        rc, out = verify(d)
        self.assertEqual((rc, "VERIFY_EMPTY(0)" in out, "VERIFIED" in out), (4, True, False), out)

    def test_answer_flip_is_what_the_answer_check_stops(self):
        d = self.copy("answer-skip")
        raw = bytearray((d / "log").read_bytes())
        pos, rq, an, tr = list(frames(bytes(raw)))[5]
        raw[pos + 16 + rq + an // 2] ^= 1
        (d / "log").write_bytes(bytes(raw))
        self.assert_diagnostic(d, "answer")

    def flip_in(self, name: str, *tampers):
        """A copy with `("answer"|"head", frame number)` tamperings; the verifier's exit code and output."""
        d = self.copy(name)
        raw = bytearray((d / "log").read_bytes())
        fs = list(frames(bytes(raw)))
        for what, n in tampers:
            pos, rq, an, tr = fs[n - 1]
            raw[pos + 16 + rq + an // 2 if what == "answer" else pos + 16 + rq + an + tr - 1] ^= 1
        (d / "log").write_bytes(bytes(raw))
        return verify(d)

    def test_earlier_of_two_tampered_frames_is_reported(self):
        # batch 6's answer is checked on another core, batch 7's head on the frame path: batch 6 is still the one named
        rc, out = self.flip_in("two", ("answer", 6), ("head", 7))
        self.assertEqual((rc, "batch 6 answer" in out, "batch 7" in out), (3, True, False), out)

    def test_a_late_error_far_before_the_next_error_is_reported(self):
        rc, out = self.flip_in("far", ("answer", 6), ("head", 10))
        self.assertEqual((rc, "batch 6 answer" in out, "batch 10" in out), (3, True, False), out)

    def test_the_earlier_of_two_late_errors_is_reported(self):
        rc, out = self.flip_in("lates", ("answer", 8), ("answer", 6))
        self.assertEqual((rc, "batch 6 answer" in out, "batch 8" in out), (3, True, False), out)

    def test_within_one_frame_the_earlier_check_is_reported(self):
        rc, out = self.flip_in("same", ("answer", 6), ("head", 6))
        self.assertEqual((rc, "batch 6 answer" in out), (3, True), out)

    def test_a_torn_tail_is_refused_with_its_offset_and_batch(self):
        d = self.copy("torn")
        raw = (d / "log").read_bytes()
        fs = list(frames(raw))
        pos = fs[-1][0]
        (d / "log").write_bytes(raw[: pos + 40])  # the last frame cut inside its request
        rc, out = verify(d)
        self.assertEqual((rc, f"TORN_TAIL(0) batch {len(fs)} offset {pos}" in out, "VERIFIED" in out), (3, True, False), out)
        (d / "log").write_bytes(raw + b"RRF4\0")  # a header cut short after the last whole frame
        rc, out = verify(d)
        self.assertEqual((rc, f"TORN_TAIL(0) batch {len(fs) + 1} offset {len(raw)}" in out, "VERIFIED" in out), (3, True, False), out)

    def test_flipped_answer_and_head_bytes(self):
        for what, n, seen in (("answer", 6, "batch 6 answer"), ("head", 6, "batch 6 head")):
            d = self.root / what
            shutil.copytree(self.store, d)
            raw = bytearray((d / "log").read_bytes())
            pos, rq, an, tr = list(frames(bytes(raw)))[n - 1]
            raw[pos + 16 + rq + an // 2 if what == "answer" else pos + 16 + rq + an + tr - 1] ^= 1
            (d / "log").write_bytes(bytes(raw))
            rc, out = verify(d, "rows-offline")
            self.assertEqual((rc, seen in out, "VERIFIED" in out), (3, True, False), out)

    def checked(self, name: str, kept: int | None = None):
        """A copy of the store, its log cut to its first `kept` frames, checked once: the copy, its checker's directory, the whole log."""
        d = self.root / name
        shutil.copytree(self.store, d)
        full = (d / "log").read_bytes()
        if kept:
            pos, rq, an, tr = list(frames(full))[kept - 1]
            (d / "log").write_bytes(full[: pos + 16 + rq + an + tr])
        rc, out = verify(d, "rows-offline")
        self.assertEqual((rc, "VSTORE_REFUSED" in out), (0, False), out)
        return d, Path(str(d) + ".verify"), full

    @staticmethod
    def counts(out: str):
        """The lines verified in all and the lines checked by this start."""
        m = re.search(r"VERIFIED shard 0 batches \d+ lines (\d+) \(this start (\d+)\)", out)
        return (int(m[1]), int(m[2])) if m else None

    def test_resume_and_rollback_of_the_checker_store(self):
        d, vd, full = self.checked("resume", 10)
        snap = self.root / "resume.snap"
        shutil.copytree(vd, snap)
        (d / "log").write_bytes(full)
        rc, out = verify(d, "rows-offline", batches=self.batches)
        total, now = self.counts(out) or (0, 0)
        self.assertEqual((rc, "VSTORE_REFUSED" in out, total, 0 < now < total), (0, False, self.lines, True), out)
        rc, out = verify(d, "rows-offline", batches=self.batches)
        self.assertEqual((rc, "VSTORE_REFUSED" in out, self.counts(out)), (0, False, (self.lines, 0)), out)
        # the sets' files rolled back alone, with tags that hold: their counts are not the last state's
        for f in ("vrows_rel", "vrows_unr"):
            shutil.copy(snap / f, vd / f)
        rc, out = verify(d, "rows-offline", batches=self.batches)
        self.assertEqual((rc, "VSTORE_REFUSED(0) the store holds" in out, self.counts(out)), (0, True, (self.lines, self.lines)), out)
        # all of the checker's state rolled back together resumes there and checks the later frames again; whether the last
        # state is the newest is the TPM's check, a later step
        shutil.rmtree(vd)
        shutil.copytree(snap, vd)
        rc, out = verify(d, "rows-offline", batches=self.batches)
        self.assertEqual((rc, "VSTORE_REFUSED" in out, self.counts(out)), (0, False, (self.lines, now)), out)

    def test_a_changed_store_or_last_state_is_refused_then_healed(self):
        d, vd, _ = self.checked("tamper")
        ref = self.root / "tamper.ref"
        shutil.copytree(vd, ref)
        big = max((vd / "vrows_rel", vd / "vrows_unr"), key=lambda f: f.stat().st_size)
        half = 320 * (big.stat().st_size // 640)

        def put(f: Path, at: int, b: bytes):
            with open(f, "r+b") as h:
                h.seek(at)
                h.write(b)

        def flip(f: Path, at: int):
            put(f, at, bytes([f.read_bytes()[at] ^ 1]))

        cases = (
            ("a row byte", lambda: flip(big, half + 40), "the store holds"),
            ("a link byte", lambda: flip(big, half + 250), "the store holds"),
            ("a tag byte", lambda: flip(big, half + 300), "the store holds"),
            ("a record replayed at another place", lambda: put(big, half, big.read_bytes()[:320]), "the store holds"),
            ("the last state", lambda: flip(vd / "vlast", 30), "the last state fails its tag"),
            ("the key", lambda: (vd / "vkey").unlink(), "no key opens"),
        )
        self.assertGreater(half, 0)
        for what, tamper, cause in cases:
            with self.subTest(what):
                shutil.rmtree(vd)
                shutil.copytree(ref, vd)
                tamper()
                rc, out = verify(d, "rows-offline", batches=self.batches)
                self.assertEqual((rc, f"VSTORE_REFUSED(0) {cause}" in out, self.counts(out)), (0, True, (self.lines, self.lines)), out)
                rc, out = verify(d, "rows-offline", batches=self.batches)
                self.assertEqual((rc, "VSTORE_REFUSED" in out, self.counts(out)), (0, False, (self.lines, 0)), out)

    def test_a_record_changed_while_the_checker_runs_is_a_fault_then_healed(self):
        d, vd, full = self.checked("live", 10)
        cut = (d / "log").stat().st_size
        p = verify(d, "rows-tail", idle=4000, wait=False)
        time.sleep(3)  # it has resumed, so the records of the first ten frames are read from the file again
        for f in ("vrows_rel", "vrows_unr"):
            with open(vd / f, "r+b") as h:
                b = bytearray(h.read())
                for at in range(40, len(b), 320):
                    b[at] ^= 1
                h.seek(0)
                h.write(b)
        with open(d / "log", "ab") as h:
            h.write(full[cut:])
        out = p.communicate(timeout=600)[0]
        self.assertIn("VSTORE_REFUSED(0) VSTORE_FAULT", out)
        self.assertEqual((p.returncode, self.counts(out)), (0, (self.lines, self.lines)), out)

    def test_a_log_changed_after_it_was_checked_is_checked_again(self):
        d, _, full = self.checked("relog")
        (d / "log").write_bytes(full[:-1] + bytes([full[-1] ^ 1]))
        rc, out = verify(d, "rows-offline")
        seen = ("VSTORE_REFUSED(0) the log does not hold the checked head" in out, f"batch {self.batches} head" in out, "VERIFIED" in out)
        self.assertEqual((rc, seen), (3, (True, True, False)), out)


def cost(kind: str, total: int, batch: int) -> None:
    root = Path(tempfile.mkdtemp(prefix=f"e3cost_{kind}_", dir=os.environ.get("E3_SCRATCH")))
    a = drive(root / "alone", kind, total, batch) if (root / "alone").mkdir() is None else None
    print(f"ENGINE ALONE {kind}: lines {a['lines']} batches {a['batches']} engine-seconds {a['send_s']:.1f} lines/s {a['lines'] / a['send_s']:.0f} (wall incl. host {a['lines'] / a['wall_s']:.0f})", flush=True)
    t = time.perf_counter()
    rc, out = verify(root / "alone")
    print(f"VERIFIER OFFLINE {kind}: exit {rc} elapsed {time.perf_counter() - t:.1f}s\n{out}", flush=True)
    (root / "both").mkdir()
    p = []
    t = time.perf_counter()
    b = drive(root / "both", kind, total, batch, hook=lambda: p.append(verify(root / "both", "rows-tail", idle=2000, wait=False)))
    out = p[0].communicate()[0]
    print(f"BOTH TAIL {kind}: engine lines {b['lines']} engine-wall {b['wall_s']:.1f}s -> {b['lines'] / b['wall_s']:.0f} lines/s; verifier exit {p[0].returncode}\n{out}", flush=True)
    shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__" and len(sys.argv) > 2 and sys.argv[1] == "cost":
    cost(sys.argv[2], int(sys.argv[3]) if len(sys.argv) > 3 else 300000, int(sys.argv[4]) if len(sys.argv) > 4 else BATCH)
elif __name__ == "__main__":
    unittest.main()
