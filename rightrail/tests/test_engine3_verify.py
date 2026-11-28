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


def drive(d: Path, kind: str, total: int, batch: int = BATCH, hook=None, exe: Path = ec.NEW, *, grants=None, env: dict | None = None, after=None, answers: list | None = None) -> dict:
    """The engine `exe` on `d` over the corpus; `hook()` is called after the init batch (the key and the log exist then).
    `grants[n - 1]` is batch n's grant (default: the standing one); `env` is added to the engine's environment; `after=(head, n)`
    continues a store whose last batch was n and ended at `head` (no init batch is sent); each answer is appended to `answers`."""
    bodies = []
    for built in range(0, total, batch):
        k = min(batch, total - built)
        bodies.append([ec.line_body(i, t, kind == "hot") for i, t in enumerate(ec.gate_corpus.lines(ec.gb.SEED, built, k, total), built)])
    eng = ec.fw.Engine(d, exe, env)
    (head, n), lines, secs = after or (ec.fw.GENESIS, 0), 0, 0.0
    t_all = time.perf_counter()
    for b in ([] if after else [[]]) + bodies:
        n += 1
        grant = grants[n - 1] if grants else ec.g.GRANT
        data = ec.decider.request_frame(ec.g.HEAD, 0, n, ec.g.ASOF, head, ec.g.PIN, ec.fw.floors(head), ec.g.KEYS, grant, ec.RELEASE, (), b)
        t = time.perf_counter()
        out = eng.send(data)
        secs += time.perf_counter() - t
        if answers is not None:
            answers.append(out)
        why, recs, head = ec.fw.read(data, out)[:3]
        if why is not None:
            raise RuntimeError(f"batch {n} refused: {why}")
        lines += len(recs)
        if n == 1 and hook:
            hook()
    eng.close()
    return {"lines": lines, "batches": n, "send_s": secs, "wall_s": time.perf_counter() - t_all, "head": head}


def verify(d: Path, mode: str = "rows-offline", skip: str = "", idle: int = 3000, wait: bool = True, batches: int | None = None, env: dict | None = None):
    env = {**os.environ, "RR_V3_SKIP": skip, **(env or {})}
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
        # a body byte of the first request and of a later one (the engine does not read an earlier frame's request on load),
        # and a byte of the digest in a request's header: the checker recomputes the digest the engine carried
        for n, at in ((1, 100), (6, 100), (6, 30)):
            d = self.copy(f"request{n}-{at}")
            raw = bytearray((d / "log").read_bytes())
            pos, *_ = list(frames(bytes(raw)))[n - 1]
            raw[pos + 16 + at] ^= 1
            (d / "log").write_bytes(bytes(raw))
            rc, out = verify(d)
            self.assertEqual((rc, f"batch {n} frame digest:" in out, "VERIFIED" in out), (3, True, False), out)

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


class KeptAdmission(unittest.TestCase):
    """The engine and the checker each reuse their last admission while every admission input is the same (`admitC`);
    `RR_E3_ADMIT_FRESH` (a test hook) admits every batch in full instead.  Both must give the same bytes, also across a batch
    that differs from the one before it in the grant alone.  The runs continue copies of one store (one key, so equal requests
    have equal answers) at the product's spec-check rate (1 batch in 64), so no per-batch spec check stands in for the test."""

    PER, DATA = 500, 6  # lines per batch, batches after the init batch

    @classmethod
    def setUpClass(cls):
        cls.root = Path(tempfile.mkdtemp(prefix="e3adm_", dir=os.environ.get("E3_SCRATCH")))
        cls.addClassCleanup(shutil.rmtree, cls.root, ignore_errors=True)
        (cls.root / "seed").mkdir()
        init = drive(cls.root / "seed", "mixed", 0)  # the init batch alone: it makes the store's key
        # the standing grant at OBSERVE level: same tenant, program, flows, serial and signers; other bytes, another grant id
        cls.observe = ec.g.au.grant([(ec.fx.PROGRAM, 1 << 1 | 1 << 3, 1, 0)])
        cls.grants = [ec.g.GRANT] * 3 + [cls.observe] * 2 + [ec.g.GRANT] * 2  # by batch; batch 1 is the init batch (nothing admitted)
        cls.runs = {}
        for name, grants in (("same", None), ("changed", cls.grants)):
            for fresh in (False, True):
                d, answers = cls.root / f"{name}-{'fresh' if fresh else 'kept'}", []
                shutil.copytree(cls.root / "seed", d)
                r = drive(d, "mixed", cls.PER * cls.DATA, cls.PER, grants=grants, env=cls.env(fresh), after=(init["head"], 1), answers=answers)
                cls.runs[name, fresh] = d, r, answers

    @staticmethod
    def env(fresh: bool) -> dict:
        return {"RR_E3_SPEC": "64", **({"RR_E3_ADMIT_FRESH": "1"} if fresh else {})}

    def test_kept_and_fresh_admission_give_the_same_answer_bytes(self):
        for name in ("same", "changed"):
            (_, r, kept), (_, _, fresh) = self.runs[name, False], self.runs[name, True]
            self.assertEqual((r["batches"], r["lines"], len(kept)), (1 + self.DATA, self.PER * self.DATA, self.DATA), name)
            self.assertTrue(kept == fresh, name)  # not assertEqual: its diff of two unequal long answer lists does not finish

    def test_a_batch_whose_grant_alone_changed_is_admitted_anew(self):
        same, changed = self.runs["same", False][2], self.runs["changed", False][2]  # [i] is the answer to batch i + 2
        # batches 2 and 3 are the same frames in both runs; batch 4 differs in its grant alone
        self.assertTrue(same[:2] == changed[:2] and same[2] != changed[2])
        standing, observe = ec.g.GRANT_ID, ec.g.au.grant_id(self.observe)
        for n, grant in enumerate(self.grants[1:], 2):  # each answer names its own frame's grant, never the one kept before it
            own, kept = (standing, observe) if grant == ec.g.GRANT else (observe, standing)
            self.assertEqual((own in changed[n - 2], kept in changed[n - 2]), (True, False), n)

    def test_the_checker_verifies_both_stores_with_a_kept_and_a_fresh_admission(self):
        for name in ("same", "changed"):
            d, r, _ = self.runs[name, False]
            for fresh in (False, True):
                rc, out = verify(d, batches=r["batches"], env=self.env(fresh))
                self.assertEqual(rc, 0, (name, fresh, out))
                self.assertIn(f"VERIFIED shard 0 batches {r['batches']} lines {r['lines']} ", out)
                shutil.rmtree(str(d) + ".verify")


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
