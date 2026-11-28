"""Signed rule sets on the rows-file engine `gate_hist3` (conformance/RULESET_V1.md section 9): the record a batch presents
is admitted into the shard's authority record, every later batch presents it again, and each other case holds the batch
whole and writes nothing.  A shard behind the tenant admits the record the tenant asserts and no other.  A crash, a
rolled-back or corrupt store, and the checker (`gate_verify3`) are run over stores with a rule set in force.
Synthetic, nonpayment, non-PHI."""

import os
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from tests import _gate_authority as au
from tests import engine3_compare as ec
from tests import test_engine3_facts as tf
from tests import test_engine3_recovery as rc
from tests import test_engine3_verify as ev
from tests import test_ruleset_admission as ra
from tests import test_ruleset_v1_codec as rs

# the key set the batches present: the genesis one (the store's pin) and its step to epoch 1, which adds the POLICY keys
KEYS = ec.decider.Keys(au.genesis()[1], ((au.TODAY, au.keyset_doc(au.keyset_body(1, au.genesis()[0], 20270310, 20270409,
                                                                                    extra=ra.POLICY_KEYS))),))
RUN_DOC = rs.with_(ra.BASE, version=1, prev=bytes(64), eff_from=10101, eff_to=99991231)  # runnable: pack 1 for all time
OTHER_DOC = rs.with_(RUN_DOC, not_before=ra.NB + 1)  # runnable, another digest
LATE_DOC = rs.with_(RUN_DOC, not_before=20270101, not_after=20270131)  # runnable, its signing window closed before today
LATE_OTHER_DOC = rs.with_(LATE_DOC, not_after=20270130)
EARLY_DOC = rs.with_(RUN_DOC, not_before=au.TODAY + 1)  # runnable, its signing window opens tomorrow
RUN, RUN_ID = ra.sign(RUN_DOC), ra.digest(RUN_DOC)
OTHER = ra.sign(OTHER_DOC)
UNRUNNABLE = ra.sign(ra.V1)  # admitted, but effective from 2027-01-01, not for all time
ONE_SIGNER = ra.sign(RUN_DOC, ("p1",))  # below the POLICY threshold: refused
LATE, LATE_ID = ra.sign(LATE_DOC), ra.digest(LATE_DOC)


def body(n: int) -> bytes:
    member = ec.g.member(1001, 0)
    line = ec.gate.encode_line("FFS_CLAIM", "L" + str(n).zfill(31), member, "P7001", "R7001", 20270301, "C99213", 1, 12500)
    return ec.gate.encode_decide_request(ec.gate.DecideRequest(
        ec.fx.TENANT, ec.fx.PROGRAM, "FFS_CLAIM", f"cmd-rulesets-{n}", f"pay-rulesets-{n}", member, "P7001", 12500,
        ec.fx.PERIOD, (line,), ec.EVIDENCE))


def frame(n: int, prev: bytes, records=(), floors=None, bodies=None) -> bytes:
    """Batch `n` on `prev` presenting `records`, under the floors the store reported for `prev` unless `floors`."""
    return ec.decider.request_frame(ec.g.HEAD, 0, n, ec.g.ASOF, prev, ec.g.PIN, floors or ec.fw.floors(prev), KEYS, ec.g.GRANT,
                                    ec.RELEASE, (), [body(n)] if bodies is None else bodies, rulesets=records)


def rule_set(head: bytes) -> tuple[int, bytes]:
    """The rule-set version and digest the authority record ending at `head` holds."""
    return tuple(ec.fw.floors(head)[2:])


class Engine3RuleSets(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="engine3-rulesets-", dir=os.environ.get("E3_SCRATCH"))
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def engine(self, d: Path, crash: str = ""):
        eng = ec.fw.Engine(d, ec.NEW, {"RR_E3_CRASH": crash})
        self.addCleanup(eng.close)
        return eng

    def ok(self, eng, data: bytes):
        why, recs, head, *_ = rc.answer(data, eng.send(data))
        self.assertIsNone(why)
        return recs, head

    def held(self, eng, d: Path, data: bytes, want: str) -> None:
        """`data` is held whole (`want`) and the log is unchanged."""
        log = (d / "log").read_bytes()
        self.assertEqual(rc.answer(data, eng.send(data))[0], want)
        self.assertEqual((d / "log").read_bytes(), log)

    def store(self, name: str):
        """A store whose first batch presented no record: (dir, engine, head)."""
        d = self.dir / name
        d.mkdir()
        eng = self.engine(d)
        return d, eng, self.ok(eng, frame(1, ec.fw.GENESIS))[1]

    def test_an_admitted_record_is_kept_and_every_later_batch_presents_it_again(self):
        d, eng, head = self.store("active")
        _, twin, twin_head = self.store("twin")  # the same batches with no rule set: the decisions are the same
        recs, head = self.ok(eng, frame(2, head, [RUN]))
        self.assertEqual(rule_set(head), (1, RUN_ID))
        twin_recs, twin_head = self.ok(twin, frame(2, twin_head))
        self.assertEqual([r.outcome for r in recs], [r.outcome for r in twin_recs])
        for name, records, floors, want in (
                ("no record", [], None, "grant_ruleset_missing"),
                ("no record, the zero rule set asserted", [], (*ec.fw.floors(head)[:2], 0, bytes(64)), "grant_ruleset_missing"),
                ("another runnable record", [OTHER], None, "grant_ruleset_other"),
                ("a record that cannot run", [UNRUNNABLE], None, "grant_ruleset_other"),
                ("the record twice", [RUN, RUN], None, "grant_ruleset_not_run"),
                ("the record and another", [RUN, OTHER], None, "grant_ruleset_not_run"),
                ("a later version asserted", [RUN], (*ec.fw.floors(head)[:2], 2, RUN_ID), "grant_ruleset_stale"),
                ("another digest asserted", [RUN], (*ec.fw.floors(head)[:2], 1, bytes([7]) * 64), "grant_ruleset_fork"),
                ("the record without requests", [RUN], None, "flat_record")):
            with self.subTest(name):
                self.held(eng, d, frame(3, head, records, floors, [] if want == "flat_record" else None), want)
        for n in (3, 4):
            recs, head = self.ok(eng, frame(n, head, [RUN]))
            twin_recs, twin_head = self.ok(twin, frame(n, twin_head))
            self.assertEqual(([r.outcome for r in recs], rule_set(head)), ([r.outcome for r in twin_recs], (1, RUN_ID)))
        eng.close()
        again = self.engine(d)  # a new process reads the rule set from the log
        self.held(again, d, frame(5, head), "grant_ruleset_missing")
        head = self.ok(again, frame(5, head, [RUN]))[1]
        again.close()
        code, out = ev.verify(d)
        self.assertEqual(code, 0, out)
        self.assertIn("VERIFIED shard 0 batches 5 ", out)

    def test_a_first_record_that_is_refused_or_cannot_run_holds_the_batch(self):
        d, eng, head = self.store("first")
        for name, records, want in (("refused", [ONE_SIGNER], "grant_ruleset_refused"),
                                    ("signing window closed", [LATE], "grant_ruleset_refused"),
                                    ("cannot run", [UNRUNNABLE], "grant_ruleset_not_run"),
                                    ("two records", [RUN, OTHER], "grant_ruleset_not_run"),
                                    ("not a record", [b"not a rule-set record"], "grant_ruleset_refused"),
                                    ("a version asserted, none presented", [], "grant_ruleset_stale")):
            with self.subTest(name):
                floors = (*ec.fw.floors(head)[:2], 1, RUN_ID) if not records else None
                self.held(eng, d, frame(2, head, records, floors), want)
        head = self.ok(eng, frame(2, head))[1]  # the shard goes on without a rule set
        self.assertEqual(rule_set(head), (0, bytes(64)))

    def test_a_shard_behind_the_tenant_admits_the_asserted_record_and_no_other(self):
        # the tenant asserts version 1 under LATE's digest, whose signing window has closed: this shard, still at version 0,
        # admits that record and only that one
        d, eng, head = self.store("late")
        late = (*ec.fw.floors(head)[:2], 1, LATE_ID)
        for name, records, want in (("another record", [ra.sign(LATE_OTHER_DOC)], "grant_ruleset_other"),
                                    ("an open-window record", [RUN], "grant_ruleset_other"),
                                    ("the asserted record, one signer", [ra.sign(LATE_DOC, ("p1",))], "grant_ruleset_refused"),
                                    ("no record", [], "grant_ruleset_stale")):
            with self.subTest(name):
                self.held(eng, d, frame(2, head, records, late), want)
        self.held(eng, d, frame(2, head, [LATE]), "grant_ruleset_refused")  # not behind: the window applies
        # behind, but before the record's window opens: only the end of the window is waived
        early = (*ec.fw.floors(head)[:2], 1, ra.digest(EARLY_DOC))
        self.held(eng, d, frame(2, head, [ra.sign(EARLY_DOC)], early), "grant_ruleset_refused")
        head = self.ok(eng, frame(2, head, [LATE], late))[1]
        self.assertEqual(rule_set(head), (1, LATE_ID))
        head = self.ok(eng, frame(3, head, [LATE]))[1]
        eng.close()
        code, out = ev.verify(d)
        self.assertEqual(code, 0, out)

    def test_a_pending_frame_the_floors_have_passed_does_not_block_its_shard(self):
        # batch 2 is decided under rule-set version 0 and never signed, so a new process finds it pending (ENGINE_V3 section 9)
        d, eng, head = self.store("passed")
        self.ok(eng, frame(2, head))
        eng.close()
        eng = self.engine(d)
        # another request whose floors have not passed its record: CONFLICT, the pending frame kept
        self.held(eng, d, frame(2, head, bodies=[body(9)]), "flat_conflict")
        # the tenant is at version 1 now: a frame asserting it cuts the pending one and is decided in its place
        late = (*ec.fw.floors(head)[:2], 1, LATE_ID)
        head = self.ok(eng, frame(2, head, [LATE], late))[1]
        self.assertEqual(rule_set(head), (1, LATE_ID))
        log = (d / "log").read_bytes()
        self.assertEqual(len(rc.frames(log)), 2)
        t = rc.frames(log)[1][3]
        self.assertNotEqual(log[t + rc.P + rc.A + 128 : t + rc.P + rc.A + 192], bytes(64))  # the cut frame is named
        head = self.ok(eng, frame(3, head, [LATE]))[1]
        eng.close()
        code, out = ev.verify(d)
        self.assertEqual(code, 0, out)
        self.assertIn("VERIFIED shard 0 batches 3 ", out)

    def test_a_pending_fact_frame_is_never_cut(self):
        # a fact frame carries the authority record of the batch before it, so floors above that record do not pass it
        d, eng, head = self.store("fact")
        fact = tf.fact_request(2, head, tf.A, [tf.R0, tf.R1, tf.R2])
        out = eng.send(fact)
        self.assertEqual(len(tf.f.decode_answer(out)["entries"]), 3)  # decided: each row a new statement
        eng.close()
        eng = self.engine(d)
        self.held(eng, d, frame(2, head, [LATE], (*ec.fw.floors(head)[:2], 1, LATE_ID)), "flat_conflict")
        self.assertEqual(eng.send(fact), out)  # its own resend is answered as first decided

    def test_a_crash_while_a_record_is_admitted_decides_the_batch_again(self):
        for crash in ("before_append", "after_append"):
            with self.subTest(crash):
                d, eng, head = self.store(crash)
                eng.close()
                data = frame(2, head, [RUN])
                dying = self.engine(d, crash)
                self.assertEqual(dying.send(data), b"")
                dying.close()
                self.assertEqual(dying.p.returncode, 99)
                eng = self.engine(d)
                head = self.ok(eng, data)[1]
                self.assertEqual(rule_set(head), (1, RUN_ID))
                head = self.ok(eng, frame(3, head, [RUN]))[1]
                eng.close()
                code, out = ev.verify(d)
                self.assertEqual(code, 0, out)

    def test_a_rolled_back_store_is_behind_and_a_corrupt_one_is_refused(self):
        d, eng, head1 = self.store("base")
        eng.close()
        back = self.dir / "back"
        shutil.copytree(d, back, ignore=shutil.ignore_patterns("lock"))  # the store before its rule set
        eng = self.engine(d)
        head2 = self.ok(eng, frame(2, head1, [RUN]))[1]
        head3 = self.ok(eng, frame(3, head2, [RUN]))[1]
        eng.close()
        # rolled back to batch 1 while the tenant is at version 1: it holds unless it is sent the asserted record
        old = self.engine(back)
        asserted = (*ec.fw.floors(head1)[:2], 1, RUN_ID)
        self.held(old, back, frame(2, head1, [], asserted), "grant_ruleset_stale")
        self.held(old, back, frame(2, head1, [OTHER], asserted), "grant_ruleset_other")
        self.assertEqual(rule_set(self.ok(old, frame(2, head1, [RUN], asserted))[1]), (1, RUN_ID))
        old.close()
        # a logged record whose version is zeroed but whose digest is kept is refused on load, as is any edit of it
        log = (d / "log").read_bytes()
        for k in (1, 2):
            pos, _, _, t = rc.frames(log)[k]
            for name, at, value in (("version zeroed", t + rc.P + 272, bytes(4)), ("digest zeroed", t + rc.P + 208, bytes(64))):
                with self.subTest(frame=k + 1, edit=name):
                    e = self.dir / f"c{k}{name[0]}"
                    shutil.copytree(d, e, ignore=shutil.ignore_patterns("lock"))
                    raw = bytearray(log)
                    raw[at : at + len(value)] = value
                    (e / "log").write_bytes(bytes(raw))
                    self.assertEqual(rc.answer(frame(4, head3, [RUN]), self.engine(e).send(frame(4, head3, [RUN])))[0], "flat_corrupt")
        # a byte of the logged record itself: the checker refuses the frame
        e = self.dir / "edited"
        shutil.copytree(d, e, ignore=shutil.ignore_patterns("lock"))
        at = log.index(RUN) + 100
        rc.flip(e / "log", at)
        code, out = ev.verify(e)
        self.assertNotEqual(code, 0, out)
        self.assertNotIn("VERIFIED", out)
        code, out = ev.verify(d)
        self.assertEqual(code, 0, out)


class CutTestText(unittest.TestCase):
    """The theorem tying the rows-file engine's cut test to the pinned engine's is proved by `rfl` over the text it
    states, so that text must be the pinned engine's: any edit to one side and not the other fails here."""

    def test_passed_by_worker_states_the_pinned_engines_cut_test(self):
        lean = Path(__file__).resolve().parents[1] / "lean" / "BlindLedger" / "Gate"
        worker = (lean / "Flat" / "Worker.lean").read_text(encoding="utf-8")
        theorem = (lean / "Engine3" / "RuleGate.lean").read_text(encoding="utf-8")
        texts = [re.findall(pattern, text, re.S) for pattern, text in (
            (r"\n\s*let passed := (match decAuth pau with\n.*?\| none => false)\n", worker),
            (r"\ntheorem passedBy_worker .*?=\s*\((match decAuth pau with\n.*?\| none => false)\) := by\n", theorem))]
        self.assertEqual([len(x) for x in texts], [1, 1])
        self.assertEqual(*(" ".join(x[0].split()) for x in texts))


if __name__ == "__main__":
    unittest.main()
