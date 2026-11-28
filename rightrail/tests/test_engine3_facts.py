"""Fact frames (`RRDF`) in the unpinned rows-file engine `gate_hist3`: a frame's receipt and rows go to the store's `facts` file and
its answer (`RRDA` version 3) is checked byte for byte against the fact frame codec; a resend, a conflict, a frame out of turn and
each refusal of the request are as the codec's `retry` and `decode_request` say; every open leaves the same file, kept after a
clean stop or rebuilt from the log, and refuses a log holding an answer whose version is not its request kind's.
The checker `gate_verify3` replays the log: a changed fact answer, or a `facts` file that is not the log's records (or a prefix
of them, or them and bytes past them), is refused.  The row in force does not depend on the order files arrive in.  Every fact answer
carries the reference set's `rs`; two stores given the same reference receipts in other orders, with other member rows and
receipts, answer the same `rs`."""

import hashlib
import itertools
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from app import right_rail_fact_codec as c
from app import right_rail_fact_frame as f
from app import right_rail_fact_store as store
from tests import engine3_compare as ec
from tests import test_engine3_verify as v3
from tests.test_engine3_recovery import request
from tests.test_fact_codecs import FACTS, RECEIPTS, pat

OPEN = 99991231
STALE_TAG = "VSTORE_REFUSED(0) the facts of the checked frames are not the ones the last state holds"


def row(name, **change):
    return {**{k: v for k, v in FACTS[name].items() if k not in ("until", "receipt")}, **change}


R0, R1, R2, P = row("elig_basic"), row("death_state"), row("excl_basic"), row("pdeath_basic")
A = {**RECEIPTS["receipt_full"], "kb": 0, "admitted": 0, "same": 0, "quar": 0, "rows": 3}


def receipt(**change):
    return {**A, **change}


def fact_request(batch, prev, rcpt, rows, pin=None, shard=0):
    return f.encode_request({"shard": shard, "batch": batch, "prev": prev, "pin": pin or ec.g.PIN,
                             "receipt": {**rcpt, "rows": len(rows)}, "rows": rows})


def receipt_body(rcpt, kb, admitted, same, rows=()):
    """A stored receipt of a frame whose rows are each new (`admitted`) or as in force (`same`); `rd` is the hash of the
    frame's reference rows among `rows` (zero without any)."""
    e = f.ref_entry(rcpt, list(rows))
    return c.encode_receipt({**rcpt, "kb": kb, "rows": admitted + same, "admitted": admitted, "same": same,
                             "rd": e[-64:] if e else bytes(64)})


def row_body(w, until, at):
    return c.encode_fact({**w, "until": until, "receipt": at})


def held(facts):
    """The rows in force read from a facts file alone (§3.2): per statement (subject, kind, sid), the row of greatest rank
    in force, of equal ranks the later record.  A row's rank in force is its own and its record, or, once lifted, its
    last lift's (the lifting receipt's fseq and reader, the lift's roff) and the lift record."""
    rcpts, rows, at = {}, {}, {}
    for i in range(0, len(facts), 256):
        b, n = facts[i:i + c.BODY], i // 256
        kind, x = store.decode_body(b)
        if kind == "receipt":
            rcpts[n] = x
        elif kind == "fact":
            r = rcpts[x["receipt"]]
            rows[n], at[n] = x, (c.rank(r["fseq"], r["reader"], x["roff"]), n)
        elif kind == "lift":
            r = rcpts[x["receipt"]]
            for j, roff in x["lifts"]:
                at[j] = (c.rank(r["fseq"], r["reader"], roff), n)
    best = {}
    for n, x in rows.items():
        k = (x["subject"], x["kind"], x["sid"])
        if k not in best or best[k][0] <= at[n]:
            best[k] = (at[n], n, x)
    return {k: (rk, n, x) for k, ((rk, _), n, x) in best.items()}


def day_before(d):
    import datetime
    t = datetime.date(d // 10000, d // 100 % 100, d % 100) - datetime.timedelta(days=1)
    return t.year * 10000 + t.month * 100 + t.day


class RecordForm:
    """The reference: every restatement of the row in force at a lower rank is a new row at the restating row's rank
    (no lifts).  `until` is §3.2's: the day before the least `cfrom` of the source's full receipts with a higher fseq."""

    def __init__(self):
        self.rows, self.rcpts = [], []

    def admit(self, r, ws):
        fr = [x["cfrom"] for x in self.rcpts if x["src"] == r["src"] and x["cover"] == 1 and x["fseq"] > r["fseq"]]
        u = day_before(min(fr)) if fr else OPEN
        self.rcpts.append(r)
        for w in ws:
            k, x, rk = (w["subject"], w["kind"], w["sid"]), {**w, "until": u}, c.rank(r["fseq"], r["reader"], w["roff"])
            cur = self.held().get(k)
            if cur and cur[1] == x and cur[0] >= rk:
                continue
            self.rows.append((k, x, rk))

    def held(self):
        best = {}
        for n, (k, x, rk) in enumerate(self.rows):
            if k not in best or best[k][0] <= (rk, n):
                best[k] = ((rk, n), x)
        return {k: (rk, x) for k, ((rk, _), x) in best.items()}


class Engine3Facts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="engine3-facts-", dir=os.environ.get("E3_SCRATCH"))
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def engine(self):
        eng = ec.fw.Engine(self.dir, ec.NEW)
        self.addCleanup(eng.close)
        return eng

    def decide(self, eng, data):
        why, _, head, *_ = ec.fw.read(data, eng.send(data))
        self.assertIsNone(why)
        return head

    def word(self, eng, data):
        """The refusal word of the answer to `data` (an `RRDA` version 4 refusal echoing its digest)."""
        return ec.decider._answer(eng.send(data), data)[0]

    def fact(self, eng, data, entries, prev, refs):
        """Sends a fact frame that is decided; its answer is the codec's encoding of `entries` and of `rs` over the reference
        entries `refs` admitted so far, and the head moves."""
        out = eng.send(data)
        a = f.decode_answer(out)
        self.assertEqual(a["entries"], entries)
        self.assertEqual(out, f.encode_answer({"shard": 0, "batch": int.from_bytes(data[10:18], "little"), "digest": data[18:82],
                                               "entries": entries, "head": a["head"], "root": a["root"], "rs": f.ref_set(refs),
                                               "items": 0, "money": 0}))
        self.assertNotEqual(a["head"], prev)
        ec.fw.FLOORS[a["head"]] = ec.fw.floors(prev)  # a fact frame keeps the authority record
        return out, a["head"]

    def facts_file(self, bodies):
        got, want = (self.dir / "facts").read_bytes(), store.facts_writer(bodies)[0]
        self.assertEqual([got[i:i + 256].hex() for i in range(0, len(got), 256)],
                         [want[i:i + 256].hex() for i in range(0, len(want), 256)])

    def test_fact_frames_are_admitted_retried_and_refused(self):
        eng = self.engine()
        h1 = self.decide(eng, request(1, ec.fw.GENESIS))
        self.assertEqual((self.dir / "facts").read_bytes(), b"")

        # batch 2: a full file of three rows, each a new statement
        q2 = fact_request(2, h1, A, [R0, R1, R2])
        # its excluded provider row (kind 3) makes it a reference receipt; rd is over that row alone
        refs = [f.ref_entry(A, [R2])]
        self.assertEqual(refs, [f.ref_entry(A, [R0, R1, R2])])
        a2, h2 = self.fact(eng, q2, [(1, 0, 1), (1, 0, 2), (1, 0, 3)], h1, refs)
        bodies = [receipt_body(A, 2, 3, 0, [R0, R1, R2]), *(row_body(w, OPEN, 0) for w in (R0, R1, R2))]
        self.facts_file(bodies)
        model = {"shard": 0, "head": h2, "log": [(request(1, ec.fw.GENESIS)[18:82], b""), (q2[18:82], a2)]}

        # the exact resend answers the same bytes; another request on batch 2 conflicts; batch 1 and a far batch are not next;
        # the next batch on another head is HEAD
        other = fact_request(2, h1, receipt(file=pat(64, 41)), [R0])
        far, wrong_head = fact_request(5, h2, A, [R0]), fact_request(3, h1, receipt(file=pat(64, 41)), [R0])
        first = fact_request(1, ec.fw.GENESIS, A, [R0])
        for name, data in (("resend", q2), ("conflict", other), ("first", first), ("far", far), ("head", wrong_head)):
            with self.subTest(name):
                q, rq = f.decode_request(data)
                want = f.retry(model, q, rq)
                if want[0] == "replay":
                    self.assertEqual(eng.send(data), want[1])
                else:
                    self.assertEqual(self.word(eng, data), "flat_" + want[1].lower())
        self.facts_file(bodies)

        # refusals of the request itself: a nonzero authority section, a receipt that fails its own checks, a changed body
        # byte, another key-set pin
        good = fact_request(3, h2, receipt(file=pat(64, 41)), [R0])
        body = bytearray(good[82:])
        body[128] = 1
        authority = f.frame(0, 3, bytes(body))
        bad_channel = fact_request(3, h2, receipt(file=pat(64, 41), channel=0), [R0])
        flipped = good[:100] + bytes([good[100] ^ 1]) + good[101:]
        other_pin = fact_request(3, h2, receipt(file=pat(64, 41)), [R0], pin=bytes([ec.g.PIN[0] ^ 1]) + ec.g.PIN[1:])
        for name, data, word in (("authority", authority, "RECORD"), ("receipt", bad_channel, "RECORD"),
                                 ("digest", flipped, "DIGEST"), ("pin", other_pin, "PIN"),
                                 ("shard", fact_request(3, h2, A, [R0], shard=1), "SHARD")):
            with self.subTest(name):
                if name in ("authority", "digest"):
                    with self.assertRaises(f.Refused) as e:
                        f.decode_request(data)
                    self.assertEqual(e.exception.args[0], word)
                self.assertEqual(self.word(eng, data), "flat_" + word.lower())
        self.facts_file(bodies)

        # batch 3: the same file again is ALREADY, its rows answered with the receipt that holds it; nothing is written
        q3 = fact_request(3, h2, receipt(fseq=A["fseq"] + 7), [R0, R2])
        _, h3 = self.fact(eng, q3, [(4, 0, 0), (4, 0, 0)], h2, refs)
        self.facts_file(bodies)

        # batch 4: a later full file of the same source; a row as in force is lifted to its rank (disposition 2 at that row,
        # one lift record after the frame's rows), a changed row is a new fact
        b = receipt(file=pat(64, 42), fseq=A["fseq"] + 100)
        r1 = {**R1, "vstop": 20301231}
        q4 = fact_request(4, h3, b, [R0, r1])
        _, h4 = self.fact(eng, q4, [(2, 0, 1), (1, 0, 5)], h3, refs)
        bodies += [receipt_body(b, 4, 1, 1), row_body(r1, OPEN, 4), store.encode_lift(4, [(1, R0["roff"])])]
        self.facts_file(bodies)

        # a decision batch after fact batches; then a fresh process rebuilds the same file and replays the last answer
        h5 = self.decide(eng, request(5, h4))
        eng.close()
        eng = self.engine()
        self.facts_file(bodies)
        q6 = fact_request(6, h5, receipt(file=pat(64, 43), fseq=A["fseq"] - 1, cfrom=20250301), [R2])
        # a late reference receipt (an older fseq of the same source) goes before batch 2's in its source's chain
        late = receipt(file=pat(64, 43), fseq=A["fseq"] - 1, cfrom=20250301)
        refs.append(f.ref_entry(late, [R2]))
        a6, h6 = self.fact(eng, q6, [(1, 0, 8)], h5, refs)
        self.assertNotEqual(f.ref_set(refs), f.ref_set(refs[:1]))
        # a file older than the stored full files of its source: its rows stop the day before their earliest `cfrom`
        bodies += [receipt_body(receipt(file=pat(64, 43), fseq=A["fseq"] - 1, cfrom=20250301), 6, 1, 0, [R2]),
                   row_body(R2, 20241231, 7)]
        self.facts_file(bodies)
        eng.close()
        # a fresh process: the last batch on another head conflicts (its digest covers `prev`), the exact resend replays
        eng = self.engine()
        self.assertEqual(self.word(eng, fact_request(6, h4, receipt(file=pat(64, 44)), [R2])), "flat_conflict")
        self.assertEqual(eng.send(q6), a6)
        self.assertEqual(self.word(eng, fact_request(6, h5, receipt(file=pat(64, 44)), [R2])), "flat_conflict")
        self.assertEqual(self.word(eng, fact_request(7, h5, receipt(file=pat(64, 44)), [R2])), "flat_head")
        self.assertEqual(self.word(eng, fact_request(9, h6, receipt(file=pat(64, 44)), [R2])), "flat_not_next")
        self.decide(eng, request(7, h6))
        self.facts_file(bodies)
        eng.close()
        self.checker(len(bodies))
        self.relogged(q6, fact_request(6, h5, receipt(file=pat(64, 45), fseq=A["fseq"] - 1, cfrom=20250301), [R2]), bodies,
                      refs[:1])

    def test_row_in_force_does_not_depend_on_arrival_order(self):
        """Change files of one source on one statement: P, Q changing its row, R (newest) restating P's row, S (between P and
        Q) restating it too.  In every order of arrival, every 3-file prefix included (P, R, Q is the order where R's
        restatement once left Q in force), the row in force read from the facts file (§3.2: greatest rank, of equal ranks
        the later record) is R's; a late restatement of it is disposition 2 at that row; the checker verifies the log."""
        x1, x2 = R0, {**R0, "vstop": 20301231}
        files = [(0, x1), (10, x2), (20, x1), (5, x1)]

        def rcpt(k, off):
            return receipt(file=pat(64, 60 + k), fseq=A["fseq"] + off, cover=2)

        def in_force(facts):
            (x,) = held(facts).values()
            return x

        for order in itertools.permutations(range(len(files))):
            with self.subTest(order=order):
                d = self.dir / "".join(map(str, order))
                d.mkdir()
                eng = ec.fw.Engine(d, ec.NEW)
                try:
                    h = self.decide(eng, request(1, ec.fw.GENESIS))
                    for batch, k in enumerate(order, 2):
                        off, w = files[k]
                        a = f.decode_answer(eng.send(fact_request(batch, h, rcpt(k, off), [w])))
                        self.assertEqual(a["batch"], batch)
                        ec.fw.FLOORS[a["head"]] = ec.fw.floors(h)
                        h = a["head"]
                        if order[:3] == (0, 2, 1) and batch == 4:
                            self.assertEqual(in_force((d / "facts").read_bytes())[2]["vstop"], x1["vstop"])
                    rk, at, x = in_force((d / "facts").read_bytes())
                    self.assertEqual((rk, {k: x[k] for k in x1}, x["until"]),
                                     ((A["fseq"] + 20, A["reader"], x1["roff"]), x1, OPEN))
                    a = f.decode_answer(eng.send(fact_request(6, h, rcpt(4, 1), [x1])))
                    self.assertEqual(a["entries"], [(2, 0, at)])
                finally:
                    eng.close()
                self.addCleanup(shutil.rmtree, f"{d}.verify", True)
                rc, out = v3.verify(d, batches=6)
                self.assertEqual((rc, "VERIFIED shard 0 batches 6 " in out), (0, True), out)

    def test_lifts_keep_the_rows_in_force_of_written_restatements(self):
        """Full files of one source (F0, F20 newest) and a change file between them (C10) on two statements, and a full file
        of another source (G15) stating one of them: in every order of arrival, after every batch, the rows in force read
        from the facts file alone (lifts included) are the ones the record form gives, row content, `until` and rank; a
        full file's restatement of its own source's row is a lift (no row written), another source's is a row; the
        checker verifies the log."""
        x1, x2 = R0, {**R0, "vstop": 20301231}
        y1, y2 = {**R0, "sid": pat(32, 120)}, {**R0, "sid": pat(32, 120), "vstart": 20260201}
        g = {"src": A["src"] + 1}
        # F20 states x1 at another roff, so a lift of F0's row carries F20's roff in its rank
        files = [({"cover": 1}, 0, [x1, y1]), ({"cover": 2}, 10, [x2, y2]), ({"cover": 1}, 20, [{**x1, "roff": 9}, y1]),
                 ({"cover": 1, **g}, 15, [x1])]
        same = [n for n in x1 if n not in ("roff", "receipt")] + ["until"]
        lifted = 0
        for order in itertools.permutations(range(len(files))):
            with self.subTest(order=order):
                d = self.dir / ("L" + "".join(map(str, order)))
                d.mkdir()
                eng, model = ec.fw.Engine(d, ec.NEW), RecordForm()
                try:
                    h = self.decide(eng, request(1, ec.fw.GENESIS))
                    for batch, k in enumerate(order, 2):
                        ch, off, ws = files[k]
                        r = receipt(file=pat(64, 100 + k), fseq=A["fseq"] + off, **ch)
                        ws = sorted(ws, key=f.key)
                        a = f.decode_answer(eng.send(fact_request(batch, h, r, ws)))
                        self.assertEqual(a["batch"], batch)
                        ec.fw.FLOORS[a["head"]] = ec.fw.floors(h)
                        h = a["head"]
                        model.admit(r, ws)
                        facts = (d / "facts").read_bytes()
                        got = {k2: (rk, {n: x[n] for n in same}) for k2, (rk, _, x) in held(facts).items()}
                        want = {k2: (rk, {n: x[n] for n in same}) for k2, (rk, x) in model.held().items()}
                        self.assertEqual(got, want)
                    lifted += sum(facts[i] == 0x41 for i in range(0, len(facts), 256))
                finally:
                    eng.close()
                self.addCleanup(shutil.rmtree, f"{d}.verify", True)
                rc, out = v3.verify(d, batches=len(files) + 1)
                self.assertEqual((rc, f"VERIFIED shard 0 batches {len(files) + 1} " in out), (0, True), out)
        self.assertGreater(lifted, 0)

    def test_until_counts_full_files_that_arrived_late(self):
        """Full files of one source F30 and F20 (F20 covering from an earlier day) and change files C10 and C25, each
        stating its own statement: in every order of arrival, after every batch, the rows in force read from the facts file
        alone carry the `until` the record form gives (§3.2: when the row is written, the day before the least `cfrom` of
        the source's stored full files of a higher fseq, one that arrived after a higher one included); C10 arriving last
        ends the day before F20's `cfrom`; the checker verifies the log."""
        files = [({"cover": 1, "cfrom": 20260301}, 30), ({"cover": 1, "cfrom": 20260201}, 20), ({"cover": 2}, 10),
                 ({"cover": 2}, 25)]
        same = [n for n in R0 if n not in ("roff", "receipt")] + ["until"]
        for order in itertools.permutations(range(len(files))):
            with self.subTest(order=order):
                d = self.dir / ("U" + "".join(map(str, order)))
                d.mkdir()
                eng, model = ec.fw.Engine(d, ec.NEW), RecordForm()
                try:
                    h = self.decide(eng, request(1, ec.fw.GENESIS))
                    for batch, k in enumerate(order, 2):
                        ch, off = files[k]
                        r, ws = receipt(file=pat(64, 140 + k), fseq=A["fseq"] + off, **ch), [{**R0, "sid": pat(32, 140 + k)}]
                        a = f.decode_answer(eng.send(fact_request(batch, h, r, ws)))
                        self.assertEqual(a["batch"], batch)
                        ec.fw.FLOORS[a["head"]] = ec.fw.floors(h)
                        h = a["head"]
                        model.admit(r, ws)
                        facts = (d / "facts").read_bytes()
                        got = {k2: (rk, {n: x[n] for n in same}) for k2, (rk, _, x) in held(facts).items()}
                        want = {k2: (rk, {n: x[n] for n in same}) for k2, (rk, x) in model.held().items()}
                        self.assertEqual(got, want)
                    if order[-1] == 2:
                        self.assertEqual(got[(R0["subject"], R0["kind"], pat(32, 142))][1]["until"], day_before(20260201))
                finally:
                    eng.close()
                self.addCleanup(shutil.rmtree, f"{d}.verify", True)
                rc, out = v3.verify(d, batches=len(files) + 1)
                self.assertEqual((rc, f"VERIFIED shard 0 batches {len(files) + 1} " in out), (0, True), out)

    def test_reference_set_does_not_depend_on_shard_or_arrival_order(self):
        """Two stores (two shards' facts: the shard number is no input of `rs`) given the same reference receipts in other
        orders, one of them late, with other member rows beside the reference rows and member-only receipts in one store
        alone, answer the same `rs` once both hold all the reference receipts; the checker verifies both logs."""
        s1, s2 = receipt(file=pat(64, 70)), receipt(file=pat(64, 71), src=A["src"] + 1)
        late = receipt(file=pat(64, 72), fseq=A["fseq"] - 1, cfrom=20250301)
        member = receipt(file=pat(64, 73), fseq=A["fseq"] + 5)
        x = [(member, [R0], []), (s1, [R0, R2], [s1]), (s2, [P], [s2]), (late, [R2], [late])]
        y = [(late, [R2], [late]), (s2, [P], [s2]), (s1, [R1, R2], [s1])]
        want = f.ref_set([f.ref_entry(s1, [R2]), f.ref_entry(s2, [P]), f.ref_entry(late, [R2])])
        for name, frames in (("x", x), ("y", y)):
            d = self.dir / name
            d.mkdir()
            eng = ec.fw.Engine(d, ec.NEW)
            try:
                h, refs = self.decide(eng, request(1, ec.fw.GENESIS)), []
                for batch, (r, rows, ref) in enumerate(frames, 2):
                    e = f.ref_entry(r, rows)
                    self.assertEqual(e is None, not ref)
                    refs += [e] if ref else []
                    a = f.decode_answer(eng.send(fact_request(batch, h, r, rows)))
                    self.assertEqual((a["batch"], len(a["entries"]), a["rs"]), (batch, len(rows), f.ref_set(refs)))
                    ec.fw.FLOORS[a["head"]] = ec.fw.floors(h)
                    h = a["head"]
                self.assertEqual(a["rs"], want)
            finally:
                eng.close()
            self.addCleanup(shutil.rmtree, f"{d}.verify", True)
            rc, out = v3.verify(d, batches=len(frames) + 1)
            self.assertEqual((rc, f"VERIFIED shard 0 batches {len(frames) + 1} " in out), (0, True), out)
        self.assertNotEqual(want, f.ref_set([]))

    def test_a_fact_frame_that_throws_after_the_facts_are_taken_closes_their_file(self):
        """A test hook throws inside the fact frame after the facts were taken out of the engine and before they are put back.
        The error is raised again (the frame is refused as an IO failure), the facts file is closed (it can be renamed while the
        engine lives; an open handle would forbid it), and the same frame is then admitted."""
        eng = ec.fw.Engine(self.dir, ec.NEW, {"RR_E3_CRASH": "facts_in_flight"})
        self.addCleanup(eng.close)
        h1 = self.decide(eng, request(1, ec.fw.GENESIS))
        q2 = fact_request(2, h1, A, [R0, R1, R2])
        self.assertEqual(self.word(eng, q2), "flat_io")
        moved = self.dir / "facts.moved"
        (self.dir / "facts").rename(moved)  # fails with PermissionError while the engine still holds the file
        moved.rename(self.dir / "facts")
        self.assertEqual(f.decode_answer(eng.send(q2))["batch"], 2)

    def test_two_named_test_hooks_each_fail_once_in_one_run(self):
        """`RR_E3_CRASH` may name several failure points; each throws once on its own, so the first does not mask the second:
        on the open of a store with a logged frame the first request fails at `open_before_links`, the same request is then
        refused at `facts_in_flight` (a fact frame, an IO failure), and then admitted."""
        first = self.engine()
        h1 = self.decide(first, request(1, ec.fw.GENESIS))
        first.close()
        eng = ec.fw.Engine(self.dir, ec.NEW, {"RR_E3_CRASH": "open_before_links,facts_in_flight"})
        self.addCleanup(eng.close)
        q2 = fact_request(2, h1, A, [R0, R1, R2])
        self.assertIsNotNone(self.word(eng, q2))  # the open failed at open_before_links
        self.assertEqual(self.word(eng, q2), "flat_io")  # facts_in_flight, not masked by the first
        self.assertEqual(f.decode_answer(eng.send(q2))["batch"], 2)

    def test_open_after_a_clean_stop_keeps_the_facts_file(self):
        """An open after a clean stop keeps the facts file up to the receipt of its last logged fact frame and admits that
        frame again; any other open admits every fact frame of the log again.  From the same log, with the file as the
        clean stop left it, cut short, torn, with records of a batch not logged, with records out of order after it, or
        after a stop that was not clean, the next fact frame is answered with the same bytes and the file ends the same;
        the checker verifies each store."""
        eng = self.engine()
        h = self.decide(eng, request(1, ec.fw.GENESIS))
        late = receipt(file=pat(64, 92), fseq=A["fseq"] - 1, cfrom=20250301)
        newer = receipt(file=pat(64, 91), fseq=A["fseq"] + 100)
        # a full file with a reference row; a newer full file lifting a row and adding a death row; a late reference file
        for batch, (r, rows) in enumerate([(A, [R0, R1, R2]), (newer, [R0, P]), (late, [R2])], 2):
            a = f.decode_answer(eng.send(fact_request(batch, h, r, rows)))
            self.assertEqual((a["batch"], len(a["entries"])), (batch, len(rows)))
            ec.fw.FLOORS[a["head"]] = ec.fw.floors(h)
            h = a["head"]
        eng.close()
        self.assertEqual((self.dir / "clean").read_bytes(), b"\x01")
        facts = (self.dir / "facts").read_bytes()
        self.assertEqual(len(facts), 256 * 9)
        unlogged = receipt_body(receipt(file=pat(64, 94)), 5, 0, 0) + bytes(11)
        files = {"kept": facts, "short": facts[:-256], "torn": facts[:-100], "unlogged": facts + unlogged,
                 "out of order": facts + facts[:256], "not clean": facts}
        nxt = fact_request(5, h, receipt(file=pat(64, 93), fseq=A["fseq"] + 50, cover=2), [R0, R2])
        got = {}
        for name, data in files.items():
            d = self.dir.parent / f"{self.dir.name}-{name.replace(' ', '-')}"
            shutil.copytree(self.dir, d)
            self.addCleanup(shutil.rmtree, d, True)
            self.addCleanup(shutil.rmtree, f"{d}.verify", True)
            (d / "facts").write_bytes(data)
            if name == "not clean":
                (d / "clean").write_bytes(b"\x00")
            e = ec.fw.Engine(d, ec.NEW)
            try:
                got[name] = (e.send(nxt),)
            finally:
                e.close()
            got[name] += ((d / "facts").read_bytes(),)
            rc, out = v3.verify(d, batches=5)
            self.assertEqual((rc, "VERIFIED shard 0 batches 5 " in out), (0, True), (name, out))
        want = got["not clean"]
        self.assertEqual(len(f.decode_answer(want[0])["entries"]), 2)
        for name, x in got.items():
            with self.subTest(name):
                self.assertEqual(x, want)

    def test_an_answer_of_the_other_kinds_version_is_refused_on_open(self):
        """An open reads each logged answer's version by its request's kind: 4 after a decision request, 3 after a fact
        request.  A store whose decision answer says 3, or whose fact answer says 4, is refused (`MAGIC`) after a clean
        stop as after any other."""
        eng = self.engine()
        h = self.decide(eng, request(1, ec.fw.GENESIS))
        a = f.decode_answer(eng.send(fact_request(2, h, A, [R0])))
        ec.fw.FLOORS[a["head"]] = ec.fw.floors(h)
        eng.close()
        self.assertEqual((self.dir / "clean").read_bytes(), b"\x01")
        log = (self.dir / "log").read_bytes()
        decision, fact = list(v3.frames(log))
        nxt = request(3, a["head"])
        for name, (pos, rq, _, _), was, now in (("decision-as-3", decision, 4, 3), ("fact-as-4", fact, 3, 4)):
            with self.subTest(name):
                d = self.dir.parent / f"{self.dir.name}-{name}"
                shutil.copytree(self.dir, d)
                self.addCleanup(shutil.rmtree, d, True)
                edited = bytearray(log)
                self.assertEqual(edited[pos + 16 + rq + 4 : pos + 16 + rq + 6], bytes([was, 0]))
                edited[pos + 16 + rq + 4] = now
                (d / "log").write_bytes(bytes(edited))
                e = ec.fw.Engine(d, ec.NEW)
                try:
                    self.assertEqual(ec.fw.read(nxt, e.send(nxt))[0], "flat_magic")
                finally:
                    e.close()

    def checker(self, records):
        """The checker verifies the store, then refuses each tampering of a fact answer or of the `facts` file."""
        self.addCleanup(shutil.rmtree, f"{self.dir}.verify", True)
        rc, out = v3.verify(self.dir, batches=7)
        self.assertEqual((rc, "VERIFIED shard 0 batches 7 " in out), (0, True), out)
        log, facts = (self.dir / "log").read_bytes(), (self.dir / "facts").read_bytes()
        self.assertEqual(len(facts), 256 * records)
        # batch 2's answer: its first entry's seq (after the 87-byte header, a disposition and a cause byte)
        pos, rq, *_ = list(v3.frames(log))[1]
        at = pos + 16 + rq + 87 + 2
        changed = facts[:300] + bytes([facts[300] ^ 1]) + facts[301:]
        n = len(facts)
        # the file is a cache written again at every open: a prefix of the log's records (a crash before it was written
        # again) or the records and bytes past them (a batch not yet logged) is a note; any changed byte is refused
        cases = {"answer": ("log", log[:at] + bytes([log[at] ^ 1]) + log[at + 1:], 3, "batch 2 fact answer: "),
                 "record": ("facts", changed, 3, "batch 2 facts file record 1: "),
                 "short changed": ("facts", changed[:-256], 3, "batch 2 facts file record 1: "),
                 "extra changed": ("facts", changed + bytes(256), 3, "batch 2 facts file record 1: "),
                 "short": ("facts", facts[:-256], 0, f"FACTS_STALE(0) facts file holds {n - 256} of the {n} bytes of the log's {records} records"),
                 "torn": ("facts", facts[:-100], 0, f"FACTS_STALE(0) facts file holds {n - 100} of the {n} bytes"),
                 "absent": ("facts", None, 0, f"FACTS_STALE(0) facts file holds 0 of the {n} bytes"),
                 "extra": ("facts", facts + bytes(256), 0, f"FACTS_STALE(0) facts file holds 256 bytes past the {records} records of the log")}
        for name, (file, data, code, why) in cases.items():
            with self.subTest(name):
                d = self.dir.parent / f"{self.dir.name}-{name.replace(' ', '-')}"
                shutil.copytree(self.dir, d)
                self.addCleanup(shutil.rmtree, d, True)
                self.addCleanup(shutil.rmtree, f"{d}.verify", True)
                if data is None:
                    (d / file).unlink()
                else:
                    (d / file).write_bytes(data)
                rc, out = v3.verify(d)
                self.assertEqual((rc, why in out, "VERIFIED" in out), (code, True, code == 0), out)
        # the answer check turned off reaches a diagnostic completion, never verification
        rc, out = v3.verify(d.parent / f"{self.dir.name}-answer", skip="answer")
        self.assertEqual((rc, "DIAGNOSTIC_INCOMPLETE shard 0" in out, "VERIFIED" in out), (2, True, False), out)
        # a checker resumed from its own state still compares the file with its records: a changed file is still refused
        (self.dir / "facts").write_bytes(cases["record"][1])
        rc, out = v3.verify(self.dir)
        self.assertEqual((rc, cases["record"][3] in out), (3, True), out)
        (self.dir / "facts").write_bytes(facts)
        rc, out = v3.verify(self.dir, batches=7)
        self.assertEqual((rc, "FACTS_REPLAYED" in out), (0, False), out)
        # it resumes from its own copy of its records, bound by its last state; without that copy it replays the fact
        # frames from the log, reaches the digest its last state holds and writes the copy again
        vd = Path(f"{self.dir}.verify")
        kept, last = (vd / "vfacts").read_bytes(), (vd / "vlast").read_bytes()
        self.assertEqual(len(kept), 245 * records)
        (vd / "vfacts").unlink()
        rc, out = v3.verify(self.dir, batches=7)
        self.assertEqual((rc, "FACTS_REPLAYED(0) " in out, "VERIFIED shard 0 batches 7 " in out), (0, True, True), out)
        self.assertEqual(((vd / "vfacts").read_bytes(), (vd / "vlast").read_bytes()), (kept, last))
        rc, out = v3.verify(self.dir, batches=7)
        self.assertEqual((rc, "FACTS_REPLAYED" in out), (0, False), out)

    def relog(self, d, old, new, edit):
        """Replaces the fact frame `old` in the log of `d` by `new` (the same length) after the checker checked it: the
        answer gets `new`'s request digest and `edit(answer, end of its entries)`, and the trailer the new request and
        answer digests, so that the frame's own digests agree."""
        log = bytearray((d / "log").read_bytes())
        pos, rq, an, tr = next(x for x in v3.frames(bytes(log)) if log[x[0] + 16:x[0] + 16 + x[1]] == old)
        self.assertEqual(len(new), rq)
        a = bytearray(log[pos + 16 + rq:pos + 16 + rq + an])
        a[23:87] = new[18:82]  # the answer's request digest
        head = 87 + 7 * int.from_bytes(a[19:23], "little")
        edit(a, head)
        an_old, an_new = (hashlib.sha3_512(b"RR/GATE/ANSWER3/v1\x00" + bytes(x[:head] + x[head + 128:])).digest()
                          for x in (log[pos + 16 + rq:pos + 16 + rq + an], a))
        t = bytes(log[pos + 16 + rq + an:pos + 16 + rq + an + tr])
        self.assertEqual(t.count(old[18:82] + an_old), 1)
        t = t.replace(old[18:82] + an_old, new[18:82] + an_new)
        log[pos + 16:pos + 16 + rq + an + tr] = new + a + t
        (d / "log").write_bytes(bytes(log))

    def relogged(self, old, new, bodies, refs):
        """A fact frame changed after the checker checked it, to another frame of the same length whose answer (its `rs`
        over `refs` and the new frame's entry included) and trailer digests agree, and the facts file written again from
        the changed log (as the engine's next open would): a resumed checker does not take its facts from the changed log;
        it rebuilds and finds the frame's Root4 broken."""
        q, _ = f.decode_request(new)

        def edit(a, head):
            a[head + 128:head + 192] = f.ref_set([*refs, f.ref_entry(q["receipt"], q["rows"])])
        self.relog(self.dir, old, new, edit)
        nb = list(bodies)
        nb[7] = receipt_body(receipt(file=pat(64, 45), fseq=A["fseq"] - 1, cfrom=20250301), 6, 1, 0, [R2])
        (self.dir / "facts").write_bytes(store.facts_writer(nb)[0])
        rc, out = v3.verify(self.dir)
        self.assertEqual((rc, STALE_TAG in out, "batch 6 Root4: " in out), (3, True, True), out)

    def test_resume_refuses_changed_reference_entries_alone(self):
        """A late change file restating, as in force (disposition 2), first an excluded provider row (a reference row) and,
        after the checker checked it, a member row instead: the records differ only in the receipt's reference rows hash
        (a receipt of one row as in force, no row record) and the frame's digests agree, so only the reference entries
        differ.  The resumed checker refuses its last state with exactly the facts-digest refusal and rebuilds from the
        log."""
        def rcpt(k, off):
            return receipt(file=pat(64, 80 + k), fseq=A["fseq"] + off, cover=2)
        eng = self.engine()
        h = self.decide(eng, request(1, ec.fw.GENESIS))
        _, h = self.fact(eng, fact_request(2, h, rcpt(0, 20), [R1]), [(1, 0, 1)], h, [])
        refs = [f.ref_entry(rcpt(1, 21), [R2])]
        _, h = self.fact(eng, fact_request(3, h, rcpt(1, 21), [R2]), [(1, 0, 3)], h, refs)
        late = rcpt(2, 1)
        old = fact_request(4, h, late, [R2])
        self.fact(eng, old, [(2, 0, 3)], h, refs + [f.ref_entry(late, [R2])])
        eng.close()
        self.addCleanup(shutil.rmtree, f"{self.dir}.verify", True)
        rc, out = v3.verify(self.dir, batches=4)
        self.assertEqual((rc, "VERIFIED shard 0 batches 4 " in out), (0, True), out)
        facts = (self.dir / "facts").read_bytes()
        new = fact_request(4, h, late, [R1])
        self.assertIsNone(f.ref_entry(late, [R1]))

        def edit(a, head):
            a[89:94] = (1).to_bytes(5, "little")  # the entry: as in force at R1's record
            a[head + 128:head + 192] = f.ref_set(refs)
        self.relog(self.dir, old, new, edit)
        rc, out = v3.verify(self.dir)
        self.assertEqual((rc, STALE_TAG in out), (3, True), out)
        self.assertEqual((self.dir / "facts").read_bytes(), facts)


if __name__ == "__main__":
    unittest.main()
