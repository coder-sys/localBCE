"""Gate chaos: deciders on three shards interleaved by fixed seeds, with a crash or exception at every write point (the
Lean call, the seal, tokens out), decide-twice-commit-in-any-order, reboots, and store-with-mark restores.  A decider that
meets a fault dies (closes its handles) or survives and goes on.  Invariants: no shard ALLOWs a line twice (line identity is
per shard; a restored shard is the payer-newest check's, not this one's); every shard nobody restored still pays a fresh
line, and a request decided but never sealed is resent unchanged on its head (the engine keeps that frame and refuses any
other request there) and gets the decisions of its first attempt.  Synthetic, non-PHI."""

from __future__ import annotations

import contextlib
from dataclasses import replace
import json
from pathlib import Path
import random
import sqlite3
import unittest
from unittest import mock

from app import right_rail_gate_chain as chain
from app import right_rail_gate_codec as gate
from app import right_rail_gate_decide as decider
from app import right_rail_gate_producer as producer
from app import right_rail_gate_signer as signer
from tests import _gate_authority as au
from tests import _gate_shards as g
from tests import test_gate_authority_frames as af
from tests import test_right_rail_gate_formats as fx
from tests.test_right_rail_gate_shards import restore, snapshot

SHARDS, STEPS, SEEDS, POOL = 3, 30, (1, 2), range(10, 22)  # a small id pool: every shard meets repeats
PROBE = (22, 23, 36)  # fresh ids whose claim dates (id % 14 = 8, 9, 8) no pool id shares: never a near-duplicate
ACTS = ("batch",) * 10 + ("twice",) * 3 + ("reboot", "snapshot", "restore")
FAULTS = (None,) * 3 + ("lean", "seal", "verify_failed", "verify_refused", "out")
REFUSED = (decider.GateDecideError, producer.GateProducerError, signer.GateSignerError)


class Boom(Exception):
    """An injected crash or unexpected exception at a write point."""


class Chaos:
    def __init__(self, t: unittest.TestCase, c: g.Cluster, seed: int) -> None:
        self.t, self.c, self.rng = t, c, random.Random(seed)
        self.live, self.snaps, self.paid = {}, {}, {}  # shard -> producer; shard -> files; (shard, digest) -> ALLOW lines
        self.restored, self.p = set(), 0
        self.pending = {}  # shard -> (signed head, payments, bad, decisions) of a request decided and never sealed

    def close(self, k: int) -> None:
        self.live.pop(k).close()
        self.see(k)  # every sealed batch is seen before any restore can drop it

    def see(self, k: int) -> None:
        self.paid.update({(k, d): lines for d, lines in g.sealed_allows(self.c, k).items()})

    def resend(self, k: int) -> None:
        """What a producer does after a faulted seal: the abandoned request again, unchanged, on the same signed head."""
        if k not in self.pending:
            return
        if k in self.live:
            self.close(k)  # a reopen reseals or voids the open row
        head, payments, bad, first = self.pending.pop(k)
        prod = self.handles(k)
        if prod.flat_head() != head:
            return  # the reopen sealed it: the head moved, and the request is no longer the retry of anything
        ans, leaves, status = g.decide_batch(self.c, prod, k, payments, bad)
        self.t.assertEqual(status, first, f"shard {k}: the resent request decided differently")
        if leaves:
            decider.commit(prod, fx.PROGRAM, ans, fx.NOW, self.c.tenant)

    def handles(self, k: int):
        if k not in self.live:
            self.live[k] = self.c.producer(k)
        return self.live[k]

    def inject(self, fault: str | None, k: int) -> contextlib.ExitStack:
        stack, patch = contextlib.ExitStack(), lambda *a, **kw: stack.enter_context(mock.patch.object(*a, **kw))
        if fault == "lean":
            patch(decider.RulesWorker, "run_frame", side_effect=Boom(fault))
        elif fault == "seal":  # the open row is stored, nothing signed
            patch(producer.ShardProducer, "_seal", side_effect=Boom(fault))
        elif fault in ("verify_failed", "verify_refused"):
            patch(signer, "seal", side_effect=signer.GateSignerError(f"gate_{fault}"))
        return stack

    def batch(self, k: int, twice: bool) -> None:
        prod = self.handles(k)
        answers = []
        for _ in range(1 + twice):
            ids, payments = self.rng.sample(POOL, self.rng.randint(1, 4)), {}
            for i in ids:
                if not payments or self.rng.random() < 0.6:
                    self.p += 1
                payments.setdefault(self.p, []).append(i)
            bad = [i for i in ids if self.rng.random() < 0.2]
            try:
                head = prod.flat_head()
            except producer.GateProducerError:
                head = None
            ans, leaves, status = g.decide_batch(self.c, prod, k, payments, bad, seal=(fx.PROGRAM, fx.NOW))
            answers.append((ans, leaves))
            if leaves and k not in self.pending:
                self.pending[k] = (head, payments, bad, status)  # until a commit seals it
        for ans, leaves in self.rng.sample(answers, len(answers)):
            try:
                if leaves:
                    decider.commit(prod, fx.PROGRAM, ans, fx.NOW, self.c.tenant)
                    if answers[0][0] is ans:
                        self.pending.pop(k, None)
            except decider.GateDecideError as error:
                if str(error) != "stale_answer":
                    raise

    def step(self) -> None:
        k, act = self.rng.randrange(SHARDS), self.rng.choice(ACTS)
        if act == "reboot":  # every process restarts
            for s in list(self.live):
                self.close(s)
        elif act in ("snapshot", "restore"):
            if k in self.live:
                self.close(k)
            paths = (self.c.store(k), self.c.dir / f"s{k}.mark")
            if act == "snapshot":
                self.snaps[k] = [snapshot(path) for path in paths]
            elif k in self.snaps:
                for path, files in zip(paths, self.snaps[k]):
                    restore(path, files)
                self.restored.add(k)
                self.pending.pop(k, None)
        else:
            fault = self.rng.choice(FAULTS)
            self.resend(k)  # the retry comes before the fresh batch, and has no fault of its own
            try:
                with self.inject(fault, k):
                    self.batch(k, act == "twice")
                if fault == "out":
                    raise Boom(fault)  # the tokens are out; the process dies
            except (Boom, *REFUSED):
                if k in self.live and self.rng.random() < 0.5:
                    self.close(k)  # the decider dies; else it survives with its handles

    def run(self) -> None:
        for _ in range(STEPS):
            self.step()
        for k in list(self.live):
            self.close(k)
        for k in filter(lambda k: self.c.store(k).exists(), range(SHARDS)):
            self.see(k)
        for k in range(SHARDS):  # a restored shard lost batches the payer may have seen: the startup check catches that, not this
            if k not in self.restored:
                lines = sorted(i for (shard, _), paid in self.paid.items() if shard == k for _, i in paid)
                self.t.assertEqual(len(lines), len(set(lines)), f"shard {k} ALLOWed a line twice: {lines}")
        for k in set(range(SHARDS)) - self.restored:  # no healthy shard wedges
            self.resend(k)
            if k in self.live:
                self.close(k)  # the probe opens the shard itself
            self.p += 1
            self.t.assertEqual(self.c.send(k, {self.p: [PROBE[k]]}), {PROBE[k]: "ALLOW -"}, f"shard {k} is wedged")
        if not self.restored:
            g.inv(self.t, self.c)



class GateChaosTests(fx.Scratch):
    def test_interleaved_deciders_never_pay_a_line_twice(self) -> None:
        for seed in SEEDS:
            with self.subTest(seed=seed), self.scratch() as tmp:
                c = g.Cluster(tmp, fx.custody(tmp), SHARDS)
                Chaos(self, c, seed).run()

    def seal_one_decide_one(self, c: g.Cluster, prod, flat, seal=None):
        ans = g.decide_batch(c, prod, 0, {1: [10]}, flat=flat)[0]
        decider.commit(prod, fx.PROGRAM, ans, fx.NOW, c.tenant)  # batch 1 sealed
        return g.decide_batch(c, prod, 0, {2: [11]}, flat=flat, seal=seal)  # batch 2 decided; the process dies before the seal

    def test_decided_unsealed_batch_is_resent_and_sealed_before_new_work(self) -> None:
        with self.scratch() as tmp:
            c = g.Cluster(tmp, fx.custody(tmp), 1)
            prod, flat = c.producer(0), c.dir / "idx0"
            try:
                first, leaves, status = self.seal_one_decide_one(c, prod, flat)
                self.assertTrue(leaves)
                worker = decider.RulesWorker(g.ENGINE)
                try:  # a different request before recovery (no seal time) still gets HOLD RETRY
                    held = decider.decide(g.HEAD, g.ASOF, prod, [g.request(3, 0, [12])], flat, worker, g.GRANT, g.KEYS, c.tenant)
                    self.assertEqual(held.lines, ("pay-0003 HOLD flat_conflict",))
                finally:
                    worker.close()
                again, _, same = g.decide_batch(c, prod, 0, {2: [11]}, flat=flat)  # the same request: the same answer
                self.assertEqual((again.digest, same), (first.digest, status))
                decider.commit(prod, fx.PROGRAM, again, fx.NOW, c.tenant)  # the batch seals
                self.assertEqual(g.decide_batch(c, prod, 0, {3: [12]}, flat=flat)[2], {12: "ALLOW -"})  # the next request proceeds
            finally:
                prod.close()

    def test_a_stored_frame_that_is_bad_or_has_no_request_is_refused_by_name_and_left_as_it_was(self) -> None:
        def resign(doc):  # a file the owner signed, with these fields
            decider._store_pending(pend, prod, {k: v for k, v in doc.items() if k != "vouch"})

        def foreign(doc):  # the owner's file, its frame on the right head, carrying another tenant's request
            body = gate.encode_decide_request(replace(g.request(2, 0, [11]), tenant_id=fx.OTHER))
            frame = decider.request_frame(g.HEAD, 0, 2, g.ASOF, prod.flat_head()[0], g.PIN, (0, 0), g.KEYS, g.GRANT, bytes.fromhex(doc["release"]), (), [body])
            resign({**doc, "frame": frame.hex(), "bodies_at": len(frame) - 8 - len(body)})
        edits = {  # name -> (rewrite of the stored file, the refusal), each against batch 2 stored by decide
            "garbled": (lambda doc: pend.write_bytes(pend.read_bytes()[:-9] + b"\xff"), "pending_bad"),
            "not JSON hex": (lambda doc: resign({**doc, "frame": "zz"}), "pending_bad"),
            "edited without the owner's key": (lambda doc: pend.write_text(json.dumps({**doc, "created_at": fx.NOW + 1})), "pending_bad"),
            "another tenant's": (lambda doc: resign({**doc, "tenant": fx.OTHER}), "pending_bad"),
            "another number's": (lambda doc: resign({**doc, "batch": 3}), "pending_bad"),
            "another program's": (lambda doc: resign({**doc, "program": "OTHER"}), "pending_bad"),
            "no request": (lambda doc: resign({**doc, "requests": []}), "pending_empty"),
            "a request of another tenant": (foreign, "pending_bad"),
            "requests not where it says": (lambda doc: resign({**doc, "bodies_at": doc["bodies_at"] + 1}), "pending_bad"),
        }
        for name, (edit, want) in edits.items():
            with self.subTest(name), self.scratch() as tmp:
                c = g.Cluster(tmp, fx.custody(tmp), 1)
                prod, flat = c.producer(0), c.dir / "idx0"
                pend = decider._pend(flat, 2)
                try:
                    self.seal_one_decide_one(c, prod, flat, seal=(fx.PROGRAM, fx.NOW))
                    edit(json.loads(pend.read_bytes()))
                    before = pend.read_bytes()
                    with self.assertRaises(decider.GateDecideError) as caught:  # the next request, with a seal time
                        g.decide_batch(c, prod, 0, {3: [12]}, flat=flat, seal=(fx.PROGRAM, fx.NOW))
                    self.assertEqual(str(caught.exception), f"{want}:{pend}")
                    self.assertEqual(pend.read_bytes(), before)  # neither sealed, replaced nor dropped
                    self.assertEqual(prod.flat_head()[1], 1)
                finally:
                    prod.close()

    def test_a_stored_frame_the_owner_did_not_sign_is_refused_on_an_exact_retry_too(self) -> None:
        with self.scratch() as tmp:
            c = g.Cluster(tmp, fx.custody(tmp), 1)
            prod, flat = c.producer(0), c.dir / "idx0"
            pend = decider._pend(flat, 2)
            try:
                self.seal_one_decide_one(c, prod, flat)
                pend.write_text(json.dumps({**json.loads(pend.read_bytes()), "created_at": fx.NOW + 1}))  # replaced, not signed by the owner
                with self.assertRaises(decider.GateDecideError) as caught:
                    g.decide_batch(c, prod, 0, {2: [11]}, flat=flat)
                self.assertEqual(str(caught.exception), f"pending_bad:{pend}")
            finally:
                prod.close()

    def test_different_request_with_seal_time_seals_the_stored_batch_first(self) -> None:
        with self.scratch() as tmp:
            c = g.Cluster(tmp, fx.custody(tmp), 1)
            prod, flat = c.producer(0), c.dir / "idx0"
            try:
                self.seal_one_decide_one(c, prod, flat)
                ans, _, status = g.decide_batch(c, prod, 0, {3: [12]}, flat=flat, seal=(fx.PROGRAM, fx.NOW))
                self.assertEqual(status, {12: "ALLOW -"})
                decider.commit(prod, fx.PROGRAM, ans, fx.NOW, c.tenant)
                retry = g.decide_batch(c, prod, 0, {2: [11]}, flat=flat)[0]  # the stored batch's requester asks again
                self.assertEqual(retry.sealed, g.decide_batch(c, prod, 0, {2: [11]}, flat=flat)[0].sealed)  # the same bytes each time
                self.assertTrue(retry.sealed[1])
                self.assertEqual(sorted(decider._pend(flat, n).exists() for n in (1, 2, 3)), [False] * 3)  # each file went at its seal
            finally:
                prod.close()
            self.assertEqual(len(g.sealed_allows(c, 0)), 3)  # batches 1, 2 and 3 are all sealed

    def test_the_engine_decides_nothing_on_a_frame_whose_first_request_is_another_tenants(self) -> None:
        """Why a stored frame of another tenant's request needs the host's own refusal: the engine admits the grant for the
        first request's tenant, so the shard's grant is out of scope and the whole frame is a grant HOLD, deciding nothing."""
        body = gate.encode_decide_request(replace(g.request(1, 0, [10]), tenant_id=fx.OTHER))
        frame = decider.request_frame(g.HEAD, 0, 1, g.ASOF, chain.genesis(0, g.ASOF, g.PIN), g.PIN, (0, 0), g.KEYS, g.GRANT, gate.sha3_512(g.ENGINE.read_bytes()), (), [body])
        with self.scratch() as tmp:
            worker = decider.RulesWorker(g.ENGINE)
            try:
                out = worker.run_frame(str(Path(tmp) / "idx").replace("\\", "/"), 0, frame)
            finally:
                worker.close()
        self.assertEqual(decider._answer(out, frame)[0], "grant_scope")

    def test_a_retry_key_moved_to_another_sealed_batch_is_refused(self) -> None:
        """Batch 2 is sealed by recovery and filed under its requester's retry key; batches 1 and 3, sealed after a normal
        decide, have keys of their own.  An editor of the store file swaps batch 2's key with batch 1's or batch 3's, or
        rewrites its pledge: the retry is refused (``store_tampered``), nothing is served, and every row is kept."""
        for name in ("to batch 1", "to batch 3", "pledge rewritten"):
            with self.subTest(name), self.scratch() as tmp:
                c = g.Cluster(tmp, fx.custody(tmp), 1)
                prod, flat = c.producer(0), c.dir / "idx0"
                try:
                    self.seal_one_decide_one(c, prod, flat)
                    ans = g.decide_batch(c, prod, 0, {3: [12]}, flat=flat, seal=(fx.PROGRAM, fx.NOW))[0]
                    decider.commit(prod, fx.PROGRAM, ans, fx.NOW, c.tenant)
                    self.assertTrue(g.decide_batch(c, prod, 0, {2: [11]}, flat=flat)[0].sealed)  # as written: served
                    ids = [i for (i,) in prod._db.execute("SELECT id FROM batches ORDER BY id")]
                    prod._db.execute("DROP TRIGGER retries_fixed")
                    self.assertEqual(prod._db.execute("SELECT count(*) FROM retries").fetchone()[0], len(ids))
                    if name == "pledge rewritten":
                        prod._db.execute("UPDATE retries SET pledge=? WHERE batch_id=?", (bytes(gate.ML_DSA_87_SIGNATURE), ids[1]))
                    else:  # batch_id is unique, so moving the key means swapping keys with the other batch's row
                        other = ids[0] if name == "to batch 1" else ids[2]
                        (k2,), (ko,) = (prod._db.execute("SELECT key FROM retries WHERE batch_id=?", (i,)).fetchone() for i in (ids[1], other))
                        prod._db.execute("UPDATE retries SET key=x'00' WHERE batch_id=?", (ids[1],))
                        prod._db.execute("UPDATE retries SET key=? WHERE batch_id=?", (k2, other))
                        prod._db.execute("UPDATE retries SET key=? WHERE batch_id=?", (ko, ids[1]))
                    with self.assertRaisesRegex(producer.GateProducerError, "store_tampered"):
                        g.decide_batch(c, prod, 0, {2: [11]}, flat=flat)
                    self.assertEqual(prod._db.execute("SELECT count(*) FROM retries").fetchone()[0], len(ids))  # kept as evidence
                finally:
                    prod.close()

    def test_a_definite_hold_drops_its_frame_and_the_frame_decided_after_it_is_recovered(self) -> None:
        """Batch 2 is first a grant HOLD (the engine decided nothing): its file goes.  A different request is then decided on
        number 2 without a seal and the process dies; the next request, with a seal time, seals that one, never the HOLD."""
        with self.scratch() as tmp:
            c = g.Cluster(tmp, fx.custody(tmp), 1)
            prod, flat, pend = c.producer(0), c.dir / "idx0", decider._pend(c.dir / "idx0", 2)
            try:
                ans = g.decide_batch(c, prod, 0, {1: [10]}, flat=flat)[0]
                decider.commit(prod, fx.PROGRAM, ans, fx.NOW, c.tenant)
                worker = decider.RulesWorker(g.ENGINE)
                try:
                    held = decider.decide(g.HEAD, g.ASOF, prod, [g.request(2, 0, [11])], flat, worker, b"", g.KEYS, c.tenant, seal=(fx.PROGRAM, fx.NOW))
                finally:
                    worker.close()
                self.assertEqual((held.lines, pend.exists()), (("pay-0002 HOLD grant_missing",), False))
                self.assertTrue(g.decide_batch(c, prod, 0, {3: [12]}, flat=flat)[1])  # decided on number 2, never sealed
            finally:
                prod.close()
            prod = c.producer(0)
            try:
                ans, _, status = g.decide_batch(c, prod, 0, {4: [13]}, flat=flat, seal=(fx.PROGRAM, fx.NOW))
                self.assertEqual((status, ans.batches), ({13: "ALLOW -"}, 3))
                decider.commit(prod, fx.PROGRAM, ans, fx.NOW, c.tenant)
            finally:
                prod.close()
            sealed = sorted(i for lines in g.sealed_allows(c, 0).values() for _, i in lines)
            self.assertEqual(sealed, [10, 12, 13])  # 11 was HOLD and stays unsealed

    def test_a_frame_whose_answer_was_lost_is_sealed_at_its_own_time_and_release_and_given_to_its_retry(self) -> None:
        """Batch 2 is sent and its decide raises after the send (the answer is lost).  After a restart, a request on a later
        day, under another grant and engine release, seals batch 2 first with its own time and release; batch 2's requester,
        asking again, gets those tokens.  A dead worker on the way is a machine fault: the file stays and the next call heals."""
        t0, t1, release, other = fx.NOW, fx.NOW + 86400, gate.sha3_512(g.ENGINE.read_bytes()), gate.sha3_512(b"another release")
        today = next(i for i, r in enumerate(g._HEAD) if r.startswith("today "))
        later = [*g._HEAD[:today], f"today {int(g._HEAD[today].split()[1]) + 1}", *g._HEAD[today + 1:]]
        real = decider.RulesWorker.run_frame

        def sent_then_lost(self, directory, shard, data):
            real(self, directory, shard, data)
            raise Boom("after the send")
        with self.scratch() as tmp:
            c = g.Cluster(tmp, fx.custody(tmp), 1)
            prod, flat, pend = c.producer(0), c.dir / "idx0", decider._pend(c.dir / "idx0", 2)
            try:
                ans = g.decide_batch(c, prod, 0, {1: [10]}, flat=flat)[0]
                decider.commit(prod, fx.PROGRAM, ans, t0, c.tenant)
                with mock.patch.object(decider.RulesWorker, "run_frame", sent_then_lost), self.assertRaises(Boom):
                    g.decide_batch(c, prod, 0, {2: [11]}, flat=flat, seal=(fx.PROGRAM, t0))
                self.assertTrue(pend.exists())
            finally:
                prod.close()
            prod, worker = c.producer(0), decider.RulesWorker(g.ENGINE)
            worker.launched_release = lambda: other
            new = lambda: decider.decide(g.feeds_of(later), g.ASOF, prod, [g.request(3, 0, [12])], flat, worker,
                                         au.grant([(fx.PROGRAM, 1 << 1 | 1 << 3, 3, 0)], serial=2), g.KEYS, c.tenant, seal=(fx.PROGRAM, t1))
            try:
                with mock.patch.object(decider.RulesWorker, "run_frame", side_effect=decider.WorkerDied("rules_refused")), \
                        self.assertRaises(decider.MachineFault):  # every launch died: ATTEMPTS, then MachineFault
                    new()
                self.assertEqual((pend.exists(), prod.flat_head()[1]), (True, 1))
                self.assertEqual(new().batches, 3)  # batch 2 sealed, this request decided on number 3
                self.assertFalse(pend.exists())
                retry = g.decide_batch(c, prod, 0, {2: [11]}, flat=flat)[0]
            finally:
                worker.close()
                prod.close()
            db = sqlite3.connect(f"file:{c.store(0)}?mode=ro", uri=True)
            try:
                times = [int.from_bytes(h[-16:-8], "big") for (h,) in db.execute("SELECT header FROM batches ORDER BY id")]
            finally:
                db.close()
            self.assertEqual(times, [t0, t0])
            self.assertTrue(retry.sealed[1])
            self.assertTrue(all(release in t and other not in t for t in retry.sealed[1]))

    def test_a_batch_of_requests_with_no_lines_is_stored_and_recovered(self) -> None:
        sdp = af.sdp_request(member=g.member(1002, 0))
        with self.scratch() as tmp:
            c = g.Cluster(tmp, fx.custody(tmp), 1)
            prod, flat = c.producer(0), c.dir / "idx0"
            try:
                ans = g.decide_batch(c, prod, 0, {1: [10]}, flat=flat)[0]
                decider.commit(prod, fx.PROGRAM, ans, fx.NOW, c.tenant)
                worker = decider.RulesWorker(g.ENGINE)
                try:
                    zero = decider.decide(g.HEAD, g.ASOF, prod, [sdp], flat, worker, au.grant([(fx.PROGRAM, af.SDP, 3, 0)]), g.KEYS, c.tenant)
                finally:
                    worker.close()
                self.assertEqual((len(sdp.lines), len(zero.pays), bool(zero.digest)), (0, 1, True))
                self.assertEqual(json.loads(decider._pend(flat, 2).read_bytes())["requests"], [[sdp.payment_id, 0]])
            finally:
                prod.close()
            prod = c.producer(0)
            try:
                ans, _, status = g.decide_batch(c, prod, 0, {3: [12]}, flat=flat, seal=(fx.PROGRAM, fx.NOW))
                self.assertEqual((status, ans.batches), ({12: "ALLOW -"}, 3))
            finally:
                prod.close()

    def test_a_different_request_holds_at_the_first_batch_too(self) -> None:
        with self.scratch() as tmp:
            c = g.Cluster(tmp, fx.custody(tmp), 1)
            prod, flat = c.producer(0), c.dir / "idx0"
            try:
                first = g.decide_batch(c, prod, 0, {1: [10]}, flat=flat)[0]
                stored = decider._pend(flat, 1).read_bytes()
                self.assertEqual(g.decide_batch(c, prod, 0, {2: [11]}, flat=flat)[2], {11: "HOLD flat_conflict"})
                self.assertEqual(decider._pend(flat, 1).read_bytes(), stored)
                again = g.decide_batch(c, prod, 0, {1: [10]}, flat=flat)[0]
                self.assertEqual(again.digest, first.digest)
                decider.commit(prod, fx.PROGRAM, again, fx.NOW, c.tenant)
                self.assertFalse(decider._pend(flat, 1).exists())
                decider._pend(flat, 1).write_bytes(stored)  # a stop between a seal and its file's removal leaves it
                self.assertTrue(g.decide_batch(c, prod, 0, {2: [11]}, flat=flat)[1])
                self.assertFalse(decider._pend(flat, 1).exists())  # the sealed number's file goes at the next decide
            finally:
                prod.close()

    def test_a_stored_frame_whose_resend_is_refused_names_its_file_and_stays(self) -> None:
        real = decider.RulesWorker.run_frame
        with self.scratch() as tmp:
            c = g.Cluster(tmp, fx.custody(tmp), 1)
            prod, flat, pend = c.producer(0), c.dir / "idx0", decider._pend(c.dir / "idx0", 2)
            try:
                self.seal_one_decide_one(c, prod, flat, seal=(fx.PROGRAM, fx.NOW))
                before = pend.read_bytes()
                with mock.patch.object(decider.RulesWorker, "run_frame", lambda self, d, k, data: real(self, d, k, data)[:-1]):
                    for _ in range(2):  # an answer to the resend that does not parse: the same refusal each time, the file as it was
                        with self.assertRaises(decider.GateDecideError) as caught:
                            g.decide_batch(c, prod, 0, {3: [12]}, flat=flat, seal=(fx.PROGRAM, fx.NOW))
                        self.assertEqual(str(caught.exception), f"pending_refused:{pend}:rules_refused")
                        self.assertEqual((pend.read_bytes(), prod.flat_head()[1]), (before, 1))
                self.assertEqual(g.decide_batch(c, prod, 0, {3: [12]}, flat=flat, seal=(fx.PROGRAM, fx.NOW))[0].batches, 3)  # fixed, it heals
            finally:
                prod.close()


if __name__ == "__main__":
    unittest.main()
