"""Gate chaos: deciders on three shards interleaved by fixed seeds, with a crash or exception at every write point (the
reserve, the Lean call, the seal, the settle, tokens out), a second decider inside a commit, a transient
``registry_unavailable``, decide-twice-commit-in-any-order, reboots, and store-with-mark restores.  A decider that
meets a fault dies (closes its handles) or survives and goes on.  Invariants: no line id is ALLOWed by two batches
that could leave, within or across shards; no second decider ever reserves for a shard inside a commit; every shard
nobody restored still pays a fresh line.  Synthetic, non-PHI."""

from __future__ import annotations

import contextlib
import random
import unittest
from unittest import mock

from app import right_rail_gate_decide as decider
from app import right_rail_gate_idreg as idreg
from app import right_rail_gate_producer as producer
from app import right_rail_gate_signer as signer
from tests import _gate_shards as g
from tests import test_right_rail_gate_formats as fx
from tests.test_right_rail_gate_shards import restore, snapshot

SHARDS, STEPS, SEEDS, POOL = 3, 30, (1, 2), range(10, 22)  # a small id pool: shards fight over every id
PROBE = (22, 23, 36)  # fresh ids whose claim dates (id % 14 = 8, 9, 8) no pool id shares: never a near-duplicate
ACTS = ("batch",) * 10 + ("twice",) * 3 + ("reboot", "snapshot", "restore")
FAULTS = (None,) * 3 + ("reserve", "lean", "seal", "verify_failed", "verify_refused", "settle", "unavailable", "race", "out")
REFUSED = (decider.GateDecideError, producer.GateProducerError, idreg.IdRegistryError, signer.GateSignerError)


class Boom(Exception):
    """An injected crash or unexpected exception at a write point."""


class Chaos:
    def __init__(self, t: unittest.TestCase, c: g.Cluster, seed: int) -> None:
        self.t, self.c, self.rng = t, c, random.Random(seed)
        self.live, self.snaps, self.paid = {}, {}, {}  # shard -> (prod, reg); shard -> files; digest -> ALLOW lines
        self.restored, self.intruded, self.p = set(), [], 0

    def close(self, k: int) -> None:
        for handle in self.live.pop(k):
            handle.close()
        self.paid.update(g.sealed_allows(self.c, k))  # every sealed batch is seen before any restore can drop it

    def handles(self, k: int):
        if k not in self.live:
            prod = self.c.producer(k)
            try:
                self.live[k] = prod, idreg.IdRegistry(self.c.reg, boot=self.c.nonce)
            except BaseException:
                prod.close()
                raise
        return self.live[k]

    def intrude(self, k: int) -> None:
        other = idreg.IdRegistry(self.c.reg, boot=self.c.nonce)
        try:
            other.reserve(k, [], sealed=None)
            self.intruded.append(k)
        except idreg.IdRegistryError:
            pass
        finally:
            other.close()

    def inject(self, fault: str | None, k: int) -> contextlib.ExitStack:
        stack, patch = contextlib.ExitStack(), lambda *a, **kw: stack.enter_context(mock.patch.object(*a, **kw))
        if fault == "reserve":  # inside the reserve transaction, after a RESERVE row
            add = idreg._Tail.add
            patch(idreg._Tail, "add", lambda tail, kind, *rest: (add(tail, kind, *rest), kind == idreg._RESERVE and _boom()))
        elif fault == "lean":
            patch(decider.subprocess, "run", side_effect=Boom(fault))
        elif fault == "seal":  # the open row is stored, nothing signed
            patch(producer.ShardProducer, "_seal", side_effect=Boom(fault))
        elif fault in ("verify_failed", "verify_refused"):
            patch(signer, "seal", side_effect=signer.GateSignerError(f"gate_{fault}"))
        elif fault == "settle":
            patch(idreg.IdRegistry, "settle", side_effect=Boom(fault))
        elif fault == "unavailable":  # the next registry transaction only
            txn, calls = idreg._txn, []
            patch(idreg, "_txn", lambda *a: calls or calls.append(1) or _unavailable() if not calls else txn(*a))
        elif fault == "race":  # a second decider of the shard between commit's stale check and the seal
            commit = producer.ShardProducer.commit
            patch(producer.ShardProducer, "commit", lambda *a, **kw: (self.intrude(k), commit(*a, **kw))[1])
        return stack

    def batch(self, k: int, twice: bool) -> None:
        prod, reg = self.handles(k)
        answers = []
        for _ in range(1 + twice):
            ids, payments = self.rng.sample(POOL, self.rng.randint(1, 4)), {}
            for i in ids:
                if not payments or self.rng.random() < 0.6:
                    self.p += 1
                payments.setdefault(self.p, []).append(i)
            bad = [i for i in ids if self.rng.random() < 0.2]
            answers.append(g.decide_batch(self.c, prod, reg, k, payments, bad)[:2])
        for ans, leaves in self.rng.sample(answers, len(answers)):
            try:
                if leaves:
                    decider.commit(prod, reg, fx.PROGRAM, leaves, ans, fx.NOW)
            except decider.GateDecideError as error:
                if str(error) != "stale_answer":
                    raise

    def step(self) -> None:
        k, act = self.rng.randrange(SHARDS), self.rng.choice(ACTS)
        if act == "reboot":  # every process restarts
            for s in list(self.live):
                self.close(s)
            try:
                self.c.boot()
            except idreg.IdRegistryError as error:  # a rewound store halts the boot; the running nonce stays
                self.t.assertTrue(self.restored and str(error) == "registry_rewound", error)
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
        else:
            fault = self.rng.choice(FAULTS)
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
            self.paid.update(g.sealed_allows(self.c, k))
        lines = sorted(i for paid in self.paid.values() for _, i in paid)
        self.t.assertEqual(len(lines), len(set(lines)), f"a line id was ALLOWed twice: {lines}")
        self.t.assertEqual(self.intruded, [], "a second decider reserved inside a commit")
        g.owned(self.c, self.t)
        with contextlib.suppress(idreg.IdRegistryError) if self.restored else contextlib.nullcontext():
            self.c.boot()
        for k in set(range(SHARDS)) - self.restored:  # no healthy shard wedges
            self.p += 1
            self.t.assertEqual(self.c.send(k, {self.p: [PROBE[k]]}), {PROBE[k]: "ALLOW -"}, f"shard {k} is wedged")
        if not self.restored:
            g.inv(self.t, self.c)


def _boom():
    raise Boom("reserve")


def _unavailable():
    raise idreg.IdRegistryError("registry_unavailable")


class GateChaosTests(fx.Scratch):
    def test_interleaved_deciders_never_pay_a_line_twice(self) -> None:
        for seed in SEEDS:
            with self.subTest(seed=seed), self.scratch() as tmp:
                c = g.Cluster(tmp, fx.custody(tmp), SHARDS)
                c.boot()
                Chaos(self, c, seed).run()


if __name__ == "__main__":
    unittest.main()
