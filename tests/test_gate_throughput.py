"""Gate throughput bench (test-only): N synthetic lines through the real decide path (registry reserve, Lean rules worker, seal,
settle, ML-DSA sign, Lean publish check).  Prints lines/s and per-stage microseconds per line; asserts no speed.  It asserts the
results are correct and that every stored output byte (headers, tokens, state digests, adds, registry chain; not the hedged
signatures) matches the digest below.  RR_GATE_BENCH_N / _BATCH resize it (the digest is checked only for 2000 lines at batch 100 or 2000);
RR_GATE_BENCH_PROFILE=<file> writes a cProfile top 30."""

import collections
import contextlib
import cProfile
import hashlib
import io
import itertools
import os
import pstats
import random
import sqlite3
import subprocess
import time
import types
import unittest
from unittest import mock

from app import right_rail_gate_codec as gate
from app import right_rail_gate_decide as decider
from app import right_rail_gate_idreg as idreg
from app import right_rail_gate_producer as producer
from app import right_rail_gate_signer as signer
from tests import _gate_shards as g
from tests import test_gate_rules_worker as w
from tests import test_right_rail_gate_formats as fx

N, BATCH = int(os.environ.get("RR_GATE_BENCH_N", 2000)), int(os.environ.get("RR_GATE_BENCH_BATCH", 100))
PER_PAYMENT, SEED = 4, 20261005
# sha256 of the stored outputs of the 2,000-line corpus by batch size, taken before any speed change (suffixes gs-1, gs-3b2000)
NONCES = itertools.count(int.from_bytes(bytes(range(32)), "big"))  # the patched os.urandom: seeded, unique per call, first bytes(range(32))
OUTPUT_DIGEST = {100: "9e7563e9d853b49c6d640580615eddfcf3c4b72e333aaaeb96093f24ac4399d0",
                 2000: "a5af4402a537bfd77fc66faa81ac6144ee0cd4d23b80572f32d44dc587a87b73"}
STAGES = {"leaves": None, "decide": None, "  registry reserve": (idreg.IdRegistry, "reserve"), "  rules worker": (decider.RulesWorker, "run"), "  one-shot exe": None,
          "  producer reads": None, "commit": None, "  build batch": (gate, "build_batch"), "  sign": (signer, "sign"),
          "  gate_verify": (signer, "gate_verify"), "settle": (idreg.IdRegistry, "settle")}


def corpus() -> list[tuple[dict[int, list[int]], set[int]]]:
    """Batches of (payment number -> its line ids, the ids of deceased members), fixed by SEED."""
    rng, ids = random.Random(SEED), iter(range(1, N + 1))
    out = []
    for b in range(0, N, BATCH):
        take = [i for _, i in zip(range(min(BATCH, N - b)), ids)]
        out.append(({1 + (b + k) // PER_PAYMENT: take[k : k + PER_PAYMENT] for k in range(0, len(take), PER_PAYMENT)},
                    {i for i in take if rng.random() < 0.05}))
    return out


def stored_digest(c: g.Cluster) -> str:
    h = hashlib.sha256()
    for path, sql in ((c.store(0), "SELECT epoch, seq_from, seq_to, digest, header, state_digest, tokens, idreg_n, free, adds FROM batches ORDER BY id"),
                      (c.reg, "SELECT n, kind, id, shard, head FROM log ORDER BY n")):
        db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            h.update(repr(db.execute(sql).fetchall()).encode())
        finally:
            db.close()
    return h.hexdigest()


@unittest.skipUnless(os.name == "nt" and os.path.isfile(g.rules.EXE) and w.WORKER.is_file(), "GATE THROUGHPUT NOT RUN: the Lean rules exes are missing")
class GateThroughput(fx.Scratch):
    def test_bench(self):
        spent = {name: 0.0 for name in STAGES}

        def timed(name, fn):
            def run(*a, **kw):
                t = time.perf_counter()
                try:
                    return fn(*a, **kw)
                finally:
                    spent[name] += time.perf_counter() - t
            return run

        statuses, worker = {}, decider.RulesWorker(w.WORKER)
        self.addCleanup(worker.close)
        with self.scratch() as tmp, contextlib.ExitStack() as stack:
            c = g.Cluster(tmp, fx.custody(tmp), shards=1)
            with mock.patch.object(idreg.os, "urandom", lambda n: next(NONCES).to_bytes(n, "big")):  # the BOOT nonce is the only random byte in the stored outputs
                c.boot()
            stack.enter_context(mock.patch.object(decider, "subprocess", types.SimpleNamespace(
                run=timed("  one-shot exe", subprocess.run), TimeoutExpired=subprocess.TimeoutExpired)))
            for name, (owner, attr) in ((n, t) for n, t in STAGES.items() if t):
                stack.enter_context(mock.patch.object(owner, attr, timed(name, getattr(owner, attr))))
            for owner, attr, name in ((decider, "decide", "decide"), (decider, "commit", "commit"), (g, "decide_batch", "leaves")):
                stack.enter_context(mock.patch.object(owner, attr, timed(name, getattr(owner, attr))))
            prod, reg = c.producer(0), idreg.IdRegistry(c.reg, boot=c.nonce)
            for attr in ("anchor", "tip", "sealed_adds", "sealed_frees"):
                stack.enter_context(mock.patch.object(producer.ShardProducer, attr, timed("  producer reads", getattr(producer.ShardProducer, attr))))
            profile = cProfile.Profile() if os.environ.get("RR_GATE_BENCH_PROFILE") else None
            started = time.perf_counter()
            with contextlib.ExitStack() as run:
                if profile:
                    profile.enable()
                    run.callback(profile.disable)
                for payments, bad in corpus():
                    ans, leaves, status = g.decide_batch(c, prod, reg, 0, payments, bad, worker)
                    statuses.update({i: (s, i in bad) for i, s in status.items()})
                    decider.commit(prod, reg, fx.PROGRAM, leaves, ans, fx.NOW)
            elapsed = time.perf_counter() - started
            published = prod.published()
            prod.close()
            reg.close()
            digest = stored_digest(c)
        spent["leaves"] -= spent["decide"]  # decide_batch wraps decide
        print(f"\nGATE_BENCH lines={N} batch={BATCH} seconds={elapsed:.2f} lines_per_s={N / elapsed:.0f} us_per_line={elapsed / N * 1e6:.0f} digest={digest}")
        for name, sec in spent.items():
            print(f"GATE_BENCH_STAGE {name:<20}{sec / N * 1e6:8.0f} us/line {sec / elapsed:6.1%}")
        if profile:
            out = io.StringIO()
            pstats.Stats(profile, stream=out).sort_stats("cumulative").print_stats(30)
            pstats.Stats(profile, stream=out).sort_stats("tottime").print_stats(30)
            open(os.environ["RR_GATE_BENCH_PROFILE"], "w", encoding="utf-8").write(out.getvalue())
        self.assertEqual(sorted(statuses), list(range(1, N + 1)))
        print("GATE_BENCH_OUTCOMES", sorted(collections.Counter((s, bad) for s, bad in statuses.values()).items()))
        self.assertTrue(all(not s.startswith("ALLOW") for s, bad in statuses.values() if bad))
        self.assertEqual(len(published), len(corpus()))
        self.assertTrue(all(len(p) > gate.ML_DSA_87_SIGNATURE for p in published))
        if N == 2000 and BATCH in OUTPUT_DIGEST:
            self.assertEqual(digest, OUTPUT_DIGEST[BATCH])


if __name__ == "__main__":
    unittest.main()
