"""Gate throughput bench (test-only): N synthetic lines through the real decide path (Lean rules worker, seal,
ML-DSA sign, Lean publish check).  Prints lines/s and per-stage microseconds per line; asserts no speed.  It asserts the
results are correct and that every stored output byte (headers, tokens, state digests, adds; not the hedged
signatures) matches the digest below, taken on the history-index pipeline, while every batch after the first opens the index at
the signed chain head (the history never travels in a frame); a flipped head, a wrong batch count or a stale frame is refused.
RR_GATE_BENCH_N / _BATCH resize it (the digest and the per-outcome and per-reason counts are checked only for 2000 lines at
batch 100 or 2000);
RR_GATE_BENCH_PROFILE=<file> writes a cProfile top 30."""

import collections
import contextlib
import cProfile
import hashlib
import io
import os
import pstats
from pathlib import Path
import random
import re
import time
import unittest
from unittest import mock

from app import right_rail_gate_codec as gate
from app import right_rail_gate_decide as decider
from app import right_rail_gate_producer as producer
from app import right_rail_gate_signer as signer
from tests import _gate_shards as g
from tests import test_flat_worker as fw
from tests import test_gate_rules_worker as w
from tests import test_right_rail_gate_formats as fx

N, BATCH = int(os.environ.get("RR_GATE_BENCH_N", 2000)), int(os.environ.get("RR_GATE_BENCH_BATCH", 100))
PER_PAYMENT, SEED = 4, 20261005
# sha256 of the stored outputs of the 2,000-line corpus by batch size, taken on the history-index path (the index salt is seeded below);
# the tokens carry the deciding worker's digest, so a gate_engine re-pin moves them, and the checkpoints carry the counter
OUTPUT_DIGEST = {100: "09eea1c22fde6dd523fcefda77b4b642bb8b65a2118078b6df15b3b04401ce7d",
                 2000: "0ce87da422adf6c7e30c7ae1ff3c22c76c41a2bb1701ea09ef3dfa705a6da4ef"}
REALISTIC = os.environ.get("RR_GATE_BENCH_CORPUS") == "realistic"  # the seeded distinct-claims corpus (g.claim)
REALISTIC_DIGEST = {100: "5918882a88c740a1d286d43b89ad4796987fd8cffb8acc46d087a16e3ee640f0",
                    2000: "c16c02ee5d950cb9f2da2ab4878ecb5c4d7a4452738bc39847cb52f94d845012"}
# SHA3-512 of the sorted (line id, "OUTCOME REASONS") pairs of the 2,000-line corpus by (realistic?, batch size): the decisions alone,
# which carry no engine hash, so a re-pin that moves the digests above must keep these (two lines that swap outcomes change this hash)
PAIRS_DIGEST = {
    (False, 100): "ecd6ee352e1ee82333d4fa5e112636ebcc85add8cd0f75f840861f0bf761b4a2b17520f89d6ec57fa5b9c0f8775878fc5a26ad4d237f4a4013fca3999c035c17",
    (False, 2000): "767dbdffd16aa0002e49fb3bc1972cb056f2cbcd53fed58c13f071682eca7f1961ccb7a820539052e1cc4a66f399de93374273e1c179ed8b4430d8a21db9c460",
    (True, 100): "3987e2d226c39fe49189f409debc1b34220ea4c0f4e77c739bb1977435819cbbe8065dae34685f199111a1afca71a3c3043a8040b05ba4302ef27fe2d05e96b6",
    (True, 2000): "4bdf0ac46f4064870b6dd9336187d35d803f071e78a712bd34746ee2e5c33e4a4a3b9983049222ecaa9781a677a0c7a96bb0fb597bea4bad7342ddccaffbf848"}
STAGES = {"leaves": None, "decide": None, "  rules worker": (decider.RulesWorker, "run_frame"),
          "  producer reads": None, "commit": None, "  build batch": (gate, "build_batch"), "  sign": (signer, "sign"),
          "  gate_verify": (signer, "gate_verify")}


def corpus() -> list[tuple[dict[int, list[int]], set[int]]]:
    """Batches of (payment number -> its line ids, the ids of deceased members), fixed by SEED."""
    rng, ids = random.Random(SEED), iter(range(1, N + 1))
    out = []
    for b in range(0, N, BATCH):
        take = [i for _, i in zip(range(min(BATCH, N - b)), ids)]
        out.append(({1 + (b + k) // PER_PAYMENT: take[k : k + PER_PAYMENT] for k in range(0, len(take), PER_PAYMENT)},
                    {i for i in take if rng.random() < 0.05}))
    return out


def pairs_digest(statuses: dict) -> str:
    return hashlib.sha3_512("".join(f"{i} {s}\n" for i, (s, _) in sorted(statuses.items())).encode()).hexdigest()


def stored_digest(c: g.Cluster) -> str:
    h = hashlib.sha256()
    db = g.read_only(c.store(0))
    try:
        h.update(repr(db.execute("SELECT epoch, seq_from, seq_to, digest, header, state_digest, tokens, adds FROM batches ORDER BY id").fetchall()).encode())
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

        # RR_GATE_BENCH_DUMP=<dir>: every gate_verify frame (mode byte then frame) is written there.
        dump, frames = os.environ.get("RR_GATE_BENCH_DUMP"), []

        def verify(real):
            def run(mode, frame):
                if dump:
                    open(os.path.join(dump, f"v{len(os.listdir(dump)):05d}.bin"), "wb").write(bytes([mode]) + frame)
                return real(mode, frame)
            return run

        statuses, worker = {}, decider.RulesWorker(Path(os.environ.get("RR_GATE_BENCH_WORKER", w.WORKER)))
        self.addCleanup(worker.close)
        with self.scratch() as tmp, contextlib.ExitStack() as stack:
            c = g.Cluster(tmp, fx.custody(tmp), shards=1)
            wrapped = {"  rules worker": lambda f: lambda self, directory, shard, data: frames.append(data) or f(self, directory, shard, data), "  gate_verify": verify}
            for name, (owner, attr) in ((n, t) for n, t in STAGES.items() if t):
                stack.enter_context(mock.patch.object(owner, attr, timed(name, wrapped.get(name, lambda f: f)(getattr(owner, attr)))))
            for owner, attr, name in ((decider, "decide", "decide"), (decider, "commit", "commit"), (g, "decide_batch", "leaves")):
                stack.enter_context(mock.patch.object(owner, attr, timed(name, getattr(owner, attr))))
            prod = c.producer(0)
            for attr in ("anchor", "tip", "flat_head", "sealed_quar"):
                stack.enter_context(mock.patch.object(producer.ShardProducer, attr, timed("  producer reads", getattr(producer.ShardProducer, attr))))
            profile = cProfile.Profile() if os.environ.get("RR_GATE_BENCH_PROFILE") else None
            started = time.perf_counter()
            with contextlib.ExitStack() as run:
                if profile:
                    profile.enable()
                    run.callback(profile.disable)
                for payments, bad in corpus():
                    ans, leaves, status = g.decide_batch(c, prod, 0, payments, bad, worker)
                    statuses.update({i: (s, i in bad) for i, s in status.items()})
                    decider.commit(prod, fx.PROGRAM, ans, fx.NOW, c.tenant)
            elapsed = time.perf_counter() - started
            ran = dict(spent)  # the stage times of the run, before the kill check calls the worker again
            self.assertEqual([int.from_bytes(f[10:18], "little") for f in frames], list(range(1, len(corpus()) + 1)))  # batch numbers run on from the genesis
            self.kill_check(worker, frames[-1], c.dir / "idx0", *prod.flat_head())
            worker.close()  # it holds the index files the scratch directory removes
            published = prod.published()
            prod.close()
            digest = stored_digest(c)
        ran["leaves"] -= ran["decide"]  # decide_batch wraps decide
        print(f"\nGATE_BENCH lines={N} batch={BATCH} seconds={elapsed:.2f} lines_per_s={N / elapsed:.0f} us_per_line={elapsed / N * 1e6:.0f} digest={digest}")
        for name, sec in ran.items():
            print(f"GATE_BENCH_STAGE {name:<20}{sec / N * 1e6:8.0f} us/line {sec / elapsed:6.1%}")
        if profile:
            out = io.StringIO()
            pstats.Stats(profile, stream=out).sort_stats("cumulative").print_stats(30)
            pstats.Stats(profile, stream=out).sort_stats("tottime").print_stats(30)
            open(os.environ["RR_GATE_BENCH_PROFILE"], "w", encoding="utf-8").write(out.getvalue())
        self.assertEqual(sorted(statuses), list(range(1, N + 1)))
        counts = collections.Counter((s, bad) for s, bad in statuses.values())
        print("GATE_BENCH_OUTCOMES", sorted(counts.items()))
        self.assertTrue(all(not s.startswith("ALLOW") for s, bad in statuses.values() if bad))
        self.assertEqual(len(published), len(corpus()))
        self.assertTrue(all(len(p) > gate.ML_DSA_87_SIGNATURE for p in published))
        if N == 2000 and BATCH in OUTPUT_DIGEST:
            table = REALISTIC_DIGEST if REALISTIC else OUTPUT_DIGEST
            self.assertIn(BATCH, table, f"no stored digest for this corpus at batch {BATCH}")
            self.assertEqual(pairs_digest(statuses), PAIRS_DIGEST[REALISTIC, BATCH])
            self.assertEqual(digest, table[BATCH])

    def kill_check(self, worker, last: bytes, directory, anchor: bytes, count: int):
        """The index is at the signed head after the run: a request that names the head with one byte flipped, or the wrong next
        batch number, is refused; the last batch's own frame, now stale (the index is past the head it names), is refused;
        a request at the true head is answered OK, before and after the first two refusals."""
        flip = lambda b: b[:len(b) // 2] + bytes([b[len(b) // 2] ^ 1]) + b[len(b) // 2 + 1:]
        where = str(directory.absolute()).replace("\\", "/")
        probe = lambda head, n: worker.run_frame(where, 0, decider.request_frame(g.HEAD, 0, n, 0, head, g.PIN, fw.floors(head), g.KEYS, g.GRANT, worker.launched_release(), (), ()))[6]
        self.assertEqual(probe(anchor, count + 1), 0)
        self.assertNotEqual(probe(flip(anchor), count + 1), 0)
        self.assertNotEqual(probe(anchor, count + 2), 0)
        worker.close()  # as decide does after a refused request: a fresh process reads the index, which the refusals left at the head
        self.assertEqual(probe(anchor, count + 1), 0)
        if count > 1:  # a one-batch run only inits
            self.assertNotEqual(worker.run_frame(where, 0, last)[6], 0)  # last: the index is past the head it names


if __name__ == "__main__":
    unittest.main()
