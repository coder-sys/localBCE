"""Gate pipeline bench (speed plan step 0; test-only, synthetic, non-PHI): seeded lines through the real decide path, in batches,
with the exclusive time of each stage per line and its growth with history.  ``python -m tests.gate_bench --sizes 10000,100000
--batch 1000 --out <json>``.  It changes no product code: each stage is a timing wrapper over the real function.

Stages (µs per line): parse (the harness's line text and answer parse), frame (decide's text and hex of the sealed history),
registry, storage (SQLite reads and writes), lean_decide and lean_replay (the Lean call, split by a probe that sends the same
frame without its ``line`` rows: what is left is the history replay), canon (encoding and digests), sign, verify (Lean
``gate_verify``), seal_other.  ``total`` leaves out the probe and the harness's own token leaves.  The guard owns memory policy: only with ``free`` (callable, free bytes; the CLI passes the live reading) does a batch whose Lean call
would need more (about 700 times its frame) stop the run and record the wall."""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import itertools
import json
import os
import random
import sqlite3
import subprocess
import tempfile
import time
import types
from collections import defaultdict
from pathlib import Path
from unittest import mock

from app import right_rail_gate_codec as gate
from app import right_rail_gate_decide as decider
from app import right_rail_gate_idreg as idreg
from app import right_rail_gate_producer as producer
from app import right_rail_gate_signer as signer
from tests import _gate_shards as g
from tests import test_gate_rules_worker as w
from tests import test_right_rail_gate_formats as fx

SEED, PER_PAYMENT, MEM_PER_FRAME_BYTE = 20261005, 4, 700
NONCES = itertools.count(int.from_bytes(bytes(range(32)), "big"))  # the patched os.urandom: seeded, unique per call, first bytes(range(32))
REPORT = ("parse", "frame", "registry", "storage", "lean_decide", "lean_replay", "canon", "sign", "verify", "seal_other")


def free_bytes() -> int:
    fields = [("size", ctypes.c_ulong), ("load", ctypes.c_ulong)] + [(n, ctypes.c_ulonglong) for n in ("total", "avail", "a", "b", "c", "d", "e")]
    status = type("MEMORYSTATUSEX", (ctypes.Structure,), {"_fields_": fields})()
    status.size = ctypes.sizeof(status)
    ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status))
    return status.avail


class Stages:
    """Exclusive time per named stage: a wrapped call stops its caller's clock and restarts it on return."""

    def __init__(self) -> None:
        self.t, self.stack = defaultdict(float), [["other", time.perf_counter()]]

    def wrap(self, name, fn):
        def run(*a, **kw):
            now = time.perf_counter()
            self.t[self.stack[-1][0]] += now - self.stack[-1][1]
            self.stack.append([name, now])
            try:
                return fn(*a, **kw)
            finally:
                now = time.perf_counter()
                self.t[name] += now - self.stack.pop()[1]
                self.stack[-1][1] = now
        return run

    def take(self) -> dict[str, float]:
        now = time.perf_counter()
        self.t[self.stack[-1][0]] += now - self.stack[-1][1]
        self.stack[-1][1] = now
        out, self.t = dict(self.t), defaultdict(float)
        return out


def corpus(total: int, batch: int):
    """Batches of (payment number -> line ids, ids of deceased members), fixed by SEED; line ids run 1..total."""
    rng, ids = random.Random(SEED), iter(range(1, total + 1))
    for b in range(0, total, batch):
        take = [i for _, i in zip(range(min(batch, total - b)), ids)]
        yield ({1 + (b + k) // PER_PAYMENT: take[k : k + PER_PAYMENT] for k in range(0, len(take), PER_PAYMENT)},
               {i for i in take if rng.random() < 0.05})


def _probe(fn, S):
    """Wrap a Lean call so the same frame minus its ``line`` rows runs first, as the replay probe (answer checked, never used)."""
    def run(first, *rest, **kw):
        if isinstance(first, bytes):
            probe = b"\n".join(r for r in first.split(b"\n") if not r.startswith(b"line "))
            ok = S.wrap("lean_probe", fn)(probe, *rest, **kw)
        else:  # the one-shot exe: (argv, ...) with the frame file last
            argv = list(first)
            Path(argv[1] + ".probe").write_bytes(b"\n".join(r for r in Path(argv[1]).read_bytes().split(b"\n") if not r.startswith(b"line ")))
            ok = S.wrap("lean_probe", fn)([argv[0], argv[1] + ".probe"], *rest, **kw).stdout.splitlines()
        S.probes.append("RULES_VECTORS=PASS checked=0 expected=0 failed=0" in ok)
        return S.wrap("lean_call", fn)(first, *rest, **kw)
    return run


def run_bench(total: int, batch: int, probe: bool = True, sizes: tuple[int, ...] = (), free=None) -> dict:
    S, rows, wall, store = Stages(), [], None, []
    S.probes = []
    worker = decider.RulesWorker(w.WORKER)
    adds_of = producer.ShardProducer.sealed_adds  # the unwrapped read, for the pre-flight estimate
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp, contextlib.ExitStack() as stack:
        stack.callback(worker.close)
        c = g.Cluster(tmp, fx.custody(tmp), shards=1)
        with mock.patch.object(idreg.os, "urandom", lambda n: next(NONCES).to_bytes(n, "big")):
            c.boot()
        real_run, real_exe = decider.RulesWorker.run, subprocess.run
        if probe:
            wrapped_run = _probe(lambda data: real_run(worker, data), S)
            patch_worker = lambda self, data: wrapped_run(data)
            patch_exe = types.SimpleNamespace(run=lambda argv, **kw: _probe(lambda a, **k: real_exe(a, **k), S)(argv, **kw), TimeoutExpired=subprocess.TimeoutExpired)
        else:
            patch_worker = S.wrap("lean_call", real_run)
            patch_exe = types.SimpleNamespace(run=S.wrap("lean_call", real_exe), TimeoutExpired=subprocess.TimeoutExpired)
        stack.enter_context(mock.patch.object(decider.RulesWorker, "run", patch_worker))
        stack.enter_context(mock.patch.object(decider, "subprocess", patch_exe))
        for owner, attr, name in (
                (g, "decide_batch", "parse"), (decider, "decide", "frame"), (decider, "commit", "storage"), (fx, "_leaf", "harness"),
                (fx, "member", "harness"), (idreg.IdRegistry, "reserve", "registry"), (idreg.IdRegistry, "settle", "registry"),
                (idreg.IdRegistry, "in_flight", "registry"), (idreg.IdRegistry, "settled", "registry"),
                (producer.ShardProducer, "commit", "storage"), (producer.ShardProducer, "anchor", "storage"),
                (producer.ShardProducer, "tip", "storage"), (producer.ShardProducer, "sealed_adds", "storage"),
                (producer.ShardProducer, "sealed_frees", "storage"), (gate, "build_batch", "canon"), (gate, "encode_token", "canon"),
                (gate, "encode_checkpoint_header", "canon"), (gate, "checkpoint_digest", "canon"), (signer, "framed", "canon"),
                (signer, "seal", "seal_other"), (signer, "sign", "sign"), (signer, "gate_verify", "verify")):
            stack.enter_context(mock.patch.object(owner, attr, S.wrap(name, getattr(owner, attr))))
        prod, reg = c.producer(0), idreg.IdRegistry(c.reg, boot=c.nonce)
        stack.callback(reg.close)
        done, started = 0, time.perf_counter()
        S.take()
        for payments, bad in corpus(total, batch):
            lines = sum(map(len, payments.values()))
            frame = 2 * len(adds_of(prod)) + 400 * lines + 4096
            need, avail = MEM_PER_FRAME_BYTE * frame, free() if free else None
            if free and avail < need:
                wall = {"reason": "memory", "history_lines": done, "frame_bytes": frame, "need_bytes": need, "free_bytes": avail}
                break
            S.take()
            t0 = time.perf_counter()
            try:
                ans, leaves, _ = g.decide_batch(c, prod, reg, 0, payments, bad, worker)
                decider.commit(prod, reg, fx.PROGRAM, leaves, ans, fx.NOW)
            except decider.GateDecideError as error:
                wall = {"reason": f"refused:{error}", "history_lines": done, "frame_bytes": frame, "need_bytes": need, "free_bytes": avail}
                break
            spent = S.take()
            t1 = time.perf_counter()
            us = {k: v / lines * 1e6 for k, v in spent.items()}
            probed = us.pop("lean_probe", 0.0)
            call = us.pop("lean_call", 0.0)
            us["lean_replay"], us["lean_decide"] = probed, call - probed  # a cold first batch can make this negative: its probe pays the start
            us.setdefault("other", 0.0)
            us["total"] = (t1 - t0 - spent.get("lean_probe", 0.0) - spent.get("harness", 0.0)) / lines * 1e6
            rows.append({"cold": not rows, "history_before": done, "lines": lines, "frame_est_bytes": frame, "path": "exe" if frame > decider.FRAME_CAP else "worker",
                         "us_per_line": {k: round(v, 1) for k, v in us.items()}})
            done += lines
        elapsed = time.perf_counter() - started
        published, flat = prod.published(), []
        prod.close()
        for path, sql in ((c.store(0), "SELECT header, tokens, state_digest, adds FROM batches ORDER BY id"), (c.reg, "SELECT head FROM log ORDER BY n")):
            db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
            try:
                flat += [x for r in db.execute(sql).fetchall() for x in r]
            finally:
                db.close()
        store = flat + published
    warm = rows[1:]  # the first batch pays the exes' first start: kept in ``batches``, left out of the fit
    xs, ys, rs = [r["history_before"] for r in warm], [r["us_per_line"]["total"] for r in warm], [r["us_per_line"]["lean_replay"] for r in warm]
    slope = lambda a, b: (sum((x - sum(a) / len(a)) * (y - sum(b) / len(b)) for x, y in zip(a, b)) / sum((x - sum(a) / len(a)) ** 2 for x in a) * 1000
                          if len(a) > 1 and len(set(a)) > 1 else None)
    return {"seed": SEED, "batch": batch, "requested_lines": total, "sizes_requested": list(sizes), "lines_done": done,
            "batches_done": len(rows), "wall": wall, "probe": probe, "probes_ok": sum(S.probes), "probes": len(S.probes),
            "seconds": round(elapsed, 2), "batches": rows,
            "growth": {"warm_first_total_us": ys[0] if ys else None, "warm_last_total_us": ys[-1] if ys else None,
                       "total_us_per_line_per_1000_history_lines": slope(xs, ys), "replay_us_per_line_per_1000_history_lines": slope(xs, rs)},
            "stages": list(REPORT) + ["total"], "corpus": store}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sizes", default="10000,100000", help="history sizes to reach, comma separated (1000000 only on request)")
    ap.add_argument("--batch", type=int, default=1000)
    ap.add_argument("--no-probe", action="store_true")
    ap.add_argument("--out")
    a = ap.parse_args()
    sizes = tuple(int(s) for s in a.sizes.split(","))
    result = run_bench(max(sizes), a.batch, not a.no_probe, sizes, free_bytes)
    result.pop("corpus")
    if a.out:
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(json.dumps(result, indent=1), "utf-8")
    print("BENCH", {k: v for k, v in result.items() if k != "batches"})
    for r in result["batches"]:
        print("BENCH_BATCH", r["history_before"], r["path"], r["frame_est_bytes"], r["us_per_line"])


if __name__ == "__main__":
    main()
