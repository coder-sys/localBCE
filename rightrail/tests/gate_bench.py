"""Gate pipeline bench (test-only, synthetic, non-PHI): seeded lines through the real decide path on the history index, in
batches, with the exclusive time of each stage per line and its growth with history.  ``python -m tests.gate_bench --sizes
10000,100000 --batch 1000 --out <json>``.  It changes no product code: each stage is a timing wrapper over the real function.

Stages (us per line): parse (the harness's line text and answer parse), frame (decide's text and the index sync),
storage (SQLite reads and writes), lean (the call to the rules worker), canon (encoding and digests), sign, verify (Lean
``gate_verify``), seal_other.  ``total`` leaves out the harness's own token leaves.  The guard owns memory policy: only with
``free`` (callable, free bytes; the CLI passes the live reading) does a batch whose Lean call would need more (twice the
worker's commit plus about 500 times the batch's frame) stop the run and record the wall.  A wall of any kind exits non-zero: a
run that stops short is never a pass.  So does any batch whose worker died and was relaunched (e.g. at the job's memory
cap): a batch's ``served`` says which, and ``relaunches`` counts them.  ``--flat`` runs ``run_flat`` instead: the engine
alone over a pipe, one binary frame of signed requests per batch, with its phase timers at growing history."""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import json
import shutil
import os
import random
import struct
import subprocess
import sys
import tempfile
import threading
import time
from collections import defaultdict
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # so `python tests/gate_bench.py` finds `app` and `tests`

from app import right_rail_gate_chain as chain
from app import right_rail_gate_codec as gate
from app import right_rail_gate_decide as decider
from app import right_rail_gate_producer as producer
from app import right_rail_gate_signer as signer
from tests import _gate_shards as g
from tests import gate_corpus
from tests import test_gate_rules_worker as w
from tests import test_right_rail_gate_formats as fx

SEED, PER_PAYMENT, MEM_PER_FRAME_BYTE = 20261005, 4, 500
REPORT = ("parse", "frame", "storage", "lean", "canon", "sign", "verify", "seal_other")


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


def run_bench(total: int, batch: int, sizes: tuple[int, ...] = (), free=None) -> dict:
    S, rows, wall, store = Stages(), [], None, []
    S.relaunches = 0
    worker = decider.RulesWorker(w.WORKER)
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp, contextlib.ExitStack() as stack:
        stack.callback(worker.close)
        c = g.Cluster(tmp, fx.custody(tmp), shards=1)
        run_frame = decider.RulesWorker.run_frame

        def counted(self, directory, shard, data):  # decide relaunches a dead worker and sends the frame again: the bench counts the death
            try:
                return run_frame(self, directory, shard, data)
            except decider.WorkerDied:
                S.relaunches += 1
                raise

        stack.enter_context(mock.patch.object(decider.RulesWorker, "run_frame", S.wrap("lean", counted)))
        for owner, attr, name in (
                (g, "decide_batch", "parse"), (decider, "decide", "frame"), (decider, "commit", "storage"), (fx, "_leaf", "harness"),
                (fx, "member", "harness"),
                (producer.ShardProducer, "commit", "storage"), (producer.ShardProducer, "anchor", "storage"),
                (producer.ShardProducer, "tip", "storage"), (producer.ShardProducer, "flat_head", "storage"),
                (producer.ShardProducer, "sealed_quar", "storage"), (gate, "build_batch", "canon"),
                (gate, "encode_token", "canon"), (gate, "encode_checkpoint_header", "canon"), (gate, "checkpoint_digest", "canon"),
                (signer, "framed", "canon"), (signer, "seal", "seal_other"), (signer, "sign", "sign"), (signer, "gate_verify", "verify")):
            stack.enter_context(mock.patch.object(owner, attr, S.wrap(name, getattr(owner, attr))))
        prod = c.producer(0)
        done, started = 0, time.perf_counter()
        S.take()
        for payments, bad in corpus(total, batch):
            lines = sum(map(len, payments.values()))
            frame = 400 * lines + 4096  # the batch's own text: the history stays in the index, never in a frame
            cur = worker._worker.commit_bytes() if worker._worker else 0
            need, avail = 2 * cur + MEM_PER_FRAME_BYTE * frame, free() if free else None
            if free and avail < need:
                wall = {"reason": "memory", "history_lines": done, "frame_bytes": frame, "need_bytes": need, "free_bytes": avail}
                break
            S.take()
            t0, relaunches = time.perf_counter(), S.relaunches
            why = "hold_answer"
            try:
                ans, leaves, status = g.decide_batch(c, prod, 0, payments, bad, worker)
                if not ans.digest:  # a HOLD answer: name its own cause (state_mismatch, r3_unconfirmed, quar_torn, ...)
                    why = (next(iter(status.values()), "").split() or [why])[-1]
                decider.commit(prod, fx.PROGRAM, ans, fx.NOW, c.tenant)
            except decider.GateDecideError as error:
                wall = {"reason": f"held:{why}" if str(error) == "hold_answer" else f"refused:{error.args[0]}:{getattr(error, 'action', '-')}", "history_lines": done, "frame_bytes": frame, "need_bytes": need, "free_bytes": avail}
                break
            spent = S.take()
            t1 = time.perf_counter()
            us = {k: v / lines * 1e6 for k, v in spent.items()}
            us.setdefault("other", 0.0)
            us["total"] = (t1 - t0 - spent.get("harness", 0.0)) / lines * 1e6
            rows.append({"cold": not rows, "history_before": done, "lines": lines, "frame_est_bytes": frame, "worker_commit_bytes": cur,
                         "served": "relaunched" if S.relaunches > relaunches else "resident", "us_per_line": {k: round(v, 1) for k, v in us.items()}})
            done += lines
        elapsed = time.perf_counter() - started
        published, flat = prod.published(), []
        prod.close()
        for path, sql in ((c.store(0), "SELECT header, tokens, state_digest, adds FROM batches ORDER BY id"),):
            db = g.read_only(path)
            try:
                flat += [x for r in db.execute(sql).fetchall() for x in r]
            finally:
                db.close()
        store = flat + published
        worker.close()  # it holds the index files the temporary directory removes
    warm = rows[1:]  # the first batch pays the exes' first start: kept in ``batches``, left out of the fit
    xs, ys = [r["history_before"] for r in warm], [r["us_per_line"]["total"] for r in warm]
    mean = lambda v: sum(v) / len(v)
    slope = (sum((x - mean(xs)) * (y - mean(ys)) for x, y in zip(xs, ys)) / sum((x - mean(xs)) ** 2 for x in xs) * 1000
             if len(xs) > 1 and len(set(xs)) > 1 else None)
    return {"seed": SEED, "batch": batch, "requested_lines": total, "sizes_requested": list(sizes), "lines_done": done,
            "batches_done": len(rows), "relaunches": S.relaunches, "wall": wall, "seconds": round(elapsed, 2), "batches": rows,
            "growth": {"warm_first_total_us": ys[0] if ys else None, "warm_last_total_us": ys[-1] if ys else None,
                       "total_us_per_line_per_1000_history_lines": slope},
            "stages": list(REPORT) + ["total"], "corpus": store}


def peak_rss(proc) -> int:
    """Peak working set of a running child, bytes (Windows psapi)."""
    class Counters(ctypes.Structure):
        _fields_ = [("cb", ctypes.c_ulong), ("faults", ctypes.c_ulong), ("peak", ctypes.c_size_t)] + [(n, ctypes.c_size_t) for n in "abcdefg"]
    c = Counters()
    c.cb = ctypes.sizeof(c)
    ctypes.windll.psapi.GetProcessMemoryInfo(ctypes.c_void_p(int(proc._handle)), ctypes.byref(c), c.cb)
    return c.peak


class Engine:
    """`gate_engine` on one store over a pipe: a tag 4 frame is a request, the reply its answer.  With `prof` the engine's stderr is
    read by a thread (its counters and phase timers, `RR_FLAT_PROF`), so the pipe never fills."""

    def __init__(self, where: str, prof: bool, log, exe: Path) -> None:
        self.log, self.counters, self.prof, self.n = log, {}, [], 0
        self.p = subprocess.Popen([str(exe), where, "0"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE if prof else None,
                                  env={**os.environ, **({"RR_FLAT_PROF": "1"} if prof else {})})
        if prof:
            threading.Thread(target=self._drain, daemon=True).start()

    def _drain(self) -> None:
        for raw in self.p.stderr:
            words = raw.decode(errors="replace").split()
            if words[:1] == ["RULES_FLAT_COUNTERS"]:
                self.counters = dict(kv.split("=") for kv in words[1:])
            elif words[:1] == ["RULES_FLAT_PROF"]:
                self.prof, self.n = [int(x) for x in words[1:]], self.n + 1

    def frame(self, data: bytes, timers: bool = True) -> bytes:
        """The answer to `data`; with `timers` (a decided batch, not a refusal) also waits for the engine's timer line."""
        before = self.n
        dog = threading.Timer(900, lambda: (self.log("FLAT STUCK: no answer in 900 s; killing the engine"), self.p.kill()))
        dog.start()
        try:
            self.p.stdin.write(struct.pack(">I", len(data) + 1) + b"\x04" + data)
            self.p.stdin.flush()
            out = self.p.stdout.read(struct.unpack(">I", self.p.stdout.read(4))[0])
        finally:
            dog.cancel()
        if timers and self.p.stderr:
            end = time.time() + 10
            while self.n == before and time.time() < end:
                time.sleep(0.001)
        return out

    def ping(self) -> None:
        """A frame that is not one: refused at once.  The engine has started and reserved its arena when it answers."""
        self.frame(b"ping", timers=False)

    def close(self) -> None:
        self.p.stdin.close()
        self.p.wait(timeout=60)


def run_flat(sizes=(3000, 30000, 300000, 3000000), batch=2000, trials=3, work_dir=None, log=print, prof=False, warm=False, both=False, resume=False, span=None,
             tail=20, tail_batch=100) -> dict:
    """FLAT bench (design flat-r1 section 6.3): the history index in `gate_engine` over a pipe, one binary frame per batch.  The history
    is built through the chain from the streaming synthetic corpus (`tests/gate_corpus.py`: the claim mix, repeats reaching back into
    all of the history), each line a signed one-line payment request; the next `batch` corpus lines are a committed anchor batch
    (unmeasured), and a fresh engine process (cold page cache, prefetch on) runs the `batch` lines after it.  Every line the run feeds
    is history from then on.  After every committed batch `resume.json` in the work dir keeps the head, batch count and position, so
    `resume=True` (with the same work dir) goes on from there.  Per trial: with `prof` the engine's counters (work and pages), the
    frame's wall time per line, the engine's peak working set.  Reported per size: counters, pages per line, us per line (mean, median,
    min, max), peak RSS, disk bytes, build time.  The last `tail` batches before each size are `tail_batch` lines each, on the resident
    engine (steady state, no timers unless `prof`): their us per line and ms per batch are reported, and so are the seconds a fresh
    engine takes to load the store at that size, in place and on a fresh copy of the directory (`load_in_place_s`, `load_copy_s`)."""
    from tests import test_flat_worker as fw

    release = gate.sha3_512(fw.ENGINE.read_bytes())
    evidence = tuple(sorted((fx.D[2], fx.D[5])))

    def request(i: int, text: str) -> bytes:
        ident, _, member, payee, rendering, date, code, units, cents = text.split()
        key = int(member).to_bytes(gate.MEMBER_KEY, "big")
        line = gate.encode_line("FFS_CLAIM", f"L{ident.split(':')[0]}", key, f"P{payee}", f"R{rendering}", int(date), f"C{code}", int(units), int(cents))
        return gate.encode_decide_request(gate.DecideRequest(fx.TENANT, fx.PROGRAM, "FFS_CLAIM", f"cmd-{i}", f"pay-{i}", key, f"P{payee}",
                                                             int(cents), fx.PERIOD, (line,), evidence))

    def bodies(n: int) -> list[bytes]:
        nonlocal built
        out = [request(i, text) for i, text in enumerate(gate_corpus.lines(SEED, built, n, span), built)]
        built += n
        return out

    def ask(eng: Engine, reqs: list[bytes]) -> tuple[bytes, bytes]:
        """The next batch's frame (opening at the signed head) and the engine's answer."""
        data = decider.request_frame(g.HEAD, 0, batches + 1, g.ASOF, head, g.PIN, fw.floors(head), g.KEYS, g.GRANT, release, (), reqs)
        return data, eng.frame(data)

    def head_of(data: bytes, out: bytes) -> bytes:
        why, _, new, *_ = fw.read(data, out)
        assert why is None, why
        return new

    d = Path(work_dir or tempfile.mkdtemp(prefix="flatbench")) / "idx"
    ck = d.parent / "resume.json"
    asked, span = span, span or max(sizes)  # the corpus dates spread over span lines; a resume keeps the checkpoint's span and seed
    dirs, result, head, batches, built = str(d).replace("\\", "/"), [], b"", 0, 0
    if resume:
        c = json.loads(ck.read_text("utf-8"))
        if c["seed"] != SEED or asked not in (None, c["span"]):
            raise ValueError(f"resume: checkpoint seed {c['seed']} span {c['span']} differ from seed {SEED} span {span}; the repeats would not repeat")
        head, batches, built, result, span = bytes.fromhex(c["head"]), c["batches"], c["built"], c["result"], c["span"]
    else:
        d.parent.mkdir(parents=True, exist_ok=True)
    start = lambda where=dirs: Engine(where, prof, log, fw.ENGINE)  # noqa: E731
    eng = start()
    if not resume:
        head, data = chain.genesis(0, g.ASOF, g.PIN), None
        data, out = ask(eng, [])
        head, batches = head_of(data, out), 1  # init and its commit

    def save() -> None:
        ck.with_suffix(".tmp").write_text(json.dumps({"head": head.hex(), "batches": batches, "built": built, "result": result, "seed": SEED, "span": span}), "utf-8")
        os.replace(ck.with_suffix(".tmp"), ck)

    for r, h in enumerate(sizes):
        if r < len(result):
            continue  # measured before the stop
        t0, b0, tail_s = time.time(), built, []
        while built < h:
            left, n_tail = h - built, tail * tail_batch
            n = tail_batch if left <= n_tail else min(batch, left - n_tail)
            reqs = bodies(n)
            t1 = time.perf_counter()
            data, out = ask(eng, reqs)
            if left <= n_tail:
                tail_s.append((time.perf_counter() - t1, n))
            head, batches = head_of(data, out), batches + 1
            save()
        build_s, build_rss = time.time() - t0, peak_rss(eng.p)
        log(f"FLAT built {built - b0} rows to {built} in {build_s:.0f}s (not measured)")
        eng.close()  # the engine holds the directory's lock: load with fresh engines, then start the next one

        def load_s(where: str, keep: bool = False) -> float:  # keep: the batch is committed to the store the run goes on with
            q = start(where)
            q.ping()  # started, arena reserved
            t1 = time.perf_counter()
            data, out = ask(q, [])
            took = time.perf_counter() - t1
            new = head_of(data, out)
            if keep:
                nonlocal head, batches
                head, batches = new, batches + 1
                save()
            q.close()
            return took

        copy = d.parent / "copy"
        shutil.rmtree(copy, ignore_errors=True)
        shutil.copytree(d, copy, ignore=shutil.ignore_patterns("lock"))
        load_copy_s = load_s(str(copy).replace("\\", "/"))
        shutil.rmtree(copy, ignore_errors=True)
        load_in_place_s = load_s(dirs, True)
        log(f"FLAT load at {built}: in place {load_in_place_s:.3f}s, fresh copy {load_copy_s:.3f}s")
        eng = start()
        trial_rows = []
        for t in range(trials):
            data, out = ask(eng, bodies(batch))
            head, batches = head_of(data, out), batches + 1
            save()  # every committed batch, timed or not, so the index never runs ahead of the checkpoint
            if not warm:  # a fresh engine (cold page cache); warm: the same engine keeps its cache across batches
                eng.close()
                eng = start()
                eng.ping()  # started, arena reserved; its reads below are cold
            reqs = bodies(batch)
            t1 = time.perf_counter()
            data, out = ask(eng, reqs)
            wall = time.perf_counter() - t1
            trial_rows.append({"work": int(eng.counters.get("work", 0)), "pages": int(eng.counters.get("pages", 0)),
                               "hashed": int(eng.counters.get("hashed", 0)), "syncs": int(eng.counters.get("syncs", 0)), "us_per_line": wall / batch * 1e6,
                               "peak_rss": peak_rss(eng.p), **({"prof_us": list(eng.prof)} if prof else {})})
            head, batches = head_of(data, out), batches + 1
            save()
            if both:  # the engine that just ran the batch above, its cache warm: one more batch on the same members
                reqs = bodies(batch)
                t1 = time.perf_counter()
                data, out = ask(eng, reqs)
                wall = time.perf_counter() - t1
                trial_rows[-1].update({"warm_work": int(eng.counters.get("work", 0)), "warm_pages": int(eng.counters.get("pages", 0)),
                                       "warm_us_per_line": wall / batch * 1e6, "warm_peak_rss": peak_rss(eng.p)})
                head, batches = head_of(data, out), batches + 1
                save()
        pages, us = sorted(x["pages"] for x in trial_rows), sorted(x["us_per_line"] for x in trial_rows)
        disk = sum(f.stat().st_size for f in d.rglob("*") if f.is_file())
        result.append({"history": h, "lines": batch, "trials": trials, "work": sorted({x["work"] for x in trial_rows}),
                       "pages_per_line_mean": sum(pages) / trials / batch,
                       "hashed_per_line_mean": sum(x["hashed"] for x in trial_rows) / trials / batch, "syncs_per_batch": sorted({x["syncs"] for x in trial_rows}), "pages_per_line_p99": pages[min(trials - 1, int(trials * 0.99))] / batch,
                       "us_per_line_mean": sum(us) / trials, "us_per_line_median": us[trials // 2], "us_per_line_min": us[0], "us_per_line_max": us[-1],
                       "load_in_place_s": load_in_place_s, "load_copy_s": load_copy_s,
                       "tail_us_per_line_mean": sum(t for t, _ in tail_s) / max(sum(n for _, n in tail_s), 1) * 1e6,
                       "tail_ms_per_batch_mean": sum(t for t, _ in tail_s) / max(len(tail_s), 1) * 1e3, "tail_batches": len(tail_s),
                       "disk_bytes": disk, "history_built": built, "build_s": build_s, "build_us_per_line": build_s / max(built - b0, 1) * 1e6, "build_peak_rss": build_rss,
                       "peak_rss_max": max(x["peak_rss"] for x in trial_rows), "peak_rss_series": [x["peak_rss"] for x in trial_rows],
                       **({"warm_work": sorted({x["warm_work"] for x in trial_rows}), "warm_pages_per_line_mean": sum(x["warm_pages"] for x in trial_rows) / trials / batch,
                           "warm_us_per_line_mean": sum(x["warm_us_per_line"] for x in trial_rows) / trials, "warm_peak_rss_max": max(x["warm_peak_rss"] for x in trial_rows)} if both else {}),
                       **({"prof_us_mean": [round(sum(x["prof_us"][i] for x in trial_rows) / trials) for i in range(len(trial_rows[0]["prof_us"]))]} if prof else {})})
        log("FLAT", result[-1])
        save()
    eng.close()
    return {"flat": result}


def child_counters(proc) -> dict:
    """CPU seconds (user + kernel) and I/O counts of a running child (Windows): counts do not swing with the clock."""
    h, t = ctypes.c_void_p(int(proc._handle)), [ctypes.c_ulonglong() for _ in range(4)]
    ctypes.windll.kernel32.GetProcessTimes(h, *(ctypes.byref(x) for x in t))
    io = (ctypes.c_ulonglong * 6)()
    ctypes.windll.kernel32.GetProcessIoCounters(h, io)
    return {"cpu_s": (t[2].value + t[3].value) / 1e7, "read_ops": io[0], "write_ops": io[1], "read_b": io[3], "write_b": io[4]}


def child_mem(proc) -> dict:
    """Working set, its peak and private (committed) bytes of a child now."""
    class Counters(ctypes.Structure):
        _fields_ = [("cb", ctypes.c_ulong), ("faults", ctypes.c_ulong), ("peak", ctypes.c_size_t), ("ws", ctypes.c_size_t)] + [(n, ctypes.c_size_t) for n in "abcde"] + [("peak_private", ctypes.c_size_t), ("private", ctypes.c_size_t)]  # ..., PagefileUsage, PeakPagefileUsage, PrivateUsage
    c = Counters()
    c.cb = ctypes.sizeof(c)
    ctypes.windll.psapi.GetProcessMemoryInfo(ctypes.c_void_p(int(proc._handle)), ctypes.byref(c), c.cb)
    return {"ws": c.ws, "peak_ws": c.peak, "private": c.private, "peak_private": c.peak_private}


def _delta(a: dict, b: dict) -> dict:
    return {k: b[k] - a[k] for k in a}


MEM_WALL = 900_000_000  # the bench stops growing the history below this much free memory (three samples in a row)


def run_e3(sizes, batch=2000, trials=3, work_dir=None, log=print, hot=False, spec=None) -> dict:
    """History gate of engine v3 (the 2026-10-30 history-cut design, bar: us/line at 3M at most 1.05x that at 0.3M).  One store, one
    `gate_verify3` that follows its log from batch 1 (never restarted), the mixed corpus of `tests/engine3_compare.py`, `batch` lines per
    frame.  The history grows through `sizes` in turn; at each size `trials` batches run back to back on the resident engine, each with
    its host stages (corpus lines and request encoding, frame, the round trip to the engine, answer parse), the engine's CPU and I/O counts,
    and the verifier's stage clocks, CPU and I/O counts for the same batch (the verifier prints `PROGRESS` after every pump with
    RR_V3_PROGRESS).  Then peak RSS of both, disk bytes, and the load time: a fresh engine opens the store on an empty batch (the same
    batch on the warm engine is subtracted).  The history build between sizes is unmeasured except for an engine us/line per batch.
    `spec` (RR_E3_SPEC, the engine's spec-check rate: 1 = every batch, 64 = the product's 1 in 64) is set before `engine3_compare` is
    imported, which would otherwise default it to 1; the setting used is in the result."""
    if spec is not None:
        os.environ["RR_E3_SPEC"] = str(spec)
    from tests import engine3_compare as ec
    from tests import test_flat_worker as fw

    root = Path(work_dir or tempfile.mkdtemp(prefix="e3hist", dir=os.environ.get("E3_SCRATCH")))
    d, vd, exe = root / "store", root / "verify", fw.BIN / "gate_verify3.exe"
    d.mkdir(parents=True)
    prog = []

    class E3(fw.Engine):  # fw.Engine with its stderr kept: RR_E3_PROF prints the load stages there
        def __init__(self, where=None) -> None:
            self.release, self.stage = ec.RELEASE, ""
            self.p = subprocess.Popen([str(ec.NEW), str(where or d).replace("\\", "/"), "0"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      env={**os.environ, "RR_E3_PROF": "1"})
            threading.Thread(target=self._drain, daemon=True).start()

        def _drain(self) -> None:
            last = []
            for raw in self.p.stderr:  # the last two lines: the replay's, then the load's
                if line := raw.decode(errors="replace").strip():
                    if os.environ.get("RR_E3_STDERR"):
                        with open(os.environ["RR_E3_STDERR"], "a") as f:
                            f.write(line + chr(10))
                    last = (last + [line])[-2:]
                    self.stage = "; ".join(last)

    # the rows-file store of gate_hist3 is followed by the checker on its own history
    mode, checker = "rows-tail", "gate_verify3 checker on its own history"
    verifier = subprocess.Popen([str(exe), str(d).replace("\\", "/"), "0", mode, str(vd).replace("\\", "/"), "120000"], stdout=subprocess.PIPE,
                                text=True, env={**os.environ, "RR_V3_PROGRESS": "1"})
    final, cond = [], threading.Condition()

    def follow() -> None:
        for row in verifier.stdout:
            words = row.replace("[", " ").replace("]", " ").replace(",", " ").split()
            with cond:
                if words[:1] == ["PROGRESS"]:
                    prog.append((int(words[1]), int(words[2]), [int(x) for x in words[3:]]))
                else:
                    final.append(row.strip())
                cond.notify_all()
    reader = threading.Thread(target=follow, daemon=True)
    reader.start()

    def verified(n: int) -> tuple:
        """The verifier's (batches, lines, stage ns) once it has verified batch `n`."""
        with cond:
            if not cond.wait_for(lambda: (prog and prog[-1][0] >= n) or verifier.poll() is not None, 1800):
                raise RuntimeError(f"STOP verifier made no progress to batch {n}")
            if not prog or prog[-1][0] < n:
                raise RuntimeError(f"STOP verifier ended before batch {n}: {final}")
            return prog[-1]

    eng, head, n, built, span = E3(), fw.GENESIS, 0, 0, max(sizes)
    eng.send(b"ping")  # refused at once: the process is up before the clock runs

    def ask(bodies, e=None, strict=True):
        nonlocal head, n
        e, n = e or eng, n + 1
        t0 = time.perf_counter()
        data = decider.request_frame(g.HEAD, 0, n, g.ASOF, head, g.PIN, fw.floors(head), g.KEYS, g.GRANT, ec.RELEASE, (), bodies)
        t1 = time.perf_counter()
        out = e.send(data)
        t2 = time.perf_counter()
        why, recs, new, *_ = fw.read(data, out)
        if why is not None and not strict:
            return {"refused": str(why), "engine_s": t2 - t1}
        assert why is None, f"batch {n}: {why} (engine exit {e.p.poll()})"
        head = new
        return {"frame_s": t1 - t0, "engine_s": t2 - t1, "parse_s": time.perf_counter() - t2, "recs": len(recs)}

    def fresh(count):
        nonlocal built
        t0 = time.perf_counter()
        out = [ec.line_body(i, t, hot) for i, t in enumerate(gate_corpus.lines(SEED, built, count, span), built)]
        built += count
        return out, time.perf_counter() - t0

    def disk(p: Path) -> int:
        return sum(f.stat().st_size for f in p.rglob("*") if f.is_file())

    ask([])  # the init batch
    result, curve = [], []
    wall, low = None, 0
    for target in sizes:
        while built < target:
            if free_bytes() < MEM_WALL:  # the guard's floor is below this; stop here and measure what is stored
                low += 1
                if low >= 3:
                    wall = {"history_lines": built, "free_bytes": free_bytes()}
                    break
            else:
                low = 0
            bodies, _ = fresh(min(batch, target - built))
            c0, t = child_counters(eng.p), ask(bodies)
            c = _delta(c0, child_counters(eng.p))
            curve.append({"history": built - len(bodies), "engine_us": t["engine_s"] / len(bodies) * 1e6, "engine_cpu_us": c["cpu_s"] / len(bodies) * 1e6,
                          "read_b": c["read_b"] / len(bodies), "write_b": c["write_b"] / len(bodies), "ws": child_mem(eng.p)["ws"],
                          "private": child_mem(eng.p)["private"]})
            if len(curve) % 50 == 0:
                log("E3HIST build", curve[-1], "engine", child_mem(eng.p), "verifier", child_mem(verifier), "free", free_bytes(), "second process:", checker, flush=True)
        verified(n)  # the verifier has caught up: the trials below are its alone
        rows = []
        for _ in range(trials):
            h0 = time.process_time()
            bodies, gen_s = fresh(batch)
            e0, v0, (_, vlines0, st0) = child_counters(eng.p), child_counters(verifier), verified(n)
            t, w0 = ask(bodies), time.perf_counter()
            e1 = child_counters(eng.p)
            host_cpu_s = time.process_time() - h0  # this process only: corpus lines, request frame, pipe, answer parse
            _, vlines1, st1 = verified(n)
            v_wait, v1 = time.perf_counter() - w0, child_counters(verifier)
            per = lambda x: x / batch * 1e6
            rows.append({"history": built - batch, "harness_us": per(gen_s), "frame_us": per(t["frame_s"]), "engine_us": per(t["engine_s"]), "parse_us": per(t["parse_s"]), "host_cpu_us": per(host_cpu_s),
                         "engine": {k: v / batch for k, v in _delta(e0, e1).items()}, "verifier": {k: v / batch for k, v in _delta(v0, v1).items()},
                         "verifier_wait_us": per(v_wait), "verifier_stage_us": [per(b / 1e9) for b in (x - y for x, y in zip(st1, st0))]})
            assert vlines1 - vlines0 == batch, f"verifier saw {vlines1 - vlines0} lines for a batch of {batch}"
            log("E3HIST trial", rows[-1], flush=True)
        mem_e, mem_v = child_mem(eng.p), child_mem(verifier)
        store_bytes, verify_bytes = disk(d), disk(vd)
        result.append({"stored_lines": built, "second_process": checker, "rows": rows, "engine_mem": mem_e, "verifier_mem": mem_v, "disk_bytes": store_bytes, "verifier_disk_bytes": verify_bytes})
        log("E3HIST size", {k: v for k, v in result[-1].items() if k != "rows"}, flush=True)
        # load: a fresh engine on a copy of the store (the resident one goes on); its first request opens the store, and its time less the
        # same empty batch on the open store is the load
        copy, saved = root / "copy", (head, n)
        shutil.copytree(d, copy, ignore=shutil.ignore_patterns("lock"))
        loader = E3(copy)
        loader.send(b"ping")
        cold = ask([], loader, strict=False)
        again = ask([], loader, strict=False) if "refused" not in cold else cold
        result[-1].update({"load_refused": cold.get("refused"), "load_stages": loader.stage, "first_empty_s": cold["engine_s"], "warm_empty_s": again["engine_s"],
                           "load_s": cold["engine_s"] - again["engine_s"], "load_mem": child_mem(loader.p)})
        loader.close()
        shutil.rmtree(copy, ignore_errors=True)
        head, n = saved
        log("E3HIST load", {k: result[-1][k] for k in ("stored_lines", "load_refused", "load_s", "first_empty_s", "warm_empty_s", "load_stages", "load_mem")}, flush=True)
        if wall:
            break
    eng.close()
    verifier.wait(timeout=600)  # idle for 120 s, then it checks the engine's chunk files and prints VERIFIED
    reader.join(60)
    ec.drop_store(root, not work_dir and verifier.returncode == 0 and any("VERIFIED" in x for x in final))  # only a dir made here, and only on a pass
    return {"seed": SEED, "batch": batch, "spec": os.environ.get("RR_E3_SPEC"), "sizes": list(sizes), "second_process": checker, "memory_wall": wall, "sizes_result": result, "build_curve": curve, "verifier_exit": verifier.returncode, "verifier_final": final}


def size(text: str) -> int:
    """A history size: 300000, 300k, 3M or 30M."""
    return int(text[:-1]) * {"k": 1000, "M": 1_000_000}[text[-1]] if text[-1] in "kM" else int(text)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sizes", default="10000,100000", help="history sizes to reach, comma separated (1000000 only on request)")
    ap.add_argument("--batch", type=int, default=1000)
    ap.add_argument("--out")
    ap.add_argument("--flat", action="store_true", help="the history index bench: --sizes (default 3000,30000,300000,3000000), --batch 2000")
    ap.add_argument("--work-dir")
    ap.add_argument("--trials", type=int, default=3)
    ap.add_argument("--resume", action="store_true", help="flat bench: go on from resume.json in --work-dir (same --sizes)")
    ap.add_argument("--both", action="store_true", help="flat bench: per trial, also one batch on the worker that kept its cache from the anchor batch (warm_* fields)")
    ap.add_argument("--warm", action="store_true", help="flat bench: keep one worker (and its page cache) for the whole run")
    ap.add_argument("--hot", action="store_true", help="with --e3: the hot corpus (a few members, providers and days, long cores) in place of the mixed one")
    ap.add_argument("--spec", default="64", help="with --e3: RR_E3_SPEC for the engine and checker (default 64, the product setting; 1 checks every batch)")
    ap.add_argument("--e3", action="store_true", help="engine v3 history gate: --sizes (default 300k,1M,3M), --batch 2000, --trials 3; engine, verifier and host stages")
    ap.add_argument("--prof", action="store_true", help="flat bench: phase timers of the worker (RR_FLAT_PROF), us per batch, slots 3 decide, 9 fetch, 10 commit, 12 install, 18 answer assembly, 19 frame decode, 20 answer render")
    a = ap.parse_args()
    if a.e3:
        result = run_e3(tuple(size(x) for x in (a.sizes if a.sizes != "10000,100000" else "300k,1M,3M").split(",")), 2000 if a.batch == 1000 else a.batch, a.trials, a.work_dir, hot=a.hot, spec=a.spec)
        if a.out:
            Path(a.out).parent.mkdir(parents=True, exist_ok=True)
            Path(a.out).write_text(json.dumps(result, indent=1), "utf-8")
        return
    if a.flat:
        result = run_flat(tuple(size(x) for x in (a.sizes if a.sizes != "10000,100000" else "3000,30000,300000,3000000").split(",")), 2000 if a.batch == 1000 else a.batch, a.trials, a.work_dir, prof=a.prof, warm=a.warm, both=a.both, resume=a.resume)
        if a.out:
            Path(a.out).parent.mkdir(parents=True, exist_ok=True)
            Path(a.out).write_text(json.dumps(result, indent=1), "utf-8")
        return
    sizes = tuple(int(s) for s in a.sizes.split(","))
    result = run_bench(max(sizes), a.batch, sizes, free_bytes)
    result.pop("corpus")
    if a.out:
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(json.dumps(result, indent=1), "utf-8")
    print("BENCH", {k: v for k, v in result.items() if k != "batches"})
    for r in result["batches"]:
        print("BENCH_BATCH", r["history_before"], r["worker_commit_bytes"], r["frame_est_bytes"], r["us_per_line"])
    if result["wall"]:
        raise SystemExit(f"BENCH_WALL {result['wall']['reason']} at {result['wall']['history_lines']} lines")
    if result["relaunches"]:
        raise SystemExit(f"BENCH_RELAUNCH {result['relaunches']} worker deaths: batches were decided on a relaunched worker")


if __name__ == "__main__":
    main()
