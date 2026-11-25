"""One command that measures the four founder bars of the gate (test-only, synthetic, non-PHI); run it only through the guard.

    python tests/_gate_bars.py --out-dir DIR [--sizes 300k,3M] [--trials 5] [--spec 64] [--shards 4] [--tp-lines 300000]

Bars: (S) engine + checker at most 40 us process CPU per line; (T) 200k lines/s over 4 shards; (H) the CPU per line of a 3M history at most
1.05x that of 0.3M (engine, checker and their sum); (M) each process at most 18 B/line + 256 MB private memory, at 3M.  For the mixed and
the hot corpus it runs `tests.gate_bench --e3` (gate_hist3 + gate_verify3, RR_E3_SPEC=--spec, default 64 = the product) with the batches
of each size as the trials; then replays saved frames into the shards (the Python host only writes frames to pipes and reads answers).
A bar whose measurement was not run, or failed, is MISS with the reason; nothing is extrapolated.  Writes DIR/gate-bars.json and .md."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import right_rail_gate_decide as decider  # noqa: E402
from tests import _gate_shards as g  # noqa: E402
from tests import gate_bench as gb  # noqa: E402
from tests import gate_corpus  # noqa: E402
from tests import test_flat_worker as fw  # noqa: E402

LIMITS = {"S_us": 40.0, "T_lines_s": 200_000, "H_ratio": 1.05, "M_fixed_b": 256_000_000, "M_per_line_b": 18}
MB = 1e6


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Load:
    """Whole-machine CPU busy share over a window (GetSystemTimes), our own processes included."""

    def __init__(self) -> None:
        self.t0 = self._now()

    @staticmethod
    def _now() -> tuple[int, int]:
        idle, kern, user = (ctypes.c_ulonglong() for _ in range(3))
        ctypes.windll.kernel32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kern), ctypes.byref(user))
        return idle.value, kern.value + user.value  # kernel time includes idle

    def busy_pct(self) -> float:
        i, t = self._now()
        return round(100 * (1 - (i - self.t0[0]) / max(t - self.t0[1], 1)), 1)


def quiet_probe(seconds: float = 3.0) -> float:
    w = Load()
    time.sleep(seconds)
    return w.busy_pct()


def run_e3_bench(corpus: str, a, out: Path) -> dict:
    """gate_bench --e3 in a child; its JSON, exit code and the machine busy share while it ran."""
    cmd = [sys.executable, "-m", "tests.gate_bench", "--e3", "--sizes", a.sizes, "--trials", str(a.trials), "--spec", a.spec, "--out", str(out)]
    if corpus == "hot":
        cmd.append("--hot")
    load, t0 = Load(), time.time()
    with open(out.with_suffix(".stdout.txt"), "w", encoding="utf-8") as log:
        code = subprocess.run(cmd, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, env=os.environ.copy()).returncode
    info = {"cmd": cmd, "exit": code, "seconds": round(time.time() - t0), "machine_busy_pct": load.busy_pct(), "json": str(out)}
    info["result"] = json.loads(out.read_text("utf-8")) if code == 0 and out.exists() else None
    return info


# ---- throughput: saved frames replayed into shards ----

def send(proc, data: bytes) -> bytes:
    proc.stdin.write(struct.pack(">I", len(data) + 1) + b"\x04" + data)
    proc.stdin.flush()
    n = proc.stdout.read(4)
    if len(n) < 4:
        raise RuntimeError("the engine closed its pipe")
    return proc.stdout.read(struct.unpack(">I", n)[0])


def verdict_bytes(out: bytes) -> tuple[bytes, bytes]:
    """(the answer's per-line records, its new head): the records do not depend on the store's random key, the head does."""
    if len(out) < 87 or out[6] != 0:
        raise RuntimeError(f"the engine refused the frame (answer {out[:24].hex()})")
    end = 87 + 20 * int.from_bytes(out[19:23], "little")
    return out[87:end], out[end:end + 64]


def with_head(data: bytes, head: bytes) -> bytes:
    """The saved frame with this store's head as the previous head (body offset 8), and the frame digest over the new body (FRAME_V1 section 2).
    A store's key is random, so a saved frame cannot carry the head: the sender puts it in between two answers (the time is reported)."""
    body = data[82:90] + head + data[154:]
    return data[:18] + hashlib.sha3_512(b"RR/GATE/FRAME2/v1\x00" + body).digest() + body


def spawn_engine(store: Path) -> subprocess.Popen:
    p = subprocess.Popen([str(fw.BIN / "gate_hist3.exe"), str(store).replace("\\", "/"), "0"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, env=os.environ.copy())
    send(p, b"ping")  # refused at once: the process is up before the clock runs
    return p


def build_frames(path: Path, corpus: str, shard: int, lines: int, batch: int, tag: str) -> dict:
    """Run one fresh engine over `lines` corpus lines (seed + shard) and save each request frame with the SHA3-256 of its answer.  Reused when
    the saved meta matches (engine exe hash, corpus, size)."""
    from tests import engine3_compare as ec
    meta_path = path.with_suffix(".meta.json")
    want = {"tag": tag, "corpus": corpus, "shard": shard, "lines": lines, "batch": batch, "seed": gb.SEED}
    if meta_path.exists() and json.loads(meta_path.read_text("utf-8")).get("want") == want and path.exists():
        return json.loads(meta_path.read_text("utf-8"))
    store = path.with_suffix(".store")
    store.mkdir(parents=True)
    eng, head, frames, answers, counts = spawn_engine(store), fw.GENESIS, [], [], []
    seed, built = gb.SEED + shard, 0
    plan = [0] + [min(batch, lines - at) for at in range(0, lines, batch)]  # the init batch, then the corpus
    try:
        for n in plan:
            bodies = [ec.line_body(i, t, corpus == "hot") for i, t in enumerate(gate_corpus.lines(seed, built, n, lines), built)]
            data = decider.request_frame(g.HEAD, 0, len(frames) + 1, g.ASOF, head, g.PIN, fw.floors(head), g.KEYS, g.GRANT, ec.RELEASE, (), bodies)
            out = send(eng, data)
            why, _, head, *_ = fw.read(data, out)
            assert why is None, f"build frame {len(frames) + 1}: {why}"
            assert head == verdict_bytes(out)[1]
            frames.append(data)
            answers.append(hashlib.sha3_256(verdict_bytes(out)[0]).digest())
            counts.append(n)
            built += n
    finally:
        eng.stdin.close()
        eng.wait(timeout=120)
    with open(path, "wb") as f:
        for d in frames:
            f.write(struct.pack(">I", len(d)) + d)
    meta = {"want": want, "frames": len(frames), "lines": sum(counts), "counts": counts, "answers": [x.hex() for x in answers], "bytes": path.stat().st_size}
    meta_path.write_text(json.dumps(meta), "utf-8")
    shutil.rmtree(store, ignore_errors=True)
    return meta


def load_frames(path: Path) -> list[bytes]:
    out, raw = [], path.read_bytes()
    i = 0
    while i < len(raw):
        n = struct.unpack(">I", raw[i:i + 4])[0]
        out.append(raw[i + 4:i + 4 + n])
        i += 4 + n
    return out


def replay(root: Path, shards: list[tuple[list[bytes], dict]], spec: str) -> dict:
    """Fresh stores; per shard one gate_hist3 and one gate_verify3 following it.  A sender thread per shard writes its saved frames and
    reads the answers; the clock starts when every sender is ready and stops at the last answer (engines) and at the checkers' last PROGRESS."""
    root.mkdir(parents=True)
    n = len(shards)
    engines = [spawn_engine(root / f"s{k}") for k in range(n)]
    verifiers = [subprocess.Popen([str(fw.BIN / "gate_verify3.exe"), str(root / f"s{k}").replace("\\", "/"), "0", "rows-tail",
                                   str(root / f"v{k}").replace("\\", "/"), "30000"], stdout=subprocess.PIPE, text=True,
                                  env={**os.environ, "RR_V3_PROGRESS": "1"}) for k in range(n)]
    seen = [[] for _ in range(n)]  # (perf_counter, batches) per checker PROGRESS
    final = [[] for _ in range(n)]

    def follow(k: int) -> None:
        for row in verifiers[k].stdout:
            words = row.replace("[", " ").replace("]", " ").replace(",", " ").split()
            if words[:1] == ["PROGRESS"]:
                seen[k].append((time.perf_counter(), int(words[1])))
            else:
                final[k].append(row.strip())
    readers = [threading.Thread(target=follow, args=(k,), daemon=True) for k in range(n)]
    for r in readers:
        r.start()
    ready, answers, stamps, errors = threading.Barrier(n + 1), [[] for _ in range(n)], [[] for _ in range(n)], []
    patch_s = [0.0] * n

    def sender(k: int) -> None:
        frames = shards[k][0]
        ready.wait()
        try:
            for i, data in enumerate(frames):
                if i:
                    t = time.perf_counter()
                    data = with_head(data, verdict_bytes(answers[k][-1])[1])
                    patch_s[k] += time.perf_counter() - t
                answers[k].append(send(engines[k], data))
                stamps[k].append(time.perf_counter())
        except Exception as e:  # noqa: BLE001 - recorded, the run is then a failed measurement
            errors.append(f"shard {k}: {e!r}")
    threads = [threading.Thread(target=sender, args=(k,)) for k in range(n)]
    for t in threads:
        t.start()
    load, h0 = Load(), time.process_time()
    ready.wait()
    t0 = time.perf_counter()
    for t in threads:
        t.join()
    host_cpu = time.process_time() - h0
    total = sum(sum(m["counts"]) for _, m in shards)
    end_eng = max((s[-1] for s in stamps if s), default=t0)
    wanted = [len(f) for f, _ in shards]
    deadline, progress = time.time() + 120, -1
    while time.time() < deadline and not errors and not all(seen[k] and seen[k][-1][1] >= wanted[k] for k in range(n)):
        if (now := sum(s[-1][1] for s in seen if s)) != progress:
            progress, deadline = now, time.time() + 120  # a checker that makes no progress for 120 s has stopped
        time.sleep(0.01)
    done = all(seen[k] and seen[k][-1][1] >= wanted[k] for k in range(n))
    end_chk = max((next(t for t, b in seen[k] if b >= wanted[k]) for k in range(n)), default=t0) if done else None
    busy = load.busy_pct()
    cpu = {"engine_cpu_s": sum(gb.child_counters(p)["cpu_s"] for p in engines), "checker_cpu_s": sum(gb.child_counters(p)["cpu_s"] for p in verifiers)}
    late = 0.0  # lines per second in the second half of each shard's stream (history at least half built), summed over shards
    for k in range(n):
        if len(stamps[k]) == wanted[k] and wanted[k] > 2:
            mid = wanted[k] // 2
            late += sum(shards[k][1]["counts"][mid:]) / max(stamps[k][-1] - stamps[k][mid - 1], 1e-9)
    mismatches = sum(1 for k in range(n) for i, out in enumerate(answers[k]) if hashlib.sha3_256(verdict_bytes(out)[0]).hexdigest() != shards[k][1]["answers"][i])
    for p in engines:
        p.stdin.close()
    for p in engines:
        p.wait(timeout=120)
    for p in verifiers:
        try:
            p.wait(timeout=120)  # idles 30 s after the last frame, then checks the engine's files and prints VERIFIED
        except subprocess.TimeoutExpired:
            p.kill()
    for r in readers:
        r.join(10)
    ok = not errors and done
    return {"shards": n, "lines": total, "ok": ok, "errors": errors, "answer_mismatches": mismatches,
            "engine_wall_s": round(end_eng - t0, 3), "engine_lines_per_s": round(total / (end_eng - t0)) if ok else None,
            "pair_wall_s": round(end_chk - t0, 3) if end_chk else None, "pair_lines_per_s": round(total / (end_chk - t0)) if ok and end_chk else None,
            "late_engine_lines_per_s": round(late) if ok else None, "host_cpu_s": round(host_cpu, 2), "reframe_s_per_shard": [round(x, 3) for x in patch_s], "machine_busy_pct": busy,
            "cpu_us_per_line": {k: round(v / total * 1e6, 1) for k, v in cpu.items()}, "verified": [any("VERIFIED" in x for x in f) for f in final],
            "checker_exit": [p.returncode for p in verifiers]}


def throughput(corpus: str, a, out_dir: Path, tag: str) -> dict:
    frames_dir = Path(a.frames_dir) if a.frames_dir else out_dir / "frames"
    frames_dir.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    metas = [build_frames(frames_dir / f"{corpus}-{k}.frames", corpus, k, a.tp_lines, a.batch, tag) for k in range(a.shards)]
    built_s = round(time.time() - t0)
    shards = [(load_frames(frames_dir / f"{corpus}-{k}.frames"), metas[k]) for k in range(a.shards)]
    runs = {"one": [], "all": []}
    for _ in range(a.tp_trials):
        for name, use in (("one", shards[:1]), ("all", shards)):
            store = Path(os.environ.get("E3_SCRATCH", str(out_dir))) / f"tp-{corpus}-{name}-{int(time.time())}"
            r = replay(store, use, a.spec)
            if r["ok"] and not r["answer_mismatches"] and all(r["verified"]):
                shutil.rmtree(store, ignore_errors=True)  # a replay that passed leaves nothing; a failed one keeps its stores
            runs[name].append(r)
            print("TP", corpus, name, {k: v for k, v in r.items() if k not in ("verified",)}, flush=True)
    return {"corpus": corpus, "lines_per_shard": a.tp_lines, "frames_build_and_load_s": built_s, "frames_files": [str(frames_dir / f"{corpus}-{k}.frames") for k in range(a.shards)],
            "runs": runs}


# ---- the bars ----

def mean(v):
    return sum(v) / len(v)


def per_size(res: dict) -> dict:
    """Requested size -> per-line numbers from the trial batches at that size (the store then holds `history_lines`: the size plus the trials)."""
    out = {}
    for size, s in zip(res["sizes"], res["sizes_result"]):
        rows = s["rows"]
        e, c = [r["engine"]["cpu_s"] * 1e6 for r in rows], [r["verifier"]["cpu_s"] * 1e6 for r in rows]
        out[size] = {
            "history_lines": s["stored_lines"], "trials": len(rows), "engine_cpu_us": mean(e), "checker_cpu_us": mean(c), "sum_cpu_us": mean([x + y for x, y in zip(e, c)]),
            "sum_cpu_us_trials": [round(x + y, 1) for x, y in zip(e, c)], "engine_read_b": mean([r["engine"]["read_b"] for r in rows]),
            "checker_read_b": mean([r["verifier"]["read_b"] for r in rows]), "engine_wall_us": mean([r["engine_us"] for r in rows]),
            "engine_private_mb": s["engine_mem"]["private"] / MB, "engine_peak_private_mb": s["engine_mem"]["peak_private"] / MB,
            "checker_private_mb": s["verifier_mem"]["private"] / MB, "checker_peak_private_mb": s["verifier_mem"]["peak_private"] / MB,
            "mem_limit_mb": (LIMITS["M_fixed_b"] + LIMITS["M_per_line_b"] * s["stored_lines"]) / MB}
    return out


def verdicts(runs: dict, tp: dict, small: int, large: int) -> list[dict]:
    """The four bars: measured number, limit, PASS or MISS with the reason."""
    out = []

    def miss(why):
        return {"verdict": f"MISS (not run: {why})"}

    def need(c):
        r = runs[c]
        if r["result"] is None:
            return None, f"the {c} bench failed (exit {r['exit']})"
        return per_size(r["result"]), None
    stats = {c: need(c) for c in runs}
    # S: at the large size, both corpora
    vals, whys = {}, []
    for c, (ps, why) in stats.items():
        if why:
            whys.append(why)
        elif large not in ps:
            whys.append(f"{c} not measured at {large} lines")
        else:
            vals[c] = ps[large]["sum_cpu_us"]
    if whys:
        s = miss("; ".join(whys))
    else:
        s = {"verdict": "PASS" if all(v <= LIMITS["S_us"] for v in vals.values()) else "MISS"}
    out.append({"bar": "S speed: engine + checker CPU per line at 3M", "limit": f"<= {LIMITS['S_us']} us", "measured": {c: round(v, 1) for c, v in vals.items()}, **s})
    # T
    allr = [r for c in tp for r in tp[c]["runs"]["all"]] if tp else []
    if not tp:
        t = miss("throughput replay not run")
        got = {}
    else:
        got = {c: [r["pair_lines_per_s"] for r in tp[c]["runs"]["all"]] for c in tp}
        bad = [r for r in allr if not r["ok"] or r["answer_mismatches"]]
        if bad:
            t = {"verdict": f"MISS (failed: {bad[0]['errors'] or str(bad[0]['answer_mismatches']) + ' answers differ from the saved ones'})"}
        else:
            t = {"verdict": "PASS" if all(min(v) >= LIMITS["T_lines_s"] for v in got.values()) else "MISS"}
    out.append({"bar": "T throughput: 4 shards, engine + checker caught up, wall lines/s", "limit": f">= {LIMITS['T_lines_s']} lines/s", "measured": got, **t})
    # H
    ratios, whys = {}, []
    for c, (ps, why) in stats.items():
        if why:
            whys.append(why)
        elif small not in ps or large not in ps:
            whys.append(f"{c} needs both {small} and {large} lines")
        else:
            ratios[c] = {k: round(ps[large][f"{k}_cpu_us"] / ps[small][f"{k}_cpu_us"], 3) for k in ("engine", "checker", "sum")}
    h = miss("; ".join(whys)) if whys else {"verdict": "PASS" if all(x <= LIMITS["H_ratio"] for r in ratios.values() for x in r.values()) else "MISS"}
    out.append({"bar": "H history: CPU per line at 3M over 0.3M (engine, checker, sum each)", "limit": f"<= {LIMITS['H_ratio']}", "measured": ratios, **h})
    # M
    mem, whys = {}, []
    for c, (ps, why) in stats.items():
        if why:
            whys.append(why)
        elif large not in ps:
            whys.append(f"{c} not measured at {large} lines")
        else:
            p = ps[large]
            mem[c] = {"engine_peak_private_mb": round(p["engine_peak_private_mb"], 1), "checker_peak_private_mb": round(p["checker_peak_private_mb"], 1),
                      "limit_mb": round(p["mem_limit_mb"], 1)}
    m = miss("; ".join(whys)) if whys else {"verdict": "PASS" if all(max(v["engine_peak_private_mb"], v["checker_peak_private_mb"]) <= v["limit_mb"] for v in mem.values()) else "MISS"}
    out.append({"bar": "M memory: peak private per process at 3M", "limit": "<= 18 B/line + 256 MB (310 MB at 3M)", "measured": mem, **m})
    return out


def markdown(doc: dict) -> str:
    L = [f"# Gate bars, measured ({doc['when']})", "",
         f"Tree {doc['head']} ({doc['tree']}), RR_E3_SPEC={doc['spec']}, {doc['trials']} trials per size, batch {doc['batch']}. {doc['note']}",
         f"Machine before start: {doc['idle_busy_pct']}% busy over {os.cpu_count()} logical processors. Every number is measured; none is extrapolated.", ""]
    L += ["## Executables", "", "```", doc["pin_check"].strip(), "```", ""]
    for name, info in doc["exes"].items():
        L.append(f"- {name}: sha256 {info['sha256']}, built {info['built']}")
    L += ["", "## Per line, process CPU and reads (mean of the trial batches at each size)", "",
          "| corpus | history | engine CPU us | checker CPU us | sum us | engine read B | checker read B | engine priv / peak MB | checker priv / peak MB | limit MB | bench busy % |",
          "|---|---|---|---|---|---|---|---|---|---|---|"]
    for c, r in doc["runs"].items():
        if r["result"] is None:
            L.append(f"| {c} | FAILED (exit {r['exit']}) | | | | | | | | | |")
            continue
        for size, p in per_size(r["result"]).items():
            L.append(f"| {c} | {size:,} (+{p['history_lines'] - size:,}) | {p['engine_cpu_us']:.1f} | {p['checker_cpu_us']:.1f} | {p['sum_cpu_us']:.1f} | {p['engine_read_b']:.0f} | {p['checker_read_b']:.0f} | "
                     f"{p['engine_private_mb']:.0f} / {p['engine_peak_private_mb']:.0f} | {p['checker_private_mb']:.0f} / {p['checker_peak_private_mb']:.0f} | "
                     f"{p['mem_limit_mb']:.0f} | {r['machine_busy_pct']} |")
    L += ["", "## Throughput (saved frames replayed; host only writes frames and reads answers)", ""]
    if doc["throughput"]:
        L += ["| corpus | shards | trial | lines | engine lines/s | engine + checker lines/s | engine lines/s, second half | answers differing | host CPU s | machine busy % |", "|---|---|---|---|---|---|---|---|---|---|"]
        for c, t in doc["throughput"].items():
            for name in ("one", "all"):
                for i, r in enumerate(t["runs"][name], 1):
                    L.append(f"| {c} | {r['shards']} | {i} | {r['lines']:,} | {r['engine_lines_per_s']} | {r['pair_lines_per_s']} | {r['late_engine_lines_per_s']} | "
                             f"{r['answer_mismatches']} | {r['host_cpu_s']} | {r['machine_busy_pct']} |")
    else:
        L.append("Not run.")
    L += ["", "## The four bars", "", "| bar | limit | measured | verdict |", "|---|---|---|---|"]
    for b in doc["bars"]:
        L.append(f"| {b['bar']} | {b['limit']} | {json.dumps(b['measured'])} | {b['verdict']} |")
    L += ["", "Rules: S, M and H are judged at 3M (H needs 0.3M as well); S is the sum of the engine's and the checker's process CPU per line; M is the peak private bytes of "
          "each process; H passes only if engine, checker and sum are each within the limit; T is the slowest trial of the 4-shard replay, timed until every checker has verified its last "
          "batch. A bar not measured is MISS with the reason.", "", "## Raw files", ""]
    L += [f"- {c}: {r['json']} (exit {r['exit']}, {r['seconds']} s)" for c, r in doc["runs"].items()]
    for c, t in (doc["throughput"] or {}).items():
        L += [f"- {c} frames: {f}" for f in t["frames_files"]]
    return "\n".join(L) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--md", help="also write the table here")
    ap.add_argument("--sizes", default="300k,3M")
    ap.add_argument("--trials", type=int, default=5)
    ap.add_argument("--batch", type=int, default=2000)
    ap.add_argument("--spec", default="64")
    ap.add_argument("--shards", type=int, default=4)
    ap.add_argument("--tp-lines", type=int, default=300000, help="lines per shard in the throughput replay")
    ap.add_argument("--tp-trials", type=int, default=3)
    ap.add_argument("--no-throughput", action="store_true")
    ap.add_argument("--corpora", default="mixed,hot")
    ap.add_argument("--frames-dir", help="saved frames, reused when their meta matches")
    ap.add_argument("--note", default="")
    ap.add_argument("--pin-check", help="path of the pin_check.py tool; its output is recorded with the run")
    a = ap.parse_args()
    os.environ["RR_E3_SPEC"] = a.spec  # before engine3_compare is imported (lazily, below), which would default it to 1
    os.environ["E3_NEW_EXE"] = "gate_hist3.exe"
    out_dir = Path(a.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    git = lambda *x: subprocess.run(["git", *x], cwd=ROOT, capture_output=True, text=True).stdout.strip()  # noqa: E731
    sizes = [gb.size(x) for x in a.sizes.split(",")]
    small, large = 300_000, 3_000_000
    exes = {n: {"sha256": sha256(fw.BIN / n), "built": time.strftime("%Y-%m-%d %H:%M", time.localtime((fw.BIN / n).stat().st_mtime))} for n in ("gate_hist3.exe", "gate_verify3.exe")}
    doc = {"when": time.strftime("%Y-%m-%d %H:%M"), "head": git("rev-parse", "HEAD")[:8], "tree": "clean" if not git("status", "--short") else "DIRTY: " + git("status", "--short").replace("\n", "; "),
           "spec": a.spec, "trials": a.trials, "batch": a.batch, "note": a.note, "sizes": sizes, "exes": exes,
           "pin_check": subprocess.run([sys.executable, a.pin_check, str(ROOT)], capture_output=True, text=True).stdout if a.pin_check else "not run",
           "idle_busy_pct": quiet_probe(), "runs": {}, "throughput": {}}
    tag = hashlib.sha256((exes["gate_hist3.exe"]["sha256"] + exes["gate_verify3.exe"]["sha256"]).encode()).hexdigest()[:16]
    for c in a.corpora.split(","):
        doc["runs"][c] = run_e3_bench(c, a, out_dir / f"{c}.json")
        print("E3", c, "exit", doc["runs"][c]["exit"], flush=True)
    if not a.no_throughput:
        for c in a.corpora.split(","):
            doc["throughput"][c] = throughput(c, a, out_dir, tag)
    doc["bars"] = verdicts(doc["runs"], doc["throughput"], small, large)
    slim = {**doc, "runs": {c: {k: v for k, v in r.items() if k != "result"} for c, r in doc["runs"].items()}}
    slim["per_size"] = {c: per_size(r["result"]) for c, r in doc["runs"].items() if r["result"]}
    (out_dir / "gate-bars.json").write_text(json.dumps(slim, indent=1), "utf-8")
    text = markdown(doc)
    (out_dir / "gate-bars.md").write_text(text, "utf-8")
    if a.md:
        Path(a.md).write_text(text, "utf-8")
    print(text)
    return 0 if all(r["exit"] == 0 for r in doc["runs"].values()) else 1


if __name__ == "__main__":
    sys.exit(main())
