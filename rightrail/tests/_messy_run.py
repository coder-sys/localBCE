"""Runs the messy file (tests/_messy_file.py) through the whole replay path (tools/replay_diff.py with the deployment opener, the signed
store and the pinned rules engine) and reduces what came out to a short report: what was accepted, what was set aside and why, what each
injected defect did, and how many staff items the set-asides come to.  ``python -m tests._messy_run`` prints the report.
"""

import collections
import contextlib
import cProfile
import hashlib
import io
import json
import os
import pstats
import sys
import tempfile
import time
import traceback
from pathlib import Path

from app import right_rail_gate_decide as decider
from app import right_rail_gate_ffs as ffs
from app import right_rail_gate_producer as producer
from app import right_rail_gate_signer as signer
from app import right_rail_reader_provider_death as pdeath
from app import right_rail_replay_diff as diff
from app import right_rail_x12_835 as r835
from app import right_rail_x12_837 as r837
from app import right_rail_reader_leie as leie
from app import right_rail_replay_deployment as opener
from app import right_rail_x12_834 as r834
from tests import _gate_authority as au
from tests import _messy_file as mf
from tests import test_right_rail_gate_formats as fx
from tests.test_right_rail_replay_deployment import DAY, PIN, SCOPE, deaths_file
from tools import replay_diff as tool

ACTIONS = {row["code"]: row for row in json.loads((Path(opener.__file__).with_name("cause_actions.json")).read_text("utf-8"))}


def write_inputs(root, files, w):
    """The state's hand-over: the deployment folder (grant, key sets, roster, exclusion list, provider deaths) and the 837 and 835 folders."""
    root = Path(root)
    day, step = au.kstep()
    dead = w.providers[mf.DEAD][0]
    parts = {"deployment.json": json.dumps({"tenant": fx.TENANT, "program": fx.PROGRAM, "period": fx.PERIOD, "leie_as_of": DAY, "leie_kind": "full"}).encode(),
             "keyset/genesis": au.genesis()[1], f"keyset/steps/{day}": step, "grant": au.grant(SCOPE), "leie": files["leie"],
             "provider_deaths": deaths_file("20270301", [(mf.tl.make_npi(2), "20270201"), (dead, "20270120")]), "834/roster.834": files["834"]}
    for name, data in parts.items():
        (root / "state" / name).parent.mkdir(parents=True, exist_ok=True)
        (root / "state" / name).write_bytes(data)
    for name, data in (("claims/claims.837", files["837"]), ("paid/paid.835", files["835"])):
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_bytes(data)
    return root


def replay(files, w, scratch=None):
    """(exit code, the replay report, what the decide returned, the 837 reads, seconds)."""
    base = scratch or os.environ.get("E3_SCRATCH") or None
    if base:
        os.makedirs(base, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=base) as tmp:
        root = write_inputs(tmp, files, w)
        inner, seen = opener.replay_decide(root / "state", PIN), {}

        def decide(reads, store, paid):
            seen["reads"] = reads
            seen["result"] = inner(reads, store, paid)
            return seen["result"]
        decide.wants_835, decide.folder = True, inner.folder
        out = root / "report.json"
        started = time.perf_counter()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
            code = tool.main([str(root / "claims" / "claims.837"), "--835", str(root / "paid" / "paid.835"), "--out", str(out)], decide, scratch=Path(tmp))
        seconds = time.perf_counter() - started
        report = json.loads(out.read_text()) if out.exists() else None
        return code, report, seen.get("result"), seen.get("reads"), seconds, err.getvalue()


def faults(reads):
    """The fault that holds each claim, as ``ffs.requests_of`` finds it: {(read, CLM offset): (reader cause, unit, offset of the fault's unit)}."""
    held = {}
    for i, read in enumerate(reads):
        starts, done = [c.offset for c in read.claims], set()
        for q in read.quarantines:
            wide = q.unit in ("file", "set", "group", "interchange")
            if wide and (q.unit, q.offset) in done:
                continue
            done.add((q.unit, q.offset))
            if wide:
                near = read.claims if q.unit == "file" else [c for c in read.claims if getattr(c, q.unit) == q.offset]
            else:
                near = ffs._near(read.claims, starts, q.offset)
            for c in near:
                held.setdefault((i, c.offset), (q.cause, q.unit, q.offset))
    return held


def outcomes(w, reads, result):
    """What became of each claim key: {key: {"decided": None | "ALLOW" | "HOLD:<reasons>", "aside": [(cause, reader, root)]}}, and the unit-level items."""
    sent, left, rows, feed_left, _ruleset_left = result
    at = {}  # CLM offset -> key, for the claims that were read as rows
    for i, read in enumerate(reads):
        for r in read.rows:
            at[(i, r.offsets[0])] = f"{r.billing_npi}/{r.claim_id}"
    pid = {ffs.canonical_id("C", c.npi, c.id): c.key for c in w.claims}
    for b in w.blocks.values():
        for c in b.claims:
            pid[ffs.canonical_id("C", c.npi, c.id)] = c.key
    asked = {r.payment_id for r in sent}
    got = collections.defaultdict(list)
    for p, _, outcome, reasons in rows:
        got[p].append((outcome, tuple(sorted(reasons))))
    result_of = {k: {"decided": None, "aside": []} for k in pid.values()}
    for p, key in pid.items():
        if p in asked:
            lines = got.get(p, [])
            bad = sorted({why for o, rs in lines if o != "ALLOW" for why in (rs or (o,))})
            result_of[key]["decided"] = "ALLOW" if lines and not bad else "HOLD:" + ",".join(bad or ["NO_ROW"])
    roots = faults(reads)
    by_offset = {(i, c.offset): c for i, read in enumerate(reads) for c in read.claims}
    missing = {}
    data = w.files["837"]
    for c in w.claims:
        if c.defect == "claim_id_missing":
            at_ref = data.find(f"REF*6R*{c.id}L1".encode())
            missing[data.rfind(b"CLM*", 0, at_ref)] = c.key
    lone = []
    for a in left:
        key = None
        if a.id.startswith("offset "):
            key = missing.get(int(a.offset))
        elif any(k.endswith("/" + a.id) for k in result_of):
            cands = [k for k in result_of if k.endswith("/" + a.id)]
            key = at.get((0, a.offset)) or cands[0]
        root = roots.get((0, a.offset)) if a.cause == "quarantined" else None
        if key is None:
            lone.append(a)
        else:
            result_of[key]["aside"].append((a.cause, a.reader, root))
    return result_of, lone


def held(r):
    """Whether the claim's result is not a payment."""
    return not (r["decided"] == "ALLOW" and all(c == "retry" for c, _, _ in r["aside"]))


def why(r):
    """The cause a held claim carries: the rules' reasons, else the set-aside cause with the reader's cause."""
    asides = [(c, rd if c == "quarantined" else "") for c, rd, _ in r["aside"] if c != "retry"]
    if asides:
        c, rd = sorted(asides)[0]
        return f"{c}:{rd}" if rd else c
    return r["decided"] if r["decided"] and r["decided"] != "ALLOW" else "LOST"


def staff_items(w, result_of, lone, feed_left):
    """Staff work as items: one per root cause.  A fault that holds many claims, a provider excluded on many claims, a member
    named on many claims, and a pair of conflicting copies are each one item."""
    items = collections.OrderedDict()
    for key in sorted(result_of):
        r = result_of[key]
        if not held(r):
            continue
        npi, cid = key.split("/", 1)
        asides = [(c, rd, root) for c, rd, root in r["aside"] if c != "retry"]
        if asides:
            c, rd, root = sorted(asides, key=lambda x: (x[0], x[1], str(x[2])))[0]
            pair = c == "replaced_or_voided"  # one item with the replacement or void that names it ("named by claim <id> ...")
            who = (("fault", root) if root else ("row", rd) if c == "exclusion_npi_unreadable" else ("claim", f"{npi}/{rd.split()[3]}") if pair
                   else ("claim", key) if c != "payment_id_conflict" else ("pair", cid, npi))
            code = rd if root and rd else "replacement_or_void" if pair else c
        else:
            reason = r["decided"][5:].split(",")[0] if r["decided"] else "NOT_DECIDED"
            claim = next(x for b in w.blocks.values() for x in b.claims if x.key == key)
            code = reason
            who = (("provider", npi) if reason.startswith("PROVIDER_") else ("member", claim.member) if reason.startswith("MEMBER_") else ("claim", key))
        items.setdefault((code, who), []).append(key)
    for a in lone:
        items.setdefault((a.reader or a.cause, ("unit", a.id, a.offset)), [])
    for a in feed_left:
        items.setdefault(("feed:" + a.cause, ("row", a.id)), []).append(a.offset)
    return items


def action_of(code):
    row = ACTIONS.get(code)
    return row["action"] if row else "No staff wording is on file for this cause."


def analyse(w, files, notes, run):
    code, report, result, reads, seconds, err = run
    result_of, lone = outcomes(w, reads, result)
    items = staff_items(w, result_of, lone, result[3])
    claim_of = {c.key: c for b in w.blocks.values() for c in b.claims if c.copy}
    claim_of.update({c.key: c for b in w.blocks.values() for c in b.claims if not c.copy})
    kinds = collections.OrderedDict()
    for key, r in result_of.items():
        c = claim_of[key]
        k = kinds.setdefault(c.defect or "clean", {"claims": 0, "held": 0, "wrong": [], "caught": 0, "missed": [], "by": collections.Counter()})
        k["claims"] += 1
        if held(r):
            k["held"] += 1
            k["by"][why(r)] += 1
        if c.role == "allow" and held(r):
            k["wrong"].append(key)  # held and should not be
        if c.role in ("hold", "genuine"):
            k["missed"].append(key) if not held(r) else k.__setitem__("caught", k["caught"] + 1)
    for entry in w.manifest:  # one service sent under two claim ids: exactly one of the two may be paid
        if entry["kind"] == "same_service_new_claim_id":
            k = kinds[entry["kind"]]
            if sum(held(result_of[x]) for x in (entry["original"], entry["copy"])) == 1:
                k["caught"] += 1
            else:
                k["missed"].append(entry["copy"])
    allow_held = [key for key, r in result_of.items() if claim_of[key].role == "allow" and held(r)]
    clean_held = [key for key in allow_held if not claim_of[key].defect]
    lost = [key for key, r in result_of.items() if held(r) and why(r) == "LOST"]
    return {"code": code, "result_of": result_of, "kinds": kinds, "items": items, "allow_held": allow_held, "clean_held": clean_held, "lost": lost,
            "lone": lone, "seconds": seconds, "report": report, "claim_of": claim_of, "stderr": err, "reads": reads, "result": result, "notes": notes}


def headline(a, w):
    claims = [c for b in w.blocks.values() for c in b.claims]
    lines = sum(len(c.lines) for c in claims)
    keys = a["result_of"]
    allowed = [k for k, r in keys.items() if not held(r)]
    held_by = collections.Counter(why(r) for r in keys.values() if held(r))
    by_cause = collections.Counter()
    for (code, _), members in a["items"].items():
        by_cause[code] += 1
    return {"claim_records_in": len(claims), "service_lines_in": lines, "distinct_claims": len(keys), "accepted": len(allowed),
            "exact_copies_ignored": sum(1 for r in keys.values() for c, _, _ in r["aside"] if c == "retry"),
            "set_aside_or_held": len(keys) - len(allowed), "held_by_cause": dict(sorted(held_by.items())),
            "clean_claims_held": len(a["clean_held"]), "tolerated_defects_held": len(a["allow_held"]) - len(a["clean_held"]),
            "lost_claims": len(a["lost"]), "staff_items": len(a["items"]), "staff_items_by_cause": dict(sorted(by_cause.items())),
            "wall_seconds": round(a["seconds"], 1)}


def defect_table(a):
    rows = []
    for kind, k in a["kinds"].items():
        if kind == "clean":
            continue
        rows.append({"defect": kind, "claims": k["claims"], "caught": k["caught"], "missed": sorted(k["missed"]), "tolerated_but_held": sorted(k["wrong"]),
                     "held_as": dict(k["by"])})
    return rows


def digest(a, w):
    """A digest of what the run decided, claim by claim, so the same file always gives the same answer."""
    body = [(k, r["decided"], sorted((c, rd or "") for c, rd, _ in r["aside"])) for k, r in sorted(a["result_of"].items())]
    return hashlib.sha3_256(json.dumps(body, sort_keys=True).encode()).hexdigest()


# ---- volume: ``scale <lines> <folder>`` writes a state hand-over of about that many service lines; ``time <folder> [profile] [recycle]`` replays it
# and says where the wall time and the CPU went, stage by stage (each stage counted without the stages inside it).
STAGES = (  # (label, module or class, name)
    ("read 835", r835, "read_835"), ("read 837", r837, "read_837"), ("read exclusion list", leie, "read_leie"),
    ("read provider deaths", pdeath, "read_provider_deaths"), ("read 834 roster", r834, "read_834"), ("build feeds", ffs, "feeds"),
    ("claims to requests (per-claim Python)", ffs, "requests_of"), ("decide_claims glue (routing, rows, groups)", ffs, "decide_claims"),
    ("decide: frame build and journal (Python)", decider, "decide"), ("engine process (frame exchange, wall)", decider.RulesWorker, "run_frame"),
    ("verify the engine's answer", decider, "_answer"), ("write the pending frame (fsync)", decider, "_store_pending"), ("checker: gate_verify (Lean, wall)", signer, "gate_verify"),
    ("commit (Python, outside the seal)", decider, "commit"), ("seal: sign and store write", producer.ShardProducer, "_seal"),
    ("report: from 835", diff, "from_835"), ("report: from decision", diff, "from_decision"), ("report: diff", diff, "diff_report"),
    ("report: render", diff, "render"))


class Clock:
    """Wall and process CPU seconds per stage, each without the stages called inside it.  The engine is another process: its CPU is not
    in ``cpu``, only the wall time the Python side waited for it."""

    def __init__(self):
        self.wall, self.cpu, self.calls, self.stack, self.batches = collections.Counter(), collections.Counter(), collections.Counter(), [], []

    def _charge(self):
        now, cpu = time.perf_counter(), time.process_time()
        if self.stack:
            label, w0, c0 = self.stack[-1]
            self.wall[label] += now - w0
            self.cpu[label] += cpu - c0
        return now, cpu

    def wrap(self, label, fn):
        def timed(*a, **k):
            self.calls[label] += 1
            self.stack.append((label, *self._charge()))
            try:
                return fn(*a, **k)
            finally:
                self._charge()
                self.stack.pop()
                if self.stack:
                    self.stack[-1] = (self.stack[-1][0], time.perf_counter(), time.process_time())
        return timed


def peak_bytes():
    """The most memory this process has held (Windows peak working set)."""
    import ctypes
    from ctypes import wintypes

    class Counters(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("faults", wintypes.DWORD), ("peak", ctypes.c_size_t)] + [(n, ctypes.c_size_t) for n in ("ws", "pp", "pnp", "qpp", "qpnp", "pf", "ppf")]
    info = Counters()
    info.cb = ctypes.sizeof(info)
    ctypes.windll.kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    ctypes.windll.psapi.GetProcessMemoryInfo(ctypes.c_void_p(ctypes.windll.kernel32.GetCurrentProcess()), ctypes.byref(info), info.cb)
    return info.peak


def folder_bytes(path):
    return sum(f.stat().st_size for f in Path(path).rglob("*") if f.is_file())


def scale(lines, root):
    started = time.perf_counter()
    w, files, notes = mf.build(skip=("roster_member_id_missing", "leie_row_missing_column"), lines=lines)  # the two faults that refuse a whole replay stay out
    w.files = files
    built = time.perf_counter() - started
    write_inputs(root, files, w)
    claims = [c for b in w.blocks.values() for c in b.claims]
    meta = {"service_lines_in": sum(len(c.lines) for c in claims), "claim_records_in": len(claims), "members": w.n_members, "build_seconds": round(built, 1),
            "bytes": {k: len(v) for k, v in files.items()}}
    (Path(root) / "meta.json").write_text(json.dumps(meta))
    print(json.dumps(meta))


def timed_replay(root, profile=False, recycle=False):
    root, clock, kept = Path(root), Clock(), {}
    for label, owner, name in STAGES:
        setattr(owner, name, clock.wrap(label, getattr(owner, name)))
    run_decide, ffs_decide, run_verify = decider.decide, ffs.decide_claims, signer.gate_verify
    checks = []

    def verify(mode, frame):  # every checker call: its mode, the frame's size and how long it took
        if recycle and len(checks) % 8 == 7:  # the resident checker grows ~34 MB a checkpoint and dies at its 512 MiB cap on the 15th: restart it
            signer._close_server(signer._VSERVER)  # (it decides each request from its own bytes, so a fresh one answers the same)
        started = time.perf_counter()
        try:
            return run_verify(mode, frame)
        finally:
            worker = signer._VSERVER[0]
            checks.append((mode, len(frame), round(time.perf_counter() - started, 2), worker.peak_job_memory() if worker is not None else None))

    def batch(feeds, asof, prod, requests, *rest, **more):  # one mark per batch: when it began and how many lines it held
        clock.batches.append((time.perf_counter(), sum(len(r.lines) for r in requests)))
        return run_decide(feeds, asof, prod, requests, *rest, **more)

    def whole(*a, **k):
        try:
            return ffs_decide(*a, **k)
        finally:
            clock.batches.append((time.perf_counter(), 0))
    decider.decide, ffs.decide_claims = batch, whole
    signer.gate_verify = verify
    inner = opener.replay_decide(root / "state", PIN)

    def decide(reads, store, paid):
        try:
            return inner(reads, store, paid)
        except Exception:
            kept["trace"] = traceback.format_exc()
            raise
        finally:
            kept["store_bytes"] = folder_bytes(store)
    decide.wants_835, decide.folder = True, inner.folder
    base = os.environ.get("E3_SCRATCH") or None
    out, prof = root / "report.json", cProfile.Profile() if profile else None
    started_at = wall = time.perf_counter()
    cpu = time.process_time()
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
        if prof:
            prof.enable()
        code = tool.main([str(root / "claims" / "claims.837"), "--835", str(root / "paid" / "paid.835"), "--out", str(out), "--overwrite"], decide, scratch=base)
        if prof:
            prof.disable()
    wall, cpu = time.perf_counter() - wall, time.process_time() - cpu
    if code:
        sys.exit(f"replay failed, exit {code} after {len(clock.batches)} batches, {time.perf_counter() - started_at:.0f}s: {err.getvalue()} {checks} {kept.get('trace', '')}")
    meta = json.loads((root / "meta.json").read_text())
    lines = meta["service_lines_in"]
    report = json.loads(out.read_text())
    rows = [{"stage": label, "calls": clock.calls[label], "wall_s": round(clock.wall[label], 2), "cpu_s": round(clock.cpu[label], 2)} for label, _, _ in STAGES]
    rows.append({"stage": "other (tool glue, GC)", "calls": 1, "wall_s": round(wall - sum(clock.wall.values()), 2), "cpu_s": round(cpu - sum(clock.cpu.values()), 2)})
    marks, tenths = clock.batches, []
    if len(marks) > 10:  # lines per second within each tenth of the batches: the rate as the store grows
        n = len(marks) - 1
        for k in range(10):
            a, b = k * n // 10, (k + 1) * n // 10
            held = sum(m[1] for m in marks[a:b])
            tenths.append(round(held / (marks[b][0] - marks[a][0]), 1) if b > a and held else None)
    result = {"service_lines": lines, "claims": meta["claim_records_in"], "exit": code, "wall_s": round(wall, 1), "cpu_s_this_process": round(cpu, 1),
              "lines_per_s": round(lines / wall, 1), "cpu_us_per_line": round(cpu / lines * 1e6, 1), "peak_working_set_bytes": peak_bytes(),
              "store_bytes": kept.get("store_bytes"), "store_bytes_per_line": round(kept.get("store_bytes", 0) / lines, 1), "batches": len(marks) - 1,
              "lines_per_s_by_tenth_of_run": tenths, "checker_calls_mode_bytes_seconds_peak_job_memory": checks[::max(1, len(checks) // 12)], "compared": report["compared"], "differing": report["differing"], "stages": rows}
    print(json.dumps(result, indent=1))
    if prof:
        pstats.Stats(prof).sort_stats("tottime").print_stats(30)


def main():
    if sys.argv[1:2] == ["scale"]:
        return scale(int(sys.argv[2]), sys.argv[3])
    if sys.argv[1:2] == ["time"]:
        return timed_replay(sys.argv[2], "profile" in sys.argv[3:], "recycle" in sys.argv[3:])
    cut = "cut" in sys.argv[1:]
    skip = tuple(a for a in sys.argv[1:] if a != "cut")
    w, files, notes = mf.build(skip=skip, cut=cut)
    w.files = files
    run = replay(files, w)
    if run[2] is None:
        sys.exit(f"replay refused, exit {run[0]}: {run[5]}")
    a = analyse(w, files, notes, run)
    out = {"exit": a["code"], "digest": digest(a, w), "headline": headline(a, w), "defects": defect_table(a)}
    out["staff"] = [{"cause": c, "root": list(map(str, who)), "claims": len(keys), "action": action_of(c)} for (c, who), keys in a["items"].items()]
    out["clean_held"] = [(k, why(a["result_of"][k])) for k in a["clean_held"]]
    out["tolerated_held"] = [(k, a["claim_of"][k].defect, why(a["result_of"][k])) for k in a["allow_held"] if a["claim_of"][k].defect]
    out["missed"] = {r["defect"]: r["missed"] for r in out["defects"] if r["missed"]}
    out["manifest_entries"] = len(w.manifest)
    out["replay_report"] = {k: a["report"][k] for k in ("compared", "differing", "cents_at_stake", "set_aside", "by_cause")} if a["report"] else None
    json.dump(out, sys.stdout, indent=1, default=str)
    print()
    print(a["stderr"], file=sys.stderr)


if __name__ == "__main__":
    main()
