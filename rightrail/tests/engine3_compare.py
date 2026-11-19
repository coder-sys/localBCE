"""Equivalence tool (not a unittest): the same request batches go to `gate_engine` and to `gate_hist3`; each line's outcome, rule
and reasons are compared (head, root and the counterpart's chunk/row differ by design, conformance/ENGINE_V3.md section 23).
A batch the new engine refuses is counted apart from mismatches, and ends that corpus (the two stores no longer follow one history).
The checker (gate_verify3 on its own history) then runs over each new store, and a store it does not verify counts as one mismatch.

    python tests/engine3_compare.py WORKTREE golden
    python tests/engine3_compare.py WORKTREE mixed|hot|overcap [LINES [BATCH]]      (default 300000 lines, 2000 per batch)
    (overcap: one core of LINES rows, each of its keys under the cap; use 5000 or more lines)

Prints one summary line per corpus.  Synthetic, nonpayment, non-PHI."""

import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

if __name__ == "__main__":
    if len(sys.argv) < 3 or not os.path.isdir(sys.argv[1]):
        raise SystemExit(f"STOP expected an existing WORKTREE and a corpus: {sys.argv[1:]!r}")
    WT = sys.argv[1]
else:
    WT = str(Path(__file__).resolve().parents[1])  # imported by the tests: this tree
os.chdir(WT)
sys.path.insert(0, WT)
from app import right_rail_gate_chain as chain  # noqa: E402
from app import right_rail_gate_codec as gate  # noqa: E402
from app import right_rail_gate_decide as decider  # noqa: E402
from tests import _gate_shards as g  # noqa: E402
from tests import gate_bench as gb  # noqa: E402
from tests import gate_corpus  # noqa: E402
from tests import test_flat_worker as fw  # noqa: E402
from tests import test_right_rail_gate_formats as fx  # noqa: E402

NEW = fw.BIN / "gate_hist3.exe"
os.environ.setdefault("RR_E3_SPEC", "1")  # the new engine also runs the list decoder and spec admission on every batch (default: 1 in 64)
NONE = 0xFFFFFFFF
EVIDENCE = tuple(sorted((fx.D[2], fx.D[5])))
RELEASE = gate.sha3_512(fw.ENGINE.read_bytes())


def capped_ok(o, n) -> bool:
    """A line of a core already past the cap (the cap is per core on the rows files, per key on the old engine) fails closed: HOLD with
    POSTING_CAP.  The other reasons come from the capped reads and are not compared."""
    return n.outcome == "HOLD" and "POSTING_CAP" in n.reasons


def mismatch_indices(old: dict, new: dict, capped: bool = False) -> list[int]:
    """Compare per-line outcome, rule and reasons, and a line missing from either answer.  Where a counterpart is stored is not
    compared: engine v3 gives no place to an entry still in a window (Step.lean:9), so the old engine's place with none in the new
    is no difference.  A place only the new engine reports is one (an entry the old engine does not have)."""
    return [i for i in sorted(set(old) | set(new)) if i not in old or i not in new or
            (not capped_ok(old[i], new[i]) if capped else
             (old[i].outcome, old[i].rule, old[i].reasons) != (new[i].outcome, new[i].rule, new[i].reasons)) or
            (new[i].chunk != NONE and old[i].chunk == NONE)]


def report_mismatch(label: str, batch: int, index: int, old, new) -> None:
    print(f"MISMATCH {label} batch {batch} line {index}: old {old} new {new}")


def semantic_leaves(leaves):
    """INPUT/v6 binds each engine's own head (in its context); every other Pay field must agree.

    This comparator checks decision equivalence, not independent input-commitment validity.
    The engine verifier checks the engine-local binding.
    """
    return [leaf._replace(input=b"") for leaf in leaves]


class Pair:
    """The two engines on scratch stores; each follows its own head."""

    def __init__(self, root: Path) -> None:
        self.dirs = [root / "old", root / "new"]
        for d in self.dirs:
            d.mkdir(parents=True)
        self.eng = [fw.Engine(self.dirs[0], fw.ENGINE), fw.Engine(self.dirs[1], NEW)]
        self.batch_lines = 2000
        self.head, self.n, self.ws, self.secs = [fw.GENESIS, fw.GENESIS], 0, [0, 0], [0.0, 0.0]
        self.lines = self.batches = self.mismatch = self.refused = self.examples = self.capped = 0
        self.outcomes: dict[str, int] = {}
        self.info = {"leaves_differ": 0, "adds_differ": 0}

    def batch(self, bodies: list[bytes], label: str) -> bool:
        """Send one batch to both; False when the corpus must stop (a refusal or an unreadable answer)."""
        self.n += 1
        outs = []
        for i in range(2):
            data = decider.request_frame(g.HEAD, 0, self.n, g.ASOF, self.head[i], g.PIN, fw.floors(self.head[i]), g.KEYS, g.GRANT, RELEASE, (), bodies)
            t0 = time.perf_counter()
            out = self.eng[i].send(data)
            self.secs[i] += time.perf_counter() - t0
            outs.append((data, out))
        self.ws = [max(w, gb.peak_rss(e.p)) for w, e in zip(self.ws, self.eng)]
        if self.n % 10 == 1 or not all(o for _, o in outs):
            print(f"WS batch {self.n} peak working set old {self.ws[0] >> 20} MB new {self.ws[1] >> 20} MB; engine seconds so far old {self.secs[0]:.1f} new {self.secs[1]:.1f}", flush=True)
        try:
            ans = [fw.read(d, o) for d, o in outs]
        except decider.GateDecideError as e:
            return self.fail(f"{label} batch {self.n}: unreadable answer {e}; answer bytes old {len(outs[0][1])} new {len(outs[1][1])}, "
                             f"exit old {self.eng[0].p.poll()} new {self.eng[1].p.poll()}")
        (whyo, ro, ho, _, _, lo, ao), (whyn, rn, hn, _, _, ln, an) = ans
        if whyo is not None:
            return self.fail(f"{label} batch {self.n}: the old engine refused: {whyo}")
        if whyn is not None:
            self.refused += 1  # a hold or refusal the new engine writes where the old decided
            print(f"REFUSED {label} batch {self.n}: {whyn}")
            return False
        self.batches += 1
        a, b = {r.index: r for r in ro}, {r.index: r for r in rn}
        capd = label == "overcap" and self.lines > 1024  # one core: its rows so far are the lines so far
        bad = mismatch_indices(a, b, capd)
        self.capped += sum("POSTING_CAP" in r.reasons for r in rn)
        self.lines += len(ro)
        for r in ro:
            k = f"{r.outcome} {','.join(r.reasons) or '-'}"
            self.outcomes[k] = self.outcomes.get(k, 0) + 1
        self.mismatch += len(bad)
        if bad and self.examples < 3:
            self.examples += 1
            i = bad[0]
            report_mismatch(label, self.n, i, a.get(i), b.get(i))
            if label in ("mixed", "hot"):
                g_i = (self.n - 2) * self.batch_lines + i  # the corpus line (batch 1 is the empty init batch)
                t = gate_corpus.target(gb.SEED, g_i)
                print(f"  corpus line {g_i} is a {gate_corpus.kind(gb.SEED, g_i)} of line {t} (batch {t // self.batch_lines + 2})")
        leaves_differ = len(lo) != len(bodies) or len(ln) != len(bodies) or (not capd and semantic_leaves(lo) != semantic_leaves(ln))
        if leaves_differ and not self.info["leaves_differ"]:
            print("LEAF example", len(lo), len(ln), next(((x, y) for x, y in zip(lo, ln) if x != y), None))
        self.info["leaves_differ"] += leaves_differ
        self.info["adds_differ"] += sorted(ao) != sorted(an)
        if leaves_differ:
            self.mismatch += 1
            print(f"DIFF leaves batch {self.n}: old={len(lo)} new={len(ln)}")
        if sorted(ao) != sorted(an):
            self.mismatch += 1
            print(f"DIFF adds batch {self.n}: old={len(ao)} new={len(an)}")
        self.head = [ho, hn]
        return True

    def fail(self, why: str) -> bool:
        print("STOP " + why)
        self.mismatch += 1
        return False

    def close(self) -> dict:
        for e in self.eng:
            e.close()
        self.mismatch += checker(self.dirs[1])
        return events(self.dirs[1] / "log")


def checker(d: Path) -> int:
    """The checker (`gate_verify3` on its own history) over the rows-file store `d`: 0 when it verifies every frame, else 1."""
    r = subprocess.run([str(fw.BIN / "gate_verify3.exe"), str(d), "0", "rows-offline", f"{d}.verify", "0"], capture_output=True, text=True, timeout=7200)
    print(f"CHECKER {d}: exit {r.returncode} {(r.stdout.splitlines() or [r.stderr[-300:]])[0]}", flush=True)
    return 0 if r.returncode == 0 else 1


def events(log: Path) -> dict:
    """Seal, install and reclaim events in the new store's log trailers (all zero on a rows-file store)."""
    raw, pos, ev = log.read_bytes(), 0, {"frames": 0, "seals": 0, "installs": 0, "reclaims": 0, "torn_tail_bytes": 0}
    trailer_len = 24 + 4 + 8 + 20 + 20 + 24 + 79 + 208 + 7 * 64  # Frame3.Trailer.trailerLen
    while pos + 16 <= len(raw):
        if raw[pos : pos + 4] != b"RRF4":
            raise ValueError(f"invalid journal frame magic at offset {pos}")
        rq, an, tr = struct.unpack("<III",raw[pos + 4 : pos + 16])
        if tr != trailer_len:
            raise ValueError(f"invalid journal trailer length {tr} at offset {pos}; expected {trailer_len}")
        t = pos + 16 + rq + an
        if t + tr > len(raw):
            ev["torn_tail_bytes"] = len(raw) - pos  # Engine3.scanFrames permits an incomplete final frame.
            break
        e = t + tr - 448 - 208 - 79
        if any(raw[e + off] not in (0, 1) for off in (0, 5, 74)):
            raise ValueError(f"invalid event flag at offset {e}")
        ev["frames"] += 1
        ev["seals"] += raw[e]
        ev["installs"] += raw[e + 5]
        ev["reclaims"] += raw[e + 74]
        pos = t + tr
    if not ev["torn_tail_bytes"] and pos < len(raw):
        ev["torn_tail_bytes"] = len(raw) - pos
    return ev


def lid(x: str) -> str:
    """A line id of 32 characters: the engine v3 store takes `id` as an n33 number (ENGINE_V3 section 1); a shorter one is a wide field."""
    return f"L{x:0>31}"


def line_body(i: int, text: str, hot: bool) -> bytes:
    ident, _, member, payee, rendering, date, code, units, cents = text.split()
    if hot:  # a few enrolled members, providers and days: the same keys come back batch after batch
        key = g.member(fw.MEMBERS[int(member) % len(fw.MEMBERS)], 0)
        payee, rendering = int(payee) % 4, int(rendering) % 4
        date = 20270201 + (int(date) % 20)
        code = 99213 + 7 * (int(code) % 6) if int(code) in gate_corpus.CODES else code
        cents = gate_corpus.CENTS[(int(code) - 99213) // 7] * int(units) if int(code) in gate_corpus.CODES else cents
    else:
        key = int(member).to_bytes(gate.MEMBER_KEY, "big")
    line = gate.encode_line("FFS_CLAIM", lid(ident.split(":")[0]), key, f"P{payee}", f"R{rendering}", int(date), f"C{code}", int(units), int(cents))
    return gate.encode_decide_request(gate.DecideRequest(fx.TENANT, fx.PROGRAM, "FFS_CLAIM", f"cmd-{i}", f"pay-{i}", key, f"P{payee}",
                                                         int(cents), fx.PERIOD, (line,), EVIDENCE))


def overcap_body(i: int) -> bytes:
    """One member, day and procedure for every line, so all lines are one core, with payee, rendering provider and units spread so
    that no exact or near key reaches the cap on its own: the core passes the cap (1,024 rows) while each of its keys stays below."""
    key = g.member(fw.MEMBERS[0], 0)
    payee, rendering, units = i % 4, (i // 4) % 4, 1 + (i // 16) % 10
    cents = gate_corpus.CENTS[0] * units
    line = gate.encode_line("FFS_CLAIM", lid(str(i)), key, f"P{payee}", f"R{rendering}", 20270201, "C99213", units, cents)
    return gate.encode_decide_request(gate.DecideRequest(fx.TENANT, fx.PROGRAM, "FFS_CLAIM", f"cmd-{i}", f"pay-{i}", key, f"P{payee}",
                                                         cents, fx.PERIOD, (line,), EVIDENCE))


def bench(kind: str, total: int, batch: int) -> dict:
    root = Path(tempfile.mkdtemp(prefix=f"e3cmp_{kind}_", dir=os.environ.get("E3_SCRATCH")))
    p = Pair(root)
    p.batch_lines = batch
    built = 0
    ok = p.batch([], kind)  # the init batch
    while ok and built < total:
        n = min(batch, total - built)
        if kind == "overcap":
            bodies = [overcap_body(i) for i in range(built, built + n)]
        else:
            bodies = [line_body(i, t, kind == "hot") for i, t in enumerate(gate_corpus.lines(gb.SEED, built, n, total), built)]
        built += n
        ok = p.batch(bodies, kind)
    result = summary(kind, p, root)
    drop_store(root, not (result["mismatch"] or result["refused"]))
    return result


def drop_store(root: Path, passed: bool) -> None:
    """A run removes the store it made itself when it passed; a failed run, or E3_KEEP=1, leaves it for inspection."""
    if passed and not os.environ.get("E3_KEEP"):
        shutil.rmtree(root, ignore_errors=True)


def summary(kind: str, p: Pair, root: Path) -> dict:
    ev = p.close()
    top = sorted(p.outcomes.items(), key=lambda kv: -kv[1])[:6]
    if kind == "overcap" and not p.capped:
        p.mismatch += 1
        print("STOP the core never passed the cap: no POSTING_CAP line")
    print(f"SUMMARY {kind}: lines={p.lines} batches={p.batches} capped={p.capped} mismatches={p.mismatch} refused={p.refused} events={ev} "
          f"info={p.info} outcomes={top} store={root}")
    return {"mismatch": p.mismatch, "refused": p.refused, "lines": p.lines, "batches": p.batches, "events": ev}


def golden() -> dict:
    """Each case of tests/gate_rules/rules_v2.vectors that starts from empty sets and only has lines and commits: a fresh pair of
    stores, a batch per commit.  Other cases (preloaded sets, redo, drop, own feeds) are counted as skipped."""
    cases, cur = [], None
    for row in Path(WT, "tests/gate_rules/rules_v2.vectors").read_text("utf-8").splitlines():
        f = row.split()
        if f[:1] == ["case"]:
            cur = [f[1], []]
            cases.append(cur)
        elif cur is not None and f and not row.startswith("#"):
            cur[1].append(f)
    root = Path(tempfile.mkdtemp(prefix="e3cmp_golden_", dir=os.environ.get("E3_SCRATCH")))
    used, skipped = 0, 0
    lines = batches = mism = refused = 0
    for name, rows in cases:
        while rows and rows[-1][0] != "commit" and rows[-1][0] != "line":
            rows.pop()  # a snapshot restore after the case
        if any(r[0] not in ("line", "commit") for r in rows) or not rows:
            skipped += 1
            continue
        used += 1
        p = Pair(root / name)
        bodies = {}
        groups: list[dict] = [{}]
        for r in rows:
            if r[0] == "commit":
                groups.append({})
                continue
            ident, _, pay = r[1].partition(":")
            groups[-1].setdefault(pay or ident, []).append(r[1:])
        for gi, grp in enumerate(groups):
            if not grp:
                continue
            reqs = []
            for pay, ls in grp.items():
                enc = [gate.encode_line(x[1], lid(x[0].split(":")[0]), g.member(int(x[2]), 0), f"P{x[3]}", f"R{x[4]}", int(x[5]), f"C{x[6]}", int(x[7]), int(x[8])) for x in ls]
                key = g.member(int(ls[0][2]), 0)
                reqs.append(gate.encode_decide_request(gate.DecideRequest(fx.TENANT, fx.PROGRAM, ls[0][1], f"cmd-{pay}", f"pay-{pay}", key, f"P{ls[0][3]}",
                                                                          sum(int(x[8]) for x in ls), fx.PERIOD, tuple(enc), EVIDENCE)))
            if not p.batch(reqs, name):
                break
        p.close()
        lines, batches, mism, refused = lines + p.lines, batches + p.batches, mism + p.mismatch, refused + p.refused
    print(f"SUMMARY golden: cases_used={used} cases_skipped={skipped} lines={lines} batches={batches} mismatches={mism} refused={refused}")
    drop_store(root, not (mism or refused))
    return {"mismatch": mism, "refused": refused, "skipped": skipped, "cases_used": used, "lines": lines, "batches": batches}


def main(argv=None, bench_fn=bench, golden_fn=golden) -> int:
    argv = sys.argv if argv is None else argv
    what = argv[2]
    if what == "golden":
        result = golden_fn()
    else:
        total, batch = int(argv[3]) if len(argv) > 3 else 300000, int(argv[4]) if len(argv) > 4 else 2000
        if what not in ("mixed", "hot", "overcap") or total <= 0 or batch <= 0:
            print("STOP expected mixed|hot|overcap with positive LINES and BATCH")
            return 1
        result = bench_fn(what, total, batch)
    print("SCOPE decision fields, semantic token leaves and shared adds; engine-local input commitments require the verifier")
    if result.get("lines", 0) <= 0 or result.get("batches", 0) <= 0 or (what == "golden" and result.get("cases_used", 0) <= 0):
        print("STOP no comparison coverage: " + repr(result))
        return 1
    return 1 if result["mismatch"] or result["refused"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
