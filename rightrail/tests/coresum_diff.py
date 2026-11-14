"""Long-core summary differential for gate_hist3.  usage: coresum_diff.py [WT]
The same batches go to several copies of the engine on their own stores (each follows its own head: an answer is signed afresh,
so two answers of one decision differ in bytes).  Every answer must decode to the same decisions, reasons, leaves (but for the
engine's own input commitment) and adds, and at the end the rows files of every store must be byte for byte the same:
  default      the summary at its default size
  chain        RR_CORESUM_CAP=0,2: no row can be linked, every read walks the chain (what the engine did before the summary)
  full         RR_CORESUM_CAP=64,16: the table fills at once; reads of unlisted cores walk the chain
  healed       the default size, killed half way, rows files cut in half, reopened (the summary is rebuilt from the rows files)
  base         E3_BASE_EXE, when set: another build of the engine (for example the one before the summary)
and the checker must verify the default store with its own summary at each of the first three sizes,
over a hot corpus (a few keys again and again: long cores), the over-cap corpus (one core past POSTING_CAP) and the redo
corpus (the over-cap corpus with early payments sent again as redone: the reads that must walk a long core's chain).
Synthetic, nonpayment, non-PHI."""
import os, subprocess, sys, tempfile
from pathlib import Path
WT = sys.argv[1] if len(sys.argv) > 1 else str(Path(__file__).resolve().parents[1])
os.environ.setdefault("E3_SCRATCH", tempfile.gettempdir())
sys.path.insert(0, WT)
os.chdir(WT)
from app import right_rail_gate_decide as decider  # noqa: E402
from tests import _gate_shards as g  # noqa: E402
from tests import engine3_compare as ec  # noqa: E402
from tests import gate_bench as gb  # noqa: E402
from tests import gate_corpus  # noqa: E402
from tests import test_flat_worker as fw  # noqa: E402

EXE = fw.BIN / "gate_hist3.exe"
VARIANTS = {"default": (EXE, {}), "chain": (EXE, {"RR_CORESUM_CAP": "0,2"}), "full": (EXE, {"RR_CORESUM_CAP": "64,16"}),
            "healed": (EXE, {})}
if os.environ.get("E3_BASE_EXE"):
    VARIANTS["base"] = (Path(os.environ["E3_BASE_EXE"]), {})
# The checker (gate_verify3, its own summary from the rows it checked) over the default store, with its summary at the default
# size, none (every read walks the chain) and full: each must verify every frame.
CHECKS = (("default", None), ("chain", "0,2"), ("full", "64,16"))


def bodies(kind, built, n, total):
    if kind in ("overcap", "redo"):
        return [ec.overcap_body(i) for i in range(built, built + n)]
    return [ec.line_body(i, t, True) for i, t in enumerate(gate_corpus.lines(gb.SEED, built, n, total), built)]


def redone(kind, bi):
    """The redo corpus: the over-cap corpus with, from the second batch on, five payments of the first batch sent again
    as redone (their lines are the first rows of keys of the long core: the reads that walk its chain)."""
    if kind != "redo" or bi < 2:
        return [], ()
    ids = range(5 * (bi - 2), 5 * (bi - 1))
    return [ec.overcap_body(i) for i in ids], tuple(fw.pay_number(i) for i in ids)


def run(kind, total, batch):
    root = Path(tempfile.mkdtemp(prefix=f"cs_{kind}_", dir=os.environ["E3_SCRATCH"]))
    dirs = {k: root / k for k in VARIANTS}
    eng = {}
    for k, (exe, env) in VARIANTS.items():
        dirs[k].mkdir()
        eng[k] = fw.Engine(dirs[k], exe, env)
    head, built, n = {k: fw.GENESIS for k in eng}, 0, 0
    batches = [[]] + [None] * ((total + batch - 1) // batch)
    for bi in range(len(batches)):
        if bi == len(batches) // 2:  # heal: kill, cut the rows files, reopen
            eng["healed"].p.kill()
            eng["healed"].p.wait()
            for f in ("rows_rel", "rows_unr"):
                fp = dirs["healed"] / f
                with open(fp, "r+b") as h:
                    h.truncate((fp.stat().st_size // 256 // 2) * 256)
            eng["healed"] = fw.Engine(dirs["healed"], EXE, {})
        if bi:
            m = min(batch, total - built)
            body = bodies(kind, built, m, total)
            built += m
        else:
            body = []
        again, redo = redone(kind, bi)
        n += 1
        got = {}
        for k, e in eng.items():
            data = decider.request_frame(g.HEAD, 0, n, g.ASOF, head[k], g.PIN, fw.floors(head[k]), g.KEYS, g.GRANT, ec.RELEASE, (), again + body, redo)
            why, recs, head[k], _, _, leaves, adds = fw.read(data, e.send(data))
            assert why is None, f"{kind} batch {n}: {k} refused {why}"
            got[k] = (recs, ec.semantic_leaves(leaves), adds)
        for k, v in got.items():
            assert v == got["default"], f"{kind} batch {n}: answer of {k} differs from default"
    for e in eng.values():
        e.close()
    rows = ("rows_rel", "rows_unr")
    ref = {f: (dirs["default"] / f).read_bytes() for f in rows}
    assert all(ref.values()), f"{kind}: no rows"
    for k in dirs:
        for f in rows:
            assert (dirs[k] / f).read_bytes() == ref[f], f"{kind}: {k} file {f} differs from default"
    for name, cap in CHECKS:
        env = {k: v for k, v in os.environ.items() if k != "RR_CORESUM_CAP"} | ({"RR_CORESUM_CAP": cap} if cap else {})
        d = dirs["default"]
        r = subprocess.run([str(fw.BIN / "gate_verify3.exe"), str(d), "0", "rows-offline", f"{d}.verify-{name}", "0"],
                           capture_output=True, text=True, timeout=7200, env=env)
        assert r.returncode == 0, f"{kind}: checker ({name}) exit {r.returncode}: {(r.stdout + r.stderr)[-300:]}"
    print(f"OK {kind}: {built} lines in {n - 1} batches, {len(VARIANTS)} engines, decisions and the rows files identical, "
          f"checker verified with {len(CHECKS)} summary sizes ({root})", flush=True)


run("hot", 40000, 2000)  # 960 cores: past 32 rows each from about 31,000 lines
run("overcap", 6000, 2000)
run("redo", 6000, 500)
print("coresum_diff done")
