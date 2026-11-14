"""Crash and refill differential for gate_hist3 against the old engine.  usage: hist3_crash.py [WT]
A hover corpus (one line again and again under new ids: one core past the cap) plus ordinary lines, sent to both engines;
between batches the new engine is killed and its store damaged, then reopened:
  1 kill, rows files cut short       (refill from the frames)
  2 kill, half a record added        (cut to a whole record, then cut to the trailer)
  3 kill, the last log frame cut off (rows past the trailer are cut; the batch is sent again, same head expected)
  4 kill in the middle of a batch    (the batch is sent again to the reopened engine)
  5 kill, rows files of full length with zeroed / garbage records and no clean-stop marker (rebuilt from the log)
  6 kill in the middle of a batch, then the same damage
  7 clean stop writes the marker 1, a start writes 0 before any write
A clean stop followed by damage to whole records is not tested: with the marker present the engine trusts its rows files,
which is the threat model's limit (a disk fault behind a completed sync); only a stop without the marker is healed.
Then the checker (gate_verify3 on its own history) must verify the whole log."""
import os, struct, sys, time
from pathlib import Path
WT = sys.argv[1] if len(sys.argv) > 1 else str(Path(__file__).resolve().parents[1])
os.environ.setdefault("E3_SCRATCH", r"C:\Users\neers\AppData\Local\Temp\claude\s")
sys.path.insert(0, WT)
os.chdir(WT)
from app import right_rail_gate_decide as decider  # noqa: E402
from tests import _gate_shards as g  # noqa: E402
from tests import engine3_compare as ec  # noqa: E402
from tests import gate_bench as gb  # noqa: E402
from tests import gate_corpus  # noqa: E402
from tests import test_flat_worker as fw  # noqa: E402
import tempfile  # noqa: E402

EXE = fw.BIN / "gate_hist3.exe"
root = Path(tempfile.mkdtemp(prefix="hcrash_", dir=os.environ["E3_SCRATCH"]))
p = ec.Pair(root)
nd = p.dirs[1]
base = gate_corpus.lines(gb.SEED, 0, 1, 1000).__next__().split()
counter = [0]


def hover(n):
    out = []
    for _ in range(n):
        counter[0] += 1
        t = base[:]
        t[0] = f"{9000000 + counter[0]}:{9000000 + counter[0]}"
        out.append(ec.line_body(10_000_000 + counter[0], " ".join(t), True))
    return out


def normal(n, start):
    return [ec.line_body(i, t, True) for i, t in enumerate(gate_corpus.lines(gb.SEED, start, n, 100000), start)]


def cold(n, start):
    return [ec.line_body(i, t, False) for i, t in enumerate(gate_corpus.lines(gb.SEED, start, n, 100000), start)]


def reopen():
    p.eng[1].p.kill()
    p.eng[1].p.wait()


def start():
    p.eng[1] = fw.Engine(nd, EXE)


def frames(raw):
    pos, out = 0, []
    while pos + 16 <= len(raw) and raw[pos:pos + 4] == b"RRF4":
        rq, an, tr = struct.unpack("<III", raw[pos + 4:pos + 16])
        end = pos + 16 + rq + an + tr
        if end > len(raw):
            break
        out.append((pos, end))
        pos = end
    return out


def check(label):
    print(label, "mismatches so far", p.mismatch, "refused", p.refused, flush=True)
    assert p.mismatch == 0 and p.refused == 0, label


p.batch([], "init")
built = 0
for k in range(3):                       # 1500 hover lines: one core past the cap of 1024
    assert p.batch(hover(500), "hover"); check(f"hover {k}")
assert p.batch(normal(500, built), "normal"); built += 500; check("normal")
print("outcomes", sorted(p.outcomes.items(), key=lambda kv: -kv[1])[:8])

# 1 rows files cut short
reopen()
for f in ("rows_rel", "rows_unr"):
    fp = nd / f
    sz = fp.stat().st_size
    with open(fp, "r+b") as h:
        h.truncate((sz // 256 // 2) * 256)
start()
assert p.batch(hover(300) + normal(200, built), "after cut"); built += 200; check("1 rows cut short")

# 2 half a record added
reopen()
for f in ("rows_rel", "rows_unr"):
    with open(nd / f, "ab") as h:
        h.write(b"\x07" * 100)
start()
assert p.batch(hover(300) + normal(200, built), "after junk"); built += 200; check("2 junk tail")

# 3 last frame cut off, the batch sent again (same head expected)
head_before = p.head[1]
last = hover(200) + normal(200, built); built += 200
assert p.batch(last, "last"); check("3 before cut")
head_after, n_last = p.head[1], p.n
reopen()
fr = frames((nd / "log").read_bytes())
with open(nd / "log", "r+b") as h:
    h.truncate(fr[-1][0])
start()
data = decider.request_frame(g.HEAD, 0, n_last, g.ASOF, head_before, g.PIN, ec.fw.floors(head_before), g.KEYS, g.GRANT, ec.RELEASE, (), last)
why, recs, new, *_ = fw.read(data, p.eng[1].send(data))
assert why is None and new == head_after, f"resend: {why} head same {new == head_after}"
print("3 resent the cut batch: same head", flush=True)
assert p.batch(hover(300) + normal(200, built), "after cut frame"); built += 200; check("3 cut frame")

# 4 kill in the middle of a batch, the batch sent again to the reopened engine
def damage(kind):
    """Overwrite the last 40% of the records of both rows files in place (the length stays whole)."""
    for f in ("rows_rel", "rows_unr"):
        fp = nd / f
        n = fp.stat().st_size // 256
        cut = n - (n * 4) // 10
        if cut >= n:
            continue
        with open(fp, "r+b") as h:
            h.seek(cut * 256)
            h.write(b"\x00" * ((n - cut) * 256) if kind == "zero" else os.urandom((n - cut) * 256))


class Killer:
    def __init__(self, delay, kind=None):
        self.delay = delay
        self.kind = kind
    @property
    def p(self):
        return real.p
    def send(self, data):
        real.p.stdin.write(struct.pack(">I", len(data) + 1) + b"" + data)
        real.p.stdin.flush()
        time.sleep(self.delay)
        real.p.kill()
        real.p.wait()
        global real2
        if self.kind:
            damage(self.kind)
        real2 = fw.Engine(nd, EXE)
        return real2.send(data)
    def close(self):
        real2.close()
for d in [round(0.01 + 0.0125 * i, 4) for i in range(24)]:
    real = p.eng[1]
    p.eng[1] = Killer(d)
    assert p.batch(hover(300) + cold(700, built), "killed"); built += 700
    p.eng[1] = real2
    check(f"4 kill after {d}s")
assert p.batch(hover(100) + cold(400, built), "final"); built += 400; check("final")
print("CRASH_DONE outcomes", sorted(p.outcomes.items(), key=lambda kv: -kv[1])[:8])

# 5 whole-length rows files with hollow records, no marker: rebuilt from the log, same decisions as the old engine
for kind in ("zero", "garbage"):
    reopen()
    assert not (nd / "clean").exists() or (nd / "clean").read_bytes() == b"\x00"
    damage(kind)
    start()
    assert p.batch(hover(300) + normal(200, built), f"after {kind}"); built += 200; check(f"5 {kind} records")

# 6 killed in the middle of a batch, then the same damage
for kind, d in (("zero", 0.05), ("garbage", 0.11)):
    real = p.eng[1]
    p.eng[1] = Killer(d, kind)
    assert p.batch(hover(300) + cold(700, built), "killed+damaged"); built += 700
    p.eng[1] = real2
    check(f"6 kill after {d}s, {kind} records")

# 7 a clean stop writes the marker, a start clears it before any write
p.eng[1].close()
assert (nd / "clean").read_bytes() == b"\x01", "no clean-stop marker after a clean stop"
start()
assert p.batch(hover(100) + normal(100, built), "after clean stop"); built += 100; check("7 clean stop")
assert (nd / "clean").read_bytes() == b"\x00", "marker not cleared at start"
assert p.batch(hover(100) + normal(100, built), "final 2"); built += 100; check("final 2")
print("CRASH_DONE2", flush=True)
p.eng[1].close(); p.eng[0].close()
assert ec.checker(nd) == 0, "the checker did not verify the store after the crashes"
ec.drop_store(root, True)  # every check above is an assert: reaching here is a pass
