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
  8 clean stop, then a link changed in one links file and, in the other, a rule of another set and a cut inside a record
    (each kept up to its first record the rows do not give or whose rule is not its set's, the rest from the answers)
  9 kill, a links answer field changed, then a first open that fails after the rows are rebuilt (test hook): the retry
    must not trust the links files
 10 fact frames (`RRDF`, new engine only): a crash after a frame's facts records are written and before its log append
    (the checker refuses the records the log does not hold; the reopened engine drops them); a frame cut in the middle of
    its log append (the resend answers the same bytes); a crash after the append and before the answer (each resend answers
    the same bytes).  The facts file is written without a sync and rebuilt at open: the checker derives it from the log.
After each, both links files must equal, byte for byte, the files the log's answers and the rows derive (the Python twin
of the links projection, app/right_rail_fact_store.py).
A clean stop followed by damage to whole records is not tested: with the marker present the engine trusts its rows files,
which is the threat model's limit (a disk fault behind a completed sync); only a stop without the marker is healed.
Then the checker (gate_verify3 on its own history) must verify the whole log."""
import os, struct, sys, time
from pathlib import Path
WT = sys.argv[1] if len(sys.argv) > 1 else str(Path(__file__).resolve().parents[1])
os.environ.setdefault("E3_SCRATCH", r"C:\Users\neers\AppData\Local\Temp\claude\s")
sys.path.insert(0, WT)
os.chdir(WT)
from app import right_rail_fact_store as fs  # noqa: E402
from app import right_rail_gate_decide as decider  # noqa: E402
from tests import _gate_shards as g  # noqa: E402
from tests import engine3_compare as ec  # noqa: E402
from tests import gate_bench as gb  # noqa: E402
from tests import gate_corpus  # noqa: E402
from tests import test_flat_worker as fw  # noqa: E402
from app import right_rail_fact_frame as ff  # noqa: E402
from tests import test_engine3_facts as tf  # noqa: E402
from tests import test_engine3_verify as v3  # noqa: E402
from tests.test_fact_codecs import pat  # noqa: E402
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


def links_check(label):
    """Both links files equal the files a rebuild derives: per set, its rows with the answer fields of the released (rule 1
    and 5) or unresolved (rule 2) records of each frame's answer, in record order, its batch and its authority day."""
    raw = (nd / "log").read_bytes()
    tails = ([], [])
    for j, (pos, _) in enumerate(frames(raw)):
        rq, an, _tr = struct.unpack("<III", raw[pos + 4:pos + 16])
        a = raw[pos + 16 + rq:pos + 16 + rq + an]
        assert int.from_bytes(a[11:19], "little") == j + 1, f"{label}: frame {j} answers batch {a[11:19].hex()}"
        if raw[pos + 16:pos + 20] == b"RRDF":  # a fact frame adds no rows
            continue
        nr = int.from_bytes(a[19:23], "little")
        au = 87 + 20 * nr + 128 + 16 + 64  # after the head, root, hold word and grant id
        day = int.from_bytes(a[au + 132:au + 136], "big")
        for i in range(nr):
            r = a[87 + 20 * i:87 + 20 * (i + 1)]
            if r[4] in (1, 2, 5):
                tails[r[4] == 2].append({"batch": j + 1, "windex": i, "reasons": int.from_bytes(r[5:13], "little"),
                                         "rule": r[4], "day": day})
    for rows_f, links_f, ts in (("rows_rel", "released.links", tails[0]), ("rows_unr", "unresolved.links", tails[1])):
        rb = (nd / rows_f).read_bytes()
        rows = [rb[i * 256:i * 256 + 245] for i in range(len(rb) // 256)]
        assert len(rows) == len(ts), f"{label}: {rows_f} holds {len(rows)} rows, the answers name {len(ts)}"
        got = (nd / links_f).read_bytes()
        assert got == fs.links_writer(list(zip(rows, ts)))[0], f"{label}: {links_f} ({len(got)} bytes) is not the rebuild"
    print(label, "links equal the rebuild:", len(tails[0]), "released,", len(tails[1]), "unresolved", flush=True)


def check(label):
    print(label, "mismatches so far", p.mismatch, "refused", p.refused, flush=True)
    assert p.mismatch == 0 and p.refused == 0, label
    links_check(label)


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

# 8 a clean stop, then the links files damaged; the load keeps each up to its first record the rows do not give
p.eng[1].close()
rl, ul = nd / "released.links", nd / "unresolved.links"
n_r = rl.stat().st_size // 32
assert n_r > 3, "no released rows to damage"
with open(rl, "r+b") as h:              # a byte of the member link of a record a third of the way in
    h.seek((n_r // 3) * 32 + 2)
    b = h.read(1)
    h.seek((n_r // 3) * 32 + 2)
    h.write(bytes([b[0] ^ 0x5A]))
n_u = ul.stat().st_size // 32
with open(ul, "r+b") as h:              # a released rule in an unresolved record a quarter of the way in, then a cut
    h.seek((n_u // 4) * 32 + 27)
    assert h.read(1) == b"\x02", "unresolved record without rule 2"
    h.seek((n_u // 4) * 32 + 27)
    h.write(b"\x01")
    h.truncate(n_u // 2 * 32 + 7)
start()
assert p.batch(hover(100) + normal(100, built), "after links damage"); built += 100; check("8 links damaged")

# 9 a kill, then an answer field of a links record changed (a field a trusted load does not compute again); the first
# open fails after it rebuilt the rows, and the retry in the same process must rebuild the links files too
head_before = p.head[1]
last = hover(100) + normal(100, built); built += 100
assert p.batch(last, "before failed open"); check("9 before failed open")
head_after, n_last = p.head[1], p.n
reopen()
assert (nd / "clean").read_bytes() == b"\x00", "marker set after a kill"
n_r = rl.stat().st_size // 32
with open(rl, "r+b") as h:              # the record index of a record half way in
    h.seek((n_r // 2) * 32 + 20)
    b = h.read(1)
    h.seek((n_r // 2) * 32 + 20)
    h.write(bytes([b[0] ^ 0x5A]))
p.eng[1] = fw.Engine(nd, EXE, {"RR_E3_CRASH": "open_before_links"})
data = decider.request_frame(g.HEAD, 0, n_last, g.ASOF, head_before, g.PIN, ec.fw.floors(head_before), g.KEYS, g.GRANT, ec.RELEASE, (), last)
why, *_ = fw.read(data, p.eng[1].send(data))
assert why is not None, "the open the hook fails answered"
print("9 first open refused:", why, flush=True)
why, recs, new, *_ = fw.read(data, p.eng[1].send(data))
assert why is None and new == head_after, f"retry: {why} head same {new == head_after}"
links_check("9 retry after a failed open")
assert p.batch(hover(100) + normal(100, built), "after failed open"); built += 100; check("9 after failed open")
print("CRASH_DONE2", flush=True)


# 10 fact frames, sent to the new engine alone (the old engine has none)
def fact(data, entries, prev, refs):
    """The new engine's answer to the fact frame `data`: the codec's encoding of `entries` and of `rs` over the reference
    entries `refs`, on a new head."""
    out = p.eng[1].send(data)
    a = ff.decode_answer(out)
    assert a["entries"] == entries, f"fact entries {a['entries']} != {entries}"
    assert out == ff.encode_answer({"shard": 0, "batch": int.from_bytes(data[10:18], "little"), "digest": data[18:82],
                                    "entries": entries, "head": a["head"], "root": a["root"], "rs": ff.ref_set(refs), "items": 0,
                                    "money": 0}), "fact answer is not the codec's"
    assert a["head"] != prev
    return out, a["head"]


def crashed(env, data):
    """The new engine with the test hook `env` dies (exit 99) on `data` without an answer."""
    p.eng[1].close()
    p.eng[1] = fw.Engine(nd, EXE, {"RR_E3_CRASH": env})
    assert p.eng[1].send(data) == b"" and p.eng[1].p.wait(timeout=60) == 99, f"{env}: the engine answered"


def facts_equal(bodies, label):
    got = (nd / "facts").read_bytes()
    assert got == fs.facts_writer(bodies)[0], f"{label}: facts file ({len(got)} bytes) is not the {len(bodies)} records"
    print(label, "facts equal the log's", len(bodies), "records", flush=True)


n0, h0 = p.n, p.head[1]
assert (nd / "facts").read_bytes() == b""
# a crash after the facts records and before the log append: the file holds records the log does not, a note only
# (the engine writes the file again from the log at its next open)
x = tf.fact_request(n0 + 1, h0, tf.A, [tf.R0, tf.R1, tf.R2])
crashed("before_append", x)
assert (nd / "facts").stat().st_size == 4 * 256, "the crashed frame wrote no facts records"
rc, out = v3.verify(nd)
assert rc == 0 and "VERIFIED" in out and "FACTS_STALE(0) facts file holds 1024 bytes past the 0 records of the log" in out, out
print("10 checker notes the unlogged records:", next(x for x in out.splitlines() if "FACTS_STALE" in x)[:120], flush=True)
start()
# the reopened engine rebuilds the file from the log; another frame on the same batch is decided on it alone
ry = tf.receipt(file=pat(64, 41))
refs = [ff.ref_entry(ry, [tf.R2])]
_, h1 = fact(tf.fact_request(n0 + 1, h0, ry, [tf.R2]), [(1, 0, 1)], h0, refs)
bodies = [tf.receipt_body(ry, n0 + 1, 1, 0, [tf.R2]), tf.row_body(tf.R2, tf.OPEN, 0)]
facts_equal(bodies, "10 before_append")
# a frame cut in the middle of its log append: the resend answers the same bytes
rz = tf.receipt(file=pat(64, 42), fseq=tf.A["fseq"] + 100)
z = tf.fact_request(n0 + 2, h1, rz, [tf.R0, tf.R2])
refs.append(ff.ref_entry(rz, [tf.R2]))
az, h2 = fact(z, [(1, 0, 3), (2, 0, 1)], h1, refs)  # R2 restated by a newer full file: a lift, not a row
reopen()
fr = frames((nd / "log").read_bytes())
with open(nd / "log", "r+b") as h:
    h.truncate((fr[-1][0] + fr[-1][1]) // 2)
start()
assert p.eng[1].send(z) == az, "the resend of a cut fact frame answered other bytes"
bodies += [tf.receipt_body(rz, n0 + 2, 1, 1, [tf.R0, tf.R2]), tf.row_body(tf.R0, tf.OPEN, 2), fs.encode_lift(2, [(1, tf.R2["roff"])])]
facts_equal(bodies, "10 cut frame")
# a crash after the append and before the answer: each resend answers the same bytes
rw = tf.receipt(file=pat(64, 43), fseq=tf.A["fseq"] + 200)
w = tf.fact_request(n0 + 3, h2, rw, [tf.R1])
crashed("after_append", w)
start()
aw, h3 = fact(w, [(1, 0, 6)], h2, refs)  # no reference row: rs stays
reopen()
start()
assert p.eng[1].send(w) == aw, "a second resend answered other bytes"
bodies += [tf.receipt_body(rw, n0 + 3, 1, 0), tf.row_body(tf.R1, tf.OPEN, 5)]
facts_equal(bodies, "10 after_append")
links_check("10 fact frames")
p.eng[1].close(); p.eng[0].close()
assert ec.checker(nd) == 0, "the checker did not verify the store after the crashes"
ec.drop_store(root, True)  # every check above is an assert: reaching here is a pass
