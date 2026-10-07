"""OS-B0 prototype (owner-scale-3 design sections 1, 2, 4, 8): one spine plus K item-shard SQLite stores, in the bench only.
The spine process judges (cell directory, routing by item hash, REV/PLB/RAW/zero on the spine), writes the directory, the spine rows and
the record R_n (each shard's input bytes, digests, heads), and is the only commit point; shard 0 runs inside the spine process, every other
shard in its own process. The shard build reuses the PERF-B Writer (mutate/finish). Lean is NOT modelled (no multi-command frame exists):
w is measured without it. Synthetic, non-PHI; moves no money. Results: JSON list, append-only.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import multiprocessing
import pickle
import shutil
import sqlite3
import statistics
import sys
import time
import zlib
from ctypes import wintypes
from operator import itemgetter
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools import r9_bench as rb  # noqa: E402

SCRATCH = Path("C:/Users/neers/rrb/state/scratch-osbench")
PAYER, SPINE = "bench-payer", -1
SPINE_DDL = """
CREATE TABLE IF NOT EXISTS cells (cell_id BLOB PRIMARY KEY, home INTEGER NOT NULL, item_id TEXT NOT NULL, state TEXT NOT NULL, gross INTEGER, raw_digest BLOB NOT NULL, origin_record INTEGER NOT NULL, origin_row INTEGER NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS records (n INTEGER PRIMARY KEY, file_index INTEGER NOT NULL, pool TEXT NOT NULL, t_f INTEGER NOT NULL, build_id BLOB NOT NULL, source_sha BLOB NOT NULL, j BLOB NOT NULL, parts BLOB NOT NULL, head BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS heads (k INTEGER PRIMARY KEY, head BLOB NOT NULL);
"""
SHARD_DDL = "CREATE TABLE IF NOT EXISTS applied (n INTEGER PRIMARY KEY, spine_id BLOB NOT NULL, rcore BLOB NOT NULL, i_digest BLOB NOT NULL);"
BUILD_ID = rb.sha("RR/SHARD/BUILD/v1", *(hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in (__file__, rb.__file__)))
SPINE_ID = rb.sha("RR/SHARD/SPINE/v1", PAYER)
T0_MS = 1_700_000_000_000


class ShardDiverged(Exception):
    """A shard head is not the spine's expected head: loud refusal, nothing written."""


def io_write_bytes() -> int:
    class Counters(ctypes.Structure):
        _fields_ = [(n, ctypes.c_ulonglong) for n in ("ro", "wo", "oo", "rb", "wb", "ob")]
    c = Counters()
    ctypes.windll.kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    ctypes.windll.kernel32.GetProcessIoCounters.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    ctypes.windll.kernel32.GetProcessIoCounters(ctypes.windll.kernel32.GetCurrentProcess(), ctypes.byref(c))
    return int(c.wb)


class Shard:
    """One item shard: an owner database plus the bench store. build() is steps 4a-4c (apply the part, digest, check); commit() is step 7."""

    def __init__(self, k: int, db: Path) -> None:
        self.k, self.db = k, db
        self.c, self.w = rb.open_store(db, True, True)
        self.c.executescript(SHARD_DDL)
        self.busy = self.check_s = self.commit_s = 0.0
        self.lines = 0
        self.undo = None

    def build(self, n: int, index: int, pool: str, t_f: int, blob: bytes, pre_head: bytes, verdict: bytes) -> tuple[bytes, bytes]:
        t0, w = time.perf_counter(), self.w
        if w.head != pre_head:
            raise ShardDiverged(f"shard {self.k}: head differs from the spine's expected head")
        parts = pickle.loads(blob)
        if hashlib.sha3_256(b"".join(p[1].encode() for p in parts)).digest() != verdict:
            raise ShardDiverged(f"shard {self.k}: verdicts differ from the record")
        seq0 = w.seq
        w.ckpt.before_begin()
        w.c.execute("BEGIN IMMEDIATE")
        try:
            t = {name: [] for name in ("cell_rows", "resolutions", "charges", "evidence", "payments", "financial_events", "commands")}
            touched: dict[str, int] = {}
            began = dict(w.revision)
            for rk, origin, tag, key, amount, raw, rawdig, ob, cid in parts:
                t["cell_rows"].append((rk, origin, tag, amount, raw, rawdig))
                t["resolutions"].append((rk, cid, None, amount, "INTAKE"))
                t["charges"].append((rk, rk, ob, amount))
                w.mutate(t, touched, index, t_f, ob, key, amount, "PAYMENT_RECEIVED")
            digest = hashlib.sha3_256()
            for name, data in t.items():
                digest.update(pickle.dumps(data, 5))
                w.write(name, data)
            w.finish(index, t_f, touched, began)
            digest.update(pickle.dumps(sorted(touched.items()), 5) + w.head)
            w.c.execute("INSERT INTO applied VALUES (?,?,?,?)", (n, SPINE_ID, rb.sha("RR/SHARD/RCORE/v1", n, index, pool, t_f), hashlib.sha3_256(blob).digest()))
            w.c.execute("UPDATE financial_meta SET sequence=?,history_head=?", (w.seq, w.head))
            c0 = time.perf_counter()
            self.check(index, parts, seq0, pre_head)
            self.check_s += time.perf_counter() - c0
        except BaseException:
            if w.c.in_transaction:
                w.c.execute("ROLLBACK")
            w.seq, w.head, w.revision = seq0, pre_head, began  # the part leaves no trace in memory either
            raise
        self.undo = (seq0, pre_head, began, len(parts))
        self.lines += len(parts)
        self.busy += time.perf_counter() - t0
        return w.head, digest.digest()

    def check(self, index: int, parts: list, seq0: int, pre_head: bytes) -> None:
        """Shard check: the chain recomputes link by link from the pre-head, and rows, charges and amounts equal the part."""
        w, previous = self.w, pre_head
        events = w.c.execute("SELECT * FROM financial_events WHERE event_sequence>? ORDER BY event_sequence", (seq0,)).fetchall()
        for e in events:
            if e[9] != previous or e[8] != rb.sha(e[7]) or e[10] != rb.sha(previous, e[8]):
                raise rb.FinancialIntegrityError("shard_chain")
            previous = e[10]
        count, cents = w.c.execute("SELECT COUNT(*),COALESCE(SUM(cents),0) FROM charges WHERE row_key BETWEEN ? AND ?", (index * rb.KEY, (index + 1) * rb.KEY - 1)).fetchone()
        if previous != w.head or len(events) != len(parts) or count != len(parts) or cents != sum(p[4] for p in parts):
            raise rb.FinancialIntegrityError("shard_check")

    def commit(self) -> None:
        c0 = time.perf_counter()
        self.w.c.execute("COMMIT")
        self.undo = None
        self.commit_s += time.perf_counter() - c0
        self.w.ckpt.kick()

    def abort(self) -> None:
        if self.c.in_transaction:
            self.c.execute("ROLLBACK")
        if self.undo:  # a built part that never committed: memory goes back with the database
            (self.w.seq, self.w.head, self.w.revision, built), self.undo = self.undo, None
            self.lines -= built

    def snapshot(self, path: Path) -> None:
        if self.c.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0]:
            raise rb.FinancialIntegrityError("snapshot_busy")
        shutil.copyfile(self.db, path)

    def stats(self) -> dict:
        self.w.ckpt.close()
        self.c.close()
        return {"k": self.k, "busy_s": self.busy, "check_s": self.check_s, "commit_s": self.commit_s, "lines": self.lines, "peak_rss": rb.peak_rss_bytes(), "io_write": io_write_bytes()}


def shard_main(conn, k: int, db: str) -> None:
    shard = Shard(k, Path(db))
    conn.send(("READY", shard.w.head))
    while True:
        message = conn.recv()
        try:
            if message[0] == "PART":
                conn.send(("BUILT", *shard.build(*message[1:])))
            elif message[0] == "COMMIT":
                shard.commit()
                conn.send(("ACK", shard.w.head))
            elif message[0] == "ABORT":
                shard.abort()
                conn.send(("ACK", shard.w.head))
            elif message[0] == "SNAPSHOT":
                shard.snapshot(Path(message[1]))
                conn.send(("ACK", shard.w.head))
            else:
                conn.send(("STATS", shard.stats()))
                return
        except BaseException as error:  # reported to the spine, which aborts everything
            shard.abort()
            conn.send(("ERR", repr(error)))


class Spine:
    """Spine process: judge, spine write, record R_n, spine check, COMMIT; shard 0 inline, shards 1..K-1 as processes."""

    def __init__(self, work: Path, k_count: int, template: Path) -> None:
        self.K, self.work = k_count, work
        shutil.rmtree(work, ignore_errors=True)
        work.mkdir(parents=True)
        db = work / "spine.sqlite3"
        self.c = sqlite3.connect(str(db), isolation_level=None)
        for pragma in ("journal_mode=WAL", "synchronous=FULL", "cache_size=-65536", "busy_timeout=5000", "wal_autocheckpoint=0"):
            self.c.execute(f"PRAGMA {pragma}")
        self.c.executescript(SPINE_DDL + rb.STORE_DDL)
        self.ckpt = rb.Checkpointer(db)
        self.c.execute("CREATE TEMP TABLE probe (k BLOB NOT NULL)")
        with sqlite3.connect(str(template)) as t:
            self.obl = {r[0]: r[1] for r in t.execute("SELECT obligation_id,item_id FROM obligations ORDER BY item_id")}
        self.obl_ids = list(self.obl)
        self.route = {item: int.from_bytes(rb.sha("RR/SHARD/v1", PAYER, item)[:8], "big") % k_count for item in self.obl.values()}
        self.shard0 = None
        self.workers: dict[int, tuple] = {}
        context = multiprocessing.get_context("spawn")
        for k in range(k_count):
            path = work / f"shard{k}.sqlite3"
            shutil.copyfile(template, path)
            if k == 0:
                self.shard0 = Shard(0, path)
            else:
                parent, child = context.Pipe()
                process = context.Process(target=shard_main, args=(child, k, str(path)), daemon=True)
                process.start()
                self.workers[k] = (process, parent)
        self.heads = {0: self.shard0.w.head}
        for k, (_, conn) in self.workers.items():
            self.heads[k] = self.expect(conn, "READY")[0]
        self.c.executemany("INSERT INTO heads VALUES (?,?)", sorted(self.heads.items()))
        self.n, self.prev_head, self.last_t_f = 0, bytes(64), 0
        self.owed: list[int] = []
        self.tt = {name: 0.0 for name in ("judge", "ipc", "shard0", "wait_built", "spine_write", "spine_commit", "shard0_commit", "ack_wait")}
        self.snapshot_at, self.snapshot_path = None, None

    @staticmethod
    def expect(conn, kind: str):
        message = conn.recv()
        if message[0] == "ERR":
            raise rb.FinancialIntegrityError(f"shard_refused:{message[1]}")
        if message[0] != kind:
            raise rb.FinancialIntegrityError(f"shard_protocol:{message[0]}")
        return message[1:]

    def wait_acks(self) -> None:
        """Step 2: every shard is past its last commit and its head equals heads(k), else a loud halt."""
        t0 = time.perf_counter()
        for k in self.owed:
            head = self.expect(self.workers[k][1], "ACK")[0]
            if head != self.heads[k]:
                raise ShardDiverged(f"shard {k}: head differs after commit")
        self.owed = []
        if self.shard0.w.head != self.heads[0]:
            raise ShardDiverged("shard 0: head differs")
        self.tt["ack_wait"] += time.perf_counter() - t0

    def judge(self, index: int, rows: list, pool: str, n: int):
        """Spine judge: cell directory dedup, routing by item hash, classification (the PERF-B Writer.chunk rules, no Lean)."""
        t0 = time.perf_counter()
        base, sp = index * rb.KEY, {name: [] for name in ("cell_rows", "holds", "links", "resolutions", "charges")}
        dirs, parts, pending, resolved, classes, prep = [], {}, {}, set(), {}, []
        for row_index, row in rows:
            tag, key = row.key[0], "/".join(row.key[1:])
            origin = f"{index}/{tag}/{key}"
            ref = row.key[4] if tag == "PLB" else row.key[1]
            ob = self.obl_ids[zlib.crc32(ref.encode()) % len(self.obl_ids)]
            prep.append((row_index, row, tag, key, origin, ref, ob, rb.sha("RR/CELL/CASH/v2", "bench-tenant", self.obl[ob], origin)))
        self.c.execute("DELETE FROM temp.probe")
        self.c.executemany("INSERT INTO temp.probe VALUES (?)", [(p[7],) for p in prep])
        known = {r[0] for r in self.c.execute("SELECT p.k FROM temp.probe p JOIN main.cells c ON c.cell_id=p.k")}
        seen: set[bytes] = set()
        for row_index, row, tag, key, origin, ref, ob, cid in prep:
            amount, rk = row.amount_cents, base + row_index
            if cid in seen or cid in known:
                classes["duplicate"] = classes.get("duplicate", 0) + 1
                continue
            seen.add(cid)
            rawdig, item = hashlib.sha3_256(row.raw.encode()).digest(), self.obl[ob]
            if amount == 0 or tag == "RAW" or amount is None or amount < 0:
                state = "ZERO" if amount == 0 else "HELD" if (tag == "RAW" or amount is None) else "NEGATIVE"
                sp["cell_rows"].append((rk, origin, tag, amount, row.raw, rawdig))
                dirs.append((cid, SPINE, item, state, amount, rawdig, n, rk))
                if state == "NEGATIVE":
                    target = f"{index}/CLP/{ref}"
                    sp["holds"].append((rk, cid, "TARGET"))
                    sp["links"].append((rk, cid, target, "EFFECTIVE" if target in resolved else "PENDING"))
                    pending.setdefault(target, []).append((origin, cid, rk, ob))
                classes[state] = classes.get(state, 0) + 1
            else:
                k = self.route[item]
                dirs.append((cid, k, item, "RESOLVED", amount, rawdig, n, rk))
                parts.setdefault(k, []).append((rk, origin, tag, key, amount, row.raw, rawdig, ob, cid))
                for _, negcid, negrk, negob in pending.pop(origin, ()):
                    sp["resolutions"].append((negrk, negcid, None, 0, "NET"))
                    sp["charges"].append((negrk, negrk, negob, 0))
                resolved.add(origin)
                classes["applied"] = classes.get("applied", 0) + 1
        j = hashlib.sha3_256(b"".join(d[0] for d in dirs)).digest()
        source = hashlib.sha256(b"".join(d[5] for d in dirs)).digest()
        self.tt["judge"] += time.perf_counter() - t0
        return sp, dirs, parts, j, source, classes

    def ingest(self, index: int, record, deposit: dict) -> dict:
        t0 = time.perf_counter()
        rows = sorted(enumerate(record.rows), key=lambda p: (0 if (p[1].amount_cents or 0) < 0 else 1, p[0]))
        self.tt["judge"] += time.perf_counter() - t0
        pool, n, t_f = f"x12/SYNTHPAYER/{record.trace_origin}/{record.trace}", self.n + 1, T0_MS + index
        if t_f < self.last_t_f:
            raise rb.FinancialIntegrityError("clock_regressed")
        self.ckpt.before_begin()
        self.c.execute("BEGIN IMMEDIATE")
        sent: list[int] = []
        try:
            sp, dirs, parts, j, source, classes = self.judge(index, rows, pool, n)
            self.wait_acks()  # judge(n+1) overlapped the shards' commits of n
            pre = dict(self.heads)
            t0 = time.perf_counter()
            blobs = {k: pickle.dumps(p, 5) for k, p in parts.items()}
            verdicts = {k: hashlib.sha3_256(b"".join(p[1].encode() for p in parts[k])).digest() for k in parts}
            for k in parts:
                if k:
                    self.workers[k][1].send(("PART", n, index, pool, t_f, blobs[k], pre[k], verdicts[k]))
                    sent.append(k)
            self.tt["ipc"] += time.perf_counter() - t0
            built: dict[int, tuple] = {}
            if 0 in parts:
                t0 = time.perf_counter()
                built[0] = self.shard0.build(n, index, pool, t_f, blobs[0], pre[0], verdicts[0])
                self.tt["shard0"] += time.perf_counter() - t0
            t0 = time.perf_counter()
            for k in sent:
                built[k] = self.expect(self.workers[k][1], "BUILT")
            self.tt["wait_built"] += time.perf_counter() - t0
            t0 = time.perf_counter()
            self.write_spine(index, pool, n, t_f, deposit, sp, dirs, j, source, pre, built, blobs, verdicts)
            self.tt["spine_write"] += time.perf_counter() - t0
        except BaseException:
            for k in sent:  # step 6: abort the shards that were asked (unread BUILT/ERR replies are drained), roll the spine back
                conn = self.workers[k][1]
                conn.send(("ABORT",))
                while conn.recv()[0] != "ACK":
                    pass
            self.shard0.abort()
            self.c.execute("ROLLBACK")
            raise
        t0 = time.perf_counter()
        self.c.execute("COMMIT")  # the only commit point
        self.ckpt.kick()
        self.tt["spine_commit"] += time.perf_counter() - t0
        self.n, self.last_t_f, self.prev_head = n, t_f, self.prev_head_next
        for k, (head, _) in built.items():
            self.heads[k] = head
        for k in sent:
            self.workers[k][1].send(("COMMIT",))
            self.owed.append(k)
        if 0 in built:
            t0 = time.perf_counter()
            self.shard0.commit()
            self.tt["shard0_commit"] += time.perf_counter() - t0
        return classes

    def write_spine(self, index, pool, n, t_f, deposit, sp, dirs, j, source, pre, built, blobs, verdicts) -> None:
        c, base = self.c, index * rb.KEY
        if c.execute("SELECT 1 FROM deposit_rows WHERE row_key=?", (base,)).fetchone() is None:  # a resent file keeps its deposit row
            c.execute("INSERT INTO deposit_rows VALUES (?,?,?,?)", (base, deposit["entry_id"], pool, deposit["amount_cents"]))
        added = c.executemany("INSERT INTO cells VALUES (?,?,?,?,?,?,?,?)", sorted(dirs, key=itemgetter(0))).rowcount
        for table, data in sp.items():
            if data:
                c.executemany(f"INSERT INTO {table} VALUES ({','.join('?' * len(data[0]))})", sorted(data, key=itemgetter(0)))
        body = pickle.dumps({k: (blobs[k], verdicts[k], pre[k], built[k][1], built[k][0]) for k in built}, 5)
        rd = rb.sha(n, index, pool, t_f, BUILD_ID, source, j, hashlib.sha3_256(body).digest())
        self.prev_head_next = head = rb.sha(self.prev_head, rd)
        c.execute("INSERT INTO records VALUES (?,?,?,?,?,?,?,?,?)", (n, index, pool, t_f, BUILD_ID, source, j, body, head))
        c.executemany("UPDATE heads SET head=? WHERE k=?", [(built[k][0], k) for k in built])
        # spine check: the record recomputes and chains; one directory row per new cell; heads moved only for touched shards
        stored = c.execute("SELECT n,file_index,pool,t_f,build_id,source_sha,j,parts,head FROM records WHERE n=?", (n,)).fetchone()
        again = rb.sha(stored[0], stored[1], stored[2], stored[3], stored[4], stored[5], stored[6], hashlib.sha3_256(stored[7]).digest())
        expected = {k: (built[k][0] if k in built else pre[k]) for k in pre}
        if rb.sha(self.prev_head, again) != stored[8] or added != len(dirs) or dict(c.execute("SELECT k,head FROM heads")) != expected or stored[4] != BUILD_ID:
            raise rb.FinancialIntegrityError("spine_check")

    def snapshot(self, k: int, path: Path) -> None:
        if k == 0:
            self.shard0.snapshot(path)
        else:
            self.workers[k][1].send(("SNAPSHOT", str(path)))
            self.expect(self.workers[k][1], "ACK")

    def close(self) -> list[dict]:
        self.wait_acks()
        stats = [self.shard0.stats()]
        for k, (process, conn) in self.workers.items():
            conn.send(("STOP",))
            stats.append(self.expect(conn, "STATS")[0])
            process.join()
        self.ckpt.close()
        self.c.close()
        return stats


def replay(spine_db: Path, snapshot: Path, k: int) -> dict:
    """Recovery (design section 4): shard k holds its pre-R_last state; replay R_last's recorded input bytes from the committed spine and require the same digests."""
    t0 = time.perf_counter()
    with sqlite3.connect(str(spine_db)) as s:
        n, index, pool, t_f, build_id, body = s.execute("SELECT n,file_index,pool,t_f,build_id,parts FROM records ORDER BY n DESC LIMIT 1").fetchone()
        heads = dict(s.execute("SELECT k,head FROM heads"))
    blob, verdict, pre, digest, post = pickle.loads(body)[k]
    shard = Shard(k, snapshot)
    pending = shard.w.head == pre and shard.w.head != heads[k]
    t1 = time.perf_counter()
    head, got = shard.build(n, index, pool, t_f, blob, pre, verdict)
    shard.commit()
    done = time.perf_counter()
    same = head == post == heads[k] and got == digest and build_id == BUILD_ID
    shard.stats()
    return {"k": k, "n": n, "lines": len(pickle.loads(blob)), "owed": pending, "identical": same, "replay_ms": (done - t0) * 1000, "replay_ms_excl_open": (done - t1) * 1000, "input_bytes": len(blob)}


def corpus(seed: int, lines: int, files: int) -> list[tuple[SimpleNamespace, dict]]:
    """Logical files of `lines` lines each: the 5,000-segment cap of the trunk parser refuses a 5,000-CLP 835, so each is two parsed 835s of lines/2 joined."""
    from app.x12_835_intake import parse_835
    out = []
    for m in range(files):
        halves = []
        for h in (2 * m, 2 * m + 1):
            data, deposit = rb.gen_file(h, seed, lines // 2)
            halves.append((parse_835(data), deposit))
        rows = halves[0][0].rows + halves[1][0].rows
        record = SimpleNamespace(rows=rows, trace_origin=halves[0][0].trace_origin, trace=halves[0][0].trace)
        out.append((record, {**halves[0][1], "amount_cents": halves[0][1]["amount_cents"] + halves[1][1]["amount_cents"]}))
    return out


def run_once(k_count: int, files: list, template: Path, work: Path, with_replay: bool = True) -> dict:
    spine = Spine(work, k_count, template)
    db_bytes = lambda: sum(p.stat().st_size for p in work.glob("*.sqlite3*"))  # noqa: E731
    size0, io0 = db_bytes(), io_write_bytes()
    lines, classes, kk, snap, snap_s = 0, {}, k_count - 1, work / "snapshot.sqlite3", 0.0
    t0 = time.perf_counter()
    for position, (record, deposit) in enumerate(files):
        if with_replay and position == len(files) - 1:
            s0 = time.perf_counter()
            spine.wait_acks()
            spine.snapshot(kk, snap)
            snap_s = time.perf_counter() - s0  # the replay setup is not throughput
        for name, value in spine.ingest(position, record, deposit).items():
            classes[name] = classes.get(name, 0) + value
        lines += len(record.rows)
    spine.wait_acks()
    wall = time.perf_counter() - t0 - snap_s
    grown, spine_io, spine_rss = db_bytes() - size0, io_write_bytes() - io0, rb.peak_rss_bytes()
    stats = spine.close()
    spine_row = {"k": "spine+shard0", "io_write": spine_io, "peak_rss": spine_rss}
    shard_stats = sorted(stats, key=lambda s: s["k"])
    busy = sum(s["busy_s"] for s in shard_stats)
    out = {"K": k_count, "lines": lines, "wall_s": wall, "lines_per_s": lines / wall, "classes": classes,
           "j_us": spine.tt["judge"] / lines * 1e6, "s_us": spine.tt["spine_write"] / lines * 1e6, "ipc_us": spine.tt["ipc"] / lines * 1e6,
           "w_us": busy / lines * 1e6, "shard_check_us": sum(s["check_s"] for s in shard_stats) / lines * 1e6,
           "shard_busy_s": [s["busy_s"] for s in shard_stats], "shard_lines": [s["lines"] for s in shard_stats], "imbalance": max(s["busy_s"] for s in shard_stats) / (busy / k_count),
           "phase_s": spine.tt, "commit_ms_per_file": [(spine.tt["spine_commit"] / len(files)) * 1000, sum(s["commit_s"] for s in shard_stats) / (k_count * len(files)) * 1000],
           "store_bytes_per_s": grown / wall, "io_write_bytes_per_s": (spine_io + sum(s["io_write"] for s in stats[1:])) / wall,
           "peak_rss_spine_mb": spine_rss / 2**20, "peak_rss_shards_mb": [s["peak_rss"] / 2**20 for s in stats[1:]],
           "peak_rss_total_mb": (spine_rss + sum(s["peak_rss"] for s in stats[1:])) / 2**20, "python_processes": k_count}
    if with_replay:
        out["replay"] = replay(work / "spine.sqlite3", snap, kk)
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--k", type=int, nargs="+", default=[1, 2, 3, 4, 6, 8])
    ap.add_argument("--corpus", nargs="+", default=["FL", "DE"])
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--lines", type=int, default=5000)
    ap.add_argument("--files", type=int, default=2)
    ap.add_argument("--suffix", default="")
    a = ap.parse_args(argv)
    SCRATCH.mkdir(parents=True, exist_ok=True)
    template = SCRATCH / "template.sqlite3"
    if not template.exists():
        rb.make_owner_db(template)
    seeds = {"FL": 20261006, "DE": 20261007}
    runs = []
    for name in a.corpus:
        files = corpus(seeds[name], a.lines, a.files)
        for k in a.k:
            for rep in range(a.reps + 1):  # the last rep also snapshots one shard and replays its last record; its setup time is cut from the wall
                r = {"suffix": a.suffix, "corpus": name, "rep": rep, **run_once(k, files, template, SCRATCH / f"run-{a.suffix}-{name}-{k}", rep == a.reps)}
                runs.append(r)
                print(f"{name} K={k} rep={rep} {r['lines_per_s']:,.0f} lines/s j={r['j_us']:.1f} s={r['s_us']:.1f} ipc={r['ipc_us']:.1f} w={r['w_us']:.1f} us rss={r['peak_rss_total_mb']:.0f} MB" + (f" replay={r['replay']['replay_ms']:.0f} ms ok={r['replay']['identical']}" if "replay" in r else ""), flush=True)
    previous = json.loads(a.out.read_text(encoding="utf-8")) if a.out.exists() else {"runs": []}
    previous["runs"].extend(runs)
    a.out.write_text(json.dumps(previous, indent=1, default=str), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
