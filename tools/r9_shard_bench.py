"""OS-B0 prototype (owner-scale-3 design sections 1, 2, 4, 8): one spine plus K item-shard SQLite stores, in the bench only.
A prep stage (its own process, where the product's parser runs) does the per-row pure work: keys, cell ids, raw digests, classification, routing by item
hash and each shard's input bytes. The spine process checks the file's cell ids against its in-memory directory keys (equal to the cells table at every
commit), writes the directory, the spine rows and the record R_n (each shard's input bytes, digests, heads), and is the only commit point; every shard
is its own process. The shard build reuses the PERF-B Writer (mutations/finish). Lean is NOT modelled (no multi-command frame exists):
w is measured without it. Synthetic, non-PHI; moves no money. Results: JSON list, append-only.
"""

from __future__ import annotations

import argparse
import collections
import ctypes
import hashlib
import json
import multiprocessing
import os
import pickle
import queue
import shutil
import sqlite3
import statistics
import struct
import sys
import threading
import time
import zlib
from ctypes import wintypes
from multiprocessing import connection
from multiprocessing.reduction import ForkingPickler
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
GROWING = ("payments", "evidence", "evaluations", "commands")  # owner tables that only grow; check() counts the rows a part adds by the move of MAX(rowid)
BUILD_ID = rb.sha("RR/SHARD/BUILD/v1", *(hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in (__file__, rb.__file__)))
SPINE_ID = rb.sha("RR/SHARD/SPINE/v1", PAYER)
T0_MS = 1_700_000_000_000


class ShardDiverged(Exception):
    """A shard head is not the spine's expected head: loud refusal, nothing written."""


class GroupCommitFailed(Exception):
    """A failure once the spine's COMMIT has started: every shard is dead and the run ends, never retried (the shards replay the group from the spine's records, or never had it)."""


def io_write_bytes() -> int:
    class Counters(ctypes.Structure):
        _fields_ = [(n, ctypes.c_ulonglong) for n in ("ro", "wo", "oo", "rb", "wb", "ob")]
    c = Counters()
    ctypes.windll.kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    ctypes.windll.kernel32.GetProcessIoCounters.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    ctypes.windll.kernel32.GetProcessIoCounters(ctypes.windll.kernel32.GetCurrentProcess(), ctypes.byref(c))
    return int(c.wb)


def system_cpu() -> tuple[int, int]:
    """(busy, total) CPU time of the whole machine in 100 ns ticks; the difference of two samples is the machine load over that time (other processes included)."""
    idle, kernel, user = (wintypes.FILETIME() for _ in range(3))
    ctypes.windll.kernel32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kernel), ctypes.byref(user))
    t = lambda f: (f.dwHighDateTime << 32) | f.dwLowDateTime  # noqa: E731
    return t(kernel) + t(user) - t(idle), t(kernel) + t(user)


def load_pct(a: tuple[int, int], b: tuple[int, int]) -> float:
    return 100.0 * (b[0] - a[0]) / max(1, b[1] - a[1])


def prewrite_mode() -> int:
    """0 off; 1 flush + fsync of the WAL after each built part; 2 the same flush without the fsync; 3 flush only, once per group per database (the shard on the spine's PREFLUSH, the spine at its first wait)."""
    mode = os.environ.get("RR_SHARD_PREWRITE", "0")  # read at call time: spawned workers inherit the environment
    return int(mode) if mode in ("1", "2", "3") else 0


def sender_on() -> bool:
    """I1 and I3, the default (lead 2026-10-07): only a sender thread keeps a silent shard from blocking the spine in a write (a Windows pipe write has no deadline once the pipe is full).
    RR_SHARD_SENDER=0 is the earlier path, every message pickled and written by the spine's own thread: no write deadline, test and bench only."""
    mode = os.environ.get("RR_SHARD_SENDER", "1")
    if mode not in ("0", "1"):  # "", "true", "1 " must not quietly pick the path with no write deadline
        raise ValueError(f"RR_SHARD_SENDER must be 0 or 1, not {mode!r}")
    return mode == "1"


PART_HEAD = struct.Struct("<4sqqqHHHq")  # b"PART", n, index, t_f, then the lengths of pool, pre_head, verdict and blob; the bytes of those four follow, and nothing else


def encode(message: tuple) -> bytes:
    """One spine -> shard message as bytes. PART is a fixed header with the blob copied in once (the blob is already a pickle; Connection.send would pickle it a second time); the rest are pickled."""
    if message[0] != "PART":
        return ForkingPickler.dumps(message)
    _, n, index, pool, t_f, blob, pre, verdict = message
    name = pool.encode()
    return b"".join((PART_HEAD.pack(b"PART", n, index, t_f, len(name), len(pre), len(verdict), len(blob)), name, pre, verdict, blob))


def decode(buf: bytes) -> tuple:
    """The inverse of encode (a pickle starts with 0x80, never with PART): the same tuple the shard got from Connection.recv before."""
    if buf[:4] != b"PART":
        return ForkingPickler.loads(buf)
    _, n, index, t_f, a, b, c, d = PART_HEAD.unpack_from(buf)
    o = PART_HEAD.size
    if min(a, b, c, d) < 0 or len(buf) != o + a + b + c + d:
        raise ValueError("part message length")  # short, long or shifted: never built
    return ("PART", n, index, buf[o:o + a].decode(), t_f, buf[o + a + b + c:], buf[o + a:o + a + b], buf[o + a + b:o + a + b + c])


class Prewriter:
    """G1: while a transaction is open and the process would otherwise wait, push its dirty pages into the WAL and fsync the WAL, so the COMMIT writes and syncs
    only what changed since. sqlite3_db_cacheflush appends uncommitted frames, which recovery ignores (they carry no commit marker): stored bytes and formats are unchanged."""

    def __init__(self, conn: sqlite3.Connection, db: Path, fsync: bool = True) -> None:
        self.fsync = fsync
        self.lib = ctypes.CDLL(os.path.join(sys.base_prefix, "DLLs", "sqlite3.dll"))
        self.lib.sqlite3_db_cacheflush.argtypes = [ctypes.c_void_p]
        self.lib.sqlite3_db_filename.argtypes, self.lib.sqlite3_db_filename.restype = [ctypes.c_void_p, ctypes.c_char_p], ctypes.c_char_p
        self.handle = ctypes.c_void_p.from_address(id(conn) + 16).value  # pysqlite_Connection: PyObject_HEAD, then sqlite3 *db (CPython 3.11); verified below
        name = self.lib.sqlite3_db_filename(self.handle, b"main") if self.handle else None
        if name is None or os.path.normcase(os.path.abspath(name.decode())) != os.path.normcase(os.path.abspath(db)):
            raise RuntimeError("prewrite: the connection handle does not name the database")
        self.wal, self.count, self.flush_s, self.fsync_s = str(db) + "-wal", 0, 0.0, 0.0

    def flush(self) -> None:
        t0 = time.perf_counter()
        rc = self.lib.sqlite3_db_cacheflush(self.handle)
        t1 = time.perf_counter()
        if rc:
            raise RuntimeError(f"prewrite: sqlite3_db_cacheflush returned {rc}")
        if self.fsync:
            fd = os.open(self.wal, os.O_RDWR | os.O_BINARY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        self.count, self.flush_s, self.fsync_s = self.count + 1, self.flush_s + t1 - t0, self.fsync_s + (time.perf_counter() - t1 if self.fsync else 0.0)

    def stats(self) -> dict:
        return {"count": self.count, "flush_s": self.flush_s, "fsync_s": self.fsync_s}


def pre_stats(p: Prewriter | None) -> dict:
    return p.stats() if p else {"count": 0, "flush_s": 0.0, "fsync_s": 0.0}


class Shard:
    """One item shard: an owner database plus the bench store. build() is steps 4a-4c (apply the part, digest, check); commit() is step 7."""

    def __init__(self, k: int, db: Path) -> None:
        self.k, self.db = k, db
        self.c, self.w = rb.open_store(db, True, True)
        self.c.executescript(SHARD_DDL)
        self.applied_count, self.last_applied_n = self.c.execute("SELECT COUNT(*),COALESCE(MAX(n),0) FROM applied").fetchone()  # seeded once, as the database is when the shard opens; build keeps them, a refused part or an abort puts them back
        self.busy = self.check_s = self.commit_s = self.idle_s = 0.0
        self.commit_log: list[tuple[float, int]] = []  # per group: COMMIT ms and bytes the process wrote during it (the checkpointer thread's writes are in it too)
        self.lines = 0
        self.undo = None
        self.pre, self.pre_mark = None, 0  # G1 prewriter (set by shard_main when on); lines of the open transaction already pushed to the WAL

    def prewrite(self, conn, group_end: bool = False) -> None:
        """Modes 1 and 2, after BUILT is sent with nothing queued for this worker, or mode 3 on the spine's PREFLUSH (group_end): push the open transaction's new pages to the WAL."""
        if self.pre and self.undo and self.undo[3] > self.pre_mark and (group_end or not conn.poll(0)):
            self.pre.flush()
            self.pre_mark = self.undo[3]

    def build(self, n: int, index: int, pool: str, t_f: int, blob: bytes, pre_head: bytes, verdict: bytes) -> tuple[bytes, bytes]:
        t0, w = time.perf_counter(), self.w
        if w.head != pre_head:
            raise ShardDiverged(f"shard {self.k}: head differs from the spine's expected head")
        parts = pickle.loads(blob)
        if verdict_of(parts) != verdict:
            raise ShardDiverged(f"shard {self.k}: verdicts differ from the record")
        seq0, began, count0, last0 = w.seq, dict(w.revision), self.applied_count, self.last_applied_n
        if not w.c.in_transaction:  # the first part of a group opens the shard's one transaction; the group is only a commit boundary
            w.ckpt.before_begin()
            w.c.execute("BEGIN IMMEDIATE")
            self.undo, self.pre_mark = [seq0, pre_head, began, 0, count0, last0], 0
        w.c.execute("SAVEPOINT part")  # a refused part leaves no trace, the parts before it in the group stay until the spine aborts the group
        try:
            self.timed(self.amounts, parts)
            t = {"cell_rows": [(rk, origin, tag, amount, raw, rawdig) for rk, origin, tag, _, amount, raw, rawdig, _, _ in parts],
                 "resolutions": [(rk, cid, None, amount, "INTAKE") for rk, _, _, _, amount, _, _, _, cid in parts],
                 "charges": [(rk, rk, ob, amount) for rk, _, _, _, amount, _, _, ob, _ in parts],
                 "evidence": [], "payments": [], "financial_events": [], "commands": []}
            touched: dict[str, int] = {}
            w.mutations(t, touched, index, t_f, [(ob, key, amount, "PAYMENT_RECEIVED") for _, _, _, key, amount, _, _, ob, _ in parts])
            if parts and w.head == pre_head:  # a part that adds events must move the head (ShardSplit.lean `adv`): a closed chain is refused before anything is written
                raise rb.FinancialIntegrityError("shard_fixed_point")
            self.timed(self.chain, parts, seq0, pre_head, t_f, began, t["financial_events"])  # a wrong build is refused before any write
            before = self.timed(self.state, parts)
            digest = hashlib.sha3_256()
            for name, data in t.items():
                digest.update(pickle.dumps(data, 5))
                w.write(name, data)
            w.finish(index, t_f, touched, began)
            digest.update(pickle.dumps(sorted(touched.items()), 5) + w.head)
            self.seen = hashlib.sha3_256(blob).digest()  # what the shard was sent: BUILT returns it and the spine checks it against its own copy
            w.c.execute("INSERT INTO applied VALUES (?,?,?,?)", (n, SPINE_ID, rb.sha("RR/SHARD/RCORE/v1", n, index, pool, t_f), self.seen))
            self.applied_count, self.last_applied_n = count0 + 1, n
            w.c.execute("UPDATE financial_meta SET sequence=?,history_head=?", (w.seq, w.head))
            self.timed(self.check, index, parts, seq0, t_f, t["financial_events"], before)
        except BaseException:
            if w.c.in_transaction:
                w.c.execute("ROLLBACK TO part")
                w.c.execute("RELEASE part")
                if not self.undo[3]:  # nothing of the group is built: leave no open transaction
                    w.c.execute("ROLLBACK")
                    self.undo = None
            w.seq, w.head, w.revision = seq0, pre_head, began  # the part leaves no trace in memory either
            self.applied_count, self.last_applied_n = count0, last0
            raise
        w.c.execute("RELEASE part")
        self.undo[3] += len(parts)
        self.lines += len(parts)
        self.busy += time.perf_counter() - t0
        return w.head, digest.digest()

    def timed(self, fn, *args):
        """Everything that checks, hashes it recomputes included, is shard_check_us: amounts, chain, state and check run through here."""
        c0 = time.perf_counter()
        try:
            return fn(*args)
        finally:
            self.check_s += time.perf_counter() - c0

    @staticmethod
    def amounts(parts: list) -> None:
        """Cents are an int, never a bool, never negative (zero is real data: a denied or zero-pay line). Anything else is refused by name before the builder meets
        it: text would be a raw TypeError there, a float or a negative would be written as it stands."""
        if any(type(p[4]) is not int or p[4] < 0 for p in parts):
            raise rb.FinancialIntegrityError("shard_amount")

    def chain(self, parts: list, seq0: int, pre_head: bytes, t_f: int, began: dict, built: list) -> None:
        """Before anything is written: every event mutations built is recomputed from the part and the pre-state alone and compared field by field, in order (the
        product checker's rule, independent.py _verify_events, so a builder that is wrong but self-consistent is refused): sequence seq0+i+1 without a gap, id,
        aggregate, kind, revisions from the obligation's pre-revision, payload text, payload digest, link from the pre-head, head and time."""
        previous, revision = pre_head, dict(began)
        if len(built) != len(parts) or self.w.seq != seq0 + len(parts):
            raise rb.FinancialIntegrityError("shard_chain")
        for i, (e, p) in enumerate(zip(built, parts)):
            ob, key = p[7], p[3]
            before, revision[ob] = revision[ob], revision[ob] + 1
            payload = f'{{"kind":"PAYMENT_RECEIVED","obligation":"{ob}","before":{before},"after":{before + 1},"ref":"{key}"}}'
            if (e[0] != seq0 + i + 1 or e[1] != rb.sha("event", e[0]) or e[2:8] != ("OBLIGATION", ob, "PAYMENT_RECEIVED", before, before + 1, payload)
                    or e[8] != rb.sha(payload) or e[9] != previous or e[10] != rb.sha(previous, e[8]) or e[11] != t_f):
                raise rb.FinancialIntegrityError("shard_chain")
            previous = e[10]
        if previous != self.w.head:
            raise rb.FinancialIntegrityError("shard_chain")

    def stored(self, select: str, ids: list) -> list:
        """The rows `select` (ending in `WHERE <key column>`) finds for these keys, 500 keys to a statement."""
        out = []
        for i in range(0, len(ids), 500):
            chunk = ids[i:i + 500]
            out += self.w.c.execute(f"{select} IN ({','.join('?' * len(chunk))})", chunk).fetchall()
        return out

    def state(self, parts: list) -> tuple:
        """Before the writes: the part's obligations' (cash, revision), all obligations' cash, and where each growing owner table ends. These tables only grow (their
        triggers refuse update and delete), so MAX(rowid), which is O(1), moves by the rows the writes added."""
        c = self.w.c
        rows = self.stored("SELECT obligation_id,received_cash_cents,revision FROM obligations WHERE obligation_id", sorted({p[7] for p in parts}))
        return ({r[0]: r[1:] for r in rows}, c.execute("SELECT SUM(received_cash_cents) FROM obligations").fetchone()[0],
                [c.execute(f"SELECT COALESCE(MAX(rowid),0) FROM {table}").fetchone()[0] for table in GROWING])

    def check(self, index: int, parts: list, seq0: int, t_f: int, built: list, before: tuple) -> None:
        """Shard check after the writes (amounts and chain have already refused a wrong part or build). All of it is recomputed from the part and the state before it (`before`,
        from state()), never from the builder's rows: the stored events equal the built ones; the part's cell_rows, resolutions and charges equal it row for row; and the owner
        tables hold exactly what the part makes and nothing else: commands (id, kind, canonical request text, its digest, sequence), payments and evidence (every column, digests
        too), one evaluation per touched obligation (id, revision, time, digests), each touched obligation's cash, revision and current evaluation, and in total the cash moved by
        the part's cents while payments, evidence, evaluations and commands each grew by exactly their rows (the product checker's rule: the named rows, no other obligation moved)."""
        c, obl = self.w.c, self.w.obl
        cash0, total0, rowid0 = before
        if c.execute("SELECT * FROM financial_events WHERE event_sequence>? ORDER BY event_sequence", (seq0,)).fetchall() != built:
            raise rb.FinancialIntegrityError("shard_chain")
        rng = (index * rb.KEY, (index + 1) * rb.KEY - 1)

        def rows(table, cols):
            return sorted(c.execute(f"SELECT {cols} FROM {table} WHERE row_key BETWEEN ? AND ?", rng))
        if (rows("cell_rows", "row_key,origin_id,tag,amount_cents,raw,line_digest") != sorted((p[0], p[1], p[2], p[4], p[5], p[6]) for p in parts)
                or rows("resolutions", "row_key,cell_id,act,cents,basis") != sorted((p[0], p[8], None, p[4], "INTAKE") for p in parts)
                or rows("charges", "row_key,resolution_key,obligation_id,cents") != sorted((p[0], p[0], p[7], p[4]) for p in parts)):
            raise rb.FinancialIntegrityError("shard_check")
        cents, lines = {}, collections.Counter(p[7] for p in parts)
        for p in parts:
            cents[p[7]] = cents.get(p[7], 0) + p[4]
        pay, ev = f"pay:{index:06d}:", f"ev:{index:06d}:"
        eid = {ob: f"eval:{index:06d}:{ob}:{cash0[ob][1] + n}" for ob, n in lines.items()}
        payments = sorted((pay + p[3], p[7], obl[p[7]], ev + p[3], f"x12/{p[3]}", p[4] or 1, t_f, 1, None) for p in parts)  # a zero-cent line is a payment of one cent (the owner takes no zero payment), its evidence and the obligation's cash keep zero
        evidence = sorted((ev + p[3], obl[p[7]], "PAYMENT", f"x12/{p[3]}", "x12", "v1", "", t_f, t_f, t_f, rb.sha(ev + p[3], 1), rb.sha(ev + p[3], 2), p[4], None, None) for p in parts)
        evaluations = sorted((eid[ob], ob, cash0[ob][1] + n, t_f, rb.sha(eid[ob], 1), rb.sha(eid[ob], 2), rb.sha(eid[ob], 3)) for ob, n in lines.items())
        obligations = sorted((ob, cash0[ob][0] + cents[ob], cash0[ob][1] + n, eid[ob]) for ob, n in lines.items())
        commands = []
        for i, p in enumerate(parts):  # the owner's canonical request (keys sorted, ascii, compact) and its domain digest, by json.dumps rather than the builder's text
            request = json.dumps({"command": "PAYMENT", "key": pay + p[3], "amount_cents": p[4], "common_origin_id": f"x12/{p[3]}", "event_at_ms": t_f, "evidence_id": ev + p[3],
                                  "item_id": obl[p[7]], "local_ref": "", "source_id": "x12", "source_version": "v1"}, sort_keys=True, separators=(",", ":")).encode("ascii")
            commands.append((f"PAYMENT:{pay}{p[3]}", "PAYMENT", request.decode("ascii"), hashlib.sha3_512(b"RR/FINANCIAL/COMMAND/v1\x00" + request).digest(), seq0 + i + 1))
        grown = [r + d for r, d in zip(rowid0, (len(parts), len(parts), len(lines), len(parts)))]
        if (sorted(self.stored("SELECT command_id,kind,request_json,request_digest,event_sequence FROM commands WHERE command_id", [r[0] for r in commands])) != sorted(commands)
                or sorted(self.stored("SELECT * FROM payments WHERE payment_id", [r[0] for r in payments])) != payments
                or sorted(self.stored("SELECT * FROM evidence WHERE evidence_id", [r[0] for r in evidence])) != evidence
                or sorted(self.stored("SELECT evaluation_id,obligation_id,revision,evaluated_at_ms,result_digest,input_snapshot_digest,receipt_digest FROM evaluations WHERE evaluation_id",
                                      list(eid.values()))) != evaluations
                or sorted(self.stored("SELECT obligation_id,received_cash_cents,revision,current_evaluation_id FROM obligations WHERE obligation_id", list(lines))) != obligations
                or c.execute("SELECT SUM(received_cash_cents) FROM obligations").fetchone()[0] != total0 + sum(cents.values())
                or [c.execute(f"SELECT COALESCE(MAX(rowid),0) FROM {table}").fetchone()[0] for table in GROWING] != grown):
            raise rb.FinancialIntegrityError("shard_money")

    def commit(self) -> None:
        c0, b0 = time.perf_counter(), io_write_bytes()
        self.w.c.execute("COMMIT")
        self.undo = None
        self.commit_s += time.perf_counter() - c0
        self.commit_log.append(((time.perf_counter() - c0) * 1000, io_write_bytes() - b0))
        self.w.ckpt.kick()

    def abort(self) -> None:
        if self.c.in_transaction:
            self.c.execute("ROLLBACK")
        if self.undo:  # the parts of a group that never committed: memory goes back with the database
            (self.w.seq, self.w.head, self.w.revision, built, self.applied_count, self.last_applied_n), self.undo = self.undo, None
            self.lines -= built

    def snapshot(self, path: Path) -> None:
        for _ in range(100):  # the checkpointer thread may hold the checkpoint lock for a moment
            if not self.c.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0]:
                break
            time.sleep(0.02)
        else:
            raise rb.FinancialIntegrityError("snapshot_busy")
        shutil.copyfile(self.db, path)

    def stats(self) -> dict:
        self.w.ckpt.close()
        self.c.close()
        return {"k": self.k, "busy_s": self.busy, "check_s": self.check_s, "commit_s": self.commit_s, "idle_s": self.idle_s, "commit_log": self.commit_log, "cpu_s": time.process_time(),
                "lines": self.lines, "peak_rss": rb.peak_rss_bytes(), "io_write": io_write_bytes(), "prewrite": pre_stats(self.pre)}


def shard_main(conn, k: int, db: str) -> None:
    try:
        shard = Shard(k, Path(db))
        mode = prewrite_mode()
        shard.pre = Prewriter(shard.c, Path(db), mode == 1) if mode else None
    except BaseException as error:  # a shard that cannot open its database says so, or the spine would wait for its READY
        conn.send(("ERR", repr(error)))
        return
    conn.send(("READY", shard.w.head))
    while True:
        i0 = time.perf_counter()
        raw = conn.recv_bytes()
        shard.idle_s += time.perf_counter() - i0
        try:
            message = decode(raw)
            if message[0] == "PART":
                conn.send(("BUILT", *shard.build(*message[1:]), shard.seen, shard.applied_count, shard.last_applied_n))
                if mode != 3:
                    shard.prewrite(conn)
            elif message[0] == "PREFLUSH":  # mode 3: every part of the group is built and the spine is committing; no reply
                if mode == 3:
                    shard.prewrite(conn, True)
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


Prepared = collections.namedtuple("Prepared", "index n sp dirs j source classes blobs verdicts")


def tables(template: Path, k_count: int) -> SimpleNamespace:
    with sqlite3.connect(str(template)) as t:
        obl = {r[0]: r[1] for r in t.execute("SELECT obligation_id,item_id FROM obligations ORDER BY item_id")}
    return SimpleNamespace(obl=obl, obl_ids=list(obl), route={item: int.from_bytes(rb.sha("RR/SHARD/v1", PAYER, item)[:8], "big") % k_count for item in obl.values()})


def verdict_of(part: list) -> bytes:
    return hashlib.sha3_256(b"".join(p[1].encode() for p in part)).digest()


def judge_rows(tbl: SimpleNamespace, index: int, rows: list, n: int, known) -> tuple:
    """The judge of one file: dedup against `known` (a container of cell ids) and itself, routing by item hash, classification (the PERF-B Writer.chunk rules, no Lean)."""
    base, sp = index * rb.KEY, {name: [] for name in ("cell_rows", "holds", "links", "resolutions", "charges")}
    dirs, parts, pending, resolved, classes = [], {}, {}, set(), {}
    obl, obl_ids, route, sha512, sha256 = tbl.obl, tbl.obl_ids, tbl.route, hashlib.sha3_512, hashlib.sha3_256
    seen: dict[bytes, bytes] = {}  # cell id -> raw digest, for the cells this file creates
    for row_index, row in rows:
        tag, key = row.key[0], "/".join(row.key[1:])
        origin = f"{index}/{tag}/{key}"
        ref = row.key[4] if tag == "PLB" else row.key[1]
        ob = obl_ids[zlib.crc32(ref.encode()) % len(obl_ids)]
        item = obl[ob]
        cid = sha512(f"RR/CELL/CASH/v2\x1fbench-tenant\x1f{item}\x1f{origin}".encode()).digest()  # = rb.sha("RR/CELL/CASH/v2", "bench-tenant", item, origin)
        amount, rk = row.amount_cents, base + row_index
        rawdig = sha256(row.raw.encode()).digest()
        held = seen.get(cid) or known.get(cid)  # owner-scale-3 design 1 (line 10) and 3 (line 37): a known cell with the same raw is a DUPLICATE, with other raw a CONFLICT; neither writes
        if held is not None:
            cls = "duplicate" if held == rawdig else "conflict"
            classes[cls] = classes.get(cls, 0) + 1
            continue
        seen[cid] = rawdig
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
            k = route[item]
            dirs.append((cid, k, item, "RESOLVED", amount, rawdig, n, rk))
            parts.setdefault(k, []).append((rk, origin, tag, key, amount, row.raw, rawdig, ob, cid))
            for _, negcid, negrk, negob in pending.pop(origin, ()):
                sp["resolutions"].append((negrk, negcid, None, 0, "NET"))
                sp["charges"].append((negrk, negrk, negob, 0))
            resolved.add(origin)
            classes["applied"] = classes.get("applied", 0) + 1
    j = hashlib.sha3_256(b"".join(d[0] for d in dirs)).digest()
    source = hashlib.sha256(b"".join(d[5] for d in dirs)).digest()
    return sp, dirs, parts, j, source, classes


def prepare(tbl: SimpleNamespace, index: int, rows: list, n: int, known: dict | None = None) -> Prepared:
    """Everything about one file that does not depend on the shards' state: the judge (sorted: negatives first, then file order), the insert order of the
    spine rows, and each shard's input bytes with their verdict digest. The prep stage runs it against nothing; the spine runs it against the directory
    only when the file meets a cell it already holds."""
    ordered = sorted(enumerate(rows), key=lambda p: (0 if (p[1].amount_cents or 0) < 0 else 1, p[0]))
    sp, dirs, parts, j, source, classes = judge_rows(tbl, index, ordered, n, known or {})
    return Prepared(index, n, {t: sorted(d, key=itemgetter(0)) for t, d in sp.items()}, sorted(dirs, key=itemgetter(0)), j, source, classes,
                    {k: pickle.dumps(p, 5) for k, p in parts.items()}, {k: verdict_of(p) for k, p in parts.items()})


def prep_main(conn, tbl: SimpleNamespace, rows: dict) -> None:
    """Prep-stage process (where the product's parser runs): file index in, Prepared out; the parsed rows are loaded at start, parsing is not timed."""
    conn.send(("READY",))
    busy = 0.0
    while True:
        message = conn.recv()
        if message[0] == "STOP":
            conn.send(("STATS", busy, rb.peak_rss_bytes(), time.process_time()))
            return
        t0 = time.perf_counter()
        out = prepare(tbl, message[1], rows[message[1]], message[1] + 1)
        busy += time.perf_counter() - t0
        conn.send(("PREPARED", out))


GROUP_LINES = 40_000  # one group: the prepared files already queued when the spine is free, up to this many lines (the first file always goes); it never waits for a file
PREP_AHEAD = 16  # files requested from the prep stage beyond the last one taken
REPLY_DEADLINE = 120.0  # seconds a wait for a shard's reply (BUILT, ACK, an ABORT's or a SNAPSHOT's answer, STATS) may last before it is a named error, never a hang
ROW_SLICE = 1024  # rows per executemany of the spine's rows; the spine takes the workers' replies between slices


def slices(data: list):
    return (data[i:i + ROW_SLICE] for i in range(0, len(data), ROW_SLICE))


class PrepPool:
    """P prep processes; file i goes to process i % P. Their outputs are drained into memory as they arrive (a process blocks in send until its output is read)
    and `take` hands the spine the next group: the files in order that are already prepared, never waiting for more than the first."""

    def __init__(self, tbl: SimpleNamespace, rows: dict, procs: int) -> None:
        context = multiprocessing.get_context("spawn")
        self.files, self.procs, self.next, self.taken, self.conns, self.processes = len(rows), procs, 0, 0, [], []
        self.sizes, self.done, self.pending = {i: len(r) for i, r in rows.items()}, {}, [collections.deque() for _ in range(procs)]
        for i in range(procs):
            parent, child = context.Pipe()
            process = context.Process(target=prep_main, args=(child, tbl, {x: r for x, r in rows.items() if x % procs == i}), daemon=True)
            process.start()
            self.conns.append(parent)
            self.processes.append(process)
        for conn in self.conns:
            Spine.expect(conn, "READY")

    def request(self) -> None:
        while self.next < min(self.files, self.taken + PREP_AHEAD):
            self.conns[self.next % self.procs].send(("PREP", self.next))
            self.pending[self.next % self.procs].append(self.next)
            self.next += 1

    def waiting(self) -> list:
        return [c for c, q in zip(self.conns, self.pending) if q]

    def drain(self) -> None:
        """Receive every output that is ready, then keep the processes busy."""
        for conn, queue in zip(self.conns, self.pending):
            while queue and conn.poll():
                self.done[queue.popleft()] = Spine.expect(conn, "PREPARED")[0]
        self.request()

    def take(self, max_lines: int = GROUP_LINES) -> list[Prepared]:
        """The next group, in file order. The first file is waited for; after it only files already prepared, within `max_lines`."""
        self.request()
        out, lines = [], 0
        while self.taken < self.files:
            if self.taken not in self.done:
                self.drain()
            if self.taken not in self.done:
                if out:
                    break
                queue = self.pending[self.taken % self.procs]
                self.done[queue.popleft()] = Spine.expect(self.conns[self.taken % self.procs], "PREPARED")[0]
            if out and lines + self.sizes[self.taken] > max_lines:
                break
            lines += self.sizes[self.taken]
            out.append(self.done.pop(self.taken))
            self.taken += 1
        self.request()
        return out

    def close(self) -> tuple[float, float, float]:
        stats = []
        for conn, process, queue in zip(self.conns, self.processes, self.pending):
            while queue:  # outputs of files that were requested and never taken
                queue.popleft()
                Spine.expect(conn, "PREPARED")
            conn.send(("STOP",))
            stats.append(Spine.expect(conn, "STATS"))
            process.join()
        return sum(s[0] for s in stats), sum(s[1] for s in stats), sum(s[2] for s in stats)


class Sender:
    """I1: one FIFO queue and one thread per shard. The spine puts each encoded message on the queue and the thread writes it; the write ends only as the shard drains the pipe (on Windows),
    so the spine no longer stands in a shard's COMMIT. A write error is kept and the thread drops what follows (the pipe is gone); the spine raises it at its next pump and before its COMMIT."""

    def __init__(self, k: int, conn) -> None:
        self.k, self.conn, self.queue, self.error, self.seconds = k, conn, queue.SimpleQueue(), None, {"owed": 0.0, "free": 0.0}
        self.thread = threading.Thread(target=self.run, name=f"shard-sender-{k}", daemon=True)
        self.thread.start()

    def run(self) -> None:
        while (item := self.queue.get()) is not None:
            buf, kind = item  # kind: how the spine labelled the write when it queued it (None: not timed)
            if self.error is None:
                t0 = time.perf_counter()
                try:
                    self.conn.send_bytes(buf)
                except BaseException as error:  # kept for the spine's thread
                    self.error = error.with_traceback(None)  # the traceback would hold the overlapped write and its buffer for the life of the spine
                if kind:
                    self.seconds[kind] += time.perf_counter() - t0

    def stop(self) -> None:
        self.queue.put(None)
        self.thread.join()


class Spine:
    """Spine process: membership check, spine rows, record R_n, spine check, COMMIT; shards 0..K-1 are worker processes, and the per-row pure work is in the prep stage."""

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
        self.mode = prewrite_mode()
        self.pre, self.dirty = Prewriter(self.c, db, self.mode == 1) if self.mode else None, False  # G1: dirty = the open transaction has pages written since the last prewrite
        self.tbl = tables(template, k_count)
        self.keys = dict(self.c.execute("SELECT cell_id, raw_digest FROM cells"))  # the directory's cell id -> raw digest, loaded once and kept equal to main.cells at every commit
        self.workers: dict[int, tuple] = {}
        self.senders: dict[int, Sender] = {}
        context = multiprocessing.get_context("spawn")
        try:
            for k in range(k_count):  # every shard is a worker process; the spine process only judges, ships, writes its record and commits
                path = work / f"shard{k}.sqlite3"
                shutil.copyfile(template, path)
                parent, child = context.Pipe()
                process = context.Process(target=shard_main, args=(child, k, str(path)), daemon=True)
                process.start()
                child.close()  # only the shard holds its end now: its death or ERR ends the spine's wait for READY
                self.workers[k] = (process, parent)
            self.heads = {k: self.ready(k) for k in self.workers}
            self.c.executemany("INSERT INTO heads VALUES (?,?)", sorted(self.heads.items()))
            if sender_on():
                for k, (_, conn) in self.workers.items():
                    self.senders[k] = Sender(k, conn)
        except BaseException:  # a spine that did not start leaves no shard process and no sender thread, and its databases are closed
            for process, _ in self.workers.values():
                process.terminate()
                process.join()
            for sender in self.senders.values():
                sender.stop()
            self.ckpt.close()
            self.c.close()
            raise
        self.n, self.prev_head, self.last_t_f = 0, bytes(64), 0
        self.tally = {k: (0, 0) for k in range(k_count)}  # per shard: (count, last n) of the spine records written that touch it; a fresh spine's shards hold no applied rows
        self.pre_done = False  # mode 3: the spine has pushed its pages once in this group
        self.owed: dict[int, bytes] = {}  # shards whose group COMMIT is not yet ACKed -> the head the ACK must carry
        self.diverged_seen = False  # a wrong head after a commit was found: run_once ends in ShardDiverged, whatever else failed in the same run
        self.dead: dict[int, str] = {}  # shards lost to this run (their COMMIT was refused, or they stopped answering) -> the error every later attempt and close raises
        self.feed, self.g, self.nested, self.ack_mark, self.latency, self.groups = None, None, 0.0, None, [], []
        self.tt = {name: 0.0 for name in ("judge", "ipc", "spine_rows", "wait_built", "spine_write", "spine_commit", "ack_wait", "feed", "ipc_pickle", "ipc_send_owed", "ipc_send_free", "ipc_bytes", "thread_send_owed", "thread_send_free")}
        self.commit_sent, self.ack_ms = 0.0, {k: [] for k in range(k_count)}  # per shard: ms from the spine's COMMIT send to the spine reading that shard's ACK, per group

    @staticmethod
    def expect(conn, kind: str):
        message = conn.recv()
        if message[0] == "ERR":
            raise rb.FinancialIntegrityError(f"shard_refused:{message[1]}")
        if message[0] != kind:
            raise rb.FinancialIntegrityError(f"shard_protocol:{message[0]}")
        return message[1:]

    def ready(self, k: int) -> bytes:
        process, conn = self.workers[k]
        deadline = time.monotonic() + REPLY_DEADLINE
        while not conn.poll(0.5):  # the shard's ERR or its death ends the wait at once; a shard that does neither ends it at the deadline
            if not process.is_alive() or time.monotonic() > deadline:
                raise rb.FinancialIntegrityError(f"shard_not_ready:{k}")
        return self.expect(conn, "READY")[0]

    def wait_acks(self) -> None:
        """Step 2: every shard is past its last commit and its head equals the head the commit was made at, else a loud halt."""
        while self.owed:
            self.pump(True, "ack_wait")

    def acked(self) -> None:
        if self.ack_mark:  # every ACK of the last group is in: each of its files is acknowledged now
            started, files = self.ack_mark
            self.latency += [time.perf_counter() - started] * files
            self.ack_mark = None

    def send(self, k: int, message: tuple) -> None:
        """The message to shard k, in the order given: encoded here and queued for k's sender thread (I1, I3), or, with RR_SHARD_SENDER=0 (no write deadline: test and bench only), pickled and written here, which on
        Windows ends only as the worker drains the pipe (a write to a worker whose COMMIT is still owed is counted apart: it is time spent waiting on that commit)."""
        t0, sender, tt, counted = time.perf_counter(), self.senders.get(k), self.tt, message[0] in ("PART", "PREFLUSH", "COMMIT")  # as at 311fdb75 only these are timed
        buf = encode(message) if sender else ForkingPickler.dumps(message)
        t1 = time.perf_counter()
        kind = ("owed" if k in self.owed and message[0] != "COMMIT" else "free") if counted else None  # a write while k's COMMIT is owed is time spent waiting on that commit
        if counted:
            tt["ipc_pickle"] += t1 - t0
            tt["ipc_bytes"] += len(buf)
        if sender:
            sender.queue.put((buf, kind))
        else:
            self.workers[k][1].send_bytes(buf)
        if counted:
            tt[f"ipc_send_{kind}"] += time.perf_counter() - t1  # the spine's own time in the call; the sender thread's write time is thread_send_*

    def check_senders(self) -> None:
        failed = {k: f"shard_send:{k}:{sender.error!r}" for k, sender in self.senders.items() if sender.error is not None}
        self.dead.update((k, reason) for k, reason in failed.items() if k in self.owed and k not in self.dead)  # a write to k failed after the spine committed: k is lost to this run (as in handle's ERR), every such k before the raise, the healthy shards are drained at close
        if failed:
            raise rb.FinancialIntegrityError(next(iter(failed.values())))

    def ship(self, f, k: int) -> None:
        """Step 3: PART of file f to shard k; its pre_head is the head k last reported (the committed head, or the post head of k's previous part of this group)."""
        t0, g = time.perf_counter(), self.g
        f.pre[k] = g.tip[k]
        self.send(k, ("PART", f.n, f.index, f.pool, f.t_f, f.p.blobs[k], f.pre[k], f.p.verdicts[k]))
        g.busy[k] = f.pos  # at most one PART is outstanding per worker
        g.sent.add(k)
        self.tt["ipc"] += time.perf_counter() - t0

    def pump(self, block: bool, bucket: str = "wait_built") -> None:
        """Handle every reply that is ready (or wait for one), and keep the prep stage's outputs flowing in."""
        self.check_senders()
        t0, g = time.perf_counter(), self.g
        conns = {self.workers[k][1]: k for k in (*self.owed, *(g.busy if g else ()))}
        feed = self.feed.waiting() if self.feed else []
        if not conns and (block or not feed):
            if block:
                raise rb.FinancialIntegrityError("relay_stalled")
            return
        if block and self.pre and self.dirty and not (self.mode == 3 and self.pre_done) and not connection.wait([*conns, *feed], 0):  # about to wait with nothing ready: the wait is the time to push the spine's pages to the WAL
            self.pre.flush()
            self.dirty, self.pre_done = False, True
        deadline = time.monotonic() + REPLY_DEADLINE
        ready = connection.wait([*conns, *feed], 0.5 if block else 0)
        while block and not ready:  # a failed write is not a reply, and a silent shard must not hold the run: look at the senders and the clock now and then
            self.check_senders()
            if time.monotonic() > deadline:
                reason = f"reply_timeout:{sorted(conns.values())}"
                self.dead.update(dict.fromkeys(conns.values(), reason))
                raise rb.FinancialIntegrityError(reason)
            ready = connection.wait([*conns, *feed], 0.5)
        if block:
            self.tt[bucket] += time.perf_counter() - t0
        for conn in ready:
            if conn in conns:
                try:
                    m = conn.recv()
                except (EOFError, OSError) as error:  # the shard's end of the pipe is closed
                    raise rb.FinancialIntegrityError(f"shard_lost:{conns[conn]}") from error
                self.handle(conns[conn], m)
        if any(conn not in conns for conn in ready):
            f0 = time.perf_counter()
            self.feed.drain()
            self.tt["feed"] += time.perf_counter() - f0
        self.nested += time.perf_counter() - t0

    def diverged(self, k: int) -> ShardDiverged:
        """A shard's ACK of the spine's COMMIT carries a head other than the one owed: the spine committed, so which shard holds what is no longer known and the run ends (every shard dead; close raises)."""
        self.diverged_seen = True
        error = ShardDiverged(f"shard {k}: head differs after commit")
        self.dead = {**dict.fromkeys(self.workers, str(error)), **self.dead}  # a shard already lost keeps its own reason
        return error

    def lost(self) -> str:
        return "; ".join(dict.fromkeys(self.dead[k] for k in sorted(self.dead)))  # every dead shard, by shard

    def handle(self, k: int, m: tuple) -> None:
        if m[0] == "ERR":
            if k in self.owed:  # a shard's first reply after COMMIT is the COMMIT's: it was refused after the spine committed, so the shard is lost to this run and replay recovers it
                self.owed.pop(k)
                self.dead[k] = f"shard_commit_refused:{k}:{m[1]}"
                raise rb.FinancialIntegrityError(self.dead[k])
            raise rb.FinancialIntegrityError(f"shard_refused:{m[1]}")
        if m[0] == "ACK":
            if m[1] != self.owed.pop(k):
                raise self.diverged(k)
            self.ack_ms[k].append((time.perf_counter() - self.commit_sent) * 1000)
            if not self.owed:
                self.acked()
            return
        if m[0] != "BUILT":
            raise rb.FinancialIntegrityError(f"shard_protocol:{m[0]}")
        g = self.g
        f = g.files[g.busy.pop(k)]
        if m[3] != hashlib.sha3_256(f.p.blobs[k]).digest():  # the shard built from other bytes than the spine sent
            raise rb.FinancialIntegrityError(f"shard_blob_mismatch:{k}")
        f.built[k], g.tip[k] = (m[1], m[2], m[4], m[5]), m[1]
        f.need.discard(k)
        if g.queue[k]:  # k is free: the group's next part for it goes out on the head it just reported
            self.ship(g.files[g.queue[k].popleft()], k)
        self.flush()

    def flush(self) -> None:
        """Step 5: record R_n goes in, in n order, once file n's rows are written and every BUILT of it is in."""
        g = self.g
        while g.flushed < len(g.files):
            f = g.files[g.flushed]
            if not f.rows_done or f.need:
                return
            t0 = time.perf_counter()
            self.added = f.added
            self.write_spine(f.index, f.pool, f.n, f.t_f, f.p, f.pre, f.built)
            self.tt["spine_write"] += time.perf_counter() - t0
            g.flushed += 1

    def ingest(self, index: int, record, deposit: dict, prepared: Prepared | None = None) -> dict:
        """One file as a group of one."""
        result = self.ingest_group([(index, record, deposit, prepared)])[0]
        if isinstance(result, Exception):
            raise result
        return result

    def ingest_group(self, items: list) -> list:
        """Files (index, record, deposit, prepared) in order, one spine commit for all that go through; the result per file is its classes or the
        exception that refused it. `prepared` is the prep stage's output (made against nothing but the file); it is used when it was made for this index
        and this n and meets no cell the directory holds, else the file is judged here against the keys, by the same code. A group that fails after
        shipping is rolled back whole and its files run one at a time (step 7), so each is refused or applied as if no group had been formed."""
        results, plan, last = [None] * len(items), [], self.last_t_f
        for pos, (index, record, deposit, prepared) in enumerate(items):
            t_f = T0_MS + index
            if t_f < last:
                results[pos] = rb.FinancialIntegrityError("clock_regressed")
                continue
            plan.append((pos, index, record, deposit, prepared, t_f))
            last = t_f
        if plan:
            try:
                for entry, classes in zip(plan, self.attempt(plan)):
                    results[entry[0]] = classes
            except (ShardDiverged, GroupCommitFailed):
                raise
            except Exception as error:
                if len(plan) > 1:
                    return [self.ingest_group([item])[0] for item in items]
                results[plan[0][0]] = error
        return results

    def attempt(self, plan: list) -> list[dict]:
        """Steps 2-6 for one group. On a failure before the spine's COMMIT every shard asked is aborted, the spine rolled back and the keys undone, then it raises; from the COMMIT on, GroupCommitFailed."""
        if self.dead:
            raise rb.FinancialIntegrityError(next(iter(self.dead.values())))
        started = time.perf_counter()
        self.ckpt.before_begin()
        self.c.execute("BEGIN IMMEDIATE")
        undo, heads0, prev0, tally0 = [], dict(self.heads), self.prev_head, dict(self.tally)
        g = self.g = SimpleNamespace(files=[], busy={}, queue={k: collections.deque() for k in self.workers}, tip=dict(self.heads), sent=set(), flushed=0)
        try:
            for pos, (_, index, record, deposit, prepared, t_f) in enumerate(plan):
                n, t0 = self.n + 1 + pos, time.perf_counter()
                p = prepared
                if p is None or p.index != index or p.n != n or not self.keys.keys().isdisjoint([d[0] for d in p.dirs]):
                    p = prepare(self.tbl, index, record.rows, n, self.keys)
                pool = f"x12/SYNTHPAYER/{record.trace_origin}/{record.trace}"
                if len(pool.encode()) > 0xFFFF:
                    raise rb.FinancialIntegrityError("pool_too_long")
                f = SimpleNamespace(pos=pos, index=index, n=n, t_f=t_f, p=p, pool=pool, need=set(p.blobs), built={}, pre={}, added=0, rows_done=False)
                g.files.append(f)
                self.keys.update((d[0], d[5]) for d in p.dirs)  # the next file of the group is judged against these cells; a rollback takes them out again
                undo.extend(d[0] for d in p.dirs)
                self.tt["judge"] += time.perf_counter() - t0
                for k in p.blobs:
                    if k in g.busy:
                        g.queue[k].append(pos)
                    else:
                        self.ship(f, k)
                t0, nested = time.perf_counter(), self.nested
                f.added = self.write_rows(index, f.pool, deposit, p, lambda: self.pump(False))  # the spine's rows go in while the shards build
                self.tt["spine_rows"] += time.perf_counter() - t0 - (self.nested - nested)
                f.rows_done = True
                if pos == 0:
                    self.wait_acks()  # step 2: the shards that committed the last group have been building this one since
                self.flush()
            while g.flushed < len(g.files):
                self.pump(True)
            if self.mode == 3:  # every part is built: the shards push their pages while the spine commits
                for k in sorted(g.sent):
                    self.send(k, ("PREFLUSH",))
            self.check_senders()
        except BaseException:
            self.tally = tally0  # the group's records are not written: the writer's per-shard count and last n go back with the heads
            self.fail(g, undo, heads0, prev0)
            raise
        finally:
            self.g = None
        try:
            t0 = time.perf_counter()
            self.c.execute("COMMIT")  # the only commit point
            self.dirty = self.pre_done = False
            self.ckpt.kick()
            self.tt["spine_commit"] += time.perf_counter() - t0
            self.n, self.last_t_f = g.files[-1].n, g.files[-1].t_f
            t0 = self.commit_sent = time.perf_counter()
            for k in sorted(g.sent):
                self.owed[k] = self.heads[k]  # before the write: should it fail (here, or in k's sender), k owes the commit and the run ends; send() counts the COMMIT write itself as free
                self.send(k, ("COMMIT",))
            self.tt["ipc"] += time.perf_counter() - t0
        except BaseException as error:  # the spine may or may not hold the group, and the shards told to commit hold it: never retried, every shard is dead (replay recovers each from the spine)
            reason = f"group_commit_failed:{error!r}"
            self.dead = dict.fromkeys(self.workers, reason)
            if not isinstance(error, Exception):
                raise
            raise GroupCommitFailed(reason) from error
        self.groups.append(len(plan))
        self.ack_mark = (started, len(plan))
        if not self.owed:
            self.acked()
        return [f.p.classes for f in g.files]

    def reply(self, k: int, deadline: float) -> tuple:
        """The next reply of shard k, polled so that a never-sent ABORT (a failed write) or a silent shard ends in an error at the deadline."""
        conn, sender = self.workers[k][1], self.senders.get(k)
        while not conn.poll(0.5):
            if sender is not None and sender.error is not None:
                raise EOFError("abort_unsent")
            if time.monotonic() > deadline:
                raise TimeoutError(f"shard_reply_timeout:{k}")
        return conn.recv()

    def fail(self, g, undo: list, heads0: dict, prev0: bytes) -> None:
        """Step 6/7: abort the shards that were asked, roll the spine back, forget the group's keys and heads; then raise what the replies showed (a shard that diverged or went silent)."""
        sent, problems, deadline = [k for k in sorted(g.sent) if k not in self.dead], [], time.monotonic() + REPLY_DEADLINE  # a dead shard is not written to or waited on again: close stops it
        for k in list(sent):
            try:
                self.send(k, ("ABORT",))
            except OSError as error:  # sender 0, the pipe is gone: k is dead, and the rollback below still runs
                self.dead[k] = f"shard_send:{k}:{error!r}"
                sent.remove(k)
        for k in sent:  # a shard still owing a COMMIT answers it first (ACK, or ERR: refused), then BUILT or ERR of its part, the last ACK being the abort's
            commit = k in self.owed
            try:
                while True:
                    m = self.reply(k, deadline)
                    if commit:
                        commit, expected = False, self.owed.pop(k)
                        if m[0] != "ACK":
                            self.dead[k] = f"shard_commit_refused:{k}:{m[1]}"
                        elif m[1] != expected:
                            problems.append(self.diverged(k))
                    elif m[0] == "ACK":
                        break
            except TimeoutError as error:
                self.dead[k] = str(error)
                problems.append(rb.FinancialIntegrityError(str(error)))
            except (EOFError, OSError):
                continue  # the pipe is gone or the ABORT was never written: a shard still owing a COMMIT keeps its debt (the next wait for acks says shard_lost); a write error is raised again by every check_senders
            except Exception as error:  # a garbled reply: k is lost to this run, and the rollback below still runs
                self.dead[k] = f"shard_reply:{k}:{error!r}"
                problems.append(rb.FinancialIntegrityError(self.dead[k]))
        try:
            if self.c.in_transaction:  # SQLite has already rolled back by itself after an I/O error (or a full disk): the first error is the one to raise, not a failed ROLLBACK
                self.c.execute("ROLLBACK")
        finally:
            self.dirty = self.pre_done = False
            for cid in undo:
                self.keys.pop(cid, None)
            self.heads, self.prev_head = heads0, prev0
        if problems:
            raise next((p for p in problems if isinstance(p, ShardDiverged)), problems[0])

    def write_rows(self, index, pool, deposit, p: Prepared, tick=lambda: None) -> int:
        c, base, added, self.dirty = self.c, index * rb.KEY, 0, True
        if c.execute("SELECT 1 FROM deposit_rows WHERE row_key=?", (base,)).fetchone() is None:  # a resent file keeps its deposit row
            c.execute("INSERT INTO deposit_rows VALUES (?,?,?,?)", (base, deposit["entry_id"], pool, deposit["amount_cents"]))
        for data in slices(p.dirs):
            added += c.executemany("INSERT INTO cells VALUES (?,?,?,?,?,?,?,?)", data).rowcount
            tick()  # between statements the spine takes the replies that came in, so a worker is not left idle for a whole executemany
        for table, rows in p.sp.items():
            for data in slices(rows):
                c.executemany(f"INSERT INTO {table} VALUES ({','.join('?' * len(data[0]))})", data)
                tick()
        return added

    def write_spine(self, index, pool, n, t_f, p: Prepared, pre, built) -> None:
        c, dirs, j, source, prev, self.dirty = self.c, p.dirs, p.j, p.source, self.prev_head, True
        if any(pre[k] != self.heads[k] for k in built):  # the head shipped for k is the post head of k's previous record, in order
            raise rb.FinancialIntegrityError("spine_check")
        if any(built[k][2:] != (self.tally[k][0] + 1, n) for k in built):  # the shard holds one applied row more than the spine's records touching it, and n is the last of them
            raise ShardDiverged(f"shard applied count or last n is not the spine's records touching it (record {n})")
        body = pickle.dumps({k: (p.blobs[k], p.verdicts[k], pre[k], built[k][1], built[k][0]) for k in p.blobs}, 5)
        rd = rb.sha(n, index, pool, t_f, BUILD_ID, source, j, hashlib.sha3_256(body).digest())
        head = rb.sha(prev, rd)
        c.execute("INSERT INTO records VALUES (?,?,?,?,?,?,?,?,?)", (n, index, pool, t_f, BUILD_ID, source, j, body, head))
        c.executemany("UPDATE heads SET head=? WHERE k=?", [(built[k][0], k) for k in built])
        # spine check: the record recomputes and chains; one directory row per new cell; heads moved only for touched shards
        stored = c.execute("SELECT n,file_index,pool,t_f,build_id,source_sha,j,parts,head FROM records WHERE n=?", (n,)).fetchone()
        again = rb.sha(stored[0], stored[1], stored[2], stored[3], stored[4], stored[5], stored[6], hashlib.sha3_256(stored[7]).digest())
        expected = {k: (built[k][0] if k in built else v) for k, v in self.heads.items()}
        if rb.sha(prev, again) != stored[8] or self.added != len(dirs) or dict(c.execute("SELECT k,head FROM heads")) != expected or stored[4] != BUILD_ID:
            raise rb.FinancialIntegrityError("spine_check")
        self.heads = {**self.heads, **{k: built[k][0] for k in built}}
        self.tally = {**self.tally, **{k: (self.tally[k][0] + 1, n) for k in built}}
        self.prev_head = head

    def await_reply(self, k: int, what: str) -> None:
        conn, deadline = self.workers[k][1], time.monotonic() + REPLY_DEADLINE
        while not conn.poll(0.5):  # a failed write is not a reply, and a silent shard must not hold the run: look at the senders and the clock now and then
            self.check_senders()
            if time.monotonic() > deadline:
                self.dead[k] = f"{what}_timeout:{k}"  # close stops it, never waits for its STATS
                raise rb.FinancialIntegrityError(self.dead[k])

    def snapshot(self, k: int, path: Path) -> None:
        self.send(k, ("SNAPSHOT", str(path)))
        self.await_reply(k, "snapshot")
        self.expect(self.workers[k][1], "ACK")

    def drain_owed(self) -> ShardDiverged | None:
        """M-1: a shard that is alive and whose write has not failed was told to commit what the spine committed: its reply is read before any shard is stopped, so that its COMMIT is never killed half-way. A refusal (ERR) or a
        silent shard is lost to this run (self.dead), a wrong head diverges (returned): close raises either, so the caller hears of every shard lost here."""
        deadline, wrong = time.monotonic() + REPLY_DEADLINE, None
        for k in [k for k in self.owed if k not in self.dead and not (k in self.senders and self.senders[k].error)]:
            try:
                m = self.reply(k, deadline)
                if m[0] != "ACK":
                    self.dead[k] = f"shard_commit_refused:{k}:{m[1:]}"
                elif m[1] != self.owed.pop(k):
                    wrong = self.diverged(k)
            except Exception as error:  # a silent, lost or garbled shard
                self.dead[k] = f"shard_reply:{k}:{error!r}"
            except BaseException as interrupt:  # Ctrl-C or SystemExit in the drain: every shard still owing its COMMIT is lost to this run, and the interrupt goes on with the list
                for j in self.owed:
                    self.dead.setdefault(j, f"shard_unconfirmed:{j}")
                interrupt.add_note(self.lost())
                raise
        return wrong

    def close(self) -> list[dict]:
        stats = []
        try:
            self.check_senders()  # a STOP that cannot be written gets no STATS: say so, and stop the shards below
            if self.dead:
                raise rb.FinancialIntegrityError(self.lost())
            self.wait_acks()
            for k, (process, conn) in self.workers.items():
                self.send(k, ("STOP",))
                self.await_reply(k, "stats")
                stats.append(self.expect(conn, "STATS")[0])
                process.join(REPLY_DEADLINE)
                if process.is_alive():  # it answered STATS and does not end
                    self.dead[k] = f"stop_timeout:{k}"
                    raise rb.FinancialIntegrityError(self.dead[k])
        finally:  # after a failure too: no shard process and no sender thread outlives the spine
            first, wrong = sys.exception(), None
            try:
                try:
                    wrong = self.drain_owed()  # first: a healthy shard is not stopped inside its COMMIT
                finally:
                    for process, _ in self.workers.values():
                        if process.is_alive():
                            process.terminate()
                            process.join()
            finally:
                for sender in self.senders.values():
                    sender.stop()
                    for kind, seconds in sender.seconds.items():
                        self.tt[f"thread_send_{kind}"] += seconds
                self.ckpt.close()
                self.c.close()
            if first is not None and not isinstance(first, Exception):  # Ctrl-C, SystemExit: not turned into another error, it carries the shards lost
                if self.dead:
                    first.add_note(self.lost())
            elif wrong or (self.dead and str(first) != self.lost()):  # the error in flight (if any) does not name every shard lost to this run
                raise (ShardDiverged if wrong or isinstance(first, ShardDiverged) else rb.FinancialIntegrityError)(self.lost()) from first
        return stats


def replay(spine_db: Path, snapshot: Path, k: int) -> dict:
    """Recovery (design section 3): shard k holds some committed state with applied max n = a. Its pending records are the committed spine records after a that touch k
    (at most the last group), replayed in n order from their recorded input bytes, with their own t_f. Refused, with the shard rolled back before any commit, when a spine
    record touching k below a is not applied (gap), the pending n are not strictly increasing, a pending pre head equals its post head, a replayed head or digest is not
    its record's, or the head after the last part is not heads(k), or the applied n's are not exactly the spine records touching k (the Lean fits rule)."""
    t0 = time.perf_counter()
    shard = Shard(k, snapshot)
    applied = shard.c.execute("SELECT COALESCE(MAX(n),0) FROM applied").fetchone()[0]
    have = {n for (n,) in shard.c.execute("SELECT n FROM applied")}
    with sqlite3.connect(str(spine_db)) as s:
        records = s.execute("SELECT n,file_index,pool,t_f,build_id,parts FROM records ORDER BY n").fetchall()
        heads = dict(s.execute("SELECT k,head FROM heads"))
    touching = [(r, part) for r in records for part in [pickle.loads(r[5]).get(k)] if part]
    gaps = [r[0] for r, _ in touching if r[0] < applied and r[0] not in have]
    if gaps:
        raise ShardDiverged(f"shard {k}: spine records {gaps} touch the shard below its applied max and are not applied")
    pending = [(r, part) for r, part in touching if r[0] > applied]
    ns = [r[0] for r, _ in pending]
    if any(a >= b for a, b in zip(ns, ns[1:])):
        raise ShardDiverged(f"shard {k}: pending spine records are not strictly increasing in n (duplicate or out of order)")
    if any(part[2] == part[4] for _, part in pending):
        raise ShardDiverged(f"shard {k}: a pending spine record has pre head equal to post head")
    owed = bool(pending) and shard.w.head == pending[0][1][2] and shard.w.head != heads[k]
    t1, lines, input_bytes = time.perf_counter(), 0, 0
    try:
        for (n, index, pool, t_f, build_id, _), (blob, verdict, pre, digest, post) in pending:
            head, got = shard.build(n, index, pool, t_f, blob, pre, verdict)
            if head != post or got != digest or build_id != BUILD_ID:
                raise ShardDiverged(f"shard {k}: record {n} does not replay to its recorded head and digest")
            lines, input_bytes = lines + len(pickle.loads(blob)), input_bytes + len(blob)
        if shard.w.head != heads[k]:
            raise ShardDiverged(f"shard {k}: the replayed head is not the spine's head for the shard")
        if [n for (n,) in shard.c.execute("SELECT n FROM applied ORDER BY n")] != [r[0] for r, _ in touching]:
            raise ShardDiverged(f"shard {k}: applied n's do not fit the spine: they are not exactly the spine records touching the shard")
    except BaseException:
        shard.abort()
        raise
    if pending:
        shard.commit()
    done = time.perf_counter()
    shard.stats()
    return {"k": k, "n": pending[-1][0][0] if pending else applied, "records": len(pending), "lines": lines, "owed": owed, "identical": True, "replay_ms": (done - t0) * 1000, "replay_ms_excl_open": (done - t1) * 1000, "input_bytes": input_bytes}


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


def run_once(k_count: int, files: list, template: Path, work: Path, with_replay: bool = True, prep_procs: int = 1) -> dict:
    s0_cpu = system_cpu()
    time.sleep(0.25)
    load_before = load_pct(s0_cpu, system_cpu())  # what the machine was doing before this run, other processes included
    spine, prep = Spine(work, k_count, template), None
    try:
        prep = PrepPool(spine.tbl, {i: r.rows for i, (r, _) in enumerate(files)}, prep_procs)
        db_bytes = lambda: sum(p.stat().st_size for p in work.glob("*.sqlite3*"))  # noqa: E731
        size0, io0 = db_bytes(), io_write_bytes()
        lines, classes, kk, snap, snap_s, recv_s = 0, {}, k_count - 1, work / "snapshot.sqlite3", 0.0, 0.0
        spine.feed = prep
        sys0, cpu0, t0 = system_cpu(), time.process_time(), time.perf_counter()
        while prep.taken < len(files):
            r0 = time.perf_counter()
            group = prep.take()  # the files already prepared and queued, up to GROUP_LINES; never waits past the first
            recv_s += time.perf_counter() - r0
            if with_replay and prep.taken == len(files):  # the last group: shard kk is snapshotted at its start, so the replay has the group's records pending
                s0 = time.perf_counter()
                spine.wait_acks()
                spine.snapshot(kk, snap)
                snap_s = time.perf_counter() - s0  # the replay setup is not throughput
            for result in spine.ingest_group([(p.index, *files[p.index], p) for p in group]):
                if isinstance(result, Exception):
                    raise result
                for name, value in result.items():
                    classes[name] = classes.get(name, 0) + value
            lines += sum(len(files[p.index][0].rows) for p in group)
        spine.wait_acks()
        wall = time.perf_counter() - t0 - snap_s
        load_during, spine_cpu = load_pct(sys0, system_cpu()), time.process_time() - cpu0
        grown, spine_io, spine_rss = db_bytes() - size0, io_write_bytes() - io0, rb.peak_rss_bytes()
        spine.feed = None
        prep_busy, prep_rss, prep_cpu = prep.close()
    except BaseException as error:  # no process, thread or connection outlives a failed run; the first error is the one raised, unless close lost more shards
        for process in prep.processes if prep else ():
            process.terminate()
            process.join()
        try:
            spine.close()
        except Exception as closed:
            if spine.dead and str(error) != spine.lost():  # this error does not name every shard lost: the caller must hear of all of them
                if isinstance(error, Exception):
                    raise (ShardDiverged if spine.diverged_seen else rb.FinancialIntegrityError)(spine.lost()) from closed
                error.add_note(spine.lost())  # Ctrl-C, SystemExit: raised as it is
        raise
    latency = sorted(spine.latency)
    pct = lambda q: latency[min(len(latency) - 1, int(q * len(latency)))] * 1000  # noqa: E731
    spine.tt["prep_wait"] = recv_s
    stats = spine.close()
    shard_stats = sorted(stats, key=lambda s: s["k"])
    busy = sum(s["busy_s"] for s in shard_stats)
    out = {"K": k_count, "sender": sender_on(), "lines": lines, "wall_s": wall, "lines_per_s": lines / wall, "classes": classes,
           "j_us": spine.tt["judge"] / lines * 1e6, "prep_us": prep_busy / lines * 1e6, "prep_wait_us": recv_s / lines * 1e6, "s_us": (spine.tt["spine_rows"] + spine.tt["spine_write"]) / lines * 1e6, "ipc_us": spine.tt["ipc"] / lines * 1e6,
           "w_us": busy / lines * 1e6, "shard_check_us": sum(s["check_s"] for s in shard_stats) / lines * 1e6,
           "shard_busy_s": [s["busy_s"] for s in shard_stats], "shard_lines": [s["lines"] for s in shard_stats], "imbalance": max(s["busy_s"] for s in shard_stats) / (busy / k_count),
           "phase_s": spine.tt, "commit_ms_per_group": [(spine.tt["spine_commit"] / len(spine.groups)) * 1000, sum(s["commit_s"] for s in shard_stats) / (k_count * len(spine.groups)) * 1000],
           "groups": spine.groups, "ack_p50_ms": pct(0.5), "ack_p99_ms": pct(0.99),
           "cpu_count": os.cpu_count(), "load_before_pct": load_before, "load_during_pct": load_during,  # of all logical CPUs, other processes included
           "cpu_s": {"spine_during_loop": spine_cpu, "prep_total": prep_cpu, "shards_total": sum(s["cpu_s"] for s in shard_stats)},  # shard and prep CPU is whole-process time, startup included
           "shard_idle_s": [s["idle_s"] for s in shard_stats], "shard_commit_log": [s["commit_log"] for s in shard_stats], "ack_ms_by_shard": spine.ack_ms,
           "store_bytes_per_s": grown / wall, "io_write_bytes_per_s": (spine_io + sum(s["io_write"] for s in stats)) / wall,
           "peak_rss_spine_mb": spine_rss / 2**20, "peak_rss_shards_mb": [s["peak_rss"] / 2**20 for s in shard_stats],
           "peak_rss_prep_mb": prep_rss / 2**20, "peak_rss_total_mb": (spine_rss + prep_rss + sum(s["peak_rss"] for s in stats)) / 2**20, "python_processes": k_count + 1 + prep_procs,
           "prewrite": {"on": prewrite_mode(), "spine": pre_stats(spine.pre), "shards": {key: sum(s["prewrite"][key] for s in shard_stats) for key in ("count", "flush_s", "fsync_s")}, "shard_counts": [s["prewrite"]["count"] for s in shard_stats]}}
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
    ap.add_argument("--prep", type=int, default=1, help="prep-stage processes")
    ap.add_argument("--suffix", default="")
    ap.add_argument("--sender", choices=["0", "1"], help="I1 and I3 for this run (1 default: a sender thread per shard, PART as header plus blob; 0: the earlier path, the spine writes itself, no write deadline, test and bench only) (sets RR_SHARD_SENDER)")
    ap.add_argument("--prewrite", choices=["0", "1", "2", "3"], help="G1 mode for this run (0 off, 1 flush+fsync per part, 2 flush per part, 3 flush once per group) (sets RR_SHARD_PREWRITE; workers inherit it)")
    a = ap.parse_args(argv)
    if a.prewrite:
        os.environ["RR_SHARD_PREWRITE"] = a.prewrite
    if a.sender:
        os.environ["RR_SHARD_SENDER"] = a.sender
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
                r = {"suffix": a.suffix, "corpus": name, "rep": rep, **run_once(k, files, template, SCRATCH / f"run-{a.suffix}-{name}-{k}", rep == a.reps, a.prep)}
                runs.append(r)
                print(f"{name} K={k} rep={rep} {r['lines_per_s']:,.0f} lines/s j={r['j_us']:.1f} pw={r['prep_wait_us']:.1f} prep={r['prep_us']:.1f} s={r['s_us']:.1f} ipc={r['ipc_us']:.1f} w={r['w_us']:.1f} us ack p50/p99={r['ack_p50_ms']:.0f}/{r['ack_p99_ms']:.0f} ms groups={len(r['groups'])} load={r['load_before_pct']:.0f}/{r['load_during_pct']:.0f}% rss={r['peak_rss_total_mb']:.0f} MB pre={r['prewrite']['shards']['count']}+{r['prewrite']['spine']['count']}" +(f" replay={r['replay']['replay_ms']:.0f} ms ok={r['replay']['identical']}" if "replay" in r else ""), flush=True)
    previous = json.loads(a.out.read_text(encoding="utf-8")) if a.out.exists() else {"runs": []}
    previous["runs"].extend(runs)
    a.out.write_text(json.dumps(previous, indent=1, default=str), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
