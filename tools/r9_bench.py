"""R9a speed bench (hold-release r4.2 section 11): synthetic, seeded, non-PHI. Measures; changes no product code.

Stages, each run alone (`--stage a|b|c|d|gen|report`; e rides on b):
  a  trunk parse_835 + fold over the corpus.
  b  per-row judge + the corrected per-line writes, plain SQL, one transaction per chunk (a file, up to 8,192 lines), into a real trunk owner database
     (owner tables) plus bench-side store tables. The trunk has no store v9 (cells, holds, links, verdicts, pool rule):
     the judge here is a stand-in that decides only the write class, so (b) measures write cost, not judge cost.
  c  trunk FinancialOwner.record_payment_evidence (Lean decides, one command per call) at k_pre payments in one obligation.
  d  the pinned Lean worker. It has no multi-command BLFPAY frame (batchFast is S1); this times 1,000 single-command round
     trips and the 1,000 frame-rejection floor, a proxy that cannot be read as a PASS of the bar.
  e  write-lock hold (BEGIN IMMEDIATE to COMMIT) per chunk: timed inside each (b) run and read from those runs by `report`.
Corpus: 835 files by the repo's tests.test_x12_835_intake.build; one 1-line deposit file per file (its pool).
Results: JSON `runs` list, one record per guarded run; `--stage report` sums slices.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import random
import shutil
import sqlite3
import statistics
import sys
import tempfile
import threading
import time
import zlib
from ctypes import wintypes
from operator import itemgetter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.right_rail_financial_owner import FinancialIntegrityError  # noqa: E402

SCRATCH = Path("C:/Users/neers/rrb/state/scratch-r9")
# trunk x12_tokenizer.MAX_SEGMENTS is 5,000 per file, so 5,000 CLP per file is refused (x12:cap-segments): 250 files x 4,000 CLP = 1M lines
FILES, PER_FILE, OBLIGATIONS, C_MAX = 250, 4000, 1000, 8192  # a chunk is one transaction: the file, or 8,192 lines of a longer one
BARS = {"a": ("lines_per_s", ">=", 250_000), "b": ("lines_per_s", ">=", 80_000), "d": ("ms_per_1000_commands", "<=", 20), "e": ("max_hold_s", "<", 1.0)}


def peak_rss_bytes() -> int:
    class Counters(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD), ("PeakWorkingSetSize", ctypes.c_size_t)] + [(n, ctypes.c_size_t) for n in ("WorkingSetSize", "QuotaPeakPagedPoolUsage", "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage", "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage")]
    c = Counters()
    c.cb = ctypes.sizeof(c)
    ctypes.windll.kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    ctypes.windll.psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD]
    ctypes.windll.psapi.GetProcessMemoryInfo(ctypes.windll.kernel32.GetCurrentProcess(), ctypes.byref(c), c.cb)
    return int(c.PeakWorkingSetSize)


def pct(values: list[float], p: int) -> float:
    s = sorted(values)
    return s[min(len(s) - 1, max(0, -(-len(s) * p // 100) - 1))] if s else 0.0


def money(c: int) -> str:
    return f"{'-' if c < 0 else ''}{abs(c) // 100}.{abs(c) % 100:02d}"


# ---------------------------------------------------------------- corpus
def gen_file(index: int, seed: int, per_file: int) -> tuple[bytes, dict]:
    """One 835 of `per_file` CLP blocks: 5% REV (half before, half after their CLP), 2% PLB pairs (extra segments), 1% unreadable
    CLP07 (RAW), 0.5% reissues (half a changed amount), 1% zero rows. Keys are unique across files. Returns (bytes, deposit)."""
    from tests.test_x12_835_intake import build
    rng = random.Random(seed * 1_000_003 + index)
    n_rev, n_plb, n_raw, n_re, n_zero = (per_file * k // 1000 for k in (50, 20, 10, 5, 10))
    n_plain = per_file - n_rev - n_raw - n_re - n_zero
    blocks: list[tuple[str, list[str]]] = []  # (clp07 or "", segments)
    paid_total, readable = 0, []

    def claim(key: str, paid: int, charge: int | None = None, status: str = "1") -> list[str]:
        charge = paid if charge is None else charge
        segs = [f"CLP*C{index:03d}{key}*{status}*{money(charge)}*{money(paid)}*0.00*MC*{key}*11*1"]
        if charge != paid:
            segs.append(f"CAS*PR*1*{money(charge - paid)}")
        return segs

    for i in range(n_plain + n_re + n_zero):
        key = f"F{index:03d}K{i:05d}"
        if i < n_zero:
            blocks.append((key, claim(key, 0, rng.randint(100, 50_000))))
        else:
            paid = rng.randint(500, 500_000)
            paid_total += paid
            readable.append(key)
            blocks.append((key, claim(key, paid)))
            if i < n_zero + n_re:  # reissue: same CLP07 again, half with a changed amount
                again = paid if i % 2 else paid + 100
                paid_total += again
                blocks.append((key, claim(key, again)))
    for i in range(n_raw):
        key = f"R{index:03d}%{i:04d}"  # '%' fails the CLP07 text pattern: keyed RAW
        paid = rng.randint(500, 50_000)
        paid_total += paid
        blocks.append(("", claim(key, paid)))
    rng.shuffle(blocks)
    for i in range(n_rev):
        target = readable[i * (len(readable) // n_rev)]
        pos = next(k for k, (key, _) in enumerate(blocks) if key == target)
        cents = rng.randint(100, 5000)
        paid_total -= cents
        rev = (f"V{index:03d}{i:04d}", claim(target, -cents, status="22"))
        blocks.insert(pos if i % 2 == 0 else pos + 1, rev)  # half before the target, half after
    segments = [s for _, segs in blocks for s in segs]
    plb, wires = [], 0
    for i in range(0, n_plb, 6):
        pairs = []
        for _ in range(min(6, n_plb - i)):
            wire = rng.randint(100, 3000)
            wires += wire
            pairs += [f"FB:{readable[rng.randrange(len(readable))]}", money(wire)]
        plb.append(f"PLB*1234567890*20261231*{'*'.join(pairs)}")
    total = paid_total - wires
    trace = f"TR{index:06d}"
    head = [f"BPR*I*{money(total)}*C*ACH*CCP{'*' * 11}20261005", f"TRN*1*{trace}*1999999999", "DTM*405*20261003",
            "N1*PR*SYNTH STATE MEDICAID PROGRAM*PI*SYNTHPAYER01", "N1*PE*EXAMPLE CLINIC OF NOWHERE*XX*1234567890"]
    data = build(head + segments + plb, icn=f"{index + 1:09d}")
    return data, {"entry_id": f"DEP{index:06d}", "trace": trace, "kind": "CREDIT", "amount_cents": total}


def corpus_path(index: int) -> Path:
    return SCRATCH / "corpus" / f"f{index:03d}.835"


def ensure_corpus(first: int, count: int, seed: int, per_file: int) -> None:
    (SCRATCH / "corpus").mkdir(parents=True, exist_ok=True)
    for i in range(first, first + count):
        p = corpus_path(i)
        if not p.exists():
            data, deposit = gen_file(i, seed, per_file)
            p.write_bytes(data)
            p.with_suffix(".dep").write_text(json.dumps(deposit, sort_keys=True), encoding="utf-8")


# ---------------------------------------------------------------- stage a
def stage_a(first: int, count: int, seed: int, per_file: int, profile: bool) -> dict:
    from app.x12_835_intake import parse_835
    ensure_corpus(first, count, seed, per_file)
    times, rows, lines = [], 0, 0
    prof = None
    if profile:
        import cProfile
        prof = cProfile.Profile()
    for i in range(first, first + count):
        data = corpus_path(i).read_bytes()
        t = time.perf_counter()
        if prof:
            prof.enable()
        record = parse_835(data)
        if prof:
            prof.disable()
        times.append(time.perf_counter() - t)
        rows += len(record.rows)
        lines += per_file
    out = {"files": count, "lines": lines, "rows": rows, "seconds": sum(times), "lines_per_s": lines / sum(times), "per_file_s": times}
    return {**out, "profile": _top(prof)} if prof else out


def _top(prof) -> list[str]:
    import io
    import pstats
    buf = io.StringIO()
    pstats.Stats(prof, stream=buf).sort_stats("tottime").print_stats(15)
    return [ln for ln in buf.getvalue().splitlines() if ln.strip()][-18:]


# ---------------------------------------------------------------- stage b / e
STORE_DDL = """
CREATE TABLE IF NOT EXISTS cell_rows (row_key INTEGER PRIMARY KEY, origin_id TEXT NOT NULL, tag TEXT NOT NULL, amount_cents INTEGER, raw TEXT NOT NULL, line_digest BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS cells (row_key INTEGER PRIMARY KEY, cell_id BLOB NOT NULL UNIQUE, origin_id TEXT NOT NULL, pool TEXT NOT NULL, obligation_id TEXT NOT NULL, state TEXT NOT NULL, amount_cents INTEGER);
CREATE TABLE IF NOT EXISTS resolutions (row_key INTEGER PRIMARY KEY, cell_id BLOB NOT NULL, act TEXT, cents INTEGER NOT NULL, basis TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS charges (row_key INTEGER PRIMARY KEY, resolution_key INTEGER NOT NULL, obligation_id TEXT NOT NULL, cents INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS holds (row_key INTEGER PRIMARY KEY, cell_id BLOB NOT NULL, reason TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS links (row_key INTEGER PRIMARY KEY, negative_cell_id BLOB NOT NULL, target_origin_id TEXT NOT NULL, status TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS deposit_rows (row_key INTEGER PRIMARY KEY, entry_id TEXT NOT NULL, pool TEXT NOT NULL, amount_cents INTEGER NOT NULL);
"""
# The store tables are bench-only (S3 is not stored anywhere yet), so keys are chosen for append order: row_key = file index * 2^20 + row index, monotone over the day.
# cells keeps the one inherent random index, UNIQUE(cell_id), which is also the dedup key.
KEY = 1 << 20


def make_owner_db(path: Path) -> None:
    """A real trunk owner database with a published 1,000-obligation population (the load harness's own setup)."""
    from app.right_rail_financial_owner import FinancialOwner, FinancialOwnerConfig, SyntheticTrustedAuthority
    from tests.instruments.load_synthetic import _SCOPE, _setup
    authority = SyntheticTrustedAuthority()
    with FinancialOwner(path=path, config=FinancialOwnerConfig(**_SCOPE), trusted_authority=authority) as owner:
        _setup(owner, random.Random(1), OBLIGATIONS, authority)


def sha(*parts: object) -> bytes:
    return hashlib.sha3_512("\x1f".join(map(str, parts)).encode()).digest()


class Checkpointer:
    """WAL checkpoints (PASSIVE) on their own connection and thread, so a commit never copies pages into the database (PERF-B design 2.7).
    A checkpoint copies only committed frames and fsyncs the database before the WAL may reset, so committed state is unchanged."""

    def __init__(self, path: Path, wal_limit: int = 256 * 2**20) -> None:
        self.wal, self.limit, self.seconds, self.runs, self.errors = Path(str(path) + "-wal"), wal_limit, 0.0, 0, []
        self.wake, self.idle, self.stopping = threading.Event(), threading.Event(), False
        self.idle.set()
        self.thread = threading.Thread(target=self._run, args=(str(path),), daemon=True)
        self.thread.start()

    def _run(self, path: str) -> None:
        c = sqlite3.connect(path, isolation_level=None)
        c.execute("PRAGMA busy_timeout=5000")
        while True:
            self.wake.wait()
            self.wake.clear()
            if self.stopping:
                break
            t = time.perf_counter()
            try:
                c.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchall()
            except sqlite3.Error as error:  # reported, never silent
                self.errors.append(repr(error))
            self.seconds += time.perf_counter() - t
            self.runs += 1
            if not self.wake.is_set():
                self.idle.set()
        c.close()

    def kick(self) -> None:
        self.idle.clear()
        self.wake.set()

    def before_begin(self) -> None:
        """The writer waits for a checkpoint only when the WAL is past the limit."""
        if self.wal.exists() and self.wal.stat().st_size > self.limit:
            self.kick()
            self.idle.wait()

    def close(self) -> None:
        self.stopping = True
        self.wake.set()
        self.thread.join()


class Crash(BaseException):
    """Test hook: stands for the process dying inside a chunk (nothing rolls back; the connection is just dropped)."""


class Writer:
    """The corrected per-line writes (section 11), as plain SQL on one connection: one transaction per chunk (a file, or C_MAX lines).
    fast=True is the PERF-B path (set-based dedup probe, one executemany per table in key order, per-obligation writes once, checkpointer);
    fast=False is the reference (one execute per row in file order, one dedup SELECT per row). Both write identical rows."""

    def __init__(self, connection: sqlite3.Connection, fast: bool = True, checkpointer: Checkpointer | None = None) -> None:
        self.c, self.fast, self.ckpt = connection, fast, checkpointer
        cur = connection
        self.obl = {r[0]: r[1] for r in cur.execute("SELECT obligation_id,item_id FROM obligations ORDER BY item_id")}  # obligation -> item
        self.obl_ids = list(self.obl)
        self.revision = {r[0]: r[1] for r in cur.execute("SELECT obligation_id,revision FROM obligations")}
        self.cols = [r[1] for r in cur.execute("PRAGMA table_info(evaluations)")]
        self.base = {r[1]: r for r in cur.execute("SELECT * FROM evaluations e WHERE evaluation_id IN (SELECT current_evaluation_id FROM obligations)")}
        self.seq, self.head = cur.execute("SELECT COALESCE(MAX(event_sequence),0),COALESCE((SELECT head FROM financial_events ORDER BY event_sequence DESC LIMIT 1),zeroblob(64)) FROM financial_events").fetchone()
        cur.execute("CREATE TEMP TABLE IF NOT EXISTS probe (k BLOB NOT NULL)")
        self.commit_s: list[float] = []  # COMMIT alone (fsync, deferred FK check, WAL checkpoint when the writer does it) of each chunk
        self.tally: dict[str, int] = {}
        self.classes: dict[str, int] = {}
        self.before_commit = None  # test hook: called (file index, chunk start) inside the transaction, before COMMIT

    def obligation(self, ref: str) -> str:
        return self.obl_ids[zlib.crc32(ref.encode()) % len(self.obl_ids)]

    def run_file(self, index: int, record, deposit: dict, hold_times: list[float]) -> int:
        rows = sorted(enumerate(record.rows), key=lambda p: (0 if (p[1].amount_cents or 0) < 0 else 1, p[0]))  # negatives first, then file order
        pool = f"x12/SYNTHPAYER/{record.trace_origin}/{record.trace}"
        pending: dict[str, list[tuple[str, bytes, int]]] = {}
        resolved: set[str] = set()
        for start in range(0, len(rows), C_MAX):
            t0 = time.perf_counter()
            if self.ckpt:
                self.ckpt.before_begin()
            self.c.execute("BEGIN IMMEDIATE")
            try:
                if start == 0 and self.c.execute("SELECT 1 FROM deposit_rows WHERE row_key=?", (index * KEY,)).fetchone() is None:
                    self.write("deposit_rows", [(index * KEY, deposit["entry_id"], pool, deposit["amount_cents"])])
                self.chunk(index, pool, rows[start:start + C_MAX], pending, resolved)
                if start + C_MAX >= len(rows):  # financial_meta rides the file's last transaction
                    self.c.execute("UPDATE financial_meta SET sequence=?,history_head=?", (self.seq, self.head))
                if self.before_commit:
                    self.before_commit(index, start)
            except Exception as error:  # the judge and the store disagree: an integrity defect, never a hold. The Writer is dead; reopen it.
                self.c.execute("ROLLBACK")
                if isinstance(error, sqlite3.Error):
                    raise FinancialIntegrityError(f"store_constraint:{error}") from error
                raise
            c0 = time.perf_counter()
            self.c.execute("COMMIT")
            self.commit_s.append(time.perf_counter() - c0)
            if self.ckpt:
                self.ckpt.kick()
            hold_times.append(time.perf_counter() - t0)
        return len(rows)

    def write(self, table: str, rows: list[tuple]) -> None:
        if not rows:
            return
        self.tally[table] = self.tally.get(table, 0) + len(rows)
        sql = f"INSERT INTO {table} VALUES ({','.join('?' * len(rows[0]))})"
        if self.fast:
            self.c.executemany(sql, sorted(rows, key=itemgetter(0)))
        else:
            for row in rows:
                self.c.execute(sql, row)

    def known_cells(self, cids: list[bytes]) -> set[bytes]:
        """One probe per chunk: the chunk's cell ids into a temp key table, one JOIN against cells."""
        self.c.execute("DELETE FROM temp.probe")
        self.c.executemany("INSERT INTO temp.probe VALUES (?)", [(cid,) for cid in cids])
        return {r[0] for r in self.c.execute("SELECT p.k FROM temp.probe p JOIN main.cells c ON c.cell_id=p.k")}

    def mutate(self, t, touched, index, now, ob: str, key: str, cents: int, kind: str) -> None:
        rev = self.revision[ob]
        self.revision[ob] = rev + 1
        touched[ob] = touched.get(ob, 0) + cents
        ev = f"ev:{index:06d}:{key}"  # zero-padded, so the owner ids the adapter mints are monotone over the day
        pay = f"pay:{index:06d}:{key}"
        request = {"command": "PAYMENT" if kind == "PAYMENT_RECEIVED" else "PAYMENT_REVERSAL", "key": pay if kind == "PAYMENT_RECEIVED" else ev, "item_id": self.obl[ob],
                   "evidence_id": ev, "common_origin_id": f"x12/{key}", "amount_cents": cents, "event_at_ms": now, "source_id": "x12", "source_version": "v1", "local_ref": ""}
        body = json.dumps(request, sort_keys=True, separators=(",", ":")).encode("ascii")  # the owner's commands row (owner._record_command): canonical request, domain digest
        t["commands"].append((f"{request['command']}:{request['key']}", request["command"], body.decode("ascii"), hashlib.sha3_512(b"RR/FINANCIAL/COMMAND/v1\x00" + body).digest(), self.seq + 1))
        t["evidence"].append((ev, self.obl[ob], "PAYMENT", f"x12/{key}", "x12", "v1", "", now, now, now, sha(ev, 1), sha(ev, 2), cents, None, None))
        t["payments"].append((pay, ob, self.obl[ob], ev, f"x12/{key}", abs(cents) or 1, now, 1, None))
        self.seq += 1  # one history event per mutation, hash-chained (SHA3-512)
        payload = f'{{"kind":"{kind}","obligation":"{ob}","before":{rev},"after":{rev + 1},"ref":"{key}"}}'
        pd, previous = sha(payload), self.head
        self.head = sha(previous, pd)
        t["financial_events"].append((self.seq, sha("event", self.seq), "OBLIGATION", ob, kind, rev, rev + 1, payload, pd, previous, self.head, now))

    def finish(self, index, now, touched, began) -> None:
        evals, cases, obls = [], [], []
        for ob in sorted(touched) if self.fast else touched:  # per touched obligation, once per chunk: cases UPDATE, final evaluation INSERT, guarded obligations UPDATE
            rev, cents = self.revision[ob], touched[ob]
            eid = f"eval:{index:06d}:{ob}:{rev}"
            row = list(self.base[ob])
            for name, value in (("evaluation_id", eid), ("revision", rev), ("evaluated_at_ms", now), ("result_digest", sha(eid, 1)), ("input_snapshot_digest", sha(eid, 2)), ("receipt_digest", sha(eid, 3))):
                row[self.cols.index(name)] = value
            evals.append(tuple(row))
            cases.append((now, ob))
            obls.append((rev, max(cents, 0), eid, now, ob, began[ob]))
        self.write("evaluations", evals)
        guarded = [("UPDATE cases SET updated_at_ms=? WHERE obligation_id=?", cases),
                   ("UPDATE obligations SET revision=?,received_cash_cents=received_cash_cents+?,current_evaluation_id=?,updated_at_ms=? WHERE obligation_id=? AND revision=?", obls)]
        for sql, args in guarded:
            if self.fast:
                changed = self.c.executemany(sql, args).rowcount  # the sum over the batch; each statement matches one primary key, so the sum is the count only if every one hit
            else:
                changed = sum(self.c.execute(sql, a).rowcount for a in args)
            if changed != len(args):
                raise FinancialIntegrityError("obligation_revision_moved")

    def chunk(self, index: int, pool: str, rows, pending, resolved) -> None:
        t = {k: [] for k in ("cell_rows", "cells", "resolutions", "charges", "holds", "links", "evidence", "payments", "financial_events", "commands")}
        touched: dict[str, int] = {}  # obligation -> cents received in this chunk
        now = 1_700_000_000_000 + index
        began = dict(self.revision)
        base = index * KEY

        mutate = lambda ob, key, cents, kind: self.mutate(t, touched, index, now, ob, key, cents, kind)  # noqa: E731

        prep = []
        for row_index, row in rows:
            tag, key = row.key[0], "/".join(row.key[1:])
            origin = f"{index}/{tag}/{key}"
            ref = row.key[4] if tag == "PLB" else row.key[1]
            ob = self.obligation(ref)
            cid = sha("RR/CELL/CASH/v2", "bench-tenant", self.obl[ob], origin)  # the real cell id: a random-looking 64-byte digest, so the UNIQUE index on it is the random one
            prep.append((row_index, row, tag, key, origin, ref, ob, cid))
        known = self.known_cells([p[7] for p in prep]) if self.fast else None
        seen: set[bytes] = set()  # keys this chunk creates are answered from memory
        for row_index, row, tag, key, origin, ref, ob, cid in prep:
            amount, rk = row.amount_cents, base + row_index
            if cid in seen or (cid in known if known is not None else self.c.execute("SELECT 1 FROM cells WHERE cell_id=?", (cid,)).fetchone() is not None):
                self.classes["duplicate"] = self.classes.get("duplicate", 0) + 1  # a row already judged (a replayed file) writes nothing
                continue
            seen.add(cid)
            t["cell_rows"].append((rk, origin, tag, amount, row.raw, hashlib.sha3_256(row.raw.encode()).digest()))
            if amount == 0:
                cls = "zero"
                t["cells"].append((rk, cid, origin, pool, ob, "ZERO", amount))
            elif tag == "RAW" or amount is None:
                cls = "held"
                t["cells"].append((rk, cid, origin, pool, ob, "HELD", amount))
            elif amount < 0:
                target = f"{index}/CLP/{ref}"  # "negatives first, then file order": a REV's target is resolved only if it came earlier
                t["cells"].append((rk, cid, origin, pool, ob, "NEGATIVE", amount))
                t["holds"].append((rk, cid, "TARGET"))
                t["links"].append((rk, cid, target, "EFFECTIVE" if target in resolved else "PENDING"))
                if target in resolved:
                    cls = "negative_applied"
                    t["resolutions"].append((rk, cid, None, amount, "INTAKE"))
                    t["charges"].append((rk, rk, ob, amount))
                    mutate(ob, key, amount, "PAYMENT_REVERSED")
                else:
                    cls = "negative_pending"
                    pending.setdefault(target, []).append((origin, cid, rk))
            else:
                cls = "applied"
                t["cells"].append((rk, cid, origin, pool, ob, "RESOLVED", amount))
                t["resolutions"].append((rk, cid, None, amount, "INTAKE"))
                t["charges"].append((rk, rk, ob, amount))
                for _, negcid, negrk in pending.pop(origin, ()):  # the target's resolution nets each pending link: its resolution and charge only
                    t["resolutions"].append((negrk, negcid, None, 0, "NET"))
                    t["charges"].append((negrk, negrk, ob, 0))
                resolved.add(origin)
                mutate(ob, key, amount, "PAYMENT_RECEIVED")
            self.classes[cls] = self.classes.get(cls, 0) + 1
        for table, data in t.items():
            self.write(table, data)
        self.finish(index, now, touched, began)

def open_store(db: Path, fast: bool, checkpointer: bool) -> tuple[sqlite3.Connection, Writer]:
    """The writer connection (foreign_keys, recursive_triggers, synchronous=FULL, WAL, unchanged) and its Writer; checkpointer=True moves checkpoints off the commit path."""
    c = sqlite3.connect(str(db), isolation_level=None)
    for pragma in ("foreign_keys=ON", "recursive_triggers=ON", "synchronous=FULL", "cache_size=-65536", "busy_timeout=5000") + (("wal_autocheckpoint=0",) if checkpointer else ()):
        c.execute(f"PRAGMA {pragma}")
    c.executescript(STORE_DDL)
    return c, Writer(c, fast, Checkpointer(db) if checkpointer else None)


def stage_b(first: int, count: int, seed: int, per_file: int, db: Path, fresh: bool, profile: bool, reference: bool = False) -> dict:
    from app.x12_835_intake import parse_835
    ensure_corpus(first, count, seed, per_file)
    if fresh and db.exists():
        for p in db.parent.glob(db.name + "*"):
            p.unlink()
    if not db.exists():
        make_owner_db(db)
    c, w = open_store(db, not reference, not reference)
    size = lambda: db.stat().st_size + (Path(str(db) + "-wal").stat().st_size if Path(str(db) + "-wal").exists() else 0)  # noqa: E731
    size0 = size()
    holds: list[float] = []
    per_file_s, lines = [], 0
    prof = None
    if profile:
        import cProfile
        prof = cProfile.Profile()
    for i in range(first, first + count):
        record = parse_835(corpus_path(i).read_bytes())  # untimed: stage a measures it
        deposit = json.loads(corpus_path(i).with_suffix(".dep").read_text(encoding="utf-8"))
        t = time.perf_counter()
        if prof:
            prof.enable()
        w.run_file(i, record, deposit, holds)
        if prof:
            prof.disable()
        per_file_s.append(time.perf_counter() - t)
        lines += per_file
    grown = size() - size0
    if w.ckpt:
        w.ckpt.close()
    c.close()
    out = {"files": count, "lines": lines, "seconds": sum(per_file_s), "lines_per_s": lines / sum(per_file_s), "per_file_s": per_file_s, "hold_s": holds,
           "p50_hold_s": pct(holds, 50), "p99_hold_s": pct(holds, 99), "max_hold_s": max(holds), "commit_share_of_hold": sum(w.commit_s) / sum(holds), "writes_by_table": w.tally,
           "writes_per_line": sum(w.tally.values()) / lines, "row_classes": w.classes, "db": str(db), "reference": reference, "db_bytes_per_line": grown / lines,
           "checkpoint_s": w.ckpt.seconds if w.ckpt else None, "checkpoint_runs": w.ckpt.runs if w.ckpt else None, "checkpoint_errors": w.ckpt.errors if w.ckpt else None}
    return {**out, "profile": _top(prof)} if prof else out


# ---------------------------------------------------------------- stage c / d
def open_owner_for(path: Path):
    from app.right_rail_financial_owner import FinancialOwner, FinancialOwnerConfig, SyntheticTrustedAuthority
    from tests.instruments.load_synthetic import _SCOPE
    return FinancialOwner(path=path, config=FinancialOwnerConfig(**_SCOPE), trusted_authority=SyntheticTrustedAuthority())


def seeded(k: int, seed_seconds: float) -> tuple[Path, int]:
    """A one-obligation owner database holding up to k payments, built through the owner (resumable across runs)."""
    from tests.instruments.load_synthetic import _setup
    path = SCRATCH / f"c_k{k}.sqlite3"
    first = not path.exists()
    if first:
        from app.right_rail_financial_owner import FinancialOwner, FinancialOwnerConfig, SyntheticTrustedAuthority
        from tests.instruments.load_synthetic import _SCOPE
        authority = SyntheticTrustedAuthority()
        with FinancialOwner(path=path, config=FinancialOwnerConfig(**_SCOPE), trusted_authority=authority) as owner:
            _setup(owner, random.Random(1), 1, authority)
    with sqlite3.connect(str(path)) as c:
        have = c.execute("SELECT COUNT(*) FROM payments").fetchone()[0]
        item = c.execute("SELECT item_id FROM obligations").fetchone()[0]
    deadline = time.perf_counter() + seed_seconds
    if have < k:
        with open_owner_for(path) as owner:
            while have < k and time.perf_counter() < deadline:
                n = min(250, k - have)
                owner.run_batch([("record_payment_evidence", {"item_id": item, "payment_id": f"pay:s{have + j}", "common_origin_id": f"orig:s{have + j}", "amount_cents": 100,
                                  "evidence_id": f"ev:s{have + j}", "event_at_ms": 1_000 + have + j}) for j in range(n)])
                have += n
    return path, have


def stage_c(k: int, commands: int, seed_seconds: float) -> dict:
    from app import right_rail_financial_engine as engine
    path, have = seeded(k, seed_seconds)
    if have < k:
        return {"k_pre": k, "status": "SEEDING", "seeded": have, "note": "rerun to resume"}
    work = Path(tempfile.mkdtemp(prefix="r9c-", dir=SCRATCH))
    copy = work / "c.sqlite3"
    shutil.copyfile(path, copy)
    for suffix in ("-wal", "-shm"):
        if Path(str(path) + suffix).exists():
            shutil.copyfile(str(path) + suffix, str(copy) + suffix)
    with sqlite3.connect(str(copy)) as c:
        item = c.execute("SELECT item_id FROM obligations").fetchone()[0]
    lean, real = [], engine.decide_payment_live
    def timed(*a, **kw):
        t = time.perf_counter()
        try:
            return real(*a, **kw)
        finally:
            lean.append(time.perf_counter() - t)
    engine.decide_payment_live = timed
    times, refused = [], None
    try:
        with open_owner_for(copy) as owner:
            for j in range(commands):
                t = time.perf_counter()
                try:
                    owner.record_payment_evidence(item_id=item, payment_id=f"pay:m{j}", common_origin_id=f"orig:m{j}", amount_cents=100, evidence_id=f"ev:m{j}", event_at_ms=2_000_000 + j)
                except Exception as error:  # a capacity refusal is a result
                    refused = f"{type(error).__name__}: {error} at command {j}"
                    break
                times.append(time.perf_counter() - t)
    finally:
        engine.decide_payment_live = real
        engine._close_evaluator()
        shutil.rmtree(work, ignore_errors=True)
    return {"k_pre": k, "commands": len(times), "refused": refused, "ms_per_command": 1000 * statistics.fmean(times) if times else None,
            "p50_ms": 1000 * pct(times, 50), "p99_ms": 1000 * pct(times, 99), "lean_call_ms_per_command": 1000 * statistics.fmean(lean) if lean else None}


def stage_d(rounds: int) -> dict:
    from app import right_rail_financial_engine as engine
    from app import right_rail_financial_owner as owner_module
    from app import right_rail_financial_semantic_adapter as adapter
    path, have = seeded(10, 300)
    work = Path(tempfile.mkdtemp(prefix="r9d-", dir=SCRATCH))
    copy = work / "d.sqlite3"
    shutil.copyfile(path, copy)
    out: dict = {"k_pre": 10, "worker": str(engine.EVALUATOR_PATH), "rounds": rounds}
    try:
        with open_owner_for(copy) as owner:
            with owner._write() as connection:  # builds the item from the owner's own transaction; writes nothing
                row = connection.execute("SELECT obligation_id,updated_at_ms FROM obligations").fetchone()
                command = {"kind": "record", "payment_id": "d-p1", "evidence_id": "d-e1", "common_origin_id": "d-o1", "source_id": "synthetic-payment-source", "source_version": "fixture-v1",
                           "local_ref": None, "amount_cents": 100, "event_at_ms": 1_500, "pays_action_id": None}
                item, data = adapter.live_payment_input(
                    connection, obligation_id=row[0], authority_context=adapter.TrustedAuthorityContext.from_authority(owner.trusted_authority), now_ms=max(owner._now(), row[1]),
                    verification={"scope": owner._scope_value(), "owner_id": owner.owner_id, "mode": owner.mode}, expected_revision=None, command=command,
                    receipts=owner_module._payment_receipts(connection, row[0]))
        answer = engine._evaluate_wire(item)  # warm the worker
        t = time.perf_counter()
        for _ in range(rounds):
            engine._evaluate_wire(item)
        full = time.perf_counter() - t
        t = time.perf_counter()
        for _ in range(rounds):
            adapter.decode_payment_outcome(answer, data, command)
        decode = time.perf_counter() - t
        bad, floor = item[:8], 0.0
        t = time.perf_counter()
        for _ in range(rounds):
            try:
                engine._evaluate_wire(bad)
            except engine.FinancialEngineResultError:
                pass
        floor = time.perf_counter() - t
        scale = 1000 / rounds
        out |= {"item_bytes": len(item), "answer_bytes": len(answer), "ms_per_1000_single_roundtrips": 1000 * full * scale, "python_decode_ms_per_1000": 1000 * decode * scale,
                "rejected_frame_floor_ms_per_1000": 1000 * floor * scale,
                "ms_per_1000_commands": None, "note": "NOT MEASURABLE as specified: the pinned worker has no multi-command BLFPAY frame (batchFast is S1); the figures are 1,000 single-command round trips"}
    finally:
        engine._close_evaluator()
        shutil.rmtree(work, ignore_errors=True)
    return out


# ---------------------------------------------------------------- main
def verdict(stage: str, record: dict) -> str:
    if stage not in BARS:
        return "NO BAR"
    key, op, bar = BARS[stage]
    value = record.get(key)
    if value is None:
        return "NOT MEASURED"
    return "PASS" if (value >= bar if op == ">=" else value <= bar if op == "<=" else value < bar) else "FAIL"


def report(out: Path) -> dict:
    runs = json.loads(out.read_text(encoding="utf-8"))["runs"] if out.exists() else []
    summary: dict = {}
    for stage in ("a", "b", "e"):
        mine = [r for r in runs if r["stage"] == ("b" if stage == "e" else stage) and "lines" in r["result"]]  # (e) is read from the (b) runs' chunk timings
        if mine:
            lines, secs = sum(r["result"]["lines"] for r in mine), sum(r["result"]["seconds"] for r in mine)
            per_file = [x for r in mine for x in r["result"]["per_file_s"]]
            holds = [x for r in mine for x in r["result"].get("hold_s", [])]
            s = {"files": sum(r["result"]["files"] for r in mine), "lines": lines, "lines_per_s": lines / secs, "p50_file_s": pct(per_file, 50), "p99_file_s": pct(per_file, 99),
                 "peak_rss_mb": max(r["peak_rss_bytes"] for r in mine) / 2**20, "suffixes": [r.get("suffix") for r in mine]}
            if holds:
                s |= {"max_hold_s": max(holds), "p99_hold_s": pct(holds, 99)}
            if stage == "e":
                s = {k: v for k, v in s.items() if k not in ("lines_per_s", "p50_file_s", "p99_file_s")}
            s["verdict"] = verdict(stage, s)
            summary[stage] = s
    summary["c"] = sorted((r["result"] for r in runs if r["stage"] == "c" and "ms_per_command" in r["result"]), key=lambda r: r["k_pre"])
    ds = [r["result"] for r in runs if r["stage"] == "d"]
    if ds:
        summary["d"] = {**ds[-1], "verdict": verdict("d", ds[-1])}
    return summary


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--stage", required=True, choices=("gen", "a", "b", "c", "d", "report"))
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--first", type=int, default=0)
    ap.add_argument("--files", type=int, default=FILES)
    ap.add_argument("--per-file", type=int, default=PER_FILE)
    ap.add_argument("--seed", type=int, default=20261006)
    ap.add_argument("--suffix", default="")
    ap.add_argument("--db", type=Path, default=None)
    ap.add_argument("--fresh", action="store_true")
    ap.add_argument("--profile", action="store_true")
    ap.add_argument("--reference", action="store_true", help="stage b: the per-row reference writer (default autocheckpoint) instead of the PERF-B chunk path")
    ap.add_argument("--kpre", type=int, default=10)
    ap.add_argument("--commands", type=int, default=200)
    ap.add_argument("--seed-seconds", type=float, default=420)
    ap.add_argument("--rounds", type=int, default=1000)
    a = ap.parse_args(argv)
    SCRATCH.mkdir(parents=True, exist_ok=True)
    if a.stage == "report":
        print(json.dumps(report(a.out), indent=1))
        return 0
    if a.stage == "gen":
        ensure_corpus(a.first, a.files, a.seed, a.per_file)
        return 0
    db = a.db or SCRATCH / f"{a.stage}_store.sqlite3"
    result = {"a": lambda: stage_a(a.first, a.files, a.seed, a.per_file, a.profile), "b": lambda: stage_b(a.first, a.files, a.seed, a.per_file, db, a.fresh, a.profile, a.reference),
              "c": lambda: stage_c(a.kpre, a.commands, a.seed_seconds), "d": lambda: stage_d(a.rounds)}[a.stage]()
    record = {"stage": a.stage, "suffix": a.suffix, "args": {k: str(v) for k, v in vars(a).items()}, "peak_rss_bytes": peak_rss_bytes(), "result": result}
    prior = json.loads(a.out.read_text(encoding="utf-8")) if a.out.exists() else {"runs": []}
    prior["runs"].append(record)
    a.out.write_text(json.dumps(prior, indent=1), encoding="utf-8")
    brief = {k: v for k, v in result.items() if not isinstance(v, (list, dict)) or k in ("writes_by_table", "row_classes")}
    print(json.dumps({"stage": a.stage, "verdict": verdict(a.stage, result), "peak_rss_mb": record["peak_rss_bytes"] / 2**20, **brief}, indent=1))
    for line in result.get("profile", []):
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
