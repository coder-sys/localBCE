"""OS-B0 shard harness (tools/r9_shard_bench.py): routing, merge equivalence with K=1, refusal and abort atomicity, resend, recovery replay."""

from __future__ import annotations

import hashlib
import multiprocessing
import os
import pickle
import shutil
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tools import r9_bench as rb
from tools import r9_shard_bench as sb

LINES = 300  # two parsed files of 150 lines per logical file; the sweep uses 5,000


def digests(db: Path) -> dict[str, str]:
    c = sqlite3.connect(str(db))
    try:
        names = [r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
        return {n: hashlib.sha256(repr(c.execute(f"SELECT * FROM {n} ORDER BY 1").fetchall()).encode()).hexdigest() for n in names}
    finally:
        c.close()


def directory(db: Path) -> dict[bytes, bytes]:
    with sqlite3.connect(str(db)) as c:
        return dict(c.execute("SELECT cell_id, raw_digest FROM cells"))


# sha256[:16] of repr(judge output) for each judge call (file 0, file 0 again as a resend, file 1), K=3, recorded from the judge that probed the
# database per line (HEAD b069057c, run spp2); the in-memory directory must give the same verdicts row for row on both corpora
JUDGE_HASHES = {"FL": ["5ccf079b6a787f7d", "3ba8899fc760fd46", "fdf5e4726a800644"], "DE": ["a02c8b38ef59e725", "3ba8899fc760fd46", "600340a668f07ecc"]}


SHARD_PINNED_TABLES = ("applied", "cell_rows", "charges", "commands", "evidence", "payments", "resolutions")


def pinned(db: Path, shard: bool) -> str:
    """sha256[:16] of the tables that do not depend on the owner template (its wall-clock stamps move every head): a shard's input-derived tables; the spine's
    tables but heads, and its records without build_id (which hashes the bench source), parts and head."""
    with sqlite3.connect(str(db)) as c:
        names = [r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
        names = [n for n in names if (n in SHARD_PINNED_TABLES if shard else n != "heads")]
        out = {n: hashlib.sha256(repr(c.execute(f"SELECT {'n,file_index,pool,t_f,source_sha,j' if n == 'records' else '*'} FROM {n} ORDER BY 1").fetchall()).encode()).hexdigest()[:16] for n in names}
    return hashlib.sha256(repr(sorted(out.items())).encode()).hexdigest()[:16]


# spine, shard0..shard3 of 12 files x 300 lines at K=4, recorded from the per-file code at HEAD 83a79331 (script scratch-spine3/pin_tables.py), before any group existed
GROUP_PINNED = {"FL": ["a3ad9c4cbccc3ff1", "8d7e5b0aa7a55d05", "59802cdeb36c4859", "447c83213a0e82ec", "ed63467592ab5a8c"],
                "DE": ["ccc7eb40344c7153", "f8069f7e6d4c431f", "85a3986dab841d57", "8e06fdff80af5e0a", "46842524f7b28356"]}
FAULT_FILE = 2  # the third file: its shard check fails (test only)


def faulty_main(conn, k: int, db: str) -> None:
    """A shard worker whose check refuses file FAULT_FILE; spawned workers do not see the parent's patches, so the patch is made here, in the child."""
    real = sb.Shard.check

    def check(self, index, *args):
        if index == FAULT_FILE:
            raise rb.FinancialIntegrityError("forced_shard_check")
        return real(self, index, *args)

    sb.Shard.check = check
    sb.shard_main(conn, k, db)


DIE_SHARD = 1


def die_in_commit(conn, k: int, db: str, after: bool, slow: bool = False) -> None:
    """A shard worker that dies on its COMMIT message: before it commits, or just after (so the commit is durable but never ACKed); patched here, in the child. slow: the others take 1.5 s over their COMMIT."""
    real = sb.Shard.commit

    def commit(self):
        if k == DIE_SHARD:
            if after:
                real(self)
            os._exit(3)
        if slow:
            time.sleep(1.5)
        return real(self)

    sb.Shard.commit = commit
    sb.shard_main(conn, k, db)


def die_before_commit_main(conn, k: int, db: str) -> None:
    die_in_commit(conn, k, db, False)


def die_after_commit_main(conn, k: int, db: str) -> None:
    die_in_commit(conn, k, db, True)


def die_before_commit_slow_main(conn, k: int, db: str) -> None:
    die_in_commit(conn, k, db, False, True)


def die_after_commit_slow_main(conn, k: int, db: str) -> None:
    die_in_commit(conn, k, db, True, True)


def unreadable_db_main(conn, k: int, db: str) -> None:
    """A shard worker whose database file is not one."""
    if k == DIE_SHARD + 2:
        Path(db).write_bytes(b"not a database" * 300)
    sb.shard_main(conn, k, db)


def refuse_commit_main(conn, k: int, db: str) -> None:
    """A shard worker whose COMMIT raises (the shard rolls back and answers ERR); patched here, in the child."""
    real = sb.Shard.commit

    def commit(self):
        if k == DIE_SHARD:
            raise rb.FinancialIntegrityError("forced_commit")
        return real(self)

    sb.Shard.commit = commit
    sb.shard_main(conn, k, db)


def wrong_ack_main(conn, k: int, db: str) -> None:
    """A shard worker that commits and then ACKs a head that is not the one the spine expects."""
    real = sb.Shard.commit

    def commit(self):
        real(self)
        if k == DIE_SHARD:
            self.w.head = bytes(64)

    sb.Shard.commit = commit
    sb.shard_main(conn, k, db)


def slow_commit_main(conn, k: int, db: str) -> None:
    """A shard worker whose COMMIT never ends (a stalled disk)."""
    real = sb.Shard.commit

    def commit(self):
        if k == DIE_SHARD:
            time.sleep(3600)
        return real(self)

    sb.Shard.commit = commit
    sb.shard_main(conn, k, db)


def wrong_ack_and_stuck_main(conn, k: int, db: str) -> None:
    """Shard DIE_SHARD ACKs a wrong head after its commit; shard 0 is stuck in building any part after file 1 (n >= 2)."""
    real_commit, real_build = sb.Shard.commit, sb.Shard.build

    def commit(self):
        real_commit(self)
        if k == DIE_SHARD:
            self.w.head = bytes(64)

    def build(self, n, *args):
        if k == 0 and n >= 2:
            time.sleep(3600)
        return real_build(self, n, *args)

    sb.Shard.commit, sb.Shard.build = commit, build
    sb.shard_main(conn, k, db)


def die_and_refuse_main(conn, k: int, db: str) -> None:
    """Shard DIE_SHARD dies inside its COMMIT; shard 0 answers its COMMIT with an ERR (it stays at the state before the group)."""
    real = sb.Shard.commit

    def commit(self):
        if k == DIE_SHARD:
            os._exit(3)
        if k == 0:
            raise rb.FinancialIntegrityError("forced_commit")
        return real(self)

    sb.Shard.commit = commit
    sb.shard_main(conn, k, db)


def refuse_and_wrong_ack_main(conn, k: int, db: str) -> None:
    """Shard 1 refuses its COMMIT; shard 2 commits and ACKs a head that is not the one the spine expects."""
    real = sb.Shard.commit

    def commit(self):
        if k == 1:
            raise rb.FinancialIntegrityError("forced_commit")
        real(self)
        if k == 2:
            self.w.head = bytes(64)

    sb.Shard.commit = commit
    sb.shard_main(conn, k, db)


def gated_commit_main(conn, k: int, db: str) -> None:
    """Every shard holds its COMMIT until the file `gate` in its directory exists."""
    real, gate = sb.Shard.commit, Path(db).parent / "gate"

    def commit(self):
        while not gate.exists():
            time.sleep(0.05)
        return real(self)

    sb.Shard.commit = commit
    sb.shard_main(conn, k, db)


def refuse_ready_main(conn, k: int, db: str) -> None:
    """Shard 1 answers its start with an error."""
    if k == 1:
        conn.send(("ERR", "forced_ready"))
        return
    sb.shard_main(conn, k, db)


def stats_stuck_main(conn, k: int, db: str) -> None:
    """A shard worker that never answers its STOP (stuck while it closes)."""
    sb.Shard.stats = lambda self: time.sleep(3600)
    sb.shard_main(conn, k, db)


def stuck_main(conn, k: int, db: str) -> None:
    """A shard worker that is stuck in the middle of a PART or a SNAPSHOT and answers nothing."""
    sb.Shard.build = sb.Shard.snapshot = lambda self, *args: time.sleep(3600)
    sb.shard_main(conn, k, db)


def liar_main(conn, k: int, db: str) -> None:
    """A shard worker that builds the part and reports a digest of other bytes than it was sent."""
    real = sb.Shard.build

    def build(self, *args):
        result = real(self, *args)
        self.seen = bytes(32)
        return result

    sb.Shard.build = build
    sb.shard_main(conn, k, db)


class Gated:
    """A sender's connection that writes only once the gate is open: the messages behind the one it holds stay queued."""

    def __init__(self, conn, gate: threading.Event) -> None:
        self.conn, self.gate = conn, gate

    def send_bytes(self, buf: bytes) -> None:
        self.gate.wait()
        self.conn.send_bytes(buf)


class Broken:
    def send_bytes(self, buf: bytes) -> None:
        raise BrokenPipeError("forced_send")


class FailingCommit:
    """The spine's connection, whose COMMIT fails as on a full disk; every other call goes to the real one."""

    def __init__(self, c) -> None:
        self.c = c

    def __getattr__(self, name: str):
        return getattr(self.c, name)

    def execute(self, sql: str, *args):
        if sql == "COMMIT":
            raise sqlite3.OperationalError("database or disk is full")
        return self.c.execute(sql, *args)


class AutoRolledBack:
    """The spine's connection, whose first executemany fails as SQLite does on an I/O error: it has already rolled the transaction back by itself (here, a real ROLLBACK)."""

    def __init__(self, c) -> None:
        self.c, self.armed = c, True

    def __getattr__(self, name: str):
        return getattr(self.c, name)

    def execute(self, sql: str, *args):
        return self.c.execute(sql, *args)

    def executemany(self, sql: str, *args):
        if self.armed:
            self.armed = False
            self.c.execute("ROLLBACK")
            raise sqlite3.OperationalError("disk I/O error")
        return self.c.executemany(sql, *args)


# pinned() of the spine and shard0..K-1 for 12 files x 300 lines (FL seed 20261006, DE seed 20261007), recorded at HEAD 311fdb75, before the sender thread and the PART header existed
# (rrb/state/owc-s12-pre-digests-20261007.json)
PRE_S12_PINNED = {
    "FL": {1: ["dfdd4e92e9efd849", "7fc4dc1ee1faece2"],
           8: ["9a4c1166e7188b16", "d062278907301bf2", "593392b320dfc9bd", "6828f53803c03c2b", "39c2ff0ad60210b0", "ddcabdf158b3f8bb", "ee6903a355fda141", "5ee45e9d03ef4d15", "ccc6d48ba2792f87"],
           12: ["49de65dab44af122", "d7a1f008b3d7b219", "5327a0867229cb2f", "5a7ea2674af49802", "afbd0cd96cfa612f", "05a169b941d16c71", "69609bc8e945376a", "9a05ed648c72dd9b", "f11a29c4a6332efe",
                "4bf6616496e14456", "ed5f00673cdd2160", "50185d80d51165ae", "b62854f6398e2d0c"]},
    "DE": {1: ["41fad92ff03045f1", "37274a28b4c745af"],
           8: ["9ae8998ee7b51143", "33dada86348a1a28", "b87997f77b72694d", "ab7768b333be88ea", "ae46023e8d08ce2d", "1ff39de894fb9964", "8e8591aecfcb3b21", "1c948e844ab4a693", "d24dbcfa5f82e5e7"],
           12: ["ceae8dde505dd8b9", "60e993e8fd7e8d04", "81854c9fa5718ea4", "b512c94851b89bef", "708f4cfc9680bd8d", "202226326aae6378", "2695f3194c1836d8", "cf2f5048e6a48dd1", "10db8f34cbab32fb",
                "a38af31228892647", "4d943c49a17489d0", "6a028072bb69a523", "206300ac874796a7"]},
}
PRE_S12_CLASSES = {"NEGATIVE": 239, "applied": 3384, "HELD": 24, "ZERO": 24}


class ShardBench(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = Path(tempfile.mkdtemp(prefix="osb_test_"))
        cls.template = cls.tmp / "template.sqlite3"
        rb.make_owner_db(cls.template)
        cls.files = sb.corpus(20261006, LINES, 2)

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def drive(self, k: int, name: str, pipelined: bool = True) -> Path:
        work = self.tmp / name
        spine = sb.Spine(work, k, self.template)
        prep = sb.PrepPool(spine.tbl, {i: r.rows for i, (r, _) in enumerate(self.files)}, 2) if pipelined else None
        for position, (record, deposit) in enumerate(self.files):
            spine.ingest(position, record, deposit, prep.take(0)[0] if prep else None)
            self.assertEqual(spine.keys, directory(work / "spine.sqlite3"))  # the in-memory keys equal the cells table after every commit
        if prep:
            prep.close()
        spine.close()
        return work

    def merged(self, work: Path, k: int) -> dict[str, list]:
        out: dict[str, list] = {}
        dbs = [work / "spine.sqlite3"] + [work / f"shard{i}.sqlite3" for i in range(k)]
        for table in ("cell_rows", "resolutions", "charges", "payments", "holds", "links"):
            out[table] = []
            for db in dbs:
                c = sqlite3.connect(str(db))
                if c.execute("SELECT 1 FROM sqlite_master WHERE name=?", (table,)).fetchone():
                    out[table] += c.execute(f"SELECT * FROM {table}").fetchall()
                c.close()
            out[table].sort()
        return out

    def test_routing_and_merge_equals_single(self) -> None:
        one, three = self.drive(1, "k1"), self.drive(3, "k3")
        self.assertEqual(self.merged(one, 1), self.merged(three, 3))  # sharded = single, row for row
        plain = self.drive(3, "k3plain", pipelined=False)  # preparing files in other processes changes nothing stored
        for name in ("spine.sqlite3", "shard0.sqlite3", "shard1.sqlite3", "shard2.sqlite3"):
            self.assertEqual(digests(plain / name), digests(three / name), name)
        spine = sqlite3.connect(str(three / "spine.sqlite3"))
        single = sqlite3.connect(str(one / "spine.sqlite3"))
        strip = lambda c: sorted((r[0], r[2], r[3], r[4], r[5]) for r in c.execute("SELECT * FROM cells"))  # noqa: E731
        self.assertEqual(strip(spine), strip(single))  # the directory judges the same cells
        homes = {state: {h for (h,) in spine.execute("SELECT home FROM cells WHERE state=?", (state,))} for (state,) in spine.execute("SELECT DISTINCT state FROM cells")}
        for state in ("ZERO", "HELD", "NEGATIVE"):
            self.assertEqual(homes[state], {sb.SPINE})  # REV/PLB/RAW/zero never reach a shard
        self.assertEqual(homes["RESOLVED"], {0, 1, 2})
        for k in range(3):  # every shard row routes to its shard
            route = {item: int.from_bytes(rb.sha("RR/SHARD/v1", sb.PAYER, item)[:8], "big") % 3 for (item,) in spine.execute("SELECT item_id FROM cells")}
            with sqlite3.connect(str(three / f"shard{k}.sqlite3")) as s:
                items = {r[2] for r in s.execute("SELECT * FROM payments")}
            self.assertTrue(items and all(route[i] == k for i in items))
        for k in range(3):  # spine heads name each shard's head
            head = sqlite3.connect(str(three / f"shard{k}.sqlite3")).execute("SELECT head FROM financial_events ORDER BY event_sequence DESC LIMIT 1").fetchone()[0]
            self.assertEqual(head, spine.execute("SELECT head FROM heads WHERE k=?", (k,)).fetchone()[0])
        self.assertEqual(spine.execute("SELECT COUNT(*) FROM records").fetchone()[0], 2)

    def test_stale_head_and_bad_verdict_refuse_without_writing(self) -> None:
        work = self.tmp / "refuse"
        shutil.rmtree(work, ignore_errors=True)
        work.mkdir()
        shutil.copyfile(self.template, work / "s.sqlite3")
        shard = sb.Shard(0, work / "s.sqlite3")
        head = shard.w.head
        blob = pickle.dumps([], 5)
        verdict = hashlib.sha3_256(b"").digest()
        with self.assertRaises(sb.ShardDiverged):
            shard.build(1, 0, "pool", 1, blob, bytes(64), verdict)
        with self.assertRaises(sb.ShardDiverged):
            shard.build(1, 0, "pool", 1, blob, head, bytes(32))
        self.assertFalse(shard.c.in_transaction)
        self.assertEqual(shard.w.head, head)
        shard.stats()
        self.assertEqual(sqlite3.connect(str(work / "s.sqlite3")).execute("SELECT COUNT(*) FROM applied").fetchone()[0], 0)

    def test_shard_refuses_a_part_whose_post_head_equals_its_pre_head_and_writes_nothing(self) -> None:
        prep = sb.prepare(sb.tables(self.template, 1), 0, self.files[0][0].rows, 1)
        work = self.tmp / "fixed-point"
        shutil.rmtree(work, ignore_errors=True)
        work.mkdir()
        shutil.copyfile(self.template, work / "s.sqlite3")
        shard = sb.Shard(0, work / "s.sqlite3")
        head, w, seq0, began = shard.w.head, shard.w, shard.w.seq, dict(shard.w.revision)
        real_mutations, closed = w.mutations, [False]
        writer = type(w)
        w._h = w.__dict__.pop("head")

        def mutations(t, *args):  # the real mutations run and move seq, head and revision; the last link is the pre-head (store and built agree) and the build reads the head as closed on itself
            real_mutations(t, *args)
            self.assertNotEqual(w._h, head)
            e = t["financial_events"][-1]
            t["financial_events"][-1] = e[:10] + (head,) + e[11:]
            closed[0] = True
        w.mutations = mutations
        with mock.patch.object(writer, "head", property(lambda s: head if closed[0] else s._h, lambda s, v: setattr(s, "_h", v)), create=True):
            with self.assertRaises(rb.FinancialIntegrityError) as caught:
                shard.build(prep.n, prep.index, "pool", 1, prep.blobs[0], head, prep.verdicts[0])
            closed[0] = False
            self.assertIn("shard_fixed_point", str(caught.exception))
            self.assertFalse(shard.c.in_transaction)
            self.assertEqual((w.head, w.seq, w.revision), (head, seq0, began))  # what the part moved in memory is moved back
        shard.stats()
        self.assertEqual(sqlite3.connect(str(work / "s.sqlite3")).execute("SELECT COUNT(*) FROM applied").fetchone()[0], 0)

    def test_shard_check_refuses_a_stored_event_that_differs_from_the_built_one_and_a_broken_link(self) -> None:
        prep = sb.prepare(sb.tables(self.template, 1), 0, self.files[0][0].rows, 1)
        for fault in ("stored_digest", "broken_link"):
            work = self.tmp / f"check-{fault}"
            shutil.rmtree(work, ignore_errors=True)
            work.mkdir()
            shutil.copyfile(self.template, work / "s.sqlite3")
            shard = sb.Shard(0, work / "s.sqlite3")
            head, w = shard.w.head, shard.w
            real_write, real_mutations = w.write, w.mutations
            if fault == "stored_digest":  # the store holds a payload digest that mutations did not build
                w.write = lambda table, rows: real_write(table, [r[:8] + (bytes(64),) + r[9:] for r in rows] if table == "financial_events" else rows)
            else:  # the last built event does not link to the one before it (store and built agree, the link does not)
                def mutations(t, *args):
                    real_mutations(t, *args)
                    e = t["financial_events"][-1]
                    t["financial_events"][-1] = e[:9] + (bytes(64),) + e[10:]
                w.mutations = mutations
            with self.assertRaises(rb.FinancialIntegrityError) as caught:
                shard.build(prep.n, prep.index, "pool", 1, prep.blobs[0], head, prep.verdicts[0])
            self.assertIn("shard_chain", str(caught.exception), fault)
            self.assertFalse(shard.c.in_transaction)
            self.assertEqual(w.head, head)
            shard.stats()

    def test_abort_after_shards_built_leaves_every_database_unchanged_and_retry_matches(self) -> None:
        clean = self.drive(3, "clean")
        work = self.tmp / "abort"
        spine = sb.Spine(work, 3, self.template)
        spine.ingest(0, *self.files[0], sb.prepare(spine.tbl, 0, self.files[0][0].rows, 1))  # file 1 is prepared ahead, then the commit of file 1 fails
        spine.wait_acks()
        before = {p.name: digests(p) for p in sorted(work.glob("*.sqlite3")) if p.name != "template.sqlite3"}
        real = spine.write_spine

        def crash(*args, **kwargs):
            raise rb.Crash

        spine.write_spine = crash
        with self.assertRaises(rb.Crash):
            spine.ingest(1, *self.files[1], sb.prepare(spine.tbl, 1, self.files[1][0].rows, 2))
        self.assertEqual(spine.n, 1)
        self.assertEqual(spine.keys, directory(work / "spine.sqlite3"))  # the aborted file left no key behind, in memory or stored
        self.assertEqual({p.name: digests(p) for p in sorted(work.glob("*.sqlite3"))}, before)  # spine rolled back, every shard rolled back
        spine.write_spine = real
        spine.ingest(1, *self.files[1])
        spine.close()
        for name in ("spine.sqlite3", "shard0.sqlite3", "shard1.sqlite3", "shard2.sqlite3"):
            self.assertEqual(digests(work / name), digests(clean / name), name)  # the retry ends where the uninterrupted run ends

    def test_judge_verdicts_equal_the_database_probing_judge_on_both_corpora(self) -> None:
        for name, seed in (("FL", 20261006), ("DE", 20261007)):
            files, seen = sb.corpus(seed, LINES, 2), []
            spine = sb.Spine(self.tmp / f"judge{name}", 3, self.template)
            real = sb.judge_rows

            def recording(*args, real=real):
                out = real(*args)
                seen.append(hashlib.sha256(repr(out).encode()).hexdigest()[:16])
                return out

            sb.judge_rows = recording
            try:
                spine.ingest(0, *files[0], sb.prepare(spine.tbl, 0, files[0][0].rows, 1))  # the prep stage's judge against nothing
                spine.ingest(0, *files[0])  # the resend: judged by the spine against the directory (all duplicates)
                spine.ingest(1, *files[1])  # n is 3, not the index + 1 the prep stage assumes
            finally:
                sb.judge_rows = real
            spine.close()
            self.assertEqual(seen, JUDGE_HASHES[name], name)

    def test_prep_process_output_equals_in_process_output_byte_for_byte(self) -> None:
        for seed in (20261006, 20261007):
            files, tbl = sb.corpus(seed, LINES, 2), sb.tables(self.template, 3)
            pool = sb.PrepPool(tbl, {i: r.rows for i, (r, _) in enumerate(files)}, 2)
            try:
                for i, (record, _) in enumerate(files):
                    self.assertEqual(pool.take(0)[0], sb.prepare(tbl, i, record.rows, i + 1), (seed, i))  # blobs, verdicts, directory rows, digests
            finally:
                pool.close()

    def test_stored_command_evidence_and_payment_rows_are_byte_identical_to_the_json_dumps_writer(self) -> None:
        work = self.drive(3, "bytes")  # sha256[:16] of every row of three tables per shard, recorded at HEAD 6224a94c (json.dumps body, runs spp8 and spp9)
        pinned = [("c60825022bf049a6", "ca6d98ea9725aaf0", "1aaebb83b7c38f5e"), ("6b7b5c6d15a5a3e5", "5a57d418562f8fba", "f9a130bd1fde486d"), ("9a41da5c1fc2587b", "693d32ac2130929f", "e1272ede2d2119db")]
        for k, want in enumerate(pinned):
            with sqlite3.connect(str(work / f"shard{k}.sqlite3")) as c:
                got = tuple(hashlib.sha256(repr(c.execute(f"SELECT * FROM {t} ORDER BY 1").fetchall()).encode()).hexdigest()[:16] for t in ("commands", "evidence", "payments"))
            self.assertEqual(got, want, k)

    def test_resend_is_all_duplicates_and_moves_no_head(self) -> None:
        work = self.tmp / "resend"
        spine = sb.Spine(work, 3, self.template)
        spine.ingest(0, *self.files[0])
        spine.wait_acks()
        heads = dict(spine.heads)
        classes = spine.ingest(0, *self.files[0], sb.prepare(spine.tbl, 0, self.files[0][0].rows, 2))  # a prepared file that meets held cells is judged again
        spine.wait_acks()
        self.assertEqual(set(classes), {"duplicate"})
        self.assertEqual(classes["duplicate"], len(self.files[0][0].rows))
        self.assertEqual(spine.heads, heads)
        spine.close()

    def test_resend_with_other_raw_is_a_conflict_and_writes_nothing(self) -> None:
        work = self.tmp / "conflict"
        spine = sb.Spine(work, 3, self.template)
        record, deposit = self.files[0]
        spine.ingest(0, record, deposit)
        spine.wait_acks()
        heads, cells, before = dict(spine.heads), dict(spine.keys), digests(work / "spine.sqlite3")
        rows = list(record.rows)
        tampered = [i for i, r in enumerate(rows) if (r.amount_cents or 0) > 0][:2]
        for i in tampered:  # a resend whose raw differs on a shard cell
            rows[i] = SimpleNamespace(key=rows[i].key, amount_cents=rows[i].amount_cents, raw=rows[i].raw + "X")
        classes = spine.ingest(0, SimpleNamespace(rows=rows, trace_origin=record.trace_origin, trace=record.trace), deposit)
        spine.wait_acks()
        self.assertEqual(classes, {"conflict": len(tampered), "duplicate": len(rows) - len(tampered)})
        self.assertEqual(spine.heads, heads)
        self.assertEqual(spine.keys, cells)
        after = digests(work / "spine.sqlite3")
        for table in ("cells", "cell_rows", "holds", "links", "resolutions", "charges"):
            self.assertEqual(after[table], before[table], table)  # no row written for a conflict
        spine.close()

    def test_replay_of_last_record_reproduces_digest_and_head(self) -> None:
        for k_count in (1, 3):
            result = sb.run_once(k_count, self.files, self.template, self.tmp / f"run{k_count}")
            self.assertTrue(result["replay"]["identical"])
            self.assertTrue(result["replay"]["owed"])
            self.assertGreater(result["replay"]["lines"], 0)
            self.assertEqual(result["lines"], sum(len(r.rows) for r, _ in self.files))
            self.assertEqual(sum(result["shard_lines"]), result["classes"]["applied"])
            self.assertEqual(sum(result["classes"].values()), result["lines"])

    def group_run(self, name: str, files: list, group: int, fault: bool = False, snapshot_before: int | None = None):
        """All files prepared first (in process), then ingested `group` at a time. With snapshot_before=i, shard 3 is snapshotted once the group starting at file i
        is about to begin (every ACK in, so the snapshot is the last committed state)."""
        work, real = self.tmp / name, sb.shard_main
        sb.shard_main = faulty_main if fault else real
        try:
            spine = sb.Spine(work, 4, self.template)
        finally:
            sb.shard_main = real
        prepared, results = [sb.prepare(spine.tbl, i, r.rows, i + 1) for i, (r, _) in enumerate(files)], []
        for start in range(0, len(files), group):
            if start == snapshot_before:
                spine.wait_acks()
                spine.snapshot(3, self.tmp / f"{name}-snapshot.sqlite3")
            results += spine.ingest_group([(i, *files[i], prepared[i]) for i in range(start, min(start + group, len(files)))])
            self.assertEqual(spine.keys, directory(work / "spine.sqlite3"))  # the keys equal the cells table after every spine commit, grouped or not
        groups = list(spine.groups)
        spine.close()
        return work, results, groups

    def all_digests(self, work: Path) -> dict[str, dict]:
        return {p.name: digests(p) for p in sorted(work.glob("*.sqlite3"))}

    def test_t1_group_of_eight_stores_what_group_of_one_stores(self) -> None:
        for name, seed in (("FL", 20261006), ("DE", 20261007)):
            files = sb.corpus(seed, LINES, 12)
            one, r1, g1 = self.group_run(f"t1-{name}-1", files, 1)
            eight, r8, g8 = self.group_run(f"t1-{name}-8", files, 8)
            self.assertEqual((g1, g8), ([1] * 12, [8, 4]), name)  # the groups really formed
            self.assertEqual(r1, r8, name)  # equal verdicts (class counts per file)
            self.assertEqual(self.all_digests(one), self.all_digests(eight), name)  # every row of the spine and of each shard: records bytes, heads, cells, shard rows
            got = [pinned(eight / "spine.sqlite3", False)] + [pinned(eight / f"shard{k}.sqlite3", True) for k in range(4)]
            self.assertEqual(got, GROUP_PINNED[name], name)  # and both equal what the per-file code stored before groups existed

    def test_t2_failed_shard_check_on_file_three_gives_the_group_of_one_stores(self) -> None:
        files = sb.corpus(20261006, LINES, 12)
        one, r1, _ = self.group_run("t2-1", files, 1, fault=True)
        eight, r8, g8 = self.group_run("t2-8", files, 8, fault=True)
        self.assertEqual(g8, [1] * 7 + [4])  # the first group failed whole, was rolled back, and its files ran one at a time: file 3 refused, the other seven went in
        self.assertEqual([repr(r) if isinstance(r, Exception) else r for r in r8], [repr(r) if isinstance(r, Exception) else r for r in r1])
        self.assertTrue(isinstance(r8[FAULT_FILE], rb.FinancialIntegrityError) and "forced_shard_check" in str(r8[FAULT_FILE]))
        self.assertTrue(all(isinstance(r, dict) for i, r in enumerate(r8) if i != FAULT_FILE))
        self.assertEqual(self.all_digests(one), self.all_digests(eight))
        with sqlite3.connect(str(eight / "spine.sqlite3")) as c:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM records").fetchone()[0], 11)

    def test_t3_spine_commit_without_shard_commit_replays_the_pending_suffix(self) -> None:
        files = sb.corpus(20261007, LINES, 12)
        work, results, groups = self.group_run("t3", files, 8, snapshot_before=8)
        self.assertEqual(groups, [8, 4])
        snapshot = self.tmp / "t3-snapshot.sqlite3"  # shard 3 as it was when the second group began: the spine commit of that group is not in it
        result = sb.replay(work / "spine.sqlite3", snapshot, 3)
        self.assertEqual((result["records"], result["owed"], result["identical"]), (4, True, True))
        self.assertEqual(digests(snapshot), digests(work / "shard3.sqlite3"))  # same rows, same heads, same applied as the shard that committed itself

    def test_t4_stale_head_at_group_start_is_refused_with_no_write(self) -> None:
        files, work = sb.corpus(20261006, LINES, 3), self.tmp / "t4"
        spine = sb.Spine(work, 4, self.template)
        prepared = [sb.prepare(spine.tbl, i, r.rows, i + 1) for i, (r, _) in enumerate(files)]
        before, real = self.all_digests(work), dict(spine.heads)
        spine.heads[0] = bytes(64)  # the spine's head for shard 0 is not the head shard 0 holds
        results = spine.ingest_group([(i, *files[i], prepared[i]) for i in range(3)])  # refused whole, then one at a time: refused again each time
        self.assertTrue(all(isinstance(r, rb.FinancialIntegrityError) and "shard_refused" in str(r) for r in results), results)
        self.assertEqual((spine.n, spine.keys), (0, {}))
        self.assertEqual(self.all_digests(work), before)
        spine.heads[0] = real[0]
        self.assertTrue(all(isinstance(r, dict) for r in spine.ingest_group([(0, *files[0], prepared[0])])))  # the shards are intact: the right head goes in
        spine.close()

    def prewrite_run(self, mode: int, k: int, files: list, name: str) -> dict:
        """run_once with G1 in mode 0 (off) to 3 (spawned workers inherit the environment of the moment); the stores are returned as table digests, snapshot.sqlite3 excluded (its content depends on group timing)."""
        with mock.patch.dict(os.environ):
            os.environ.pop("RR_SHARD_PREWRITE", None)
            if mode:
                os.environ["RR_SHARD_PREWRITE"] = str(mode)
            work = self.tmp / name
            r = sb.run_once(k, files, self.template, work, True, 2)
        r["tables"] = {p.name: digests(p) for p in sorted(work.glob("*.sqlite3")) if p.name != "snapshot.sqlite3"}
        r["pinned"] = [pinned(work / "spine.sqlite3", False)] + [pinned(work / f"shard{i}.sqlite3", True) for i in range(k)]
        return r

    def test_g1_prewrite_modes_1_2_3_store_exactly_what_off_stores_at_k1_8_12(self) -> None:
        for name, seed in (("FL", 20261006), ("DE", 20261007)):
            files, classes = sb.corpus(seed, LINES, 12), []
            for k in (1, 8, 12):
                off = self.prewrite_run(0, k, files, f"g1-{name}-{k}-off")
                self.assertEqual((off["prewrite"]["shards"]["count"], off["prewrite"]["spine"]["count"]), (0, 0), name)  # off does nothing
                for mode in (1, 2, 3):
                    on, label = self.prewrite_run(mode, k, files, f"g1-{name}-{k}-m{mode}"), f"{name} K={k} mode {mode}"
                    self.assertEqual(off["classes"], on["classes"], label)
                    self.assertTrue(off["replay"]["identical"] and on["replay"]["identical"], label)
                    self.assertEqual(off["tables"], on["tables"], label)  # every table of the spine and of each shard, records and heads included
                    self.assertEqual(off["pinned"], on["pinned"], label)
                    self.assertGreater(on["prewrite"]["shards"]["count"] + on["prewrite"]["spine"]["count"], 0, label)  # on really flushed
                    if mode == 3:
                        self.assertLessEqual(on["prewrite"]["shards"]["count"], len(on["groups"]) * k, label)  # at most once per group per shard
                    if mode > 1:
                        self.assertEqual(on["prewrite"]["shards"]["fsync_s"] + on["prewrite"]["spine"]["fsync_s"], 0.0, label)  # no fsync of its own
                    classes.append(on["classes"])
            self.assertTrue(all(c == classes[0] for c in classes), name)  # the same per-class counts at every K

    def test_g1_crash_with_pushed_pages_leaves_the_committed_state_and_commit_applies_the_part(self) -> None:
        for mode in (1, 2, 3):
            with self.subTest(mode=mode):
                self.crash_image(mode)

    def crash_image(self, mode: int) -> None:
        record, deposit = self.files[0]
        work = self.tmp / f"g1-crash-{mode}"
        work.mkdir()
        db = work / "shard0.sqlite3"
        shutil.copyfile(self.template, db)
        tbl = sb.tables(self.template, 1)
        p = sb.prepare(tbl, 0, record.rows, 1)
        shard = sb.Shard(0, db)
        shard.pre = sb.Prewriter(shard.c, db, mode == 1)
        before = digests(db)  # the committed state before the part
        shard.build(1, 0, f"x12/SYNTHPAYER/{record.trace_origin}/{record.trace}", sb.T0_MS, p.blobs[0], shard.w.head, p.verdicts[0])
        wal = Path(str(db) + "-wal")
        wal_before = wal.stat().st_size
        shard.prewrite(SimpleNamespace(poll=lambda timeout: False), mode == 3)
        self.assertEqual(shard.pre.count, 1)
        self.assertEqual(shard.pre.fsync_s > 0, mode == 1)
        self.assertGreater(wal.stat().st_size, wal_before)  # the pages are in the WAL: the image below is not vacuous
        crash = work / "crash"
        crash.mkdir()
        shutil.copyfile(db, crash / "shard0.sqlite3")
        shutil.copyfile(wal, crash / "shard0.sqlite3-wal")  # the process dies here: the transaction is open, its frames are in the WAL, no commit marker
        self.assertEqual(digests(crash / "shard0.sqlite3"), before)  # recovery ignores the frames
        shard.commit()
        done = work / "done"
        done.mkdir()
        shutil.copyfile(db, done / "shard0.sqlite3")
        shutil.copyfile(wal, done / "shard0.sqlite3-wal")
        after = digests(done / "shard0.sqlite3")
        self.assertNotEqual(after, before)
        with sqlite3.connect(str(done / "shard0.sqlite3")) as c:
            self.assertEqual(c.execute("SELECT n FROM applied").fetchall(), [(1,)])
        self.assertEqual(after, digests(db))  # the committed image is the live store
        shard.stats()

    def test_g1_prewriter_refuses_a_connection_that_is_not_the_named_database(self) -> None:
        other = self.tmp / "g1-other.sqlite3"
        c = sqlite3.connect(str(other))
        try:
            with self.assertRaises(RuntimeError):
                sb.Prewriter(c, self.tmp / "g1-not-it.sqlite3")
        finally:
            c.close()

    # S12: one sender thread per shard (I1) and PART as a fixed header plus the blob (I3); RR_SHARD_SENDER=0 is the earlier path

    def sender_env(self, on: bool):
        return mock.patch.dict(os.environ, {"RR_SHARD_SENDER": "1" if on else "0"})  # the spine reads it at start; spawned workers inherit it

    def quiet(self, spine=None) -> None:
        """No shard process and no sender thread of the spine (or any) is left alive."""
        if spine:
            self.assertEqual([k for k, (p, _) in spine.workers.items() if p.is_alive()], [])
            self.assertEqual([k for k, s in spine.senders.items() if s.thread.is_alive()], [])
        self.assertEqual([t.name for t in threading.enumerate() if t.name.startswith("shard-sender-")], [])
        self.assertEqual(multiprocessing.active_children(), [])

    def watchdog(self, spine, seconds: int = 120):
        """A hang must be a failure, not a stuck run: after `seconds` the shards are terminated (their pipes then end) and the fired flag fails the test."""
        fired = []

        def kill() -> None:
            fired.append(1)
            for p, _ in spine.workers.values():
                if p.is_alive():
                    p.terminate()

        timer = threading.Timer(seconds, kill)
        timer.daemon = True
        timer.start()
        return timer, fired

    def spine_with(self, main, name: str, on: bool = True) -> "sb.Spine":
        work, real = self.tmp / name, sb.shard_main
        sb.shard_main = main
        try:
            with self.sender_env(on):
                return sb.Spine(work, 4, self.template)
        finally:
            sb.shard_main = real

    def replay_identical(self, work: Path, k: int, name: str, expect_records: int | None = None) -> dict:
        """Recovery from a copy of shard k's files as they stand (a killed worker leaves db and wal): the replay equals the spine's head."""
        copy = self.tmp / f"{name}-replay{k}.sqlite3"
        shutil.copyfile(work / f"shard{k}.sqlite3", copy)
        wal = Path(str(work / f"shard{k}.sqlite3") + "-wal")
        if wal.exists():
            shutil.copyfile(wal, str(copy) + "-wal")
        result = sb.replay(work / "spine.sqlite3", copy, k)
        self.assertTrue(result["identical"], result)
        if expect_records is not None:
            self.assertEqual(result["records"] > 0, expect_records > 0, result)
        return result

    def test_s12_part_header_decodes_to_the_same_tuple_and_holds_the_blob_once(self) -> None:
        record, _ = self.files[0]
        p = sb.prepare(sb.tables(self.template, 3), 0, record.rows, 1)
        for k, blob in p.blobs.items():
            message = ("PART", 1, 0, f"x12/SYNTHPAYER/{record.trace_origin}/{record.trace}", sb.T0_MS, blob, bytes(range(64)), p.verdicts[k])
            buf = sb.encode(message)
            self.assertEqual(sb.decode(buf), message)
            self.assertTrue(buf.startswith(b"PART") and buf.endswith(blob) and buf.count(blob) == 1)
            self.assertEqual(len(buf), sb.PART_HEAD.size + len(message[3].encode()) + 64 + len(p.verdicts[k]) + len(blob))  # nothing but the header and the bytes themselves
            with self.assertRaises(ValueError):
                sb.decode(buf[:sb.PART_HEAD.size + 3])
        for message in (("COMMIT",), ("ABORT",), ("PREFLUSH",), ("STOP",), ("SNAPSHOT", "snap.sqlite3")):
            self.assertEqual(sb.decode(sb.encode(message)), message)  # every other message stays a pickle
        self.assertEqual(sb.decode(pickle.dumps(("PART", 1, 0, "p", 5, b"b", b"h", b"v"), 5)), ("PART", 1, 0, "p", 5, b"b", b"h", b"v"))  # and a pickled PART (the earlier form) still decodes

    def test_s12_sender_on_stores_exactly_what_off_and_the_pre_s12_code_store_at_k1_8_12(self) -> None:
        for name, seed in (("FL", 20261006), ("DE", 20261007)):
            files = sb.corpus(seed, LINES, 12)
            for k in (1, 8, 12):
                runs = {}
                for on in (False, True):
                    closed, real_close = [], sb.Spine.close

                    def close(spine):
                        closed.append(bool(spine.senders))  # the toggle really chose the path: threads when on, none when off
                        return real_close(spine)

                    with self.sender_env(on), mock.patch.object(sb.Spine, "close", close):
                        work = self.tmp / f"s12-{name}-{k}-{int(on)}"
                        r = sb.run_once(k, files, self.template, work, True, 2)
                    self.assertEqual((closed, r["sender"]), ([on], on), (name, k, on))
                    self.assertEqual(r["phase_s"]["thread_send_owed"] + r["phase_s"]["thread_send_free"] > 0, on, (name, k, on))
                    r["tables"] = {p.name: digests(p) for p in sorted(work.glob("*.sqlite3")) if p.name != "snapshot.sqlite3"}
                    r["pinned"] = [pinned(work / "spine.sqlite3", False)] + [pinned(work / f"shard{i}.sqlite3", True) for i in range(k)]
                    runs[on] = r
                    self.quiet()
                label = f"{name} K={k}"
                off, on = runs[False], runs[True]
                self.assertEqual(off["classes"], on["classes"], label)
                self.assertEqual(on["classes"], PRE_S12_CLASSES, label)
                self.assertTrue(off["replay"]["identical"] and on["replay"]["identical"], label)
                self.assertEqual(off["tables"], on["tables"], label)  # every table of the spine and of each shard, records and heads included
                self.assertEqual(on["pinned"], PRE_S12_PINNED[name][k], label)  # and the input-derived tables are what the code before S12 stored
                self.assertEqual(off["pinned"], PRE_S12_PINNED[name][k], label)

    def test_s12_shard_err_mid_group_gives_the_same_stores_with_the_sender_and_leaves_nothing_alive(self) -> None:
        files = sb.corpus(20261006, LINES, 12)
        with self.sender_env(False):
            off, r_off, g_off = self.group_run("s12-err-off", files, 8, fault=True)
        with self.sender_env(True):
            on, r_on, g_on = self.group_run("s12-err-on", files, 8, fault=True)
        self.assertEqual((g_off, g_on), ([1] * 7 + [4],) * 2)
        self.assertEqual([repr(r) if isinstance(r, Exception) else r for r in r_on], [repr(r) if isinstance(r, Exception) else r for r in r_off])
        self.assertTrue(isinstance(r_on[FAULT_FILE], rb.FinancialIntegrityError) and "forced_shard_check" in str(r_on[FAULT_FILE]))
        self.assertEqual(self.all_digests(off), self.all_digests(on))
        self.replay_identical(on, 3, "s12-err")
        self.quiet()

    def test_s12_shard_killed_in_commit_stops_the_run_cleanly_and_replay_recovers_it(self) -> None:
        files = sb.corpus(20261007, LINES, 12)
        clean, _, _ = self.group_run("s12-kill-clean", files[:8], 8)  # what the first group alone stores
        for after, main, forced in ((False, die_before_commit_main, False), (True, die_after_commit_main, False), (False, die_before_commit_slow_main, True), (True, die_after_commit_slow_main, True)):
            name = f"s12-kill-{int(after)}{'-sender-first' if forced else ''}"
            spine = self.spine_with(main, name)
            timer, fired = self.watchdog(spine)
            try:
                prepared = [sb.prepare(spine.tbl, i, r.rows, i + 1) for i, (r, _) in enumerate(files)]
                first = spine.ingest_group([(i, *files[i], prepared[i]) for i in range(8)])  # the spine commits; shard 1 is told to commit and dies
                self.assertTrue(all(isinstance(r, dict) for r in first), first)
                if forced:  # the sender error is in before group 2 ships (the first pump sees an owed shard's write fail), and the others are still inside their COMMIT
                    spine.workers[DIE_SHARD][0].join(30)
                    spine.senders[DIE_SHARD].queue.put((b"x", None))
                    for _ in range(300):
                        if spine.senders[DIE_SHARD].error is not None:
                            break
                        time.sleep(0.1)
                    self.assertIsNotNone(spine.senders[DIE_SHARD].error)
                rest = spine.ingest_group([(i, *files[i], prepared[i]) for i in range(8, 12)])
                self.assertTrue(all(isinstance(r, rb.FinancialIntegrityError) and ("shard_lost" in str(r) or "shard_send" in str(r)) for r in rest), rest)
                with self.assertRaises(rb.FinancialIntegrityError):
                    spine.close()  # the dead shard never ACKed: close says so, and stops what is left
            finally:
                timer.cancel()
                for p, _ in spine.workers.values():
                    if p.is_alive():
                        p.terminate()
            self.assertEqual(fired, [], name)  # no hang
            self.quiet(spine)
            work = self.tmp / name
            for k in (0, 2, 3):  # the other shards and the spine hold exactly the first group
                self.assertEqual(digests(work / f"shard{k}.sqlite3"), digests(clean / f"shard{k}.sqlite3"), (name, k))
            self.assertEqual(digests(work / "spine.sqlite3"), digests(clean / "spine.sqlite3"), name)
            result = self.replay_identical(work, DIE_SHARD, name, 0 if after else 8)  # the dead shard comes back: committed already (after) or from the spine's records (before)
            self.assertEqual(result["owed"], not after, name)

    def test_s12_garbled_reply_to_an_abort_marks_the_shard_dead_and_the_rollback_and_the_undo_still_run(self) -> None:
        spine = self.spine_with(sb.shard_main, "s12-garbled")
        try:
            spine.c.execute("BEGIN IMMEDIATE")
            heads0, prev0, spine.keys["zz"] = dict(spine.heads), spine.prev_head, b"x"
            spine.heads, spine.prev_head = {}, b"y"
            spine.owed = {0: heads0[0], 2: heads0[2]}
            with mock.patch.object(spine, "reply", side_effect=[("ACK",), pickle.UnpicklingError("garbled")]):  # a one-tuple where the COMMIT's ACK is owed; an unreadable reply
                with self.assertRaises(rb.FinancialIntegrityError):
                    spine.fail(SimpleNamespace(sent={0, 2}), ["zz"], heads0, prev0)
            self.assertEqual(sorted(spine.dead), [0, 2])
            self.assertFalse(spine.c.in_transaction)
            self.assertEqual((spine.heads, spine.prev_head, "zz" in spine.keys), (heads0, prev0, False))
        finally:
            for p, _ in spine.workers.values():
                p.terminate()
            with self.assertRaises(rb.FinancialIntegrityError):
                spine.close()
        self.quiet(spine)

    def test_s12_a_shard_that_cannot_open_its_database_fails_the_spine_start_without_a_hang_or_a_leaked_process(self) -> None:
        with mock.patch.object(sb, "REPLY_DEADLINE", 20.0), self.assertRaisesRegex(rb.FinancialIntegrityError, "shard_refused"):
            self.spine_with(unreadable_db_main, "s12-start")
        self.quiet()

    def test_s12_sender_switch_accepts_only_0_and_1(self) -> None:
        for value, expected in (("0", False), ("1", True)):
            with mock.patch.dict(os.environ, {"RR_SHARD_SENDER": value}):
                self.assertEqual(sb.sender_on(), expected)
        for value in ("", "true", "yes", "1 ", "2"):
            with mock.patch.dict(os.environ, {"RR_SHARD_SENDER": value}), self.assertRaises(ValueError):
                sb.sender_on()

    def test_s12_abort_with_parts_still_queued_leaves_the_pre_state_and_a_retry_equals_the_clean_run(self) -> None:
        files = sb.corpus(20261006, LINES, 4)
        clean, _, _ = self.group_run("s12-abort-clean", files[:2], 1)
        spine = self.spine_with(sb.shard_main, "s12-abort")
        timer, fired = self.watchdog(spine)
        gate, seen, calls = threading.Event(), [], [0]
        try:
            for sender in spine.senders.values():
                sender.conn = Gated(sender.conn, gate)  # every PART waits in its sender; what the spine enqueues next stays behind it
            before = self.all_digests(self.tmp / "s12-abort")
            real_send, real_rows = spine.send, spine.write_rows

            def send(k, message):
                real_send(k, message)
                if message[0] == "ABORT":
                    seen.append((k, spine.senders[k].queue.qsize(), gate.is_set()))

            def write_rows(*args, **kwargs):
                calls[0] += 1
                if calls[0] == 2:  # the second file of the group fails in the spine while the first file's PARTs are unwritten
                    threading.Timer(0.5, gate.set).start()
                    raise rb.FinancialIntegrityError("forced_spine_rows")
                return real_rows(*args, **kwargs)

            spine.send, spine.write_rows = send, write_rows
            prepared = [sb.prepare(spine.tbl, i, r.rows, i + 1) for i, (r, _) in enumerate(files[:2])]
            results = spine.ingest_group([(i, *files[i], prepared[i]) for i in range(2)])  # fails whole (ABORTs behind the PARTs), then one file at a time
            self.assertTrue(seen and all(size >= 1 and not opened for _, size, opened in seen), seen)  # the ABORTs really queued behind unwritten PARTs
            self.assertTrue(all(isinstance(r, dict) for r in results), results)  # the retries, one file at a time, went in
            self.assertNotEqual(self.all_digests(self.tmp / "s12-abort"), before)
            self.assertEqual(spine.groups, [1, 1])
            spine.close()
        finally:
            gate.set()
            timer.cancel()
            for p, _ in spine.workers.values():
                if p.is_alive():
                    p.terminate()
        self.assertEqual(fired, [])
        self.quiet(spine)
        self.assertEqual(self.all_digests(self.tmp / "s12-abort"), self.all_digests(clean))  # the abort left nothing behind: the retry stored what a clean run stores
        self.replay_identical(self.tmp / "s12-abort", 3, "s12-abort")

    def test_s12_a_failed_write_is_raised_before_anything_commits_and_close_stops_everything(self) -> None:
        files = sb.corpus(20261006, LINES, 2)
        spine = self.spine_with(sb.shard_main, "s12-send")
        timer, fired = self.watchdog(spine)
        try:
            before = self.all_digests(self.tmp / "s12-send")
            spine.senders[1].conn = Broken()
            prepared = [sb.prepare(spine.tbl, i, r.rows, i + 1) for i, (r, _) in enumerate(files)]
            results = spine.ingest_group([(i, *files[i], prepared[i]) for i in range(2)])
            self.assertTrue(all(isinstance(r, rb.FinancialIntegrityError) and "shard_send:1" in str(r) for r in results), results)
            self.assertEqual((spine.n, spine.keys), (0, {}))
            self.assertEqual(self.all_digests(self.tmp / "s12-send"), before)  # nothing committed anywhere
            with self.assertRaises(rb.FinancialIntegrityError):
                spine.close()
        finally:
            timer.cancel()
            for p, _ in spine.workers.values():
                if p.is_alive():
                    p.terminate()
        self.assertEqual(fired, [])
        self.quiet(spine)

    def test_s12_a_refused_commit_is_a_named_error_never_a_hang_and_a_wrong_commit_ack_in_abort_is_diverged(self) -> None:
        files = sb.corpus(20261007, LINES, 12)
        for on in (True, False):
            for mode in ("pump", "abort", "diverged"):
                name = f"s12-refuse-{int(on)}-{mode}"
                spine = self.spine_with(wrong_ack_main if mode == "diverged" else refuse_commit_main, name, on)
                timer, fired = self.watchdog(spine)
                try:
                    prepared = [sb.prepare(spine.tbl, i, r.rows, i + 1) for i, (r, _) in enumerate(files)]
                    first = spine.ingest_group([(i, *files[i], prepared[i]) for i in range(8)])  # the spine commits; shard 1 is told to commit and refuses (or ACKs a wrong head)
                    self.assertTrue(all(isinstance(r, dict) for r in first), (name, first))
                    if mode != "pump":  # the next group fails in the spine while shard 1's reply to COMMIT is in flight: the abort reads it
                        real_rows, calls = spine.write_rows, [0]

                        def write_rows(*args, **kwargs):
                            calls[0] += 1
                            if calls[0] == 1:
                                raise rb.FinancialIntegrityError("forced_spine_rows")
                            return real_rows(*args, **kwargs)

                        spine.write_rows = write_rows
                    rest_items = [(i, *files[i], prepared[i]) for i in range(8, 12)]
                    if mode == "diverged":
                        with self.assertRaises(sb.ShardDiverged):
                            spine.ingest_group(rest_items)
                        self.assertEqual((spine.n, spine.keys), (8, directory(self.tmp / name / "spine.sqlite3")))  # the failed group left no trace in the spine or its keys
                        self.assertEqual(list(spine.dead), list(range(4)), name)  # a shard that ACKed a head the spine did not expect: every shard is dead, the run is over
                        with self.assertRaises(rb.FinancialIntegrityError):  # S12-CLOSE M1: close() used to return the STATS of a run whose shard had diverged
                            spine.close()
                    else:
                        rest = spine.ingest_group(rest_items)
                        self.assertTrue(all(isinstance(r, rb.FinancialIntegrityError) and "shard_commit_refused:1" in str(r) for r in rest), (name, rest))
                        self.assertEqual(list(spine.dead), [DIE_SHARD], name)
                        with self.assertRaises(rb.FinancialIntegrityError) as raised:
                            spine.close()
                        self.assertIn("shard_commit_refused:1", str(raised.exception), name)
                finally:
                    timer.cancel()
                    for p, _ in spine.workers.values():
                        if p.is_alive():
                            p.terminate()
                self.assertEqual(fired, [], name)  # no hang
                self.quiet(spine)
                if mode != "diverged":
                    self.assertTrue(self.replay_identical(self.tmp / name, DIE_SHARD, name, 8)["owed"], name)  # the refusing shard comes back from the spine's records

    def test_s12_a_silent_shard_ends_snapshot_and_abort_in_a_named_error_at_the_deadline(self) -> None:
        files = sb.corpus(20261006, LINES, 2)
        # sender 0 has no write deadline (a write to a worker that does not read blocks on Windows): here the stuck worker has read its PART, so the small ABORT and SNAPSHOT writes complete and the reply deadline is what ends each wait
        for on, step in ((True, "snapshot"), (True, "abort"), (True, "built"), (False, "snapshot"), (False, "abort"), (False, "built")):
            name = f"s12-stuck-{int(on)}-{step}"
            spine = self.spine_with(stuck_main, name, on)
            timer, fired = self.watchdog(spine)
            try:
                with mock.patch.object(sb, "REPLY_DEADLINE", 1.0):
                    if step == "snapshot":
                        with self.assertRaises(rb.FinancialIntegrityError) as raised:
                            spine.snapshot(1, self.tmp / f"{name}-snapshot.sqlite3")
                        self.assertIn("snapshot_timeout:1", str(raised.exception), name)
                        self.assertEqual(list(spine.dead), [1], name)
                    else:
                        if step == "abort":
                            spine.write_rows = mock.Mock(side_effect=rb.FinancialIntegrityError("forced_spine_rows"))  # PARTs are out and never answered; the abort gets no ACK
                        results = spine.ingest_group([(0, *files[0], sb.prepare(spine.tbl, 0, files[0][0].rows, 1))])
                        expected = "shard_reply_timeout" if step == "abort" else "reply_timeout:["  # built: the spine's own wait for the parts ends at the deadline
                        self.assertTrue(isinstance(results[0], rb.FinancialIntegrityError) and str(results[0]).startswith(expected), (name, results))
                        self.assertTrue(spine.dead, name)
                        self.assertEqual((spine.n, spine.keys), (0, {}), name)
                    with self.assertRaises(rb.FinancialIntegrityError):  # the silent shard is dead: close stops the workers itself, never waits for a STATS
                        spine.close()
            finally:
                timer.cancel()
                for p, _ in spine.workers.values():
                    if p.is_alive():
                        p.terminate()
                        p.join()
            self.assertEqual(fired, [], name)
            self.quiet(spine)

    def test_s12_close_6a_a_commit_that_never_acks_ends_wait_acks_at_the_deadline(self) -> None:
        files = sb.corpus(20261006, LINES, 2)
        spine = self.spine_with(slow_commit_main, "s12-6a")
        timer, fired = self.watchdog(spine)
        try:
            with mock.patch.object(sb, "REPLY_DEADLINE", 1.0):
                prepared = sb.prepare(spine.tbl, 0, files[0][0].rows, 1)
                self.assertIn(1, prepared.blobs)  # shard 1 is asked to commit and never answers
                results = spine.ingest_group([(0, *files[0], prepared)])
                self.assertTrue(all(isinstance(r, dict) for r in results), results)
                with self.assertRaises(rb.FinancialIntegrityError) as raised:
                    spine.wait_acks()
                self.assertTrue(str(raised.exception).startswith("reply_timeout:[1]"), str(raised.exception))
                self.assertEqual(list(spine.dead), [1])
                with self.assertRaises(rb.FinancialIntegrityError):
                    spine.close()
        finally:
            timer.cancel()
            for p, _ in spine.workers.values():
                if p.is_alive():
                    p.terminate()
        self.assertEqual(fired, [])
        self.quiet(spine)

    def test_s12_close_6b_a_diverged_ack_wins_over_a_timeout_raised_in_the_same_abort(self) -> None:
        files = sb.corpus(20261006, LINES, 2)
        spine = self.spine_with(wrong_ack_and_stuck_main, "s12-6b")
        timer, fired = self.watchdog(spine)
        try:
            with mock.patch.object(sb, "REPLY_DEADLINE", 1.0):
                prepared = [sb.prepare(spine.tbl, i, r.rows, i + 1) for i, (r, _) in enumerate(files)]
                self.assertTrue({0, DIE_SHARD} <= set(prepared[0].blobs) and {0, DIE_SHARD} <= set(prepared[1].blobs))
                first = spine.ingest_group([(0, *files[0], prepared[0])])  # the spine commits; shard 1's ACK will carry a wrong head
                self.assertTrue(isinstance(first[0], dict), first)
                spine.write_rows = mock.Mock(side_effect=rb.FinancialIntegrityError("forced_spine_rows"))
                with self.assertRaises(sb.ShardDiverged):  # abort: shard 0 (first) times out, then shard 1's pending wrong ACK is read: the divergence is the error
                    spine.ingest_group([(1, *files[1], prepared[1])])
                self.assertEqual(list(spine.dead), list(range(4)))
                with self.assertRaises(rb.FinancialIntegrityError):
                    spine.close()
        finally:
            timer.cancel()
            for p, _ in spine.workers.values():
                if p.is_alive():
                    p.terminate()
        self.assertEqual(fired, [])
        self.quiet(spine)

    def test_s12_close_the_sender_thread_is_the_default_so_a_silent_shard_cannot_block_the_spine_in_a_write(self) -> None:
        with mock.patch.dict(os.environ):
            os.environ.pop("RR_SHARD_SENDER", None)
            self.assertTrue(sb.sender_on())
            spine = sb.Spine(self.tmp / "s12-default", 2, self.template)
            try:
                self.assertEqual(sorted(spine.senders), [0, 1])
            finally:
                spine.close()
            os.environ["RR_SHARD_SENDER"] = "0"
            self.assertFalse(sb.sender_on())  # still there, for tests and the bench: no write deadline
        self.quiet()

    def test_s12_close_a_failure_in_start_or_after_the_loop_leaves_no_shard_alive_and_a_silent_stop_ends_at_the_deadline(self) -> None:
        files = sb.corpus(20261006, LINES, 2)
        real = sb.shard_main
        sb.shard_main = refuse_ready_main  # L3: Spine() itself fails once some shards are running
        try:
            with self.assertRaises(rb.FinancialIntegrityError) as raised:
                sb.Spine(self.tmp / "s12-start", 3, self.template)
        finally:
            sb.shard_main = real
        self.assertIn("shard_refused:forced_ready", str(raised.exception))
        self.quiet()
        with mock.patch.object(sb.PrepPool, "close", side_effect=rb.FinancialIntegrityError("forced_prep_close")):  # L3: the run's own end fails, after the loop
            with self.assertRaises(rb.FinancialIntegrityError) as raised:
                sb.run_once(2, files, self.template, self.tmp / "s12-run-end", False, 2)
        self.assertEqual(str(raised.exception), "forced_prep_close")
        self.quiet()
        spine = self.spine_with(stats_stuck_main, "s12-stop")  # L2: close() waits for a STATS the shard never sends
        timer, fired = self.watchdog(spine, 20)
        try:
            with mock.patch.object(sb, "REPLY_DEADLINE", 1.0):
                with self.assertRaises(rb.FinancialIntegrityError) as raised:
                    spine.close()
            self.assertTrue(str(raised.exception).startswith("stats_timeout:"), str(raised.exception))
        finally:
            timer.cancel()
            for p, _ in spine.workers.values():
                if p.is_alive():
                    p.terminate()
        self.assertEqual(fired, [])
        self.quiet(spine)

    def test_s12_close_a_failure_from_the_spine_commit_on_ends_the_run_and_no_shard_holds_a_group_the_spine_lost(self) -> None:
        files = sb.corpus(20261006, LINES, 4)
        clean = self.all_digests(self.group_run("s12-post-clean", files[:2], 2)[0])  # what the first group alone stores
        for on in (False, True):
            for fault in ("spine", "pipe"):
                name = f"s12-post-{int(on)}-{fault}"
                spine = self.spine_with(sb.shard_main, name, on)
                timer, fired = self.watchdog(spine)
                try:
                    before = self.all_digests(self.tmp / name)
                    prepared = [sb.prepare(spine.tbl, i, r.rows, i + 1) for i, (r, _) in enumerate(files)]
                    items = [(i, *files[i], prepared[i]) for i in range(4)]
                    if fault == "spine":
                        spine.c = FailingCommit(spine.c)
                    else:  # shard 1's COMMIT is never written (sender 0: in the spine's call; sender 1: in its thread): the same connection either way
                        conn = spine.workers[1][1]

                        def send_bytes(buf, real=conn.send_bytes) -> None:
                            if sb.decode(bytes(buf)) == ("COMMIT",):
                                raise BrokenPipeError("forced_commit_send")
                            real(buf)

                        conn.send_bytes = send_bytes
                    if on and fault == "pipe":  # the thread fails after the spine's call returned: the next group finds it
                        first = spine.ingest_group(items[:2])
                        self.assertTrue(all(isinstance(r, dict) for r in first), (name, first))
                        reason = "shard_send:1:BrokenPipeError('forced_commit_send')"
                    else:
                        with self.assertRaises(sb.GroupCommitFailed) as raised:  # never retried one file at a time
                            spine.ingest_group(items[:2])
                        reason = "group_commit_failed:" + ("OperationalError('database or disk is full')" if fault == "spine" else "BrokenPipeError('forced_commit_send')")
                        self.assertEqual(str(raised.exception), reason, name)
                    rest = spine.ingest_group(items[2:])
                    self.assertTrue(all(isinstance(r, rb.FinancialIntegrityError) and str(r) == reason for r in rest), (name, rest))
                    self.assertEqual(spine.dead, {1: reason} if on and fault == "pipe" else dict.fromkeys(range(4), reason), name)  # nothing more goes in: the shard whose write failed is dead, or after a failed spine commit every shard
                    with self.assertRaises(rb.FinancialIntegrityError) as closed:
                        spine.close()
                    self.assertEqual(str(closed.exception), reason, name)
                finally:
                    timer.cancel()
                    for p, _ in spine.workers.values():
                        if p.is_alive():
                            p.terminate()
                self.assertEqual(fired, [], name)  # no hang
                self.quiet(spine)
                now = self.all_digests(self.tmp / name)
                if fault == "spine":
                    self.assertEqual(now, before, name)  # the spine lost the group and no shard committed it
                    continue
                self.assertEqual(now["spine.sqlite3"], clean["spine.sqlite3"], name)
                self.assertEqual(now["shard1.sqlite3"], before["shard1.sqlite3"], name)  # shard 1 never got its COMMIT
                for k in range(4):  # a shard told to commit may have been stopped before its commit ended: either way replay brings each to the spine's head
                    self.assertIn(now[f"shard{k}.sqlite3"], (before[f"shard{k}.sqlite3"], clean[f"shard{k}.sqlite3"]), (name, k))
                    if on and fault == "pipe" and k != 1:  # the healthy shards were drained, not stopped inside their COMMIT
                        self.assertEqual(now[f"shard{k}.sqlite3"], clean[f"shard{k}.sqlite3"], (name, k))
                    self.replay_identical(self.tmp / name, k, name)

    def test_s12_close_drains_a_healthy_shard_before_stopping_it_when_the_failure_starts_in_close(self) -> None:
        files = sb.corpus(20261006, LINES, 2)
        clean = self.all_digests(self.group_run("s12-drain-clean", files, 2)[0])
        spine = self.spine_with(gated_commit_main, "s12-drain")
        timer, fired = self.watchdog(spine)
        try:
            before = self.all_digests(self.tmp / "s12-drain")
            conn, real_reply = spine.workers[1][1], spine.reply

            def send_bytes(buf, real=conn.send_bytes) -> None:  # shard 1's COMMIT is never written: the failure is found in close, on the last group
                if sb.decode(bytes(buf)) == ("COMMIT",):
                    raise BrokenPipeError("forced_commit_send")
                real(buf)

            def reply(k, deadline):  # the shards hold their COMMIT until the drain, and only the drain, reads a reply
                (self.tmp / "s12-drain" / "gate").touch()
                return real_reply(k, deadline)

            conn.send_bytes, spine.reply = send_bytes, reply
            prepared = [sb.prepare(spine.tbl, i, r.rows, i + 1) for i, (r, _) in enumerate(files)]
            first = spine.ingest_group([(i, *files[i], prepared[i]) for i in range(2)])
            self.assertTrue(all(isinstance(r, dict) for r in first), first)
            with self.assertRaises(rb.FinancialIntegrityError) as closed:
                spine.close()
            self.assertIn("shard_send:1", str(closed.exception))
        finally:
            timer.cancel()
            for p, _ in spine.workers.values():
                if p.is_alive():
                    p.terminate()
        self.assertEqual(fired, [])
        self.quiet(spine)
        now = self.all_digests(self.tmp / "s12-drain")
        for k in (0, 2, 3):
            self.assertNotEqual(clean[f"shard{k}.sqlite3"], before[f"shard{k}.sqlite3"], k)  # the group does reach this shard: the next check is not vacuous
            self.assertEqual(now[f"shard{k}.sqlite3"], clean[f"shard{k}.sqlite3"], k)

    def test_s12_close_names_every_shard_the_drain_lost_to_the_caller(self) -> None:
        files = sb.corpus(20261007, LINES, 4)
        with self.sender_env(True), mock.patch.object(sb, "shard_main", die_and_refuse_main):
            with self.assertRaises(rb.FinancialIntegrityError) as raised:  # the last group commits; shard 1 dies in its COMMIT and shard 0 refuses its own
                sb.run_once(4, files, self.template, self.tmp / "s12-drain-lost", False, 1)
        self.assertRegex(str(raised.exception), r"shard_commit_refused:0.*shard_(lost|reply|send):1")
        self.quiet()

    def test_s12_close_raises_shard_diverged_for_a_wrong_head_found_in_the_drain(self) -> None:
        files = sb.corpus(20261007, LINES, 2)
        spine = self.spine_with(wrong_ack_main, "s12-drain-diverged")
        timer, fired = self.watchdog(spine)
        try:
            prepared = [sb.prepare(spine.tbl, i, r.rows, i + 1) for i, (r, _) in enumerate(files)]
            first = spine.ingest_group([(i, *files[i], prepared[i]) for i in range(2)])
            self.assertTrue(all(isinstance(r, dict) for r in first), first)  # the spine committed; shard 1's ACK will carry a wrong head
            with mock.patch.object(spine, "wait_acks", side_effect=rb.FinancialIntegrityError("forced_wait")):  # the failure is in close, before any ACK is read
                with self.assertRaises(sb.ShardDiverged) as raised:
                    spine.close()
            self.assertIsInstance(raised.exception.__cause__, rb.FinancialIntegrityError)
            self.assertEqual(list(spine.dead), list(range(4)))
        finally:
            timer.cancel()
            for p, _ in spine.workers.values():
                if p.is_alive():
                    p.terminate()
        self.assertEqual(fired, [])
        self.quiet(spine)

    def owed_spine(self, name: str, errors: tuple) -> "sb.Spine":
        """A spine whose group is committed and whose shards still hold their COMMIT (gated); the senders of `errors` have failed, as a thread records a dead pipe."""
        files = sb.corpus(20261006, LINES, 2)
        spine = self.spine_with(gated_commit_main, name)
        prepared = [sb.prepare(spine.tbl, i, r.rows, i + 1) for i, (r, _) in enumerate(files)]
        first = spine.ingest_group([(i, *files[i], prepared[i]) for i in range(2)])
        self.assertTrue(all(isinstance(r, dict) for r in first), first)
        self.assertTrue({1, 2} <= set(spine.owed), spine.owed)
        for k in errors:
            spine.senders[k].error = BrokenPipeError(f"forced_{k}")
        return spine

    def test_of4_close_names_every_owed_shard_whose_sender_failed_not_only_the_first(self) -> None:
        for name, errors, owed, gate in (("of4-two-dead", (1, 2), None, True), ("of4-non-owed-first", (0, 2), (2,), False)):
            spine = self.owed_spine(name, errors)
            timer, fired = self.watchdog(spine)
            try:
                if owed:  # only shard 2 owes a COMMIT; shard 0, which owes none, fails first
                    spine.owed = {k: v for k, v in spine.owed.items() if k in owed}
                if gate:
                    (self.tmp / name / "gate").touch()
                with self.assertRaises(rb.FinancialIntegrityError) as raised:
                    spine.close()
                for k in (k for k in errors if k in (owed or errors)):
                    self.assertIn(f"shard_send:{k}:BrokenPipeError('forced_{k}')", str(raised.exception), name)
                self.assertEqual(sorted(spine.dead), sorted(owed or errors), name)
            finally:
                timer.cancel()
                for p, _ in spine.workers.values():
                    if p.is_alive():
                        p.terminate()
            self.assertEqual(fired, [], name)
            self.quiet(spine)

    def test_of4_ctrl_c_in_close_with_a_lost_shard_stays_ctrl_c_with_the_lost_shards_in_a_note(self) -> None:
        spine = self.spine_with(sb.shard_main, "of4-ctrl-c")

        def check_senders() -> None:
            spine.dead[1] = "shard_send:1:forced"
            raise KeyboardInterrupt

        with mock.patch.object(spine, "check_senders", check_senders), self.assertRaises(KeyboardInterrupt) as raised:
            spine.close()
        self.assertEqual(raised.exception.__notes__, ["shard_send:1:forced"])
        self.quiet(spine)

        def attempt(self, *args, **kwargs) -> None:  # run_once: Ctrl-C with a lost shard; close raises its own error, the interrupt is what the caller gets
            self.dead[1] = "shard_send:1:forced"
            raise KeyboardInterrupt

        with mock.patch.object(sb.Spine, "attempt", attempt), self.assertRaises(KeyboardInterrupt) as raised:
            sb.run_once(2, sb.corpus(20261006, LINES, 2), self.template, self.tmp / "of4-ctrl-c-run", False, 1)
        self.assertEqual(raised.exception.__notes__, ["shard_send:1:forced"])
        self.quiet()

    def test_of4_run_once_keeps_shard_diverged_when_another_shard_refused_in_the_same_abort(self) -> None:
        files, real, calls = sb.corpus(20261007, LINES, 4), sb.Spine.ingest_group, []

        def ingest_group(self, items):  # one file per group; the second group fails in the spine while shard 1's refusal and shard 2's wrong ACK of the first group are in flight
            results = []
            for item in items:
                calls.append(1)
                if len(calls) == 2:
                    self.write_rows = mock.Mock(side_effect=rb.FinancialIntegrityError("forced_spine_rows"))
                results += real(self, [item])
            return results

        with self.sender_env(True), mock.patch.object(sb, "shard_main", refuse_and_wrong_ack_main), mock.patch.object(sb.Spine, "ingest_group", ingest_group):
            with self.assertRaises(sb.ShardDiverged) as raised:
                sb.run_once(4, files, self.template, self.tmp / "of4-diverged", False, 1)
        self.assertRegex(str(raised.exception), r"shard 2: head differs after commit.*shard_commit_refused:1")
        self.assertIsInstance(raised.exception.__cause__, rb.FinancialIntegrityError)
        self.quiet()

    def test_of4_run_once_names_a_shard_the_drain_lost_when_cleanup_then_raises(self) -> None:
        files, real, real_ingest, calls = sb.corpus(20261007, LINES, 4), rb.Checkpointer.close, sb.Spine.ingest_group, []

        def close(self) -> None:
            real(self)
            raise sqlite3.OperationalError("forced_cleanup")

        def ingest_group(self, items):  # one file per group; the second group fails at once, while shard 1's COMMIT of the first is owed and shard 1 is dying in it
            results = []
            for item in items:
                calls.append(1)
                if len(calls) == 2:
                    raise rb.FinancialIntegrityError("forced_group")
                results += real_ingest(self, [item])
            return results

        with self.sender_env(True), mock.patch.object(sb, "shard_main", die_before_commit_main), mock.patch.object(sb.Spine, "ingest_group", ingest_group), mock.patch.object(rb.Checkpointer, "close", close):
            with self.assertRaises(rb.FinancialIntegrityError) as raised:  # the drain at close loses shard 1; the cleanup then raises another message
                sb.run_once(4, files, self.template, self.tmp / "of4-cleanup", False, 1)
        self.assertRegex(str(raised.exception), r"shard_(lost|reply|send):1")
        self.assertIsInstance(raised.exception.__cause__, sqlite3.OperationalError)
        self.quiet()

    def test_of4_ctrl_c_in_the_close_drain_names_every_owing_shard_and_reraises(self) -> None:  # FIX4b MEDIUM-1: the interrupt goes on with the shards it left owing
        spine = self.owed_spine("of4-drain-ctrlc", ())
        timer, fired = self.watchdog(spine)
        try:
            owing = sorted(spine.owed)
            with mock.patch.object(spine, "wait_acks", side_effect=rb.FinancialIntegrityError("forced_wait")), mock.patch.object(spine, "reply", side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt) as raised:
                    spine.close()
            self.assertEqual(sorted(spine.dead), owing)
            note = " ".join(raised.exception.__notes__)
            for k in owing:
                self.assertIn(f"shard_unconfirmed:{k}", note)
        finally:
            timer.cancel()
            for p, _ in spine.workers.values():
                if p.is_alive():
                    p.terminate()
        self.assertEqual(fired, [])
        self.quiet(spine)

    def group_two_fails_with_a_wrong_ack(self, out: str, cleanup=None) -> None:
        """run_once over four files: the second group fails in the spine while shard 1 ACKs a wrong head, so the divergence is found only in close's drain."""
        files, real_ingest, calls = sb.corpus(20261007, LINES, 4), sb.Spine.ingest_group, []

        def ingest_group(self, items):
            results = []
            for item in items:
                calls.append(1)
                if len(calls) == 2:
                    raise rb.FinancialIntegrityError("forced_group")
                results += real_ingest(self, [item])
            return results

        with self.sender_env(True), mock.patch.object(sb, "shard_main", wrong_ack_main), mock.patch.object(sb.Spine, "ingest_group", ingest_group), mock.patch.object(rb.Checkpointer, "close", cleanup or rb.Checkpointer.close):
            sb.run_once(4, files, self.template, self.tmp / out, False, 1)

    def test_of4_run_once_raises_shard_diverged_when_close_finds_the_wrong_head_after_another_error(self) -> None:  # FIX4b LOW-2
        with self.assertRaises(sb.ShardDiverged) as raised:
            self.group_two_fails_with_a_wrong_ack("of4-close-diverged")
        self.assertRegex(str(raised.exception), r"head differs after commit")
        self.quiet()

    def test_of4_run_once_stays_shard_diverged_when_checkpoint_cleanup_raises_after_the_wrong_head(self) -> None:  # FIX4b LOW-3
        real = rb.Checkpointer.close

        def close(self) -> None:
            real(self)
            raise sqlite3.OperationalError("forced_cleanup")

        with self.assertRaises(sb.ShardDiverged) as raised:
            self.group_two_fails_with_a_wrong_ack("of4-cleanup-diverged", close)
        self.assertRegex(str(raised.exception), r"head differs after commit")
        self.assertIsInstance(raised.exception.__cause__, sqlite3.OperationalError)
        self.quiet()

    def test_of4_check_senders_keeps_the_first_reason_a_shard_already_lost(self) -> None:  # FIX4b LOW-4
        spine = self.owed_spine("of4-first-reason", (1,))
        timer, fired = self.watchdog(spine)
        try:
            spine.dead[1] = "shard_commit_refused:1:first"
            with self.assertRaises(rb.FinancialIntegrityError):
                spine.check_senders()
            self.assertEqual(spine.dead[1], "shard_commit_refused:1:first")
            (self.tmp / "of4-first-reason" / "gate").touch()
            with self.assertRaises(rb.FinancialIntegrityError):
                spine.close()  # stops the senders and shards too: a test that leaves a sender thread alive fails every later quiet()
            self.assertEqual(spine.dead[1], "shard_commit_refused:1:first")
        finally:
            timer.cancel()
            for p, _ in spine.workers.values():
                if p.is_alive():
                    p.terminate()
        self.assertEqual(fired, [])
        self.quiet(spine)

    def test_s12_close_an_abort_that_cannot_be_written_still_rolls_the_spine_back(self) -> None:
        files = sb.corpus(20261006, LINES, 2)
        spine = self.spine_with(sb.shard_main, "s12-abort-send", False)
        timer, fired = self.watchdog(spine)
        try:
            before = self.all_digests(self.tmp / "s12-abort-send")
            conn = spine.workers[1][1]

            def send_bytes(buf, real=conn.send_bytes) -> None:
                if sb.decode(bytes(buf)) == ("ABORT",):
                    raise BrokenPipeError("forced_abort_send")
                real(buf)

            conn.send_bytes = send_bytes
            spine.write_rows = mock.Mock(side_effect=rb.FinancialIntegrityError("forced_spine_rows"))
            prepared = [sb.prepare(spine.tbl, i, r.rows, i + 1) for i, (r, _) in enumerate(files)]
            results = spine.ingest_group([(i, *files[i], prepared[i]) for i in range(2)])
            reason = "shard_send:1:BrokenPipeError('forced_abort_send')"
            self.assertTrue(all(isinstance(r, rb.FinancialIntegrityError) and str(r) == reason for r in results), results)  # the retries meet the dead shard
            self.assertEqual((spine.n, spine.keys, spine.dead), (0, {}, {1: reason}))
            self.assertFalse(spine.c.in_transaction)  # the rollback ran
            with self.assertRaises(rb.FinancialIntegrityError):
                spine.close()
        finally:
            timer.cancel()
            for p, _ in spine.workers.values():
                if p.is_alive():
                    p.terminate()
        self.assertEqual(fired, [])
        self.quiet(spine)
        self.assertEqual(self.all_digests(self.tmp / "s12-abort-send"), before)

    def test_s12_close_run_once_stops_every_process_on_an_error(self) -> None:
        files = sb.corpus(20261006, LINES, 2)
        with mock.patch.object(sb.Spine, "attempt", side_effect=rb.FinancialIntegrityError("forced_attempt")):
            with self.assertRaises(rb.FinancialIntegrityError) as raised:
                sb.run_once(2, files, self.template, self.tmp / "s12-run-error", False, 2)
        self.assertEqual(str(raised.exception), "forced_attempt")
        self.quiet()

    def test_s12_snapshot_raises_a_failed_write_at_once(self) -> None:
        spine = self.spine_with(sb.shard_main, "s12-snap-send")
        timer, fired = self.watchdog(spine)
        try:
            spine.senders[1].conn = Broken()
            with self.assertRaises(rb.FinancialIntegrityError) as raised:
                spine.snapshot(1, self.tmp / "s12-snap-send.sqlite3")
            self.assertIn("shard_send:1", str(raised.exception))
            with self.assertRaises(rb.FinancialIntegrityError):
                spine.close()
        finally:
            timer.cancel()
            for p, _ in spine.workers.values():
                if p.is_alive():
                    p.terminate()
        self.assertEqual(fired, [])
        self.quiet(spine)

    def test_s12_an_io_error_that_already_rolled_the_spine_back_is_the_error_raised_and_leaves_no_keys(self) -> None:
        files = sb.corpus(20261006, LINES, 2)
        clean = self.group_run("s12-h1-clean", files, 2)[1]
        for items, name in ((2, "s12-h1-group"), (1, "s12-h1-one")):
            spine = self.spine_with(sb.shard_main, name)
            timer, fired = self.watchdog(spine)
            try:
                spine.c = AutoRolledBack(spine.c)
                prepared = [sb.prepare(spine.tbl, i, r.rows, i + 1) for i, (r, _) in enumerate(files)]
                results = spine.ingest_group([(i, *files[i], prepared[i]) for i in range(items)])
                if items == 1:  # the first error, not "cannot rollback - no transaction is active", and the failed file's cells are not kept
                    self.assertTrue(isinstance(results[0], sqlite3.OperationalError) and "disk I/O error" in str(results[0]), results)
                    self.assertEqual((spine.n, spine.keys), (0, {}))
                else:  # the group is retried one file at a time against clean keys: each file gets the classes of the clean run
                    self.assertEqual(results, clean)
                spine.close()
            finally:
                timer.cancel()
                for p, _ in spine.workers.values():
                    if p.is_alive():
                        p.terminate()
            self.assertEqual(fired, [], name)
            self.quiet(spine)

    def test_s12_part_frame_with_trailing_bytes_a_short_blob_or_shifted_lengths_is_rejected(self) -> None:
        record, _ = self.files[0]
        pool = f"x12/SYNTHPAYER/{record.trace_origin}/{record.trace}"
        p = sb.prepare(sb.tables(self.template, 1), 0, record.rows, 1)
        work = self.tmp / "s12-frame"
        work.mkdir()
        shutil.copyfile(self.template, work / "s.sqlite3")
        shard = sb.Shard(0, work / "s.sqlite3")
        message = ("PART", 1, 0, pool, sb.T0_MS, p.blobs[0], shard.w.head, p.verdicts[0])
        buf = sb.encode(message)
        self.assertEqual(sb.decode(buf), message)
        for name, bad in (("trailing byte", buf + b"x"), ("short blob", buf[:-1]), ("empty blob", buf[:-len(p.blobs[0])])):
            with self.assertRaises(ValueError, msg=name):
                sb.decode(bad)
        fields, rest = list(sb.PART_HEAD.unpack_from(buf)), buf[sb.PART_HEAD.size:]
        for at, delta in ((4, 1), (4, -1), (5, 1), (5, -1), (6, 1), (6, -1), (7, 1), (7, -1)):  # one length moved: the total no longer matches the frame
            moved = fields.copy()
            moved[at] += delta
            with self.assertRaises(ValueError, msg=(at, delta)):
                sb.decode(sb.PART_HEAD.pack(*moved) + rest)
        for at in (4, 5, 6):  # a boundary moved with the total kept: the frame decodes, but not to a part any shard builds
            moved = fields.copy()
            moved[at] += 1
            moved[at + 1] -= 1
            with self.assertRaises(Exception, msg=at):
                shard.build(*sb.decode(sb.PART_HEAD.pack(*moved) + rest)[1:])
            self.assertFalse(shard.c.in_transaction)
        shard.stats()

    def test_s12_a_shard_that_built_from_other_bytes_fails_closed_with_the_sender_on_and_off(self) -> None:
        files = sb.corpus(20261006, LINES, 2)
        for on in (True, False):
            name = f"s12-liar-{int(on)}"
            spine = self.spine_with(liar_main, name, on)
            timer, fired = self.watchdog(spine)
            try:
                results = spine.ingest_group([(0, *files[0], sb.prepare(spine.tbl, 0, files[0][0].rows, 1))])
                self.assertTrue(isinstance(results[0], rb.FinancialIntegrityError) and "shard_blob_mismatch" in str(results[0]), (name, results))
                self.assertEqual(spine.c.execute("SELECT COUNT(*) FROM records").fetchone()[0], 0, name)  # nothing was recorded
                spine.close()
            finally:
                timer.cancel()
                for p, _ in spine.workers.values():
                    if p.is_alive():
                        p.terminate()
            self.assertEqual(fired, [], name)
            self.quiet(spine)

    def test_s12_a_pool_name_over_65535_bytes_is_refused_the_same_way_with_the_sender_on_and_off(self) -> None:
        record, deposit = self.files[0]
        for on in (True, False):
            for extra, refused in (("t", False), ("tt", True)):  # "x12/SYNTHPAYER/" + origin + "/" + trace is 65,535 bytes, then 65,536
                name = f"s12-pool-{int(on)}-{len(extra)}"
                spine = self.spine_with(sb.shard_main, name, on)
                timer, fired = self.watchdog(spine)
                try:
                    long_record = SimpleNamespace(rows=record.rows, trace_origin="o" * 65518, trace=extra)
                    result = spine.ingest_group([(0, long_record, deposit, sb.prepare(spine.tbl, 0, record.rows, 1))])[0]
                    if refused:
                        self.assertTrue(isinstance(result, rb.FinancialIntegrityError) and "pool_too_long" in str(result), (name, result))
                    else:
                        self.assertIsInstance(result, dict, name)
                    spine.close()
                finally:
                    timer.cancel()
                    for p, _ in spine.workers.values():
                        if p.is_alive():
                            p.terminate()
                self.assertEqual(fired, [], name)
                self.quiet(spine)

    def test_s12_blobs_over_the_pipe_buffer_store_the_same_with_the_sender_on_and_off(self) -> None:
        files = sb.corpus(20261006, 3000, 2)
        biggest = max(len(b) for r, _ in files[:1] for b in sb.prepare(sb.tables(self.template, 1), 0, r.rows, 1).blobs.values())
        self.assertGreater(biggest, 1 << 16)  # more than a pipe holds: the writer really waits on the shard
        runs = {}
        for on in (False, True):
            with self.sender_env(on):
                work = self.tmp / f"s12-big-{int(on)}"
                runs[on] = sb.run_once(1, files, self.template, work, True, 2)
            runs[on]["tables"] = {p.name: digests(p) for p in sorted(work.glob("*.sqlite3")) if p.name != "snapshot.sqlite3"}
            self.quiet()
        self.assertEqual(runs[False]["classes"], runs[True]["classes"])
        self.assertEqual(runs[False]["tables"], runs[True]["tables"])
        self.assertTrue(runs[False]["replay"]["identical"] and runs[True]["replay"]["identical"])


if __name__ == "__main__":
    unittest.main()
