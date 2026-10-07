"""OS-B0 shard harness (tools/r9_shard_bench.py): routing, merge equivalence with K=1, refusal and abort atomicity, resend, recovery replay."""

from __future__ import annotations

import hashlib
import os
import pickle
import shutil
import sqlite3
import tempfile
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

    def test_shard_check_refuses_a_stored_event_that_differs_from_the_built_one_and_a_broken_link(self) -> None:
        prep = sb.prepare(sb.tables(self.template, 1), 0, self.files[0][0].rows, 1)
        for fault in ("stored_digest", "broken_link"):
            work = self.tmp / f"check-{fault}"
            shutil.rmtree(work, ignore_errors=True)
            work.mkdir()
            shutil.copyfile(self.template, work / "s.sqlite3")
            shard = sb.Shard(0, work / "s.sqlite3")
            head, w = shard.w.head, shard.w
            real_write, real_mutate = w.write, w.mutate
            if fault == "stored_digest":  # the store holds a payload digest that mutate did not build
                w.write = lambda table, rows: real_write(table, [r[:8] + (bytes(64),) + r[9:] for r in rows] if table == "financial_events" else rows)
            else:  # the last built event does not link to the one before it (store and built agree, the link does not)
                def mutate(t, *args):
                    real_mutate(t, *args)
                    e = t["financial_events"][-1]
                    t["financial_events"][-1] = e[:9] + (bytes(64),) + e[10:]
                w.mutate = mutate
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

    def prewrite_run(self, on: bool, k: int, files: list, name: str) -> dict:
        """run_once with G1 on or off (spawned workers inherit the environment of the moment); the stores are returned as table digests, snapshot.sqlite3 excluded (its content depends on group timing)."""
        with mock.patch.dict(os.environ):
            os.environ.pop("RR_SHARD_PREWRITE", None)
            if on:
                os.environ["RR_SHARD_PREWRITE"] = "1"
            work = self.tmp / name
            r = sb.run_once(k, files, self.template, work, True, 2)
        r["tables"] = {p.name: digests(p) for p in sorted(work.glob("*.sqlite3")) if p.name != "snapshot.sqlite3"}
        r["pinned"] = [pinned(work / "spine.sqlite3", False)] + [pinned(work / f"shard{i}.sqlite3", True) for i in range(k)]
        return r

    def test_g1_prewrite_on_stores_exactly_what_off_stores_at_k1_8_12(self) -> None:
        for name, seed in (("FL", 20261006), ("DE", 20261007)):
            files, classes = sb.corpus(seed, LINES, 12), []
            for k in (1, 8, 12):
                off, on = self.prewrite_run(False, k, files, f"g1-{name}-{k}-off"), self.prewrite_run(True, k, files, f"g1-{name}-{k}-on")
                label = f"{name} K={k}"
                self.assertEqual(off["classes"], on["classes"], label)
                self.assertTrue(off["replay"]["identical"] and on["replay"]["identical"], label)
                self.assertEqual(off["tables"], on["tables"], label)  # every table of the spine and of each shard, records and heads included
                self.assertEqual(off["pinned"], on["pinned"], label)
                self.assertEqual((off["prewrite"]["shards"]["count"], off["prewrite"]["spine"]["count"]), (0, 0), label)  # off does nothing
                self.assertGreater(on["prewrite"]["shards"]["count"] + on["prewrite"]["spine"]["count"], 0, label)  # on really flushed
                classes.append(on["classes"])
            self.assertTrue(all(c == classes[0] for c in classes), name)  # the same per-class counts at every K

    def test_g1_crash_with_pushed_pages_leaves_the_committed_state_and_commit_applies_the_part(self) -> None:
        record, deposit = self.files[0]
        work = self.tmp / "g1-crash"
        work.mkdir()
        db = work / "shard0.sqlite3"
        shutil.copyfile(self.template, db)
        tbl = sb.tables(self.template, 1)
        p = sb.prepare(tbl, 0, record.rows, 1)
        shard = sb.Shard(0, db)
        shard.pre = sb.Prewriter(shard.c, db)
        before = digests(db)  # the committed state before the part
        shard.build(1, 0, f"x12/SYNTHPAYER/{record.trace_origin}/{record.trace}", sb.T0_MS, p.blobs[0], shard.w.head, p.verdicts[0])
        wal = Path(str(db) + "-wal")
        wal_before = wal.stat().st_size
        shard.prewrite(SimpleNamespace(poll=lambda timeout: False))
        self.assertEqual(shard.pre.count, 1)
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


if __name__ == "__main__":
    unittest.main()
