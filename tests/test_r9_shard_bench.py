"""OS-B0 shard harness (tools/r9_shard_bench.py): routing, merge equivalence with K=1, refusal and abort atomicity, resend, recovery replay."""

from __future__ import annotations

import hashlib
import pickle
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

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
            spine.ingest(position, record, deposit, prep.get(position) if prep else None)
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
                    self.assertEqual(pool.get(i), sb.prepare(tbl, i, record.rows, i + 1), (seed, i))  # blobs, verdicts, directory rows, digests
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


if __name__ == "__main__":
    unittest.main()
