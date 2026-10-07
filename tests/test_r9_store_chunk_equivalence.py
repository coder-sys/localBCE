"""PERF-B: the chunk-transaction store path (set-based dedup probe, key-order executemany, per-obligation writes once, checkpointer thread) writes
exactly what the per-row reference writes: every table digest, the event chain, the row classes, the hostile row's outcome, a crash before any
chunk's COMMIT, a WAL that was never checkpointed, and the checkpointer on or off. No timing asserts."""

import dataclasses
import hashlib
import shutil
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.x12_835_intake import Row, parse_835  # noqa: E402
from tools import r9_bench  # noqa: E402

PER_FILE, FILES = 300, 3


def digests(path: Path) -> dict[str, str]:
    """One SHA-256 per table over `SELECT * ORDER BY 1`, read through its own connection (sees committed state only)."""
    c = sqlite3.connect(str(path))
    try:
        tables = [r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
        return {t: hashlib.sha256(repr(c.execute(f"SELECT * FROM {t} ORDER BY 1").fetchall()).encode()).hexdigest() for t in tables}
    finally:
        c.close()


def chain_ok(path: Path, template: Path) -> bool:
    """The events the bench wrote recompute link by link from the template's last event, and financial_meta names the last one."""
    t = sqlite3.connect(str(template))
    last, head = t.execute("SELECT event_sequence,head FROM financial_events ORDER BY event_sequence DESC LIMIT 1").fetchone() or (0, bytes(64))
    t.close()
    c = sqlite3.connect(str(path))
    try:
        n = 0
        for seq, payload, digest, previous, this in c.execute("SELECT event_sequence,payload_json,payload_digest,previous_head,head FROM financial_events WHERE event_sequence>? ORDER BY event_sequence", (last,)):
            if seq != last + 1 or previous != head or digest != r9_bench.sha(payload) or this != r9_bench.sha(previous, digest):
                return False
            head, last, n = this, seq, n + 1
        meta = c.execute("SELECT sequence,history_head FROM financial_meta").fetchone()
        return n > 0 and meta[0] == last and meta[1] == head
    finally:
        c.close()


class StoreChunkEquivalence(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.template = Path(cls.tmp.name) / "template.sqlite3"
        r9_bench.make_owner_db(cls.template)
        cls.files = []
        for i in range(FILES):
            data, deposit = r9_bench.gen_file(i, 11, PER_FILE)
            cls.files.append((parse_835(data), deposit))
        record, deposit = cls.files[1]  # a hostile row mid-file, twice (the second is a duplicate), and a duplicate of a real row
        hostile = Row(key=("RAW", "x'); DELETE FROM cells; -- ☃"), amount_cents=None, raw="x'); DELETE FROM cells; --\x00☃" * 40, flags=("hostile",))
        rows = list(record.rows)
        mid = len(rows) // 2
        rows[mid:mid] = [hostile, hostile, rows[5]]
        cls.files[1] = (dataclasses.replace(record, rows=tuple(rows)), deposit)
        cls.hostile_origin = "1/RAW/" + hostile.key[1]

    def fresh(self, name: str) -> Path:
        path = Path(self.tmp.name) / f"{name}.sqlite3"
        shutil.copyfile(self.template, path)
        return path

    def ingest(self, name: str, fast: bool, checkpointer: bool, first: int = 0, hook=None, path: Path | None = None):
        path = path or self.fresh(name)
        c, w = r9_bench.open_store(path, fast, checkpointer)
        w.before_commit = hook
        try:
            for i in range(first, FILES):
                w.run_file(i, *self.files[i], [])
        finally:
            if w.ckpt:
                w.ckpt.close()
            c.close()
        return path, w

    def test_chunk_path_writes_what_the_reference_writes(self) -> None:
        ref_path, ref = self.ingest("ref", False, False)
        want = digests(ref_path)
        self.assertTrue(chain_ok(ref_path, self.template))
        for name, checkpointer in (("fast_ckpt", True), ("fast_plain", False)):  # the checkpointer on and off
            path, w = self.ingest(name, True, checkpointer)
            self.assertEqual(digests(path), want, name)
            self.assertEqual((w.classes, w.tally), (ref.classes, ref.tally), name)
            self.assertTrue(chain_ok(path, self.template), name)
        for cls in ("applied", "negative_pending", "held", "zero", "duplicate"):  # negatives sort first, so negative_applied never occurs in either path
            self.assertGreater(ref.classes.get(cls, 0), 0, cls)

    def test_hostile_row_is_held_and_its_file_applies(self) -> None:
        path, w = self.ingest("hostile", True, True)
        c = sqlite3.connect(str(path))
        self.assertEqual(c.execute("SELECT state,amount_cents FROM cells WHERE origin_id=?", (self.hostile_origin,)).fetchall(), [("HELD", None)])
        positive = {f"1/{r.key[0]}/{'/'.join(r.key[1:])}" for r in self.files[1][0].rows if r.key[0] != "RAW" and (r.amount_cents or 0) > 0}
        got = {r[0] for r in c.execute("SELECT origin_id FROM cells WHERE state='RESOLVED' AND origin_id LIKE '1/%'")}
        self.assertEqual(got, positive)  # every other applicable row of the hostile file applied
        self.assertGreaterEqual(w.classes["duplicate"], 2)  # the hostile row's second copy and the repeated real row
        c.close()

    def test_crash_before_any_commit_leaves_the_prefix_and_replay_restores_the_end_state(self) -> None:
        with mock.patch.object(r9_bench, "C_MAX", 100):  # several chunks per file
            prefix: dict[tuple[int, int], dict[str, str]] = {}
            ref_path = self.fresh("crash_ref")

            def note(index, start):  # committed state at the moment chunk (index, start) is about to commit
                prefix[(index, start)] = digests(ref_path)

            ref_path, _ = self.ingest("crash_ref", False, False, hook=note, path=ref_path)
            final = digests(ref_path)
            self.assertGreater(len(prefix), FILES)
            for point in prefix:
                class Die(r9_bench.Crash):
                    pass

                def die(index, start, point=point):
                    if (index, start) == point:
                        raise Die()

                path = self.fresh(f"crash_{point[0]}_{point[1]}")
                with self.assertRaises(Die):
                    self.ingest("x", True, True, hook=die, path=path)
                self.assertEqual(digests(path), prefix[point], point)  # the crashed chunk left nothing; every earlier chunk stands
                if point[1] == 0:  # nothing of that file committed: re-ingesting it and the rest gives the uninterrupted end state
                    self.ingest("x", True, True, first=point[0], path=path)
                    self.assertEqual(digests(path), final, point)

    def test_unchecked_wal_recovers_to_the_committed_state(self) -> None:
        ref_path = self.fresh("wal_ref")
        wanted: dict[int, dict[str, str]] = {}
        c, w = r9_bench.open_store(ref_path, False, False)
        for i in range(FILES):
            w.run_file(i, *self.files[i], [])
            wanted[i] = digests(ref_path)
        c.close()
        path = self.fresh("wal_live")
        c, w = r9_bench.open_store(path, True, False)
        c.execute("PRAGMA wal_autocheckpoint=0")  # the WAL is never copied into the database while the writer runs
        for i in range(FILES):
            w.run_file(i, *self.files[i], [])
            copy = Path(self.tmp.name) / f"wal_copy_{i}.sqlite3"  # the files a crash would leave: database and WAL, no shm
            shutil.copyfile(path, copy)
            shutil.copyfile(str(path) + "-wal", str(copy) + "-wal")
            self.assertGreater(Path(str(copy) + "-wal").stat().st_size, 0)
            self.assertEqual(digests(copy), wanted[i], i)
        c.close()

    def test_a_moved_obligation_is_an_integrity_error_and_rolls_the_chunk_back(self) -> None:
        for fast in (True, False):
            path = self.fresh(f"moved_{fast}")
            c, w = r9_bench.open_store(path, fast, False)
            before = digests(path)  # after open_store: its tables exist
            ob = w.obl_ids[0]
            w.revision[ob] += 5  # the judge's view disagrees with the store
            w.obl_ids[:] = [ob]
            with self.assertRaises(r9_bench.FinancialIntegrityError):
                w.run_file(0, *self.files[0], [])
            c.close()
            self.assertEqual(digests(path), before)


if __name__ == "__main__":
    unittest.main()
