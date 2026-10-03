"""The gate's per-tenant line-id registry (``app/right_rail_gate_idreg.py``, store v2): chained RESERVE, FREE,
SETTLE and BOOT rows; settle-then-reserve in one transaction; the boot check.  Synthetic ids, non-PHI."""

from __future__ import annotations

import contextlib
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest

from app import right_rail_gate_codec as gate
from app import right_rail_gate_idreg as idreg

ROOT = Path(__file__).resolve().parents[1]
_RESERVE_1000 = (  # argv: path nonce-hex shard start-time; the start time is the barrier that makes the two batches race
    "import sys, time\n"
    "from pathlib import Path\n"
    "from app.right_rail_gate_idreg import IdRegistry\n"
    "r = IdRegistry(Path(sys.argv[1]), boot=bytes.fromhex(sys.argv[2]), timeout=30)\n"
    "time.sleep(max(0.0, float(sys.argv[4]) - time.time()))\n"
    "print(repr(r.reserve(int(sys.argv[3]), list(range(1000)), sealed=None)[0]))\n")


class _Dying:
    """Stands in for the registry's connection and breaks the COMMIT statement.  ``die``: the process dies
    there (the connection closes with the transaction uncommitted); otherwise COMMIT fails and the connection lives."""

    def __init__(self, db: sqlite3.Connection, die: bool) -> None:
        self._real, self._die, self._dead = db, die, False

    @property
    def in_transaction(self) -> bool:
        return not self._dead and self._real.in_transaction

    def execute(self, sql: str, *args):
        if sql == "COMMIT":
            if self._die:
                self._real.close()
                self._dead = True
            raise sqlite3.OperationalError("injected failure at COMMIT")
        return self._real.execute(sql, *args)

    def __getattr__(self, name: str):
        return getattr(self._real, name)


class _NoRollback(_Dying):
    """COMMIT fails, then ROLLBACK fails too."""

    def execute(self, sql: str, *args):
        if sql == "ROLLBACK":
            raise sqlite3.OperationalError("injected failure at ROLLBACK")
        return super().execute(sql, *args)


class IdRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)  # cleanups run last-in first: stores close before the directory goes
        self.path = Path(tmp.name) / "ids.sqlite3"
        self.nonce = idreg.boot(self.path, {})
        self.reg = self.open(self.nonce)

    def open(self, nonce: bytes, **kwargs) -> idreg.IdRegistry:
        reg = idreg.IdRegistry(self.path, boot=nonce, **kwargs)
        self.addCleanup(reg.close)
        return reg

    def rows(self) -> int:
        return self.reg._db.execute("SELECT COUNT(*) FROM log").fetchone()[0]

    def state(self):
        return self.rows(), self.reg.verify(), self.reg.pending(0), self.reg.pending(1)

    def _edit(self, sql: str) -> None:
        with contextlib.closing(sqlite3.connect(self.path, isolation_level=None)) as db:
            db.execute(sql)

    def test_v1_store_refused(self) -> None:
        old = self.path.parent / "v1.sqlite3"
        with contextlib.closing(sqlite3.connect(old)) as db:
            db.execute("CREATE TABLE ids(n INTEGER PRIMARY KEY, id BLOB NOT NULL UNIQUE, shard INTEGER NOT NULL, head BLOB NOT NULL)")
        with self.assertRaisesRegex(idreg.IdRegistryError, "store_version"):
            idreg.boot(old, {})
        with self.assertRaisesRegex(idreg.IdRegistryError, "store_version"):
            idreg.IdRegistry(old, boot=self.nonce)

    def test_genesis_owners(self) -> None:
        n, head = self.reg.genesis({0: [1, 2], 1: [3]})
        self.assertEqual(self.reg.verify(), head)
        owners, n2, head2 = self.reg.reserve(0, [1, 3, 9], sealed=None)
        self.assertEqual(owners, [(1, 0, True), (3, 1, True), (9, 0, False)])
        self.assertEqual((n2, head2), (self.rows(), self.reg.verify()))
        self.assertEqual(n, 1 + 3 + 2)  # BOOT, 3 RESERVE, 2 SETTLE
        with self.assertRaisesRegex(idreg.IdRegistryError, "genesis_double_acceptance"):
            self.reg.genesis({0: [50], 1: [50]})
        self.assertEqual(self.reg.verify(), head2)  # nothing of the refused genesis was written

    def test_head_rule(self) -> None:
        _, n, head = self.reg.reserve(0, [1, 2, 1], sealed=None)
        want = self.reg._db.execute("SELECT head FROM log WHERE n = 1").fetchone()[0]  # the BOOT row
        for kind, i in ((0, 1), (0, 2)):
            want = gate.sha3_512(b"RR/GATE/ID-REG/v2\x00" + want + bytes([kind]) + i.to_bytes(129, "big") + (0).to_bytes(4, "big"))
        self.assertEqual((head, self.reg.verify()), (want, want))
        self.assertEqual(n, 3)  # a repeat inside one batch counts once

    def test_settle_guard(self) -> None:
        self.reg.genesis({0: [7], 1: [8]})
        n = self.reg.reserve(0, [1, 2], sealed=None)[1]
        self.reg.reserve(1, [], sealed=None)
        before = self.state()
        for name, bad in (("other shard's id", 8), ("recorded id", 7), ("unknown id", 99)):
            with self.subTest(name), self.assertRaisesRegex(idreg.IdRegistryError, "settle_mismatch"):
                self.reg.reserve(0, [5], sealed=(n, [bad]))
            self.assertEqual(self.state(), before)

    def test_settle_frees_and_keeps(self) -> None:
        n = self.reg.reserve(0, [1, 2], sealed=None)[1]
        self.assertEqual(self.reg.pending(0), (n, [1, 2]))
        self.reg.reserve(0, [], sealed=(n, [1]))
        self.assertEqual(self.reg.reserve(1, [1, 2], sealed=None)[0], [(1, 1, False), (2, 0, True)])
        self.assertEqual(self.reg.pending(0), (None, []))

    def test_settle_stale_frees_all(self) -> None:
        n = self.reg.reserve(0, [1, 2], sealed=None)[1]
        self.reg.reserve(0, [], sealed=(n - 1, []))
        self.assertEqual(self.reg.reserve(1, [1, 2], sealed=None)[0], [(1, 1, False), (2, 1, False)])

    def test_settle_atomic_with_reserve(self) -> None:
        n = self.reg.reserve(0, [1, 2], sealed=None)[1]
        before = self.state()
        with self.assertRaisesRegex(idreg.IdRegistryError, "id"):
            self.reg.reserve(0, [-1], sealed=(n, [1]))
        self.assertEqual(self.state(), before)

    def test_boot_nonce(self) -> None:
        stale = self.open(b"\x01" * 32)
        before = self.rows()
        for call in (lambda: stale.reserve(0, [1], sealed=None), lambda: stale.pending(0)):
            with self.assertRaisesRegex(idreg.IdRegistryError, "registry_not_booted"):
                call()
        self.assertEqual(self.rows(), before)
        second = self.open(idreg.boot(self.path, {}))
        with self.assertRaisesRegex(idreg.IdRegistryError, "registry_not_booted"):
            self.reg.pending(0)
        self.assertEqual(second.pending(0), (None, []))

    def test_boot_commitments(self) -> None:
        n, head = self.reg.genesis({0: [1], 1: [2]})
        idreg.boot(self.path, {0: (n, head), 1: (n, head)})
        idreg.boot(self.path, {0: (0, gate.ZERO_DIGEST), 1: (2, self.reg._db.execute("SELECT head FROM log WHERE n = 2").fetchone()[0])})
        with self.assertRaisesRegex(idreg.IdRegistryError, "commitment_missing"):
            idreg.boot(self.path, {0: (n, head)})
        for bad in ((n, bytes(64)), (n + 10, head)):
            with self.subTest(bad), self.assertRaisesRegex(idreg.IdRegistryError, "registry_rewound"):
                idreg.boot(self.path, {0: bad, 1: (n, head)})
        self._edit("DROP TRIGGER log_no_update")
        self._edit("UPDATE log SET shard = 5 WHERE n = 3")  # a middle row edited, stored heads kept
        with self.assertRaisesRegex(idreg.IdRegistryError, "chain_broken"):
            idreg.boot(self.path, {0: (n, head), 1: (n, head)})

    def test_rows_are_append_only(self) -> None:
        self.reg.reserve(0, [1, 2, 3], sealed=None)
        for sql in ("UPDATE log SET shard = 9 WHERE n = 2", "DELETE FROM log WHERE n = 3"):
            with self.assertRaises(sqlite3.DatabaseError):
                self._edit(sql)
        self.assertNotEqual(self.reg.verify(), gate.ZERO_DIGEST)

    def test_concurrent_reserve(self) -> None:
        start = str(time.time() + 3)
        procs = [subprocess.Popen([sys.executable, "-c", _RESERVE_1000, str(self.path), self.nonce.hex(), str(shard), start],
                                  cwd=ROOT, stdout=subprocess.PIPE, text=True) for shard in (0, 1)]
        owners = []
        for proc in procs:
            out, _ = proc.communicate(timeout=120)
            self.assertEqual(proc.returncode, 0)
            owners.append(eval(out))
        self.assertIn(owners[0][0][1], (0, 1))
        self.assertEqual(owners[0], owners[1])  # one owner s for every id, seen by both: (i, s, False)
        self.assertEqual({shard for _, shard, _ in owners[0]}, {owners[0][0][1]})
        count = self.reg._db.execute("SELECT COUNT(*), COUNT(DISTINCT id) FROM log WHERE kind = 0").fetchone()
        self.assertEqual(count, (1000, 1000))

    def test_dying_at_commit_writes_nothing(self) -> None:
        self.reg._db = _Dying(self.reg._db, die=True)
        with self.assertRaisesRegex(idreg.IdRegistryError, "registry_unavailable"):
            self.reg.reserve(1, [1, 2], sealed=None)
        again = self.open(self.nonce)
        self.assertEqual(again.reserve(0, [1, 2], sealed=None)[0], [(1, 0, False), (2, 0, False)])

    def test_failed_commit_rolls_back_and_the_registry_still_works(self) -> None:
        live = self.reg._db
        self.reg._db = _Dying(live, die=False)
        with self.assertRaisesRegex(idreg.IdRegistryError, "registry_unavailable"):
            self.reg.reserve(1, [1], sealed=None)
        self.reg._db = live
        self.assertEqual(self.reg.reserve(0, [1], sealed=None)[0], [(1, 0, False)])

    def test_bad_input_is_refused_before_anything_is_written(self) -> None:
        before = self.rows()
        for shard, ids in ((-1, [1]), (1 << 32, [1]), (True, [1]), (0, [1, -1]), (0, [1, True]), (0, [1, 2 ** 1032]),
                           (0, [1, b"short"]), (0, [1, "x" * idreg.ID_LEN])):
            with self.assertRaises(idreg.IdRegistryError):
                self.reg.reserve(shard, ids, sealed=None)
        with self.assertRaises(idreg.IdRegistryError):
            self.reg.genesis({0: [1], 1: [b"short"]})
        self.assertEqual(self.rows(), before)

    def test_an_unavailable_registry_is_a_typed_refusal(self) -> None:
        with self.assertRaisesRegex(idreg.IdRegistryError, "registry_unavailable"):
            idreg.IdRegistry(self.path.parent / "missing" / "ids.sqlite3", boot=self.nonce)
        busy = self.open(self.nonce, timeout=0.1)
        with contextlib.closing(sqlite3.connect(self.path, isolation_level=None)) as other:
            other.execute("BEGIN IMMEDIATE")  # another writer holds the lock
            with self.assertRaisesRegex(idreg.IdRegistryError, "registry_unavailable"):
                busy.reserve(0, [1], sealed=None)
        self.assertEqual(busy.reserve(0, [1], sealed=None)[0], [(1, 0, False)])  # and it recovers once the lock is gone

    def test_a_broken_database_or_rollback_is_a_typed_refusal(self) -> None:
        live = self.reg._db
        self.reg._db = _NoRollback(live, die=False)
        with self.assertRaisesRegex(idreg.IdRegistryError, "registry_unavailable"):
            self.reg.reserve(0, [2], sealed=None)
        live.execute("ROLLBACK")
        self.reg._db = live
        self._edit("DROP TABLE log")
        with self.assertRaisesRegex(idreg.IdRegistryError, "registry_unavailable"):
            self.reg.verify()

    def test_durability_pragmas_are_set_and_a_rollback_journal_is_refused(self) -> None:
        self.assertEqual(self.reg._db.execute("PRAGMA journal_mode").fetchone()[0], "wal")
        self.assertEqual(self.reg._db.execute("PRAGMA synchronous").fetchone()[0], 2)  # FULL
        with self.assertRaisesRegex(idreg.IdRegistryError, "registry_unavailable"):
            idreg.IdRegistry(Path(":memory:"), boot=self.nonce)  # journal_mode stays 'memory'


if __name__ == "__main__":
    unittest.main()
