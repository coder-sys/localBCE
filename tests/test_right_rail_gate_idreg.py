"""The gate's per-tenant line-id registry (``app/right_rail_gate_idreg.py``, store v2): chained RESERVE, FREE,
SETTLE and BOOT rows; settle-then-reserve in one transaction; the boot check.  Synthetic ids, non-PHI."""

from __future__ import annotations

import contextlib
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from app import right_rail_gate_codec as gate
from app import right_rail_gate_idreg as idreg
from tests.test_right_rail_gate_shards import link

ROOT = Path(__file__).resolve().parents[1]
STORES = {0: Path("no-store-0"), 1: Path("no-store-1")}  # with a payer that stored no checkpoint ({}), B3 passes
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
        self.nonce = idreg.boot(self.path, lambda: ({}, {}, {}))
        self.reg = self.open(self.nonce)

    def open(self, nonce: bytes, **kwargs) -> idreg.IdRegistry:
        reg = idreg.IdRegistry(self.path, boot=nonce, **kwargs)
        self.addCleanup(reg.close)
        return reg

    def tail(self) -> tuple[int, bytes]:
        """The newest row's (n, head); the log is append-only, so an unchanged tail means nothing was written."""
        return self.reg._db.execute("SELECT n, head FROM log ORDER BY n DESC LIMIT 1").fetchone()

    def _edit(self, sql: str) -> None:
        with contextlib.closing(sqlite3.connect(self.path, isolation_level=None)) as db:
            db.execute(sql)

    def test_v1_store_refused(self) -> None:
        old = self.path.parent / "v1.sqlite3"
        with contextlib.closing(sqlite3.connect(old)) as db:
            db.execute("CREATE TABLE ids(n INTEGER PRIMARY KEY, id BLOB NOT NULL UNIQUE, shard INTEGER NOT NULL, head BLOB NOT NULL)")
        with self.assertRaisesRegex(idreg.IdRegistryError, "store_version"):
            idreg.boot(old, lambda: ({}, {}, {}))
        with self.assertRaisesRegex(idreg.IdRegistryError, "store_version"):
            idreg.IdRegistry(old, boot=self.nonce)

    def test_genesis_owners(self) -> None:
        n, head = self.reg.genesis({0: [1, 2], 1: [3]})
        self.assertEqual(self.tail(), (n, head))
        owners, n2, head2 = self.reg.reserve(0, [1, 3, 9], sealed=None)
        self.assertEqual(owners, [(1, 0, True), (3, 1, True), (9, 0, False)])
        self.assertEqual(self.tail(), (n2, head2))
        self.assertEqual(n, 1 + 3 + 2)  # BOOT, 3 RESERVE, 2 SETTLE
        with self.assertRaisesRegex(idreg.IdRegistryError, "genesis_double_acceptance"):
            self.reg.genesis({0: [50], 1: [50]})
        self.assertEqual(self.tail(), (n2, head2))  # nothing of the refused genesis was written

    def test_head_rule(self) -> None:
        _, n, head = self.reg.reserve(0, [1, 2, 1], sealed=None)
        want = self.reg._db.execute("SELECT head FROM log WHERE n = 1").fetchone()[0]  # the BOOT row
        for kind, i in ((0, 1), (0, 2)):
            want = gate.sha3_512(b"RR/GATE/ID-REG/v2\x00" + want + bytes([kind]) + i.to_bytes(129, "big") + (0).to_bytes(4, "big"))
        self.assertEqual(((n, head), self.tail()), ((3, want), (3, want)))  # a repeat inside one batch counts once

    def test_settle_guard(self) -> None:
        self.reg.genesis({0: [7], 1: [8]})
        _, n, head = self.reg.reserve(0, [1, 2], sealed=None)
        self.reg.reserve(1, [], sealed=None)
        before = self.tail()
        for name, bad in (("other shard's id", 8), ("recorded id", 7), ("unknown id", 99)):
            with self.subTest(name), self.assertRaisesRegex(idreg.IdRegistryError, "settle_mismatch"):
                self.reg.reserve(0, [5], sealed=(n, head, [bad]))
            self.assertEqual(self.tail(), before)

    def test_settle_frees_and_keeps(self) -> None:
        _, n, head = self.reg.reserve(0, [1, 2], sealed=None)
        self.reg.reserve(0, [], sealed=(n, head, [1]))
        self.assertEqual(self.reg.reserve(1, [1, 2], sealed=None)[0], [(1, 1, False), (2, 0, True)])

    def test_settle_then_reserve_in_one_call(self) -> None:
        _, n, head = self.reg.reserve(0, [1, 2], sealed=None)
        owners = self.reg.reserve(0, [1, 2], sealed=(n, head, [1]))[0]  # settle frees 1 and records 2, then reserves both
        self.assertEqual(owners, [(1, 0, False), (2, 0, True)])  # 1 in flight again, 2 recorded
        self.assertEqual(self.reg._db.execute("SELECT kind FROM log WHERE n > ?", (n,)).fetchall(), [(1,), (2,), (0,)])

    def test_settle_stale_frees_all(self) -> None:
        n = self.reg.reserve(0, [1, 2], sealed=None)[1]
        self.reg.reserve(0, [], sealed=(n - 1, *self.reg._db.execute("SELECT head FROM log WHERE n = ?", (n - 1,)).fetchone(), []))
        self.assertEqual(self.reg.reserve(1, [1, 2], sealed=None)[0], [(1, 1, False), (2, 1, False)])

    def test_settle_atomic_with_reserve(self) -> None:
        _, n, head = self.reg.reserve(0, [1, 2], sealed=None)
        before = self.tail()
        with self.assertRaisesRegex(idreg.IdRegistryError, "id"):
            self.reg.reserve(0, [-1], sealed=(n, head, [1]))
        self.assertEqual(self.tail(), before)

    def test_settle_refuses_a_newer_reserve(self) -> None:  # decide B1, decide B2 (frees B1's 1), commit B1
        for newer in ([2], []):  # B2's 2 in flight, or nothing in flight
            with self.subTest(newer=newer):
                n = self.reg.reserve(0, [1], sealed=None)[1]
                self.reg.reserve(0, newer, sealed=None)
                before = self.tail()
                with self.assertRaisesRegex(idreg.IdRegistryError, "settle_mismatch"):
                    self.reg.settle(0, [n], [])
                self.assertEqual(self.tail(), before)

    def test_boot_nonce(self) -> None:
        stale = self.open(b"\x01" * 32)
        before = self.tail()
        with self.assertRaisesRegex(idreg.IdRegistryError, "registry_not_booted"):
            stale.reserve(0, [1], sealed=None)
        self.assertEqual(self.tail(), before)
        second = self.open(idreg.boot(self.path, lambda: ({}, {}, {})))
        with self.assertRaisesRegex(idreg.IdRegistryError, "registry_not_booted"):
            self.reg.reserve(0, [1], sealed=None)
        self.assertEqual(second.reserve(0, [1], sealed=None)[0], [(1, 0, False)])

    def test_boot_fences_under_the_lock_after_a_sqlite_rollback(self) -> None:
        """Review LOW-2 and LOW-A: SQLite rolled the transaction back inside the checks (disk full, I/O error); the fence is
        still written, under a fresh lock (never unlocked in autocommit, and never skipped: the running nonce must HOLD)."""
        for refuse in (False, True):
            def admit(db, inputs):
                db.execute("ROLLBACK")  # what SQLite does itself on SQLITE_FULL or SQLITE_IOERR mid-statement
                if refuse:
                    raise idreg.IdRegistryError("registry_rewound")
            before = self.tail()[0]
            with self.subTest(refuse=refuse), mock.patch.object(idreg, "_admit", admit), \
                    self.assertRaisesRegex(idreg.IdRegistryError, "registry_unavailable") as refused:
                idreg.boot(self.path, lambda: ({}, {}, {}))
            self.assertEqual(self.reg._db.execute("SELECT kind FROM log WHERE n > ?", (before,)).fetchall(), [(idreg._BOOT,)])  # exactly one new row: the fence
            cause = refused.exception.__cause__
            if refuse:
                self.assertIsInstance(cause, idreg.IdRegistryError)
                self.assertRegex(str(cause), "registry_rewound")
            else:
                self.assertIsNone(cause)

    def test_boot_commitments(self) -> None:
        n, head = self.reg.genesis({0: [1], 1: [2]})  # rows 2-3: RESERVE 1, SETTLE of shard 0; rows 4-5: the same for shard 1
        at = lambda i: (i, self.reg._db.execute("SELECT head FROM log WHERE n = ?", (i,)).fetchone()[0])
        idreg.boot(self.path, lambda: ({0: (n, head), 1: (n, head)}, STORES, {}))
        live = self.open(idreg.boot(self.path, lambda: ({0: at(2), 1: (n, head)}, STORES, {})))  # a batch ending at its RESERVE, then the next batch's settle
        self.addCleanup(live.close)
        before = self.tail()
        for bad in ({0: (n, head)}, {0: (0, gate.ZERO_DIGEST), 1: (n, head)}):  # a shard with rows needs its commitment
            with self.subTest(bad), self.assertRaisesRegex(idreg.IdRegistryError, "commitment_missing"):
                idreg.boot(self.path, lambda: (bad, STORES, {}))
        with self.assertRaisesRegex(idreg.IdRegistryError, "registry_rewound"):
            idreg.boot(self.path, lambda: ({0: (n, head), 1: at(2)}, STORES, {}))  # shard 1's RESERVE (row 4) and a later SETTLE lie past row 2
        for bad in ((n, bytes(64)), (n + 10, head)):
            with self.subTest(bad), self.assertRaisesRegex(idreg.IdRegistryError, "registry_rewound"):
                idreg.boot(self.path, lambda: ({0: bad, 1: (n, head)}, STORES, {}))
        junk = self.path.with_name("junk.sqlite3")
        junk.write_bytes(b"not a database" * 64)
        for stores, stored, error in (({0: STORES[0]}, {}, "anchor_missing"), ({**STORES, 2: STORES[1]}, {}, "anchor_missing"),
                                      (STORES, {2: bytes(64)}, "anchor_missing"), (STORES, None, "payer_unavailable"),
                                      (STORES, {1: bytes(64)}, "store_rewound"),  # a missing store holds nothing
                                      ({**STORES, 1: junk}, {1: bytes(64)}, "store_unavailable")):
            with self.subTest(error), self.assertRaisesRegex(idreg.IdRegistryError, error):
                idreg.boot(self.path, lambda: ({0: (n, head), 1: (n, head)}, stores, stored))
        stat = os.stat  # only the stores' stat fails: boot also stats the registry it opened (S4)

        def denied(p, *a, **k):
            if Path(p) in STORES.values():
                raise PermissionError(p)
            return stat(p, *a, **k)
        with mock.patch.object(idreg.producer.os, "stat", denied), self.assertRaisesRegex(
                idreg.IdRegistryError, "store_unavailable"):  # the store path's cause, never a raw OSError
            idreg.boot(self.path, lambda: ({0: (n, head), 1: (n, head)}, STORES, {0: bytes(64)}))
        added = self.reg._db.execute("SELECT kind, id FROM log WHERE n > ?", (before[0],)).fetchall()
        self.assertEqual(([kind for kind, _ in added], len({nonce for _, nonce in added})), ([3] * 12, 12))  # one fence each
        with self.assertRaisesRegex(idreg.IdRegistryError, "registry_not_booted"):
            live.reserve(0, [9], sealed=None)  # the last passing boot's nonce is fenced; nothing reserves
        self._edit("DROP TRIGGER log_no_update")
        self._edit("UPDATE log SET shard = 5 WHERE n = 3")  # a middle row edited, stored heads kept
        with self.assertRaisesRegex(idreg.IdRegistryError, "chain_broken"):
            idreg.boot(self.path, lambda: ({0: (n, head), 1: (n, head)}, STORES, {}))

    def test_rows_are_append_only(self) -> None:
        self.reg.reserve(0, [1, 2, 3], sealed=None)
        for sql in ("UPDATE log SET shard = 9 WHERE n = 2", "DELETE FROM log WHERE n = 3"):
            with self.assertRaises(sqlite3.DatabaseError):
                self._edit(sql)
        idreg.boot(self.path, lambda: ({0: self.tail()}, {0: STORES[0]}, {}))  # the chain still replays

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
        with mock.patch.object(idreg, "_SEEN", {}):  # the next process on the nonce
            again = self.open(self.nonce)
            self.assertEqual(again.reserve(0, [1, 2], sealed=None)[0], [(1, 0, False), (2, 0, False)])

    def test_failed_commit_rolls_back_and_the_registry_still_works(self) -> None:
        """Review LOW-1: the process remembers the new tail before COMMIT, under the write lock, so a COMMIT that fails
        leaves the memory ahead of the file: the nonce then fences (fail closed) and the registry works after a boot."""
        live = self.reg._db
        self.reg._db = _Dying(live, die=False)
        with self.assertRaisesRegex(idreg.IdRegistryError, "registry_unavailable"):
            self.reg.reserve(1, [1], sealed=None)
        self.reg._db = live
        with self.assertRaisesRegex(idreg.IdRegistryError, "registry_not_booted"):
            self.reg.reserve(0, [1], sealed=None)
        again = self.open(idreg.boot(self.path, lambda: ({}, {}, {})))
        self.assertEqual(again.reserve(0, [1], sealed=None)[0], [(1, 0, False)])

    def test_boots_in_one_process_run_one_at_a_time(self) -> None:
        """Review LOW-2: boot A is inside its open (its COMMIT will fail, so no fence lands) when boot B starts.  B waits
        for A, so B's pass, which ends the process's stop, never comes before A's failure, which must leave it set."""
        inside, go, real, done = threading.Event(), threading.Event(), idreg._open, {}

        def hooked(path, *a, **k):
            if threading.current_thread().name != "A":
                return real(path, *a, **k)
            inside.set()
            go.wait(30)
            return _Dying(real(path, *a, **k), die=False)

        def run():
            try:
                done[threading.current_thread().name] = idreg.boot(self.path, lambda: ({}, {}, {}))
            except idreg.IdRegistryError as error:
                done[threading.current_thread().name] = str(error)
        a, b = threading.Thread(target=run, name="A"), threading.Thread(target=run, name="B")
        with mock.patch.object(idreg, "_open", hooked):
            a.start()
            try:
                inside.wait(30)
                b.start()
                b.join(1.0)
                self.assertTrue(b.is_alive())  # B waits while A is inside its open
            finally:
                go.set()
                a.join(30)
                b.join(30)
        self.assertEqual((done["A"], len(done["B"])), ("registry_unavailable", 32))
        self.assertEqual(self.open(done["B"]).reserve(0, [1], sealed=None)[0], [(1, 0, False)])  # B passed last

    def test_a_boot_that_waits_too_long_for_another_is_a_typed_refusal(self) -> None:
        """Review L-1 (s3fix1): another boot of this process holds the boot lock past 5 s: ``registry_unavailable``,
        nothing written.  Review L-1 (s3fix2): it stops the path like every other boot that does not pass, so the
        running handle HOLDs until a boot passes (before: it kept reserving on a file nobody checked)."""
        before = self.tail()
        with idreg._BOOTING, self.assertRaisesRegex(idreg.IdRegistryError, "registry_unavailable"):
            idreg.boot(self.path, lambda: ({}, {}, {}))
        self.assertEqual(self.tail(), before)
        with self.assertRaisesRegex(idreg.IdRegistryError, "registry_not_booted"):
            self.reg.reserve(0, [1], sealed=None)
        self.assertEqual(self.open(idreg.boot(self.path, lambda: ({}, {}, {}))).reserve(0, [1], sealed=None)[0], [(1, 0, False)])

    def test_boot_stops_old_nonces_inside_its_transaction(self) -> None:
        """Review L-2 (s3fix2): boot's pre-read fails (suppressed), so only its in-transaction sweep stops the old nonce;
        a copy taken before the boot, reached later, must not let that nonce reserve again."""
        copy = self.path.with_name("copy.sqlite3")
        for s in ("", "-wal"):
            shutil.copyfile(f"{self.path}{s}", f"{copy}{s}")
        with mock.patch.object(idreg, "_stop_boots", wraps=idreg._stop_boots,
                               side_effect=[sqlite3.OperationalError("database is locked"), mock.DEFAULT]):
            idreg.boot(self.path, lambda: ({}, {}, {}))
        with contextlib.closing(idreg.IdRegistry(copy, boot=self.nonce)) as old, self.assertRaisesRegex(
                idreg.IdRegistryError, "registry_not_booted"):
            old.reserve(0, [1], sealed=None)

    def test_bad_input_is_refused_before_anything_is_written(self) -> None:
        before = self.tail()
        for shard, ids in ((-1, [1]), (1 << 32, [1]), (True, [1]), (0, [1, -1]), (0, [1, True]), (0, [1, 2 ** 1032]),
                           (0, [1, b"short"]), (0, [1, "x" * idreg.ID_LEN])):
            with self.assertRaises(idreg.IdRegistryError):
                self.reg.reserve(shard, ids, sealed=None)
        with self.assertRaises(idreg.IdRegistryError):
            self.reg.genesis({0: [1], 1: [b"short"]})
        self.assertEqual(self.tail(), before)

    def test_an_unavailable_registry_is_a_typed_refusal(self) -> None:
        for start in (lambda p: idreg.IdRegistry(p, boot=self.nonce), lambda p: idreg.boot(p, lambda: ({}, {}, {}))):
            with self.assertRaisesRegex(idreg.IdRegistryError, "registry_unavailable"):
                start(self.path.parent / "missing" / "ids.sqlite3")
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
            self.reg.reserve(0, [1], sealed=None)

    def test_durability_pragmas_are_set_and_a_rollback_journal_is_refused(self) -> None:
        self.assertEqual(self.reg._db.execute("PRAGMA journal_mode").fetchone()[0], "wal")
        self.assertEqual(self.reg._db.execute("PRAGMA synchronous").fetchone()[0], 2)  # FULL
        with self.assertRaisesRegex(idreg.IdRegistryError, "registry_unavailable"):
            idreg.IdRegistry(Path(":memory:"), boot=self.nonce)  # journal_mode stays 'memory'

    def test_only_boot_creates_or_writes_the_registry_file(self) -> None:
        """Review L-b (s3fix3): a handle open writes no registry file: a missing one is not created, an empty one (a
        restore mid-copy) is refused unwritten (before: both got WAL and the schema), and a refused handle is closed."""
        new = self.path.with_name("new.sqlite3")
        for exists in (False, True):
            if exists:
                new.touch()
            with self.assertRaisesRegex(idreg.IdRegistryError, "registry_unavailable"):
                idreg.IdRegistry(new, boot=self.nonce)
            self.assertEqual([(p.name, p.stat().st_size) for p in new.parent.glob("new.*")], [("new.sqlite3", 0)] * exists)
        real_open, opened = idreg._open, []  # no file at the path after the connect (S4: the identity is the opened file's)
        with mock.patch.object(idreg, "_open", lambda *a, **k: opened.append(real_open(*a, **k)) or opened[-1]), \
                mock.patch.object(idreg, "_ident", return_value=None), \
                self.assertRaisesRegex(idreg.IdRegistryError, "registry_moved"):
            idreg.IdRegistry(self.path, boot=self.nonce)
        with self.assertRaisesRegex(sqlite3.ProgrammingError, "closed"):
            opened[0].execute("SELECT 1")

    def copied(self) -> tuple[Path, Path, bytes]:
        """A registry booted in ``a/`` and its copy in ``b/``: the same rows and nonce, so a handle on the copy writes
        there as if it were on ``a``."""
        a, b = self.path.with_name("a"), self.path.with_name("b")
        a.mkdir()
        nonce = idreg.boot(a / "ids.sqlite3", lambda: ({}, {}, {}))
        shutil.copytree(a, b)
        return a, b, nonce

    def test_the_file_opened_is_the_file_checked(self) -> None:
        """S4 R1: a link re-pointed to a copy for the connect only (A->B->A) left the path's identity the same before
        and after it, so the handle wrote the copy as the registry; the connect now takes the link-free path whose
        identity it binds."""
        a, b, nonce = self.copied()
        via = link(self.path.with_name("via"), a)
        self.addCleanup(link, via, None)
        real_open, before = idreg._open, rows(b)

        def swapped(*args, **kwargs):
            link(via, b)
            try:
                return real_open(*args, **kwargs)
            finally:
                link(via, a)
        with mock.patch.object(idreg, "_open", swapped):
            reg = idreg.IdRegistry(via / "ids.sqlite3", boot=nonce)
        self.addCleanup(reg.close)
        reg.reserve(0, [1], sealed=None)
        self.assertEqual([rows(a), rows(b)], [before + 1, before])

    @unittest.skipUnless(os.name == "nt", "POSIX keeps no pin (closing any descriptor of a file drops this process's "
                         "SQLite locks on it): a real directory swapped inside the connect is the named residual there")
    def test_the_file_and_its_directories_stay_put_while_open(self) -> None:
        """S4 R1 (Windows): the registry's directory renamed away and a link to the copy put in its place for the
        connect only (A->B->A) was not seen; the handle taken before the connect bars the rename."""
        a, b, nonce = self.copied()
        real_open, before, barred = idreg._open, rows(b), []

        def swapped(*args, **kwargs):
            try:
                os.rename(a, a.with_name("x"))
            except PermissionError as error:
                barred.append(error)
                return real_open(*args, **kwargs)
            link(a, b)
            try:
                return real_open(*args, **kwargs)
            finally:
                link(a, None)
                os.rename(a.with_name("x"), a)
        with mock.patch.object(idreg, "_open", swapped):
            reg = idreg.IdRegistry(a / "ids.sqlite3", boot=nonce)
        self.addCleanup(reg.close)
        reg.reserve(0, [1], sealed=None)
        self.assertEqual([len(barred), rows(a), rows(b)], [1, before + 1, before])

    def test_a_lease_is_the_opened_files_and_a_moved_path_refuses(self) -> None:
        """S4 R1: a link re-pointed after the open moved the handle's lease to the copy's lease file, so a second
        decider on the opened file got the shard too; the lease is now beside the file opened, and taking it on a
        path that names another file refuses ``registry_moved``."""
        a, b, nonce = self.copied()
        via = link(self.path.with_name("via"), a)
        self.addCleanup(link, via, None)
        moved = idreg.IdRegistry(via / "ids.sqlite3", boot=nonce)
        self.addCleanup(moved.close)
        link(via, b)
        with self.assertRaisesRegex(idreg.IdRegistryError, "registry_moved"):
            moved.in_flight(0)
        direct = idreg.IdRegistry(a / "ids.sqlite3", boot=nonce)
        self.addCleanup(direct.close)
        self.assertEqual(direct.in_flight(0), [])
        link(via, a)
        with self.assertRaisesRegex(idreg.IdRegistryError, "shard_busy"):
            moved.in_flight(0)
        self.assertEqual(sorted(p.name for p in b.iterdir() if "lease" in p.name), [])

    @unittest.skipUnless(hasattr(os, "fork"), "no os.fork here (Windows spawns, never forks): no child can inherit a "
                         "handle or the boot lock")
    def test_a_forked_child_reuses_no_handle_or_lock(self) -> None:
        """S4 R3: a child forked while the parent holds the boot lock and a shard lease gets a free boot lock, and
        each use of the parent's handle is refused ``registry_forked``; the parent's handle still works."""
        self.reg.in_flight(0)
        read, write = os.pipe()
        with idreg._BOOTING:
            pid = os.fork()
            if pid == 0:  # the child reports through the pipe and never returns into the runner
                code = 1
                try:
                    out = [idreg._BOOTING.acquire(timeout=0)]
                    for use in (lambda: self.reg.reserve(0, [1], sealed=None), lambda: self.reg.in_flight(1),
                                lambda: self.reg.settled(0), lambda: self.reg.settle(0, [], []), lambda: self.reg.genesis({})):
                        try:
                            out.append(repr(use()))
                        except idreg.IdRegistryError as error:
                            out.append(str(error))
                    os.write(write, repr(out).encode())
                    code = 0
                finally:
                    os._exit(code)
        os.close(write)
        self.assertEqual(os.waitpid(pid, 0)[1], 0)
        with os.fdopen(read, "rb") as pipe:
            self.assertEqual(pipe.read().decode(), repr([True] + ["registry_forked"] * 5))
        self.assertEqual(self.reg.reserve(0, [1], sealed=None)[0], [(1, 0, False)])

    def test_the_opening_process_uses_its_handle(self) -> None:
        """S4 R3: the fork check passes in the process that opened the handle (on Windows the only one there is)."""
        self.assertEqual(self.reg._pid, os.getpid())
        owners, n, _ = self.reg.reserve(0, [1], sealed=None)
        self.assertEqual((owners, self.reg.in_flight(0), self.reg.settled(0)), ([(1, 0, False)], [n], False))

    @unittest.skipIf(os.name == "nt", "Windows bars the replace (an open SQLite handle shares no delete access): "
                     "test_a_file_replaced_under_an_open_handle_is_barred")
    def test_a_file_replaced_under_an_open_handle_is_refused(self) -> None:
        """S4 R4 (POSIX): os.replace of the registry by a copy under an open handle names another inode: a lease
        refuses ``registry_moved`` and the next transaction fences and is refused ``registry_not_booted``."""
        copy = self.path.with_name("copy.sqlite3")
        shutil.copy(self.path, copy)
        os.replace(copy, self.path)
        with self.assertRaisesRegex(idreg.IdRegistryError, "registry_moved"):
            self.reg.in_flight(0)
        with self.assertRaisesRegex(idreg.IdRegistryError, "registry_not_booted"):
            self.reg.reserve(0, [1], sealed=None)

    @unittest.skipUnless(os.name == "nt", "POSIX allows the replace: test_a_file_replaced_under_an_open_handle_is_refused")
    def test_a_file_replaced_under_an_open_handle_is_barred(self) -> None:
        """S4 R4 (Windows): os.replace onto the open registry is refused by the OS, and the handle still works."""
        copy = self.path.with_name("copy.sqlite3")
        shutil.copy(self.path, copy)
        with self.assertRaises(PermissionError):
            os.replace(copy, self.path)
        self.assertEqual(self.reg.reserve(0, [1], sealed=None)[0], [(1, 0, False)])

    @unittest.skipUnless(os.name == "nt", "UNC is Windows path syntax")
    def test_unc_paths_are_refused(self) -> None:
        """S4: a UNC path (a share, or the \\\\?\\ form) is refused ``registry_unavailable`` by boot and by a handle, and
        a refused boot creates no file."""
        local = str(self.path.resolve())
        forms = ("\\\\localhost\\" + local.replace(":", "$", 1), "\\\\?\\" + local)
        try:
            os.stat(forms[0])
        except OSError as error:
            raise unittest.SkipTest(f"LOUD SKIP: no administrative share here: {error}") from error
        for unc in forms:
            for path in (Path(unc), Path(unc).with_name("unc.sqlite3")):
                for use in (lambda: idreg.boot(path, lambda: ({}, {}, {})), lambda: idreg.IdRegistry(path, boot=self.nonce)):
                    with self.subTest(path=path), self.assertRaisesRegex(idreg.IdRegistryError, "registry_unavailable"):
                        use()
        self.assertFalse(self.path.with_name("unc.sqlite3").exists())
        self.assertEqual(self.reg.reserve(0, [1], sealed=None)[0], [(1, 0, False)])


def rows(d: Path) -> int:
    with contextlib.closing(sqlite3.connect(d / "ids.sqlite3")) as db:
        return db.execute("SELECT count(*) FROM log").fetchone()[0]


if __name__ == "__main__":
    unittest.main()
