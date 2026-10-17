"""Core R0.5 (rrb/archive/xi2-records-20261001.md "R0.5"; red team rrb/reviews/core-r1-redteam.md H4-H5):
the store is WAL with full sync, so an acknowledged commit is durable and a reader never blocks a write.

Power loss cannot be simulated here: durability rests on WAL with synchronous=FULL (SQLite's documented guarantee,
a trust assumption in the XI.2 record). These tests pin the settings, where they apply and their effects."""

from contextlib import closing
from pathlib import Path
import re
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

from app import right_rail_financial_owner as owner
from tests.test_right_rail_financial_core_r1 import _pay
from tests import test_right_rail_financial_acceptance as acceptance
from tests.rightrail_intake_rows import pay

BEGIN_WRITE = re.compile(r"\s*BEGIN\s+(IMMEDIATE|EXCLUSIVE)", re.I)
FULL_SYNC = re.compile(r"\s*PRAGMA\s+synchronous\s*=\s*(FULL|EXTRA|2|3)\s*;?\s*", re.I)


def _journal(path, assignment=""):
    with closing(sqlite3.connect(str(path), isolation_level=None)) as connection:
        return connection.execute(f"PRAGMA journal_mode{assignment}").fetchone()[0]


class DurabilityR05Tests(unittest.TestCase):
    def setUp(self):
        self.fixture = acceptance.RightRailFinancialAcceptanceTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def _restore(self, store, destination):
        return owner.FinancialOwner.restore_continuity(package_bytes=store.export_continuity(), recovered_path=destination,
                                                       trusted_authority=self.fixture.authority, clock=acceptance._Clock())

    def test_store_is_wal_and_every_owner_connection_syncs_fully(self):
        # Every connection the owner opens, enumerated by the function that asked for it: creation, open verification,
        # write, read snapshot and the restore checkpoint all go through _connect. (The empty-file probe in _initialize
        # opens directly, but only begins and rolls back while another creator holds the new file.)
        traces, connect = [], sqlite3.connect

        def traced(*args, **kwargs):
            connection, statements = connect(*args, **kwargs), []
            connection.set_trace_callback(statements.append)
            if sys._getframe(1).f_code.co_filename == owner.__file__:
                traces.append((sys._getframe(1).f_code.co_name, sys._getframe(2).f_code.co_name, statements))
            return connection

        with patch.object(sqlite3, "connect", traced):
            store = self.fixture._build_base()
            pay(self.fixture._make_owner(path=store.path, clock=store.clock), **_pay("item-06"))
            store.summary()
            self._restore(store, Path(self.fixture.temp_dir.name) / "restored.sqlite")
        with open(store.path, "rb") as handle:
            self.assertEqual(handle.read(20)[18:20], b"\x02\x02", "file header bytes 18-19 are 2,2 only in WAL mode")
        self.assertEqual({opener for opener, _caller, _statements in traces}, {"_connect"})
        self.assertEqual({caller for _opener, caller, _statements in traces},
                         {"_initialize", "_verify_open_identity", "_read_snapshot", "restore_continuity"})  # R1a: writes reuse the open's connection
        for _opener, caller, statements in traces:
            with self.subTest(caller=caller):
                sync = next((i for i, sql in enumerate(statements) if FULL_SYNC.fullmatch(sql)), None)
                self.assertIsNotNone(sync, statements)
                self.assertFalse([sql for sql in statements[:sync] if BEGIN_WRITE.match(sql) or "PRAGMA journal_mode" in sql or "wal_checkpoint" in sql])

    def test_an_acknowledged_commit_is_in_the_files_a_crash_leaves(self):
        # The commit reached the main file or -wal by the time the response is released (also true of the rollback
        # journal: this shows no commit is held back, not that it was synced; synchronous=FULL is the test above).
        store = self.fixture._build_base()
        self.assertIn("status", pay(store, **_pay("item-06")))
        crashed = Path(tempfile.mkdtemp(dir=self.fixture.temp_dir.name)) / "crashed.sqlite"
        for suffix in ("", "-wal"):  # what is on disk the moment the response is released; the owner is never closed
            source = Path(str(store.path) + suffix)
            if source.exists():
                Path(str(crashed) + suffix).write_bytes(source.read_bytes())
        with closing(sqlite3.connect(str(crashed))) as reopened:
            self.assertIsNotNone(reopened.execute("SELECT 1 FROM payments WHERE payment_id='x-item-06-payment'").fetchone())

    def test_a_reader_does_not_block_a_write(self):
        store = self.fixture._build_base()
        with closing(sqlite3.connect(str(store.path), isolation_level=None)) as reader:
            reader.execute("BEGIN")
            reader.execute("SELECT COUNT(*) FROM financial_events").fetchone()  # a staff read or audit in progress (H4)
            self.assertIn("status", pay(store, **_pay("item-06")))
            reader.execute("COMMIT")

    def test_a_pre_wal_store_changes_only_in_an_open_that_may_migrate_it(self):
        store = self.fixture._make_owner()
        summary = store.summary()
        shadow = self._restore(store, Path(self.fixture.temp_dir.name) / "shadow.sqlite")
        store.close()  # R1a: changing the journal mode needs the owner's writer closed
        common = {"config": store.config, "trusted_authority": self.fixture.authority, "clock": acceptance._Clock()}
        opens = {
            "shadow": (shadow.path, "^shadow_requires_migration$", {"mode": "SHADOW", "owner_id": owner._SHADOW_OWNER_ID}),
            "existing-only": (store.path, "^shadow_requires_migration$", {"existing_only": True}),
            "refused": (store.path, "^owner_identity$", {"owner_id": "another-owner"}),
        }
        for name, (path, refusal, arguments) in opens.items():
            with self.subTest(name):
                self.assertEqual(_journal(path, "=DELETE"), "delete")
                before = path.read_bytes()  # the whole store: a rollback-journal store has no -wal
                with self.assertRaisesRegex(owner.FinancialIntegrityError, refusal):
                    owner.FinancialOwner(path=path, **common, **arguments)
                self.assertEqual((path.read_bytes(), Path(f"{path}-wal").exists()), (before, False))
        migrated = owner.FinancialOwner(path=store.path, **common)
        self.addCleanup(migrated.close)
        self.assertEqual(_journal(store.path), "wal")
        self.assertEqual(migrated.summary(), summary)
        self.fixture._assert_verified(migrated)

    def test_a_store_that_will_not_become_wal_is_refused(self):
        # A file system without shared memory answers journal_mode=WAL with another mode: creation and the migrating
        # switch both refuse it rather than acknowledge commits without the WAL durability claim.
        connect = sqlite3.connect

        class NoWal(sqlite3.Connection):
            def execute(self, sql, *args):
                return super().execute("SELECT 'delete'" if sql == "PRAGMA journal_mode=WAL" else sql, *args)

        no_wal = patch.object(sqlite3, "connect", lambda *args, **kwargs: connect(*args, factory=NoWal, **kwargs))
        with no_wal, self.assertRaisesRegex(owner.FinancialIntegrityError, "^journal_mode$"):
            self.fixture._make_owner(path=Path(self.fixture.temp_dir.name) / "born.sqlite")
        store = self.fixture._make_owner()
        store.close()
        self.assertEqual(_journal(store.path, "=DELETE"), "delete")
        with no_wal, self.assertRaisesRegex(owner.FinancialIntegrityError, "^journal_mode$"):
            owner.FinancialOwner(path=store.path, config=store.config, trusted_authority=self.fixture.authority, clock=acceptance._Clock())
        self.assertEqual(_journal(store.path), "delete")

    def test_a_restore_refuses_to_publish_while_a_reader_pins_the_wal(self):
        # A reader's open transaction keeps the import in the attempt's -wal: the checkpoint cannot empty it.
        store = self.fixture._build_base()
        derive, close = owner.FinancialOwner._derive_command_log, owner.FinancialOwner.close
        readers = []
        self.addCleanup(lambda: [reader.close() for reader in readers])
        for released in (True, False):
            with self.subTest(released=released):
                closes = []

                def read_during_import(attempt, connection):
                    readers.append(sqlite3.connect(attempt.path.resolve().as_uri() + "?mode=ro", uri=True, isolation_level=None))
                    readers[-1].execute("BEGIN")
                    readers[-1].execute("SELECT 1 FROM sqlite_master").fetchone()
                    derive(attempt, connection)

                def close_releasing(attempt):
                    closes.append(close(attempt))
                    if released and len(closes) == 2:  # the failure path closes the owner again before its cleanup
                        readers.pop().close()

                destination = Path(self.fixture.temp_dir.name) / f"pinned-{released}.sqlite"
                patched = patch.multiple(owner.FinancialOwner, _derive_command_log=read_during_import, close=close_releasing)
                with patched, self.assertRaises(owner.FinancialContinuityError) as refused:
                    self._restore(store, destination)
                self.assertFalse(destination.exists())
                # Windows: SQLite opens without FILE_SHARE_DELETE, so the reader that pins the -wal also keeps the attempt
                # files from being removed, and a cleanup failure is reported over its cause (XI.2 record).
                masked = not released and sys.platform == "win32"
                self.assertEqual(str(refused.exception), "continuity_restore_cleanup" if masked else "continuity_restore_checkpoint")


if __name__ == "__main__":
    unittest.main()
