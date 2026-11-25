"""A refused open of a closed gate store (producer or payer) is a read: the folder is byte for byte as it was, mtimes
included (no -wal, -shm or journal file, no header rewrite).  Synthetic, non-PHI."""

from __future__ import annotations

import contextlib
import hashlib
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest
from unittest import mock

from app import right_rail_gate_codec as gate
from app import right_rail_gate_payer as payer
from app import right_rail_gate_producer as producer
from tests import _gate_shards as g
from tests import test_right_rail_gate_formats as fx
from tests import test_right_rail_gate_producer as pt
from tests._test_only_counter import TestOnlyCounter


def snapshot(folder: Path) -> dict[str, tuple[int, int, str]]:
    return {p.name: (p.stat().st_size, p.stat().st_mtime_ns, hashlib.sha256(p.read_bytes()).hexdigest()) for p in sorted(folder.iterdir())}


class ReadOnlyOpenTests(fx.Scratch):
    def _folder(self) -> Path:
        folder = Path(tempfile.mkdtemp(prefix="ro-", dir=os.environ.get("E3_SCRATCH") or None))
        self.addCleanup(shutil.rmtree, folder, ignore_errors=True)
        return folder

    def _producer(self, folder: Path, custody, *, epoch: int = fx.EPOCH, payer_newest: bytes = gate.ZERO_DIGEST):
        handle, held, cert = custody
        return producer.ShardProducer(folder / "shard.sqlite3", mark_path=folder / "shard.mark", tenant_id=fx.TENANT, shard_id=fx.SHARD,
                                      epoch=epoch, handle=handle, link=held, cosign=fx.cosigner(), key_cert=cert, payer_newest=payer_newest,
                                      counter=TestOnlyCounter(folder / "shard.counter"), floors=lambda: (0, 0, 0, bytes(64)))

    def _refused(self, folder: Path, error, reason: str, attempt) -> None:
        before = snapshot(folder)
        with self.assertRaisesRegex(error, reason):
            attempt()
        self.assertEqual(snapshot(folder), before)

    def test_a_refused_producer_open_leaves_the_folder_untouched(self) -> None:
        folder = self._folder()
        custody = fx.custody(str(folder))
        p = self._producer(folder, custody)
        pt.sealed(p, fx.batch_pays(2), state_digest=fx.STATE, created_at=fx.NOW, adds=b"")
        p.close()
        self._refused(folder, producer.GateProducerError, "epoch_regress", lambda: self._producer(folder, custody, epoch=fx.EPOCH - 1))
        self._refused(folder, producer.GateProducerError, "store_rewound", lambda: self._producer(folder, custody, payer_newest=bytes(range(64))))

    def test_a_refused_open_of_a_store_from_before_lists_were_stored_leaves_it_untouched(self) -> None:
        """The migration an open makes (the ``listed`` and ``rset`` columns, the ``earlier`` and ``rbuckets`` tables, their
        triggers) is kept only once every refusal has passed: a refused open of an older store leaves it byte for byte as
        it was."""
        for columns in (("listed", "rset"), ("rset",)):
            with self.subTest(columns=columns):
                folder = self._folder()
                custody = fx.custody(str(folder))
                p = self._producer(folder, custody)
                pt.filed(p, pt.A, 0)
                p.close()
                with contextlib.closing(sqlite3.connect(folder / "shard.sqlite3")) as db:
                    g.before(db, custody[0], (fx.TENANT, fx.SHARD), *columns)
                    db.commit()
                self._refused(folder, producer.GateProducerError, "epoch_regress", lambda: self._producer(folder, custody, epoch=fx.EPOCH - 1))
                q = self._producer(folder, custody)  # accepted: migrated, and its row still verifies
                self.assertEqual((len(q.published()), q.answered(pt.B)), (1, None))
                self.assertEqual((q._db.execute("SELECT count(*) FROM rbuckets").fetchone(), q._db.execute("SELECT rset FROM batches").fetchall()),
                                 ((0,), [(None,)]))  # the new table empty, the older row's root NULL
                q.close()

    def test_a_failed_migration_commit_is_store_locked_and_leaves_the_store_untouched(self) -> None:
        """The open's COMMIT of the migration fails (a disk error, say): the open refuses ``store_locked``, as a failed
        migration does, its connection is closed, and the older store is byte for byte as it was."""
        folder = self._folder()
        custody = fx.custody(str(folder))
        p = self._producer(folder, custody)
        pt.sealed(p, fx.batch_pays(2), state_digest=fx.STATE, created_at=fx.NOW, adds=b"")
        p.close()
        with contextlib.closing(sqlite3.connect(folder / "shard.sqlite3")) as db:
            g.before_lists(db, custody[0], (fx.TENANT, fx.SHARD))
            db.commit()
        real, opened = sqlite3.connect, []

        class FailingCommit:
            def __init__(self, db) -> None:
                self.db = db

            def __getattr__(self, name):
                return getattr(self.db, name)

            def execute(self, sql, *args):
                if sql == "COMMIT":
                    raise sqlite3.OperationalError("disk I/O error")
                return self.db.execute(sql, *args)

        def connect(*args, **kwargs):
            opened.append(real(*args, **kwargs))
            return FailingCommit(opened[-1])
        with mock.patch.object(producer.sqlite3, "connect", connect):
            self._refused(folder, producer.GateProducerError, "^store_locked$", lambda: self._producer(folder, custody))
        self.assertEqual(len(opened), 1)
        with self.assertRaises(sqlite3.ProgrammingError):  # closed
            opened[0].execute("SELECT 1")
        q = self._producer(folder, custody)  # the next open commits it
        self.assertEqual(len(q.published()), 1)
        q.close()

    def test_a_refused_payer_open_leaves_the_folder_untouched(self) -> None:
        folder = self._folder()
        with contextlib.closing(sqlite3.connect(folder / "payer.sqlite3")) as db:  # a store from before holds named their tenant
            db.execute("CREATE TABLE holds(id INTEGER PRIMARY KEY, payment_id TEXT NOT NULL, token BLOB NOT NULL, reason TEXT NOT NULL, at INTEGER NOT NULL)")
            db.commit()
        self._refused(folder, payer.GatePayerError, "store_version", lambda: payer.PayerStore(folder / "payer.sqlite3", links={}, grants=()))

    def test_a_read_only_connection_to_a_closed_producer_store_leaves_the_folder_untouched(self) -> None:
        folder = self._folder()
        p = self._producer(folder, fx.custody(str(folder)))
        pt.sealed(p, fx.batch_pays(2), state_digest=fx.STATE, created_at=fx.NOW, adds=b"")
        p.close()
        before = snapshot(folder)
        with contextlib.closing(g.read_only(folder / "shard.sqlite3")) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM batches").fetchone()[0], 1)
        self.assertEqual(snapshot(folder), before)

    def test_a_store_with_unmerged_wal_frames_is_refused_not_read_short(self) -> None:
        folder = self._folder()
        (folder / "shard.sqlite3").write_bytes(b"")
        (folder / "shard.sqlite3-wal").write_bytes(b"frames")
        with self.assertRaisesRegex(RuntimeError, "not closed cleanly"):
            g.read_only(folder / "shard.sqlite3")


if __name__ == "__main__":
    unittest.main()
