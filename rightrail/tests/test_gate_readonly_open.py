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
        handle, root_pk, cert = custody
        return producer.ShardProducer(folder / "shard.sqlite3", mark_path=folder / "shard.mark", tenant_id=fx.TENANT, shard_id=fx.SHARD,
                                      epoch=epoch, handle=handle, root_pk=root_pk, key_cert=cert, payer_newest=payer_newest,
                                      counter=TestOnlyCounter(folder / "shard.counter"), floors=lambda: (0, 0))

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

    def test_a_refused_payer_open_leaves_the_folder_untouched(self) -> None:
        folder = self._folder()
        with contextlib.closing(sqlite3.connect(folder / "payer.sqlite3")) as db:  # a store from before holds named their tenant
            db.execute("CREATE TABLE holds(id INTEGER PRIMARY KEY, payment_id TEXT NOT NULL, token BLOB NOT NULL, reason TEXT NOT NULL, at INTEGER NOT NULL)")
            db.commit()
        self._refused(folder, payer.GatePayerError, "store_version", lambda: payer.PayerStore(folder / "payer.sqlite3", root_keys={}, grants=()))

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
