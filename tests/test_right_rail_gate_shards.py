"""Multi-shard scenarios (multi-shard-runtime-v1 section B): the id registry, the producers and ``gate_rules`` together,
with crashes as child processes.  After every scenario ``_gate_shards.inv`` holds.  Synthetic, non-PHI."""

from __future__ import annotations

import contextlib
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest
from unittest import mock

from app import right_rail_gate_idreg as idreg
from app import right_rail_gate_producer as producer
from app import right_rail_gate_signer as signer
from tests import _gate_shards as g
from tests import test_right_rail_gate_formats as fx

T, BAD, NEXT = {1: [10], 2: [11, 12]}, (12,), {3: [20]}  # payment 1 ALLOW; payment 2 HOLD (line 12's member died), 11 is its ALLOW line
ELSEWHERE = {4: [10], 5: [11], 6: [12], 7: [20]}  # shard 1 sends every id shard 0 has seen


def count(c: g.Cluster, kind: int) -> int:
    db = sqlite3.connect(f"file:{c.reg}?mode=ro", uri=True)
    try:
        return db.execute("SELECT COUNT(*) FROM log WHERE kind = ?", (kind,)).fetchone()[0]
    finally:
        db.close()


def snapshot(path: Path) -> dict[str, bytes]:
    return {s: Path(f"{path}{s}").read_bytes() for s in ("", "-wal") if Path(f"{path}{s}").exists()}


def restore(path: Path, files: dict[str, bytes]) -> None:
    for s in ("", "-wal", "-shm"):
        Path(f"{path}{s}").unlink(missing_ok=True)
        if s in files:
            Path(f"{path}{s}").write_bytes(files[s])


def tear(path: Path) -> None:
    wal = Path(f"{path}-wal")
    if wal.exists() and wal.stat().st_size > 100:
        wal.write_bytes(wal.read_bytes()[:-100])


def newest_row(c: g.Cluster, k: int):
    db = sqlite3.connect(f"file:{c.store(k)}?mode=ro", uri=True)
    try:
        return db.execute("SELECT idreg_n, header, signature FROM batches ORDER BY id DESC LIMIT 1").fetchone()
    finally:
        db.close()


def head_at(c: g.Cluster, n: int) -> bytes:
    db = sqlite3.connect(f"file:{c.reg}?mode=ro", uri=True)
    try:
        return db.execute("SELECT head FROM log WHERE n = ?", (n,)).fetchone()[0]
    finally:
        db.close()


class ShardTests(fx.Scratch):
    @contextlib.contextmanager
    def cluster(self):
        with self.scratch() as tmp:
            c = g.Cluster(tmp, fx.custody(tmp))
            c.boot()
            yield c

    def finish(self, c: g.Cluster, *again: dict) -> None:
        """Restart, shard 0 sends ``again`` (the batches that left no checkpoint), shard 1 sends every id, then the
        invariants.  A sealed batch is not resent: a repeat inside one shard is the decide layer's (unbuilt), not the registry's."""
        c.boot()
        for batch in again:
            c.send(0, batch, BAD)
        c.send(1, ELSEWHERE)
        g.inv(self, c)
        self.assertEqual([s for s, _, line in g.allowed(c) if line == 10], [0])  # paid once, by shard 0

    def test_s1_hold_frees_allow_id(self) -> None:
        with self.cluster() as c:
            first = c.send(0, {1: [10, 11]}, bad=(11,))
            self.assertEqual([first[10], first[11].split()[0]], ["ALLOW -", "HOLD"])  # 10 is an ALLOW line in a HOLD payment
            c.send(0, NEXT)  # the next batch's settle frees 10 and records 11
            second = c.send(1, {3: [10], 4: [11]})
            self.assertEqual((second[10], second[11]), ("ALLOW -", "HOLD ALREADY_DECIDED"))
            g.inv(self, c)

    def test_s2_retry_no_second_payment(self) -> None:
        with self.cluster() as c:
            c.send(0, {1: [10]}, crash="commit")  # reserved 10, died before the checkpoint
            c.boot()
            before = count(c, 0)
            for _ in range(3):
                self.assertEqual(c.send(1, {2: [10]}), {10: "WAIT -"})  # unavailable, and no shard-1 leaf or row
            self.assertEqual(count(c, 0), before)
            self.assertEqual(c.send(0, {1: [10]}), {10: "ALLOW -"})  # the retry frees and re-reserves 10
            c.send(0, NEXT)  # its settle makes 10 recorded
            self.assertEqual(c.send(1, {2: [10]}), {10: "HOLD ALREADY_DECIDED"})
            self.assertEqual([x for x in g.allowed(c) if x[2] == 10], [(0, 1, 10)])
            g.inv(self, c)

    def test_k0_dies_in_the_registry_transaction(self) -> None:
        for torn in (False, True):
            with self.subTest(torn=torn), self.cluster() as c:
                before = count(c, 0)
                c.send(0, T, BAD, crash="reserve")
                if torn:
                    tear(c.reg)
                self.assertEqual(count(c, 0), before)
                self.finish(c, T, NEXT)

    def test_k1_dies_before_the_checkpoint(self) -> None:
        with self.cluster() as c:
            c.send(0, T, BAD, crash="commit")
            self.assertEqual((count(c, 0), newest_row(c, 0)), (3, None))  # reserved, nothing signed
            self.finish(c, T, NEXT)

    def test_k2_dies_after_row_a_and_k3_after_the_batch(self) -> None:
        for point, torn in (("seal", False), ("seal", True), ("after", False)):
            with self.subTest(point=point, torn=torn), self.cluster() as c:
                c.send(0, T, BAD, crash=point)
                if torn:
                    tear(c.store(0))
                row = newest_row(c, 0)
                if row:
                    self.assertEqual(row[1][-64:], head_at(c, row[0]))
                reserved = count(c, 0)
                c.boot()
                c.producer(0).close()  # opening re-seals the open row
                self.assertEqual(count(c, 0), reserved)  # a restart reserves nothing
                if row:
                    self.assertEqual(newest_row(c, 0)[:2], row[:2])  # the same header bytes
                    self.assertIsNotNone(newest_row(c, 0)[2])
                self.finish(c, *(() if row else (T,)), NEXT)

    def test_k4_dies_in_the_next_transaction(self) -> None:
        with self.cluster() as c:
            c.send(0, T, BAD)
            frees, reserves = count(c, 1), count(c, 0)
            c.send(0, NEXT, crash="reserve")
            self.assertEqual((count(c, 1), count(c, 0)), (frees, reserves))  # t's frees and t+1's reserve are both absent
            c.boot()
            c.send(0, NEXT)
            self.assertGreater(count(c, 1), frees)  # both present after the retry
            self.assertGreater(count(c, 0), reserves)
            self.finish(c)

    def test_voided_reservation_is_freed_on_retry(self) -> None:
        with self.cluster() as c:
            with mock.patch.object(signer, "seal", side_effect=signer.GateSignerError("gate_verify_refused")), \
                    self.assertRaisesRegex(producer.GateProducerError, "publish_refused"):
                c.send(0, T, BAD)
            self.assertIsNone(newest_row(c, 0))  # the voided row is gone
            self.finish(c, T, NEXT)

    def test_k5_dead_shard_keeps_its_ids_unavailable(self) -> None:
        with self.cluster() as c:
            c.send(0, {1: [10]}, crash="commit")
            c.boot()
            for _ in range(2):
                self.assertEqual(c.send(1, {2: [10]}), {10: "WAIT -"})
            self.assertEqual([x for x in g.allowed(c) if x[0] == 1], [])
            g.inv(self, c)

    def test_r1_registry_only_restore_is_rewound(self) -> None:
        for wal in (True, False):
            with self.subTest(wal=wal), self.cluster() as c:
                c.send(0, T, BAD, crash="after")
                old = snapshot(c.reg)
                c.boot()
                c.send(0, NEXT)
                restore(c.reg, old if wal else {"": old[""]})
                with self.assertRaisesRegex(idreg.IdRegistryError, "registry_rewound"):
                    c.boot()

    def test_r2_lost_uncommitted_rows_still_boot(self) -> None:
        with self.cluster() as c:
            c.send(0, T, BAD)
            old = snapshot(c.reg)
            c.send(0, NEXT, crash="reserve")
            restore(c.reg, old)
            self.finish(c, NEXT)

    def test_r3_producer_only_restore_is_refused(self) -> None:
        with self.cluster() as c:
            c.send(0, T, BAD)
            old = snapshot(c.store(0))
            c.send(0, NEXT)
            restore(c.store(0), old)
            c.boot()  # the older commitment lies inside the chain
            with self.assertRaisesRegex(producer.GateProducerError, "store_rewound"):
                c.producer(0)

    def test_r4_a_swapped_registry_is_not_booted(self) -> None:
        with self.cluster() as c:
            c.send(0, T, BAD)
            old = snapshot(c.reg)
            c.boot()
            restore(c.reg, old)
            with self.assertRaisesRegex(idreg.IdRegistryError, "registry_not_booted"):
                c.send(0, NEXT)

    def test_r5_whole_directory_restore_boots_and_forks(self) -> None:
        with self.cluster() as c, tempfile.TemporaryDirectory() as keep:
            c.send(0, T, BAD)
            shutil.copytree(c.dir, keep, dirs_exist_ok=True)
            c.send(0, NEXT)
            published = c.producer(0)
            original = published.published()[-1]
            published.close()
            for f in c.dir.iterdir():
                f.unlink()
            shutil.copytree(keep, c.dir, dirs_exist_ok=True)
            c.boot()  # documented residual (design 9, R5): a whole-directory restore passes the boot check
            c.send(0, {3: [30]})  # the restored shard publishes a different batch at the same seq
            again = c.producer(0)
            new = again.published()[-1]
            again.close()
            handle, root_pk, cert = c.custody
            frame = root_pk + fx._list([signer.framed(cert)]) + fx._list([signer.framed(original)]) + fx._u16(0) + signer.framed(new)
            self.assertTrue(signer.gate_verify(3, frame).startswith("GATE_VERIFY=FORK"))


if __name__ == "__main__":
    unittest.main()
