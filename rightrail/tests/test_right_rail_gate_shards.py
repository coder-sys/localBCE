"""Multi-shard scenarios: the producers and ``gate_rules`` together, with crashes as child processes.  Line identity is per
shard: each shard's own history index decides a repeated line.  After every scenario ``_gate_shards.inv`` holds.
Synthetic, non-PHI."""

from __future__ import annotations

import contextlib
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest
from unittest import mock

from app import right_rail_gate_codec as gate
from app import right_rail_gate_decide as decider
from app import right_rail_gate_payer as payer
from app import right_rail_gate_producer as producer
from app import right_rail_gate_signer as signer
from tests import _gate_shards as g
from tests import test_right_rail_gate_formats as fx

T, BAD, NEXT = {1: [10], 2: [11, 12]}, (12,), {3: [20]}  # payment 1 ALLOW; payment 2 HOLD (line 12 is dated outside the enrollment), 11 is its ALLOW line


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
        return db.execute("SELECT header, signature FROM batches ORDER BY id DESC LIMIT 1").fetchone()
    finally:
        db.close()


class ShardTests(fx.Scratch):
    @contextlib.contextmanager
    def cluster(self, shards: int = 2):
        with self.scratch() as tmp:
            yield g.Cluster(tmp, fx.custody(tmp), shards=shards)

    def finish(self, c: g.Cluster, *again: dict) -> None:
        """Shard 0 sends ``again`` (sealed or not: a sealed batch's lines hold as already decided), then the invariants."""
        for batch in again:
            c.send(0, batch, BAD)
        g.inv(self, c)
        self.assertEqual([s for s, _, line in g.allowed(c) if line == 10], [0])  # paid once, by shard 0

    def test_a_hold_in_a_payment_does_not_record_its_allow_line(self) -> None:
        with self.cluster() as c:
            first = c.send(0, {1: [10, 11]}, bad=(11,))
            self.assertEqual([first[10], first[11].split()[0]], ["ALLOW -", "HOLD"])  # 10 is an ALLOW line in a HOLD payment
            second = c.send(0, {3: [10], 4: [11]})
            self.assertEqual((second[10], second[11]), ("ALLOW -", "HOLD ALREADY_DECIDED"))
            g.inv(self, c)

    def test_a_retry_makes_no_second_payment(self) -> None:
        with self.cluster() as c:
            c.send(0, {1: [10]}, crash="commit")  # decided, died before the checkpoint
            self.assertEqual(c.send(0, {1: [10]}), {10: "ALLOW -"})  # the retry decides it again
            self.assertEqual(c.send(0, {2: [10]}), {10: "HOLD ALREADY_DECIDED,FFS_DUPLICATE_LINE"})
            self.assertEqual([x for x in g.allowed(c) if x[2] == 10], [(0, 1, 10)])
            g.inv(self, c)

    def test_a_crash_before_the_checkpoint_signs_nothing(self) -> None:
        with self.cluster() as c:
            c.send(0, T, BAD, crash="commit")
            self.assertIsNone(newest_row(c, 0) if c.store(0).exists() else None)  # nothing signed
            self.finish(c, T, NEXT)

    def test_a_crash_after_the_first_row_or_after_the_batch(self) -> None:
        for point, torn in (("seal", False), ("seal", True), ("after", False)):
            with self.subTest(point=point, torn=torn), self.cluster() as c:
                c.send(0, T, BAD, crash=point)
                if torn:
                    tear(c.store(0))
                row = newest_row(c, 0)
                c.producer(0).close()  # opening re-seals the open row
                if row:
                    self.assertEqual(newest_row(c, 0)[0], row[0])  # the same header bytes
                    self.assertIsNotNone(newest_row(c, 0)[1])
                self.finish(c, T, NEXT)  # the resend pays nothing twice

    def test_a_stale_answer_is_refused_before_the_seal(self) -> None:
        # B2's decide discards B1's prepared answer, so B1 is not sealed from it; B2 is another request on the number B1's
        # stored frame holds, so it HOLDs (HOLD RETRY) and decides nothing.  The next request with a seal time seals B1 first.
        with self.cluster() as c:
            prod = c.producer(0)
            try:
                b1, b2 = [g.decide_batch(c, prod, 0, p, flat=c.dir / "idx0") for p in ({1: [10]}, {2: [11]})]
                self.assertEqual(b2[2], {11: "HOLD flat_conflict"})
                with self.assertRaisesRegex(decider.GateDecideError, "stale_answer"):
                    decider.commit(prod, fx.PROGRAM, b1[0], fx.NOW, c.tenant)
                with self.assertRaisesRegex(decider.GateDecideError, "hold_answer"):
                    decider.commit(prod, fx.PROGRAM, b2[0], fx.NOW, c.tenant)
            finally:
                prod.close()
            self.assertEqual(c.send(0, {7: [12]}), {12: "ALLOW -"})
            self.assertEqual(sorted(i for lines in g.sealed_allows(c, 0).values() for _, i in lines), [10, 12])
            g.inv(self, c)

    def test_an_open_row_blocks_the_next_decide_and_reseals_at_reopen(self) -> None:
        # A seal that fails short of gate_verify_refused leaves an open row and closes the producer: the next decide is refused, and a reopen reseals it.
        for reseal in (False, True):
            with self.subTest(reseal=reseal), self.cluster() as c:
                prod = c.producer(0)
                try:
                    ans, leaves, _ = g.decide_batch(c, prod, 0, T, BAD)
                    with mock.patch.object(signer, "seal", side_effect=signer.GateSignerError("gate_verify_failed")), \
                            self.assertRaises(signer.GateSignerError):
                        decider.commit(prod, fx.PROGRAM, ans, fx.NOW, c.tenant)
                    with self.assertRaisesRegex(producer.GateProducerError, "producer_closed"):
                        g.decide_batch(c, prod, 0, NEXT)
                finally:
                    prod.close()
                if not reseal:
                    with mock.patch.object(signer, "seal", side_effect=signer.GateSignerError("gate_verify_refused")), \
                            self.assertRaisesRegex(producer.GateProducerError, "publish_refused"):
                        c.producer(0)
                self.finish(c, T, NEXT)

    def test_voided_reservation_is_decided_again_on_retry(self) -> None:
        with self.cluster() as c:
            with mock.patch.object(signer, "seal", side_effect=signer.GateSignerError("gate_verify_refused")), \
                    self.assertRaisesRegex(producer.GateProducerError, "publish_refused"):
                c.send(0, T, BAD)
            self.assertIsNone(newest_row(c, 0))  # the voided row is gone
            self.finish(c, T, NEXT)

    def test_a_producer_only_restore_is_refused(self) -> None:
        with self.cluster() as c:
            c.send(0, T, BAD)
            old = snapshot(c.store(0))
            c.send(0, NEXT)
            restore(c.store(0), old)
            with self.assertRaisesRegex(producer.GateProducerError, "store_rewound"):
                c.producer(0)  # the store is behind its mark

    def pay(self, c: g.Cluster, store: payer.PayerStore, k: int, p: int) -> str | None:
        """Shard k decides payment p (line 10, X) and seals it; the payer stores the checkpoint, sends p and releases it."""
        prod = c.producer(k)
        try:
            ans, leaves, status = g.decide_batch(c, prod, k, {p: [10]})
            _, signed, tokens = decider.commit(prod, fx.PROGRAM, ans, fx.NOW, c.tenant)
        finally:
            prod.close()
        self.assertEqual((status, store.store_checkpoint(signed)), ({10: "ALLOW -"}, "stored"))
        store.send(g.request(p, k, [10]), transmit=lambda data: None)
        return store.release(g.request(p, k, [10]), gate.encode_token(tokens[0]), now=fx.NOW)

    @contextlib.contextmanager
    def paid_then_restored(self, restore_dir: bool = True):
        """Copy the whole directory; shard 0 pays X in payment 1 (sealed, stored and released by the payer).  Then, with
        ``restore_dir``, the copy comes back."""
        with tempfile.TemporaryDirectory() as keep, self.cluster() as c:
            copy = Path(keep) / "copy"
            shutil.copytree(c.dir, copy)
            c.payer = store = self.track(payer.PayerStore(Path(keep) / "payer.sqlite3", links={fx.TENANT: c.custody[1]},
                                                          grants=((fx.TENANT, g.GRANT_ID, (g.release(),), (g.release(),)),)))
            store.install_cert(c.custody[2])
            self.assertIsNone(self.pay(c, store, 0, 1))
            if restore_dir:
                g.wipe(c.dir)
                shutil.copytree(copy, c.dir, dirs_exist_ok=True)
            yield c, store

    def test_startup_store_rewound(self) -> None:
        """The payer holds shard 0's newest checkpoint.  A store restored from before it is refused at startup, so the shard
        decides nothing and X is released once; a current store opens and decides on."""
        with self.paid_then_restored(False) as (c, store):
            c.producer(0).close()  # the store holds the payer's newest checkpoint
            self.assertEqual(c.send(0, {2: [11]}), {11: "ALLOW -"})
        with self.paid_then_restored() as (c, store):
            with self.assertRaisesRegex(producer.GateProducerError, "store_rewound"):
                c.producer(0)
            with self.assertRaisesRegex(producer.GateProducerError, "store_rewound"):
                c.send(0, {2: [10]})
            self.assertEqual([p for (p,) in store._db.execute("SELECT payment_id FROM releases")], ["pay-0001"])
            self.assertEqual(g.allowed(c), [])  # the restored store sealed nothing past the copy

    def test_startup_refuses_a_missing_store_the_payer_has_a_checkpoint_for(self) -> None:
        with self.paid_then_restored(False) as (c, store):
            for suffix in ("", "-wal", "-shm"):
                Path(f"{c.store(0)}{suffix}").unlink(missing_ok=True)
            with self.assertRaisesRegex(producer.GateProducerError, "store_rewound"):
                c.producer(0)

    def test_the_refusal_is_sticky_and_leaves_the_directory_as_it_was(self) -> None:
        """The store and its mark are both deleted, the payer's newest checkpoint is past genesis: a start refuses and
        creates nothing, so the next start refuses the same way (not as a new shard)."""
        with self.paid_then_restored(False) as (c, store):
            for name in (c.store(0), c.dir / "s0.mark"):
                for suffix in ("", "-wal", "-shm"):
                    Path(f"{name}{suffix}").unlink(missing_ok=True)
            before = sorted(f.name for f in c.dir.iterdir())
            for _ in range(2):
                with self.assertRaisesRegex(producer.GateProducerError, "store_rewound"):
                    c.producer(0)
                self.assertEqual(sorted(f.name for f in c.dir.iterdir()), before)
            self.assertFalse(c.store(0).exists() or (c.dir / "s0.mark").exists())

    def test_lost_adds_stop_the_shard(self) -> None:
        with self.cluster() as c:
            c.send(0, T, BAD)
            with contextlib.closing(sqlite3.connect(c.store(0))) as db:  # an edit outside the producer drops a row
                db.execute("DROP TRIGGER batches_fixed")
                db.execute("UPDATE batches SET adds = substr(adds, 925)")
                db.commit()
            with self.assertRaisesRegex(producer.GateProducerError, "store_tampered"):  # TINS: the pledge signs adds, so the edit is refused at open
                c.send(0, T, BAD)

    def test_same_shard_resend_of_a_paid_line(self) -> None:
        with self.cluster() as c:
            c.send(0, {1: [10]})
            c.send(0, NEXT)
            self.assertEqual(c.send(0, {8: [10]})[10], "HOLD ALREADY_DECIDED,FFS_DUPLICATE_LINE")
            g.inv(self, c)


if __name__ == "__main__":
    unittest.main()
