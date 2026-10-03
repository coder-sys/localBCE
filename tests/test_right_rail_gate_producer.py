"""The gate checkpoint producer (``app/right_rail_gate_producer.py``): chain, crash, rewind and epoch behaviour.
Synthetic, non-PHI."""

from __future__ import annotations

from pathlib import Path
import sqlite3
import unittest
from unittest import mock

from app import right_rail_gate_codec as gate
from app import right_rail_gate_idreg as idreg
from app import right_rail_gate_mark as marks
from app import right_rail_gate_producer as producer
from app import right_rail_gate_signer as signer
from tests import test_right_rail_gate_formats as fx

_RECORD = 80 + marks.CHECK  # one producer mark record
IDREG = (1, bytes(range(1, 65)))  # a registry reply (n, head): the head is signed into the CHECKPOINT/v2 header


class ProducerTests(fx.Scratch):
    """One serial producer per (tenant, shard): reserve, sign, Lean publish check, seal, mark, publish."""

    def _open(self, tmp: str, custody, epoch: int = fx.EPOCH, mark: str = "shard.mark"):
        handle, root_pk, cert = custody
        return self.track(producer.ShardProducer(Path(tmp) / "shard.sqlite3", mark_path=Path(tmp) / mark,
                                      tenant_id=fx.TENANT, shard_id=fx.SHARD, epoch=epoch, handle=handle,
                                      root_pk=root_pk, key_cert=cert))

    def test_chain_links_and_publishes_in_seq_order(self) -> None:
        with self.scratch() as tmp:
            p = self._open(tmp, fx.custody(tmp))
            ca, sa, _ = p.commit(fx.PROGRAM, fx.batch_leaves(0, 3), state_digest=fx.STATE, created_at=fx.NOW, idreg=IDREG, free=(), adds=b"")
            cb, sb, tb = p.commit(fx.PROGRAM, fx.batch_leaves(0, 2, 3), state_digest=fx.STATE, created_at=fx.NOW + 1, idreg=IDREG, free=(), adds=b"")
            self.assertEqual((ca.seq_from, ca.seq_to, cb.seq_from, cb.seq_to), (0, 2, 3, 4))
            self.assertEqual((cb.prev_checkpoint_digest, cb.event_head), (gate.checkpoint_digest(ca),) * 2)
            self.assertEqual(ca.event_head, gate.ZERO_DIGEST)
            self.assertEqual((cb.evidence_root, len(tb)), (gate.ZERO_DIGEST, 2))
            self.assertEqual(p.published(), [sa, sb])
            self.assertEqual(p.anchor(), fx.STATE)  # the decide layer's Ctx.anchor: the last sealed state digest

    def test_no_empty_checkpoint(self) -> None:
        with self.scratch() as tmp:
            p = self._open(tmp, fx.custody(tmp))
            with self.assertRaises(producer.GateProducerError):
                p.commit(fx.PROGRAM, [], state_digest=fx.STATE, created_at=fx.NOW, idreg=IDREG, free=(), adds=b"")
            self.assertEqual(p.published(), [])

    def test_a_refused_batch_is_voided_and_the_next_one_takes_its_seq(self) -> None:
        with self.scratch() as tmp:
            p = self._open(tmp, fx.custody(tmp))
            stray = fx._leaf(0, 0, member_key=fx.member(0, shard=5))  # a member key that routes to another shard
            with self.assertRaisesRegex(producer.GateProducerError, "publish_refused"):
                p.commit(fx.PROGRAM, [stray], state_digest=fx.STATE, created_at=fx.NOW, idreg=IDREG, free=(), adds=b"")
            self.assertEqual((p.published(), p.anchor()), ([], None))
            self.assertEqual(p.commit(fx.PROGRAM, fx.batch_leaves(0, 1), state_digest=fx.STATE, created_at=fx.NOW, idreg=IDREG, free=(), adds=b"")[0].seq_from, 0)
            foreign = fx._leaf(1, 1, shard=2)
            with self.assertRaisesRegex(producer.GateProducerError, "foreign_leaf"):
                p.commit(fx.PROGRAM, [foreign], state_digest=fx.STATE, created_at=fx.NOW, idreg=IDREG, free=(), adds=b"")

    def test_crash_between_sign_and_persist_reseals_the_same_header(self) -> None:
        with self.scratch() as tmp:
            custody = fx.custody(tmp)
            p = self._open(tmp, custody)
            p.commit(fx.PROGRAM, fx.batch_leaves(0, 2), state_digest=fx.STATE, created_at=fx.NOW, idreg=IDREG, free=(), adds=b"")
            reserved: list[bytes] = []
            real = signer.seal

            def crash(*args):
                reserved.append(args[4])
                real(*args)  # signed and verified, then the process dies before the seal commits
                raise KeyboardInterrupt

            with mock.patch.object(signer, "seal", crash), self.assertRaises(KeyboardInterrupt):
                p.commit(fx.PROGRAM, fx.batch_leaves(0, 2, 2), state_digest=fx.STATE, created_at=fx.NOW + 1, idreg=IDREG, free=(), adds=b"")
            self.assertEqual(len(p.published()), 1)  # nothing unsealed was published
            p.close()
            again = self._open(tmp, custody)  # opening re-seals the reserved batch before any new one
            published = again.published()
            self.assertEqual(len(published), 2)
            self.assertTrue(published[1].startswith(reserved[0]))  # same header bytes at the same seq
            self.assertEqual(len(published[1]), len(reserved[0]) + 2 + gate.ML_DSA_87_SIGNATURE)

    def test_restart_never_gives_a_position_a_second_batch(self) -> None:
        """After any restart a position holds one header and one signature; a later batch takes the next seq."""
        with self.scratch() as tmp:
            custody = fx.custody(tmp)
            first = self._open(tmp, custody)
            first.commit(fx.PROGRAM, fx.batch_leaves(0, 2), state_digest=fx.STATE, created_at=fx.NOW, idreg=IDREG, free=(), adds=b"")
            before = first.published()
            first.close()
            again = self._open(tmp, custody)
            again.commit(fx.PROGRAM, fx.batch_leaves(0, 2, 2), state_digest=fx.STATE, created_at=fx.NOW + 1, idreg=IDREG, free=(), adds=b"")
            self.assertEqual(again.published()[0], before[0])  # the signed position is untouched
            rows = again._db.execute("SELECT epoch, seq_from, count(*) FROM batches GROUP BY epoch, seq_from").fetchall()
            self.assertEqual([row[2] for row in rows], [1, 1])
            with self.assertRaises(sqlite3.IntegrityError):  # another header at a taken position
                again._db.execute("INSERT INTO batches(epoch, seq_from, seq_to, digest, header, state_digest, tokens)"
                                  " VALUES(?,?,?,?,?,?,?)", (fx.EPOCH, 0, 1, b"d" * 64, b"h", b"s" * 64, b""))
            with self.assertRaises(sqlite3.DatabaseError):  # a second signature on a sealed row
                again._db.execute("UPDATE batches SET signature=? WHERE seq_from=0", (b"x",))
            again.close()

    def _two_batches(self, tmp: str, custody) -> tuple[Path, bytes]:
        """Seal two batches, closing between them; return the mark path and the store as it was after the first."""
        p = self._open(tmp, custody)
        p.commit(fx.PROGRAM, fx.batch_leaves(0, 2), state_digest=fx.STATE, created_at=fx.NOW, idreg=IDREG, free=(), adds=b"")
        p.close()
        saved = (Path(tmp) / "shard.sqlite3").read_bytes()
        p = self._open(tmp, custody)
        p.commit(fx.PROGRAM, fx.batch_leaves(0, 2, 2), state_digest=fx.STATE, created_at=fx.NOW + 1, idreg=IDREG, free=(), adds=b"")
        p.close()
        return Path(tmp) / "shard.mark", saved

    def _restore(self, tmp: str, saved: bytes) -> None:
        for suffix in ("-wal", "-shm"):
            (Path(tmp) / f"shard.sqlite3{suffix}").unlink(missing_ok=True)
        (Path(tmp) / "shard.sqlite3").write_bytes(saved)

    def test_rewound_store_is_refused(self) -> None:
        with self.scratch() as tmp:
            custody = fx.custody(tmp)
            self._restore(tmp, self._two_batches(tmp, custody)[1])
            with self.assertRaisesRegex(producer.GateProducerError, "store_rewound"):
                self._open(tmp, custody)

    def test_a_zero_filled_mark_tail_does_not_hide_a_restored_older_store(self) -> None:
        with self.scratch() as tmp:
            custody = fx.custody(tmp)
            mark, saved = self._two_batches(tmp, custody)
            marked = mark.read_bytes()
            for zeros in (80, 112):  # power loss can leave the file longer with its new bytes zero
                self._restore(tmp, saved)
                mark.write_bytes(marked + bytes(zeros))
                with self.assertRaisesRegex(producer.GateProducerError, "store_rewound"):
                    self._open(tmp, custody)

    def test_after_a_torn_last_mark_record_the_store_must_be_strictly_ahead_of_the_one_before(self) -> None:
        with self.scratch() as tmp:
            custody = fx.custody(tmp)
            mark, saved = self._two_batches(tmp, custody)  # the store as it was after the first batch
            whole = mark.read_bytes()
            torns = (whole[:-50], whole[:-40] + bytes(40))  # cut short; its second page never written
            for torn in torns:
                mark.write_bytes(torn)
                self._open(tmp, custody).close()  # ahead of the record before: the torn bytes go, batch 2 is marked again
                self.assertEqual(mark.read_bytes(), whole)
            for torn in torns:
                mark.write_bytes(torn)
                self._restore(tmp, saved)  # restored to exactly the record before the damaged one
                with self.assertRaisesRegex(producer.GateProducerError, "store_rewound"):
                    self._open(tmp, custody)
                self.assertEqual(mark.read_bytes(), torn)  # refused, not re-marked
            damaged = bytearray(whole)
            damaged[-1] ^= 1
            damaged[-_RECORD - 1] ^= 1  # the last two records both bad
            mark.write_bytes(damaged)
            with self.assertRaisesRegex(producer.GateProducerError, "mark_corrupt"):
                self._open(tmp, custody)

    def test_a_new_store_whose_only_mark_record_is_torn_opens_and_repairs(self) -> None:
        with self.scratch() as tmp:
            custody = fx.custody(tmp)
            self._open(tmp, custody).close()
            mark = Path(tmp) / "shard.mark"
            whole = mark.read_bytes()
            mark.write_bytes(whole[:50])
            self._open(tmp, custody).close()
            self.assertEqual(mark.read_bytes(), whole)

    def test_the_first_one_leaf_batch_of_epoch_zero_seals_and_reopens(self) -> None:
        """Position zero's key is (0, 0); the batch's key is (epoch, seq_to + 1), so (0, 0) + 1 still rises."""
        with self.scratch() as tmp:
            custody = fx.custody(tmp, "e0")
            p = self._open(tmp, custody, epoch=0)
            p.commit(fx.PROGRAM, fx.batch_leaves(0, 1), state_digest=fx.STATE, created_at=fx.NOW, idreg=IDREG, free=(), adds=b"")
            p.close()
            self.assertEqual(len(self._open(tmp, custody, epoch=0).published()), 1)

    def test_mark_file_and_database_errors_are_typed(self) -> None:
        with self.scratch() as tmp:
            custody = fx.custody(tmp)
            with self.assertRaisesRegex(producer.GateProducerError, "store_unavailable"):
                self._open(tmp, custody, mark="missing/shard.mark")  # the mark's directory is gone
            p = self._open(tmp, custody)
            p._db.close()
            with self.assertRaisesRegex(producer.GateProducerError, "store_unavailable"):
                p.commit(fx.PROGRAM, fx.batch_leaves(0, 1), state_digest=fx.STATE, created_at=fx.NOW, idreg=IDREG, free=(), adds=b"")

    def test_a_new_store_marks_position_zero_and_a_crash_before_the_first_mark_is_caught_up(self) -> None:
        with self.scratch() as tmp:
            custody = fx.custody(tmp)
            p = self._open(tmp, custody)
            mark = Path(tmp) / "shard.mark"
            self.assertEqual(len(mark.read_bytes()), _RECORD)  # position zero, before any seal
            p.commit(fx.PROGRAM, fx.batch_leaves(0, 1), state_digest=fx.STATE, created_at=fx.NOW, idreg=IDREG, free=(), adds=b"")
            p.close()
            whole = mark.read_bytes()
            self.assertEqual(len(whole), 2 * _RECORD)
            mark.write_bytes(whole[:_RECORD])  # the crash between the first seal and its mark
            self._open(tmp, custody).close()
            self.assertEqual(mark.read_bytes(), whole)

    def test_a_store_with_sealed_batches_and_no_mark_is_refused(self) -> None:
        with self.scratch() as tmp:
            custody = fx.custody(tmp)
            mark = self._two_batches(tmp, custody)[0]
            moved = mark.read_bytes()
            for left in (None, b""):  # the mark moved away, or emptied
                mark.unlink(missing_ok=True)
                if left is not None:
                    mark.write_bytes(left)
                with self.assertRaisesRegex(producer.GateProducerError, "store_rewound"):
                    self._open(tmp, custody)
            mark.write_bytes(moved)
            self._open(tmp, custody).close()

    def test_epoch_change_restarts_seq_and_links_by_event_head(self) -> None:
        with self.scratch() as tmp:
            custody = fx.custody(tmp)
            p = self._open(tmp, custody)
            first = p.commit(fx.PROGRAM, fx.batch_leaves(0, 2), state_digest=fx.STATE, created_at=fx.NOW, idreg=IDREG, free=(), adds=b"")[0]
            p.close()
            p = self._open(tmp, fx.custody(tmp, "e8"), epoch=fx.EPOCH + 1)  # the producer sets epoch and seq
            nxt = p.commit(fx.PROGRAM, fx.batch_leaves(0, 2, 2), state_digest=fx.STATE, created_at=fx.NOW + 1, idreg=IDREG, free=(), adds=b"")[0]
            self.assertEqual((nxt.epoch, nxt.seq_from, nxt.prev_checkpoint_digest, nxt.event_head),
                             (fx.EPOCH + 1, 0, gate.ZERO_DIGEST, gate.checkpoint_digest(first)))

    def test_epoch_regress_is_refused(self) -> None:
        with self.scratch() as tmp:
            custody = fx.custody(tmp)
            p = self._open(tmp, custody)
            p.commit(fx.PROGRAM, fx.batch_leaves(0, 1), state_digest=fx.STATE, created_at=fx.NOW, idreg=IDREG, free=(), adds=b"")
            p.close()
            with self.assertRaisesRegex(producer.GateProducerError, "epoch"):
                self._open(tmp, fx.custody(tmp, "e6"), epoch=fx.EPOCH - 1)


    def test_v2_carries_registry_head_and_the_frees(self) -> None:
        with self.scratch() as tmp:
            reg = self.track(idreg.IdRegistry(Path(tmp) / "ids.sqlite3", boot=idreg.boot(Path(tmp) / "ids.sqlite3", {})))
            _, n, head = reg.reserve(0, [1, 2], sealed=None)
            p = self._open(tmp, fx.custody(tmp))
            self.assertIsNone(p.sealed_frees())
            cb, signed, _ = p.commit(fx.PROGRAM, fx.batch_leaves(0, 2), state_digest=fx.STATE, created_at=fx.NOW,
                                     idreg=(n, head), free=[2], adds=b"")
            header = signed[:-4629]
            self.assertTrue(header.startswith(gate.CHECKPOINT_V2))
            self.assertEqual(header[-64:], head)
            self.assertNotEqual(head, gate.ZERO_DIGEST)
            self.assertEqual(p.sealed_frees(), (n, [2]))
            p.close()  # the store is EXCLUSIVE while a shard runs: ``newest`` is for boot, before any shard starts
            self.assertEqual(producer.newest(Path(tmp) / "shard.sqlite3"), (n, head))
            self.assertEqual(cb.evidence_root, gate.ZERO_DIGEST)

    def test_pre_decide_store_refused(self) -> None:
        with self.scratch() as tmp:
            with sqlite3.connect(Path(tmp) / "shard.sqlite3") as db:
                db.execute("CREATE TABLE batches(id INTEGER PRIMARY KEY, epoch INTEGER, signature BLOB, idreg_n INTEGER)")
            db.close()
            with self.assertRaisesRegex(producer.GateProducerError, "store_version"):
                self._open(tmp, fx.custody(tmp))


if __name__ == "__main__":
    unittest.main()
