"""The gate checkpoint producer (``app/right_rail_gate_producer.py``): chain, crash, rewind and epoch behaviour.
Synthetic, non-PHI."""

from __future__ import annotations

import contextlib
from dataclasses import replace
import hashlib
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import unittest
from unittest import mock

from tests._test_only_counter import TestOnlyCounter
from app import right_rail_gate_chain as chain
from app import right_rail_gate_codec as gate
from app import right_rail_gate_decide as decide
from app import right_rail_gate_mark as marks
from app import right_rail_gate_producer as producer
from app import right_rail_gate_signer as signer
from tests import _gate_shards as g
from tests import test_right_rail_gate_formats as fx

_RECORD = 80 + marks.CHECK  # one producer mark record


def sealed(p, pays, *, state_digest, created_at, adds, cut=None):
    """Prepare the answer a decide would (the shard's Lean payment answers) and seal it through the producer's one path."""
    ans = decide.Answer((), state_digest, adds or bytes(chain.AUTH), None, None, fx.D[1], 0, 1, tuple(pays), fx.D[6])  # every batch carries its authority record
    p.prepared = ans
    return p.commit(fx.PROGRAM, ans, created_at, cut)


class _Flaky(TestOnlyCounter):
    """The test counter, whose increment can be made to raise or to report a value another writer took."""
    mode = None

    def increment(self) -> int:
        if self.mode == "raises":
            raise OSError("tpm_gone")
        value = super().increment()
        return value + 1 if self.mode == "raced" else value


class ProducerTests(fx.Scratch):
    """One serial producer per (tenant, shard): reserve, sign, Lean publish check, seal, mark, publish."""

    def _open(self, tmp: str, custody, epoch: int = fx.EPOCH, mark: str = "shard.mark"):
        handle, held, cert = custody
        return self.track(producer.ShardProducer(Path(tmp) / "shard.sqlite3", mark_path=Path(tmp) / mark,
                                      tenant_id=fx.TENANT, shard_id=fx.SHARD, epoch=epoch, handle=handle,
                                      link=held, cosign=fx.cosigner(),  key_cert=cert, payer_newest=gate.ZERO_DIGEST,
                                      counter=TestOnlyCounter(Path(tmp) / "shard.counter"), floors=lambda: (0, 0, 0, bytes(64))))

    def test_chain_links_and_publishes_in_seq_order(self) -> None:
        with self.scratch() as tmp:
            p = self._open(tmp, fx.custody(tmp))
            ca, sa, _ = sealed(p, fx.batch_pays(3), state_digest=fx.STATE, created_at=fx.NOW, adds=b"")
            cb, sb, tb = sealed(p, fx.batch_pays(2, 3), state_digest=fx.STATE, created_at=fx.NOW + 1, adds=b"")
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
                sealed(p, [], state_digest=fx.STATE, created_at=fx.NOW, adds=b"")
            self.assertEqual(p.published(), [])

    def test_only_the_answer_a_decide_prepared_is_sealed(self) -> None:
        """No caller supplies a leaf: an answer that is not the prepared one (never prepared, or any field edited) is refused,
        and nothing is sealed."""
        with self.scratch() as tmp:
            p = self._open(tmp, fx.custody(tmp))
            ans = decide.Answer((), fx.STATE, b"", None, None, fx.D[1], 0, 1, tuple(fx.batch_pays(2)), fx.D[6])
            with self.assertRaisesRegex(producer.GateProducerError, "stale_answer"):
                p.commit(fx.PROGRAM, ans, fx.NOW)  # nothing was prepared
            p.prepared = ans
            for edit in ({"adds": b"x"}, {"pre": fx.D[2]}, {"digest": fx.D[5]},
                         {"pays": tuple(fx.batch_pays(2))[:1]}, {"pays": (ans.pays[0]._replace(cents=1),)}):
                with self.assertRaisesRegex(producer.GateProducerError, "stale_answer"):
                    p.commit(fx.PROGRAM, ans._replace(**edit), fx.NOW)
            self.assertEqual((p.published(), p.prepared), ([], ans))  # the refusals spent nothing
            p.commit(fx.PROGRAM, ans, fx.NOW)
            self.assertIsNone(p.prepared)
            with self.assertRaisesRegex(producer.GateProducerError, "stale_answer"):
                p.commit(fx.PROGRAM, ans, fx.NOW)  # sealed once only
            self.assertEqual(len(p.published()), 1)

    def test_a_refused_batch_is_voided_and_the_next_one_takes_its_seq(self) -> None:
        with self.scratch() as tmp:
            p = self._open(tmp, fx.custody(tmp))
            key = fx.member(0, shard=5)  # a member key that routes to another shard
            r = fx._request("FFS_CLAIM", 0, fx._lines(0, "FFS_CLAIM", key), member_key=key)
            stray = decide.Pay("ALLOW", ("ELIGIBLE", "RATE_OK"), r.tenant_id, r.program_id, r.flow, r.payment_id, r.member_key, r.payee_ref,
                               r.amount_cents, r.period, gate.lines_root(r.lines), fx.synthetic_input(r, fx.D[1]), "TRANSFER", fx.D[3], bytes(64))
            with self.assertRaisesRegex(producer.GateProducerError, "publish_refused"):
                sealed(p, [stray], state_digest=fx.STATE, created_at=fx.NOW, adds=b"")
            self.assertEqual((p.published(), p.anchor()), ([], None))
            self.assertEqual(sealed(p, fx.batch_pays(1), state_digest=fx.STATE, created_at=fx.NOW, adds=b"")[0].seq_from, 0)
            foreign = fx.batch_pays(1, 1)[0]._replace(tenant="other-tenant")  # another tenant's payment
            with self.assertRaisesRegex(producer.GateProducerError, "foreign_leaf"):
                sealed(p, [foreign], state_digest=fx.STATE, created_at=fx.NOW, adds=b"")

    def _dying(self, p, sql: str):
        """Make ``p``'s database raise a sqlite error on a statement starting with ``sql`` (a crash there); the real connection."""
        real = p._db

        class Dying:
            def __getattr__(self, name):
                return getattr(real, name)

            def execute(self, text, *args):
                if text.startswith(sql):
                    raise sqlite3.OperationalError("crash")
                return real.execute(text, *args)
        p._db = Dying()
        return real

    def test_voiding_a_reservation_is_one_transaction(self) -> None:
        """A crash between the two deletes leaves both rows (else an unsigned batch with no frame stays and cannot be sealed)."""
        with self.scratch() as tmp:
            p = self._open(tmp, fx.custody(tmp))
            real = self._dying(p, "DELETE FROM batches")
            with mock.patch.object(signer, "seal", side_effect=signer.GateSignerError("gate_verify_refused")),                     self.assertRaisesRegex(producer.GateProducerError, "reservation_not_voided"):  # Round 4 M1: a void that fails closes the producer
                sealed(p, fx.batch_pays(1), state_digest=fx.STATE, created_at=fx.NOW, adds=b"")
            self.assertTrue(p._closed)
            with contextlib.closing(sqlite3.connect(Path(tmp) / "shard.sqlite3")) as db:  # the producer closed its own connection
                self.assertEqual(tuple(db.execute(f"SELECT count(*) FROM {t}").fetchone()[0] for t in ("batches", "records")), (1, 1))

    def test_a_database_error_writing_the_reservation_is_tried_again(self) -> None:
        """Final review M2: the reservation's transaction rolls back whole on a database error and is written again; the
        seal then signs it once."""
        with self.scratch() as tmp:
            p, real, calls = self._open(tmp, fx.custody(tmp)), signer.sign, []

            def flaky(*args):
                calls.append(1)
                if len(calls) == 1:
                    raise sqlite3.OperationalError("disk I/O error")
                return real(*args)
            with mock.patch.object(signer, "sign", flaky), mock.patch.object(producer.time, "sleep"):
                sealed(p, fx.batch_pays(1), state_digest=fx.STATE, created_at=fx.NOW, adds=b"")
            self.assertEqual((len(calls), len(p.published())), (3, 1))  # the failed pledge, the pledge, the header after the seal

    def test_an_error_storing_the_signature_closes_the_producer(self) -> None:
        with self.scratch() as tmp:
            p = self._open(tmp, fx.custody(tmp))
            self._dying(p, "UPDATE batches SET signature")
            with self.assertRaisesRegex(producer.GateProducerError, "signature_not_stored"):  # final review F1: a reopen, not a retry
                sealed(p, fx.batch_pays(1), state_digest=fx.STATE, created_at=fx.NOW, adds=b"")
            with self.assertRaisesRegex(producer.GateProducerError, "producer_closed"):
                p.published()

    def test_a_counter_failure_closes_the_producer_until_a_reopen(self) -> None:
        """Review M: the counter raced, or its increment raised, after the signature was stored: the batch is unreleased, so
        every call refuses (``tip`` and ``anchor`` do not serve the stored row, ``commit`` signs nothing on it) until a reopen."""
        for mode, error in (("raced", "counter_raced"), ("raises", "signature_not_stored")):
            with self.subTest(mode), self.scratch() as tmp:
                custody = fx.custody(tmp)
                counter = _Flaky(Path(tmp) / "shard.counter")
                handle, held, cert = custody
                p = self.track(producer.ShardProducer(Path(tmp) / "shard.sqlite3", mark_path=Path(tmp) / "shard.mark", tenant_id=fx.TENANT,
                                                      shard_id=fx.SHARD, epoch=fx.EPOCH, handle=handle, link=held, cosign=fx.cosigner(),  key_cert=cert,
                                                      payer_newest=gate.ZERO_DIGEST, counter=counter, floors=lambda: (0, 0, 0, bytes(64))))
                sealed(p, fx.batch_pays(1, 7), state_digest=fx.STATE, created_at=fx.NOW - 1, adds=b"")  # the first seal arms the counter
                counter.mode = mode
                with self.assertRaisesRegex(Exception, error):
                    sealed(p, fx.batch_pays(2), state_digest=fx.STATE, created_at=fx.NOW, adds=b"")
                with contextlib.closing(sqlite3.connect(Path(tmp) / "shard.sqlite3")) as db:
                    self.assertEqual(db.execute("SELECT count(*) FROM batches WHERE signature IS NOT NULL").fetchone(), (2,))
                with mock.patch.object(signer, "seal") as seal:
                    for call in (p.tip, p.anchor, p.published, p.flat_head, lambda: p.record(1),
                                 lambda: sealed(p, fx.batch_pays(2, 2), state_digest=fx.STATE, created_at=fx.NOW + 1, adds=b"")):
                        with self.assertRaisesRegex(producer.GateProducerError, "producer_closed"):
                            call()
                seal.assert_not_called()
                counter.mode = None
                reopened = self._open(tmp, custody)  # a reopen is the only way back; when the increment was lost it takes it (Custody.lean seal_crash_resumes)
                self.assertEqual((len(reopened.published()), counter.read()), (2, 2))
                self.assertEqual(sealed(reopened, fx.batch_pays(1, 5), state_digest=fx.STATE, created_at=fx.NOW + 2, adds=b"")[0].counter, 3)

    def test_a_crash_between_the_first_seal_and_the_first_increment_heals_on_reopen(self) -> None:
        """Final review U5: the shard's first signature is stored, then the counter's first increment is lost, so the counter
        is still unwritten under the signed counter-1 checkpoint.  The reopen catches up (Lean ``first_seal_crash_heals``)
        instead of refusing ``counter_reset`` for ever, every reopen after it serves, and the next seal takes counter 2
        (``counter_one_once``)."""
        with self.scratch() as tmp:
            custody = fx.custody(tmp)
            counter = _Flaky(Path(tmp) / "shard.counter")
            counter.mode = "raises"
            handle, held, cert = custody
            p = self.track(producer.ShardProducer(Path(tmp) / "shard.sqlite3", mark_path=Path(tmp) / "shard.mark", tenant_id=fx.TENANT,
                                                  shard_id=fx.SHARD, epoch=fx.EPOCH, handle=handle, link=held, cosign=fx.cosigner(),  key_cert=cert,
                                                  payer_newest=gate.ZERO_DIGEST, counter=counter, floors=lambda: (0, 0, 0, bytes(64))))
            with self.assertRaisesRegex(producer.GateProducerError, "signature_not_stored"):  # Round 3: the counter's OSError needs a reopen
                sealed(p, fx.batch_pays(1), state_digest=fx.STATE, created_at=fx.NOW, adds=b"")
            p.close()
            with contextlib.closing(sqlite3.connect(Path(tmp) / "shard.sqlite3")) as db:
                self.assertEqual(db.execute("SELECT count(*) FROM batches WHERE signature IS NOT NULL").fetchone(), (1,))
            self.assertIsNone(counter.read())
            counter.mode = None
            reopened = self._open(tmp, custody)
            self.assertEqual((len(reopened.published()), counter.read()), (1, 1))
            self.assertEqual(sealed(reopened, fx.batch_pays(1, 1), state_digest=fx.STATE, created_at=fx.NOW + 1, adds=b"")[0].counter, 2)
            reopened.close()
            self.assertEqual((len(self._open(tmp, custody).published()), counter.read()), (2, 2))

    def test_a_reopen_refuses_a_counter_that_is_not_the_newest_header_s(self) -> None:
        """Review M: a counter two or more behind the stored header is Lean's ``store_ahead``; another writer's
        increment leaves the store behind it (``store_rewound``).  Both are sticky and delete no row, reservation or mark
        record; a normal reopen passes."""
        for behind in (True, False):
            with self.subTest(behind=behind), self.scratch() as tmp:
                custody = fx.custody(tmp)
                counter = _Flaky(Path(tmp) / "shard.counter")
                handle, held, cert = custody
                p = self.track(producer.ShardProducer(Path(tmp) / "shard.sqlite3", mark_path=Path(tmp) / "shard.mark", tenant_id=fx.TENANT,
                                                      shard_id=fx.SHARD, epoch=fx.EPOCH, handle=handle, link=held, cosign=fx.cosigner(),  key_cert=cert,
                                                      payer_newest=gate.ZERO_DIGEST, counter=counter, floors=lambda: (0, 0, 0, bytes(64))))
                sealed(p, fx.batch_pays(1), state_digest=fx.STATE, created_at=fx.NOW, adds=b"")
                p.close()
                self._open(tmp, custody).close()  # the normal reopen passes
                p = self.track(producer.ShardProducer(Path(tmp) / "shard.sqlite3", mark_path=Path(tmp) / "shard.mark", tenant_id=fx.TENANT,
                                                      shard_id=fx.SHARD, epoch=fx.EPOCH, handle=handle, link=held, cosign=fx.cosigner(),  key_cert=cert,
                                                      payer_newest=gate.ZERO_DIGEST, counter=counter, floors=lambda: (0, 0, 0, bytes(64))))
                sealed(p, fx.batch_pays(1, 1), state_digest=fx.STATE, created_at=fx.NOW + 1, adds=b"")
                if behind:  # two behind: one lost increment resumes (next test), two cannot come from the honest order
                    counter._write(bytes([1]) + (0).to_bytes(8, "big"))
                else:
                    TestOnlyCounter(Path(tmp) / "shard.counter").increment()  # a race: another writer took the next value
                p.close()
                counter.mode = None

                def rows():
                    with contextlib.closing(sqlite3.connect(Path(tmp) / "shard.sqlite3")) as db:
                        return db.execute("SELECT id, signature FROM batches ORDER BY id").fetchall(), db.execute("SELECT count(*) FROM records").fetchone()
                before, mark = rows(), (Path(tmp) / "shard.mark").read_bytes()
                for _ in range(2):  # sticky
                    with self.assertRaisesRegex(producer.GateProducerError, "store_ahead" if behind else "store_rewound"):
                        self._open(tmp, custody)
                self.assertEqual((rows(), (Path(tmp) / "shard.mark").read_bytes()), (before, mark))

    def test_a_start_takes_the_proved_custody_step(self) -> None:
        """Fault hunt item 2: a start asks Lean ``custodyStep`` (``signer.custody``) with the counter and the newest sealed
        checkpoint signed with its certificate (Lean reads the store's counter from it), and refuses under Lean's name whatever its answer,
        writing nothing."""
        with self.scratch() as tmp:
            custody = fx.custody(tmp)
            p = self._open(tmp, custody)
            _, signed, _ = sealed(p, fx.batch_pays(1), state_digest=fx.STATE, created_at=fx.NOW, adds=b"")
            p.close()
            real, asked = signer.custody, []
            with mock.patch.object(signer, "custody", lambda *args: asked.append(args) or real(*args)):
                self._open(tmp, custody).close()
            self.assertEqual(asked, [(1, custody[1], custody[2], signed)])
            mark = (Path(tmp) / "shard.mark").read_bytes()
            for answer in ("no_store", "counter_reset", "store_rewound", "store_ahead"):
                with self.subTest(answer), mock.patch.object(signer, "custody", return_value=answer):
                    with self.assertRaisesRegex(producer.GateProducerError, f"^{answer}$"):
                        self._open(tmp, custody)
            self.assertEqual((Path(tmp) / "shard.mark").read_bytes(), mark)

    def test_a_mark_failure_after_the_seal_closes_the_producer(self) -> None:
        """Review M: the signature is stored and the counter moved, then the mark write fails: nothing is served until a reopen."""
        with self.scratch() as tmp:
            custody = fx.custody(tmp)
            p = self._open(tmp, custody)
            sealed(p, fx.batch_pays(1), state_digest=fx.STATE, created_at=fx.NOW, adds=b"")
            with mock.patch.object(marks, "append", side_effect=OSError("disk")):
                with self.assertRaisesRegex(producer.GateProducerError, "mark_not_written"):  # final review F1: a reopen, not a retry
                    sealed(p, fx.batch_pays(1, 1), state_digest=fx.STATE, created_at=fx.NOW + 1, adds=b"")
            for call in (p.tip, p.anchor):
                with self.assertRaisesRegex(producer.GateProducerError, "producer_closed"):
                    call()
            self.assertEqual(len(self._open(tmp, custody).published()), 2)  # the reopen catches the mark up

    def test_crash_between_sign_and_persist_reseals_the_same_header(self) -> None:
        with self.scratch() as tmp:
            custody = fx.custody(tmp)
            p = self._open(tmp, custody)
            sealed(p, fx.batch_pays(2), state_digest=fx.STATE, created_at=fx.NOW, adds=b"")
            reserved: list[bytes] = []
            real = signer.seal

            def crash(*args):
                reserved.append(args[4])
                real(*args)  # signed and verified, then the process dies before the seal commits
                raise KeyboardInterrupt

            with mock.patch.object(signer, "seal", crash), self.assertRaises(KeyboardInterrupt):
                sealed(p, fx.batch_pays(2, 2), state_digest=fx.STATE, created_at=fx.NOW + 1, adds=b"")
            with self.assertRaisesRegex(producer.GateProducerError, "producer_closed"):  # the failed seal left a reservation: serve nothing
                p.published()
            with contextlib.closing(sqlite3.connect(Path(tmp) / "shard.sqlite3")) as db:
                self.assertEqual(db.execute("SELECT count(*) FROM batches WHERE signature IS NOT NULL").fetchone()[0], 1)  # nothing unsealed was published
            again = self._open(tmp, custody)  # opening re-seals the reserved batch before any new one
            published = again.published()
            self.assertEqual(len(published), 2)
            self.assertTrue(published[1].startswith(reserved[0]))  # same header bytes at the same seq
            self.assertEqual(len(published[1]), len(reserved[0]) + 2 + gate.ML_DSA_87_SIGNATURE + gate.COSIGN_RECORD)

    def _seal_with_second_check(self, tmp: str, custody, second):
        """Open a producer, make the seal's second floor check (under the lock) run ``second``, and seal one batch."""
        p = self._open(tmp, custody)
        real, calls = p._check_floors, []

        def check(row, last):
            calls.append(row[0])
            if len(calls) == 2:
                second(p, real, row, last)
            else:
                real(row, last)

        p._check_floors = check
        return p, calls

    def test_an_interrupt_after_the_floor_check_closes_the_producer(self) -> None:
        """An interrupt inside the lock after the first check leaves an unsigned, unvoided reservation: the producer closes,
        nothing signed is stored, and a reopen checks the reservation against the floors and then serves."""
        with self.scratch() as tmp:
            custody = fx.custody(tmp)

            def interrupt(p, real, row, last):
                raise KeyboardInterrupt

            p, _ = self._seal_with_second_check(tmp, custody, interrupt)
            with self.assertRaises(KeyboardInterrupt):
                sealed(p, fx.batch_pays(2), state_digest=fx.STATE, created_at=fx.NOW, adds=b"")
            with self.assertRaisesRegex(producer.GateProducerError, "producer_closed"):
                p.published()
            with contextlib.closing(sqlite3.connect(Path(tmp) / "shard.sqlite3")) as db:
                self.assertEqual(db.execute("SELECT count(*) FROM batches WHERE signature IS NOT NULL").fetchone()[0], 0)
                self.assertEqual(db.execute("SELECT count(*) FROM batches WHERE signature IS NULL").fetchone()[0], 1)
            checked = []
            real = producer.ShardProducer._check_floors
            with mock.patch.object(producer.ShardProducer, "_check_floors", lambda self, row, last: checked.append(row[0]) or real(self, row, last)):
                again = self._open(tmp, custody)
            self.assertEqual(len(checked), 2)  # the reopen checked the reservation before it sealed it
            self.assertEqual(len(again.published()), 1)
            sealed(again, fx.batch_pays(2, 2), state_digest=fx.STATE, created_at=fx.NOW + 1, adds=b"")
            self.assertEqual(len(again.published()), 2)

    def test_a_floor_refusal_under_the_lock_voids_and_leaves_the_producer_open(self) -> None:
        """The refusal path stays as it was: _check_floors voids the reservation itself and the producer serves on."""
        with self.scratch() as tmp:
            custody = fx.custody(tmp)

            def raised(p, real, row, last):
                p._floors = lambda: (10**9, 10**9)
                real(row, last)

            p, _ = self._seal_with_second_check(tmp, custody, raised)
            with self.assertRaisesRegex(producer.GateProducerError, "reservation_below_floor"):
                sealed(p, fx.batch_pays(2), state_digest=fx.STATE, created_at=fx.NOW, adds=b"")
            self.assertEqual(p.published(), [])  # still open
            self.assertEqual(p._db.execute("SELECT count(*) FROM batches").fetchone()[0], 0)  # voided

    def test_restart_never_gives_a_position_a_second_batch(self) -> None:
        """After any restart a position holds one header and one signature; a later batch takes the next seq."""
        with self.scratch() as tmp:
            custody = fx.custody(tmp)
            first = self._open(tmp, custody)
            sealed(first, fx.batch_pays(2), state_digest=fx.STATE, created_at=fx.NOW, adds=b"")
            before = first.published()
            first.close()
            again = self._open(tmp, custody)
            sealed(again, fx.batch_pays(2, 2), state_digest=fx.STATE, created_at=fx.NOW + 1, adds=b"")
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
        sealed(p, fx.batch_pays(2), state_digest=fx.STATE, created_at=fx.NOW, adds=b"")
        p.close()
        saved = (Path(tmp) / "shard.sqlite3").read_bytes()
        p = self._open(tmp, custody)
        sealed(p, fx.batch_pays(2, 2), state_digest=fx.STATE, created_at=fx.NOW + 1, adds=b"")
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
            sealed(p, fx.batch_pays(1), state_digest=fx.STATE, created_at=fx.NOW, adds=b"")
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
                sealed(p, fx.batch_pays(1), state_digest=fx.STATE, created_at=fx.NOW, adds=b"")

    def test_a_new_store_marks_position_zero_and_a_crash_before_the_first_mark_is_caught_up(self) -> None:
        with self.scratch() as tmp:
            custody = fx.custody(tmp)
            p = self._open(tmp, custody)
            mark = Path(tmp) / "shard.mark"
            self.assertEqual(len(mark.read_bytes()), _RECORD)  # position zero, before any seal
            sealed(p, fx.batch_pays(1), state_digest=fx.STATE, created_at=fx.NOW, adds=b"")
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
            first = sealed(p, fx.batch_pays(2), state_digest=fx.STATE, created_at=fx.NOW, adds=b"")[0]
            p.close()
            p = self._open(tmp, fx.custody(tmp, "e8"), epoch=fx.EPOCH + 1)  # the producer sets epoch and seq
            nxt = sealed(p, fx.batch_pays(2, 2), state_digest=fx.STATE, created_at=fx.NOW + 1, adds=b"")[0]
            self.assertEqual((nxt.epoch, nxt.seq_from, nxt.prev_checkpoint_digest, nxt.event_head),
                             (fx.EPOCH + 1, 0, gate.ZERO_DIGEST, gate.checkpoint_digest(first)))

    def test_epoch_regress_is_refused(self) -> None:
        with self.scratch() as tmp:
            custody = fx.custody(tmp)
            p = self._open(tmp, custody)
            sealed(p, fx.batch_pays(1), state_digest=fx.STATE, created_at=fx.NOW, adds=b"")
            p.close()
            with self.assertRaisesRegex(producer.GateProducerError, "epoch"):
                self._open(tmp, fx.custody(tmp, "e6"), epoch=fx.EPOCH - 1)


    def test_the_header_is_checkpoint_v1_with_no_registry_head(self) -> None:
        with self.scratch() as tmp:
            p = self._open(tmp, fx.custody(tmp))
            cb, signed, _ = sealed(p, fx.batch_pays(2), state_digest=fx.STATE, created_at=fx.NOW, adds=b"")
            header = signed[: -4629 - gate.COSIGN_RECORD]
            self.assertEqual(header, gate.encode_checkpoint_header(cb))
            self.assertTrue(header.startswith(gate.CHECKPOINT))
            self.assertEqual(cb.evidence_root, gate.ZERO_DIGEST)

    def test_startup_refuses_a_store_without_the_payers_newest_checkpoint(self) -> None:
        """The payer's newest stored checkpoint for the shard must be a sealed batch of the store, else ``store_rewound``;
        the genesis digest asks nothing, and ``None`` (the payer could not be read) is ``payer_unavailable``."""
        with self.scratch() as tmp:
            custody = fx.custody(tmp)
            p = self._open(tmp, custody)
            cb, _, _ = sealed(p, fx.batch_pays(1), state_digest=fx.STATE, created_at=fx.NOW, adds=b"")
            p.close()
            handle, held, cert = custody

            def reopen(newest):
                return producer.ShardProducer(Path(tmp) / "shard.sqlite3", mark_path=Path(tmp) / "shard.mark", tenant_id=fx.TENANT,
                                              shard_id=fx.SHARD, epoch=fx.EPOCH, handle=handle, link=held, cosign=fx.cosigner(),  key_cert=cert,
                                              payer_newest=newest, counter=TestOnlyCounter(Path(tmp) / "shard.counter"), floors=lambda: (0, 0, 0, bytes(64)))
            reopen(gate.checkpoint_digest(cb)).close()
            reopen(gate.ZERO_DIGEST).close()
            with self.assertRaisesRegex(producer.GateProducerError, "payer_unavailable"):
                reopen(None)
            with self.assertRaisesRegex(producer.GateProducerError, "store_rewound"):
                reopen(fx.D[5])

    def test_a_restored_store_with_an_open_row_is_refused_without_resealing(self) -> None:
        """The payer holds a checkpoint the restored store has only as an open row: ``store_rewound`` before anything is signed,
        so the store, the mark and the key are as they were."""
        with self.scratch() as tmp:
            custody = fx.custody(tmp)
            p = self._open(tmp, custody)
            cb, _, _ = sealed(p, fx.batch_pays(1), state_digest=fx.STATE, created_at=fx.NOW, adds=b"")
            p.close()
            with contextlib.closing(sqlite3.connect(Path(tmp) / "shard.sqlite3")) as db:
                db.executescript("DROP TRIGGER batches_seal; UPDATE batches SET signature = NULL;")
            files = {f.name: f.read_bytes() for f in Path(tmp).iterdir()}
            handle, held, cert = custody
            with mock.patch.object(signer, "seal") as seal:
                for _ in range(2):
                    with self.assertRaisesRegex(producer.GateProducerError, "store_rewound"):
                        producer.ShardProducer(Path(tmp) / "shard.sqlite3", mark_path=Path(tmp) / "shard.mark", tenant_id=fx.TENANT,
                                               shard_id=fx.SHARD, epoch=fx.EPOCH, handle=handle, link=held, cosign=fx.cosigner(),  key_cert=cert,
                                               payer_newest=gate.checkpoint_digest(cb), counter=TestOnlyCounter(Path(tmp) / "shard.counter"), floors=lambda: (0, 0, 0, bytes(64)))
            seal.assert_not_called()
            self.assertEqual({f.name: f.read_bytes() for f in Path(tmp).iterdir()}, files)

    def test_a_row_inserted_into_a_closed_store_is_refused_never_signed(self) -> None:
        """TAMPER-INS: a valid successor row added by raw SQL (no pledge, a pledge over other bytes, or a second open
        row) is ``store_tampered`` at open, before any signing, and stays as evidence; the owner's own row reseals."""
        with self.scratch() as tmp:
            custody = fx.custody(tmp)
            p = self._open(tmp, custody)
            sealed(p, fx.batch_pays(2), state_digest=fx.STATE, created_at=fx.NOW, adds=b"")
            with mock.patch.object(signer, "seal", side_effect=signer.GateSignerError("gate_verify_failed")), \
                    self.assertRaises(signer.GateSignerError):  # the owner's reservation of a genuine successor
                sealed(p, fx.batch_pays(2, 2), state_digest=fx.STATE, created_at=fx.NOW + 1, adds=b"")
            p.close()
            cols = producer._PLEDGED
            with sqlite3.connect(Path(tmp) / "shard.sqlite3") as db:
                *row, pledge = db.execute(f"SELECT {cols}, pledge FROM batches WHERE signature IS NULL").fetchone()
                db.execute("DELETE FROM batches WHERE signature IS NULL")  # the store is closed: one sealed row
            db.close()
            for name, values in (("unpledged", (*row, None)), ("other bytes", (*row[:8], "7", *row[9:], pledge)),
                                 ("second open row", None)):
                with self.subTest(name):
                    db = sqlite3.connect(Path(tmp) / "shard.sqlite3")
                    db.execute("DELETE FROM batches WHERE signature IS NULL")
                    if values is None:  # the owner's row plus one more, both open
                        db.execute(f"INSERT INTO batches({cols}, pledge) VALUES({'?,' * len(row)}?)", (*row, pledge))
                        values = (row[0], row[1] + 5, row[2] + 5, b"x" * 64, *row[4:], None)
                    db.execute(f"INSERT INTO batches({cols}, pledge) VALUES({'?,' * len(row)}?)", values)
                    db.commit()
                    db.close()
                    with mock.patch.object(signer, "seal") as seal, \
                            self.assertRaisesRegex(producer.GateProducerError, "store_tampered"):
                        self._open(tmp, custody)
                    seal.assert_not_called()
            with sqlite3.connect(Path(tmp) / "shard.sqlite3") as db:
                self.assertEqual(db.execute("SELECT count(*) FROM batches WHERE signature IS NULL").fetchone(), (2,))
                db.execute("DELETE FROM batches WHERE signature IS NULL")
                db.execute(f"INSERT INTO batches({cols}, pledge) VALUES({'?,' * len(row)}?)", (*row, pledge))
            db.close()
            self.assertEqual(len(self._open(tmp, custody).published()), 2)  # the owner's pledged row reseals

    def test_a_changed_sealed_row_is_refused_never_served(self) -> None:
        """Review M: the newest sealed row is trusted only under its own epoch's certificate (pledge and checkpoint
        signature): a forged signature or an UPDATEd ``adds`` (triggers dropped by raw SQL) is ``store_tampered`` at
        reopen, before the mark moves."""
        with self.scratch() as tmp:
            custody = fx.custody(tmp)
            p = self._open(tmp, custody)
            sealed(p, fx.batch_pays(2), state_digest=fx.STATE, created_at=fx.NOW, adds=b"")
            p.close()
            store = Path(tmp) / "shard.sqlite3"
            saved = store.read_bytes()
            for name, sql in (("forged signature", "UPDATE batches SET signature = randomblob(length(signature))"),
                              ("updated adds", "UPDATE batches SET adds = X'00'")):
                with self.subTest(name):
                    store.write_bytes(saved)
                    with contextlib.closing(sqlite3.connect(store)) as db:
                        db.executescript(f"DROP TRIGGER batches_fixed; DROP TRIGGER batches_seal; {sql};")
                    with self.assertRaisesRegex(producer.GateProducerError, "store_tampered"):
                        self._open(tmp, custody)
            store.write_bytes(saved)
            self.assertEqual(len(self._open(tmp, custody).published()), 1)

    def test_another_shards_reservation_is_refused_never_signed(self) -> None:
        """Review L1: shard A's first reservation (open, pledged) copied into shard B's new store under the same epoch
        key is ``store_tampered``: the pledge binds (tenant, shard) and the header must name this shard."""
        with self.scratch() as tmp:
            custody = fx.custody(tmp)
            p = self._open(tmp, custody)
            with mock.patch.object(signer, "seal", side_effect=signer.GateSignerError("gate_verify_failed")), \
                    self.assertRaises(signer.GateSignerError):
                sealed(p, fx.batch_pays(1), state_digest=fx.STATE, created_at=fx.NOW, adds=b"")
            p.close()
            other = Path(tmp) / "b"
            other.mkdir()
            shutil.copyfile(Path(tmp) / "shard.sqlite3", other / "shard.sqlite3")
            handle, held, cert = custody
            with mock.patch.object(signer, "seal") as seal, \
                    self.assertRaisesRegex(producer.GateProducerError, "store_tampered"):
                producer.ShardProducer(other / "shard.sqlite3", mark_path=other / "shard.mark", tenant_id=fx.TENANT,
                                       shard_id=fx.SHARD + 1, epoch=fx.EPOCH, handle=handle, link=held, cosign=fx.cosigner(),  key_cert=cert,
                                       payer_newest=gate.ZERO_DIGEST, counter=TestOnlyCounter(other / "shard.counter"), floors=lambda: (0, 0, 0, bytes(64)))
            seal.assert_not_called()

    def test_pre_decide_and_uncertified_stores_refused(self) -> None:
        for name, columns in (("pre-decide", ""), ("no cert", ", pledge BLOB"), ("per-registry identity", ", cert BLOB, idreg_n INTEGER")):
            with self.subTest(name), self.scratch() as tmp:
                with contextlib.closing(sqlite3.connect(Path(tmp) / "shard.sqlite3")) as db:
                    db.execute(f"CREATE TABLE batches(id INTEGER PRIMARY KEY, epoch INTEGER, signature BLOB{columns})")
                with self.assertRaisesRegex(producer.GateProducerError, "store_version"):
                    self._open(tmp, fx.custody(tmp))

    def test_a_store_sealed_under_an_older_header_version_is_store_version(self) -> None:
        """Review L: a v1 or v2 header on a sealed row is ``store_version``, found before the owner is read from it."""
        with self.scratch() as tmp:
            custody = fx.custody(tmp)
            p = self._open(tmp, custody)
            sealed(p, fx.batch_pays(1), state_digest=fx.STATE, created_at=fx.NOW, adds=b"")
            p.close()
            store = Path(tmp) / "shard.sqlite3"
            saved = store.read_bytes()
            for old in (b"v1", b"v2"):
                with self.subTest(old):
                    store.write_bytes(saved)
                    with contextlib.closing(sqlite3.connect(store)) as db:
                        db.executescript("DROP TRIGGER batches_fixed; DROP TRIGGER batches_seal;")
                        header = db.execute("SELECT header FROM batches").fetchone()[0]
                        db.execute("UPDATE batches SET header = ?", (gate.CHECKPOINT[:-3] + old + bytes(1) + header[len(gate.CHECKPOINT) :],))
                        db.commit()
                    with mock.patch.object(producer, "_owner") as owner, self.assertRaisesRegex(producer.GateProducerError, "store_version"):
                        self._open(tmp, custody)
                    owner.assert_not_called()

    def test_a_store_with_sealed_rows_and_no_counter_is_refused_not_armed(self) -> None:
        """Review L: only a store with no sealed row arms a fresh counter; sealed rows past the shard's first and no counter
        file is ``counter_reset`` and creates nothing (the first alone is a lost first increment, caught up: U5)."""
        with self.scratch() as tmp:
            custody = fx.custody(tmp)
            p = self._open(tmp, custody)
            sealed(p, fx.batch_pays(1), state_digest=fx.STATE, created_at=fx.NOW, adds=b"")
            sealed(p, fx.batch_pays(1, 1), state_digest=fx.STATE, created_at=fx.NOW + 1, adds=b"")
            p.close()
            counter = Path(tmp) / "shard.counter"
            counter.unlink()
            mark = (Path(tmp) / "shard.mark")
            mark.write_bytes(mark.read_bytes()[:_RECORD])  # behind the store: a catch-up record would be written if the mark ran first
            before = mark.read_bytes()
            with self.assertRaisesRegex(producer.GateProducerError, "counter_reset"):
                self._open(tmp, custody)
            self.assertFalse(counter.exists())
            self.assertEqual(mark.read_bytes(), before)  # Review L: no mark record for a reset store

    def test_a_store_that_appears_after_the_missing_store_check_is_still_checked(self) -> None:
        """Final review L1: the store was absent when the start looked, then a sealed one appeared before the connect: the
        start still asks Lean with its newest sealed header (here ``counter_reset``: two sealed, no counter), never serves it
        as created."""
        with self.scratch() as tmp:
            custody = fx.custody(tmp)
            p = self._open(tmp, custody)
            sealed(p, fx.batch_pays(1), state_digest=fx.STATE, created_at=fx.NOW, adds=b"")
            sealed(p, fx.batch_pays(1, 1), state_digest=fx.STATE, created_at=fx.NOW + 1, adds=b"")
            p.close()
            TestOnlyCounter(Path(tmp) / "shard.counter").clear()
            store, exists = Path(tmp) / "shard.sqlite3", Path.exists
            with mock.patch.object(Path, "exists", lambda self, *a, **kw: False if self == store else exists(self, *a, **kw)):
                with self.assertRaisesRegex(producer.GateProducerError, "^counter_reset$"):
                    self._open(tmp, custody)

    def test_a_counter_that_has_counted_under_a_store_with_nothing_sealed_is_no_store(self) -> None:
        """Review H: the store (and mark) deleted or restored to its creation while the counter is at t > 0 is refused, sticky,
        before any write, with or without an open reservation and under the same or a new epoch's certificate; an unset
        counter is armed by the first seal, which signs counter 1."""
        for epoch, name in ((fx.EPOCH, "e7"), (fx.EPOCH + 1, "e8")):
            for how in ("deleted", "emptied", "open_row"):
                with self.subTest(epoch=epoch, how=how), self.scratch() as tmp:
                    custody, counter = fx.custody(tmp), TestOnlyCounter(Path(tmp) / "shard.counter")
                    p = self._open(tmp, custody)
                    self.assertIsNone(counter.read())  # opening arms nothing
                    first = sealed(p, fx.batch_pays(1), state_digest=fx.STATE, created_at=fx.NOW, adds=b"")[0]
                    self.assertEqual((first.counter, counter.read()), (1, 1))
                    sealed(p, fx.batch_pays(1, 1), state_digest=fx.STATE, created_at=fx.NOW + 1, adds=b"")
                    p.close()
                    store, mark = Path(tmp) / "shard.sqlite3", Path(tmp) / "shard.mark"
                    for file in (store, mark, store.with_name(store.name + "-wal"), store.with_name(store.name + "-shm")):
                        file.unlink(missing_ok=True)
                    later = custody if name == "e7" else fx.custody(tmp, name)  # the same or a new epoch's certificate

                    def open_(counter_):
                        return self.track(producer.ShardProducer(store, mark_path=mark, tenant_id=fx.TENANT, shard_id=fx.SHARD, epoch=epoch,
                                                                 handle=later[0], link=later[1], cosign=fx.cosigner(), key_cert=later[2],
                                                                 payer_newest=gate.ZERO_DIGEST, counter=counter_, floors=lambda: (0, 0, 0, bytes(64))))
                    if how != "deleted":  # a store recreated at its creation (the schema), and for open_row one reservation too
                        q = open_(TestOnlyCounter(Path(tmp) / "fresh.counter"))
                        if how == "open_row":
                            with mock.patch.object(signer, "seal", side_effect=signer.GateSignerError("tpm_gone")):
                                with self.assertRaises(signer.GateSignerError):
                                    sealed(q, fx.batch_pays(1), state_digest=fx.STATE, created_at=fx.NOW, adds=b"")
                        q.close()
                    seen = {f.name: f.stat().st_size for f in Path(tmp).iterdir()}
                    for _ in range(2):  # sticky
                        with self.assertRaisesRegex(producer.GateProducerError, "no_store"):
                            open_(counter)
                    self.assertEqual((counter.read(), {f.name: f.stat().st_size for f in Path(tmp).iterdir()}), (2, seen))

    def test_the_test_counter_is_atomic_across_processes_and_refuses_a_short_file(self) -> None:
        with self.scratch() as tmp:
            path = Path(tmp) / "c"
            counter = TestOnlyCounter(path)
            self.assertEqual(counter.increment(), 1)
            code = ("import sys; from pathlib import Path; from tests._test_only_counter import TestOnlyCounter as C; "
                    "c = C(Path(sys.argv[1])); [c.increment() for _ in range(20)]")
            root = Path(__file__).resolve().parents[1]
            procs = [subprocess.Popen([sys.executable, "-c", code, str(path)], cwd=root) for _ in range(2)]
            self.assertEqual([x.wait(timeout=120) for x in procs], [0, 0])
            self.assertEqual(counter.read(), 41)  # no increment was lost: c + 2 * 20
            for name, data in (("short", path.read_bytes()[:-3]), ("garbled", b"x" * len(path.read_bytes())), ("empty", b"")):
                with self.subTest(name):
                    path.write_bytes(data)
                    with self.assertRaisesRegex(producer.GateProducerError, "counter_unavailable"):
                        counter.read()
                    with self.assertRaisesRegex(producer.GateProducerError, "counter_unavailable"):
                        counter.increment()

    def test_cutover_binds_qb_and_any_record_edit_holds_that_shard(self) -> None:
        """C4: the cutover row stores qb, its SHA3-512 and the cut tag; later rows carry dq under their pledge.  A record
        deleted, reordered or substituted in qb, or qb or the tag dropped, is ``quar_torn`` (that shard HOLDs); the
        newest row's dq dropped or moved into qb or cut (each pledged with its column index) is ``store_tampered``; a
        second cutover is refused."""
        qb, tag = b"A" * 9 + b"B" * 9 + b"C" * 9, bytes(range(64))
        go = lambda p, i, **kw: sealed(p, fx.batch_pays(1), state_digest=fx.STATE, created_at=fx.NOW + i, adds=b"", **kw)
        with self.scratch() as tmp:
            custody = fx.custody(tmp)
            p = self._open(tmp, custody)
            go(p, 0)
            self.assertIsNone(p.sealed_quar())
            go(p, 1, cut=(qb, tag))
            go(p, 2)
            with self.assertRaisesRegex(producer.GateProducerError, "cut_over"):
                go(p, 3, cut=(qb, tag))
            p.close()
            self.assertEqual(self._open(tmp, custody).sealed_quar(), (qb, hashlib.sha3_512(qb).digest()))
            self._stores.pop().close()
            store = Path(tmp) / "shard.sqlite3"
            saved = store.read_bytes()
            for name, sql, error in (("record deleted", "qb = x'" + (b"A" * 9 + b"C" * 9).hex() + "'", "quar_torn"),
                                     ("records reordered", "qb = x'" + (b"C" * 9 + b"B" * 9 + b"A" * 9).hex() + "'", "quar_torn"),
                                     ("record substituted", "qb = x'" + (b"A" * 9 + b"D" * 9 + b"C" * 9).hex() + "'", "quar_torn"),
                                     ("qb missing", "qb = NULL", "quar_torn"), ("tag dropped", "cut = NULL", "quar_torn"),
                                     ("newest dq dropped", "dq = NULL WHERE id = (SELECT max(id) FROM batches)", "store_tampered"),
                                     ("newest dq moved into qb", "qb = dq, dq = NULL WHERE id = (SELECT max(id) FROM batches)", "store_tampered"),
                                     ("newest dq moved into cut", "cut = dq, dq = NULL WHERE id = (SELECT max(id) FROM batches)", "store_tampered")):
                with self.subTest(name):
                    store.write_bytes(saved)
                    with contextlib.closing(sqlite3.connect(store)) as db:
                        db.executescript(f"DROP TRIGGER batches_quar; UPDATE batches SET {sql if 'WHERE' in sql else sql + ' WHERE cut IS NOT NULL'};")
                    with self.assertRaisesRegex(producer.GateProducerError, error):
                        self._open(tmp, custody).sealed_quar()
                    while self._stores:
                        self._stores.pop().close()

    def test_the_newest_cutover_rows_qb_and_tag_are_pledged(self) -> None:
        """While the cutover row is newest, its qb substituted with a matching dq, or its tag changed (triggers dropped),
        passes every quar check but the pledge, and qb edited under the old dq fails the pledge before the dq check:
        ``store_tampered`` at open, that shard decides nothing."""
        qb, other = b"A" * 9, b"B" * 9
        with self.scratch() as tmp:
            custody = fx.custody(tmp)
            p = self._open(tmp, custody)
            for i, cut in ((0, None), (1, (qb, bytes(range(64))))):
                sealed(p, fx.batch_pays(1), state_digest=fx.STATE, created_at=fx.NOW + i, adds=b"", cut=cut)
            p.close()
            store = Path(tmp) / "shard.sqlite3"
            saved = store.read_bytes()
            for name, sql in (("qb substituted", f"qb = x'{other.hex()}', dq = x'{hashlib.sha3_512(other).hexdigest()}'"),
                              ("qb edited", f"qb = x'{other.hex()}'"), ("tag changed", f"cut = x'{bytes(64).hex()}'")):
                with self.subTest(name):
                    store.write_bytes(saved)
                    with contextlib.closing(sqlite3.connect(store)) as db:
                        db.executescript(f"DROP TRIGGER batches_quar; UPDATE batches SET {sql} WHERE cut IS NOT NULL;")
                    with self.assertRaisesRegex(producer.GateProducerError, "store_tampered"):
                        self._open(tmp, custody).sealed_quar()
                    while self._stores:
                        self._stores.pop().close()

    def test_a_store_from_before_cutover_columns_opens_unchanged(self) -> None:
        """Pre-cutover pledges skip the NULL columns, so a store written before them reopens, verifies and serves."""
        with self.scratch() as tmp:
            custody = fx.custody(tmp)
            p = self._open(tmp, custody)
            sealed(p, fx.batch_pays(2), state_digest=fx.STATE, created_at=fx.NOW, adds=b"")
            published = p.published()
            p.close()
            with contextlib.closing(sqlite3.connect(Path(tmp) / "shard.sqlite3")) as db:
                db.executescript("DROP TRIGGER batches_quar; ALTER TABLE batches DROP COLUMN qb; "
                                 "ALTER TABLE batches DROP COLUMN dq; ALTER TABLE batches DROP COLUMN cut;")
            q = self._open(tmp, custody)
            self.assertEqual((q.published(), q.sealed_quar()), (published, None))


EARLIER = (("line-1-0", fx.PROGRAM, "pay-0007", "line-7-0"),)  # payment 1's first line repeats paid payment 7's
RETRY = b"r" * 32


def answered(p, frame: bytes = b""):
    """Seal payments 0 to 2, payment 1 ANSWERED with ``EARLIER``, filed under retry key ``RETRY``, its frame ``frame``."""
    pays = fx.batch_pays(3)
    pays[1] = pays[1]._replace(outcome="ANSWERED", reasons=("FFS_DUPLICATE_LINE",), earlier=EARLIER)
    p.prepared = decide.Answer((), fx.STATE, bytes(chain.AUTH), None, None, fx.D[1], 0, 1, tuple(pays), fx.D[6], frame=frame, retry=RETRY)
    return p.commit(fx.PROGRAM, p.prepared, fx.NOW)


def request_frame(n: int) -> bytes:
    """A decide request frame (conformance/FRAME_V1.md section 2) carrying payments 0 to ``n - 1``'s requests, with no
    feeds, grant, key set, release, steps, bypasses or rule-set records: what ``right_rail_gate_decide._requests`` reads."""
    le = lambda v: v.to_bytes(4, "little")  # noqa: E731
    bodies = [gate.encode_decide_request(fx.payment_request(k)) for k in range(n)]
    return bytes(82 + 4 + 4 + 64) + le(0) + bytes(4 * 77 + 64 + 9 + 4 + 4 + 64) + le(0) * 6 + le(len(bodies)) + b"".join(le(len(b)) + b for b in bodies)


class EarlierListTests(fx.Scratch):
    """Constitution I.4: an answered payment's earlier list is delivered again to an exact retry, byte for byte."""
    _open = ProducerTests._open

    def test_the_earlier_list_is_served_again_with_its_batch_and_completes_the_same_response(self) -> None:
        with self.scratch() as tmp:
            custody = fx.custody(tmp)
            p = self._open(tmp, custody)
            _, signed, tokens = answered(p)
            got = p.answered(RETRY)
            self.assertEqual(got, (signed, tuple(map(gate.encode_token, tokens)), ((), EARLIER, ())))
            response = gate.encode_decide_response(gate.DecideResponse(fx.TENANT, fx.PROGRAM, "cmd-0001", "DECIDED", tokens[1], earlier=EARLIER))
            self.assertTrue(response.endswith(len(got[1][1]).to_bytes(4, "big") + got[1][1] + gate.earlier_body(got[2][1])))
            p.close()
            self.assertEqual(self._open(tmp, custody).answered(RETRY), got)

    def test_a_token_whose_outcome_byte_names_no_outcome_is_refused_by_both_readers(self) -> None:
        with self.scratch() as tmp:
            p = self._open(tmp, fx.custody(tmp))
            raw = gate.encode_token(answered(p)[2][1])
            p.close()
        at = raw.index(gate.lines_root(fx.payment_request(1).lines)) + gate.DIGEST
        self.assertEqual((gate.read_token(raw)[1], gate.read_token_lines(raw)[3]), ("ANSWERED", "ANSWERED"))
        for byte in (0, len(gate.OUTCOMES) + 1):
            for reader in (gate.read_token, gate.read_token_lines):
                with self.subTest(byte=byte, reader=reader.__name__), self.assertRaisesRegex(gate.GateCodecError, "outcome"):
                    reader(raw[:at] + bytes([byte]) + raw[at + 1 :])

    def test_a_token_sealed_before_earlier_roots_is_read_by_its_own_layout_and_another_prefix_is_refused(self) -> None:
        with self.scratch() as tmp:
            p = self._open(tmp, fx.custody(tmp))
            raw = gate.encode_token(answered(p)[2][0])  # an ALLOW token: its earlier root is zero
            p.close()
        leaf = gate.token_leaf(raw)
        cut = len(leaf) - 3 * gate.DIGEST - 5 * 8 - gate.DIGEST  # its earlier root, before rule version, release, input, five times
        self.assertEqual(leaf[cut : cut + gate.DIGEST], gate.ZERO_DIGEST)
        old = b"RR/GATE/TOKEN/v2\x00" + leaf[len(gate.TOKEN) : cut] + leaf[cut + gate.DIGEST :]  # the leaf as sealed before 2026-11-16
        token = old + raw[len(leaf) :]
        self.assertEqual(gate.token_leaf(token), old)
        self.assertEqual((gate.read_token(token), gate.read_token_lines(token)), (gate.read_token(raw), gate.read_token_lines(raw)))
        self.assertNotEqual(gate.token_leaf(gate.TOKEN + token[len(gate.TOKEN) :]), old)  # relabelled: another leaf, so another root
        at = token.index(gate.lines_root(fx.payment_request(0).lines)) + gate.DIGEST
        self.assertEqual(token[at], gate.OUTCOMES.index("ALLOW") + 1)
        answered_v2 = token[:at] + bytes([gate.OUTCOMES.index("ANSWERED") + 1]) + token[at + 1 :]  # ANSWERED came with v3
        for reader in (gate.token_leaf, gate.read_token, gate.read_token_lines):
            with self.subTest(answered_in_v2=reader.__name__), self.assertRaisesRegex(gate.GateCodecError, "^outcome$"):
                reader(answered_v2)
        for prefix in (b"RR/GATE/TOKEN/v4\x00", b"RR/GATE/TOKEN/v1\x00", bytes(len(gate.TOKEN))):
            for reader in (gate.token_leaf, gate.read_token, gate.read_token_lines):
                with self.subTest(prefix=prefix, reader=reader.__name__), self.assertRaisesRegex(gate.GateCodecError, "^token$"):
                    reader(prefix + token[len(gate.TOKEN) :])

    def test_a_crash_after_the_reservation_reseals_it_with_its_earlier_list(self) -> None:
        with self.scratch() as tmp:
            custody = fx.custody(tmp)
            p = self._open(tmp, custody)
            real = signer.seal

            def crash(*args):
                real(*args)  # signed and verified, then the process dies before the seal commits
                raise KeyboardInterrupt

            with mock.patch.object(signer, "seal", crash), self.assertRaises(KeyboardInterrupt):
                answered(p)
            again = self._open(tmp, custody)  # the reopen reseals the reservation, its list stored in the same transaction
            signed, _, lists = again.answered(RETRY)
            self.assertEqual((again.published(), lists), ([signed], ((), EARLIER, ())))

    def test_a_voided_reservation_takes_its_earlier_list_with_it(self) -> None:
        with self.scratch() as tmp:
            p = self._open(tmp, fx.custody(tmp))
            p._floors = lambda: (10**9, 10**9)
            with self.assertRaisesRegex(producer.GateProducerError, "reservation_below_floor"):
                answered(p)
            p._floors = lambda: (0, 0, 0, bytes(64))
            self.assertEqual([p._db.execute(f"SELECT count(*) FROM {t}").fetchone()[0] for t in ("batches", "earlier")], [0, 0])
            answered(p)  # the next batch takes the voided id, and its own list
            self.assertEqual(p.answered(RETRY)[2], ((), EARLIER, ()))

    def test_a_changed_or_missing_earlier_list_is_refused_never_served(self) -> None:
        with self.scratch() as tmp:
            custody = fx.custody(tmp)
            p = self._open(tmp, custody)
            answered(p, request_frame(3))
            sealed(p, fx.batch_pays(2, 3), state_digest=fx.STATE, created_at=fx.NOW + 1, adds=b"")  # so the store opens on another batch
            published = p.published()
            p.close()
            store = Path(tmp) / "shard.sqlite3"
            saved = store.read_bytes()
            moved = (("line-1-0", fx.PROGRAM, "pay-0007", "line-7-1"),)
            other = gate.earlier_body(moved)
            gone = ("DELETE FROM earlier WHERE ?", (1,))
            old = (None, ())  # the store made one sealed before lists were stored (``g.before_lists``)
            with contextlib.closing(sqlite3.connect(store)) as db:
                packed = db.execute("SELECT tokens FROM batches WHERE id=1").fetchone()[0]
            self.assertEqual(packed.count(gate.earlier_root(EARLIER)), 1)
            resigned = packed.replace(gate.earlier_root(EARLIER), gate.earlier_root(moved))  # the token now names the other list
            for name, edits, error in (
                    # the row's pledge signs its tokens, so the retry is refused before any list is read
                    ("the token's earlier root and its list changed together",
                     [("UPDATE batches SET tokens=? WHERE id=1", (resigned,)), ("UPDATE earlier SET lists=?", (other,))], "^store_tampered$"),
                    ("another list", [("UPDATE earlier SET lists=?", (other,))], "^store_tampered$"),
                    ("a list no token names", [("UPDATE earlier SET lists=lists||?", (gate.earlier_body(EARLIER),))], "^store_tampered$"),
                    ("bytes that are no list", [("UPDATE earlier SET lists=?", (b"\x00\x01\x00",))], "^store_tampered$"),
                    ("text", [("UPDATE earlier SET lists=?", ("x",))], "^store_tampered$"),
                    # sealed with its list stored: the deleted row is evidence, never rebuilt, and hiding that it was stored breaks the pledge
                    ("no list (deleted)", [gone], "^store_tampered$"),
                    ("no list, and the row's word that it was stored cleared", [gone, ("UPDATE batches SET listed=NULL WHERE id=1", ())], "^store_tampered$"),
                    # a store sealed before lists were stored: its frame is read, and no paid line in it is the one EARLIER names
                    ("no list (a store sealed before lists were stored)", [old], "^store_version_earlier$"),
                    ("no list, and a frame no decide wrote", [old, ("UPDATE records SET frame=?", (b"",))], "^store_tampered$")):
                with self.subTest(name):
                    store.write_bytes(saved)
                    with contextlib.closing(sqlite3.connect(store)) as db:
                        db.executescript("DROP TRIGGER earlier_fixed; DROP TRIGGER earlier_void; DROP TRIGGER records_fixed; "
                                         "DROP TRIGGER batches_fixed; DROP TRIGGER batches_listed;")
                        for sql, args in edits:
                            g.before_lists(db, custody[0], (fx.TENANT, fx.SHARD)) if sql is None else db.execute(sql, args)
                        db.commit()
                    q = self._open(tmp, custody)
                    with self.assertRaisesRegex(producer.GateProducerError, error):
                        q.answered(RETRY)
                    self.assertEqual(q.published(), published)  # the store stays readable; only the retry is refused
                    q.close()

    def test_a_row_without_listed_is_pledged_as_before_lists_were_stored(self) -> None:
        """The message of a row with ``listed`` NULL is the one a producer signed before ``listed`` existed, written out
        here and not read from the module: (tenant, shard), epoch, seq_from, seq_to, digest, header, state digest,
        tokens, adds, then qb, dq, cut (NULLs skipped; once any is set, each set one after its index 8, 9 or 10), then
        cert, each u32-length framed, integers as 8 bytes, under PRODUCER-PLEDGE/v2.  ``listed`` = 1, or an ``rset``, is
        another message."""
        who = (fx.TENANT, fx.SHARD)
        base = {"epoch": fx.EPOCH, "seq_from": 0, "seq_to": 2, "digest": b"d" * 64, "header": b"h", "state_digest": b"s" * 64,
                "tokens": b"t", "adds": b"a", "cert": b"c"}

        def before(qb, dq, cut):
            n = lambda v: v.to_bytes(8, "big")  # noqa: E731
            fields = [who[0].encode("ascii"), n(who[1]), *(n(base[k]) if type(base[k]) is int else base[k] for k in list(base)[:8])]
            tag = any(v is not None for v in (qb, dq, cut))
            for index, value in ((8, qb), (9, dq), (10, cut)):
                fields += ([n(index)] if tag else []) + [value] if value is not None else []
            fields.append(base["cert"])
            return b"RR/GATE/PRODUCER-PLEDGE/v2\x00" + hashlib.sha3_512(b"".join(len(f).to_bytes(4, "big") + f for f in fields)).digest()
        for qb, dq, cut in ((None, None, None), (b"q", b"r" * 64, b"x"), (None, b"r" * 64, None)):
            with self.subTest(qb=qb, dq=dq, cut=cut):
                row = {**base, "qb": qb, "dq": dq, "cut": cut, "listed": None, "rset": None}
                self.assertEqual(producer._pledge(who, [row[c] for c in producer._PLEDGED.split(", ")]), before(qb, dq, cut))
                for column, value in (("listed", 1), ("rset", b"k" * 64)):
                    self.assertNotEqual(producer._pledge(who, [{**row, column: value}[c] for c in producer._PLEDGED.split(", ")]), before(qb, dq, cut))

    def test_a_listed_value_outside_eight_bytes_is_store_tampered(self) -> None:
        """``listed`` = -1 (no integer a pledge frames) on the newest sealed row or on an open reservation refuses the
        open as ``store_tampered``, never another error."""
        for state in ("sealed", "open"):
            with self.subTest(state), self.scratch() as tmp:
                custody = fx.custody(tmp)
                p = self._open(tmp, custody)
                if state == "sealed":
                    answered(p)
                    p.close()
                else:
                    with mock.patch.object(signer, "seal", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
                        answered(p)  # the reservation stays, unsigned
                with contextlib.closing(sqlite3.connect(Path(tmp) / "shard.sqlite3")) as db:
                    db.executescript("DROP TRIGGER batches_listed; UPDATE batches SET listed=-1;")
                with mock.patch.object(signer, "seal") as seal, self.assertRaisesRegex(producer.GateProducerError, "^store_tampered$"):
                    self._open(tmp, custody)
                seal.assert_not_called()

    def test_a_deleted_list_of_a_batch_sealed_with_it_is_tampered_and_nothing_is_rebuilt_or_removed(self) -> None:
        """A batch sealed after lists were stored whose ``earlier`` row was deleted is ``store_tampered`` at every exact
        retry: nothing is rebuilt or written, and its batch, frame and retry rows stay as evidence."""
        with self.scratch() as tmp:
            custody = fx.custody(tmp)
            p = self._open(tmp, custody)
            answered(p, request_frame(3))
            p.close()
            store = Path(tmp) / "shard.sqlite3"
            with contextlib.closing(sqlite3.connect(store)) as db:
                db.executescript("DROP TRIGGER earlier_void; DELETE FROM earlier;")
            q = self._open(tmp, custody)
            with mock.patch.object(producer.ShardProducer, "_rebuilt") as rebuilt:
                for _ in range(2):
                    with self.assertRaisesRegex(producer.GateProducerError, "^store_tampered$"):
                        q.answered(RETRY)
            rebuilt.assert_not_called()
            self.assertEqual([q._db.execute(f"SELECT count(*) FROM {t}").fetchone()[0] for t in ("batches", "records", "retries", "earlier")],
                             [1, 1, 1, 0])
            self.assertEqual(q._db.execute("SELECT listed FROM batches").fetchone(), (1,))

    def test_a_lists_value_that_is_not_a_blob_is_store_tampered_even_when_no_token_reads_it(self) -> None:
        with self.scratch() as tmp:
            custody = fx.custody(tmp)
            p = self._open(tmp, custody)
            p.prepared = decide.Answer((), fx.STATE, bytes(chain.AUTH), None, None, fx.D[1], 0, 1, tuple(fx.batch_pays(3)), fx.D[6], retry=RETRY)
            p.commit(fx.PROGRAM, p.prepared, fx.NOW)
            p.close()
            with contextlib.closing(sqlite3.connect(Path(tmp) / "shard.sqlite3")) as db:
                db.execute("INSERT INTO earlier(batch_id, lists) VALUES(1, 7)")  # an integer where bytes are stored
                db.commit()
            q = self._open(tmp, custody)
            with self.assertRaisesRegex(producer.GateProducerError, "store_tampered"):
                q.answered(RETRY)

    def test_an_orphan_earlier_row_at_the_next_batch_id_does_not_wedge_the_shard(self) -> None:
        with self.scratch() as tmp:
            custody = fx.custody(tmp)
            p = self._open(tmp, custody)
            p._floors = lambda: (10**9, 10**9)
            with self.assertRaisesRegex(producer.GateProducerError, "reservation_below_floor"):
                answered(p)  # voided: the next reservation takes id 1 again
            p._db.execute("INSERT INTO earlier(batch_id, lists) VALUES(1, ?)", (gate.earlier_body(EARLIER) * 2,))  # what an older void left behind
            p._db.commit()
            p._floors = lambda: (0, 0, 0, bytes(64))
            _, signed, _ = answered(p)
            self.assertEqual(p.answered(RETRY)[::2], (signed, ((), EARLIER, ())))


def key(b: int, i: int) -> bytes:
    """A 32-byte retry key in bucket ``b`` (its top 10 bits); ``i`` tells keys of one bucket apart."""
    return (b << 6).to_bytes(2, "big") + bytes([i]) * 30


def filed(p, retry: bytes, n: int):
    """Seal payment ``n`` alone, filed under retry key ``retry``."""
    p.prepared = decide.Answer((), fx.STATE, bytes(chain.AUTH), None, None, fx.D[1], 0, 1, tuple(fx.batch_pays(1, n)), fx.D[6], retry=retry)
    return p.commit(fx.PROGRAM, p.prepared, fx.NOW)


A, B, C = key(1, 1), key(1, 2), key(2, 1)  # A and B share bucket 1; C is alone in bucket 2
FRESH = (key(1, 7), key(2, 7), key(9, 7))  # never filed: in A's bucket, C's, and an empty one


class RetrySetTests(fx.Scratch):
    """Each batch row pledges the root of the set of retry keys: a retries row deleted or rekeyed is ``store_tampered`` at
    its exact retry, never decided again."""
    _open = ProducerTests._open

    def _store(self, tmp: str, custody) -> tuple[Path, list[bytes]]:
        """A closed store with A, B and C filed, each on its own sealed batch: (its path, their signed checkpoints)."""
        p = self._open(tmp, custody)
        signed = [filed(p, k, n)[1] for n, k in enumerate((A, B, C))]
        p.close()
        return Path(tmp) / "shard.sqlite3", signed

    def _edit(self, store: Path, *edits: tuple[str, tuple]) -> None:
        """Edit the closed store as someone without the key: retries triggers dropped, then each (sql, args)."""
        with contextlib.closing(sqlite3.connect(store)) as db:
            db.executescript("DROP TRIGGER retries_void; DROP TRIGGER retries_fixed; DROP TRIGGER batches_rset;")
            for sql, args in edits:
                db.execute(sql, args)
            db.commit()

    def _refused(self, q, keys) -> None:
        for k in keys:
            with self.subTest(retry=k.hex()[:6]), self.assertRaisesRegex(producer.GateProducerError, "^store_tampered$"):
                q.answered(k)

    def test_a_deleted_retries_row_is_store_tampered_at_its_exact_retry_and_the_batches_are_kept(self) -> None:
        for gone in (A, C):
            with self.subTest(gone=gone.hex()[:6]), self.scratch() as tmp:
                custody = fx.custody(tmp)
                store, signed = self._store(tmp, custody)
                self._edit(store, ("DELETE FROM retries WHERE key=?", (gone,)))
                q = self._open(tmp, custody)
                with mock.patch.object(signer, "sign") as sign:
                    self._refused(q, (gone, gone))  # every time, and nothing is signed
                sign.assert_not_called()
                self.assertEqual(q.published(), signed)  # every batch kept, readable
                self.assertEqual([q.answered(k)[0] for k in (A, B, C) if k != gone], [s for k, s in zip((A, B, C), signed) if k != gone])  # a hit is unchanged
                self.assertIsNone(q.answered(key(9, 7)))  # a miss in an untouched bucket is still decided
                self.assertEqual([q._db.execute(f"SELECT count(*) FROM {t}").fetchone()[0] for t in ("batches", "retries")], [3, 2])

    def test_a_rekeyed_retries_row_is_store_tampered(self) -> None:
        for name, new in (("within its bucket", key(1, 9)), ("to another bucket", key(5, 1))):
            with self.subTest(name), self.scratch() as tmp:
                custody = fx.custody(tmp)
                store, _ = self._store(tmp, custody)
                self._edit(store, ("UPDATE retries SET key=? WHERE key=?", (new, A)))
                self._refused(self._open(tmp, custody), (A, new))  # the old key: its bucket; the new one: its pledge

    def test_a_changed_bucket_hash_or_a_row_pointed_away_from_its_batch_is_store_tampered(self) -> None:
        """A stored bucket hash deleted or edited breaks the root, so a fresh key in any bucket is refused; a row moved to a
        batch id with no batch drops out of its bucket's hash (each key is hashed with its batch's digest)."""
        for name, edit, refused in (
                ("bucket 1 deleted", ("DELETE FROM rbuckets WHERE b=1", ()), FRESH),
                ("bucket 2 edited", ("UPDATE rbuckets SET h=? WHERE b=2", (bytes(64),)), FRESH),
                ("bucket 9 added", ("INSERT INTO rbuckets(b, h) VALUES(9, ?)", (bytes(64),)), FRESH),
                ("A's row pointed at no batch", ("UPDATE retries SET batch_id=99 WHERE key=?", (A,)), (A, key(1, 7)))):
            with self.subTest(name), self.scratch() as tmp:
                custody = fx.custody(tmp)
                store, _ = self._store(tmp, custody)
                self._edit(store, edit)
                self._refused(self._open(tmp, custody), refused)

    def test_a_deleted_row_with_the_buckets_and_the_newest_root_rewritten_to_agree_breaks_the_pledge(self) -> None:
        with self.scratch() as tmp:
            custody = fx.custody(tmp)
            store, _ = self._store(tmp, custody)
            with contextlib.closing(sqlite3.connect(store)) as db:
                left = db.execute("SELECT key, digest FROM retries JOIN batches ON id = batch_id WHERE key >= ? AND key < ? AND key != ? "
                                  "ORDER BY key", (key(1, 0)[:2], key(2, 0)[:2], A)).fetchall()
                buckets = {**dict(db.execute("SELECT b, h FROM rbuckets")), 1: producer._bucket_hash(left)}
            self._edit(store, ("DELETE FROM retries WHERE key=?", (A,)), ("UPDATE rbuckets SET h=? WHERE b=1", (buckets[1],)),
                       ("UPDATE batches SET rset=? WHERE id=3", (producer._set_root(buckets),)))
            with mock.patch.object(signer, "seal") as seal, self.assertRaisesRegex(producer.GateProducerError, "^store_tampered$"):
                self._open(tmp, custody)
            seal.assert_not_called()

    def test_honest_misses_stay_none_across_buckets_a_void_and_a_retried_reservation(self) -> None:
        with self.scratch() as tmp:
            custody = fx.custody(tmp)
            p = self._open(tmp, custody)
            fresh = lambda q: [q.answered(k) for k in FRESH]  # noqa: E731
            self.assertEqual(fresh(p), [None] * 3)
            for n, k in enumerate((A, B, C)):  # A and B in one bucket, C in another
                filed(p, k, n)
                self.assertEqual(fresh(p), [None] * 3)
            p._floors = lambda: (10**9, 10**9)
            with self.assertRaisesRegex(producer.GateProducerError, "reservation_below_floor"):
                filed(p, key(1, 3), 3)  # voided: its key's bucket is recomputed without it
            p._floors = lambda: (0, 0, 0, bytes(64))
            self.assertEqual(fresh(p) + [p.answered(key(1, 3))], [None] * 4)
            real, failed = p._db, []

            class Once:  # a database error after the bucket hashes are written, before the reservation commits
                def __getattr__(self, name):
                    return getattr(real, name)

                def execute(self, text, *args):
                    if text.startswith("DELETE FROM earlier") and not failed:
                        failed.append(text)
                        raise sqlite3.OperationalError("disk I/O error")
                    return real.execute(text, *args)
            p._db = Once()
            with mock.patch.object(producer.time, "sleep"):
                filed(p, key(2, 3), 3)  # rolled back whole and written again
            p._db = real
            self.assertEqual((len(failed), fresh(p), bool(p.answered(key(2, 3)))), (1, [None] * 3, True))
            p.close()
            q = self._open(tmp, custody)
            self.assertEqual(fresh(q) + [q.answered(key(1, 3))], [None] * 4)
            self.assertTrue(all(q.answered(k) for k in (A, B, C, key(2, 3))))

    def test_a_commit_into_the_bucket_of_a_deleted_row_is_store_tampered_and_writes_nothing(self) -> None:
        """A fresh key filed in a deleted row's bucket is refused before its reservation: the bucket is checked against the
        pledged root first, never rebuilt from the rows left (which would pledge a root without the deleted row)."""
        with self.scratch() as tmp:
            custody = fx.custody(tmp)
            store, _ = self._store(tmp, custody)
            self._edit(store, ("DELETE FROM retries WHERE key=?", (A,)))
            q = self._open(tmp, custody)
            kept = lambda: (q._db.execute("SELECT b, h FROM rbuckets ORDER BY b").fetchall(), q._db.execute("SELECT count(*) FROM batches").fetchone()[0])  # noqa: E731
            before = kept()
            with self.assertRaisesRegex(producer.GateProducerError, "^store_tampered$"):
                filed(q, key(1, 7), 3)
            self.assertEqual((kept(), before[1]), (before, 3))
            self._refused(q, (A,))

    def test_a_void_after_a_row_of_its_bucket_was_deleted_leaves_the_stored_bucket_hash(self) -> None:
        """A reservation voided after another row of its bucket was deleted does not rebuild that bucket's hash from the rows
        left: the stored hash stays, so the deleted row's retry is still refused."""
        with self.scratch() as tmp:
            custody = fx.custody(tmp)
            self._store(tmp, custody)
            p = self._open(tmp, custody)
            rbuckets = lambda: p._db.execute("SELECT b, h FROM rbuckets ORDER BY b").fetchall()  # noqa: E731
            real, seen = p._void, []

            def void(id_: int) -> None:  # B's row deleted between the reservation and its void
                p._db.execute("DROP TRIGGER retries_void")
                p._db.execute("DELETE FROM retries WHERE key=?", (B,))
                seen.append(rbuckets())
                real(id_)
            p._void, p._floors = void, lambda: (10**9, 10**9)
            with self.assertRaisesRegex(producer.GateProducerError, "reservation_below_floor"):
                filed(p, key(1, 3), 3)
            self.assertEqual((len(seen), rbuckets()), (1, seen[0]))
            self.assertEqual(p._db.execute("SELECT count(*) FROM batches").fetchone()[0], 3)  # the reservation itself is voided
            self._refused(p, (B, key(1, 4)))

    def test_keys_in_the_first_and_last_buckets_answer_a_miss_a_hit_and_a_void(self) -> None:
        low, high = (bytes(32), b"\x00\x3f" + b"\xff" * 30), (b"\xff\xc0" + bytes(30), b"\xff" * 32)
        self.assertEqual([producer._bucket(k) for k in low + high], [0, 0, 1023, 1023])
        with self.scratch() as tmp:
            custody = fx.custody(tmp)
            p = self._open(tmp, custody)
            signed = [filed(p, k, n)[1] for n, k in enumerate((low[0], high[1]))]
            self.assertEqual([p.answered(k) for k in (low[1], high[0])], [None, None])
            p._floors = lambda: (10**9, 10**9)
            for n, k in enumerate((low[1], high[0]), 2):
                with self.subTest(void=k.hex()[:6]), self.assertRaisesRegex(producer.GateProducerError, "reservation_below_floor"):
                    filed(p, k, n)
            p.close()
            q = self._open(tmp, custody)
            self.assertEqual([q.answered(k) for k in (low[1], high[0])], [None, None])
            self.assertEqual([q.answered(k)[0] for k in (low[0], high[1])], signed)
            signed.append(filed(q, high[0], 4)[1])
            self.assertEqual([(got := q.answered(k)) and got[0] for k in (*low, *high)], [signed[0], None, signed[2], signed[1]])

    def test_a_store_from_before_the_root_opens_unchanged_and_is_checked_from_its_next_commit(self) -> None:
        """A store whose rows pledge no root opens and serves as before (its misses are not checked, and its pledges are
        unchanged); its next commit builds every bucket from its rows, so from then on a deleted older row is refused."""
        with self.scratch() as tmp:
            custody = fx.custody(tmp)
            store, signed = self._store(tmp, custody)
            with contextlib.closing(sqlite3.connect(store)) as db:
                g.before(db, custody[0], (fx.TENANT, fx.SHARD), "rset")
                db.commit()
                pledges = db.execute("SELECT id, pledge FROM batches ORDER BY id").fetchall()
            q = self._open(tmp, custody)
            self.assertEqual([q.answered(k) for k in FRESH], [None] * 3)
            self.assertEqual([q.answered(k)[0] for k in (A, B, C)], signed)
            filed(q, key(9, 1), 3)
            self.assertEqual(q._db.execute("SELECT id, pledge FROM batches WHERE id <= 3 ORDER BY id").fetchall(), pledges)
            self.assertEqual([r is None for (r,) in q._db.execute("SELECT rset FROM batches ORDER BY id")], [True] * 3 + [False])
            self.assertEqual([q.answered(k) for k in FRESH], [None] * 3)
            q.close()
            self._edit(store, ("DELETE FROM retries WHERE key=?", (B,)))
            self._refused(self._open(tmp, custody), (B,))

    def test_a_commit_without_a_retry_key_copies_the_root_so_a_deleted_row_is_still_store_tampered(self) -> None:
        with self.scratch() as tmp:
            custody = fx.custody(tmp)
            p = self._open(tmp, custody)
            filed(p, A, 0)
            filed(p, b"", 1)  # no key: the root is copied, not rebuilt from the rows left
            rsets = [r for (r,) in p._db.execute("SELECT rset FROM batches ORDER BY id")]
            self.assertEqual((rsets[0] is None, rsets[0] == rsets[1]), (False, True))
            p.close()
            self._edit(Path(tmp) / "shard.sqlite3", ("DELETE FROM retries WHERE key=?", (A,)))
            self._refused(self._open(tmp, custody), (A,))

    def test_a_retries_key_sqlite_cannot_decode_is_store_tampered_on_every_read_never_unavailable(self) -> None:
        """Text that is not UTF-8 sorts into bucket 0 and fails on fetch; that decode failure, and only it, is ``store_tampered``."""
        bad = "UPDATE retries SET key=CAST(X'ff80' AS TEXT) WHERE key=?"
        tampered = r"^store_tampered$"
        with self.subTest("answered and commit"), self.scratch() as tmp:
            custody = fx.custody(tmp)
            store, _ = self._store(tmp, custody)
            self._edit(store, (bad, (A,)))
            q = self._open(tmp, custody)
            self._refused(q, (key(0, 7),))
            with self.assertRaisesRegex(producer.GateProducerError, tampered):
                filed(q, key(0, 8), 3)
            self.assertEqual(q._db.execute("SELECT count(*) FROM batches").fetchone()[0], 3)
            self.assertIsNone(q.answered(key(9, 7)))  # a bucket without it is read as before
        with self.subTest("the upgrade build"), self.scratch() as tmp:
            custody = fx.custody(tmp)
            store, _ = self._store(tmp, custody)
            with contextlib.closing(sqlite3.connect(store)) as db:
                g.before(db, custody[0], (fx.TENANT, fx.SHARD), "rset")
                db.executescript("DROP TRIGGER retries_void; DROP TRIGGER retries_fixed;")
                db.execute(bad, (A,))
                db.commit()
            q = self._open(tmp, custody)
            with self.assertRaisesRegex(producer.GateProducerError, tampered):
                filed(q, key(9, 1), 3)
        with self.subTest("a void"), self.scratch() as tmp:
            custody = fx.custody(tmp)
            self._store(tmp, custody)
            p = self._open(tmp, custody)
            real = p._void

            def void(id_: int) -> None:
                p._db.execute("DROP TRIGGER retries_void")
                p._db.execute("DROP TRIGGER retries_fixed")
                p._db.execute("UPDATE retries SET key=CAST(X'ff80' AS TEXT) WHERE batch_id=?", (id_,))
                real(id_)
            p._void, p._floors = void, lambda: (10**9, 10**9)
            with self.assertRaisesRegex(producer.GateProducerError, tampered):
                filed(p, key(1, 3), 3)
        with self.subTest("a locked store is not tampered"), self.scratch() as tmp:
            custody = fx.custody(tmp)
            self._store(tmp, custody)
            p = self._open(tmp, custody)
            real = p._db

            class Locked:
                def __getattr__(self, name):
                    return getattr(real, name)

                def execute(self, text, *args):
                    if text.startswith("SELECT key, digest"):
                        raise sqlite3.OperationalError("database is locked")
                    return real.execute(text, *args)
            p._db = Locked()
            with self.assertRaisesRegex(sqlite3.OperationalError, "locked"):
                p.answered(key(9, 7))

    def test_a_retry_key_that_is_not_32_bytes_is_refused_and_nothing_is_written(self) -> None:
        with self.scratch() as tmp:
            p = self._open(tmp, fx.custody(tmp))
            for bad in (b"r", bytes(31), bytes(33)):
                with self.subTest(len=len(bad)), self.assertRaisesRegex(producer.GateProducerError, "^bad_retry_key$"):
                    filed(p, bad, 0)
                self.assertEqual([p._db.execute(f"SELECT count(*) FROM {t}").fetchone()[0] for t in ("batches", "retries", "rbuckets")], [0, 0, 0])
            filed(p, A, 0)  # the answer was not spent by a refusal before it
            self.assertTrue(p.answered(A))

    def test_the_first_upgrade_commit_voided_is_followed_by_an_honest_second_commit(self) -> None:
        with self.scratch() as tmp:
            custody = fx.custody(tmp)
            store, _ = self._store(tmp, custody)
            with contextlib.closing(sqlite3.connect(store)) as db:
                g.before(db, custody[0], (fx.TENANT, fx.SHARD), "rset")
                db.commit()
            q = self._open(tmp, custody)
            q._floors = lambda: (10**9, 10**9)
            with self.assertRaisesRegex(producer.GateProducerError, "reservation_below_floor"):
                filed(q, key(9, 1), 3)  # the first commit under the root: its buckets are voided with it
            q._floors = lambda: (0, 0, 0, bytes(64))
            filed(q, key(9, 2), 3)
            self.assertEqual([r is None for (r,) in q._db.execute("SELECT rset FROM batches ORDER BY id")], [True] * 3 + [False])
            self.assertEqual([q.answered(k) for k in (key(9, 1), *FRESH)], [None] * 4)
            q.close()
            self._edit(store, ("DELETE FROM retries WHERE key=?", (B,)))
            self._refused(self._open(tmp, custody), (B,))


if __name__ == "__main__":
    unittest.main()
