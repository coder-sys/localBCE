"""The reference payer (``app/right_rail_gate_payer.py``): pin before send, Lean decides every release,
anything else is a recorded hold.  Synthetic, non-PHI."""

from __future__ import annotations

import contextlib
from dataclasses import replace
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import threading
from typing import Callable
import unittest

from app import right_rail_gate_codec as gate
from app import right_rail_gate_payer as payer
from tests import test_right_rail_gate_formats as fx

ROOT = Path(__file__).resolve().parents[1]

_KILL = """
import os, sys
sys.path.insert(0, {root!r})
from app import right_rail_gate_payer as payer
from tests import test_right_rail_gate_formats as fx
store = payer.PayerStore({path!r}, root_keys={{}}, grants=())
store.send(fx.payment_request(1), transmit=lambda data: os._exit(9))
"""


class PayerTests(fx.Scratch):
    """The payer reference adapter: pin before send, Lean decides every release, anything else holds."""

    def _store(self, tmp: str, grants=((fx.TENANT, fx.D[3], (fx.D[4],), (fx.D[6],)),)) -> payer.PayerStore:
        return self.track(payer.PayerStore(Path(tmp) / "payer.sqlite3", root_keys={fx.TENANT: fx.keypair(f"root-{fx.TENANT}")[0]}, grants=grants))

    def test_kill_between_pin_persist_and_send_leaves_a_pin_and_no_command(self) -> None:
        with self.scratch() as tmp:
            self._store(tmp).close()
            path = str(Path(tmp) / "payer.sqlite3")
            done = subprocess.run([sys.executable, "-c", _KILL.format(root=str(ROOT), path=path)],
                                  capture_output=True, timeout=120, env={**os.environ, "PYTHONIOENCODING": "utf-8"})
            self.assertEqual(done.returncode, 9, done.stderr[-2000:])
            with contextlib.closing(sqlite3.connect(path)) as db:
                self.assertEqual(db.execute("SELECT count(*) FROM pins").fetchone()[0], 1)
                self.assertEqual(db.execute("SELECT count(*) FROM commands WHERE sent=1").fetchone()[0], 0)

    def test_a_changed_member_key_sends_nothing(self) -> None:
        with self.scratch() as tmp:
            store = self._store(tmp)
            sent: list[bytes] = []
            store.send(fx.payment_request(1), transmit=sent.append)
            with self.assertRaisesRegex(payer.GatePayerError, "member_key_changed"):
                store.send(replace(fx.payment_request(1), command_key="cmd-0002", member_key=fx.member(99)), transmit=sent.append)
            self.assertEqual(len(sent), 1)

    def test_pin_agrees_with_every_gate_vector_payment_line(self) -> None:
        """The SQL pin is the Lean ``send``: each ``payment`` line of the gate vectors gets Lean's verdict."""
        with self.scratch() as tmp:
            store = self._store(tmp)
            for line in fx.VECTORS.read_text("ascii").splitlines():
                if not line.startswith("payment "):
                    continue
                _, verdict, name, tenant, program, _, payment_id, key, *_ = line.split()
                with self.subTest(name):
                    if verdict == "unsent":
                        self.assertIsNone(store._db.execute("SELECT 1 FROM pins WHERE tenant=? AND program=? AND payment_id=?",
                                                            (tenant, program, payment_id)).fetchone())
                    elif verdict == "accept":
                        store.pin(tenant, program, payment_id, bytes.fromhex(key))
                    else:
                        with self.assertRaisesRegex(payer.GatePayerError, verdict):
                            store.pin(tenant, program, payment_id, bytes.fromhex(key))

    def test_pins_cannot_be_edited(self) -> None:
        with self.scratch() as tmp:
            store = self._store(tmp)
            store.send(fx.payment_request(1), transmit=lambda data: None)
            store.close()
            with contextlib.closing(sqlite3.connect(Path(tmp) / "payer.sqlite3")) as db:
                for statement in ("UPDATE pins SET member_key=zeroblob(32)", "DELETE FROM pins"):
                    with self.subTest(statement), self.assertRaises(sqlite3.DatabaseError):
                        db.execute(statement)

    def test_release_is_lean_decided_once_and_holds_otherwise(self) -> None:
        with self.scratch() as tmp:
            request, (token, token1) = self._ready(tmp, send=False)  # payments 0 and 1, in order
            store = self._store(tmp)
            self.assertEqual(store.release(request, token, now=fx.NOW), "pin")  # never sent: check 12 holds it
            store.send(request, transmit=lambda data: None)
            self.assertIsNone(store.release(request, token, now=fx.NOW))
            self.assertEqual(store.release(request, token, now=fx.NOW), "released")
            other = replace(fx.payment_request(1), period="2026-10")  # still a canonical request; the token says 2026-09
            store.send(other, transmit=lambda data: None)
            self.assertEqual(store.release(other, token1, now=fx.NOW), "payment")
            self.assertEqual(store.holds(), [(request.payment_id, "pin"), (request.payment_id, "released"), (other.payment_id, "payment")])

    def _ready(self, tmp: str, send: bool = True) -> tuple[gate.DecideRequest, list[bytes]]:
        """A stored checkpoint of payments 0 and 1 (and payment 0 sent), in a closed store: payment 0's request, both tokens."""
        handle, root_pk, cert = fx.custody(tmp)
        store = self._store(tmp)
        store.install_cert(cert)
        signed, tokens = fx.signed_genesis(handle, seal=(root_pk, cert))
        self.assertEqual(store.store_checkpoint(signed), "stored")
        request = fx.payment_request(0)
        if send:
            store.send(request, transmit=lambda data: None)
        store.close()
        return request, tokens

    def test_a_grant_of_another_tenant_releases_nothing(self) -> None:
        """Check 9 matches the grant's tenant: its grant id under another tenant holds the token and moves nothing, under its
        own tenant it releases once.  A grant's tenant is required and canonical, refused when the store is built."""
        with self.scratch() as tmp:
            request, (token, _) = self._ready(tmp)
            approves = ((fx.D[4],), (fx.D[6],))
            foreign = self._store(tmp, ((fx.OTHER, fx.D[3], *approves), (fx.TENANT, fx.D[9], *approves)))
            self.assertEqual(foreign.release(request, token, now=fx.NOW), "grant")
            self.assertEqual(foreign.holds()[-1], (request.payment_id, "grant"))
            self.assertEqual(self._count(tmp, "closed", "releases"), [0, 0])
            own = self._store(tmp, ((fx.OTHER, fx.D[3], *approves), (fx.TENANT, fx.D[3], *approves)))
            self.assertIsNone(own.release(request, token, now=fx.NOW))
            self.assertEqual(own.release(request, token, now=fx.NOW), "released")
            for i, bad in enumerate(((fx.D[3], *approves), ("-" + fx.TENANT, fx.D[3], *approves), (fx.TENANT.encode(), fx.D[3], *approves))):
                fresh = Path(tmp) / f"bad{i}.sqlite3"
                with self.subTest(bad=bad[0]), self.assertRaises(gate.GateCodecError):
                    payer.PayerStore(fresh, root_keys={}, grants=(bad,))
                self.assertFalse(fresh.exists())  # refused before any write

    def test_grants_may_be_a_one_shot_iterable(self) -> None:
        with self.scratch() as tmp:
            request, (token, _) = self._ready(tmp)
            store = self._store(tmp, (g for g in ((fx.TENANT, fx.D[3], (fx.D[4],), (fx.D[6],)),)))
            self.assertIsNone(store.release(request, token, now=fx.NOW))
            self.assertEqual(store.release(request, token, now=fx.NOW), "released")

    def _raw(self, tmp: str, *statements: str) -> None:
        with contextlib.closing(sqlite3.connect(Path(tmp) / "payer.sqlite3", isolation_level=None)) as db:
            for statement in statements: db.execute(statement)

    def _race(self, tmp: str, *calls: Callable[[payer.PayerStore], object]) -> list[object]:
        """Run each call on its own connection and thread, started together; the results, in finishing order."""
        barrier, outcomes = threading.Barrier(len(calls)), []

        def run(call: Callable[[payer.PayerStore], object]) -> None:
            store = payer.PayerStore(Path(tmp) / "payer.sqlite3", root_keys={fx.TENANT: fx.keypair(f"root-{fx.TENANT}")[0]},
                                     grants=((fx.TENANT, fx.D[3], (fx.D[4],), (fx.D[6],)),))
            barrier.wait()
            outcomes.append(call(store))
            store.close()  # a connection closes in its own thread

        threads = [threading.Thread(target=run, args=(call,)) for call in calls]
        for thread in threads: thread.start()
        for thread in threads: thread.join()
        return outcomes

    def _count(self, tmp: str, *tables: str) -> list[int]:
        with contextlib.closing(sqlite3.connect(Path(tmp) / "payer.sqlite3")) as db:
            return [db.execute(f"SELECT count(*) FROM {table}").fetchone()[0] for table in tables]

    def test_newest_stored_per_shard_epoch_then_seq_to_then_lowest_digest(self) -> None:
        with self.scratch() as tmp:
            store = self._store(tmp)
            self.assertEqual(store.newest_stored(fx.TENANT), {})
            rows = [(fx.TENANT, 0, 7, 9, "02"), (fx.TENANT, 0, 8, 1, "03"), (fx.TENANT, 0, 7, 5, "01"),  # epoch beats seq_to
                    (fx.TENANT, 1, 7, 4, "0b"), (fx.TENANT, 1, 7, 4, "0a"),  # a tie: the lowest digest, not row order
                    (fx.OTHER, 0, 9, 9, "0c"), (fx.OTHER, 2, 9, 9, "0d")]  # another tenant's newer rows are ignored
            self._raw(tmp, *(f"INSERT INTO checkpoints VALUES(X'{d}', '{t}', {s}, {e}, 0, {q}, X'', X'')" for t, s, e, q, d in rows))
            self.assertEqual(store.newest_stored(fx.TENANT), {0: b"\x03", 1: b"\x0a"})
            self.assertEqual(store.newest_stored(fx.OTHER), {0: b"\x0c", 2: b"\x0d"})

    def test_two_connections_release_one_key_once(self) -> None:
        with self.scratch() as tmp:
            request, (token, _) = self._ready(tmp)
            outcomes = self._race(tmp, *[lambda store: store.release(request, token, now=fx.NOW)] * 2)
            self.assertEqual(sorted(outcomes, key=str), [None, "released"])  # the loser sees the winner's row under the lock
            self.assertEqual(self._count(tmp, "closed", "releases", "holds"), [1, 1, 1])  # the winner's two rows, the loser's one hold
            with contextlib.closing(sqlite3.connect(Path(tmp) / "payer.sqlite3")) as db:
                self.assertEqual(db.execute("SELECT reason FROM holds").fetchall(), [("released",)])

    def test_two_connections_storing_forking_checkpoints_store_one_and_record_the_fork(self) -> None:
        with self.scratch() as tmp:
            handle, _, cert = fx.custody(tmp)
            self._store(tmp).install_cert(cert)
            signed = [fx.signed_genesis(handle, n)[0] for n in (0, 5)]  # two geneses of one shard and epoch, by an equivocating writer
            outcomes = self._race(tmp, *[lambda store, one=one: store.store_checkpoint(one) for one in signed])
            self.assertEqual(sorted(outcomes), ["fork", "stored"])
            self.assertEqual(self._count(tmp, "checkpoints", "forks"), [1, 1])

    def test_a_failed_commit_rolls_back_and_leaves_the_connection_usable(self) -> None:
        with self.scratch() as tmp:
            request, (token, _) = self._ready(tmp)
            store = self._store(tmp)
            store._db.execute("PRAGMA busy_timeout=100")
            with contextlib.closing(sqlite3.connect(Path(tmp) / "payer.sqlite3", isolation_level=None)) as reader:
                reader.execute("BEGIN")
                reader.execute("SELECT count(*) FROM pins").fetchone()  # a reader's SHARED lock: COMMIT cannot get EXCLUSIVE
                with self.assertRaisesRegex(sqlite3.OperationalError, "locked"):
                    store.release(request, token, now=fx.NOW)
            self.assertEqual(self._count(tmp, "closed", "releases", "holds"), [0, 0, 0])
            self.assertIsNone(store.release(request, token, now=fx.NOW))  # no transaction was left open

    def test_a_commit_that_fails_after_the_transaction_ended_raises_the_commit_error(self) -> None:
        class Gone:  # COMMIT fails the way a full disk does: SQLite has already rolled the transaction back
            def __init__(self, db: sqlite3.Connection) -> None:
                self.db = db

            def execute(self, sql: str, *args: object) -> sqlite3.Cursor:
                if sql == "COMMIT":
                    self.db.execute("ROLLBACK")
                    raise sqlite3.OperationalError("disk I/O error")
                return self.db.execute(sql, *args)

        with self.scratch() as tmp:
            store = self._store(tmp)
            real, store._db = store._db, Gone(store._db)
            try:
                with self.assertRaisesRegex(sqlite3.OperationalError, "disk I/O error") as caught:
                    store.pin("t", "p", "pay", b"k")
            finally:
                store._db = real
            self.assertRegex(str(caught.exception.__cause__), "no transaction is active")  # the ROLLBACK error is chained, not raised
            store.pin("t", "p", "pay", b"k")  # the connection is usable
            self.assertEqual(self._count(tmp, "pins"), [1])

    @staticmethod
    def _self_cert(epoch: int) -> bytes:  # the root key certifying itself, signed by the root
        body = gate.encode_key_cert(fx.TENANT, epoch, fx.SHARDS, fx.keypair(f"root-{fx.TENANT}")[0])
        return gate.attach_signature(body, fx.det_sign(f"root-{fx.TENANT}", body))

    def test_concurrent_installs_cannot_pass_the_cert_cap(self) -> None:
        def install(epoch: int) -> Callable[[payer.PayerStore], str]:
            cert = self._self_cert(epoch)

            def call(store: payer.PayerStore) -> str:
                try:
                    store.install_cert(cert)
                except payer.GatePayerError as refusal:
                    return str(refusal)
                return "installed"
            return call

        with self.scratch() as tmp:
            self._store(tmp).close()
            self._raw(tmp, *(f"INSERT INTO certs VALUES(x'{n:04x}')" for n in range(payer.MAX_CERTS - 1)))
            outcomes = self._race(tmp, *[install(fx.EPOCH + n) for n in range(4)])
            self.assertEqual(sorted(outcomes), ["cert_store_full"] * 3 + ["installed"])
            self.assertEqual(self._count(tmp, "certs"), [payer.MAX_CERTS])

    def test_a_complete_store_opens_without_a_write(self) -> None:
        with self.scratch() as tmp:
            self._store(tmp).close()
            path = Path(tmp) / "payer.sqlite3"
            path.chmod(stat.S_IREAD)
            try:
                self._store(tmp).close()
            finally:
                path.chmod(stat.S_IREAD | stat.S_IWRITE)

    def test_a_closed_key_is_already_closed_and_records_one_hold_each_time(self) -> None:
        with self.scratch() as tmp:
            request, (token, _) = self._ready(tmp)
            # a closed key of the same payment_id under another program does not close this one (R4.1-13)
            self._raw(tmp, f"INSERT INTO closed VALUES('{fx.TENANT}','other-program','{request.payment_id}','DENIED','x',1)")
            store = self._store(tmp)
            # the same key already closed (a DENIED, so no releases row): the PK hit is caught, one hold and no payment row
            self._raw(tmp, f"INSERT INTO closed VALUES('{fx.TENANT}','{request.program_id}','{request.payment_id}','DENIED','x',1)")
            self.assertEqual(store.release(request, token, now=fx.NOW), "already_closed")
            self.assertEqual((store.holds(), store._db.execute("SELECT count(*) FROM releases").fetchone()[0]),
                             ([(request.payment_id, "already_closed")], 0))
            self.assertEqual(store._db.execute("SELECT count(*) FROM closed").fetchone()[0], 2)
            self.assertEqual(store.release(request, token, now=fx.NOW), "already_closed")  # the connection stays usable
            self.assertEqual(len(store.holds()), 2)
        with self.scratch() as tmp:
            request, (token, _) = self._ready(tmp)
            self._raw(tmp, f"INSERT INTO closed VALUES('{fx.TENANT}','other-program','{request.payment_id}','DENIED','x',1)")
            self.assertIsNone(self._store(tmp).release(request, token, now=fx.NOW))

    def test_an_integrity_error_on_releases_rolls_back_closed_and_fails_loudly(self) -> None:
        with self.scratch() as tmp:
            request, (token, _) = self._ready(tmp)
            self._raw(tmp, "CREATE TRIGGER boom BEFORE INSERT ON releases BEGIN SELECT RAISE(ABORT, 'boom'); END")
            store = self._store(tmp)
            with self.assertRaises(sqlite3.IntegrityError):
                store.release(request, token, now=fx.NOW)
            self.assertEqual(self._count(tmp, "closed", "releases", "holds"), [0, 0, 0])
            self._raw(tmp, "DROP TRIGGER boom")
            self.assertIsNone(store.release(request, token, now=fx.NOW))  # the connection is usable and the key still free

    def test_closed_is_migrated_from_releases_without_loss_and_idempotently(self) -> None:
        with self.scratch() as tmp:
            self._store(tmp).close()
            self._raw(tmp, "DROP TABLE closed", *(
                f"INSERT INTO releases VALUES('t{n % 2}','p{n}','pay-{n}',x'00','payee',{n},'2026-09',{100 + n})" for n in range(5)))
            for _ in range(2):  # the second open changes nothing
                store = self._store(tmp)
                self.assertEqual(store._db.execute("SELECT tenant, program, payment_id, outcome, ref, closed_at FROM closed "
                                                   "ORDER BY closed_at").fetchall(),
                                 [(f"t{n % 2}", f"p{n}", f"pay-{n}", "RELEASED", "payee", 100 + n) for n in range(5)])
                store.close()

    def test_a_second_genesis_is_recorded_as_a_fork(self) -> None:
        with self.scratch() as tmp:
            handle, root_pk, cert = fx.custody(tmp)
            store = self._store(tmp)
            store.install_cert(cert)
            outcomes = [store.store_checkpoint(fx.signed_genesis(handle, n)[0]) for n in (0, 5)]  # two geneses, one equivocating writer
            self.assertEqual(outcomes, ["stored", "fork"])
            self.assertEqual(store.holds(), [])  # nothing is released or held by storing

    def test_a_root_signed_self_certificate_still_fences_and_equivocates(self) -> None:
        """M4 refuses the root key only as a checkpoint key: a root-signed certificate of the root key itself still
        raises its tenant's fence, and with another key for the same epoch still blocks that epoch, in either order."""
        with self.scratch() as tmp:
            handle, _, cert = fx.custody(tmp)
            store = self._store(tmp)
            store.install_cert(cert)
            signed, tokens = fx.signed_genesis(handle)
            self.assertEqual(store.store_checkpoint(signed), "stored")
            store.send(fx.payment_request(0), transmit=lambda data: None)
            store.install_cert(self._self_cert(fx.EPOCH + 1))
            self.assertEqual(store.release(fx.payment_request(0), tokens[0], now=fx.NOW), "fence")
        for self_first in (True, False):
            with self.subTest(self_first=self_first), self.scratch() as tmp:
                handle, _, cert = fx.custody(tmp)
                store = self._store(tmp)
                for one in (self._self_cert(fx.EPOCH), cert)[:: 1 if self_first else -1]:
                    store.install_cert(one)
                with self.assertRaisesRegex(payer.GatePayerError, "checkpoint_rejected"):
                    store.store_checkpoint(fx.signed_genesis(handle)[0])


if __name__ == "__main__":
    unittest.main()
