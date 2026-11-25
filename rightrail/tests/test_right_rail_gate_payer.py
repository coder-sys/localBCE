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
from unittest import mock
from typing import Callable
import unittest

from app import right_rail_gate_codec as gate
from app import right_rail_gate_payer as payer
from app import right_rail_gate_producer as producer
from app import right_rail_gate_signer as signer
from tests import test_right_rail_gate_formats as fx
from tests import test_right_rail_gate_producer as pt
from tests._test_only_counter import TestOnlyCounter

ROOT = Path(__file__).resolve().parents[1]


def _cp(handle: str, epoch: int, counter: int, *, first: int = 0, start: int = 0, prev: bytes = gate.ZERO_DIGEST,
        head: bytes = gate.ZERO_DIGEST, tenant: str = fx.TENANT) -> tuple[bytes, list[bytes], bytes]:
    """Payments ``start``, ``start``+1 on the main shard as a signed checkpoint of ``epoch`` taking ``counter``, from seq ``first``,
    linked to ``prev`` with chain head ``head``: its bytes, its tokens and its digest."""
    cp, tokens = fx.build([replace(leaf, epoch=epoch, tenant_id=tenant) for leaf in fx.batch_leaves(first, 2, start)], prev, head, counter)
    header = gate.encode_checkpoint_header(cp)
    return (gate.attach_signature(header, signer.sign(handle, header)) + fx.cosign_record(header, tenant),
            [gate.encode_token(t) for t in tokens], gate.checkpoint_digest(cp))

_KILL = """
import os, sys
sys.path.insert(0, {root!r})
from app import right_rail_gate_payer as payer
from app import right_rail_gate_producer as producer
from app import right_rail_gate_signer as signer
from tests import test_right_rail_gate_formats as fx
from tests import test_right_rail_gate_producer as pt
from tests._test_only_counter import TestOnlyCounter
store = payer.PayerStore({path!r}, links={{}}, grants=())
store.send(fx.payment_request(1), transmit=lambda data: os._exit(9))
"""


class PayerTests(fx.Scratch):
    """The payer reference adapter: pin before send, Lean decides every release, anything else holds."""

    def _store(self, tmp: str, grants=((fx.TENANT, fx.D[3], (fx.D[4],), (fx.D[6],)),)) -> payer.PayerStore:
        return self.track(payer.PayerStore(Path(tmp) / "payer.sqlite3", links={t: fx.link(t) for t in (fx.TENANT, fx.OTHER)}, grants=grants))

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

    def test_a_command_the_store_lost_is_a_typed_refusal_and_sends_nothing(self) -> None:
        with self.scratch() as tmp:
            store = self._store(tmp)
            sent: list[bytes] = []
            with mock.patch.object(store, "pin"), self.assertRaisesRegex(payer.GatePayerError, "command_missing"):
                store.send(fx.payment_request(1), transmit=sent.append)
            self.assertEqual(sent, [])

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
            key = (fx.TENANT, request.program_id)
            self.assertEqual(store.holds(), [(*key, request.payment_id, "pin"), (*key, request.payment_id, "released"),
                                             (*key, other.payment_id, "payment")])

    def _ready(self, tmp: str, send: bool = True) -> tuple[gate.DecideRequest, list[bytes]]:
        """A stored checkpoint of payments 0 and 1 (and payment 0 sent), in a closed store: payment 0's request, both tokens."""
        handle, held, cert = fx.custody(tmp)
        store = self._store(tmp)
        store.install_cert(cert)
        signed, tokens = fx.signed_genesis(handle, seal=(held, cert))
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
            self.assertEqual(foreign.holds()[-1], (fx.TENANT, request.program_id, request.payment_id, "grant"))
            self.assertEqual(self._count(tmp, "closed", "releases"), [0, 0])
            own = self._store(tmp, ((fx.OTHER, fx.D[3], *approves), (fx.TENANT, fx.D[3], *approves)))
            self.assertIsNone(own.release(request, token, now=fx.NOW))
            self.assertEqual(own.release(request, token, now=fx.NOW), "released")
            for i, bad in enumerate(((fx.D[3], *approves), ("-" + fx.TENANT, fx.D[3], *approves), (fx.TENANT.encode(), fx.D[3], *approves))):
                fresh = Path(tmp) / f"bad{i}.sqlite3"
                with self.subTest(bad=bad[0]), self.assertRaises(gate.GateCodecError):
                    payer.PayerStore(fresh, links={}, grants=(bad,))
                self.assertFalse(fresh.exists())  # refused before any write

    def test_release_requires_the_exact_command_to_have_been_sent(self) -> None:
        with self.scratch() as tmp:
            request, (token, _) = self._ready(tmp, send=False)
            store = self._store(tmp)
            with self.assertRaisesRegex(OSError, "transport failed"):
                store.send(request, lambda _: (_ for _ in ()).throw(OSError("transport failed")))
            self.assertEqual(store.release(request, token, now=fx.NOW), "pin")
            store.send(request, lambda _: None)
            self.assertEqual(store.release(replace(request, command_key="unsent-command"), token, now=fx.NOW), "pin")
            self.assertIsNone(store.release(request, token, now=fx.NOW))

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
            store = payer.PayerStore(Path(tmp) / "payer.sqlite3", links={fx.TENANT: fx.link(fx.TENANT)},
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
            self._raw(tmp, *(f"INSERT INTO checkpoints VALUES(X'{d}', '{t}', {s}, {e}, 0, {q}, X'', X'', 0)" for t, s, e, q, d in rows))
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
    def _self_cert(epoch: int, key: bytes | None = None, rnd: bytes = bytes(32)) -> bytes:
        """A certificate signed by the tenant's root and witness keys: of ``key``, by default one nothing else uses."""
        body = gate.encode_key_cert(fx.TENANT, epoch, fx.link_digest(fx.TENANT), (fx.SHARDS,), key or bytes([9]) * gate.ML_DSA_87_PUBLIC_KEY,
                                    fx.keypair(f"verifier-{fx.TENANT}")[0])
        return fx.certify(body, fx.TENANT, rnd)

    def test_concurrent_installs_of_one_epoch_install_one_key(self) -> None:
        """Four connections install four keys for one tenant and epoch: each is answered on the witnesses under the write
        lock, so exactly one is installed and the other three equivocate it."""
        certs = [self._self_cert(fx.EPOCH, bytes([n + 1]) * gate.ML_DSA_87_PUBLIC_KEY) for n in range(4)]
        with self.scratch() as tmp:
            self._store(tmp).close()
            outcomes = self._race(tmp, *[lambda store, cert=cert: store.install_cert(cert) for cert in certs])
            self.assertEqual(sorted(outcomes), ["EQUIVOCATES"] * 3 + ["INSTALLED"])
            self.assertEqual(self._count(tmp, "certs"), [4])

    def test_a_re_signature_is_same_and_an_unsigned_cert_is_refused_and_neither_writes(self) -> None:
        with self.scratch() as tmp:
            store = self._store(tmp)
            self.assertEqual(store.install_cert(self._self_cert(fx.EPOCH)), "INSTALLED")
            self.assertEqual(store.install_cert(self._self_cert(fx.EPOCH, rnd=bytes([1]) * 32)), "SAME")
            signed = self._self_cert(fx.EPOCH + 1)
            unsigned = signed[:-1] + bytes([signed[-1] ^ 1])
            with self.assertRaisesRegex(payer.GatePayerError, "cert_refused"):
                store.install_cert(unsigned)
            self.assertEqual(self._count(tmp, "certs"), [1])

    def test_holds_and_refusals_name_their_tenant_and_program(self) -> None:
        """Fault hunt item 10: one payment id under two tenants, or two programs, is two keys in the evidence as in the pins:
        each hold and each refusal names its (tenant, program, payment id)."""
        with self.scratch() as tmp:
            request, (token, _) = self._ready(tmp, send=False)
            store = self._store(tmp)
            for tenant, program in ((fx.TENANT, "p1"), (fx.OTHER, "p1"), (fx.TENANT, "p2")):
                store.pin(tenant, program, "pay-1", bytes(32))
                with self.assertRaisesRegex(payer.GatePayerError, "member_key_changed"):
                    store.pin(tenant, program, "pay-1", bytes([1]) * 32)
            self.assertEqual(store._db.execute("SELECT tenant, program, payment_id FROM refusals ORDER BY id").fetchall(),
                             [(fx.TENANT, "p1", "pay-1"), (fx.OTHER, "p1", "pay-1"), (fx.TENANT, "p2", "pay-1")])
            foreign = replace(request, tenant_id=fx.OTHER)  # this tenant's token offered under another tenant: held
            reason = store.release(foreign, token, now=fx.NOW)
            self.assertIsNotNone(reason)
            self.assertEqual(store.holds(), [(fx.OTHER, request.program_id, request.payment_id, reason)])

    # The layout of holds, refusals and commands before they named their tenant and program.
    _PRE_TENANT = (
        ("holds", "id INTEGER PRIMARY KEY, payment_id TEXT NOT NULL, token BLOB NOT NULL, reason TEXT NOT NULL, at INTEGER NOT NULL"),
        ("refusals", "id INTEGER PRIMARY KEY, payment_id TEXT NOT NULL, member_key BLOB NOT NULL"),
        ("commands", "command_key TEXT PRIMARY KEY, request BLOB NOT NULL, sent INTEGER NOT NULL DEFAULT 0"))

    def _refused_untouched(self, tmp: str) -> None:
        path = Path(tmp) / "payer.sqlite3"
        image = path.read_bytes()
        with self.assertRaisesRegex(payer.GatePayerError, "store_version"):
            self._store(tmp)
        self.assertEqual(path.read_bytes(), image)

    def test_a_store_from_before_tenant_keyed_evidence_is_refused_untouched(self) -> None:
        nullable = ("commands", "tenant TEXT, program TEXT, command_key TEXT, request BLOB NOT NULL, sent INTEGER NOT NULL DEFAULT 0, "
                                "PRIMARY KEY(tenant, program, command_key)")  # owners not yet required: a command no one resends
        for table, columns in (*self._PRE_TENANT, nullable):
            with self.subTest(columns), self.scratch() as tmp:
                self._store(tmp).close()
                self._raw(tmp, f"DROP TABLE {table}", f"CREATE TABLE {table}({columns})")
                self._refused_untouched(tmp)

    def test_a_complete_store_opens_without_a_write_and_its_closed_key_still_holds(self) -> None:
        with self.scratch() as tmp:
            request, (token, _) = self._ready(tmp)
            store = self._store(tmp)
            self.assertIsNone(store.release(request, token, now=fx.NOW))
            store.close()
            path = Path(tmp) / "payer.sqlite3"
            path.chmod(stat.S_IREAD)
            try:
                self._store(tmp).close()
            finally:
                path.chmod(stat.S_IREAD | stat.S_IWRITE)
            self.assertIsNotNone(self._store(tmp).release(request, token, now=fx.NOW))  # released once, never again

    def test_a_stored_link_that_no_longer_verifies_fails_the_open(self) -> None:
        """The stored chain is replayed through Lean at open: a link row whose signature was changed in the file is refused."""
        with self.scratch() as tmp:
            self._store(tmp).close()
            db = sqlite3.connect(Path(tmp) / "payer.sqlite3", isolation_level=None)
            db.execute("DROP TRIGGER links_update")  # the file's own guard against it; whoever edits the file can drop it
            (stored,) = db.execute("SELECT link FROM links WHERE tenant=?", (fx.TENANT,)).fetchone()
            db.execute("UPDATE links SET link=? WHERE tenant=?", (stored[:-1] + bytes([stored[-1] ^ 1]), fx.TENANT))
            db.close()
            with self.assertRaisesRegex(payer.GatePayerError, "link_refused"):
                self._store(tmp)

    def test_a_first_open_cut_short_before_releases_is_completed_by_the_next_open(self) -> None:
        names = list(payer._TABLES)
        self.assertLess(names.index("closed"), names.index("releases"))  # releases never exists without closed
        with self.scratch() as tmp:
            self._store(tmp).close()
            self._raw(tmp, "DROP TABLE releases")
            self._store(tmp).close()
            self.assertEqual(self._count(tmp, "releases"), [0])

    def test_a_closed_key_is_already_closed_and_records_one_hold_each_time(self) -> None:
        with self.scratch() as tmp:
            request, (token, _) = self._ready(tmp)
            # a closed key of the same payment_id under another program does not close this one
            self._raw(tmp, f"INSERT INTO closed VALUES('{fx.TENANT}','other-program','{request.payment_id}','DENIED','x',1)")
            store = self._store(tmp)
            # the same key already closed (a DENIED, so no releases row): the PK hit is caught, one hold and no payment row
            self._raw(tmp, f"INSERT INTO closed VALUES('{fx.TENANT}','{request.program_id}','{request.payment_id}','DENIED','x',1)")
            self.assertEqual(store.release(request, token, now=fx.NOW), "already_closed")
            self.assertEqual((store.holds(), store._db.execute("SELECT count(*) FROM releases").fetchone()[0]),
                             ([(fx.TENANT, request.program_id, request.payment_id, "already_closed")], 0))
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

    def test_a_store_with_a_release_that_has_no_closed_row_is_refused_untouched(self) -> None:
        release = "INSERT INTO releases VALUES('t','p','pay-1',x'00','payee',1,'2026-09',100)"
        for name, edits in (("no closed table", ("DROP TABLE closed", release)), ("closed row missing", (release,))):
            with self.subTest(name), self.scratch() as tmp:
                self._store(tmp).close()
                self._raw(tmp, *edits)
                self._refused_untouched(tmp)

    def test_a_second_genesis_is_recorded_as_a_fork(self) -> None:
        with self.scratch() as tmp:
            handle, held, cert = fx.custody(tmp)
            store = self._store(tmp)
            store.install_cert(cert)
            outcomes = [store.store_checkpoint(fx.signed_genesis(handle, n)[0]) for n in (0, 5)]  # two geneses, one equivocating writer
            self.assertEqual(outcomes, ["stored", "fork"])
            self.assertEqual(store.holds(), [])  # nothing is released or held by storing

    def test_a_certificate_of_the_root_key_is_refused(self) -> None:
        """No certificate may name a key of the held link (key reuse), though the root signs it: it is refused, no row."""
        with self.scratch() as tmp:
            store = self._store(tmp)
            with self.assertRaisesRegex(payer.GatePayerError, "cert_refused"):
                store.install_cert(self._self_cert(fx.EPOCH, fx.keypair(f"root-{fx.TENANT}")[0]))
            self.assertEqual(self._count(tmp, "certs"), [0])

    def test_a_root_signed_certificate_of_another_key_fences_and_equivocates(self) -> None:
        """A root-signed certificate of an unused key raises its tenant's fence, and with another key for the same epoch
        blocks that epoch, in either order."""
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

    def _keyed(self, tmp: str, *names: str) -> tuple[payer.PayerStore, dict[str, str]]:
        """A store with the epoch certificates ``names`` installed, and their key files."""
        store, handles = self._store(tmp), {}
        for name in names:
            handles[name], _, cert = fx.custody(tmp, name)
            store.install_cert(cert)
        return store, handles

    def test_the_same_counter_in_another_epoch_is_a_fork(self) -> None:
        with self.scratch() as tmp:
            store, key = self._keyed(tmp, "e6", "e7")
            self.assertEqual(store.store_checkpoint(_cp(key["e6"], fx.EPOCH - 1, 1)[0]), "stored")
            self.assertEqual(store.store_checkpoint(_cp(key["e7"], fx.EPOCH, 1, start=5)[0]), "fork")

    def test_a_replayed_fork_adds_no_row_and_the_store_still_answers(self) -> None:
        with self.scratch() as tmp:
            store, key = self._keyed(tmp, "e7")
            self.assertEqual(store.store_checkpoint(_cp(key["e7"], fx.EPOCH, 1)[0]), "stored")
            forking = _cp(key["e7"], fx.EPOCH, 1, start=5)[0]
            for _ in range(40):
                self.assertEqual(store.store_checkpoint(forking), "fork")
            self.assertEqual(self._count(tmp, "checkpoints", "forks"), [1, 1])
            self.assertEqual(store.store_checkpoint(_cp(key["e7"], fx.EPOCH, 1, start=9)[0]), "fork")
            self.assertEqual(self._count(tmp, "forks"), [2])

    def test_every_branch_of_the_candidate_lookup_is_indexed(self) -> None:
        with self.scratch() as tmp:
            self._store(tmp)
            with contextlib.closing(sqlite3.connect(Path(tmp) / "payer.sqlite3")) as db:
                plan = [row[3] for row in db.execute("EXPLAIN QUERY PLAN " + payer._CANDIDATES, ("t", 0, 0, 2, "t", 0, 1, 3, 0, "t", 0, 1, b"d", "t", 0, 1, b"p"))]
            self.assertTrue(plan and not [row for row in plan if row.startswith("SCAN checkpoints")], plan)
            self.assertTrue([row for row in plan if "checkpoints_seq_to" in row and "seq_to>" in row], plan)  # the range branch starts at the newest end

    def test_a_counter_at_the_top_of_what_sqlite_holds_still_records_a_fork(self) -> None:
        with self.scratch() as tmp:
            store, key = self._keyed(tmp, "e7")
            top = 2**63 - 1
            self.assertEqual(store.store_checkpoint(_cp(key["e7"], fx.EPOCH, top)[0]), "stored")
            self.assertEqual(store.store_checkpoint(_cp(key["e7"], fx.EPOCH, top, start=5)[0]), "fork")
            self.assertEqual(self._count(tmp, "checkpoints", "forks"), [1, 1])

    def test_a_value_past_what_sqlite_holds_is_refused_and_leaves_the_store(self) -> None:
        with self.scratch() as tmp:
            store, key = self._keyed(tmp, "e7")
            before = self._count(tmp, "checkpoints", "forks")
            line = f"GATE_VERIFY=INDEX {fx.TENANT.encode().hex()} 0 7 0 1 {'11' * 64} {'00' * 64} {{}}"
            for counter in (2**63, 2**64 - 1):
                with mock.patch.object(payer.signer, "gate_verify", return_value=line.format(counter)):
                    with self.assertRaisesRegex(payer.GatePayerError, "checkpoint_out_of_range"):
                        store.store_checkpoint(b"x")
            self.assertEqual(self._count(tmp, "checkpoints", "forks"), before)

    def test_a_tenants_forks_are_in_its_own_frames_only(self) -> None:
        with self.scratch() as tmp:
            store, key = self._keyed(tmp, "e7", "other")
            self.assertEqual(store.store_checkpoint(_cp(key["e7"], fx.EPOCH, 1)[0]), "stored")
            forking = _cp(key["e7"], fx.EPOCH, 1, start=5)[0]
            self.assertEqual(store.store_checkpoint(forking), "fork")
            self.assertIn(signer.framed(forking), store._fork_witnesses(fx.TENANT, fx.SHARD, fx.EPOCH))
            self.assertEqual(store._fork_witnesses(fx.OTHER, fx.SHARD, fx.EPOCH), b"\x00\x00")
            self.assertEqual(store.store_checkpoint(_cp(key["other"], fx.EPOCH, 1, tenant=fx.OTHER)[0]), "stored")
            self.assertEqual(self._count(tmp, "forks"), [1])

    def test_a_store_with_the_old_forks_table_is_refused(self) -> None:
        for forks in ("id INTEGER PRIMARY KEY, stored BLOB NOT NULL, forking BLOB NOT NULL, UNIQUE(stored, forking)",
                      "id INTEGER PRIMARY KEY, tenant TEXT NOT NULL, stored BLOB NOT NULL, forking BLOB NOT NULL"):
            with self.subTest(forks=forks), self.scratch() as tmp:
                self._raw(tmp, f"CREATE TABLE forks({forks})")
                with self.assertRaisesRegex(payer.GatePayerError, "store_version"):
                    self._store(tmp)

    def test_a_fork_stops_its_shard_in_every_epoch(self) -> None:
        """The stored side's own next checkpoint (a later epoch, the next counter, linked to it) is refused once its shard has a recorded fork."""
        with self.scratch() as tmp:
            store, key = self._keyed(tmp, "e7", "e8")
            honest = _cp(key["e7"], fx.EPOCH, 1)
            self.assertEqual(store.store_checkpoint(honest[0]), "stored")
            self.assertEqual(store.store_checkpoint(_cp(key["e7"], fx.EPOCH, 1, start=5)[0]), "fork")
            later = _cp(key["e8"], fx.EPOCH + 1, 2, first=2, start=10, prev=honest[2], head=honest[2])
            with self.assertRaisesRegex(payer.GatePayerError, "checkpoint_rejected"):
                store.store_checkpoint(later[0])
            self.assertEqual(self._count(tmp, "checkpoints", "forks"), [1, 1])

    def test_after_a_fork_an_honest_token_of_the_shard_in_another_epoch_holds_forked(self) -> None:
        with self.scratch() as tmp:
            store, key = self._keyed(tmp, "e6", "e8")
            signed, tokens, _ = _cp(key["e8"], fx.EPOCH + 1, 5, first=4, prev=fx.D[0], head=fx.D[1])
            self.assertEqual(store.store_checkpoint(signed), "stored")
            self.assertEqual(store.store_checkpoint(_cp(key["e6"], fx.EPOCH - 1, 1)[0]), "stored")
            self.assertEqual(store.store_checkpoint(_cp(key["e6"], fx.EPOCH - 1, 1, start=5)[0]), "fork")
            request = fx.payment_request(0)
            store.send(request, transmit=lambda data: None)
            self.assertEqual(store.release(request, tokens[0], now=fx.NOW), "forked")

    def test_a_store_without_the_counter_column_is_refused_and_the_column_is_kept(self) -> None:
        with self.scratch() as tmp:
            store, key = self._keyed(tmp, "e7")
            store.store_checkpoint(_cp(key["e7"], fx.EPOCH, 1)[0])
            self.assertEqual(store._db.execute("SELECT counter FROM checkpoints").fetchall(), [(1,)])
            self.assertEqual(store._db.execute("SELECT name FROM sqlite_master WHERE name='checkpoints_counter'").fetchall(),
                             [("checkpoints_counter",)])
        with self.scratch() as tmp:
            self._raw(tmp, "CREATE TABLE checkpoints(digest BLOB PRIMARY KEY, tenant TEXT, shard INTEGER, epoch INTEGER, "
                           "seq_from INTEGER, seq_to INTEGER, prev BLOB, signed BLOB)")
            with self.assertRaisesRegex(payer.GatePayerError, "store_version"):
                self._store(tmp)

    def test_a_crash_window_swap_is_a_fork_at_the_payer(self) -> None:
        """A seals N at counter 2 and the increment is lost; an older copy C (counter 1) is swapped in under a later epoch
        certificate and seals N' at counter 2; A is swapped back and seals counter 3.  The payer holds N' and answers
        ``fork`` for A's counter 3, whose chain head is N."""
        with self.scratch() as tmp:
            keys = {name: fx.custody(tmp, name) for name in ("e7", "e8")}
            tpm = pt._Flaky(Path(tmp) / "tpm.counter")

            def open_(where: str, name: str, epoch: int) -> producer.ShardProducer:
                (Path(tmp) / where).mkdir(exist_ok=True)
                handle, held, cert = keys[name]
                return self.track(producer.ShardProducer(
                    Path(tmp) / where / "shard.sqlite3", mark_path=Path(tmp) / where / "shard.mark", tenant_id=fx.TENANT,
                    shard_id=fx.SHARD, epoch=epoch, handle=handle, link=held, cosign=fx.cosigner(),  key_cert=cert,
                    payer_newest=gate.ZERO_DIGEST, counter=tpm, floors=lambda: (0, 0, 0, bytes(64))))

            seal = lambda p, start, at: pt.sealed(p, fx.batch_pays(2, start), state_digest=fx.STATE, created_at=fx.NOW + at, adds=b"")
            a = open_("a", "e7", fx.EPOCH)
            first = seal(a, 0, 0)[1]
            a.close()
            for name in ("shard.sqlite3", "shard.mark"):
                (Path(tmp) / "c").mkdir(exist_ok=True)
                (Path(tmp) / "c" / name).write_bytes((Path(tmp) / "a" / name).read_bytes())
            a = open_("a", "e7", fx.EPOCH)
            tpm.mode = "raises"
            with self.assertRaisesRegex(Exception, "signature_not_stored"):
                seal(a, 2, 1)  # N: signed and stored, the increment lost
            tpm.mode = None
            c = open_("c", "e8", fx.EPOCH + 1)
            swapped = seal(c, 2, 2)[1]  # N' at counter 2
            c.close()
            a = open_("a", "e7", fx.EPOCH)
            third = seal(a, 4, 3)[1]  # A's counter 3, on N
            store = self._store(tmp)
            for name in ("e7", "e8"):
                store.install_cert(keys[name][2])
            self.assertEqual([store.store_checkpoint(first), store.store_checkpoint(swapped)], ["stored", "stored"])
            self.assertEqual(store.store_checkpoint(third), "fork")


if __name__ == "__main__":
    unittest.main()
