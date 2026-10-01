"""The reference payer (``app/right_rail_gate_payer.py``): pin before send, Lean decides every release,
anything else is a recorded hold.  Synthetic, non-PHI."""

from __future__ import annotations

import contextlib
from dataclasses import replace
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import unittest

from app import right_rail_gate_codec as gate
from app import right_rail_gate_payer as payer
from app import right_rail_gate_signer as signer
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

    def _store(self, tmp: str) -> payer.PayerStore:
        return self.track(payer.PayerStore(Path(tmp) / "payer.sqlite3", root_keys={fx.TENANT: fx.keypair(f"root-{fx.TENANT}")[0]},
                                grants=((fx.D[3], (fx.D[4],), (fx.D[6],)),)))

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
            handle, root_pk, cert = fx.custody(tmp)
            store = self._store(tmp)
            store.install_cert(cert)
            leaves = fx.batch_leaves(0, 2)
            checkpoint, tokens = fx.build(leaves)
            header = gate.encode_checkpoint_header(checkpoint)
            signed = gate.attach_signature(header, signer.seal(handle, root_pk, cert, None, header,
                                                               [gate.encode_token(t) for t in tokens]))
            self.assertEqual(store.store_checkpoint(signed), "stored")
            request, token = fx.payment_request(0), gate.encode_token(tokens[0])  # leaves are payments 0 and 1, in order
            self.assertEqual(store.release(request, token, now=fx.NOW), "pin")  # never sent: check 12 holds it
            store.send(request, transmit=lambda data: None)
            self.assertIsNone(store.release(request, token, now=fx.NOW))
            self.assertEqual(store.release(request, token, now=fx.NOW), "released")
            other = replace(fx.payment_request(1), period="2026-10")  # still a canonical request; the token says 2026-09
            store.send(other, transmit=lambda data: None)
            self.assertEqual(store.release(other, gate.encode_token(tokens[1]), now=fx.NOW), "payment")
            self.assertEqual(store.holds(), [(request.payment_id, "pin"), (request.payment_id, "released"),
                                             (other.payment_id, "payment")])

    def test_a_second_genesis_is_recorded_as_a_fork(self) -> None:
        with self.scratch() as tmp:
            handle, root_pk, cert = fx.custody(tmp)
            store = self._store(tmp)
            store.install_cert(cert)
            outcomes = []
            for n in (0, 5):  # two different geneses of one shard and epoch, signed by an equivocating writer
                header = gate.encode_checkpoint_header(fx.build(fx.batch_leaves(0, 2, n))[0])
                outcomes.append(store.store_checkpoint(gate.attach_signature(header, signer.sign(handle, header))))
            self.assertEqual(outcomes, ["stored", "fork"])
            self.assertEqual(store.holds(), [])  # nothing is released or held by storing



if __name__ == "__main__":
    unittest.main()
