"""A reference payer for the gate, on SQLite: pin before send, Lean decides every release.  Synthetic,
activation=false; a payer may build its own adapter, with the gate vectors as the conformance test.

Every table is append-only by schema triggers; ``commands.sent`` alone changes, once, from 0 to 1.
``send`` records the payment's member-key pin and its unsent command in one transaction and only then
transmits, so a kill leaves a pin and no sent command.  Python decodes nothing and decides nothing: the pinned
Lean ``gate_verify`` decodes a checkpoint (INDEX), decides whether it is stored or forks the stored ones
(STORE) and whether a token may be released (RELEASE, ``firstFailure`` on the state this adapter loads).
Anything but ACCEPT is a recorded hold; nothing is released on an error.
"""

from __future__ import annotations

import contextlib
from pathlib import Path
import sqlite3
from typing import Callable, Final, Iterator, Mapping, Sequence

from app import right_rail_gate_codec as gate
from app import right_rail_gate_signer as signer

_TABLES: Final = {
    "pins": "tenant TEXT, program TEXT, payment_id TEXT, member_key BLOB NOT NULL, PRIMARY KEY(tenant, program, payment_id)",
    "commands": "command_key TEXT PRIMARY KEY, request BLOB NOT NULL, sent INTEGER NOT NULL DEFAULT 0",
    "refusals": "id INTEGER PRIMARY KEY, payment_id TEXT NOT NULL, member_key BLOB NOT NULL",
    "certs": "cert BLOB PRIMARY KEY",
    "checkpoints": "digest BLOB PRIMARY KEY, tenant TEXT, shard INTEGER, epoch INTEGER, seq_from INTEGER, seq_to INTEGER, "
                   "prev BLOB, signed BLOB",
    "forks": "id INTEGER PRIMARY KEY, stored BLOB NOT NULL, forking BLOB NOT NULL",
    "releases": "tenant TEXT, program TEXT, payment_id TEXT, token BLOB NOT NULL, payee_ref TEXT NOT NULL, "
                "amount_cents INTEGER NOT NULL, period TEXT NOT NULL, at INTEGER NOT NULL, PRIMARY KEY(tenant, program, payment_id)",
    "holds": "id INTEGER PRIMARY KEY, payment_id TEXT NOT NULL, token BLOB NOT NULL, reason TEXT NOT NULL, at INTEGER NOT NULL",
}
_SCHEMA: Final = "".join(
    f"CREATE TABLE IF NOT EXISTS {name}({columns});" + "".join(
        f"CREATE TRIGGER IF NOT EXISTS {name}_{verb.lower()} BEFORE {verb} ON {name} {when}"
        "BEGIN SELECT RAISE(ABORT, 'append_only'); END;"
        for verb, when in (("UPDATE", "WHEN OLD.sent=1 OR NEW.sent!=1 OR NEW.command_key IS NOT OLD.command_key OR "
                                      "NEW.request IS NOT OLD.request " if name == "commands" else ""), ("DELETE", "")))
    for name, columns in _TABLES.items())


class GatePayerError(RuntimeError):
    """A payment's member key changed, or a checkpoint was refused."""


def _list(items: Sequence[bytes]) -> bytes:
    return len(items).to_bytes(2, "big") + b"".join(items)


def _blob(data: bytes) -> bytes:
    return len(data).to_bytes(2, "big") + data


class PayerStore:
    def __init__(self, path: Path | str, *, root_keys: Mapping[str, bytes],
                 grants: Sequence[tuple[bytes, Sequence[bytes], Sequence[bytes]]]) -> None:
        self._roots = dict(root_keys)
        self._grants = _list([_blob(g) + _list([_blob(v) for v in rules]) + _list([_blob(r) for r in engines])
                              for g, rules, engines in grants])
        self._db = sqlite3.connect(path, isolation_level=None)
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.executescript(_SCHEMA)

    @contextlib.contextmanager
    def _tx(self) -> Iterator[None]:
        self._db.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self._db.execute("ROLLBACK")
            raise
        self._db.execute("COMMIT")

    def pin(self, tenant: str, program: str, payment_id: str, member_key: bytes,
            command: tuple[str, bytes] | None = None) -> None:
        """Pin the payment's member key at first sight and store its command, unsent, in the same transaction;
        another key is recorded as a refusal and raises ``member_key_changed``."""
        with self._tx():
            held = self._db.execute("SELECT member_key FROM pins WHERE tenant=? AND program=? AND payment_id=?",
                                    (tenant, program, payment_id)).fetchone()
            changed = held is not None and held[0] != member_key
            if changed:
                self._db.execute("INSERT INTO refusals(payment_id, member_key) VALUES(?,?)", (payment_id, member_key))
            else:
                self._db.execute("INSERT OR IGNORE INTO pins VALUES(?,?,?,?)", (tenant, program, payment_id, member_key))
                if command:
                    self._db.execute("INSERT OR IGNORE INTO commands(command_key, request) VALUES(?,?)", command)
        if changed:
            raise GatePayerError("member_key_changed")

    def _deliver(self, key: str, data: bytes, transmit: Callable[[bytes], object]) -> None:
        transmit(data)
        self._db.execute("UPDATE commands SET sent=1 WHERE command_key=?", (key,))

    def send(self, request: gate.DecideRequest, transmit: Callable[[bytes], object]) -> None:
        """Pin, persist, then transmit the encoded request (the gate deduplicates by command key)."""
        data = gate.encode_decide_request(request)
        self.pin(request.tenant_id, request.program_id, request.payment_id, request.member_key, (request.command_key, data))
        if not self._db.execute("SELECT sent FROM commands WHERE command_key=?", (request.command_key,)).fetchone()[0]:
            self._deliver(request.command_key, data, transmit)

    def resend(self, transmit: Callable[[bytes], object]) -> None:
        """Re-transmit the commands a crash left unsent, in order."""
        for key, data in self._db.execute("SELECT command_key, request FROM commands WHERE sent=0 ORDER BY rowid").fetchall():
            self._deliver(key, data, transmit)

    def install_cert(self, cert: bytes) -> None:
        """Keep a KEY-CERT as received; Lean installs it, or ignores it, wherever it is used."""
        self._db.execute("INSERT OR IGNORE INTO certs VALUES(?)", (cert,))

    def _all(self, column: str, table: str) -> bytes:
        return _list([signer.framed(row[0]) for row in self._db.execute(f"SELECT {column} FROM {table} ORDER BY rowid")])

    def store_checkpoint(self, signed: bytes) -> str:
        """``stored``, or ``fork`` when it forks a stored checkpoint (the pair is recorded and it is not stored)."""
        info = signer.gate_verify(2, signer.framed(signed)).split()
        if info[0] != "GATE_VERIFY=INDEX":
            raise GatePayerError("checkpoint_rejected")
        tenant = bytes.fromhex(info[1]).decode("ascii")
        shard, epoch, low, high = map(int, info[2:6])
        digest, prev = bytes.fromhex(info[6]), bytes.fromhex(info[7])
        candidates = [signer.framed(row[0]) for row in self._db.execute(
            "SELECT signed FROM checkpoints WHERE tenant=? AND shard=? AND epoch=? AND "
            "(seq_from<=? AND seq_to>=? OR digest=? OR prev=?)", (tenant, shard, epoch, high + 1, low - 1, prev, digest))]
        frame = (self._roots.get(tenant, bytes(gate.ML_DSA_87_PUBLIC_KEY)) + self._all("cert", "certs") + _list(candidates)
                 + self._all("stored", "forks") + signer.framed(signed))
        answer = signer.gate_verify(3, frame).split()
        if answer[0] == "GATE_VERIFY=STORED":
            self._db.execute("INSERT OR IGNORE INTO checkpoints VALUES(?,?,?,?,?,?,?,?)",
                             (digest, tenant, shard, epoch, low, high, prev, signed))
            return "stored"
        if answer[0] != "GATE_VERIFY=FORK":
            raise GatePayerError("checkpoint_rejected")
        stored = self._db.execute("SELECT signed FROM checkpoints WHERE digest=?", (bytes.fromhex(answer[1]),)).fetchone()[0]
        self._db.execute("INSERT INTO forks(stored, forking) VALUES(?,?)", (stored, signed))
        return "fork"

    def _decide(self, request: gate.DecideRequest, token: bytes, now: int) -> str | None:
        """None when Lean RELEASE accepts, else why not."""
        key = (request.tenant_id, request.program_id, request.payment_id)
        pin = self._db.execute("SELECT member_key FROM pins WHERE tenant=? AND program=? AND payment_id=?", key).fetchone()
        released = self._db.execute("SELECT 1 FROM releases WHERE tenant=? AND program=? AND payment_id=?", key).fetchone()
        checkpoint = self._db.execute("SELECT signed FROM checkpoints WHERE digest=?", (token[-gate.DIGEST :],)).fetchone()
        frame = (self._roots.get(request.tenant_id, bytes(gate.ML_DSA_87_PUBLIC_KEY)) + self._all("cert", "certs")
                 + self._all("stored", "forks") + signer.framed(checkpoint[0] if checkpoint else b"") + now.to_bytes(8, "big")
                 + self._grants + bytes([bool(released), bool(pin)]) + (pin[0] if pin else b"")
                 + signer.framed(gate.encode_decide_request(request)) + signer.framed(token))
        try:
            answer = signer.gate_verify(4, frame)
        except signer.GateSignerError:
            return "verifier_error"
        if answer == signer.ACCEPT:
            return None
        return answer.removeprefix("GATE_VERIFY=HOLD ") if answer.startswith("GATE_VERIFY=HOLD ") else "verifier_error"

    def release(self, request: gate.DecideRequest, token: bytes, *, now: int) -> str | None:
        """Release the payment (its instruction is the ``releases`` row) if Lean accepts; else record a hold and
        return its reason.  Both signatures are re-verified here, at every release."""
        reason = self._decide(request, token, now)
        with self._tx():
            if reason is None:
                self._db.execute("INSERT INTO releases VALUES(?,?,?,?,?,?,?,?)", (
                    request.tenant_id, request.program_id, request.payment_id, token, request.payee_ref,
                    request.amount_cents, request.period, now))
            else:
                self._db.execute("INSERT INTO holds(payment_id, token, reason, at) VALUES(?,?,?,?)",
                                 (request.payment_id, token, reason, now))
        return reason

    def holds(self) -> list[tuple[str, str]]:
        return self._db.execute("SELECT payment_id, reason FROM holds ORDER BY id").fetchall()

    def close(self) -> None:
        self._db.close()
