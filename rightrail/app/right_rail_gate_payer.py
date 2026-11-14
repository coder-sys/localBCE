"""A reference payer for the gate, on SQLite: pin before send, Lean decides every release.  Synthetic,
activation=false; a payer may build its own adapter, with the gate vectors as the conformance test.

Every table is append-only by schema triggers; ``commands.sent`` alone changes, once, from 0 to 1.
``send`` records the payment's member-key pin and its unsent command in one transaction and only then
transmits, so a kill leaves a pin and no sent command.  Python decodes nothing and decides nothing: the pinned
Lean ``gate_verify`` decodes a checkpoint (INDEX), decides whether it is stored or forks the stored ones
(STORE; a recorded fork stops its shard in every epoch) and whether a token may be released (RELEASE, ``firstFailure`` on the state this adapter loads).
Lean INSTALL gives each certificate its role.  A frame carries only the witnesses of its tenant, shards and epochs (Lean
``select`` and ``selectForks``, mirrored clause for clause by ``_WITNESSES`` and ``_FORK_WITNESSES``), which decide as the
whole history does (``select_decides``, ``forks_witness``), so no frame grows with the store and the store has no count limit.
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
    "commands": "tenant TEXT NOT NULL, program TEXT NOT NULL, command_key TEXT NOT NULL, request BLOB NOT NULL, sent INTEGER NOT NULL DEFAULT 0, "
                "PRIMARY KEY(tenant, program, command_key)",
    "refusals": "id INTEGER PRIMARY KEY, tenant TEXT NOT NULL, program TEXT NOT NULL, payment_id TEXT NOT NULL, member_key BLOB NOT NULL",
    # Each certificate Lean INSTALL kept, with the role it answered; SAME and REFUSED change nothing and write no row.
    "certs": "id INTEGER PRIMARY KEY, tenant TEXT NOT NULL, epoch INTEGER NOT NULL, "
             "role TEXT NOT NULL CHECK(role IN ('INSTALLED','EQUIVOCATES','FENCE_ONLY')), body_sha3_512 BLOB NOT NULL, "
             "cert BLOB NOT NULL, UNIQUE(tenant, epoch, role, body_sha3_512)",
    # The root key each tenant's roles were answered under: one per tenant, forever.
    "roots": "tenant TEXT PRIMARY KEY, root BLOB NOT NULL",
    "checkpoints": "digest BLOB PRIMARY KEY, tenant TEXT, shard INTEGER, epoch INTEGER, seq_from INTEGER, seq_to INTEGER, "
                   "prev BLOB, signed BLOB, counter INTEGER NOT NULL",
    # tenant, shard and epoch_stored are the stored side's, epoch_forking the forking side's (both from INDEX).
    "forks": "id INTEGER PRIMARY KEY, tenant TEXT NOT NULL, stored BLOB NOT NULL, forking BLOB NOT NULL, shard INTEGER NOT NULL, "
             "epoch_stored INTEGER NOT NULL, epoch_forking INTEGER NOT NULL, UNIQUE(tenant, stored, forking)",
    # closed is created before releases, so a first open cut short can never leave releases without closed
    "closed": "tenant TEXT, program TEXT, payment_id TEXT, outcome TEXT NOT NULL CHECK(outcome IN ('RELEASED','DENIED')), "
              "ref TEXT NOT NULL, closed_at INTEGER NOT NULL, PRIMARY KEY(tenant, program, payment_id)",
    "releases": "tenant TEXT, program TEXT, payment_id TEXT, token BLOB NOT NULL, payee_ref TEXT NOT NULL, "
                "amount_cents INTEGER NOT NULL, period TEXT NOT NULL, at INTEGER NOT NULL, PRIMARY KEY(tenant, program, payment_id)",
    "holds": "id INTEGER PRIMARY KEY, tenant TEXT NOT NULL, program TEXT NOT NULL, payment_id TEXT NOT NULL, token BLOB NOT NULL, "
             "reason TEXT NOT NULL, at INTEGER NOT NULL",
}
_SCHEMA: Final = [statement for name, columns in _TABLES.items() for statement in (
    f"CREATE TABLE IF NOT EXISTS {name}({columns})", *(
        f"CREATE TRIGGER IF NOT EXISTS {name}_{verb.lower()} BEFORE {verb} ON {name} {when}"
        "BEGIN SELECT RAISE(ABORT, 'append_only'); END"
        for verb, when in (("UPDATE", "WHEN OLD.sent=1 OR NEW.sent!=1 OR NEW.tenant IS NOT OLD.tenant OR NEW.program IS NOT "
                                      "OLD.program OR NEW.command_key IS NOT OLD.command_key OR NEW.request IS NOT OLD.request "
                                      if name == "commands" else ""), ("DELETE", ""))))] + [
    f"CREATE INDEX IF NOT EXISTS {name} ON {columns}" for name, columns in (
        ("checkpoints_counter", "checkpoints(tenant, shard, counter)"),
        ("checkpoints_seq_to", "checkpoints(tenant, shard, epoch, seq_to)"),
        ("checkpoints_prev", "checkpoints(tenant, shard, epoch, prev)"),
        ("checkpoints_newest", "checkpoints(tenant, shard, epoch DESC, seq_to DESC, digest)"),
        # one per witness clause, each a seek to its first row (the rowid follows the equality columns)
        ("certs_first", "certs(tenant, role)"), ("certs_top", "certs(tenant, epoch)"), ("certs_role", "certs(tenant, role, epoch)"),
        ("forks_shard", "forks(tenant, shard)"), ("forks_stored", "forks(tenant, epoch_stored)"),
        ("forks_forking", "forks(tenant, epoch_forking)"))]


_INT_MAX: Final = 2**63 - 1
# Lean ``candidate``, one indexed lookup per clause (checkpoints_counter, _seq_to, the digest key, _prev); the rows in insertion order.
_CANDIDATES: Final = (
    "SELECT signed FROM checkpoints WHERE rowid IN ("
    "SELECT rowid FROM checkpoints WHERE tenant=? AND shard=? AND counter BETWEEN ? AND ? "
    "UNION SELECT rowid FROM checkpoints WHERE tenant=? AND shard=? AND epoch=? AND seq_to>=? AND seq_from<=? "
    "UNION SELECT rowid FROM checkpoints WHERE tenant=? AND shard=? AND epoch=? AND prev=? "
    "UNION SELECT rowid FROM checkpoints WHERE tenant=? AND shard=? AND epoch=? AND digest=?) ORDER BY rowid")
# Lean ``select`` for tenant :t and epochs [:e] (none when :e is NULL), clause for clause: the tenant's first INSTALLED row;
# the first of its rows at its highest epoch (its fence); the epoch's first INSTALLED and first EQUIVOCATES row.
_WITNESSES: Final = (
    "SELECT cert FROM certs WHERE id IN ("
    "SELECT min(id) FROM certs WHERE tenant=:t AND role='INSTALLED' "
    "UNION SELECT min(id) FROM certs WHERE tenant=:t AND epoch=(SELECT max(epoch) FROM certs WHERE tenant=:t) "
    "UNION SELECT min(id) FROM certs WHERE tenant=:t AND role='INSTALLED' AND epoch=:e "
    "UNION SELECT min(id) FROM certs WHERE tenant=:t AND role='EQUIVOCATES' AND epoch=:e) ORDER BY id")
# Lean ``selectForks`` for tenant :t, shards [:s] and epochs [:e]: the first fork on the shard, the first whose stored
# side is in the epoch and the first whose forking side is.
_FORK_WITNESSES: Final = (
    "SELECT stored, forking FROM forks WHERE id IN ("
    "SELECT min(id) FROM forks WHERE tenant=:t AND shard=:s "
    "UNION SELECT min(id) FROM forks WHERE tenant=:t AND epoch_stored=:e "
    "UNION SELECT min(id) FROM forks WHERE tenant=:t AND epoch_forking=:e) ORDER BY id")

MAX_CERT_BYTES = 8 * 1024  # Lean `maxKeyCertBytes`
_ROLES: Final = ("INSTALLED", "SAME", "EQUIVOCATES", "FENCE_ONLY", "REFUSED")


class GatePayerError(RuntimeError):
    """A payment's member key changed, or a checkpoint was refused."""


def _list(items: Sequence[bytes]) -> bytes:
    return len(items).to_bytes(2, "big") + b"".join(items)


def _blob(data: bytes) -> bytes:
    return len(data).to_bytes(2, "big") + data


def _index(signed: bytes) -> tuple[str, int, int, int, int, bytes, bytes, int]:
    """Lean INDEX of a signed checkpoint: tenant, shard, epoch, seq_from, seq_to, digest, prev and counter."""
    info = signer.gate_verify(2, signer.framed(signed)).split()
    if info[0] != "GATE_VERIFY=INDEX":
        raise GatePayerError("checkpoint_rejected")
    shard, epoch, low, high, counter = map(int, (*info[2:6], info[8]))
    if max(shard, epoch, high, counter) > _INT_MAX:  # SQLite holds 63 bits: a bigger value cannot be stored or looked up
        raise GatePayerError("checkpoint_out_of_range")
    return bytes.fromhex(info[1]).decode("ascii"), shard, epoch, low, high, bytes.fromhex(info[6]), bytes.fromhex(info[7]), counter


class PayerStore:
    def __init__(self, path: Path | str, *, root_keys: Mapping[str, bytes],
                 grants: Sequence[tuple[str, bytes, Sequence[bytes], Sequence[bytes]]]) -> None:
        self._roots, grants = dict(root_keys), tuple(grants)  # grants is walked twice
        for tenant, *_ in grants: gate._Writer(b"").ident(tenant, "grant_tenant")  # a canonical ident, refused before any write
        self._grants = _list([_blob(t.encode()) + _blob(g) + _list([*map(_blob, rs)]) + _list([*map(_blob, es)]) for t, g, rs, es in grants])
        self._db = sqlite3.connect(path, isolation_level=None, timeout=60)  # Lean may hold the write lock up to 30 s
        self._db.execute("PRAGMA synchronous=FULL")
        info = {table: self._db.execute(f"PRAGMA table_info({table})").fetchall()
                for table in ("checkpoints", "forks", "certs", "holds", "refusals", "commands", "releases", "closed")}
        cols = {table: [row[1] for row in rows] for table, rows in info.items()}
        unique = any(row[2] for row in self._db.execute("PRAGMA index_list(forks)"))
        # A store from before a column, the per-tenant unique forks, required command owners, or ``closed``: refused before
        # any write, never migrated (a NULL would hide forks or leave a command no one resends; an unclosed release would
        # reopen its payment)
        if (cols["checkpoints"] and "counter" not in cols["checkpoints"]) or (cols["forks"] and (
                "tenant" not in cols["forks"] or "shard" not in cols["forks"] or not unique)) or (
                cols["certs"] and "role" not in cols["certs"]) or any(
                cols[table] and "tenant" not in cols[table] for table in ("holds", "refusals", "commands")) or any(
                row[1] == "tenant" and not row[3] for row in info["commands"]) or (
                cols["releases"] and (not cols["closed"] or self._db.execute(
                    "SELECT 1 FROM releases r WHERE NOT EXISTS(SELECT 1 FROM closed c WHERE c.tenant=r.tenant AND "
                    "c.program=r.program AND c.payment_id=r.payment_id) LIMIT 1").fetchone())):
            self._db.close()
            raise GatePayerError("store_version")
        for statement in _SCHEMA:
            self._db.execute(statement)
        # A tenant's rows hold only under the root they were answered under (Lean `select_decides`, one root per tenant)
        for tenant, root in self._db.execute("SELECT tenant, root FROM roots").fetchall():
            if self._roots.get(tenant, root) != root:
                self._db.close()
                raise GatePayerError(f"root_changed: {tenant}")

    @contextlib.contextmanager
    def _tx(self) -> Iterator[None]:
        self._db.execute("BEGIN IMMEDIATE")
        try:
            yield
            self._db.execute("COMMIT")  # a COMMIT that fails (busy) rolls back and raises: no half-open transaction
        except BaseException as fault:
            try:
                self._db.execute("ROLLBACK")
            except sqlite3.Error as rollback:  # a failed COMMIT may already have ended the transaction: keep the first error
                raise fault from rollback
            raise

    def pin(self, tenant: str, program: str, payment_id: str, member_key: bytes,
            command: tuple[str, bytes] | None = None) -> None:
        """Pin the payment's member key at first sight and store its command, unsent, in the same transaction;
        another key is recorded as a refusal and raises ``member_key_changed``, whatever its command key. Otherwise,
        reusing a command key of the same tenant and program with different canonical bytes raises ``command_conflict``
        before any pin or command changes; another tenant's or program's command key is its own."""
        with self._tx():
            held = self._db.execute("SELECT member_key FROM pins WHERE tenant=? AND program=? AND payment_id=?",
                                    (tenant, program, payment_id)).fetchone()
            changed = held is not None and held[0] != member_key
            if changed:
                self._db.execute("INSERT INTO refusals(tenant, program, payment_id, member_key) VALUES(?,?,?,?)",
                                 (tenant, program, payment_id, member_key))
            else:
                if command is not None:
                    prior = self._db.execute("SELECT request FROM commands WHERE tenant=? AND program=? AND command_key=?",
                                             (tenant, program, command[0])).fetchone()
                    if prior is not None and prior[0] != command[1]:
                        raise GatePayerError("command_conflict")
                self._db.execute("INSERT OR IGNORE INTO pins VALUES(?,?,?,?)", (tenant, program, payment_id, member_key))
                if command:
                    self._db.execute("INSERT OR IGNORE INTO commands(tenant, program, command_key, request) VALUES(?,?,?,?)",
                                     (tenant, program, *command))
        if changed:
            raise GatePayerError("member_key_changed")

    def _deliver(self, key: tuple[str, str, str], data: bytes, transmit: Callable[[bytes], object]) -> None:
        """Transmit, then mark the command under ``key`` (tenant, program, command key) sent."""
        transmit(data)
        with self._tx():
            # Another connection may have delivered the same durable command while this callback ran.
            self._db.execute("UPDATE commands SET sent=1 WHERE tenant=? AND program=? AND command_key=? AND request=? AND sent=0",
                             (*key, data))

    def send(self, request: gate.DecideRequest, transmit: Callable[[bytes], object]) -> None:
        """Pin, persist, then transmit the encoded request (the gate deduplicates by command key)."""
        data = gate.encode_decide_request(request)
        self.pin(request.tenant_id, request.program_id, request.payment_id, request.member_key, (request.command_key, data))
        key = (request.tenant_id, request.program_id, request.command_key)
        row = self._db.execute("SELECT sent FROM commands WHERE tenant=? AND program=? AND command_key=?", key).fetchone()
        if row is None:  # the pin above stores it; a store that lost it must not look sent
            raise GatePayerError("command_missing")
        if not row[0]:
            self._deliver(key, data, transmit)

    def resend(self, transmit: Callable[[bytes], object]) -> None:
        """Re-transmit the commands a crash left unsent, in order."""
        for *key, data in self._db.execute(
                "SELECT tenant, program, command_key, request FROM commands WHERE sent=0 ORDER BY rowid").fetchall():
            self._deliver(tuple(key), data, transmit)

    def install_cert(self, cert: bytes) -> str:
        """Lean INSTALL's role for a KEY-CERT: ``INSTALLED``, ``SAME`` (a re-signature or replay: no effect, no row),
        ``EQUIVOCATES`` (blocks its tenant and epoch) or ``FENCE_ONLY`` (raises its tenant's fence).  A cert that Lean
        cannot decode raises ``cert_rejected``, one that is not root-signed ``cert_refused``; neither writes a row.  Lean
        answers on the tenant's witnesses for the cert's epoch, which decide as its whole history (``install_classifies``),
        so the cost of an install, and of every frame, does not grow with the store."""
        if len(cert) > MAX_CERT_BYTES:
            raise GatePayerError("cert_too_large")
        with self._tx():  # the witnesses, Lean's answer and the row under one write lock: two installs never both see an empty epoch
            role = self._install(cert)[1]
        if role == "REFUSED":
            raise GatePayerError("cert_refused")
        return role

    def _install(self, cert: bytes) -> tuple[str, str]:
        """The cert's tenant and Lean role, and its row if the role is kept; the caller holds the write lock."""
        info = signer.gate_verify(9, signer.framed(cert)).split()
        if info[0] != "GATE_VERIFY=CERT-INDEX":
            raise GatePayerError("cert_rejected")
        tenant, epoch, body = bytes.fromhex(info[1]).decode("ascii"), int(info[2]), bytes.fromhex(info[3])
        if epoch > _INT_MAX:
            raise GatePayerError("cert_out_of_range")
        root = self._roots.get(tenant, bytes(gate.ML_DSA_87_PUBLIC_KEY))
        pinned = self._db.execute("SELECT root FROM roots WHERE tenant=?", (tenant,)).fetchone()
        if pinned and pinned[0] != root:  # another connection opened with another root for this tenant
            raise GatePayerError(f"root_changed: {tenant}")
        role = signer.gate_verify(8, root + self._witnesses(tenant, epoch) + signer.framed(cert)).removeprefix("GATE_VERIFY=CERT ")
        if role not in _ROLES:
            raise GatePayerError("cert_rejected")
        if role in ("INSTALLED", "EQUIVOCATES", "FENCE_ONLY"):  # Lean `Role.kept`
            if not pinned:
                self._db.execute("INSERT INTO roots VALUES(?,?)", (tenant, root))
            # An exact duplicate (a replayed equivocation or fence-only cert) is never the first of any clause: no row.
            self._db.execute("INSERT INTO certs(tenant, epoch, role, body_sha3_512, cert) VALUES(?,?,?,?,?) "
                             "ON CONFLICT(tenant, epoch, role, body_sha3_512) DO NOTHING", (tenant, epoch, role, body, cert))
        return tenant, role

    def _witnesses(self, tenant: str, epoch: int | None) -> bytes:
        """The tenant's certificate witnesses for ``epoch`` (Lean ``select``), framed for a STORE, RELEASE or INSTALL frame."""
        return _list([signer.framed(row[0]) for row in self._db.execute(_WITNESSES, {"t": tenant, "e": epoch})])

    def _fork_witnesses(self, tenant: str | None, shard: int | None, epoch: int | None) -> bytes:
        """The fork witnesses for the checkpoint's tenant, shard and epoch (Lean ``selectForks``), each its stored side
        then its forking one: no other tenant's fork, shard or epoch can bind it (``forks_witness``)."""
        return _list([signer.framed(a) + signer.framed(b) for a, b in self._db.execute(
            _FORK_WITNESSES, {"t": tenant, "s": shard, "e": epoch})])

    def store_checkpoint(self, signed: bytes) -> str:
        """``stored``, or ``fork`` when it forks a stored checkpoint (the pair is recorded and it is not stored).  Once a
        shard has a recorded fork, nothing of it is stored, in any epoch.  The candidates are the shard's checkpoints whose
        counter is within one of the new one's, and, in its epoch, those touching or linked to it (Lean ``candidate``)."""
        tenant, shard, epoch, low, high, digest, prev, counter = _index(signed)
        with self._tx():  # the candidates, Lean's answer and the write under one write lock: two forks never both store
            candidates = [signer.framed(row[0]) for row in self._db.execute(_CANDIDATES, (
                tenant, shard, counter - 1, min(counter + 1, _INT_MAX), tenant, shard, epoch, low - 1, min(high + 1, _INT_MAX),
                tenant, shard, epoch, digest, tenant, shard, epoch, prev))]
            frame = (self._roots.get(tenant, bytes(gate.ML_DSA_87_PUBLIC_KEY)) + self._witnesses(tenant, epoch) + _list(candidates)
                     + self._fork_witnesses(tenant, shard, epoch) + signer.framed(signed))
            answer = signer.gate_verify(3, frame).split()
            if answer[0] == "GATE_VERIFY=STORED":
                self._db.execute("INSERT OR IGNORE INTO checkpoints VALUES(?,?,?,?,?,?,?,?,?)",
                                 (digest, tenant, shard, epoch, low, high, prev, signed, counter))
                return "stored"
            if answer[0] != "GATE_VERIFY=FORK":
                raise GatePayerError("checkpoint_rejected")
            # the stored side's tenant, shard and epoch, as INDEX gave them when it was stored
            stored = self._db.execute("SELECT signed, tenant, shard, epoch FROM checkpoints WHERE digest=?",
                                      (bytes.fromhex(answer[1]),)).fetchone()
            self._db.execute("INSERT INTO forks(tenant, stored, forking, shard, epoch_stored, epoch_forking) VALUES(?,?,?,?,?,?) "
                             "ON CONFLICT(tenant, stored, forking) DO NOTHING",  # a replay adds no row
                             (stored[1], stored[0], signed, stored[2], stored[3], epoch))
            return "fork"

    def _decide(self, request: gate.DecideRequest, token: bytes, now: int) -> str | None:
        """None when Lean RELEASE accepts, else why not."""
        data = gate.encode_decide_request(request)  # before any lookup: refuses, typed, what SQLite cannot bind
        key =(request.tenant_id, request.program_id, request.payment_id)
        pin = self._db.execute("SELECT member_key FROM pins WHERE tenant=? AND program=? AND payment_id=?", key).fetchone()
        sent = self._db.execute("SELECT 1 FROM commands WHERE tenant=? AND program=? AND command_key=? AND request=? AND sent=1",
                                (*key[:2], request.command_key, data)).fetchone()
        if not sent:
            pin = None  # A pin alone is not evidence that this exact command was sent.
        released = self._db.execute("SELECT 1 FROM releases WHERE tenant=? AND program=? AND payment_id=?", key).fetchone()
        # the token's checkpoint and its tenant, shard and epoch: the witnesses are those of its items (no checkpoint, none)
        signed, tenant, shard, epoch = self._db.execute("SELECT signed, tenant, shard, epoch FROM checkpoints WHERE digest=?",
                                                        (token[-gate.DIGEST :],)).fetchone() or (b"", None, None, None)
        frame = (self._roots.get(request.tenant_id, bytes(gate.ML_DSA_87_PUBLIC_KEY)) + self._witnesses(request.tenant_id, epoch)
                 + self._fork_witnesses(tenant, shard, epoch) + signer.framed(signed) + now.to_bytes(8, "big")
                 + self._grants + bytes([bool(released), bool(pin)]) + (pin[0] if pin else b"")
                 + signer.framed(data) + signer.framed(token))
        try:
            answer = signer.gate_verify(5, frame)
        except signer.GateSignerError:
            return "verifier_error"
        if answer == signer.ACCEPT:
            return None
        return answer.removeprefix("GATE_VERIFY=HOLD ") if answer.startswith("GATE_VERIFY=HOLD ") else "verifier_error"

    def release(self, request: gate.DecideRequest, token: bytes, *, now: int) -> str | None:
        """Release the payment (its instruction is the ``releases`` row) if Lean accepts; else record a hold and
        return its reason.  Both signatures are re-verified here, at every release."""
        if not 0 <= now <= gate.MAX_NAT:  # the frame's u64 and the store's INTEGER both hold it
            raise GatePayerError("now_out_of_range")
        with self._tx():  # the whole decision under one write lock: no read-then-write window
            reason = self._decide(request, token, now)
            if reason is None:
                try:  # the used-set's primary key is the only guard against a second release of this key
                    self._db.execute("INSERT INTO closed VALUES(?,?,?,'RELEASED',?,?)", (
                        request.tenant_id, request.program_id, request.payment_id, request.payee_ref, now))
                except sqlite3.IntegrityError:
                    reason = "already_closed"
                else:  # an IntegrityError here means closed and releases disagree: it propagates, the transaction rolls back
                    self._db.execute("INSERT INTO releases VALUES(?,?,?,?,?,?,?,?)", (
                        request.tenant_id, request.program_id, request.payment_id, token, request.payee_ref,
                        request.amount_cents, request.period, now))
            if reason is not None:  # every refusal is exactly one hold row and nothing else
                self._db.execute("INSERT INTO holds(tenant, program, payment_id, token, reason, at) VALUES(?,?,?,?,?,?)",
                                 (request.tenant_id, request.program_id, request.payment_id, token, reason, now))
        return reason

    def holds(self) -> list[tuple[str, str, str, str]]:
        """Every hold in order: (tenant, program, payment id, reason)."""
        return self._db.execute("SELECT tenant, program, payment_id, reason FROM holds ORDER BY id").fetchall()

    def newest_stored(self, tenant: str) -> dict[int, bytes]:
        """The registry boot anchor (B2): per shard, the digest of the stored checkpoint with the highest epoch, then the
        highest seq_to.  A tie (two at one epoch and seq_to; ``store_checkpoint`` records a fork instead of storing it)
        goes to the lowest digest bytes, so the answer never depends on row order."""
        # Seek the next shard, then its newest row. DISTINCT/GROUP BY would still walk its entire history.
        return dict(self._db.execute(
            "WITH RECURSIVE shards(shard) AS ("
            "SELECT MIN(shard) FROM checkpoints WHERE tenant=? UNION ALL "
            "SELECT (SELECT MIN(shard) FROM checkpoints WHERE tenant=? AND shard>shards.shard) "
            "FROM shards WHERE shard IS NOT NULL) "
            "SELECT shard, (SELECT digest FROM checkpoints WHERE tenant=? AND shard=shards.shard "
            "ORDER BY epoch DESC, seq_to DESC, digest LIMIT 1) FROM shards WHERE shard IS NOT NULL",
            (tenant, tenant, tenant)))

    def close(self) -> None:
        self._db.close()
