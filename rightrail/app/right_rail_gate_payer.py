"""A reference payer for the gate, on SQLite: pin before send, Lean decides every release.  Synthetic,
activation=false; a payer may build its own adapter, with the gate vectors as the conformance test.

Every table is append-only by schema triggers; ``commands.sent`` alone changes, once, from 0 to 1.
``send`` records the payment's member-key pin and its unsent command in one transaction and only then
transmits, so a kill leaves a pin and no sent command.  Python decodes nothing and decides nothing: the pinned
Lean ``gate_verify`` decodes a checkpoint (INDEX), decides whether it is stored or forks the stored ones
(STORE; a recorded fork stops its shard in every epoch) and whether a token may be released (RELEASE, ``firstFailure`` on the state this adapter loads).
Lean LINK answers each authority link (``Cosign.installLink``) and INSTALL each certificate (``Cosign.install``); the
store keeps every link, recorded link conflict and recorded certificate with its answer.  A frame carries only the
witnesses of its tenant, shards and epochs (Lean ``select``, ``selectFence``, ``selectConflict``, ``selectInstall`` and
``selectForks``, mirrored clause for clause by the SQL below), which decide as the whole history does (``select_decides``,
``install_classifies``, ``forks_witness``), so no frame grows with the store and the store has no count limit.
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
    # Every authority link Lean LINK answered GENESIS or EXTENDS, keyed by digest, with the SHA3-512 of its two keys, its
    # two commitments and the last epoch it closes (NULL for none) (LINK-INDEX); a tenant's chain is its links of one base.
    "links": "digest BLOB PRIMARY KEY, tenant TEXT NOT NULL, gen INTEGER NOT NULL, base INTEGER NOT NULL, "
             "root_key BLOB NOT NULL, witness_key BLOB NOT NULL, root_next BLOB NOT NULL, witness_next BLOB NOT NULL, "
             "link BLOB NOT NULL, closed INTEGER, UNIQUE(tenant, gen)",
    # Every link Lean LINK answered CONFLICTS: a second successor in the chain of base ``base``; evidence that blocks it.
    "link_conflicts": "id INTEGER PRIMARY KEY, tenant TEXT NOT NULL, base INTEGER NOT NULL, gen INTEGER NOT NULL, "
                      "digest BLOB NOT NULL UNIQUE, link BLOB NOT NULL",
    # Each certificate Lean INSTALL recorded, with its answer, the link it names and the SHA3-512 of its two keys
    # (CERT-INDEX); SAME and refusals change nothing and write no row.
    "certs": "id INTEGER PRIMARY KEY, tenant TEXT NOT NULL, epoch INTEGER NOT NULL, "
             "role TEXT NOT NULL CHECK(role IN ('INSTALLED','EQUIVOCATES','UNFIT')), body_sha3_512 BLOB NOT NULL, "
             "link BLOB NOT NULL REFERENCES links(digest), epoch_key BLOB NOT NULL, verifier_key BLOB NOT NULL, "
             "cert BLOB NOT NULL, UNIQUE(tenant, epoch, role, body_sha3_512)",
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
        ("links_chain", "links(tenant, base, gen)"), ("link_conflicts_chain", "link_conflicts(tenant, base, gen)"),
        ("certs_top", "certs(tenant, epoch)"), ("certs_role", "certs(tenant, role, epoch)"), ("certs_body", "certs(body_sha3_512)"),
        ("certs_epoch_key", "certs(tenant, role, epoch_key)"), ("certs_verifier_key", "certs(tenant, role, verifier_key)"),
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
# Lean ``select`` for tenant :t and epochs [:e] (none when :e is NULL): the epoch's first INSTALLED and first EQUIVOCATES row.
_EPOCH: Final = ("SELECT min(id) FROM certs WHERE tenant=:t AND role='INSTALLED' AND epoch=:e "
                 "UNION SELECT min(id) FROM certs WHERE tenant=:t AND role='EQUIVOCATES' AND epoch=:e")
_WITNESSES: Final = f"SELECT cert, link FROM certs WHERE id IN ({_EPOCH}) ORDER BY id"
# Lean ``Cosign.ownedBy`` for the head's chain (base :b, head generation :hg; :lo and :top the first and last epoch of
# generations :b to :hg): the epoch's generation is the head's, or the next generation's link closes it at or above it.
_OWNED: Final = ("epoch BETWEEN :lo AND :top AND ((epoch >> 32)=:hg OR epoch<="
                 "(SELECT closed FROM links WHERE tenant=:t AND base=:b AND gen=(epoch >> 32) + 1))")
# Lean ``selectInstall`` for :t and :e: ``select`` and the INSTALLED rows of the nearest epoch below and above among those
# the head's chain owns (one it disowns is kept but decides no fit: ``Cosign.fits_neighbours``).
_INSTALL_WITNESSES: Final = (
    f"SELECT cert, link FROM certs WHERE id IN ({_EPOCH} "
    "UNION SELECT min(id) FROM certs WHERE tenant=:t AND role='INSTALLED' AND epoch="
    f"(SELECT max(epoch) FROM certs WHERE tenant=:t AND role='INSTALLED' AND epoch<:e AND {_OWNED}) "
    "UNION SELECT min(id) FROM certs WHERE tenant=:t AND role='INSTALLED' AND epoch="
    f"(SELECT min(epoch) FROM certs WHERE tenant=:t AND role='INSTALLED' AND epoch>:e AND {_OWNED})) ORDER BY id")
# Lean ``selectFence``: the first of the tenant's rows at its highest epoch, unless ``select`` already carries it.
_FENCE: Final = (
    "SELECT cert, link FROM certs WHERE id=(SELECT min(id) FROM certs WHERE tenant=:t AND epoch="
    "(SELECT max(epoch) FROM certs WHERE tenant=:t)) AND NOT (epoch IS :e AND role IN ('INSTALLED','EQUIVOCATES'))")
# Lean ``sameRow``: a row holding the body as INSTALLED or EQUIVOCATES.
_SAME: Final = "SELECT cert FROM certs WHERE body_sha3_512=? AND role IN ('INSTALLED','EQUIVOCATES') ORDER BY id LIMIT 1"
# The tenant's head link (the highest generation: a genesis is above every held link), and Lean ``selectConflict``: of the
# recorded conflicts of the head's chain, the lowest generation's first.
_HEAD: Final = "SELECT link, base, gen FROM links WHERE tenant=? ORDER BY gen DESC LIMIT 1"
_CONFLICT: Final = "SELECT link FROM link_conflicts WHERE tenant=? AND base=? ORDER BY gen, id LIMIT 1"
# Lean ``touches``: the tenant's links a key (by the SHA3-512 of its encoding) is, or is committed to become, a key of.
_TOUCHED: Final = ("SELECT link FROM links WHERE tenant=:t AND (root_key IN (:a, :b) OR witness_key IN (:a, :b) "
                   "OR root_next IN (:a, :b) OR witness_next IN (:a, :b)) ORDER BY gen")
# Lean ``certsApart`` fails exactly when an INSTALLED certificate of the tenant has a key among a new link's keys and
# commitments (:r :w :rn :wn); one such certificate per key column is enough to answer it.
_TOUCHING: Final = (
    "SELECT cert FROM certs WHERE id IN ("
    "SELECT min(id) FROM certs WHERE tenant=:t AND role='INSTALLED' AND epoch_key IN (:r, :w, :rn, :wn) "
    "UNION SELECT min(id) FROM certs WHERE tenant=:t AND role='INSTALLED' AND verifier_key IN (:r, :w, :rn, :wn)) ORDER BY id")
# Lean ``selectForks`` for tenant :t, shards [:s] and epochs [:e]: the first fork on the shard, the first whose stored
# side is in the epoch and the first whose forking side is.
_FORK_WITNESSES: Final = (
    "SELECT stored, forking FROM forks WHERE id IN ("
    "SELECT min(id) FROM forks WHERE tenant=:t AND shard=:s "
    "UNION SELECT min(id) FROM forks WHERE tenant=:t AND epoch_stored=:e "
    "UNION SELECT min(id) FROM forks WHERE tenant=:t AND epoch_forking=:e) ORDER BY id")

MAX_CERT_BYTES = gate.MAX_KEY_CERT  # Lean `Cosign.maxCertBytes`
_RECORDED: Final = ("INSTALLED", "EQUIVOCATES", "UNFIT")  # Lean `Cosign.record`'s answers: each writes its row


class GatePayerError(RuntimeError):
    """A payment's member key changed, or a checkpoint was refused."""


def _list(items: Sequence[bytes]) -> bytes:
    return len(items).to_bytes(2, "big") + b"".join(items)


def _blob(data: bytes) -> bytes:
    return len(data).to_bytes(2, "big") + data


def _frames(items: Sequence[bytes]) -> bytes:
    return _list([*map(signer.framed, items)])


def _link_index(link: bytes) -> tuple[str, int, int, bytes, bytes, bytes, bytes, bytes, int | None]:
    """Lean LINK-INDEX of an AUTHORITY-LINK/v1: tenant, generation, base, digest, the SHA3-512 of its root and witness
    keys, its root and witness commitments, and the last epoch it closes (none for a genesis or a link closing none)."""
    info = signer.gate_verify(11, signer.framed(link)).split()
    if info[0] != "GATE_VERIFY=LINK-INDEX":
        raise GatePayerError("link_rejected")
    return (bytes.fromhex(info[1]).decode("ascii"), int(info[2]), int(info[3]), *map(bytes.fromhex, info[4:9]),
            None if info[9] == "-" else int(info[9]))


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
    def __init__(self, path: Path | str, *, links: Mapping[str, bytes],
                 grants: Sequence[tuple[str, bytes, Sequence[bytes], Sequence[bytes]]]) -> None:
        """``links``: the genesis AUTHORITY-LINK/v1 this payer is configured with for each tenant it serves.  Its digest
        is the tenant's genesis pin, and it is installed at open (Lean LINK: SAME or GENESIS, else ``link_refused``); then
        every stored link of the tenant is replayed, and the head's chain must start at that pin (``_recheck_links``).
        Later links arrive by ``install_link``.  A tenant with no configured link is not served (``no_link``)."""
        grants = tuple(grants)  # grants is walked twice
        for tenant, *_ in grants: gate._Writer(b"").ident(tenant, "grant_tenant")  # a canonical ident, refused before any write
        self._grants = _list([_blob(t.encode()) + _blob(g) + _list([*map(_blob, rs)]) + _list([*map(_blob, es)]) for t, g, rs, es in grants])
        self._db = sqlite3.connect(path, isolation_level=None, timeout=60)  # Lean may hold the write lock up to 30 s
        self._db.execute("PRAGMA synchronous=FULL")
        info = {table: self._db.execute(f"PRAGMA table_info({table})").fetchall()
                for table in ("checkpoints", "forks", "certs", "links", "holds", "refusals", "commands", "releases", "closed", "roots")}
        cols = {table: [row[1] for row in rows] for table, rows in info.items()}
        unique = any(row[2] for row in self._db.execute("PRAGMA index_list(forks)"))
        # A store from before a column, the per-tenant unique forks, required command owners, ``closed``, or the link chain
        # (one link per tenant, no certificate keys, no closing epoch per link): refused before any write, never migrated (a NULL would hide forks or
        # leave a command no one resends; an unclosed release would reopen its payment; a certificate row without the link
        # it names cannot be re-verified)
        if cols["roots"] or (cols["checkpoints"] and "counter" not in cols["checkpoints"]) or (cols["forks"] and (
                "tenant" not in cols["forks"] or "shard" not in cols["forks"] or not unique)) or (
                cols["certs"] and "epoch_key" not in cols["certs"]) or (cols["links"] and "closed" not in cols["links"]) or any(
                cols[table] and "tenant" not in cols[table] for table in ("holds", "refusals", "commands")) or any(
                row[1] == "tenant" and not row[3] for row in info["commands"]) or (
                cols["releases"] and (not cols["closed"] or self._db.execute(
                    "SELECT 1 FROM releases r WHERE NOT EXISTS(SELECT 1 FROM closed c WHERE c.tenant=r.tenant AND "
                    "c.program=r.program AND c.payment_id=r.payment_id) LIMIT 1").fetchone())):
            self._db.close()
            raise GatePayerError("store_version")
        self._db.execute("PRAGMA foreign_keys=ON")
        for statement in _SCHEMA:
            self._db.execute(statement)
        self._pins: dict[str, bytes] = {}
        try:
            for tenant, link in links.items():
                info = _link_index(link)
                if info[0] != tenant:
                    raise GatePayerError(f"link_refused: {tenant}")
                self._pins[tenant] = info[3]
                if self.install_link(link) not in ("SAME", "GENESIS"):
                    raise GatePayerError(f"link_refused: {tenant}")
                self._recheck_links(tenant)
        except BaseException:
            self._db.close()
            raise

    def _recheck_links(self, tenant: str) -> None:
        """Replay the stored links of ``tenant`` through Lean LINK: each chain from its genesis, link by link, answers GENESIS
        then EXTENDS; the head's chain is the last one and starts at the configured pin; and each recorded conflict of the
        head's chain answers CONFLICTS.  Otherwise ``link_refused``: whoever writes the file chooses neither the head, nor
        its chain, nor the conflicts, and every row's columns equal what Lean reads from its link bytes."""
        rows = self._db.execute("SELECT base, link, tenant, gen, base, digest, root_key, witness_key, root_next, witness_next, closed "
                                "FROM links WHERE tenant=? ORDER BY base, gen", (tenant,)).fetchall()
        pin, newest = self._pins[tenant], []  # newest: the chain being replayed, newest first
        for index, (base, link, *columns) in enumerate(rows):
            if columns != list(_link_index(link)):  # the columns that fits and witness queries follow must tell what the link says
                raise GatePayerError(f"link_refused: {tenant}")
            if index == 0 or rows[index - 1][0] != base:
                pin, newest = _link_index(link)[3], []  # a replaced chain's genesis was the pin of its time
            frame = pin + _frames(newest) + _list([]) + _frames([]) + _frames([]) + signer.framed(link)
            if signer.gate_verify(10, frame).removeprefix("GATE_VERIFY=LINK ") != ("EXTENDS" if newest else "GENESIS"):
                raise GatePayerError(f"link_refused: {tenant}")
            newest.insert(0, link)
        if not rows or pin != self._pins[tenant] or self._head(tenant)[1] != rows[-1][0]:
            raise GatePayerError(f"link_refused: {tenant}")
        if newest:  # the last chain replayed is the head's: each of its recorded conflicts answers CONFLICTS against it
            for (link,) in self._db.execute("SELECT link FROM link_conflicts WHERE tenant=? AND base=?", (tenant, rows[-1][0])).fetchall():
                frame = pin + _frames(newest) + _list([]) + _frames([]) + _frames([]) + signer.framed(link)
                if signer.gate_verify(10, frame).removeprefix("GATE_VERIFY=LINK ") != "CONFLICTS":
                    raise GatePayerError(f"link_refused: {tenant}")

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

    def install_link(self, link: bytes) -> str:
        """Lean LINK's answer for an AUTHORITY-LINK/v1 of a served tenant: ``SAME`` (held: no effect), ``GENESIS`` (a new
        chain under the tenant's configured pin; the old one stays as evidence and its keys never return), ``EXTENDS``,
        ``CONFLICTS`` (a second successor: recorded, it blocks its chain from its generation on) or ``STALE`` (a successor
        in a replaced chain: no effect).  A refused link raises ``link_refused``, one Lean cannot decode
        ``link_rejected``.  Lean reads every link of the tenant (a link install is rare), the recorded conflict of the new
        digest and an installed certificate of each key column that the new link's keys or commitments match."""
        tenant, gen, base, digest, *keys, closed = _link_index(link)
        with self._tx():
            head = self._head(tenant)
            chains: dict[int, list[bytes]] = {}  # each chain newest first, the newest chain first
            for held, held_base in self._db.execute("SELECT link, base FROM links WHERE tenant=? ORDER BY base DESC, gen DESC",
                                                    (tenant,)):
                chains.setdefault(held_base, []).append(held)
            present = chains.pop(head[1]) if head else []
            conflicts = [row[0] for row in self._db.execute("SELECT link FROM link_conflicts WHERE digest=?", (digest,))]
            certs = [row[0] for row in self._db.execute(_TOUCHING, dict(zip(("t", "r", "w", "rn", "wn"), (tenant, *keys))))]
            frame = (self._pins[tenant] + _frames(present) + _list([_frames(chain) for chain in chains.values()])
                     + _frames(conflicts) + _frames(certs) + signer.framed(link))
            answer = signer.gate_verify(10, frame).removeprefix("GATE_VERIFY=LINK ")
            if answer in ("GENESIS", "EXTENDS"):
                self._db.execute("INSERT INTO links VALUES(?,?,?,?,?,?,?,?,?,?)", (digest, tenant, gen, base, *keys, link, closed))
            elif answer == "CONFLICTS":
                self._db.execute("INSERT INTO link_conflicts(tenant, base, gen, digest, link) VALUES(?,?,?,?,?)",
                                 (tenant, base, gen, digest, link))
            elif answer not in ("SAME", "STALE"):
                raise GatePayerError(f"link_refused: {tenant}")
        return answer

    def install_cert(self, cert: bytes) -> str:
        """Lean INSTALL's answer for a KEY-CERT: ``INSTALLED``, ``SAME`` (its body is held: no effect, no row),
        ``EQUIVOCATES`` (another body than the installed one of its tenant and epoch: blocks them) or ``UNFIT`` (verified,
        but its shard counts do not extend its neighbours': it raises its tenant's fence only).  A cert that Lean cannot
        decode raises ``cert_rejected``, a refused one ``cert_refused: <Lean's reason>``; neither writes a row.  Lean answers on the
        tenant's witnesses for the cert's epoch, which decide as its whole history (``install_classifies``); how the cost
        of an install grows with the store is not measured."""
        if len(cert) > MAX_CERT_BYTES:
            raise GatePayerError("cert_too_large")
        info = signer.gate_verify(9, signer.framed(cert)).split()
        if info[0] != "GATE_VERIFY=CERT-INDEX":
            raise GatePayerError("cert_rejected")
        tenant, epoch = bytes.fromhex(info[1]).decode("ascii"), int(info[2])
        body, named, epoch_key, verifier_key = map(bytes.fromhex, info[3:7])
        if epoch > _INT_MAX:
            raise GatePayerError("cert_out_of_range")
        with self._tx():  # the witnesses, Lean's answer and the row under one write lock: two installs never both see an empty epoch
            head = self._head(tenant)
            # the head's chain's links of the cert's generation (Lean `Cosign.genOf`) and of the next
            own, after = (self._db.execute("SELECT link FROM links WHERE tenant=? AND base=? AND gen=?", (tenant, head[1], g)).fetchone()
                          for g in ((epoch >> 32), (epoch >> 32) + 1))
            touched = [row[0] for row in self._db.execute(_TOUCHED, {"t": tenant, "a": epoch_key, "b": verifier_key})]
            same = self._db.execute(_SAME, (body,)).fetchone()
            frame = (b"".join(signer.framed(row[0] if row else b"") for row in (head, own, after)) + _frames(touched)
                     + signer.framed(same[0] if same else b"")
                     + self._carried(self._witnesses(_INSTALL_WITNESSES, {"t": tenant, "e": epoch, "b": head[1], "hg": head[2],
                                                                          "lo": head[1] << 32, "top": ((head[2] + 1) << 32) - 1}))
                     + signer.framed(cert))
            answer = signer.gate_verify(8, frame).removeprefix("GATE_VERIFY=CERT ")
            if answer in _RECORDED:
                # Lean's ``same`` never names an UNFIT row, so a re-signature of an UNFIT body is answered UNFIT again: its
                # fence is already held, and its row is kept once.
                self._db.execute(f"INSERT{' OR IGNORE' if answer == 'UNFIT' else ''} INTO certs(tenant, epoch, role, body_sha3_512, "
                                 "link, epoch_key, verifier_key, cert) VALUES(?,?,?,?,?,?,?,?)",
                                 (tenant, epoch, answer, body, named, epoch_key, verifier_key, cert))
            elif answer == "UNKNOWN_TENANT":
                raise GatePayerError(f"no_link: {tenant}")
            elif answer != "SAME":
                raise GatePayerError(f"cert_refused: {answer.removeprefix('REFUSED ')}")
        return answer

    def _head(self, tenant: str) -> tuple[bytes, int, int] | None:
        """The served tenant's head link, its chain's base and its generation (none only while its configured link is installed at open); a
        tenant with no configured link is ``no_link``, and nothing of it is installed or stored."""
        if tenant not in self._pins:
            raise GatePayerError(f"no_link: {tenant}")
        return self._db.execute(_HEAD, (tenant,)).fetchone()

    def _witnesses(self, sql: str, args: Mapping[str, object]) -> list[tuple[bytes, bytes]]:
        """The certificate witnesses ``sql`` picks: each certificate and the digest of the link it names."""
        return self._db.execute(sql, args).fetchall()

    def _carried(self, rows: Sequence[tuple[bytes, bytes]], fence: Sequence[tuple[bytes, bytes]] = ()) -> bytes:
        """The links the certificates name, then the certificates, framed: Lean verifies each certificate under its link."""
        named = [self._db.execute("SELECT link FROM links WHERE digest=?", (d,)).fetchone()[0]
                 for d in dict.fromkeys(d for _, d in (*rows, *fence))]
        return _frames(named) + _frames([c for c, _ in rows])

    def _authority(self, tenant: str, epoch: int | None) -> bytes:
        """A STORE or RELEASE frame's authority part for the tenant and epoch (none: no epoch's witnesses): the head link,
        the carried link conflict (Lean ``selectConflict``), the certificate witnesses with the links they name, and the
        fence certificate (``selectFence``)."""
        head = self._head(tenant)
        conflict = self._db.execute(_CONFLICT, (tenant, head[1])).fetchone()
        fence = self._fence(tenant, epoch)
        return (signer.framed(head[0]) + signer.framed(conflict[0] if conflict else b"")
                + self._carried(self._witnesses(_WITNESSES, {"t": tenant, "e": epoch}), fence)
                + signer.framed(fence[0][0] if fence else b""))

    def _fence(self, tenant: str, epoch: int | None) -> list[tuple[bytes, bytes]]:
        """The fence certificate and the digest of its link, if any (Lean ``selectFence``)."""
        return self._db.execute(_FENCE, {"t": tenant, "e": epoch}).fetchall()

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
            frame = (self._authority(tenant, epoch) + _list(candidates) + self._fork_witnesses(tenant, shard, epoch)
                     + signer.framed(signed))
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
        try:
            authority = self._authority(request.tenant_id, epoch)
        except GatePayerError:  # a tenant not served: no release
            return "no_link"
        frame = (authority + self._fork_witnesses(tenant, shard, epoch) + signer.framed(signed) + now.to_bytes(8, "big")
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
