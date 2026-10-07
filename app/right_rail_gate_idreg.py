"""The gate's per-tenant line-id registry (multi-shard-runtime-v1), synthetic, activation=false.

One append-only chained log (store v2; a v1 store is refused): RESERVE gives a free id to a shard, FREE returns it,
SETTLE marks the shard's unfreed reservations as in its sealed sets, BOOT names the process generation.  An id is in
flight while its holder has no later SETTLE.  The decide layer settles each sealed batch before its tokens leave
(``decide.commit``); ``reserve`` settles it first if a crash came between, then reserves, in one transaction, and returns the raw answer per id (Lean decides).  Every transaction requires the newest BOOT row to
carry this handle's nonce.  One decider per shard: the handle that first writes for a shard (or reads its in-flight
rows) holds the shard's lease, an exclusive lock on ``<path>-lease<shard>`` the OS drops when the handle closes or its
process dies; any other handle is refused ``shard_busy``, so nothing reserves for the shard between a commit's stale
check and its seal.  ``boot``, and ``reserve`` for its shard, require each shard's newest signed commitment
(row n and head, the checkpoint's registryHead) to lie in the chain, with no settle of a newer batch of the shard
after it, else ``registry_rewound``.  A whole directory restored together passes that; ``boot`` refuses it
``store_rewound`` when a shard's store lacks the payer's newest stored checkpoint (design idreg-restore B3), and the
decide layer then answers HOLD (``decide`` with no registry).
"""

from __future__ import annotations

import contextlib
import os
from pathlib import Path
import sqlite3
from typing import Final, Iterable, Mapping, Sequence

from app import right_rail_gate_codec as gate
from app import right_rail_gate_producer as producer

ID_LEN: Final = 129  # the Line.fields id field
_DOMAIN: Final = b"RR/GATE/ID-REG/v2\x00"
_RESERVE, _FREE, _SETTLE, _BOOT = range(4)
_SCHEMA: Final = """
CREATE TABLE IF NOT EXISTS log(
  n INTEGER PRIMARY KEY, kind INTEGER NOT NULL, id BLOB NOT NULL, shard INTEGER NOT NULL, head BLOB NOT NULL);
CREATE INDEX IF NOT EXISTS log_id ON log(id, n);
CREATE INDEX IF NOT EXISTS log_settle ON log(shard, n) WHERE kind = 2;
CREATE INDEX IF NOT EXISTS log_boot ON log(n) WHERE kind = 3;
CREATE TRIGGER IF NOT EXISTS log_no_update BEFORE UPDATE ON log BEGIN SELECT RAISE(ABORT, 'append_only'); END;
CREATE TRIGGER IF NOT EXISTS log_no_delete BEFORE DELETE ON log BEGIN SELECT RAISE(ABORT, 'append_only'); END;
"""


class IdRegistryError(RuntimeError):
    """The registry is unavailable, rewound, unbooted or inconsistent, or a start state or settle is refused."""


def _head(prev: bytes, kind: int, key: bytes, shard: int) -> bytes:
    return gate.sha3_512(_DOMAIN + prev + bytes([kind]) + key + shard.to_bytes(4, "big"))


def _check(shard: int, ids: Iterable[int]) -> list[int]:
    if type(shard) is not int or not 0 <= shard < 1 << 32:
        raise IdRegistryError("shard")
    ids = list(ids)
    if any(type(i) is not int or not 0 <= i < 1 << 8 * ID_LEN for i in ids):
        raise IdRegistryError("id")
    return ids


def _key(id_: int) -> bytes:
    """Lean ``be idWidth id``, the Line.id field bytes: the one place an id becomes bytes."""
    return id_.to_bytes(ID_LEN, "big")


def _open(path: Path, timeout: float = 5.0) -> sqlite3.Connection:
    try:
        db = sqlite3.connect(path, timeout=timeout, isolation_level=None)
    except sqlite3.OperationalError as error:  # e.g. the directory is missing: same typed refusal
        raise IdRegistryError("registry_unavailable") from error
    try:
        if db.execute("PRAGMA journal_mode=WAL").fetchone()[0] != "wal":
            raise IdRegistryError("registry_unavailable")  # a rollback journal is not the durability promised
        db.execute("PRAGMA synchronous=FULL")
        if db.execute("SELECT 1 FROM sqlite_master WHERE name = 'ids'").fetchone():
            raise IdRegistryError("store_version")  # the v1 table: refused, never migrated
        db.executescript(_SCHEMA)
    except sqlite3.Error as error:
        db.close()
        raise IdRegistryError("registry_unavailable") from error
    except BaseException:
        db.close()
        raise
    return db


@contextlib.contextmanager
def _txn(db: sqlite3.Connection, boot: bytes | None):
    """One write transaction (BEGIN IMMEDIATE, one fsync at COMMIT) whose newest BOOT row must carry ``boot``."""
    try:
        db.execute("BEGIN IMMEDIATE")
        try:
            row = db.execute("SELECT id FROM log WHERE kind = 3 ORDER BY n DESC LIMIT 1").fetchone()
            if boot is not None and (not row or row[0] != boot):
                raise IdRegistryError("registry_not_booted")
            yield
            db.execute("COMMIT")
        except BaseException:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise
    except (sqlite3.Error, OSError):  # a failed ROLLBACK included
        raise IdRegistryError("registry_unavailable") from None


class _Tail:
    """The chain's end inside a transaction; ``add`` appends one row."""

    def __init__(self, db: sqlite3.Connection) -> None:
        self.db = db
        self.n, self.head = db.execute("SELECT n, head FROM log ORDER BY n DESC LIMIT 1").fetchone() or (0, gate.ZERO_DIGEST)

    def add(self, kind: int, key: bytes, shard: int) -> None:
        self.head = _head(self.head, kind, key, shard)
        self.n += 1
        self.db.execute("INSERT INTO log VALUES (?, ?, ?, ?, ?)", (self.n, kind, key, shard, self.head))

    def take(self, key: bytes, shard: int):
        """RESERVE the id for ``shard`` if it is unowned or freed (returns None); else its owner row (kind, shard, n)."""
        row = self.db.execute("SELECT kind, shard, n FROM log WHERE id = ? AND kind < 2 ORDER BY n DESC LIMIT 1", (key,)).fetchone()
        if row is None or row[0] == _FREE:
            self.add(_RESERVE, key, shard)
            return None
        return row


def _pending(db: sqlite3.Connection, shard: int) -> list[tuple[int, bytes]]:
    """(row n, id key) of the shard's in-flight reservations: its RESERVE rows after its newest SETTLE that no later
    RESERVE or FREE of the id follows."""
    return db.execute(
        "SELECT n, id FROM log r WHERE kind = 0 AND shard = ?1 AND n > "
        "(SELECT COALESCE(MAX(n), 0) FROM log WHERE kind = 2 AND shard = ?1) "
        "AND NOT EXISTS (SELECT 1 FROM log f WHERE f.id = r.id AND f.n > r.n AND f.kind < 2) ORDER BY n", (shard,)).fetchall()


def _rewound(db: sqlite3.Connection, shard: int, n: int, head: bytes) -> bool:
    """Whether the shard's newest signed commitment ``(n, head)`` is not row n of the chain, or a SETTLE of the shard
    follows a RESERVE of it past n (a newer batch's settle: the shard's store is behind)."""
    row = db.execute("SELECT head FROM log WHERE n = ?", (n,)).fetchone() if n else (gate.ZERO_DIGEST,)
    return not row or row[0] != head or db.execute(
        "SELECT 1 FROM log WHERE kind = 0 AND shard = ?1 AND n > ?2 AND n < "
        "(SELECT COALESCE(MAX(n), 0) FROM log WHERE kind = 2 AND shard = ?1)", (shard, n)).fetchone() is not None


def boot(path: Path, commitments: Mapping[int, tuple[int, bytes]],
         anchors: Mapping[int, tuple[Path, bytes | None]]) -> bytes:
    """Before any shard starts: replay the chain, require each shard's newest signed commitment ``(n, head)`` (shards
    0..count-1; a shard with rows needs a batch's or the tenant genesis commitment, never ``(0, ZERO)``) to be row n
    of it with no SETTLE of the shard after a RESERVE of it past n, append BOOT with a fresh nonce and return it.
    ``anchors`` names, for exactly those shards, the producer store the commitment came from and the payer's newest
    stored checkpoint digest (``None``: the payer stored none); a store that lacks it is ``store_rewound`` (B3, design
    idreg-restore 1), so a store, registry and mark restored together to before a released checkpoint cannot boot.
    Every refusal writes nothing: no BOOT row, no nonce, so no shard can reserve until a boot passes."""
    db = _open(path)
    try:
        with _txn(db, None):
            head = gate.ZERO_DIGEST
            for kind, key, shard, stored in db.execute("SELECT kind, id, shard, head FROM log ORDER BY n"):
                head = _head(head, kind, key, shard)
                if head != stored:
                    raise IdRegistryError("chain_broken")
            if set(commitments) != set(range(len(commitments))) or any(
                    not commitments.get(s, (0,))[0] for (s,) in db.execute("SELECT DISTINCT shard FROM log WHERE kind < 3")):
                raise IdRegistryError("commitment_missing")
            if any(_rewound(db, s, n, head) for s, (n, head) in commitments.items()):
                raise IdRegistryError("registry_rewound")
            if set(anchors) != set(commitments):
                raise IdRegistryError("anchor_missing")
            if any(digest is not None and not producer.holds(store, digest) for store, digest in anchors.values()):
                raise IdRegistryError("store_rewound")
            nonce = os.urandom(32)
            _Tail(db).add(_BOOT, nonce.rjust(ID_LEN, b"\0"), 0)
        return nonce
    finally:
        db.close()


class IdRegistry:
    def __init__(self, path: Path, *, boot: bytes, timeout: float = 5.0) -> None:
        self._db, self._boot, self._path, self._leases = _open(path, timeout), boot.rjust(ID_LEN, b"\0"), path, {}

    def close(self) -> None:
        for lock in self._leases.values():
            lock.close()
        self._db.close()

    def _lease(self, shard: int) -> None:
        """Hold ``shard``'s decider lease until ``close``, else ``shard_busy`` (another live handle holds it)."""
        if shard not in self._leases:
            lock = sqlite3.connect(f"{self._path}-lease{shard}", timeout=0, isolation_level=None)
            try:
                lock.execute("BEGIN EXCLUSIVE")
            except sqlite3.Error as error:
                lock.close()
                raise IdRegistryError("shard_busy") from error
            self._leases[shard] = lock

    def reserve(self, shard: int, ids: Sequence[int], *, sealed: tuple[int, bytes, Sequence[int]] | None
                ) -> tuple[list[tuple[int, int, bool]], int, bytes]:
        """Check the shard's newest sealed commitment ``sealed = (n, head, free)`` as ``boot`` does (each batch: a store
        restored after boot is ``registry_rewound`` too), settle the shard's in-flight ids, then reserve ``ids``, in one
        durable transaction; return one ``(id, owner shard, settled)`` per id in request order, then the row count n
        and head after.  Settle: when n is the pending reserve's, free ``free`` (each must be in flight for the shard,
        else ``settle_mismatch``, nothing written) and keep the rest recorded; otherwise (no seal, or an older batch
        whose successor died before its seal) free all of them."""
        ids = _check(shard, ids)
        with _txn(self._db, self._boot):
            self._lease(shard)
            if sealed and _rewound(self._db, shard, sealed[0], sealed[1]):
                raise IdRegistryError("registry_rewound")
            pend, frees = _pending(self._db, shard), _check(shard, sealed[2] if sealed else ())
            tail = self._settle(shard, pend, frees if sealed and pend and sealed[0] == pend[-1][0] else None)
            owners = []
            for i in ids:
                row = tail.take(_key(i), shard)
                owners.append((i, shard, False) if row is None else (i, row[1], self._db.execute(
                    "SELECT 1 FROM log WHERE kind = 2 AND shard = ? AND n > ?", (row[1], row[2])).fetchone() is not None))
            return owners, tail.n, tail.head

    def in_flight(self, shard: int) -> list[int]:
        """The row numbers of the shard's in-flight reservations, under its lease (a commit's check holds to its seal)."""
        self._lease(shard)
        return [n for n, _ in _pending(self._db, shard)]

    def settle(self, shard: int, rows: list[int], free: Sequence[int]) -> None:
        """Settle the batch that reserved exactly ``rows`` (``decide.commit``, after the seal): ``settle_mismatch``,
        nothing written, unless they are the shard's in-flight rows."""
        with _txn(self._db, self._boot):
            self._lease(shard)
            pend = _pending(self._db, shard)
            if [n for n, _ in pend] != rows:
                raise IdRegistryError("settle_mismatch")
            self._settle(shard, pend, _check(shard, free))

    def _settle(self, shard: int, pend: list[tuple[int, bytes]], free: list[int] | None) -> _Tail:
        """Free ``free`` (each must be in flight; None: all of ``pend``) and SETTLE the rest."""
        tail, held = _Tail(self._db), {key for _, key in pend}
        for key in [key for _, key in pend] if free is None else [_key(i) for i in free]:
            if key not in held:
                raise IdRegistryError("settle_mismatch")
            held.remove(key)
            tail.add(_FREE, key, shard)
        if held:
            tail.add(_SETTLE, bytes(ID_LEN), shard)
        return tail

    def settled(self, shard: int) -> bool:
        """Whether the shard has a SETTLE row: a sealed batch's, or ``genesis()``'s."""
        return self._db.execute("SELECT 1 FROM log WHERE kind = 2 AND shard = ?", (shard,)).fetchone() is not None

    def genesis(self, shard_ids: Mapping[int, Sequence[int]]) -> tuple[int, bytes]:
        """Reserve and settle each shard's starting-set ids; refuse, writing nothing, if two shards' sets share an id
        (an existing double acceptance that needs a person).  Returns (n, head)."""
        groups = [(s, _check(s, ids)) for s, ids in shard_ids.items()]
        with _txn(self._db, self._boot):
            tail = _Tail(self._db)
            for shard, ids in groups:
                for i in ids:
                    row = tail.take(_key(i), shard)
                    if row and row[1] != shard:
                        raise IdRegistryError("genesis_double_acceptance")
                if ids:
                    self._lease(shard)
                    tail.add(_SETTLE, bytes(ID_LEN), shard)
            return tail.n, tail.head
