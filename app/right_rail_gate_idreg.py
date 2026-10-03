"""The gate's per-tenant line-id registry (multi-shard-runtime-v1), synthetic, activation=false.

One append-only chained log (store v2; a v1 store is refused, nothing was deployed): RESERVE gives a free id to a
shard, FREE returns it, SETTLE is the shard's recorded marker (its unfreed reservations are now in its sealed
sets), BOOT names the process generation.  An id is in flight while its holder has no later SETTLE, recorded after.
``reserve`` settles the shard's previous batch, then reserves, in one transaction, and returns the raw answer per
id; Lean decides from it.  Every transaction requires the newest BOOT row to carry this handle's nonce.  ``boot``
replays the chain and requires each shard's newest signed commitment (row n and head, the checkpoint's
registryHead) to lie in it: a registry restored alone or rolled back is refused ``registry_rewound``.  A whole
directory restored together is not detectable here (design 9, R5).
"""

from __future__ import annotations

import contextlib
import os
from pathlib import Path
import sqlite3
from typing import Final, Iterable, Mapping, Sequence

from app import right_rail_gate_codec as gate

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

    def owner(self, key: bytes):
        """(kind, shard, n) of the id's newest RESERVE or FREE row, or None."""
        return self.db.execute("SELECT kind, shard, n FROM log WHERE id = ? AND kind < 2 ORDER BY n DESC LIMIT 1", (key,)).fetchone()


def _pending(db: sqlite3.Connection, shard: int) -> list[tuple[int, bytes]]:
    """(row n, id key) of the shard's in-flight reservations: its RESERVE rows after its newest SETTLE that no later
    RESERVE or FREE of the id follows."""
    return db.execute(
        "SELECT n, id FROM log r WHERE kind = 0 AND shard = ?1 AND n > "
        "(SELECT COALESCE(MAX(n), 0) FROM log WHERE kind = 2 AND shard = ?1) "
        "AND NOT EXISTS (SELECT 1 FROM log f WHERE f.id = r.id AND f.n > r.n AND f.kind < 2) ORDER BY n", (shard,)).fetchall()


def _replay(db: sqlite3.Connection) -> bytes:
    head = gate.ZERO_DIGEST
    try:
        for kind, key, shard, stored in db.execute("SELECT kind, id, shard, head FROM log ORDER BY n"):
            head = _head(head, kind, key, shard)
            if head != stored:
                raise IdRegistryError("chain_broken")
    except sqlite3.Error:
        raise IdRegistryError("registry_unavailable") from None
    return head


def boot(path: Path, commitments: Mapping[int, tuple[int, bytes]]) -> bytes:
    """Before any shard starts: replay the chain, require each shard's newest signed commitment ``(n, head)`` (shards
    0..count-1, every shard with rows included) to be row n of it, append BOOT with a fresh nonce and return it."""
    db = _open(path)
    try:
        with _txn(db, None):
            _replay(db)
            if set(commitments) != set(range(len(commitments))) or any(
                    s not in commitments for (s,) in db.execute("SELECT DISTINCT shard FROM log WHERE kind < 3")):
                raise IdRegistryError("commitment_missing")
            for n, head in commitments.values():
                row = db.execute("SELECT head FROM log WHERE n = ?", (n,)).fetchone() if n else (gate.ZERO_DIGEST,)
                if not row or row[0] != head:
                    raise IdRegistryError("registry_rewound")
            nonce = os.urandom(32)
            _Tail(db).add(_BOOT, nonce.rjust(ID_LEN, b"\0"), 0)
        return nonce
    finally:
        db.close()


class IdRegistry:
    def __init__(self, path: Path, *, boot: bytes, timeout: float = 5.0) -> None:
        self._db, self._boot = _open(path, timeout), boot.rjust(ID_LEN, b"\0")

    def close(self) -> None:
        self._db.close()

    def pending(self, shard: int) -> tuple[int | None, list[int]]:
        """The shard's in-flight ids in reserve order, and the row n of the newest (None when there are none)."""
        _check(shard, ())
        with _txn(self._db, self._boot):
            rows = _pending(self._db, shard)
        return (rows[-1][0] if rows else None), [int.from_bytes(key, "big") for _, key in rows]

    def reserve(self, shard: int, ids: Sequence[int], *, sealed: tuple[int, Sequence[int]] | None
                ) -> tuple[list[tuple[int, int, bool]], int, bytes]:
        """Settle the shard's in-flight ids, then reserve ``ids``, in one durable transaction; return one
        ``(id, owner shard, settled)`` per id in request order, then the row count n and head after.  Settle: when
        ``sealed = (n, free)`` names the pending reserve's n, free ``free`` (each must be in flight for the shard,
        else ``settle_mismatch``, nothing written) and keep the rest recorded; otherwise (no seal, or an older batch)
        free all of them."""
        ids, frees = _check(shard, ids), _check(shard, sealed[1] if sealed else ())
        with _txn(self._db, self._boot):
            tail, pend = _Tail(self._db), _pending(self._db, shard)
            held = {key for _, key in pend}
            for key in [_key(i) for i in frees] if sealed and pend and sealed[0] == pend[-1][0] else [key for _, key in pend]:
                if key not in held:
                    raise IdRegistryError("settle_mismatch")
                held.remove(key)
                tail.add(_FREE, key, shard)
            if held:
                tail.add(_SETTLE, bytes(ID_LEN), shard)
            owners = []
            for i in ids:
                row = tail.owner(_key(i))
                if row is None or row[0] == _FREE:
                    tail.add(_RESERVE, _key(i), shard)
                    owners.append((i, shard, False))
                else:
                    owners.append((i, row[1], self._db.execute("SELECT 1 FROM log WHERE kind = 2 AND shard = ? AND n > ?",
                                                                 (row[1], row[2])).fetchone() is not None))
            return owners, tail.n, tail.head

    def genesis(self, shard_ids: Mapping[int, Sequence[int]]) -> tuple[int, bytes]:
        """Reserve and settle each shard's starting-set ids; refuse, writing nothing, if two shards' sets share an id
        (an existing double acceptance that needs a person).  Returns (n, head)."""
        groups = [(s, _check(s, ids)) for s, ids in shard_ids.items()]
        with _txn(self._db, self._boot):
            tail = _Tail(self._db)
            for shard, ids in groups:
                for i in ids:
                    row = tail.owner(_key(i))
                    if row is None or row[0] == _FREE:
                        tail.add(_RESERVE, _key(i), shard)
                    elif row[1] != shard:
                        raise IdRegistryError("genesis_double_acceptance")
                if ids:
                    tail.add(_SETTLE, bytes(ID_LEN), shard)
            return tail.n, tail.head

    def verify(self) -> bytes:
        """Replay the chain; return the head (the zero digest when empty) or raise on any broken link."""
        return _replay(self._db)
