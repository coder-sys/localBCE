"""The gate's per-tenant line-id registry (gate-shard-uniqueness-v1), synthetic, activation=false.

One line id is accepted in one shard only.  Before deciding, a shard reserves every id of its batch; the
registry gives each id to the first shard that reserves it and returns the ids another shard owns
(``foreign``), which the decide layer passes to Lean ``decideBatchIn`` so they get ``ALREADY_DECIDED``.
The reply is sent only after the commit is durable (SQLite WAL, synchronous FULL) and its (row count n, head)
is in a checked, fsynced record of the mark file beside the database.  Open and ``reserve`` refuse
(``registry_rewound``) a database whose row n is missing or has another head: a restored older copy, or lost
newest rows.  They do not see an earlier row edited while row n's stored head is kept (only ``verify``, which
replays the whole chain, does; ``reserve`` does not call it), nor a whole directory (database, WAL and mark)
restored together.  A database copied without its mark stays refused: there is no re-adopt path, a person acts.
No decide layer calls ``reserve`` yet; runtime multi-shard safety is the open #3 design item.
"""

from __future__ import annotations

import contextlib
from pathlib import Path
import sqlite3
from typing import Final, Iterable, Mapping, Sequence

from app import right_rail_gate_codec as gate
from app import right_rail_gate_mark as marks

ID_LEN: Final = 129  # the Line.fields id field
_DOMAIN: Final = b"RR/GATE/ID-REG/v1\x00"
_MARK_DOMAIN: Final = b"RR/GATE/ID-MARK/v1\x00"
_MARK_BODY: Final = 72  # a mark record body (right_rail_gate_mark): n (8 bytes, big-endian) and head (64)
_SCHEMA: Final = """
CREATE TABLE IF NOT EXISTS ids(
  n INTEGER PRIMARY KEY, id BLOB NOT NULL UNIQUE, shard INTEGER NOT NULL, head BLOB NOT NULL);
CREATE TRIGGER IF NOT EXISTS ids_no_update BEFORE UPDATE ON ids BEGIN SELECT RAISE(ABORT, 'append_only'); END;
CREATE TRIGGER IF NOT EXISTS ids_no_delete BEFORE DELETE ON ids BEGIN SELECT RAISE(ABORT, 'append_only'); END;
"""


class IdRegistryError(RuntimeError):
    """The registry is unavailable, rewound or inconsistent, or a start state is refused.  Callers decide nothing."""


def _head(prev: bytes, key: bytes, shard: int) -> bytes:
    return gate.sha3_512(_DOMAIN + prev + key + shard.to_bytes(4, "big"))


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


class IdRegistry:
    def __init__(self, path: Path, *, timeout: float = 5.0) -> None:
        self._mark = Path(f"{path}.mark")
        try:
            self._db = sqlite3.connect(path, timeout=timeout, isolation_level=None)
        except sqlite3.OperationalError as error:  # e.g. the directory is missing: same typed refusal
            raise IdRegistryError("registry_unavailable") from error
        try:
            if self._db.execute("PRAGMA journal_mode=WAL").fetchone()[0] != "wal":
                raise IdRegistryError("registry_unavailable")  # a rollback journal is not the durability promised
            self._db.execute("PRAGMA synchronous=FULL")
            self._db.executescript(_SCHEMA)
            with self._txn():  # refuses a rewound registry
                pass
        except sqlite3.Error as error:
            self._db.close()
            raise IdRegistryError("registry_unavailable") from error
        except BaseException:
            self._db.close()
            raise

    def close(self) -> None:
        self._db.close()

    def _last(self) -> tuple[int, bytes]:
        return self._db.execute("SELECT n, head FROM ids ORDER BY n DESC LIMIT 1").fetchone() or (0, gate.ZERO_DIGEST)

    def _sync(self) -> None:
        """Inside a transaction: refuse a registry behind the mark (the row the newest verified record names is
        missing or has another head, or no record verifies for a non-empty registry) and a mark with an
        unverifiable record before its last or an n that does not rise; catch the mark up to a registry ahead of
        it, as after a crash between the commit and the mark."""
        n, head = self._last()
        bodies = marks.read(self._mark, _MARK_DOMAIN, _MARK_BODY, 8)
        if bodies is None:
            raise IdRegistryError("mark_corrupt")
        if bodies:
            marked = int.from_bytes(bodies[-1][:8], "big")
            row = self._db.execute("SELECT head FROM ids WHERE n = ?", (marked,)).fetchone() if marked else (gate.ZERO_DIGEST,)
            if not row or row[0] != bodies[-1][8:]:
                raise IdRegistryError("registry_rewound")
        elif n:
            raise IdRegistryError("registry_rewound")
        if not bodies or bodies[-1] != n.to_bytes(8, "big") + head:
            marks.append(self._mark, _MARK_DOMAIN, bodies, n.to_bytes(8, "big") + head)

    @contextlib.contextmanager
    def _lock(self):
        try:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                self._sync()
                yield
                self._db.execute("COMMIT")
            except BaseException:
                if self._db.in_transaction:
                    self._db.execute("ROLLBACK")
                raise
        except (sqlite3.Error, OSError):  # a failed ROLLBACK included
            raise IdRegistryError("registry_unavailable") from None

    @contextlib.contextmanager
    def _txn(self):
        """A write transaction, then a second lock that records the committed state in the mark before any reply."""
        with self._lock():
            yield
        with self._lock():
            pass

    def _reserve(self, shard: int, ids: list[int]) -> list[tuple[int, int]]:
        head = self._last()[1]
        for id_ in ids:
            new = _head(head, _key(id_), shard)
            if self._db.execute("INSERT INTO ids(id, shard, head) VALUES (?, ?, ?) ON CONFLICT(id) DO NOTHING",
                                (_key(id_), shard, new)).rowcount:
                head = new
        owners = {i: self._db.execute("SELECT shard FROM ids WHERE id = ?", (_key(i),)).fetchone()[0] for i in ids}
        return [(i, o) for i, o in owners.items() if o != shard]

    def reserve(self, shard: int, ids: Sequence[int]) -> tuple[list[tuple[int, int]], bytes, int]:
        """Reserve the int line ids for ``shard``; return the ids another shard owns, each with its owner, then the
        registry head and row count n after the reservation (for the batch record).  Durable, and marked, before it
        returns."""
        ids = _check(shard, ids)
        with self._txn():
            foreign = self._reserve(shard, ids)
            n, head = self._last()
            return foreign, head, n

    def genesis(self, shard_ids: Mapping[int, Sequence[int]]) -> bytes:
        """Reserve each shard's starting-set ids; refuse, reserving nothing, if two shards' sets share an id
        (an existing double acceptance that needs a person).  Returns the head."""
        groups = [(s, _check(s, ids)) for s, ids in shard_ids.items()]
        with self._txn():
            for shard, ids in groups:
                if self._reserve(shard, ids):
                    raise IdRegistryError("genesis_double_acceptance")
            return self._last()[1]

    def verify(self) -> bytes:
        """Replay the chain; return the head (the zero digest when empty) or raise on any broken link."""
        head = gate.ZERO_DIGEST
        try:
            for key, shard, stored in self._db.execute("SELECT id, shard, head FROM ids ORDER BY n"):
                head = _head(head, key, shard)
                if head != stored:
                    raise IdRegistryError("chain_broken")
        except sqlite3.Error:
            raise IdRegistryError("registry_unavailable") from None
        return head
