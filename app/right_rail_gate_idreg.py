"""The gate's per-tenant line-id registry (gate-shard-uniqueness-v1), synthetic, activation=false.

One line id is accepted in one shard only.  Before deciding, a shard reserves every id of its batch; the
registry gives each id to the first shard that reserves it and returns the ids another shard owns
(``foreign``), which the decide layer passes to Lean ``decideBatchIn`` so they get ``ALREADY_DECIDED``.
The reply is sent only after the commit is durable (SQLite WAL, synchronous FULL).  Append-only and
hash-chained: ``verify`` replays the chain.  No multi-shard decide runtime exists yet; until the decide
layer calls ``reserve``, ``refuse_multi_shard`` keeps a tenant at one shard.
"""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import sqlite3
from typing import Final, Iterable, Mapping, Sequence

from app import right_rail_gate_codec as gate

ID_LEN: Final = 129  # the Line.fields id field
_DOMAIN: Final = b"RR/GATE/ID-REG/v1\x00"
_SCHEMA: Final = """
CREATE TABLE IF NOT EXISTS ids(
  n INTEGER PRIMARY KEY, id BLOB NOT NULL UNIQUE, shard INTEGER NOT NULL, head BLOB NOT NULL);
CREATE TRIGGER IF NOT EXISTS ids_no_update BEFORE UPDATE ON ids BEGIN SELECT RAISE(ABORT, 'append_only'); END;
CREATE TRIGGER IF NOT EXISTS ids_no_delete BEFORE DELETE ON ids BEGIN SELECT RAISE(ABORT, 'append_only'); END;
"""


class IdRegistryError(RuntimeError):
    """The registry is unavailable or inconsistent, or a start state is refused.  Callers decide nothing."""


def refuse_multi_shard(shard_count: int, registry: "IdRegistry | None" = None) -> None:
    """Interim rule: a tenant with more than one shard and no registry could accept one id in two shards."""
    if shard_count > 1 and registry is None:
        raise IdRegistryError("multi_shard_without_registry")


def _head(prev: bytes, id_: bytes, shard: int) -> bytes:
    return gate.sha3_512(_DOMAIN + prev + id_ + shard.to_bytes(4, "big"))


def _check(shard: int, ids: Iterable[bytes]) -> list[bytes]:
    if type(shard) is not int or not 0 <= shard < 1 << 32:
        raise IdRegistryError("shard")
    ids = list(ids)
    if any(type(i) is not bytes or len(i) != ID_LEN for i in ids):
        raise IdRegistryError("id")
    return ids


class IdRegistry:
    def __init__(self, path: Path, *, timeout: float = 5.0) -> None:
        try:
            self._db = sqlite3.connect(path, timeout=timeout, isolation_level=None)
        except sqlite3.OperationalError as error:  # e.g. the directory is missing: same typed refusal
            raise IdRegistryError("registry_unavailable") from error
        try:
            for pragma in ("journal_mode=WAL", "synchronous=FULL"):
                self._db.execute(f"PRAGMA {pragma}")
            self._db.executescript(_SCHEMA)
        except sqlite3.OperationalError as error:
            self._db.close()
            raise IdRegistryError("registry_unavailable") from error

    def close(self) -> None:
        self._db.close()

    @contextmanager
    def _txn(self):
        try:
            self._db.execute("BEGIN IMMEDIATE")
        except sqlite3.OperationalError as error:
            raise IdRegistryError("registry_unavailable") from error
        try:
            yield
            self._db.execute("COMMIT")
        except BaseException:
            if self._db.in_transaction:
                self._db.execute("ROLLBACK")
            raise

    def _reserve(self, shard: int, ids: list[bytes]) -> tuple[list[tuple[bytes, int]], bytes]:
        row = self._db.execute("SELECT head FROM ids ORDER BY n DESC LIMIT 1").fetchone()
        head = row[0] if row else gate.ZERO_DIGEST
        for id_ in ids:
            new = _head(head, id_, shard)
            if self._db.execute("INSERT INTO ids(id, shard, head) VALUES (?, ?, ?) ON CONFLICT(id) DO NOTHING",
                                (id_, shard, new)).rowcount:
                head = new
        owners = {i: self._db.execute("SELECT shard FROM ids WHERE id = ?", (i,)).fetchone()[0] for i in ids}
        return [(i, o) for i, o in owners.items() if o != shard], head

    def reserve(self, shard: int, ids: Sequence[bytes]) -> tuple[list[tuple[bytes, int]], bytes]:
        """Reserve ``ids`` for ``shard``; return the ids another shard owns, each with its owner, and the
        registry head after the reservation (for the batch record).  Durable before it returns."""
        ids = _check(shard, ids)
        with self._txn():
            return self._reserve(shard, ids)

    def genesis(self, shard_ids: Mapping[int, Sequence[bytes]]) -> bytes:
        """Reserve each shard's starting-set ids; refuse, reserving nothing, if two shards' sets share an id
        (an existing double acceptance that needs a person).  Returns the head."""
        groups = [(s, _check(s, ids)) for s, ids in shard_ids.items()]
        head = gate.ZERO_DIGEST
        with self._txn():
            for shard, ids in groups:
                foreign, head = self._reserve(shard, ids)
                if foreign:
                    raise IdRegistryError("genesis_double_acceptance")
        return head

    def verify(self) -> bytes:
        """Replay the chain; return the head (the zero digest when empty) or raise on any broken link."""
        head = gate.ZERO_DIGEST
        for id_, shard, stored in self._db.execute("SELECT id, shard, head FROM ids ORDER BY n"):
            head = _head(head, id_, shard)
            if head != stored:
                raise IdRegistryError("chain_broken")
        return head
