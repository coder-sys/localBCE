"""The gate's checkpoint producer: one serial writer per (tenant, shard), synthetic, activation=false.

``commit`` is reserve, sign and Lean-check, seal, mark; the decide layer's ``commit`` then settles the registry and only
then hands out the tokens.  It needs the id registry's reply for the batch
(row n and head): the head is signed into the CHECKPOINT/v2 header, and n and the batch's ``free`` ids are stored so
the next registry settle can be derived after a restart.  The header and tokens are stored before the key is used,
so a crash re-signs the same header at the same seq and never reuses a seq with other bytes; ``signer.seal``
releases a signature only when Lean ``publishOk`` accepts it, and only a sealed batch is published.  Seriality is
the store's: one SQLite file opened EXCLUSIVE, WAL, synchronous FULL.  A checked mark file outside the database
(``right_rail_gate_mark``) records the last sealed (epoch, seq_to + 1, digest), so a restored older database is
refused; an old unchecked mark file is refused as corrupt.  The state digest and ``adds`` (the set rows the batch
appended, Lean's bytes, never decoded here) come from the decide layer and are stored in the header's row.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import sqlite3
from typing import Final, Sequence

from app import right_rail_gate_codec as gate
from app import right_rail_gate_mark as marks
from app import right_rail_gate_signer as signer

LIFETIME: Final = 7 * 86_400  # maxTokenLifetime; the decision's age stays the payer's check 5
_MARK_DOMAIN: Final = b"RR/GATE/PRODUCER-MARK/v1\x00"  # bodies: epoch, seq_to + 1 (8 bytes each, big-endian), digest
_ZERO: Final = bytes(80)  # position zero, a new store: its key sorts below any batch's (seq_to + 1 >= 1)
_SCHEMA: Final = """
CREATE TABLE IF NOT EXISTS batches(
  id INTEGER PRIMARY KEY, epoch INTEGER NOT NULL, seq_from INTEGER NOT NULL, seq_to INTEGER NOT NULL,
  digest BLOB NOT NULL UNIQUE, header BLOB NOT NULL, state_digest BLOB NOT NULL, tokens BLOB NOT NULL,
  signature BLOB, idreg_n INTEGER NOT NULL, free TEXT NOT NULL, adds BLOB NOT NULL, UNIQUE(epoch, seq_from));
CREATE TRIGGER IF NOT EXISTS batches_fixed BEFORE UPDATE OF id, epoch, seq_from, seq_to, digest, header,
  state_digest, tokens, idreg_n, free, adds ON batches BEGIN SELECT RAISE(ABORT, 'append_only'); END;
CREATE TRIGGER IF NOT EXISTS batches_seal BEFORE UPDATE OF signature ON batches
  WHEN OLD.signature IS NOT NULL OR NEW.signature IS NULL BEGIN SELECT RAISE(ABORT, 'append_only'); END;
CREATE TRIGGER IF NOT EXISTS batches_void BEFORE DELETE ON batches
  WHEN OLD.signature IS NOT NULL BEGIN SELECT RAISE(ABORT, 'append_only'); END;
"""
_COLUMNS: Final = "id, epoch, seq_to, digest, header, state_digest, tokens, signature"


class GateProducerError(RuntimeError):
    """The store is locked, unavailable, rewound or from a newer epoch, or a batch was empty or refused."""


class ShardProducer:
    def __init__(self, path: Path, *, mark_path: Path, tenant_id: str, shard_id: int, epoch: int, handle: str,
                 root_pk: bytes, key_cert: bytes) -> None:
        self.shard = shard_id
        self._who, self._epoch, self._handle, self._root_pk, self._cert, self._mark = (tenant_id, shard_id), epoch, handle, root_pk, key_cert, mark_path
        self._db = sqlite3.connect(path, timeout=0, isolation_level=None)
        try:
            for pragma in ("locking_mode=EXCLUSIVE", "journal_mode=WAL", "synchronous=FULL"):
                self._db.execute(f"PRAGMA {pragma}")
            columns = [column[1] for column in self._db.execute("PRAGMA table_info(batches)")]
            if columns and "adds" not in columns:
                raise GateProducerError("store_version")  # a pre-decide store: refused, never migrated
            self._db.executescript(_SCHEMA)
        except sqlite3.OperationalError as error:
            self._db.close()
            raise GateProducerError("store_locked") from error
        except GateProducerError:
            self._db.close()
            raise
        try:
            last, open_ = self._sealed(), self._db.execute(f"SELECT {_COLUMNS} FROM batches WHERE signature IS NULL").fetchone()
            newest = max((row[1] for row in (last, open_) if row), default=epoch)
            if newest > epoch:
                raise GateProducerError("epoch_regress")
            if open_ and open_[1] != epoch:
                raise GateProducerError("unsealed_old_epoch")
            self._check_mark(last)
            if open_:
                self._seal(open_, last)
        except BaseException:
            self._db.close()
            raise

    def _sealed(self):
        return self._db.execute(f"SELECT {_COLUMNS} FROM batches WHERE signature IS NOT NULL ORDER BY id DESC LIMIT 1").fetchone()

    def _check_mark(self, last) -> None:
        """Refuse a corrupt mark, a missing one for a store with sealed batches, or a store behind the mark (a lower
        (epoch, seq), or the same with another digest, or, after a torn mark tail, the same as the newest verified
        record); write the position-zero record for a new store, and catch the mark up to a store any distance ahead
        (as trunk), as after a crash between the seal and the mark.  Mark file errors are ``store_unavailable``."""
        try:
            tail, end, torn = marks.read(self._mark, _MARK_DOMAIN, 80, 16)
            mine = last[1].to_bytes(8, "big") + (last[2] + 1).to_bytes(8, "big") + last[3] if last else _ZERO
            if (tail is None and last) or (tail and (mine[:16] < tail[:16] or (mine[:16] == tail[:16] and (torn or mine != tail)))):
                raise GateProducerError("store_rewound")
            if mine != tail:
                marks.append(self._mark, _MARK_DOMAIN, end, mine)
        except marks.MarkCorrupt as error:
            raise GateProducerError("mark_corrupt") from error
        except OSError as error:
            raise GateProducerError("store_unavailable") from error

    def _seal(self, row, last):
        """Steps 3-6 for the reserved ``row``: sign and check, store the signature, mark; return the sealed row."""
        tokens, data = [], row[6]
        while data:
            size = int.from_bytes(data[:4], "big")
            tokens.append(data[4 : 4 + size])
            data = data[4 + size :]
        try:
            signature = signer.seal(self._handle, self._root_pk, self._cert, last and gate.attach_signature(last[4], last[7]),
                                    row[4], tokens)
        except signer.GateSignerError as error:
            if str(error) == "gate_verify_refused":  # no signature left custody: the reservation can be voided
                self._db.execute("DELETE FROM batches WHERE id=?", (row[0],))
                raise GateProducerError("publish_refused") from error
            raise
        self._db.execute("UPDATE batches SET signature=? WHERE id=?", (signature, row[0]))
        sealed = self._sealed()
        self._check_mark(sealed)
        return sealed

    def commit(self, program: str, leaves: Sequence[gate.TokenLeaf], *, state_digest: bytes, created_at: int,
               idreg: tuple[int, bytes], free: Sequence[int], adds: bytes):
        """One batch of decided leaves (one program) -> (checkpoint, signed checkpoint, tokens); ``idreg`` is the
        registry's (n, head) after the batch's reserve and ``free`` the ids Lean says the batch leaves free (``adds``
        its set rows); a database error is ``store_unavailable``."""
        try:
            return self._commit(program, leaves, state_digest, created_at, idreg, free, adds)
        except sqlite3.Error as error:
            raise GateProducerError("store_unavailable") from error

    def _commit(self, program: str, leaves: Sequence[gate.TokenLeaf], state_digest: bytes, created_at: int,
                idreg: tuple[int, bytes], free: Sequence[int], adds: bytes):
        if not leaves:
            raise GateProducerError("empty_batch")
        if any((leaf.tenant_id, leaf.shard_id) != self._who for leaf in leaves):
            raise GateProducerError("foreign_leaf")  # this writer's chain holds only its own shard
        last = self._sealed()
        if self._db.execute("SELECT 1 FROM batches WHERE signature IS NULL").fetchone():
            raise GateProducerError("unsealed_reservation")
        same = bool(last) and last[1] == self._epoch
        first = last[2] + 1 if same else 0
        ordered = sorted(leaves, key=lambda leaf: leaf.payment_id.encode())
        checkpoint, tokens = gate.build_batch(
            [replace(leaf, program_id=program, epoch=self._epoch, seq=first + i, issued_at=created_at,
                     expires_at=created_at + LIFETIME) for i, leaf in enumerate(ordered)],
            prev_checkpoint_digest=last[3] if same else gate.ZERO_DIGEST, event_head=last[3] if last else gate.ZERO_DIGEST,
            evidence_root=gate.ZERO_DIGEST, state_digest=state_digest, created_at=created_at, registry_head=idreg[1])
        header = gate.encode_checkpoint_header(checkpoint)
        framed = b"".join(signer.framed(gate.encode_token(token)) for token in tokens)
        digest = gate.checkpoint_digest(checkpoint)
        self._db.execute("INSERT INTO batches(epoch, seq_from, seq_to, digest, header, state_digest, tokens, idreg_n, free, adds) VALUES(?,?,?,?,?,?,?,?,?,?)",
                         (self._epoch, checkpoint.seq_from, checkpoint.seq_to, digest, header, state_digest, framed, idreg[0],
                          ",".join(map(str, free)), adds))
        sealed = self._seal(self._db.execute(f"SELECT {_COLUMNS} FROM batches WHERE digest=?", (digest,)).fetchone(), last)
        return checkpoint, gate.attach_signature(sealed[4], sealed[7]), tokens

    def published(self) -> list[bytes]:
        """The sealed signed checkpoints in seq order."""
        return [gate.attach_signature(header, signature) for header, signature in
                self._db.execute("SELECT header, signature FROM batches WHERE signature IS NOT NULL ORDER BY id")]

    def anchor(self) -> bytes | None:
        """The last sealed checkpoint's state digest (None at the shard's genesis): the decide layer's anchor."""
        last = self._sealed()
        return last and last[5]

    def tip(self) -> bytes | None:
        """The last sealed checkpoint's digest (None at the shard's genesis): a decide answer is stale once it moves."""
        last = self._sealed()
        return last and last[3]

    def sealed_adds(self) -> bytes:
        """The sealed batches' ``adds`` in id order: the rows the decide layer folds onto genesis to reach ``anchor``."""
        return b"".join(row[0] for row in self._db.execute("SELECT adds FROM batches WHERE signature IS NOT NULL ORDER BY id"))

    def sealed_frees(self) -> tuple[int, bytes, list[int]] | None:
        """The newest batch's (idreg_n, registry head, free): the next registry reserve's ``sealed``.  An open newest row
        is refused (``unsealed_reservation``): only a reopen reseals or voids it, so no reserve settles or frees it."""
        row = self._db.execute("SELECT idreg_n, header, free, signature FROM batches ORDER BY id DESC LIMIT 1").fetchone()
        if row and row[3] is None:
            raise GateProducerError("unsealed_reservation")
        return row and (row[0], row[1][-64:], [int(i) for i in row[2].split(",") if i])

    def close(self) -> None:
        self._db.close()


def newest(path: Path) -> tuple[int, bytes] | None:
    """Read-only, for the registry boot check: the newest batch's (idreg_n, registry head), sealed or open."""
    db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        row = db.execute("SELECT idreg_n, header FROM batches ORDER BY id DESC LIMIT 1").fetchone()
    finally:
        db.close()
    return row and (row[0], row[1][-64:])


def holds(path: Path, digest: bytes) -> bool:
    """Read-only, for the registry boot check (B3): whether the store holds the batch ``digest``, sealed or open (as
    ``newest``).  No store holds nothing; a store that cannot be read is ``store_unavailable``, never an answer."""
    if not path.exists():
        return False
    try:
        db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            return db.execute("SELECT 1 FROM batches WHERE digest=?", (digest,)).fetchone() is not None
        finally:
            db.close()
    except sqlite3.Error as error:
        raise GateProducerError("store_unavailable") from error
