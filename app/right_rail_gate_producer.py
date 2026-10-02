"""The gate's checkpoint producer: one serial writer per (tenant, shard), synthetic, activation=false.

``commit`` is reserve, sign and Lean-check, seal, mark, publish.  The batch's header bytes and tokens are
stored before the key is used, so a crash re-signs the same header at the same seq and never reuses a seq
with other bytes; ``signer.seal`` releases a signature only when Lean ``publishOk`` accepts it, and only a
sealed batch is published.  Seriality is the store's: one SQLite file opened EXCLUSIVE, WAL, synchronous
FULL.  A mark file outside the database records the last sealed (epoch, seq_to, digest), so a restored
older database is refused.  The batch's state digest comes from the decide layer; the producer computes no pin.
"""

from __future__ import annotations

from dataclasses import replace
import os
from pathlib import Path
import sqlite3
import struct
from typing import Final, Sequence

from app import right_rail_gate_codec as gate
from app import right_rail_gate_signer as signer

LIFETIME: Final = 7 * 86_400  # maxTokenLifetime; the decision's age stays the payer's check 5
_MARK: Final = struct.Struct(">QQ64s")
_SCHEMA: Final = """
CREATE TABLE IF NOT EXISTS batches(
  id INTEGER PRIMARY KEY, epoch INTEGER NOT NULL, seq_from INTEGER NOT NULL, seq_to INTEGER NOT NULL,
  digest BLOB NOT NULL UNIQUE, header BLOB NOT NULL, state_digest BLOB NOT NULL, tokens BLOB NOT NULL,
  signature BLOB, UNIQUE(epoch, seq_from));
CREATE TRIGGER IF NOT EXISTS batches_fixed BEFORE UPDATE OF id, epoch, seq_from, seq_to, digest, header,
  state_digest, tokens ON batches BEGIN SELECT RAISE(ABORT, 'append_only'); END;
CREATE TRIGGER IF NOT EXISTS batches_seal BEFORE UPDATE OF signature ON batches
  WHEN OLD.signature IS NOT NULL OR NEW.signature IS NULL BEGIN SELECT RAISE(ABORT, 'append_only'); END;
CREATE TRIGGER IF NOT EXISTS batches_void BEFORE DELETE ON batches
  WHEN OLD.signature IS NOT NULL BEGIN SELECT RAISE(ABORT, 'append_only'); END;
"""
_COLUMNS: Final = "id, epoch, seq_to, digest, header, state_digest, tokens, signature"


class GateProducerError(RuntimeError):
    """The store is locked, rewound or from a newer epoch, or a batch was empty or refused."""


class ShardProducer:
    def __init__(self, path: Path, *, mark_path: Path, tenant_id: str, shard_id: int, epoch: int, handle: str,
                 root_pk: bytes, key_cert: bytes) -> None:
        self._who, self._epoch, self._handle, self._root_pk, self._cert, self._mark = (tenant_id, shard_id), epoch, handle, root_pk, key_cert, mark_path
        self._db = sqlite3.connect(path, timeout=0, isolation_level=None)
        try:
            for pragma in ("locking_mode=EXCLUSIVE", "journal_mode=WAL", "synchronous=FULL"):
                self._db.execute(f"PRAGMA {pragma}")
            self._db.executescript(_SCHEMA)
        except sqlite3.OperationalError as error:
            self._db.close()
            raise GateProducerError("store_locked") from error
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
        """Refuse a store behind the mark (a lower seq, or the same seq with another digest); catch the mark up
        to a store one batch ahead, as after a crash between the seal and the mark."""
        self._mark.touch()
        size = self._mark.stat().st_size // _MARK.size * _MARK.size  # a torn tail was never fsynced
        with open(self._mark, "r+b") as mark:
            tail = None
            if size:
                mark.seek(size - _MARK.size)
                tail = _MARK.unpack(mark.read(_MARK.size))
            mine = last and (last[1], last[2], last[3])
            if tail and (not mine or mine[:2] < tail[:2] or (mine[:2] == tail[:2] and mine != tail)):
                raise GateProducerError("store_rewound")
            if mine and mine != tail:
                mark.truncate(size)
                mark.seek(size)
                mark.write(_MARK.pack(*mine))
                mark.flush()
                os.fsync(mark.fileno())

    def _seal(self, row, last) -> None:
        """Steps 3-6 for the reserved ``row``: sign and check, store the signature, mark."""
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
        self._check_mark(self._sealed())

    def commit(self, program: str, leaves: Sequence[gate.TokenLeaf], *, state_digest: bytes, created_at: int):
        """One batch of decided leaves (one program) -> (checkpoint, signed checkpoint, tokens)."""
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
            evidence_root=gate.ZERO_DIGEST, state_digest=state_digest, created_at=created_at)
        header = gate.encode_checkpoint_header(checkpoint)
        framed = b"".join(signer.framed(gate.encode_token(token)) for token in tokens)
        digest = gate.checkpoint_digest(checkpoint)
        self._db.execute("INSERT INTO batches(epoch, seq_from, seq_to, digest, header, state_digest, tokens) VALUES(?,?,?,?,?,?,?)",
                         (self._epoch, checkpoint.seq_from, checkpoint.seq_to, digest, header, state_digest, framed))
        self._seal(self._db.execute(f"SELECT {_COLUMNS} FROM batches WHERE digest=?", (digest,)).fetchone(), last)
        return checkpoint, self.published()[-1], tokens

    def published(self) -> list[bytes]:
        """The sealed signed checkpoints in seq order."""
        return [gate.attach_signature(header, signature) for header, signature in
                self._db.execute("SELECT header, signature FROM batches WHERE signature IS NOT NULL ORDER BY id")]

    def anchor(self) -> bytes | None:
        """The last sealed checkpoint's state digest (None at the shard's genesis): the decide layer's anchor."""
        last = self._sealed()
        return last and last[5]

    def close(self) -> None:
        self._db.close()
