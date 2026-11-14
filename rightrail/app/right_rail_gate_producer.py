"""The gate's checkpoint producer: one serial writer per (tenant, shard), synthetic, activation=false.

``commit`` is reserve, sign and Lean-check, seal, mark.  Line identity is per shard: the shard's own history index
finds a repeated line id.  The header and tokens are stored before the key is used,
so a crash re-signs the same header at the same seq and never reuses a seq with other bytes; ``signer.seal``
releases a signature only when Lean ``publishOk`` accepts it, and only a sealed batch is published.  Seriality is
the store's: one SQLite file opened EXCLUSIVE, WAL, synchronous FULL.  A checked mark file outside the database
(``right_rail_gate_mark``) records the last sealed (epoch, seq_to + 1, digest), so a restored older database is
refused; an old unchecked mark file is refused as corrupt.  The state digest and ``adds`` (the set rows the batch
appended, Lean's bytes, never decoded here) come from the decide layer and are stored in the header's row.  Each row
carries the owner's pledge, an ML-DSA-87 signature by this handle (domain ``_PLEDGE_DOMAIN``, which no checkpoint
verifier accepts) over its (tenant, shard) and every column it wrote, its epoch's certificate included, made before
the INSERT: a reopen reseals an open row only when it is the single newest row, its header this
shard's and its pledge this key's, and trusts the newest sealed row only when its certificate verifies under the root
key and its pledge and checkpoint signature under that certificate's key (O(1) per open), so a row added or changed by
anyone without the key is never signed, served or used (``store_tampered``, the row kept as evidence).  A retries row
(the retry key of a batch sealed by recovery) carries its own pledge over the key and its batch's checkpoint digest
(``_RETRY_DOMAIN``), checked with its batch's row before its tokens are served again.
At cutover the batch's row also stores ``qb`` (the RULES_QUARANTINE bytes) and the cut tag, and it and every later row
``dq = SHA3-512(qb)``, all pledged with their column index (a row before cutover has none: its message is unchanged): the
newest row's ``dq``, verified at open, says the shard is cut over even if the cutover row is later edited.
"""

from __future__ import annotations

import contextlib
from dataclasses import replace
import hashlib
from pathlib import Path
import sqlite3
import time
from typing import Final, Iterator, Sequence

from app import right_rail_gate_chain as chain
from app import right_rail_gate_codec as gate
from app import right_rail_gate_mark as marks
from app import right_rail_gate_signer as signer

_TRIES: Final = 3  # a reservation a database error rolled back is written again at most this often
LIFETIME: Final = 7 * 86_400  # maxTokenLifetime; the decision's age stays the payer's check 5
_MARK_DOMAIN: Final = b"RR/GATE/PRODUCER-MARK/v1\x00"  # bodies: epoch, seq_to + 1 (8 bytes each, big-endian), digest
_ZERO: Final = bytes(80)  # position zero, a new store: its key sorts below any batch's (seq_to + 1 >= 1)
_PLEDGE_DOMAIN: Final = b"RR/GATE/PRODUCER-PLEDGE/v2\x00"  # || SHA3-512 of the framed row columns (``_pledge``)
_PENDING_DOMAIN: Final = b"RR/GATE/PRODUCER-PENDING/v1\x00"  # || SHA3-512 of the framed (tenant, shard) and a stored decide frame's record
_RETRY_DOMAIN: Final = b"RR/GATE/PRODUCER-RETRY/v1\x00"  # || SHA3-512 of the framed (tenant, shard), retry key and its batch's checkpoint digest
_SCHEMA: Final = """
CREATE TABLE IF NOT EXISTS batches(
  id INTEGER PRIMARY KEY, epoch INTEGER NOT NULL, seq_from INTEGER NOT NULL, seq_to INTEGER NOT NULL,
  digest BLOB NOT NULL UNIQUE, header BLOB NOT NULL, state_digest BLOB NOT NULL, tokens BLOB NOT NULL,
  signature BLOB, adds BLOB NOT NULL, pledge BLOB, cert BLOB NOT NULL,
  qb BLOB, dq BLOB, cut BLOB, UNIQUE(epoch, seq_from));
CREATE TRIGGER IF NOT EXISTS batches_quar BEFORE UPDATE OF qb, dq, cut ON batches BEGIN SELECT RAISE(ABORT, 'append_only'); END;
CREATE TRIGGER IF NOT EXISTS batches_fixed BEFORE UPDATE OF id, epoch, seq_from, seq_to, digest, header,
  state_digest, tokens, adds, pledge, cert ON batches BEGIN SELECT RAISE(ABORT, 'append_only'); END;
CREATE TRIGGER IF NOT EXISTS batches_seal BEFORE UPDATE OF signature ON batches
  WHEN OLD.signature IS NOT NULL OR NEW.signature IS NULL BEGIN SELECT RAISE(ABORT, 'append_only'); END;
CREATE TRIGGER IF NOT EXISTS batches_void BEFORE DELETE ON batches
  WHEN OLD.signature IS NOT NULL BEGIN SELECT RAISE(ABORT, 'append_only'); END;
CREATE TABLE IF NOT EXISTS records(batch_id INTEGER PRIMARY KEY REFERENCES batches(id), frame BLOB NOT NULL);
CREATE TRIGGER IF NOT EXISTS records_fixed BEFORE UPDATE ON records BEGIN SELECT RAISE(ABORT, 'append_only'); END;
CREATE TRIGGER IF NOT EXISTS records_void BEFORE DELETE ON records
  WHEN EXISTS(SELECT 1 FROM batches WHERE id=OLD.batch_id AND signature IS NOT NULL)
  BEGIN SELECT RAISE(ABORT, 'append_only'); END;
CREATE TABLE IF NOT EXISTS retries(key BLOB PRIMARY KEY, batch_id INTEGER NOT NULL UNIQUE REFERENCES batches(id), pledge BLOB NOT NULL);
CREATE TRIGGER IF NOT EXISTS retries_fixed BEFORE UPDATE ON retries BEGIN SELECT RAISE(ABORT, 'append_only'); END;
CREATE TRIGGER IF NOT EXISTS retries_void BEFORE DELETE ON retries
  WHEN EXISTS(SELECT 1 FROM batches WHERE id=OLD.batch_id AND signature IS NOT NULL)
  BEGIN SELECT RAISE(ABORT, 'append_only'); END;
"""
_COLUMNS: Final = "id, epoch, seq_to, digest, header, state_digest, tokens, signature, dq"
_PLEDGED: Final = "epoch, seq_from, seq_to, digest, header, state_digest, tokens, adds, qb, dq, cut, cert"


_OPTIONAL: Final = tuple(_PLEDGED.split(", ").index(c) for c in ("qb", "dq", "cut"))


def _pledge(who: tuple[str, int], row: Sequence) -> bytes:
    """The message the owner signs for a row: the store's (tenant, shard), then ``_PLEDGED``'s values, each framed
    (integers as 8 bytes big-endian), so a row copied from another shard's store does not verify here.  NULLs are
    skipped; once any of qb, dq, cut is set, each set one is preceded by its column index, so bytes moved between
    them change the message (a row with all three NULL, before cutover, keeps its message)."""
    tag = any(row[i] is not None for i in _OPTIONAL)
    row = [x for i, v in enumerate(row) if v is not None for x in ((i, v) if tag and i in _OPTIONAL else (v,))]
    fields = (v.to_bytes(8, "big") if type(v) is int else v.encode("ascii") if type(v) is str else bytes(v) for v in (*who, *row))
    return _PLEDGE_DOMAIN + hashlib.sha3_512(b"".join(map(signer.framed, fields))).digest()


def _retry(who: tuple[str, int], key: bytes, digest: bytes) -> bytes:
    """The message the owner signs for a retries row: the store's (tenant, shard), the retry key and the checkpoint digest
    of the batch it names, so a key moved to another batch, or a row copied from another store, does not verify."""
    fields = (who[0].encode("ascii"), who[1].to_bytes(8, "big"), key, digest)
    return _RETRY_DOMAIN + hashlib.sha3_512(b"".join(map(signer.framed, fields))).digest()


def _tokens(data: bytes) -> list[bytes]:
    """The token bytes of a ``tokens`` column (each u32 BE length-prefixed)."""
    tokens, at = [], 0
    while at < len(data):
        size = int.from_bytes(data[at : at + 4], "big")
        tokens.append(data[at + 4 : at + 4 + size])
        at += 4 + size
    return tokens


def _ident(data: bytes, at: int) -> tuple[bytes, int]:
    """The u16-length-prefixed field of ``data`` at ``at``, and the offset after it."""
    end = at + 2 + int.from_bytes(data[at : at + 2], "big")
    return data[at + 2 : end], end


def _owner(header: bytes) -> tuple[str, int] | None:
    """The (tenant, shard) a CHECKPOINT/v3 header names; None for any other bytes."""
    if not header.startswith(gate.CHECKPOINT):
        return None
    tenant, at = _ident(header, len(gate.CHECKPOINT) + 1)
    at = _ident(header, at)[1]
    return tenant.decode("ascii", "replace"), int.from_bytes(header[at : at + 4], "big")


class GateProducerError(RuntimeError):
    """The store is locked, unavailable, rewound or from a newer epoch, or a batch was empty or refused."""


def _custody(tpm: int | None, root_pk: bytes, cert: bytes, signed: bytes) -> str:
    """Lean ``custodyOf``'s step (``create``, ``ready``, ``catch_up``); its refusal is raised under Lean's name."""
    step = signer.custody(tpm, root_pk, cert, signed)
    if step not in ("create", "ready", "catch_up"):
        raise GateProducerError(step)
    return step


class ShardProducer:
    def __init__(self, path: Path, *, mark_path: Path, tenant_id: str, shard_id: int, epoch: int, handle: str,
                 root_pk: bytes, key_cert: bytes, payer_newest: bytes | None, counter, floors, lock=contextlib.nullcontext) -> None:
        """``floors``: a callable giving the tenant's (grant serial, key-set epoch) floors, read from the tenant's floor file
        alone (``right_rail_gate_decide.TenantAuthority.floors_in``), so any shard can reopen first after a cold restart.  An
        unsigned reservation found at start, never released, is sealed only if its authority record is not below the higher of
        those floors and this shard's own newest sealed record; otherwise it is voided (its batch is decided again) and the
        start refuses ``reservation_below_floor``.  ``lock``: the tenant's floor lock as a context (``TenantAuthority._locked``'s
        file), taken around the last floor check and the stored signature of a reseal at start, as ``commit``'s ``lock`` is.
        ``payer_newest``: the digest of the payer's newest stored checkpoint for this shard, ``gate.ZERO_DIGEST`` if it
        has none, ``None`` if the caller could not read it (``payer_unavailable``).  A store that does not hold it sealed is
        ``store_rewound``.  Both refusals come before anything is created or written, so they repeat on every start.
        ``counter``: the shard's counter (``read`` its value or None while never written, ``increment``); each checkpoint takes the
        value after the one read (the first seal signs 1 and its increment arms the counter), and the counter moves once its
        signature is stored.  What a start does with the counter and the newest sealed header's counter (None: nothing sealed)
        is Lean ``custodyOf`` (``signer.custody``, which reads the counter from that checkpoint signed and its certificate, so a crash between the
        first seal and the counter's first increment is caught up, ``first_seal_crash_heals``): serve, or increment once and read back (else ``counter_raced``), or
        refuse under Lean's name (``no_store``, ``counter_reset``, ``store_rewound``, ``store_ahead``).  Each refusal but
        ``counter_raced`` comes before anything is written and repeats on every start; ``counter_raced`` comes after the mark
        and the increment, so the next start finds the store behind the counter and refuses ``store_rewound``."""
        if payer_newest is None:
            raise GateProducerError("payer_unavailable")
        if payer_newest != gate.ZERO_DIGEST and not Path(path).exists():
            raise GateProducerError("store_rewound")
        if not Path(path).exists():
            _custody(counter.read(), root_pk, b"", b"")  # a missing store: refused before a file is created
        self.shard, self.tenant = shard_id, tenant_id
        self._flat_count = (0, 0)  # (id of the last sealed batch counted, sealed batches so far)
        self._authority: tuple[int, bytes | None] = (0, None)  # (id of the sealed batch checked, its authority record)
        # the whole answer the last decide prepared, until it is sealed: ``commit`` signs only an answer equal to it
        self.prepared = None
        self._counter, self._floors, self._lock, self._closed = counter, floors, lock, False
        self._who, self._epoch, self._handle, self._root_pk, self._cert, self._mark = (tenant_id, shard_id), epoch, handle, root_pk, key_cert, mark_path
        self._db = sqlite3.connect(path, timeout=0, isolation_level=None)
        try:
            for pragma in ("locking_mode=EXCLUSIVE", "journal_mode=WAL", "synchronous=FULL"):
                self._db.execute(f"PRAGMA {pragma}")
            columns = [column[1] for column in self._db.execute("PRAGMA table_info(batches)")]
            if columns and ("cert" not in columns or "idreg_n" in columns):
                raise GateProducerError("store_version")  # a store without pledged certificates, or from before line identity was per shard: refused, never migrated
            retries = [column[1] for column in self._db.execute("PRAGMA table_info(retries)")]
            if retries and "pledge" not in retries:
                raise GateProducerError("store_version")  # retry rows without the owner's pledge: refused, never migrated
            if payer_newest != gate.ZERO_DIGEST and not (columns and self._db.execute(
                    "SELECT 1 FROM batches WHERE digest=? AND signature IS NOT NULL", (payer_newest,)).fetchone()):
                raise GateProducerError("store_rewound")  # the payer's newest checkpoint, sealed here; the TPM counter (custody branch) replaces this
            for column in [c for c in ("qb", "dq", "cut") if columns and c not in columns]:  # older rows: NULL, not cut over
                self._db.execute(f"ALTER TABLE batches ADD COLUMN {column} BLOB")
            self._db.executescript(_SCHEMA)
        except sqlite3.OperationalError as error:
            self._db.close()
            raise GateProducerError("store_locked") from error
        except GateProducerError:
            self._db.close()
            raise
        try:
            last, opens = self._sealed(), self._db.execute(f"SELECT {_COLUMNS} FROM batches WHERE signature IS NULL").fetchall()
            for kept in (last, *opens):  # an older header version: refused, never migrated, before anything reads it as this version's
                if kept and type(kept[4]) is bytes and kept[4].startswith(gate.CHECKPOINT[:-2]) and not kept[4].startswith(gate.CHECKPOINT):
                    raise GateProducerError("store_version")
            open_ = opens[0] if opens else None
            newest = max((row[1] for row in (last, open_) if row), default=epoch)
            if newest > epoch:
                raise GateProducerError("epoch_regress")
            if open_ and open_[1] != epoch:
                raise GateProducerError("unsealed_old_epoch")
            if open_:  # only the owner's own reservation is resealed: one, the newest row, this shard's, its pledge this key's
                *row, pledge = self._db.execute(f"SELECT {_PLEDGED}, pledge FROM batches WHERE id=?", (open_[0],)).fetchone()
                if (len(opens) > 1 or (last and last[0] > open_[0]) or type(pledge) is not bytes or _owner(open_[4]) != self._who
                        or not signer.verify(signer.public_key(handle), _pledge(self._who, row), pledge)):
                    raise GateProducerError("store_tampered")
            if last and not self._trusted(last[0]):  # before the mark moves to it, it is served
                raise GateProducerError("store_tampered")
            self._check_mark(last, write=False)  # a store behind the mark is rewound whatever its counter says
            # before the mark moves and before any reseal: a refusal here writes nothing and repeats on every start
            stored = int.from_bytes(last[4][-8:], "big") if last else None  # the newest sealed header's own counter
            cert = self._db.execute("SELECT cert FROM batches WHERE id=?", (last[0],)).fetchone()[0] if last else b""
            step = _custody(counter.read(), root_pk, cert,  # always: a store can appear after the check above
                            gate.attach_signature(last[4], last[7]) if last else b"")
            self._check_mark(last)
            if step == "catch_up" and counter.increment() != stored:  # Custody.lean seal_crash_resumes: increment once, read back
                raise GateProducerError("counter_raced")
            if open_:
                self._seal(open_, last, self._lock)
        except BaseException:
            self._db.close()
            raise

    def _void(self, id_: int) -> None:
        """Delete an unsigned reservation (its retry key, its record and its batch) in one transaction: all go or none."""
        self._db.execute("BEGIN IMMEDIATE")
        try:
            self._db.execute("DELETE FROM retries WHERE batch_id=?", (id_,))
            self._db.execute("DELETE FROM records WHERE batch_id=?", (id_,))
            self._db.execute("DELETE FROM batches WHERE id=?", (id_,))
        except BaseException:
            self._db.execute("ROLLBACK")
            raise
        self._db.execute("COMMIT")

    def _trusted(self, id_: int, also: tuple[bytes, bytes] = (b"", b"")) -> bool:
        """Whether sealed row ``id_`` is as its owner wrote it: its certificate is the root key's for this tenant and
        the row's epoch, and that certificate's key signed the row's pledge and its checkpoint header (this shard's), and
        ``also`` (message, signature), when it names a message."""
        *row, pledge, signature = self._db.execute(f"SELECT {_PLEDGED}, pledge, signature FROM batches WHERE id=?", (id_,)).fetchone()
        cert, size, pk = row[-1], gate.ML_DSA_87_SIGNATURE, gate.ML_DSA_87_PUBLIC_KEY
        try:
            body, sig = cert[: -2 - size], cert[-size:]
            return (cert[-2 - size : -size] == size.to_bytes(2, "big") and body.startswith(gate.KEY_CERT)
                    and _ident(body, len(gate.KEY_CERT) + 1)[0] == self._who[0].encode("ascii")
                    and int.from_bytes(body[-pk - 12 : -pk - 4], "big") == row[0] and _owner(row[4]) == self._who
                    and signer.verify(self._root_pk, body, sig)
                    and signer.verify(body[-pk:], _pledge(self._who, row), pledge)
                    and signer.verify(body[-pk:], row[4], signature)
                    and (not also[0] or signer.verify(body[-pk:], *also)))
        except (TypeError, ValueError, AttributeError):  # a value no owner writes (text where bytes are stored)
            return False

    def _void_or_close(self, id_: int) -> None:
        """Void the unsigned reservation ``id_``; if the store cannot, close (a reopen checks it) and raise ``reservation_not_voided``."""
        try:
            self._void(id_)
        except BaseException as error:
            self.close()
            if isinstance(error, sqlite3.Error):
                raise GateProducerError("reservation_not_voided") from error
            raise

    def _live(self) -> None:
        if self._closed:
            raise GateProducerError("producer_closed")  # after a counter failure or close: only a reopen serves again

    def _sealed(self):
        self._live()
        return self._db.execute(f"SELECT {_COLUMNS} FROM batches WHERE signature IS NOT NULL ORDER BY id DESC LIMIT 1").fetchone()

    def _check_mark(self, last, write: bool = True) -> None:
        """Refuse a corrupt mark, a missing one for a store with sealed batches, or a store behind the mark (a lower
        (epoch, seq), or the same with another digest, or, after a torn mark tail, the same as the newest verified
        record); write the position-zero record for a new store, and catch the mark up to a store any distance ahead
        (as trunk), as after a crash between the seal and the mark.  Mark file errors are ``store_unavailable``."""
        try:
            tail, end, torn = marks.read(self._mark, _MARK_DOMAIN, 80, 16)
            mine = last[1].to_bytes(8, "big") + (last[2] + 1).to_bytes(8, "big") + last[3] if last else _ZERO
            if (tail is None and last) or (tail and (mine[:16] < tail[:16] or (mine[:16] == tail[:16] and (torn or mine != tail)))):
                raise GateProducerError("store_rewound")
            if write and mine != tail:
                marks.append(self._mark, _MARK_DOMAIN, end, mine)
        except marks.MarkCorrupt as error:
            raise GateProducerError("mark_corrupt") from error
        except OSError as error:
            raise GateProducerError("store_unavailable") from error

    def _check_floors(self, row, last) -> None:
        """Void reservation ``row`` and refuse ``reservation_below_floor`` if its authority record is below the tenant's floors or
        below this shard's own newest sealed record; floors that cannot be read void it too (nothing is signed or released
        for it, so voiding is always safe) and the read error is raised."""
        auth = lambda id_: chain.floors_of(bytes(self._db.execute(  # no record (empty adds) reads as (0, 0): below any raised floor
            "SELECT substr(adds, 1, ?) FROM batches WHERE id=?", (chain.AUTH, id_)).fetchone()[0] or b""))
        below = failed = None
        try:
            below = any(a < max(b, c) for a, b, c in zip(auth(row[0]), self._floors(), auth(last[0]) if last else (0, 0)))
        except Exception as error:
            failed = error
        except BaseException:  # an interrupt: not voided, so the reservation stays for a reopen and nothing more is served
            self.close()
            raise
        if below or failed:
            self._void_or_close(row[0])
        if failed:
            raise failed
        if below:
            raise GateProducerError("reservation_below_floor")

    def _seal(self, row, last, lock=contextlib.nullcontext):
        """Steps 3-6 for the reserved ``row``: sign and check, store the signature, mark; return the sealed row.  First, at a
        commit as at a reopen, the tenant's floors are read again: a reservation whose authority record is below them or below
        this shard's own newest sealed record (a floor rose after its admission) is voided, ``reservation_below_floor``, and
        its batch is decided again, so a crash before the seal never changes the outcome."""
        self._check_floors(row, last)
        tokens = _tokens(row[6] or b"")
        try:
            before = self._counter.read() or 0
        except BaseException:  # nothing is signed yet: void it, the producer stays open and the batch is decided again
            self._void_or_close(row[0])
            raise
        try:
            signature = signer.seal(self._handle, self._root_pk, self._cert, last and gate.attach_signature(last[4], last[7]),
                                    row[4], tokens, before)
        except signer.GateSignerError as error:
            if str(error) == "gate_verify_refused":  # no signature left custody: the reservation can be voided
                self._void_or_close(row[0])
                raise GateProducerError("publish_refused") from error
            self.close()  # a reservation stays, never released: serve nothing until a reopen checks it against the tenant's floors
            raise
        except BaseException:
            self.close()
            raise
        stage = 0  # 0: before the lock is held, 1: floors checked under it, 2: the signature may be stored
        try:
            with lock():  # no floor rises between the last check and the stored signature
                stage = 1
                self._check_floors(row, last)  # voids the reservation itself when it refuses
                stage = 2
                self._db.execute("UPDATE batches SET signature=? WHERE id=?", (signature, row[0]))
                moved = self._counter.increment()
        except BaseException as error:
            if stage == 0:  # nothing signed is stored: void it, the producer stays open and a retry decides the batch again
                self._void_or_close(row[0])
                raise
            if stage == 1:
                if not isinstance(error, Exception):  # an interrupt after the check: the reservation stays unsigned and unvoided, so serve nothing until a reopen checks it
                    self.close()
                raise  # an Exception here: _check_floors has already voided or closed as its own refusal requires
            self.close()  # the signed row may be stored but its batch is unreleased: serve nothing until a reopen
            if isinstance(error, GateProducerError):
                raise
            raise GateProducerError("signature_not_stored") from error  # not retry_later: a retry cannot help, only a reopen
        if moved != before + 1:
            self.close()
            raise GateProducerError("counter_raced")
        try:
            sealed = self._sealed()
            self._check_mark(sealed)
        except BaseException as error:  # sealed and counted but not marked: serve nothing until a reopen catches the mark up
            self.close()
            if isinstance(error, sqlite3.Error) or str(error) == "store_unavailable":  # the store or the mark file failed: a retry cannot help, only a reopen
                raise GateProducerError("mark_not_written") from error
            raise
        return sealed

    def commit(self, program: str, ans, created_at: int,
               cut: tuple[bytes, bytes] | None = None, admit=contextlib.nullcontext, lock=contextlib.nullcontext):
        """Seal the batch ``decide`` prepared -> (checkpoint, signed checkpoint, tokens).  No caller supplies a leaf: ``ans``
        must equal ``self.prepared`` (set only by ``decide``, so its payments are Lean's ``RULES_PAY`` answers), and each leaf
        copies its request's own fields, Lean's outcome and reason codes, the deciding worker's release (as rule version and engine release)
        INPUT/v6 as Lean and the host each computed it, and Lean's authority and grant id; the batch's frame is stored with it (``record``), and an answer
        naming a retry key (``ans.retry``) is filed under it in the same transaction (``answered``); the caller names the program.  The answer is spent from here.  ``cut``, (qb, cut tag) of the batch that cut over,
        once (``cut_over``); a database error before the reservation is stored is ``store_unavailable`` (one writing the reservation is tried again, at most
        ``_TRIES`` times, first).  ``admit``: a context the reservation is written
        inside, and only it (the tenant's floor check and lock, ``right_rail_gate_decide.commit``); the answer is spent once it is
        entered, and the seal runs after it.  ``lock``: the same lock as a context, held again around the seal's last floor check and the
        signature store."""
        self._live()
        if self.prepared is None or self.prepared != ans:
            raise GateProducerError("stale_answer")
        leaves = [gate.TokenLeaf(y.tenant, program, self._who[1], y.flow, 0, y.payment_id, y.member_key, y.payee_ref,
                                 y.cents, y.period, y.lines_root, y.outcome, y.reasons, y.authority, y.grant_id, y.bypass,
                                 ans.release, ans.release, y.input, created_at, 0, 0, created_at,
                                 created_at) for y in ans.pays]
        try:
            return self._commit(program, leaves, ans.digest, created_at, ans.adds, cut, ans.frame, ans.retry, admit, lock)
        except sqlite3.Error as error:
            raise GateProducerError("store_unavailable") from error

    def _commit(self, program: str, leaves: Sequence[gate.TokenLeaf], state_digest: bytes, created_at: int,
                adds: bytes, cut: tuple[bytes, bytes] | None, frame: bytes, retry: bytes, admit, lock):
        if not leaves:
            raise GateProducerError("empty_batch")
        if any((leaf.tenant_id, leaf.shard_id) != self._who for leaf in leaves):
            raise GateProducerError("foreign_leaf")  # this writer's chain holds only its own shard
        last = self._sealed()
        newest = self._db.execute("SELECT signature IS NULL FROM batches ORDER BY id DESC LIMIT 1").fetchone()
        if newest and newest[0]:  # only the newest row can be open: a start refuses any other (store_tampered), and the lock holds the rest out
            raise GateProducerError("unsealed_reservation")
        if cut and last and last[8] is not None:
            raise GateProducerError("cut_over")
        same = bool(last) and last[1] == self._epoch
        first = last[2] + 1 if same else 0
        ordered = sorted(leaves, key=lambda leaf: leaf.payment_id.encode())
        checkpoint, tokens = gate.build_batch(
            [replace(leaf, program_id=program, epoch=self._epoch, seq=first + i, issued_at=created_at,
                     expires_at=created_at + LIFETIME) for i, leaf in enumerate(ordered)],
            prev_checkpoint_digest=last[3] if same else gate.ZERO_DIGEST, event_head=last[3] if last else gate.ZERO_DIGEST,
            evidence_root=gate.ZERO_DIGEST, state_digest=state_digest, created_at=created_at, counter=(self._counter.read() or 0) + 1)
        header = gate.encode_checkpoint_header(checkpoint)
        framed = b"".join(signer.framed(gate.encode_token(token)) for token in tokens)
        digest = gate.checkpoint_digest(checkpoint)
        row = (self._epoch, checkpoint.seq_from, checkpoint.seq_to, digest, header, state_digest, framed, adds, cut and cut[0], hashlib.sha3_512(cut[0]).digest() if cut else last and last[8],
               cut and cut[1], self._cert)
        retried = retry and signer.sign(self._handle, _retry(self._who, retry, digest))
        with admit():  # the admission: the reservation is written under it or not at all
            self.prepared = None  # spent once admitted: a refusal before it (a busy lock) keeps the answer
            for tries in range(1, _TRIES + 1):  # a database error rolls the reservation back whole: it is tried again
                if tries > 1 and self._db.execute("SELECT 1 FROM batches WHERE digest=?", (digest,)).fetchone():
                    break  # an earlier try's COMMIT landed and then reported an error: its row is this one
                try:
                    self._db.execute("BEGIN IMMEDIATE")  # the reservation and its record are one transaction: a batch never exists without its frame
                    batch_id = self._db.execute(f"INSERT INTO batches({_PLEDGED}, pledge) VALUES({'?,' * len(row)}?)",
                                                (*row, signer.sign(self._handle, _pledge(self._who, row)))).lastrowid
                    self._db.execute("INSERT INTO records(batch_id, frame) VALUES(?, ?)", (batch_id, frame))
                    if retry:
                        self._db.execute("INSERT INTO retries(key, batch_id, pledge) VALUES(?, ?, ?)", (retry, batch_id, retried))
                    self._db.execute("COMMIT")
                    break
                except BaseException as error:
                    if self._db.in_transaction:
                        self._db.execute("ROLLBACK")
                    if not isinstance(error, sqlite3.Error) or tries == _TRIES:
                        raise
                    time.sleep(0.05 * tries)
        sealed = self._seal(self._db.execute(f"SELECT {_COLUMNS} FROM batches WHERE digest=?", (digest,)).fetchone(), last, lock)
        return checkpoint, gate.attach_signature(sealed[4], sealed[7]), tokens

    def record(self, batch_id: int) -> bytes:
        """The exact decide frame batch ``batch_id`` (its ``id``) was decided on: what a replay re-runs."""
        self._live()
        found = self._db.execute("SELECT frame FROM records WHERE batch_id=?", (batch_id,)).fetchone()
        if found is None:
            raise GateProducerError("no_record")
        return found[0]

    def answered(self, key: bytes) -> tuple[bytes, tuple[bytes, ...]] | None:
        """(signed checkpoint, token bytes) of the sealed batch filed under retry ``key``: what an exact retry of its requests is
        given, byte for byte.  None while no sealed batch is filed under it.  A row whose pledge, or whose batch, is not as
        its owner wrote it (a key moved to another batch, say) is ``store_tampered``, and the row is kept as evidence."""
        self._live()
        row = self._db.execute("SELECT id, digest, retries.pledge, header, signature, tokens FROM retries JOIN batches ON id = batch_id "
                               "WHERE key=? AND signature IS NOT NULL", (key,)).fetchone()
        if row is None:
            return None
        if type(row[1]) is not bytes or not self._trusted(row[0], (_retry(self._who, key, row[1]), row[2])):
            raise GateProducerError("store_tampered")
        return gate.attach_signature(row[3], row[4]), tuple(_tokens(row[5]))

    def vouch(self, record: bytes) -> bytes:
        """This owner's signature over a stored decide frame's ``record`` for this (tenant, shard), under ``_PENDING_DOMAIN``."""
        self._live()
        return signer.sign(self._handle, self._pending(record))

    def vouched(self, record: bytes, signature: bytes) -> bool:
        """Whether ``signature`` is this owner's ``vouch`` of ``record`` for this (tenant, shard)."""
        self._live()
        return signer.verify(signer.public_key(self._handle), self._pending(record), signature)

    def _pending(self, record: bytes) -> bytes:
        fields = (self._who[0].encode("ascii"), self._who[1].to_bytes(8, "big"), record)
        return _PENDING_DOMAIN + hashlib.sha3_512(b"".join(map(signer.framed, fields))).digest()

    def published(self) -> list[bytes]:
        """The sealed signed checkpoints in seq order."""
        self._live()
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

    def sealed_batches(self) -> Iterator[bytes]:
        """The sealed batches' ``adds``, one entry per batch in id order: the segments the decide layer folds onto genesis
        to reach ``anchor``."""
        self._live()
        return (row[0] for row in self._db.execute("SELECT adds FROM batches WHERE signature IS NOT NULL ORDER BY id"))

    def flat_head(self) -> tuple[bytes, int] | None:
        """(CHAIN/v1 head, sealed batch count) of a shard on the history index, None at its genesis.  The head is the sealed
        row's state digest; it is read back from the signed header, so a row whose column was edited apart from the header
        the key signed is ``head_unsigned``.  An open row is ``unsealed_reservation``: only a reopen reseals or voids it, and
        a decide before then would discard the journal that row's seal commits.  The count is kept across calls: O(batch)."""
        self._live()
        if self._db.execute("SELECT 1 FROM batches WHERE signature IS NULL").fetchone():
            raise GateProducerError("unsealed_reservation")
        last = self._sealed()
        if not last:
            return None
        if last[4][-82:-18] != last[5]:  # header tail: state digest, u16 count, u64 created_at, u64 counter
            raise GateProducerError("head_unsigned")
        done, n = self._flat_count
        row = self._db.execute("SELECT COUNT(*), MAX(id) FROM batches WHERE signature IS NOT NULL AND id > ?", (done,)).fetchone()
        self._flat_count = (row[1] or done, n + row[0])
        return last[5], self._flat_count[1]

    def authority(self) -> bytes | None:
        """The newest sealed batch's authority record (the first ``chain.AUTH`` bytes of its ``adds``), None at the shard's
        genesis.  It is used only when the batch's ``adds`` step the head before it (the previous sealed batch's signed state
        digest; at the first batch, the genesis its frame names) to the batch's own signed state digest; otherwise
        ``authority_unchained``.  Checked once per sealed batch."""
        self._live()
        newest = self._db.execute("SELECT id FROM batches WHERE signature IS NOT NULL ORDER BY id DESC LIMIT 1").fetchone()
        if newest is None:
            return None
        if self._authority[0] != newest[0]:
            header, adds = self._db.execute("SELECT header, adds FROM batches WHERE id=?", newest).fetchone()
            before = self._db.execute("SELECT header FROM batches WHERE signature IS NOT NULL AND id < ? ORDER BY id DESC LIMIT 1",
                                      newest).fetchone()
            pre = before[0][-82:-18] if before else self._genesis(newest[0])  # header tail: the signed state digest
            if pre is None or chain.step_adds(pre, adds) != header[-82:-18]:  # adds that do not decode are not a chain step
                raise GateProducerError("authority_unchained")
            self._authority = (newest[0], adds[:chain.AUTH])
        return self._authority[1]

    def _genesis(self, batch_id: int) -> bytes | None:
        """The head the shard's first batch stepped from: the ``prev`` its frame (conformance/FRAME_V1.md section 2) names,
        None if the record is not such a frame.  Only a genesis that the batch's ``adds`` step to the signed head is used."""
        found = self._db.execute("SELECT frame FROM records WHERE batch_id=?", (batch_id,)).fetchone()
        frame = found[0] if found and type(found[0]) is bytes else b""
        return frame[90:154] if frame[:4] == b"RRDQ" and len(frame) >= 154 else None

    def audit_flat(self, as_of: int, pin: bytes) -> bool:
        """Rebuild the chain head from the shard's genesis (sets dated ``as_of``, key-set pin ``pin``) over every sealed
        batch's ``adds`` and compare it with the sealed head: every batch must name ``pin``, and no batch lowers the key-set
        epoch or the grant floor (``chain.head_after``)."""
        last = self._sealed()
        return bool(last) and chain.head_after(chain.genesis(self.shard, as_of, pin), pin, self.sealed_batches()) == last[5]

    def sealed_quar(self) -> tuple[bytes, bytes] | None:
        """(qb, dq) once cut over (None before): ``dq`` the newest sealed row's, ``qb`` the cutover row's.  A missing
        ``qb``, or one whose SHA3-512 is not ``dq``, is ``quar_torn``: the shard HOLDs, never restarts without them."""
        last = self._sealed()
        if not last or last[8] is None:
            return None
        qb = self._db.execute("SELECT qb FROM batches WHERE cut IS NOT NULL AND signature IS NOT NULL ORDER BY id DESC LIMIT 1").fetchone()
        if not qb or type(qb[0]) is not bytes or hashlib.sha3_512(qb[0]).digest() != last[8]:
            raise GateProducerError("quar_torn")
        return qb[0], last[8]

    def close(self) -> None:
        self._closed = True
        self._db.close()
