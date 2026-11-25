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
(``_RETRY_DOMAIN``), checked with its batch's row before its tokens are served again.  Each batch row also pledges the
root of the set of retry keys (``rset``, over the hashes in ``rbuckets``: a key's bucket is its top 10 bits, and each
bucket's hash covers its keys and their batches' digests), so a retries row deleted or rekeyed is ``store_tampered`` when
its exact retry arrives, never decided again.  A batch with ANSWERED tokens
stores their earlier lists (``earlier``: the EARLIER/v1 bodies in token order) in the reservation's transaction; each is
served again only when it hashes to its signed token's ``earlier_root``, so it needs no pledge of its own.  Its batch
row says so (``listed`` = 1, pledged), so a missing ``earlier`` row of such a batch is ``store_tampered``.  A batch
sealed before lists were stored (``listed`` NULL: its pledge is as an older producer wrote it) has each list rebuilt
from the shard's stored frames at its first exact retry, served only under that same check, and stored then
(``answered``).
At cutover the batch's row also stores ``qb`` (the RULES_QUARANTINE bytes) and the cut tag, and it and every later row
``dq = SHA3-512(qb)``, all pledged with their column index (a row before cutover has none: its message is unchanged): the
newest row's ``dq``, verified at open, says the shard is cut over even if the cutover row is later edited.
"""

from __future__ import annotations

import contextlib
from dataclasses import replace
import hashlib
import itertools
import math
from pathlib import Path
import sqlite3
import time
from typing import Final, Iterator, Sequence

from app import right_rail_gate_chain as chain
from app import right_rail_gate_codec as gate
from app import right_rail_gate_mark as marks
from app import right_rail_gate_signer as signer

_TRIES: Final = 3  # a reservation a database error rolled back is written again at most this often
_SEARCH: Final = 1 << 16  # the most other earlier lists ``_rebuilt`` may try for one batch's payments its first twins leave open; more refuses
LIFETIME: Final = 7 * 86_400  # maxTokenLifetime; the decision's age stays the payer's check 5
_MARK_DOMAIN: Final = b"RR/GATE/PRODUCER-MARK/v1\x00"  # bodies: epoch, seq_to + 1 (8 bytes each, big-endian), digest
_ZERO: Final = bytes(80)  # position zero, a new store: its key sorts below any batch's (seq_to + 1 >= 1)
_PLEDGE_DOMAIN: Final = b"RR/GATE/PRODUCER-PLEDGE/v2\x00"  # || SHA3-512 of the framed row columns (``_pledge``)
_PENDING_DOMAIN: Final = b"RR/GATE/PRODUCER-PENDING/v1\x00"  # || SHA3-512 of the framed (tenant, shard) and a stored decide frame's record
_RETRY_DOMAIN: Final = b"RR/GATE/PRODUCER-RETRY/v1\x00"  # || SHA3-512 of the framed (tenant, shard), retry key and its batch's checkpoint digest
_RSET_DOMAIN: Final = b"RR/GATE/PRODUCER-RSET/v1\x00"  # || each non-empty (bucket, its hash) in bucket order (``_set_root``)
_BUCKETS: Final = 1024  # a retry key's bucket is its top 10 bits
_SCHEMA: Final = """
CREATE TABLE IF NOT EXISTS batches(
  id INTEGER PRIMARY KEY, epoch INTEGER NOT NULL, seq_from INTEGER NOT NULL, seq_to INTEGER NOT NULL,
  digest BLOB NOT NULL UNIQUE, header BLOB NOT NULL, state_digest BLOB NOT NULL, tokens BLOB NOT NULL,
  signature BLOB, adds BLOB NOT NULL, pledge BLOB, cert BLOB NOT NULL,
  qb BLOB, dq BLOB, cut BLOB, vcosign BLOB, listed BLOB, rset BLOB, UNIQUE(epoch, seq_from));
CREATE TRIGGER IF NOT EXISTS batches_vcosign BEFORE UPDATE OF vcosign ON batches
  WHEN OLD.signature IS NOT NULL OR NEW.vcosign IS NULL BEGIN SELECT RAISE(ABORT, 'append_only'); END;
CREATE TRIGGER IF NOT EXISTS batches_quar BEFORE UPDATE OF qb, dq, cut ON batches BEGIN SELECT RAISE(ABORT, 'append_only'); END;
CREATE TRIGGER IF NOT EXISTS batches_listed BEFORE UPDATE OF listed ON batches BEGIN SELECT RAISE(ABORT, 'append_only'); END;
CREATE TRIGGER IF NOT EXISTS batches_rset BEFORE UPDATE OF rset ON batches BEGIN SELECT RAISE(ABORT, 'append_only'); END;
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
CREATE TABLE IF NOT EXISTS earlier(batch_id INTEGER PRIMARY KEY REFERENCES batches(id), lists BLOB NOT NULL);
CREATE TRIGGER IF NOT EXISTS earlier_fixed BEFORE UPDATE ON earlier BEGIN SELECT RAISE(ABORT, 'append_only'); END;
CREATE TRIGGER IF NOT EXISTS earlier_void BEFORE DELETE ON earlier
  WHEN EXISTS(SELECT 1 FROM batches WHERE id=OLD.batch_id AND signature IS NOT NULL)
  BEGIN SELECT RAISE(ABORT, 'append_only'); END;
CREATE TABLE IF NOT EXISTS rbuckets(b INTEGER PRIMARY KEY, h BLOB NOT NULL);
"""
_COLUMNS: Final = "id, epoch, seq_to, digest, header, state_digest, tokens, signature, dq, vcosign"
_PLEDGED: Final = "epoch, seq_from, seq_to, digest, header, state_digest, tokens, adds, qb, dq, cut, listed, rset, cert"


_OPTIONAL: Final = tuple(_PLEDGED.split(", ").index(c) for c in ("qb", "dq", "cut", "listed", "rset"))


def _pledge(who: tuple[str, int], row: Sequence) -> bytes:
    """The message the owner signs for a row: the store's (tenant, shard), then ``_PLEDGED``'s values, each framed
    (integers as 8 bytes big-endian), so a row copied from another shard's store does not verify here.  NULLs are
    skipped; once any of qb, dq, cut, listed, rset is set, each set one is preceded by its column index, so bytes moved
    between them change the message (a row with all five NULL, before cutover, before lists were stored and before the
    root of its retry keys was pledged, keeps its message)."""
    tag = any(row[i] is not None for i in _OPTIONAL)
    row = [x for i, v in enumerate(row) if v is not None for x in ((i, v) if tag and i in _OPTIONAL else (v,))]
    fields = (v.to_bytes(8, "big") if type(v) is int else v.encode("ascii") if type(v) is str else bytes(v) for v in (*who, *row))
    return _PLEDGE_DOMAIN + hashlib.sha3_512(b"".join(map(signer.framed, fields))).digest()


def _retry(who: tuple[str, int], key: bytes, digest: bytes) -> bytes:
    """The message the owner signs for a retries row: the store's (tenant, shard), the retry key and the checkpoint digest
    of the batch it names, so a key moved to another batch, or a row copied from another store, does not verify."""
    fields = (who[0].encode("ascii"), who[1].to_bytes(8, "big"), key, digest)
    return _RETRY_DOMAIN + hashlib.sha3_512(b"".join(map(signer.framed, fields))).digest()


def _bucket(key: bytes) -> int:
    """A retry key's bucket: its top 10 bits (keys are SHA3-256, so they spread evenly over the ``_BUCKETS``)."""
    return int.from_bytes(key[:2], "big") >> 6


def _bucket_hash(rows: Sequence[tuple[bytes, bytes]]) -> bytes | None:
    """SHA3-512 over each (retry key, its batch's checkpoint digest), framed, of one bucket, in key order; None for none.
    A value no owner writes (not bytes) raises TypeError."""
    return hashlib.sha3_512(b"".join(signer.framed(k) + signer.framed(d) for k, d in rows)).digest() if rows else None


def _set_root(buckets: dict[int, bytes]) -> bytes:
    """The root of the set of retry keys (``rset``): SHA3-512 of ``_RSET_DOMAIN`` and each non-empty bucket (2 bytes) and its
    framed hash, in bucket order.  A value no owner writes raises TypeError, OverflowError or AttributeError."""
    return hashlib.sha3_512(_RSET_DOMAIN + b"".join(b.to_bytes(2, "big") + signer.framed(h) for b, h in sorted(buckets.items()))).digest()


@contextlib.contextmanager
def _decoded():
    """Reads of a retries key: one sqlite cannot decode (text that is not UTF-8, which no owner writes) is ``store_tampered``;
    any other database error, a locked or busy store included, passes."""
    try:
        yield
    except sqlite3.OperationalError as error:
        if str(error).startswith("Could not decode"):
            raise GateProducerError("store_tampered") from error
        raise


def _signed(row) -> bytes:
    """The signed checkpoint of a sealed ``_COLUMNS`` row: header, signature and the verifier's cosign record."""
    return gate.attach_signature(row[4], row[7]) + (row[9] or b"")


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


def _request_lines(body: bytes) -> tuple[str, str, list[bytes]]:
    """(program, payment id, lines) of DECIDE-REQUEST/v2 bytes; read, not checked (the caller checks the lines root)."""
    program, at = _ident(body, _ident(body, len(gate.DECIDE_REQUEST))[1])  # tenant, program
    payment, at = _ident(body, _ident(body, at + 1)[1])  # flow, command key, payment
    at = _ident(body, _ident(body, at + gate.MEMBER_KEY)[1] + 8)[1]  # member, payee, amount, period
    lines, at = [], at + 2
    for _ in range(int.from_bytes(body[at - 2 : at], "big")):
        line, at = _ident(body, at)
        lines.append(line)
    return program.decode("ascii"), payment.decode("ascii"), lines


def _twin_key(line: bytes) -> tuple[str, bytes]:
    """(line id, the line's bytes but its id) of a canonical line (``gate.encode_line``): two lines with the same bytes
    but the id are Lean ``sameLine``.  An id that is not ASCII is kept replaced: no list naming it has a signed root."""
    end = 3 + int.from_bytes(line[1:3], "big")
    return line[3:end].decode("ascii", "replace"), line[:1] + line[end:]


def _root(entries: tuple[tuple[str, str, str, str], ...]) -> bytes | None:
    """``gate.earlier_root`` of ``entries``; None for a list no answer carries (a line id twice, say)."""
    try:
        return gate.earlier_root(entries)
    except gate.GateCodecError:
        return None


def _heads(header: bytes) -> tuple[bytes, bytes]:
    """(``event_head``, ``token_root``) of CHECKPOINT/v3 header bytes: the digest of the shard's sealed batch before it
    (zero for its first), and the Merkle root of its token leaves."""
    at = _ident(header, _ident(header, len(gate.CHECKPOINT) + 1)[1])[1] + 4 + 3 * 8 + gate.DIGEST  # tenant, program; shard, seqs, epoch, prev
    return header[at : at + gate.DIGEST], header[at + gate.DIGEST : at + 2 * gate.DIGEST]


def _owner(header: bytes) -> tuple[str, int] | None:
    """The (tenant, shard) a CHECKPOINT/v3 header names; None for any other bytes."""
    if not header.startswith(gate.CHECKPOINT):
        return None
    tenant, at = _ident(header, len(gate.CHECKPOINT) + 1)
    at = _ident(header, at)[1]
    return tenant.decode("ascii", "replace"), int.from_bytes(header[at : at + 4], "big")


class GateProducerError(RuntimeError):
    """The store is locked, unavailable, rewound or from a newer epoch, or a batch was empty or refused."""


def _custody(tpm: int | None, link: bytes, cert: bytes, signed: bytes) -> str:
    """Lean ``custodyOf``'s step (``create``, ``ready``, ``catch_up``); its refusal is raised under Lean's name."""
    step = signer.custody(tpm, link, cert, signed)
    if step not in ("create", "ready", "catch_up"):
        raise GateProducerError(step)
    return step


class ShardProducer:
    def __init__(self, path: Path, *, mark_path: Path, tenant_id: str, shard_id: int, epoch: int, handle: str,
                 link: bytes, key_cert: bytes, payer_newest: bytes | None, counter, floors, cosign, lock=contextlib.nullcontext) -> None:
        """``floors``: a callable giving the tenant's (grant serial, key-set epoch, rule-set version, rule-set digest)
        floors, read from the tenant's floor file alone (``right_rail_gate_decide.TenantAuthority.floors_in``), so any shard
        can reopen first after a cold restart.  An unsigned reservation found at start, never released, is sealed only if its
        authority record is behind neither those floors nor this shard's own newest sealed record (``chain.behind``); otherwise it is voided (its batch is decided again) and the
        start refuses ``reservation_below_floor``.  ``lock``: the tenant's floor lock as a context (``TenantAuthority._locked``'s
        file), taken around the last floor check and the stored signature of a reseal at start, as ``commit``'s ``lock`` is.
        ``link``: the tenant's held AUTHORITY-LINK/v1 (the certificate and every checkpoint count only under it).  ``cosign``: a
        callable from a signed checkpoint (header and signature) to the verifier's cosign record; the verifier service is its
        caller's, and ``signer.seal`` releases nothing that Lean ``publishOk`` does not accept with that record.
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
            _custody(counter.read(), link, b"", b"")  # a missing store: refused before a file is created
        self.shard, self.tenant = shard_id, tenant_id
        self._flat_count = (0, 0)  # (id of the last sealed batch counted, sealed batches so far)
        self._authority: tuple[int, bytes | None] = (0, None)  # (id of the sealed batch checked, its authority record)
        # the whole answer the last decide prepared, until it is sealed: ``commit`` signs only an answer equal to it
        self.prepared = None
        self._counter, self._floors, self._lock, self._closed = counter, floors, lock, False
        self._who, self._epoch, self._handle, self._link, self._cert, self._mark = (tenant_id, shard_id), epoch, handle, link, key_cert, mark_path
        self._cosign = cosign
        self._db = sqlite3.connect(path, timeout=0, isolation_level=None)
        try:
            for pragma in ("locking_mode=EXCLUSIVE", "journal_mode=WAL", "synchronous=FULL"):
                self._db.execute(f"PRAGMA {pragma}")
            columns = [column[1] for column in self._db.execute("PRAGMA table_info(batches)")]
            if columns and ("cert" not in columns or "vcosign" not in columns or "idreg_n" in columns):
                raise GateProducerError("store_version")  # a store without pledged certificates or cosign records, or from before line identity was per shard: refused, never migrated
            retries = [column[1] for column in self._db.execute("PRAGMA table_info(retries)")]
            if retries and "pledge" not in retries:
                raise GateProducerError("store_version")  # retry rows without the owner's pledge: refused, never migrated
            if payer_newest != gate.ZERO_DIGEST and not (columns and self._db.execute(
                    "SELECT 1 FROM batches WHERE digest=? AND signature IS NOT NULL", (payer_newest,)).fetchone()):
                raise GateProducerError("store_rewound")  # the payer's newest checkpoint, sealed here; the TPM counter (custody branch) replaces this
            # older rows: NULL, not cut over, no lists stored, no root of the retry keys (``rbuckets`` starts empty).  The migration is one transaction, committed only once every
            # refusal below has passed: a refused open closes, which rolls it back, so the store stays byte for byte as it was
            alter = "".join(f"ALTER TABLE batches ADD COLUMN {c} BLOB;" for c in ("qb", "dq", "cut", "listed", "rset") if columns and c not in columns)
            self._db.executescript(f"BEGIN IMMEDIATE;{alter}{_SCHEMA}")
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
                try:
                    owned = type(pledge) is bytes and signer.verify(signer.public_key(handle), _pledge(self._who, row), pledge)
                except (TypeError, ValueError, OverflowError):  # a value no owner writes (text, or an integer outside 8 bytes)
                    owned = False
                if len(opens) > 1 or (last and last[0] > open_[0]) or _owner(open_[4]) != self._who or not owned:
                    raise GateProducerError("store_tampered")
            if last and not self._trusted(last[0]):  # before the mark moves to it, it is served
                raise GateProducerError("store_tampered")
            self._check_mark(last, write=False)  # a store behind the mark is rewound whatever its counter says
            # before the mark moves and before any reseal: a refusal here writes nothing and repeats on every start
            stored = int.from_bytes(last[4][-8:], "big") if last else None  # the newest sealed header's own counter
            cert = self._db.execute("SELECT cert FROM batches WHERE id=?", (last[0],)).fetchone()[0] if last else b""
            step = _custody(counter.read(), link, cert,  # always: a store can appear after the check above
                            _signed(last) if last else b"")
            try:
                self._db.execute("COMMIT")  # the migration above: every refusal before it has passed
            except sqlite3.OperationalError as error:  # as when the migration itself fails: closed below, rolled back
                raise GateProducerError("store_locked") from error
            self._check_mark(last)
            if step == "catch_up" and counter.increment() != stored:  # Custody.lean seal_crash_resumes: increment once, read back
                raise GateProducerError("counter_raced")
            if open_:
                self._seal(open_, last, self._lock)
        except BaseException:
            self._db.close()
            raise

    def _void(self, id_: int) -> None:
        """Delete an unsigned reservation (its retry key, record, earlier lists and batch) in one transaction: all go or none.
        Its key's bucket hash is recomputed in the same transaction when its rows were as stored; otherwise it is left for a
        miss in that bucket to find (``store_tampered``), never rebuilt over a changed row."""
        self._db.execute("BEGIN IMMEDIATE")
        try:
            with _decoded():
                found = self._db.execute("SELECT key FROM retries WHERE batch_id=?", (id_,)).fetchone()
            b = _bucket(found[0]) if found and type(found[0]) is bytes else None
            stored = None if b is None else self._db.execute("SELECT h FROM rbuckets WHERE b=?", (b,)).fetchone()
            try:
                kept = stored is not None and _bucket_hash(self._rows(b)) == stored[0]
            except TypeError:
                kept = False
            self._db.execute("DELETE FROM retries WHERE batch_id=?", (id_,))
            self._db.execute("DELETE FROM records WHERE batch_id=?", (id_,))
            self._db.execute("DELETE FROM earlier WHERE batch_id=?", (id_,))
            self._db.execute("DELETE FROM batches WHERE id=?", (id_,))
            if kept:
                h = _bucket_hash(self._rows(b))
                self._db.execute(*(("DELETE FROM rbuckets WHERE b=?", (b,)) if h is None else ("INSERT OR REPLACE INTO rbuckets(b, h) VALUES(?, ?)", (b, h))))
        except BaseException:
            self._db.execute("ROLLBACK")
            raise
        self._db.execute("COMMIT")

    def _rows(self, b: int) -> list[tuple[bytes, bytes]]:
        """(retry key, its batch's checkpoint digest) of each retries row in bucket ``b``, in key order: the keys from
        ``b``'s 10 bits followed by zeros up to the next bucket's (bucket 0 and the last are open below and above)."""
        bounds = ([("key >= ?", (b << 6).to_bytes(2, "big"))] if b > 0 else []) + ([("key < ?", ((b + 1) << 6).to_bytes(2, "big"))] if b < _BUCKETS - 1 else [])
        where = " AND ".join(c for c, _ in bounds)
        with _decoded():
            return self._db.execute(f"SELECT key, digest FROM retries JOIN batches ON id = batch_id WHERE {where} ORDER BY key",
                                    [v for _, v in bounds]).fetchall()

    def _checked(self, key: bytes, root: bytes) -> tuple[dict[int, bytes], list[tuple[bytes, bytes]]]:
        """The stored bucket hashes and ``key``'s bucket's rows (``_rows``), once those hashes give ``root`` (the newest row's
        pledged ``rset``) and those rows give their bucket's stored hash (no row for an empty bucket); else ``store_tampered``,
        and nothing is written.  No signature is checked here: the open checked the newest row's pledge, or this producer wrote it."""
        try:
            buckets, rows = dict(self._db.execute("SELECT b, h FROM rbuckets")), self._rows(_bucket(key))
            if _set_root(buckets) != root or _bucket_hash(rows) != buckets.get(_bucket(key)):
                raise GateProducerError("store_tampered")
        except (TypeError, OverflowError, AttributeError) as error:  # a value no owner writes
            raise GateProducerError("store_tampered") from error
        return buckets, rows

    def _trusted(self, id_: int, also: tuple[bytes, bytes] = (b"", b"")) -> bool:
        """Whether sealed row ``id_`` is as its owner wrote it: its certificate is the held link's, signed by its root and
        witness keys, for this tenant and the row's epoch, and that certificate's key signed the row's pledge and its
        checkpoint header (this shard's), the certificate's verifier key signed the header's cosign record, and ``also``
        (message, signature), when it names a message."""
        *row, pledge, signature, vcosign = self._db.execute(
            f"SELECT {_PLEDGED}, pledge, signature, vcosign FROM batches WHERE id=?", (id_,)).fetchone()
        try:
            cert, held = gate.read_key_cert(row[-1]), gate.read_link(self._link)
            vrel, vsig = vcosign[len(gate.VCOSIGN) : len(gate.VCOSIGN) + gate.DIGEST], vcosign[-gate.ML_DSA_87_SIGNATURE :]
            return (cert.tenant_id == self._who[0] == held.tenant_id and cert.epoch == row[0] and _owner(row[4]) == self._who
                    and cert.link == gate.sha3_512(held.body)
                    and signer.verify(held.root_key, cert.body, cert.root_signature)
                    and signer.verify(held.witness_key, cert.body, cert.witness_signature)
                    and signer.verify(cert.key, _pledge(self._who, row), pledge)
                    and signer.verify(cert.key, row[4], signature)
                    and gate.encode_cosign(vrel, vsig) == vcosign
                    and signer.verify(cert.verifier_key, gate.cosign_message(row[4], vrel), vsig)
                    and (not also[0] or signer.verify(cert.key, *also)))
        except (TypeError, ValueError, AttributeError, OverflowError):  # a value no owner writes (text where bytes are stored, an integer outside 8 bytes)
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
        auth = lambda id_: chain.floors_of(bytes(self._db.execute(  # no record (empty adds) reads as none: below any raised floor
            "SELECT substr(adds, 1, ?) FROM batches WHERE id=?", (chain.AUTH, id_)).fetchone()[0] or b""))
        below = failed = None
        try:
            mine = auth(row[0])
            below = chain.behind(mine, self._floors()) or bool(last) and chain.behind(mine, auth(last[0]))
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
            signature, record = signer.seal(self._handle, self._link, self._cert, last and _signed(last),
                                            row[4], tokens, before, self._cosign)
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
                self._db.execute("UPDATE batches SET signature=?, vcosign=? WHERE id=?", (signature, record, row[0]))
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
        INPUT/v7 as Lean and the host each computed it, and Lean's authority and grant id; the batch's frame is stored with it (``record``), and an answer
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
                                 created_at, gate.earlier_root(y.earlier) if y.earlier else gate.ZERO_DIGEST)
                  for y in ans.pays]
        try:
            return self._commit(program, leaves, ans.digest, created_at, ans.adds, cut, ans.frame, ans.retry,
                                {y.payment_id: y.earlier for y in ans.pays}, admit, lock)
        except sqlite3.Error as error:
            raise GateProducerError("store_unavailable") from error

    def _commit(self, program: str, leaves: Sequence[gate.TokenLeaf], state_digest: bytes, created_at: int,
                adds: bytes, cut: tuple[bytes, bytes] | None, frame: bytes, retry: bytes,
                earlier: dict[str, tuple[tuple[str, str, str, str], ...]], admit, lock):
        if not leaves:
            raise GateProducerError("empty_batch")
        if any((leaf.tenant_id, leaf.shard_id) != self._who for leaf in leaves):
            raise GateProducerError("foreign_leaf")  # this writer's chain holds only its own shard
        if retry and len(retry) != 32:  # a retry key is SHA3-256 (``_bucket`` and the SQL bounds place only such keys alike): nothing is written
            raise GateProducerError("bad_retry_key")
        last = self._sealed()
        newest = self._db.execute("SELECT signature IS NULL, rset FROM batches ORDER BY id DESC LIMIT 1").fetchone()
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
        lists = b"".join(gate.earlier_body(earlier[leaf.payment_id]) for leaf in ordered if leaf.outcome == "ANSWERED")  # token order
        # the root of the set of retry keys, this batch's included: at the store's first commit under it every bucket is built
        # from its rows; after that only the key's bucket, from rows first checked against the pledged root (as ``answered``)
        whole, writes = not newest or newest[1] is None, {}
        try:
            if whole:  # bucket by bucket: only the key's own bucket's rows are kept
                buckets, rows = {}, []
                for b in range(_BUCKETS):
                    if (h := _bucket_hash(got := self._rows(b))) is not None:
                        buckets[b] = h
                    if retry and b == _bucket(retry):
                        rows = got
                writes = buckets
            elif retry:
                buckets, rows = self._checked(retry, newest[1])
            if retry:
                buckets[_bucket(retry)] = writes[_bucket(retry)] = _bucket_hash(sorted([*rows, (retry, digest)]))
            rset = _set_root(buckets) if whole or retry else newest[1]
        except (TypeError, OverflowError, AttributeError) as error:  # a value no owner writes, in a store's older rows
            raise GateProducerError("store_tampered") from error
        row = (self._epoch, checkpoint.seq_from, checkpoint.seq_to, digest, header, state_digest, framed, adds, cut and cut[0], hashlib.sha3_512(cut[0]).digest() if cut else last and last[8],
               cut and cut[1], 1 if lists else None, rset, self._cert)  # listed: an int, never a bool (``_pledge`` frames ints)
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
                    if whole:
                        self._db.execute("DELETE FROM rbuckets")
                    for b, h in writes.items():  # one execute per row: every write goes through the same call
                        self._db.execute("INSERT OR REPLACE INTO rbuckets(b, h) VALUES(?, ?)", (b, h))
                    self._db.execute("DELETE FROM earlier WHERE batch_id=?", (batch_id,))  # an orphan an older void left at a reused id
                    if lists:
                        self._db.execute("INSERT INTO earlier(batch_id, lists) VALUES(?, ?)", (batch_id, lists))
                    self._db.execute("COMMIT")
                    break
                except BaseException as error:
                    if self._db.in_transaction:
                        self._db.execute("ROLLBACK")
                    if not isinstance(error, sqlite3.Error) or tries == _TRIES:
                        raise
                    time.sleep(0.05 * tries)
        sealed = self._seal(self._db.execute(f"SELECT {_COLUMNS} FROM batches WHERE digest=?", (digest,)).fetchone(), last, lock)
        return checkpoint, _signed(sealed), tokens

    def record(self, batch_id: int) -> bytes:
        """The exact decide frame batch ``batch_id`` (its ``id``) was decided on: what a replay re-runs."""
        self._live()
        found = self._db.execute("SELECT frame FROM records WHERE batch_id=?", (batch_id,)).fetchone()
        if found is None:
            raise GateProducerError("no_record")
        return found[0]

    def answered(self, key: bytes) -> tuple[bytes, tuple[bytes, ...], tuple[tuple[tuple[str, str, str, str], ...], ...]] | None:
        """(signed checkpoint, token bytes, per token its earlier list, empty unless ANSWERED) of the sealed batch filed under
        retry ``key``: what an exact retry of its requests is given, byte for byte.  None while no sealed batch is filed under
        it, once the stored bucket hashes give the newest row's pledged root of the retry keys and ``key``'s bucket's rows
        give its hash (``_checked``): otherwise a filed row was deleted or rekeyed, and the miss is ``store_tampered``, never
        decided again (a store whose newest row pledges no root, before its first commit under it, is not checked).
        A row whose pledge, or whose batch, is not as its owner wrote it (a key moved to another batch, say), or a stored
        earlier list that is not its token's (``earlier_root``), or no stored list for a batch whose pledged row says it
        stored them (``listed``), is ``store_tampered``, and the row is kept as evidence.  A batch with ANSWERED tokens,
        sealed before lists were stored, has them rebuilt from the shard's stored frames and stored (``_rebuilt``): never
        served without them, and never with any list but the one its tokens sign."""
        self._live()
        row = self._db.execute("SELECT id, digest, retries.pledge, header, signature, tokens, vcosign, lists, listed FROM retries "
                               "JOIN batches ON id = retries.batch_id LEFT JOIN earlier ON earlier.batch_id = id "
                               "WHERE key=? AND signature IS NOT NULL", (key,)).fetchone()
        if row is None:
            root = self._db.execute("SELECT rset FROM batches ORDER BY id DESC LIMIT 1").fetchone()
            if root and root[0] is not None:
                self._checked(key, root[0])
            return None
        if type(row[1]) is not bytes or not self._trusted(row[0], (_retry(self._who, key, row[1]), row[2])):
            raise GateProducerError("store_tampered")
        tokens, lists, at = tuple(_tokens(row[5])), [], 0
        read = [gate.read_token(token) for token in tokens]
        roots = [r[3] for r in read]
        if row[7] is None and any(root != gate.ZERO_DIGEST for root in roots):
            if row[8] is not None:  # sealed with its lists stored (pledged above): the row was deleted, never rebuilt
                raise GateProducerError("store_tampered")
            return gate.attach_signature(row[3], row[4]) + row[6], tokens, self._rebuilt(row[0], row[5], read)
        try:
            for root in roots:
                entries, at = ((), at) if root == gate.ZERO_DIGEST else gate.read_earlier(row[7], at)
                if entries and gate.earlier_root(entries) != root:
                    raise GateProducerError("store_tampered")
                lists.append(entries)
            if row[7] is not None and at != len(row[7]):  # lists no token names
                raise GateProducerError("store_tampered")
        except (gate.GateCodecError, TypeError) as error:
            raise GateProducerError("store_tampered") from error
        return gate.attach_signature(row[3], row[4]) + row[6], tokens, tuple(lists)

    def _rebuilt(self, id_: int, packed: bytes, read: Sequence[tuple[str, str, tuple[str, ...], bytes]]
                 ) -> tuple[tuple[tuple[str, str, str, str], ...], ...]:
        """Per token of sealed batch ``id_`` (its tokens column ``packed``, each read as ``gate.read_token``), sealed before
        earlier lists were stored, the list its token signs, then stored in ``earlier`` so a later retry reads it as any other
        batch's (``answered`` checks it against the same root).  An answered line's twin is a line of an ALLOW payment of an
        earlier sealed batch of this shard whose bytes but the id are its own (Lean ``sameLine`` compares every field after
        the id).  Batches are read in store order, and after each one that adds a twin, each payment still open is given
        every line with a twin its first one (Lean ``twin``: the first released line); the read stops once every payment
        has the signed ``earlier_root``.  Only for payments still open after the whole history are the other choices
        tried, at most ``_SEARCH`` lists in all.  Only a list with the signed root is ever returned.  A stored frame that
        is missing or that the decide layer cannot read (no store that opens has one), or a request that is not its
        token's (another program or payment, or lines that are not its ``lines_root``), is ``store_tampered``.  With no
        list found, the batches below ``id_`` are checked (``_chained``: their headers and token leaves hash up to this
        trusted batch, so each frame read above was checked against its signed tokens): a check that fails is
        ``store_tampered``, else ``store_version_earlier``: refused, never guessed."""
        from app import right_rail_gate_decide as decide  # the frame's format is the decide layer's; it imports this module

        def requests(frame, tokens: bytes) -> list[tuple[str, str, list[bytes], str]]:
            """(program, payment id, lines, signed outcome) of each request of a stored batch, checked against its tokens."""
            if type(frame) is not bytes:  # every batch's frame is stored in its reservation's transaction
                raise GateProducerError("store_tampered")
            out = []
            try:
                signed = {p: (program, root, outcome) for program, p, root, outcome in map(gate.read_token_lines, _tokens(tokens))}
                for program, payment, lines in map(_request_lines, decide._requests(frame)[1]):
                    if signed.get(payment, ())[:2] != (program, gate.lines_root(lines)):
                        raise GateProducerError("store_tampered")
                    out.append((program, payment, lines, signed[payment][2]))
            except (decide.GateDecideError, gate.GateCodecError, UnicodeDecodeError, IndexError, TypeError) as error:
                raise GateProducerError("store_tampered") from error  # TypeError: a value no owner writes
            if len(out) != len(signed) or {x[1] for x in out} != signed.keys():  # one request a token
                raise GateProducerError("store_tampered")
            return out

        def refuse() -> None:
            if not self._chained(id_):
                raise GateProducerError("store_tampered")
            raise GateProducerError("store_version_earlier")

        def first(i: int) -> tuple[tuple[str, str, str, str], ...]:
            return tuple(sorted(((line_id, *twins[same][0]) for line_id, same in open_[i] if same in twins), key=lambda e: e[0].encode()))
        found = self._db.execute("SELECT frame FROM records WHERE batch_id=?", (id_,)).fetchone()
        own = {p: lines for _, p, lines, _ in requests(found and found[0], packed)}
        open_ = {i: list(map(_twin_key, own[payment])) for i, (payment, _, _, root) in enumerate(read) if root != gate.ZERO_DIGEST}
        want = {same for keys in open_.values() for _, same in keys}
        lists: list[tuple[tuple[str, str, str, str], ...]] = [() for _ in read]
        twins: dict[bytes, list[tuple[str, str, str]]] = {}  # a line's bytes but the id: (program, payment id, line id) of each paid one, in store order
        with contextlib.closing(self._db.execute("SELECT frame, tokens FROM batches LEFT JOIN records ON batch_id = id "
                                                 "WHERE id < ? AND signature IS NOT NULL ORDER BY id", (id_,))) as history:
            for frame, tokens in history:  # one frame at a time
                added = False
                for program, payment, lines, outcome in requests(frame, tokens):
                    for line_id, same in map(_twin_key, lines):
                        if outcome == "ALLOW" and same in want and (program, payment, line_id) not in twins.get(same, ()):
                            twins.setdefault(same, []).append((program, payment, line_id))
                            added = True
                for i in list(open_) if added else ():
                    if _root(entries := first(i)) == read[i][3]:
                        lists[i] = entries
                        del open_[i]
                if not open_:
                    break
        # each payment still open: per line with a twin, no entry or one entry per twin
        options = {i: [[None, *((line_id, *twin) for twin in twins[same])] for line_id, same in keys if same in twins] for i, keys in open_.items()}
        if sum(math.prod(map(len, o)) for o in options.values()) > _SEARCH:
            refuse()
        for i, o in options.items():
            entries = next((e for e in (tuple(sorted(filter(None, pick), key=lambda e: e[0].encode())) for pick in itertools.product(*o))
                            if _root(e) == read[i][3]), None)
            if entries is None:
                refuse()
            lists[i] = entries
        with contextlib.suppress(sqlite3.Error):  # each list has its signed root; one not stored is only rebuilt again next time
            self._db.execute("INSERT INTO earlier(batch_id, lists) VALUES(?, ?)",
                             (id_, b"".join(gate.earlier_body(e) for e, r in zip(lists, read) if r[3] != gate.ZERO_DIGEST)))
        return tuple(lists)

    def _chained(self, id_: int) -> bool:
        """Whether the sealed batches up to ``id_`` form one hash chain: each row's digest is the SHA3-512 of its header,
        each header's ``event_head`` the digest of the sealed row before it (zero for the first), and its ``token_root`` the
        Merkle root of its stored tokens' leaves.  With ``id_`` trusted, a sealed row removed below it, or a header or a
        token leaf changed (an outcome, a payment, a lines root), shows: hashes only, no signature."""
        prev = gate.ZERO_DIGEST
        for digest, header, tokens in self._db.execute("SELECT digest, header, tokens FROM batches WHERE id <= ? AND "
                                                       "signature IS NOT NULL ORDER BY id", (id_,)):
            try:
                if (digest != gate.sha3_512(header) or _heads(header) != (prev, gate.merkle_tree(
                        gate.MERKLE_NODE, [gate.token_leaf(token) for token in _tokens(tokens)])[0])):
                    return False
            except (gate.GateCodecError, IndexError, TypeError):  # bytes no owner writes, or a value that is not bytes
                return False
            prev = digest
        return True

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
        return [gate.attach_signature(header, signature) + record for header, signature, record in
                self._db.execute("SELECT header, signature, vcosign FROM batches WHERE signature IS NOT NULL ORDER BY id")]

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
