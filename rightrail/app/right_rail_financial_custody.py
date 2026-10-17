"""The owner's custody log (H2): every committed (owner_id, sequence, history head), hash-chained in a file outside
the store's directory, so a store copied back after a restart is refused unless the log was edited too (Limit,
below).  Synthetic, activation=false.

``<directory>/<owner_id>.custody`` holds one canonical JSON record per line, chained by
``digest = SHA3-512("RR/FINANCIAL/CUSTODY/v1\\0" || the record's canonical JSON without digest and sig)`` and
``prev`` (the previous digest; 128 zeros first).  Kinds:

- MARK: unsigned, appended and fsynced after each COMMIT that moved the sequence, never before it, so no record
  names an uncommitted head.  A failed append is owed, and the next write is refused until it lands.
- ANCHOR: signed, at a new store's genesis and at every close.
- ADOPTED: signed, first record only; an operator restarts custody for a store whose log is lost.
- REWIND_ACCEPTED: signed; an operator accepts a restored store, naming the tail it lowers from.

Signed records carry ``alg`` and an ML-DSA-87 ``sig`` (the pinned gate worker) over
``"RR/FINANCIAL/CUSTODY-SIGNED/v1\\0" || digest``.  MARK sequences rise; an ANCHOR may repeat its predecessor's
(sequence, head); only REWIND_ACCEPTED lowers them.  Open walks the whole chain (one SHA3 per record, the order of
the open's own history replay) and verifies the newest signed record under the key's public key, which covers every
record before it.  With C the last record and S the store's verified (sequence, head):
C ahead of S is ``store_rewound``; S's head at C's sequence differing from C's is ``store_forked``; C behind S with
equal heads (a crash between COMMIT and MARK) gets one catch-up MARK.  A final line without its newline is a torn
append: ignored, and cut before the next append.  A pack is signed with the same key, only at the log's tail.

Limit: the local refusal is only as strong as the custody file's write ACL.  MARKs are unsigned, so whoever can
write the log can, with no key, cut it back to an earlier MARK and restore the store copied there, or append a MARK
naming a fork.  The ANCHOR, ADOPTED and REWIND_ACCEPTED signatures bind only the exported witness (signed packs) and
operator attribution.  Closing this needs an outside witness or per-commit signing under a separate account.
"""

from __future__ import annotations

import hashlib
import json
import msvcrt
import os
from pathlib import Path
import re
from typing import Callable, Final

from app import right_rail_gate_signer as signer
from app.right_rail_financial_canonical_json import encode as _encode
from app.right_rail_financial_owner import FinancialIntegrityError

DIGEST: Final = b"RR/FINANCIAL/CUSTODY/v1\x00"
SIGNED: Final = b"RR/FINANCIAL/CUSTODY-SIGNED/v1\x00"
PACK: Final = b"RR/FINANCIAL/PACK-SIGNED/v1\x00"  # || SHA3-512 of the pack's canonical bytes without "signature"
ALG: Final = "ML-DSA-87"
_ZERO: Final = "0" * 128
_BASE: Final = frozenset({"kind", "owner_id", "n", "prev", "sequence", "head", "digest"})
_KEYS: Final = {"MARK": _BASE, "ANCHOR": _BASE | {"alg", "sig"}, "ADOPTED": _BASE | {"alg", "sig", "actor_id", "reason_ref"},
                "REWIND_ACCEPTED": _BASE | {"alg", "sig", "actor_id", "reason_ref", "from_sequence", "from_head"}}
_HEAD: Final = re.compile(r"[0-9a-f]{128}\Z")
_SIG: Final = re.compile(r"[0-9a-f]{%d}\Z" % (2 * 4627))
_LOCK_AT: Final = 0x7FFF_FFFE  # one byte far past the records: Windows byte locks are mandatory, so readers never meet it


def _refuse(code: str) -> None:
    raise FinancialIntegrityError(code) from None


def _digest(record: dict) -> str:
    return hashlib.sha3_512(DIGEST + _encode({k: v for k, v in record.items() if k not in ("digest", "sig")})).hexdigest()


def _next(line: bytes, owner_id: str, last: dict | None) -> dict:
    """The record on ``line`` if it is canonical and follows ``last``; otherwise ``custody_corrupt``."""
    try:
        record = json.loads(line)
        kind = record["kind"]
        ok = (line == _encode(record) + b"\n" and set(record) == _KEYS[kind] and record["owner_id"] == owner_id
              and type(record["n"]) is type(record["sequence"]) is int and record["sequence"] >= 0 and _HEAD.match(record["head"])
              and record["n"] == (0 if last is None else last["n"] + 1) and record["prev"] == (_ZERO if last is None else last["digest"])
              and record["digest"] == _digest(record) and (kind == "MARK" or (record["alg"] == ALG and _SIG.match(record["sig"]))))
        if ok and last is None:
            ok = kind in ("ANCHOR", "ADOPTED")
        elif ok:
            tail = (last["sequence"], last["head"])
            ok = (kind != "ADOPTED" and record["sequence"] > tail[0] or kind == "ANCHOR" and (record["sequence"], record["head"]) == tail
                  if kind != "REWIND_ACCEPTED" else (record["from_sequence"], record["from_head"]) == tail)
    except (ValueError, TypeError, KeyError, AttributeError):
        ok = False
    if not ok:
        _refuse("custody_corrupt")
    return record


class Custody:
    """One owner's custody log in ``directory``, signed with the ML-DSA-87 key file ``key`` (a gate worker handle)."""

    def __init__(self, directory: Path, key: str) -> None:
        self.directory, self.key = Path(directory), key
        self._owner_id: str | None = None  # bound by first use: one log per object
        self._fd: int | None = None  # held from the first append until close
        self._tail: tuple[int, dict | None] | None = None  # (bytes through the last complete record, that record)
        self._public: bytes | None = None
        self._verified: str | None = None  # the newest signed digest this object verified
        self._owed: tuple[int, bytes] | None = None  # a committed state whose MARK failed

    def _path(self, owner_id: str) -> Path:
        if self._owner_id not in (None, owner_id):
            _refuse("custody_owner")
        self._owner_id = owner_id
        return self.directory / f"{owner_id}.custody"

    def _walk(self, owner_id: str) -> tuple[int, dict | None, dict | None]:
        """(bytes through the last complete record, the last record, the newest signed record) over the whole chain."""
        size, last, signed = 0, None, None
        try:
            with open(self._path(owner_id), "rb") as log:
                for line in log:
                    if not line.endswith(b"\n"):
                        break  # a torn append was never acknowledged
                    last = _next(line, owner_id, last)
                    size += len(line)
                    signed = last if last["kind"] != "MARK" else signed
        except FileNotFoundError:
            pass
        except OSError:
            _refuse("custody_unreadable")
        return size, last, signed

    def _signer(self, call: Callable[[], object]) -> object:
        try:
            return call()
        except signer.GateSignerError:
            _refuse("custody_signer")

    def _public_key(self) -> bytes:
        if self._public is None:
            self._public = self._signer(lambda: signer.public_key(self.key))
        return self._public

    def _sign(self, message: bytes) -> str:
        return self._signer(lambda: signer.sign(self.key, message)).hex()

    def _verify(self, record: dict) -> None:
        if record["digest"] != self._verified:
            if not self._signer(lambda: signer.verify(self._public_key(), SIGNED + bytes.fromhex(record["digest"]), bytes.fromhex(record["sig"]))):
                _refuse("custody_signature")
            self._verified = record["digest"]

    def _checked_tail(self, owner_id: str, store_path: Path) -> dict | None:
        here, store = self.directory.resolve(), store_path.resolve().parent
        if here == store or store in here.parents:
            _refuse("custody_dir_in_store")  # one copy command would carry both
        _size, last, signed = self._walk(owner_id)
        if last is not None:
            self._verify(signed)
        return last

    @staticmethod
    def _behind(last: dict, state: tuple[int, bytes], head_at: Callable[[int], bytes | None]) -> bool:
        """Refuse a store older than, or forked from, the log's tail; True when the tail is behind it."""
        if last["sequence"] > state[0]:
            _refuse("store_rewound")
        if last["kind"] in ("ADOPTED", "REWIND_ACCEPTED") and last["sequence"] != state[0]:
            _refuse("store_forked")  # an operator accepted exactly one (sequence, head): no catch-up past it
        if (state[1] if last["sequence"] == state[0] else head_at(last["sequence"])) != bytes.fromhex(last["head"]):
            _refuse("store_forked")
        return last["sequence"] < state[0]

    def open(self, owner_id: str, store_path: Path, state: tuple[int, bytes], head_at: Callable[[int], bytes | None], *, created: bool) -> None:
        """At the owner's open, after its full verification and before any write."""
        last = self._checked_tail(owner_id, store_path)
        if last is None:
            if not created:
                _refuse("custody_missing")  # recovery: an operator's ADOPTED (resolve)
            self._append(owner_id, "ANCHOR", state)
        elif self._behind(last, state, head_at):
            self._append(owner_id, "MARK", state)

    def mark(self, owner_id: str, state: tuple[int, bytes]) -> None:
        """After a COMMIT that moved the sequence.  Never raises: the command stands, and the MARK is owed."""
        try:
            self._append(owner_id, "MARK", state)
        except (OSError, FinancialIntegrityError):
            self._owed = state

    def settle(self, owner_id: str) -> None:
        """Before a write: land an owed MARK, or refuse the write."""
        if self._owed is not None:
            try:
                self._append(owner_id, "MARK", self._owed)
            except OSError:
                _refuse("custody_unwritable")
            self._owed = None

    def close(self, owner_id: str, state: tuple[int, bytes]) -> None:
        """Sign the last verified or committed state (skipped when the tail is already signed there), release the log."""
        try:
            self._append(owner_id, "ANCHOR", state)
        except OSError:
            _refuse("custody_unwritable")
        finally:
            self._release()

    def resolve(self, owner_id: str, kind: str, store_path: Path, state: tuple[int, bytes], head_at: Callable[[int], bytes | None],
                *, actor_id: str, reason_ref: str) -> None:
        """An operator's act on a store the caller verified in full at the state the operator stated: ADOPTED where
        no log exists, REWIND_ACCEPTED where the log is ahead of or forked from the store."""
        last = self._checked_tail(owner_id, store_path)
        if kind == "ADOPTED" and last is not None:
            _refuse("custody_present")
        if kind == "REWIND_ACCEPTED":
            if last is None:
                _refuse("custody_missing")
            try:
                self._behind(last, state, head_at)
            except FinancialIntegrityError:
                pass
            else:
                _refuse("custody_not_rewound")
        more = {} if kind == "ADOPTED" else {"from_sequence": last["sequence"], "from_head": last["head"]}
        self._append(owner_id, kind, state, actor_id=actor_id, reason_ref=reason_ref, **more)

    def pack_signer(self, source: dict, store_path: Path) -> dict:
        """A pack's ``signer``: only at the log's tail, so no pack speaks for a rewound, forked or unmarked store."""
        last = self._checked_tail(source["owner_id"], store_path)
        if last is None:
            _refuse("custody_missing")
        if last["sequence"] < source["sequence"]:
            _refuse("pack_unanchored")  # an owner's open catches the log up
        self._behind(last, (source["sequence"], bytes.fromhex(source["history_head"])), None)
        return {"alg": ALG, "public_key_sha3_512": hashlib.sha3_512(self._public_key()).hexdigest(), "custody_n": last["n"], "custody_digest": last["digest"]}

    def sign_pack(self, body: bytes) -> str:
        return self._sign(PACK + hashlib.sha3_512(body).digest())

    def _append(self, owner_id: str, kind: str, state: tuple[int, bytes], **more: object) -> None:
        path = self._path(owner_id)
        if self._fd is None:
            self._fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_BINARY)
        try:
            os.lseek(self._fd, _LOCK_AT, 0)
            msvcrt.locking(self._fd, msvcrt.LK_LOCK, 1)  # another owner of the same store appends to the same log
            actual = os.fstat(self._fd).st_size
            if self._tail is None or self._tail[0] != actual:
                self._tail = self._walk(owner_id)[:2]
            size, last = self._tail
            if kind in ("MARK", "ANCHOR") and last is not None and last["sequence"] >= state[0]:
                if last["sequence"] == state[0] and last["head"] != state[1].hex():
                    _refuse("store_forked")  # another store marked this log at this sequence
                if last["sequence"] > state[0] or kind == "MARK" or last["kind"] != "MARK":
                    kind = None  # already there: a later MARK by another owner, or a signed record at this state
            if kind is not None:
                record = {"kind": kind, "owner_id": owner_id, "n": 0 if last is None else last["n"] + 1, "prev": _ZERO if last is None else last["digest"],
                          "sequence": state[0], "head": state[1].hex(), **more, **({} if kind == "MARK" else {"alg": ALG})}
                record["digest"] = _digest(record)
                if kind != "MARK":
                    record["sig"] = self._sign(SIGNED + bytes.fromhex(record["digest"]))
                line = _encode(record) + b"\n"
                if size != actual:
                    os.ftruncate(self._fd, size)  # cut a torn append
                os.lseek(self._fd, size, 0)
                if os.write(self._fd, line) != len(line):
                    raise OSError("custody_short_write")
                os.fsync(self._fd)
                self._tail = (size + len(line), record)
            os.lseek(self._fd, _LOCK_AT, 0)
            msvcrt.locking(self._fd, msvcrt.LK_UNLCK, 1)
        except BaseException:
            self._release()  # closing the handle drops its lock; the next append re-reads the log
            raise

    def _release(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd, self._tail = None, None


def verify_pack(raw: bytes, public_key: bytes) -> dict:
    """A recipient's check of a signed pack: canonical bytes, the key it names, and the signature over the rest."""
    try:
        pack = json.loads(raw)
        signature = bytes.fromhex(pack.pop("signature"))
        body = _encode(pack)
        ok = (_encode({**pack, "signature": signature.hex()}) == raw and pack["signer"]["alg"] == ALG
              and pack["signer"]["public_key_sha3_512"] == hashlib.sha3_512(public_key).hexdigest()
              and signer.verify(public_key, PACK + hashlib.sha3_512(body).digest(), signature))
    except (ValueError, TypeError, KeyError, AttributeError, signer.GateSignerError):
        ok = False
    if not ok:
        _refuse("pack_signature")
    return pack
