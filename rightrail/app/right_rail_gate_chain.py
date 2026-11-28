"""CHAIN/v1, the hash chain over a shard's released and unresolved sets (conformance/FLAT_V1.md sections 2, 5 and 6).

The shard's history is kept by the worker in a chunk store, a directory with one append-only ``log`` and images of the
directory.  A batch is one frame of the log: a header, the chunk's 4,096-byte pages, its metadata and a trailer.  A batch
that grew the directory (or the first, or after many rows) also writes an image ``img<k>`` first, under a temporary name,
synced and renamed.  The frame's header, pages and metadata are appended and synced, then the trailer, which commits the
batch.  Nothing is released before the trailer is on disk.

The worker's open loads the store at the signed head and batch count: it reads the newest image up to that count, checks its
hash and decodes it, and replays the frames after it.  It refuses (``RULES_FLAT_HOLD``) a directory holding any other file,
an image that is missing or does not give the hash its frame names, a frame that does not replay to the head it states, two
whole frames past the signed head, and a head or count the log does not give.  A batch killed after its trailer was written
but before the host signed it leaves one whole frame past the signed head: the open cuts it off.  A torn frame is cut off too.

The genesis head hashes the shard, the key-set pin and the two empty sets.  The head after a batch is
``SHA3-512("RR/GATE/CHAIN/v1" 00 02 prev digest root)``: the head before, the batch digest
``SHA3-512("RR/GATE/CHAIN/v1" 00 03 leb(AUTH) auth delta)`` over the shard's authority record after the batch and the rows it
appended, and the state root after the batch.  The
frame's trailer (``RR/GATE/FLAT/FRAME/v1``, then the batch count, the chunk, the two sets' heads, the next install number, the
image and its hash, ``prev``, the digest and the head) holds them.  The producer signs the
head in each checkpoint's state digest; the adapter recomputes the step from the batch's ``RULES_ADDS`` rows and the worker's
printed root before it trusts the worker's head.  The producer stores a batch's ``adds`` as the authority record, the
state root, then the rows, so a sealed record is trusted only when its batch steps the signed chain (``step_adds``).
"""

from __future__ import annotations

import hashlib
from typing import Iterable, Sequence

DOMAIN = b"RR/GATE/CHAIN/v1\x00"
HEAD = 64
# The shard's authority record (Lean ``Worker.encAuth``): key-set genesis pin 64, ratchet epoch 4, head 64, day 4, checkpoint
# 64, grant floor 8 (the highest grant serial admitted), rule-set digest 64 and rule-set version 4 (the newest rule-set
# record admitted; zero and 0 for none).
AUTH = 276
ZERO = bytes(HEAD)
Floors = tuple[int, int, int, bytes]  # grant serial, key-set epoch, rule-set version, rule-set digest
# A batch's ``adds`` as the producer stores it: the authority record, the state root after the batch, then the rows.
ROOT = AUTH + HEAD
# One RULES_ADDS row: the set tag (1 released, 2 unresolved), then Line.fields: id, pay, flow, member, payee, rendering, date,
# proc, units, cents at these widths.
_WIDTHS = (129, 261, 1, 129, 129, 129, 4, 129, 4, 8)
ROW = 1 + sum(_WIDTHS)


def leb(n: int) -> bytes:
    """Minimal unsigned LEB128."""
    if n < 0:
        raise ValueError("leb")
    out = bytearray()
    while n >= 128:
        out.append(n % 128 + 128)
        n //= 128
    out.append(n)
    return bytes(out)


def enc_line(fields: Sequence[int]) -> bytes:
    """A line's ten numbers (flow tag, member, payee, rendering, date, procedure, units, cents, id, payment) as LEBs."""
    if len(fields) != 10:
        raise ValueError("line")
    return b"".join(map(leb, fields))


def enc_set(as_of: int, count: int, rows: Sequence[Sequence[int]]) -> bytes:
    return leb(as_of) + leb(count) + leb(len(rows)) + b"".join(map(enc_line, rows))


def enc_delta(released: Iterable[Sequence[int]], unresolved: Iterable[Sequence[int]]) -> bytes:
    r, u = list(released), list(unresolved)
    return leb(len(r)) + b"".join(map(enc_line, r)) + leb(len(u)) + b"".join(map(enc_line, u))


def genesis(shard: int, as_of: int, pin: bytes) -> bytes:
    """The head of a shard under key-set genesis pin ``pin`` whose two sets are empty and dated ``as_of`` (what ``flat init``
    starts from)."""
    empty = enc_set(as_of, 0, [])
    return hashlib.sha3_512(DOMAIN + b"\x00" + leb(shard) + leb(len(pin)) + pin + empty + empty).digest()


def batch_digest(delta: bytes) -> bytes:
    """The digest of one batch on the chunk store (Lean ``Chunk.batchDigest``): ``delta`` is ``delta_of_adds``'s, the
    authority record with its length, then the appended rows."""
    return hashlib.sha3_512(DOMAIN + b"\x03" + delta).digest()


def step_root(head: bytes, digest: bytes, root: bytes) -> bytes:
    """The chunk store's chain step (Lean ``Chunk.chainStepR``): the head before, the batch digest, the state root after."""
    if type(head) is not bytes or len(head) != HEAD or len(digest) != HEAD or len(root) != HEAD:
        raise ValueError("head")
    return hashlib.sha3_512(DOMAIN + b"\x02" + head + digest + root).digest()


def floors_of(record: bytes | None) -> Floors:
    """(grant serial floor, key-set epoch, rule-set version, rule-set digest) of an authority record (``AUTH`` bytes);
    (0, 0, 0, ``ZERO``) for none or an empty record."""
    if not record:
        return 0, 0, 0, ZERO
    return (int.from_bytes(record[200:208], "big"), int.from_bytes(record[64:68], "big"),
            int.from_bytes(record[272:276], "big"), record[208:272])


def behind(rec: Floors, floor: Floors) -> bool:
    """Whether floors ``rec`` are below ``floor``: a lower grant serial, key-set epoch or rule-set version, or the same
    rule-set version under another digest (a fork), so a batch decided under ``rec`` can never pass ``floor``."""
    return rec[0] < floor[0] or rec[1] < floor[1] or rec[2] < floor[2] or (rec[2] == floor[2] and rec[3] != floor[3])


def delta_of_adds(adds: bytes) -> bytes | None:
    """The batch digest's input after its tag, from a batch's ``adds`` (the authority record, the state root, then released
    rows, then unresolved rows), or None for bytes shorter than a record and a root, rows that are not a whole number of
    rows, a tag other than 1 then 2, or a flow outside 1..3 (the producer then refuses the head)."""
    if len(adds) < ROOT:
        return None
    auth, adds = adds[:AUTH], adds[ROOT:]
    if len(adds) % ROW:
        return None
    sets: tuple[list[list[int]], list[list[int]]] = ([], [])
    last = 1
    for at in range(0, len(adds), ROW):
        tag, at = adds[at], at + 1
        if tag not in (1, 2) or tag < last:
            return None
        last = tag
        nums, o = [], at
        for w in _WIDTHS:
            nums.append(int.from_bytes(adds[o:o + w], "big"))
            o += w
        i, pay, flow, member, payee, rendering, date, proc, units, cents = nums
        if flow not in (1, 2, 3):
            return None
        sets[tag - 1].append([flow, member, payee, rendering, date, proc, units, cents, i, pay])
    return leb(AUTH) + auth + enc_delta(*sets)


def step_adds(head: bytes, adds: bytes) -> bytes | None:
    """The head after the batch whose ``adds`` (authority record, state root, rows) follow ``head``; None if they do not
    decode."""
    delta = delta_of_adds(adds)
    return None if delta is None else step_root(head, batch_digest(delta), adds[AUTH:ROOT])


def head_after(first: bytes, pin: bytes, batches: Iterable[bytes]) -> bytes | None:
    """``first`` stepped over each batch's ``adds`` in order; None if any does not decode, names another key-set pin than
    ``pin``, or does not follow the record of the batch before it (Lean ``ChunkIo.authFollows``: a lower key-set epoch,
    grant floor or rule-set version, another rule-set digest at the same version, or a version above 0 with digest zero)."""
    head, last = first, floors_of(None)
    for adds in batches:
        now = floors_of(adds[:AUTH])
        new = step_adds(head, adds)
        if new is None or adds[:64] != pin or behind(now, last) or (now[2] and now[3] == ZERO):
            return None
        head, last = new, now
    return head
