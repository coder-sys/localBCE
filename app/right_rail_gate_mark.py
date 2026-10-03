"""Checked mark files beside the gate's local SQLite stores (id registry, checkpoint producer), synthetic, activation=false.

A mark records a store's last durable state so a restored older store is refused.  Each record is
body || SHA3-256(domain || body); each store kind has its own domain, so one kind's mark never passes as
another's.  Records are appended and fsynced.  Only the tail carries meaning, so a read looks at the last two
whole records and never at earlier ones: per-operation work does not grow with the file.  The mark is the last
record if its check verifies; otherwise (a torn write, never fsynced, so nothing relied on it) the one before it,
which must verify.  Bytes after the last whole record are a torn tail too and are ignored.  Two verified records
must have strictly rising keys.  The next write cuts the file back to the mark and appends.  A damaged record
deeper in the file is not detected and cannot change the outcome.  Marks from before the check (unchecked 72-
and 80-byte records) do not read: there is no migration path (synthetic; no store was deployed).
"""

from __future__ import annotations

import contextlib
import hashlib
import os
from pathlib import Path
from typing import Final

CHECK: Final = 32  # the SHA3-256 after each body


def _record(domain: bytes, body: bytes) -> bytes:
    return body + hashlib.sha3_256(domain + body).digest()


class MarkCorrupt(ValueError):
    """Neither of the last two records verifies, or their keys do not rise."""


def read(path: Path, domain: bytes, body_len: int, key_len: int) -> tuple[bytes | None, int]:
    """(the mark's body, the byte length of the file up to and including it), or (None, 0) for no mark.  Each body's
    first ``key_len`` bytes are its big-endian key.  Reads at most two records."""
    size = body_len + CHECK
    try:
        with open(path, "rb") as handle:
            whole = handle.seek(0, os.SEEK_END) // size
            start = max(whole - 2, 0) * size
            handle.seek(start)
            records = [handle.read(size) for _ in range(whole - start // size)]
    except FileNotFoundError:
        return None, 0
    ok = [r == _record(domain, r[:body_len]) for r in records]
    if not ok or (len(ok) == 1 and not ok[0]):  # empty, or a first write torn
        return None, 0
    if not ok[-1] and not ok[0]:
        raise MarkCorrupt
    at = len(ok) - 1 if ok[-1] else 0
    if at and ok[0] and records[0][:key_len] >= records[1][:key_len]:
        raise MarkCorrupt
    return records[at][:body_len], start + (at + 1) * size


def append(path: Path, domain: bytes, end: int, body: bytes) -> None:
    """Cut the file to ``end``, what ``read`` returned (dropping a torn tail; 0 for none), then append ``body`` and fsync.
    The records before ``end`` are never rewritten; a new file also gets a best-effort directory fsync."""
    new = not path.exists()
    with open(path, "ab") as handle:
        handle.truncate(end)
        handle.write(_record(domain, body))
        handle.flush()
        os.fsync(handle.fileno())
    if new:
        with contextlib.suppress(OSError):  # Windows cannot open a directory to sync it
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
