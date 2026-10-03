"""Checked mark files beside the gate's local SQLite stores (id registry, checkpoint producer), synthetic, activation=false.

A mark records a store's last durable state so a restored older store is refused.  Each record is
body || SHA3-256(domain || body); each store kind has its own domain, so one kind's mark never passes as
another's.  Records are appended and fsynced.  A last record that fails its check is a torn write (never fsynced,
so nothing relied on it): it is skipped, and the next write rewrites the file without it.  A bad record before
the last, or keys that do not strictly rise, make the mark corrupt.  Marks from before the check (unchecked 72-
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


def read(path: Path, domain: bytes, body_len: int, key_len: int) -> list[bytes] | None:
    """The verified bodies, oldest first, or None for a corrupt mark.  Each body's first ``key_len`` bytes are its
    big-endian key, which must strictly rise."""
    data = path.read_bytes() if path.exists() else b""
    records = [data[at:at + body_len + CHECK] for at in range(0, len(data), body_len + CHECK)]
    if records and records[-1] != _record(domain, records[-1][:body_len]):  # a short record never matches
        records.pop()
    if any(r != _record(domain, r[:body_len]) for r in records) or any(a[:key_len] >= b[:key_len] for a, b in zip(records, records[1:])):
        return None
    return [r[:body_len] for r in records]


def append(path: Path, domain: bytes, bodies: list[bytes], body: bytes) -> None:
    """Add ``body`` after ``bodies``, what ``read`` returned: append and fsync, or, when the file holds anything else
    (a torn tail, or no file yet), rewrite it whole (temporary file, fsync, rename, best-effort directory fsync)."""
    clean = path.exists() and path.stat().st_size == len(bodies) * (len(body) + CHECK)
    target = path if clean else path.with_name(f"{path.name}.tmp")
    with open(target, "ab" if clean else "wb") as handle:
        handle.write(b"".join(_record(domain, b) for b in ([body] if clean else [*bodies, body])))
        handle.flush()
        os.fsync(handle.fileno())
    if clean:
        return
    os.replace(target, path)
    with contextlib.suppress(OSError):  # Windows cannot open a directory to sync it
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
