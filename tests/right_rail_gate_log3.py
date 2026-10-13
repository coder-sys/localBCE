"""Reference codec for the v3 tenant-log entry ``RR/GATE/TENANT-LOG/v3\\0`` (ENGINE-0 S1).

Byte-for-byte the encoder and decoder of ``lean/BlindLedger/Gate/Engine/Log.lean`` (``entryIn3``,
``decodeEntry3B``): tag, be8 idx, 64-byte prev, u8 kind, body.  Kinds: 0 batch, 1 resume (be4 shard
+ permit), 2 seal (be4 shard + tip), 3 segment.  Widths are fixed and big-endian; a registry row is
1 + 129 + 4 = 134 bytes.  Test-only reference: Lean decides, this only conforms to it.  A value that
does not fit its width raises ``Log3Error`` (the Lean statements hold under that same ``wf``).
Synthetic, nonpayment; moves no money.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Final
import unittest

TAG: Final = b"RR/GATE/TENANT-LOG/v3\x00"
DIGEST: Final = 64
ROW: Final = 134


class Log3Error(ValueError):
    """The bytes are not one entry, or a value does not fit its field."""


def be(width: int, value: int) -> bytes:
    if not 0 <= value < 256**width:
        raise Log3Error("width")
    return value.to_bytes(width, "big")


def lp(x: bytes) -> bytes:
    return be(4, len(x)) + x


def lps(xs: list[bytes]) -> bytes:
    return be(4, len(xs)) + b"".join(lp(x) for x in xs)


def reg_rows(rows: list[tuple[int, int, int]]) -> bytes:
    return b"".join(be(1, k) + be(129, i) + be(4, s) for k, i, s in rows)


def digest(x: bytes) -> bytes:
    if len(x) != DIGEST:
        raise Log3Error("digest")
    return x


def batch(shard: int, header: bytes, manifest: bytes, reqs: list[bytes], rows: list[tuple[int, int, int]],
          leaves: list[bytes]) -> bytes:
    return (be(1, 0) + be(4, shard) + lp(header) + lp(manifest) + lps(reqs) + lp(reg_rows(rows)) + lps(leaves))


def resume(shard: int, permit: bytes) -> bytes:
    return be(1, 1) + be(4, shard) + permit


def seal(shard: int, tip: bytes) -> bytes:
    return be(1, 2) + be(4, shard) + tip


def segment(first: int, last: int, last_entry: bytes, sha3_seg: bytes, sha512_seg: bytes, snap: bytes) -> bytes:
    return (be(1, 3) + be(8, first) + be(8, last) + digest(last_entry) + digest(sha3_seg) + digest(sha512_seg)
            + digest(snap))


def entry_in(idx: int, prev: bytes, body: bytes) -> bytes:
    return TAG + be(8, idx) + digest(prev) + body


def entry_digest(entry: bytes) -> bytes:
    return hashlib.sha3_512(entry).digest()


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data, self.pos = data, 0

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise Log3Error("short")
        self.pos += n
        return self.data[self.pos - n:self.pos]

    def num(self, width: int) -> int:
        return int.from_bytes(self.take(width), "big")

    def lp(self) -> bytes:
        return self.take(self.num(4))

    def many(self, one, count: int) -> list:
        return [one() for _ in range(count)]

    def rest(self) -> bytes:
        return self.take(len(self.data) - self.pos)


def decode(data: bytes) -> tuple[int, bytes, str, tuple]:
    """(idx, prev, kind, fields); refuses a wrong tag, a short input, an unknown kind and bytes after a BATCH or
    SEGMENT body.  A RESUME permit and a SEAL tip run to the end of the input, so bytes after them are part of it."""
    r = _Reader(data)
    if r.take(len(TAG)) != TAG:
        raise Log3Error("tag")
    idx, prev, kind = r.num(8), r.take(DIGEST), r.num(1)
    if kind == 0:
        shard, header, manifest = r.num(4), r.lp(), r.lp()
        reqs = r.many(r.lp, r.num(4))
        n = r.num(4)
        if n % ROW:
            raise Log3Error("rows")
        rows = r.many(lambda: (r.num(1), r.num(129), r.num(4)), n // ROW)
        leaves = r.many(r.lp, r.num(4))
        out = ("batch", (shard, header, manifest, reqs, rows, leaves))
    elif kind in (1, 2):
        shard = r.num(4)
        out = ("resume" if kind == 1 else "seal", (shard, r.rest()))
    elif kind == 3:
        out = ("segment", (r.num(8), r.num(8)) + tuple(r.take(DIGEST) for _ in range(4)))
    else:
        raise Log3Error("kind")
    if r.pos != len(data):
        raise Log3Error("trailing")
    return idx, prev, out[0], out[1]


def encode(idx: int, prev: bytes, kind: str, fields: tuple) -> bytes:
    body = {"batch": batch, "resume": resume, "seal": seal, "segment": segment}[kind](*fields)
    return entry_in(idx, prev, body)


def d(n: int) -> bytes:
    return hashlib.sha3_512(bytes([n])).digest()


def lean_leg(case: unittest.TestCase, module: str, runner: str, vectors: Path, saved: Path, want: str) -> None:
    """The built module is current, `lean --run <runner> <vectors>` prints `want`, and so does the saved output."""
    lake = shutil.which("lake") or os.path.join(os.path.expanduser("~"), ".elan", "bin", "lake")
    lean = vectors.parents[2] / "lean"
    built = subprocess.run([lake, "build", "--no-build", f"BlindLedger.Gate.Engine.{module}"], cwd=lean,
                           capture_output=True, text=True, timeout=600)
    case.assertEqual(built.returncode, 0, f"Engine.{module} is stale; run `lake build` in lean/\n" + built.stdout[-1500:])
    run = subprocess.run([lake, "env", "lean", "--run", f"BlindLedger/Gate/Engine/{runner}.lean", str(vectors)],
                         cwd=lean, capture_output=True, text=True, timeout=600)
    case.assertEqual(run.returncode, 0, run.stderr[-1500:])
    diff = [g for g, w in zip(run.stdout.splitlines(), want.splitlines()) if g != w]
    case.assertEqual(run.stdout, want, "first Lean lines that differ: " + " | ".join(diff[:4])[:1200])
    case.assertEqual(saved.read_text("utf-8"), want)


def emit_main(render) -> None:
    if len(sys.argv) == 3 and sys.argv[1] == "--emit":
        Path(sys.argv[2]).write_text(render(), encoding="utf-8", newline="\n")
    else:
        unittest.main()
