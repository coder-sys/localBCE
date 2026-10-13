"""ENGINE-0 S2: the ENGINE-SNAP/v1 snapshot codec against lean/BlindLedger/Gate/Engine/Snap.lean.
Synthetic, nonpayment, non-PHI; test-only reference (Lean decides, this only conforms to it).

``tag || be8 (len-1) || head || lp(rhead || be4 n || rows)``, a row ``be4 shard || (0 | 1 || lp tip)
|| live``, rows strictly ascending by shard.  The Lean leg runs
`lake env lean --run BlindLedger/Gate/Engine/SnapVectors.lean <vectors>` in lean/ and checks its output
against the Python verdicts and the saved LEAN_OUT.  Emit the vector file from the repo root with
`python -m tests.test_engine_snap_vectors --emit <path>`.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

from tests.right_rail_gate_log3 import DIGEST, Log3Error, be, lp

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "tests" / "engine_log" / "snap_v1.vectors"
LEAN_OUT = ROOT / "tests" / "engine_log" / "snap_v1.lean.out"
LEAN = ROOT / "lean"
TAG = b"RR/GATE/ENGINE-SNAP/v1\x00"


def encode(length: int, head: bytes, rhead: bytes, shards: dict[int, tuple["bytes | None", bool]]) -> bytes:
    if len(head) != DIGEST or len(rhead) != DIGEST:
        raise Log3Error("digest")
    rows = b"".join(be(4, k) + (be(1, 0) if t is None else be(1, 1) + lp(t)) + be(1, live)
                    for k, (t, live) in sorted(shards.items()))
    return TAG + be(8, length - 1) + head + lp(rhead + be(4, len(shards)) + rows)


def decode(data: bytes) -> tuple[int, bytes, bytes, dict[int, tuple["bytes | None", bool]]]:
    def take(b: bytes, n: int) -> tuple[bytes, bytes]:
        if n > len(b):
            raise Log3Error("short")
        return b[:n], b[n:]

    def num(b: bytes, w: int) -> tuple[int, bytes]:
        x, b = take(b, w)
        return int.from_bytes(x, "big"), b

    def flag(b: bytes) -> tuple[int, bytes]:
        v, b = num(b, 1)
        if v > 1:
            raise Log3Error("flag")
        return v, b

    tag, b = take(data, len(TAG))
    if tag != TAG:
        raise Log3Error("tag")
    idx, b = num(b, 8)
    head, b = take(b, DIGEST)
    n, b = num(b, 4)
    body, b = take(b, n)
    if b:
        raise Log3Error("trailing")
    rhead, body = take(body, DIGEST)
    count, body = num(body, 4)
    shards: dict[int, tuple[bytes | None, bool]] = {}
    last = -1
    for _ in range(count):
        k, body = num(body, 4)
        sealed, body = flag(body)
        tip = None
        if sealed:
            w, body = num(body, 4)
            tip, body = take(body, w)
        live, body = flag(body)
        if k <= last:
            raise Log3Error("order")
        last, shards[k] = k, (tip, bool(live))
    if body:
        raise Log3Error("trailing state")
    return idx + 1, head, rhead, shards


def d(n: int) -> bytes:
    return hashlib.sha3_512(bytes([n])).digest()


THREE = {2**32 - 1: (b"", True), 0: (None, True), 7: (d(2), False)}
GOOD = {
    "empty": (1, d(1), bytes(DIGEST), {}),
    "three": (2**64, d(1), d(3), THREE),
    "sealed_live": (5, d(4), d(5), {9: (b"tip", True)}),
}


def vectors() -> list[tuple[str, bytes, bool]]:
    """(name, bytes, must the snapshot decode)."""
    out = [(f"ok_{n}", encode(*g), True) for n, g in GOOD.items()]
    one, three = encode(*GOOD["sealed_live"]), encode(*GOOD["three"])
    at = len(TAG) + 8 + DIGEST  # lp(state)
    rows = at + 4 + DIGEST + 4  # first row
    n3 = int.from_bytes(three[at:at + 4], "big")

    def state(b: bytes, s: bytes) -> bytes:  # same snapshot head, new inner state
        return b[:at] + lp(s)

    s1, s3 = one[at + 4:], three[at + 4:]
    out += [
        ("refuse_empty", b"", False),
        ("refuse_only_tag", TAG, False),
        ("refuse_bad_tag", b"RR/GATE/ENGINE-SNAP/v2\x00" + one[len(TAG):], False),
        ("refuse_trailing", one + b"\x00", False),
        ("refuse_truncated", one[:-1], False),
        ("refuse_state_trailing", state(three, s3 + b"\x00"), False),
        ("refuse_count_over", state(three, s3[:DIGEST] + be(4, 4) + s3[DIGEST + 4:]), False),
        ("refuse_count_under", state(three, s3[:DIGEST] + be(4, 2) + s3[DIGEST + 4:]), False),
        ("refuse_lp_over", three[:at] + be(4, n3 + 1) + three[at + 4:], False),
        ("refuse_sealed_flag_2", one[:rows + 4] + b"\x02" + one[rows + 5:], False),
        ("refuse_live_flag_2", one[:-1] + b"\x02", False),
        ("refuse_keys_equal", state(one, s1[:DIGEST] + be(4, 2) + s1[DIGEST + 4:] * 2), False),
        ("refuse_keys_descending", state(three, s3[:DIGEST] + be(4, 2) + be(4, 7) + b"\x00\x01" + be(4, 0) + b"\x00\x01"),
         False),
    ]
    return out


def verdict(data: bytes) -> str:
    try:
        snap = decode(data)
    except Log3Error:
        return "refuse"
    assert encode(*snap) == data
    return "ok " + hashlib.sha3_512(data).hexdigest()


class SnapCodec(unittest.TestCase):
    def test_roundtrip(self) -> None:
        for name, g in GOOD.items():
            with self.subTest(name):
                self.assertEqual(decode(encode(*g)), (g[0], g[1], g[2], dict(sorted(g[3].items()))))

    def test_vectors(self) -> None:
        names = [n for n, _, _ in vectors()]
        self.assertEqual(len(names), len(set(names)))
        for name, data, ok in vectors():
            with self.subTest(name):
                self.assertEqual(verdict(data).startswith("ok"), ok)

    def test_encoder_refuses_values_that_do_not_fit(self) -> None:
        for args in [(0, d(1), d(1), {}), (2**64 + 1, d(1), d(1), {}), (1, d(1)[:-1], d(1), {}),
                     (1, d(1), d(1) + b"\x00", {}), (1, d(1), d(1), {2**32: (None, False)})]:
            with self.subTest(args[0]), self.assertRaises(Log3Error):
                encode(*args)

    def test_size_is_per_shard_not_per_line(self) -> None:
        self.assertEqual(len(encode(*GOOD["empty"])), len(TAG) + 8 + 2 * DIGEST + 8)
        self.assertEqual(len(encode(*GOOD["three"])) - len(encode(*GOOD["empty"])), 6 + 10 + 74)


class SnapAgainstLean(unittest.TestCase):
    def test_python_matches_lean(self) -> None:
        self.assertEqual(VECTORS.read_text("utf-8"), render(), "stale vector file; re-emit it")
        lake = shutil.which("lake") or os.path.join(os.path.expanduser("~"), ".elan", "bin", "lake")
        built = subprocess.run([lake, "build", "--no-build", "BlindLedger.Gate.Engine.Snap"], cwd=LEAN,
                               capture_output=True, text=True, timeout=600)
        self.assertEqual(built.returncode, 0, "Engine.Snap is stale; run `lake build` in lean/\n" + built.stdout[-1500:])
        run = subprocess.run([lake, "env", "lean", "--run", "BlindLedger/Gate/Engine/SnapVectors.lean", str(VECTORS)],
                             cwd=LEAN, capture_output=True, text=True, timeout=600)
        self.assertEqual(run.returncode, 0, run.stderr[-1500:])
        want = "".join(f"{name} {verdict(data)}\n" for name, data, _ in vectors())
        self.assertEqual(run.stdout, want)
        self.assertEqual(LEAN_OUT.read_text("utf-8"), want)


def render() -> str:
    return "".join(f"{name} {data.hex()}\n" for name, data, _ in vectors())


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--emit":
        Path(sys.argv[2]).write_text(render(), encoding="utf-8", newline="\n")
    else:
        unittest.main()
