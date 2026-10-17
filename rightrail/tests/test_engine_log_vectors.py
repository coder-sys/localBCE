"""ENGINE-0 S1: the v3 tenant-log entry codec (tests/right_rail_gate_log3.py) against
lean/BlindLedger/Gate/Engine/Log.lean.  Synthetic, nonpayment, non-PHI.

The Lean leg runs `lake env lean --run BlindLedger/Gate/Engine/LogVectors.lean <vectors>` in lean/
live and checks its output against the Python verdicts and the saved LEAN_OUT.
Emit the vector file from the repo root with `python -m tests.test_engine_log_vectors --emit <path>`.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
import unittest

from tests import right_rail_gate_log3 as log3

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "tests" / "engine_log" / "log3_v1.vectors"
LEAN_OUT = ROOT / "tests" / "engine_log" / "log3_v1.lean.out"
LOG_LEAN = ROOT / "lean" / "BlindLedger" / "Gate" / "Engine" / "Log.lean"


d = log3.d
PREV = d(0)
ROWS = [(1, 2**1031, 7), (0, 5, 0), (255, 0, 2**32 - 1)]
GOOD = {
    "batch": (3, d(1), d(2), [b"", b"req-a", d(3)], ROWS, [d(4), d(5)]),
    "batch_empty": (0, b"", b"", [], [], []),
    "resume": (9, b"permit-bytes"),
    "resume_empty_permit": (0, b""),
    "seal": (2**32 - 1, d(6)),
    "segment": (0, 2**64 - 1, d(7), d(8), d(9), d(10)),
}
KIND = {"batch_empty": "batch", "resume_empty_permit": "resume"}


def good(name: str) -> bytes:
    return log3.encode(11, PREV, KIND.get(name, name), GOOD[name])


def vectors() -> list[tuple[str, bytes, bool]]:
    """(name, bytes, must the entry decode)."""
    out = [(f"ok_{n}", good(n), True) for n in GOOD]
    seg, bat, res, sea = good("segment"), good("batch"), good("resume"), good("seal")
    kind_at = len(log3.TAG) + 8 + 64
    rows_prefix = log3.lp(log3.reg_rows(ROWS))
    at = bat.index(rows_prefix)
    reqs_at = bat.index(log3.lps(GOOD["batch"][3]))
    header_at = kind_at + 1 + 4
    out += [
        ("refuse_bad_tag", b"RR/GATE/TENANT-LOG/v2\x00" + seg[len(log3.TAG):], False),
        ("refuse_tag_no_nul", log3.TAG[:-1] + b"\x01" + seg[len(log3.TAG):], False),
        ("refuse_trailing_segment", seg + b"\x00", False),
        ("refuse_trailing_batch", bat + b"\x00", False),
        ("refuse_truncated_segment", seg[:-1], False),
        ("refuse_truncated_batch", bat[:-1], False),
        ("refuse_only_tag", log3.TAG, False),
        ("refuse_kind_4", seg[:kind_at] + b"\x04" + seg[kind_at + 1:], False),
        ("refuse_rows_not_134", bat[:at] + (len(rows_prefix) - 4 + 1).to_bytes(4, "big") + bat[at + 4:], False),
        ("refuse_empty", b"", False),
        ("refuse_resume_short_shard", res[:kind_at + 4], False),
        ("refuse_seal_short_shard", sea[:kind_at + 4], False),
        ("refuse_kind_ff", seg[:kind_at] + b"\xff" + seg[kind_at + 1:], False),
        ("refuse_reqs_count_over", bat[:reqs_at] + (len(GOOD["batch"][3]) + 1).to_bytes(4, "big") + bat[reqs_at + 4:],
         False),
        ("refuse_header_len_max", bat[:header_at] + b"\xff" * 4 + bat[header_at + 4:], False),
        ("refuse_truncated_row", bat[:at + 4 + log3.ROW - 1], False),
        ("refuse_shifted_tag", log3.TAG[:-1] + seg[len(log3.TAG):], False),
        ("ok_resume_trailing_is_permit", res + b"\x00", True),
        ("ok_seal_trailing_is_tip", sea + b"\x00", True),
    ]
    return out


def verdict(data: bytes) -> str:
    try:
        idx, prev, kind, fields = log3.decode(data)
    except log3.Log3Error:
        return "refuse"
    assert log3.encode(idx, prev, kind, fields) == data
    return "ok " + hashlib.sha3_512(data).hexdigest()


class Log3Codec(unittest.TestCase):
    def test_roundtrip_every_kind(self) -> None:
        for name in GOOD:
            with self.subTest(name):
                data = good(name)
                idx, prev, kind, fields = log3.decode(data)
                self.assertEqual((idx, prev, kind, fields), (11, PREV, KIND.get(name, name), GOOD[name]))

    def test_widths_match_the_lean_spec(self) -> None:
        self.assertEqual(len(log3.reg_rows([(1, 2, 3)])), log3.ROW)
        text = LOG_LEAN.read_text("utf-8")
        for needle in ('"RR/GATE/TENANT-LOG/v3".toUTF8.toList ++ [0]', "regRowWidth : Nat := 134"):
            self.assertIn(needle, text)

    def test_vectors_unique_deterministic_and_decided(self) -> None:
        names = [n for n, _, _ in vectors()]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(vectors(), vectors())
        for name, data, ok in vectors():
            with self.subTest(name):
                self.assertEqual(verdict(data).startswith("ok"), ok)

    def test_encoder_refuses_values_that_do_not_fit(self) -> None:
        bad = [
            lambda: log3.encode(2**64, PREV, "resume", GOOD["resume"]),
            lambda: log3.encode(-1, PREV, "resume", GOOD["resume"]),
            lambda: log3.encode(0, PREV[:-1], "resume", GOOD["resume"]),
            lambda: log3.encode(0, PREV, "resume", (2**32, b"")),
            lambda: log3.encode(0, PREV, "seal", (-1, b"")),
            lambda: log3.encode(0, PREV, "batch", (2**32, b"", b"", [], [], [])),
            lambda: log3.encode(0, PREV, "batch", (0, b"", b"", [], [(256, 0, 0)], [])),
            lambda: log3.encode(0, PREV, "batch", (0, b"", b"", [], [(0, 256**129, 0)], [])),
            lambda: log3.encode(0, PREV, "batch", (0, b"", b"", [], [(0, 0, 2**32)], [])),
            lambda: log3.encode(0, PREV, "segment", (2**64, 0, d(1), d(1), d(1), d(1))),
            lambda: log3.encode(0, PREV, "segment", (0, 0, d(1)[:-1], d(1), d(1), d(1))),
            lambda: log3.encode(0, PREV, "segment", (0, 0, d(1), d(1), d(1), d(1) + b"\x00")),
        ]
        for i, f in enumerate(bad):
            with self.subTest(i), self.assertRaises(log3.Log3Error):
                f()


class Log3AgainstLean(unittest.TestCase):
    def test_python_matches_lean(self) -> None:
        log3.lean_leg(self, "Log", "LogVectors", VECTORS, LEAN_OUT, vectors(), verdict)


if __name__ == "__main__":
    log3.emit_main(vectors)
