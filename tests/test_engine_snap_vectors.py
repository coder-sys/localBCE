"""ENGINE-0 S2/S3b: the ENGINE-SNAP/v2 snapshot codec and the S3b push fold against lean/BlindLedger/Gate/Engine/Snap.lean and
Log.lean.  Synthetic, nonpayment, non-PHI; test-only reference (Lean decides, this only conforms to it).

``tag || be8 (len-1) || head || lp(rhead || lp(reg rows) || be4 n || rows)``, a row ``be4 shard || own || sealed || live ||
last || base || pays``: own ``be4 n || (be8 epoch || be8 count)*``, sealed ``0 | 1 || lp tip``, live ``0 | 1``, last ``0 | 1
|| lp s || lp c``, base 64 bytes, pays ``be4 n || (be261 key || lp leaf)*``; shard, epoch and pay keys strictly ascending.
The decoder also refuses an own count of 0, a live shard on the zero base, a parked shard with own rows, a last or a nonzero
base (StateV2 parks only Shard.init plus a seal), an rhead other than reg's chain head, pays with no last and a pay leaf that
is not one whole Spec leaf of its shard keyed by its ``payNat`` (the encoder raises on the same).  A
``fold`` vector pushes v3 entries from the empty state or a leading snapshot (a BATCH needs a live shard and puts its rows
ahead of reg, a SEAL no resume tip, a SEGMENT a snap equal to the prior state's digest) and prints the result's snapshot
digest.  The Lean leg runs `lake env lean --run BlindLedger/Gate/Engine/SnapVectors.lean <vectors>` in lean/ against the
Python verdicts and LEAN_OUT.  Emit from the repo root with `python -m tests.test_engine_snap_vectors --emit <path>`.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import NamedTuple
import unittest

from app import right_rail_gate_codec as codec
from tests import right_rail_gate_log3 as log3
from tests.right_rail_gate_log3 import DIGEST, Log3Error, be, d, lp

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "tests" / "engine_log" / "snap_v2.vectors"
LEAN_OUT = ROOT / "tests" / "engine_log" / "snap_v2.lean.out"
TAG = b"RR/GATE/ENGINE-SNAP/v2\x00"
ZERO = bytes(DIGEST)
PAY = 261


class Shard(NamedTuple):
    own: tuple = ()
    sealed: "bytes | None" = None
    live: bool = False
    last: "tuple[bytes, bytes] | None" = None
    base: bytes = ZERO
    pays: tuple = ()


def tip_in(t: "tuple[bytes, bytes] | None") -> bytes:
    return be(1, 0) if t is None else be(1, 1) + lp(t[0]) + lp(t[1])


def row(k: int, s: Shard) -> bytes:
    if len(s.base) != DIGEST:
        raise Log3Error("digest")
    return (be(4, k) + be(4, len(s.own)) + b"".join(be(8, e) + be(8, c) for e, c in s.own)
            + (be(1, 0) if s.sealed is None else be(1, 1) + lp(s.sealed)) + be(1, s.live) + tip_in(s.last)
            + s.base + be(4, len(s.pays)) + b"".join(be(PAY, n) + lp(x) for n, x in s.pays))


def state_in(reg: list, rhead: bytes, rows: bytes, n: int) -> bytes:
    return rhead + lp(log3.reg_rows(reg)) + be(4, n) + rows


def pay_nat(program: str, payment: str) -> int:
    return int.from_bytes(bytes([1]) + b"".join(be(2, len(x)) + x.encode() for x in (program, payment)), "big")


def leaf_key(x: bytes) -> "tuple[int, int] | None":
    """Spec `pLeaf` on all of x, by reading its fields and re-encoding them with the product codec, then (shard, `payNat`)."""
    r = _R(x)
    ident, tag = lambda: r.take(r.num(2)).decode("latin-1"), lambda names: dict(enumerate(names, 1)).get(r.num(1))
    try:
        f = [r.take(len(codec.TOKEN)), ident(), ident(), r.num(4), tag(codec.FLOWS), r.num(8), ident(), r.take(32), ident(),
             r.num(8), ident(), r.take(DIGEST), tag(codec.OUTCOMES), tuple(ident() for _ in range(r.num(1))),
             tag(codec.AUTHORITIES)] + [r.take(DIGEST) for _ in range(4)] + [r.num(8) for _ in range(5)]
        return (f[3], pay_nat(f[2], f[6])) if codec.encode_token_leaf(codec.TokenLeaf(*f[1:])) == x else None
    except (Log3Error, codec.GateCodecError):
        return None


def wf(reg: list, rhead: bytes, shards: dict[int, Shard]) -> None:
    """Beyond layout: rhead = registry head, own counts > 0, no live zero base, a parked shard is Shard() plus a seal, pays need a
    last and leaf (shard, payNat)."""
    if rhead != log3.chain_head(reg) or any(s.live and s.base == ZERO or not all(c for _, c in s.own) or s.pays and not s.last
                                             or not s.live and (s.own or s.last or s.base != ZERO)
                                             or any(leaf_key(x) != (k, n) for n, x in s.pays) for k, s in shards.items()):
        raise Log3Error("wf")


def encode(length: int, head: bytes, reg: list, rhead: bytes, shards: dict[int, Shard], check: bool = True) -> bytes:
    """check=False is Lean's total encoder: a fold keeps a resumed shard on the zero base."""
    if len(head) != DIGEST or len(rhead) != DIGEST:
        raise Log3Error("digest")
    if check:
        wf(reg, rhead, shards)
    rows = b"".join(row(k, s) for k, s in sorted(shards.items()))
    return TAG + be(8, length - 1) + head + lp(state_in(reg, rhead, rows, len(shards)))


class _R(log3._Reader):
    def flag(self) -> int:
        v = self.num(1)
        if v > 1:
            raise Log3Error("flag")
        return v

    def asc(self, one) -> tuple:
        out = tuple(one() for _ in range(self.num(4)))
        if any(a[0] >= b[0] for a, b in zip(out, out[1:])):
            raise Log3Error("order")
        return out

    def tip(self) -> "tuple[bytes, bytes] | None":
        return (self.lp(), self.lp()) if self.flag() else None


def decode(data: bytes) -> tuple[int, bytes, list, bytes, dict[int, Shard]]:
    r = _R(data)
    if r.take(len(TAG)) != TAG:
        raise Log3Error("tag")
    idx, head = r.num(8), r.take(DIGEST)
    body = _R(r.lp())
    if r.rest():
        raise Log3Error("trailing")
    rhead, raw = body.take(DIGEST), body.lp()
    if len(raw) % 134:
        raise Log3Error("reg")
    reg = [(raw[i], int.from_bytes(raw[i + 1:i + 130], "big"), int.from_bytes(raw[i + 130:i + 134], "big"))
           for i in range(0, len(raw), 134)]
    rows = body.asc(lambda: (body.num(4), Shard(
        body.asc(lambda: (body.num(8), body.num(8))), body.lp() if body.flag() else None, bool(body.flag()),
        body.tip(), body.take(DIGEST), body.asc(lambda: (body.num(PAY), body.lp())))))
    if body.rest():
        raise Log3Error("trailing state")
    wf(reg, rhead, dict(rows))
    return idx + 1, head, reg, rhead, dict(rows)


def sdig(n: int, *rest, check: bool = True) -> bytes:
    """`snapDigest`; a fold's length 0 encodes as 1, as Lean's `len - 1` does."""
    return hashlib.sha3_512(encode(max(n, 1), *rest, check=check)).digest()


def fold(entries: list[bytes]) -> tuple[int, bytes, list, bytes, dict[int, Shard]]:
    """Log.lean `pushM` on BATCH, SEAL, RESUME and SEGMENT entries, after a leading snapshot if there is one."""
    lead = bool(entries) and entries[0].startswith(TAG)
    n, head, reg, rhead, shards = decode(entries[0]) if lead else (0, ZERO, [], ZERO, {})
    for e in entries[lead:]:
        idx, prev, kind, f = log3.decode(e)
        if (idx, prev) != (n, head):
            raise Log3Error("chain")
        if kind == "batch":
            if not shards.get(f[0], Shard()).live:
                raise Log3Error(kind)
            reg, rhead = f[4] + reg, log3.chain_head(f[4], rhead)
        elif kind == "segment":
            if f[5] != sdig(n, head, reg, rhead, shards, check=False):
                raise Log3Error("snap")
        else:
            s, t = shards.get(f[0], Shard()), _R(f[1]).tip() if kind == "resume" else None
            if s.live or ((s.sealed is not None or s.last is not None) if kind == "seal" else (t and t[0]) != s.sealed):
                raise Log3Error(kind)
            shards[f[0]] = s._replace(sealed=f[1]) if kind == "seal" else s._replace(live=True, last=t)
        n, head = n + 1, hashlib.sha3_512(e).digest()
    return n, head, reg, rhead, shards


def pay(payment: str, shard: int = 1, seq: int = 1) -> tuple[int, bytes]:
    """A pay row: an SDP payment of `shard` held for review in program P1, keyed by its payNat."""
    leaf = codec.TokenLeaf("T1", "P1", shard, "SDP", 0, payment, d(5)[:32], "R1", 1, "M1", ZERO, "HUMAN_REVIEW", (), "HOLD",
                           d(1), d(2), d(3), d(4), 0, 1, seq, 2, 3)
    return pay_nat("P1", payment), codec.encode_token_leaf(leaf)


REG = [(1, 5, 6), (255, 256**129 - 1, 2**32 - 1)]
TOP = Shard(((0, 1), (2**64 - 1, 2**64 - 1)), b"", True, (b"", b"c"), d(9), (pay("A", 2**32 - 1), pay("B" * 128, 2**32 - 1)))
THREE = {2**32 - 1: TOP, 0: Shard(live=True, base=d(6)), 7: Shard(sealed=d(2))}
GOOD = {
    "empty": (1, d(1), [], ZERO, {}),
    "three": (2**64, d(1), REG, log3.chain_head(REG), THREE),
    "sealed_live": (5, d(4), [], ZERO, {9: Shard(sealed=b"tip", live=True, last=(b"tip", b"cert"), base=d(2))}),
}
T1, T2 = d(8), d(10)
SEAL = ("seal", (3, T1))


def chain(*bodies: tuple[str, tuple], at: "tuple[int, bytes]" = (0, ZERO)) -> list[bytes]:
    out, head = [], at[1]
    for i, (kind, f) in enumerate(bodies, at[0]):
        out.append(log3.encode(i, head, kind, f))
        head = hashlib.sha3_512(out[-1]).digest()
    return out


def resume(t: "tuple[bytes, bytes] | None", shard: int = 3) -> tuple:
    return "resume", (shard, tip_in(t) + b"opaque sets")


def segment(*before: tuple[str, tuple], bad: bool = False) -> tuple:
    """A SEGMENT whose snap is the digest of the state after `before` (a wrong one if bad)."""
    return "segment", (0, 0, d(1), d(2), d(3), d(4) if bad else sdig(*fold(chain(*before)), check=False))


def lead(*bodies: tuple[str, tuple]) -> list[bytes]:
    """A fold that starts from a snapshot of shard 3 (parked, unsealed)."""
    return [encode(2, d(1), [], ZERO, {3: Shard()})] + chain(*bodies, at=(2, d(1)))


LIVE = encode(2, d(1), [], ZERO, {3: Shard(live=True, base=d(3)), 4: Shard(live=True, base=d(4)), 7: THREE[7]})
# Sealed shard 7 and 2 shards x 2 batches of 2 registry rows each; MID is the state after the first two.  PRE-S3e pins (review
# r2 HIGH-2): hand-built live shards, leaf b"l" is no Spec leaf, the batch writes no shard; S3e changes them.  Not E5 evidence.
BATCHES = [("batch", (k, b"h", b"m", [b"r"], [(1, 2 * i, k), (2, 2 * i + 1, k)], [b"l"])) for i, k in enumerate((3, 4, 3, 4))]
MID = fold([LIVE] + chain(*BATCHES[:2], at=(2, d(1))))
FOLDS = {
    "fold_seal_resume_tip": chain(SEAL, resume((T1, b"cert"))),
    "fold_resume_fresh": chain(resume(None, 4)),
    "fold_seg_ok": chain(segment()),
    "fold_seal_segment_resume_tip": chain(SEAL, segment(SEAL), resume((T1, b""))),
    "fold_lead_seal": lead(SEAL),
    "fold_batch_2x2": [LIVE] + chain(*BATCHES, at=(2, d(1))),
    "fold_batch_2x2_mid": [encode(*MID)] + chain(*BATCHES[2:], at=MID[:2]),
    "refuse_fold_batch_parked": chain(BATCHES[0]),
    "refuse_fold_batch_sealed": [LIVE] + chain(("batch", (7, *BATCHES[0][1][1:])), at=(2, d(1))),
    "refuse_fold_seal_resume_other_tip": chain(SEAL, resume((T2, b"cert"))),
    "refuse_fold_seal_resume_no_tip": chain(SEAL, resume(None)),
    "refuse_fold_fresh_resume_with_tip": chain(resume((T1, b"cert"), 4)),
    "refuse_fold_resume_twice": chain(SEAL, resume((T1, b"")), resume((T1, b""))),
    "refuse_fold_resume_then_seal": chain(resume(None, 4), ("seal", (4, T1))),
    "refuse_fold_seal_twice": chain(SEAL, SEAL),
    "refuse_fold_tip_flag_2": chain(("resume", (4, b"\x02"))),
    "refuse_fold_tip_truncated": chain(SEAL, ("resume", (3, resume((T1, b"cert"))[1][1][:-12]))),
    "refuse_fold_seg_wrong_snap": chain(SEAL, segment(SEAL, bad=True)),
    "refuse_fold_seg_snap_before_seal": chain(SEAL, segment()),
    "refuse_fold_bad_prev": chain(SEAL) + [log3.encode(1, ZERO, *resume((T1, b"")))],
}


def vectors() -> list[tuple[str, "bytes | list[bytes]", bool]]:
    """(name, snapshot bytes or a fold's entries, must it be accepted)."""
    out: list = [(f"ok_{n}", encode(*g), True) for n, g in GOOD.items()]
    one, three = encode(*GOOD["sealed_live"]), encode(*GOOD["three"])
    at = len(TAG) + 8 + DIGEST  # lp(state)
    s1, s3 = one[at + 4:], three[at + 4:]
    c1, c3 = DIGEST + 4, DIGEST + 4 + 134 * len(REG)  # shard count
    r9 = row(9, GOOD["sealed_live"][4][9])

    def state(b: bytes, s: bytes) -> bytes:  # same snapshot head, new inner state
        return b[:at] + lp(s)

    def rows(*rs: bytes) -> bytes:  # raw rows, no ordering
        return state(one, state_in([], ZERO, b"".join(rs), len(rs)))
    live = lambda **f: Shard(live=True, base=d(6), **f)  # so a parked-shard refusal does not mask the one under test
    paid = lambda *ps: rows(row(1, live(last=(b"", b"c"), pays=ps)))  # shard 1 with a last and these pays

    out += [
        ("refuse_empty", b"", False),
        ("refuse_only_tag", TAG, False),
        ("refuse_v1_tag", b"RR/GATE/ENGINE-SNAP/v1\x00" + one[len(TAG):], False),
        ("refuse_bad_tag", b"RR/GATE/ENGINE-SNAP/v3\x00" + one[len(TAG):], False),
        ("refuse_trailing", one + b"\x00", False),
        ("refuse_truncated", one[:-1], False),
        ("refuse_state_trailing", state(three, s3 + b"\x00"), False),
        ("refuse_count_over", state(three, s3[:c3] + be(4, 4) + s3[c3 + 4:]), False),
        ("refuse_count_under", state(three, s3[:c3] + be(4, 2) + s3[c3 + 4:]), False),
        ("refuse_lp_over", three[:at] + be(4, len(s3) + 1) + three[at + 4:], False),
        ("refuse_reg_partial_row", state(one, ZERO + lp(b"\x00" * 133) + s1[c1:]), False),
        ("refuse_sealed_flag_2", rows(r9[:8] + b"\x02" + r9[9:]), False),
        ("refuse_live_flag_2", rows(r9[:16] + b"\x02" + r9[17:]), False),
        ("refuse_last_flag_2", rows(r9[:17] + b"\x02" + r9[18:]), False),
        ("refuse_keys_equal", rows(r9, r9), False),
        ("refuse_keys_descending", rows(row(7, Shard()), row(0, Shard())), False),
        ("refuse_own_epochs_equal", rows(row(1, live(own=((5, 1), (5, 2))))), False),
        ("refuse_own_epochs_descending", rows(row(1, live(own=((6, 1), (5, 2))))), False),
        ("refuse_pays_keys_equal", paid(pay("A"), pay("A", seq=2)), False),
        ("refuse_pays_keys_descending", paid(pay("B"), pay("A")), False),
        ("refuse_pay_key_mismatch", paid((pay("B")[0], pay("A")[1])), False),
        ("refuse_pay_leaf_trailing", paid((pay("A")[0], pay("A")[1] + b"\x00")), False),
        ("refuse_pay_shard_mismatch", paid(pay("A", 0)), False),
        ("refuse_pays_no_last", rows(row(1, Shard(pays=(pay("A"),)))), False),
        ("refuse_rhead_forged", state(three, d(3) + s3[DIGEST:]), False),
        ("refuse_own_count_0", rows(row(1, live(own=((5, 0),)))), False),
        ("refuse_parked_forged", rows(row(1, Shard(sealed=b"t", base=d(7)))), False),
        ("refuse_parked_forged_own", rows(row(1, Shard(own=((5, 1),)))), False),
        ("refuse_parked_forged_last", rows(row(1, Shard(last=(b"", b"c")))), False),
        ("refuse_live_zero_base", rows(row(1, Shard(live=True))), False),
        ("refuse_base_short", rows(row(1, Shard())[:-4 - DIGEST] + d(1)[:-1] + be(4, 0)), False),
    ]
    return out + [(n, es, not n.startswith("refuse")) for n, es in FOLDS.items()]


def verdict(data: "bytes | list[bytes]") -> str:
    try:
        snap = fold(data) if isinstance(data, list) else decode(data)
    except Log3Error:
        return "refuse"
    if not isinstance(data, list):
        assert encode(*snap) == data
    return "ok " + sdig(*snap, check=False).hex()


class SnapCodec(unittest.TestCase):
    def test_roundtrip(self) -> None:
        for name, g in GOOD.items():
            with self.subTest(name):
                self.assertEqual(decode(encode(*g)), (g[0], g[1], g[2], g[3], dict(sorted(g[4].items()))))

    def test_vectors(self) -> None:
        names = [n for n, _, _ in vectors()]
        self.assertEqual(len(names), len(set(names)))
        for name, data, ok in vectors():
            with self.subTest(name):
                self.assertEqual(verdict(data).startswith("ok"), ok)

    def test_seal_then_matching_resume_keeps_seal_and_sets_live(self) -> None:
        # PRE-S3e pin (review r2 HIGH-2): base stays ZERO after a resume; S3e computes StateV2's base and changes this.
        shard = fold(FOLDS["fold_seal_resume_tip"])[4][3]
        self.assertEqual(shard, Shard(sealed=T1, live=True, last=(T1, b"cert")))

    def test_batch_fold_replays_from_mid_snapshot(self) -> None:  # PRE-S3e pin, not E5 evidence (see BATCHES)
        self.assertEqual(verdict(FOLDS["fold_batch_2x2"]), verdict(FOLDS["fold_batch_2x2_mid"]))
        self.assertEqual(fold(FOLDS["fold_batch_2x2"])[2], [r for _, f in BATCHES[::-1] for r in f[4]])

    def test_encoder_refuses_values_that_do_not_fit(self) -> None:
        for args in [(0, d(1), [], ZERO, {}), (2**64 + 1, d(1), [], ZERO, {}), (1, d(1)[:-1], [], ZERO, {}),
                     (1, d(1), [], ZERO + b"\x00", {}), (1, d(1), [], ZERO, {2**32: Shard()}),
                     (1, d(1), [], ZERO, {0: Shard(live=True, base=b"")}), (1, d(1), [(256, 0, 0)], ZERO, {}),
                     (1, d(1), [], d(5), {}), (1, d(1), [], ZERO, {0: Shard(live=True, base=d(6), own=((1, 0),))}),
                     (1, d(1), [], ZERO, {0: Shard(live=True)})]:
            with self.subTest(args), self.assertRaises(Log3Error):
                encode(*args)

    def test_size_is_per_shard_not_per_line(self) -> None:
        self.assertEqual(len(encode(*GOOD["empty"])), len(TAG) + 8 + 2 * DIGEST + 12)
        one = (1, d(1), [], ZERO, {0: Shard()})
        self.assertEqual(len(encode(*one)) - len(encode(*GOOD["empty"])), 4 + 4 + 1 + 1 + 1 + DIGEST + 4)


class SnapAgainstLean(unittest.TestCase):
    def test_python_matches_lean(self) -> None:
        log3.lean_leg(self, "Snap", "SnapVectors", VECTORS, LEAN_OUT, vectors(), verdict)


if __name__ == "__main__":
    log3.emit_main(vectors)
