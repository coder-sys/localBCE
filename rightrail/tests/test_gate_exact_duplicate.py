"""Exact duplicates answered at once (Constitution I.4; docs/RIGHTRAIL_FULL_STACK_TARGET.md section 6): frozen acceptance
tests, failing until the engine answers `ANSWERED` and the codec carries `TOKEN/v3` and `DECIDE-REQUEST/v2`.  Frames go
to one engine on one store in turn (``tests/test_gate_authority_frames.py``).  Synthetic, non-PHI.
"""

from __future__ import annotations

from dataclasses import replace
from functools import lru_cache
from pathlib import Path
import tempfile
import unittest

from app import right_rail_gate_codec as gate
from app import right_rail_gate_decide as decide
from tests import _gate_authority as au
from tests import _gate_shards as g
from tests import test_gate_authority_frames as af
from tests import test_gate_cause_release as cr
from tests import test_right_rail_gate_formats as fx

F, NONE, CLEAN, HELD = af.F, af.NONE, af.CLEAN, af.HELD
KEY = g.member(1001, 0)  # CLEAN's and HELD's member
_, _, _, L10_DATE, _, _, L10_CENTS = map(int, g.claim(10, False).split())  # CLEAN's line L10: payee P7001, rendering R7001, C99213, 1 unit
L12_CENTS = int(g.claim(12, False).split()[6])  # HELD's line L12, dated g.BAD_DATE


def line(i: str, date: int = L10_DATE, cents: int = L10_CENTS, proc: str = "C99213", rendering: str = "R7001") -> bytes:
    return gate.encode_line("FFS_CLAIM", i, KEY, "P7001", rendering, date, proc, 1, cents)


def req(payment: str, *lines: tuple[bytes, int]) -> gate.DecideRequest:
    return gate.DecideRequest(fx.TENANT, fx.PROGRAM, "FFS_CLAIM", "cmd-" + payment, payment, KEY, "P7001", sum(c for _, c in lines),
                              fx.PERIOD, tuple(b for b, _ in lines), tuple(sorted((fx.D[2], fx.D[5]))))


DUP = req("pay-dup", (line("L90"), L10_CENTS))  # L10 in every field but the line id
MIXED = req("pay-mix", (line("L91"), L10_CENTS), (line("L92", 20270309, 7000, "C99214"), 7000))  # L10 again beside a clean line
NEAR = req("pay-near", (line("L93", cents=L10_CENTS + 77), L10_CENTS + 77))  # L10's near key, other cents
RENDER = req("pay-rnd", (line("L94", rendering="R7002"), L10_CENTS))  # L10's exact key, another rendering party
HELD_TWIN = req("pay-dh", (line("L95", g.BAD_DATE, L12_CENTS), L12_CENTS))  # HELD's L12, which waits for a person
EARLIER = (("L90", fx.PROGRAM, CLEAN.payment_id, "L10"),)
enc = gate.encode_decide_request
allow = cr.allow


def cases() -> dict[str, list[dict]]:
    a, dup = enc(CLEAN), enc(DUP)
    return {
        "a_paid_line_sent_again_is_answered": [F(allow(), [a]), F(allow(), [dup])],
        "a_paid_line_beside_a_clean_one": [F(allow(), [a]), F(allow(), [enc(MIXED)])],
        "answered_again_when_resent": [F(allow(), [a]), F(allow(), [dup]), F(allow(), [dup])],
        "a_bypass_cannot_release_an_answered_payment": [F(allow(), [a]), F(allow(), [dup], [
            au.bypass(fx.PROGRAM, DUP.payment_id, au.digest(dup), af.BYPASSABLE)])],
        "a_near_repeat_goes_to_a_person": [F(allow(), [a]), F(allow(), [enc(NEAR)])],
        "the_exact_key_with_another_rendering_party_stays_held": [F(allow(), [a]), F(allow(), [enc(RENDER)])],
        "a_repeat_in_one_batch_is_not_paid_yet": [F(allow(), [a, dup])],
        "a_repeat_of_a_held_line_stays_held": [F(allow(), [enc(HELD)]), F(allow(), [enc(HELD_TWIN)])],
        "a_redecision_is_not_answered_by_its_own_lines": [F(allow(), [a]), F(allow(), [a], redo=(af.pay_number(CLEAN),))],
    }


@lru_cache(maxsize=None)
def results() -> dict[str, list]:
    out = {}
    for name, frames in cases().items():
        with tempfile.TemporaryDirectory() as tmp:
            out[name] = af.run_case(frames, Path(tmp))
    return out


def pays(name: str) -> list[decide.Pay]:
    return [p for _, ps, _ in results()[name] for p in ps]


class StaysWithAPersonToday(unittest.TestCase):
    """What the amendment leaves as it is: these pass before it is built."""

    def test_what_is_not_an_exact_repeat_of_a_paid_line(self):
        near = pays("a_near_repeat_goes_to_a_person")
        self.assertEqual([(p.outcome, p.reasons) for p in near], [("ALLOW", ()), ("HUMAN_REVIEW", ("FFS_NEAR_DUPLICATE",))])
        for name, why in (("the_exact_key_with_another_rendering_party_stays_held", "FFS_DUPLICATE_LINE"),
                          ("a_repeat_of_a_held_line_stays_held", "DUPLICATE_OF_UNRESOLVED")):
            self.assertEqual(pays(name)[-1].outcome, "HOLD", name)
            self.assertIn(why, pays(name)[-1].reasons, name)
        one = pays("a_repeat_in_one_batch_is_not_paid_yet")
        self.assertEqual(sorted(p.outcome for p in one), ["ALLOW", "HOLD"])
        self.assertIn("FFS_DUPLICATE_LINE", next(p for p in one if p.outcome == "HOLD").reasons)
        self.assertEqual([p.outcome for p in pays("a_redecision_is_not_answered_by_its_own_lines")], ["ALLOW", "ALLOW"])


class AnsweredAtOnceTests(unittest.TestCase):
    def test_an_exact_repeat_of_a_paid_line_is_answered_in_its_batch(self):
        first, y = pays("a_paid_line_sent_again_is_answered")
        self.assertEqual(first.outcome, "ALLOW")
        self.assertEqual((y.outcome, y.reasons, y.authority, y.bypass, y.earlier), ("ANSWERED", ("FFS_DUPLICATE_LINE",), "TRANSFER", NONE, EARLIER))
        mixed = pays("a_paid_line_beside_a_clean_one")[1]  # the whole payment, though one line is clean
        self.assertEqual((mixed.outcome, mixed.earlier), ("ANSWERED", (("L91", fx.PROGRAM, CLEAN.payment_id, "L10"),)))

    def test_an_answered_payment_joins_neither_set(self):
        again = pays("answered_again_when_resent")  # not ALREADY_DECIDED: nothing of it was recorded as released or held
        self.assertEqual([(p.outcome, p.reasons, p.earlier) for p in again[1:]], [("ANSWERED", ("FFS_DUPLICATE_LINE",), EARLIER)] * 2)
        byp = results()["a_bypass_cannot_release_an_answered_payment"]
        self.assertEqual([(p.outcome, p.bypass) for p in pays("a_bypass_cannot_release_an_answered_payment")], [("ALLOW", NONE), ("ANSWERED", NONE)])
        self.assertEqual([x.split() for _, _, ns in byp for x in ns], [["RULES_BYPASS", cr.q(DUP), "NOT_HELD"]])

    def test_nothing_else_is_answered(self):
        for name in cases():
            if name not in ("a_paid_line_sent_again_is_answered", "a_paid_line_beside_a_clean_one", "answered_again_when_resent",
                            "a_bypass_cannot_release_an_answered_payment"):
                self.assertEqual([p.earlier for p in pays(name) if p.outcome == "ANSWERED" or p.earlier], [], name)

    def test_a_contested_repeat_is_decided_as_before(self):
        contested = enc(replace(DUP, contest=True))
        with tempfile.TemporaryDirectory() as tmp:
            out = af.run_case([F(allow(), [enc(CLEAN)]), F(allow(), [contested])], Path(tmp))
        y = out[1][1][0]
        self.assertEqual((y.outcome, y.earlier), ("HOLD", ()))
        self.assertIn("FFS_DUPLICATE_LINE", y.reasons)


class FormatTests(unittest.TestCase):
    def test_decide_request_v2_carries_the_contest_flag_last(self):
        self.assertEqual(gate.DECIDE_REQUEST, b"RR/GATE/DECIDE-REQUEST/v2\x00")
        self.assertIs(DUP.contest, False)
        plain, contested = enc(DUP), enc(replace(DUP, contest=True))
        self.assertEqual((plain[-1:], contested), (b"\x00", plain[:-1] + b"\x01"))
        for bad in (2, 1, None):
            with self.subTest(bad), self.assertRaises(gate.GateCodecError):
                enc(replace(DUP, contest=bad))

    def test_token_v3_answered_and_earlier_root(self):
        self.assertEqual(gate.TOKEN, b"RR/GATE/TOKEN/v3\x00")
        self.assertEqual(gate.OUTCOMES, ("ALLOW", "HOLD", "HUMAN_REVIEW", "BLOCK", "ANSWERED"))
        held = fx._leaf(1, 1, "HOLD")
        answered = replace(held, outcome="ANSWERED", reason_codes=("FFS_DUPLICATE_LINE",), earlier_root=fx.D[9])
        b = gate.encode_token_leaf(answered)
        self.assertEqual(b[b.index(answered.lines_root) + 64], 5)  # the outcome tag
        at = b.index(answered.grant_id + answered.bypass) + 128  # earlier_root follows the bypass field
        self.assertEqual(b[at:at + 64], fx.D[9])
        self.assertEqual(held.earlier_root, gate.ZERO_DIGEST)
        for name, bad in (("answered with no earlier root", replace(answered, earlier_root=gate.ZERO_DIGEST)),
                          ("an earlier root on a held leaf", replace(held, earlier_root=fx.D[9])),
                          ("an earlier root on an allowed leaf", replace(fx._leaf(1, 1), earlier_root=fx.D[9])),
                          ("answered with a bypass id", replace(answered, bypass=fx.D[8])),
                          ("answered without lines", replace(answered, flow="SDP", lines_root=gate.ZERO_DIGEST))):
            with self.subTest(name), self.assertRaises(gate.GateCodecError):
                gate.encode_token_leaf(bad)

    def test_earlier_root_digest(self):
        ident = lambda s: len(s.encode()).to_bytes(2, "big") + s.encode()  # noqa: E731
        two = (("L90", fx.PROGRAM, "pay-0001", "L10"), ("L91", fx.PROGRAM, "pay-0007", "L3"))
        self.assertEqual(gate.earlier_root(two), gate.sha3_512(b"RR/GATE/EARLIER/v1\x00" + (2).to_bytes(2, "big")
                                                                 + b"".join(ident(x) for e in two for x in e)))
        for bad in ((), two[::-1], two[:1] * 2):  # empty, out of line-id order, a line twice
            with self.subTest(bad), self.assertRaises(gate.GateCodecError):
                gate.earlier_root(bad)

    def test_read_earlier_reads_back_only_what_earlier_body_writes(self):
        two = (("L90", fx.PROGRAM, "pay-0001", "L10"), ("L91", fx.PROGRAM, "pay-0007", "L3"))
        body = gate.earlier_body(two)
        self.assertEqual(gate.read_earlier(b"x" + body + b"y", 1), (two, 1 + len(body)))
        ident = lambda s: len(s.encode()).to_bytes(2, "big") + s.encode()  # noqa: E731
        unordered = (2).to_bytes(2, "big") + b"".join(ident(x) for e in two[::-1] for x in e)
        for bad in (b"", b"\x00", b"\x00\x00", body[:-1], unordered, body.replace(b"L90", b"L\xff0")):
            with self.subTest(bad), self.assertRaises(gate.GateCodecError):
                gate.read_earlier(bad)

    def test_the_largest_token_fits_max_token_bytes(self):
        """Every identifier at 128 characters, 32 reason codes of 64, a full Merkle path: the codec comment's number."""
        big = lambda c: c * 128  # noqa: E731
        leaf = replace(fx._leaf(1, 1), tenant_id=big("t"), program_id=big("p"), payment_id=big("y"), payee_ref=big("e"), period=big("d"),
                       outcome="ANSWERED", reason_codes=tuple(f"R{i:02d}" + "X" * 61 for i in range(32)), earlier_root=fx.D[9])
        token = gate.encode_token(gate.Token(leaf, (fx.D[1],) * gate.MAX_TOKEN_PATH, fx.D[2]))
        self.assertEqual(len(token), 4_028)
        self.assertLess(len(token), gate.MAX_TOKEN_BYTES)
        self.assertEqual(gate.read_token(token), (big("y"), "ANSWERED", leaf.reason_codes, fx.D[9]))


class NoMoneyMovesTwiceTests(fx.Scratch):
    def test_the_payer_never_releases_an_answered_payment(self):
        y = pays("a_paid_line_sent_again_is_answered")[1]
        self.assertEqual(y.outcome, "ANSWERED")
        first, second = cr.through_payer(self, DUP, y)
        self.assertIsNotNone(first)
        self.assertIsNotNone(second)
        self.assertNotIn("released", (first, second))


if __name__ == "__main__":
    unittest.main()
