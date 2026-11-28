"""The host's reading of a decision answer at header version 4 (conformance/FRAME_V1.md section 4): 20-byte records and
leaves with a u64 reason field, a rule reason at bit ``Reason.idx`` and the leaf-only codes at bits 62
(UNENCODABLE_PAYMENT) and 63 (SCOPE).  Version 3 is the fact answer's (``FactFrame.ansVersion``), so a decision answer
skips it.  No engine runs; only ``decide._answer`` reads the bytes.  Synthetic, non-PHI."""

from __future__ import annotations

from pathlib import Path
import re
import unittest

from app import right_rail_gate_chain as flatchain
from app import right_rail_gate_codec as gate
from app import right_rail_gate_decide as decide
from tests import _gate_authority as au
from tests import test_right_rail_gate_formats as fx

NONE_REF = (2**32 - 1, 2**24 - 1)
SPEC = Path(__file__).resolve().parents[1] / "lean" / "BlindLedger" / "Gate" / "Rules" / "Spec.lean"


def _le(n: int, w: int) -> bytes:
    return n.to_bytes(w, "little")


def _frame(bodies: list[bytes]) -> tuple[bytes, bytes]:
    """A request frame (feeds absent) carrying the standing test grant and these requests, and that grant's id."""
    grant, keys = au.standing()
    pin = au.genesis()[0]
    frame = decide.request_frame((0, ((bytes(77), b""),) * 4), 3, 1, 20270315, flatchain.genesis(3, 20270315, pin), pin,
                                 (0, 0, 0, flatchain.ZERO), keys, grant, b"", [], bodies)
    return frame, au.grant_id(grant)


def _answer(frame: bytes, grant: bytes, recs: list[tuple[int, int, int, int]], leaves: list[tuple[int, int, int, bytes]],
            version: int = 4) -> bytes:
    """An answer to ``frame``: records (index, outcome, rule, reasons) with no counterpart and leaves (outcome, reasons,
    authority, input) with no bypass."""
    out = b"RRDA" + _le(version, 2) + b"\0" + frame[6:18] + _le(len(recs), 4) + frame[18:82]
    out += b"".join(_le(i, 3) + _le(o, 1) + _le(u, 1) + _le(m, 8) + _le(NONE_REF[0], 4) + _le(NONE_REF[1], 3) for i, o, u, m in recs)
    out += bytes(64) + bytes(64) + bytes(16) + grant + bytes(flatchain.AUTH) + _le(0, 4)
    out += _le(len(leaves), 4) + b"".join(_le(o, 1) + _le(m, 8) + _le(a, 1) + b"\0" + x for o, m, a, x in leaves)
    return out + _le(0, 4)


class AnswerV4Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.body = gate.encode_decide_request(fx.payment_request(1))
        cls.frame, cls.grant = _frame([cls.body])
        cls.inp = fx.frame_inputs(cls.frame)[cls.body]

    def answer(self, recs, leaf_mask: int = 0, **kw) -> bytes:
        return _answer(self.frame, self.grant, recs, [(1 if leaf_mask else 0, leaf_mask, 2, self.inp)], **kw)

    def test_the_bits_are_the_reason_numbers(self) -> None:
        # The host's table equals Lean's ``Reason.idx``, read from the source, never from the place in REASONS.
        body = SPEC.read_text("utf-8").split("def Reason.idx : Reason → Nat", 1)[1].split("\n\n", 1)[0]
        lean_idx = {name: int(n) for name, n in re.findall(r"\|\s*\.([A-Z_]+)\s*=>\s*(\d+)", body)}
        self.assertEqual(decide.REASON_IDX, lean_idx)
        self.assertEqual(sorted(lean_idx.values()), list(range(29)))
        self.assertEqual(list(decide.REASONS), sorted(lean_idx, key=str.encode))
        self.assertEqual({n: lean_idx[n] for n in ("BENEFIT_LEVEL_MISSING", "BENEFIT_LEVEL_MISSING_UNVERIFIED",
                                                    "PROGRAM_NOT_ELIGIBLE", "PROGRAM_NOT_ELIGIBLE_UNVERIFIED",
                                                    "STALE_ELIGIBILITY")}, dict(zip(
            ("BENEFIT_LEVEL_MISSING", "BENEFIT_LEVEL_MISSING_UNVERIFIED", "PROGRAM_NOT_ELIGIBLE",
             "PROGRAM_NOT_ELIGIBLE_UNVERIFIED", "STALE_ELIGIBILITY"), range(24, 29))))
        self.assertEqual(decide.LEAF_ONLY, {62: "UNENCODABLE_PAYMENT", 63: "SCOPE"})
        # A reason that sorts into the middle by name keeps its number: POSTING_CAP is still bit 11.
        self.assertEqual(decide._names(1 << 11), ("POSTING_CAP",))
        self.assertEqual(decide._names(1 << 24 | 1 << 26), ("BENEFIT_LEVEL_MISSING", "PROGRAM_NOT_ELIGIBLE"))
        self.assertEqual(decide._names(1 << 23 | 1), ("ALREADY_DECIDED", "STALE_UNRESOLVED"))
        self.assertEqual(decide._names(1 << 62 | 1 << 63), ())  # a record never names a leaf code
        self.assertEqual(decide._names(1 << 62 | 1 << 63, leaf=True), ("SCOPE", "UNENCODABLE_PAYMENT"))

    def test_a_version_4_answer_is_read(self) -> None:
        why, recs, _, _, _, pays, _ = decide._answer(self.answer([(0, 1, 0, 1 << 23 | 1 << 4)], 1 << 7 | 1 << 11), self.frame)
        self.assertIsNone(why)
        self.assertEqual([(r.outcome, r.reasons) for r in recs], [("HOLD", ("FFS_DUPLICATE_LINE", "STALE_UNRESOLVED"))])
        self.assertEqual([(p.outcome, p.reasons, p.authority) for p in pays],
                         [("HOLD", ("MEMBER_DECEASED", "POSTING_CAP"), "TRANSFER")])
        for mask, names in ((1 << 62, ("UNENCODABLE_PAYMENT",)), (1 << 63, ("SCOPE",))):
            with self.subTest(names):
                self.assertEqual(decide._answer(self.answer([(0, 1, 0, 1)], mask), self.frame)[5][0].reasons, names)

    def test_bit_28_is_the_last_reason_and_is_read(self) -> None:
        why, recs, _, _, _, pays, _ = decide._answer(self.answer([(0, 2, 0, 1 << 28)], 1 << 28 | 1 << 24), self.frame)
        self.assertIsNone(why)
        self.assertEqual([r.reasons for r in recs], [("STALE_ELIGIBILITY",)])
        self.assertEqual([p.reasons for p in pays], [("BENEFIT_LEVEL_MISSING", "STALE_ELIGIBILITY")])

    def test_other_versions_and_bits_beyond_the_reasons_are_refused(self) -> None:
        good = self.answer([(0, 1, 0, 1)], 1 << 62)
        decide._answer(good, self.frame)
        bad = [(f"version {v}", self.answer([(0, 1, 0, 1)], 1 << 62, version=v)) for v in (1, 2, 3, 5)]
        bad += [(f"record bit {b}", self.answer([(0, 1, 0, 1 << b)])) for b in (29, 32, 60, 61, 62, 63)]
        bad += [(f"leaf bit {b}", self.answer([(0, 1, 0, 1)], 1 << b)) for b in (29, 32, 60, 61)]
        bad.append(("trailing byte", good + b"\0"))
        for name, data in bad:
            with self.subTest(name), self.assertRaises(decide.GateDecideError):
                decide._answer(data, self.frame)


if __name__ == "__main__":
    unittest.main()
