"""Differential test of the Python BLFCRES3 decoder against results the pinned Lean worker really emits.

Lean output is the oracle: it comes from the pinned evaluator worker run on the shipped request and on
variants of it (one header field changed at a time), never from a Python encoder. A decoder that
skips or misreads a field cannot pass the byte-sensitivity check: flipping any single byte of a
Lean result must either be refused or change the decoded value."""

from __future__ import annotations

from pathlib import Path
import unittest

from app import right_rail_financial_engine as engine

VECTORS = Path(__file__).resolve().parents[1] / "artifacts" / "engine-correction" / "vectors"


def _header(request: bytes) -> tuple[dict[str, int], str]:
    """Offsets of the fixed-width BLFCMD02 header fields, and the action id."""
    at = 10
    strings = []

    def skip() -> None:
        nonlocal at
        size = int.from_bytes(request[at:at + 2], "big")
        strings.append(request[at + 2:at + 2 + size].decode())
        at += 2 + size

    for _ in range(7):  # contract, item, claim, action, actor, role, authority id
        skip()
    offsets = {"authority_epoch": at, "expected_revision": at + 72}
    at += 72 + 8
    skip()  # evaluation id
    at += 64
    offsets.update(decision_at=at, owner_now=at + 8)
    return offsets, strings[3]


def _refused(payload: bytes) -> bool:
    try:
        engine.decode_correction_transition_result(payload)
    except engine.FinancialEngineError:
        return True
    return False


class LeanDifferentialTests(unittest.TestCase):
    def test_python_decoder_agrees_with_every_lean_result(self) -> None:
        request = (VECTORS / "request.bin").read_bytes()
        offsets, action_id = _header(request)
        variants = [request]
        for offset in offsets.values():
            for delta in (1, -1):
                value = int.from_bytes(request[offset:offset + 8], "big") + delta
                if value >= 0:
                    variants.append(request[:offset] + value.to_bytes(8, "big") + request[offset + 8:])
        answers, refusals = [], []
        for body in variants:
            try:
                answers.append(engine._evaluate_wire(body))
            except engine.FinancialEngineResultError as error:  # only Lean's own decode refusal is tolerated
                refusals.append(str(error))
        self.assertEqual(len(variants), 9)  # the shipped request and each of four header numbers plus and minus one
        self.assertEqual(refusals, ["evaluator_input_rejected"])
        outputs = set(answers)
        self.assertIn((VECTORS / "result.expected.bin").read_bytes(), outputs)
        seen = set()
        for payload in outputs:
            decoded = engine.decode_correction_transition_result(payload)
            seen.add((decoded["status"], decoded["reject_reason"]))
            if decoded["status"] == "ACCEPTED":
                self.assertEqual((decoded["action_id"], decoded["determination_id"]), (action_id, f"determination:{action_id}"))
            with self.subTest(status=decoded["status"], reason=decoded["reject_reason"], size=len(payload)):
                for cut in range(len(payload)):
                    self.assertTrue(_refused(payload[:cut]), f"prefix {cut} accepted")
                for bad in (payload + b"\x00", b"BLFCRES4" + payload[8:], payload[:8] + b"\x00\x04" + payload[10:], payload[:10] + b"\x09" + payload[11:]):
                    self.assertTrue(_refused(bad))
                for index in range(len(payload)):
                    flipped = payload[:index] + bytes([payload[index] ^ 1]) + payload[index + 1:]
                    self.assertTrue(_refused(flipped) or engine.decode_correction_transition_result(flipped) != decoded, f"byte {index} is never read")
        self.assertEqual(sorted(seen, key=str), [("ACCEPTED", None), ("REJECTED", "AUTHORITY_STALE"), ("REJECTED", "REVISION_CONFLICT")])


if __name__ == "__main__":
    unittest.main()
