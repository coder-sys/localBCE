"""Differential test of the Python BLFCRES3 decoder against results the pinned Lean engine really emits.

Lean output is the oracle: it comes from the pinned executable run on the shipped request and on
variants of it (one header field changed at a time), never from a Python encoder. A decoder that
skips or misreads a field cannot pass the byte-sensitivity check: flipping any single byte of a
Lean result must either be refused or change the decoded value."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from app import right_rail_financial_engine as engine
from tests.test_right_rail_financial_acceptance import _correction_transition_test_release

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
        with tempfile.TemporaryDirectory(prefix="rr-lean-differential-") as workspace:
            release = _correction_transition_test_release(workspace=Path(workspace))
            outputs = set()
            for body in variants:
                try:  # Lean exits nonzero on input it refuses to decode; only exit-0 results are decoded below
                    outputs.add(engine._run_pinned(release, engine.CORRECTION_TRANSITION_ARGUMENTS, body, failure_code="differential").stdout)
                except engine.FinancialEngineContainmentError:
                    pass
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
        self.assertIn("ACCEPTED", {status for status, _ in seen})
        self.assertGreater(len(seen), 1, "Lean produced no rejection to decode")


if __name__ == "__main__":
    unittest.main()
