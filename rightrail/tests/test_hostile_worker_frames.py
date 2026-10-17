"""Hostile input at the evaluator worker: mutated BLFPAY01 / BLFIN02 / BLFOFA01 frames and mutated worker answers.

Fixed seeds, a few hundred cases per entry point.  A frame under the cap is answered 00/01/02/03 and never ends the worker;
a mutated answer is a typed refusal or decodes exactly like the clean one."""

import dataclasses
import json
import random
import timeit
import unittest
from pathlib import Path

from app import right_rail_financial_engine as engine
from app import right_rail_financial_semantic_adapter as adapter
from tests import test_right_rail_financial_lean_payments as payments

_HERE = Path(__file__).resolve().parent
_VECTORS = _HERE.parent / "artifacts" / "engine-correction" / "vectors"
_FRAME_CAP = adapter.MAX_WIRE_BYTES + 8  # Lean maxWorkerFrameBytes: the 8-byte frame magic on top of the largest body
_SPECIAL_U32 = (0, 1, 2, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0x00800000, 0x00800001)
_DECISION = ("completion_at_ms", "owed_cents", "claimed_adjustment_cents", "lawful_adjustment_cents", "received_cash_cents", "shortfall_cents", "overage_cents",
             "cash_satisfied", "amount_satisfied", "timely", "reporting_complete", "verification_status", "case_status", "delivery_status")
_TEXT = (b"\x00", b"\r\n", "é€‮".encode(), b"\xff\xfe", b"\xc0\x80", b"\xed\xa0\x80")


def _mutate(rng: random.Random, frame: bytes) -> bytes:
    n = len(frame)
    at = rng.randrange(n)
    op = rng.randrange(10)
    if op == 0:
        return frame[:at]
    if op == 1:
        out = bytearray(frame)
        for _ in range(rng.randint(1, 3)):
            out[rng.randrange(n)] ^= 1 << rng.randrange(8)
        return bytes(out)
    if op == 2:
        return frame[:at] + frame[at + rng.randint(1, 16):]
    if op == 3:
        return frame[:at] + rng.randbytes(rng.randint(1, 16)) + frame[at:]
    if op == 4:
        special = rng.choice(_SPECIAL_U32 + (n - at, n + 1, max(n - 1, 0)))
        return frame[:at] + (special & 0xFFFFFFFF).to_bytes(4, "big") + frame[at + 4:]
    if op == 5:
        word = rng.choice((b"\xff" * 8, (1 << 63).to_bytes(8, "big"), (2**63 - 1).to_bytes(8, "big"), (2**64 - 1).to_bytes(8, "big")))
        return frame[:at] + word + frame[at + 8:]
    if op == 6:
        span = frame[at:at + rng.randint(1, 32)]
        return frame[:at] + span + frame[at:]
    if op == 7:
        a, b = sorted((at, rng.randrange(n)))
        w = rng.randint(1, 12)
        return frame[:a] + frame[b:b + w] + frame[a + w:b] + frame[a:a + w] + frame[b + w:] if b - a >= w else frame
    if op == 8:
        return frame[:at] + rng.choice(_TEXT) + frame[at:]
    return frame + rng.randbytes(rng.randint(1, 64))


def _outcome(frame: bytes, rejections=engine._EVALUATOR_REJECTIONS) -> object:
    try:
        return engine._evaluate_wire(frame, rejections)
    except engine.FinancialEngineError as error:
        return f"{type(error).__name__}:{error}"


class HostileWorkerFrameTests(unittest.TestCase):
    def setUp(self) -> None:
        self.addCleanup(engine._close_evaluator)
        fixture = payments.LeanPaymentFrameTests("test_a_record_is_recorded_and_the_same_item_always_gets_the_same_answer")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.store, self._frame = fixture.store, fixture._frame

    def _bases(self) -> dict[str, bytes]:
        frames = {k: bytes.fromhex(v) for k, v in json.loads((_HERE / "fixtures" / "payment_frames.json").read_text(encoding="utf-8")).items()}
        record, _data, _command = self._frame({})
        reverse, _data, _command = self._frame({"kind": "reverse", "common_origin_id": None, "event_at_ms": None})
        bases = {name: frames[name] for name in ("c1", "c2", "s1_refused")}
        bases.update({"form_a_record": record, "form_a_reverse": reverse, "blfin02": record[13:13 + int.from_bytes(record[9:13], "big")]})
        bases["blfofa01"] = b"BLFOFA01" + (_VECTORS / "request.bin").read_bytes()
        return bases

    def test_mutated_frames_under_the_cap_get_a_typed_answer_and_never_end_the_worker(self) -> None:
        bad = []
        for name, base in self._bases().items():
            rng = random.Random(f"hostile-frames:{name}")
            for case in range(48):
                frame = _mutate(rng, base)[:_FRAME_CAP]
                if not frame:
                    continue
                started = timeit.default_timer()
                first = _outcome(frame)
                if timeit.default_timer() - started > engine.EVALUATOR_TIMEOUT_SECONDS:
                    bad.append((name, case, "slow"))
                if isinstance(first, str) and first.startswith("FinancialEngineContainmentError"):
                    bad.append((name, case, first, len(frame)))
                elif _outcome(frame) != first:
                    bad.append((name, case, "not_deterministic"))
        self.assertEqual(bad, [])

    def test_the_degenerate_frames_get_a_typed_answer(self) -> None:
        bad = []
        for frame in (b"\x00", b"BLFPAY01", b"BLFPAY01\x01", b"BLFPAY01\x02", b"BLFPAY01\xff" * 3, b"BLFOFA01", b"BLFIN02", bytes(1024), b"\xff" * 4096):
            first = _outcome(frame)
            if isinstance(first, str) and first.startswith("FinancialEngineContainmentError"):
                bad.append((frame[:12], first))
        self.assertEqual(bad, [])

    def test_oversize_payment_frame_kills_the_worker_instead_of_a_typed_refusal(self) -> None:
        engine._evaluate_wire(self._bases()["c1"])
        worker = engine._evaluator[0]
        at_cap = adapter.PAYMENT_MAGIC + b"\x01" + bytes(_FRAME_CAP - 9)
        with self.assertRaises(engine.FinancialEngineResultError) as raised:  # the cap itself is the worker's to refuse
            engine._evaluate_wire(at_cap)
        self.assertEqual(str(raised.exception), "evaluator_input_rejected")
        self.assertIs(engine._evaluator[0], worker)
        with self.assertRaises(engine.FinancialEngineInputError) as raised:  # one byte over is refused here, before the send
            engine._evaluate_wire(at_cap + b"\x00")
        self.assertEqual(str(raised.exception), "evaluator_frame_size")
        self.assertIs(engine._evaluator[0], worker)
        self.assertTrue(worker.alive)

    def test_mutated_payment_answers_are_refused_or_decode_as_the_clean_answer(self) -> None:
        item, data, command = self._frame({})
        answer = engine._evaluate_wire(item)
        base = adapter.decode_payment_outcome(answer, data, command)
        key = lambda out: (out.status, out.payment_row, out.event_payload, out.event_kind)
        bad = []
        rng = random.Random("hostile-payment-answer")
        for case in range(300):
            mutant = _mutate(rng, answer)
            try:
                out = adapter.decode_payment_outcome(mutant, data, command)
            except adapter.SemanticAdapterError:
                continue
            except Exception as error:  # noqa: BLE001 - any untyped escape is the defect
                bad.append((case, type(error).__name__))
                continue
            if key(out) != key(base):
                bad.append((case, "decoded_differently"))
        self.assertEqual(bad, [])

    def test_mutated_evaluation_answers_are_refused_or_change_only_lean_decision_fields(self) -> None:
        item, data, _command = self._frame({})
        connection = self.store._connect()
        self.addCleanup(connection.close)
        connection.execute("BEGIN")
        wire, evaluation = adapter.live_evaluation_input(
            connection, obligation_id=data["pre_evaluation"]["obligation_id"],
            authority_context=adapter.TrustedAuthorityContext.from_authority(self.store.trusted_authority),
            evaluation_time_ms=self.store.clock.value + 1, verification={"scope": self.store._scope_value(), "owner_id": self.store.owner_id, "mode": self.store.mode})
        connection.execute("ROLLBACK")
        answer = engine._evaluate_wire(wire)
        base = adapter.decode_live_result(answer, evaluation)
        bad = []
        rng = random.Random("hostile-live-answer")
        for case in range(300):
            mutant = _mutate(rng, answer)
            try:
                out = adapter.decode_live_result(mutant, evaluation)
            except adapter.SemanticAdapterError:
                continue
            except Exception as error:  # noqa: BLE001
                bad.append((case, type(error).__name__))
                continue
            if dataclasses.replace(out, **{field: getattr(base, field) for field in _DECISION}) != base:  # Lean's decision fields are its own to change
                bad.append((case, "identity_changed"))
        self.assertEqual(bad, [])

    def test_mutated_correction_results_raise_only_typed_errors(self) -> None:
        clean = (_VECTORS / "result.expected.bin").read_bytes()
        bad = []
        rng = random.Random("hostile-correction-result")
        for case in range(300):
            mutant = _mutate(rng, clean)
            try:
                engine.decode_correction_transition_result(mutant)
            except (engine.FinancialEngineError, adapter.SemanticAdapterError):
                continue
            except Exception as error:  # noqa: BLE001
                bad.append((case, type(error).__name__))
        self.assertEqual(bad, [])


if __name__ == "__main__":
    unittest.main()
