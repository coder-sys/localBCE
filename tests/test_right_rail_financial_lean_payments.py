"""Lean-live M3 step 3: the payment item and its answer on the live worker, fail closed (lean-live-m3 sections 3 and 7.2)."""

import unittest

from app import right_rail_financial_engine as engine
from app import right_rail_financial_owner as owner_module
from app import right_rail_financial_semantic_adapter as adapter
from tests import test_right_rail_financial_semantic_adapter as adapter_tests


class LeanPaymentFrameTests(unittest.TestCase):
    def setUp(self) -> None:
        self.addCleanup(engine._close_evaluator)
        fixture = adapter_tests.RightRailFinancialSemanticAdapterTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.store = fixture._build_base()

    def _frame(self, command: dict, expected_revision: int | None = None) -> tuple[bytes, dict, dict]:
        """The BLFPAY01 item for the first obligation's item, read inside a transaction that is never committed."""
        connection = self.store._connect()
        self.addCleanup(connection.close)
        connection.execute("BEGIN")
        obligation_id, item_id = connection.execute("SELECT obligation_id,item_id FROM obligations ORDER BY obligation_id").fetchone()
        command = {"kind": "record", "item_id": item_id, "payment_id": "m3-p1", "evidence_id": "m3-e1", "common_origin_id": "m3-o1",
                   "source_id": "m3-source", "source_version": "v1", "local_ref": None, "amount_cents": 100,
                   "event_at_ms": self.store.clock.value, "pays_action_id": None, **command}
        item, data = adapter.live_payment_input(
            connection, obligation_id=obligation_id, authority_context=adapter.TrustedAuthorityContext.from_authority(self.store.trusted_authority),
            now_ms=self.store.clock.value + 1, verification={"scope": self.store._scope_value(), "owner_id": self.store.owner_id, "mode": self.store.mode},
            expected_revision=expected_revision, command=command, receipts=owner_module._payment_receipts(connection, obligation_id))
        connection.execute("ROLLBACK")
        return item, data, command

    def _decide(self, item: bytes, data: dict, command: dict) -> adapter.PaymentOutcome:
        return adapter.decode_payment_outcome(engine._evaluate_wire(item), data, command)

    def test_a_record_is_recorded_and_the_same_item_always_gets_the_same_answer(self) -> None:
        item, data, command = self._frame({})
        first = engine._evaluate_wire(item)
        out = adapter.decode_payment_outcome(first, data, command)
        self.assertEqual((out.status, out.payment_row["amount_cents"], out.event_kind), ("RECORDED", 100, "PAYMENT_RECEIVED"))
        self.assertEqual(out.decided.after_revision, data["pre_evaluation"]["revision"] + 1)
        self.assertEqual(engine._evaluate_wire(item), first)

    def test_truncated_and_misframed_items_are_rejected_and_the_worker_survives(self) -> None:
        item, _data, _command = self._frame({})
        for bad in (item[:-1], item[:8], b"X" + item[1:], item[:8] + b"\x03" + item[9:], item + b"\x00"):
            with self.assertRaises(engine.FinancialEngineResultError) as raised:
                engine._evaluate_wire(bad)
            self.assertEqual(str(raised.exception), "evaluator_input_rejected")
        worker = engine._evaluator[0]
        self.assertTrue(worker.alive)
        self.assertEqual(engine._evaluate_wire(item)[:8], adapter.PAYMENT_ANSWER_MAGIC)

    def test_no_flipped_answer_byte_changes_what_would_be_written(self) -> None:
        item, data, command = self._frame({})
        answer = engine._evaluate_wire(item)
        base = adapter.decode_payment_outcome(answer, data, command)
        for index in range(len(answer)):
            flipped = answer[:index] + bytes([answer[index] ^ 0x01]) + answer[index + 1:]
            try:
                out = adapter.decode_payment_outcome(flipped, data, command)
            except adapter.SemanticAdapterError:
                continue
            self.assertEqual((out.status, out.payment_row, out.event_payload), (base.status, base.payment_row, base.event_payload), index)
        for short in (answer[:-1], answer + b"\x00", b"", answer[:8]):
            with self.assertRaises(adapter.SemanticAdapterError):
                adapter.decode_payment_outcome(short, data, command)

    def test_an_answer_that_names_another_command_is_refused(self) -> None:
        item, data, command = self._frame({})
        answer = engine._evaluate_wire(item)
        for other in ({"payment_id": "m3-p2"}, {"evidence_id": "m3-e2"}, {"amount_cents": 101}, {"common_origin_id": "m3-o2"}):
            with self.assertRaises(adapter.SemanticAdapterIntegrityError) as raised:
                adapter.decode_payment_outcome(answer, data, {**command, **other})
            self.assertEqual(str(raised.exception), "payment_binding")

    def test_an_evaluator_answer_is_not_a_payment_answer_and_the_worker_handles_both_interleaved(self) -> None:
        item, data, command = self._frame({})
        connection = self.store._connect()
        self.addCleanup(connection.close)
        connection.execute("BEGIN")
        wire, _evaluation = adapter.live_evaluation_input(
            connection, obligation_id=data["pre_evaluation"]["obligation_id"],
            authority_context=adapter.TrustedAuthorityContext.from_authority(self.store.trusted_authority),
            evaluation_time_ms=self.store.clock.value + 1, verification={"scope": self.store._scope_value(), "owner_id": self.store.owner_id, "mode": self.store.mode})
        paid, evaluated = engine._evaluate_wire(item), engine._evaluate_wire(wire)
        with self.assertRaises(adapter.SemanticAdapterCodecError):
            adapter.decode_payment_outcome(evaluated, data, command)
        with self.assertRaises(adapter.SemanticAdapterCodecError):
            adapter.decode_live_result(paid, data)
        self.assertEqual((engine._evaluate_wire(item), engine._evaluate_wire(wire)), (paid, evaluated))

    def test_a_zero_amount_and_a_stale_revision_are_refused_by_code(self) -> None:
        _item, data, _command = self._frame({})
        pre = data["pre_evaluation"]["revision"]
        for command, expected, code in (({"amount_cents": 0}, None, 1), ({}, pre + 1, 4)):
            item, data, command = self._frame(command, expected)
            out = self._decide(item, data, command)
            self.assertEqual((out.status, out.reason), ("REFUSED", code))


if __name__ == "__main__":
    unittest.main()
