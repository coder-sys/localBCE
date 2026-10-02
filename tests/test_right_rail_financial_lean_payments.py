"""Lean-live M3 step 3: the payment item and its answer on the live worker, fail closed (lean-live-m3 sections 3 and 7.2)."""

import statistics
import time
import unittest
from unittest.mock import patch

from app import right_rail_financial_engine as engine
from app import right_rail_financial_owner as owner_module
from app import right_rail_financial_owner_independent as independent
from app import right_rail_financial_semantic_adapter as adapter
from tests import rightrail_financial_expected_cases as expected
from tests import test_right_rail_financial_acceptance as acceptance_tests
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

    def test_a_payment_frame_costs_about_one_evaluation(self) -> None:
        """T1: the payment frame replaces the evaluation frame one for one, so its cost must stay near it."""
        pay, _data, _command = self._frame({})
        timings = {}
        for name, wire in (("evaluate", pay[13:13 + int.from_bytes(pay[9:13], "big")]), ("payment", pay)):
            engine._evaluate_wire(wire)
            samples = []
            for _ in range(30):
                started = time.perf_counter()
                engine._evaluate_wire(wire)
                samples.append((time.perf_counter() - started) * 1000)
            timings[name] = statistics.median(samples)
        print("FINANCIAL_M3_FRAME_PROFILE", timings)
        self.assertLessEqual(timings["payment"], 2.0 * timings["evaluate"] + 2.0)


class LeanPaymentOwnerTests(unittest.TestCase):
    """The owner with the flag on: Lean's answer is written as the rows it names, and anything else fails closed."""

    def setUp(self) -> None:
        self.addCleanup(engine._close_evaluator)
        patcher = patch.object(owner_module, "_LEAN_DECIDES_PAYMENTS", True)
        patcher.start()
        self.addCleanup(patcher.stop)
        fixture = adapter_tests.RightRailFinancialSemanticAdapterTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.store = fixture._build_base()
        self.at = self.store.clock.value  # fixed: the owner's clock ticks on every command, and a retry must repeat the event time
        with self.store._connect() as connection:
            self.item_id = connection.execute("SELECT item_id FROM obligations ORDER BY obligation_id").fetchone()[0]

    def _pay(self, payment_id: str = "m3-p1", **more):
        fields = {"item_id": self.item_id, "payment_id": payment_id, "common_origin_id": "o-" + payment_id, "amount_cents": 100,
                  "evidence_id": "e-" + payment_id, "event_at_ms": self.at, **more}
        return self.store.record_payment_evidence(**fields)

    def test_record_retry_and_reverse_write_what_lean_names(self) -> None:
        first = self._pay()
        self.assertEqual((first["status"], first["payment_id"]), ("RECORDED", "m3-p1"))
        with self.store._connect() as connection:
            self.assertEqual(connection.execute("SELECT amount_cents,active FROM payments WHERE payment_id='m3-p1'").fetchone()[:], (100, 1))
        before = _rows(self.store)
        self.assertEqual(self._pay(expected_revision=first["revision"] - 1)["status"], "DUPLICATE")
        with self.assertRaisesRegex(owner_module.FinancialConflictError, "^payment_request_conflict$"):  # a later event time is not the same payment
            self._pay(expected_revision=first["revision"] - 1, event_at_ms=self.at + 1)
        self.assertEqual(_rows(self.store), before)
        reversed_ = self.store.reverse_payment(item_id=self.item_id, payment_id="m3-p1", evidence_id="r-m3-p1", event_at_ms=self.store.clock.value)
        self.assertEqual(reversed_["status"], "REVERSED")

    def test_refusals_and_a_dead_worker_write_nothing(self) -> None:
        self._pay()
        before = _rows(self.store)
        with self.assertRaises(owner_module.FinancialRevisionError):
            self._pay("m3-p2", expected_revision=10**6)
        with self.assertRaises(owner_module.FinancialRevisionError) as raised:
            self._pay("m3-p2", expected_revision="1")
        self.assertEqual(str(raised.exception), "obligation_revision_conflict")
        with self.assertRaisesRegex(owner_module.FinancialInputError, "^local_ref$"):  # the id passes; "payment:" + id is 129 bytes
            self._pay("x" * 121)
        with patch.object(engine, "_evaluate_wire", side_effect=engine.FinancialEngineContainmentError("evaluator_containment")):
            with self.assertRaises(owner_module.FinancialIntegrityError) as raised:
                self._pay("m3-p2")
        self.assertEqual(str(raised.exception), "lean_payment:evaluator_containment")
        self.assertEqual(_rows(self.store), before)

    def test_misaligned_receipts_fail_closed_without_writing(self) -> None:
        self._pay()
        before, real = _rows(self.store), owner_module._payment_receipts
        with patch.object(owner_module, "_payment_receipts", lambda c, o: real(c, o)[1:]), self.assertRaises(owner_module.FinancialIntegrityError) as raised:
            self._pay("m3-p2")
        self.assertEqual(str(raised.exception), "lean_payment:evaluator_input_rejected")
        self.assertEqual(_rows(self.store), before)
        self.assertEqual(self._pay("m3-p2")["status"], "RECORDED")  # and the honest carry is accepted

    def test_a_tampered_answer_is_refused_closes_the_worker_and_writes_nothing(self) -> None:
        """Each answer below is well framed and byte-exact with one field changed, so only the adapter's binding to the command and the stored rows can stop it."""
        first = self._pay()
        with self.store._connect() as connection:
            obligation_id = connection.execute("SELECT obligation_id FROM obligations").fetchone()[0]
        acts = {"record": lambda: self._pay("m3-p2"),
                "alias": lambda: self._pay("m3-p3", common_origin_id="o-m3-p1"),  # the first payment's origin and amount, a new evidence id
                "retry": lambda: self._pay("m3-p1", expected_revision=first["revision"] - 1),
                "reverse": lambda: self.store.reverse_payment(item_id=self.item_id, payment_id="m3-p1", evidence_id="r-m3-p1", event_at_ms=self.at)}
        evidence = {"kind": "PAYMENT_X", "amount_cents": 101, "source_id": "other-source", "source_version": "v9", "local_ref": "other-ref", "applicable_at_ms": self.at + 1,
                    "event_at_ms": self.at + 1, "common_origin_id": "o-other", "reversal_of": "m3-px", "supersedes": "e-x", "item_id": "other-item"}
        cases = [(name, field, value) for name in ("record", "reverse") for field, value in evidence.items()]
        cases += [("alias", "common_origin_id", "o-other"), ("alias", "payment_id", "m3-px"), ("retry", "payment_id", "m3-px"), ("record", "evidence", None)]
        before, real = _rows(self.store), engine._evaluate_wire
        for name, field, value in cases:
            with self.subTest(name, field=field), patch.object(engine, "_evaluate_wire", lambda wire: _swap(real(wire), obligation_id, field, value)):
                with self.assertRaisesRegex(owner_module.FinancialIntegrityError, "^lean_payment:payment_binding$"):
                    acts[name]()
                self.assertEqual((_rows(self.store), engine._evaluator), (before, []))

    def test_an_exact_retry_costs_no_more_than_a_record(self) -> None:
        """T3: a retry builds a snapshot and asks Lean; it must not cost more than recording."""
        record, retry = [], []
        for n in range(20):
            kwargs = dict(expected_revision=self.store.obligation_detail(self.item_id)["revision"])
            started = time.perf_counter()
            self._pay(f"m3-t{n}", **kwargs)
            record.append(time.perf_counter() - started)
            started = time.perf_counter()
            self.assertEqual(self._pay(f"m3-t{n}", **kwargs)["status"], "DUPLICATE")
            retry.append(time.perf_counter() - started)
        print("FINANCIAL_M3_RETRY_PROFILE", statistics.median(record), statistics.median(retry))
        self.assertLessEqual(statistics.median(retry[3:]), 1.25 * statistics.median(record[3:]))


def _rows(store) -> tuple:
    with store._connect() as connection:
        return tuple(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in ("payments", "evidence", "financial_events", "evaluations"))


def _swap(answer: bytes, obligation_id: str, field: str, value) -> bytes:
    """The BLFPRS01 answer with one field replaced (or, for value None, the evidence row dropped) and re-encoded."""
    reader = adapter._WireReader(answer, max_bytes=adapter.MAX_WIRE_BYTES)
    reader.take(8, "magic")
    tag, start = reader.byte("tag"), reader._offset
    if field == "payment_id":  # the leading id of ALIAS (5) and DUPLICATE (6)
        (reader.identifier if tag == 5 else reader.option_identifier)("payment_id")
        writer = adapter._WireWriter()
        (writer.identifier if tag == 5 else writer.option_identifier)(value, "payment_id")
        return answer[:start] + bytes(writer._buffer) + answer[reader._offset:]
    reader.identifier("payment_id") if tag == 5 else reader.boolean("evidence")
    start = reader._offset
    row = adapter._read_image(reader, adapter._EVIDENCE_ROW, adapter._encode_evidence, obligation_id)
    if value is None:
        return answer[:start - 1] + b"\x00" + answer[reader._offset:]
    writer = adapter._WireWriter()
    adapter._encode_evidence(writer, {**row, field: value}, "image", obligation_id)
    return answer[:start] + bytes(writer._buffer) + answer[reader._offset:]


def _open_state(requests, shortfall: int) -> dict[str, int]:
    """Test oracle for Lean's openState (S11): counted requests oldest first, each clamped to what is left of the balance."""
    left, open_ = shortfall, {}
    for action_id, amount, paid, _revision, _counted in sorted((r for r in requests if r[4]), key=lambda r: (r[3], r[0])):
        open_[action_id] = min(max(amount - paid, 0), left)
        left -= open_[action_id]
    return open_


class LeanPaymentCorrectionTests(unittest.TestCase):
    """Linked payments on the correction fixture, decided by Lean with the flag on."""

    def setUp(self) -> None:
        self.addCleanup(engine._close_evaluator)
        patcher = patch.object(owner_module, "_LEAN_DECIDES_PAYMENTS", True)
        patcher.start()
        self.addCleanup(patcher.stop)
        fixture = acceptance_tests.RightRailFinancialAcceptanceTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture, self.store = fixture, fixture._build_base_for_correction()
        fixture._prepare_acknowledged(self.store)
        fixture._advance_clock(self.store, expected.CORRECTION_AUTH_MS + 500)

    def _pay(self, suffix: str, cents: int, *, linked: bool = True):
        return self.store.record_payment_evidence(
            item_id=expected.H_ITEM_ID, payment_id=f"payment:h:{suffix}", common_origin_id=f"origin:payment:h:{suffix}", amount_cents=cents,
            evidence_id=f"evidence:payment-h:{suffix}", event_at_ms=expected.CORRECTION_AUTH_MS + 500, pays_action_id=expected.ACTION_CORRECTION_ID if linked else None)

    def test_python_open_cents_equals_lean_open_state(self) -> None:
        outcomes, real, opened = [], adapter.decode_payment_outcome, []
        with self.store._connect() as connection:
            oid = connection.execute("SELECT obligation_id FROM obligations WHERE item_id=?", (expected.H_ITEM_ID,)).fetchone()[0]

        def spy(*args):
            outcomes.append(real(*args))
            return outcomes[-1]

        def over():  # one cent past what Lean says the request may still collect
            with self.assertRaisesRegex(owner_module.FinancialConflictError, "^payment_exceeds_unpaid_balance$"):
                self._pay("m3x", opened[-1][expected.ACTION_CORRECTION_ID] + 1)
        with patch.object(adapter, "decode_payment_outcome", spy):
            for step in (lambda: self._pay("m3a", 100_000), lambda: self._pay("m3b", 50_000), over,
                         lambda: self.store.reverse_payment(item_id=expected.H_ITEM_ID, payment_id="payment:h:m3a", evidence_id="evidence:payment-h:m3a-reversal",
                                                            event_at_ms=expected.CORRECTION_AUTH_MS + 500),
                         lambda: self._pay("m3c", 100_000), lambda: self._pay("m3d", 20_000, linked=False)):
                if step() is None:
                    continue
                out = outcomes[-1]
                opened.append(_open_state(out.requests, out.decided.shortfall_cents))
                with self.store._connect() as connection:
                    self.assertEqual(owner_module._open_requests(connection, oid, out.decided.shortfall_cents), opened[-1], out.status)
        self.assertEqual(len(opened), 5)
        self.assertGreater(opened[0][expected.ACTION_CORRECTION_ID], 0)

    def test_dropped_links_let_lean_overpay_and_the_checker_refuses_before_commit(self) -> None:
        """The carry fault one layer down: Lean sees no earlier links, so only the checker's payment:link stops the overpayment."""
        store, reject_b = self.fixture._two_claim_corrections(300_000, 300_000, unpaid_cents=600_000)  # requests A and B: 300,000 left of the balance after A is paid
        reject_b()
        self.fixture._pay_a(store, 300_000, "m3a")
        seen, real_verify, real = [], independent.verify_obligation_connection, owner_module._payment_receipts

        def spy(*args, **kwargs):
            try:
                return real_verify(*args, **kwargs)
            except independent.IndependentFinancialError as error:
                seen.append(str(error))
                raise
        before = _rows(store)
        with patch.object(owner_module, "_payment_receipts", lambda c, o: [(p, r, None) for p, r, _a in real(c, o)]), \
             patch.object(independent, "verify_obligation_connection", spy), self.assertRaises(owner_module.FinancialError):
            self.fixture._pay_a(store, 1, "m3b")
        self.assertEqual((seen, _rows(store)), (["payment:link"], before))


if __name__ == "__main__":
    unittest.main()
