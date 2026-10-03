"""Lean-live M3 step 3: the payment item and its answer on the live worker, fail closed (lean-live-m3 sections 3 and 7.2)."""

import dataclasses
import sqlite3
import statistics
import time
import unittest
from unittest.mock import patch

from app import right_rail_financial_engine as engine
from app import right_rail_financial_owner as owner_module
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

    def test_many_payment_frames_keep_the_worker_flat(self) -> None:
        """One worker, recycling off: 1,000 payment items interleaved with 1,000 evaluations, then 8 items at the 8 MiB bound.
        From each phase's second request the commit stays in a 16 MB band; a leaked 32 MiB segment per request fails this."""
        small, data, command = self._frame({})
        evaluate = small[13:13 + int.from_bytes(small[9:13], "big")]
        # A valid 8 MiB pre-state takes longer than the 5 s evaluator bound, so the large items carry trailing bytes: Lean
        # reads the whole 8 MB input and refuses it at once.
        large = adapter.encode_payment_item(blfin02=evaluate + bytes(8_100_000), receipts=data["receipts"], foreign=(False, False),
                                            expected_revision=None, command=command)
        self.assertGreater(len(large), 8_000_000)
        with patch.object(engine, "EVALUATOR_RECYCLE_COMMIT_BYTES", 1 << 40), patch.object(engine, "EVALUATOR_RECYCLE_REQUESTS", 1 << 40):
            for frames in ([small, evaluate] * 1000, [large] * 8):
                answers, commits = {}, []
                for wire in frames:
                    try:
                        answers.setdefault(wire, set()).add(engine._evaluate_wire(wire))
                    except engine.FinancialEngineResultError as error:  # the large item is refused
                        answers.setdefault(wire, set()).add(str(error))
                    commits.append(engine._evaluator[0].commit_bytes())
                self.assertTrue(all(len(a) == 1 for a in answers.values()))
                self.assertLess(max(commits[1:]) - commits[1], 16_000_000, [round(c / 1e6) for c in commits[:40]])


class LeanPaymentOwnerTests(unittest.TestCase):
    """The owner with the flag on: Lean's answer is written as the rows it names, and anything else fails closed."""

    def setUp(self) -> None:
        self.addCleanup(engine._close_evaluator)
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

    def test_only_an_exact_retry_is_answered_while_the_clock_is_behind(self) -> None:
        """D4: crash recovery must not depend on the clock, so the write-free exact retry is a DUPLICATE; every other answer fails closed."""
        first = self._pay()
        self.store.reverse_payment(item_id=self.item_id, payment_id="m3-p1", evidence_id="r-m3-p1", event_at_ms=self.at)
        before = _rows(self.store)
        self.store.clock.value -= 10**6  # behind the obligation's last update
        self.assertEqual(self._pay(expected_revision=first["revision"] - 1)["status"], "DUPLICATE")
        self.assertEqual(self.store.reverse_payment(item_id=self.item_id, payment_id="m3-p1", evidence_id="r-m3-p1", event_at_ms=self.at)["status"], "DUPLICATE")
        for changed in ({"payment_id": "m3-p2"}, {"expected_revision": first["revision"] - 1, "event_at_ms": self.at + 1}):  # a new payment; a changed retry
            with self.assertRaises(owner_module.FinancialIntegrityError) as raised:
                self._pay(**changed)
            self.assertEqual(str(raised.exception), "lean_payment:obligation_after_evaluation")
        self.assertEqual(_rows(self.store), before)

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

    def test_a_second_population_naming_the_item_cannot_publish_so_the_item_keeps_one_obligation(self) -> None:
        """A store holds one period and an obligation's id is its item and period, so live_payment_input's evidence by item is exactly
        this obligation's: review Low 3's two-obligation case is unreachable."""
        pack, population = expected.CONTROL_PACK_V1, "m3-second-population"
        manifest = adapter_tests._population_manifest_from_fixture(expected.POPULATION_MANIFEST_V1, self.store.trusted_authority,
                                                                    manifest_id="m3-second-manifest", source_owner_id="m3-second-source")
        self.store.register_population_manifest(manifest)
        self.store.stage_population(population_id=population, manifest_id=manifest.manifest_id, pack_id=pack.pack_id, cutoff_ms=pack.effective_start_ms,
                                    inclusion_rules=("included:synthetic",), expected_count=adapter_tests.EXPECTED_HOSPITAL_COUNT,
                                    items=adapter_tests._items_from_fixture(expected.PROGRAM_ITEMS, population))
        self.store.validate_population(population)
        with self.assertRaisesRegex(sqlite3.IntegrityError, "obligations.obligation_id"):
            self.store.publish_population(population)
        with self.store._connect() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM obligations WHERE item_id=?", (self.item_id,)).fetchone()[0], 1)

    def test_a_stored_confirmation_id_comes_back_as_a_duplicate_an_unchanged_conflict_or_a_refusal(self) -> None:
        """Each stored confirmation has a payment of its origin (Types.lean paymentConfirmationAccounted), so a record naming a stored id is
        never RECORDED or CONFLICT_RECORDED, and the adapter requires an evidence row on those tags."""
        self._pay()
        conflict = self._pay("m3-c1", common_origin_id="o-m3-p1", amount_cents=101)
        before = _rows(self.store)
        self.assertEqual(self._pay("m3-p2", common_origin_id="o-m3-p1", evidence_id="e-m3-p1", local_ref="payment:m3-p1")["status"], "DUPLICATE")
        again = self._pay("m3-c1", common_origin_id="o-m3-p1", amount_cents=101)  # the owner reports CONFLICT for recorded and unchanged alike
        self.assertEqual(_rows(self.store), before)
        self.assertEqual((again["status"], again["conflict_id"]), ("CONFLICT", conflict["conflict_id"]))
        for evidence_id in ("e-m3-p1", "e-m3-c1"):
            with self.assertRaisesRegex(owner_module.FinancialConflictError, "^evidence_identity_conflict$"):
                self._pay("m3-p3", evidence_id=evidence_id)
        self.assertEqual(_rows(self.store), before)

    def test_a_tampered_answer_is_refused_closes_the_worker_and_writes_nothing(self) -> None:
        """Each answer below is well framed and byte-exact with one field changed, so only the adapter's binding to the command and the stored rows can stop it."""
        first = self._pay()
        self._pay("m3-c1", common_origin_id="o-m3-p1", amount_cents=101)  # a stored conflict, so the same call again is CONFLICT_UNCHANGED
        with self.store._connect() as connection:
            obligation_id = connection.execute("SELECT obligation_id FROM obligations").fetchone()[0]
        acts = {"record": lambda: self._pay("m3-p2"),
                "alias": lambda: self._pay("m3-p3", common_origin_id="o-m3-p1"),  # the first payment's origin and amount, a new evidence id
                "retry": lambda: self._pay("m3-p1", expected_revision=first["revision"] - 1),
                "reverse": lambda: self.store.reverse_payment(item_id=self.item_id, payment_id="m3-p1", evidence_id="r-m3-p1", event_at_ms=self.at),
                "conflict": lambda: self._pay("m3-c2", common_origin_id="o-m3-p1", amount_cents=102),
                "unchanged": lambda: self._pay("m3-c1", common_origin_id="o-m3-p1", amount_cents=101)}
        evidence = {"kind": "PAYMENT_X", "amount_cents": 101, "source_id": "other-source", "source_version": "v9", "local_ref": "other-ref", "applicable_at_ms": self.at + 1,
                    "event_at_ms": self.at + 1, "received_at_ms": self.at + 10**6, "common_origin_id": "o-other", "reversal_of": "m3-px", "supersedes": "e-x", "item_id": "other-item"}
        conflict = {"conflict_id": "conflict:other", "obligation_id": "other-obligation", "common_origin_id": "o-other", "existing_payment_id": "m3-px",
                    "candidate_evidence_id": "e-other", "existing_amount_cents": 99, "candidate_amount_cents": 103, "reason": "OTHER", "visible_at_ms": self.at + 10**6}
        cases = [(name, field, value) for name in ("record", "reverse") for field, value in evidence.items()]
        cases += [("conflict", field, value) for field, value in conflict.items()] + [("conflict", "received_at_ms", self.at + 10**6)]
        cases += [("alias", "common_origin_id", "o-other"), ("alias", "payment_id", "m3-px"), ("retry", "payment_id", "m3-px"), ("record", "evidence", None),
                  ("conflict", "evidence", None), ("unchanged", "conflict_id", "conflict:other")]
        before, real = _rows(self.store), engine._evaluate_wire
        for name, field, value in cases:
            with self.subTest(name, field=field), patch.object(engine, "_evaluate_wire", lambda wire: _swap(real(wire), obligation_id, field, value)):
                with self.assertRaisesRegex(owner_module.FinancialIntegrityError, "^lean_payment:payment_binding$"):
                    acts[name]()
                self.assertEqual((_rows(self.store), engine._evaluator), (before, []))

    def test_a_duplicate_or_alias_answer_lean_would_not_give_is_refused_and_writes_nothing(self) -> None:
        """Lean answers DUPLICATE only for a stored evidence id (a fresh record's twin is a stored payment of the same amount) and ALIAS only for a
        record of a stored payment's amount; each forged answer below passed the origin check alone."""
        self._pay()
        with self.store._connect() as connection:
            obligation_id = connection.execute("SELECT obligation_id FROM obligations").fetchone()[0]
        reverse = lambda evidence_id: lambda: self.store.reverse_payment(item_id=self.item_id, payment_id="m3-p1", evidence_id=evidence_id, common_origin_id="o-m3-p1", event_at_ms=self.at)  # noqa: E731
        cases = [("no twin for a fresh origin", 6, None, lambda: self._pay("m3-p2", evidence_id="e-m3-p1", common_origin_id="o-new")),
                 ("another amount", 6, "m3-p1", lambda: self._pay("m3-p2", evidence_id="e-m3-p1", amount_cents=101, common_origin_id="o-m3-p1")),
                 ("unstored evidence", 6, "m3-p1", lambda: self._pay("m3-p2", common_origin_id="o-m3-p1")),
                 ("reversal, unstored evidence", 6, None, reverse("r-m3-p1")),
                 ("alias of another amount", 5, "m3-p1", lambda: self._pay("m3-p2", amount_cents=101, common_origin_id="o-m3-p1")),
                 ("alias of a reversal", 5, "m3-p1", reverse("r-m3-p1"))]
        before, real = _rows(self.store), engine._evaluate_wire

        def forge(answer: bytes, tag: int, lead: str | None) -> bytes:
            writer = adapter._WireWriter()
            writer.option_identifier(lead, "payment_id")
            body = bytes(writer._buffer)
            if tag == 5:  # the real answer's own evidence row, so only the alias binding is left to refuse
                reader = adapter._WireReader(answer, max_bytes=adapter.MAX_WIRE_BYTES)
                reader.take(8, "magic"), reader.byte("tag"), reader.boolean("evidence")
                start = reader._offset
                adapter._read_image(reader, adapter._EVIDENCE_ROW, adapter._encode_evidence, obligation_id)
                body = body[1:] + answer[start:reader._offset]
            return adapter.PAYMENT_ANSWER_MAGIC + bytes([tag]) + body

        for name, tag, lead, act in cases:
            with self.subTest(name), patch.object(engine, "_evaluate_wire", lambda wire: forge(real(wire), tag, lead)):
                with self.assertRaisesRegex(owner_module.FinancialIntegrityError, "^lean_payment:payment_binding$"):
                    act()
                self.assertEqual((_rows(self.store), engine._evaluator), (before, []))

    def test_a_wrong_total_in_leans_answer_is_refused_before_commit_and_the_worker_stays_open(self) -> None:
        """decode_live_result binds identity only; the independent checker recomputes the post-payment totals from the exact rows."""
        real = adapter.decode_live_result
        before = _rows(self.store)
        with patch.object(adapter, "decode_live_result", lambda *a: (lambda r: dataclasses.replace(r, received_cash_cents=r.received_cash_cents + 1))(real(*a))):
            with self.assertRaisesRegex(owner_module.FinancialIntegrityError, "evaluation_verification"):
                self._pay()
        self.assertEqual(_rows(self.store), before)
        self.assertNotEqual(engine._evaluator, [])

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
        return tuple(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in ("payments", "evidence", "financial_events", "evaluations", "financial_conflicts"))


def _swap(answer: bytes, obligation_id: str, field: str, value) -> bytes:
    """The BLFPRS01 answer with one field replaced (or, for value None, the evidence row dropped) and re-encoded."""
    reader = adapter._WireReader(answer, max_bytes=adapter.MAX_WIRE_BYTES)
    reader.take(8, "magic")
    tag, start = reader.byte("tag"), reader._offset
    if field == "payment_id" or tag == 4:  # the leading id of ALIAS (5), DUPLICATE (6) and CONFLICT_UNCHANGED (4)
        (reader.identifier if tag != 6 else reader.option_identifier)(field)
        writer = adapter._WireWriter()
        (writer.identifier if tag != 6 else writer.option_identifier)(value, field)
        return answer[:start] + bytes(writer._buffer) + answer[reader._offset:]
    if field in dict(adapter._CONFLICT_ROW) and tag == 3:  # past the evidence row and the payment flag, the conflict row
        if reader.boolean("evidence"):
            adapter._read_image(reader, adapter._EVIDENCE_ROW, adapter._encode_evidence, obligation_id)
        reader.boolean("payment"), reader.boolean("conflict")
        start = reader._offset
        row = adapter._read_image(reader, adapter._CONFLICT_ROW, lambda w, v, _l, _c: adapter._write_conflicts(w, [v]), skip=2)
        writer = adapter._WireWriter()
        adapter._write_conflicts(writer, [{**row, field: value}])
        return answer[:start] + bytes(writer._buffer)[2:] + answer[reader._offset:]
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


if __name__ == "__main__":
    unittest.main()
