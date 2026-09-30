"""The live Lean evaluator worker: one process, one frame each way, fail closed (Art. V.1, V.2, IV.2)."""

import sqlite3
import unittest
from unittest.mock import patch

from app import minimal_clearance_verifier_process as process
from app import right_rail_financial_engine as engine
from app import right_rail_financial_owner as owner_module
from app import right_rail_financial_semantic_adapter as adapter
from tests import test_right_rail_financial_semantic_adapter as adapter_tests


class EvaluatorWorkerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.addCleanup(engine._close_evaluator)
        fixture = adapter_tests.RightRailFinancialSemanticAdapterTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.store = fixture._build_base()

    def _wires(self) -> list[tuple[bytes, dict]]:
        """A BLFIN02 input for every obligation, read inside a transaction that is never committed."""

        connection = self.store._connect()
        self.addCleanup(connection.close)
        connection.execute("BEGIN")
        authority = adapter.TrustedAuthorityContext.from_authority(self.store.trusted_authority)
        verification = {"scope": self.store._scope_value(), "owner_id": self.store.owner_id, "mode": self.store.mode}
        wires = [
            adapter.live_evaluation_input(
                connection, obligation_id=row[0], authority_context=authority,
                evaluation_time_ms=self.store.clock.value + 1, verification=verification,
            )
            for row in connection.execute("SELECT obligation_id FROM obligations ORDER BY obligation_id")
        ]
        connection.execute("ROLLBACK")
        return wires

    def _counts(self) -> dict[str, int]:
        connection = sqlite3.connect(self.store.path)
        try:
            tables = [row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
            return {table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in tables}
        finally:
            connection.close()

    def test_rejected_input_fails_closed_without_echo_and_worker_survives(self) -> None:
        wire = self._wires()[0][0]
        engine._evaluate_wire(wire)
        worker = engine._evaluator[0]
        with self.assertRaises(engine.FinancialEngineResultError) as raised:
            engine._evaluate_wire(wire[:-1])
        self.assertEqual(str(raised.exception), "evaluator_input_rejected")
        self.assertIs(engine._evaluator[0], worker)
        self.assertTrue(worker.alive)

    def test_broken_frame_ends_the_worker_and_the_next_decision_relaunches(self) -> None:
        wire = self._wires()[0][0]
        expected = engine._evaluate_wire(wire)
        worker = engine._evaluator[0]
        with self.assertRaises(process.VerifierProcessError) as raised:  # a length the worker refuses to read
            worker.exchange(bytes(adapter.MAX_WIRE_BYTES + 2), response_cap_bytes=1024, timeout_seconds=5.0)
        self.assertEqual(str(raised.exception), "worker_exchange")
        self.assertFalse(worker.alive)
        self.assertEqual(engine._evaluate_wire(wire), expected)
        self.assertIsNot(engine._evaluator[0], worker)

    def test_worker_is_replaced_between_requests_by_count_or_commit(self) -> None:
        wire = self._wires()[0][0]
        answer = engine._evaluate_wire(wire)
        self.assertGreater(engine._evaluator[0].commit_bytes(), 0)
        worker = engine._evaluator[0]
        with patch.object(engine, "EVALUATOR_RECYCLE_REQUESTS", 2):
            self.assertEqual(engine._evaluate_wire(wire), answer)  # second request: same answer, then replaced
            self.assertFalse(engine._evaluator)
            self.assertFalse(worker.alive)
            self.assertEqual(engine._evaluate_wire(wire), answer)
            self.assertTrue(engine._evaluator[0].alive)
        worker = engine._evaluator[0]
        with patch.object(engine, "EVALUATOR_RECYCLE_COMMIT_BYTES", 1):
            self.assertEqual(engine._evaluate_wire(wire), answer)
            self.assertFalse(engine._evaluator)
            self.assertFalse(worker.alive)
        self.assertEqual(engine._evaluate_wire(wire), answer)  # and the next request relaunches

    def test_large_requests_keep_the_worker_flat(self) -> None:
        """One worker, 20 accepted 600 KB requests then 8 near the 8 MiB ceiling: from each phase's second request its
        commit stays in a 16 MB band.  The M1 pin kept a further 32 MiB segment per request (M1.5 XI.2 record)."""
        data, key, long = self._wires()[0][1], "0" * 110, "x" * 500

        def padded(rows: int, text: str) -> bytes:
            extra = [dict(data["evidence"][0], evidence_id=f"zz{i:05d}{key}", kind="NOTE", common_origin_id=f"zz{i:05d}{key}",
                          source_id=text, source_version=text, local_ref=text, amount_cents=None, reversal_of=None, supersedes=None)
                     for i in range(rows)]
            return adapter._encode_blfin02(dict(data, evidence=sorted(data["evidence"] + extra, key=lambda row: row["evidence_id"])))

        base = len(padded(0, ""))
        phases = ((padded(1000, key), 20), (padded((adapter.MAX_WIRE_BYTES - base) // (len(padded(1, long)) - base) - 1, long), 8))
        self.assertGreater(len(phases[1][0]), 8_000_000)
        with patch.object(engine, "EVALUATOR_RECYCLE_COMMIT_BYTES", 1 << 40):
            for wire, calls in phases:
                answers, commits = set(), []
                for _ in range(calls):
                    try:
                        answers.add(engine._evaluate_wire(wire))
                    except engine.FinancialEngineResultError as error:  # the near-ceiling frame is refused, as wire_max was
                        answers.add(str(error))
                    commits.append(engine._evaluator[0].commit_bytes())
                self.assertEqual(len(answers), 1)
                self.assertLess(max(commits[1:]) - commits[1], 16_000_000, [round(c / 1e6) for c in commits])

    def test_unpinned_executable_is_never_run(self) -> None:
        engine._close_evaluator()  # building the fixture store already started one
        with patch.object(engine, "EVALUATOR_ARTIFACT_SHA256", bytes(32)):
            with self.assertRaises(engine.FinancialEngineContainmentError) as raised:
                engine._evaluate_wire(self._wires()[0][0])
        self.assertEqual(str(raised.exception), "evaluator_containment")
        self.assertEqual(engine._evaluator, [])

    def test_payment_is_decided_by_lean_and_stored_as_decided(self) -> None:
        decisions = []
        real = engine.evaluate_live

        def spy(*args, **kwargs):
            decisions.append(real(*args, **kwargs))
            return decisions[-1]

        with patch.object(engine, "evaluate_live", spy):
            self.fixture._record_cash(self.store)
        self.assertEqual(len(decisions), 1)
        decided = decisions[0]
        connection = sqlite3.connect(self.store.path)
        connection.row_factory = sqlite3.Row
        self.addCleanup(connection.close)
        obligation = connection.execute("SELECT * FROM obligations WHERE obligation_id=?", (decided.obligation_id,)).fetchone()
        evaluation = connection.execute("SELECT * FROM evaluations WHERE obligation_id=? ORDER BY revision DESC", (decided.obligation_id,)).fetchone()
        for row in (obligation, evaluation):
            for field in owner_module._DECIDED_VALUES:
                self.assertEqual(row[field], getattr(decided, field), field)
            for field in ("cash_satisfied", "amount_satisfied", "timely"):
                self.assertEqual(row[field], int(getattr(decided, field)), field)
        self.assertEqual((evaluation["revision"], evaluation["evaluated_at_ms"]), (decided.after_revision, decided.evaluated_at_ms))
        self.assertGreater(decided.received_cash_cents, 0)
        self.store.verify_integrity()

    def test_worker_down_refuses_the_write_and_changes_nothing(self) -> None:
        engine._evaluate_wire(self._wires()[0][0])
        engine._close_evaluator()
        before = self._counts()
        with patch.object(process, "launch_contained_worker", side_effect=process.VerifierProcessError("worker_down")):
            with self.assertRaises(owner_module.FinancialIntegrityError) as raised:
                self.fixture._record_cash(self.store)
        self.assertEqual(str(raised.exception), "lean_evaluation:evaluator_containment")
        self.assertEqual(self._counts(), before)
        self.store.verify_integrity()
        self.fixture._record_cash(self.store)  # the same write succeeds once the worker can start

    def test_a_result_for_another_obligation_is_refused(self) -> None:
        mine = self.store._obligation_id(adapter_tests.expected.H_ITEM_ID, adapter_tests.expected.PERIOD_ONE_ID)
        other = next(wire for wire, data in self._wires() if data["pre_evaluation"]["obligation_id"] != mine)
        foreign = engine._evaluate_wire(other)
        before = self._counts()
        with patch.object(engine, "_evaluate_wire", return_value=foreign):
            with self.assertRaises(owner_module.FinancialIntegrityError) as raised:
                self.fixture._record_cash(self.store)
        self.assertEqual(str(raised.exception), "lean_evaluation:result_context_binding")
        self.assertEqual(self._counts(), before)


if __name__ == "__main__":
    unittest.main()
