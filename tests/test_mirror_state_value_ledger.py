"""Focused adversarial tests for the synthetic State Value Ledger V1 seam."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import threading
import unittest

from app.mirror import continuity_export as export
from app.mirror import continuity_store as store
from app.mirror import continuity_store_independent as store_independent
from app.mirror import money_mirror_independent as money_independent
from app.mirror import state_value_ledger as state_value
from app.mirror import state_value_ledger_independent as state_value_independent
from app.mirror import support_boundary as support
from app.mirror import transition_mirror as transition
from app.mirror import transition_mirror_independent as transition_independent
from tests.test_mirror_money_mirror import _payload


class MirrorStateValueLedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        from tests.test_mirror_money_mirror import MirrorMoneyMirrorTests

        self._upstream = MirrorMoneyMirrorTests()
        self._upstream.setUp()
        self.addCleanup(self._upstream.doCleanups)

    def _setup(self, name: str = "state.db", *, transaction_fixture: str | None = None):
        kwargs = {} if transaction_fixture is None else {"transaction_fixture": transaction_fixture}
        instance, registry, _trace_raw, trace_id, money_service = self._upstream._setup(name, **kwargs)
        return instance, registry, trace_id, money_service, state_value.StateValueLedgerService(instance, graph_profile_registry=registry)

    @staticmethod
    def _value(instance: store.ContinuityStore, receipt: store.AdmissionReceipt) -> dict[str, object]:
        return state_value_independent._parse(_payload(instance, receipt))

    @staticmethod
    def _rebind(value: dict[str, object]) -> bytes:
        body = deepcopy(value)
        body.pop("artifact_id", None)
        body.pop("current_stage_id", None)
        body.pop("transition_id", None)
        artifact_id, stage_id, transition_id = state_value_independent._identity_values(body)
        return state_value_independent._canonical({**body, "artifact_id": artifact_id, "current_stage_id": stage_id, "transition_id": transition_id})

    @staticmethod
    def _context(instance: store.ContinuityStore, raw: bytes) -> dict[str, object]:
        connection = instance._connect()
        try:
            connection.execute("BEGIN")
            context = instance._state_value_context_for_raw(connection, raw)
            connection.commit()
            return context
        finally:
            connection.close()

    def test_fixed_profile_counts_once_and_exact_retry_is_byte_identical(self) -> None:
        instance, registry, trace_id, money_service, value_service = self._setup()
        money_receipt = money_service.observe(trace_id)
        money_value = money_independent._parse(_payload(instance, money_receipt))
        first = value_service.observe(str(money_value["artifact_id"]))
        retry = value_service.observe(str(money_value["artifact_id"]))
        value = self._value(instance, first)
        self.assertEqual(first.raw, retry.raw)
        self.assertEqual(state_value_independent.PROFILE_ID, value["profile_binding"]["profile_id"])
        self.assertEqual(state_value_independent.STAGE_OBSERVED, value["stage_kind"])
        self.assertEqual(state_value_independent.STATUS_EXCLUDED, value["entries"][0]["eligibility_status"])
        self.assertEqual(0, value["aggregate"]["excluded_minor"])
        self.assertEqual(0, value["aggregate"]["counted_minor"])
        self.assertFalse(value["flags"]["state_approval"])
        self.assertFalse(value["flags"]["causal_inference"])
        self.assertFalse(value["authority"]["payment_authority"])
        self.assertFalse(value["authority"]["clearance_authority"])
        self.assertTrue(store_independent.verify_database(instance.path, registry)["accepted"])

    def test_adjustment_replaces_not_sums_and_recalculation_is_idempotent(self) -> None:
        instance, registry, trace_id, money_service, value_service = self._setup("adjust.db")
        money_receipt = money_service.observe(trace_id)
        money_value = money_independent._parse(_payload(instance, money_receipt))
        initial = value_service.observe(str(money_value["artifact_id"]))
        initial_value = self._value(instance, initial)
        adjusted = money_service.adjust(str(money_value["artifact_id"]))
        adjusted_value = money_independent._parse(_payload(instance, adjusted))
        recalculated = value_service.recalculate(str(initial_value["artifact_id"]), str(adjusted_value["artifact_id"]))
        retry = value_service.recalculate(str(initial_value["artifact_id"]), str(adjusted_value["artifact_id"]))
        value = self._value(instance, recalculated)
        self.assertEqual(recalculated.raw, retry.raw)
        self.assertEqual("REPLACE_EXISTING", value["recalculation"]["mode"])
        self.assertEqual(1, value["aggregate"]["counted_entries"])
        self.assertEqual(500, value["aggregate"]["counted_minor"])
        self.assertEqual(0, value["aggregate"]["reversed_entries"])
        self.assertEqual(initial_value["entries"][0]["economic_event_key"], value["entries"][0]["economic_event_key"])
        self.assertNotEqual(initial_value["entries"][0]["value_claim_id"], value["entries"][0]["value_claim_id"])
        self.assertEqual(initial_value["aggregate"]["excluded_minor"], 0)
        self.assertTrue(store_independent.verify_database(instance.path, registry)["accepted"])

        before = instance._snapshot_rows()
        with self.assertRaises(store.StoreConflictError):
            value_service.recalculate(str(initial_value["artifact_id"]), str(money_value["artifact_id"]))
        self.assertEqual(before, instance._snapshot_rows())

    def test_unknown_reversed_and_negative_observations_remain_explicit(self) -> None:
        instance, registry, trace_id, money_service, value_service = self._setup("gapped.db", transaction_fixture="SYNTHETIC_GAPPED_OFFICIAL_TRACE_V1")
        money_receipt = money_service.observe(trace_id, fixture_id=money_independent.FIXTURE_GAPPED)
        money_value = money_independent._parse(_payload(instance, money_receipt))
        unknown = self._value(instance, value_service.observe(str(money_value["artifact_id"])))
        self.assertEqual(state_value_independent.STATUS_UNKNOWN, unknown["entries"][0]["eligibility_status"])
        self.assertIsNone(unknown["aggregate"]["unknown_minor"])
        self.assertNotEqual(0, unknown["aggregate"]["unknown_entries"])
        self.assertTrue(store_independent.verify_database(instance.path, registry)["accepted"])

        self._upstream.doCleanups()
        self._upstream.setUp()
        instance, registry, trace_id, money_service, value_service = self._setup("void.db")
        initial_money = money_independent._parse(_payload(instance, money_service.observe(trace_id)))
        voided = money_service.void(str(initial_money["artifact_id"]))
        voided_value = money_independent._parse(_payload(instance, voided))
        reversed_value = self._value(instance, value_service.observe(str(voided_value["artifact_id"])))
        self.assertEqual(state_value_independent.STATUS_REVERSED, reversed_value["entries"][0]["eligibility_status"])
        self.assertEqual(-12_500, reversed_value["aggregate"]["reversed_minor"])
        self.assertTrue(store_independent.verify_database(instance.path, registry)["accepted"])

        self._upstream.doCleanups()
        self._upstream.setUp()
        instance, registry, trace_id, money_service, value_service = self._setup("negative.db")
        negative_money = money_independent._parse(_payload(instance, money_service.observe(trace_id, fixture_id=money_independent.FIXTURE_MISMATCHED)))
        negative = self._value(instance, value_service.observe(str(negative_money["artifact_id"])))
        self.assertEqual(state_value_independent.STATUS_COUNTED, negative["entries"][0]["eligibility_status"])
        self.assertEqual(-12_500, negative["aggregate"]["counted_minor"])
        self.assertEqual("NEGATIVE", negative["entries"][0]["calculation"]["sign"])

    def test_optional_transition_binding_is_exact_and_state_owned(self) -> None:
        instance, registry, trace_id, money_service, value_service = self._setup("transition.db")
        money_receipt = money_service.observe(trace_id)
        money_value = money_independent._parse(_payload(instance, money_receipt))
        transition_receipt = transition.TransitionMirrorService(instance, graph_profile_registry=registry).compare(str(money_value["artifact_id"]))
        transition_value = transition_independent._parse(_payload(instance, transition_receipt))
        value = self._value(instance, value_service.observe(str(money_value["artifact_id"]), transition_artifact_id=str(transition_value["artifact_id"])))
        self.assertIsNotNone(value["entries"][0]["upstream"]["transition"])
        self.assertEqual(transition_value["artifact_id"], value["entries"][0]["upstream"]["transition"]["artifact_id"])
        self.assertTrue(store_independent.verify_database(instance.path, registry)["accepted"])

    def test_rebound_values_duplicate_economic_keys_and_missing_as_zero_fail_closed(self) -> None:
        instance, registry, trace_id, money_service, value_service = self._setup("attacks.db")
        money_receipt = money_service.observe(trace_id)
        money_value = money_independent._parse(_payload(instance, money_receipt))
        receipt = value_service.observe(str(money_value["artifact_id"]))
        raw = _payload(instance, receipt)
        original = state_value_independent._parse(raw)
        context = self._context(instance, raw)
        before = instance._snapshot_rows()
        mutations: list[bytes] = []

        aggregate_rebound = deepcopy(original)
        aggregate_rebound["aggregate"]["counted_minor"] = 99
        mutations.append(self._rebind(aggregate_rebound))

        category_relabel = deepcopy(original)
        category_relabel["entries"][0]["category"] = state_value_independent.CATEGORY_COUNTED
        mutations.append(self._rebind(category_relabel))

        upstream_swap = deepcopy(original)
        upstream_swap["entries"][0]["upstream"]["money"]["artifact_id"] = "0" * 128
        mutations.append(self._rebind(upstream_swap))

        baseline_rebound = deepcopy(original)
        baseline_rebound["entries"][0]["baseline"]["amount_minor"] = 0
        mutations.append(self._rebind(baseline_rebound))

        formula_rebound = deepcopy(original)
        formula_rebound["entries"][0]["calculation"]["formula_version"] = 2
        mutations.append(self._rebind(formula_rebound))

        missing_as_zero = deepcopy(original)
        missing_as_zero["entries"][0]["intervention"]["amount_minor"] = 0
        missing_as_zero["entries"][0]["calculation"]["delta_minor"] = -12_500
        mutations.append(self._rebind(missing_as_zero))

        duplicate = deepcopy(original)
        duplicate["entries"] = [duplicate["entries"][0], deepcopy(duplicate["entries"][0])]
        duplicate["aggregate"] = state_value_independent._aggregate(duplicate["entries"])
        mutations.append(self._rebind(duplicate))

        for forged in mutations:
            with self.subTest(forged=len(forged)):
                with self.assertRaises(state_value_independent.IndependentStateValueLedgerError):
                    state_value_independent.verify_artifact(
                        forged,
                        money_contexts=context["money_contexts"],
                        transition_contexts=context["transition_contexts"],
                        registry=registry,
                    )
        with self.assertRaises(store.StoreConflictError):
            instance.admit(store.ARTIFACT_STATE_VALUE, mutations[0])
        self.assertEqual(before, instance._snapshot_rows())
        self.assertTrue(store_independent.verify_database(instance.path, registry)["accepted"])

    def test_fault_rollback_concurrency_and_export_restore_support_are_aggregate_only(self) -> None:
        instance, registry, trace_id, money_service, value_service = self._setup("fault.db")
        money_value = money_independent._parse(_payload(instance, money_service.observe(trace_id)))
        before = instance._snapshot_rows()
        instance._fault_point = "after_event_receipt_before_commit"
        with self.assertRaises(store.InjectedFault):
            value_service.observe(str(money_value["artifact_id"]))
        self.assertEqual(before, instance._snapshot_rows())
        value_service.observe(str(money_value["artifact_id"]))
        self.assertTrue(store_independent.verify_database(instance.path, registry)["accepted"])

        self._upstream.doCleanups()
        self._upstream.setUp()
        instance, registry, trace_id, money_service, value_service = self._setup("concurrent.db")
        money_value = money_independent._parse(_payload(instance, money_service.observe(trace_id)))
        results: list[bytes] = []
        failures: list[BaseException] = []

        def run() -> None:
            try:
                results.append(value_service.observe(str(money_value["artifact_id"])).raw)
            except BaseException as exc:  # test evidence collection only
                failures.append(exc)

        threads = [threading.Thread(target=run) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertFalse(failures)
        self.assertEqual(2, len(results))
        self.assertEqual(results[0], results[1])
        exported = export.export_database(instance.path, registry)
        self.assertTrue(export.verify_export_bytes(exported, registry)["accepted"])
        support_raw = support.build_support_bundle(instance.path, graph_profile_registry=registry)
        self.assertTrue(support.verify_support_bytes(support_raw)["accepted"])
        for prohibited in (
            state_value_independent.SCHEMA,
            money_independent.SCHEMA,
            money_independent.FIXTURE_MATCHED,
            "SYNTH_OFFICIAL_ADJUDICATION_BOUNDARY_V1",
        ):
            self.assertNotIn(prohibited.encode("ascii"), support_raw)
        restored = Path(self._upstream.root) / "state-value-restored.db"
        self.assertTrue(export.import_export(exported, restored, registry)["restored"])
        self.assertEqual(store_independent.verify_database(instance.path, registry), store_independent.verify_database(restored, registry))


if __name__ == "__main__":
    unittest.main()
