"""Focused adversarial tests for the synthetic Transition Mirror V1 seam."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import threading
import unittest

from app.governance import provider_continuity_control_pack_v2 as governance
from app.mirror import continuity_export as export
from app.mirror import continuity_store as store
from app.mirror import continuity_store_independent as store_independent
from app.mirror import money_mirror_independent as money_independent
from app.mirror import nc_medicaid_fhir_profile as profile
from app.mirror import support_boundary as support
from app.mirror import transition_mirror as transition
from app.mirror import transition_mirror_independent as transition_independent
from tests.test_mirror_money_mirror import _payload


class MirrorTransitionMirrorTests(unittest.TestCase):
    def setUp(self) -> None:
        from tests.test_mirror_money_mirror import MirrorMoneyMirrorTests

        self._upstream = MirrorMoneyMirrorTests()
        self._upstream.setUp()
        self.addCleanup(self._upstream.doCleanups)

    def _setup(self, name: str = "state.db", *, transaction_fixture: str = "SYNTHETIC_FULL_TRACE_V1"):
        instance, registry, _trace_raw, trace_id, money_service = self._upstream._setup(name, transaction_fixture=transaction_fixture)
        money_receipt = money_service.observe(trace_id)
        money_raw = _payload(instance, money_receipt)
        money_id = str(money_independent._parse(money_raw)["artifact_id"])
        service = transition.TransitionMirrorService(instance, graph_profile_registry=registry)
        return instance, registry, money_raw, money_id, service

    @staticmethod
    def _money_context(instance: store.ContinuityStore, money_raw: bytes) -> dict[str, object]:
        connection = instance._connect()
        try:
            return instance._money_context_for_raw(connection, money_raw)
        finally:
            connection.close()

    @staticmethod
    def _rebind(value: dict[str, object]) -> bytes:
        body = deepcopy(value)
        body.pop("artifact_id", None)
        body.pop("current_stage_id", None)
        body.pop("transition_id", None)
        artifact_id, stage_id, transition_id = transition_independent._identity_values(body)
        return transition_independent._canonical({**body, "artifact_id": artifact_id, "current_stage_id": stage_id, "transition_id": transition_id})

    def test_canonical_comparison_is_read_only_and_exact_retry_is_byte_identical(self) -> None:
        instance, registry, money_raw, money_id, service = self._setup()
        first = service.compare(money_id)
        second = service.compare(money_id)
        raw = _payload(instance, first)
        value = transition_independent._parse(raw)
        self.assertEqual(first.raw, second.raw)
        self.assertEqual([item["lane_id"] for item in value["lanes"]], ["INCUMBENT", "CHALLENGER"])
        self.assertIsNone(value["comparison"]["overall"]["winner"])
        self.assertEqual("NOT_AUTHORIZED", value["comparison"]["overall"]["cutover"])
        self.assertEqual("APPEND_ONLY_OBSERVATION", value["parity_history"]["history_mode"])
        self.assertEqual(value["comparison"]["overall"]["status"], value["parity_history"]["status"])
        self.assertFalse(value["flags"]["business_equivalence_proven"])
        self.assertFalse(value["flags"]["winner_selected"])
        self.assertEqual("PARTIAL", value["comparison"]["overall"]["status"])
        self.assertTrue(store_independent.verify_database(instance.path, registry)["accepted"])

    def test_fixed_fixture_matrix_exposes_each_bounded_difference_without_winner(self) -> None:
        expected = {
            transition_independent.FIXTURE_MATCHED: "PARTIAL",
            transition_independent.FIXTURE_INTERFACE_DIVERGENT: "DIVERGENT",
            transition_independent.FIXTURE_TRANSACTION_DIVERGENT: "DIVERGENT",
            transition_independent.FIXTURE_CONTRACT_DIVERGENT: "DIVERGENT",
            transition_independent.FIXTURE_DENOMINATOR_PARTIAL: "PARTIAL",
            transition_independent.FIXTURE_MONEY_DIVERGENT: "DIVERGENT",
            transition_independent.FIXTURE_ERROR_UNKNOWN: "PARTIAL",
            transition_independent.FIXTURE_CONFLICTED: "CONFLICTED",
        }
        for index, (fixture_id, overall) in enumerate(expected.items()):
            instance, registry, _money_raw, money_id, service = self._setup(f"fixture-{index}.db")
            receipt = service.compare(money_id, fixture_id=fixture_id)
            value = transition_independent._parse(_payload(instance, receipt))
            self.assertEqual(overall, value["comparison"]["overall"]["status"], fixture_id)
            self.assertIsNone(value["comparison"]["overall"]["winner"])
            self.assertFalse(value["flags"]["cutover_authority"])
            self.assertTrue(store_independent.verify_database(instance.path, registry)["accepted"])

    def test_rebound_lane_summary_shared_input_currency_and_unit_fail_independently_without_mutation(self) -> None:
        instance, registry, money_raw, money_id, service = self._setup()
        receipt = service.compare(money_id)
        original = _payload(instance, receipt)
        context = {"money_raw": money_raw, "money_context": self._money_context(instance, money_raw), "prior_transition_raw": None}
        before = instance._snapshot_rows()
        mutations = []

        lane_swap = transition_independent._parse(original)
        lane_swap["lanes"][0], lane_swap["lanes"][1] = lane_swap["lanes"][1], lane_swap["lanes"][0]
        mutations.append(self._rebind(lane_swap))

        forged_winner = transition_independent._parse(original)
        forged_winner["comparison"]["overall"]["winner"] = "CHALLENGER"
        mutations.append(self._rebind(forged_winner))

        wrong_currency = transition_independent._parse(original)
        wrong_currency["shared_binding"]["currency"] = "EUR"
        mutations.append(self._rebind(wrong_currency))

        wrong_unit = transition_independent._parse(original)
        wrong_unit["shared_binding"]["unit"] = "MAJOR_UNITS"
        mutations.append(self._rebind(wrong_unit))

        wrong_transaction = transition_independent._parse(original)
        wrong_transaction["shared_binding"]["transaction"]["artifact_id"] = "0" * 128
        mutations.append(self._rebind(wrong_transaction))

        wrong_profile = transition_independent._parse(original)
        wrong_profile["profile_binding"]["profile_digest"] = "0" * 128
        mutations.append(self._rebind(wrong_profile))

        for forged in mutations:
            with self.assertRaises(transition_independent.IndependentTransitionMirrorError):
                transition_independent.verify_artifact(
                    forged,
                    money_raw=money_raw,
                    money_context=context["money_context"],
                    registry=registry,
                )
            with self.assertRaises(store.ArtifactAdmissionError):
                store.verify_artifact(
                    store.ARTIFACT_TRANSITION,
                    forged,
                    graph_profile_registry=registry,
                    transition_context=context,
                )
            self.assertEqual(before, instance._snapshot_rows())

    def test_gapped_money_remains_partial_and_never_becomes_missing_or_success(self) -> None:
        instance, registry, _money_raw, money_id, service = self._setup("gapped.db", transaction_fixture="SYNTHETIC_GAPPED_OFFICIAL_TRACE_V1")
        # The upstream helper admitted the gapped Transaction Trace; the fixed
        # initial Money fixture then preserves the source gap as an observation.
        receipt = service.compare(money_id)
        value = transition_independent._parse(_payload(instance, receipt))
        self.assertIn(value["comparison"]["overall"]["status"], {"PARTIAL", "UNKNOWN"})
        self.assertFalse(value["flags"]["business_equivalence_proven"])
        self.assertFalse(value["shared_binding"]["money"]["event_status"] == "MATCHED" and value["shared_binding"]["money"]["overall_status"] == "MATCHED")
        self.assertTrue(store_independent.verify_database(instance.path, registry)["accepted"])

    def test_retest_history_stale_head_and_fault_rollback_are_fail_closed(self) -> None:
        instance, registry, _money_raw, money_id, service = self._setup("retest.db")
        initial = service.compare(money_id)
        initial_value = transition_independent._parse(_payload(instance, initial))
        before_fault = instance._snapshot_rows()
        instance._fault_point = "after_event_receipt_before_commit"
        with self.assertRaises(store.InjectedFault):
            service.retest(str(initial_value["artifact_id"]))
        instance._fault_point = None
        self.assertEqual(before_fault, instance._snapshot_rows())
        retest = service.retest(str(initial_value["artifact_id"]))
        retest_raw = _payload(instance, retest)
        retest_value = transition_independent._parse(retest_raw)
        self.assertEqual(initial_value["artifact_id"], retest_value["prior_artifact_id"])
        self.assertEqual(retest.raw, service.retest(str(initial_value["artifact_id"])).raw)
        self.assertEqual(initial.raw, service.compare(money_id).raw)
        before_conflict = instance._snapshot_rows()
        with self.assertRaises(store.StoreConflictError):
            service.retest(str(initial_value["artifact_id"]), fixture_id=transition_independent.FIXTURE_MONEY_DIVERGENT)
        self.assertEqual(before_conflict, instance._snapshot_rows())
        self.assertTrue(store_independent.verify_database(instance.path, registry)["accepted"])

    def test_concurrent_exact_initial_converges_and_cross_profile_selector_does_not_mutate(self) -> None:
        instance, registry, _money_raw, money_id, service = self._setup("concurrent.db")
        results: list[bytes] = []
        failures: list[BaseException] = []

        def run() -> None:
            try:
                results.append(service.compare(money_id).raw)
            except BaseException as exc:  # evidence collection only
                failures.append(exc)

        threads = [threading.Thread(target=run) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertFalse(failures)
        self.assertEqual(2, len(results))
        self.assertEqual(results[0], results[1])
        before = instance._snapshot_rows()
        with self.assertRaises(store.StoreConflictError):
            instance.admit_transition("TRANSITION_INITIAL", money_artifact_id=money_id, fixture_id=transition_independent.FIXTURE_MATCHED, graph_profile_registry={"wrong": object()})
        self.assertEqual(before, instance._snapshot_rows())
        self.assertTrue(store_independent.verify_database(instance.path, registry)["accepted"])

    def test_governance_withdrawal_preserves_history_but_blocks_new_transition(self) -> None:
        instance, registry, _money_raw, money_id, service = self._setup("withdrawal.db")
        initial = service.compare(money_id)
        initial_value = transition_independent._parse(_payload(instance, initial))
        approval_row = next(
            row
            for row in instance._snapshot_rows()["artifacts"]
            if row["kind"] == store.ARTIFACT_GOVERNANCE
            and json.loads(bytes(row["payload"]).decode("ascii")).get("current_stage_kind") == governance.STAGE_APPROVED
        )
        approval_raw = bytes(approval_row["payload"])
        authorization = governance.build_withdrawal_authorization(approval_raw, profile.NC_MEDICAID_GRAPH_PROFILE, withdrawal_time=7_400)
        withdrawal, _ = governance.build_withdrawal(approval_raw, authorization, profile.NC_MEDICAID_GRAPH_PROFILE)
        instance.admit(store.ARTIFACT_GOVERNANCE, withdrawal)
        self.assertEqual(initial.raw, service.compare(money_id).raw)
        with self.assertRaises(store.GovernanceObservationOnly):
            service.retest(str(initial_value["artifact_id"]))
        self.assertTrue(store_independent.verify_database(instance.path, registry)["accepted"])

    def test_export_restore_corruption_and_support_are_bounded(self) -> None:
        instance, registry, _money_raw, money_id, service = self._setup("export.db")
        receipt = service.compare(money_id, fixture_id=transition_independent.FIXTURE_INTERFACE_DIVERGENT)
        raw = _payload(instance, receipt)
        support_raw = support.build_support_bundle(instance.path, graph_profile_registry=registry)
        self.assertTrue(support.verify_support_bytes(support_raw)["accepted"])
        for prohibited in (transition_independent.FIXTURE_INTERFACE_DIVERGENT.encode("ascii"), transition_independent.SCHEMA.encode("ascii"), raw, b"INCUMBENT", b"CHALLENGER"):
            self.assertNotIn(prohibited, support_raw)
        exported = export.export_database(instance.path, registry)
        self.assertTrue(export.verify_export_bytes(exported, registry)["accepted"])
        corrupted = bytearray(exported)
        corrupted[-1] = ord("0") if corrupted[-1] != ord("0") else ord("1")
        with self.assertRaises(export.ContinuityExportError):
            export.verify_export_bytes(bytes(corrupted), registry)
        restored = Path(self._upstream.root) / "restored-transition.db"
        self.assertTrue(export.import_export(exported, restored, registry)["restored"])
        self.assertEqual(store_independent.verify_database(instance.path, registry), store_independent.verify_database(restored, registry))

    def test_duplicate_keys_noncanonical_and_oversize_inputs_fail_closed(self) -> None:
        with self.assertRaises(transition_independent.IndependentTransitionMirrorError):
            transition_independent._parse(b'{"schema":"x","schema":"y"}')
        with self.assertRaises(transition_independent.IndependentTransitionMirrorError):
            transition_independent._parse(b'{"schema":"x", "schema_version": 1}')
        with self.assertRaises(transition_independent.IndependentTransitionMirrorError):
            transition_independent._parse(b'{"x":"' + b"a" * transition_independent.MAX_ARTIFACT_BYTES + b'"}')
        deep: dict[str, object] = {}
        cursor = deep
        for _ in range(transition_independent.MAX_DEPTH + 2):
            cursor["x"] = {}
            cursor = cursor["x"]
        with self.assertRaises(transition_independent.IndependentTransitionMirrorError):
            transition_independent._parse(transition_independent._canonical(deep))


if __name__ == "__main__":
    unittest.main()
