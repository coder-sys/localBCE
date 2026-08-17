"""Focused adversarial tests for the synthetic Money Mirror V1 seam."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest

from app.governance import provider_continuity_control_pack_v2 as governance
from app.mirror import continuity_export as export
from app.mirror import continuity_store as store
from app.mirror import continuity_store_independent as store_independent
from app.mirror import contract_mirror as contract
from app.mirror import denominator_ledger as denominator
from app.mirror import denominator_ledger_independent as denominator_independent
from app.mirror import money_mirror as money
from app.mirror import money_mirror_independent as money_independent
from app.mirror import nc_medicaid_fhir_profile as profile
from app.mirror import source_evidence_custody as custody
from app.mirror import source_evidence_custody_independent as custody_independent
from app.mirror import source_reconciliation as reconciliation
from app.mirror import support_boundary as support
from app.mirror import transaction_mirror as transaction
from app.mirror import transaction_mirror_independent as transaction_independent
from tests.test_mirror_source_evidence_custody import _approved_store, _envelope


def _payload(instance: store.ContinuityStore, receipt: store.AdmissionReceipt) -> bytes:
    connection = sqlite3.connect(instance.path)
    try:
        row = connection.execute(
            "SELECT a.payload FROM artifacts a JOIN operations o ON o.artifact_kind=a.kind AND o.artifact_id=a.artifact_id WHERE o.operation_id=?",
            (receipt.operation_id,),
        ).fetchone()
        if row is None:
            raise AssertionError("receipt has no artifact")
        return bytes(row[0])
    finally:
        connection.close()


def _rebind(value: dict[str, object]) -> bytes:
    body = deepcopy(value)
    body.pop("artifact_id", None)
    body.pop("current_stage_id", None)
    body.pop("transition_id", None)
    artifact_id, stage_id, transition_id = money_independent._identity_values(body)
    return money_independent._canonical(
        {**body, "artifact_id": artifact_id, "current_stage_id": stage_id, "transition_id": transition_id}
    )


class MirrorMoneyMirrorTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory(prefix="mirror-money-")
        self.addCleanup(self._temporary.cleanup)
        self.root = Path(self._temporary.name)

    def _setup(
        self,
        name: str = "state.db",
        *,
        transaction_fixture: str = transaction_independent.FIXTURE_FULL,
    ) -> tuple[store.ContinuityStore, dict[str, object], bytes, str, money.MoneyMirrorService]:
        database_root = self.root / name.replace(".db", "")
        database_root.mkdir()
        instance, registry, _ = _approved_store(database_root)
        source_admission = custody.SourceEvidenceCustodyService(instance, graph_profile_registry=registry).ingest(_envelope())
        if source_admission.graph_receipt is None:
            raise AssertionError("fixture graph was not admitted")
        source_raw = _payload(instance, source_admission.custody_receipt)
        source_id = custody_independent._parse(source_raw)["artifact_id"]
        denominator_service = denominator.DenominatorLedgerService(instance, graph_profile_registry=registry)
        denominator_service.create_baseline(str(source_id))
        baseline_row = next(
            row
            for row in instance._snapshot_rows()["artifacts"]
            if row["kind"] == denominator_independent.ARTIFACT_KIND
            and json.loads(row["payload"].decode("ascii")).get("stage_kind") == denominator_independent.STAGE_BASELINE
        )
        narrowed = denominator_service.narrow(str(baseline_row["artifact_id"]))
        narrowed_value = json.loads(_payload(instance, narrowed).decode("ascii"))
        reconciliation_receipt = reconciliation.SourceReconciliationService(instance, graph_profile_registry=registry).reconcile(source_raw)
        reconciliation_value = json.loads(_payload(instance, reconciliation_receipt).decode("ascii"))
        graph_id = narrowed_value["source_binding"]["graph_artifact_id"]
        graph_row = next(
            row
            for row in instance._snapshot_rows()["artifacts"]
            if row["kind"] == store.ARTIFACT_GRAPH and row["artifact_id"] == graph_id
        )
        finding_id = json.loads(bytes(graph_row["payload"]).decode("ascii"))["findings"][0]["finding_id"]
        contract_receipt = contract.ContractMirrorService(instance, graph_profile_registry=registry).evaluate(
            str(narrowed_value["artifact_id"]),
            str(reconciliation_value["artifact_id"]),
            str(finding_id),
        )
        contract_value = json.loads(_payload(instance, contract_receipt).decode("ascii"))
        trace_receipt = transaction.TransactionMirrorService(instance, graph_profile_registry=registry).trace(
            str(contract_value["artifact_id"]),
            fixture_id=transaction_fixture,
        )
        trace_raw = _payload(instance, trace_receipt)
        trace_id = str(transaction_independent._parse(trace_raw)["artifact_id"])
        return instance, registry, trace_raw, trace_id, money.MoneyMirrorService(instance, graph_profile_registry=registry)

    @staticmethod
    def _money_context(instance: store.ContinuityStore, raw: bytes) -> dict[str, object]:
        connection = instance._connect()
        try:
            return instance._money_context_for_raw(connection, raw)
        finally:
            connection.close()

    def test_matched_exact_retry_and_integer_conservation(self) -> None:
        instance, registry, _trace_raw, trace_id, service = self._setup()
        first = service.observe(trace_id)
        retry = service.observe(trace_id)
        self.assertEqual(first.raw, retry.raw)
        value = money_independent._parse(_payload(instance, first))
        self.assertEqual(list(money_independent.ROLE_ORDER), [item["role"] for item in value["roles"]])
        self.assertEqual(
            {
                "currency": "USD",
                "gross_official_posted_minor": 12_500,
                "signed_adjustments_minor": 0,
                "voided_amount_minor": 0,
                "net_official_observed_minor": 12_500,
                "report_amount_minor": 12_500,
            },
            value["terms"],
        )
        self.assertEqual(money_independent.RESULT_MATCHED, value["comparisons"]["overall"]["status"])
        self.assertTrue(value["flags"]["read_only"])
        self.assertFalse(value["flags"]["payment_movement"])
        self.assertFalse(value["authority"]["payment_authority"])
        self.assertTrue(store_independent.verify_database(instance.path, registry)["accepted"])

    def test_gapped_is_partial_not_zero_and_mismatch_is_divergent(self) -> None:
        gapped, registry, _trace_raw, trace_id, service = self._setup(
            "gapped.db",
            transaction_fixture=transaction_independent.FIXTURE_GAPPED,
        )
        gapped_receipt = service.observe(trace_id, fixture_id=money_independent.FIXTURE_GAPPED)
        gapped_value = money_independent._parse(_payload(gapped, gapped_receipt))
        self.assertEqual(money_independent.RESULT_PARTIAL, gapped_value["comparisons"]["overall"]["status"])
        self.assertIsNone(gapped_value["terms"]["net_official_observed_minor"])
        self.assertIsNone(gapped_value["terms"]["report_amount_minor"])
        self.assertEqual(money_independent.COVERAGE_PARTIAL, gapped_value["evidence_coverage"]["status"])
        self.assertIsNone(gapped_value["case_link"])

        mismatched, registry, _trace_raw, trace_id, service = self._setup(
            "mismatched.db",
            transaction_fixture=transaction_independent.FIXTURE_MISMATCHED,
        )
        mismatch_receipt = service.observe(trace_id, fixture_id=money_independent.FIXTURE_MISMATCHED)
        mismatch_value = money_independent._parse(_payload(mismatched, mismatch_receipt))
        self.assertEqual(money_independent.RESULT_DIVERGENT, mismatch_value["comparisons"]["processor_vs_official"]["status"])
        self.assertEqual(money_independent.RESULT_DIVERGENT, mismatch_value["comparisons"]["overall"]["status"])
        self.assertIsNotNone(mismatch_value["case_link"])
        self.assertTrue(store_independent.verify_database(mismatched.path, registry)["accepted"])

    def test_void_reversal_and_adjustment_report_correction_are_append_only(self) -> None:
        instance, registry, _trace_raw, trace_id, service = self._setup()
        initial = service.observe(trace_id)
        initial_raw = _payload(instance, initial)
        initial_value = money_independent._parse(initial_raw)
        voided = service.void(str(initial_value["artifact_id"]))
        self.assertEqual(voided.raw, service.void(str(initial_value["artifact_id"])).raw)
        void_value = money_independent._parse(_payload(instance, voided))
        self.assertEqual(money_independent.STAGE_VOIDED, void_value["stage_kind"])
        self.assertEqual(12_500, void_value["terms"]["voided_amount_minor"])
        self.assertEqual(0, void_value["terms"]["net_official_observed_minor"])
        self.assertTrue(store_independent.verify_database(instance.path, registry)["accepted"])

        instance, registry, _trace_raw, trace_id, service = self._setup("adjustment.db")
        initial = service.observe(trace_id)
        initial_value = money_independent._parse(_payload(instance, initial))
        adjusted = service.adjust(str(initial_value["artifact_id"]))
        self.assertEqual(adjusted.raw, service.adjust(str(initial_value["artifact_id"])).raw)
        adjusted_value = money_independent._parse(_payload(instance, adjusted))
        self.assertEqual(500, adjusted_value["terms"]["signed_adjustments_minor"])
        self.assertEqual(13_000, adjusted_value["terms"]["net_official_observed_minor"])
        mismatched_report = service.report_mismatch(str(adjusted_value["artifact_id"]))
        self.assertEqual(mismatched_report.raw, service.report_mismatch(str(adjusted_value["artifact_id"])).raw)
        report_value = money_independent._parse(_payload(instance, mismatched_report))
        self.assertEqual(money_independent.RESULT_DIVERGENT, report_value["comparisons"]["official_net_vs_report"]["status"])
        corrected = service.correct(str(report_value["artifact_id"]))
        self.assertEqual(corrected.raw, service.correct(str(report_value["artifact_id"])).raw)
        corrected_value = money_independent._parse(_payload(instance, corrected))
        self.assertEqual(money_independent.STAGE_CORRECTED, corrected_value["stage_kind"])
        self.assertEqual(13_000, corrected_value["terms"]["report_amount_minor"])
        self.assertEqual(report_value["artifact_id"], corrected_value["prior_artifact_id"])
        self.assertEqual(initial_value, money_independent._parse(initial_raw))
        self.assertTrue(store_independent.verify_database(instance.path, registry)["accepted"])

    def test_multi_currency_direct_artifact_and_direct_admission_reject_without_mutation(self) -> None:
        instance, registry, trace_raw, trace_id, service = self._setup()
        initial = service.observe(trace_id)
        before = store_independent.verify_database(instance.path, registry)
        context = self._money_context(instance, _payload(instance, initial))
        candidate = money.build_artifact(
            money_independent.FIXTURE_MULTI_CURRENCY,
            transaction_raw=trace_raw,
            transaction_context=context["transaction_context"],
        )
        with self.assertRaisesRegex(money_independent.IndependentMoneyMirrorError, "currency-mismatch"):
            money_independent.verify_artifact(
                candidate,
                transaction_raw=context["transaction_raw"],
                transaction_context=context["transaction_context"],
                registry=registry,
            )
        with self.assertRaisesRegex(store.StoreConflictError, "transaction-required"):
            instance.admit(store.ARTIFACT_MONEY_OBSERVATION, candidate)
        self.assertEqual(before, store_independent.verify_database(instance.path, registry))

    def test_independent_mutations_parser_attacks_and_missing_as_zero_fail_closed(self) -> None:
        instance, registry, _trace_raw, trace_id, service = self._setup()
        receipt = service.observe(trace_id)
        raw = _payload(instance, receipt)
        context = self._money_context(instance, raw)
        original = money_independent._parse(raw)
        before = store_independent.verify_database(instance.path, registry)
        mutations = {
            "terms-rebound-to-zero": lambda value: value["terms"].__setitem__("net_official_observed_minor", 0),
            "role-reordered": lambda value: value.__setitem__("roles", list(reversed(value["roles"]))),
            "role-duplicated": lambda value: value["roles"].__setitem__(1, deepcopy(value["roles"][0])),
            "transaction-substitution": lambda value: value["transaction_binding"].__setitem__("trace_artifact_id", "0" * 128),
            "payment-authority": lambda value: value["flags"].__setitem__("payment_movement", True),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                forged = deepcopy(original)
                mutate(forged)
                candidate = _rebind(forged)
                with self.assertRaises(money_independent.IndependentMoneyMirrorError):
                    money_independent.verify_artifact(
                        candidate,
                        transaction_raw=context["transaction_raw"],
                        transaction_context=context["transaction_context"],
                        registry=registry,
                    )
        for candidate in (
            b'{"x":1,"x":2}',
            b'{"x":NaN}',
            b'{"x":1.0}',
            b'{"x":' + b"[" * 30 + b"0" + b"]" * 30 + b"}",
            b'{"x":"' + b"a" * money_independent.MAX_ARTIFACT_BYTES + b'"}',
        ):
            with self.assertRaises(money_independent.IndependentMoneyMirrorError):
                money_independent._parse(candidate)
        self.assertEqual(before, store_independent.verify_database(instance.path, registry))

    def test_stale_transition_fork_and_fault_rollback_do_not_mutate_store(self) -> None:
        instance, registry, _trace_raw, trace_id, service = self._setup()
        initial = service.observe(trace_id)
        initial_value = money_independent._parse(_payload(instance, initial))
        adjusted = service.adjust(str(initial_value["artifact_id"]))
        before = store_independent.verify_database(instance.path, registry)
        with self.assertRaises(store.StoreConflictError):
            service.report_mismatch(str(initial_value["artifact_id"]))
        with self.assertRaises(store.ArtifactAdmissionError):
            service.correct(str(initial_value["artifact_id"]))
        self.assertEqual(before, store_independent.verify_database(instance.path, registry))
        self.assertTrue(adjusted.raw)

        instance, registry, _trace_raw, trace_id, service = self._setup("fault.db")
        initial = service.observe(trace_id)
        before = store_independent.verify_database(instance.path, registry)
        instance._fault_point = "after_event_receipt_before_commit"
        with self.assertRaises(store.InjectedFault):
            service.void(str(money_independent._parse(_payload(instance, initial))["artifact_id"]))
        self.assertEqual(before, store_independent.verify_database(instance.path, registry))
        self.assertTrue(service.void(str(money_independent._parse(_payload(instance, initial))["artifact_id"])).raw)
        self.assertTrue(store_independent.verify_database(instance.path, registry)["accepted"])

    def test_concurrent_exact_initial_converges_and_conflicting_initial_rejects(self) -> None:
        instance, registry, _trace_raw, trace_id, service = self._setup()
        results: list[bytes] = []
        failures: list[BaseException] = []

        def run() -> None:
            try:
                results.append(service.observe(trace_id).raw)
            except BaseException as exc:  # test evidence only
                failures.append(exc)

        threads = [threading.Thread(target=run) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertFalse(failures)
        self.assertEqual(2, len(results))
        self.assertEqual(results[0], results[1])
        before = store_independent.verify_database(instance.path, registry)
        with self.assertRaises(store.StoreConflictError):
            service.observe(trace_id, fixture_id=money_independent.FIXTURE_GAPPED)
        self.assertEqual(before, store_independent.verify_database(instance.path, registry))

    def test_governance_withdrawal_preserves_money_history_but_blocks_new_observation(self) -> None:
        instance, registry, _trace_raw, trace_id, service = self._setup()
        initial = service.observe(trace_id)
        initial_value = money_independent._parse(_payload(instance, initial))
        approval_row = next(
            row
            for row in instance._snapshot_rows()["artifacts"]
            if row["kind"] == store.ARTIFACT_GOVERNANCE
            and json.loads(row["payload"].decode("ascii")).get("current_stage_kind") == governance.STAGE_APPROVED
        )
        approval_raw = bytes(approval_row["payload"])
        authorization = governance.build_withdrawal_authorization(
            approval_raw,
            profile.NC_MEDICAID_GRAPH_PROFILE,
            withdrawal_time=7_400,
        )
        withdrawal, _ = governance.build_withdrawal(
            approval_raw,
            authorization,
            profile.NC_MEDICAID_GRAPH_PROFILE,
        )
        instance.admit(store.ARTIFACT_GOVERNANCE, withdrawal)
        self.assertEqual(initial.raw, service.observe(trace_id).raw)
        with self.assertRaises(store.GovernanceObservationOnly):
            service.observe(trace_id, fixture_id=money_independent.FIXTURE_GAPPED)
        with self.assertRaises(store.GovernanceObservationOnly):
            service.adjust(str(initial_value["artifact_id"]))
        self.assertTrue(store_independent.verify_database(instance.path, registry)["accepted"])

    def test_export_restore_support_and_corruption_remain_aggregate_only(self) -> None:
        instance, registry, _trace_raw, trace_id, service = self._setup()
        receipt = service.observe(trace_id, fixture_id=money_independent.FIXTURE_MISMATCHED)
        raw = _payload(instance, receipt)
        support_raw = support.build_support_bundle(instance.path, graph_profile_registry=registry)
        self.assertTrue(support.verify_support_bytes(support_raw)["accepted"])
        for prohibited in (
            money_independent.FIXTURE_MISMATCHED,
            "SYNTH_OFFICIAL_ADJUDICATION_BOUNDARY_V1",
            "SYNTH_OFFICIAL_PAYMENT_RAIL_BOUNDARY_V1",
            money_independent.SCHEMA,
            transaction_independent.TRACE_SCHEMA,
        ):
            self.assertNotIn(prohibited.encode("ascii"), support_raw)
        self.assertNotIn(raw, support_raw)
        exported = export.export_database(instance.path, registry)
        self.assertTrue(export.verify_export_bytes(exported, registry)["accepted"])
        corrupted = bytearray(exported)
        corrupted[-1] = ord("0") if corrupted[-1] != ord("0") else ord("1")
        with self.assertRaises(export.ContinuityExportError):
            export.verify_export_bytes(bytes(corrupted), registry)
        restored = self.root / "restored.db"
        self.assertTrue(export.import_export(exported, restored, registry)["restored"])
        self.assertEqual(
            store_independent.verify_database(instance.path, registry),
            store_independent.verify_database(restored, registry),
        )


if __name__ == "__main__":
    unittest.main()
