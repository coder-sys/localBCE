"""Focused adversarial tests for the synthetic Contract Mirror V1 seam."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest

from app.governance import provider_continuity_control_pack_v2 as governance
from app.mirror import contract_mirror as contract
from app.mirror import contract_mirror_independent as contract_independent
from app.mirror import continuity_export as export
from app.mirror import continuity_store as store
from app.mirror import continuity_store_independent as store_independent
from app.mirror import discrepancy_case as discrepancy_case
from app.mirror import nc_medicaid_fhir_profile as profile
from app.mirror import source_evidence_custody as custody
from app.mirror import source_evidence_custody_independent as custody_independent
from app.mirror import source_reconciliation as reconciliation
from app.mirror import support_boundary as support
from app.mirror import denominator_ledger as denominator
from app.mirror import denominator_ledger_independent as denominator_independent
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
    for key in ("artifact_id", "current_stage_id", "transition_id"):
        body.pop(key, None)
    artifact_id, stage_id, transition_id = contract_independent._identity_values(body)
    return json.dumps(
        {**body, "artifact_id": artifact_id, "current_stage_id": stage_id, "transition_id": transition_id},
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _verify_contract(instance: store.ContinuityStore, registry: dict[str, object], raw: bytes) -> dict[str, object]:
    connection = instance._connect()
    try:
        context = instance._contract_context_for_raw(connection, raw)
        return contract_independent.verify_artifact(
            raw,
            denominator_raw=context["denominator_raw"],
            denominator_context=context["denominator_context"],
            case_raw=context["case_raw"],
            case_context=context["case_context"],
            registry=registry,
            prior_contract_raw=context.get("prior_contract_raw"),
        )
    finally:
        connection.close()


class MirrorContractMirrorTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory(prefix="mirror-contract-")
        self.addCleanup(self._temporary.cleanup)
        self.root = Path(self._temporary.name)

    def _setup(self, *, narrow: bool = True) -> tuple[store.ContinuityStore, dict[str, object], contract.ContractMirrorService, str, str, str, bytes]:
        instance, registry, _ = _approved_store(self.root)
        source_admission = custody.SourceEvidenceCustodyService(instance, graph_profile_registry=registry).ingest(_envelope())
        if source_admission.graph_receipt is None:
            raise AssertionError("fixture graph was not admitted")
        source_raw = _payload(instance, source_admission.custody_receipt)
        source_value = custody_independent._parse(source_raw)
        source_id = str(source_value["artifact_id"])
        denominator_service = denominator.DenominatorLedgerService(instance, graph_profile_registry=registry)
        denominator_service.create_baseline(source_id)
        denominator_row = next(
            row for row in instance._snapshot_rows()["artifacts"]
            if row["kind"] == denominator_independent.ARTIFACT_KIND and json.loads(row["payload"].decode("ascii"))["stage_kind"] == denominator_independent.STAGE_BASELINE
        )
        baseline_raw = bytes(denominator_row["payload"])
        baseline_value = denominator_independent._parse(baseline_raw)
        if narrow:
            narrowed_receipt = denominator_service.narrow(str(denominator_row["artifact_id"]))
            narrowed_raw = _payload(instance, narrowed_receipt)
            denominator_value = denominator_independent._parse(narrowed_raw)
        else:
            denominator_value = baseline_value
        recon_receipt = reconciliation.SourceReconciliationService(instance, graph_profile_registry=registry).reconcile(source_raw)
        recon_raw = _payload(instance, recon_receipt)
        recon_value = json.loads(recon_raw.decode("ascii"))
        graph_id = str(denominator_value["source_binding"]["graph_artifact_id"])
        graph_row = next(row for row in instance._snapshot_rows()["artifacts"] if row["kind"] == store.ARTIFACT_GRAPH and row["artifact_id"] == graph_id)
        graph_value = json.loads(bytes(graph_row["payload"]).decode("ascii"))
        finding_id = str(graph_value["findings"][0]["finding_id"])
        return (
            instance,
            registry,
            contract.ContractMirrorService(instance, graph_profile_registry=registry),
            str(denominator_value["artifact_id"]),
            str(recon_value["artifact_id"]),
            finding_id,
            source_raw,
        )

    def test_governed_obligation_binds_denominator_observation_and_case(self) -> None:
        instance, registry, service, denominator_id, reconciliation_id, finding_id, _ = self._setup()
        receipt = service.evaluate(denominator_id, reconciliation_id, finding_id)
        retry = service.evaluate(denominator_id, reconciliation_id, finding_id)
        self.assertEqual(receipt.raw, retry.raw)
        value = contract_independent._parse(_payload(instance, receipt))
        self.assertEqual(contract_independent.STAGE_EVALUATED, value["stage_kind"])
        self.assertEqual(contract_independent.OBLIGATION_ID, value["obligation"]["obligation_id"])
        self.assertEqual(denominator_id, value["denominator"]["artifact_id"])
        self.assertEqual(reconciliation_id, value["observation"]["reconciliation_artifact_id"])
        self.assertEqual(contract_independent.RESULT_INDETERMINATE, value["evaluation"]["status"])
        self.assertFalse(value["evaluation"]["conformance_claim"])
        self.assertEqual("OPEN_DISCREPANCY", value["case_link"]["lifecycle_state"])
        self.assertTrue(store_independent.verify_database(instance.path, registry)["accepted"])

    def test_un_narrowed_baseline_does_not_invent_bucket_counts(self) -> None:
        instance, registry, service, denominator_id, reconciliation_id, finding_id, _ = self._setup(narrow=False)
        receipt = service.evaluate(denominator_id, reconciliation_id, finding_id)
        value = contract_independent._parse(_payload(instance, receipt))
        self.assertEqual(denominator_independent.STAGE_BASELINE, value["denominator"]["stage_kind"])
        self.assertIsNone(value["denominator"]["outcome_counts"])
        self.assertIsNone(value["denominator"]["outcome_root"])
        self.assertEqual(contract_independent.RESULT_INDETERMINATE, value["evaluation"]["status"])

    def test_case_remediation_and_retest_are_composed_not_reimplemented(self) -> None:
        instance, registry, service, denominator_id, reconciliation_id, finding_id, _ = self._setup()
        first = service.evaluate(denominator_id, reconciliation_id, finding_id)
        first_value = contract_independent._parse(_payload(instance, first))
        case_id = str(first_value["case_link"]["case_id"])
        case_service = discrepancy_case.DiscrepancyCaseService(instance, graph_profile_registry=registry)
        case_service.record_responsibility(case_id)
        case_service.propose_remediation(case_id)
        case_service.attach_remediation_evidence(case_id)
        retest = service.retest(str(first_value["artifact_id"]))
        retest_retry = service.retest(str(first_value["artifact_id"]))
        self.assertEqual(retest.raw, retest_retry.raw)
        value = contract_independent._parse(_payload(instance, retest))
        self.assertEqual(contract_independent.STAGE_RETESTED, value["stage_kind"])
        self.assertIn(value["case_link"]["lifecycle_state"], {"PARITY_OBSERVED", "DISCREPANCY_PERSISTS"})
        self.assertEqual("UNKNOWN", value["observation"]["source_completeness"])
        self.assertFalse(value["flags"]["business_truth_proven"])
        self.assertTrue(store_independent.verify_database(instance.path, registry)["accepted"])

    def test_rebound_result_or_case_link_rejects_without_mutation(self) -> None:
        instance, registry, service, denominator_id, reconciliation_id, finding_id, _ = self._setup()
        receipt = service.evaluate(denominator_id, reconciliation_id, finding_id)
        raw = _payload(instance, receipt)
        value = json.loads(raw.decode("ascii"))
        before = store_independent.verify_database(instance.path, registry)
        value["evaluation"]["status"] = contract_independent.RESULT_CONFORMING
        body = deepcopy(value)
        for key in ("artifact_id", "current_stage_id", "transition_id"):
            body.pop(key, None)
        artifact_id, stage_id, transition_id = contract_independent._identity_values(body)
        forged = json.dumps({**body, "artifact_id": artifact_id, "current_stage_id": stage_id, "transition_id": transition_id}, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
        row = next(row for row in instance._snapshot_rows()["artifacts"] if row["kind"] == store.ARTIFACT_CONTRACT)
        connection = instance._connect()
        with self.assertRaisesRegex(contract_independent.IndependentContractMirrorError, "semantic-binding"):
            try:
                context = instance._contract_context_for_raw(connection, raw)
                contract_independent.verify_artifact(
                    forged,
                    denominator_raw=context["denominator_raw"],
                    denominator_context=context["denominator_context"],
                    case_raw=context["case_raw"],
                    case_context=context["case_context"],
                    registry=registry,
                )
            finally:
                connection.close()
        self.assertEqual(before, store_independent.verify_database(instance.path, registry))
        self.assertEqual(row["artifact_id"], value["artifact_id"])

    def test_rebound_obligation_denominator_governance_and_exception_reject(self) -> None:
        instance, registry, service, denominator_id, reconciliation_id, finding_id, _ = self._setup()
        receipt = service.evaluate(denominator_id, reconciliation_id, finding_id)
        raw = _payload(instance, receipt)
        original = contract_independent._parse(raw)
        before = store_independent.verify_database(instance.path, registry)
        mutations = {
            "obligation": lambda value: value["obligation"].update({"obligation_id": "forged-obligation"}),
            "denominator": lambda value: value["denominator"].update({"population_root": "0" * 128}),
            "governance": lambda value: value["governance_binding"].update({"effective_start": 0}),
            "exception": lambda value: value["exception_reference"].update({"status": "APPLIED"}),
            "case": lambda value: value["case_link"].update({"finding_id": "0" * 128}),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                forged = deepcopy(original)
                mutate(forged)
                with self.assertRaises(contract_independent.IndependentContractMirrorError):
                    _verify_contract(instance, registry, _rebind(forged))
                self.assertEqual(before, store_independent.verify_database(instance.path, registry))

    def test_same_evaluation_converges_under_concurrency(self) -> None:
        instance, registry, service, denominator_id, reconciliation_id, finding_id, _ = self._setup()
        results: list[bytes] = []
        failures: list[BaseException] = []

        def run() -> None:
            try:
                results.append(service.evaluate(denominator_id, reconciliation_id, finding_id).raw)
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
        self.assertTrue(store_independent.verify_database(instance.path, registry)["accepted"])

    def test_fault_rollback_and_withdrawal_do_not_downgrade_contract(self) -> None:
        instance, registry, service, denominator_id, reconciliation_id, finding_id, _ = self._setup()
        before = store_independent.verify_database(instance.path, registry)
        instance._fault_point = "after_event_receipt_before_commit"
        with self.assertRaises(store.InjectedFault):
            service.evaluate(denominator_id, reconciliation_id, finding_id)
        self.assertEqual(before, store_independent.verify_database(instance.path, registry))
        receipt = service.evaluate(denominator_id, reconciliation_id, finding_id)
        value = contract_independent._parse(_payload(instance, receipt))
        approval_row = next(
            row for row in instance._snapshot_rows()["artifacts"]
            if row["kind"] == store.ARTIFACT_GOVERNANCE and json.loads(row["payload"].decode("ascii")).get("current_stage_kind") == governance.STAGE_APPROVED
        )
        auth = governance.build_withdrawal_authorization(bytes(approval_row["payload"]), profile.NC_MEDICAID_GRAPH_PROFILE, withdrawal_time=7_400)
        withdrawal, _ = governance.build_withdrawal(bytes(approval_row["payload"]), auth, profile.NC_MEDICAID_GRAPH_PROFILE)
        instance.admit(store.ARTIFACT_GOVERNANCE, withdrawal)
        self.assertEqual(receipt.raw, service.evaluate(denominator_id, reconciliation_id, finding_id).raw)
        with self.assertRaises(store.GovernanceObservationOnly):
            service.retest(str(value["artifact_id"]))
        self.assertTrue(store_independent.verify_database(instance.path, registry)["accepted"])

    def test_export_support_remain_aggregate_only_with_contract_artifact(self) -> None:
        instance, registry, service, denominator_id, reconciliation_id, finding_id, _ = self._setup()
        service.evaluate(denominator_id, reconciliation_id, finding_id)
        raw = support.build_support_bundle(instance.path, graph_profile_registry=registry)
        support_result = support.verify_support_bytes(raw)
        self.assertTrue(support_result["accepted"])
        self.assertEqual("DB_CONFORMANCE_PASS", support_result["diagnostic_code"])
        self.assertNotIn(contract_independent.SCHEMA.encode("ascii"), raw)
        self.assertNotIn(profile.SYNTHETIC_PRACTITIONER_ID.encode("ascii"), raw)
        exported = export.export_database(instance.path, registry)
        self.assertTrue(export.verify_export_bytes(exported, registry)["accepted"])
        corrupted = bytearray(exported)
        corrupted[len(corrupted) // 2] ^= 1
        with self.assertRaises(export.ContinuityExportError):
            export.verify_export_bytes(bytes(corrupted), registry)
        restored = self.root / "restored.db"
        self.assertTrue(export.import_export(exported, restored, registry)["restored"])
        self.assertEqual(store_independent.verify_database(instance.path, registry), store_independent.verify_database(restored, registry))


if __name__ == "__main__":
    unittest.main()
