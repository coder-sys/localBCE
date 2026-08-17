"""Focused adversarial tests for the synthetic Mirror case lifecycle."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest

from app.mirror import continuity_export as export
from app.mirror import continuity_store as store
from app.mirror import continuity_store_independent as store_independent
from app.mirror import discrepancy_case as case
from app.mirror import discrepancy_case_independent as case_independent
from app.mirror import nc_medicaid_fhir as fhir
from app.mirror import nc_medicaid_fhir_profile as profile
from app.mirror import source_evidence_custody as custody
from app.mirror import source_reconciliation as reconciliation
from app.mirror import provider_trust_graph_independent as graph_independent
from app.mirror import source_reconciliation_independent as reconciliation_independent
from app.mirror import support_boundary as support
from app.governance import provider_continuity_control_pack_v2 as governance
from tests.test_mirror_source_evidence_custody import _approved_store
from tests.test_nc_medicaid_fhir_source import _bundle, _envelope, _location, _practitioner, _role, _transport


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


def _graph_and_reconciliation(
    instance: store.ContinuityStore,
    registry: dict[str, object],
    *,
    second_envelope: bytes | None = None,
) -> tuple[custody.SourceEvidenceCustodyService, reconciliation.SourceReconciliationService, bytes, bytes, bytes, bytes]:
    source_service = custody.SourceEvidenceCustodyService(instance, graph_profile_registry=registry)
    recon_service = reconciliation.SourceReconciliationService(instance, graph_profile_registry=registry)
    first = source_service.ingest(_envelope())
    if first.graph_receipt is None:
        raise AssertionError("fixture graph was not admitted")
    graph_raw = _payload(instance, first.graph_receipt)
    custody_raw = _payload(instance, first.custody_receipt)
    first_recon_receipt = recon_service.reconcile(custody_raw)
    first_recon_raw = _payload(instance, first_recon_receipt)
    if second_envelope is None:
        return source_service, recon_service, graph_raw, first_recon_raw, custody_raw, custody_raw
    second = source_service.ingest(second_envelope)
    second_custody_raw = _payload(instance, second.custody_receipt)
    second_recon_receipt = recon_service.reconcile(second_custody_raw)
    second_recon_raw = _payload(instance, second_recon_receipt)
    return source_service, recon_service, graph_raw, first_recon_raw, custody_raw, second_recon_raw


class MirrorDiscrepancyCaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory(prefix="mirror-case-")
        self.addCleanup(self._temporary.cleanup)
        self.root = Path(self._temporary.name)

    def _service(self, *, second: bool = False) -> tuple[store.ContinuityStore, dict[str, object], case.DiscrepancyCaseService, bytes, bytes, bytes]:
        registry = dict(profile.NC_MEDICAID_GRAPH_PROFILE_REGISTRY)
        instance, _registry, _graph = _approved_store(self.root)
        source_service, _recon_service, graph_raw, first_recon_raw, _first_custody, latest_recon_raw = _graph_and_reconciliation(
            instance,
            registry,
            second_envelope=(
                _envelope(last_updated="2026-08-15T11:00:00Z")
                if second
                else None
            ),
        )
        del source_service, _registry
        return instance, registry, case.DiscrepancyCaseService(instance, graph_profile_registry=registry), graph_raw, first_recon_raw, latest_recon_raw

    def _selectors(self, graph_raw: bytes, reconciliation_raw: bytes) -> tuple[str, str, str]:
        graph_value = json.loads(graph_raw.decode("ascii"))
        recon_value = json.loads(reconciliation_raw.decode("ascii"))
        return (
            graph_value["report"]["report_id"],
            graph_value["findings"][0]["finding_id"],
            recon_value["artifact_id"],
        )

    def test_complete_case_chain_derives_responsibility_retest_parity_and_restore(self) -> None:
        instance, registry, service, graph_raw, first_recon_raw, _latest = self._service(second=True)
        graph_id, finding_id, recon_id = self._selectors(graph_raw, first_recon_raw)

        opened = service.open_case(graph_id, finding_id, recon_id)
        opened_again = service.open_case(graph_id, finding_id, recon_id)
        self.assertEqual(opened.raw, opened_again.raw)
        opened_value = json.loads(_payload(instance, opened).decode("ascii"))
        case_id = opened_value["case_id"]
        self.assertEqual(case_independent.STAGE_OPEN, opened_value["lifecycle_state"])
        self.assertFalse(opened_value["flags"]["business_truth_proven"])

        responsibility = service.record_responsibility(case_id)
        self.assertEqual(responsibility.raw, service.record_responsibility(case_id).raw)
        responsibility_value = json.loads(_payload(instance, responsibility).decode("ascii"))
        self.assertEqual(case_independent.RESP_STATE_SOURCE, responsibility_value["responsibility"]["boundary"])
        self.assertFalse(responsibility_value["responsibility"]["liability_claim"])

        proposal = service.propose_remediation(case_id)
        assertion = service.attach_remediation_evidence(case_id)
        assertion_value = json.loads(_payload(instance, assertion).decode("ascii"))
        self.assertIsNotNone(assertion_value["remediation"]["proposal"])
        self.assertIsNotNone(assertion_value["remediation"]["assertion"])
        self.assertFalse(assertion_value["remediation"]["real_world_correction_proven"])

        retest = service.execute_retest(case_id)
        retest_value = json.loads(_payload(instance, retest).decode("ascii"))
        self.assertEqual("EXECUTED", retest_value["retest"]["status"])
        self.assertEqual(case_independent.PARITY_PARTIAL, retest_value["retest"]["parity"]["status"])
        persisted = service.observe_parity_or_persistence(case_id)
        self.assertEqual(persisted.raw, service.observe_parity_or_persistence(case_id).raw)
        persisted_value = json.loads(_payload(instance, persisted).decode("ascii"))
        self.assertEqual(case_independent.STAGE_PERSISTS, persisted_value["lifecycle_state"])
        self.assertEqual("UNRESOLVED_OBSERVATION", persisted_value["resolution"]["state"])
        self.assertFalse(persisted_value["resolution"]["business_truth_proven"])
        with self.assertRaises(case.DiscrepancyCaseError):
            service.observe_resolution(case_id)

        verified = store_independent.verify_database(instance.path, registry)
        self.assertTrue(verified["accepted"])
        exported = export.export_database(instance.path, registry)
        self.assertTrue(export.verify_export_bytes(exported, registry)["accepted"])
        restored = self.root / "restored.db"
        export.import_export(exported, restored, registry)
        self.assertEqual(verified, store_independent.verify_database(restored, registry))

    def test_illegal_transition_and_caller_substitution_leave_state_unchanged(self) -> None:
        instance, registry, service, graph_raw, recon_raw, _latest = self._service()
        graph_id, finding_id, recon_id = self._selectors(graph_raw, recon_raw)
        before = store_independent.verify_database(instance.path, registry)
        with self.assertRaises(case.DiscrepancyCaseError):
            service.observe_resolution("0" * 128)
        with self.assertRaises(case.DiscrepancyCaseError):
            service.open_case(graph_id, "0" * 128, recon_id)
        self.assertEqual(before, store_independent.verify_database(instance.path, registry))

        opened = service.open_case(graph_id, finding_id, recon_id)
        case_id = json.loads(_payload(instance, opened).decode("ascii"))["case_id"]
        before_illegal = store_independent.verify_database(instance.path, registry)
        with self.assertRaises(case.DiscrepancyCaseError):
            service.observe_resolution(case_id)
        self.assertEqual(before_illegal, store_independent.verify_database(instance.path, registry))

    def test_concurrent_exact_transition_converges_and_illegal_transition_rejects(self) -> None:
        instance, registry, service, graph_raw, recon_raw, _latest = self._service()
        graph_id, finding_id, recon_id = self._selectors(graph_raw, recon_raw)
        opened = service.open_case(graph_id, finding_id, recon_id)
        case_id = json.loads(_payload(instance, opened).decode("ascii"))["case_id"]
        other = case.DiscrepancyCaseService(
            store.ContinuityStore(instance.path, graph_profile_registry=registry),
            graph_profile_registry=registry,
        )
        barrier = threading.Barrier(2)
        results: list[store.AdmissionReceipt] = []
        errors: list[BaseException] = []

        def run(action: str) -> None:
            try:
                barrier.wait()
                result = service.record_responsibility(case_id) if action == "responsibility" else other.record_responsibility(case_id)
                results.append(result)
            except BaseException as exc:  # the test must observe both outcomes
                errors.append(exc)

        threads = [threading.Thread(target=run, args=("responsibility",)) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(2, len(results))
        self.assertEqual([], errors)
        self.assertEqual(results[0].raw, results[1].raw)
        self.assertEqual(results[0].raw, service.record_responsibility(case_id).raw)

        conflict_barrier = threading.Barrier(2)
        conflict_results: list[store.AdmissionReceipt] = []
        conflict_errors: list[BaseException] = []

        def run_conflict(action: str) -> None:
            try:
                conflict_barrier.wait()
                result = other.propose_remediation(case_id) if action == "proposal" else service.observe_resolution(case_id)
                conflict_results.append(result)
            except BaseException as exc:  # the test must observe both outcomes
                conflict_errors.append(exc)

        conflict_threads = [
            threading.Thread(target=run_conflict, args=(action,))
            for action in ("proposal", "resolution")
        ]
        for thread in conflict_threads:
            thread.start()
        for thread in conflict_threads:
            thread.join()
        self.assertEqual(1, len(conflict_results))
        self.assertEqual(1, len(conflict_errors))
        self.assertIsInstance(conflict_errors[0], case.DiscrepancyCaseError)
        self.assertTrue(store_independent.verify_database(instance.path, registry)["accepted"])

    def test_fault_rollback_and_forged_parity_are_fail_closed(self) -> None:
        instance, registry, service, graph_raw, recon_raw, _latest = self._service(second=True)
        graph_id, finding_id, recon_id = self._selectors(graph_raw, recon_raw)
        opened = service.open_case(graph_id, finding_id, recon_id)
        case_id = json.loads(_payload(instance, opened).decode("ascii"))["case_id"]
        service.record_responsibility(case_id)
        service.propose_remediation(case_id)
        service.attach_remediation_evidence(case_id)
        before = store_independent.verify_database(instance.path, registry)
        instance._fault_point = "after_artifact_insert"
        with self.assertRaises(case.DiscrepancyCaseError):
            service.execute_retest(case_id)
        self.assertEqual(before, store_independent.verify_database(instance.path, registry))

        retest = service.execute_retest(case_id)
        forged = json.loads(_payload(instance, retest).decode("ascii"))
        forged["retest"]["parity"]["status"] = case_independent.PARITY_FULL
        forged_body = deepcopy(forged)
        forged_body.pop("artifact_id")
        forged_body.pop("current_stage_id")
        forged_body.pop("transition_id")
        forged["artifact_id"] = case_independent._digest("artifact-id", forged_body)
        forged["current_stage_id"] = case_independent._digest(
            "stage-id",
            {
                "artifact_id": forged["artifact_id"],
                "case_id": forged["case_id"],
                "lifecycle_state": forged["lifecycle_state"],
                "prior_artifact_id": forged["transition"]["prior_artifact_id"],
                "prior_stage_id": forged["transition"]["prior_stage_id"],
                "retest_reconciliation_artifact_id": forged["retest"]["reconciliation_artifact_id"],
                "resolution_state": forged["resolution"]["state"],
            },
        )
        forged["transition_id"] = case_independent._digest(
            "transition-id",
            {
                "artifact_id": forged["artifact_id"],
                "current_stage_id": forged["current_stage_id"],
                "transition_kind": forged["lifecycle_state"],
                "prior_artifact_id": forged["transition"]["prior_artifact_id"],
                "prior_stage_id": forged["transition"]["prior_stage_id"],
                "case_id": forged["case_id"],
            },
        )
        connection = instance._connect()
        try:
            prior_row = connection.execute(
                "SELECT payload FROM artifacts WHERE kind=? AND report_id=? AND stage_kind=?",
                (store.ARTIFACT_CASE, case_id, case_independent.STAGE_REMEDIATION_EVIDENCE),
            ).fetchone()
            self.assertIsNotNone(prior_row)
            prior_case_raw = bytes(prior_row["payload"])
            reconciliation_context = instance._case_reconciliation_context_for_raw(connection, recon_raw)
            governance_raw = instance._case_governance_for_graph(connection, graph_raw)
        finally:
            connection.close()
        with self.assertRaises(case_independent.IndependentDiscrepancyCaseError):
            case_independent.verify_artifact(
                json.dumps(forged, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii"),
                graph_raw=graph_raw,
                reconciliation_raw=recon_raw,
                reconciliation_context=reconciliation_context,
                governance_raw=governance_raw,
                graph_profile_registry=registry,
                prior_case_raw=prior_case_raw,
            )

    def test_responsibility_mapping_is_bounded_and_never_liability(self) -> None:
        unknown = case_independent._responsibility(graph_independent.FINDING_CONTINUITY, "COMPLETE")
        shared = case_independent._responsibility(graph_independent.FINDING_CONFLICT, "COMPLETE")
        source = case_independent._responsibility(graph_independent.FINDING_INCOMPLETE, "PARTIAL")
        processing = case_independent._responsibility(graph_independent.FINDING_CONTINUITY, reconciliation_independent.STATUS_SOURCE_FAILURE)
        self.assertEqual(case_independent.RESP_UNKNOWN, unknown["boundary"])
        self.assertEqual(case_independent.RESP_SHARED, shared["boundary"])
        self.assertEqual(case_independent.RESP_STATE_SOURCE, source["boundary"])
        self.assertEqual(case_independent.RESP_RIGHTRAIL_PROCESSING, processing["boundary"])
        for item in (unknown, shared, source, processing):
            self.assertFalse(item["liability_claim"])
            self.assertFalse(item["blame_claim"])

    def test_new_evidence_supersedes_without_erasing_original_case(self) -> None:
        instance, registry, service, graph_raw, first_recon_raw, _latest = self._service(second=True)
        graph_id, finding_id, recon_id = self._selectors(graph_raw, first_recon_raw)
        opened = service.open_case(graph_id, finding_id, recon_id)
        case_id = json.loads(_payload(instance, opened).decode("ascii"))["case_id"]
        superseded = service.supersede_with_new_evidence(case_id)
        value = json.loads(_payload(instance, superseded).decode("ascii"))
        self.assertEqual(case_independent.STAGE_SUPERSEDED, value["lifecycle_state"])
        self.assertEqual(case_independent.STAGE_OPEN, json.loads(_payload(instance, opened).decode("ascii"))["lifecycle_state"])
        self.assertNotEqual(recon_id, value["retest"]["reconciliation_artifact_id"])
        self.assertEqual("SUPERSEDED_OBSERVATION", value["resolution"]["state"])
        self.assertTrue(store_independent.verify_database(instance.path, registry)["accepted"])

    def test_withdrawal_preserves_historical_case_and_support_is_aggregate_only(self) -> None:
        instance, registry, service, graph_raw, recon_raw, _latest = self._service()
        graph_id, finding_id, recon_id = self._selectors(graph_raw, recon_raw)
        opened = service.open_case(graph_id, finding_id, recon_id)
        case_id = json.loads(_payload(instance, opened).decode("ascii"))["case_id"]

        connection = instance._connect()
        try:
            approval_row = connection.execute(
                "SELECT a.payload FROM artifacts a JOIN heads h ON h.artifact_kind=a.kind AND h.artifact_id=a.artifact_id WHERE a.kind=? AND h.stage_kind=?",
                (store.ARTIFACT_GOVERNANCE, governance.STAGE_APPROVED),
            ).fetchone()
            self.assertIsNotNone(approval_row)
            approval_raw = bytes(approval_row["payload"])
        finally:
            connection.close()
        withdrawal_auth = governance.build_withdrawal_authorization(
            approval_raw,
            profile.NC_MEDICAID_GRAPH_PROFILE,
            withdrawal_time=7_400,
        )
        withdrawal, _ = governance.build_withdrawal(
            approval_raw,
            withdrawal_auth,
            profile.NC_MEDICAID_GRAPH_PROFILE,
        )
        instance.admit(store.ARTIFACT_GOVERNANCE, withdrawal)

        responsibility = service.record_responsibility(case_id)
        self.assertEqual(case_independent.STAGE_RESPONSIBILITY, json.loads(_payload(instance, responsibility).decode("ascii"))["lifecycle_state"])
        bundle = support.build_support_bundle(instance.path, graph_profile_registry=registry)
        support_result = support.verify_support_bytes(bundle)
        self.assertEqual("DB_CONFORMANCE_PASS", support_result["diagnostic_code"])
        rendered = bundle.decode("ascii")
        for forbidden in (
            profile.SYNTHETIC_PRACTITIONER_ID,
            profile.SYNTHETIC_LOCATION_ID,
            case_id,
        ):
            self.assertNotIn(forbidden, rendered)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
