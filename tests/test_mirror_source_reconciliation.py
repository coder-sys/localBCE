"""Focused tests for the synthetic state-side temporal reconciliation seam."""

from __future__ import annotations

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
from app.mirror import nc_medicaid_fhir as fhir
from app.mirror import nc_medicaid_fhir_profile as profile
from app.mirror import source_evidence_custody as custody
from app.mirror import source_reconciliation as reconciliation
from app.mirror import source_reconciliation_independent as reconciliation_independent
from app.mirror import support_boundary as support
from tests.test_mirror_source_evidence_custody import _approved_store
from tests.test_nc_medicaid_fhir_source import (
    _bundle,
    _envelope,
    _location,
    _practitioner,
    _role,
    _transport,
)


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")


def _rebind_reconciliation(value: dict[str, object]) -> bytes:
    body = dict(value)
    body.pop("artifact_id")
    body.pop("current_stage_id")
    body.pop("transition_id")
    artifact_id = reconciliation_independent._digest("artifact-id", body)
    current = body["current_custody"]
    predecessor = body["predecessor_custody"]
    result = body["result"]
    stage_id = reconciliation_independent._digest(
        "stage-id",
        {
            "artifact_id": artifact_id,
            "current_custody_artifact_id": current["artifact_id"],
            "current_snapshot_root": current["snapshot_root"],
            "result_status": result["status"],
            "prior_artifact_id": body["prior_artifact_id"],
            "prior_stage_id": body["prior_stage_id"],
        },
    )
    transition_id = reconciliation_independent._digest(
        "transition-id",
        {
            "artifact_id": artifact_id,
            "current_stage_id": stage_id,
            "prior_artifact_id": body["prior_artifact_id"],
            "prior_stage_id": body["prior_stage_id"],
            "predecessor_custody_artifact_id": predecessor["artifact_id"] if isinstance(predecessor, dict) else None,
            "current_custody_artifact_id": current["artifact_id"],
        },
    )
    return _canonical({**body, "artifact_id": artifact_id, "current_stage_id": stage_id, "transition_id": transition_id})


def _changed_envelope(marker: str, *, name: str = "Synthetic NC Site") -> bytes:
    resources = [_practitioner(), _role(), _location()]
    resources[2]["name"] = name
    return fhir.build_fixture_envelope(_transport(_bundle(resources=resources, last_updated=marker)))


def _failed_envelope() -> bytes:
    request_url = profile.NC_MEDICAID_PROFILE.page_url(0)
    transport = fhir.SyntheticFhirTransport({}, failures={(request_url, 0): "timeout"})
    return fhir.build_fixture_envelope(transport)


def _partial_envelope() -> bytes:
    first = _bundle(0, resources=[_practitioner(), _role()], next_page=True)
    return fhir.build_fixture_envelope(_transport(first))


def _payload_for_receipt(instance: store.ContinuityStore, receipt: store.AdmissionReceipt) -> bytes:
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


def _approval_raw(instance: store.ContinuityStore) -> bytes:
    connection = sqlite3.connect(instance.path)
    try:
        row = connection.execute(
            "SELECT a.payload FROM artifacts a JOIN heads h ON h.artifact_kind=a.kind AND h.artifact_id=a.artifact_id WHERE a.kind=? AND h.stage_kind=?",
            (store.ARTIFACT_GOVERNANCE, governance.STAGE_APPROVED),
        ).fetchone()
        if row is None:
            raise AssertionError("approved governance row missing")
        return bytes(row[0])
    finally:
        connection.close()


class MirrorSourceReconciliationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory(prefix="mirror-source-reconciliation-")
        self.addCleanup(self._temporary.cleanup)
        self.root = Path(self._temporary.name)

    def _services(self, name: str = "state.db") -> tuple[store.ContinuityStore, dict[str, object], custody.SourceEvidenceCustodyService, reconciliation.SourceReconciliationService]:
        instance = store.ContinuityStore(self.root / name, graph_profile_registry=dict(profile.NC_MEDICAID_GRAPH_PROFILE_REGISTRY))
        registry = dict(profile.NC_MEDICAID_GRAPH_PROFILE_REGISTRY)
        return (
            instance,
            registry,
            custody.SourceEvidenceCustodyService(instance, graph_profile_registry=registry),
            reconciliation.SourceReconciliationService(instance, graph_profile_registry=registry),
        )

    def _custody_and_reconcile(
        self,
        source_service: custody.SourceEvidenceCustodyService,
        recon_service: reconciliation.SourceReconciliationService,
        envelope: bytes,
    ) -> tuple[bytes, bytes, store.AdmissionReceipt]:
        admitted = source_service.ingest(envelope)
        custody_raw = _payload_for_receipt(source_service.store, admitted.custody_receipt)
        receipt = recon_service.reconcile(custody_raw)
        return custody_raw, _payload_for_receipt(source_service.store, receipt), receipt

    def test_initial_changed_retry_independent_binding_export_restore_and_support(self) -> None:
        instance, registry, _graph_raw = _approved_store(self.root)
        source_service = custody.SourceEvidenceCustodyService(instance, graph_profile_registry=registry)
        recon_service = reconciliation.SourceReconciliationService(instance, graph_profile_registry=registry)

        custody_one, recon_one, first = self._custody_and_reconcile(source_service, recon_service, _envelope())
        second_source_admission = source_service.ingest(_changed_envelope("2026-08-15T11:00:00Z", name="Synthetic NC Site Changed"))
        custody_two = _payload_for_receipt(instance, second_source_admission.custody_receipt)
        context = instance.source_reconciliation_context(custody_two, registry)
        prior_value = reconciliation_independent._parse(context["prior_reconciliation_raw"])
        candidate_two = reconciliation_independent.build_artifact(
            context["current_custody_raw"],
            context["prior_custody_raw"],
            current_graph_raw=context["current_graph_raw"],
            prior_graph_raw=context["prior_graph_raw"],
            prior_artifact_id=prior_value["artifact_id"],
            prior_stage_id=prior_value["current_stage_id"],
            graph_profile_registry=registry,
        )
        second = instance.admit_source_reconciliation(custody_two, candidate_two, registry)
        recon_two = _payload_for_receipt(instance, second)
        first_value = json.loads(recon_one.decode("ascii"))
        second_value = json.loads(recon_two.decode("ascii"))
        self.assertEqual(reconciliation_independent.STATUS_OBSERVED_NEW, first_value["result"]["status"])
        self.assertEqual(reconciliation_independent.STATUS_OBSERVED_CHANGED, second_value["result"]["status"])
        self.assertEqual("ADVANCES", second_value["chronology"]["order"])
        self.assertEqual(reconciliation_independent.RECONCILIATION_CONTRACT_ID, second_value["reconciliation_contract"]["contract_id"])
        self.assertEqual(reconciliation_independent.MAX_GAP_SECONDS, second_value["reconciliation_contract"]["max_gap_seconds"])
        self.assertFalse(second_value["result"]["absence_inferred"])
        self.assertFalse(second_value["result"]["nonmembership_inferred"])
        self.assertTrue(custody_one)

        before = store_independent.verify_database(instance.path, registry)
        retry = recon_service.reconcile(custody_two)
        self.assertEqual(second.raw, retry.raw)
        self.assertEqual(before, store_independent.verify_database(instance.path, registry))

        checked = reconciliation_independent.verify_artifact(
            recon_two,
            current_custody_raw=context["current_custody_raw"],
            prior_custody_raw=context["prior_custody_raw"],
            current_graph_raw=context["current_graph_raw"],
            prior_graph_raw=context["prior_graph_raw"],
            prior_reconciliation_raw=context["prior_reconciliation_raw"],
            graph_profile_registry=registry,
        )
        self.assertEqual(reconciliation_independent.STATUS_OBSERVED_CHANGED, checked["result_status"])

        exported = export.export_database(instance.path, registry)
        restored = self.root / "restored.db"
        export.import_export(exported, restored, registry)
        self.assertEqual(exported, export.export_database(restored, registry))
        self.assertEqual(store_independent.verify_database(instance.path, registry), store_independent.verify_database(restored, registry))
        corrupted_export = bytearray(exported)
        corrupted_export[-1] = ord("0") if corrupted_export[-1] != ord("0") else ord("1")
        with self.assertRaises(export.ContinuityExportError):
            export.verify_export_bytes(bytes(corrupted_export), registry)
        bundle = support.build_support_bundle(instance.path, graph_profile_registry=registry)
        self.assertTrue(support.verify_support_bytes(bundle)["accepted"])
        support_text = bundle.decode("ascii")
        self.assertNotIn(profile.SYNTHETIC_PRACTITIONER_ID, support_text)
        self.assertNotIn("NCPROV-001", support_text)
        self.assertNotIn("Synthetic NC Site Changed", support_text)
        self.assertNotIn(_changed_envelope("2026-08-15T11:00:00Z", name="Synthetic NC Site Changed").hex(), support_text)

    def test_incomplete_failure_stale_and_gap_states_never_claim_absence(self) -> None:
        instance, registry, source_service, recon_service = self._services("statuses.db")
        raw_one, recon_one, _ = self._custody_and_reconcile(source_service, recon_service, _envelope())
        raw_partial, recon_partial, _ = self._custody_and_reconcile(source_service, recon_service, _partial_envelope())
        raw_failed, recon_failed, _ = self._custody_and_reconcile(source_service, recon_service, _failed_envelope())
        raw_stale, recon_stale, _ = self._custody_and_reconcile(source_service, recon_service, _envelope(last_updated="2020-01-01T00:00:00Z"))
        del raw_one, raw_partial, raw_failed, raw_stale
        values = [json.loads(raw.decode("ascii")) for raw in (recon_one, recon_partial, recon_failed, recon_stale)]
        self.assertEqual(
            [
                reconciliation_independent.STATUS_OBSERVED_NEW,
                reconciliation_independent.STATUS_NOT_OBSERVED_INCOMPLETE,
                reconciliation_independent.STATUS_SOURCE_FAILURE,
                reconciliation_independent.STATUS_STALE_OR_GAPPED,
            ],
            [value["result"]["status"] for value in values],
        )
        for value in values:
            self.assertFalse(value["result"]["absence_inferred"])
            self.assertFalse(value["result"]["nonmembership_inferred"])
        self.assertEqual(8, store_independent.verify_database(instance.path, registry)["event_count"])

        gap_instance, gap_registry, gap_source, gap_recon = self._services("gap.db")
        self._custody_and_reconcile(gap_source, gap_recon, _envelope(last_updated="2026-08-01T12:00:00Z"))
        _raw_gap, recon_gap, _ = self._custody_and_reconcile(gap_source, gap_recon, _envelope(last_updated="2026-08-14T12:00:00Z"))
        self.assertEqual(
            reconciliation_independent.STATUS_STALE_OR_GAPPED,
            json.loads(recon_gap.decode("ascii"))["result"]["status"],
        )
        self.assertTrue(gap_instance.path.is_file())
        self.assertEqual("GAP", json.loads(recon_gap.decode("ascii"))["chronology"]["order"])

    def test_equal_marker_conflict_late_arrival_and_forged_result_rollback(self) -> None:
        instance, registry, source_service, recon_service = self._services("adversarial.db")
        first_raw, _first_recon, _ = self._custody_and_reconcile(source_service, recon_service, _envelope())
        conflict_raw, conflict_recon, _ = self._custody_and_reconcile(
            source_service,
            recon_service,
            _changed_envelope(profile.FIXTURE_LAST_UPDATED, name="Synthetic Conflicting Site"),
        )
        self.assertEqual(
            reconciliation_independent.STATUS_CONFLICTING,
            json.loads(conflict_recon.decode("ascii"))["result"]["status"],
        )

        equal_graph_value = json.loads(conflict_recon.decode("ascii"))
        equal_graph_prior = dict(equal_graph_value["predecessor_custody"])
        equal_graph_current = dict(equal_graph_value["current_custody"])
        equal_graph_current["snapshot_root"] = equal_graph_prior["snapshot_root"]
        equal_graph_current["graph_link"] = {"artifact_id": "synthetic-different-governed-link"}
        equal_graph_result = reconciliation_independent._result(
            equal_graph_prior,
            equal_graph_current,
            equal_graph_value["chronology"],
        )
        self.assertEqual(reconciliation_independent.STATUS_CONFLICTING, equal_graph_result["status"])

        late_raw, late_recon, _ = self._custody_and_reconcile(
            source_service,
            recon_service,
            _changed_envelope("2026-08-13T12:00:00Z", name="Synthetic Late Site"),
        )
        self.assertEqual(
            reconciliation_independent.STATUS_STALE_OR_GAPPED,
            json.loads(late_recon.decode("ascii"))["result"]["status"],
        )
        del first_raw, conflict_raw

        fault_admission = source_service.ingest(_envelope(last_updated="2026-08-15T10:00:00Z"))
        fault_raw = _payload_for_receipt(instance, fault_admission.custody_receipt)
        fault_context = instance.source_reconciliation_context(fault_raw, registry)
        prior_value = reconciliation_independent._parse(fault_context["prior_reconciliation_raw"])
        valid_fault_candidate = reconciliation_independent.build_artifact(
            fault_context["current_custody_raw"],
            fault_context["prior_custody_raw"],
            current_graph_raw=fault_context["current_graph_raw"],
            prior_graph_raw=fault_context["prior_graph_raw"],
            prior_artifact_id=prior_value["artifact_id"],
            prior_stage_id=prior_value["current_stage_id"],
            graph_profile_registry=registry,
        )
        before_fault = store_independent.verify_database(instance.path, registry)
        forged_value = json.loads(valid_fault_candidate.decode("ascii"))
        forged_value["result"]["status"] = reconciliation_independent.STATUS_OBSERVED_NEW
        forged = _rebind_reconciliation(forged_value)
        with self.assertRaises(store.ArtifactAdmissionError):
            instance.admit_source_reconciliation(
                fault_raw,
                forged,
                registry,
            )
        self.assertEqual(before_fault, store_independent.verify_database(instance.path, registry))

        instance._fault_point = "after_artifact_insert"
        with self.assertRaises(reconciliation.SourceReconciliationError):
            recon_service.reconcile(fault_raw)
        self.assertEqual(before_fault, store_independent.verify_database(instance.path, registry))

    def test_withdrawal_history_concurrency_and_profile_substitution_fail_closed(self) -> None:
        withdrawal_root = self.root / "withdrawal"
        withdrawal_root.mkdir()
        instance, registry, _graph_raw = _approved_store(withdrawal_root)
        source_service = custody.SourceEvidenceCustodyService(instance, graph_profile_registry=registry)
        recon_service = reconciliation.SourceReconciliationService(instance, graph_profile_registry=registry)
        first_raw, _first_recon, _ = self._custody_and_reconcile(source_service, recon_service, _envelope())
        approval_raw = _approval_raw(instance)
        authorization = governance.build_withdrawal_authorization(approval_raw, profile.NC_MEDICAID_GRAPH_PROFILE, withdrawal_time=7_400)
        withdrawal_raw, _ = governance.build_withdrawal(approval_raw, authorization, profile.NC_MEDICAID_GRAPH_PROFILE)
        instance.admit(store.ARTIFACT_GOVERNANCE, withdrawal_raw)

        second_admission = source_service.ingest(_changed_envelope("2026-08-15T11:00:00Z", name="Synthetic Withdrawn Site"))
        self.assertFalse(second_admission.graph_admitted)
        second_raw = _payload_for_receipt(instance, second_admission.custody_receipt)
        barrier = threading.Barrier(2)
        results: list[store.AdmissionReceipt] = []
        errors: list[BaseException] = []

        def worker() -> None:
            try:
                barrier.wait(timeout=5)
                results.append(recon_service.reconcile(second_raw))
            except BaseException as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual([], errors)
        self.assertEqual(2, len(results))
        self.assertEqual(results[0].raw, results[1].raw)
        self.assertEqual(
            reconciliation_independent.STATUS_OBSERVED_CHANGED,
            json.loads(_payload_for_receipt(instance, results[0]).decode("ascii"))["result"]["status"],
        )
        self.assertEqual(9, store_independent.verify_database(instance.path, registry)["event_count"])

        before = store_independent.verify_database(instance.path, registry)
        with self.assertRaises(store.StoreConflictError):
            instance.admit_source_reconciliation(first_raw, results[0].raw, {"wrong": profile.NC_MEDICAID_GRAPH_PROFILE})
        self.assertEqual(before, store_independent.verify_database(instance.path, registry))


if __name__ == "__main__":
    unittest.main()
