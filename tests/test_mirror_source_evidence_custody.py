"""Focused adversarial tests for state-side NC fixture evidence custody."""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest import mock

from app.governance import provider_continuity_control_pack_v2 as governance
from app.mirror import continuity_export as export
from app.mirror import continuity_store as store
from app.mirror import continuity_store_independent as store_independent
from app.mirror import nc_medicaid_fhir as fhir
from app.mirror import nc_medicaid_fhir_independent as fhir_independent
from app.mirror import nc_medicaid_fhir_profile as profile
from app.mirror import source_evidence_custody as custody
from app.mirror import source_evidence_custody_independent as custody_independent
from app.mirror import support_boundary as support
from app.mirror import provider_trust_graph as graph
from app.mirror.source_admission import SourceAdmissionService
from tests.test_nc_medicaid_fhir_source import _bundle, _envelope, _location, _practitioner, _role, _transport


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")


def _approved_store(root: Path) -> tuple[store.ContinuityStore, dict[str, object], bytes]:
    registry = dict(profile.NC_MEDICAID_GRAPH_PROFILE_REGISTRY)
    database = root / "state.db"
    instance = store.ContinuityStore(database, graph_profile_registry=registry)
    admission = SourceAdmissionService(
        profile.NC_MEDICAID_GRAPH_PROFILE,
        fhir_independent.NcMedicaidFhirVerifier(),
    ).admit(_envelope())
    candidate, _ = governance.build_candidate(admission.graph_artifact, profile.NC_MEDICAID_GRAPH_PROFILE)
    tested, _ = governance.build_tested(candidate, profile.NC_MEDICAID_GRAPH_PROFILE)
    approval_record = governance.build_approval_record(tested, profile.NC_MEDICAID_GRAPH_PROFILE, approval_time=7_300)
    approved, _ = governance.build_approved(tested, approval_record, profile.NC_MEDICAID_GRAPH_PROFILE)
    for artifact in (candidate, tested, approved):
        instance.admit(store.ARTIFACT_GOVERNANCE, artifact)
    return instance, registry, admission.graph_artifact


def _rebind_artifact(value: dict[str, object]) -> bytes:
    body = dict(value)
    body.pop("artifact_id")
    body.pop("current_stage_id")
    body.pop("transition_id")
    artifact_id = custody_independent._digest("artifact-id", body)
    stage_id = custody_independent._digest(
        "stage-id",
        {
            "artifact_id": artifact_id,
            "envelope_digest": value["envelope_digest"],
            "source_status": value["source_status"],
            "prior_artifact_id": value["prior_artifact_id"],
            "prior_stage_id": value["prior_stage_id"],
        },
    )
    transition_id = custody_independent._digest(
        "transition-id",
        {
            "artifact_id": artifact_id,
            "current_stage_id": stage_id,
            "prior_artifact_id": value["prior_artifact_id"],
            "prior_stage_id": value["prior_stage_id"],
        },
    )
    return _canonical({**body, "artifact_id": artifact_id, "current_stage_id": stage_id, "transition_id": transition_id})


def _partial_envelope() -> bytes:
    first = _bundle(0, resources=[_practitioner(), _role()], next_page=True)
    return fhir.build_fixture_envelope(_transport(first))


def _distinct_complete_envelope() -> bytes:
    return fhir.build_fixture_envelope(_transport(_bundle(resources=[_location(), _role(), _practitioner()])))


class MirrorSourceEvidenceCustodyTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory(prefix="mirror-source-custody-")
        self.addCleanup(self._temporary.cleanup)
        self.root = Path(self._temporary.name)

    def test_approved_fixture_custody_is_atomic_and_exactly_retryable(self) -> None:
        instance, registry, graph_raw = _approved_store(self.root)
        service = custody.SourceEvidenceCustodyService(instance, graph_profile_registry=registry)
        envelope = _envelope()
        first = service.ingest(envelope)
        before = store_independent.verify_database(instance.path, registry)
        replay = service.ingest(envelope)
        after = store_independent.verify_database(instance.path, registry)
        self.assertTrue(first.graph_admitted)
        self.assertIsNotNone(first.graph_receipt)
        self.assertEqual(first.custody_receipt.raw, replay.custody_receipt.raw)
        self.assertEqual(first.graph_receipt.raw if first.graph_receipt else None, replay.graph_receipt.raw if replay.graph_receipt else None)
        self.assertEqual(before, after)
        self.assertEqual(5, after["event_count"])
        self.assertEqual(5, after["artifact_count"])
        self.assertTrue(store_independent.verify_database(instance.path, registry)["accepted"])
        custody_row = next(row for row in instance._snapshot_rows()["artifacts"] if row["kind"] == custody_independent.ARTIFACT_KIND)
        custody_value = json.loads(custody_row["payload"].decode("ascii"))
        self.assertEqual(custody_independent.ARTIFACT_KIND, custody_row["kind"])
        self.assertEqual(profile.SOURCE_PROFILE_ID, custody_value["profile_binding"]["source_profile_id"])
        self.assertEqual(graph_raw is not None, custody_value["graph_link"] is not None)
        self.assertEqual("STATE_SIDE_MIRROR_CUSTODY", custody_value["custody_policy"]["owner"])
        self.assertFalse(custody_value["custody_policy"]["encryption_at_rest_qualified"])

    def test_partial_fixture_is_custodied_without_graph_or_absence_claim(self) -> None:
        registry = dict(profile.NC_MEDICAID_GRAPH_PROFILE_REGISTRY)
        instance = store.ContinuityStore(self.root / "partial.db", graph_profile_registry=registry)
        result = custody.SourceEvidenceCustodyService(instance, graph_profile_registry=registry).ingest(_partial_envelope())
        self.assertFalse(result.graph_admitted)
        self.assertEqual(1, store_independent.verify_database(instance.path, registry)["event_count"])
        rows = instance._snapshot_rows()["artifacts"]
        value = json.loads(rows[0]["payload"].decode("ascii"))
        self.assertIsNone(value["graph_link"])
        self.assertEqual("PARTIAL", value["source_status"])
        self.assertEqual("UNKNOWN", value["source_completeness"])
        self.assertFalse(value["allow_nonmembership"])

    def test_governance_observation_outcome_is_typed_and_atomic(self) -> None:
        registry = dict(profile.NC_MEDICAID_GRAPH_PROFILE_REGISTRY)
        instance = store.ContinuityStore(self.root / "typed-governance.db", graph_profile_registry=registry)
        admission = SourceAdmissionService(
            profile.NC_MEDICAID_GRAPH_PROFILE,
            fhir_independent.NcMedicaidFhirVerifier(),
        ).admit(_envelope())
        result = fhir_independent.verify_bytes(_envelope())
        candidate = custody.build_artifact(_envelope(), result, admission=admission)
        before = store_independent.verify_database(instance.path, registry)
        with self.assertRaises(store.GovernanceObservationOnly) as caught:
            instance.admit_source_evidence(candidate.raw, admission.graph_artifact, registry)
        self.assertEqual("not-approved", caught.exception.reason)
        self.assertEqual(before, store_independent.verify_database(instance.path, registry))

        retained = custody.SourceEvidenceCustodyService(instance, graph_profile_registry=registry).ingest(_envelope())
        self.assertFalse(retained.graph_admitted)
        self.assertEqual(1, store_independent.verify_database(instance.path, registry)["event_count"])

    def test_non_governance_store_conflicts_never_fallback_or_mutate(self) -> None:
        for index, reason in enumerate(("governance:profile-binding", "governance:effective-interval", "head:stale-or-wrong-prior")):
            with self.subTest(reason=reason):
                fault_root = self.root / f"conflict-{index}"
                fault_root.mkdir()
                instance, registry, _graph_raw = _approved_store(fault_root)
                service = custody.SourceEvidenceCustodyService(instance, graph_profile_registry=registry)
                before = store_independent.verify_database(instance.path, registry)
                with mock.patch.object(
                    instance,
                    "admit_source_evidence_with_governance_observation",
                    side_effect=store.StoreConflictError(reason),
                ) as attempt:
                    with self.assertRaises(store.StoreConflictError):
                        service.ingest(_envelope())
                attempt.assert_called_once()
                self.assertEqual(before, store_independent.verify_database(instance.path, registry))

        atomic_root = self.root / "atomic-conflict"
        atomic_root.mkdir()
        instance, registry, _graph_raw = _approved_store(atomic_root)
        service = custody.SourceEvidenceCustodyService(instance, graph_profile_registry=registry)
        before = store_independent.verify_database(instance.path, registry)
        with mock.patch.object(
            instance,
            "_require_active_v2_governance",
            side_effect=store.StoreConflictError("governance:profile-binding"),
        ) as gate:
            with self.assertRaises(store.StoreConflictError):
                service.ingest(_envelope())
        gate.assert_called_once()
        self.assertEqual(before, store_independent.verify_database(instance.path, registry))

    def test_unapproved_or_withdrawn_graph_is_not_admitted_but_evidence_remains_durable(self) -> None:
        registry = dict(profile.NC_MEDICAID_GRAPH_PROFILE_REGISTRY)
        instance = store.ContinuityStore(self.root / "unapproved.db", graph_profile_registry=registry)
        service = custody.SourceEvidenceCustodyService(instance, graph_profile_registry=registry)
        first = service.ingest(_envelope())
        self.assertFalse(first.graph_admitted)
        self.assertEqual(1, store_independent.verify_database(instance.path, registry)["event_count"])

        withdrawn_root = self.root / "withdrawn"
        withdrawn_root.mkdir()
        approved, registry, _graph_raw = _approved_store(withdrawn_root)
        service = custody.SourceEvidenceCustodyService(approved, graph_profile_registry=registry)
        governed = service.ingest(_envelope())
        self.assertTrue(governed.graph_admitted)
        self.assertEqual(5, store_independent.verify_database(approved.path, registry)["event_count"])

        # A distinct complete fixture is accepted as observation custody after
        # withdrawal, but cannot create another governed graph admission.
        connection = sqlite3.connect(approved.path)
        try:
            approval_raw = connection.execute(
                "SELECT a.payload FROM artifacts a JOIN heads h ON h.artifact_id=a.artifact_id WHERE a.kind=? AND h.stage_kind=?",
                (store.ARTIFACT_GOVERNANCE, governance.STAGE_APPROVED),
            ).fetchone()[0]
        finally:
            connection.close()
        withdrawal_auth = governance.build_withdrawal_authorization(
            approval_raw,
            profile.NC_MEDICAID_GRAPH_PROFILE,
            withdrawal_time=7_400,
        )
        withdrawal, _ = governance.build_withdrawal(approval_raw, withdrawal_auth, profile.NC_MEDICAID_GRAPH_PROFILE)
        approved.admit(store.ARTIFACT_GOVERNANCE, withdrawal)
        second = service.ingest(_distinct_complete_envelope())
        self.assertFalse(second.graph_admitted)
        self.assertEqual(7, store_independent.verify_database(approved.path, registry)["event_count"])

    def test_stale_and_failed_statuses_are_custodied_without_graph_authority(self) -> None:
        registry = dict(profile.NC_MEDICAID_GRAPH_PROFILE_REGISTRY)
        instance = store.ContinuityStore(self.root / "status.db", graph_profile_registry=registry)
        service = custody.SourceEvidenceCustodyService(instance, graph_profile_registry=registry)
        stale = service.ingest(_envelope(last_updated="2020-01-01T00:00:00Z"))
        partial = service.ingest(_partial_envelope())
        self.assertFalse(stale.graph_admitted)
        self.assertFalse(partial.graph_admitted)
        statuses = sorted(
            json.loads(row["payload"].decode("ascii"))["source_status"]
            for row in instance._snapshot_rows()["artifacts"]
            if row["kind"] == custody_independent.ARTIFACT_KIND
        )
        self.assertEqual(["PARTIAL", "STALE"], statuses)
        self.assertEqual(2, store_independent.verify_database(instance.path, registry)["event_count"])

    def test_profile_or_database_tamper_is_independently_rejected_and_support_is_sanitized(self) -> None:
        instance, registry, graph_raw = _approved_store(self.root)
        service = custody.SourceEvidenceCustodyService(instance, graph_profile_registry=registry)
        service.ingest(_envelope())
        before = store_independent.verify_database(instance.path, registry)
        custody_row = next(row for row in instance._snapshot_rows()["artifacts"] if row["kind"] == custody_independent.ARTIFACT_KIND)
        value = json.loads(custody_row["payload"].decode("ascii"))
        value["profile_binding"]["source_profile_digest"] = "0" * 128
        forged_profile = _rebind_artifact(value)
        with self.assertRaises(custody_independent.IndependentSourceCustodyError):
            custody_independent.verify_artifact(forged_profile, graph_raw=graph_raw, graph_profile_registry=registry)
        self.assertEqual(before, store_independent.verify_database(instance.path, registry))
        with self.assertRaises(custody.SourceEvidenceCustodyError):
            custody.SourceEvidenceCustodyService(instance, source_profile=None, graph_profile_registry=registry)  # type: ignore[arg-type]
        with self.assertRaises(custody.SourceEvidenceCustodyError):
            custody.SourceEvidenceCustodyService(instance, graph_profile_registry={"caller": profile.NC_MEDICAID_GRAPH_PROFILE})

        connection = sqlite3.connect(instance.path)
        try:
            connection.execute(
                "UPDATE artifacts SET payload=? WHERE kind=? AND artifact_id=?",
                (sqlite3.Binary(forged_profile), custody_independent.ARTIFACT_KIND, custody_row["artifact_id"]),
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(store_independent.IndependentStoreError):
            store_independent.verify_database(instance.path, registry)
        bundle = support.build_support_bundle(instance.path, graph_profile_registry=registry)
        self.assertIn(support.verify_support_bytes(bundle)["diagnostic_code"], support.DIAGNOSTIC_CODES)
        self.assertNotIn(profile.SYNTHETIC_PRACTITIONER_ID, bundle.decode("ascii"))

    def test_forged_receipt_and_graph_substitution_reject_without_mutation(self) -> None:
        instance, registry, graph_raw = _approved_store(self.root)
        admission = SourceAdmissionService(
            profile.NC_MEDICAID_GRAPH_PROFILE,
            fhir_independent.NcMedicaidFhirVerifier(),
        ).admit(_envelope())
        result = fhir_independent.verify_bytes(_envelope())
        candidate = custody.build_artifact(_envelope(), result, admission=admission)
        value = json.loads(candidate.raw.decode("ascii"))
        value["verification_receipt"]["resource_count"] += 1
        forged = _rebind_artifact(value)
        before = store_independent.verify_database(instance.path, registry)
        with self.assertRaises(custody_independent.IndependentSourceCustodyError):
            custody_independent.verify_artifact(forged, graph_raw=graph_raw, graph_profile_registry=registry)
        with self.assertRaises(store.StoreConflictError):
            instance.admit_source_evidence(forged, graph_raw, registry)
        self.assertEqual(before, store_independent.verify_database(instance.path, registry))

        different_input = json.loads(admission.graph_input.decode("utf-8"))
        different_input["observation_time"] = 7_001
        for source in different_input["sources"]:
            source["coverage_observation_time"] = 7_001
            source["coverage_effective_start"] = 6_000
            source["coverage_effective_end"] = 9_000
            for record in source["records"]:
                record["observed_at"] = 7_001
        different_graph, _ = graph.build_report(
            graph.canonical_input(graph.refresh_input_digests(different_input, profile.NC_MEDICAID_GRAPH_PROFILE)),
            profile=profile.NC_MEDICAID_GRAPH_PROFILE,
        )
        with self.assertRaises(store.StoreConflictError):
            instance.admit_source_evidence(candidate.raw, different_graph, registry)
        self.assertEqual(before, store_independent.verify_database(instance.path, registry))

    def test_transaction_fault_rolls_back_both_custody_and_graph_events(self) -> None:
        instance, registry, _graph_raw = _approved_store(self.root)
        before = store_independent.verify_database(instance.path, registry)
        instance._fault_point = "after_artifact_insert"
        with self.assertRaises(store.InjectedFault):
            custody.SourceEvidenceCustodyService(instance, graph_profile_registry=registry).ingest(_envelope())
        self.assertEqual(before, store_independent.verify_database(instance.path, registry))

    def test_concurrent_exact_ingestion_converges_and_export_restore_is_deterministic(self) -> None:
        instance, registry, _graph_raw = _approved_store(self.root)
        service = custody.SourceEvidenceCustodyService(instance, graph_profile_registry=registry)
        barrier = threading.Barrier(2)
        results: list[store.SourceCustodyAdmission] = []
        errors: list[BaseException] = []

        def worker() -> None:
            try:
                barrier.wait(timeout=5)
                results.append(service.ingest(_envelope()))
            except BaseException as exc:  # the assertion below reports any peer failure
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual([], errors)
        self.assertEqual(2, len(results))
        self.assertEqual(results[0].custody_receipt.raw, results[1].custody_receipt.raw)
        exported = export.export_database(instance.path, registry)
        export_value = json.loads(exported.decode("ascii"))
        exported_payloads = [bytes.fromhex(item["payload_hex"]) for item in export_value["artifacts"]]
        self.assertTrue(any(_envelope().hex().encode("ascii") in payload for payload in exported_payloads))
        restored = self.root / "restored.db"
        export.import_export(exported, restored, registry)
        self.assertEqual(exported, export.export_database(restored, registry))
        self.assertEqual(store_independent.verify_database(restored, registry), store_independent.verify_database(instance.path, registry))

        bundle = support.build_support_bundle(instance.path, graph_profile_registry=registry)
        self.assertTrue(support.verify_support_bytes(bundle)["accepted"])
        text = bundle.decode("ascii")
        self.assertNotIn(profile.SYNTHETIC_PRACTITIONER_ID, text)
        self.assertNotIn("NCPROV-001", text)
        self.assertNotIn("Synthetic NC Site", text)
        self.assertNotIn(_envelope().hex(), text)

        corrupted = bytearray(exported)
        corrupted[-1] = ord("0") if corrupted[-1] != ord("0") else ord("1")
        with self.assertRaises(export.ContinuityExportError):
            export.verify_export_bytes(bytes(corrupted), registry)


if __name__ == "__main__":
    unittest.main()
