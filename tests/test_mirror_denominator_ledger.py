"""Focused synthetic Denominator Ledger V1 seam tests."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import threading
import unittest

from app.governance import provider_continuity_control_pack_v2 as governance
from app.mirror import continuity_export as export
from app.mirror import continuity_store as store
from app.mirror import continuity_store_independent as store_independent
from app.mirror import denominator_ledger as denominator
from app.mirror import denominator_ledger_independent as denominator_independent
from app.mirror import nc_medicaid_fhir as fhir
from app.mirror import source_evidence_custody as custody
from app.mirror import source_evidence_custody_independent as custody_independent
from app.mirror import support_boundary as support
from app.mirror import nc_medicaid_fhir_profile as profile
from tests.test_mirror_source_evidence_custody import _approved_store, _distinct_complete_envelope, _envelope, _partial_envelope
from tests.test_nc_medicaid_fhir_source import _bundle, _location, _practitioner, _role, _transport


class MirrorDenominatorLedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory(prefix="mirror-denominator-")
        self.addCleanup(self._temporary.cleanup)
        self.root = Path(self._temporary.name)

    def _source(self, instance: store.ContinuityStore) -> str:
        rows = instance._snapshot_rows()["artifacts"]
        return next(row["artifact_id"] for row in rows if row["kind"] == custody_independent.ARTIFACT_KIND)

    def _admit_baseline(self) -> tuple[store.ContinuityStore, dict[str, object], str, bytes]:
        instance, registry, _ = _approved_store(self.root)
        custody.SourceEvidenceCustodyService(instance, graph_profile_registry=registry).ingest(_envelope())
        source_id = self._source(instance)
        receipt = denominator.DenominatorLedgerService(instance, graph_profile_registry=registry).create_baseline(source_id)
        row = next(row for row in instance._snapshot_rows()["artifacts"] if row["kind"] == denominator_independent.ARTIFACT_KIND)
        return instance, registry, source_id, bytes(row["payload"])

    def test_baseline_narrowing_conserves_population_and_exact_retry(self) -> None:
        instance, registry, source_id, baseline_raw = self._admit_baseline()
        service = denominator.DenominatorLedgerService(instance, graph_profile_registry=registry)
        baseline_retry = service.create_baseline(source_id)
        baseline_row = next(row for row in instance._snapshot_rows()["artifacts"] if row["kind"] == denominator_independent.ARTIFACT_KIND)
        first_narrow = service.narrow(str(baseline_row["artifact_id"]))
        narrow_retry = service.narrow(str(baseline_row["artifact_id"]))
        self.assertEqual(baseline_retry.raw, next(row for row in instance._snapshot_rows()["receipts"] if row["operation_id"] == baseline_retry.operation_id)["receipt"])
        self.assertEqual(first_narrow.raw, narrow_retry.raw)
        self.assertEqual(1, first_narrow.value["event_sequence"] - baseline_retry.value["event_sequence"])
        rows = [row for row in instance._snapshot_rows()["artifacts"] if row["kind"] == denominator_independent.ARTIFACT_KIND]
        self.assertEqual(2, len(rows))
        baseline = denominator_independent._parse(baseline_raw)
        narrowed = denominator_independent._parse(next(row for row in rows if json.loads(row["payload"].decode("ascii"))["stage_kind"] == denominator_independent.STAGE_NARROWED)["payload"])
        self.assertEqual("UNKNOWN", baseline["population"]["source_completeness"])
        self.assertFalse(baseline["population"]["allow_nonmembership"])
        self.assertEqual(narrowed["narrowing"]["input_record_count"], sum(narrowed["narrowing"]["outcome_counts"].values()))
        self.assertEqual(narrowed["narrowing"]["input_record_count"], sum(narrowed["narrowing"]["reason_counts"].values()))
        self.assertEqual(1, narrowed["narrowing"]["outcome_counts"][denominator_independent.BUCKET_RETAINED])
        self.assertTrue(store_independent.verify_database(instance.path, registry)["accepted"])

    def test_partial_source_is_accounted_without_complete_or_absence_claim(self) -> None:
        instance, registry, _ = _approved_store(self.root)
        admission = custody.SourceEvidenceCustodyService(instance, graph_profile_registry=registry).ingest(_partial_envelope())
        self.assertFalse(admission.graph_admitted)
        source_id = self._source(instance)
        denominator.DenominatorLedgerService(instance, graph_profile_registry=registry).create_baseline(source_id)
        row = next(row for row in instance._snapshot_rows()["artifacts"] if row["kind"] == denominator_independent.ARTIFACT_KIND)
        value = denominator_independent._parse(bytes(row["payload"]))
        self.assertEqual(denominator_independent.COVERAGE_PARTIAL_UNKNOWN, value["population"]["coverage_status"])
        self.assertEqual(1, value["population"]["source_quality"]["source_gap"])
        self.assertEqual(0, value["population"]["source_quality"]["source_conflict"])
        self.assertFalse(value["flags"]["complete_population_proven"])
        self.assertFalse(value["flags"]["nonmembership_inferred"])

    def test_marker_conflict_is_explicitly_bucketed(self) -> None:
        instance, registry, _ = _approved_store(self.root)
        first = _bundle(0, resources=[_practitioner(), _role()], next_page=True, total=3)
        second = _bundle(1, resources=[_location()], total=2)
        conflicting = fhir.build_fixture_envelope(_transport(first, second))
        custody.SourceEvidenceCustodyService(instance, graph_profile_registry=registry).ingest(conflicting)
        source_id = self._source(instance)
        denominator.DenominatorLedgerService(instance, graph_profile_registry=registry).create_baseline(source_id)
        row = next(row for row in instance._snapshot_rows()["artifacts"] if row["kind"] == denominator_independent.ARTIFACT_KIND)
        denominator.DenominatorLedgerService(instance, graph_profile_registry=registry).narrow(str(row["artifact_id"]))
        narrowed = next(
            denominator_independent._parse(bytes(item["payload"]))
            for item in instance._snapshot_rows()["artifacts"]
            if item["kind"] == denominator_independent.ARTIFACT_KIND
            and json.loads(item["payload"].decode("ascii"))["stage_kind"] == denominator_independent.STAGE_NARROWED
        )
        self.assertEqual(denominator_independent.COVERAGE_CONFLICTING_UNKNOWN, narrowed["narrowing"]["coverage_status"])
        self.assertEqual(1, narrowed["narrowing"]["outcome_counts"][denominator_independent.BUCKET_CONFLICTED])

    def test_governed_rule_exclusion_is_not_a_silent_drop(self) -> None:
        instance, registry, _ = _approved_store(self.root)
        inactive = _practitioner()
        inactive["active"] = False
        excluded_envelope = fhir.build_fixture_envelope(_transport(_bundle(resources=[inactive, _role(), _location()])))
        custody.SourceEvidenceCustodyService(instance, graph_profile_registry=registry).ingest(excluded_envelope)
        source_id = self._source(instance)
        denominator.DenominatorLedgerService(instance, graph_profile_registry=registry).create_baseline(source_id)
        baseline_row = next(row for row in instance._snapshot_rows()["artifacts"] if row["kind"] == denominator_independent.ARTIFACT_KIND)
        denominator.DenominatorLedgerService(instance, graph_profile_registry=registry).narrow(str(baseline_row["artifact_id"]))
        narrowed = next(
            denominator_independent._parse(bytes(item["payload"]))
            for item in instance._snapshot_rows()["artifacts"]
            if item["kind"] == denominator_independent.ARTIFACT_KIND
            and json.loads(item["payload"].decode("ascii"))["stage_kind"] == denominator_independent.STAGE_NARROWED
        )
        self.assertEqual(1, narrowed["narrowing"]["outcome_counts"][denominator_independent.BUCKET_EXCLUDED])
        self.assertEqual(1, narrowed["narrowing"]["reason_counts"][denominator_independent.REASON_EXCLUDED])
        self.assertEqual(1, narrowed["narrowing"]["input_record_count"])

    def test_independent_verifier_rejects_rebound_counts_without_mutation(self) -> None:
        instance, registry, _source_id, baseline_raw = self._admit_baseline()
        before = store_independent.verify_database(instance.path, registry)
        value = json.loads(baseline_raw.decode("ascii"))
        value["population"]["input_record_count"] = 2
        forged = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
        rows = instance._snapshot_rows()["artifacts"]
        source_row = next(row for row in rows if row["kind"] == custody_independent.ARTIFACT_KIND)
        source_raw = bytes(source_row["payload"])
        source_value = json.loads(source_raw.decode("ascii"))
        graph_raw = None
        if source_value["graph_link"] is not None:
            graph_id = source_value["graph_link"]["artifact_id"]
            graph_raw = bytes(next(row for row in rows if row["kind"] == store.ARTIFACT_GRAPH and row["artifact_id"] == graph_id)["payload"])
        governance_id = value["governance_binding"]["artifact_id"]
        governance_raw = bytes(next(row for row in rows if row["kind"] == store.ARTIFACT_GOVERNANCE and row["artifact_id"] == governance_id)["payload"])
        with self.assertRaisesRegex(denominator_independent.IndependentDenominatorError, "semantic-binding|conservation"):
            denominator_independent.verify_artifact(
                forged,
                source_raw=source_raw,
                graph_raw=graph_raw,
                governance_raw=governance_raw,
                registry=registry,
            )
        self.assertEqual(before, store_independent.verify_database(instance.path, registry))

    def test_fault_rollback_and_export_restore_include_denominator(self) -> None:
        instance, registry, _ = _approved_store(self.root)
        custody.SourceEvidenceCustodyService(instance, graph_profile_registry=registry).ingest(_envelope())
        source_id = self._source(instance)
        before = store_independent.verify_database(instance.path, registry)
        instance._fault_point = "after_artifact_insert"
        with self.assertRaises(store.InjectedFault):
            denominator.DenominatorLedgerService(instance, graph_profile_registry=registry).create_baseline(source_id)
        self.assertEqual(before, store_independent.verify_database(instance.path, registry))
        denominator.DenominatorLedgerService(instance, graph_profile_registry=registry).create_baseline(source_id)
        exported = export.export_database(instance.path, registry)
        self.assertEqual(1, export.verify_export_bytes(exported, registry)["accepted"])
        restored = self.root / "restored.db"
        self.assertTrue(export.import_export(exported, restored, registry)["restored"])
        self.assertEqual(store_independent.verify_database(instance.path, registry), store_independent.verify_database(restored, registry))

    def test_withdrawal_blocks_new_baseline_but_history_remains_verifiable(self) -> None:
        instance, registry, _source_id, _baseline_raw = self._admit_baseline()
        approval_row = next(
            row for row in instance._snapshot_rows()["artifacts"]
            if row["kind"] == store.ARTIFACT_GOVERNANCE and json.loads(row["payload"].decode("ascii")).get("current_stage_kind") == governance.STAGE_APPROVED
        )
        withdrawal_auth = governance.build_withdrawal_authorization(bytes(approval_row["payload"]), profile.NC_MEDICAID_GRAPH_PROFILE, withdrawal_time=7_400)
        withdrawal, _ = governance.build_withdrawal(bytes(approval_row["payload"]), withdrawal_auth, profile.NC_MEDICAID_GRAPH_PROFILE)
        instance.admit(store.ARTIFACT_GOVERNANCE, withdrawal)
        baseline_row = next(row for row in instance._snapshot_rows()["artifacts"] if row["kind"] == denominator_independent.ARTIFACT_KIND)
        # Historical narrowing uses the approval bound into the baseline, not
        # the withdrawn current head.
        denominator.DenominatorLedgerService(instance, graph_profile_registry=registry).narrow(str(baseline_row["artifact_id"]))
        self.assertTrue(store_independent.verify_database(instance.path, registry)["accepted"])
        # A new source custody observation cannot create a new governed
        # denominator baseline after withdrawal.
        custody.SourceEvidenceCustodyService(instance, graph_profile_registry=registry).ingest(_distinct_complete_envelope())
        source_ids = [row["artifact_id"] for row in instance._snapshot_rows()["artifacts"] if row["kind"] == custody_independent.ARTIFACT_KIND]
        with self.assertRaises(store.GovernanceObservationOnly):
            denominator.DenominatorLedgerService(instance, graph_profile_registry=registry).create_baseline(source_ids[-1])

    def test_support_is_aggregate_only_and_no_raw_fixture_identifier(self) -> None:
        instance, registry, _source_id, _baseline_raw = self._admit_baseline()
        raw = support.build_support_bundle(instance.path, graph_profile_registry=registry)
        result = support.verify_support_bytes(raw)
        self.assertEqual("DB_CONFORMANCE_PASS", result["diagnostic_code"])
        self.assertNotIn(profile.SYNTHETIC_PRACTITIONER_ID.encode("ascii"), raw)
        self.assertNotIn(profile.SYNTHETIC_LOCATION_ID.encode("ascii"), raw)
        self.assertNotIn(b"mirror-denominator-ledger-v1", raw)

    def test_same_narrowing_call_converges_under_concurrency(self) -> None:
        instance, registry, _source_id, _baseline_raw = self._admit_baseline()
        baseline_row = next(row for row in instance._snapshot_rows()["artifacts"] if row["kind"] == denominator_independent.ARTIFACT_KIND)
        service = denominator.DenominatorLedgerService(instance, graph_profile_registry=registry)
        results: list[bytes] = []
        failures: list[BaseException] = []

        def run() -> None:
            try:
                results.append(service.narrow(str(baseline_row["artifact_id"])).raw)
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


if __name__ == "__main__":
    unittest.main()
