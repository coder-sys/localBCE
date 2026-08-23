"""Focused tests for the synthetic Mirror continuity operational candidate."""

from __future__ import annotations

from copy import deepcopy
from contextlib import redirect_stderr
import io
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest

from app.governance import provider_continuity_control_pack as governance
from app.governance import provider_continuity_control_pack_withdrawal as withdrawal
from app.mirror import continuity_export as export
from app.mirror import continuity_store as store
from app.mirror import continuity_store_independent as independent
from app.mirror import restore_publication
from app.mirror import provider_trust_graph as graph
from app.mirror import support_boundary as support
from tests.test_provider_continuity_control_pack import APPROVAL_FIXTURE_BYTES
from tests.test_provider_continuity_control_pack_withdrawal import _authorization


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")


def _object(raw: bytes) -> dict[str, object]:
    value = json.loads(raw.decode("ascii"))
    assert isinstance(value, dict)
    return value


def _graph_retest_raw() -> tuple[bytes, bytes]:
    prior_raw, _ = graph.build_demo_report("expired")
    prior = graph.prior_link_from_artifact(prior_raw)
    current = graph.demo_input("confirmed")
    current["observation_time"] = 8_000
    for source in current["sources"]:
        source["coverage_observation_time"] = 8_000
        source["coverage_effective_start"] = 7_000
        source["coverage_effective_end"] = 9_000
        for record in source["records"]:
            record["observed_at"] = 8_000
    current["prior_artifact"] = prior
    current["remediation"] = {
        "action_artifact_id": "SYNTH_ACTION_001",
        "submitted_at": 7_500,
        "retest_result": "PASSED",
        "prior_finding_ids": [prior["findings"][0]["finding_id"]],
    }
    retest_raw, _ = graph.build_report(graph.canonical_input(graph.refresh_input_digests(current)))
    return prior_raw, retest_raw


def _governance_chain() -> tuple[bytes, bytes, bytes]:
    candidate, _ = governance.build_demo_candidate("confirmed")
    tested, _ = governance.build_tested(candidate)
    approved, _ = governance.build_approved(tested, APPROVAL_FIXTURE_BYTES)
    return candidate, tested, approved


def _governance_withdrawal() -> tuple[bytes, bytes, bytes, bytes]:
    candidate, tested, approved = _governance_chain()
    withdrawal_raw, _ = withdrawal.build_withdrawal(approved, _authorization(approved))
    return candidate, tested, approved, withdrawal_raw


class MirrorContinuityOperationalFoundationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.directory = Path(self._temporary.name)
        self.database = self.directory / "continuity.db"

    def _store(self) -> store.ContinuityStore:
        return store.ContinuityStore(self.database)

    def _admit_graph(self, instance: store.ContinuityStore | None = None) -> tuple[bytes, store.AdmissionReceipt]:
        raw, _ = graph.build_demo_report("confirmed")
        receipt = (instance or self._store()).admit(store.ARTIFACT_GRAPH, raw)
        return raw, receipt

    def _tamper(self, sql: str, parameters: tuple[object, ...] = ()) -> None:
        connection = sqlite3.connect(self.database)
        try:
            connection.execute(sql, parameters)
            connection.commit()
        finally:
            connection.close()

    def _tamper_statements(self, statements: tuple[str, ...]) -> None:
        connection = sqlite3.connect(self.database)
        try:
            for statement in statements:
                connection.execute(statement)
            connection.commit()
        finally:
            connection.close()

    def _file_state(self) -> tuple[tuple[str, bytes | None], ...]:
        paths = (self.database, Path(str(self.database) + "-wal"), Path(str(self.database) + "-shm"))
        return tuple((path.name, path.read_bytes() if path.is_file() else None) for path in paths)

    def _row_counts(self) -> tuple[int, ...]:
        connection = sqlite3.connect(self.database)
        try:
            return tuple(int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]) for table in ("artifacts", "operations", "receipts", "events", "heads"))
        finally:
            connection.close()

    def test_fresh_graph_initial_retest_restart_and_cross_process_verification(self) -> None:
        prior_raw, retest_raw = _graph_retest_raw()
        instance = self._store()
        first = instance.admit(store.ARTIFACT_GRAPH, prior_raw)
        second = instance.admit(store.ARTIFACT_GRAPH, retest_raw)
        self.assertNotEqual(first.raw, second.raw)
        self.assertEqual(2, independent.verify_database(self.database)["event_count"])
        instance.close()
        restarted = store.ContinuityStore(self.database)
        self.assertEqual(second.raw, restarted.admit(store.ARTIFACT_GRAPH, retest_raw).raw)
        accepted = subprocess.run(
            [sys.executable, "-m", "app.mirror.continuity_store_independent", str(self.database)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(0, accepted.returncode, accepted.stderr)
        self.assertIn('"accepted":true', accepted.stdout)

    def test_governance_candidate_tested_approved_chain_and_authority_flags(self) -> None:
        candidate, tested, approved = _governance_chain()
        instance = self._store()
        for raw in (candidate, tested, approved):
            receipt = instance.admit(store.ARTIFACT_GOVERNANCE, raw)
            self.assertEqual(128, len(receipt.value["operation_id"]))
        result = independent.verify_database(self.database)
        self.assertEqual({"artifact_count": 3, "event_count": 3, "receipt_count": 3, "head_count": 1}, {key: result[key] for key in ("artifact_count", "event_count", "receipt_count", "head_count")})
        for raw in (candidate, tested, approved):
            self.assertNotIn(b"CLEAR", raw)
            self.assertNotIn(b"payment_directive", raw.lower())

    def test_terminal_withdrawal_advances_durable_lifecycle_head_and_replays_exactly(self) -> None:
        candidate, tested, approved, withdrawal_raw = _governance_withdrawal()
        instance = self._store()
        for raw in (candidate, tested, approved):
            instance.admit(store.ARTIFACT_GOVERNANCE, raw)
        before = instance.provider_continuity_lifecycle_head(
            governance.PROVIDER_GRAPH_SUBJECT,
            governance.SCOPE,
        )
        self.assertIsNotNone(before)
        assert before is not None
        self.assertEqual(governance.STAGE_APPROVED, before.stage_kind)
        self.assertEqual(store.LIFECYCLE_STATUS_APPROVED, before.status)
        self.assertTrue(before.active)
        self.assertFalse(before.terminal)

        normalized = store.verify_artifact(store.ARTIFACT_GOVERNANCE, withdrawal_raw)
        self.assertEqual(withdrawal.SCHEMA, normalized.schema)
        self.assertEqual(withdrawal.ACTION, normalized.stage_kind)
        self.assertEqual(before.artifact_id, normalized.prior_artifact_id)
        receipt = instance.admit(store.ARTIFACT_GOVERNANCE, withdrawal_raw)
        replay = instance.admit(store.ARTIFACT_GOVERNANCE, withdrawal_raw)
        self.assertEqual(receipt.raw, replay.raw)

        after = instance.provider_continuity_lifecycle_head(
            governance.PROVIDER_GRAPH_SUBJECT,
            governance.SCOPE,
        )
        self.assertIsNotNone(after)
        assert after is not None
        self.assertEqual(withdrawal.ACTION, after.stage_kind)
        self.assertEqual(store.LIFECYCLE_STATUS_WITHDRAWN, after.status)
        self.assertFalse(after.active)
        self.assertTrue(after.terminal)
        self.assertGreater(after.event_sequence, before.event_sequence)
        result = independent.verify_database(self.database)
        self.assertEqual(4, result["event_count"])
        self.assertEqual(1, result["head_count"])

    def test_withdrawal_requires_approved_head_and_does_not_mutate(self) -> None:
        candidate, tested, _approved, withdrawal_raw = _governance_withdrawal()
        instance = self._store()
        instance.admit(store.ARTIFACT_GOVERNANCE, candidate)
        instance.admit(store.ARTIFACT_GOVERNANCE, tested)
        before_counts = self._row_counts()
        with self.assertRaisesRegex(store.StoreConflictError, "head:stale-or-wrong-prior"):
            instance.admit(store.ARTIFACT_GOVERNANCE, withdrawal_raw)
        self.assertEqual(before_counts, self._row_counts())
        head = instance.provider_continuity_lifecycle_head(
            governance.PROVIDER_GRAPH_SUBJECT,
            governance.SCOPE,
        )
        self.assertIsNotNone(head)
        assert head is not None
        self.assertEqual(store.LIFECYCLE_STATUS_NOT_APPROVED, head.status)
        self.assertFalse(head.active)
        self.assertEqual(2, independent.verify_database(self.database)["event_count"])

    def test_terminal_withdrawal_survives_state_owned_export_and_fresh_restore(self) -> None:
        candidate, tested, approved, withdrawal_raw = _governance_withdrawal()
        instance = self._store()
        for raw in (candidate, tested, approved, withdrawal_raw):
            instance.admit(store.ARTIFACT_GOVERNANCE, raw)
        expected = instance.provider_continuity_lifecycle_head(
            governance.PROVIDER_GRAPH_SUBJECT,
            governance.SCOPE,
        )
        self.assertIsNotNone(expected)
        exported = export.export_database(self.database)
        self.assertEqual(exported, export.export_database(self.database))
        export.verify_export_bytes(exported)
        restored = self.directory / "withdrawn-restored.db"
        export.import_export(exported, restored)
        restored_head = store.ContinuityStore(restored).provider_continuity_lifecycle_head(
            governance.PROVIDER_GRAPH_SUBJECT,
            governance.SCOPE,
        )
        self.assertEqual(expected, restored_head)
        self.assertIsNotNone(restored_head)
        assert restored_head is not None
        self.assertEqual(store.LIFECYCLE_STATUS_WITHDRAWN, restored_head.status)
        self.assertFalse(restored_head.active)
        self.assertTrue(restored_head.terminal)
        self.assertEqual(4, independent.verify_database(restored)["event_count"])

    def test_lifecycle_head_fails_closed_on_durable_head_tamper(self) -> None:
        candidate, tested, approved, _withdrawal_raw = _governance_withdrawal()
        instance = self._store()
        instance.admit(store.ARTIFACT_GOVERNANCE, candidate)
        instance.admit(store.ARTIFACT_GOVERNANCE, tested)
        instance.admit(store.ARTIFACT_GOVERNANCE, approved)
        self._tamper("UPDATE heads SET stage_kind=?", (withdrawal.ACTION,))
        with self.assertRaisesRegex(store.StoreSchemaError, "database:conformance:database:head-binding"):
            instance.provider_continuity_lifecycle_head(
                governance.PROVIDER_GRAPH_SUBJECT,
                governance.SCOPE,
            )

    def test_derived_chains_for_distinct_artifact_kinds_coexist(self) -> None:
        instance = self._store()
        graph_raw, _ = self._admit_graph(instance)
        governance_raw, _, _ = _governance_chain()
        instance.admit(store.ARTIFACT_GOVERNANCE, governance_raw)
        result = independent.verify_database(self.database)
        self.assertEqual(2, result["head_count"])
        self.assertEqual(2, result["artifact_count"])
        self.assertTrue(graph_raw)

    def test_exact_retry_is_byte_identical_and_does_not_append(self) -> None:
        instance = self._store()
        raw, first = self._admit_graph(instance)
        chain_id = store._chain_id(store.ARTIFACT_GRAPH, store.verify_artifact(store.ARTIFACT_GRAPH, raw).subject, store.verify_artifact(store.ARTIFACT_GRAPH, raw).scope)
        self.assertEqual(128, len(chain_id))
        normalized = store.verify_artifact(store.ARTIFACT_GRAPH, raw)
        self.assertEqual(chain_id, independent._chain_id(store.ARTIFACT_GRAPH, normalized.subject, normalized.scope))
        self.assertEqual(chain_id, first.value["chain_id"])
        self.assertNotIn("chain_key", first.value)
        replay = instance.admit(store.ARTIFACT_GRAPH, raw)
        self.assertEqual(first.raw, replay.raw)
        result = independent.verify_database(self.database)
        self.assertEqual(1, result["event_count"])
        self.assertEqual(1, result["artifact_count"])

    def test_caller_chain_key_fork_attempts_reject_without_mutation(self) -> None:
        instance = self._store()
        raw, first = self._admit_graph(instance)
        before_counts = self._row_counts()
        before_files = self._file_state()
        for caller_key in ("graph-a", "graph-b"):
            with self.assertRaises(TypeError):
                instance.admit(store.ARTIFACT_GRAPH, raw, chain_key=caller_key)
        self.assertEqual(before_counts, self._row_counts())
        self.assertEqual(before_files, self._file_state())
        self.assertEqual(1, independent.verify_database(self.database)["event_count"])
        self.assertEqual(1, independent.verify_database(self.database)["head_count"])
        self.assertTrue(first.raw)

        self.database = self.directory / "governance-fork-attempt.db"
        instance = self._store()
        candidate, tested, _ = _governance_chain()
        instance.admit(store.ARTIFACT_GOVERNANCE, candidate)
        original = instance.admit(store.ARTIFACT_GOVERNANCE, tested)
        before_counts = self._row_counts()
        before_files = self._file_state()
        for caller_key in ("gov-a", "gov-b"):
            with self.assertRaises(TypeError):
                instance.admit(store.ARTIFACT_GOVERNANCE, tested, chain_key=caller_key)
        self.assertEqual(before_counts, self._row_counts())
        self.assertEqual(before_files, self._file_state())
        result = independent.verify_database(self.database)
        self.assertEqual(2, result["event_count"])
        self.assertEqual(1, result["head_count"])
        self.assertTrue(original.raw)

    def test_v2_rejects_v1_database_receipt_export_and_support_material(self) -> None:
        self._admit_graph()
        self._tamper("UPDATE store_meta SET value=? WHERE key='schema_version'", ("1",))
        with self.assertRaises(independent.IndependentStoreError):
            independent.verify_database(self.database)
        with self.assertRaises(store.StoreSchemaError):
            store.ContinuityStore(self.database)

        self.database = self.directory / "v2-receipt.db"
        raw, receipt = self._admit_graph()
        receipt_value = receipt.value
        receipt_value["schema"] = "mirror-continuity-receipt-v1"
        self._tamper("UPDATE receipts SET receipt=?", (_canonical(receipt_value),))
        with self.assertRaises(independent.IndependentStoreError):
            independent.verify_database(self.database)

        self.database = self.directory / "v2-export.db"
        self._admit_graph()
        export_value = _object(export.export_database(self.database))
        export_value["schema"] = "mirror-continuity-state-export-v1"
        with self.assertRaises(export.ContinuityExportError):
            export.verify_export_bytes(_canonical(export_value))

        support_value = _object(support.build_support_bundle(self.database))
        support_value["schema"] = "mirror-continuity-support-bundle-v1"
        with self.assertRaises(support.SupportBoundaryError):
            support.verify_support_bytes(_canonical(support_value))

    def test_tampered_receipt_retry_and_corrupt_history_cannot_advance(self) -> None:
        instance = self._store()
        raw, _ = self._admit_graph(instance)
        self._tamper("UPDATE receipts SET receipt=?", (b"{}",))
        before_files = self._file_state()
        before_counts = self._row_counts()
        with self.assertRaisesRegex(store.StoreSchemaError, "database:conformance:database:receipt-binding"):
            instance.admit(store.ARTIFACT_GRAPH, raw)
        self.assertEqual(before_files, self._file_state())
        self.assertEqual(before_counts, self._row_counts())

        self.database = self.directory / "corrupt-history.db"
        instance = self._store()
        first, _ = self._admit_graph(instance)
        self._tamper("UPDATE events SET event_root=? WHERE sequence=1", ("0" * 128,))
        candidate, _, _ = _governance_chain()
        before_files = self._file_state()
        before_counts = self._row_counts()
        with self.assertRaisesRegex(store.StoreSchemaError, "database:conformance:database:receipt-binding"):
            instance.admit(store.ARTIFACT_GOVERNANCE, candidate)
        self.assertEqual(before_files, self._file_state())
        self.assertEqual(before_counts, self._row_counts())
        self.assertTrue(first)

    def test_post_commit_response_loss_is_indeterminate_and_retry_replays(self) -> None:
        instance = self._store()
        raw, _ = graph.build_demo_report("confirmed")
        instance._fault_point = "after_commit_before_response"
        with self.assertRaises(store.IndeterminateCommitError) as context:
            instance.admit(store.ARTIFACT_GRAPH, raw)
        self.assertEqual(128, len(context.exception.operation_id))
        before = independent.verify_database(self.database)
        self.assertEqual(1, before["event_count"])
        replay = instance.admit(store.ARTIFACT_GRAPH, raw)
        self.assertEqual(128, len(replay.operation_id))
        self.assertEqual(before, independent.verify_database(self.database))

    def test_every_precommit_fault_rolls_back_completely(self) -> None:
        raw, _ = graph.build_demo_report("confirmed")
        for point in ("before_transaction", "after_begin", "after_artifact_insert", "after_event_receipt_before_commit"):
            with self.subTest(point=point):
                database = self.directory / f"{point}.db"
                instance = store.ContinuityStore(database)
                instance._fault_point = point
                with self.assertRaises(store.InjectedFault):
                    instance.admit(store.ARTIFACT_GRAPH, raw)
                result = independent.verify_database(database)
                self.assertEqual(0, result["artifact_count"])
                self.assertEqual(0, result["event_count"])

    def test_wrong_kind_noncanonical_and_prior_stage_rejections(self) -> None:
        graph_raw, _ = graph.build_demo_report("confirmed")
        candidate, tested, _ = _governance_chain()
        instance = self._store()
        with self.assertRaises(store.ArtifactAdmissionError):
            instance.admit(store.ARTIFACT_GOVERNANCE, graph_raw)
        with self.assertRaises(store.ArtifactAdmissionError):
            instance.admit(store.ARTIFACT_GRAPH, candidate)
        with self.assertRaises(store.ArtifactAdmissionError):
            instance.admit(store.ARTIFACT_GRAPH, graph_raw + b"\n")
        with self.assertRaises(store.StoreConflictError):
            instance.admit(store.ARTIFACT_GOVERNANCE, tested)

    def test_same_derived_chain_replay_and_different_initial_conflict(self) -> None:
        prior_raw, retest_raw = _graph_retest_raw()
        instance = self._store()
        instance.admit(store.ARTIFACT_GRAPH, prior_raw)
        self.assertEqual(
            instance.admit(store.ARTIFACT_GRAPH, prior_raw).raw,
            instance.admit(store.ARTIFACT_GRAPH, prior_raw).raw,
        )
        different_initial, _ = graph.build_demo_report("confirmed")
        with self.assertRaisesRegex(store.StoreConflictError, "head:unexpected-existing"):
            instance.admit(store.ARTIFACT_GRAPH, different_initial)
        first_retest = instance.admit(store.ARTIFACT_GRAPH, retest_raw)
        self.assertEqual(first_retest.raw, instance.admit(store.ARTIFACT_GRAPH, retest_raw).raw)

    def test_busy_writer_fails_closed(self) -> None:
        instance = self._store()
        lock = sqlite3.connect(self.database, timeout=0)
        try:
            lock.execute("BEGIN IMMEDIATE")
            raw, _ = graph.build_demo_report("confirmed")
            with self.assertRaises(store.StoreBusyError):
                instance.admit(store.ARTIFACT_GRAPH, raw)
        finally:
            lock.rollback()
            lock.close()
        self.assertEqual(0, independent.verify_database(self.database)["event_count"])

    def test_independent_detects_artifact_event_receipt_head_and_schema_tamper(self) -> None:
        tamper_cases = (
            ("artifact", "UPDATE artifacts SET payload_hash=?", ("0" * 128,)),
            ("event-previous", "UPDATE events SET previous_event_root=?", ("0" * 128,)),
            ("event-root", "UPDATE events SET event_root=?", ("0" * 128,)),
            ("operation-request", "UPDATE operations SET request_hash=?", ("0" * 128,)),
            ("receipt", "UPDATE receipts SET receipt=?", (b"{}",)),
            ("head", "UPDATE heads SET state_root=?", ("0" * 128,)),
            ("schema", "UPDATE store_meta SET value=? WHERE key='schema_version'", ("99",)),
        )
        for name, sql, parameters in tamper_cases:
            with self.subTest(name=name):
                self.database = self.directory / f"tamper-{name}.db"
                self._admit_graph()
                self._tamper(sql, parameters)
                with self.assertRaises(independent.IndependentStoreError):
                    independent.verify_database(self.database)

    def test_independent_row_count_cap_rejects_before_materialization(self) -> None:
        self._admit_graph()
        self._tamper(
            "INSERT INTO store_meta(key,value) VALUES(?,?)",
            ("unexpected_meta", "bounded-test"),
        )
        with self.assertRaisesRegex(independent.IndependentStoreError, "database:store_meta-count-cap"):
            independent.verify_database(self.database)

    def test_unknown_database_object_and_duplicate_replay_shape_reject(self) -> None:
        self._admit_graph()
        self._tamper("CREATE TABLE forbidden_table(value TEXT)")
        with self.assertRaisesRegex(independent.IndependentStoreError, "database:tables"):
            independent.verify_database(self.database)

    def test_independent_pins_index_and_constraint_definitions(self) -> None:
        self._admit_graph()
        self._tamper("DROP INDEX events_chain_idx")
        self._tamper("CREATE INDEX events_chain_idx ON events(artifact_id)")
        with self.assertRaisesRegex(independent.IndependentStoreError, "database:index-definition-events_chain_idx"):
            independent.verify_database(self.database)
        with self.assertRaisesRegex(store.StoreSchemaError, "database:conformance:database:index-definition-events_chain_idx"):
            store.ContinuityStore(self.database)

        self.database = self.directory / "constraint-downgrade.db"
        self._admit_graph()
        self._tamper_statements(
            (
                "ALTER TABLE heads RENAME TO heads_saved",
                "CREATE TABLE heads(chain_id TEXT NOT NULL, artifact_kind TEXT NOT NULL, artifact_id TEXT NOT NULL, current_stage_id TEXT NOT NULL, stage_kind TEXT NOT NULL, transition_id TEXT NOT NULL, event_sequence INTEGER NOT NULL, head_root TEXT NOT NULL, state_root TEXT NOT NULL, FOREIGN KEY(artifact_kind, artifact_id) REFERENCES artifacts(kind, artifact_id))",
                "INSERT INTO heads SELECT * FROM heads_saved",
                "DROP TABLE heads_saved",
            )
        )
        with self.assertRaisesRegex(independent.IndependentStoreError, "database:table-info-heads"):
            independent.verify_database(self.database)
        with self.assertRaisesRegex(store.StoreSchemaError, "database:conformance:database:table-info-heads"):
            store.ContinuityStore(self.database)

    def test_export_is_deterministic_independently_verified_and_restores_fresh_only(self) -> None:
        instance = self._store()
        graph_raw, _ = graph.build_demo_report("confirmed")
        instance.admit(store.ARTIFACT_GRAPH, graph_raw)
        candidate, tested, approved = _governance_chain()
        for raw in (candidate, tested, approved):
            instance.admit(store.ARTIFACT_GOVERNANCE, raw)
        raw = export.export_database(self.database)
        self.assertEqual(raw, export.export_database(self.database))
        self.assertEqual(4, export.verify_export_bytes(raw)["artifact_count"])
        export_path = self.directory / "export.json"
        export_path.write_bytes(raw)
        accepted = subprocess.run(
            [sys.executable, "-m", "app.mirror.continuity_export", str(export_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(0, accepted.returncode, accepted.stderr)
        self.assertIn('"accepted":true', accepted.stdout)
        restored = self.directory / "restored.db"
        result = export.import_export(raw, restored)
        self.assertTrue(result["restored"])
        self.assertEqual(raw, export.export_database(restored))
        self.assertEqual(result, export.import_export(raw, restored))

    def test_restore_fault_recovery_and_exact_retry(self) -> None:
        instance = self._store()
        graph_raw, _ = graph.build_demo_report("confirmed")
        instance.admit(store.ARTIFACT_GRAPH, graph_raw)
        raw = export.export_database(self.database)
        value = _object(raw)
        expected = independent.verify_database(self.database)
        for point in export.RESTORE_FAULT_POINTS:
            with self.subTest(point=point):
                target = self.directory / f"restore-{point}.db"
                stage, marker = restore_publication.stage_paths(target, str(value["export_root"]), create_parent=False)
                export._restore_fault_point = point
                with self.assertRaises(export.InjectedRestoreFault):
                    export.import_export(raw, target)
                self.assertIsNone(export._restore_fault_point)
                if point == "after_atomic_publication_before_response":
                    self.assertTrue(target.is_file())
                    self.assertFalse(stage.exists())
                    self.assertTrue(marker.is_file())
                elif point == "before_staging_creation":
                    self.assertFalse(target.exists())
                    self.assertFalse(stage.exists())
                    self.assertFalse(marker.exists())
                else:
                    self.assertFalse(target.exists())
                    self.assertTrue(stage.is_file())
                    self.assertTrue(marker.is_file())
                    staged = independent.verify_database(stage)
                    if point == "after_empty_staging_db_creation":
                        self.assertEqual(0, staged["event_count"])
                    else:
                        self.assertEqual(expected, staged)
                first = export.import_export(raw, target)
                second = export.import_export(raw, target)
                self.assertEqual(first, second)
                self.assertEqual(raw, export.export_database(target))
                self.assertFalse(stage.exists())
                self.assertFalse(marker.exists())
                for suffix in ("-wal", "-shm"):
                    sidecar = Path(str(target) + suffix)
                    self.assertFalse(sidecar.exists() and sidecar.stat().st_size != 0)

    def test_restore_preplanted_and_tampered_staging_fails_closed(self) -> None:
        instance = self._store()
        graph_raw, _ = graph.build_demo_report("confirmed")
        instance.admit(store.ARTIFACT_GRAPH, graph_raw)
        raw = export.export_database(self.database)
        value = _object(raw)

        empty_target = self.directory / "empty-preplanted.db"
        empty_stage, _empty_marker = restore_publication.stage_paths(
            empty_target, str(value["export_root"]), create_parent=True,
        )
        with self.assertRaisesRegex(export.ContinuityExportError, "restore:staging-state"):
            export.import_export(raw, empty_target)
        self.assertTrue(empty_stage.parent.is_dir())
        self.assertEqual([], list(empty_stage.parent.iterdir()))

        preplanted_target = self.directory / "preplanted.db"
        stage, marker = restore_publication.stage_paths(preplanted_target, str(value["export_root"]), create_parent=True)
        stage.write_bytes(b"not-a-database")
        with self.assertRaisesRegex(export.ContinuityExportError, "restore:staging-state"):
            export.import_export(raw, preplanted_target)
        self.assertFalse(preplanted_target.exists())
        self.assertEqual(b"not-a-database", stage.read_bytes())

        marker_target = self.directory / "preplanted-marker.db"
        marker_stage, marker_path = restore_publication.stage_paths(marker_target, str(value["export_root"]), create_parent=True)
        marker_path.write_bytes(b"{}")
        with self.assertRaisesRegex(export.ContinuityExportError, "restore:staging-marker"):
            export.import_export(raw, marker_target)
        self.assertFalse(marker_target.exists())
        self.assertFalse(marker_stage.exists())

        lock_target = self.directory / "preplanted-lock.db"
        _lock_stage, _lock_marker = restore_publication.stage_paths(lock_target, str(value["export_root"]), create_parent=True)
        lock_path = restore_publication._lock_path(lock_target)
        lock_path.write_bytes(b"{}")
        with self.assertRaisesRegex(export.ContinuityExportError, "restore:lock-binding"):
            export.import_export(raw, lock_target)
        self.assertFalse(lock_target.exists())
        self.assertEqual(b"{}", lock_path.read_bytes())

        foreign_target = self.directory / "foreign-stage.db"
        foreign_stage, _foreign_marker = restore_publication.stage_paths(foreign_target, "0" * 128, create_parent=True)
        foreign_stage.write_bytes(b"foreign-stage")
        with self.assertRaisesRegex(export.ContinuityExportError, "restore:staging-foreign"):
            export.import_export(raw, foreign_target)
        self.assertFalse(foreign_target.exists())
        self.assertEqual(b"foreign-stage", foreign_stage.read_bytes())

        tampered_target = self.directory / "tampered-stage.db"
        tampered_stage, _tampered_marker = restore_publication.stage_paths(tampered_target, str(value["export_root"]), create_parent=False)
        export._restore_fault_point = "after_snapshot_transaction"
        with self.assertRaises(export.InjectedRestoreFault):
            export.import_export(raw, tampered_target)
        connection = sqlite3.connect(tampered_stage)
        try:
            connection.execute("UPDATE events SET event_root=?", ("0" * 128,))
            connection.commit()
        finally:
            connection.close()
        with self.assertRaisesRegex(export.ContinuityExportError, "restore:staging-invalid"):
            export.import_export(raw, tampered_target)
        self.assertFalse(tampered_target.exists())

    def test_restore_competing_exact_and_conflicting_destinations_are_no_clobber(self) -> None:
        instance = self._store()
        graph_raw, _ = graph.build_demo_report("confirmed")
        instance.admit(store.ARTIFACT_GRAPH, graph_raw)
        raw = export.export_database(self.database)
        other_database = self.directory / "other-source.db"
        other_instance = store.ContinuityStore(other_database)
        other_raw_artifact, _ = graph.build_demo_report("expired")
        other_instance.admit(store.ARTIFACT_GRAPH, other_raw_artifact)
        other_raw = export.export_database(other_database)
        original_publish = restore_publication._publish_link

        exact_target = self.directory / "exact-competing.db"
        exact_competitor = self.directory / "exact-competitor.db"

        def publish_with_exact_competitor(stage: Path, target: Path) -> bool:
            restore_publication._publish_link = original_publish
            try:
                export.import_export(raw, exact_competitor)
                shutil.copyfile(exact_competitor, target)
            finally:
                restore_publication._publish_link = publish_with_exact_competitor
            return original_publish(stage, target)

        restore_publication._publish_link = publish_with_exact_competitor
        try:
            exact_result = export.import_export(raw, exact_target)
        finally:
            restore_publication._publish_link = original_publish
        self.assertEqual(raw, export.export_database(exact_target))
        self.assertEqual(exact_result, export.import_export(raw, exact_target))

        conflict_target = self.directory / "conflicting-competing.db"
        conflict_competitor = self.directory / "conflicting-competitor.db"

        def publish_with_conflicting_competitor(stage: Path, target: Path) -> bool:
            restore_publication._publish_link = original_publish
            try:
                export.import_export(other_raw, conflict_competitor)
                shutil.copyfile(conflict_competitor, target)
            finally:
                restore_publication._publish_link = publish_with_conflicting_competitor
            return original_publish(stage, target)

        restore_publication._publish_link = publish_with_conflicting_competitor
        try:
            with self.assertRaisesRegex(export.ContinuityExportError, "restore:target-conflict"):
                export.import_export(raw, conflict_target)
        finally:
            restore_publication._publish_link = original_publish
        self.assertEqual(other_raw, export.export_database(conflict_target))

    def test_extra_hardlink_after_publication_rolls_back_only_created_target_link(self) -> None:
        instance = self._store()
        graph_raw, _ = graph.build_demo_report("confirmed")
        instance.admit(store.ARTIFACT_GRAPH, graph_raw)
        raw = export.export_database(self.database)
        value = _object(raw)
        target = self.directory / "extra-link-target.db"
        alias = self.directory / "foreign-extra-link.db"
        original_publish = restore_publication._publish_link

        def publish_with_extra_link(stage: Path, destination: Path) -> bool:
            created = original_publish(stage, destination)
            if created:
                os.link(stage, alias)
            return created

        restore_publication._publish_link = publish_with_extra_link
        try:
            with self.assertRaises(export.ContinuityExportError):
                export.import_export(raw, target)
        finally:
            restore_publication._publish_link = original_publish
        stage, marker = restore_publication.stage_paths(target, str(value["export_root"]), create_parent=False)
        self.assertFalse(target.exists())
        self.assertTrue(stage.exists())
        self.assertTrue(marker.exists())
        self.assertTrue(alias.exists())
        alias.unlink()
        export.import_export(raw, target)
        self.assertEqual(raw, export.export_database(target))

    def test_stage_delete_interruption_is_recoverable_without_target_conflict(self) -> None:
        instance = self._store()
        graph_raw, _ = graph.build_demo_report("confirmed")
        instance.admit(store.ARTIFACT_GRAPH, graph_raw)
        raw = export.export_database(self.database)
        target = self.directory / "stage-delete-target.db"
        fired = {"value": False}

        def fault(point: str) -> None:
            if point == "before_stage_delete" and not fired["value"]:
                fired["value"] = True
                raise export.InjectedRestoreFault("restore:test-stage-delete")

        export._restore_fault_point = "before_stage_delete"
        try:
            with self.assertRaises(export.InjectedRestoreFault):
                export.import_export(raw, target)
        finally:
            export._restore_fault_point = None
        self.assertFalse(target.exists())
        export.import_export(raw, target)
        self.assertEqual(raw, export.export_database(target))

    def test_generic_publisher_no_longer_parses_component_export_json(self) -> None:
        source = Path(restore_publication.__file__).read_text(encoding="utf-8")
        self.assertNotIn("_extract_export_root", source)

    def test_exact_cleanup_preserves_a_path_replacement(self) -> None:
        owned = self.directory / "owned.db"
        replacement = self.directory / "replacement.db"
        owned.write_bytes(b"owned")
        replacement.write_bytes(b"foreign")
        identity = restore_publication._regular_identity(owned)
        os.replace(replacement, owned)
        with self.assertRaises(restore_publication.RestorePublicationCleanupError):
            restore_publication._delete_exact_file(
                owned,
                expected_identity=identity,
                allow_empty=False,
                label="replacement",
            )
        self.assertEqual(b"foreign", owned.read_bytes())

    def test_publication_rollback_preserves_a_foreign_target_replacement(self) -> None:
        instance = self._store()
        graph_raw, _ = graph.build_demo_report("confirmed")
        instance.admit(store.ARTIFACT_GRAPH, graph_raw)
        raw = export.export_database(self.database)
        target = self.directory / "replaced-publication-target.db"
        replacement = self.directory / "foreign-publication-target.db"
        original_publish = restore_publication._publish_link

        def publish_and_replace(stage: Path, destination: Path) -> bool:
            created = original_publish(stage, destination)
            if created:
                replacement.write_bytes(b"foreign replacement")
                os.replace(replacement, destination)
            return created

        restore_publication._publish_link = publish_and_replace
        try:
            with self.assertRaises(export.ContinuityExportError):
                export.import_export(raw, target)
        finally:
            restore_publication._publish_link = original_publish
        self.assertEqual(b"foreign replacement", target.read_bytes())

    def test_owned_stage_adoption_persists_an_adopted_workspace_receipt(self) -> None:
        instance = self._store()
        graph_raw, _ = graph.build_demo_report("confirmed")
        instance.admit(store.ARTIFACT_GRAPH, graph_raw)
        raw = export.export_database(self.database)
        value, snapshot, expected = export._decode_and_verify(raw)
        identity = "2" * 128
        children = ("continuity",)
        with restore_publication.owned_restore_workspace(self.directory, identity, children=children) as root:
            target = root / "continuity" / "continuity.db"
            export._restore_fault_point = "before_publish"
            try:
                with self.assertRaises(export.InjectedRestoreFault):
                    export.import_export(raw, target)
            finally:
                export._restore_fault_point = None
            stage, marker = restore_publication.stage_paths(target, str(value["export_root"]), create_parent=False)
            self.assertTrue(stage.exists())
            self.assertTrue(marker.exists())
            os.link(stage, target)

            def build_stage(path: Path) -> None:
                service = store.ContinuityStore(path)
                service._restore_snapshot(snapshot)

            receipts: list[dict[str, object]] = []

            def persist(receipt: dict[str, object]) -> None:
                receipts.append(dict(receipt))
                restore_publication.persist_workspace_receipt(
                    root,
                    identity,
                    "continuity",
                    receipt,
                    children=children,
                    target=target,
                )

            restore_publication.publish_create_only(
                target,
                raw,
                export_root=str(value["export_root"]),
                expected_evidence={**expected, "export_root": value["export_root"]},
                build_stage=build_stage,
                verify_database=independent.verify_database,
                result_factory=lambda _path: {"accepted": True},
                publication_receipt_sink=persist,
            )
            self.assertEqual("ADOPTED_EXISTING", receipts[0]["publication_kind"])
            self.assertTrue((root / "continuity.publication.json").exists())

    def test_restore_path_object_and_sidecar_rejections(self) -> None:
        instance = self._store()
        graph_raw, _ = graph.build_demo_report("confirmed")
        instance.admit(store.ARTIFACT_GRAPH, graph_raw)
        raw = export.export_database(self.database)

        with self.assertRaisesRegex(export.ContinuityExportError, "restore:parent-missing"):
            export.import_export(raw, self.directory / "missing-parent" / "target.db")

        directory_target = self.directory / "directory-target.db"
        directory_target.mkdir()
        with self.assertRaisesRegex(export.ContinuityExportError, "restore:target-object"):
            export.import_export(raw, directory_target)

        sidecar_target = self.directory / "sidecar-target.db"
        sidecar = Path(str(sidecar_target) + "-wal")
        sidecar.write_bytes(b"")
        with self.assertRaisesRegex(export.ContinuityExportError, "restore:target-sidecar-existing"):
            export.import_export(raw, sidecar_target)
        self.assertFalse(sidecar_target.exists())
        self.assertEqual(b"", sidecar.read_bytes())

        existing_target = self.directory / "existing-with-sidecar.db"
        export.import_export(raw, existing_target)
        existing_before = existing_target.read_bytes()
        existing_sidecar = Path(str(existing_target) + "-wal")
        existing_sidecar.write_bytes(b"")
        with self.assertRaisesRegex(export.ContinuityExportError, "restore:target-conflict"):
            export.import_export(raw, existing_target)
        self.assertEqual(existing_before, existing_target.read_bytes())
        self.assertEqual(b"", existing_sidecar.read_bytes())

    def test_restore_publication_rejects_inode_aliases_stage_mutation_and_unbounded_scan(self) -> None:
        instance = self._store()
        graph_raw, _ = graph.build_demo_report("confirmed")
        instance.admit(store.ARTIFACT_GRAPH, graph_raw)
        raw = export.export_database(self.database)
        root = str(_object(raw)["export_root"])

        missing = self.directory / "checkpoint-missing.db"
        with self.assertRaises(restore_publication.RestorePublicationVerification):
            restore_publication._checkpoint_closed_database(missing)
        self.assertFalse(missing.exists())

        for kind in ("marker", "stage", "lock"):
            with self.subTest(kind=kind):
                target = self.directory / f"hardlink-{kind}.db"
                point = "before_staging_creation" if kind == "lock" else "after_snapshot_transaction"
                export._restore_fault_point = point
                with self.assertRaises(export.InjectedRestoreFault):
                    export.import_export(raw, target)
                self.assertIsNone(export._restore_fault_point)
                stage, marker = restore_publication.stage_paths(target, root, create_parent=False)
                owned = {"marker": marker, "stage": stage, "lock": restore_publication._lock_path(target)}[kind]
                alias = self.directory / f"foreign-{kind}.link"
                os.link(owned, alias)
                try:
                    with self.assertRaises(export.ContinuityExportError):
                        export.import_export(raw, target)
                    self.assertFalse(target.exists())
                finally:
                    alias.unlink()
                export.import_export(raw, target)
                self.assertEqual(raw, export.export_database(target))

        other_database = self.directory / "toctou-source.db"
        other_store = store.ContinuityStore(other_database)
        other_graph, _ = graph.build_demo_report("expired")
        other_store.admit(store.ARTIFACT_GRAPH, other_graph)
        other_raw = export.export_database(other_database)
        other_target = self.directory / "toctou-source-closed.db"
        export.import_export(other_raw, other_target)
        target = self.directory / "toctou-target.db"
        original_publish = restore_publication._publish_link

        def mutate_before_link(stage: Path, destination: Path) -> bool:
            shutil.copyfile(other_target, stage)
            return original_publish(stage, destination)

        restore_publication._publish_link = mutate_before_link
        try:
            with self.assertRaisesRegex(export.ContinuityExportError, "target-conflict"):
                export.import_export(raw, target)
        finally:
            restore_publication._publish_link = original_publish
        self.assertFalse(target.exists())

        bounded_parent = self.directory / "bounded-parent"
        bounded_parent.mkdir()
        for index in range(3):
            (bounded_parent / f"unrelated-{index}.txt").write_text("x", encoding="ascii")
        bounded_target = bounded_parent / "restored.db"
        original_cap = restore_publication.MAX_PARENT_ENTRIES
        restore_publication.MAX_PARENT_ENTRIES = 2
        try:
            with self.assertRaisesRegex(export.ContinuityExportError, "staging-scan-cap"):
                export.import_export(raw, bounded_target)
        finally:
            restore_publication.MAX_PARENT_ENTRIES = original_cap
        self.assertFalse(bounded_target.exists())
        export.import_export(raw, bounded_target)
        self.assertEqual(raw, export.export_database(bounded_target))

    def test_closed_delete_journal_image_is_not_reinterpreted_as_wal(self) -> None:
        candidate = self.directory / "delete-journal.db"
        store.ContinuityStore(candidate)
        unpaired_wal = Path(str(candidate) + "-wal")
        unpaired_wal.write_bytes(b"")
        with self.assertRaisesRegex(independent.IndependentStoreError, "database:image"):
            independent.verify_database(candidate)
        unpaired_wal.unlink()
        connection = sqlite3.connect(candidate)
        try:
            self.assertEqual("delete", str(connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0]).lower())
        finally:
            connection.close()
        self.assertEqual(b"\x01\x01", candidate.read_bytes()[18:20])
        with self.assertRaisesRegex(independent.IndependentStoreError, "database:journal-mode"):
            independent.verify_database(candidate)

    def test_restore_distinct_destinations_do_not_share_state(self) -> None:
        instance = self._store()
        graph_raw, _ = graph.build_demo_report("confirmed")
        instance.admit(store.ARTIFACT_GRAPH, graph_raw)
        raw = export.export_database(self.database)

        for index in range(3):
            target = self.directory / f"sequential-{index}.db"
            result = export.import_export(raw, target)
            self.assertTrue(result["accepted"])
            self.assertEqual(raw, export.export_database(target))

    def test_restore_same_export_converges_concurrently(self) -> None:
        instance = self._store()
        graph_raw, _ = graph.build_demo_report("confirmed")
        instance.admit(store.ARTIFACT_GRAPH, graph_raw)
        raw = export.export_database(self.database)
        target = self.directory / "concurrent.db"
        barrier = threading.Barrier(2)
        results: list[dict[str, object]] = []
        errors: list[BaseException] = []

        def worker() -> None:
            try:
                barrier.wait(timeout=5)
                results.append(export.import_export(raw, target))
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
        self.assertEqual(results[0], results[1])
        self.assertEqual(raw, export.export_database(target))
        value = _object(raw)
        stage, marker = restore_publication.stage_paths(target, str(value["export_root"]), create_parent=False)
        self.assertFalse(stage.exists())
        self.assertFalse(marker.exists())

    def test_restore_same_export_converges_across_processes(self) -> None:
        instance = self._store()
        graph_raw, _ = graph.build_demo_report("confirmed")
        instance.admit(store.ARTIFACT_GRAPH, graph_raw)
        raw = export.export_database(self.database)
        export_path = self.directory / "cross-process-export.json"
        target = self.directory / "cross-process-restored.db"
        export_path.write_bytes(raw)
        script = (
            "import sys\n"
            "from pathlib import Path\n"
            "from app.mirror import continuity_export as e\n"
            "raw = Path(sys.argv[1]).read_bytes()\n"
            "print(e.import_export(raw, sys.argv[2]))\n"
        )
        processes = [
            subprocess.Popen(
                [sys.executable, "-c", script, str(export_path), str(target)],
                cwd=Path(__file__).resolve().parents[1],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for _ in range(2)
        ]
        completed = [process.communicate(timeout=20) for process in processes]
        for process, (stdout, stderr) in zip(processes, completed):
            self.assertEqual(0, process.returncode, stderr)
            self.assertIn("'restored': True", stdout)
        self.assertEqual(raw, export.export_database(target))

    def test_restore_export_roundtrip_in_fresh_process(self) -> None:
        instance = self._store()
        graph_raw, _ = graph.build_demo_report("confirmed")
        instance.admit(store.ARTIFACT_GRAPH, graph_raw)
        raw = export.export_database(self.database)
        export_path = self.directory / "fresh-process-export.json"
        target = self.directory / "fresh-process-restored.db"
        export_path.write_bytes(raw)
        script = (
            "import sys\n"
            "from pathlib import Path\n"
            "from app.mirror import continuity_export as e\n"
            "raw = Path(sys.argv[1]).read_bytes()\n"
            "result = e.import_export(raw, sys.argv[2])\n"
            "assert e.export_database(sys.argv[2]) == raw\n"
            "print(result)\n"
        )
        completed = subprocess.run(
            [sys.executable, "-c", script, str(export_path), str(target)],
            cwd=Path(__file__).resolve().parents[1],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertIn("'restored': True", completed.stdout)
        self.assertEqual(raw, export.export_database(target))

    def test_export_omission_reorder_duplicate_truncation_and_root_mutation_reject(self) -> None:
        instance = self._store()
        first, _ = graph.build_demo_report("confirmed")
        instance.admit(store.ARTIFACT_GRAPH, first)
        candidate, tested, approved = _governance_chain()
        for raw in (candidate, tested, approved):
            instance.admit(store.ARTIFACT_GOVERNANCE, raw)
        raw = export.export_database(self.database)
        value = _object(raw)
        mutations = []
        omission = deepcopy(value)
        omission["events"] = omission["events"][:-1]
        mutations.append(omission)
        reorder = deepcopy(value)
        reorder["events"] = list(reversed(reorder["events"]))
        mutations.append(reorder)
        duplicate = deepcopy(value)
        duplicate["heads"].append(deepcopy(duplicate["heads"][0]))
        mutations.append(duplicate)
        root = deepcopy(value)
        root["export_root"] = "0" * 128
        mutations.append(root)
        for mutated in mutations:
            with self.subTest():
                with self.assertRaises(export.ContinuityExportError):
                    export.verify_export_bytes(_canonical(mutated))
        with self.assertRaises(export.ContinuityExportError):
            export.verify_export_bytes(raw[:-1])

    def test_support_boundary_is_allowlist_only_and_canary_safe(self) -> None:
        raw, _ = self._admit_graph()
        canary = "CANARY_PROVIDER_SECRET_123"
        bundle = support.build_support_bundle(
            self.database,
            {
                "process_tree_peak_bytes": 123_456,
                "database_bytes": self.database.stat().st_size,
                "wal_bytes": 0,
                "scratch_bytes": 0,
            },
        )
        self.assertEqual("DB_CONFORMANCE_PASS", support.verify_support_bytes(bundle)["diagnostic_code"])
        self.assertNotIn(canary.encode("ascii"), bundle)
        value = _object(bundle)
        self.assertNotIn(raw.hex().encode("ascii"), bundle)
        self.assertNotIn(graph.SUBJECT_KEY.encode("ascii"), bundle)
        bad = support.build_support_bundle(self.directory / (canary + ".db"), {"canary": canary})
        self.assertEqual("SUPPORT_INPUT_REJECTED", support.verify_support_bytes(bad)["diagnostic_code"])
        self.assertNotIn(canary.encode("ascii"), bad)
        self.assertEqual(True, value["support_safe"])
        self.assertEqual(True, value["zero_phi_boundary"])

    def test_export_cli_never_echoes_input_paths(self) -> None:
        missing = self.directory / "PRIVATE-PATIENT-path.json"
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            self.assertEqual(1, export.main([str(missing)]))
        self.assertEqual("REJECT input\n", stderr.getvalue())
        self.assertNotIn(str(missing), stderr.getvalue())

    def test_support_rejects_corrupt_database_with_fixed_code(self) -> None:
        self.database.write_bytes(b"not sqlite")
        bundle = support.build_support_bundle(self.database)
        result = support.verify_support_bytes(bundle)
        self.assertIn(result["diagnostic_code"], support.DIAGNOSTIC_CODES)
        self.assertNotIn(b"not sqlite", bundle)

    def test_support_output_rejects_raw_identity_material_structurally(self) -> None:
        self._admit_graph()
        bundle = support.build_support_bundle(self.database)
        self.assertIsNone(re.search(rb"[0-9a-f]{128}", bundle))
        for forbidden in (b"artifact_id", b"operation_id", b"event_root", b"state_root", b"report_id", b"transition_id", b"continuity.db", b"CANARY_PROVIDER_SECRET_123"):
            self.assertNotIn(forbidden, bundle)
        value = _object(bundle)
        value["profiles"]["schema_profile"] = "0" * 128
        with self.assertRaises(support.SupportBoundaryError):
            support.verify_support_bytes(_canonical(value))

    def test_resource_caps_and_forbidden_producer_import_boundary(self) -> None:
        self.assertLess(len(graph.build_demo_report("confirmed")[0]), store.MAX_ARTIFACT_BYTES)
        independent_source = Path(independent.__file__).read_text(encoding="utf-8")
        self.assertNotIn("from app.mirror import continuity_store", independent_source)
        self.assertNotIn("import continuity_store", independent_source)
        self.assertNotIn("provider_trust_graph.py", independent_source)
        with self.assertRaises(TypeError):
            self._store().admit(store.ARTIFACT_GRAPH, graph.build_demo_report("confirmed")[0], chain_key="caller-selected")


if __name__ == "__main__":
    unittest.main()
