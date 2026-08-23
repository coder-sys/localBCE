"""Focused synthetic operational-recovery and DR evidence tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest

from app.mirror import controlled_shadow_runtime as runtime
from app.mirror import operational_recovery as recovery
from app.mirror import operational_recovery_fixtures as recovery_fixtures
from app.mirror import operational_recovery_independent as independent
from tests import test_mirror_controlled_shadow_runtime as runtime_tests


class OperationalRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.upstream = object.__new__(runtime_tests.ControlledShadowRuntimeTests)
        runtime_tests.ControlledShadowRuntimeTests.setUp(self.upstream)
        self.addCleanup(self.upstream.tearDown)
        self.root = Path(self.upstream.temporary.name)
        self.catalog = self.root / "recovery.db"
        self.clock = recovery_fixtures.SyntheticRecoveryClock()
        self.custody = recovery_fixtures.SyntheticKeyCustody()
        self.storage = recovery_fixtures.SyntheticRecoveryStorage()
        self.profile = recovery.OperationalRecoveryProfileV1(
            profile_id="SYNTHETIC_OPERATIONAL_RECOVERY_V1",
            version=1,
            quarantine_policy_digest=self.upstream.source_policy.digest,
            runtime_profile_digest=self.upstream.profile.digest,
            custody_id=self.custody.custody_id,
            storage_id=self.storage.storage_id,
        )
        self.service = self._new_service(self.catalog)
        self.quarantine_export = self.upstream.quarantine_service.export_bytes()
        self.runtime_export = self.upstream.service.export_bytes()

    def _new_service(self, path: Path, *, fault=None) -> recovery.OperationalRecoveryService:
        return recovery.OperationalRecoveryService(
            path,
            profile=self.profile,
            quarantine_policy=self.upstream.source_policy,
            runtime_profile=self.upstream.profile,
            clock=self.clock,
            key_custody=self.custody,
            storage=self.storage,
            fault_injector=fault,
        )

    def _genesis(self) -> str:
        return independent._genesis_root(self.profile.digest, self.profile.custody_id, self.profile.storage_id)

    def _different_runtime_export(self) -> bytes:
        holder = object.__new__(runtime_tests.ControlledShadowRuntimeTests)
        runtime_tests.ControlledShadowRuntimeTests.setUp(holder)
        self.addCleanup(holder.tearDown)
        session_id, head = holder._open("SECOND")
        first = holder.service.run_observation("OBS_SECOND_0", session_id, expected_head=head, evaluator=holder.evaluator)
        holder.clock.advance(10)
        holder.service.run_observation("OBS_SECOND_1", session_id, expected_head=first["head_root"], evaluator=holder.evaluator)
        return holder.service.export_bytes()

    def test_generation_rotation_restore_supersede_revoke_and_dr(self) -> None:
        first = self.service.create_recovery_point(
            "CREATE_ONE", generation=1, expected_head=self._genesis(),
            quarantine_export=self.quarantine_export, runtime_export=self.runtime_export,
        )
        self.assertEqual(first["state"], recovery.STATE_STORED)
        restored_one = self.service.restore_point(first["point_id"], expected_head=first["head_root"])
        self.assertEqual(restored_one["state"], recovery.STATE_RESTORE_VERIFIED)
        before_rotation = self.service.integrity()
        self.custody.rotate(2)
        second = self.service.create_recovery_point(
            "CREATE_TWO", generation=2, expected_head=restored_one["head_root"],
            quarantine_export=self.quarantine_export, runtime_export=self.runtime_export,
        )
        restored_two = self.service.restore_point(second["point_id"], expected_head=second["head_root"])
        self.assertEqual(restored_two["state"], recovery.STATE_RESTORE_VERIFIED)
        superseded = self.service.supersede(first["point_id"], expected_head=restored_two["head_root"])
        self.assertEqual(superseded["state"], recovery.STATE_SUPERSEDED)
        self.custody.revoke(1)
        self.assertEqual(self.service.select_latest_restore_verified()["point_id"], second["point_id"])
        with self.assertRaises(recovery.RecoveryConflictError):
            self.service.restore_point(first["point_id"], expected_head=superseded["head_root"])
        self.assertEqual(self.service.integrity()["generation"], 2)
        self.assertEqual(self.service.integrity()["state_counts"][recovery.STATE_SUPERSEDED], 1)
        exported = self.service.export_bytes()
        restored_catalog = self.root / "restored-recovery.db"
        copy = recovery.restore_export(
            restored_catalog, exported, profile=self.profile,
            quarantine_policy=self.upstream.source_policy, runtime_profile=self.upstream.profile,
            clock=self.clock, key_custody=self.custody, storage=self.storage,
        )
        self.assertEqual(copy.export_bytes(), exported)
        same_target = recovery.restore_export(
            restored_catalog, exported, profile=self.profile,
            quarantine_policy=self.upstream.source_policy, runtime_profile=self.upstream.profile,
            clock=self.clock, key_custody=self.custody, storage=self.storage,
        )
        self.assertEqual(same_target.export_bytes(), exported)
        self.assertEqual(copy.integrity(), self.service.integrity())
        self.assertGreaterEqual(copy.integrity()["restore_count"], before_rotation["restore_count"])
        evidence = {
            "schema": "mirror-operational-recovery-exercise-v1",
            "claim": "SYNTHETIC_SOFTWARE_ONLY",
            "state_counts": self.service.integrity()["state_counts"],
            "artifact_counts": {
                "recovery_points": self.service.integrity()["point_count"],
                "operations": self.service.integrity()["operation_count"],
                "transitions": self.service.integrity()["transition_count"],
                "restore_drills": self.service.integrity()["restore_count"],
            },
            "key_epochs": self.service.integrity()["key_epochs"],
            "exercise_counts": {
                "generations": 2,
                "key_rotations": 1,
                "key_revocations": 1,
                "supersessions": 1,
                "fresh_target_restores": 2,
            },
            "flags": {
                "zero_phi": True,
                "read_only": True,
                "production_usable": False,
                "activation": False,
                "payment_authority": False,
                "clearance_authority": False,
                "settlement_authority": False,
                "proofSuiteId": None,
            },
        }
        print("RECOVERY_EXERCISE_EVIDENCE=" + json.dumps(evidence, sort_keys=True, separators=(",", ":")))

    def test_precommit_rollback_and_post_put_response_loss_recover_exactly(self) -> None:
        before = self.service.export_bytes()

        def precommit(point: str) -> None:
            if point == "before_prepare_commit":
                raise recovery.RecoveryInjectedFault("recovery:test-precommit")

        faulted = self._new_service(self.catalog, fault=precommit)
        with self.assertRaises(recovery.RecoveryInjectedFault):
            faulted.create_recovery_point(
                "ROLLBACK", generation=1, expected_head=self._genesis(),
                quarantine_export=self.quarantine_export, runtime_export=self.runtime_export,
            )
        self.assertEqual(faulted.export_bytes(), before)

        def after_put(point: str) -> None:
            if point == "after_put_before_record":
                raise recovery.RecoveryResponseLost("recovery:test-response-loss")

        lossy = self._new_service(self.catalog, fault=after_put)
        with self.assertRaises(recovery.RecoveryResponseLost):
            lossy.create_recovery_point(
                "LOSSY", generation=1, expected_head=self._genesis(),
                quarantine_export=self.quarantine_export, runtime_export=self.runtime_export,
            )
        self.assertEqual(lossy.integrity()["state_counts"][recovery.STATE_STORE_PENDING], 1)
        self.custody.rotate(2)
        recovered = self._new_service(self.catalog).create_recovery_point(
            "LOSSY", generation=1, expected_head=self._genesis(),
            quarantine_export=self.quarantine_export, runtime_export=self.runtime_export,
        )
        self.assertEqual(recovered["state"], recovery.STATE_STORED)
        self.assertEqual(self._new_service(self.catalog).create_recovery_point(
            "LOSSY", generation=1, expected_head=self._genesis(),
            quarantine_export=self.quarantine_export, runtime_export=self.runtime_export,
        )["receipt_raw"], recovered["receipt_raw"])

    def test_identical_concurrent_writers_converge_and_catalog_is_independent(self) -> None:
        path = self.root / "concurrent.db"
        first = self._new_service(path)
        second = self._new_service(path)
        barrier = threading.Barrier(3)
        results: list[object] = []

        def run(service: recovery.OperationalRecoveryService) -> None:
            barrier.wait()
            try:
                results.append(service.create_recovery_point(
                    "CONCURRENT_IDENTICAL", generation=1, expected_head=self._genesis(),
                    quarantine_export=self.quarantine_export, runtime_export=self.runtime_export,
                ))
            except Exception as exc:  # pragma: no cover - assertion below records any race failure
                results.append(exc)

        threads = [threading.Thread(target=run, args=(first,)), threading.Thread(target=run, args=(second,))]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(5)
        self.assertEqual(len(results), 2)
        self.assertTrue(all(isinstance(item, dict) for item in results), results)
        self.assertEqual(results[0]["receipt_raw"], results[1]["receipt_raw"])
        evidence = first.integrity()
        self.assertEqual(evidence["point_count"], 1)
        self.assertEqual(evidence["transition_count"], 3)
        self.assertEqual(evidence["operation_count"], 3)
        independent.verify_database(path, profile=self.profile.material())

    def test_conflicting_concurrent_writers_have_one_winner_in_both_orders(self) -> None:
        other_runtime = self._different_runtime_export()
        for order in (0, 1):
            path = self.root / f"conflict-{order}.db"
            left = self._new_service(path)
            right = self._new_service(path)
            args = [
                (left, "CONFLICT_LEFT", self.runtime_export),
                (right, "CONFLICT_RIGHT", other_runtime),
            ]
            if order:
                args.reverse()
            barrier = threading.Barrier(3)
            results: list[object] = []

            def run(service: recovery.OperationalRecoveryService, key: str, raw: bytes) -> None:
                barrier.wait()
                try:
                    results.append(service.create_recovery_point(
                        key, generation=1, expected_head=self._genesis(),
                        quarantine_export=self.quarantine_export, runtime_export=raw,
                    ))
                except Exception as exc:
                    results.append(exc)

            threads = [threading.Thread(target=run, args=item) for item in args]
            for thread in threads:
                thread.start()
            barrier.wait()
            for thread in threads:
                thread.join(5)
            self.assertEqual(len(results), 2)
            conflicts = [item for item in results if isinstance(item, recovery.RecoveryConflictError)]
            winners = [item for item in results if isinstance(item, dict)]
            self.assertEqual(len(conflicts), 1, results)
            self.assertEqual(len(winners), 1, results)
            self.assertIn("head-conflict", str(conflicts[0]))
            evidence = left.integrity()
            self.assertEqual(evidence["point_count"], 1)
            self.assertEqual(evidence["transition_count"], 3)
            catalog = left.export_bytes()
            catalog_value = json.loads(catalog.decode("ascii"))
            runtime_manifests = [
                item["export_digest"]
                for item in catalog_value["tables"]["recovery_manifests"]
                if item["component_kind"] == "CONTROLLED_SHADOW_RUNTIME"
            ]
            self.assertEqual(1, len(runtime_manifests))
            self.assertIn(runtime_manifests[0], {
                hashlib.sha3_512(self.runtime_export).hexdigest(),
                hashlib.sha3_512(other_runtime).hexdigest(),
            })
            self.assertNotIn(other_runtime, catalog)

    def test_corrupt_object_rejects_and_catalog_export_mutations_fail_closed(self) -> None:
        stored = self.service.create_recovery_point(
            "CORRUPT", generation=1, expected_head=self._genesis(),
            quarantine_export=self.quarantine_export, runtime_export=self.runtime_export,
        )
        object_id = stored["point_id"]
        connection = sqlite3.connect(self.catalog)
        point = connection.execute("SELECT object_id FROM recovery_points WHERE point_id=?", (object_id,)).fetchone()[0]
        connection.close()
        self.storage.corrupt(point)
        with self.assertRaises(recovery.RecoveryIntegrityError):
            self.service.restore_point(object_id, expected_head=stored["head_root"])
        exported = self.service.export_bytes()
        value = json.loads(exported.decode("ascii"))
        value["export_root"] = "0" * 128
        with self.assertRaises(independent.IndependentOperationalRecoveryError):
            independent.verify_export_bytes(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii"), profile=self.profile.material())
        value = json.loads(exported.decode("ascii"))
        value["unknown"] = True
        with self.assertRaises(independent.IndependentOperationalRecoveryError):
            independent.verify_export_bytes(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii"), profile=self.profile.material())

    def test_busy_lock_is_bounded_and_leaves_catalog_unchanged(self) -> None:
        before = self.service.export_bytes()
        lock = sqlite3.connect(self.catalog, timeout=0, isolation_level=None)
        lock.execute("BEGIN IMMEDIATE")
        started = time.monotonic()
        try:
            with self.assertRaises(recovery.RecoveryBusyError):
                self.service.create_recovery_point(
                    "BUSY", generation=1, expected_head=self._genesis(),
                    quarantine_export=self.quarantine_export, runtime_export=self.runtime_export,
                )
        finally:
            lock.rollback()
            lock.close()
        self.assertLess(time.monotonic() - started, 2.0)
        self.assertEqual(self.service.export_bytes(), before)

    def test_support_storage_and_independent_module_are_zero_phi_bounded(self) -> None:
        result = self.service.create_recovery_point(
            "PRIVACY", generation=1, expected_head=self._genesis(),
            quarantine_export=self.quarantine_export, runtime_export=self.runtime_export,
        )
        support = json.dumps(self.service.support_snapshot(), sort_keys=True)
        catalog = self.service.export_bytes()
        connection = sqlite3.connect(self.catalog)
        try:
            object_id = connection.execute("SELECT object_id FROM recovery_points WHERE point_id=?", (result["point_id"],)).fetchone()[0]
        finally:
            connection.close()
        sealed = self.storage.get(object_id)
        self.assertNotIn(self.quarantine_export, sealed)
        self.assertNotIn(self.runtime_export, sealed)
        self.assertNotIn(self.quarantine_export, catalog)
        self.assertNotIn(self.runtime_export, catalog)
        for forbidden in ("http://", "https://", "token", "password", "patient", "member", "claim"):
            self.assertNotIn(forbidden, support.lower())
        self.assertNotIn("point_id", support)
        self.assertNotRegex(support, r"[0-9a-f]{128}")
        for key in ("head_root", "state_root", "object_id", "storage_id"):
            self.assertNotIn(key, support)
        support_value = self.service.support_snapshot()
        self.assertTrue(support_value["flags"]["production_usable"] is False)
        self.assertEqual(support_value["last_verified_age_bucket"], "NEVER")
        self.assertEqual(support_value["drill_duration_bucket"], "NONE")
        self.assertEqual(support_value["key_state_counts"], {"ACTIVE": 1})
        self.assertEqual(support_value["failure_counts"], {"invalidated": 0})

    def test_component_export_mutation_and_key_downgrade_fail_before_catalog_mutation(self) -> None:
        before = self.service.export_bytes()
        bad = bytearray(self.runtime_export)
        bad[-2] = ord("0") if bad[-2] != ord("0") else ord("1")
        with self.assertRaises(recovery.RecoveryIntegrityError):
            self.service.create_recovery_point(
                "BAD_EXPORT", generation=1, expected_head=self._genesis(),
                quarantine_export=self.quarantine_export, runtime_export=bytes(bad),
            )
        self.assertEqual(self.service.export_bytes(), before)
        self.custody.rotate(2)
        first = self.service.create_recovery_point(
            "EPOCH_TWO", generation=1, expected_head=self._genesis(),
            quarantine_export=self.quarantine_export, runtime_export=self.runtime_export,
        )
        self.assertEqual(first["state"], recovery.STATE_STORED)
        self.custody._current_epoch = 1  # test-only attempt to downgrade the port
        self.custody._states[1] = "ACTIVE"
        with self.assertRaises(recovery.RecoveryConflictError):
            self.service.create_recovery_point(
                "EPOCH_ONE", generation=2, expected_head=first["head_root"],
                quarantine_export=self.quarantine_export, runtime_export=self.runtime_export,
            )

    def test_independent_reconstruction_after_restart_and_restore(self) -> None:
        first = self.service.create_recovery_point(
            "RESTART", generation=1, expected_head=self._genesis(),
            quarantine_export=self.quarantine_export, runtime_export=self.runtime_export,
        )
        self.service.restore_point(first["point_id"], expected_head=first["head_root"])
        before = self.service.export_bytes()
        reopened = self._new_service(self.catalog)
        self.assertEqual(reopened.export_bytes(), before)
        independent.verify_database(self.catalog, profile=self.profile.material())

    def test_storage_overwrite_revocation_and_existing_restore_target_fail_closed(self) -> None:
        stored = self.service.create_recovery_point(
            "PORT_FAILURES", generation=1, expected_head=self._genesis(),
            quarantine_export=self.quarantine_export, runtime_export=self.runtime_export,
        )
        connection = sqlite3.connect(self.catalog)
        try:
            object_id = connection.execute(
                "SELECT object_id FROM recovery_points WHERE point_id=?", (stored["point_id"],)
            ).fetchone()[0]
        finally:
            connection.close()
        with self.assertRaises(ValueError):
            self.storage.put(object_id, b"different-sealed-object")
        self.custody.revoke(1)
        with self.assertRaises(recovery.RecoveryIntegrityError):
            self.service.restore_point(stored["point_id"], expected_head=stored["head_root"])
        self.assertEqual(
            self.service.integrity()["state_counts"][recovery.STATE_INVALIDATED], 1
        )

        export = self.service.export_bytes()
        existing = self.root / "existing-restore.db"
        existing.write_bytes(b"occupied")
        with self.assertRaises(recovery.RecoveryConflictError):
            recovery.restore_export(
                existing, export, profile=self.profile,
                quarantine_policy=self.upstream.source_policy,
                runtime_profile=self.upstream.profile, clock=self.clock,
                key_custody=self.custody, storage=self.storage,
            )

    def test_restore_export_truncation_reorder_and_profile_drift_fail_closed(self) -> None:
        stored = self.service.create_recovery_point(
            "EXPORT_FAILURES", generation=1, expected_head=self._genesis(),
            quarantine_export=self.quarantine_export, runtime_export=self.runtime_export,
        )
        export = self.service.export_bytes()
        with self.assertRaises(recovery.RecoveryIntegrityError):
            recovery.restore_export(
                self.root / "truncated.db", export[:-1], profile=self.profile,
                quarantine_policy=self.upstream.source_policy,
                runtime_profile=self.upstream.profile, clock=self.clock,
                key_custody=self.custody, storage=self.storage,
            )

        reordered = json.loads(export.decode("ascii"))
        reordered["tables"]["recovery_transitions"] = list(
            reversed(reordered["tables"]["recovery_transitions"])
        )
        body = dict(reordered)
        body.pop("export_root")
        reordered["export_root"] = recovery._digest("export-root", body)
        with self.assertRaises(recovery.RecoveryIntegrityError):
            recovery.restore_export(
                self.root / "reordered.db",
                recovery._canonical(reordered), profile=self.profile,
                quarantine_policy=self.upstream.source_policy,
                runtime_profile=self.upstream.profile, clock=self.clock,
                key_custody=self.custody, storage=self.storage,
            )

        drifted_profile = recovery.OperationalRecoveryProfileV1(
            profile_id=self.profile.profile_id,
            version=2,
            quarantine_policy_digest=self.profile.quarantine_policy_digest,
            runtime_profile_digest=self.profile.runtime_profile_digest,
            custody_id=self.profile.custody_id,
            storage_id=self.profile.storage_id,
        )
        with self.assertRaises(recovery.RecoveryIntegrityError):
            recovery.restore_export(
                self.root / "drifted-profile.db", export, profile=drifted_profile,
                quarantine_policy=self.upstream.source_policy,
                runtime_profile=self.upstream.profile, clock=self.clock,
                key_custody=self.custody, storage=self.storage,
            )
        self.assertEqual(self.service.integrity()["point_count"], 1)

    def test_custody_snapshot_object_and_storage_owner_bindings_fail_closed(self) -> None:
        class WrongKeyCustody(recovery_fixtures.SyntheticKeyCustody):
            def seal_for(self, plaintext: bytes, *, object_id: str, key_id: str, key_epoch: int) -> recovery.SealedRecoveryObjectV1:
                value = super().seal_for(plaintext, object_id=object_id, key_id=key_id, key_epoch=key_epoch)
                return recovery.SealedRecoveryObjectV1(object_id, "SYNTHETIC_OTHER_KEY", value.key_epoch, value.key_state, value.sealed_bytes)

        class DriftStorage(recovery_fixtures.SyntheticRecoveryStorage):
            def __init__(self) -> None:
                super().__init__()
                self._gets = 0

            def get(self, object_id: str) -> bytes:
                self._gets += 1
                value = super().get(object_id)
                return value + b"x" if self._gets == 2 else value

        bad = self._new_service(self.root / "wrong-key.db")
        bad.key_custody = WrongKeyCustody()
        before = bad.export_bytes()
        with self.assertRaises(recovery.RecoveryStorageError):
            bad.create_recovery_point(
                "WRONG_KEY", generation=1, expected_head=self._genesis(),
                quarantine_export=self.quarantine_export, runtime_export=self.runtime_export,
            )
        self.assertNotEqual(bad.export_bytes(), before)
        self.assertEqual(bad.integrity()["state_counts"][recovery.STATE_STORE_PENDING], 1)

        drift = self._new_service(self.root / "drift-storage.db")
        drift.storage = DriftStorage()
        with self.assertRaises(recovery.RecoveryStorageError):
            drift.create_recovery_point(
                "DRIFT_STORAGE", generation=1, expected_head=self._genesis(),
                quarantine_export=self.quarantine_export, runtime_export=self.runtime_export,
            )
        self.assertEqual(drift.integrity()["point_count"], 1)

        class WrongOwnerStorage(recovery_fixtures.SyntheticRecoveryStorage):
            storage_id = "SYNTHETIC_OTHER_STORAGE_V1"

        with self.assertRaises(recovery.OperationalRecoveryError):
            recovery.OperationalRecoveryService(
                self.root / "wrong-owner.db", profile=self.profile,
                quarantine_policy=self.upstream.source_policy, runtime_profile=self.upstream.profile,
                clock=self.clock, key_custody=self.custody,
                storage=WrongOwnerStorage(),
            )

    def test_revoked_after_restore_never_returns_historical_success(self) -> None:
        stored = self.service.create_recovery_point(
            "REVOKE_AFTER_RESTORE", generation=1, expected_head=self._genesis(),
            quarantine_export=self.quarantine_export, runtime_export=self.runtime_export,
        )
        restored = self.service.restore_point(stored["point_id"], expected_head=stored["head_root"])
        self.custody.revoke(1)
        with self.assertRaises(recovery.RecoveryIntegrityError):
            self.service.restore_point(stored["point_id"], expected_head=restored["head_root"])
        self.assertIsNone(self.service.select_latest_restore_verified())
        exported = self.service.export_bytes()
        class WrongOwnerCustody(recovery_fixtures.SyntheticKeyCustody):
            custody_id = "SYNTHETIC_OTHER_CUSTODY_V1"

        with self.assertRaises(recovery.OperationalRecoveryError):
            recovery.restore_export(
                self.root / "wrong-custody-export.db", exported, profile=self.profile,
                quarantine_policy=self.upstream.source_policy, runtime_profile=self.upstream.profile,
                clock=self.clock, key_custody=WrongOwnerCustody(),
                storage=self.storage,
            )

    def test_precommit_faults_leave_catalog_at_the_prior_state(self) -> None:
        for fault_point in ("before_record_stored", "before_record_stored_commit"):
            path = self.root / f"store-{fault_point}.db"

            def fault(point: str, expected: str = fault_point) -> None:
                if point == expected:
                    raise recovery.RecoveryInjectedFault(f"recovery:{expected}")

            faulted = self._new_service(path, fault=fault)
            with self.assertRaises(recovery.RecoveryInjectedFault):
                faulted.create_recovery_point(
                    f"FAULT_{fault_point}", generation=1, expected_head=self._genesis(),
                    quarantine_export=self.quarantine_export, runtime_export=self.runtime_export,
                )
            evidence = faulted.integrity()
            self.assertEqual(evidence["state_counts"][recovery.STATE_STORE_PENDING], 1)
            self.assertEqual(evidence["state_counts"][recovery.STATE_STORED], 0)
            self.assertEqual(evidence["transition_count"], 2)

        path = self.root / "restore-before-commit.db"
        stored = self._new_service(path).create_recovery_point(
            "RESTORE_FAULT", generation=1, expected_head=self._genesis(),
            quarantine_export=self.quarantine_export, runtime_export=self.runtime_export,
        )

        def restore_fault(point: str) -> None:
            if point == "before_restore_verified_commit":
                raise recovery.RecoveryInjectedFault("recovery:restore-before-commit")

        faulted_restore = self._new_service(path, fault=restore_fault)
        with self.assertRaises(recovery.RecoveryInjectedFault):
            faulted_restore.restore_point(stored["point_id"], expected_head=stored["head_root"])
        evidence = faulted_restore.integrity()
        self.assertEqual(evidence["state_counts"][recovery.STATE_STORED], 1)
        self.assertEqual(evidence["restore_count"], 0)

    def test_store_pending_is_durable_before_put_and_reuses_reserved_key_after_rotation(self) -> None:
        path = self.root / "pending-before-put.db"
        observed_states: list[str] = []

        class ObservingStorage(recovery_fixtures.SyntheticRecoveryStorage):
            def put(inner_self, object_id: str, sealed_bytes: bytes):
                connection = sqlite3.connect(path)
                try:
                    observed_states.append(str(connection.execute("SELECT state FROM recovery_points").fetchone()[0]))
                finally:
                    connection.close()
                return super(ObservingStorage, inner_self).put(object_id, sealed_bytes)

        storage = ObservingStorage()
        rotated = False

        def rotate_before_seal(point: str) -> None:
            nonlocal rotated
            if point == "before_seal" and not rotated:
                rotated = True
                self.custody.rotate(2)

        service = recovery.OperationalRecoveryService(
            path, profile=self.profile, quarantine_policy=self.upstream.source_policy,
            runtime_profile=self.upstream.profile, clock=self.clock,
            key_custody=self.custody, storage=storage, fault_injector=rotate_before_seal,
        )
        result = service.create_recovery_point(
            "PENDING_RESERVE", generation=1, expected_head=self._genesis(),
            quarantine_export=self.quarantine_export, runtime_export=self.runtime_export,
        )
        self.assertEqual(observed_states, [recovery.STATE_STORE_PENDING])
        self.assertEqual(result["state"], recovery.STATE_STORED)
        connection = service._connect()
        try:
            point = service._point(connection, result["point_id"])
        finally:
            connection.close()
        self.assertEqual(point["key_epoch"], 1)  # type: ignore[index]

    def test_revoked_reserved_key_becomes_durable_invalidated_without_storage(self) -> None:
        path = self.root / "pending-revoked.db"
        revoked = False

        def revoke_before_seal(point: str) -> None:
            nonlocal revoked
            if point == "before_seal" and not revoked:
                revoked = True
                self.custody.revoke(1)

        service = recovery.OperationalRecoveryService(
            path, profile=self.profile, quarantine_policy=self.upstream.source_policy,
            runtime_profile=self.upstream.profile, clock=self.clock,
            key_custody=self.custody, storage=self.storage, fault_injector=revoke_before_seal,
        )
        with self.assertRaises(recovery.RecoveryConflictError):
            service.create_recovery_point(
                "PENDING_REVOKED", generation=1, expected_head=self._genesis(),
                quarantine_export=self.quarantine_export, runtime_export=self.runtime_export,
            )
        evidence = service.integrity()
        self.assertEqual(evidence["state_counts"][recovery.STATE_INVALIDATED], 1)
        self.assertEqual(evidence["storage_count"], 0)

    def test_nondeterministic_reserved_seal_fails_before_storage_side_effect(self) -> None:
        path = self.root / "nondeterministic-seal.db"

        class NondeterministicCustody(recovery_fixtures.SyntheticKeyCustody):
            def __init__(inner_self) -> None:
                super().__init__()
                inner_self.calls = 0

            def seal_for(inner_self, plaintext: bytes, *, object_id: str, key_id: str, key_epoch: int) -> recovery.SealedRecoveryObjectV1:
                inner_self.calls += 1
                sealed = super().seal_for(plaintext, object_id=object_id, key_id=key_id, key_epoch=key_epoch)
                if inner_self.calls == 2:
                    return recovery.SealedRecoveryObjectV1(sealed.object_id, sealed.key_id, sealed.key_epoch, sealed.key_state, sealed.sealed_bytes + b"x")
                return sealed

        custody = NondeterministicCustody()
        storage = recovery_fixtures.SyntheticRecoveryStorage()
        service = recovery.OperationalRecoveryService(
            path, profile=self.profile, quarantine_policy=self.upstream.source_policy,
            runtime_profile=self.upstream.profile, clock=self.clock,
            key_custody=custody, storage=storage,
        )
        with self.assertRaises(recovery.RecoveryStorageError):
            service.create_recovery_point(
                "NONDETERMINISTIC_SEAL", generation=1, expected_head=self._genesis(),
                quarantine_export=self.quarantine_export, runtime_export=self.runtime_export,
            )
        self.assertEqual(service.integrity()["state_counts"][recovery.STATE_STORE_PENDING], 1)
        self.assertEqual(service.integrity()["storage_count"], 0)


if __name__ == "__main__":
    unittest.main()
