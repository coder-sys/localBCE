"""Focused adversarial coverage for the durable external-source quarantine."""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import traceback
import unittest

from app.mirror import external_source_adapter as adapter
from app.mirror import external_source_quarantine as quarantine
from app.mirror import external_source_quarantine_independent as independent
from tests.test_mirror_external_source_adapter import _FixtureVerifier, _policy


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")


class ExternalSourceQuarantineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = _policy()
        self._temporary = tempfile.TemporaryDirectory()
        self.database = Path(self._temporary.name) / "quarantine.db"
        self.database_id = "SYNTH_Q_DB_V1"
        self.service = quarantine.ExternalSourceQuarantineService(self.database, policy=self.policy, database_id=self.database_id)

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def _artifact(
        self,
        label: str,
        *,
        observed_at: int = 1_200,
        complete: bool = True,
        failure_code: str = "NONE",
        transport_authenticated: bool = True,
    ) -> bytes:
        raw = label.encode("ascii")
        verifier = _FixtureVerifier(
            self.policy,
            observed_at=observed_at,
            fetched_at=observed_at + 10,
            complete=complete,
            failure_code=failure_code,
            transport_authenticated=transport_authenticated,
        )
        return adapter.ExternalSourceAdapterService(self.policy, verifier).admit(raw).raw

    def _export(self) -> bytes:
        return self.service.export_bytes()

    def test_initial_admission_is_only_quarantine_and_independently_reconstructed(self) -> None:
        raw = self._artifact("capture-a")
        result = self.service.admit("admit-a", raw)
        self.assertEqual(result["action"], quarantine.ACTION_ADMIT)
        self.assertEqual(result["durable_status"], quarantine.QUARANTINE_STATUS)
        self.assertNotIn("source_status", result)
        self.assertFalse(result["flags"]["downstream_bridge"])
        self.assertFalse(result["flags"]["payment_authority"])
        evidence = self.service.integrity()
        self.assertEqual(evidence["artifact_count"], 1)
        self.assertEqual(evidence["operation_count"], 1)
        self.assertEqual(evidence["transition_count"], 1)
        self.assertEqual(evidence["head_state"], "QUARANTINED")
        self.assertEqual(evidence["head_artifact_id"], result["artifact_id"])
        self.assertNotIn(b"capture-a", self._export())

    def test_exact_retry_is_byte_identical_and_conflicting_retry_is_atomic(self) -> None:
        first_raw = self._artifact("capture-a")
        second_raw = self._artifact("capture-b")
        first = self.service.admit("same-operation", first_raw)
        before = self._export()
        retry = self.service.admit("same-operation", first_raw)
        self.assertEqual(retry["receipt_raw"], first["receipt_raw"])
        self.assertEqual(self._export(), before)
        with self.assertRaisesRegex(quarantine.QuarantineConflictError, "operation-conflict"):
            self.service.admit("same-operation", second_raw)
        self.assertEqual(self._export(), before)
        with self.assertRaisesRegex(quarantine.QuarantineConflictError, "stale-head"):
            self.service.admit("other-operation", second_raw)
        self.assertEqual(self.service.integrity()["artifact_count"], 1)

    def test_receipt_binds_artifact_digest_and_verifies_the_supplied_bytes(self) -> None:
        result = self.service.admit("receipt-binding", self._artifact("receipt-binding"))
        receipt = json.loads(result["receipt_raw"].decode("ascii"))
        self.assertEqual(result["artifact_digest"], receipt["artifact_digest"])
        connection = sqlite3.connect(self.database)
        connection.row_factory = sqlite3.Row
        try:
            operation = dict(connection.execute("SELECT * FROM quarantine_operations").fetchone())
            transition = dict(connection.execute("SELECT * FROM quarantine_transitions").fetchone())
            artifact = dict(connection.execute("SELECT * FROM quarantine_artifacts").fetchone())
            head = dict(connection.execute("SELECT * FROM quarantine_heads").fetchone())
        finally:
            connection.close()
        with self.assertRaisesRegex(independent.IndependentQuarantineError, "receipt-input"):
            independent.verify_admission_receipt(
                b"{}", policy=self.policy.material(), database_id=self.database_id,
                operation=operation, transition=transition, artifact=artifact, head=head,
            )
        tampered_head = dict(head)
        tampered_head["observed_at"] = int(head["observed_at"]) + 1
        with self.assertRaisesRegex(independent.IndependentQuarantineError, "receipt-head"):
            independent.verify_admission_receipt(
                result["receipt_raw"], policy=self.policy.material(), database_id=self.database_id,
                operation=operation, transition=transition, artifact=artifact, head=tampered_head,
            )

    def test_adapter_failure_never_echoes_private_exception_content(self) -> None:
        raw = self._artifact("adapter-private-error")

        def fail_adapter(*_args: object, **_kwargs: object) -> object:
            raise RuntimeError("PRIVATE-PATIENT-PATH")

        original = quarantine.adapter.verify_artifact
        quarantine.adapter.verify_artifact = fail_adapter
        try:
            with self.assertRaisesRegex(quarantine.ExternalSourceQuarantineError, "adapter-verification") as caught:
                self.service.admit("adapter-private-error", raw)
        finally:
            quarantine.adapter.verify_artifact = original
        self.assertNotIn("PRIVATE-PATIENT-PATH", str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        self.assertNotIn("PRIVATE-PATIENT-PATH", "".join(traceback.format_exception(caught.exception)))
        self.assertEqual(0, self.service.integrity()["artifact_count"])

    def test_newer_artifact_supersedes_and_out_of_order_or_withdrawn_admission_rejects(self) -> None:
        first_raw = self._artifact("capture-a")
        second_raw = self._artifact("capture-b", observed_at=1_300)
        first = self.service.admit("first", first_raw)
        second = self.service.admit("second", second_raw, expected_head=first["artifact_id"])
        self.assertEqual(second["action"], quarantine.ACTION_SUPERSEDE)
        self.assertEqual(self.service.integrity()["sequence"], 2)
        before = self._export()
        first_retry = self.service.admit("first", first_raw)
        second_retry = self.service.admit("second", second_raw, expected_head=first["artifact_id"])
        self.assertEqual(first_retry["receipt_raw"], first["receipt_raw"])
        self.assertEqual(second_retry["receipt_raw"], second["receipt_raw"])
        self.assertEqual(first_retry["head_root"], first["head_root"])
        self.assertEqual(self.service.head()["head_root"], second["head_root"])  # type: ignore[index]
        self.assertEqual(self._export(), before)
        with self.assertRaisesRegex(quarantine.QuarantineConflictError, "out-of-order"):
            self.service.admit("old", self._artifact("capture-old", observed_at=1_250), expected_head=second["artifact_id"])
        self.assertEqual(self._export(), before)
        withdrawn = self.service.withdraw("withdraw", expected_head=second["artifact_id"], reason="SOURCE_WITHDRAWN")
        self.assertEqual(withdrawn["state"], "WITHDRAWN")
        retry = self.service.withdraw("withdraw", expected_head=second["artifact_id"], reason="SOURCE_WITHDRAWN")
        self.assertEqual(retry["receipt_raw"], withdrawn["receipt_raw"])
        before = self._export()
        self.assertEqual(self.service.admit("first", first_raw)["receipt_raw"], first["receipt_raw"])
        self.assertEqual(
            self.service.admit("second", second_raw, expected_head=first["artifact_id"])["receipt_raw"],
            second["receipt_raw"],
        )
        self.assertEqual(self._export(), before)
        with self.assertRaisesRegex(quarantine.QuarantineConflictError, "withdrawn"):
            self.service.admit("after-withdrawal", self._artifact("capture-c", observed_at=1_400), expected_head=second["artifact_id"])
        self.assertEqual(self._export(), before)
        self.assertEqual(self.service.integrity()["head_state"], "WITHDRAWN")

    def test_hold_source_status_is_durably_quarantined_and_policy_drift_fails_closed(self) -> None:
        held = self._artifact("incomplete", complete=False, failure_code="INCOMPLETE")
        result = self.service.admit("held", held)
        self.assertEqual(result["durable_status"], "QUARANTINED")
        connection = sqlite3.connect(self.database)
        try:
            self.assertEqual(connection.execute("SELECT status FROM quarantine_artifacts").fetchone()[0], "QUARANTINED")
        finally:
            connection.close()
        drifted = _policy(logical_endpoint_id="SYNTHETIC_OTHER_ENDPOINT_V1")
        with self.assertRaisesRegex(quarantine.ExternalSourceQuarantineError, "policy-drift"):
            quarantine.ExternalSourceQuarantineService(self.database, policy=drifted, database_id=self.database_id)

    def test_same_capture_identity_with_rebound_artifact_bytes_is_rejected(self) -> None:
        first_raw = self._artifact("capture-identity")
        first = self.service.admit("capture-identity-a", first_raw)
        value = json.loads(first_raw.decode("ascii"))
        capture = value["capture"]
        capture["observed_at"] = 1_300
        capture["fetched_at"] = 1_310
        capture["transport_receipt_digest"] = adapter._digest(
            "transport-receipt",
            {
                "policy_digest": capture["policy_digest"],
                "verifier_id": capture["verifier_id"],
                "verifier_epoch": capture["verifier_epoch"],
                "payload_sha3_512": capture["payload_sha3_512"],
                "page_digests": capture["page_digests"],
                "server_identity_digest": capture["server_identity_digest"],
                "observed_at": capture["observed_at"],
                "fetched_at": capture["fetched_at"],
                "transport_authenticated": capture["transport_authenticated"],
                "complete": capture["complete"],
                "failure_code": capture["failure_code"],
            },
        )
        body = {key: item for key, item in value.items() if key != "artifact_id"}
        value["artifact_id"] = adapter._digest("artifact-id", body)
        rebound = _canonical(value)
        before = self._export()
        with self.assertRaisesRegex(quarantine.QuarantineConflictError, "capture-collision"):
            self.service.admit("capture-identity-b", rebound, expected_head=first["artifact_id"])
        self.assertEqual(self._export(), before)

    def test_precommit_faults_leave_schema_logical_state_unchanged(self) -> None:
        fault_points = ("before_transaction", "after_begin", "after_artifact_insert", "after_operation_insert", "after_transition_insert", "before_commit")
        for point in fault_points:
            with self.subTest(point=point):
                path = Path(self._temporary.name) / f"{point}.db"
                armed = {"value": True}

                def inject(current: str, *, target: str = point, state: dict[str, bool] = armed) -> None:
                    if state["value"] and current == target:
                        state["value"] = False
                        raise quarantine.QuarantineInjectedFault(f"quarantine:injected:{target}")

                service = quarantine.ExternalSourceQuarantineService(path, policy=self.policy, database_id=self.database_id, fault_injector=inject)
                with self.assertRaises(quarantine.QuarantineInjectedFault):
                    service.admit(f"fault-{point}", self._artifact(f"raw-{point}"))
                evidence = independent.verify_database(path, policy=self.policy.material(), database_id=self.database_id)
                self.assertEqual(evidence["sequence"], 0)
                self.assertEqual(evidence["artifact_count"], 0)
                self.assertEqual(service.export_bytes(), quarantine.ExternalSourceQuarantineService(path, policy=self.policy, database_id=self.database_id).export_bytes())

    def test_postcommit_response_loss_recovers_by_exact_retry(self) -> None:
        state = {"armed": True}

        def inject(point: str) -> None:
            if point == "after_commit_before_response" and state["armed"]:
                state["armed"] = False
                raise quarantine.QuarantineResponseLost("quarantine:response-lost")

        service = quarantine.ExternalSourceQuarantineService(self.database, policy=self.policy, database_id=self.database_id, fault_injector=inject)
        raw = self._artifact("response-loss")
        with self.assertRaises(quarantine.QuarantineResponseLost):
            service.admit("response-loss", raw)
        retry = service.admit("response-loss", raw)
        self.assertEqual(retry["action"], "ADMIT")
        self.assertEqual(service.integrity()["sequence"], 1)

    def test_busy_writer_contention_is_bounded_and_leaves_state_unchanged(self) -> None:
        lock = sqlite3.connect(self.database, timeout=0, isolation_level=None)
        try:
            lock.execute("BEGIN IMMEDIATE")
            started = time.monotonic()
            with self.assertRaisesRegex(quarantine.QuarantineBusyError, "busy"):
                self.service.admit("busy", self._artifact("busy"))
            elapsed = time.monotonic() - started
            self.assertLess(elapsed, 2.0)
            evidence = independent.verify_database(self.database, policy=self.policy.material(), database_id=self.database_id)
            self.assertEqual(evidence["sequence"], 0)
            self.assertEqual(evidence["artifact_count"], 0)
        finally:
            lock.rollback()
            lock.close()

    def test_identical_concurrent_writers_converge_without_duplicate_rows(self) -> None:
        services = [quarantine.ExternalSourceQuarantineService(self.database, policy=self.policy, database_id=self.database_id) for _ in range(2)]
        raw = self._artifact("identical-race")
        barrier = threading.Barrier(2)
        outcomes: list[object] = []

        def worker(service: quarantine.ExternalSourceQuarantineService) -> None:
            barrier.wait()
            try:
                outcomes.append(service.admit("identical-race", raw))
            except Exception as exc:  # pragma: no cover - assertion below reports the raw type
                outcomes.append(exc)

        threads = [threading.Thread(target=worker, args=(service,)) for service in services]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)
        self.assertEqual(len(outcomes), 2)
        self.assertTrue(all(isinstance(item, dict) for item in outcomes), outcomes)
        self.assertEqual(outcomes[0]["receipt_raw"], outcomes[1]["receipt_raw"])  # type: ignore[index]
        evidence = self.service.integrity()
        self.assertEqual((evidence["artifact_count"], evidence["operation_count"], evidence["transition_count"]), (1, 1, 1))

    def test_conflicting_concurrent_writers_have_one_winner_and_no_loser_residue(self) -> None:
        for reverse in (False, True):
            with self.subTest(reverse=reverse):
                path = Path(self._temporary.name) / ("conflict-reverse.db" if reverse else "conflict-forward.db")
                services = [quarantine.ExternalSourceQuarantineService(path, policy=self.policy, database_id=self.database_id) for _ in range(2)]
                artifacts = [self._artifact("conflict-a"), self._artifact("conflict-b")]
                barrier = threading.Barrier(2)
                outcomes: list[object] = []

                def worker(index: int) -> None:
                    barrier.wait()
                    actual = 1 - index if reverse else index
                    try:
                        outcomes.append(services[actual].admit(f"conflict-{actual}", artifacts[actual]))
                    except Exception as exc:
                        outcomes.append(exc)

                threads = [threading.Thread(target=worker, args=(index,)) for index in range(2)]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join(timeout=5)
                self.assertEqual(len(outcomes), 2)
                self.assertEqual(sum(isinstance(item, dict) for item in outcomes), 1, outcomes)
                self.assertEqual(sum(isinstance(item, quarantine.QuarantineConflictError) for item in outcomes), 1, outcomes)
                evidence = independent.verify_database(path, policy=self.policy.material(), database_id=self.database_id)
                self.assertEqual((evidence["artifact_count"], evidence["operation_count"], evidence["transition_count"]), (1, 1, 1))
                winner = next(item for item in outcomes if isinstance(item, dict))
                self.assertEqual(evidence["head_artifact_id"], winner["artifact_id"])  # type: ignore[index]
                candidate_ids = {
                    adapter.ExternalSourceAdapterService(self.policy, _FixtureVerifier(self.policy)).admit(b"conflict-a").artifact_id,
                    adapter.ExternalSourceAdapterService(self.policy, _FixtureVerifier(self.policy)).admit(b"conflict-b").artifact_id,
                }
                loser_id = next(item for item in candidate_ids if item != winner["artifact_id"])  # type: ignore[index]
                self.assertNotEqual(evidence["head_artifact_id"], loser_id)

    def test_withdrawal_conflicts_and_stale_heads_leave_state_unchanged(self) -> None:
        first = self.service.admit("head", self._artifact("head"))
        before = self._export()
        with self.assertRaisesRegex(quarantine.QuarantineConflictError, "stale-head"):
            self.service.withdraw("wrong-head", expected_head="0" * 128, reason="POLICY_REVOKED")
        with self.assertRaisesRegex(quarantine.QuarantineConflictError, "withdraw-reason"):
            self.service.withdraw("bad-reason", expected_head=first["artifact_id"], reason="CALLER_REASON")
        self.assertEqual(self._export(), before)

    def test_export_restore_and_corruption_reject_without_clobber(self) -> None:
        first = self.service.admit("a", self._artifact("a"))
        self.service.admit("b", self._artifact("b", observed_at=1_300), expected_head=first["artifact_id"])
        exported = self._export()
        verified = independent.verify_export_bytes(exported, policy=self.policy.material(), database_id=self.database_id)
        self.assertEqual(verified["sequence"], 2)
        restored = Path(self._temporary.name) / "restored.db"
        copy = quarantine.ExternalSourceQuarantineService.restore_export(restored, exported, policy=self.policy, database_id=self.database_id)
        self.assertEqual(copy.export_bytes(), exported)
        with self.assertRaises(independent.IndependentQuarantineError):
            independent.verify_export_bytes(exported[:-1], policy=self.policy.material(), database_id=self.database_id)
        value = json.loads(exported.decode("ascii"))
        value["unknown"] = True
        with self.assertRaises(independent.IndependentQuarantineError):
            independent.verify_export_bytes(_canonical(value), policy=self.policy.material(), database_id=self.database_id)
        retry = quarantine.ExternalSourceQuarantineService.restore_export(restored, exported, policy=self.policy, database_id=self.database_id)
        self.assertEqual(retry.export_bytes(), exported)
        connection = sqlite3.connect(self.database)
        try:
            connection.execute("UPDATE quarantine_meta SET value=? WHERE key='head_root'", ("0" * 128,))
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(independent.IndependentQuarantineError):
            independent.verify_database(self.database, policy=self.policy.material(), database_id=self.database_id)

    def test_restore_publication_is_create_only_and_converges_without_clobber(self) -> None:
        self.service.admit("publication-a", self._artifact("publication-a"))
        exported = self._export()
        destination = Path(self._temporary.name) / "publication.db"
        barrier = threading.Barrier(3)
        results: list[object] = []

        def restore() -> None:
            barrier.wait()
            try:
                results.append(quarantine.ExternalSourceQuarantineService.restore_export(destination, exported, policy=self.policy, database_id=self.database_id))
            except Exception as exc:  # pragma: no cover - assertion below records the race
                results.append(exc)

        threads = [threading.Thread(target=restore), threading.Thread(target=restore)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(5)
        self.assertEqual(len(results), 2)
        self.assertTrue(all(isinstance(item, quarantine.ExternalSourceQuarantineService) for item in results), results)
        self.assertEqual(results[0].export_bytes(), exported)
        self.assertEqual(results[1].export_bytes(), exported)
        self.assertEqual(list(Path(self._temporary.name).glob(".publication.db.restore-*.db")), [])

        alternate_path = Path(self._temporary.name) / "alternate.db"
        alternate = quarantine.ExternalSourceQuarantineService(alternate_path, policy=self.policy, database_id=self.database_id)
        alternate.admit("publication-other", self._artifact("publication-other"))
        alternate_export = alternate.export_bytes()
        before = destination.read_bytes()
        with self.assertRaises(quarantine.QuarantineConflictError):
            quarantine.ExternalSourceQuarantineService.restore_export(destination, alternate_export, policy=self.policy, database_id=self.database_id)
        self.assertEqual(destination.read_bytes(), before)

        fired = False

        def after_publish(point: str) -> None:
            nonlocal fired
            if point == "after_atomic_publication_before_response" and not fired:
                fired = True
                raise quarantine.QuarantineResponseLost("quarantine:restore-response-lost")

        crash_target = Path(self._temporary.name) / "publication-crash.db"
        with self.assertRaises(quarantine.QuarantineResponseLost):
            quarantine.ExternalSourceQuarantineService.restore_export(crash_target, exported, policy=self.policy, database_id=self.database_id, fault_injector=after_publish)
        recovered = quarantine.ExternalSourceQuarantineService.restore_export(crash_target, exported, policy=self.policy, database_id=self.database_id)
        self.assertEqual(recovered.export_bytes(), exported)

        interrupted_target = Path(self._temporary.name) / "publication-interrupted.db"
        original_restore = quarantine.ExternalSourceQuarantineService._restore_snapshot

        def interrupt_restore(_service: object, _snapshot: object) -> None:
            raise quarantine.QuarantineInjectedFault("quarantine:restore-interrupted")

        quarantine.ExternalSourceQuarantineService._restore_snapshot = interrupt_restore
        try:
            with self.assertRaises(quarantine.QuarantineInjectedFault):
                quarantine.ExternalSourceQuarantineService.restore_export(
                    interrupted_target, exported, policy=self.policy, database_id=self.database_id,
                )
        finally:
            quarantine.ExternalSourceQuarantineService._restore_snapshot = original_restore
        self.assertFalse(interrupted_target.exists())
        interrupted = quarantine.ExternalSourceQuarantineService.restore_export(
            interrupted_target, exported, policy=self.policy, database_id=self.database_id,
        )
        self.assertEqual(interrupted.export_bytes(), exported)

    def test_corrupt_current_artifact_cannot_be_used_as_a_mutation_anchor(self) -> None:
        first = self.service.admit("anchor", self._artifact("anchor"))
        connection = sqlite3.connect(self.database)
        try:
            connection.execute("UPDATE quarantine_artifacts SET artifact_digest=?", ("0" * 128,))
            connection.commit()
        finally:
            connection.close()
        with self.assertRaisesRegex(quarantine.QuarantineConflictError, "head-artifact-integrity"):
            self.service.admit("new-anchor", self._artifact("new-anchor", observed_at=1_300), expected_head=first["artifact_id"])
        with self.assertRaisesRegex(quarantine.QuarantineConflictError, "head-artifact-integrity"):
            self.service.withdraw("withdraw-corrupt", expected_head=first["artifact_id"], reason="INTEGRITY_REVIEW")
        # The corruption is detected, never repaired or advanced.
        connection = sqlite3.connect(self.database)
        try:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM quarantine_artifacts").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM quarantine_operations").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM quarantine_transitions").fetchone()[0], 1)
        finally:
            connection.close()
        with self.assertRaises(independent.IndependentQuarantineError):
            independent.verify_database(self.database, policy=self.policy.material(), database_id=self.database_id)

    def test_adapter_mutation_and_authority_flags_cannot_enter_quarantine(self) -> None:
        raw = self._artifact("mutation")
        value = json.loads(raw.decode("ascii"))
        value["flags"]["production_usable"] = True
        body = {key: item for key, item in value.items() if key != "artifact_id"}
        value["artifact_id"] = adapter._digest("artifact-id", body)
        mutated = _canonical(value)
        before = self._export()
        with self.assertRaisesRegex(quarantine.ExternalSourceQuarantineError, "authority-flags"):
            self.service.admit("mutated", mutated)
        self.assertEqual(self._export(), before)

    def test_every_fixed_export_flag_mutation_rejects_after_root_rebind(self) -> None:
        self.service.admit("flags", self._artifact("flags"))
        original = json.loads(self._export().decode("ascii"))
        for field, expected in independent.FIXED_FLAGS.items():
            with self.subTest(field=field):
                mutated = dict(original)
                mutated[field] = "MUTATED" if expected is None else not expected
                body = {key: value for key, value in mutated.items() if key != "export_root"}
                mutated["export_root"] = independent._digest("export-root", body)
                with self.assertRaises(independent.IndependentQuarantineError):
                    independent.verify_export_bytes(
                        _canonical(mutated),
                        policy=self.policy.material(),
                        database_id=self.database_id,
                    )

    def test_support_is_aggregate_only_and_no_downstream_bridge_exists(self) -> None:
        raw = self._artifact("support-capture")
        self.service.admit("support", raw)
        support = _canonical(self.service.support_snapshot())
        forbidden = (
            b"support-capture", self.policy.logical_endpoint_id.encode("ascii"),
            self.policy.authorization_artifact_digest.encode("ascii"), self.policy.terms_artifact_digest.encode("ascii"),
            b"artifact_raw", b"capture_id", b"payload_sha3_512", b"http://", b"https://",
        )
        for marker in forbidden:
            self.assertNotIn(marker, support)
        self.assertNotRegex(support.decode("ascii"), r"[0-9a-f]{128}")
        for key in (b"chain_id", b"database_id", b"head_root"):
            self.assertNotIn(key, support)
        source = Path(quarantine.__file__).read_text(encoding="utf-8")
        self.assertNotIn("from app.mirror import continuity_store", source)
        self.assertNotIn("from app.mirror import provider_trust_graph", source)
        self.assertNotIn(b"CLEAR", support)
        self.assertIn(b"payment_authority", support)


if __name__ == "__main__":
    unittest.main()
