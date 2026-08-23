"""Focused adversarial tests for the durable controlled-shadow runtime."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest

from app.mirror import controlled_shadow_runtime as runtime
from app.mirror import controlled_shadow_runtime_fixtures as fixtures
from app.mirror import controlled_shadow_runtime_independent as independent
from app.mirror import external_source_adapter as source_adapter
from app.mirror import external_source_quarantine as quarantine
from app.mirror import external_governance_approval as governance
from app.mirror import external_privacy_support_approval as privacy
from tests.test_mirror_external_source_adapter import _FixtureVerifier as SourceVerifier
from tests.test_mirror_external_source_adapter import _policy as source_policy_factory
from tests.test_mirror_external_governance_approval import _FixtureVerifier as GovernanceVerifier
from tests.test_mirror_external_governance_approval import _policy as governance_policy_factory
from tests.test_mirror_external_privacy_support_approval import _FixtureVerifier as PrivacyVerifier
from tests.test_mirror_external_privacy_support_approval import _policy as privacy_policy_factory


def _hex(label: str) -> str:
    return hashlib.sha3_512(label.encode("ascii")).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")


class ControlledShadowRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.quarantine_db = root / "quarantine.db"
        self.runtime_db = root / "runtime.db"
        self.source_policy = source_policy_factory()
        source_artifact = source_adapter.ExternalSourceAdapterService(self.source_policy, SourceVerifier(self.source_policy)).admit(b"synthetic-shadow-capture")
        self.quarantine_service = quarantine.ExternalSourceQuarantineService(self.quarantine_db, policy=self.source_policy, database_id="SYNTH_SHADOW_Q_DB_V1")
        admitted = self.quarantine_service.admit("synthetic-quarantine-open", source_artifact.raw)
        head = self.quarantine_service.head()
        assert head is not None
        self.quarantine_head = {
            "policy_digest": self.quarantine_service.policy_digest,
            "head_artifact_id": head["head_artifact_id"],
            "head_root": head["head_root"],
            "state": head["state"],
            "sequence": head["sequence"],
        }
        self.quarantine_raw = source_artifact.raw
        self.governance_evidence = b"synthetic-shadow-governance"
        self.governance_policy = governance_policy_factory(
            source_policy_digest=self.source_policy.digest,
            quarantine_policy_digest=self.quarantine_service.policy_digest,
            quarantine_artifact_id=admitted["artifact_id"],
            quarantine_head_artifact_id=head["head_artifact_id"],
            quarantine_head_root=head["head_root"],
        )
        governance_artifact = governance.ExternalGovernanceApprovalService(self.governance_policy, GovernanceVerifier(self.governance_policy)).observe(self.governance_evidence)
        self.governance_raw = governance_artifact.raw
        self.privacy_evidence = b"synthetic-shadow-privacy-support"
        self.privacy_policy = privacy_policy_factory(
            source_policy_digest=self.source_policy.digest,
            quarantine_policy_digest=self.quarantine_service.policy_digest,
            quarantine_artifact_id=admitted["artifact_id"],
            quarantine_head_artifact_id=head["head_artifact_id"],
            quarantine_head_root=head["head_root"],
            governance_observation_artifact_id=governance_artifact.artifact_id,
            governance_evidence_digest=hashlib.sha3_512(self.governance_evidence).hexdigest(),
            governance_decision=governance_artifact.decision,
            terms_digest=self.governance_policy.terms_digest,
            retention_policy_digest=self.governance_policy.retention_policy_digest,
        )
        self.privacy_raw = privacy.ExternalPrivacySupportApprovalService(self.privacy_policy, PrivacyVerifier(self.privacy_policy)).observe(self.privacy_evidence).raw
        self.profile = runtime.ControlledShadowRuntimeProfileV1(
            profile_id="SYNTHETIC_CONTROLLED_SHADOW_RUNTIME_V1",
            version=1,
            runtime_id_domain="SYNTHETIC_RUNTIME_DOMAIN_V1",
            source_policy_digest=self.source_policy.digest,
            quarantine_policy_digest=self.quarantine_service.policy_digest,
            quarantine_artifact_id=admitted["artifact_id"],
            quarantine_head_artifact_id=head["head_artifact_id"],
            quarantine_head_root=head["head_root"],
            governance_policy_digest=self.governance_policy.digest,
            governance_artifact_id=governance_artifact.artifact_id,
            governance_evidence_digest=hashlib.sha3_512(self.governance_evidence).hexdigest(),
            governance_decision=governance_artifact.decision,
            privacy_policy_digest=self.privacy_policy.digest,
            privacy_artifact_id=json.loads(self.privacy_raw.decode("ascii"))["artifact_id"],
            privacy_evidence_digest=hashlib.sha3_512(self.privacy_evidence).hexdigest(),
            privacy_decision="GRANTED",
            support_decision="GRANTED",
            authorization_verifier_id=fixtures.SyntheticAuthorizationVerifier.verifier_id,
            authorization_verifier_epoch=fixtures.SyntheticAuthorizationVerifier.verifier_epoch,
            evaluator_id="SYNTHETIC_SHADOW_EVALUATOR_V1",
            evaluator_epoch=1,
        )
        self.bundle = runtime.RuntimeUpstreamBundleV1(
            source_policy=self.source_policy.material(),
            quarantine_raw=self.quarantine_raw,
            quarantine_head=self.quarantine_head,
            governance_policy=self.governance_policy.material(),
            governance_raw=self.governance_raw,
            governance_evidence_raw=self.governance_evidence,
            privacy_policy=self.privacy_policy.material(),
            privacy_raw=self.privacy_raw,
            privacy_evidence_raw=self.privacy_evidence,
        )
        self.clock = fixtures.SyntheticClock()
        self.service = runtime.ControlledShadowRuntimeService(self.runtime_db, profile=self.profile, clock=self.clock)
        self.authorization = fixtures.SyntheticAuthorizationVerifier()
        self.evaluator = fixtures.SyntheticShadowEvaluator(self.clock)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _open(self, key: str = "SYNTHETIC_SESSION_A") -> tuple[str, str]:
        opened = self.service.create_session("OPEN_" + key, key, self.bundle, self.authorization)
        started = self.service.start_session("START_" + key, opened["session_id"], expected_head=opened["head_root"])
        return str(opened["session_id"]), str(started["head_root"])

    def test_full_synthetic_lifecycle_is_independently_reconstructed(self) -> None:
        session_id, head = self._open()
        first = self.service.run_observation("OBS_0", session_id, expected_head=head, evaluator=self.evaluator)
        self.clock.advance(10)
        second = self.service.run_observation("OBS_1", session_id, expected_head=first["head_root"], evaluator=self.evaluator)
        completed = self.service.complete_session("COMPLETE", session_id, expected_head=second["head_root"])
        self.assertEqual(completed["state"], independent.STATE_COMPLETED)
        evidence = self.service.integrity()
        self.assertEqual(evidence["session_count"], 1)
        self.assertEqual(evidence["result_counts"]["PARITY"], 1)
        self.assertEqual(evidence["result_counts"]["DISCREPANCY"], 1)
        self.assertEqual(evidence["discrepancy_count"], 1)
        self.assertEqual(self.service.support_snapshot()["flags"]["production_usable"], False)

    def test_pause_resume_and_abort_are_explicit_terminal_paths(self) -> None:
        session_id, head = self._open()
        paused = self.service.pause_session("PAUSE", session_id, expected_head=head, reason="MANUAL_PAUSE")
        resumed = self.service.resume_session("RESUME", session_id, expected_head=paused["head_root"])
        aborted = self.service.abort_session("ABORT", session_id, expected_head=resumed["head_root"], reason="MANUAL_ABORT")
        self.assertEqual(aborted["state"], independent.STATE_ABORTED)
        with self.assertRaisesRegex(runtime.RuntimeConflictError, "illegal-state"):
            self.service.resume_session("BAD_RESUME", session_id, expected_head=aborted["head_root"])

    def test_exact_retry_is_byte_identical_and_response_loss_recovers(self) -> None:
        opened = self.service.create_session("OPEN_RETRY", "SYNTHETIC_SESSION_RETRY", self.bundle, self.authorization)
        retry = self.service.create_session("OPEN_RETRY", "SYNTHETIC_SESSION_RETRY", self.bundle, self.authorization)
        self.assertEqual(retry["receipt_raw"], opened["receipt_raw"])
        started = self.service.start_session("START_RETRY", opened["session_id"], expected_head=opened["head_root"])
        self.clock.advance(1)
        faulted = {"done": False}

        def inject(point: str) -> None:
            if point == "after_commit_before_response" and not faulted["done"]:
                faulted["done"] = True
                raise runtime.RuntimeInjectedFault("runtime:test-response-loss")

        self.service.fault_injector = inject
        with self.assertRaises(runtime.RuntimeResponseLost):
            self.service.run_observation("OBS_RETRY", started["session_id"], expected_head=started["head_root"], evaluator=self.evaluator)
        self.service.fault_injector = None
        recovered = self.service.run_observation("OBS_RETRY", started["session_id"], expected_head=started["head_root"], evaluator=self.evaluator)
        self.assertEqual(recovered["receipt"]["operation_id"], "OBS_RETRY")
        self.assertEqual(self.service.integrity()["operation_count"], 4)

    def test_conflicting_operation_and_stale_head_fail_without_mutation(self) -> None:
        opened = self.service.create_session("OPEN_CONFLICT", "SYNTHETIC_SESSION_CONFLICT", self.bundle, self.authorization)
        before = self.service.export_bytes()
        with self.assertRaisesRegex(runtime.RuntimeConflictError, "operation-conflict"):
            self.service.create_session("OPEN_CONFLICT", "SYNTHETIC_SESSION_OTHER", self.bundle, self.authorization)
        self.assertEqual(self.service.export_bytes(), before)
        with self.assertRaisesRegex(runtime.RuntimeConflictError, "stale-head"):
            self.service.start_session("START_STALE", opened["session_id"], expected_head=_hex("wrong-head"))
        self.assertEqual(self.service.export_bytes(), before)

    def test_evaluator_discrepancy_is_runtime_local_and_no_downstream_bridge_exists(self) -> None:
        source = Path("app/mirror/controlled_shadow_runtime.py").read_text(encoding="utf-8")
        self.assertNotIn("from app.mirror import continuity_store", source)
        self.assertNotIn("import app.mirror.continuity_store", source)
        self.assertNotIn("discrepancy_case", source)
        session_id, head = self._open("SYNTHETIC_SESSION_LOCAL")
        result = self.service.run_observation("OBS_LOCAL", session_id, expected_head=head, evaluator=self.evaluator)
        self.assertEqual(result["receipt"]["details"]["result"], "PARITY")
        connection = sqlite3.connect(self.runtime_db)
        try:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM runtime_discrepancies").fetchone()[0], 0)
        finally:
            connection.close()

    def test_invalid_evaluator_result_pauses_without_accepting_it(self) -> None:
        session_id, head = self._open("SYNTHETIC_SESSION_INVALID")

        class InvalidEvaluator:
            evaluator_id = "SYNTHETIC_SHADOW_EVALUATOR_V1"
            evaluator_epoch = 1

            def evaluate(self, input_raw: bytes) -> runtime.VerifiedShadowEvaluationV1:
                raise ValueError("invalid fixture result")

        result = self.service.run_observation("OBS_INVALID", session_id, expected_head=head, evaluator=InvalidEvaluator())
        self.assertEqual(result["state"], independent.STATE_RUNNING)
        self.assertEqual(result["receipt"]["details"]["failure_code"], "EVALUATOR_EXCEPTION")
        self.assertEqual(self.service.integrity()["slot_count"], 1)
        self.assertEqual(self.service.integrity()["failure_count"], 1)

    def test_retryable_evaluator_failure_returns_due_then_retries(self) -> None:
        session_id, head = self._open("SYNTHETIC_SESSION_FAILURE")
        failing = fixtures.SyntheticShadowEvaluator(self.clock, fail_once={0: "EVALUATOR_TIMEOUT"})
        failure = self.service.run_observation("OBS_FAILURE", session_id, expected_head=head, evaluator=failing)
        self.assertEqual(failure["state"], independent.STATE_RUNNING)
        retried = self.service.run_observation("OBS_FAILURE_RETRY", session_id, expected_head=failure["head_root"], evaluator=failing)
        self.assertEqual(retried["receipt"]["details"]["result"], "PARITY")

    def test_lease_expiry_makes_old_completion_stale_and_new_claim_deterministic(self) -> None:
        session_id, head = self._open("SYNTHETIC_SESSION_LEASE")
        claim = self.service.claim_observation("CLAIM_OLD", session_id, expected_head=head)
        self.clock.advance(self.profile.lease_seconds + 1)
        new_claim = self.service.claim_observation("CLAIM_NEW", session_id, expected_head=claim.head_root)
        self.assertEqual(claim.slot_number, new_claim.slot_number)
        self.assertGreater(new_claim.attempt, claim.attempt)
        old_result = self.evaluator.evaluate(claim.input_raw)
        with self.assertRaisesRegex(runtime.RuntimeLeaseError, "stale"):
            self.service.complete_observation("COMPLETE_OLD", claim, old_result)

    def test_export_restore_reopen_and_corruption_fail_closed(self) -> None:
        session_id, head = self._open("SYNTHETIC_SESSION_EXPORT")
        self.service.run_observation("OBS_EXPORT", session_id, expected_head=head, evaluator=self.evaluator)
        exported = self.service.export_bytes()
        restored_path = Path(self.temporary.name) / "restored.db"
        restored = runtime.restore_export(restored_path, exported, profile=self.profile, clock=self.clock)
        self.assertEqual(restored.export_bytes(), exported)
        for mutated in (exported[:-1], exported.replace(b"runtime-export", b"runtime-mutated", 1)):
            with self.assertRaises(runtime.RuntimeIntegrityError):
                runtime.restore_export(Path(self.temporary.name) / ("bad-" + str(len(mutated)) + ".db"), mutated, profile=self.profile, clock=self.clock)

    def test_fault_before_commit_rolls_back_to_empty_state(self) -> None:
        faulted_path = Path(self.temporary.name) / "faulted.db"

        def inject(point: str) -> None:
            if point == "after_transition_insert":
                raise runtime.RuntimeInjectedFault("runtime:test-before-commit")

        faulted = runtime.ControlledShadowRuntimeService(faulted_path, profile=self.profile, clock=self.clock, fault_injector=inject)
        with self.assertRaises(runtime.RuntimeInjectedFault):
            faulted.create_session("OPEN_FAULT", "SYNTHETIC_SESSION_FAULT", self.bundle, self.authorization)
        self.assertEqual(faulted.integrity()["session_count"], 0)
        self.assertEqual(faulted.integrity()["transition_count"], 0)

    def test_profile_or_upstream_mutation_is_rejected_before_sqlite_mutation(self) -> None:
        before = self.service.export_bytes()
        mutated = self.bundle.snapshot()
        mutated["quarantine_raw"] = bytes(mutated["quarantine_raw"]) + b"x"
        bad_bundle = runtime.RuntimeUpstreamBundleV1(**mutated)
        with self.assertRaises(runtime.RuntimeAuthorizationError):
            self.service.create_session("OPEN_BAD_BUNDLE", "SYNTHETIC_SESSION_BAD", bad_bundle, self.authorization)
        self.assertEqual(self.service.export_bytes(), before)

        class ExternalFixtureMistake(fixtures.SyntheticAuthorizationVerifier):
            mode = independent.MODE_EXTERNAL

        with self.assertRaisesRegex(runtime.RuntimeAuthorizationError, "external-verifier-fixture"):
            self.service.create_session("OPEN_BAD_AUTH", "SYNTHETIC_SESSION_BAD_AUTH", self.bundle, ExternalFixtureMistake())
        self.assertEqual(self.service.export_bytes(), before)

    def test_support_is_aggregate_only_and_flags_cannot_escalate(self) -> None:
        session_id, head = self._open("SYNTHETIC_SESSION_SUPPORT")
        self.service.run_observation("OBS_SUPPORT", session_id, expected_head=head, evaluator=self.evaluator)
        support = json.dumps(self.service.support_snapshot(), sort_keys=True)
        for forbidden in ("synthetic-shadow-capture", "SYNTHETIC_SESSION_SUPPORT", "provider", "patient", "member", "claim", "http://", "https://"):
            self.assertNotIn(forbidden.lower(), support.lower())
        self.assertNotIn("CLEAR", support)
        self.assertFalse(self.service.support_snapshot()["flags"]["payment_authority"])

    def test_two_concurrent_distinct_sessions_are_independent(self) -> None:
        services = [self.service, runtime.ControlledShadowRuntimeService(Path(self.temporary.name) / "runtime.db", profile=self.profile, clock=self.clock)]
        barrier = threading.Barrier(2)
        outcomes: list[object] = []

        def worker(index: int) -> None:
            try:
                barrier.wait(timeout=5)
                outcomes.append(services[index].create_session(f"OPEN_CONCURRENT_{index}", f"SYNTHETIC_SESSION_{index}", self.bundle, self.authorization))
            except Exception as exc:  # pragma: no cover - surfaced by assertions below
                outcomes.append(exc)

        threads = [threading.Thread(target=worker, args=(index,)) for index in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertEqual(len(outcomes), 2)
        self.assertTrue(all(isinstance(item, dict) for item in outcomes), outcomes)
        self.assertEqual(self.service.integrity()["session_count"], 2)

    def test_worker_capacity_and_session_capacity_are_bounded_without_mutation(self) -> None:
        first_id, first_head = self._open("SYNTHETIC_SESSION_WORKER_ONE")
        second_id, second_head = self._open("SYNTHETIC_SESSION_WORKER_TWO")
        third_id, third_head = self._open("SYNTHETIC_SESSION_WORKER_THREE")
        first_claim = self.service.claim_observation("CLAIM_WORKER_ONE", first_id, expected_head=first_head)
        self.service.claim_observation("CLAIM_WORKER_TWO", second_id, expected_head=second_head)
        before = self.service.export_bytes()
        with self.assertRaisesRegex(runtime.RuntimeBusyError, "worker-capacity"):
            self.service.claim_observation("CLAIM_WORKER_THREE", third_id, expected_head=third_head)
        self.assertEqual(self.service.export_bytes(), before)
        self.assertEqual(first_claim.slot_number, 0)

    def test_invalid_typed_evaluator_result_pauses_and_is_not_admitted(self) -> None:
        session_id, head = self._open("SYNTHETIC_SESSION_BAD_RESULT")

        class FalsePhiEvaluator:
            evaluator_id = "SYNTHETIC_SHADOW_EVALUATOR_V1"
            evaluator_epoch = 1

            def evaluate(inner_self, input_raw: bytes) -> runtime.VerifiedShadowEvaluationV1:
                valid = self.evaluator.evaluate(input_raw)
                body = replace(valid, zero_phi=False, result_digest="").material()
                return replace(valid, zero_phi=False, result_digest=independent._digest("evaluation-result", body))

        result = self.service.run_observation("OBS_BAD_RESULT", session_id, expected_head=head, evaluator=FalsePhiEvaluator())
        self.assertEqual(result["state"], independent.STATE_PAUSED)
        self.assertEqual(result["receipt"]["details"]["failure_code"], "EVALUATOR_INVALID")
        self.assertEqual(self.service.integrity()["discrepancy_count"], 0)

    def test_authority_expiry_blocks_resume_without_state_change(self) -> None:
        session_id, head = self._open("SYNTHETIC_SESSION_EXPIRY")
        paused = self.service.pause_session("PAUSE_EXPIRY", session_id, expected_head=head, reason="MANUAL_PAUSE")
        self.clock.advance(self.profile.authorization_effective_end - self.clock.now() + 1)
        before = self.service.export_bytes()
        with self.assertRaisesRegex(runtime.RuntimeConflictError, "authority-expired"):
            self.service.resume_session("RESUME_EXPIRED", session_id, expected_head=paused["head_root"])
        self.assertEqual(self.service.export_bytes(), before)

    def test_completion_requirements_fail_closed_before_minimum_observations(self) -> None:
        session_id, head = self._open("SYNTHETIC_SESSION_REQUIREMENTS")
        before = self.service.export_bytes()
        with self.assertRaisesRegex(runtime.RuntimeConflictError, "completion-requirements"):
            self.service.complete_session("COMPLETE_EMPTY", session_id, expected_head=head)
        self.assertEqual(self.service.export_bytes(), before)
        first = self.service.run_observation("OBS_REQUIREMENT_ONE", session_id, expected_head=head, evaluator=self.evaluator)
        before = self.service.export_bytes()
        with self.assertRaisesRegex(runtime.RuntimeConflictError, "completion-requirements"):
            self.service.complete_session("COMPLETE_ONE", session_id, expected_head=first["head_root"])
        self.assertEqual(self.service.export_bytes(), before)

    def test_wrong_result_binding_and_stale_completion_leave_lease_state_unchanged(self) -> None:
        session_id, head = self._open("SYNTHETIC_SESSION_STALE")
        claim = self.service.claim_observation("CLAIM_STALE", session_id, expected_head=head)
        valid = self.evaluator.evaluate(claim.input_raw)
        bad_body = replace(valid, input_digest=_hex("wrong-input"), result_digest="").material()
        bad = replace(valid, input_digest=_hex("wrong-input"), result_digest=independent._digest("evaluation-result", bad_body))
        before = self.service.export_bytes()
        with self.assertRaisesRegex(runtime.RuntimeIntegrityError, "evaluation-binding"):
            self.service.complete_observation("COMPLETE_WRONG_RESULT", claim, bad)
        self.assertEqual(self.service.export_bytes(), before)
        paused = self.service.pause_session("PAUSE_STALE", session_id, expected_head=claim.head_root, reason="MANUAL_PAUSE")
        before = self.service.export_bytes()
        with self.assertRaisesRegex(runtime.RuntimeLeaseError, "stale-head"):
            self.service.complete_observation("COMPLETE_STALE", claim, valid)
        self.assertEqual(self.service.export_bytes(), before)
        self.assertEqual(paused["state"], independent.STATE_PAUSED)

    def test_external_mode_has_no_fixture_promotion_path(self) -> None:
        class UnimplementedExternalVerifier(fixtures.SyntheticAuthorizationVerifier):
            mode = independent.MODE_EXTERNAL
            fixture_only = False

        before = self.service.export_bytes()
        with self.assertRaisesRegex(runtime.RuntimeAuthorizationError, "authorization-authenticated"):
            self.service.create_session("OPEN_EXTERNAL_UNIMPLEMENTED", "SYNTHETIC_SESSION_EXTERNAL", self.bundle, UnimplementedExternalVerifier())
        self.assertEqual(self.service.export_bytes(), before)

    def test_upstream_withdrawal_rebinding_and_verifier_identity_fail_closed(self) -> None:
        mutations = {
            "withdrawn-head": lambda value: value.update(quarantine_head={**value["quarantine_head"], "state": "WITHDRAWN"}),
            "governance-bytes": lambda value: value.update(governance_raw=bytes(value["governance_raw"]) + b"x"),
            "privacy-bytes": lambda value: value.update(privacy_raw=bytes(value["privacy_raw"]) + b"x"),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                snapshot = self.bundle.snapshot()
                mutate(snapshot)
                before = self.service.export_bytes()
                with self.assertRaises(runtime.RuntimeAuthorizationError):
                    self.service.create_session("OPEN_MUTATION_" + label, "SYNTHETIC_SESSION_MUTATION_" + label, runtime.RuntimeUpstreamBundleV1(**snapshot), self.authorization)
                self.assertEqual(self.service.export_bytes(), before)

        class WrongIdentityVerifier(fixtures.SyntheticAuthorizationVerifier):
            verifier_id = "SYNTHETIC_WRONG_AUTHORIZER_V1"

        before = self.service.export_bytes()
        with self.assertRaisesRegex(runtime.RuntimeAuthorizationError, "authorization-verifier"):
            self.service.create_session("OPEN_WRONG_VERIFIER", "SYNTHETIC_SESSION_WRONG_VERIFIER", self.bundle, WrongIdentityVerifier())
        self.assertEqual(self.service.export_bytes(), before)

    def test_concurrent_slot_claims_have_one_winner_and_no_overlap(self) -> None:
        session_id, head = self._open("SYNTHETIC_SESSION_SLOT_RACE")
        contender = runtime.ControlledShadowRuntimeService(self.runtime_db, profile=self.profile, clock=self.clock)
        barrier = threading.Barrier(2)
        outcomes: list[object] = []

        def worker(service: runtime.ControlledShadowRuntimeService, operation_id: str) -> None:
            try:
                barrier.wait(timeout=5)
                outcomes.append(service.claim_observation(operation_id, session_id, expected_head=head))
            except Exception as exc:  # pragma: no cover - asserted below
                outcomes.append(exc)

        threads = [
            threading.Thread(target=worker, args=(self.service, "CLAIM_RACE_A")),
            threading.Thread(target=worker, args=(contender, "CLAIM_RACE_B")),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertEqual(len(outcomes), 2)
        self.assertEqual(sum(isinstance(item, runtime.ObservationClaim) for item in outcomes), 1)
        self.assertEqual(sum(isinstance(item, (runtime.RuntimeBusyError, runtime.RuntimeConflictError)) for item in outcomes), 1)
        self.assertEqual(self.service.integrity()["slot_count"], 1)

    def test_evaluator_type_oversize_and_indeterminate_results_are_bounded(self) -> None:
        cases = ("wrong-type", "oversize", "indeterminate")
        for label in cases:
            with self.subTest(label=label):
                path = Path(self.temporary.name) / ("evaluator-" + label + ".db")
                service = runtime.ControlledShadowRuntimeService(path, profile=self.profile, clock=self.clock)
                opened = service.create_session("OPEN_EVALUATOR_" + label, "SYNTHETIC_EVALUATOR_" + label, self.bundle, self.authorization)
                started = service.start_session("START_EVALUATOR_" + label, opened["session_id"], expected_head=opened["head_root"])
                if label == "wrong-type":
                    class WrongTypeEvaluator:
                        evaluator_id = "SYNTHETIC_SHADOW_EVALUATOR_V1"
                        evaluator_epoch = 1

                        def evaluate(inner_self, input_raw: bytes) -> object:
                            return {"result": "PARITY"}

                    result = service.run_observation("OBS_EVALUATOR_" + label, started["session_id"], expected_head=started["head_root"], evaluator=WrongTypeEvaluator())
                    self.assertEqual(result["receipt"]["details"]["failure_code"], "EVALUATOR_INVALID")
                    self.assertEqual(result["state"], independent.STATE_PAUSED)
                elif label == "oversize":
                    class OversizeEvaluator:
                        evaluator_id = "SYNTHETIC_SHADOW_EVALUATOR_V1"
                        evaluator_epoch = 1

                        def evaluate(inner_self, input_raw: bytes) -> runtime.VerifiedShadowEvaluationV1:
                            valid = self.evaluator.evaluate(input_raw)
                            aggregate = {"evaluated": 1_000_001, "matched": 1_000_001, "differing": 0, "unknown": 0}
                            body = replace(valid, aggregate=aggregate, result_digest="").material()
                            return replace(valid, aggregate=aggregate, result_digest=independent._digest("evaluation-result", body))

                    result = service.run_observation("OBS_EVALUATOR_" + label, started["session_id"], expected_head=started["head_root"], evaluator=OversizeEvaluator())
                    self.assertEqual(result["receipt"]["details"]["failure_code"], "EVALUATOR_INVALID")
                    self.assertEqual(result["state"], independent.STATE_PAUSED)
                else:
                    evaluator = fixtures.SyntheticShadowEvaluator(self.clock, results={0: "INDETERMINATE"})
                    result = service.run_observation("OBS_EVALUATOR_" + label, started["session_id"], expected_head=started["head_root"], evaluator=evaluator)
                    self.assertEqual(result["receipt"]["details"]["result"], "INDETERMINATE")
                    self.assertEqual(result["state"], independent.STATE_RUNNING)

    def test_session_capacity_is_profile_owned_and_fail_closed(self) -> None:
        limited_profile = replace(self.profile, max_sessions=1)
        limited_path = Path(self.temporary.name) / "limited-sessions.db"
        limited = runtime.ControlledShadowRuntimeService(limited_path, profile=limited_profile, clock=self.clock)
        limited.create_session("OPEN_LIMIT_ONE", "SYNTHETIC_LIMIT_ONE", self.bundle, self.authorization)
        before = limited.export_bytes()
        with self.assertRaisesRegex(runtime.RuntimeConflictError, "session-capacity"):
            limited.create_session("OPEN_LIMIT_TWO", "SYNTHETIC_LIMIT_TWO", self.bundle, self.authorization)
        self.assertEqual(limited.export_bytes(), before)

    def test_restore_profile_drift_and_receipt_tamper_fail_independently(self) -> None:
        session_id, head = self._open("SYNTHETIC_SESSION_TAMPER")
        self.service.run_observation("OBS_TAMPER", session_id, expected_head=head, evaluator=self.evaluator)
        exported = self.service.export_bytes()
        drifted = replace(self.profile, evaluator_epoch=2)
        with self.assertRaises(runtime.RuntimeIntegrityError):
            runtime.restore_export(Path(self.temporary.name) / "drifted.db", exported, profile=drifted, clock=self.clock)
        connection = sqlite3.connect(self.runtime_db)
        try:
            connection.execute("UPDATE runtime_operations SET receipt_raw=? WHERE operation_id=?", (b"{}", "OBS_TAMPER"))
            connection.commit()
        finally:
            connection.close()
        with self.assertRaisesRegex(runtime.RuntimeIntegrityError, "operation-digest"):
            self.service.integrity()

    def test_bounded_synthetic_end_to_end_exercise_emits_aggregate_evidence(self) -> None:
        session_id, head = self._open("SYNTHETIC_SESSION_EXERCISE")
        paused = self.service.pause_session("EXERCISE_PAUSE", session_id, expected_head=head, reason="MANUAL_PAUSE")
        resumed = self.service.resume_session("EXERCISE_RESUME", session_id, expected_head=paused["head_root"])

        before_fault = self.service.export_bytes()
        def precommit_fault(point: str) -> None:
            if point == "after_transition_insert":
                raise runtime.RuntimeInjectedFault("runtime:exercise-precommit")

        self.service.fault_injector = precommit_fault
        with self.assertRaises(runtime.RuntimeInjectedFault):
            self.service.claim_observation("EXERCISE_FAULT", session_id, expected_head=resumed["head_root"])
        self.service.fault_injector = None
        self.assertEqual(self.service.export_bytes(), before_fault)

        response_loss = {"done": False}
        def lose_one_response(point: str) -> None:
            if point == "after_commit_before_response" and not response_loss["done"]:
                response_loss["done"] = True
                raise runtime.RuntimeInjectedFault("runtime:exercise-response-loss")

        self.service.fault_injector = lose_one_response
        with self.assertRaises(runtime.RuntimeResponseLost):
            self.service.run_observation("EXERCISE_OBS_ONE", session_id, expected_head=resumed["head_root"], evaluator=self.evaluator)
        self.service.fault_injector = None
        first = self.service.run_observation("EXERCISE_OBS_ONE", session_id, expected_head=resumed["head_root"], evaluator=self.evaluator)
        self.clock.advance(self.profile.cadence_seconds)
        second = self.service.run_observation("EXERCISE_OBS_TWO", session_id, expected_head=first["head_root"], evaluator=self.evaluator)
        completed = self.service.complete_session("EXERCISE_COMPLETE", session_id, expected_head=second["head_root"])

        reopened = runtime.ControlledShadowRuntimeService(self.runtime_db, profile=self.profile, clock=self.clock)
        reopened_evidence = reopened.integrity()
        exported = reopened.export_bytes()
        restored_path = Path(self.temporary.name) / "exercise-restored.db"
        restored = runtime.restore_export(restored_path, exported, profile=self.profile, clock=self.clock)
        restored_evidence = restored.integrity()
        self.assertEqual(reopened_evidence, restored_evidence)
        self.assertEqual(independent.verify_export_bytes(exported, profile=self.profile.material())["accepted"], True)
        self.assertEqual(completed["state"], independent.STATE_COMPLETED)
        source = Path("app/mirror/controlled_shadow_runtime.py").read_text(encoding="utf-8")
        self.assertNotIn("continuity_store", source.lower())
        self.assertNotIn("provider_trust_graph", source.lower())
        self.assertNotIn("discrepancy_case", source.lower())

        evidence = {
            "schema": "mirror-controlled-shadow-runtime-exercise-v1",
            "claim": "SYNTHETIC_SOFTWARE_ONLY",
            "state": completed["state"],
            "transition_count": reopened_evidence["transition_count"],
            "operation_count": reopened_evidence["operation_count"],
            "slot_count": reopened_evidence["slot_count"],
            "discrepancy_count": reopened_evidence["discrepancy_count"],
            "state_counts": reopened_evidence["state_counts"],
            "result_counts": reopened_evidence["result_counts"],
            "pause_resume_count": 1,
            "precommit_rollback_count": 1,
            "postcommit_response_loss_recovery_count": 1,
            "restart_reconstruction_count": 1,
            "export_restore_reconstruction_count": 1,
            "external_authorization": False,
            "controlled_shadow_ready": False,
            "production_usable": False,
            "activation": False,
            "payment_authority": False,
            "clearance_authority": False,
            "settlement_authority": False,
            "proofSuiteId": None,
        }
        evidence_raw = _canonical(evidence)
        self.assertLessEqual(len(evidence_raw), 16_384)
        self.assertNotIn(b"SYNTHETIC_SESSION", evidence_raw)
        self.assertNotIn(b"exercise-restored", evidence_raw)
        print("EVIDENCE_JSON=" + evidence_raw.decode("ascii"))

    def test_qualification_claim_and_runtime_flags_remain_nonactivating(self) -> None:
        self.assertEqual(self.profile.scope, runtime.SCOPE)
        self.assertFalse(self.profile.production_usable)
        self.assertFalse(self.profile.activation)
        self.assertIsNone(self.profile.proofSuiteId)
        self.assertNotIn("APPROVED", runtime.__dict__)
        self.assertNotIn("CLEAR", runtime.__dict__)


if __name__ == "__main__":
    unittest.main()
