"""Focused synthetic tests for authenticated shadow admission supervision."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest

from app.mirror import authenticated_shadow_admission as admission
from app.mirror import authenticated_shadow_admission_independent as admission_independent
from app.mirror import authenticated_source_acquisition as acquisition
from app.mirror import controlled_shadow_runtime as runtime
from app.mirror import controlled_shadow_runtime_fixtures as runtime_fixtures
from app.mirror import external_governance_approval as governance
from app.mirror import external_privacy_support_approval as privacy
from app.mirror import external_source_adapter as source_adapter
from app.mirror import external_source_quarantine as quarantine
from app.mirror import external_source_adapter_independent as source_adapter_independent
from app.mirror import nc_medicaid_fhir_profile as nc_profile
from tests.test_mirror_authenticated_source_acquisition import _AuthenticatedFixtureTransport, _policy as nc_policy
from tests.test_mirror_external_source_adapter import _FixtureVerifier as SourceVerifier
from tests.test_mirror_external_governance_approval import _FixtureVerifier as GovernanceVerifier, _policy as governance_policy
from tests.test_mirror_external_privacy_support_approval import _FixtureVerifier as PrivacyVerifier, _policy as privacy_policy


def _sha(raw: bytes) -> str:
    return hashlib.sha3_512(raw).hexdigest()


class AuthenticatedShadowAdmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.source_policy = nc_policy()
        self.quarantine_database_id = "SYNTH_ADMISSION_QUARANTINE_DB_V1"
        self.quarantine = quarantine.ExternalSourceQuarantineService(
            root / "quarantine.db", policy=self.source_policy, database_id=self.quarantine_database_id,
        )
        self.acquisition_config = acquisition.AuthenticatedSourceAcquisitionConfigV1(
            acquisition_id="SYNTH_ADMISSION_ACQUISITION_V1",
            version=1,
            nc_profile_digest=nc_profile.NC_MEDICAID_PROFILE.profile_digest,
            external_policy_digest=self.source_policy.digest,
            quarantine_policy_digest=self.quarantine.policy_digest,
            quarantine_chain_id=self.quarantine.chain_id,
            quarantine_database_id=self.quarantine_database_id,
            transport_id=_AuthenticatedFixtureTransport.transport_id,
            transport_epoch=1,
            authorization_artifact_digest=self.source_policy.authorization_artifact_digest,
            terms_artifact_digest=self.source_policy.terms_artifact_digest,
            endpoint_id=self.source_policy.logical_endpoint_id,
            request_digest=acquisition.request_digest_for_profile(),
            effective_start=self.source_policy.effective_start,
            effective_end=self.source_policy.effective_end,
            expected_server_identity_digest=source_adapter_independent._digest("server-identity", self.source_policy.logical_endpoint_id),
            cadence_seconds=600,
            freshness_grace_seconds=60,
            max_body_bytes=nc_profile.TRANSPORT_CAPS["max_page_bytes"],
            max_page_count=nc_profile.TRANSPORT_CAPS["max_pages"],
            max_attempts=3,
            lease_seconds=60,
            busy_timeout_ms=500,
            max_slots=16,
        )
        self.acquisition = acquisition.AuthenticatedSourceAcquisitionService(
            root / "acquisition.db", config=self.acquisition_config, external_policy=self.source_policy,
            quarantine_service=self.quarantine, clock=lambda: 7_000,
        )
        created = self.acquisition.ensure_slot(7_000)
        lease = self.acquisition.claim_next(7_000)
        self.assertIsNotNone(lease)
        result = self.acquisition.acquire(lease, _AuthenticatedFixtureTransport(self.source_policy))  # type: ignore[arg-type]
        self.assertEqual("QUARANTINED", result["state"])
        self.slot_id = str(created["slot_id"])
        self.view = self.acquisition.qualification_view(self.slot_id)

        self.governance_evidence = b"synthetic-admission-governance"
        self.governance_policy = governance_policy(
            source_policy_digest=self.source_policy.digest,
            quarantine_policy_digest=self.quarantine.policy_digest,
            quarantine_artifact_id=self.view.artifact_id,
            quarantine_head_artifact_id=self.view.quarantine_head_artifact_id,
            quarantine_head_root=self.view.quarantine_head_root,
        )
        self.governance_artifact = governance.ExternalGovernanceApprovalService(
            self.governance_policy, GovernanceVerifier(self.governance_policy),
        ).observe(self.governance_evidence)

        self.privacy_evidence = b"synthetic-admission-privacy"
        self.privacy_policy = privacy_policy(
            source_policy_digest=self.source_policy.digest,
            quarantine_policy_digest=self.quarantine.policy_digest,
            quarantine_artifact_id=self.view.artifact_id,
            quarantine_head_artifact_id=self.view.quarantine_head_artifact_id,
            quarantine_head_root=self.view.quarantine_head_root,
            governance_observation_artifact_id=self.governance_artifact.artifact_id,
            governance_evidence_digest=_sha(self.governance_evidence),
            governance_decision=self.governance_artifact.decision,
            terms_digest=self.governance_policy.terms_digest,
            retention_policy_digest=self.governance_policy.retention_policy_digest,
        )
        self.privacy_artifact = privacy.ExternalPrivacySupportApprovalService(
            self.privacy_policy, PrivacyVerifier(self.privacy_policy),
        ).observe(self.privacy_evidence)

        self.clock = runtime_fixtures.SyntheticClock(value=1_200)
        self.admission_clock = lambda: self.clock.now()
        self.authorization = runtime_fixtures.SyntheticAuthorizationVerifier()
        self.profile = runtime.ControlledShadowRuntimeProfileV1(
            profile_id="SYNTHETIC_ADMISSION_RUNTIME_V1",
            version=1,
            runtime_id_domain="SYNTHETIC_ADMISSION_RUNTIME_DOMAIN_V1",
            source_policy_digest=self.source_policy.digest,
            quarantine_policy_digest=self.quarantine.policy_digest,
            quarantine_artifact_id=self.view.artifact_id,
            quarantine_head_artifact_id=self.view.quarantine_head_artifact_id,
            quarantine_head_root=self.view.quarantine_head_root,
            governance_policy_digest=self.governance_policy.digest,
            governance_artifact_id=self.governance_artifact.artifact_id,
            governance_evidence_digest=_sha(self.governance_evidence),
            governance_decision=self.governance_artifact.decision,
            privacy_policy_digest=self.privacy_policy.digest,
            privacy_artifact_id=self.privacy_artifact.artifact_id,
            privacy_evidence_digest=_sha(self.privacy_evidence),
            privacy_decision="GRANTED",
            support_decision="GRANTED",
            authorization_verifier_id=self.authorization.verifier_id,
            authorization_verifier_epoch=self.authorization.verifier_epoch,
            evaluator_id="SYNTHETIC_ADMISSION_EVALUATOR_V1",
            evaluator_epoch=1,
        )
        self.runtime = runtime.ControlledShadowRuntimeService(
            root / "runtime.db", profile=self.profile, clock=self.clock,
        )
        self.runtime_database_id = "SYNTH_ADMISSION_RUNTIME_DB_V1"
        self.config = admission.AuthenticatedShadowAdmissionConfigV1(
            admission_ledger_id="SYNTHETIC_ADMISSION_LEDGER_V1",
            version=1,
            acquisition_id=self.acquisition_config.acquisition_id,
            acquisition_config_digest=self.acquisition_config.digest,
            acquisition_database_id=acquisition_independent_chain(self.acquisition_config.digest),
            acquisition_profile_digest=nc_profile.NC_MEDICAID_PROFILE.profile_digest,
            source_policy_digest=self.source_policy.digest,
            quarantine_database_id=self.quarantine.database_id,
            quarantine_policy_digest=self.quarantine.policy_digest,
            quarantine_chain_id=self.quarantine.chain_id,
            governance_policy_digest=self.governance_policy.digest,
            governance_verifier_id=self.governance_policy.verifier_id,
            governance_verifier_epoch=self.governance_policy.verifier_epoch,
            privacy_policy_digest=self.privacy_policy.digest,
            privacy_verifier_id=self.privacy_policy.verifier_id,
            privacy_verifier_epoch=self.privacy_policy.verifier_epoch,
            runtime_profile_digest=self.profile.digest,
            runtime_database_id=self.runtime_database_id,
            cadence_seconds=600,
            freshness_grace_seconds=60,
            lease_seconds=60,
            max_admissions=16,
            max_attempts=3,
            busy_timeout_ms=500,
        )
        self.service = admission.AuthenticatedShadowAdmissionService(
            root / "admission.db", config=self.config, acquisition_service=self.acquisition,
            runtime_service=self.runtime, runtime_database_id=self.runtime_database_id,
            authorization_verifier=self.authorization, clock=self.admission_clock,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _approval_args(self) -> dict[str, object]:
        return {
            "governance_policy": self.governance_policy,
            "governance_raw": self.governance_artifact.raw,
            "governance_evidence_raw": self.governance_evidence,
            "privacy_policy": self.privacy_policy,
            "privacy_raw": self.privacy_artifact.raw,
            "privacy_evidence_raw": self.privacy_evidence,
        }

    def test_qualification_view_is_current_head_bound_and_support_safe(self) -> None:
        view = self.acquisition.qualification_view(self.slot_id)
        self.assertEqual(view.artifact_id, view.quarantine_head_artifact_id)
        self.assertEqual(view.quarantine_head_root, self.view.quarantine_head_root)
        self.assertTrue(view.flags["observation_only"])
        self.assertFalse(view.flags["production_usable"])
        self.assertNotIn(view.artifact_id, json.dumps(view.support_material(), sort_keys=True))

    def test_happy_admission_opens_and_starts_exactly_one_runtime_session(self) -> None:
        qualified = self.service.qualify("QUALIFY", self.slot_id, **self._approval_args())
        self.assertEqual("QUALIFIED", qualified["state"])
        opened = self.service.open("OPEN", qualified["admission_id"], **self._approval_args())
        started = self.service.start("START", qualified["admission_id"], **self._approval_args())
        self.assertEqual("OPENED", opened["state"])
        self.assertEqual("STARTED", started["state"])
        self.assertEqual(1, self.runtime.integrity()["session_count"])
        evidence = admission_independent.verify_database(self.service.database, config=self.config.material())
        self.assertEqual(1, evidence["admission_count"])
        self.assertFalse(self.service.support_snapshot()["controlled_shadow_ready"])
        self.assertFalse(self.service.support_snapshot()["production_usable"])

    def test_exact_retry_returns_the_same_receipt_without_a_second_session(self) -> None:
        first = self.service.qualify("QUALIFY", self.slot_id, **self._approval_args())
        retry = self.service.qualify("QUALIFY", self.slot_id, **self._approval_args())
        self.assertEqual(first["receipt_raw"], retry["receipt_raw"])
        opened = self.service.open("OPEN", first["admission_id"], **self._approval_args())
        opened_retry = self.service.open("OPEN", first["admission_id"], **self._approval_args())
        self.assertEqual(opened["receipt_raw"], opened_retry["receipt_raw"])
        self.assertEqual(1, self.runtime.integrity()["session_count"])

    def test_two_identical_qualification_writers_converge_and_conflicting_key_fails_closed(self) -> None:
        contender = admission.AuthenticatedShadowAdmissionService(
            self.service.database, config=self.config, acquisition_service=self.acquisition,
            runtime_service=self.runtime, runtime_database_id=self.runtime_database_id,
            authorization_verifier=self.authorization, clock=self.admission_clock,
        )
        barrier = threading.Barrier(2)
        outcomes: list[object] = []

        def identical_worker(service: admission.AuthenticatedShadowAdmissionService) -> None:
            barrier.wait()
            try:
                outcomes.append(service.qualify("SAME", self.slot_id, **self._approval_args()))
            except Exception as exc:  # test records every concurrent result
                outcomes.append(exc)

        threads = [threading.Thread(target=identical_worker, args=(service,)) for service in (self.service, contender)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)
        self.assertEqual(2, len(outcomes), outcomes)
        self.assertTrue(all(isinstance(item, dict) for item in outcomes), outcomes)
        self.assertEqual(outcomes[0]["receipt_raw"], outcomes[1]["receipt_raw"])  # type: ignore[index]
        self.assertEqual(1, self.service.integrity()["admission_count"])

        with self.assertRaises(admission.ShadowAdmissionConflictError):
            contender.qualify("CONFLICT", self.slot_id, **self._approval_args())
        self.assertEqual(1, self.service.integrity()["admission_count"])

    def test_runtime_response_loss_reconciles_one_session_and_exact_retry(self) -> None:
        qualified = self.service.qualify("QUALIFY", self.slot_id, **self._approval_args())
        faulted = {"done": False}

        def inject(point: str) -> None:
            if point == "after_commit_before_response" and not faulted["done"]:
                faulted["done"] = True
                raise runtime.RuntimeInjectedFault("runtime:fixture-response-loss")

        self.runtime.fault_injector = inject
        opened = self.service.open("OPEN", qualified["admission_id"], **self._approval_args())
        self.assertTrue(faulted["done"])
        self.assertEqual("OPENED", opened["state"])
        self.runtime.fault_injector = None
        retry = self.service.open("OPEN", qualified["admission_id"], **self._approval_args())
        self.assertEqual(opened["receipt_raw"], retry["receipt_raw"])
        self.assertEqual(1, self.runtime.integrity()["session_count"])

    def test_two_exact_open_writers_converge_to_one_runtime_session(self) -> None:
        qualified = self.service.qualify("QUALIFY", self.slot_id, **self._approval_args())
        contender = admission.AuthenticatedShadowAdmissionService(
            self.service.database, config=self.config, acquisition_service=self.acquisition,
            runtime_service=self.runtime, runtime_database_id=self.runtime_database_id,
            authorization_verifier=self.authorization, clock=self.admission_clock,
        )
        barrier = threading.Barrier(2)
        outcomes: list[object] = []

        def worker(service: admission.AuthenticatedShadowAdmissionService) -> None:
            barrier.wait()
            try:
                outcomes.append(service.open("OPEN", qualified["admission_id"], **self._approval_args()))
            except Exception as exc:  # test records every concurrent result
                outcomes.append(exc)

        threads = [threading.Thread(target=worker, args=(service,)) for service in (self.service, contender)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)
        self.assertEqual(2, len(outcomes), outcomes)
        self.assertTrue(all(isinstance(item, dict) for item in outcomes), outcomes)
        self.assertEqual("OPENED", outcomes[0]["state"])  # type: ignore[index]
        self.assertEqual(outcomes[0]["receipt_raw"], outcomes[1]["receipt_raw"])  # type: ignore[index]
        self.assertEqual(1, self.runtime.integrity()["session_count"])

    def test_admission_commit_fault_rolls_back_and_postcommit_loss_retries_exactly(self) -> None:
        faults = {"before": True, "after": True}

        def inject(point: str) -> None:
            if point == "before_commit" and faults["before"]:
                faults["before"] = False
                raise admission.ShadowAdmissionInjectedFault("admission:fixture-fault")
            if point == "after_commit_before_response" and faults["after"]:
                faults["after"] = False
                raise admission.ShadowAdmissionInjectedFault("admission:fixture-response-loss")

        self.service.fault_injector = inject
        with self.assertRaises(admission.ShadowAdmissionInjectedFault):
            self.service.qualify("FAULT", self.slot_id, **self._approval_args())
        self.assertEqual(0, self.service.integrity()["admission_count"])
        with self.assertRaises(admission.ShadowAdmissionResponseLost):
            self.service.qualify("FAULT", self.slot_id, **self._approval_args())
        self.service.fault_injector = None
        retry = self.service.qualify("FAULT", self.slot_id, **self._approval_args())
        self.assertEqual("QUALIFIED", retry["state"])
        self.assertEqual(1, self.service.integrity()["admission_count"])

    def test_start_response_loss_reconciles_without_duplicate_runtime_operation(self) -> None:
        qualified = self.service.qualify("QUALIFY", self.slot_id, **self._approval_args())
        opened = self.service.open("OPEN", qualified["admission_id"], **self._approval_args())
        faulted = {"done": False}

        def inject(point: str) -> None:
            if point == "after_commit_before_response" and not faulted["done"]:
                faulted["done"] = True
                raise runtime.RuntimeInjectedFault("runtime:fixture-start-response-loss")

        self.runtime.fault_injector = inject
        started = self.service.start("START", qualified["admission_id"], **self._approval_args())
        self.runtime.fault_injector = None
        self.assertTrue(faulted["done"])
        self.assertEqual("STARTED", started["state"])
        retry = self.service.start("START", qualified["admission_id"], **self._approval_args())
        self.assertEqual(started["receipt_raw"], retry["receipt_raw"])
        self.assertEqual(1, self.runtime.integrity()["session_count"])

    def test_candidate_rebinding_and_forbidden_flags_fail_independent_reconstruction(self) -> None:
        qualified = self.service.qualify("QUALIFY", self.slot_id, **self._approval_args())
        self.assertEqual("QUALIFIED", qualified["state"])
        connection = sqlite3.connect(self.service.database)
        try:
            connection.execute("UPDATE admission_candidates SET state=? WHERE admission_id=?", ("STARTED", qualified["admission_id"]))
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(admission_independent.IndependentAuthenticatedShadowAdmissionError):
            admission_independent.verify_database(self.service.database, config=self.config.material())

    def test_denied_approval_fails_before_any_admission_or_runtime_mutation(self) -> None:
        denied = governance.ExternalGovernanceApprovalService(
            self.governance_policy, GovernanceVerifier(self.governance_policy, decision="DENIED"),
        ).observe(self.governance_evidence)
        args = self._approval_args()
        args["governance_raw"] = denied.raw
        with self.assertRaises(admission.ShadowAdmissionAuthorityError):
            self.service.qualify("DENIED", self.slot_id, **args)
        self.assertEqual(0, self.service.integrity()["admission_count"])
        self.assertEqual(0, self.runtime.integrity()["session_count"])

    def test_local_quarantine_supersession_pauses_started_runtime_without_auto_resume(self) -> None:
        qualified = self.service.qualify("QUALIFY", self.slot_id, **self._approval_args())
        self.service.open("OPEN", qualified["admission_id"], **self._approval_args())
        started = self.service.start("START", qualified["admission_id"], **self._approval_args())
        replacement = source_adapter.ExternalSourceAdapterService(
            self.source_policy, SourceVerifier(self.source_policy, observed_at=7_600, fetched_at=7_610),
        ).admit(b"synthetic-admission-supersession")
        current_head = self.quarantine.head()
        self.assertIsNotNone(current_head)
        self.quarantine.admit("SUPERSEDE", replacement.raw, expected_head=str(current_head["head_artifact_id"]))
        with self.assertRaises(acquisition.AcquisitionQualificationError) as caught:
            self.acquisition.qualification_view(self.slot_id)
        self.assertEqual("SOURCE_SUPERSEDED", caught.exception.reason)
        paused = self.service.supervise("PAUSE", qualified["admission_id"], **self._approval_args())
        self.assertEqual("PAUSED", paused["state"])
        self.assertEqual(1, self.runtime.integrity()["session_count"])
        snapshot = admission_independent.snapshot_database(self.service.database, config=self.config.material())
        candidate = snapshot["snapshot"]["admission_candidates"][0]
        self.assertEqual("PAUSED", candidate["state"])
        self.assertEqual("SOURCE_SUPERSEDED", candidate["failure_code"])
        self.assertEqual(started["admission_id"], paused["admission_id"])

    def test_independent_export_restore_and_support_are_nonactivating(self) -> None:
        qualified = self.service.qualify("QUALIFY", self.slot_id, **self._approval_args())
        self.service.open("OPEN", qualified["admission_id"], **self._approval_args())
        exported = self.service.export_bytes()
        restored_path = Path(self.temporary.name) / "restored-admission.db"
        restored = admission.AuthenticatedShadowAdmissionService.restore_export(
            restored_path, exported, config=self.config, acquisition_service=self.acquisition,
            runtime_service=self.runtime, runtime_database_id=self.runtime_database_id,
            authorization_verifier=self.authorization, clock=self.admission_clock, **self._approval_args(),
        )
        self.assertEqual(self.service.export_bytes(), restored.export_bytes())
        support = json.dumps(restored.support_snapshot(), sort_keys=True)
        self.assertNotRegex(support, r"[0-9a-f]{128}")
        self.assertNotIn(str(self.temporary.name), support)
        self.assertFalse(restored.support_snapshot()["production_usable"])

    def test_export_hex_corruption_is_a_stable_independent_rejection(self) -> None:
        qualified = self.service.qualify("QUALIFY", self.slot_id, **self._approval_args())
        self.assertEqual("QUALIFIED", qualified["state"])
        body = json.loads(self.service.export_bytes().decode("ascii"))
        body["operations"][0]["material_hex"] = "zz"
        raw = json.dumps(body, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
        with self.assertRaisesRegex(admission_independent.IndependentAuthenticatedShadowAdmissionError, "admission:export-hex"):
            admission_independent.verify_export_bytes(raw, config=self.config.material())


def acquisition_independent_chain(config_digest: str) -> str:
    from app.mirror import authenticated_source_acquisition_independent as independent
    return independent._chain_id(config_digest)


if __name__ == "__main__":
    unittest.main()
