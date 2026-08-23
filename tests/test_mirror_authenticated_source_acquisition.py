"""Focused synthetic evidence for authenticated-source acquisition."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import threading
import unittest

from app.mirror import authenticated_source_acquisition as acquisition
from app.mirror import authenticated_source_acquisition_independent as independent
from app.mirror import external_source_adapter as adapter
from app.mirror import external_source_adapter_independent as adapter_independent
from app.mirror import external_source_quarantine as quarantine
from app.mirror import nc_medicaid_fhir as fhir
from app.mirror import nc_medicaid_fhir_profile as profile
from tests.test_nc_medicaid_fhir_source import _bundle, _location, _practitioner, _role


def _hex(label: str) -> str:
    return hashlib.sha3_512(label.encode("ascii")).hexdigest()


def _policy() -> adapter.ExternalSourcePolicyV1:
    return adapter.ExternalSourcePolicyV1(
        profile_id=profile.SOURCE_PROFILE_ID,
        version=1,
        subject=profile.SYNTHETIC_SUBJECT,
        scope=profile.SOURCE_PROFILE_ID,
        logical_endpoint_id="SYNTH_NC_MEDICAID_DIRECTORY_ENDPOINT_V1",
        source_roles=("PRACTITIONER", "PRACTITIONER_ROLE_LOCATION"),
        verifier_id=profile.VERIFIER_ID,
        verifier_epoch=profile.VERIFIER_EPOCH,
        authorization_artifact_digest=_hex("nc-authorization-fixture"),
        terms_artifact_digest=_hex("nc-terms-fixture"),
        effective_start=6_000,
        effective_end=9_000,
        expected_cadence_seconds=600,
        freshness_grace_seconds=60,
        max_capture_bytes=524_288,
        max_page_count=4,
    )


class _AuthenticatedFixtureTransport:
    transport_id = "SYNTH_NC_AUTHENTICATED_TRANSPORT_V1"
    transport_epoch = 1

    def __init__(self, policy: adapter.ExternalSourcePolicyV1, *, partial: bool = False, bad_digest: bool = False, bad_server: bool = False, bad_authority: bool = False, redirect: bool = False, authenticated: bool = True, status: int = 200) -> None:
        first = _bundle(0, resources=[_practitioner(), _role()], next_page=not partial)
        second = _bundle(1, resources=[_location()])
        self.bodies = {0: fhir.canonical_json(first), 1: fhir.canonical_json(second)}
        if partial:
            self.bodies.pop(1)
        self.policy = policy
        self.bad_digest = bad_digest
        self.bad_server = bad_server
        self.bad_authority = bad_authority
        self.redirect = redirect
        self.authenticated = authenticated
        self.status = status
        self.calls: list[tuple[int, int]] = []

    def fetch(self, request: acquisition.AuthenticatedFhirRequestV1) -> acquisition.AuthenticatedFhirResponseV1:
        self.calls.append((request.page_index, request.attempt))
        body = self.bodies.get(request.page_index)
        if body is None:
            raise acquisition.AuthenticatedSourceAcquisitionError("acquisition:timeout")
        server = _hex("wrong-server") if self.bad_server else adapter_independent._digest("server-identity", self.policy.logical_endpoint_id)
        authorization = _hex("wrong-authorization") if self.bad_authority else self.policy.authorization_artifact_digest
        material: dict[str, object] = {
            "transport_id": self.transport_id,
            "transport_epoch": self.transport_epoch,
            "page_index": request.page_index,
            "attempt": request.attempt,
            "request_digest": request.request_digest,
            "server_identity_digest": server,
            "authorization_artifact_digest": authorization,
            "terms_artifact_digest": self.policy.terms_artifact_digest,
            "response_digest": hashlib.sha3_512(body).hexdigest(),
            "status": self.status,
            "media_type": profile.ALLOWED_MEDIA_TYPE,
            "observed_at": 7_000,
            "fetched_at": 7_010,
            "redirect": self.redirect,
            "transport_authenticated": self.authenticated,
        }
        digest = acquisition._digest("transport-attestation", material)
        if self.bad_digest:
            digest = _hex("wrong-response")
        attestation = acquisition.FhirTransportAttestationV1(**material, attestation_digest=digest)
        return acquisition.AuthenticatedFhirResponseV1(body, attestation)


class AuthenticatedSourceAcquisitionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.policy = _policy()
        self.quarantine = quarantine.ExternalSourceQuarantineService(root / "quarantine.db", policy=self.policy)
        self.config = acquisition.AuthenticatedSourceAcquisitionConfigV1(
            acquisition_id="SYNTH_NC_MEDICAID_ACQUISITION_V1",
            version=1,
            nc_profile_digest=profile.NC_MEDICAID_PROFILE.profile_digest,
            external_policy_digest=self.policy.digest,
            quarantine_policy_digest=self.quarantine.policy_digest,
            quarantine_chain_id=self.quarantine.chain_id,
            quarantine_database_id="SYNTH_NC_QUARANTINE_DATABASE_V1",
            transport_id=_AuthenticatedFixtureTransport.transport_id,
            transport_epoch=1,
            authorization_artifact_digest=self.policy.authorization_artifact_digest,
            terms_artifact_digest=self.policy.terms_artifact_digest,
            endpoint_id=self.policy.logical_endpoint_id,
            request_digest=acquisition.request_digest_for_profile(),
            cadence_seconds=600,
            freshness_grace_seconds=60,
            max_body_bytes=profile.TRANSPORT_CAPS["max_page_bytes"],
            max_page_count=profile.TRANSPORT_CAPS["max_pages"],
            max_attempts=3,
            lease_seconds=60,
            busy_timeout_ms=500,
            max_slots=16,
        )
        self.service = acquisition.AuthenticatedSourceAcquisitionService(root / "acquisition.db", config=self.config, external_policy=self.policy, quarantine_service=self.quarantine, clock=lambda: 7_000)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_two_page_capture_is_independently_verified_and_quarantined(self) -> None:
        created = self.service.ensure_slot(7_000)
        lease = self.service.claim_next(7_000)
        self.assertIsNotNone(lease)
        result = self.service.acquire(lease, _AuthenticatedFixtureTransport(self.policy))  # type: ignore[arg-type]
        self.assertEqual("QUARANTINED", result["state"])
        self.assertFalse(result["production_source_authentication"])
        self.assertFalse(result["production_usable"])
        self.assertIsNone(result["proofSuiteId"])
        evidence = self.service.integrity()
        self.assertEqual((1, 4, 4, 2), (evidence["slot_count"], evidence["operation_count"], evidence["transition_count"], evidence["attestation_count"]))
        self.assertEqual("QUARANTINED", evidence["states"]["QUARANTINED"] and "QUARANTINED")
        self.assertEqual(created["slot_id"], lease.slot_id)  # type: ignore[union-attr]
        self.assertEqual(1, self.quarantine.integrity()["artifact_count"])
        self.assertTrue(self.service.support_snapshot()["zero_phi"])

    def test_same_slot_claim_is_single_writer_and_exact_retry_is_stable(self) -> None:
        created = self.service.ensure_slot(7_000)
        services = [self.service, acquisition.AuthenticatedSourceAcquisitionService(Path(self.temporary.name) / "acquisition.db", config=self.config, external_policy=self.policy, quarantine_service=self.quarantine, clock=lambda: 7_000)]
        barrier = threading.Barrier(2)
        outcomes: list[object] = []

        def worker(service: acquisition.AuthenticatedSourceAcquisitionService) -> None:
            barrier.wait()
            try:
                outcomes.append(service.claim_next(7_000))
            except Exception as exc:  # pragma: no cover - assertion below preserves the raw type
                outcomes.append(exc)

        threads = [threading.Thread(target=worker, args=(service,)) for service in services]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)
        leases = [item for item in outcomes if isinstance(item, acquisition.AcquisitionLease)]
        self.assertEqual(1, len(leases), outcomes)
        self.assertEqual(created["slot_id"], leases[0].slot_id)
        first = self.service.acquire(leases[0], _AuthenticatedFixtureTransport(self.policy))  # type: ignore[arg-type]
        retry = self.service.acquire(leases[0], _AuthenticatedFixtureTransport(self.policy))
        self.assertEqual(first["quarantine_receipt_digest"], retry["quarantine_receipt_digest"])
        self.assertEqual(self.service.export_bytes(), self.service.export_bytes())

    def test_lease_expiry_requeues_then_exhausts_without_quarantine(self) -> None:
        self.service.ensure_slot(7_000)
        first = self.service.claim_next(7_000)
        self.assertIsNotNone(first)
        self.assertEqual(1, self.service.requeue_expired(7_061))
        second = self.service.claim_next(7_061)
        self.assertIsNotNone(second)
        self.assertEqual(1, self.service.requeue_expired(7_122))
        third = self.service.claim_next(7_122)
        self.assertIsNotNone(third)
        self.assertEqual(1, self.service.requeue_expired(7_183))
        self.assertEqual(1, self.service.integrity()["states"].get("HELD"))
        self.assertEqual(0, self.quarantine.integrity()["artifact_count"])

    def test_response_loss_after_quarantine_is_recoverable_at_least_once(self) -> None:
        self.service.ensure_slot(7_000)
        lease = self.service.claim_next(7_000)
        armed = {"value": True}

        def fault(point: str) -> None:
            if point == "after_commit_before_response" and armed["value"]:
                armed["value"] = False
                raise quarantine.QuarantineResponseLost("quarantine:response-lost")

        self.quarantine.fault_injector = fault
        with self.assertRaises(acquisition.AcquisitionResponseLost):
            self.service.acquire(lease, _AuthenticatedFixtureTransport(self.policy))  # type: ignore[arg-type]
        self.assertEqual("CAPTURED", self.service.integrity()["states"]["CAPTURED"] and "CAPTURED")
        self.quarantine.fault_injector = None
        retry = self.service.acquire(lease, _AuthenticatedFixtureTransport(self.policy))  # type: ignore[arg-type]
        self.assertEqual("QUARANTINED", retry["state"])
        self.assertEqual(1, self.quarantine.integrity()["artifact_count"])

    def test_partial_or_bad_attestation_never_reaches_quarantine(self) -> None:
        for bad in ("partial", "digest"):
            with self.subTest(bad=bad):
                root = Path(self.temporary.name) / bad
                root.mkdir()
                q = quarantine.ExternalSourceQuarantineService(root / "q.db", policy=self.policy)
                service = acquisition.AuthenticatedSourceAcquisitionService(root / "a.db", config=self.config, external_policy=self.policy, quarantine_service=q, clock=lambda: 7_000)
                service.ensure_slot(7_000)
                lease = service.claim_next(7_000)
                transport = _AuthenticatedFixtureTransport(self.policy, partial=bad == "partial", bad_digest=bad == "digest")
                with self.assertRaises(acquisition.AuthenticatedSourceAcquisitionError):
                    service.acquire(lease, transport)
                self.assertEqual(0, q.integrity()["artifact_count"])
                self.assertNotEqual("QUARANTINED", service.integrity()["states"].get("QUARANTINED"))

    def test_transport_identity_authority_redirect_and_authentication_fail_closed(self) -> None:
        cases = {
            "server": {"bad_server": True},
            "authority": {"bad_authority": True},
            "redirect": {"redirect": True},
            "unauthenticated": {"authenticated": False},
            "server-error": {"status": 500},
        }
        for label, changes in cases.items():
            with self.subTest(label=label):
                root = Path(self.temporary.name) / ("transport-" + label)
                root.mkdir()
                q = quarantine.ExternalSourceQuarantineService(root / "q.db", policy=self.policy)
                service = acquisition.AuthenticatedSourceAcquisitionService(root / "a.db", config=self.config, external_policy=self.policy, quarantine_service=q, clock=lambda: 7_000)
                service.ensure_slot(7_000)
                lease = service.claim_next(7_000)
                with self.assertRaises(acquisition.AuthenticatedSourceAcquisitionError):
                    service.acquire(lease, _AuthenticatedFixtureTransport(self.policy, **changes))
                self.assertEqual(0, q.integrity()["artifact_count"])

    def test_two_same_lease_acquisitions_converge_without_duplicate_quarantine(self) -> None:
        self.service.ensure_slot(7_000)
        lease = self.service.claim_next(7_000)
        barrier = threading.Barrier(2)
        outcomes: list[object] = []

        def worker() -> None:
            barrier.wait()
            try:
                outcomes.append(self.service.acquire(lease, _AuthenticatedFixtureTransport(self.policy)))  # type: ignore[arg-type]
            except Exception as exc:  # pragma: no cover - assertion below reports the raw type
                outcomes.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)
        self.assertTrue(all(isinstance(item, dict) for item in outcomes), outcomes)
        self.assertEqual(1, self.quarantine.integrity()["artifact_count"])
        self.assertEqual(1, self.service.integrity()["states"]["QUARANTINED"])

    def test_export_restore_and_tamper_fail_closed_without_raw_capture(self) -> None:
        self.service.ensure_slot(7_000)
        lease = self.service.claim_next(7_000)
        transport = _AuthenticatedFixtureTransport(self.policy)
        self.service.acquire(lease, transport)  # type: ignore[arg-type]
        exported = self.service.export_bytes()
        verified = independent.verify_export_bytes(exported, config=self.config.material())
        self.assertEqual(verified["state_root"], self.service.integrity()["state_root"])
        self.assertNotIn(profile.BASE_URL.encode("ascii"), exported)
        self.assertNotIn(transport.bodies[0], exported)
        self.assertNotIn(transport.bodies[1], exported)
        restored = Path(self.temporary.name) / "restored.db"
        restored_service = acquisition.restore_export(restored, exported, config=self.config, external_policy=self.policy, quarantine_service=self.quarantine)
        self.assertEqual(restored_service.export_bytes(), exported)
        reopened = acquisition.AuthenticatedSourceAcquisitionService(Path(self.temporary.name) / "acquisition.db", config=self.config, external_policy=self.policy, quarantine_service=self.quarantine, clock=lambda: 7_000)
        self.assertEqual(reopened.integrity()["state_root"], self.service.integrity()["state_root"])
        mutated = bytearray(exported)
        mutated[-2] ^= 1
        with self.assertRaises(independent.IndependentAcquisitionError):
            independent.verify_export_bytes(bytes(mutated), config=self.config.material())
        support = restored_service.support_snapshot()
        self.assertNotIn(profile.BASE_URL, json.dumps(support))
        self.assertNotIn(profile.SYNTHETIC_PRACTITIONER_ID, json.dumps(support))

    def test_precommit_fault_rolls_back_without_a_slot_or_quarantine_artifact(self) -> None:
        armed = {"value": True}

        def fault(point: str) -> None:
            if point == "before_operation_insert" and armed["value"]:
                armed["value"] = False
                raise acquisition.AcquisitionInjectedFault("acquisition:injected")

        self.service.fault_injector = fault
        with self.assertRaises(acquisition.AcquisitionInjectedFault):
            self.service.ensure_slot(7_000)
        self.assertEqual(0, self.service.integrity()["slot_count"])
        self.assertEqual(0, self.service.integrity()["transition_count"])
        self.assertEqual(0, self.quarantine.integrity()["artifact_count"])

    def test_config_and_transport_authority_cannot_drift(self) -> None:
        with self.assertRaises(acquisition.AuthenticatedSourceAcquisitionError):
            acquisition.AuthenticatedSourceAcquisitionConfigV1(**{**self.config.material(), "request_digest": _hex("wrong-request")})
        drifted = adapter.ExternalSourcePolicyV1(**{**self.policy.__dict__, "logical_endpoint_id": "SYNTH_NC_OTHER_ENDPOINT_V1"})
        with self.assertRaises(acquisition.AuthenticatedSourceAcquisitionError):
            acquisition.AuthenticatedSourceAcquisitionService(Path(self.temporary.name) / "drift.db", config=self.config, external_policy=drifted, quarantine_service=self.quarantine, clock=lambda: 7_000)
        self.service.ensure_slot(7_000)
        lease = self.service.claim_next(7_000)
        with self.assertRaises(acquisition.AuthenticatedSourceAcquisitionError):
            self.service.acquire(lease, _AuthenticatedFixtureTransport(self.policy, bad_digest=True))  # type: ignore[arg-type]
        self.assertEqual(0, self.quarantine.integrity()["artifact_count"])

    def test_independent_module_has_no_producer_or_network_dependency(self) -> None:
        source = Path(independent.__file__).read_text(encoding="utf-8")
        self.assertNotIn("from app.mirror import authenticated_source_acquisition", source)
        self.assertNotIn("requests", source.lower())
        self.assertNotIn("urllib", source.lower())


if __name__ == "__main__":
    unittest.main()
