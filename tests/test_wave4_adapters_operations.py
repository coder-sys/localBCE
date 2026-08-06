from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path

import pytest

from app.wave4_adapters import (
    AdapterDowngradeError,
    AdapterIdentity,
    AdapterRequest,
    CircuitBreaker,
    DualPqAuthenticator,
    ML_DSA_87,
    PqcryptoSoftwareSigner,
    RetryPolicy,
    RetryableAdapterError,
    SLH_DSA_SHAKE_256F,
    SyntheticAdapter,
    SyntheticFixture,
    Wave4AdapterError,
    build_synthetic_registry,
    retry_call,
    run_adapter_conformance,
)
from app.wave4_operations import (
    FixedCadenceQueue,
    IncidentController,
    KeyLifecycleRegistry,
    NonPhiAuditLog,
    NonceReuseGuard,
    SoftwarePqKmsReference,
    UniformQueueError,
    Wave4OperationsError,
    build_wave4_release_manifest,
    healthy_entropy_sample,
    secure_zeroize,
)


@pytest.fixture(scope="module")
def authority() -> DualPqAuthenticator:
    ml = PqcryptoSoftwareSigner.generate(ML_DSA_87)
    slh = PqcryptoSoftwareSigner.generate(SLH_DSA_SHAKE_256F)
    authority = DualPqAuthenticator((ml, slh))
    yield authority
    ml.destroy()
    slh.destroy()


def test_all_i02_i07_capabilities_pass_shared_conformance(authority: DualPqAuthenticator) -> None:
    report = run_adapter_conformance(build_synthetic_registry(authority))

    assert report.ok, report.failures
    assert len(report.failures) == 0
    assert len(report.passed) >= 1 + (3 * 22)


def test_capsule_is_dual_pq_authenticated_and_does_not_serialize_private_facts(
    authority: DualPqAuthenticator,
) -> None:
    registry = build_synthetic_registry(authority)
    adapter = registry.resolve("claim_source")
    request = AdapterRequest.create(
        request_id="SYNTHETIC-REQUEST-PRIVATE",
        capability="claim_source",
        lookup_key="SYNTHETIC-FIXTURE-CLAIM_SOURCE",
        idempotency_key="SYNTHETIC-IDEMPOTENCY-PRIVATE",
    )
    response = adapter.fetch(request)
    encoded = json.dumps(response.public_event(), sort_keys=True)

    assert response.status == "complete"
    assert response.capsule.cryptographic_profile == "DUAL-PQ-ML-DSA-87+SLH-DSA-SHAKE-256F"
    assert "private_facts" not in encoded
    assert "fixture_present" not in encoded
    adapter.verify(response)  # type: ignore[attr-defined]

    tampered_signature = replace(
        response.capsule.signatures[0],
        signature_hex=("00" * (len(response.capsule.signatures[0].signature_hex) // 2)),
    )
    tampered = replace(response, capsule=replace(response.capsule, signatures=(tampered_signature, *response.capsule.signatures[1:])))
    with pytest.raises(Wave4AdapterError, match="pq_authentication_failed"):
        adapter.verify(tampered)  # type: ignore[attr-defined]


def test_direct_request_construction_cannot_bypass_private_lookup_validation() -> None:
    with pytest.raises(ValueError, match="lookup_key_must_be_local"):
        AdapterRequest(
            "SYNTHETIC-REQUEST-DIRECT",
            "claim_source",
            "0" * 128,
            "1" * 128,
            "SYNTHETIC-IDEMPOTENCY-DIRECT",
            1,
            1_000,
            "PATIENT-PRIVATE-LOOKUP",
        )


def test_missing_source_is_authenticated_absence_and_idempotency_conflicts_fail(
    authority: DualPqAuthenticator,
) -> None:
    registry = build_synthetic_registry(authority)
    adapter = registry.resolve("eligibility")
    missing = AdapterRequest.create(
        request_id="SYNTHETIC-REQUEST-MISSING",
        capability="eligibility",
        lookup_key="SYNTHETIC-MISSING-ELIGIBILITY",
        idempotency_key="SYNTHETIC-IDEMPOTENCY-MISSING",
    )
    response = adapter.fetch(missing)
    assert response.status == "absent"
    assert response.capsule.error_class == "SOURCE_MISSING"
    adapter.verify(response)  # type: ignore[attr-defined]

    conflict = AdapterRequest.create(
        request_id="SYNTHETIC-REQUEST-MISSING-OTHER",
        capability="eligibility",
        lookup_key="SYNTHETIC-OTHER",
        idempotency_key="SYNTHETIC-IDEMPOTENCY-MISSING",
    )
    with pytest.raises(Wave4AdapterError, match="idempotency_conflict"):
        adapter.fetch(conflict)


def test_retry_circuit_and_version_migration_fail_closed(authority: DualPqAuthenticator) -> None:
    attempts = 0

    def transient() -> str:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise RetryableAdapterError("transient")
        return "ok"

    assert retry_call(transient, RetryPolicy(max_attempts=3), sleep=lambda _: None) == "ok"
    assert attempts == 3
    with pytest.raises(RetryableAdapterError, match="exhausted"):
        retry_call(lambda: (_ for _ in ()).throw(RetryableAdapterError("always")), RetryPolicy(max_attempts=2), sleep=lambda _: None)

    breaker = CircuitBreaker(failure_threshold=2, cooldown_seconds=10)
    breaker.record_failure(now=1)
    breaker.record_failure(now=1)
    with pytest.raises(RetryableAdapterError, match="circuit_open"):
        breaker.before_call(now=2)
    breaker.before_call(now=12)

    registry = build_synthetic_registry(authority)
    base = registry.resolve("policy").identity
    upgraded_identity = replace(base, adapter_id="SYNTHETIC-WAVE4-POLICY-V2", adapter_version=2)
    upgraded = SyntheticAdapter(
        upgraded_identity,
        authenticator=authority,
        fixtures=(
            SyntheticFixture(
                capability="policy",
                lookup_key="SYNTHETIC-FIXTURE-POLICY",
                source_bytes=b"synthetic-policy-v2",
                private_facts={"fixture_present": True},
            ),
        ),
    )
    registry.register(upgraded)
    assert len(registry.migrate("policy", from_version=1, to_version=2)) == 128
    with pytest.raises(AdapterDowngradeError, match="downgrade"):
        registry.resolve("policy", version=1)


def test_credential_port_never_returns_a_secret(authority: DualPqAuthenticator) -> None:
    from app.wave4_adapters import SyntheticCredentialPort

    port = SyntheticCredentialPort("SYNTHETIC-WAVE4-PROVIDER")
    handle = port.handle("identity")
    with pytest.raises(Wave4AdapterError, match="secret_unavailable"):
        port.read_secret(handle)


def test_operations_cover_kms_lifecycle_entropy_audit_and_incident(tmp_path: Path) -> None:
    kms = SoftwarePqKmsReference()
    envelope = kms.seal(plaintext=b"synthetic-private", associated_data=b"aad")
    assert kms.open(envelope=envelope, associated_data=b"aad") == b"synthetic-private"
    kms.destroy()
    with pytest.raises(Wave4OperationsError, match="destroyed"):
        kms.open(envelope=envelope, associated_data=b"aad")

    roots = KeyLifecycleRegistry()
    roots.register("SYNTHETIC-KEY-1", "1" * 128)
    rotated = roots.rotate("SYNTHETIC-KEY-1", "2" * 128)
    assert rotated.epoch == 2
    assert roots.retire("SYNTHETIC-KEY-1").status == "retired"
    assert roots.destroy("SYNTHETIC-KEY-1").status == "destroyed"
    assert len(roots.registry_digest_sha3_512) == 128

    guard = NonceReuseGuard()
    guard.reserve(b"nonce-1", context=b"wave4")
    with pytest.raises(Wave4OperationsError, match="nonce_reuse"):
        guard.reserve(b"nonce-1", context=b"wave4")
    assert len(healthy_entropy_sample()) == 32

    audit_path = tmp_path / "audit.jsonl"
    audit = NonPhiAuditLog(audit_path)
    checkpoint = "3" * 128
    audit.append(
        "WAVE4_TEST",
        correlation_digest_sha3_512=checkpoint,
        metadata={"capability": "payment", "status": "ok"},
    )
    assert NonPhiAuditLog(audit_path).head_digest_sha3_512 != "0" * 128
    audit_path.write_text(audit_path.read_text(encoding="utf-8").replace("WAVE4_TEST", "WAVE4_TAMPER"), encoding="utf-8")
    with pytest.raises(Wave4OperationsError, match="corrupt"):
        NonPhiAuditLog(audit_path)

    unknown_field_path = tmp_path / "unknown-field.jsonl"
    unknown_field_path.write_text(
        json.dumps({"extra": "rejected"}) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(Wave4OperationsError, match="corrupt"):
        NonPhiAuditLog(unknown_field_path)

    clean_audit = NonPhiAuditLog(tmp_path / "incident.jsonl")
    incident = IncidentController(clean_audit)
    assert incident.drill(checkpoint_digest_sha3_512="4" * 128) == ("pause", "recovery", "resume")
    assert incident.state.status == "healthy"


def test_fixed_cadence_queue_has_exact_slots_and_uniform_failures() -> None:
    queue = FixedCadenceQueue(capacity=4, batch_size=4, cadence_ms=1_000)
    queue.submit(job_id="SYNTHETIC-JOB-1", opaque_commitment_sha3_512="5" * 128)
    with pytest.raises(UniformQueueError, match="BATCH_REJECTED"):
        queue.submit(job_id="SYNTHETIC-JOB-1", opaque_commitment_sha3_512="5" * 128)
    slots = queue.tick()
    assert len(slots) == 4
    assert [slot.kind for slot in slots] == ["real", "cover", "cover", "cover"]
    assert all(len(slot.commitment_sha3_512) == 128 for slot in slots)


def test_wave4_release_manifest_is_reproducible_and_nonactivating() -> None:
    root = Path(__file__).resolve().parents[1]
    first = build_wave4_release_manifest(root)
    second = build_wave4_release_manifest(root)
    assert first.manifest_digest_sha3_512 == second.manifest_digest_sha3_512
    assert first.production_usable is False
    assert first.proof_suite_id is None
    assert len(first.package_status) == 15
    assert all(status == "complete_internal_nonactivating" for status in first.package_status.values())
