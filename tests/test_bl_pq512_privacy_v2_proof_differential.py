from __future__ import annotations

import inspect
import json
from pathlib import Path

import pytest

from app.batch.pq_suite_candidate import CandidateSidecarV1
from app.privacy_v2_migration import (
    ACTIVATION_ALLOWED,
    PRODUCTION_USABLE,
    PROOF_SUITE_ID,
    PrivacyV2MigrationTarget,
    _build_privacy_v2_migration_evidence_with_salt,
    build_privacy_v2_migration_evidence,
    generate_migration_privacy_salt,
    public_migration_artifact,
)
from app.production_boundary import ProductionBoundaryError
from tests.test_bl_pq512_transactional_privacy_v2_migration import (
    _DOMAIN,
    _NEW,
    _SUBMITTER,
    _ReceiptVerifier,
    _authority_for_epoch,
    _coordinator,
    _migration_inputs,
    _sidecar,
    _store,
    _target_authority_for_envelope,
    _wide,
)


_PRIVATE_CASES = (
    (
        (b"opaque-private-alpha|hidden-value-a|cipher-a",),
        (b"opaque-record-alpha",),
        (b"opaque-semantics-alpha",),
    ),
    (
        (
            b"opaque-private-bravo|hidden-value-b|cipher-b1",
            b"opaque-private-charlie|hidden-value-c|cipher-c2",
            b"opaque-private-delta|hidden-value-d|cipher-d3",
            b"opaque-private-echo|hidden-value-e|cipher-e4",
        ),
        (
            b"opaque-record-bravo",
            b"opaque-record-charlie",
            b"opaque-record-delta",
            b"opaque-record-echo",
        ),
        (
            b"opaque-semantics-bravo",
            b"opaque-semantics-charlie",
            b"opaque-semantics-delta",
            b"opaque-semantics-echo",
        ),
    ),
)


def test_private_values_and_record_count_do_not_change_artifact_shape(
    tmp_path: Path,
) -> None:
    observations = []
    for index, (old_private, new_private, semantics) in enumerate(_PRIVATE_CASES):
        store = _store(tmp_path / f"ledger-{index}.sqlite3")
        verifier = _ReceiptVerifier()
        coordinator = _coordinator(store, verifier)
        envelope, nonce, evidence = _migration_inputs(
            coordinator,
            label=f"differential-{index}",
            old_private_records=old_private,
            new_private_records=new_private,
            semantic_records=semantics,
        )
        operation = coordinator._prepare(
            envelope=envelope,
            batch_nonce=nonce,
            submitter=_SUBMITTER,
            evidence=evidence,
            target_governance_authority=_target_authority_for_envelope(envelope),
        )
        artifact = public_migration_artifact(operation)
        artifact_payload = json.loads(artifact)
        evidence_json = json.dumps(
            evidence.as_public_dict(), sort_keys=True, separators=(",", ":")
        ).encode("ascii")
        public_surface = b"|".join(
            (envelope.public_outputs, envelope.sidecar, artifact, evidence_json)
        )

        for private_value in old_private + new_private + semantics:
            assert private_value not in public_surface
        for forbidden_value in (
            b"opaque-private-alpha",
            b"opaque-private-bravo",
            b"opaque-private-charlie",
            b"opaque-record-alpha",
            b"opaque-record-bravo",
            b"hidden-value-a",
            b"hidden-value-b",
            b"cipher-a",
            b"cipher-b1",
        ):
            assert forbidden_value not in public_surface.lower()

        assert verifier.calls == 1
        assert len(envelope.public_outputs) == 384
        assert len(envelope.public_outputs) // 32 == 12
        assert len(envelope.sidecar) == 744
        assert artifact_payload["proofSuiteId"] is None
        assert artifact_payload["productionUsable"] is False
        assert artifact_payload["activationAllowed"] is False
        assert evidence.as_public_dict()["proofSuiteId"] is None
        observations.append(
            (
                len(envelope.public_outputs),
                len(envelope.sidecar),
                len(envelope.encode()),
                len(artifact),
                len(evidence_json),
                tuple(sorted(artifact_payload)),
                tuple(sorted(evidence.as_public_dict())),
            )
        )

    assert observations[0] == observations[1]


def test_public_migration_surfaces_are_commitment_only_and_nonactivating(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "ledger.sqlite3")
    coordinator = _coordinator(store, _ReceiptVerifier())
    envelope, nonce, evidence = _migration_inputs(coordinator, label="public-surface")
    operation = coordinator._prepare(
        envelope=envelope,
        batch_nonce=nonce,
        submitter=_SUBMITTER,
        evidence=evidence,
        target_governance_authority=_target_authority_for_envelope(envelope),
    )
    artifact = json.loads(public_migration_artifact(operation))
    evidence_public = evidence.as_public_dict()

    assert PROOF_SUITE_ID is None
    assert PRODUCTION_USABLE is False
    assert ACTIVATION_ALLOWED is False
    assert set(evidence_public) == {
        "status",
        "kind",
        "versionCommitment",
        "equivalenceCommitment",
        "sourceCheckpointCommitment",
        "targetStateCommitment",
        "knownTargetCheckpoint",
        "evidenceCommitment",
        "proofSuiteId",
        "activationAllowed",
        "productionUsable",
    }
    assert set(artifact) == {
        "status",
        "kind",
        "migrationCommitment",
        "evidenceCommitment",
        "sourceCheckpointCommitment",
        "targetStateCommitment",
        "epochBefore",
        "epochAfter",
        "sequenceBefore",
        "sequenceAfter",
        "profileIdAfter",
        "proofSuiteIdAfter",
        "schemaIdAfter",
        "verifierArtifactIdentityAfter",
        "proofSuiteId",
        "activationAllowed",
        "productionUsable",
    }
    forbidden_names = {"amount", "count", "decision", "phi", "ciphertext", "claim"}
    for key in set(evidence_public) | set(artifact):
        assert not any(name in key.lower() for name in forbidden_names)


def test_private_semantic_difference_fails_before_native_verification(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "ledger.sqlite3")
    verifier = _ReceiptVerifier()
    coordinator = _coordinator(store, verifier)

    with pytest.raises(ProductionBoundaryError, match="migration_semantic_equivalence_failed"):
        _migration_inputs(
            coordinator,
            label="semantic-mismatch",
            old_private_records=(b"opaque-old-private",),
            new_private_records=(b"opaque-new-private",),
            semantic_records=(b"opaque-old-semantics",),
            new_semantic_records=(b"opaque-new-semantics",),
        )
    assert verifier.calls == 0
    assert store.identity_snapshot().sequence == 0


def test_public_evidence_builder_owns_fresh_privacy_randomness(
    tmp_path: Path,
) -> None:
    assert "privacy_salt" not in inspect.signature(
        build_privacy_v2_migration_evidence
    ).parameters
    store = _store(tmp_path / "ledger.sqlite3")
    coordinator = _coordinator(store, _ReceiptVerifier())
    source = coordinator.source_identity
    target = PrivacyV2MigrationTarget.from_sidecar(
        CandidateSidecarV1.decode(
            _sidecar(
                source=source,
                target_config=_NEW,
                nullifier_after=_wide("rng-nullifier-after"),
                payment_after=_wide("rng-payment-after"),
                batch_commitment=_wide("rng-provisional-batch"),
            )
        ),
        settlement_domain=_DOMAIN,
        governance_authority=_authority_for_epoch(source.epoch + 1),
    )
    inputs = dict(
        kind="MIGRATION",
        migration_version="privacy-v2-rng-ownership",
        source=source,
        target=target,
        old_private_records=(b"opaque-old",),
        new_private_records=(b"opaque-new",),
        old_semantic_records=(b"opaque-same",),
        new_semantic_records=(b"opaque-same",),
    )
    first = build_privacy_v2_migration_evidence(**inputs)
    second = build_privacy_v2_migration_evidence(**inputs)
    assert first.equivalence_commitment != second.equivalence_commitment
    assert first.commitment != second.commitment


def test_migration_entropy_failure_is_bounded_and_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def all_zero_entropy(length: int) -> bytes:
        nonlocal calls
        calls += 1
        assert length == 64
        return bytes(64)

    monkeypatch.setattr(
        "app.privacy_v2_migration.secrets.token_bytes", all_zero_entropy
    )
    with pytest.raises(ProductionBoundaryError, match="migration_entropy_failure"):
        generate_migration_privacy_salt()
    assert calls == 4


def test_migration_evidence_known_answer_is_stable(tmp_path: Path) -> None:
    store = _store(tmp_path / "ledger.sqlite3")
    coordinator = _coordinator(store, _ReceiptVerifier())
    envelope, _, evidence = _migration_inputs(coordinator, label="kat-shape")
    target = PrivacyV2MigrationTarget.from_sidecar(
        CandidateSidecarV1.decode(envelope.sidecar),
        settlement_domain=envelope.public_outputs[32:64],
        governance_authority=_target_authority_for_envelope(envelope),
    )
    deterministic = _build_privacy_v2_migration_evidence_with_salt(
        kind="MIGRATION",
        migration_version="privacy-v2-kat-v1",
        source=coordinator.source_identity,
        target=target,
        old_private_records=(b"old-private-record",),
        new_private_records=(b"new-private-record",),
        old_semantic_records=(b"same-private-semantics",),
        new_semantic_records=(b"same-private-semantics",),
        privacy_salt=bytes(range(64)),
    )
    assert evidence.commitment != deterministic.commitment
    assert deterministic.commitment.hex() == (
        "ce9e59897bcbdce1c560c6600bbe8efc737a61445f1014ed33e32c171235bd10"
        "be4f8a21844e530290b3293cdeafeed16b136b447a25dd124872093cf47dbf8e"
    )
