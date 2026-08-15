from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
import sqlite3
from threading import Event

import pytest

from app.batch.pq_suite_candidate import CandidateSidecarV1
from app.privacy_v2_migration import (
    PrivacyV2MigrationTarget,
    _build_privacy_v2_migration_evidence_with_salt,
    derive_migration_nonce,
)
from app.production_boundary import (
    ProductionBoundaryError,
    ProductionProofEnvelope,
    _BATCH_NONCE_BINDING,
    _digest,
    build_v2_public_fields,
)
from app.transactional_database_boundary import TransactionalSettlementV2
from tests.test_bl_pq512_transactional_privacy_v2_migration import (
    _DOMAIN,
    _NEW,
    _NULLIFIER_1,
    _NULLIFIER_2,
    _OLD,
    _PAYMENT_1,
    _PAYMENT_2,
    _ROLLBACK_DOMAIN,
    _ROOTS,
    _SUBMITTER,
    _ReceiptVerifier,
    _authority_for_epoch,
    _config,
    _coordinator,
    _migration_inputs,
    _settlement_envelope,
    _sidecar,
    _store,
    _target_authority_for_envelope,
    _wide,
)


def test_caller_chosen_migration_salt_is_rejected_before_native_verification(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "ledger.sqlite3")
    verifier = _ReceiptVerifier()
    coordinator = _coordinator(store, verifier)
    source = coordinator.source_identity
    provisional = _sidecar(
        source=source,
        target_config=_NEW,
        nullifier_after=_NULLIFIER_1,
        payment_after=_PAYMENT_1,
        batch_commitment=_wide("chosen-salt-provisional-batch"),
    )
    target = PrivacyV2MigrationTarget.from_sidecar(
        CandidateSidecarV1.decode(provisional),
        settlement_domain=_DOMAIN,
        governance_authority=_authority_for_epoch(source.epoch + 1),
    )
    evidence = _build_privacy_v2_migration_evidence_with_salt(
        kind="MIGRATION",
        migration_version="privacy-v2-chosen-salt-attack",
        source=source,
        target=target,
        old_private_records=(b"old-private",),
        new_private_records=(b"new-private",),
        old_semantic_records=(b"same-semantics",),
        new_semantic_records=(b"same-semantics",),
        privacy_salt=_wide("attacker-chosen-predictable-salt"),
    )
    nonce = derive_migration_nonce(source, target, evidence)
    sidecar = _sidecar(
        source=source,
        target_config=_NEW,
        nullifier_after=_NULLIFIER_1,
        payment_after=_PAYMENT_1,
        batch_commitment=_digest(_BATCH_NONCE_BINDING, nonce),
    )
    envelope = ProductionProofEnvelope(
        suite_id=_NEW.suite,
        schema_id=_NEW.schema,
        verifier_artifact_identity=_NEW.verifier,
        public_outputs=b"".join(
            build_v2_public_fields(
                settlement_domain=_DOMAIN,
                batch_nonce=nonce,
                sidecar=sidecar,
                governance_authority=target.governance_authority,
                suite_id=_NEW.suite,
                schema_id=_NEW.schema,
                verifier_artifact_identity=_NEW.verifier,
            )
        ),
        sidecar=sidecar,
        proof_package=_wide("chosen-salt-synthetic-proof"),
        transcript_evidence=_wide("chosen-salt-synthetic-transcript"),
        evidence_commitment=evidence.commitment,
    )

    with pytest.raises(
        ProductionBoundaryError,
        match="migration_evidence_randomness_provenance_invalid",
    ):
        coordinator.submit(
            envelope=envelope,
            batch_nonce=nonce,
            submitter=_SUBMITTER,
            evidence=evidence,
            target_governance_authority=target.governance_authority,
        )
    assert verifier.calls == 0
    assert store.identity_snapshot().sequence == 0


def test_mixed_target_evidence_and_stale_source_fail_closed(tmp_path: Path) -> None:
    store = _store(tmp_path / "ledger.sqlite3")
    coordinator = _coordinator(store, _ReceiptVerifier())
    envelope_a, nonce_a, evidence_a = _migration_inputs(
        coordinator, target_config=_NEW, label="mixed-a"
    )
    envelope_b, nonce_b, _ = _migration_inputs(
        coordinator, target_config=_config("mixed-b"), label="mixed-b"
    )

    with pytest.raises(ProductionBoundaryError, match="migration_evidence_target_mismatch"):
        coordinator.submit(
            envelope=envelope_b,
            batch_nonce=nonce_b,
            submitter=_SUBMITTER,
            evidence=evidence_a,
            target_governance_authority=_target_authority_for_envelope(envelope_b),
        )

    coordinator.submit(
        envelope=envelope_a,
        batch_nonce=nonce_a,
        submitter=_SUBMITTER,
        evidence=evidence_a,
        target_governance_authority=_target_authority_for_envelope(envelope_a),
    )
    stale_envelope, stale_nonce, stale_evidence = _migration_inputs(
        coordinator, target_config=_config("stale-target"), label="stale"
    )
    with pytest.raises(
        ProductionBoundaryError,
        match="database_migration_source_(configuration|checkpoint)_stale",
    ):
        coordinator.submit(
            envelope=stale_envelope,
            batch_nonce=stale_nonce,
            submitter=_SUBMITTER,
            evidence=stale_evidence,
            target_governance_authority=_target_authority_for_envelope(stale_envelope),
        )


def test_target_profile_code_substitution_fails_before_native_verification(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "ledger.sqlite3")
    verifier = _ReceiptVerifier()
    coordinator = _coordinator(store, verifier)
    envelope, nonce, evidence = _migration_inputs(coordinator, label="profile-code-swap")
    authority = _target_authority_for_envelope(envelope)
    substituted = replace(authority, profile_code=3)
    with pytest.raises(
        ProductionBoundaryError,
        match="migration_target_governance_authority_mismatch",
    ):
        coordinator.submit(
            envelope=envelope,
            batch_nonce=nonce,
            submitter=_SUBMITTER,
            evidence=evidence,
            target_governance_authority=substituted,
        )
    assert verifier.calls == 0
    assert store.identity_snapshot().sequence == 0


def test_forged_seal_cannot_reach_database_mutation(tmp_path: Path) -> None:
    store = _store(tmp_path / "ledger.sqlite3")
    coordinator = _coordinator(store, _ReceiptVerifier())
    envelope, nonce, evidence = _migration_inputs(coordinator, label="forgery")
    operation = coordinator._prepare(
        envelope=envelope,
        batch_nonce=nonce,
        submitter=_SUBMITTER,
        evidence=evidence,
        target_governance_authority=_target_authority_for_envelope(envelope),
    )
    forged = replace(operation, seal=_wide("forged-migration-seal"))
    before = store.identity_snapshot()

    with pytest.raises(ProductionBoundaryError, match="database_migration_not_native_authorized"):
        store._commit_verified_migration(forged)
    assert store.identity_snapshot() == before


def test_concurrent_distinct_migrations_from_one_checkpoint_have_one_winner(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "ledger.sqlite3")
    coordinator = _coordinator(store, _ReceiptVerifier())
    prepared = []
    for label in ("race-a", "race-b"):
        envelope, nonce, evidence = _migration_inputs(
            coordinator, target_config=_config(label), label=label
        )
        prepared.append(
            coordinator._prepare(
                envelope=envelope,
                batch_nonce=nonce,
                submitter=_SUBMITTER,
                evidence=evidence,
                target_governance_authority=_target_authority_for_envelope(envelope),
            )
        )

    def commit(index: int) -> object:
        try:
            return store._commit_verified_migration(prepared[index])
        except ProductionBoundaryError as exc:
            return exc

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(commit, (0, 1)))

    errors = [result for result in results if isinstance(result, ProductionBoundaryError)]
    receipts = [result for result in results if not isinstance(result, ProductionBoundaryError)]
    assert len(receipts) == 1
    assert len(errors) == 1
    assert str(errors[0]) in {
        "database_migration_source_configuration_stale",
        "database_migration_source_checkpoint_stale",
    }
    assert store.identity_snapshot().sequence == 1
    store.verify_integrity()


def test_old_profile_operation_prepared_before_cutover_is_rejected_after_cutover(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "ledger.sqlite3")
    old_identity = store.identity_snapshot()
    old_envelope, old_nonce = _settlement_envelope(old_identity)
    old_settlement = TransactionalSettlementV2(
        verifier=_ReceiptVerifier(),
        storage=store,
        settlement_domain=_DOMAIN,
        governance_authority=old_identity.governance_authority,
        authorized_submitters=(_SUBMITTER,),
    )
    old_operation = old_settlement._prepare(
        envelope=old_envelope, batch_nonce=old_nonce, submitter=_SUBMITTER
    )

    migration = _coordinator(store, _ReceiptVerifier())
    envelope, nonce, evidence = _migration_inputs(migration, label="cutover")
    migration.submit(
        envelope=envelope, batch_nonce=nonce, submitter=_SUBMITTER, evidence=evidence,
        target_governance_authority=_target_authority_for_envelope(envelope),
    )

    with pytest.raises(
        ProductionBoundaryError, match="database_operation_configuration_stale"
    ):
        store._commit_verified(old_operation)
    assert store.identity_snapshot().profile_id == _NEW.profile
    assert store.identity_snapshot().sequence == 1


def test_old_profile_operation_cannot_cross_a_concurrent_cutover(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "ledger.sqlite3")
    old_identity = store.identity_snapshot()
    old_envelope, old_nonce = _settlement_envelope(old_identity)
    old_settlement = TransactionalSettlementV2(
        verifier=_ReceiptVerifier(),
        storage=store,
        settlement_domain=_DOMAIN,
        governance_authority=old_identity.governance_authority,
        authorized_submitters=(_SUBMITTER,),
    )
    old_operation = old_settlement._prepare(
        envelope=old_envelope,
        batch_nonce=old_nonce,
        submitter=_SUBMITTER,
    )

    validated = Event()
    continue_commit = Event()
    original_validate = store._validate_operation

    def pause_after_precheck(operation: object) -> object:
        parsed = original_validate(operation)  # type: ignore[arg-type]
        validated.set()
        assert continue_commit.wait(timeout=10)
        return parsed

    store._validate_operation = pause_after_precheck  # type: ignore[method-assign]
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(store._commit_verified, old_operation)
        assert validated.wait(timeout=10)
        migration = _coordinator(store, _ReceiptVerifier())
        envelope, nonce, evidence = _migration_inputs(
            migration,
            label="concurrent-cutover",
        )
        migration.submit(
            envelope=envelope,
            batch_nonce=nonce,
            submitter=_SUBMITTER,
            evidence=evidence,
            target_governance_authority=_target_authority_for_envelope(envelope),
        )
        continue_commit.set()
        result = pending.exception(timeout=10)

    assert isinstance(result, ProductionBoundaryError)
    assert str(result) in {
        "database_configuration_identity_mismatch",
        "database_operation_configuration_stale",
    }
    assert store.identity_snapshot().sequence == 1
    store.verify_integrity()


def test_migration_ledger_tamper_is_detected_on_integrity_replay(tmp_path: Path) -> None:
    path = tmp_path / "ledger.sqlite3"
    store = _store(path)
    coordinator = _coordinator(store, _ReceiptVerifier())
    envelope, nonce, evidence = _migration_inputs(coordinator, label="tamper")
    coordinator.submit(
        envelope=envelope, batch_nonce=nonce, submitter=_SUBMITTER, evidence=evidence,
        target_governance_authority=_target_authority_for_envelope(envelope),
    )

    with sqlite3.connect(path) as connection:
        connection.execute("DROP TRIGGER migration_requests_no_update")
        connection.execute(
            "UPDATE migration_requests SET migration_evidence_commitment=?",
            (sqlite3.Binary(_wide("tampered-evidence-commitment")),),
        )
        connection.commit()

    with pytest.raises(ProductionBoundaryError):
        store.verify_integrity()


def test_governance_tuple_tamper_is_detected_from_durable_recomputation(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "ledger.sqlite3")
    coordinator = _coordinator(store, _ReceiptVerifier())
    envelope, nonce, evidence = _migration_inputs(coordinator, label="authority-tamper")
    coordinator.submit(
        envelope=envelope,
        batch_nonce=nonce,
        submitter=_SUBMITTER,
        evidence=evidence,
        target_governance_authority=_target_authority_for_envelope(envelope),
    )
    with sqlite3.connect(store.path) as connection:
        connection.execute("DROP TRIGGER governance_authorities_no_update")
        connection.execute(
            "UPDATE governance_authorities SET truth_root_2=? WHERE activation_sequence=1",
            (sqlite3.Binary(_wide("tampered-full-truth-root")),),
        )
        connection.commit()
    with pytest.raises(
        ProductionBoundaryError,
        match="database_governance_authority_digest_mismatch",
    ):
        store.verify_integrity()


def test_reused_old_configuration_is_rejected_as_downgrade(tmp_path: Path) -> None:
    path = tmp_path / "ledger.sqlite3"
    store = _store(path)
    migration = _coordinator(store, _ReceiptVerifier())
    envelope, nonce, evidence = _migration_inputs(migration, label="forward")
    migration.submit(
        envelope=envelope, batch_nonce=nonce, submitter=_SUBMITTER, evidence=evidence,
        target_governance_authority=_target_authority_for_envelope(envelope),
    )
    store.close()

    store = _store(path, config=_NEW, epoch=2)
    downgrade = _coordinator(store, _ReceiptVerifier())
    envelope, nonce, evidence = _migration_inputs(
        downgrade,
        target_config=_OLD,
        nullifier_after=_NULLIFIER_2,
        payment_after=_PAYMENT_2,
        label="downgrade",
    )
    with pytest.raises(ProductionBoundaryError, match="database_migration_downgrade_or_reuse"):
        downgrade.submit(
            envelope=envelope,
            batch_nonce=nonce,
            submitter=_SUBMITTER,
            evidence=evidence,
            target_governance_authority=_target_authority_for_envelope(envelope),
        )


def test_rollback_without_fresh_settlement_domain_is_rejected(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "ledger.sqlite3")
    genesis = store.identity_snapshot()
    coordinator = _coordinator(store, _ReceiptVerifier())
    envelope, nonce, evidence = _migration_inputs(
        coordinator,
        target_config=_config("same-domain-rollback"),
        kind="ROLLBACK",
        known_target_checkpoint=genesis.checkpoint_commitment,
        label="same-domain-rollback",
    )
    with pytest.raises(
        ProductionBoundaryError,
        match="migration_recovery_domain_not_rotated",
    ):
        coordinator.submit(
            envelope=envelope,
            batch_nonce=nonce,
            submitter=_SUBMITTER,
            evidence=evidence,
            target_governance_authority=_target_authority_for_envelope(envelope),
        )
    assert store.identity_snapshot() == genesis


def test_recovery_cannot_reuse_any_historical_settlement_domain(
    tmp_path: Path,
) -> None:
    path = tmp_path / "ledger.sqlite3"
    store = _store(path)
    genesis = store.identity_snapshot()
    forward_coordinator = _coordinator(store, _ReceiptVerifier())
    envelope, nonce, evidence = _migration_inputs(
        forward_coordinator,
        label="domain-reuse-forward",
    )
    forward_coordinator.submit(
        envelope=envelope,
        batch_nonce=nonce,
        submitter=_SUBMITTER,
        evidence=evidence,
        target_governance_authority=_target_authority_for_envelope(envelope),
    )
    forward = store.identity_snapshot()
    store.close()

    rollback_config = _config("domain-reuse-rollback")
    store = _store(path, config=_NEW, epoch=2)
    rollback = _coordinator(
        store,
        _ReceiptVerifier(),
        settlement_domain=_ROLLBACK_DOMAIN,
    )
    envelope, nonce, evidence = _migration_inputs(
        rollback,
        target_config=rollback_config,
        nullifier_after=genesis.strong_nullifier_root,
        payment_after=genesis.strong_payment_state_root,
        kind="ROLLBACK",
        known_target_checkpoint=genesis.checkpoint_commitment,
        label="domain-reuse-rollback",
        target_settlement_domain=_ROLLBACK_DOMAIN,
    )
    rollback.submit(
        envelope=envelope,
        batch_nonce=nonce,
        submitter=_SUBMITTER,
        evidence=evidence,
        target_governance_authority=_target_authority_for_envelope(envelope),
    )
    store.close()

    store = _store(
        path,
        config=rollback_config,
        epoch=3,
        settlement_domain=_ROLLBACK_DOMAIN,
    )
    recovery = _coordinator(
        store,
        _ReceiptVerifier(),
        settlement_domain=_DOMAIN,
    )
    envelope, nonce, evidence = _migration_inputs(
        recovery,
        target_config=_config("domain-reuse-recovery"),
        nullifier_after=forward.strong_nullifier_root,
        payment_after=forward.strong_payment_state_root,
        kind="RECOVERY",
        known_target_checkpoint=forward.checkpoint_commitment,
        label="domain-reuse-recovery",
        target_settlement_domain=_DOMAIN,
    )
    with pytest.raises(
        ProductionBoundaryError,
        match="database_migration_recovery_domain_reuse",
    ):
        recovery.submit(
            envelope=envelope,
            batch_nonce=nonce,
            submitter=_SUBMITTER,
            evidence=evidence,
            target_governance_authority=_target_authority_for_envelope(envelope),
        )
    assert store.identity_snapshot().sequence == 2
