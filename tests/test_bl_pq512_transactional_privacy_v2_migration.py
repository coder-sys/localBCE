from __future__ import annotations

from dataclasses import dataclass, replace
from hashlib import sha3_512
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from threading import RLock

import pytest

from app.batch.poseidon import FIELD_MODULUS
from app.batch.pq_suite_candidate import CandidateSidecarV1
from app.privacy_v2_migration import (
    PrivacyV2DatabaseIdentity,
    PrivacyV2MigrationTarget,
    TransactionalPrivacyV2Migration,
    build_privacy_v2_migration_evidence,
    derive_migration_nonce,
)
from app.production_boundary import (
    GovernanceAuthorityV2,
    NativeVerificationResult,
    ProductionBoundaryError,
    ProductionProofEnvelope,
    SIDECAR_BYTES,
    _BATCH_NONCE_BINDING,
    _SETTLEMENT_DOMAIN_BINDING,
    _digest,
    build_v2_public_fields,
)
from app.transactional_database_boundary import (
    InMemoryAntiRollbackReference,
    SQLiteSettlementStoreV2,
    TransactionalSettlementV2,
)
from experiments.bl_pq512_crypto_foundation.production_candidate import (
    PROOF_PACKAGE_BYTES,
    PROOF_PACKAGE_COMMITMENT_DOMAIN,
    TRANSCRIPT_COMMITMENT_DOMAIN,
    NativeVerificationReceipt,
    statement_commitment,
)


def _wide(label: str) -> bytes:
    return sha3_512(label.encode("ascii")).digest()


def _field(label: str) -> bytes:
    value = int.from_bytes(_wide(label), "big") % (FIELD_MODULUS - 1) + 1
    return value.to_bytes(32, "big")


_DOMAIN = _field("migration-domain")
_ROLLBACK_DOMAIN = _field("migration-rollback-domain")
_RECOVERY_DOMAIN = _field("migration-recovery-domain")
def _authority_for_epoch(epoch: int) -> GovernanceAuthorityV2:
    return GovernanceAuthorityV2(
        profile_code=((epoch - 1) % 3) + 1,
        epoch=epoch,
        claim_truth_roots_512=tuple(
            _wide(f"migration-truth-{index}") for index in range(6)
        ),
        claim_truth_authority_digest_512=_wide("migration-truth-authority"),
        nullifier_authority_id_512=_wide("migration-nullifier-authority"),
        pepper_commitment_512=_wide("migration-pepper"),
    )


_ROOTS = _authority_for_epoch(1)
_SUBMITTER = _wide("migration-submitter")
_NULLIFIER_0 = _wide("migration-nullifier-0")
_NULLIFIER_1 = _wide("migration-nullifier-1")
_NULLIFIER_2 = _wide("migration-nullifier-2")
_PAYMENT_0 = _wide("migration-payment-0")
_PAYMENT_1 = _wide("migration-payment-1")
_PAYMENT_2 = _wide("migration-payment-2")


@dataclass(frozen=True)
class _Config:
    profile: bytes
    suite: bytes
    schema: bytes
    verifier: bytes


def _config(label: str) -> _Config:
    return _Config(
        profile=_wide(label + "-profile"),
        suite=_wide(label + "-suite"),
        schema=_wide(label + "-schema"),
        verifier=_wide(label + "-verifier"),
    )


_OLD = _config("migration-old")
_NEW = _config("migration-new")


class _ReceiptVerifier:
    """Synthetic receipt builder; it is deliberately not a native verifier."""

    def __init__(self) -> None:
        self._lock = RLock()
        self.calls = 0

    def verify(self, envelope: ProductionProofEnvelope) -> NativeVerificationResult:
        with self._lock:
            self.calls += 1
        receipt = NativeVerificationReceipt(
            proof_suite_id=envelope.suite_id,
            schema_id=envelope.schema_id,
            verifier_artifact_identity=envelope.verifier_artifact_identity,
            envelope_commitment=sha3_512(envelope.encode()).digest(),
            statement_commitment=statement_commitment(
                envelope.public_outputs, envelope.sidecar
            ),
            evidence_commitment=envelope.evidence_commitment,
            proof_package_commitment=sha3_512(
                PROOF_PACKAGE_COMMITMENT_DOMAIN + envelope.proof_package
            ).digest(),
            transcript_commitment=sha3_512(
                TRANSCRIPT_COMMITMENT_DOMAIN + envelope.transcript_evidence
            ).digest(),
        )
        return NativeVerificationResult(
            receipt=receipt,
            envelope_commitment=receipt.envelope_commitment,
            statement_commitment=receipt.statement_commitment,
        )


class _FinalizeGateAnchor:
    def __init__(self) -> None:
        self._delegate = InMemoryAntiRollbackReference()
        self.fail_finalize = False

    def snapshot(self) -> object:
        return self._delegate.snapshot()

    def initialize(self, epoch: int, state_binding: bytes) -> None:
        self._delegate.initialize(epoch, state_binding)

    def prepare(self, **values: object) -> None:
        self._delegate.prepare(**values)  # type: ignore[arg-type]

    def finalize(self, **values: object) -> None:
        if self.fail_finalize:
            raise RuntimeError("injected_anchor_finalize_failure")
        self._delegate.finalize(**values)  # type: ignore[arg-type]


def _store(
    path: Path,
    *,
    config: _Config = _OLD,
    epoch: int = 1,
    settlement_domain: bytes = _DOMAIN,
    anti_rollback: object | None = None,
    before_commit_hook: object | None = None,
) -> SQLiteSettlementStoreV2:
    return SQLiteSettlementStoreV2(
        path=path,
        settlement_domain=settlement_domain,
        governance_authority=_authority_for_epoch(epoch),
        initial_strong_nullifier_root=_NULLIFIER_0,
        initial_strong_payment_state_root=_PAYMENT_0,
        epoch=epoch,
        profile_id=config.profile,
        suite_id=config.suite,
        schema_id=config.schema,
        verifier_artifact_identity=config.verifier,
        anti_rollback=anti_rollback,  # type: ignore[arg-type]
        before_commit_hook=before_commit_hook,  # type: ignore[arg-type]
    )


def _sidecar(
    *,
    source: PrivacyV2DatabaseIdentity,
    target_config: _Config,
    nullifier_after: bytes,
    payment_after: bytes,
    batch_commitment: bytes,
    settlement_domain: bytes = _DOMAIN,
) -> bytes:
    return CandidateSidecarV1(
        profile_id=target_config.profile,
        proof_suite_id=target_config.suite,
        schema_id=target_config.schema,
        verifier_artifact_identity=target_config.verifier,
        strong_settlement_domain_id=_digest(
            _SETTLEMENT_DOMAIN_BINDING, settlement_domain
        ),
        epoch=source.epoch + 1,
        sequence_before=source.sequence,
        sequence_after=source.sequence + 1,
        strong_nullifier_root_before=source.strong_nullifier_root,
        strong_nullifier_root_after=nullifier_after,
        strong_governance_commitment=_authority_for_epoch(source.epoch + 1).commitment_512,
        strong_payment_state_root_before=source.strong_payment_state_root,
        strong_payment_state_root_after=payment_after,
        strong_batch_commitment=batch_commitment,
    ).encode()


def _migration_inputs(
    coordinator: TransactionalPrivacyV2Migration,
    *,
    target_config: _Config = _NEW,
    nullifier_after: bytes = _NULLIFIER_1,
    payment_after: bytes = _PAYMENT_1,
    kind: str = "MIGRATION",
    known_target_checkpoint: bytes | None = None,
    label: str = "migration",
    old_private_records: tuple[bytes, ...] = (b"old-private-record",),
    new_private_records: tuple[bytes, ...] = (b"new-private-record",),
    semantic_records: tuple[bytes, ...] = (b"same-private-semantics",),
    new_semantic_records: tuple[bytes, ...] | None = None,
    target_settlement_domain: bytes = _DOMAIN,
) -> tuple[ProductionProofEnvelope, bytes, object]:
    source = coordinator.source_identity
    provisional = _sidecar(
        source=source,
        target_config=target_config,
        nullifier_after=nullifier_after,
        payment_after=payment_after,
        batch_commitment=_wide(label + "-provisional-batch"),
        settlement_domain=target_settlement_domain,
    )
    target = PrivacyV2MigrationTarget.from_sidecar(
        CandidateSidecarV1.decode(provisional),
        settlement_domain=target_settlement_domain,
        governance_authority=_authority_for_epoch(source.epoch + 1),
    )
    evidence = build_privacy_v2_migration_evidence(
        kind=kind,
        migration_version="privacy-v2-" + label,
        source=source,
        target=target,
        old_private_records=old_private_records,
        new_private_records=new_private_records,
        old_semantic_records=semantic_records,
        new_semantic_records=(
            semantic_records if new_semantic_records is None else new_semantic_records
        ),
        known_target_checkpoint=known_target_checkpoint,
    )
    nonce = derive_migration_nonce(source, target, evidence)
    sidecar = _sidecar(
        source=source,
        target_config=target_config,
        nullifier_after=nullifier_after,
        payment_after=payment_after,
        batch_commitment=_digest(_BATCH_NONCE_BINDING, nonce),
        settlement_domain=target_settlement_domain,
    )
    fields = build_v2_public_fields(
        settlement_domain=target_settlement_domain,
        batch_nonce=nonce,
        sidecar=sidecar,
        governance_authority=_authority_for_epoch(source.epoch + 1),
        suite_id=target_config.suite,
        schema_id=target_config.schema,
        verifier_artifact_identity=target_config.verifier,
    )
    envelope = ProductionProofEnvelope(
        suite_id=target_config.suite,
        schema_id=target_config.schema,
        verifier_artifact_identity=target_config.verifier,
        public_outputs=b"".join(fields),
        sidecar=sidecar,
        proof_package=_wide(label + "-synthetic-proof"),
        transcript_evidence=_wide(label + "-synthetic-transcript"),
        evidence_commitment=evidence.commitment,
    )
    return envelope, nonce, evidence


def _coordinator(
    store: SQLiteSettlementStoreV2,
    verifier: _ReceiptVerifier,
    *,
    settlement_domain: bytes = _DOMAIN,
) -> TransactionalPrivacyV2Migration:
    return TransactionalPrivacyV2Migration(
        verifier=verifier,
        storage=store,
        settlement_domain=settlement_domain,
        governance_authority=store.identity_snapshot().governance_authority,
        authorized_submitters=(_SUBMITTER,),
    )


def _target_authority_for_envelope(
    envelope: ProductionProofEnvelope,
) -> GovernanceAuthorityV2:
    return _authority_for_epoch(CandidateSidecarV1.decode(envelope.sidecar).epoch)


def _settlement_envelope(
    identity: PrivacyV2DatabaseIdentity,
    *,
    settlement_domain: bytes = _DOMAIN,
) -> tuple[ProductionProofEnvelope, bytes]:
    nonce = _field("post-cutover-settlement-nonce")
    sidecar = CandidateSidecarV1(
        profile_id=identity.profile_id,
        proof_suite_id=identity.suite_id,
        schema_id=identity.schema_id,
        verifier_artifact_identity=identity.verifier_artifact_identity,
        strong_settlement_domain_id=_digest(
            _SETTLEMENT_DOMAIN_BINDING, settlement_domain
        ),
        epoch=identity.epoch,
        sequence_before=identity.sequence,
        sequence_after=identity.sequence + 1,
        strong_nullifier_root_before=identity.strong_nullifier_root,
        strong_nullifier_root_after=_NULLIFIER_2,
        strong_governance_commitment=identity.governance_authority.commitment_512,
        strong_payment_state_root_before=identity.strong_payment_state_root,
        strong_payment_state_root_after=_PAYMENT_2,
        strong_batch_commitment=_digest(_BATCH_NONCE_BINDING, nonce),
    ).encode()
    fields = build_v2_public_fields(
        settlement_domain=settlement_domain,
        batch_nonce=nonce,
        sidecar=sidecar,
        governance_authority=identity.governance_authority,
        suite_id=identity.suite_id,
        schema_id=identity.schema_id,
        verifier_artifact_identity=identity.verifier_artifact_identity,
    )
    return (
        ProductionProofEnvelope(
            suite_id=identity.suite_id,
            schema_id=identity.schema_id,
            verifier_artifact_identity=identity.verifier_artifact_identity,
            public_outputs=b"".join(fields),
            sidecar=sidecar,
            proof_package=_wide("post-cutover-synthetic-proof"),
            transcript_evidence=_wide("post-cutover-synthetic-transcript"),
            evidence_commitment=_wide("post-cutover-synthetic-evidence"),
        ),
        nonce,
    )


def test_native_verified_migration_is_atomic_fixed_shape_and_exactly_retryable(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "ledger.sqlite3")
    verifier = _ReceiptVerifier()
    coordinator = _coordinator(store, verifier)
    envelope, nonce, evidence = _migration_inputs(coordinator)

    first = coordinator.submit(
        envelope=envelope, batch_nonce=nonce, submitter=_SUBMITTER, evidence=evidence,
        target_governance_authority=_target_authority_for_envelope(envelope),
    )
    second = coordinator.submit(
        envelope=envelope, batch_nonce=nonce, submitter=_SUBMITTER, evidence=evidence,
        target_governance_authority=_target_authority_for_envelope(envelope),
    )

    assert first == second
    assert verifier.calls == 2
    assert len(envelope.public_outputs) == 12 * 32
    assert len(envelope.sidecar) == SIDECAR_BYTES == 744
    identity = store.identity_snapshot()
    assert identity.sequence == identity.anti_rollback_epoch == 1
    assert identity.epoch == 2
    assert identity.governance_authority == _authority_for_epoch(2)
    assert identity.governance_commitment == _authority_for_epoch(2).commitment_512
    assert identity.governance_commitment != coordinator.source_identity.governance_commitment
    assert identity.settled_batch_count == 0
    assert (identity.profile_id, identity.suite_id, identity.schema_id) == (
        _NEW.profile,
        _NEW.suite,
        _NEW.schema,
    )
    assert identity.strong_nullifier_root == _NULLIFIER_1
    assert identity.strong_payment_state_root == _PAYMENT_1
    with sqlite3.connect(store.path) as connection:
        assert connection.execute(
            "SELECT activation_sequence, profile_code, epoch FROM governance_authorities "
            "ORDER BY activation_sequence"
        ).fetchall() == [(0, 1, 1), (1, 2, 2)]
    store.verify_integrity()


def test_restart_backup_recovery_and_new_profile_settlement_after_cutover(
    tmp_path: Path,
) -> None:
    database = tmp_path / "ledger.sqlite3"
    backup = tmp_path / "ledger.backup.sqlite3"
    recovered_path = tmp_path / "ledger.recovered.sqlite3"
    store = _store(database)
    coordinator = _coordinator(store, _ReceiptVerifier())
    envelope, nonce, evidence = _migration_inputs(coordinator)
    coordinator.submit(
        envelope=envelope, batch_nonce=nonce, submitter=_SUBMITTER, evidence=evidence,
        target_governance_authority=_target_authority_for_envelope(envelope),
    )
    store.create_backup(backup)
    store.close()

    restarted = _store(database, config=_NEW, epoch=2)
    recovered = restarted.recover_from_backup(
        backup_path=backup, recovered_path=recovered_path
    )
    assert recovered.identity_snapshot() == restarted.identity_snapshot()
    recovered.verify_integrity()
    recovered.close()

    identity = restarted.identity_snapshot()
    settlement_envelope, settlement_nonce = _settlement_envelope(identity)
    settlement = TransactionalSettlementV2(
        verifier=_ReceiptVerifier(),
        storage=restarted,
        settlement_domain=_DOMAIN,
        governance_authority=identity.governance_authority,
        authorized_submitters=(_SUBMITTER,),
    )
    receipt = settlement.submit(
        envelope=settlement_envelope,
        batch_nonce=settlement_nonce,
        submitter=_SUBMITTER,
    )
    final = restarted.identity_snapshot()
    assert receipt.sequence_after == final.sequence == 2
    assert final.epoch == 2
    assert final.settled_batch_count == 1
    assert final.strong_nullifier_root == _NULLIFIER_2
    assert final.strong_payment_state_root == _PAYMENT_2
    restarted.verify_integrity()


def test_exact_pre_cutover_settlement_retry_survives_governance_rotation(
    tmp_path: Path,
) -> None:
    path = tmp_path / "ledger.sqlite3"
    store = _store(path)
    source_identity = store.identity_snapshot()
    old_envelope, old_nonce = _settlement_envelope(source_identity)
    settlement = TransactionalSettlementV2(
        verifier=_ReceiptVerifier(),
        storage=store,
        settlement_domain=_DOMAIN,
        governance_authority=source_identity.governance_authority,
        authorized_submitters=(_SUBMITTER,),
    )
    original = settlement.submit(
        envelope=old_envelope,
        batch_nonce=old_nonce,
        submitter=_SUBMITTER,
    )

    migration = _coordinator(store, _ReceiptVerifier())
    migration_envelope, migration_nonce, evidence = _migration_inputs(
        migration,
        nullifier_after=_wide("migration-after-settlement-nullifier"),
        payment_after=_wide("migration-after-settlement-payment"),
        label="after-settlement",
    )
    migration.submit(
        envelope=migration_envelope,
        batch_nonce=migration_nonce,
        submitter=_SUBMITTER,
        evidence=evidence,
        target_governance_authority=_target_authority_for_envelope(
            migration_envelope
        ),
    )
    after_migration = store.identity_snapshot()
    store.close()

    restarted = _store(path, config=_NEW, epoch=2)
    retry_settlement = TransactionalSettlementV2(
        verifier=_ReceiptVerifier(),
        storage=restarted,
        settlement_domain=_DOMAIN,
        governance_authority=restarted.identity_snapshot().governance_authority,
        authorized_submitters=(_SUBMITTER,),
    )

    retry = retry_settlement.submit(
        envelope=old_envelope,
        batch_nonce=old_nonce,
        submitter=_SUBMITTER,
    )
    assert retry == original
    assert restarted.identity_snapshot() == after_migration

    conflicting = replace(
        old_envelope,
        evidence_commitment=_wide("conflicting-old-settlement-evidence"),
    )
    with pytest.raises(ProductionBoundaryError, match="database_conflicting_retry"):
        retry_settlement.submit(
            envelope=conflicting,
            batch_nonce=old_nonce,
            submitter=_SUBMITTER,
        )
    assert restarted.identity_snapshot() == after_migration
    restarted.verify_integrity()


def test_precommit_failure_rolls_back_database_and_retry_commits_once(
    tmp_path: Path,
) -> None:
    fail = {"enabled": True}

    def hook() -> None:
        if fail["enabled"]:
            raise RuntimeError("injected_precommit_failure")

    anchor = InMemoryAntiRollbackReference()
    store = _store(
        tmp_path / "ledger.sqlite3",
        anti_rollback=anchor,
        before_commit_hook=hook,
    )
    before = store.identity_snapshot()
    coordinator = _coordinator(store, _ReceiptVerifier())
    envelope, nonce, evidence = _migration_inputs(coordinator)

    with pytest.raises(RuntimeError, match="injected_precommit_failure"):
        coordinator.submit(
            envelope=envelope,
            batch_nonce=nonce,
            submitter=_SUBMITTER,
            evidence=evidence,
            target_governance_authority=_target_authority_for_envelope(envelope),
        )
    assert store.identity_snapshot() == before
    assert anchor.snapshot() is not None and anchor.snapshot().pending is not None

    fail["enabled"] = False
    coordinator.submit(
        envelope=envelope, batch_nonce=nonce, submitter=_SUBMITTER, evidence=evidence,
        target_governance_authority=_target_authority_for_envelope(envelope),
    )
    assert store.identity_snapshot().sequence == 1
    assert anchor.snapshot() is not None and anchor.snapshot().pending is None
    store.verify_integrity()


def test_committed_anchor_pending_is_reconciled_on_restart(tmp_path: Path) -> None:
    path = tmp_path / "ledger.sqlite3"
    anchor = _FinalizeGateAnchor()
    store = _store(path, anti_rollback=anchor)
    coordinator = _coordinator(store, _ReceiptVerifier())
    envelope, nonce, evidence = _migration_inputs(coordinator, label="anchor-crash")
    anchor.fail_finalize = True

    with pytest.raises(
        ProductionBoundaryError, match="database_migration_committed_anchor_pending"
    ):
        coordinator.submit(
            envelope=envelope,
            batch_nonce=nonce,
            submitter=_SUBMITTER,
            evidence=evidence,
            target_governance_authority=_target_authority_for_envelope(envelope),
        )
    committed = store.identity_snapshot()
    assert committed.sequence == 1
    assert anchor.snapshot() is not None and anchor.snapshot().pending is not None
    store.close()

    anchor.fail_finalize = False
    restarted = _store(path, config=_NEW, epoch=2, anti_rollback=anchor)
    assert restarted.identity_snapshot() == committed
    assert anchor.snapshot() is not None and anchor.snapshot().pending is None
    retry = _coordinator(restarted, _ReceiptVerifier()).submit(
        envelope=envelope,
        batch_nonce=nonce,
        submitter=_SUBMITTER,
        evidence=evidence,
        target_governance_authority=_target_authority_for_envelope(envelope),
    )
    assert retry.sequence_after == committed.sequence
    restarted.verify_integrity()


def test_committed_migration_exact_retry_survives_process_restart(
    tmp_path: Path,
) -> None:
    path = tmp_path / "ledger.sqlite3"
    store = _store(path)
    verifier = _ReceiptVerifier()
    coordinator = _coordinator(store, verifier)
    envelope, nonce, evidence = _migration_inputs(coordinator, label="restart-retry")
    envelope = replace(
        envelope,
        proof_package=b"BLPQSPK1\x00\x02"
        + bytes(PROOF_PACKAGE_BYTES - len(b"BLPQSPK1\x00\x02")),
    )
    first = coordinator.submit(
        envelope=envelope,
        batch_nonce=nonce,
        submitter=_SUBMITTER,
        evidence=evidence,
        target_governance_authority=_target_authority_for_envelope(envelope),
    )
    store.close()
    envelope_path = tmp_path / "retry-envelope.bin"
    payload_path = tmp_path / "retry-evidence.json"
    envelope_path.write_bytes(envelope.encode())
    payload_path.write_text(
        json.dumps(
            {
                "kind": evidence.kind,
                "version": evidence.version_commitment.hex(),
                "equivalence": evidence.equivalence_commitment.hex(),
                "source": evidence.source_checkpoint_commitment.hex(),
                "target": evidence.target_state_commitment.hex(),
                "known": (
                    None
                    if evidence.known_target_checkpoint is None
                    else evidence.known_target_checkpoint.hex()
                ),
                "native_evidence": envelope.evidence_commitment.hex(),
                "nonce": nonce.hex(),
                "submitter": _SUBMITTER.hex(),
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="ascii",
    )
    script = """
import json
from pathlib import Path
import sys
from app.privacy_v2_migration import PrivacyV2MigrationEvidence
from experiments.bl_pq512_crypto_foundation.production_candidate import ProductionProofEnvelope
from tests.test_bl_pq512_transactional_privacy_v2_migration import _NEW, _ReceiptVerifier, _coordinator, _store, _target_authority_for_envelope

database_path, envelope_path, payload_path = map(Path, sys.argv[1:4])
payload = json.loads(payload_path.read_text(encoding="ascii"))
evidence = PrivacyV2MigrationEvidence(
    kind=payload["kind"],
    version_commitment=bytes.fromhex(payload["version"]),
    equivalence_commitment=bytes.fromhex(payload["equivalence"]),
    source_checkpoint_commitment=bytes.fromhex(payload["source"]),
    target_state_commitment=bytes.fromhex(payload["target"]),
    known_target_checkpoint=(
        None if payload["known"] is None else bytes.fromhex(payload["known"])
    ),
)
envelope = ProductionProofEnvelope.decode(
    envelope_path.read_bytes(),
    evidence_commitment=bytes.fromhex(payload["native_evidence"]),
)
store = _store(database_path, config=_NEW, epoch=2)
receipt = _coordinator(store, _ReceiptVerifier()).submit(
    envelope=envelope,
    batch_nonce=bytes.fromhex(payload["nonce"]),
    submitter=bytes.fromhex(payload["submitter"]),
    evidence=evidence,
    target_governance_authority=_target_authority_for_envelope(envelope),
)
store.verify_integrity()
print(json.dumps({
    "sequence_after": receipt.sequence_after,
    "migration_commitment": receipt.migration_commitment.hex(),
    "database_sequence": store.identity_snapshot().sequence,
}, sort_keys=True, separators=(",", ":")))
"""
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            script,
            str(path),
            str(envelope_path),
            str(payload_path),
        ],
        cwd=Path(__file__).resolve().parents[1],
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, (completed.stdout, completed.stderr)
    result = json.loads(completed.stdout.strip())
    assert result == {
        "database_sequence": 1,
        "migration_commitment": first.migration_commitment.hex(),
        "sequence_after": first.sequence_after,
    }
    restarted = _store(path, config=_NEW, epoch=2)
    assert restarted.identity_snapshot().sequence == 1
    restarted.verify_integrity()


def test_rollback_and_recovery_require_known_checkpoint_and_fresh_identity(
    tmp_path: Path,
) -> None:
    path = tmp_path / "ledger.sqlite3"
    store = _store(path)
    genesis = store.identity_snapshot()

    migration = _coordinator(store, _ReceiptVerifier())
    envelope, nonce, evidence = _migration_inputs(migration, label="forward")
    migration.submit(
        envelope=envelope, batch_nonce=nonce, submitter=_SUBMITTER, evidence=evidence,
        target_governance_authority=_target_authority_for_envelope(envelope),
    )
    forward = store.identity_snapshot()
    store.close()

    rollback_config = _config("migration-rollback-fresh")
    store = _store(path, config=_NEW, epoch=2)
    rollback = _coordinator(
        store,
        _ReceiptVerifier(),
        settlement_domain=_ROLLBACK_DOMAIN,
    )
    envelope, nonce, evidence = _migration_inputs(
        rollback,
        target_config=rollback_config,
        nullifier_after=_NULLIFIER_0,
        payment_after=_PAYMENT_0,
        kind="ROLLBACK",
        known_target_checkpoint=genesis.checkpoint_commitment,
        label="rollback",
        target_settlement_domain=_ROLLBACK_DOMAIN,
    )
    rollback.submit(
        envelope=envelope, batch_nonce=nonce, submitter=_SUBMITTER, evidence=evidence,
        target_governance_authority=_target_authority_for_envelope(envelope),
    )
    rolled_back = store.identity_snapshot()
    assert rolled_back.epoch == 3 and rolled_back.sequence == 2
    assert (
        rolled_back.settlement_domain_commitment
        != forward.settlement_domain_commitment
    )
    assert rolled_back.strong_nullifier_root == genesis.strong_nullifier_root
    assert rolled_back.profile_id not in {genesis.profile_id, forward.profile_id}
    store.close()

    recovery_config = _config("migration-recovery-fresh")
    store = _store(
        path,
        config=rollback_config,
        epoch=3,
        settlement_domain=_ROLLBACK_DOMAIN,
    )
    recovery = _coordinator(
        store,
        _ReceiptVerifier(),
        settlement_domain=_RECOVERY_DOMAIN,
    )
    envelope, nonce, evidence = _migration_inputs(
        recovery,
        target_config=recovery_config,
        nullifier_after=_NULLIFIER_1,
        payment_after=_PAYMENT_1,
        kind="RECOVERY",
        known_target_checkpoint=forward.checkpoint_commitment,
        label="recovery",
        target_settlement_domain=_RECOVERY_DOMAIN,
    )
    recovery.submit(
        envelope=envelope, batch_nonce=nonce, submitter=_SUBMITTER, evidence=evidence,
        target_governance_authority=_target_authority_for_envelope(envelope),
    )
    recovered = store.identity_snapshot()
    assert recovered.epoch == 4 and recovered.sequence == 3
    assert (
        recovered.settlement_domain_commitment
        != rolled_back.settlement_domain_commitment
    )
    assert recovered.strong_nullifier_root == forward.strong_nullifier_root
    assert recovered.strong_payment_state_root == forward.strong_payment_state_root
    assert recovered.profile_id not in {
        genesis.profile_id,
        forward.profile_id,
        rolled_back.profile_id,
    }
    assert recovered.settled_batch_count == 0
    store.verify_integrity()


def test_obsolete_schema_is_rejected_without_silent_governance_upgrade(
    tmp_path: Path,
) -> None:
    path = tmp_path / "ledger.sqlite3"
    store = _store(path)
    store.close()

    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA ignore_check_constraints=ON")
        connection.execute("UPDATE metadata SET schema_version=2 WHERE id=1")
        connection.commit()

    with pytest.raises(
        ProductionBoundaryError,
        match="database_legacy_governance_schema_rejected",
    ):
        _store(path)
    with sqlite3.connect(path) as connection:
        assert connection.execute(
            "SELECT schema_version FROM metadata WHERE id=1"
        ).fetchone() == (2,)
        assert connection.execute(
            "SELECT COUNT(*) FROM governance_authorities"
        ).fetchone() == (1,)
