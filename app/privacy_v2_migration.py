"""Proof-authorized Privacy V2 database migration boundary.

This is a local, nonactivating Phase 2 boundary.  It binds a native-verified
12-field/744-byte proof envelope to one exact database identity transition.
Only commitments cross the public migration/audit seam; private canonical
records are consumed solely while building reference equivalence evidence.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field, replace
import hashlib
import hmac
import json
import secrets
from typing import Final, Protocol

from app.batch.pq_suite_candidate import CandidateSidecarV1
from app.production_boundary import (
    GovernedRootsV2,
    NativeVerificationResult,
    PUBLIC_FIELD_BYTES,
    ProductionBoundaryError,
    ProductionProofEnvelope,
    VerifiedSettlementOperationV2,
    _BATCH_NONCE_BINDING,
    _SETTLEMENT_DOMAIN_BINDING,
    _digest,
    _field,
    _field_alias,
    _sidecar,
    _verified_operation_seal,
    _wide,
    public_fields_commitment,
    validate_v2_public_projection,
)
from experiments.bl_pq512_crypto_foundation.production_candidate import (
    PROOF_PACKAGE_COMMITMENT_DOMAIN,
    TRANSCRIPT_COMMITMENT_DOMAIN,
    NativeVerificationReceipt,
    statement_commitment,
)


STATUS: Final[str] = "LB007_PRIVACY_V2_MIGRATION_LOCAL_NONACTIVATING"
PROOF_SUITE_ID: None = None
PRODUCTION_USABLE: Final[bool] = False
ACTIVATION_ALLOWED: Final[bool] = False
MIGRATION_KINDS: Final[frozenset[str]] = frozenset(
    {"MIGRATION", "ROLLBACK", "RECOVERY"}
)

_CHECKPOINT_DOMAIN = b"BL/PQ512/V2/DATABASE-CHECKPOINT/v1\x00"
_TARGET_STATE_DOMAIN = b"BL/PQ512/V2/MIGRATION-TARGET/v1\x00"
_EQUIVALENCE_DOMAIN = b"BL/PQ512/V2/MIGRATION-EQUIVALENCE/v1\x00"
_PRIVATE_RECORD_DOMAIN = b"BL/PQ512/V2/MIGRATION-PRIVATE-RECORD/v1\x00"
_SEMANTIC_RECORD_DOMAIN = b"BL/PQ512/V2/MIGRATION-SEMANTIC-RECORD/v1\x00"
_MIGRATION_NONCE_DOMAIN = b"BL/PQ512/V2/MIGRATION-NONCE/v1\x00"
_MIGRATION_OPERATION_DOMAIN = b"BL/PQ512/V2/MIGRATION-OPERATION/v1\x00"
_MIGRATION_SEAL_DOMAIN = b"BL/PQ512/V2/MIGRATION-SEAL/v1\x00"
_MIGRATION_EVIDENCE_PROVENANCE_DOMAIN = (
    b"BL/PQ512/V2/MIGRATION-EVIDENCE-PROVENANCE/v1\x00"
)
_MIGRATION_VERSION_DOMAIN = b"BL/PQ512/V2/MIGRATION-VERSION/v1\x00"
_SETTLEMENT_DOMAIN_COMMITMENT = b"BL/PQ512/V2/DATABASE-DOMAIN/v1\x00"
_MAX_PRIVATE_RECORD_BYTES: Final[int] = 1 << 20
_MAX_PRIVATE_RECORDS: Final[int] = 4096


def _new_runtime_authority_key() -> bytes:
    for _ in range(4):
        value = secrets.token_bytes(64)
        if value != bytes(64):
            return value
    raise ProductionBoundaryError("migration_entropy_failure")


_EVIDENCE_RUNTIME_AUTHORITY_KEY: Final[bytes] = _new_runtime_authority_key()


def _u64(value: object, label: str) -> bytes:
    if type(value) is not int or value < 0 or value >= 2**64:
        raise ProductionBoundaryError(f"migration_{label}_invalid")
    return value.to_bytes(8, "big")


def _kind(value: object) -> str:
    if type(value) is not str or value not in MIGRATION_KINDS:
        raise ProductionBoundaryError("migration_kind_invalid")
    return value


def migration_version_commitment(value: object) -> bytes:
    if type(value) is not str or not value or len(value) > 128:
        raise ProductionBoundaryError("migration_version_invalid")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ProductionBoundaryError("migration_version_not_ascii") from exc
    if b"\x00" in encoded:
        raise ProductionBoundaryError("migration_version_nul")
    return _digest(_MIGRATION_VERSION_DOMAIN, encoded)


@dataclass(frozen=True, slots=True)
class PrivacyV2DatabaseIdentity:
    """Exact current database identity and authoritative committed state."""

    settlement_domain_commitment: bytes
    governance_commitment: bytes
    profile_id: bytes
    suite_id: bytes
    schema_id: bytes
    verifier_artifact_identity: bytes
    epoch: int
    sequence: int
    strong_nullifier_root: bytes
    strong_payment_state_root: bytes
    state_binding: bytes
    audit_head: bytes
    anti_rollback_epoch: int
    settled_batch_count: int

    def __post_init__(self) -> None:
        for label, value in (
            ("identity_settlement_domain", self.settlement_domain_commitment),
            ("identity_governance", self.governance_commitment),
            ("identity_profile", self.profile_id),
            ("identity_suite", self.suite_id),
            ("identity_schema", self.schema_id),
            ("identity_verifier", self.verifier_artifact_identity),
            ("identity_nullifier", self.strong_nullifier_root),
            ("identity_payment", self.strong_payment_state_root),
            ("identity_state_binding", self.state_binding),
            ("identity_audit_head", self.audit_head),
        ):
            _wide(label, value)
        _u64(self.epoch, "identity_epoch")
        if self.epoch == 0:
            raise ProductionBoundaryError("migration_identity_epoch_invalid")
        _u64(self.sequence, "identity_sequence")
        _u64(self.anti_rollback_epoch, "identity_anti_rollback_epoch")
        _u64(self.settled_batch_count, "identity_settled_batch_count")
        if self.anti_rollback_epoch != self.sequence:
            raise ProductionBoundaryError("migration_identity_anti_rollback_mismatch")
        if self.settled_batch_count > self.sequence:
            raise ProductionBoundaryError("migration_identity_count_invalid")

    @property
    def checkpoint_commitment(self) -> bytes:
        return _digest(
            _CHECKPOINT_DOMAIN,
            self.settlement_domain_commitment,
            self.governance_commitment,
            self.profile_id,
            self.suite_id,
            self.schema_id,
            self.verifier_artifact_identity,
            _u64(self.epoch, "identity_epoch"),
            _u64(self.sequence, "identity_sequence"),
            self.strong_nullifier_root,
            self.strong_payment_state_root,
            self.state_binding,
            self.audit_head,
            _u64(self.anti_rollback_epoch, "identity_anti_rollback_epoch"),
            _u64(self.settled_batch_count, "identity_settled_batch_count"),
        )


@dataclass(frozen=True, slots=True)
class PrivacyV2MigrationTarget:
    settlement_domain_commitment: bytes
    profile_id: bytes
    suite_id: bytes
    schema_id: bytes
    verifier_artifact_identity: bytes
    epoch: int
    sequence_before: int
    sequence_after: int
    strong_nullifier_root_before: bytes
    strong_nullifier_root_after: bytes
    strong_payment_state_root_before: bytes
    strong_payment_state_root_after: bytes
    governance_commitment: bytes

    def __post_init__(self) -> None:
        for label, value in (
            ("target_settlement_domain", self.settlement_domain_commitment),
            ("target_profile", self.profile_id),
            ("target_suite", self.suite_id),
            ("target_schema", self.schema_id),
            ("target_verifier", self.verifier_artifact_identity),
            ("target_nullifier_before", self.strong_nullifier_root_before),
            ("target_nullifier_after", self.strong_nullifier_root_after),
            ("target_payment_before", self.strong_payment_state_root_before),
            ("target_payment_after", self.strong_payment_state_root_after),
            ("target_governance", self.governance_commitment),
        ):
            _wide(label, value)
        _u64(self.epoch, "target_epoch")
        if self.epoch == 0:
            raise ProductionBoundaryError("migration_target_epoch_invalid")
        _u64(self.sequence_before, "target_sequence_before")
        _u64(self.sequence_after, "target_sequence_after")
        if self.sequence_after != self.sequence_before + 1:
            raise ProductionBoundaryError("migration_target_sequence_invalid")

    @classmethod
    def from_sidecar(
        cls,
        sidecar: CandidateSidecarV1,
        *,
        settlement_domain: bytes,
    ) -> "PrivacyV2MigrationTarget":
        if type(sidecar) is not CandidateSidecarV1:
            raise TypeError("migration_sidecar_required")
        domain = _field("migration_target_settlement_domain", settlement_domain, nonzero=True)
        if sidecar.strong_settlement_domain_id != _digest(
            _SETTLEMENT_DOMAIN_BINDING, domain
        ):
            raise ProductionBoundaryError("migration_target_settlement_domain_mismatch")
        return cls(
            settlement_domain_commitment=_digest(_SETTLEMENT_DOMAIN_COMMITMENT, domain),
            profile_id=sidecar.profile_id,
            suite_id=sidecar.proof_suite_id,
            schema_id=sidecar.schema_id,
            verifier_artifact_identity=sidecar.verifier_artifact_identity,
            epoch=sidecar.epoch,
            sequence_before=sidecar.sequence_before,
            sequence_after=sidecar.sequence_after,
            strong_nullifier_root_before=sidecar.strong_nullifier_root_before,
            strong_nullifier_root_after=sidecar.strong_nullifier_root_after,
            strong_payment_state_root_before=sidecar.strong_payment_state_root_before,
            strong_payment_state_root_after=sidecar.strong_payment_state_root_after,
            governance_commitment=sidecar.strong_governance_commitment,
        )

    @property
    def target_state_commitment(self) -> bytes:
        return _digest(
            _TARGET_STATE_DOMAIN,
            self.settlement_domain_commitment,
            self.profile_id,
            self.suite_id,
            self.schema_id,
            self.verifier_artifact_identity,
            _u64(self.epoch, "target_epoch"),
            _u64(self.sequence_before, "target_sequence_before"),
            _u64(self.sequence_after, "target_sequence_after"),
            self.strong_nullifier_root_before,
            self.strong_nullifier_root_after,
            self.strong_payment_state_root_before,
            self.strong_payment_state_root_after,
            self.governance_commitment,
        )


@dataclass(frozen=True, slots=True)
class PrivacyV2MigrationEvidence:
    """Public, fixed-shape result of a private reference equivalence check."""

    kind: str
    version_commitment: bytes
    equivalence_commitment: bytes
    source_checkpoint_commitment: bytes
    target_state_commitment: bytes
    known_target_checkpoint: bytes | None = None
    _freshness_seal: bytes = field(
        default=bytes(64),
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        _kind(self.kind)
        for label, value in (
            ("evidence_version", self.version_commitment),
            ("evidence_equivalence", self.equivalence_commitment),
            ("evidence_source_checkpoint", self.source_checkpoint_commitment),
            ("evidence_target_state", self.target_state_commitment),
        ):
            _wide(label, value)
        if self.known_target_checkpoint is not None:
            _wide("evidence_known_target", self.known_target_checkpoint)
        if type(self._freshness_seal) is not bytes or len(self._freshness_seal) != 64:
            raise ProductionBoundaryError("migration_evidence_freshness_seal_invalid")
        if self.kind == "MIGRATION" and self.known_target_checkpoint is not None:
            raise ProductionBoundaryError("migration_unexpected_known_target")
        if self.kind in {"ROLLBACK", "RECOVERY"} and self.known_target_checkpoint is None:
            raise ProductionBoundaryError("migration_known_target_required")

    @property
    def commitment(self) -> bytes:
        known = self.known_target_checkpoint or bytes(64)
        return _digest(
            _EQUIVALENCE_DOMAIN,
            self.kind.encode("ascii"),
            self.version_commitment,
            self.equivalence_commitment,
            self.source_checkpoint_commitment,
            self.target_state_commitment,
            known,
        )

    def as_public_dict(self) -> dict[str, object]:
        return {
            "status": STATUS,
            "kind": self.kind,
            "versionCommitment": self.version_commitment.hex(),
            "equivalenceCommitment": self.equivalence_commitment.hex(),
            "sourceCheckpointCommitment": self.source_checkpoint_commitment.hex(),
            "targetStateCommitment": self.target_state_commitment.hex(),
            "knownTargetCheckpoint": (
                None
                if self.known_target_checkpoint is None
                else self.known_target_checkpoint.hex()
            ),
            "evidenceCommitment": self.commitment.hex(),
            "proofSuiteId": None,
            "activationAllowed": False,
            "productionUsable": False,
        }

    def _has_runtime_randomness_provenance(self) -> bool:
        expected = hmac.new(
            _EVIDENCE_RUNTIME_AUTHORITY_KEY,
            _digest(_MIGRATION_EVIDENCE_PROVENANCE_DOMAIN, self.commitment),
            hashlib.sha3_512,
        ).digest()
        return hmac.compare_digest(self._freshness_seal, expected)


def _authorize_runtime_evidence(
    evidence: PrivacyV2MigrationEvidence,
) -> PrivacyV2MigrationEvidence:
    if type(evidence) is not PrivacyV2MigrationEvidence:
        raise TypeError("migration_evidence_required")
    seal = hmac.new(
        _EVIDENCE_RUNTIME_AUTHORITY_KEY,
        _digest(_MIGRATION_EVIDENCE_PROVENANCE_DOMAIN, evidence.commitment),
        hashlib.sha3_512,
    ).digest()
    return replace(evidence, _freshness_seal=seal)


def _private_records(values: Sequence[bytes] | Iterable[bytes], label: str) -> tuple[bytes, ...]:
    if isinstance(values, (bytes, bytearray, str)):
        raise TypeError(f"migration_{label}_records_required")
    records = tuple(values)
    if not records or len(records) > _MAX_PRIVATE_RECORDS:
        raise ProductionBoundaryError(f"migration_{label}_record_count_invalid")
    for value in records:
        if type(value) is not bytes or not value or len(value) > _MAX_PRIVATE_RECORD_BYTES:
            raise ProductionBoundaryError(f"migration_{label}_record_invalid")
    return records


def _build_privacy_v2_migration_evidence_with_salt(
    *,
    kind: str,
    migration_version: str,
    source: PrivacyV2DatabaseIdentity,
    target: PrivacyV2MigrationTarget,
    old_private_records: Sequence[bytes] | Iterable[bytes],
    new_private_records: Sequence[bytes] | Iterable[bytes],
    old_semantic_records: Sequence[bytes] | Iterable[bytes],
    new_semantic_records: Sequence[bytes] | Iterable[bytes],
    privacy_salt: bytes,
    known_target_checkpoint: bytes | None = None,
) -> PrivacyV2MigrationEvidence:
    """Check exact private semantic equality and return commitments only.

    This is reproducible local equivalence evidence, not the production
    migration theorem.  The native proof binds its resulting commitment.
    """

    migration_kind = _kind(kind)
    if type(source) is not PrivacyV2DatabaseIdentity:
        raise TypeError("migration_source_identity_required")
    if type(target) is not PrivacyV2MigrationTarget:
        raise TypeError("migration_target_identity_required")
    salt = _wide("migration_privacy_salt", privacy_salt)
    if salt == bytes(64):
        raise ProductionBoundaryError("migration_privacy_salt_zero")
    old_private = _private_records(old_private_records, "old_private")
    new_private = _private_records(new_private_records, "new_private")
    old_semantic = _private_records(old_semantic_records, "old_semantic")
    new_semantic = _private_records(new_semantic_records, "new_semantic")
    if not (
        len(old_private)
        == len(new_private)
        == len(old_semantic)
        == len(new_semantic)
    ):
        raise ProductionBoundaryError("migration_private_shape_mismatch")
    if old_semantic != new_semantic:
        raise ProductionBoundaryError("migration_semantic_equivalence_failed")
    private_pairs = tuple(
        _digest(_PRIVATE_RECORD_DOMAIN, salt, old, new)
        for old, new in zip(old_private, new_private, strict=True)
    )
    semantic_pairs = tuple(
        _digest(_SEMANTIC_RECORD_DOMAIN, salt, semantic)
        for semantic in old_semantic
    )
    equivalence = _digest(
        _EQUIVALENCE_DOMAIN,
        salt,
        _digest(_PRIVATE_RECORD_DOMAIN, *private_pairs),
        _digest(_SEMANTIC_RECORD_DOMAIN, *semantic_pairs),
    )
    return PrivacyV2MigrationEvidence(
        kind=migration_kind,
        version_commitment=migration_version_commitment(migration_version),
        equivalence_commitment=equivalence,
        source_checkpoint_commitment=source.checkpoint_commitment,
        target_state_commitment=target.target_state_commitment,
        known_target_checkpoint=known_target_checkpoint,
    )


def build_privacy_v2_migration_evidence(
    *,
    kind: str,
    migration_version: str,
    source: PrivacyV2DatabaseIdentity,
    target: PrivacyV2MigrationTarget,
    old_private_records: Sequence[bytes] | Iterable[bytes],
    new_private_records: Sequence[bytes] | Iterable[bytes],
    old_semantic_records: Sequence[bytes] | Iterable[bytes],
    new_semantic_records: Sequence[bytes] | Iterable[bytes],
    known_target_checkpoint: bytes | None = None,
) -> PrivacyV2MigrationEvidence:
    """Build hidden equivalence evidence with function-owned OS randomness.

    Callers never select the privacy salt.  A deterministic test vector may use
    the private ``_build_privacy_v2_migration_evidence_with_salt`` helper, which
    is deliberately absent from the exported production-facing surface.
    """

    return _authorize_runtime_evidence(
        _build_privacy_v2_migration_evidence_with_salt(
            kind=kind,
            migration_version=migration_version,
            source=source,
            target=target,
            old_private_records=old_private_records,
            new_private_records=new_private_records,
            old_semantic_records=old_semantic_records,
            new_semantic_records=new_semantic_records,
            privacy_salt=generate_migration_privacy_salt(),
            known_target_checkpoint=known_target_checkpoint,
        )
    )


def generate_migration_privacy_salt() -> bytes:
    for _ in range(4):
        value = secrets.token_bytes(64)
        if value != bytes(64):
            return value
    raise ProductionBoundaryError("migration_entropy_failure")


def derive_migration_nonce(
    source: PrivacyV2DatabaseIdentity,
    target: PrivacyV2MigrationTarget,
    evidence: PrivacyV2MigrationEvidence,
) -> bytes:
    if type(source) is not PrivacyV2DatabaseIdentity:
        raise TypeError("migration_source_identity_required")
    if type(target) is not PrivacyV2MigrationTarget:
        raise TypeError("migration_target_identity_required")
    if type(evidence) is not PrivacyV2MigrationEvidence:
        raise TypeError("migration_evidence_required")
    if evidence.source_checkpoint_commitment != source.checkpoint_commitment:
        raise ProductionBoundaryError("migration_evidence_source_mismatch")
    if evidence.target_state_commitment != target.target_state_commitment:
        raise ProductionBoundaryError("migration_evidence_target_mismatch")
    return _field_alias(
        _digest(
            _MIGRATION_NONCE_DOMAIN,
            source.checkpoint_commitment,
            target.target_state_commitment,
            evidence.commitment,
        )
    )


def _migration_operation_digest(
    operation: VerifiedSettlementOperationV2,
    evidence: PrivacyV2MigrationEvidence,
) -> bytes:
    return _digest(
        _MIGRATION_OPERATION_DOMAIN,
        operation.batch_nonce,
        operation.submitter,
        operation.envelope_commitment,
        operation.statement_commitment,
        operation.evidence_commitment,
        operation.proof_package_commitment,
        operation.transcript_commitment,
        operation.public_fields_commitment,
        b"".join(operation.public_fields),
        operation.sidecar,
        operation.profile_id,
        operation.suite_id,
        operation.schema_id,
        operation.verifier_artifact_identity,
        _u64(operation.epoch, "operation_epoch"),
        _u64(operation.sequence_before, "operation_sequence_before"),
        _u64(operation.sequence_after, "operation_sequence_after"),
        operation.strong_nullifier_root_before,
        operation.strong_nullifier_root_after,
        operation.strong_governance_commitment,
        operation.strong_payment_state_root_before,
        operation.strong_payment_state_root_after,
        operation.strong_batch_commitment,
        evidence.commitment,
    )


@dataclass(frozen=True, slots=True)
class VerifiedMigrationOperationV2:
    transition: VerifiedSettlementOperationV2
    evidence: PrivacyV2MigrationEvidence
    source_identity: PrivacyV2DatabaseIdentity
    target: PrivacyV2MigrationTarget
    seal: bytes

    def __post_init__(self) -> None:
        if type(self.transition) is not VerifiedSettlementOperationV2:
            raise TypeError("migration_transition_required")
        if type(self.evidence) is not PrivacyV2MigrationEvidence:
            raise TypeError("migration_evidence_required")
        if type(self.source_identity) is not PrivacyV2DatabaseIdentity:
            raise TypeError("migration_source_identity_required")
        if type(self.target) is not PrivacyV2MigrationTarget:
            raise TypeError("migration_target_required")
        _wide("migration_operation_seal", self.seal)
        if self.evidence.source_checkpoint_commitment != self.source_identity.checkpoint_commitment:
            raise ProductionBoundaryError("migration_operation_source_mismatch")
        if self.evidence.target_state_commitment != self.target.target_state_commitment:
            raise ProductionBoundaryError("migration_operation_target_mismatch")
        if self.target != PrivacyV2MigrationTarget.from_sidecar(
            _sidecar(self.transition.sidecar),
            settlement_domain=self.transition.public_fields[1],
        ):
            raise ProductionBoundaryError("migration_operation_sidecar_mismatch")

    @property
    def migration_commitment(self) -> bytes:
        return _migration_operation_digest(self.transition, self.evidence)

    def is_native_authorized(self, authority_key: bytes) -> bool:
        key = _wide("migration_authority_key", authority_key)
        expected = hmac.new(
            key,
            _digest(
                _MIGRATION_SEAL_DOMAIN,
                self.transition.seal,
                self.evidence.commitment,
                self.source_identity.checkpoint_commitment,
                self.target.target_state_commitment,
            ),
            hashlib.sha3_512,
        ).digest()
        return hmac.compare_digest(self.seal, expected)


@dataclass(frozen=True, slots=True)
class MigrationReceiptV2:
    kind: str
    migration_commitment: bytes
    evidence_commitment: bytes
    source_checkpoint_commitment: bytes
    target_state_commitment: bytes
    epoch_before: int
    epoch_after: int
    sequence_before: int
    sequence_after: int
    strong_nullifier_root_after: bytes
    strong_payment_state_root_after: bytes
    state_binding_after: bytes
    audit_head_after: bytes

    def __post_init__(self) -> None:
        _kind(self.kind)
        for label, value in (
            ("receipt_migration", self.migration_commitment),
            ("receipt_evidence", self.evidence_commitment),
            ("receipt_source", self.source_checkpoint_commitment),
            ("receipt_target", self.target_state_commitment),
            ("receipt_nullifier", self.strong_nullifier_root_after),
            ("receipt_payment", self.strong_payment_state_root_after),
            ("receipt_state_binding", self.state_binding_after),
            ("receipt_audit_head", self.audit_head_after),
        ):
            _wide(label, value)
        if self.epoch_after != self.epoch_before + 1:
            raise ProductionBoundaryError("migration_receipt_epoch_invalid")
        if self.sequence_after != self.sequence_before + 1:
            raise ProductionBoundaryError("migration_receipt_sequence_invalid")


class TransactionalPrivacyV2MigrationStoragePort(Protocol):
    def _bind_migration_authority(self, authority_key: bytes) -> None: ...

    def _commit_verified_migration(
        self, operation: VerifiedMigrationOperationV2
    ) -> MigrationReceiptV2: ...

    def identity_snapshot(self) -> PrivacyV2DatabaseIdentity: ...

    def _migration_source_identity(
        self,
        source_checkpoint_commitment: bytes,
        migration_evidence_commitment: bytes,
    ) -> PrivacyV2DatabaseIdentity: ...

    def verify_integrity(self) -> None: ...


class TransactionalPrivacyV2Migration:
    """Pinned native verifier followed by one atomic database migration."""

    def __init__(
        self,
        *,
        verifier: object,
        storage: TransactionalPrivacyV2MigrationStoragePort,
        settlement_domain: bytes,
        governed_roots: GovernedRootsV2,
        authorized_submitters: Sequence[bytes],
    ) -> None:
        if not callable(getattr(verifier, "verify", None)):
            raise TypeError("migration_native_verifier_required")
        if not all(
            callable(getattr(storage, name, None))
            for name in (
                "_bind_migration_authority",
                "_commit_verified_migration",
                "_migration_source_identity",
                "identity_snapshot",
                "verify_integrity",
            )
        ):
            raise TypeError("migration_storage_port_required")
        if type(governed_roots) is not GovernedRootsV2:
            raise TypeError("migration_governed_roots_required")
        self._verifier = verifier
        self._storage = storage
        self._settlement_domain = _field(
            "migration_settlement_domain", settlement_domain, nonzero=True
        )
        self._governed_roots = governed_roots
        self._authorized_submitters = frozenset(
            _wide("migration_authorized_submitter", value)
            for value in authorized_submitters
        )
        if not self._authorized_submitters:
            raise ProductionBoundaryError("migration_submitters_empty")
        self._source_identity = storage.identity_snapshot()
        if self._source_identity.governance_commitment != governed_roots.commitment_512:
            raise ProductionBoundaryError("migration_source_configuration_mismatch")
        self.__authority_key = secrets.token_bytes(64)
        self._storage._bind_migration_authority(self.__authority_key)

    @property
    def source_identity(self) -> PrivacyV2DatabaseIdentity:
        return self._source_identity

    def _prepare(
        self,
        *,
        envelope: ProductionProofEnvelope,
        batch_nonce: bytes,
        submitter: bytes,
        evidence: PrivacyV2MigrationEvidence,
    ) -> VerifiedMigrationOperationV2:
        if type(envelope) is not ProductionProofEnvelope:
            raise ProductionBoundaryError("migration_envelope_required")
        if type(evidence) is not PrivacyV2MigrationEvidence:
            raise TypeError("migration_evidence_required")
        submitter_id = _wide("migration_submitter", submitter)
        if submitter_id not in self._authorized_submitters:
            raise ProductionBoundaryError("migration_submitter_not_authorized")
        nonce = _field("migration_batch_nonce", batch_nonce, nonzero=True)
        parsed = _sidecar(envelope.sidecar)
        target = PrivacyV2MigrationTarget.from_sidecar(
            parsed,
            settlement_domain=self._settlement_domain,
        )
        source = self._source_identity
        historical_retry = False
        if evidence.source_checkpoint_commitment != source.checkpoint_commitment:
            source = self._storage._migration_source_identity(
                evidence.source_checkpoint_commitment,
                evidence.commitment,
            )
            historical_retry = True
        if (
            not historical_retry
            and not evidence._has_runtime_randomness_provenance()
        ):
            raise ProductionBoundaryError(
                "migration_evidence_randomness_provenance_invalid"
            )
        if (
            target.epoch != source.epoch + 1
            or target.sequence_before != source.sequence
            or target.sequence_after != source.sequence + 1
            or target.strong_nullifier_root_before != source.strong_nullifier_root
            or target.strong_payment_state_root_before != source.strong_payment_state_root
            or target.governance_commitment != source.governance_commitment
        ):
            raise ProductionBoundaryError("migration_source_state_mismatch")
        if (
            evidence.kind in {"ROLLBACK", "RECOVERY"}
            and target.settlement_domain_commitment
            == source.settlement_domain_commitment
        ):
            raise ProductionBoundaryError("migration_recovery_domain_not_rotated")
        if (
            target.profile_id,
            target.suite_id,
            target.schema_id,
            target.verifier_artifact_identity,
        ) == (
            source.profile_id,
            source.suite_id,
            source.schema_id,
            source.verifier_artifact_identity,
        ):
            raise ProductionBoundaryError("migration_identity_not_rotated")
        if evidence.source_checkpoint_commitment != source.checkpoint_commitment:
            raise ProductionBoundaryError("migration_evidence_source_mismatch")
        if evidence.target_state_commitment != target.target_state_commitment:
            raise ProductionBoundaryError("migration_evidence_target_mismatch")
        if nonce != derive_migration_nonce(source, target, evidence):
            raise ProductionBoundaryError("migration_nonce_mismatch")
        if parsed.strong_batch_commitment != _digest(_BATCH_NONCE_BINDING, nonce):
            raise ProductionBoundaryError("migration_batch_commitment_mismatch")
        fields = validate_v2_public_projection(
            public_fields=tuple(
                envelope.public_outputs[index : index + PUBLIC_FIELD_BYTES]
                for index in range(0, len(envelope.public_outputs), PUBLIC_FIELD_BYTES)
            ),
            sidecar=envelope.sidecar,
            settlement_domain=self._settlement_domain,
            batch_nonce=nonce,
            governed_roots=self._governed_roots,
            suite_id=envelope.suite_id,
            schema_id=envelope.schema_id,
            verifier_artifact_identity=envelope.verifier_artifact_identity,
        )
        result = self._verifier.verify(envelope)
        if type(result) is not NativeVerificationResult:
            raise ProductionBoundaryError("migration_verifier_result_invalid")
        receipt = result.receipt
        if type(receipt) is not NativeVerificationReceipt:
            raise ProductionBoundaryError("migration_verifier_receipt_invalid")
        expected_envelope = hashlib.sha3_512(envelope.encode()).digest()
        expected_statement = statement_commitment(
            envelope.public_outputs, envelope.sidecar
        )
        expected_package = hashlib.sha3_512(
            PROOF_PACKAGE_COMMITMENT_DOMAIN + envelope.proof_package
        ).digest()
        expected_transcript = hashlib.sha3_512(
            TRANSCRIPT_COMMITMENT_DOMAIN + envelope.transcript_evidence
        ).digest()
        if (
            result.envelope_commitment != expected_envelope
            or receipt.envelope_commitment != expected_envelope
            or result.statement_commitment != expected_statement
            or receipt.statement_commitment != expected_statement
            or receipt.evidence_commitment != envelope.evidence_commitment
            or receipt.proof_package_commitment != expected_package
            or receipt.transcript_commitment != expected_transcript
            or receipt.proof_suite_id != envelope.suite_id
            or receipt.schema_id != envelope.schema_id
            or receipt.verifier_artifact_identity
            != envelope.verifier_artifact_identity
        ):
            raise ProductionBoundaryError("migration_verifier_binding_mismatch")
        values = {
            "batch_nonce": nonce,
            "submitter": submitter_id,
            "envelope_commitment": expected_envelope,
            "statement_commitment": expected_statement,
            "evidence_commitment": receipt.evidence_commitment,
            "proof_package_commitment": expected_package,
            "transcript_commitment": expected_transcript,
            "public_fields_commitment": public_fields_commitment(fields),
            "public_fields": fields,
            "sidecar": envelope.sidecar,
            "profile_id": parsed.profile_id,
            "suite_id": envelope.suite_id,
            "schema_id": envelope.schema_id,
            "verifier_artifact_identity": envelope.verifier_artifact_identity,
            "epoch": parsed.epoch,
            "sequence_before": parsed.sequence_before,
            "sequence_after": parsed.sequence_after,
            "strong_nullifier_root_before": parsed.strong_nullifier_root_before,
            "strong_nullifier_root_after": parsed.strong_nullifier_root_after,
            "strong_governance_commitment": parsed.strong_governance_commitment,
            "strong_payment_state_root_before": parsed.strong_payment_state_root_before,
            "strong_payment_state_root_after": parsed.strong_payment_state_root_after,
            "strong_batch_commitment": parsed.strong_batch_commitment,
        }
        transition_seal = _verified_operation_seal(
            authority_key=self.__authority_key,
            **values,  # type: ignore[arg-type]
        )
        transition = VerifiedSettlementOperationV2(
            **values,  # type: ignore[arg-type]
            seal=transition_seal,
        )
        migration_seal = hmac.new(
            self.__authority_key,
            _digest(
                _MIGRATION_SEAL_DOMAIN,
                transition.seal,
                evidence.commitment,
                source.checkpoint_commitment,
                target.target_state_commitment,
            ),
            hashlib.sha3_512,
        ).digest()
        return VerifiedMigrationOperationV2(
            transition=transition,
            evidence=evidence,
            source_identity=source,
            target=target,
            seal=migration_seal,
        )

    def submit(
        self,
        *,
        envelope: ProductionProofEnvelope,
        batch_nonce: bytes,
        submitter: bytes,
        evidence: PrivacyV2MigrationEvidence,
    ) -> MigrationReceiptV2:
        return self._storage._commit_verified_migration(
            self._prepare(
                envelope=envelope,
                batch_nonce=batch_nonce,
                submitter=submitter,
                evidence=evidence,
            )
        )

    def close(self) -> None:
        self.__authority_key = bytes(64)


def public_migration_artifact(operation: VerifiedMigrationOperationV2) -> bytes:
    """Return the fixed-key commitment-only artifact allowed outside the DB."""

    if type(operation) is not VerifiedMigrationOperationV2:
        raise TypeError("migration_operation_required")
    payload = {
        "status": STATUS,
        "kind": operation.evidence.kind,
        "migrationCommitment": operation.migration_commitment.hex(),
        "evidenceCommitment": operation.evidence.commitment.hex(),
        "sourceCheckpointCommitment": operation.source_identity.checkpoint_commitment.hex(),
        "targetStateCommitment": operation.target.target_state_commitment.hex(),
        "epochBefore": operation.source_identity.epoch,
        "epochAfter": operation.target.epoch,
        "sequenceBefore": operation.target.sequence_before,
        "sequenceAfter": operation.target.sequence_after,
        "profileIdAfter": operation.target.profile_id.hex(),
        "proofSuiteIdAfter": operation.target.suite_id.hex(),
        "schemaIdAfter": operation.target.schema_id.hex(),
        "verifierArtifactIdentityAfter": operation.target.verifier_artifact_identity.hex(),
        "proofSuiteId": None,
        "activationAllowed": False,
        "productionUsable": False,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")


__all__ = (
    "ACTIVATION_ALLOWED",
    "MIGRATION_KINDS",
    "PRODUCTION_USABLE",
    "PROOF_SUITE_ID",
    "STATUS",
    "MigrationReceiptV2",
    "PrivacyV2DatabaseIdentity",
    "PrivacyV2MigrationEvidence",
    "PrivacyV2MigrationTarget",
    "TransactionalPrivacyV2Migration",
    "TransactionalPrivacyV2MigrationStoragePort",
    "VerifiedMigrationOperationV2",
    "build_privacy_v2_migration_evidence",
    "derive_migration_nonce",
    "generate_migration_privacy_salt",
    "migration_version_commitment",
    "public_migration_artifact",
)
