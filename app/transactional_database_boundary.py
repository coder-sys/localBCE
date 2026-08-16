"""Qualification-only transactional database boundary for Privacy V2.

This module deliberately implements a local SQLite reference, not a production
database selection.  The native verifier remains the authority for proof
acceptance; this module only proves the durable all-or-nothing state seam that
follows it.  No network, Ethereum, PHI, payment connector, or activation
credential is opened here.
"""

from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass, replace
import hashlib
import hmac
import json
from pathlib import Path
import secrets
import sqlite3
from threading import RLock
from typing import Callable, Final, Protocol

from app.production_boundary import (
    DatabaseSettlementSnapshotV2,
    GovernanceAuthorityV2,
    NativeVerificationResult,
    PUBLIC_FIELD_BYTES,
    ProductionBoundaryError,
    ProductionProofEnvelope,
    SettlementReceiptV2,
    TransactionalSettlementStoragePort,
    VerifiedSettlementOperationV2,
    _BATCH_NONCE_BINDING,
    _DATABASE_STATE_BINDING,
    _digest,
    _field,
    _field_alias,
    _sidecar,
    _verified_operation_seal,
    _wide,
    public_fields_commitment,
    validate_v2_public_projection,
)
from app.batch.pq_suite_candidate import CandidateSidecarV1
from app.privacy_v2_migration import (
    MigrationReceiptV2,
    PrivacyV2DatabaseIdentity,
    PrivacyV2MigrationEvidence,
    PrivacyV2MigrationTarget,
    VerifiedMigrationOperationV2,
    derive_migration_nonce,
)
from experiments.bl_pq512_crypto_foundation.production_candidate import (
    PROOF_PACKAGE_COMMITMENT_DOMAIN,
    TRANSCRIPT_COMMITMENT_DOMAIN,
    NativeVerificationReceipt,
    statement_commitment,
)


_SCHEMA_VERSION: Final[int] = 3
_AUDIT_GENESIS_DOMAIN = b"BL/PQ512/V2/DATABASE-AUDIT-GENESIS/v1\x00"
_AUDIT_EVENT_DOMAIN = b"BL/PQ512/V2/DATABASE-AUDIT-EVENT/v1\x00"
_AUDIT_HEAD_DOMAIN = b"BL/PQ512/V2/DATABASE-AUDIT-HEAD/v1\x00"
_OPERATION_DIGEST_DOMAIN = b"BL/PQ512/V2/DATABASE-OPERATION/v1\x00"
_DOMAIN_COMMITMENT_DOMAIN = b"BL/PQ512/V2/DATABASE-DOMAIN/v1\x00"
_SUBMITTER_AUDIT_DOMAIN = b"BL/PQ512/V2/DATABASE-SUBMITTER-AUDIT/v1\x00"
_MIGRATION_AUDIT_EVENT_DOMAIN = b"BL/PQ512/V2/DATABASE-MIGRATION-AUDIT/v1\x00"
_MIGRATION_STATE_BINDING_DOMAIN = b"BL/PQ512/V2/DATABASE-MIGRATION-STATE/v1\x00"
_TRANSITION_RECORD_DOMAIN = b"BL/PQ512/V2/DATABASE-TRANSITION-RECORD/v1\x00"
_DIRECT_OPERATION_DOMAIN = b"BL/DIRECT-STATE-OWNED/CLEARANCE-OPERATION/v1\x00"
_DIRECT_OPERATION_SEAL_DOMAIN = b"BL/DIRECT-STATE-OWNED/CLEARANCE-SEAL/v1\x00"
_DIRECT_REPLAY_ROOT_DOMAIN = b"BL/DIRECT-STATE-OWNED/REPLAY-ROOT/v1\x00"
_DIRECT_CLEARANCE_ROOT_DOMAIN = b"BL/DIRECT-STATE-OWNED/CLEARANCE-ROOT/v1\x00"
_DIRECT_CONTINUITY_STATE_MAGIC = b"BLCSTA02"
_DIRECT_CONTINUITY_STATE_VERSION = 2
_DIRECT_CONTINUITY_STATE_CONTEXT_DOMAIN = b"BL/NATIVE-V3/CONTINUITY/STATE-CONTEXT/v2\x00"
_DIRECT_CONTINUITY_STATE_ID_DOMAIN = b"BL/NATIVE-V3/CONTINUITY/STATE-ID/v2\x00"
_DIRECT_CONTINUITY_AUDIT_HEAD_DOMAIN = b"BL/NATIVE-V3/CONTINUITY/AUDIT-HEAD/v2\x00"
_DIRECT_CONTINUITY_ROOT_DOMAIN = b"BL/NATIVE-V3/CONTINUITY/ROOT/v2\x00"
_AUDIT_HEX_FIELDS = frozenset(
    {
        "batch_nonce_commitment",
        "nullifier_root_before",
        "nullifier_root_after",
        "payment_state_root_before",
        "payment_state_root_after",
        "governance_commitment",
        "envelope_commitment",
        "statement_commitment",
        "evidence_commitment",
        "proof_package_commitment",
        "transcript_commitment",
        "public_fields_commitment",
        "operation_digest",
        "submitter_commitment",
        "state_binding",
        "previous_audit_head",
        "profile_id",
        "proof_suite_id",
        "schema_id",
        "verifier_artifact_identity",
    }
)
_AUDIT_PAYLOAD_FIELDS = _AUDIT_HEX_FIELDS | {
    "version",
    "epoch",
    "sequence_before",
    "sequence_after",
}


@dataclass(frozen=True, slots=True)
class PendingAntiRollbackTransition:
    """Exact write-ahead reservation held outside the SQLite database."""

    next_epoch: int
    next_state_binding: bytes
    transition_commitment: bytes

    def __post_init__(self) -> None:
        if type(self.next_epoch) is not int or self.next_epoch <= 0:
            raise ProductionBoundaryError("anti_rollback_pending_epoch_invalid")
        _wide("anti_rollback_pending_state_binding", self.next_state_binding)
        _wide("anti_rollback_pending_transition_commitment", self.transition_commitment)


@dataclass(frozen=True, slots=True)
class AntiRollbackAnchorSnapshot:
    """Committed external anchor plus at most one exact in-doubt successor."""

    epoch: int
    state_binding: bytes
    pending: PendingAntiRollbackTransition | None = None
    transition_commitment: bytes | None = None

    def __post_init__(self) -> None:
        if type(self.epoch) is not int or self.epoch < 0:
            raise ProductionBoundaryError("anti_rollback_epoch_invalid")
        _wide("anti_rollback_state_binding", self.state_binding)
        if self.pending is not None:
            if type(self.pending) is not PendingAntiRollbackTransition:
                raise ProductionBoundaryError("anti_rollback_pending_shape_invalid")
            if self.pending.next_epoch != self.epoch + 1:
                raise ProductionBoundaryError("anti_rollback_pending_epoch_invalid")
        if self.epoch == 0:
            if self.transition_commitment is not None:
                raise ProductionBoundaryError("anti_rollback_genesis_transition_invalid")
        elif self.transition_commitment is None:
            raise ProductionBoundaryError("anti_rollback_transition_commitment_missing")
        else:
            _wide(
                "anti_rollback_transition_commitment",
                self.transition_commitment,
            )


class AntiRollbackReference(Protocol):
    """External write-ahead anchor used for file-rollback detection."""

    def snapshot(self) -> AntiRollbackAnchorSnapshot | None:
        """Return the committed anchor and any exact in-doubt successor."""

    def initialize(self, epoch: int, state_binding: bytes) -> None:
        """Initialize only a fresh epoch-zero database anchor."""

    def prepare(
        self,
        *,
        expected_epoch: int,
        expected_state_binding: bytes,
        next_epoch: int,
        next_state_binding: bytes,
        transition_commitment: bytes,
    ) -> None:
        """Reserve one exact successor before the SQLite commit."""

    def finalize(
        self,
        *,
        next_epoch: int,
        next_state_binding: bytes,
        transition_commitment: bytes,
    ) -> None:
        """Idempotently promote the reserved successor after commit."""


@dataclass(frozen=True, slots=True)
class DirectStateOwnedOperationV1:
    """Independent semantic result sealed for the direct database boundary.

    This is not a proof envelope and contains no private source bytes.  The
    direct adapter constructs it only from a successful independent bundle
    parse; the database authenticates the value with a store-bound key before
    opening its transaction.
    """

    bundle_id: bytes
    receipt_id: bytes
    request_id: bytes
    attempt_id: bytes
    decision_id: bytes
    join_id: bytes
    source_root: bytes
    profile_id: bytes
    schema_id: bytes
    program_id: bytes
    mode_id: bytes
    evaluator_id: bytes
    control_set_id: bytes
    rule_id: bytes
    phase0_receipt_binding: bytes
    exception_id: bytes
    policy_result: int
    effective_directive: int
    event_time: int
    observation_time: int
    rule_effective_time: int
    decision_time: int
    continuity_epoch: int
    continuity_sequence_before: int
    continuity_sequence_after: int
    continuity_before_state_id: bytes
    continuity_after_state_id: bytes
    continuity_before_audit_head: bytes
    continuity_after_audit_head: bytes
    continuity_before_root: bytes
    continuity_after_root: bytes
    seal: bytes | None = None

    def __post_init__(self) -> None:
        for label, value in (
            ("direct_bundle_id", self.bundle_id),
            ("direct_receipt_id", self.receipt_id),
            ("direct_request_id", self.request_id),
            ("direct_attempt_id", self.attempt_id),
            ("direct_decision_id", self.decision_id),
            ("direct_join_id", self.join_id),
            ("direct_source_root", self.source_root),
            ("direct_profile_id", self.profile_id),
            ("direct_schema_id", self.schema_id),
            ("direct_program_id", self.program_id),
            ("direct_mode_id", self.mode_id),
            ("direct_evaluator_id", self.evaluator_id),
            ("direct_control_set_id", self.control_set_id),
            ("direct_rule_id", self.rule_id),
            ("direct_phase0_receipt_binding", self.phase0_receipt_binding),
            ("direct_exception_id", self.exception_id),
            ("direct_before_state_id", self.continuity_before_state_id),
            ("direct_after_state_id", self.continuity_after_state_id),
            ("direct_before_audit_head", self.continuity_before_audit_head),
            ("direct_after_audit_head", self.continuity_after_audit_head),
            ("direct_before_root", self.continuity_before_root),
            ("direct_after_root", self.continuity_after_root),
        ):
            _wide(label, value)
        if type(self.policy_result) is not int or self.policy_result not in (1, 2, 3, 4):
            raise ProductionBoundaryError("direct_policy_result_invalid")
        if type(self.effective_directive) is not int or self.effective_directive not in (1, 2, 3, 4, 5):
            raise ProductionBoundaryError("direct_effective_directive_invalid")
        if self.policy_result != {1: 1, 2: 2, 3: 3, 4: 4, 5: 4}[self.effective_directive]:
            raise ProductionBoundaryError("direct_policy_directive_mismatch")
        for label, value in (
            ("direct_event_time", self.event_time),
            ("direct_observation_time", self.observation_time),
            ("direct_rule_effective_time", self.rule_effective_time),
            ("direct_decision_time", self.decision_time),
            ("direct_continuity_epoch", self.continuity_epoch),
            ("direct_continuity_sequence_before", self.continuity_sequence_before),
            ("direct_continuity_sequence_after", self.continuity_sequence_after),
        ):
            if type(value) is not int or value < 0 or value >= 2**64:
                raise ProductionBoundaryError(f"{label}_invalid")
        if not (
            self.rule_effective_time
            < self.event_time
            < self.observation_time
            < self.decision_time
        ):
            raise ProductionBoundaryError("direct_chronology_invalid")
        if (
            self.continuity_epoch != 7
            or self.continuity_sequence_before != 0
            or self.continuity_sequence_after != 1
        ):
            raise ProductionBoundaryError("direct_continuity_state_shape_invalid")
        expected_empty_audit = _direct_continuity_sha(
            _DIRECT_CONTINUITY_AUDIT_HEAD_DOMAIN,
            b"empty",
        )
        expected_empty_root = _direct_continuity_sha(
            _DIRECT_CONTINUITY_ROOT_DOMAIN,
            b"empty",
        )
        if (
            self.continuity_before_audit_head != expected_empty_audit
            or self.continuity_before_root != expected_empty_root
            or self.continuity_before_state_id
            != _direct_continuity_state_id(
                profile_id=self.profile_id,
                mode_id=self.mode_id,
                sequence=0,
                row_count=0,
                audit_head=self.continuity_before_audit_head,
                continuity_root=self.continuity_before_root,
            )
        ):
            raise ProductionBoundaryError("direct_continuity_before_state_invalid")
        expected_after_audit = _direct_continuity_sha(
            _DIRECT_CONTINUITY_AUDIT_HEAD_DOMAIN,
            self.continuity_before_audit_head,
            self.decision_id,
            bytes((self.effective_directive,)),
        )
        expected_after_root = _direct_continuity_sha(
            _DIRECT_CONTINUITY_ROOT_DOMAIN,
            self.continuity_before_root,
            self.source_root,
            self.decision_id,
        )
        if (
            self.continuity_after_audit_head != expected_after_audit
            or self.continuity_after_root != expected_after_root
            or self.continuity_after_state_id
            != _direct_continuity_state_id(
                profile_id=self.profile_id,
                mode_id=self.mode_id,
                sequence=1,
                row_count=1,
                audit_head=self.continuity_after_audit_head,
                continuity_root=self.continuity_after_root,
            )
        ):
            raise ProductionBoundaryError("direct_continuity_after_state_invalid")
        if self.seal is not None:
            _wide("direct_operation_seal", self.seal)


@dataclass(frozen=True, slots=True)
class DirectStateOwnedDatabaseReceiptV1:
    """Committed identity returned by the direct transactional database lane."""

    operation_digest: bytes
    bundle_id: bytes
    receipt_id: bytes
    decision_id: bytes
    join_id: bytes
    sequence_before: int
    sequence_after: int
    nullifier_root_before: bytes
    nullifier_root_after: bytes
    clearance_root_before: bytes
    clearance_root_after: bytes
    state_binding: bytes
    audit_head: bytes
    effective_directive: int
    clearance_advanced: bool

    def __post_init__(self) -> None:
        for label, value in (
            ("direct_receipt_operation", self.operation_digest),
            ("direct_receipt_bundle", self.bundle_id),
            ("direct_receipt_id", self.receipt_id),
            ("direct_receipt_decision", self.decision_id),
            ("direct_receipt_join", self.join_id),
            ("direct_receipt_nullifier_before", self.nullifier_root_before),
            ("direct_receipt_nullifier_after", self.nullifier_root_after),
            ("direct_receipt_clearance_before", self.clearance_root_before),
            ("direct_receipt_clearance_after", self.clearance_root_after),
            ("direct_receipt_binding", self.state_binding),
            ("direct_receipt_audit", self.audit_head),
        ):
            _wide(label, value)
        if type(self.sequence_before) is not int or self.sequence_before < 0:
            raise ProductionBoundaryError("direct_receipt_sequence_before_invalid")
        if self.sequence_after != self.sequence_before + 1:
            raise ProductionBoundaryError("direct_receipt_sequence_after_invalid")
        if type(self.effective_directive) is not int or self.effective_directive not in (1, 2, 3, 4, 5):
            raise ProductionBoundaryError("direct_receipt_directive_invalid")
        if type(self.clearance_advanced) is not bool:
            raise ProductionBoundaryError("direct_receipt_clearance_flag_invalid")


def _direct_operation_parts(operation: DirectStateOwnedOperationV1) -> tuple[bytes, ...]:
    return (
        operation.bundle_id,
        operation.receipt_id,
        operation.request_id,
        operation.attempt_id,
        operation.decision_id,
        operation.join_id,
        operation.source_root,
        operation.profile_id,
        operation.schema_id,
        operation.program_id,
        operation.mode_id,
        operation.evaluator_id,
        operation.control_set_id,
        operation.rule_id,
        operation.phase0_receipt_binding,
        operation.exception_id,
        _u64(operation.policy_result, "direct_policy_result"),
        _u64(operation.effective_directive, "direct_effective_directive"),
        _u64(operation.event_time, "direct_event_time"),
        _u64(operation.observation_time, "direct_observation_time"),
        _u64(operation.rule_effective_time, "direct_rule_effective_time"),
        _u64(operation.decision_time, "direct_decision_time"),
        _u64(operation.continuity_epoch, "direct_continuity_epoch"),
        _u64(operation.continuity_sequence_before, "direct_continuity_sequence_before"),
        _u64(operation.continuity_sequence_after, "direct_continuity_sequence_after"),
        operation.continuity_before_state_id,
        operation.continuity_after_state_id,
        operation.continuity_before_audit_head,
        operation.continuity_after_audit_head,
        operation.continuity_before_root,
        operation.continuity_after_root,
    )


def _direct_operation_digest(operation: DirectStateOwnedOperationV1) -> bytes:
    return _digest(_DIRECT_OPERATION_DOMAIN, *_direct_operation_parts(operation))


def _direct_operation_seal(
    authority_key: bytes,
    operation: DirectStateOwnedOperationV1,
) -> bytes:
    key = _wide("direct_operation_authority_key", authority_key)
    return hmac.new(
        key,
        _digest(_DIRECT_OPERATION_SEAL_DOMAIN, _direct_operation_digest(operation)),
        hashlib.sha3_512,
    ).digest()


class InMemoryAntiRollbackReference:
    """Thread-safe reference anchor used only by local qualification tests.

    A fresh instance intentionally has no prior observation.  Production
    custody must replace this port with an independently durable monotonic
    authority; this class is not a HSM, FIPS implementation, or deployment
    claim.
    """

    def __init__(self) -> None:
        self._lock = RLock()
        self._observed: AntiRollbackAnchorSnapshot | None = None
        self._finalized: dict[int, tuple[bytes, bytes | None]] = {}

    def snapshot(self) -> AntiRollbackAnchorSnapshot | None:
        with self._lock:
            return self._observed

    def initialize(self, epoch: int, state_binding: bytes) -> None:
        if type(epoch) is not int or epoch != 0:
            raise ProductionBoundaryError("anti_rollback_epoch_invalid")
        binding = _wide("anti_rollback_state_binding", state_binding)
        with self._lock:
            if self._observed is None:
                self._observed = AntiRollbackAnchorSnapshot(epoch, binding)
                self._finalized[epoch] = (binding, None)
                return
            if self._observed.epoch != epoch or self._observed.state_binding != binding:
                raise ProductionBoundaryError("anti_rollback_already_initialized")

    def prepare(
        self,
        *,
        expected_epoch: int,
        expected_state_binding: bytes,
        next_epoch: int,
        next_state_binding: bytes,
        transition_commitment: bytes,
    ) -> None:
        if type(expected_epoch) is not int or expected_epoch < 0:
            raise ProductionBoundaryError("anti_rollback_epoch_invalid")
        expected_binding = _wide(
            "anti_rollback_expected_state_binding",
            expected_state_binding,
        )
        pending = PendingAntiRollbackTransition(
            next_epoch,
            next_state_binding,
            transition_commitment,
        )
        if pending.next_epoch != expected_epoch + 1:
            raise ProductionBoundaryError("anti_rollback_transition_epoch_invalid")
        with self._lock:
            if self._observed is None:
                raise ProductionBoundaryError("anti_rollback_anchor_uninitialized")
            if self._observed.pending is not None:
                if (
                    self._observed.epoch == expected_epoch
                    and self._observed.state_binding == expected_binding
                    and self._observed.pending == pending
                ):
                    return
                raise ProductionBoundaryError("anti_rollback_transition_conflict")
            if (
                self._observed.epoch != expected_epoch
                or self._observed.state_binding != expected_binding
            ):
                raise ProductionBoundaryError("anti_rollback_expected_state_mismatch")
            self._observed = AntiRollbackAnchorSnapshot(
                epoch=expected_epoch,
                state_binding=expected_binding,
                pending=pending,
                transition_commitment=self._observed.transition_commitment,
            )

    def finalize(
        self,
        *,
        next_epoch: int,
        next_state_binding: bytes,
        transition_commitment: bytes,
    ) -> None:
        pending = PendingAntiRollbackTransition(
            next_epoch,
            next_state_binding,
            transition_commitment,
        )
        with self._lock:
            if self._observed is None:
                raise ProductionBoundaryError("anti_rollback_anchor_uninitialized")
            finalized = self._finalized.get(pending.next_epoch)
            if finalized is not None:
                if finalized == (
                    pending.next_state_binding,
                    pending.transition_commitment,
                ):
                    return
                raise ProductionBoundaryError("anti_rollback_finalize_mismatch")
            if self._observed.pending is None:
                if (
                    self._observed.epoch == pending.next_epoch
                    and self._observed.state_binding == pending.next_state_binding
                    and self._observed.transition_commitment
                    == pending.transition_commitment
                ):
                    return
                raise ProductionBoundaryError("anti_rollback_finalize_without_reservation")
            if self._observed.pending != pending:
                raise ProductionBoundaryError("anti_rollback_finalize_mismatch")
            self._observed = AntiRollbackAnchorSnapshot(
                epoch=pending.next_epoch,
                state_binding=pending.next_state_binding,
                transition_commitment=pending.transition_commitment,
            )
            self._finalized[pending.next_epoch] = (
                pending.next_state_binding,
                pending.transition_commitment,
            )


def _u64(value: int, label: str) -> bytes:
    if type(value) is not int or value < 0 or value >= 2**64:
        raise ProductionBoundaryError(f"{label}_invalid")
    return value.to_bytes(8, "big")


def _hex(value: bytes) -> str:
    return value.hex()


def _governance_authority_row(
    activation_sequence: int,
    authority: GovernanceAuthorityV2,
) -> tuple[object, ...]:
    if type(activation_sequence) is not int or activation_sequence < 0:
        raise ProductionBoundaryError("database_governance_activation_sequence_invalid")
    if type(authority) is not GovernanceAuthorityV2:
        raise TypeError("database_governance_authority_required")
    return (
        activation_sequence,
        authority.commitment_512,
        authority.profile_code,
        authority.epoch,
        *authority.claim_truth_roots_512,
        authority.claim_truth_authority_digest_512,
        authority.nullifier_authority_id_512,
        authority.pepper_commitment_512,
    )


def _governance_authority_from_row(row: tuple[object, ...]) -> GovernanceAuthorityV2:
    if len(row) != 13:
        raise ProductionBoundaryError("database_governance_authority_shape_invalid")
    normalized = tuple(
        value if type(value) is int else bytes(value)
        for value in row
    )
    try:
        authority = GovernanceAuthorityV2(
            profile_code=normalized[2],  # type: ignore[arg-type]
            epoch=normalized[3],  # type: ignore[arg-type]
            claim_truth_roots_512=tuple(normalized[4:10]),  # type: ignore[arg-type]
            claim_truth_authority_digest_512=normalized[10],  # type: ignore[arg-type]
            nullifier_authority_id_512=normalized[11],  # type: ignore[arg-type]
            pepper_commitment_512=normalized[12],  # type: ignore[arg-type]
        )
    except ValueError as exc:
        raise ProductionBoundaryError(
            "database_governance_authority_tuple_invalid"
        ) from exc
    if normalized[1] != authority.commitment_512:
        raise ProductionBoundaryError("database_governance_authority_digest_mismatch")
    return authority


def _operation_digest(operation: VerifiedSettlementOperationV2) -> bytes:
    return _digest(
        _OPERATION_DIGEST_DOMAIN,
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
        operation.governance_authority.canonical_bytes,
        operation.strong_governance_commitment,
        operation.strong_payment_state_root_before,
        operation.strong_payment_state_root_after,
        operation.strong_batch_commitment,
    )


def _audit_payload(
    *,
    operation: VerifiedSettlementOperationV2,
    receipt: SettlementReceiptV2,
    previous_head: bytes,
) -> bytes:
    """Build an audit event containing commitments, never private claim data."""

    payload = {
        "version": 1,
        "epoch": operation.epoch,
        "sequence_before": receipt.sequence_before,
        "sequence_after": receipt.sequence_after,
        "batch_nonce_commitment": _hex(_digest(_BATCH_NONCE_BINDING, operation.batch_nonce)),
        "nullifier_root_before": _hex(operation.strong_nullifier_root_before),
        "nullifier_root_after": _hex(operation.strong_nullifier_root_after),
        "payment_state_root_before": _hex(operation.strong_payment_state_root_before),
        "payment_state_root_after": _hex(operation.strong_payment_state_root_after),
        "governance_commitment": _hex(operation.strong_governance_commitment),
        "envelope_commitment": _hex(operation.envelope_commitment),
        "statement_commitment": _hex(operation.statement_commitment),
        "evidence_commitment": _hex(operation.evidence_commitment),
        "proof_package_commitment": _hex(operation.proof_package_commitment),
        "transcript_commitment": _hex(operation.transcript_commitment),
        "public_fields_commitment": _hex(operation.public_fields_commitment),
        "operation_digest": _hex(_operation_digest(operation)),
        "submitter_commitment": _hex(
            _digest(_SUBMITTER_AUDIT_DOMAIN, operation.submitter)
        ),
        "state_binding": _hex(receipt.state_binding),
        "previous_audit_head": _hex(previous_head),
        "profile_id": _hex(operation.profile_id),
        "proof_suite_id": _hex(operation.suite_id),
        "schema_id": _hex(operation.schema_id),
        "verifier_artifact_identity": _hex(operation.verifier_artifact_identity),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")


def _audit_payload_from_json(encoded: bytes) -> dict[str, object]:
    try:
        payload = json.loads(encoded.decode("ascii"))
        if type(payload) is not dict or set(payload) != _AUDIT_PAYLOAD_FIELDS:
            raise ValueError
        if payload["version"] != 1:
            raise ValueError
        epoch = payload["epoch"]
        before = payload["sequence_before"]
        after = payload["sequence_after"]
        if (
            type(epoch) is not int
            or epoch <= 0
            or type(before) is not int
            or before < 0
            or type(after) is not int
            or after != before + 1
        ):
            raise ValueError
        for name in _AUDIT_HEX_FIELDS:
            value = payload[name]
            if type(value) is not str or len(bytes.fromhex(value)) != 64:
                raise ValueError
        return payload
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise ProductionBoundaryError("database_audit_payload_invalid") from exc


_DIRECT_AUDIT_HEX_FIELDS = frozenset(
    {
        "operation_digest",
        "bundle_id",
        "receipt_id",
        "request_id",
        "attempt_id",
        "decision_id",
        "join_id",
        "source_root",
        "profile_id",
        "schema_id",
        "program_id",
        "mode_id",
        "evaluator_id",
        "control_set_id",
        "rule_id",
        "phase0_receipt_binding",
        "exception_id",
        "continuity_before_state_id",
        "continuity_after_state_id",
        "continuity_before_audit_head",
        "continuity_after_audit_head",
        "continuity_before_root",
        "continuity_after_root",
        "nullifier_root_before",
        "nullifier_root_after",
        "payment_root_before",
        "payment_root_after",
        "state_binding",
        "previous_audit_head",
    }
)
_DIRECT_AUDIT_PAYLOAD_FIELDS = _DIRECT_AUDIT_HEX_FIELDS | {
    "version",
    "event_kind",
    "epoch",
    "sequence_before",
    "sequence_after",
    "policy_result",
    "effective_directive",
    "clearance_advanced",
    "event_time",
    "observation_time",
    "rule_effective_time",
    "decision_time",
}


def _direct_continuity_sha(domain: bytes, *parts: bytes) -> bytes:
    digest = hashlib.sha3_512(domain)
    for part in parts:
        digest.update(part)
    return digest.digest()


def _direct_continuity_state_id(
    *,
    profile_id: bytes,
    mode_id: bytes,
    sequence: int,
    row_count: int,
    audit_head: bytes,
    continuity_root: bytes,
) -> bytes:
    context_id = _direct_continuity_sha(
        _DIRECT_CONTINUITY_STATE_CONTEXT_DOMAIN,
        profile_id,
        mode_id,
    )
    raw = b"".join(
        (
            _DIRECT_CONTINUITY_STATE_MAGIC,
            _DIRECT_CONTINUITY_STATE_VERSION.to_bytes(2, "big"),
            b"\0\0",
            context_id,
            sequence.to_bytes(8, "big"),
            row_count.to_bytes(4, "big"),
            b"\0" * 4,
            audit_head,
            continuity_root,
        )
    )
    return _direct_continuity_sha(_DIRECT_CONTINUITY_STATE_ID_DOMAIN, raw)


def _direct_audit_payload(
    *,
    operation: DirectStateOwnedOperationV1,
    operation_digest: bytes,
    sequence_before: int,
    sequence_after: int,
    nullifier_before: bytes,
    nullifier_after: bytes,
    payment_before: bytes,
    payment_after: bytes,
    state_binding: bytes,
    previous_head: bytes,
) -> bytes:
    payload = {
        "version": 3,
        "event_kind": "DIRECT_STATE_OWNED_CLEARANCE_V1",
        "epoch": operation.continuity_epoch,
        "sequence_before": sequence_before,
        "sequence_after": sequence_after,
        "policy_result": operation.policy_result,
        "effective_directive": operation.effective_directive,
        "clearance_advanced": int(operation.effective_directive in (1, 5)),
        "event_time": operation.event_time,
        "observation_time": operation.observation_time,
        "rule_effective_time": operation.rule_effective_time,
        "decision_time": operation.decision_time,
        "operation_digest": operation_digest.hex(),
        "bundle_id": operation.bundle_id.hex(),
        "receipt_id": operation.receipt_id.hex(),
        "request_id": operation.request_id.hex(),
        "attempt_id": operation.attempt_id.hex(),
        "decision_id": operation.decision_id.hex(),
        "join_id": operation.join_id.hex(),
        "source_root": operation.source_root.hex(),
        "profile_id": operation.profile_id.hex(),
        "schema_id": operation.schema_id.hex(),
        "program_id": operation.program_id.hex(),
        "mode_id": operation.mode_id.hex(),
        "evaluator_id": operation.evaluator_id.hex(),
        "control_set_id": operation.control_set_id.hex(),
        "rule_id": operation.rule_id.hex(),
        "phase0_receipt_binding": operation.phase0_receipt_binding.hex(),
        "exception_id": operation.exception_id.hex(),
        "continuity_before_state_id": operation.continuity_before_state_id.hex(),
        "continuity_after_state_id": operation.continuity_after_state_id.hex(),
        "continuity_before_audit_head": operation.continuity_before_audit_head.hex(),
        "continuity_after_audit_head": operation.continuity_after_audit_head.hex(),
        "continuity_before_root": operation.continuity_before_root.hex(),
        "continuity_after_root": operation.continuity_after_root.hex(),
        "nullifier_root_before": nullifier_before.hex(),
        "nullifier_root_after": nullifier_after.hex(),
        "payment_root_before": payment_before.hex(),
        "payment_root_after": payment_after.hex(),
        "state_binding": state_binding.hex(),
        "previous_audit_head": previous_head.hex(),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")


def _direct_audit_payload_from_json(encoded: bytes) -> dict[str, object]:
    try:
        payload = json.loads(encoded.decode("ascii"))
        if type(payload) is not dict or set(payload) != _DIRECT_AUDIT_PAYLOAD_FIELDS:
            raise ValueError
        if payload["version"] != 3 or payload["event_kind"] != "DIRECT_STATE_OWNED_CLEARANCE_V1":
            raise ValueError
        for name in ("epoch", "sequence_before", "sequence_after", "event_time", "observation_time", "rule_effective_time", "decision_time"):
            value = payload[name]
            if type(value) is not int or value < 0:
                raise ValueError
        if payload["epoch"] <= 0 or payload["sequence_after"] != payload["sequence_before"] + 1:
            raise ValueError
        if payload["policy_result"] not in (1, 2, 3, 4) or payload["effective_directive"] not in (1, 2, 3, 4, 5):
            raise ValueError
        if payload["policy_result"] != {1: 1, 2: 2, 3: 3, 4: 4, 5: 4}[payload["effective_directive"]]:
            raise ValueError
        if payload["clearance_advanced"] not in (0, 1):
            raise ValueError
        for name in _DIRECT_AUDIT_HEX_FIELDS:
            value = payload[name]
            if type(value) is not str or len(bytes.fromhex(value)) != 64:
                raise ValueError
        return payload
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise ProductionBoundaryError("database_direct_audit_payload_invalid") from exc


def _direct_operation_record_values(
    operation: DirectStateOwnedOperationV1,
) -> tuple[object, ...]:
    return (
        operation.bundle_id,
        operation.receipt_id,
        operation.request_id,
        operation.attempt_id,
        operation.decision_id,
        operation.join_id,
        operation.source_root,
        operation.profile_id,
        operation.schema_id,
        operation.program_id,
        operation.mode_id,
        operation.evaluator_id,
        operation.control_set_id,
        operation.rule_id,
        operation.phase0_receipt_binding,
        operation.exception_id,
        operation.policy_result,
        operation.effective_directive,
        operation.event_time,
        operation.observation_time,
        operation.rule_effective_time,
        operation.decision_time,
        operation.continuity_epoch,
        operation.continuity_sequence_before,
        operation.continuity_sequence_after,
        operation.continuity_before_state_id,
        operation.continuity_after_state_id,
        operation.continuity_before_audit_head,
        operation.continuity_after_audit_head,
        operation.continuity_before_root,
        operation.continuity_after_root,
    )


def _direct_receipt_from_row(
    row: tuple[object, ...],
) -> DirectStateOwnedDatabaseReceiptV1:
    if len(row) != 15:
        raise ProductionBoundaryError("database_direct_receipt_shape_invalid")
    normalized = tuple(
        value if type(value) is int else bytes(value)
        for value in row
    )
    return DirectStateOwnedDatabaseReceiptV1(
        operation_digest=normalized[0],  # type: ignore[arg-type]
        bundle_id=normalized[1],  # type: ignore[arg-type]
        receipt_id=normalized[2],  # type: ignore[arg-type]
        decision_id=normalized[3],  # type: ignore[arg-type]
        join_id=normalized[4],  # type: ignore[arg-type]
        sequence_before=normalized[5],  # type: ignore[arg-type]
        sequence_after=normalized[6],  # type: ignore[arg-type]
        nullifier_root_before=normalized[7],  # type: ignore[arg-type]
        nullifier_root_after=normalized[8],  # type: ignore[arg-type]
        clearance_root_before=normalized[9],  # type: ignore[arg-type]
        clearance_root_after=normalized[10],  # type: ignore[arg-type]
        state_binding=normalized[11],  # type: ignore[arg-type]
        audit_head=normalized[12],  # type: ignore[arg-type]
        effective_directive=normalized[13],  # type: ignore[arg-type]
        clearance_advanced=bool(normalized[14]),
    )


def _direct_operation_from_record(
    row: tuple[object, ...],
) -> DirectStateOwnedOperationV1:
    if len(row) != 41:
        raise ProductionBoundaryError("database_direct_operation_record_shape_invalid")
    normalized = tuple(
        value if type(value) is int else bytes(value)
        for value in row
    )
    try:
        return DirectStateOwnedOperationV1(
            bundle_id=normalized[1],  # type: ignore[arg-type]
            receipt_id=normalized[2],  # type: ignore[arg-type]
            request_id=normalized[3],  # type: ignore[arg-type]
            attempt_id=normalized[4],  # type: ignore[arg-type]
            decision_id=normalized[5],  # type: ignore[arg-type]
            join_id=normalized[6],  # type: ignore[arg-type]
            source_root=normalized[7],  # type: ignore[arg-type]
            profile_id=normalized[8],  # type: ignore[arg-type]
            schema_id=normalized[9],  # type: ignore[arg-type]
            program_id=normalized[10],  # type: ignore[arg-type]
            mode_id=normalized[11],  # type: ignore[arg-type]
            evaluator_id=normalized[12],  # type: ignore[arg-type]
            control_set_id=normalized[13],  # type: ignore[arg-type]
            rule_id=normalized[14],  # type: ignore[arg-type]
            phase0_receipt_binding=normalized[15],  # type: ignore[arg-type]
            exception_id=normalized[16],  # type: ignore[arg-type]
            policy_result=normalized[17],  # type: ignore[arg-type]
            effective_directive=normalized[18],  # type: ignore[arg-type]
            event_time=normalized[19],  # type: ignore[arg-type]
            observation_time=normalized[20],  # type: ignore[arg-type]
            rule_effective_time=normalized[21],  # type: ignore[arg-type]
            decision_time=normalized[22],  # type: ignore[arg-type]
            continuity_epoch=normalized[23],  # type: ignore[arg-type]
            continuity_sequence_before=normalized[24],  # type: ignore[arg-type]
            continuity_sequence_after=normalized[25],  # type: ignore[arg-type]
            continuity_before_state_id=normalized[26],  # type: ignore[arg-type]
            continuity_after_state_id=normalized[27],  # type: ignore[arg-type]
            continuity_before_audit_head=normalized[28],  # type: ignore[arg-type]
            continuity_after_audit_head=normalized[29],  # type: ignore[arg-type]
            continuity_before_root=normalized[30],  # type: ignore[arg-type]
            continuity_after_root=normalized[31],  # type: ignore[arg-type]
        )
    except (TypeError, ValueError) as exc:
        raise ProductionBoundaryError(
            "database_direct_operation_record_invalid"
        ) from exc


_MIGRATION_AUDIT_HEX_FIELDS = frozenset(
    {
        "migration_commitment",
        "migration_evidence_commitment",
        "migration_version_commitment",
        "equivalence_commitment",
        "source_checkpoint_commitment",
        "target_state_commitment",
        "known_target_checkpoint",
        "batch_nonce_commitment",
        "envelope_commitment",
        "statement_commitment",
        "native_evidence_commitment",
        "proof_package_commitment",
        "transcript_commitment",
        "public_fields_commitment",
        "submitter_commitment",
        "previous_audit_head",
        "state_binding_before",
        "state_binding_after",
        "nullifier_root_before",
        "nullifier_root_after",
        "payment_state_root_before",
        "payment_state_root_after",
        "governance_commitment",
        "settlement_domain_commitment_before",
        "settlement_domain_commitment_after",
        "profile_id_before",
        "profile_id_after",
        "proof_suite_id_before",
        "proof_suite_id_after",
        "schema_id_before",
        "schema_id_after",
        "verifier_artifact_identity_before",
        "verifier_artifact_identity_after",
    }
)
_MIGRATION_AUDIT_PAYLOAD_FIELDS = _MIGRATION_AUDIT_HEX_FIELDS | {
    "version",
    "event_kind",
    "migration_kind",
    "epoch_before",
    "epoch_after",
    "sequence_before",
    "sequence_after",
}


def _migration_audit_payload(
    *,
    operation: VerifiedMigrationOperationV2,
    state_binding_after: bytes,
    previous_audit_head: bytes,
) -> bytes:
    transition = operation.transition
    source = operation.source_identity
    target = operation.target
    evidence = operation.evidence
    payload = {
        "version": 2,
        "event_kind": "PRIVACY_V2_MIGRATION",
        "migration_kind": evidence.kind,
        "epoch_before": source.epoch,
        "epoch_after": target.epoch,
        "sequence_before": target.sequence_before,
        "sequence_after": target.sequence_after,
        "migration_commitment": operation.migration_commitment.hex(),
        "migration_evidence_commitment": evidence.commitment.hex(),
        "migration_version_commitment": evidence.version_commitment.hex(),
        "equivalence_commitment": evidence.equivalence_commitment.hex(),
        "source_checkpoint_commitment": source.checkpoint_commitment.hex(),
        "target_state_commitment": target.target_state_commitment.hex(),
        "known_target_checkpoint": (
            bytes(64).hex()
            if evidence.known_target_checkpoint is None
            else evidence.known_target_checkpoint.hex()
        ),
        "batch_nonce_commitment": _digest(
            _BATCH_NONCE_BINDING, transition.batch_nonce
        ).hex(),
        "envelope_commitment": transition.envelope_commitment.hex(),
        "statement_commitment": transition.statement_commitment.hex(),
        "native_evidence_commitment": transition.evidence_commitment.hex(),
        "proof_package_commitment": transition.proof_package_commitment.hex(),
        "transcript_commitment": transition.transcript_commitment.hex(),
        "public_fields_commitment": transition.public_fields_commitment.hex(),
        "submitter_commitment": _digest(
            _SUBMITTER_AUDIT_DOMAIN, transition.submitter
        ).hex(),
        "previous_audit_head": previous_audit_head.hex(),
        "state_binding_before": source.state_binding.hex(),
        "state_binding_after": state_binding_after.hex(),
        "nullifier_root_before": target.strong_nullifier_root_before.hex(),
        "nullifier_root_after": target.strong_nullifier_root_after.hex(),
        "payment_state_root_before": target.strong_payment_state_root_before.hex(),
        "payment_state_root_after": target.strong_payment_state_root_after.hex(),
        "governance_commitment": target.governance_commitment.hex(),
        "settlement_domain_commitment_before": source.settlement_domain_commitment.hex(),
        "settlement_domain_commitment_after": target.settlement_domain_commitment.hex(),
        "profile_id_before": source.profile_id.hex(),
        "profile_id_after": target.profile_id.hex(),
        "proof_suite_id_before": source.suite_id.hex(),
        "proof_suite_id_after": target.suite_id.hex(),
        "schema_id_before": source.schema_id.hex(),
        "schema_id_after": target.schema_id.hex(),
        "verifier_artifact_identity_before": source.verifier_artifact_identity.hex(),
        "verifier_artifact_identity_after": target.verifier_artifact_identity.hex(),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")


def _migration_audit_payload_from_json(encoded: bytes) -> dict[str, object]:
    try:
        payload = json.loads(encoded.decode("ascii"))
        if type(payload) is not dict or set(payload) != _MIGRATION_AUDIT_PAYLOAD_FIELDS:
            raise ValueError
        if payload["version"] != 2 or payload["event_kind"] != "PRIVACY_V2_MIGRATION":
            raise ValueError
        if payload["migration_kind"] not in {"MIGRATION", "ROLLBACK", "RECOVERY"}:
            raise ValueError
        before = payload["sequence_before"]
        after = payload["sequence_after"]
        epoch_before = payload["epoch_before"]
        epoch_after = payload["epoch_after"]
        if (
            type(before) is not int
            or before < 0
            or type(after) is not int
            or after != before + 1
            or type(epoch_before) is not int
            or epoch_before <= 0
            or type(epoch_after) is not int
            or epoch_after != epoch_before + 1
        ):
            raise ValueError
        for name in _MIGRATION_AUDIT_HEX_FIELDS:
            value = payload[name]
            if type(value) is not str or len(bytes.fromhex(value)) != 64:
                raise ValueError
        return payload
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise ProductionBoundaryError("database_migration_audit_payload_invalid") from exc


class SQLiteSettlementStoreV2(TransactionalSettlementStoragePort):
    """Serializable SQLite reference for one atomic proof/state transition."""

    def __init__(
        self,
        *,
        path: Path,
        settlement_domain: bytes,
        governance_authority: GovernanceAuthorityV2,
        initial_strong_nullifier_root: bytes,
        initial_strong_payment_state_root: bytes,
        epoch: int,
        profile_id: bytes,
        suite_id: bytes,
        schema_id: bytes,
        verifier_artifact_identity: bytes,
        anti_rollback: AntiRollbackReference | None = None,
        before_commit_hook: Callable[[], None] | None = None,
    ) -> None:
        if not isinstance(path, Path):
            raise TypeError("database_path_required")
        if path.exists() and path.is_symlink():
            raise ProductionBoundaryError("database_path_symlink_forbidden")
        if path.exists() and not path.is_file():
            raise ProductionBoundaryError("database_path_must_be_regular_file")
        if not path.parent.is_dir():
            raise ProductionBoundaryError("database_parent_directory_missing")
        if type(governance_authority) is not GovernanceAuthorityV2:
            raise TypeError("database_governance_authority_required")
        self._path = path
        self._settlement_domain = _field("database_settlement_domain", settlement_domain, nonzero=True)
        self._governance_authority = governance_authority
        self._initial_nullifier_root = _wide(
            "database_initial_strong_nullifier_root", initial_strong_nullifier_root
        )
        self._initial_payment_root = _wide(
            "database_initial_strong_payment_state_root", initial_strong_payment_state_root
        )
        if type(epoch) is not int or epoch <= 0 or epoch >= 2**64:
            raise ProductionBoundaryError("database_epoch_invalid")
        self._epoch = epoch
        self._profile_id = _wide("database_profile_id", profile_id)
        self._suite_id = _wide("database_suite_id", suite_id)
        self._schema_id = _wide("database_schema_id", schema_id)
        self._verifier_artifact_identity = _wide(
            "database_verifier_artifact_identity", verifier_artifact_identity
        )
        if before_commit_hook is not None and not callable(before_commit_hook):
            raise TypeError("database_commit_hook_invalid")
        self._anti_rollback = anti_rollback
        self._before_commit_hook = before_commit_hook
        self._native_authority_key: bytes | None = None
        self._migration_authority_key: bytes | None = None
        self._direct_authority_key: bytes | None = None
        self._direct_mode_id: bytes | None = None
        self._direct_evaluator_id: bytes | None = None
        self._direct_control_set_id: bytes | None = None
        self._direct_rule_id: bytes | None = None
        self._direct_phase0_receipt_binding: bytes | None = None
        self._closed = False
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        if self._closed:
            raise ProductionBoundaryError("database_store_closed")
        connection = sqlite3.connect(
            str(self._path),
            timeout=10.0,
            isolation_level=None,
            check_same_thread=False,
        )
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=10000")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    @staticmethod
    def _discard_created_database(path: Path) -> None:
        for candidate in (path, Path(str(path) + "-wal"), Path(str(path) + "-shm")):
            if candidate.exists() and candidate.is_file() and not candidate.is_symlink():
                candidate.unlink()

    @property
    def path(self) -> Path:
        return self._path

    def _bind_native_authority(self, authority_key: bytes) -> None:
        key = _wide("database_native_authority_key", authority_key)
        if self._closed:
            raise ProductionBoundaryError("database_store_closed")
        if self._native_authority_key is not None:
            raise ProductionBoundaryError("database_native_authority_already_bound")
        self._native_authority_key = key

    def _bind_migration_authority(self, authority_key: bytes) -> None:
        key = _wide("database_migration_authority_key", authority_key)
        if self._closed:
            raise ProductionBoundaryError("database_store_closed")
        if self._migration_authority_key is not None:
            raise ProductionBoundaryError("database_migration_authority_already_bound")
        self._migration_authority_key = key

    def _bind_direct_authority(
        self,
        authority_key: bytes,
        *,
        mode_id: bytes,
        evaluator_id: bytes,
        control_set_id: bytes,
        rule_id: bytes,
        phase0_receipt_binding: bytes,
    ) -> None:
        key = _wide("database_direct_authority_key", authority_key)
        mode = _wide("database_direct_mode_id", mode_id)
        evaluator = _wide("database_direct_evaluator_id", evaluator_id)
        control = _wide("database_direct_control_set_id", control_set_id)
        rule = _wide("database_direct_rule_id", rule_id)
        phase0 = _wide(
            "database_direct_phase0_receipt_binding",
            phase0_receipt_binding,
        )
        if self._closed:
            raise ProductionBoundaryError("database_store_closed")
        if self._direct_authority_key is not None:
            raise ProductionBoundaryError("database_direct_authority_already_bound")
        self._direct_authority_key = key
        self._direct_mode_id = mode
        self._direct_evaluator_id = evaluator
        self._direct_control_set_id = control
        self._direct_rule_id = rule
        self._direct_phase0_receipt_binding = phase0

    def _seal_direct_state_owned(
        self,
        operation: DirectStateOwnedOperationV1,
    ) -> DirectStateOwnedOperationV1:
        if type(operation) is not DirectStateOwnedOperationV1:
            raise TypeError("direct_operation_required")
        if self._direct_authority_key is None:
            raise ProductionBoundaryError("database_direct_authority_unbound")
        return replace(
            operation,
            seal=_direct_operation_seal(self._direct_authority_key, operation),
        )

    def _reconcile_anti_rollback_state(
        self,
        *,
        epoch: int,
        state_binding: bytes,
        transition_commitment: bytes | None,
    ) -> PendingAntiRollbackTransition | None:
        if self._anti_rollback is None:
            return None
        if type(epoch) is not int or epoch < 0:
            raise ProductionBoundaryError("anti_rollback_epoch_invalid")
        binding = _wide("anti_rollback_state_binding", state_binding)
        if epoch == 0:
            if transition_commitment is not None:
                raise ProductionBoundaryError("anti_rollback_genesis_transition_invalid")
            committed_transition = None
        else:
            committed_transition = _wide(
                "anti_rollback_transition_commitment",
                transition_commitment,
            )
        observed = self._anti_rollback.snapshot()
        if observed is None:
            if epoch != 0:
                raise ProductionBoundaryError("anti_rollback_anchor_uninitialized")
            self._anti_rollback.initialize(epoch, binding)
            observed = self._anti_rollback.snapshot()
            if observed is None:
                raise ProductionBoundaryError("anti_rollback_anchor_initialization_failed")
        if type(observed) is not AntiRollbackAnchorSnapshot:
            raise ProductionBoundaryError("anti_rollback_snapshot_invalid")
        pending = observed.pending
        if pending is not None:
            if epoch == pending.next_epoch and binding == pending.next_state_binding:
                if committed_transition != pending.transition_commitment:
                    raise ProductionBoundaryError(
                        "anti_rollback_pending_transition_mismatch"
                    )
                self._anti_rollback.finalize(
                    next_epoch=pending.next_epoch,
                    next_state_binding=pending.next_state_binding,
                    transition_commitment=pending.transition_commitment,
                )
                return None
            if epoch == observed.epoch and binding == observed.state_binding:
                if committed_transition != observed.transition_commitment:
                    raise ProductionBoundaryError(
                        "anti_rollback_committed_transition_mismatch"
                    )
                return pending
            if epoch < observed.epoch:
                raise ProductionBoundaryError("anti_rollback_state_older_than_anchor")
            raise ProductionBoundaryError("anti_rollback_pending_state_mismatch")
        if epoch < observed.epoch:
            raise ProductionBoundaryError("anti_rollback_state_older_than_anchor")
        if epoch > observed.epoch:
            raise ProductionBoundaryError("anti_rollback_anchor_behind_state")
        if binding != observed.state_binding:
            raise ProductionBoundaryError("anti_rollback_state_binding_mismatch")
        if committed_transition != observed.transition_commitment:
            raise ProductionBoundaryError(
                "anti_rollback_committed_transition_mismatch"
            )
        return None

    @staticmethod
    def _latest_operation_digest(
        connection: sqlite3.Connection,
        epoch: int,
    ) -> bytes | None:
        if type(epoch) is not int or epoch < 0:
            raise ProductionBoundaryError("database_state_anti_rollback_epoch_invalid")
        if epoch == 0:
            return None
        row = connection.execute(
            "SELECT transition_kind, record_commitment FROM transition_records "
            "WHERE sequence_after=?",
            (epoch,),
        ).fetchone()
        if row is None:
            raise ProductionBoundaryError("database_latest_operation_missing")
        kind, recorded = row[0], bytes(row[1])
        if kind == "SETTLEMENT":
            authority = connection.execute(
                "SELECT operation_digest FROM settlement_requests WHERE sequence_after=?",
                (epoch,),
            ).fetchone()
            if authority is None:
                authority = connection.execute(
                    "SELECT operation_digest FROM direct_clearance_requests "
                    "WHERE sequence_after=?",
                    (epoch,),
                ).fetchone()
        else:
            authority = connection.execute(
                "SELECT migration_commitment FROM migration_requests WHERE sequence_after=?",
                (epoch,),
            ).fetchone()
        if authority is None:
            raise ProductionBoundaryError("database_latest_operation_missing")
        authoritative = _wide("database_latest_operation_digest", bytes(authority[0]))
        # Return the source record's value so an external pending reservation
        # reports its exact mismatch.  Full integrity additionally rejects a
        # divergence from the immutable transition ledger.
        if authoritative != recorded:
            return authoritative
        return recorded

    @staticmethod
    def _upgrade_schema_version(connection: sqlite3.Connection) -> None:
        row = connection.execute(
            "SELECT schema_version FROM metadata WHERE id=1"
        ).fetchone()
        if row == (_SCHEMA_VERSION,):
            return
        if row in {(1,), (2,)}:
            raise ProductionBoundaryError("database_legacy_governance_schema_rejected")
        raise ProductionBoundaryError("database_schema_version_mismatch")

    @staticmethod
    def _governance_authority_at(
        connection: sqlite3.Connection,
        activation_sequence: int,
    ) -> GovernanceAuthorityV2:
        row = connection.execute(
            "SELECT activation_sequence, governance_commitment, profile_code, epoch, "
            "truth_root_0, truth_root_1, truth_root_2, truth_root_3, truth_root_4, "
            "truth_root_5, claim_truth_authority_digest, nullifier_authority_id, "
            "pepper_commitment FROM governance_authorities WHERE activation_sequence=?",
            (activation_sequence,),
        ).fetchone()
        if row is None:
            raise ProductionBoundaryError("database_governance_authority_missing")
        return _governance_authority_from_row(row)

    @staticmethod
    def _governance_authority_by_commitment(
        connection: sqlite3.Connection,
        commitment: bytes,
    ) -> GovernanceAuthorityV2:
        row = connection.execute(
            "SELECT activation_sequence, governance_commitment, profile_code, epoch, "
            "truth_root_0, truth_root_1, truth_root_2, truth_root_3, truth_root_4, "
            "truth_root_5, claim_truth_authority_digest, nullifier_authority_id, "
            "pepper_commitment FROM governance_authorities WHERE governance_commitment=?",
            (sqlite3.Binary(_wide("database_governance_commitment", commitment)),),
        ).fetchone()
        if row is None:
            raise ProductionBoundaryError("database_governance_authority_missing")
        return _governance_authority_from_row(row)

    @staticmethod
    def _insert_governance_authority(
        connection: sqlite3.Connection,
        activation_sequence: int,
        authority: GovernanceAuthorityV2,
    ) -> None:
        values = _governance_authority_row(activation_sequence, authority)
        connection.execute(
            "INSERT INTO governance_authorities VALUES "
            "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            tuple(
                value if type(value) is int else sqlite3.Binary(value)
                for value in values
            ),
        )

    def _ensure_genesis_and_history(
        self,
        connection: sqlite3.Connection,
        config: tuple[object, ...],
        state: tuple[object, ...],
    ) -> None:
        domain_commitment, governance, profile, suite, schema, verifier, epoch = tuple(
            bytes(value) if isinstance(value, (bytes, bytearray)) else value
            for value in config
        )
        governance = _wide("database_genesis_governance", governance)
        governance_authority = self._governance_authority
        profile = _wide("database_genesis_profile", profile)
        suite = _wide("database_genesis_suite", suite)
        schema = _wide("database_genesis_schema", schema)
        verifier = _wide("database_genesis_verifier", verifier)
        domain_commitment = _wide("database_genesis_domain", domain_commitment)
        if type(epoch) is not int or epoch <= 0:
            raise ProductionBoundaryError("database_genesis_epoch_invalid")
        genesis_binding = _digest(
            _DATABASE_STATE_BINDING,
            _u64(epoch, "database_epoch"),
            _u64(0, "database_sequence"),
            self._initial_nullifier_root,
            self._initial_payment_root,
            governance,
        )
        genesis_audit = _digest(
            _AUDIT_GENESIS_DOMAIN,
            genesis_binding,
            self._initial_nullifier_root,
            self._initial_payment_root,
        )
        genesis_identity = PrivacyV2DatabaseIdentity(
            settlement_domain_commitment=domain_commitment,
            governance_commitment=governance,
            governance_authority=governance_authority,
            profile_id=profile,
            suite_id=suite,
            schema_id=schema,
            verifier_artifact_identity=verifier,
            epoch=epoch,
            sequence=0,
            strong_nullifier_root=self._initial_nullifier_root,
            strong_payment_state_root=self._initial_payment_root,
            state_binding=genesis_binding,
            audit_head=genesis_audit,
            anti_rollback_epoch=0,
            settled_batch_count=0,
        )
        observed = connection.execute(
            "SELECT settlement_domain_commitment, governance_commitment, profile_id, suite_id, "
            "schema_id, verifier_artifact_identity, epoch, strong_nullifier_root, "
            "strong_payment_state_root, state_binding, audit_head, checkpoint_commitment "
            "FROM database_genesis WHERE id=1"
        ).fetchone()
        expected = (
            domain_commitment,
            governance,
            profile,
            suite,
            schema,
            verifier,
            epoch,
            self._initial_nullifier_root,
            self._initial_payment_root,
            genesis_binding,
            genesis_audit,
            genesis_identity.checkpoint_commitment,
        )
        if observed is None:
            connection.execute(
                "INSERT INTO database_genesis VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                tuple(
                    value if type(value) is int else sqlite3.Binary(value)
                    for value in expected
                ),
            )
        else:
            normalized = tuple(
                value if type(value) is int else bytes(value) for value in observed
            )
            (
                domain_commitment,
                governance,
                profile,
                suite,
                schema,
                verifier,
                epoch,
                genesis_nullifier,
                genesis_payment,
                observed_binding,
                observed_audit,
                observed_checkpoint,
            ) = normalized
            governance_authority = self._governance_authority_by_commitment(
                connection,
                governance,  # type: ignore[arg-type]
            )
            if (
                genesis_nullifier != self._initial_nullifier_root
                or genesis_payment != self._initial_payment_root
            ):
                raise ProductionBoundaryError("database_genesis_input_mismatch")
            genesis_binding = _digest(
                _DATABASE_STATE_BINDING,
                _u64(epoch, "database_epoch"),  # type: ignore[arg-type]
                _u64(0, "database_sequence"),
                genesis_nullifier,  # type: ignore[arg-type]
                genesis_payment,  # type: ignore[arg-type]
                governance,  # type: ignore[arg-type]
            )
            genesis_audit = _digest(
                _AUDIT_GENESIS_DOMAIN,
                genesis_binding,
                genesis_nullifier,  # type: ignore[arg-type]
                genesis_payment,  # type: ignore[arg-type]
            )
            genesis_identity = PrivacyV2DatabaseIdentity(
                settlement_domain_commitment=domain_commitment,  # type: ignore[arg-type]
                governance_commitment=governance,  # type: ignore[arg-type]
                governance_authority=governance_authority,
                profile_id=profile,  # type: ignore[arg-type]
                suite_id=suite,  # type: ignore[arg-type]
                schema_id=schema,  # type: ignore[arg-type]
                verifier_artifact_identity=verifier,  # type: ignore[arg-type]
                epoch=epoch,  # type: ignore[arg-type]
                sequence=0,
                strong_nullifier_root=genesis_nullifier,  # type: ignore[arg-type]
                strong_payment_state_root=genesis_payment,  # type: ignore[arg-type]
                state_binding=genesis_binding,
                audit_head=genesis_audit,
                anti_rollback_epoch=0,
                settled_batch_count=0,
            )
            expected = (
                domain_commitment,
                governance,
                profile,
                suite,
                schema,
                verifier,
                epoch,
                genesis_nullifier,
                genesis_payment,
                genesis_binding,
                genesis_audit,
                genesis_identity.checkpoint_commitment,
            )
            if normalized != expected:
                raise ProductionBoundaryError("database_genesis_identity_mismatch")
        history = connection.execute(
            "SELECT settlement_domain_commitment, profile_id, suite_id, schema_id, "
            "verifier_artifact_identity, epoch, "
            "migration_commitment FROM configuration_history WHERE activation_sequence=0"
        ).fetchone()
        expected_history = (domain_commitment, profile, suite, schema, verifier, epoch, None)
        if history is None:
            connection.execute(
                "INSERT INTO configuration_history VALUES (0, ?, ?, ?, ?, ?, ?, NULL)",
                (
                    sqlite3.Binary(domain_commitment),
                    sqlite3.Binary(profile),
                    sqlite3.Binary(suite),
                    sqlite3.Binary(schema),
                    sqlite3.Binary(verifier),
                    epoch,
                ),
            )
        else:
            normalized_history = tuple(
                value
                if value is None or type(value) is int
                else bytes(value)
                for value in history
            )
            if normalized_history != expected_history:
                raise ProductionBoundaryError("database_genesis_history_mismatch")

        transition_count = connection.execute(
            "SELECT COUNT(*) FROM transition_records"
        ).fetchone()[0]
        request_count = connection.execute(
            "SELECT COUNT(*) FROM settlement_requests"
        ).fetchone()[0]
        direct_count = connection.execute(
            "SELECT COUNT(*) FROM direct_clearance_requests"
        ).fetchone()[0]
        migration_count = connection.execute(
            "SELECT COUNT(*) FROM migration_requests"
        ).fetchone()[0]
        if transition_count == 0 and request_count and migration_count == 0:
            previous_binding = genesis_binding
            settled_count = 0
            rows = connection.execute(
                "SELECT operation_digest, sequence_before, sequence_after, "
                "strong_nullifier_root_before, strong_nullifier_root_after, "
                "strong_payment_state_root_before, strong_payment_state_root_after, "
                "state_binding_after FROM settlement_requests ORDER BY sequence_after"
            )
            for row in rows:
                operation_digest = bytes(row[0])
                sequence_before, sequence_after = row[1], row[2]
                if sequence_before != settled_count or sequence_after != settled_count + 1:
                    raise ProductionBoundaryError("database_v1_transition_sequence_invalid")
                state_binding_after = bytes(row[7])
                audit_row = connection.execute(
                    "SELECT current_head FROM audit_events WHERE sequence=?",
                    (sequence_after,),
                ).fetchone()
                if audit_row is None:
                    raise ProductionBoundaryError("database_v1_audit_missing")
                checkpoint = PrivacyV2DatabaseIdentity(
                    settlement_domain_commitment=domain_commitment,
                    governance_commitment=governance,
                    governance_authority=governance_authority,
                    profile_id=profile,
                    suite_id=suite,
                    schema_id=schema,
                    verifier_artifact_identity=verifier,
                    epoch=epoch,
                    sequence=sequence_after,
                    strong_nullifier_root=bytes(row[4]),
                    strong_payment_state_root=bytes(row[6]),
                    state_binding=state_binding_after,
                    audit_head=bytes(audit_row[0]),
                    anti_rollback_epoch=sequence_after,
                    settled_batch_count=sequence_after,
                )
                connection.execute(
                    "INSERT INTO transition_records VALUES "
                    "(?, 'SETTLEMENT', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        sequence_after,
                        sqlite3.Binary(operation_digest),
                        sqlite3.Binary(previous_binding),
                        sqlite3.Binary(state_binding_after),
                        sqlite3.Binary(bytes(row[3])),
                        sqlite3.Binary(bytes(row[4])),
                        sqlite3.Binary(bytes(row[5])),
                        sqlite3.Binary(bytes(row[6])),
                        sqlite3.Binary(governance),
                        sqlite3.Binary(governance),
                        sqlite3.Binary(profile),
                        sqlite3.Binary(profile),
                        sqlite3.Binary(suite),
                        sqlite3.Binary(suite),
                        sqlite3.Binary(schema),
                        sqlite3.Binary(schema),
                        sqlite3.Binary(verifier),
                        sqlite3.Binary(verifier),
                        epoch,
                        epoch,
                        sqlite3.Binary(checkpoint.checkpoint_commitment),
                    ),
                )
                previous_binding = state_binding_after
                settled_count += 1
        elif transition_count != request_count + direct_count + migration_count:
            raise ProductionBoundaryError("database_transition_ledger_count_mismatch")

    def _initialize(self) -> None:
        with closing(self._connect()) as connection:
            began = False
            try:
                tables = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                    ).fetchall()
                }
                if "metadata" in tables:
                    self._upgrade_schema_version(connection)
                elif tables:
                    raise ProductionBoundaryError("database_schema_metadata_missing")
                connection.execute("PRAGMA journal_mode=WAL")
                self._create_schema(connection)
                connection.execute("BEGIN IMMEDIATE")
                began = True
                self._upgrade_schema_version(connection)
                self._validate_schema_version(connection)
                config = connection.execute(
                    "SELECT settlement_domain_commitment, governance_commitment, profile_id, "
                    "suite_id, schema_id, verifier_artifact_identity, epoch "
                    "FROM configuration WHERE id=1"
                ).fetchone()
                if config is None:
                    config = (
                        _digest(_DOMAIN_COMMITMENT_DOMAIN, self._settlement_domain),
                        self._governance_authority.commitment_512,
                        self._profile_id,
                        self._suite_id,
                        self._schema_id,
                        self._verifier_artifact_identity,
                        self._epoch,
                    )
                    connection.execute(
                        "INSERT INTO configuration VALUES (1, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            *(sqlite3.Binary(value) for value in config[:-1]),
                            config[-1],
                        ),
                    )
                else:
                    self._validate_config_row(config)
                authority_rows = connection.execute(
                    "SELECT COUNT(*) FROM governance_authorities"
                ).fetchone()[0]
                if authority_rows == 0:
                    self._insert_governance_authority(
                        connection,
                        0,
                        self._governance_authority,
                    )
                elif (
                    self._governance_authority_by_commitment(
                        connection,
                        bytes(config[1]),
                    )
                    != self._governance_authority
                ):
                    raise ProductionBoundaryError(
                        "database_current_governance_authority_mismatch"
                    )
                state = connection.execute(
                    "SELECT epoch, sequence, strong_nullifier_root, strong_payment_state_root, "
                    "state_binding, audit_head, governance_commitment, anti_rollback_epoch, "
                    "settled_batch_count FROM state WHERE id=1"
                ).fetchone()
                if state is None:
                    state_binding = _digest(
                        _DATABASE_STATE_BINDING,
                        _u64(self._epoch, "database_epoch"),
                        _u64(0, "database_sequence"),
                        self._initial_nullifier_root,
                        self._initial_payment_root,
                        self._governance_authority.commitment_512,
                    )
                    audit_head = _digest(
                        _AUDIT_GENESIS_DOMAIN,
                        state_binding,
                        self._initial_nullifier_root,
                        self._initial_payment_root,
                    )
                    connection.execute(
                        "INSERT INTO state VALUES (1, ?, 0, ?, ?, ?, ?, ?, 0, 0)",
                        (
                            self._epoch,
                            sqlite3.Binary(self._initial_nullifier_root),
                            sqlite3.Binary(self._initial_payment_root),
                            sqlite3.Binary(state_binding),
                            sqlite3.Binary(audit_head),
                            sqlite3.Binary(self._governance_authority.commitment_512),
                        ),
                    )
                    state = (
                        self._epoch,
                        0,
                        self._initial_nullifier_root,
                        self._initial_payment_root,
                        state_binding,
                        audit_head,
                        self._governance_authority.commitment_512,
                        0,
                        0,
                    )
                self._validate_state_row(state)
                self._ensure_genesis_and_history(connection, config, state)
                state_transition_commitment = self._latest_operation_digest(
                    connection,
                    state[7],  # type: ignore[arg-type]
                )
                connection.execute("COMMIT")
                began = False
            except Exception:
                if began and connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        try:
            self._reconcile_anti_rollback_state(
                epoch=state[7],  # type: ignore[arg-type]
                state_binding=bytes(state[4]),
                transition_commitment=state_transition_commitment,
            )
        except Exception:
            self.close()
            raise
        self.verify_integrity()

    @staticmethod
    def _create_schema(connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS metadata (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                schema_version INTEGER NOT NULL CHECK (schema_version = 3)
            );
            INSERT OR IGNORE INTO metadata(id, schema_version) VALUES (1, 3);
            CREATE TABLE IF NOT EXISTS configuration (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                settlement_domain_commitment BLOB NOT NULL CHECK (length(settlement_domain_commitment) = 64),
                governance_commitment BLOB NOT NULL CHECK (length(governance_commitment) = 64),
                profile_id BLOB NOT NULL CHECK (length(profile_id) = 64),
                suite_id BLOB NOT NULL CHECK (length(suite_id) = 64),
                schema_id BLOB NOT NULL CHECK (length(schema_id) = 64),
                verifier_artifact_identity BLOB NOT NULL CHECK (length(verifier_artifact_identity) = 64),
                epoch INTEGER NOT NULL CHECK (epoch > 0)
            );
            CREATE TABLE IF NOT EXISTS state (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                epoch INTEGER NOT NULL CHECK (epoch > 0),
                sequence INTEGER NOT NULL CHECK (sequence >= 0),
                strong_nullifier_root BLOB NOT NULL CHECK (length(strong_nullifier_root) = 64),
                strong_payment_state_root BLOB NOT NULL CHECK (length(strong_payment_state_root) = 64),
                state_binding BLOB NOT NULL CHECK (length(state_binding) = 64),
                audit_head BLOB NOT NULL CHECK (length(audit_head) = 64),
                governance_commitment BLOB NOT NULL CHECK (length(governance_commitment) = 64),
                anti_rollback_epoch INTEGER NOT NULL CHECK (anti_rollback_epoch >= 0),
                settled_batch_count INTEGER NOT NULL CHECK (settled_batch_count >= 0)
            );
            CREATE TABLE IF NOT EXISTS governance_authorities (
                activation_sequence INTEGER PRIMARY KEY CHECK (activation_sequence >= 0),
                governance_commitment BLOB NOT NULL UNIQUE CHECK (length(governance_commitment) = 64),
                profile_code INTEGER NOT NULL CHECK (profile_code IN (1, 2, 3)),
                epoch INTEGER NOT NULL CHECK (epoch > 0),
                truth_root_0 BLOB NOT NULL CHECK (length(truth_root_0) = 64),
                truth_root_1 BLOB NOT NULL CHECK (length(truth_root_1) = 64),
                truth_root_2 BLOB NOT NULL CHECK (length(truth_root_2) = 64),
                truth_root_3 BLOB NOT NULL CHECK (length(truth_root_3) = 64),
                truth_root_4 BLOB NOT NULL CHECK (length(truth_root_4) = 64),
                truth_root_5 BLOB NOT NULL CHECK (length(truth_root_5) = 64),
                claim_truth_authority_digest BLOB NOT NULL CHECK (length(claim_truth_authority_digest) = 64),
                nullifier_authority_id BLOB NOT NULL CHECK (length(nullifier_authority_id) = 64),
                pepper_commitment BLOB NOT NULL CHECK (length(pepper_commitment) = 64),
                UNIQUE(profile_code, epoch)
            );
            CREATE TABLE IF NOT EXISTS settlement_requests (
                envelope_commitment BLOB PRIMARY KEY CHECK (length(envelope_commitment) = 64),
                batch_nonce BLOB NOT NULL UNIQUE CHECK (length(batch_nonce) = 32),
                public_fields_commitment BLOB NOT NULL UNIQUE CHECK (length(public_fields_commitment) = 64),
                submitter BLOB NOT NULL CHECK (length(submitter) = 64),
                operation_digest BLOB NOT NULL CHECK (length(operation_digest) = 64),
                sequence_before INTEGER NOT NULL CHECK (sequence_before >= 0),
                sequence_after INTEGER NOT NULL CHECK (sequence_after = sequence_before + 1),
                statement_commitment BLOB NOT NULL CHECK (length(statement_commitment) = 64),
                evidence_commitment BLOB NOT NULL CHECK (length(evidence_commitment) = 64),
                proof_package_commitment BLOB NOT NULL CHECK (length(proof_package_commitment) = 64),
                transcript_commitment BLOB NOT NULL CHECK (length(transcript_commitment) = 64),
                strong_nullifier_root_before BLOB NOT NULL CHECK (length(strong_nullifier_root_before) = 64),
                strong_nullifier_root_after BLOB NOT NULL CHECK (length(strong_nullifier_root_after) = 64),
                strong_payment_state_root_before BLOB NOT NULL CHECK (length(strong_payment_state_root_before) = 64),
                strong_payment_state_root_after BLOB NOT NULL CHECK (length(strong_payment_state_root_after) = 64),
                state_binding_after BLOB NOT NULL CHECK (length(state_binding_after) = 64)
            );
            CREATE TABLE IF NOT EXISTS direct_clearance_requests (
                operation_digest BLOB PRIMARY KEY CHECK (length(operation_digest) = 64),
                bundle_id BLOB NOT NULL UNIQUE CHECK (length(bundle_id) = 64),
                receipt_id BLOB NOT NULL UNIQUE CHECK (length(receipt_id) = 64),
                request_id BLOB NOT NULL UNIQUE CHECK (length(request_id) = 64),
                attempt_id BLOB NOT NULL UNIQUE CHECK (length(attempt_id) = 64),
                decision_id BLOB NOT NULL UNIQUE CHECK (length(decision_id) = 64),
                join_id BLOB NOT NULL UNIQUE CHECK (length(join_id) = 64),
                source_root BLOB NOT NULL CHECK (length(source_root) = 64),
                profile_id BLOB NOT NULL CHECK (length(profile_id) = 64),
                schema_id BLOB NOT NULL CHECK (length(schema_id) = 64),
                program_id BLOB NOT NULL CHECK (length(program_id) = 64),
                mode_id BLOB NOT NULL CHECK (length(mode_id) = 64),
                evaluator_id BLOB NOT NULL CHECK (length(evaluator_id) = 64),
                control_set_id BLOB NOT NULL CHECK (length(control_set_id) = 64),
                rule_id BLOB NOT NULL CHECK (length(rule_id) = 64),
                phase0_receipt_binding BLOB NOT NULL CHECK (length(phase0_receipt_binding) = 64),
                exception_id BLOB NOT NULL CHECK (length(exception_id) = 64),
                policy_result INTEGER NOT NULL CHECK (policy_result IN (1, 2, 3, 4)),
                effective_directive INTEGER NOT NULL CHECK (effective_directive IN (1, 2, 3, 4, 5)),
                event_time INTEGER NOT NULL CHECK (event_time >= 0),
                observation_time INTEGER NOT NULL CHECK (observation_time >= 0),
                rule_effective_time INTEGER NOT NULL CHECK (rule_effective_time >= 0),
                decision_time INTEGER NOT NULL CHECK (decision_time >= 0),
                continuity_epoch INTEGER NOT NULL CHECK (continuity_epoch > 0),
                continuity_sequence_before INTEGER NOT NULL CHECK (continuity_sequence_before >= 0),
                continuity_sequence_after INTEGER NOT NULL CHECK (continuity_sequence_after = continuity_sequence_before + 1),
                continuity_before_state_id BLOB NOT NULL CHECK (length(continuity_before_state_id) = 64),
                continuity_after_state_id BLOB NOT NULL CHECK (length(continuity_after_state_id) = 64),
                continuity_before_audit_head BLOB NOT NULL CHECK (length(continuity_before_audit_head) = 64),
                continuity_after_audit_head BLOB NOT NULL CHECK (length(continuity_after_audit_head) = 64),
                continuity_before_root BLOB NOT NULL CHECK (length(continuity_before_root) = 64),
                continuity_after_root BLOB NOT NULL CHECK (length(continuity_after_root) = 64),
                sequence_before INTEGER NOT NULL CHECK (sequence_before >= 0),
                sequence_after INTEGER NOT NULL CHECK (sequence_after = sequence_before + 1),
                nullifier_root_before BLOB NOT NULL CHECK (length(nullifier_root_before) = 64),
                nullifier_root_after BLOB NOT NULL UNIQUE CHECK (length(nullifier_root_after) = 64),
                payment_root_before BLOB NOT NULL CHECK (length(payment_root_before) = 64),
                payment_root_after BLOB NOT NULL CHECK (length(payment_root_after) = 64),
                state_binding_after BLOB NOT NULL CHECK (length(state_binding_after) = 64),
                audit_head_after BLOB NOT NULL CHECK (length(audit_head_after) = 64),
                clearance_advanced INTEGER NOT NULL CHECK (clearance_advanced IN (0, 1))
            );
            CREATE TRIGGER IF NOT EXISTS direct_clearance_requests_no_update
            BEFORE UPDATE ON direct_clearance_requests
            BEGIN SELECT RAISE(ABORT, 'direct_clearance_requests_append_only'); END;
            CREATE TRIGGER IF NOT EXISTS direct_clearance_requests_no_delete
            BEFORE DELETE ON direct_clearance_requests
            BEGIN SELECT RAISE(ABORT, 'direct_clearance_requests_append_only'); END;
            CREATE TABLE IF NOT EXISTS settled_nullifier_roots (
                strong_nullifier_root_after BLOB PRIMARY KEY CHECK (length(strong_nullifier_root_after) = 64),
                envelope_commitment BLOB NOT NULL REFERENCES settlement_requests(envelope_commitment)
            );
            CREATE TABLE IF NOT EXISTS audit_events (
                sequence INTEGER PRIMARY KEY CHECK (sequence > 0),
                previous_head BLOB NOT NULL CHECK (length(previous_head) = 64),
                event_commitment BLOB NOT NULL UNIQUE CHECK (length(event_commitment) = 64),
                current_head BLOB NOT NULL CHECK (length(current_head) = 64),
                payload BLOB NOT NULL
            );
            CREATE TRIGGER IF NOT EXISTS audit_events_no_update
            BEFORE UPDATE ON audit_events
            BEGIN SELECT RAISE(ABORT, 'audit_events_append_only'); END;
            CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
            BEFORE DELETE ON audit_events
            BEGIN SELECT RAISE(ABORT, 'audit_events_append_only'); END;
            CREATE TABLE IF NOT EXISTS database_genesis (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                settlement_domain_commitment BLOB NOT NULL CHECK (length(settlement_domain_commitment) = 64),
                governance_commitment BLOB NOT NULL CHECK (length(governance_commitment) = 64),
                profile_id BLOB NOT NULL CHECK (length(profile_id) = 64),
                suite_id BLOB NOT NULL CHECK (length(suite_id) = 64),
                schema_id BLOB NOT NULL CHECK (length(schema_id) = 64),
                verifier_artifact_identity BLOB NOT NULL CHECK (length(verifier_artifact_identity) = 64),
                epoch INTEGER NOT NULL CHECK (epoch > 0),
                strong_nullifier_root BLOB NOT NULL CHECK (length(strong_nullifier_root) = 64),
                strong_payment_state_root BLOB NOT NULL CHECK (length(strong_payment_state_root) = 64),
                state_binding BLOB NOT NULL CHECK (length(state_binding) = 64),
                audit_head BLOB NOT NULL CHECK (length(audit_head) = 64),
                checkpoint_commitment BLOB NOT NULL UNIQUE CHECK (length(checkpoint_commitment) = 64)
            );
            CREATE TABLE IF NOT EXISTS configuration_history (
                activation_sequence INTEGER PRIMARY KEY CHECK (activation_sequence >= 0),
                settlement_domain_commitment BLOB NOT NULL CHECK (length(settlement_domain_commitment) = 64),
                profile_id BLOB NOT NULL CHECK (length(profile_id) = 64),
                suite_id BLOB NOT NULL CHECK (length(suite_id) = 64),
                schema_id BLOB NOT NULL CHECK (length(schema_id) = 64),
                verifier_artifact_identity BLOB NOT NULL CHECK (length(verifier_artifact_identity) = 64),
                epoch INTEGER NOT NULL UNIQUE CHECK (epoch > 0),
                migration_commitment BLOB UNIQUE,
                UNIQUE(settlement_domain_commitment, profile_id, suite_id, schema_id, verifier_artifact_identity)
            );
            CREATE TABLE IF NOT EXISTS transition_records (
                sequence_after INTEGER PRIMARY KEY CHECK (sequence_after > 0),
                transition_kind TEXT NOT NULL CHECK (transition_kind IN ('SETTLEMENT', 'MIGRATION', 'ROLLBACK', 'RECOVERY')),
                record_commitment BLOB NOT NULL UNIQUE CHECK (length(record_commitment) = 64),
                state_binding_before BLOB NOT NULL CHECK (length(state_binding_before) = 64),
                state_binding_after BLOB NOT NULL CHECK (length(state_binding_after) = 64),
                nullifier_root_before BLOB NOT NULL CHECK (length(nullifier_root_before) = 64),
                nullifier_root_after BLOB NOT NULL CHECK (length(nullifier_root_after) = 64),
                payment_root_before BLOB NOT NULL CHECK (length(payment_root_before) = 64),
                payment_root_after BLOB NOT NULL CHECK (length(payment_root_after) = 64),
                governance_before BLOB NOT NULL CHECK (length(governance_before) = 64),
                governance_after BLOB NOT NULL CHECK (length(governance_after) = 64),
                profile_before BLOB NOT NULL CHECK (length(profile_before) = 64),
                profile_after BLOB NOT NULL CHECK (length(profile_after) = 64),
                suite_before BLOB NOT NULL CHECK (length(suite_before) = 64),
                suite_after BLOB NOT NULL CHECK (length(suite_after) = 64),
                schema_before BLOB NOT NULL CHECK (length(schema_before) = 64),
                schema_after BLOB NOT NULL CHECK (length(schema_after) = 64),
                verifier_before BLOB NOT NULL CHECK (length(verifier_before) = 64),
                verifier_after BLOB NOT NULL CHECK (length(verifier_after) = 64),
                epoch_before INTEGER NOT NULL CHECK (epoch_before > 0),
                epoch_after INTEGER NOT NULL CHECK (epoch_after > 0),
                checkpoint_commitment_after BLOB NOT NULL UNIQUE CHECK (length(checkpoint_commitment_after) = 64)
            );
            CREATE TABLE IF NOT EXISTS migration_requests (
                migration_commitment BLOB PRIMARY KEY CHECK (length(migration_commitment) = 64),
                migration_kind TEXT NOT NULL CHECK (migration_kind IN ('MIGRATION', 'ROLLBACK', 'RECOVERY')),
                migration_evidence_commitment BLOB NOT NULL UNIQUE CHECK (length(migration_evidence_commitment) = 64),
                migration_version_commitment BLOB NOT NULL CHECK (length(migration_version_commitment) = 64),
                equivalence_commitment BLOB NOT NULL CHECK (length(equivalence_commitment) = 64),
                source_checkpoint_commitment BLOB NOT NULL CHECK (length(source_checkpoint_commitment) = 64),
                target_state_commitment BLOB NOT NULL CHECK (length(target_state_commitment) = 64),
                known_target_checkpoint BLOB CHECK (known_target_checkpoint IS NULL OR length(known_target_checkpoint) = 64),
                envelope_commitment BLOB NOT NULL UNIQUE CHECK (length(envelope_commitment) = 64),
                batch_nonce BLOB NOT NULL UNIQUE CHECK (length(batch_nonce) = 32),
                public_fields_commitment BLOB NOT NULL UNIQUE CHECK (length(public_fields_commitment) = 64),
                submitter BLOB NOT NULL CHECK (length(submitter) = 64),
                native_evidence_commitment BLOB NOT NULL CHECK (length(native_evidence_commitment) = 64),
                statement_commitment BLOB NOT NULL CHECK (length(statement_commitment) = 64),
                proof_package_commitment BLOB NOT NULL CHECK (length(proof_package_commitment) = 64),
                transcript_commitment BLOB NOT NULL CHECK (length(transcript_commitment) = 64),
                sequence_before INTEGER NOT NULL CHECK (sequence_before >= 0),
                sequence_after INTEGER NOT NULL CHECK (sequence_after = sequence_before + 1),
                epoch_before INTEGER NOT NULL CHECK (epoch_before > 0),
                epoch_after INTEGER NOT NULL CHECK (epoch_after = epoch_before + 1),
                settlement_domain_before BLOB NOT NULL CHECK (length(settlement_domain_before) = 64),
                settlement_domain_after BLOB NOT NULL CHECK (length(settlement_domain_after) = 64),
                profile_before BLOB NOT NULL CHECK (length(profile_before) = 64),
                profile_after BLOB NOT NULL CHECK (length(profile_after) = 64),
                suite_before BLOB NOT NULL CHECK (length(suite_before) = 64),
                suite_after BLOB NOT NULL CHECK (length(suite_after) = 64),
                schema_before BLOB NOT NULL CHECK (length(schema_before) = 64),
                schema_after BLOB NOT NULL CHECK (length(schema_after) = 64),
                verifier_before BLOB NOT NULL CHECK (length(verifier_before) = 64),
                verifier_after BLOB NOT NULL CHECK (length(verifier_after) = 64),
                governance_commitment BLOB NOT NULL CHECK (length(governance_commitment) = 64),
                nullifier_root_before BLOB NOT NULL CHECK (length(nullifier_root_before) = 64),
                nullifier_root_after BLOB NOT NULL CHECK (length(nullifier_root_after) = 64),
                payment_root_before BLOB NOT NULL CHECK (length(payment_root_before) = 64),
                payment_root_after BLOB NOT NULL CHECK (length(payment_root_after) = 64),
                state_binding_before BLOB NOT NULL CHECK (length(state_binding_before) = 64),
                state_binding_after BLOB NOT NULL CHECK (length(state_binding_after) = 64),
                audit_head_after BLOB NOT NULL CHECK (length(audit_head_after) = 64)
            );
            CREATE TRIGGER IF NOT EXISTS migration_requests_no_update
            BEFORE UPDATE ON migration_requests
            BEGIN SELECT RAISE(ABORT, 'migration_requests_append_only'); END;
            CREATE TRIGGER IF NOT EXISTS migration_requests_no_delete
            BEFORE DELETE ON migration_requests
            BEGIN SELECT RAISE(ABORT, 'migration_requests_append_only'); END;
            CREATE TRIGGER IF NOT EXISTS configuration_history_no_update
            BEFORE UPDATE ON configuration_history
            BEGIN SELECT RAISE(ABORT, 'configuration_history_append_only'); END;
            CREATE TRIGGER IF NOT EXISTS configuration_history_no_delete
            BEFORE DELETE ON configuration_history
            BEGIN SELECT RAISE(ABORT, 'configuration_history_append_only'); END;
            CREATE TRIGGER IF NOT EXISTS transition_records_no_update
            BEFORE UPDATE ON transition_records
            BEGIN SELECT RAISE(ABORT, 'transition_records_append_only'); END;
            CREATE TRIGGER IF NOT EXISTS transition_records_no_delete
            BEFORE DELETE ON transition_records
            BEGIN SELECT RAISE(ABORT, 'transition_records_append_only'); END;
            CREATE TRIGGER IF NOT EXISTS governance_authorities_no_update
            BEFORE UPDATE ON governance_authorities
            BEGIN SELECT RAISE(ABORT, 'governance_authorities_append_only'); END;
            CREATE TRIGGER IF NOT EXISTS governance_authorities_no_delete
            BEFORE DELETE ON governance_authorities
            BEGIN SELECT RAISE(ABORT, 'governance_authorities_append_only'); END;
            """
        )

    @staticmethod
    def _validate_schema_version(connection: sqlite3.Connection) -> None:
        row = connection.execute("SELECT schema_version FROM metadata WHERE id=1").fetchone()
        if row != (_SCHEMA_VERSION,):
            raise ProductionBoundaryError("database_schema_version_mismatch")

    def _validate_config_row(self, row: tuple[object, ...]) -> None:
        expected = (
            _digest(_DOMAIN_COMMITMENT_DOMAIN, self._settlement_domain),
            self._governance_authority.commitment_512,
            self._profile_id,
            self._suite_id,
            self._schema_id,
            self._verifier_artifact_identity,
            self._epoch,
        )
        observed = tuple(bytes(value) if isinstance(value, (bytes, bytearray)) else value for value in row)
        if observed != expected:
            raise ProductionBoundaryError("database_configuration_identity_mismatch")

    @staticmethod
    def _validate_state_row(row: tuple[object, ...]) -> None:
        if len(row) != 9:
            raise ProductionBoundaryError("database_state_shape_invalid")
        epoch, sequence, nullifier, payment, binding, audit, governance, anti_epoch, count = row
        if type(epoch) is not int or epoch <= 0:
            raise ProductionBoundaryError("database_state_epoch_invalid")
        if type(sequence) is not int or sequence < 0:
            raise ProductionBoundaryError("database_state_sequence_invalid")
        if type(anti_epoch) is not int or anti_epoch < 0 or anti_epoch != sequence:
            raise ProductionBoundaryError("database_state_anti_rollback_epoch_invalid")
        if type(count) is not int or count < 0 or count > sequence:
            raise ProductionBoundaryError("database_state_count_mismatch")
        for label, value in (
            ("database_state_nullifier_root", nullifier),
            ("database_state_payment_root", payment),
            ("database_state_binding", binding),
            ("database_state_audit_head", audit),
            ("database_state_governance", governance),
        ):
            _wide(label, bytes(value) if isinstance(value, (bytes, bytearray)) else value)

    @staticmethod
    def _state_snapshot(row: tuple[object, ...]) -> DatabaseSettlementSnapshotV2:
        SQLiteSettlementStoreV2._validate_state_row(row)
        epoch, sequence, nullifier, payment, binding, audit, governance, anti_epoch, count = row
        return DatabaseSettlementSnapshotV2(
            epoch=epoch,  # type: ignore[arg-type]
            sequence=sequence,  # type: ignore[arg-type]
            strong_nullifier_root=bytes(nullifier),
            strong_payment_state_root=bytes(payment),
            state_binding=bytes(binding),
            audit_head=bytes(audit),
            governance_commitment=bytes(governance),
            anti_rollback_epoch=anti_epoch,  # type: ignore[arg-type]
            settled_batch_count=count,  # type: ignore[arg-type]
        )

    def _validate_operation(self, operation: VerifiedSettlementOperationV2) -> CandidateSidecarV1:
        if (
            self._native_authority_key is None
            or type(operation) is not VerifiedSettlementOperationV2
            or not operation.is_native_authorized(self._native_authority_key)
        ):
            raise ProductionBoundaryError("database_operation_not_native_authorized")
        if operation.public_fields_commitment != public_fields_commitment(operation.public_fields):
            raise ProductionBoundaryError("database_public_fields_commitment_mismatch")
        parsed = _sidecar(operation.sidecar)
        validate_v2_public_projection(
            public_fields=operation.public_fields,
            sidecar=operation.sidecar,
            settlement_domain=operation.public_fields[1],
            batch_nonce=operation.batch_nonce,
            governance_authority=operation.governance_authority,
            suite_id=operation.suite_id,
            schema_id=operation.schema_id,
            verifier_artifact_identity=operation.verifier_artifact_identity,
        )
        return parsed

    def _validate_direct_operation(
        self,
        operation: DirectStateOwnedOperationV1,
    ) -> bytes:
        if (
            self._direct_authority_key is None
            or type(operation) is not DirectStateOwnedOperationV1
            or operation.seal is None
        ):
            raise ProductionBoundaryError("database_direct_operation_not_authorized")
        if (
            operation.profile_id != self._profile_id
            or operation.schema_id != self._schema_id
            or operation.program_id != self._verifier_artifact_identity
            or operation.mode_id != self._direct_mode_id
            or operation.evaluator_id != self._direct_evaluator_id
            or operation.control_set_id != self._direct_control_set_id
            or operation.rule_id != self._direct_rule_id
            or operation.phase0_receipt_binding != self._direct_phase0_receipt_binding
            or operation.continuity_epoch != self._epoch
        ):
            raise ProductionBoundaryError("database_direct_operation_configuration_stale")
        expected_seal = _direct_operation_seal(
            self._direct_authority_key,
            replace(operation, seal=None),
        )
        if not hmac.compare_digest(operation.seal, expected_seal):
            raise ProductionBoundaryError("database_direct_operation_not_authorized")
        return _direct_operation_digest(operation)

    def snapshot(self) -> DatabaseSettlementSnapshotV2:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT epoch, sequence, strong_nullifier_root, strong_payment_state_root, "
                "state_binding, audit_head, governance_commitment, anti_rollback_epoch, "
                "settled_batch_count FROM state WHERE id=1"
            ).fetchone()
            if row is not None:
                transition_commitment = self._latest_operation_digest(
                    connection,
                    row[7],  # type: ignore[arg-type]
                )
        if row is None:
            raise ProductionBoundaryError("database_state_missing")
        snapshot = self._state_snapshot(row)
        self._reconcile_anti_rollback_state(
            epoch=snapshot.anti_rollback_epoch,
            state_binding=snapshot.state_binding,
            transition_commitment=transition_commitment,
        )
        return snapshot

    def identity_snapshot(self) -> PrivacyV2DatabaseIdentity:
        """Read one transactionally consistent configuration/state checkpoint."""

        with closing(self._connect()) as connection:
            connection.execute("BEGIN")
            config = connection.execute(
                "SELECT settlement_domain_commitment, governance_commitment, profile_id, "
                "suite_id, schema_id, verifier_artifact_identity, epoch "
                "FROM configuration WHERE id=1"
            ).fetchone()
            state = connection.execute(
                "SELECT epoch, sequence, strong_nullifier_root, strong_payment_state_root, "
                "state_binding, audit_head, governance_commitment, anti_rollback_epoch, "
                "settled_batch_count FROM state WHERE id=1"
            ).fetchone()
            authority = None
            if config is not None:
                authority = self._governance_authority_by_commitment(
                    connection,
                    bytes(config[1]),
                )
            connection.execute("COMMIT")
        if config is None or state is None or authority is None:
            raise ProductionBoundaryError("database_identity_missing")
        self._validate_config_row(config)
        snapshot = self._state_snapshot(state)
        normalized = tuple(
            value if type(value) is int else bytes(value) for value in config
        )
        if (
            normalized[1] != snapshot.governance_commitment
            or normalized[6] != snapshot.epoch
        ):
            raise ProductionBoundaryError("database_identity_split_brain")
        return PrivacyV2DatabaseIdentity(
            settlement_domain_commitment=normalized[0],  # type: ignore[arg-type]
            governance_commitment=normalized[1],  # type: ignore[arg-type]
            governance_authority=authority,
            profile_id=normalized[2],  # type: ignore[arg-type]
            suite_id=normalized[3],  # type: ignore[arg-type]
            schema_id=normalized[4],  # type: ignore[arg-type]
            verifier_artifact_identity=normalized[5],  # type: ignore[arg-type]
            epoch=normalized[6],  # type: ignore[arg-type]
            sequence=snapshot.sequence,
            strong_nullifier_root=snapshot.strong_nullifier_root,
            strong_payment_state_root=snapshot.strong_payment_state_root,
            state_binding=snapshot.state_binding,
            audit_head=snapshot.audit_head,
            anti_rollback_epoch=snapshot.anti_rollback_epoch,
            settled_batch_count=snapshot.settled_batch_count,
        )

    def _governance_authority_for_commitment(
        self,
        commitment: bytes,
    ) -> GovernanceAuthorityV2:
        with closing(self._connect()) as connection:
            self._validate_schema_version(connection)
            return self._governance_authority_by_commitment(
                connection,
                commitment,
            )

    def _migration_source_identity(
        self,
        source_checkpoint_commitment: bytes,
        migration_evidence_commitment: bytes,
    ) -> PrivacyV2DatabaseIdentity:
        """Resolve only the historical source of one already-recorded retry.

        A historical checkpoint is never returned merely because it is known.
        The evidence commitment must identify the existing migration that
        consumed it, which prevents this restart-recovery seam from becoming a
        general stale-state preparation API.
        """

        source_checkpoint = _wide(
            "database_migration_retry_source_checkpoint",
            source_checkpoint_commitment,
        )
        evidence_commitment = _wide(
            "database_migration_retry_evidence_commitment",
            migration_evidence_commitment,
        )
        with closing(self._connect()) as connection:
            connection.execute("BEGIN")
            rows = connection.execute(
                "SELECT m.settlement_domain_before, t.governance_before, "
                "m.profile_before, m.suite_before, m.schema_before, m.verifier_before, "
                "m.epoch_before, m.sequence_before, m.nullifier_root_before, "
                "m.payment_root_before, m.state_binding_before "
                "FROM migration_requests AS m JOIN transition_records AS t "
                "ON t.record_commitment=m.migration_commitment "
                "WHERE m.source_checkpoint_commitment=? "
                "AND m.migration_evidence_commitment=?",
                (
                    sqlite3.Binary(source_checkpoint),
                    sqlite3.Binary(evidence_commitment),
                ),
            ).fetchall()
            if len(rows) != 1:
                connection.execute("COMMIT")
                raise ProductionBoundaryError(
                    "database_migration_retry_source_not_recorded"
                )
            row = rows[0]
            sequence = row[7]
            if type(sequence) is not int or sequence < 0:
                connection.execute("COMMIT")
                raise ProductionBoundaryError(
                    "database_migration_retry_source_invalid"
                )
            if sequence == 0:
                audit_row = connection.execute(
                    "SELECT audit_head FROM database_genesis WHERE id=1"
                ).fetchone()
            else:
                audit_row = connection.execute(
                    "SELECT current_head FROM audit_events WHERE sequence=?",
                    (sequence,),
                ).fetchone()
            settled_count = connection.execute(
                "SELECT COUNT(*) FROM settlement_requests WHERE sequence_after<=?",
                (sequence,),
            ).fetchone()[0]
            authority = self._governance_authority_by_commitment(
                connection,
                bytes(row[1]),
            )
            connection.execute("COMMIT")
        if audit_row is None or type(settled_count) is not int:
            raise ProductionBoundaryError("database_migration_retry_source_invalid")
        identity = PrivacyV2DatabaseIdentity(
            settlement_domain_commitment=bytes(row[0]),
            governance_commitment=bytes(row[1]),
            governance_authority=authority,
            profile_id=bytes(row[2]),
            suite_id=bytes(row[3]),
            schema_id=bytes(row[4]),
            verifier_artifact_identity=bytes(row[5]),
            epoch=row[6],  # type: ignore[arg-type]
            sequence=sequence,
            strong_nullifier_root=bytes(row[8]),
            strong_payment_state_root=bytes(row[9]),
            state_binding=bytes(row[10]),
            audit_head=bytes(audit_row[0]),
            anti_rollback_epoch=sequence,
            settled_batch_count=settled_count,
        )
        if identity.checkpoint_commitment != source_checkpoint:
            raise ProductionBoundaryError(
                "database_migration_retry_source_checkpoint_mismatch"
            )
        return identity

    def _commit_verified(self, operation: VerifiedSettlementOperationV2) -> SettlementReceiptV2:
        parsed = self._validate_operation(operation)
        operation_digest = _operation_digest(operation)
        with closing(self._connect()) as connection:
            began = False
            try:
                connection.execute("BEGIN IMMEDIATE")
                began = True
                self._validate_schema_version(connection)
                config = connection.execute(
                    "SELECT settlement_domain_commitment, governance_commitment, profile_id, "
                    "suite_id, schema_id, verifier_artifact_identity, epoch "
                    "FROM configuration WHERE id=1"
                ).fetchone()
                if config is None:
                    raise ProductionBoundaryError("database_configuration_missing")
                self._validate_config_row(config)
                normalized_config = tuple(
                    value if type(value) is int else bytes(value) for value in config
                )
                recorded_operation_authority = self._governance_authority_by_commitment(
                    connection,
                    operation.strong_governance_commitment,
                )
                if recorded_operation_authority != operation.governance_authority:
                    raise ProductionBoundaryError(
                        "database_operation_governance_authority_mismatch"
                    )
                row = connection.execute(
                    "SELECT epoch, sequence, strong_nullifier_root, strong_payment_state_root, "
                    "state_binding, audit_head, governance_commitment, anti_rollback_epoch, "
                    "settled_batch_count FROM state WHERE id=1"
                ).fetchone()
                if row is None:
                    raise ProductionBoundaryError("database_state_missing")
                self._validate_state_row(row)
                if row[0] != self._epoch or bytes(row[6]) != self._governance_authority.commitment_512:
                    raise ProductionBoundaryError("database_state_identity_mismatch")
                pending_anchor = self._reconcile_anti_rollback_state(
                    epoch=row[7],  # type: ignore[arg-type]
                    state_binding=bytes(row[4]),
                    transition_commitment=self._latest_operation_digest(
                        connection,
                        row[7],  # type: ignore[arg-type]
                    ),
                )

                existing = connection.execute(
                    "SELECT envelope_commitment, batch_nonce, public_fields_commitment, submitter, "
                    "operation_digest, sequence_before, sequence_after, statement_commitment, "
                    "evidence_commitment, proof_package_commitment, transcript_commitment, "
                    "strong_nullifier_root_before, strong_nullifier_root_after, "
                    "strong_payment_state_root_before, strong_payment_state_root_after, "
                    "state_binding_after FROM settlement_requests "
                    "WHERE envelope_commitment=? OR batch_nonce=? OR public_fields_commitment=?",
                    (
                        sqlite3.Binary(operation.envelope_commitment),
                        sqlite3.Binary(operation.batch_nonce),
                        sqlite3.Binary(operation.public_fields_commitment),
                    ),
                ).fetchall()
                if existing:
                    if len(existing) != 1:
                        raise ProductionBoundaryError("database_conflicting_retry")
                    observed = existing[0]
                    normalized = tuple(
                        value if index in (5, 6) else bytes(value)
                        for index, value in enumerate(observed)
                    )
                    if normalized[:-1] != (
                        operation.envelope_commitment,
                        operation.batch_nonce,
                        operation.public_fields_commitment,
                        operation.submitter,
                        operation_digest,
                        operation.sequence_before,
                        operation.sequence_after,
                        operation.statement_commitment,
                        operation.evidence_commitment,
                        operation.proof_package_commitment,
                        operation.transcript_commitment,
                        operation.strong_nullifier_root_before,
                        operation.strong_nullifier_root_after,
                        operation.strong_payment_state_root_before,
                        operation.strong_payment_state_root_after,
                    ):
                        raise ProductionBoundaryError("database_conflicting_retry")
                    receipt = SettlementReceiptV2(
                        sequence_before=normalized[5],  # type: ignore[arg-type]
                        sequence_after=normalized[6],  # type: ignore[arg-type]
                        nullifier_root_before=_field_alias(normalized[11]),  # type: ignore[arg-type]
                        nullifier_root_after=_field_alias(normalized[12]),  # type: ignore[arg-type]
                        public_fields_commitment=normalized[2],  # type: ignore[arg-type]
                        envelope_commitment=normalized[0],  # type: ignore[arg-type]
                        native_statement_commitment=normalized[7],  # type: ignore[arg-type]
                        proof_suite_id=operation.suite_id,
                        state_binding=normalized[15],  # type: ignore[arg-type]
                    )
                    connection.execute("COMMIT")
                    return receipt

                operation_config = (
                    _digest(_DOMAIN_COMMITMENT_DOMAIN, operation.public_fields[1]),
                    operation.strong_governance_commitment,
                    operation.profile_id,
                    operation.suite_id,
                    operation.schema_id,
                    operation.verifier_artifact_identity,
                    operation.epoch,
                )
                if normalized_config != operation_config:
                    raise ProductionBoundaryError(
                        "database_operation_configuration_stale"
                    )
                if operation.governance_authority != self._governance_authority:
                    raise ProductionBoundaryError(
                        "database_operation_governance_authority_stale"
                    )

                if parsed.sequence_before != row[1]:
                    raise ProductionBoundaryError("database_sequence_stale")
                if parsed.strong_nullifier_root_before != bytes(row[2]):
                    raise ProductionBoundaryError("database_nullifier_root_stale")
                if parsed.strong_payment_state_root_before != bytes(row[3]):
                    raise ProductionBoundaryError("database_payment_state_root_stale")
                duplicate_nullifier = connection.execute(
                    "SELECT envelope_commitment FROM settled_nullifier_roots "
                    "WHERE strong_nullifier_root_after=?",
                    (sqlite3.Binary(parsed.strong_nullifier_root_after),),
                ).fetchone()
                if duplicate_nullifier is not None:
                    raise ProductionBoundaryError("database_nullifier_replay")

                previous_binding = bytes(row[4])
                next_binding = _digest(
                    _DATABASE_STATE_BINDING,
                    previous_binding,
                    operation.batch_nonce,
                    parsed.strong_nullifier_root_after,
                    parsed.strong_payment_state_root_after,
                    operation.envelope_commitment,
                    operation.evidence_commitment,
                    operation.submitter,
                    operation.strong_governance_commitment,
                    _u64(operation.epoch, "operation_epoch"),
                )
                receipt = SettlementReceiptV2(
                    sequence_before=row[1],  # type: ignore[arg-type]
                    sequence_after=parsed.sequence_after,
                    nullifier_root_before=_field_alias(parsed.strong_nullifier_root_before),
                    nullifier_root_after=_field_alias(parsed.strong_nullifier_root_after),
                    public_fields_commitment=operation.public_fields_commitment,
                    envelope_commitment=operation.envelope_commitment,
                    native_statement_commitment=operation.statement_commitment,
                    proof_suite_id=operation.suite_id,
                    state_binding=next_binding,
                )
                event_payload = _audit_payload(
                    operation=operation,
                    receipt=receipt,
                    previous_head=bytes(row[5]),
                )
                event_commitment = _digest(
                    _AUDIT_EVENT_DOMAIN,
                    bytes(row[5]),
                    event_payload,
                )
                next_audit_head = _digest(
                    _AUDIT_HEAD_DOMAIN,
                    bytes(row[5]),
                    event_commitment,
                )
                next_anti_epoch = row[7] + 1
                if self._anti_rollback is not None:
                    expected_pending = PendingAntiRollbackTransition(
                        next_anti_epoch,
                        next_binding,
                        operation_digest,
                    )
                    if pending_anchor is not None:
                        if pending_anchor != expected_pending:
                            raise ProductionBoundaryError(
                                "anti_rollback_transition_conflict"
                            )
                    else:
                        self._anti_rollback.prepare(
                            expected_epoch=row[7],  # type: ignore[arg-type]
                            expected_state_binding=bytes(row[4]),
                            next_epoch=next_anti_epoch,
                            next_state_binding=next_binding,
                            transition_commitment=operation_digest,
                        )
                connection.execute(
                    "INSERT INTO settlement_requests VALUES "
                    "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        sqlite3.Binary(operation.envelope_commitment),
                        sqlite3.Binary(operation.batch_nonce),
                        sqlite3.Binary(operation.public_fields_commitment),
                        sqlite3.Binary(operation.submitter),
                        sqlite3.Binary(operation_digest),
                        row[1],
                        parsed.sequence_after,
                        sqlite3.Binary(operation.statement_commitment),
                        sqlite3.Binary(operation.evidence_commitment),
                        sqlite3.Binary(operation.proof_package_commitment),
                        sqlite3.Binary(operation.transcript_commitment),
                        sqlite3.Binary(parsed.strong_nullifier_root_before),
                        sqlite3.Binary(parsed.strong_nullifier_root_after),
                        sqlite3.Binary(parsed.strong_payment_state_root_before),
                        sqlite3.Binary(parsed.strong_payment_state_root_after),
                        sqlite3.Binary(next_binding),
                    ),
                )
                connection.execute(
                    "INSERT INTO settled_nullifier_roots VALUES (?, ?)",
                    (
                        sqlite3.Binary(parsed.strong_nullifier_root_after),
                        sqlite3.Binary(operation.envelope_commitment),
                    ),
                )
                connection.execute(
                    "INSERT INTO audit_events VALUES (?, ?, ?, ?, ?)",
                    (
                        parsed.sequence_after,
                        sqlite3.Binary(bytes(row[5])),
                        sqlite3.Binary(event_commitment),
                        sqlite3.Binary(next_audit_head),
                        sqlite3.Binary(event_payload),
                    ),
                )
                checkpoint = PrivacyV2DatabaseIdentity(
                    settlement_domain_commitment=_digest(
                        _DOMAIN_COMMITMENT_DOMAIN, self._settlement_domain
                    ),
                    governance_commitment=self._governance_authority.commitment_512,
                    governance_authority=self._governance_authority,
                    profile_id=self._profile_id,
                    suite_id=self._suite_id,
                    schema_id=self._schema_id,
                    verifier_artifact_identity=self._verifier_artifact_identity,
                    epoch=self._epoch,
                    sequence=parsed.sequence_after,
                    strong_nullifier_root=parsed.strong_nullifier_root_after,
                    strong_payment_state_root=parsed.strong_payment_state_root_after,
                    state_binding=next_binding,
                    audit_head=next_audit_head,
                    anti_rollback_epoch=next_anti_epoch,
                    settled_batch_count=row[8] + 1,  # type: ignore[operator]
                )
                connection.execute(
                    "INSERT INTO transition_records VALUES "
                    "(?, 'SETTLEMENT', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        parsed.sequence_after,
                        sqlite3.Binary(operation_digest),
                        sqlite3.Binary(previous_binding),
                        sqlite3.Binary(next_binding),
                        sqlite3.Binary(parsed.strong_nullifier_root_before),
                        sqlite3.Binary(parsed.strong_nullifier_root_after),
                        sqlite3.Binary(parsed.strong_payment_state_root_before),
                        sqlite3.Binary(parsed.strong_payment_state_root_after),
                        sqlite3.Binary(self._governance_authority.commitment_512),
                        sqlite3.Binary(self._governance_authority.commitment_512),
                        sqlite3.Binary(self._profile_id),
                        sqlite3.Binary(self._profile_id),
                        sqlite3.Binary(self._suite_id),
                        sqlite3.Binary(self._suite_id),
                        sqlite3.Binary(self._schema_id),
                        sqlite3.Binary(self._schema_id),
                        sqlite3.Binary(self._verifier_artifact_identity),
                        sqlite3.Binary(self._verifier_artifact_identity),
                        self._epoch,
                        self._epoch,
                        sqlite3.Binary(checkpoint.checkpoint_commitment),
                    ),
                )
                connection.execute(
                    "UPDATE state SET sequence=?, strong_nullifier_root=?, "
                    "strong_payment_state_root=?, state_binding=?, audit_head=?, "
                    "anti_rollback_epoch=?, settled_batch_count=? WHERE id=1",
                    (
                        parsed.sequence_after,
                        sqlite3.Binary(parsed.strong_nullifier_root_after),
                        sqlite3.Binary(parsed.strong_payment_state_root_after),
                        sqlite3.Binary(next_binding),
                        sqlite3.Binary(next_audit_head),
                        next_anti_epoch,
                        row[8] + 1,
                    ),
                )
                if self._before_commit_hook is not None:
                    self._before_commit_hook()
                connection.execute("COMMIT")
                began = False
            except sqlite3.IntegrityError as exc:
                if began and connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise ProductionBoundaryError("database_transition_conflict") from exc
            except sqlite3.OperationalError as exc:
                if began and connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise ProductionBoundaryError("database_transition_unavailable") from exc
            except Exception:
                if began and connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        if self._anti_rollback is not None:
            try:
                self._anti_rollback.finalize(
                    next_epoch=next_anti_epoch,
                    next_state_binding=next_binding,
                    transition_commitment=operation_digest,
                )
            except Exception as exc:
                raise ProductionBoundaryError(
                    "database_transition_committed_anchor_pending"
                ) from exc
        return receipt

    def _commit_direct_state_owned(
        self,
        operation: DirectStateOwnedOperationV1,
    ) -> DirectStateOwnedDatabaseReceiptV1:
        """Commit one independently verified direct-state clearance attempt."""

        operation_digest = self._validate_direct_operation(operation)
        operation_values = _direct_operation_record_values(operation)
        next_binding: bytes | None = None
        next_anti_epoch: int | None = None
        with closing(self._connect()) as connection:
            began = False
            try:
                connection.execute("BEGIN IMMEDIATE")
                began = True
                self._validate_schema_version(connection)
                config = connection.execute(
                    "SELECT settlement_domain_commitment, governance_commitment, profile_id, "
                    "suite_id, schema_id, verifier_artifact_identity, epoch "
                    "FROM configuration WHERE id=1"
                ).fetchone()
                if config is None:
                    raise ProductionBoundaryError("database_configuration_missing")
                self._validate_config_row(config)
                if self._governance_authority_by_commitment(
                    connection,
                    bytes(config[1]),
                ) != self._governance_authority:
                    raise ProductionBoundaryError(
                        "database_direct_governance_authority_mismatch"
                    )
                row = connection.execute(
                    "SELECT epoch, sequence, strong_nullifier_root, strong_payment_state_root, "
                    "state_binding, audit_head, governance_commitment, anti_rollback_epoch, "
                    "settled_batch_count FROM state WHERE id=1"
                ).fetchone()
                if row is None:
                    raise ProductionBoundaryError("database_state_missing")
                self._validate_state_row(row)
                if (
                    row[0] != self._epoch
                    or bytes(row[6]) != self._governance_authority.commitment_512
                ):
                    raise ProductionBoundaryError(
                        "database_direct_state_identity_mismatch"
                    )
                pending_anchor = self._reconcile_anti_rollback_state(
                    epoch=row[7],  # type: ignore[arg-type]
                    state_binding=bytes(row[4]),
                    transition_commitment=self._latest_operation_digest(
                        connection,
                        row[7],  # type: ignore[arg-type]
                    ),
                )

                existing = connection.execute(
                    "SELECT operation_digest, bundle_id, receipt_id, request_id, attempt_id, "
                    "decision_id, join_id, source_root, profile_id, schema_id, program_id, "
                    "mode_id, evaluator_id, control_set_id, rule_id, phase0_receipt_binding, "
                    "exception_id, policy_result, effective_directive, event_time, "
                    "observation_time, rule_effective_time, decision_time, continuity_epoch, "
                    "continuity_sequence_before, continuity_sequence_after, "
                    "continuity_before_state_id, continuity_after_state_id, "
                    "continuity_before_audit_head, continuity_after_audit_head, "
                    "continuity_before_root, continuity_after_root "
                    "FROM direct_clearance_requests "
                    "WHERE operation_digest=? OR bundle_id=? OR receipt_id=? OR request_id=? "
                    "OR attempt_id=? OR decision_id=? OR join_id=?",
                    (
                        sqlite3.Binary(operation_digest),
                        sqlite3.Binary(operation.bundle_id),
                        sqlite3.Binary(operation.receipt_id),
                        sqlite3.Binary(operation.request_id),
                        sqlite3.Binary(operation.attempt_id),
                        sqlite3.Binary(operation.decision_id),
                        sqlite3.Binary(operation.join_id),
                    ),
                ).fetchall()
                if existing:
                    if len(existing) != 1:
                        raise ProductionBoundaryError(
                            "database_direct_conflicting_retry"
                        )
                    observed = tuple(
                        value if type(value) is int else bytes(value)
                        for value in existing[0]
                    )
                    if observed[0] != operation_digest or observed[1:] != operation_values:
                        raise ProductionBoundaryError(
                            "database_direct_conflicting_retry"
                        )
                    receipt_row = connection.execute(
                        "SELECT operation_digest, bundle_id, receipt_id, decision_id, join_id, "
                        "sequence_before, sequence_after, nullifier_root_before, "
                        "nullifier_root_after, payment_root_before, payment_root_after, "
                        "state_binding_after, audit_head_after, effective_directive, "
                        "clearance_advanced FROM direct_clearance_requests "
                        "WHERE operation_digest=?",
                        (sqlite3.Binary(operation_digest),),
                    ).fetchone()
                    if receipt_row is None:
                        raise ProductionBoundaryError(
                            "database_direct_receipt_missing"
                        )
                    receipt = _direct_receipt_from_row(receipt_row)
                    connection.execute("COMMIT")
                    began = False
                    return receipt

                if row[1] != 0:
                    raise ProductionBoundaryError("database_direct_sequence_stale")
                nullifier_before = bytes(row[2])
                payment_before = bytes(row[3])
                nullifier_after = _digest(
                    _DIRECT_REPLAY_ROOT_DOMAIN,
                    nullifier_before,
                    operation.attempt_id,
                    operation.bundle_id,
                    operation.receipt_id,
                )
                duplicate = connection.execute(
                    "SELECT operation_digest FROM direct_clearance_requests "
                    "WHERE nullifier_root_after=?",
                    (sqlite3.Binary(nullifier_after),),
                ).fetchone()
                if duplicate is not None:
                    raise ProductionBoundaryError("database_direct_replay")
                clearance_advanced = operation.effective_directive in (1, 5)
                payment_after = (
                    _digest(
                        _DIRECT_CLEARANCE_ROOT_DOMAIN,
                        payment_before,
                        operation.continuity_after_state_id,
                        operation.decision_id,
                        bytes((operation.effective_directive,)),
                    )
                    if clearance_advanced
                    else payment_before
                )
                previous_binding = bytes(row[4])
                next_binding = _digest(
                    _DATABASE_STATE_BINDING,
                    previous_binding,
                    operation.attempt_id,
                    nullifier_after,
                    payment_after,
                    operation.bundle_id,
                    operation_digest,
                    self._governance_authority.commitment_512,
                    _u64(self._epoch, "database_epoch"),
                )
                event_payload = _direct_audit_payload(
                    operation=operation,
                    operation_digest=operation_digest,
                    sequence_before=row[1],  # type: ignore[arg-type]
                    sequence_after=row[1] + 1,  # type: ignore[operator]
                    nullifier_before=nullifier_before,
                    nullifier_after=nullifier_after,
                    payment_before=payment_before,
                    payment_after=payment_after,
                    state_binding=next_binding,
                    previous_head=bytes(row[5]),
                )
                event_commitment = _digest(
                    _AUDIT_EVENT_DOMAIN,
                    bytes(row[5]),
                    event_payload,
                )
                next_audit_head = _digest(
                    _AUDIT_HEAD_DOMAIN,
                    bytes(row[5]),
                    event_commitment,
                )
                next_anti_epoch = row[7] + 1  # type: ignore[operator]
                if self._anti_rollback is not None:
                    expected_pending = PendingAntiRollbackTransition(
                        next_anti_epoch,
                        next_binding,
                        operation_digest,
                    )
                    if pending_anchor is not None:
                        if pending_anchor != expected_pending:
                            raise ProductionBoundaryError(
                                "anti_rollback_transition_conflict"
                            )
                    else:
                        self._anti_rollback.prepare(
                            expected_epoch=row[7],  # type: ignore[arg-type]
                            expected_state_binding=bytes(row[4]),
                            next_epoch=next_anti_epoch,
                            next_state_binding=next_binding,
                            transition_commitment=operation_digest,
                        )
                direct_values = (
                    operation_digest,
                    *operation_values,
                    row[1],
                    row[1] + 1,
                    nullifier_before,
                    nullifier_after,
                    payment_before,
                    payment_after,
                    next_binding,
                    next_audit_head,
                    int(clearance_advanced),
                )
                connection.execute(
                    "INSERT INTO direct_clearance_requests VALUES ("
                    + ", ".join("?" for _ in range(41))
                    + ")",
                    tuple(
                        value if type(value) is int else sqlite3.Binary(value)
                        for value in direct_values
                    ),
                )
                connection.execute(
                    "INSERT INTO audit_events VALUES (?, ?, ?, ?, ?)",
                    (
                        row[1] + 1,
                        sqlite3.Binary(bytes(row[5])),
                        sqlite3.Binary(event_commitment),
                        sqlite3.Binary(next_audit_head),
                        sqlite3.Binary(event_payload),
                    ),
                )
                checkpoint = PrivacyV2DatabaseIdentity(
                    settlement_domain_commitment=_digest(
                        _DOMAIN_COMMITMENT_DOMAIN,
                        self._settlement_domain,
                    ),
                    governance_commitment=self._governance_authority.commitment_512,
                    governance_authority=self._governance_authority,
                    profile_id=self._profile_id,
                    suite_id=self._suite_id,
                    schema_id=self._schema_id,
                    verifier_artifact_identity=self._verifier_artifact_identity,
                    epoch=self._epoch,
                    sequence=row[1] + 1,  # type: ignore[operator]
                    strong_nullifier_root=nullifier_after,
                    strong_payment_state_root=payment_after,
                    state_binding=next_binding,
                    audit_head=next_audit_head,
                    anti_rollback_epoch=next_anti_epoch,
                    settled_batch_count=row[8] + 1,  # type: ignore[operator]
                )
                connection.execute(
                    "INSERT INTO transition_records VALUES "
                    "(?, 'SETTLEMENT', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        row[1] + 1,
                        sqlite3.Binary(operation_digest),
                        sqlite3.Binary(previous_binding),
                        sqlite3.Binary(next_binding),
                        sqlite3.Binary(nullifier_before),
                        sqlite3.Binary(nullifier_after),
                        sqlite3.Binary(payment_before),
                        sqlite3.Binary(payment_after),
                        sqlite3.Binary(self._governance_authority.commitment_512),
                        sqlite3.Binary(self._governance_authority.commitment_512),
                        sqlite3.Binary(self._profile_id),
                        sqlite3.Binary(self._profile_id),
                        sqlite3.Binary(self._suite_id),
                        sqlite3.Binary(self._suite_id),
                        sqlite3.Binary(self._schema_id),
                        sqlite3.Binary(self._schema_id),
                        sqlite3.Binary(self._verifier_artifact_identity),
                        sqlite3.Binary(self._verifier_artifact_identity),
                        self._epoch,
                        self._epoch,
                        sqlite3.Binary(checkpoint.checkpoint_commitment),
                    ),
                )
                connection.execute(
                    "UPDATE state SET sequence=?, strong_nullifier_root=?, "
                    "strong_payment_state_root=?, state_binding=?, audit_head=?, "
                    "anti_rollback_epoch=?, settled_batch_count=? WHERE id=1",
                    (
                        row[1] + 1,
                        sqlite3.Binary(nullifier_after),
                        sqlite3.Binary(payment_after),
                        sqlite3.Binary(next_binding),
                        sqlite3.Binary(next_audit_head),
                        next_anti_epoch,
                        row[8] + 1,
                    ),
                )
                if self._before_commit_hook is not None:
                    self._before_commit_hook()
                connection.execute("COMMIT")
                began = False
                receipt = DirectStateOwnedDatabaseReceiptV1(
                    operation_digest=operation_digest,
                    bundle_id=operation.bundle_id,
                    receipt_id=operation.receipt_id,
                    decision_id=operation.decision_id,
                    join_id=operation.join_id,
                    sequence_before=row[1],  # type: ignore[arg-type]
                    sequence_after=row[1] + 1,  # type: ignore[operator]
                    nullifier_root_before=nullifier_before,
                    nullifier_root_after=nullifier_after,
                    clearance_root_before=payment_before,
                    clearance_root_after=payment_after,
                    state_binding=next_binding,
                    audit_head=next_audit_head,
                    effective_directive=operation.effective_directive,
                    clearance_advanced=clearance_advanced,
                )
            except sqlite3.IntegrityError as exc:
                if began and connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise ProductionBoundaryError("database_direct_transition_conflict") from exc
            except sqlite3.OperationalError as exc:
                if began and connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise ProductionBoundaryError("database_direct_transition_unavailable") from exc
            except Exception:
                if began and connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        if self._anti_rollback is not None:
            if next_binding is None or next_anti_epoch is None:
                raise ProductionBoundaryError("database_direct_anchor_state_missing")
            try:
                self._anti_rollback.finalize(
                    next_epoch=next_anti_epoch,
                    next_state_binding=next_binding,
                    transition_commitment=operation_digest,
                )
            except Exception as exc:
                raise ProductionBoundaryError(
                    "database_direct_transition_committed_anchor_pending"
                ) from exc
        return receipt

    @staticmethod
    def _migration_receipt_from_row(row: tuple[object, ...]) -> MigrationReceiptV2:
        if len(row) != 13:
            raise ProductionBoundaryError("database_migration_receipt_shape_invalid")
        return MigrationReceiptV2(
            kind=row[0],  # type: ignore[arg-type]
            migration_commitment=bytes(row[1]),
            evidence_commitment=bytes(row[2]),
            source_checkpoint_commitment=bytes(row[3]),
            target_state_commitment=bytes(row[4]),
            epoch_before=row[5],  # type: ignore[arg-type]
            epoch_after=row[6],  # type: ignore[arg-type]
            sequence_before=row[7],  # type: ignore[arg-type]
            sequence_after=row[8],  # type: ignore[arg-type]
            strong_nullifier_root_after=bytes(row[9]),
            strong_payment_state_root_after=bytes(row[10]),
            state_binding_after=bytes(row[11]),
            audit_head_after=bytes(row[12]),
        )

    def _validate_migration_operation(
        self, operation: VerifiedMigrationOperationV2
    ) -> CandidateSidecarV1:
        if (
            self._migration_authority_key is None
            or type(operation) is not VerifiedMigrationOperationV2
            or not operation.is_native_authorized(self._migration_authority_key)
            or not operation.transition.is_native_authorized(
                self._migration_authority_key
            )
        ):
            raise ProductionBoundaryError("database_migration_not_native_authorized")
        transition = operation.transition
        if (
            transition.public_fields_commitment
            != public_fields_commitment(transition.public_fields)
        ):
            raise ProductionBoundaryError(
                "database_migration_public_fields_commitment_mismatch"
            )
        parsed = _sidecar(transition.sidecar)
        validate_v2_public_projection(
            public_fields=transition.public_fields,
            sidecar=transition.sidecar,
            settlement_domain=transition.public_fields[1],
            batch_nonce=transition.batch_nonce,
            governance_authority=operation.target.governance_authority,
            suite_id=transition.suite_id,
            schema_id=transition.schema_id,
            verifier_artifact_identity=transition.verifier_artifact_identity,
        )
        return parsed

    @staticmethod
    def _known_checkpoint_roots(
        connection: sqlite3.Connection, checkpoint: bytes
    ) -> tuple[bytes, bytes, bytes] | None:
        row = connection.execute(
            "SELECT strong_nullifier_root, strong_payment_state_root, governance_commitment "
            "FROM database_genesis WHERE checkpoint_commitment=?",
            (sqlite3.Binary(checkpoint),),
        ).fetchone()
        if row is None:
            row = connection.execute(
                "SELECT nullifier_root_after, payment_root_after, governance_after "
                "FROM transition_records WHERE checkpoint_commitment_after=?",
                (sqlite3.Binary(checkpoint),),
            ).fetchone()
        if row is None:
            return None
        return (bytes(row[0]), bytes(row[1]), bytes(row[2]))

    def _commit_verified_migration(
        self, operation: VerifiedMigrationOperationV2
    ) -> MigrationReceiptV2:
        parsed = self._validate_migration_operation(operation)
        transition = operation.transition
        evidence = operation.evidence
        source = operation.source_identity
        target = operation.target
        migration_commitment = operation.migration_commitment
        next_binding: bytes | None = None
        next_anti_epoch: int | None = None
        committed_new = False
        receipt: MigrationReceiptV2 | None = None
        with closing(self._connect()) as connection:
            began = False
            try:
                connection.execute("BEGIN IMMEDIATE")
                began = True
                self._validate_schema_version(connection)
                config = connection.execute(
                    "SELECT settlement_domain_commitment, governance_commitment, profile_id, "
                    "suite_id, schema_id, verifier_artifact_identity, epoch "
                    "FROM configuration WHERE id=1"
                ).fetchone()
                state = connection.execute(
                    "SELECT epoch, sequence, strong_nullifier_root, strong_payment_state_root, "
                    "state_binding, audit_head, governance_commitment, anti_rollback_epoch, "
                    "settled_batch_count FROM state WHERE id=1"
                ).fetchone()
                if config is None or state is None:
                    raise ProductionBoundaryError("database_migration_state_missing")
                self._validate_config_row(config)
                self._validate_state_row(state)
                current_authority = self._governance_authority_by_commitment(
                    connection,
                    bytes(config[1]),
                )
                if current_authority != self._governance_authority:
                    raise ProductionBoundaryError(
                        "database_current_governance_authority_mismatch"
                    )
                if (
                    state[0] != self._epoch
                    or bytes(state[6])
                    != self._governance_authority.commitment_512
                ):
                    raise ProductionBoundaryError("database_state_identity_mismatch")
                pending_anchor = self._reconcile_anti_rollback_state(
                    epoch=state[7],  # type: ignore[arg-type]
                    state_binding=bytes(state[4]),
                    transition_commitment=self._latest_operation_digest(
                        connection, state[7]  # type: ignore[arg-type]
                    ),
                )

                existing = connection.execute(
                    "SELECT migration_kind, migration_commitment, "
                    "migration_evidence_commitment, source_checkpoint_commitment, "
                    "target_state_commitment, epoch_before, epoch_after, sequence_before, "
                    "sequence_after, nullifier_root_after, payment_root_after, "
                    "state_binding_after, audit_head_after FROM migration_requests "
                    "WHERE migration_commitment=? OR envelope_commitment=? OR batch_nonce=? "
                    "OR public_fields_commitment=? OR migration_evidence_commitment=?",
                    (
                        sqlite3.Binary(migration_commitment),
                        sqlite3.Binary(transition.envelope_commitment),
                        sqlite3.Binary(transition.batch_nonce),
                        sqlite3.Binary(transition.public_fields_commitment),
                        sqlite3.Binary(evidence.commitment),
                    ),
                ).fetchall()
                if existing:
                    if len(existing) != 1:
                        raise ProductionBoundaryError("database_migration_conflicting_retry")
                    receipt = self._migration_receipt_from_row(existing[0])
                    recorded_target_authority = (
                        self._governance_authority_by_commitment(
                            connection,
                            target.governance_commitment,
                        )
                    )
                    if (
                        recorded_target_authority != target.governance_authority
                        or receipt.kind != evidence.kind
                        or receipt.migration_commitment != migration_commitment
                        or receipt.evidence_commitment != evidence.commitment
                        or receipt.source_checkpoint_commitment
                        != source.checkpoint_commitment
                        or receipt.target_state_commitment
                        != target.target_state_commitment
                        or receipt.epoch_before != source.epoch
                        or receipt.epoch_after != target.epoch
                        or receipt.sequence_before != target.sequence_before
                        or receipt.sequence_after != target.sequence_after
                        or receipt.strong_nullifier_root_after
                        != target.strong_nullifier_root_after
                        or receipt.strong_payment_state_root_after
                        != target.strong_payment_state_root_after
                    ):
                        raise ProductionBoundaryError(
                            "database_migration_conflicting_retry"
                        )
                    connection.execute("COMMIT")
                    began = False
                else:
                    normalized_config = tuple(
                        value if type(value) is int else bytes(value)
                        for value in config
                    )
                    expected_source_config = (
                        source.settlement_domain_commitment,
                        source.governance_commitment,
                        source.profile_id,
                        source.suite_id,
                        source.schema_id,
                        source.verifier_artifact_identity,
                        source.epoch,
                    )
                    if normalized_config != expected_source_config:
                        raise ProductionBoundaryError(
                            "database_migration_source_configuration_stale"
                        )
                    observed_source = PrivacyV2DatabaseIdentity(
                        settlement_domain_commitment=normalized_config[0],  # type: ignore[arg-type]
                        governance_commitment=normalized_config[1],  # type: ignore[arg-type]
                        governance_authority=self._governance_authority_by_commitment(
                            connection,
                            normalized_config[1],  # type: ignore[arg-type]
                        ),
                        profile_id=normalized_config[2],  # type: ignore[arg-type]
                        suite_id=normalized_config[3],  # type: ignore[arg-type]
                        schema_id=normalized_config[4],  # type: ignore[arg-type]
                        verifier_artifact_identity=normalized_config[5],  # type: ignore[arg-type]
                        epoch=normalized_config[6],  # type: ignore[arg-type]
                        sequence=state[1],  # type: ignore[arg-type]
                        strong_nullifier_root=bytes(state[2]),
                        strong_payment_state_root=bytes(state[3]),
                        state_binding=bytes(state[4]),
                        audit_head=bytes(state[5]),
                        anti_rollback_epoch=state[7],  # type: ignore[arg-type]
                        settled_batch_count=state[8],  # type: ignore[arg-type]
                    )
                    if observed_source != source:
                        raise ProductionBoundaryError(
                            "database_migration_source_checkpoint_stale"
                        )
                    if source.governance_authority != self._governance_authority:
                        raise ProductionBoundaryError(
                            "database_migration_source_governance_authority_stale"
                        )
                    if (
                        parsed.epoch != source.epoch + 1
                        or parsed.sequence_before != source.sequence
                        or parsed.sequence_after != source.sequence + 1
                        or parsed.strong_nullifier_root_before
                        != source.strong_nullifier_root
                        or parsed.strong_payment_state_root_before
                        != source.strong_payment_state_root
                        or parsed.strong_governance_commitment
                        != target.governance_commitment
                        or transition.governance_authority
                        != target.governance_authority
                        or target.profile_id != transition.profile_id
                        or target.suite_id != transition.suite_id
                        or target.schema_id != transition.schema_id
                        or target.verifier_artifact_identity
                        != transition.verifier_artifact_identity
                    ):
                        raise ProductionBoundaryError(
                            "database_migration_transition_binding_mismatch"
                        )
                    prior_identity = connection.execute(
                        "SELECT activation_sequence FROM configuration_history "
                        "WHERE epoch=? OR (profile_id=? AND suite_id=? AND schema_id=? "
                        "AND verifier_artifact_identity=?)",
                        (
                            target.epoch,
                            sqlite3.Binary(target.profile_id),
                            sqlite3.Binary(target.suite_id),
                            sqlite3.Binary(target.schema_id),
                            sqlite3.Binary(target.verifier_artifact_identity),
                        ),
                    ).fetchone()
                    if prior_identity is not None:
                        raise ProductionBoundaryError(
                            "database_migration_downgrade_or_reuse"
                        )
                    prior_authority = connection.execute(
                        "SELECT activation_sequence FROM governance_authorities "
                        "WHERE governance_commitment=? OR (profile_code=? AND epoch=?)",
                        (
                            sqlite3.Binary(target.governance_commitment),
                            target.governance_authority.profile_code,
                            target.governance_authority.epoch,
                        ),
                    ).fetchone()
                    if prior_authority is not None:
                        raise ProductionBoundaryError(
                            "database_migration_governance_authority_reuse"
                        )
                    if evidence.kind in {"ROLLBACK", "RECOVERY"}:
                        reused_domain = connection.execute(
                            "SELECT activation_sequence FROM configuration_history "
                            "WHERE settlement_domain_commitment=?",
                            (sqlite3.Binary(target.settlement_domain_commitment),),
                        ).fetchone()
                        if reused_domain is not None:
                            raise ProductionBoundaryError(
                                "database_migration_recovery_domain_reuse"
                            )
                        if evidence.known_target_checkpoint is None:
                            raise ProductionBoundaryError(
                                "database_migration_known_target_required"
                            )
                        known = self._known_checkpoint_roots(
                            connection, evidence.known_target_checkpoint
                        )
                        if known is None:
                            raise ProductionBoundaryError(
                                "database_migration_unknown_target_checkpoint"
                            )
                        known_authority = self._governance_authority_by_commitment(
                            connection,
                            known[2],
                        )
                        if (
                            known[:2]
                            != (
                                target.strong_nullifier_root_after,
                                target.strong_payment_state_root_after,
                            )
                            or known_authority.authority_material
                            != target.governance_authority.authority_material
                        ):
                            raise ProductionBoundaryError(
                                "database_migration_target_checkpoint_mismatch"
                            )
                    elif evidence.known_target_checkpoint is not None:
                        raise ProductionBoundaryError(
                            "database_migration_unexpected_target_checkpoint"
                        )

                    next_binding = _digest(
                        _MIGRATION_STATE_BINDING_DOMAIN,
                        source.state_binding,
                        migration_commitment,
                        evidence.commitment,
                        source.checkpoint_commitment,
                        target.target_state_commitment,
                        transition.batch_nonce,
                        transition.submitter,
                        target.settlement_domain_commitment,
                        target.profile_id,
                        target.suite_id,
                        target.schema_id,
                        target.verifier_artifact_identity,
                        _u64(target.epoch, "migration_epoch_after"),
                        _u64(target.sequence_after, "migration_sequence_after"),
                        target.strong_nullifier_root_after,
                        target.strong_payment_state_root_after,
                        target.governance_commitment,
                    )
                    provisional_payload = _migration_audit_payload(
                        operation=operation,
                        state_binding_after=next_binding,
                        previous_audit_head=source.audit_head,
                    )
                    event_commitment = _digest(
                        _AUDIT_EVENT_DOMAIN,
                        source.audit_head,
                        provisional_payload,
                    )
                    next_audit_head = _digest(
                        _AUDIT_HEAD_DOMAIN, source.audit_head, event_commitment
                    )
                    next_anti_epoch = source.anti_rollback_epoch + 1
                    if next_anti_epoch != target.sequence_after:
                        raise ProductionBoundaryError(
                            "database_migration_anti_rollback_sequence_mismatch"
                        )
                    if self._anti_rollback is not None:
                        expected_pending = PendingAntiRollbackTransition(
                            next_anti_epoch,
                            next_binding,
                            migration_commitment,
                        )
                        if pending_anchor is not None:
                            if pending_anchor != expected_pending:
                                raise ProductionBoundaryError(
                                    "anti_rollback_transition_conflict"
                                )
                        else:
                            self._anti_rollback.prepare(
                                expected_epoch=source.anti_rollback_epoch,
                                expected_state_binding=source.state_binding,
                                next_epoch=next_anti_epoch,
                                next_state_binding=next_binding,
                                transition_commitment=migration_commitment,
                            )

                    self._insert_governance_authority(
                        connection,
                        target.sequence_after,
                        target.governance_authority,
                    )
                    connection.execute(
                        "INSERT INTO migration_requests VALUES "
                        "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
                        "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            sqlite3.Binary(migration_commitment),
                            evidence.kind,
                            sqlite3.Binary(evidence.commitment),
                            sqlite3.Binary(evidence.version_commitment),
                            sqlite3.Binary(evidence.equivalence_commitment),
                            sqlite3.Binary(source.checkpoint_commitment),
                            sqlite3.Binary(target.target_state_commitment),
                            None
                            if evidence.known_target_checkpoint is None
                            else sqlite3.Binary(evidence.known_target_checkpoint),
                            sqlite3.Binary(transition.envelope_commitment),
                            sqlite3.Binary(transition.batch_nonce),
                            sqlite3.Binary(transition.public_fields_commitment),
                            sqlite3.Binary(transition.submitter),
                            sqlite3.Binary(transition.evidence_commitment),
                            sqlite3.Binary(transition.statement_commitment),
                            sqlite3.Binary(transition.proof_package_commitment),
                            sqlite3.Binary(transition.transcript_commitment),
                            target.sequence_before,
                            target.sequence_after,
                            source.epoch,
                            target.epoch,
                            sqlite3.Binary(source.settlement_domain_commitment),
                            sqlite3.Binary(target.settlement_domain_commitment),
                            sqlite3.Binary(source.profile_id),
                            sqlite3.Binary(target.profile_id),
                            sqlite3.Binary(source.suite_id),
                            sqlite3.Binary(target.suite_id),
                            sqlite3.Binary(source.schema_id),
                            sqlite3.Binary(target.schema_id),
                            sqlite3.Binary(source.verifier_artifact_identity),
                            sqlite3.Binary(target.verifier_artifact_identity),
                            sqlite3.Binary(target.governance_commitment),
                            sqlite3.Binary(target.strong_nullifier_root_before),
                            sqlite3.Binary(target.strong_nullifier_root_after),
                            sqlite3.Binary(target.strong_payment_state_root_before),
                            sqlite3.Binary(target.strong_payment_state_root_after),
                            sqlite3.Binary(source.state_binding),
                            sqlite3.Binary(next_binding),
                            sqlite3.Binary(next_audit_head),
                        ),
                    )
                    connection.execute(
                        "INSERT INTO configuration_history VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            target.sequence_after,
                            sqlite3.Binary(target.settlement_domain_commitment),
                            sqlite3.Binary(target.profile_id),
                            sqlite3.Binary(target.suite_id),
                            sqlite3.Binary(target.schema_id),
                            sqlite3.Binary(target.verifier_artifact_identity),
                            target.epoch,
                            sqlite3.Binary(migration_commitment),
                        ),
                    )
                    connection.execute(
                        "INSERT INTO audit_events VALUES (?, ?, ?, ?, ?)",
                        (
                            target.sequence_after,
                            sqlite3.Binary(source.audit_head),
                            sqlite3.Binary(event_commitment),
                            sqlite3.Binary(next_audit_head),
                            sqlite3.Binary(provisional_payload),
                        ),
                    )
                    checkpoint = PrivacyV2DatabaseIdentity(
                        settlement_domain_commitment=target.settlement_domain_commitment,
                        governance_commitment=target.governance_commitment,
                        governance_authority=target.governance_authority,
                        profile_id=target.profile_id,
                        suite_id=target.suite_id,
                        schema_id=target.schema_id,
                        verifier_artifact_identity=target.verifier_artifact_identity,
                        epoch=target.epoch,
                        sequence=target.sequence_after,
                        strong_nullifier_root=target.strong_nullifier_root_after,
                        strong_payment_state_root=target.strong_payment_state_root_after,
                        state_binding=next_binding,
                        audit_head=next_audit_head,
                        anti_rollback_epoch=next_anti_epoch,
                        settled_batch_count=source.settled_batch_count,
                    )
                    connection.execute(
                        "INSERT INTO transition_records VALUES "
                        "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            target.sequence_after,
                            evidence.kind,
                            sqlite3.Binary(migration_commitment),
                            sqlite3.Binary(source.state_binding),
                            sqlite3.Binary(next_binding),
                            sqlite3.Binary(target.strong_nullifier_root_before),
                            sqlite3.Binary(target.strong_nullifier_root_after),
                            sqlite3.Binary(target.strong_payment_state_root_before),
                            sqlite3.Binary(target.strong_payment_state_root_after),
                            sqlite3.Binary(source.governance_commitment),
                            sqlite3.Binary(target.governance_commitment),
                            sqlite3.Binary(source.profile_id),
                            sqlite3.Binary(target.profile_id),
                            sqlite3.Binary(source.suite_id),
                            sqlite3.Binary(target.suite_id),
                            sqlite3.Binary(source.schema_id),
                            sqlite3.Binary(target.schema_id),
                            sqlite3.Binary(source.verifier_artifact_identity),
                            sqlite3.Binary(target.verifier_artifact_identity),
                            source.epoch,
                            target.epoch,
                            sqlite3.Binary(checkpoint.checkpoint_commitment),
                        ),
                    )
                    connection.execute(
                        "UPDATE configuration SET settlement_domain_commitment=?, "
                        "governance_commitment=?, profile_id=?, "
                        "suite_id=?, schema_id=?, verifier_artifact_identity=?, epoch=? "
                        "WHERE id=1",
                        (
                            sqlite3.Binary(target.settlement_domain_commitment),
                            sqlite3.Binary(target.governance_commitment),
                            sqlite3.Binary(target.profile_id),
                            sqlite3.Binary(target.suite_id),
                            sqlite3.Binary(target.schema_id),
                            sqlite3.Binary(target.verifier_artifact_identity),
                            target.epoch,
                        ),
                    )
                    connection.execute(
                        "UPDATE state SET epoch=?, sequence=?, strong_nullifier_root=?, "
                        "strong_payment_state_root=?, state_binding=?, audit_head=?, "
                        "governance_commitment=?, anti_rollback_epoch=? WHERE id=1",
                        (
                            target.epoch,
                            target.sequence_after,
                            sqlite3.Binary(target.strong_nullifier_root_after),
                            sqlite3.Binary(target.strong_payment_state_root_after),
                            sqlite3.Binary(next_binding),
                            sqlite3.Binary(next_audit_head),
                            sqlite3.Binary(target.governance_commitment),
                            next_anti_epoch,
                        ),
                    )
                    if self._before_commit_hook is not None:
                        self._before_commit_hook()
                    connection.execute("COMMIT")
                    began = False
                    committed_new = True
                    receipt = MigrationReceiptV2(
                        kind=evidence.kind,
                        migration_commitment=migration_commitment,
                        evidence_commitment=evidence.commitment,
                        source_checkpoint_commitment=source.checkpoint_commitment,
                        target_state_commitment=target.target_state_commitment,
                        epoch_before=source.epoch,
                        epoch_after=target.epoch,
                        sequence_before=target.sequence_before,
                        sequence_after=target.sequence_after,
                        strong_nullifier_root_after=target.strong_nullifier_root_after,
                        strong_payment_state_root_after=target.strong_payment_state_root_after,
                        state_binding_after=next_binding,
                        audit_head_after=next_audit_head,
                    )
            except sqlite3.IntegrityError as exc:
                if began and connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise ProductionBoundaryError("database_migration_conflict") from exc
            except sqlite3.OperationalError as exc:
                if began and connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise ProductionBoundaryError("database_migration_unavailable") from exc
            except Exception:
                if began and connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        if receipt is None:
            raise ProductionBoundaryError("database_migration_receipt_missing")
        if committed_new:
            self._settlement_domain = transition.public_fields[1]
            self._profile_id = target.profile_id
            self._suite_id = target.suite_id
            self._schema_id = target.schema_id
            self._verifier_artifact_identity = target.verifier_artifact_identity
            self._epoch = target.epoch
            self._governance_authority = target.governance_authority
        if self._anti_rollback is not None and committed_new:
            if next_binding is None or next_anti_epoch is None:
                raise ProductionBoundaryError("database_migration_anchor_state_missing")
            try:
                self._anti_rollback.finalize(
                    next_epoch=next_anti_epoch,
                    next_state_binding=next_binding,
                    transition_commitment=migration_commitment,
                )
            except Exception as exc:
                raise ProductionBoundaryError(
                    "database_migration_committed_anchor_pending"
                ) from exc
        return receipt

    def _verify_integrity_single_epoch(self) -> None:
        with closing(self._connect()) as connection:
            result = connection.execute("PRAGMA integrity_check").fetchone()
            if result != ("ok",):
                raise ProductionBoundaryError("database_sqlite_integrity_failed")
            self._validate_schema_version(connection)
            config = connection.execute(
                "SELECT settlement_domain_commitment, governance_commitment, profile_id, "
                "suite_id, schema_id, verifier_artifact_identity, epoch "
                "FROM configuration WHERE id=1"
            ).fetchone()
            if config is None:
                raise ProductionBoundaryError("database_configuration_missing")
            self._validate_config_row(config)
            foreign = connection.execute("PRAGMA foreign_key_check").fetchone()
            if foreign is not None:
                raise ProductionBoundaryError("database_foreign_key_integrity_failed")
            state_row = connection.execute(
                "SELECT epoch, sequence, strong_nullifier_root, strong_payment_state_root, "
                "state_binding, audit_head, governance_commitment, anti_rollback_epoch, "
                "settled_batch_count FROM state WHERE id=1"
            ).fetchone()
            if state_row is None:
                raise ProductionBoundaryError("database_state_missing")
            snapshot = self._state_snapshot(state_row)
            if (
                snapshot.epoch != self._epoch
                or snapshot.governance_commitment != self._governance_authority.commitment_512
            ):
                raise ProductionBoundaryError("database_state_identity_mismatch")
            counts = (
                connection.execute("SELECT COUNT(*) FROM settlement_requests").fetchone()[0],
                connection.execute("SELECT COUNT(*) FROM settled_nullifier_roots").fetchone()[0],
                connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0],
            )
            direct_count = connection.execute(
                "SELECT COUNT(*) FROM direct_clearance_requests"
            ).fetchone()[0]
            if counts[0] + direct_count != snapshot.settled_batch_count or counts[1] != counts[0] or counts[2] != snapshot.sequence:
                raise ProductionBoundaryError("database_transition_count_mismatch")
            previous_head = _digest(
                _AUDIT_GENESIS_DOMAIN,
                _digest(
                    _DATABASE_STATE_BINDING,
                    _u64(snapshot.epoch, "database_epoch"),
                    _u64(0, "database_sequence"),
                    self._initial_nullifier_root,
                    self._initial_payment_root,
                    snapshot.governance_commitment,
                ),
                self._initial_nullifier_root,
                self._initial_payment_root,
            )
            audit_payloads: dict[int, dict[str, object]] = {}
            expected_sequence = 1
            for row in connection.execute(
                "SELECT sequence, previous_head, event_commitment, current_head, payload "
                "FROM audit_events ORDER BY sequence"
            ):
                sequence, observed_previous, event_commitment, current_head, payload = row
                if sequence != expected_sequence:
                    raise ProductionBoundaryError("database_audit_sequence_invalid")
                observed_previous = bytes(observed_previous)
                event_commitment = bytes(event_commitment)
                current_head = bytes(current_head)
                payload = bytes(payload)
                if observed_previous != previous_head:
                    raise ProductionBoundaryError("database_audit_chain_broken")
                if event_commitment != _digest(_AUDIT_EVENT_DOMAIN, previous_head, payload):
                    raise ProductionBoundaryError("database_audit_event_commitment_invalid")
                expected_head = _digest(_AUDIT_HEAD_DOMAIN, previous_head, event_commitment)
                if current_head != expected_head:
                    raise ProductionBoundaryError("database_audit_head_invalid")
                try:
                    payload_probe = json.loads(payload.decode("ascii"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise ProductionBoundaryError(
                        "database_audit_payload_invalid"
                    ) from exc
                if (
                    type(payload_probe) is dict
                    and payload_probe.get("event_kind")
                    == "DIRECT_STATE_OWNED_CLEARANCE_V1"
                ):
                    decoded_payload = _direct_audit_payload_from_json(payload)
                    if (
                        decoded_payload["epoch"] != snapshot.epoch
                        or decoded_payload["sequence_before"] != sequence - 1
                        or decoded_payload["sequence_after"] != sequence
                        or decoded_payload["previous_audit_head"] != previous_head.hex()
                    ):
                        raise ProductionBoundaryError(
                            "database_audit_payload_binding_mismatch"
                        )
                else:
                    decoded_payload = _audit_payload_from_json(payload)
                    if (
                        decoded_payload["epoch"] != snapshot.epoch
                        or decoded_payload["sequence_before"] != sequence - 1
                        or decoded_payload["sequence_after"] != sequence
                        or decoded_payload["previous_audit_head"] != previous_head.hex()
                        or decoded_payload["governance_commitment"]
                        != snapshot.governance_commitment.hex()
                    ):
                        raise ProductionBoundaryError(
                            "database_audit_payload_binding_mismatch"
                        )
                audit_payloads[sequence] = decoded_payload
                previous_head = current_head
                expected_sequence += 1
            if expected_sequence - 1 != snapshot.sequence:
                raise ProductionBoundaryError("database_audit_sequence_invalid")
            if previous_head != snapshot.audit_head:
                raise ProductionBoundaryError("database_audit_head_mismatch")

            previous_nullifier = self._initial_nullifier_root
            previous_payment = self._initial_payment_root
            previous_binding = _digest(
                _DATABASE_STATE_BINDING,
                _u64(snapshot.epoch, "database_epoch"),
                _u64(0, "database_sequence"),
                self._initial_nullifier_root,
                self._initial_payment_root,
                snapshot.governance_commitment,
            )
            expected_sequence = 1
            request_rows = connection.execute(
                "SELECT r.envelope_commitment, r.batch_nonce, r.public_fields_commitment, "
                "r.submitter, r.operation_digest, r.sequence_before, r.sequence_after, "
                "r.statement_commitment, r.evidence_commitment, r.proof_package_commitment, "
                "r.transcript_commitment, r.strong_nullifier_root_before, "
                "r.strong_nullifier_root_after, r.strong_payment_state_root_before, "
                "r.strong_payment_state_root_after, r.state_binding_after, "
                "n.strong_nullifier_root_after "
                "FROM settlement_requests AS r JOIN settled_nullifier_roots AS n "
                "ON n.envelope_commitment=r.envelope_commitment ORDER BY r.sequence_after"
            )
            for row in request_rows:
                normalized = tuple(
                    value if index in (5, 6) else bytes(value)
                    for index, value in enumerate(row)
                )
                (
                    envelope_commitment,
                    batch_nonce,
                    fields_commitment,
                    submitter,
                    operation_digest,
                    sequence_before,
                    sequence_after,
                    statement,
                    evidence,
                    proof_package,
                    transcript,
                    nullifier_before,
                    nullifier_after,
                    payment_before,
                    payment_after,
                    state_binding_after,
                    indexed_nullifier_after,
                ) = normalized
                if sequence_before != expected_sequence - 1 or sequence_after != expected_sequence:
                    raise ProductionBoundaryError("database_request_sequence_invalid")
                _field("database_request_batch_nonce", batch_nonce, nonzero=True)
                for label, value in (
                    ("database_request_envelope", envelope_commitment),
                    ("database_request_fields", fields_commitment),
                    ("database_request_submitter", submitter),
                    ("database_request_operation", operation_digest),
                    ("database_request_statement", statement),
                    ("database_request_evidence", evidence),
                    ("database_request_proof_package", proof_package),
                    ("database_request_transcript", transcript),
                    ("database_request_nullifier_before", nullifier_before),
                    ("database_request_nullifier_after", nullifier_after),
                    ("database_request_payment_before", payment_before),
                    ("database_request_payment_after", payment_after),
                    ("database_request_state_binding", state_binding_after),
                ):
                    _wide(label, value)
                if (
                    nullifier_before != previous_nullifier
                    or payment_before != previous_payment
                    or indexed_nullifier_after != nullifier_after
                ):
                    raise ProductionBoundaryError("database_request_state_chain_broken")
                expected_binding = _digest(
                    _DATABASE_STATE_BINDING,
                    previous_binding,
                    batch_nonce,
                    nullifier_after,
                    payment_after,
                    envelope_commitment,
                    evidence,
                    submitter,
                    snapshot.governance_commitment,
                    _u64(snapshot.epoch, "database_epoch"),
                )
                if state_binding_after != expected_binding:
                    raise ProductionBoundaryError("database_request_state_binding_invalid")
                payload = audit_payloads.get(expected_sequence)
                if payload is None:
                    raise ProductionBoundaryError("database_request_audit_missing")
                expected_payload = {
                    "batch_nonce_commitment": _digest(_BATCH_NONCE_BINDING, batch_nonce).hex(),
                    "nullifier_root_before": nullifier_before.hex(),
                    "nullifier_root_after": nullifier_after.hex(),
                    "payment_state_root_before": payment_before.hex(),
                    "payment_state_root_after": payment_after.hex(),
                    "envelope_commitment": envelope_commitment.hex(),
                    "statement_commitment": statement.hex(),
                    "evidence_commitment": evidence.hex(),
                    "proof_package_commitment": proof_package.hex(),
                    "transcript_commitment": transcript.hex(),
                    "public_fields_commitment": fields_commitment.hex(),
                    "operation_digest": operation_digest.hex(),
                    "submitter_commitment": _digest(
                        _SUBMITTER_AUDIT_DOMAIN,
                        submitter,
                    ).hex(),
                    "state_binding": state_binding_after.hex(),
                    "profile_id": self._profile_id.hex(),
                    "proof_suite_id": self._suite_id.hex(),
                    "schema_id": self._schema_id.hex(),
                    "verifier_artifact_identity": self._verifier_artifact_identity.hex(),
                }
                if any(payload[name] != value for name, value in expected_payload.items()):
                    raise ProductionBoundaryError("database_request_audit_binding_mismatch")
                previous_nullifier = nullifier_after
                previous_payment = payment_after
                previous_binding = state_binding_after
                expected_sequence += 1
            direct_rows = connection.execute(
                "SELECT operation_digest, bundle_id, receipt_id, request_id, attempt_id, "
                "decision_id, join_id, source_root, profile_id, schema_id, program_id, "
                "mode_id, evaluator_id, control_set_id, rule_id, phase0_receipt_binding, "
                "exception_id, policy_result, effective_directive, event_time, "
                "observation_time, rule_effective_time, decision_time, continuity_epoch, "
                "continuity_sequence_before, continuity_sequence_after, "
                "continuity_before_state_id, continuity_after_state_id, "
                "continuity_before_audit_head, continuity_after_audit_head, "
                "continuity_before_root, continuity_after_root, sequence_before, "
                "sequence_after, nullifier_root_before, nullifier_root_after, "
                "payment_root_before, payment_root_after, state_binding_after, "
                "audit_head_after, clearance_advanced "
                "FROM direct_clearance_requests ORDER BY sequence_after"
            )
            for raw_direct in direct_rows:
                direct = tuple(
                    value if type(value) is int else bytes(value)
                    for value in raw_direct
                )
                direct_operation = _direct_operation_from_record(direct)
                operation_digest = direct[0]
                if (
                    _direct_operation_digest(direct_operation) != operation_digest
                    or direct_operation.profile_id != self._profile_id
                    or direct_operation.schema_id != self._schema_id
                    or direct_operation.program_id != self._verifier_artifact_identity
                    or direct_operation.continuity_epoch != snapshot.epoch
                    or direct[32] != expected_sequence - 1
                    or direct[33] != expected_sequence
                    or direct[34] != previous_nullifier
                    or direct[36] != previous_payment
                    or direct[40] != int(direct_operation.effective_directive in (1, 5))
                ):
                    raise ProductionBoundaryError("database_direct_transition_mismatch")
                if (
                    self._direct_mode_id is not None
                    and (
                        direct_operation.mode_id != self._direct_mode_id
                        or direct_operation.evaluator_id != self._direct_evaluator_id
                        or direct_operation.control_set_id != self._direct_control_set_id
                        or direct_operation.rule_id != self._direct_rule_id
                        or direct_operation.phase0_receipt_binding
                        != self._direct_phase0_receipt_binding
                    )
                ):
                    raise ProductionBoundaryError(
                        "database_direct_operation_context_mismatch"
                    )
                expected_nullifier = _digest(
                    _DIRECT_REPLAY_ROOT_DOMAIN,
                    previous_nullifier,
                    direct_operation.attempt_id,
                    direct_operation.bundle_id,
                    direct_operation.receipt_id,
                )
                expected_payment = (
                    _digest(
                        _DIRECT_CLEARANCE_ROOT_DOMAIN,
                        previous_payment,
                        direct_operation.continuity_after_state_id,
                        direct_operation.decision_id,
                        bytes((direct_operation.effective_directive,)),
                    )
                    if direct_operation.effective_directive in (1, 5)
                    else previous_payment
                )
                expected_binding = _digest(
                    _DATABASE_STATE_BINDING,
                    previous_binding,
                    direct_operation.attempt_id,
                    expected_nullifier,
                    expected_payment,
                    direct_operation.bundle_id,
                    operation_digest,
                    snapshot.governance_commitment,
                    _u64(snapshot.epoch, "database_epoch"),
                )
                if (
                    direct[35] != expected_nullifier
                    or direct[37] != expected_payment
                    or direct[38] != expected_binding
                ):
                    raise ProductionBoundaryError("database_direct_state_binding_invalid")
                payload = audit_payloads.get(expected_sequence)
                if payload is None:
                    raise ProductionBoundaryError("database_direct_audit_missing")
                if expected_sequence == 1:
                    expected_previous_head = _digest(
                        _AUDIT_GENESIS_DOMAIN,
                        _digest(
                            _DATABASE_STATE_BINDING,
                            _u64(snapshot.epoch, "database_epoch"),
                            _u64(0, "database_sequence"),
                            self._initial_nullifier_root,
                            self._initial_payment_root,
                            snapshot.governance_commitment,
                        ),
                        self._initial_nullifier_root,
                        self._initial_payment_root,
                    )
                else:
                    previous_row = connection.execute(
                        "SELECT previous_head FROM audit_events WHERE sequence=?",
                        (expected_sequence,),
                    ).fetchone()
                    if previous_row is None:
                        raise ProductionBoundaryError("database_direct_audit_missing")
                    expected_previous_head = bytes(previous_row[0])
                expected_payload = json.loads(
                    _direct_audit_payload(
                        operation=direct_operation,
                        operation_digest=operation_digest,  # type: ignore[arg-type]
                        sequence_before=expected_sequence - 1,
                        sequence_after=expected_sequence,
                        nullifier_before=previous_nullifier,
                        nullifier_after=direct[35],  # type: ignore[arg-type]
                        payment_before=previous_payment,
                        payment_after=direct[37],  # type: ignore[arg-type]
                        state_binding=direct[38],  # type: ignore[arg-type]
                        previous_head=expected_previous_head,
                    ).decode("ascii")
                )
                if payload != expected_payload:
                    raise ProductionBoundaryError("database_direct_audit_binding_mismatch")
                audit_row = connection.execute(
                    "SELECT current_head FROM audit_events WHERE sequence=?",
                    (expected_sequence,),
                ).fetchone()
                if audit_row is None or direct[39] != bytes(audit_row[0]):
                    raise ProductionBoundaryError("database_direct_audit_head_mismatch")
                transition = connection.execute(
                    "SELECT sequence_after, record_commitment, state_binding_before, "
                    "state_binding_after, nullifier_root_before, nullifier_root_after, "
                    "payment_root_before, payment_root_after, governance_before, "
                    "governance_after, profile_before, profile_after, suite_before, "
                    "suite_after, schema_before, schema_after, verifier_before, "
                    "verifier_after, epoch_before, epoch_after, checkpoint_commitment_after "
                    "FROM transition_records WHERE record_commitment=?",
                    (sqlite3.Binary(operation_digest),),
                ).fetchone()
                if transition is None:
                    raise ProductionBoundaryError("database_direct_transition_missing")
                transition = tuple(
                    value if type(value) is int else bytes(value)
                    for value in transition
                )
                if (
                    transition[0] != expected_sequence
                    or transition[1] != operation_digest
                    or transition[2] != previous_binding
                    or transition[3] != direct[38]
                    or transition[4] != previous_nullifier
                    or transition[5] != direct[35]
                    or transition[6] != previous_payment
                    or transition[7] != direct[37]
                    or transition[8] != snapshot.governance_commitment
                    or transition[9] != snapshot.governance_commitment
                    or transition[10] != self._profile_id
                    or transition[11] != self._profile_id
                    or transition[12] != self._suite_id
                    or transition[13] != self._suite_id
                    or transition[14] != self._schema_id
                    or transition[15] != self._schema_id
                    or transition[16] != self._verifier_artifact_identity
                    or transition[17] != self._verifier_artifact_identity
                    or transition[18] != snapshot.epoch
                    or transition[19] != snapshot.epoch
                ):
                    raise ProductionBoundaryError("database_direct_transition_mismatch")
                checkpoint = PrivacyV2DatabaseIdentity(
                    settlement_domain_commitment=_digest(
                        _DOMAIN_COMMITMENT_DOMAIN,
                        self._settlement_domain,
                    ),
                    governance_commitment=snapshot.governance_commitment,
                    governance_authority=self._governance_authority,
                    profile_id=self._profile_id,
                    suite_id=self._suite_id,
                    schema_id=self._schema_id,
                    verifier_artifact_identity=self._verifier_artifact_identity,
                    epoch=snapshot.epoch,
                    sequence=expected_sequence,
                    strong_nullifier_root=direct[35],  # type: ignore[arg-type]
                    strong_payment_state_root=direct[37],  # type: ignore[arg-type]
                    state_binding=direct[38],  # type: ignore[arg-type]
                    audit_head=direct[39],  # type: ignore[arg-type]
                    anti_rollback_epoch=expected_sequence,
                    settled_batch_count=expected_sequence,
                )
                if transition[20] != checkpoint.checkpoint_commitment:
                    raise ProductionBoundaryError("database_transition_checkpoint_invalid")
                previous_nullifier = direct[35]  # type: ignore[assignment]
                previous_payment = direct[37]  # type: ignore[assignment]
                previous_binding = direct[38]  # type: ignore[assignment]
                expected_sequence += 1
            if (
                expected_sequence - 1 != snapshot.sequence
                or previous_nullifier != snapshot.strong_nullifier_root
                or previous_payment != snapshot.strong_payment_state_root
                or previous_binding != snapshot.state_binding
            ):
                raise ProductionBoundaryError("database_request_final_state_mismatch")
            transition_commitment = self._latest_operation_digest(
                connection,
                snapshot.anti_rollback_epoch,
            )
        self._reconcile_anti_rollback_state(
            epoch=snapshot.anti_rollback_epoch,
            state_binding=snapshot.state_binding,
            transition_commitment=transition_commitment,
        )

    def _verify_migrated_integrity(self) -> None:
        with closing(self._connect()) as connection:
            if connection.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                raise ProductionBoundaryError("database_sqlite_integrity_failed")
            self._validate_schema_version(connection)
            if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
                raise ProductionBoundaryError("database_foreign_key_integrity_failed")
            config = connection.execute(
                "SELECT settlement_domain_commitment, governance_commitment, profile_id, "
                "suite_id, schema_id, verifier_artifact_identity, epoch "
                "FROM configuration WHERE id=1"
            ).fetchone()
            state = connection.execute(
                "SELECT epoch, sequence, strong_nullifier_root, strong_payment_state_root, "
                "state_binding, audit_head, governance_commitment, anti_rollback_epoch, "
                "settled_batch_count FROM state WHERE id=1"
            ).fetchone()
            genesis = connection.execute(
                "SELECT settlement_domain_commitment, governance_commitment, profile_id, suite_id, "
                "schema_id, verifier_artifact_identity, epoch, strong_nullifier_root, "
                "strong_payment_state_root, state_binding, audit_head, checkpoint_commitment "
                "FROM database_genesis WHERE id=1"
            ).fetchone()
            if config is None or state is None or genesis is None:
                raise ProductionBoundaryError("database_integrity_authority_missing")
            self._validate_config_row(config)
            snapshot = self._state_snapshot(state)
            normalized_genesis = tuple(
                value if type(value) is int else bytes(value) for value in genesis
            )
            current = PrivacyV2DatabaseIdentity(
                settlement_domain_commitment=normalized_genesis[0],  # type: ignore[arg-type]
                governance_commitment=normalized_genesis[1],  # type: ignore[arg-type]
                governance_authority=self._governance_authority_by_commitment(
                    connection,
                    normalized_genesis[1],  # type: ignore[arg-type]
                ),
                profile_id=normalized_genesis[2],  # type: ignore[arg-type]
                suite_id=normalized_genesis[3],  # type: ignore[arg-type]
                schema_id=normalized_genesis[4],  # type: ignore[arg-type]
                verifier_artifact_identity=normalized_genesis[5],  # type: ignore[arg-type]
                epoch=normalized_genesis[6],  # type: ignore[arg-type]
                sequence=0,
                strong_nullifier_root=normalized_genesis[7],  # type: ignore[arg-type]
                strong_payment_state_root=normalized_genesis[8],  # type: ignore[arg-type]
                state_binding=normalized_genesis[9],  # type: ignore[arg-type]
                audit_head=normalized_genesis[10],  # type: ignore[arg-type]
                anti_rollback_epoch=0,
                settled_batch_count=0,
            )
            if (
                current.checkpoint_commitment != normalized_genesis[11]
                or current.strong_nullifier_root != self._initial_nullifier_root
                or current.strong_payment_state_root != self._initial_payment_root
            ):
                raise ProductionBoundaryError("database_genesis_integrity_failed")
            genesis_history = connection.execute(
                "SELECT settlement_domain_commitment, profile_id, suite_id, schema_id, "
                "verifier_artifact_identity, epoch, migration_commitment "
                "FROM configuration_history WHERE activation_sequence=0"
            ).fetchone()
            expected_genesis_history = (
                current.settlement_domain_commitment,
                current.profile_id,
                current.suite_id,
                current.schema_id,
                current.verifier_artifact_identity,
                current.epoch,
                None,
            )
            if genesis_history is None or tuple(
                value
                if value is None or type(value) is int
                else bytes(value)
                for value in genesis_history
            ) != expected_genesis_history:
                raise ProductionBoundaryError(
                    "database_genesis_configuration_history_invalid"
                )

            settlement_count = connection.execute(
                "SELECT COUNT(*) FROM settlement_requests"
            ).fetchone()[0]
            nullifier_count = connection.execute(
                "SELECT COUNT(*) FROM settled_nullifier_roots"
            ).fetchone()[0]
            migration_count = connection.execute(
                "SELECT COUNT(*) FROM migration_requests"
            ).fetchone()[0]
            transition_count = connection.execute(
                "SELECT COUNT(*) FROM transition_records"
            ).fetchone()[0]
            audit_count = connection.execute(
                "SELECT COUNT(*) FROM audit_events"
            ).fetchone()[0]
            history_count = connection.execute(
                "SELECT COUNT(*) FROM configuration_history"
            ).fetchone()[0]
            if (
                settlement_count != snapshot.settled_batch_count
                or nullifier_count != settlement_count
                or transition_count != settlement_count + migration_count
                or transition_count != snapshot.sequence
                or audit_count != transition_count
                or history_count != migration_count + 1
            ):
                raise ProductionBoundaryError("database_transition_count_mismatch")

            expected_sequence = 1
            transition_rows = connection.execute(
                "SELECT sequence_after, transition_kind, record_commitment, "
                "state_binding_before, state_binding_after, nullifier_root_before, "
                "nullifier_root_after, payment_root_before, payment_root_after, "
                "governance_before, governance_after, profile_before, profile_after, "
                "suite_before, suite_after, schema_before, schema_after, verifier_before, "
                "verifier_after, epoch_before, epoch_after, checkpoint_commitment_after "
                "FROM transition_records ORDER BY sequence_after"
            )
            for raw_transition in transition_rows:
                transition = tuple(
                    value
                    if type(value) is int or isinstance(value, str)
                    else bytes(value)
                    for value in raw_transition
                )
                (
                    sequence_after,
                    transition_kind,
                    record_commitment,
                    state_binding_before,
                    state_binding_after,
                    nullifier_before,
                    nullifier_after,
                    payment_before,
                    payment_after,
                    governance_before,
                    governance_after,
                    profile_before,
                    profile_after,
                    suite_before,
                    suite_after,
                    schema_before,
                    schema_after,
                    verifier_before,
                    verifier_after,
                    epoch_before,
                    epoch_after,
                    checkpoint_after,
                ) = transition
                if sequence_after != expected_sequence:
                    raise ProductionBoundaryError("database_transition_sequence_invalid")
                if (
                    state_binding_before != current.state_binding
                    or nullifier_before != current.strong_nullifier_root
                    or payment_before != current.strong_payment_state_root
                    or governance_before != current.governance_commitment
                    or profile_before != current.profile_id
                    or suite_before != current.suite_id
                    or schema_before != current.schema_id
                    or verifier_before != current.verifier_artifact_identity
                    or epoch_before != current.epoch
                ):
                    raise ProductionBoundaryError("database_transition_chain_broken")
                audit_row = connection.execute(
                    "SELECT previous_head, event_commitment, current_head, payload "
                    "FROM audit_events WHERE sequence=?",
                    (sequence_after,),
                ).fetchone()
                if audit_row is None:
                    raise ProductionBoundaryError("database_transition_audit_missing")
                previous_head, event_commitment, audit_head_after, payload = (
                    bytes(value) for value in audit_row
                )
                if previous_head != current.audit_head:
                    raise ProductionBoundaryError("database_audit_chain_broken")
                if event_commitment != _digest(
                    _AUDIT_EVENT_DOMAIN, current.audit_head, payload
                ):
                    raise ProductionBoundaryError(
                        "database_audit_event_commitment_invalid"
                    )
                if audit_head_after != _digest(
                    _AUDIT_HEAD_DOMAIN, current.audit_head, event_commitment
                ):
                    raise ProductionBoundaryError("database_audit_head_invalid")

                if transition_kind == "SETTLEMENT":
                    next_domain_commitment = current.settlement_domain_commitment
                    request = connection.execute(
                        "SELECT envelope_commitment, batch_nonce, public_fields_commitment, "
                        "submitter, operation_digest, sequence_before, sequence_after, "
                        "statement_commitment, evidence_commitment, proof_package_commitment, "
                        "transcript_commitment, strong_nullifier_root_before, "
                        "strong_nullifier_root_after, strong_payment_state_root_before, "
                        "strong_payment_state_root_after, state_binding_after "
                        "FROM settlement_requests WHERE operation_digest=?",
                        (sqlite3.Binary(record_commitment),),
                    ).fetchone()
                    if request is None:
                        raise ProductionBoundaryError("database_request_missing")
                    request = tuple(
                        value if index in (5, 6) else bytes(value)
                        for index, value in enumerate(request)
                    )
                    if (
                        request[4] != record_commitment
                        or request[5] != current.sequence
                        or request[6] != sequence_after
                        or request[11] != nullifier_before
                        or request[12] != nullifier_after
                        or request[13] != payment_before
                        or request[14] != payment_after
                        or request[15] != state_binding_after
                        or governance_after != governance_before
                        or profile_after != profile_before
                        or suite_after != suite_before
                        or schema_after != schema_before
                        or verifier_after != verifier_before
                        or epoch_after != epoch_before
                    ):
                        raise ProductionBoundaryError(
                            "database_request_transition_mismatch"
                        )
                    indexed = connection.execute(
                        "SELECT envelope_commitment FROM settled_nullifier_roots "
                        "WHERE strong_nullifier_root_after=?",
                        (sqlite3.Binary(nullifier_after),),
                    ).fetchone()
                    if indexed is None or bytes(indexed[0]) != request[0]:
                        raise ProductionBoundaryError(
                            "database_request_nullifier_index_invalid"
                        )
                    expected_binding = _digest(
                        _DATABASE_STATE_BINDING,
                        current.state_binding,
                        request[1],
                        nullifier_after,
                        payment_after,
                        request[0],
                        request[8],
                        request[3],
                        governance_after,
                        _u64(epoch_after, "database_epoch"),  # type: ignore[arg-type]
                    )
                    if expected_binding != state_binding_after:
                        raise ProductionBoundaryError(
                            "database_request_state_binding_invalid"
                        )
                    decoded = _audit_payload_from_json(payload)
                    expected_payload = {
                        "epoch": epoch_after,
                        "sequence_before": current.sequence,
                        "sequence_after": sequence_after,
                        "previous_audit_head": current.audit_head.hex(),
                        "batch_nonce_commitment": _digest(
                            _BATCH_NONCE_BINDING, request[1]
                        ).hex(),
                        "nullifier_root_before": nullifier_before.hex(),
                        "nullifier_root_after": nullifier_after.hex(),
                        "payment_state_root_before": payment_before.hex(),
                        "payment_state_root_after": payment_after.hex(),
                        "governance_commitment": governance_after.hex(),
                        "envelope_commitment": request[0].hex(),
                        "statement_commitment": request[7].hex(),
                        "evidence_commitment": request[8].hex(),
                        "proof_package_commitment": request[9].hex(),
                        "transcript_commitment": request[10].hex(),
                        "public_fields_commitment": request[2].hex(),
                        "operation_digest": record_commitment.hex(),
                        "submitter_commitment": _digest(
                            _SUBMITTER_AUDIT_DOMAIN, request[3]
                        ).hex(),
                        "state_binding": state_binding_after.hex(),
                        "profile_id": profile_after.hex(),
                        "proof_suite_id": suite_after.hex(),
                        "schema_id": schema_after.hex(),
                        "verifier_artifact_identity": verifier_after.hex(),
                    }
                    if any(decoded[name] != value for name, value in expected_payload.items()):
                        raise ProductionBoundaryError(
                            "database_request_audit_binding_mismatch"
                        )
                    settled_batch_count = current.settled_batch_count + 1
                else:
                    migration = connection.execute(
                        "SELECT migration_kind, migration_evidence_commitment, "
                        "migration_version_commitment, equivalence_commitment, "
                        "source_checkpoint_commitment, target_state_commitment, "
                        "known_target_checkpoint, envelope_commitment, batch_nonce, "
                        "public_fields_commitment, submitter, native_evidence_commitment, "
                        "statement_commitment, proof_package_commitment, transcript_commitment, "
                        "sequence_before, sequence_after, epoch_before, epoch_after, "
                        "settlement_domain_before, settlement_domain_after, "
                        "profile_before, profile_after, suite_before, suite_after, "
                        "schema_before, schema_after, verifier_before, verifier_after, "
                        "governance_commitment, nullifier_root_before, nullifier_root_after, "
                        "payment_root_before, payment_root_after, state_binding_before, "
                        "state_binding_after, audit_head_after FROM migration_requests "
                        "WHERE migration_commitment=?",
                        (sqlite3.Binary(record_commitment),),
                    ).fetchone()
                    if migration is None:
                        raise ProductionBoundaryError("database_migration_record_missing")
                    migration = tuple(
                        value
                        if value is None or type(value) is int or isinstance(value, str)
                        else bytes(value)
                        for value in migration
                    )
                    if (
                        migration[0] != transition_kind
                        or migration[4] != current.checkpoint_commitment
                        or migration[15] != current.sequence
                        or migration[16] != sequence_after
                        or migration[17] != epoch_before
                        or migration[18] != epoch_after
                        or migration[19] != current.settlement_domain_commitment
                        or migration[21] != profile_before
                        or migration[22] != profile_after
                        or migration[23] != suite_before
                        or migration[24] != suite_after
                        or migration[25] != schema_before
                        or migration[26] != schema_after
                        or migration[27] != verifier_before
                        or migration[28] != verifier_after
                        or migration[29] != governance_after
                        or migration[30] != nullifier_before
                        or migration[31] != nullifier_after
                        or migration[32] != payment_before
                        or migration[33] != payment_after
                        or migration[34] != state_binding_before
                        or migration[35] != state_binding_after
                        or migration[36] != audit_head_after
                        or epoch_after != epoch_before + 1
                    ):
                        raise ProductionBoundaryError(
                            "database_migration_transition_mismatch"
                        )
                    next_domain_commitment = migration[20]
                    migration_target = PrivacyV2MigrationTarget(
                        settlement_domain_commitment=next_domain_commitment,
                        profile_id=profile_after,
                        suite_id=suite_after,
                        schema_id=schema_after,
                        verifier_artifact_identity=verifier_after,
                        epoch=epoch_after,  # type: ignore[arg-type]
                        sequence_before=current.sequence,
                        sequence_after=sequence_after,  # type: ignore[arg-type]
                        strong_nullifier_root_before=nullifier_before,
                        strong_nullifier_root_after=nullifier_after,
                        strong_payment_state_root_before=payment_before,
                        strong_payment_state_root_after=payment_after,
                        governance_authority=self._governance_authority_by_commitment(
                            connection,
                            governance_after,
                        ),
                        governance_commitment=governance_after,
                    )
                    migration_evidence = PrivacyV2MigrationEvidence(
                        kind=transition_kind,
                        version_commitment=migration[2],
                        equivalence_commitment=migration[3],
                        source_checkpoint_commitment=migration[4],
                        target_state_commitment=migration[5],
                        known_target_checkpoint=migration[6],
                    )
                    if (
                        migration_target.target_state_commitment != migration[5]
                        or migration_evidence.commitment != migration[1]
                        or derive_migration_nonce(
                            current,
                            migration_target,
                            migration_evidence,
                        )
                        != migration[8]
                    ):
                        raise ProductionBoundaryError(
                            "database_migration_evidence_binding_invalid"
                        )
                    expected_binding = _digest(
                        _MIGRATION_STATE_BINDING_DOMAIN,
                        current.state_binding,
                        record_commitment,
                        migration[1],
                        migration[4],
                        migration[5],
                        migration[8],
                        migration[10],
                        next_domain_commitment,
                        profile_after,
                        suite_after,
                        schema_after,
                        verifier_after,
                        _u64(epoch_after, "migration_epoch_after"),  # type: ignore[arg-type]
                        _u64(sequence_after, "migration_sequence_after"),  # type: ignore[arg-type]
                        nullifier_after,
                        payment_after,
                        governance_after,
                    )
                    if expected_binding != state_binding_after:
                        raise ProductionBoundaryError(
                            "database_migration_state_binding_invalid"
                        )
                    decoded = _migration_audit_payload_from_json(payload)
                    expected_migration_payload = {
                        "migration_kind": transition_kind,
                        "epoch_before": epoch_before,
                        "epoch_after": epoch_after,
                        "sequence_before": current.sequence,
                        "sequence_after": sequence_after,
                        "migration_commitment": record_commitment.hex(),
                        "migration_evidence_commitment": migration[1].hex(),
                        "migration_version_commitment": migration[2].hex(),
                        "equivalence_commitment": migration[3].hex(),
                        "source_checkpoint_commitment": migration[4].hex(),
                        "target_state_commitment": migration[5].hex(),
                        "known_target_checkpoint": (
                            bytes(64).hex()
                            if migration[6] is None
                            else migration[6].hex()
                        ),
                        "batch_nonce_commitment": _digest(
                            _BATCH_NONCE_BINDING, migration[8]
                        ).hex(),
                        "envelope_commitment": migration[7].hex(),
                        "statement_commitment": migration[12].hex(),
                        "native_evidence_commitment": migration[11].hex(),
                        "proof_package_commitment": migration[13].hex(),
                        "transcript_commitment": migration[14].hex(),
                        "public_fields_commitment": migration[9].hex(),
                        "submitter_commitment": _digest(
                            _SUBMITTER_AUDIT_DOMAIN, migration[10]
                        ).hex(),
                        "previous_audit_head": current.audit_head.hex(),
                        "state_binding_before": current.state_binding.hex(),
                        "state_binding_after": state_binding_after.hex(),
                        "nullifier_root_before": nullifier_before.hex(),
                        "nullifier_root_after": nullifier_after.hex(),
                        "payment_state_root_before": payment_before.hex(),
                        "payment_state_root_after": payment_after.hex(),
                        "governance_commitment": governance_after.hex(),
                        "settlement_domain_commitment_before": current.settlement_domain_commitment.hex(),
                        "settlement_domain_commitment_after": next_domain_commitment.hex(),
                        "profile_id_before": profile_before.hex(),
                        "profile_id_after": profile_after.hex(),
                        "proof_suite_id_before": suite_before.hex(),
                        "proof_suite_id_after": suite_after.hex(),
                        "schema_id_before": schema_before.hex(),
                        "schema_id_after": schema_after.hex(),
                        "verifier_artifact_identity_before": verifier_before.hex(),
                        "verifier_artifact_identity_after": verifier_after.hex(),
                    }
                    if any(
                        decoded[name] != value
                        for name, value in expected_migration_payload.items()
                    ):
                        raise ProductionBoundaryError(
                            "database_migration_audit_binding_mismatch"
                        )
                    history = connection.execute(
                        "SELECT settlement_domain_commitment, profile_id, suite_id, schema_id, "
                        "verifier_artifact_identity, "
                        "epoch, migration_commitment FROM configuration_history "
                        "WHERE activation_sequence=?",
                        (sequence_after,),
                    ).fetchone()
                    expected_history = (
                        next_domain_commitment,
                        profile_after,
                        suite_after,
                        schema_after,
                        verifier_after,
                        epoch_after,
                        record_commitment,
                    )
                    if history is None or tuple(
                        value if type(value) is int else bytes(value) for value in history
                    ) != expected_history:
                        raise ProductionBoundaryError(
                            "database_configuration_history_invalid"
                        )
                    settled_batch_count = current.settled_batch_count

                next_identity = PrivacyV2DatabaseIdentity(
                    settlement_domain_commitment=next_domain_commitment,
                    governance_commitment=governance_after,
                    governance_authority=self._governance_authority_by_commitment(
                        connection,
                        governance_after,
                    ),
                    profile_id=profile_after,
                    suite_id=suite_after,
                    schema_id=schema_after,
                    verifier_artifact_identity=verifier_after,
                    epoch=epoch_after,  # type: ignore[arg-type]
                    sequence=sequence_after,  # type: ignore[arg-type]
                    strong_nullifier_root=nullifier_after,
                    strong_payment_state_root=payment_after,
                    state_binding=state_binding_after,
                    audit_head=audit_head_after,
                    anti_rollback_epoch=sequence_after,  # type: ignore[arg-type]
                    settled_batch_count=settled_batch_count,
                )
                if next_identity.checkpoint_commitment != checkpoint_after:
                    raise ProductionBoundaryError(
                        "database_transition_checkpoint_invalid"
                    )
                current = next_identity
                expected_sequence += 1

            normalized_config = tuple(
                value if type(value) is int else bytes(value) for value in config
            )
            if (
                current.sequence != snapshot.sequence
                or current.epoch != snapshot.epoch
                or current.strong_nullifier_root
                != snapshot.strong_nullifier_root
                or current.strong_payment_state_root
                != snapshot.strong_payment_state_root
                or current.state_binding != snapshot.state_binding
                or current.audit_head != snapshot.audit_head
                or current.governance_commitment
                != snapshot.governance_commitment
                or current.anti_rollback_epoch
                != snapshot.anti_rollback_epoch
                or current.settled_batch_count
                != snapshot.settled_batch_count
                or normalized_config
                != (
                    current.settlement_domain_commitment,
                    current.governance_commitment,
                    current.profile_id,
                    current.suite_id,
                    current.schema_id,
                    current.verifier_artifact_identity,
                    current.epoch,
                )
            ):
                raise ProductionBoundaryError("database_final_state_mismatch")
            transition_commitment = self._latest_operation_digest(
                connection, snapshot.anti_rollback_epoch
            )
        self._reconcile_anti_rollback_state(
            epoch=snapshot.anti_rollback_epoch,
            state_binding=snapshot.state_binding,
            transition_commitment=transition_commitment,
        )

    def verify_integrity(self) -> None:
        with closing(self._connect()) as connection:
            authority_rows = connection.execute(
                "SELECT activation_sequence, governance_commitment, profile_code, epoch, "
                "truth_root_0, truth_root_1, truth_root_2, truth_root_3, truth_root_4, "
                "truth_root_5, claim_truth_authority_digest, nullifier_authority_id, "
                "pepper_commitment FROM governance_authorities ORDER BY activation_sequence"
            ).fetchall()
            if not authority_rows:
                raise ProductionBoundaryError("database_governance_authority_missing")
            authority_by_sequence = {
                row[0]: _governance_authority_from_row(row)
                for row in authority_rows
            }
            genesis_governance = connection.execute(
                "SELECT governance_commitment FROM database_genesis WHERE id=1"
            ).fetchone()
            if (
                genesis_governance is None
                or 0 not in authority_by_sequence
                or authority_by_sequence[0].commitment_512
                != bytes(genesis_governance[0])
            ):
                raise ProductionBoundaryError(
                    "database_genesis_governance_authority_mismatch"
                )
            migration_authorities = connection.execute(
                "SELECT sequence_after, governance_after, epoch_after FROM transition_records "
                "WHERE transition_kind!='SETTLEMENT' ORDER BY sequence_after"
            ).fetchall()
            expected_authority_sequences = {0}
            for sequence_after, governance_after, epoch_after in migration_authorities:
                expected_authority_sequences.add(sequence_after)
                authority = authority_by_sequence.get(sequence_after)
                if (
                    authority is None
                    or authority.commitment_512 != bytes(governance_after)
                    or authority.epoch != epoch_after
                ):
                    raise ProductionBoundaryError(
                        "database_transition_governance_authority_mismatch"
                    )
            if set(authority_by_sequence) != expected_authority_sequences:
                raise ProductionBoundaryError(
                    "database_governance_authority_ledger_count_mismatch"
                )
            migration_count = connection.execute(
                "SELECT COUNT(*) FROM migration_requests"
            ).fetchone()[0]
            direct_count = connection.execute(
                "SELECT COUNT(*) FROM direct_clearance_requests"
            ).fetchone()[0]
            transition_count = connection.execute(
                "SELECT COUNT(*) FROM transition_records"
            ).fetchone()[0]
            request_count = connection.execute(
                "SELECT COUNT(*) FROM settlement_requests"
            ).fetchone()[0]
        if transition_count != request_count + direct_count + migration_count:
            raise ProductionBoundaryError("database_transition_ledger_count_mismatch")
        if migration_count == 0:
            self._verify_integrity_single_epoch()
            return
        self._verify_migrated_integrity()

    def create_backup(self, destination: Path) -> None:
        """Create and fully verify one SQLite online-backup snapshot."""

        if not isinstance(destination, Path):
            raise TypeError("database_backup_path_required")
        if destination.exists() or destination.is_symlink():
            raise ProductionBoundaryError("database_backup_destination_must_not_exist")
        if not destination.parent.is_dir():
            raise ProductionBoundaryError("database_backup_parent_directory_missing")
        if destination.resolve() == self._path.resolve():
            raise ProductionBoundaryError("database_backup_destination_matches_source")
        self.verify_integrity()
        try:
            with closing(self._connect()) as source, closing(
                sqlite3.connect(str(destination), isolation_level=None)
            ) as target:
                source.backup(target)
                result = target.execute("PRAGMA integrity_check").fetchone()
                if result != ("ok",):
                    raise ProductionBoundaryError("database_backup_integrity_failed")
            candidate = SQLiteSettlementStoreV2(
                path=destination,
                settlement_domain=self._settlement_domain,
                governance_authority=self._governance_authority,
                initial_strong_nullifier_root=self._initial_nullifier_root,
                initial_strong_payment_state_root=self._initial_payment_root,
                epoch=self._epoch,
                profile_id=self._profile_id,
                suite_id=self._suite_id,
                schema_id=self._schema_id,
                verifier_artifact_identity=self._verifier_artifact_identity,
            )
            candidate.close()
            with closing(sqlite3.connect(str(destination), isolation_level=None)) as connection:
                connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                connection.execute("PRAGMA journal_mode=DELETE")
        except Exception:
            self._discard_created_database(destination)
            raise

    def recover_from_backup(
        self,
        *,
        backup_path: Path,
        recovered_path: Path,
    ) -> "SQLiteSettlementStoreV2":
        """Restore a verified backup into a new file and reapply all gates.

        The active database is never overwritten.  An external anti-rollback
        reference, when configured, rejects a backup older than its anchor.
        """

        if not isinstance(backup_path, Path) or not isinstance(recovered_path, Path):
            raise TypeError("database_recovery_paths_required")
        if backup_path.is_symlink() or not backup_path.is_file():
            raise ProductionBoundaryError("database_recovery_backup_invalid")
        if recovered_path.exists() or recovered_path.is_symlink():
            raise ProductionBoundaryError("database_recovery_destination_must_not_exist")
        if not recovered_path.parent.is_dir():
            raise ProductionBoundaryError("database_recovery_parent_directory_missing")
        if recovered_path.resolve() in (backup_path.resolve(), self._path.resolve()):
            raise ProductionBoundaryError("database_recovery_destination_invalid")
        source_uri = backup_path.resolve().as_uri() + "?mode=ro"
        try:
            with closing(sqlite3.connect(source_uri, uri=True, isolation_level=None)) as source:
                if source.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                    raise ProductionBoundaryError("database_recovery_backup_integrity_failed")
                with closing(sqlite3.connect(str(recovered_path), isolation_level=None)) as target:
                    source.backup(target)
            return SQLiteSettlementStoreV2(
                path=recovered_path,
                settlement_domain=self._settlement_domain,
                governance_authority=self._governance_authority,
                initial_strong_nullifier_root=self._initial_nullifier_root,
                initial_strong_payment_state_root=self._initial_payment_root,
                epoch=self._epoch,
                profile_id=self._profile_id,
                suite_id=self._suite_id,
                schema_id=self._schema_id,
                verifier_artifact_identity=self._verifier_artifact_identity,
                anti_rollback=self._anti_rollback,
            )
        except Exception:
            self._discard_created_database(recovered_path)
            raise

    def close(self) -> None:
        self._native_authority_key = None
        self._migration_authority_key = None
        self._direct_authority_key = None
        self._direct_mode_id = None
        self._direct_evaluator_id = None
        self._direct_control_set_id = None
        self._direct_rule_id = None
        self._direct_phase0_receipt_binding = None
        self._closed = True


class TransactionalSettlementV2:
    """Native-verifier gate followed by one storage-port transition."""

    def __init__(
        self,
        *,
        verifier: object,
        storage: TransactionalSettlementStoragePort,
        settlement_domain: bytes,
        governance_authority: GovernanceAuthorityV2,
        authorized_submitters: tuple[bytes, ...] | list[bytes],
    ) -> None:
        if not callable(getattr(verifier, "verify", None)):
            raise TypeError("transactional_native_verifier_required")
        # Protocols are intentionally not runtime-checkable; these method
        # checks keep the boundary explicit without accepting a feature flag.
        if not all(
            callable(getattr(storage, name, None))
            for name in (
                "_bind_native_authority",
                "_commit_verified",
                "_governance_authority_for_commitment",
                "identity_snapshot",
                "snapshot",
                "verify_integrity",
                "close",
            )
        ):
            raise TypeError("transactional_storage_port_required")
        if type(governance_authority) is not GovernanceAuthorityV2:
            raise TypeError("transactional_governance_authority_required")
        self._verifier = verifier
        self._storage = storage
        self._settlement_domain = _field("transactional_settlement_domain", settlement_domain, nonzero=True)
        self._initial_governance_authority = governance_authority
        self._authorized_submitters = frozenset(
            _wide("transactional_authorized_submitter", value) for value in authorized_submitters
        )
        if not self._authorized_submitters:
            raise ProductionBoundaryError("transactional_submitters_empty")
        initial_identity = self._storage.identity_snapshot()
        if (
            type(initial_identity) is not PrivacyV2DatabaseIdentity
            or initial_identity.governance_authority != governance_authority
            or initial_identity.settlement_domain_commitment
            != _digest(_DOMAIN_COMMITMENT_DOMAIN, self._settlement_domain)
        ):
            raise ProductionBoundaryError("transactional_initial_configuration_mismatch")
        self.__native_authority_key = secrets.token_bytes(64)
        self._storage._bind_native_authority(self.__native_authority_key)

    def _prepare(
        self,
        *,
        envelope: ProductionProofEnvelope,
        batch_nonce: bytes,
        submitter: bytes,
    ) -> VerifiedSettlementOperationV2:
        if type(envelope) is not ProductionProofEnvelope:
            raise ProductionBoundaryError("transactional_envelope_required")
        submitter_id = _wide("transactional_submitter", submitter)
        if submitter_id not in self._authorized_submitters:
            raise ProductionBoundaryError("transactional_submitter_not_authorized")
        nonce = _field("transactional_batch_nonce", batch_nonce, nonzero=True)
        parsed = _sidecar(envelope.sidecar)
        governance_authority = self._storage._governance_authority_for_commitment(
            parsed.strong_governance_commitment
        )
        active_domain = tuple(
            envelope.public_outputs[index : index + PUBLIC_FIELD_BYTES]
            for index in range(0, len(envelope.public_outputs), PUBLIC_FIELD_BYTES)
        )[1]
        fields = validate_v2_public_projection(
            public_fields=tuple(
                envelope.public_outputs[index : index + PUBLIC_FIELD_BYTES]
                for index in range(0, len(envelope.public_outputs), PUBLIC_FIELD_BYTES)
            ),
            sidecar=envelope.sidecar,
            settlement_domain=active_domain,
            batch_nonce=nonce,
            governance_authority=governance_authority,
            suite_id=envelope.suite_id,
            schema_id=envelope.schema_id,
            verifier_artifact_identity=envelope.verifier_artifact_identity,
        )
        result = self._verifier.verify(envelope)
        if type(result) is not NativeVerificationResult:
            raise ProductionBoundaryError("transactional_verifier_result_invalid")
        receipt = result.receipt
        if type(receipt) is not NativeVerificationReceipt:
            raise ProductionBoundaryError("transactional_verifier_receipt_invalid")
        encoded = envelope.encode()
        expected_envelope = hashlib.sha3_512(encoded).digest()
        expected_statement = statement_commitment(envelope.public_outputs, envelope.sidecar)
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
            or receipt.verifier_artifact_identity != envelope.verifier_artifact_identity
        ):
            raise ProductionBoundaryError("transactional_verifier_binding_mismatch")
        operation_values = {
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
            "governance_authority": governance_authority,
            "strong_governance_commitment": parsed.strong_governance_commitment,
            "strong_payment_state_root_before": parsed.strong_payment_state_root_before,
            "strong_payment_state_root_after": parsed.strong_payment_state_root_after,
            "strong_batch_commitment": parsed.strong_batch_commitment,
        }
        seal = _verified_operation_seal(
            authority_key=self.__native_authority_key,
            **operation_values,  # type: ignore[arg-type]
        )
        return VerifiedSettlementOperationV2(
            **operation_values,  # type: ignore[arg-type]
            seal=seal,
        )

    def submit(
        self,
        *,
        envelope: ProductionProofEnvelope,
        batch_nonce: bytes,
        submitter: bytes,
    ) -> SettlementReceiptV2:
        operation = self._prepare(
            envelope=envelope,
            batch_nonce=batch_nonce,
            submitter=submitter,
        )
        return self._storage._commit_verified(operation)

    def snapshot(self) -> DatabaseSettlementSnapshotV2:
        return self._storage.snapshot()

    def verify_integrity(self) -> None:
        self._storage.verify_integrity()

    def close(self) -> None:
        self._storage.close()
        self.__native_authority_key = b"\x00" * 64


__all__ = (
    "AntiRollbackAnchorSnapshot",
    "AntiRollbackReference",
    "InMemoryAntiRollbackReference",
    "PendingAntiRollbackTransition",
    "SQLiteSettlementStoreV2",
    "TransactionalSettlementV2",
)
