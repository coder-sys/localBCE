"""Qualification-only direct-state-owned transactional database boundary.

This module deliberately implements a local SQLite reference, not a production
database selection.  The direct state-owned evaluator remains the semantic
authority; this module only proves the durable all-or-nothing clearance-state
seam that follows it.  No network, Ethereum, PHI, payment connector, or
activation credential is opened here.
"""

from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass, replace
import hashlib
import hmac
import json
from pathlib import Path
import sqlite3
from threading import RLock
from typing import Callable, Final, Protocol

from app.batch.poseidon import FIELD_MODULUS
from parked.state_clearance.app.governance_authority_v2 import GovernanceAuthorityV2


PUBLIC_FIELD_BYTES: Final[int] = 32
_SCHEMA_VERSION: Final[int] = 4
_DATABASE_STATE_BINDING = b"BL/PQ512/V2/DATABASE-ATOMIC-STATE/v1\x00"
_CHECKPOINT_DOMAIN = b"BL/PQ512/V2/DATABASE-CHECKPOINT/v1\x00"
_AUDIT_GENESIS_DOMAIN = b"BL/PQ512/V2/DATABASE-AUDIT-GENESIS/v1\x00"
_AUDIT_EVENT_DOMAIN = b"BL/PQ512/V2/DATABASE-AUDIT-EVENT/v1\x00"
_AUDIT_HEAD_DOMAIN = b"BL/PQ512/V2/DATABASE-AUDIT-HEAD/v1\x00"
_DOMAIN_COMMITMENT_DOMAIN = b"BL/PQ512/V2/DATABASE-DOMAIN/v1\x00"
_DIRECT_OPERATION_DOMAIN = b"BL/DIRECT-STATE-OWNED/CLEARANCE-OPERATION/v1\x00"
_DIRECT_STATE_OPERATION_DOMAIN = b"BL/DIRECT-STATE-OWNED/CLEARANCE-OPERATION/STATE-V1\x00"
_DIRECT_OPERATION_SEAL_DOMAIN = b"BL/DIRECT-STATE-OWNED/CLEARANCE-SEAL/v1\x00"
_DIRECT_REPLAY_ROOT_DOMAIN = b"BL/DIRECT-STATE-OWNED/REPLAY-ROOT/v1\x00"
_DIRECT_CLEARANCE_ROOT_DOMAIN = b"BL/DIRECT-STATE-OWNED/CLEARANCE-ROOT/v1\x00"
_DIRECT_CLEARANCE_STATE_BINDING_DOMAIN = b"BL/DIRECT-STATE-OWNED/CLEARANCE-STATE-BINDING/v1\x00"
_DIRECT_CLEARANCE_GENESIS_DOMAIN = b"BL/DIRECT-STATE-OWNED/CLEARANCE-GENESIS/v1\x00"
_DIRECT_DATABASE_STATE_BINDING_DOMAIN = b"BL/DIRECT-STATE-OWNED/DATABASE-STATE-BINDING/v1\x00"
_DIRECT_CLEARANCE_SCHEMA_VERSION: Final[int] = 1
_DIRECT_TRANSITION_KIND = "DIRECT_CLEARANCE"
_SCHEMA_TABLES: Final[frozenset[str]] = frozenset(
    {
        "metadata",
        "configuration",
        "state",
        "governance_authorities",
        "direct_clearance_state",
        "direct_clearance_requests",
        "audit_events",
        "database_genesis",
        "transition_records",
    }
)
_DIRECT_CLEARANCE_STATE_COLUMNS: Final[tuple[str, ...]] = (
    "id",
    "schema_version",
    "epoch",
    "sequence",
    "clearance_root",
    "direct_clearance_count",
    "state_binding",
    "database_state_binding",
    "payment_root",
    "settled_batch_count",
    "audit_head",
    "last_operation_digest",
)
_DIRECT_CLEARANCE_REQUEST_COLUMNS: Final[tuple[str, ...]] = (
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
    "policy_result",
    "effective_directive",
    "event_time",
    "observation_time",
    "rule_effective_time",
    "decision_time",
    "continuity_epoch",
    "continuity_sequence_before",
    "continuity_sequence_after",
    "continuity_before_state_id",
    "continuity_after_state_id",
    "continuity_before_audit_head",
    "continuity_after_audit_head",
    "continuity_before_root",
    "continuity_after_root",
    "sequence_before",
    "sequence_after",
    "nullifier_root_before",
    "nullifier_root_after",
    "payment_root_before",
    "payment_root_after",
    "state_binding_after",
    "audit_head_after",
    "clearance_advanced",
    "clearance_root_before",
    "clearance_root_after",
    "direct_clearance_count_before",
    "direct_clearance_count_after",
    "direct_state_binding_after",
    "settled_batch_count_before",
    "settled_batch_count_after",
)
_DIRECT_CONTINUITY_STATE_MAGIC = b"BLCSTA02"
_DIRECT_CONTINUITY_STATE_VERSION = 2
_DIRECT_CONTINUITY_STATE_CONTEXT_DOMAIN = b"BL/NATIVE-V3/CONTINUITY/STATE-CONTEXT/v2\x00"
_DIRECT_CONTINUITY_STATE_ID_DOMAIN = b"BL/NATIVE-V3/CONTINUITY/STATE-ID/v2\x00"
_DIRECT_CONTINUITY_AUDIT_HEAD_DOMAIN = b"BL/NATIVE-V3/CONTINUITY/AUDIT-HEAD/v2\x00"
_DIRECT_CONTINUITY_ROOT_DOMAIN = b"BL/NATIVE-V3/CONTINUITY/ROOT/v2\x00"


class ProductionBoundaryError(ValueError):
    """Stable fail-closed errors at the local direct database boundary."""


def _wide(label: str, value: object) -> bytes:
    if type(value) is not bytes or len(value) != 64 or not any(value):
        raise ProductionBoundaryError(f"{label}_must_be_nonzero_512_bits")
    return value


def _field(label: str, value: object, *, nonzero: bool = False) -> bytes:
    if type(value) is not bytes or len(value) != PUBLIC_FIELD_BYTES:
        raise ProductionBoundaryError(f"{label}_must_be_bytes32")
    if int.from_bytes(value, "big") >= FIELD_MODULUS:
        raise ProductionBoundaryError(f"{label}_not_canonical_field")
    if nonzero and not any(value):
        raise ProductionBoundaryError(f"{label}_must_be_nonzero")
    return value


def _digest(domain: bytes, *parts: bytes) -> bytes:
    if type(domain) is not bytes or not domain or len(domain) > 128:
        raise ProductionBoundaryError("binding_domain_invalid")
    digest = hashlib.sha3_512(domain)
    for part in parts:
        if type(part) is not bytes or len(part) > 512 * 1024 * 1024:
            raise ProductionBoundaryError("binding_part_invalid")
        digest.update(len(part).to_bytes(8, "big"))
        digest.update(part)
    return digest.digest()


def _u64(value: int, label: str) -> bytes:
    if type(value) is not int or value < 0 or value >= 2**64:
        raise ProductionBoundaryError(f"{label}_invalid")
    return value.to_bytes(8, "big")


@dataclass(frozen=True, slots=True)
class DatabaseSettlementSnapshotV2:
    """Durable state readback retained for the direct database port."""

    epoch: int
    sequence: int
    strong_nullifier_root: bytes
    strong_payment_state_root: bytes
    state_binding: bytes
    audit_head: bytes
    governance_commitment: bytes
    anti_rollback_epoch: int
    settled_batch_count: int

    def __post_init__(self) -> None:
        if type(self.epoch) is not int or self.epoch <= 0:
            raise ProductionBoundaryError("database_snapshot_epoch_invalid")
        if type(self.sequence) is not int or self.sequence < 0:
            raise ProductionBoundaryError("database_snapshot_sequence_invalid")
        if type(self.anti_rollback_epoch) is not int or self.anti_rollback_epoch < 0:
            raise ProductionBoundaryError("database_snapshot_anti_rollback_epoch_invalid")
        if type(self.settled_batch_count) is not int or self.settled_batch_count < 0:
            raise ProductionBoundaryError("database_snapshot_count_invalid")
        for label, value in (
            ("database_snapshot_nullifier_root", self.strong_nullifier_root),
            ("database_snapshot_payment_state_root", self.strong_payment_state_root),
            ("database_snapshot_binding", self.state_binding),
            ("database_snapshot_audit_head", self.audit_head),
            ("database_snapshot_governance_commitment", self.governance_commitment),
        ):
            _wide(label, value)


@dataclass(frozen=True, slots=True)
class PrivacyV2DatabaseIdentity:
    """Exact direct database identity and authoritative committed state."""

    settlement_domain_commitment: bytes
    governance_commitment: bytes
    governance_authority: GovernanceAuthorityV2
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
            raise ProductionBoundaryError("database_identity_epoch_invalid")
        _u64(self.sequence, "identity_sequence")
        _u64(self.anti_rollback_epoch, "identity_anti_rollback_epoch")
        _u64(self.settled_batch_count, "identity_settled_batch_count")
        if self.anti_rollback_epoch != self.sequence:
            raise ProductionBoundaryError("database_identity_anti_rollback_mismatch")
        if self.settled_batch_count > self.sequence:
            raise ProductionBoundaryError("database_identity_count_invalid")
        if type(self.governance_authority) is not GovernanceAuthorityV2:
            raise TypeError("database_identity_governance_authority_required")
        if (
            self.governance_authority.epoch != self.epoch
            or self.governance_authority.commitment_512 != self.governance_commitment
        ):
            raise ProductionBoundaryError("database_identity_governance_authority_mismatch")

    @property
    def checkpoint_commitment(self) -> bytes:
        return _digest(
            _CHECKPOINT_DOMAIN,
            self.settlement_domain_commitment,
            self.governance_authority.canonical_bytes,
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
    """Lean-bound semantic result sealed for the direct database boundary.

    This is not a proof envelope and contains no private source bytes.  The
    direct adapter constructs it only from an accepted versioned State result
    while the database transaction is open; the database authenticates the
    value with a store-bound key before applying its transition.
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
    clearance_advanced: bool | None = None
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
            or self.continuity_sequence_after != self.continuity_sequence_before + 1
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
        if self.continuity_sequence_before == 0 and (
            self.continuity_before_audit_head != expected_empty_audit
            or self.continuity_before_root != expected_empty_root
        ):
            raise ProductionBoundaryError("direct_continuity_before_state_invalid")
        if self.continuity_before_state_id != _direct_continuity_state_id(
            profile_id=self.profile_id,
            mode_id=self.mode_id,
            sequence=self.continuity_sequence_before,
            row_count=self.continuity_sequence_before,
            audit_head=self.continuity_before_audit_head,
            continuity_root=self.continuity_before_root,
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
                sequence=self.continuity_sequence_after,
                row_count=self.continuity_sequence_after,
                audit_head=self.continuity_after_audit_head,
                continuity_root=self.continuity_after_root,
            )
        ):
            raise ProductionBoundaryError("direct_continuity_after_state_invalid")
        if self.clearance_advanced is not None and (
            type(self.clearance_advanced) is not bool
            or self.clearance_advanced != (self.effective_directive in (1, 5))
        ):
            raise ProductionBoundaryError("direct_clearance_decision_invalid")
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
    clearance_count_before: int
    clearance_count_after: int
    payment_root_before: bytes
    payment_root_after: bytes
    settled_batch_count_before: int
    settled_batch_count_after: int
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
            ("direct_receipt_payment_before", self.payment_root_before),
            ("direct_receipt_payment_after", self.payment_root_after),
            ("direct_receipt_binding", self.state_binding),
            ("direct_receipt_audit", self.audit_head),
        ):
            _wide(label, value)
        if type(self.sequence_before) is not int or self.sequence_before < 0:
            raise ProductionBoundaryError("direct_receipt_sequence_before_invalid")
        if self.sequence_after != self.sequence_before + 1:
            raise ProductionBoundaryError("direct_receipt_sequence_after_invalid")
        if type(self.clearance_count_before) is not int or self.clearance_count_before < 0:
            raise ProductionBoundaryError("direct_receipt_clearance_count_before_invalid")
        if self.clearance_count_after != self.clearance_count_before + 1:
            raise ProductionBoundaryError("direct_receipt_clearance_count_after_invalid")
        if type(self.settled_batch_count_before) is not int or self.settled_batch_count_before < 0:
            raise ProductionBoundaryError("direct_receipt_settled_count_before_invalid")
        if self.settled_batch_count_after != self.settled_batch_count_before:
            raise ProductionBoundaryError("direct_receipt_settled_count_changed")
        if self.payment_root_after != self.payment_root_before:
            raise ProductionBoundaryError("direct_receipt_payment_root_changed")
        if type(self.effective_directive) is not int or self.effective_directive not in (1, 2, 3, 4, 5):
            raise ProductionBoundaryError("direct_receipt_directive_invalid")
        if type(self.clearance_advanced) is not bool:
            raise ProductionBoundaryError("direct_receipt_clearance_flag_invalid")


@dataclass(frozen=True, slots=True)
class DirectClearanceStateSnapshotV1:
    """Dedicated direct-clearance state, separate from settlement state."""

    schema_version: int
    epoch: int
    sequence: int
    clearance_root: bytes
    clearance_count: int
    state_binding: bytes
    database_state_binding: bytes
    payment_root: bytes
    settled_batch_count: int
    audit_head: bytes
    last_operation_digest: bytes | None

    def __post_init__(self) -> None:
        if self.schema_version != _DIRECT_CLEARANCE_SCHEMA_VERSION:
            raise ProductionBoundaryError("direct_clearance_schema_version_invalid")
        for label, value in (
            ("direct_clearance_root", self.clearance_root),
            ("direct_clearance_state_binding", self.state_binding),
            ("direct_clearance_database_binding", self.database_state_binding),
            ("direct_clearance_payment_root", self.payment_root),
            ("direct_clearance_audit_head", self.audit_head),
        ):
            _wide(label, value)
        if type(self.epoch) is not int or self.epoch <= 0:
            raise ProductionBoundaryError("direct_clearance_epoch_invalid")
        if type(self.sequence) is not int or self.sequence < 0:
            raise ProductionBoundaryError("direct_clearance_sequence_invalid")
        if type(self.clearance_count) is not int or self.clearance_count < 0:
            raise ProductionBoundaryError("direct_clearance_count_invalid")
        if type(self.settled_batch_count) is not int or self.settled_batch_count < 0:
            raise ProductionBoundaryError("direct_clearance_settled_count_invalid")
        if self.last_operation_digest is not None:
            _wide("direct_clearance_last_operation", self.last_operation_digest)


@dataclass(frozen=True, slots=True)
class DirectStateOwnedCommitContextV1:
    """Authoritative state and retry row read under the owner's write lock."""

    epoch: int
    global_sequence: int
    anti_rollback_epoch: int
    global_state_binding: bytes
    global_audit_head: bytes
    nullifier_root: bytes
    payment_root: bytes
    global_settled_batch_count: int
    governance_commitment: bytes
    direct_count: int
    direct_state: DirectClearanceStateSnapshotV1
    continuity_sequence: int
    continuity_row_count: int
    continuity_state_id: bytes
    continuity_audit_head: bytes
    continuity_root: bytes
    prior_operation_digest: bytes | None
    prior_operation: DirectStateOwnedOperationV1 | None


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
    if operation.clearance_advanced is None:
        return _digest(_DIRECT_OPERATION_DOMAIN, *_direct_operation_parts(operation))
    return _digest(
        _DIRECT_STATE_OPERATION_DOMAIN,
        *_direct_operation_parts(operation),
        bytes((int(operation.clearance_advanced),)),
    )


def _direct_operation_clearance_advanced(
    operation: DirectStateOwnedOperationV1,
) -> bool:
    if operation.clearance_advanced is None:
        return operation.effective_directive in (1, 5)
    return operation.clearance_advanced


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
        "clearance_root_before",
        "clearance_root_after",
        "direct_state_binding",
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
    "direct_clearance_count_before",
    "direct_clearance_count_after",
    "settled_batch_count_before",
    "settled_batch_count_after",
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


def _direct_clearance_genesis_binding(
    *,
    epoch: int,
    database_state_binding: bytes,
    clearance_root: bytes,
    payment_root: bytes,
    settled_batch_count: int,
    governance_commitment: bytes,
) -> bytes:
    return _digest(
        _DIRECT_CLEARANCE_GENESIS_DOMAIN,
        _u64(_DIRECT_CLEARANCE_SCHEMA_VERSION, "direct_clearance_schema_version"),
        _u64(epoch, "direct_clearance_epoch"),
        database_state_binding,
        clearance_root,
        _u64(0, "direct_clearance_count"),
        payment_root,
        _u64(settled_batch_count, "direct_clearance_settled_count"),
        governance_commitment,
    )


def _direct_clearance_state_binding(
    *,
    previous_binding: bytes,
    previous_database_binding: bytes,
    operation_digest: bytes,
    epoch: int,
    sequence: int,
    clearance_root: bytes,
    clearance_count: int,
    payment_root: bytes,
    settled_batch_count: int,
    governance_commitment: bytes,
) -> bytes:
    return _digest(
        _DIRECT_CLEARANCE_STATE_BINDING_DOMAIN,
        _u64(_DIRECT_CLEARANCE_SCHEMA_VERSION, "direct_clearance_schema_version"),
        previous_binding,
        previous_database_binding,
        operation_digest,
        _u64(epoch, "direct_clearance_epoch"),
        _u64(sequence, "direct_clearance_sequence"),
        clearance_root,
        _u64(clearance_count, "direct_clearance_count"),
        payment_root,
        _u64(settled_batch_count, "direct_clearance_settled_count"),
        governance_commitment,
    )


def _direct_database_state_binding(
    *,
    previous_database_binding: bytes,
    direct_state_binding: bytes,
    operation: DirectStateOwnedOperationV1,
    operation_digest: bytes,
    sequence: int,
    nullifier_after: bytes,
    payment_root_after: bytes,
    settled_batch_count_after: int,
    clearance_root_after: bytes,
    clearance_count_after: int,
    governance_commitment: bytes,
) -> bytes:
    return _digest(
        _DIRECT_DATABASE_STATE_BINDING_DOMAIN,
        previous_database_binding,
        direct_state_binding,
        operation.attempt_id,
        nullifier_after,
        payment_root_after,
        operation.bundle_id,
        operation_digest,
        governance_commitment,
        _u64(operation.continuity_epoch, "direct_database_epoch"),
        _u64(sequence, "direct_database_sequence"),
        clearance_root_after,
        _u64(clearance_count_after, "direct_database_clearance_count"),
        _u64(settled_batch_count_after, "direct_database_settled_count"),
    )


def _direct_clearance_state_from_row(
    row: tuple[object, ...],
) -> DirectClearanceStateSnapshotV1:
    if len(row) != 12:
        raise ProductionBoundaryError("database_direct_clearance_state_shape_invalid")
    normalized = tuple(
        value if value is None or type(value) is int else bytes(value)
        for value in row
    )
    return DirectClearanceStateSnapshotV1(
        schema_version=normalized[1],  # type: ignore[arg-type]
        epoch=normalized[2],  # type: ignore[arg-type]
        sequence=normalized[3],  # type: ignore[arg-type]
        clearance_root=normalized[4],  # type: ignore[arg-type]
        clearance_count=normalized[5],  # type: ignore[arg-type]
        state_binding=normalized[6],  # type: ignore[arg-type]
        database_state_binding=normalized[7],  # type: ignore[arg-type]
        payment_root=normalized[8],  # type: ignore[arg-type]
        settled_batch_count=normalized[9],  # type: ignore[arg-type]
        audit_head=normalized[10],  # type: ignore[arg-type]
        last_operation_digest=normalized[11],  # type: ignore[arg-type]
    )


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
    clearance_before: bytes,
    clearance_after: bytes,
    clearance_count_before: int,
    clearance_count_after: int,
    direct_state_binding: bytes,
    settled_batch_count_before: int,
    settled_batch_count_after: int,
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
        "clearance_advanced": int(_direct_operation_clearance_advanced(operation)),
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
        "clearance_root_before": clearance_before.hex(),
        "clearance_root_after": clearance_after.hex(),
        "direct_clearance_count_before": clearance_count_before,
        "direct_clearance_count_after": clearance_count_after,
        "direct_state_binding": direct_state_binding.hex(),
        "settled_batch_count_before": settled_batch_count_before,
        "settled_batch_count_after": settled_batch_count_after,
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
        for name in ("epoch", "sequence_before", "sequence_after", "event_time", "observation_time", "rule_effective_time", "decision_time", "direct_clearance_count_before", "direct_clearance_count_after", "settled_batch_count_before", "settled_batch_count_after"):
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
        if payload["direct_clearance_count_after"] != payload["direct_clearance_count_before"] + 1:
            raise ValueError
        if payload["settled_batch_count_after"] != payload["settled_batch_count_before"]:
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
    if len(row) != 21:
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
        clearance_count_before=normalized[11],  # type: ignore[arg-type]
        clearance_count_after=normalized[12],  # type: ignore[arg-type]
        payment_root_before=normalized[13],  # type: ignore[arg-type]
        payment_root_after=normalized[14],  # type: ignore[arg-type]
        settled_batch_count_before=normalized[15],  # type: ignore[arg-type]
        settled_batch_count_after=normalized[16],  # type: ignore[arg-type]
        state_binding=normalized[17],  # type: ignore[arg-type]
        audit_head=normalized[18],  # type: ignore[arg-type]
        effective_directive=normalized[19],  # type: ignore[arg-type]
        clearance_advanced=bool(normalized[20]),
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
        legacy = DirectStateOwnedOperationV1(
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
        if _direct_operation_digest(legacy) == normalized[0]:
            return legacy
        if type(normalized[40]) is not int or normalized[40] not in (0, 1):
            raise ProductionBoundaryError("database_direct_operation_version_invalid")
        state_operation = replace(legacy, clearance_advanced=bool(normalized[40]))
        if _direct_operation_digest(state_operation) == normalized[0]:
            return state_operation
        raise ProductionBoundaryError("database_direct_operation_digest_invalid")
    except ProductionBoundaryError:
        raise
    except (TypeError, ValueError) as exc:
        raise ProductionBoundaryError(
            "database_direct_operation_record_invalid"
        ) from exc

class SQLiteSettlementStoreV2:
    """Serializable SQLite reference for one atomic direct clearance transition."""

    def __init__(
        self,
        *,
        path: Path,
        settlement_domain: bytes,
        governance_authority: GovernanceAuthorityV2,
        initial_strong_nullifier_root: bytes,
        initial_strong_payment_state_root: bytes,
        initial_direct_clearance_root: bytes | None = None,
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
        self._initial_direct_clearance_root = _wide(
            "database_initial_direct_clearance_root",
            self._initial_payment_root
            if initial_direct_clearance_root is None
            else initial_direct_clearance_root,
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
        self._direct_authority_key: bytes | None = None
        self._direct_mode_id: bytes | None = None
        self._direct_evaluator_id: bytes | None = None
        self._direct_control_set_id: bytes | None = None
        self._direct_rule_id: bytes | None = None
        self._direct_phase0_receipt_binding: bytes | None = None
        self._closed = False
        self._preflight_existing_schema_version(self._path)
        self._initialize()

    @staticmethod
    def _preflight_existing_schema_version(path: Path) -> None:
        """Reject an unsupported existing schema before opening it read-write.

        Opening a WAL-mode SQLite database through the normal connection path can create
        ``-wal``/``-shm`` sidecars even when initialization subsequently rejects its
        schema.  The immutable read-only preflight observes only an explicit metadata
        version and leaves all other initialization and corruption handling to the
        normal path.
        """

        try:
            if not path.exists() or path.stat().st_size == 0:
                return
        except OSError:
            return

        source_uri = path.resolve().as_uri() + "?mode=ro&immutable=1"
        try:
            with closing(
                sqlite3.connect(source_uri, uri=True, isolation_level=None)
            ) as connection:
                tables = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master "
                        "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                    ).fetchall()
                }
                if "metadata" not in tables:
                    return
                row = connection.execute(
                    "SELECT schema_version FROM metadata WHERE id=1"
                ).fetchone()
        except sqlite3.DatabaseError:
            return

        if row is None or row == (_SCHEMA_VERSION,):
            return
        if row in {(1,), (2,)}:
            raise ProductionBoundaryError("database_legacy_governance_schema_rejected")
        raise ProductionBoundaryError("database_schema_version_mismatch")

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
        sequence: int,
    ) -> bytes | None:
        if type(sequence) is not int or sequence < 0:
            raise ProductionBoundaryError("database_state_anti_rollback_epoch_invalid")
        if sequence == 0:
            return None
        row = connection.execute(
            "SELECT transition_kind, record_commitment FROM transition_records "
            "WHERE sequence_after=?",
            (sequence,),
        ).fetchone()
        if row is None or row[0] != _DIRECT_TRANSITION_KIND:
            raise ProductionBoundaryError("database_direct_transition_kind_invalid")
        recorded = _wide("database_latest_operation_digest", bytes(row[1]))
        authority = connection.execute(
            "SELECT operation_digest FROM direct_clearance_requests "
            "WHERE sequence_after=?",
            (sequence,),
        ).fetchone()
        if authority is None:
            raise ProductionBoundaryError("database_latest_operation_missing")
        authoritative = _wide("database_latest_operation_digest", bytes(authority[0]))
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

    @staticmethod
    def _validate_direct_table_shapes(connection: sqlite3.Connection) -> None:
        observed_state = tuple(
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(direct_clearance_state)"
            ).fetchall()
        )
        observed_requests = tuple(
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(direct_clearance_requests)"
            ).fetchall()
        )
        if observed_state != _DIRECT_CLEARANCE_STATE_COLUMNS:
            raise ProductionBoundaryError("database_direct_clearance_schema_mismatch")
        if observed_requests != _DIRECT_CLEARANCE_REQUEST_COLUMNS:
            raise ProductionBoundaryError("database_direct_clearance_schema_mismatch")

    def _direct_clearance_genesis_row(
        self,
        connection: sqlite3.Connection,
    ) -> tuple[object, ...]:
        row = connection.execute(
            "SELECT epoch, governance_commitment, strong_payment_state_root, "
            "state_binding, audit_head FROM database_genesis WHERE id=1"
        ).fetchone()
        if row is None:
            raise ProductionBoundaryError("database_genesis_integrity_failed")
        epoch, governance, payment, database_binding, audit_head = tuple(
            value if type(value) is int else bytes(value) for value in row
        )
        existing_root = connection.execute(
            "SELECT clearance_root FROM direct_clearance_state WHERE id=1"
        ).fetchone()
        clearance_root = (
            self._initial_direct_clearance_root
            if existing_root is None
            else _wide("database_direct_clearance_genesis_root", bytes(existing_root[0]))
        )
        clearance_binding = _direct_clearance_genesis_binding(
            epoch=epoch,  # type: ignore[arg-type]
            database_state_binding=database_binding,  # type: ignore[arg-type]
            clearance_root=clearance_root,
            payment_root=payment,  # type: ignore[arg-type]
            settled_batch_count=0,
            governance_commitment=governance,  # type: ignore[arg-type]
        )
        return (
            1,
            _DIRECT_CLEARANCE_SCHEMA_VERSION,
            epoch,
            0,
            clearance_root,
            0,
            clearance_binding,
            database_binding,
            payment,
            0,
            audit_head,
            None,
        )

    @staticmethod
    def _normalized_direct_state_row(
        row: tuple[object, ...],
    ) -> tuple[object, ...]:
        return tuple(
            value if value is None or type(value) is int else bytes(value)
            for value in row
        )

    def _validate_direct_state_current(
        self,
        connection: sqlite3.Connection,
        direct_state: DirectClearanceStateSnapshotV1,
        direct_count: int,
    ) -> None:
        state = connection.execute(
            "SELECT epoch, sequence, strong_nullifier_root, strong_payment_state_root, "
            "state_binding, audit_head, governance_commitment, anti_rollback_epoch, "
            "settled_batch_count FROM state WHERE id=1"
        ).fetchone()
        if state is None:
            raise ProductionBoundaryError("database_state_missing")
        self._validate_state_row(state)
        if direct_count == 0:
            expected = self._direct_clearance_genesis_row(connection)
            observed = connection.execute(
                "SELECT * FROM direct_clearance_state WHERE id=1"
            ).fetchone()
            if observed is None or self._normalized_direct_state_row(observed) != expected:
                raise ProductionBoundaryError("database_direct_clearance_state_mismatch")
            return
        transition = connection.execute(
            "SELECT transition_kind FROM transition_records WHERE sequence_after=?",
            (state[1],),
        ).fetchone()
        if transition is None or transition[0] != _DIRECT_TRANSITION_KIND:
            raise ProductionBoundaryError("database_direct_transition_kind_invalid")
        latest = self._latest_operation_digest(connection, state[7])
        if (
            direct_state.epoch != state[0]
            or direct_state.sequence != state[1]
            or direct_state.clearance_count != direct_count
            or direct_state.database_state_binding != bytes(state[4])
            or direct_state.payment_root != bytes(state[3])
            or direct_state.settled_batch_count != state[8]
            or direct_state.audit_head != bytes(state[5])
            or direct_state.last_operation_digest != latest
        ):
            raise ProductionBoundaryError("database_direct_clearance_state_mismatch")

    def _ensure_direct_clearance_state(
        self,
        connection: sqlite3.Connection,
    ) -> None:
        self._validate_direct_table_shapes(connection)
        direct_count = connection.execute(
            "SELECT COUNT(*) FROM direct_clearance_requests"
        ).fetchone()[0]
        state_count = connection.execute(
            "SELECT COUNT(*) FROM direct_clearance_state"
        ).fetchone()[0]
        if state_count > 1:
            raise ProductionBoundaryError("database_direct_clearance_state_multiplicity")
        expected = self._direct_clearance_genesis_row(connection)
        observed = connection.execute(
            "SELECT * FROM direct_clearance_state WHERE id=1"
        ).fetchone()
        if observed is None:
            if direct_count:
                raise ProductionBoundaryError("database_direct_clearance_state_missing")
            connection.execute(
                "INSERT INTO direct_clearance_state VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                tuple(
                    value if type(value) is int or value is None else sqlite3.Binary(value)
                    for value in expected
                ),
            )
            return
        normalized = self._normalized_direct_state_row(observed)
        direct_state = _direct_clearance_state_from_row(normalized)
        if direct_count == 0:
            if normalized != expected:
                raise ProductionBoundaryError("database_direct_clearance_state_mismatch")
            return
        self._validate_direct_state_current(connection, direct_state, direct_count)

    def _validate_direct_clearance_state(
        self,
        connection: sqlite3.Connection,
    ) -> tuple[int, DirectClearanceStateSnapshotV1]:
        self._validate_direct_table_shapes(connection)
        direct_count = connection.execute(
            "SELECT COUNT(*) FROM direct_clearance_requests"
        ).fetchone()[0]
        rows = connection.execute(
            "SELECT * FROM direct_clearance_state WHERE id=1"
        ).fetchall()
        if len(rows) != 1:
            raise ProductionBoundaryError("database_direct_clearance_state_missing")
        normalized = self._normalized_direct_state_row(rows[0])
        snapshot = _direct_clearance_state_from_row(normalized)
        if direct_count == 0:
            if normalized != self._direct_clearance_genesis_row(connection):
                raise ProductionBoundaryError("database_direct_clearance_state_mismatch")
        else:
            self._validate_direct_state_current(connection, snapshot, direct_count)
        return direct_count, snapshot

    def _ensure_genesis_and_direct_ledger(
        self,
        connection: sqlite3.Connection,
        config: tuple[object, ...],
        state: tuple[object, ...],
    ) -> None:
        del state
        if len(config) != 7:
            raise ProductionBoundaryError("database_configuration_shape_invalid")
        normalized = tuple(
            bytes(value) if isinstance(value, (bytes, bytearray)) else value
            for value in config
        )
        (
            domain_commitment,
            governance,
            profile,
            suite,
            schema,
            verifier,
            epoch,
        ) = normalized
        domain_commitment = _wide("database_genesis_domain", domain_commitment)
        governance = _wide("database_genesis_governance", governance)
        profile = _wide("database_genesis_profile", profile)
        suite = _wide("database_genesis_suite", suite)
        schema = _wide("database_genesis_schema", schema)
        verifier = _wide("database_genesis_verifier", verifier)
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
            governance_authority=self._governance_authority,
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
            observed_normalized = tuple(
                value if type(value) is int else bytes(value)
                for value in observed
            )
            if observed_normalized != expected:
                raise ProductionBoundaryError("database_genesis_identity_mismatch")

        transition_count = connection.execute(
            "SELECT COUNT(*) FROM transition_records"
        ).fetchone()[0]
        direct_count = connection.execute(
            "SELECT COUNT(*) FROM direct_clearance_requests"
        ).fetchone()[0]
        audit_count = connection.execute(
            "SELECT COUNT(*) FROM audit_events"
        ).fetchone()[0]
        if (
            transition_count != direct_count
            or audit_count != direct_count
        ):
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
                self._validate_schema_surface(connection)
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
                self._ensure_genesis_and_direct_ledger(connection, config, state)
                self._ensure_direct_clearance_state(connection)
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
                schema_version INTEGER NOT NULL CHECK (schema_version = 4)
            );
            INSERT OR IGNORE INTO metadata(id, schema_version) VALUES (1, 4);
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
            CREATE TABLE IF NOT EXISTS direct_clearance_state (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                schema_version INTEGER NOT NULL CHECK (schema_version = 1),
                epoch INTEGER NOT NULL CHECK (epoch > 0),
                sequence INTEGER NOT NULL CHECK (sequence >= 0),
                clearance_root BLOB NOT NULL CHECK (length(clearance_root) = 64),
                direct_clearance_count INTEGER NOT NULL CHECK (direct_clearance_count >= 0),
                state_binding BLOB NOT NULL CHECK (length(state_binding) = 64),
                database_state_binding BLOB NOT NULL CHECK (length(database_state_binding) = 64),
                payment_root BLOB NOT NULL CHECK (length(payment_root) = 64),
                settled_batch_count INTEGER NOT NULL CHECK (settled_batch_count >= 0),
                audit_head BLOB NOT NULL CHECK (length(audit_head) = 64),
                last_operation_digest BLOB CHECK (last_operation_digest IS NULL OR length(last_operation_digest) = 64)
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
                clearance_advanced INTEGER NOT NULL CHECK (clearance_advanced IN (0, 1)),
                clearance_root_before BLOB NOT NULL CHECK (length(clearance_root_before) = 64),
                clearance_root_after BLOB NOT NULL CHECK (length(clearance_root_after) = 64),
                direct_clearance_count_before INTEGER NOT NULL CHECK (direct_clearance_count_before >= 0),
                direct_clearance_count_after INTEGER NOT NULL CHECK (direct_clearance_count_after = direct_clearance_count_before + 1),
                direct_state_binding_after BLOB NOT NULL CHECK (length(direct_state_binding_after) = 64),
                settled_batch_count_before INTEGER NOT NULL CHECK (settled_batch_count_before >= 0),
                settled_batch_count_after INTEGER NOT NULL CHECK (settled_batch_count_after = settled_batch_count_before)
            );
            CREATE TRIGGER IF NOT EXISTS direct_clearance_requests_no_update
            BEFORE UPDATE ON direct_clearance_requests
            BEGIN SELECT RAISE(ABORT, 'direct_clearance_requests_append_only'); END;
            CREATE TRIGGER IF NOT EXISTS direct_clearance_requests_no_delete
            BEFORE DELETE ON direct_clearance_requests
            BEGIN SELECT RAISE(ABORT, 'direct_clearance_requests_append_only'); END;
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
            CREATE TABLE IF NOT EXISTS transition_records (
                sequence_after INTEGER PRIMARY KEY CHECK (sequence_after > 0),
                transition_kind TEXT NOT NULL CHECK (transition_kind = 'DIRECT_CLEARANCE'),
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

    @staticmethod
    def _validate_schema_surface(connection: sqlite3.Connection) -> None:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
        }
        if tables != _SCHEMA_TABLES:
            raise ProductionBoundaryError("database_schema_surface_invalid")

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

    def direct_clearance_snapshot(self) -> DirectClearanceStateSnapshotV1:
        """Read the independently bound direct-clearance state snapshot."""

        with closing(self._connect()) as connection:
            self._validate_direct_clearance_state(connection)
            row = connection.execute(
                "SELECT * FROM direct_clearance_state WHERE id=1"
            ).fetchone()
        if row is None:
            raise ProductionBoundaryError("database_direct_clearance_state_missing")
        return _direct_clearance_state_from_row(
            self._normalized_direct_state_row(row)
        )

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

    def _commit_direct_state_owned(
        self,
        prepare_operation: Callable[
            [DirectStateOwnedCommitContextV1], DirectStateOwnedOperationV1
        ],
        *,
        retry_lookup_ids: tuple[tuple[str, bytes], ...],
    ) -> tuple[DirectStateOwnedDatabaseReceiptV1, DirectStateOwnedOperationV1]:
        """Evaluate and commit one direct clearance under the same write lock."""

        if not callable(prepare_operation):
            raise ProductionBoundaryError("database_direct_prepare_required")
        if type(retry_lookup_ids) is not tuple or not retry_lookup_ids:
            raise ProductionBoundaryError("database_direct_retry_lookup_required")
        allowed_retry_columns = {"bundle_id", "attempt_id"}
        if any(
            type(item) is not tuple
            or len(item) != 2
            or type(item[0]) is not str
            or item[0] not in allowed_retry_columns
            or type(item[1]) is not bytes
            or len(item[1]) != 64
            or not any(item[1])
            for item in retry_lookup_ids
        ):
            raise ProductionBoundaryError("database_direct_retry_lookup_invalid")
        retry_lookup_ids = tuple(dict.fromkeys(retry_lookup_ids))
        if (
            len(retry_lookup_ids) != 2
            or {column for column, _ in retry_lookup_ids} != allowed_retry_columns
        ):
            raise ProductionBoundaryError("database_direct_retry_lookup_invalid")
        next_binding: bytes | None = None
        next_anti_epoch: int | None = None
        operation: DirectStateOwnedOperationV1 | None = None
        operation_digest: bytes | None = None
        receipt: DirectStateOwnedDatabaseReceiptV1 | None = None
        with closing(self._connect()) as connection:
            began = False
            try:
                connection.execute("BEGIN IMMEDIATE")
                began = True
                self._validate_schema_version(connection)
                self._validate_schema_surface(connection)
                self._validate_direct_table_shapes(connection)
                direct_count = connection.execute(
                    "SELECT COUNT(*) FROM direct_clearance_requests"
                ).fetchone()[0]
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
                direct_state_row = connection.execute(
                    "SELECT * FROM direct_clearance_state WHERE id=1"
                ).fetchone()
                if direct_state_row is None:
                    raise ProductionBoundaryError("database_direct_clearance_state_missing")
                direct_state = _direct_clearance_state_from_row(
                    self._normalized_direct_state_row(direct_state_row)
                )
                self._validate_direct_state_current(
                    connection,
                    direct_state,
                    direct_count,
                )
                if direct_count == 0:
                    continuity_sequence = 0
                    continuity_row_count = 0
                    continuity_audit_head = _direct_continuity_sha(
                        _DIRECT_CONTINUITY_AUDIT_HEAD_DOMAIN,
                        b"empty",
                    )
                    continuity_root = _direct_continuity_sha(
                        _DIRECT_CONTINUITY_ROOT_DOMAIN,
                        b"empty",
                    )
                    continuity_state_id = _direct_continuity_state_id(
                        profile_id=self._profile_id,
                        mode_id=self._direct_mode_id,
                        sequence=continuity_sequence,
                        row_count=continuity_row_count,
                        audit_head=continuity_audit_head,
                        continuity_root=continuity_root,
                    )
                else:
                    continuity_row = connection.execute(
                        "SELECT continuity_sequence_after, continuity_after_state_id, "
                        "continuity_after_audit_head, continuity_after_root "
                        "FROM direct_clearance_requests WHERE sequence_after=?",
                        (row[1],),
                    ).fetchone()
                    if continuity_row is None:
                        raise ProductionBoundaryError("database_direct_continuity_head_missing")
                    continuity_sequence = continuity_row[0]
                    continuity_row_count = direct_count
                    continuity_state_id = bytes(continuity_row[1])
                    continuity_audit_head = bytes(continuity_row[2])
                    continuity_root = bytes(continuity_row[3])
                    expected_continuity_id = _direct_continuity_state_id(
                        profile_id=self._profile_id,
                        mode_id=self._direct_mode_id,
                        sequence=continuity_sequence,
                        row_count=continuity_row_count,
                        audit_head=continuity_audit_head,
                        continuity_root=continuity_root,
                    )
                    if (
                        continuity_sequence != row[1]
                        or continuity_state_id != expected_continuity_id
                    ):
                        raise ProductionBoundaryError("database_direct_continuity_head_invalid")

                lookup_sql = " OR ".join(
                    f"{column}=?" for column, _ in retry_lookup_ids
                )
                prior_rows = connection.execute(
                    "SELECT * FROM direct_clearance_requests WHERE " + lookup_sql,
                    tuple(sqlite3.Binary(value) for _, value in retry_lookup_ids),
                ).fetchall()
                if len(prior_rows) > 1:
                    raise ProductionBoundaryError("database_direct_conflicting_retry")
                prior_operation: DirectStateOwnedOperationV1 | None = None
                prior_operation_digest: bytes | None = None
                if prior_rows:
                    prior_row = tuple(
                        value if type(value) is int else bytes(value)
                        for value in prior_rows[0]
                    )
                    if len(prior_row) != 48:
                        raise ProductionBoundaryError("database_direct_operation_record_shape_invalid")
                    prior_operation = _direct_operation_from_record(prior_row[:41])
                    prior_operation_digest = prior_row[0]  # type: ignore[assignment]
                    if (
                        prior_operation.bundle_id
                        != dict(retry_lookup_ids)["bundle_id"]
                        or prior_operation.attempt_id
                        != dict(retry_lookup_ids)["attempt_id"]
                    ):
                        raise ProductionBoundaryError("database_direct_conflicting_retry")
                context = DirectStateOwnedCommitContextV1(
                    epoch=row[0],  # type: ignore[arg-type]
                    global_sequence=row[1],  # type: ignore[arg-type]
                    anti_rollback_epoch=row[7],  # type: ignore[arg-type]
                    global_state_binding=bytes(row[4]),
                    global_audit_head=bytes(row[5]),
                    nullifier_root=bytes(row[2]),
                    payment_root=bytes(row[3]),
                    global_settled_batch_count=row[8],  # type: ignore[arg-type]
                    governance_commitment=bytes(row[6]),
                    direct_count=direct_count,
                    direct_state=direct_state,
                    continuity_sequence=continuity_sequence,
                    continuity_row_count=continuity_row_count,
                    continuity_state_id=continuity_state_id,
                    continuity_audit_head=continuity_audit_head,
                    continuity_root=continuity_root,
                    prior_operation_digest=prior_operation_digest,
                    prior_operation=prior_operation,
                )
                prepared = prepare_operation(context)
                if type(prepared) is not DirectStateOwnedOperationV1:
                    raise ProductionBoundaryError("database_direct_prepare_result_invalid")
                operation = self._seal_direct_state_owned(prepared)
                operation_digest = self._validate_direct_operation(operation)
                if operation is None or operation_digest is None:
                    raise ProductionBoundaryError("database_direct_operation_missing")
                operation_values = _direct_operation_record_values(operation)
                if context.prior_operation is None and operation.clearance_advanced is None:
                    raise ProductionBoundaryError("database_direct_legacy_operation_not_new")
                pending_anchor = self._reconcile_anti_rollback_state(
                    epoch=row[7],  # type: ignore[arg-type]
                    state_binding=bytes(row[4]),
                    transition_commitment=self._latest_operation_digest(
                        connection,
                        row[7],  # type: ignore[arg-type]
                    ),
                )
                existing = connection.execute(
                    "SELECT * "
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
                    if (
                        len(observed) != 48
                        or observed[0] != operation_digest
                        or observed[1:32] != operation_values
                        or observed[40]
                        != int(_direct_operation_clearance_advanced(operation))
                    ):
                        raise ProductionBoundaryError(
                            "database_direct_conflicting_retry"
                        )
                    receipt_row = connection.execute(
                        "SELECT operation_digest, bundle_id, receipt_id, decision_id, join_id, "
                        "sequence_before, sequence_after, nullifier_root_before, "
                        "nullifier_root_after, clearance_root_before, clearance_root_after, "
                        "direct_clearance_count_before, direct_clearance_count_after, "
                        "payment_root_before, payment_root_after, "
                        "settled_batch_count_before, settled_batch_count_after, "
                        "state_binding_after, audit_head_after, effective_directive, "
                        "clearance_advanced FROM direct_clearance_requests "
                        "WHERE operation_digest=?",
                        (sqlite3.Binary(operation_digest),),
                    ).fetchone()
                    if receipt_row is None:
                        raise ProductionBoundaryError("database_direct_receipt_missing")
                    receipt = _direct_receipt_from_row(receipt_row)
                    if (
                        receipt.operation_digest != operation_digest
                        or receipt.bundle_id != operation.bundle_id
                        or receipt.receipt_id != operation.receipt_id
                        or receipt.decision_id != operation.decision_id
                        or receipt.join_id != operation.join_id
                        or receipt.sequence_before != operation.continuity_sequence_before
                        or receipt.sequence_after != operation.continuity_sequence_after
                        or receipt.nullifier_root_before != bytes(existing[0][34])
                        or receipt.nullifier_root_after != bytes(existing[0][35])
                        or receipt.effective_directive != operation.effective_directive
                        or receipt.clearance_advanced
                        != _direct_operation_clearance_advanced(operation)
                        or receipt.clearance_root_before != bytes(existing[0][41])
                        or receipt.clearance_root_after != bytes(existing[0][42])
                        or receipt.clearance_count_before != existing[0][43]
                        or receipt.clearance_count_after != existing[0][44]
                        or receipt.payment_root_before != bytes(existing[0][36])
                        or receipt.payment_root_after != bytes(existing[0][37])
                        or receipt.settled_batch_count_before != existing[0][46]
                        or receipt.settled_batch_count_after != existing[0][47]
                        or receipt.state_binding != bytes(existing[0][38])
                        or receipt.audit_head != bytes(existing[0][39])
                    ):
                        raise ProductionBoundaryError(
                            "database_direct_retry_receipt_mismatch"
                        )
                    connection.execute("COMMIT")
                    began = False
                    return receipt, operation

                if (
                    row[1] >= (2**63 - 1)
                    or row[7] >= (2**63 - 1)
                    or row[1] != operation.continuity_sequence_before
                    or direct_state.sequence != row[1]
                    or direct_count != row[1]
                    or direct_state.clearance_count != direct_count
                    or operation.continuity_sequence_after != row[1] + 1
                ):
                    raise ProductionBoundaryError("database_direct_sequence_stale")
                nullifier_before = bytes(row[2])
                payment_before = bytes(row[3])
                clearance_before = direct_state.clearance_root
                clearance_count_before = direct_state.clearance_count
                settled_batch_count_before = row[8]
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
                clearance_advanced = _direct_operation_clearance_advanced(operation)
                clearance_after = (
                    _digest(
                        _DIRECT_CLEARANCE_ROOT_DOMAIN,
                        clearance_before,
                        operation.continuity_after_state_id,
                        operation.decision_id,
                        bytes((operation.effective_directive,)),
                    )
                    if clearance_advanced
                    else clearance_before
                )
                clearance_count_after = clearance_count_before + 1
                settled_batch_count_after = settled_batch_count_before
                previous_binding = bytes(row[4])
                direct_state_binding_after = _direct_clearance_state_binding(
                    previous_binding=direct_state.state_binding,
                    previous_database_binding=previous_binding,
                    operation_digest=operation_digest,
                    epoch=self._epoch,
                    sequence=row[1] + 1,  # type: ignore[operator]
                    clearance_root=clearance_after,
                    clearance_count=clearance_count_after,
                    payment_root=payment_before,
                    settled_batch_count=settled_batch_count_after,
                    governance_commitment=self._governance_authority.commitment_512,
                )
                next_binding = _direct_database_state_binding(
                    previous_database_binding=previous_binding,
                    direct_state_binding=direct_state_binding_after,
                    operation=operation,
                    operation_digest=operation_digest,
                    sequence=row[1] + 1,  # type: ignore[operator]
                    nullifier_after=nullifier_after,
                    payment_root_after=payment_before,
                    settled_batch_count_after=settled_batch_count_after,
                    clearance_root_after=clearance_after,
                    clearance_count_after=clearance_count_after,
                    governance_commitment=self._governance_authority.commitment_512,
                )
                event_payload = _direct_audit_payload(
                    operation=operation,
                    operation_digest=operation_digest,
                    sequence_before=row[1],  # type: ignore[arg-type]
                    sequence_after=row[1] + 1,  # type: ignore[operator]
                    nullifier_before=nullifier_before,
                    nullifier_after=nullifier_after,
                    payment_before=payment_before,
                    payment_after=payment_before,
                    clearance_before=clearance_before,
                    clearance_after=clearance_after,
                    clearance_count_before=clearance_count_before,
                    clearance_count_after=clearance_count_after,
                    direct_state_binding=direct_state_binding_after,
                    settled_batch_count_before=settled_batch_count_before,
                    settled_batch_count_after=settled_batch_count_after,
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
                    payment_before,
                    next_binding,
                    next_audit_head,
                    int(clearance_advanced),
                    clearance_before,
                    clearance_after,
                    clearance_count_before,
                    clearance_count_after,
                    direct_state_binding_after,
                    settled_batch_count_before,
                    settled_batch_count_after,
                )
                connection.execute(
                    "INSERT INTO direct_clearance_requests VALUES ("
                    + ", ".join("?" for _ in range(48))
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
                    strong_payment_state_root=payment_before,
                    state_binding=next_binding,
                    audit_head=next_audit_head,
                    anti_rollback_epoch=next_anti_epoch,
                    settled_batch_count=settled_batch_count_after,
                )
                connection.execute(
                    "INSERT INTO transition_records VALUES "
                    "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        row[1] + 1,
                        _DIRECT_TRANSITION_KIND,
                        sqlite3.Binary(operation_digest),
                        sqlite3.Binary(previous_binding),
                        sqlite3.Binary(next_binding),
                        sqlite3.Binary(nullifier_before),
                        sqlite3.Binary(nullifier_after),
                        sqlite3.Binary(payment_before),
                        sqlite3.Binary(payment_before),
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
                    "state_binding=?, audit_head=?, anti_rollback_epoch=? WHERE id=1",
                    (
                        row[1] + 1,
                        sqlite3.Binary(nullifier_after),
                        sqlite3.Binary(next_binding),
                        sqlite3.Binary(next_audit_head),
                        next_anti_epoch,
                    ),
                )
                connection.execute(
                    "UPDATE direct_clearance_state SET epoch=?, sequence=?, "
                    "clearance_root=?, direct_clearance_count=?, state_binding=?, "
                    "database_state_binding=?, payment_root=?, settled_batch_count=?, "
                    "audit_head=?, last_operation_digest=? WHERE id=1",
                    (
                        self._epoch,
                        row[1] + 1,
                        sqlite3.Binary(clearance_after),
                        clearance_count_after,
                        sqlite3.Binary(direct_state_binding_after),
                        sqlite3.Binary(next_binding),
                        sqlite3.Binary(payment_before),
                        settled_batch_count_after,
                        sqlite3.Binary(next_audit_head),
                        sqlite3.Binary(operation_digest),
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
                    clearance_root_before=clearance_before,
                    clearance_root_after=clearance_after,
                    clearance_count_before=clearance_count_before,
                    clearance_count_after=clearance_count_after,
                    payment_root_before=payment_before,
                    payment_root_after=payment_before,
                    settled_batch_count_before=settled_batch_count_before,
                    settled_batch_count_after=settled_batch_count_after,
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
        if receipt is None or operation is None:
            raise ProductionBoundaryError("database_direct_receipt_missing")
        return receipt, operation

    def _verify_integrity_single_epoch(self) -> None:
        with closing(self._connect()) as connection:
            result = connection.execute("PRAGMA integrity_check").fetchone()
            if result != ("ok",):
                raise ProductionBoundaryError("database_sqlite_integrity_failed")
            self._validate_schema_version(connection)
            self._validate_schema_surface(connection)
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
            direct_count, direct_state = self._validate_direct_clearance_state(connection)
            audit_count = connection.execute(
                "SELECT COUNT(*) FROM audit_events"
            ).fetchone()[0]
            if (
                direct_count != snapshot.sequence
                or audit_count != snapshot.sequence
            ):
                raise ProductionBoundaryError("database_direct_transition_count_mismatch")
            if snapshot.settled_batch_count != 0:
                raise ProductionBoundaryError("database_direct_settled_count_invalid")
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
            previous_clearance_root = self._initial_direct_clearance_root
            previous_clearance_count = 0
            previous_clearance_binding = _direct_clearance_genesis_binding(
                epoch=snapshot.epoch,
                database_state_binding=previous_binding,
                clearance_root=previous_clearance_root,
                payment_root=previous_payment,
                settled_batch_count=0,
                governance_commitment=snapshot.governance_commitment,
            )
            previous_settled_batch_count = 0
            previous_continuity: tuple[int, bytes, bytes, bytes] | None = None
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
                "audit_head_after, clearance_advanced, clearance_root_before, "
                "clearance_root_after, direct_clearance_count_before, "
                "direct_clearance_count_after, direct_state_binding_after, "
                "settled_batch_count_before, settled_batch_count_after "
                "FROM direct_clearance_requests ORDER BY sequence_after"
            )
            for raw_direct in direct_rows:
                direct = tuple(
                    value if type(value) is int else bytes(value)
                    for value in raw_direct
                )
                if (
                    len(direct) != 48
                    or type(direct[5]) is not bytes
                    or type(direct[7]) is not bytes
                    or type(direct[8]) is not bytes
                    or type(direct[11]) is not bytes
                    or type(direct[18]) is not int
                    or direct[18] not in (1, 2, 3, 4, 5)
                    or type(direct[25]) is not int
                    or not 0 < direct[25] <= 0xFFFF_FFFF
                    or type(direct[27]) is not bytes
                    or type(direct[28]) is not bytes
                    or type(direct[29]) is not bytes
                    or type(direct[30]) is not bytes
                    or type(direct[31]) is not bytes
                ):
                    raise ProductionBoundaryError(
                        "database_direct_continuity_transition_mismatch"
                    )
                # Recompute before row deserialization; do not certify via the producer helper.
                expected_continuity_after_audit = _direct_continuity_sha(
                    _DIRECT_CONTINUITY_AUDIT_HEAD_DOMAIN,
                    direct[28],
                    direct[5],
                    bytes((direct[18],)),
                )
                expected_continuity_after_root = _direct_continuity_sha(
                    _DIRECT_CONTINUITY_ROOT_DOMAIN,
                    direct[30],
                    direct[7],
                    direct[5],
                )
                continuity_context = _direct_continuity_sha(
                    _DIRECT_CONTINUITY_STATE_CONTEXT_DOMAIN,
                    direct[8],
                    direct[11],
                )
                continuity_after_state_material = b"".join(
                    (
                        _DIRECT_CONTINUITY_STATE_MAGIC,
                        _DIRECT_CONTINUITY_STATE_VERSION.to_bytes(2, "big"),
                        b"\0\0",
                        continuity_context,
                        direct[25].to_bytes(8, "big"),
                        direct[25].to_bytes(4, "big"),
                        b"\0" * 4,
                        expected_continuity_after_audit,
                        expected_continuity_after_root,
                    )
                )
                expected_continuity_after_state_id = _direct_continuity_sha(
                    _DIRECT_CONTINUITY_STATE_ID_DOMAIN,
                    continuity_after_state_material,
                )
                if (
                    direct[27] != expected_continuity_after_state_id
                    or direct[29] != expected_continuity_after_audit
                    or direct[31] != expected_continuity_after_root
                ):
                    raise ProductionBoundaryError(
                        "database_direct_continuity_transition_mismatch"
                    )
                direct_operation = _direct_operation_from_record(direct[:41])
                if previous_continuity is None:
                    empty_audit_head = _direct_continuity_sha(
                        _DIRECT_CONTINUITY_AUDIT_HEAD_DOMAIN,
                        b"empty",
                    )
                    empty_root = _direct_continuity_sha(
                        _DIRECT_CONTINUITY_ROOT_DOMAIN,
                        b"empty",
                    )
                    expected_continuity_before = (
                        0,
                        _direct_continuity_state_id(
                            profile_id=direct_operation.profile_id,
                            mode_id=direct_operation.mode_id,
                            sequence=0,
                            row_count=0,
                            audit_head=empty_audit_head,
                            continuity_root=empty_root,
                        ),
                        empty_audit_head,
                        empty_root,
                    )
                else:
                    expected_continuity_before = previous_continuity
                if (
                    (
                        direct_operation.continuity_sequence_before,
                        direct_operation.continuity_before_state_id,
                        direct_operation.continuity_before_audit_head,
                        direct_operation.continuity_before_root,
                    )
                    != expected_continuity_before
                    or direct_operation.continuity_sequence_after != expected_sequence
                ):
                    raise ProductionBoundaryError(
                        "database_direct_continuity_chain_broken"
                    )
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
                    or direct[40] != int(_direct_operation_clearance_advanced(direct_operation))
                    or direct[41] != previous_clearance_root
                    or direct[43] != previous_clearance_count
                    or direct[46] != previous_settled_batch_count
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
                expected_clearance = (
                    _digest(
                        _DIRECT_CLEARANCE_ROOT_DOMAIN,
                        previous_clearance_root,
                        direct_operation.continuity_after_state_id,
                        direct_operation.decision_id,
                        bytes((direct_operation.effective_directive,)),
                    )
                    if _direct_operation_clearance_advanced(direct_operation)
                    else previous_clearance_root
                )
                expected_clearance_count = previous_clearance_count + 1
                expected_settled_batch_count = previous_settled_batch_count
                expected_direct_binding = _direct_clearance_state_binding(
                    previous_binding=previous_clearance_binding,
                    previous_database_binding=previous_binding,
                    operation_digest=operation_digest,
                    epoch=snapshot.epoch,
                    sequence=expected_sequence,
                    clearance_root=expected_clearance,
                    clearance_count=expected_clearance_count,
                    payment_root=previous_payment,
                    settled_batch_count=expected_settled_batch_count,
                    governance_commitment=snapshot.governance_commitment,
                )
                expected_binding = _direct_database_state_binding(
                    previous_database_binding=previous_binding,
                    direct_state_binding=expected_direct_binding,
                    operation=direct_operation,
                    operation_digest=operation_digest,
                    sequence=expected_sequence,
                    nullifier_after=expected_nullifier,
                    payment_root_after=previous_payment,
                    settled_batch_count_after=expected_settled_batch_count,
                    clearance_root_after=expected_clearance,
                    clearance_count_after=expected_clearance_count,
                    governance_commitment=snapshot.governance_commitment,
                )
                if (
                    direct[35] != expected_nullifier
                    or direct[37] != previous_payment
                    or direct[42] != expected_clearance
                    or direct[44] != expected_clearance_count
                    or direct[45] != expected_direct_binding
                    or direct[47] != expected_settled_batch_count
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
                        payment_after=previous_payment,
                        clearance_before=previous_clearance_root,
                        clearance_after=direct[42],  # type: ignore[arg-type]
                        clearance_count_before=previous_clearance_count,
                        clearance_count_after=direct[44],  # type: ignore[arg-type]
                        direct_state_binding=direct[45],  # type: ignore[arg-type]
                        settled_batch_count_before=previous_settled_batch_count,
                        settled_batch_count_after=direct[47],  # type: ignore[arg-type]
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
                transition_kind = connection.execute(
                    "SELECT transition_kind FROM transition_records "
                    "WHERE record_commitment=?",
                    (sqlite3.Binary(operation_digest),),
                ).fetchone()
                if transition_kind is None or transition_kind[0] != _DIRECT_TRANSITION_KIND:
                    raise ProductionBoundaryError("database_direct_transition_kind_invalid")
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
                    or transition[7] != previous_payment
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
                    strong_payment_state_root=previous_payment,
                    state_binding=direct[38],  # type: ignore[arg-type]
                    audit_head=direct[39],  # type: ignore[arg-type]
                    anti_rollback_epoch=expected_sequence,
                    settled_batch_count=previous_settled_batch_count,
                )
                if transition[20] != checkpoint.checkpoint_commitment:
                    raise ProductionBoundaryError("database_transition_checkpoint_invalid")
                previous_nullifier = direct[35]  # type: ignore[assignment]
                previous_payment = direct[37]  # type: ignore[assignment]
                previous_binding = direct[38]  # type: ignore[assignment]
                previous_clearance_root = direct[42]  # type: ignore[assignment]
                previous_clearance_count = direct[44]  # type: ignore[assignment]
                previous_clearance_binding = direct[45]  # type: ignore[assignment]
                previous_settled_batch_count = direct[47]  # type: ignore[assignment]
                previous_continuity = (
                    direct_operation.continuity_sequence_after,
                    direct_operation.continuity_after_state_id,
                    direct_operation.continuity_after_audit_head,
                    direct_operation.continuity_after_root,
                )
                expected_sequence += 1
            if (
                expected_sequence - 1 != snapshot.sequence
                or previous_nullifier != snapshot.strong_nullifier_root
                or previous_payment != snapshot.strong_payment_state_root
                or previous_binding != snapshot.state_binding
            ):
                raise ProductionBoundaryError("database_request_final_state_mismatch")
            if direct_count:
                if (
                    direct_state.sequence != snapshot.sequence
                    or direct_state.clearance_count != previous_clearance_count
                    or direct_state.clearance_root != previous_clearance_root
                    or direct_state.state_binding != previous_clearance_binding
                    or direct_state.database_state_binding != snapshot.state_binding
                    or direct_state.payment_root != snapshot.strong_payment_state_root
                    or direct_state.settled_batch_count != previous_settled_batch_count
                    or direct_state.audit_head != snapshot.audit_head
                    or direct_state.last_operation_digest
                    != self._latest_operation_digest(connection, snapshot.sequence)
                ):
                    raise ProductionBoundaryError(
                        "database_direct_clearance_state_mismatch"
                    )
            transition_commitment = self._latest_operation_digest(
                connection,
                snapshot.anti_rollback_epoch,
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
            if len(authority_rows) != 1:
                raise ProductionBoundaryError("database_governance_authority_missing")
            authority_row = authority_rows[0]
            if authority_row[0] != 0:
                raise ProductionBoundaryError("database_governance_authority_sequence_invalid")
            authority = _governance_authority_from_row(authority_row)
            if authority != self._governance_authority:
                raise ProductionBoundaryError("database_governance_authority_mismatch")
            genesis_governance = connection.execute(
                "SELECT governance_commitment FROM database_genesis WHERE id=1"
            ).fetchone()
            if (
                genesis_governance is None
                or authority.commitment_512 != bytes(genesis_governance[0])
            ):
                raise ProductionBoundaryError(
                    "database_genesis_governance_authority_mismatch"
                )
            direct_count = connection.execute(
                "SELECT COUNT(*) FROM direct_clearance_requests"
            ).fetchone()[0]
            transition_count = connection.execute(
                "SELECT COUNT(*) FROM transition_records"
            ).fetchone()[0]
            audit_count = connection.execute(
                "SELECT COUNT(*) FROM audit_events"
            ).fetchone()[0]
        if transition_count != direct_count or audit_count != direct_count:
            raise ProductionBoundaryError("database_direct_transition_count_mismatch")
        self._verify_integrity_single_epoch()

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
                initial_direct_clearance_root=self._initial_direct_clearance_root,
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
                initial_direct_clearance_root=self._initial_direct_clearance_root,
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
        self._direct_authority_key = None
        self._direct_mode_id = None
        self._direct_evaluator_id = None
        self._direct_control_set_id = None
        self._direct_rule_id = None
        self._direct_phase0_receipt_binding = None
        self._closed = True




__all__ = (
    "AntiRollbackAnchorSnapshot",
    "AntiRollbackReference",
    "InMemoryAntiRollbackReference",
    "PendingAntiRollbackTransition",
    "SQLiteSettlementStoreV2",
)
