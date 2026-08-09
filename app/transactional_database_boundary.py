"""Qualification-only transactional database boundary for Privacy V2.

This module deliberately implements a local SQLite reference, not a production
database selection.  The native verifier remains the authority for proof
acceptance; this module only proves the durable all-or-nothing state seam that
follows it.  No network, Ethereum, PHI, payment connector, or activation
credential is opened here.
"""

from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import secrets
import sqlite3
from threading import RLock
from typing import Callable, Final, Protocol

from app.production_boundary import (
    DatabaseSettlementSnapshotV2,
    GovernedRootsV2,
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


_SCHEMA_VERSION: Final[int] = 2
_AUDIT_GENESIS_DOMAIN = b"BL/PQ512/V2/DATABASE-AUDIT-GENESIS/v1\x00"
_AUDIT_EVENT_DOMAIN = b"BL/PQ512/V2/DATABASE-AUDIT-EVENT/v1\x00"
_AUDIT_HEAD_DOMAIN = b"BL/PQ512/V2/DATABASE-AUDIT-HEAD/v1\x00"
_OPERATION_DIGEST_DOMAIN = b"BL/PQ512/V2/DATABASE-OPERATION/v1\x00"
_DOMAIN_COMMITMENT_DOMAIN = b"BL/PQ512/V2/DATABASE-DOMAIN/v1\x00"
_SUBMITTER_AUDIT_DOMAIN = b"BL/PQ512/V2/DATABASE-SUBMITTER-AUDIT/v1\x00"
_MIGRATION_AUDIT_EVENT_DOMAIN = b"BL/PQ512/V2/DATABASE-MIGRATION-AUDIT/v1\x00"
_MIGRATION_STATE_BINDING_DOMAIN = b"BL/PQ512/V2/DATABASE-MIGRATION-STATE/v1\x00"
_TRANSITION_RECORD_DOMAIN = b"BL/PQ512/V2/DATABASE-TRANSITION-RECORD/v1\x00"
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
        governed_roots: GovernedRootsV2,
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
        if type(governed_roots) is not GovernedRootsV2:
            raise TypeError("database_governed_roots_required")
        self._path = path
        self._settlement_domain = _field("database_settlement_domain", settlement_domain, nonzero=True)
        self._governed_roots = governed_roots
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
        if row != (1,):
            raise ProductionBoundaryError("database_schema_version_mismatch")
        # The v1 table constrained its only row to schema_version=1.  Rebuild
        # this one-row metadata table inside the same initialization
        # transaction; no state or audit bytes are rewritten.
        connection.execute("ALTER TABLE metadata RENAME TO metadata_v1")
        connection.execute(
            "CREATE TABLE metadata ("
            "id INTEGER PRIMARY KEY CHECK (id = 1), "
            "schema_version INTEGER NOT NULL CHECK (schema_version IN (1, 2)))"
        )
        connection.execute("INSERT INTO metadata VALUES (1, ?)", (_SCHEMA_VERSION,))
        connection.execute("DROP TABLE metadata_v1")

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
            if (
                governance != self._governed_roots.commitment_512
                or genesis_nullifier != self._initial_nullifier_root
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
        elif transition_count != request_count + migration_count:
            raise ProductionBoundaryError("database_transition_ledger_count_mismatch")

    def _initialize(self) -> None:
        with closing(self._connect()) as connection:
            began = False
            try:
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
                        self._governed_roots.commitment_512,
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
                        self._governed_roots.commitment_512,
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
                            sqlite3.Binary(self._governed_roots.commitment_512),
                        ),
                    )
                    state = (
                        self._epoch,
                        0,
                        self._initial_nullifier_root,
                        self._initial_payment_root,
                        state_binding,
                        audit_head,
                        self._governed_roots.commitment_512,
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
                schema_version INTEGER NOT NULL CHECK (schema_version IN (1, 2))
            );
            INSERT OR IGNORE INTO metadata(id, schema_version) VALUES (1, 2);
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
            self._governed_roots.commitment_512,
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
        if operation.profile_id != self._profile_id:
            raise ProductionBoundaryError("database_profile_identity_mismatch")
        if (
            operation.suite_id != self._suite_id
            or operation.schema_id != self._schema_id
            or operation.verifier_artifact_identity != self._verifier_artifact_identity
        ):
            raise ProductionBoundaryError("database_verifier_identity_mismatch")
        if operation.epoch != self._epoch:
            raise ProductionBoundaryError("database_epoch_mismatch")
        if operation.strong_governance_commitment != self._governed_roots.commitment_512:
            raise ProductionBoundaryError("database_governance_root_mismatch")
        if operation.public_fields_commitment != public_fields_commitment(operation.public_fields):
            raise ProductionBoundaryError("database_public_fields_commitment_mismatch")
        parsed = _sidecar(operation.sidecar)
        validate_v2_public_projection(
            public_fields=operation.public_fields,
            sidecar=operation.sidecar,
            settlement_domain=self._settlement_domain,
            batch_nonce=operation.batch_nonce,
            governed_roots=self._governed_roots,
            suite_id=operation.suite_id,
            schema_id=operation.schema_id,
            verifier_artifact_identity=operation.verifier_artifact_identity,
        )
        return parsed

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
            connection.execute("COMMIT")
        if config is None or state is None:
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
                "SELECT settlement_domain_before, governance_commitment, "
                "profile_before, suite_before, schema_before, verifier_before, "
                "epoch_before, sequence_before, nullifier_root_before, "
                "payment_root_before, state_binding_before "
                "FROM migration_requests WHERE source_checkpoint_commitment=? "
                "AND migration_evidence_commitment=?",
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
            connection.execute("COMMIT")
        if audit_row is None or type(settled_count) is not int:
            raise ProductionBoundaryError("database_migration_retry_source_invalid")
        identity = PrivacyV2DatabaseIdentity(
            settlement_domain_commitment=bytes(row[0]),
            governance_commitment=bytes(row[1]),
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
                operation_config = (
                    _digest(_DOMAIN_COMMITMENT_DOMAIN, self._settlement_domain),
                    operation.strong_governance_commitment,
                    operation.profile_id,
                    operation.suite_id,
                    operation.schema_id,
                    operation.verifier_artifact_identity,
                    operation.epoch,
                )
                normalized_config = tuple(
                    value if type(value) is int else bytes(value) for value in config
                )
                if normalized_config != operation_config:
                    raise ProductionBoundaryError(
                        "database_operation_configuration_stale"
                    )
                row = connection.execute(
                    "SELECT epoch, sequence, strong_nullifier_root, strong_payment_state_root, "
                    "state_binding, audit_head, governance_commitment, anti_rollback_epoch, "
                    "settled_batch_count FROM state WHERE id=1"
                ).fetchone()
                if row is None:
                    raise ProductionBoundaryError("database_state_missing")
                self._validate_state_row(row)
                if row[0] != self._epoch or bytes(row[6]) != self._governed_roots.commitment_512:
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
                        proof_suite_id=self._suite_id,
                        state_binding=normalized[15],  # type: ignore[arg-type]
                    )
                    connection.execute("COMMIT")
                    return receipt

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
                    governance_commitment=self._governed_roots.commitment_512,
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
                        sqlite3.Binary(self._governed_roots.commitment_512),
                        sqlite3.Binary(self._governed_roots.commitment_512),
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
            governed_roots=self._governed_roots,
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
                self._validate_state_row(state)
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
                    if (
                        receipt.kind != evidence.kind
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
                    if (
                        parsed.epoch != source.epoch + 1
                        or parsed.sequence_before != source.sequence
                        or parsed.sequence_after != source.sequence + 1
                        or parsed.strong_nullifier_root_before
                        != source.strong_nullifier_root
                        or parsed.strong_payment_state_root_before
                        != source.strong_payment_state_root
                        or parsed.strong_governance_commitment
                        != source.governance_commitment
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
                        if known != (
                            target.strong_nullifier_root_after,
                            target.strong_payment_state_root_after,
                            target.governance_commitment,
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
                or snapshot.governance_commitment != self._governed_roots.commitment_512
            ):
                raise ProductionBoundaryError("database_state_identity_mismatch")
            counts = (
                connection.execute("SELECT COUNT(*) FROM settlement_requests").fetchone()[0],
                connection.execute("SELECT COUNT(*) FROM settled_nullifier_roots").fetchone()[0],
                connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0],
            )
            if counts != (
                snapshot.settled_batch_count,
                snapshot.settled_batch_count,
                snapshot.settled_batch_count,
            ):
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
                decoded_payload = _audit_payload_from_json(payload)
                if (
                    decoded_payload["epoch"] != snapshot.epoch
                    or decoded_payload["sequence_before"] != sequence - 1
                    or decoded_payload["sequence_after"] != sequence
                    or decoded_payload["previous_audit_head"] != previous_head.hex()
                    or decoded_payload["governance_commitment"]
                    != snapshot.governance_commitment.hex()
                ):
                    raise ProductionBoundaryError("database_audit_payload_binding_mismatch")
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
                or current.governance_commitment
                != self._governed_roots.commitment_512
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
            migration_count = connection.execute(
                "SELECT COUNT(*) FROM migration_requests"
            ).fetchone()[0]
            transition_count = connection.execute(
                "SELECT COUNT(*) FROM transition_records"
            ).fetchone()[0]
            request_count = connection.execute(
                "SELECT COUNT(*) FROM settlement_requests"
            ).fetchone()[0]
        if transition_count != request_count + migration_count:
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
                governed_roots=self._governed_roots,
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
                governed_roots=self._governed_roots,
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
        self._closed = True


class TransactionalSettlementV2:
    """Native-verifier gate followed by one storage-port transition."""

    def __init__(
        self,
        *,
        verifier: object,
        storage: TransactionalSettlementStoragePort,
        settlement_domain: bytes,
        governed_roots: GovernedRootsV2,
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
                "identity_snapshot",
                "snapshot",
                "verify_integrity",
                "close",
            )
        ):
            raise TypeError("transactional_storage_port_required")
        if type(governed_roots) is not GovernedRootsV2:
            raise TypeError("transactional_governed_roots_required")
        self._verifier = verifier
        self._storage = storage
        self._settlement_domain = _field("transactional_settlement_domain", settlement_domain, nonzero=True)
        self._governed_roots = governed_roots
        self._authorized_submitters = frozenset(
            _wide("transactional_authorized_submitter", value) for value in authorized_submitters
        )
        if not self._authorized_submitters:
            raise ProductionBoundaryError("transactional_submitters_empty")
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
        identity = self._storage.identity_snapshot()
        if type(identity) is not PrivacyV2DatabaseIdentity:
            raise ProductionBoundaryError("transactional_database_identity_invalid")
        if (
            parsed.profile_id != identity.profile_id
            or envelope.suite_id != identity.suite_id
            or envelope.schema_id != identity.schema_id
            or envelope.verifier_artifact_identity
            != identity.verifier_artifact_identity
            or parsed.epoch != identity.epoch
            or parsed.strong_governance_commitment
            != identity.governance_commitment
        ):
            raise ProductionBoundaryError("transactional_active_identity_mismatch")
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
