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
from experiments.bl_pq512_crypto_foundation.production_candidate import (
    PROOF_PACKAGE_COMMITMENT_DOMAIN,
    TRANSCRIPT_COMMITMENT_DOMAIN,
    NativeVerificationReceipt,
    statement_commitment,
)


_SCHEMA_VERSION: Final[int] = 1
_AUDIT_GENESIS_DOMAIN = b"BL/PQ512/V2/DATABASE-AUDIT-GENESIS/v1\x00"
_AUDIT_EVENT_DOMAIN = b"BL/PQ512/V2/DATABASE-AUDIT-EVENT/v1\x00"
_AUDIT_HEAD_DOMAIN = b"BL/PQ512/V2/DATABASE-AUDIT-HEAD/v1\x00"
_OPERATION_DIGEST_DOMAIN = b"BL/PQ512/V2/DATABASE-OPERATION/v1\x00"
_DOMAIN_COMMITMENT_DOMAIN = b"BL/PQ512/V2/DATABASE-DOMAIN/v1\x00"
_SUBMITTER_AUDIT_DOMAIN = b"BL/PQ512/V2/DATABASE-SUBMITTER-AUDIT/v1\x00"
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
            "SELECT operation_digest FROM settlement_requests WHERE sequence_after=?",
            (epoch,),
        ).fetchone()
        if row is None:
            raise ProductionBoundaryError("database_latest_operation_missing")
        return _wide("database_latest_operation_digest", bytes(row[0]))

    def _initialize(self) -> None:
        with closing(self._connect()) as connection:
            began = False
            try:
                connection.execute("PRAGMA journal_mode=WAL")
                self._create_schema(connection)
                connection.execute("BEGIN IMMEDIATE")
                began = True
                self._validate_schema_version(connection)
                config = connection.execute(
                    "SELECT settlement_domain_commitment, governance_commitment, profile_id, "
                    "suite_id, schema_id, verifier_artifact_identity, epoch "
                    "FROM configuration WHERE id=1"
                ).fetchone()
                if config is None:
                    connection.execute(
                        "INSERT INTO configuration VALUES (1, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            sqlite3.Binary(_digest(_DOMAIN_COMMITMENT_DOMAIN, self._settlement_domain)),
                            sqlite3.Binary(self._governed_roots.commitment_512),
                            sqlite3.Binary(self._profile_id),
                            sqlite3.Binary(self._suite_id),
                            sqlite3.Binary(self._schema_id),
                            sqlite3.Binary(self._verifier_artifact_identity),
                            self._epoch,
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
                schema_version INTEGER NOT NULL CHECK (schema_version = 1)
            );
            INSERT OR IGNORE INTO metadata(id, schema_version) VALUES (1, 1);
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
        if type(count) is not int or count < 0 or count != sequence:
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
                        parsed.sequence_after,
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

    def verify_integrity(self) -> None:
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
