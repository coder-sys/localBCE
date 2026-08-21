"""Durable application of independently verified queue receipts.

This module owns only the orchestration ledger between a terminal queue result
and the existing proof-bound clearance state store.  The queue owns proof
verification, the state store owns policy and state mutation, and this ledger
owns neither proof bytes nor payment authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from contextlib import closing
import hashlib
import json
from pathlib import Path
import re
import secrets
import sqlite3
from typing import Any, Callable, Final, Mapping, Protocol

from app.minimal_clearance_proof_state import (
    MinimalClearanceIndeterminateError,
    MinimalClearanceReceiptV1,
    MinimalClearanceStateStoreV1,
    MinimalProofAcceptanceV1,
    parse_acceptance_bytes,
)
from app.minimal_clearance_queue_application_independent import (
    IndependentQueueApplicationError,
    read_application_job,
)


class QueueApplicationError(RuntimeError):
    """Bounded orchestration failure."""


class QueueApplicationConflictError(QueueApplicationError):
    pass


class QueueApplicationBackpressureError(QueueApplicationError):
    pass


class QueueApplicationLeaseError(QueueApplicationError):
    pass


class QueueApplicationIntegrityError(QueueApplicationError):
    pass


class QueueApplicationIndeterminateError(QueueApplicationError):
    pass


_SCHEMA_VERSION: Final[int] = 1
_SCHEMA: Final[str] = "BL/NATIVE-V3/MINIMAL-CLEARANCE-QUEUE-APPLICATION/v1"
_STATUS: Final[frozenset[str]] = frozenset({"DISCOVERED", "LEASED", "APPLIED", "HELD"})
_NONTERMINAL: Final[frozenset[str]] = frozenset({"DISCOVERED", "LEASED"})
_TOKEN = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
_MAX_ACCEPTANCE: Final[int] = 65_536
_MAX_RECEIPT: Final[int] = 16 * 1024
_MAX_EXPORT: Final[int] = 64 * 1024 * 1024
_CAP_BYTES: Final[int] = 5_000_000_000
_ACTIVE_PROCESS_LIMIT: Final[int] = 1
_APP_MATERIAL = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/APPLICATION/MATERIAL/v1\x00"
_APP_OPERATION = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/APPLICATION/OPERATION/v1\x00"
_APP_ACCEPTANCE = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/APPLICATION/ACCEPTANCE/v1\x00"
_APP_QUEUE_RECEIPT = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/APPLICATION/QUEUE-RECEIPT/v1\x00"
_APP_GENESIS = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/APPLICATION/GENESIS/v1\x00"
_APP_EVENT = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/APPLICATION/EVENT/v1\x00"
_APP_HEAD = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/APPLICATION/HEAD/v1\x00"
_APP_STATE_RECEIPT = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/APPLICATION/STATE-RECEIPT/v1\x00"


def _sha(domain: bytes, *parts: bytes) -> bytes:
    digest = hashlib.sha3_512()
    digest.update(domain)
    for part in parts:
        if type(part) is not bytes:
            raise QueueApplicationIntegrityError("application_binding_type")
        digest.update(part)
    return digest.digest()


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise QueueApplicationIntegrityError("application_json") from exc


def _hex(value: bytes) -> str:
    return value.hex().upper()


def _token(value: object, label: str) -> str:
    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        raise QueueApplicationError(f"{label}_invalid")
    return value


def _fixed_bytes(value: object, size: int, label: str) -> bytes:
    if type(value) is not bytes or len(value) != size:
        raise QueueApplicationIntegrityError(f"{label}_width")
    return bytes(value)


def _u64(value: int) -> bytes:
    if type(value) is not int or not 0 <= value < 2**64:
        raise QueueApplicationIntegrityError("application_integer")
    return value.to_bytes(8, "big")


@dataclass(frozen=True, slots=True)
class QueueApplicationConfigV1:
    application_id: str
    queue_id: str
    queue_config_digest: bytes
    verifier_sha256: bytes
    state_store_identity: bytes
    capacity: int = 16
    lease_seconds: int = 300
    max_attempts: int = 3
    busy_timeout_ms: int = 5_000
    proof_suite_id: None = None
    production_usable: bool = False
    activation: bool = False

    def __post_init__(self) -> None:
        _token(self.application_id, "application_id")
        _token(self.queue_id, "queue_id")
        _fixed_bytes(self.queue_config_digest, 64, "queue_config_digest")
        _fixed_bytes(self.verifier_sha256, 32, "verifier_sha256")
        _fixed_bytes(self.state_store_identity, 64, "state_store_identity")
        if type(self.capacity) is not int or not 1 <= self.capacity <= 10_000:
            raise QueueApplicationIntegrityError("application_capacity")
        if type(self.lease_seconds) is not int or not 1 <= self.lease_seconds <= 3_600:
            raise QueueApplicationIntegrityError("application_lease_seconds")
        if self.max_attempts != 3 or self.busy_timeout_ms != 5_000:
            raise QueueApplicationIntegrityError("application_fixed_config")
        if self.proof_suite_id is not None or self.production_usable is not False or self.activation is not False:
            raise QueueApplicationIntegrityError("application_nonactivation")

    def as_json(self) -> dict[str, Any]:
        return {
            "schema_version": _SCHEMA_VERSION,
            "application_id": self.application_id,
            "queue_id": self.queue_id,
            "queue_config_digest": _hex(self.queue_config_digest),
            "verifier_sha256": _hex(self.verifier_sha256),
            "state_store_identity": _hex(self.state_store_identity),
            "capacity": self.capacity,
            "lease_seconds": self.lease_seconds,
            "max_attempts": self.max_attempts,
            "busy_timeout_ms": self.busy_timeout_ms,
            "proof_suite_id": None,
            "production_usable": False,
            "activation": False,
        }

    @property
    def canonical_bytes(self) -> bytes:
        return _json_bytes(self.as_json())

    @property
    def digest(self) -> bytes:
        return _sha(_APP_MATERIAL, self.canonical_bytes)


@dataclass(frozen=True, slots=True)
class QueueApplicationJobV1:
    job_id: str
    operation_id: bytes
    status: str
    attempt: int
    queue_receipt_digest: bytes
    acceptance_digest: bytes


@dataclass(frozen=True, slots=True)
class QueueApplicationWorkV1:
    application_id: str
    job_id: str
    operation_id: bytes
    attempt: int
    worker_id: str
    lease_token: bytes
    lease_expires_ms: int
    acceptance_bytes: bytes
    queue_receipt_bytes: bytes


@dataclass(frozen=True, slots=True)
class QueueApplicationResultV1:
    job_id: str
    operation_id: bytes
    status: str
    state_receipt_bytes: bytes | None
    state_receipt_digest: bytes | None
    duplicate_convergence: bool
    error_code: str | None


class ApplicationClock(Protocol):
    def now_ms(self) -> int:
        """Return an injected monotonic application time."""


class _SystemClock:
    def now_ms(self) -> int:
        import time

        return int(time.time() * 1000)


class QueueApplicationStoreV1:
    """Producer-owned coordinator ledger with no proof verifier dependency."""

    def __init__(
        self,
        *,
        path: Path,
        config: QueueApplicationConfigV1,
        clock: ApplicationClock | None = None,
        before_fault: Callable[[str], None] | None = None,
        after_commit_fault: Callable[[str], None] | None = None,
    ) -> None:
        if not isinstance(path, Path) or path.exists() and path.is_symlink() or not path.parent.is_dir():
            raise QueueApplicationError("application_database_path")
        self.path = path
        self.config = config
        self.clock = clock or _SystemClock()
        self._before_fault = before_fault
        self._after_commit_fault = after_commit_fault
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=self.config.busy_timeout_ms / 1000, isolation_level=None)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(f"PRAGMA busy_timeout={self.config.busy_timeout_ms}")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def _initialize(self) -> None:
        with closing(self._connect()) as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS app_metadata (
                    id INTEGER PRIMARY KEY CHECK(id=1), schema_version INTEGER NOT NULL,
                    application_id TEXT NOT NULL, config_json BLOB NOT NULL, config_digest BLOB NOT NULL,
                    queue_id TEXT NOT NULL, queue_config_digest BLOB NOT NULL,
                    verifier_sha256 BLOB NOT NULL, state_store_identity BLOB NOT NULL,
                    head_root BLOB NOT NULL, next_sequence INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS app_jobs (
                    job_id TEXT PRIMARY KEY, operation_id BLOB NOT NULL UNIQUE,
                    queue_receipt_digest BLOB NOT NULL, acceptance_digest BLOB NOT NULL,
                    acceptance_bytes BLOB NOT NULL, queue_receipt_bytes BLOB NOT NULL,
                    status TEXT NOT NULL, admission_sequence INTEGER NOT NULL UNIQUE,
                    attempt INTEGER NOT NULL, next_eligible_ms INTEGER NOT NULL,
                    created_ms INTEGER NOT NULL, updated_ms INTEGER NOT NULL, last_error_code TEXT
                );
                CREATE TABLE IF NOT EXISTS app_leases (
                    job_id TEXT PRIMARY KEY, worker_id TEXT NOT NULL, token BLOB NOT NULL,
                    attempt INTEGER NOT NULL, leased_ms INTEGER NOT NULL, expires_ms INTEGER NOT NULL,
                    FOREIGN KEY(job_id) REFERENCES app_jobs(job_id)
                );
                CREATE TABLE IF NOT EXISTS app_results (
                    job_id TEXT PRIMARY KEY, status TEXT NOT NULL, state_receipt_bytes BLOB,
                    state_receipt_digest BLOB, operation_id BLOB NOT NULL UNIQUE,
                    duplicate_convergence INTEGER NOT NULL, completed_ms INTEGER NOT NULL,
                    FOREIGN KEY(job_id) REFERENCES app_jobs(job_id)
                );
                CREATE TABLE IF NOT EXISTS app_transitions (
                    sequence INTEGER PRIMARY KEY, transition_kind TEXT NOT NULL, job_id TEXT NOT NULL,
                    before_root BLOB NOT NULL, after_root BLOB NOT NULL, event_bytes BLOB NOT NULL,
                    event_digest BLOB NOT NULL UNIQUE, FOREIGN KEY(job_id) REFERENCES app_jobs(job_id)
                );
                CREATE TRIGGER IF NOT EXISTS app_jobs_no_delete BEFORE DELETE ON app_jobs BEGIN SELECT RAISE(ABORT,'app_jobs_append_only'); END;
                CREATE TRIGGER IF NOT EXISTS app_transitions_no_update BEFORE UPDATE ON app_transitions BEGIN SELECT RAISE(ABORT,'app_transitions_append_only'); END;
                CREATE TRIGGER IF NOT EXISTS app_transitions_no_delete BEFORE DELETE ON app_transitions BEGIN SELECT RAISE(ABORT,'app_transitions_append_only'); END;
                """
            )
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT * FROM app_metadata WHERE id=1").fetchone()
            head = _sha(_APP_GENESIS, self.config.application_id.encode("ascii"), self.config.digest)
            if row is None:
                connection.execute(
                    "INSERT INTO app_metadata VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (1, _SCHEMA_VERSION, self.config.application_id, self.config.canonical_bytes, self.config.digest,
                     self.config.queue_id, self.config.queue_config_digest, self.config.verifier_sha256,
                     self.config.state_store_identity, head, 0),
                )
            elif (
                len(row) != 11 or int(row[1]) != _SCHEMA_VERSION or str(row[2]) != self.config.application_id
                or bytes(row[3]) != self.config.canonical_bytes or bytes(row[4]) != self.config.digest
                or str(row[5]) != self.config.queue_id or bytes(row[6]) != self.config.queue_config_digest
                or bytes(row[7]) != self.config.verifier_sha256 or bytes(row[8]) != self.config.state_store_identity
            ):
                raise QueueApplicationIntegrityError("application_config_drift")
            connection.execute("COMMIT")
        self.verify_integrity()

    def _meta(self, connection) -> tuple[Any, ...]:
        row = connection.execute("SELECT * FROM app_metadata WHERE id=1").fetchone()
        if row is None or len(row) != 11:
            raise QueueApplicationIntegrityError("application_metadata_missing")
        if (
            int(row[1]) != _SCHEMA_VERSION or str(row[2]) != self.config.application_id
            or bytes(row[3]) != self.config.canonical_bytes or bytes(row[4]) != self.config.digest
            or str(row[5]) != self.config.queue_id or bytes(row[6]) != self.config.queue_config_digest
            or bytes(row[7]) != self.config.verifier_sha256 or bytes(row[8]) != self.config.state_store_identity
        ):
            raise QueueApplicationIntegrityError("application_metadata_drift")
        return tuple(row)

    def _fault(self, name: str) -> None:
        if self._before_fault is not None:
            self._before_fault(name)

    def _append_transition(self, connection, *, kind: str, job_id: str, event: Mapping[str, Any]) -> None:
        meta = self._meta(connection)
        sequence = int(meta[10]) + 1
        before = bytes(meta[9])
        event_bytes = _json_bytes(dict(event))
        event_digest = _sha(_APP_EVENT, kind.encode("ascii"), job_id.encode("ascii"), event_bytes)
        after = _sha(_APP_HEAD, before, _u64(sequence), event_digest)
        connection.execute(
            "INSERT INTO app_transitions VALUES (?,?,?,?,?,?,?)",
            (sequence, kind, job_id, before, after, event_bytes, event_digest),
        )
        connection.execute("UPDATE app_metadata SET head_root=?,next_sequence=? WHERE id=1", (after, sequence))

    @staticmethod
    def _job_from_row(row: tuple[Any, ...]) -> QueueApplicationJobV1:
        if len(row) != 13:
            raise QueueApplicationIntegrityError("application_job_shape")
        return QueueApplicationJobV1(
            job_id=str(row[0]), operation_id=bytes(row[1]), status=str(row[6]), attempt=int(row[8]),
            queue_receipt_digest=bytes(row[2]), acceptance_digest=bytes(row[3]),
        )

    def _get_job_locked(self, connection, job_id: str) -> QueueApplicationJobV1 | None:
        row = connection.execute("SELECT * FROM app_jobs WHERE job_id=?", (job_id,)).fetchone()
        return None if row is None else self._job_from_row(tuple(row))

    def _material(self, verified) -> tuple[bytes, bytes, bytes, bytes]:
        queue_receipt_digest = _sha(_APP_QUEUE_RECEIPT, verified.receipt_bytes)
        acceptance_digest = _sha(_APP_ACCEPTANCE, verified.acceptance_bytes)
        operation_id = _sha(
            _APP_OPERATION, verified.job_id.encode("ascii"), verified.operation_id,
            verified.acceptance_bytes, self.config.state_store_identity, self.config.verifier_sha256,
        )
        material = _sha(_APP_MATERIAL, operation_id, queue_receipt_digest, acceptance_digest, self.config.digest)
        return operation_id, queue_receipt_digest, acceptance_digest, material

    def discover(self, queue_database: Path, job_id: str) -> QueueApplicationJobV1:
        """Independently verify and admit one terminal VERIFIED queue job."""
        _token(job_id, "job_id")
        try:
            verified = read_application_job(queue_database, job_id)
        except IndependentQueueApplicationError as exc:
            raise QueueApplicationIntegrityError("queue_verification_failed") from exc
        if (
            verified.queue_id != self.config.queue_id
            or verified.config_digest != self.config.queue_config_digest
            or verified.verifier_sha256 != self.config.verifier_sha256
            or verified.cap_bytes != _CAP_BYTES or verified.cap_enforced is not True
            or verified.active_process_limit != _ACTIVE_PROCESS_LIMIT
            or verified.timed_out is not False or verified.exit_code != 0
            or verified.peak_job_commit_bytes > _CAP_BYTES
        ):
            raise QueueApplicationIntegrityError("queue_binding")
        try:
            acceptance = parse_acceptance_bytes(verified.acceptance_bytes)
        except Exception as exc:
            raise QueueApplicationIntegrityError("acceptance_parse") from exc
        if (
            acceptance.canonical_bytes() != verified.acceptance_bytes
            or acceptance.artifact_bytes != verified.artifact_bytes
            or acceptance.artifact_sha256 != verified.artifact_sha256
            or acceptance.artifact_digest != verified.artifact_sha3_512
            or acceptance.circuit_id != verified.circuit_id
        ):
            raise QueueApplicationIntegrityError("acceptance_binding")
        operation_id, queue_digest, acceptance_digest, material = self._material(verified)
        now = int(self.clock.now_ms())
        with closing(self._connect()) as connection:
            began = False
            try:
                connection.execute("BEGIN IMMEDIATE")
                began = True
                self._meta(connection)
                existing_row = connection.execute("SELECT * FROM app_jobs WHERE job_id=?", (job_id,)).fetchone()
                if existing_row is not None:
                    existing = self._job_from_row(tuple(existing_row))
                    if existing.operation_id != operation_id or existing.queue_receipt_digest != queue_digest or existing.acceptance_digest != acceptance_digest:
                        raise QueueApplicationConflictError("application_discovery_conflict")
                    connection.execute("COMMIT")
                    began = False
                    return existing
                depth = int(connection.execute("SELECT COUNT(*) FROM app_jobs WHERE status IN ('DISCOVERED','LEASED')").fetchone()[0])
                if depth >= self.config.capacity:
                    raise QueueApplicationBackpressureError("application_backpressure")
                meta = self._meta(connection)
                admission = int(meta[10]) + 1
                connection.execute(
                    "INSERT INTO app_jobs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (job_id, operation_id, queue_digest, acceptance_digest, verified.acceptance_bytes,
                     verified.receipt_bytes, "DISCOVERED", admission, 0, now, now, now, None),
                )
                self._append_transition(connection, kind="DISCOVER", job_id=job_id,
                                        event={"at_ms": now, "status": "DISCOVERED", "admission_sequence": admission})
                self._fault("after_discovery_transition")
                connection.execute("COMMIT")
                began = False
            except Exception:
                if began and connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        self.verify_integrity()
        return QueueApplicationJobV1(job_id, operation_id, "DISCOVERED", 0, queue_digest, acceptance_digest)

    def claim_next(self, worker_id: str) -> QueueApplicationWorkV1 | None:
        _token(worker_id, "worker_id")
        now = int(self.clock.now_ms())
        with closing(self._connect()) as connection:
            began = False
            try:
                connection.execute("BEGIN IMMEDIATE")
                began = True
                self._meta(connection)
                row = connection.execute(
                    "SELECT * FROM app_jobs WHERE status='DISCOVERED' AND next_eligible_ms<=? ORDER BY admission_sequence LIMIT 1",
                    (now,),
                ).fetchone()
                if row is None:
                    connection.execute("COMMIT")
                    return None
                job = self._job_from_row(tuple(row))
                attempt = job.attempt + 1
                if attempt > self.config.max_attempts:
                    raise QueueApplicationLeaseError("application_attempts_exhausted")
                token = secrets.token_bytes(24)
                expires = now + self.config.lease_seconds * 1000
                connection.execute(
                    "UPDATE app_jobs SET status='LEASED',attempt=?,updated_ms=? WHERE job_id=? AND status='DISCOVERED' AND attempt=?",
                    (attempt, now, job.job_id, job.attempt),
                )
                if connection.total_changes != 1:
                    raise QueueApplicationLeaseError("application_claim_cas")
                connection.execute(
                    "INSERT INTO app_leases VALUES (?,?,?,?,?,?)",
                    (job.job_id, worker_id, token, attempt, now, expires),
                )
                self._append_transition(connection, kind="CLAIM", job_id=job.job_id,
                                        event={"at_ms": now, "status": "LEASED", "attempt": attempt,
                                               "worker_id": worker_id, "expires_ms": expires})
                connection.execute("COMMIT")
                began = False
                return QueueApplicationWorkV1(
                    self.config.application_id, job.job_id, job.operation_id, attempt, worker_id, token, expires,
                    bytes(row[4]), bytes(row[5]),
                )
            except Exception:
                if began and connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def _live_lease(self, connection, work: QueueApplicationWorkV1) -> tuple[Any, ...]:
        row = connection.execute("SELECT * FROM app_leases WHERE job_id=?", (work.job_id,)).fetchone()
        if row is None or str(row[1]) != work.worker_id or bytes(row[2]) != work.lease_token or int(row[3]) != work.attempt:
            raise QueueApplicationLeaseError("application_lease")
        return tuple(row)

    def _held(self, work: QueueApplicationWorkV1, code: str) -> QueueApplicationResultV1:
        now = int(self.clock.now_ms())
        with closing(self._connect()) as connection:
            began = False
            try:
                connection.execute("BEGIN IMMEDIATE")
                began = True
                self._live_lease(connection, work)
                connection.execute("DELETE FROM app_leases WHERE job_id=?", (work.job_id,))
                connection.execute("UPDATE app_jobs SET status='HELD',updated_ms=?,last_error_code=? WHERE job_id=? AND status='LEASED'", (now, code, work.job_id))
                connection.execute("INSERT INTO app_results VALUES (?,?,?,?,?,?,?)", (work.job_id, "HELD", None, None, work.operation_id, 0, now))
                self._append_transition(connection, kind="HELD", job_id=work.job_id,
                                        event={"at_ms": now, "status": "HELD", "error_code": code, "attempt": work.attempt})
                connection.execute("COMMIT")
                began = False
            except Exception:
                if began and connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return QueueApplicationResultV1(work.job_id, work.operation_id, "HELD", None, None, False, code)

    @staticmethod
    def _validate_state_receipt(
        acceptance: MinimalProofAcceptanceV1,
        receipt: MinimalClearanceReceiptV1,
        before: Any,
        after: Any,
        duplicate: bool,
    ) -> None:
        if (
            type(receipt) is not MinimalClearanceReceiptV1
            or receipt.proof_session_accepted is not True
            or receipt.economic_mutation is not False
            or receipt.proof_suite_id is not None
            or receipt.artifact_sha256 != acceptance.artifact_sha256
            or receipt.artifact_digest != acceptance.artifact_digest
            or receipt.circuit_id != acceptance.circuit_id
            or receipt.statement_digest != acceptance.statement_digest
            or receipt.policy_result != acceptance.policy_result
            or receipt.effective_directive != acceptance.effective_directive
            or receipt.payment_root_before != before.payment_root
            or receipt.payment_root_after != after.payment_root
            or before.payment_root != after.payment_root
            or receipt.settled_batch_count_before != before.settled_batch_count
            or receipt.settled_batch_count_after != after.settled_batch_count
            or before.settled_batch_count != after.settled_batch_count
            or (not duplicate and receipt.sequence_after not in (before.sequence, before.sequence + 1))
            or (not duplicate and after.sequence != receipt.sequence_after)
            or (duplicate and (receipt.sequence_after != before.sequence or after.sequence != before.sequence))
        ):
            raise QueueApplicationIntegrityError("state_receipt_binding")

    def _existing_result(self, job_id: str) -> QueueApplicationResultV1 | None:
        with closing(self._connect()) as connection:
            row = connection.execute("SELECT * FROM app_results WHERE job_id=?", (job_id,)).fetchone()
        if row is None:
            return None
        receipt = None if row[2] is None else bytes(row[2])
        digest = None if row[3] is None else bytes(row[3])
        return QueueApplicationResultV1(str(row[0]), bytes(row[4]), str(row[1]), receipt, digest, bool(row[5]), None if str(row[1]) == "APPLIED" else "application_held")

    def apply(
        self,
        work: QueueApplicationWorkV1,
        *,
        queue_database: Path,
        state_store: MinimalClearanceStateStoreV1,
    ) -> QueueApplicationResultV1:
        """Recheck queue evidence and apply the typed acceptance exactly once."""
        existing = self._existing_result(work.job_id)
        if existing is not None:
            return existing
        if type(work) is not QueueApplicationWorkV1:
            raise QueueApplicationLeaseError("application_work_type")
        try:
            verified = read_application_job(queue_database, work.job_id)
        except IndependentQueueApplicationError as exc:
            return self._held(work, "queue_reverification_failed")
        if verified.receipt_bytes != work.queue_receipt_bytes or verified.acceptance_bytes != work.acceptance_bytes:
            return self._held(work, "queue_result_drift")
        try:
            acceptance = parse_acceptance_bytes(work.acceptance_bytes)
        except Exception:
            return self._held(work, "acceptance_reparse_failed")
        with closing(self._connect()) as connection:
            primary_row = connection.execute(
                "SELECT job_id FROM app_jobs WHERE acceptance_digest=? ORDER BY admission_sequence LIMIT 1",
                (_sha(_APP_ACCEPTANCE, work.acceptance_bytes),),
            ).fetchone()
        duplicate = primary_row is None or str(primary_row[0]) != work.job_id
        with closing(self._connect()) as connection:
            self._live_lease(connection, work)
        try:
            if bytes(state_store.expected_verifier_sha256) != self.config.verifier_sha256 or state_store.state_store_identity() != self.config.state_store_identity:
                return self._held(work, "state_binding_drift")
            before = state_store.snapshot()
            receipt = state_store.submit_verified_acceptance(acceptance)
            after = state_store.snapshot()
            self._validate_state_receipt(acceptance, receipt, before, after, duplicate)
        except MinimalClearanceIndeterminateError:
            raise
        except Exception:
            return self._held(work, "state_admission_failed")
        receipt_bytes = receipt.canonical_bytes()
        if len(receipt_bytes) > _MAX_RECEIPT:
            raise QueueApplicationIntegrityError("state_receipt_bounds")
        receipt_digest = _sha(_APP_STATE_RECEIPT, receipt_bytes)
        self._fault("after_state_commit_before_coordinator")
        now = int(self.clock.now_ms())
        with closing(self._connect()) as connection:
            began = False
            try:
                connection.execute("BEGIN IMMEDIATE")
                began = True
                self._live_lease(connection, work)
                connection.execute("DELETE FROM app_leases WHERE job_id=?", (work.job_id,))
                connection.execute("UPDATE app_jobs SET status='APPLIED',updated_ms=?,last_error_code=NULL WHERE job_id=? AND status='LEASED'", (now, work.job_id))
                connection.execute("INSERT INTO app_results VALUES (?,?,?,?,?,?,?)", (work.job_id, "APPLIED", receipt_bytes, receipt_digest, work.operation_id, int(duplicate), now))
                self._append_transition(connection, kind="APPLIED", job_id=work.job_id,
                                        event={"at_ms": now, "status": "APPLIED", "attempt": work.attempt,
                                               "state_receipt_digest": _hex(receipt_digest), "duplicate_convergence": int(duplicate)})
                self._fault("before_application_commit")
                connection.execute("COMMIT")
                began = False
            except Exception:
                if began and connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        if self._after_commit_fault is not None:
            try:
                self._after_commit_fault("after_application_commit")
            except Exception as exc:
                raise QueueApplicationIndeterminateError("application_commit_indeterminate") from exc
        return QueueApplicationResultV1(work.job_id, work.operation_id, "APPLIED", receipt_bytes, receipt_digest, duplicate, None)

    def get_job(self, job_id: str) -> QueueApplicationJobV1 | None:
        _token(job_id, "job_id")
        with closing(self._connect()) as connection:
            return self._get_job_locked(connection, job_id)

    def snapshot(self) -> dict[str, Any]:
        with closing(self._connect()) as connection:
            meta = self._meta(connection)
            counts = {status: int(connection.execute("SELECT COUNT(*) FROM app_jobs WHERE status=?", (status,)).fetchone()[0]) for status in sorted(_STATUS)}
            transitions = int(connection.execute("SELECT COUNT(*) FROM app_transitions").fetchone()[0])
        return {"schema": _SCHEMA, "application_id": self.config.application_id, "head_root": _hex(bytes(meta[9])), "status_counts": counts, "transition_count": transitions}

    def support_summary(self) -> dict[str, Any]:
        snap = self.snapshot()
        with closing(self._connect()) as connection:
            duplicate = int(connection.execute("SELECT COUNT(*) FROM app_results WHERE duplicate_convergence=1").fetchone()[0])
        return {**snap, "duplicate_convergence_count": duplicate, "proof_suite_id": None, "production_usable": False, "activation": False}

    def export_bytes(self) -> bytes:
        self.verify_integrity()
        with closing(self._connect()) as connection:
            meta = self._meta(connection)
            def blob(value: object) -> str | None:
                return None if value is None else _hex(bytes(value))
            value = {
                "schema": _SCHEMA, "config": self.config.as_json(),
                "metadata": {"head_root": blob(meta[9]), "next_sequence": int(meta[10])},
                "jobs": [
                    {"job_id": str(row[0]), "operation_id": blob(row[1]), "queue_receipt_digest": blob(row[2]), "acceptance_digest": blob(row[3]),
                     "acceptance_bytes": blob(row[4]), "queue_receipt_bytes": blob(row[5]), "status": str(row[6]), "admission_sequence": int(row[7]),
                     "attempt": int(row[8]), "next_eligible_ms": int(row[9]), "created_ms": int(row[10]), "updated_ms": int(row[11]), "last_error_code": row[12]}
                    for row in connection.execute("SELECT * FROM app_jobs ORDER BY admission_sequence")
                ],
                "leases": [
                    {"job_id": str(row[0]), "worker_id": str(row[1]), "token": blob(row[2]), "attempt": int(row[3]), "leased_ms": int(row[4]), "expires_ms": int(row[5])}
                    for row in connection.execute("SELECT * FROM app_leases ORDER BY job_id")
                ],
                "results": [
                    {"job_id": str(row[0]), "status": str(row[1]), "state_receipt_bytes": blob(row[2]), "state_receipt_digest": blob(row[3]),
                     "operation_id": blob(row[4]), "duplicate_convergence": bool(row[5]), "completed_ms": int(row[6])}
                    for row in connection.execute("SELECT * FROM app_results ORDER BY job_id")
                ],
                "transitions": [
                    {"sequence": int(row[0]), "transition_kind": str(row[1]), "job_id": str(row[2]), "before_root": blob(row[3]), "after_root": blob(row[4]),
                     "event_bytes": blob(row[5]), "event_digest": blob(row[6])}
                    for row in connection.execute("SELECT * FROM app_transitions ORDER BY sequence")
                ],
            }
        return _json_bytes(value)

    def verify_integrity(self) -> None:
        with closing(self._connect()) as connection:
            meta = self._meta(connection)
            jobs = connection.execute("SELECT * FROM app_jobs ORDER BY admission_sequence").fetchall()
            leases = connection.execute("SELECT * FROM app_leases ORDER BY job_id").fetchall()
            results = connection.execute("SELECT * FROM app_results ORDER BY job_id").fetchall()
            transitions = connection.execute("SELECT * FROM app_transitions ORDER BY sequence").fetchall()
            if int(meta[10]) != len(transitions):
                raise QueueApplicationIntegrityError("application_transition_count")
            expected = _sha(_APP_GENESIS, self.config.application_id.encode("ascii"), self.config.digest)
            for index, row in enumerate(transitions, start=1):
                if int(row[0]) != index or bytes(row[3]) != expected:
                    raise QueueApplicationIntegrityError("application_head_chain")
                event_digest = _sha(_APP_EVENT, str(row[1]).encode("ascii"), str(row[2]).encode("ascii"), bytes(row[5]))
                if event_digest != bytes(row[6]):
                    raise QueueApplicationIntegrityError("application_event_digest")
                expected = _sha(_APP_HEAD, expected, _u64(index), event_digest)
                if expected != bytes(row[4]):
                    raise QueueApplicationIntegrityError("application_head_transition")
            if expected != bytes(meta[9]):
                raise QueueApplicationIntegrityError("application_head_current")
            job_map: dict[str, tuple[Any, ...]] = {}
            for row in jobs:
                if len(row) != 13 or str(row[6]) not in _STATUS or str(row[0]) in job_map:
                    raise QueueApplicationIntegrityError("application_job_shape")
                acceptance_raw = bytes(row[4])
                receipt_raw = bytes(row[5])
                if not 0 < len(acceptance_raw) <= _MAX_ACCEPTANCE or not 0 < len(receipt_raw) <= _MAX_RECEIPT:
                    raise QueueApplicationIntegrityError("application_job_bounds")
                try:
                    acceptance = parse_acceptance_bytes(acceptance_raw)
                except Exception as exc:
                    raise QueueApplicationIntegrityError("application_job_acceptance") from exc
                if (
                    acceptance.canonical_bytes() != acceptance_raw
                    or bytes(row[3]) != _sha(_APP_ACCEPTANCE, acceptance_raw)
                    or bytes(row[2]) != _sha(_APP_QUEUE_RECEIPT, receipt_raw)
                ):
                    raise QueueApplicationIntegrityError("application_job_binding")
                job_map[str(row[0])] = tuple(row)
            lease_map = {str(row[0]): tuple(row) for row in leases}
            result_map = {str(row[0]): tuple(row) for row in results}
            if len(lease_map) != len(leases) or len(result_map) != len(results):
                raise QueueApplicationIntegrityError("application_duplicate")
            for job_id, row in job_map.items():
                status = str(row[6])
                if (status == "LEASED") != (job_id in lease_map):
                    raise QueueApplicationIntegrityError("application_lease_binding")
                if (status in {"APPLIED", "HELD"}) != (job_id in result_map):
                    raise QueueApplicationIntegrityError("application_result_binding")
            for job_id, row in result_map.items():
                status = str(row[1])
                if status not in {"APPLIED", "HELD"} or job_id not in job_map or str(job_map[job_id][6]) != status:
                    raise QueueApplicationIntegrityError("application_result_shape")
                if status == "APPLIED":
                    if row[2] is None or row[3] is None or bytes(row[3]) != _sha(_APP_STATE_RECEIPT, bytes(row[2])):
                        raise QueueApplicationIntegrityError("application_state_receipt")
                    try:
                        decoded = json.loads(bytes(row[2]).decode("ascii"))
                    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                        raise QueueApplicationIntegrityError("application_state_receipt_encoding") from exc
                    if bytes(row[2]) != _json_bytes(decoded) or decoded.get("economic_mutation") is not False or decoded.get("proof_session_accepted") is not True or decoded.get("proof_suite_id") is not None:
                        raise QueueApplicationIntegrityError("application_state_receipt_claim")

__all__ = (
    "QueueApplicationConfigV1", "QueueApplicationError", "QueueApplicationConflictError",
    "QueueApplicationBackpressureError", "QueueApplicationLeaseError", "QueueApplicationIntegrityError",
    "QueueApplicationIndeterminateError", "QueueApplicationJobV1", "QueueApplicationWorkV1",
    "QueueApplicationResultV1", "QueueApplicationStoreV1",
)
