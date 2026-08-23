"""Durable, nonpayment handoff of an applied clearance directive.

The outbox is deliberately downstream of the queue application ledger.  It
stores only a typed, digest-bound directive envelope and receiver
acknowledgment; the injected official receiver remains the external owner of
directive consumption and any later payment action.
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

from app.minimal_clearance_official_handoff_independent import (
    AppliedApplicationViewV1,
    IndependentOfficialHandoffError,
    acknowledgment_digest,
    envelope_digest,
    parse_acknowledgment_bytes,
    parse_envelope_bytes,
    read_applied_application,
    restore_export_to_fresh_database,
    verify_database as independent_verify_database,
    verify_export_bytes as independent_verify_export_bytes,
)


class OfficialHandoffError(RuntimeError):
    """Bounded handoff failure."""


class OfficialHandoffConflictError(OfficialHandoffError):
    pass


class OfficialHandoffLeaseError(OfficialHandoffError):
    pass


class OfficialHandoffIntegrityError(OfficialHandoffError):
    pass


class OfficialHandoffIndeterminateError(OfficialHandoffError):
    pass


_SCHEMA_VERSION: Final[int] = 1
_SCHEMA: Final[str] = "BL/NATIVE-V3/MINIMAL-CLEARANCE-OFFICIAL-HANDOFF/v1"
_STATUS: Final[frozenset[str]] = frozenset({"DISCOVERED", "LEASED", "ACKNOWLEDGED", "HELD"})
_MAX_ENVELOPE: Final[int] = 16 * 1024
_MAX_ACK: Final[int] = 4096
_MAX_EXPORT: Final[int] = 8 * 1024 * 1024
_TOKEN = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
_MATERIAL = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/OFFICIAL-HANDOFF/MATERIAL/v1\x00"
_GENESIS = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/OFFICIAL-HANDOFF/GENESIS/v1\x00"
_HEAD = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/OFFICIAL-HANDOFF/HEAD/v1\x00"
_EVENT = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/OFFICIAL-HANDOFF/EVENT/v1\x00"
_ENVELOPE = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/OFFICIAL-DIRECTIVE-ENVELOPE/v1\x00"
_IDEMPOTENCY = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/OFFICIAL-DIRECTIVE-IDEMPOTENCY/v1\x00"
_RESULT = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/OFFICIAL-DIRECTIVE-RESULT/v1\x00"
_CAP_BYTES: Final[int] = 5_000_000_000


def _sha(domain: bytes, *parts: bytes) -> bytes:
    digest = hashlib.sha3_512()
    digest.update(domain)
    for part in parts:
        if type(part) is not bytes:
            raise OfficialHandoffIntegrityError("handoff_binding_type")
        digest.update(part)
    return digest.digest()


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise OfficialHandoffIntegrityError("handoff_json") from exc


def _hex(value: bytes) -> str:
    return value.hex().upper()


def _token(value: object, label: str) -> str:
    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        raise OfficialHandoffError(f"{label}_invalid")
    return value


def _fixed(value: object, size: int, label: str) -> bytes:
    if type(value) is not bytes or len(value) != size:
        raise OfficialHandoffIntegrityError(f"{label}_width")
    return bytes(value)


def _u64(value: int) -> bytes:
    if type(value) is not int or not 0 <= value < 2**64:
        raise OfficialHandoffIntegrityError("handoff_integer")
    return value.to_bytes(8, "big")


class ApplicationClock(Protocol):
    def now_ms(self) -> int:
        """Return the injected handoff clock."""


class _SystemClock:
    def now_ms(self) -> int:
        import time

        return int(time.time() * 1000)


class OfficialStateReceiverPort(Protocol):
    def identity_sha256(self) -> bytes:
        """Return the immutable receiver identity."""

    def epoch(self) -> int:
        """Return the current receiver epoch."""

    def dispatch(self, envelope_bytes: bytes, idempotency_key: bytes) -> bytes:
        """Consume one canonical directive and return a typed acknowledgment."""


@dataclass(frozen=True, slots=True)
class OfficialHandoffConfigV1:
    outbox_id: str
    application_id: str
    application_config_digest: bytes
    verifier_sha256: bytes
    state_store_identity: bytes
    receiver_identity: bytes
    receiver_epoch: int
    capacity: int = 16
    lease_seconds: int = 300
    max_attempts: int = 3
    busy_timeout_ms: int = 5_000
    proof_suite_id: None = None
    production_usable: bool = False
    activation: bool = False

    def __post_init__(self) -> None:
        _token(self.outbox_id, "outbox_id")
        _token(self.application_id, "application_id")
        _fixed(self.application_config_digest, 64, "application_config_digest")
        _fixed(self.verifier_sha256, 32, "verifier_sha256")
        _fixed(self.state_store_identity, 64, "state_store_identity")
        _fixed(self.receiver_identity, 32, "receiver_identity")
        if type(self.receiver_epoch) is not int or self.receiver_epoch < 1:
            raise OfficialHandoffIntegrityError("receiver_epoch")
        if type(self.capacity) is not int or not 1 <= self.capacity <= 10_000:
            raise OfficialHandoffIntegrityError("handoff_capacity")
        if type(self.lease_seconds) is not int or not 1 <= self.lease_seconds <= 3_600:
            raise OfficialHandoffIntegrityError("handoff_lease_seconds")
        if self.max_attempts != 3 or self.busy_timeout_ms != 5_000:
            raise OfficialHandoffIntegrityError("handoff_fixed_config")
        if self.proof_suite_id is not None or self.production_usable is not False or self.activation is not False:
            raise OfficialHandoffIntegrityError("handoff_nonactivation")

    def as_json(self) -> dict[str, Any]:
        return {
            "schema_version": _SCHEMA_VERSION, "outbox_id": self.outbox_id, "application_id": self.application_id,
            "application_config_digest": _hex(self.application_config_digest),
            "verifier_sha256": _hex(self.verifier_sha256),
            "state_store_identity": _hex(self.state_store_identity), "receiver_identity": _hex(self.receiver_identity),
            "receiver_epoch": self.receiver_epoch, "capacity": self.capacity, "lease_seconds": self.lease_seconds,
            "max_attempts": 3, "busy_timeout_ms": 5_000, "proof_suite_id": None,
            "production_usable": False, "activation": False,
        }

    @property
    def canonical_bytes(self) -> bytes:
        return _json_bytes(self.as_json())

    @property
    def digest(self) -> bytes:
        return _sha(_MATERIAL, self.canonical_bytes)


@dataclass(frozen=True, slots=True)
class OfficialHandoffJobV1:
    job_id: str
    operation_id: bytes
    status: str
    attempt: int
    envelope_digest: bytes


@dataclass(frozen=True, slots=True)
class OfficialHandoffWorkV1:
    outbox_id: str
    job_id: str
    operation_id: bytes
    attempt: int
    worker_id: str
    lease_token: bytes
    lease_expires_ms: int
    envelope_bytes: bytes
    idempotency_key: bytes


@dataclass(frozen=True, slots=True)
class OfficialHandoffResultV1:
    job_id: str
    operation_id: bytes
    status: str
    acknowledgment_bytes: bytes | None
    acknowledgment_digest: bytes | None
    delivery_count: int
    error_code: str | None


def build_directive_envelope(view: AppliedApplicationViewV1, config: OfficialHandoffConfigV1) -> bytes:
    """Construct the only bytes this outbox is allowed to persist."""
    receipt = view.receipt
    if (
        receipt["proof_session_accepted"] is not True or receipt["economic_mutation"] is not False
        or receipt["proof_suite_id"] is not None or receipt["payment_root_before"] != receipt["payment_root_after"]
        or receipt["settled_batch_count_before"] != receipt["settled_batch_count_after"]
        or not 1 <= int(receipt["effective_directive"]) <= 5
    ):
        raise OfficialHandoffIntegrityError("handoff_receipt_claim")
    value = {
        "schema": _SCHEMA,
        "application_id_digest": _hex(_sha(_ENVELOPE, view.application_id.encode("ascii"))),
        "application_config_digest": _hex(view.application_config_digest),
        "application_job_id_digest": _hex(_sha(_ENVELOPE, view.job_id.encode("ascii"))),
        "application_operation_id": _hex(view.operation_id),
        "application_result_digest": _hex(view.application_result_digest),
        "state_store_identity": _hex(view.state_store_identity),
        "state_receipt_digest": _hex(view.state_receipt_digest),
        "request_id": receipt["request_id"], "attempt_id": receipt["attempt_id"],
        "decision_id": receipt["decision_id"], "receipt_id": receipt["receipt_id"],
        "state_after_id": receipt["state_after_id"], "state_binding_after": receipt["state_binding_after"],
        "audit_head_after": receipt["audit_head_after"], "policy_result": int(receipt["policy_result"]),
        "effective_directive": int(receipt["effective_directive"]), "proof_session_accepted": True,
        "proof_acceptance_is_clear": False, "payment_root_unchanged": True,
        "settled_batch_count_unchanged": True, "economic_mutation": False, "proof_suite_id": None,
    }
    raw = _json_bytes(value)
    parse_envelope_bytes(raw)
    return raw


class OfficialHandoffStoreV1:
    """Producer-owned durable directive outbox."""

    def __init__(
        self,
        *,
        path: Path,
        config: OfficialHandoffConfigV1,
        clock: ApplicationClock | None = None,
        before_fault: Callable[[str], None] | None = None,
        after_commit_fault: Callable[[str], None] | None = None,
    ) -> None:
        if not isinstance(path, Path) or path.exists() and path.is_symlink() or not path.parent.is_dir():
            raise OfficialHandoffError("handoff_database_path")
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
                CREATE TABLE IF NOT EXISTS outbox_metadata (
                    id INTEGER PRIMARY KEY CHECK(id=1), schema_version INTEGER NOT NULL, outbox_id TEXT NOT NULL,
                    config_json BLOB NOT NULL, config_digest BLOB NOT NULL, application_id TEXT NOT NULL,
                    application_config_digest BLOB NOT NULL, state_store_identity BLOB NOT NULL,
                    receiver_identity BLOB NOT NULL, receiver_epoch INTEGER NOT NULL, head_root BLOB NOT NULL,
                    next_sequence INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS outbox_jobs (
                    job_id TEXT PRIMARY KEY, operation_id BLOB NOT NULL UNIQUE, envelope_digest BLOB NOT NULL UNIQUE,
                    envelope_bytes BLOB NOT NULL, idempotency_key BLOB NOT NULL UNIQUE, status TEXT NOT NULL,
                    discovery_sequence INTEGER NOT NULL UNIQUE, attempt INTEGER NOT NULL, next_eligible_ms INTEGER NOT NULL,
                    created_ms INTEGER NOT NULL, updated_ms INTEGER NOT NULL, last_error_code TEXT
                );
                CREATE TABLE IF NOT EXISTS outbox_leases (
                    job_id TEXT PRIMARY KEY, worker_id TEXT NOT NULL, token BLOB NOT NULL, attempt INTEGER NOT NULL,
                    leased_ms INTEGER NOT NULL, expires_ms INTEGER NOT NULL, FOREIGN KEY(job_id) REFERENCES outbox_jobs(job_id)
                );
                CREATE TABLE IF NOT EXISTS outbox_acks (
                    job_id TEXT PRIMARY KEY, status TEXT NOT NULL, ack_bytes BLOB NOT NULL, ack_digest BLOB NOT NULL,
                    operation_id BLOB NOT NULL UNIQUE, delivery_count INTEGER NOT NULL, completed_ms INTEGER NOT NULL,
                    FOREIGN KEY(job_id) REFERENCES outbox_jobs(job_id)
                );
                CREATE TABLE IF NOT EXISTS outbox_transitions (
                    sequence INTEGER PRIMARY KEY, transition_kind TEXT NOT NULL, job_id TEXT NOT NULL,
                    before_root BLOB NOT NULL, after_root BLOB NOT NULL, event_bytes BLOB NOT NULL,
                    event_digest BLOB NOT NULL UNIQUE, FOREIGN KEY(job_id) REFERENCES outbox_jobs(job_id)
                );
                CREATE TRIGGER IF NOT EXISTS outbox_jobs_no_delete BEFORE DELETE ON outbox_jobs BEGIN SELECT RAISE(ABORT,'outbox_jobs_append_only'); END;
                CREATE TRIGGER IF NOT EXISTS outbox_transitions_no_update BEFORE UPDATE ON outbox_transitions BEGIN SELECT RAISE(ABORT,'outbox_transitions_append_only'); END;
                CREATE TRIGGER IF NOT EXISTS outbox_transitions_no_delete BEFORE DELETE ON outbox_transitions BEGIN SELECT RAISE(ABORT,'outbox_transitions_append_only'); END;
                """
            )
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT * FROM outbox_metadata WHERE id=1").fetchone()
            head = _sha(_GENESIS, self.config.outbox_id.encode("ascii"), self.config.digest)
            if row is None:
                connection.execute(
                    "INSERT INTO outbox_metadata VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (1, _SCHEMA_VERSION, self.config.outbox_id, self.config.canonical_bytes, self.config.digest,
                     self.config.application_id, self.config.application_config_digest, self.config.state_store_identity,
                     self.config.receiver_identity, self.config.receiver_epoch, head, 0),
                )
            elif (
                len(row) != 12 or int(row[1]) != _SCHEMA_VERSION or str(row[2]) != self.config.outbox_id
                or bytes(row[3]) != self.config.canonical_bytes or bytes(row[4]) != self.config.digest
                or str(row[5]) != self.config.application_id or bytes(row[6]) != self.config.application_config_digest
                or bytes(row[7]) != self.config.state_store_identity or bytes(row[8]) != self.config.receiver_identity
                or int(row[9]) != self.config.receiver_epoch
            ):
                raise OfficialHandoffIntegrityError("handoff_config_drift")
            connection.execute("COMMIT")
        self.verify_integrity()

    def _meta(self, connection) -> tuple[Any, ...]:
        row = connection.execute("SELECT * FROM outbox_metadata WHERE id=1").fetchone()
        if row is None or len(row) != 12:
            raise OfficialHandoffIntegrityError("handoff_metadata_missing")
        if (
            int(row[1]) != _SCHEMA_VERSION or str(row[2]) != self.config.outbox_id
            or bytes(row[3]) != self.config.canonical_bytes or bytes(row[4]) != self.config.digest
            or str(row[5]) != self.config.application_id or bytes(row[6]) != self.config.application_config_digest
            or bytes(row[7]) != self.config.state_store_identity or bytes(row[8]) != self.config.receiver_identity
            or int(row[9]) != self.config.receiver_epoch
        ):
            raise OfficialHandoffIntegrityError("handoff_metadata_drift")
        return tuple(row)

    def _fault(self, name: str) -> None:
        if self._before_fault is not None:
            self._before_fault(name)

    def _append_transition(self, connection, *, kind: str, job_id: str, event: Mapping[str, Any]) -> None:
        meta = self._meta(connection)
        sequence = int(meta[11]) + 1
        before = bytes(meta[10])
        event_bytes = _json_bytes(dict(event))
        event_digest = _sha(_EVENT, kind.encode("ascii"), job_id.encode("ascii"), event_bytes)
        after = _sha(_HEAD, before, _u64(sequence), event_digest)
        connection.execute("INSERT INTO outbox_transitions VALUES (?,?,?,?,?,?,?)", (sequence, kind, job_id, before, after, event_bytes, event_digest))
        connection.execute("UPDATE outbox_metadata SET head_root=?,next_sequence=? WHERE id=1", (after, sequence))

    def _recover_expired(self, connection, now: int) -> None:
        rows = connection.execute(
            "SELECT l.job_id,l.attempt,l.expires_ms,j.operation_id,j.status FROM outbox_leases l JOIN outbox_jobs j ON j.job_id=l.job_id WHERE l.expires_ms<=? ORDER BY l.job_id",
            (now,),
        ).fetchall()
        for job_id, attempt, expires_ms, operation_id, status in rows:
            if str(status) != "LEASED":
                raise OfficialHandoffIntegrityError("handoff_expired_status")
            connection.execute("DELETE FROM outbox_leases WHERE job_id=?", (str(job_id),))
            if int(attempt) < self.config.max_attempts:
                connection.execute("UPDATE outbox_jobs SET status='DISCOVERED',next_eligible_ms=?,updated_ms=?,last_error_code=? WHERE job_id=? AND status='LEASED'", (now, now, "handoff_lease_expired", str(job_id)))
                self._append_transition(connection, kind="EXPIRED_REQUEUE", job_id=str(job_id), event={"at_ms": now, "status": "DISCOVERED", "attempt": int(attempt), "error_code": "handoff_lease_expired", "expired_ms": int(expires_ms)})
            else:
                connection.execute("UPDATE outbox_jobs SET status='HELD',updated_ms=?,last_error_code=? WHERE job_id=? AND status='LEASED'", (now, "handoff_lease_exhausted", str(job_id)))
                self._append_transition(connection, kind="EXPIRED_HELD", job_id=str(job_id), event={"at_ms": now, "status": "HELD", "attempt": int(attempt), "error_code": "handoff_lease_exhausted", "expired_ms": int(expires_ms)})

    def _validate_work(self, work: OfficialHandoffWorkV1) -> tuple[Any, ...]:
        if type(work) is not OfficialHandoffWorkV1 or work.outbox_id != self.config.outbox_id:
            raise OfficialHandoffLeaseError("handoff_work_identity")
        _token(work.job_id, "job_id")
        _token(work.worker_id, "worker_id")
        _fixed(work.operation_id, 64, "work_operation")
        _fixed(work.lease_token, 24, "work_token")
        _fixed(work.idempotency_key, 64, "work_idempotency")
        if type(work.attempt) is not int or not 1 <= work.attempt <= self.config.max_attempts or type(work.lease_expires_ms) is not int or work.lease_expires_ms <= 0:
            raise OfficialHandoffLeaseError("handoff_work_attempt")
        if type(work.envelope_bytes) is not bytes or not 0 < len(work.envelope_bytes) <= _MAX_ENVELOPE:
            raise OfficialHandoffLeaseError("handoff_work_envelope")
        try:
            parse_envelope_bytes(work.envelope_bytes)
        except IndependentOfficialHandoffError as exc:
            raise OfficialHandoffLeaseError("handoff_work_envelope") from exc
        with closing(self._connect()) as connection:
            row = connection.execute("SELECT * FROM outbox_jobs WHERE job_id=?", (work.job_id,)).fetchone()
        if row is None or len(row) != 12:
            raise OfficialHandoffLeaseError("handoff_work_job")
        if (
            bytes(row[1]) != work.operation_id or bytes(row[2]) != envelope_digest(work.envelope_bytes)
            or bytes(row[3]) != work.envelope_bytes or bytes(row[4]) != work.idempotency_key
            or int(row[7]) != work.attempt or str(row[5]) not in _STATUS
        ):
            raise OfficialHandoffLeaseError("handoff_work_binding")
        return tuple(row)

    def _live_lease(self, connection, work: OfficialHandoffWorkV1) -> tuple[Any, ...]:
        if work.outbox_id != self.config.outbox_id:
            raise OfficialHandoffLeaseError("handoff_lease_identity")
        now = int(self.clock.now_ms())
        row = connection.execute("SELECT l.*,j.status,j.operation_id,j.attempt FROM outbox_leases l JOIN outbox_jobs j ON j.job_id=l.job_id WHERE l.job_id=?", (work.job_id,)).fetchone()
        if row is None:
            raise OfficialHandoffLeaseError("handoff_lease_missing")
        if (
            str(row[1]) != work.worker_id or bytes(row[2]) != work.lease_token or int(row[3]) != work.attempt
            or int(row[5]) != work.lease_expires_ms or str(row[6]) != "LEASED" or bytes(row[7]) != work.operation_id
            or int(row[8]) != work.attempt
        ):
            raise OfficialHandoffLeaseError("handoff_lease_binding")
        if now >= int(row[5]):
            raise OfficialHandoffLeaseError("handoff_lease_expired")
        return tuple(row[:6])

    def discover(self, application_database: Path, state_database: Path, job_id: str) -> OfficialHandoffJobV1:
        _token(job_id, "job_id")
        try:
            view = read_applied_application(
                application_database, state_database, expected_application_id=self.config.application_id,
                expected_application_config_digest=self.config.application_config_digest,
                expected_state_store_identity=self.config.state_store_identity,
                expected_verifier_sha256=self.config.verifier_sha256, job_id=job_id,
            )
        except IndependentOfficialHandoffError as exc:
            # The actual verifier identity is carried by the application/state binding.
            # The caller supplies it through the application config in the runner; this
            # branch remains a bounded independent failure.
            raise OfficialHandoffIntegrityError("handoff_discovery_failed") from exc
        envelope = build_directive_envelope(view, self.config)
        env_digest = envelope_digest(envelope)
        operation = _sha(_RESULT, self.config.application_id.encode("ascii"), job_id.encode("ascii"), env_digest, self.config.digest)
        idempotency = _sha(_IDEMPOTENCY, self.config.outbox_id.encode("ascii"), job_id.encode("ascii"), env_digest)
        now = int(self.clock.now_ms())
        with closing(self._connect()) as connection:
            began = False
            try:
                connection.execute("BEGIN IMMEDIATE")
                began = True
                self._meta(connection)
                existing = connection.execute("SELECT * FROM outbox_jobs WHERE job_id=?", (job_id,)).fetchone()
                if existing is not None:
                    if bytes(existing[1]) != operation or bytes(existing[2]) != env_digest or bytes(existing[3]) != envelope or bytes(existing[4]) != idempotency:
                        raise OfficialHandoffConflictError("handoff_discovery_conflict")
                    connection.execute("COMMIT")
                    began = False
                    return OfficialHandoffJobV1(job_id, operation, str(existing[5]), int(existing[7]), env_digest)
                depth = int(connection.execute("SELECT COUNT(*) FROM outbox_jobs WHERE status IN ('DISCOVERED','LEASED')").fetchone()[0])
                if depth >= self.config.capacity:
                    raise OfficialHandoffError("handoff_backpressure")
                sequence = int(self._meta(connection)[11]) + 1
                connection.execute("INSERT INTO outbox_jobs VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", (job_id, operation, env_digest, envelope, idempotency, "DISCOVERED", sequence, 0, now, now, now, None))
                self._append_transition(connection, kind="DISCOVER", job_id=job_id, event={"at_ms": now, "status": "DISCOVERED", "discovery_sequence": sequence, "effective_directive": int(view.receipt["effective_directive"]), "policy_result": int(view.receipt["policy_result"])})
                self._fault("after_discovery_transition")
                connection.execute("COMMIT")
                began = False
            except Exception:
                if began and connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        self.verify_integrity()
        return OfficialHandoffJobV1(job_id, operation, "DISCOVERED", 0, env_digest)

    def claim_next(self, worker_id: str) -> OfficialHandoffWorkV1 | None:
        _token(worker_id, "worker_id")
        now = int(self.clock.now_ms())
        with closing(self._connect()) as connection:
            began = False
            try:
                connection.execute("BEGIN IMMEDIATE")
                began = True
                self._meta(connection)
                self._recover_expired(connection, now)
                row = connection.execute("SELECT * FROM outbox_jobs WHERE status='DISCOVERED' AND next_eligible_ms<=? ORDER BY discovery_sequence LIMIT 1", (now,)).fetchone()
                if row is None:
                    connection.execute("COMMIT")
                    began = False
                    return None
                attempt = int(row[7]) + 1
                if attempt > self.config.max_attempts:
                    raise OfficialHandoffLeaseError("handoff_attempts_exhausted")
                token = secrets.token_bytes(24)
                expires = now + self.config.lease_seconds * 1000
                changed = connection.execute("UPDATE outbox_jobs SET status='LEASED',attempt=?,updated_ms=? WHERE job_id=? AND status='DISCOVERED' AND attempt=?", (attempt, now, str(row[0]), int(row[7])))
                if changed.rowcount != 1:
                    raise OfficialHandoffLeaseError("handoff_claim_cas")
                connection.execute("INSERT INTO outbox_leases VALUES (?,?,?,?,?,?)", (str(row[0]), worker_id, token, attempt, now, expires))
                self._append_transition(connection, kind="CLAIM", job_id=str(row[0]), event={"at_ms": now, "status": "LEASED", "attempt": attempt, "worker_id": worker_id, "expires_ms": expires})
                connection.execute("COMMIT")
                began = False
                return OfficialHandoffWorkV1(self.config.outbox_id, str(row[0]), bytes(row[1]), attempt, worker_id, token, expires, bytes(row[3]), bytes(row[4]))
            except Exception:
                if began and connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def _existing_ack(self, job_id: str) -> OfficialHandoffResultV1 | None:
        with closing(self._connect()) as connection:
            row = connection.execute("SELECT * FROM outbox_acks WHERE job_id=?", (job_id,)).fetchone()
        if row is None:
            return None
        return OfficialHandoffResultV1(str(row[0]), bytes(row[4]), "ACKNOWLEDGED", bytes(row[2]), bytes(row[3]), int(row[5]), None)

    def _held(self, work: OfficialHandoffWorkV1, code: str) -> OfficialHandoffResultV1:
        now = int(self.clock.now_ms())
        with closing(self._connect()) as connection:
            began = False
            try:
                connection.execute("BEGIN IMMEDIATE")
                began = True
                self._live_lease(connection, work)
                connection.execute("DELETE FROM outbox_leases WHERE job_id=?", (work.job_id,))
                connection.execute("UPDATE outbox_jobs SET status='HELD',updated_ms=?,last_error_code=? WHERE job_id=? AND status='LEASED'", (now, code, work.job_id))
                self._append_transition(connection, kind="HELD", job_id=work.job_id, event={"at_ms": now, "status": "HELD", "attempt": work.attempt, "error_code": code})
                connection.execute("COMMIT")
                began = False
            except Exception:
                if began and connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return OfficialHandoffResultV1(work.job_id, work.operation_id, "HELD", None, None, 0, code)

    def dispatch(self, work: OfficialHandoffWorkV1, *, application_database: Path, state_database: Path, receiver: OfficialStateReceiverPort) -> OfficialHandoffResultV1:
        self._validate_work(work)
        existing = self._existing_ack(work.job_id)
        if existing is not None:
            return existing
        with closing(self._connect()) as connection:
            self._live_lease(connection, work)
        try:
            identity = receiver.identity_sha256()
            epoch = receiver.epoch()
            if identity != self.config.receiver_identity or epoch != self.config.receiver_epoch:
                return self._held(work, "receiver_identity_drift")
            view = read_applied_application(
                application_database, state_database, expected_application_id=self.config.application_id,
                expected_application_config_digest=self.config.application_config_digest,
                expected_state_store_identity=self.config.state_store_identity,
                expected_verifier_sha256=self.config.verifier_sha256, job_id=work.job_id,
            )
            envelope = build_directive_envelope(view, self.config)
            if envelope != work.envelope_bytes:
                return self._held(work, "handoff_envelope_drift")
            ack_raw = receiver.dispatch(envelope, work.idempotency_key)
            if type(ack_raw) is not bytes:
                return self._held(work, "receiver_ack_type")
            ack = parse_acknowledgment_bytes(ack_raw)
            if (
                bytes.fromhex(ack["receiver_identity"]) != self.config.receiver_identity
                or int(ack["receiver_epoch"]) != self.config.receiver_epoch
                or bytes.fromhex(ack["idempotency_key"]) != work.idempotency_key
                or bytes.fromhex(ack["envelope_digest"]) != envelope_digest(envelope)
                or int(ack["effective_directive"]) != int(parse_envelope_bytes(envelope)["effective_directive"])
            ):
                return self._held(work, "receiver_ack_binding")
        except (IndependentOfficialHandoffError, OSError):
            return self._held(work, "handoff_reverification_failed")
        self._fault("after_dispatch_before_outbox_commit")
        now = int(self.clock.now_ms())
        ack_digest = acknowledgment_digest(ack_raw)
        with closing(self._connect()) as connection:
            began = False
            try:
                connection.execute("BEGIN IMMEDIATE")
                began = True
                try:
                    self._live_lease(connection, work)
                except OfficialHandoffLeaseError as exc:
                    raise OfficialHandoffIndeterminateError("handoff_lease_lost_after_dispatch") from exc
                connection.execute("DELETE FROM outbox_leases WHERE job_id=?", (work.job_id,))
                changed = connection.execute("UPDATE outbox_jobs SET status='ACKNOWLEDGED',updated_ms=?,last_error_code=NULL WHERE job_id=? AND status='LEASED'", (now, work.job_id))
                if changed.rowcount != 1:
                    raise OfficialHandoffIndeterminateError("handoff_job_cas_after_dispatch")
                connection.execute("INSERT INTO outbox_acks VALUES (?,?,?,?,?,?,?)", (work.job_id, "ACKNOWLEDGED", ack_raw, ack_digest, work.operation_id, 1, now))
                self._append_transition(connection, kind="ACKNOWLEDGED", job_id=work.job_id, event={"at_ms": now, "status": "ACKNOWLEDGED", "attempt": work.attempt, "ack_digest": _hex(ack_digest), "effective_directive": int(ack["effective_directive"])})
                self._fault("before_outbox_commit")
                connection.execute("COMMIT")
                began = False
            except Exception:
                if began and connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        if self._after_commit_fault is not None:
            try:
                self._after_commit_fault("after_outbox_commit")
            except Exception as exc:
                raise OfficialHandoffIndeterminateError("handoff_commit_indeterminate") from exc
        return OfficialHandoffResultV1(work.job_id, work.operation_id, "ACKNOWLEDGED", ack_raw, ack_digest, 1, None)

    def snapshot(self) -> dict[str, Any]:
        with closing(self._connect()) as connection:
            meta = self._meta(connection)
            counts = {status: int(connection.execute("SELECT COUNT(*) FROM outbox_jobs WHERE status=?", (status,)).fetchone()[0]) for status in sorted(_STATUS)}
            transitions = int(connection.execute("SELECT COUNT(*) FROM outbox_transitions").fetchone()[0])
        return {"schema": _SCHEMA, "status_counts": counts, "head_root": _hex(bytes(meta[10])), "transition_count": transitions}

    def support_summary(self) -> dict[str, Any]:
        snap = self.snapshot()
        with closing(self._connect()) as connection:
            duplicate = int(connection.execute("SELECT COALESCE(SUM(delivery_count-1),0) FROM outbox_acks").fetchone()[0])
            directives = {str(int(row[0])): int(row[1]) for row in connection.execute("SELECT json_extract(json_extract(CAST(event_bytes AS TEXT),'$'), '$.effective_directive'), COUNT(*) FROM outbox_transitions WHERE transition_kind='DISCOVER' GROUP BY 1")}
        return {**snap, "receiver_identity": _hex(self.config.receiver_identity), "duplicate_delivery_count": duplicate, "directive_counts": directives, "proof_suite_id": None, "production_usable": False, "activation": False}

    def export_bytes(self) -> bytes:
        self.verify_integrity()
        with closing(self._connect()) as connection:
            meta = self._meta(connection)
            blob = lambda value: None if value is None else _hex(bytes(value))
            value = {
                "schema": _SCHEMA, "config": self.config.as_json(),
                "metadata": {"head_root": blob(meta[10]), "next_sequence": int(meta[11])},
                "jobs": [{"job_id": str(row[0]), "operation_id": blob(row[1]), "envelope_digest": blob(row[2]), "envelope_bytes": blob(row[3]), "idempotency_key": blob(row[4]), "status": str(row[5]), "discovery_sequence": int(row[6]), "attempt": int(row[7]), "next_eligible_ms": int(row[8]), "created_ms": int(row[9]), "updated_ms": int(row[10]), "last_error_code": row[11]} for row in connection.execute("SELECT * FROM outbox_jobs ORDER BY discovery_sequence")],
                "leases": [{"job_id": str(row[0]), "worker_id": str(row[1]), "token": blob(row[2]), "attempt": int(row[3]), "leased_ms": int(row[4]), "expires_ms": int(row[5])} for row in connection.execute("SELECT * FROM outbox_leases ORDER BY job_id")],
                "acks": [{"job_id": str(row[0]), "ack_bytes": blob(row[2]), "ack_digest": blob(row[3]), "operation_id": blob(row[4]), "delivery_count": int(row[5]), "completed_ms": int(row[6])} for row in connection.execute("SELECT * FROM outbox_acks ORDER BY job_id")],
                "transitions": [{"sequence": int(row[0]), "transition_kind": str(row[1]), "job_id": str(row[2]), "before_root": blob(row[3]), "after_root": blob(row[4]), "event_bytes": blob(row[5]), "event_digest": blob(row[6])} for row in connection.execute("SELECT * FROM outbox_transitions ORDER BY sequence")],
            }
        raw = _json_bytes(value)
        if len(raw) > _MAX_EXPORT:
            raise OfficialHandoffIntegrityError("handoff_export_bounds")
        return raw

    def verify_integrity(self) -> None:
        try:
            independent_verify_database(self.path, expected_config=self.config.as_json())
        except IndependentOfficialHandoffError as exc:
            raise OfficialHandoffIntegrityError("handoff_integrity") from exc

    def restore_from_export(self, path: Path, raw: bytes) -> dict[str, Any]:
        try:
            return restore_export_to_fresh_database(path, raw)
        except IndependentOfficialHandoffError as exc:
            raise OfficialHandoffIntegrityError("handoff_restore") from exc


__all__ = (
    "OfficialHandoffConfigV1", "OfficialHandoffError",
    "OfficialHandoffConflictError", "OfficialHandoffIndeterminateError", "OfficialHandoffIntegrityError",
    "OfficialHandoffJobV1", "OfficialHandoffLeaseError", "OfficialHandoffResultV1",
    "OfficialHandoffStoreV1", "OfficialHandoffWorkV1", "OfficialStateReceiverPort",
    "build_directive_envelope", "independent_verify_database", "independent_verify_export_bytes",
)
