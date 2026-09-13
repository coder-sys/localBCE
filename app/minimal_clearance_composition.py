"""State-owned Queue/Proof Handoff V8 composition.

Verifier output contributes only ``proof_accepted`` and its opaque receipt.
Disposition is computed from a separate state-owned control. Complete ordered
batches are preflighted against one pure in-memory state snapshot before the
single SQLite transaction writes a row, event, state root, or outbox item.
"""

from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import secrets
import sqlite3
import time
from typing import Any, Callable, Final, Mapping, NoReturn, Protocol

from app.minimal_clearance_verification_queue_independent import IndependentVerifiedQueueJob


class CompositionError(RuntimeError):
    pass


class CompositionConflictError(CompositionError):
    pass


class CompositionBackpressureError(CompositionError):
    pass


class CompositionLeaseError(CompositionError):
    pass


class CompositionIntegrityError(CompositionError):
    pass


class CompositionIndeterminateError(CompositionError):
    pass


def _fail(error_type: type[CompositionError], code: str) -> NoReturn:
    error = error_type(code)
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    raise error


_SCHEMA_VERSION: Final[int] = 4
_SCHEMA: Final[str] = "BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/v4"
_HANDOFF_SCHEMA: Final[str] = "BL/NATIVE-V3/MINIMAL-CLEARANCE/OFFICIAL-HANDOFF/v3"
_DIRECTIVES: Final[tuple[str, ...]] = ("CLEAR", "HOLD", "HUMAN_REVIEW", "BLOCK", "EXCEPTION_APPROVED")
_POLICY_RESULTS: Final[tuple[str, ...]] = ("PASS", "MISSING", "AMBIGUOUS", "FAIL")
_MATERIAL = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/MATERIAL/v4\x00"
_GENESIS = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/GENESIS/v4\x00"
_EVENT = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/EVENT/v4\x00"
_HEAD = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/HEAD/v4\x00"
_STATE = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/STATE/v4\x00"
_TOKEN = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
_CODE = re.compile(r"[a-z][a-z0-9_]{0,95}\Z")
_ZERO = bytes(64)
_INITIAL_PAYMENT = bytes(64)
_LEASE = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/LEASE/v4\x00"
_OUTBOX_BATCH_CAPACITY: Final[int] = 100
_EVENT_PAYLOAD_KEYS = {"APPLIED": frozenset({"operation_ref", "proof_accepted", "policy_result", "effective_directive", "state_receipt_digest", "sequence_before", "sequence_after"})}


def _sha(domain: bytes, *parts: bytes) -> bytes:
    digest = hashlib.sha3_512()
    digest.update(domain)
    for part in parts:
        if type(part) is not bytes:
            _fail(CompositionIntegrityError, "binding_type")
        digest.update(part)
    return digest.digest()


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        _fail(CompositionIntegrityError, "json")


def _hex(value: bytes) -> str:
    return value.hex().upper()


def _u64(value: int) -> bytes:
    if type(value) is not int or not 0 <= value < 2**64:
        _fail(CompositionIntegrityError, "integer")
    return value.to_bytes(8, "big")


def _blob(value: object, size: int, code: str) -> bytes:
    if type(value) is not bytes or len(value) != size:
        _fail(CompositionIntegrityError, code)
    return bytes(value)


def _token(value: object, code: str) -> str:
    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        _fail(CompositionIntegrityError, code)
    return value


def _code(value: object, code: str) -> str:
    if type(value) is not str or _CODE.fullmatch(value) is None:
        _fail(CompositionIntegrityError, code)
    return value


def resolve_effective_directive(policy_result: str, exception_approved: bool = False) -> str:
    if policy_result == "PASS":
        return "CLEAR"
    if policy_result == "MISSING":
        return "HOLD"
    if policy_result == "AMBIGUOUS":
        return "HUMAN_REVIEW"
    if policy_result == "FAIL":
        return "EXCEPTION_APPROVED" if exception_approved else "BLOCK"
    _fail(CompositionIntegrityError, "policy_result")


@dataclass(frozen=True, slots=True)
class StateDispositionControl:
    """State-owner input; it is never produced by the verifier."""

    operation_ref: bytes
    policy_result: str
    exception_approved: bool = False
    exception_authorization_id: bytes = _ZERO
    state_profile_identity: bytes = _ZERO
    predecessor_state_id: bytes = _ZERO
    predecessor_state_bytes: bytes = _ZERO
    epoch: int = 1
    sequence_before: int = 0
    predecessor_continuity_root: bytes = _ZERO
    predecessor_audit_head: bytes = _ZERO
    predecessor_clearance_root: bytes = _ZERO
    clearance_marker_before: int = 0
    clearance_count_before: int = 0
    state_after_id: bytes = _ZERO
    state_after_bytes: bytes = _ZERO
    state_after_continuity_root: bytes = _ZERO
    state_after_clearance_root: bytes = _ZERO
    decision_id: bytes = _ZERO
    economic_mutation: bool = False
    payment_root: bytes = _INITIAL_PAYMENT
    sequence_after: int | None = None
    clearance_marker_after: int | None = None
    clearance_count_after: int | None = None

    def __post_init__(self) -> None:
        _blob(self.operation_ref, 32, "operation_ref")
        if self.policy_result not in _POLICY_RESULTS:
            _fail(CompositionIntegrityError, "policy_result")
        if type(self.exception_approved) is not bool or type(self.economic_mutation) is not bool or self.economic_mutation:
            _fail(CompositionIntegrityError, "state_economic_mutation")
        for value, code in ((self.exception_authorization_id, "exception_authorization_id"), (self.state_profile_identity, "state_profile_identity"), (self.predecessor_state_id, "predecessor_state_id"), (self.predecessor_state_bytes, "predecessor_state_bytes"), (self.predecessor_continuity_root, "predecessor_continuity_root"), (self.predecessor_audit_head, "predecessor_audit_head"), (self.state_after_id, "state_after_id"), (self.state_after_bytes, "state_after_bytes"), (self.state_after_continuity_root, "state_after_continuity_root"), (self.state_after_clearance_root, "state_after_clearance_root"), (self.decision_id, "decision_id"), (self.payment_root, "payment_root")):
            _blob(value, 64, code)
        _blob(self.predecessor_clearance_root, 64, "predecessor_clearance_root")
        if type(self.epoch) is not int or self.epoch < 1 or type(self.sequence_before) is not int or self.sequence_before < 0 or type(self.clearance_marker_before) is not int or self.clearance_marker_before not in (0, 1) or type(self.clearance_count_before) is not int or self.clearance_count_before < 0:
            _fail(CompositionIntegrityError, "state_control_shape")
        if self.state_after_id == _ZERO:
            object.__setattr__(self, "state_after_id", _sha(_STATE, b"state-after", self.operation_ref, self.sequence_before.to_bytes(8, "big")))
        if self.state_after_bytes == _ZERO:
            object.__setattr__(self, "state_after_bytes", _sha(_STATE, b"state-bytes", self.operation_ref, self.sequence_before.to_bytes(8, "big")))
        expected_after_id = _sha(_STATE, b"state-after", self.operation_ref, self.sequence_before.to_bytes(8, "big"))
        expected_after_bytes = _sha(_STATE, b"state-bytes", self.operation_ref, self.sequence_before.to_bytes(8, "big"))
        if self.state_after_id != expected_after_id or self.state_after_bytes != expected_after_bytes:
            _fail(CompositionIntegrityError, "state_after_binding")
        if self.decision_id == _ZERO:
            object.__setattr__(self, "decision_id", _sha(_STATE, b"decision", self.operation_ref))
        if self.sequence_after is not None and (type(self.sequence_after) is not int or self.sequence_after != self.sequence_before + 1):
            _fail(CompositionIntegrityError, "state_sequence")
        advanced = resolve_effective_directive(self.policy_result, self.exception_approved) in {"CLEAR", "EXCEPTION_APPROVED"}
        if self.exception_approved != (self.policy_result == "FAIL" and self.exception_authorization_id != _ZERO):
            _fail(CompositionIntegrityError, "exception_authorization")
        if self.policy_result != "FAIL" and self.exception_authorization_id != _ZERO:
            _fail(CompositionIntegrityError, "exception_authorization")
        expected_count = self.clearance_count_before + int(advanced)
        expected_marker = int(bool(self.clearance_marker_before or advanced))
        if self.clearance_count_after is not None and self.clearance_count_after != expected_count:
            _fail(CompositionIntegrityError, "state_clearance_count")
        if self.clearance_marker_after is not None and self.clearance_marker_after != expected_marker:
            _fail(CompositionIntegrityError, "state_clearance_marker")
        expected_continuity = _sha(_STATE, self.predecessor_continuity_root, self.state_after_id, self.effective_directive.encode("ascii"))
        if self.state_after_continuity_root == _ZERO:
            object.__setattr__(self, "state_after_continuity_root", expected_continuity)
        elif self.state_after_continuity_root != expected_continuity:
            _fail(CompositionIntegrityError, "state_continuity_root")
        expected_clearance = self.predecessor_clearance_root
        if advanced:
            expected_clearance = _sha(_STATE, self.predecessor_clearance_root, self.state_after_id, self.effective_directive.encode("ascii"))
        if self.state_after_clearance_root == _ZERO:
            object.__setattr__(self, "state_after_clearance_root", expected_clearance)
        elif self.state_after_clearance_root != expected_clearance:
            _fail(CompositionIntegrityError, "state_clearance_root")

    @property
    def effective_directive(self) -> str:
        return resolve_effective_directive(self.policy_result, self.exception_approved)


@dataclass(frozen=True, slots=True)
class SyntheticAckEvidenceProfileV2:
    verifier_identity: bytes
    verifier_epoch: int
    receiver_identity: bytes
    receiver_epoch: int
    mode: str = "SYNTHETIC_ONLY"
    proof_suite_id: None = None
    production_usable: bool = False
    activation: bool = False

    def __post_init__(self) -> None:
        _blob(self.verifier_identity, 32, "profile_verifier")
        _blob(self.receiver_identity, 32, "profile_receiver")
        if type(self.verifier_epoch) is not int or self.verifier_epoch < 1 or type(self.receiver_epoch) is not int or self.receiver_epoch < 1 or self.mode != "SYNTHETIC_ONLY" or self.proof_suite_id is not None or type(self.production_usable) is not bool or self.production_usable is not False or type(self.activation) is not bool or self.activation is not False:
            _fail(CompositionIntegrityError, "profile_nonactivation")

    @property
    def canonical_bytes(self) -> bytes:
        return _json_bytes({"schema_version": 3, "mode": self.mode, "verifier_epoch": self.verifier_epoch, "receiver_epoch": self.receiver_epoch, "proof_suite_id": None, "production_usable": False, "activation": False})

    @property
    def digest(self) -> bytes:
        return _sha(_MATERIAL, self.canonical_bytes)


@dataclass(frozen=True, slots=True)
class CompositionConfigV2:
    queue_id: str
    queue_config_digest: bytes
    verifier_profile_identity: bytes = bytes(32)
    receiver_identity: bytes = bytes(32)
    receiver_epoch: int = 1
    composition_id: str = "minimal-clearance-state-v10"
    verifier_epoch: int = 1
    capacity: int = 100
    lease_seconds: int = 300
    reconciliation_capacity: int = 16
    reconciliation_lease_seconds: int = 300
    max_attempts: int = 3
    busy_timeout_ms: int = 5_000
    proof_suite_id: None = None
    production_usable: bool = False
    activation: bool = False

    def __post_init__(self) -> None:
        _token(self.queue_id, "queue_id")
        _token(self.composition_id, "composition_id")
        _blob(self.queue_config_digest, 64, "queue_config_digest")
        _blob(self.verifier_profile_identity, 32, "verifier_profile")
        _blob(self.receiver_identity, 32, "receiver_identity")
        if type(self.capacity) is not int or not 1 <= self.capacity <= 10_000 or type(self.verifier_epoch) is not int or self.verifier_epoch < 1 or type(self.receiver_epoch) is not int or self.receiver_epoch < 1 or type(self.max_attempts) is not int or self.max_attempts != 3 or self.proof_suite_id is not None or type(self.production_usable) is not bool or self.production_usable is not False or type(self.activation) is not bool or self.activation is not False:
            _fail(CompositionIntegrityError, "composition_config")
        if type(self.lease_seconds) is not int or not 1 <= self.lease_seconds <= 86_400 or type(self.reconciliation_capacity) is not int or not 1 <= self.reconciliation_capacity <= 10_000 or type(self.reconciliation_lease_seconds) is not int or not 1 <= self.reconciliation_lease_seconds <= 86_400 or type(self.busy_timeout_ms) is not int or not 1 <= self.busy_timeout_ms <= 60_000:
            _fail(CompositionIntegrityError, "composition_delivery_config")

    @property
    def profile_digest(self) -> bytes:
        return _sha(_MATERIAL, b"synthetic-ack-profile", self.receiver_identity, self.verifier_profile_identity)

    @property
    def as_json(self) -> dict[str, Any]:
        return {"schema_version": _SCHEMA_VERSION, "composition_id": self.composition_id, "queue_id": self.queue_id, "queue_config_digest": _hex(self.queue_config_digest), "capacity": self.capacity, "verifier_profile_identity": _hex(self.verifier_profile_identity), "verifier_epoch": self.verifier_epoch, "receiver_identity": _hex(self.receiver_identity), "receiver_epoch": self.receiver_epoch, "lease_seconds": self.lease_seconds, "reconciliation_capacity": self.reconciliation_capacity, "reconciliation_lease_seconds": self.reconciliation_lease_seconds, "max_attempts": self.max_attempts, "busy_timeout_ms": self.busy_timeout_ms, "directives": list(_DIRECTIVES), "policy_results": list(_POLICY_RESULTS), "proof_suite_id": None, "production_usable": False, "activation": False}

    @property
    def canonical_bytes(self) -> bytes:
        return _json_bytes(self.as_json)

    @property
    def digest(self) -> bytes:
        return _sha(_MATERIAL, self.canonical_bytes)

    @property
    def acknowledgment_profile(self) -> SyntheticAckEvidenceProfileV2:
        return SyntheticAckEvidenceProfileV2(self.verifier_profile_identity, self.verifier_epoch, self.receiver_identity, self.receiver_epoch)


@dataclass(frozen=True, slots=True)
class CompositionProcessResultV2:
    job_id: str
    operation_id: bytes
    status: str
    disposition_id: bytes
    state_receipt_bytes: bytes | None
    state_receipt_digest: bytes | None
    outbox_job_id: str | None
    outbox_operation_id: bytes | None
    duplicate_convergence: bool
    error_code: str | None


@dataclass(frozen=True, slots=True)
class CompositionOutboxWorkV2:
    composition_id: str
    job_id: str
    operation_id: bytes
    attempt: int
    worker_id: str
    lease_token: bytes
    lease_expires_ms: int
    envelope_bytes: bytes
    idempotency_key: bytes
    effective_directive: str = "HOLD"


@dataclass(frozen=True, slots=True)
class CompositionReconciliationWorkV2:
    composition_id: str
    job_id: str
    operation_id: bytes
    attempt: int
    worker_id: str
    lease_token: bytes
    lease_expires_ms: int
    effective_directive: str
    envelope_digest: bytes
    idempotency_key: bytes


@dataclass(frozen=True, slots=True)
class CompositionDeliveryResultV2:
    job_id: str
    operation_id: bytes
    status: str
    acknowledgment_bytes: bytes | None
    acknowledgment_digest: bytes | None
    error_code: str | None
    qualification_receipt: bytes | None = None
    profile_digest: bytes | None = None
    acknowledgment_id: str | None = None


@dataclass(frozen=True, slots=True)
class CompositionOutboxBatchWorkV2:
    composition_id: str
    worker_id: str
    works: tuple[CompositionOutboxWorkV2, ...]
    has_more: bool


@dataclass(frozen=True, slots=True)
class CompositionReconciliationBatchWorkV2:
    composition_id: str
    worker_id: str
    works: tuple[CompositionReconciliationWorkV2, ...]
    has_more: bool


@dataclass(frozen=True, slots=True)
class CompositionBatchDeliveryResultV2:
    composition_id: str
    worker_id: str
    operation: str
    results: tuple[CompositionDeliveryResultV2, ...]
    has_more: bool


class CompositionClock(Protocol):
    def now_ms(self) -> int: ...


class _SystemClock:
    def now_ms(self) -> int:
        return time.time_ns() // 1_000_000


class OfficialStateReceiverPort(Protocol):
    """The receiver must durably deduplicate the supplied idempotency key.

    The local outbox preserves a stable key across retries but cannot prove that
    an external receiver has durable idempotency. Lease expiry during an in-flight
    call therefore remains an acknowledged ambiguity at this boundary.
    """

    def identity_sha256(self) -> bytes: ...
    def epoch(self) -> int: ...
    def dispatch(self, envelope_bytes: bytes, idempotency_key: bytes) -> bytes: ...


class OfficialStateReceiverLookupPort(Protocol):
    """Lookup port for reconciling an externally durable acknowledgment."""

    def acknowledgment_profile(self) -> SyntheticAckEvidenceProfileV2: ...
    def lookup_acknowledgment(self, **query: Any) -> bytes | None: ...


def _envelope(operation_ref: bytes, directive: str, config: CompositionConfigV2) -> bytes:
    value = {"schema": _HANDOFF_SCHEMA, "operation_ref": _hex(operation_ref), "effective_directive": directive, "proof_acceptance_is_clear": False, "payment_authority": False, "proof_suite_id": None, "production_usable": False, "activation": False}
    return _json_bytes(value)


def build_synthetic_acknowledgment(envelope_bytes: bytes, *, config: CompositionConfigV2, idempotency_key: bytes, accepted_ms: int) -> bytes:
    try:
        envelope = json.loads(envelope_bytes.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail(CompositionIntegrityError, "ack_envelope")
    if type(envelope) is not dict or set(envelope) != {"schema", "operation_ref", "effective_directive", "proof_acceptance_is_clear", "payment_authority", "proof_suite_id", "production_usable", "activation"} or envelope["schema"] != _HANDOFF_SCHEMA or envelope["proof_acceptance_is_clear"] is not False or envelope["payment_authority"] is not False or envelope["proof_suite_id"] is not None or type(envelope["production_usable"]) is not bool or envelope["production_usable"] is not False or type(envelope["activation"]) is not bool or envelope["activation"] is not False:
        _fail(CompositionIntegrityError, "ack_envelope")
    _blob(idempotency_key, 64, "idempotency_key")
    return _json_bytes({"schema": _HANDOFF_SCHEMA, "operation_ref": envelope["operation_ref"], "effective_directive": envelope["effective_directive"], "accepted_ms": accepted_ms, "acknowledgment_id": _hex(_sha(_MATERIAL, envelope_bytes, idempotency_key, str(accepted_ms).encode("ascii")))})


def _parse_acknowledgment(raw: bytes, *, envelope_bytes: bytes, idempotency_key: bytes, operation_ref: bytes, directive: str) -> bytes:
    if type(raw) is not bytes or not 0 < len(raw) <= 16 * 1024:
        _fail(CompositionIntegrityError, "ack_shape")
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail(CompositionIntegrityError, "ack_shape")
    if type(value) is not dict or set(value) != {"schema", "operation_ref", "effective_directive", "accepted_ms", "acknowledgment_id"} or raw != _json_bytes(value) or value["schema"] != _HANDOFF_SCHEMA or value["operation_ref"] != _hex(operation_ref) or value["effective_directive"] != directive or type(value["accepted_ms"]) is not int or value["accepted_ms"] < 0:
        _fail(CompositionIntegrityError, "ack_shape")
    if type(value["acknowledgment_id"]) is not str or value["acknowledgment_id"] != value["acknowledgment_id"].upper() or re.fullmatch(r"[0-9A-F]{128}\Z", value["acknowledgment_id"]) is None:
        _fail(CompositionIntegrityError, "acknowledgment_id")
    _blob(idempotency_key, 64, "idempotency_key")
    expected = _hex(_sha(_MATERIAL, envelope_bytes, idempotency_key, str(value["accepted_ms"]).encode("ascii")))
    if value["acknowledgment_id"] != expected:
        _fail(CompositionIntegrityError, "ack_binding")
    return raw


_QUEUE_TABLES = frozenset(("queue_metadata", "queue_batches", "queue_members", "queue_leases", "queue_attempts", "queue_source_admissions", "queue_results", "queue_transitions"))
_COMPOSITION_TABLES = frozenset(("composition_meta", "composition_transactions", "composition_events", "composition_outbox"))
_META_COLUMNS = ("id", "schema_version", "config_json", "config_digest", "event_head", "next_event_sequence", "state_profile_identity", "state_id", "state_bytes", "state_epoch", "state_sequence", "state_continuity_root", "state_audit_head", "state_clearance_root", "state_clearance_count", "payment_root", "active_dispatch_count")
_TX_COLUMNS = ("transaction_id", "operation_ref", "status", "proof_accepted", "policy_result", "effective_directive", "disposition_id", "state_profile_identity", "state_before_id", "state_after_id", "sequence_before", "sequence_after", "state_receipt_bytes", "state_receipt_digest", "error_code", "created_ms", "updated_ms")
_EVENT_COLUMNS = ("sequence", "operation_ref", "event_kind", "before_state", "after_state", "payload", "event_digest", "event_root", "at_ms")
_OUTBOX_COLUMNS = ("operation_ref", "effective_directive", "status", "attempt", "worker_id", "lease_token", "lease_expires_ms", "updated_ms")
_COMPOSITION_TABLE_SQL = {
    "composition_meta": "CREATE TABLE composition_meta (id INTEGER PRIMARY KEY CHECK(id=1), schema_version INTEGER NOT NULL CHECK(schema_version=4), config_json BLOB NOT NULL, config_digest BLOB NOT NULL CHECK(length(config_digest)=64), event_head BLOB NOT NULL CHECK(length(event_head)=64), next_event_sequence INTEGER NOT NULL CHECK(next_event_sequence>=0), state_profile_identity BLOB, state_id BLOB, state_bytes BLOB, state_epoch INTEGER, state_sequence INTEGER, state_continuity_root BLOB, state_audit_head BLOB, state_clearance_root BLOB, state_clearance_count INTEGER, payment_root BLOB NOT NULL CHECK(length(payment_root)=64), active_dispatch_count INTEGER NOT NULL CHECK(active_dispatch_count>=0))",
    "composition_transactions": "CREATE TABLE composition_transactions (transaction_id BLOB PRIMARY KEY CHECK(length(transaction_id)=64), operation_ref BLOB NOT NULL UNIQUE CHECK(length(operation_ref)=32) REFERENCES queue_members(operation_ref), status TEXT NOT NULL CHECK(status IN ('APPLIED','HELD')), proof_accepted INTEGER NOT NULL CHECK(proof_accepted IN (0,1)), policy_result TEXT NOT NULL CHECK(policy_result IN ('PASS','MISSING','AMBIGUOUS','FAIL')), effective_directive TEXT NOT NULL CHECK(effective_directive IN ('CLEAR','HOLD','HUMAN_REVIEW','BLOCK','EXCEPTION_APPROVED')), disposition_id BLOB NOT NULL CHECK(length(disposition_id)=64), state_profile_identity BLOB NOT NULL CHECK(length(state_profile_identity)=64), state_before_id BLOB NOT NULL CHECK(length(state_before_id)=64), state_after_id BLOB NOT NULL CHECK(length(state_after_id)=64), sequence_before INTEGER NOT NULL, sequence_after INTEGER NOT NULL, state_receipt_bytes BLOB, state_receipt_digest BLOB, error_code TEXT, created_ms INTEGER NOT NULL, updated_ms INTEGER NOT NULL)",
    "composition_events": "CREATE TABLE composition_events (sequence INTEGER PRIMARY KEY CHECK(sequence>=1), operation_ref BLOB NOT NULL CHECK(length(operation_ref)=32) REFERENCES queue_members(operation_ref), event_kind TEXT NOT NULL CHECK(event_kind IN ('APPLIED','HELD','DISPATCH_LEASED','ACKNOWLEDGED','DELIVERY_UNCONFIRMED','LEASE_EXPIRED')), before_state TEXT NOT NULL, after_state TEXT NOT NULL, payload BLOB NOT NULL CHECK(length(payload)<=4096), event_digest BLOB NOT NULL UNIQUE CHECK(length(event_digest)=64), event_root BLOB NOT NULL CHECK(length(event_root)=64), at_ms INTEGER NOT NULL)",
    "composition_outbox": "CREATE TABLE composition_outbox (operation_ref BLOB PRIMARY KEY CHECK(length(operation_ref)=32) REFERENCES queue_members(operation_ref), effective_directive TEXT NOT NULL CHECK(effective_directive IN ('CLEAR','HOLD','HUMAN_REVIEW','BLOCK','EXCEPTION_APPROVED')), status TEXT NOT NULL CHECK(status IN ('READY','LEASED','ACKNOWLEDGED','DELIVERY_UNCONFIRMED')), attempt INTEGER NOT NULL CHECK(attempt BETWEEN 0 AND 3), worker_id TEXT, lease_token BLOB, lease_expires_ms INTEGER, updated_ms INTEGER NOT NULL)",
}
_COMPOSITION_TRIGGER_SQL = {
    "composition_transactions_no_delete": "CREATE TRIGGER composition_transactions_no_delete BEFORE DELETE ON composition_transactions BEGIN SELECT RAISE(ABORT,'composition_append_only'); END",
    "composition_events_no_update": "CREATE TRIGGER composition_events_no_update BEFORE UPDATE ON composition_events BEGIN SELECT RAISE(ABORT,'composition_append_only'); END",
    "composition_events_no_delete": "CREATE TRIGGER composition_events_no_delete BEFORE DELETE ON composition_events BEGIN SELECT RAISE(ABORT,'composition_append_only'); END",
}


def _create_composition_schema(connection: sqlite3.Connection, config: CompositionConfigV2) -> None:
    """Create the Composition half of an already-open State database."""
    for table in ("composition_meta", "composition_transactions", "composition_events", "composition_outbox"):
        connection.execute(_COMPOSITION_TABLE_SQL[table])
    connection.execute("CREATE INDEX composition_outbox_ready_idx ON composition_outbox(status,updated_ms)")
    for trigger in ("composition_transactions_no_delete", "composition_events_no_update", "composition_events_no_delete"):
        connection.execute(_COMPOSITION_TRIGGER_SQL[trigger])
    head = _sha(_GENESIS, config.digest)
    connection.execute("INSERT INTO composition_meta VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (1, _SCHEMA_VERSION, config.canonical_bytes, config.digest, head, 0, None, None, None, None, None, None, None, None, None, _INITIAL_PAYMENT, 0))


def _check_composition_schema(connection: sqlite3.Connection, config: CompositionConfigV2, *, require_queue: bool = True) -> None:
    tables = {str(row[0]) for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
    expected = _COMPOSITION_TABLES | (_QUEUE_TABLES if require_queue else frozenset())
    if tables != expected:
        _fail(CompositionIntegrityError, "composition_schema")
    if tuple(str(row[1]) for row in connection.execute("PRAGMA table_info(composition_meta)")) != _META_COLUMNS or tuple(str(row[1]) for row in connection.execute("PRAGMA table_info(composition_transactions)")) != _TX_COLUMNS or tuple(str(row[1]) for row in connection.execute("PRAGMA table_info(composition_events)")) != _EVENT_COLUMNS or tuple(str(row[1]) for row in connection.execute("PRAGMA table_info(composition_outbox)")) != _OUTBOX_COLUMNS:
        _fail(CompositionIntegrityError, "composition_schema")
    table_sql = {str(row[0]): str(row[1]) for row in connection.execute("SELECT name,sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
    if any(re.sub(r"\s+", " ", table_sql[name].strip()).lower() != re.sub(r"\s+", " ", expected.strip()).lower() for name, expected in _COMPOSITION_TABLE_SQL.items()):
        _fail(CompositionIntegrityError, "composition_schema")
    triggers = {str(row[0]) for row in connection.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
    expected_triggers = set(_COMPOSITION_TRIGGER_SQL)
    if not expected_triggers.issubset(triggers):
        _fail(CompositionIntegrityError, "composition_schema")
    trigger_rows = {str(row[0]): str(row[1]) for row in connection.execute("SELECT name,sql FROM sqlite_master WHERE type='trigger'")}
    if any(re.sub(r"\s+", " ", trigger_rows[name].strip()).lower() != re.sub(r"\s+", " ", expected.strip()).lower() for name, expected in _COMPOSITION_TRIGGER_SQL.items()):
        _fail(CompositionIntegrityError, "composition_schema")
    row = connection.execute("SELECT schema_version,config_json,config_digest FROM composition_meta WHERE id=1").fetchone()
    if row is None or int(row[0]) != _SCHEMA_VERSION or bytes(row[2]) != config.digest or bytes(row[1]) != config.canonical_bytes:
        _fail(CompositionIntegrityError, "composition_schema")


class ClearanceCompositionStoreV2:
    def __init__(self, *, path: Path, config: CompositionConfigV2, clock: CompositionClock | None = None, before_fault: Callable[[str], None] | None = None, after_commit_fault: Callable[[str], None] | None = None) -> None:
        if not isinstance(path, Path) or not path.is_absolute() or path.name != "state.sqlite" or not path.parent.is_dir() or not isinstance(config, CompositionConfigV2):
            _fail(CompositionIntegrityError, "composition_configuration")
        self.path = path
        self.config = config
        self.clock = clock or _SystemClock()
        self._before_fault = before_fault
        self._after_commit_fault = after_commit_fault
        if not path.exists():
            _fail(CompositionIntegrityError, "state_database_required")
        self._check_schema()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.path), timeout=5.0, isolation_level=None)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute("PRAGMA page_size=4096")
        connection.execute("PRAGMA max_page_count=32768")
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def _check_schema(self) -> None:
        with closing(sqlite3.connect(str(self.path))) as connection:
            _check_composition_schema(connection, self.config)
            try:
                from app.minimal_clearance_verification_queue_independent import _verify_connection
                _verify_connection(connection)
            except Exception:
                _fail(CompositionIntegrityError, "composition_schema")

    def _initialize(self) -> None:
        _fail(CompositionIntegrityError, "state_database_required")

    def _meta(self, connection: sqlite3.Connection) -> tuple[Any, ...]:
        row = connection.execute("SELECT * FROM composition_meta WHERE id=1").fetchone()
        if row is None:
            _fail(CompositionIntegrityError, "composition_meta")
        return tuple(row)

    def _fault(self, label: str) -> None:
        if self._before_fault is not None:
            self._before_fault(label)

    def _after_fault(self, label: str) -> None:
        if self._after_commit_fault is not None:
            self._after_commit_fault(label)

    def _append_event(self, connection: sqlite3.Connection, *, operation_ref: bytes, kind: str, before: str, after: str, payload: Mapping[str, Any], at_ms: int) -> None:
        if kind not in _EVENT_PAYLOAD_KEYS or set(payload) != _EVENT_PAYLOAD_KEYS[kind] or type(payload.get("proof_accepted")) is not bool or payload.get("proof_accepted") is not True or payload.get("policy_result") not in _POLICY_RESULTS or payload.get("effective_directive") not in _DIRECTIVES or type(payload.get("sequence_before")) is not int or type(payload.get("sequence_after")) is not int:
            _fail(CompositionIntegrityError, "event_payload")
        if type(payload["operation_ref"]) is not str or payload["operation_ref"] != payload["operation_ref"].upper() or re.fullmatch(r"[0-9A-F]{64}\Z", payload["operation_ref"]) is None or type(payload["state_receipt_digest"]) is not str or payload["state_receipt_digest"] != payload["state_receipt_digest"].upper() or re.fullmatch(r"[0-9A-F]{128}\Z", payload["state_receipt_digest"]) is None:
            _fail(CompositionIntegrityError, "event_payload")
        if payload["operation_ref"] != _hex(operation_ref) or payload["sequence_before"] < 0 or payload["sequence_after"] != payload["sequence_before"] + 1:
            _fail(CompositionIntegrityError, "event_payload")
        meta = self._meta(connection)
        sequence = int(meta[5]) + 1
        payload_raw = _json_bytes(payload)
        event = {"schema": _SCHEMA, "sequence": sequence, "operation_ref": _hex(operation_ref), "event_kind": kind, "before_state": before, "after_state": after, "payload": json.loads(payload_raw.decode("ascii")), "at_ms": at_ms}
        raw = _json_bytes(event)
        digest = _sha(_EVENT, _u64(sequence), raw)
        root = _sha(_HEAD, bytes(meta[4]), _u64(sequence), digest)
        connection.execute("INSERT INTO composition_events VALUES (?,?,?,?,?,?,?,?,?)", (sequence, operation_ref, kind, before, after, payload_raw, digest, root, at_ms))
        connection.execute("UPDATE composition_meta SET event_head=?,next_event_sequence=? WHERE id=1", (root, sequence))

    @staticmethod
    def _control_for(job: IndependentVerifiedQueueJob, controls: Mapping[bytes, StateDispositionControl] | None) -> StateDispositionControl:
        if controls is not None and job.operation_ref in controls:
            control = controls[job.operation_ref]
            if type(control) is not StateDispositionControl:
                _fail(CompositionIntegrityError, "state_control_shape")
            return control
        return StateDispositionControl(job.operation_ref, "MISSING")

    def _preflight(self, connection: sqlite3.Connection, prepared: list[tuple[IndependentVerifiedQueueJob, StateDispositionControl]]) -> list[tuple[StateDispositionControl, str, bytes, bytes, int, int, int, int]]:
        meta = self._meta(connection)
        current: tuple[Any, ...] | None = None if meta[7] is None else (bytes(meta[7]), int(meta[9]), int(meta[10]), bytes(meta[11]), bytes(meta[13]), int(meta[14]), bytes(meta[12]), bytes(meta[8]), int(int(meta[14]) > 0))
        expected_profile = None if meta[6] is None else bytes(meta[6])
        if current is None and prepared and prepared[0][1].sequence_before != 0:
            _fail(CompositionIntegrityError, "composition_batch_state_chain")
        checked: list[tuple[StateDispositionControl, str, bytes, bytes, int, int, int, int]] = []
        for job, control in prepared:
            if control.operation_ref != job.operation_ref or job.status != "VERIFIED" or not job.proof_accepted:
                _fail(CompositionIntegrityError, "composition_batch_state_chain")
            if expected_profile is not None and control.state_profile_identity != expected_profile:
                _fail(CompositionIntegrityError, "composition_batch_state_chain")
            if current is None:
                if control.predecessor_state_id != _ZERO or control.predecessor_state_bytes != _ZERO or control.sequence_before != 0 or control.predecessor_continuity_root != _ZERO or control.predecessor_audit_head != _ZERO or control.predecessor_clearance_root != _ZERO or control.clearance_count_before != 0 or control.clearance_marker_before != 0:
                    _fail(CompositionIntegrityError, "composition_batch_state_chain")
                expected_profile = control.state_profile_identity
                current = (control.predecessor_state_id, control.epoch, 0, control.predecessor_continuity_root, _ZERO, 0, control.predecessor_audit_head, control.predecessor_state_bytes, control.clearance_marker_before)
            if bytes(current[0]) != control.predecessor_state_id or int(current[1]) != control.epoch or int(current[2]) != control.sequence_before or bytes(current[3]) != control.predecessor_continuity_root or bytes(current[4]) != control.predecessor_clearance_root or bytes(current[6]) != control.predecessor_audit_head or bytes(current[7]) != control.predecessor_state_bytes or int(current[8]) != control.clearance_marker_before or int(current[5]) != control.clearance_count_before or control.payment_root != _INITIAL_PAYMENT or control.economic_mutation:
                _fail(CompositionIntegrityError, "composition_batch_state_chain")
            directive = control.effective_directive
            sequence_after = control.sequence_before + 1
            advanced = directive in {"CLEAR", "EXCEPTION_APPROVED"}
            count_after = control.clearance_count_before + int(advanced)
            marker_after = int(bool(control.clearance_marker_before or advanced))
            if control.sequence_after is not None and control.sequence_after != sequence_after or control.clearance_count_after is not None and control.clearance_count_after != count_after or control.clearance_marker_after is not None and control.clearance_marker_after != marker_after:
                _fail(CompositionIntegrityError, "composition_batch_state_chain")
            if control.state_after_id == _ZERO or control.state_after_bytes == _ZERO:
                _fail(CompositionIntegrityError, "composition_batch_state_chain")
            checked.append((control, directive, control.predecessor_state_id, control.state_after_id, control.sequence_before, sequence_after, control.clearance_count_before, count_after))
            current = (control.state_after_id, control.epoch, sequence_after, control.state_after_continuity_root, control.state_after_clearance_root, count_after, _sha(_STATE, control.predecessor_audit_head, control.decision_id, directive.encode("ascii")), control.state_after_bytes, marker_after)
        return checked

    def _receipt(self, job: IndependentVerifiedQueueJob, control: StateDispositionControl, directive: str, seq_before: int, seq_after: int, count_before: int, count_after: int) -> bytes:
        audit_after = _sha(_STATE, control.predecessor_audit_head, control.decision_id, directive.encode("ascii"))
        return _json_bytes({"schema": _SCHEMA, "operation_ref": _hex(job.operation_ref), "proof_accepted": True, "policy_result": control.policy_result, "effective_directive": directive, "state_profile_identity": _hex(control.state_profile_identity), "state_before_id": _hex(control.predecessor_state_id), "state_before_bytes": _hex(control.predecessor_state_bytes), "state_after_id": _hex(control.state_after_id), "state_after_bytes": _hex(control.state_after_bytes), "epoch": control.epoch, "predecessor_continuity_root": _hex(control.predecessor_continuity_root), "state_after_continuity_root": _hex(control.state_after_continuity_root), "predecessor_audit_head": _hex(control.predecessor_audit_head), "decision_id": _hex(control.decision_id), "state_after_audit_head": _hex(audit_after), "predecessor_clearance_root": _hex(control.predecessor_clearance_root), "state_after_clearance_root": _hex(control.state_after_clearance_root), "clearance_marker_before": control.clearance_marker_before, "clearance_marker_after": int(bool(control.clearance_marker_before or directive in {"CLEAR", "EXCEPTION_APPROVED"})), "sequence_before": seq_before, "sequence_after": seq_after, "clearance_count_before": count_before, "clearance_count_after": count_after, "payment_root": _hex(control.payment_root), "exception_approved": control.exception_approved, "exception_authorization_id": _hex(control.exception_authorization_id), "economic_mutation": False, "proof_suite_id": None, "production_usable": False, "activation": False})

    @staticmethod
    def _result(job: IndependentVerifiedQueueJob, status: str, disposition: bytes, receipt: bytes | None, duplicate: bool, error: str | None) -> CompositionProcessResultV2:
        digest = None if receipt is None else _sha(_STATE, receipt)
        job_id = _hex(job.operation_ref)
        return CompositionProcessResultV2(job_id, job.operation_ref, status, disposition, receipt, digest, job_id if status == "APPLIED" else None, job.operation_ref if status == "APPLIED" else None, duplicate, error)

    def _validate_event_chain(self, connection: sqlite3.Connection) -> None:
        meta = self._meta(connection)
        expected_head = _sha(_GENESIS, self.config.digest)
        rows = connection.execute("SELECT * FROM composition_events ORDER BY sequence").fetchall()
        for index, row in enumerate(rows, start=1):
            if int(row[0]) != index or type(row[5]) is not bytes:
                _fail(CompositionConflictError, "composition_conflicting_retry")
            try:
                payload = json.loads(bytes(row[5]).decode("ascii"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                _fail(CompositionConflictError, "composition_conflicting_retry")
            event = {"schema": _SCHEMA, "sequence": index, "operation_ref": _hex(bytes(row[1])), "event_kind": str(row[2]), "before_state": str(row[3]), "after_state": str(row[4]), "payload": payload, "at_ms": int(row[8])}
            raw = _json_bytes(event)
            digest = _sha(_EVENT, _u64(index), raw)
            root = _sha(_HEAD, expected_head, _u64(index), digest)
            if bytes(row[6]) != digest or bytes(row[7]) != root:
                _fail(CompositionConflictError, "composition_conflicting_retry")
            expected_head = root
        if bytes(meta[4]) != expected_head or int(meta[5]) != len(rows):
            _fail(CompositionConflictError, "composition_conflicting_retry")

    def _apply_verified_jobs_in_transaction(self, connection: sqlite3.Connection, jobs: tuple[IndependentVerifiedQueueJob, ...], *, state_controls: Mapping[bytes, StateDispositionControl], now: int) -> tuple[CompositionProcessResultV2, ...]:
        if type(jobs) is not tuple or len(jobs) != 100 or not isinstance(state_controls, Mapping) or len(state_controls) != 100:
            _fail(CompositionIntegrityError, "state_control_set")
        refs = tuple(job.operation_ref for job in jobs)
        if len(set(refs)) != 100 or set(state_controls) != set(refs):
            _fail(CompositionIntegrityError, "state_control_set")
        prepared: list[tuple[IndependentVerifiedQueueJob, StateDispositionControl]] = []
        for job in jobs:
            if job.queue_id != self.config.queue_id or job.config_digest != self.config.queue_config_digest:
                _fail(CompositionIntegrityError, "queue_authority_binding")
            control = state_controls.get(job.operation_ref)
            if type(control) is not StateDispositionControl or control.operation_ref != job.operation_ref:
                _fail(CompositionIntegrityError, "state_control_shape")
            prepared.append((job, control))

        existing = [connection.execute("SELECT * FROM composition_transactions WHERE operation_ref=?", (job.operation_ref,)).fetchone() for job, _ in prepared]
        if any(row is not None for row in existing):
            if not all(row is not None for row in existing):
                _fail(CompositionConflictError, "composition_conflicting_retry")
            self._validate_event_chain(connection)
            results: list[CompositionProcessResultV2] = []
            for (job, control), row in zip(prepared, existing):
                assert row is not None
                directive = control.effective_directive
                disposition = _sha(_MATERIAL, b"disposition", job.operation_ref, directive.encode("ascii"), control.state_profile_identity)
                count_after = control.clearance_count_before + int(directive in {"CLEAR", "EXCEPTION_APPROVED"})
                expected_receipt = self._receipt(job, control, directive, int(row[10]), int(row[11]), control.clearance_count_before, count_after)
                if str(row[2]) != "APPLIED" or int(row[3]) != 1 or str(row[4]) != control.policy_result or str(row[5]) != directive or bytes(row[6]) != disposition or bytes(row[7]) != control.state_profile_identity or bytes(row[8]) != control.predecessor_state_id or bytes(row[9]) != control.state_after_id or int(row[11]) != int(row[10]) + 1 or row[12] is None or bytes(row[12]) != expected_receipt or row[13] is None or bytes(row[13]) != _sha(_STATE, expected_receipt):
                    _fail(CompositionConflictError, "composition_conflicting_retry")
                outbox = connection.execute("SELECT * FROM composition_outbox WHERE operation_ref=?", (job.operation_ref,)).fetchall()
                events = connection.execute("SELECT * FROM composition_events WHERE operation_ref=? AND event_kind='APPLIED'", (job.operation_ref,)).fetchall()
                if len(outbox) != 1 or bytes(outbox[0][0]) != job.operation_ref or str(outbox[0][1]) != directive or str(outbox[0][2]) not in {"READY", "LEASED", "ACKNOWLEDGED", "DELIVERY_UNCONFIRMED"} or len(events) != 1:
                    _fail(CompositionConflictError, "composition_conflicting_retry")
                try:
                    payload = json.loads(bytes(events[0][5]).decode("ascii"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    _fail(CompositionConflictError, "composition_conflicting_retry")
                expected_payload = {"operation_ref": _hex(job.operation_ref), "proof_accepted": True, "policy_result": control.policy_result, "effective_directive": directive, "state_receipt_digest": _hex(bytes(row[13])), "sequence_before": int(row[10]), "sequence_after": int(row[11])}
                if payload != expected_payload or str(events[0][3]) != "NONE" or str(events[0][4]) != "READY":
                    _fail(CompositionConflictError, "composition_conflicting_retry")
                results.append(self._result(job, "APPLIED", disposition, expected_receipt, True, None))
            return tuple(results)

        checked = self._preflight(connection, prepared)
        if len(checked) != 100 or int(self._meta(connection)[16]) + 100 > self.config.capacity:
            _fail(CompositionBackpressureError, "outbox_capacity")
        entries: list[tuple[IndependentVerifiedQueueJob, StateDispositionControl, str, bytes, bytes, bytes, bytes, tuple[Any, ...], bytes, dict[str, Any], int]] = []
        meta = self._meta(connection)
        audit_head = _ZERO if meta[12] is None else bytes(meta[12])
        for (job, control), checked_row in zip(prepared, checked):
            _, directive, state_before_id, state_after_id, seq_before, seq_after, count_before, count_after = checked_row
            disposition = _sha(_MATERIAL, b"disposition", job.operation_ref, directive.encode("ascii"), control.state_profile_identity)
            transaction_id = _sha(_MATERIAL, b"transaction", disposition)
            receipt = self._receipt(job, control, directive, seq_before, seq_after, count_before, count_after)
            receipt_digest = _sha(_STATE, receipt)
            tx = (transaction_id, job.operation_ref, "APPLIED", 1, control.policy_result, directive, disposition, control.state_profile_identity, state_before_id, state_after_id, seq_before, seq_after, receipt, receipt_digest, None, now, now)
            payload = {"operation_ref": _hex(job.operation_ref), "proof_accepted": True, "policy_result": control.policy_result, "effective_directive": directive, "state_receipt_digest": _hex(receipt_digest), "sequence_before": seq_before, "sequence_after": seq_after}
            audit_head = _sha(_STATE, audit_head, control.decision_id, directive.encode("ascii"))
            entries.append((job, control, directive, disposition, transaction_id, receipt, receipt_digest, tx, payload, audit_head, count_after))

        for entry in entries:
            connection.execute("INSERT INTO composition_transactions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", entry[7])
        self._fault("after_composition_transactions")
        for entry in entries:
            self._append_event(connection, operation_ref=entry[0].operation_ref, kind="APPLIED", before="NONE", after="READY", payload=entry[8], at_ms=now)
        self._fault("after_composition_events")
        for entry in entries:
            connection.execute("INSERT INTO composition_outbox VALUES (?,?,?,?,?,?,?,?)", (entry[0].operation_ref, entry[2], "READY", 0, None, None, None, now))
        self._fault("after_composition_outbox")
        last_job, last_control, last_directive, _, _, _, _, _, _, final_audit, final_count = entries[-1]
        connection.execute("UPDATE composition_meta SET state_profile_identity=?,state_id=?,state_bytes=?,state_epoch=?,state_sequence=?,state_continuity_root=?,state_audit_head=?,state_clearance_root=?,state_clearance_count=?,payment_root=?,active_dispatch_count=active_dispatch_count+100 WHERE id=1", (last_control.state_profile_identity, last_control.state_after_id, last_control.state_after_bytes, last_control.epoch, last_control.sequence_before + 1, last_control.state_after_continuity_root, final_audit, last_control.state_after_clearance_root, final_count, _INITIAL_PAYMENT))
        self._fault("after_composition_meta")
        self._fault("before_composition_commit")
        return tuple(self._result(entry[0], "APPLIED", entry[3], entry[5], False, None) for entry in entries)

    def _expire_outbox_locked(self, connection: sqlite3.Connection, now: int) -> None:
        rows = connection.execute("SELECT operation_ref,attempt FROM composition_outbox WHERE status='LEASED' AND lease_expires_ms<=?", (now,)).fetchall()
        for ref, attempt in rows:
            next_status = "DELIVERY_UNCONFIRMED" if int(attempt) >= self.config.max_attempts else "READY"
            connection.execute("UPDATE composition_outbox SET status=?,worker_id=NULL,lease_token=NULL,lease_expires_ms=NULL,updated_ms=? WHERE operation_ref=? AND status='LEASED'", (next_status, now, bytes(ref)))

    def _outbox_work_matches(self, row: tuple[Any, ...] | None, work: CompositionOutboxWorkV2, now: int) -> bool:
        if row is None or str(row[2]) != "LEASED" or bytes(row[0]) != work.operation_id or str(row[1]) != work.effective_directive or int(row[3]) != work.attempt or str(row[4]) != work.worker_id or row[5] is None or bytes(row[5]) != _sha(_LEASE, work.lease_token) or row[6] is None or int(row[6]) <= now:
            return False
        expected_envelope = _envelope(work.operation_id, work.effective_directive, self.config)
        return work.envelope_bytes == expected_envelope and work.idempotency_key == _sha(_MATERIAL, work.operation_id, work.effective_directive.encode("ascii"))

    def _reconciliation_work_matches(self, row: tuple[Any, ...] | None, work: CompositionReconciliationWorkV2, now: int) -> bool:
        if row is None or str(row[2]) != "LEASED" or bytes(row[0]) != work.operation_id or str(row[1]) != work.effective_directive or int(row[3]) != work.attempt or str(row[4]) != work.worker_id or row[5] is None or bytes(row[5]) != _sha(_LEASE, work.lease_token) or row[6] is None or int(row[6]) <= now:
            return False
        envelope = _envelope(work.operation_id, work.effective_directive, self.config)
        return work.envelope_digest == _sha(_MATERIAL, envelope) and work.idempotency_key == _sha(_MATERIAL, work.operation_id, work.effective_directive.encode("ascii"))

    def _work_is_live(self, work: CompositionOutboxWorkV2 | CompositionReconciliationWorkV2, now: int | None = None) -> bool:
        with closing(self._connect()) as connection:
            row = connection.execute("SELECT * FROM composition_outbox WHERE operation_ref=?", (work.operation_id,)).fetchone()
        check_now = int(self.clock.now_ms()) if now is None else now
        if type(work) is CompositionOutboxWorkV2:
            return self._outbox_work_matches(tuple(row) if row is not None else None, work, check_now)
        if type(work) is CompositionReconciliationWorkV2:
            return self._reconciliation_work_matches(tuple(row) if row is not None else None, work, check_now)
        _fail(CompositionLeaseError, "outbox_work")

    def _claim_outbox_batch(self, worker_id: str) -> CompositionOutboxBatchWorkV2 | None:
        """Claim at most 100 direct-delivery rows and return no persisted batch identity."""
        _token(worker_id, "worker_id")
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                now = int(self.clock.now_ms())
                self._expire_outbox_locked(connection, now)
                rows = connection.execute("SELECT operation_ref,effective_directive,attempt FROM composition_outbox WHERE status='READY' ORDER BY updated_ms,operation_ref LIMIT ?", (_OUTBOX_BATCH_CAPACITY,)).fetchall()
                if not rows:
                    connection.execute("COMMIT")
                    return None
                works: list[CompositionOutboxWorkV2] = []
                for row in rows:
                    ref, directive, attempt = bytes(row[0]), str(row[1]), int(row[2]) + 1
                    token = secrets.token_bytes(32)
                    expires = now + self.config.lease_seconds * 1000
                    updated = connection.execute("UPDATE composition_outbox SET status='LEASED',attempt=?,worker_id=?,lease_token=?,lease_expires_ms=?,updated_ms=? WHERE operation_ref=? AND status='READY' AND attempt<?", (attempt, worker_id, _sha(_LEASE, token), expires, now, ref, self.config.max_attempts))
                    if updated.rowcount != 1:
                        _fail(CompositionLeaseError, "outbox_claim_conflict")
                    self._fault("after_outbox_claim_update")
                    works.append(CompositionOutboxWorkV2(self.config.composition_id, _hex(ref), ref, attempt, worker_id, token, expires, _envelope(ref, directive, self.config), _sha(_MATERIAL, ref, directive.encode("ascii")), directive))
                has_more = connection.execute("SELECT 1 FROM composition_outbox WHERE status='READY' LIMIT 1").fetchone() is not None
                self._fault("before_outbox_claim_commit")
                connection.execute("COMMIT")
                self._after_fault("after_outbox_claim_commit")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return CompositionOutboxBatchWorkV2(self.config.composition_id, worker_id, tuple(works), has_more)

    def _claim_reconciliation_batch(self, worker_id: str) -> CompositionReconciliationBatchWorkV2 | None:
        """Claim at most 100 reconciliation rows with independent lease material."""
        _token(worker_id, "worker_id")
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                now = int(self.clock.now_ms())
                self._expire_outbox_locked(connection, now)
                rows = connection.execute("SELECT operation_ref,effective_directive,attempt FROM composition_outbox WHERE status='DELIVERY_UNCONFIRMED' AND attempt<? ORDER BY updated_ms,operation_ref LIMIT ?", (self.config.max_attempts, _OUTBOX_BATCH_CAPACITY)).fetchall()
                if not rows:
                    connection.execute("COMMIT")
                    return None
                works: list[CompositionReconciliationWorkV2] = []
                for row in rows:
                    ref, directive, attempt = bytes(row[0]), str(row[1]), int(row[2]) + 1
                    token = secrets.token_bytes(32)
                    expires = now + self.config.reconciliation_lease_seconds * 1000
                    updated = connection.execute("UPDATE composition_outbox SET status='LEASED',attempt=?,worker_id=?,lease_token=?,lease_expires_ms=?,updated_ms=? WHERE operation_ref=? AND status='DELIVERY_UNCONFIRMED' AND attempt<?", (attempt, worker_id, _sha(_LEASE, token), expires, now, ref, self.config.max_attempts))
                    if updated.rowcount != 1:
                        _fail(CompositionLeaseError, "reconciliation_claim_conflict")
                    self._fault("after_reconciliation_claim_update")
                    envelope = _envelope(ref, directive, self.config)
                    works.append(CompositionReconciliationWorkV2(self.config.composition_id, _hex(ref), ref, attempt, worker_id, token, expires, directive, _sha(_MATERIAL, envelope), _sha(_MATERIAL, ref, directive.encode("ascii"))))
                has_more = connection.execute("SELECT 1 FROM composition_outbox WHERE status='DELIVERY_UNCONFIRMED' AND attempt<? LIMIT 1", (self.config.max_attempts,)).fetchone() is not None
                self._fault("before_reconciliation_claim_commit")
                connection.execute("COMMIT")
                self._after_fault("after_reconciliation_claim_commit")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return CompositionReconciliationBatchWorkV2(self.config.composition_id, worker_id, tuple(works), has_more)

    @staticmethod
    def _unconfirmed_result(work: CompositionOutboxWorkV2 | CompositionReconciliationWorkV2) -> CompositionDeliveryResultV2:
        return CompositionDeliveryResultV2(work.job_id, work.operation_id, "DELIVERY_UNCONFIRMED", None, None, "delivery_unconfirmed")

    def _attempt_direct_delivery(self, work: CompositionOutboxWorkV2, *, receiver: OfficialStateReceiverPort) -> bytes | None:
        # This check is deliberately outside any database write transaction. A
        # clock that reaches the deadline before this point must not start I/O.
        if not self._work_is_live(work) or int(self.clock.now_ms()) >= work.lease_expires_ms:
            return None
        try:
            ack = receiver.dispatch(work.envelope_bytes, work.idempotency_key)
            return _parse_acknowledgment(ack, envelope_bytes=work.envelope_bytes, idempotency_key=work.idempotency_key, operation_ref=work.operation_id, directive=work.effective_directive)
        except Exception:
            # A process-level crash (BaseException) intentionally escapes here,
            # leaving every claimed row for lease-expiry recovery.
            return None

    def _attempt_reconciliation(self, work: CompositionReconciliationWorkV2, *, lookup: OfficialStateReceiverLookupPort) -> bytes | None:
        if not self._work_is_live(work) or int(self.clock.now_ms()) >= work.lease_expires_ms:
            return None
        envelope = _envelope(work.operation_id, work.effective_directive, self.config)
        try:
            ack = lookup.lookup_acknowledgment(receiver_identity=self.config.receiver_identity, receiver_epoch=self.config.receiver_epoch, job_id=work.job_id, operation_id=work.operation_id, idempotency_key=work.idempotency_key, envelope_digest=work.envelope_digest)
            if ack is None:
                return None
            return _parse_acknowledgment(ack, envelope_bytes=envelope, idempotency_key=work.idempotency_key, operation_ref=work.operation_id, directive=work.effective_directive)
        except Exception:
            return None

    def _settle_delivery_batch(self, *, worker_id: str, operation: str, works: tuple[CompositionOutboxWorkV2 | CompositionReconciliationWorkV2, ...], acknowledgments: tuple[bytes | None, ...], has_more: bool) -> CompositionBatchDeliveryResultV2:
        if len(works) != len(acknowledgments):
            _fail(CompositionIntegrityError, "outbox_batch_result")
        if operation not in {"DIRECT_DELIVERY", "RECONCILIATION"}:
            _fail(CompositionIntegrityError, "outbox_operation")
        results: list[CompositionDeliveryResultV2] = []
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                settlement_now = int(self.clock.now_ms())
                self._expire_outbox_locked(connection, settlement_now)
                self._fault("before_outbox_settlement")
                for work, acknowledgment in zip(works, acknowledgments):
                    row = connection.execute("SELECT * FROM composition_outbox WHERE operation_ref=?", (work.operation_id,)).fetchone()
                    if type(work) is CompositionOutboxWorkV2:
                        live = self._outbox_work_matches(tuple(row) if row is not None else None, work, settlement_now)
                    elif type(work) is CompositionReconciliationWorkV2:
                        live = self._reconciliation_work_matches(tuple(row) if row is not None else None, work, settlement_now)
                    else:
                        _fail(CompositionLeaseError, "outbox_work")
                    fence = (settlement_now, work.operation_id, work.attempt, work.worker_id, _sha(_LEASE, work.lease_token), settlement_now)
                    if acknowledgment is not None and live:
                        updated = connection.execute("UPDATE composition_outbox SET status='ACKNOWLEDGED',worker_id=NULL,lease_token=NULL,lease_expires_ms=NULL,updated_ms=? WHERE operation_ref=? AND status='LEASED' AND attempt=? AND worker_id=? AND lease_token=? AND lease_expires_ms>?", fence)
                        if updated.rowcount == 1:
                            meta_updated = connection.execute("UPDATE composition_meta SET active_dispatch_count=active_dispatch_count-1 WHERE id=1 AND active_dispatch_count>0")
                            if meta_updated.rowcount != 1:
                                _fail(CompositionIntegrityError, "active_dispatch_count")
                            results.append(CompositionDeliveryResultV2(work.job_id, work.operation_id, "ACKNOWLEDGED", acknowledgment, _sha(_MATERIAL, acknowledgment), None))
                        else:
                            results.append(self._unconfirmed_result(work))
                    elif live:
                        updated = connection.execute("UPDATE composition_outbox SET status='DELIVERY_UNCONFIRMED',worker_id=NULL,lease_token=NULL,lease_expires_ms=NULL,updated_ms=? WHERE operation_ref=? AND status='LEASED' AND attempt=? AND worker_id=? AND lease_token=? AND lease_expires_ms>?", fence)
                        if updated.rowcount != 1:
                            _fail(CompositionLeaseError, "outbox_settlement_conflict")
                        results.append(self._unconfirmed_result(work))
                    else:
                        results.append(self._unconfirmed_result(work))
                    self._fault("after_outbox_settlement_update")
                if operation == "DIRECT_DELIVERY":
                    remaining = connection.execute("SELECT 1 FROM composition_outbox WHERE status='READY' LIMIT 1").fetchone() is not None
                else:
                    remaining = connection.execute("SELECT 1 FROM composition_outbox WHERE status='DELIVERY_UNCONFIRMED' AND attempt<? LIMIT 1", (self.config.max_attempts,)).fetchone() is not None
                has_more = has_more or remaining
                self._fault("before_outbox_settlement_commit")
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return CompositionBatchDeliveryResultV2(self.config.composition_id, worker_id, operation, tuple(results), has_more)

    def dispatch_outbox_batch(self, worker_id: str, *, receiver: OfficialStateReceiverPort) -> CompositionBatchDeliveryResultV2 | None:
        """Claim, deliver sequentially, and settle one direct batch.

        The external receiver is required to durably deduplicate the stable
        per-operation idempotency keys. This store preserves those keys but does
        not prove that external prerequisite; in-flight lease expiry remains
        indeterminate and is reconciled through the separate batch operation.
        """
        batch = self._claim_outbox_batch(worker_id)
        if batch is None:
            return None
        acknowledgments = tuple(self._attempt_direct_delivery(work, receiver=receiver) for work in batch.works)
        return self._settle_delivery_batch(worker_id=worker_id, operation="DIRECT_DELIVERY", works=batch.works, acknowledgments=acknowledgments, has_more=batch.has_more)

    def reconcile_outbox_batch(self, worker_id: str, *, lookup: OfficialStateReceiverLookupPort | None = None) -> CompositionBatchDeliveryResultV2 | None:
        """Claim, look up sequentially, and settle one reconciliation batch."""
        if lookup is None:
            _fail(CompositionLeaseError, "reconciliation_lookup_required")
        batch = self._claim_reconciliation_batch(worker_id)
        if batch is None:
            return None
        acknowledgments = tuple(self._attempt_reconciliation(work, lookup=lookup) for work in batch.works)
        return self._settle_delivery_batch(worker_id=worker_id, operation="RECONCILIATION", works=batch.works, acknowledgments=acknowledgments, has_more=batch.has_more)

    def snapshot(self) -> dict[str, Any]:
        with closing(self._connect()) as connection:
            meta = self._meta(connection)
            counts = {status: int(connection.execute("SELECT COUNT(*) FROM composition_transactions WHERE status=?", (status,)).fetchone()[0]) for status in ("APPLIED", "HELD")}
            outbox = {status: int(connection.execute("SELECT COUNT(*) FROM composition_outbox WHERE status=?", (status,)).fetchone()[0]) for status in ("READY", "LEASED", "ACKNOWLEDGED", "DELIVERY_UNCONFIRMED")}
            return {"schema": _SCHEMA, "transaction_counts": counts, "outbox_counts": outbox, "state_sequence": meta[10], "state_id": meta[7], "event_head": meta[4], "proof_suite_id": None, "production_usable": False, "activation": False}

    def verify_integrity(self) -> None:
        from app.minimal_clearance_composition_independent import verify_database
        verify_database(self.path, expected_config=self.config.as_json)

    def create_backup(self, destination: Path) -> None:
        if not isinstance(destination, Path) or destination.exists():
            _fail(CompositionIntegrityError, "backup_path")
        self.verify_integrity()
        destination.write_bytes(self.path.read_bytes())
        self.verify_integrity()

    @classmethod
    def recover_from_backup(cls, *, backup_path: Path, recovered_path: Path, config: CompositionConfigV2) -> "ClearanceCompositionStoreV2":
        if not isinstance(backup_path, Path) or not isinstance(recovered_path, Path) or recovered_path.exists():
            _fail(CompositionIntegrityError, "recovery_path")
        recovered_path.write_bytes(backup_path.read_bytes())
        return cls(path=recovered_path, config=config)

    def close(self) -> None:
        return None


def _apply_verified_jobs_in_transaction(connection: sqlite3.Connection, *, config: CompositionConfigV2, jobs: tuple[IndependentVerifiedQueueJob, ...], state_controls: Mapping[bytes, StateDispositionControl], now: int, before_fault: Callable[[str], None] | None = None) -> tuple[CompositionProcessResultV2, ...]:
    """Apply one exact accepted batch on the caller's State transaction."""
    writer = object.__new__(ClearanceCompositionStoreV2)
    writer.config = config
    writer.clock = _SystemClock()
    writer._before_fault = before_fault
    writer._after_commit_fault = None
    return writer._apply_verified_jobs_in_transaction(connection, jobs, state_controls=state_controls, now=now)


__all__ = ("ClearanceCompositionStoreV2", "CompositionBackpressureError", "CompositionBatchDeliveryResultV2", "CompositionClock", "CompositionConflictError", "CompositionConfigV2", "CompositionDeliveryResultV2", "CompositionError", "CompositionIndeterminateError", "CompositionIntegrityError", "CompositionLeaseError", "CompositionOutboxBatchWorkV2", "CompositionOutboxWorkV2", "CompositionProcessResultV2", "CompositionReconciliationBatchWorkV2", "CompositionReconciliationWorkV2", "OfficialStateReceiverLookupPort", "OfficialStateReceiverPort", "StateDispositionControl", "SyntheticAckEvidenceProfileV2", "build_synthetic_acknowledgment", "resolve_effective_directive")
