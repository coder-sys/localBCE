"""State-owned Queue/Proof Handoff V7 composition.

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

from app.minimal_clearance_authoritative_assertion import (
    AuthoritativeAssertionError,
    AuthoritativeAssertionResultV1,
    AuthoritativeAssertionTemplateV1,
    AuthoritativeBatchStatementV1,
    AuthoritativeIssuedOperationV1,
    AuthoritativeReservation,
    LIFETIME_ACCEPTANCE_CAP,
    MEMBER_COUNT,
    MODE as AUTHORITATIVE_ASSERTION_MODE,
    QUALIFICATION_FLAGS,
    RESERVATION_UNITS,
    SIGNATURE_PROFILE_VERSION,
    SOURCE_AUTH_PROFILE_ID,
    _create_reservation,
    compute_reservation_after,
    compute_batch_root,
)
from app.minimal_clearance_verification_queue_independent import (
    IndependentQueueError,
    IndependentVerifiedQueueBatch,
    IndependentVerifiedQueueJob,
    read_verified_batch,
)
from app.minimal_clearance_authoritative_assertion_independent import (
    IndependentAuthoritativeAssertionBatch,
    IndependentAuthoritativeAssertionJob,
    read_authoritative_batch,
    verify_authoritative_connection,
)


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


_SCHEMA_VERSION: Final[int] = 6
_SCHEMA: Final[str] = "BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/v6"
_HANDOFF_SCHEMA: Final[str] = "BL/NATIVE-V3/MINIMAL-CLEARANCE/OFFICIAL-HANDOFF/v3"
_DIRECTIVES: Final[tuple[str, ...]] = ("CLEAR", "HOLD", "HUMAN_REVIEW", "BLOCK", "EXCEPTION_APPROVED")
_POLICY_RESULTS: Final[tuple[str, ...]] = ("PASS", "MISSING", "AMBIGUOUS", "FAIL")
_MATERIAL = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/MATERIAL/v6\x00"
_GENESIS = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/GENESIS/v6\x00"
_EVENT = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/EVENT/v6\x00"
_HEAD = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/HEAD/v6\x00"
_STATE = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/STATE/v6\x00"
_TOKEN = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
_CODE = re.compile(r"[a-z][a-z0-9_]{0,95}\Z")
_ZERO = bytes(64)
_INITIAL_PAYMENT = bytes(64)
_LEASE = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/LEASE/v4\x00"
_EVENT_PAYLOAD_KEYS = {"APPLIED": frozenset({"operation_ref", "proof_accepted", "policy_result", "effective_directive", "state_receipt_digest", "sequence_before", "sequence_after"})}
_AUTHORITATIVE_EVENT_PAYLOAD_KEYS = frozenset({"operation_ref", "evidence_mode", "assertion_accepted", "proof_accepted", "batch_root", "policy_result", "effective_directive", "state_receipt_digest", "sequence_before", "sequence_after"})


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


def _clock_ms(clock: Any) -> int:
    value = clock.now_ms()
    if type(value) is not int or not 0 <= value < 2**64:
        _fail(CompositionIntegrityError, "authoritative_verification_time")
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
    composition_id: str = "minimal-clearance-composition-v7"
    verifier_epoch: int = 1
    capacity: int = 128
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


class CompositionClock(Protocol):
    def now_ms(self) -> int: ...


class _SystemClock:
    def now_ms(self) -> int:
        return time.time_ns() // 1_000_000


class OfficialStateReceiverPort(Protocol):
    def identity_sha256(self) -> bytes: ...
    def epoch(self) -> int: ...
    def dispatch(self, envelope_bytes: bytes, idempotency_key: bytes) -> bytes: ...


class OfficialStateReceiverLookupPort(Protocol):
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


_META_COLUMNS = ("id", "schema_version", "config_json", "config_digest", "event_head", "next_event_sequence", "state_profile_identity", "state_id", "state_bytes", "state_epoch", "state_sequence", "state_continuity_root", "state_audit_head", "state_clearance_root", "state_clearance_count", "payment_root", "active_dispatch_count")
_TX_COLUMNS = ("transaction_id", "operation_ref", "status", "proof_accepted", "policy_result", "effective_directive", "disposition_id", "state_profile_identity", "state_before_id", "state_after_id", "sequence_before", "sequence_after", "state_receipt_bytes", "state_receipt_digest", "error_code", "created_ms", "updated_ms")
_EVENT_COLUMNS = ("sequence", "operation_ref", "event_kind", "before_state", "after_state", "payload", "event_digest", "event_root", "at_ms")
_OUTBOX_COLUMNS = ("operation_ref", "effective_directive", "status", "attempt", "worker_id", "lease_token", "lease_expires_ms", "updated_ms")
_AUTHORITATIVE_OPERATION_COLUMNS = ("operation_ref", "batch_root", "batch_position", "assertion_identifier", "assertion_version", "state_profile_version", "valid_from_ms", "valid_until_ms", "approved_source_registry_root", "qualification_flags", "status", "updated_ms")
_AUTHORITATIVE_BATCH_COLUMNS = ("batch_root", "member_count", "status", "state_profile_version", "source_auth_profile_id", "signature_profile_version", "source_key_epoch", "reservation_units", "reservation_before", "reservation_after", "cryptographic_attempted", "verification_time_ms", "created_ms", "updated_ms", "last_error_code")
_AUTHORITATIVE_RESULT_COLUMNS = ("batch_root", "assertion_accepted", "receipt_bytes", "receipt_digest", "outcome_code", "error_code", "created_ms")
_AUTHORITATIVE_LEDGER_COLUMNS = ("profile_id", "lifetime_cap", "computational_units_used", "statistical_units_used", "last_key_epoch")


class ClearanceCompositionStoreV2:
    def __init__(self, *, path: Path, config: CompositionConfigV2, clock: CompositionClock | None = None, before_fault: Callable[[str], None] | None = None, after_commit_fault: Callable[[str], None] | None = None) -> None:
        if not isinstance(path, Path) or not path.is_absolute() or not path.parent.is_dir() or not isinstance(config, CompositionConfigV2):
            _fail(CompositionIntegrityError, "composition_configuration")
        self.path = path
        self.config = config
        self.clock = clock or _SystemClock()
        self._before_fault = before_fault
        self._after_commit_fault = after_commit_fault
        if path.exists():
            self._check_schema()
        else:
            self._initialize()
        self._recover_authoritative_batches()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.path), timeout=5.0, isolation_level=None)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    def _check_schema(self) -> None:
        with closing(sqlite3.connect(str(self.path))) as connection:
            tables = {str(row[0]) for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
            if tables != {"composition_meta", "composition_transactions", "composition_events", "composition_outbox", "authoritative_operations", "authoritative_batches", "authoritative_results", "authoritative_profile_ledger"}:
                _fail(CompositionIntegrityError, "composition_schema")
            if tuple(str(row[1]) for row in connection.execute("PRAGMA table_info(composition_meta)")) != _META_COLUMNS or tuple(str(row[1]) for row in connection.execute("PRAGMA table_info(composition_transactions)")) != _TX_COLUMNS or tuple(str(row[1]) for row in connection.execute("PRAGMA table_info(composition_events)")) != _EVENT_COLUMNS or tuple(str(row[1]) for row in connection.execute("PRAGMA table_info(composition_outbox)")) != _OUTBOX_COLUMNS or tuple(str(row[1]) for row in connection.execute("PRAGMA table_info(authoritative_operations)")) != _AUTHORITATIVE_OPERATION_COLUMNS or tuple(str(row[1]) for row in connection.execute("PRAGMA table_info(authoritative_batches)")) != _AUTHORITATIVE_BATCH_COLUMNS or tuple(str(row[1]) for row in connection.execute("PRAGMA table_info(authoritative_results)")) != _AUTHORITATIVE_RESULT_COLUMNS or tuple(str(row[1]) for row in connection.execute("PRAGMA table_info(authoritative_profile_ledger)")) != _AUTHORITATIVE_LEDGER_COLUMNS:
                _fail(CompositionIntegrityError, "composition_schema")
            row = connection.execute("SELECT schema_version,config_json,config_digest FROM composition_meta WHERE id=1").fetchone()
            if row is None or int(row[0]) != _SCHEMA_VERSION or bytes(row[2]) != self.config.digest or bytes(row[1]) != self.config.canonical_bytes:
                _fail(CompositionIntegrityError, "composition_schema")

    def _initialize(self) -> None:
        with closing(self._connect()) as connection:
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("CREATE TABLE composition_meta (id INTEGER PRIMARY KEY CHECK(id=1), schema_version INTEGER NOT NULL CHECK(schema_version=6), config_json BLOB NOT NULL, config_digest BLOB NOT NULL CHECK(length(config_digest)=64), event_head BLOB NOT NULL CHECK(length(event_head)=64), next_event_sequence INTEGER NOT NULL CHECK(next_event_sequence>=0), state_profile_identity BLOB, state_id BLOB, state_bytes BLOB, state_epoch INTEGER, state_sequence INTEGER, state_continuity_root BLOB, state_audit_head BLOB, state_clearance_root BLOB, state_clearance_count INTEGER, payment_root BLOB NOT NULL CHECK(length(payment_root)=64), active_dispatch_count INTEGER NOT NULL CHECK(active_dispatch_count>=0))")
            connection.execute("CREATE TABLE composition_transactions (transaction_id BLOB PRIMARY KEY CHECK(length(transaction_id)=64), operation_ref BLOB NOT NULL UNIQUE CHECK(length(operation_ref)=32), status TEXT NOT NULL CHECK(status IN ('APPLIED','HELD')), proof_accepted INTEGER NOT NULL CHECK(proof_accepted IN (0,1)), policy_result TEXT NOT NULL CHECK(policy_result IN ('PASS','MISSING','AMBIGUOUS','FAIL')), effective_directive TEXT NOT NULL CHECK(effective_directive IN ('CLEAR','HOLD','HUMAN_REVIEW','BLOCK','EXCEPTION_APPROVED')), disposition_id BLOB NOT NULL CHECK(length(disposition_id)=64), state_profile_identity BLOB NOT NULL CHECK(length(state_profile_identity)=64), state_before_id BLOB NOT NULL CHECK(length(state_before_id)=64), state_after_id BLOB NOT NULL CHECK(length(state_after_id)=64), sequence_before INTEGER NOT NULL, sequence_after INTEGER NOT NULL, state_receipt_bytes BLOB, state_receipt_digest BLOB, error_code TEXT, created_ms INTEGER NOT NULL, updated_ms INTEGER NOT NULL)")
            connection.execute("CREATE TABLE composition_events (sequence INTEGER PRIMARY KEY CHECK(sequence>=1), operation_ref BLOB NOT NULL CHECK(length(operation_ref)=32), event_kind TEXT NOT NULL CHECK(event_kind IN ('APPLIED','HELD','DISPATCH_LEASED','ACKNOWLEDGED','DELIVERY_UNCONFIRMED','LEASE_EXPIRED')), before_state TEXT NOT NULL, after_state TEXT NOT NULL, payload BLOB NOT NULL CHECK(length(payload)<=4096), event_digest BLOB NOT NULL UNIQUE CHECK(length(event_digest)=64), event_root BLOB NOT NULL CHECK(length(event_root)=64), at_ms INTEGER NOT NULL)")
            connection.execute("CREATE TABLE composition_outbox (operation_ref BLOB PRIMARY KEY CHECK(length(operation_ref)=32), effective_directive TEXT NOT NULL CHECK(effective_directive IN ('CLEAR','HOLD','HUMAN_REVIEW','BLOCK','EXCEPTION_APPROVED')), status TEXT NOT NULL CHECK(status IN ('READY','LEASED','ACKNOWLEDGED','DELIVERY_UNCONFIRMED')), attempt INTEGER NOT NULL CHECK(attempt BETWEEN 0 AND 3), worker_id TEXT, lease_token BLOB, lease_expires_ms INTEGER, updated_ms INTEGER NOT NULL)")
            connection.execute("CREATE TABLE authoritative_operations (operation_ref BLOB PRIMARY KEY CHECK(length(operation_ref)=32), batch_root BLOB NOT NULL CHECK(length(batch_root)=64), batch_position INTEGER NOT NULL CHECK(batch_position BETWEEN 0 AND 99), assertion_identifier TEXT NOT NULL, assertion_version INTEGER NOT NULL CHECK(assertion_version>=1), state_profile_version TEXT NOT NULL, valid_from_ms INTEGER NOT NULL CHECK(valid_from_ms>=0), valid_until_ms INTEGER NOT NULL CHECK(valid_until_ms>valid_from_ms), approved_source_registry_root BLOB CHECK(approved_source_registry_root IS NULL OR length(approved_source_registry_root)=64), qualification_flags BLOB NOT NULL CHECK(qualification_flags=X'617574686F72697461746976655F617373657274696F6E5F7631'), status TEXT NOT NULL CHECK(status IN ('ISSUED','RESERVED','HELD','APPLIED')), updated_ms INTEGER NOT NULL)")
            connection.execute("CREATE TABLE authoritative_batches (batch_root BLOB PRIMARY KEY CHECK(length(batch_root)=64), member_count INTEGER NOT NULL CHECK(member_count=100), status TEXT NOT NULL CHECK(status IN ('ISSUED','RESERVED','HELD','APPLIED')), state_profile_version TEXT NOT NULL, source_auth_profile_id TEXT NOT NULL CHECK(source_auth_profile_id='ML-DSA-65-PURE-V1'), signature_profile_version TEXT NOT NULL CHECK(signature_profile_version='FIPS204-ML-DSA-65-PURE-V1'), source_key_epoch INTEGER NOT NULL CHECK(source_key_epoch>=0), reservation_units INTEGER NOT NULL CHECK(reservation_units=101), reservation_before INTEGER NOT NULL CHECK(reservation_before>=0), reservation_after INTEGER NOT NULL CHECK(reservation_after=reservation_before OR reservation_after=reservation_before+reservation_units), cryptographic_attempted INTEGER NOT NULL CHECK(cryptographic_attempted IN (0,1)), verification_time_ms INTEGER CHECK(verification_time_ms IS NULL OR verification_time_ms>=0), created_ms INTEGER NOT NULL CHECK(created_ms>=0), updated_ms INTEGER NOT NULL CHECK(updated_ms>=0), last_error_code TEXT)")
            connection.execute("CREATE TABLE authoritative_results (batch_root BLOB PRIMARY KEY CHECK(length(batch_root)=64), assertion_accepted INTEGER NOT NULL CHECK(assertion_accepted IN (0,1)), receipt_bytes BLOB CHECK(receipt_bytes IS NULL OR length(receipt_bytes)<=16384), receipt_digest BLOB CHECK(receipt_digest IS NULL OR length(receipt_digest)=64), outcome_code TEXT NOT NULL, error_code TEXT, created_ms INTEGER NOT NULL CHECK(created_ms>=0), FOREIGN KEY(batch_root) REFERENCES authoritative_batches(batch_root), CHECK((assertion_accepted=1 AND receipt_bytes IS NOT NULL AND receipt_digest IS NOT NULL AND outcome_code='ACCEPTED' AND error_code IS NULL) OR (assertion_accepted=0 AND receipt_bytes IS NOT NULL AND receipt_digest IS NOT NULL AND ((outcome_code='SIGNATURE_INVALID' AND error_code='signature_invalid') OR (outcome_code='KEY_EPOCH_MISMATCH' AND error_code='source_key_epoch_mismatch') OR (outcome_code='MALFORMED' AND error_code IN ('signature_handoff_stream','signature_length','signature_transport','signature_bytes','signature_trailing_bytes','signature_handoff_closed','signature_handoff_reuse'))))))")
            connection.execute("CREATE TABLE authoritative_profile_ledger (profile_id TEXT PRIMARY KEY CHECK(profile_id='ML-DSA-65-PURE-V1'), lifetime_cap INTEGER NOT NULL CHECK(lifetime_cap=4294967296), computational_units_used INTEGER NOT NULL CHECK(computational_units_used>=0), statistical_units_used INTEGER NOT NULL CHECK(statistical_units_used=0), last_key_epoch INTEGER NOT NULL CHECK(last_key_epoch>=0))")
            connection.execute("INSERT INTO authoritative_profile_ledger VALUES (?,?,?,?,?)", (SOURCE_AUTH_PROFILE_ID, LIFETIME_ACCEPTANCE_CAP, 0, 0, 0))
            connection.execute("CREATE INDEX composition_outbox_ready_idx ON composition_outbox(status,updated_ms)")
            connection.execute("CREATE TRIGGER composition_transactions_no_delete BEFORE DELETE ON composition_transactions BEGIN SELECT RAISE(ABORT,'composition_append_only'); END")
            connection.execute("CREATE TRIGGER composition_events_no_update BEFORE UPDATE ON composition_events BEGIN SELECT RAISE(ABORT,'composition_append_only'); END")
            connection.execute("CREATE TRIGGER composition_events_no_delete BEFORE DELETE ON composition_events BEGIN SELECT RAISE(ABORT,'composition_append_only'); END")
            head = _sha(_GENESIS, self.config.digest)
            connection.execute("INSERT INTO composition_meta VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (1, _SCHEMA_VERSION, self.config.canonical_bytes, self.config.digest, head, 0, None, None, None, None, None, None, None, None, None, _INITIAL_PAYMENT, 0))
            connection.execute("COMMIT")
        self._check_schema()

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

    def _recover_authoritative_batches(self) -> None:
        """A reserved volatile handoff cannot survive process restart."""
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    verify_authoritative_connection(connection)
                except Exception:
                    _fail(CompositionIntegrityError, "authoritative_recovery")
                rows = connection.execute("SELECT batch_root FROM authoritative_batches WHERE status='RESERVED'").fetchall()
                now = int(self.clock.now_ms())
                for (batch_root,) in rows:
                    root = bytes(batch_root)
                    connection.execute("UPDATE authoritative_batches SET status='HELD',updated_ms=?,last_error_code=? WHERE batch_root=? AND status='RESERVED'", (now, "fresh_batch_required", root))
                    connection.execute("UPDATE authoritative_operations SET status='HELD',updated_ms=? WHERE batch_root=? AND status='RESERVED'", (now, root))
                connection.execute("COMMIT")
            except sqlite3.Error:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                _fail(CompositionIntegrityError, "authoritative_recovery")

    def _append_event(self, connection: sqlite3.Connection, *, operation_ref: bytes, kind: str, before: str, after: str, payload: Mapping[str, Any], at_ms: int) -> None:
        authoritative = set(payload) == _AUTHORITATIVE_EVENT_PAYLOAD_KEYS
        generic = kind in _EVENT_PAYLOAD_KEYS and set(payload) == _EVENT_PAYLOAD_KEYS[kind]
        if not generic and not authoritative:
            _fail(CompositionIntegrityError, "event_payload")
        if type(payload.get("proof_accepted")) is not bool or payload.get("proof_accepted") is not (False if authoritative else True) or payload.get("policy_result") not in _POLICY_RESULTS or payload.get("effective_directive") not in _DIRECTIVES or type(payload.get("sequence_before")) is not int or type(payload.get("sequence_after")) is not int:
            _fail(CompositionIntegrityError, "event_payload")
        if authoritative and (payload.get("evidence_mode") != AUTHORITATIVE_ASSERTION_MODE or payload.get("assertion_accepted") is not True or type(payload.get("batch_root")) is not str or re.fullmatch(r"[0-9A-F]{128}\Z", payload["batch_root"]) is None):
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

    def rotate_authoritative_key_epoch(self, source_key_epoch: int) -> None:
        """Advance the state-owned key epoch without resetting the lifetime ledger."""
        if type(source_key_epoch) is not int or source_key_epoch < 0:
            _fail(CompositionIntegrityError, "authoritative_key_epoch")
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                if connection.execute("SELECT COUNT(*) FROM authoritative_batches WHERE status IN ('ISSUED','RESERVED')").fetchone()[0] != 0:
                    _fail(CompositionConflictError, "authoritative_batch_pending")
                row = connection.execute("SELECT last_key_epoch FROM authoritative_profile_ledger WHERE profile_id=?", (SOURCE_AUTH_PROFILE_ID,)).fetchone()
                if row is None or source_key_epoch <= int(row[0]):
                    _fail(CompositionConflictError, "authoritative_key_epoch")
                connection.execute("UPDATE authoritative_profile_ledger SET last_key_epoch=? WHERE profile_id=? AND last_key_epoch<?", (source_key_epoch, SOURCE_AUTH_PROFILE_ID, source_key_epoch))
                if connection.execute("SELECT changes()").fetchone()[0] != 1:
                    _fail(CompositionIntegrityError, "authoritative_key_epoch_coordination")
                connection.execute("COMMIT")
            except (CompositionError, sqlite3.Error):
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def issue_authoritative_batch(self, *, templates: tuple[AuthoritativeAssertionTemplateV1, ...]) -> AuthoritativeBatchStatementV1:
        """Issue exactly one state-owned, ordered 100-operation assertion batch."""
        if type(templates) is not tuple or len(templates) != MEMBER_COUNT or any(type(template) is not AuthoritativeAssertionTemplateV1 for template in templates):
            _fail(CompositionIntegrityError, "authoritative_batch_cardinality")
        if self.config.capacity < MEMBER_COUNT:
            _fail(CompositionBackpressureError, "authoritative_capacity")
        now = int(self.clock.now_ms())
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                if connection.execute("SELECT COUNT(*) FROM authoritative_batches WHERE status IN ('ISSUED','RESERVED')").fetchone()[0] != 0:
                    _fail(CompositionConflictError, "authoritative_batch_pending")
                try:
                    verify_authoritative_connection(connection)
                except Exception:
                    _fail(CompositionIntegrityError, "authoritative_ledger")
                ledger = connection.execute("SELECT lifetime_cap,computational_units_used,statistical_units_used,last_key_epoch FROM authoritative_profile_ledger WHERE profile_id=?", (SOURCE_AUTH_PROFILE_ID,)).fetchone()
                if ledger is None or int(ledger[0]) != LIFETIME_ACCEPTANCE_CAP or int(ledger[1]) < 0 or int(ledger[1]) > int(ledger[0]) or int(ledger[2]) != 0 or int(ledger[3]) < 0:
                    _fail(CompositionIntegrityError, "authoritative_ledger")
                source_key_epoch = int(ledger[3])
                reservation_before = int(ledger[1])
                try:
                    compute_reservation_after(reservation_before)
                except AuthoritativeAssertionError as error:
                    _fail(CompositionIntegrityError, str(error))
                refs = tuple(secrets.token_bytes(32) for _ in templates)
                zero_root = bytes(64)
                unsigned = tuple(AuthoritativeIssuedOperationV1(ref, template, position, zero_root) for position, (ref, template) in enumerate(zip(refs, templates)))
                batch_root = compute_batch_root(unsigned)
                statements = tuple(AuthoritativeIssuedOperationV1(statement.operation_ref, statement.template, statement.batch_position, batch_root) for statement in unsigned)
                batch = AuthoritativeBatchStatementV1(statements, batch_root, source_key_epoch)
                connection.execute("INSERT INTO authoritative_batches VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (batch_root, MEMBER_COUNT, "ISSUED", batch.state_profile_version, SOURCE_AUTH_PROFILE_ID, SIGNATURE_PROFILE_VERSION, batch.source_key_epoch, RESERVATION_UNITS, reservation_before, reservation_before, 0, None, now, now, None))
                for statement in statements:
                    template = statement.template
                    connection.execute("INSERT INTO authoritative_operations VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", (statement.operation_ref, batch_root, statement.batch_position, template.assertion_identifier, template.assertion_version, template.state_profile_version, template.valid_from_ms, template.valid_until_ms, template.approved_source_registry_root, b"authoritative_assertion_v1", "ISSUED", now))
                connection.execute("COMMIT")
            except CompositionError:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
            except sqlite3.Error:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                _fail(CompositionIntegrityError, "authoritative_batch_issue")
        return batch

    def reserve_authoritative_batch(self, batch: AuthoritativeBatchStatementV1) -> AuthoritativeReservation:
        """Atomically consume the 101 computational units before crypto."""
        if type(batch) is not AuthoritativeBatchStatementV1:
            _fail(CompositionIntegrityError, "authoritative_batch_shape")
        try:
            stored = read_authoritative_batch(self.path, batch.batch_root, expected_status="ISSUED")
        except Exception as error:
            if isinstance(error, CompositionError):
                raise
            _fail(CompositionIntegrityError, "authoritative_batch_binding")
        if stored.batch != batch:
            _fail(CompositionIntegrityError, "authoritative_batch_binding")
        reservation_time: int | None = None
        terminal_error: str | None = None
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    verify_authoritative_connection(connection)
                except Exception:
                    _fail(CompositionIntegrityError, "authoritative_ledger")
                row = connection.execute("SELECT * FROM authoritative_batches WHERE batch_root=?", (batch.batch_root,)).fetchone()
                if row is None:
                    _fail(CompositionIntegrityError, "authoritative_batch_unknown")
                if str(row[2]) != "ISSUED":
                    _fail(CompositionConflictError, "authoritative_handoff_duplicate")
                ledger = connection.execute("SELECT lifetime_cap,computational_units_used,statistical_units_used,last_key_epoch FROM authoritative_profile_ledger WHERE profile_id=?", (SOURCE_AUTH_PROFILE_ID,)).fetchone()
                if ledger is None or int(ledger[0]) != LIFETIME_ACCEPTANCE_CAP or int(ledger[2]) != 0:
                    _fail(CompositionIntegrityError, "authoritative_ledger")
                if batch.source_key_epoch != int(ledger[3]):
                    _fail(CompositionIntegrityError, "authoritative_key_epoch")
                used = int(ledger[1])
                before = int(row[8])
                if used != before or int(row[9]) != before or int(row[10]) != 0 or row[11] is not None:
                    _fail(CompositionIntegrityError, "authoritative_ledger_coordination")
                now = _clock_ms(self.clock)
                if now < int(row[12]):
                    terminal_error = "authoritative_clock_rewind"
                elif any(not statement.template.valid_from_ms <= now < statement.template.valid_until_ms for statement in batch.statements):
                    terminal_error = "authoritative_validity_window"
                if terminal_error is not None:
                    connection.execute("UPDATE authoritative_batches SET status='HELD',cryptographic_attempted=0,verification_time_ms=?,reservation_before=?,reservation_after=?,updated_ms=?,last_error_code=? WHERE batch_root=? AND status='ISSUED'", (now, before, before, now, terminal_error, batch.batch_root))
                    if connection.execute("SELECT changes()").fetchone()[0] != 1:
                        _fail(CompositionIntegrityError, "authoritative_reservation")
                    connection.execute("UPDATE authoritative_operations SET status='HELD',updated_ms=? WHERE batch_root=? AND status='ISSUED'", (now, batch.batch_root))
                    if connection.execute("SELECT changes()").fetchone()[0] != MEMBER_COUNT:
                        _fail(CompositionIntegrityError, "authoritative_reservation")
                else:
                    try:
                        after = compute_reservation_after(used)
                    except AuthoritativeAssertionError as error:
                        _fail(CompositionIntegrityError, str(error))
                    connection.execute("UPDATE authoritative_profile_ledger SET computational_units_used=?,last_key_epoch=MAX(last_key_epoch,?) WHERE profile_id=? AND lifetime_cap=? AND computational_units_used=?", (after, batch.source_key_epoch, SOURCE_AUTH_PROFILE_ID, LIFETIME_ACCEPTANCE_CAP, used))
                    if connection.execute("SELECT changes()").fetchone()[0] != 1:
                        _fail(CompositionIntegrityError, "authoritative_ledger_coordination")
                    connection.execute("UPDATE authoritative_batches SET status='RESERVED',reservation_after=?,cryptographic_attempted=1,verification_time_ms=?,updated_ms=? WHERE batch_root=? AND status='ISSUED' AND reservation_before=? AND reservation_after=? AND cryptographic_attempted=0 AND verification_time_ms IS NULL", (after, now, now, batch.batch_root, before, before))
                    if connection.execute("SELECT changes()").fetchone()[0] != 1:
                        _fail(CompositionIntegrityError, "authoritative_reservation")
                    connection.execute("UPDATE authoritative_operations SET status='RESERVED',updated_ms=? WHERE batch_root=? AND status='ISSUED'", (now, batch.batch_root))
                    if connection.execute("SELECT changes()").fetchone()[0] != MEMBER_COUNT:
                        _fail(CompositionIntegrityError, "authoritative_reservation")
                    reservation_time = now
                connection.execute("COMMIT")
            except (CompositionError, sqlite3.Error):
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        if terminal_error is not None:
            _fail(CompositionIntegrityError, terminal_error)
        if reservation_time is None:
            _fail(CompositionIntegrityError, "authoritative_reservation")
        return _create_reservation(batch.batch_root, reservation_time)

    def hold_authoritative_batch(self, batch: AuthoritativeBatchStatementV1, result: AuthoritativeAssertionResultV1, *, error_code: str | None = None) -> None:
        """Consume a failed handoff without creating state or outbox rows."""
        if type(batch) is not AuthoritativeBatchStatementV1 or type(result) is not AuthoritativeAssertionResultV1 or not result.verifier_owned or result.batch_root != batch.batch_root or result.source_key_epoch != batch.source_key_epoch or result.assertion_accepted:
            _fail(CompositionIntegrityError, "authoritative_result_binding")
        if result.error_code is None or (error_code is not None and error_code != result.error_code):
            _fail(CompositionIntegrityError, "authoritative_result_binding")
        now = _clock_ms(self.clock)
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    verify_authoritative_connection(connection)
                except Exception:
                    _fail(CompositionIntegrityError, "authoritative_ledger")
                row = connection.execute("SELECT * FROM authoritative_batches WHERE batch_root=?", (batch.batch_root,)).fetchone()
                if row is None:
                    _fail(CompositionIntegrityError, "authoritative_batch_unknown")
                if str(row[2]) != "RESERVED":
                    _fail(CompositionConflictError, "authoritative_handoff_duplicate")
                if int(row[10]) != 1 or row[11] is None or result.verification_time_ms != int(row[11]):
                    _fail(CompositionIntegrityError, "authoritative_result_binding")
                connection.execute("INSERT INTO authoritative_results VALUES (?,?,?,?,?,?,?)", (batch.batch_root, 0, result.receipt_bytes, result.receipt_digest, result.outcome_code, result.error_code, result.verification_time_ms))
                connection.execute("UPDATE authoritative_batches SET status='HELD',updated_ms=?,last_error_code=? WHERE batch_root=? AND status='RESERVED'", (now, result.error_code, batch.batch_root))
                if connection.execute("SELECT changes()").fetchone()[0] != 1:
                    _fail(CompositionIntegrityError, "authoritative_batch_finalize")
                connection.execute("UPDATE authoritative_operations SET status='HELD',updated_ms=? WHERE batch_root=? AND status='RESERVED'", (now, batch.batch_root))
                if connection.execute("SELECT changes()").fetchone()[0] != MEMBER_COUNT:
                    _fail(CompositionIntegrityError, "authoritative_batch_finalize")
                connection.execute("COMMIT")
            except (CompositionError, sqlite3.Error):
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

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
            accepted = getattr(job, "proof_accepted", getattr(job, "assertion_accepted", False))
            if control.operation_ref != job.operation_ref or job.status not in {"VERIFIED", "RESERVED"} or not accepted:
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

    def _receipt(self, job: IndependentVerifiedQueueJob, control: StateDispositionControl, directive: str, seq_before: int, seq_after: int, count_before: int, count_after: int, *, evidence_mode: str = "PRIVATE_ZK", assertion_accepted: bool = False, batch_root: bytes | None = None, assertion_receipt_digest: bytes | None = None) -> bytes:
        audit_after = _sha(_STATE, control.predecessor_audit_head, control.decision_id, directive.encode("ascii"))
        value = {"schema": _SCHEMA, "operation_ref": _hex(job.operation_ref), "proof_accepted": evidence_mode == "PRIVATE_ZK", "policy_result": control.policy_result, "effective_directive": directive, "state_profile_identity": _hex(control.state_profile_identity), "state_before_id": _hex(control.predecessor_state_id), "state_before_bytes": _hex(control.predecessor_state_bytes), "state_after_id": _hex(control.state_after_id), "state_after_bytes": _hex(control.state_after_bytes), "epoch": control.epoch, "predecessor_continuity_root": _hex(control.predecessor_continuity_root), "state_after_continuity_root": _hex(control.state_after_continuity_root), "predecessor_audit_head": _hex(control.predecessor_audit_head), "decision_id": _hex(control.decision_id), "state_after_audit_head": _hex(audit_after), "predecessor_clearance_root": _hex(control.predecessor_clearance_root), "state_after_clearance_root": _hex(control.state_after_clearance_root), "clearance_marker_before": control.clearance_marker_before, "clearance_marker_after": int(bool(control.clearance_marker_before or directive in {"CLEAR", "EXCEPTION_APPROVED"})), "sequence_before": seq_before, "sequence_after": seq_after, "clearance_count_before": count_before, "clearance_count_after": count_after, "payment_root": _hex(control.payment_root), "exception_approved": control.exception_approved, "exception_authorization_id": _hex(control.exception_authorization_id), "economic_mutation": False, "proof_suite_id": None, "production_usable": False, "activation": False}
        if evidence_mode == AUTHORITATIVE_ASSERTION_MODE:
            if not assertion_accepted or batch_root is None or assertion_receipt_digest is None:
                _fail(CompositionIntegrityError, "authoritative_receipt_binding")
            value.update({"evidence_mode": AUTHORITATIVE_ASSERTION_MODE, "assertion_accepted": True, "batch_root": _hex(batch_root), "assertion_receipt_digest": _hex(assertion_receipt_digest)})
        elif evidence_mode != "PRIVATE_ZK":
            _fail(CompositionIntegrityError, "evidence_mode")
        return _json_bytes(value)

    @staticmethod
    def _result(job: IndependentVerifiedQueueJob, status: str, disposition: bytes, receipt: bytes | None, duplicate: bool, error: str | None) -> CompositionProcessResultV2:
        digest = None if receipt is None else _sha(_STATE, receipt)
        job_id = _hex(job.operation_ref)
        return CompositionProcessResultV2(job_id, job.operation_ref, status, disposition, receipt, digest, job_id if status == "APPLIED" else None, job.operation_ref if status == "APPLIED" else None, duplicate, error)

    def process_verified_jobs(self, queue_database: Path, promotion_batch: IndependentVerifiedQueueBatch | list[str] | tuple[str, ...], *, state_controls: Mapping[bytes, StateDispositionControl] | None = None) -> tuple[CompositionProcessResultV2, ...]:
        if type(promotion_batch) is not IndependentVerifiedQueueBatch:
            _fail(CompositionIntegrityError, "promotion_batch_required")
        requested = promotion_batch
        selector = requested.batch.batch_id
        try:
            batch = read_verified_batch(queue_database, selector)
        except (IndependentQueueError, OSError, sqlite3.Error):
            _fail(CompositionIntegrityError, "queue_verification_failed")
        if not batch.jobs or any(job.queue_id != self.config.queue_id or job.config_digest != self.config.queue_config_digest for job in batch.jobs):
            _fail(CompositionIntegrityError, "queue_authority_binding")
        if requested.batch != batch.batch or requested.jobs != batch.jobs:
            _fail(CompositionIntegrityError, "queue_batch_binding")
        prepared = [(job, self._control_for(job, state_controls)) for job in batch.jobs]
        if not prepared:
            _fail(CompositionIntegrityError, "empty_batch")
        now = int(self.clock.now_ms())
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                existing = [connection.execute("SELECT * FROM composition_transactions WHERE operation_ref=?", (job.operation_ref,)).fetchone() for job, _ in prepared]
                if any(row is not None for row in existing) and not all(row is not None for row in existing):
                    _fail(CompositionConflictError, "composition_conflicting_retry")
                if all(row is not None for row in existing):
                    if len({str(row[2]) for row in existing if row is not None}) != 1 or any(str(row[2]) != "APPLIED" for row in existing if row is not None):
                        _fail(CompositionIntegrityError, "composition_batch_state_chain")
                    for (job, control), row in zip(prepared, existing):
                        if row is None or str(row[4]) != control.policy_result or str(row[5]) != control.effective_directive or row[12] is None:
                            _fail(CompositionConflictError, "composition_conflicting_retry")
                        expected_receipt = self._receipt(job, control, control.effective_directive, int(row[10]), int(row[11]), control.clearance_count_before, control.clearance_count_before + int(control.effective_directive in {"CLEAR", "EXCEPTION_APPROVED"}))
                        if bytes(row[12]) != expected_receipt or bytes(row[13]) != _sha(_STATE, expected_receipt):
                            _fail(CompositionConflictError, "composition_conflicting_retry")
                    connection.execute("COMMIT")
                    return tuple(self._result(job, str(row[2]), bytes(row[6]), None if row[12] is None else bytes(row[12]), True, None if row[14] is None else str(row[14])) for (job, _), row in zip(prepared, existing) if row is not None)
                checked = self._preflight(connection, prepared)
                if int(self._meta(connection)[16]) + len(prepared) > self.config.capacity:
                    _fail(CompositionBackpressureError, "outbox_capacity")
                results: list[CompositionProcessResultV2] = []
                current_state = self._meta(connection)
                for (job, control), (_, directive, state_before_id, state_after_id, seq_before, seq_after, count_before, count_after) in zip(prepared, checked):
                    disposition = _sha(_MATERIAL, b"disposition", job.operation_ref, directive.encode("ascii"), control.state_profile_identity)
                    transaction_id = _sha(_MATERIAL, b"transaction", disposition)
                    receipt = self._receipt(job, control, directive, seq_before, seq_after, count_before, count_after)
                    receipt_digest = _sha(_STATE, receipt)
                    tx = (transaction_id, job.operation_ref, "APPLIED", 1, control.policy_result, directive, disposition, control.state_profile_identity, state_before_id, state_after_id, seq_before, seq_after, receipt, receipt_digest, None, now, now)
                    connection.execute("INSERT INTO composition_transactions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", tx)
                    connection.execute("INSERT INTO composition_outbox VALUES (?,?,?,?,?,?,?,?)", (job.operation_ref, directive, "READY", 0, None, None, None, now))
                    payload = {"operation_ref": _hex(job.operation_ref), "proof_accepted": True, "policy_result": control.policy_result, "effective_directive": directive, "state_receipt_digest": _hex(receipt_digest), "sequence_before": seq_before, "sequence_after": seq_after}
                    self._append_event(connection, operation_ref=job.operation_ref, kind="APPLIED", before="NONE", after="READY", payload=payload, at_ms=now)
                    audit_after = _sha(_STATE, bytes(current_state[12]) if current_state[12] is not None else _ZERO, control.decision_id, directive.encode("ascii"))
                    clearance_after = control.state_after_clearance_root
                    connection.execute("UPDATE composition_meta SET state_profile_identity=?,state_id=?,state_bytes=?,state_epoch=?,state_sequence=?,state_continuity_root=?,state_audit_head=?,state_clearance_root=?,state_clearance_count=?,payment_root=?,active_dispatch_count=active_dispatch_count+1 WHERE id=1", (control.state_profile_identity, state_after_id, control.state_after_bytes, control.epoch, seq_after, control.state_after_continuity_root, audit_after, clearance_after, count_after, _INITIAL_PAYMENT))
                    current_state = self._meta(connection)
                    results.append(self._result(job, "APPLIED", disposition, receipt, False, None))
                self._fault("before_composition_commit")
                connection.execute("COMMIT")
            except (CompositionError, sqlite3.Error):
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                _fail(CompositionIntegrityError, "composition_transaction_rollback")
        self._after_fault("after_composition_commit")
        return tuple(results)

    def process_authoritative_assertion(self, batch: AuthoritativeBatchStatementV1, result: AuthoritativeAssertionResultV1, *, state_controls: Mapping[bytes, StateDispositionControl] | None = None) -> tuple[CompositionProcessResultV2, ...]:
        """Apply one accepted source assertion batch through the same state owner."""
        if type(batch) is not AuthoritativeBatchStatementV1 or type(result) is not AuthoritativeAssertionResultV1 or not result.verifier_owned or result.batch_root != batch.batch_root or result.source_key_epoch != batch.source_key_epoch or not result.assertion_accepted:
            _fail(CompositionIntegrityError, "authoritative_result_binding")
        try:
            stored = read_authoritative_batch(self.path, batch.batch_root)
        except Exception:
            _fail(CompositionIntegrityError, "authoritative_batch_verification_failed")
        if stored.batch != batch or stored.status not in {"RESERVED", "APPLIED"} or not stored.cryptographic_attempted or stored.verification_time_ms is None or any(not job.valid_from_ms <= stored.verification_time_ms < job.valid_until_ms for job in stored.jobs):
            _fail(CompositionIntegrityError, "authoritative_batch_binding")
        if result.verification_time_ms != stored.verification_time_ms:
            _fail(CompositionIntegrityError, "authoritative_result_binding")
        if stored.status == "APPLIED" and stored.result != result:
            _fail(CompositionIntegrityError, "authoritative_result_binding")
        if stored.status == "RESERVED" and stored.result is not None:
            _fail(CompositionIntegrityError, "authoritative_result_binding")
        prepared_jobs = tuple(IndependentAuthoritativeAssertionJob(job.operation_ref, job.batch_root, job.batch_position, job.assertion_identifier, job.assertion_version, job.state_profile_version, job.valid_from_ms, job.valid_until_ms, job.approved_source_registry_root, job.qualification_flags, "RESERVED", True) for job in stored.jobs)
        prepared = [(job, self._control_for(job, state_controls)) for job in prepared_jobs]
        terminal_error: str | None = None
        results: list[CompositionProcessResultV2] = []
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                now = _clock_ms(self.clock)
                try:
                    verify_authoritative_connection(connection)
                except Exception:
                    _fail(CompositionIntegrityError, "authoritative_ledger")
                live = connection.execute("SELECT status,cryptographic_attempted,verification_time_ms,reservation_before,reservation_after FROM authoritative_batches WHERE batch_root=?", (batch.batch_root,)).fetchone()
                if live is None or int(live[1]) != 1 or live[2] is None or int(live[2]) != stored.verification_time_ms or int(live[3]) != stored.reservation_before or int(live[4]) != stored.reservation_after:
                    _fail(CompositionIntegrityError, "authoritative_batch_state")
                live_status = str(live[0])
                if live_status not in {"RESERVED", "APPLIED"} or (stored.status == "APPLIED" and live_status != "APPLIED") or (stored.status == "RESERVED" and live_status not in {"RESERVED", "APPLIED"}):
                    _fail(CompositionIntegrityError, "authoritative_batch_state")
                if live_status == "APPLIED":
                    durable_result = connection.execute("SELECT * FROM authoritative_results WHERE batch_root=?", (batch.batch_root,)).fetchone()
                    if durable_result is None or len(durable_result) != 7 or int(durable_result[1]) != 1 or bytes(durable_result[2]) != result.receipt_bytes or bytes(durable_result[3]) != result.receipt_digest or str(durable_result[4]) != result.outcome_code or durable_result[5] != result.error_code or int(durable_result[6]) != result.verification_time_ms:
                        _fail(CompositionIntegrityError, "authoritative_result_binding")
                if now < stored.verification_time_ms:
                    if live_status == "RESERVED":
                        terminal_error = "authoritative_clock_rewind"
                    else:
                        _fail(CompositionIntegrityError, "authoritative_clock_rewind")
                elif live_status == "RESERVED" and any(not job.valid_from_ms <= now < job.valid_until_ms for job in prepared_jobs):
                    terminal_error = "authoritative_validity_window"
                if terminal_error is not None:
                    connection.execute("UPDATE authoritative_batches SET status='HELD',cryptographic_attempted=1,verification_time_ms=?,reservation_before=?,reservation_after=?,updated_ms=?,last_error_code=? WHERE batch_root=? AND status='RESERVED' AND cryptographic_attempted=1 AND verification_time_ms=? AND reservation_before=? AND reservation_after=?", (stored.verification_time_ms, stored.reservation_before, stored.reservation_after, now, terminal_error, batch.batch_root, stored.verification_time_ms, stored.reservation_before, stored.reservation_after))
                    if connection.execute("SELECT changes()").fetchone()[0] != 1:
                        _fail(CompositionIntegrityError, "authoritative_batch_finalize")
                    connection.execute("UPDATE authoritative_operations SET status='HELD',updated_ms=? WHERE batch_root=? AND status='RESERVED'", (now, batch.batch_root))
                    if connection.execute("SELECT changes()").fetchone()[0] != MEMBER_COUNT:
                        _fail(CompositionIntegrityError, "authoritative_batch_finalize")
                    connection.execute("COMMIT")
                else:
                    if any(not job.valid_from_ms <= stored.verification_time_ms < job.valid_until_ms for job in prepared_jobs):
                        _fail(CompositionIntegrityError, "authoritative_validity_window")
                    existing = [connection.execute("SELECT * FROM composition_transactions WHERE operation_ref=?", (job.operation_ref,)).fetchone() for job, _ in prepared]
                    if any(row is not None for row in existing) and not all(row is not None for row in existing):
                        _fail(CompositionConflictError, "composition_conflicting_retry")
                    if live_status == "APPLIED" and not all(row is not None for row in existing):
                        _fail(CompositionIntegrityError, "authoritative_batch_state")
                    if live_status == "RESERVED" and any(row is not None for row in existing):
                        _fail(CompositionIntegrityError, "authoritative_batch_state")
                    if all(row is not None for row in existing):
                        if len({str(row[2]) for row in existing if row is not None}) != 1 or any(str(row[2]) != "APPLIED" for row in existing if row is not None) or any(int(row[3]) != 0 for row in existing if row is not None):
                            _fail(CompositionIntegrityError, "authoritative_batch_state")
                        for (job, control), row in zip(prepared, existing):
                            if row is None or str(row[4]) != control.policy_result or str(row[5]) != control.effective_directive or row[12] is None:
                                _fail(CompositionConflictError, "composition_conflicting_retry")
                            receipt = self._receipt(job, control, control.effective_directive, int(row[10]), int(row[11]), control.clearance_count_before, control.clearance_count_before + int(control.effective_directive in {"CLEAR", "EXCEPTION_APPROVED"}), evidence_mode=AUTHORITATIVE_ASSERTION_MODE, assertion_accepted=True, batch_root=batch.batch_root, assertion_receipt_digest=result.receipt_digest)
                            if bytes(row[12]) != receipt or bytes(row[13]) != _sha(_STATE, receipt):
                                _fail(CompositionConflictError, "composition_conflicting_retry")
                        connection.execute("COMMIT")
                        return tuple(self._result(job, str(row[2]), bytes(row[6]), bytes(row[12]), True, None) for (job, _), row in zip(prepared, existing) if row is not None)
                    checked = self._preflight(connection, prepared)
                    if int(self._meta(connection)[16]) + len(prepared) > self.config.capacity:
                        _fail(CompositionBackpressureError, "outbox_capacity")
                    connection.execute("INSERT INTO authoritative_results VALUES (?,?,?,?,?,?,?)", (batch.batch_root, 1, result.receipt_bytes, result.receipt_digest, result.outcome_code, result.error_code, result.verification_time_ms))
                    current_state = self._meta(connection)
                    for (job, control), (_, directive, state_before_id, state_after_id, seq_before, seq_after, count_before, count_after) in zip(prepared, checked):
                        disposition = _sha(_MATERIAL, b"disposition", job.operation_ref, directive.encode("ascii"), control.state_profile_identity)
                        transaction_id = _sha(_MATERIAL, b"transaction", disposition)
                        receipt = self._receipt(job, control, directive, seq_before, seq_after, count_before, count_after, evidence_mode=AUTHORITATIVE_ASSERTION_MODE, assertion_accepted=True, batch_root=batch.batch_root, assertion_receipt_digest=result.receipt_digest)
                        receipt_digest = _sha(_STATE, receipt)
                        tx = (transaction_id, job.operation_ref, "APPLIED", 0, control.policy_result, directive, disposition, control.state_profile_identity, state_before_id, state_after_id, seq_before, seq_after, receipt, receipt_digest, None, now, now)
                        connection.execute("INSERT INTO composition_transactions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", tx)
                        connection.execute("INSERT INTO composition_outbox VALUES (?,?,?,?,?,?,?,?)", (job.operation_ref, directive, "READY", 0, None, None, None, now))
                        payload = {"operation_ref": _hex(job.operation_ref), "evidence_mode": AUTHORITATIVE_ASSERTION_MODE, "assertion_accepted": True, "proof_accepted": False, "batch_root": _hex(batch.batch_root), "policy_result": control.policy_result, "effective_directive": directive, "state_receipt_digest": _hex(receipt_digest), "sequence_before": seq_before, "sequence_after": seq_after}
                        self._append_event(connection, operation_ref=job.operation_ref, kind="APPLIED", before="NONE", after="READY", payload=payload, at_ms=now)
                        audit_after = _sha(_STATE, bytes(current_state[12]) if current_state[12] is not None else _ZERO, control.decision_id, directive.encode("ascii"))
                        connection.execute("UPDATE composition_meta SET state_profile_identity=?,state_id=?,state_bytes=?,state_epoch=?,state_sequence=?,state_continuity_root=?,state_audit_head=?,state_clearance_root=?,state_clearance_count=?,payment_root=?,active_dispatch_count=active_dispatch_count+1 WHERE id=1", (control.state_profile_identity, state_after_id, control.state_after_bytes, control.epoch, seq_after, control.state_after_continuity_root, audit_after, control.state_after_clearance_root, count_after, _INITIAL_PAYMENT))
                        connection.execute("UPDATE authoritative_operations SET status='APPLIED',updated_ms=? WHERE operation_ref=? AND status='RESERVED'", (now, job.operation_ref))
                        if connection.execute("SELECT changes()").fetchone()[0] != 1:
                            _fail(CompositionIntegrityError, "authoritative_batch_finalize")
                        current_state = self._meta(connection)
                        results.append(self._result(job, "APPLIED", disposition, receipt, False, None))
                    connection.execute("UPDATE authoritative_batches SET status='APPLIED',updated_ms=?,last_error_code=NULL WHERE batch_root=? AND status='RESERVED' AND cryptographic_attempted=1 AND verification_time_ms=?", (now, batch.batch_root, result.verification_time_ms))
                    if connection.execute("SELECT changes()").fetchone()[0] != 1:
                        _fail(CompositionIntegrityError, "authoritative_batch_finalize")
                    self._fault("before_composition_commit")
                    connection.execute("COMMIT")
            except (CompositionError, sqlite3.Error):
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                _fail(CompositionIntegrityError, "composition_transaction_rollback")
        if terminal_error is not None:
            _fail(CompositionIntegrityError, terminal_error)
        self._after_fault("after_composition_commit")
        return tuple(results)

    def _expire_outbox_locked(self, connection: sqlite3.Connection, now: int) -> None:
        rows = connection.execute("SELECT operation_ref,attempt FROM composition_outbox WHERE status='LEASED' AND lease_expires_ms<=?", (now,)).fetchall()
        for ref, attempt in rows:
            next_status = "DELIVERY_UNCONFIRMED" if int(attempt) >= self.config.max_attempts else "READY"
            connection.execute("UPDATE composition_outbox SET status=?,worker_id=NULL,lease_token=NULL,lease_expires_ms=NULL,updated_ms=? WHERE operation_ref=? AND status='LEASED'", (next_status, now, bytes(ref)))

    def _outbox_work_matches(self, row: tuple[Any, ...], work: CompositionOutboxWorkV2, now: int) -> bool:
        if row is None or str(row[2]) != "LEASED" or bytes(row[0]) != work.operation_id or str(row[1]) != work.effective_directive or int(row[3]) != work.attempt or str(row[4]) != work.worker_id or row[5] is None or bytes(row[5]) != _sha(_LEASE, work.lease_token) or row[6] is None or int(row[6]) <= now:
            return False
        expected_envelope = _envelope(work.operation_id, work.effective_directive, self.config)
        return work.envelope_bytes == expected_envelope and work.idempotency_key == _sha(_MATERIAL, work.operation_id, work.effective_directive.encode("ascii"))

    def _reconciliation_work_matches(self, row: tuple[Any, ...] | None, work: CompositionReconciliationWorkV2, directive: str, now: int) -> bool:
        if row is None or str(row[2]) != "LEASED" or bytes(row[0]) != work.operation_id or str(row[1]) != directive or int(row[3]) != work.attempt or str(row[4]) != work.worker_id or row[5] is None or bytes(row[5]) != _sha(_LEASE, work.lease_token) or row[6] is None or int(row[6]) <= now:
            return False
        envelope = _envelope(work.operation_id, directive, self.config)
        return work.envelope_digest == _sha(_MATERIAL, envelope) and work.idempotency_key == _sha(_MATERIAL, work.operation_id, directive.encode("ascii"))

    def claim_next_outbox(self, worker_id: str) -> CompositionOutboxWorkV2 | None:
        _token(worker_id, "worker_id")
        now = int(self.clock.now_ms())
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._expire_outbox_locked(connection, now)
            row = connection.execute("SELECT operation_ref,effective_directive,attempt FROM composition_outbox WHERE status='READY' ORDER BY updated_ms,operation_ref LIMIT 1").fetchone()
            if row is None:
                connection.execute("COMMIT")
                return None
            ref, directive, attempt = bytes(row[0]), str(row[1]), int(row[2]) + 1
            token = secrets.token_bytes(32)
            expires = now + self.config.lease_seconds * 1000
            connection.execute("UPDATE composition_outbox SET status='LEASED',attempt=?,worker_id=?,lease_token=?,lease_expires_ms=?,updated_ms=? WHERE operation_ref=? AND status='READY' AND attempt<?", (attempt, worker_id, _sha(_LEASE, token), expires, now, ref, self.config.max_attempts))
            connection.execute("COMMIT")
        return CompositionOutboxWorkV2(self.config.composition_id, _hex(ref), ref, attempt, worker_id, token, expires, _envelope(ref, directive, self.config), _sha(_MATERIAL, ref, directive.encode("ascii")), directive)

    def dispatch(self, work: CompositionOutboxWorkV2, *, receiver: OfficialStateReceiverPort) -> CompositionDeliveryResultV2:
        if type(work) is not CompositionOutboxWorkV2:
            _fail(CompositionLeaseError, "outbox_work")
        now = int(self.clock.now_ms())
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT * FROM composition_outbox WHERE operation_ref=?", (work.operation_id,)).fetchone()
            if not self._outbox_work_matches(tuple(row) if row is not None else None, work, now):
                connection.execute("ROLLBACK")
                _fail(CompositionLeaseError, "outbox_lease_fence")
            connection.execute("COMMIT")
        try:
            ack = receiver.dispatch(work.envelope_bytes, work.idempotency_key)
            _parse_acknowledgment(ack, envelope_bytes=work.envelope_bytes, idempotency_key=work.idempotency_key, operation_ref=work.operation_id, directive=work.effective_directive)
        except CompositionError:
            ack = None
        except BaseException:
            ack = None
        if ack is None:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute("SELECT * FROM composition_outbox WHERE operation_ref=?", (work.operation_id,)).fetchone()
                if row is not None and self._outbox_work_matches(tuple(row), work, int(self.clock.now_ms())):
                    connection.execute("UPDATE composition_outbox SET status='DELIVERY_UNCONFIRMED',worker_id=NULL,lease_token=NULL,lease_expires_ms=NULL,updated_ms=? WHERE operation_ref=? AND status='LEASED'", (int(self.clock.now_ms()), work.operation_id))
                connection.execute("COMMIT")
            return CompositionDeliveryResultV2(work.job_id, work.operation_id, "DELIVERY_UNCONFIRMED", None, None, "delivery_unconfirmed")
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT * FROM composition_outbox WHERE operation_ref=?", (work.operation_id,)).fetchone()
            if row is None or not self._outbox_work_matches(tuple(row), work, int(self.clock.now_ms())):
                connection.execute("ROLLBACK")
                return CompositionDeliveryResultV2(work.job_id, work.operation_id, "DELIVERY_UNCONFIRMED", None, None, "delivery_unconfirmed")
            connection.execute("UPDATE composition_outbox SET status='ACKNOWLEDGED',worker_id=NULL,lease_token=NULL,lease_expires_ms=NULL,updated_ms=? WHERE operation_ref=? AND status='LEASED'", (int(self.clock.now_ms()), work.operation_id))
            connection.execute("UPDATE composition_meta SET active_dispatch_count=max(0,active_dispatch_count-1) WHERE id=1")
            connection.execute("COMMIT")
        return CompositionDeliveryResultV2(work.job_id, work.operation_id, "ACKNOWLEDGED", ack, _sha(_MATERIAL, ack), None)

    def claim_reconciliation_next(self, worker_id: str) -> CompositionReconciliationWorkV2 | None:
        _token(worker_id, "worker_id")
        now = int(self.clock.now_ms())
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._expire_outbox_locked(connection, now)
            row = connection.execute("SELECT operation_ref,effective_directive,attempt FROM composition_outbox WHERE status='DELIVERY_UNCONFIRMED' AND attempt<? ORDER BY updated_ms,operation_ref LIMIT 1", (self.config.max_attempts,)).fetchone()
            if row is None:
                connection.execute("COMMIT")
                return None
            ref, directive, attempt = bytes(row[0]), str(row[1]), int(row[2]) + 1
            token = secrets.token_bytes(32)
            expires = now + self.config.reconciliation_lease_seconds * 1000
            updated = connection.execute("UPDATE composition_outbox SET status='LEASED',attempt=?,worker_id=?,lease_token=?,lease_expires_ms=?,updated_ms=? WHERE operation_ref=? AND status='DELIVERY_UNCONFIRMED' AND attempt<?", (attempt, worker_id, _sha(_LEASE, token), expires, now, ref, self.config.max_attempts))
            if updated.rowcount != 1:
                connection.execute("ROLLBACK")
                return None
            connection.execute("COMMIT")
        envelope = _envelope(ref, directive, self.config)
        return CompositionReconciliationWorkV2(self.config.composition_id, _hex(ref), ref, attempt, worker_id, token, expires, _sha(_MATERIAL, envelope), _sha(_MATERIAL, ref, directive.encode("ascii")))

    def reconcile_next(self, worker_id: str, *, lookup: OfficialStateReceiverLookupPort | None = None) -> CompositionDeliveryResultV2 | None:
        if lookup is None:
            _fail(CompositionLeaseError, "reconciliation_lookup_required")
        work = self.claim_reconciliation_next(worker_id)
        if work is None:
            return None
        with closing(self._connect()) as connection:
            row = connection.execute("SELECT effective_directive FROM composition_outbox WHERE operation_ref=?", (work.operation_id,)).fetchone()
        if row is None:
            _fail(CompositionLeaseError, "reconciliation_work")
        directive = str(row[0])
        envelope = _envelope(work.operation_id, directive, self.config)
        with closing(self._connect()) as connection:
            row = connection.execute("SELECT * FROM composition_outbox WHERE operation_ref=?", (work.operation_id,)).fetchone()
            if not self._reconciliation_work_matches(tuple(row) if row is not None else None, work, directive, int(self.clock.now_ms())):
                _fail(CompositionLeaseError, "outbox_lease_fence")
        try:
            ack = lookup.lookup_acknowledgment(operation_ref=work.operation_id, idempotency_key=work.idempotency_key)
            if ack is not None:
                _parse_acknowledgment(ack, envelope_bytes=envelope, idempotency_key=work.idempotency_key, operation_ref=work.operation_id, directive=directive)
        except BaseException:
            ack = None
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT * FROM composition_outbox WHERE operation_ref=?", (work.operation_id,)).fetchone()
            live = self._reconciliation_work_matches(tuple(row) if row is not None else None, work, directive, int(self.clock.now_ms()))
            if ack is None:
                if live:
                    connection.execute("UPDATE composition_outbox SET status='DELIVERY_UNCONFIRMED',worker_id=NULL,lease_token=NULL,lease_expires_ms=NULL,updated_ms=? WHERE operation_ref=? AND status='LEASED'", (int(self.clock.now_ms()), work.operation_id))
                connection.execute("COMMIT")
                return CompositionDeliveryResultV2(work.job_id, work.operation_id, "DELIVERY_UNCONFIRMED", None, None, "delivery_unconfirmed")
            if not live:
                connection.execute("COMMIT")
                return CompositionDeliveryResultV2(work.job_id, work.operation_id, "DELIVERY_UNCONFIRMED", None, None, "delivery_unconfirmed")
            connection.execute("UPDATE composition_outbox SET status='ACKNOWLEDGED',worker_id=NULL,lease_token=NULL,lease_expires_ms=NULL,updated_ms=? WHERE operation_ref=? AND status='LEASED'", (int(self.clock.now_ms()), work.operation_id))
            connection.execute("UPDATE composition_meta SET active_dispatch_count=max(0,active_dispatch_count-1) WHERE id=1")
            connection.execute("COMMIT")
        return CompositionDeliveryResultV2(work.job_id, work.operation_id, "ACKNOWLEDGED", ack, _sha(_MATERIAL, ack), None)

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


__all__ = ("ClearanceCompositionStoreV2", "CompositionBackpressureError", "CompositionClock", "CompositionConflictError", "CompositionConfigV2", "CompositionDeliveryResultV2", "CompositionError", "CompositionIndeterminateError", "CompositionIntegrityError", "CompositionLeaseError", "CompositionOutboxWorkV2", "CompositionProcessResultV2", "CompositionReconciliationWorkV2", "OfficialStateReceiverLookupPort", "OfficialStateReceiverPort", "StateDispositionControl", "SyntheticAckEvidenceProfileV2", "build_synthetic_acknowledgment", "resolve_effective_directive")
