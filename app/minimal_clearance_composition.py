"""Single-owner synthetic clearance composition and official handoff V2."""

from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
from functools import wraps
import hashlib
import json
from pathlib import Path
import re
import secrets
import sqlite3
import time
from typing import Any, Callable, Final, Mapping, NoReturn, Protocol

from app.minimal_clearance_acceptance_independent import parse_acceptance_bytes
from app.minimal_clearance_verification_queue_independent import (
    IndependentQueueError,
    IndependentVerifiedQueueBatch,
    IndependentVerifiedQueueJob,
    read_verified_batch,
)


class CompositionError(RuntimeError): pass
class CompositionConflictError(CompositionError): pass
class CompositionBackpressureError(CompositionError): pass
class CompositionLeaseError(CompositionError): pass
class CompositionIntegrityError(CompositionError): pass
class CompositionIndeterminateError(CompositionError): pass


def _raise_fixed(error_type: type[CompositionError], code: str) -> NoReturn:
    error = error_type(code)
    try:
        raise error from None
    except CompositionError as clean:
        clean.__cause__ = None
        clean.__context__ = None
        raise


def _public_v2_api(method: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(method)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        try:
            return method(*args, **kwargs)
        except CompositionError as exc:
            exc.__cause__ = None
            exc.__context__ = None
            raise
        except Exception:
            _raise_fixed(CompositionIntegrityError, "composition_internal_error")
    return wrapped


_SCHEMA_VERSION: Final[int] = 3
_SCHEMA: Final[str] = "BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/v3"
_HANDOFF_SCHEMA: Final[str] = "BL/NATIVE-V3/MINIMAL-CLEARANCE/OFFICIAL-HANDOFF/v2"
_ACK_MODE: Final[str] = "SYNTHETIC_ONLY"
_DIRECTIVES: Final[tuple[str, ...]] = ("CLEAR", "HOLD", "HUMAN_REVIEW", "BLOCK", "EXCEPTION_APPROVED")
_DELIVERY_STATES: Final[frozenset[str]] = frozenset({"READY", "DISPATCH_LEASED", "DELIVERY_UNCONFIRMED", "RECONCILIATION_LEASED", "ACKNOWLEDGED", "DISPATCH_EXHAUSTED", "RECONCILIATION_EXHAUSTED"})
_EVENT_KINDS: Final[frozenset[str]] = frozenset({"APPLIED", "HELD", "DISPATCH_LEASED", "DISPATCH_RELEASED", "DELIVERY_UNCONFIRMED", "DISPATCH_LEASE_EXPIRED", "DISPATCH_EXHAUSTED", "RECONCILIATION_LEASED", "RECONCILIATION_INDETERMINATE", "RECONCILIATION_LEASE_EXPIRED", "RECONCILIATION_EXHAUSTED", "ACKNOWLEDGED", "ACKNOWLEDGED_BY_RECONCILIATION", "ACK_CONFLICT"})
_EVENT_PAYLOAD_KEYS: Final[dict[str, frozenset[str]]] = {
    "APPLIED": frozenset({"operation_digest", "queue_view_digest", "acceptance_digest", "artifact_digest", "state_receipt_digest", "envelope_digest", "outbox_operation_id", "idempotency_key", "policy_result", "effective_directive", "payment_root_unchanged", "settlement_id", "settlement_domain", "exception_authorization_id", "exception_scope_id", "exception_valid_from", "exception_valid_until", "queue_batch_id", "queue_batch_member_set_digest", "composition_batch_id", "batch_member_index", "batch_member_count"}),
    "HELD": frozenset({"acceptance_digest", "error_code"}),
    "DISPATCH_LEASED": frozenset({"attempt", "worker_id", "lease_token_digest", "lease_expires_ms"}),
    "DISPATCH_RELEASED": frozenset({"attempt", "error_code"}),
    "DELIVERY_UNCONFIRMED": frozenset({"attempt", "error_code"}),
    "DISPATCH_LEASE_EXPIRED": frozenset({"attempt", "error_code"}),
    "DISPATCH_EXHAUSTED": frozenset({"attempt", "error_code"}),
    "RECONCILIATION_LEASED": frozenset({"attempt", "worker_id", "lease_token_digest", "lease_expires_ms"}),
    "RECONCILIATION_INDETERMINATE": frozenset({"attempt", "error_code"}),
    "RECONCILIATION_LEASE_EXPIRED": frozenset({"attempt", "error_code"}),
    "RECONCILIATION_EXHAUSTED": frozenset({"attempt", "error_code"}),
    "ACKNOWLEDGED": frozenset({"ack_digest", "acknowledgment_id", "qualification_receipt_digest", "profile_digest", "policy_result", "effective_directive"}),
    "ACKNOWLEDGED_BY_RECONCILIATION": frozenset({"ack_digest", "acknowledgment_id", "qualification_receipt_digest", "profile_digest", "policy_result", "effective_directive"}),
    "ACK_CONFLICT": frozenset({"candidate_ack_digest", "stored_ack_digest", "error_code"}),
}
_TOKEN = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
_CODE = re.compile(r"[a-z][a-z0-9_]{0,95}\Z")
_MAX_RECEIPT = 16 * 1024
_MAX_ENVELOPE = 16 * 1024
_MAX_ACK = 4096
_MAX_ID = 128
_CAP_BYTES = 5_000_000_000
_ACTIVE_PROCESS_LIMIT = 1
_ZERO_SUITE = bytes(64)
_CIRCUIT_ID = bytes.fromhex("0f9fefb8cf05cc4e7a6b9657878c05a37034736d193272e14981f97fdd5a4275")
_COMPOSITION_TABLES: Final[frozenset[str]] = frozenset({"composition_meta", "composition_transactions", "composition_events"})
_MATERIAL = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/MATERIAL/v3\x00"
_GENESIS = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/GENESIS/v3\x00"
_HEAD = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/HEAD/v3\x00"
_EVENT = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/EVENT/v3\x00"
_STATE_OPERATION = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/PROOF-OPERATION/v1\x00"
_STATE_REPLAY = b"BL/MINIMAL-CLEARANCE/PROOF-REPLAY/v1\x00"
_STATE_CLEARANCE = b"BL/MINIMAL-CLEARANCE/CLEARANCE-ROOT/v1\x00"
_STATE_BINDING = b"BL/MINIMAL-CLEARANCE/STATE-BINDING/v1\x00"
_STATE_GENESIS = b"BL/MINIMAL-CLEARANCE/GENESIS/v1\x00"
_STATE_AUDIT_EVENT = b"BL/MINIMAL-CLEARANCE/AUDIT-EVENT/v1\x00"
_STATE_AUDIT_HEAD = b"BL/MINIMAL-CLEARANCE/AUDIT-HEAD/v1\x00"
_STATE_RECEIPT = b"BL/MINIMAL-CLEARANCE/RECEIPT/v1\x00"
_SETTLEMENT_REFERENCE = b"BL/NATIVE-V3/MINIMAL-SETTLEMENT-REFERENCE/v2\x00"
_STATE_IDENTITY = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/STATE-STORE-IDENTITY/v1\x00"
_ENVELOPE = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/OFFICIAL-DIRECTIVE-ENVELOPE/v2\x00"
_ACK = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/OFFICIAL-DIRECTIVE-ACK/v2\x00"
_ACK_PROFILE = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/OFFICIAL-DIRECTIVE-ACK-PROFILE/v2\x00"
_ACK_RECEIPT = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/OFFICIAL-DIRECTIVE-ACK-RECEIPT/v2\x00"
_OUTBOX_OPERATION = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/OFFICIAL-DIRECTIVE-OPERATION/v2\x00"
_IDEMPOTENCY = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/OFFICIAL-DIRECTIVE-IDEMPOTENCY/v2\x00"
_QUEUE_VIEW_SCHEMA = "BL/NATIVE-V3/MINIMAL-CLEARANCE/QUEUE-VIEW/v2"
_COMPOSITION_BATCH = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/BATCH/v1\x00"


def _sha(domain: bytes, *parts: bytes) -> bytes:
    digest = hashlib.sha3_512()
    digest.update(domain)
    for part in parts:
        if type(part) is not bytes:
            _raise_fixed(CompositionIntegrityError, "binding_type")
        digest.update(part)
    return digest.digest()


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        _raise_fixed(CompositionIntegrityError, "json")


def _hex(value: bytes) -> str: return value.hex().upper()


def _blob(value: object, size: int, label: str) -> bytes:
    if type(value) is not bytes or len(value) != size:
        _raise_fixed(CompositionIntegrityError, label + "_width")
    return bytes(value)


def _hex_blob(value: object, size: int, label: str) -> bytes:
    if type(value) is not str:
        _raise_fixed(CompositionIntegrityError, label)
    try: raw = bytes.fromhex(value)
    except ValueError: _raise_fixed(CompositionIntegrityError, label)
    if len(raw) != size: _raise_fixed(CompositionIntegrityError, label)
    return raw


def _token(value: object, label: str) -> str:
    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        _raise_fixed(CompositionIntegrityError, label + "_invalid")
    return value


def _code(value: object, label: str = "error_code") -> str:
    if type(value) is not str or _CODE.fullmatch(value) is None:
        _raise_fixed(CompositionIntegrityError, label + "_invalid")
    return value


def _u64(value: int) -> bytes:
    if type(value) is not int or not 0 <= value < 2**64:
        _raise_fixed(CompositionIntegrityError, "integer")
    return value.to_bytes(8, "big")


def _private_identity(label: str) -> bytes:
    return _sha(b"BL/NATIVE-V3/PRIVATE-ZK/IDENTITY/v1\x00", label.encode("ascii"))


_PRIVATE_CONTEXT = _private_identity("database-context.v1")
_PRIVATE_SCHEMA = _private_identity("database-schema.v1")
_PRIVATE_PROGRAM = _private_identity("database-program.v1")
_PRIVATE_MODE = _private_identity("mode.PRIVATE_ZK.v1")
_INITIAL_PAYMENT = _private_identity("payment-genesis.v1")
_INITIAL_CLEARANCE = _private_identity("clearance-genesis.v1")
_PRIVATE_EPOCH = 7


def _profile_digest(statement: Any, verifier_sha256: bytes) -> bytes:
    return _sha(
        b"BL/NATIVE-V3/PRIVATE-ZK/PROFILE/v6\x00",
        _PRIVATE_MODE,
        _PRIVATE_CONTEXT,
        _PRIVATE_SCHEMA,
        _PRIVATE_PROGRAM,
        bytes(statement.get("proof_role")),
        bytes(statement.get("execution_context")),
        bytes(statement.get("source_registry_snapshot")),
        bytes(statement.get("source_profile")),
        bytes(statement.get("governance_snapshot")),
        bytes(statement.get("automatic_control_set")),
        bytes(statement.get("evaluator_id")),
        bytes(statement.get("schema_id")),
        bytes(statement.get("program_id")),
        bytes(statement.get("policy_id")),
        bytes(statement.get("rule_id")),
        _CIRCUIT_ID,
        verifier_sha256,
        _ZERO_SUITE,
        _u64(_PRIVATE_EPOCH),
    )


def _state_store_identity(statement: Any, verifier_sha256: bytes) -> bytes:
    return _sha(
        _STATE_IDENTITY,
        _PRIVATE_CONTEXT,
        _PRIVATE_SCHEMA,
        _PRIVATE_PROGRAM,
        _PRIVATE_MODE,
        _CIRCUIT_ID,
        _profile_digest(statement, verifier_sha256),
        verifier_sha256,
    )


def _fixed_ascii(value: str, label: str) -> bytes:
    try: encoded = value.encode("ascii")
    except UnicodeEncodeError: _raise_fixed(CompositionIntegrityError, label)
    if len(encoded) > _MAX_ID: _raise_fixed(CompositionIntegrityError, label)
    return len(encoded).to_bytes(2, "big") + encoded + bytes(_MAX_ID - len(encoded))


class CompositionClock(Protocol):
    def now_ms(self) -> int: ...


class _SystemClock:
    def now_ms(self) -> int: return int(time.time() * 1000)


class OfficialStateReceiverPort(Protocol):
    def identity_sha256(self) -> bytes: ...
    def epoch(self) -> int: ...
    def dispatch(self, envelope_bytes: bytes, idempotency_key: bytes) -> bytes: ...


class OfficialStateReceiverLookupPort(Protocol):
    def acknowledgment_profile(self) -> "SyntheticAckEvidenceProfileV2": ...
    def lookup_acknowledgment(self, *, receiver_identity: bytes, receiver_epoch: int, job_id: str, operation_id: bytes, idempotency_key: bytes, envelope_digest: bytes) -> bytes | None: ...


@dataclass(frozen=True, slots=True)
class SyntheticAckEvidenceProfileV2:
    verifier_identity: bytes
    verifier_epoch: int
    receiver_identity: bytes
    receiver_epoch: int
    mode: str = _ACK_MODE
    proof_suite_id: None = None
    production_usable: bool = False
    activation: bool = False

    def __post_init__(self) -> None:
        _blob(self.verifier_identity, 32, "profile_verifier")
        _blob(self.receiver_identity, 32, "profile_receiver")
        if type(self.verifier_epoch) is not int or self.verifier_epoch < 1 or type(self.receiver_epoch) is not int or self.receiver_epoch < 1:
            _raise_fixed(CompositionIntegrityError, "profile_epoch")
        if self.mode != _ACK_MODE or self.proof_suite_id is not None or self.production_usable is not False or self.activation is not False:
            _raise_fixed(CompositionIntegrityError, "profile_nonactivation")

    @property
    def canonical_bytes(self) -> bytes:
        return _json_bytes({"schema_version": 2, "mode": self.mode, "verifier_identity": _hex(self.verifier_identity), "verifier_epoch": self.verifier_epoch, "receiver_identity": _hex(self.receiver_identity), "receiver_epoch": self.receiver_epoch, "proof_suite_id": None, "production_usable": False, "activation": False})

    @property
    def digest(self) -> bytes: return _sha(_ACK_PROFILE, self.canonical_bytes)


@dataclass(frozen=True, slots=True)
class CompositionConfigV2:
    queue_id: str
    queue_config_digest: bytes
    verifier_sha256: bytes
    receiver_identity: bytes = bytes(32)
    receiver_epoch: int = 1
    composition_id: str = "minimal-clearance-composition-v2"
    verifier_epoch: int = 1
    capacity: int = 16
    lease_seconds: int = 300
    reconciliation_capacity: int = 16
    reconciliation_lease_seconds: int = 300
    max_attempts: int = 3
    busy_timeout_ms: int = 5_000
    proof_suite_id: None = None
    production_usable: bool = False
    activation: bool = False

    def __post_init__(self) -> None:
        _token(self.queue_id, "queue_id"); _token(self.composition_id, "composition_id")
        _blob(self.queue_config_digest, 64, "queue_config_digest"); _blob(self.verifier_sha256, 32, "verifier_sha256"); _blob(self.receiver_identity, 32, "receiver_identity")
        for value, label, maximum in ((self.receiver_epoch, "receiver_epoch", 2**63), (self.verifier_epoch, "verifier_epoch", 2**63), (self.capacity, "capacity", 10_000), (self.reconciliation_capacity, "reconciliation_capacity", 10_000), (self.lease_seconds, "lease_seconds", 3_600), (self.reconciliation_lease_seconds, "reconciliation_lease_seconds", 3_600)):
            if type(value) is not int or not 1 <= value <= maximum: _raise_fixed(CompositionIntegrityError, label)
        if self.max_attempts != 3 or self.busy_timeout_ms != 5_000: _raise_fixed(CompositionIntegrityError, "fixed_config")
        if self.proof_suite_id is not None or self.production_usable is not False or self.activation is not False: _raise_fixed(CompositionIntegrityError, "nonactivation")

    @property
    def profile_digest(self) -> bytes: return SyntheticAckEvidenceProfileV2(self.verifier_sha256, self.verifier_epoch, self.receiver_identity, self.receiver_epoch).digest
    @property
    def as_json(self) -> dict[str, Any]:
        return {"schema_version": _SCHEMA_VERSION, "composition_id": self.composition_id, "queue_id": self.queue_id, "queue_config_digest": _hex(self.queue_config_digest), "verifier_sha256": _hex(self.verifier_sha256), "receiver_identity": _hex(self.receiver_identity), "receiver_epoch": self.receiver_epoch, "verifier_epoch": self.verifier_epoch, "capacity": self.capacity, "lease_seconds": self.lease_seconds, "reconciliation_capacity": self.reconciliation_capacity, "reconciliation_lease_seconds": self.reconciliation_lease_seconds, "max_attempts": self.max_attempts, "busy_timeout_ms": self.busy_timeout_ms, "ack_evidence_profile_digest": _hex(self.profile_digest), "directives": list(_DIRECTIVES), "proof_suite_id": None, "production_usable": False, "activation": False}
    @property
    def canonical_bytes(self) -> bytes: return _json_bytes(self.as_json)
    @property
    def digest(self) -> bytes: return _sha(_MATERIAL, self.canonical_bytes)
    @property
    def acknowledgment_profile(self) -> SyntheticAckEvidenceProfileV2: return SyntheticAckEvidenceProfileV2(self.verifier_sha256, self.verifier_epoch, self.receiver_identity, self.receiver_epoch)


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


def _operation_identity(config: CompositionConfigV2, job_id: str, envelope_digest: bytes) -> bytes:
    return _sha(_OUTBOX_OPERATION, config.digest, _fixed_ascii(config.composition_id, "composition_id"), _fixed_ascii(job_id, "job_id"), envelope_digest)


def _idempotency_key(config: CompositionConfigV2, job_id: str, envelope_digest: bytes) -> bytes:
    return _sha(_IDEMPOTENCY, config.digest, _fixed_ascii(config.composition_id, "composition_id"), _fixed_ascii(job_id, "job_id"), envelope_digest)


def _composition_batch_id(config: CompositionConfigV2, batch: IndependentVerifiedQueueBatch) -> bytes:
    token = batch.batch
    if not 1 <= token.accepted_count <= 256 or len(token.operation_ids) != token.accepted_count or tuple(job.operation_id for job in batch.jobs) != token.operation_ids:
        _raise_fixed(CompositionIntegrityError, "queue_batch_shape")
    return _sha(
        _COMPOSITION_BATCH,
        config.digest,
        token.batch_id,
        token.member_set_digest,
        token.pre_head_root,
        token.post_head_root,
        _u64(token.pre_transition_count),
        _u64(token.accepted_count),
        b"".join(token.operation_ids),
    )


def _receipt_digest(raw: bytes) -> bytes: return _sha(_STATE_RECEIPT, raw)
def _receipt_values(receipt: Mapping[str, Any]) -> dict[str, Any]: return {key: (_hex(value) if type(value) is bytes else value) for key, value in receipt.items()}
_NO_EXCEPTION: Final[bytes] = b"\xe0" + bytes(63)


def _exception_fields(acceptance: Any) -> tuple[bytes, bytes, int, int]:
    statement = acceptance.statement
    directive = int(acceptance.effective_directive)
    if directive != 5:
        return _NO_EXCEPTION, _NO_EXCEPTION, 0, 0
    authorization = bytes(statement.get("exception_id"))
    scope = bytes(statement.get("exception_scope_id"))
    valid_from = int(statement.state("exception_valid_from"))
    valid_until = int(statement.state("exception_valid_until"))
    if authorization == _NO_EXCEPTION or scope == _NO_EXCEPTION or not valid_from < valid_until:
        _raise_fixed(CompositionIntegrityError, "exception_authorization")
    return authorization, scope, valid_from, valid_until


def _parse_receipt(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not 0 < len(raw) <= _MAX_RECEIPT: _raise_fixed(CompositionIntegrityError, "receipt_bounds")
    try: value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError): _raise_fixed(CompositionIntegrityError, "receipt_encoding")
    required = {"operation_digest", "artifact_sha256", "artifact_digest", "statement_digest", "circuit_id", "bundle_id", "receipt_id", "join_id", "settlement_id", "settlement_domain", "request_id", "attempt_id", "decision_id", "sequence_before", "sequence_after", "state_before_id", "state_after_id", "clearance_root_before", "clearance_root_after", "clearance_count_before", "clearance_count_after", "payment_root_before", "payment_root_after", "settled_batch_count_before", "settled_batch_count_after", "state_binding_after", "audit_head_after", "policy_result", "effective_directive", "exception_authorization_id", "exception_scope_id", "exception_valid_from", "exception_valid_until", "proof_session_accepted", "economic_mutation", "proof_suite_id", "queue_batch_id", "queue_batch_member_set_digest", "composition_batch_id", "batch_member_index", "batch_member_count"}
    if type(value) is not dict or raw != _json_bytes(value) or set(value) != required: _raise_fixed(CompositionIntegrityError, "receipt_keys")
    for name in ("operation_digest", "artifact_digest", "statement_digest", "bundle_id", "receipt_id", "join_id", "settlement_id", "settlement_domain", "request_id", "attempt_id", "decision_id", "state_before_id", "state_after_id", "clearance_root_before", "clearance_root_after", "payment_root_before", "payment_root_after", "state_binding_after", "audit_head_after", "exception_authorization_id", "exception_scope_id", "queue_batch_id", "queue_batch_member_set_digest", "composition_batch_id"): _hex_blob(value[name], 64, "receipt_" + name)
    _hex_blob(value["artifact_sha256"], 32, "receipt_artifact_sha256"); _hex_blob(value["circuit_id"], 32, "receipt_circuit")
    for name in ("sequence_before", "sequence_after", "clearance_count_before", "clearance_count_after", "settled_batch_count_before", "settled_batch_count_after"):
        if type(value[name]) is not int or value[name] < 0: _raise_fixed(CompositionIntegrityError, "receipt_integer")
    for name in ("policy_result", "effective_directive"):
        if type(value[name]) is not int or not 1 <= value[name] <= 5: _raise_fixed(CompositionIntegrityError, "receipt_directive")
    for name in ("exception_valid_from", "exception_valid_until"):
        if type(value[name]) is not int or value[name] < 0: _raise_fixed(CompositionIntegrityError, "receipt_exception_interval")
    if type(value["batch_member_index"]) is not int or type(value["batch_member_count"]) is not int or not 1 <= value["batch_member_count"] <= 256 or not 0 <= value["batch_member_index"] < value["batch_member_count"]: _raise_fixed(CompositionIntegrityError, "receipt_batch")
    if int(value["effective_directive"]) != 5 and (value["exception_authorization_id"] != _hex(_NO_EXCEPTION) or value["exception_scope_id"] != _hex(_NO_EXCEPTION) or value["exception_valid_from"] != 0 or value["exception_valid_until"] != 0): _raise_fixed(CompositionIntegrityError, "receipt_exception_sentinel")
    if value["proof_session_accepted"] is not True or value["economic_mutation"] is not False or value["proof_suite_id"] is not None: _raise_fixed(CompositionIntegrityError, "receipt_nonactivation")
    return value


def _parse_envelope(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not 0 < len(raw) <= _MAX_ENVELOPE: _raise_fixed(CompositionIntegrityError, "envelope_bounds")
    try: value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError): _raise_fixed(CompositionIntegrityError, "envelope_encoding")
    keys = {"schema", "composition_config_digest", "composition_id_digest", "receiver_identity", "receiver_epoch", "verifier_epoch", "ack_evidence_profile_digest", "job_id_digest", "operation_id", "disposition_digest", "state_store_identity", "state_receipt_digest", "request_id", "attempt_id", "decision_id", "receipt_id", "settlement_id", "settlement_domain", "state_after_id", "state_binding_after", "audit_head_after", "policy_result", "effective_directive", "exception_authorization_id", "exception_scope_id", "exception_valid_from", "exception_valid_until", "proof_session_accepted", "proof_acceptance_is_clear", "payment_root_unchanged", "settled_batch_count_unchanged", "economic_mutation", "proof_suite_id"}
    if type(value) is not dict or set(value) != keys or raw != _json_bytes(value) or value["schema"] != _HANDOFF_SCHEMA: _raise_fixed(CompositionIntegrityError, "envelope_canonical")
    for name, size in (("composition_config_digest", 64), ("composition_id_digest", 64), ("receiver_identity", 32), ("ack_evidence_profile_digest", 64), ("job_id_digest", 64), ("operation_id", 64), ("disposition_digest", 64), ("state_store_identity", 64), ("state_receipt_digest", 64), ("request_id", 64), ("attempt_id", 64), ("decision_id", 64), ("receipt_id", 64), ("settlement_id", 64), ("settlement_domain", 64), ("state_after_id", 64), ("state_binding_after", 64), ("audit_head_after", 64), ("exception_authorization_id", 64), ("exception_scope_id", 64)): _hex_blob(value[name], size, "envelope_" + name)
    for name in ("receiver_epoch", "verifier_epoch", "policy_result", "effective_directive"):
        if type(value[name]) is not int or value[name] < 1: _raise_fixed(CompositionIntegrityError, "envelope_integer")
    for name in ("exception_valid_from", "exception_valid_until"):
        if type(value[name]) is not int or value[name] < 0: _raise_fixed(CompositionIntegrityError, "envelope_exception_interval")
    if int(value["effective_directive"]) != 5 and (value["exception_authorization_id"] != _hex(_NO_EXCEPTION) or value["exception_scope_id"] != _hex(_NO_EXCEPTION) or value["exception_valid_from"] != 0 or value["exception_valid_until"] != 0): _raise_fixed(CompositionIntegrityError, "envelope_exception_sentinel")
    if value["proof_session_accepted"] is not True or value["proof_acceptance_is_clear"] is not False or value["payment_root_unchanged"] is not True or value["settled_batch_count_unchanged"] is not True or value["economic_mutation"] is not False or value["proof_suite_id"] is not None: _raise_fixed(CompositionIntegrityError, "envelope_nonactivation")
    return value


def _parse_ack(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not 0 < len(raw) <= _MAX_ACK: _raise_fixed(CompositionIntegrityError, "ack_bounds")
    try: value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError): _raise_fixed(CompositionIntegrityError, "ack_encoding")
    keys = {"schema", "receiver_identity", "receiver_epoch", "verifier_identity", "verifier_epoch", "profile_digest", "idempotency_key", "envelope_digest", "effective_directive", "accepted_ms", "acknowledgment_id"}
    if type(value) is not dict or set(value) not in (keys, keys | {"policy_result"}) or raw != _json_bytes(value) or value["schema"] != _HANDOFF_SCHEMA: _raise_fixed(CompositionIntegrityError, "ack_canonical")
    _hex_blob(value["receiver_identity"], 32, "ack_receiver"); _hex_blob(value["verifier_identity"], 32, "ack_verifier"); _hex_blob(value["profile_digest"], 64, "ack_profile"); _hex_blob(value["idempotency_key"], 64, "ack_idempotency"); _hex_blob(value["envelope_digest"], 64, "ack_envelope"); _hex_blob(value["acknowledgment_id"], 64, "ack_id")
    if type(value["receiver_epoch"]) is not int or value["receiver_epoch"] < 1 or type(value["verifier_epoch"]) is not int or value["verifier_epoch"] < 1 or type(value["accepted_ms"]) is not int or value["accepted_ms"] < 0 or type(value["effective_directive"]) is not int or not 1 <= value["effective_directive"] <= 5: _raise_fixed(CompositionIntegrityError, "ack_values")
    if "policy_result" in value and (type(value["policy_result"]) is not int or not 1 <= value["policy_result"] <= 5): _raise_fixed(CompositionIntegrityError, "ack_policy")
    return value


def _parse_qualification(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not 0 < len(raw) <= _MAX_RECEIPT: _raise_fixed(CompositionIntegrityError, "qualification_bounds")
    try: value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError): _raise_fixed(CompositionIntegrityError, "qualification_encoding")
    keys = {"schema_version", "mode", "profile_digest", "verifier_identity", "verifier_epoch", "receiver_identity", "receiver_epoch", "operation_id", "job_id_digest", "idempotency_key", "envelope_digest", "ack_digest", "acknowledgment_id", "policy_result", "effective_directive", "proof_suite_id", "production_usable", "activation", "attempt", "lease_kind", "lease_token_digest"}
    if type(value) is not dict or set(value) != keys or raw != _json_bytes(value) or value["schema_version"] != 2 or value["mode"] != _ACK_MODE: _raise_fixed(CompositionIntegrityError, "qualification_canonical")
    for name in ("profile_digest", "operation_id", "job_id_digest", "idempotency_key", "envelope_digest", "ack_digest", "acknowledgment_id", "lease_token_digest"): _hex_blob(value[name], 64, "qualification_" + name)
    _hex_blob(value["verifier_identity"], 32, "qualification_verifier"); _hex_blob(value["receiver_identity"], 32, "qualification_receiver")
    for name in ("verifier_epoch", "receiver_epoch", "policy_result", "effective_directive", "attempt"):
        if type(value[name]) is not int or not 1 <= value[name] <= 2**63: _raise_fixed(CompositionIntegrityError, "qualification_integer")
    if value["lease_kind"] not in ("DISPATCH", "RECONCILIATION"): _raise_fixed(CompositionIntegrityError, "qualification_lease_kind")
    if value["policy_result"] > 5 or value["effective_directive"] > 5 or value["proof_suite_id"] is not None or value["production_usable"] is not False or value["activation"] is not False: _raise_fixed(CompositionIntegrityError, "qualification_nonactivation")
    return value


@_public_v2_api
def parse_envelope_bytes(raw: bytes) -> dict[str, Any]: return _parse_envelope(raw)


@_public_v2_api
def parse_acknowledgment_bytes(raw: bytes) -> dict[str, Any]: return _parse_ack(raw)


@_public_v2_api
def envelope_digest(raw: bytes) -> bytes:
    _parse_envelope(raw); return _sha(_ENVELOPE, raw)


@_public_v2_api
def acknowledgment_digest(raw: bytes) -> bytes:
    _parse_ack(raw); return _sha(_ACK, raw)


@_public_v2_api
def build_synthetic_acknowledgment(envelope_bytes: bytes, *, config: CompositionConfigV2, job_id: str | None = None, idempotency_key: bytes | None = None, accepted_ms: int = 0, acknowledgment_id: bytes | None = None, policy_result: int | None = None) -> bytes:
    envelope = _parse_envelope(envelope_bytes)
    if type(accepted_ms) is not int or accepted_ms < 0: _raise_fixed(CompositionIntegrityError, "ack_time")
    ack_id = acknowledgment_id or _sha(_ACK_RECEIPT, envelope_bytes, _u64(accepted_ms)); _blob(ack_id, 64, "ack_id")
    if idempotency_key is None:
        if job_id is None: _raise_fixed(CompositionIntegrityError, "ack_job_id")
        idempotency_key = _idempotency_key(config, job_id, _sha(_ENVELOPE, envelope_bytes))
    _blob(idempotency_key, 64, "ack_idempotency")
    value: dict[str, Any] = {"schema": _HANDOFF_SCHEMA, "receiver_identity": _hex(config.receiver_identity), "receiver_epoch": config.receiver_epoch, "verifier_identity": _hex(config.verifier_sha256), "verifier_epoch": config.verifier_epoch, "profile_digest": _hex(config.profile_digest), "idempotency_key": _hex(idempotency_key), "envelope_digest": _hex(_sha(_ENVELOPE, envelope_bytes)), "effective_directive": int(envelope["effective_directive"]), "accepted_ms": accepted_ms, "acknowledgment_id": _hex(ack_id)}
    if policy_result is not None: value["policy_result"] = policy_result
    return _json_bytes(value)


@_public_v2_api
def build_directive_envelope(*, config: CompositionConfigV2, job_id: str, operation_id: bytes, disposition_digest: bytes, state_store_identity: bytes, receipt: Mapping[str, Any]) -> bytes:
    if receipt["proof_session_accepted"] is not True or receipt["economic_mutation"] is not False or receipt["proof_suite_id"] is not None: _raise_fixed(CompositionIntegrityError, "envelope_receipt_claim")
    env = {"schema": _HANDOFF_SCHEMA, "composition_config_digest": _hex(config.digest), "composition_id_digest": _hex(_sha(_ENVELOPE, config.composition_id.encode("ascii"))), "receiver_identity": _hex(config.receiver_identity), "receiver_epoch": config.receiver_epoch, "verifier_epoch": config.verifier_epoch, "ack_evidence_profile_digest": _hex(config.profile_digest), "job_id_digest": _hex(_sha(_ENVELOPE, job_id.encode("ascii"))), "operation_id": _hex(operation_id), "disposition_digest": _hex(disposition_digest), "state_store_identity": _hex(state_store_identity), "state_receipt_digest": _hex(_receipt_digest(_json_bytes(_receipt_values(receipt)))), "request_id": receipt["request_id"], "attempt_id": receipt["attempt_id"], "decision_id": receipt["decision_id"], "receipt_id": receipt["receipt_id"], "settlement_id": receipt["settlement_id"], "settlement_domain": receipt["settlement_domain"], "state_after_id": receipt["state_after_id"], "state_binding_after": receipt["state_binding_after"], "audit_head_after": receipt["audit_head_after"], "policy_result": int(receipt["policy_result"]), "effective_directive": int(receipt["effective_directive"]), "exception_authorization_id": receipt["exception_authorization_id"], "exception_scope_id": receipt["exception_scope_id"], "exception_valid_from": int(receipt["exception_valid_from"]), "exception_valid_until": int(receipt["exception_valid_until"]), "proof_session_accepted": True, "proof_acceptance_is_clear": False, "payment_root_unchanged": receipt["payment_root_before"] == receipt["payment_root_after"], "settled_batch_count_unchanged": receipt["settled_batch_count_before"] == receipt["settled_batch_count_after"], "economic_mutation": False, "proof_suite_id": None}
    raw = _json_bytes(env); _parse_envelope(raw); return raw


def _state_receipt(*, operation_digest: bytes, acceptance: Any, sequence_before: int, sequence_after: int, state_before_id: bytes, state_after_id: bytes, clearance_before: bytes, clearance_after: bytes, count_before: int, count_after: int, binding_after: bytes, audit_after: bytes, queue_batch_id: bytes, queue_batch_member_set_digest: bytes, composition_batch_id: bytes, batch_member_index: int, batch_member_count: int) -> dict[str, Any]:
    statement = acceptance.statement
    authorization, scope, valid_from, valid_until = _exception_fields(acceptance)
    return {"operation_digest": _hex(operation_digest), "artifact_sha256": _hex(acceptance.artifact_sha256), "artifact_digest": _hex(acceptance.artifact_digest), "statement_digest": _hex(acceptance.statement_digest), "circuit_id": _hex(acceptance.circuit_id), "bundle_id": _hex(acceptance.bundle_id), "receipt_id": _hex(statement.receipt_id), "join_id": _hex(statement.join_id), "settlement_id": _hex(statement.settlement_id), "settlement_domain": _hex(statement.get("settlement_domain")), "request_id": _hex(statement.request_id), "attempt_id": _hex(statement.attempt_id), "decision_id": _hex(statement.decision_id), "sequence_before": sequence_before, "sequence_after": sequence_after, "state_before_id": _hex(state_before_id), "state_after_id": _hex(state_after_id), "clearance_root_before": _hex(clearance_before), "clearance_root_after": _hex(clearance_after), "clearance_count_before": count_before, "clearance_count_after": count_after, "payment_root_before": _hex(_INITIAL_PAYMENT), "payment_root_after": _hex(_INITIAL_PAYMENT), "settled_batch_count_before": 0, "settled_batch_count_after": 0, "state_binding_after": _hex(binding_after), "audit_head_after": _hex(audit_after), "policy_result": int(acceptance.policy_result), "effective_directive": int(acceptance.effective_directive), "exception_authorization_id": _hex(authorization), "exception_scope_id": _hex(scope), "exception_valid_from": valid_from, "exception_valid_until": valid_until, "proof_session_accepted": True, "economic_mutation": False, "proof_suite_id": None, "queue_batch_id": _hex(queue_batch_id), "queue_batch_member_set_digest": _hex(queue_batch_member_set_digest), "composition_batch_id": _hex(composition_batch_id), "batch_member_index": batch_member_index, "batch_member_count": batch_member_count}


class ClearanceCompositionStoreV2:
    @_public_v2_api
    def __init__(self, *, path: Path, config: CompositionConfigV2, clock: CompositionClock | None = None, before_fault: Callable[[str], None] | None = None, after_commit_fault: Callable[[str], None] | None = None) -> None:
        if not isinstance(path, Path) or path.is_symlink() or not path.parent.is_dir(): _raise_fixed(CompositionError, "composition_database_path")
        self.path, self.config, self.clock = path, config, clock or _SystemClock()
        self._before_fault, self._after_commit_fault = before_fault, after_commit_fault
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=self.config.busy_timeout_ms / 1000, isolation_level=None)
        connection.execute("PRAGMA foreign_keys=ON"); connection.execute(f"PRAGMA busy_timeout={self.config.busy_timeout_ms}"); connection.execute("PRAGMA synchronous=FULL")
        return connection

    def _fault(self, label: str) -> None:
        if self._before_fault is not None: self._before_fault(label)
    def _after_fault(self, label: str) -> None:
        if self._after_commit_fault is not None: self._after_commit_fault(label)

    def _initialize(self) -> None:
        with closing(self._connect()) as connection:
            names = {str(row[0]) for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
            if names and names != _COMPOSITION_TABLES: _raise_fixed(CompositionIntegrityError, "composition_wrong_schema")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS composition_meta (
                    id INTEGER PRIMARY KEY CHECK(id=1), schema_version INTEGER NOT NULL,
                    composition_id TEXT NOT NULL, config_json BLOB NOT NULL, config_digest BLOB NOT NULL,
                    state_profile_identity BLOB, state_bytes BLOB,
                    event_head BLOB NOT NULL, next_event_sequence INTEGER NOT NULL,
                    active_dispatch_count INTEGER NOT NULL, active_reconciliation_count INTEGER NOT NULL,
                    state_id BLOB, state_epoch INTEGER, state_sequence INTEGER,
                    state_continuity_root BLOB, state_clearance_root BLOB, state_clearance_count INTEGER,
                    state_replay_root BLOB, payment_root BLOB, settled_batch_count INTEGER,
                    state_binding BLOB, audit_head BLOB, last_operation_digest BLOB,
                    proof_suite_id BLOB, production_usable INTEGER NOT NULL, activation INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS composition_transactions (
                    transaction_id BLOB PRIMARY KEY, queue_job_id TEXT NOT NULL UNIQUE,
                    queue_operation_id BLOB NOT NULL UNIQUE, queue_view_bytes BLOB NOT NULL,
                    queue_view_digest BLOB NOT NULL, acceptance_bytes BLOB NOT NULL,
                    acceptance_digest BLOB NOT NULL, artifact_digest BLOB NOT NULL UNIQUE,
                    request_id BLOB NOT NULL UNIQUE, attempt_id BLOB NOT NULL UNIQUE,
                    decision_id BLOB NOT NULL UNIQUE, operation_digest BLOB NOT NULL UNIQUE,
                    disposition_id BLOB NOT NULL UNIQUE, status TEXT NOT NULL CHECK(status IN ('HELD','APPLIED')),
                    state_receipt_bytes BLOB, state_receipt_digest BLOB, applied_sequence INTEGER,
                    envelope_bytes BLOB, envelope_digest BLOB UNIQUE, outbox_operation_id BLOB UNIQUE,
                    idempotency_key BLOB UNIQUE, delivery_status TEXT,
                    dispatch_attempt INTEGER NOT NULL CHECK(dispatch_attempt >= 0),
                    reconciliation_attempt INTEGER NOT NULL CHECK(reconciliation_attempt >= 0),
                    lease_kind TEXT, lease_worker_id TEXT, lease_token BLOB,
                    lease_started_ms INTEGER, lease_expires_ms INTEGER, next_eligible_ms INTEGER,
                    acknowledgment_bytes BLOB, acknowledgment_digest BLOB, acknowledgment_id TEXT,
                    acknowledged_ms INTEGER, ack_profile_digest BLOB, qualification_receipt BLOB,
                    error_code TEXT, created_ms INTEGER NOT NULL, updated_ms INTEGER NOT NULL,
                    CHECK(delivery_status IS NULL OR delivery_status IN ('READY','DISPATCH_LEASED','DELIVERY_UNCONFIRMED','RECONCILIATION_LEASED','ACKNOWLEDGED','DISPATCH_EXHAUSTED','RECONCILIATION_EXHAUSTED')),
                    CHECK(lease_kind IS NULL OR lease_kind IN ('DISPATCH','RECONCILIATION')),
                    CHECK((lease_kind IS NULL AND lease_worker_id IS NULL AND lease_token IS NULL AND lease_started_ms IS NULL AND lease_expires_ms IS NULL) OR (lease_kind IS NOT NULL AND lease_worker_id IS NOT NULL AND lease_token IS NOT NULL AND lease_started_ms IS NOT NULL AND lease_expires_ms IS NOT NULL)),
                    CHECK((status='HELD' AND state_receipt_bytes IS NULL AND envelope_bytes IS NULL AND delivery_status IS NULL AND lease_kind IS NULL AND acknowledgment_bytes IS NULL) OR (status='APPLIED' AND state_receipt_bytes IS NOT NULL AND envelope_bytes IS NOT NULL AND delivery_status IS NOT NULL)),
                    CHECK((delivery_status='READY' AND lease_kind IS NULL) OR (delivery_status='DISPATCH_LEASED' AND lease_kind='DISPATCH') OR (delivery_status='DELIVERY_UNCONFIRMED' AND lease_kind IS NULL) OR (delivery_status='RECONCILIATION_LEASED' AND lease_kind='RECONCILIATION') OR (delivery_status IN ('ACKNOWLEDGED','DISPATCH_EXHAUSTED','RECONCILIATION_EXHAUSTED') AND lease_kind IS NULL))
                );
                CREATE TABLE IF NOT EXISTS composition_events (
                    global_sequence INTEGER PRIMARY KEY, job_id TEXT NOT NULL,
                    job_sequence INTEGER NOT NULL, event_kind TEXT NOT NULL,
                    operation_id BLOB NOT NULL, request_id BLOB NOT NULL,
                    transaction_id BLOB NOT NULL, before_state TEXT NOT NULL,
                    after_state TEXT NOT NULL, previous_root BLOB NOT NULL,
                    event_root BLOB NOT NULL, event_bytes BLOB NOT NULL,
                    event_digest BLOB NOT NULL UNIQUE, receipt_digest BLOB,
                    at_ms INTEGER NOT NULL, UNIQUE(job_id, job_sequence),
                    FOREIGN KEY(transaction_id) REFERENCES composition_transactions(transaction_id)
                );
                CREATE INDEX IF NOT EXISTS composition_ready_idx ON composition_transactions(delivery_status,next_eligible_ms,created_ms,queue_job_id) WHERE delivery_status='READY' AND lease_kind IS NULL;
                CREATE INDEX IF NOT EXISTS composition_reconcile_idx ON composition_transactions(delivery_status,next_eligible_ms,created_ms,queue_job_id) WHERE delivery_status='DELIVERY_UNCONFIRMED' AND lease_kind IS NULL;
                CREATE INDEX IF NOT EXISTS composition_lease_expiry_idx ON composition_transactions(lease_kind,lease_expires_ms) WHERE lease_kind IS NOT NULL;
                CREATE TRIGGER IF NOT EXISTS composition_meta_no_delete BEFORE DELETE ON composition_meta BEGIN SELECT RAISE(ABORT,'composition_meta_immutable'); END;
                CREATE TRIGGER IF NOT EXISTS composition_meta_guard BEFORE UPDATE ON composition_meta
                WHEN NEW.id IS NOT OLD.id OR NEW.schema_version IS NOT OLD.schema_version OR NEW.composition_id IS NOT OLD.composition_id OR NEW.config_json IS NOT OLD.config_json OR NEW.config_digest IS NOT OLD.config_digest OR (OLD.state_profile_identity IS NOT NULL AND NEW.state_profile_identity IS NOT OLD.state_profile_identity) OR NEW.proof_suite_id IS NOT OLD.proof_suite_id OR NEW.production_usable IS NOT OLD.production_usable OR NEW.activation IS NOT OLD.activation OR (OLD.payment_root IS NOT NULL AND NEW.payment_root IS NOT OLD.payment_root) OR (OLD.settled_batch_count IS NOT NULL AND NEW.settled_batch_count IS NOT OLD.settled_batch_count)
                BEGIN SELECT RAISE(ABORT,'composition_meta_immutable'); END;
                CREATE TRIGGER IF NOT EXISTS composition_transactions_no_delete BEFORE DELETE ON composition_transactions BEGIN SELECT RAISE(ABORT,'composition_transactions_append_only'); END;
                CREATE TRIGGER IF NOT EXISTS composition_transactions_guard BEFORE UPDATE ON composition_transactions
                WHEN NEW.transaction_id IS NOT OLD.transaction_id OR NEW.queue_job_id IS NOT OLD.queue_job_id OR NEW.queue_operation_id IS NOT OLD.queue_operation_id OR NEW.queue_view_bytes IS NOT OLD.queue_view_bytes OR NEW.queue_view_digest IS NOT OLD.queue_view_digest OR NEW.acceptance_bytes IS NOT OLD.acceptance_bytes OR NEW.acceptance_digest IS NOT OLD.acceptance_digest OR NEW.artifact_digest IS NOT OLD.artifact_digest OR NEW.request_id IS NOT OLD.request_id OR NEW.attempt_id IS NOT OLD.attempt_id OR NEW.decision_id IS NOT OLD.decision_id OR NEW.operation_digest IS NOT OLD.operation_digest OR NEW.disposition_id IS NOT OLD.disposition_id OR NEW.status IS NOT OLD.status OR NEW.state_receipt_bytes IS NOT OLD.state_receipt_bytes OR NEW.state_receipt_digest IS NOT OLD.state_receipt_digest OR NEW.applied_sequence IS NOT OLD.apPLIED_sequence OR NEW.envelope_bytes IS NOT OLD.envelope_bytes OR NEW.envelope_digest IS NOT OLD.envelope_digest OR NEW.outbox_operation_id IS NOT OLD.outbox_operation_id OR NEW.idempotency_key IS NOT OLD.idempotency_key OR NEW.created_ms IS NOT OLD.created_ms
                BEGIN SELECT RAISE(ABORT,'composition_transaction_immutable'); END;
                CREATE TRIGGER IF NOT EXISTS composition_events_no_update BEFORE UPDATE ON composition_events BEGIN SELECT RAISE(ABORT,'composition_events_append_only'); END;
                CREATE TRIGGER IF NOT EXISTS composition_events_no_delete BEFORE DELETE ON composition_events BEGIN SELECT RAISE(ABORT,'composition_events_append_only'); END;
                """
            )
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute("SELECT * FROM composition_meta WHERE id=1").fetchone()
                if row is None:
                    head = _sha(_GENESIS, self.config.composition_id.encode("ascii"), self.config.digest)
                    values = (1, _SCHEMA_VERSION, self.config.composition_id, self.config.canonical_bytes, self.config.digest, None, None, head, 0, 0, 0, *([None] * 12), None, 0, 0)
                    connection.execute("INSERT INTO composition_meta VALUES (" + ",".join("?" for _ in values) + ")", values)
                else: self._check_meta(tuple(row))
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction: connection.execute("ROLLBACK")
                raise

    def _check_meta(self, row: tuple[Any, ...]) -> tuple[Any, ...]:
        if len(row) != 26 or int(row[1]) != _SCHEMA_VERSION or str(row[2]) != self.config.composition_id: _raise_fixed(CompositionIntegrityError, "composition_schema")
        if bytes(row[3]) != self.config.canonical_bytes or bytes(row[4]) != self.config.digest or row[23] is not None or int(row[24]) != 0 or int(row[25]) != 0: _raise_fixed(CompositionIntegrityError, "composition_config_drift")
        if type(row[7]) is not bytes or len(row[7]) != 64 or type(row[8]) is not int or row[8] < 0: _raise_fixed(CompositionIntegrityError, "composition_event_head")
        if row[6] is not None and (type(row[6]) is not bytes or len(row[6]) != 1686): _raise_fixed(CompositionIntegrityError, "composition_state_bytes")
        if type(row[9]) is not int or not 0 <= row[9] <= self.config.capacity or type(row[10]) is not int or not 0 <= row[10] <= self.config.reconciliation_capacity: _raise_fixed(CompositionIntegrityError, "composition_counters")
        state = row[11:23]
        if row[11] is None and any(x is not None for x in state): _raise_fixed(CompositionIntegrityError, "composition_state_partial")
        if row[11] is not None and any(x is None for x in row[11:22]): _raise_fixed(CompositionIntegrityError, "composition_state_partial")
        if row[11] is not None and (bytes(row[18]) != _INITIAL_PAYMENT or int(row[19]) != 0): _raise_fixed(CompositionIntegrityError, "economic_sentinel")
        return row

    def _meta(self, connection: sqlite3.Connection) -> tuple[Any, ...]:
        row = connection.execute("SELECT * FROM composition_meta WHERE id=1").fetchone()
        if row is None: _raise_fixed(CompositionIntegrityError, "composition_meta_missing")
        return self._check_meta(tuple(row))

    def _state(self, connection: sqlite3.Connection) -> tuple[Any, ...] | None:
        meta = self._meta(connection)
        return None if meta[11] is None else tuple(meta[11:23])

    def _append_event(self, connection: sqlite3.Connection, *, kind: str, tx: tuple[Any, ...], before_state: str, after_state: str, payload: Mapping[str, Any], receipt_digest: bytes | None, now: int) -> bytes:
        if kind not in _EVENT_KINDS or set(payload) != _EVENT_PAYLOAD_KEYS[kind]: _raise_fixed(CompositionIntegrityError, "event_payload")
        if before_state != "NONE" and before_state not in _DELIVERY_STATES or after_state != "NONE" and after_state not in _DELIVERY_STATES: _raise_fixed(CompositionIntegrityError, "event_state")
        meta = self._meta(connection); sequence = int(meta[8]) + 1; job_id = str(tx[1])
        job_sequence = int(connection.execute("SELECT COALESCE(MAX(job_sequence),0)+1 FROM composition_events WHERE job_id=?", (job_id,)).fetchone()[0])
        previous_root, operation_id, request_id, transaction_id = bytes(meta[7]), bytes(tx[2]), bytes(tx[8]), bytes(tx[0])
        event_value = {"event_kind": kind, "global_sequence": sequence, "job_sequence": job_sequence, "job_id": job_id, "operation_id": _hex(operation_id), "request_id": _hex(request_id), "transaction_id": _hex(transaction_id), "before_state": before_state, "after_state": after_state, "previous_root": _hex(previous_root), "payload": dict(payload), "receipt_digest": None if receipt_digest is None else _hex(receipt_digest), "at_ms": now}
        event_bytes = _json_bytes(event_value)
        event_digest = _sha(_EVENT, _u64(sequence), _u64(job_sequence), kind.encode("ascii"), _fixed_ascii(job_id, "job_id"), operation_id, request_id, transaction_id, before_state.encode("ascii"), after_state.encode("ascii"), previous_root, event_bytes, b"" if receipt_digest is None else receipt_digest)
        event_root = _sha(_HEAD, previous_root, _u64(sequence), event_digest)
        connection.execute("INSERT INTO composition_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (sequence, job_id, job_sequence, kind, operation_id, request_id, transaction_id, before_state, after_state, previous_root, event_root, event_bytes, event_digest, receipt_digest, now))
        if connection.execute("UPDATE composition_meta SET event_head=?,next_event_sequence=? WHERE id=1 AND event_head=? AND next_event_sequence=?", (event_root, sequence, previous_root, sequence - 1)).rowcount != 1: _raise_fixed(CompositionIntegrityError, "event_head_cas")
        return event_root

    def _ensure_state(self, connection: sqlite3.Connection, acceptance: Any) -> tuple[Any, ...] | None:
        meta = self._meta(connection); statement = acceptance.statement
        if meta[11] is not None:
            predecessor = bytes(statement.get("predecessor_state_bytes"))
            return None if meta[6] != predecessor or meta[5] != _state_store_identity(statement, self.config.verifier_sha256) else tuple(meta[11:23])
        profile, identity = _profile_digest(statement, self.config.verifier_sha256), _state_store_identity(statement, self.config.verifier_sha256)
        predecessor = bytes(statement.get("predecessor_state_bytes"))
        continuity, audit = bytes(statement.state("before_continuity_root")), bytes(statement.state("before_audit_head"))
        clearance, replay = _sha(_STATE_GENESIS, statement.state_before_id, _INITIAL_CLEARANCE), _sha(_STATE_GENESIS, statement.attempt_id, statement.request_id)
        binding = _sha(_STATE_BINDING, predecessor, statement.state_before_id, _u64(statement.epoch), _u64(statement.sequence_before), continuity, clearance, replay, _INITIAL_PAYMENT, _u64(0), self.config.verifier_sha256, profile)
        state = (bytes(statement.state_before_id), int(statement.epoch), int(statement.sequence_before), continuity, clearance, int(statement.state("clearance_count_before")), replay, _INITIAL_PAYMENT, 0, binding, audit, None)
        connection.execute("UPDATE composition_meta SET state_profile_identity=?,state_bytes=?,state_id=?,state_epoch=?,state_sequence=?,state_continuity_root=?,state_clearance_root=?,state_clearance_count=?,state_replay_root=?,payment_root=?,settled_batch_count=?,state_binding=?,audit_head=?,last_operation_digest=? WHERE id=1", (identity, predecessor, *state))
        return self._state(connection)

    def _validate_queue_result(self, verified: IndependentVerifiedQueueJob) -> Any:
        if verified.queue_id != self.config.queue_id or verified.config_digest != self.config.queue_config_digest or verified.verifier_sha256 != self.config.verifier_sha256 or verified.cap_bytes != _CAP_BYTES or verified.cap_enforced is not True or verified.active_process_limit != _ACTIVE_PROCESS_LIMIT or verified.timed_out is not False or verified.exit_code != 0 or verified.peak_job_commit_bytes > _CAP_BYTES: _raise_fixed(CompositionIntegrityError, "queue_binding")
        try: acceptance = parse_acceptance_bytes(verified.acceptance_bytes)
        except Exception: _raise_fixed(CompositionIntegrityError, "acceptance_parse")
        if acceptance.canonical_bytes() != verified.acceptance_bytes or acceptance.artifact_bytes != verified.artifact_bytes or acceptance.artifact_sha256 != verified.artifact_sha256 or acceptance.artifact_digest != verified.artifact_sha3_512 or acceptance.circuit_id != verified.circuit_id or bytes(acceptance.statement.settlement_id) != _sha(_SETTLEMENT_REFERENCE, bytes(acceptance.statement.get("settlement_domain")), bytes((int(acceptance.effective_directive),)), bytes(acceptance.statement.decision_id), bytes(acceptance.statement.state_after_id), bytes(acceptance.statement.state("authorized_payment_commitment"))): _raise_fixed(CompositionIntegrityError, "acceptance_binding")
        return acceptance

    @staticmethod
    def _queue_view_bytes(
        verified: IndependentVerifiedQueueJob,
        batch: IndependentVerifiedQueueBatch,
        member_index: int,
        composition_batch_id: bytes,
    ) -> bytes:
        token = batch.batch
        return _json_bytes({
            "schema": _QUEUE_VIEW_SCHEMA,
            "queue_id": verified.queue_id,
            "config_digest": _hex(verified.config_digest),
            "verifier_sha256": _hex(verified.verifier_sha256),
            "job_id": verified.job_id,
            "operation_id": _hex(verified.operation_id),
            "attempt": verified.attempt,
            "artifact_bytes": verified.artifact_bytes,
            "artifact_sha256": _hex(verified.artifact_sha256),
            "artifact_sha3_512": _hex(verified.artifact_sha3_512),
            "circuit_id": _hex(verified.circuit_id),
            "peak_job_commit_bytes": verified.peak_job_commit_bytes,
            "cap_bytes": verified.cap_bytes,
            "cap_enforced": verified.cap_enforced,
            "active_process_limit": verified.active_process_limit,
            "timed_out": verified.timed_out,
            "exit_code": verified.exit_code,
            "queue_batch_id": _hex(token.batch_id),
            "queue_batch_member_set_digest": _hex(token.member_set_digest),
            "queue_batch_pre_head_root": _hex(token.pre_head_root),
            "queue_batch_post_head_root": _hex(token.post_head_root),
            "queue_batch_pre_transition_count": token.pre_transition_count,
            "queue_batch_member_index": member_index,
            "queue_batch_member_count": token.accepted_count,
            "composition_batch_id": _hex(composition_batch_id),
        })

    def _result_from_tx(self, row: tuple[Any, ...], duplicate: bool) -> CompositionProcessResultV2:
        return CompositionProcessResultV2(str(row[1]), bytes(row[2]), str(row[13]), bytes(row[12]), None if row[14] is None else bytes(row[14]), None if row[15] is None else bytes(row[15]), str(row[1]) if row[17] is not None else None, None if row[19] is None else bytes(row[19]), duplicate, None if row[36] is None else str(row[36]))

    def _apply_verified_job_in_transaction(self, connection: sqlite3.Connection, prepared: tuple[Any, ...], now: int) -> tuple[CompositionProcessResultV2, bool]:
        verified, acceptance, encoded, queue_view, queue_view_digest, acceptance_digest, batch, composition_batch_id, member_index = prepared
        batch_token = batch.batch
        job_id = verified.job_id
        operation_digest = _sha(_STATE_OPERATION, encoded, bytes(acceptance.statement.state_before_id), bytes(acceptance.statement.attempt_id), self.config.verifier_sha256)
        if connection.execute("SELECT 1 FROM composition_transactions WHERE artifact_digest=? OR request_id=? OR attempt_id=? OR operation_digest=?", (acceptance.artifact_digest, acceptance.statement.request_id, acceptance.statement.attempt_id, operation_digest)).fetchone() is not None: _raise_fixed(CompositionConflictError, "composition_conflicting_retry")
        state = self._ensure_state(connection, acceptance)
        disposition_id = _sha(_MATERIAL, b"disposition", job_id.encode("ascii"), verified.operation_id, acceptance_digest)
        transaction_id = _sha(_MATERIAL, b"transaction", disposition_id)
        if state is None:
            tx = (transaction_id, job_id, verified.operation_id, queue_view, queue_view_digest, encoded, acceptance_digest, acceptance.artifact_digest, acceptance.statement.request_id, acceptance.statement.attempt_id, acceptance.statement.decision_id, operation_digest, disposition_id, "HELD", None, None, None, None, None, None, None, None, 0, 0, None, None, None, None, None, now, None, None, None, None, None, None, "state_profile_mismatch", now, now)
            connection.execute("INSERT INTO composition_transactions VALUES (" + ",".join("?" for _ in tx) + ")", tx)
            self._append_event(connection, kind="HELD", tx=tx, before_state="NONE", after_state="NONE", payload={"acceptance_digest": _hex(acceptance_digest), "error_code": "state_profile_mismatch"}, receipt_digest=None, now=now)
            return CompositionProcessResultV2(job_id, verified.operation_id, "HELD", disposition_id, None, None, None, None, False, "state_profile_mismatch"), False
        if bytes(state[0]) != acceptance.statement.state_before_id or int(state[1]) != acceptance.statement.epoch or int(state[2]) != acceptance.statement.sequence_before or bytes(state[3]) != bytes(acceptance.statement.state("before_continuity_root")) or bytes(state[10]) != bytes(acceptance.statement.state("before_audit_head")) or int(state[5]) != int(acceptance.statement.state("clearance_count_before")) or bytes(state[7]) != _INITIAL_PAYMENT or int(state[8]) != 0:
            tx = (transaction_id, job_id, verified.operation_id, queue_view, queue_view_digest, encoded, acceptance_digest, acceptance.artifact_digest, acceptance.statement.request_id, acceptance.statement.attempt_id, acceptance.statement.decision_id, operation_digest, disposition_id, "HELD", None, None, None, None, None, None, None, None, 0, 0, None, None, None, None, None, now, None, None, None, None, None, None, "stale_or_conflicting_state", now, now)
            connection.execute("INSERT INTO composition_transactions VALUES (" + ",".join("?" for _ in tx) + ")", tx)
            self._append_event(connection, kind="HELD", tx=tx, before_state="NONE", after_state="NONE", payload={"acceptance_digest": _hex(acceptance_digest), "error_code": "stale_or_conflicting_state"}, receipt_digest=None, now=now)
            return CompositionProcessResultV2(job_id, verified.operation_id, "HELD", disposition_id, None, None, None, None, False, "stale_or_conflicting_state"), False
        meta = self._meta(connection)
        if int(meta[9]) >= self.config.capacity: _raise_fixed(CompositionBackpressureError, "outbox_capacity")
        statement, sequence_before = acceptance.statement, int(state[2]); sequence_after = sequence_before + 1
        replay_after = _sha(_STATE_REPLAY, bytes(state[6]), statement.attempt_id, statement.request_id, statement.receipt_id)
        advanced = int(statement.directive) in (1, 5)
        clearance_after = _sha(_STATE_CLEARANCE, bytes(state[4]), statement.state_after_id, statement.decision_id, bytes((int(statement.directive),))) if advanced else bytes(state[4])
        count_after = int(state[5]) + int(advanced)
        binding_after = _sha(_STATE_BINDING, bytes(meta[20]), operation_digest, statement.state_after_id, replay_after, clearance_after, _u64(count_after), bytes(state[7]), _u64(0), _u64(int(state[1])), _u64(sequence_after), self.config.verifier_sha256, _profile_digest(statement, self.config.verifier_sha256))
        audit_after = _sha(b"BL/NATIVE-V3/MINIMAL-AUDIT-HEAD/v1\x00", bytes(state[10]), bytes(statement.decision_id), bytes((int(statement.directive),)))
        receipt_raw = _json_bytes(_state_receipt(operation_digest=operation_digest, acceptance=acceptance, sequence_before=sequence_before, sequence_after=sequence_after, state_before_id=bytes(state[0]), state_after_id=statement.state_after_id, clearance_before=bytes(state[4]), clearance_after=clearance_after, count_before=int(state[5]), count_after=count_after, binding_after=binding_after, audit_after=audit_after, queue_batch_id=batch_token.batch_id, queue_batch_member_set_digest=batch_token.member_set_digest, composition_batch_id=composition_batch_id, batch_member_index=member_index, batch_member_count=batch_token.accepted_count))
        receipt = _parse_receipt(receipt_raw); receipt_digest = _receipt_digest(receipt_raw)
        envelope = build_directive_envelope(config=self.config, job_id=job_id, operation_id=verified.operation_id, disposition_digest=disposition_id, state_store_identity=_state_store_identity(statement, self.config.verifier_sha256), receipt=_parse_receipt(receipt_raw))
        envelope_digest = _sha(_ENVELOPE, envelope); outbox_operation_id = _operation_identity(self.config, job_id, envelope_digest); idempotency = _idempotency_key(self.config, job_id, envelope_digest)
        tx = (transaction_id, job_id, verified.operation_id, queue_view, queue_view_digest, encoded, acceptance_digest, acceptance.artifact_digest, statement.request_id, statement.attempt_id, statement.decision_id, operation_digest, disposition_id, "APPLIED", receipt_raw, receipt_digest, sequence_after, envelope, envelope_digest, outbox_operation_id, idempotency, "READY", 0, 0, None, None, None, None, None, now, None, None, None, None, None, None, None, now, now)
        connection.execute("INSERT INTO composition_transactions VALUES (" + ",".join("?" for _ in tx) + ")", tx)
        connection.execute("UPDATE composition_meta SET state_bytes=?,state_id=?,state_epoch=?,state_sequence=?,state_continuity_root=?,state_clearance_root=?,state_clearance_count=?,state_replay_root=?,payment_root=?,settled_batch_count=?,state_binding=?,audit_head=?,last_operation_digest=?,active_dispatch_count=active_dispatch_count+1 WHERE id=1", (bytes(statement.get("state_commitment_bytes")), statement.state_after_id, statement.epoch, sequence_after, statement.state("after_continuity_root"), clearance_after, count_after, replay_after, _INITIAL_PAYMENT, 0, binding_after, audit_after, operation_digest))
        self._append_event(connection, kind="APPLIED", tx=tx, before_state="NONE", after_state="READY", payload={"operation_digest": _hex(operation_digest), "queue_view_digest": _hex(queue_view_digest), "acceptance_digest": _hex(acceptance_digest), "artifact_digest": _hex(acceptance.artifact_digest), "state_receipt_digest": _hex(receipt_digest), "envelope_digest": _hex(envelope_digest), "outbox_operation_id": _hex(outbox_operation_id), "idempotency_key": _hex(idempotency), "policy_result": int(acceptance.policy_result), "effective_directive": int(acceptance.effective_directive), "payment_root_unchanged": True, "settlement_id": receipt["settlement_id"], "settlement_domain": receipt["settlement_domain"], "exception_authorization_id": receipt["exception_authorization_id"], "exception_scope_id": receipt["exception_scope_id"], "exception_valid_from": int(receipt["exception_valid_from"]), "exception_valid_until": int(receipt["exception_valid_until"]), "queue_batch_id": _hex(batch_token.batch_id), "queue_batch_member_set_digest": _hex(batch_token.member_set_digest), "composition_batch_id": _hex(composition_batch_id), "batch_member_index": member_index, "batch_member_count": batch_token.accepted_count}, receipt_digest=receipt_digest, now=now)
        return CompositionProcessResultV2(job_id, verified.operation_id, "APPLIED", disposition_id, receipt_raw, receipt_digest, job_id, outbox_operation_id, False, None), True

    @_public_v2_api
    def process_verified_jobs(self, queue_database: Path, promotion_batch: IndependentVerifiedQueueBatch | list[str] | tuple[str, ...]) -> tuple[CompositionProcessResultV2, ...]:
        if type(promotion_batch) is IndependentVerifiedQueueBatch:
            requested_batch = promotion_batch
            selector = requested_batch.batch.batch_id
        elif type(promotion_batch) in (list, tuple):
            if not 1 <= len(promotion_batch) <= 256 or len(set(promotion_batch)) != len(promotion_batch) or any(type(job_id) is not str for job_id in promotion_batch): _raise_fixed(CompositionIntegrityError, "job_ids")
            for job_id in promotion_batch: _token(job_id, "job_id")
            requested_batch = None
            selector = None
        else:
            _raise_fixed(CompositionIntegrityError, "promotion_batch_required")
        try:
            verified_batch = read_verified_batch(queue_database, selector)
        except (IndependentQueueError, OSError, sqlite3.Error): _raise_fixed(CompositionIntegrityError, "queue_verification_failed")
        if requested_batch is not None:
            if requested_batch.batch != verified_batch.batch or requested_batch.jobs != verified_batch.jobs: _raise_fixed(CompositionIntegrityError, "queue_batch_binding")
        else:
            if tuple(verified.job_id for verified in verified_batch.jobs) != tuple(promotion_batch): _raise_fixed(CompositionIntegrityError, "queue_job_binding")
        verified_jobs = verified_batch.jobs
        composition_batch_id = _composition_batch_id(self.config, verified_batch)
        prepared: list[tuple[Any, ...]] = []
        for member_index, verified in enumerate(verified_jobs):
            acceptance = self._validate_queue_result(verified); encoded = bytes(verified.acceptance_bytes); queue_view = self._queue_view_bytes(verified, verified_batch, member_index, composition_batch_id)
            queue_view_digest, acceptance_digest = _sha(_MATERIAL, b"queue-view", queue_view), _sha(_MATERIAL, b"acceptance", encoded)
            prepared.append((verified, acceptance, encoded, queue_view, queue_view_digest, acceptance_digest, verified_batch, composition_batch_id, member_index))
        now = int(self.clock.now_ms()); results: list[CompositionProcessResultV2] = []; applied_any = False; new_count = 0
        with closing(self._connect()) as connection:
            began = False
            try:
                connection.execute("BEGIN IMMEDIATE"); began = True; self._meta(connection)
                existing_rows: list[tuple[Any, ...] | None] = []
                new_material: set[bytes] = set()
                for item in prepared:
                    verified, acceptance, encoded, _queue_view, queue_view_digest, acceptance_digest, _batch, _composition_batch_identity, _member_index = item
                    existing = connection.execute("SELECT * FROM composition_transactions WHERE queue_job_id=?", (verified.job_id,)).fetchone()
                    if existing is not None:
                        if bytes(existing[2]) != verified.operation_id or bytes(existing[4]) != queue_view_digest or bytes(existing[6]) != acceptance_digest or bytes(existing[5]) != encoded: _raise_fixed(CompositionConflictError, "composition_conflicting_retry")
                        existing_rows.append(tuple(existing)); continue
                    operation_digest = _sha(_STATE_OPERATION, encoded, bytes(acceptance.statement.state_before_id), bytes(acceptance.statement.attempt_id), self.config.verifier_sha256)
                    material = (bytes(acceptance.artifact_digest), bytes(acceptance.statement.request_id), bytes(acceptance.statement.attempt_id), operation_digest)
                    if any(value in new_material for value in material) or connection.execute("SELECT 1 FROM composition_transactions WHERE artifact_digest=? OR request_id=? OR attempt_id=? OR operation_digest=?", material).fetchone() is not None: _raise_fixed(CompositionConflictError, "composition_conflicting_retry")
                    new_material.update(material); existing_rows.append(None); new_count += 1
                if int(self._meta(connection)[9]) + new_count > self.config.capacity: _raise_fixed(CompositionBackpressureError, "outbox_capacity")
                for item, existing in zip(prepared, existing_rows):
                    if existing is not None:
                        results.append(self._result_from_tx(existing, True)); continue
                    result, applied = self._apply_verified_job_in_transaction(connection, item, now)
                    results.append(result); applied_any = applied_any or applied
                if new_count: self._fault("before_composition_commit")
                connection.execute("COMMIT"); began = False
            except Exception:
                if began and connection.in_transaction: connection.execute("ROLLBACK")
                raise
        if applied_any:
            try: self._after_fault("after_composition_commit")
            except Exception: _raise_fixed(CompositionIndeterminateError, "composition_commit_indeterminate")
        return tuple(results)

    @_public_v2_api
    def process_verified_job(self, queue_database: Path, job_id: str) -> CompositionProcessResultV2:
        _token(job_id, "job_id")
        try:
            batch = read_verified_batch(queue_database)
        except (IndependentQueueError, OSError, sqlite3.Error): _raise_fixed(CompositionIntegrityError, "queue_verification_failed")
        if len(batch.jobs) != 1 or batch.jobs[0].job_id != job_id: _raise_fixed(CompositionIntegrityError, "size_one_batch_required")
        return self.process_verified_jobs(queue_database, batch)[0]

    def _recover_expired_leases(self, connection: sqlite3.Connection, now: int) -> None:
        for row in connection.execute("SELECT * FROM composition_transactions WHERE lease_kind IS NOT NULL AND lease_expires_ms<=? ORDER BY lease_expires_ms,queue_job_id", (now,)).fetchall():
            tx = tuple(row); kind = str(tx[24]); before = "DISPATCH_LEASED" if kind == "DISPATCH" else "RECONCILIATION_LEASED"
            if kind == "DISPATCH":
                status, event_kind, code = "DELIVERY_UNCONFIRMED", "DISPATCH_LEASE_EXPIRED", "dispatch_lease_expired"
                connection.execute("UPDATE composition_transactions SET delivery_status=?,lease_kind=NULL,lease_worker_id=NULL,lease_token=NULL,lease_started_ms=NULL,lease_expires_ms=NULL,next_eligible_ms=?,error_code=?,updated_ms=? WHERE queue_job_id=? AND lease_kind='DISPATCH'", (status, now, code, now, tx[1]))
                attempt = int(tx[22])
            else:
                terminal = int(tx[23]) >= self.config.max_attempts; status = "RECONCILIATION_EXHAUSTED" if terminal else "DELIVERY_UNCONFIRMED"; event_kind = "RECONCILIATION_EXHAUSTED" if terminal else "RECONCILIATION_LEASE_EXPIRED"; code = "reconciliation_attempts_exhausted" if terminal else "reconciliation_lease_expired"; attempt = int(tx[23])
                connection.execute("UPDATE composition_transactions SET delivery_status=?,lease_kind=NULL,lease_worker_id=NULL,lease_token=NULL,lease_started_ms=NULL,lease_expires_ms=NULL,next_eligible_ms=?,error_code=?,updated_ms=? WHERE queue_job_id=? AND lease_kind='RECONCILIATION'", (status, now, code, now, tx[1]))
                connection.execute("UPDATE composition_meta SET active_reconciliation_count=active_reconciliation_count-1,active_dispatch_count=active_dispatch_count-? WHERE id=1", (1 if terminal else 0,))
            updated = tuple(connection.execute("SELECT * FROM composition_transactions WHERE queue_job_id=?", (tx[1],)).fetchone())
            self._append_event(connection, kind=event_kind, tx=updated, before_state=before, after_state=status, payload={"attempt": attempt, "error_code": code}, receipt_digest=None, now=now)

    def _live_lease(self, connection: sqlite3.Connection, work: CompositionOutboxWorkV2 | CompositionReconciliationWorkV2, expected: str) -> tuple[Any, ...]:
        row = connection.execute("SELECT * FROM composition_transactions WHERE queue_job_id=?", (work.job_id,)).fetchone(); now = int(self.clock.now_ms())
        if row is None or str(row[24]) != expected or str(row[25]) != work.worker_id or bytes(row[26]) != work.lease_token or int(row[28]) != work.lease_expires_ms or now >= int(row[28]) or bytes(row[2]) != work.operation_id or work.composition_id != self.config.composition_id: _raise_fixed(CompositionLeaseError, "lease_stale")
        if expected == "DISPATCH" and (str(row[21]) != "DISPATCH_LEASED" or bytes(row[17]) != work.envelope_bytes or bytes(row[20]) != work.idempotency_key or int(row[22]) != work.attempt): _raise_fixed(CompositionLeaseError, "lease_stale")
        if expected == "RECONCILIATION" and (str(row[21]) != "RECONCILIATION_LEASED" or bytes(row[18]) != work.envelope_digest or bytes(row[20]) != work.idempotency_key or int(row[23]) != work.attempt): _raise_fixed(CompositionLeaseError, "lease_stale")
        return tuple(row)

    @_public_v2_api
    def claim_next_outbox(self, worker_id: str) -> CompositionOutboxWorkV2 | None:
        _token(worker_id, "worker_id"); now = int(self.clock.now_ms())
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                self._meta(connection); self._recover_expired_leases(connection, now)
                row = connection.execute("SELECT * FROM composition_transactions WHERE delivery_status='READY' AND lease_kind IS NULL AND next_eligible_ms<=? ORDER BY created_ms,queue_job_id LIMIT 1", (now,)).fetchone()
                if row is None: connection.execute("COMMIT"); return None
                row = tuple(row); attempt = int(row[22]) + 1
                if attempt > self.config.max_attempts:
                    connection.execute("UPDATE composition_transactions SET delivery_status='DISPATCH_EXHAUSTED',error_code=?,updated_ms=? WHERE queue_job_id=? AND delivery_status='READY' AND lease_kind IS NULL", ("dispatch_attempts_exhausted", now, row[1])); connection.execute("UPDATE composition_meta SET active_dispatch_count=active_dispatch_count-1 WHERE id=1")
                    updated = tuple(connection.execute("SELECT * FROM composition_transactions WHERE queue_job_id=?", (row[1],)).fetchone()); self._append_event(connection, kind="DISPATCH_EXHAUSTED", tx=updated, before_state="READY", after_state="DISPATCH_EXHAUSTED", payload={"attempt": attempt, "error_code": "dispatch_attempts_exhausted"}, receipt_digest=None, now=now); connection.execute("COMMIT"); return None
                token, expires = secrets.token_bytes(24), now + self.config.lease_seconds * 1000
                connection.execute("UPDATE composition_transactions SET delivery_status='DISPATCH_LEASED',dispatch_attempt=?,lease_kind='DISPATCH',lease_worker_id=?,lease_token=?,lease_started_ms=?,lease_expires_ms=?,updated_ms=? WHERE queue_job_id=? AND delivery_status='READY' AND lease_kind IS NULL", (attempt, worker_id, token, now, expires, now, row[1]))
                updated = tuple(connection.execute("SELECT * FROM composition_transactions WHERE queue_job_id=?", (row[1],)).fetchone()); self._append_event(connection, kind="DISPATCH_LEASED", tx=updated, before_state="READY", after_state="DISPATCH_LEASED", payload={"attempt": attempt, "worker_id": worker_id, "lease_token_digest": _hex(_sha(_MATERIAL, token)), "lease_expires_ms": expires}, receipt_digest=None, now=now); connection.execute("COMMIT")
                return CompositionOutboxWorkV2(self.config.composition_id, str(row[1]), bytes(row[2]), attempt, worker_id, token, expires, bytes(row[17]), bytes(row[20]))
            except Exception:
                if connection.in_transaction: connection.execute("ROLLBACK")
                raise

    def _validate_ack_work(self, work: CompositionOutboxWorkV2 | CompositionReconciliationWorkV2, row: tuple[Any, ...]) -> None:
        if work.composition_id != self.config.composition_id or bytes(row[2]) != work.operation_id or str(row[1]) != work.job_id or bytes(row[20]) != work.idempotency_key or (isinstance(work, CompositionOutboxWorkV2) and (bytes(row[17]) != work.envelope_bytes or bytes(row[18]) != _sha(_ENVELOPE, work.envelope_bytes) or int(row[22]) != work.attempt)) or (isinstance(work, CompositionReconciliationWorkV2) and (bytes(row[18]) != work.envelope_digest or int(row[23]) != work.attempt)):
            _raise_fixed(CompositionLeaseError, "ack_work_mismatch")
        if row[21] != "ACKNOWLEDGED": return
        ack = _parse_ack(bytes(row[30])); envelope = _parse_envelope(bytes(row[17])); qualification = _parse_qualification(bytes(row[35]))
        if bytes(row[31]) != _sha(_ACK, bytes(row[30])) or bytes.fromhex(str(ack["receiver_identity"])) != self.config.receiver_identity or int(ack["receiver_epoch"]) != self.config.receiver_epoch or bytes.fromhex(str(ack["verifier_identity"])) != self.config.verifier_sha256 or int(ack["verifier_epoch"]) != self.config.verifier_epoch or bytes.fromhex(str(ack["profile_digest"])) != self.config.profile_digest or bytes.fromhex(str(ack["envelope_digest"])) != bytes(row[18]) or bytes.fromhex(str(ack["idempotency_key"])) != bytes(row[20]) or int(ack["effective_directive"]) != int(envelope["effective_directive"]) or ("policy_result" in ack and int(ack["policy_result"]) != int(envelope["policy_result"])) or str(ack["acknowledgment_id"]) != str(row[32]) or bytes(row[34]) != self.config.profile_digest or bytes.fromhex(str(qualification["profile_digest"])) != self.config.profile_digest or bytes.fromhex(str(qualification["verifier_identity"])) != self.config.verifier_sha256 or int(qualification["verifier_epoch"]) != self.config.verifier_epoch or bytes.fromhex(str(qualification["receiver_identity"])) != self.config.receiver_identity or int(qualification["receiver_epoch"]) != self.config.receiver_epoch or bytes.fromhex(str(qualification["operation_id"])) != bytes(row[2]) or bytes.fromhex(str(qualification["job_id_digest"])) != _sha(_ACK_RECEIPT, str(row[1]).encode("ascii")) or bytes.fromhex(str(qualification["idempotency_key"])) != bytes(row[20]) or bytes.fromhex(str(qualification["envelope_digest"])) != bytes(row[18]) or bytes.fromhex(str(qualification["ack_digest"])) != bytes(row[31]) or bytes.fromhex(str(qualification["acknowledgment_id"])) != bytes.fromhex(str(ack["acknowledgment_id"])) or int(qualification["policy_result"]) != int(envelope["policy_result"]) or int(qualification["effective_directive"]) != int(envelope["effective_directive"]):
            _raise_fixed(CompositionIntegrityError, "ack_profile_binding")
        expected_attempt = int(row[22]) if qualification["lease_kind"] == "DISPATCH" else int(row[23])
        if qualification["lease_kind"] not in ("DISPATCH", "RECONCILIATION") or int(qualification["attempt"]) != expected_attempt or bytes.fromhex(str(qualification["lease_token_digest"])) != _sha(_MATERIAL, b"lease-token", work.lease_token):
            _raise_fixed(CompositionLeaseError, "ack_work_mismatch")

    def _existing_ack(self, work: CompositionOutboxWorkV2 | CompositionReconciliationWorkV2) -> CompositionDeliveryResultV2 | None:
        with closing(self._connect()) as connection: row = connection.execute("SELECT * FROM composition_transactions WHERE queue_job_id=?", (work.job_id,)).fetchone()
        if row is None: return None
        self._validate_ack_work(work, tuple(row))
        if row[21] != "ACKNOWLEDGED": return None
        return CompositionDeliveryResultV2(work.job_id, bytes(row[2]), "ACKNOWLEDGED", bytes(row[30]), bytes(row[31]), None, bytes(row[35]), bytes(row[34]), str(row[32]))

    def _release_dispatch(self, work: CompositionOutboxWorkV2, code: str) -> CompositionDeliveryResultV2:
        code, now = _code(code), int(self.clock.now_ms())
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                self._live_lease(connection, work, "DISPATCH"); terminal = work.attempt >= self.config.max_attempts; status = "DISPATCH_EXHAUSTED" if terminal else "READY"
                connection.execute("UPDATE composition_transactions SET delivery_status=?,lease_kind=NULL,lease_worker_id=NULL,lease_token=NULL,lease_started_ms=NULL,lease_expires_ms=NULL,next_eligible_ms=?,error_code=?,updated_ms=? WHERE queue_job_id=? AND lease_kind='DISPATCH'", (status, now, code, now, work.job_id))
                if terminal: connection.execute("UPDATE composition_meta SET active_dispatch_count=active_dispatch_count-1 WHERE id=1")
                updated = tuple(connection.execute("SELECT * FROM composition_transactions WHERE queue_job_id=?", (work.job_id,)).fetchone()); self._append_event(connection, kind="DISPATCH_EXHAUSTED" if terminal else "DISPATCH_RELEASED", tx=updated, before_state="DISPATCH_LEASED", after_state=status, payload={"attempt": work.attempt, "error_code": code}, receipt_digest=None, now=now); connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction: connection.execute("ROLLBACK")
                raise
        return CompositionDeliveryResultV2(work.job_id, work.operation_id, status, None, None, code)

    def _mark_delivery_unconfirmed(self, work: CompositionOutboxWorkV2, code: str) -> CompositionDeliveryResultV2:
        code, now = _code(code), int(self.clock.now_ms())
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                self._live_lease(connection, work, "DISPATCH"); connection.execute("UPDATE composition_transactions SET delivery_status='DELIVERY_UNCONFIRMED',lease_kind=NULL,lease_worker_id=NULL,lease_token=NULL,lease_started_ms=NULL,lease_expires_ms=NULL,next_eligible_ms=?,error_code=?,updated_ms=? WHERE queue_job_id=? AND lease_kind='DISPATCH'", (now, code, now, work.job_id))
                updated = tuple(connection.execute("SELECT * FROM composition_transactions WHERE queue_job_id=?", (work.job_id,)).fetchone()); self._append_event(connection, kind="DELIVERY_UNCONFIRMED", tx=updated, before_state="DISPATCH_LEASED", after_state="DELIVERY_UNCONFIRMED", payload={"attempt": work.attempt, "error_code": code}, receipt_digest=None, now=now); connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction: connection.execute("ROLLBACK")
                raise
        return CompositionDeliveryResultV2(work.job_id, work.operation_id, "DELIVERY_UNCONFIRMED", None, None, code)

    def _qualification_receipt(self, *, ack_raw: bytes, envelope: Mapping[str, Any], operation_id: bytes, job_id: str, idem: bytes, attempt: int, lease_kind: str, lease_token: bytes) -> bytes:
        ack = _parse_ack(ack_raw)
        _blob(lease_token, 24, "lease_token")
        if lease_kind not in ("DISPATCH", "RECONCILIATION"): _raise_fixed(CompositionIntegrityError, "lease_kind")
        return _json_bytes({"schema_version": 2, "mode": _ACK_MODE, "profile_digest": _hex(self.config.profile_digest), "verifier_identity": _hex(self.config.verifier_sha256), "verifier_epoch": self.config.verifier_epoch, "receiver_identity": _hex(self.config.receiver_identity), "receiver_epoch": self.config.receiver_epoch, "operation_id": _hex(operation_id), "job_id_digest": _hex(_sha(_ACK_RECEIPT, job_id.encode("ascii"))), "idempotency_key": _hex(idem), "envelope_digest": _hex(_sha(_ENVELOPE, _json_bytes(envelope))), "ack_digest": _hex(_sha(_ACK, ack_raw)), "acknowledgment_id": str(ack["acknowledgment_id"]), "policy_result": int(envelope["policy_result"]), "effective_directive": int(envelope["effective_directive"]), "proof_suite_id": None, "production_usable": False, "activation": False, "attempt": attempt, "lease_kind": lease_kind, "lease_token_digest": _hex(_sha(_MATERIAL, b"lease-token", lease_token))})

    def _validate_ack(self, raw: bytes, tx: tuple[Any, ...], *, build_qualification: bool = True) -> tuple[dict[str, Any], bytes, bytes, bytes]:
        ack, envelope, receipt = _parse_ack(raw), _parse_envelope(bytes(tx[17])), _parse_receipt(bytes(tx[14])); env_digest, ack_digest = _sha(_ENVELOPE, bytes(tx[17])), _sha(_ACK, raw)
        if bytes.fromhex(str(ack["receiver_identity"])) != self.config.receiver_identity or int(ack["receiver_epoch"]) != self.config.receiver_epoch or bytes.fromhex(str(ack["verifier_identity"])) != self.config.verifier_sha256 or int(ack["verifier_epoch"]) != self.config.verifier_epoch or bytes.fromhex(str(ack["profile_digest"])) != self.config.profile_digest or bytes.fromhex(str(ack["idempotency_key"])) != bytes(tx[20]) or bytes.fromhex(str(ack["envelope_digest"])) != env_digest or int(ack["effective_directive"]) != int(envelope["effective_directive"]) or ("policy_result" in ack and int(ack["policy_result"]) != int(envelope["policy_result"])) or bytes.fromhex(str(envelope["composition_config_digest"])) != self.config.digest or bytes.fromhex(str(envelope["receiver_identity"])) != self.config.receiver_identity or int(envelope["receiver_epoch"]) != self.config.receiver_epoch or int(envelope["verifier_epoch"]) != self.config.verifier_epoch or bytes.fromhex(str(envelope["ack_evidence_profile_digest"])) != self.config.profile_digest or bytes.fromhex(str(envelope["job_id_digest"])) != _sha(_ENVELOPE, str(tx[1]).encode("ascii")) or bytes.fromhex(str(envelope["operation_id"])) != bytes(tx[2]) or bytes.fromhex(str(envelope["disposition_digest"])) != bytes(tx[12]) or bytes.fromhex(str(envelope["state_receipt_digest"])) != bytes(tx[15]) or envelope["request_id"] != receipt["request_id"] or envelope["attempt_id"] != receipt["attempt_id"] or envelope["decision_id"] != receipt["decision_id"] or envelope["settlement_id"] != receipt["settlement_id"] or envelope["settlement_domain"] != receipt["settlement_domain"] or int(envelope["policy_result"]) != int(receipt["policy_result"]) or int(envelope["effective_directive"]) != int(receipt["effective_directive"]) or any(envelope[name] != receipt[name] for name in ("exception_authorization_id", "exception_scope_id", "exception_valid_from", "exception_valid_until")): _raise_fixed(CompositionIntegrityError, "ack_binding")
        qualification = self._qualification_receipt(ack_raw=raw, envelope=envelope, operation_id=bytes(tx[2]), job_id=str(tx[1]), idem=bytes(tx[20]), attempt=int(tx[22] if tx[24] == "DISPATCH" else tx[23]), lease_kind=str(tx[24]), lease_token=bytes(tx[26])) if build_qualification else b""
        return ack, env_digest, ack_digest, qualification

    def _commit_ack(self, work: CompositionOutboxWorkV2 | CompositionReconciliationWorkV2, raw: bytes, event_kind: str) -> CompositionDeliveryResultV2:
        with closing(self._connect()) as connection: row = connection.execute("SELECT * FROM composition_transactions WHERE queue_job_id=?", (work.job_id,)).fetchone()
        if row is None: _raise_fixed(CompositionIntegrityError, "transaction_missing")
        tx = tuple(row)
        if bytes(tx[2]) != work.operation_id: _raise_fixed(CompositionIntegrityError, "ack_operation_binding")
        initial_acknowledged = tx[21] == "ACKNOWLEDGED"
        if initial_acknowledged: self._validate_ack_work(work, tx)
        ack, _env_digest, ack_digest, qualification = self._validate_ack(raw, tx, build_qualification=not initial_acknowledged); now = int(self.clock.now_ms()); expected = "DISPATCH" if event_kind == "ACKNOWLEDGED" else "RECONCILIATION"
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                current_row = connection.execute("SELECT * FROM composition_transactions WHERE queue_job_id=?", (work.job_id,)).fetchone()
                if current_row is None: _raise_fixed(CompositionIntegrityError, "transaction_missing")
                if str(current_row[21]) == "ACKNOWLEDGED":
                    self._validate_ack_work(work, tuple(current_row))
                    if bytes(current_row[30]) == raw:
                        connection.execute("ROLLBACK")
                        return CompositionDeliveryResultV2(work.job_id, work.operation_id, "ACKNOWLEDGED", bytes(current_row[30]), bytes(current_row[31]), None, bytes(current_row[35]), bytes(current_row[34]), str(current_row[32]))
                    self._append_event(connection, kind="ACK_CONFLICT", tx=tuple(current_row), before_state="ACKNOWLEDGED", after_state="ACKNOWLEDGED", payload={"candidate_ack_digest": _hex(ack_digest), "stored_ack_digest": _hex(bytes(current_row[31])), "error_code": "ack_conflict"}, receipt_digest=bytes(current_row[15]), now=now)
                    connection.execute("COMMIT")
                    _raise_fixed(CompositionConflictError, "ack_conflict")
                current = self._live_lease(connection, work, expected); old = "DISPATCH_LEASED" if expected == "DISPATCH" else "RECONCILIATION_LEASED"
                if str(current[21]) != old: _raise_fixed(CompositionIndeterminateError, "ack_status_indeterminate")
                connection.execute("UPDATE composition_transactions SET delivery_status='ACKNOWLEDGED',lease_kind=NULL,lease_worker_id=NULL,lease_token=NULL,lease_started_ms=NULL,lease_expires_ms=NULL,acknowledgment_bytes=?,acknowledgment_digest=?,acknowledgment_id=?,acknowledged_ms=?,ack_profile_digest=?,qualification_receipt=?,error_code=NULL,updated_ms=? WHERE queue_job_id=? AND lease_kind=?", (raw, ack_digest, str(ack["acknowledgment_id"]), now, self.config.profile_digest, qualification, now, work.job_id, expected))
                connection.execute("UPDATE composition_meta SET active_dispatch_count=active_dispatch_count-?,active_reconciliation_count=active_reconciliation_count-? WHERE id=1", (1, 1 if expected == "RECONCILIATION" else 0))
                updated = tuple(connection.execute("SELECT * FROM composition_transactions WHERE queue_job_id=?", (work.job_id,)).fetchone()); receipt = _parse_receipt(bytes(updated[14]))
                self._append_event(connection, kind=event_kind, tx=updated, before_state=old, after_state="ACKNOWLEDGED", payload={"ack_digest": _hex(ack_digest), "acknowledgment_id": str(ack["acknowledgment_id"]), "qualification_receipt_digest": _hex(_sha(_MATERIAL, qualification)), "profile_digest": _hex(self.config.profile_digest), "policy_result": int(receipt["policy_result"]), "effective_directive": int(receipt["effective_directive"])}, receipt_digest=bytes(updated[15]), now=now)
                self._fault("before_ack_commit"); connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction: connection.execute("ROLLBACK")
                raise
        try: self._after_fault("after_reconciliation_commit" if expected == "RECONCILIATION" else "after_ack_commit")
        except Exception: _raise_fixed(CompositionIndeterminateError, "ack_commit_indeterminate")
        return CompositionDeliveryResultV2(work.job_id, work.operation_id, "ACKNOWLEDGED", raw, ack_digest, None, qualification, self.config.profile_digest, str(ack["acknowledgment_id"]))

    @_public_v2_api
    def dispatch(self, work: CompositionOutboxWorkV2, *, receiver: OfficialStateReceiverPort) -> CompositionDeliveryResultV2:
        existing = self._existing_ack(work)
        if existing is not None: return existing
        with closing(self._connect()) as connection: self._live_lease(connection, work, "DISPATCH")
        called = False
        try:
            if receiver.identity_sha256() != self.config.receiver_identity or receiver.epoch() != self.config.receiver_epoch: return self._release_dispatch(work, "receiver_identity_drift")
            called = True; raw = receiver.dispatch(work.envelope_bytes, work.idempotency_key)
            if type(raw) is not bytes: return self._mark_delivery_unconfirmed(work, "delivery_indeterminate")
            self._fault("after_dispatch_before_ack_commit"); return self._commit_ack(work, raw, "ACKNOWLEDGED")
        except CompositionConflictError:
            raise
        except CompositionLeaseError:
            existing = self._existing_ack(work)
            if existing is not None: return existing
            raise
        except Exception:
            return self._mark_delivery_unconfirmed(work, "delivery_indeterminate") if called else self._release_dispatch(work, "receiver_identity_drift")

    @_public_v2_api
    def claim_reconciliation_next(self, worker_id: str) -> CompositionReconciliationWorkV2 | None:
        _token(worker_id, "worker_id"); now = int(self.clock.now_ms())
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                self._meta(connection); self._recover_expired_leases(connection, now); meta = self._meta(connection)
                row = connection.execute("SELECT * FROM composition_transactions WHERE delivery_status='DELIVERY_UNCONFIRMED' AND lease_kind IS NULL AND next_eligible_ms<=? ORDER BY created_ms,queue_job_id LIMIT 1", (now,)).fetchone()
                if row is None or int(meta[10]) >= self.config.reconciliation_capacity: connection.execute("COMMIT"); return None
                row = tuple(row); attempt = int(row[23]) + 1
                if attempt > self.config.max_attempts:
                    connection.execute("UPDATE composition_transactions SET delivery_status='RECONCILIATION_EXHAUSTED',error_code=?,updated_ms=? WHERE queue_job_id=? AND delivery_status='DELIVERY_UNCONFIRMED' AND lease_kind IS NULL", ("reconciliation_attempts_exhausted", now, row[1])); connection.execute("UPDATE composition_meta SET active_dispatch_count=active_dispatch_count-1 WHERE id=1")
                    updated = tuple(connection.execute("SELECT * FROM composition_transactions WHERE queue_job_id=?", (row[1],)).fetchone()); self._append_event(connection, kind="RECONCILIATION_EXHAUSTED", tx=updated, before_state="DELIVERY_UNCONFIRMED", after_state="RECONCILIATION_EXHAUSTED", payload={"attempt": attempt, "error_code": "reconciliation_attempts_exhausted"}, receipt_digest=None, now=now); connection.execute("COMMIT"); return None
                token, expires = secrets.token_bytes(24), now + self.config.reconciliation_lease_seconds * 1000
                connection.execute("UPDATE composition_transactions SET delivery_status='RECONCILIATION_LEASED',reconciliation_attempt=?,lease_kind='RECONCILIATION',lease_worker_id=?,lease_token=?,lease_started_ms=?,lease_expires_ms=?,updated_ms=? WHERE queue_job_id=? AND delivery_status='DELIVERY_UNCONFIRMED' AND lease_kind IS NULL", (attempt, worker_id, token, now, expires, now, row[1])); connection.execute("UPDATE composition_meta SET active_reconciliation_count=active_reconciliation_count+1 WHERE id=1")
                updated = tuple(connection.execute("SELECT * FROM composition_transactions WHERE queue_job_id=?", (row[1],)).fetchone()); self._append_event(connection, kind="RECONCILIATION_LEASED", tx=updated, before_state="DELIVERY_UNCONFIRMED", after_state="RECONCILIATION_LEASED", payload={"attempt": attempt, "worker_id": worker_id, "lease_token_digest": _hex(_sha(_MATERIAL, token)), "lease_expires_ms": expires}, receipt_digest=None, now=now); connection.execute("COMMIT")
                return CompositionReconciliationWorkV2(self.config.composition_id, str(row[1]), bytes(row[2]), attempt, worker_id, token, expires, bytes(row[18]), bytes(row[20]))
            except Exception:
                if connection.in_transaction: connection.execute("ROLLBACK")
                raise

    def _release_reconciliation(self, work: CompositionReconciliationWorkV2, code: str) -> CompositionDeliveryResultV2:
        code, now = _code(code), int(self.clock.now_ms())
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                self._live_lease(connection, work, "RECONCILIATION"); terminal = work.attempt >= self.config.max_attempts; status = "RECONCILIATION_EXHAUSTED" if terminal else "DELIVERY_UNCONFIRMED"
                connection.execute("UPDATE composition_transactions SET delivery_status=?,lease_kind=NULL,lease_worker_id=NULL,lease_token=NULL,lease_started_ms=NULL,lease_expires_ms=NULL,next_eligible_ms=?,error_code=?,updated_ms=? WHERE queue_job_id=? AND lease_kind='RECONCILIATION'", (status, now, code, now, work.job_id)); connection.execute("UPDATE composition_meta SET active_dispatch_count=active_dispatch_count-?,active_reconciliation_count=active_reconciliation_count-1 WHERE id=1", (1 if terminal else 0,))
                updated = tuple(connection.execute("SELECT * FROM composition_transactions WHERE queue_job_id=?", (work.job_id,)).fetchone()); self._append_event(connection, kind="RECONCILIATION_EXHAUSTED" if terminal else "RECONCILIATION_INDETERMINATE", tx=updated, before_state="RECONCILIATION_LEASED", after_state=status, payload={"attempt": work.attempt, "error_code": code}, receipt_digest=None, now=now); connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction: connection.execute("ROLLBACK")
                raise
        return CompositionDeliveryResultV2(work.job_id, work.operation_id, status, None, None, code)

    @_public_v2_api
    def reconcile(self, work: CompositionReconciliationWorkV2, *, lookup: OfficialStateReceiverLookupPort | None = None) -> CompositionDeliveryResultV2:
        existing = self._existing_ack(work)
        if existing is not None: return existing
        if lookup is None: return self._release_reconciliation(work, "reconciliation_indeterminate")
        try:
            if lookup.acknowledgment_profile() != self.config.acknowledgment_profile: return self._release_reconciliation(work, "reconciliation_indeterminate")
            raw = lookup.lookup_acknowledgment(receiver_identity=self.config.receiver_identity, receiver_epoch=self.config.receiver_epoch, job_id=work.job_id, operation_id=work.operation_id, idempotency_key=work.idempotency_key, envelope_digest=work.envelope_digest)
            if raw is None or type(raw) is not bytes: return self._release_reconciliation(work, "reconciliation_indeterminate")
            return self._commit_ack(work, raw, "ACKNOWLEDGED_BY_RECONCILIATION")
        except CompositionConflictError:
            raise
        except CompositionLeaseError:
            existing = self._existing_ack(work)
            if existing is not None: return existing
            raise
        except Exception:
            return self._release_reconciliation(work, "reconciliation_indeterminate")

    @_public_v2_api
    def reconcile_next(self, worker_id: str, *, lookup: OfficialStateReceiverLookupPort | None = None) -> CompositionDeliveryResultV2 | None:
        work = self.claim_reconciliation_next(worker_id)
        return None if work is None else self.reconcile(work, lookup=lookup)

    @_public_v2_api
    def snapshot(self) -> dict[str, Any]:
        with closing(self._connect()) as connection:
            meta = self._meta(connection)
            counts = {status: int(connection.execute("SELECT COUNT(*) FROM composition_transactions WHERE delivery_status=?", (status,)).fetchone()[0]) for status in sorted(_DELIVERY_STATES)}
            dispositions = {status: int(connection.execute("SELECT COUNT(*) FROM composition_transactions WHERE status=?", (status,)).fetchone()[0]) for status in ("APPLIED", "HELD")}
            return {"schema": _SCHEMA, "composition_id": self.config.composition_id, "head_root": _hex(bytes(meta[7])), "transition_count": int(meta[8]), "disposition_counts": dispositions, "outbox_counts": counts, "active_dispatch_count": int(meta[9]), "active_reconciliation_count": int(meta[10]), "proof_suite_id": None, "production_usable": False, "activation": False}

    @_public_v2_api
    def verify_integrity(self) -> None:
        from app.minimal_clearance_composition_independent import verify_database
        verify_database(self.path, expected_config=self.config.as_json)

    @_public_v2_api
    def create_backup(self, destination: Path) -> None:
        if not isinstance(destination, Path) or destination.exists() or not destination.parent.is_dir() or destination == self.path: _raise_fixed(CompositionError, "backup_destination")
        self.verify_integrity()
        with closing(self._connect()) as source, closing(sqlite3.connect(destination)) as target: source.backup(target); target.commit()
        from app.minimal_clearance_composition_independent import verify_database
        verify_database(destination, expected_config=self.config.as_json)

    @_public_v2_api
    def recover_from_backup(self, *, backup_path: Path, recovered_path: Path) -> "ClearanceCompositionStoreV2":
        if not isinstance(backup_path, Path) or not backup_path.is_file() or not isinstance(recovered_path, Path) or recovered_path.exists() or not recovered_path.parent.is_dir() or backup_path == recovered_path: _raise_fixed(CompositionError, "backup_recovery_path")
        from app.minimal_clearance_composition_independent import verify_database
        verify_database(backup_path, expected_config=self.config.as_json)
        with closing(sqlite3.connect(backup_path)) as source, closing(sqlite3.connect(recovered_path)) as target: source.backup(target); target.commit()
        verify_database(recovered_path, expected_config=self.config.as_json)
        return type(self)(path=recovered_path, config=self.config, clock=self.clock)

    def close(self) -> None: return None


__all__ = ("CompositionBackpressureError", "CompositionClock", "CompositionConfigV2", "CompositionConflictError", "CompositionDeliveryResultV2", "CompositionError", "CompositionIndeterminateError", "CompositionIntegrityError", "CompositionLeaseError", "CompositionOutboxWorkV2", "CompositionProcessResultV2", "CompositionReconciliationWorkV2", "ClearanceCompositionStoreV2", "OfficialStateReceiverLookupPort", "OfficialStateReceiverPort", "SyntheticAckEvidenceProfileV2", "acknowledgment_digest", "build_directive_envelope", "build_synthetic_acknowledgment", "envelope_digest", "parse_acknowledgment_bytes", "parse_envelope_bytes")
