"""Single-owner synthetic clearance composition and official handoff V2.

The verification queue remains a separate database and process boundary.  This
module reads one independently reconstructed terminal queue result before it
opens a composition transaction.  It never runs a native verifier, owns no
artifact custody, and never mutates payment state.
"""

from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
from functools import wraps
import hashlib
import inspect
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
    IndependentVerifiedQueueJob,
    read_verified_job,
)


class CompositionError(RuntimeError):
    """Fail-closed composition error."""


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


def _raise_fixed(error_type: type[CompositionError], code: str) -> NoReturn:
    """Raise a fixed public error with no retained exception context."""
    error = error_type(code)
    try:
        raise error from None
    except CompositionError as clean:
        clean.__cause__ = None
        clean.__context__ = None
        raise


def _public_v2_api(method: Callable[..., Any]) -> Callable[..., Any]:
    """Redact producer/receiver/storage failures at every V2 public seam."""
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


_SCHEMA_VERSION: Final[int] = 2
_SCHEMA: Final[str] = "BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/v2"
_HANDOFF_SCHEMA: Final[str] = "BL/NATIVE-V3/MINIMAL-CLEARANCE/OFFICIAL-HANDOFF/v2"
_ACK_MODE: Final[str] = "SYNTHETIC_ONLY"
_DIRECTIVES: Final[tuple[str, ...]] = ("CLEAR", "HOLD", "HUMAN_REVIEW", "BLOCK", "EXCEPTION_APPROVED")
_STATUSES: Final[frozenset[str]] = frozenset({"DISCOVERED", "LEASED", "ACKNOWLEDGED", "DELIVERY_UNCONFIRMED"})
_RECON_STATUSES: Final[frozenset[str]] = frozenset({"DISCOVERED", "LEASED", "EXHAUSTED", "ACKNOWLEDGED"})
_TOKEN = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
_CODE = re.compile(r"[a-z][a-z0-9_]{0,95}\Z")
_MAX_ACCEPTANCE = 65_536
_MAX_RECEIPT = 16 * 1024
_MAX_ENVELOPE = 16 * 1024
_MAX_ACK = 4096
_MAX_EXPORT = 64 * 1024 * 1024
_MAX_ID = 128
_CAP_BYTES = 5_000_000_000
_ACTIVE_PROCESS_LIMIT = 1
_ZERO_SUITE = bytes(64)
_CIRCUIT_ID = bytes.fromhex("1eaaf14f3b23db1ed02f3c378099627767f81142e0114f90448cac7c1cc66be0")
_COMPOSITION_TABLES: Final[frozenset[str]] = frozenset({
    "composition_metadata", "composition_state", "composition_transitions", "proof_requests",
    "proof_audit", "proof_transitions", "application_dispositions", "outbox_jobs", "outbox_leases",
    "outbox_acks", "outbox_transitions", "reconciliation_records",
})

_MATERIAL = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/MATERIAL/v2\x00"
_GENESIS = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/GENESIS/v2\x00"
_HEAD = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/HEAD/v2\x00"
_EVENT = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/EVENT/v2\x00"
_STATE_OPERATION = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/PROOF-OPERATION/v1\x00"
_STATE_REPLAY = b"BL/MINIMAL-CLEARANCE/PROOF-REPLAY/v1\x00"
_STATE_CLEARANCE = b"BL/MINIMAL-CLEARANCE/CLEARANCE-ROOT/v1\x00"
_STATE_BINDING = b"BL/MINIMAL-CLEARANCE/STATE-BINDING/v1\x00"
_STATE_GENESIS = b"BL/MINIMAL-CLEARANCE/GENESIS/v1\x00"
_STATE_AUDIT_EVENT = b"BL/MINIMAL-CLEARANCE/AUDIT-EVENT/v1\x00"
_STATE_AUDIT_HEAD = b"BL/MINIMAL-CLEARANCE/AUDIT-HEAD/v1\x00"
_STATE_RECEIPT = b"BL/MINIMAL-CLEARANCE/RECEIPT/v1\x00"
_STATE_IDENTITY = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/STATE-STORE-IDENTITY/v1\x00"
_ENVELOPE = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/OFFICIAL-DIRECTIVE-ENVELOPE/v2\x00"
_ACK = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/OFFICIAL-DIRECTIVE-ACK/v2\x00"
_ACK_PROFILE = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/OFFICIAL-DIRECTIVE-ACK-PROFILE/v2\x00"
_ACK_RECEIPT = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/OFFICIAL-DIRECTIVE-ACK-RECEIPT/v2\x00"
_OUTBOX_OPERATION = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/OFFICIAL-DIRECTIVE-OPERATION/v2\x00"
_IDEMPOTENCY = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/OFFICIAL-DIRECTIVE-IDEMPOTENCY/v2\x00"
_QUEUE_VIEW_SCHEMA = "BL/NATIVE-V3/MINIMAL-CLEARANCE/QUEUE-VIEW/v1"


def _sha(domain: bytes, *parts: bytes) -> bytes:
    digest = hashlib.sha3_512()
    digest.update(domain)
    for part in parts:
        if type(part) is not bytes:
            raise CompositionIntegrityError("binding_type")
        digest.update(part)
    return digest.digest()


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        _raise_fixed(CompositionIntegrityError, "json")


def _hex(value: bytes) -> str:
    return value.hex().upper()


def _blob(value: object, size: int, label: str) -> bytes:
    if type(value) is not bytes or len(value) != size:
        _raise_fixed(CompositionIntegrityError, f"{label}_width")
    return bytes(value)


def _hex_blob(value: object, size: int, label: str) -> bytes:
    if type(value) is not str:
        raise CompositionIntegrityError(label)
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        _raise_fixed(CompositionIntegrityError, label)
    if len(raw) != size:
        raise CompositionIntegrityError(label)
    return raw


def _token(value: object, label: str) -> str:
    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        raise CompositionError(f"{label}_invalid")
    return value


def _code(value: object, label: str = "error_code") -> str:
    if type(value) is not str or _CODE.fullmatch(value) is None:
        raise CompositionIntegrityError(f"{label}_invalid")
    return value


def _u64(value: int) -> bytes:
    if type(value) is not int or not 0 <= value < 2**64:
        raise CompositionIntegrityError("integer")
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
        b"BL/NATIVE-V3/PRIVATE-ZK/PROFILE/v1\x00", _PRIVATE_MODE, _PRIVATE_CONTEXT,
        _PRIVATE_SCHEMA, _PRIVATE_PROGRAM, bytes(statement.get("execution_context")),
        bytes(statement.get("evaluator_id")), bytes(statement.get("schema_id")),
        bytes(statement.get("program_id")), bytes(statement.get("automatic_control_set")),
        _CIRCUIT_ID, verifier_sha256, _ZERO_SUITE, _u64(_PRIVATE_EPOCH),
    )


def _state_store_identity(statement: Any, verifier_sha256: bytes) -> bytes:
    expected = bytes(statement.statement_bytes)
    return _sha(
        _STATE_IDENTITY, _PRIVATE_CONTEXT, _PRIVATE_SCHEMA, _PRIVATE_PROGRAM, _PRIVATE_MODE,
        _CIRCUIT_ID, expected, verifier_sha256, _profile_digest(statement, verifier_sha256),
    )


def _fixed_ascii(value: str, label: str) -> bytes:
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError:
        _raise_fixed(CompositionIntegrityError, label)
    if len(encoded) > _MAX_ID:
        raise CompositionIntegrityError(label)
    return len(encoded).to_bytes(2, "big") + encoded + bytes(_MAX_ID - len(encoded))


class CompositionClock(Protocol):
    def now_ms(self) -> int: ...


class _SystemClock:
    def now_ms(self) -> int:
        return int(time.time() * 1000)


class OfficialStateReceiverPort(Protocol):
    def identity_sha256(self) -> bytes: ...
    def epoch(self) -> int: ...
    def dispatch(self, envelope_bytes: bytes, idempotency_key: bytes) -> bytes: ...


class OfficialStateReceiverLookupPort(Protocol):
    def lookup_acknowledgment(
        self, *, receiver_identity: bytes, receiver_epoch: int, job_id: str,
        operation_id: bytes, idempotency_key: bytes, envelope_digest: bytes,
    ) -> bytes | None: ...


@dataclass(frozen=True, slots=True)
class CompositionLookupQueryV2:
    receiver_identity: bytes
    receiver_epoch: int
    job_id: str
    operation_id: bytes
    idempotency_key: bytes
    envelope_digest: bytes


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
        if type(self.verifier_epoch) is not int or self.verifier_epoch < 1:
            raise CompositionIntegrityError("profile_verifier_epoch")
        if type(self.receiver_epoch) is not int or self.receiver_epoch < 1:
            raise CompositionIntegrityError("profile_receiver_epoch")
        if self.mode != _ACK_MODE or self.proof_suite_id is not None or self.production_usable is not False or self.activation is not False:
            raise CompositionIntegrityError("profile_nonactivation")

    @property
    def canonical_bytes(self) -> bytes:
        return _json_bytes({
            "schema_version": 2, "mode": self.mode,
            "verifier_identity": _hex(self.verifier_identity), "verifier_epoch": self.verifier_epoch,
            "receiver_identity": _hex(self.receiver_identity), "receiver_epoch": self.receiver_epoch,
            "proof_suite_id": None, "production_usable": False, "activation": False,
        })

    @property
    def digest(self) -> bytes:
        return _sha(_ACK_PROFILE, self.canonical_bytes)


@dataclass(frozen=True, slots=True)
class CompositionConfigV2:
    queue_id: str
    queue_config_digest: bytes
    verifier_sha256: bytes
    state_profile_identity: bytes | None = None
    receiver_identity: bytes = bytes(32)
    receiver_epoch: int = 1
    composition_id: str = "minimal-clearance-composition-v2"
    verifier_epoch: int = 1
    expected_statement: bytes | None = None
    capacity: int = 16
    lease_seconds: int = 300
    reconciliation_capacity: int = 16
    reconciliation_lease_seconds: int = 300
    max_attempts: int = 3
    busy_timeout_ms: int = 5_000
    state_store_identity: bytes | None = None
    proof_suite_id: None = None
    production_usable: bool = False
    activation: bool = False

    def __post_init__(self) -> None:
        _token(self.queue_id, "queue_id")
        _token(self.composition_id, "composition_id")
        _blob(self.queue_config_digest, 64, "queue_config_digest")
        _blob(self.verifier_sha256, 32, "verifier_sha256")
        _blob(self.receiver_identity, 32, "receiver_identity")
        if self.state_profile_identity is None and self.state_store_identity is not None:
            object.__setattr__(self, "state_profile_identity", bytes(self.state_store_identity))
        elif self.state_profile_identity is not None and self.state_store_identity is not None and self.state_profile_identity != self.state_store_identity:
            raise CompositionIntegrityError("state_profile_alias_conflict")
        if self.state_profile_identity is not None:
            _blob(self.state_profile_identity, 64, "state_profile_identity")
        if self.expected_statement is not None and (type(self.expected_statement) is not bytes or len(self.expected_statement) != 3340):
            raise CompositionIntegrityError("expected_statement")
        for value, label, maximum in (
            (self.receiver_epoch, "receiver_epoch", 2**63), (self.verifier_epoch, "verifier_epoch", 2**63),
            (self.capacity, "capacity", 10_000), (self.reconciliation_capacity, "reconciliation_capacity", 10_000),
            (self.lease_seconds, "lease_seconds", 3_600), (self.reconciliation_lease_seconds, "reconciliation_lease_seconds", 3_600),
        ):
            if type(value) is not int or not 1 <= value <= maximum:
                raise CompositionIntegrityError(label)
        if self.max_attempts != 3 or self.busy_timeout_ms != 5_000:
            raise CompositionIntegrityError("fixed_config")
        if self.proof_suite_id is not None or self.production_usable is not False or self.activation is not False:
            raise CompositionIntegrityError("nonactivation")

    @property
    def state_identity(self) -> bytes | None:
        return self.state_profile_identity

    @property
    def profile_digest(self) -> bytes:
        return SyntheticAckEvidenceProfileV2(
            self.verifier_sha256, self.verifier_epoch, self.receiver_identity, self.receiver_epoch,
        ).digest

    @property
    def as_json(self) -> dict[str, Any]:
        return {
            "schema_version": _SCHEMA_VERSION, "composition_id": self.composition_id,
            "queue_id": self.queue_id, "queue_config_digest": _hex(self.queue_config_digest),
            "verifier_sha256": _hex(self.verifier_sha256),
            "state_profile_identity": None if self.state_profile_identity is None else _hex(self.state_profile_identity),
            "receiver_identity": _hex(self.receiver_identity), "receiver_epoch": self.receiver_epoch,
            "verifier_epoch": self.verifier_epoch, "expected_statement": None if self.expected_statement is None else _hex(self.expected_statement),
            "capacity": self.capacity, "lease_seconds": self.lease_seconds,
            "reconciliation_capacity": self.reconciliation_capacity,
            "reconciliation_lease_seconds": self.reconciliation_lease_seconds,
            "max_attempts": self.max_attempts, "busy_timeout_ms": self.busy_timeout_ms,
            "ack_evidence_profile_digest": _hex(self.profile_digest), "directives": list(_DIRECTIVES),
            "proof_suite_id": None, "production_usable": False, "activation": False,
        }

    @property
    def canonical_bytes(self) -> bytes:
        return _json_bytes(self.as_json)

    @property
    def digest(self) -> bytes:
        return _sha(_MATERIAL, self.canonical_bytes)

    @property
    def acknowledgment_profile(self) -> SyntheticAckEvidenceProfileV2:
        return SyntheticAckEvidenceProfileV2(
            self.verifier_sha256, self.verifier_epoch, self.receiver_identity, self.receiver_epoch,
        )


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


def _receipt_values(receipt: Mapping[str, Any]) -> dict[str, Any]:
    return {key: (_hex(value) if type(value) is bytes else value) for key, value in receipt.items()}


def _receipt_digest(raw: bytes) -> bytes:
    return _sha(_STATE_RECEIPT, raw)


def _parse_receipt(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not 0 < len(raw) <= _MAX_RECEIPT:
        raise CompositionIntegrityError("receipt_bounds")
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _raise_fixed(CompositionIntegrityError, "receipt_encoding")
    if type(value) is not dict or raw != _json_bytes(value):
        raise CompositionIntegrityError("receipt_canonical")
    required = {
        "operation_digest", "artifact_sha256", "artifact_digest", "statement_digest", "circuit_id", "bundle_id", "receipt_id", "join_id", "settlement_id", "request_id", "attempt_id", "decision_id", "sequence_before", "sequence_after", "state_before_id", "state_after_id", "clearance_root_before", "clearance_root_after", "clearance_count_before", "clearance_count_after", "payment_root_before", "payment_root_after", "settled_batch_count_before", "settled_batch_count_after", "state_binding_after", "audit_head_after", "policy_result", "effective_directive", "proof_session_accepted", "economic_mutation", "proof_suite_id",
    }
    if set(value) != required:
        raise CompositionIntegrityError("receipt_keys")
    digest_names = ("operation_digest", "artifact_sha256", "artifact_digest", "statement_digest", "circuit_id", "bundle_id", "receipt_id", "join_id", "settlement_id", "request_id", "attempt_id", "decision_id", "state_before_id", "state_after_id", "clearance_root_before", "clearance_root_after", "payment_root_before", "payment_root_after", "state_binding_after", "audit_head_after")
    for name in digest_names:
        size = 32 if name in {"artifact_sha256", "circuit_id"} else 64
        _hex_blob(value[name], size, "receipt_" + name)
    for name in ("sequence_before", "sequence_after", "clearance_count_before", "clearance_count_after", "settled_batch_count_before", "settled_batch_count_after"):
        if type(value[name]) is not int or value[name] < 0:
            raise CompositionIntegrityError("receipt_integer")
    for name in ("policy_result", "effective_directive"):
        if type(value[name]) is not int or not 1 <= value[name] <= 5:
            raise CompositionIntegrityError("receipt_directive")
    if value["proof_session_accepted"] is not True or value["economic_mutation"] is not False or value["proof_suite_id"] is not None:
        raise CompositionIntegrityError("receipt_nonactivation")
    return value


def _parse_envelope(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not 0 < len(raw) <= _MAX_ENVELOPE:
        raise CompositionIntegrityError("envelope_bounds")
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _raise_fixed(CompositionIntegrityError, "envelope_encoding")
    required = {"schema", "composition_config_digest", "composition_id_digest", "receiver_identity", "receiver_epoch", "verifier_epoch", "ack_evidence_profile_digest", "job_id_digest", "operation_id", "disposition_digest", "state_store_identity", "state_receipt_digest", "request_id", "attempt_id", "decision_id", "receipt_id", "state_after_id", "state_binding_after", "audit_head_after", "policy_result", "effective_directive", "proof_session_accepted", "proof_acceptance_is_clear", "payment_root_unchanged", "settled_batch_count_unchanged", "economic_mutation", "proof_suite_id"}
    if type(value) is not dict or set(value) != required or raw != _json_bytes(value):
        raise CompositionIntegrityError("envelope_canonical")
    if value["schema"] != _HANDOFF_SCHEMA:
        raise CompositionIntegrityError("envelope_schema")
    for name, size in (("composition_config_digest", 64), ("composition_id_digest", 64), ("receiver_identity", 32), ("ack_evidence_profile_digest", 64), ("job_id_digest", 64), ("operation_id", 64), ("disposition_digest", 64), ("state_store_identity", 64), ("state_receipt_digest", 64), ("request_id", 64), ("attempt_id", 64), ("decision_id", 64), ("receipt_id", 64), ("state_after_id", 64), ("state_binding_after", 64), ("audit_head_after", 64)):
        _hex_blob(value[name], size, "envelope_" + name)
    for name in ("receiver_epoch", "verifier_epoch", "policy_result", "effective_directive"):
        if type(value[name]) is not int or value[name] < 1:
            raise CompositionIntegrityError("envelope_integer")
    if value["proof_session_accepted"] is not True or value["proof_acceptance_is_clear"] is not False or value["payment_root_unchanged"] is not True or value["settled_batch_count_unchanged"] is not True or value["economic_mutation"] is not False or value["proof_suite_id"] is not None:
        raise CompositionIntegrityError("envelope_nonactivation")
    return value


def _parse_ack(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not 0 < len(raw) <= _MAX_ACK:
        raise CompositionIntegrityError("ack_bounds")
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _raise_fixed(CompositionIntegrityError, "ack_encoding")
    keys = {"schema", "receiver_identity", "receiver_epoch", "idempotency_key", "envelope_digest", "effective_directive", "accepted_ms", "acknowledgment_id"}
    keys_with_policy = keys | {"policy_result"}
    if type(value) is not dict or set(value) not in (keys, keys_with_policy) or raw != _json_bytes(value):
        raise CompositionIntegrityError("ack_canonical")
    if value["schema"] != _HANDOFF_SCHEMA:
        raise CompositionIntegrityError("ack_schema")
    _hex_blob(value["receiver_identity"], 32, "ack_receiver")
    _hex_blob(value["idempotency_key"], 64, "ack_idempotency")
    _hex_blob(value["envelope_digest"], 64, "ack_envelope")
    _hex_blob(value["acknowledgment_id"], 64, "ack_id")
    for name in ("receiver_epoch", "effective_directive", "accepted_ms"):
        if type(value[name]) is not int or value[name] < 0:
            raise CompositionIntegrityError("ack_integer")
    if "policy_result" in value and (type(value["policy_result"]) is not int or not 1 <= value["policy_result"] <= 5):
        raise CompositionIntegrityError("ack_policy")
    if not 1 <= value["effective_directive"] <= 5:
        raise CompositionIntegrityError("ack_directive")
    return value


@_public_v2_api
def parse_envelope_bytes(raw: bytes) -> dict[str, Any]:
    return _parse_envelope(raw)


@_public_v2_api
def parse_acknowledgment_bytes(raw: bytes) -> dict[str, Any]:
    return _parse_ack(raw)


@_public_v2_api
def envelope_digest(raw: bytes) -> bytes:
    _parse_envelope(raw)
    return _sha(_ENVELOPE, raw)


@_public_v2_api
def acknowledgment_digest(raw: bytes) -> bytes:
    _parse_ack(raw)
    return _sha(_ACK, raw)


@_public_v2_api
def build_synthetic_acknowledgment(
    envelope_bytes: bytes, *, config: CompositionConfigV2, job_id: str | None = None,
    idempotency_key: bytes | None = None, accepted_ms: int = 0,
    acknowledgment_id: bytes | None = None, policy_result: int | None = None,
) -> bytes:
    envelope = _parse_envelope(envelope_bytes)
    ack_id = acknowledgment_id or _sha(_ACK_RECEIPT, envelope_bytes, _u64(accepted_ms))
    _blob(ack_id, 64, "ack_id")
    if idempotency_key is None:
        if job_id is None:
            raise CompositionIntegrityError("ack_job_id")
        idempotency_key = _idempotency_key(config, job_id, _sha(_ENVELOPE, envelope_bytes))
    _blob(idempotency_key, 64, "ack_idempotency")
    value: dict[str, Any] = {
        "schema": _HANDOFF_SCHEMA, "receiver_identity": _hex(config.receiver_identity),
        "receiver_epoch": config.receiver_epoch, "idempotency_key": _hex(idempotency_key),
        "envelope_digest": _hex(_sha(_ENVELOPE, envelope_bytes)),
        "effective_directive": int(envelope["effective_directive"]), "accepted_ms": accepted_ms,
        "acknowledgment_id": _hex(ack_id),
    }
    if policy_result is not None:
        value["policy_result"] = policy_result
    return _json_bytes(value)


@_public_v2_api
def build_directive_envelope(
    *, config: CompositionConfigV2, job_id: str, operation_id: bytes,
    disposition_digest: bytes, state_store_identity: bytes, receipt: Mapping[str, Any],
) -> bytes:
    if receipt["proof_session_accepted"] is not True or receipt["economic_mutation"] is not False or receipt["proof_suite_id"] is not None:
        raise CompositionIntegrityError("envelope_receipt_claim")
    env = {
        "schema": _HANDOFF_SCHEMA, "composition_config_digest": _hex(config.digest),
        "composition_id_digest": _hex(_sha(_ENVELOPE, config.composition_id.encode("ascii"))),
        "receiver_identity": _hex(config.receiver_identity), "receiver_epoch": config.receiver_epoch,
        "verifier_epoch": config.verifier_epoch, "ack_evidence_profile_digest": _hex(config.profile_digest),
        "job_id_digest": _hex(_sha(_ENVELOPE, job_id.encode("ascii"))), "operation_id": _hex(operation_id),
        "disposition_digest": _hex(disposition_digest), "state_store_identity": _hex(state_store_identity),
        "state_receipt_digest": _hex(_receipt_digest(_json_bytes(_receipt_values(receipt)))),
        "request_id": receipt["request_id"], "attempt_id": receipt["attempt_id"], "decision_id": receipt["decision_id"],
        "receipt_id": receipt["receipt_id"], "state_after_id": receipt["state_after_id"],
        "state_binding_after": receipt["state_binding_after"], "audit_head_after": receipt["audit_head_after"],
        "policy_result": int(receipt["policy_result"]), "effective_directive": int(receipt["effective_directive"]),
        "proof_session_accepted": True, "proof_acceptance_is_clear": False,
        "payment_root_unchanged": receipt["payment_root_before"] == receipt["payment_root_after"],
        "settled_batch_count_unchanged": receipt["settled_batch_count_before"] == receipt["settled_batch_count_after"],
        "economic_mutation": False, "proof_suite_id": None,
    }
    raw = _json_bytes(env)
    _parse_envelope(raw)
    return raw


def _receipt_from_row(row: sqlite3.Row | tuple[Any, ...]) -> dict[str, Any]:
    raw = bytes(row[0])
    value = _parse_receipt(raw)
    return value


def _state_receipt(
    *, operation_digest: bytes, acceptance: Any, sequence_before: int, sequence_after: int,
    state_before_id: bytes, state_after_id: bytes, clearance_before: bytes, clearance_after: bytes,
    count_before: int, count_after: int, binding_after: bytes, audit_after: bytes,
) -> dict[str, Any]:
    return {
        "operation_digest": _hex(operation_digest), "artifact_sha256": _hex(acceptance.artifact_sha256),
        "artifact_digest": _hex(acceptance.artifact_digest), "statement_digest": _hex(acceptance.statement_digest),
        "circuit_id": _hex(acceptance.circuit_id), "bundle_id": _hex(acceptance.bundle_id),
        "receipt_id": _hex(acceptance.statement.receipt_id), "join_id": _hex(acceptance.statement.join_id),
        "settlement_id": _hex(acceptance.statement.settlement_id), "request_id": _hex(acceptance.statement.request_id),
        "attempt_id": _hex(acceptance.statement.attempt_id), "decision_id": _hex(acceptance.statement.decision_id),
        "sequence_before": sequence_before, "sequence_after": sequence_after,
        "state_before_id": _hex(state_before_id), "state_after_id": _hex(state_after_id),
        "clearance_root_before": _hex(clearance_before), "clearance_root_after": _hex(clearance_after),
        "clearance_count_before": count_before, "clearance_count_after": count_after,
        "payment_root_before": _hex(_INITIAL_PAYMENT), "payment_root_after": _hex(_INITIAL_PAYMENT),
        "settled_batch_count_before": 0, "settled_batch_count_after": 0,
        "state_binding_after": _hex(binding_after), "audit_head_after": _hex(audit_after),
        "policy_result": int(acceptance.policy_result), "effective_directive": int(acceptance.effective_directive),
        "proof_session_accepted": True, "economic_mutation": False, "proof_suite_id": None,
    }


class ClearanceCompositionStoreV2:
    """The only SQLite writer for proof state, application, and handoff V2."""

    @_public_v2_api
    def __init__(
        self, *, path: Path, config: CompositionConfigV2,
        clock: CompositionClock | None = None,
        before_fault: Callable[[str], None] | None = None,
        after_commit_fault: Callable[[str], None] | None = None,
    ) -> None:
        if not isinstance(path, Path) or path.exists() and path.is_symlink() or not path.parent.is_dir():
            raise CompositionError("composition_database_path")
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

    def _fault(self, label: str) -> None:
        if self._before_fault is not None:
            self._before_fault(label)

    def _after_fault(self, label: str) -> None:
        if self._after_commit_fault is not None:
            self._after_commit_fault(label)

    def _initialize(self) -> None:
        with closing(self._connect()) as connection:
            existing = {
                str(row[0]) for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                ).fetchall()
            }
            if existing and not existing.issubset(_COMPOSITION_TABLES):
                raise CompositionIntegrityError("composition_wrong_schema")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS composition_metadata (
                    id INTEGER PRIMARY KEY CHECK(id=1), schema_version INTEGER NOT NULL,
                    composition_id TEXT NOT NULL, config_json BLOB NOT NULL, config_digest BLOB NOT NULL,
                    queue_id TEXT NOT NULL, queue_config_digest BLOB NOT NULL, verifier_sha256 BLOB NOT NULL,
                    state_profile_identity BLOB, receiver_identity BLOB NOT NULL, receiver_epoch INTEGER NOT NULL,
                    verifier_epoch INTEGER NOT NULL, ack_profile_digest BLOB NOT NULL, expected_statement BLOB,
                    proof_suite_id BLOB, production_usable INTEGER NOT NULL, activation INTEGER NOT NULL,
                    head_root BLOB NOT NULL, next_sequence INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS composition_state (
                    id INTEGER PRIMARY KEY CHECK(id=1), expected_statement BLOB NOT NULL, circuit_id BLOB NOT NULL,
                    state_id BLOB NOT NULL, epoch INTEGER NOT NULL, sequence INTEGER NOT NULL,
                    continuity_root BLOB NOT NULL, clearance_root BLOB NOT NULL, clearance_count INTEGER NOT NULL,
                    replay_root BLOB NOT NULL, payment_root BLOB NOT NULL, settled_batch_count INTEGER NOT NULL,
                    state_binding BLOB NOT NULL, audit_head BLOB NOT NULL, last_operation_digest BLOB,
                    verifier_sha256 BLOB NOT NULL, profile_digest BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS composition_transitions (
                    sequence INTEGER PRIMARY KEY, transition_kind TEXT NOT NULL, job_id TEXT NOT NULL,
                    before_root BLOB NOT NULL, after_root BLOB NOT NULL, event_bytes BLOB NOT NULL,
                    event_digest BLOB NOT NULL UNIQUE
                );
                CREATE TABLE IF NOT EXISTS proof_requests (
                    operation_digest BLOB PRIMARY KEY, queue_job_id TEXT NOT NULL UNIQUE, queue_operation_id BLOB NOT NULL UNIQUE,
                    queue_view_bytes BLOB NOT NULL, queue_view_digest BLOB NOT NULL, acceptance_bytes BLOB NOT NULL,
                    acceptance_digest BLOB NOT NULL, receipt_bytes BLOB NOT NULL, artifact_digest BLOB NOT NULL UNIQUE,
                    request_id BLOB NOT NULL, attempt_id BLOB NOT NULL, decision_id BLOB NOT NULL,
                    sequence_before INTEGER NOT NULL, sequence_after INTEGER NOT NULL, state_before_id BLOB NOT NULL,
                    state_after_id BLOB NOT NULL, clearance_root_before BLOB NOT NULL, clearance_root_after BLOB NOT NULL,
                    clearance_count_before INTEGER NOT NULL, clearance_count_after INTEGER NOT NULL,
                    state_binding_before BLOB NOT NULL, state_binding_after BLOB NOT NULL, audit_head_before BLOB NOT NULL,
                    audit_head_after BLOB NOT NULL, policy_result INTEGER NOT NULL, effective_directive INTEGER NOT NULL,
                    created_ms INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS proof_audit (
                    sequence INTEGER PRIMARY KEY, previous_head BLOB NOT NULL, event_commitment BLOB NOT NULL UNIQUE,
                    current_head BLOB NOT NULL, payload BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS proof_transitions (
                    sequence_after INTEGER PRIMARY KEY, operation_digest BLOB NOT NULL UNIQUE,
                    state_binding_before BLOB NOT NULL, state_binding_after BLOB NOT NULL,
                    payment_root_before BLOB NOT NULL, payment_root_after BLOB NOT NULL,
                    settled_batch_count_before INTEGER NOT NULL, settled_batch_count_after INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS application_dispositions (
                    disposition_id BLOB PRIMARY KEY, queue_job_id TEXT NOT NULL UNIQUE, queue_operation_id BLOB NOT NULL UNIQUE,
                    operation_digest BLOB NOT NULL UNIQUE, acceptance_digest BLOB NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('APPLIED','HELD')), receipt_bytes BLOB,
                    receipt_digest BLOB, duplicate_convergence INTEGER NOT NULL, error_code TEXT, created_ms INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS outbox_jobs (
                    job_id TEXT PRIMARY KEY, operation_id BLOB NOT NULL UNIQUE, disposition_id BLOB NOT NULL UNIQUE,
                    envelope_bytes BLOB NOT NULL, envelope_digest BLOB NOT NULL UNIQUE, idempotency_key BLOB NOT NULL UNIQUE,
                    status TEXT NOT NULL, attempt INTEGER NOT NULL, next_eligible_ms INTEGER NOT NULL,
                    created_ms INTEGER NOT NULL, updated_ms INTEGER NOT NULL, last_error_code TEXT
                );
                CREATE TABLE IF NOT EXISTS outbox_leases (
                    job_id TEXT PRIMARY KEY, worker_id TEXT NOT NULL, token BLOB NOT NULL,
                    attempt INTEGER NOT NULL, leased_ms INTEGER NOT NULL, expires_ms INTEGER NOT NULL,
                    FOREIGN KEY(job_id) REFERENCES outbox_jobs(job_id)
                );
                CREATE TABLE IF NOT EXISTS outbox_acks (
                    job_id TEXT PRIMARY KEY, status TEXT NOT NULL, acknowledgment_bytes BLOB NOT NULL,
                    acknowledgment_digest BLOB NOT NULL, operation_id BLOB NOT NULL UNIQUE, acknowledged_ms INTEGER NOT NULL,
                    qualification_receipt BLOB NOT NULL, profile_digest BLOB NOT NULL, acknowledgment_id TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS outbox_transitions (
                    sequence INTEGER PRIMARY KEY, transition_kind TEXT NOT NULL, job_id TEXT NOT NULL,
                    before_root BLOB NOT NULL, after_root BLOB NOT NULL, event_bytes BLOB NOT NULL,
                    event_digest BLOB NOT NULL UNIQUE
                );
                CREATE TABLE IF NOT EXISTS reconciliation_records (
                    job_id TEXT PRIMARY KEY, operation_id BLOB NOT NULL UNIQUE, envelope_digest BLOB NOT NULL UNIQUE,
                    idempotency_key BLOB NOT NULL UNIQUE, status TEXT NOT NULL, attempt INTEGER NOT NULL,
                    worker_id TEXT, token BLOB, leased_ms INTEGER, expires_ms INTEGER,
                    next_eligible_ms INTEGER NOT NULL, created_ms INTEGER NOT NULL, updated_ms INTEGER NOT NULL,
                    last_error_code TEXT
                );
                CREATE TRIGGER IF NOT EXISTS composition_metadata_no_delete BEFORE DELETE ON composition_metadata BEGIN SELECT RAISE(ABORT,'composition_metadata_immutable'); END;
                CREATE TRIGGER IF NOT EXISTS composition_state_no_delete BEFORE DELETE ON composition_state BEGIN SELECT RAISE(ABORT,'composition_state_immutable'); END;
                CREATE TRIGGER IF NOT EXISTS composition_transitions_no_update BEFORE UPDATE ON composition_transitions BEGIN SELECT RAISE(ABORT,'composition_transitions_append_only'); END;
                CREATE TRIGGER IF NOT EXISTS composition_transitions_no_delete BEFORE DELETE ON composition_transitions BEGIN SELECT RAISE(ABORT,'composition_transitions_append_only'); END;
                CREATE TRIGGER IF NOT EXISTS proof_requests_no_update BEFORE UPDATE ON proof_requests BEGIN SELECT RAISE(ABORT,'proof_requests_append_only'); END;
                CREATE TRIGGER IF NOT EXISTS proof_requests_no_delete BEFORE DELETE ON proof_requests BEGIN SELECT RAISE(ABORT,'proof_requests_append_only'); END;
                CREATE TRIGGER IF NOT EXISTS proof_audit_no_update BEFORE UPDATE ON proof_audit BEGIN SELECT RAISE(ABORT,'proof_audit_append_only'); END;
                CREATE TRIGGER IF NOT EXISTS proof_audit_no_delete BEFORE DELETE ON proof_audit BEGIN SELECT RAISE(ABORT,'proof_audit_append_only'); END;
                CREATE TRIGGER IF NOT EXISTS proof_transitions_no_update BEFORE UPDATE ON proof_transitions BEGIN SELECT RAISE(ABORT,'proof_transitions_append_only'); END;
                CREATE TRIGGER IF NOT EXISTS proof_transitions_no_delete BEFORE DELETE ON proof_transitions BEGIN SELECT RAISE(ABORT,'proof_transitions_append_only'); END;
                CREATE TRIGGER IF NOT EXISTS dispositions_no_update BEFORE UPDATE ON application_dispositions BEGIN SELECT RAISE(ABORT,'dispositions_append_only'); END;
                CREATE TRIGGER IF NOT EXISTS dispositions_no_delete BEFORE DELETE ON application_dispositions BEGIN SELECT RAISE(ABORT,'dispositions_append_only'); END;
                CREATE TRIGGER IF NOT EXISTS outbox_transitions_no_update BEFORE UPDATE ON outbox_transitions BEGIN SELECT RAISE(ABORT,'outbox_transitions_append_only'); END;
                CREATE TRIGGER IF NOT EXISTS outbox_transitions_no_delete BEFORE DELETE ON outbox_transitions BEGIN SELECT RAISE(ABORT,'outbox_transitions_append_only'); END;
                """
            )
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute("SELECT * FROM composition_metadata WHERE id=1").fetchone()
                if row is None:
                    head = _sha(_GENESIS, self.config.composition_id.encode("ascii"), self.config.digest)
                    connection.execute(
                        "INSERT INTO composition_metadata VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (1, _SCHEMA_VERSION, self.config.composition_id, self.config.canonical_bytes, self.config.digest,
                         self.config.queue_id, self.config.queue_config_digest, self.config.verifier_sha256,
                         self.config.state_profile_identity, self.config.receiver_identity, self.config.receiver_epoch,
                         self.config.verifier_epoch, self.config.profile_digest, self.config.expected_statement,
                         None, 0, 0, head, 0),
                    )
                else:
                    self._check_meta(row)
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def _check_meta(self, row: tuple[Any, ...]) -> tuple[Any, ...]:
        if len(row) != 19 or int(row[1]) != _SCHEMA_VERSION or str(row[2]) != self.config.composition_id:
            raise CompositionIntegrityError("composition_schema")
        expected = (
            bytes(row[3]) == self.config.canonical_bytes, bytes(row[4]) == self.config.digest,
            str(row[5]) == self.config.queue_id, bytes(row[6]) == self.config.queue_config_digest,
            bytes(row[7]) == self.config.verifier_sha256, bytes(row[9]) == self.config.receiver_identity,
            int(row[10]) == self.config.receiver_epoch, int(row[11]) == self.config.verifier_epoch,
            bytes(row[12]) == self.config.profile_digest,
        )
        if not all(expected) or row[14] is not None or int(row[15]) != 0 or int(row[16]) != 0:
            raise CompositionIntegrityError("composition_config_drift")
        if self.config.state_profile_identity is not None and row[8] is not None and bytes(row[8]) != self.config.state_profile_identity:
            raise CompositionIntegrityError("state_profile_drift")
        if self.config.expected_statement is not None and row[13] is not None and bytes(row[13]) != self.config.expected_statement:
            raise CompositionIntegrityError("expected_statement_drift")
        return tuple(row)

    def _meta(self, connection: sqlite3.Connection) -> tuple[Any, ...]:
        row = connection.execute("SELECT * FROM composition_metadata WHERE id=1").fetchone()
        if row is None:
            raise CompositionIntegrityError("composition_metadata_missing")
        return self._check_meta(tuple(row))

    def _append_composition_transition(self, connection: sqlite3.Connection, *, kind: str, job_id: str, event: Mapping[str, Any]) -> None:
        kind = _token(kind, "transition_kind")
        meta = self._meta(connection)
        sequence = int(meta[18]) + 1
        before = bytes(meta[17])
        event_bytes = _json_bytes(event)
        digest = _sha(_EVENT, kind.encode("ascii"), job_id.encode("ascii"), event_bytes)
        after = _sha(_HEAD, before, _u64(sequence), digest)
        connection.execute("INSERT INTO composition_transitions VALUES (?,?,?,?,?,?,?)", (sequence, kind, job_id, before, after, event_bytes, digest))
        # The unified head records only composition-level dispositions.  Proof
        # and outbox chains remain explicit in their own tables.
        connection.execute("UPDATE composition_metadata SET head_root=?,next_sequence=? WHERE id=1", (after, sequence))

    def _state(self, connection: sqlite3.Connection) -> tuple[Any, ...]:
        row = connection.execute("SELECT * FROM composition_state WHERE id=1").fetchone()
        if row is None:
            raise CompositionIntegrityError("state_missing")
        if len(row) != 17:
            raise CompositionIntegrityError("state_shape")
        return tuple(row)

    def _ensure_state(self, connection: sqlite3.Connection, acceptance: Any) -> tuple[Any, ...]:
        row = connection.execute("SELECT * FROM composition_state WHERE id=1").fetchone()
        if row is not None:
            state = tuple(row)
            expected = bytes(state[1])
            if expected != bytes(acceptance.statement.statement_bytes):
                # The expected statement is immutable.  This is a deterministic
                # held disposition, not an attempt to overwrite state.
                return state
            return state
        statement = acceptance.statement
        if self.config.expected_statement is not None and bytes(statement.statement_bytes) != self.config.expected_statement:
            return tuple()
        profile = _profile_digest(statement, self.config.verifier_sha256)
        identity = _state_store_identity(statement, self.config.verifier_sha256)
        if self.config.state_profile_identity is not None and identity != self.config.state_profile_identity:
            return tuple()
        before_continuity = bytes(statement.state("before_continuity_root"))
        before_audit = bytes(statement.state("before_audit_head"))
        clearance = _sha(_STATE_GENESIS, statement.state_before_id, _INITIAL_CLEARANCE)
        replay = _sha(_STATE_GENESIS, statement.attempt_id, statement.request_id)
        binding = _sha(
            _STATE_BINDING, statement.statement_bytes, statement.state_before_id,
            _u64(statement.epoch), _u64(statement.sequence_before), before_continuity,
            clearance, replay, _INITIAL_PAYMENT, _u64(0), self.config.verifier_sha256, profile,
        )
        connection.execute(
            "INSERT INTO composition_state VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (1, statement.statement_bytes, acceptance.circuit_id, statement.state_before_id, statement.epoch,
             statement.sequence_before, before_continuity, clearance, int(statement.state("clearance_count_before")),
             replay, _INITIAL_PAYMENT, 0, binding, before_audit, None, self.config.verifier_sha256, profile),
        )
        if self.config.state_profile_identity is None:
            connection.execute("UPDATE composition_metadata SET state_profile_identity=?,expected_statement=? WHERE id=1", (identity, statement.statement_bytes))
        return self._state(connection)

    def _validate_queue_result(self, verified: IndependentVerifiedQueueJob) -> Any:
        if (
            verified.queue_id != self.config.queue_id or verified.config_digest != self.config.queue_config_digest
            or verified.verifier_sha256 != self.config.verifier_sha256 or verified.cap_bytes != _CAP_BYTES
            or verified.cap_enforced is not True or verified.active_process_limit != _ACTIVE_PROCESS_LIMIT
            or verified.timed_out is not False or verified.exit_code != 0 or verified.peak_job_commit_bytes > _CAP_BYTES
        ):
            raise CompositionIntegrityError("queue_binding")
        try:
            acceptance = parse_acceptance_bytes(verified.acceptance_bytes)
        except Exception:
            _raise_fixed(CompositionIntegrityError, "acceptance_parse")
        if (
            acceptance.canonical_bytes() != verified.acceptance_bytes
            or acceptance.artifact_bytes != verified.artifact_bytes
            or acceptance.artifact_sha256 != verified.artifact_sha256
            or acceptance.artifact_digest != verified.artifact_sha3_512
            or acceptance.circuit_id != verified.circuit_id
        ):
            raise CompositionIntegrityError("acceptance_binding")
        return acceptance

    @staticmethod
    def _queue_view_bytes(verified: IndependentVerifiedQueueJob) -> bytes:
        # The queue receipt contains stable stdout/stderr digests used only by
        # queue custody.  They are deliberately not copied across the
        # clearance boundary; retain only typed identities and containment
        # facts that this composition contract actually consumes.
        return _json_bytes({
            "schema": _QUEUE_VIEW_SCHEMA, "queue_id": verified.queue_id,
            "config_digest": _hex(verified.config_digest), "verifier_sha256": _hex(verified.verifier_sha256),
            "job_id": verified.job_id, "operation_id": _hex(verified.operation_id), "attempt": verified.attempt,
            "artifact_bytes": verified.artifact_bytes, "artifact_sha256": _hex(verified.artifact_sha256),
            "artifact_sha3_512": _hex(verified.artifact_sha3_512), "circuit_id": _hex(verified.circuit_id),
            "peak_job_commit_bytes": verified.peak_job_commit_bytes, "cap_bytes": verified.cap_bytes,
            "cap_enforced": verified.cap_enforced, "active_process_limit": verified.active_process_limit,
            "timed_out": verified.timed_out, "exit_code": verified.exit_code,
        })

    def _result_from_disposition(self, row: tuple[Any, ...], *, duplicate: bool | None = None) -> CompositionProcessResultV2:
        raw = None if row[6] is None else bytes(row[6])
        digest = None if row[7] is None else bytes(row[7])
        outbox = None
        outrow = None
        with closing(self._connect()) as connection:
            outrow = connection.execute("SELECT job_id,operation_id FROM outbox_jobs WHERE disposition_id=?", (bytes(row[0]),)).fetchone()
        if outrow is not None:
            outbox = str(outrow[0])
            out_operation = bytes(outrow[1])
        else:
            out_operation = None
        return CompositionProcessResultV2(str(row[1]), bytes(row[2]), str(row[5]), bytes(row[0]), raw, digest, outbox, out_operation, bool(row[8]) if duplicate is None else duplicate, None if row[9] is None else str(row[9]))

    @_public_v2_api
    def process_verified_job(self, queue_database: Path, job_id: str) -> CompositionProcessResultV2:
        """Read VERIFIED queue state independently, then commit composition once."""
        _token(job_id, "job_id")
        try:
            verified = read_verified_job(queue_database, job_id)
        except (IndependentQueueError, OSError, sqlite3.Error):
            _raise_fixed(CompositionIntegrityError, "queue_verification_failed")
        acceptance = self._validate_queue_result(verified)
        encoded = bytes(verified.acceptance_bytes)
        queue_view = self._queue_view_bytes(verified)
        queue_view_digest = _sha(_MATERIAL, b"queue-view", queue_view)
        acceptance_digest = _sha(_MATERIAL, b"acceptance", encoded)
        now = int(self.clock.now_ms())
        with closing(self._connect()) as connection:
            began = False
            try:
                connection.execute("BEGIN IMMEDIATE")
                began = True
                self._meta(connection)
                existing = connection.execute("SELECT * FROM application_dispositions WHERE queue_job_id=?", (job_id,)).fetchone()
                if existing is not None:
                    if bytes(existing[2]) != verified.operation_id or bytes(existing[4]) != acceptance_digest:
                        raise CompositionConflictError("composition_conflicting_retry")
                    proof = connection.execute(
                        "SELECT operation_digest,queue_view_digest,queue_view_bytes,acceptance_bytes FROM proof_requests WHERE queue_job_id=?",
                        (job_id,),
                    ).fetchone()
                    if str(existing[5]) == "APPLIED":
                        if proof is None or bytes(proof[0]) != bytes(existing[3]) or bytes(proof[1]) != queue_view_digest or bytes(proof[2]) != queue_view or bytes(proof[3]) != encoded:
                            raise CompositionIntegrityError("composition_retry_history")
                    elif proof is not None:
                        raise CompositionIntegrityError("composition_retry_history")
                    connection.execute("COMMIT")
                    began = False
                    return self._result_from_disposition(tuple(existing), duplicate=True)
                state = self._ensure_state(connection, acceptance)
                if not state:
                    disposition_id = _sha(_MATERIAL, b"held", job_id.encode("ascii"), verified.operation_id, encoded)
                    connection.execute("INSERT INTO application_dispositions VALUES (?,?,?,?,?,?,?,?,?,?,?)", (disposition_id, job_id, verified.operation_id, disposition_id, acceptance_digest, "HELD", None, None, 0, "state_profile_mismatch", now))
                    self._append_composition_transition(connection, kind="HELD", job_id=job_id, event={"status": "HELD", "error_code": "state_profile_mismatch", "at_ms": now})
                    connection.execute("COMMIT")
                    began = False
                    return CompositionProcessResultV2(job_id, verified.operation_id, "HELD", disposition_id, None, None, None, None, False, "state_profile_mismatch")
                state = self._state(connection)
                operation_digest = _sha(_STATE_OPERATION, encoded, bytes(state[12]), bytes(state[13]), bytes(state[10]), self.config.verifier_sha256)
                conflicting = connection.execute("SELECT operation_digest,acceptance_bytes FROM proof_requests WHERE operation_digest=? OR artifact_digest=? OR request_id=? OR attempt_id=? OR queue_job_id=?", (operation_digest, acceptance.artifact_digest, acceptance.statement.request_id, acceptance.statement.attempt_id, job_id)).fetchall()
                if conflicting:
                    if len(conflicting) != 1 or bytes(conflicting[0][1]) != encoded:
                        raise CompositionConflictError("composition_conflicting_retry")
                    existing = connection.execute("SELECT * FROM application_dispositions WHERE queue_job_id=?", (job_id,)).fetchone()
                    if existing is not None:
                        connection.execute("COMMIT")
                        began = False
                        return self._result_from_disposition(tuple(existing), duplicate=True)
                    raise CompositionConflictError("proof_disposition_missing")
                if (
                    bytes(state[3]) != acceptance.statement.state_before_id or int(state[4]) != acceptance.statement.epoch
                    or int(state[5]) != acceptance.statement.sequence_before
                    or bytes(state[6]) != bytes(acceptance.statement.state("before_continuity_root"))
                    or bytes(state[13]) != bytes(acceptance.statement.state("before_audit_head"))
                    or int(state[8]) != int(acceptance.statement.state("clearance_count_before"))
                    or bytes(state[10]) != _INITIAL_PAYMENT or int(state[11]) != 0
                ):
                    disposition_id = _sha(_MATERIAL, b"held", job_id.encode("ascii"), verified.operation_id, encoded)
                    connection.execute("INSERT INTO application_dispositions VALUES (?,?,?,?,?,?,?,?,?,?,?)", (disposition_id, job_id, verified.operation_id, operation_digest, acceptance_digest, "HELD", None, None, 0, "stale_or_conflicting_state", now))
                    self._append_composition_transition(connection, kind="HELD", job_id=job_id, event={"status": "HELD", "error_code": "stale_or_conflicting_state", "at_ms": now})
                    connection.execute("COMMIT")
                    began = False
                    return CompositionProcessResultV2(job_id, verified.operation_id, "HELD", disposition_id, None, None, None, None, False, "stale_or_conflicting_state")
                statement = acceptance.statement
                sequence_before = int(state[5])
                sequence_after = sequence_before + 1
                replay_after = _sha(_STATE_REPLAY, bytes(state[9]), statement.attempt_id, statement.request_id, statement.receipt_id)
                advanced = statement.directive in (1, 5)
                clearance_after = _sha(_STATE_CLEARANCE, bytes(state[7]), statement.state_after_id, statement.decision_id, bytes((statement.directive,))) if advanced else bytes(state[7])
                count_after = int(state[8]) + int(advanced)
                profile = bytes(state[16])
                binding_after = _sha(_STATE_BINDING, bytes(state[12]), operation_digest, statement.state_after_id, replay_after, clearance_after, _u64(count_after), bytes(state[10]), _u64(0), _u64(int(state[4])), _u64(sequence_after), self.config.verifier_sha256, profile)
                payload = _json_bytes({
                    "event_kind": "MINIMAL_COMPOSITION_PROOF_CLEARANCE_V2", "version": 2,
                    "sequence_before": sequence_before, "sequence_after": sequence_after,
                    "operation_digest": _hex(operation_digest), "queue_job_id": job_id,
                    "queue_operation_id": _hex(verified.operation_id), "queue_view_digest": _hex(queue_view_digest),
                    "acceptance_digest": _hex(acceptance_digest), "artifact_digest": _hex(acceptance.artifact_digest),
                    "receipt_id": _hex(statement.receipt_id), "request_id": _hex(statement.request_id),
                    "attempt_id": _hex(statement.attempt_id), "decision_id": _hex(statement.decision_id),
                    "policy_result": acceptance.policy_result, "effective_directive": statement.directive,
                    "clearance_advanced": int(advanced), "state_binding_before": _hex(bytes(state[12])),
                    "state_binding_after": _hex(binding_after), "payment_root_unchanged": True,
                })
                event_commitment = _sha(_STATE_AUDIT_EVENT, bytes(state[13]), payload)
                audit_after = _sha(_STATE_AUDIT_HEAD, bytes(state[13]), event_commitment)
                receipt = _state_receipt(operation_digest=operation_digest, acceptance=acceptance, sequence_before=sequence_before, sequence_after=sequence_after, state_before_id=bytes(state[3]), state_after_id=statement.state_after_id, clearance_before=bytes(state[7]), clearance_after=clearance_after, count_before=int(state[8]), count_after=count_after, binding_after=binding_after, audit_after=audit_after)
                receipt_raw = _json_bytes(receipt)
                receipt_digest = _receipt_digest(receipt_raw)
                # Capacity is checked inside the same lock before any state
                # rows are inserted.  A full outbox rolls the whole transaction.
                active = int(connection.execute("SELECT COUNT(*) FROM outbox_jobs WHERE status IN ('DISCOVERED','LEASED','DELIVERY_UNCONFIRMED')").fetchone()[0])
                if active >= self.config.capacity:
                    raise CompositionBackpressureError("outbox_capacity")
                disposition_id = _sha(_MATERIAL, b"disposition", job_id.encode("ascii"), verified.operation_id, acceptance_digest)
                envelope = build_directive_envelope(config=self.config, job_id=job_id, operation_id=verified.operation_id, disposition_digest=disposition_id, state_store_identity=_state_store_identity(statement, self.config.verifier_sha256), receipt=_receipt_values(receipt))
                env_digest = _sha(_ENVELOPE, envelope)
                outbox_operation = _operation_identity(self.config, job_id, env_digest)
                idem = _idempotency_key(self.config, job_id, env_digest)
                connection.execute("INSERT INTO proof_requests VALUES (" + ",".join("?" for _ in range(27)) + ")", (operation_digest, job_id, verified.operation_id, queue_view, queue_view_digest, encoded, acceptance_digest, receipt_raw, acceptance.artifact_digest, statement.request_id, statement.attempt_id, statement.decision_id, sequence_before, sequence_after, bytes(state[3]), statement.state_after_id, bytes(state[7]), clearance_after, int(state[8]), count_after, bytes(state[12]), binding_after, bytes(state[13]), audit_after, acceptance.policy_result, statement.directive, now))
                connection.execute("UPDATE composition_state SET state_id=?,sequence=?,continuity_root=?,clearance_root=?,clearance_count=?,replay_root=?,state_binding=?,audit_head=?,last_operation_digest=? WHERE id=1", (statement.state_after_id, sequence_after, bytes(statement.state("after_continuity_root")), clearance_after, count_after, replay_after, binding_after, audit_after, operation_digest))
                connection.execute("INSERT INTO proof_audit VALUES (?,?,?,?,?)", (sequence_after, bytes(state[13]), event_commitment, audit_after, payload))
                connection.execute("INSERT INTO proof_transitions VALUES (" + ",".join("?" for _ in range(8)) + ")", (sequence_after, operation_digest, bytes(state[12]), binding_after, bytes(state[10]), bytes(state[10]), 0, 0))
                connection.execute("INSERT INTO application_dispositions VALUES (?,?,?,?,?,?,?,?,?,?,?)", (disposition_id, job_id, verified.operation_id, operation_digest, acceptance_digest, "APPLIED", receipt_raw, receipt_digest, 0, None, now))
                connection.execute("INSERT INTO outbox_jobs VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", (job_id, outbox_operation, disposition_id, envelope, env_digest, idem, "DISCOVERED", 0, now, now, now, None))
                self._append_composition_transition(connection, kind="APPLIED", job_id=job_id, event={"status": "APPLIED", "operation_digest": _hex(operation_digest), "outbox_operation_id": _hex(outbox_operation), "at_ms": now})
                self._fault("before_composition_commit")
                connection.execute("COMMIT")
                began = False
            except Exception:
                if began and connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        try:
            self._after_fault("after_composition_commit")
        except Exception:
            _raise_fixed(CompositionIndeterminateError, "composition_commit_indeterminate")
        return CompositionProcessResultV2(job_id, verified.operation_id, "APPLIED", disposition_id, receipt_raw, receipt_digest, job_id, outbox_operation, False, None)

    process = process_verified_job
    apply_verified_job = process_verified_job

    def _recover_expired_leases(self, connection: sqlite3.Connection, now: int) -> None:
        rows = connection.execute("SELECT job_id,worker_id,token,attempt,expires_ms FROM outbox_leases WHERE expires_ms<=?", (now,)).fetchall()
        for job_id, worker_id, token, attempt, expires in rows:
            connection.execute("DELETE FROM outbox_leases WHERE job_id=?", (job_id,))
            status = "DELIVERY_UNCONFIRMED" if int(attempt) >= 1 else "DISCOVERED"
            connection.execute("UPDATE outbox_jobs SET status=?,next_eligible_ms=?,updated_ms=?,last_error_code=? WHERE job_id=? AND status='LEASED'", (status, now, now, "lease_expired", job_id))
            if status == "DELIVERY_UNCONFIRMED":
                self._ensure_reconciliation_locked(connection, str(job_id), now, "lease_expired")

    @_public_v2_api
    def claim_next_outbox(self, worker_id: str) -> CompositionOutboxWorkV2 | None:
        _token(worker_id, "worker_id")
        now = int(self.clock.now_ms())
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                self._meta(connection)
                self._recover_expired_leases(connection, now)
                row = connection.execute("SELECT * FROM outbox_jobs WHERE status IN ('DISCOVERED','DELIVERY_UNCONFIRMED') AND next_eligible_ms<=? ORDER BY created_ms,job_id LIMIT 1", (now,)).fetchone()
                if row is None:
                    connection.execute("COMMIT")
                    return None
                attempt = int(row[7]) + 1
                if attempt > self.config.max_attempts:
                    connection.execute("UPDATE outbox_jobs SET next_eligible_ms=?,updated_ms=?,last_error_code=? WHERE job_id=?", (now + self.config.lease_seconds * 1000, now, "dispatch_attempts_exhausted", row[0]))
                    connection.execute("COMMIT")
                    return None
                token = secrets.token_bytes(24)
                expires = now + self.config.lease_seconds * 1000
                connection.execute("UPDATE outbox_jobs SET status='LEASED',attempt=?,updated_ms=? WHERE job_id=? AND status IN ('DISCOVERED','DELIVERY_UNCONFIRMED')", (attempt, now, row[0]))
                connection.execute("INSERT OR REPLACE INTO outbox_leases VALUES (?,?,?,?,?,?)", (row[0], worker_id, token, attempt, now, expires))
                self._append_outbox_transition(connection, kind="LEASED", job_id=str(row[0]), event={"status": "LEASED", "attempt": attempt, "at_ms": now})
                connection.execute("COMMIT")
                return CompositionOutboxWorkV2(self.config.composition_id, str(row[0]), bytes(row[1]), attempt, worker_id, token, expires, bytes(row[3]), bytes(row[5]))
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    claim_next = claim_next_outbox

    def _append_outbox_transition(self, connection: sqlite3.Connection, *, kind: str, job_id: str, event: Mapping[str, Any]) -> None:
        meta = self._meta(connection)
        seq = int(connection.execute("SELECT COALESCE(MAX(sequence),0)+1 FROM outbox_transitions").fetchone()[0])
        before = bytes(meta[17])
        event_bytes = _json_bytes(event)
        digest = _sha(_EVENT, kind.encode("ascii"), job_id.encode("ascii"), event_bytes)
        after = _sha(_HEAD, before, _u64(seq), digest)
        connection.execute("INSERT INTO outbox_transitions VALUES (?,?,?,?,?,?,?)", (seq, kind, job_id, before, after, event_bytes, digest))

    def _live_outbox_lease(self, connection: sqlite3.Connection, work: CompositionOutboxWorkV2) -> tuple[Any, ...]:
        row = connection.execute(
            "SELECT l.*,o.operation_id,o.envelope_bytes,o.idempotency_key FROM outbox_leases l JOIN outbox_jobs o ON o.job_id=l.job_id WHERE l.job_id=?",
            (work.job_id,),
        ).fetchone()
        now = int(self.clock.now_ms())
        if (
            work.composition_id != self.config.composition_id
            or row is None
            or str(row[1]) != work.worker_id
            or bytes(row[2]) != work.lease_token
            or int(row[3]) != work.attempt
            or int(row[5]) != work.lease_expires_ms
            or bytes(row[6]) != work.operation_id
            or bytes(row[7]) != work.envelope_bytes
            or bytes(row[8]) != work.idempotency_key
            or now >= int(row[5])
        ):
            raise CompositionLeaseError("outbox_lease_stale")
        return tuple(row)

    def _existing_ack(self, job_id: str) -> CompositionDeliveryResultV2 | None:
        with closing(self._connect()) as connection:
            row = connection.execute("SELECT o.operation_id,a.acknowledgment_bytes,a.acknowledgment_digest,a.qualification_receipt,a.profile_digest,a.acknowledgment_id FROM outbox_jobs o JOIN outbox_acks a ON a.job_id=o.job_id WHERE o.job_id=?", (job_id,)).fetchone()
        if row is None:
            return None
        return CompositionDeliveryResultV2(job_id, bytes(row[0]), "ACKNOWLEDGED", bytes(row[1]), bytes(row[2]), None, bytes(row[3]), bytes(row[4]), str(row[5]))

    def _ensure_reconciliation_locked(self, connection: sqlite3.Connection, job_id: str, now: int, code: str) -> None:
        row = connection.execute("SELECT 1 FROM reconciliation_records WHERE job_id=?", (job_id,)).fetchone()
        if row is not None:
            return
        outbox = connection.execute("SELECT operation_id,envelope_digest,idempotency_key FROM outbox_jobs WHERE job_id=?", (job_id,)).fetchone()
        if outbox is None:
            raise CompositionIntegrityError("reconciliation_outbox_missing")
        active = int(connection.execute("SELECT COUNT(*) FROM reconciliation_records WHERE status IN ('DISCOVERED','LEASED')").fetchone()[0])
        status = "DISCOVERED" if active < self.config.reconciliation_capacity else "EXHAUSTED"
        connection.execute("INSERT INTO reconciliation_records VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (job_id, bytes(outbox[0]), bytes(outbox[1]), bytes(outbox[2]), status, 0, None, None, None, None, now, now, now, code))
        self._append_outbox_transition(connection, kind="RECONCILIATION_DISCOVERED", job_id=job_id, event={"status": "DELIVERY_UNCONFIRMED", "reconciliation_status": status, "at_ms": now})

    def _mark_delivery_unconfirmed(self, work: CompositionOutboxWorkV2, code: str) -> CompositionDeliveryResultV2:
        now = int(self.clock.now_ms())
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                self._live_outbox_lease(connection, work)
                connection.execute("DELETE FROM outbox_leases WHERE job_id=?", (work.job_id,))
                changed = connection.execute("UPDATE outbox_jobs SET status='DELIVERY_UNCONFIRMED',updated_ms=?,next_eligible_ms=?,last_error_code=? WHERE job_id=? AND status='LEASED'", (now, now, _code(code), work.job_id))
                if changed.rowcount != 1:
                    existing = self._existing_ack(work.job_id)
                    if existing is not None:
                        connection.execute("ROLLBACK")
                        return existing
                    raise CompositionIndeterminateError("delivery_status_cas")
                self._ensure_reconciliation_locked(connection, work.job_id, now, _code(code))
                self._append_outbox_transition(connection, kind="DELIVERY_UNCONFIRMED", job_id=work.job_id, event={"status": "DELIVERY_UNCONFIRMED", "attempt": work.attempt, "error_code": _code(code), "at_ms": now})
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return CompositionDeliveryResultV2(work.job_id, work.operation_id, "DELIVERY_UNCONFIRMED", None, None, _code(code))

    def _qualification_receipt(self, *, ack_raw: bytes, envelope: Mapping[str, Any], operation_id: bytes, job_id: str, idem: bytes) -> bytes:
        ack = _parse_ack(ack_raw)
        ack_digest = _sha(_ACK, ack_raw)
        env_digest = _sha(_ENVELOPE, _json_bytes(envelope))
        value = {
            "schema_version": 2, "mode": _ACK_MODE, "profile_digest": _hex(self.config.profile_digest),
            "verifier_identity": _hex(self.config.verifier_sha256), "verifier_epoch": self.config.verifier_epoch,
            "receiver_identity": _hex(self.config.receiver_identity), "receiver_epoch": self.config.receiver_epoch,
            "operation_id": _hex(operation_id), "job_id_digest": _hex(_sha(_ACK_RECEIPT, job_id.encode("ascii"))),
            "idempotency_key": _hex(idem), "envelope_digest": _hex(env_digest), "ack_digest": _hex(ack_digest),
            "acknowledgment_id": str(ack["acknowledgment_id"]), "policy_result": int(envelope["policy_result"]),
            "effective_directive": int(envelope["effective_directive"]), "proof_suite_id": None,
            "production_usable": False, "activation": False,
        }
        return _json_bytes(value)

    def _validate_ack(self, raw: bytes, *, envelope_bytes: bytes, operation_id: bytes, job_id: str, expected_idem: bytes) -> tuple[dict[str, Any], bytes, bytes, bytes]:
        ack = _parse_ack(raw)
        envelope = _parse_envelope(envelope_bytes)
        env_digest = _sha(_ENVELOPE, envelope_bytes)
        ack_digest = _sha(_ACK, raw)
        if (
            bytes.fromhex(str(ack["receiver_identity"])) != self.config.receiver_identity
            or int(ack["receiver_epoch"]) != self.config.receiver_epoch
            or bytes.fromhex(str(ack["idempotency_key"])) != expected_idem
            or bytes.fromhex(str(ack["envelope_digest"])) != env_digest
            or int(ack["effective_directive"]) != int(envelope["effective_directive"])
            or bytes.fromhex(str(envelope["composition_config_digest"])) != self.config.digest
            or bytes.fromhex(str(envelope["receiver_identity"])) != self.config.receiver_identity
            or int(envelope["receiver_epoch"]) != self.config.receiver_epoch
            or int(envelope["verifier_epoch"]) != self.config.verifier_epoch
            or bytes.fromhex(str(envelope["ack_evidence_profile_digest"])) != self.config.profile_digest
            or bytes.fromhex(str(envelope["job_id_digest"])) != _sha(_ENVELOPE, job_id.encode("ascii"))
        ):
            raise CompositionIntegrityError("ack_binding")
        if "policy_result" in ack and int(ack["policy_result"]) != int(envelope["policy_result"]):
            raise CompositionIntegrityError("ack_policy_binding")
        receipt = self._qualification_receipt(ack_raw=raw, envelope=envelope, operation_id=operation_id, job_id=job_id, idem=expected_idem)
        return ack, env_digest, ack_digest, receipt

    def _commit_ack(self, *, job_id: str, operation_id: bytes, ack_raw: bytes, expected_idem: bytes, mode: str, dispatch_work: CompositionOutboxWorkV2 | None = None, reconciliation_work: CompositionReconciliationWorkV2 | None = None) -> CompositionDeliveryResultV2:
        with closing(self._connect()) as connection:
            row = connection.execute("SELECT o.operation_id,o.envelope_bytes,o.idempotency_key,d.queue_operation_id FROM outbox_jobs o JOIN application_dispositions d ON d.disposition_id=o.disposition_id WHERE o.job_id=?", (job_id,)).fetchone()
        if row is None:
            raise CompositionIntegrityError("outbox_job_missing")
        if bytes(row[0]) != operation_id:
            raise CompositionIntegrityError("ack_outbox_operation_binding")
        envelope_bytes = bytes(row[1])
        if bytes.fromhex(str(_parse_envelope(envelope_bytes)["operation_id"])) != bytes(row[3]):
            raise CompositionIntegrityError("ack_historical_operation_binding")
        ack, env_digest, ack_digest, qualification = self._validate_ack(ack_raw, envelope_bytes=envelope_bytes, operation_id=operation_id, job_id=job_id, expected_idem=bytes(row[2]))
        now = int(self.clock.now_ms())
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                if mode == "DISPATCH":
                    if dispatch_work is None:
                        raise CompositionLeaseError("dispatch_work_missing")
                    self._live_outbox_lease(connection, dispatch_work)
                    required = "LEASED"
                elif mode == "RECONCILIATION":
                    if reconciliation_work is None:
                        raise CompositionLeaseError("reconciliation_work_missing")
                    self._live_reconciliation_lease(connection, reconciliation_work)
                    required = "DELIVERY_UNCONFIRMED"
                else:
                    raise CompositionIntegrityError("ack_mode")
                current = connection.execute("SELECT status FROM outbox_jobs WHERE job_id=?", (job_id,)).fetchone()
                if current is None or str(current[0]) != required:
                    existing = connection.execute("SELECT acknowledgment_bytes,acknowledgment_digest,qualification_receipt,profile_digest,acknowledgment_id FROM outbox_acks WHERE job_id=?", (job_id,)).fetchone()
                    if existing is not None:
                        connection.execute("ROLLBACK")
                        return CompositionDeliveryResultV2(job_id, operation_id, "ACKNOWLEDGED", bytes(existing[0]), bytes(existing[1]), None, bytes(existing[2]), bytes(existing[3]), str(existing[4]))
                    raise CompositionIndeterminateError("ack_status_indeterminate")
                connection.execute("DELETE FROM outbox_leases WHERE job_id=?", (job_id,))
                changed = connection.execute("UPDATE outbox_jobs SET status='ACKNOWLEDGED',updated_ms=?,last_error_code=NULL WHERE job_id=? AND status=?", (now, job_id, required))
                if changed.rowcount != 1:
                    raise CompositionIndeterminateError("ack_status_cas")
                connection.execute("INSERT INTO outbox_acks VALUES (?,?,?,?,?,?,?,?,?)", (job_id, "ACKNOWLEDGED", ack_raw, ack_digest, operation_id, now, qualification, self.config.profile_digest, str(ack["acknowledgment_id"])))
                connection.execute("UPDATE reconciliation_records SET status='ACKNOWLEDGED',worker_id=NULL,token=NULL,leased_ms=NULL,expires_ms=NULL,updated_ms=?,last_error_code=NULL WHERE job_id=? AND status IN ('DISCOVERED','LEASED')", (now, job_id))
                self._append_outbox_transition(connection, kind="ACKNOWLEDGED_BY_RECONCILIATION" if reconciliation_work is not None else "ACKNOWLEDGED", job_id=job_id, event={"status": "ACKNOWLEDGED", "mode": mode, "ack_digest": _hex(ack_digest), "acknowledgment_id": str(ack["acknowledgment_id"]), "effective_directive": int(ack["effective_directive"]), "policy_result": int(_parse_envelope(envelope_bytes)["policy_result"]), "profile_digest": _hex(self.config.profile_digest), "at_ms": now})
                self._fault("before_ack_commit")
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        try:
            self._after_fault("after_reconciliation_commit" if reconciliation_work is not None else "after_ack_commit")
        except Exception:
            _raise_fixed(CompositionIndeterminateError, "ack_commit_indeterminate")
        return CompositionDeliveryResultV2(job_id, operation_id, "ACKNOWLEDGED", ack_raw, ack_digest, None, qualification, self.config.profile_digest, str(ack["acknowledgment_id"]))

    @_public_v2_api
    def dispatch(self, work: CompositionOutboxWorkV2, *, receiver: OfficialStateReceiverPort) -> CompositionDeliveryResultV2:
        existing = self._existing_ack(work.job_id)
        if existing is not None:
            return existing
        with closing(self._connect()) as connection:
            self._live_outbox_lease(connection, work)
        called = False
        try:
            if receiver.identity_sha256() != self.config.receiver_identity or receiver.epoch() != self.config.receiver_epoch:
                return self._mark_delivery_unconfirmed(work, "receiver_identity_drift")
            called = True
            ack_raw = receiver.dispatch(work.envelope_bytes, work.idempotency_key)
            if type(ack_raw) is not bytes:
                return self._mark_delivery_unconfirmed(work, "delivery_indeterminate")
            self._fault("after_dispatch_before_ack_commit")
            return self._commit_ack(job_id=work.job_id, operation_id=work.operation_id, ack_raw=ack_raw, expected_idem=work.idempotency_key, mode="DISPATCH", dispatch_work=work)
        except CompositionIndeterminateError:
            if called:
                try:
                    self._mark_delivery_unconfirmed(work, "delivery_indeterminate")
                except CompositionLeaseError:
                    existing = self._existing_ack(work.job_id)
                    if existing is not None:
                        return existing
            raise
        except CompositionLeaseError:
            existing = self._existing_ack(work.job_id)
            if existing is not None:
                return existing
            raise
        except Exception:
            try:
                return self._mark_delivery_unconfirmed(work, "delivery_indeterminate")
            except CompositionLeaseError:
                existing = self._existing_ack(work.job_id)
                if existing is not None:
                    return existing
                _raise_fixed(CompositionIndeterminateError, "delivery_indeterminate")

    send = dispatch

    def _live_reconciliation_lease(self, connection: sqlite3.Connection, work: CompositionReconciliationWorkV2) -> tuple[Any, ...]:
        row = connection.execute("SELECT * FROM reconciliation_records WHERE job_id=?", (work.job_id,)).fetchone()
        now = int(self.clock.now_ms())
        if (
            work.composition_id != self.config.composition_id
            or row is None
            or str(row[4]) != "LEASED"
            or str(row[6]) != work.worker_id
            or bytes(row[7]) != work.lease_token
            or int(row[5]) != work.attempt
            or int(row[9]) != work.lease_expires_ms
            or bytes(row[1]) != work.operation_id
            or bytes(row[2]) != work.envelope_digest
            or bytes(row[3]) != work.idempotency_key
            or now >= int(row[9])
        ):
            raise CompositionLeaseError("reconciliation_lease_stale")
        return tuple(row)

    def _recover_reconciliation(self, connection: sqlite3.Connection, now: int) -> None:
        rows = connection.execute("SELECT job_id,attempt FROM reconciliation_records WHERE status='LEASED' AND expires_ms<=?", (now,)).fetchall()
        for job_id, attempt in rows:
            next_status = "DISCOVERED" if int(attempt) < self.config.max_attempts else "EXHAUSTED"
            connection.execute("UPDATE reconciliation_records SET status=?,worker_id=NULL,token=NULL,leased_ms=NULL,expires_ms=NULL,next_eligible_ms=?,updated_ms=?,last_error_code=? WHERE job_id=? AND status='LEASED'", (next_status, now, now, "reconciliation_lease_expired", job_id))

    @_public_v2_api
    def claim_reconciliation_next(self, worker_id: str) -> CompositionReconciliationWorkV2 | None:
        _token(worker_id, "worker_id")
        now = int(self.clock.now_ms())
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                self._meta(connection)
                self._recover_reconciliation(connection, now)
                row = connection.execute("SELECT r.* FROM reconciliation_records r JOIN outbox_jobs o ON o.job_id=r.job_id WHERE r.status='DISCOVERED' AND o.status='DELIVERY_UNCONFIRMED' AND r.next_eligible_ms<=? ORDER BY r.created_ms,r.job_id LIMIT 1", (now,)).fetchone()
                if row is None:
                    connection.execute("COMMIT")
                    return None
                attempt = int(row[5]) + 1
                if attempt > self.config.max_attempts:
                    connection.execute("UPDATE reconciliation_records SET status='EXHAUSTED',updated_ms=?,last_error_code=? WHERE job_id=?", (now, "reconciliation_attempts_exhausted", row[0]))
                    connection.execute("COMMIT")
                    return None
                token = secrets.token_bytes(24)
                expires = now + self.config.reconciliation_lease_seconds * 1000
                connection.execute("UPDATE reconciliation_records SET status='LEASED',attempt=?,worker_id=?,token=?,leased_ms=?,expires_ms=?,updated_ms=? WHERE job_id=? AND status='DISCOVERED'", (attempt, worker_id, token, now, expires, now, row[0]))
                connection.execute("COMMIT")
                return CompositionReconciliationWorkV2(self.config.composition_id, str(row[0]), bytes(row[1]), attempt, worker_id, token, expires, bytes(row[2]), bytes(row[3]))
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    claim_reconciliation = claim_reconciliation_next

    @staticmethod
    def _lookup(lookup: OfficialStateReceiverLookupPort, query: CompositionLookupQueryV2) -> bytes | None:
        method = getattr(lookup, "lookup_acknowledgment", None) or getattr(lookup, "lookup", None) or getattr(lookup, "lookup_ack", None) or getattr(lookup, "find_acknowledgment", None)
        if method is None:
            raise CompositionIndeterminateError("reconciliation_lookup_unavailable")
        try:
            parameters = tuple(inspect.signature(method).parameters.values())
        except (TypeError, ValueError):
            return method(receiver_identity=query.receiver_identity, receiver_epoch=query.receiver_epoch, job_id=query.job_id, operation_id=query.operation_id, idempotency_key=query.idempotency_key, envelope_digest=query.envelope_digest)
        names = {parameter.name for parameter in parameters}
        expected = {"receiver_identity", "receiver_epoch", "job_id", "operation_id", "idempotency_key", "envelope_digest"}
        if any(parameter.kind is inspect.Parameter.VAR_KEYWORD for parameter in parameters) or expected.issubset(names):
            return method(receiver_identity=query.receiver_identity, receiver_epoch=query.receiver_epoch, job_id=query.job_id, operation_id=query.operation_id, idempotency_key=query.idempotency_key, envelope_digest=query.envelope_digest)
        if len(parameters) == 1:
            return method(query)
        return method(query.receiver_identity, query.receiver_epoch, query.job_id, query.operation_id, query.idempotency_key, query.envelope_digest)

    def _release_reconciliation(self, work: CompositionReconciliationWorkV2, code: str) -> CompositionDeliveryResultV2:
        now = int(self.clock.now_ms())
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                self._live_reconciliation_lease(connection, work)
                next_status = "DISCOVERED" if work.attempt < self.config.max_attempts else "EXHAUSTED"
                connection.execute("UPDATE reconciliation_records SET status=?,worker_id=NULL,token=NULL,leased_ms=NULL,expires_ms=NULL,next_eligible_ms=?,updated_ms=?,last_error_code=? WHERE job_id=? AND status='LEASED'", (next_status, now, now, _code(code), work.job_id))
                connection.execute("UPDATE outbox_jobs SET status='DELIVERY_UNCONFIRMED',updated_ms=?,last_error_code=? WHERE job_id=? AND status='DELIVERY_UNCONFIRMED'", (now, _code(code), work.job_id))
                self._append_outbox_transition(connection, kind="RECONCILIATION_INDETERMINATE", job_id=work.job_id, event={"status": "DELIVERY_UNCONFIRMED", "attempt": work.attempt, "error_code": _code(code), "at_ms": now})
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return CompositionDeliveryResultV2(work.job_id, work.operation_id, "DELIVERY_UNCONFIRMED", None, None, _code(code))

    @_public_v2_api
    def reconcile(self, work: CompositionReconciliationWorkV2, *, lookup: OfficialStateReceiverLookupPort | None = None, lookup_port: OfficialStateReceiverLookupPort | None = None, evidence_profile: SyntheticAckEvidenceProfileV2 | None = None) -> CompositionDeliveryResultV2:
        existing = self._existing_ack(work.job_id)
        if existing is not None:
            return existing
        with closing(self._connect()) as connection:
            self._live_reconciliation_lease(connection, work)
        if lookup is None:
            lookup = lookup_port
        if lookup is None:
            return self._release_reconciliation(work, "reconciliation_indeterminate")
        if evidence_profile is not None and evidence_profile != self.config.acknowledgment_profile:
            return self._release_reconciliation(work, "reconciliation_indeterminate")
        provider = getattr(lookup, "acknowledgment_profile", None) or getattr(lookup, "profile", None)
        if provider is not None:
            try:
                candidate = provider() if callable(provider) else provider
            except Exception:
                return self._release_reconciliation(work, "reconciliation_indeterminate")
            if candidate != self.config.acknowledgment_profile:
                return self._release_reconciliation(work, "reconciliation_indeterminate")
        try:
            raw = self._lookup(lookup, CompositionLookupQueryV2(self.config.receiver_identity, self.config.receiver_epoch, work.job_id, work.operation_id, work.idempotency_key, work.envelope_digest))
            if raw is None or type(raw) is not bytes:
                return self._release_reconciliation(work, "reconciliation_indeterminate")
            return self._commit_ack(job_id=work.job_id, operation_id=work.operation_id, ack_raw=raw, expected_idem=work.idempotency_key, mode="RECONCILIATION", reconciliation_work=work)
        except (CompositionIntegrityError, CompositionIndeterminateError):
            existing = self._existing_ack(work.job_id)
            if existing is not None:
                return existing
            return self._release_reconciliation(work, "reconciliation_indeterminate")
        except CompositionLeaseError:
            existing = self._existing_ack(work.job_id)
            if existing is not None:
                return existing
            raise
        except Exception:
            return self._release_reconciliation(work, "reconciliation_indeterminate")

    reconcile_delivery = reconcile
    reconcile_unconfirmed = reconcile

    @_public_v2_api
    def reconcile_next(self, worker_id: str, *, lookup: OfficialStateReceiverLookupPort | None = None, lookup_port: OfficialStateReceiverLookupPort | None = None, evidence_profile: SyntheticAckEvidenceProfileV2 | None = None) -> CompositionDeliveryResultV2 | None:
        work = self.claim_reconciliation_next(worker_id)
        if work is None:
            return None
        return self.reconcile(work, lookup=lookup, lookup_port=lookup_port, evidence_profile=evidence_profile)

    reconcile_next_delivery = reconcile_next

    @_public_v2_api
    def snapshot(self) -> dict[str, Any]:
        with closing(self._connect()) as connection:
            meta = self._meta(connection)
            disposition_counts = {status: int(connection.execute("SELECT COUNT(*) FROM application_dispositions WHERE status=?", (status,)).fetchone()[0]) for status in ("APPLIED", "HELD")}
            outbox_counts = {status: int(connection.execute("SELECT COUNT(*) FROM outbox_jobs WHERE status=?", (status,)).fetchone()[0]) for status in sorted(_STATUSES)}
            recon_counts = {status: int(connection.execute("SELECT COUNT(*) FROM reconciliation_records WHERE status=?", (status,)).fetchone()[0]) for status in sorted(_RECON_STATUSES)}
            return {"schema": _SCHEMA, "composition_id": self.config.composition_id, "head_root": _hex(bytes(meta[17])), "transition_count": int(meta[18]), "disposition_counts": disposition_counts, "outbox_counts": outbox_counts, "reconciliation_counts": recon_counts, "proof_suite_id": None, "production_usable": False, "activation": False}

    support_summary = snapshot

    @_public_v2_api
    def export_bytes(self) -> bytes:
        self.verify_integrity()
        with closing(self._connect()) as connection:
            meta = self._meta(connection)
            names = ("composition_state", "composition_transitions", "proof_requests", "proof_audit", "proof_transitions", "application_dispositions", "outbox_jobs", "outbox_leases", "outbox_acks", "outbox_transitions", "reconciliation_records")
            tables: dict[str, list[list[Any]]] = {}
            for name in names:
                tables[name] = [[_hex(x) if isinstance(x, bytes) else x for x in row] for row in connection.execute(f"SELECT * FROM {name} ORDER BY rowid").fetchall()]
            value = {"schema": _SCHEMA, "config": self.config.as_json, "metadata": [_hex(x) if isinstance(x, bytes) else x for x in meta], "tables": tables}
        raw = _json_bytes(value)
        if len(raw) > _MAX_EXPORT:
            raise CompositionIntegrityError("export_bounds")
        return raw

    @_public_v2_api
    def verify_integrity(self) -> None:
        from app.minimal_clearance_composition_independent import verify_database
        verify_database(self.path, expected_config=self.config.as_json)

    @_public_v2_api
    def restore_from_export(self, path: Path, raw: bytes) -> dict[str, Any]:
        from app.minimal_clearance_composition_independent import restore_export_to_fresh_database
        return restore_export_to_fresh_database(path, raw, expected_config=self.config.as_json)

    @_public_v2_api
    def create_backup(self, destination: Path) -> None:
        if not isinstance(destination, Path) or destination.exists() or not destination.parent.is_dir() or destination == self.path:
            raise CompositionError("backup_destination")
        self.verify_integrity()
        with closing(self._connect()) as source, closing(sqlite3.connect(destination)) as target:
            source.backup(target)
            target.commit()
        from app.minimal_clearance_composition_independent import verify_database
        verify_database(destination, expected_config=self.config.as_json)

    @_public_v2_api
    def recover_from_backup(self, *, backup_path: Path, recovered_path: Path) -> "ClearanceCompositionStoreV2":
        if (
            not isinstance(backup_path, Path) or not backup_path.is_file() or
            not isinstance(recovered_path, Path) or recovered_path.exists() or
            not recovered_path.parent.is_dir() or backup_path == recovered_path
        ):
            raise CompositionError("backup_recovery_path")
        from app.minimal_clearance_composition_independent import verify_database
        verify_database(backup_path, expected_config=self.config.as_json)
        with closing(sqlite3.connect(backup_path)) as source, closing(sqlite3.connect(recovered_path)) as target:
            source.backup(target)
            target.commit()
        verify_database(recovered_path, expected_config=self.config.as_json)
        return type(self)(path=recovered_path, config=self.config, clock=self.clock)

    restore_from_backup = recover_from_backup

    def close(self) -> None:
        return None


MinimalClearanceCompositionConfigV2 = CompositionConfigV2
MinimalClearanceCompositionStoreV2 = ClearanceCompositionStoreV2
MinimalClearanceCompositionDispatcherV2 = ClearanceCompositionStoreV2
OfficialAckEvidenceProfileV2 = SyntheticAckEvidenceProfileV2


__all__ = (
    "CompositionBackpressureError", "CompositionClock", "CompositionConfigV2", "CompositionConflictError",
    "CompositionDeliveryResultV2", "CompositionError", "CompositionIndeterminateError", "CompositionIntegrityError",
    "CompositionLeaseError", "CompositionLookupQueryV2", "CompositionOutboxWorkV2", "CompositionProcessResultV2",
    "CompositionReconciliationWorkV2", "ClearanceCompositionStoreV2",
    "MinimalClearanceCompositionConfigV2", "MinimalClearanceCompositionStoreV2", "MinimalClearanceCompositionDispatcherV2",
    "OfficialAckEvidenceProfileV2", "OfficialStateReceiverLookupPort", "OfficialStateReceiverPort",
    "SyntheticAckEvidenceProfileV2", "acknowledgment_digest", "build_directive_envelope", "build_synthetic_acknowledgment",
    "envelope_digest", "parse_acknowledgment_bytes", "parse_envelope_bytes",
)
