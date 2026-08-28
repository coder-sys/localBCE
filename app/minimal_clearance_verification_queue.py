"""Queue V9: one state-owned handoff for exactly one Range100 proof.

The queue owns only the public batch statement, the volatile handoff, one
lease, one 101-opportunity theorem-relevant proof-attempt reservation, and a
bounded receipt.
It never parses proof bytes, constructs a proof transcript, stores proof or
source material, or chooses a clearance disposition.
"""

from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
from typing import Any, BinaryIO, Callable, Final, Mapping, NoReturn, Protocol

from app.minimal_clearance_resource_limits import (
    ACTIVE_PROCESS_LIMIT,
    ADMISSION_CAP_BYTES,
    PROCESS_TREE_PEAK_CAP_BYTES,
)


class VerificationQueueError(RuntimeError):
    pass


class QueueConflictError(VerificationQueueError):
    pass


class QueueBackpressureError(VerificationQueueError):
    pass


class QueueIntegrityError(VerificationQueueError):
    pass


class QueueLeaseError(VerificationQueueError):
    pass


class QueueRetryableError(VerificationQueueError):
    pass


class QueueDeterministicRejectError(VerificationQueueError):
    pass


class QueueHeldError(VerificationQueueError):
    pass


class QueueIndeterminateError(VerificationQueueError):
    pass


def _raise_fixed(error: VerificationQueueError) -> NoReturn:
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    raise error


SCHEMA_VERSION: Final[int] = 10
_SCHEMA: Final[str] = "BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/v10"
MAX_QUEUE_CAPACITY: Final[int] = 512
DATABASE_PAGE_SIZE: Final[int] = 4096
DATABASE_MAX_PAGE_COUNT: Final[int] = 32768
MAX_QUEUE_DATABASE_BYTES: Final[int] = DATABASE_PAGE_SIZE * DATABASE_MAX_PAGE_COUNT
MAX_TERMINAL_GROWTH_PER_NONTERMINAL: Final[int] = 256
MAX_RECEIPT_BYTES: Final[int] = 16 * 1024
MAX_OPERATION_REF_BYTES: Final[int] = 32
MAX_BATCH_ROOT_BYTES: Final[int] = 64
MAX_STATE_CHALLENGE_BYTES: Final[int] = 32
MAX_ORDERED_BINDING_BYTES: Final[int] = 32
PROOF_STATEMENT_BYTES: Final[int] = 240
RANGE100_COUNT: Final[int] = 100
PROOF_ATTEMPTS_PER_BATCH: Final[int] = 101
PROOF_ATTEMPTS_CAP: Final[int] = 2**32
MAX_VALIDITY_WINDOW_MS: Final[int] = 3_600_000
MAX_SOURCE_KEY_EPOCH: Final[int] = 2**64 - 1
DIRECTIVES: Final[tuple[str, ...]] = (
    "CLEAR", "HOLD", "HUMAN_REVIEW", "BLOCK", "EXCEPTION_APPROVED",
)
BOOTSTRAP_CAPABILITY_LIMITATION_COUNT: Final[int] = 0

PROFILE_VERSION: Final[int] = 4
RELATION_VERSION: Final[int] = 1
POLICY_VERSION: Final[int] = 1
PROFILE_VERSION_TOKEN: Final[str] = "BLIND-ZKBPP-CUNRUH-RANGE100-V4"
SOURCE_AUTH_PROFILE_DEFAULT: Final[str] = "synthetic-source-auth-v9-unqualified"
STATEMENT_MAGIC: Final[bytes] = b"BL-R100-STMT-V1\x00"
# Opaque registered identifiers.  The queue has no proof parser, transcript,
# or proof-internal fingerprint construction.
CIRCUIT_FINGERPRINT: Final[bytes] = bytes.fromhex(
    "982cbb064e424c3734b09a4e8579338092fd3b71d7ae81f7a64174d9ba8919f6"
    "c1fcc3b7c0837d64dc1cec954194e1648f3375bfe7f08a8a9347aa320137efd4"
)
PROFILE_FINGERPRINT: Final[bytes] = bytes.fromhex(
    "8ed47d3fd17bb3a332adf8dd5d8facb97be23cb430e2e582cb360d383577d706"
    "e88d2a568a78772e89292201fc273a958ac1263280be1662b7ec64830347822a"
)


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        _raise_fixed(QueueIntegrityError("json"))


def _sha3(domain: bytes, *parts: bytes) -> bytes:
    digest = hashlib.sha3_512()
    digest.update(domain)
    for part in parts:
        if type(part) is not bytes:
            _raise_fixed(QueueIntegrityError("binding_type"))
        digest.update(part)
    return digest.digest()


def _hex(value: bytes) -> str:
    return value.hex().upper()


def _blob(value: object, size: int, code: str) -> bytes:
    if type(value) is not bytes or len(value) != size:
        _raise_fixed(QueueIntegrityError(code))
    return value


_SAFE_TOKEN = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
_SAFE_CODE = re.compile(r"[a-z][a-z0-9_]{0,95}\Z")
_FORBIDDEN_CODE_WORDS: Final[tuple[str, ...]] = (
    "provider", "patient", "member", "claim", "identity", "digest", "path",
    "log", "stdout", "stderr", "credential", "secret",
)
# Every code that can cross a queue/runtime/database result boundary is
# explicitly registered.  Free text is never persisted.
_ALLOWED_CODES: Final[frozenset[str]] = frozenset({
    "accepted", "rejected", "proof_or_source_not_accepted",
    "fresh_handoff_required", "validity_expired", "lease_expired",
    "verifier_timeout", "verifier_transport", "verifier_stream_not_consumed",
    "verifier_result_mismatch", "verifier_result_unknown_field",
    "verifier_result_shape", "verifier_result_flags", "verifier_key_epoch",
    "verifier_result_code", "proof_handoff_stream", "proof_handoff_length",
    "proof_handoff_oversize", "proof_handoff_empty", "proof_handoff_closed",
    "proof_handoff_bytes", "batch_binding", "batch_unknown", "queue_capacity",
    "computational_budget_exhausted", "queue_database_bounds", "queue_schema_unsupported",
    "queue_profile_mismatch", "queue_config_encoding", "queue_config_binding",
    "queue_integrity_failed", "startup_recovery", "runtime_startup",
    "completion_not_live", "completion_lease_fence", "completion_status",
    "completion_acceptance", "batch_required", "queue_closed", "runtime_closed",
    "runtime_owner", "runtime_scope", "runtime_already_owned", "runtime_configuration",
    "queue_parent", "queue_owner_required", "queue_configuration", "queue_integer",
    "queue_batch_shape", "queue_batch_order", "queue_batch_requires_100",
    "batch_window_mismatch", "source_key_epoch", "queue_profile_invalid",
    "queue_profile_epoch", "queue_profile_version", "queue_capacity_invalid",
    "qualification_flags_invalid", "validity_window_invalid", "validity_window_too_long",
    "queue_randomness",
    "template_shape", "assertion_identifier_invalid", "assertion_identifier_forbidden",
    "assertion_version_invalid", "state_profile_version_invalid", "state_profile_version_forbidden",
    "source_registry_root", "qualification_flag_invalid", "batch_position_invalid",
    "batch_root", "batch_statement", "batch_identity", "statement_binding",
    "statement_length", "statement_window", "state_challenge", "ordered_binding",
    "admission_seq", "attempt_missing", "attempt_status", "attempt_chain",
    "proof_attempt_ledger", "receipt_cap", "receipt_bounds", "receipt_encoding",
    "receipt_keys", "receipt_flags", "receipt_acceptance", "receipt_batch_id",
    "receipt_statement", "receipt_root", "receipt_source_profile", "receipt_source_epoch",
    "receipt_result_code", "receipt_error", "flags_bounds", "flags_encoding",
    "flags_shape", "event_fields", "event_bounds", "handoff_not_consumed",
    "runtime_backend_unqualified", "runtime_result", "runtime_max_batches",
    "state_disposition", "state_disposition_shape", "state_control_set", "state_control_shape", "composition_schema", "proof_session_active",
})


def _token(value: object, label: str, maximum: int = 128) -> str:
    if type(value) is not str or not 1 <= len(value) <= maximum or _SAFE_TOKEN.fullmatch(value) is None:
        _raise_fixed(VerificationQueueError(f"{label}_invalid"))
    if any(word in value.lower() for word in _FORBIDDEN_CODE_WORDS):
        _raise_fixed(VerificationQueueError(f"{label}_forbidden"))
    return value


def _code(value: object, label: str = "queue_error") -> str:
    if type(value) is not str or _SAFE_CODE.fullmatch(value) is None or value not in _ALLOWED_CODES or any(word in value.lower() for word in _FORBIDDEN_CODE_WORDS):
        _raise_fixed(QueueIntegrityError(label))
    return value


def _u64(value: int) -> bytes:
    if type(value) is not int or not 0 <= value < 2**64:
        _raise_fixed(QueueIntegrityError("queue_integer"))
    return value.to_bytes(8, "big")


def _u64le(value: int) -> bytes:
    if type(value) is not int or not 0 <= value < 2**64:
        _raise_fixed(QueueIntegrityError("queue_integer"))
    return value.to_bytes(8, "little")


def _reserve_proof_attempt(used: int, *, cap: int = PROOF_ATTEMPTS_CAP) -> int:
    if type(used) is not int or used < 0 or type(cap) is not int or not 0 < cap <= PROOF_ATTEMPTS_CAP:
        _raise_fixed(QueueIntegrityError("proof_attempt_ledger"))
    after = used + PROOF_ATTEMPTS_PER_BATCH
    if after > cap:
        _raise_fixed(QueueBackpressureError("computational_budget_exhausted"))
    return after


def _template_value_check(template: "OperationTemplate") -> None:
    if type(template) is not OperationTemplate:
        _raise_fixed(VerificationQueueError("template_shape"))
    _token(template.assertion_identifier, "assertion_identifier", 96)
    if type(template.assertion_version) is not int or not 1 <= template.assertion_version <= 2**31:
        _raise_fixed(VerificationQueueError("assertion_version_invalid"))
    _token(template.state_profile_version, "state_profile_version", 96)
    if type(template.valid_from_ms) is not int or type(template.valid_until_ms) is not int or not 0 <= template.valid_from_ms < template.valid_until_ms:
        _raise_fixed(VerificationQueueError("validity_window_invalid"))
    if template.valid_until_ms - template.valid_from_ms > MAX_VALIDITY_WINDOW_MS:
        _raise_fixed(VerificationQueueError("validity_window_too_long"))
    if template.approved_source_registry_root is not None:
        _blob(template.approved_source_registry_root, 64, "source_registry_root")
    if type(template.qualification_flags) is not tuple or len(template.qualification_flags) > 32 or tuple(sorted(template.qualification_flags)) != template.qualification_flags or len(set(template.qualification_flags)) != len(template.qualification_flags):
        _raise_fixed(VerificationQueueError("qualification_flags_invalid"))
    for flag in template.qualification_flags:
        _token(flag, "qualification_flag", 96)


@dataclass(frozen=True, slots=True)
class QueueConfig:
    """Immutable state-owned V9 queue configuration."""

    queue_id: str
    capacity: int
    profile_digest: bytes | None = None
    profile_epoch: int = PROFILE_VERSION
    profile_version: str = PROFILE_VERSION_TOKEN
    source_auth_profile: str = SOURCE_AUTH_PROFILE_DEFAULT
    source_key_epoch: int = 1
    qualification_flags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _token(self.queue_id, "queue_id", 96)
        if type(self.capacity) is not int or not 100 <= self.capacity <= MAX_QUEUE_CAPACITY:
            _raise_fixed(VerificationQueueError("queue_capacity_invalid"))
        if type(self.profile_epoch) is not int or self.profile_epoch != PROFILE_VERSION:
            _raise_fixed(VerificationQueueError("queue_profile_epoch"))
        if self.profile_version != PROFILE_VERSION_TOKEN:
            _raise_fixed(VerificationQueueError("queue_profile_version"))
        _token(self.source_auth_profile, "source_auth_profile", 96)
        if type(self.source_key_epoch) is not int or not 1 <= self.source_key_epoch <= MAX_SOURCE_KEY_EPOCH:
            _raise_fixed(VerificationQueueError("source_key_epoch"))
        if type(self.qualification_flags) is not tuple or len(self.qualification_flags) > 32 or tuple(sorted(self.qualification_flags)) != self.qualification_flags or len(set(self.qualification_flags)) != len(self.qualification_flags):
            _raise_fixed(VerificationQueueError("qualification_flags_invalid"))
        for flag in self.qualification_flags:
            _token(flag, "qualification_flag", 96)
        if self.profile_digest is None:
            object.__setattr__(self, "profile_digest", PROFILE_FINGERPRINT)
        elif self.profile_digest != PROFILE_FINGERPRINT:
            _raise_fixed(VerificationQueueError("queue_profile_invalid"))

    @property
    def lease_seconds(self) -> int:
        return 60

    @property
    def max_attempts(self) -> int:
        return 1

    @property
    def retryable_codes(self) -> tuple[str, ...]:
        return ("fresh_handoff_required", "verifier_timeout", "verifier_transport")

    @property
    def as_json(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "handoff_protocol": "BATCH_ISSUE_THEN_HANDOFF_V1",
            "queue_id": self.queue_id,
            "capacity": self.capacity,
            "admission_cap_bytes": ADMISSION_CAP_BYTES,
            "process_tree_peak_cap_bytes": PROCESS_TREE_PEAK_CAP_BYTES,
            "active_process_limit": ACTIVE_PROCESS_LIMIT,
            "database_page_size": DATABASE_PAGE_SIZE,
            "database_max_page_count": DATABASE_MAX_PAGE_COUNT,
            "database_journal_mode": "delete",
            "database_synchronous": 2,
            "proof_attempts_cap": PROOF_ATTEMPTS_CAP,
            "profile_version": self.profile_version,
            "profile_digest": _hex(self.profile_digest or PROFILE_FINGERPRINT),
            "profile_epoch": self.profile_epoch,
            "source_auth_profile": self.source_auth_profile,
            "source_key_epoch": self.source_key_epoch,
            "qualification_flags": list(self.qualification_flags),
            "directives": list(DIRECTIVES),
            "proof_suite_id": None,
            "production_usable": False,
            "activation": False,
        }

    @property
    def canonical_bytes(self) -> bytes:
        return _json_bytes(self.as_json)

    @property
    def digest(self) -> bytes:
        return _sha3(b"BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/MATERIAL/v9\x00", self.canonical_bytes)


@dataclass(frozen=True, slots=True)
class OperationTemplate:
    """One shared allowlisted public statement template for all 100 members."""

    assertion_identifier: str
    assertion_version: int
    state_profile_version: str
    valid_from_ms: int
    valid_until_ms: int
    approved_source_registry_root: bytes | None = None
    qualification_flags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _template_value_check(self)

    @property
    def as_json(self) -> dict[str, Any]:
        return {
            "assertion_identifier": self.assertion_identifier,
            "assertion_version": self.assertion_version,
            "state_profile_version": self.state_profile_version,
            "valid_from_ms": self.valid_from_ms,
            "valid_until_ms": self.valid_until_ms,
            "approved_source_registry_root": None if self.approved_source_registry_root is None else _hex(self.approved_source_registry_root),
            "qualification_flags": list(self.qualification_flags),
        }

    @property
    def canonical_bytes(self) -> bytes:
        return _json_bytes(self.as_json)


@dataclass(frozen=True, slots=True)
class IssuedOperationStatement:
    """A reconstructed public candidate; it is not a durable queue row."""

    operation_ref: bytes
    assertion_identifier: str
    assertion_version: int
    state_profile_version: str
    valid_from_ms: int
    valid_until_ms: int
    batch_position: int
    batch_root: bytes
    approved_source_registry_root: bytes | None = None
    qualification_flags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _blob(self.operation_ref, MAX_OPERATION_REF_BYTES, "operation_ref")
        _template_value_check(OperationTemplate(self.assertion_identifier, self.assertion_version, self.state_profile_version, self.valid_from_ms, self.valid_until_ms, self.approved_source_registry_root, self.qualification_flags))
        if type(self.batch_position) is not int or not 0 <= self.batch_position < RANGE100_COUNT:
            _raise_fixed(VerificationQueueError("batch_position_invalid"))
        _blob(self.batch_root, MAX_BATCH_ROOT_BYTES, "batch_root")

    @property
    def template(self) -> OperationTemplate:
        return OperationTemplate(self.assertion_identifier, self.assertion_version, self.state_profile_version, self.valid_from_ms, self.valid_until_ms, self.approved_source_registry_root, self.qualification_flags)

    @property
    def as_json(self) -> dict[str, Any]:
        return {"operation_ref": _hex(self.operation_ref), **self.template.as_json, "batch_position": self.batch_position, "batch_root": _hex(self.batch_root)}

    @property
    def canonical_bytes(self) -> bytes:
        return _json_bytes(self.as_json)


def _batch_leaf(position: int, operation_ref: bytes, template: OperationTemplate) -> bytes:
    return _sha3(b"BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/BATCH-LEAF/v9\x00", _u64(position), operation_ref, template.canonical_bytes)


def _compute_batch_root_from_refs(template: OperationTemplate, operation_refs: tuple[bytes, ...]) -> bytes:
    _template_value_check(template)
    if type(operation_refs) is not tuple or len(operation_refs) != RANGE100_COUNT or len(set(operation_refs)) != RANGE100_COUNT:
        _raise_fixed(VerificationQueueError("queue_batch_shape"))
    for ref in operation_refs:
        _blob(ref, MAX_OPERATION_REF_BYTES, "operation_ref")
    leaves = tuple(_batch_leaf(position, ref, template) for position, ref in enumerate(operation_refs))
    return _sha3(b"BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/BATCH-ROOT/v9\x00", _u64(RANGE100_COUNT), b"".join(leaves))


def _compute_batch_root(statements: tuple[IssuedOperationStatement, ...]) -> bytes:
    if type(statements) is not tuple or len(statements) != RANGE100_COUNT or tuple(item.batch_position for item in statements) != tuple(range(RANGE100_COUNT)):
        _raise_fixed(VerificationQueueError("queue_batch_shape"))
    template = statements[0].template
    if any(item.template != template for item in statements):
        _raise_fixed(VerificationQueueError("batch_window_mismatch"))
    return _compute_batch_root_from_refs(template, tuple(item.operation_ref for item in statements))


def _build_statement(*, batch_root: bytes, state_challenge: bytes, valid_from_ms: int, valid_until_ms: int) -> bytes:
    _blob(batch_root, MAX_BATCH_ROOT_BYTES, "batch_root")
    _blob(state_challenge, MAX_STATE_CHALLENGE_BYTES, "state_challenge")
    if type(valid_from_ms) is not int or type(valid_until_ms) is not int or not 0 <= valid_from_ms < valid_until_ms or valid_until_ms - valid_from_ms > MAX_VALIDITY_WINDOW_MS:
        _raise_fixed(QueueIntegrityError("statement_window"))
    statement = (
        STATEMENT_MAGIC + (1).to_bytes(2, "little") + PROOF_STATEMENT_BYTES.to_bytes(2, "little")
        + state_challenge + batch_root[:MAX_ORDERED_BINDING_BYTES]
        + PROFILE_VERSION.to_bytes(4, "little") + RELATION_VERSION.to_bytes(4, "little") + POLICY_VERSION.to_bytes(4, "little")
        + _u64le(valid_from_ms) + _u64le(valid_until_ms) + CIRCUIT_FINGERPRINT + PROFILE_FINGERPRINT
    )
    if len(statement) != PROOF_STATEMENT_BYTES:
        _raise_fixed(QueueIntegrityError("statement_length"))
    return statement


@dataclass(frozen=True, slots=True)
class IssuedVerificationBatch:
    """Complete immutable state-issued batch with one shared template."""

    batch_id: bytes
    template: OperationTemplate
    operation_refs: tuple[bytes, ...]
    batch_root: bytes
    state_challenge: bytes
    ordered_binding: bytes
    proof_statement: bytes
    admission_seq: int
    identity_digest: bytes

    def __post_init__(self) -> None:
        _blob(self.batch_id, 32, "batch_id")
        _template_value_check(self.template)
        if type(self.operation_refs) is not tuple or len(self.operation_refs) != RANGE100_COUNT or len(set(self.operation_refs)) != RANGE100_COUNT:
            _raise_fixed(VerificationQueueError("queue_batch_shape"))
        for ref in self.operation_refs:
            _blob(ref, MAX_OPERATION_REF_BYTES, "operation_ref")
        _blob(self.batch_root, MAX_BATCH_ROOT_BYTES, "batch_root")
        _blob(self.state_challenge, MAX_STATE_CHALLENGE_BYTES, "state_challenge")
        _blob(self.ordered_binding, MAX_ORDERED_BINDING_BYTES, "ordered_binding")
        _blob(self.proof_statement, PROOF_STATEMENT_BYTES, "proof_statement")
        _blob(self.identity_digest, 64, "batch_identity")
        if _compute_batch_root_from_refs(self.template, self.operation_refs) != self.batch_root:
            _raise_fixed(VerificationQueueError("batch_root"))
        expected = _build_statement(batch_root=self.batch_root, state_challenge=self.state_challenge, valid_from_ms=self.template.valid_from_ms, valid_until_ms=self.template.valid_until_ms)
        if self.ordered_binding != self.batch_root[:32] or self.proof_statement != expected or self.proof_statement[52:84] != self.ordered_binding:
            _raise_fixed(VerificationQueueError("statement_binding"))
        if type(self.admission_seq) is not int or self.admission_seq < 1:
            _raise_fixed(VerificationQueueError("admission_seq"))

    @property
    def statements(self) -> tuple[IssuedOperationStatement, ...]:
        return tuple(IssuedOperationStatement(ref, self.template.assertion_identifier, self.template.assertion_version, self.template.state_profile_version, self.template.valid_from_ms, self.template.valid_until_ms, position, self.batch_root, self.template.approved_source_registry_root, self.template.qualification_flags) for position, ref in enumerate(self.operation_refs))

    @property
    def batch_id_hex(self) -> str:
        return _hex(self.batch_id)


def _batch_identity_digest(batch: IssuedVerificationBatch, config: QueueConfig) -> bytes:
    ordered_refs = b"".join(_u64(position) + ref for position, ref in enumerate(batch.operation_refs))
    return _sha3(
        b"BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/BATCH-IDENTITY/v9\x00",
        batch.batch_id, batch.batch_root, batch.state_challenge, batch.proof_statement,
        batch.template.canonical_bytes, _u64(RANGE100_COUNT), ordered_refs,
        _u64(batch.template.valid_from_ms), _u64(batch.template.valid_until_ms),
        config.source_auth_profile.encode("ascii"), _u64(config.source_key_epoch),
    )


def _generate_operation_refs() -> tuple[bytes, ...]:
    refs: list[bytes] = []
    for _ in range(RANGE100_COUNT):
        try:
            operation_ref = secrets.token_bytes(MAX_OPERATION_REF_BYTES)
        except BaseException:
            _raise_fixed(VerificationQueueError("queue_randomness"))
        if type(operation_ref) is not bytes or len(operation_ref) != MAX_OPERATION_REF_BYTES or operation_ref in refs:
            _raise_fixed(VerificationQueueError("queue_randomness"))
        refs.append(operation_ref)
    return tuple(refs)


class VolatileProofHandoff:
    """Single-use readable stream with bounded mutable staging."""

    __slots__ = ("_stream", "declared_length", "_used", "_closed", "_eof", "_total", "_staging")

    def __init__(self, stream: BinaryIO, *, declared_length: int | None = None) -> None:
        if not hasattr(stream, "read") or not callable(stream.read):
            _raise_fixed(QueueHeldError("proof_handoff_stream"))
        if declared_length is not None and (type(declared_length) is not int or declared_length < 0):
            _raise_fixed(QueueHeldError("proof_handoff_length"))
        if declared_length is not None and declared_length > ADMISSION_CAP_BYTES:
            close = getattr(stream, "close", None)
            if callable(close):
                close()
            _raise_fixed(QueueHeldError("proof_handoff_oversize"))
        self._stream = stream
        self.declared_length = declared_length
        self._used = False
        self._closed = False
        self._eof = False
        self._total = 0
        self._staging = bytearray()

    @property
    def total_read(self) -> int:
        return self._total

    @property
    def used(self) -> bool:
        return self._used

    @property
    def consumed(self) -> bool:
        return self._total > 0

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def exhausted(self) -> bool:
        return self._eof

    def _assert_open(self) -> None:
        if self._closed:
            _raise_fixed(QueueHeldError("proof_handoff_closed"))
        self._used = True

    def read(self, size: int = -1) -> bytes:
        self._assert_open()
        if self._eof:
            return b""
        if type(size) is not int:
            _raise_fixed(QueueHeldError("proof_handoff_bytes"))
        if size == 0:
            return b""
        remaining = ADMISSION_CAP_BYTES - self._total
        request = remaining + 1 if size < 0 else min(size, remaining + 1)
        try:
            value = self._stream.read(request)
        except BaseException:
            _raise_fixed(QueueRetryableError("verifier_transport"))
        if type(value) is not bytes:
            _raise_fixed(QueueHeldError("proof_handoff_bytes"))
        if len(value) > remaining:
            _raise_fixed(QueueHeldError("proof_handoff_oversize"))
        if self.declared_length is not None and self._total + len(value) > self.declared_length:
            _raise_fixed(QueueHeldError("proof_handoff_length"))
        if not value:
            self._eof = True
            if self._total == 0:
                _raise_fixed(QueueHeldError("proof_handoff_empty"))
            if self.declared_length is not None and self._total != self.declared_length:
                _raise_fixed(QueueHeldError("proof_handoff_length"))
            return b""
        self._total += len(value)
        retained = value[-64 * 1024:]
        if len(self._staging) + len(retained) > 64 * 1024:
            del self._staging[:len(self._staging) + len(retained) - 64 * 1024]
        self._staging.extend(retained)
        return value

    def drain(self) -> None:
        self._assert_open()
        while not self._eof:
            self.read(min(1 << 20, ADMISSION_CAP_BYTES - self._total + 1))

    def wipe(self) -> None:
        for index in range(len(self._staging)):
            self._staging[index] = 0
        self._staging.clear()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            close = getattr(self._stream, "close", None)
            if callable(close):
                close()
        finally:
            self.wipe()


@dataclass(frozen=True, slots=True)
class VerificationOutcome:
    """Non-dispositive verifier fact passed across the runtime/State seam."""

    proof_accepted: bool
    source_authenticated: bool
    result_code: str
    qualification_flags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if type(self.proof_accepted) is not bool or type(self.source_authenticated) is not bool:
            _raise_fixed(QueueIntegrityError("verifier_result_shape"))
        _code(self.result_code, "verifier_result_code")
        if type(self.qualification_flags) is not tuple or len(self.qualification_flags) > 32 or tuple(sorted(self.qualification_flags)) != self.qualification_flags or len(set(self.qualification_flags)) != len(self.qualification_flags):
            _raise_fixed(QueueIntegrityError("verifier_result_flags"))
        for flag in self.qualification_flags:
            _token(flag, "qualification_flag", 96)


@dataclass(frozen=True, slots=True)
class BatchVerifierResult:
    proof_accepted: bool
    source_authenticated: bool
    proof_statement: bytes
    batch_root: bytes
    source_auth_profile: str
    source_key_epoch: int
    result_code: str
    qualification_flags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if type(self.proof_accepted) is not bool or type(self.source_authenticated) is not bool:
            _raise_fixed(QueueIntegrityError("verifier_result_shape"))
        _blob(self.proof_statement, PROOF_STATEMENT_BYTES, "verifier_statement")
        _blob(self.batch_root, MAX_BATCH_ROOT_BYTES, "verifier_batch_root")
        _token(self.source_auth_profile, "source_auth_profile", 96)
        if type(self.source_key_epoch) is not int or not 1 <= self.source_key_epoch <= MAX_SOURCE_KEY_EPOCH:
            _raise_fixed(QueueIntegrityError("verifier_key_epoch"))
        _code(self.result_code, "verifier_result_code")
        if type(self.qualification_flags) is not tuple or len(self.qualification_flags) > 32 or tuple(sorted(self.qualification_flags)) != self.qualification_flags or len(set(self.qualification_flags)) != len(self.qualification_flags):
            _raise_fixed(QueueIntegrityError("verifier_result_flags"))
        for flag in self.qualification_flags:
            _token(flag, "qualification_flag", 96)

    @property
    def as_json(self) -> dict[str, Any]:
        return {"proof_accepted": self.proof_accepted, "source_authenticated": self.source_authenticated, "proof_statement": _hex(self.proof_statement), "batch_root": _hex(self.batch_root), "source_auth_profile": self.source_auth_profile, "source_key_epoch": self.source_key_epoch, "result_code": self.result_code, "qualification_flags": list(self.qualification_flags)}

    @property
    def non_dispositive_outcome(self) -> VerificationOutcome:
        return VerificationOutcome(self.proof_accepted, self.source_authenticated, self.result_code, self.qualification_flags)


def parse_batch_verifier_result(value: object) -> BatchVerifierResult:
    if isinstance(value, BatchVerifierResult):
        return value
    if type(value) is not dict:
        _raise_fixed(QueueIntegrityError("verifier_result_shape"))
    required = {"proof_accepted", "source_authenticated", "proof_statement", "batch_root", "source_auth_profile", "source_key_epoch", "result_code", "qualification_flags"}
    if set(value) != required:
        _raise_fixed(QueueIntegrityError("verifier_result_unknown_field"))
    if type(value["proof_statement"]) is not bytes or type(value["batch_root"]) is not bytes:
        _raise_fixed(QueueIntegrityError("verifier_result_shape"))
    flags = tuple(value["qualification_flags"]) if type(value["qualification_flags"]) is list else value["qualification_flags"]
    return BatchVerifierResult(value["proof_accepted"], value["source_authenticated"], value["proof_statement"], value["batch_root"], value["source_auth_profile"], value["source_key_epoch"], value["result_code"], flags)


class VerifierPort(Protocol):
    def verify(self, stream: VolatileProofHandoff, issued_batch: IssuedVerificationBatch) -> BatchVerifierResult | Mapping[str, Any]: ...


@dataclass(frozen=True, slots=True)
class QueueResult:
    batch_id: bytes
    status: str
    receipt_bytes: bytes | None
    error_code: str | None
    accepted_count: int = 0


@dataclass(frozen=True, slots=True)
class _QueueWorkItem:
    batch: IssuedVerificationBatch
    attempt: int
    worker_id: str
    claim_sequence: int
    lease_token: bytes
    lease_expires_ms: int


def _owner_process_is_live(pid: int) -> bool:
    """Return live for a confirmed live or ambiguously probeable owner PID."""
    if type(pid) is not int or pid <= 0:
        return False
    if os.name == "nt":
        try:
            import ctypes
            from ctypes import wintypes

            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            ERROR_INVALID_PARAMETER = 87
            STILL_ACTIVE = 259
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
            kernel32.OpenProcess.restype = wintypes.HANDLE
            kernel32.GetExitCodeProcess.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
            kernel32.GetExitCodeProcess.restype = wintypes.BOOL
            kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
            kernel32.CloseHandle.restype = wintypes.BOOL

            handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if not handle:
                return ctypes.get_last_error() != ERROR_INVALID_PARAMETER
            result = True
            try:
                exit_code = wintypes.DWORD()
                if kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                    result = exit_code.value == STILL_ACTIVE
            finally:
                if not kernel32.CloseHandle(handle):
                    result = True
            return result
        except BaseException:
            return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except (PermissionError, OSError):
        return True
    except BaseException:
        return True
    return True


class _QueueRuntimeOwnership:
    """Exclusive process ownership with exact stale-lock recovery."""

    __slots__ = ("_lock_path", "_parent", "_closed", "_pid")

    def __init__(self, *, lock_path: Path, parent: Path) -> None:
        if not isinstance(lock_path, Path) or not isinstance(parent, Path) or not lock_path.is_absolute() or not parent.is_absolute() or not parent.is_dir():
            _raise_fixed(VerificationQueueError("runtime_scope"))
        self._lock_path = lock_path
        self._parent = parent
        self._closed = False
        self._pid = os.getpid()
        self._acquire()

    def _acquire(self) -> None:
        created = False
        fd: int | None = None
        try:
            try:
                fd = os.open(self._lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                created = True
            except FileExistsError:
                stale = False
                try:
                    raw = self._lock_path.read_text(encoding="ascii").strip()
                    pid = int(raw)
                    if pid <= 0:
                        stale = True
                    else:
                        stale = not _owner_process_is_live(pid)
                except (OSError, ValueError):
                    stale = True
                if not stale:
                    _raise_fixed(VerificationQueueError("runtime_already_owned"))
                self._lock_path.unlink()
                fd = os.open(self._lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                created = True
            if fd is None:
                _raise_fixed(VerificationQueueError("runtime_already_owned"))
            os.write(fd, str(self._pid).encode("ascii"))
        except VerificationQueueError:
            if fd is not None:
                os.close(fd)
            if created:
                try:
                    self._lock_path.unlink()
                except OSError:
                    pass
            raise
        except BaseException:
            if fd is not None:
                os.close(fd)
            if created:
                try:
                    self._lock_path.unlink()
                except OSError:
                    pass
            _raise_fixed(VerificationQueueError("runtime_scope"))
        finally:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass

    def assert_scope(self, *, lock_path: Path, parent: Path) -> None:
        if self._closed or lock_path != self._lock_path or parent != self._parent:
            _raise_fixed(VerificationQueueError("runtime_scope"))

    def assert_live(self) -> None:
        if self._closed:
            _raise_fixed(VerificationQueueError("runtime_closed"))

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            if self._lock_path.read_text(encoding="ascii").strip() == str(self._pid):
                self._lock_path.unlink()
        except (FileNotFoundError, OSError, UnicodeError):
            pass


_TABLE_COLUMNS: Final[dict[str, tuple[str, ...]]] = {
    "queue_metadata": ("id", "schema_version", "queue_id", "config_json", "config_digest", "admission_cap_bytes", "process_tree_peak_cap_bytes", "active_process_limit", "page_size", "max_page_count", "journal_mode", "synchronous", "head_root", "next_transition_seq", "next_admission_seq", "nonterminal_count", "live_lease_count", "proof_attempts_used", "proof_attempts_cap", "next_attempt_seq"),
    "queue_batches": ("batch_id", "batch_root", "state_challenge", "ordered_binding", "proof_statement", "assertion_identifier", "assertion_version", "state_profile_version", "valid_from_ms", "valid_until_ms", "approved_source_registry_root", "qualification_flags", "identity_digest", "status", "admission_seq", "attempt", "next_eligible_ms", "created_ms", "updated_ms", "last_error_code"),
    "queue_members": ("batch_id", "batch_position", "operation_ref", "admission_seq"),
    "queue_leases": ("batch_id", "worker_id", "token_digest", "attempt", "claim_sequence", "leased_ms", "expires_ms"),
    "queue_attempts": ("attempt_id", "batch_id", "reservation_before", "reservation_after", "proof_attempts", "source_key_epoch", "status", "reserved_ms", "closed_ms", "result_code"),
    "queue_results": ("batch_id", "terminal_status", "receipt_id", "receipt_bytes", "proof_accepted", "source_authenticated", "proof_statement", "batch_root", "source_auth_profile", "source_key_epoch", "result_code", "qualification_flags", "completed_ms", "attempt", "error_code"),
    "queue_transitions": ("sequence", "transition_kind", "batch_id", "before_root", "after_root", "event_bytes", "event_digest"),
}
_TABLES: Final[frozenset[str]] = frozenset(_TABLE_COLUMNS)
_TABLE_SCHEMA_SQL: Final[dict[str, str]] = {
    "queue_metadata": "CREATE TABLE queue_metadata (id INTEGER PRIMARY KEY CHECK(id=1), schema_version INTEGER NOT NULL, queue_id TEXT NOT NULL, config_json BLOB NOT NULL, config_digest BLOB NOT NULL CHECK(length(config_digest)=64), admission_cap_bytes INTEGER NOT NULL, process_tree_peak_cap_bytes INTEGER NOT NULL, active_process_limit INTEGER NOT NULL, page_size INTEGER NOT NULL CHECK(page_size=4096), max_page_count INTEGER NOT NULL CHECK(max_page_count=32768), journal_mode TEXT NOT NULL CHECK(journal_mode='delete'), synchronous INTEGER NOT NULL CHECK(synchronous=2), head_root BLOB NOT NULL CHECK(length(head_root)=64), next_transition_seq INTEGER NOT NULL, next_admission_seq INTEGER NOT NULL, nonterminal_count INTEGER NOT NULL, live_lease_count INTEGER NOT NULL, proof_attempts_used INTEGER NOT NULL, proof_attempts_cap INTEGER NOT NULL CHECK(proof_attempts_cap=4294967296), next_attempt_seq INTEGER NOT NULL)",
    "queue_batches": "CREATE TABLE queue_batches (batch_id BLOB PRIMARY KEY CHECK(length(batch_id)=32), batch_root BLOB NOT NULL CHECK(length(batch_root)=64), state_challenge BLOB NOT NULL CHECK(length(state_challenge)=32), ordered_binding BLOB NOT NULL CHECK(length(ordered_binding)=32), proof_statement BLOB NOT NULL CHECK(length(proof_statement)=240), assertion_identifier TEXT NOT NULL, assertion_version INTEGER NOT NULL, state_profile_version TEXT NOT NULL, valid_from_ms INTEGER NOT NULL, valid_until_ms INTEGER NOT NULL, approved_source_registry_root BLOB, qualification_flags BLOB NOT NULL, identity_digest BLOB NOT NULL CHECK(length(identity_digest)=64), status TEXT NOT NULL CHECK(status IN ('AWAITING_HANDOFF','QUEUED','LEASED','VERIFIED','REJECTED','HELD')), admission_seq INTEGER NOT NULL UNIQUE CHECK(admission_seq>=1), attempt INTEGER NOT NULL CHECK(attempt IN (0,1)), next_eligible_ms INTEGER NOT NULL, created_ms INTEGER NOT NULL, updated_ms INTEGER NOT NULL, last_error_code TEXT, CHECK(approved_source_registry_root IS NULL OR length(approved_source_registry_root)=64), CHECK(valid_from_ms<valid_until_ms))",
    "queue_members": "CREATE TABLE queue_members (batch_id BLOB NOT NULL REFERENCES queue_batches(batch_id), batch_position INTEGER NOT NULL CHECK(batch_position BETWEEN 0 AND 99), operation_ref BLOB NOT NULL CHECK(length(operation_ref)=32), admission_seq INTEGER NOT NULL CHECK(admission_seq>=1), PRIMARY KEY(batch_id,batch_position), UNIQUE(operation_ref), UNIQUE(admission_seq))",
    "queue_leases": "CREATE TABLE queue_leases (batch_id BLOB PRIMARY KEY REFERENCES queue_batches(batch_id), worker_id TEXT NOT NULL, token_digest BLOB NOT NULL CHECK(length(token_digest)=64), attempt INTEGER NOT NULL CHECK(attempt=1), claim_sequence INTEGER NOT NULL, leased_ms INTEGER NOT NULL, expires_ms INTEGER NOT NULL CHECK(expires_ms>leased_ms))",
    "queue_attempts": "CREATE TABLE queue_attempts (attempt_id INTEGER PRIMARY KEY, batch_id BLOB NOT NULL UNIQUE REFERENCES queue_batches(batch_id), reservation_before INTEGER NOT NULL CHECK(reservation_before>=0), reservation_after INTEGER NOT NULL CHECK(reservation_after>reservation_before), proof_attempts INTEGER NOT NULL CHECK(proof_attempts=101), source_key_epoch BLOB NOT NULL CHECK(length(source_key_epoch)=8), status TEXT NOT NULL CHECK(status IN ('RESERVED','ACCEPTED','REJECTED','HELD')), reserved_ms INTEGER NOT NULL, closed_ms INTEGER, result_code TEXT)",
    "queue_results": "CREATE TABLE queue_results (batch_id BLOB PRIMARY KEY REFERENCES queue_batches(batch_id), terminal_status TEXT NOT NULL CHECK(terminal_status IN ('VERIFIED','REJECTED','HELD')), receipt_id BLOB NOT NULL CHECK(length(receipt_id)=32), receipt_bytes BLOB NOT NULL, proof_accepted INTEGER NOT NULL CHECK(proof_accepted IN (0,1)), source_authenticated INTEGER NOT NULL CHECK(source_authenticated IN (0,1)), proof_statement BLOB NOT NULL CHECK(length(proof_statement)=240), batch_root BLOB NOT NULL CHECK(length(batch_root)=64), source_auth_profile TEXT NOT NULL, source_key_epoch BLOB NOT NULL CHECK(length(source_key_epoch)=8), result_code TEXT NOT NULL, qualification_flags BLOB NOT NULL, completed_ms INTEGER NOT NULL, attempt INTEGER NOT NULL CHECK(attempt IN (0,1)), error_code TEXT)",
    "queue_transitions": "CREATE TABLE queue_transitions (sequence INTEGER PRIMARY KEY, transition_kind TEXT NOT NULL, batch_id BLOB NOT NULL REFERENCES queue_batches(batch_id), before_root BLOB NOT NULL CHECK(length(before_root)=64), after_root BLOB NOT NULL CHECK(length(after_root)=64), event_bytes BLOB NOT NULL, event_digest BLOB NOT NULL CHECK(length(event_digest)=64))",
}
_STATUSES: Final[tuple[str, ...]] = ("AWAITING_HANDOFF", "QUEUED", "LEASED", "VERIFIED", "REJECTED", "HELD")
_TERMINAL: Final[frozenset[str]] = frozenset(("VERIFIED", "REJECTED", "HELD"))
_ACTIVE: Final[frozenset[str]] = frozenset(("AWAITING_HANDOFF", "QUEUED", "LEASED"))
_GENESIS: Final[bytes] = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/GENESIS/v9\x00"
_EVENT: Final[bytes] = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/EVENT/v9\x00"
_HEAD: Final[bytes] = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/HEAD/v9\x00"
_LEASE: Final[bytes] = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/LEASE/v9\x00"
_MATERIAL: Final[bytes] = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/MATERIAL/v9\x00"
_RUNTIME_WORKER: Final[str] = "queue-v9-worker"
_LEASE_MS: Final[int] = 60_000
_MAX_EVENT_BYTES: Final[int] = 4096

_TRIGGER_DEFS: Final[tuple[tuple[str, str], ...]] = (
    ("queue_batches_identity_guard", "CREATE TRIGGER queue_batches_identity_guard BEFORE UPDATE OF batch_id,batch_root,state_challenge,ordered_binding,proof_statement,assertion_identifier,assertion_version,state_profile_version,valid_from_ms,valid_until_ms,approved_source_registry_root,qualification_flags,identity_digest,admission_seq,created_ms ON queue_batches BEGIN SELECT RAISE(ABORT,'queue_batch_identity_guard'); END"),
    ("queue_batches_no_delete", "CREATE TRIGGER queue_batches_no_delete BEFORE DELETE ON queue_batches BEGIN SELECT RAISE(ABORT,'queue_batch_delete_guard'); END"),
    ("queue_members_no_update", "CREATE TRIGGER queue_members_no_update BEFORE UPDATE ON queue_members BEGIN SELECT RAISE(ABORT,'queue_member_update_guard'); END"),
    ("queue_members_no_delete", "CREATE TRIGGER queue_members_no_delete BEFORE DELETE ON queue_members BEGIN SELECT RAISE(ABORT,'queue_member_delete_guard'); END"),
    ("queue_results_no_update", "CREATE TRIGGER queue_results_no_update BEFORE UPDATE ON queue_results BEGIN SELECT RAISE(ABORT,'queue_result_update_guard'); END"),
    ("queue_results_no_delete", "CREATE TRIGGER queue_results_no_delete BEFORE DELETE ON queue_results BEGIN SELECT RAISE(ABORT,'queue_result_delete_guard'); END"),
    ("queue_transitions_no_update", "CREATE TRIGGER queue_transitions_no_update BEFORE UPDATE ON queue_transitions BEGIN SELECT RAISE(ABORT,'queue_transition_update_guard'); END"),
    ("queue_transitions_no_delete", "CREATE TRIGGER queue_transitions_no_delete BEFORE DELETE ON queue_transitions BEGIN SELECT RAISE(ABORT,'queue_transition_delete_guard'); END"),
    ("queue_attempts_transition_guard", "CREATE TRIGGER queue_attempts_transition_guard BEFORE UPDATE ON queue_attempts WHEN NOT (OLD.status='RESERVED' AND NEW.status IN ('ACCEPTED','REJECTED','HELD') AND OLD.attempt_id=NEW.attempt_id AND OLD.batch_id=NEW.batch_id AND OLD.reservation_before=NEW.reservation_before AND OLD.reservation_after=NEW.reservation_after AND OLD.proof_attempts=NEW.proof_attempts AND OLD.source_key_epoch=NEW.source_key_epoch AND OLD.reserved_ms=NEW.reserved_ms AND NEW.closed_ms IS NOT NULL AND (OLD.result_code IS NULL OR NEW.result_code=OLD.result_code OR NEW.result_code IS NOT NULL)) BEGIN SELECT RAISE(ABORT,'queue_attempt_transition_guard'); END"),
    ("queue_attempts_no_delete", "CREATE TRIGGER queue_attempts_no_delete BEFORE DELETE ON queue_attempts BEGIN SELECT RAISE(ABORT,'queue_attempt_delete_guard'); END"),
    ("queue_metadata_config_guard", "CREATE TRIGGER queue_metadata_config_guard BEFORE UPDATE OF schema_version,queue_id,config_json,config_digest,admission_cap_bytes,process_tree_peak_cap_bytes,active_process_limit,page_size,max_page_count,journal_mode,synchronous,proof_attempts_cap ON queue_metadata BEGIN SELECT RAISE(ABORT,'queue_metadata_config_guard'); END"),
)


def _columns(connection: sqlite3.Connection, table: str) -> tuple[str, ...]:
    return tuple(str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})").fetchall())


def _normalize_schema_sql(value: str) -> str:
    normalized = re.sub(r"\s+", " ", value.strip()).lower()
    return re.sub(r"\(\s+", "(", re.sub(r"\s+\)", ")", normalized))


def _create_schema(connection: sqlite3.Connection, composition_config: object) -> None:
    connection.executescript(
        """
        CREATE TABLE queue_metadata (
            id INTEGER PRIMARY KEY CHECK(id=1), schema_version INTEGER NOT NULL,
            queue_id TEXT NOT NULL, config_json BLOB NOT NULL,
            config_digest BLOB NOT NULL CHECK(length(config_digest)=64),
            admission_cap_bytes INTEGER NOT NULL, process_tree_peak_cap_bytes INTEGER NOT NULL,
            active_process_limit INTEGER NOT NULL, page_size INTEGER NOT NULL CHECK(page_size=4096),
            max_page_count INTEGER NOT NULL CHECK(max_page_count=32768), journal_mode TEXT NOT NULL CHECK(journal_mode='delete'),
            synchronous INTEGER NOT NULL CHECK(synchronous=2), head_root BLOB NOT NULL CHECK(length(head_root)=64),
            next_transition_seq INTEGER NOT NULL, next_admission_seq INTEGER NOT NULL,
            nonterminal_count INTEGER NOT NULL, live_lease_count INTEGER NOT NULL,
            proof_attempts_used INTEGER NOT NULL, proof_attempts_cap INTEGER NOT NULL CHECK(proof_attempts_cap=4294967296),
            next_attempt_seq INTEGER NOT NULL
        );
        CREATE TABLE queue_batches (
            batch_id BLOB PRIMARY KEY CHECK(length(batch_id)=32), batch_root BLOB NOT NULL CHECK(length(batch_root)=64),
            state_challenge BLOB NOT NULL CHECK(length(state_challenge)=32), ordered_binding BLOB NOT NULL CHECK(length(ordered_binding)=32),
            proof_statement BLOB NOT NULL CHECK(length(proof_statement)=240), assertion_identifier TEXT NOT NULL,
            assertion_version INTEGER NOT NULL, state_profile_version TEXT NOT NULL, valid_from_ms INTEGER NOT NULL,
            valid_until_ms INTEGER NOT NULL, approved_source_registry_root BLOB,
            qualification_flags BLOB NOT NULL, identity_digest BLOB NOT NULL CHECK(length(identity_digest)=64),
            status TEXT NOT NULL CHECK(status IN ('AWAITING_HANDOFF','QUEUED','LEASED','VERIFIED','REJECTED','HELD')),
            admission_seq INTEGER NOT NULL UNIQUE CHECK(admission_seq>=1), attempt INTEGER NOT NULL CHECK(attempt IN (0,1)),
            next_eligible_ms INTEGER NOT NULL, created_ms INTEGER NOT NULL, updated_ms INTEGER NOT NULL, last_error_code TEXT,
            CHECK(approved_source_registry_root IS NULL OR length(approved_source_registry_root)=64), CHECK(valid_from_ms<valid_until_ms)
        );
        CREATE TABLE queue_members (
            batch_id BLOB NOT NULL REFERENCES queue_batches(batch_id), batch_position INTEGER NOT NULL CHECK(batch_position BETWEEN 0 AND 99),
            operation_ref BLOB NOT NULL CHECK(length(operation_ref)=32), admission_seq INTEGER NOT NULL CHECK(admission_seq>=1),
            PRIMARY KEY(batch_id,batch_position), UNIQUE(operation_ref), UNIQUE(admission_seq)
        );
        CREATE TABLE queue_leases (
            batch_id BLOB PRIMARY KEY REFERENCES queue_batches(batch_id), worker_id TEXT NOT NULL,
            token_digest BLOB NOT NULL CHECK(length(token_digest)=64), attempt INTEGER NOT NULL CHECK(attempt=1),
            claim_sequence INTEGER NOT NULL, leased_ms INTEGER NOT NULL, expires_ms INTEGER NOT NULL CHECK(expires_ms>leased_ms)
        );
        CREATE TABLE queue_attempts (
            attempt_id INTEGER PRIMARY KEY, batch_id BLOB NOT NULL UNIQUE REFERENCES queue_batches(batch_id),
            reservation_before INTEGER NOT NULL CHECK(reservation_before>=0), reservation_after INTEGER NOT NULL CHECK(reservation_after>reservation_before),
            proof_attempts INTEGER NOT NULL CHECK(proof_attempts=101), source_key_epoch BLOB NOT NULL CHECK(length(source_key_epoch)=8),
            status TEXT NOT NULL CHECK(status IN ('RESERVED','ACCEPTED','REJECTED','HELD')), reserved_ms INTEGER NOT NULL,
            closed_ms INTEGER, result_code TEXT
        );
        CREATE TABLE queue_results (
            batch_id BLOB PRIMARY KEY REFERENCES queue_batches(batch_id), terminal_status TEXT NOT NULL CHECK(terminal_status IN ('VERIFIED','REJECTED','HELD')),
            receipt_id BLOB NOT NULL CHECK(length(receipt_id)=32), receipt_bytes BLOB NOT NULL,
            proof_accepted INTEGER NOT NULL CHECK(proof_accepted IN (0,1)), source_authenticated INTEGER NOT NULL CHECK(source_authenticated IN (0,1)),
            proof_statement BLOB NOT NULL CHECK(length(proof_statement)=240), batch_root BLOB NOT NULL CHECK(length(batch_root)=64),
            source_auth_profile TEXT NOT NULL, source_key_epoch BLOB NOT NULL CHECK(length(source_key_epoch)=8), result_code TEXT NOT NULL,
            qualification_flags BLOB NOT NULL, completed_ms INTEGER NOT NULL, attempt INTEGER NOT NULL CHECK(attempt IN (0,1)), error_code TEXT
        );
        CREATE TABLE queue_transitions (
            sequence INTEGER PRIMARY KEY, transition_kind TEXT NOT NULL, batch_id BLOB NOT NULL REFERENCES queue_batches(batch_id),
            before_root BLOB NOT NULL CHECK(length(before_root)=64), after_root BLOB NOT NULL CHECK(length(after_root)=64),
            event_bytes BLOB NOT NULL, event_digest BLOB NOT NULL CHECK(length(event_digest)=64)
        );
        """
    )
    connection.executescript("\n".join(sql + ";" for _, sql in _TRIGGER_DEFS))
    from app.minimal_clearance_composition import _create_composition_schema
    _create_composition_schema(connection, composition_config)


def _flags_bytes(flags: tuple[str, ...]) -> bytes:
    return _json_bytes({"qualification_flags": list(flags)})


def _parse_flags(raw: bytes) -> tuple[str, ...]:
    if type(raw) is not bytes or len(raw) > 4096:
        _raise_fixed(QueueIntegrityError("flags_bounds"))
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _raise_fixed(QueueIntegrityError("flags_encoding"))
    if type(value) is not dict or set(value) != {"qualification_flags"} or type(value["qualification_flags"]) is not list:
        _raise_fixed(QueueIntegrityError("flags_shape"))
    flags = tuple(value["qualification_flags"])
    if len(flags) > 32 or tuple(sorted(flags)) != flags or len(set(flags)) != len(flags):
        _raise_fixed(QueueIntegrityError("flags_shape"))
    for flag in flags:
        _token(flag, "qualification_flag", 96)
    if raw != _flags_bytes(flags):
        _raise_fixed(QueueIntegrityError("flags_encoding"))
    return flags


def _statement_from_batch(connection: sqlite3.Connection, batch_row: tuple[Any, ...]) -> IssuedVerificationBatch:
    if len(batch_row) != len(_TABLE_COLUMNS["queue_batches"]):
        _raise_fixed(QueueIntegrityError("batch_statement"))
    batch_id = _blob(batch_row[0], 32, "batch_id")
    member_rows = [tuple(row) for row in connection.execute("SELECT * FROM queue_members WHERE batch_id=? ORDER BY batch_position", (batch_id,)).fetchall()]
    if len(member_rows) != RANGE100_COUNT:
        _raise_fixed(QueueIntegrityError("queue_batch_shape"))
    if tuple(int(row[1]) for row in member_rows) != tuple(range(RANGE100_COUNT)):
        _raise_fixed(QueueIntegrityError("queue_batch_order"))
    admission_start = (int(batch_row[14]) - 1) * RANGE100_COUNT + 1
    if tuple(int(row[3]) for row in member_rows) != tuple(range(admission_start, admission_start + RANGE100_COUNT)):
        _raise_fixed(QueueIntegrityError("queue_batch_order"))
    refs = tuple(_blob(row[2], MAX_OPERATION_REF_BYTES, "operation_ref") for row in member_rows)
    template = OperationTemplate(str(batch_row[5]), int(batch_row[6]), str(batch_row[7]), int(batch_row[8]), int(batch_row[9]), None if batch_row[10] is None else _blob(batch_row[10], 64, "source_registry_root"), _parse_flags(bytes(batch_row[11])))
    return IssuedVerificationBatch(batch_id, template, refs, _blob(batch_row[1], 64, "batch_root"), _blob(batch_row[2], 32, "state_challenge"), _blob(batch_row[3], 32, "ordered_binding"), _blob(batch_row[4], 240, "proof_statement"), int(batch_row[14]), _blob(batch_row[12], 64, "batch_identity"))


class _VerificationQueueStore:
    def __init__(self, *, path: Path, config: QueueConfig, owner: _QueueRuntimeOwnership | None = None, clock: "QueueClock | None" = None, before_fault: Callable[[str], None] | None = None, after_commit_fault: Callable[[str], None] | None = None, composition_config: object | None = None) -> None:
        if owner is None:
            _raise_fixed(VerificationQueueError("queue_owner_required"))
        try:
            if not isinstance(path, Path) or not path.is_absolute() or path.name != "state.sqlite" or not isinstance(config, QueueConfig):
                _raise_fixed(VerificationQueueError("queue_configuration"))
            if not path.parent.is_dir():
                _raise_fixed(VerificationQueueError("queue_parent"))
            owner.assert_scope(lock_path=path.with_name(path.name + ".runtime-lock"), parent=path.parent)
        except BaseException:
            # Ownership is acquired before store/schema construction.  Any
            # scope failure must release that exact lock before propagating.
            owner.close()
            raise
        self.path = path
        self.config = config
        self.owner = owner
        self.clock = clock or SystemQueueClock()
        self._before_fault = before_fault
        self._after_commit_fault = after_commit_fault
        from app.minimal_clearance_composition import CompositionConfigV2
        if composition_config is None:
            composition_config = CompositionConfigV2(config.queue_id, config.digest, capacity=max(RANGE100_COUNT, config.capacity))
        if type(composition_config) is not CompositionConfigV2 or composition_config.queue_id != config.queue_id or composition_config.queue_config_digest != config.digest:
            owner.close()
            _raise_fixed(VerificationQueueError("composition_schema"))
        self.composition_config = composition_config
        self._handoffs: dict[bytes, VolatileProofHandoff] = {}
        self._closed = False
        self._startup_recovered_count = 0
        self._last_claim_error: str | None = None
        self._last_claim_held_count = 0
        try:
            if self.path.exists():
                if self.path.is_symlink() or self.path.stat().st_size > MAX_QUEUE_DATABASE_BYTES:
                    _raise_fixed(VerificationQueueError("queue_database_bounds"))
                self._schema_check()
                from app.minimal_clearance_verification_queue_independent import verify_database
                verify_database(self.path, expected_config=self.config.as_json)
            else:
                self._create_database()
            self._startup_recovered_count = self._recover_startup()
        except BaseException:
            owner.close()
            raise

    def _assert_owner(self) -> None:
        if self._closed:
            _raise_fixed(VerificationQueueError("queue_closed"))
        self.owner.assert_live()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.path), timeout=5.0)
        try:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA busy_timeout=5000")
            connection.execute("PRAGMA page_size=4096")
            connection.execute("PRAGMA max_page_count=32768")
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA synchronous=FULL")
            checks = {"foreign_keys": int(connection.execute("PRAGMA foreign_keys").fetchone()[0]), "page_size": int(connection.execute("PRAGMA page_size").fetchone()[0]), "max_page_count": int(connection.execute("PRAGMA max_page_count").fetchone()[0]), "journal_mode": str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower(), "synchronous": int(connection.execute("PRAGMA synchronous").fetchone()[0])}
            if checks != {"foreign_keys": 1, "page_size": DATABASE_PAGE_SIZE, "max_page_count": DATABASE_MAX_PAGE_COUNT, "journal_mode": "delete", "synchronous": 2}:
                _raise_fixed(VerificationQueueError("queue_schema_unsupported"))
            return connection
        except BaseException:
            connection.close()
            raise

    def _create_database(self) -> None:
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                _create_schema(connection, self.composition_config)
                config_raw = self.config.canonical_bytes
                config_digest = self.config.digest
                head = _sha3(_GENESIS, self.config.queue_id.encode("ascii"), config_digest)
                connection.execute("INSERT INTO queue_metadata VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (1, SCHEMA_VERSION, self.config.queue_id, config_raw, config_digest, ADMISSION_CAP_BYTES, PROCESS_TREE_PEAK_CAP_BYTES, ACTIVE_PROCESS_LIMIT, DATABASE_PAGE_SIZE, DATABASE_MAX_PAGE_COUNT, "delete", 2, head, 0, 0, 0, 0, 0, PROOF_ATTEMPTS_CAP, 0))
                connection.commit()
            except BaseException:
                connection.rollback()
                raise

    def _schema_check(self) -> None:
        with closing(self._connect()) as connection:
            tables = {str(row[0]) for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
            from app.minimal_clearance_composition import _COMPOSITION_TABLES, _check_composition_schema
            if tables != _TABLES | _COMPOSITION_TABLES or any(_columns(connection, table) != _TABLE_COLUMNS[table] for table in _TABLES):
                _raise_fixed(VerificationQueueError("queue_schema_unsupported"))
            table_sql = {str(row[0]): str(row[1]) for row in connection.execute("SELECT name,sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
            if set(table_sql) != _TABLES | _COMPOSITION_TABLES or any(_normalize_schema_sql(table_sql[name]) != _normalize_schema_sql(_TABLE_SCHEMA_SQL[name]) for name in _TABLES):
                _raise_fixed(VerificationQueueError("queue_schema_unsupported"))
            trigger_rows = {str(row[0]): str(row[1]) for row in connection.execute("SELECT name,sql FROM sqlite_master WHERE type='trigger'")}
            expected_triggers = {name for name, _ in _TRIGGER_DEFS} | {"composition_transactions_no_delete", "composition_events_no_update", "composition_events_no_delete"}
            if set(trigger_rows) != expected_triggers:
                _raise_fixed(VerificationQueueError("queue_schema_unsupported"))
            for name, expected in _TRIGGER_DEFS:
                if re.sub(r"\s+", " ", trigger_rows[name].strip()).lower() != re.sub(r"\s+", " ", expected.strip()).lower():
                    _raise_fixed(VerificationQueueError("queue_schema_unsupported"))
            meta = connection.execute("SELECT * FROM queue_metadata WHERE id=1").fetchone()
            if meta is None or len(meta) != len(_TABLE_COLUMNS["queue_metadata"]) or int(meta[1]) != SCHEMA_VERSION:
                _raise_fixed(VerificationQueueError("queue_schema_unsupported"))
            if int(meta[8]) != DATABASE_PAGE_SIZE or int(meta[9]) != DATABASE_MAX_PAGE_COUNT or str(meta[10]).lower() != "delete" or int(meta[11]) != 2:
                _raise_fixed(VerificationQueueError("queue_schema_unsupported"))
            try:
                stored = json.loads(bytes(meta[3]).decode("ascii"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                _raise_fixed(VerificationQueueError("queue_config_encoding"))
            if stored != self.config.as_json or bytes(meta[4]) != self.config.digest or bytes(meta[4]) != _sha3(_MATERIAL, bytes(meta[3])):
                _raise_fixed(VerificationQueueError("queue_config_binding"))
            try:
                _check_composition_schema(connection, self.composition_config)
            except BaseException:
                _raise_fixed(VerificationQueueError("composition_schema"))

    def _meta(self, connection: sqlite3.Connection) -> tuple[Any, ...]:
        row = connection.execute("SELECT * FROM queue_metadata WHERE id=1").fetchone()
        if row is None:
            _raise_fixed(QueueIntegrityError("queue_integrity_failed"))
        return tuple(row)

    def _fault(self, label: str) -> None:
        if self._before_fault is not None:
            self._before_fault(label)

    def _after_commit(self, label: str) -> None:
        if self._after_commit_fault is not None:
            self._after_commit_fault(label)

    def _append_event(self, connection: sqlite3.Connection, *, kind: str, batch_id: bytes, status: str, error_code: str | None, attempt: int, at_ms: int, extra: Mapping[str, Any] | None = None) -> None:
        if status not in _STATUSES or type(attempt) is not int or not 0 <= attempt <= 1:
            _raise_fixed(QueueIntegrityError("event_fields"))
        if error_code is not None:
            error_code = _code(error_code, "event_code")
        meta = self._meta(connection)
        sequence = int(meta[13]) + 1
        event: dict[str, Any] = {"schema": _SCHEMA, "sequence": sequence, "kind": kind, "batch_id": _hex(batch_id), "status": status, "error_code": error_code, "attempt": attempt, "at_ms": at_ms}
        if extra:
            if set(extra) - {"member_count", "reservation_before", "reservation_after", "receipt_id", "identity_digest"}:
                _raise_fixed(QueueIntegrityError("event_fields"))
            event.update(extra)
        raw = _json_bytes(event)
        if len(raw) > _MAX_EVENT_BYTES:
            _raise_fixed(QueueIntegrityError("event_bounds"))
        digest = _sha3(_EVENT, _u64(sequence), raw)
        after = _sha3(_HEAD, bytes(meta[12]), _u64(sequence), digest)
        connection.execute("INSERT INTO queue_transitions VALUES (?,?,?,?,?,?,?)", (sequence, kind, batch_id, bytes(meta[12]), after, raw, digest))
        connection.execute("UPDATE queue_metadata SET head_root=?,next_transition_seq=? WHERE id=1", (after, sequence))

    def _insert_batch(self, connection: sqlite3.Connection, *, batch: IssuedVerificationBatch, now: int, batch_admission_seq: int) -> None:
        connection.execute("INSERT INTO queue_batches VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (batch.batch_id, batch.batch_root, batch.state_challenge, batch.ordered_binding, batch.proof_statement, batch.template.assertion_identifier, batch.template.assertion_version, batch.template.state_profile_version, batch.template.valid_from_ms, batch.template.valid_until_ms, batch.template.approved_source_registry_root, _flags_bytes(batch.template.qualification_flags), batch.identity_digest, "AWAITING_HANDOFF", batch_admission_seq, 0, now, now, now, None))
        for position, operation_ref in enumerate(batch.operation_refs):
            connection.execute("INSERT INTO queue_members VALUES (?,?,?,?)", (batch.batch_id, position, operation_ref, (batch_admission_seq - 1) * RANGE100_COUNT + position + 1))
        self._append_event(connection, kind="BATCH_ISSUED", batch_id=batch.batch_id, status="AWAITING_HANDOFF", error_code=None, attempt=0, at_ms=now, extra={"member_count": RANGE100_COUNT, "identity_digest": _hex(batch.identity_digest)})
        connection.execute("UPDATE queue_metadata SET next_admission_seq=?,nonterminal_count=nonterminal_count+1 WHERE id=1", (batch_admission_seq * RANGE100_COUNT,))

    def issue_batch(self, *, template: OperationTemplate) -> IssuedVerificationBatch:
        self._assert_owner()
        _template_value_check(template)
        operation_refs = _generate_operation_refs()
        root = _compute_batch_root_from_refs(template, operation_refs)
        challenge = secrets.token_bytes(MAX_STATE_CHALLENGE_BYTES)
        batch_id = secrets.token_bytes(32)
        proof_statement = _build_statement(batch_root=root, state_challenge=challenge, valid_from_ms=template.valid_from_ms, valid_until_ms=template.valid_until_ms)
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                meta = self._meta(connection)
                if int(meta[15]) * RANGE100_COUNT + RANGE100_COUNT > self.config.capacity:
                    _raise_fixed(QueueBackpressureError("queue_capacity"))
                batch_admission_seq = int(meta[14]) // RANGE100_COUNT + 1
                provisional = IssuedVerificationBatch(batch_id, template, operation_refs, root, challenge, root[:32], proof_statement, batch_admission_seq, bytes(64))
                batch = IssuedVerificationBatch(batch_id, template, operation_refs, root, challenge, root[:32], proof_statement, batch_admission_seq, _batch_identity_digest(provisional, self.config))
                self._insert_batch(connection, batch=batch, now=int(self.clock.now_ms()), batch_admission_seq=batch_admission_seq)
                connection.commit()
            except BaseException:
                connection.rollback()
                raise
        return batch

    @staticmethod
    def _coerce_handoff(stream: BinaryIO | VolatileProofHandoff, declared_length: int | None) -> VolatileProofHandoff:
        return stream if isinstance(stream, VolatileProofHandoff) else VolatileProofHandoff(stream, declared_length=declared_length)

    def _close_handoff_locked(self, batch_id: bytes) -> None:
        handoff = self._handoffs.pop(batch_id, None)
        if handoff is not None:
            handoff.close()

    def _hold_batch_locked(self, connection: sqlite3.Connection, *, batch_id: bytes, now: int, code: str) -> bool:
        code = _code(code, "hold_code")
        row = connection.execute("SELECT * FROM queue_batches WHERE batch_id=?", (batch_id,)).fetchone()
        if row is None:
            return False
        status = str(row[13])
        if status in _TERMINAL:
            return False
        attempt = int(row[15])
        if status == "LEASED":
            attempt_row = connection.execute("SELECT * FROM queue_attempts WHERE batch_id=?", (batch_id,)).fetchone()
            if attempt_row is None or str(attempt_row[6]) != "RESERVED":
                _raise_fixed(QueueIntegrityError("attempt_missing"))
            connection.execute("UPDATE queue_attempts SET status='HELD',closed_ms=?,result_code=? WHERE attempt_id=?", (now, code, int(attempt_row[0])))
        connection.execute("DELETE FROM queue_leases WHERE batch_id=?", (batch_id,))
        connection.execute("UPDATE queue_batches SET status='HELD',updated_ms=?,last_error_code=? WHERE batch_id=?", (now, code, batch_id))
        batch = _statement_from_batch(connection, tuple(row))
        receipt = self._receipt(batch=batch, proof_accepted=False, source_authenticated=False, result_code=code, error_code=code, qualification_flags=self.config.qualification_flags)
        connection.execute("INSERT INTO queue_results VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (batch_id, "HELD", _sha3(_MATERIAL, b"receipt", batch_id, _u64(attempt))[:32], receipt, 0, 0, batch.proof_statement, batch.batch_root, self.config.source_auth_profile, _u64(self.config.source_key_epoch), code, _flags_bytes(self.config.qualification_flags), now, attempt, code))
        self._append_event(connection, kind="BATCH_HELD", batch_id=batch_id, status="HELD", error_code=code, attempt=attempt, at_ms=now, extra={"member_count": RANGE100_COUNT})
        meta = self._meta(connection)
        connection.execute("UPDATE queue_metadata SET nonterminal_count=?,live_lease_count=0 WHERE id=1", (max(0, int(meta[15]) - 1),))
        return True

    def submit_batch_handoff(self, *, issued_batch: IssuedVerificationBatch, proof_stream: BinaryIO | VolatileProofHandoff, declared_length: int | None = None) -> IssuedVerificationBatch:
        self._assert_owner()
        if type(issued_batch) is not IssuedVerificationBatch:
            close = getattr(proof_stream, "close", None)
            if callable(close):
                close()
            _raise_fixed(QueueConflictError("batch_required"))
        handoff = self._coerce_handoff(proof_stream, declared_length)
        stored = False
        committed = False
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    row = connection.execute("SELECT * FROM queue_batches WHERE batch_id=?", (issued_batch.batch_id,)).fetchone()
                    if row is None:
                        _raise_fixed(QueueConflictError("batch_unknown"))
                    durable = _statement_from_batch(connection, tuple(row))
                    if durable != issued_batch or _batch_identity_digest(durable, self.config) != durable.identity_digest:
                        held = self._hold_batch_locked(connection, batch_id=issued_batch.batch_id, now=int(self.clock.now_ms()), code="batch_binding")
                        connection.commit()
                        committed = True
                        if held:
                            self._close_handoff_locked(issued_batch.batch_id)
                            handoff.close()
                        _raise_fixed(QueueConflictError("batch_binding"))
                    now = int(self.clock.now_ms())
                    if str(row[13]) != "AWAITING_HANDOFF":
                        held = self._hold_batch_locked(connection, batch_id=issued_batch.batch_id, now=now, code="fresh_handoff_required")
                        connection.commit()
                        committed = True
                        if held:
                            self._close_handoff_locked(issued_batch.batch_id)
                            handoff.close()
                        _raise_fixed(QueueConflictError("fresh_handoff_required"))
                    if issued_batch.template.valid_from_ms > now or issued_batch.template.valid_until_ms <= now:
                        held = self._hold_batch_locked(connection, batch_id=issued_batch.batch_id, now=now, code="validity_expired")
                        connection.commit()
                        committed = True
                        if held:
                            self._close_handoff_locked(issued_batch.batch_id)
                            handoff.close()
                        _raise_fixed(QueueConflictError("validity_expired"))
                    self._handoffs[issued_batch.batch_id] = handoff
                    stored = True
                    connection.execute("UPDATE queue_batches SET status='QUEUED',next_eligible_ms=?,updated_ms=? WHERE batch_id=?", (now, now, issued_batch.batch_id))
                    self._append_event(connection, kind="HANDOFF_SUBMITTED", batch_id=issued_batch.batch_id, status="QUEUED", error_code=None, attempt=0, at_ms=now, extra={"member_count": RANGE100_COUNT})
                    connection.commit()
                    committed = True
                except BaseException:
                    connection.rollback()
                    raise
        except BaseException:
            # An unconsumed handoff remains available across a failed SQL/COMMIT.
            if not stored:
                handoff.close()
            raise
        return issued_batch

    def _expire_locked(self, connection: sqlite3.Connection, now: int) -> tuple[bytes, ...]:
        held: list[bytes] = []
        for (batch_id,) in connection.execute("SELECT batch_id FROM queue_batches WHERE status IN ('AWAITING_HANDOFF','QUEUED') AND valid_until_ms<=?", (now,)).fetchall():
            if self._hold_batch_locked(connection, batch_id=bytes(batch_id), now=now, code="validity_expired"):
                held.append(bytes(batch_id))
        for (batch_id,) in connection.execute("SELECT batch_id FROM queue_leases WHERE expires_ms<=?", (now,)).fetchall():
            if self._hold_batch_locked(connection, batch_id=bytes(batch_id), now=now, code="lease_expired"):
                held.append(bytes(batch_id))
        return tuple(held)

    def _recover_startup(self) -> int:
        self._assert_owner()
        recovered = 0
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                now = int(self.clock.now_ms())
                held: list[bytes] = []
                for (batch_id,) in connection.execute("SELECT batch_id FROM queue_batches WHERE status IN ('AWAITING_HANDOFF','QUEUED','LEASED') ORDER BY admission_seq").fetchall():
                    if self._hold_batch_locked(connection, batch_id=bytes(batch_id), now=now, code="fresh_handoff_required"):
                        recovered += 1
                        held.append(bytes(batch_id))
                connection.commit()
                for batch_id in held:
                    self._close_handoff_locked(batch_id)
            except BaseException:
                connection.rollback()
                raise
        self._handoffs.clear()
        return recovered

    def _claim_next_batch(self) -> _QueueWorkItem | None:
        self._assert_owner()
        self._last_claim_error = None
        self._last_claim_held_count = 0
        now = int(self.clock.now_ms())
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                held = list(self._expire_locked(connection, now))
                row = connection.execute("SELECT * FROM queue_batches WHERE status='QUEUED' AND next_eligible_ms<=? ORDER BY admission_seq LIMIT 1", (now,)).fetchone()
                if row is None:
                    connection.commit()
                    for batch_id in held:
                        self._close_handoff_locked(batch_id)
                    self._last_claim_held_count = len(held)
                    return None
                meta = self._meta(connection)
                if int(meta[16]) != 0 or int(connection.execute("SELECT COUNT(*) FROM queue_leases").fetchone()[0]) != 0:
                    connection.rollback()
                    self._last_claim_error = "proof_session_active"
                    return None
                before = int(meta[17])
                try:
                    after = _reserve_proof_attempt(before, cap=min(int(meta[18]), PROOF_ATTEMPTS_CAP))
                except QueueBackpressureError:
                    connection.rollback()
                    self._last_claim_error = "computational_budget_exhausted"
                    return None
                batch_id = bytes(row[0])
                attempt_id = int(meta[19]) + 1
                claim_seq = int(meta[13]) + 1
                token = secrets.token_bytes(32)
                expires = now + _LEASE_MS
                token_digest = hmac.new(token, _sha3(_LEASE, self.config.digest, batch_id, _u64(1), _u64(claim_seq), _u64(now), _u64(expires)), hashlib.sha3_512).digest()
                connection.execute("INSERT INTO queue_attempts VALUES (?,?,?,?,?,?,?,?,?,?)", (attempt_id, batch_id, before, after, PROOF_ATTEMPTS_PER_BATCH, _u64(self.config.source_key_epoch), "RESERVED", now, None, None))
                connection.execute("UPDATE queue_metadata SET proof_attempts_used=?,next_attempt_seq=?,live_lease_count=1 WHERE id=1", (after, attempt_id))
                connection.execute("UPDATE queue_batches SET status='LEASED',attempt=1,updated_ms=? WHERE batch_id=?", (now, batch_id))
                connection.execute("INSERT INTO queue_leases VALUES (?,?,?,?,?,?,?)", (batch_id, _RUNTIME_WORKER, token_digest, 1, claim_seq, now, expires))
                self._append_event(connection, kind="ATTEMPT_RESERVED", batch_id=batch_id, status="LEASED", error_code=None, attempt=1, at_ms=now, extra={"member_count": RANGE100_COUNT, "reservation_before": before, "reservation_after": after})
                connection.commit()
                for held_id in held:
                    self._close_handoff_locked(held_id)
                self._last_claim_held_count = len(held)
            except BaseException:
                connection.rollback()
                raise
        try:
            self._after_commit("after_reservation")
        except BaseException:
            self._close_handoff_locked(batch_id)
            raise
        with closing(self._connect()) as connection:
            row = connection.execute("SELECT * FROM queue_batches WHERE batch_id=?", (batch_id,)).fetchone()
            if row is None:
                _raise_fixed(QueueIntegrityError("queue_integrity_failed"))
            batch = _statement_from_batch(connection, tuple(row))
        return _QueueWorkItem(batch, 1, _RUNTIME_WORKER, claim_seq, token, expires)

    def _lease_fence(self, connection: sqlite3.Connection, work: _QueueWorkItem) -> tuple[tuple[Any, ...], tuple[Any, ...]]:
        row = connection.execute("SELECT * FROM queue_batches WHERE batch_id=?", (work.batch.batch_id,)).fetchone()
        lease = connection.execute("SELECT * FROM queue_leases WHERE batch_id=?", (work.batch.batch_id,)).fetchone()
        attempt = connection.execute("SELECT * FROM queue_attempts WHERE batch_id=?", (work.batch.batch_id,)).fetchone()
        if row is None or lease is None or str(row[13]) != "LEASED" or int(row[15]) != work.attempt or str(lease[1]) != work.worker_id or int(lease[3]) != work.attempt or int(lease[4]) != work.claim_sequence or int(lease[6]) != work.lease_expires_ms:
            _raise_fixed(QueueLeaseError("completion_not_live"))
        if attempt is None or int(attempt[0]) <= 0 or bytes(attempt[1]) != work.batch.batch_id or int(attempt[4]) != PROOF_ATTEMPTS_PER_BATCH or bytes(attempt[5]) != _u64(self.config.source_key_epoch) or str(attempt[6]) != "RESERVED":
            _raise_fixed(QueueLeaseError("completion_not_live"))
        try:
            durable = _statement_from_batch(connection, tuple(row))
        except VerificationQueueError:
            _raise_fixed(QueueLeaseError("completion_not_live"))
        if durable != work.batch or _batch_identity_digest(durable, self.config) != durable.identity_digest:
            _raise_fixed(QueueLeaseError("completion_not_live"))
        expected = hmac.new(work.lease_token, _sha3(_LEASE, self.config.digest, work.batch.batch_id, _u64(work.attempt), _u64(work.claim_sequence), _u64(int(lease[5])), _u64(int(lease[6]))), hashlib.sha3_512).digest()
        if bytes(lease[2]) != expected:
            _raise_fixed(QueueLeaseError("completion_lease_fence"))
        return tuple(row), tuple(lease)

    def _receipt(self, *, batch: IssuedVerificationBatch, proof_accepted: bool, source_authenticated: bool, result_code: str, error_code: str | None, qualification_flags: tuple[str, ...]) -> bytes:
        result_code = _code(result_code, "receipt_result_code")
        if error_code is not None:
            error_code = _code(error_code, "receipt_error")
        value = {"schema": _SCHEMA, "batch_id": _hex(batch.batch_id), "proof_accepted": proof_accepted, "source_authenticated": source_authenticated, "proof_statement": _hex(batch.proof_statement), "batch_root": _hex(batch.batch_root), "source_auth_profile": self.config.source_auth_profile, "source_key_epoch": self.config.source_key_epoch, "result_code": result_code, "qualification_flags": list(qualification_flags), "error_code": error_code, "proof_suite_id": None, "production_usable": False, "activation": False}
        raw = _json_bytes(value)
        if len(raw) > MAX_RECEIPT_BYTES:
            _raise_fixed(QueueIntegrityError("receipt_cap"))
        return raw

    def _composition_jobs(self, work: _QueueWorkItem, verifier_result: BatchVerifierResult) -> tuple[Any, ...]:
        from app.minimal_clearance_verification_queue_independent import IndependentVerifiedQueueJob
        return tuple(IndependentVerifiedQueueJob(self.config.queue_id, self.config.digest, operation_ref, "VERIFIED", True, work.attempt, b"", bytes(32), work.batch.template.assertion_identifier, work.batch.template.assertion_version, work.batch.template.state_profile_version, work.batch.template.valid_from_ms, work.batch.template.valid_until_ms, position, work.batch.batch_root, work.batch.template.approved_source_registry_root, self.config.profile_version, verifier_result.result_code, self.config.qualification_flags) for position, operation_ref in enumerate(work.batch.operation_refs))

    def _verified_duplicate_result(self, connection: sqlite3.Connection, work: _QueueWorkItem, verifier_result: BatchVerifierResult) -> tuple[Any, ...]:
        existing_batch = connection.execute("SELECT * FROM queue_batches WHERE batch_id=?", (work.batch.batch_id,)).fetchone()
        if existing_batch is None or str(existing_batch[13]) != "VERIFIED":
            _raise_fixed(QueueLeaseError("completion_not_live"))
        try:
            durable = _statement_from_batch(connection, tuple(existing_batch))
        except VerificationQueueError:
            _raise_fixed(QueueLeaseError("completion_not_live"))
        if durable != work.batch or _batch_identity_digest(durable, self.config) != durable.identity_digest or type(work.attempt) is not int or work.attempt != int(existing_batch[15]):
            _raise_fixed(QueueLeaseError("completion_not_live"))
        if not verifier_result.proof_accepted or not verifier_result.source_authenticated or verifier_result.result_code != "accepted" or verifier_result.proof_statement != durable.proof_statement or verifier_result.batch_root != durable.batch_root or verifier_result.source_auth_profile != self.config.source_auth_profile or verifier_result.source_key_epoch != self.config.source_key_epoch or verifier_result.qualification_flags != self.config.qualification_flags:
            _raise_fixed(QueueIntegrityError("completion_acceptance"))
        existing_result = connection.execute("SELECT * FROM queue_results WHERE batch_id=?", (durable.batch_id,)).fetchone()
        if existing_result is None:
            _raise_fixed(QueueIntegrityError("completion_acceptance"))
        if type(existing_result[13]) is not int or int(existing_result[13]) != int(existing_batch[15]):
            _raise_fixed(QueueLeaseError("completion_not_live"))
        expected_receipt = self._receipt(batch=durable, proof_accepted=True, source_authenticated=True, result_code="accepted", error_code=None, qualification_flags=self.config.qualification_flags)
        expected_receipt_id = _sha3(_MATERIAL, b"receipt", durable.batch_id, _u64(int(existing_batch[15])))[:32]
        expected_flags = _flags_bytes(self.config.qualification_flags)
        if type(existing_result[0]) is not bytes or bytes(existing_result[0]) != durable.batch_id or str(existing_result[1]) != "VERIFIED" or type(existing_result[2]) is not bytes or bytes(existing_result[2]) != expected_receipt_id or type(existing_result[3]) is not bytes or bytes(existing_result[3]) != expected_receipt or type(existing_result[4]) is not int or int(existing_result[4]) != 1 or type(existing_result[5]) is not int or int(existing_result[5]) != 1 or type(existing_result[6]) is not bytes or bytes(existing_result[6]) != durable.proof_statement or type(existing_result[7]) is not bytes or bytes(existing_result[7]) != durable.batch_root or str(existing_result[8]) != self.config.source_auth_profile or type(existing_result[9]) is not bytes or bytes(existing_result[9]) != _u64(self.config.source_key_epoch) or str(existing_result[10]) != verifier_result.result_code or type(existing_result[11]) is not bytes or bytes(existing_result[11]) != expected_flags or existing_result[14] is not None:
            _raise_fixed(QueueIntegrityError("completion_acceptance"))
        return tuple(existing_result)

    def _complete_batch(self, work: _QueueWorkItem, *, status: str, verifier_result: BatchVerifierResult | None = None, error_code: str | None = None, state_controls: Mapping[bytes, object] | None = None) -> QueueResult:
        if status not in _TERMINAL:
            _raise_fixed(QueueIntegrityError("completion_status"))
        accepted = bool(verifier_result is not None and verifier_result.proof_accepted)
        authenticated = bool(verifier_result is not None and verifier_result.source_authenticated)
        if status == "VERIFIED" and not (accepted and authenticated):
            _raise_fixed(QueueIntegrityError("completion_acceptance"))
        if status == "VERIFIED" and (state_controls is None or not isinstance(state_controls, Mapping)):
            _raise_fixed(QueueIntegrityError("state_disposition"))
        if verifier_result is not None and (
            verifier_result.proof_statement != work.batch.proof_statement
            or verifier_result.batch_root != work.batch.batch_root
            or verifier_result.source_auth_profile != self.config.source_auth_profile
            or verifier_result.source_key_epoch != self.config.source_key_epoch
            or verifier_result.qualification_flags != self.config.qualification_flags
        ):
            _raise_fixed(QueueIntegrityError("verifier_result_mismatch"))
        if status == "VERIFIED" and verifier_result is not None and verifier_result.result_code != "accepted":
            _raise_fixed(QueueIntegrityError("verifier_result_code"))
        result_code = verifier_result.result_code if verifier_result is not None else ("rejected" if status == "REJECTED" else "fresh_handoff_required")
        result_code = _code(result_code, "completion_code")
        final_error = None if error_code is None else _code(error_code, "completion_error")
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                existing_batch = connection.execute("SELECT * FROM queue_batches WHERE batch_id=?", (work.batch.batch_id,)).fetchone()
                if existing_batch is None:
                    _raise_fixed(QueueLeaseError("completion_not_live"))
                if str(existing_batch[13]) == "VERIFIED":
                    if status != "VERIFIED" or verifier_result is None:
                        _raise_fixed(QueueLeaseError("completion_not_live"))
                    existing_result = self._verified_duplicate_result(connection, work, verifier_result)
                    from app.minimal_clearance_composition import _apply_verified_jobs_in_transaction
                    _apply_verified_jobs_in_transaction(connection, config=self.composition_config, jobs=self._composition_jobs(work, verifier_result), state_controls=state_controls, now=int(self.clock.now_ms()))  # type: ignore[arg-type]
                    connection.commit()
                    self._close_handoff_locked(work.batch.batch_id)
                    return QueueResult(work.batch.batch_id, "VERIFIED", bytes(existing_result[3]), None if existing_result[14] is None else str(existing_result[14]), RANGE100_COUNT)
                row, lease = self._lease_fence(connection, work)
                # Recheck the clock after the live lease fence, within the
                # same completion transaction that closes the reservation.
                now = int(self.clock.now_ms())
                if now < work.batch.template.valid_from_ms or now >= work.batch.template.valid_until_ms:
                    status = "HELD"
                    result_code = "validity_expired"
                    final_error = "validity_expired"
                elif int(lease[6]) <= now:
                    status = "HELD"
                    result_code = "lease_expired"
                    final_error = "lease_expired"
                if status == "HELD":
                    accepted = False
                    authenticated = False
                    if final_error is None:
                        final_error = result_code
                receipt = self._receipt(batch=work.batch, proof_accepted=accepted, source_authenticated=authenticated, result_code=result_code, error_code=final_error, qualification_flags=self.config.qualification_flags)
                connection.execute("DELETE FROM queue_leases WHERE batch_id=?", (work.batch.batch_id,))
                attempt_status = "ACCEPTED" if status == "VERIFIED" else status
                connection.execute("UPDATE queue_attempts SET status=?,closed_ms=?,result_code=? WHERE batch_id=? AND status='RESERVED'", (attempt_status, now, result_code, work.batch.batch_id))
                connection.execute("UPDATE queue_batches SET status=?,updated_ms=?,last_error_code=? WHERE batch_id=?", (status, now, final_error, work.batch.batch_id))
                connection.execute("INSERT INTO queue_results VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (work.batch.batch_id, status, _sha3(_MATERIAL, b"receipt", work.batch.batch_id, _u64(work.attempt))[:32], receipt, int(accepted), int(authenticated), work.batch.proof_statement, work.batch.batch_root, self.config.source_auth_profile, _u64(self.config.source_key_epoch), result_code, _flags_bytes(self.config.qualification_flags), now, work.attempt, final_error))
                self._append_event(connection, kind="BATCH_HELD" if status == "HELD" else "BATCH_COMPLETED", batch_id=work.batch.batch_id, status=status, error_code=final_error, attempt=work.attempt, at_ms=now, extra={"member_count": RANGE100_COUNT})
                meta = self._meta(connection)
                connection.execute("UPDATE queue_metadata SET live_lease_count=0,nonterminal_count=? WHERE id=1", (max(0, int(meta[15]) - 1),))
                if status == "VERIFIED":
                    from app.minimal_clearance_composition import _apply_verified_jobs_in_transaction
                    composition_jobs = self._composition_jobs(work, verifier_result)
                    _apply_verified_jobs_in_transaction(connection, config=self.composition_config, jobs=composition_jobs, state_controls=state_controls, now=now, before_fault=self._fault)  # type: ignore[arg-type]
                self._fault("before_queue_commit")
                connection.commit()
            except BaseException:
                connection.rollback()
                raise
        # Close the volatile handoff only after the terminal commit is durable.
        self._close_handoff_locked(work.batch.batch_id)
        self._after_commit("batch_complete")
        return QueueResult(work.batch.batch_id, status, receipt, final_error, RANGE100_COUNT if status == "VERIFIED" else 0)

    def _consume_failed_handoff(self, work: _QueueWorkItem) -> None:
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute("SELECT status FROM queue_batches WHERE batch_id=?", (work.batch.batch_id,)).fetchone()
                if row is not None and str(row[0]) == "LEASED":
                    self._lease_fence(connection, work)
                    self._hold_batch_locked(connection, batch_id=work.batch.batch_id, now=int(self.clock.now_ms()), code="fresh_handoff_required")
                    connection.commit()
                    self._close_handoff_locked(work.batch.batch_id)
                else:
                    connection.rollback()
            except BaseException:
                connection.rollback()
                raise

    def _state_controls(self, work: _QueueWorkItem, outcome: VerificationOutcome, port: object | None) -> Mapping[bytes, object]:
        if port is None:
            _raise_fixed(QueueHeldError("state_disposition"))
        controls_for = getattr(port, "controls_for", None)
        if not callable(controls_for):
            _raise_fixed(QueueHeldError("state_disposition"))
        try:
            controls = controls_for(batch_id=work.batch.batch_id, operation_refs=work.batch.operation_refs, verification_outcome=outcome)
        except BaseException:
            _raise_fixed(QueueHeldError("state_disposition"))
        if not isinstance(controls, Mapping) or len(controls) != RANGE100_COUNT or set(controls) != set(work.batch.operation_refs):
            _raise_fixed(QueueHeldError("state_control_set"))
        return controls

    def _process_one_batch(self, *, verifier: VerifierPort, state_disposition_port: object | None = None) -> QueueResult | None:
        self._assert_owner()
        work = self._claim_next_batch()
        if work is None:
            return None
        handoff = self._handoffs.get(work.batch.batch_id)
        if handoff is None:
            return self._complete_batch(work, status="HELD", error_code="fresh_handoff_required")
        try:
            try:
                result = parse_batch_verifier_result(verifier.verify(handoff, work.batch))
                if not handoff.exhausted:
                    raise QueueHeldError("verifier_stream_not_consumed")
                if result.proof_statement != work.batch.proof_statement or result.batch_root != work.batch.batch_root or result.source_auth_profile != self.config.source_auth_profile or result.source_key_epoch != self.config.source_key_epoch or result.qualification_flags != self.config.qualification_flags:
                    raise QueueDeterministicRejectError("verifier_result_mismatch")
                if result.proof_accepted and result.source_authenticated:
                    if result.result_code != "accepted":
                        raise QueueHeldError("verifier_result_code")
                    controls = self._state_controls(work, result.non_dispositive_outcome, state_disposition_port)
                    return self._complete_batch(work, status="VERIFIED", verifier_result=result, state_controls=controls)
                if result.result_code != "rejected":
                    raise QueueHeldError("verifier_result_code")
                return self._complete_batch(work, status="REJECTED", verifier_result=result, error_code="proof_or_source_not_accepted")
            except QueueLeaseError:
                raise
            except QueueDeterministicRejectError as exc:
                return self._complete_batch(work, status="REJECTED", error_code=_code(str(exc), "completion_error"))
            except (QueueHeldError, QueueIntegrityError) as exc:
                raw = str(exc)
                code = raw if raw in {"verifier_stream_not_consumed", "verifier_result_unknown_field", "verifier_result_shape", "verifier_result_flags", "verifier_key_epoch", "verifier_result_code", "verifier_transport", "state_disposition", "state_control_set", "state_control_shape"} else "fresh_handoff_required"
                return self._complete_batch(work, status="HELD", error_code=code)
            except QueueRetryableError:
                return self._complete_batch(work, status="HELD", error_code="fresh_handoff_required")
            except (VerificationQueueError, sqlite3.Error):
                return self._complete_batch(work, status="HELD", error_code="fresh_handoff_required")
            except BaseException:
                return self._complete_batch(work, status="HELD", error_code="fresh_handoff_required")
        except BaseException:
            # Every post-reservation failure burns the attempt.  In particular,
            # an unconsumed or partially consumed stream is never retryable.
            if not handoff.closed:
                try:
                    self._consume_failed_handoff(work)
                except BaseException:
                    self._close_handoff_locked(work.batch.batch_id)
            raise

    def _read_projection(self) -> dict[str, Any]:
        self._assert_owner()
        with closing(self._connect()) as connection:
            meta = self._meta(connection)
            counts = {status: 0 for status in _STATUSES}
            for status, count in connection.execute("SELECT status,COUNT(*) FROM queue_batches GROUP BY status"):
                counts[str(status)] = int(count)
            verified_batches = counts["VERIFIED"]
            return {"schema": _SCHEMA, "head_root": bytes(meta[12]), "counts": counts, "transitions": int(meta[13]), "issued_batch_count": int(meta[14]) // RANGE100_COUNT, "verified_batch_count": verified_batches, "accepted_operation_count": verified_batches * RANGE100_COUNT, "proof_attempts_used": int(meta[17]), "proof_attempts_cap": int(meta[18]), "proof_suite_id": None, "production_usable": False, "activation": False}

    def _snapshot(self) -> dict[str, Any]:
        return self._read_projection()

    def _support_summary(self) -> dict[str, Any]:
        return {**self._read_projection(), "admission_cap_bytes": ADMISSION_CAP_BYTES, "process_tree_peak_cap_bytes": PROCESS_TREE_PEAK_CAP_BYTES, "proof_bytes_persisted": False, "path_custody": False, "backend_qualified": False, "resource_product_credit": False}

    def _verify_integrity(self) -> None:
        from app.minimal_clearance_verification_queue_independent import verify_database
        verify_database(self.path, expected_config=self.config.as_json)

    def _export_bytes(self) -> bytes:
        self._verify_integrity()
        return self.path.read_bytes()

    def _close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for handoff in tuple(self._handoffs.values()):
            handoff.close()
        self._handoffs.clear()


class QueueClock(Protocol):
    def now_ms(self) -> int: ...


class SystemQueueClock:
    def now_ms(self) -> int:
        import time
        return int(time.time() * 1000)


def _parse_receipt(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_RECEIPT_BYTES:
        _raise_fixed(QueueIntegrityError("receipt_bounds"))
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _raise_fixed(QueueIntegrityError("receipt_encoding"))
    required = {"schema", "batch_id", "proof_accepted", "source_authenticated", "proof_statement", "batch_root", "source_auth_profile", "source_key_epoch", "result_code", "qualification_flags", "error_code", "proof_suite_id", "production_usable", "activation"}
    if type(value) is not dict or set(value) != required or raw != _json_bytes(value) or value["schema"] != _SCHEMA:
        _raise_fixed(QueueIntegrityError("receipt_keys"))
    if value["proof_suite_id"] is not None or value["production_usable"] is not False or value["activation"] is not False:
        _raise_fixed(QueueIntegrityError("receipt_flags"))
    if type(value["proof_accepted"]) is not bool or type(value["source_authenticated"]) is not bool:
        _raise_fixed(QueueIntegrityError("receipt_acceptance"))
    for name, size, code in (("batch_id", 32, "receipt_batch_id"), ("proof_statement", 240, "receipt_statement"), ("batch_root", 64, "receipt_root")):
        if type(value[name]) is not str or value[name] != value[name].upper() or re.fullmatch(rf"[0-9A-F]{{{size * 2}}}\Z", value[name]) is None:
            _raise_fixed(QueueIntegrityError(code))
    _token(value["source_auth_profile"], "source_auth_profile", 96)
    if type(value["source_key_epoch"]) is not int or not 1 <= value["source_key_epoch"] <= MAX_SOURCE_KEY_EPOCH:
        _raise_fixed(QueueIntegrityError("receipt_source_epoch"))
    _code(value["result_code"], "receipt_result_code")
    flags = tuple(value["qualification_flags"]) if type(value["qualification_flags"]) is list else value["qualification_flags"]
    _parse_flags(_flags_bytes(flags))
    if value["error_code"] is not None:
        _code(value["error_code"], "receipt_error")
    return value


__all__ = (
    "ADMISSION_CAP_BYTES", "ACTIVE_PROCESS_LIMIT", "DATABASE_MAX_PAGE_COUNT", "DATABASE_PAGE_SIZE",
    "DIRECTIVES", "MAX_QUEUE_DATABASE_BYTES", "MAX_QUEUE_CAPACITY", "MAX_TERMINAL_GROWTH_PER_NONTERMINAL", "PROCESS_TREE_PEAK_CAP_BYTES",
    "PROFILE_FINGERPRINT", "PROFILE_VERSION", "CIRCUIT_FINGERPRINT", "PROOF_STATEMENT_BYTES", "RANGE100_COUNT", "PROOF_ATTEMPTS_CAP", "PROOF_ATTEMPTS_PER_BATCH",
    "BatchVerifierResult", "IssuedOperationStatement", "IssuedVerificationBatch", "OperationTemplate", "QueueBackpressureError", "QueueClock", "QueueConfig",
    "QueueConflictError", "QueueDeterministicRejectError", "QueueHeldError", "QueueIndeterminateError", "QueueIntegrityError", "QueueLeaseError", "QueueResult", "QueueRetryableError", "SystemQueueClock", "VerificationOutcome", "VerificationQueueError", "VerifierPort", "VolatileProofHandoff", "parse_batch_verifier_result", "_QueueRuntimeOwnership", "_VerificationQueueStore", "_compute_batch_root", "_build_statement", "_parse_receipt", "_reserve_proof_attempt", "BOOTSTRAP_CAPABILITY_LIMITATION_COUNT",
)
