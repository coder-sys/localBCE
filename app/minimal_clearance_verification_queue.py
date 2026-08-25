"""Queue/Proof Handoff V7.

The queue persists only a state-issued opaque operation reference and a small
allowlist of nonidentifying control metadata. Proof bytes are accepted through
one volatile, single-use stream and are never copied to a path, database,
receipt, event, export, log, or error. The verifier returns a narrow result;
state-owned disposition is deliberately outside this module.

This is an experimental, nonactivating boundary. No verifier backend is
qualified by this module.
"""

from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import time
from typing import Any, BinaryIO, Callable, Final, Mapping, NoReturn, Protocol


class VerificationQueueError(RuntimeError):
    """Fixed-code fail-closed queue error."""


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


SCHEMA_VERSION: Final[int] = 7
_SCHEMA: Final[str] = "BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/v7"
ADMISSION_CAP_BYTES: Final[int] = 4_500_000_000
PROCESS_TREE_PEAK_CAP_BYTES: Final[int] = 4_999_999_999
CAP_BYTES: Final[int] = 5_000_000_000
ACTIVE_PROCESS_LIMIT: Final[int] = 1
MAX_QUEUE_DATABASE_BYTES: Final[int] = 64 * 1024 * 1024
MAX_QUEUE_CAPACITY: Final[int] = 512
MAX_TERMINAL_GROWTH_PER_NONTERMINAL: Final[int] = 64 * 1024
MAX_RECEIPT_BYTES: Final[int] = 16 * 1024
MAX_ERROR_BYTES: Final[int] = 96
MAX_OPERATION_REF_BYTES: Final[int] = 32
_MAX_FLAGS = 16
_MAX_FLAG = 48
_MAX_ASSERTION = 96
_MAX_PROFILE_VERSION = 96
_MAX_QUEUE_ID = 96
_STAGING_LIMIT = 64 * 1024
_LEASE_MS: Final[int] = 3_600_000
_MAX_ATTEMPTS: Final[int] = 3
_RUNTIME_WORKER = "minimal-clearance-runtime-v7"
_SAFE_TOKEN = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
_SAFE_CODE = re.compile(r"[a-z][a-z0-9_]{0,95}\Z")

DIRECTIVES: Final[tuple[str, ...]] = (
    "CLEAR", "HOLD", "HUMAN_REVIEW", "BLOCK", "EXCEPTION_APPROVED",
)
_STATUSES: Final[frozenset[str]] = frozenset({"QUEUED", "LEASED", "VERIFIED", "REJECTED", "HELD"})
_MATERIAL = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/MATERIAL/v7\x00"
_GENESIS = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/GENESIS/v7\x00"
_EVENT = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/EVENT/v7\x00"
_HEAD = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/HEAD/v7\x00"
_RECEIPT = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/RECEIPT/v7\x00"
_LEASE = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/LEASE/v7\x00"
_FORBIDDEN_DISPOSITION_KEYS: Final[frozenset[str]] = frozenset({
    "policyResult", "policy_result", "effectiveDirective", "effective_directive",
})

BOOTSTRAP_CAPABILITY_LIMITATION_COUNT = 0


def _sha(domain: bytes, *parts: bytes) -> bytes:
    digest = hashlib.sha3_512()
    digest.update(domain)
    for part in parts:
        if type(part) is not bytes:
            _raise_fixed(QueueIntegrityError("queue_binding_type"))
        digest.update(part)
    return digest.digest()


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        _raise_fixed(QueueIntegrityError("queue_json_encoding"))


def _hex(value: bytes) -> str:
    return value.hex().upper()


def _parse_hex(value: object, size: int, code: str) -> bytes:
    if type(value) is not str or value != value.upper() or re.fullmatch(rf"[0-9A-F]{{{size * 2}}}\Z", value) is None:
        _raise_fixed(QueueIntegrityError(code))
    try:
        return bytes.fromhex(value)
    except ValueError:
        _raise_fixed(QueueIntegrityError(code))


def _token(value: object, label: str, maximum: int = 128) -> str:
    if type(value) is not str or not 1 <= len(value) <= maximum or _SAFE_TOKEN.fullmatch(value) is None:
        _raise_fixed(VerificationQueueError(label + "_invalid"))
    return value


def _code(value: object, label: str = "queue_error") -> str:
    if type(value) is not str or len(value) > MAX_ERROR_BYTES or _SAFE_CODE.fullmatch(value) is None:
        _raise_fixed(QueueIntegrityError(label + "_invalid"))
    return value


def _blob(value: object, size: int, label: str) -> bytes:
    if type(value) is not bytes or len(value) != size:
        _raise_fixed(VerificationQueueError(label + "_invalid"))
    return bytes(value)


class QueueClock(Protocol):
    def now_ms(self) -> int: ...


class SystemQueueClock:
    def now_ms(self) -> int:
        return time.time_ns() // 1_000_000


@dataclass(frozen=True, slots=True)
class QueueConfig:
    """Nonidentifying V7 queue policy."""

    queue_id: str
    capacity: int
    profile_digest: bytes | None = None
    profile_epoch: int = 7
    verifier_profile_version: str = "synthetic-v7-unqualified"

    def __post_init__(self) -> None:
        _token(self.queue_id, "queue_id", _MAX_QUEUE_ID)
        if type(self.capacity) is not int or not 1 <= self.capacity <= MAX_QUEUE_CAPACITY:
            _raise_fixed(VerificationQueueError("queue_capacity_invalid"))
        if type(self.profile_epoch) is not int or self.profile_epoch != 7:
            _raise_fixed(VerificationQueueError("queue_profile_epoch"))
        _token(self.verifier_profile_version, "verifier_profile_version", _MAX_PROFILE_VERSION)
        digest = _sha(_MATERIAL, self.verifier_profile_version.encode("ascii"))
        if self.profile_digest is None:
            object.__setattr__(self, "profile_digest", digest)
        elif type(self.profile_digest) is not bytes or len(self.profile_digest) != 64 or self.profile_digest != digest:
            _raise_fixed(VerificationQueueError("queue_profile_invalid"))

    @property
    def lease_seconds(self) -> int:
        return _LEASE_MS // 1000

    @property
    def max_attempts(self) -> int:
        return _MAX_ATTEMPTS

    @property
    def retryable_codes(self) -> tuple[str, ...]:
        return ("fresh_handoff_required", "verifier_timeout", "verifier_transport")

    @property
    def as_json(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "queue_id": self.queue_id,
            "capacity": self.capacity,
            "admission_cap_bytes": ADMISSION_CAP_BYTES,
            "process_tree_peak_cap_bytes": PROCESS_TREE_PEAK_CAP_BYTES,
            "active_process_limit": ACTIVE_PROCESS_LIMIT,
            "profile_version": self.verifier_profile_version,
            "profile_digest": _hex(self.profile_digest or bytes(64)),
            "profile_epoch": self.profile_epoch,
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
        return _sha(_MATERIAL, self.canonical_bytes)


@dataclass(frozen=True, slots=True)
class OperationStatement:
    """State-issued allowlisted statement; no caller identity or source bytes."""

    assertion_identifier: str
    assertion_version: int
    state_profile_version: str
    valid_from_ms: int
    valid_until_ms: int
    batch_position: int = 0
    batch_root: bytes | None = None
    approved_source_registry_root: bytes | None = None
    qualification_flags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _token(self.assertion_identifier, "assertion_identifier", _MAX_ASSERTION)
        if type(self.assertion_version) is not int or not 1 <= self.assertion_version <= 2**31:
            _raise_fixed(VerificationQueueError("assertion_version_invalid"))
        _token(self.state_profile_version, "state_profile_version", _MAX_PROFILE_VERSION)
        if type(self.valid_from_ms) is not int or type(self.valid_until_ms) is not int or not 0 <= self.valid_from_ms < self.valid_until_ms:
            _raise_fixed(VerificationQueueError("validity_window_invalid"))
        if type(self.batch_position) is not int or not 0 <= self.batch_position < 256:
            _raise_fixed(VerificationQueueError("batch_position_invalid"))
        if self.batch_root is not None:
            _blob(self.batch_root, 64, "batch_root")
        if self.approved_source_registry_root is not None:
            _blob(self.approved_source_registry_root, 64, "source_registry_root")
        if type(self.qualification_flags) is not tuple or len(self.qualification_flags) > _MAX_FLAGS or tuple(sorted(self.qualification_flags)) != self.qualification_flags or len(set(self.qualification_flags)) != len(self.qualification_flags):
            _raise_fixed(VerificationQueueError("qualification_flags_invalid"))
        for flag in self.qualification_flags:
            _token(flag, "qualification_flag", _MAX_FLAG)

    @property
    def as_json(self) -> dict[str, Any]:
        return {
            "assertion_identifier": self.assertion_identifier,
            "assertion_version": self.assertion_version,
            "state_profile_version": self.state_profile_version,
            "valid_from_ms": self.valid_from_ms,
            "valid_until_ms": self.valid_until_ms,
            "batch_position": self.batch_position,
            "batch_root": None if self.batch_root is None else _hex(self.batch_root),
            "approved_source_registry_root": None if self.approved_source_registry_root is None else _hex(self.approved_source_registry_root),
            "qualification_flags": list(self.qualification_flags),
        }


class VolatileProofHandoff:
    """Single-use readable stream with mutable bounded staging only."""

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
    def closed(self) -> bool:
        return self._closed

    def _assert_open(self) -> None:
        if self._closed:
            _raise_fixed(QueueHeldError("proof_handoff_closed"))
        if not self._used:
            self._used = True

    def read(self, size: int = -1) -> bytes:
        self._assert_open()
        if self._eof:
            return b""
        if type(size) is not int:
            _raise_fixed(QueueHeldError("proof_handoff_read"))
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
        retained = value[-_STAGING_LIMIT:]
        if len(self._staging) + len(retained) > _STAGING_LIMIT:
            del self._staging[:len(self._staging) + len(retained) - _STAGING_LIMIT]
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

    def __enter__(self) -> "VolatileProofHandoff":
        return self

    def __exit__(self, _exc_type: object, _exc: object, _tb: object) -> None:
        self.close()


@dataclass(frozen=True, slots=True)
class VerifierResult:
    proof_accepted: bool
    operation_ref: bytes
    assertion_identifier: str
    assertion_version: int
    state_profile_version: str
    valid_from_ms: int
    valid_until_ms: int
    batch_position: int
    batch_root: bytes | None
    verifier_profile_version: str
    outcome_code: str
    error_code: str | None = None
    resource_code: str | None = None
    qualification_flags: tuple[str, ...] = ()

    @property
    def as_json(self) -> dict[str, Any]:
        return {
            "proof_accepted": self.proof_accepted,
            "operation_ref": _hex(self.operation_ref),
            "assertion_identifier": self.assertion_identifier,
            "assertion_version": self.assertion_version,
            "state_profile_version": self.state_profile_version,
            "valid_from_ms": self.valid_from_ms,
            "valid_until_ms": self.valid_until_ms,
            "batch_position": self.batch_position,
            "batch_root": None if self.batch_root is None else _hex(self.batch_root),
            "verifier_profile_version": self.verifier_profile_version,
            "outcome_code": self.outcome_code,
            "error_code": self.error_code,
            "resource_code": self.resource_code,
            "qualification_flags": list(self.qualification_flags),
        }

    @property
    def canonical_bytes(self) -> bytes:
        return _json_bytes(self.as_json)


_VERIFIER_RESULT_KEYS: Final[frozenset[str]] = frozenset({
    "proof_accepted", "operation_ref", "assertion_identifier", "assertion_version",
    "state_profile_version", "valid_from_ms", "valid_until_ms", "batch_position",
    "batch_root", "verifier_profile_version", "outcome_code", "error_code",
    "resource_code", "qualification_flags",
})


def parse_verifier_result(value: object) -> VerifierResult:
    if isinstance(value, VerifierResult):
        result = value
    elif type(value) is dict:
        if set(value) != _VERIFIER_RESULT_KEYS or _FORBIDDEN_DISPOSITION_KEYS.intersection(value):
            _raise_fixed(QueueHeldError("verifier_result_unknown_field"))
        try:
            if type(value["proof_accepted"]) is not bool or type(value["assertion_identifier"]) is not str or type(value["assertion_version"]) is not int or type(value["state_profile_version"]) is not str or type(value["valid_from_ms"]) is not int or type(value["valid_until_ms"]) is not int or type(value["batch_position"]) is not int or type(value["verifier_profile_version"]) is not str or type(value["outcome_code"]) is not str or (value["error_code"] is not None and type(value["error_code"]) is not str) or (value["resource_code"] is not None and type(value["resource_code"]) is not str) or type(value["qualification_flags"]) is not list:
                _raise_fixed(QueueHeldError("verifier_result_shape"))
            batch_root = None if value["batch_root"] is None else _parse_hex(value["batch_root"], 64, "verifier_batch_root")
            flags = tuple(value["qualification_flags"])
            result = VerifierResult(
                bool(value["proof_accepted"]), _parse_hex(value["operation_ref"], 32, "verifier_operation_ref"),
                str(value["assertion_identifier"]), int(value["assertion_version"]), str(value["state_profile_version"]),
                int(value["valid_from_ms"]), int(value["valid_until_ms"]), int(value["batch_position"]), batch_root,
                str(value["verifier_profile_version"]), str(value["outcome_code"]),
                None if value["error_code"] is None else str(value["error_code"]),
                None if value["resource_code"] is None else str(value["resource_code"]), flags,
            )
        except (KeyError, TypeError, ValueError):
            _raise_fixed(QueueHeldError("verifier_result_shape"))
    else:
        _raise_fixed(QueueHeldError("verifier_result_shape"))
    if type(result.proof_accepted) is not bool:
        _raise_fixed(QueueHeldError("verifier_result_shape"))
    _blob(result.operation_ref, 32, "verifier_operation_ref")
    _token(result.assertion_identifier, "verifier_assertion_identifier", _MAX_ASSERTION)
    if type(result.assertion_version) is not int or result.assertion_version < 1:
        _raise_fixed(QueueHeldError("verifier_result_shape"))
    _token(result.state_profile_version, "verifier_state_profile", _MAX_PROFILE_VERSION)
    if type(result.valid_from_ms) is not int or type(result.valid_until_ms) is not int or not 0 <= result.valid_from_ms < result.valid_until_ms:
        _raise_fixed(QueueHeldError("verifier_result_shape"))
    if type(result.batch_position) is not int or not 0 <= result.batch_position < 256:
        _raise_fixed(QueueHeldError("verifier_result_shape"))
    if result.batch_root is not None:
        _blob(result.batch_root, 64, "verifier_batch_root")
    _token(result.verifier_profile_version, "verifier_profile_version", _MAX_PROFILE_VERSION)
    _code(result.outcome_code, "verifier_outcome_code")
    if result.error_code is not None:
        _code(result.error_code, "verifier_error_code")
    if result.resource_code is not None:
        _code(result.resource_code, "verifier_resource_code")
    if type(result.qualification_flags) is not tuple or tuple(sorted(result.qualification_flags)) != result.qualification_flags or len(set(result.qualification_flags)) != len(result.qualification_flags):
        _raise_fixed(QueueHeldError("verifier_result_flags"))
    for flag in result.qualification_flags:
        _token(flag, "verifier_flag", _MAX_FLAG)
    return result


class VerifierPort(Protocol):
    def verify(self, stream: VolatileProofHandoff, statement: OperationStatement, operation_ref: bytes) -> VerifierResult | Mapping[str, Any]: ...


@dataclass(frozen=True, slots=True)
class QueueJob:
    operation_ref: bytes
    statement: OperationStatement
    status: str
    admission_seq: int
    attempt: int
    next_eligible_ms: int
    last_error_code: str | None = None

@dataclass(frozen=True, slots=True)
class QueueResult:
    operation_ref: bytes
    status: str
    receipt_bytes: bytes | None
    error_code: str | None

@dataclass(frozen=True, slots=True)
class _QueueWorkItem:
    operation_ref: bytes
    statement: OperationStatement
    attempt: int
    worker_id: str
    claim_sequence: int
    lease_token: bytes = field(repr=False)
    lease_expires_ms: int

class _QueueRuntimeOwnership:
    """One process owner for the durable queue; the lock contains no proof data."""

    def __init__(self, *, lock_path: Path, parent: Path) -> None:
        if not isinstance(lock_path, Path) or not isinstance(parent, Path) or lock_path.parent != parent or not parent.is_dir():
            _raise_fixed(VerificationQueueError("queue_owner"))
        self.lock_path = lock_path
        self._closed = False
        try:
            self._descriptor = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.write(self._descriptor, b"BL/NATIVE-V3/QUEUE-OWNER/v7\x00")
        except FileExistsError:
            _raise_fixed(VerificationQueueError("queue_owner"))
        except OSError:
            _raise_fixed(VerificationQueueError("queue_owner"))

    def assert_scope(self, *, lock_path: Path, parent: Path) -> None:
        if self._closed or lock_path != self.lock_path or parent != self.lock_path.parent:
            _raise_fixed(VerificationQueueError("queue_owner"))

    def assert_live(self) -> None:
        self.assert_scope(lock_path=self.lock_path, parent=self.lock_path.parent)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            os.close(self._descriptor)
        finally:
            try:
                self.lock_path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                _raise_fixed(VerificationQueueError("queue_owner_close"))


_TABLE_COLUMNS: Final[dict[str, tuple[str, ...]]] = {
    "queue_metadata": ("id", "schema_version", "queue_id", "config_json", "config_digest", "admission_cap_bytes", "process_tree_peak_cap_bytes", "active_process_limit", "profile_version", "profile_digest", "head_root", "next_transition_seq", "next_admission_seq", "nonterminal_count", "live_lease_count"),
    "queue_jobs": ("operation_ref", "assertion_identifier", "assertion_version", "state_profile_version", "valid_from_ms", "valid_until_ms", "batch_position", "batch_root", "approved_source_registry_root", "qualification_flags", "status", "admission_seq", "attempt", "next_eligible_ms", "created_ms", "updated_ms", "last_error_code"),
    "queue_leases": ("operation_ref", "worker_id", "token_digest", "attempt", "claim_sequence", "leased_ms", "expires_ms"),
    "queue_results": ("operation_ref", "terminal_status", "receipt_bytes", "error_code", "completed_ms", "attempt"),
    "queue_transitions": ("sequence", "transition_kind", "operation_ref", "before_root", "after_root", "event_bytes", "event_digest"),
}
_TABLES = frozenset(_TABLE_COLUMNS)


def _create_schema(connection: sqlite3.Connection) -> None:
    statements = (
        "CREATE TABLE queue_metadata (id INTEGER PRIMARY KEY CHECK(id=1), schema_version INTEGER NOT NULL CHECK(schema_version=7), queue_id TEXT NOT NULL, config_json BLOB NOT NULL, config_digest BLOB NOT NULL CHECK(length(config_digest)=64), admission_cap_bytes INTEGER NOT NULL CHECK(admission_cap_bytes=4500000000), process_tree_peak_cap_bytes INTEGER NOT NULL CHECK(process_tree_peak_cap_bytes<5000000000), active_process_limit INTEGER NOT NULL CHECK(active_process_limit=1), profile_version TEXT NOT NULL, profile_digest BLOB NOT NULL CHECK(length(profile_digest)=64), head_root BLOB NOT NULL CHECK(length(head_root)=64), next_transition_seq INTEGER NOT NULL CHECK(next_transition_seq>=0), next_admission_seq INTEGER NOT NULL CHECK(next_admission_seq>=0), nonterminal_count INTEGER NOT NULL CHECK(nonterminal_count>=0), live_lease_count INTEGER NOT NULL CHECK(live_lease_count BETWEEN 0 AND 1))",
        "CREATE TABLE queue_jobs (operation_ref BLOB PRIMARY KEY CHECK(length(operation_ref)=32), assertion_identifier TEXT NOT NULL, assertion_version INTEGER NOT NULL CHECK(assertion_version>=1), state_profile_version TEXT NOT NULL, valid_from_ms INTEGER NOT NULL CHECK(valid_from_ms>=0), valid_until_ms INTEGER NOT NULL CHECK(valid_until_ms>valid_from_ms), batch_position INTEGER NOT NULL CHECK(batch_position BETWEEN 0 AND 255), batch_root BLOB CHECK(batch_root IS NULL OR length(batch_root)=64), approved_source_registry_root BLOB CHECK(approved_source_registry_root IS NULL OR length(approved_source_registry_root)=64), qualification_flags BLOB NOT NULL, status TEXT NOT NULL CHECK(status IN ('QUEUED','LEASED','VERIFIED','REJECTED','HELD')), admission_seq INTEGER NOT NULL UNIQUE CHECK(admission_seq>=1), attempt INTEGER NOT NULL CHECK(attempt BETWEEN 0 AND 3), next_eligible_ms INTEGER NOT NULL CHECK(next_eligible_ms>=0), created_ms INTEGER NOT NULL CHECK(created_ms>=0), updated_ms INTEGER NOT NULL CHECK(updated_ms>=0), last_error_code TEXT)",
        "CREATE TABLE queue_leases (operation_ref BLOB PRIMARY KEY CHECK(length(operation_ref)=32), worker_id TEXT NOT NULL, token_digest BLOB NOT NULL CHECK(length(token_digest)=64), attempt INTEGER NOT NULL CHECK(attempt BETWEEN 1 AND 3), claim_sequence INTEGER NOT NULL UNIQUE CHECK(claim_sequence>=1), leased_ms INTEGER NOT NULL CHECK(leased_ms>=0), expires_ms INTEGER NOT NULL CHECK(expires_ms>leased_ms), FOREIGN KEY(operation_ref) REFERENCES queue_jobs(operation_ref))",
        "CREATE TABLE queue_results (operation_ref BLOB PRIMARY KEY CHECK(length(operation_ref)=32), terminal_status TEXT NOT NULL CHECK(terminal_status IN ('VERIFIED','REJECTED','HELD')), receipt_bytes BLOB CHECK(receipt_bytes IS NULL OR length(receipt_bytes)<=16384), error_code TEXT, completed_ms INTEGER NOT NULL CHECK(completed_ms>=0), attempt INTEGER NOT NULL CHECK(attempt BETWEEN 1 AND 3), FOREIGN KEY(operation_ref) REFERENCES queue_jobs(operation_ref), CHECK((terminal_status='VERIFIED' AND receipt_bytes IS NOT NULL AND error_code IS NULL) OR (terminal_status IN ('REJECTED','HELD') AND receipt_bytes IS NULL AND error_code IS NOT NULL)))",
        "CREATE TABLE queue_transitions (sequence INTEGER PRIMARY KEY CHECK(sequence>=1), transition_kind TEXT NOT NULL, operation_ref BLOB CHECK(operation_ref IS NULL OR length(operation_ref)=32), before_root BLOB NOT NULL CHECK(length(before_root)=64), after_root BLOB NOT NULL CHECK(length(after_root)=64), event_bytes BLOB NOT NULL CHECK(length(event_bytes)<=4096), event_digest BLOB NOT NULL UNIQUE CHECK(length(event_digest)=64), FOREIGN KEY(operation_ref) REFERENCES queue_jobs(operation_ref))",
        "CREATE INDEX queue_jobs_status_eligible ON queue_jobs(status,next_eligible_ms,admission_seq)",
        "CREATE INDEX queue_leases_expiry ON queue_leases(expires_ms,operation_ref)",
        "CREATE UNIQUE INDEX queue_leases_worker_unique ON queue_leases(worker_id)",
        "CREATE TRIGGER queue_jobs_no_delete BEFORE DELETE ON queue_jobs BEGIN SELECT RAISE(ABORT,'queue_jobs_append_only'); END",
        "CREATE TRIGGER queue_jobs_identity_guard BEFORE UPDATE OF operation_ref,assertion_identifier,assertion_version,state_profile_version,valid_from_ms,valid_until_ms,batch_position,batch_root,approved_source_registry_root,qualification_flags,admission_seq ON queue_jobs BEGIN SELECT RAISE(ABORT,'queue_jobs_identity_immutable'); END",
        "CREATE TRIGGER queue_results_no_update BEFORE UPDATE ON queue_results BEGIN SELECT RAISE(ABORT,'queue_results_immutable'); END",
        "CREATE TRIGGER queue_results_no_delete BEFORE DELETE ON queue_results BEGIN SELECT RAISE(ABORT,'queue_results_immutable'); END",
        "CREATE TRIGGER queue_transitions_no_update BEFORE UPDATE ON queue_transitions BEGIN SELECT RAISE(ABORT,'queue_transitions_append_only'); END",
        "CREATE TRIGGER queue_transitions_no_delete BEFORE DELETE ON queue_transitions BEGIN SELECT RAISE(ABORT,'queue_transitions_append_only'); END",
    )
    for statement in statements:
        connection.execute(statement)


def _columns(connection: sqlite3.Connection, table: str) -> tuple[str, ...]:
    return tuple(str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})").fetchall())


def _safe_flags(flags: tuple[str, ...]) -> bytes:
    return _json_bytes({"qualification_flags": list(flags)})


def _parse_flags(raw: bytes) -> tuple[str, ...]:
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _raise_fixed(QueueIntegrityError("qualification_flags_encoding"))
    if type(value) is not dict or set(value) != {"qualification_flags"} or type(value["qualification_flags"]) is not list:
        _raise_fixed(QueueIntegrityError("qualification_flags_shape"))
    flags = tuple(value["qualification_flags"])
    if tuple(sorted(flags)) != flags or len(set(flags)) != len(flags):
        _raise_fixed(QueueIntegrityError("qualification_flags_shape"))
    for flag in flags:
        _token(flag, "qualification_flag", _MAX_FLAG)
    return flags


def _statement_from_row(row: tuple[Any, ...]) -> OperationStatement:
    return OperationStatement(str(row[1]), int(row[2]), str(row[3]), int(row[4]), int(row[5]), int(row[6]), None if row[7] is None else bytes(row[7]), None if row[8] is None else bytes(row[8]), _parse_flags(bytes(row[9])))


class _VerificationQueueStore:
    """Sole durable queue writer; proof handoffs remain process-local."""

    def __init__(self, *, path: Path, config: QueueConfig, owner: _QueueRuntimeOwnership | None = None, clock: QueueClock | None = None, before_fault: Callable[[str], None] | None = None, after_commit_fault: Callable[[str], None] | None = None) -> None:
        if not isinstance(path, Path) or not isinstance(config, QueueConfig) or not isinstance(owner, _QueueRuntimeOwnership):
            _raise_fixed(VerificationQueueError("queue_configuration"))
        if not path.is_absolute() or not path.parent.is_dir():
            _raise_fixed(VerificationQueueError("queue_database_path"))
        owner.assert_scope(lock_path=path.with_name(path.name + ".runtime-lock"), parent=path.parent)
        self.path = path
        self.config = config
        self._owner = owner
        self.clock = clock or SystemQueueClock()
        self._before_fault = before_fault
        self._after_commit_fault = after_commit_fault
        self._handoffs: dict[bytes, VolatileProofHandoff] = {}
        self._closed = False
        if not path.exists():
            self._bootstrap()
        else:
            self._schema_check()
            self._recover_startup_leases()

    def _assert_owner(self) -> None:
        if self._closed:
            _raise_fixed(VerificationQueueError("queue_closed"))
        self._owner.assert_live()

    def _connect(self) -> sqlite3.Connection:
        self._assert_owner()
        try:
            connection = sqlite3.connect(str(self.path), timeout=5.0, isolation_level=None)
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA busy_timeout=5000")
            if str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower() != "delete":
                connection.close()
                _raise_fixed(VerificationQueueError("queue_journal"))
            return connection
        except sqlite3.Error:
            _raise_fixed(VerificationQueueError("queue_database"))

    def _schema_check(self) -> None:
        with closing(sqlite3.connect(str(self.path), timeout=5.0)) as connection:
            tables = {str(row[0]) for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
            if tables != frozenset(_TABLE_COLUMNS) or any(_columns(connection, table) != _TABLE_COLUMNS[table] for table in _TABLE_COLUMNS):
                _raise_fixed(QueueIntegrityError("queue_schema"))
            row = connection.execute("SELECT schema_version,queue_id,config_json,config_digest FROM queue_metadata WHERE id=1").fetchone()
            if row is None or int(row[0]) != SCHEMA_VERSION or str(row[1]) != self.config.queue_id or bytes(row[3]) != self.config.digest or bytes(row[2]) != self.config.canonical_bytes:
                _raise_fixed(QueueIntegrityError("queue_schema"))

    def _bootstrap(self) -> None:
        self._assert_owner()
        connection = sqlite3.connect(str(self.path), timeout=5.0, isolation_level=None)
        try:
            connection.execute("PRAGMA page_size=4096")
            connection.execute("PRAGMA max_page_count=16384")
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("BEGIN IMMEDIATE")
            _create_schema(connection)
            head = _sha(_GENESIS, self.config.queue_id.encode("ascii"), self.config.digest)
            connection.execute("INSERT INTO queue_metadata VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (1, SCHEMA_VERSION, self.config.queue_id, self.config.canonical_bytes, self.config.digest, ADMISSION_CAP_BYTES, PROCESS_TREE_PEAK_CAP_BYTES, ACTIVE_PROCESS_LIMIT, self.config.verifier_profile_version, self.config.profile_digest, head, 0, 0, 0, 0))
            connection.execute("COMMIT")
        except sqlite3.Error:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            try:
                self.path.unlink()
            except OSError:
                pass
            _raise_fixed(VerificationQueueError("queue_bootstrap"))
        finally:
            connection.close()
        self._schema_check()

    def _meta(self, connection: sqlite3.Connection) -> tuple[Any, ...]:
        row = connection.execute("SELECT * FROM queue_metadata WHERE id=1").fetchone()
        if row is None or len(row) != len(_TABLE_COLUMNS["queue_metadata"]):
            _raise_fixed(QueueIntegrityError("queue_metadata"))
        return tuple(row)

    def _fault(self, label: str) -> None:
        if self._before_fault is not None:
            self._before_fault(label)

    def _after_commit(self, label: str) -> None:
        if self._after_commit_fault is not None:
            self._after_commit_fault(label)

    def _append_event(self, connection: sqlite3.Connection, *, kind: str, operation_ref: bytes | None, status: str | None, error_code: str | None, attempt: int, at_ms: int) -> None:
        meta = self._meta(connection)
        sequence = int(meta[11]) + 1
        before = bytes(meta[10])
        event = {"schema": _SCHEMA, "sequence": sequence, "kind": kind, "operation_ref": None if operation_ref is None else _hex(operation_ref), "status": status, "error_code": error_code, "attempt": attempt, "at_ms": at_ms}
        raw = _json_bytes(event)
        digest = _sha(_EVENT, _u64(sequence), raw)
        after = _sha(_HEAD, before, _u64(sequence), digest)
        connection.execute("INSERT INTO queue_transitions VALUES (?,?,?,?,?,?,?)", (sequence, kind, operation_ref, before, after, raw, digest))
        updated = connection.execute("UPDATE queue_metadata SET head_root=?,next_transition_seq=? WHERE id=1 AND head_root=? AND next_transition_seq=?", (after, sequence, before, sequence - 1))
        if updated.rowcount != 1:
            _raise_fixed(QueueIntegrityError("queue_head"))

    @staticmethod
    def _row_to_job(row: tuple[Any, ...]) -> QueueJob:
        return QueueJob(bytes(row[0]), _statement_from_row(row), str(row[10]), int(row[11]), int(row[12]), int(row[13]), None if row[16] is None else str(row[16]))

    def _get_job_locked(self, connection: sqlite3.Connection, operation_ref: bytes) -> QueueJob | None:
        row = connection.execute("SELECT * FROM queue_jobs WHERE operation_ref=?", (operation_ref,)).fetchone()
        return None if row is None else self._row_to_job(tuple(row))

    def _admit(self, *, statement: OperationStatement, handoff: VolatileProofHandoff) -> QueueJob:
        self._assert_owner()
        if type(statement) is not OperationStatement or type(handoff) is not VolatileProofHandoff:
            _raise_fixed(VerificationQueueError("queue_admission_shape"))
        operation_ref = secrets.token_bytes(MAX_OPERATION_REF_BYTES)
        now = int(self.clock.now_ms())
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                meta = self._meta(connection)
                if int(meta[13]) >= self.config.capacity:
                    connection.execute("ROLLBACK")
                    handoff.close()
                    _raise_fixed(QueueBackpressureError("queue_capacity"))
                admission_seq = int(meta[12]) + 1
                connection.execute("INSERT INTO queue_jobs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (operation_ref, statement.assertion_identifier, statement.assertion_version, statement.state_profile_version, statement.valid_from_ms, statement.valid_until_ms, statement.batch_position, statement.batch_root, statement.approved_source_registry_root, _safe_flags(statement.qualification_flags), "QUEUED", admission_seq, 0, now, now, now, None))
                self._append_event(connection, kind="ADMITTED", operation_ref=operation_ref, status="QUEUED", error_code=None, attempt=0, at_ms=now)
                meta = self._meta(connection)
                connection.execute("UPDATE queue_metadata SET next_admission_seq=?,nonterminal_count=? WHERE id=1", (admission_seq, int(meta[13]) + 1))
                connection.execute("COMMIT")
            except QueueBackpressureError:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                handoff.close()
                raise
            except (VerificationQueueError, sqlite3.Error):
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                handoff.close()
                _raise_fixed(VerificationQueueError("queue_admission"))
        self._handoffs[operation_ref] = handoff
        self._after_commit("admit")
        return QueueJob(operation_ref, statement, "QUEUED", admission_seq, 0, now, None)

    def admit(self, *, statement: OperationStatement, proof_stream: BinaryIO | VolatileProofHandoff, declared_length: int | None = None) -> QueueJob:
        handoff = proof_stream if isinstance(proof_stream, VolatileProofHandoff) else VolatileProofHandoff(proof_stream, declared_length=declared_length)
        return self._admit(statement=statement, handoff=handoff)

    def admit_batch(self, *, statements: tuple[OperationStatement, ...], proof_streams: tuple[BinaryIO | VolatileProofHandoff, ...], declared_lengths: tuple[int | None, ...] | None = None) -> tuple[QueueJob, ...]:
        if type(statements) is not tuple or type(proof_streams) is not tuple or len(statements) != len(proof_streams) or not 1 <= len(statements) <= 256:
            _raise_fixed(VerificationQueueError("queue_batch_shape"))
        if tuple(statement.batch_position for statement in statements) != tuple(range(len(statements))):
            _raise_fixed(VerificationQueueError("queue_batch_order"))
        lengths = declared_lengths or (None,) * len(statements)
        if len(lengths) != len(statements):
            _raise_fixed(VerificationQueueError("queue_batch_shape"))
        handoffs: list[VolatileProofHandoff] = []
        try:
            for statement, stream, length in zip(statements, proof_streams, lengths):
                if type(statement) is not OperationStatement:
                    _raise_fixed(VerificationQueueError("queue_admission_shape"))
                handoffs.append(stream if isinstance(stream, VolatileProofHandoff) else VolatileProofHandoff(stream, declared_length=length))
            self._assert_owner()
            refs = tuple(secrets.token_bytes(MAX_OPERATION_REF_BYTES) for _ in statements)
            now = int(self.clock.now_ms())
            jobs: list[QueueJob] = []
            with closing(self._connect()) as connection:
                try:
                    connection.execute("BEGIN IMMEDIATE")
                    meta = self._meta(connection)
                    if int(meta[13]) + len(statements) > self.config.capacity:
                        _raise_fixed(QueueBackpressureError("queue_capacity"))
                    admission_seq = int(meta[12])
                    for ref, statement, handoff in zip(refs, statements, handoffs):
                        admission_seq += 1
                        connection.execute("INSERT INTO queue_jobs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (ref, statement.assertion_identifier, statement.assertion_version, statement.state_profile_version, statement.valid_from_ms, statement.valid_until_ms, statement.batch_position, statement.batch_root, statement.approved_source_registry_root, _safe_flags(statement.qualification_flags), "QUEUED", admission_seq, 0, now, now, now, None))
                        self._append_event(connection, kind="ADMITTED", operation_ref=ref, status="QUEUED", error_code=None, attempt=0, at_ms=now)
                        jobs.append(QueueJob(ref, statement, "QUEUED", admission_seq, 0, now, None))
                    connection.execute("UPDATE queue_metadata SET next_admission_seq=?,nonterminal_count=? WHERE id=1", (admission_seq, int(meta[13]) + len(statements)))
                    connection.execute("COMMIT")
                except QueueBackpressureError:
                    if connection.in_transaction:
                        connection.execute("ROLLBACK")
                    raise
                except (VerificationQueueError, sqlite3.Error):
                    if connection.in_transaction:
                        connection.execute("ROLLBACK")
                    _raise_fixed(VerificationQueueError("queue_admission"))
            for ref, handoff in zip(refs, handoffs):
                self._handoffs[ref] = handoff
            self._after_commit("admit_batch")
            return tuple(jobs)
        except BaseException:
            for handoff in handoffs:
                if not handoff.closed:
                    handoff.close()
            raise

    def _claim_next(self) -> _QueueWorkItem | None:
        self._assert_owner()
        now = int(self.clock.now_ms())
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                self._expire_locked(connection, now)
                row = connection.execute("SELECT * FROM queue_jobs WHERE status='QUEUED' AND next_eligible_ms<=? ORDER BY admission_seq LIMIT 1", (now,)).fetchone()
                if row is None:
                    connection.execute("COMMIT")
                    return None
                job = self._row_to_job(tuple(row))
                attempt = job.attempt + 1
                token = secrets.token_bytes(32)
                claim_seq = int(self._meta(connection)[11]) + 1
                expires = now + _LEASE_MS
                digest = hmac.new(token, _sha(_LEASE, self.config.digest, job.operation_ref, _u64(attempt), _u64(claim_seq), _u64(now), _u64(expires)), hashlib.sha3_512).digest()
                connection.execute("INSERT INTO queue_leases VALUES (?,?,?,?,?,?,?)", (job.operation_ref, _RUNTIME_WORKER, digest, attempt, claim_seq, now, expires))
                connection.execute("UPDATE queue_jobs SET status='LEASED',attempt=?,updated_ms=? WHERE operation_ref=? AND status='QUEUED'", (attempt, now, job.operation_ref))
                self._append_event(connection, kind="LEASED", operation_ref=job.operation_ref, status="LEASED", error_code=None, attempt=attempt, at_ms=now)
                connection.execute("UPDATE queue_metadata SET live_lease_count=1 WHERE id=1")
                connection.execute("COMMIT")
            except (VerificationQueueError, sqlite3.Error):
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                _raise_fixed(VerificationQueueError("queue_claim"))
        return _QueueWorkItem(job.operation_ref, job.statement, attempt, _RUNTIME_WORKER, claim_seq, token, expires)

    def _expire_locked(self, connection: sqlite3.Connection, now: int) -> int:
        rows = connection.execute("SELECT operation_ref,attempt FROM queue_jobs WHERE status='LEASED' AND operation_ref IN (SELECT operation_ref FROM queue_leases WHERE expires_ms<=?)", (now,)).fetchall()
        for ref, attempt in rows:
            ref = bytes(ref)
            connection.execute("DELETE FROM queue_leases WHERE operation_ref=?", (ref,))
            connection.execute("UPDATE queue_jobs SET status='HELD',updated_ms=?,last_error_code=? WHERE operation_ref=? AND status='LEASED'", (now, "fresh_handoff_required", ref))
            connection.execute("INSERT INTO queue_results VALUES (?,?,?,?,?,?)", (ref, "HELD", None, "fresh_handoff_required", now, int(attempt)))
            self._append_event(connection, kind="LEASE_EXPIRED", operation_ref=ref, status="HELD", error_code="fresh_handoff_required", attempt=int(attempt), at_ms=now)
            handoff = self._handoffs.pop(ref, None)
            if handoff is not None:
                handoff.close()
        if rows:
            meta = self._meta(connection)
            connection.execute("UPDATE queue_metadata SET live_lease_count=0,nonterminal_count=? WHERE id=1", (max(0, int(meta[13]) - len(rows)),))
        return len(rows)

    def _recover_startup_leases(self) -> int:
        self._assert_owner()
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            count = self._expire_locked(connection, int(self.clock.now_ms()) + _LEASE_MS + 1)
            connection.execute("COMMIT")
        self._handoffs.clear()
        return count

    def _lease_live(self, connection: sqlite3.Connection, work: _QueueWorkItem) -> None:
        row = connection.execute("SELECT * FROM queue_jobs WHERE operation_ref=?", (work.operation_ref,)).fetchone()
        lease = connection.execute("SELECT worker_id,token_digest,attempt,claim_sequence,leased_ms,expires_ms FROM queue_leases WHERE operation_ref=?", (work.operation_ref,)).fetchone()
        if row is None or lease is None or str(row[10]) != "LEASED" or int(row[12]) != work.attempt or str(lease[0]) != work.worker_id or int(lease[2]) != work.attempt or int(lease[3]) != work.claim_sequence or int(lease[5]) != work.lease_expires_ms:
            _raise_fixed(QueueLeaseError("completion_not_live"))
        if int(lease[5]) <= int(self.clock.now_ms()):
            self._expire_locked(connection, int(self.clock.now_ms()))
            connection.execute("COMMIT")
            _raise_fixed(QueueLeaseError("lease_expired"))
        expected = hmac.new(work.lease_token, _sha(_LEASE, self.config.digest, work.operation_ref, _u64(work.attempt), _u64(work.claim_sequence), _u64(int(lease[4])), _u64(int(lease[5]))), hashlib.sha3_512).digest()
        if bytes(lease[1]) != expected:
            _raise_fixed(QueueLeaseError("completion_lease_fence"))

    def _receipt(self, result: VerifierResult) -> bytes:
        value = {
            "schema": _SCHEMA,
            **result.as_json,
            "proof_suite_id": None,
            "production_usable": False,
            "activation": False,
        }
        raw = _json_bytes(value)
        if len(raw) > MAX_RECEIPT_BYTES:
            _raise_fixed(QueueHeldError("receipt_cap"))
        return raw

    def _complete(self, work: _QueueWorkItem, *, status: str, result: VerifierResult | None = None, error_code: str | None = None) -> QueueResult:
        if status not in {"VERIFIED", "REJECTED", "HELD"}:
            _raise_fixed(QueueIntegrityError("completion_status"))
        code = None if error_code is None else _code(error_code)
        receipt = self._receipt(result) if status == "VERIFIED" and result is not None else None
        if status == "VERIFIED" and receipt is None:
            _raise_fixed(QueueIntegrityError("completion_receipt"))
        if status in {"REJECTED", "HELD"} and code is None:
            code = "proof_rejected" if status == "REJECTED" else "fresh_handoff_required"
        now = int(self.clock.now_ms())
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                self._lease_live(connection, work)
                connection.execute("DELETE FROM queue_leases WHERE operation_ref=?", (work.operation_ref,))
                connection.execute("UPDATE queue_jobs SET status=?,updated_ms=?,last_error_code=? WHERE operation_ref=? AND status='LEASED'", (status, now, code, work.operation_ref))
                connection.execute("INSERT INTO queue_results VALUES (?,?,?,?,?,?)", (work.operation_ref, status, receipt, code, now, work.attempt))
                self._append_event(connection, kind="COMPLETED", operation_ref=work.operation_ref, status=status, error_code=code, attempt=work.attempt, at_ms=now)
                meta = self._meta(connection)
                connection.execute("UPDATE queue_metadata SET live_lease_count=0,nonterminal_count=? WHERE id=1", (max(0, int(meta[13]) - 1),))
                self._fault("after_result_write")
                connection.execute("COMMIT")
            except (QueueLeaseError, QueueIntegrityError, QueueHeldError, VerificationQueueError):
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
            except sqlite3.Error:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                _raise_fixed(QueueIndeterminateError("queue_completion_indeterminate"))
        self._after_commit("complete")
        return QueueResult(work.operation_ref, status, receipt, code)

    def _process_one(self, *, verifier: VerifierPort) -> QueueResult | None:
        self._assert_owner()
        work = self._claim_next()
        if work is None:
            return None
        handoff = self._handoffs.pop(work.operation_ref, None)
        if handoff is None:
            return self._complete(work, status="HELD", error_code="fresh_handoff_required")
        try:
            try:
                result = parse_verifier_result(verifier.verify(handoff, work.statement, work.operation_ref))
                if result.operation_ref != work.operation_ref or result.assertion_identifier != work.statement.assertion_identifier or result.assertion_version != work.statement.assertion_version or result.state_profile_version != work.statement.state_profile_version or result.valid_from_ms != work.statement.valid_from_ms or result.valid_until_ms != work.statement.valid_until_ms or result.batch_position != work.statement.batch_position or result.batch_root != work.statement.batch_root or result.qualification_flags != work.statement.qualification_flags:
                    raise QueueHeldError("verifier_statement_mismatch")
                handoff.drain()
            except QueueDeterministicRejectError:
                return self._complete(work, status="REJECTED", error_code="proof_rejected")
            except QueueHeldError as exc:
                allowed = {"proof_handoff_oversize", "proof_handoff_length", "verifier_result_unknown_field", "verifier_statement_mismatch", "verifier_result_shape", "verifier_result_flags", "verifier_transport"}
                code = str(exc) if str(exc) in allowed else "fresh_handoff_required"
                return self._complete(work, status="HELD", error_code=code)
            except QueueRetryableError:
                return self._complete(work, status="HELD", error_code="fresh_handoff_required")
            except BaseException:
                return self._complete(work, status="HELD", error_code="fresh_handoff_required")
            return self._complete(work, status="VERIFIED" if result.proof_accepted else "REJECTED", result=result, error_code=None if result.proof_accepted else "proof_rejected")
        finally:
            handoff.close()

    def _promote_candidates(self) -> tuple[dict[str, Any], ...]:
        self._assert_owner()
        try:
            from app.minimal_clearance_verification_queue_independent import read_verified_batch
            batch = read_verified_batch(self.path)
        except Exception:
            return ()
        return () if not batch.jobs else ({"batch_id": batch.batch.batch_id, "head_root": batch.batch.post_head_root, "accepted_count": len(batch.jobs)},)

    def _read_projection(self) -> dict[str, Any]:
        self._assert_owner()
        with closing(self._connect()) as connection:
            meta = self._meta(connection)
            counts = {status: 0 for status in _STATUSES}
            for status, count in connection.execute("SELECT status,COUNT(*) FROM queue_jobs GROUP BY status"):
                counts[str(status)] = int(count)
            return {"schema": _SCHEMA, "head_root": bytes(meta[10]), "counts": counts, "transitions": int(meta[11]), "admission_count": int(meta[12]), "proof_suite_id": None, "production_usable": False, "activation": False}

    def _snapshot(self) -> dict[str, Any]:
        return self._read_projection()

    def _support_summary(self) -> dict[str, Any]:
        return {**self._read_projection(), "admission_cap_bytes": ADMISSION_CAP_BYTES, "process_tree_peak_cap_bytes": PROCESS_TREE_PEAK_CAP_BYTES, "proof_bytes_persisted": False, "path_custody": False, "backend_qualified": False}

    def _verify_integrity(self) -> None:
        from app.minimal_clearance_verification_queue_independent import verify_database
        verify_database(self.path, expected_config=self.config.as_json)

    def _export_bytes(self) -> bytes:
        self._verify_integrity()
        return self.path.read_bytes()

    def _get_job(self, operation_ref: bytes) -> QueueJob | None:
        _blob(operation_ref, 32, "operation_ref")
        with closing(self._connect()) as connection:
            return self._get_job_locked(connection, operation_ref)

    def _close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for handoff in tuple(self._handoffs.values()):
            handoff.close()
        self._handoffs.clear()


def _u64(value: int) -> bytes:
    if type(value) is not int or not 0 <= value < 2**64:
        _raise_fixed(QueueIntegrityError("queue_integer"))
    return value.to_bytes(8, "big")


def _parse_receipt(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_RECEIPT_BYTES:
        _raise_fixed(QueueIntegrityError("receipt_bounds"))
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _raise_fixed(QueueIntegrityError("receipt_encoding"))
    required = {"schema", "proof_accepted", "operation_ref", "assertion_identifier", "assertion_version", "state_profile_version", "valid_from_ms", "valid_until_ms", "batch_position", "batch_root", "verifier_profile_version", "outcome_code", "error_code", "resource_code", "qualification_flags", "proof_suite_id", "production_usable", "activation"}
    if type(value) is not dict or set(value) != required or raw != _json_bytes(value) or value["schema"] != _SCHEMA or value["proof_suite_id"] is not None or value["production_usable"] is not False or value["activation"] is not False:
        _raise_fixed(QueueIntegrityError("receipt_keys"))
    return value


__all__ = (
    "ADMISSION_CAP_BYTES", "ACTIVE_PROCESS_LIMIT", "CAP_BYTES", "DIRECTIVES",
    "MAX_QUEUE_DATABASE_BYTES", "MAX_QUEUE_CAPACITY", "MAX_TERMINAL_GROWTH_PER_NONTERMINAL",
    "PROCESS_TREE_PEAK_CAP_BYTES", "OperationStatement", "QueueBackpressureError",
    "QueueClock", "QueueConfig", "QueueConflictError", "QueueDeterministicRejectError",
    "QueueHeldError", "QueueIndeterminateError", "QueueIntegrityError", "QueueJob", "QueueLeaseError",
    "QueueResult", "QueueRetryableError", "SystemQueueClock", "VerificationQueueError",
    "VerifierResult", "VolatileProofHandoff", "parse_verifier_result", "_QueueRuntimeOwnership",
    "_VerificationQueueStore", "_parse_receipt", "BOOTSTRAP_CAPABILITY_LIMITATION_COUNT",
)
