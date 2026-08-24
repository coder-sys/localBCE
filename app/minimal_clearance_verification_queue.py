"""Durable experimental queue for independent minimal-clearance verification.

The queue owns admission, random in-memory lease bearers, bounded retry, custody,
and proof-evidence receipts.  It never imports a clearance state owner and never
turns verifier acceptance into a directive.
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
import stat
import tempfile
import time
from typing import Any, Callable, Final, Mapping, NoReturn, Protocol

from app.minimal_clearance_proof_primitives import (
    MinimalClearanceProofStateError,
    MinimalProofAcceptanceV1,
    NativeVerificationCallResult,
    NativeMinimalClearanceVerifier,
    parse_acceptance_bytes,
)
from app.minimal_clearance_verifier_process import ContainedVerifierResult


class VerificationQueueError(RuntimeError):
    """Base fail-closed queue error with a fixed code only."""


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
    """Raise a fixed-code error without retaining caught exception context."""
    try:
        raise error
    except VerificationQueueError as fixed:
        fixed.__cause__ = None
        fixed.__context__ = None
        fixed.__suppress_context__ = True
        raise


_SCHEMA_VERSION: Final[int] = 3
_SCHEMA: Final[str] = "BL/NATIVE-V3/MINIMAL-CLEARANCE-VERIFICATION-QUEUE/v3"
_STATUS: Final = frozenset({"QUEUED", "LEASED", "VERIFIED", "REJECTED", "HELD"})
_NONTERMINAL: Final = frozenset({"QUEUED", "LEASED"})
_TERMINAL: Final = frozenset({"VERIFIED", "REJECTED", "HELD"})
_SAFE_TOKEN = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
_SAFE_CODE = re.compile(r"[a-z][a-z0-9_]{0,95}\Z")
_MAX_QUEUE_ID: Final[int] = 96
_MAX_WORKER_ID: Final[int] = 96
_MAX_ARTIFACT_REF: Final[int] = 128
_MAX_ERROR: Final[int] = 96
_MAX_STDOUT: Final[int] = 65_536
_MAX_STDERR: Final[int] = 262_144
_MAX_ACCEPTANCE: Final[int] = 65_536
_MAX_RECEIPT: Final[int] = 16 * 1024
_CAP_BYTES: Final[int] = 5_000_000_000
_ACTIVE_PROCESS_LIMIT: Final[int] = 1
MAX_QUEUE_DATABASE_BYTES: Final[int] = 64 * 1024 * 1024
MAX_QUEUE_CAPACITY: Final[int] = 512
MAX_TERMINAL_GROWTH_PER_NONTERMINAL: Final[int] = 64 * 1024
_RUNTIME_WORKER_ID: Final[str] = "minimal-clearance-runtime"
_LEASE_SECONDS: Final[int] = 3_600
_MAX_ATTEMPTS: Final[int] = 3
_WORKSPACE_PREFIX: Final[str] = "BLV3-WORKSPACE-"
_WORKSPACE_MARKER_NAME: Final[str] = ".BLV3-WORKSPACE"
_WORKSPACE_MARKER: Final[bytes] = b"BL/NATIVE-V3/MINIMAL-CLEARANCE-WORKSPACE/v3\x00"
_PAGE_SIZE: Final[int] = 4096
_MAX_PAGE_COUNT: Final[int] = MAX_QUEUE_DATABASE_BYTES // _PAGE_SIZE
_MAX_ARTIFACT_BYTES: Final[int] = 512 * 1024 * 1024
BOOTSTRAP_CAPABILITY_LIMITATION_COUNT = 0

_GENESIS_DOMAIN = b"BL/NATIVE-V3/VERIFICATION-QUEUE/GENESIS/v3\x00"
_MATERIAL_DOMAIN = b"BL/NATIVE-V3/VERIFICATION-QUEUE/MATERIAL/v3\x00"
_OPERATION_DOMAIN = b"BL/NATIVE-V3/VERIFICATION-QUEUE/OPERATION/v3\x00"
_EVENT_DOMAIN = b"BL/NATIVE-V3/VERIFICATION-QUEUE/EVENT/v3\x00"
_HEAD_DOMAIN = b"BL/NATIVE-V3/VERIFICATION-QUEUE/HEAD/v3\x00"
_RECEIPT_DOMAIN = b"BL/NATIVE-V3/VERIFICATION-QUEUE/RECEIPT/v3\x00"
_ACCEPTANCE_DOMAIN = b"BL/NATIVE-V3/VERIFICATION-QUEUE/ACCEPTANCE/v3\x00"
_LEASE_DOMAIN = b"BL/NATIVE-V3/VERIFICATION-QUEUE/LEASE-FENCE/v3\x00"

# These are producer-owned literals, not caller-controlled strings.  A worker
# can only expose one of these codes when the exception is the exact trusted
# type that created it and its args have the exact one-string shape below.
_PROOF_DETERMINISTIC_REJECT_CODES: Final = frozenset({
    "proof_rejected",
    "proof_verifier_rejected", "proof_circuit_id", "proof_public_statement_mismatch",
    "proof_verifier_output_encoding", "proof_verified_statement_missing",
    "proof_verified_statement_length", "proof_acceptance_truncated", "proof_acceptance_magic",
    "proof_acceptance_version", "proof_acceptance_statement_size", "proof_acceptance_trailing",
})
_PROOF_TRUSTED_CODES: Final = frozenset({
    "proof_verifier_rejected", "proof_circuit_id", "proof_public_statement_mismatch",
    "proof_verifier_output_encoding", "proof_verified_statement_missing", "proof_verified_statement_length",
    "proof_acceptance_truncated", "proof_acceptance_magic", "proof_acceptance_version",
    "proof_acceptance_statement_size", "proof_acceptance_trailing", "proof_acceptance_statement_invalid",
    "proof_acceptance_artifact_sha256_invalid", "proof_acceptance_artifact_bytes_invalid",
    "proof_acceptance_circuit_or_flag_invalid", "proof_acceptance_required", "proof_statement_length",
    "proof_statement_role", "statement_trailing", "state_header", "state_length", "proof_verifier_stderr_encoding",
    "proof_verifier_stderr_grammar", "proof_verifier_stderr_line_count", "proof_verifier_build_trace",
    "proof_verifier_build_complete", "proof_verifier_build_profile", "proof_verifier_stage_trace",
    "proof_verifier_output_grammar", "proof_verifier_output_profile", "proof_preflight_encoding",
    "proof_preflight_grammar", "proof_preflight_profile", "proof_preflight_statement", "proof_preflight_endian",
    "proof_statement_output_encoding", "proof_statement_output_grammar", "proof_statement_stderr_encoding",
    "proof_statement_stderr_grammar", "proof_policy_directive", "proof_economic_mutation", "proof_directive_flags",
    "proof_public_flag_binding", "proof_state_epoch_sequence", "proof_chronology", "proof_access_time",
    "proof_access_shape", "proof_sequence_after", "proof_clearance_marker", "proof_clearance_count",
    "proof_exception", "proof_exception_sentinel", "proof_exception_interval", "proof_suite_not_null",
    "proof_source_root_binding", "proof_completeness_binding", "proof_subject_binding", "proof_attempt_binding",
    "proof_request_binding", "proof_decision_context_binding", "proof_decision_binding", "proof_join_decision_binding",
    "proof_read_value_binding", "proof_write_value_binding", "proof_write_address_binding", "proof_read_address_binding",
    "proof_before_state_id", "proof_request_id", "proof_decision_id", "proof_after_continuity", "proof_after_state_id",
    "proof_u64_invalid", "proof_u32_invalid", "proof_binding_part_invalid", "proof_artifact_header",
    "proof_artifact_version", "proof_artifact_length", "verifier_executable_hash", "verifier_timeout",
    "verifier_executable_identity_changed", "verifier_process_unavailable", "verifier_containment",
    "verifier_memory_cap", "verifier_preflight_rejected", "verifier_statement_reconstruction", "verifier_statement_length",
})
_QUEUE_RETRY_CODES: Final = frozenset({
    "custody_read", "custody_snapshot", "custody_parent", "custody_workspace", "verifier_output_type",
    "verifier_output_cap", "verifier_output_encoding", "telemetry_missing", "verifier_result_shape",
    "verifier_containment_shape", "verifier_containment", "verifier_resource", "verifier_timeout",
    "verifier_process_unavailable", "verifier_memory_cap", "verifier_statement_reconstruction", "verifier_preflight_rejected",
})
_QUEUE_HELD_CODES: Final = frozenset({
    "custody_size", "custody_source", "custody_source_identity", "custody_snapshot_identity", "custody_identity_mismatch",
    "custody_snapshot", "custody_cleanup", "snapshot_missing", "proof_acceptance_type", "proof_acceptance_shape", "verifier_type", "verifier_identity",
})
_STORE_LEASE_LOSS_CODES: Final = frozenset({"lease_expired", "completion_not_live"})
_STORE_INDETERMINATE_CODES: Final = frozenset({"queue_commit_indeterminate", "retry_reconciled"})


def _exact_code(error: BaseException, *, types: tuple[type[BaseException], ...], allowed: frozenset[str]) -> str | None:
    if type(error) not in types:
        return None
    try:
        args = error.args
    except BaseException:
        return None
    if type(args) is not tuple or len(args) != 1 or type(args[0]) is not str:
        return None
    return args[0] if args[0] in allowed else None


def _trusted_store_code(error: BaseException, allowed: frozenset[str]) -> str | None:
    return _exact_code(error, types=(QueueLeaseError, QueueIndeterminateError), allowed=allowed)


def _sha(domain: bytes, *parts: bytes) -> bytes:
    digest = hashlib.sha3_512()
    digest.update(domain)
    for part in parts:
        digest.update(part)
    return digest.digest()


def _u64(value: int) -> bytes:
    if type(value) is not int or not 0 <= value < 2**64:
        raise QueueIntegrityError("queue_integer_range")
    return value.to_bytes(8, "big")


def _frame(domain: bytes, *parts: bytes) -> bytes:
    """Length-frame every lease fact so the HMAC context is unambiguous."""
    result = bytearray(domain)
    for part in parts:
        result.extend(_u64(len(part)))
        result.extend(part)
    return bytes(result)


def _lease_digest(
    config: QueueConfig,
    job_id: str,
    worker_id: str,
    attempt: int,
    claim_sequence: int,
    leased_ms: int,
    expires_ms: int,
    raw_token: bytes,
) -> bytes:
    if type(raw_token) is not bytes or len(raw_token) != 32:
        raise QueueLeaseError("completion_token_shape")
    context = _frame(
        _LEASE_DOMAIN,
        config.queue_id.encode("ascii"), config.digest,
        job_id.encode("ascii"), worker_id.encode("ascii"),
        _u64(attempt), _u64(claim_sequence), _u64(leased_ms), _u64(expires_ms),
    )
    return hmac.new(raw_token, context, hashlib.sha3_512).digest()


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        _raise_fixed(QueueIntegrityError("queue_json_encoding"))


def _safe_token(value: object, label: str, *, maximum: int = 128) -> str:
    if type(value) is not str or len(value) == 0 or len(value) > maximum or _SAFE_TOKEN.fullmatch(value) is None:
        raise VerificationQueueError(f"{label}_invalid")
    return value


def _safe_code(value: object, label: str = "queue_error") -> str:
    if type(value) is not str or len(value) > _MAX_ERROR or _SAFE_CODE.fullmatch(value) is None:
        raise QueueIntegrityError(f"{label}_invalid")
    return value


def _bytes(value: object, length: int, label: str) -> bytes:
    if type(value) is not bytes or len(value) != length:
        raise VerificationQueueError(f"{label}_invalid")
    return bytes(value)


def _hex(value: bytes) -> str:
    return value.hex().upper()


def _parse_hex(value: object, length: int | None, label: str) -> bytes:
    if type(value) is not str:
        raise QueueIntegrityError(f"{label}_invalid")
    if length is not None:
        if re.fullmatch(rf"[0-9a-fA-F]{{{length * 2}}}\Z", value) is None:
            raise QueueIntegrityError(f"{label}_invalid")
    elif re.fullmatch(r"[0-9a-fA-F]+\Z", value) is None:
        raise QueueIntegrityError(f"{label}_invalid")
    try:
        result = bytes.fromhex(value)
    except ValueError:
        _raise_fixed(QueueIntegrityError(f"{label}_invalid"))
    if length is not None and len(result) != length:
        raise QueueIntegrityError(f"{label}_invalid")
    return result


class QueueClock(Protocol):
    def now_ms(self) -> int:
        """Return the injected state clock in integer milliseconds."""


class SystemQueueClock:
    def now_ms(self) -> int:
        return time.time_ns() // 1_000_000


@dataclass(frozen=True, slots=True)
class QueueConfig:
    queue_id: str
    capacity: int
    verifier_sha256: bytes
    artifact_bytes_cap: int

    def __post_init__(self) -> None:
        _safe_token(self.queue_id, "queue_id", maximum=_MAX_QUEUE_ID)
        if type(self.capacity) is not int or not 1 <= self.capacity <= MAX_QUEUE_CAPACITY:
            raise VerificationQueueError("queue_capacity_invalid")
        _bytes(self.verifier_sha256, 32, "queue_verifier_sha256")
        if type(self.artifact_bytes_cap) is not int or not 0 < self.artifact_bytes_cap <= _MAX_ARTIFACT_BYTES:
            raise VerificationQueueError("queue_artifact_cap_invalid")

    @property
    def lease_seconds(self) -> int:
        return _LEASE_SECONDS

    @property
    def max_attempts(self) -> int:
        return _MAX_ATTEMPTS

    @property
    def retryable_codes(self) -> tuple[str, ...]:
        return tuple(sorted(_QUEUE_RETRY_CODES))

    def as_json(self) -> dict[str, Any]:
        return {
            "schema_version": _SCHEMA_VERSION,
            "queue_id": self.queue_id,
            "capacity": self.capacity,
            "lease_seconds": _LEASE_SECONDS,
            "max_attempts": _MAX_ATTEMPTS,
            "max_worker_concurrency": 1,
            "verifier_sha256": _hex(self.verifier_sha256),
            "artifact_bytes_cap": self.artifact_bytes_cap,
            "retryable_codes": list(self.retryable_codes),
        }

    @property
    def canonical_bytes(self) -> bytes:
        return _json_bytes(self.as_json())

    @property
    def digest(self) -> bytes:
        return _sha(_MATERIAL_DOMAIN, self.canonical_bytes)


@dataclass(frozen=True, slots=True)
class ArtifactMetadata:
    artifact_ref: str
    artifact_bytes: int
    artifact_sha256: bytes
    artifact_sha3_512: bytes

    def __post_init__(self) -> None:
        _safe_token(self.artifact_ref, "artifact_ref", maximum=_MAX_ARTIFACT_REF)
        if type(self.artifact_bytes) is not int or not 0 < self.artifact_bytes <= _MAX_ARTIFACT_BYTES:
            raise VerificationQueueError("artifact_bytes_invalid")
        _bytes(self.artifact_sha256, 32, "artifact_sha256")
        _bytes(self.artifact_sha3_512, 64, "artifact_sha3_512")

    def as_json(self) -> dict[str, Any]:
        return {"artifact_ref": self.artifact_ref, "artifact_bytes": self.artifact_bytes, "artifact_sha256": _hex(self.artifact_sha256), "artifact_sha3_512": _hex(self.artifact_sha3_512)}


@dataclass(frozen=True, slots=True)
class CustodySnapshot:
    """In-memory custody result; the path never enters queue storage/export."""

    path: Path = field(repr=False)
    artifact_bytes: int
    artifact_sha256: bytes
    artifact_sha3_512: bytes
    readonly: bool
    cleanup: Callable[[], None] | None = None


@dataclass(frozen=True, slots=True)
class _QueueWorkItem:
    queue_id: str
    job_id: str
    operation_id: bytes
    metadata: ArtifactMetadata
    attempt: int
    worker_id: str
    claim_sequence: int
    lease_token: bytes = field(repr=False)
    lease_expires_ms: int
    expected_verifier_sha256: bytes


@dataclass(frozen=True, slots=True)
class _VerificationEvidence:
    artifact_bytes: int
    artifact_sha256: bytes
    artifact_sha3_512: bytes
    verifier_sha256: bytes
    circuit_id: bytes
    acceptance_bytes: bytes = field(repr=False)
    proof_acceptance_digest: bytes
    peak_job_commit_bytes: int
    cap_bytes: int
    cap_enforced: bool
    active_process_limit: int
    timed_out: bool
    exit_code: int
    stdout_sha3_512: bytes
    stderr_sha3_512: bytes

    def __post_init__(self) -> None:
        if type(self.artifact_bytes) is not int or self.artifact_bytes <= 0:
            raise QueueIntegrityError("evidence_artifact_bytes")
        for name, length in (("artifact_sha256", 32), ("artifact_sha3_512", 64), ("verifier_sha256", 32), ("circuit_id", 32), ("proof_acceptance_digest", 64), ("stdout_sha3_512", 64), ("stderr_sha3_512", 64)):
            _bytes(getattr(self, name), length, f"evidence_{name}")
        if type(self.acceptance_bytes) is not bytes or not 0 < len(self.acceptance_bytes) <= _MAX_ACCEPTANCE:
            raise QueueIntegrityError("evidence_acceptance_bytes")
        try:
            parsed = parse_acceptance_bytes(self.acceptance_bytes)
        except Exception:
            _raise_fixed(QueueIntegrityError("evidence_acceptance_invalid"))
        if parsed.canonical_bytes() != self.acceptance_bytes or parsed.artifact_bytes != self.artifact_bytes or parsed.artifact_sha256 != self.artifact_sha256 or parsed.artifact_digest != self.artifact_sha3_512 or parsed.circuit_id != self.circuit_id or _sha(_ACCEPTANCE_DOMAIN, self.acceptance_bytes) != self.proof_acceptance_digest:
            raise QueueIntegrityError("evidence_acceptance_binding")
        if type(self.peak_job_commit_bytes) is not int or self.peak_job_commit_bytes < 0:
            raise QueueIntegrityError("evidence_peak")
        if type(self.cap_bytes) is not int or self.cap_bytes != _CAP_BYTES:
            raise QueueIntegrityError("evidence_cap")
        if type(self.cap_enforced) is not bool or type(self.active_process_limit) is not int or self.active_process_limit != _ACTIVE_PROCESS_LIMIT:
            raise QueueIntegrityError("evidence_containment")
        if type(self.timed_out) is not bool or type(self.exit_code) is not int:
            raise QueueIntegrityError("evidence_process")

    def as_json(self) -> dict[str, Any]:
        return {"artifact_bytes": self.artifact_bytes, "artifact_sha256": _hex(self.artifact_sha256), "artifact_sha3_512": _hex(self.artifact_sha3_512), "verifier_sha256": _hex(self.verifier_sha256), "circuit_id": _hex(self.circuit_id), "acceptance_bytes": _hex(self.acceptance_bytes), "proof_acceptance_digest": _hex(self.proof_acceptance_digest), "peak_job_commit_bytes": self.peak_job_commit_bytes, "cap_bytes": self.cap_bytes, "cap_enforced": self.cap_enforced, "active_process_limit": self.active_process_limit, "timed_out": self.timed_out, "exit_code": self.exit_code, "stdout_sha3_512": _hex(self.stdout_sha3_512), "stderr_sha3_512": _hex(self.stderr_sha3_512)}

    @property
    def canonical_bytes(self) -> bytes:
        return _json_bytes(self.as_json())


@dataclass(frozen=True, slots=True)
class _VerificationReceipt:
    schema: str
    queue_id: str
    job_id: str
    operation_id: bytes
    attempt: int
    evidence: _VerificationEvidence
    receipt_id: bytes

    def as_json(self, *, include_id: bool = True) -> dict[str, Any]:
        value: dict[str, Any] = {"schema": self.schema, "queue_id": self.queue_id, "job_id": self.job_id, "operation_id": _hex(self.operation_id), "attempt": self.attempt, "evidence": self.evidence.as_json()}
        if include_id:
            value["receipt_id"] = _hex(self.receipt_id)
        return value

    @property
    def canonical_bytes(self) -> bytes:
        return _json_bytes(self.as_json())

    @property
    def digest(self) -> bytes:
        return _sha(_RECEIPT_DOMAIN, self.canonical_bytes)


@dataclass(frozen=True, slots=True)
class QueueJob:
    job_id: str
    operation_id: bytes
    metadata: ArtifactMetadata
    status: str
    admission_seq: int
    attempt: int
    next_eligible_ms: int
    last_error_code: str | None


@dataclass(frozen=True, slots=True)
class QueueResult:
    job_id: str
    operation_id: bytes
    status: str
    receipt_bytes: bytes | None = field(default=None, repr=False)
    error_code: str | None = None


class _ProofArtifactCustodyPort(Protocol):
    def snapshot(self, artifact_ref: str, expected: ArtifactMetadata) -> CustodySnapshot:
        """Return a fresh verifier-owned read-only snapshot."""


def _is_reparse(stat_result: os.stat_result) -> bool:
    attributes = int(getattr(stat_result, "st_file_attributes", 0))
    return bool(attributes & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)))


def _owned_directory(path: Path) -> bool:
    try:
        item = os.lstat(path)
        return stat.S_ISDIR(item.st_mode) and int(item.st_nlink) == 1 and not _is_reparse(item)
    except (OSError, ValueError):
        return False


def _same_file_identity(first: os.stat_result, second: os.stat_result) -> bool:
    return (int(first.st_dev), int(first.st_ino), int(first.st_nlink), int(first.st_size), int(first.st_mtime_ns)) == (int(second.st_dev), int(second.st_ino), int(second.st_nlink), int(second.st_size), int(second.st_mtime_ns)) and stat.S_ISREG(second.st_mode) and not _is_reparse(second)


def _open_regular_file(path: Path, expected_bytes: int) -> tuple[int, os.stat_result]:
    if type(expected_bytes) is not int or not 0 < expected_bytes <= _MAX_ARTIFACT_BYTES:
        raise QueueHeldError("custody_size")
    descriptor: int | None = None
    try:
        before = os.lstat(path)
        if not stat.S_ISREG(before.st_mode) or int(before.st_nlink) != 1 or _is_reparse(before):
            raise QueueHeldError("custody_source")
        flags = int(os.O_RDONLY) | int(getattr(os, "O_BINARY", 0))
        if hasattr(os, "O_NOFOLLOW"):
            flags |= int(os.O_NOFOLLOW)
        descriptor = os.open(str(path), flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or int(opened.st_nlink) != 1 or _is_reparse(opened) or int(opened.st_size) != expected_bytes or not _same_file_identity(before, opened):
            raise QueueHeldError("custody_source_identity")
        return descriptor, opened
    except QueueHeldError:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise
    except (OSError, ValueError):
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        _raise_fixed(QueueRetryableError("custody_read"))


def _stream_digest(descriptor: int, expected_bytes: int, digest256: Any, digest512: Any) -> int:
    total = 0
    while total <= expected_bytes:
        chunk = os.read(descriptor, min(1 << 20, expected_bytes + 1 - total))
        if not chunk:
            break
        total += len(chunk)
        if total > expected_bytes:
            break
        digest256.update(chunk); digest512.update(chunk)
    return total


def _write_all(descriptor: int, chunk: bytes) -> None:
    offset = 0
    while offset < len(chunk):
        written = os.write(descriptor, chunk[offset:])
        if written <= 0:
            raise OSError
        offset += written


def _new_owned_directory(parent: Path) -> tuple[Path, tuple[int, int, int]]:
    if not _owned_directory(parent):
        raise QueueRetryableError("custody_parent")
    directory: Path | None = None
    marker: Path | None = None
    directory_identity: tuple[int, int, int] | None = None
    marker_identity: tuple[int, int, int] | None = None
    try:
        directory = Path(tempfile.mkdtemp(prefix=_WORKSPACE_PREFIX, dir=parent))
        directory_stat = os.lstat(directory)
        directory_identity = (int(directory_stat.st_dev), int(directory_stat.st_ino), int(directory_stat.st_nlink))
        marker = directory / _WORKSPACE_MARKER_NAME
        if not _owned_directory(directory):
            raise OSError
        descriptor = os.open(str(marker), int(os.O_CREAT) | int(os.O_EXCL) | int(os.O_WRONLY) | int(getattr(os, "O_BINARY", 0)), 0o600)
        try:
            opened_marker = os.fstat(descriptor)
            marker_identity = (int(opened_marker.st_dev), int(opened_marker.st_ino), int(opened_marker.st_nlink))
            _write_all(descriptor, _WORKSPACE_MARKER)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        marker_stat = os.lstat(marker)
        marker_identity = (int(marker_stat.st_dev), int(marker_stat.st_ino), int(marker_stat.st_nlink))
        if not stat.S_ISREG(marker_stat.st_mode) or int(marker_stat.st_nlink) != 1 or _is_reparse(marker_stat):
            raise OSError
        os.chmod(marker, stat.S_IREAD)
        return directory, marker_identity
    except (OSError, ValueError):
        cleanup_failed = False
        if directory is not None and marker is not None and directory_identity is not None and marker_identity is not None:
            cleanup_failed = not _remove_owned_marker_directory(directory, marker, directory_identity, marker_identity)
        elif directory is not None:
            cleanup_failed = True
        if cleanup_failed:
            _raise_fixed(QueueHeldError("custody_cleanup"))
        _raise_fixed(QueueRetryableError("custody_workspace"))


def _remove_owned_marker_directory(
    directory: Path,
    marker: Path,
    directory_identity: tuple[int, int, int],
    marker_identity: tuple[int, int, int],
) -> bool:
    """Remove only an exact empty workspace whose marker is still intact."""
    try:
        current_directory = os.lstat(directory)
        current_marker = os.lstat(marker)
        if (
            (int(current_directory.st_dev), int(current_directory.st_ino), int(current_directory.st_nlink)) != directory_identity
            or (int(current_marker.st_dev), int(current_marker.st_ino), int(current_marker.st_nlink)) != marker_identity
            or not stat.S_ISDIR(current_directory.st_mode)
            or not stat.S_ISREG(current_marker.st_mode)
            or _is_reparse(current_directory)
            or _is_reparse(current_marker)
            or tuple(directory.iterdir()) != (marker,)
        ):
            return False
        flags = int(os.O_RDONLY) | int(getattr(os, "O_BINARY", 0)) | int(getattr(os, "O_NOFOLLOW", 0))
        descriptor = os.open(str(marker), flags)
        try:
            opened_marker = os.fstat(descriptor)
            marker_bytes = os.read(descriptor, len(_WORKSPACE_MARKER) + 1)
        finally:
            os.close(descriptor)
        if (
            (int(opened_marker.st_dev), int(opened_marker.st_ino), int(opened_marker.st_nlink)) != marker_identity
            or marker_bytes != _WORKSPACE_MARKER
        ):
            return False
        os.chmod(marker, stat.S_IRUSR | stat.S_IWUSR)
        os.unlink(marker)
        os.rmdir(directory)
        return True
    except (OSError, ValueError):
        return False


def _database_identity(path: Path, *, allow_missing: bool = False) -> tuple[int, int, int, int, int] | None:
    try:
        item = os.lstat(path)
    except FileNotFoundError:
        if allow_missing:
            return None
        _raise_fixed(VerificationQueueError("queue_database_path"))
    except (OSError, ValueError):
        _raise_fixed(VerificationQueueError("queue_database_path"))
    if not stat.S_ISREG(item.st_mode) or int(item.st_nlink) != 1 or _is_reparse(item):
        raise VerificationQueueError("queue_database_path")
    if int(item.st_size) > MAX_QUEUE_DATABASE_BYTES:
        raise QueueBackpressureError("queue_storage_capacity")
    return (int(item.st_dev), int(item.st_ino), int(item.st_nlink), int(item.st_size), int(item.st_mtime_ns))


def _directory_identity(path: Path) -> tuple[int, int, int]:
    try:
        item = os.lstat(path)
    except (OSError, ValueError):
        _raise_fixed(VerificationQueueError("queue_database_parent"))
    if not stat.S_ISDIR(item.st_mode) or int(item.st_nlink) != 1 or _is_reparse(item):
        raise VerificationQueueError("queue_database_parent")
    return int(item.st_dev), int(item.st_ino), int(item.st_nlink)


def _database_uri(path: Path, mode: str) -> str:
    if mode not in {"rw", "ro"}:
        _raise_fixed(VerificationQueueError("queue_database_mode"))
    try:
        return path.resolve(strict=True).as_uri() + f"?mode={mode}"
    except (OSError, ValueError):
        _raise_fixed(VerificationQueueError("queue_database_path"))


def _connection_binding(
    connection: sqlite3.Connection,
    intended: Path,
    intended_identity: tuple[int, int, int, int, int],
    parent_identity: tuple[int, int, int],
) -> None:
    """Bind SQLite's opened main file before any queue read or mutation."""
    try:
        rows = connection.execute("PRAGMA database_list").fetchall()
        if len(rows) != 1 or str(rows[0][1]) != "main" or not str(rows[0][2]):
            _raise_fixed(VerificationQueueError("queue_database_binding"))
        opened = Path(str(rows[0][2])).resolve(strict=True)
        expected = intended.resolve(strict=True)
        if opened != expected:
            _raise_fixed(VerificationQueueError("queue_database_binding"))
        opened_identity = _database_identity(opened)
        if opened_identity is None or opened_identity[:3] != intended_identity[:3] or _directory_identity(intended.parent) != parent_identity:
            _raise_fixed(VerificationQueueError("queue_database_identity"))
    except VerificationQueueError:
        raise
    except Exception:
        _raise_fixed(VerificationQueueError("queue_database_binding"))


def _sidecar_identity(path: Path) -> tuple[int, int, int, int, int]:
    try:
        item = os.lstat(path)
    except (OSError, ValueError):
        _raise_fixed(VerificationQueueError("queue_database_journal"))
    if not stat.S_ISREG(item.st_mode) or int(item.st_nlink) != 1 or _is_reparse(item):
        _raise_fixed(VerificationQueueError("queue_database_journal"))
    return int(item.st_dev), int(item.st_ino), int(item.st_nlink), int(item.st_size), int(item.st_mtime_ns)


class _QueueRuntimeOwnership:
    """One OS-held ownership object for an exact marker and parent.

    The runtime is the only production caller that may create this object.  On
    Windows the marker handle denies write/delete/rename sharing; on POSIX the
    advisory lock is retained with identity checks and no stronger claim.
    """

    def __init__(self, *, lock_path: Path, parent: Path) -> None:
        if (
            not isinstance(lock_path, Path)
            or not isinstance(parent, Path)
            or lock_path.parent != parent
            or not _owned_directory(parent)
        ):
            _raise_fixed(VerificationQueueError("queue_owner"))
        self._path = lock_path
        self._parent = parent
        self._parent_identity = _directory_identity(parent)
        self._path_identity: tuple[int, int, int] | None = None
        self._descriptor: int | None = None
        self._locked = False
        self._closed = False
        try:
            before = None
            try:
                before = os.lstat(self._path)
            except FileNotFoundError:
                pass
            except (OSError, ValueError):
                _raise_fixed(VerificationQueueError("queue_owner"))
            if before is not None and (
                not stat.S_ISREG(before.st_mode)
                or int(before.st_nlink) != 1
                or _is_reparse(before)
            ):
                _raise_fixed(VerificationQueueError("queue_owner"))

            if os.name == "nt":
                import ctypes
                import msvcrt

                if before is None:
                    create_flags = int(os.O_RDWR) | int(os.O_CREAT) | int(os.O_EXCL) | int(getattr(os, "O_BINARY", 0))
                    try:
                        created = os.open(str(self._path), create_flags, 0o600)
                        os.close(created)
                    except FileExistsError:
                        pass
                    except (OSError, ValueError):
                        _raise_fixed(VerificationQueueError("queue_owner"))
                kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
                kernel32.CreateFileW.argtypes = [
                    ctypes.c_wchar_p,
                    ctypes.c_uint32,
                    ctypes.c_uint32,
                    ctypes.c_void_p,
                    ctypes.c_uint32,
                    ctypes.c_uint32,
                    ctypes.c_void_p,
                ]
                kernel32.CreateFileW.restype = ctypes.c_void_p
                kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
                kernel32.CloseHandle.restype = ctypes.c_int
                handle = kernel32.CreateFileW(
                    str(self._path),
                    0xC0000000,  # GENERIC_READ | GENERIC_WRITE
                    0x00000001,  # FILE_SHARE_READ only: deny write/delete/rename
                    None,
                    3,  # OPEN_ALWAYS
                    0x00200080,  # FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT
                    None,
                )
                handle_value = getattr(handle, "value", handle)
                invalid = ctypes.c_void_p(-1).value
                if handle_value in (None, invalid):
                    _raise_fixed(VerificationQueueError("queue_owner"))
                try:
                    descriptor = msvcrt.open_osfhandle(
                        int(handle_value), int(os.O_RDWR) | int(getattr(os, "O_BINARY", 0))
                    )
                except (OSError, ValueError):
                    kernel32.CloseHandle(ctypes.c_void_p(handle_value))
                    _raise_fixed(VerificationQueueError("queue_owner"))
            else:
                flags = int(os.O_RDWR) | int(os.O_CREAT) | int(getattr(os, "O_BINARY", 0))
                if before is None:
                    flags |= int(getattr(os, "O_EXCL", 0))
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= int(os.O_NOFOLLOW)
                descriptor = os.open(str(self._path), flags, 0o600)
                if before is not None:
                    opened_before = os.fstat(descriptor)
                    if (
                        int(opened_before.st_dev),
                        int(opened_before.st_ino),
                        int(opened_before.st_nlink),
                    ) != (int(before.st_dev), int(before.st_ino), int(before.st_nlink)):
                        _raise_fixed(VerificationQueueError("queue_owner"))
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)

            self._descriptor = descriptor
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or int(opened.st_nlink) != 1 or _is_reparse(opened):
                _raise_fixed(VerificationQueueError("queue_owner"))
            if int(opened.st_size) > 1:
                _raise_fixed(VerificationQueueError("queue_owner"))
            if int(opened.st_size) == 1:
                os.lseek(descriptor, 0, os.SEEK_SET)
                if os.read(descriptor, 1) != b"\x00":
                    _raise_fixed(VerificationQueueError("queue_owner"))
            else:
                os.lseek(descriptor, 0, os.SEEK_SET)
                _write_all(descriptor, b"\x00")
                os.fsync(descriptor)
            os.lseek(descriptor, 0, os.SEEK_SET)
            current = os.lstat(self._path)
            identity = (int(opened.st_dev), int(opened.st_ino), int(opened.st_nlink))
            if (
                not stat.S_ISREG(current.st_mode)
                or int(current.st_nlink) != 1
                or _is_reparse(current)
                or
                (int(current.st_dev), int(current.st_ino), int(current.st_nlink)) != identity
                or _directory_identity(self._parent) != self._parent_identity
            ):
                _raise_fixed(VerificationQueueError("queue_owner"))
            self._path_identity = identity
            self._locked = True
            self.assert_live()
        except VerificationQueueError:
            try:
                self.close()
            except VerificationQueueError:
                pass
            raise
        except (OSError, ValueError, ImportError):
            try:
                self.close()
            except VerificationQueueError:
                pass
            _raise_fixed(VerificationQueueError("queue_owner"))

    def assert_scope(self, *, lock_path: Path, parent: Path) -> None:
        if not isinstance(lock_path, Path) or not isinstance(parent, Path):
            _raise_fixed(VerificationQueueError("queue_owner"))
        if self._path != lock_path or self._parent != parent:
            _raise_fixed(VerificationQueueError("queue_owner"))
        self.assert_live()

    def assert_live(self) -> None:
        descriptor = self._descriptor
        if self._closed or not self._locked or descriptor is None or self._path_identity is None:
            _raise_fixed(VerificationQueueError("queue_owner"))
        try:
            opened = os.fstat(descriptor)
            current = os.lstat(self._path)
            if (
                not stat.S_ISREG(opened.st_mode)
                or int(opened.st_nlink) != 1
                or _is_reparse(opened)
                or not stat.S_ISREG(current.st_mode)
                or int(current.st_nlink) != 1
                or _is_reparse(current)
                or (int(opened.st_dev), int(opened.st_ino), int(opened.st_nlink)) != self._path_identity
                or (int(current.st_dev), int(current.st_ino), int(current.st_nlink)) != self._path_identity
                or _directory_identity(self._parent) != self._parent_identity
                or int(opened.st_size) != 1
            ):
                _raise_fixed(VerificationQueueError("queue_owner"))
            os.lseek(descriptor, 0, os.SEEK_SET)
            marker = os.read(descriptor, 2)
            os.lseek(descriptor, 0, os.SEEK_SET)
            if marker != b"\x00" or int(current.st_size) != 1:
                _raise_fixed(VerificationQueueError("queue_owner"))
        except VerificationQueueError:
            raise
        except (OSError, ValueError):
            _raise_fixed(VerificationQueueError("queue_owner"))

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        descriptor = self._descriptor
        self._descriptor = None
        failed = False
        if descriptor is not None:
            try:
                if self._locked:
                    if os.name == "nt":
                        # CreateFileW sharing is the Windows ownership lock;
                        # closing the descriptor releases it atomically.
                        pass
                    else:
                        import fcntl

                        fcntl.flock(descriptor, fcntl.LOCK_UN)
            except (OSError, ValueError):
                failed = True
            finally:
                self._locked = False
                try:
                    os.close(descriptor)
                except (OSError, ValueError):
                    failed = True
        if failed:
            _raise_fixed(VerificationQueueError("queue_owner_close"))


class _FilesystemArtifactCustody:
    """Verifier-owned bounded snapshot adapter; queue state sees only opaque refs."""

    def __init__(self, *, source_root: Path, workspace_parent: Path) -> None:
        if not isinstance(source_root, Path) or not isinstance(workspace_parent, Path) or not _owned_directory(source_root) or not _owned_directory(workspace_parent):
            raise VerificationQueueError("custody_configuration")
        self._source_root = source_root
        self._workspace_parent = workspace_parent
        self._source_root_identity = _directory_identity(source_root)
        self._workspace_parent_identity = _directory_identity(workspace_parent)

    def _source_path(self, artifact_ref: str) -> Path:
        if (
            type(artifact_ref) is not str
            or artifact_ref in {".", ".."}
            or any(part in artifact_ref for part in ("/", "\\", ":"))
            or _SAFE_TOKEN.fullmatch(artifact_ref) is None
        ):
            raise QueueHeldError("custody_source")
        if _directory_identity(self._source_root) != self._source_root_identity or _directory_identity(self._workspace_parent) != self._workspace_parent_identity:
            raise QueueHeldError("custody_parent")
        source = self._source_root / artifact_ref
        try:
            if source.parent != self._source_root:
                raise QueueHeldError("custody_source")
            return source
        except (OSError, ValueError):
            _raise_fixed(QueueHeldError("custody_source"))

    @staticmethod
    def _readonly(path: Path) -> None:
        path.chmod(stat.S_IREAD)

    @staticmethod
    def _cleanup(directory: Path, artifact: Path, marker: Path, directory_identity: tuple[int, int], artifact_identity: tuple[int, int, int], marker_identity: tuple[int, int, int]) -> None:
        try:
            current_directory = os.stat(directory, follow_symlinks=False); current_artifact = os.stat(artifact, follow_symlinks=False)
            if (int(current_directory.st_dev), int(current_directory.st_ino)) != directory_identity or (int(current_artifact.st_dev), int(current_artifact.st_ino), int(current_artifact.st_nlink)) != artifact_identity:
                raise OSError
            current_marker = os.lstat(marker)
            if marker.name != _WORKSPACE_MARKER_NAME or marker.parent != directory or (int(current_marker.st_dev), int(current_marker.st_ino), int(current_marker.st_nlink)) != marker_identity or not stat.S_ISREG(current_marker.st_mode) or _is_reparse(current_marker):
                raise OSError
            flags = int(os.O_RDONLY) | int(getattr(os, "O_BINARY", 0)) | int(getattr(os, "O_NOFOLLOW", 0))
            marker_descriptor = os.open(str(marker), flags)
            try:
                opened_marker = os.fstat(marker_descriptor)
                marker_bytes = os.read(marker_descriptor, len(_WORKSPACE_MARKER) + 1)
            finally:
                os.close(marker_descriptor)
            if (int(opened_marker.st_dev), int(opened_marker.st_ino), int(opened_marker.st_nlink)) != marker_identity or marker_bytes != _WORKSPACE_MARKER:
                raise OSError
            os.chmod(artifact, stat.S_IRUSR | stat.S_IWUSR); os.chmod(marker, stat.S_IRUSR | stat.S_IWUSR); os.unlink(artifact); os.unlink(marker); os.rmdir(directory)
        except (OSError, ValueError):
            _raise_fixed(QueueHeldError("custody_cleanup"))

    def snapshot(self, artifact_ref: str, expected: ArtifactMetadata) -> CustodySnapshot:
        _safe_token(artifact_ref, "artifact_ref", maximum=_MAX_ARTIFACT_REF)
        if type(expected) is not ArtifactMetadata or expected.artifact_bytes > _MAX_ARTIFACT_BYTES:
            raise QueueHeldError("custody_source")
        source = self._source_path(artifact_ref)
        source_handle: int | None = None; directory: Path | None = None; artifact: Path | None = None; directory_identity: tuple[int, int, int] | None = None; artifact_identity: tuple[int, int, int] | None = None; marker_identity: tuple[int, int, int] | None = None
        try:
            source_handle, source_stat = _open_regular_file(source, expected.artifact_bytes)
            directory, marker_identity = _new_owned_directory(self._workspace_parent); artifact = directory / "artifact.bin"
            opened_directory = os.lstat(directory)
            directory_identity = (int(opened_directory.st_dev), int(opened_directory.st_ino), int(opened_directory.st_nlink))
            descriptor = os.open(str(artifact), int(os.O_CREAT) | int(os.O_EXCL) | int(os.O_WRONLY) | int(getattr(os, "O_BINARY", 0)), 0o600)
            opened_artifact = os.fstat(descriptor); artifact_identity = (int(opened_artifact.st_dev), int(opened_artifact.st_ino), int(opened_artifact.st_nlink))
            digest256 = hashlib.sha256(); digest512 = hashlib.sha3_512(); total = 0
            try:
                while total <= expected.artifact_bytes:
                    chunk = os.read(source_handle, min(1 << 20, expected.artifact_bytes + 1 - total))
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > expected.artifact_bytes:
                        raise QueueHeldError("custody_source_identity")
                    _write_all(descriptor, chunk); digest256.update(chunk); digest512.update(chunk)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            after_source = os.fstat(source_handle); path_source = os.stat(source, follow_symlinks=False)
            if not _same_file_identity(source_stat, after_source) or not _same_file_identity(source_stat, path_source) or total != expected.artifact_bytes:
                raise QueueHeldError("custody_source_identity")
            digest256_value = digest256.digest(); digest512_value = digest512.digest()
            if digest256_value != expected.artifact_sha256 or digest512_value != expected.artifact_sha3_512:
                raise QueueHeldError("custody_source_identity")
            self._readonly(artifact); verify_handle, snapshot_stat = _open_regular_file(artifact, expected.artifact_bytes)
            try:
                verify256 = hashlib.sha256(); verify512 = hashlib.sha3_512(); verified = _stream_digest(verify_handle, expected.artifact_bytes, verify256, verify512)
            finally:
                os.close(verify_handle)
            if verified != expected.artifact_bytes or verify256.digest() != digest256_value or verify512.digest() != digest512_value or not _same_file_identity(snapshot_stat, os.stat(artifact, follow_symlinks=False)):
                raise QueueHeldError("custody_snapshot_identity")
            directory_stat = os.stat(directory, follow_symlinks=False)
            marker = directory / _WORKSPACE_MARKER_NAME
            if marker_identity is None:
                raise QueueHeldError("custody_snapshot_identity")
            return CustodySnapshot(artifact, verified, digest256_value, digest512_value, True, lambda: self._cleanup(directory, artifact, marker, (int(directory_stat.st_dev), int(directory_stat.st_ino)), artifact_identity, marker_identity))
        except QueueHeldError:
            cleanup_failed = False
            if source_handle is not None:
                try: os.close(source_handle)
                except OSError: pass
            if artifact is not None and artifact_identity is not None and marker_identity is not None and directory is not None:
                try:
                    directory_stat = os.stat(directory, follow_symlinks=False); self._cleanup(directory, artifact, directory / _WORKSPACE_MARKER_NAME, (int(directory_stat.st_dev), int(directory_stat.st_ino)), artifact_identity, marker_identity)
                except (OSError, QueueHeldError): cleanup_failed = True
            elif directory is not None and directory_identity is not None and marker_identity is not None:
                cleanup_failed = not _remove_owned_marker_directory(directory, directory / _WORKSPACE_MARKER_NAME, directory_identity, marker_identity)
            elif directory is not None:
                cleanup_failed = True
            if cleanup_failed: _raise_fixed(QueueHeldError("custody_cleanup"))
            raise
        except (OSError, ValueError):
            cleanup_failed = False
            if source_handle is not None:
                try: os.close(source_handle)
                except OSError: pass
            if artifact is not None and artifact_identity is not None and marker_identity is not None and directory is not None:
                try:
                    directory_stat = os.stat(directory, follow_symlinks=False); self._cleanup(directory, artifact, directory / _WORKSPACE_MARKER_NAME, (int(directory_stat.st_dev), int(directory_stat.st_ino)), artifact_identity, marker_identity)
                except QueueHeldError: cleanup_failed = True
            elif directory is not None and directory_identity is not None and marker_identity is not None:
                cleanup_failed = not _remove_owned_marker_directory(directory, directory / _WORKSPACE_MARKER_NAME, directory_identity, marker_identity)
            elif directory is not None:
                cleanup_failed = True
            if cleanup_failed: _raise_fixed(QueueHeldError("custody_cleanup"))
            _raise_fixed(QueueRetryableError("custody_snapshot"))
        finally:
            if source_handle is not None:
                try: os.close(source_handle)
                except OSError: pass


def _material_digest(config: QueueConfig, job_id: str, metadata: ArtifactMetadata) -> bytes:
    return _sha(_MATERIAL_DOMAIN, config.queue_id.encode("ascii"), job_id.encode("ascii"), _json_bytes(metadata.as_json()), config.verifier_sha256)


def _operation_id(config: QueueConfig, job_id: str, material_digest: bytes) -> bytes:
    return _sha(_OPERATION_DOMAIN, config.queue_id.encode("ascii"), job_id.encode("ascii"), material_digest)


def _bounded_output_digests(stdout: object, stderr: object) -> tuple[bytes, bytes]:
    if type(stdout) is not bytes or type(stderr) is not bytes:
        raise QueueRetryableError("verifier_output_type")
    if len(stdout) > _MAX_STDOUT or len(stderr) > _MAX_STDERR:
        raise QueueRetryableError("verifier_output_cap")
    try:
        stdout.decode("ascii", "strict"); stderr.decode("ascii", "strict")
    except UnicodeDecodeError:
        _raise_fixed(QueueRetryableError("verifier_output_encoding"))
    return hashlib.sha3_512(stdout).digest(), hashlib.sha3_512(stderr).digest()


def _build_verification_evidence(acceptance: object, containment: object, snapshot: CustodySnapshot, expected_verifier_sha256: bytes) -> _VerificationEvidence:
    if type(containment) is not ContainedVerifierResult: raise QueueRetryableError("telemetry_missing")
    if type(acceptance) is not MinimalProofAcceptanceV1: raise QueueHeldError("proof_acceptance_type")
    if acceptance.proof_accepted is not True: raise QueueDeterministicRejectError("proof_rejected")
    try:
        artifact_bytes = acceptance.artifact_bytes; artifact_sha256 = acceptance.artifact_sha256; artifact_sha3_512 = acceptance.artifact_digest; circuit_id = acceptance.circuit_id; canonical_acceptance = acceptance.canonical_bytes(); peak = containment.peak_job_commit_bytes; cap = containment.cap_bytes; cap_enforced = containment.cap_enforced; active = containment.active_process_limit; timed_out = containment.timed_out; exit_code = containment.exit_code; stdout = containment.stdout; stderr = containment.stderr
    except (AttributeError, TypeError, ValueError): _raise_fixed(QueueRetryableError("verifier_result_shape"))
    try: parsed_acceptance = parse_acceptance_bytes(canonical_acceptance)
    except Exception: _raise_fixed(QueueHeldError("proof_acceptance_shape"))
    if type(artifact_bytes) is not int or type(artifact_sha256) is not bytes or len(artifact_sha256) != 32 or type(artifact_sha3_512) is not bytes or len(artifact_sha3_512) != 64 or type(circuit_id) is not bytes or len(circuit_id) != 32 or type(canonical_acceptance) is not bytes or not 0 < len(canonical_acceptance) <= _MAX_ACCEPTANCE or parsed_acceptance.canonical_bytes() != canonical_acceptance or parsed_acceptance != acceptance:
        raise QueueHeldError("proof_acceptance_shape")
    if artifact_bytes != snapshot.artifact_bytes or artifact_sha256 != snapshot.artifact_sha256 or artifact_sha3_512 != snapshot.artifact_sha3_512 or not snapshot.readonly: raise QueueHeldError("custody_identity_mismatch")
    _bytes(expected_verifier_sha256, 32, "queue_verifier_sha256")
    if type(cap) is not int or type(cap_enforced) is not bool or type(active) is not int or type(timed_out) is not bool or type(exit_code) is not int or type(peak) is not int or peak < 0: raise QueueRetryableError("verifier_containment_shape")
    if cap != _CAP_BYTES or cap_enforced is not True or active != _ACTIVE_PROCESS_LIMIT: raise QueueRetryableError("verifier_containment")
    if timed_out or exit_code != 0 or peak > cap: raise QueueRetryableError("verifier_resource")
    stdout_digest, stderr_digest = _bounded_output_digests(stdout, stderr)
    return _VerificationEvidence(artifact_bytes, artifact_sha256, artifact_sha3_512, bytes(expected_verifier_sha256), bytes(circuit_id), canonical_acceptance, _sha(_ACCEPTANCE_DOMAIN, canonical_acceptance), peak, cap, cap_enforced, active, timed_out, exit_code, stdout_digest, stderr_digest)


_TABLE_COLUMNS: Final[dict[str, tuple[str, ...]]] = {
    "queue_metadata": ("id", "schema_version", "queue_id", "config_json", "config_digest", "verifier_sha256", "artifact_bytes_cap", "head_root", "next_transition_seq", "next_admission_seq", "storage_used_bytes", "storage_reserved_bytes", "nonterminal_count", "live_lease_count"),
    "queue_jobs": ("job_id", "operation_id", "material_digest", "artifact_ref", "artifact_bytes", "artifact_sha256", "artifact_sha3_512", "status", "admission_seq", "attempt", "next_eligible_ms", "created_ms", "updated_ms", "last_error_code"),
    "queue_leases": ("job_id", "worker_id", "token_digest", "attempt", "claim_sequence", "leased_ms", "expires_ms"),
    "queue_results": ("operation_id", "job_id", "terminal_status", "receipt_bytes", "error_code", "completed_ms", "claim_sequence", "worker_id", "leased_ms", "expires_ms", "token_digest"),
    "queue_transitions": ("sequence", "transition_kind", "job_id", "operation_id", "before_root", "after_root", "event_bytes", "event_digest"),
}

_DDL: Final[tuple[str, ...]] = (
    "CREATE TABLE queue_metadata (id INTEGER PRIMARY KEY CHECK(id=1), schema_version INTEGER NOT NULL CHECK(schema_version=3), queue_id TEXT NOT NULL, config_json BLOB NOT NULL, config_digest BLOB NOT NULL CHECK(length(config_digest)=64), verifier_sha256 BLOB NOT NULL CHECK(length(verifier_sha256)=32), artifact_bytes_cap INTEGER NOT NULL CHECK(artifact_bytes_cap>0), head_root BLOB NOT NULL CHECK(length(head_root)=64), next_transition_seq INTEGER NOT NULL CHECK(next_transition_seq>=0), next_admission_seq INTEGER NOT NULL CHECK(next_admission_seq>=0), storage_used_bytes INTEGER NOT NULL CHECK(storage_used_bytes>=0), storage_reserved_bytes INTEGER NOT NULL CHECK(storage_reserved_bytes>=0), nonterminal_count INTEGER NOT NULL CHECK(nonterminal_count>=0), live_lease_count INTEGER NOT NULL CHECK(live_lease_count BETWEEN 0 AND 1))",
    "CREATE TABLE queue_jobs (job_id TEXT PRIMARY KEY, operation_id BLOB NOT NULL UNIQUE CHECK(length(operation_id)=64), material_digest BLOB NOT NULL CHECK(length(material_digest)=64), artifact_ref TEXT NOT NULL, artifact_bytes INTEGER NOT NULL CHECK(artifact_bytes>0), artifact_sha256 BLOB NOT NULL CHECK(length(artifact_sha256)=32), artifact_sha3_512 BLOB NOT NULL CHECK(length(artifact_sha3_512)=64), status TEXT NOT NULL CHECK(status IN ('QUEUED','LEASED','VERIFIED','REJECTED','HELD')), admission_seq INTEGER NOT NULL UNIQUE CHECK(admission_seq>=1), attempt INTEGER NOT NULL CHECK(attempt BETWEEN 0 AND 3), next_eligible_ms INTEGER NOT NULL CHECK(next_eligible_ms>=0), created_ms INTEGER NOT NULL CHECK(created_ms>=0), updated_ms INTEGER NOT NULL CHECK(updated_ms>=0), last_error_code TEXT)",
    "CREATE TABLE queue_leases (job_id TEXT PRIMARY KEY, worker_id TEXT NOT NULL, token_digest BLOB NOT NULL CHECK(length(token_digest)=64), attempt INTEGER NOT NULL CHECK(attempt BETWEEN 1 AND 3), claim_sequence INTEGER NOT NULL UNIQUE CHECK(claim_sequence>=1), leased_ms INTEGER NOT NULL CHECK(leased_ms>=0), expires_ms INTEGER NOT NULL CHECK(expires_ms>leased_ms), FOREIGN KEY(job_id) REFERENCES queue_jobs(job_id))",
    "CREATE TABLE queue_results (operation_id BLOB PRIMARY KEY CHECK(length(operation_id)=64), job_id TEXT NOT NULL UNIQUE, terminal_status TEXT NOT NULL CHECK(terminal_status IN ('VERIFIED','REJECTED','HELD')), receipt_bytes BLOB CHECK(receipt_bytes IS NULL OR length(receipt_bytes)<=16384), error_code TEXT, completed_ms INTEGER NOT NULL CHECK(completed_ms>=0), claim_sequence INTEGER NOT NULL CHECK(claim_sequence>=1), worker_id TEXT NOT NULL, leased_ms INTEGER NOT NULL CHECK(leased_ms>=0), expires_ms INTEGER NOT NULL CHECK(expires_ms>leased_ms), token_digest BLOB NOT NULL CHECK(length(token_digest)=64), FOREIGN KEY(operation_id) REFERENCES queue_jobs(operation_id), FOREIGN KEY(job_id) REFERENCES queue_jobs(job_id), CHECK((terminal_status='VERIFIED' AND receipt_bytes IS NOT NULL AND error_code IS NULL) OR (terminal_status IN ('REJECTED','HELD') AND receipt_bytes IS NULL AND error_code IS NOT NULL)))",
    "CREATE TABLE queue_transitions (sequence INTEGER PRIMARY KEY CHECK(sequence>=1), transition_kind TEXT NOT NULL, job_id TEXT NOT NULL, operation_id BLOB NOT NULL CHECK(length(operation_id)=64), before_root BLOB NOT NULL CHECK(length(before_root)=64), after_root BLOB NOT NULL CHECK(length(after_root)=64), event_bytes BLOB NOT NULL, event_digest BLOB NOT NULL UNIQUE CHECK(length(event_digest)=64), FOREIGN KEY(job_id) REFERENCES queue_jobs(job_id), FOREIGN KEY(operation_id) REFERENCES queue_jobs(operation_id))",
)
_TRIGGERS: Final[tuple[str, ...]] = (
    "CREATE TRIGGER queue_jobs_no_delete BEFORE DELETE ON queue_jobs BEGIN SELECT RAISE(ABORT,'queue_jobs_append_only'); END",
    "CREATE TRIGGER queue_jobs_no_update BEFORE UPDATE OF job_id,operation_id,material_digest,artifact_ref,artifact_bytes,artifact_sha256,artifact_sha3_512,admission_seq ON queue_jobs BEGIN SELECT RAISE(ABORT,'queue_jobs_identity_immutable'); END",
    "CREATE TRIGGER queue_leases_no_update BEFORE UPDATE ON queue_leases BEGIN SELECT RAISE(ABORT,'queue_leases_insert_delete_only'); END",
    "CREATE TRIGGER queue_results_no_update BEFORE UPDATE ON queue_results BEGIN SELECT RAISE(ABORT,'queue_results_immutable'); END",
    "CREATE TRIGGER queue_results_no_delete BEFORE DELETE ON queue_results BEGIN SELECT RAISE(ABORT,'queue_results_immutable'); END",
    "CREATE TRIGGER queue_transitions_no_update BEFORE UPDATE ON queue_transitions BEGIN SELECT RAISE(ABORT,'queue_transitions_append_only'); END",
    "CREATE TRIGGER queue_transitions_no_delete BEFORE DELETE ON queue_transitions BEGIN SELECT RAISE(ABORT,'queue_transitions_append_only'); END",
    "CREATE TRIGGER queue_metadata_immutable BEFORE UPDATE OF id,schema_version,queue_id,config_json,config_digest,verifier_sha256,artifact_bytes_cap ON queue_metadata BEGIN SELECT RAISE(ABORT,'queue_metadata_immutable'); END",
)
_INDEXES: Final[tuple[str, ...]] = ("CREATE INDEX queue_jobs_status_eligible ON queue_jobs(status,next_eligible_ms,admission_seq)", "CREATE INDEX queue_leases_expiry ON queue_leases(expires_ms,job_id)", "CREATE UNIQUE INDEX queue_leases_worker_unique ON queue_leases(worker_id)")
_TABLE_SQL: Final[dict[str, str]] = dict(zip(_TABLE_COLUMNS, _DDL))
_INDEX_SQL: Final[dict[str, str]] = {
    "queue_jobs_status_eligible": _INDEXES[0],
    "queue_leases_expiry": _INDEXES[1],
    "queue_leases_worker_unique": _INDEXES[2],
}
_TRIGGER_SQL: Final[dict[str, str]] = {
    "queue_jobs_no_delete": _TRIGGERS[0],
    "queue_jobs_no_update": _TRIGGERS[1],
    "queue_leases_no_update": _TRIGGERS[2],
    "queue_results_no_update": _TRIGGERS[3],
    "queue_results_no_delete": _TRIGGERS[4],
    "queue_transitions_no_update": _TRIGGERS[5],
    "queue_transitions_no_delete": _TRIGGERS[6],
    "queue_metadata_immutable": _TRIGGERS[7],
}


def _normalize_sql(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().rstrip(";")).lower()


class _VerificationQueueStore:
    """The sole writer for the local queue database."""

    def __init__(self, *, path: Path, config: QueueConfig, owner: _QueueRuntimeOwnership | None = None, clock: QueueClock | None = None, before_fault: Callable[[str], None] | None = None, after_commit_fault: Callable[[str], None] | None = None) -> None:
        if not isinstance(path, Path): raise VerificationQueueError("queue_database_path")
        if type(config) is not QueueConfig: raise VerificationQueueError("queue_configuration")
        if type(owner) is not _QueueRuntimeOwnership: raise VerificationQueueError("queue_owner")
        owner.assert_scope(lock_path=path.with_name(path.name + ".runtime-lock"), parent=path.parent)
        if not _owned_directory(path.parent): raise VerificationQueueError("queue_database_parent")
        _database_identity(path, allow_missing=True)
        self.path = path; self.config = config; self._owner = owner; self.clock = clock or SystemQueueClock(); self._before_fault = before_fault; self._after_commit_fault = after_commit_fault
        self._path_identity: tuple[int, int, int, int, int] | None = None; self._parent_identity = _directory_identity(path.parent)
        self._owner_assert()
        if _database_identity(path, allow_missing=True) is None:
            self._bootstrap_missing()
        else:
            self._recover_hot_journal()
            self._verify_existing_before_open()
        self._path_identity = _database_identity(path); self._parent_identity = _directory_identity(path.parent); self._owner_assert(); self._verify_integrity(); self._owner_assert()

    def _owner_assert(self) -> None:
        if type(self._owner) is not _QueueRuntimeOwnership:
            _raise_fixed(VerificationQueueError("queue_owner"))
        self._owner.assert_scope(lock_path=self.path.with_name(self.path.name + ".runtime-lock"), parent=self.path.parent)

    def _verify_existing_before_open(self) -> None:
        self._owner_assert()
        try:
            from app.minimal_clearance_verification_queue_independent import IndependentQueueError, verify_database
            verify_database(self.path, expected_config=self.config.as_json())
        except IndependentQueueError:
            _raise_fixed(QueueIntegrityError("queue_schema"))
        except VerificationQueueError as exc:
            _raise_fixed(exc)
        except Exception:
            _raise_fixed(QueueIntegrityError("queue_database_verify"))
        self._owner_assert()

    @staticmethod
    def _create_schema(connection: sqlite3.Connection) -> None:
        for statement in _DDL + _TRIGGERS + _INDEXES: connection.execute(statement)

    def _recover_hot_journal(self) -> None:
        """Allow SQLite's native rollback recovery, then verify the result."""
        self._owner_assert()
        # A rollback journal may be consumed by SQLite, but a competing WAL
        # or shared-memory sidecar must be rejected before SQLite opens the
        # database.  This path never parses or removes any sidecar itself.
        for suffix in ("-wal", "-shm"):
            try:
                os.lstat(Path(str(self.path) + suffix))
            except FileNotFoundError:
                continue
            except (OSError, ValueError):
                _raise_fixed(VerificationQueueError("queue_database_journal"))
            _raise_fixed(VerificationQueueError("queue_database_journal"))
        journal = Path(str(self.path) + "-journal")
        try:
            os.lstat(journal)
        except FileNotFoundError:
            self._owner_assert()
            return
        except (OSError, ValueError):
            _raise_fixed(VerificationQueueError("queue_database_journal"))
        journal_identity = _sidecar_identity(journal)
        if not 512 <= journal_identity[3] <= MAX_QUEUE_DATABASE_BYTES:
            _raise_fixed(VerificationQueueError("queue_journal_recovery"))
        base_identity = _database_identity(self.path)
        parent_identity = _directory_identity(self.path.parent)
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(_database_uri(self.path, "rw"), uri=True, timeout=5.0, isolation_level=None)
            _connection_binding(connection, self.path, base_identity, parent_identity)  # type: ignore[arg-type]
            # Opening and this read are the only recovery authority.  SQLite
            # consumes a hot rollback journal; this code never parses/unlinks it.
            connection.execute("SELECT 1").fetchone()
            _connection_binding(connection, self.path, base_identity, parent_identity)  # type: ignore[arg-type]
        except VerificationQueueError:
            _raise_fixed(VerificationQueueError("queue_journal_recovery"))
        except Exception:
            _raise_fixed(VerificationQueueError("queue_journal_recovery"))
        finally:
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    _raise_fixed(VerificationQueueError("queue_journal_recovery"))
        try:
            os.lstat(journal)
        except FileNotFoundError:
            pass
        except (OSError, ValueError):
            _raise_fixed(VerificationQueueError("queue_journal_recovery"))
        else:
            _raise_fixed(VerificationQueueError("queue_journal_recovery"))
        current = _database_identity(self.path)
        if base_identity is None or current is None or current[:3] != base_identity[:3] or _directory_identity(self.path.parent) != parent_identity:
            _raise_fixed(VerificationQueueError("queue_database_identity"))
        # The sidecar identity is captured to make the intended recovery
        # object explicit; no caller-visible path or sidecar bytes are used.
        _ = journal_identity
        self._owner_assert()

    def _bootstrap_missing(self) -> None:
        self._owner_assert()
        parent = self.path.parent; parent_identity = _directory_identity(parent); descriptor: int | None = None; stage: Path | None = None; stage_identity: tuple[int, int, int, int, int] | None = None; published_identity: tuple[int, int, int] | None = None; published_by_call = False
        try:
            descriptor, name = tempfile.mkstemp(prefix=".queue-bootstrap-", dir=parent); os.close(descriptor); descriptor = None; stage = Path(name); stage_identity = _database_identity(stage)
            connection = sqlite3.connect(stage, timeout=5.0, isolation_level=None)
            try:
                connection.execute(f"PRAGMA page_size={_PAGE_SIZE}"); connection.execute(f"PRAGMA max_page_count={_MAX_PAGE_COUNT}"); connection.execute("PRAGMA journal_mode=DELETE"); connection.execute("PRAGMA synchronous=FULL"); connection.execute("PRAGMA foreign_keys=ON"); connection.execute("BEGIN IMMEDIATE"); self._create_schema(connection)
                config_bytes = self.config.canonical_bytes; head = _sha(_GENESIS_DOMAIN, self.config.queue_id.encode("ascii"), self.config.digest)
                connection.execute("INSERT INTO queue_metadata VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (1, _SCHEMA_VERSION, self.config.queue_id, config_bytes, self.config.digest, self.config.verifier_sha256, self.config.artifact_bytes_cap, head, 0, 0, 0, 0, 0, 0))
                used = int(connection.execute("PRAGMA page_count").fetchone()[0]) * _PAGE_SIZE; connection.execute("UPDATE queue_metadata SET storage_used_bytes=? WHERE id=1", (used,)); connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction: connection.execute("ROLLBACK")
                raise
            finally: connection.close()
            if stage_identity is None: raise VerificationQueueError("queue_bootstrap_identity")
            with open(stage, "r+b") as handle: os.fsync(handle.fileno())
            from app.minimal_clearance_verification_queue_independent import verify_database
            verify_database(stage, expected_config=self.config.as_json())
            if _directory_identity(parent) != parent_identity: raise VerificationQueueError("queue_database_parent")
            try:
                os.link(stage, self.path); published_by_call = True; target = os.lstat(self.path); published_identity = (int(target.st_dev), int(target.st_ino), int(target.st_nlink))
                try:
                    descriptor = os.open(str(parent), int(getattr(os, "O_RDONLY", 0)) | int(getattr(os, "O_DIRECTORY", 0))); os.fsync(descriptor)
                except (OSError, ValueError):
                    global BOOTSTRAP_CAPABILITY_LIMITATION_COUNT
                    BOOTSTRAP_CAPABILITY_LIMITATION_COUNT += 1
                finally:
                    if descriptor is not None:
                        os.close(descriptor); descriptor = None
            except FileExistsError:
                if _directory_identity(parent) != parent_identity: raise VerificationQueueError("queue_database_parent")
                verify_database(self.path, expected_config=self.config.as_json())
            else:
                current_stage = os.lstat(stage)
                if (int(current_stage.st_dev), int(current_stage.st_ino)) != stage_identity[:2]: raise VerificationQueueError("queue_bootstrap_identity")
                os.unlink(stage); stage = None
                verify_database(self.path, expected_config=self.config.as_json())
            if stage is not None:
                current_stage = os.lstat(stage)
                if (int(current_stage.st_dev), int(current_stage.st_ino)) != stage_identity[:2]: raise VerificationQueueError("queue_bootstrap_identity")
                os.unlink(stage); stage = None
            published_by_call = False
        except Exception as exc:
            if isinstance(exc, VerificationQueueError): _raise_fixed(exc)
            if exc.__class__.__name__ == "IndependentQueueError": _raise_fixed(QueueIntegrityError("queue_bootstrap_verify"))
            _raise_fixed(VerificationQueueError("queue_bootstrap"))
        finally:
            if descriptor is not None:
                try: os.close(descriptor)
                except OSError: pass
            if stage is not None and stage_identity is not None:
                try:
                    current = os.lstat(stage)
                    if (int(current.st_dev), int(current.st_ino)) == stage_identity[:2]: os.unlink(stage)
                except (OSError, ValueError): pass
            if published_by_call and published_identity is not None:
                try:
                    current = os.lstat(self.path)
                    if (int(current.st_dev), int(current.st_ino), int(current.st_nlink)) == published_identity: os.unlink(self.path)
                except (OSError, ValueError): pass
        self._owner_assert()

    def _connect(self) -> sqlite3.Connection:
        self._owner_assert()
        journal = Path(str(self.path) + "-journal")
        try:
            os.lstat(journal)
        except FileNotFoundError:
            pass
        except (OSError, ValueError):
            _raise_fixed(VerificationQueueError("queue_database_journal"))
        else:
            self._recover_hot_journal()
            self._verify_existing_before_open()
        identity = _database_identity(self.path); parent_identity = _directory_identity(self.path.parent)
        if identity is None or (self._path_identity is not None and identity[:3] != self._path_identity[:3]): _raise_fixed(VerificationQueueError("queue_database_identity"))
        if self._parent_identity is not None and parent_identity != self._parent_identity: _raise_fixed(VerificationQueueError("queue_database_parent"))
        for suffix in ("-wal", "-shm"):
            try: os.lstat(Path(str(self.path) + suffix))
            except FileNotFoundError: continue
            except (OSError, ValueError): _raise_fixed(VerificationQueueError("queue_database_journal"))
            _raise_fixed(VerificationQueueError("queue_database_journal"))
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(_database_uri(self.path, "rw"), uri=True, timeout=5.0, isolation_level=None)
            _connection_binding(connection, self.path, identity, parent_identity)
            current = _database_identity(self.path); current_parent = _directory_identity(self.path.parent)
            if current is None or current[:3] != identity[:3] or current_parent != parent_identity: _raise_fixed(VerificationQueueError("queue_database_identity"))
            connection.execute("PRAGMA foreign_keys=ON"); connection.execute("PRAGMA busy_timeout=5000")
            if str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower() != "delete": connection.close(); raise VerificationQueueError("queue_database_journal")
            if int(connection.execute("PRAGMA page_size").fetchone()[0]) != _PAGE_SIZE: connection.close(); raise QueueIntegrityError("queue_schema")
            connection.execute(f"PRAGMA max_page_count={_MAX_PAGE_COUNT}"); connection.execute("PRAGMA synchronous=FULL")
            _connection_binding(connection, self.path, identity, parent_identity)
            final = _database_identity(self.path)
            if final is None or final[:3] != identity[:3] or _directory_identity(self.path.parent) != parent_identity: _raise_fixed(VerificationQueueError("queue_database_identity"))
            self._owner_assert()
            return connection
        except (VerificationQueueError, QueueBackpressureError, QueueIntegrityError) as exc:
            if connection is not None:
                try: connection.close()
                except Exception: pass
            _raise_fixed(exc)
        except sqlite3.Error as exc:
            if connection is not None:
                try: connection.close()
                except Exception: pass
            _raise_fixed(self._translate_sqlite(exc))
        except Exception:
            if connection is not None:
                try: connection.close()
                except Exception: pass
            _raise_fixed(VerificationQueueError("queue_database_open"))

    def _fault(self, label: str) -> None:
        if self._before_fault is not None: self._before_fault(label)

    def _after_commit(self, label: str) -> None:
        if self._after_commit_fault is not None:
            try: self._after_commit_fault(label)
            except BaseException: _raise_fixed(QueueIndeterminateError("queue_commit_indeterminate"))

    def _schema_check(self, connection: sqlite3.Connection) -> None:
        for table, expected in _TABLE_COLUMNS.items():
            if tuple(str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})").fetchall()) != expected: raise QueueIntegrityError("queue_schema")
        objects = connection.execute("SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchall(); expected_objects = {("table", name) for name in _TABLE_COLUMNS} | {("index", name) for name in _INDEX_SQL} | {("trigger", name) for name in _TRIGGER_SQL}
        if {(str(row[0]), str(row[1])) for row in objects} != expected_objects: raise QueueIntegrityError("queue_schema_objects")
        for name, sql_text in _TABLE_SQL.items():
            row = connection.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone()
            if row is None or _normalize_sql(str(row[0])) != _normalize_sql(sql_text): raise QueueIntegrityError("queue_schema_table_sql")
        for name, sql_text in _INDEX_SQL.items():
            row = connection.execute("SELECT sql FROM sqlite_master WHERE type='index' AND name=?", (name,)).fetchone()
            if row is None or _normalize_sql(str(row[0])) != _normalize_sql(sql_text): raise QueueIntegrityError("queue_schema_index_sql")
            expected_columns = {"queue_jobs_status_eligible": ("status", "next_eligible_ms", "admission_seq"), "queue_leases_expiry": ("expires_ms", "job_id"), "queue_leases_worker_unique": ("worker_id",)}[name]
            if tuple(str(item[2]) for item in connection.execute(f"PRAGMA index_info({name})").fetchall()) != expected_columns: raise QueueIntegrityError("queue_schema_index_columns")
            index_table = "queue_jobs" if name == "queue_jobs_status_eligible" else "queue_leases"
            listed = [item for item in connection.execute(f"PRAGMA index_list({index_table})").fetchall() if str(item[1]) == name]
            if len(listed) != 1 or int(listed[0][2]) != (1 if name == "queue_leases_worker_unique" else 0): raise QueueIntegrityError("queue_schema_index_unique")
        for name, sql_text in _TRIGGER_SQL.items():
            row = connection.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?", (name,)).fetchone()
            if row is None or _normalize_sql(str(row[0])) != _normalize_sql(sql_text): raise QueueIntegrityError("queue_schema_trigger_sql")
        foreign_keys = {"queue_leases": {("queue_jobs", "job_id", "job_id")}, "queue_results": {("queue_jobs", "operation_id", "operation_id"), ("queue_jobs", "job_id", "job_id")}, "queue_transitions": {("queue_jobs", "operation_id", "operation_id"), ("queue_jobs", "job_id", "job_id")}}
        for table, expected_fk in foreign_keys.items():
            actual = {(str(row[2]), str(row[3]), str(row[4])) for row in connection.execute(f"PRAGMA foreign_key_list({table})").fetchall()}
            if actual != expected_fk: raise QueueIntegrityError("queue_schema_foreign_keys")

    def _meta(self, connection: sqlite3.Connection) -> tuple[Any, ...]:
        self._assert_connection(connection)
        row = connection.execute("SELECT * FROM queue_metadata WHERE id=1").fetchone()
        if row is None or len(row) != 14: raise QueueIntegrityError("queue_metadata_missing")
        if int(row[1]) != _SCHEMA_VERSION or str(row[2]) != self.config.queue_id or bytes(row[3]) != self.config.canonical_bytes or bytes(row[4]) != self.config.digest or bytes(row[5]) != self.config.verifier_sha256 or int(row[6]) != self.config.artifact_bytes_cap or int(row[10]) < 0 or int(row[11]) < 0 or int(row[12]) < 0 or int(row[12]) > self.config.capacity or int(row[13]) < 0 or int(row[13]) > 1: raise QueueIntegrityError("queue_metadata_drift")
        return tuple(row)

    @staticmethod
    def _page_bytes(connection: sqlite3.Connection) -> int:
        try: count = int(connection.execute("PRAGMA page_count").fetchone()[0]); page = int(connection.execute("PRAGMA page_size").fetchone()[0]); maximum = int(connection.execute("PRAGMA max_page_count").fetchone()[0])
        except (sqlite3.Error, TypeError, ValueError): _raise_fixed(QueueIntegrityError("queue_storage_state"))
        if page != _PAGE_SIZE or maximum != _MAX_PAGE_COUNT or count < 1 or count > _MAX_PAGE_COUNT: raise QueueBackpressureError("queue_storage_capacity")
        return count * page

    def _update_storage_locked(self, connection: sqlite3.Connection, *, nonterminal: int | None = None, leases: int | None = None) -> None:
        meta = self._meta(connection); active = int(meta[12]) if nonterminal is None else nonterminal; live = int(meta[13]) if leases is None else leases
        if not 0 <= active <= self.config.capacity or not 0 <= live <= 1: raise QueueIntegrityError("queue_counter_metadata")
        reserved = active * MAX_TERMINAL_GROWTH_PER_NONTERMINAL; used = self._page_bytes(connection)
        if used + reserved > MAX_QUEUE_DATABASE_BYTES: raise QueueBackpressureError("queue_storage_capacity")
        connection.execute("UPDATE queue_metadata SET storage_used_bytes=?,storage_reserved_bytes=?,nonterminal_count=?,live_lease_count=? WHERE id=1", (used, reserved, active, live)); used_after = self._page_bytes(connection)
        if used_after + reserved > MAX_QUEUE_DATABASE_BYTES: raise QueueBackpressureError("queue_storage_capacity")
        if used_after != used: connection.execute("UPDATE queue_metadata SET storage_used_bytes=? WHERE id=1", (used_after,))

    @staticmethod
    def _metadata_from_row(row: tuple[Any, ...]) -> ArtifactMetadata:
        return ArtifactMetadata(str(row[3]), int(row[4]), bytes(row[5]), bytes(row[6]))

    def _row_to_job(self, row: tuple[Any, ...]) -> QueueJob:
        if len(row) != 14 or str(row[7]) not in _STATUS: raise QueueIntegrityError("queue_job_shape")
        error = None if row[13] is None else _safe_code(str(row[13]))
        return QueueJob(str(row[0]), bytes(row[1]), self._metadata_from_row(row), str(row[7]), int(row[8]), int(row[9]), int(row[10]), error)

    def _get_job_locked(self, connection: sqlite3.Connection, job_id: str) -> QueueJob | None:
        row = connection.execute("SELECT * FROM queue_jobs WHERE job_id=?", (job_id,)).fetchone(); return None if row is None else self._row_to_job(tuple(row))

    @staticmethod
    def _result_from_row(row: tuple[Any, ...]) -> QueueResult:
        if len(row) != 11 or type(row[0]) is not bytes or len(row[0]) != 64 or str(row[2]) not in _TERMINAL: raise QueueIntegrityError("queue_result_shape")
        if row[3] is not None and (type(row[3]) is not bytes or len(row[3]) > _MAX_RECEIPT): raise QueueIntegrityError("queue_result_receipt")
        if str(row[2]) == "VERIFIED" and (row[3] is None or row[4] is not None): raise QueueIntegrityError("queue_result_verified")
        if str(row[2]) != "VERIFIED" and (row[3] is not None or row[4] is None): raise QueueIntegrityError("queue_result_terminal")
        return QueueResult(_safe_token(str(row[1]), "result_job_id", maximum=_MAX_QUEUE_ID), bytes(row[0]), str(row[2]), None if row[3] is None else bytes(row[3]), None if row[4] is None else _safe_code(str(row[4])))

    def _append_transition(self, connection: sqlite3.Connection, *, kind: str, job_id: str, operation_id: bytes, event: Mapping[str, Any]) -> tuple[int, bytes]:
        kind = _safe_token(kind, "queue_transition_kind", maximum=64); metadata = self._meta(connection); sequence = int(metadata[8]) + 1; before = bytes(metadata[7]); event_bytes = _json_bytes(dict(event)); digest = _sha(_EVENT_DOMAIN, _u64(sequence), kind.encode("ascii"), job_id.encode("ascii"), operation_id, event_bytes); after = _sha(_HEAD_DOMAIN, before, _u64(sequence), digest)
        connection.execute("INSERT INTO queue_transitions VALUES (?,?,?,?,?,?,?,?)", (sequence, kind, job_id, operation_id, before, after, event_bytes, digest)); connection.execute("UPDATE queue_metadata SET head_root=?,next_transition_seq=? WHERE id=1", (after, sequence)); return sequence, after

    def _begin(self, connection: sqlite3.Connection) -> None:
        self._owner_assert()
        self._assert_connection(connection)
        try: connection.execute("BEGIN IMMEDIATE"); self._assert_connection(connection); self._owner_assert()
        except sqlite3.Error as exc: _raise_fixed(self._translate_sqlite(exc))

    def _begin_read(self, connection: sqlite3.Connection) -> None:
        self._owner_assert()
        self._assert_connection(connection)
        try:
            connection.execute("BEGIN")
            self._assert_connection(connection)
            self._owner_assert()
        except sqlite3.Error as exc:
            _raise_fixed(self._translate_sqlite(exc))

    def _assert_connection(self, connection: sqlite3.Connection) -> None:
        self._owner_assert()
        identity = _database_identity(self.path)
        parent_identity = _directory_identity(self.path.parent)
        if identity is None or (self._path_identity is not None and identity[:3] != self._path_identity[:3]) or (self._parent_identity is not None and parent_identity != self._parent_identity):
            _raise_fixed(VerificationQueueError("queue_database_identity"))
        _connection_binding(connection, self.path, identity, parent_identity)
        self._owner_assert()

    def _commit(self, connection: sqlite3.Connection) -> None:
        self._owner_assert()
        self._assert_connection(connection)
        try:
            connection.execute("COMMIT")
        except sqlite3.Error as exc:
            _raise_fixed(self._translate_sqlite(exc))
        self._assert_connection(connection)
        self._owner_assert()

    @staticmethod
    def _translate_sqlite(error: sqlite3.Error) -> VerificationQueueError:
        code = getattr(error, "sqlite_errorcode", None)
        if code in {getattr(sqlite3, "SQLITE_FULL", -1), getattr(sqlite3, "SQLITE_TOOBIG", -2)}: return QueueBackpressureError("queue_storage_capacity")
        if code in {getattr(sqlite3, "SQLITE_BUSY", -3), getattr(sqlite3, "SQLITE_LOCKED", -4)}: return VerificationQueueError("queue_busy")
        return VerificationQueueError("queue_database_write")

    def _admit(self, *, job_id: str, metadata: ArtifactMetadata) -> QueueJob:
        self._owner_assert()
        _safe_token(job_id, "job_id", maximum=_MAX_QUEUE_ID)
        if metadata.artifact_bytes > self.config.artifact_bytes_cap: raise QueueConflictError("artifact_cap")
        material = _material_digest(self.config, job_id, metadata); operation_id = _operation_id(self.config, job_id, material); now = int(self.clock.now_ms())
        with closing(self._connect()) as connection:
            began = False
            try:
                self._begin(connection); began = True; self._schema_check(connection); meta = self._meta(connection); existing = self._get_job_locked(connection, job_id)
                if existing is not None:
                    if existing.operation_id != operation_id or existing.metadata != metadata: raise QueueConflictError("admission_conflict")
                    self._commit(connection); began = False; self._owner_assert(); return existing
                depth = int(meta[12])
                if depth >= self.config.capacity: raise QueueBackpressureError("queue_capacity")
                if self._page_bytes(connection) + MAX_TERMINAL_GROWTH_PER_NONTERMINAL * (depth + 1) > MAX_QUEUE_DATABASE_BYTES: raise QueueBackpressureError("queue_storage_capacity")
                admission_seq = int(meta[9]) + 1
                connection.execute("INSERT INTO queue_jobs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (job_id, operation_id, material, metadata.artifact_ref, metadata.artifact_bytes, metadata.artifact_sha256, metadata.artifact_sha3_512, "QUEUED", admission_seq, 0, now, now, now, None)); self._fault("after_admission_write"); connection.execute("UPDATE queue_metadata SET next_admission_seq=? WHERE id=1", (admission_seq,)); self._append_transition(connection, kind="ADMIT", job_id=job_id, operation_id=operation_id, event={"at_ms": now, "status": "QUEUED", "admission_seq": admission_seq, "attempt": 0, "created_ms": now, "next_eligible_ms": now, "material_digest": _hex(material)}); self._fault("after_transition"); self._update_storage_locked(connection, nonterminal=depth + 1, leases=int(meta[13])); self._commit(connection); began = False
            except VerificationQueueError as exc:
                if began and connection.in_transaction: connection.execute("ROLLBACK")
                _raise_fixed(exc)
            except sqlite3.Error as exc:
                if began and connection.in_transaction: connection.execute("ROLLBACK")
                _raise_fixed(self._translate_sqlite(exc))
            except Exception:
                if began and connection.in_transaction: connection.execute("ROLLBACK")
                _raise_fixed(VerificationQueueError("queue_internal"))
        self._after_commit("admit"); self._owner_assert(); return QueueJob(job_id, operation_id, metadata, "QUEUED", admission_seq, 0, now, None)

    @staticmethod
    def _decode_event(row: tuple[Any, ...]) -> dict[str, Any]:
        try: event = json.loads(bytes(row[6]).decode("ascii"))
        except (TypeError, UnicodeDecodeError, json.JSONDecodeError): _raise_fixed(QueueIntegrityError("queue_transition_event"))
        if type(event) is not dict or bytes(row[6]) != _json_bytes(event): raise QueueIntegrityError("queue_transition_event")
        return event

    def _claim_event_without_raw(self, connection: sqlite3.Connection, *, job_id: str, operation_id: bytes, claim_sequence: int) -> dict[str, Any]:
        row = connection.execute("SELECT sequence,transition_kind,job_id,operation_id,before_root,after_root,event_bytes,event_digest FROM queue_transitions WHERE sequence=?", (claim_sequence,)).fetchone()
        if row is None or str(row[1]) != "CLAIM" or str(row[2]) != job_id or bytes(row[3]) != operation_id: raise QueueIntegrityError("queue_claim_history")
        event = self._decode_event(tuple(row)); required = {"at_ms", "status", "attempt", "worker_id", "leased_ms", "expires_ms", "claim_sequence", "token_digest"}
        if set(event) != required or event["status"] != "LEASED" or int(event["claim_sequence"]) != claim_sequence: raise QueueIntegrityError("queue_claim_history")
        _parse_hex(event["token_digest"], 64, "queue_claim_digest"); return event

    def _expire_locked(self, connection: sqlite3.Connection, now: int, *, recover_all: bool = False) -> int:
        query = "SELECT job_id,worker_id,token_digest,attempt,claim_sequence,leased_ms,expires_ms FROM queue_leases ORDER BY expires_ms,job_id" if recover_all else "SELECT job_id,worker_id,token_digest,attempt,claim_sequence,leased_ms,expires_ms FROM queue_leases INDEXED BY queue_leases_expiry WHERE expires_ms<=? ORDER BY expires_ms,job_id"
        rows = connection.execute(query, () if recover_all else (now,)).fetchall(); count = 0; held_count = 0; meta = self._meta(connection); event_prefix = "LEASE_RECOVER_" if recover_all else "LEASE_EXPIRE_"; error_code = "runtime_restart" if recover_all else "lease_expired"
        for job_id, worker_id, token_digest, attempt, claim_sequence, leased_ms, expires_ms in rows:
            job = self._get_job_locked(connection, str(job_id))
            if job is None or job.status != "LEASED" or job.attempt != int(attempt): raise QueueIntegrityError("queue_lease_state")
            event = self._claim_event_without_raw(connection, job_id=job.job_id, operation_id=job.operation_id, claim_sequence=int(claim_sequence))
            if event["worker_id"] != worker_id or int(event["attempt"]) != int(attempt) or int(event["leased_ms"]) != int(leased_ms) or int(event["expires_ms"]) != int(expires_ms) or _parse_hex(event["token_digest"], 64, "queue_claim_digest") != bytes(token_digest): raise QueueIntegrityError("queue_lease_history")
            connection.execute("DELETE FROM queue_leases WHERE job_id=?", (job_id,))
            if job.attempt >= self.config.max_attempts:
                status = "HELD"; held_count += 1; connection.execute("UPDATE queue_jobs SET status=?,updated_ms=?,last_error_code=? WHERE job_id=? AND status='LEASED' AND attempt=?", (status, now, error_code, job_id, job.attempt)); connection.execute("INSERT INTO queue_results VALUES (?,?,?,?,?,?,?,?,?,?,?)", (job.operation_id, job.job_id, status, None, error_code, now, int(claim_sequence), str(worker_id), int(leased_ms), int(expires_ms), bytes(token_digest)))
            else:
                status = "QUEUED"; connection.execute("UPDATE queue_jobs SET status=?,updated_ms=?,next_eligible_ms=?,last_error_code=? WHERE job_id=? AND status='LEASED' AND attempt=?", (status, now, now, error_code, job_id, job.attempt))
            self._append_transition(connection, kind=event_prefix + status, job_id=job.job_id, operation_id=job.operation_id, event={"at_ms": now, "status": status, "attempt": job.attempt, "error_code": error_code, "claim_sequence": int(claim_sequence), "worker_id": str(worker_id), "leased_ms": int(leased_ms), "expires_ms": int(expires_ms), "token_digest": _hex(bytes(token_digest))}); count += 1
        if count: self._update_storage_locked(connection, nonterminal=int(meta[12]) - held_count, leases=int(meta[13]) - count)
        return count

    def _recover_expired(self) -> int:
        self._owner_assert()
        now = int(self.clock.now_ms())
        with closing(self._connect()) as connection:
            began = False
            try:
                self._begin(connection); began = True; self._meta(connection); count = self._expire_locked(connection, now); self._commit(connection); began = False
            except VerificationQueueError as exc:
                if began and connection.in_transaction: connection.execute("ROLLBACK")
                _raise_fixed(exc)
            except sqlite3.Error as exc:
                if began and connection.in_transaction: connection.execute("ROLLBACK")
                _raise_fixed(self._translate_sqlite(exc))
            except Exception:
                if began and connection.in_transaction: connection.execute("ROLLBACK")
                _raise_fixed(VerificationQueueError("queue_internal"))
        self._owner_assert(); return count

    def _recover_startup_leases(self) -> int:
        self._owner_assert()
        now = int(self.clock.now_ms())
        with closing(self._connect()) as connection:
            began = False
            try:
                self._begin(connection); began = True; self._meta(connection); count = self._expire_locked(connection, now, recover_all=True); self._commit(connection); began = False
            except VerificationQueueError as exc:
                if began and connection.in_transaction: connection.execute("ROLLBACK")
                _raise_fixed(exc)
            except sqlite3.Error as exc:
                if began and connection.in_transaction: connection.execute("ROLLBACK")
                _raise_fixed(self._translate_sqlite(exc))
            except Exception:
                if began and connection.in_transaction: connection.execute("ROLLBACK")
                _raise_fixed(VerificationQueueError("queue_internal"))
        self._owner_assert(); return count

    def _recover_claim_after_commit(self, *, job_id: str, raw_token: bytes) -> _QueueWorkItem:
        self._owner_assert()
        try:
            with closing(self._connect()) as connection:
                row = connection.execute("SELECT j.*,l.token_digest,l.claim_sequence,l.leased_ms,l.expires_ms FROM queue_jobs j JOIN queue_leases l ON l.job_id=j.job_id WHERE j.job_id=? AND j.status='LEASED' AND l.worker_id=?", (job_id, _RUNTIME_WORKER_ID)).fetchone()
                if row is None:
                    _raise_fixed(QueueIndeterminateError("queue_commit_indeterminate"))
                job = self._row_to_job(tuple(row[:14]))
                digest = _lease_digest(self.config, job.job_id, _RUNTIME_WORKER_ID, job.attempt, int(row[15]), int(row[16]), int(row[17]), raw_token)
                if bytes(row[14]) != digest:
                    _raise_fixed(QueueIndeterminateError("queue_commit_indeterminate"))
                self._claim_event_without_raw(connection, job_id=job.job_id, operation_id=job.operation_id, claim_sequence=int(row[15]))
                result = _QueueWorkItem(self.config.queue_id, job.job_id, job.operation_id, job.metadata, job.attempt, _RUNTIME_WORKER_ID, int(row[15]), raw_token, int(row[17]), self.config.verifier_sha256)
                self._owner_assert()
                return result
        except QueueIndeterminateError:
            raise
        except BaseException:
            _raise_fixed(QueueIndeterminateError("queue_commit_indeterminate"))

    def _claim_next(self) -> _QueueWorkItem | None:
        self._owner_assert()
        worker_id = _RUNTIME_WORKER_ID
        try:
            raw_token = secrets.token_bytes(32)
        except BaseException:
            _raise_fixed(QueueIndeterminateError("queue_entropy_unavailable"))
        if type(raw_token) is not bytes or len(raw_token) != 32:
            _raise_fixed(QueueIndeterminateError("queue_entropy_unavailable"))
        now = int(self.clock.now_ms())
        with closing(self._connect()) as connection:
            began = False
            try:
                self._begin(connection); began = True; self._schema_check(connection); self._meta(connection); self._expire_locked(connection, now)
                existing = connection.execute("SELECT j.*,l.token_digest,l.claim_sequence,l.leased_ms,l.expires_ms FROM queue_jobs j JOIN queue_leases l ON l.job_id=j.job_id WHERE j.status='LEASED' AND l.worker_id=? AND l.expires_ms>?", (worker_id, now)).fetchone()
                if existing is not None:
                    # A fresh call has no right to recover a live bearer.  The
                    # only recovery path is the local post-commit path below,
                    # while the original raw token is still in memory.
                    raise QueueBackpressureError("queue_worker_capacity")
                metadata = self._meta(connection)
                if int(metadata[13]) >= 1: raise QueueBackpressureError("queue_worker_capacity")
                row = connection.execute("SELECT * FROM queue_jobs INDEXED BY queue_jobs_status_eligible WHERE status='QUEUED' AND next_eligible_ms<=? ORDER BY admission_seq LIMIT 1", (now,)).fetchone()
                if row is None: self._commit(connection); began = False; self._owner_assert(); return None
                job = self._row_to_job(tuple(row)); attempt = job.attempt + 1; expires = now + self.config.lease_seconds * 1000; claim_sequence = int(metadata[8]) + 1; token_digest = _lease_digest(self.config, job.job_id, worker_id, attempt, claim_sequence, now, expires, raw_token)
                updated = connection.execute("UPDATE queue_jobs SET status='LEASED',attempt=?,updated_ms=?,last_error_code=NULL WHERE job_id=? AND status='QUEUED' AND attempt=?", (attempt, now, job.job_id, job.attempt))
                if updated.rowcount != 1: raise QueueLeaseError("claim_cas")
                connection.execute("INSERT INTO queue_leases VALUES (?,?,?,?,?,?,?)", (job.job_id, worker_id, token_digest, attempt, claim_sequence, now, expires)); sequence, _ = self._append_transition(connection, kind="CLAIM", job_id=job.job_id, operation_id=job.operation_id, event={"at_ms": now, "status": "LEASED", "attempt": attempt, "worker_id": worker_id, "leased_ms": now, "expires_ms": expires, "claim_sequence": claim_sequence, "token_digest": _hex(token_digest)})
                if sequence != claim_sequence: raise QueueIntegrityError("queue_claim_sequence")
                self._update_storage_locked(connection, nonterminal=int(metadata[12]), leases=int(metadata[13]) + 1); self._fault("after_claim"); self._commit(connection); began = False
            except VerificationQueueError as exc:
                if began and connection.in_transaction: connection.execute("ROLLBACK")
                _raise_fixed(exc)
            except sqlite3.Error as exc:
                if began and connection.in_transaction: connection.execute("ROLLBACK")
                _raise_fixed(self._translate_sqlite(exc))
            except Exception:
                if began and connection.in_transaction: connection.execute("ROLLBACK")
                _raise_fixed(VerificationQueueError("queue_internal"))
        try:
            self._after_commit("claim")
        except QueueIndeterminateError:
            return self._recover_claim_after_commit(job_id=job.job_id, raw_token=raw_token)
        self._owner_assert(); return _QueueWorkItem(self.config.queue_id, job.job_id, job.operation_id, job.metadata, attempt, worker_id, claim_sequence, raw_token, expires, self.config.verifier_sha256)

    def _validate_work(self, work: _QueueWorkItem) -> None:
        if type(work) is not _QueueWorkItem or work.queue_id != self.config.queue_id: raise QueueLeaseError("completion_work_invalid")
        if type(work.job_id) is not str or len(work.job_id) > _MAX_QUEUE_ID or _SAFE_TOKEN.fullmatch(work.job_id) is None or type(work.operation_id) is not bytes or len(work.operation_id) != 64 or type(work.metadata) is not ArtifactMetadata or type(work.attempt) is not int or not 1 <= work.attempt <= _MAX_ATTEMPTS or work.worker_id != _RUNTIME_WORKER_ID or type(work.claim_sequence) is not int or work.claim_sequence < 1 or type(work.lease_expires_ms) is not int or work.lease_expires_ms <= 0 or type(work.expected_verifier_sha256) is not bytes or len(work.expected_verifier_sha256) != 32 or type(work.lease_token) is not bytes or len(work.lease_token) != 32: raise QueueLeaseError("completion_work_invalid")

    def _historical_work_matches(self, connection: sqlite3.Connection, work: _QueueWorkItem, result_row: tuple[Any, ...] | None = None) -> bool:
        try:
            event = self._claim_event_without_raw(connection, job_id=work.job_id, operation_id=work.operation_id, claim_sequence=work.claim_sequence); digest = _lease_digest(self.config, work.job_id, work.worker_id, work.attempt, work.claim_sequence, int(event["leased_ms"]), int(event["expires_ms"]), work.lease_token)
        except (QueueIntegrityError, QueueLeaseError): return False
        if event["worker_id"] != work.worker_id or int(event["attempt"]) != work.attempt or int(event["expires_ms"]) != work.lease_expires_ms or _parse_hex(event["token_digest"], 64, "queue_claim_digest") != digest: return False
        return result_row is None or (len(result_row) == 11 and int(result_row[6]) == work.claim_sequence and str(result_row[7]) == work.worker_id and int(result_row[8]) == int(event["leased_ms"]) and int(result_row[9]) == int(event["expires_ms"]) and bytes(result_row[10]) == digest)

    def _require_live_lease(self, connection: sqlite3.Connection, work: _QueueWorkItem) -> QueueJob:
        self._validate_work(work); job = self._get_job_locked(connection, work.job_id)
        if job is None or job.operation_id != work.operation_id or job.metadata != work.metadata or work.expected_verifier_sha256 != self.config.verifier_sha256 or job.status != "LEASED" or job.attempt != work.attempt: raise QueueLeaseError("completion_not_live")
        row = connection.execute("SELECT worker_id,token_digest,attempt,claim_sequence,leased_ms,expires_ms FROM queue_leases WHERE job_id=?", (work.job_id,)).fetchone()
        if row is None or str(row[0]) != work.worker_id or int(row[2]) != work.attempt or int(row[3]) != work.claim_sequence or int(row[5]) != work.lease_expires_ms: raise QueueLeaseError("completion_lease_mismatch")
        expected = _lease_digest(self.config, work.job_id, work.worker_id, work.attempt, work.claim_sequence, int(row[4]), int(row[5]), work.lease_token)
        if type(row[1]) is not bytes or len(row[1]) != 64 or bytes(row[1]) != expected or not self._historical_work_matches(connection, work): raise QueueLeaseError("completion_lease_fence")
        if int(row[5]) <= int(self.clock.now_ms()):
            self._expire_locked(connection, int(self.clock.now_ms())); self._commit(connection); raise QueueLeaseError("lease_expired")
        return job

    def _build_receipt(self, work: _QueueWorkItem, evidence: _VerificationEvidence) -> _VerificationReceipt:
        provisional = _VerificationReceipt(_SCHEMA, self.config.queue_id, work.job_id, work.operation_id, work.attempt, evidence, bytes(64)); receipt_id = _sha(_RECEIPT_DOMAIN, _json_bytes(provisional.as_json(include_id=False))); return _VerificationReceipt(provisional.schema, provisional.queue_id, provisional.job_id, provisional.operation_id, provisional.attempt, provisional.evidence, receipt_id)

    def _complete(self, work: _QueueWorkItem, *, status: str, evidence: _VerificationEvidence | None = None, error_code: str | None = None) -> QueueResult:
        self._owner_assert()
        self._validate_work(work)
        if status not in _TERMINAL: raise QueueIntegrityError("completion_status")
        if error_code is not None: error_code = _safe_code(error_code)
        receipt = None if evidence is None else self._build_receipt(work, evidence); receipt_bytes = None if receipt is None else receipt.canonical_bytes; now = int(self.clock.now_ms())
        with closing(self._connect()) as connection:
            began = False
            try:
                self._begin(connection); began = True; self._schema_check(connection); durable = connection.execute("SELECT operation_id,job_id,terminal_status,receipt_bytes,error_code,completed_ms,claim_sequence,worker_id,leased_ms,expires_ms,token_digest FROM queue_results WHERE operation_id=?", (work.operation_id,)).fetchone()
                if durable is not None:
                    if not self._historical_work_matches(connection, work, tuple(durable)): raise QueueLeaseError("completion_lease_fence")
                    result = self._result_from_row(tuple(durable)); intended_error = None if status == "VERIFIED" else error_code or ("verification_rejected" if status == "REJECTED" else "queue_held")
                    if result.status != status or result.receipt_bytes != receipt_bytes or result.error_code != intended_error: raise QueueConflictError("completion_conflict")
                    self._commit(connection); began = False; self._owner_assert(); return result
                job = self._require_live_lease(connection, work)
                if status == "VERIFIED" and receipt is None: raise QueueIntegrityError("verified_receipt_missing")
                if status != "VERIFIED" and evidence is not None: raise QueueIntegrityError("nonverified_evidence")
                new_error = None if status == "VERIFIED" else error_code or ("verification_rejected" if status == "REJECTED" else "queue_held"); lease = connection.execute("SELECT worker_id,token_digest,attempt,claim_sequence,leased_ms,expires_ms FROM queue_leases WHERE job_id=?", (work.job_id,)).fetchone()
                if lease is None: raise QueueLeaseError("completion_lease_mismatch")
                connection.execute("DELETE FROM queue_leases WHERE job_id=?", (work.job_id,)); updated = connection.execute("UPDATE queue_jobs SET status=?,updated_ms=?,last_error_code=? WHERE job_id=? AND status='LEASED' AND attempt=?", (status, now, new_error, work.job_id, work.attempt))
                if updated.rowcount != 1: raise QueueLeaseError("completion_cas")
                connection.execute("INSERT INTO queue_results VALUES (?,?,?,?,?,?,?,?,?,?,?)", (work.operation_id, work.job_id, status, receipt_bytes, new_error, now, int(lease[3]), str(lease[0]), int(lease[4]), int(lease[5]), bytes(lease[1]))); self._fault("after_result_write"); self._append_transition(connection, kind="COMPLETE_" + status, job_id=work.job_id, operation_id=work.operation_id, event={"at_ms": now, "status": status, "attempt": work.attempt, "error_code": new_error, "receipt_digest": None if receipt is None else _hex(receipt.digest), "claim_sequence": int(lease[3]), "worker_id": str(lease[0]), "leased_ms": int(lease[4]), "expires_ms": int(lease[5]), "token_digest": _hex(bytes(lease[1]))}); self._fault("after_transition"); meta = self._meta(connection); self._update_storage_locked(connection, nonterminal=int(meta[12]) - 1, leases=int(meta[13]) - 1); self._commit(connection); began = False
            except (QueueLeaseError, VerificationQueueError) as exc:
                if began and connection.in_transaction: connection.execute("ROLLBACK")
                _raise_fixed(exc)
            except sqlite3.Error as exc:
                if began and connection.in_transaction: connection.execute("ROLLBACK")
                _raise_fixed(self._translate_sqlite(exc))
            except Exception:
                if began and connection.in_transaction: connection.execute("ROLLBACK")
                _raise_fixed(VerificationQueueError("queue_internal"))
        self._after_commit("complete"); self._owner_assert(); return QueueResult(work.job_id, work.operation_id, status, receipt_bytes, new_error)

    def _complete_verified(self, work: _QueueWorkItem, evidence: _VerificationEvidence) -> QueueResult:
        self._validate_work(work)
        if type(evidence) is not _VerificationEvidence: raise QueueIntegrityError("completion_evidence_shape")
        if evidence.verifier_sha256 != self.config.verifier_sha256 or evidence.artifact_bytes != work.metadata.artifact_bytes or evidence.artifact_sha256 != work.metadata.artifact_sha256 or evidence.artifact_sha3_512 != work.metadata.artifact_sha3_512 or evidence.cap_bytes != _CAP_BYTES or evidence.cap_enforced is not True or evidence.active_process_limit != _ACTIVE_PROCESS_LIMIT or evidence.timed_out is not False or evidence.exit_code != 0 or evidence.peak_job_commit_bytes > _CAP_BYTES: raise QueueIntegrityError("completion_evidence_binding")
        return self._complete(work, status="VERIFIED", evidence=evidence)

    def _complete_rejected(self, work: _QueueWorkItem, error_code: str = "verification_rejected") -> QueueResult:
        if type(error_code) is not str or error_code not in (_PROOF_DETERMINISTIC_REJECT_CODES | {"proof_rejected", "verification_rejected"}):
            _raise_fixed(QueueIntegrityError("rejection_code_not_allowed"))
        return self._complete(work, status="REJECTED", error_code=error_code)

    def _complete_retryable(self, work: _QueueWorkItem, error_code: str) -> QueueResult | None:
        self._owner_assert()
        self._validate_work(work); error_code = _safe_code(error_code)
        if error_code not in self.config.retryable_codes: raise QueueIntegrityError("retry_code_not_allowed")
        if work.attempt >= self.config.max_attempts: return self._complete(work, status="HELD", error_code=error_code)
        now = int(self.clock.now_ms())
        with closing(self._connect()) as connection:
            began = False
            try:
                self._begin(connection); began = True; self._schema_check(connection); durable = connection.execute("SELECT operation_id,job_id,terminal_status,receipt_bytes,error_code,completed_ms,claim_sequence,worker_id,leased_ms,expires_ms,token_digest FROM queue_results WHERE operation_id=?", (work.operation_id,)).fetchone()
                if durable is not None:
                    if not self._historical_work_matches(connection, work, tuple(durable)): raise QueueLeaseError("completion_lease_fence")
                    result = self._result_from_row(tuple(durable))
                    if result.status != "HELD" or result.error_code != error_code: raise QueueConflictError("retry_conflict")
                    self._commit(connection); began = False; self._owner_assert(); return result
                current = self._get_job_locked(connection, work.job_id)
                if current is not None and current.status == "QUEUED" and current.attempt == work.attempt and current.last_error_code == error_code: self._commit(connection); began = False; self._owner_assert(); return None
                if current is not None and current.status != "LEASED": self._commit(connection); began = False; _raise_fixed(QueueIndeterminateError("retry_reconciled"))
                job = self._require_live_lease(connection, work); lease = connection.execute("SELECT worker_id,token_digest,attempt,claim_sequence,leased_ms,expires_ms FROM queue_leases WHERE job_id=?", (work.job_id,)).fetchone()
                if lease is None: raise QueueLeaseError("completion_lease_mismatch")
                connection.execute("DELETE FROM queue_leases WHERE job_id=?", (work.job_id,)); updated = connection.execute("UPDATE queue_jobs SET status='QUEUED',updated_ms=?,next_eligible_ms=?,last_error_code=? WHERE job_id=? AND status='LEASED' AND attempt=?", (now, now, error_code, work.job_id, work.attempt))
                if updated.rowcount != 1: raise QueueLeaseError("retry_cas")
                self._fault("after_retry_write"); self._append_transition(connection, kind="RETRY_QUEUED", job_id=job.job_id, operation_id=job.operation_id, event={"at_ms": now, "status": "QUEUED", "attempt": work.attempt, "error_code": error_code, "claim_sequence": int(lease[3]), "worker_id": str(lease[0]), "leased_ms": int(lease[4]), "expires_ms": int(lease[5]), "token_digest": _hex(bytes(lease[1]))}); self._fault("after_transition"); meta = self._meta(connection); self._update_storage_locked(connection, nonterminal=int(meta[12]), leases=int(meta[13]) - 1); self._commit(connection); began = False
            except (QueueLeaseError, VerificationQueueError) as exc:
                if began and connection.in_transaction: connection.execute("ROLLBACK")
                _raise_fixed(exc)
            except sqlite3.Error as exc:
                if began and connection.in_transaction: connection.execute("ROLLBACK")
                _raise_fixed(self._translate_sqlite(exc))
            except Exception:
                if began and connection.in_transaction: connection.execute("ROLLBACK")
                _raise_fixed(VerificationQueueError("queue_internal"))
        self._after_commit("retry"); self._owner_assert(); return None

    def _retry_result(self, operation_id: bytes) -> QueueResult | None:
        self._owner_assert()
        operation_id = _bytes(operation_id, 64, "operation_id")
        with closing(self._connect()) as connection: row = connection.execute("SELECT operation_id,job_id,terminal_status,receipt_bytes,error_code,completed_ms,claim_sequence,worker_id,leased_ms,expires_ms,token_digest FROM queue_results WHERE operation_id=?", (operation_id,)).fetchone()
        self._owner_assert()
        return None if row is None else self._result_from_row(tuple(row))

    def _get_job(self, job_id: str) -> QueueJob | None:
        self._owner_assert()
        _safe_token(job_id, "job_id", maximum=_MAX_QUEUE_ID)
        with closing(self._connect()) as connection: result = self._get_job_locked(connection, job_id)
        self._owner_assert(); return result

    def _read_projection(self) -> dict[str, Any]:
        self._owner_assert()
        with closing(self._connect()) as connection:
            began = False
            try:
                self._begin_read(connection); began = True
                meta = self._meta(connection)
                counts = {status: 0 for status in _STATUS}
                for (status,) in connection.execute("SELECT status FROM queue_jobs ORDER BY admission_seq"):
                    counts[str(status)] = counts.get(str(status), 0) + 1
                oldest = connection.execute("SELECT MIN(admission_seq) FROM queue_jobs WHERE status IN ('QUEUED','LEASED')").fetchone()[0]
                lease_age = connection.execute("SELECT MIN(?-leased_ms) FROM queue_leases", (int(self.clock.now_ms()),)).fetchone()[0]
                rows = [str(code) for (code,) in connection.execute("SELECT last_error_code FROM queue_jobs WHERE last_error_code IS NOT NULL ORDER BY last_error_code")]
                failures: dict[str, int] = {}
                for code in rows:
                    failures[code] = failures.get(code, 0) + 1
                projection = {
                    "head_root": bytes(meta[7]),
                    "counts": counts,
                    "leases": int(meta[13]),
                    "transitions": int(meta[8]),
                    "oldest_admission_seq": oldest,
                    "oldest_lease_age_ms": None if lease_age is None else int(lease_age),
                    "failure_counts": failures,
                    "storage_used_bytes": int(meta[10]),
                    "storage_reserved_bytes": int(meta[11]),
                }
                connection.execute("COMMIT"); began = False
                self._owner_assert(); return projection
            except VerificationQueueError as exc:
                if began and connection.in_transaction:
                    connection.execute("ROLLBACK")
                _raise_fixed(exc)
            except sqlite3.Error as exc:
                if began and connection.in_transaction:
                    connection.execute("ROLLBACK")
                _raise_fixed(self._translate_sqlite(exc))
            except Exception:
                if began and connection.in_transaction:
                    connection.execute("ROLLBACK")
                _raise_fixed(VerificationQueueError("queue_projection"))

    def _snapshot(self) -> dict[str, Any]:
        self._owner_assert()
        projection = self._read_projection()
        result = {"head_root": projection["head_root"], "counts": projection["counts"], "leases": projection["leases"], "transitions": projection["transitions"]}
        self._owner_assert(); return result

    def _support_summary(self) -> dict[str, Any]:
        self._owner_assert()
        projection = self._read_projection()
        lease_age = projection["oldest_lease_age_ms"]
        counts = projection["counts"]
        result = {"schema": _SCHEMA, "queue_id": self.config.queue_id, "head_root": _hex(projection["head_root"]), "status_counts": counts, "nonterminal_depth": counts["QUEUED"] + counts["LEASED"], "oldest_admission_seq": projection["oldest_admission_seq"], "oldest_lease_age_bucket": None if lease_age is None else ("0-59s" if lease_age < 60_000 else "60s+"), "failure_counts": projection["failure_counts"], "storage_used_bytes": projection["storage_used_bytes"], "storage_reserved_bytes": projection["storage_reserved_bytes"], "storage_capacity_bytes": MAX_QUEUE_DATABASE_BYTES}
        self._owner_assert(); return result

    def _verify_integrity(self) -> None:
        self._owner_assert()
        try:
            from app.minimal_clearance_verification_queue_independent import IndependentQueueError, verify_database
            verify_database(self.path, expected_config=self.config.as_json())
        except IndependentQueueError: _raise_fixed(QueueIntegrityError("queue_integrity"))
        except VerificationQueueError as exc: _raise_fixed(exc)
        except Exception: _raise_fixed(QueueIntegrityError("queue_integrity"))
        self._owner_assert()

    def _export_bytes(self) -> bytes:
        self._owner_assert()
        with closing(self._connect()) as connection:
            began = False
            try:
                self._begin(connection); began = True; self._schema_check(connection); self._meta(connection); raw = connection.serialize()
                if type(raw) is not bytes or not 0 < len(raw) <= MAX_QUEUE_DATABASE_BYTES: raise QueueBackpressureError("queue_export_capacity")
                self._commit(connection); began = False
            except VerificationQueueError as exc:
                if began and connection.in_transaction: connection.execute("ROLLBACK")
                _raise_fixed(exc)
            except sqlite3.Error as exc:
                if began and connection.in_transaction: connection.execute("ROLLBACK")
                _raise_fixed(self._translate_sqlite(exc))
            except Exception:
                if began and connection.in_transaction: connection.execute("ROLLBACK")
                _raise_fixed(VerificationQueueError("queue_export"))
        try:
            from app.minimal_clearance_verification_queue_independent import verify_export_bytes
            verify_export_bytes(raw, expected_config=self.config.as_json())
        except Exception: _raise_fixed(QueueIntegrityError("queue_export_integrity"))
        self._owner_assert()
        return raw

    def _process_one(self, *, verifier: NativeMinimalClearanceVerifier, custody: _FilesystemArtifactCustody) -> QueueResult | None:
        self._owner_assert()
        result = _QueueProcessor(store=self, verifier=verifier, custody=custody).process_one()
        self._owner_assert()
        return result

    def _close(self) -> None:
        self._owner_assert()
        return None


def _parse_receipt(raw: bytes, config: QueueConfig) -> _VerificationReceipt:
    if type(raw) is not bytes or not 0 < len(raw) <= _MAX_RECEIPT: raise QueueIntegrityError("queue_receipt_bounds")
    try: value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError): _raise_fixed(QueueIntegrityError("queue_receipt_encoding"))
    if type(value) is not dict or value.get("schema") != _SCHEMA or value.get("queue_id") != config.queue_id: raise QueueIntegrityError("queue_receipt_schema")
    expected_keys = {"schema", "queue_id", "job_id", "operation_id", "attempt", "evidence", "receipt_id"}
    if set(value) != expected_keys: raise QueueIntegrityError("queue_receipt_keys")
    operation = _parse_hex(value["operation_id"], 64, "receipt_operation_id"); receipt_id = _parse_hex(value["receipt_id"], 64, "receipt_id")
    if _safe_token(value["job_id"], "receipt_job_id", maximum=_MAX_QUEUE_ID) != value["job_id"] or type(value["attempt"]) is not int or value["attempt"] < 1: raise QueueIntegrityError("queue_receipt_identity")
    evidence = value["evidence"]; evidence_keys = {"artifact_bytes", "artifact_sha256", "artifact_sha3_512", "verifier_sha256", "circuit_id", "acceptance_bytes", "proof_acceptance_digest", "peak_job_commit_bytes", "cap_bytes", "cap_enforced", "active_process_limit", "timed_out", "exit_code", "stdout_sha3_512", "stderr_sha3_512"}
    if type(evidence) is not dict or set(evidence) != evidence_keys: raise QueueIntegrityError("queue_receipt_evidence_keys")
    if any(type(evidence[field]) is not int for field in ("artifact_bytes", "peak_job_commit_bytes", "cap_bytes", "active_process_limit", "exit_code")) or type(evidence["cap_enforced"]) is not bool or type(evidence["timed_out"]) is not bool: raise QueueIntegrityError("queue_receipt_evidence_types")
    evidence_object = _VerificationEvidence(evidence["artifact_bytes"], _parse_hex(evidence["artifact_sha256"], 32, "evidence_sha256"), _parse_hex(evidence["artifact_sha3_512"], 64, "evidence_sha3"), _parse_hex(evidence["verifier_sha256"], 32, "evidence_verifier"), _parse_hex(evidence["circuit_id"], 32, "evidence_circuit"), _parse_hex(evidence["acceptance_bytes"], None, "evidence_acceptance_bytes"), _parse_hex(evidence["proof_acceptance_digest"], 64, "evidence_acceptance"), evidence["peak_job_commit_bytes"], evidence["cap_bytes"], evidence["cap_enforced"], evidence["active_process_limit"], evidence["timed_out"], evidence["exit_code"], _parse_hex(evidence["stdout_sha3_512"], 64, "evidence_stdout"), _parse_hex(evidence["stderr_sha3_512"], 64, "evidence_stderr"))
    result = _VerificationReceipt(_SCHEMA, config.queue_id, value["job_id"], operation, value["attempt"], evidence_object, receipt_id)
    if raw != result.canonical_bytes or receipt_id != _sha(_RECEIPT_DOMAIN, _json_bytes(result.as_json(include_id=False))) or evidence_object.verifier_sha256 != config.verifier_sha256: raise QueueIntegrityError("queue_receipt_binding")
    return result


class _QueueProcessor:
    """One runtime-owned synchronous verifier/custody processing boundary."""

    def __init__(self, *, store: _VerificationQueueStore, custody: _ProofArtifactCustodyPort, verifier: NativeMinimalClearanceVerifier) -> None:
        if type(verifier) is not NativeMinimalClearanceVerifier or type(custody) is not _FilesystemArtifactCustody:
            raise VerificationQueueError("queue_processor_port")
        self.store = store; self.custody = custody; self.verifier = verifier; self.last_verification_wall_ms: int | None = None; self.last_verification_started: float | None = None; self.last_verification_ended: float | None = None

    def _reconcile_lease_loss(self, work: _QueueWorkItem) -> QueueResult:
        try:
            durable = self.store._retry_result(work.operation_id)
        except BaseException:
            _raise_fixed(QueueIndeterminateError("queue_lease_indeterminate"))
        if durable is not None: return durable
        try:
            job = self.store._get_job(work.job_id)
        except BaseException:
            _raise_fixed(QueueIndeterminateError("queue_lease_indeterminate"))
        if job is not None and job.status == "QUEUED" and job.attempt == work.attempt: return QueueResult(job.job_id, job.operation_id, "QUEUED", None, job.last_error_code)
        _raise_fixed(QueueIndeterminateError("queue_lease_indeterminate"))

    def _terminal(self, work: _QueueWorkItem, *, status: str, error_code: str | None = None, evidence: _VerificationEvidence | None = None) -> QueueResult:
        try:
            if status == "VERIFIED": return self.store._complete_verified(work, evidence)  # type: ignore[arg-type]
            if status == "REJECTED": return self.store._complete_rejected(work, error_code or "verification_rejected")
            return self.store._complete(work, status="HELD", error_code=error_code or "queue_held")
        except QueueLeaseError as exc:
            if _trusted_store_code(exc, _STORE_LEASE_LOSS_CODES) is not None: return self._reconcile_lease_loss(work)
            _raise_fixed(QueueIndeterminateError("queue_lease_indeterminate"))
        except QueueIndeterminateError as exc:
            if _trusted_store_code(exc, _STORE_INDETERMINATE_CODES) is None: _raise_fixed(QueueIndeterminateError("queue_commit_indeterminate"))
            try:
                durable = self.store._retry_result(work.operation_id)
            except BaseException:
                _raise_fixed(QueueIndeterminateError("queue_commit_indeterminate"))
            if durable is not None: return durable
            _raise_fixed(QueueIndeterminateError("queue_commit_indeterminate"))
        except BaseException:
            _raise_fixed(QueueIndeterminateError("queue_commit_indeterminate"))

    def _retry(self, work: _QueueWorkItem, code: str) -> QueueResult:
        try:
            result = self.store._complete_retryable(work, code); return result or QueueResult(work.job_id, work.operation_id, "QUEUED", None, code)
        except QueueLeaseError as exc:
            if _trusted_store_code(exc, _STORE_LEASE_LOSS_CODES) is not None: return self._reconcile_lease_loss(work)
            _raise_fixed(QueueIndeterminateError("queue_retry_indeterminate"))
        except QueueIndeterminateError as exc:
            if _trusted_store_code(exc, _STORE_INDETERMINATE_CODES) is None: _raise_fixed(QueueIndeterminateError("queue_retry_indeterminate"))
            try:
                durable = self.store._retry_result(work.operation_id)
                if durable is not None: return durable
                job = self.store._get_job(work.job_id)
            except BaseException:
                _raise_fixed(QueueIndeterminateError("queue_retry_indeterminate"))
            if job is not None and job.status == "QUEUED" and job.attempt == work.attempt: return QueueResult(work.job_id, work.operation_id, "QUEUED", None, job.last_error_code)
            _raise_fixed(QueueIndeterminateError("queue_retry_indeterminate"))
        except BaseException:
            _raise_fixed(QueueIndeterminateError("queue_retry_indeterminate"))

    @staticmethod
    def _snapshot_valid(snapshot: object, work: _QueueWorkItem) -> bool:
        try:
            return (
                type(snapshot) is CustodySnapshot
                and isinstance(snapshot.path, Path)
                and snapshot.path.is_file()
                and not snapshot.path.is_symlink()
                and snapshot.artifact_bytes == work.metadata.artifact_bytes
                and snapshot.artifact_sha256 == work.metadata.artifact_sha256
                and snapshot.artifact_sha3_512 == work.metadata.artifact_sha3_512
                and snapshot.readonly is True
                and callable(snapshot.cleanup)
            )
        except BaseException:
            return False

    @staticmethod
    def _cleanup_snapshot(snapshot: CustodySnapshot | None) -> bool:
        if type(snapshot) is not CustodySnapshot:
            return False
        try:
            cleanup = snapshot.cleanup
            if not callable(cleanup):
                return False
            cleanup()
            return False
        except BaseException:
            return True

    def _snapshot_failure(self, work: _QueueWorkItem, snapshot: CustodySnapshot | None, code: str) -> QueueResult:
        if self._cleanup_snapshot(snapshot):
            return self._terminal(work, status="HELD", error_code="custody_cleanup")
        return self._terminal(work, status="HELD", error_code=code)

    def _snapshot_exception(self, work: _QueueWorkItem, error: BaseException) -> QueueResult:
        """Classify only exact producer custody codes at the custody boundary."""
        if type(error) is QueueRetryableError:
            code = _exact_code(error, types=(QueueRetryableError,), allowed=_QUEUE_RETRY_CODES)
            if code is not None and code in self.store.config.retryable_codes:
                return self._retry(work, code)
        if type(error) is QueueHeldError:
            code = _exact_code(error, types=(QueueHeldError,), allowed=_QUEUE_HELD_CODES)
            return self._terminal(work, status="HELD", error_code=code or "custody_snapshot")
        return self._terminal(work, status="HELD", error_code="custody_snapshot")

    def _proof_failure(self, work: _QueueWorkItem, error: BaseException) -> QueueResult:
        if type(error) is not MinimalClearanceProofStateError:
            return self._terminal(work, status="HELD", error_code="worker_exception")
        code = _exact_code(error, types=(MinimalClearanceProofStateError,), allowed=_PROOF_TRUSTED_CODES | _PROOF_DETERMINISTIC_REJECT_CODES)
        if code is None:
            return self._terminal(work, status="HELD", error_code="worker_exception")
        if code in _PROOF_DETERMINISTIC_REJECT_CODES:
            return self._terminal(work, status="REJECTED", error_code=code)
        if code in self.store.config.retryable_codes:
            return self._retry(work, code)
        return self._terminal(work, status="HELD", error_code=code)

    def _producer_failure(self, work: _QueueWorkItem, error: BaseException) -> QueueResult:
        """Map only fixed errors raised by the producer-owned evidence builder."""
        if type(error) is QueueDeterministicRejectError:
            code = _exact_code(error, types=(QueueDeterministicRejectError,), allowed=_PROOF_DETERMINISTIC_REJECT_CODES | {"proof_rejected"})
            return self._terminal(work, status="REJECTED", error_code=code) if code is not None else self._terminal(work, status="HELD", error_code="worker_exception")
        if type(error) is QueueRetryableError:
            code = _exact_code(error, types=(QueueRetryableError,), allowed=_QUEUE_RETRY_CODES)
            if code is None:
                return self._terminal(work, status="HELD", error_code="worker_exception")
            return self._retry(work, code) if code in self.store.config.retryable_codes else self._terminal(work, status="HELD", error_code=code)
        if type(error) is QueueHeldError:
            code = _exact_code(error, types=(QueueHeldError,), allowed=_QUEUE_HELD_CODES)
            return self._terminal(work, status="HELD", error_code=code) if code is not None else self._terminal(work, status="HELD", error_code="worker_exception")
        return self._terminal(work, status="HELD", error_code="worker_exception")

    def process_one(self) -> QueueResult | None:
        work = self.store._claim_next()
        if work is None: return None
        snapshot: CustodySnapshot | None = None
        try:
            snapshot = self.custody.snapshot(work.metadata.artifact_ref, work.metadata)
        except BaseException as error:
            return self._snapshot_exception(work, error)
        if not self._snapshot_valid(snapshot, work):
            return self._snapshot_failure(work, snapshot, "custody_snapshot_identity")
        try:
            identity = self.verifier.identity_sha256()
        except BaseException:
            return self._snapshot_failure(work, snapshot, "verifier_identity")
        if identity != self.store.config.verifier_sha256:
            return self._snapshot_failure(work, snapshot, "verifier_identity")
        started = time.perf_counter(); self.last_verification_started = started
        try:
            call_result = self.verifier.verify(
                snapshot.path,
                expected_artifact_bytes=work.metadata.artifact_bytes,
                expected_artifact_sha256=work.metadata.artifact_sha256,
                expected_artifact_sha3_512=work.metadata.artifact_sha3_512,
            )
        except MinimalClearanceProofStateError as exc:
            if self._cleanup_snapshot(snapshot):
                return self._terminal(work, status="HELD", error_code="custody_cleanup")
            return self._proof_failure(work, exc)
        except BaseException:
            return self._snapshot_failure(work, snapshot, "worker_exception")
        finally:
            ended = time.perf_counter(); self.last_verification_ended = ended; self.last_verification_wall_ms = max(1, int(round((ended - started) * 1000)))
        if type(call_result) is not NativeVerificationCallResult:
            if self._cleanup_snapshot(snapshot):
                return self._terminal(work, status="HELD", error_code="custody_cleanup")
            return self._terminal(work, status="HELD", error_code="verifier_result_shape")
        try:
            evidence = _build_verification_evidence(call_result.acceptance, call_result.containment, snapshot, self.store.config.verifier_sha256)
        except (QueueDeterministicRejectError, QueueRetryableError, QueueHeldError) as exc:
            if self._cleanup_snapshot(snapshot):
                return self._terminal(work, status="HELD", error_code="custody_cleanup")
            return self._producer_failure(work, exc)
        except BaseException:
            return self._snapshot_failure(work, snapshot, "worker_exception")
        if self._cleanup_snapshot(snapshot):
            return self._terminal(work, status="HELD", error_code="custody_cleanup")
        snapshot = None
        return self._terminal(work, status="VERIFIED", evidence=evidence)

__all__ = ("ArtifactMetadata", "QueueBackpressureError", "QueueClock", "QueueConfig", "QueueConflictError", "QueueDeterministicRejectError", "QueueHeldError", "QueueIndeterminateError", "QueueIntegrityError", "QueueJob", "QueueLeaseError", "QueueResult", "QueueRetryableError", "SystemQueueClock", "VerificationQueueError", "MAX_QUEUE_DATABASE_BYTES", "MAX_QUEUE_CAPACITY", "MAX_TERMINAL_GROWTH_PER_NONTERMINAL", "BOOTSTRAP_CAPABILITY_LIMITATION_COUNT")
