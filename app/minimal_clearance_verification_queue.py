"""Durable experimental queue for independent minimal-clearance verification.

This module owns only queue admission, leases, bounded retry, and proof-evidence
receipts.  It never imports or calls the clearance state store, never stores an
artifact path or payload, and never turns proof acceptance into a directive.
"""

from __future__ import annotations

from dataclasses import dataclass
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Final, Mapping, NoReturn, Protocol

from app.minimal_clearance_proof_primitives import MinimalProofAcceptanceV1, NativeMinimalClearanceVerifier, parse_acceptance_bytes
from app.minimal_clearance_verifier_process import ContainedVerifierResult


class VerificationQueueError(RuntimeError):
    """Base fail-closed queue error with a bounded token only."""


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
    """Raise a public fixed-code error without retaining caught exception context."""
    try:
        raise error
    except VerificationQueueError as fixed:
        fixed.__cause__ = None
        fixed.__context__ = None
        fixed.__suppress_context__ = True
        raise


_SCHEMA_VERSION: Final[int] = 2
_SCHEMA = "BL/NATIVE-V3/MINIMAL-CLEARANCE-VERIFICATION-QUEUE/v2"
_STATUS = frozenset({"QUEUED", "LEASED", "VERIFIED", "REJECTED", "HELD"})
_NONTERMINAL = frozenset({"QUEUED", "LEASED"})
_TERMINAL = frozenset({"VERIFIED", "REJECTED", "HELD"})
_SAFE_TOKEN = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
_SAFE_CODE = re.compile(r"[a-z][a-z0-9_]{0,95}\Z")
_MAX_QUEUE_ID = 96
_MAX_WORKER_ID = 96
_MAX_ARTIFACT_REF = 128
_MAX_ERROR = 96
_MAX_STDOUT = 65_536
_MAX_STDERR = 262_144
_MAX_ACCEPTANCE = 65_536
_CAP_BYTES = 5_000_000_000
_ACTIVE_PROCESS_LIMIT = 1
_DETERMINISTIC_REJECT_CODES = frozenset({
    "proof_verifier_rejected", "proof_circuit_id", "proof_public_statement_mismatch",
    "proof_verifier_output_encoding", "proof_verified_statement_missing",
    "proof_verified_statement_length", "proof_acceptance_truncated", "proof_acceptance_magic",
    "proof_acceptance_version", "proof_acceptance_statement_size", "proof_acceptance_trailing",
})

_GENESIS_DOMAIN = b"BL/NATIVE-V3/VERIFICATION-QUEUE/GENESIS/v1\x00"
_MATERIAL_DOMAIN = b"BL/NATIVE-V3/VERIFICATION-QUEUE/MATERIAL/v1\x00"
_OPERATION_DOMAIN = b"BL/NATIVE-V3/VERIFICATION-QUEUE/OPERATION/v1\x00"
_EVENT_DOMAIN = b"BL/NATIVE-V3/VERIFICATION-QUEUE/EVENT/v1\x00"
_HEAD_DOMAIN = b"BL/NATIVE-V3/VERIFICATION-QUEUE/HEAD/v1\x00"
_RECEIPT_DOMAIN = b"BL/NATIVE-V3/VERIFICATION-QUEUE/RECEIPT/v1\x00"
_ACCEPTANCE_DOMAIN = b"BL/NATIVE-V3/VERIFICATION-QUEUE/ACCEPTANCE/v1\x00"
_LEASE_DOMAIN = b"BL/NATIVE-V3/VERIFICATION-QUEUE/LEASE-FENCE/v2\x00"
_LEASE_RAW_DOMAIN = b"BL/NATIVE-V3/VERIFICATION-QUEUE/LEASE-RAW/v2\x00"

MAX_QUEUE_DATABASE_BYTES: Final[int] = 64 * 1024 * 1024
MAX_QUEUE_CAPACITY: Final[int] = 512
MAX_TERMINAL_GROWTH_PER_NONTERMINAL: Final[int] = 64 * 1024
MAX_WORKER_CONCURRENCY: Final[int] = 4
_PAGE_SIZE: Final[int] = 4096
_MAX_PAGE_COUNT: Final[int] = MAX_QUEUE_DATABASE_BYTES // _PAGE_SIZE
_MAX_ARTIFACT_BYTES: Final[int] = 512 * 1024 * 1024


def _sha(domain: bytes, *parts: bytes) -> bytes:
    digest = hashlib.sha3_512()
    digest.update(domain)
    for part in parts:
        digest.update(part)
    return digest.digest()


def _lease_raw(config: QueueConfig, job_id: str, worker_id: str, attempt: int, leased_ms: int, expires_ms: int) -> bytes:
    return _sha(
        _LEASE_RAW_DOMAIN, config.queue_id.encode("ascii"), config.digest, job_id.encode("ascii"),
        worker_id.encode("ascii"), _u64(attempt), _u64(leased_ms), _u64(expires_ms),
    )[:24]


def _lease_digest(config: QueueConfig, job_id: str, worker_id: str, attempt: int, leased_ms: int, expires_ms: int, raw_token: bytes) -> bytes:
    # This is a deterministic fencing identity, never an authentication credential.
    return _sha(
        _LEASE_DOMAIN, config.queue_id.encode("ascii"), config.digest, job_id.encode("ascii"),
        worker_id.encode("ascii"), _u64(attempt), _u64(leased_ms), _u64(expires_ms), raw_token,
    )


def _u64(value: int) -> bytes:
    if type(value) is not int or not 0 <= value < 2**64:
        raise QueueIntegrityError("queue_integer_range")
    return value.to_bytes(8, "big")


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
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
    if type(value) is not str or (length is not None and re.fullmatch(rf"[0-9a-fA-F]{{{length * 2}}}\Z", value) is None) or (length is None and re.fullmatch(r"[0-9a-fA-F]+\Z", value) is None):
        raise QueueIntegrityError(f"{label}_invalid")
    try:
        result = bytes.fromhex(value)
    except ValueError as exc:
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
    lease_seconds: int
    verifier_sha256: bytes
    artifact_bytes_cap: int
    retryable_codes: tuple[str, ...]
    max_attempts: int = 3
    max_worker_concurrency: int = 4

    def __post_init__(self) -> None:
        _safe_token(self.queue_id, "queue_id", maximum=_MAX_QUEUE_ID)
        if type(self.capacity) is not int or not 1 <= self.capacity <= MAX_QUEUE_CAPACITY:
            raise VerificationQueueError("queue_capacity_invalid")
        if type(self.lease_seconds) is not int or not 1 <= self.lease_seconds <= 3_600:
            raise VerificationQueueError("queue_lease_seconds_invalid")
        _bytes(self.verifier_sha256, 32, "queue_verifier_sha256")
        if type(self.artifact_bytes_cap) is not int or not 0 < self.artifact_bytes_cap <= _MAX_ARTIFACT_BYTES:
            raise VerificationQueueError("queue_artifact_cap_invalid")
        if type(self.max_attempts) is not int or self.max_attempts != 3:
            raise VerificationQueueError("queue_max_attempts_invalid")
        if type(self.max_worker_concurrency) is not int or self.max_worker_concurrency != MAX_WORKER_CONCURRENCY:
            raise VerificationQueueError("queue_worker_concurrency_invalid")
        if type(self.retryable_codes) is not tuple or not self.retryable_codes:
            raise VerificationQueueError("queue_retryable_codes_invalid")
        if tuple(sorted(set(self.retryable_codes))) != self.retryable_codes:
            raise VerificationQueueError("queue_retryable_codes_order")
        for code in self.retryable_codes:
            _safe_code(code, "queue_retryable_code")

    def as_json(self) -> dict[str, Any]:
        return {
            "schema_version": _SCHEMA_VERSION,
            "queue_id": self.queue_id,
            "capacity": self.capacity,
            "lease_seconds": self.lease_seconds,
            "max_attempts": self.max_attempts,
            "max_worker_concurrency": self.max_worker_concurrency,
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
        if type(self.artifact_bytes) is not int or not 0 < self.artifact_bytes <= 512 * 1024 * 1024:
            raise VerificationQueueError("artifact_bytes_invalid")
        _bytes(self.artifact_sha256, 32, "artifact_sha256")
        _bytes(self.artifact_sha3_512, 64, "artifact_sha3_512")

    def as_json(self) -> dict[str, Any]:
        return {
            "artifact_ref": self.artifact_ref,
            "artifact_bytes": self.artifact_bytes,
            "artifact_sha256": _hex(self.artifact_sha256),
            "artifact_sha3_512": _hex(self.artifact_sha3_512),
        }


@dataclass(frozen=True, slots=True)
class CustodySnapshot:
    """In-memory custody result; the path never enters queue storage/export."""

    path: Path
    artifact_bytes: int
    artifact_sha256: bytes
    artifact_sha3_512: bytes
    readonly: bool
    cleanup: Callable[[], None] | None = None


@dataclass(frozen=True, slots=True)
class QueueWorkItem:
    queue_id: str
    job_id: str
    operation_id: bytes
    metadata: ArtifactMetadata
    attempt: int
    worker_id: str
    lease_token: bytes
    lease_expires_ms: int
    expected_verifier_sha256: bytes


@dataclass(frozen=True, slots=True)
class VerificationEvidence:
    artifact_bytes: int
    artifact_sha256: bytes
    artifact_sha3_512: bytes
    verifier_sha256: bytes
    circuit_id: bytes
    acceptance_bytes: bytes
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
        for name, length in (
            ("artifact_sha256", 32), ("artifact_sha3_512", 64),
            ("verifier_sha256", 32), ("circuit_id", 32), ("proof_acceptance_digest", 64),
            ("stdout_sha3_512", 64), ("stderr_sha3_512", 64),
        ):
            _bytes(getattr(self, name), length, f"evidence_{name}")
        if type(self.acceptance_bytes) is not bytes or not 0 < len(self.acceptance_bytes) <= _MAX_ACCEPTANCE:
            raise QueueIntegrityError("evidence_acceptance_bytes")
        try:
            parsed = parse_acceptance_bytes(self.acceptance_bytes)
        except Exception as exc:
            _raise_fixed(QueueIntegrityError("evidence_acceptance_invalid"))
        if (
            parsed.canonical_bytes() != self.acceptance_bytes
            or parsed.artifact_bytes != self.artifact_bytes
            or parsed.artifact_sha256 != self.artifact_sha256
            or parsed.artifact_digest != self.artifact_sha3_512
            or parsed.circuit_id != self.circuit_id
            or _sha(_ACCEPTANCE_DOMAIN, self.acceptance_bytes) != self.proof_acceptance_digest
        ):
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
        return {
            "artifact_bytes": self.artifact_bytes,
            "artifact_sha256": _hex(self.artifact_sha256),
            "artifact_sha3_512": _hex(self.artifact_sha3_512),
            "verifier_sha256": _hex(self.verifier_sha256),
            "circuit_id": _hex(self.circuit_id),
            "acceptance_bytes": _hex(self.acceptance_bytes),
            "proof_acceptance_digest": _hex(self.proof_acceptance_digest),
            "peak_job_commit_bytes": self.peak_job_commit_bytes,
            "cap_bytes": self.cap_bytes,
            "cap_enforced": self.cap_enforced,
            "active_process_limit": self.active_process_limit,
            "timed_out": self.timed_out,
            "exit_code": self.exit_code,
            "stdout_sha3_512": _hex(self.stdout_sha3_512),
            "stderr_sha3_512": _hex(self.stderr_sha3_512),
        }

    @property
    def canonical_bytes(self) -> bytes:
        return _json_bytes(self.as_json())


@dataclass(frozen=True, slots=True)
class VerificationReceipt:
    schema: str
    queue_id: str
    job_id: str
    operation_id: bytes
    attempt: int
    evidence: VerificationEvidence
    receipt_id: bytes

    def as_json(self, *, include_id: bool = True) -> dict[str, Any]:
        value: dict[str, Any] = {
            "schema": self.schema,
            "queue_id": self.queue_id,
            "job_id": self.job_id,
            "operation_id": _hex(self.operation_id),
            "attempt": self.attempt,
            "evidence": self.evidence.as_json(),
        }
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
    receipt_bytes: bytes | None
    error_code: str | None


class ProofArtifactCustodyPort(Protocol):
    def snapshot(self, artifact_ref: str, expected: ArtifactMetadata) -> CustodySnapshot:
        """Return a fresh verifier-owned read-only snapshot."""


class VerificationFactory(Protocol):
    def __call__(self) -> NativeMinimalClearanceVerifier:
        """Return a fresh verifier instance for one job."""


def _is_reparse(stat_result: os.stat_result) -> bool:
    attributes = int(getattr(stat_result, "st_file_attributes", 0))
    return bool(attributes & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)))


def _owned_directory(path: Path) -> bool:
    try:
        item = os.lstat(path)
        return stat.S_ISDIR(item.st_mode) and item.st_nlink == 1 and not _is_reparse(item)
    except (OSError, ValueError):
        return False


def _open_regular_file(path: Path, expected_bytes: int) -> tuple[int, os.stat_result]:
    if type(expected_bytes) is not int or not 0 < expected_bytes <= _MAX_ARTIFACT_BYTES:
        raise QueueHeldError("custody_size")
    try:
        before = os.lstat(path)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or _is_reparse(before):
            raise QueueHeldError("custody_source")
        flags = int(os.O_RDONLY) | int(getattr(os, "O_BINARY", 0))
        if hasattr(os, "O_NOFOLLOW"):
            flags |= int(os.O_NOFOLLOW)
        descriptor = os.open(str(path), flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or _is_reparse(opened) or opened.st_size != expected_bytes:
            os.close(descriptor)
            raise QueueHeldError("custody_source_identity")
        if (int(before.st_dev), int(before.st_ino), int(before.st_nlink), int(before.st_size), int(before.st_mtime_ns)) != (
            int(opened.st_dev), int(opened.st_ino), int(opened.st_nlink), int(opened.st_size), int(opened.st_mtime_ns)
        ):
            os.close(descriptor)
            raise QueueHeldError("custody_source_identity")
        return descriptor, opened
    except QueueHeldError:
        raise
    except (OSError, ValueError) as exc:
        _raise_fixed(QueueRetryableError("custody_read"))


def _same_file_identity(first: os.stat_result, second: os.stat_result) -> bool:
    return (
        int(first.st_dev), int(first.st_ino), int(first.st_nlink), int(first.st_size), int(first.st_mtime_ns)
    ) == (
        int(second.st_dev), int(second.st_ino), int(second.st_nlink), int(second.st_size), int(second.st_mtime_ns)
    ) and stat.S_ISREG(second.st_mode) and not _is_reparse(second)


def _stream_digest(descriptor: int, expected_bytes: int, digest256: Any, digest512: Any) -> int:
    total = 0
    while total <= expected_bytes:
        chunk = os.read(descriptor, min(1 << 20, expected_bytes + 1 - total))
        if not chunk:
            break
        total += len(chunk)
        if total > expected_bytes:
            break
        digest256.update(chunk)
        digest512.update(chunk)
    return total


def _write_all(descriptor: int, chunk: bytes) -> None:
    offset = 0
    while offset < len(chunk):
        written = os.write(descriptor, chunk[offset:])
        if written <= 0:
            raise OSError
        offset += written


def _new_owned_directory(parent: Path) -> Path:
    if not _owned_directory(parent):
        raise QueueRetryableError("custody_parent")
    try:
        directory = Path(tempfile.mkdtemp(prefix="bl-queue-", dir=parent))
        if not _owned_directory(directory):
            raise OSError
        return directory
    except (OSError, ValueError) as exc:
        _raise_fixed(QueueRetryableError("custody_workspace"))


def _database_identity(path: Path, *, allow_missing: bool = False) -> tuple[int, int, int, int, int] | None:
    try:
        item = os.lstat(path)
    except FileNotFoundError:
        if allow_missing:
            return None
        _raise_fixed(VerificationQueueError("queue_database_path"))
    except (OSError, ValueError) as exc:
        _raise_fixed(VerificationQueueError("queue_database_path"))
    if not stat.S_ISREG(item.st_mode) or item.st_nlink != 1 or _is_reparse(item):
        raise VerificationQueueError("queue_database_path")
    size = int(item.st_size)
    if size > MAX_QUEUE_DATABASE_BYTES:
        raise QueueBackpressureError("queue_storage_capacity")
    return (int(item.st_dev), int(item.st_ino), int(item.st_nlink), size, int(item.st_mtime_ns))


class FilesystemArtifactCustody:
    """Verifier-owned snapshot adapter; queue state sees only opaque refs."""

    def __init__(self, *, resolver: Callable[[str], Path], workspace_parent: Path) -> None:
        if not callable(resolver) or not isinstance(workspace_parent, Path) or not _owned_directory(workspace_parent):
            raise VerificationQueueError("custody_configuration")
        self._resolver = resolver
        self._workspace_parent = workspace_parent

    @staticmethod
    def _readonly(path: Path) -> None:
        path.chmod(stat.S_IREAD)

    @staticmethod
    def _cleanup(directory: Path, artifact: Path, directory_identity: tuple[int, int], artifact_identity: tuple[int, int, int]) -> None:
        try:
            current_directory = os.stat(directory, follow_symlinks=False)
            current_artifact = os.stat(artifact, follow_symlinks=False)
            if (int(current_directory.st_dev), int(current_directory.st_ino)) != directory_identity:
                raise OSError
            if (int(current_artifact.st_dev), int(current_artifact.st_ino), int(current_artifact.st_nlink)) != artifact_identity:
                raise OSError
            os.chmod(artifact, stat.S_IRUSR | stat.S_IWUSR)
            os.unlink(artifact)
            os.rmdir(directory)
        except (OSError, ValueError) as exc:
            _raise_fixed(QueueHeldError("custody_cleanup"))

    def snapshot(self, artifact_ref: str, expected: ArtifactMetadata) -> CustodySnapshot:
        _safe_token(artifact_ref, "artifact_ref", maximum=_MAX_ARTIFACT_REF)
        if type(expected) is not ArtifactMetadata:
            raise QueueHeldError("custody_source")
        try:
            source = self._resolver(artifact_ref)
        except Exception:
            _raise_fixed(QueueHeldError("custody_source"))
        if not isinstance(source, Path) or expected.artifact_bytes > _MAX_ARTIFACT_BYTES:
            raise QueueHeldError("custody_source")
        source_handle: int | None = None
        directory: Path | None = None
        artifact: Path | None = None
        artifact_identity: tuple[int, int, int] | None = None
        try:
            source_handle, source_stat = _open_regular_file(source, expected.artifact_bytes)
            directory = _new_owned_directory(self._workspace_parent)
            artifact = directory / "artifact.bin"
            descriptor = os.open(
                str(artifact),
                int(os.O_CREAT) | int(os.O_EXCL) | int(os.O_WRONLY) | int(getattr(os, "O_BINARY", 0)),
                0o600,
            )
            opened_artifact = os.fstat(descriptor)
            artifact_identity = (int(opened_artifact.st_dev), int(opened_artifact.st_ino), int(opened_artifact.st_nlink))
            digest256 = hashlib.sha256()
            digest512 = hashlib.sha3_512()
            total = 0
            try:
                while total <= expected.artifact_bytes:
                    chunk = os.read(source_handle, min(1 << 20, expected.artifact_bytes + 1 - total))
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > expected.artifact_bytes:
                        raise QueueHeldError("custody_source_identity")
                    _write_all(descriptor, chunk)
                    digest256.update(chunk)
                    digest512.update(chunk)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            after_source = os.fstat(source_handle)
            path_source = os.stat(source, follow_symlinks=False)
            if not _same_file_identity(source_stat, after_source) or not _same_file_identity(source_stat, path_source) or total != expected.artifact_bytes:
                raise QueueHeldError("custody_source_identity")
            digest256_value = digest256.digest()
            digest512_value = digest512.digest()
            if digest256_value != expected.artifact_sha256 or digest512_value != expected.artifact_sha3_512:
                raise QueueHeldError("custody_source_identity")
            self._readonly(artifact)
            verify_handle, snapshot_stat = _open_regular_file(artifact, expected.artifact_bytes)
            try:
                verify256 = hashlib.sha256()
                verify512 = hashlib.sha3_512()
                verified = _stream_digest(verify_handle, expected.artifact_bytes, verify256, verify512)
            finally:
                os.close(verify_handle)
            if verified != expected.artifact_bytes or verify256.digest() != digest256_value or verify512.digest() != digest512_value:
                raise QueueHeldError("custody_snapshot_identity")
            if not _same_file_identity(snapshot_stat, os.stat(artifact, follow_symlinks=False)):
                raise QueueHeldError("custody_snapshot_identity")
            directory_stat = os.stat(directory, follow_symlinks=False)
            return CustodySnapshot(
                path=artifact, artifact_bytes=verified, artifact_sha256=digest256_value,
                artifact_sha3_512=digest512_value, readonly=True,
                cleanup=lambda: self._cleanup(
                    directory, artifact,
                    (int(directory_stat.st_dev), int(directory_stat.st_ino)), artifact_identity,
                ),
            )
        except QueueHeldError:
            cleanup_failed = False
            if source_handle is not None:
                try: os.close(source_handle)
                except OSError: pass
            if artifact is not None and artifact_identity is not None and directory is not None:
                try:
                    directory_stat = os.stat(directory, follow_symlinks=False)
                    self._cleanup(directory, artifact, (int(directory_stat.st_dev), int(directory_stat.st_ino)), artifact_identity)
                except (OSError, QueueHeldError):
                    cleanup_failed = True
            elif directory is not None:
                try: os.rmdir(directory)
                except OSError: cleanup_failed = True
            if cleanup_failed:
                _raise_fixed(QueueHeldError("custody_cleanup"))
            raise
        except (OSError, ValueError) as exc:
            cleanup_failed = False
            if source_handle is not None:
                try:
                    os.close(source_handle)
                except OSError: pass
            if artifact is not None and artifact_identity is not None and directory is not None:
                try:
                    directory_stat = os.stat(directory, follow_symlinks=False)
                    self._cleanup(directory, artifact, (int(directory_stat.st_dev), int(directory_stat.st_ino)), artifact_identity)
                except QueueHeldError:
                    cleanup_failed = True
            elif directory is not None:
                try: os.rmdir(directory)
                except OSError: cleanup_failed = True
            if cleanup_failed:
                _raise_fixed(QueueHeldError("custody_cleanup"))
            _raise_fixed(QueueRetryableError("custody_snapshot"))
        finally:
            if source_handle is not None:
                try: os.close(source_handle)
                except OSError: pass


def _material_digest(config: QueueConfig, job_id: str, metadata: ArtifactMetadata) -> bytes:
    return _sha(
        _MATERIAL_DOMAIN, config.queue_id.encode("ascii"), job_id.encode("ascii"),
        _json_bytes(metadata.as_json()), config.verifier_sha256,
    )


def _operation_id(config: QueueConfig, job_id: str, material_digest: bytes) -> bytes:
    return _sha(_OPERATION_DOMAIN, config.queue_id.encode("ascii"), job_id.encode("ascii"), material_digest)


def _bounded_output_digests(stdout: object, stderr: object) -> tuple[bytes, bytes]:
    """Bound opaque native output without reimplementing its grammar.

    The contained native verifier owns acceptance markers, dimensions, trace
    ordering, and diagnostic semantics.  The queue only owns transport
    bounds, ASCII validity, and digest retention.
    """
    if type(stdout) is not bytes or type(stderr) is not bytes:
        raise QueueRetryableError("verifier_output_type")
    if len(stdout) > _MAX_STDOUT or len(stderr) > _MAX_STDERR:
        raise QueueRetryableError("verifier_output_cap")
    try:
        stdout.decode("ascii", "strict")
        stderr.decode("ascii", "strict")
    except UnicodeDecodeError as exc:
        _raise_fixed(QueueRetryableError("verifier_output_encoding"))
    return hashlib.sha3_512(stdout).digest(), hashlib.sha3_512(stderr).digest()


def build_verification_evidence(
    acceptance: object,
    containment: object,
    snapshot: CustodySnapshot,
    expected_verifier_sha256: bytes,
) -> VerificationEvidence:
    """Convert one verifier result into bounded proof-only evidence."""

    if type(containment) is not ContainedVerifierResult:
        raise QueueRetryableError("telemetry_missing")
    if type(acceptance) is not MinimalProofAcceptanceV1:
        raise QueueHeldError("proof_acceptance_type")
    if acceptance.proof_accepted is not True:
        raise QueueDeterministicRejectError("proof_rejected")
    try:
        artifact_bytes = acceptance.artifact_bytes
        artifact_sha256 = acceptance.artifact_sha256
        artifact_sha3_512 = acceptance.artifact_digest
        circuit_id = acceptance.circuit_id
        canonical_acceptance = acceptance.canonical_bytes()
        peak = containment.peak_job_commit_bytes
        cap = containment.cap_bytes
        cap_enforced = containment.cap_enforced
        active = containment.active_process_limit
        timed_out = containment.timed_out
        exit_code = containment.exit_code
        stdout = containment.stdout
        stderr = containment.stderr
    except (AttributeError, TypeError, ValueError) as exc:
        _raise_fixed(QueueRetryableError("verifier_result_shape"))
    try:
        parsed_acceptance = parse_acceptance_bytes(canonical_acceptance)
    except Exception as exc:
        _raise_fixed(QueueHeldError("proof_acceptance_shape"))
    if (
        type(artifact_bytes) is not int
        or type(artifact_sha256) is not bytes or len(artifact_sha256) != 32
        or type(artifact_sha3_512) is not bytes or len(artifact_sha3_512) != 64
        or type(circuit_id) is not bytes or len(circuit_id) != 32
        or type(canonical_acceptance) is not bytes
        or not 0 < len(canonical_acceptance) <= _MAX_ACCEPTANCE
        or parsed_acceptance.canonical_bytes() != canonical_acceptance
        or parsed_acceptance != acceptance
    ):
        raise QueueHeldError("proof_acceptance_shape")
    if (
        artifact_bytes != snapshot.artifact_bytes
        or artifact_sha256 != snapshot.artifact_sha256
        or artifact_sha3_512 != snapshot.artifact_sha3_512
        or not snapshot.readonly
    ):
        raise QueueHeldError("custody_identity_mismatch")
    _bytes(expected_verifier_sha256, 32, "queue_verifier_sha256")
    if (
        type(cap) is not int or type(cap_enforced) is not bool
        or type(active) is not int or type(timed_out) is not bool or type(exit_code) is not int
        or type(peak) is not int or peak < 0
    ):
        raise QueueRetryableError("verifier_containment_shape")
    if cap != _CAP_BYTES or cap_enforced is not True or active != _ACTIVE_PROCESS_LIMIT:
        raise QueueRetryableError("verifier_containment")
    if timed_out or exit_code != 0 or peak > cap:
        raise QueueRetryableError("verifier_resource")
    stdout_digest, stderr_digest = _bounded_output_digests(stdout, stderr)
    return VerificationEvidence(
        artifact_bytes=artifact_bytes,
        artifact_sha256=artifact_sha256,
        artifact_sha3_512=artifact_sha3_512,
        verifier_sha256=bytes(expected_verifier_sha256),
        circuit_id=bytes(circuit_id),
        acceptance_bytes=canonical_acceptance,
        proof_acceptance_digest=_sha(_ACCEPTANCE_DOMAIN, canonical_acceptance),
        peak_job_commit_bytes=peak,
        cap_bytes=cap,
        cap_enforced=cap_enforced,
        active_process_limit=active,
        timed_out=timed_out,
        exit_code=exit_code,
        stdout_sha3_512=stdout_digest,
        stderr_sha3_512=stderr_digest,
    )


_TABLE_COLUMNS: Final[dict[str, tuple[str, ...]]] = {
    "queue_metadata": (
        "id", "schema_version", "queue_id", "config_json", "config_digest", "verifier_sha256",
        "artifact_bytes_cap", "head_root", "next_transition_seq", "next_admission_seq",
        "storage_used_bytes", "storage_reserved_bytes", "nonterminal_count", "live_lease_count",
    ),
    "queue_jobs": (
        "job_id", "operation_id", "material_digest", "artifact_ref", "artifact_bytes", "artifact_sha256",
        "artifact_sha3_512", "status", "admission_seq", "attempt", "next_eligible_ms", "created_ms",
        "updated_ms", "last_error_code",
    ),
    "queue_operations": (
        "operation_id", "job_id", "material_digest", "result_status", "result_receipt", "result_error_code",
    ),
    "queue_leases": ("job_id", "worker_id", "token", "attempt", "leased_ms", "expires_ms"),
    "queue_results": ("operation_id", "job_id", "terminal_status", "receipt_bytes", "error_code", "completed_ms"),
    "queue_transitions": (
        "sequence", "transition_kind", "job_id", "operation_id", "before_root", "after_root",
        "event_bytes", "event_digest",
    ),
}


class VerificationQueueStore:
    """Producer-owned durable queue state machine."""

    def __init__(
        self,
        *,
        path: Path,
        config: QueueConfig,
        clock: QueueClock | None = None,
        before_fault: Callable[[str], None] | None = None,
        after_commit_fault: Callable[[str], None] | None = None,
    ) -> None:
        if not isinstance(path, Path):
            raise VerificationQueueError("queue_database_path")
        _database_identity(path, allow_missing=True)
        if not _owned_directory(path.parent):
            raise VerificationQueueError("queue_database_parent")
        self.path = path
        self.config = config
        self.clock = clock or SystemQueueClock()
        self._before_fault = before_fault
        self._after_commit_fault = after_commit_fault
        self._path_identity: tuple[int, int, int, int, int] | None = None
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        try:
            identity = _database_identity(self.path, allow_missing=True)
            connection = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA busy_timeout=5000")
            connection.execute(f"PRAGMA page_size={_PAGE_SIZE}")
            connection.execute(f"PRAGMA max_page_count={_MAX_PAGE_COUNT}")
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA synchronous=FULL")
            current = _database_identity(self.path, allow_missing=True)
            if identity is not None and current is not None and identity[:3] != current[:3]:
                connection.close()
                raise VerificationQueueError("queue_database_identity")
            if self._path_identity is not None and identity is not None and identity[:3] != self._path_identity[:3]:
                connection.close()
                raise VerificationQueueError("queue_database_identity")
            return connection
        except VerificationQueueError:
            raise
        except sqlite3.Error as exc:
            _raise_fixed(VerificationQueueError("queue_database_open"))

    def _fault(self, label: str) -> None:
        if self._before_fault is not None:
            self._before_fault(label)

    def _after_commit(self, label: str) -> None:
        if self._after_commit_fault is not None:
            try:
                self._after_commit_fault(label)
            except Exception as exc:
                _raise_fixed(QueueIndeterminateError("queue_commit_indeterminate"))

    def _schema_check(self, connection: sqlite3.Connection) -> None:
        for table, expected in _TABLE_COLUMNS.items():
            rows = connection.execute(f"PRAGMA table_info({table})").fetchall()
            actual = tuple(str(row[1]) for row in rows)
            if actual != expected:
                raise QueueIntegrityError("queue_schema")
        objects = connection.execute("SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchall()
        expected_objects = {("table", name) for name in _TABLE_COLUMNS}
        indexes = {str(row[1]) for row in objects if str(row[0]) == "index"}
        required_indexes = {"queue_jobs_status_eligible", "queue_leases_expiry", "queue_leases_worker_unique"}
        triggers = {str(row[1]) for row in objects if str(row[0]) == "trigger"}
        required_triggers = {
            "queue_jobs_no_delete", "queue_jobs_no_update", "queue_operations_no_delete",
            "queue_transitions_no_update", "queue_transitions_no_delete", "queue_metadata_immutable",
        }
        expected_objects |= {("index", name) for name in required_indexes} | {("trigger", name) for name in required_triggers}
        if {(str(row[0]), str(row[1])) for row in objects} != expected_objects:
            raise QueueIntegrityError("queue_schema_indexes")
        if indexes != required_indexes or triggers != required_triggers:
            raise QueueIntegrityError("queue_schema_triggers")

    def _initialize(self) -> None:
        with closing(self._connect()) as connection:
            try:
                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS queue_metadata (
                        id INTEGER PRIMARY KEY CHECK(id=1), schema_version INTEGER NOT NULL,
                        queue_id TEXT NOT NULL, config_json BLOB NOT NULL, config_digest BLOB NOT NULL,
                        verifier_sha256 BLOB NOT NULL, artifact_bytes_cap INTEGER NOT NULL,
                        head_root BLOB NOT NULL, next_transition_seq INTEGER NOT NULL,
                        next_admission_seq INTEGER NOT NULL, storage_used_bytes INTEGER NOT NULL,
                        storage_reserved_bytes INTEGER NOT NULL, nonterminal_count INTEGER NOT NULL,
                        live_lease_count INTEGER NOT NULL,
                        CHECK(storage_used_bytes >= 0 AND storage_reserved_bytes >= 0),
                        CHECK(nonterminal_count >= 0 AND live_lease_count BETWEEN 0 AND 4)
                    );
                    CREATE TABLE IF NOT EXISTS queue_jobs (
                        job_id TEXT PRIMARY KEY, operation_id BLOB NOT NULL UNIQUE,
                        material_digest BLOB NOT NULL, artifact_ref TEXT NOT NULL,
                        artifact_bytes INTEGER NOT NULL, artifact_sha256 BLOB NOT NULL,
                        artifact_sha3_512 BLOB NOT NULL, status TEXT NOT NULL,
                        admission_seq INTEGER NOT NULL UNIQUE, attempt INTEGER NOT NULL,
                        next_eligible_ms INTEGER NOT NULL, created_ms INTEGER NOT NULL,
                        updated_ms INTEGER NOT NULL, last_error_code TEXT
                    );
                    CREATE TABLE IF NOT EXISTS queue_operations (
                        operation_id BLOB PRIMARY KEY, job_id TEXT NOT NULL UNIQUE,
                        material_digest BLOB NOT NULL, result_status TEXT,
                        result_receipt BLOB, result_error_code TEXT,
                        FOREIGN KEY(job_id) REFERENCES queue_jobs(job_id)
                    );
                    CREATE TABLE IF NOT EXISTS queue_leases (
                        job_id TEXT PRIMARY KEY, worker_id TEXT NOT NULL, token BLOB NOT NULL,
                        attempt INTEGER NOT NULL, leased_ms INTEGER NOT NULL, expires_ms INTEGER NOT NULL,
                        FOREIGN KEY(job_id) REFERENCES queue_jobs(job_id)
                    );
                    CREATE TABLE IF NOT EXISTS queue_results (
                        operation_id BLOB PRIMARY KEY, job_id TEXT NOT NULL UNIQUE,
                        terminal_status TEXT NOT NULL, receipt_bytes BLOB,
                        error_code TEXT, completed_ms INTEGER NOT NULL,
                        FOREIGN KEY(operation_id) REFERENCES queue_operations(operation_id),
                        FOREIGN KEY(job_id) REFERENCES queue_jobs(job_id)
                    );
                    CREATE TABLE IF NOT EXISTS queue_transitions (
                        sequence INTEGER PRIMARY KEY, transition_kind TEXT NOT NULL,
                        job_id TEXT NOT NULL, operation_id BLOB NOT NULL,
                        before_root BLOB NOT NULL, after_root BLOB NOT NULL,
                        event_bytes BLOB NOT NULL, event_digest BLOB NOT NULL UNIQUE,
                        FOREIGN KEY(job_id) REFERENCES queue_jobs(job_id),
                        FOREIGN KEY(operation_id) REFERENCES queue_operations(operation_id)
                    );
                    CREATE TRIGGER IF NOT EXISTS queue_jobs_no_delete BEFORE DELETE ON queue_jobs BEGIN SELECT RAISE(ABORT,'queue_jobs_append_only'); END;
                    CREATE TRIGGER IF NOT EXISTS queue_jobs_no_update BEFORE UPDATE OF job_id,operation_id,material_digest,artifact_ref,artifact_bytes,artifact_sha256,artifact_sha3_512,admission_seq ON queue_jobs BEGIN SELECT RAISE(ABORT,'queue_jobs_identity_immutable'); END;
                    CREATE TRIGGER IF NOT EXISTS queue_operations_no_delete BEFORE DELETE ON queue_operations BEGIN SELECT RAISE(ABORT,'queue_operations_append_only'); END;
                    CREATE TRIGGER IF NOT EXISTS queue_transitions_no_update BEFORE UPDATE ON queue_transitions BEGIN SELECT RAISE(ABORT,'queue_transitions_append_only'); END;
                    CREATE TRIGGER IF NOT EXISTS queue_transitions_no_delete BEFORE DELETE ON queue_transitions BEGIN SELECT RAISE(ABORT,'queue_transitions_append_only'); END;
                    CREATE TRIGGER IF NOT EXISTS queue_metadata_immutable BEFORE UPDATE OF id,schema_version,queue_id,config_json,config_digest,verifier_sha256,artifact_bytes_cap ON queue_metadata BEGIN SELECT RAISE(ABORT,'queue_metadata_immutable'); END;
                    CREATE INDEX IF NOT EXISTS queue_jobs_status_eligible ON queue_jobs(status,next_eligible_ms,admission_seq);
                    CREATE INDEX IF NOT EXISTS queue_leases_expiry ON queue_leases(expires_ms,job_id);
                    CREATE UNIQUE INDEX IF NOT EXISTS queue_leases_worker_unique ON queue_leases(worker_id);
                    """
                )
                connection.execute("BEGIN IMMEDIATE")
                self._schema_check(connection)
                row = connection.execute("SELECT * FROM queue_metadata WHERE id=1").fetchone()
                if row is None:
                    config_bytes = self.config.canonical_bytes
                    head = _sha(_GENESIS_DOMAIN, self.config.queue_id.encode("ascii"), self.config.digest)
                    connection.execute(
                        "INSERT INTO queue_metadata VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (1, _SCHEMA_VERSION, self.config.queue_id, config_bytes, self.config.digest,
                         self.config.verifier_sha256, self.config.artifact_bytes_cap, head, 0, 0, 0, 0, 0, 0),
                    )
                    self._update_storage_locked(connection, nonterminal=0, leases=0)
                else:
                    if len(row) != 14 or int(row[1]) != _SCHEMA_VERSION or str(row[2]) != self.config.queue_id:
                        raise QueueIntegrityError("queue_metadata")
                    if bytes(row[3]) != self.config.canonical_bytes or bytes(row[4]) != self.config.digest:
                        raise QueueIntegrityError("queue_config_drift")
                    if bytes(row[5]) != self.config.verifier_sha256 or int(row[6]) != self.config.artifact_bytes_cap:
                        raise QueueIntegrityError("queue_verifier_drift")
                connection.execute("COMMIT")
            except sqlite3.Error as exc:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                _raise_fixed(self._translate_sqlite(exc))
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        self._path_identity = _database_identity(self.path)
        self.verify_integrity()

    def _meta(self, connection: sqlite3.Connection) -> tuple[Any, ...]:
        identity = _database_identity(self.path)
        if self._path_identity is not None and identity is not None and identity[:3] != self._path_identity[:3]:
            raise QueueIntegrityError("queue_database_identity")
        row = connection.execute("SELECT * FROM queue_metadata WHERE id=1").fetchone()
        if row is None or len(row) != 14:
            raise QueueIntegrityError("queue_metadata_missing")
        if (
            int(row[1]) != _SCHEMA_VERSION or str(row[2]) != self.config.queue_id
            or bytes(row[3]) != self.config.canonical_bytes or bytes(row[4]) != self.config.digest
            or bytes(row[5]) != self.config.verifier_sha256
            or int(row[6]) != self.config.artifact_bytes_cap
            or int(row[10]) < 0 or int(row[11]) < 0
            or int(row[12]) < 0 or int(row[12]) > self.config.capacity
            or int(row[13]) < 0 or int(row[13]) > MAX_WORKER_CONCURRENCY
        ):
            raise QueueIntegrityError("queue_metadata_drift")
        return tuple(row)

    @staticmethod
    def _page_bytes(connection: sqlite3.Connection) -> int:
        try:
            count = int(connection.execute("PRAGMA page_count").fetchone()[0])
            page = int(connection.execute("PRAGMA page_size").fetchone()[0])
        except (sqlite3.Error, TypeError, ValueError) as exc:
            _raise_fixed(QueueIntegrityError("queue_storage_state"))
        max_pages = int(connection.execute("PRAGMA max_page_count").fetchone()[0])
        if page != _PAGE_SIZE or max_pages != _MAX_PAGE_COUNT or count < 1 or count > _MAX_PAGE_COUNT:
            raise QueueBackpressureError("queue_storage_capacity")
        return count * page

    def _update_storage_locked(self, connection: sqlite3.Connection, *, nonterminal: int | None = None, leases: int | None = None) -> None:
        meta = self._meta(connection)
        active = int(meta[12]) if nonterminal is None else nonterminal
        live = int(meta[13]) if leases is None else leases
        used = self._page_bytes(connection)
        reserved = active * MAX_TERMINAL_GROWTH_PER_NONTERMINAL
        if used + reserved > MAX_QUEUE_DATABASE_BYTES:
            raise QueueBackpressureError("queue_storage_capacity")
        connection.execute(
            "UPDATE queue_metadata SET storage_used_bytes=?,storage_reserved_bytes=?,nonterminal_count=?,live_lease_count=? WHERE id=1",
            (used, reserved, active, live),
        )

    @staticmethod
    def _metadata_from_row(row: tuple[Any, ...]) -> ArtifactMetadata:
        return ArtifactMetadata(
            artifact_ref=str(row[3]), artifact_bytes=int(row[4]),
            artifact_sha256=bytes(row[5]), artifact_sha3_512=bytes(row[6]),
        )

    def _row_to_job(self, row: tuple[Any, ...]) -> QueueJob:
        if len(row) != 14:
            raise QueueIntegrityError("queue_job_shape")
        status = str(row[7])
        if status not in _STATUS:
            raise QueueIntegrityError("queue_status")
        error = None if row[13] is None else _safe_code(str(row[13]))
        return QueueJob(
            job_id=str(row[0]), operation_id=bytes(row[1]), metadata=self._metadata_from_row(row),
            status=status, admission_seq=int(row[8]), attempt=int(row[9]),
            next_eligible_ms=int(row[10]), last_error_code=error,
        )

    def _get_job_locked(self, connection: sqlite3.Connection, job_id: str) -> QueueJob | None:
        row = connection.execute("SELECT * FROM queue_jobs WHERE job_id=?", (job_id,)).fetchone()
        return None if row is None else self._row_to_job(tuple(row))

    @staticmethod
    def _result_from_row(row: tuple[Any, ...]) -> QueueResult:
        if len(row) != 5:
            raise QueueIntegrityError("queue_result_shape")
        job_id = _safe_token(str(row[0]), "result_job_id", maximum=_MAX_QUEUE_ID)
        if type(row[1]) is not bytes or len(row[1]) != 64 or str(row[2]) not in _TERMINAL:
            raise QueueIntegrityError("queue_result_binding")
        if row[3] is not None and (type(row[3]) is not bytes or len(row[3]) > 16 * 1024):
            raise QueueIntegrityError("queue_result_receipt")
        if row[2] == "VERIFIED" and (row[3] is None or row[4] is not None):
            raise QueueIntegrityError("queue_result_verified")
        if row[2] != "VERIFIED" and (row[3] is not None or row[4] is None):
            raise QueueIntegrityError("queue_result_terminal")
        return QueueResult(
            job_id, bytes(row[1]), str(row[2]),
            None if row[3] is None else bytes(row[3]),
            None if row[4] is None else _safe_code(str(row[4])),
        )

    def _append_transition(
        self,
        connection: sqlite3.Connection,
        *,
        kind: str,
        job_id: str,
        operation_id: bytes,
        event: Mapping[str, Any],
    ) -> tuple[int, bytes]:
        kind = _safe_token(kind, "queue_transition_kind", maximum=64)
        metadata = self._meta(connection)
        sequence = int(metadata[8]) + 1
        before = bytes(metadata[7])
        event_bytes = _json_bytes(dict(event))
        event_digest = _sha(_EVENT_DOMAIN, _u64(sequence), kind.encode("ascii"), job_id.encode("ascii"), operation_id, event_bytes)
        after = _sha(_HEAD_DOMAIN, before, _u64(sequence), event_digest)
        connection.execute(
            "INSERT INTO queue_transitions VALUES (?,?,?,?,?,?,?,?)",
            (sequence, kind, job_id, operation_id, before, after, event_bytes, event_digest),
        )
        connection.execute(
            "UPDATE queue_metadata SET head_root=?, next_transition_seq=? WHERE id=1",
            (after, sequence),
        )
        return sequence, after

    def _begin(self, connection: sqlite3.Connection) -> None:
        try:
            connection.execute("BEGIN IMMEDIATE")
        except sqlite3.Error as exc:
            _raise_fixed(VerificationQueueError("queue_busy"))

    @staticmethod
    def _translate_sqlite(error: sqlite3.Error) -> VerificationQueueError:
        text = str(error).lower()
        if "full" in text or "too big" in text or "toobig" in text:
            return QueueBackpressureError("queue_storage_capacity")
        return VerificationQueueError("queue_database_write")

    def admit(self, *, job_id: str, metadata: ArtifactMetadata) -> QueueJob:
        _safe_token(job_id, "job_id", maximum=_MAX_QUEUE_ID)
        if metadata.artifact_bytes > self.config.artifact_bytes_cap:
            raise QueueConflictError("artifact_cap")
        material = _material_digest(self.config, job_id, metadata)
        operation_id = _operation_id(self.config, job_id, material)
        now = int(self.clock.now_ms())
        with closing(self._connect()) as connection:
            began = False
            try:
                self._begin(connection)
                began = True
                self._meta(connection)
                existing = self._get_job_locked(connection, job_id)
                if existing is not None:
                    if existing.operation_id != operation_id or existing.metadata != metadata:
                        raise QueueConflictError("admission_conflict")
                    connection.execute("COMMIT")
                    began = False
                    return existing
                meta = self._meta(connection)
                depth = int(meta[12])
                if depth >= self.config.capacity:
                    raise QueueBackpressureError("queue_capacity")
                current_bytes = self._page_bytes(connection)
                if current_bytes + MAX_TERMINAL_GROWTH_PER_NONTERMINAL * (depth + 1) > MAX_QUEUE_DATABASE_BYTES:
                    raise QueueBackpressureError("queue_storage_capacity")
                admission_seq = int(meta[9]) + 1
                connection.execute(
                    "INSERT INTO queue_jobs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (job_id, operation_id, material, metadata.artifact_ref, metadata.artifact_bytes,
                     metadata.artifact_sha256, metadata.artifact_sha3_512, "QUEUED", admission_seq,
                     0, now, now, now, None),
                )
                connection.execute(
                    "INSERT INTO queue_operations VALUES (?,?,?,?,?,?)",
                    (operation_id, job_id, material, None, None, None),
                )
                self._fault("after_admission_write")
                connection.execute("UPDATE queue_metadata SET next_admission_seq=? WHERE id=1", (admission_seq,))
                self._append_transition(
                    connection, kind="ADMIT", job_id=job_id, operation_id=operation_id,
                    event={"at_ms": now, "status": "QUEUED", "admission_seq": admission_seq},
                )
                self._fault("after_transition")
                self._update_storage_locked(connection, nonterminal=depth + 1, leases=int(meta[13]))
                connection.execute("COMMIT")
                began = False
            except sqlite3.Error as exc:
                if began and connection.in_transaction:
                    connection.execute("ROLLBACK")
                _raise_fixed(self._translate_sqlite(exc))
            except Exception:
                if began and connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        self._after_commit("admit")
        return QueueJob(job_id, operation_id, metadata, "QUEUED", admission_seq, 0, now, None)

    def _expire_locked(self, connection: sqlite3.Connection, now: int) -> int:
        rows = connection.execute(
            "SELECT job_id,worker_id,token,attempt,leased_ms,expires_ms FROM queue_leases WHERE expires_ms<=? ORDER BY expires_ms,job_id",
            (now,),
        ).fetchall()
        count = 0
        held_count = 0
        for raw in rows:
            job_id, worker_id, token, attempt, leased_ms, expires_ms = raw
            job = self._get_job_locked(connection, str(job_id))
            if job is None or job.status != "LEASED" or job.attempt != int(attempt):
                raise QueueIntegrityError("queue_lease_state")
            expected_token = _lease_digest(
                self.config, str(job_id), str(worker_id), int(attempt), int(leased_ms), int(expires_ms),
                _lease_raw(self.config, str(job_id), str(worker_id), int(attempt), int(leased_ms), int(expires_ms)),
            )
            if type(token) is not bytes or len(token) != 64 or bytes(token) != expected_token:
                raise QueueIntegrityError("queue_lease_fence")
            connection.execute("DELETE FROM queue_leases WHERE job_id=?", (job_id,))
            if job.attempt >= self.config.max_attempts:
                status = "HELD"
                held_count += 1
                connection.execute(
                    "UPDATE queue_jobs SET status=?,updated_ms=?,last_error_code=? WHERE job_id=? AND status='LEASED' AND attempt=?",
                    (status, now, "lease_expired", job_id, job.attempt),
                )
                connection.execute(
                    "INSERT INTO queue_results VALUES (?,?,?,?,?,?)",
                    (job.operation_id, job.job_id, status, None, "lease_expired", now),
                )
                connection.execute(
                    "UPDATE queue_operations SET result_status=?,result_error_code=? WHERE operation_id=?",
                    (status, "lease_expired", job.operation_id),
                )
            else:
                status = "QUEUED"
                connection.execute(
                    "UPDATE queue_jobs SET status=?,updated_ms=?,next_eligible_ms=?,last_error_code=? WHERE job_id=? AND status='LEASED' AND attempt=?",
                    (status, now, now, "lease_expired", job_id, job.attempt),
                )
            self._append_transition(
                connection, kind="LEASE_EXPIRE_" + status, job_id=job.job_id, operation_id=job.operation_id,
                event={"at_ms": now, "status": status, "attempt": job.attempt, "error_code": "lease_expired"},
            )
            count += 1
        if count:
            meta = self._meta(connection)
            self._update_storage_locked(
                connection, nonterminal=int(meta[12]) - held_count,
                leases=int(meta[13]) - count,
            )
        return count

    def recover_expired(self) -> int:
        now = int(self.clock.now_ms())
        with closing(self._connect()) as connection:
            began = False
            try:
                self._begin(connection)
                began = True
                self._meta(connection)
                count = self._expire_locked(connection, now)
                connection.execute("COMMIT")
                began = False
            except sqlite3.Error as exc:
                if began and connection.in_transaction:
                    connection.execute("ROLLBACK")
                _raise_fixed(self._translate_sqlite(exc))
            except Exception:
                if began and connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return count

    def claim_next(self, *, worker_id: str) -> QueueWorkItem | None:
        _safe_token(worker_id, "worker_id", maximum=_MAX_WORKER_ID)
        now = int(self.clock.now_ms())
        with closing(self._connect()) as connection:
            began = False
            try:
                self._begin(connection)
                began = True
                self._meta(connection)
                self._expire_locked(connection, now)
                existing_lease = connection.execute(
                    "SELECT j.*,l.token,l.leased_ms,l.expires_ms FROM queue_jobs j JOIN queue_leases l ON l.job_id=j.job_id WHERE j.status='LEASED' AND l.worker_id=? AND l.expires_ms>?",
                    (worker_id, now),
                ).fetchone()
                if existing_lease is not None:
                    existing_job = self._row_to_job(tuple(existing_lease[:14]))
                    existing_raw = _lease_raw(
                        self.config, existing_job.job_id, worker_id, existing_job.attempt,
                        int(existing_lease[15]), int(existing_lease[16]),
                    )
                    if bytes(existing_lease[14]) != _lease_digest(
                        self.config, existing_job.job_id, worker_id, existing_job.attempt,
                        int(existing_lease[15]), int(existing_lease[16]), existing_raw,
                    ):
                        raise QueueIntegrityError("queue_lease_fence")
                    connection.execute("COMMIT")
                    began = False
                    return QueueWorkItem(
                        queue_id=self.config.queue_id, job_id=existing_job.job_id,
                        operation_id=existing_job.operation_id, metadata=existing_job.metadata,
                        attempt=existing_job.attempt, worker_id=worker_id,
                        lease_token=existing_raw, lease_expires_ms=int(existing_lease[16]),
                        expected_verifier_sha256=self.config.verifier_sha256,
                    )
                metadata = self._meta(connection)
                live_lease_rows = connection.execute("SELECT job_id FROM queue_leases ORDER BY job_id LIMIT 5").fetchall()
                if len(live_lease_rows) != int(metadata[13]) or len(live_lease_rows) > MAX_WORKER_CONCURRENCY:
                    raise QueueIntegrityError("queue_lease_counter")
                live_leases = len(live_lease_rows)
                if live_leases >= MAX_WORKER_CONCURRENCY:
                    raise QueueBackpressureError("queue_worker_capacity")
                row = connection.execute(
                    "SELECT * FROM queue_jobs INDEXED BY queue_jobs_status_eligible WHERE status='QUEUED' AND next_eligible_ms<=? ORDER BY admission_seq LIMIT 1",
                    (now,),
                ).fetchone()
                if row is None:
                    connection.execute("COMMIT")
                    began = False
                    return None
                job = self._row_to_job(tuple(row))
                attempt = job.attempt + 1
                expires = now + self.config.lease_seconds * 1000
                token = _lease_raw(self.config, job.job_id, worker_id, attempt, now, expires)
                token_digest = _lease_digest(self.config, job.job_id, worker_id, attempt, now, expires, token)
                updated = connection.execute(
                    "UPDATE queue_jobs SET status='LEASED',attempt=?,updated_ms=?,last_error_code=NULL WHERE job_id=? AND status='QUEUED' AND attempt=?",
                    (attempt, now, job.job_id, job.attempt),
                )
                if updated.rowcount != 1:
                    raise QueueLeaseError("claim_cas")
                connection.execute(
                    "INSERT INTO queue_leases VALUES (?,?,?,?,?,?)",
                    (job.job_id, worker_id, token_digest, attempt, now, expires),
                )
                self._append_transition(
                    connection, kind="CLAIM", job_id=job.job_id, operation_id=job.operation_id,
                    event={"at_ms": now, "status": "LEASED", "attempt": attempt, "worker_id": worker_id, "expires_ms": expires},
                )
                self._update_storage_locked(connection, nonterminal=int(self._meta(connection)[12]), leases=live_leases + 1)
                self._fault("after_claim")
                connection.execute("COMMIT")
                began = False
            except sqlite3.Error as exc:
                if began and connection.in_transaction:
                    connection.execute("ROLLBACK")
                _raise_fixed(self._translate_sqlite(exc))
            except Exception:
                if began and connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        self._after_commit("claim")
        return QueueWorkItem(
            queue_id=self.config.queue_id, job_id=job.job_id, operation_id=job.operation_id,
            metadata=job.metadata, attempt=attempt, worker_id=worker_id, lease_token=token,
            lease_expires_ms=expires, expected_verifier_sha256=self.config.verifier_sha256,
        )

    def _validate_work(self, work: QueueWorkItem) -> None:
        if type(work) is not QueueWorkItem or work.queue_id != self.config.queue_id:
            raise QueueLeaseError("completion_work_invalid")
        if (
            type(work.job_id) is not str or len(work.job_id) > _MAX_QUEUE_ID or _SAFE_TOKEN.fullmatch(work.job_id) is None
            or type(work.operation_id) is not bytes or len(work.operation_id) != 64
            or type(work.metadata) is not ArtifactMetadata
            or type(work.attempt) is not int or not 1 <= work.attempt <= self.config.max_attempts
            or type(work.worker_id) is not str or len(work.worker_id) > _MAX_WORKER_ID or _SAFE_TOKEN.fullmatch(work.worker_id) is None
            or type(work.lease_expires_ms) is not int or work.lease_expires_ms <= 0
            or type(work.expected_verifier_sha256) is not bytes or len(work.expected_verifier_sha256) != 32
        ):
            raise QueueLeaseError("completion_work_invalid")
        if type(work.lease_token) is not bytes or len(work.lease_token) != 24:
            raise QueueLeaseError("completion_token_shape")

    def _require_live_lease(self, connection: sqlite3.Connection, work: QueueWorkItem) -> QueueJob:
        self._validate_work(work)
        job = self._get_job_locked(connection, work.job_id)
        if (
            job is None or job.operation_id != work.operation_id or job.metadata != work.metadata
            or work.expected_verifier_sha256 != self.config.verifier_sha256
            or job.status != "LEASED" or job.attempt != work.attempt
        ):
            raise QueueLeaseError("completion_not_live")
        row = connection.execute("SELECT worker_id,token,attempt,leased_ms,expires_ms FROM queue_leases WHERE job_id=?", (work.job_id,)).fetchone()
        if row is None or str(row[0]) != work.worker_id or int(row[2]) != work.attempt:
            raise QueueLeaseError("completion_lease_mismatch")
        expected = _lease_digest(
            self.config, work.job_id, work.worker_id, work.attempt,
            int(row[3]), int(row[4]), work.lease_token,
        )
        if bytes(row[1]) != expected:
            raise QueueLeaseError("completion_lease_fence")
        now = int(self.clock.now_ms())
        if int(row[4]) <= now:
            self._expire_locked(connection, now)
            connection.execute("COMMIT")
            raise QueueLeaseError("lease_expired")
        return job

    def _build_receipt(self, work: QueueWorkItem, evidence: VerificationEvidence) -> VerificationReceipt:
        provisional = VerificationReceipt(
            schema=_SCHEMA, queue_id=self.config.queue_id, job_id=work.job_id,
            operation_id=work.operation_id, attempt=work.attempt, evidence=evidence,
            receipt_id=bytes(64),
        )
        receipt_id = _sha(_RECEIPT_DOMAIN, _json_bytes(provisional.as_json(include_id=False)))
        return VerificationReceipt(
            schema=provisional.schema, queue_id=provisional.queue_id, job_id=provisional.job_id,
            operation_id=provisional.operation_id, attempt=provisional.attempt,
            evidence=provisional.evidence, receipt_id=receipt_id,
        )

    def _historical_work_matches(self, connection: sqlite3.Connection, work: QueueWorkItem) -> bool:
        rows = connection.execute(
            "SELECT event_bytes FROM queue_transitions WHERE job_id=? AND operation_id=? AND transition_kind='CLAIM' ORDER BY sequence DESC",
            (work.job_id, work.operation_id),
        ).fetchall()
        for (raw_event,) in rows:
            try:
                event = json.loads(bytes(raw_event).decode("ascii"))
            except (TypeError, UnicodeDecodeError, json.JSONDecodeError):
                _raise_fixed(QueueIntegrityError("queue_transition_event"))
            if type(event) is dict and event.get("attempt") == work.attempt:
                if event.get("worker_id") != work.worker_id or event.get("expires_ms") != work.lease_expires_ms:
                    return False
                try:
                    expected = _lease_raw(
                        self.config, work.job_id, work.worker_id, work.attempt,
                        int(event["at_ms"]), int(event["expires_ms"]),
                    )
                except (KeyError, TypeError, ValueError):
                    _raise_fixed(QueueIntegrityError("queue_transition_event"))
                return work.lease_token == expected
        return False

    def _complete(
        self,
        work: QueueWorkItem,
        *,
        status: str,
        evidence: VerificationEvidence | None = None,
        error_code: str | None = None,
    ) -> QueueResult:
        self._validate_work(work)
        if status not in _STATUS or status == "LEASED" or status == "QUEUED":
            raise QueueIntegrityError("completion_status")
        if error_code is not None:
            error_code = _safe_code(error_code)
        receipt = None if evidence is None else self._build_receipt(work, evidence)
        receipt_bytes = None if receipt is None else receipt.canonical_bytes
        now = int(self.clock.now_ms())
        with closing(self._connect()) as connection:
            began = False
            try:
                self._begin(connection)
                began = True
                durable = connection.execute(
                    "SELECT job_id,operation_id,terminal_status,receipt_bytes,error_code FROM queue_results WHERE operation_id=?",
                    (work.operation_id,),
                ).fetchone()
                if durable is not None:
                    if not self._historical_work_matches(connection, work):
                        raise QueueLeaseError("completion_lease_fence")
                    durable_result = self._result_from_row(tuple(durable))
                    intended_error = None if status == "VERIFIED" else (error_code or ("verification_rejected" if status == "REJECTED" else "queue_held"))
                    if durable_result.status != status or durable_result.receipt_bytes != receipt_bytes or durable_result.error_code != intended_error:
                        raise QueueConflictError("completion_conflict")
                    connection.execute("COMMIT")
                    began = False
                    return durable_result
                job = self._require_live_lease(connection, work)
                if status == "VERIFIED" and receipt is None:
                    raise QueueIntegrityError("verified_receipt_missing")
                if status != "VERIFIED" and evidence is not None:
                    raise QueueIntegrityError("nonverified_evidence")
                if status == "VERIFIED":
                    new_error = None
                elif status == "REJECTED":
                    new_error = error_code or "verification_rejected"
                else:
                    new_error = error_code or "queue_held"
                connection.execute("DELETE FROM queue_leases WHERE job_id=?", (work.job_id,))
                connection.execute(
                    "UPDATE queue_jobs SET status=?,updated_ms=?,last_error_code=? WHERE job_id=? AND status='LEASED' AND attempt=?",
                    (status, now, new_error, work.job_id, work.attempt),
                )
                connection.execute(
                    "INSERT INTO queue_results VALUES (?,?,?,?,?,?)",
                    (work.operation_id, work.job_id, status, receipt_bytes, new_error, now),
                )
                connection.execute(
                    "UPDATE queue_operations SET result_status=?,result_receipt=?,result_error_code=? WHERE operation_id=?",
                    (status, receipt_bytes, new_error, work.operation_id),
                )
                self._fault("after_result_write")
                self._append_transition(
                    connection, kind="COMPLETE_" + status, job_id=work.job_id, operation_id=work.operation_id,
                    event={
                        "at_ms": now, "status": status, "attempt": work.attempt,
                        "error_code": new_error, "receipt_digest": None if receipt is None else _hex(receipt.digest),
                    },
                )
                self._fault("after_transition")
                meta = self._meta(connection)
                self._update_storage_locked(connection, nonterminal=int(meta[12]) - 1, leases=int(meta[13]) - 1)
                connection.execute("COMMIT")
                began = False
            except sqlite3.Error as exc:
                if began and connection.in_transaction:
                    connection.execute("ROLLBACK")
                _raise_fixed(self._translate_sqlite(exc))
            except Exception:
                if began and connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        self._after_commit("complete")
        return QueueResult(work.job_id, work.operation_id, status, receipt_bytes, new_error)

    def complete_verified(self, work: QueueWorkItem, evidence: VerificationEvidence) -> QueueResult:
        self._validate_work(work)
        if type(evidence) is not VerificationEvidence:
            raise QueueIntegrityError("completion_evidence_shape")
        if (
            evidence.verifier_sha256 != self.config.verifier_sha256
            or evidence.artifact_bytes != work.metadata.artifact_bytes
            or evidence.artifact_sha256 != work.metadata.artifact_sha256
            or evidence.artifact_sha3_512 != work.metadata.artifact_sha3_512
            or evidence.cap_bytes != _CAP_BYTES or evidence.cap_enforced is not True
            or evidence.active_process_limit != _ACTIVE_PROCESS_LIMIT
            or evidence.timed_out is not False or evidence.exit_code != 0
            or evidence.peak_job_commit_bytes > _CAP_BYTES
        ):
            raise QueueIntegrityError("completion_evidence_binding")
        return self._complete(work, status="VERIFIED", evidence=evidence)

    def complete_rejected(self, work: QueueWorkItem, error_code: str = "verification_rejected") -> QueueResult:
        return self._complete(work, status="REJECTED", error_code=error_code)

    def complete_retryable(self, work: QueueWorkItem, error_code: str) -> QueueResult | None:
        self._validate_work(work)
        error_code = _safe_code(error_code)
        if error_code not in self.config.retryable_codes:
            raise QueueIntegrityError("retry_code_not_allowed")
        now = int(self.clock.now_ms())
        if work.attempt >= self.config.max_attempts:
            return self._complete(work, status="HELD", error_code=error_code)
        with closing(self._connect()) as connection:
            began = False
            try:
                self._begin(connection)
                began = True
                durable = connection.execute(
                    "SELECT job_id,operation_id,terminal_status,receipt_bytes,error_code FROM queue_results WHERE operation_id=?",
                    (work.operation_id,),
                ).fetchone()
                if durable is not None:
                    if not self._historical_work_matches(connection, work):
                        raise QueueLeaseError("completion_lease_fence")
                    result = self._result_from_row(tuple(durable))
                    if result.status != "HELD" or result.error_code != error_code:
                        raise QueueConflictError("retry_conflict")
                    connection.execute("COMMIT")
                    began = False
                    return result
                current_job = self._get_job_locked(connection, work.job_id)
                if current_job is not None and current_job.status == "QUEUED" and current_job.attempt == work.attempt and current_job.last_error_code == error_code:
                    connection.execute("COMMIT")
                    began = False
                    return None
                if current_job is not None and current_job.status != "LEASED":
                    connection.execute("COMMIT")
                    began = False
                    raise QueueIndeterminateError("retry_reconciled")
                job = self._require_live_lease(connection, work)
                connection.execute("DELETE FROM queue_leases WHERE job_id=?", (work.job_id,))
                updated = connection.execute(
                    "UPDATE queue_jobs SET status='QUEUED',updated_ms=?,next_eligible_ms=?,last_error_code=? WHERE job_id=? AND status='LEASED' AND attempt=?",
                    (now, now, error_code, work.job_id, work.attempt),
                )
                if updated.rowcount != 1:
                    raise QueueLeaseError("retry_cas")
                self._fault("after_retry_write")
                self._append_transition(
                    connection, kind="RETRY_QUEUED", job_id=job.job_id, operation_id=job.operation_id,
                    event={"at_ms": now, "status": "QUEUED", "attempt": work.attempt, "error_code": error_code},
                )
                self._fault("after_transition")
                meta = self._meta(connection)
                self._update_storage_locked(connection, nonterminal=int(meta[12]), leases=int(meta[13]) - 1)
                connection.execute("COMMIT")
                began = False
            except sqlite3.Error as exc:
                if began and connection.in_transaction:
                    connection.execute("ROLLBACK")
                _raise_fixed(self._translate_sqlite(exc))
            except Exception:
                if began and connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        self._after_commit("retry")
        return None

    def retry_result(self, operation_id: bytes) -> QueueResult | None:
        operation_id = _bytes(operation_id, 64, "operation_id")
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT job_id,operation_id,terminal_status,receipt_bytes,error_code FROM queue_results WHERE operation_id=?",
                (operation_id,),
            ).fetchone()
        if row is None:
            return None
        return self._result_from_row(tuple(row))

    def get_job(self, job_id: str) -> QueueJob | None:
        _safe_token(job_id, "job_id", maximum=_MAX_QUEUE_ID)
        with closing(self._connect()) as connection:
            return self._get_job_locked(connection, job_id)

    def snapshot(self) -> dict[str, Any]:
        with closing(self._connect()) as connection:
            meta = self._meta(connection)
            counts = {status: 0 for status in _STATUS}
            for (status,) in connection.execute("SELECT status FROM queue_jobs"):
                counts[str(status)] = counts.get(str(status), 0) + 1
            leases = sum(1 for _ in connection.execute("SELECT job_id FROM queue_leases"))
            transitions = sum(1 for _ in connection.execute("SELECT sequence FROM queue_transitions"))
        return {"head_root": bytes(meta[7]), "counts": counts, "leases": leases, "transitions": transitions}

    def support_summary(self) -> dict[str, Any]:
        snap = self.snapshot()
        with closing(self._connect()) as connection:
            oldest = connection.execute(
                "SELECT MIN(admission_seq) FROM queue_jobs WHERE status IN ('QUEUED','LEASED')"
            ).fetchone()[0]
            lease_age = connection.execute(
                "SELECT MIN(?-leased_ms) FROM queue_leases", (int(self.clock.now_ms()),)
            ).fetchone()[0]
            storage_used = int(self._meta(connection)[10])
            storage_reserved = int(self._meta(connection)[11])
        return {
            "schema": _SCHEMA,
            "queue_id": self.config.queue_id,
            "head_root": _hex(snap["head_root"]),
            "status_counts": snap["counts"],
            "nonterminal_depth": snap["counts"]["QUEUED"] + snap["counts"]["LEASED"],
            "oldest_admission_seq": oldest,
            "oldest_lease_age_bucket": None if lease_age is None else ("0-59s" if int(lease_age) < 60_000 else "60s+") ,
            "failure_counts": self._failure_counts(),
            "storage_used_bytes": storage_used,
            "storage_reserved_bytes": storage_reserved,
            "storage_capacity_bytes": MAX_QUEUE_DATABASE_BYTES,
        }

    def _failure_counts(self) -> dict[str, int]:
        with closing(self._connect()) as connection:
            rows = [str(code) for (code,) in connection.execute(
                "SELECT last_error_code FROM queue_jobs WHERE last_error_code IS NOT NULL ORDER BY last_error_code"
            )]
        counts: dict[str, int] = {}
        for code in rows:
            counts[code] = counts.get(code, 0) + 1
        return counts

    def verify_integrity(self) -> None:
        with closing(self._connect()) as connection:
            self._schema_check(connection)
            meta = self._meta(connection)
            rows = connection.execute("SELECT * FROM queue_jobs ORDER BY admission_seq").fetchall()
            operations = connection.execute("SELECT * FROM queue_operations ORDER BY job_id").fetchall()
            leases = connection.execute("SELECT * FROM queue_leases ORDER BY job_id").fetchall()
            results = connection.execute("SELECT * FROM queue_results ORDER BY job_id").fetchall()
            transitions = connection.execute("SELECT * FROM queue_transitions ORDER BY sequence").fetchall()
            if int(meta[10]) != self._page_bytes(connection) or int(meta[11]) != int(meta[12]) * MAX_TERMINAL_GROWTH_PER_NONTERMINAL:
                raise QueueIntegrityError("queue_storage_metadata")
            if int(meta[13]) != len(leases) or int(meta[12]) != sum(1 for row in rows if str(row[7]) in _NONTERMINAL):
                raise QueueIntegrityError("queue_counter_metadata")
            if int(meta[8]) != len(transitions):
                raise QueueIntegrityError("queue_transition_count")
            if int(meta[9]) != len(rows):
                raise QueueIntegrityError("queue_admission_count")
            expected_head = _sha(_GENESIS_DOMAIN, self.config.queue_id.encode("ascii"), self.config.digest)
            for index, transition in enumerate(transitions, start=1):
                if int(transition[0]) != index or bytes(transition[4]) != expected_head:
                    raise QueueIntegrityError("queue_head_chain")
                event_digest = _sha(_EVENT_DOMAIN, _u64(int(transition[0])), str(transition[1]).encode("ascii"), str(transition[2]).encode("ascii"), bytes(transition[3]), bytes(transition[6]))
                if event_digest != bytes(transition[7]):
                    raise QueueIntegrityError("queue_event_digest")
                expected_head = _sha(_HEAD_DOMAIN, expected_head, _u64(index), event_digest)
                if expected_head != bytes(transition[5]):
                    raise QueueIntegrityError("queue_head_transition")
            if expected_head != bytes(meta[7]):
                raise QueueIntegrityError("queue_head_current")
            job_map: dict[str, QueueJob] = {}
            operation_ids: set[bytes] = set()
            for row in rows:
                job = self._row_to_job(tuple(row))
                if job.job_id in job_map or job.operation_id in operation_ids:
                    raise QueueIntegrityError("queue_job_duplicate")
                if job.metadata.artifact_bytes > self.config.artifact_bytes_cap or job.attempt < 0:
                    raise QueueIntegrityError("queue_job_metadata")
                job_map[job.job_id] = job
                operation_ids.add(job.operation_id)
            if len(operations) != len(rows):
                raise QueueIntegrityError("queue_operation_count")
            operation_map: dict[bytes, tuple[Any, ...]] = {}
            for row in operations:
                operation_id = bytes(row[0])
                if operation_id in operation_map or str(row[1]) not in job_map:
                    raise QueueIntegrityError("queue_operation_binding")
                job = job_map[str(row[1])]
                if operation_id != job.operation_id or bytes(row[2]) != _material_digest(self.config, job.job_id, job.metadata):
                    raise QueueIntegrityError("queue_operation_material")
                operation_map[operation_id] = tuple(row)
            lease_map: dict[str, tuple[Any, ...]] = {str(row[0]): tuple(row) for row in leases}
            result_map: dict[bytes, tuple[Any, ...]] = {bytes(row[0]): tuple(row) for row in results}
            if len(lease_map) != len(leases) or len(result_map) != len(results):
                raise QueueIntegrityError("queue_lease_result_duplicate")
            for job_id, job in job_map.items():
                has_lease = job_id in lease_map
                has_result = job.operation_id in result_map
                if job.status == "LEASED" and not has_lease or job.status != "LEASED" and has_lease:
                    raise QueueIntegrityError("queue_lease_binding")
                if job.status in _TERMINAL and not has_result or job.status in _NONTERMINAL and has_result:
                    raise QueueIntegrityError("queue_result_binding")
                if has_lease:
                    lease = lease_map[job_id]
                    if str(lease[1]) == "" or len(bytes(lease[2])) != 64 or int(lease[3]) != job.attempt:
                        raise QueueIntegrityError("queue_lease_shape")
                    expected_token = _lease_digest(
                        self.config, job_id, str(lease[1]), int(lease[3]),
                        int(lease[4]), int(lease[5]),
                        _lease_raw(self.config, job_id, str(lease[1]), int(lease[3]), int(lease[4]), int(lease[5])),
                    )
                    if bytes(lease[2]) != expected_token or int(lease[5]) <= int(lease[4]):
                        raise QueueIntegrityError("queue_lease_fence")
                if has_result:
                    result = result_map[job.operation_id]
                    if str(result[1]) != job_id or str(result[2]) != job.status:
                        raise QueueIntegrityError("queue_result_state")
                    if job.status == "VERIFIED":
                        if result[3] is None or not bytes(result[3]):
                            raise QueueIntegrityError("queue_receipt_missing")
                        receipt = _parse_receipt(bytes(result[3]), self.config)
                        if (
                            receipt.job_id != job.job_id or receipt.operation_id != job.operation_id
                            or receipt.attempt != job.attempt
                            or receipt.evidence.artifact_bytes != job.metadata.artifact_bytes
                            or receipt.evidence.artifact_sha256 != job.metadata.artifact_sha256
                            or receipt.evidence.artifact_sha3_512 != job.metadata.artifact_sha3_512
                        ):
                            raise QueueIntegrityError("queue_receipt_job_binding")
                    elif result[4] is None:
                        raise QueueIntegrityError("queue_terminal_error_missing")
            if sum(1 for job in job_map.values() if job.status in _NONTERMINAL) > self.config.capacity or len(leases) > MAX_WORKER_CONCURRENCY:
                raise QueueIntegrityError("queue_capacity_integrity")

    def export_bytes(self) -> bytes:
        self.verify_integrity()
        with closing(self._connect()) as connection:
            began = False
            try:
                connection.execute("BEGIN")
                began = True
                self._meta(connection)
                self._schema_check(connection)
                raw = connection.serialize()
                if type(raw) is not bytes or not 0 < len(raw) <= MAX_QUEUE_DATABASE_BYTES:
                    raise QueueBackpressureError("queue_export_capacity")
                connection.execute("COMMIT")
                began = False
                return raw
            except sqlite3.Error as exc:
                if began and connection.in_transaction:
                    connection.execute("ROLLBACK")
                _raise_fixed(self._translate_sqlite(exc))
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
    def close(self) -> None:
        return None


def _parse_receipt(raw: bytes, config: QueueConfig) -> VerificationReceipt:
    if type(raw) is not bytes or len(raw) > 16 * 1024:
        raise QueueIntegrityError("queue_receipt_bounds")
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _raise_fixed(QueueIntegrityError("queue_receipt_encoding"))
    if type(value) is not dict or value.get("schema") != _SCHEMA or value.get("queue_id") != config.queue_id:
        raise QueueIntegrityError("queue_receipt_schema")
    expected_keys = {
        "schema", "queue_id", "job_id", "operation_id", "attempt", "evidence", "receipt_id",
    }
    if set(value) != expected_keys:
        raise QueueIntegrityError("queue_receipt_keys")
    if type(value["schema"]) is not str or type(value["queue_id"]) is not str:
        raise QueueIntegrityError("queue_receipt_schema")
    if _safe_token(value["job_id"], "receipt_job_id", maximum=_MAX_QUEUE_ID) != value["job_id"]:
        raise QueueIntegrityError("queue_receipt_job_id")
    operation = _parse_hex(value["operation_id"], 64, "receipt_operation_id")
    receipt_id = _parse_hex(value["receipt_id"], 64, "receipt_id")
    if type(value["attempt"]) is not int or value["attempt"] < 1:
        raise QueueIntegrityError("queue_receipt_attempt")
    evidence = value["evidence"]
    evidence_keys = {
        "artifact_bytes", "artifact_sha256", "artifact_sha3_512", "verifier_sha256",
        "circuit_id", "acceptance_bytes", "proof_acceptance_digest", "peak_job_commit_bytes", "cap_bytes", "cap_enforced",
        "active_process_limit", "timed_out", "exit_code", "stdout_sha3_512", "stderr_sha3_512",
    }
    if type(evidence) is not dict or set(evidence) != evidence_keys:
        raise QueueIntegrityError("queue_receipt_evidence_keys")
    integer_fields = ("artifact_bytes", "peak_job_commit_bytes", "cap_bytes", "active_process_limit", "exit_code")
    if any(type(evidence[field]) is not int for field in integer_fields):
        raise QueueIntegrityError("queue_receipt_evidence_types")
    if type(evidence["cap_enforced"]) is not bool or type(evidence["timed_out"]) is not bool:
        raise QueueIntegrityError("queue_receipt_evidence_types")
    evidence_object = VerificationEvidence(
        artifact_bytes=evidence["artifact_bytes"], artifact_sha256=_parse_hex(evidence["artifact_sha256"], 32, "evidence_sha256"),
        artifact_sha3_512=_parse_hex(evidence["artifact_sha3_512"], 64, "evidence_sha3"),
        verifier_sha256=_parse_hex(evidence["verifier_sha256"], 32, "evidence_verifier"),
        circuit_id=_parse_hex(evidence["circuit_id"], 32, "evidence_circuit"),
        acceptance_bytes=_parse_hex(evidence["acceptance_bytes"], None, "evidence_acceptance_bytes"),
        proof_acceptance_digest=_parse_hex(evidence["proof_acceptance_digest"], 64, "evidence_acceptance"),
        peak_job_commit_bytes=evidence["peak_job_commit_bytes"], cap_bytes=evidence["cap_bytes"],
        cap_enforced=evidence["cap_enforced"], active_process_limit=evidence["active_process_limit"],
        timed_out=evidence["timed_out"], exit_code=evidence["exit_code"],
        stdout_sha3_512=_parse_hex(evidence["stdout_sha3_512"], 64, "evidence_stdout"),
        stderr_sha3_512=_parse_hex(evidence["stderr_sha3_512"], 64, "evidence_stderr"),
    )
    result = VerificationReceipt(
        schema=_SCHEMA, queue_id=config.queue_id, job_id=value["job_id"], operation_id=operation,
        attempt=value["attempt"], evidence=evidence_object, receipt_id=receipt_id,
    )
    if raw != result.canonical_bytes:
        raise QueueIntegrityError("queue_receipt_noncanonical")
    expected_id = _sha(_RECEIPT_DOMAIN, _json_bytes(result.as_json(include_id=False)))
    if receipt_id != expected_id or evidence_object.verifier_sha256 != config.verifier_sha256:
        raise QueueIntegrityError("queue_receipt_binding")
    return result


class QueueWorker:
    """One fixed worker identity; every claim gets a fresh verifier instance."""

    def __init__(
        self,
        *,
        store: VerificationQueueStore,
        worker_id: str,
        custody: ProofArtifactCustodyPort,
        verifier_factory: VerificationFactory,
    ) -> None:
        _safe_token(worker_id, "worker_id", maximum=_MAX_WORKER_ID)
        if not callable(verifier_factory) or not callable(getattr(custody, "snapshot", None)):
            raise VerificationQueueError("queue_worker_port")
        self.store = store
        self.worker_id = worker_id
        self.custody = custody
        self.verifier_factory = verifier_factory
        self.last_verification_wall_ms: int | None = None
        self.last_verification_started: float | None = None
        self.last_verification_ended: float | None = None

    @staticmethod
    def _error_code(error: BaseException) -> str:
        current: BaseException | None = error
        while current is not None:
            token = str(current)
            if _SAFE_CODE.fullmatch(token) is not None:
                return token
            current = current.__cause__ or current.__context__
        return "worker_exception"

    def _terminal(self, work: QueueWorkItem, *, status: str, error_code: str | None = None, evidence: VerificationEvidence | None = None) -> QueueResult:
        try:
            if status == "VERIFIED":
                return self.store.complete_verified(work, evidence)  # type: ignore[arg-type]
            if status == "REJECTED":
                return self.store.complete_rejected(work, error_code or "verification_rejected")
            return self.store._complete(work, status="HELD", error_code=error_code or "queue_held")
        except QueueIndeterminateError:
            durable = self.store.retry_result(work.operation_id)
            if durable is None:
                _raise_fixed(QueueIndeterminateError("queue_commit_indeterminate"))
            return durable

    def _retry(self, work: QueueWorkItem, code: str) -> QueueResult:
        try:
            result = self.store.complete_retryable(work, code)
            return result or QueueResult(work.job_id, work.operation_id, "QUEUED", None, code)
        except QueueIndeterminateError:
            durable = self.store.retry_result(work.operation_id)
            if durable is not None:
                return durable
            job = self.store.get_job(work.job_id)
            if job is not None and job.status == "QUEUED" and job.attempt == work.attempt:
                return QueueResult(work.job_id, work.operation_id, "QUEUED", None, code)
            _raise_fixed(QueueIndeterminateError("queue_retry_indeterminate"))

    def process_one(self) -> QueueResult | None:
        try:
            work = self.store.claim_next(worker_id=self.worker_id)
        except QueueIndeterminateError:
            work = self.store.claim_next(worker_id=self.worker_id)
        if work is None:
            return None
        snapshot: CustodySnapshot | None = None
        try:
            snapshot = self.custody.snapshot(work.metadata.artifact_ref, work.metadata)
            if type(snapshot) is not CustodySnapshot:
                raise QueueHeldError("custody_snapshot_shape")
            if (
                not snapshot.path.is_file() or snapshot.path.is_symlink()
                or snapshot.artifact_bytes != work.metadata.artifact_bytes
                or snapshot.artifact_sha256 != work.metadata.artifact_sha256
                or snapshot.artifact_sha3_512 != work.metadata.artifact_sha3_512
                or snapshot.readonly is not True
                or not callable(snapshot.cleanup)
            ):
                raise QueueHeldError("custody_snapshot_identity")
            verifier = self.verifier_factory()
            if type(verifier) is not NativeMinimalClearanceVerifier:
                raise QueueHeldError("verifier_type")
            identity = verifier.identity_sha256()
            if identity != self.store.config.verifier_sha256:
                raise QueueHeldError("verifier_identity")
            started = time.perf_counter()
            self.last_verification_started = started
            try:
                acceptance = verifier.verify(snapshot.path)
            finally:
                ended = time.perf_counter()
                self.last_verification_ended = ended
                self.last_verification_wall_ms = max(1, int(round((ended - started) * 1000)))
            containment = getattr(verifier, "last_containment_result", None)
            evidence = build_verification_evidence(
                acceptance, containment, snapshot, self.store.config.verifier_sha256,
            )
            cleanup = snapshot.cleanup
            if cleanup is not None:
                try:
                    cleanup()
                except Exception as exc:
                    _raise_fixed(QueueHeldError("custody_cleanup"))
            snapshot = None
            return self._terminal(work, status="VERIFIED", evidence=evidence)
        except Exception as exc:
            if snapshot is not None and snapshot.cleanup is not None:
                try:
                    snapshot.cleanup()
                except Exception:
                    exc = QueueHeldError("custody_cleanup")
                snapshot = None
            if isinstance(exc, QueueIndeterminateError):
                durable = self.store.retry_result(work.operation_id)
                if durable is not None:
                    return durable
                raise
            if isinstance(exc, QueueDeterministicRejectError):
                return self._terminal(work, status="REJECTED", error_code=_safe_code(str(exc)))
            if isinstance(exc, QueueRetryableError):
                code = _safe_code(str(exc))
                if code in self.store.config.retryable_codes:
                    return self._retry(work, code)
                return self._terminal(work, status="HELD", error_code=code)
            if isinstance(exc, QueueHeldError):
                return self._terminal(work, status="HELD", error_code=_safe_code(str(exc)))
            if isinstance(exc, VerificationQueueError):
                return self._terminal(work, status="HELD", error_code=_safe_code(str(exc)))
            code = self._error_code(exc)
            if code in _DETERMINISTIC_REJECT_CODES:
                return self._terminal(work, status="REJECTED", error_code=code)
            if code in self.store.config.retryable_codes:
                return self._retry(work, code)
            return self._terminal(work, status="HELD", error_code=code)


def run_bounded_workers(workers: tuple[QueueWorker, ...]) -> tuple[QueueResult | None, ...]:
    """Run at most the immutable four-worker bound with no shared verifier."""

    if type(workers) is not tuple or not 0 < len(workers) <= 4:
        raise VerificationQueueError("queue_worker_bound")
    if len({worker.worker_id for worker in workers}) != len(workers):
        raise VerificationQueueError("queue_worker_identity_duplicate")
    with ThreadPoolExecutor(max_workers=len(workers), thread_name_prefix="bl-queue-worker") as executor:
        futures = [executor.submit(worker.process_one) for worker in workers]
        return tuple(future.result() for future in futures)


__all__ = (
    "ArtifactMetadata", "CustodySnapshot", "FilesystemArtifactCustody", "ProofArtifactCustodyPort", "QueueBackpressureError",
    "QueueClock", "QueueConfig", "QueueConflictError", "QueueDeterministicRejectError",
    "QueueHeldError", "QueueIndeterminateError", "QueueIntegrityError", "QueueJob", "QueueLeaseError",
    "QueueResult", "QueueRetryableError", "QueueWorkItem", "SystemQueueClock", "VerificationEvidence",
    "VerificationFactory", "VerificationQueueError", "VerificationQueueStore", "VerificationReceipt",
    "QueueWorker", "build_verification_evidence", "run_bounded_workers",
    "MAX_QUEUE_DATABASE_BYTES", "MAX_QUEUE_CAPACITY", "MAX_TERMINAL_GROWTH_PER_NONTERMINAL", "MAX_WORKER_CONCURRENCY",
)
