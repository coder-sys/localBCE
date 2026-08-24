"""Queue-owned proving resource policy.

This is a deliberately small, software-owned policy object.  Admission derives
it from the trusted process environment once; workers parse and validate the
stored canonical object again before they execute anything.  None of the
resource values are a production-capacity or readiness claim.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Final, Mapping


POLICY_SCHEMA: Final[str] = "BL/NATIVE-V3/PROVING-RESOURCE-POLICY/v1"
POLICY_SCHEMA_VERSION: Final[int] = 1
POLICY_ENVIRONMENT: Final[str] = "BL_PROVER_THREADS"
WINDOWS_JOB_MEMORY_CAP_BYTES: Final[int] = 5_000_000_000
MAX_ATTEMPTS: Final[int] = 2
TIMEOUT_SECONDS: Final[int] = 1_800
MAX_NONTERMINAL_JOBS: Final[int] = 8
MAX_TOTAL_JOBS: Final[int] = 64
MAX_JOB_BYTES: Final[int] = 5_000_000_000
MAX_QUEUE_BYTES: Final[int] = 40_000_000_000
MAX_OWNED_FILES: Final[int] = 16_384
MAX_AUDIT_BYTES: Final[int] = 2_097_152
MAX_AUDIT_EVENTS: Final[int] = 1_024
MAX_AUDIT_LINE_BYTES: Final[int] = 16_384
MAX_STDOUT_BYTES: Final[int] = 1_048_576
MAX_STDERR_BYTES: Final[int] = 1_048_576
MAX_POLICY_BYTES: Final[int] = 16_384

_THREADS_PATTERN = re.compile(r"[0-9]+\Z")
_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "schema",
        "schema_version",
        "threads",
        "max_attempts",
        "timeout_seconds",
        "windows_job_memory_cap_bytes",
        "max_nonterminal_jobs",
        "max_total_jobs",
        "max_job_bytes",
        "max_queue_bytes",
        "max_owned_files",
        "max_audit_bytes",
        "max_audit_events",
        "max_audit_line_bytes",
        "max_stdout_bytes",
        "max_stderr_bytes",
    }
)


class ProvingResourcePolicyError(RuntimeError):
    """A fixed, non-diagnostic policy error."""

    def __init__(self, code: str) -> None:
        if not isinstance(code, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,95}", code):
            code = "proving_policy_invalid"
        super().__init__(code)
        self.code = code


def _canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        raise ProvingResourcePolicyError("proving_policy_encoding") from None


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _integer(value: object, name: str, *, minimum: int = 1) -> int:
    if type(value) is not int or value < minimum:
        raise ProvingResourcePolicyError(f"proving_policy_{name}")
    return value


@dataclass(frozen=True, slots=True)
class ProvingResourcePolicyV1:
    """The exact immutable resource object persisted in every queue request."""

    threads: int
    max_attempts: int = MAX_ATTEMPTS
    timeout_seconds: int = TIMEOUT_SECONDS
    windows_job_memory_cap_bytes: int = WINDOWS_JOB_MEMORY_CAP_BYTES
    max_nonterminal_jobs: int = MAX_NONTERMINAL_JOBS
    max_total_jobs: int = MAX_TOTAL_JOBS
    max_job_bytes: int = MAX_JOB_BYTES
    max_queue_bytes: int = MAX_QUEUE_BYTES
    max_owned_files: int = MAX_OWNED_FILES
    max_audit_bytes: int = MAX_AUDIT_BYTES
    max_audit_events: int = MAX_AUDIT_EVENTS
    max_audit_line_bytes: int = MAX_AUDIT_LINE_BYTES
    max_stdout_bytes: int = MAX_STDOUT_BYTES
    max_stderr_bytes: int = MAX_STDERR_BYTES

    def __post_init__(self) -> None:
        _integer(self.threads, "threads")
        if self.threads > 32:
            raise ProvingResourcePolicyError("proving_policy_threads")
        expected = {
            "max_attempts": MAX_ATTEMPTS,
            "timeout_seconds": TIMEOUT_SECONDS,
            "windows_job_memory_cap_bytes": WINDOWS_JOB_MEMORY_CAP_BYTES,
            "max_nonterminal_jobs": MAX_NONTERMINAL_JOBS,
            "max_total_jobs": MAX_TOTAL_JOBS,
            "max_job_bytes": MAX_JOB_BYTES,
            "max_queue_bytes": MAX_QUEUE_BYTES,
            "max_owned_files": MAX_OWNED_FILES,
            "max_audit_bytes": MAX_AUDIT_BYTES,
            "max_audit_events": MAX_AUDIT_EVENTS,
            "max_audit_line_bytes": MAX_AUDIT_LINE_BYTES,
            "max_stdout_bytes": MAX_STDOUT_BYTES,
            "max_stderr_bytes": MAX_STDERR_BYTES,
        }
        for name, fixed in expected.items():
            value = getattr(self, name)
            if type(value) is not int or value != fixed:
                raise ProvingResourcePolicyError(f"proving_policy_{name}")

    @property
    def effective_threads(self) -> int:
        return self.threads

    def as_json(self) -> dict[str, Any]:
        return {
            "schema": POLICY_SCHEMA,
            "schema_version": POLICY_SCHEMA_VERSION,
            "threads": self.threads,
            "max_attempts": self.max_attempts,
            "timeout_seconds": self.timeout_seconds,
            "windows_job_memory_cap_bytes": self.windows_job_memory_cap_bytes,
            "max_nonterminal_jobs": self.max_nonterminal_jobs,
            "max_total_jobs": self.max_total_jobs,
            "max_job_bytes": self.max_job_bytes,
            "max_queue_bytes": self.max_queue_bytes,
            "max_owned_files": self.max_owned_files,
            "max_audit_bytes": self.max_audit_bytes,
            "max_audit_events": self.max_audit_events,
            "max_audit_line_bytes": self.max_audit_line_bytes,
            "max_stdout_bytes": self.max_stdout_bytes,
            "max_stderr_bytes": self.max_stderr_bytes,
        }

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical_json_bytes(self.as_json())

    @property
    def digest(self) -> str:
        return _sha256(self.canonical_bytes)

    @property
    def sha256(self) -> str:
        return self.digest


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProvingResourcePolicyError("proving_policy_duplicate_key")
        result[key] = value
    return result


def policy_from_mapping(value: object) -> ProvingResourcePolicyV1:
    if not isinstance(value, dict) or set(value) != _FIELDS:
        raise ProvingResourcePolicyError("proving_policy_schema")
    if value.get("schema") != POLICY_SCHEMA or value.get("schema_version") != POLICY_SCHEMA_VERSION:
        raise ProvingResourcePolicyError("proving_policy_schema")
    return ProvingResourcePolicyV1(
        threads=_integer(value.get("threads"), "threads"),
        max_attempts=_integer(value.get("max_attempts"), "max_attempts"),
        timeout_seconds=_integer(value.get("timeout_seconds"), "timeout_seconds"),
        windows_job_memory_cap_bytes=_integer(
            value.get("windows_job_memory_cap_bytes"), "windows_job_memory_cap_bytes"
        ),
        max_nonterminal_jobs=_integer(value.get("max_nonterminal_jobs"), "max_nonterminal_jobs"),
        max_total_jobs=_integer(value.get("max_total_jobs"), "max_total_jobs"),
        max_job_bytes=_integer(value.get("max_job_bytes"), "max_job_bytes"),
        max_queue_bytes=_integer(value.get("max_queue_bytes"), "max_queue_bytes"),
        max_owned_files=_integer(value.get("max_owned_files"), "max_owned_files"),
        max_audit_bytes=_integer(value.get("max_audit_bytes"), "max_audit_bytes"),
        max_audit_events=_integer(value.get("max_audit_events"), "max_audit_events"),
        max_audit_line_bytes=_integer(
            value.get("max_audit_line_bytes"), "max_audit_line_bytes"
        ),
        max_stdout_bytes=_integer(value.get("max_stdout_bytes"), "max_stdout_bytes"),
        max_stderr_bytes=_integer(value.get("max_stderr_bytes"), "max_stderr_bytes"),
    )


def derive_policy(environment: Mapping[str, str] | None = None) -> ProvingResourcePolicyV1:
    """Derive the sole policy authority from the trusted process environment."""

    source = os.environ if environment is None else environment
    raw = source.get(POLICY_ENVIRONMENT)
    if raw is None:
        threads = min(os.cpu_count() or 1, 8)
    else:
        if not isinstance(raw, str) or _THREADS_PATTERN.fullmatch(raw) is None:
            raise ProvingResourcePolicyError("proving_policy_threads_environment")
        try:
            threads = int(raw, 10)
        except ValueError:
            raise ProvingResourcePolicyError("proving_policy_threads_environment") from None
        if not 1 <= threads <= 32:
            raise ProvingResourcePolicyError("proving_policy_threads_environment")
    return ProvingResourcePolicyV1(threads=threads)


def validate_bound_policy(value: object, digest: object) -> ProvingResourcePolicyV1:
    policy = policy_from_mapping(value)
    if type(digest) is not str or not re.fullmatch(r"[0-9a-f]{64}", digest) or digest != policy.digest:
        raise ProvingResourcePolicyError("proving_policy_digest")
    return policy


def policy_file_bytes(policy: ProvingResourcePolicyV1) -> bytes:
    payload = {"policy": policy.as_json(), "policy_sha256": policy.digest}
    return _canonical_json_bytes(payload) + b"\n"


def _bounded_regular_read(path: Path, maximum_bytes: int) -> bytes:
    try:
        before = os.lstat(path)
    except OSError:
        raise ProvingResourcePolicyError("proving_policy_file") from None
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ProvingResourcePolicyError("proving_policy_file")
    if before.st_size > maximum_bytes:
        raise ProvingResourcePolicyError("proving_policy_file_cap")
    descriptor: int | None = None
    try:
        flags = os.O_RDONLY | (os.O_BINARY if hasattr(os, "O_BINARY") else 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if stat.S_ISLNK(opened.st_mode) or not stat.S_ISREG(opened.st_mode):
            raise ProvingResourcePolicyError("proving_policy_file")
        if opened.st_size > maximum_bytes:
            raise ProvingResourcePolicyError("proving_policy_file_cap")
        data = bytearray()
        while len(data) <= maximum_bytes:
            chunk = os.read(descriptor, maximum_bytes + 1 - len(data))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > maximum_bytes:
                raise ProvingResourcePolicyError("proving_policy_file_cap")
        after_open = os.fstat(descriptor)
    except ProvingResourcePolicyError:
        raise
    except (OSError, ValueError):
        raise ProvingResourcePolicyError("proving_policy_file") from None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                raise ProvingResourcePolicyError("proving_policy_file") from None
    try:
        after = os.lstat(path)
    except OSError:
        raise ProvingResourcePolicyError("proving_policy_file") from None
    expected = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    if (
        stat.S_ISLNK(after.st_mode)
        or not stat.S_ISREG(after.st_mode)
        or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != expected
        or (after_open.st_dev, after_open.st_ino, after_open.st_size, after_open.st_mtime_ns)
        != expected
        or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != expected
        or len(data) != before.st_size
    ):
        raise ProvingResourcePolicyError("proving_policy_file")
    return bytes(data)


def read_policy_file(path: Path, *, maximum_bytes: int = MAX_POLICY_BYTES) -> ProvingResourcePolicyV1:
    if not isinstance(path, Path) or type(maximum_bytes) is not int or maximum_bytes < 1:
        raise ProvingResourcePolicyError("proving_policy_file")
    raw = _bounded_regular_read(path, maximum_bytes)
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ProvingResourcePolicyError("proving_policy_file_encoding") from None
    if not isinstance(value, dict) or set(value) != {"policy", "policy_sha256"}:
        raise ProvingResourcePolicyError("proving_policy_file_schema")
    return validate_bound_policy(value["policy"], value["policy_sha256"])


__all__ = (
    "MAX_ATTEMPTS",
    "MAX_AUDIT_BYTES",
    "MAX_AUDIT_EVENTS",
    "MAX_AUDIT_LINE_BYTES",
    "MAX_JOB_BYTES",
    "MAX_NONTERMINAL_JOBS",
    "MAX_OWNED_FILES",
    "MAX_QUEUE_BYTES",
    "MAX_STDERR_BYTES",
    "MAX_STDOUT_BYTES",
    "MAX_TOTAL_JOBS",
    "POLICY_ENVIRONMENT",
    "POLICY_SCHEMA",
    "POLICY_SCHEMA_VERSION",
    "ProvingResourcePolicyError",
    "ProvingResourcePolicyV1",
    "TIMEOUT_SECONDS",
    "WINDOWS_JOB_MEMORY_CAP_BYTES",
    "derive_policy",
    "policy_file_bytes",
    "policy_from_mapping",
    "read_policy_file",
    "validate_bound_policy",
)
