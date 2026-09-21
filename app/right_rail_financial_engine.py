"""Contained application port for the owner-side financial Engine.

This module is an application boundary, not a second financial owner.  It
reconstructs one authenticated snapshot from the caller's already-active
owner transaction, sends only the bounded BLFIN02 bytes through the existing
Windows containment primitive, and binds the returned BLFRES02 bytes back to
that same snapshot.  It never opens, writes, commits, rolls back, or closes a
database connection and it never reloads release identity from the process
environment.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import math
from pathlib import Path
import sqlite3
import stat
from typing import Final

from app import minimal_clearance_verifier_process as process
from app import right_rail_financial_semantic_adapter as semantic


MAX_ENGINE_JOB_MEMORY_CAP_BYTES: Final[int] = 2_000_000_000
MAX_ENGINE_INPUT_BYTES: Final[int] = semantic.MAX_WIRE_BYTES
ENGINE_ARGUMENTS: Final[tuple[str, ...]] = ("--evaluate",)
_SHA256_BYTES: Final[int] = 32
_SEMANTIC_DIGEST_BYTES: Final[int] = 64


class FinancialEngineError(Exception):
    """Base error for this fail-closed application boundary."""


class FinancialEngineConfigError(FinancialEngineError):
    pass


class FinancialEngineArtifactError(FinancialEngineError):
    pass


class FinancialEngineTransactionError(FinancialEngineError):
    pass


class FinancialEngineSnapshotError(FinancialEngineError):
    pass


class FinancialEngineInputError(FinancialEngineError):
    pass


class FinancialEngineContainmentError(FinancialEngineError):
    pass


class FinancialEngineResultError(FinancialEngineError):
    pass


def _require_release_field(condition: bool, code: str) -> None:
    if not condition:
        raise FinancialEngineConfigError(code)


def _validate_release_values(release: "FinancialEngineRelease") -> None:
    _require_release_field(isinstance(release.executable, Path) and release.executable.is_absolute(), "engine_executable_path")
    _require_release_field(
        isinstance(release.workspace, Path) and release.workspace.is_absolute(),
        "engine_workspace_path",
    )
    _require_release_field(
        type(release.executable_size_bytes) is int and release.executable_size_bytes > 0,
        "engine_executable_size",
    )
    _require_release_field(
        type(release.executable_sha256) is bytes
        and len(release.executable_sha256) == _SHA256_BYTES,
        "engine_executable_hash",
    )
    _require_release_field(
        type(release.timeout_seconds) is float
        and math.isfinite(release.timeout_seconds)
        and 0 < release.timeout_seconds <= 30.0,
        "engine_timeout",
    )
    _require_release_field(
        type(release.input_max_bytes) is int
        and 0 < release.input_max_bytes <= MAX_ENGINE_INPUT_BYTES,
        "engine_input_limit",
    )
    _require_release_field(
        type(release.output_max_bytes) is int
        and 0 < release.output_max_bytes <= semantic.MAX_RESULT_BYTES,
        "engine_output_limit",
    )
    _require_release_field(
        type(release.stderr_max_bytes) is int
        and 0 < release.stderr_max_bytes <= process.MAX_STDERR_BYTES,
        "engine_stderr_limit",
    )
    _require_release_field(
        type(release.job_memory_cap_bytes) is int
        and 0 < release.job_memory_cap_bytes <= MAX_ENGINE_JOB_MEMORY_CAP_BYTES
        and release.job_memory_cap_bytes <= process.ADMISSION_CAP_BYTES,
        "engine_memory_cap",
    )


@dataclass(frozen=True, slots=True)
class FinancialEngineRelease:
    """Explicit immutable trust configuration for one Engine executable."""

    executable: Path
    executable_size_bytes: int
    executable_sha256: bytes
    timeout_seconds: float
    input_max_bytes: int
    output_max_bytes: int
    stderr_max_bytes: int
    workspace: Path
    job_memory_cap_bytes: int

    def __post_init__(self) -> None:
        _validate_release_values(self)


@dataclass(frozen=True, slots=True)
class FinancialEngineExecution:
    """Typed result and minimal exact bindings for one accepted invocation."""

    result: semantic.DecodedLeanResult
    snapshot_digest: bytes
    input_size_bytes: int
    input_sha256: bytes
    output_size_bytes: int
    output_sha256: bytes
    executable_size_bytes: int
    executable_sha256: bytes
    exit_code: int
    job_memory_cap_bytes: int
    peak_job_commit_bytes: int
    cap_enforced: bool
    active_process_limit: int
    child_process_count: int

    def __post_init__(self) -> None:
        if type(self.result) is not semantic.DecodedLeanResult:
            raise FinancialEngineResultError("engine_result_type")
        if type(self.snapshot_digest) is not bytes or len(self.snapshot_digest) != _SEMANTIC_DIGEST_BYTES:
            raise FinancialEngineResultError("engine_snapshot_binding")
        if type(self.input_size_bytes) is not int or self.input_size_bytes <= 0:
            raise FinancialEngineResultError("engine_input_binding")
        if type(self.input_sha256) is not bytes or len(self.input_sha256) != _SHA256_BYTES:
            raise FinancialEngineResultError("engine_input_binding")
        if type(self.output_size_bytes) is not int or self.output_size_bytes <= 0:
            raise FinancialEngineResultError("engine_output_binding")
        if type(self.output_sha256) is not bytes or len(self.output_sha256) != _SHA256_BYTES:
            raise FinancialEngineResultError("engine_output_binding")
        if type(self.executable_size_bytes) is not int or self.executable_size_bytes <= 0:
            raise FinancialEngineResultError("engine_artifact_binding")
        if type(self.executable_sha256) is not bytes or len(self.executable_sha256) != _SHA256_BYTES:
            raise FinancialEngineResultError("engine_artifact_binding")
        if type(self.exit_code) is not int or self.exit_code != 0:
            raise FinancialEngineResultError("engine_exit")
        if type(self.job_memory_cap_bytes) is not int or self.job_memory_cap_bytes <= 0:
            raise FinancialEngineResultError("engine_memory_binding")
        if type(self.peak_job_commit_bytes) is not int or self.peak_job_commit_bytes < 0:
            raise FinancialEngineResultError("engine_memory_binding")
        if self.cap_enforced is not True:
            raise FinancialEngineResultError("engine_containment_binding")
        if type(self.active_process_limit) is not int or self.active_process_limit <= 0:
            raise FinancialEngineResultError("engine_process_binding")
        if type(self.child_process_count) is not int or self.child_process_count < 1:
            raise FinancialEngineResultError("engine_process_binding")


def _capture_artifact_identity(release: FinancialEngineRelease) -> None:
    """Check the configured artifact without transporting its bytes."""

    try:
        before = release.executable.stat()
        if not stat.S_ISREG(before.st_mode) or before.st_size != release.executable_size_bytes:
            raise FinancialEngineArtifactError("engine_artifact_identity")
        digest = hashlib.sha256()
        total = 0
        with release.executable.open("rb") as stream:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                digest.update(chunk)
        after = release.executable.stat()
    except FinancialEngineArtifactError:
        raise
    except (OSError, ValueError):
        raise FinancialEngineArtifactError("engine_artifact_identity") from None
    if (
        total != release.executable_size_bytes
        or after.st_size != release.executable_size_bytes
        or digest.digest() != release.executable_sha256
    ):
        raise FinancialEngineArtifactError("engine_artifact_identity")


def _build_snapshot(
    connection: sqlite3.Connection,
    *,
    obligation_id: str,
    authority_context: semantic.TrustedAuthorityContext,
    evaluation_time_ms: int,
    expected_config: object,
    expected_scope: object,
    expected_mode: str,
    expected_owner_id: str,
    expected_continuity_epoch: int | None,
    max_fact_rows: int,
) -> semantic.LockedSemanticSnapshot:
    try:
        return semantic.build_locked_semantic_snapshot(
            connection,
            obligation_id=obligation_id,
            authority_context=authority_context,
            evaluation_time_ms=evaluation_time_ms,
            expected_config=expected_config,
            expected_scope=expected_scope,
            expected_mode=expected_mode,
            expected_owner_id=expected_owner_id,
            expected_continuity_epoch=expected_continuity_epoch,
            max_fact_rows=max_fact_rows,
        )
    except semantic.SemanticAdapterError:
        raise FinancialEngineSnapshotError("engine_snapshot") from None


def _validate_contained_result(
    result: object,
    release: FinancialEngineRelease,
) -> process.ContainedVerifierResult:
    if type(result) is not process.ContainedVerifierResult:
        raise FinancialEngineContainmentError("engine_containment")
    if (
        type(result.exit_code) is not int
        or result.exit_code != 0
        or result.stderr != b""
        or result.timed_out is not False
        or type(result.cap_bytes) is not int
        or result.cap_bytes != release.job_memory_cap_bytes
        or result.cap_enforced is not True
        or type(result.active_process_limit) is not int
        or result.active_process_limit != process.ACTIVE_PROCESS_LIMIT
        or type(result.child_process_count) is not int
        or result.child_process_count < 1
        or result.process_tree_complete is not True
        or result.measurement_complete is not True
        or result.cleanup_complete is not True
        or type(result.peak_job_commit_bytes) is not int
        or result.peak_job_commit_bytes < 0
        or result.peak_job_commit_bytes > release.job_memory_cap_bytes
        or type(result.stdout) is not bytes
        or type(result.stderr) is not bytes
        or len(result.stdout) > release.output_max_bytes
        or len(result.stderr) > release.stderr_max_bytes
    ):
        raise FinancialEngineContainmentError("engine_containment")
    return result


def evaluate_financial_snapshot(
    connection: sqlite3.Connection,
    *,
    release: FinancialEngineRelease,
    obligation_id: str,
    authority_context: semantic.TrustedAuthorityContext,
    evaluation_time_ms: int,
    expected_config: object,
    expected_scope: object,
    expected_mode: str,
    expected_owner_id: str,
    expected_continuity_epoch: int | None = None,
    max_fact_rows: int = semantic.MAX_FACT_ROWS,
) -> FinancialEngineExecution:
    """Evaluate one owner snapshot through the existing contained stream lane."""

    if type(release) is not FinancialEngineRelease:
        raise FinancialEngineConfigError("engine_release_type")
    _validate_release_values(release)
    _capture_artifact_identity(release)
    if type(connection) is not sqlite3.Connection or not connection.in_transaction:
        raise FinancialEngineTransactionError("engine_transaction_required")

    snapshot = _build_snapshot(
        connection,
        obligation_id=obligation_id,
        authority_context=authority_context,
        evaluation_time_ms=evaluation_time_ms,
        expected_config=expected_config,
        expected_scope=expected_scope,
        expected_mode=expected_mode,
        expected_owner_id=expected_owner_id,
        expected_continuity_epoch=expected_continuity_epoch,
        max_fact_rows=max_fact_rows,
    )
    try:
        input_wire = semantic.encode_blfin02_input(snapshot)
    except semantic.SemanticAdapterError:
        raise FinancialEngineInputError("engine_input") from None
    if (
        type(input_wire) is not bytes
        or not input_wire.startswith(semantic.BLFIN02_MAGIC)
        or not 0 < len(input_wire) <= release.input_max_bytes
    ):
        raise FinancialEngineInputError("engine_input_contract")

    try:
        contained = process.run_contained_verifier_stream(
            release.executable,
            ENGINE_ARGUMENTS,
            input_wire,
            workspace=release.workspace,
            timeout_seconds=release.timeout_seconds,
            job_memory_cap_bytes=release.job_memory_cap_bytes,
            expected_executable_size_bytes=release.executable_size_bytes,
            expected_executable_sha256=release.executable_sha256,
            stdout_cap_bytes=release.output_max_bytes,
            stderr_cap_bytes=release.stderr_max_bytes,
            stdout_ascii=False,
            stderr_ascii=False,
            expected_input_bytes=len(input_wire),
        )
    except Exception:
        raise FinancialEngineContainmentError("engine_containment") from None
    contained = _validate_contained_result(contained, release)

    try:
        result = semantic.decode_blfres02_result(
            contained.stdout,
            expected_snapshot=snapshot,
        )
    except semantic.SemanticAdapterError:
        raise FinancialEngineResultError("engine_result") from None
    return FinancialEngineExecution(
        result=result,
        snapshot_digest=snapshot.snapshot_digest,
        input_size_bytes=len(input_wire),
        input_sha256=hashlib.sha256(input_wire).digest(),
        output_size_bytes=len(contained.stdout),
        output_sha256=hashlib.sha256(contained.stdout).digest(),
        executable_size_bytes=release.executable_size_bytes,
        executable_sha256=release.executable_sha256,
        exit_code=contained.exit_code,
        job_memory_cap_bytes=contained.cap_bytes,
        peak_job_commit_bytes=contained.peak_job_commit_bytes,
        cap_enforced=contained.cap_enforced,
        active_process_limit=contained.active_process_limit,
        child_process_count=contained.child_process_count,
    )


__all__ = (
    "ENGINE_ARGUMENTS",
    "FinancialEngineArtifactError",
    "FinancialEngineContainmentError",
    "FinancialEngineConfigError",
    "FinancialEngineError",
    "FinancialEngineExecution",
    "FinancialEngineInputError",
    "FinancialEngineRelease",
    "FinancialEngineResultError",
    "FinancialEngineSnapshotError",
    "FinancialEngineTransactionError",
    "MAX_ENGINE_INPUT_BYTES",
    "MAX_ENGINE_JOB_MEMORY_CAP_BYTES",
    "evaluate_financial_snapshot",
)
