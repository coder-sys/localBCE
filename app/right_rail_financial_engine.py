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
import json
import math
from pathlib import Path
import sqlite3
import stat
from collections.abc import Mapping
from typing import Any, Final

from app import minimal_clearance_verifier_process as process
from app import right_rail_financial_semantic_adapter as semantic


MAX_ENGINE_JOB_MEMORY_CAP_BYTES: Final[int] = 2_000_000_000
MAX_ENGINE_INPUT_BYTES: Final[int] = semantic.MAX_WIRE_BYTES
ENGINE_ARGUMENTS: Final[tuple[str, ...]] = ("--evaluate",)
CORRECTION_TRANSITION_OPERATION: Final[str] = "RR/FINANCIAL/CORRECTION-TRANSITION/v1"
CORRECTION_TRANSITION_ARGUMENTS: Final[tuple[str, ...]] = ("--apply-correction-transition",)
MAX_CORRECTION_TRANSITION_BYTES: Final[int] = semantic.MAX_WIRE_BYTES
CORRECTION_TRANSITION_ARTIFACT_SIZE_BYTES: Final[int] = 6_245_376
CORRECTION_TRANSITION_ARTIFACT_SHA256: Final[bytes] = bytes.fromhex(
    "E911E8844130155E4615D284D6D29A597B6E441DC45101D411EE8422EAE684B9"
)
CORRECTION_TRANSITION_REQUEST_VECTOR_SHA256: Final[bytes] = bytes.fromhex(
    "13F832E80B93CC55D17ADD29470A2CD789CFCED1CBCF5A055FCBA3ECB927B537"
)
CORRECTION_TRANSITION_RESULT_VECTOR_SHA256: Final[bytes] = bytes.fromhex(
    "312AB06C76D6F6F2F40CF93F9EE37DA328161B733FE7D5567E0694B85D3AE18E"
)
_SHA256_BYTES: Final[int] = 32
_SEMANTIC_DIGEST_BYTES: Final[int] = 64
_MAX_SQLITE_INTEGER: Final[int] = 2**63 - 1


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


class FinancialEngineTransitionUnavailable(FinancialEngineError):
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


def _validate_correction_release_values(
    release: "FinancialCorrectionTransitionRelease",
) -> None:
    _require_release_field(
        isinstance(release.executable, Path) and release.executable.is_absolute(),
        "engine_correction_executable_path",
    )
    _require_release_field(
        isinstance(release.workspace, Path) and release.workspace.is_absolute(),
        "engine_correction_workspace_path",
    )
    _require_release_field(
        type(release.executable_size_bytes) is int and release.executable_size_bytes > 0,
        "engine_correction_executable_size",
    )
    _require_release_field(
        type(release.executable_sha256) is bytes
        and len(release.executable_sha256) == _SHA256_BYTES,
        "engine_correction_executable_hash",
    )
    _require_release_field(
        type(release.request_vector_sha256) is bytes
        and len(release.request_vector_sha256) == _SHA256_BYTES,
        "engine_correction_request_vector_hash",
    )
    _require_release_field(
        type(release.result_vector_sha256) is bytes
        and len(release.result_vector_sha256) == _SHA256_BYTES,
        "engine_correction_result_vector_hash",
    )
    _require_release_field(
        type(release.timeout_seconds) is float
        and math.isfinite(release.timeout_seconds)
        and 0 < release.timeout_seconds <= 30.0,
        "engine_correction_timeout",
    )
    _require_release_field(
        type(release.input_max_bytes) is int
        and 0 < release.input_max_bytes <= MAX_CORRECTION_TRANSITION_BYTES,
        "engine_correction_input_limit",
    )
    _require_release_field(
        type(release.output_max_bytes) is int
        and 0 < release.output_max_bytes <= MAX_CORRECTION_TRANSITION_BYTES,
        "engine_correction_output_limit",
    )
    _require_release_field(
        type(release.stderr_max_bytes) is int
        and 0 < release.stderr_max_bytes <= process.MAX_STDERR_BYTES,
        "engine_correction_stderr_limit",
    )
    _require_release_field(
        type(release.job_memory_cap_bytes) is int
        and 0 < release.job_memory_cap_bytes <= MAX_ENGINE_JOB_MEMORY_CAP_BYTES
        and release.job_memory_cap_bytes <= process.ADMISSION_CAP_BYTES,
        "engine_correction_memory_cap",
    )
    _require_release_field(
        type(release.operation_contract) is str
        and release.operation_contract == CORRECTION_TRANSITION_OPERATION
        and type(release.operation_version) is int
        and release.operation_version == 1,
        "engine_correction_operation_identity",
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
class FinancialCorrectionTransitionRelease:
    """Explicit release identity for the additive correction transition."""

    executable: Path
    executable_size_bytes: int
    executable_sha256: bytes
    request_vector_sha256: bytes
    result_vector_sha256: bytes
    timeout_seconds: float
    input_max_bytes: int
    output_max_bytes: int
    stderr_max_bytes: int
    workspace: Path
    job_memory_cap_bytes: int
    operation_contract: str = CORRECTION_TRANSITION_OPERATION
    operation_version: int = 1

    def __post_init__(self) -> None:
        _validate_correction_release_values(self)


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


@dataclass(frozen=True, slots=True)
class FinancialCorrectionTransitionExecution:
    """One contained and artifact-bound correction transition response."""

    result: dict[str, Any]
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
        if type(self.result) is not dict or self.result.get("status") not in {"ACCEPTED", "DUPLICATE", "REJECTED"}:
            raise FinancialEngineResultError("engine_correction_result_type")
        for value, label in (
            (self.input_sha256, "engine_correction_input_binding"),
            (self.output_sha256, "engine_correction_output_binding"),
            (self.executable_sha256, "engine_correction_artifact_binding"),
        ):
            if type(value) is not bytes or len(value) != _SHA256_BYTES:
                raise FinancialEngineResultError(label)
        for value, label in (
            (self.input_size_bytes, "engine_correction_input_binding"),
            (self.output_size_bytes, "engine_correction_output_binding"),
            (self.executable_size_bytes, "engine_correction_artifact_binding"),
            (self.job_memory_cap_bytes, "engine_correction_memory_binding"),
            (self.active_process_limit, "engine_correction_process_binding"),
            (self.child_process_count, "engine_correction_process_binding"),
        ):
            if type(value) is not int or value <= 0:
                raise FinancialEngineResultError(label)
        if (
            type(self.exit_code) is not int
            or self.exit_code != 0
            or type(self.peak_job_commit_bytes) is not int
            or self.peak_job_commit_bytes < 0
            or self.peak_job_commit_bytes > self.job_memory_cap_bytes
            or self.cap_enforced is not True
        ):
            raise FinancialEngineResultError("engine_correction_containment_binding")


def _capture_artifact_identity(
    release: FinancialEngineRelease | FinancialCorrectionTransitionRelease,
) -> None:
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
    release: FinancialEngineRelease | FinancialCorrectionTransitionRelease,
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


def _transition_digest(value: object, label: str) -> bytes:
    try:
        if type(value) is bytes:
            return semantic._wire_digest(value, label)
        return semantic._wire_hex_digest(value, label)
    except semantic.SemanticAdapterError:
        raise FinancialEngineInputError(label) from None


def _transition_id(value: object, label: str) -> str:
    try:
        return semantic._wire_id(value, label)
    except semantic.SemanticAdapterError:
        raise FinancialEngineInputError(label) from None


def _transition_role(value: object, label: str) -> str:
    try:
        return semantic._wire_role(value, label)
    except semantic.SemanticAdapterError:
        raise FinancialEngineInputError(label) from None


def _transition_u64(writer: object, value: object, label: str) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_SQLITE_INTEGER:
        raise FinancialEngineInputError(label)
    try:
        writer.nat(value, label)  # type: ignore[attr-defined]
    except semantic.SemanticAdapterError:
        raise FinancialEngineInputError(label) from None
    return value


def _transition_write_identifier(writer: object, value: object, label: str) -> str:
    text = _transition_id(value, label)
    try:
        writer.identifier(text, label)  # type: ignore[attr-defined]
    except semantic.SemanticAdapterError:
        raise FinancialEngineInputError(label) from None
    return text


def _transition_write_role(writer: object, value: object, label: str) -> str:
    text = _transition_role(value, label)
    try:
        writer.role(text, label)  # type: ignore[attr-defined]
    except semantic.SemanticAdapterError:
        raise FinancialEngineInputError(label) from None
    return text


def _transition_write_digest(writer: object, value: object, label: str) -> bytes:
    digest = _transition_digest(value, label)
    try:
        writer.digest(digest, label)  # type: ignore[attr-defined]
    except semantic.SemanticAdapterError:
        raise FinancialEngineInputError(label) from None
    return digest


def _transition_write_text(writer: object, value: object, label: str, *, max_bytes: int = 512) -> str:
    if type(value) is not str:
        raise FinancialEngineInputError(label)
    try:
        text = semantic._wire_text(value, label, max_bytes=max_bytes)
        writer.string(text, label, max_bytes=max_bytes)  # type: ignore[attr-defined]
        return text
    except semantic.SemanticAdapterError:
        raise FinancialEngineInputError(label) from None


def _write_correction_action_lookup(writer: object, lookup: Mapping[str, Any]) -> None:
    kind = lookup.get("kind")
    if kind == "absent":
        writer.byte(1, "action_lookup")  # type: ignore[attr-defined]
        return
    if kind == "conflicting":
        writer.byte(3, "action_lookup")  # type: ignore[attr-defined]
        return
    if kind != "existing" or type(lookup.get("identity")) is not dict:
        raise FinancialEngineInputError("engine_correction_action_lookup")
    identity = lookup["identity"]
    writer.byte(2, "action_lookup")  # type: ignore[attr-defined]
    for key in (
        "action_id", "action_obligation_id", "determination_id",
        "determination_obligation_id", "action_kind", "claim_id", "actor_id",
    ):
        _transition_write_identifier(writer, identity.get(key), f"action_lookup_{key}")
    _transition_write_role(writer, identity.get("actor_role"), "action_lookup_actor_role")
    _transition_write_identifier(writer, identity.get("authority_id"), "action_lookup_authority_id")
    _transition_u64(writer, identity.get("authority_epoch"), "action_lookup_authority_epoch")
    _transition_write_digest(writer, identity.get("authority_digest"), "action_lookup_authority_digest")
    if identity.get("decision") != "OFFSET_REJECTED_CORRECTION_AUTHORIZED":
        raise FinancialEngineInputError("action_lookup_decision")
    writer.byte(2, "action_lookup_decision")  # type: ignore[attr-defined]
    _transition_write_identifier(writer, identity.get("input_evaluation_id"), "action_lookup_evaluation_id")
    _transition_write_digest(writer, identity.get("input_evaluation_result_digest"), "action_lookup_evaluation_digest")
    _transition_u64(writer, identity.get("expected_revision"), "action_lookup_expected_revision")
    _transition_u64(writer, identity.get("decided_at_ms"), "action_lookup_decided_at")


def _write_correction_query_observation(writer: object, observation: Mapping[str, Any], label: str) -> None:
    predicates = {"ACTION_ID": 1, "DETERMINATION_ID": 2, "EVALUATION_CONSUMED": 3}
    predicate = observation.get("predicate")
    if predicate not in predicates:
        raise FinancialEngineInputError(f"{label}_predicate")
    writer.byte(predicates[predicate], f"{label}_predicate")  # type: ignore[attr-defined]
    _transition_write_identifier(writer, observation.get("subject"), f"{label}_subject")
    complete = observation.get("complete")
    if type(complete) is not bool:
        raise FinancialEngineInputError(f"{label}_complete")
    writer.boolean(complete, f"{label}_complete")  # type: ignore[attr-defined]
    match_count = observation.get("match_count")
    if type(match_count) is not int or match_count not in (0, 1):
        raise FinancialEngineInputError(f"{label}_match_count")
    _transition_u64(writer, match_count, f"{label}_match_count")
    result_identity = observation.get("result_identity")
    if result_identity is None:
        writer.byte(0, f"{label}_result_identity")  # type: ignore[attr-defined]
    else:
        writer.byte(1, f"{label}_result_identity")  # type: ignore[attr-defined]
        _transition_write_identifier(writer, result_identity, f"{label}_result_identity")
    _transition_u64(writer, observation.get("version_sequence"), f"{label}_version_sequence")
    _transition_write_digest(writer, observation.get("version_head"), f"{label}_version_head")


def _encode_correction_evaluation_receipt(receipt: Mapping[str, Any]) -> bytes:
    writer = semantic._WireWriter()
    _transition_write_text(writer, receipt.get("contract_version"), "receipt_contract")
    scope = receipt.get("scope")
    if type(scope) is not dict:
        raise FinancialEngineInputError("receipt_scope")
    for field in ("state_id", "deployment_id", "program_id", "period_id"):
        _transition_write_identifier(writer, scope.get(field), f"receipt_scope_{field}")
    _transition_write_text(writer, scope.get("currency"), "receipt_scope_currency", max_bytes=128)
    pack = receipt.get("control_pack")
    if type(pack) is not dict:
        raise FinancialEngineInputError("receipt_control_pack")
    _transition_write_identifier(writer, pack.get("pack_id"), "receipt_pack_id")
    _transition_u64(writer, pack.get("version"), "receipt_pack_version")
    _transition_write_digest(writer, pack.get("digest"), "receipt_pack_digest")
    bindings = receipt.get("evidence_bindings")
    if type(bindings) is not list or len(bindings) > semantic.MAX_WIRE_LIST:
        raise FinancialEngineInputError("receipt_evidence_bindings")
    writer.count(len(bindings), "receipt_evidence_bindings")
    previous = ""
    for index, binding in enumerate(bindings):
        if type(binding) is not dict:
            raise FinancialEngineInputError("receipt_evidence_binding")
        evidence_id = _transition_write_identifier(writer, binding.get("evidence_id"), f"receipt_evidence_{index}_id")
        if index and evidence_id <= previous:
            raise FinancialEngineInputError("receipt_evidence_order")
        previous = evidence_id
        _transition_write_digest(writer, binding.get("record_digest"), f"receipt_evidence_{index}_digest")
    snapshot_digest = _transition_digest(receipt.get("input_snapshot_digest"), "receipt_snapshot_digest")
    writer.byte(1, "receipt_snapshot_digest_tag")
    writer.digest(snapshot_digest, "receipt_snapshot_digest")
    authority = receipt.get("authority")
    if type(authority) is not dict:
        raise FinancialEngineInputError("receipt_authority")
    _transition_u64(writer, authority.get("epoch"), "receipt_authority_epoch")
    _transition_write_digest(writer, authority.get("digest"), "receipt_authority_digest")
    for field in ("evaluation_id", "obligation_id"):
        _transition_write_identifier(writer, receipt.get(field), f"receipt_{field}")
    _transition_u64(writer, receipt.get("revision"), "receipt_revision")
    _transition_u64(writer, receipt.get("rule_version"), "receipt_rule_version")
    evidence_ids = receipt.get("evidence_ids")
    if type(evidence_ids) is not list or len(evidence_ids) > semantic.MAX_WIRE_LIST:
        raise FinancialEngineInputError("receipt_evidence_ids")
    writer.count(len(evidence_ids), "receipt_evidence_ids")
    previous = ""
    for index, evidence_id in enumerate(evidence_ids):
        encoded = _transition_write_identifier(writer, evidence_id, f"receipt_evidence_id_{index}")
        if index and encoded <= previous:
            raise FinancialEngineInputError("receipt_evidence_order")
        previous = encoded
    _transition_write_identifier(writer, receipt.get("authority_id"), "receipt_result_authority_id")
    _transition_u64(writer, receipt.get("evaluated_at_ms"), "receipt_evaluated_at")
    for field in (
        "owed_cents", "claimed_adjustment_cents", "lawful_adjustment_cents",
        "received_cash_cents", "shortfall_cents", "overage_cents",
    ):
        _transition_u64(writer, receipt.get(field), f"receipt_{field}")
    for field in ("cash_satisfied", "amount_satisfied", "timely", "reporting_complete"):
        value = receipt.get(field)
        if type(value) is not int or value not in (0, 1):
            raise FinancialEngineInputError(f"receipt_{field}")
        writer.boolean(bool(value), f"receipt_{field}")
    for field in ("verification_status", "case_status", "delivery_status"):
        _transition_write_identifier(writer, receipt.get(field), f"receipt_{field}")
    result_digest = _transition_digest(receipt.get("result_digest"), "receipt_result_digest")
    evaluation_result_digest = _transition_digest(
        receipt.get("evaluation_result_digest"), "receipt_evaluation_result_digest"
    )
    if result_digest != evaluation_result_digest:
        raise FinancialEngineInputError("receipt_result_digest_binding")
    writer.digest(result_digest, "receipt_result_digest")
    _transition_write_digest(writer, receipt.get("receipt_digest"), "receipt_digest")
    writer.digest(evaluation_result_digest, "receipt_evaluation_result_digest")
    return writer.finish(label="engine_correction_receipt_size")


def _correction_input_bytes(
    snapshot: semantic.LockedSemanticSnapshot,
    *,
    expected_revision: int,
    action_lookup_kind: str,
) -> bytes:
    if type(snapshot) is not semantic.LockedSemanticSnapshot:
        raise FinancialEngineInputError("engine_correction_snapshot_type")
    try:
        body = snapshot.data
        if action_lookup_kind == "absent":
            if expected_revision < 1:
                raise FinancialEngineInputError("engine_correction_expected_revision")
            current_evaluation = body.get("current_evaluation")
            receipt = current_evaluation.get("receipt") if type(current_evaluation) is dict else None
            if type(receipt) is not dict:
                raise FinancialEngineInputError("engine_correction_receipt_missing")
            receipt_time = receipt.get("evaluated_at_ms")
            if type(receipt_time) is not int or receipt_time < 0:
                raise FinancialEngineInputError("engine_correction_receipt_time")
            body["pre_evaluation"]["revision"] = expected_revision - 1
            body["evaluation_time_ms"] = receipt_time
        body.pop("snapshot_digest", None)
        rebound = semantic._make_snapshot(body)
        payload = semantic.encode_blfin02_input(rebound)
    except semantic.SemanticAdapterError:
        raise FinancialEngineInputError("engine_correction_snapshot") from None
    if type(payload) is not bytes or not payload.startswith(semantic.BLFIN02_MAGIC):
        raise FinancialEngineInputError("engine_correction_input_contract")
    return payload


def encode_correction_transition_request(
    *,
    snapshot: semantic.LockedSemanticSnapshot,
    command: Mapping[str, Any],
    action_lookup: Mapping[str, Any],
    query_observations: Mapping[str, Mapping[str, Any]],
    current_event_sequence: int,
    previous_history_head: bytes,
) -> bytes:
    """Encode the candidate BLFCMD01 request from one locked Owner snapshot."""

    if type(command) is not dict or type(action_lookup) is not dict or type(query_observations) is not dict:
        raise FinancialEngineInputError("engine_correction_request_shape")
    expected_revision = command.get("expected_revision")
    if type(expected_revision) is not int or not 0 <= expected_revision <= 10_000:
        raise FinancialEngineInputError("engine_correction_expected_revision")
    action_lookup_kind = action_lookup.get("kind")
    current_input = _correction_input_bytes(
        snapshot,
        expected_revision=expected_revision,
        action_lookup_kind=action_lookup_kind,
    )
    data = snapshot.data
    current_receipt = data.get("current_evaluation", {}).get("receipt")
    if type(current_receipt) is not dict:
        raise FinancialEngineInputError("engine_correction_receipt_missing")
    receipt_bytes = _encode_correction_evaluation_receipt(current_receipt)
    if len(current_input) > MAX_CORRECTION_TRANSITION_BYTES or len(receipt_bytes) > MAX_CORRECTION_TRANSITION_BYTES:
        raise FinancialEngineInputError("engine_correction_request_limit")

    writer = semantic._WireWriter()
    writer.raw(b"BLFCMD01", "engine_correction_magic")
    writer.raw((1).to_bytes(2, "big"), "engine_correction_version")
    _transition_write_text(writer, CORRECTION_TRANSITION_OPERATION, "engine_correction_contract")
    for field in ("item_id", "claim_id", "action_id", "actor_id"):
        _transition_write_identifier(writer, command.get(field), f"engine_correction_{field}")
    _transition_write_role(writer, command.get("actor_role"), "engine_correction_actor_role")
    _transition_write_identifier(writer, command.get("current_authority_id"), "engine_correction_authority_id")
    _transition_u64(writer, command.get("current_authority_epoch"), "engine_correction_authority_epoch")
    _transition_write_digest(writer, command.get("current_authority_digest"), "engine_correction_authority_digest")
    _transition_u64(writer, expected_revision, "engine_correction_expected_revision")
    _transition_write_identifier(writer, command.get("evaluation_id"), "engine_correction_evaluation_id")
    _transition_write_digest(writer, command.get("evaluation_result_digest"), "engine_correction_evaluation_digest")
    _transition_u64(writer, command.get("decision_at_ms"), "engine_correction_decision_at")
    _transition_u64(writer, command.get("owner_now_ms"), "engine_correction_owner_now")
    _write_correction_action_lookup(writer, action_lookup)
    for key, label in (
        ("action_id", "action_query"),
        ("determination_id", "determination_query"),
        ("evaluation_consumed", "evaluation_consumed_query"),
    ):
        observation = query_observations.get(key)
        if type(observation) is not dict:
            raise FinancialEngineInputError(f"engine_correction_{label}")
        _write_correction_query_observation(writer, observation, label)
    _transition_u64(writer, current_event_sequence, "engine_correction_event_sequence")
    _transition_write_digest(writer, previous_history_head, "engine_correction_history_head")
    writer.raw(len(current_input).to_bytes(4, "big"), "engine_correction_input_length")
    writer.raw(current_input, "engine_correction_input")
    writer.raw(len(receipt_bytes).to_bytes(4, "big"), "engine_correction_receipt_length")
    writer.raw(receipt_bytes, "engine_correction_receipt")
    try:
        encoded = writer.finish(label="engine_correction_request_size")
    except semantic.SemanticAdapterError:
        raise FinancialEngineInputError("engine_correction_request_size") from None
    if not encoded.startswith(b"BLFCMD01") or len(encoded) > MAX_CORRECTION_TRANSITION_BYTES:
        raise FinancialEngineInputError("engine_correction_request_contract")
    return encoded


def require_correction_transition_v1(release: object | None) -> FinancialCorrectionTransitionRelease:
    """Require an immutable v1 release bound to its artifact and exact vectors."""

    if release is None:
        raise FinancialEngineTransitionUnavailable("engine_correction_transition_release_required")
    if type(release) is not FinancialCorrectionTransitionRelease:
        raise FinancialEngineConfigError("engine_correction_transition_release_type")
    _validate_correction_release_values(release)
    if (
        type(CORRECTION_TRANSITION_ARTIFACT_SIZE_BYTES) is not int
        or CORRECTION_TRANSITION_ARTIFACT_SIZE_BYTES <= 0
        or type(CORRECTION_TRANSITION_ARTIFACT_SHA256) is not bytes
        or len(CORRECTION_TRANSITION_ARTIFACT_SHA256) != _SHA256_BYTES
        or type(CORRECTION_TRANSITION_REQUEST_VECTOR_SHA256) is not bytes
        or len(CORRECTION_TRANSITION_REQUEST_VECTOR_SHA256) != _SHA256_BYTES
        or type(CORRECTION_TRANSITION_RESULT_VECTOR_SHA256) is not bytes
        or len(CORRECTION_TRANSITION_RESULT_VECTOR_SHA256) != _SHA256_BYTES
    ):
        raise FinancialEngineTransitionUnavailable("engine_correction_transition_evidence_unavailable")
    if (
        release.executable_size_bytes != CORRECTION_TRANSITION_ARTIFACT_SIZE_BYTES
        or release.executable_sha256 != CORRECTION_TRANSITION_ARTIFACT_SHA256
    ):
        raise FinancialEngineArtifactError("engine_correction_transition_artifact_identity")
    if release.request_vector_sha256 != CORRECTION_TRANSITION_REQUEST_VECTOR_SHA256:
        raise FinancialEngineArtifactError("engine_correction_transition_request_vector_identity")
    if release.result_vector_sha256 != CORRECTION_TRANSITION_RESULT_VECTOR_SHA256:
        raise FinancialEngineArtifactError("engine_correction_transition_result_vector_identity")
    return release


def _read_transition_nat(reader: object, label: str) -> int:
    value = reader.nat(label)  # type: ignore[attr-defined]
    if value > _MAX_SQLITE_INTEGER:
        raise FinancialEngineResultError(label)
    return value


def _read_transition_identifier(reader: object, label: str) -> str:
    try:
        return reader.identifier(label)  # type: ignore[attr-defined]
    except semantic.SemanticAdapterError:
        raise FinancialEngineResultError(label) from None


def _read_transition_role(reader: object, label: str) -> str:
    try:
        return reader.role(label)  # type: ignore[attr-defined]
    except semantic.SemanticAdapterError:
        raise FinancialEngineResultError(label) from None


def _read_transition_text(reader: object, label: str, *, max_bytes: int = 512) -> str:
    try:
        return reader.string(label, max_bytes=max_bytes)  # type: ignore[attr-defined]
    except semantic.SemanticAdapterError:
        raise FinancialEngineResultError(label) from None


def _read_optional_transition_identifier(reader: object, label: str) -> str | None:
    try:
        return reader.option_identifier(label)  # type: ignore[attr-defined]
    except semantic.SemanticAdapterError:
        raise FinancialEngineResultError(label) from None


def _read_optional_transition_nat(reader: object, label: str) -> int | None:
    try:
        value = reader.option_nat(label)  # type: ignore[attr-defined]
    except semantic.SemanticAdapterError:
        raise FinancialEngineResultError(label) from None
    if value is not None and value > _MAX_SQLITE_INTEGER:
        raise FinancialEngineResultError(label)
    return value


def _read_optional_transition_text(reader: object, label: str) -> str | None:
    tag = reader.byte(f"{label}_tag")  # type: ignore[attr-defined]
    if tag == 0:
        return None
    if tag != 1:
        raise FinancialEngineResultError(label)
    return _read_transition_text(reader, label)


def _read_correction_query_observation(reader: object, label: str) -> dict[str, Any]:
    predicates = {1: "ACTION_ID", 2: "DETERMINATION_ID", 3: "EVALUATION_CONSUMED"}
    predicate_tag = reader.byte(f"{label}_predicate")  # type: ignore[attr-defined]
    predicate = predicates.get(predicate_tag)
    if predicate is None:
        raise FinancialEngineResultError(f"{label}_predicate")
    subject = _read_transition_identifier(reader, f"{label}_subject")
    complete = reader.boolean(f"{label}_complete")  # type: ignore[attr-defined]
    match_count = _read_transition_nat(reader, f"{label}_match_count")
    if match_count > 1:
        raise FinancialEngineResultError(f"{label}_match_count")
    result_identity = _read_optional_transition_identifier(reader, f"{label}_result_identity")
    if (match_count == 0) != (result_identity is None):
        raise FinancialEngineResultError(f"{label}_result_identity")
    version_sequence = _read_transition_nat(reader, f"{label}_version_sequence")
    version_head = reader.digest(f"{label}_version_head")  # type: ignore[attr-defined]
    return {
        "predicate": predicate,
        "subject": subject,
        "complete": complete,
        "match_count": match_count,
        "result_identity": result_identity,
        "version_sequence": version_sequence,
        "version_head": version_head,
    }


def _read_correction_query_observations(reader: object) -> dict[str, dict[str, Any]]:
    return {
        "action_id": _read_correction_query_observation(reader, "action_query"),
        "determination_id": _read_correction_query_observation(reader, "determination_query"),
        "evaluation_consumed": _read_correction_query_observation(reader, "evaluation_consumed_query"),
    }


def _read_correction_claim(reader: object, label: str = "claim") -> dict[str, Any]:
    status_tags = {1: "CLAIMED", 2: "AUTHORIZED", 3: "REJECTED"}
    claim = {
        "claim_id": _read_transition_identifier(reader, f"{label}_id"),
        "obligation_id": _read_transition_identifier(reader, f"{label}_obligation"),
        "evidence_id": _read_transition_identifier(reader, f"{label}_evidence"),
        "amount_cents": _read_transition_nat(reader, f"{label}_amount"),
        "owner_role": _read_transition_role(reader, f"{label}_owner_role"),
        "deadline_at_ms": _read_transition_nat(reader, f"{label}_deadline"),
    }
    status = status_tags.get(reader.byte(f"{label}_status"))  # type: ignore[attr-defined]
    if status is None:
        raise FinancialEngineResultError(f"{label}_status")
    claim["status"] = status
    return claim


def _read_correction_evidence_binding(reader: object, label: str) -> dict[str, Any]:
    return {
        "evidence_id": _read_transition_identifier(reader, f"{label}_id"),
        "record_digest": reader.digest(f"{label}_digest"),  # type: ignore[attr-defined]
    }


def _read_correction_dependency_facts(reader: object) -> dict[str, Any]:
    artifact_contract = _read_transition_text(reader, "dependency_artifact_contract")
    artifact_version = _read_transition_nat(reader, "dependency_artifact_version")
    authority_id = _read_transition_identifier(reader, "dependency_authority_id")
    authority_epoch = _read_transition_nat(reader, "dependency_authority_epoch")
    authority_digest = reader.digest("dependency_authority_digest")  # type: ignore[attr-defined]
    control_pack_id = _read_transition_identifier(reader, "dependency_pack_id")
    control_pack_version = _read_transition_nat(reader, "dependency_pack_version")
    control_pack_digest = reader.digest("dependency_pack_digest")  # type: ignore[attr-defined]
    input_evaluation_id = _read_transition_identifier(reader, "dependency_evaluation_id")
    input_evaluation_result_digest = reader.digest("dependency_evaluation_digest")  # type: ignore[attr-defined]
    input_evaluation_revision = _read_transition_nat(reader, "dependency_evaluation_revision")
    input_evaluation_evaluated_at_ms = _read_transition_nat(reader, "dependency_evaluation_time")
    input_evaluation_snapshot_digest = reader.digest("dependency_snapshot_digest")  # type: ignore[attr-defined]
    decision_at_ms = _read_transition_nat(reader, "dependency_decision_time")
    owner_now_ms = _read_transition_nat(reader, "dependency_owner_now")
    claim_before = _read_correction_claim(reader, "dependency_claim")
    supporting_evidence = reader.list(  # type: ignore[attr-defined]
        "dependency_supporting_evidence",
        lambda label: _read_correction_evidence_binding(reader, label),
    )
    if len(supporting_evidence) > 10_000:
        raise FinancialEngineResultError("dependency_supporting_evidence_limit")
    observations = _read_correction_query_observations(reader)
    current_event_sequence = _read_transition_nat(reader, "dependency_event_sequence")
    previous_history_head = reader.digest("dependency_history_head")  # type: ignore[attr-defined]
    if current_event_sequence > 10_000:
        raise FinancialEngineResultError("dependency_event_sequence")
    return {
        "artifact_contract": artifact_contract,
        "artifact_version": artifact_version,
        "authority_id": authority_id,
        "authority_epoch": authority_epoch,
        "authority_digest": authority_digest,
        "control_pack_id": control_pack_id,
        "control_pack_version": control_pack_version,
        "control_pack_digest": control_pack_digest,
        "input_evaluation_id": input_evaluation_id,
        "input_evaluation_result_digest": input_evaluation_result_digest,
        "input_evaluation_revision": input_evaluation_revision,
        "input_evaluation_evaluated_at_ms": input_evaluation_evaluated_at_ms,
        "input_evaluation_snapshot_digest": input_evaluation_snapshot_digest,
        "decision_at_ms": decision_at_ms,
        "owner_now_ms": owner_now_ms,
        "claim_before": claim_before,
        "supporting_evidence": supporting_evidence,
        "query_observations": observations,
        "current_event_sequence": current_event_sequence,
        "previous_history_head": previous_history_head,
    }


def _read_correction_followups(reader: object) -> dict[str, Any]:
    action_id = _read_transition_identifier(reader, "followup_action_id")
    outbox_action_id = _read_transition_identifier(reader, "followup_outbox_action_id")
    case_id = _read_transition_identifier(reader, "followup_case_id")
    resulting_evaluation_id = _read_transition_identifier(reader, "followup_evaluation_id")
    event_sequence = _read_transition_nat(reader, "followup_event_sequence")
    return {
        "action_id": action_id,
        "outbox_action_id": outbox_action_id,
        "case_id": case_id,
        "resulting_evaluation_id": resulting_evaluation_id,
        "event_sequence": event_sequence,
    }


def _read_correction_determination(reader: object) -> dict[str, Any]:
    decision_tags = {1: "OFFSET_AUTHORIZED", 2: "OFFSET_REJECTED_CORRECTION_AUTHORIZED"}
    determination = {
        "determination_id": _read_transition_identifier(reader, "determination_id"),
        "obligation_id": _read_transition_identifier(reader, "determination_obligation_id"),
        "claim_id": _read_transition_identifier(reader, "determination_claim_id"),
        "actor_id": _read_transition_identifier(reader, "determination_actor_id"),
        "actor_role": _read_transition_role(reader, "determination_actor_role"),
        "authority_id": _read_transition_identifier(reader, "determination_authority_id"),
        "authority_epoch": _read_transition_nat(reader, "determination_authority_epoch"),
        "authority_digest": reader.digest("determination_authority_digest"),  # type: ignore[attr-defined]
    }
    decision = decision_tags.get(reader.byte("determination_decision"))  # type: ignore[attr-defined]
    if decision is None:
        raise FinancialEngineResultError("determination_decision")
    determination["decision"] = decision
    determination["amount_cents"] = _read_transition_nat(reader, "determination_amount")
    determination["supporting_evidence_ids"] = reader.list(  # type: ignore[attr-defined]
        "determination_supporting_evidence",
        lambda label: _read_transition_identifier(reader, label),
    )
    determination["expected_revision"] = _read_transition_nat(reader, "determination_expected_revision")
    determination["resulting_revision"] = _read_transition_nat(reader, "determination_resulting_revision")
    determination["decided_at_ms"] = _read_transition_nat(reader, "determination_decided_at")
    return determination


def _read_correction_action(reader: object) -> dict[str, Any]:
    status_tags = {1: "READY", 2: "ACKNOWLEDGED", 3: "CANCELLED"}
    action_id = _read_transition_identifier(reader, "action_id")
    obligation_id = _read_transition_identifier(reader, "action_obligation_id")
    determination_id = _read_optional_transition_identifier(reader, "action_determination_id")
    kind = _read_transition_identifier(reader, "action_kind")
    amount_cents = _read_transition_nat(reader, "action_amount")
    currency = _read_transition_text(reader, "action_currency", max_bytes=128)
    revision = _read_transition_nat(reader, "action_revision")
    status = status_tags.get(reader.byte("action_status"))  # type: ignore[attr-defined]
    if status is None:
        raise FinancialEngineResultError("action_status")
    payload_digest = reader.digest("action_payload_digest")  # type: ignore[attr-defined]
    created_at_ms = _read_transition_nat(reader, "action_created_at")
    return {
        "action_id": action_id,
        "obligation_id": obligation_id,
        "determination_id": determination_id,
        "kind": kind,
        "amount_cents": amount_cents,
        "currency": currency,
        "revision": revision,
        "status": status,
        "payload_digest": payload_digest,
        "created_at_ms": created_at_ms,
    }


def _read_correction_case(reader: object) -> dict[str, Any]:
    status_tags = {1: "OPEN", 2: "AUTHORIZED", 3: "CORRECTION_REQUIRED", 4: "ACTIONED", 5: "RESOLVED"}
    case_record = {
        "case_id": _read_transition_identifier(reader, "case_id"),
        "obligation_id": _read_transition_identifier(reader, "case_obligation_id"),
        "reason": _read_transition_identifier(reader, "case_reason"),
        "next_action_owner": _read_transition_role(reader, "case_next_action_owner"),
        "due_at_ms": _read_transition_nat(reader, "case_due_at"),
    }
    status = status_tags.get(reader.byte("case_status"))  # type: ignore[attr-defined]
    if status is None:
        raise FinancialEngineResultError("case_status")
    case_record["status"] = status
    case_record["updated_at_ms"] = _read_transition_nat(reader, "case_updated_at")
    return case_record


def _decode_correction_financial_result(payload: bytes) -> semantic.DecodedLeanResult:
    reader = semantic._WireReader(payload, max_bytes=MAX_CORRECTION_TRANSITION_BYTES)
    if reader.take(8, "correction_financial_result_magic") != semantic.BLFRES02_MAGIC:
        raise FinancialEngineResultError("engine_correction_financial_result_magic")
    context = {
        "owner_id": _read_transition_identifier(reader, "result_owner_id"),
        "mode": semantic._read_tag(reader, semantic._MODE_TAGS, "result_mode"),
        "provenance": semantic._read_tag(reader, semantic._PROVENANCE_TAGS, "result_provenance"),
        "state_id": _read_transition_identifier(reader, "result_state_id"),
        "deployment_id": _read_transition_identifier(reader, "result_deployment_id"),
        "program_id": _read_transition_identifier(reader, "result_program_id"),
        "period_id": _read_transition_identifier(reader, "result_period_id"),
        "population_id": _read_transition_identifier(reader, "result_population_id"),
        "item_id": _read_transition_identifier(reader, "result_item_id"),
        "obligation_id": _read_transition_identifier(reader, "result_obligation_id"),
        "currency": _read_transition_text(reader, "result_currency", max_bytes=128),
    }
    result = semantic.DecodedLeanResult(
        **context,
        authority_id=_read_transition_identifier(reader, "result_authority_id"),
        authority_epoch=_read_transition_nat(reader, "result_authority_epoch"),
        authority_digest=reader.digest("result_authority_digest"),  # type: ignore[attr-defined]
        pack_id=_read_transition_identifier(reader, "result_pack_id"),
        pack_digest=reader.digest("result_pack_digest"),  # type: ignore[attr-defined]
        before_revision=_read_transition_nat(reader, "result_before_revision"),
        after_revision=_read_transition_nat(reader, "result_after_revision"),
        evaluated_at_ms=_read_transition_nat(reader, "result_evaluated_at"),
        rule_version=_read_transition_nat(reader, "result_rule_version"),
        evidence_ids=tuple(
            reader.list("result_evidence_ids", lambda label: _read_transition_identifier(reader, label))  # type: ignore[attr-defined]
        ),
        completion_at_ms=_read_optional_transition_nat(reader, "result_completion_at"),
        owed_cents=_read_transition_nat(reader, "result_owed_cents"),
        claimed_adjustment_cents=_read_transition_nat(reader, "result_claimed_adjustment_cents"),
        lawful_adjustment_cents=_read_transition_nat(reader, "result_lawful_adjustment_cents"),
        received_cash_cents=_read_transition_nat(reader, "result_received_cash_cents"),
        shortfall_cents=_read_transition_nat(reader, "result_shortfall_cents"),
        overage_cents=_read_transition_nat(reader, "result_overage_cents"),
        cash_satisfied=reader.boolean("result_cash_satisfied"),  # type: ignore[attr-defined]
        amount_satisfied=reader.boolean("result_amount_satisfied"),  # type: ignore[attr-defined]
        timely=reader.boolean("result_timely"),  # type: ignore[attr-defined]
        reporting_complete=reader.boolean("result_reporting_complete"),  # type: ignore[attr-defined]
        verification_status=semantic._read_tag(
            reader, semantic._VERIFICATION_STATUS_TAGS, "result_verification_status"
        ),
        case_status=semantic._read_tag(reader, semantic._CASE_STATUS_TAGS, "result_case_status"),
        delivery_status=semantic._read_tag(reader, semantic._DELIVERY_STATUS_TAGS, "result_delivery_status"),
    )
    reader.finish()
    if semantic._encode_blfres02_result(result) != payload:
        raise FinancialEngineResultError("engine_correction_financial_result_canonical")
    return result


def _read_correction_mutation(reader: object) -> dict[str, Any] | None:
    tag = reader.byte("correction_mutation_tag")  # type: ignore[attr-defined]
    if tag == 0:
        return None
    if tag != 1:
        raise FinancialEngineResultError("engine_correction_mutation_tag")
    transition_tag = reader.byte("correction_transition_kind")  # type: ignore[attr-defined]
    if transition_tag != 1:
        raise FinancialEngineResultError("engine_correction_transition_kind")
    effect_tags = {
        1: "DETERMINATION_RECORDED",
        2: "CLAIM_REJECTED",
        3: "CASE_UPSERTED",
        4: "ACTION_CREATED",
        5: "OUTBOX_CREATED",
        6: "PROJECTION_RECOMPUTED",
        7: "EVENT_APPENDED",
    }

    def read_effect(_label: str) -> str:
        value = effect_tags.get(reader.byte("correction_effect"))  # type: ignore[attr-defined]
        if value is None:
            raise FinancialEngineResultError("engine_correction_effect")
        return value

    ordered_effects = reader.list("correction_effects", read_effect)  # type: ignore[attr-defined]
    if len(ordered_effects) > 16:
        raise FinancialEngineResultError("engine_correction_effect_limit")
    dependencies = _read_correction_dependency_facts(reader)
    followups = _read_correction_followups(reader)
    input_size = int.from_bytes(reader.take(4, "correction_input_size"), "big")  # type: ignore[attr-defined]
    if input_size > MAX_CORRECTION_TRANSITION_BYTES:
        raise FinancialEngineResultError("engine_correction_input_size")
    resulting_input = reader.take(input_size, "correction_resulting_input")  # type: ignore[attr-defined]
    if not resulting_input.startswith(semantic.BLFIN02_MAGIC):
        raise FinancialEngineResultError("engine_correction_resulting_input_magic")
    result_size = int.from_bytes(reader.take(4, "correction_result_size"), "big")  # type: ignore[attr-defined]
    if result_size > MAX_CORRECTION_TRANSITION_BYTES:
        raise FinancialEngineResultError("engine_correction_result_size")
    resulting_result_wire = reader.take(result_size, "correction_resulting_result")  # type: ignore[attr-defined]
    resulting_result = _decode_correction_financial_result(resulting_result_wire)
    determination = _read_correction_determination(reader)
    determination_digest = reader.digest("correction_determination_digest")  # type: ignore[attr-defined]
    action = _read_correction_action(reader)
    action_payload_digest = reader.digest("correction_action_payload_digest")  # type: ignore[attr-defined]
    action_idempotency_key = reader.digest("correction_action_idempotency_key")  # type: ignore[attr-defined]
    case_record = _read_correction_case(reader)
    contractual_accountability = _read_transition_identifier(reader, "correction_case_accountability")
    completion_amount = reader.boolean("correction_case_amount_complete")  # type: ignore[attr-defined]
    completion_reporting = reader.boolean("correction_case_reporting_complete")  # type: ignore[attr-defined]
    completion_delivery = reader.boolean("correction_case_delivery_complete")  # type: ignore[attr-defined]
    inserted = reader.boolean("correction_case_inserted")  # type: ignore[attr-defined]
    case_delta = {
        "record": case_record,
        "contractual_accountability": contractual_accountability,
        "completion_conditions_amount_satisfied": completion_amount,
        "completion_conditions_reporting_complete": completion_reporting,
        "completion_conditions_delivery_acknowledged_or_not_required": completion_delivery,
        "inserted": inserted,
    }
    outbox_action_id = _read_transition_identifier(reader, "correction_outbox_action_id")
    outbox_status_tags = {1: "READY", 2: "ACKNOWLEDGED", 3: "CANCELLED"}
    outbox_status = outbox_status_tags.get(reader.byte("correction_outbox_status"))  # type: ignore[attr-defined]
    if outbox_status is None:
        raise FinancialEngineResultError("engine_correction_outbox_status")
    outbox_attempt = _read_transition_nat(reader, "correction_outbox_attempt")
    outbox_payload_digest = reader.digest("correction_outbox_payload_digest")  # type: ignore[attr-defined]
    outbox_idempotency_key = reader.digest("correction_outbox_idempotency_key")  # type: ignore[attr-defined]
    acknowledgment_reference = _read_optional_transition_text(reader, "correction_outbox_acknowledgment")
    outbox_updated_at_ms = _read_transition_nat(reader, "correction_outbox_updated_at")
    outbox = {
        "action_id": outbox_action_id,
        "status": outbox_status,
        "attempt": outbox_attempt,
        "payload_digest": outbox_payload_digest,
        "idempotency_key": outbox_idempotency_key,
        "acknowledgment_reference": acknowledgment_reference,
        "updated_at_ms": outbox_updated_at_ms,
    }
    event_sequence = _read_transition_nat(reader, "correction_event_sequence")
    event_previous_head = reader.digest("correction_event_previous_head")  # type: ignore[attr-defined]
    event_aggregate_type = _read_transition_identifier(reader, "correction_event_aggregate_type")
    event_aggregate_id = _read_transition_identifier(reader, "correction_event_aggregate_id")
    event_kind = _read_transition_identifier(reader, "correction_event_kind")
    event_before_revision = _read_transition_nat(reader, "correction_event_before_revision")
    event_after_revision = _read_transition_nat(reader, "correction_event_after_revision")
    event_committed_at_ms = _read_transition_nat(reader, "correction_event_committed_at")
    event_base_payload_json = _read_transition_text(reader, "correction_event_base_payload")
    event = {
        "sequence": event_sequence,
        "previous_head": event_previous_head,
        "aggregate_type": event_aggregate_type,
        "aggregate_id": event_aggregate_id,
        "kind": event_kind,
        "before_revision": event_before_revision,
        "after_revision": event_after_revision,
        "committed_at_ms": event_committed_at_ms,
        "base_payload_json": event_base_payload_json,
    }
    return {
        "transition": "OFFSET_REJECTED_CORRECTION_AUTHORIZED",
        "ordered_effects": ordered_effects,
        "dependencies": dependencies,
        "followups": followups,
        "resulting_input_wire": resulting_input,
        "resulting_result_wire": resulting_result_wire,
        "resulting_result": resulting_result,
        "determination": determination,
        "determination_digest": determination_digest,
        "action": action,
        "action_payload_digest": action_payload_digest,
        "action_idempotency_key": action_idempotency_key,
        "case_delta": case_delta,
        "outbox": outbox,
        "event": event,
    }


_CORRECTION_REJECT_REASON_TAGS: Final[dict[int, str]] = {
    1: "INVALID_REQUEST",
    2: "INVALID_INPUT",
    3: "SHADOW_READ_ONLY",
    4: "SCOPE_MISMATCH",
    5: "AUTHORITY_STALE",
    6: "ACTOR_UNAUTHORIZED",
    7: "CONTROL_PACK_REJECTED",
    8: "REVISION_CONFLICT",
    9: "EVALUATION_CONFLICT",
    10: "EVALUATION_CONSUMED",
    11: "EVIDENCE_COVERAGE",
    12: "CLAIM_MISSING",
    13: "CLAIM_NOT_CLAIMED",
    14: "ACTION_CONFLICT",
    15: "DETERMINATION_CONFLICT",
    16: "CHRONOLOGY",
    17: "CAPACITY",
    18: "QUERY_OBSERVATION_INVALID",
    19: "INPUT_SNAPSHOT_MISSING",
}
_CORRECTION_REQUIREMENT_TAGS: Final[dict[int, str]] = {
    1: "VALID_COMMAND",
    2: "WELL_FORMED_FINANCIAL_SNAPSHOT",
    3: "ACTIONABLE_OWNER_MODE",
    4: "REQUEST_SCOPE_MATCH",
    5: "CURRENT_AUTHORITY_MATCH",
    6: "AUTHORIZED_ACTOR_ROLE",
    7: "APPROVED_CONTROL_PACK",
    8: "CURRENT_REVISION_MATCH",
    9: "CURRENT_EVALUATION_BINDING",
    10: "UNIQUE_EVALUATION_USE",
    11: "CLAIM_EVIDENCE_COVERAGE",
    12: "CLAIM_EXISTS_IN_SCOPE",
    13: "CLAIM_IS_CLAIMED",
    14: "ACTION_IDENTITY_MATCH",
    15: "DETERMINATION_ID_AVAILABLE",
    16: "RECEIPT_PRECEDES_DECISION",
    17: "HISTORY_CAPACITY_AVAILABLE",
    18: "COMPLETE_QUERY_OBSERVATIONS",
    19: "INPUT_SNAPSHOT_DIGEST_AVAILABLE",
}
_CORRECTION_REJECT_REQUIREMENTS: Final[dict[str, str]] = {
    "INVALID_REQUEST": "VALID_COMMAND",
    "INVALID_INPUT": "WELL_FORMED_FINANCIAL_SNAPSHOT",
    "SHADOW_READ_ONLY": "ACTIONABLE_OWNER_MODE",
    "SCOPE_MISMATCH": "REQUEST_SCOPE_MATCH",
    "AUTHORITY_STALE": "CURRENT_AUTHORITY_MATCH",
    "ACTOR_UNAUTHORIZED": "AUTHORIZED_ACTOR_ROLE",
    "CONTROL_PACK_REJECTED": "APPROVED_CONTROL_PACK",
    "REVISION_CONFLICT": "CURRENT_REVISION_MATCH",
    "EVALUATION_CONFLICT": "CURRENT_EVALUATION_BINDING",
    "EVALUATION_CONSUMED": "UNIQUE_EVALUATION_USE",
    "EVIDENCE_COVERAGE": "CLAIM_EVIDENCE_COVERAGE",
    "CLAIM_MISSING": "CLAIM_EXISTS_IN_SCOPE",
    "CLAIM_NOT_CLAIMED": "CLAIM_IS_CLAIMED",
    "ACTION_CONFLICT": "ACTION_IDENTITY_MATCH",
    "DETERMINATION_CONFLICT": "DETERMINATION_ID_AVAILABLE",
    "CHRONOLOGY": "RECEIPT_PRECEDES_DECISION",
    "CAPACITY": "HISTORY_CAPACITY_AVAILABLE",
    "QUERY_OBSERVATION_INVALID": "COMPLETE_QUERY_OBSERVATIONS",
    "INPUT_SNAPSHOT_MISSING": "INPUT_SNAPSHOT_DIGEST_AVAILABLE",
}


def _read_optional_correction_reject_reason(reader: object, label: str) -> str | None:
    tag = reader.byte(f"{label}_tag")  # type: ignore[attr-defined]
    if tag == 0:
        return None
    if tag != 1:
        raise FinancialEngineResultError(label)
    reason = _CORRECTION_REJECT_REASON_TAGS.get(reader.byte(label))  # type: ignore[attr-defined]
    if reason is None:
        raise FinancialEngineResultError(label)
    return reason


def _read_optional_correction_requirement(reader: object, label: str) -> str | None:
    tag = reader.byte(f"{label}_tag")  # type: ignore[attr-defined]
    if tag == 0:
        return None
    if tag != 1:
        raise FinancialEngineResultError(label)
    requirement = _CORRECTION_REQUIREMENT_TAGS.get(reader.byte(label))  # type: ignore[attr-defined]
    if requirement is None:
        raise FinancialEngineResultError(label)
    return requirement


def _read_correction_explanation(reader: object) -> dict[str, Any]:
    explanation_codes = {1: "CORRECTION_AUTHORIZED", 2: "EXACT_RETRY", 3: "REJECTED"}
    transition_kinds = {1: "OFFSET_REJECTED_CORRECTION_AUTHORIZED"}
    code = explanation_codes.get(reader.byte("correction_explanation_code"))  # type: ignore[attr-defined]
    if code is None:
        raise FinancialEngineResultError("engine_correction_explanation_code")
    transition_tag = reader.byte("correction_explanation_transition_tag")  # type: ignore[attr-defined]
    if transition_tag == 0:
        transition = None
    elif transition_tag == 1:
        transition = transition_kinds.get(reader.byte("correction_explanation_transition"))  # type: ignore[attr-defined]
        if transition is None:
            raise FinancialEngineResultError("engine_correction_explanation_transition")
    else:
        raise FinancialEngineResultError("engine_correction_explanation_transition_tag")
    return {
        "code": code,
        "transition": transition,
        "reject_reason": _read_optional_correction_reject_reason(reader, "correction_explanation_reject_reason"),
        "unresolved_requirement": _read_optional_correction_requirement(reader, "correction_explanation_requirement"),
        "claim_id": _read_optional_transition_identifier(reader, "correction_explanation_claim"),
        "action_id": _read_optional_transition_identifier(reader, "correction_explanation_action"),
        "input_evaluation_id": _read_optional_transition_identifier(reader, "correction_explanation_evaluation"),
        "expected_revision": _read_optional_transition_nat(reader, "correction_explanation_expected_revision"),
        "resulting_revision": _read_optional_transition_nat(reader, "correction_explanation_resulting_revision"),
    }


def _validate_correction_result_shape(result: Mapping[str, Any]) -> None:
    status = result["status"]
    explanation = result["explanation"]
    action_id = result["action_id"]
    determination_id = result["determination_id"]
    mutation = result["mutation"]
    reject_reason = result["reject_reason"]
    if status == "ACCEPTED":
        if (
            reject_reason is not None
            or explanation["code"] != "CORRECTION_AUTHORIZED"
            or explanation["transition"] != "OFFSET_REJECTED_CORRECTION_AUTHORIZED"
            or explanation["reject_reason"] is not None
            or explanation["unresolved_requirement"] is not None
            or action_id is None
            or determination_id is None
            or mutation is None
        ):
            raise FinancialEngineResultError("engine_correction_accepted_shape")
        if mutation["ordered_effects"] != [
            "DETERMINATION_RECORDED", "CLAIM_REJECTED", "CASE_UPSERTED", "ACTION_CREATED",
            "OUTBOX_CREATED", "PROJECTION_RECOMPUTED", "EVENT_APPENDED",
        ]:
            raise FinancialEngineResultError("engine_correction_effect_order")
        deps = mutation["dependencies"]
        det = mutation["determination"]
        action = mutation["action"]
        event = mutation["event"]
        case_delta = mutation["case_delta"]
        outbox = mutation["outbox"]
        followups = mutation["followups"]
        transition_id = f"determination:{action_id}"
        event_payload = {
            "action_id": action_id,
            "amount_cents": det["amount_cents"],
            "determination_id": determination_id,
            "evaluation_id": followups["resulting_evaluation_id"],
        }
        try:
            expected_event_payload = json.dumps(
                event_payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
            )
        except (TypeError, ValueError):
            raise FinancialEngineResultError("engine_correction_event_payload") from None
        observations = deps["query_observations"]
        if (
            action_id != transition_id.removeprefix("determination:")
            or determination_id != transition_id
            or det["determination_id"] != determination_id
            or det["decision"] != "OFFSET_REJECTED_CORRECTION_AUTHORIZED"
            or det["amount_cents"] <= 0
            or det["resulting_revision"] != det["expected_revision"] + 1
            or action["action_id"] != action_id
            or action["determination_id"] != determination_id
            or action["kind"] != "CORRECTION_PAYMENT_REQUEST"
            or action["status"] != "READY"
            or action["amount_cents"] != det["amount_cents"]
            or action["payload_digest"] != mutation["action_payload_digest"]
            or len(mutation["action_idempotency_key"]) != _SEMANTIC_DIGEST_BYTES
            or outbox["action_id"] != action_id
            or outbox["status"] != "READY"
            or outbox["attempt"] != 0
            or outbox["acknowledgment_reference"] is not None
            or outbox["payload_digest"] != mutation["action_payload_digest"]
            or outbox["idempotency_key"] != mutation["action_idempotency_key"]
            or case_delta["contractual_accountability"] != "PROGRAM_ACCOUNTABILITY"
            or not case_delta["completion_conditions_amount_satisfied"]
            or not case_delta["completion_conditions_reporting_complete"]
            or not case_delta["completion_conditions_delivery_acknowledged_or_not_required"]
            or case_delta["record"]["case_id"] != f"case:{det['obligation_id']}"
            or case_delta["record"]["obligation_id"] != det["obligation_id"]
            or case_delta["record"]["reason"] != "CORRECTION_REQUIRED"
            or case_delta["record"]["next_action_owner"] != "CASE_OWNER"
            or case_delta["record"]["due_at_ms"] != deps["claim_before"]["deadline_at_ms"]
            or case_delta["record"]["status"] != mutation["resulting_result"].case_status
            or case_delta["record"]["updated_at_ms"] != event["committed_at_ms"]
            or event["sequence"] != deps["current_event_sequence"] + 1
            or event["previous_head"] != deps["previous_history_head"]
            or event["aggregate_type"] != "OBLIGATION"
            or event["aggregate_id"] != det["obligation_id"]
            or event["kind"] != "OFFSET_REJECTED_CORRECTION_AUTHORIZED"
            or event["before_revision"] != det["expected_revision"]
            or event["after_revision"] != det["resulting_revision"]
            or event["committed_at_ms"] != outbox["updated_at_ms"]
            or event["base_payload_json"] != expected_event_payload
            or followups["action_id"] != action_id
            or followups["outbox_action_id"] != action_id
            or followups["case_id"] != case_delta["record"]["case_id"]
            or followups["resulting_evaluation_id"]
            != f"evaluation:{det['obligation_id']}:r{det['resulting_revision']}"
            or followups["event_sequence"] != event["sequence"]
            or explanation["action_id"] != action_id
            or explanation["claim_id"] != det["claim_id"]
            or explanation["input_evaluation_id"] != deps["input_evaluation_id"]
            or explanation["expected_revision"] != det["expected_revision"]
            or explanation["resulting_revision"] != mutation["resulting_result"].after_revision
            or action["created_at_ms"] != event["committed_at_ms"]
            or action["revision"] != det["resulting_revision"]
            or observations["action_id"]["subject"] != action_id
            or observations["determination_id"]["subject"] != determination_id
            or observations["evaluation_consumed"]["subject"] != deps["input_evaluation_id"]
        ):
            raise FinancialEngineResultError("engine_correction_accepted_binding")
        if (
            deps["artifact_contract"] != CORRECTION_TRANSITION_OPERATION
            or deps["artifact_version"] != 1
            or deps["claim_before"]["status"] != "CLAIMED"
            or deps["claim_before"]["claim_id"] != det["claim_id"]
            or deps["claim_before"]["amount_cents"] != det["amount_cents"]
            or deps["claim_before"]["obligation_id"] != det["obligation_id"]
            or det["supporting_evidence_ids"]
            != [binding["evidence_id"] for binding in deps["supporting_evidence"]]
            or len(mutation["determination_digest"]) != _SEMANTIC_DIGEST_BYTES
            or len(mutation["action_payload_digest"]) != _SEMANTIC_DIGEST_BYTES
            or len(deps["input_evaluation_snapshot_digest"]) != _SEMANTIC_DIGEST_BYTES
            or not all(observation["complete"] for observation in observations.values())
            or any(
                observation["version_sequence"] != deps["current_event_sequence"]
                or observation["version_head"] != deps["previous_history_head"]
                for observation in observations.values()
            )
        ):
            raise FinancialEngineResultError("engine_correction_dependency_binding")
        if (
            observations["action_id"]["predicate"] != "ACTION_ID"
            or observations["determination_id"]["predicate"] != "DETERMINATION_ID"
            or observations["evaluation_consumed"]["predicate"] != "EVALUATION_CONSUMED"
            or observations["action_id"]["match_count"] != 0
            or observations["determination_id"]["match_count"] != 0
            or observations["evaluation_consumed"]["match_count"] != 0
            or observations["action_id"]["result_identity"] is not None
            or observations["determination_id"]["result_identity"] is not None
            or observations["evaluation_consumed"]["result_identity"] is not None
        ):
            raise FinancialEngineResultError("engine_correction_absence_binding")
        financial_result = mutation["resulting_result"]
        if (
            financial_result.before_revision != det["expected_revision"]
            or financial_result.after_revision != det["resulting_revision"]
            or financial_result.evaluated_at_ms != event["committed_at_ms"]
            or financial_result.obligation_id != det["obligation_id"]
            or financial_result.delivery_status != "READY"
            or not mutation["resulting_input_wire"].startswith(semantic.BLFIN02_MAGIC)
        ):
            raise FinancialEngineResultError("engine_correction_result_projection")
        return

    if status == "DUPLICATE":
        if (
            reject_reason is not None
            or explanation["code"] != "EXACT_RETRY"
            or explanation["transition"] != "OFFSET_REJECTED_CORRECTION_AUTHORIZED"
            or explanation["reject_reason"] is not None
            or explanation["unresolved_requirement"] is not None
            or action_id is None
            or determination_id != f"determination:{action_id}"
            or mutation is not None
            or explanation["claim_id"] is None
            or explanation["action_id"] != action_id
            or explanation["input_evaluation_id"] is None
            or explanation["expected_revision"] is None
            or explanation["resulting_revision"] is not None
        ):
            raise FinancialEngineResultError("engine_correction_duplicate_shape")
        return

    if status != "REJECTED" or reject_reason is None or mutation is not None:
        raise FinancialEngineResultError("engine_correction_rejected_shape")
    if (
        explanation["code"] != "REJECTED"
        or explanation["transition"] is not None
        or explanation["reject_reason"] != reject_reason
        or explanation["unresolved_requirement"] != _CORRECTION_REJECT_REQUIREMENTS.get(reject_reason)
        or explanation["resulting_revision"] is not None
        or action_id is not None
        or determination_id is not None
    ):
        raise FinancialEngineResultError("engine_correction_rejected_binding")


def decode_correction_transition_result(payload: bytes) -> dict[str, Any]:
    """Strictly decode one BLFCRES1 value and reject any trailing bytes."""

    try:
        reader = semantic._WireReader(payload, max_bytes=MAX_CORRECTION_TRANSITION_BYTES)
        if reader.take(8, "correction_result_magic") != b"BLFCRES1":
            raise FinancialEngineResultError("engine_correction_result_magic")
        if int.from_bytes(reader.take(2, "correction_result_version"), "big") != 1:
            raise FinancialEngineResultError("engine_correction_result_version")
        status_tags = {1: "ACCEPTED", 2: "DUPLICATE", 3: "REJECTED"}
        status = status_tags.get(reader.byte("correction_result_status"))
        if status is None:
            raise FinancialEngineResultError("engine_correction_result_status")
        contract = _read_transition_text(reader, "correction_result_contract")
        if contract != CORRECTION_TRANSITION_OPERATION:
            raise FinancialEngineResultError("engine_correction_result_contract")
        reject_reason = _read_optional_correction_reject_reason(reader, "correction_result_reject_reason")
        explanation = _read_correction_explanation(reader)
        action_id = _read_optional_transition_identifier(reader, "correction_result_action_id")
        determination_id = _read_optional_transition_identifier(reader, "correction_result_determination_id")
        mutation = _read_correction_mutation(reader)
        reader.finish()
        result = {
            "status": status,
            "reject_reason": reject_reason,
            "explanation": explanation,
            "action_id": action_id,
            "determination_id": determination_id,
            "mutation": mutation,
        }
        _validate_correction_result_shape(result)
        return result
    except FinancialEngineResultError:
        raise
    except semantic.SemanticAdapterError:
        raise FinancialEngineResultError("engine_correction_result_codec") from None
    except (KeyError, TypeError, ValueError, UnicodeError, OverflowError, IndexError):
        raise FinancialEngineResultError("engine_correction_result_shape") from None


def validate_correction_result_input(
    snapshot: semantic.LockedSemanticSnapshot,
    *,
    expected_revision: int,
    result: Mapping[str, Any],
) -> semantic.LockedSemanticSnapshot:
    """Require the accepted post-state input to contain only Engine's exact delta."""

    if result.get("status") != "ACCEPTED" or type(result.get("mutation")) is not dict:
        raise FinancialEngineResultError("engine_correction_result_not_accepted")
    mutation = result["mutation"]
    deps = mutation["dependencies"]
    determination = mutation["determination"]
    action = mutation["action"]
    case_delta = mutation["case_delta"]
    event = mutation["event"]
    try:
        body = snapshot.data
        body.pop("snapshot_digest", None)
        body["pre_evaluation"]["revision"] = expected_revision
        body["evaluation_time_ms"] = event["committed_at_ms"]
        claims = body["claims"]
        matching_claims = [claim for claim in claims if claim["claim_id"] == determination["claim_id"]]
        if len(matching_claims) != 1 or matching_claims[0]["status"] != "CLAIMED":
            raise FinancialEngineResultError("engine_correction_result_claim_delta")
        claim_amount_cents = matching_claims[0]["amount_cents"]
        obligation = body["obligation"]
        claimed_adjustment_cents = obligation["claimed_adjustment_cents"]
        if (
            type(claim_amount_cents) is not int
            or claim_amount_cents <= 0
            or type(claimed_adjustment_cents) is not int
            or claimed_adjustment_cents < claim_amount_cents
        ):
            raise FinancialEngineResultError("engine_correction_result_claim_projection")
        # A CLAIMED adjustment contributes to the claimed projection, but not
        # the lawful amount or satisfied/shortfall projections. Rejection only
        # removes this claim from the claimed projection.
        obligation["claimed_adjustment_cents"] = claimed_adjustment_cents - claim_amount_cents
        matching_claims[0]["status"] = "REJECTED"
        matching_claims[0]["updated_at_ms"] = event["committed_at_ms"]

        if any(value["determination_id"] == determination["determination_id"] for value in body["determinations"]):
            raise FinancialEngineResultError("engine_correction_result_determination_collision")
        body["determinations"].append({
            "determination_id": determination["determination_id"],
            "obligation_id": determination["obligation_id"],
            "claim_id": determination["claim_id"],
            "actor_id": determination["actor_id"],
            "actor_role": determination["actor_role"],
            "authority_id": determination["authority_id"],
            "authority_epoch": determination["authority_epoch"],
            "authority_digest": determination["authority_digest"].hex().upper(),
            "decision": determination["decision"],
            "amount_cents": determination["amount_cents"],
            "supporting_evidence": [
                {"evidence_id": item["evidence_id"], "record_digest": item["record_digest"].hex().upper()}
                for item in deps["supporting_evidence"]
            ],
            "expected_revision": determination["expected_revision"],
            "resulting_revision": determination["resulting_revision"],
            "decided_at_ms": determination["decided_at_ms"],
            "determination_digest": mutation["determination_digest"].hex().upper(),
            "input_evaluation_id": deps["input_evaluation_id"],
            "input_evaluation_result_digest": deps["input_evaluation_result_digest"].hex().upper(),
            "action_id": action["action_id"],
        })
        body["determinations"].sort(key=lambda value: value["determination_id"])

        case_record = case_delta["record"]
        cases = body["cases"]
        matches = [case for case in cases if case["case_id"] == case_record["case_id"]]
        if bool(matches) == case_delta["inserted"]:
            raise FinancialEngineResultError("engine_correction_result_case_inserted")
        for case in cases:
            case["status"] = case_record["status"]
            case["updated_at_ms"] = case_record["updated_at_ms"]
        if matches:
            case = matches[0]
            case.update({
                "obligation_id": case_record["obligation_id"],
                "reason": case_record["reason"],
                "contractual_accountability": case_delta["contractual_accountability"],
                "next_action_owner": case_record["next_action_owner"],
                "due_at_ms": case_record["due_at_ms"],
                "completion_conditions": {
                    "amount_satisfied": case_delta["completion_conditions_amount_satisfied"],
                    "reporting_complete": case_delta["completion_conditions_reporting_complete"],
                    "delivery_acknowledged_or_not_required": case_delta[
                        "completion_conditions_delivery_acknowledged_or_not_required"
                    ],
                },
                "status": case_record["status"],
                "updated_at_ms": case_record["updated_at_ms"],
            })
        else:
            cases.append({
                "case_id": case_record["case_id"],
                "obligation_id": case_record["obligation_id"],
                "reason": case_record["reason"],
                "contractual_accountability": case_delta["contractual_accountability"],
                "next_action_owner": case_record["next_action_owner"],
                "due_at_ms": case_record["due_at_ms"],
                "completion_conditions": {
                    "amount_satisfied": case_delta["completion_conditions_amount_satisfied"],
                    "reporting_complete": case_delta["completion_conditions_reporting_complete"],
                    "delivery_acknowledged_or_not_required": case_delta[
                        "completion_conditions_delivery_acknowledged_or_not_required"
                    ],
                },
                "status": case_record["status"],
                "updated_at_ms": case_record["updated_at_ms"],
            })
        cases.sort(key=lambda value: value["case_id"])
        obligation["case_status"] = cases[-1]["status"]

        if any(value["action_id"] == action["action_id"] for value in body["actions"]):
            raise FinancialEngineResultError("engine_correction_result_action_collision")
        body["actions"].append({
            "action_id": action["action_id"],
            "obligation_id": action["obligation_id"],
            "determination_id": action["determination_id"],
            "kind": action["kind"],
            "status": action["status"],
            "revision": action["revision"],
            "payload": {"amount_cents": action["amount_cents"], "currency": action["currency"]},
            "payload_digest": action["payload_digest"].hex().upper(),
            "idempotency_key": mutation["action_idempotency_key"].hex().upper(),
            "created_at_ms": action["created_at_ms"],
        })
        body["actions"].sort(key=lambda value: value["action_id"])
        latest_action = max(body["actions"], key=lambda value: (value["created_at_ms"], value["action_id"]))
        obligation["delivery_status"] = latest_action["status"]
        expected_snapshot = semantic._make_snapshot(body)
        expected_wire = semantic.encode_blfin02_input(expected_snapshot)
    except FinancialEngineResultError:
        raise
    except (semantic.SemanticAdapterError, KeyError, TypeError, ValueError, IndexError):
        raise FinancialEngineResultError("engine_correction_result_input_delta") from None
    if expected_wire != mutation["resulting_input_wire"]:
        raise FinancialEngineResultError("engine_correction_result_input_delta")
    return expected_snapshot


def run_correction_transition_v1(
    release: object | None,
    *,
    request: bytes,
) -> FinancialCorrectionTransitionExecution:
    """Run only a fully pinned candidate through the existing contained lane."""

    configured = require_correction_transition_v1(release)
    if (
        type(request) is not bytes
        or not request.startswith(b"BLFCMD01")
        or not 0 < len(request) <= configured.input_max_bytes
    ):
        raise FinancialEngineInputError("engine_correction_request_contract")
    _capture_artifact_identity(configured)
    try:
        contained = process.run_contained_verifier_stream(
            configured.executable,
            CORRECTION_TRANSITION_ARGUMENTS,
            request,
            workspace=configured.workspace,
            timeout_seconds=configured.timeout_seconds,
            job_memory_cap_bytes=configured.job_memory_cap_bytes,
            expected_executable_size_bytes=configured.executable_size_bytes,
            expected_executable_sha256=configured.executable_sha256,
            stdout_cap_bytes=configured.output_max_bytes,
            stderr_cap_bytes=configured.stderr_max_bytes,
            stdout_ascii=False,
            stderr_ascii=False,
            expected_input_bytes=len(request),
        )
    except Exception:
        raise FinancialEngineContainmentError("engine_correction_containment") from None
    contained = _validate_contained_result(contained, configured)
    try:
        result = decode_correction_transition_result(contained.stdout)
    except FinancialEngineResultError:
        raise
    return FinancialCorrectionTransitionExecution(
        result=result,
        input_size_bytes=len(request),
        input_sha256=hashlib.sha256(request).digest(),
        output_size_bytes=len(contained.stdout),
        output_sha256=hashlib.sha256(contained.stdout).digest(),
        executable_size_bytes=configured.executable_size_bytes,
        executable_sha256=configured.executable_sha256,
        exit_code=contained.exit_code,
        job_memory_cap_bytes=contained.cap_bytes,
        peak_job_commit_bytes=contained.peak_job_commit_bytes,
        cap_enforced=contained.cap_enforced,
        active_process_limit=contained.active_process_limit,
        child_process_count=contained.child_process_count,
    )


__all__ = (
    "ENGINE_ARGUMENTS",
    "CORRECTION_TRANSITION_OPERATION",
    "CORRECTION_TRANSITION_ARGUMENTS",
    "CORRECTION_TRANSITION_ARTIFACT_SIZE_BYTES",
    "CORRECTION_TRANSITION_ARTIFACT_SHA256",
    "CORRECTION_TRANSITION_REQUEST_VECTOR_SHA256",
    "CORRECTION_TRANSITION_RESULT_VECTOR_SHA256",
    "FinancialCorrectionTransitionExecution",
    "FinancialCorrectionTransitionRelease",
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
    "FinancialEngineTransitionUnavailable",
    "MAX_CORRECTION_TRANSITION_BYTES",
    "MAX_ENGINE_INPUT_BYTES",
    "MAX_ENGINE_JOB_MEMORY_CAP_BYTES",
    "evaluate_financial_snapshot",
    "encode_correction_transition_request",
    "decode_correction_transition_result",
    "require_correction_transition_v1",
    "run_correction_transition_v1",
    "validate_correction_result_input",
)
