"""Owner-side adapter for the pinned financial Engine executable.

Lean decides; this module only moves bytes (Constitution V.1).  One path for
both lanes: encode request -> run the pinned executable under the Windows
Job Object lane (``minimal_clearance_verifier_process``, which is the single
place the executable is opened, hashed and bound to the launched image) ->
strictly parse the result -> return a typed value.  It never opens, commits,
rolls back or closes a database connection and never reads release identity
from the environment.
"""

from __future__ import annotations

import atexit
from dataclasses import dataclass
import hashlib
import math
from pathlib import Path
import shutil
import sqlite3
import tempfile
import threading
from collections.abc import Mapping
from typing import Any, Final

from app import minimal_clearance_verifier_process as process
from app import right_rail_financial_semantic_adapter as semantic


MAX_ENGINE_JOB_MEMORY_CAP_BYTES: Final[int] = 2_000_000_000
CORRECTION_TRANSITION_OPERATION: Final[str] = "RR/FINANCIAL/CORRECTION-TRANSITION/v1"
CORRECTION_TRANSITION_ARGUMENTS: Final[tuple[str, ...]] = ("--apply-correction-transition",)
MAX_CORRECTION_TRANSITION_BYTES: Final[int] = semantic.MAX_WIRE_BYTES
CORRECTION_TRANSITION_ARTIFACT_SIZE_BYTES: Final[int] = 6_433_792
CORRECTION_TRANSITION_ARTIFACT_SHA256: Final[bytes] = bytes.fromhex(
    "874E2A37123E3B3EA5AD6E96DEE9DD066C596029D5268EF9FE6F3AF6A278323F"
)
CORRECTION_TRANSITION_REQUEST_VECTOR_SHA256: Final[bytes] = bytes.fromhex(
    "234FDF65E630E41D38E1ECA1CC674845969ED35B409AEB12CB41E3116487E666"
)
CORRECTION_TRANSITION_RESULT_VECTOR_SHA256: Final[bytes] = bytes.fromhex(
    "83BB53D184B0B7D9268B565B844ECE9D6943C37DD022E2D361F735A4C835E0D6"
)
# Support's fictional reproduction (CORPORATE-SUPPORT/v2): the published request vector and the case its result creates.
CORRECTION_TRANSITION_REPRODUCTION: Final[dict[str, str]] = {
    "vector_file_digest": CORRECTION_TRANSITION_REQUEST_VECTOR_SHA256.hex().upper(), "case_id": "case:obligation:item-h:period-01",
}
_SHA256_BYTES: Final[int] = 32
_MAX_SQLITE_INTEGER: Final[int] = 2**63 - 1


class FinancialEngineError(Exception):
    """Base error for this fail-closed application boundary."""


class FinancialEngineConfigError(FinancialEngineError):
    pass


class FinancialEngineArtifactError(FinancialEngineError):
    pass


class FinancialEngineInputError(FinancialEngineError):
    pass


class FinancialEngineContainmentError(FinancialEngineError):
    pass


class FinancialEngineResultError(FinancialEngineError):
    pass


class FinancialEngineTransitionUnavailable(FinancialEngineError):
    pass


@dataclass(frozen=True, slots=True)
class FinancialCorrectionTransitionRelease:
    """Explicit release identity for the correction transition."""

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

    def __post_init__(self) -> None:
        def require(condition: bool, field: str) -> None:
            if not condition:
                raise FinancialEngineConfigError(f"engine_correction_{field}")

        require(isinstance(self.executable, Path) and self.executable.is_absolute(), "executable_path")
        require(isinstance(self.workspace, Path) and self.workspace.is_absolute(), "workspace_path")
        require(type(self.executable_size_bytes) is int and self.executable_size_bytes > 0, "executable_size")
        require(
            type(self.executable_sha256) is bytes and len(self.executable_sha256) == _SHA256_BYTES,
            "executable_hash",
        )
        for field in ("request_vector_sha256", "result_vector_sha256"):
            value = getattr(self, field)
            require(type(value) is bytes and len(value) == _SHA256_BYTES, field.replace("_sha256", "_hash"))
        require(
            type(self.timeout_seconds) is float and math.isfinite(self.timeout_seconds) and 0 < self.timeout_seconds <= 30.0,
            "timeout",
        )
        for field, cap in (("input", MAX_CORRECTION_TRANSITION_BYTES), ("output", MAX_CORRECTION_TRANSITION_BYTES)):
            value = getattr(self, f"{field}_max_bytes")
            require(type(value) is int and 0 < value <= cap, f"{field}_limit")
        require(
            type(self.stderr_max_bytes) is int and 0 < self.stderr_max_bytes <= process.MAX_STDERR_BYTES,
            "stderr_limit",
        )
        require(
            type(self.job_memory_cap_bytes) is int
            and 0 < self.job_memory_cap_bytes <= MAX_ENGINE_JOB_MEMORY_CAP_BYTES
            and self.job_memory_cap_bytes <= process.ADMISSION_CAP_BYTES,
            "memory_cap",
        )


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


def _validate_contained_result(
    result: object,
    release: FinancialCorrectionTransitionRelease,
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


def _run_pinned(
    release: FinancialCorrectionTransitionRelease,
    arguments: tuple[str, ...],
    frame: bytes,
    *,
    failure_code: str,
) -> process.ContainedVerifierResult:
    """The single launch: pinned executable, Job Object limits, bounded I/O."""

    try:
        contained = process.run_contained_verifier_stream(
            release.executable,
            arguments,
            frame,
            workspace=release.workspace,
            timeout_seconds=release.timeout_seconds,
            job_memory_cap_bytes=release.job_memory_cap_bytes,
            expected_executable_size_bytes=release.executable_size_bytes,
            expected_executable_sha256=release.executable_sha256,
            stdout_cap_bytes=release.output_max_bytes,
            stderr_cap_bytes=release.stderr_max_bytes,
            stdout_ascii=False,
            stderr_ascii=False,
            expected_input_bytes=len(frame),
        )
    except Exception:
        raise FinancialEngineContainmentError(failure_code) from None
    return _validate_contained_result(contained, release)


def _execution_fields(
    release: FinancialCorrectionTransitionRelease,
    frame: bytes,
    contained: process.ContainedVerifierResult,
) -> dict[str, Any]:
    return {
        "input_size_bytes": len(frame),
        "input_sha256": hashlib.sha256(frame).digest(),
        "output_size_bytes": len(contained.stdout),
        "output_sha256": hashlib.sha256(contained.stdout).digest(),
        "executable_size_bytes": release.executable_size_bytes,
        "executable_sha256": release.executable_sha256,
        "exit_code": contained.exit_code,
        "job_memory_cap_bytes": contained.cap_bytes,
        "peak_job_commit_bytes": contained.peak_job_commit_bytes,
        "cap_enforced": contained.cap_enforced,
        "active_process_limit": contained.active_process_limit,
        "child_process_count": contained.child_process_count,
    }


def _transition_digest(value: object, label: str) -> bytes:
    """Accept a raw 64-byte digest or its checked upper-hex form."""

    try:
        if type(value) is bytes:
            return semantic._wire_digest(value, label)
        return semantic._wire_hex_digest(value, label)
    except semantic.SemanticAdapterError:
        raise FinancialEngineInputError(label) from None


# Encoding helpers.  The wire writer already validates every value; codec
# failures are mapped to FinancialEngineInputError(label) once, at the top of
# encode_correction_transition_request.  Only the stricter SQLite integer
# bound and the bytes-or-hex digest form are added here.
def _u64(writer: Any, value: object, label: str) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_SQLITE_INTEGER:
        raise FinancialEngineInputError(label)
    writer.nat(value, label)
    return value


def _ident(writer: Any, value: object, label: str) -> str:
    writer.identifier(value, label)
    return value  # type: ignore[return-value]


def _digest(writer: Any, value: object, label: str) -> bytes:
    digest = _transition_digest(value, label)
    writer.digest(digest, label)
    return digest


def _write_correction_action_lookup(writer: Any, lookup: Mapping[str, Any]) -> None:
    kind = lookup.get("kind")
    if kind == "absent":
        writer.byte(1, "action_lookup")
        return
    if kind == "conflicting":
        writer.byte(3, "action_lookup")
        return
    if kind != "existing" or type(lookup.get("identity")) is not dict:
        raise FinancialEngineInputError("engine_correction_action_lookup")
    identity = lookup["identity"]
    writer.byte(2, "action_lookup")
    for key in (
        "action_id", "action_obligation_id", "determination_id",
        "determination_obligation_id", "action_kind", "claim_id", "actor_id",
    ):
        _ident(writer, identity.get(key), f"action_lookup_{key}")
    writer.role(identity.get("actor_role"), "action_lookup_actor_role")
    _ident(writer, identity.get("authority_id"), "action_lookup_authority_id")
    _u64(writer, identity.get("authority_epoch"), "action_lookup_authority_epoch")
    _digest(writer, identity.get("authority_digest"), "action_lookup_authority_digest")
    if identity.get("decision") != "OFFSET_REJECTED_CORRECTION_AUTHORIZED":
        raise FinancialEngineInputError("action_lookup_decision")
    writer.byte(2, "action_lookup_decision")
    _ident(writer, identity.get("input_evaluation_id"), "action_lookup_evaluation_id")
    _digest(writer, identity.get("input_evaluation_result_digest"), "action_lookup_evaluation_digest")
    _u64(writer, identity.get("expected_revision"), "action_lookup_expected_revision")
    _u64(writer, identity.get("decided_at_ms"), "action_lookup_decided_at")


def _write_correction_query_observation(writer: Any, observation: Mapping[str, Any], label: str) -> None:
    predicates = {"ACTION_ID": 1, "DETERMINATION_ID": 2, "EVALUATION_CONSUMED": 3}
    predicate = observation.get("predicate")
    if predicate not in predicates:
        raise FinancialEngineInputError(f"{label}_predicate")
    writer.byte(predicates[predicate], f"{label}_predicate")
    _ident(writer, observation.get("subject"), f"{label}_subject")
    writer.boolean(observation.get("complete"), f"{label}_complete")
    match_count = observation.get("match_count")
    if type(match_count) is not int or match_count not in (0, 1):
        raise FinancialEngineInputError(f"{label}_match_count")
    _u64(writer, match_count, f"{label}_match_count")
    result_identity = observation.get("result_identity")
    if result_identity is None:
        writer.byte(0, f"{label}_result_identity")
    else:
        writer.byte(1, f"{label}_result_identity")
        _ident(writer, result_identity, f"{label}_result_identity")
    _u64(writer, observation.get("version_sequence"), f"{label}_version_sequence")
    _digest(writer, observation.get("version_head"), f"{label}_version_head")


def _write_sorted_ids(writer: Any, values: object, label: str, item_label: Any) -> None:
    if type(values) is not list or len(values) > semantic.MAX_WIRE_LIST:
        raise FinancialEngineInputError(label)
    writer.count(len(values), label)
    previous = ""
    for index, value in enumerate(values):
        current = item_label(index, value)
        if index and current <= previous:
            raise FinancialEngineInputError("receipt_evidence_order")
        previous = current


def _encode_correction_evaluation_receipt(receipt: Mapping[str, Any]) -> bytes:
    writer = semantic._WireWriter()
    writer.string(receipt.get("contract_version"), "receipt_contract")
    scope = receipt.get("scope")
    if type(scope) is not dict:
        raise FinancialEngineInputError("receipt_scope")
    for field in ("state_id", "deployment_id", "program_id", "period_id"):
        _ident(writer, scope.get(field), f"receipt_scope_{field}")
    writer.string(scope.get("currency"), "receipt_scope_currency", max_bytes=128)
    pack = receipt.get("control_pack")
    if type(pack) is not dict:
        raise FinancialEngineInputError("receipt_control_pack")
    _ident(writer, pack.get("pack_id"), "receipt_pack_id")
    _u64(writer, pack.get("version"), "receipt_pack_version")
    _digest(writer, pack.get("digest"), "receipt_pack_digest")

    def write_binding(index: int, binding: object) -> str:
        if type(binding) is not dict:
            raise FinancialEngineInputError("receipt_evidence_binding")
        evidence_id = _ident(writer, binding.get("evidence_id"), f"receipt_evidence_{index}_id")
        _digest(writer, binding.get("record_digest"), f"receipt_evidence_{index}_digest")
        return evidence_id

    _write_sorted_ids(writer, receipt.get("evidence_bindings"), "receipt_evidence_bindings", write_binding)
    snapshot_digest = _transition_digest(receipt.get("input_snapshot_digest"), "receipt_snapshot_digest")
    writer.byte(1, "receipt_snapshot_digest_tag")
    writer.digest(snapshot_digest, "receipt_snapshot_digest")
    authority = receipt.get("authority")
    if type(authority) is not dict:
        raise FinancialEngineInputError("receipt_authority")
    _u64(writer, authority.get("epoch"), "receipt_authority_epoch")
    _digest(writer, authority.get("digest"), "receipt_authority_digest")
    for field in ("evaluation_id", "obligation_id"):
        _ident(writer, receipt.get(field), f"receipt_{field}")
    _u64(writer, receipt.get("revision"), "receipt_revision")
    _u64(writer, receipt.get("rule_version"), "receipt_rule_version")
    _write_sorted_ids(
        writer,
        receipt.get("evidence_ids"),
        "receipt_evidence_ids",
        lambda index, value: _ident(writer, value, f"receipt_evidence_id_{index}"),
    )
    _ident(writer, receipt.get("authority_id"), "receipt_result_authority_id")
    _u64(writer, receipt.get("evaluated_at_ms"), "receipt_evaluated_at")
    for field in (
        "owed_cents", "claimed_adjustment_cents", "lawful_adjustment_cents",
        "received_cash_cents", "shortfall_cents", "overage_cents",
    ):
        _u64(writer, receipt.get(field), f"receipt_{field}")
    for field in ("cash_satisfied", "amount_satisfied", "timely", "reporting_complete"):
        value = receipt.get(field)
        if type(value) is not int or value not in (0, 1):
            raise FinancialEngineInputError(f"receipt_{field}")
        writer.boolean(bool(value), f"receipt_{field}")
    for field in ("verification_status", "case_status", "delivery_status"):
        _ident(writer, receipt.get(field), f"receipt_{field}")
    result_digest = _transition_digest(receipt.get("result_digest"), "receipt_result_digest")
    evaluation_result_digest = _transition_digest(
        receipt.get("evaluation_result_digest"), "receipt_evaluation_result_digest"
    )
    if result_digest != evaluation_result_digest:
        raise FinancialEngineInputError("receipt_result_digest_binding")
    writer.digest(result_digest, "receipt_result_digest")
    _digest(writer, receipt.get("receipt_digest"), "receipt_digest")
    writer.digest(evaluation_result_digest, "receipt_evaluation_result_digest")
    return writer.finish(label="engine_correction_receipt_size")


def _correction_input_bytes(body: dict[str, Any], *, expected_revision: int, action_lookup_kind: object) -> bytes:
    """Rebind the locked snapshot to the evaluation the command consumes."""

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
    try:
        return semantic.encode_blfin02_input(semantic._make_snapshot(body))
    except semantic.SemanticAdapterError:
        raise FinancialEngineInputError("engine_correction_snapshot") from None


def encode_correction_transition_request(
    *,
    snapshot: semantic.LockedSemanticSnapshot,
    command: Mapping[str, Any],
    action_lookup: Mapping[str, Any],
    query_observations: Mapping[str, Mapping[str, Any]],
    current_event_sequence: int,
    previous_history_head: bytes,
    payment_links: list[dict[str, Any]],
) -> bytes:
    """Encode the BLFCMD03 request from one locked Owner snapshot; payment_links names the correction
    request each linked payment row pays. Lean sums the rows and judges order, duplicates and targets."""

    if type(snapshot) is not semantic.LockedSemanticSnapshot:
        raise FinancialEngineInputError("engine_correction_snapshot_type")
    if type(command) is not dict or type(action_lookup) is not dict or type(query_observations) is not dict:
        raise FinancialEngineInputError("engine_correction_request_shape")
    expected_revision = command.get("expected_revision")
    if type(expected_revision) is not int or not 0 <= expected_revision <= 10_000:
        raise FinancialEngineInputError("engine_correction_expected_revision")
    try:
        body = snapshot.data
        current_receipt = body.get("current_evaluation", {}).get("receipt")
        if type(current_receipt) is not dict:
            raise FinancialEngineInputError("engine_correction_receipt_missing")
        receipt_bytes = _encode_correction_evaluation_receipt(current_receipt)
        current_input = _correction_input_bytes(
            body,
            expected_revision=expected_revision,
            action_lookup_kind=action_lookup.get("kind"),
        )

        writer = semantic._WireWriter()
        writer.raw(b"BLFCMD03", "engine_correction_magic")
        writer.raw((3).to_bytes(2, "big"), "engine_correction_version")
        writer.string(CORRECTION_TRANSITION_OPERATION, "engine_correction_contract")
        for field in ("item_id", "claim_id", "action_id", "actor_id"):
            _ident(writer, command.get(field), f"engine_correction_{field}")
        writer.role(command.get("actor_role"), "engine_correction_actor_role")
        _ident(writer, command.get("current_authority_id"), "engine_correction_authority_id")
        _u64(writer, command.get("current_authority_epoch"), "engine_correction_authority_epoch")
        _digest(writer, command.get("current_authority_digest"), "engine_correction_authority_digest")
        _u64(writer, expected_revision, "engine_correction_expected_revision")
        _ident(writer, command.get("evaluation_id"), "engine_correction_evaluation_id")
        _digest(writer, command.get("evaluation_result_digest"), "engine_correction_evaluation_digest")
        _u64(writer, command.get("decision_at_ms"), "engine_correction_decision_at")
        _u64(writer, command.get("owner_now_ms"), "engine_correction_owner_now")
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
        _u64(writer, current_event_sequence, "engine_correction_event_sequence")
        _digest(writer, previous_history_head, "engine_correction_history_head")
        writer.list(payment_links, "engine_correction_links", lambda link, label: (_ident(writer, link["payment_id"], label), _ident(writer, link["action_id"], label)))
        writer.raw(len(current_input).to_bytes(4, "big"), "engine_correction_input_length")
        writer.raw(current_input, "engine_correction_input")
        writer.raw(len(receipt_bytes).to_bytes(4, "big"), "engine_correction_receipt_length")
        writer.raw(receipt_bytes, "engine_correction_receipt")
        encoded = writer.finish(label="engine_correction_request_size")
    except semantic.SemanticAdapterError as error:
        raise FinancialEngineInputError(str(error)) from None
    return encoded


def _is_reparse_path(path: Path) -> bool:
    if path.is_symlink():
        return True
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except FileNotFoundError:
        return False
    if attributes & 0x400:  # FILE_ATTRIBUTE_REPARSE_POINT on Windows.
        return True
    is_junction = getattr(path, "is_junction", None)
    return bool(is_junction()) if callable(is_junction) else False


def load_correction_transition_release(
    executable_path: Path,
    workspace_path: Path,
) -> FinancialCorrectionTransitionRelease:
    """Bind an operator-named executable and workspace to the pinned v1 release.

    The one loader for the operator entry points (staff server, CLI).  The
    caller names the paths; identity comes only from the pins in this module,
    never from the environment.  Any mismatch raises ``ValueError``.
    """

    if (
        not isinstance(executable_path, Path)
        or not executable_path.is_absolute()
        or _is_reparse_path(executable_path)
        or not executable_path.is_file()
        or not isinstance(workspace_path, Path)
        or not workspace_path.is_absolute()
        or _is_reparse_path(workspace_path)
        or not workspace_path.is_dir()
    ):
        raise ValueError("correction_transition_paths")
    try:
        executable_size = executable_path.stat().st_size
        digest = hashlib.sha256()
        with executable_path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise ValueError("correction_transition_artifact_unavailable") from error
    executable_sha256 = digest.digest()
    if (
        executable_size != CORRECTION_TRANSITION_ARTIFACT_SIZE_BYTES
        or executable_sha256 != CORRECTION_TRANSITION_ARTIFACT_SHA256
    ):
        raise ValueError("correction_transition_artifact_identity")
    release = FinancialCorrectionTransitionRelease(
        executable=executable_path,
        executable_size_bytes=executable_size,
        executable_sha256=executable_sha256,
        request_vector_sha256=CORRECTION_TRANSITION_REQUEST_VECTOR_SHA256,
        result_vector_sha256=CORRECTION_TRANSITION_RESULT_VECTOR_SHA256,
        timeout_seconds=30.0,
        input_max_bytes=MAX_CORRECTION_TRANSITION_BYTES,
        output_max_bytes=MAX_CORRECTION_TRANSITION_BYTES,
        stderr_max_bytes=process.MAX_STDERR_BYTES,
        workspace=workspace_path,
        job_memory_cap_bytes=min(MAX_ENGINE_JOB_MEMORY_CAP_BYTES, process.ADMISSION_CAP_BYTES),
    )
    return require_correction_transition_v1(release)


def require_correction_transition_v1(release: object | None) -> FinancialCorrectionTransitionRelease:
    """Require the immutable v1 release bound to the pinned artifact and vectors."""

    if release is None:
        raise FinancialEngineTransitionUnavailable("engine_correction_transition_release_required")
    if type(release) is not FinancialCorrectionTransitionRelease:
        raise FinancialEngineConfigError("engine_correction_transition_release_type")
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


_PREDICATE_TAGS: Final[dict[int, str]] = {1: "ACTION_ID", 2: "DETERMINATION_ID", 3: "EVALUATION_CONSUMED"}
_CLAIM_STATUS_TAGS: Final[dict[int, str]] = {1: "CLAIMED", 2: "AUTHORIZED", 3: "REJECTED"}
_DECISION_TAGS: Final[dict[int, str]] = {1: "OFFSET_AUTHORIZED", 2: "OFFSET_REJECTED_CORRECTION_AUTHORIZED"}
_ACTION_STATUS_TAGS: Final[dict[int, str]] = {1: "READY", 2: "ACKNOWLEDGED", 3: "CANCELLED"}
_CASE_STATUS_TAGS: Final[dict[int, str]] = {1: "OPEN", 2: "AUTHORIZED", 3: "CORRECTION_REQUIRED", 4: "ACTIONED", 5: "RESOLVED"}
_EFFECT_TAGS: Final[dict[int, str]] = {
    1: "DETERMINATION_RECORDED", 2: "CLAIM_REJECTED", 3: "CASE_UPSERTED", 4: "ACTION_CREATED",
    5: "OUTBOX_CREATED", 6: "PROJECTION_RECOMPUTED", 7: "EVENT_APPENDED",
}
_EXPLANATION_CODE_TAGS: Final[dict[int, str]] = {1: "CORRECTION_AUTHORIZED", 2: "EXACT_RETRY", 3: "REJECTED"}
_TRANSITION_KIND_TAGS: Final[dict[int, str]] = {1: "OFFSET_REJECTED_CORRECTION_AUTHORIZED"}
_RESULT_STATUS_TAGS: Final[dict[int, str]] = {1: "ACCEPTED", 2: "DUPLICATE", 3: "REJECTED"}


# Decoding helpers.  Reader codec failures surface as
# FinancialEngineResultError(<wire label>) from decode_correction_transition_result.
def _read_transition_nat(reader: Any, label: str) -> int:
    value = reader.nat(label)
    if value > _MAX_SQLITE_INTEGER:
        raise FinancialEngineResultError(label)
    return value


def _read_optional_transition_nat(reader: Any, label: str) -> int | None:
    value = reader.option_nat(label)
    if value is not None and value > _MAX_SQLITE_INTEGER:
        raise FinancialEngineResultError(label)
    return value


def _read_optional_transition_text(reader: Any, label: str) -> str | None:
    tag = reader.byte(f"{label}_tag")
    if tag == 0:
        return None
    if tag != 1:
        raise FinancialEngineResultError(label)
    return reader.string(label)


def _read_correction_query_observation(reader: Any, label: str) -> dict[str, Any]:
    predicate = _PREDICATE_TAGS.get(reader.byte(f"{label}_predicate"))
    if predicate is None:
        raise FinancialEngineResultError(f"{label}_predicate")
    subject = reader.identifier(f"{label}_subject")
    complete = reader.boolean(f"{label}_complete")
    match_count = _read_transition_nat(reader, f"{label}_match_count")
    if match_count > 1:
        raise FinancialEngineResultError(f"{label}_match_count")
    result_identity = reader.option_identifier(f"{label}_result_identity")
    if (match_count == 0) != (result_identity is None):
        raise FinancialEngineResultError(f"{label}_result_identity")
    version_sequence = _read_transition_nat(reader, f"{label}_version_sequence")
    version_head = reader.digest(f"{label}_version_head")
    return {
        "predicate": predicate,
        "subject": subject,
        "complete": complete,
        "match_count": match_count,
        "result_identity": result_identity,
        "version_sequence": version_sequence,
        "version_head": version_head,
    }


def _read_correction_query_observations(reader: Any) -> dict[str, dict[str, Any]]:
    return {
        "action_id": _read_correction_query_observation(reader, "action_query"),
        "determination_id": _read_correction_query_observation(reader, "determination_query"),
        "evaluation_consumed": _read_correction_query_observation(reader, "evaluation_consumed_query"),
    }


def _read_correction_claim(reader: Any, label: str = "claim") -> dict[str, Any]:
    claim = {
        "claim_id": reader.identifier(f"{label}_id"),
        "obligation_id": reader.identifier(f"{label}_obligation"),
        "evidence_id": reader.identifier(f"{label}_evidence"),
        "amount_cents": _read_transition_nat(reader, f"{label}_amount"),
        "owner_role": reader.role(f"{label}_owner_role"),
        "deadline_at_ms": _read_transition_nat(reader, f"{label}_deadline"),
    }
    status = _CLAIM_STATUS_TAGS.get(reader.byte(f"{label}_status"))
    if status is None:
        raise FinancialEngineResultError(f"{label}_status")
    claim["status"] = status
    return claim


def _read_correction_evidence_binding(reader: Any, label: str) -> dict[str, Any]:
    return {
        "evidence_id": reader.identifier(f"{label}_id"),
        "record_digest": reader.digest(f"{label}_digest"),
    }


def _read_correction_dependency_facts(reader: Any) -> dict[str, Any]:
    artifact_contract = reader.string("dependency_artifact_contract")
    artifact_version = _read_transition_nat(reader, "dependency_artifact_version")
    authority_id = reader.identifier("dependency_authority_id")
    authority_epoch = _read_transition_nat(reader, "dependency_authority_epoch")
    authority_digest = reader.digest("dependency_authority_digest")
    control_pack_id = reader.identifier("dependency_pack_id")
    control_pack_version = _read_transition_nat(reader, "dependency_pack_version")
    control_pack_digest = reader.digest("dependency_pack_digest")
    input_evaluation_id = reader.identifier("dependency_evaluation_id")
    input_evaluation_result_digest = reader.digest("dependency_evaluation_digest")
    input_evaluation_revision = _read_transition_nat(reader, "dependency_evaluation_revision")
    input_evaluation_evaluated_at_ms = _read_transition_nat(reader, "dependency_evaluation_time")
    input_evaluation_snapshot_digest = reader.digest("dependency_snapshot_digest")
    input_shortfall_cents = _read_transition_nat(reader, "dependency_input_shortfall")
    decision_at_ms = _read_transition_nat(reader, "dependency_decision_time")
    owner_now_ms = _read_transition_nat(reader, "dependency_owner_now")
    claim_before = _read_correction_claim(reader, "dependency_claim")
    supporting_evidence = reader.list(
        "dependency_supporting_evidence",
        lambda label: _read_correction_evidence_binding(reader, label),
    )
    if len(supporting_evidence) > 10_000:
        raise FinancialEngineResultError("dependency_supporting_evidence_limit")
    observations = _read_correction_query_observations(reader)
    current_event_sequence = _read_transition_nat(reader, "dependency_event_sequence")
    previous_history_head = reader.digest("dependency_history_head")
    correction_paid = reader.list(
        "dependency_correction_paid",
        lambda label: {"action_id": reader.identifier(f"{label}_id"), "paid_cents": _read_transition_nat(reader, f"{label}_cents")},
    )
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
        "input_shortfall_cents": input_shortfall_cents,
        "decision_at_ms": decision_at_ms,
        "owner_now_ms": owner_now_ms,
        "claim_before": claim_before,
        "supporting_evidence": supporting_evidence,
        "query_observations": observations,
        "current_event_sequence": current_event_sequence,
        "previous_history_head": previous_history_head,
        "correction_paid": correction_paid,
    }


def _read_correction_followups(reader: Any) -> dict[str, Any]:
    action_id = reader.identifier("followup_action_id")
    outbox_action_id = reader.identifier("followup_outbox_action_id")
    case_id = reader.identifier("followup_case_id")
    resulting_evaluation_id = reader.identifier("followup_evaluation_id")
    event_sequence = _read_transition_nat(reader, "followup_event_sequence")
    return {
        "action_id": action_id,
        "outbox_action_id": outbox_action_id,
        "case_id": case_id,
        "resulting_evaluation_id": resulting_evaluation_id,
        "event_sequence": event_sequence,
    }


def _read_correction_determination(reader: Any) -> dict[str, Any]:
    determination = {
        "determination_id": reader.identifier("determination_id"),
        "obligation_id": reader.identifier("determination_obligation_id"),
        "claim_id": reader.identifier("determination_claim_id"),
        "actor_id": reader.identifier("determination_actor_id"),
        "actor_role": reader.role("determination_actor_role"),
        "authority_id": reader.identifier("determination_authority_id"),
        "authority_epoch": _read_transition_nat(reader, "determination_authority_epoch"),
        "authority_digest": reader.digest("determination_authority_digest"),
    }
    decision = _DECISION_TAGS.get(reader.byte("determination_decision"))
    if decision is None:
        raise FinancialEngineResultError("determination_decision")
    determination["decision"] = decision
    determination["amount_cents"] = _read_transition_nat(reader, "determination_amount")
    determination["supporting_evidence_ids"] = reader.list(
        "determination_supporting_evidence",
        lambda label: reader.identifier(label),
    )
    determination["expected_revision"] = _read_transition_nat(reader, "determination_expected_revision")
    determination["resulting_revision"] = _read_transition_nat(reader, "determination_resulting_revision")
    determination["decided_at_ms"] = _read_transition_nat(reader, "determination_decided_at")
    return determination


def _read_correction_action(reader: Any) -> dict[str, Any]:
    action_id = reader.identifier("action_id")
    obligation_id = reader.identifier("action_obligation_id")
    determination_id = reader.option_identifier("action_determination_id")
    kind = reader.identifier("action_kind")
    amount_cents = _read_transition_nat(reader, "action_amount")
    currency = reader.string("action_currency", max_bytes=128)
    revision = _read_transition_nat(reader, "action_revision")
    status = _ACTION_STATUS_TAGS.get(reader.byte("action_status"))
    if status is None:
        raise FinancialEngineResultError("action_status")
    payload_digest = reader.digest("action_payload_digest")
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


def _read_correction_case(reader: Any) -> dict[str, Any]:
    case_record = {
        "case_id": reader.identifier("case_id"),
        "obligation_id": reader.identifier("case_obligation_id"),
        "reason": reader.identifier("case_reason"),
        "next_action_owner": reader.role("case_next_action_owner"),
        "due_at_ms": _read_transition_nat(reader, "case_due_at"),
    }
    status = _CASE_STATUS_TAGS.get(reader.byte("case_status"))
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
        "owner_id": reader.identifier("result_owner_id"),
        "mode": semantic._read_tag(reader, semantic._MODE_TAGS, "result_mode"),
        "provenance": semantic._read_tag(reader, semantic._PROVENANCE_TAGS, "result_provenance"),
        "state_id": reader.identifier("result_state_id"),
        "deployment_id": reader.identifier("result_deployment_id"),
        "program_id": reader.identifier("result_program_id"),
        "period_id": reader.identifier("result_period_id"),
        "population_id": reader.identifier("result_population_id"),
        "item_id": reader.identifier("result_item_id"),
        "obligation_id": reader.identifier("result_obligation_id"),
        "currency": reader.string("result_currency", max_bytes=128),
    }
    result = semantic.DecodedLeanResult(
        **context,
        authority_id=reader.identifier("result_authority_id"),
        authority_epoch=_read_transition_nat(reader, "result_authority_epoch"),
        authority_digest=reader.digest("result_authority_digest"),
        pack_id=reader.identifier("result_pack_id"),
        pack_digest=reader.digest("result_pack_digest"),
        before_revision=_read_transition_nat(reader, "result_before_revision"),
        after_revision=_read_transition_nat(reader, "result_after_revision"),
        evaluated_at_ms=_read_transition_nat(reader, "result_evaluated_at"),
        rule_version=_read_transition_nat(reader, "result_rule_version"),
        evidence_ids=tuple(
            reader.list("result_evidence_ids", lambda label: reader.identifier(label))
        ),
        completion_at_ms=_read_optional_transition_nat(reader, "result_completion_at"),
        owed_cents=_read_transition_nat(reader, "result_owed_cents"),
        claimed_adjustment_cents=_read_transition_nat(reader, "result_claimed_adjustment_cents"),
        lawful_adjustment_cents=_read_transition_nat(reader, "result_lawful_adjustment_cents"),
        received_cash_cents=_read_transition_nat(reader, "result_received_cash_cents"),
        shortfall_cents=_read_transition_nat(reader, "result_shortfall_cents"),
        overage_cents=_read_transition_nat(reader, "result_overage_cents"),
        cash_satisfied=reader.boolean("result_cash_satisfied"),
        amount_satisfied=reader.boolean("result_amount_satisfied"),
        timely=reader.boolean("result_timely"),
        reporting_complete=reader.boolean("result_reporting_complete"),
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


def _read_correction_mutation(reader: Any) -> dict[str, Any] | None:
    tag = reader.byte("correction_mutation_tag")
    if tag == 0:
        return None
    if tag != 1:
        raise FinancialEngineResultError("engine_correction_mutation_tag")
    transition_tag = reader.byte("correction_transition_kind")
    if transition_tag != 1:
        raise FinancialEngineResultError("engine_correction_transition_kind")
    def read_effect(_label: str) -> str:
        value = _EFFECT_TAGS.get(reader.byte("correction_effect"))
        if value is None:
            raise FinancialEngineResultError("engine_correction_effect")
        return value

    ordered_effects = reader.list("correction_effects", read_effect)
    if len(ordered_effects) > 16:
        raise FinancialEngineResultError("engine_correction_effect_limit")
    dependencies = _read_correction_dependency_facts(reader)
    followups = _read_correction_followups(reader)
    input_size = int.from_bytes(reader.take(4, "correction_input_size"), "big")
    if input_size > MAX_CORRECTION_TRANSITION_BYTES:
        raise FinancialEngineResultError("engine_correction_input_size")
    resulting_input = reader.take(input_size, "correction_resulting_input")
    if not resulting_input.startswith(semantic.BLFIN02_MAGIC):
        raise FinancialEngineResultError("engine_correction_resulting_input_magic")
    result_size = int.from_bytes(reader.take(4, "correction_result_size"), "big")
    if result_size > MAX_CORRECTION_TRANSITION_BYTES:
        raise FinancialEngineResultError("engine_correction_result_size")
    resulting_result_wire = reader.take(result_size, "correction_resulting_result")
    resulting_result = _decode_correction_financial_result(resulting_result_wire)
    determination = _read_correction_determination(reader)
    action = _read_correction_action(reader)
    case_record = _read_correction_case(reader)
    contractual_accountability = reader.identifier("correction_case_accountability")
    completion_amount = reader.boolean("correction_case_amount_complete")
    completion_reporting = reader.boolean("correction_case_reporting_complete")
    completion_delivery = reader.boolean("correction_case_delivery_complete")
    inserted = reader.boolean("correction_case_inserted")
    case_delta = {
        "record": case_record,
        "contractual_accountability": contractual_accountability,
        "completion_conditions_amount_satisfied": completion_amount,
        "completion_conditions_reporting_complete": completion_reporting,
        "completion_conditions_delivery_acknowledged_or_not_required": completion_delivery,
        "inserted": inserted,
    }
    outbox_action_id = reader.identifier("correction_outbox_action_id")
    outbox_status = _ACTION_STATUS_TAGS.get(reader.byte("correction_outbox_status"))
    if outbox_status is None:
        raise FinancialEngineResultError("engine_correction_outbox_status")
    outbox_attempt = _read_transition_nat(reader, "correction_outbox_attempt")
    acknowledgment_reference = _read_optional_transition_text(reader, "correction_outbox_acknowledgment")
    outbox_updated_at_ms = _read_transition_nat(reader, "correction_outbox_updated_at")
    outbox = {
        "action_id": outbox_action_id,
        "status": outbox_status,
        "attempt": outbox_attempt,
        "acknowledgment_reference": acknowledgment_reference,
        "updated_at_ms": outbox_updated_at_ms,
    }
    event_sequence = _read_transition_nat(reader, "correction_event_sequence")
    event_previous_head = reader.digest("correction_event_previous_head")
    event_aggregate_type = reader.identifier("correction_event_aggregate_type")
    event_aggregate_id = reader.identifier("correction_event_aggregate_id")
    event_kind = reader.identifier("correction_event_kind")
    event_before_revision = _read_transition_nat(reader, "correction_event_before_revision")
    event_after_revision = _read_transition_nat(reader, "correction_event_after_revision")
    event_committed_at_ms = _read_transition_nat(reader, "correction_event_committed_at")
    event = {
        "sequence": event_sequence,
        "previous_head": event_previous_head,
        "aggregate_type": event_aggregate_type,
        "aggregate_id": event_aggregate_id,
        "kind": event_kind,
        "before_revision": event_before_revision,
        "after_revision": event_after_revision,
        "committed_at_ms": event_committed_at_ms,
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
        "action": action,
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
    20: "NO_SHORTFALL",
    21: "NO_REQUESTABLE_BALANCE",
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
    20: "POSITIVE_SHORTFALL",
    21: "UNREQUESTED_SHORTFALL",
}
# Lean's requiredTransitionCondition pairs each reject reason with the requirement of the same tag.
_CORRECTION_REJECT_REQUIREMENTS: Final[dict[str, str]] = {
    reason: _CORRECTION_REQUIREMENT_TAGS[tag] for tag, reason in _CORRECTION_REJECT_REASON_TAGS.items()
}


def _read_optional_correction_tag(reader: Any, tags: Mapping[int, str], label: str) -> str | None:
    tag = reader.byte(f"{label}_tag")
    if tag == 0:
        return None
    if tag != 1:
        raise FinancialEngineResultError(label)
    value = tags.get(reader.byte(label))
    if value is None:
        raise FinancialEngineResultError(label)
    return value


def _read_correction_explanation(reader: Any) -> dict[str, Any]:
    code = _EXPLANATION_CODE_TAGS.get(reader.byte("correction_explanation_code"))
    if code is None:
        raise FinancialEngineResultError("engine_correction_explanation_code")
    transition_tag = reader.byte("correction_explanation_transition_tag")
    if transition_tag == 0:
        transition = None
    elif transition_tag == 1:
        transition = _TRANSITION_KIND_TAGS.get(reader.byte("correction_explanation_transition"))
        if transition is None:
            raise FinancialEngineResultError("engine_correction_explanation_transition")
    else:
        raise FinancialEngineResultError("engine_correction_explanation_transition_tag")
    return {
        "code": code,
        "transition": transition,
        "reject_reason": _read_optional_correction_tag(reader, _CORRECTION_REJECT_REASON_TAGS, "correction_explanation_reject_reason"),
        "unresolved_requirement": _read_optional_correction_tag(reader, _CORRECTION_REQUIREMENT_TAGS, "correction_explanation_requirement"),
        "claim_id": reader.option_identifier("correction_explanation_claim"),
        "action_id": reader.option_identifier("correction_explanation_action"),
        "input_evaluation_id": reader.option_identifier("correction_explanation_evaluation"),
        "expected_revision": _read_optional_transition_nat(reader, "correction_explanation_expected_revision"),
        "resulting_revision": _read_optional_transition_nat(reader, "correction_explanation_resulting_revision"),
    }


# Re-encoder: a decoded BLFCRES3 value must encode back to the exact bytes Lean wrote, so a decoder that
# drops, defaults or normalises anything is refused (V.3).  A field kind is a _WireWriter method name, a tag
# table, or a one-tuple holding a tag table for an optional tag.
_EXPLANATION_FIELDS: Final = (
    ("code", _EXPLANATION_CODE_TAGS), ("transition", (_TRANSITION_KIND_TAGS,)),
    ("reject_reason", (_CORRECTION_REJECT_REASON_TAGS,)), ("unresolved_requirement", (_CORRECTION_REQUIREMENT_TAGS,)),
    ("claim_id", "option_identifier"), ("action_id", "option_identifier"), ("input_evaluation_id", "option_identifier"),
    ("expected_revision", "option_nat"), ("resulting_revision", "option_nat"),
)
_DEPENDENCY_FIELDS: Final = (
    ("artifact_contract", "string"), ("artifact_version", "nat"), ("authority_id", "identifier"), ("authority_epoch", "nat"),
    ("authority_digest", "digest"), ("control_pack_id", "identifier"), ("control_pack_version", "nat"),
    ("control_pack_digest", "digest"), ("input_evaluation_id", "identifier"), ("input_evaluation_result_digest", "digest"),
    ("input_evaluation_revision", "nat"), ("input_evaluation_evaluated_at_ms", "nat"),
    ("input_evaluation_snapshot_digest", "digest"), ("input_shortfall_cents", "nat"), ("decision_at_ms", "nat"),
    ("owner_now_ms", "nat"),
)
_CLAIM_FIELDS: Final = (
    ("claim_id", "identifier"), ("obligation_id", "identifier"), ("evidence_id", "identifier"), ("amount_cents", "nat"),
    ("owner_role", "role"), ("deadline_at_ms", "nat"), ("status", _CLAIM_STATUS_TAGS),
)
_OBSERVATION_FIELDS: Final = (
    ("predicate", _PREDICATE_TAGS), ("subject", "identifier"), ("complete", "boolean"), ("match_count", "nat"),
    ("result_identity", "option_identifier"), ("version_sequence", "nat"), ("version_head", "digest"),
)
_FOLLOWUP_FIELDS: Final = (
    ("action_id", "identifier"), ("outbox_action_id", "identifier"), ("case_id", "identifier"),
    ("resulting_evaluation_id", "identifier"), ("event_sequence", "nat"),
)
_DETERMINATION_HEAD: Final = (
    ("determination_id", "identifier"), ("obligation_id", "identifier"), ("claim_id", "identifier"),
    ("actor_id", "identifier"), ("actor_role", "role"), ("authority_id", "identifier"), ("authority_epoch", "nat"),
    ("authority_digest", "digest"), ("decision", _DECISION_TAGS), ("amount_cents", "nat"),
)
_DETERMINATION_TAIL: Final = (("expected_revision", "nat"), ("resulting_revision", "nat"), ("decided_at_ms", "nat"))
_ACTION_FIELDS: Final = (
    ("action_id", "identifier"), ("obligation_id", "identifier"), ("determination_id", "option_identifier"),
    ("kind", "identifier"), ("amount_cents", "nat"), ("currency", "string"), ("revision", "nat"),
    ("status", _ACTION_STATUS_TAGS), ("payload_digest", "digest"), ("created_at_ms", "nat"),
)
_CASE_FIELDS: Final = (
    ("case_id", "identifier"), ("obligation_id", "identifier"), ("reason", "identifier"), ("next_action_owner", "role"),
    ("due_at_ms", "nat"), ("status", _CASE_STATUS_TAGS), ("updated_at_ms", "nat"),
)
_CASE_DELTA_FIELDS: Final = (
    ("contractual_accountability", "identifier"), ("completion_conditions_amount_satisfied", "boolean"),
    ("completion_conditions_reporting_complete", "boolean"),
    ("completion_conditions_delivery_acknowledged_or_not_required", "boolean"), ("inserted", "boolean"),
)
_EVENT_FIELDS: Final = (
    ("sequence", "nat"), ("previous_head", "digest"), ("aggregate_type", "identifier"), ("aggregate_id", "identifier"),
    ("kind", "identifier"), ("before_revision", "nat"), ("after_revision", "nat"), ("committed_at_ms", "nat"),
)


def _tag_of(table: Mapping[int, str], value: str) -> int:
    return {name: tag for tag, name in table.items()}[value]


def _put(writer: Any, record: Mapping[str, Any], fields: tuple[tuple[str, Any], ...]) -> None:
    for key, kind in fields:
        value = record[key]
        if type(kind) is str:
            getattr(writer, kind)(value, key)
        elif type(kind) is tuple:
            writer.byte(int(value is not None), key)
            if value is not None:
                writer.byte(_tag_of(kind[0], value), key)
        else:
            writer.byte(_tag_of(kind, value), key)


def _encode_correction_transition_result(result: Mapping[str, Any]) -> bytes:
    writer = semantic._WireWriter()
    writer.raw(b"BLFCRES3\x00\x03", "correction_result_header")
    _put(writer, result, (("status", _RESULT_STATUS_TAGS),))
    writer.string(CORRECTION_TRANSITION_OPERATION, "correction_result_contract")
    _put(writer, result, (("reject_reason", (_CORRECTION_REJECT_REASON_TAGS,)),))
    _put(writer, result["explanation"], _EXPLANATION_FIELDS)
    _put(writer, result, (("action_id", "option_identifier"), ("determination_id", "option_identifier")))
    mutation = result["mutation"]
    if mutation is None:
        writer.byte(0, "correction_mutation_tag")
        return writer.finish(label="correction_result_size")
    writer.raw(b"\x01\x01", "correction_mutation_tag")  # present, and the one transition kind
    writer.list(mutation["ordered_effects"], "correction_effects", lambda value, label: writer.byte(_tag_of(_EFFECT_TAGS, value), label))
    dependencies = mutation["dependencies"]
    _put(writer, dependencies, _DEPENDENCY_FIELDS)
    _put(writer, dependencies["claim_before"], _CLAIM_FIELDS)
    writer.list(
        dependencies["supporting_evidence"], "dependency_supporting_evidence",
        lambda value, _label: _put(writer, value, (("evidence_id", "identifier"), ("record_digest", "digest"))),
    )
    for observation in dependencies["query_observations"].values():
        _put(writer, observation, _OBSERVATION_FIELDS)
    _put(writer, dependencies, (("current_event_sequence", "nat"), ("previous_history_head", "digest")))
    writer.list(
        dependencies["correction_paid"], "dependency_correction_paid",
        lambda value, _label: _put(writer, value, (("action_id", "identifier"), ("paid_cents", "nat"))),
    )
    _put(writer, mutation["followups"], _FOLLOWUP_FIELDS)
    for name in ("resulting_input_wire", "resulting_result_wire"):
        writer.raw(len(mutation[name]).to_bytes(4, "big") + mutation[name], name)
    determination = mutation["determination"]
    _put(writer, determination, _DETERMINATION_HEAD)
    writer.list(determination["supporting_evidence_ids"], "determination_supporting_evidence", writer.identifier)
    _put(writer, determination, _DETERMINATION_TAIL)
    _put(writer, mutation["action"], _ACTION_FIELDS)
    _put(writer, mutation["case_delta"]["record"], _CASE_FIELDS)
    _put(writer, mutation["case_delta"], _CASE_DELTA_FIELDS)
    outbox = mutation["outbox"]
    _put(writer, outbox, (("action_id", "identifier"), ("status", _ACTION_STATUS_TAGS), ("attempt", "nat")))
    writer.byte(int(outbox["acknowledgment_reference"] is not None), "correction_outbox_acknowledgment_tag")
    if outbox["acknowledgment_reference"] is not None:
        writer.string(outbox["acknowledgment_reference"], "correction_outbox_acknowledgment")
    writer.nat(outbox["updated_at_ms"], "correction_outbox_updated_at")
    _put(writer, mutation["event"], _EVENT_FIELDS)
    return writer.finish(label="correction_result_size")


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
        observations = deps["query_observations"]
        if (
            determination_id != transition_id
            or det["determination_id"] != determination_id
            or det["decision"] != "OFFSET_REJECTED_CORRECTION_AUTHORIZED"
            or det["amount_cents"] <= 0
            or det["resulting_revision"] != det["expected_revision"] + 1
            or action["action_id"] != action_id
            or action["determination_id"] != determination_id
            or action["kind"] != "CORRECTION_PAYMENT_REQUEST"
            or action["status"] != "READY"
            or deps["input_shortfall_cents"] <= 0
            or outbox["action_id"] != action_id
            or outbox["status"] != "READY"
            or outbox["attempt"] != 0
            or outbox["acknowledgment_reference"] is not None
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
        ):
            raise FinancialEngineResultError("engine_correction_absence_binding")
        financial_result = mutation["resulting_result"]
        if (
            financial_result.before_revision != det["expected_revision"]
            or financial_result.after_revision != det["resulting_revision"]
            or financial_result.evaluated_at_ms != event["committed_at_ms"]
            or financial_result.obligation_id != det["obligation_id"]
            or financial_result.delivery_status != "READY"
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

    if reject_reason is None or mutation is not None:
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
    """Strictly decode one BLFCRES3 value and reject any trailing bytes."""

    try:
        reader = semantic._WireReader(payload, max_bytes=MAX_CORRECTION_TRANSITION_BYTES)
        if reader.take(8, "correction_result_magic") != b"BLFCRES3":
            raise FinancialEngineResultError("engine_correction_result_magic")
        if int.from_bytes(reader.take(2, "correction_result_version"), "big") != 3:
            raise FinancialEngineResultError("engine_correction_result_version")
        status = _RESULT_STATUS_TAGS.get(reader.byte("correction_result_status"))
        if status is None:
            raise FinancialEngineResultError("engine_correction_result_status")
        contract = reader.string("correction_result_contract")
        if contract != CORRECTION_TRANSITION_OPERATION:
            raise FinancialEngineResultError("engine_correction_result_contract")
        reject_reason = _read_optional_correction_tag(reader, _CORRECTION_REJECT_REASON_TAGS, "correction_result_reject_reason")
        explanation = _read_correction_explanation(reader)
        action_id = reader.option_identifier("correction_result_action_id")
        determination_id = reader.option_identifier("correction_result_determination_id")
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
        if _encode_correction_transition_result(result) != payload:
            raise FinancialEngineResultError("engine_correction_result_canonical")
        return result
    except FinancialEngineResultError:
        raise
    except semantic.SemanticAdapterError as error:
        raise FinancialEngineResultError(str(error)) from None
    except (KeyError, TypeError, ValueError, UnicodeError, OverflowError, IndexError):
        raise FinancialEngineResultError("engine_correction_result_shape") from None


def run_correction_transition_v1(
    release: object | None,
    *,
    request: bytes,
) -> FinancialCorrectionTransitionExecution:
    """Run only the fully pinned transition through the contained lane."""

    configured = require_correction_transition_v1(release)
    # The launcher dereferences the release, so it fails closed here on
    # anything that is not the pinned release type, even if the gate above was
    # bypassed; never an AttributeError (Art. V.2, XI.10).
    if configured is None:
        raise FinancialEngineTransitionUnavailable("engine_correction_transition_release_required")
    if type(configured) is not FinancialCorrectionTransitionRelease:
        raise FinancialEngineConfigError("engine_correction_transition_release_type")
    if (
        type(request) is not bytes
        or not request.startswith(b"BLFCMD03")
        or not 0 < len(request) <= configured.input_max_bytes
    ):
        raise FinancialEngineInputError("engine_correction_request_contract")
    contained = _run_pinned(
        configured,
        CORRECTION_TRANSITION_ARGUMENTS,
        request,
        failure_code="engine_correction_containment",
    )
    return FinancialCorrectionTransitionExecution(
        result=decode_correction_transition_result(contained.stdout),
        **_execution_fields(configured, request, contained),
    )


# --- Live evaluator: one long-lived Lean worker decides every owner evaluation ---

EVALUATOR_PATH: Final[Path] = Path(__file__).resolve().parents[1] / "artifacts" / "engine-evaluator" / "blind_financial_worker.exe"
EVALUATOR_ARTIFACT_SIZE_BYTES: Final[int] = 6_460_416
EVALUATOR_ARTIFACT_SHA256: Final[bytes] = bytes.fromhex(
    "5CA5A67CD5D80F4A2D0EAED7F3EDB75D21F2470F0C07C8558FC21079EBFFA097"
)
EVALUATOR_JOB_MEMORY_CAP_BYTES: Final[int] = 1_000_000_000
EVALUATOR_TIMEOUT_SECONDS: Final[float] = 5.0
EVALUATOR_RECYCLE_REQUESTS: Final[int] = 1000  # backstop: a long-lived worker is replaced between requests,
EVALUATOR_RECYCLE_COMMIT_BYTES: Final[int] = 400_000_000  # never mid-request, so slow growth never reaches the job cap
_EVALUATOR_REJECTIONS: Final[dict[int, str]] = {
    1: "evaluator_input_rejected",
    2: "evaluator_evaluation_rejected",
    3: "evaluator_result_rejected",
}
_evaluator_lock = threading.Lock()
_evaluator: list[Any] = []  # [ContainedWorker, workspace] while one is running
_evaluator_requests = 0


def _close_evaluator() -> None:
    global _evaluator_requests
    _evaluator_requests = 0
    if _evaluator:
        worker, workspace = _evaluator
        _evaluator.clear()
        worker.close()
        shutil.rmtree(workspace, ignore_errors=True)


def _running_evaluator() -> process.ContainedWorker:
    if _evaluator and not _evaluator[0].alive:
        _close_evaluator()
    if not _evaluator:
        if _is_reparse_path(EVALUATOR_PATH):
            raise process.VerifierProcessError("evaluator_path")
        workspace = Path(tempfile.mkdtemp(prefix="rr-evaluator-"))
        try:
            worker = process.launch_contained_worker(
                EVALUATOR_PATH,
                workspace=workspace,
                job_memory_cap_bytes=EVALUATOR_JOB_MEMORY_CAP_BYTES,
                expected_executable_size_bytes=EVALUATOR_ARTIFACT_SIZE_BYTES,
                expected_executable_sha256=EVALUATOR_ARTIFACT_SHA256,
            )
        except BaseException:
            shutil.rmtree(workspace, ignore_errors=True)
            raise
        _evaluator.extend((worker, workspace))
    return _evaluator[0]


atexit.register(_close_evaluator)


def _evaluate_wire(wire: bytes) -> bytes:
    """Lean ``evaluate`` on one BLFIN02 input: the BLFRES02 answer.  Any rejection or transport
    failure is an error; a failed worker is replaced on the next use, never retried here."""

    global _evaluator_requests
    with _evaluator_lock:
        try:
            worker = _running_evaluator()
            response = worker.exchange(
                wire, response_cap_bytes=semantic.MAX_WIRE_BYTES + 1, timeout_seconds=EVALUATOR_TIMEOUT_SECONDS,
            )
            _evaluator_requests += 1
            if _evaluator_requests >= EVALUATOR_RECYCLE_REQUESTS or worker.commit_bytes() > EVALUATOR_RECYCLE_COMMIT_BYTES:
                _close_evaluator()
        except process.VerifierProcessError:
            raise FinancialEngineContainmentError("evaluator_containment") from None
    if response[0] in _EVALUATOR_REJECTIONS and len(response) == 1:
        raise FinancialEngineResultError(_EVALUATOR_REJECTIONS[response[0]])
    if response[0] != 0:
        raise FinancialEngineResultError("evaluator_response")
    return response[1:]


def evaluate_live(
    connection: sqlite3.Connection,
    *,
    obligation_id: str,
    authority_context: semantic.TrustedAuthorityContext,
    evaluation_time_ms: int,
    verification: Mapping[str, object],
) -> semantic.DecodedLeanResult:
    """The owner's live decision: BLFIN02 from its transaction, Lean decides, BLFRES02 bound back."""

    wire, data = semantic.live_evaluation_input(
        connection,
        obligation_id=obligation_id,
        authority_context=authority_context,
        evaluation_time_ms=evaluation_time_ms,
        verification=verification,
    )
    answer = _evaluate_wire(wire)
    try:
        return semantic.decode_live_result(answer, data)
    except BaseException:
        with _evaluator_lock:  # an answer that does not bind to this request may mean the worker is out of step
            _close_evaluator()
        raise
