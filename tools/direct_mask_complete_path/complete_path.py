"""One nonactivating Profile 12 source-to-State-to-ACK integration path.

The valid path intentionally keeps the source capsule and verifier IPC in
memory.  Only typed native-process measurements and durable State/composition
projections leave the path.  The receiver and State port below are synthetic
test authorities: they exercise the existing runtime seams without claiming
official authority, production qualification, Lean linkage, or activation.
"""

from __future__ import annotations

from contextlib import closing, contextmanager
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import sqlite3
import stat
import tempfile
import time
from typing import Any, Mapping

import app.minimal_clearance_composition as composition
import app.minimal_clearance_composition_independent as composition_independent
import app.minimal_clearance_source_auth_verifier_adapter as adapter_module
import app.minimal_clearance_verification_queue_independent as queue_independent
import app.minimal_clearance_verification_runtime as runtime_module
from app.minimal_clearance_composition import (
    CompositionConfigV2,
    StateDispositionControl,
    SyntheticAckEvidenceProfileV2,
    build_synthetic_acknowledgment,
)
from app.minimal_clearance_source_auth_verifier_adapter import (
    CHILD_PERFORMANCE_VERIFIER_EXECUTABLE,
    CHILD_PERFORMANCE_VERIFIER_EXECUTABLE_SHA256,
    CHILD_PERFORMANCE_VERIFIER_EXECUTABLE_SIZE_BYTES,
    ML_DSA_87_PUBLIC_KEY_BYTES,
    SOURCE_AUTH_EXECUTABLE_SHA256,
    SOURCE_AUTH_EXECUTABLE_SIZE_BYTES,
    SourceAuthVerifierConfig,
)
from app.minimal_clearance_verification_queue import (
    OperationTemplate,
    QueueConfig,
    VerificationOutcome,
    VolatileProofHandoff,
)
from app.minimal_clearance_verifier_process import ContainedVerifierResult
from tools.direct_mask_complete_path import source_boundary
from tools.direct_mask_complete_path.source_boundary import (
    CHILD_PERFORMANCE_SOURCE_APPLIANCE_EXECUTABLE,
    CHILD_PERFORMANCE_SOURCE_APPLIANCE_EXECUTABLE_SHA256,
    CHILD_PERFORMANCE_SOURCE_APPLIANCE_EXECUTABLE_SIZE_BYTES,
    Profile12SourceBoundaryCaller,
    SourceApplianceConfig,
    SOURCE_APPLIANCE_EXECUTABLE_SHA256,
    SOURCE_APPLIANCE_EXECUTABLE_SIZE_BYTES,
)


SOURCE_APPLIANCE_EXECUTABLE = Path(
    r"C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1"
    r"\work\pq-direct-mask-fixture-20260908\build-fixture\Release"
    r"\direct_mask_fixture_source.exe"
)
INDEPENDENT_VERIFIER_EXECUTABLE = Path(
    r"C:\Users\neers\Documents\Codex\2026-09-04\pmb-20260908\Release"
    r"\dm_pipeline_verifier_cli.exe"
)
FROZEN_PUBLIC_KEY_HEADER = Path(
    r"C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1"
    r"\work\pq-direct-mask-fixture-20260908\tools\direct_mask_fixture"
    r"\fixture_public_key.h"
)
FROZEN_PUBLIC_KEY_HEADER_BYTES = 19_249
FROZEN_PUBLIC_KEY_HEADER_SHA256 = bytes.fromhex(
    "ED5B965981E766AA3EFB59303D33719B6C1579C0025D615BB8354AA63AC6FAC9"
)
FROZEN_PUBLIC_KEY_SHA256 = bytes.fromhex(
    "91DC389CFAA01470B7F66EEE45A4AE9026D154817C754DFE22298B3FA241FFCD"
)

COMPLETE_QUEUE_ID = "direct-mask-e2e-profile12"
COMPLETE_COMPOSITION_ID = "direct-mask-e2e-synthetic-v1"
COMPLETE_VERIFIER_IDENTITY = hashlib.sha256(
    b"BL/DIRECT-MASK/COMPLETE-PATH/INDEPENDENT-VERIFIER/v1"
).digest()
COMPLETE_RECEIVER_IDENTITY = hashlib.sha256(
    b"BL/DIRECT-MASK/COMPLETE-PATH/SYNTHETIC-RECEIVER/v1"
).digest()
COMPLETE_FIXED_NOW_MS = 7_000
COMPLETE_VALID_FROM_MS = 6_000
COMPLETE_VALID_UNTIL_MS = 9_000
_REPARSE_POINT = 0x400
_EXPECTED_RUN_FILE_INVENTORY = ("state.sqlite",)


class CompletePathError(RuntimeError):
    """Sanitized complete-path setup or evidence failure."""


def _fail(code: str) -> None:
    error = CompletePathError(code)
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    raise error


def _raise_failure_group(
    label: str,
    failures: tuple[BaseException, ...],
    *,
    run_root: Path | None = None,
    retained: bool | None = None,
) -> None:
    if not failures:
        _fail("complete_path_failure_group")
    error: BaseException = (
        failures[0]
        if len(failures) == 1
        else BaseExceptionGroup(label, failures)
    )
    if run_root is not None:
        error.add_note(f"complete_path_run_root={run_root}")
    if retained is not None:
        error.add_note(f"complete_path_run_retained={retained}")
    raise error from None


def _wipe_bytearray(value: bytearray | None) -> None:
    if type(value) is not bytearray:
        return
    for index in range(len(value)):
        value[index] = 0
    value.clear()


def _assert_real_directory(path: Path, *, empty: bool) -> None:
    if not isinstance(path, Path) or not path.is_absolute():
        _fail("complete_path_directory")
    try:
        info = os.lstat(path)
    except OSError:
        _fail("complete_path_directory")
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or bool(getattr(info, "st_file_attributes", 0) & _REPARSE_POINT)
    ):
        _fail("complete_path_directory")
    if empty:
        try:
            if any(path.iterdir()):
                _fail("complete_path_workspace_not_empty")
        except OSError:
            _fail("complete_path_directory")


def load_frozen_public_key(path: Path = FROZEN_PUBLIC_KEY_HEADER) -> bytes:
    """Load only the pinned public key bytes from the immutable fixture header."""

    if not isinstance(path, Path) or not path.is_absolute():
        _fail("complete_path_public_key_header")
    try:
        raw = path.read_bytes()
    except OSError:
        _fail("complete_path_public_key_header")
    if (
        path.is_symlink()
        or len(raw) != FROZEN_PUBLIC_KEY_HEADER_BYTES
        or hashlib.sha256(raw).digest() != FROZEN_PUBLIC_KEY_HEADER_SHA256
    ):
        _fail("complete_path_public_key_header")
    try:
        start = raw.index(b"{")
        end = raw.index(b"};", start)
    except ValueError:
        _fail("complete_path_public_key_header")
    values = re.findall(rb"0x([0-9a-fA-F]{2})u", raw[start:end])
    try:
        public_key = bytes(int(value, 16) for value in values)
    except ValueError:
        _fail("complete_path_public_key_header")
    if (
        len(public_key) != ML_DSA_87_PUBLIC_KEY_BYTES
        or hashlib.sha256(public_key).digest() != FROZEN_PUBLIC_KEY_SHA256
    ):
        _fail("complete_path_public_key_header")
    return public_key


@dataclass(slots=True)
class DeterministicClock:
    now: int = COMPLETE_FIXED_NOW_MS

    def now_ms(self) -> int:
        return self.now

    def advance(self, milliseconds: int) -> None:
        if type(milliseconds) is not int or milliseconds < 0:
            _fail("complete_path_clock")
        self.now += milliseconds


class SyntheticStateDispositionPort:
    """Synthetic State authority used to exercise the existing State seam."""

    def __init__(self, *, policy_result: str = "MISSING") -> None:
        if policy_result not in {"PASS", "MISSING", "AMBIGUOUS", "FAIL"}:
            _fail("complete_path_policy")
        self.policy_result = policy_result
        self.calls = 0
        self.last_outcome: VerificationOutcome | None = None

    def controls_for(
        self,
        *,
        batch_id: bytes,
        operation_refs: tuple[bytes, ...],
        verification_outcome: VerificationOutcome,
    ) -> Mapping[bytes, StateDispositionControl]:
        del batch_id
        if type(verification_outcome) is not VerificationOutcome:
            _fail("complete_path_state_gate")
        self.calls += 1
        self.last_outcome = verification_outcome
        if (
            verification_outcome.proof_accepted is not True
            or verification_outcome.source_authenticated is not True
            or verification_outcome.result_code != "accepted"
        ):
            _fail("complete_path_state_gate")
        if (
            type(operation_refs) is not tuple
            or len(operation_refs) != 100
            or len(set(operation_refs)) != 100
        ):
            _fail("complete_path_state_refs")
        profile = bytes([9]) * 64
        state_id = bytes(64)
        state_bytes = bytes(64)
        continuity = bytes(64)
        audit = bytes(64)
        clearance = bytes(64)
        marker = 0
        count = 0
        controls: dict[bytes, StateDispositionControl] = {}
        for index, operation_ref in enumerate(operation_refs):
            control = StateDispositionControl(
                operation_ref=operation_ref,
                policy_result=self.policy_result,
                state_profile_identity=profile,
                predecessor_state_id=state_id,
                predecessor_state_bytes=state_bytes,
                epoch=1,
                sequence_before=index,
                predecessor_continuity_root=continuity,
                predecessor_audit_head=audit,
                predecessor_clearance_root=clearance,
                clearance_marker_before=marker,
                clearance_count_before=count,
            )
            controls[operation_ref] = control
            state_id = control.state_after_id
            state_bytes = control.state_after_bytes
            continuity = control.state_after_continuity_root
            clearance = control.state_after_clearance_root
            audit = composition._sha(
                composition._STATE,
                audit,
                control.decision_id,
                control.effective_directive.encode("ascii"),
            )
            advanced = control.effective_directive in {"CLEAR", "EXCEPTION_APPROVED"}
            marker = int(bool(marker or advanced))
            count += int(advanced)
        return controls


class SyntheticReceiver:
    """In-memory receiver/lookup with stable opaque idempotency-key storage."""

    def __init__(
        self,
        config: CompositionConfigV2,
        clock: DeterministicClock,
        *,
        fail_after_persist: bool = False,
    ) -> None:
        self.config = config
        self.clock = clock
        self.fail_after_persist = fail_after_persist
        self.acks: dict[bytes, bytes] = {}
        self.dispatch_calls = 0
        self.lookup_calls = 0
        self.side_effects = 0
        self.duplicate_dispatches = 0
        self.dispatch_keys: list[bytes] = []

    def identity_sha256(self) -> bytes:
        return self.config.receiver_identity

    def epoch(self) -> int:
        return self.config.receiver_epoch

    def acknowledgment_profile(self) -> SyntheticAckEvidenceProfileV2:
        return self.config.acknowledgment_profile

    def dispatch(self, envelope_bytes: bytes, idempotency_key: bytes) -> bytes:
        self.dispatch_calls += 1
        self.dispatch_keys.append(idempotency_key)
        acknowledgment = self.acks.get(idempotency_key)
        if acknowledgment is None:
            acknowledgment = build_synthetic_acknowledgment(
                envelope_bytes,
                config=self.config,
                idempotency_key=idempotency_key,
                accepted_ms=self.clock.now_ms(),
            )
            self.acks[idempotency_key] = acknowledgment
            self.side_effects += 1
        else:
            self.duplicate_dispatches += 1
        if self.fail_after_persist:
            raise RuntimeError("synthetic_receiver_after_persist")
        return acknowledgment

    def lookup_acknowledgment(self, **query: Any) -> bytes | None:
        self.lookup_calls += 1
        if (
            query.get("receiver_identity") != self.config.receiver_identity
            or query.get("receiver_epoch") != self.config.receiver_epoch
        ):
            raise RuntimeError("synthetic_receiver_binding")
        key = query.get("idempotency_key")
        if type(key) is not bytes:
            return None
        return self.acks.get(key)


@dataclass(frozen=True, slots=True)
class NativeStageMeasurement:
    stage: str
    elapsed_ms: float
    exit_code: int
    stdout_bytes: int
    stderr_bytes: int
    peak_job_commit_bytes: int
    peak_working_set_bytes: int
    peak_private_commit_bytes: int
    private_commit_delta_bytes: int
    scratch_peak_bytes: int
    cap_bytes: int
    cap_enforced: bool
    active_process_limit: int
    child_process_count: int
    timed_out: bool
    process_tree_complete: bool
    measurement_complete: bool
    cleanup_complete: bool
    pagefile_growth_evidence: str

    def as_json(self) -> dict[str, Any]:
        return {
            "stage": self.stage,
            "elapsed_ms": round(self.elapsed_ms, 3),
            "exit_code": self.exit_code,
            "stdout_bytes": self.stdout_bytes,
            "stderr_bytes": self.stderr_bytes,
            "peak_job_commit_bytes": self.peak_job_commit_bytes,
            "peak_working_set_bytes": self.peak_working_set_bytes,
            "peak_private_commit_bytes": self.peak_private_commit_bytes,
            "private_commit_delta_bytes": self.private_commit_delta_bytes,
            "scratch_peak_bytes": self.scratch_peak_bytes,
            "cap_bytes": self.cap_bytes,
            "cap_enforced": self.cap_enforced,
            "active_process_limit": self.active_process_limit,
            "child_process_count": self.child_process_count,
            "timed_out": self.timed_out,
            "process_tree_complete": self.process_tree_complete,
            "measurement_complete": self.measurement_complete,
            "cleanup_complete": self.cleanup_complete,
            "pagefile_growth_evidence": self.pagefile_growth_evidence,
        }


@dataclass(frozen=True, slots=True)
class CompletePathEvidence:
    operation_count: int
    issued_batch_count: int
    state_issue_ms: float
    source_call_ms: float
    handoff_ms: float
    queue_verify_state_ms: float
    outbox_ack_ms: float
    total_path_ms: float
    state_port_calls: int
    source_calls: int
    verifier_calls: int
    acknowledged_operation_count: int
    unconfirmed_operation_count: int
    transaction_count: int
    outbox_acknowledged_count: int
    state_sequence: int
    independent_verified_batch_count: int
    independent_operation_count: int
    independent_transaction_count: int
    independent_event_count: int
    independent_outbox_count: int
    unique_idempotency_keys: int
    receiver_side_effects: int
    receiver_duplicate_dispatches: int
    source_workspace_empty: bool
    verifier_workspace_empty: bool
    reopened_without_work: bool
    proof_files_persisted: bool
    run_artifact_inventory: tuple[str, ...]
    proof_suite_id: None
    production_usable: bool
    activation: bool
    source_measurement: NativeStageMeasurement
    verifier_measurement: NativeStageMeasurement

    def as_json(self) -> dict[str, Any]:
        return {
            "operation_count": self.operation_count,
            "issued_batch_count": self.issued_batch_count,
            "state_issue_ms": round(self.state_issue_ms, 3),
            "source_call_ms": round(self.source_call_ms, 3),
            "handoff_ms": round(self.handoff_ms, 3),
            "queue_verify_state_ms": round(self.queue_verify_state_ms, 3),
            "outbox_ack_ms": round(self.outbox_ack_ms, 3),
            "total_path_ms": round(self.total_path_ms, 3),
            "state_port_calls": self.state_port_calls,
            "source_calls": self.source_calls,
            "verifier_calls": self.verifier_calls,
            "acknowledged_operation_count": self.acknowledged_operation_count,
            "unconfirmed_operation_count": self.unconfirmed_operation_count,
            "transaction_count": self.transaction_count,
            "outbox_acknowledged_count": self.outbox_acknowledged_count,
            "state_sequence": self.state_sequence,
            "independent_verified_batch_count": self.independent_verified_batch_count,
            "independent_operation_count": self.independent_operation_count,
            "independent_transaction_count": self.independent_transaction_count,
            "independent_event_count": self.independent_event_count,
            "independent_outbox_count": self.independent_outbox_count,
            "unique_idempotency_keys": self.unique_idempotency_keys,
            "receiver_side_effects": self.receiver_side_effects,
            "receiver_duplicate_dispatches": self.receiver_duplicate_dispatches,
            "source_workspace_empty": self.source_workspace_empty,
            "verifier_workspace_empty": self.verifier_workspace_empty,
            "reopened_without_work": self.reopened_without_work,
            "proof_files_persisted": self.proof_files_persisted,
            "run_artifact_inventory": list(self.run_artifact_inventory),
            "proof_suite_id": self.proof_suite_id,
            "production_usable": self.production_usable,
            "activation": self.activation,
            "source_measurement": self.source_measurement.as_json(),
            "verifier_measurement": self.verifier_measurement.as_json(),
        }


def build_complete_configs(
    queue_id: str = COMPLETE_QUEUE_ID,
) -> tuple[QueueConfig, CompositionConfigV2]:
    queue_config = QueueConfig(queue_id, 100, source_key_epoch=1)
    composition_config = CompositionConfigV2(
        queue_config.queue_id,
        queue_config.digest,
        verifier_profile_identity=COMPLETE_VERIFIER_IDENTITY,
        receiver_identity=COMPLETE_RECEIVER_IDENTITY,
        receiver_epoch=1,
        composition_id=COMPLETE_COMPOSITION_ID,
        verifier_epoch=1,
        capacity=100,
    )
    return queue_config, composition_config


def _native_measurement(
    stage: str,
    started_ns: int,
    result: ContainedVerifierResult,
) -> NativeStageMeasurement:
    return NativeStageMeasurement(
        stage=stage,
        elapsed_ms=(time.perf_counter_ns() - started_ns) / 1_000_000,
        exit_code=result.exit_code,
        stdout_bytes=len(result.stdout),
        stderr_bytes=len(result.stderr),
        peak_job_commit_bytes=result.peak_job_commit_bytes,
        peak_working_set_bytes=result.peak_working_set_bytes,
        peak_private_commit_bytes=result.peak_private_commit_bytes,
        private_commit_delta_bytes=result.private_commit_delta_bytes,
        scratch_peak_bytes=result.scratch_peak_bytes,
        cap_bytes=result.cap_bytes,
        cap_enforced=result.cap_enforced,
        active_process_limit=result.active_process_limit,
        child_process_count=result.child_process_count,
        timed_out=result.timed_out,
        process_tree_complete=result.process_tree_complete,
        measurement_complete=result.measurement_complete,
        cleanup_complete=result.cleanup_complete,
        pagefile_growth_evidence=result.pagefile_growth_evidence,
    )


def _wrap_native_runner(
    stage: str,
    original: Any,
    measurements: dict[str, list[NativeStageMeasurement]],
    invocation_counts: dict[str, int],
) -> Any:
    def run(*args: Any, **kwargs: Any) -> Any:
        invocation_counts[stage] = invocation_counts.get(stage, 0) + 1
        started_ns = time.perf_counter_ns()
        result = original(*args, **kwargs)
        if type(result) is not ContainedVerifierResult:
            _fail("complete_path_native_result")
        measurements.setdefault(stage, []).append(
            _native_measurement(stage, started_ns, result)
        )
        return result

    return run


def _assert_exact_native_invocations(
    *,
    invocation_counts: Mapping[str, int],
    measurements: Mapping[str, list[NativeStageMeasurement]],
    state_port_calls: int,
) -> tuple[int, int, NativeStageMeasurement, NativeStageMeasurement]:
    source_calls = int(invocation_counts.get("source_appliance", 0))
    verifier_calls = int(invocation_counts.get("independent_verifier", 0))
    source_measurements = tuple(measurements.get("source_appliance", ()))
    verifier_measurements = tuple(measurements.get("independent_verifier", ()))
    if (
        source_calls != 1
        or verifier_calls != 1
        or state_port_calls != 1
        or len(source_measurements) != 1
        or len(verifier_measurements) != 1
    ):
        error = CompletePathError("complete_path_native_invocation_count")
        error.add_note(f"complete_path_source_calls={source_calls}")
        error.add_note(f"complete_path_verifier_calls={verifier_calls}")
        error.add_note(f"complete_path_state_port_calls={state_port_calls}")
        error.add_note(
            f"complete_path_source_measurement_count={len(source_measurements)}"
        )
        error.add_note(
            f"complete_path_verifier_measurement_count={len(verifier_measurements)}"
        )
        raise error
    return (
        source_calls,
        verifier_calls,
        source_measurements[0],
        verifier_measurements[0],
    )


@contextmanager
def _runtime_scope(
    runtime: runtime_module.MinimalClearanceVerificationRuntime,
    release_state: dict[str, bool],
):
    """Use the runtime's checked context hooks while retaining both failures."""

    release_state["entered"] = False
    release_state["release_attempted"] = False
    release_state["released"] = False
    release_state["release_failed"] = False
    try:
        runtime.__enter__()
    except BaseException as primary:
        release_state["release_attempted"] = True
        try:
            runtime.close()
        except BaseException as cleanup:
            release_state["release_failed"] = True
            _raise_failure_group(
                "complete_path_runtime_enter_and_cleanup",
                (primary, cleanup),
            )
        release_state["released"] = True
        raise
    release_state["entered"] = True
    try:
        yield runtime
    except BaseException as primary:
        release_state["release_attempted"] = True
        try:
            runtime.__exit__(type(primary), primary, primary.__traceback__)
        except BaseException as cleanup:
            release_state["release_failed"] = True
            _raise_failure_group(
                "complete_path_runtime_and_cleanup",
                (primary, cleanup),
            )
        release_state["released"] = True
        raise
    else:
        release_state["release_attempted"] = True
        try:
            runtime.__exit__(None, None, None)
        except BaseException:
            release_state["release_failed"] = True
            raise
        release_state["released"] = True


def _run_file_inventory(run_root: Path) -> tuple[str, ...]:
    try:
        return tuple(
            sorted(
                path.relative_to(run_root).as_posix()
                for path in run_root.rglob("*")
                if path.is_file() or path.is_symlink()
            )
        )
    except OSError:
        _fail("complete_path_artifact_inventory")


def _assert_expected_run_file_inventory(run_root: Path) -> tuple[str, ...]:
    inventory = _run_file_inventory(run_root)
    if inventory != _EXPECTED_RUN_FILE_INVENTORY:
        error = CompletePathError("complete_path_artifact_inventory")
        error.add_note(f"complete_path_run_file_inventory={inventory!r}")
        error.add_note(
            f"complete_path_expected_run_file_inventory={_EXPECTED_RUN_FILE_INVENTORY!r}"
        )
        raise error
    return inventory


def _assert_projection(
    *,
    runtime_result: runtime_module.RuntimeRunResult,
    delivery: runtime_module.RuntimeOutboxResult,
    summary: dict[str, Any],
) -> None:
    if (
        runtime_result.outcome != "PROCESSED"
        or runtime_result.accepted_operation_count != 100
        or runtime_result.verified_batch_count != 1
        or runtime_result.rejected_batch_count != 0
        or runtime_result.held_batch_count != 0
        or delivery.outcome != "PROCESSED"
        or delivery.batch_count != 1
        or delivery.attempted_operation_count != 100
        or delivery.acknowledged_operation_count != 100
        or delivery.unconfirmed_operation_count != 0
        or summary["counts"]["VERIFIED"] != 1
        or summary["accepted_operation_count"] != 100
        or summary["outbox_counts"]
        != {"READY": 0, "LEASED": 0, "ACKNOWLEDGED": 100, "DELIVERY_UNCONFIRMED": 0}
    ):
        _fail("complete_path_projection")
    if (
        summary["proof_suite_id"] is not None
        or summary["production_usable"] is not False
        or summary["activation"] is not False
        or summary["proof_bytes_persisted"] is not False
    ):
        _fail("complete_path_nonactivation")


def _read_only_counts(database: Path) -> tuple[int, int, int, int]:
    uri = database.resolve().as_uri() + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True, timeout=5.0)) as connection:
        transaction_count, transaction_unique = connection.execute(
            "SELECT COUNT(*),COUNT(DISTINCT operation_ref) FROM composition_transactions"
        ).fetchone()
        outbox_count, outbox_unique = connection.execute(
            "SELECT COUNT(*),COUNT(DISTINCT operation_ref) FROM composition_outbox"
        ).fetchone()
    return int(transaction_count), int(transaction_unique), int(outbox_count), int(outbox_unique)


def run_one_fresh_native_proof(*, build_root: Path) -> CompletePathEvidence:
    """Run exactly one fresh valid source proof through the full local path."""

    _assert_real_directory(build_root, empty=False)
    performance_native = os.environ.get("DIRECT_MASK_PERFORMANCE_NATIVE") == "1"
    public_key = load_frozen_public_key()
    queue_config, composition_config = build_complete_configs()
    clock = DeterministicClock()
    state_port = SyntheticStateDispositionPort(policy_result="MISSING")
    receiver = SyntheticReceiver(composition_config, clock)
    measurements: dict[str, list[NativeStageMeasurement]] = {}
    invocation_counts: dict[str, int] = {}
    source_workspace_empty = False
    verifier_workspace_empty = False
    database: Path | None = None
    source_workspace: Path | None = None
    verifier_workspace: Path | None = None
    source_calls = 0
    verifier_calls = 0
    source_measurement: NativeStageMeasurement | None = None
    verifier_measurement: NativeStageMeasurement | None = None
    run_artifact_inventory: tuple[str, ...] = ()
    evidence: CompletePathEvidence | None = None
    release_states: list[dict[str, bool]] = []
    primary_error: BaseException | None = None
    cleanup_errors: list[BaseException] = []

    run_directory = tempfile.TemporaryDirectory(
        prefix="direct-mask-complete-run-",
        dir=str(build_root),
        delete=False,
    )
    run_root = Path(run_directory.name)
    try:
        _assert_real_directory(run_root, empty=True)
        source_workspace = run_root / "source-workspace"
        verifier_workspace = run_root / "verifier-workspace"
        source_workspace.mkdir()
        verifier_workspace.mkdir()
        _assert_real_directory(source_workspace, empty=True)
        _assert_real_directory(verifier_workspace, empty=True)
        if performance_native:
            source_executable = CHILD_PERFORMANCE_SOURCE_APPLIANCE_EXECUTABLE
            source_executable_size = (
                CHILD_PERFORMANCE_SOURCE_APPLIANCE_EXECUTABLE_SIZE_BYTES
            )
            source_executable_sha256 = (
                CHILD_PERFORMANCE_SOURCE_APPLIANCE_EXECUTABLE_SHA256
            )
            source_identity_profile = "child-performance"
            verifier_executable = CHILD_PERFORMANCE_VERIFIER_EXECUTABLE
            verifier_executable_size = CHILD_PERFORMANCE_VERIFIER_EXECUTABLE_SIZE_BYTES
            verifier_executable_sha256 = CHILD_PERFORMANCE_VERIFIER_EXECUTABLE_SHA256
            verifier_identity_profile = "child-performance"
        else:
            source_executable = SOURCE_APPLIANCE_EXECUTABLE
            source_executable_size = SOURCE_APPLIANCE_EXECUTABLE_SIZE_BYTES
            source_executable_sha256 = SOURCE_APPLIANCE_EXECUTABLE_SHA256
            source_identity_profile = "accepted"
            verifier_executable = INDEPENDENT_VERIFIER_EXECUTABLE
            verifier_executable_size = SOURCE_AUTH_EXECUTABLE_SIZE_BYTES
            verifier_executable_sha256 = SOURCE_AUTH_EXECUTABLE_SHA256
            verifier_identity_profile = "accepted"
        source_caller = Profile12SourceBoundaryCaller(
            SourceApplianceConfig(
                executable_path=source_executable,
                workspace=source_workspace,
                executable_size_bytes=source_executable_size,
                executable_sha256=source_executable_sha256,
                timeout_seconds=180.0,
                identity_profile=source_identity_profile,
            )
        )
        source_auth_config = SourceAuthVerifierConfig(
            queue_config=queue_config,
            executable_path=verifier_executable,
            executable_size_bytes=verifier_executable_size,
            executable_sha256=verifier_executable_sha256,
            workspace=verifier_workspace,
            ml_dsa_87_public_key=public_key,
            timeout_seconds=30.0,
            identity_profile=verifier_identity_profile,
        )
        runtime = runtime_module.MinimalClearanceVerificationRuntime.from_source_auth(
            root=run_root,
            source_auth_config=source_auth_config,
            state_disposition_port=state_port,
            composition_config=composition_config,
            receiver=receiver,
            lookup=receiver,
            clock=clock,
        )
        first_release_state: dict[str, bool] = {}
        release_states.append(first_release_state)
        database = run_root / "state.sqlite"
        with _runtime_scope(runtime, first_release_state):
            template = OperationTemplate(
                "direct-mask-e2e-assertion",
                1,
                queue_config.profile_version,
                COMPLETE_VALID_FROM_MS,
                COMPLETE_VALID_UNTIL_MS,
            )
            started_total_ns = time.perf_counter_ns()
            issue_started_ns = time.perf_counter_ns()
            batch = runtime.issue_batch(template=template)
            state_issue_ms = (time.perf_counter_ns() - issue_started_ns) / 1_000_000

            old_source_runner = source_boundary.run_contained_verifier_stream
            old_verifier_runner = adapter_module.run_contained_verifier_stream
            capsule: bytearray | None = None
            proof_stream: VolatileProofHandoff | None = None
            handoff_transferred = False
            try:
                source_boundary.run_contained_verifier_stream = _wrap_native_runner(
                    "source_appliance",
                    old_source_runner,
                    measurements,
                    invocation_counts,
                )
                adapter_module.run_contained_verifier_stream = _wrap_native_runner(
                    "independent_verifier",
                    old_verifier_runner,
                    measurements,
                    invocation_counts,
                )
                admission = source_caller.admit_one(
                    runtime=runtime,
                    batch=batch,
                    source_key_epoch=1,
                )
                authorization = source_caller.start_one(
                    runtime=runtime,
                    admission=admission,
                )
                source_started_ns = time.perf_counter_ns()
                try:
                    capsule = source_caller.prove_one(
                        authorization=authorization,
                        source_key_epoch=1,
                    )
                except BaseException:
                    runtime.finish_source_launch(
                        authorization=authorization,
                        success=False,
                    )
                    raise
                else:
                    runtime.finish_source_launch(
                        authorization=authorization,
                        success=True,
                    )
                source_call_ms = (
                    time.perf_counter_ns() - source_started_ns
                ) / 1_000_000
                if type(capsule) is not bytearray:
                    _fail("complete_path_capsule_type")
                handoff_started_ns = time.perf_counter_ns()
                proof_stream = VolatileProofHandoff(capsule)
                capsule = None
                runtime.submit_batch_handoff(
                    issued_batch=batch,
                    proof_stream=proof_stream,
                )
                handoff_transferred = True
                handoff_ms = (
                    time.perf_counter_ns() - handoff_started_ns
                ) / 1_000_000
                queue_started_ns = time.perf_counter_ns()
                try:
                    queue_result = runtime.run(max_batches=1)
                finally:
                    if proof_stream is not None:
                        proof_stream.close()
                        proof_stream = None
                queue_verify_state_ms = (
                    time.perf_counter_ns() - queue_started_ns
                ) / 1_000_000
                (
                    source_calls,
                    verifier_calls,
                    source_measurement,
                    verifier_measurement,
                ) = _assert_exact_native_invocations(
                    invocation_counts=invocation_counts,
                    measurements=measurements,
                    state_port_calls=state_port.calls,
                )
                outbox_started_ns = time.perf_counter_ns()
                delivery = runtime.dispatch_outbox(max_batches=1)
                outbox_ack_ms = (
                    time.perf_counter_ns() - outbox_started_ns
                ) / 1_000_000
                summary = runtime.support_summary()
                composition_snapshot = runtime._composition_store.snapshot()
                _assert_projection(
                    runtime_result=queue_result,
                    delivery=delivery,
                    summary=summary,
                )
                runtime._verify_integrity()
                transaction_count, transaction_unique, outbox_count, outbox_unique = (
                    _read_only_counts(database)
                )
                if (
                    transaction_count != 100
                    or transaction_unique != 100
                    or outbox_count != 100
                    or outbox_unique != 100
                ):
                    _fail("complete_path_durable_counts")
            finally:
                if proof_stream is not None and not handoff_transferred:
                    proof_stream.close()
                _wipe_bytearray(capsule)
                source_boundary.run_contained_verifier_stream = old_source_runner
                adapter_module.run_contained_verifier_stream = old_verifier_runner

        _assert_real_directory(source_workspace, empty=True)
        _assert_real_directory(verifier_workspace, empty=True)
        source_workspace_empty = True
        verifier_workspace_empty = True
        run_artifact_inventory = _assert_expected_run_file_inventory(run_root)

        reopened_without_work = False
        reopened = runtime_module.MinimalClearanceVerificationRuntime.from_source_auth(
            root=run_root,
            source_auth_config=source_auth_config,
            state_disposition_port=state_port,
            composition_config=composition_config,
            receiver=receiver,
            lookup=receiver,
            clock=clock,
        )
        reopened_release_state: dict[str, bool] = {}
        release_states.append(reopened_release_state)
        with _runtime_scope(reopened, reopened_release_state):
            reopened_summary = reopened.support_summary()
            reopened_run = reopened.run()
            reopened_delivery = reopened.dispatch_outbox()
            reopened_without_work = (
                reopened_run.outcome == "EMPTY"
                and reopened_delivery.outcome == "EMPTY"
                and reopened_summary["outbox_counts"]
                == {
                    "READY": 0,
                    "LEASED": 0,
                    "ACKNOWLEDGED": 100,
                    "DELIVERY_UNCONFIRMED": 0,
                }
            )

        queue_verified = queue_independent.verify_database(
            database,
            expected_config=queue_config.as_json,
        )
        composition_verified = composition_independent.verify_database(
            database,
            expected_config=composition_config.as_json,
        )
        readback = queue_independent.read_verified_batch(
            database,
            selector=batch.batch_id,
        )
        independent_operation_count = len(readback.jobs)
        independent_event_count = int(composition_verified["event_count"])
        independent_transaction_count = int(
            sum(composition_verified["transaction_counts"].values())
        )
        independent_outbox_count = int(composition_verified["outbox_count"])
        proof_files_persisted = run_artifact_inventory != _EXPECTED_RUN_FILE_INVENTORY
        if (
            readback.batch.accepted_count != 100
            or independent_operation_count != 100
            or int(queue_verified["verified_batch_count"]) != 1
            or independent_transaction_count != 100
            or independent_outbox_count != 100
            or independent_event_count < 100
            or not reopened_without_work
            or proof_files_persisted
            or not source_workspace_empty
            or not verifier_workspace_empty
        ):
            _fail("complete_path_readback")
        if len(receiver.acks) != 100 or len(set(receiver.dispatch_keys)) != 100:
            _fail("complete_path_ack_deduplication")
        total_path_ms = (time.perf_counter_ns() - started_total_ns) / 1_000_000
        if source_measurement is None or verifier_measurement is None:
            _fail("complete_path_native_measurement")
        evidence = CompletePathEvidence(
            operation_count=100,
            issued_batch_count=1,
            state_issue_ms=state_issue_ms,
            source_call_ms=source_call_ms,
            handoff_ms=handoff_ms,
            queue_verify_state_ms=queue_verify_state_ms,
            outbox_ack_ms=outbox_ack_ms,
            total_path_ms=total_path_ms,
            state_port_calls=state_port.calls,
            source_calls=source_calls,
            verifier_calls=verifier_calls,
            acknowledged_operation_count=delivery.acknowledged_operation_count,
            unconfirmed_operation_count=delivery.unconfirmed_operation_count,
            transaction_count=transaction_count,
            outbox_acknowledged_count=composition_snapshot["outbox_counts"]["ACKNOWLEDGED"],
            state_sequence=int(composition_snapshot["state_sequence"]),
            independent_verified_batch_count=int(
                queue_verified["verified_batch_count"]
            ),
            independent_operation_count=independent_operation_count,
            independent_transaction_count=independent_transaction_count,
            independent_event_count=independent_event_count,
            independent_outbox_count=independent_outbox_count,
            unique_idempotency_keys=len(set(receiver.dispatch_keys)),
            receiver_side_effects=receiver.side_effects,
            receiver_duplicate_dispatches=receiver.duplicate_dispatches,
            source_workspace_empty=source_workspace_empty,
            verifier_workspace_empty=verifier_workspace_empty,
            reopened_without_work=reopened_without_work,
            proof_files_persisted=proof_files_persisted,
            run_artifact_inventory=run_artifact_inventory,
            proof_suite_id=None,
            production_usable=False,
            activation=False,
            source_measurement=source_measurement,
            verifier_measurement=verifier_measurement,
        )
    except BaseException as error:
        primary_error = error
    finally:
        all_runtime_released = bool(release_states) and all(
            state.get("released") is True for state in release_states
        )
        if primary_error is None and all_runtime_released and not cleanup_errors:
            try:
                run_directory.cleanup()
            except BaseException as error:
                cleanup_errors.append(error)

    if primary_error is not None or cleanup_errors:
        failures: list[BaseException] = []
        if primary_error is not None:
            failures.append(primary_error)
        failures.extend(cleanup_errors)
        _raise_failure_group(
            "complete_path_failure_and_cleanup",
            tuple(failures),
            run_root=run_root,
            retained=primary_error is not None or bool(cleanup_errors),
        )
    if evidence is None:
        _fail("complete_path_evidence")
    return evidence


__all__ = (
    "COMPLETE_COMPOSITION_ID",
    "COMPLETE_FIXED_NOW_MS",
    "COMPLETE_QUEUE_ID",
    "CompletePathEvidence",
    "CompletePathError",
    "DeterministicClock",
    "FROZEN_PUBLIC_KEY_HEADER",
    "FROZEN_PUBLIC_KEY_HEADER_BYTES",
    "FROZEN_PUBLIC_KEY_HEADER_SHA256",
    "FROZEN_PUBLIC_KEY_SHA256",
    "INDEPENDENT_VERIFIER_EXECUTABLE",
    "SOURCE_APPLIANCE_EXECUTABLE",
    "SyntheticReceiver",
    "SyntheticStateDispositionPort",
    "build_complete_configs",
    "load_frozen_public_key",
    "run_one_fresh_native_proof",
)
