"""Bounded per-claim verifier throughput measurement.

This is an evidence-only harness for the retained minimal-clearance verifier.
It never submits to a state store and never invokes a prover.  Each operation
constructs a new NativeMinimalClearanceVerifier; that verifier owns a fresh
private TemporaryDirectory for its executable, artifact, and output snapshots.
"""

from __future__ import annotations

import argparse
import ctypes
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import time
from typing import Any, Callable, Mapping

if __package__ in (None, ""):
    _REPO_ROOT = Path(__file__).resolve().parents[3]
    if str(_REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(_REPO_ROOT))

from app.minimal_clearance_proof_state import (
    MinimalClearanceProofStateError,
    NativeMinimalClearanceVerifier,
)
from app.minimal_clearance_verifier_process import (
    ACTIVE_PROCESS_LIMIT,
    CAP_BYTES,
    MAX_STDERR_BYTES,
    MAX_STDOUT_BYTES,
    VerifierProcessError,
)
from tests.minimal_clearance_qualification import (
    QualificationError,
    _validate_acceptance_output,
)


SCHEMA = "BL/NATIVE-V3/MINIMAL-CLEARANCE-VERIFIER-THROUGHPUT/v1"
ARTIFACT_BYTES = 411_672
ARTIFACT_SHA256 = "69F653130822D15977BC14E450B62A5A20FF7CF12512C7BBBC79714B5A5BB38E"
ARTIFACT_SHA3_512 = "A2D3DDBA8C6ECAABC70147793185318FA7910E8EBBA0675D614E95885DAC23331C3F2FE3689F30748B030C9A26D55D704DB244C5DC36136896F6B87F42045BE1"
VERIFIER_SHA256 = "E2BD096389E7D9CB3F8D83314747CA3D493DF6C30D86A57041F74B84F0023F3E"
WAVES_PER_LEVEL = 3
CONCURRENCY_LEVELS = (1, 2, 4)
EXPECTED_VERIFICATIONS = 21
PRIOR_PEAK_JOB_COMMIT_BYTES = 1_042_202_624
RESERVE_BYTES = 4 * 1024 * 1024 * 1024
REQUIRED_UNCOMMITTED_BYTES = (
    RESERVE_BYTES + 4 * PRIOR_PEAK_JOB_COMMIT_BYTES
)
MAX_EVIDENCE_BYTES = 64 * 1024
_HEX64 = re.compile(r"[0-9A-Fa-f]{64}\Z")
_SAFE_ERROR_CODE = re.compile(r"[a-z][a-z0-9_]{0,95}\Z")
_SAFE_EXCEPTION_CLASS = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z")


def _safe_error_code(value: object, fallback: str) -> str:
    if type(value) is str and _SAFE_ERROR_CODE.fullmatch(value) is not None:
        return value
    return fallback


def _safe_exception_class(value: object) -> str | None:
    if type(value) is str and _SAFE_EXCEPTION_CLASS.fullmatch(value) is not None:
        return value
    return None


class ThroughputError(RuntimeError):
    """A bounded, machine-safe throughput failure."""

    def __init__(
        self,
        code: str,
        *,
        concurrency: int | None = None,
        wave_index: int | None = None,
        operation_index: int | None = None,
        exception_class: str | None = None,
        win32_error_code: int | None = None,
    ) -> None:
        self.code = _safe_error_code(code, "unclassified_error")
        self.concurrency = concurrency if type(concurrency) is int and concurrency >= 0 else None
        self.wave_index = wave_index if type(wave_index) is int and wave_index >= 0 else None
        self.operation_index = (
            operation_index if type(operation_index) is int and operation_index >= 0 else None
        )
        self.exception_class = _safe_exception_class(exception_class)
        self.win32_error_code = (
            win32_error_code
            if type(win32_error_code) is int and win32_error_code >= 0
            else None
        )
        super().__init__(self.code)

    def with_context(
        self,
        *,
        concurrency: int | None = None,
        wave_index: int | None = None,
        operation_index: int | None = None,
    ) -> "ThroughputError":
        return ThroughputError(
            self.code,
            concurrency=self.concurrency if self.concurrency is not None else concurrency,
            wave_index=self.wave_index if self.wave_index is not None else wave_index,
            operation_index=(
                self.operation_index if self.operation_index is not None else operation_index
            ),
            exception_class=self.exception_class,
            win32_error_code=self.win32_error_code,
        )

    def bounded_text(self) -> str:
        fields = [f"code={self.code}"]
        if self.concurrency is not None:
            fields.append(f"concurrency={self.concurrency}")
        if self.wave_index is not None:
            fields.append(f"wave_index={self.wave_index}")
        if self.operation_index is not None:
            fields.append(f"operation_index={self.operation_index}")
        if self.exception_class is not None:
            fields.append(f"exception_class={self.exception_class}")
        if self.win32_error_code is not None:
            fields.append(f"win32_error_code={self.win32_error_code}")
        return " ".join(fields)


_KNOWN_REPOSITORY_ERRORS = (
    QualificationError,
    MinimalClearanceProofStateError,
    VerifierProcessError,
)


def _exception_chain(error: BaseException) -> list[BaseException]:
    chain: list[BaseException] = []
    current: BaseException | None = error
    seen: set[int] = set()
    while current is not None and id(current) not in seen and len(chain) < 8:
        chain.append(current)
        seen.add(id(current))
        next_error = current.__cause__ or current.__context__
        current = next_error
    return chain


def _repository_error_code(error: BaseException) -> str | None:
    for candidate in _exception_chain(error):
        if isinstance(candidate, ThroughputError):
            return candidate.code
        if isinstance(candidate, _KNOWN_REPOSITORY_ERRORS):
            token = _safe_error_code(str(candidate), "repository_error")
            return token
    return None


def _os_error_code(error: BaseException) -> int | None:
    if not isinstance(error, OSError):
        return None
    win32_error = getattr(error, "winerror", None)
    if type(win32_error) is int and win32_error >= 0:
        return win32_error
    errno = getattr(error, "errno", None)
    if type(errno) is int and errno >= 0:
        return errno
    return None


def _failure_from_exception(
    error: BaseException,
    *,
    fallback: str,
    concurrency: int | None = None,
    wave_index: int | None = None,
    operation_index: int | None = None,
) -> ThroughputError:
    if isinstance(error, ThroughputError):
        return error.with_context(
            concurrency=concurrency,
            wave_index=wave_index,
            operation_index=operation_index,
        )
    code = _repository_error_code(error)
    if code is None:
        code = "os_error" if isinstance(error, OSError) else fallback
    return ThroughputError(
        code,
        concurrency=concurrency,
        wave_index=wave_index,
        operation_index=operation_index,
        exception_class=_safe_exception_class(type(error).__name__),
        win32_error_code=_os_error_code(error),
    )


@dataclass(frozen=True, slots=True)
class ArtifactSnapshot:
    raw: bytes
    bytes: int
    sha256: str
    sha3_512: str
    readonly: bool
    file_token: tuple[int, int]


def _require(condition: bool, label: str) -> None:
    if not condition:
        raise ThroughputError(label)


def _is_readonly(path: Path) -> bool:
    attributes = getattr(path.stat(), "st_file_attributes", None)
    if type(attributes) is not int:
        raise ThroughputError("artifact_readonly_unavailable")
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_READONLY", 1))


def _file_token(path: Path) -> tuple[int, int]:
    info = path.stat()
    return int(info.st_dev), int(info.st_ino)


def _read_artifact_once(path: Path) -> ArtifactSnapshot:
    _require(
        isinstance(path, Path) and path.is_file() and not path.is_symlink(),
        "artifact_not_regular",
    )
    raw = bytes(path.read_bytes())
    sha256 = hashlib.sha256(raw).hexdigest().upper()
    sha3_512 = hashlib.sha3_512(raw).hexdigest().upper()
    readonly = _is_readonly(path)
    _require(len(raw) == ARTIFACT_BYTES, "artifact_length_mismatch")
    _require(sha256 == ARTIFACT_SHA256, "artifact_sha256_mismatch")
    _require(sha3_512 == ARTIFACT_SHA3_512, "artifact_sha3_512_mismatch")
    _require(readonly, "artifact_not_readonly")
    return ArtifactSnapshot(
        raw=raw,
        bytes=len(raw),
        sha256=sha256,
        sha3_512=sha3_512,
        readonly=readonly,
        file_token=_file_token(path),
    )


def _check_artifact_after(path: Path, before: ArtifactSnapshot) -> dict[str, Any]:
    _require(path.is_file() and not path.is_symlink(), "artifact_changed_not_regular")
    raw = bytes(path.read_bytes())
    sha256 = hashlib.sha256(raw).hexdigest().upper()
    sha3_512 = hashlib.sha3_512(raw).hexdigest().upper()
    readonly = _is_readonly(path)
    _require(len(raw) == before.bytes, "artifact_size_changed")
    _require(sha256 == before.sha256, "artifact_sha256_changed")
    _require(sha3_512 == before.sha3_512, "artifact_sha3_512_changed")
    _require(readonly and readonly == before.readonly, "artifact_readonly_changed")
    _require(_file_token(path) == before.file_token, "artifact_file_replaced")
    return {
        "bytes": len(raw),
        "sha256": sha256,
        "sha3_512": sha3_512,
        "readonly": readonly,
    }


def _read_verifier_sha256(path: Path) -> str:
    _require(
        isinstance(path, Path) and path.is_file() and not path.is_symlink(),
        "verifier_not_regular",
    )
    digest = hashlib.sha256(bytes(path.read_bytes())).hexdigest().upper()
    _require(digest == VERIFIER_SHA256, "verifier_identity_mismatch")
    return digest


def _windows_memory_probe() -> dict[str, int]:
    if os.name != "nt":
        raise ThroughputError("memory_probe_windows_only")

    class _PerformanceInformation(ctypes.Structure):
        _fields_ = [
            ("cb", ctypes.c_uint32),
            ("CommitTotal", ctypes.c_size_t),
            ("CommitLimit", ctypes.c_size_t),
            ("CommitPeak", ctypes.c_size_t),
            ("PhysicalTotal", ctypes.c_size_t),
            ("PhysicalAvailable", ctypes.c_size_t),
            ("SystemCache", ctypes.c_size_t),
            ("KernelTotal", ctypes.c_size_t),
            ("KernelPaged", ctypes.c_size_t),
            ("KernelNonpaged", ctypes.c_size_t),
            ("PageSize", ctypes.c_size_t),
            ("HandleCount", ctypes.c_uint32),
            ("ProcessCount", ctypes.c_uint32),
            ("ThreadCount", ctypes.c_uint32),
        ]

    info = _PerformanceInformation()
    info.cb = ctypes.sizeof(info)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    get_performance_info = psapi.GetPerformanceInfo
    get_performance_info.argtypes = [ctypes.POINTER(_PerformanceInformation), ctypes.c_uint32]
    get_performance_info.restype = ctypes.c_int
    if not get_performance_info(ctypes.byref(info), ctypes.sizeof(info)):
        raise ThroughputError("memory_probe_failed")
    page_size = int(info.PageSize)
    uncommitted = (int(info.CommitLimit) - int(info.CommitTotal)) * page_size
    _require(page_size > 0 and uncommitted >= 0, "memory_probe_invalid")
    return {
        "commit_limit_bytes": int(info.CommitLimit) * page_size,
        "commit_total_bytes": int(info.CommitTotal) * page_size,
        "uncommitted_bytes": uncommitted,
        "page_size_bytes": page_size,
    }


def preflight_memory(
    memory_probe: Callable[[], Mapping[str, int]] | None = None,
) -> dict[str, Any]:
    """Require the fixed four-worker reserve before any native verification."""
    probe = memory_probe or _windows_memory_probe
    raw = dict(probe())
    uncommitted = raw.get("uncommitted_bytes")
    _require(type(uncommitted) is int and uncommitted >= 0, "memory_uncommitted_missing")
    logical_cpu_count = os.cpu_count()
    _require(type(logical_cpu_count) is int and logical_cpu_count > 0, "logical_cpu_count_missing")
    passed = uncommitted >= REQUIRED_UNCOMMITTED_BYTES
    _require(passed, "memory_reserve_insufficient")
    return {
        "logical_cpu_count": logical_cpu_count,
        "uncommitted_bytes": uncommitted,
        "required_uncommitted_bytes": REQUIRED_UNCOMMITTED_BYTES,
        "reserve_bytes": RESERVE_BYTES,
        "prior_peak_job_commit_bytes": PRIOR_PEAK_JOB_COMMIT_BYTES,
        "memory_gate_passed": True,
    }


def _validate_containment(result: Any) -> int:
    _require(result is not None, "containment_missing")
    cap_bytes = getattr(result, "cap_bytes", None)
    cap_enforced = getattr(result, "cap_enforced", None)
    active_limit = getattr(result, "active_process_limit", None)
    peak = getattr(result, "peak_job_commit_bytes", None)
    timed_out = getattr(result, "timed_out", None)
    exit_code = getattr(result, "exit_code", None)
    _require(type(cap_bytes) is int and cap_bytes == CAP_BYTES, "containment_cap")
    _require(cap_enforced is True, "containment_cap_not_enforced")
    _require(type(active_limit) is int and active_limit == ACTIVE_PROCESS_LIMIT, "containment_process_limit")
    _require(type(peak) is int and 0 <= peak <= CAP_BYTES, "containment_peak")
    _require(type(timed_out) is bool and not timed_out, "containment_timeout")
    _require(type(exit_code) is int and exit_code == 0, "containment_exit")
    stdout = getattr(result, "stdout", None)
    stderr = getattr(result, "stderr", None)
    _require(type(stdout) is bytes and len(stdout) <= MAX_STDOUT_BYTES, "containment_stdout")
    _require(type(stderr) is bytes and len(stderr) <= MAX_STDERR_BYTES, "containment_stderr")
    return peak


def _validate_acceptance(acceptance: Any, artifact: ArtifactSnapshot) -> None:
    _require(getattr(acceptance, "proof_accepted", None) is True, "acceptance_not_true")
    artifact_sha256 = getattr(acceptance, "artifact_sha256", None)
    artifact_digest = getattr(acceptance, "artifact_digest", None)
    artifact_bytes = getattr(acceptance, "artifact_bytes", None)
    _require(type(artifact_sha256) is bytes and len(artifact_sha256) == 32, "acceptance_sha256")
    _require(type(artifact_digest) is bytes and len(artifact_digest) == 64, "acceptance_sha3_512")
    _require(type(artifact_bytes) is int and artifact_bytes == artifact.bytes, "acceptance_length")
    _require(artifact_sha256.hex().upper() == artifact.sha256, "acceptance_sha256_mismatch")
    _require(artifact_digest.hex().upper() == artifact.sha3_512, "acceptance_sha3_512_mismatch")


VerifierFactory = Callable[..., Any]


def _run_one(
    operation_index: int,
    artifact_path: Path,
    verifier_path: Path,
    artifact: ArtifactSnapshot,
    verifier_sha256: str,
    timeout_seconds: float,
    *,
    verifier_factory: VerifierFactory = NativeMinimalClearanceVerifier,
    monotonic: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    started = monotonic()
    try:
        verifier = verifier_factory(
            verifier_path,
            executable_sha256=verifier_sha256,
            timeout_seconds=float(timeout_seconds),
        )
        acceptance = verifier.verify(artifact_path)
        containment = getattr(verifier, "last_containment_result", None)
        peak = _validate_containment(containment)
        marker, dimensions, trace_digest, trace_lines = _validate_acceptance_output(
            containment.stdout,
            containment.stderr,
        )
        _require(marker == "MINIMAL_CLEARANCE_VERIFIER_ACCEPT", "acceptance_marker")
        _validate_acceptance(acceptance, artifact)
        finished = monotonic()
        wall_seconds = float(finished - started)
        _require(math.isfinite(wall_seconds) and wall_seconds >= 0, "wall_time_invalid")
        return {
            "operation_index": operation_index,
            "wall_ms": round(wall_seconds * 1000.0, 3),
            "peak_job_commit_bytes": peak,
            "cap_bytes": containment.cap_bytes,
            "cap_enforced": containment.cap_enforced,
            "active_process_limit": containment.active_process_limit,
            "timed_out": containment.timed_out,
            "exit_code": containment.exit_code,
            "stdout_sha3_512": hashlib.sha3_512(containment.stdout).hexdigest().upper(),
            "stderr_sha3_512": hashlib.sha3_512(containment.stderr).hexdigest().upper(),
            "trace_sha3_512": trace_digest,
            "trace_line_count": trace_lines,
            "dimensions": dimensions,
        }
    except Exception as exc:
        raise _failure_from_exception(
            exc,
            fallback="verification_operation_failed",
            operation_index=operation_index,
        ) from exc


def _run_wave(
    concurrency: int,
    wave_index: int,
    first_operation_index: int,
    artifact_path: Path,
    verifier_path: Path,
    artifact: ArtifactSnapshot,
    verifier_sha256: str,
    timeout_seconds: float,
    *,
    verifier_factory: VerifierFactory,
    monotonic: Callable[[], float],
) -> dict[str, Any]:
    _validate_concurrency_level(concurrency)
    started = monotonic()
    futures = []
    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=concurrency, thread_name_prefix="bl-verifier") as executor:
        for offset in range(concurrency):
            futures.append(
                executor.submit(
                    _run_one,
                    first_operation_index + offset,
                    artifact_path,
                    verifier_path,
                    artifact,
                    verifier_sha256,
                    timeout_seconds,
                    verifier_factory=verifier_factory,
                    monotonic=monotonic,
                )
            )
        failures: list[tuple[int, BaseException]] = []
        for offset, future in enumerate(futures):
            try:
                results.append(future.result())
            except BaseException as exc:
                failures.append((first_operation_index + offset, exc))
        if failures:
            operation_index, failure = failures[0]
            raise _failure_from_exception(
                failure,
                fallback="verification_wave_failed",
                concurrency=concurrency,
                wave_index=wave_index,
                operation_index=operation_index,
            ) from failure
    finished = monotonic()
    wall_seconds = float(finished - started)
    _require(math.isfinite(wall_seconds) and wall_seconds > 0, "wave_time_invalid")
    _require(len(results) == concurrency, "wave_incomplete")
    results.sort(key=lambda item: item["operation_index"])
    return {
        "wave_index": wave_index,
        "verification_count": len(results),
        "wave_wall_ms": round(wall_seconds * 1000.0, 3),
        "operations": results,
    }


def _validate_concurrency_level(value: int) -> None:
    _require(value in CONCURRENCY_LEVELS, "concurrency_level_not_allowed")


def _round_metric(value: float) -> float:
    _require(math.isfinite(value) and value >= 0, "metric_invalid")
    return round(value, 6)


def _level_metrics(concurrency: int, waves: list[dict[str, Any]]) -> dict[str, Any]:
    _validate_concurrency_level(concurrency)
    operations = [operation for wave in waves for operation in wave["operations"]]
    _require(len(waves) == WAVES_PER_LEVEL, "level_wave_count")
    _require(len(operations) == concurrency * WAVES_PER_LEVEL, "level_operation_count")
    total_seconds = sum(float(wave["wave_wall_ms"]) for wave in waves) / 1000.0
    _require(total_seconds > 0 and math.isfinite(total_seconds), "level_time_invalid")
    latencies = sorted(float(operation["wall_ms"]) for operation in operations)
    midpoint = len(latencies) // 2
    if len(latencies) % 2:
        median = latencies[midpoint]
    else:
        median = (latencies[midpoint - 1] + latencies[midpoint]) / 2.0
    throughput = len(operations) / total_seconds
    return {
        "concurrency": concurrency,
        "verification_count": len(operations),
        "wave_count": len(waves),
        "waves": waves,
        "total_wave_seconds": _round_metric(total_seconds),
        "throughput_verifications_per_second": _round_metric(throughput),
        "claims_per_day_projection": _round_metric(throughput * 86_400.0),
        "latency_ms": {
            "min": _round_metric(min(latencies)),
            "median": _round_metric(median),
            "max": _round_metric(max(latencies)),
        },
    }


def run_ladder(
    artifact_path: Path,
    verifier_path: Path,
    *,
    timeout_seconds: float = 30.0 * 60.0,
    memory_probe: Callable[[], Mapping[str, int]] | None = None,
    verifier_factory: VerifierFactory = NativeMinimalClearanceVerifier,
    monotonic: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Run exactly three waves at each fixed concurrency level 1, 2, and 4."""
    memory = preflight_memory(memory_probe)
    artifact = _read_artifact_once(artifact_path)
    verifier_sha256 = _read_verifier_sha256(verifier_path)
    levels: list[dict[str, Any]] = []
    operation_index = 0
    for concurrency in CONCURRENCY_LEVELS:
        waves = []
        for wave_index in range(1, WAVES_PER_LEVEL + 1):
            waves.append(
                _run_wave(
                    concurrency,
                    wave_index,
                    operation_index,
                    artifact_path,
                    verifier_path,
                    artifact,
                    verifier_sha256,
                    timeout_seconds,
                    verifier_factory=verifier_factory,
                    monotonic=monotonic,
                )
            )
            operation_index += concurrency
        levels.append(_level_metrics(concurrency, waves))
    _require(operation_index == EXPECTED_VERIFICATIONS, "campaign_count")
    artifact_after = _check_artifact_after(artifact_path, artifact)
    all_operations = [
        operation
        for level in levels
        for wave in level["waves"]
        for operation in wave["operations"]
    ]
    _require(len(all_operations) == EXPECTED_VERIFICATIONS, "campaign_operation_count")
    first_dimensions = all_operations[0]["dimensions"]
    first_stdout_digest = all_operations[0]["stdout_sha3_512"]
    first_stderr_digest = all_operations[0]["stderr_sha3_512"]
    for operation in all_operations:
        _require(operation["dimensions"] == first_dimensions, "dimension_drift")
        _require(operation["stdout_sha3_512"] == first_stdout_digest, "stdout_drift")
        _require(operation["stderr_sha3_512"] == first_stderr_digest, "stderr_drift")
    baseline_throughput = levels[0]["throughput_verifications_per_second"]
    _require(baseline_throughput > 0, "baseline_throughput_invalid")
    for level in levels:
        level["efficiency_relative_to_concurrency_1"] = _round_metric(
            level["throughput_verifications_per_second"] / baseline_throughput
        )
    record = {
        "schema": SCHEMA,
        "artifact": {
            "bytes": artifact.bytes,
            "sha256": artifact.sha256,
            "sha3_512": artifact.sha3_512,
            "readonly_before": artifact.readonly,
            "readonly_after": artifact_after["readonly"],
        },
        "verifier_sha256": verifier_sha256,
        "memory_preflight": memory,
        "campaign": {
            "concurrency_levels": list(CONCURRENCY_LEVELS),
            "waves_per_concurrency": WAVES_PER_LEVEL,
            "verification_count": EXPECTED_VERIFICATIONS,
            "levels": levels,
        },
        "dimensions": first_dimensions,
        "proof_verification_count": EXPECTED_VERIFICATIONS,
        "prover_invocation_count": 0,
        "state_mutation_count": 0,
        "full_claim_cost_measured": False,
        "proving_throughput_measured": False,
        "burst_queue_qualified": False,
        "production_database_qualified": False,
        "multi_node_qualified": False,
        "node_failure_qualified": False,
        "soak_24h_qualified": False,
        "k128_k512_status": "rejected_old_calibration_profiles_not_run",
        "proof_suite_id": None,
        "production_usable": False,
        "activation": False,
        "security_nonclaims": [
            "theorem_security_ledger_open",
            "malicious_verifier_qrom_composition_open",
            "retry_grinding_accounting_open",
            "sha3_512_assurance_open",
            "lean_production_gate_open",
        ],
    }
    canonical_json_bytes(record)
    return record


_FORBIDDEN_KEY_FRAGMENTS = (
    "artifact_path",
    "verifier_path",
    "workspace_path",
    "hostname",
    "username",
    "pid",
    "process_id",
    "persistent_machine",
    "fingerprint",
    "raw_bytes",
    "raw_stdout",
    "raw_stderr",
    "secret",
    "phi",
)
_FORBIDDEN_OUTPUT_MARKERS = (
    "MINIMAL_CLEARANCE_VERIFIER_ACCEPT",
    "MINIMAL_CLEARANCE_BUILD",
    "MINIMAL_CLEARANCE_VERIFIER_STAGE",
)


def _validate_record_values(value: Any, key: str = "") -> None:
    lowered = key.lower()
    _require(
        not any(fragment in lowered for fragment in _FORBIDDEN_KEY_FRAGMENTS),
        "evidence_forbidden_key",
    )
    if isinstance(value, dict):
        for child_key, child_value in value.items():
            _require(type(child_key) is str, "evidence_key_type")
            _validate_record_values(child_value, child_key)
        return
    if isinstance(value, list):
        for child in value:
            _validate_record_values(child, key)
        return
    if isinstance(value, str):
        _require(
            not any(marker in value for marker in _FORBIDDEN_OUTPUT_MARKERS),
            "evidence_raw_output",
        )
        _require(not re.search(r"(?i)(?:[A-Z]:[\\/]|file://|\\\\)", value), "evidence_path")
        _require("\x00" not in value, "evidence_nul")


def canonical_json_bytes(record: Mapping[str, Any]) -> bytes:
    _require(isinstance(record, Mapping), "evidence_record_type")
    _validate_record_values(dict(record))
    try:
        encoded = json.dumps(
            record,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ThroughputError("evidence_json_invalid") from exc
    _require(len(encoded) <= MAX_EVIDENCE_BYTES, "evidence_size_cap")
    return encoded


def write_canonical_evidence(path: Path, record: Mapping[str, Any]) -> bytes:
    encoded = canonical_json_bytes(record)
    _require(not path.exists(), "evidence_output_exists")
    _require(path.parent.is_dir(), "evidence_output_parent")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise ThroughputError("evidence_output_write") from exc
    return encoded


def _ensure_external_workspace(path: Path) -> None:
    _require(path.is_dir() and not path.is_symlink(), "workspace_not_directory")
    probe = path / ("throughput-probe-" + os.urandom(12).hex())
    try:
        with probe.open("xb") as stream:
            stream.write(b"probe")
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as exc:
        raise ThroughputError("workspace_not_writable") from exc
    finally:
        try:
            probe.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise ThroughputError("workspace_probe_cleanup") from exc


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--temp-root", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=float, default=30.0 * 60.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        _ensure_external_workspace(args.temp_root)
        os.environ["TEMP"] = str(args.temp_root)
        os.environ["TMP"] = str(args.temp_root)
        record = run_ladder(
            args.artifact,
            args.verifier,
            timeout_seconds=args.timeout_seconds,
        )
        encoded = write_canonical_evidence(args.output, record)
        sys.stdout.write(encoded.decode("ascii") + "\n")
        return 0
    except ThroughputError as exc:
        sys.stderr.write("THROUGHPUT_FAILURE " + exc.bounded_text() + "\n")
        return 1
    except OSError as exc:
        failure = _failure_from_exception(exc, fallback="main_os_error")
        sys.stderr.write("THROUGHPUT_FAILURE " + failure.bounded_text() + "\n")
        return 1
    except Exception as exc:
        failure = _failure_from_exception(exc, fallback="main_exception")
        sys.stderr.write("THROUGHPUT_FAILURE " + failure.bounded_text() + "\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
