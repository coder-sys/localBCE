"""Fail-closed evidence validation for the native two-lane K512 campaign.

The serial H5 campaign contract intentionally remains serial.  This module is
the separate evidence boundary for the native two-lane execution mode.  It
only reads externally captured artifacts; it never treats the coordinator's
summary as sufficient evidence, never assigns a proof suite, and never
changes the no-swap or resource limits.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
import re
from typing import Any, Final, Mapping


ROOT: Final[Path] = Path(__file__).resolve().parents[2]
SCHEMA_VERSION: Final[str] = "blind_ledger_k512_parallel_campaign_evidence_v1"
PROFILE_ID: Final[str] = "K512_CALIBRATION"
WARMUP_COUNT: Final[int] = 1
MEASURED_REPETITIONS: Final[int] = 10
RUN_COUNT: Final[int] = WARMUP_COUNT + MEASURED_REPETITIONS
SHARD_COUNT: Final[int] = 4
SHARD_CONCURRENCY: Final[int] = 2
LATENCY_LIMIT_SECONDS: Final[float] = 180.0
MAX_RSS_BYTES: Final[int] = 5_000_000_000
MAX_SCRATCH_BYTES: Final[int] = 5_000_000_000
MAX_JSON_BYTES: Final[int] = 16 * 1024 * 1024
MAX_STATE_BYTES: Final[int] = 128 * 1024 * 1024
MAX_STDOUT_BYTES: Final[int] = 32 * 1024 * 1024
MAX_STDERR_BYTES: Final[int] = 2 * 1024 * 1024
MAX_MONITOR_BYTES: Final[int] = 2 * 1024 * 1024

_HEX_128 = re.compile(r"^[0-9a-f]{128}$")
_INTEGER = re.compile(r"^[0-9]+$")
_SIGNED_INTEGER = re.compile(r"^-?[0-9]+$")
_NUMBER = re.compile(r"^[0-9]+(?:\.[0-9]+)?$")
_SIGNED_NUMBER = re.compile(r"^-?[0-9]+(?:\.[0-9]+)?$")
_KEY_VALUE = re.compile(r"^[^=\r\n]+=[^\r\n]*$")


class K512ParallelCampaignEvidenceError(ValueError):
    """Raised when parallel campaign evidence is missing or contradictory."""


def _object(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        raise K512ParallelCampaignEvidenceError(f"k512_parallel_{label}_shape_invalid")
    return value


def _text(value: object, label: str, maximum: int = 512) -> str:
    if type(value) is not str or not value or len(value) > maximum or "\x00" in value:
        raise K512ParallelCampaignEvidenceError(f"k512_parallel_{label}_invalid")
    return value


def _digest(value: object, label: str) -> str:
    if type(value) is not str or _HEX_128.fullmatch(value) is None or value == "0" * 128:
        raise K512ParallelCampaignEvidenceError(f"k512_parallel_{label}_digest_invalid")
    return value


def _integer(value: object, label: str, *, minimum: int = 0) -> int:
    if type(value) is int and value >= minimum:
        return value
    if type(value) is str and _INTEGER.fullmatch(value) is not None:
        parsed = int(value)
        if parsed >= minimum:
            return parsed
    raise K512ParallelCampaignEvidenceError(f"k512_parallel_{label}_integer_invalid")


def _signed_integer(value: object, label: str) -> int:
    if type(value) is int:
        return value
    if type(value) is str and _SIGNED_INTEGER.fullmatch(value) is not None:
        return int(value)
    raise K512ParallelCampaignEvidenceError(f"k512_parallel_{label}_integer_invalid")


def _number(value: object, label: str, *, minimum: float = 0.0, positive: bool = False) -> float:
    if type(value) is int or type(value) is float:
        if isinstance(value, bool):
            raise K512ParallelCampaignEvidenceError(f"k512_parallel_{label}_number_invalid")
        parsed = float(value)
    elif type(value) is str and _NUMBER.fullmatch(value) is not None:
        parsed = float(value)
    else:
        raise K512ParallelCampaignEvidenceError(f"k512_parallel_{label}_number_invalid")
    if not math.isfinite(parsed) or parsed < minimum or (positive and parsed <= 0.0):
        raise K512ParallelCampaignEvidenceError(f"k512_parallel_{label}_number_invalid")
    return parsed


def _signed_number(value: object, label: str) -> float:
    if type(value) is int or type(value) is float:
        if isinstance(value, bool):
            raise K512ParallelCampaignEvidenceError(f"k512_parallel_{label}_number_invalid")
        parsed = float(value)
    elif type(value) is str and _SIGNED_NUMBER.fullmatch(value) is not None:
        parsed = float(value)
    else:
        raise K512ParallelCampaignEvidenceError(f"k512_parallel_{label}_number_invalid")
    if not math.isfinite(parsed):
        raise K512ParallelCampaignEvidenceError(f"k512_parallel_{label}_number_invalid")
    return parsed


def _boolean_text(values: Mapping[str, str], key: str, expected: str = "true") -> None:
    if values.get(key) != expected:
        raise K512ParallelCampaignEvidenceError(f"k512_parallel_{key}_invalid")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise K512ParallelCampaignEvidenceError("k512_parallel_duplicate_json_key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise K512ParallelCampaignEvidenceError(f"k512_parallel_nonfinite_json:{value}")


def _read_json(path: Path, label: str) -> object:
    if not isinstance(path, Path) or not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise K512ParallelCampaignEvidenceError(f"k512_parallel_{label}_file_invalid")
    if path.resolve().is_relative_to(ROOT):
        raise K512ParallelCampaignEvidenceError(f"k512_parallel_{label}_inside_checkout")
    try:
        raw = path.read_bytes()
        if len(raw) > MAX_JSON_BYTES:
            raise K512ParallelCampaignEvidenceError(f"k512_parallel_{label}_too_large")
        encoding = "utf-8-sig" if raw.startswith(b"\xef\xbb\xbf") else "utf-8"
        return json.loads(raw.decode(encoding), object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_constant)
    except K512ParallelCampaignEvidenceError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise K512ParallelCampaignEvidenceError(f"k512_parallel_{label}_read_failed") from exc


def _artifact(path_value: object, label: str, *, maximum_bytes: int) -> tuple[Path, bytes]:
    path = Path(_text(path_value, f"{label}_path", 2048))
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise K512ParallelCampaignEvidenceError(f"k512_parallel_{label}_file_invalid")
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise K512ParallelCampaignEvidenceError(f"k512_parallel_{label}_read_failed") from exc
    if len(data) > maximum_bytes:
        raise K512ParallelCampaignEvidenceError(f"k512_parallel_{label}_too_large")
    if path.resolve().is_relative_to(ROOT):
        raise K512ParallelCampaignEvidenceError(f"k512_parallel_{label}_inside_checkout")
    return path, data


def _parse_key_values(data: bytes, label: str) -> dict[str, str]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise K512ParallelCampaignEvidenceError(f"k512_parallel_{label}_not_utf8") from exc
    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line or _KEY_VALUE.fullmatch(line) is None:
            raise K512ParallelCampaignEvidenceError(f"k512_parallel_{label}_line_invalid")
        key, value = line.split("=", 1)
        if key in values:
            raise K512ParallelCampaignEvidenceError(f"k512_parallel_{label}_duplicate_field:{key}")
        values[key] = value
    return values


def _parse_monitor(data: bytes, stdout: bytes, stderr: bytes) -> dict[str, str]:
    try:
        text = data.decode("utf-8").replace("\r\n", "\n")
        marker_stdout = "---stdout---\n"
        marker_stderr = "\n---stderr---\n"
        if text.count(marker_stdout) != 1 or text.count(marker_stderr) != 1:
            raise K512ParallelCampaignEvidenceError("k512_parallel_monitor_sections_invalid")
        head, rest = text.split(marker_stdout, 1)
        embedded_stdout, embedded_stderr = rest.split(marker_stderr, 1)
        if embedded_stdout.splitlines() != stdout.decode("utf-8").splitlines():
            raise K512ParallelCampaignEvidenceError("k512_parallel_monitor_stdout_disagreement")
        if embedded_stderr.splitlines() != stderr.decode("utf-8").splitlines():
            raise K512ParallelCampaignEvidenceError("k512_parallel_monitor_stderr_disagreement")
        values = _parse_key_values(head.encode("utf-8"), "monitor")
    except UnicodeDecodeError as exc:
        raise K512ParallelCampaignEvidenceError("k512_parallel_monitor_not_utf8") from exc
    expected = {
        "external_exit_code",
        "external_wall_seconds",
        "external_process_tree_peak_bytes",
        "external_process_tree_peak_mb",
        "external_gpu_peak_mib",
        "pagefile_before_mb",
        "pagefile_after_mb",
        "pagefile_growth_mb",
        "post_launch_driver_event_count",
        "stdout_bytes",
        "stdout_sha256",
        "stderr_bytes",
        "stderr_sha256",
    }
    if set(values) != expected:
        raise K512ParallelCampaignEvidenceError("k512_parallel_monitor_fields_invalid")
    return values


def _require_fields(values: Mapping[str, str], fields: set[str], label: str) -> None:
    if set(values) != fields:
        raise K512ParallelCampaignEvidenceError(f"k512_parallel_{label}_fields_invalid")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _state_path_for_stdout(stdout_path: Path) -> Path:
    if not stdout_path.name.endswith(".stdout.txt"):
        raise K512ParallelCampaignEvidenceError("k512_parallel_stdout_name_invalid")
    return stdout_path.with_name(stdout_path.name[: -len(".stdout.txt")] + ".stderr.txt")


def _required_stdout_fields() -> set[str]:
    return {
        *(f"shard_{index}_{suffix}" for index in range(SHARD_COUNT) for suffix in ("verified", "proof_seconds", "coordinator_wall_seconds")),
        "status",
        "evidence_class",
        "atomic_parent_binding_sha3_512",
        "atomic_statement_sha3_512",
        "state_plane_binding_verified",
        "state_plane_binding_digest_sha3_512",
        "state_component_proof_suite_id",
        "state_commitment_backend",
        "state_hash_bus_calls_verified",
        "execution_manifest_sha3_512",
        "semantic_hash_bus_file_sha3_512",
        "ordered_shards",
        "complete_shard_proofs",
        "shard_concurrency",
        "sequential_single_gpu_execution",
        "parallel_gpu_images",
        "theorem_free_challenge_sharing",
        "atomic_acceptance_boundary",
        "all_shards_independently_verified",
        "atomic_receipt_sha3_512",
        "complete_process_wall_seconds",
        "peak_host_mb",
        "peak_device_mb",
        "scratch_mb",
        "latency_limit_seconds",
        "complete_proof_latency_gate",
        "proof_suite_id",
        "complete_proof_qualification",
    }


def _cross_equal(actual: float, expected: float, label: str) -> None:
    if not math.isclose(actual, expected, rel_tol=0.0, abs_tol=0.000001):
        raise K512ParallelCampaignEvidenceError(f"k512_parallel_{label}_disagreement")


@dataclass(frozen=True, slots=True)
class K512ParallelRunEvidence:
    ordinal: int
    phase: str
    state_binding_sha3_512: str
    parent_binding_sha3_512: str
    statement_sha3_512: str
    state_plane_binding_sha3_512: str
    receipt_sha3_512: str
    stdout_sha256: str
    stderr_sha256: str
    execution_manifest_sha3_512: str
    complete_process_wall_seconds: float
    external_process_tree_peak_bytes: int
    scratch_bytes: int
    external_gpu_peak_mib: int


@dataclass(frozen=True, slots=True)
class K512ParallelCampaignEvidence:
    campaign_id: str
    execution_manifest_sha3_512: str
    campaign_digest_sha3_512: str
    runs: tuple[K512ParallelRunEvidence, ...]
    p95_seconds: float
    mean_seconds: float
    max_peak_rss_bytes: int
    max_scratch_bytes: int
    max_external_gpu_peak_mib: int
    proof_suite_id: None = None
    activation_allowed: bool = False

    @property
    def measured_runs(self) -> tuple[K512ParallelRunEvidence, ...]:
        return tuple(run for run in self.runs if run.phase == "measured")

    def as_public_dict(self) -> dict[str, object]:
        return {
            "schema_version": SCHEMA_VERSION,
            "status": "QUALIFIED_K512_TWO_LANE_NONACTIVATING",
            "campaign_id": self.campaign_id,
            "execution_manifest_sha3_512": self.execution_manifest_sha3_512,
            "campaign_digest_sha3_512": self.campaign_digest_sha3_512,
            "run_count": len(self.runs),
            "warmup_count": sum(run.phase == "warmup" for run in self.runs),
            "measured_count": len(self.measured_runs),
            "shard_count": SHARD_COUNT,
            "shard_concurrency": SHARD_CONCURRENCY,
            "p95_seconds": self.p95_seconds,
            "mean_seconds": self.mean_seconds,
            "max_peak_rss_bytes": self.max_peak_rss_bytes,
            "max_scratch_bytes": self.max_scratch_bytes,
            "max_external_gpu_peak_mib": self.max_external_gpu_peak_mib,
            "proofSuiteId": self.proof_suite_id,
            "activation_allowed": self.activation_allowed,
        }


def _validate_run(raw: Mapping[str, Any], *, expected_ordinal: int, results_path: Path) -> K512ParallelRunEvidence:
    required = {
        "ordinal",
        "phase",
        "state",
        "state_verify_exit",
        "monitor_exit",
        "status",
        "complete_shard_proofs",
        "wall",
        "host",
        "device",
        "scratch",
        "suite",
        "qualification",
        "external_tree",
        "external_gpu",
        "page_growth",
        "driver_events",
        "stderr_bytes",
        "stdout_path",
        "monitor_path",
    }
    item = _object(raw, required, f"run_{expected_ordinal}")
    phase = "warmup" if expected_ordinal == 0 else "measured"
    if item["ordinal"] != expected_ordinal or item["phase"] != phase:
        raise K512ParallelCampaignEvidenceError("k512_parallel_run_order_invalid")
    if _text(item["status"], "run_status") != "verified" or item["suite"] != "null" or item["qualification"] != "false":
        raise K512ParallelCampaignEvidenceError("k512_parallel_run_activation_boundary_invalid")
    if _integer(item["state_verify_exit"], "state_verify_exit") != 0 or _integer(item["monitor_exit"], "monitor_exit") != 0:
        raise K512ParallelCampaignEvidenceError("k512_parallel_external_verifier_failed")
    if _integer(item["complete_shard_proofs"], "complete_shard_proofs") != SHARD_COUNT:
        raise K512ParallelCampaignEvidenceError("k512_parallel_shard_count_invalid")

    state_path, state_bytes = _artifact(item["state"], "state_binding", maximum_bytes=MAX_STATE_BYTES)
    if state_path.resolve() == results_path.resolve() or state_path.resolve().parent == results_path.resolve().parent:
        raise K512ParallelCampaignEvidenceError("k512_parallel_state_input_reuse_boundary_invalid")
    state_digest = hashlib.sha3_512(state_bytes).hexdigest()

    stdout_path, stdout_bytes = _artifact(item["stdout_path"], "stdout", maximum_bytes=MAX_STDOUT_BYTES)
    stderr_path, stderr_bytes = _artifact(str(_state_path_for_stdout(stdout_path)), "stderr", maximum_bytes=MAX_STDERR_BYTES)
    monitor_path, monitor_bytes = _artifact(item["monitor_path"], "monitor", maximum_bytes=MAX_MONITOR_BYTES)
    if stdout_path.resolve().parent != results_path.resolve().parent or monitor_path.resolve().parent != results_path.resolve().parent or stderr_path.resolve().parent != results_path.resolve().parent:
        raise K512ParallelCampaignEvidenceError("k512_parallel_output_directory_invalid")
    monitor = _parse_monitor(monitor_bytes, stdout_bytes, stderr_bytes)
    stdout = _parse_key_values(stdout_bytes, "stdout")
    _require_fields(stdout, _required_stdout_fields(), "stdout")

    if stdout["status"] != "verified" or stdout["evidence_class"] != "k512_atomic_semantic_prototype":
        raise K512ParallelCampaignEvidenceError("k512_parallel_native_status_invalid")
    for key in (
        "state_plane_binding_verified",
        "state_hash_bus_calls_verified",
        "atomic_acceptance_boundary",
        "all_shards_independently_verified",
        "complete_proof_latency_gate",
    ):
        _boolean_text(stdout, key)
    for key in ("sequential_single_gpu_execution", "theorem_free_challenge_sharing", "complete_proof_qualification"):
        _boolean_text(stdout, key, "false")
    if stdout["state_commitment_backend"] != "TRANSPARENT_SHAKE256_1024":
        raise K512ParallelCampaignEvidenceError("k512_parallel_state_backend_invalid")
    if stdout["ordered_shards"] != "0,1,2,3" or stdout["complete_shard_proofs"] != "4":
        raise K512ParallelCampaignEvidenceError("k512_parallel_ordered_shards_invalid")
    if stdout["shard_concurrency"] != "2" or stdout["parallel_gpu_images"] != "2":
        raise K512ParallelCampaignEvidenceError("k512_parallel_concurrency_invalid")
    if stdout["proof_suite_id"] != "null":
        raise K512ParallelCampaignEvidenceError("k512_parallel_proof_suite_must_remain_null")
    for key in (
        "atomic_parent_binding_sha3_512",
        "atomic_statement_sha3_512",
        "state_plane_binding_digest_sha3_512",
        "state_component_proof_suite_id",
        "execution_manifest_sha3_512",
        "semantic_hash_bus_file_sha3_512",
        "atomic_receipt_sha3_512",
    ):
        _digest(stdout[key], key)
    for index in range(SHARD_COUNT):
        _boolean_text(stdout, f"shard_{index}_verified")
        _number(stdout[f"shard_{index}_proof_seconds"], f"shard_{index}_proof_seconds", positive=True)
        _number(stdout[f"shard_{index}_coordinator_wall_seconds"], f"shard_{index}_coordinator_wall_seconds", positive=True)

    wall = _number(stdout["complete_process_wall_seconds"], "complete_process_wall_seconds", positive=True)
    if wall >= LATENCY_LIMIT_SECONDS or _number(stdout["latency_limit_seconds"], "latency_limit_seconds") != LATENCY_LIMIT_SECONDS:
        raise K512ParallelCampaignEvidenceError("k512_parallel_latency_gate_invalid")
    host = _number(stdout["peak_host_mb"], "peak_host_mb", positive=True)
    device = _number(stdout["peak_device_mb"], "peak_device_mb", positive=True)
    scratch = _number(stdout["scratch_mb"], "scratch_mb")
    if host > 5_000.0 or device > 5_000.0 or scratch >= 5_000.0:
        raise K512ParallelCampaignEvidenceError("k512_parallel_native_resource_gate")

    if _integer(monitor["external_exit_code"], "external_exit_code") != 0 or _integer(monitor["stdout_bytes"], "stdout_bytes") != len(stdout_bytes):
        raise K512ParallelCampaignEvidenceError("k512_parallel_monitor_exit_or_stdout_invalid")
    if _integer(monitor["stderr_bytes"], "stderr_bytes") != 0 or stderr_bytes:
        raise K512ParallelCampaignEvidenceError("k512_parallel_stderr_present")
    if _integer(monitor["post_launch_driver_event_count"], "driver_event_count") != 0:
        raise K512ParallelCampaignEvidenceError("k512_parallel_driver_event_present")
    page_before = _integer(monitor["pagefile_before_mb"], "pagefile_before_mb")
    page_after = _integer(monitor["pagefile_after_mb"], "pagefile_after_mb")
    page_growth = _signed_integer(monitor["pagefile_growth_mb"], "pagefile_growth_mb")
    if page_after - page_before != page_growth or page_growth > 0:
        raise K512ParallelCampaignEvidenceError("k512_parallel_pagefile_growth")
    if monitor["stdout_sha256"] != _sha256(stdout_bytes):
        raise K512ParallelCampaignEvidenceError("k512_parallel_stdout_digest_mismatch")
    if monitor["stderr_sha256"] != _sha256(stderr_bytes):
        raise K512ParallelCampaignEvidenceError("k512_parallel_stderr_digest_mismatch")
    _number(monitor["external_wall_seconds"], "external_wall_seconds", positive=True)
    peak_rss = _integer(monitor["external_process_tree_peak_bytes"], "peak_rss", minimum=1)
    if peak_rss > MAX_RSS_BYTES:
        raise K512ParallelCampaignEvidenceError("k512_parallel_peak_rss_limit")
    _cross_equal(
        _number(monitor["external_process_tree_peak_mb"], "external_tree_mb"),
        peak_rss / 1_000_000.0,
        "monitor_external_tree",
    )
    scratch_bytes = int(scratch * 1_000_000.0)
    if scratch_bytes >= MAX_SCRATCH_BYTES:
        raise K512ParallelCampaignEvidenceError("k512_parallel_scratch_limit")
    gpu_peak = _integer(monitor["external_gpu_peak_mib"], "external_gpu_peak_mib", minimum=1)
    _cross_equal(_number(item["wall"], "result_wall"), wall, "result_wall")
    _cross_equal(_number(item["host"], "result_host"), host, "result_host")
    _cross_equal(_number(item["device"], "result_device"), device, "result_device")
    _cross_equal(_number(item["scratch"], "result_scratch"), scratch, "result_scratch")
    _cross_equal(_number(item["external_tree"], "result_external_tree"), _number(monitor["external_process_tree_peak_mb"], "external_tree_mb"), "result_external_tree")
    if _integer(item["external_gpu"], "result_external_gpu") != gpu_peak or _signed_integer(item["page_growth"], "result_page_growth") != page_growth or _integer(item["driver_events"], "result_driver_events") != 0 or _integer(item["stderr_bytes"], "result_stderr_bytes") != 0:
        raise K512ParallelCampaignEvidenceError("k512_parallel_result_monitor_disagreement")
    return K512ParallelRunEvidence(
        ordinal=expected_ordinal,
        phase=phase,
        state_binding_sha3_512=state_digest,
        parent_binding_sha3_512=stdout["atomic_parent_binding_sha3_512"],
        statement_sha3_512=stdout["atomic_statement_sha3_512"],
        state_plane_binding_sha3_512=stdout["state_plane_binding_digest_sha3_512"],
        receipt_sha3_512=stdout["atomic_receipt_sha3_512"],
        stdout_sha256=_sha256(stdout_bytes),
        stderr_sha256=_sha256(stderr_bytes),
        execution_manifest_sha3_512=stdout["execution_manifest_sha3_512"],
        complete_process_wall_seconds=wall,
        external_process_tree_peak_bytes=peak_rss,
        scratch_bytes=scratch_bytes,
        external_gpu_peak_mib=gpu_peak,
    )


def validate_k512_parallel_campaign(results_path: Path, summary_path: Path | None = None) -> K512ParallelCampaignEvidence:
    """Validate one exact 11-launch two-lane K512 campaign."""

    if not isinstance(results_path, Path):
        raise TypeError("k512_parallel_results_path_required")
    if summary_path is None:
        summary_path = results_path.with_name("campaign-summary.json")
    if not isinstance(summary_path, Path):
        raise TypeError("k512_parallel_summary_path_required")
    results_value = _read_json(results_path, "results")
    summary_value = _read_json(summary_path, "summary")
    if type(results_value) is not list or len(results_value) != RUN_COUNT:
        raise K512ParallelCampaignEvidenceError("k512_parallel_run_count_invalid")
    summary = _object(
        summary_value,
        {
            "campaign_id",
            "run_count",
            "warmup_count",
            "measured_count",
            "measured_wall_seconds",
            "p95_measured_wall_seconds",
            "mean_measured_wall_seconds",
            "max_reported_host_mb",
            "max_reported_device_mb",
            "max_external_process_tree_mb",
            "max_external_gpu_mib",
            "max_pagefile_growth_mb",
            "max_driver_events",
            "max_stderr_bytes",
        },
        "summary",
    )
    campaign_id = _text(summary["campaign_id"], "campaign_id", 128)
    if _integer(summary["run_count"], "summary_run_count") != RUN_COUNT or _integer(summary["warmup_count"], "summary_warmup_count") != WARMUP_COUNT or _integer(summary["measured_count"], "summary_measured_count") != MEASURED_REPETITIONS:
        raise K512ParallelCampaignEvidenceError("k512_parallel_summary_shape_invalid")
    parsed = tuple(_validate_run(item, expected_ordinal=index, results_path=results_path) for index, item in enumerate(results_value))
    identities = [
        (run.state_binding_sha3_512, run.parent_binding_sha3_512, run.statement_sha3_512, run.state_plane_binding_sha3_512, run.receipt_sha3_512, run.stdout_sha256)
        for run in parsed
    ]
    if len(set(identities)) != RUN_COUNT or len({run.state_binding_sha3_512 for run in parsed}) != RUN_COUNT:
        raise K512ParallelCampaignEvidenceError("k512_parallel_reused_or_duplicate_identity")
    manifests = {run.execution_manifest_sha3_512 for run in parsed}
    if len(manifests) != 1:
        raise K512ParallelCampaignEvidenceError("k512_parallel_execution_manifest_disagreement")
    measured = tuple(run.complete_process_wall_seconds for run in parsed if run.phase == "measured")
    if len(measured) != MEASURED_REPETITIONS:
        raise K512ParallelCampaignEvidenceError("k512_parallel_measured_count_invalid")
    p95 = max(measured)
    mean = sum(measured) / len(measured)
    summary_walls = summary["measured_wall_seconds"]
    if type(summary_walls) is not list or len(summary_walls) != MEASURED_REPETITIONS:
        raise K512ParallelCampaignEvidenceError("k512_parallel_summary_wall_shape_invalid")
    if any(_number(value, "summary_wall", positive=True) != wall for value, wall in zip(summary_walls, sorted(measured), strict=True)):
        raise K512ParallelCampaignEvidenceError("k512_parallel_summary_wall_disagreement")
    if _number(summary["p95_measured_wall_seconds"], "summary_p95") != p95 or not math.isclose(_number(summary["mean_measured_wall_seconds"], "summary_mean"), mean, rel_tol=0.0, abs_tol=0.000001):
        raise K512ParallelCampaignEvidenceError("k512_parallel_summary_statistics_disagreement")
    summary_pagefile = _signed_number(summary["max_pagefile_growth_mb"], "summary_pagefile")
    max_pagefile = max(_signed_integer(item["page_growth"], "summary_pagefile_item") for item in results_value)
    if summary_pagefile > 0.0 or summary_pagefile != max_pagefile or _number(summary["max_driver_events"], "summary_driver_events") != 0.0 or _number(summary["max_stderr_bytes"], "summary_stderr") != 0.0:
        raise K512ParallelCampaignEvidenceError("k512_parallel_summary_safety_gate_invalid")
    max_rss = max(run.external_process_tree_peak_bytes for run in parsed)
    max_scratch = max(run.scratch_bytes for run in parsed)
    max_gpu = max(run.external_gpu_peak_mib for run in parsed)
    if not math.isclose(_number(summary["max_external_process_tree_mb"], "summary_external_tree"), max_rss / 1_000_000.0, rel_tol=0.0, abs_tol=0.000001) or not math.isclose(_number(summary["max_external_gpu_mib"], "summary_external_gpu"), max_gpu, rel_tol=0.0, abs_tol=0.000001):
        raise K512ParallelCampaignEvidenceError("k512_parallel_summary_resource_disagreement")
    if not math.isclose(_number(summary["max_reported_host_mb"], "summary_host"), max(_number(item["host"], "summary_host_item") for item in results_value), rel_tol=0.0, abs_tol=0.000001) or not math.isclose(_number(summary["max_reported_device_mb"], "summary_device"), max(_number(item["device"], "summary_device_item") for item in results_value), rel_tol=0.0, abs_tol=0.000001):
        raise K512ParallelCampaignEvidenceError("k512_parallel_summary_reported_resource_disagreement")
    try:
        canonical_results = json.dumps(results_value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise K512ParallelCampaignEvidenceError("k512_parallel_results_not_canonicalizable") from exc
    return K512ParallelCampaignEvidence(
        campaign_id=campaign_id,
        execution_manifest_sha3_512=next(iter(manifests)),
        campaign_digest_sha3_512=hashlib.sha3_512(canonical_results).hexdigest(),
        runs=parsed,
        p95_seconds=p95,
        mean_seconds=mean,
        max_peak_rss_bytes=max_rss,
        max_scratch_bytes=max_scratch,
        max_external_gpu_peak_mib=max_gpu,
    )


__all__ = (
    "K512ParallelCampaignEvidence",
    "K512ParallelCampaignEvidenceError",
    "K512ParallelRunEvidence",
    "LATENCY_LIMIT_SECONDS",
    "MAX_RSS_BYTES",
    "MAX_SCRATCH_BYTES",
    "MEASURED_REPETITIONS",
    "PROFILE_ID",
    "RUN_COUNT",
    "SCHEMA_VERSION",
    "SHARD_CONCURRENCY",
    "SHARD_COUNT",
    "WARMUP_COUNT",
    "validate_k512_parallel_campaign",
)
