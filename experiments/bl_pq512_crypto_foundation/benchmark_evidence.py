"""Strict BL-PQ512 benchmark fixture validation and qualification boundary.

This module validates synthetic, nonactivating benchmark fixtures. It does
not run a prover. A self-hashed fixture cannot prove the source tree, worker
execution, or OS resource counters that it describes, so the public
qualification API always fails closed pending an externally captured evidence
bundle.
The JSON Schema fixes the wire shape; this module enforces relationships that
JSON Schema cannot express, including canonical bytes, self-hashes, source
continuity, exact order statistics, resource gates, and proof-section layout.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Final, Mapping, Sequence


ROOT: Final[Path] = Path(__file__).resolve().parents[2]
SCHEMA_PATH: Final[Path] = ROOT / "schemas" / "bl_pq512_benchmark_evidence_v1.schema.json"
REFERENCE_HARDWARE_PATH: Final[Path] = ROOT / "config" / "bl_pq512_reference_hardware_v1.json"
SCHEMA_VERSION: Final[str] = "blind_ledger_pq512_benchmark_evidence_v1"
REFERENCE_HARDWARE_SCHEMA: Final[str] = "blind_ledger_reference_hardware_v1"
REFERENCE_CLASS_ID: Final[str] = "BL_REF_DELL_G15_5535_V1"
MAX_DOCUMENT_BYTES: Final[int] = 16 * 1024 * 1024
U64_MAX: Final[int] = (1 << 64) - 1
PPM: Final[int] = 1_000_000

PROTOCOL: Final[dict[str, object]] = {
    "automatic_retry_allowed": False,
    "cached_proofs_allowed": False,
    "cached_witnesses_allowed": False,
    "clock": "MONOTONIC_NANOSECONDS",
    "fresh_process_per_run": True,
    "independent_verification_in_timed_boundary": True,
    "masking_in_timed_boundary": True,
    "measured_repetitions": 10,
    "outlier_exclusion_allowed": False,
    "p50_method": "EVEN_MEDIAN_FLOOR",
    "p95_method": "NEAREST_RANK_CEIL",
    "parsing_in_timed_boundary": True,
    "public_coin_in_timed_boundary": True,
    "warmup_count": 1,
}
GATES: Final[dict[str, int]] = {
    "disk_headroom_min_ppm": 150_000,
    "mad_over_p50_max_ppm": 100_000,
    "p95_over_p50_max_ppm": 1_200_000,
    "peak_rss_max_bytes": 5_000_000_000,
    "ram_headroom_min_ppm": 100_000,
    "scratch_max_bytes": 5_000_000_000,
    "swap_max_bytes": 0,
}
FAILURE_POLICY: Final[dict[str, bool]] = {
    "failed_run_disqualifies": True,
    "failed_run_preserved": True,
    "partial_campaign_qualifies": False,
    "substitution_allowed": False,
}
PROFILE_SPECS: Final[tuple[tuple[str, int, int, int, int], ...]] = (
    ("K128_CALIBRATION", 128, 100, 28, 60_000_000_000),
    ("K512_CALIBRATION", 512, 500, 12, 180_000_000_000),
)

_DIGEST = re.compile(r"^[0-9a-f]{128}$")
_GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_CAMPAIGN_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{7,127}$")
_TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_MODULE_ID = re.compile(r"^[A-Z0-9_]{1,64}$")


class BenchmarkEvidenceError(ValueError):
    """Raised when benchmark evidence is ambiguous, altered, or nonqualifying."""


@dataclass(frozen=True, slots=True)
class BenchmarkFixtureValidation:
    campaign_id: str
    k128_p95_ns: int
    k512_p95_ns: int
    measured_run_count: int
    warmup_run_count: int


def canonical_json_bytes(value: object) -> bytes:
    try:
        text = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise BenchmarkEvidenceError("benchmark_evidence_not_canonical_json_value") from exc
    return text.encode("utf-8")


def sha3_512_bytes(value: bytes) -> str:
    return hashlib.sha3_512(value).hexdigest()


def sha3_512_file(path: Path) -> str:
    digest = hashlib.sha3_512()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BenchmarkEvidenceError(f"benchmark_evidence_duplicate_key:{key}")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise BenchmarkEvidenceError(f"benchmark_evidence_nonfinite_number:{value}")


def read_canonical_json(path: Path, *, maximum_bytes: int = MAX_DOCUMENT_BYTES) -> dict[str, Any]:
    if not isinstance(path, Path):
        raise TypeError("benchmark_evidence_path_required")
    try:
        size = path.stat().st_size
    except FileNotFoundError as exc:
        raise BenchmarkEvidenceError(f"benchmark_evidence_missing:{path}") from exc
    if size < 3 or size > maximum_bytes:
        raise BenchmarkEvidenceError(f"benchmark_evidence_size_invalid:{path}")
    raw = path.read_bytes()
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BenchmarkEvidenceError(f"benchmark_evidence_json_invalid:{path}") from exc
    if not isinstance(value, dict):
        raise BenchmarkEvidenceError(f"benchmark_evidence_root_not_object:{path}")
    if raw != canonical_json_bytes(value) + b"\n":
        raise BenchmarkEvidenceError(f"benchmark_evidence_not_canonical:{path}")
    return value


def _object(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BenchmarkEvidenceError(f"{label}_object_required")
    actual = set(value)
    if actual != keys:
        raise BenchmarkEvidenceError(
            f"{label}_keys_invalid:missing={sorted(keys - actual)}:extra={sorted(actual - keys)}"
        )
    return value


def _sequence(value: object, length: int, label: str) -> list[Any]:
    if not isinstance(value, list) or len(value) != length:
        raise BenchmarkEvidenceError(f"{label}_length_invalid")
    return value


def _u64(value: object, label: str, *, positive: bool = False) -> int:
    if type(value) is not int or value < (1 if positive else 0) or value > U64_MAX:
        raise BenchmarkEvidenceError(f"{label}_u64_invalid")
    return value


def _boolean(value: object, expected: bool, label: str) -> None:
    if type(value) is not bool or value is not expected:
        raise BenchmarkEvidenceError(f"{label}_boolean_invalid")


def _string(value: object, label: str, *, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value:
        raise BenchmarkEvidenceError(f"{label}_string_invalid")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise BenchmarkEvidenceError(f"{label}_format_invalid")
    return value


def _digest(value: object, label: str) -> str:
    digest = _string(value, label, pattern=_DIGEST)
    if digest == "0" * 128:
        raise BenchmarkEvidenceError(f"{label}_zero_digest_forbidden")
    return digest


def _exact_mapping(value: object, expected: Mapping[str, object], label: str) -> None:
    actual = _object(value, set(expected), label)
    for key, expected_value in expected.items():
        actual_value = actual[key]
        if type(actual_value) is not type(expected_value) or actual_value != expected_value:
            raise BenchmarkEvidenceError(f"{label}_value_invalid")


def _ceil_ratio(numerator: int, denominator: int, scale: int = PPM) -> int:
    if denominator <= 0:
        raise BenchmarkEvidenceError("benchmark_evidence_ratio_denominator_invalid")
    return (numerator * scale + denominator - 1) // denominator


def _headroom_bytes(total: int, ppm: int) -> int:
    return _ceil_ratio(total, PPM, ppm)


def validate_reference_hardware_config(
    value: Mapping[str, Any] | None = None,
    *,
    require_ready: bool,
) -> dict[str, Any]:
    hardware = (
        read_canonical_json(REFERENCE_HARDWARE_PATH)
        if value is None
        else _object(
            value,
            {
                "benchmark_ready",
                "benchmark_ready_failures",
                "cpu",
                "discrete_gpu",
                "integrated_gpu",
                "machine",
                "measured_on",
                "memory",
                "rust",
                "schema_version",
                "storage",
            },
            "reference_hardware",
        )
    )
    _object(
        hardware,
        {
            "benchmark_ready",
            "benchmark_ready_failures",
            "cpu",
            "discrete_gpu",
            "integrated_gpu",
            "machine",
            "measured_on",
            "memory",
            "rust",
            "schema_version",
            "storage",
        },
        "reference_hardware",
    )
    if hardware["schema_version"] != REFERENCE_HARDWARE_SCHEMA:
        raise BenchmarkEvidenceError("reference_hardware_schema_invalid")
    cpu = _object(
        hardware["cpu"],
        {"logical_processors", "maximum_clock_mhz_reported", "model", "physical_cores"},
        "reference_hardware_cpu",
    )
    if cpu != {
        "logical_processors": 16,
        "maximum_clock_mhz_reported": 3801,
        "model": "AMD Ryzen 7 7840HS",
        "physical_cores": 8,
    }:
        raise BenchmarkEvidenceError("reference_hardware_cpu_invalid")
    discrete = _object(
        hardware["discrete_gpu"],
        {"compute_capability", "model", "reported_vram_mib"},
        "reference_hardware_discrete_gpu",
    )
    if discrete != {
        "compute_capability": "8.9",
        "model": "NVIDIA GeForce RTX 4060 Laptop GPU",
        "reported_vram_mib": 8188,
    }:
        raise BenchmarkEvidenceError("reference_hardware_discrete_gpu_invalid")
    integrated = _object(hardware["integrated_gpu"], {"model"}, "reference_hardware_integrated_gpu")
    if integrated != {"model": "AMD Radeon 780M"}:
        raise BenchmarkEvidenceError("reference_hardware_integrated_gpu_invalid")
    machine = _object(
        hardware["machine"],
        {"manufacturer", "model", "reference_class_id"},
        "reference_hardware_machine",
    )
    if machine != {
        "manufacturer": "Dell",
        "model": "G15 5535",
        "reference_class_id": REFERENCE_CLASS_ID,
    }:
        raise BenchmarkEvidenceError("reference_hardware_machine_invalid")
    memory = _object(hardware["memory"], {"physical_bytes"}, "reference_hardware_memory")
    if _u64(memory["physical_bytes"], "reference_hardware_memory_physical", positive=True) != 16_438_382_592:
        raise BenchmarkEvidenceError("reference_hardware_memory_invalid")
    rust = _object(hardware["rust"], {"cargo", "rustc"}, "reference_hardware_rust")
    if rust != {"cargo": "1.96.0", "rustc": "1.96.0"}:
        raise BenchmarkEvidenceError("reference_hardware_rust_invalid")
    _string(hardware["measured_on"], "reference_hardware_measured_on", pattern=re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$"))
    storage = _object(
        hardware["storage"],
        {
            "disk_headroom_min_ppm",
            "free_bytes_at_measurement",
            "headroom_shortfall_bytes",
            "required_free_bytes",
            "system_disk_bytes",
        },
        "reference_hardware_storage",
    )
    total = _u64(storage["system_disk_bytes"], "reference_hardware_disk_total", positive=True)
    free = _u64(storage["free_bytes_at_measurement"], "reference_hardware_disk_free")
    ppm = _u64(storage["disk_headroom_min_ppm"], "reference_hardware_disk_headroom_ppm", positive=True)
    required = _headroom_bytes(total, ppm)
    shortfall = max(0, required - free)
    if total != 487_335_129_088 or ppm != 150_000:
        raise BenchmarkEvidenceError("reference_hardware_storage_identity_invalid")
    if storage["required_free_bytes"] != required or storage["headroom_shortfall_bytes"] != shortfall:
        raise BenchmarkEvidenceError("reference_hardware_storage_calculation_invalid")
    ready = free >= required
    expected_failures = [] if ready else ["system_disk_free_below_15_percent_headroom"]
    if hardware["benchmark_ready"] is not ready or hardware["benchmark_ready_failures"] != expected_failures:
        raise BenchmarkEvidenceError("reference_hardware_readiness_record_invalid")
    if require_ready and not ready:
        raise BenchmarkEvidenceError("reference_hardware_not_benchmark_ready")
    return dict(hardware)


def _validate_source_identity(value: object) -> dict[str, Any]:
    keys = {
        "benchmark_driver_sha3_512",
        "build_manifest_sha3_512",
        "cbam_schema_sha3_512",
        "git_commit",
        "git_dirty",
        "git_status_sha3_512",
        "lock_manifest_sha3_512",
        "module_manifest_sha3_512",
        "parameter_set_id",
        "program_artifact_sha3_512",
        "proof_grammar_sha3_512",
        "proof_suite_id",
        "prover_artifact_sha3_512",
        "public_input_schema_id",
        "schema_sha3_512",
        "source_manifest_sha3_512_after",
        "source_manifest_sha3_512_before",
        "verifier_artifact_sha3_512",
        "workload_generator_sha3_512",
    }
    source = _object(value, keys, "benchmark_source_identity")
    _string(source["git_commit"], "benchmark_source_git_commit", pattern=_GIT_COMMIT)
    _boolean(source["git_dirty"], False, "benchmark_source_git_dirty")
    for key in keys - {"git_commit", "git_dirty"}:
        _digest(source[key], f"benchmark_source_{key}")
    if source["schema_sha3_512"] != sha3_512_file(SCHEMA_PATH):
        raise BenchmarkEvidenceError("benchmark_source_schema_digest_mismatch")
    if source["source_manifest_sha3_512_before"] != source["source_manifest_sha3_512_after"]:
        raise BenchmarkEvidenceError("benchmark_source_changed_during_campaign")
    return source


def _validate_hardware(value: object) -> dict[str, Any]:
    keys = {
        "ac_powered",
        "capture_sha3_512",
        "cpu_model",
        "discrete_gpu_model",
        "discrete_gpu_vram_mib",
        "logical_processors",
        "machine_manufacturer",
        "machine_model",
        "physical_cores",
        "physical_memory_bytes",
        "power_profile",
        "reference_class_id",
        "reference_hardware_config_sha3_512",
        "system_disk_bytes",
        "system_disk_free_bytes_at_capture",
        "wsl_kernel",
        "wsl_release",
    }
    hardware = _object(value, keys, "benchmark_reference_hardware")
    expected = {
        "cpu_model": "AMD Ryzen 7 7840HS",
        "discrete_gpu_model": "NVIDIA GeForce RTX 4060 Laptop GPU",
        "discrete_gpu_vram_mib": 8188,
        "logical_processors": 16,
        "machine_manufacturer": "Dell",
        "machine_model": "G15 5535",
        "physical_cores": 8,
        "physical_memory_bytes": 16_438_382_592,
        "reference_class_id": REFERENCE_CLASS_ID,
        "system_disk_bytes": 487_335_129_088,
    }
    for key, expected_value in expected.items():
        if hardware[key] != expected_value:
            raise BenchmarkEvidenceError(f"benchmark_reference_hardware_{key}_mismatch")
    _boolean(hardware["ac_powered"], True, "benchmark_reference_hardware_ac_powered")
    _digest(hardware["capture_sha3_512"], "benchmark_reference_hardware_capture_sha3_512")
    if hardware["reference_hardware_config_sha3_512"] != sha3_512_file(REFERENCE_HARDWARE_PATH):
        raise BenchmarkEvidenceError("benchmark_reference_hardware_config_digest_mismatch")
    _string(hardware["power_profile"], "benchmark_reference_hardware_power_profile")
    _string(hardware["wsl_kernel"], "benchmark_reference_hardware_wsl_kernel")
    _string(hardware["wsl_release"], "benchmark_reference_hardware_wsl_release")
    free = _u64(
        hardware["system_disk_free_bytes_at_capture"],
        "benchmark_reference_hardware_disk_free",
    )
    if free > expected["system_disk_bytes"]:
        raise BenchmarkEvidenceError("benchmark_reference_hardware_disk_free_exceeds_total")
    if free < _headroom_bytes(expected["system_disk_bytes"], GATES["disk_headroom_min_ppm"]):
        raise BenchmarkEvidenceError("benchmark_reference_hardware_disk_headroom_failed")
    return hardware


def _validate_proof(value: object, label: str) -> dict[str, Any]:
    proof = _object(value, {"bytes", "sections", "sha3_512"}, f"{label}_proof")
    proof_bytes = _u64(proof["bytes"], f"{label}_proof_bytes", positive=True)
    _digest(proof["sha3_512"], f"{label}_proof_sha3_512")
    sections = proof["sections"]
    if not isinstance(sections, list) or not sections:
        raise BenchmarkEvidenceError(f"{label}_proof_sections_invalid")
    expected_offset = 0
    module_ids: set[str] = set()
    for index, raw_section in enumerate(sections):
        section_label = f"{label}_proof_section_{index}"
        section = _object(
            raw_section,
            {"length_bytes", "module_id", "offset_bytes"},
            section_label,
        )
        offset = _u64(section["offset_bytes"], f"{section_label}_offset")
        length = _u64(section["length_bytes"], f"{section_label}_length", positive=True)
        module_id = _string(section["module_id"], f"{section_label}_module_id", pattern=_MODULE_ID)
        if offset != expected_offset:
            raise BenchmarkEvidenceError(f"{section_label}_not_contiguous")
        if module_id in module_ids:
            raise BenchmarkEvidenceError(f"{section_label}_duplicate_module_id")
        module_ids.add(module_id)
        expected_offset = _u64(offset + length, f"{section_label}_end")
    if expected_offset != proof_bytes:
        raise BenchmarkEvidenceError(f"{label}_proof_section_total_mismatch")
    return proof


def _validate_run(
    value: object,
    *,
    label: str,
    expected_ordinal: int,
    expected_counted: bool,
    source: Mapping[str, Any],
    hardware: Mapping[str, Any],
) -> dict[str, Any]:
    run = _object(
        value,
        {
            "batch_sha3_512",
            "cbam_sha3_512",
            "cleanup",
            "counted",
            "failure",
            "ordinal",
            "outcome",
            "proof",
            "public_inputs_sha3_512",
            "raw_evidence",
            "resources",
            "timings_ns",
            "verification",
        },
        label,
    )
    if _u64(run["ordinal"], f"{label}_ordinal") != expected_ordinal:
        raise BenchmarkEvidenceError(f"{label}_ordinal_invalid")
    _boolean(run["counted"], expected_counted, f"{label}_counted")
    for key in ("batch_sha3_512", "cbam_sha3_512", "public_inputs_sha3_512"):
        _digest(run[key], f"{label}_{key}")
    if run["outcome"] != "INDEPENDENTLY_VERIFIED" or run["failure"] is not None:
        raise BenchmarkEvidenceError(f"{label}_failed_run_disqualifies_campaign")
    _validate_proof(run["proof"], label)
    verification = _object(
        run["verification"],
        {"accepted", "independent", "semantic_output_match", "success_marker"},
        f"{label}_verification",
    )
    for key in ("accepted", "independent", "semantic_output_match", "success_marker"):
        _boolean(verification[key], True, f"{label}_verification_{key}")
    timings = _object(
        run["timings_ns"],
        {
            "cleanup_wall_ns",
            "cpu_system_ns",
            "cpu_user_ns",
            "input_to_verified_wall_ns",
            "verifier_cpu_system_ns",
            "verifier_cpu_user_ns",
            "verifier_wall_ns",
        },
        f"{label}_timings",
    )
    for key in timings:
        _u64(timings[key], f"{label}_timings_{key}", positive=key in {"input_to_verified_wall_ns", "verifier_wall_ns"})
    if timings["verifier_wall_ns"] > timings["input_to_verified_wall_ns"]:
        raise BenchmarkEvidenceError(f"{label}_verifier_wall_exceeds_total")
    if timings["verifier_cpu_user_ns"] > timings["cpu_user_ns"]:
        raise BenchmarkEvidenceError(f"{label}_verifier_user_cpu_exceeds_total")
    if timings["verifier_cpu_system_ns"] > timings["cpu_system_ns"]:
        raise BenchmarkEvidenceError(f"{label}_verifier_system_cpu_exceeds_total")
    resources = _object(
        run["resources"],
        {
            "io_read_bytes",
            "io_read_operations",
            "io_write_bytes",
            "io_write_operations",
            "minimum_available_ram_bytes",
            "minimum_disk_free_bytes",
            "peak_rss_bytes",
            "peak_swap_bytes",
            "scratch_high_water_bytes",
            "swap_in_bytes",
            "swap_out_bytes",
        },
        f"{label}_resources",
    )
    for key in resources:
        _u64(resources[key], f"{label}_resources_{key}")
    if resources["peak_rss_bytes"] > GATES["peak_rss_max_bytes"]:
        raise BenchmarkEvidenceError(f"{label}_peak_rss_gate_failed")
    if resources["scratch_high_water_bytes"] >= GATES["scratch_max_bytes"]:
        raise BenchmarkEvidenceError(f"{label}_scratch_gate_failed")
    for key in ("peak_swap_bytes", "swap_in_bytes", "swap_out_bytes"):
        if resources[key] != GATES["swap_max_bytes"]:
            raise BenchmarkEvidenceError(f"{label}_{key}_gate_failed")
    ram_required = _headroom_bytes(hardware["physical_memory_bytes"], GATES["ram_headroom_min_ppm"])
    disk_required = _headroom_bytes(hardware["system_disk_bytes"], GATES["disk_headroom_min_ppm"])
    if resources["minimum_available_ram_bytes"] < ram_required:
        raise BenchmarkEvidenceError(f"{label}_ram_headroom_gate_failed")
    if resources["minimum_available_ram_bytes"] > hardware["physical_memory_bytes"]:
        raise BenchmarkEvidenceError(f"{label}_available_ram_exceeds_physical")
    if resources["minimum_disk_free_bytes"] < disk_required:
        raise BenchmarkEvidenceError(f"{label}_disk_headroom_gate_failed")
    if resources["minimum_disk_free_bytes"] > hardware["system_disk_free_bytes_at_capture"]:
        raise BenchmarkEvidenceError(f"{label}_minimum_disk_free_exceeds_capture")
    cleanup = _object(
        run["cleanup"],
        {"complete", "process_residual_count", "scratch_residual_bytes", "sensitive_artifact_residual_count"},
        f"{label}_cleanup",
    )
    _boolean(cleanup["complete"], True, f"{label}_cleanup_complete")
    for key in ("process_residual_count", "scratch_residual_bytes", "sensitive_artifact_residual_count"):
        if _u64(cleanup[key], f"{label}_cleanup_{key}") != 0:
            raise BenchmarkEvidenceError(f"{label}_cleanup_{key}_nonzero")
    raw = _object(
        run["raw_evidence"],
        {"manifest_sha3_512"},
        f"{label}_raw_evidence",
    )
    for key in raw:
        _digest(raw[key], f"{label}_raw_evidence_{key}")
    return run


def _median_floor(values: Sequence[int]) -> int:
    if len(values) != 10:
        raise BenchmarkEvidenceError("benchmark_evidence_median_requires_ten_values")
    ordered = sorted(values)
    return (ordered[4] + ordered[5]) // 2


def _summary_for_runs(runs: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    if len(runs) != 10:
        raise BenchmarkEvidenceError("benchmark_evidence_summary_requires_ten_runs")
    walls = [run["timings_ns"]["input_to_verified_wall_ns"] for run in runs]
    verifiers = [run["timings_ns"]["verifier_wall_ns"] for run in runs]
    wall_ordered = sorted(walls)
    verifier_ordered = sorted(verifiers)
    p50 = _median_floor(walls)
    p95 = wall_ordered[9]
    deviations = sorted(abs(value - p50) for value in walls)
    mad = (deviations[4] + deviations[5]) // 2
    proof_bytes = [run["proof"]["bytes"] for run in runs]
    return {
        "cpu_system_sum_ns": sum(run["timings_ns"]["cpu_system_ns"] for run in runs),
        "cpu_user_sum_ns": sum(run["timings_ns"]["cpu_user_ns"] for run in runs),
        "io_read_bytes_sum": sum(run["resources"]["io_read_bytes"] for run in runs),
        "io_write_bytes_sum": sum(run["resources"]["io_write_bytes"] for run in runs),
        "mad_ns": mad,
        "mad_over_p50_ppm": _ceil_ratio(mad, p50),
        "measured_count": 10,
        "p95_over_p50_ppm": _ceil_ratio(p95, p50),
        "peak_rss_max_bytes": max(run["resources"]["peak_rss_bytes"] for run in runs),
        "proof_bytes_max": max(proof_bytes),
        "proof_bytes_min": min(proof_bytes),
        "scratch_max_bytes": max(run["resources"]["scratch_high_water_bytes"] for run in runs),
        "swap_in_bytes_sum": sum(run["resources"]["swap_in_bytes"] for run in runs),
        "swap_out_bytes_sum": sum(run["resources"]["swap_out_bytes"] for run in runs),
        "verifier_p50_ns": (verifier_ordered[4] + verifier_ordered[5]) // 2,
        "verifier_p95_ns": verifier_ordered[9],
        "verifier_sum_ns": sum(verifiers),
        "wall_max_ns": wall_ordered[9],
        "wall_min_ns": wall_ordered[0],
        "wall_p50_ns": p50,
        "wall_p95_ns": p95,
        "wall_sum_ns": sum(walls),
    }


def _validate_summary(value: object, expected: Mapping[str, int], label: str) -> None:
    summary = _object(value, set(expected), f"{label}_summary")
    for key, expected_value in expected.items():
        if _u64(summary[key], f"{label}_summary_{key}") != expected_value:
            raise BenchmarkEvidenceError(f"{label}_summary_{key}_mismatch")


def _validate_gate_result(value: object, summary: Mapping[str, int], latency_limit: int, label: str) -> None:
    gate = _object(
        value,
        {"cleanup_pass", "failure_reasons", "latency_pass", "passed", "resource_pass", "variance_pass", "verification_pass"},
        f"{label}_gate_result",
    )
    latency_pass = summary["wall_p95_ns"] < latency_limit
    variance_pass = (
        summary["p95_over_p50_ppm"] <= GATES["p95_over_p50_max_ppm"]
        and summary["mad_over_p50_ppm"] <= GATES["mad_over_p50_max_ppm"]
    )
    reasons: list[str] = []
    if not latency_pass:
        reasons.append("latency_p95_not_below_limit")
    if summary["p95_over_p50_ppm"] > GATES["p95_over_p50_max_ppm"]:
        reasons.append("p95_over_p50_variance_exceeded")
    if summary["mad_over_p50_ppm"] > GATES["mad_over_p50_max_ppm"]:
        reasons.append("mad_over_p50_variance_exceeded")
    expected = {
        "cleanup_pass": True,
        "failure_reasons": reasons,
        "latency_pass": latency_pass,
        "passed": latency_pass and variance_pass,
        "resource_pass": True,
        "variance_pass": variance_pass,
        "verification_pass": True,
    }
    if gate != expected:
        raise BenchmarkEvidenceError(f"{label}_gate_result_mismatch")
    if not expected["passed"]:
        raise BenchmarkEvidenceError(f"{label}_qualification_gate_failed:{reasons}")


def _validate_profile(
    value: object,
    *,
    spec: tuple[str, int, int, int, int],
    source: Mapping[str, Any],
    hardware: Mapping[str, Any],
) -> tuple[dict[str, Any], list[str], int]:
    profile_id, capacity, live, cover, latency_limit = spec
    label = f"benchmark_{profile_id.lower()}"
    profile = _object(value, {"gate_result", "repetitions", "summary", "warmup", "workload"}, label)
    workload = _object(
        profile["workload"],
        {"capacity_claims", "cover_claims", "fixed_shape", "live_claims", "profile_id", "workload_manifest_sha3_512"},
        f"{label}_workload",
    )
    if workload["profile_id"] != profile_id:
        raise BenchmarkEvidenceError(f"{label}_profile_id_invalid")
    for key, expected in (
        ("capacity_claims", capacity),
        ("live_claims", live),
        ("cover_claims", cover),
    ):
        if _u64(workload[key], f"{label}_{key}") != expected:
            raise BenchmarkEvidenceError(f"{label}_{key}_invalid")
    _boolean(workload["fixed_shape"], True, f"{label}_fixed_shape")
    if live + cover != capacity:
        raise BenchmarkEvidenceError(f"{label}_workload_shape_inconsistent")
    _digest(workload["workload_manifest_sha3_512"], f"{label}_workload_manifest")
    warmup = _validate_run(
        profile["warmup"],
        label=f"{label}_warmup",
        expected_ordinal=0,
        expected_counted=False,
        source=source,
        hardware=hardware,
    )
    repetitions = _sequence(profile["repetitions"], 10, f"{label}_repetitions")
    runs = [
        _validate_run(
            run,
            label=f"{label}_run_{index}",
            expected_ordinal=index,
            expected_counted=True,
            source=source,
            hardware=hardware,
        )
        for index, run in enumerate(repetitions, start=1)
    ]
    summary = _summary_for_runs(runs)
    _validate_summary(profile["summary"], summary, label)
    _validate_gate_result(profile["gate_result"], summary, latency_limit, label)
    batch_digests = [warmup["batch_sha3_512"], *(run["batch_sha3_512"] for run in runs)]
    return profile, batch_digests, summary["wall_p95_ns"]


def validate_synthetic_benchmark_fixture(
    value: Mapping[str, Any],
) -> BenchmarkFixtureValidation:
    """Validate fixture consistency only; never promote it to a benchmark result."""
    record = _object(value, {"payload", "payload_sha3_512", "schema_version"}, "benchmark_record")
    if record["schema_version"] != SCHEMA_VERSION:
        raise BenchmarkEvidenceError("benchmark_schema_version_invalid")
    payload = _object(
        record["payload"],
        {
            "campaign_id",
            "campaign_result",
            "created_at_utc",
            "failure_policy",
            "gates",
            "profiles",
            "protocol",
            "reference_hardware",
            "scope",
            "source_identity",
        },
        "benchmark_payload",
    )
    expected_payload_digest = sha3_512_bytes(canonical_json_bytes(payload))
    if _digest(record["payload_sha3_512"], "benchmark_payload_sha3_512") != expected_payload_digest:
        raise BenchmarkEvidenceError("benchmark_payload_digest_mismatch")
    campaign_id = _string(payload["campaign_id"], "benchmark_campaign_id", pattern=_CAMPAIGN_ID)
    _string(payload["created_at_utc"], "benchmark_created_at_utc", pattern=_TIMESTAMP)
    _exact_mapping(
        payload["scope"],
        {"activation_allowed": False, "no_phi": True, "production_usable": False, "synthetic_only": True},
        "benchmark_scope",
    )
    _exact_mapping(payload["protocol"], PROTOCOL, "benchmark_protocol")
    _exact_mapping(payload["gates"], GATES, "benchmark_gates")
    _exact_mapping(payload["failure_policy"], FAILURE_POLICY, "benchmark_failure_policy")
    source = _validate_source_identity(payload["source_identity"])
    hardware = _validate_hardware(payload["reference_hardware"])
    profiles = _sequence(payload["profiles"], 2, "benchmark_profiles")
    batch_digests: list[str] = []
    p95_values: list[int] = []
    for profile, spec in zip(profiles, PROFILE_SPECS, strict=True):
        _, profile_batches, p95 = _validate_profile(profile, spec=spec, source=source, hardware=hardware)
        batch_digests.extend(profile_batches)
        p95_values.append(p95)
    if len(batch_digests) != 22 or len(set(batch_digests)) != 22:
        raise BenchmarkEvidenceError("benchmark_batch_digests_not_globally_unique")
    campaign_result = _object(
        payload["campaign_result"],
        {"all_batches_unique", "all_profiles_pass", "failure_count", "qualifies", "reference_hardware_ready", "source_unchanged"},
        "benchmark_campaign_result",
    )
    expected_result = {
        "all_batches_unique": True,
        "all_profiles_pass": True,
        "failure_count": 0,
        "qualifies": True,
        "reference_hardware_ready": True,
        "source_unchanged": True,
    }
    if campaign_result != expected_result:
        raise BenchmarkEvidenceError("benchmark_campaign_result_mismatch")
    return BenchmarkFixtureValidation(
        campaign_id=campaign_id,
        k128_p95_ns=p95_values[0],
        k512_p95_ns=p95_values[1],
        measured_run_count=20,
        warmup_run_count=2,
    )


def validate_synthetic_benchmark_fixture_file(path: Path) -> BenchmarkFixtureValidation:
    return validate_synthetic_benchmark_fixture(read_canonical_json(path))


def validate_benchmark_evidence(value: Mapping[str, Any]) -> None:
    """Reject self-attested records after checking their internal consistency.

    The caller receives the specific structural failure first. A structurally
    sound record still cannot qualify because this repository does not yet
    provide an immutable run-owned provenance bundle tied to worker artifacts
    and external OS counters.
    """

    validate_synthetic_benchmark_fixture(value)
    raise BenchmarkEvidenceError("benchmark_evidence_external_provenance_required")


def validate_benchmark_evidence_file(path: Path) -> None:
    validate_benchmark_evidence(read_canonical_json(path))


__all__: Sequence[str] = (
    "BenchmarkEvidenceError",
    "BenchmarkFixtureValidation",
    "GATES",
    "PROFILE_SPECS",
    "PROTOCOL",
    "REFERENCE_HARDWARE_PATH",
    "SCHEMA_PATH",
    "SCHEMA_VERSION",
    "canonical_json_bytes",
    "read_canonical_json",
    "sha3_512_bytes",
    "sha3_512_file",
    "validate_benchmark_evidence",
    "validate_benchmark_evidence_file",
    "validate_reference_hardware_config",
    "validate_synthetic_benchmark_fixture",
    "validate_synthetic_benchmark_fixture_file",
)
