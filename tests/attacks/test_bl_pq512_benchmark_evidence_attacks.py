from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from typing import Callable

import pytest

from experiments.bl_pq512_crypto_foundation import benchmark_evidence as evidence


ROOT = Path(__file__).resolve().parents[2]
VECTOR = ROOT / "test_data" / "bl_pq512_benchmark_evidence_v1.json"


def _record() -> dict[str, object]:
    return deepcopy(evidence.read_canonical_json(VECTOR))


def _reseal(record: dict[str, object]) -> None:
    record["payload_sha3_512"] = evidence.sha3_512_bytes(
        evidence.canonical_json_bytes(record["payload"])
    )


def _rejects(
    mutation: Callable[[dict[str, object]], None],
    match: str,
    *,
    reseal: bool = True,
) -> None:
    record = _record()
    mutation(record)
    if reseal:
        _reseal(record)
    with pytest.raises(evidence.BenchmarkEvidenceError, match=match):
        evidence.validate_benchmark_evidence(record)


def _profile(record: dict[str, object], index: int = 0) -> dict[str, object]:
    return record["payload"]["profiles"][index]  # type: ignore[index]


def _run(record: dict[str, object], profile: int = 0, run: int = 0) -> dict[str, object]:
    return _profile(record, profile)["repetitions"][run]  # type: ignore[index]


def _refresh_summary(record: dict[str, object], profile_index: int) -> dict[str, int]:
    profile = _profile(record, profile_index)
    summary = evidence._summary_for_runs(profile["repetitions"])  # type: ignore[arg-type]
    profile["summary"] = summary
    return summary


def test_payload_self_hash_detects_any_unsealed_change() -> None:
    _rejects(
        lambda record: record["payload"]["campaign_result"].__setitem__("qualifies", False),  # type: ignore[index,union-attr]
        "benchmark_payload_digest_mismatch",
        reseal=False,
    )


def test_unknown_field_is_rejected_after_an_attacker_reseals() -> None:
    _rejects(
        lambda record: record["payload"].__setitem__("unreviewed", True),  # type: ignore[union-attr]
        "benchmark_payload_keys_invalid",
    )


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("git_dirty", True, "benchmark_source_git_dirty_boolean_invalid"),
        ("schema_sha3_512", "1" * 128, "benchmark_source_schema_digest_mismatch"),
        ("source_manifest_sha3_512_after", "2" * 128, "benchmark_source_changed_during_campaign"),
    ],
)
def test_source_identity_cannot_be_weakened(field: str, value: object, match: str) -> None:
    def mutate(record: dict[str, object]) -> None:
        record["payload"]["source_identity"][field] = value  # type: ignore[index]

    _rejects(mutate, match)


def test_reference_hardware_binding_cannot_be_substituted() -> None:
    def mutate(record: dict[str, object]) -> None:
        record["payload"]["reference_hardware"]["reference_hardware_config_sha3_512"] = "3" * 128  # type: ignore[index]

    _rejects(mutate, "benchmark_reference_hardware_config_digest_mismatch")


def test_nonqualifying_disk_capture_is_rejected() -> None:
    def mutate(record: dict[str, object]) -> None:
        record["payload"]["reference_hardware"]["system_disk_free_bytes_at_capture"] = 7_310_026_936  # type: ignore[index]

    _rejects(mutate, "benchmark_reference_hardware_disk_headroom_failed")


@pytest.mark.parametrize("count", [9, 11])
def test_exactly_ten_measured_repetitions_are_required(count: int) -> None:
    def mutate(record: dict[str, object]) -> None:
        repetitions = _profile(record)["repetitions"]  # type: ignore[index]
        if count == 9:
            repetitions.pop()  # type: ignore[union-attr]
        else:
            repetitions.append(deepcopy(repetitions[-1]))  # type: ignore[index,union-attr]

    _rejects(mutate, "benchmark_k128_calibration_repetitions_length_invalid")


def test_warmup_cannot_be_counted() -> None:
    _rejects(
        lambda record: _profile(record)["warmup"].__setitem__("counted", True),  # type: ignore[index,union-attr]
        "benchmark_k128_calibration_warmup_counted_boolean_invalid",
    )


def test_measured_ordinals_cannot_be_reordered() -> None:
    _rejects(
        lambda record: _run(record).__setitem__("ordinal", 2),
        "benchmark_k128_calibration_run_1_ordinal_invalid",
    )


def test_batches_must_be_unique_across_both_profiles_and_warmups() -> None:
    def mutate(record: dict[str, object]) -> None:
        duplicate = _profile(record)["warmup"]["batch_sha3_512"]  # type: ignore[index]
        _run(record, profile=1, run=9)["batch_sha3_512"] = duplicate

    _rejects(mutate, "benchmark_batch_digests_not_globally_unique")


@pytest.mark.parametrize(("profile_index", "exact_limit"), [(0, 60_000_000_000), (1, 180_000_000_000)])
def test_latency_limit_is_exclusive(profile_index: int, exact_limit: int) -> None:
    def mutate(record: dict[str, object]) -> None:
        profile = _profile(record, profile_index)
        profile["repetitions"][-1]["timings_ns"]["input_to_verified_wall_ns"] = exact_limit  # type: ignore[index]
        summary = _refresh_summary(record, profile_index)
        assert summary["wall_p95_ns"] == exact_limit
        profile["gate_result"] = {
            "cleanup_pass": True,
            "failure_reasons": ["latency_p95_not_below_limit"],
            "latency_pass": False,
            "passed": False,
            "resource_pass": True,
            "variance_pass": True,
            "verification_pass": True,
        }

    _rejects(mutate, "qualification_gate_failed")


def test_nearest_rank_p95_cannot_hide_a_slow_tenth_run_as_an_outlier() -> None:
    def mutate(record: dict[str, object]) -> None:
        profile = _profile(record)
        for run in profile["repetitions"][:9]:  # type: ignore[index]
            run["timings_ns"]["input_to_verified_wall_ns"] = 40_000_000_000
        profile["repetitions"][9]["timings_ns"]["input_to_verified_wall_ns"] = 50_000_000_000  # type: ignore[index]
        summary = _refresh_summary(record, 0)
        assert summary["wall_p95_ns"] == 50_000_000_000
        assert summary["p95_over_p50_ppm"] == 1_250_000
        profile["gate_result"] = {
            "cleanup_pass": True,
            "failure_reasons": ["p95_over_p50_variance_exceeded"],
            "latency_pass": True,
            "passed": False,
            "resource_pass": True,
            "variance_pass": False,
            "verification_pass": True,
        }

    _rejects(mutate, "qualification_gate_failed")


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("peak_rss_bytes", 5_000_000_001, "peak_rss_gate_failed"),
        ("scratch_high_water_bytes", 5_000_000_000, "scratch_gate_failed"),
        ("scratch_high_water_bytes", 5_000_000_001, "scratch_gate_failed"),
        ("peak_swap_bytes", 1, "peak_swap_bytes_gate_failed"),
        ("swap_in_bytes", 1, "swap_in_bytes_gate_failed"),
        ("swap_out_bytes", 1, "swap_out_bytes_gate_failed"),
        ("minimum_available_ram_bytes", 1_643_838_259, "ram_headroom_gate_failed"),
        ("minimum_disk_free_bytes", 7_310_026_936, "disk_headroom_gate_failed"),
    ],
)
def test_resource_gates_fail_closed(field: str, value: int, match: str) -> None:
    _rejects(lambda record: _run(record)["resources"].__setitem__(field, value), match)  # type: ignore[index,union-attr]


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("complete", False, "cleanup_complete_boolean_invalid"),
        ("process_residual_count", 1, "cleanup_process_residual_count_nonzero"),
        ("scratch_residual_bytes", 1, "cleanup_scratch_residual_bytes_nonzero"),
        ("sensitive_artifact_residual_count", 1, "cleanup_sensitive_artifact_residual_count_nonzero"),
    ],
)
def test_cleanup_must_be_complete_and_empty(field: str, value: object, match: str) -> None:
    _rejects(lambda record: _run(record)["cleanup"].__setitem__(field, value), match)  # type: ignore[index,union-attr]


def test_failed_repetition_is_preserved_but_never_qualifies() -> None:
    def mutate(record: dict[str, object]) -> None:
        run = _run(record)
        run["outcome"] = "FAILED"
        run["failure"] = {
            "class": "VERIFIER_REJECTION",
            "cleanup_complete": True,
            "error_code": "synthetic_rejection",
            "stage": "VERIFY",
            "state_unchanged": True,
            "success_receipt_emitted": False,
        }
        run["proof"] = None

    _rejects(mutate, "failed_run_disqualifies_campaign")


def test_independent_verifier_success_cannot_be_forged() -> None:
    _rejects(
        lambda record: _run(record)["verification"].__setitem__("independent", False),  # type: ignore[index,union-attr]
        "verification_independent_boolean_invalid",
    )


def test_proof_sections_must_be_contiguous() -> None:
    _rejects(
        lambda record: _run(record)["proof"]["sections"][1].__setitem__("offset_bytes", 1),  # type: ignore[index,union-attr]
        "proof_section_1_not_contiguous",
    )


def test_proof_sections_must_sum_to_total_bytes() -> None:
    _rejects(
        lambda record: _run(record)["proof"].__setitem__("bytes", 3_000_001),  # type: ignore[index,union-attr]
        "proof_section_total_mismatch",
    )


def test_float_cannot_substitute_for_exact_integer_telemetry() -> None:
    _rejects(
        lambda record: _run(record)["resources"].__setitem__("io_read_bytes", 1.0),  # type: ignore[index,union-attr]
        "resources_io_read_bytes_u64_invalid",
    )


def test_retry_and_cache_policy_cannot_be_relaxed() -> None:
    _rejects(
        lambda record: record["payload"]["protocol"].__setitem__("automatic_retry_allowed", True),  # type: ignore[index,union-attr]
        "benchmark_protocol_value_invalid",
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("automatic_retry_allowed", 0),
        ("fresh_process_per_run", 1),
    ],
)
def test_integer_zero_or_one_cannot_substitute_for_protocol_boolean(
    field: str, value: int
) -> None:
    _rejects(
        lambda record: record["payload"]["protocol"].__setitem__(field, value),  # type: ignore[index,union-attr]
        "benchmark_protocol_value_invalid",
    )


def test_boolean_true_cannot_substitute_for_integer_protocol_value() -> None:
    _rejects(
        lambda record: record["payload"]["protocol"].__setitem__("warmup_count", True),  # type: ignore[index,union-attr]
        "benchmark_protocol_value_invalid",
    )


def test_duplicate_json_key_is_rejected_before_validation(tmp_path: Path) -> None:
    path = tmp_path / "duplicate.json"
    path.write_bytes(b'{"payload":{},"payload":{},"payload_sha3_512":"' + b"1" * 128 + b'","schema_version":"x"}\n')
    with pytest.raises(evidence.BenchmarkEvidenceError, match="benchmark_evidence_duplicate_key:payload"):
        evidence.read_canonical_json(path)


def test_pretty_or_whitespace_reformatted_json_is_not_canonical(tmp_path: Path) -> None:
    path = tmp_path / "pretty.json"
    value = evidence.read_canonical_json(VECTOR)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    with pytest.raises(evidence.BenchmarkEvidenceError, match="benchmark_evidence_not_canonical"):
        evidence.read_canonical_json(path)
