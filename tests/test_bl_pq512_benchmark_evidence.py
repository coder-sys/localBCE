from __future__ import annotations

import json
from pathlib import Path

import pytest

from experiments.bl_pq512_crypto_foundation import benchmark_evidence as evidence


ROOT = Path(__file__).resolve().parents[1]
VECTOR = ROOT / "test_data" / "bl_pq512_benchmark_evidence_v1.json"


def test_schema_freezes_exact_profiles_protocol_and_resource_gates() -> None:
    schema = json.loads(evidence.SCHEMA_PATH.read_text(encoding="utf-8"))
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["additionalProperties"] is False
    payload = schema["properties"]["payload"]
    assert payload["additionalProperties"] is False
    gates = payload["properties"]["gates"]["properties"]
    assert gates["peak_rss_max_bytes"] == {"const": 5_000_000_000}
    assert gates["scratch_max_bytes"] == {"const": 5_000_000_000}
    assert gates["swap_max_bytes"] == {"const": 0}
    resources = schema["$defs"]["resources"]["properties"]
    assert resources["peak_rss_bytes"]["allOf"][1] == {"maximum": 5_000_000_000}
    assert resources["scratch_high_water_bytes"]["allOf"][1] == {
        "exclusiveMaximum": 5_000_000_000
    }
    protocol = payload["properties"]["protocol"]["properties"]
    assert protocol["warmup_count"] == {"const": 1}
    assert protocol["measured_repetitions"] == {"const": 10}
    assert protocol["p95_method"] == {"const": "NEAREST_RANK_CEIL"}
    profiles = payload["properties"]["profiles"]
    assert profiles["minItems"] == profiles["maxItems"] == 2


def test_canonical_synthetic_campaign_is_consistent_but_not_qualified() -> None:
    fixture = evidence.validate_synthetic_benchmark_fixture_file(VECTOR)
    assert fixture.campaign_id == "synthetic-benchmark-vector-v1"
    assert fixture.measured_run_count == 20
    assert fixture.warmup_run_count == 2
    assert fixture.k128_p95_ns == 50_500_000_000
    assert fixture.k512_p95_ns == 151_000_000_000
    with pytest.raises(
        evidence.BenchmarkEvidenceError,
        match="benchmark_evidence_external_provenance_required",
    ):
        evidence.validate_benchmark_evidence_file(VECTOR)

    record = evidence.read_canonical_json(VECTOR)
    for profile in record["payload"]["profiles"]:
        measured = profile["repetitions"]
        assert len(measured) == 10
        assert profile["summary"]["wall_p95_ns"] == max(
            run["timings_ns"]["input_to_verified_wall_ns"] for run in measured
        )
        assert profile["warmup"]["counted"] is False
        assert [run["ordinal"] for run in measured] == list(range(1, 11))


def test_reference_hardware_capture_meets_the_reduced_operational_disk_floor() -> None:
    hardware = evidence.validate_reference_hardware_config(require_ready=False)
    storage = hardware["storage"]
    assert hardware["benchmark_ready"] is True
    assert storage["system_disk_bytes"] == 487_335_129_088
    assert storage["free_bytes_at_measurement"] == 59_091_513_344
    assert storage["required_free_bytes"] == 7_310_026_937
    assert storage["headroom_shortfall_bytes"] == 0
    assert evidence.validate_reference_hardware_config(require_ready=True)["benchmark_ready"] is True


def test_vector_is_strict_canonical_json_and_self_bound() -> None:
    record = evidence.read_canonical_json(VECTOR)
    assert VECTOR.read_bytes() == evidence.canonical_json_bytes(record) + b"\n"
    assert record["payload_sha3_512"] == evidence.sha3_512_bytes(
        evidence.canonical_json_bytes(record["payload"])
    )
    assert record["payload"]["source_identity"]["schema_sha3_512"] == evidence.sha3_512_file(
        evidence.SCHEMA_PATH
    )
    assert record["payload"]["reference_hardware"][
        "reference_hardware_config_sha3_512"
    ] == evidence.sha3_512_file(evidence.REFERENCE_HARDWARE_PATH)
