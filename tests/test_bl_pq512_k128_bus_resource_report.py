from __future__ import annotations

import json
from pathlib import Path

from experiments.bl_pq512_crypto_foundation.k128_bus_resource_report import (
    ARCHITECTURE_ID,
    EVIDENCE_CLASS,
    SCHEMA_VERSION,
    build_k128_bus_resource_report,
)


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schemas" / "bl_pq512_k128_bus_resource_report_v1.schema.json"


def test_k128_direct_sha3_bus_costs_are_exact_and_nonqualifying() -> None:
    report = build_k128_bus_resource_report()
    assert report.schema_version == SCHEMA_VERSION
    assert report.evidence_class == EVIDENCE_CLASS == "DERIVED_MODEL"
    assert report.architecture_id == ARCHITECTURE_ID == "RETIRED_DIRECT_SHA3_STARK_V1"
    assert tuple(
        (segment.component, segment.tag, segment.call_offset, segment.call_count)
        for segment in report.segments
    ) == (
        ("claim_truth", 1, 0, 516),
        ("a12_nullifier", 2, 516, 129),
        ("salt_use", 3, 645, 1),
        ("replay_map", 4, 646, 9_360),
        ("payment", 5, 10_006, 36_848),
        ("master", 6, 46_854, 4),
    )
    assert (
        report.sha3_calls,
        report.sha3_permutations,
        report.sha3_preimage_bytes,
        report.sha3_digest_bytes,
        report.sha3_message_plus_digest_bytes,
        report.keccak_round_boundary_bytes,
        report.chi_and_gate_count,
    ) == (
        46_858,
        113_730,
        7_996_042,
        2_998_912,
        10_994_954,
        568_650_000,
        4_367_232_000,
    )
    assert (
        report.state_sha3_calls,
        report.state_sha3_permutations,
        report.state_preimage_bytes,
        report.ordered_map_operations,
        report.access_rows,
        report.conflict_edges,
    ) == (46_208, 96_900, 6_800_980, 641, 1_282, 764)
    assert report.generated_maximum_padded_width is None
    assert report.peak_rss_measured is False
    assert report.scratch_measured is False
    assert report.qualifies is False
    assert report.activation_allowed is False


def test_k128_bus_report_json_shape_never_hides_unknown_costs() -> None:
    report = build_k128_bus_resource_report().as_dict()
    assert report["segments"][0]["call_offset"] == 0
    assert report["segments"][-1]["call_offset"] + report["segments"][-1]["call_count"] == report["sha3_calls"]
    assert report["unmeasured_or_unbounded"] == [
        "generated_backend_width",
        "generated_backend_commitment_layout",
        "generated_backend_peak_rss",
        "generated_backend_scratch",
        "allocator_overhead",
        "cross_term_cost",
        "promoted_tail_cost",
        "measured_latency",
        "measured_io",
    ]


def test_k128_bus_report_schema_freezes_retired_model_and_nonqualification() -> None:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["additionalProperties"] is False
    properties = schema["properties"]
    assert properties["evidence_class"] == {"const": "DERIVED_MODEL"}
    assert properties["architecture_id"] == {"const": "RETIRED_DIRECT_SHA3_STARK_V1"}
    assert properties["sha3_preimage_bytes"] == {"const": 7_996_042}
    assert properties["sha3_message_plus_digest_bytes"] == {"const": 10_994_954}
    assert properties["peak_rss_measured"] == {"const": False}
    assert properties["qualifies"] == {"const": False}
    assert properties["activation_allowed"] == {"const": False}
