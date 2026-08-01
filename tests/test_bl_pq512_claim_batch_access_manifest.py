from __future__ import annotations

from dataclasses import fields
from hashlib import sha3_512
import inspect

from experiments.bl_pq512_crypto_foundation.claim_batch_access_manifest import (
    BENCHMARK_POLICY_ID_512,
    PRIVATE_BODY_SCHEMA_ID_512,
    RESOURCE_POLICY_ID_512,
    STATE_LAYOUT_ID_512,
    build_c0_claim_batch_access_manifest,
    build_c0_claim_job_binding,
    build_c0_private_access_body,
    decode_c0_claim_batch_access_manifest,
    decode_c0_claim_job_binding,
    decode_c0_private_access_body,
)
from experiments.fixed_shape_claim_air.profile import PROFILES


def _tokens(count: int, domain: bytes) -> tuple[bytes, ...]:
    return tuple(
        sha3_512(domain + ordinal.to_bytes(8, "big")).digest()
        for ordinal in range(count)
    )


def test_k128_census_and_lane_breakdown_are_exact() -> None:
    manifest = build_c0_claim_batch_access_manifest(
        PROFILES["K128_CALIBRATION"]
    )

    assert (
        manifest.global_sha3_calls,
        manifest.global_sha3_permutations,
        manifest.global_preimage_bytes,
    ) == (46_858, 113_730, 7_996_042)
    assert (
        manifest.state_sha3_calls,
        manifest.state_sha3_permutations,
        manifest.state_preimage_bytes,
        manifest.ordered_map_operations,
        manifest.access_rows,
        manifest.conflict_edge_count,
        manifest.dag_node_count,
    ) == (46_208, 96_900, 6_800_980, 641, 1_282, 764, 769)
    assert tuple(
        (
            lane.lane,
            lane.node_offset,
            lane.node_count,
            lane.ordered_map_operations,
            lane.access_rows,
            lane.sha3_calls,
            lane.sha3_permutations,
            lane.preimage_bytes,
            lane.conflict_edges,
        )
        for lane in manifest.state_lanes
    ) == (
        ("replay", 0, 129, 129, 258, 9_360, 19_236, 1_356_282, 128),
        ("benefit", 129, 128, 128, 256, 9_296, 19_104, 1_346_974, 127),
        ("obligation", 257, 128, 128, 256, 9_296, 19_104, 1_346_974, 127),
        ("ledger", 385, 256, 256, 512, 17_488, 36_000, 2_538_398, 255),
        ("payment_application", 641, 128, 0, 0, 768, 3_456, 212_352, 127),
    )


def test_k128_has_six_contiguous_authoritative_hash_ranges() -> None:
    manifest = build_c0_claim_batch_access_manifest(
        PROFILES["K128_CALIBRATION"]
    )
    assert tuple(
        (item.component, item.tag, item.call_offset, item.call_count)
        for item in manifest.hash_ranges
    ) == (
        ("claim_truth", 1, 0, 516),
        ("a12_nullifier", 2, 516, 129),
        ("salt_use", 3, 645, 1),
        ("replay_map", 4, 646, 9_360),
        ("payment", 5, 10_006, 36_848),
        ("master", 6, 46_854, 4),
    )
    assert (
        manifest.hash_ranges[-1].call_offset
        + manifest.hash_ranges[-1].call_count
        == 46_858
    )


def test_public_envelope_is_deterministic_profile_only_and_nonactivating() -> None:
    builder_signature = inspect.signature(build_c0_claim_batch_access_manifest)
    assert tuple(builder_signature.parameters) == ("profile",)
    manifest = build_c0_claim_batch_access_manifest(
        PROFILES["K128_CALIBRATION"]
    )
    repeated = build_c0_claim_batch_access_manifest(
        PROFILES["K128_CALIBRATION"]
    )
    assert manifest.encoded == repeated.encoded
    assert manifest.commitment_512 == repeated.commitment_512
    assert manifest.proof_suite_id is None
    assert manifest.proofSuiteId is None
    assert manifest.activation_allowed is False
    assert manifest.benchmark_policy_id_512 == BENCHMARK_POLICY_ID_512
    assert manifest.resource_policy_id_512 == RESOURCE_POLICY_ID_512
    assert manifest.state_layout_id_512 == STATE_LAYOUT_ID_512
    assert manifest.private_body_schema_id_512 == PRIVATE_BODY_SCHEMA_ID_512
    assert manifest.commitment_512.hex() == (
        "ee265db7fae0a0a796ff3fdff14174bbb103df13a41b2214d80e2a6061a383a4"
        "c7e6f18ce75399a53b7489edfa6dcec2322269d7dd74ab4b55d63ae859e66775"
    )

    public_fields = {item.name for item in fields(type(manifest))}
    assert not public_fields.intersection(
        {
            "claim_slots_live",
            "decision_count",
            "live_rows",
            "page_positions",
            "page_tokens",
            "keys",
            "values",
            "cpu_limit",
            "gpu_limit",
            "io_limit",
        }
    )


def test_private_body_is_profile_fixed_and_does_not_change_public_envelope() -> None:
    profile = PROFILES["K128_CALIBRATION"]
    manifest_before = build_c0_claim_batch_access_manifest(profile)
    first = build_c0_private_access_body(
        profile, _tokens(manifest_before.access_rows, b"first\x00")
    )
    second = build_c0_private_access_body(
        profile, _tokens(manifest_before.access_rows, b"second\x00")
    )
    manifest_after = build_c0_claim_batch_access_manifest(profile)

    assert len(first.rows) == len(second.rows) == 1_282
    assert len(first.encoded) == len(second.encoded) == 89_760
    assert first.encoded != second.encoded
    assert manifest_before.encoded == manifest_after.encoded
    seed_a = sha3_512(b"private-mask-a").digest()
    seed_b = sha3_512(b"private-mask-b").digest()
    assert first.masked_reference_commitment_512(
        seed_a
    ) != first.masked_reference_commitment_512(seed_b)
    assert first.masked_reference_commitment_512(
        seed_a
    ) != second.masked_reference_commitment_512(seed_a)


def test_per_job_binding_authenticates_identity_and_private_body() -> None:
    profile = PROFILES["K128_CALIBRATION"]
    manifest = build_c0_claim_batch_access_manifest(profile)
    body = build_c0_private_access_body(
        profile, _tokens(manifest.access_rows, b"job-body\x00")
    )
    seed = sha3_512(b"job-mask\x00").digest()
    ids = tuple(
        sha3_512(b"job-id\x00" + index.to_bytes(1, "big")).digest()
        for index in range(6)
    )
    binding = build_c0_claim_job_binding(
        manifest,
        body,
        seed,
        batch_id_512=ids[0],
        sidecar_root_512=ids[1],
        state_root_512=ids[2],
        claim_attempt_id_512=ids[3],
        retry_id_512=ids[4],
        job_sequence_id_512=ids[5],
    )
    binding.verify_private_body(body, seed)
    assert binding.proof_suite_id is None
    assert binding.activation_allowed is False
    assert body.encoded not in binding.encoded
    changed_retry = build_c0_claim_job_binding(
        manifest,
        body,
        seed,
        batch_id_512=ids[0],
        sidecar_root_512=ids[1],
        state_root_512=ids[2],
        claim_attempt_id_512=ids[3],
        retry_id_512=sha3_512(b"retry-two\x00").digest(),
        job_sequence_id_512=ids[5],
    )
    assert binding.commitment_512 != changed_retry.commitment_512
    assert decode_c0_claim_batch_access_manifest(manifest.encoded) == manifest
    assert decode_c0_private_access_body(body.encoded) == body
    assert decode_c0_claim_job_binding(binding.encoded) == binding


def test_all_governed_profiles_reconcile_and_fit_encoding_bounds() -> None:
    for profile in PROFILES.values():
        manifest = build_c0_claim_batch_access_manifest(profile)
        assert len(manifest.hash_ranges) == 6
        assert (
            sum(item.call_count for item in manifest.hash_ranges)
            == manifest.global_sha3_calls
        )
        assert (
            sum(item.sha3_calls for item in manifest.state_lanes)
            == manifest.state_sha3_calls
        )
        assert (
            sum(item.conflict_edges for item in manifest.state_lanes)
            == manifest.conflict_edge_count
        )
        assert len(manifest.conflict_edges) == manifest.conflict_edge_count
        assert len(manifest.encoded) < 1 << 20
