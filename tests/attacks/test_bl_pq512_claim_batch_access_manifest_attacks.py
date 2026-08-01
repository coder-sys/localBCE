from __future__ import annotations

from dataclasses import replace
from hashlib import sha3_512

import pytest

from experiments.bl_pq512_crypto_foundation.claim_batch_access_manifest import (
    CbamConflictEdge,
    CbamClaimJobBinding,
    CbamPrivateAccessBody,
    CbamPrivateAccessRow,
    ClaimBatchAccessManifest,
    build_c0_claim_batch_access_manifest,
    build_c0_claim_job_binding,
    build_c0_private_access_body,
    decode_c0_claim_batch_access_manifest,
    decode_c0_claim_job_binding,
    decode_c0_private_access_body,
)
from experiments.fixed_shape_claim_air.profile import PROFILES


@pytest.fixture(scope="module")
def manifest() -> ClaimBatchAccessManifest:
    return build_c0_claim_batch_access_manifest(PROFILES["K128_CALIBRATION"])


def _tokens(count: int) -> tuple[bytes, ...]:
    return tuple(
        sha3_512(b"attack-test-token\x00" + index.to_bytes(8, "big")).digest()
        for index in range(count)
    )


@pytest.mark.parametrize(
    ("field_name", "bad_value"),
    (
        ("global_sha3_calls", 46_857),
        ("global_sha3_permutations", 113_729),
        ("global_preimage_bytes", 7_996_041),
        ("state_sha3_calls", 46_207),
        ("state_sha3_permutations", 96_899),
        ("state_preimage_bytes", 6_800_979),
        ("ordered_map_operations", 640),
        ("access_rows", 1_281),
        ("conflict_edge_count", 763),
        ("dag_node_count", 768),
    ),
)
def test_census_scalar_tampering_fails_closed(
    manifest: ClaimBatchAccessManifest, field_name: str, bad_value: int
) -> None:
    with pytest.raises(ValueError, match="mismatch"):
        replace(manifest, **{field_name: bad_value})


@pytest.mark.parametrize(
    "field_name",
    (
        "benchmark_policy_id_512",
        "resource_policy_id_512",
        "state_layout_id_512",
        "private_body_schema_id_512",
        "global_sha3_schedule_commitment_512",
        "global_sha3_capacity_commitment_512",
    ),
)
def test_fixed_policy_and_schedule_id_substitution_is_rejected(
    manifest: ClaimBatchAccessManifest, field_name: str
) -> None:
    with pytest.raises(ValueError, match="mismatch"):
        replace(manifest, **{field_name: b"\xff" * 64})


def test_activation_and_proof_suite_promotion_are_rejected(
    manifest: ClaimBatchAccessManifest,
) -> None:
    with pytest.raises(ValueError, match="activation_forbidden"):
        replace(manifest, activation_allowed=True)
    with pytest.raises(ValueError, match="proof_suite_must_remain_none"):
        replace(manifest, proof_suite_id=b"\x01" * 64)


def test_hash_range_reorder_or_omission_is_rejected(
    manifest: ClaimBatchAccessManifest,
) -> None:
    with pytest.raises(ValueError, match="hash_ranges_not_authoritative"):
        replace(manifest, hash_ranges=manifest.hash_ranges[::-1])
    with pytest.raises(ValueError, match="hash_ranges_not_authoritative"):
        replace(manifest, hash_ranges=manifest.hash_ranges[:-1])


def test_lane_and_transitive_reduction_tampering_is_rejected(
    manifest: ClaimBatchAccessManifest,
) -> None:
    with pytest.raises(ValueError, match="state_lanes_not_authoritative"):
        replace(manifest, state_lanes=manifest.state_lanes[::-1])
    with pytest.raises(ValueError, match="conflict_edges_not_canonical_reduction"):
        replace(manifest, conflict_edges=manifest.conflict_edges[:-1])
    with pytest.raises(ValueError, match="not_canonical_serial_edge"):
        CbamConflictEdge(1, 8, 10)


def test_private_body_rejects_wrong_count_and_nonopaque_tokens(
    manifest: ClaimBatchAccessManifest,
) -> None:
    profile = PROFILES["K128_CALIBRATION"]
    good = _tokens(manifest.access_rows)
    with pytest.raises(ValueError, match="private_token_count_invalid"):
        build_c0_private_access_body(profile, good[:-1])
    with pytest.raises(ValueError, match="opaque_page_token_must_be_64_bytes"):
        build_c0_private_access_body(profile, good[:-1] + (b"short",))
    with pytest.raises(ValueError, match="opaque_page_token_must_be_nonzero"):
        build_c0_private_access_body(profile, good[:-1] + (b"\x00" * 64,))


def test_private_body_rejects_unbounded_or_lazy_token_sources(
    manifest: ClaimBatchAccessManifest,
) -> None:
    profile = PROFILES["K128_CALIBRATION"]
    lazy = (
        sha3_512(index.to_bytes(8, "big")).digest()
        for index in range(manifest.access_rows)
    )
    with pytest.raises(ValueError, match="private_tokens_sequence_invalid"):
        build_c0_private_access_body(profile, lazy)


def test_private_geometry_reorder_is_rejected(
    manifest: ClaimBatchAccessManifest,
) -> None:
    profile = PROFILES["K128_CALIBRATION"]
    body = build_c0_private_access_body(profile, _tokens(manifest.access_rows))
    rows = (body.rows[1], body.rows[0], *body.rows[2:])
    with pytest.raises(ValueError, match="geometry_not_canonical"):
        CbamPrivateAccessBody(body.status, body.profile_id, rows)
    with pytest.raises(ValueError, match="private_row_access_kind_invalid"):
        CbamPrivateAccessRow(1, 0, 2, sha3_512(b"opaque").digest())


def test_private_commitment_requires_a_nonzero_512_bit_mask(
    manifest: ClaimBatchAccessManifest,
) -> None:
    profile = PROFILES["K128_CALIBRATION"]
    body = build_c0_private_access_body(profile, _tokens(manifest.access_rows))
    with pytest.raises(ValueError, match="private_masking_seed_must_be_64_bytes"):
        body.masked_reference_commitment_512(b"short")
    with pytest.raises(ValueError, match="private_masking_seed_must_be_nonzero"):
        body.masked_reference_commitment_512(b"\x00" * 64)


def test_public_constructor_rejects_non_tuple_witness_shaped_substitution(
    manifest: ClaimBatchAccessManifest,
) -> None:
    with pytest.raises(ValueError, match="hash_ranges_not_authoritative"):
        replace(manifest, hash_ranges=list(manifest.hash_ranges))
    with pytest.raises(ValueError, match="conflict_edges_not_canonical_reduction"):
        replace(manifest, conflict_edges=list(manifest.conflict_edges))


def test_job_binding_rejects_identity_and_private_body_swaps(
    manifest: ClaimBatchAccessManifest,
) -> None:
    profile = PROFILES["K128_CALIBRATION"]
    body = build_c0_private_access_body(profile, _tokens(manifest.access_rows))
    seed = sha3_512(b"job-binding-mask\x00").digest()
    identities = tuple(
        sha3_512(b"job-binding-id\x00" + index.to_bytes(1, "big")).digest()
        for index in range(6)
    )
    binding = build_c0_claim_job_binding(
        manifest,
        body,
        seed,
        batch_id_512=identities[0],
        sidecar_root_512=identities[1],
        state_root_512=identities[2],
        claim_attempt_id_512=identities[3],
        retry_id_512=identities[4],
        job_sequence_id_512=identities[5],
    )
    with pytest.raises(ValueError, match="job_retry_id_must_be_64_bytes"):
        CbamClaimJobBinding(
            binding.status,
            binding.profile_id,
            binding.fixed_manifest_commitment_512,
            binding.masked_private_body_commitment_512,
            binding.batch_id_512,
            binding.sidecar_root_512,
            binding.state_root_512,
            binding.claim_attempt_id_512,
            b"short",
            binding.job_sequence_id_512,
        )
    changed = build_c0_private_access_body(
        profile,
        tuple(reversed(_tokens(manifest.access_rows))),
    )
    with pytest.raises(ValueError, match="job_private_body_commitment_mismatch"):
        binding.verify_private_body(changed, seed)
    with pytest.raises(ValueError, match="job_activation_forbidden"):
        replace(binding, activation_allowed=True)
    with pytest.raises(ValueError, match="job_proof_suite_must_remain_none"):
        replace(binding, proof_suite_id=b"\x01" * 64)
    with pytest.raises(ValueError, match="length_invalid"):
        decode_c0_claim_job_binding(binding.encoded + b"\x00")
    malformed = bytearray(binding.encoded)
    malformed[16] = 2
    with pytest.raises(ValueError, match="flags_invalid"):
        decode_c0_claim_job_binding(bytes(malformed))


def test_canonical_decoders_reject_trailing_or_truncated_inputs(
    manifest: ClaimBatchAccessManifest,
) -> None:
    profile = PROFILES["K128_CALIBRATION"]
    body = build_c0_private_access_body(profile, _tokens(manifest.access_rows))
    with pytest.raises(ValueError, match="length_invalid"):
        decode_c0_claim_batch_access_manifest(manifest.encoded + b"\x00")
    with pytest.raises(ValueError, match="length_invalid"):
        decode_c0_claim_batch_access_manifest(manifest.encoded[:-1])
    with pytest.raises(ValueError, match="length_invalid"):
        decode_c0_private_access_body(body.encoded + b"\x00")
    with pytest.raises(ValueError, match="length_invalid"):
        decode_c0_private_access_body(body.encoded[:-1])
