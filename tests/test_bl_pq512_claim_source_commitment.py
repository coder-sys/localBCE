from __future__ import annotations

from dataclasses import replace

import pytest

from experiments.bl_pq512_crypto_foundation.claim_source_commitment import (
    CLAIM_SOURCE_BUNDLE_BYTES,
    build_claim_source_commitments,
    claim_source_bundle_from_slot,
    claim_source_commitment_canonical_sha3_512,
    claim_source_commitment_schedule,
    claim_source_proof,
    decode_claim_source_bundle,
    encode_claim_source_bundle,
    verify_claim_source_proof,
)
from experiments.bl_pq512_crypto_foundation.oracle_bundle_commitment import (
    encode_authorization_token,
)
from experiments.fixed_shape_claim_air.measurement import (
    build_synthetic_measurement_slots,
)
from experiments.fixed_shape_claim_air.profile import PROFILES
from experiments.fixed_shape_claim_air.semantics import canonical_token_rank_sort_key


def test_compact_bundle_is_fixed_reversible_and_smaller_than_reference_leaf() -> None:
    profile = PROFILES["K128_CALIBRATION"]
    slots = build_synthetic_measurement_slots(profile, "mixed_half_real")
    for slot in (slots[0], slots[-1]):
        bundle = claim_source_bundle_from_slot(profile, slot)
        encoded = encode_claim_source_bundle(bundle)
        assert len(encoded) == CLAIM_SOURCE_BUNDLE_BYTES == 5_648
        assert decode_claim_source_bundle(encoded) == bundle
    assert CLAIM_SOURCE_BUNDLE_BYTES < 8_525


def test_full_capacity_bundle_preserves_every_claim_source_field() -> None:
    profile = PROFILES["K128_CALIBRATION"]
    slot = build_synthetic_measurement_slots(profile, "full_capacity_real")[0]
    bundle = claim_source_bundle_from_slot(profile, slot)
    decoded = decode_claim_source_bundle(encode_claim_source_bundle(bundle))
    assert decoded.source_authority_id == slot.source_authority_id
    assert decoded.source_sequence == slot.source_sequence
    assert decoded.claim_id == slot.claim_id
    assert decoded.member_id == slot.member_id
    assert decoded.provider_npi == slot.provider_npi
    assert decoded.attempt_version == slot.attempt_version
    assert decoded.revision_kind == slot.revision_kind
    assert decoded.parent_attempt_version == slot.parent_attempt_version
    assert decoded.total_charge_cents == slot.total_charge_cents
    assert decoded.patient_responsibility_cents == slot.patient_responsibility_cents
    assert decoded.diagnoses == slot.diagnoses
    assert len(decoded.service_lines) == len(slot.service_lines) == 50
    for observed, expected in zip(decoded.service_lines, slot.service_lines, strict=True):
        assert observed.original_line_index == expected.original_line_index
        assert observed.line_id == expected.line_id
        assert observed.procedure_code == expected.procedure_code
        assert observed.charge_cents == expected.charge_cents
        assert observed.units_cents == expected.units_cents
        assert observed.prior_authorization == expected.prior_authorization


def test_k128_tree_and_every_membership_proof_recompute_exact_root() -> None:
    profile = PROFILES["K128_CALIBRATION"]
    slots = build_synthetic_measurement_slots(profile, "mixed_half_real")
    commitments = build_claim_source_commitments(profile, slots)
    assert len(commitments.leaf_digests) == 128
    assert tuple(len(level) for level in commitments.levels) == (
        128,
        64,
        32,
        16,
        8,
        4,
        2,
        1,
    )
    for index in (0, 1, 63, 64, 127):
        bundle = claim_source_bundle_from_slot(profile, slots[index])
        proof = claim_source_proof(commitments, bundle)
        assert verify_claim_source_proof(proof) == bundle


@pytest.mark.parametrize(
    ("profile_id", "slots", "depth"),
    (
        ("K128_CALIBRATION", 128, 7),
        ("K256_DESIGN_POINT", 256, 8),
        ("K512_CALIBRATION", 512, 9),
    ),
)
def test_every_profile_builds_exact_power_of_two_tree(
    profile_id: str, slots: int, depth: int
) -> None:
    profile = PROFILES[profile_id]
    claims = build_synthetic_measurement_slots(profile, "all_cover")
    commitments = build_claim_source_commitments(profile, claims)
    assert len(commitments.leaf_digests) == slots
    assert len(commitments.levels) == depth + 1
    assert tuple(len(level) for level in commitments.levels) == tuple(
        slots >> height for height in range(depth + 1)
    )


def test_bundle_padding_and_tree_mutations_fail_closed() -> None:
    profile = PROFILES["K128_CALIBRATION"]
    slots = build_synthetic_measurement_slots(profile, "mixed_half_real")
    commitments = build_claim_source_commitments(profile, slots)
    bundle = claim_source_bundle_from_slot(profile, slots[0])
    encoded = bytearray(encode_claim_source_bundle(bundle))
    encoded[-1] = 1
    with pytest.raises(ValueError, match="disabled_line_not_zero"):
        decode_claim_source_bundle(bytes(encoded))

    proof = claim_source_proof(commitments, bundle)
    changed_sibling = bytes((proof.siblings[0][0] ^ 1,)) + proof.siblings[0][1:]
    with pytest.raises(ValueError, match="root_mismatch"):
        verify_claim_source_proof(
            replace(proof, siblings=(changed_sibling, *proof.siblings[1:]))
        )


def test_schedule_freezes_throughput_gain_without_activation() -> None:
    schedule = claim_source_commitment_schedule(PROFILES["K128_CALIBRATION"])
    assert schedule["bundleBytes"] == 5_648
    assert schedule["leafPermutations"] == 79
    assert schedule["nodePermutations"] == 2
    assert schedule["rootPermutations"] == 2
    assert schedule["proofSpongePermutations"] == 10_368
    assert schedule["proofKeccakRoundRows"] == 248_832
    assert schedule["sourceAuthorityBindingConstrained"] is False
    assert schedule["proofSuiteId"] is None
    assert schedule["activationAllowed"] is False
    assert claim_source_commitment_canonical_sha3_512() == (
        "5ae4ce1e6008f6232c281f7b1ff7e21873886791f3e1564d4bb4e4253cafe5b6"
        "c6461846cb46892637bc2d42efaf46267c8bbaaf5e17fe1806cedfa8c570ba7d"
    )


def test_v2_token_sort_key_is_exactly_the_authenticated_rank_order() -> None:
    tokens = ("", "0", "9", "A", "Z", "A-", "A0", "AA", "ZZ", "00")
    assert sorted(
        tokens,
        key=lambda value: canonical_token_rank_sort_key(value, allow_empty=True),
    ) == sorted(tokens, key=encode_authorization_token)
    assert sorted(("0", "A"), key=canonical_token_rank_sort_key) == ["A", "0"]
