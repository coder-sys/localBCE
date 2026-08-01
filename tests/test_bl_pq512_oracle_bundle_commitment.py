from __future__ import annotations

from dataclasses import replace

import pytest

from experiments.bl_pq512_crypto_foundation.oracle_bundle_commitment import (
    BUNDLE_BYTES,
    authorization_audit_record,
    build_oracle_commitments,
    decode_authorization_token,
    decode_oracle_bundle,
    encode_authorization_token,
    encode_oracle_bundle,
    oracle_attestation_message,
    oracle_audit_proof,
    oracle_bundle_from_slot,
    oracle_commitment_canonical_sha3_512,
    oracle_commitment_schedule,
    verify_oracle_audit_proof,
)
from experiments.fixed_shape_claim_air.measurement import (
    build_synthetic_measurement_slots,
)
from experiments.fixed_shape_claim_air.profile import PROFILES


@pytest.mark.parametrize(
    "token",
    (
        "",
        "A",
        "Z",
        "0",
        "9",
        "A-0-Z",
        "Z" * 64,
        "A" + "-" * 63,
    ),
)
def test_authorization_token_rank_is_exact_and_fixed_width(token: str) -> None:
    encoded = encode_authorization_token(token)
    assert len(encoded) == 42
    assert decode_authorization_token(encoded) == token


def test_bundle_round_trip_has_exact_information_minimum_block_shape() -> None:
    profile = PROFILES["K128_CALIBRATION"]
    slot = build_synthetic_measurement_slots(profile, "full_capacity_real")[0]
    bundle = oracle_bundle_from_slot(profile, slot)
    encoded = encode_oracle_bundle(bundle)
    assert len(encoded) == BUNDLE_BYTES == 2_133
    assert decode_oracle_bundle(encoded) == bundle
    assert len(bundle.authorizations) == 50
    assert all(value.line_enabled for value in bundle.authorizations)


def test_cover_and_real_bundle_lengths_are_identical() -> None:
    profile = PROFILES["K128_CALIBRATION"]
    cover = build_synthetic_measurement_slots(profile, "all_cover")[0]
    real = build_synthetic_measurement_slots(profile, "full_capacity_real")[0]
    assert len(encode_oracle_bundle(oracle_bundle_from_slot(profile, cover))) == len(
        encode_oracle_bundle(oracle_bundle_from_slot(profile, real))
    )


def test_execution_schedule_is_exact_for_all_profiles() -> None:
    expected = {
        "K128_CALIBRATION": (8_203, 114, 3_954, 94_896, 448),
        "K256_DESIGN_POINT": (16_395, 228, 7_908, 189_792, 512),
        "K512_CALIBRATION": (32_779, 456, 15_816, 379_584, 576),
    }
    for profile_id, values in expected.items():
        schedule = oracle_commitment_schedule(PROFILES[profile_id])
        assert schedule["bundleBytes"] == 2_133
        assert schedule["leafPermutations"] == 30
        assert (
            schedule["executionRootPreimageBytes"],
            schedule["executionRootPermutations"],
            schedule["proofSpongePermutations"],
            schedule["proofKeccakRoundRows"],
            schedule["auditProofBytes"],
        ) == values
        assert schedule["sameLeafDigests"] is True
        assert schedule["attestationBindsBothRoots"] is True
        assert schedule["activationAllowed"] is False


def test_execution_and_audit_commitments_share_leaves_and_verify_paths() -> None:
    profile = PROFILES["K128_CALIBRATION"]
    slots = build_synthetic_measurement_slots(profile, "approval_plus_cover")
    bundles = tuple(oracle_bundle_from_slot(profile, slot) for slot in slots)
    commitments = build_oracle_commitments(profile, bundles)
    assert len(commitments.leaf_digests) == 128
    assert commitments.execution_root != commitments.audit_root
    assert len(commitments.audit_levels) == 8
    for index in (0, 1, 64, 127):
        proof = oracle_audit_proof(commitments, bundles[index])
        assert verify_oracle_audit_proof(proof) == bundles[index]


def test_authorization_records_are_fixed_offset_and_independently_addressed() -> None:
    profile = PROFILES["K128_CALIBRATION"]
    slot = build_synthetic_measurement_slots(profile, "full_capacity_real")[0]
    bundle = oracle_bundle_from_slot(profile, slot)
    records = tuple(authorization_audit_record(bundle, index) for index in range(50))
    assert len(set(records)) == 50
    assert {len(value) for value in records} == {57}
    assert records[0][13] == 0
    assert records[-1][13] == 49


def test_attestation_message_binds_both_roots_epoch_profile_and_snapshot() -> None:
    profile = PROFILES["K128_CALIBRATION"]
    bundles = tuple(
        oracle_bundle_from_slot(profile, slot)
        for slot in build_synthetic_measurement_slots(profile, "all_cover")
    )
    commitments = build_oracle_commitments(profile, bundles)
    baseline = oracle_attestation_message(
        profile.profile_id,
        snapshot_id="SYNTHETIC-SNAPSHOT-1",
        signer_epoch=7,
        execution_root=commitments.execution_root,
        audit_root=commitments.audit_root,
    )
    assert baseline != oracle_attestation_message(
        profile.profile_id,
        snapshot_id="SYNTHETIC-SNAPSHOT-1",
        signer_epoch=8,
        execution_root=commitments.execution_root,
        audit_root=commitments.audit_root,
    )
    assert baseline != oracle_attestation_message(
        profile.profile_id,
        snapshot_id="SYNTHETIC-SNAPSHOT-1",
        signer_epoch=7,
        execution_root=bytes((commitments.execution_root[0] ^ 1,))
        + commitments.execution_root[1:],
        audit_root=commitments.audit_root,
    )


def test_summary_identity_is_stable() -> None:
    assert oracle_commitment_canonical_sha3_512() == (
        "038f354b3dbf32492bb6c6541e3fabd2f7d5a0b86f7667b8214533965c1787e5"
        "6c5174b18b2f0dbf85da9c20498d669112793efca0e39c1083337bf10e5665ca"
    )


def test_one_authorization_change_changes_both_commitments() -> None:
    profile = PROFILES["K128_CALIBRATION"]
    slots = build_synthetic_measurement_slots(profile, "approval_plus_cover")
    bundles = tuple(oracle_bundle_from_slot(profile, slot) for slot in slots)
    baseline = build_oracle_commitments(profile, bundles)
    authorization = bundles[0].authorizations[0]
    changed_authorization = replace(
        authorization,
        present=True,
        token="SYNTHETIC-AUTH-1",
    )
    changed_bundle = replace(
        bundles[0],
        authorizations=(changed_authorization, *bundles[0].authorizations[1:]),
    )
    changed = build_oracle_commitments(
        profile, (changed_bundle, *bundles[1:])
    )
    assert changed.execution_root != baseline.execution_root
    assert changed.audit_root != baseline.audit_root
