from __future__ import annotations

from dataclasses import replace

import pytest

from experiments.bl_pq512_crypto_foundation.oracle_bundle_commitment import (
    OracleAuthorization,
    build_oracle_commitments,
    decode_authorization_token,
    decode_oracle_bundle,
    encode_oracle_bundle,
    oracle_audit_proof,
    oracle_bundle_from_slot,
    verify_oracle_audit_proof,
)
from experiments.fixed_shape_claim_air.measurement import (
    build_synthetic_measurement_slots,
)
from experiments.fixed_shape_claim_air.profile import PROFILES


@pytest.fixture(scope="module")
def material():
    profile = PROFILES["K128_CALIBRATION"]
    bundles = tuple(
        oracle_bundle_from_slot(profile, slot)
        for slot in build_synthetic_measurement_slots(profile, "approval_plus_cover")
    )
    commitments = build_oracle_commitments(profile, bundles)
    return profile, bundles, commitments


@pytest.mark.parametrize("delta", (-1, 1))
def test_truncated_or_extended_bundle_is_rejected(material, delta: int) -> None:
    _, bundles, _ = material
    encoded = encode_oracle_bundle(bundles[0])
    changed = encoded[:-1] if delta < 0 else encoded + b"\x00"
    with pytest.raises(ValueError, match="encoded_length_invalid"):
        decode_oracle_bundle(changed)


def test_magic_and_profile_mutations_are_rejected(material) -> None:
    _, bundles, _ = material
    encoded = bytearray(encode_oracle_bundle(bundles[0]))
    encoded[0] ^= 1
    with pytest.raises(ValueError, match="magic_mismatch"):
        decode_oracle_bundle(bytes(encoded))
    encoded = bytearray(encode_oracle_bundle(bundles[0]))
    encoded[8] = 255
    with pytest.raises(ValueError, match="profile_code_unknown"):
        decode_oracle_bundle(bytes(encoded))


def test_reserved_fact_and_authorization_bits_are_rejected(material) -> None:
    _, bundles, _ = material
    encoded = bytearray(encode_oracle_bundle(bundles[0]))
    encoded[13] |= 0x80
    with pytest.raises(ValueError, match="fact_flags_noncanonical"):
        decode_oracle_bundle(bytes(encoded))
    encoded = bytearray(encode_oracle_bundle(bundles[0]))
    flags_last_byte = 14 + 18
    encoded[flags_last_byte] |= 0x80
    with pytest.raises(ValueError, match="authorization_flags_noncanonical"):
        decode_oracle_bundle(bytes(encoded))


def test_noncanonical_token_rank_is_rejected() -> None:
    with pytest.raises(ValueError, match="rank_noncanonical"):
        decode_authorization_token((37**64).to_bytes(42, "big"))


def test_disabled_authorization_cannot_carry_hidden_data() -> None:
    with pytest.raises(ValueError, match="disabled_authorization_not_zero"):
        OracleAuthorization(False, False, False, "HIDDEN")


def test_bundle_omission_duplicate_and_reorder_fail_closed(material) -> None:
    profile, bundles, _ = material
    with pytest.raises(ValueError, match="bundle_count_invalid"):
        build_oracle_commitments(profile, bundles[:-1])
    with pytest.raises(ValueError, match="bundle_order_invalid"):
        build_oracle_commitments(
            profile, (bundles[1], bundles[0], *bundles[2:])
        )
    with pytest.raises(ValueError, match="bundle_order_invalid"):
        build_oracle_commitments(
            profile, (bundles[0], bundles[0], *bundles[2:])
        )


def test_mixed_profile_bundle_is_rejected(material) -> None:
    profile, bundles, _ = material
    other_profile = PROFILES["K256_DESIGN_POINT"]
    other = oracle_bundle_from_slot(
        other_profile,
        build_synthetic_measurement_slots(other_profile, "all_cover")[0],
    )
    with pytest.raises(ValueError, match="bundle_order_invalid"):
        build_oracle_commitments(profile, (other, *bundles[1:]))


def test_bundle_path_and_root_mutations_fail_closed(material) -> None:
    _, bundles, commitments = material
    proof = oracle_audit_proof(commitments, bundles[0])
    changed_bundle = bytes((proof.bundle[0] ^ 1,)) + proof.bundle[1:]
    with pytest.raises(ValueError):
        verify_oracle_audit_proof(replace(proof, bundle=changed_bundle))
    changed_sibling = bytes((proof.siblings[0][0] ^ 1,)) + proof.siblings[0][1:]
    with pytest.raises(ValueError, match="root_mismatch"):
        verify_oracle_audit_proof(
            replace(proof, siblings=(changed_sibling, *proof.siblings[1:]))
        )
    changed_root = bytes((proof.audit_root[0] ^ 1,)) + proof.audit_root[1:]
    with pytest.raises(ValueError, match="root_mismatch"):
        verify_oracle_audit_proof(replace(proof, audit_root=changed_root))


def test_wrong_position_and_wrong_sibling_count_fail_closed(material) -> None:
    _, bundles, commitments = material
    proof = oracle_audit_proof(commitments, bundles[0])
    with pytest.raises(ValueError, match="bundle_binding_invalid"):
        verify_oracle_audit_proof(replace(proof, position=1))
    with pytest.raises(ValueError, match="sibling_count_invalid"):
        verify_oracle_audit_proof(replace(proof, siblings=proof.siblings[:-1]))

