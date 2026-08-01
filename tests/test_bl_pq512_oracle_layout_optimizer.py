from __future__ import annotations

from experiments.bl_pq512_crypto_foundation.oracle_layout_optimizer import (
    compare_oracle_layouts,
    information_lower_bound_bytes,
    oracle_layout_canonical_sha3_512,
    oracle_layout_summary,
    require_selected_layout_optimal,
)
from experiments.fixed_shape_claim_air.profile import PROFILES


def test_information_bound_and_selected_leaf_share_the_minimum_sha3_block_count() -> None:
    assert information_lower_bound_bytes() == 2_104
    summary = oracle_layout_summary()
    assert summary["selectedBundleBytes"] == 2_133
    assert summary["selectedLeafPermutations"] == 30


def test_selected_layout_is_the_constrained_minimum_for_every_profile() -> None:
    expected = {
        "K128_CALIBRATION": (98_047, 3_954, 94_093),
        "K256_DESIGN_POINT": (196_095, 7_908, 188_187),
        "K512_CALIBRATION": (392_191, 15_816, 376_375),
    }
    for profile_id, profile in PROFILES.items():
        require_selected_layout_optimal(profile)
        candidates = compare_oracle_layouts(profile)
        selected = [value for value in candidates if value.selected]
        assert len(selected) == 1
        legacy = candidates[0]
        assert (
            legacy.proof_sponge_permutations,
            selected[0].proof_sponge_permutations,
            legacy.proof_sponge_permutations
            - selected[0].proof_sponge_permutations,
        ) == expected[profile_id]
        assert selected[0].independently_decodable_authorizations == 50
        assert selected[0].independent_audit_path is True
        assert selected[0].attestation_binds_execution_and_audit is True


def test_lower_permutation_direct_manifest_is_rejected_for_deleted_boundaries() -> None:
    candidates = compare_oracle_layouts(PROFILES["K128_CALIBRATION"])
    direct = next(
        value for value in candidates if value.name == "compact-direct-batch-manifest"
    )
    selected = next(value for value in candidates if value.selected)
    assert direct.proof_sponge_permutations < selected.proof_sponge_permutations
    assert direct.per_claim_leaf_boundary is False
    assert direct.independent_audit_path is False
    assert direct.rejection_reason is not None


def test_optimizer_identity_is_stable() -> None:
    assert oracle_layout_canonical_sha3_512() == (
        "bbd63a71e2ee25b937a5245f3f1b6719bb3574e67565e6d1bc0e9189a81100bd"
        "bcb5e5631d7f0078466910a7156636c8625b05e1751dffedfb15c4d63a607536"
    )
