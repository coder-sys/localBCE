from __future__ import annotations

import pytest

from experiments.bl_pq512_crypto_foundation.application_sha3_shared_schedule import (
    STATUS,
    build_profile_shared_schedules,
    require_shared_schedule_complete,
    shared_schedule_canonical_sha3_512,
    shared_schedule_summary,
)
from experiments.fixed_shape_claim_air.profile import PROFILES


EXPECTED = {
    "K128_CALIBRATION": {
        "claim": (7, 128, 128, 256, 896),
        "oracle": (7, 128, 128, 129, 0),
        "shared": 385,
        "links": 896,
        "permutations": 14_322,
        "round_rows": 343_728,
    },
    "K256_DESIGN_POINT": {
        "claim": (8, 256, 256, 512, 2_048),
        "oracle": (8, 256, 256, 257, 0),
        "shared": 769,
        "links": 2_048,
        "permutations": 28_644,
        "round_rows": 687_456,
    },
    "K512_CALIBRATION": {
        "claim": (9, 512, 512, 1_024, 4_608),
        "oracle": (9, 512, 512, 513, 0),
        "shared": 1_537,
        "links": 4_608,
        "permutations": 57_288,
        "round_rows": 1_374_912,
    },
}


@pytest.mark.parametrize("profile_id", tuple(PROFILES))
def test_shared_tree_schedule_has_exact_fixed_geometry(profile_id: str) -> None:
    claim, oracle = build_profile_shared_schedules(PROFILES[profile_id])
    expected = EXPECTED[profile_id]
    assert (
        claim.tree_height,
        claim.record_count,
        claim.capacity,
        claim.shared_hash_invocations,
        claim.membership_path_links,
    ) == expected["claim"]
    assert (
        oracle.tree_height,
        oracle.record_count,
        oracle.capacity,
        oracle.shared_hash_invocations,
        oracle.membership_path_links,
    ) == expected["oracle"]
    assert claim.shared_hash_invocations + oracle.shared_hash_invocations == expected["shared"]
    assert claim.membership_path_links + oracle.membership_path_links == expected["links"]
    assert claim.shared_sponge_permutations + oracle.shared_sponge_permutations == (
        expected["permutations"]
    )
    assert claim.shared_keccak_round_rows + oracle.shared_keccak_round_rows == (
        expected["round_rows"]
    )
    require_shared_schedule_complete(claim)
    require_shared_schedule_complete(oracle)


def test_every_boundary_path_link_targets_a_scheduled_node() -> None:
    for profile in PROFILES.values():
        for schedule in build_profile_shared_schedules(profile):
            for position in (0, schedule.record_count // 2, schedule.record_count - 1):
                links = schedule.path_links_for_position(position)
                if schedule.tree_name == "oracle_bundle_execution":
                    assert links == ()
                    continue
                assert len(links) == schedule.tree_height
                assert links[0].child_position == position
                assert links[-1].parent_position == 0
                for link in links:
                    assert link.sibling_position == link.child_position ^ 1
                    assert link.parent_position == link.child_position >> 1


def test_k128_fixed_preimage_classes_cover_every_hash_once() -> None:
    claim, oracle = build_profile_shared_schedules(PROFILES["K128_CALIBRATION"])
    assert tuple(
        (value.name, value.preimage_bytes, value.invocations, value.total_permutations)
        for value in (*claim.preimage_classes, *oracle.preimage_classes)
    ) == (
        ("claim_source_leaf", 5_648, 128, 10_112),
        ("claim_source_internal_node", 140, 127, 254),
        ("claim_source_typed_root", 76, 1, 2),
        ("oracle_bundle_leaf", 2_133, 128, 3_840),
        ("oracle_execution_root", 8_203, 1, 114),
    )
    assert sum(
        value.invocations for value in (*claim.preimage_classes, *oracle.preimage_classes)
    ) == 385


def test_summary_freezes_dense_round_schedule_but_remains_nonactivating() -> None:
    summary = shared_schedule_summary()
    assert summary["status"] == STATUS
    assert summary["preimageWidthsSelected"] is True
    assert summary["sha3PermutationScheduleSelected"] is True
    assert summary["interactionPackingSelected"] is False
    assert summary["proofSuiteId"] is None
    assert summary["activationAllowed"] is False
    assert len(summary["profiles"]) == 3
    assert shared_schedule_canonical_sha3_512() == (
        "b25f5122554354b37b45eaeeca67fc78eeb0197ec258e55af10ff5922c667a0c"
        "d5ac04b9d8e01271564df046ef87c5b220e04492119cf0532f074c3841771e28"
    )
