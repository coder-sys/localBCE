from __future__ import annotations

from dataclasses import replace

import pytest

from experiments.bl_pq512_crypto_foundation.application_sha3_shared_schedule import (
    PathLink,
    build_profile_shared_schedules,
    require_shared_schedule_complete,
)
from experiments.fixed_shape_claim_air.profile import PROFILES


def test_legacy_51_record_oracle_geometry_is_rejected() -> None:
    _, oracle = build_profile_shared_schedules(PROFILES["K128_CALIBRATION"])
    with pytest.raises(ValueError, match="exact_count_mismatch"):
        replace(
            oracle,
            tree_height=13,
            record_count=6_528,
            capacity=8_192,
            leaf_hash_invocations=6_528,
            internal_node_hash_invocations=8_191,
            membership_path_links=84_864,
        )


@pytest.mark.parametrize(
    "field,value,error",
    (
        ("capacity", 64, "capacity_not_exact_power_of_two"),
        ("leaf_hash_invocations", 127, "exact_count_mismatch"),
        ("internal_node_hash_invocations", 1, "exact_count_mismatch"),
        ("typed_root_hash_invocations", 0, "exact_count_mismatch"),
        ("membership_path_links", 1, "exact_count_mismatch"),
        ("preimage_widths_selected", False, "security_boundary_invalid"),
        ("interaction_packing_selected", True, "security_boundary_invalid"),
        ("activation_allowed", True, "security_boundary_invalid"),
    ),
)
def test_schedule_count_or_security_mutation_fails_closed(
    field: str, value: object, error: str
) -> None:
    _, oracle = build_profile_shared_schedules(PROFILES["K128_CALIBRATION"])
    with pytest.raises(ValueError, match=error):
        replace(oracle, **{field: value})


def test_path_link_rejects_sibling_or_parent_substitution() -> None:
    with pytest.raises(ValueError, match="sibling_relation_invalid"):
        PathLink(3, 8, 8, 4)
    with pytest.raises(ValueError, match="parent_relation_invalid"):
        PathLink(3, 8, 9, 5)
