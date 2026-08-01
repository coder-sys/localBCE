"""Wave 1B SHA3-512 schedule for claims and packed oracle bundles.

The Wave 1A physical ledger budgeted 51 oracle records per claim and a large
in-proof binary tree.  The reviewed bundle encoding instead hashes one exact
2,133-byte facts-plus-authorizations bundle per claim and one ordered execution
root.  A separate audit tree reuses the leaf digests outside the proof.  Claim-
source leaves use the reversible compact v2 bundle and one bottom-up dense tree
with each node hashed once; the 8,525-byte generic reference wrapper is not in
the proof schedule.

This proves topology, fixed profile cardinalities, exact typed preimage widths,
FIPS padding blocks, and Keccak round rows for these two commitment lanes only.  It
deliberately does not select lookup interaction packing, the other application
hash-port schedules, PCS parameters, a proof suite, or activation.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
import json
from typing import Final, Sequence

from experiments.fixed_shape_claim_air.profile import PROFILES, CalibrationProfile


STATUS: Final[str] = (
    "WAVE1B_COMPACT_CLAIM_TREE_AND_PACKED_ORACLE_BUNDLE_SCHEDULE_PROVED_"
    "NONACTIVATING_INTERACTION_PACKING_OPEN"
)
CANONICAL_DOMAIN: Final[bytes] = (
    b"BL/PQ512/WAVE1B/APPLICATION-SHA3-SHARED-SCHEDULE/v2"
)
CLAIM_SOURCE_TREE: Final[str] = "claim_source_tree"
ORACLE_TREE: Final[str] = "oracle_bundle_execution"
RATE_BYTES: Final[int] = 72
KECCAK_ROUNDS: Final[int] = 24
SOURCE_LEAF_PREIMAGE_BYTES: Final[int] = 5_648
ORACLE_BUNDLE_PREIMAGE_BYTES: Final[int] = 2_133
ORACLE_EXECUTION_ROOT_PREFIX_BYTES: Final[int] = 11
INTERNAL_NODE_PREIMAGE_BYTES: Final[int] = 140
TYPED_ROOT_PREIMAGE_BYTES: Final[int] = 76


@dataclass(frozen=True, slots=True)
class FixedPreimageClass:
    name: str
    preimage_bytes: int
    invocations: int

    def __post_init__(self) -> None:
        if type(self.name) is not str or not self.name:
            raise ValueError("shared_schedule_preimage_class_name_invalid")
        if type(self.preimage_bytes) is not int or self.preimage_bytes < 0:
            raise ValueError("shared_schedule_preimage_bytes_invalid")
        if type(self.invocations) is not int or self.invocations <= 0:
            raise ValueError("shared_schedule_preimage_invocations_invalid")

    @property
    def permutations_per_invocation(self) -> int:
        return self.preimage_bytes // RATE_BYTES + 1

    @property
    def total_permutations(self) -> int:
        return self.invocations * self.permutations_per_invocation


@dataclass(frozen=True, slots=True)
class PathLink:
    child_height: int
    child_position: int
    sibling_position: int
    parent_position: int

    def __post_init__(self) -> None:
        if type(self.child_height) is not int or self.child_height < 0:
            raise ValueError("shared_schedule_child_height_invalid")
        if type(self.child_position) is not int or self.child_position < 0:
            raise ValueError("shared_schedule_child_position_invalid")
        if type(self.sibling_position) is not int or self.sibling_position < 0:
            raise ValueError("shared_schedule_sibling_position_invalid")
        if type(self.parent_position) is not int or self.parent_position < 0:
            raise ValueError("shared_schedule_parent_position_invalid")
        if self.sibling_position != (self.child_position ^ 1):
            raise ValueError("shared_schedule_sibling_relation_invalid")
        if self.parent_position != self.child_position >> 1:
            raise ValueError("shared_schedule_parent_relation_invalid")


@dataclass(frozen=True, slots=True)
class DenseTreeSharedSchedule:
    profile_id: str
    tree_name: str
    tree_height: int
    record_count: int
    capacity: int
    leaf_hash_invocations: int
    internal_node_hash_invocations: int
    typed_root_hash_invocations: int
    membership_path_links: int
    preimage_widths_selected: bool = True
    interaction_packing_selected: bool = False
    activation_allowed: bool = False

    def __post_init__(self) -> None:
        if self.profile_id not in PROFILES:
            raise ValueError("shared_schedule_profile_unknown")
        if self.tree_name not in {CLAIM_SOURCE_TREE, ORACLE_TREE}:
            raise ValueError("shared_schedule_tree_name_unknown")
        if type(self.tree_height) is not int or not 0 <= self.tree_height <= 31:
            raise ValueError("shared_schedule_tree_height_invalid")
        if type(self.capacity) is not int or self.capacity != 1 << self.tree_height:
            raise ValueError("shared_schedule_capacity_not_exact_power_of_two")
        if type(self.record_count) is not int or not 0 < self.record_count <= self.capacity:
            raise ValueError("shared_schedule_record_count_invalid")
        expected_counts = (
            (
                self.capacity,
                self.capacity - 1,
                1,
                self.record_count * self.tree_height,
            )
            if self.tree_name == CLAIM_SOURCE_TREE
            else (self.record_count, 0, 1, 0)
        )
        observed_counts = (
            self.leaf_hash_invocations,
            self.internal_node_hash_invocations,
            self.typed_root_hash_invocations,
            self.membership_path_links,
        )
        if observed_counts != expected_counts:
            raise ValueError("shared_schedule_exact_count_mismatch")
        if (
            self.preimage_widths_selected is not True
            or self.interaction_packing_selected
            or self.activation_allowed
        ):
            raise ValueError("shared_schedule_security_boundary_invalid")

    @property
    def shared_hash_invocations(self) -> int:
        return (
            self.leaf_hash_invocations
            + self.internal_node_hash_invocations
            + self.typed_root_hash_invocations
        )

    @property
    def level_widths(self) -> tuple[int, ...]:
        if self.tree_name == ORACLE_TREE:
            return (self.record_count,)
        return tuple(self.capacity >> height for height in range(self.tree_height + 1))

    @property
    def preimage_classes(self) -> tuple[FixedPreimageClass, ...]:
        profile = PROFILES[self.profile_id]
        if self.tree_name == CLAIM_SOURCE_TREE:
            return (
                FixedPreimageClass(
                    "claim_source_leaf",
                    SOURCE_LEAF_PREIMAGE_BYTES,
                    profile.claim_slots,
                ),
                FixedPreimageClass(
                    "claim_source_internal_node",
                    INTERNAL_NODE_PREIMAGE_BYTES,
                    self.internal_node_hash_invocations,
                ),
                FixedPreimageClass(
                    "claim_source_typed_root",
                    TYPED_ROOT_PREIMAGE_BYTES,
                    1,
                ),
            )
        return (
            FixedPreimageClass(
                "oracle_bundle_leaf",
                ORACLE_BUNDLE_PREIMAGE_BYTES,
                profile.claim_slots,
            ),
            FixedPreimageClass(
                "oracle_execution_root",
                ORACLE_EXECUTION_ROOT_PREFIX_BYTES
                + profile.claim_slots * 64,
                1,
            ),
        )

    @property
    def shared_sponge_permutations(self) -> int:
        return sum(value.total_permutations for value in self.preimage_classes)

    @property
    def shared_keccak_round_rows(self) -> int:
        return self.shared_sponge_permutations * KECCAK_ROUNDS

    def path_links_for_position(self, position: int) -> tuple[PathLink, ...]:
        if self.tree_name == ORACLE_TREE:
            if type(position) is not int or not 0 <= position < self.record_count:
                raise ValueError("shared_schedule_membership_position_invalid")
            return ()
        if type(position) is not int or not 0 <= position < self.record_count:
            raise ValueError("shared_schedule_membership_position_invalid")
        return tuple(
            PathLink(
                child_height=height,
                child_position=position >> height,
                sibling_position=(position >> height) ^ 1,
                parent_position=position >> (height + 1),
            )
            for height in range(self.tree_height)
        )


def _schedule(
    profile: CalibrationProfile,
    *,
    tree_name: str,
    tree_height: int,
    record_count: int,
) -> DenseTreeSharedSchedule:
    capacity = 1 << tree_height
    packed_oracle = tree_name == ORACLE_TREE
    return DenseTreeSharedSchedule(
        profile_id=profile.profile_id,
        tree_name=tree_name,
        tree_height=tree_height,
        record_count=record_count,
        capacity=capacity,
        leaf_hash_invocations=record_count if packed_oracle else capacity,
        internal_node_hash_invocations=0 if packed_oracle else capacity - 1,
        typed_root_hash_invocations=1,
        membership_path_links=0 if packed_oracle else record_count * tree_height,
    )


def build_profile_shared_schedules(
    profile: CalibrationProfile,
) -> tuple[DenseTreeSharedSchedule, DenseTreeSharedSchedule]:
    if not isinstance(profile, CalibrationProfile):
        raise TypeError("shared_schedule_calibration_profile_required")
    schedules = (
        _schedule(
            profile,
            tree_name=CLAIM_SOURCE_TREE,
            tree_height=profile.claim_source_tree_depth,
            record_count=profile.claim_slots,
        ),
        _schedule(
            profile,
            tree_name=ORACLE_TREE,
            tree_height=profile.claim_source_tree_depth,
            record_count=profile.claim_slots,
        ),
    )
    for schedule in schedules:
        require_shared_schedule_complete(schedule)
    return schedules


def require_shared_schedule_complete(schedule: DenseTreeSharedSchedule) -> None:
    """Fail closed unless every link targets the one complete node schedule."""

    if not isinstance(schedule, DenseTreeSharedSchedule):
        raise TypeError("dense_tree_shared_schedule_required")
    schedule.__post_init__()
    profile = PROFILES[schedule.profile_id]
    expected = {
        CLAIM_SOURCE_TREE: (
            profile.claim_source_tree_depth,
            profile.claim_slots,
        ),
        ORACLE_TREE: (profile.claim_source_tree_depth, profile.claim_slots),
    }[schedule.tree_name]
    if (schedule.tree_height, schedule.record_count) != expected:
        raise ValueError("shared_schedule_profile_geometry_mismatch")

    if schedule.tree_name == ORACLE_TREE:
        if schedule.level_widths != (profile.claim_slots,):
            raise ValueError("shared_schedule_level_boundary_invalid")
        if sum(value.invocations for value in schedule.preimage_classes) != (
            schedule.shared_hash_invocations
        ):
            raise ValueError("shared_schedule_preimage_class_coverage_invalid")
        if schedule.membership_path_links != 0:
            raise ValueError("shared_schedule_path_link_coverage_invalid")
        return

    widths = schedule.level_widths
    if widths[0] != schedule.capacity or widths[-1] != 1:
        raise ValueError("shared_schedule_level_boundary_invalid")
    if any(
        left != 2 * right
        for left, right in zip(widths[:-1], widths[1:], strict=True)
    ):
        raise ValueError("shared_schedule_level_halving_invalid")
    if sum(widths[1:]) != schedule.internal_node_hash_invocations:
        raise ValueError("shared_schedule_internal_node_coverage_invalid")
    if sum(value.invocations for value in schedule.preimage_classes) != (
        schedule.shared_hash_invocations
    ):
        raise ValueError("shared_schedule_preimage_class_coverage_invalid")

    observed_links = 0
    for position in range(schedule.record_count):
        links = schedule.path_links_for_position(position)
        if len(links) != schedule.tree_height:
            raise ValueError("shared_schedule_path_height_mismatch")
        for link in links:
            child_width = widths[link.child_height]
            parent_width = widths[link.child_height + 1]
            if (
                link.child_position >= child_width
                or link.sibling_position >= child_width
                or link.parent_position >= parent_width
            ):
                raise ValueError("shared_schedule_path_link_out_of_range")
            observed_links += 1
    if observed_links != schedule.membership_path_links:
        raise ValueError("shared_schedule_path_link_coverage_invalid")


def shared_schedule_summary() -> dict[str, object]:
    profiles: list[dict[str, object]] = []
    for profile_id, profile in PROFILES.items():
        schedules = build_profile_shared_schedules(profile)
        profiles.append(
            {
                "profileId": profile_id,
                "trees": [
                    {
                        "treeName": schedule.tree_name,
                        "treeHeight": schedule.tree_height,
                        "recordCount": schedule.record_count,
                        "capacity": schedule.capacity,
                        "leafHashInvocations": schedule.leaf_hash_invocations,
                        "internalNodeHashInvocations": (
                            schedule.internal_node_hash_invocations
                        ),
                        "typedRootHashInvocations": (
                            schedule.typed_root_hash_invocations
                        ),
                        "sharedHashInvocations": schedule.shared_hash_invocations,
                        "sharedSpongePermutations": (
                            schedule.shared_sponge_permutations
                        ),
                        "sharedKeccakRoundRows": schedule.shared_keccak_round_rows,
                        "membershipPathLinks": schedule.membership_path_links,
                        "preimageClasses": [
                            {
                                "name": value.name,
                                "preimageBytes": value.preimage_bytes,
                                "invocations": value.invocations,
                                "permutationsPerInvocation": (
                                    value.permutations_per_invocation
                                ),
                            }
                            for value in schedule.preimage_classes
                        ],
                    }
                    for schedule in schedules
                ],
                "sharedHashInvocations": sum(
                    schedule.shared_hash_invocations for schedule in schedules
                ),
                "membershipPathLinks": sum(
                    schedule.membership_path_links for schedule in schedules
                ),
                "sharedSpongePermutations": sum(
                    schedule.shared_sponge_permutations for schedule in schedules
                ),
                "sharedKeccakRoundRows": sum(
                    schedule.shared_keccak_round_rows for schedule in schedules
                ),
            }
        )
    return {
        "status": STATUS,
        "profiles": profiles,
        "preimageWidthsSelected": True,
        "sha3PermutationScheduleSelected": True,
        "interactionPackingSelected": False,
        "proofSuiteId": None,
        "activationAllowed": False,
    }


def shared_schedule_canonical_sha3_512() -> str:
    encoded = json.dumps(
        shared_schedule_summary(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return sha3_512(CANONICAL_DOMAIN + encoded).hexdigest()


__all__: Sequence[str] = (
    "DenseTreeSharedSchedule",
    "FixedPreimageClass",
    "PathLink",
    "STATUS",
    "build_profile_shared_schedules",
    "require_shared_schedule_complete",
    "shared_schedule_canonical_sha3_512",
    "shared_schedule_summary",
)
