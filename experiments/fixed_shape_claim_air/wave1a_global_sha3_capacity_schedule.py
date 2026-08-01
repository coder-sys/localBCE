"""Exact public capacity schedule for every Wave 1A SHA3-512 call.

The earlier global manifest fixed only call counts.  That is insufficient for
building a verifier program because SHA3 permutation count depends on the
public maximum preimage width.  This schedule derives every ordered capacity
run from the authoritative component constants without constructing private
messages or Keccak witnesses.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
from typing import Final

from experiments.bl_pq512_crypto_foundation.oracle_bundle_commitment import (
    BUNDLE_BYTES as ORACLE_BUNDLE_BYTES,
)
from experiments.bl_pq512_crypto_foundation.policy_bundle_commitment import (
    POLICY_BUNDLE_BYTES,
)
from experiments.bl_pq512_crypto_foundation.ruleset_commitment import encode_ruleset

from .ordered_map_batch_reference import build_ordered_map_batch_schedule
from .profile import CalibrationProfile
from .semantics import StructuralError
from .wave1a_global_sha3_schedule import COMPONENTS


DOMAIN: Final[bytes] = b"BL/PQ512/WAVE1A/GLOBAL-SHA3-CAPACITY-SCHEDULE/v1\x00"
HASH_BUS_DESCRIPTOR_DOMAIN: Final[bytes] = (
    b"BL/PQ512/WAVE2/HASH-BUS-DESCRIPTOR/v2\x00"
)
HASH_BUS_DESCRIPTOR_VERSION: Final[int] = 2
RATE_BYTES: Final[int] = 72
KECCAK_STATE_BITS: Final[int] = 1_600
KECCAK_ROUNDS: Final[int] = 24
PACKED_SHARDS: Final[int] = 16
GROUP_COUNT: Final[int] = 8_192
PERMUTATIONS_PER_COPROCESSOR_SHARD: Final[int] = GROUP_COUNT * PACKED_SHARDS
PROFILE_TAGS: Final[dict[str, int]] = {
    "K128_CALIBRATION": 1,
    "K256_DESIGN_POINT": 2,
    "K512_CALIBRATION": 3,
}


@dataclass(frozen=True, slots=True)
class Sha3CapacityRun:
    component: str
    label: str
    capacity: int
    count: int

    def __post_init__(self) -> None:
        if (
            self.component not in COMPONENTS
            or type(self.label) is not str
            or not self.label
            or type(self.capacity) is not int
            or self.capacity < 0
            or type(self.count) is not int
            or self.count <= 0
        ):
            raise StructuralError("wave1a_sha3_capacity_run_invalid")

    @property
    def permutations(self) -> int:
        return self.count * (self.capacity // RATE_BYTES + 1)


@dataclass(frozen=True, slots=True)
class Wave1AGlobalSha3CapacitySchedule:
    profile_id: str
    runs: tuple[Sha3CapacityRun, ...]
    total_calls: int
    total_permutations: int
    coprocessor_shards: int
    padded_permutations: int
    commitment_512: bytes
    descriptor_commitment_512: bytes

    @property
    def capacities(self) -> tuple[int, ...]:
        return tuple(
            run.capacity
            for run in self.runs
            for _ in range(run.count)
        )


def _map_runs(component: str, prefix: str, operations: int) -> tuple[Sha3CapacityRun, ...]:
    schedule = build_ordered_map_batch_schedule(operations)
    return (
        Sha3CapacityRun(component, f"{prefix}_leaf", 212, schedule.leaf_hash_rows),
        Sha3CapacityRun(component, f"{prefix}_node", 141, schedule.node_hash_rows),
        Sha3CapacityRun(component, f"{prefix}_header", 84, schedule.header_hash_rows),
    )


def _runs(profile: CalibrationProfile) -> tuple[Sha3CapacityRun, ...]:
    k = profile.claim_slots
    truth = (
        Sha3CapacityRun("claim_truth", "source_leaf", 5_648, k),
        Sha3CapacityRun("claim_truth", "source_node", 140, k - 1),
        Sha3CapacityRun("claim_truth", "source_root", 76, 1),
        Sha3CapacityRun("claim_truth", "oracle_leaf", ORACLE_BUNDLE_BYTES, k),
        Sha3CapacityRun("claim_truth", "oracle_root", 11 + 64 * k, 1),
        Sha3CapacityRun("claim_truth", "policy_leaf", POLICY_BUNDLE_BYTES, k),
        Sha3CapacityRun("claim_truth", "policy_root", 11 + 64 * k, 1),
        Sha3CapacityRun("claim_truth", "ruleset", len(encode_ruleset(profile)), 1),
        Sha3CapacityRun("claim_truth", "authority", 538, 1),
    )
    a12 = (
        Sha3CapacityRun("a12_nullifier", "nullifier", 254, k),
        Sha3CapacityRun("a12_nullifier", "pepper", 76, 1),
    )
    salt = (Sha3CapacityRun("salt_use", "salt_use", 78, 1),)
    replay = _map_runs("replay_map", "replay", k + 1)
    payment = (
        *_map_runs("payment", "benefit", k),
        *_map_runs("payment", "obligation", k),
        *_map_runs("payment", "ledger", 2 * k),
        Sha3CapacityRun("payment", "key", 169, 4 * k),
        Sha3CapacityRun("payment", "operation", 816, k),
        Sha3CapacityRun("payment", "operation_log", 167, k),
    )
    master = (
        Sha3CapacityRun("master", "governance", 607, 1),
        Sha3CapacityRun("master", "batch", 926 + 81 * k, 1),
        Sha3CapacityRun("master", "value", 654, 1),
        Sha3CapacityRun("master", "settlement", 984, 1),
    )
    return truth + a12 + salt + replay + payment + master


def build_wave1a_global_sha3_capacity_schedule(
    profile: CalibrationProfile,
) -> Wave1AGlobalSha3CapacitySchedule:
    if not isinstance(profile, CalibrationProfile):
        raise StructuralError("wave1a_sha3_capacity_profile_invalid")
    runs = _runs(profile)
    total_calls = sum(run.count for run in runs)
    total_permutations = sum(run.permutations for run in runs)
    digest = sha3_512(DOMAIN)
    encoded_profile = profile.profile_id.encode("ascii")
    digest.update(len(encoded_profile).to_bytes(1, "big"))
    digest.update(encoded_profile)
    digest.update(len(runs).to_bytes(2, "big"))
    for run in runs:
        component = run.component.encode("ascii")
        label = run.label.encode("ascii")
        digest.update(len(component).to_bytes(1, "big"))
        digest.update(component)
        digest.update(len(label).to_bytes(1, "big"))
        digest.update(label)
        digest.update(run.capacity.to_bytes(8, "big"))
        digest.update(run.count.to_bytes(8, "big"))
    digest.update(total_calls.to_bytes(8, "big"))
    digest.update(total_permutations.to_bytes(8, "big"))
    capacity_commitment = digest.digest()
    coprocessor_shards = (
        total_permutations + PERMUTATIONS_PER_COPROCESSOR_SHARD - 1
    ) // PERMUTATIONS_PER_COPROCESSOR_SHARD
    padded_permutations = (
        coprocessor_shards * PERMUTATIONS_PER_COPROCESSOR_SHARD
    )
    descriptor = sha3_512(HASH_BUS_DESCRIPTOR_DOMAIN)
    descriptor.update(HASH_BUS_DESCRIPTOR_VERSION.to_bytes(2, "big"))
    descriptor.update(PROFILE_TAGS[profile.profile_id].to_bytes(1, "big"))
    descriptor.update(total_calls.to_bytes(8, "big"))
    descriptor.update(total_permutations.to_bytes(8, "big"))
    descriptor.update(capacity_commitment)
    descriptor.update(KECCAK_STATE_BITS.to_bytes(2, "big"))
    descriptor.update(KECCAK_ROUNDS.to_bytes(2, "big"))
    descriptor.update(PACKED_SHARDS.to_bytes(2, "big"))
    descriptor.update(GROUP_COUNT.to_bytes(8, "big"))
    descriptor.update(PERMUTATIONS_PER_COPROCESSOR_SHARD.to_bytes(8, "big"))
    descriptor.update(coprocessor_shards.to_bytes(2, "big"))
    descriptor.update(padded_permutations.to_bytes(8, "big"))
    return Wave1AGlobalSha3CapacitySchedule(
        profile.profile_id,
        runs,
        total_calls,
        total_permutations,
        coprocessor_shards,
        padded_permutations,
        capacity_commitment,
        descriptor.digest(),
    )


__all__ = (
    "Sha3CapacityRun",
    "Wave1AGlobalSha3CapacitySchedule",
    "build_wave1a_global_sha3_capacity_schedule",
)
