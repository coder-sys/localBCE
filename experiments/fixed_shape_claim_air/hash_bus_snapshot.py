"""Canonical message snapshot for the Wave 1A semantic SHA3 bus.

The format is consumed by the Rust H4 coordinator.  It carries no prover
authority: Rust derives the capacity descriptor, recomputes every digest, and
recomputes the semantic-port commitment before accepting it.
"""

from __future__ import annotations

from hashlib import sha3_512
from typing import Final, Sequence

from .application_sha3_executable_air import Sha3Call
from .profile import CalibrationProfile
from .semantics import StructuralError
from .wave1a_global_sha3_capacity_schedule import (
    PROFILE_TAGS,
    RATE_BYTES,
    build_wave1a_global_sha3_capacity_schedule,
)


MAGIC: Final[bytes] = b"BLHBSN01"
VERSION: Final[int] = 1
STATE_MAGIC: Final[bytes] = b"BLHBSN02"
STATE_VERSION: Final[int] = 2
SEMANTIC_PORT_DOMAIN: Final[bytes] = (
    b"BL/PQ512/WAVE2/HASH-BUS-SEMANTIC-PORT/v1\x00"
)
STATE_SEMANTIC_PORT_DOMAIN: Final[bytes] = (
    b"BL/PQ512/WAVE2/HASH-BUS-SEMANTIC-PORT/STATE/v1\x00"
)
CAPACITY_SCHEDULE_DOMAIN: Final[bytes] = (
    b"BL/PQ512/WAVE1A/GLOBAL-SHA3-CAPACITY-SCHEDULE/v1\x00"
)
HASH_BUS_DESCRIPTOR_DOMAIN: Final[bytes] = (
    b"BL/PQ512/WAVE2/HASH-BUS-DESCRIPTOR/v2\x00"
)
HASH_BUS_DESCRIPTOR_VERSION: Final[int] = 2
KECCAK_STATE_BITS: Final[int] = 1_600
KECCAK_ROUNDS: Final[int] = 24
PACKED_SHARDS: Final[int] = 16
GROUP_COUNT: Final[int] = 8_192
PERMUTATIONS_PER_COPROCESSOR_SHARD: Final[int] = GROUP_COUNT * PACKED_SHARDS
STATE_ROOT_ENTRY_WIDTH: Final[int] = 137
STATE_ROOT_CAPACITY_BASE: Final[int] = 512
STATE_ROOT_DOMAIN: Final[bytes] = b"BL/PQ512/STATE-PLANE/ROOT/v1\x00"
MAX_MESSAGE_BYTES: Final[int] = 1 << 20
MAX_SNAPSHOT_BYTES: Final[int] = 1 << 30


def _validate(
    profile: CalibrationProfile,
    semantic_program_commitment: bytes,
    calls: Sequence[Sha3Call],
) -> tuple[tuple[Sha3Call, ...], bytes]:
    if (
        not isinstance(profile, CalibrationProfile)
        or type(semantic_program_commitment) is not bytes
        or len(semantic_program_commitment) != 64
    ):
        raise StructuralError("hash_bus_snapshot_header_invalid")
    materialized = tuple(calls)
    schedule = build_wave1a_global_sha3_capacity_schedule(profile)
    if len(materialized) != schedule.total_calls:
        raise StructuralError("hash_bus_snapshot_call_count_mismatch")
    for index, (call, capacity) in enumerate(
        zip(materialized, schedule.capacities, strict=True)
    ):
        if (
            not isinstance(call, Sha3Call)
            or call.capacity != capacity
            or len(call.message) > MAX_MESSAGE_BYTES
        ):
            raise StructuralError(f"hash_bus_snapshot_call_invalid:{index}")
    return materialized, schedule.descriptor_commitment_512


def state_root_capacity(profile: CalibrationProfile) -> int:
    if not isinstance(profile, CalibrationProfile):
        raise StructuralError("hash_bus_state_profile_invalid")
    return profile.claim_slots * STATE_ROOT_ENTRY_WIDTH + STATE_ROOT_CAPACITY_BASE


def state_composed_descriptor_commitment(profile: CalibrationProfile) -> bytes:
    """Mirror the Rust state-composed descriptor without changing the base schedule."""

    schedule = build_wave1a_global_sha3_capacity_schedule(profile)
    base_descriptor = schedule.descriptor_commitment_512
    capacity = state_root_capacity(profile)
    state_permutations = 2 * (capacity // RATE_BYTES + 1)
    total_calls = schedule.total_calls + 2
    total_permutations = schedule.total_permutations + state_permutations
    if total_permutations > schedule.padded_permutations:
        raise StructuralError("hash_bus_state_descriptor_padding_exhausted")

    runs = tuple(
        (run.component, run.label, run.capacity, run.count)
        for run in schedule.runs
    ) + (("state_plane", "root", capacity, 2),)
    digest = sha3_512(CAPACITY_SCHEDULE_DOMAIN)
    encoded_profile = profile.profile_id.encode("ascii")
    digest.update(len(encoded_profile).to_bytes(1, "big"))
    digest.update(encoded_profile)
    digest.update(len(runs).to_bytes(2, "big"))
    for component, label, run_capacity, count in runs:
        encoded_component = component.encode("ascii")
        encoded_label = label.encode("ascii")
        digest.update(len(encoded_component).to_bytes(1, "big"))
        digest.update(encoded_component)
        digest.update(len(encoded_label).to_bytes(1, "big"))
        digest.update(encoded_label)
        digest.update(run_capacity.to_bytes(8, "big"))
        digest.update(count.to_bytes(8, "big"))
    digest.update(total_calls.to_bytes(8, "big"))
    digest.update(total_permutations.to_bytes(8, "big"))
    capacity_commitment = digest.digest()

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
    descriptor.update(schedule.coprocessor_shards.to_bytes(2, "big"))
    descriptor.update(schedule.padded_permutations.to_bytes(8, "big"))
    if descriptor.digest() == base_descriptor:
        raise StructuralError("hash_bus_state_descriptor_not_distinct")
    return descriptor.digest()


def _validate_state_calls(
    profile: CalibrationProfile,
    semantic_program_commitment: bytes,
    calls: Sequence[Sha3Call],
) -> tuple[tuple[Sha3Call, ...], bytes]:
    materialized = tuple(calls)
    schedule = build_wave1a_global_sha3_capacity_schedule(profile)
    expected_count = schedule.total_calls + 2
    if len(materialized) != expected_count:
        raise StructuralError("hash_bus_state_snapshot_call_count_mismatch")
    base_calls, _ = _validate(
        profile,
        semantic_program_commitment,
        materialized[: schedule.total_calls],
    )
    capacity = state_root_capacity(profile)
    for index, call in enumerate(materialized[-2:], start=schedule.total_calls):
        if (
            not isinstance(call, Sha3Call)
            or call.capacity != capacity
            or len(call.message) > MAX_MESSAGE_BYTES
        ):
            raise StructuralError(f"hash_bus_state_snapshot_call_invalid:{index}")
    if len(base_calls) != schedule.total_calls:
        raise StructuralError("hash_bus_state_snapshot_base_call_count_mismatch")
    return materialized, state_composed_descriptor_commitment(profile)


def _port_commitment(
    profile: CalibrationProfile,
    semantic_program_commitment: bytes,
    calls: Sequence[Sha3Call],
    *,
    state_composed: bool,
) -> bytes:
    materialized = tuple(calls)
    if state_composed:
        materialized, descriptor_commitment = _validate_state_calls(
            profile, semantic_program_commitment, calls
        )
        domain = STATE_SEMANTIC_PORT_DOMAIN
        version = STATE_VERSION
    else:
        materialized, descriptor_commitment = _validate(
            profile, semantic_program_commitment, calls
        )
        domain = SEMANTIC_PORT_DOMAIN
        version = VERSION
    digest = sha3_512(domain)
    digest.update(version.to_bytes(2, "big"))
    digest.update(PROFILE_TAGS[profile.profile_id].to_bytes(1, "big"))
    digest.update(semantic_program_commitment)
    digest.update(descriptor_commitment)
    digest.update(len(materialized).to_bytes(8, "big"))
    for index, call in enumerate(materialized):
        call_digest = sha3_512(call.message).digest()
        digest.update(index.to_bytes(8, "big"))
        digest.update(call.capacity.to_bytes(8, "big"))
        digest.update(len(call.message).to_bytes(4, "big"))
        digest.update(call.message)
        digest.update(call_digest)
    return digest.digest()


def hash_bus_semantic_port_commitment(
    profile: CalibrationProfile,
    semantic_program_commitment: bytes,
    calls: Sequence[Sha3Call],
) -> bytes:
    return _port_commitment(
        profile,
        semantic_program_commitment,
        calls,
        state_composed=False,
    )


def hash_bus_state_semantic_port_commitment(
    profile: CalibrationProfile,
    semantic_program_commitment: bytes,
    calls: Sequence[Sha3Call],
) -> bytes:
    return _port_commitment(
        profile,
        semantic_program_commitment,
        calls,
        state_composed=True,
    )


def _encode_snapshot(
    profile: CalibrationProfile,
    semantic_program_commitment: bytes,
    calls: Sequence[Sha3Call],
    *,
    state_composed: bool,
) -> bytes:
    materialized = tuple(calls)
    if state_composed:
        materialized, descriptor_commitment = _validate_state_calls(
            profile, semantic_program_commitment, calls
        )
        port_commitment = _port_commitment(
            profile,
            semantic_program_commitment,
            materialized,
            state_composed=True,
        )
        magic = STATE_MAGIC
        version = STATE_VERSION
    else:
        materialized, descriptor_commitment = _validate(
            profile, semantic_program_commitment, calls
        )
        port_commitment = _port_commitment(
            profile,
            semantic_program_commitment,
            materialized,
            state_composed=False,
        )
        magic = MAGIC
        version = VERSION
    encoded = bytearray(magic)
    encoded.extend(version.to_bytes(2, "big"))
    encoded.extend(PROFILE_TAGS[profile.profile_id].to_bytes(1, "big"))
    encoded.extend(semantic_program_commitment)
    encoded.extend(descriptor_commitment)
    encoded.extend(port_commitment)
    encoded.extend(len(materialized).to_bytes(8, "big"))
    for call in materialized:
        encoded.extend(call.capacity.to_bytes(8, "big"))
        encoded.extend(len(call.message).to_bytes(4, "big"))
        encoded.extend(call.message)
        encoded.extend(sha3_512(call.message).digest())
    if len(encoded) > MAX_SNAPSHOT_BYTES:
        raise StructuralError("hash_bus_snapshot_too_large")
    return bytes(encoded)


def encode_hash_bus_snapshot(
    profile: CalibrationProfile,
    semantic_program_commitment: bytes,
    calls: Sequence[Sha3Call],
) -> bytes:
    return _encode_snapshot(
        profile,
        semantic_program_commitment,
        calls,
        state_composed=False,
    )


def encode_state_composed_hash_bus_snapshot(
    profile: CalibrationProfile,
    semantic_program_commitment: bytes,
    calls: Sequence[Sha3Call],
    before_encoded: bytes,
    after_encoded: bytes,
) -> bytes:
    """Append the two canonical state-root calls to the exact base bus."""

    materialized, _ = _validate(profile, semantic_program_commitment, calls)
    capacity = state_root_capacity(profile)
    state_calls = []
    for label, encoded in (("before", before_encoded), ("after", after_encoded)):
        if type(encoded) is not bytes or len(encoded) > 0xFFFFFFFF:
            raise StructuralError(f"hash_bus_state_{label}_encoding_invalid")
        message = STATE_ROOT_DOMAIN + len(encoded).to_bytes(4, "big") + encoded
        if len(message) > capacity:
            raise StructuralError(f"hash_bus_state_{label}_capacity_invalid")
        state_calls.append(
            Sha3Call(f"state_root_{label}", message, capacity)
        )
    return _encode_snapshot(
        profile,
        semantic_program_commitment,
        (*materialized, *state_calls),
        state_composed=True,
    )


__all__ = (
    "encode_hash_bus_snapshot",
    "encode_state_composed_hash_bus_snapshot",
    "hash_bus_semantic_port_commitment",
    "hash_bus_state_semantic_port_commitment",
    "state_composed_descriptor_commitment",
    "state_root_capacity",
)
