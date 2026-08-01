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
    build_wave1a_global_sha3_capacity_schedule,
)


MAGIC: Final[bytes] = b"BLHBSN01"
VERSION: Final[int] = 1
SEMANTIC_PORT_DOMAIN: Final[bytes] = (
    b"BL/PQ512/WAVE2/HASH-BUS-SEMANTIC-PORT/v1\x00"
)
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


def hash_bus_semantic_port_commitment(
    profile: CalibrationProfile,
    semantic_program_commitment: bytes,
    calls: Sequence[Sha3Call],
) -> bytes:
    materialized, descriptor_commitment = _validate(
        profile, semantic_program_commitment, calls
    )
    digest = sha3_512(SEMANTIC_PORT_DOMAIN)
    digest.update(VERSION.to_bytes(2, "big"))
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


def encode_hash_bus_snapshot(
    profile: CalibrationProfile,
    semantic_program_commitment: bytes,
    calls: Sequence[Sha3Call],
) -> bytes:
    materialized, descriptor_commitment = _validate(
        profile, semantic_program_commitment, calls
    )
    port_commitment = hash_bus_semantic_port_commitment(
        profile, semantic_program_commitment, materialized
    )
    encoded = bytearray(MAGIC)
    encoded.extend(VERSION.to_bytes(2, "big"))
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


__all__ = (
    "encode_hash_bus_snapshot",
    "hash_bus_semantic_port_commitment",
)
