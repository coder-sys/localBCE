"""Canonical sealed-SHA3 to Boolean-GKR boundary.

This adapter derives every capacity-padded Keccak permutation directly from
the governed application SHA3 calls.  It emits the existing strict
``BLKGINP1`` wire-major boundary consumed by the Rust GKR implementation and
an ordered semantic manifest that binds each lane to its call, block, output,
and (only for the actual final block) SHA3-512 digest.

No digest is accepted from the host.  Inputs, outputs, and digests are all
recomputed from the call message and frozen capacity.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
from typing import Final, Iterator, Sequence

from experiments.fixed_shape_claim_air.application_sha3_executable_air import (
    Sha3Call,
)
from experiments.bl_pq512_crypto_foundation.sha3_512_air_reference import (
    KECCAK_ROUNDS,
    RATE_BYTES,
    STATE_BYTES,
    _build_round,
    _pad_message,
    padded_block_count,
)


INPUT_MAGIC: Final[bytes] = b"BLKGINP1"
INPUT_VERSION: Final[int] = 1
GKR_INSTANCES: Final[int] = 1_024
GKR_INPUT_WIDTH: Final[int] = 2_048
KECCAK_STATE_BITS: Final[int] = 1_600


def _permutation_output(initial_state: bytes) -> bytes:
    state = tuple(initial_state)
    for round_index in range(KECCAK_ROUNDS):
        state = _build_round(state, round_index).output_bytes
    return bytes(state)


_DUMMY_OUTPUT: Final[bytes] = _permutation_output(bytes(STATE_BYTES))


@dataclass(frozen=True, slots=True)
class SemanticKeccakLane:
    ordinal: int
    call_index: int
    call_id: str
    block_index: int
    block_active: bool
    actual_last: bool
    initial_state: bytes
    output_state: bytes
    digest: bytes | None

    def __post_init__(self) -> None:
        if (
            type(self.ordinal) is not int
            or self.ordinal < 0
            or type(self.call_index) is not int
            or self.call_index < 0
            or type(self.call_id) is not str
            or not self.call_id
            or type(self.block_index) is not int
            or self.block_index < 0
            or type(self.block_active) is not bool
            or type(self.actual_last) is not bool
            or type(self.initial_state) is not bytes
            or len(self.initial_state) != STATE_BYTES
            or type(self.output_state) is not bytes
            or len(self.output_state) != STATE_BYTES
            or (
                self.digest is not None
                and (type(self.digest) is not bytes or len(self.digest) != 64)
            )
            or (self.actual_last != (self.digest is not None))
        ):
            raise ValueError("semantic_keccak_lane_invalid")


def iter_semantic_keccak_lanes(
    calls: Sequence[Sha3Call],
) -> Iterator[SemanticKeccakLane]:
    materialized = tuple(calls)
    if not materialized or any(type(call) is not Sha3Call for call in materialized):
        raise ValueError("semantic_keccak_calls_invalid")
    ordinal = 0
    for call_index, call in enumerate(materialized):
        padded = _pad_message(call.message)
        capacity_blocks = padded_block_count(call.capacity)
        state = bytes(STATE_BYTES)
        expected_digest = sha3_512(call.message).digest()
        for block_index in range(capacity_blocks):
            active = block_index < len(padded)
            block = padded[block_index] if active else bytes(RATE_BYTES)
            prior = state if active else bytes(STATE_BYTES)
            absorbed = bytearray(prior)
            for index, value in enumerate(block):
                absorbed[index] ^= value
            round_state = tuple(absorbed)
            for round_index in range(KECCAK_ROUNDS):
                round_state = _build_round(round_state, round_index).output_bytes
            output = bytes(round_state)
            if active:
                state = output
            actual_last = active and block_index + 1 == len(padded)
            digest = output[:64] if actual_last else None
            if digest is not None and digest != expected_digest:
                raise AssertionError("semantic_keccak_digest_mismatch")
            yield SemanticKeccakLane(
                ordinal=ordinal,
                call_index=call_index,
                call_id=call.call_id,
                block_index=block_index,
                block_active=active,
                actual_last=actual_last,
                initial_state=bytes(absorbed),
                output_state=output,
                digest=digest,
            )
            ordinal += 1


def _encode_gkr_boundary(
    lanes: Sequence[SemanticKeccakLane],
    *,
    output: bool,
) -> bytes:
    materialized = tuple(lanes)
    count = len(materialized)
    if (
        not 1 <= count <= GKR_INSTANCES
        or any(type(lane) is not SemanticKeccakLane for lane in materialized)
        or tuple(lane.ordinal for lane in materialized)
        != tuple(range(materialized[0].ordinal, materialized[0].ordinal + count))
    ):
        raise ValueError("semantic_keccak_boundary_lanes_invalid")

    words = GKR_INSTANCES // 64
    packed = [0] * (GKR_INPUT_WIDTH * words)
    states = [lane.output_state if output else lane.initial_state for lane in materialized]
    if output:
        states.extend([_DUMMY_OUTPUT] * (GKR_INSTANCES - count))
    for instance, state in enumerate(states):
        for byte_index, value in enumerate(state):
            for bit_index in range(8):
                if value & (1 << bit_index):
                    wire = 8 * byte_index + bit_index
                    packed[wire * words + instance // 64] |= 1 << (instance % 64)

    header = (
        INPUT_MAGIC
        + INPUT_VERSION.to_bytes(2, "big")
        + count.to_bytes(2, "big")
        + GKR_INSTANCES.to_bytes(2, "big")
        + GKR_INPUT_WIDTH.to_bytes(2, "big")
    )
    return header + b"".join(word.to_bytes(8, "big") for word in packed)


def encode_gkr_initial_boundary(
    lanes: Sequence[SemanticKeccakLane],
) -> bytes:
    return _encode_gkr_boundary(lanes, output=False)


def encode_gkr_output_boundary(
    lanes: Sequence[SemanticKeccakLane],
) -> bytes:
    return _encode_gkr_boundary(lanes, output=True)


def semantic_keccak_batches(
    calls: Sequence[Sha3Call],
) -> Iterator[tuple[tuple[SemanticKeccakLane, ...], bytes]]:
    pending: list[SemanticKeccakLane] = []
    for lane in iter_semantic_keccak_lanes(calls):
        pending.append(lane)
        if len(pending) == GKR_INSTANCES:
            batch = tuple(pending)
            yield batch, encode_gkr_initial_boundary(batch)
            pending.clear()
    if pending:
        batch = tuple(pending)
        yield batch, encode_gkr_initial_boundary(batch)


__all__ = [
    "GKR_INPUT_WIDTH",
    "GKR_INSTANCES",
    "INPUT_MAGIC",
    "INPUT_VERSION",
    "KECCAK_STATE_BITS",
    "SemanticKeccakLane",
    "encode_gkr_initial_boundary",
    "encode_gkr_output_boundary",
    "iter_semantic_keccak_lanes",
    "semantic_keccak_batches",
]
