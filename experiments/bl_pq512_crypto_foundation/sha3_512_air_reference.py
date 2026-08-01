"""Byte-oriented low-degree SHA3-512 AIR reference for Wave 1B.

The construction represents Keccak-f[1600] as canonical bytes and delegates
the nonlinear byte operations to three fixed public lookup families:

* ``XOR8(a, b, a xor b)``;
* ``AND_NOT8(a, b, (~a) & b)``; and
* ``SPLIT8_s(a, low, high)`` for each public shift ``s`` in ``1..7``.

The Keccak round core has 1,632 base columns and exactly 1,024 lookup messages.
A complete sponge trace adds 72 block-byte columns; its first round has 72
additional absorb-XOR lookups, for a 1,704-column trace and maximum 1,096
lookup messages per row.  The
largest direct constraint degree is two; the conservative composed envelope is
three once a LogUp-style lookup interaction is attached.  This module freezes
the permutation witness, lookup inventory, padding, and digest KATs.  It does
not select the final interaction packing, expand every Wave 1A hash port, build
a prover, or authorize activation.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
from typing import Final, Sequence


SHA3_BYTE_AIR_STATUS: Final[str] = (
    "WAVE1B_SHA3_512_BYTE_LOOKUP_AIR_REFERENCE_NONACTIVATING"
)
SHA3_BYTE_AIR_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE1B/SHA3-512-BYTE-AIR/v1"
KECCAK_ROUNDS: Final[int] = 24
STATE_BYTES: Final[int] = 200
RATE_BYTES: Final[int] = 72
CAPACITY_BYTES: Final[int] = 128
CORE_ROUND_BASE_COLUMNS: Final[int] = 1_632
SPONGE_BLOCK_COLUMNS: Final[int] = RATE_BYTES
TRACE_BASE_COLUMNS: Final[int] = CORE_ROUND_BASE_COLUMNS + SPONGE_BLOCK_COLUMNS
CORE_ROUND_LOOKUP_MESSAGES: Final[int] = 1_024
ABSORB_XOR_LOOKUPS: Final[int] = RATE_BYTES
FIRST_ROUND_LOOKUP_MESSAGES: Final[int] = (
    CORE_ROUND_LOOKUP_MESSAGES + ABSORB_XOR_LOOKUPS
)
ROUND_XOR_LOOKUPS: Final[int] = 608
ROUND_AND_NOT_LOOKUPS: Final[int] = 200
ROUND_SPLIT_LOOKUPS: Final[int] = 216
DIRECT_MAXIMUM_DEGREE: Final[int] = 2
COMPOSED_MAXIMUM_DEGREE: Final[int] = 3

_ROTATION_OFFSETS: Final[tuple[tuple[int, ...], ...]] = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)
_ROUND_CONSTANTS: Final[tuple[int, ...]] = (
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
)


def _byte(label: str, value: object) -> int:
    if type(value) is not int or not 0 <= value <= 0xFF:
        raise ValueError(f"sha3_air_{label}_not_canonical_byte")
    return value


def _byte_tuple(label: str, values: object, length: int) -> tuple[int, ...]:
    if not isinstance(values, tuple) or len(values) != length:
        raise ValueError(f"sha3_air_{label}_length_invalid")
    return tuple(_byte(label, value) for value in values)


def _xor8(left: int, right: int) -> int:
    return _byte("xor_left", left) ^ _byte("xor_right", right)


def _and_not8(left: int, right: int) -> int:
    return (~_byte("and_not_left", left) & 0xFF) & _byte("and_not_right", right)


def _split8(value: int, shift: int) -> tuple[int, int]:
    value = _byte("split_value", value)
    if type(shift) is not int or not 1 <= shift <= 7:
        raise ValueError("sha3_air_split_shift_invalid")
    low_width = 8 - shift
    return value & ((1 << low_width) - 1), value >> low_width


def _lanes_to_bytes(lanes: Sequence[int]) -> tuple[int, ...]:
    if len(lanes) != 25:
        raise ValueError("sha3_air_lane_count_invalid")
    result: list[int] = []
    for lane in lanes:
        if type(lane) is not int or not 0 <= lane < 1 << 64:
            raise ValueError("sha3_air_lane_not_u64")
        result.extend(lane.to_bytes(8, "little"))
    return tuple(result)


def _bytes_to_lanes(values: Sequence[int]) -> tuple[int, ...]:
    if len(values) != STATE_BYTES:
        raise ValueError("sha3_air_state_byte_count_invalid")
    canonical = bytes(_byte("state", value) for value in values)
    return tuple(
        int.from_bytes(canonical[offset : offset + 8], "little")
        for offset in range(0, STATE_BYTES, 8)
    )


def _lane(values: Sequence[int], x: int, y: int) -> tuple[int, ...]:
    offset = 8 * (x + 5 * y)
    return tuple(values[offset : offset + 8])


def _five_lane(values: Sequence[int], x: int) -> tuple[int, ...]:
    if len(values) != 40 or not 0 <= x < 5:
        raise ValueError("sha3_air_five_lane_input_invalid")
    return tuple(values[8 * x : 8 * (x + 1)])


def _store_lane(target: list[int], x: int, y: int, lane: Sequence[int]) -> None:
    if len(lane) != 8:
        raise ValueError("sha3_air_lane_byte_count_invalid")
    offset = 8 * (x + 5 * y)
    target[offset : offset + 8] = [_byte("lane", value) for value in lane]


def _rotate_lane_bytes(
    lane: Sequence[int], rotation: int
) -> tuple[tuple[int, ...], tuple[tuple[int, int], ...]]:
    if len(lane) != 8 or type(rotation) is not int or not 0 <= rotation < 64:
        raise ValueError("sha3_air_rotation_input_invalid")
    source = tuple(_byte("rotation_source", value) for value in lane)
    byte_shift, bit_shift = divmod(rotation, 8)
    if bit_shift == 0:
        return (
            tuple(source[(index - byte_shift) % 8] for index in range(8)),
            (),
        )
    splits = tuple(_split8(value, bit_shift) for value in source)
    rotated = []
    for destination in range(8):
        source_index = (destination - byte_shift) % 8
        previous_index = (source_index - 1) % 8
        low = splits[source_index][0]
        high = splits[previous_index][1]
        rotated.append((low << bit_shift) + high)
    return tuple(rotated), splits


@dataclass(frozen=True, slots=True)
class Sha3ByteAirShape:
    state_bytes: int = STATE_BYTES
    rate_bytes: int = RATE_BYTES
    capacity_bytes: int = CAPACITY_BYTES
    permutation_rounds: int = KECCAK_ROUNDS
    core_round_base_columns: int = CORE_ROUND_BASE_COLUMNS
    sponge_block_columns: int = SPONGE_BLOCK_COLUMNS
    trace_base_columns: int = TRACE_BASE_COLUMNS
    core_round_lookup_messages: int = CORE_ROUND_LOOKUP_MESSAGES
    absorb_xor_lookups: int = ABSORB_XOR_LOOKUPS
    first_round_lookup_messages: int = FIRST_ROUND_LOOKUP_MESSAGES
    round_xor_lookups: int = ROUND_XOR_LOOKUPS
    round_and_not_lookups: int = ROUND_AND_NOT_LOOKUPS
    round_split_lookups: int = ROUND_SPLIT_LOOKUPS
    direct_maximum_degree: int = DIRECT_MAXIMUM_DEGREE
    composed_maximum_degree: int = COMPOSED_MAXIMUM_DEGREE
    status: str = SHA3_BYTE_AIR_STATUS
    proof_suite_id: None = None
    activation_allowed: bool = False
    interaction_packing_selected: bool = False

    def __post_init__(self) -> None:
        observed_shape = (
            self.state_bytes,
            self.rate_bytes,
            self.capacity_bytes,
            self.permutation_rounds,
            self.core_round_base_columns,
            self.sponge_block_columns,
            self.trace_base_columns,
            self.core_round_lookup_messages,
            self.absorb_xor_lookups,
            self.first_round_lookup_messages,
            self.round_xor_lookups,
            self.round_and_not_lookups,
            self.round_split_lookups,
            self.direct_maximum_degree,
            self.composed_maximum_degree,
        )
        expected_shape = (
            STATE_BYTES,
            RATE_BYTES,
            CAPACITY_BYTES,
            KECCAK_ROUNDS,
            CORE_ROUND_BASE_COLUMNS,
            SPONGE_BLOCK_COLUMNS,
            TRACE_BASE_COLUMNS,
            CORE_ROUND_LOOKUP_MESSAGES,
            ABSORB_XOR_LOOKUPS,
            FIRST_ROUND_LOOKUP_MESSAGES,
            ROUND_XOR_LOOKUPS,
            ROUND_AND_NOT_LOOKUPS,
            ROUND_SPLIT_LOOKUPS,
            DIRECT_MAXIMUM_DEGREE,
            COMPOSED_MAXIMUM_DEGREE,
        )
        if observed_shape != expected_shape:
            raise ValueError("sha3_air_exact_shape_mismatch")
        if (
            self.status != SHA3_BYTE_AIR_STATUS
            or self.proof_suite_id is not None
            or self.activation_allowed
            or self.interaction_packing_selected
        ):
            raise ValueError("sha3_air_nonactivating_boundary_violated")

    @property
    def canonical_bytes(self) -> bytes:
        chunks = [
            SHA3_BYTE_AIR_DOMAIN,
            self.state_bytes.to_bytes(2, "big"),
            self.rate_bytes.to_bytes(2, "big"),
            self.capacity_bytes.to_bytes(2, "big"),
            self.permutation_rounds.to_bytes(2, "big"),
            self.core_round_base_columns.to_bytes(4, "big"),
            self.sponge_block_columns.to_bytes(4, "big"),
            self.trace_base_columns.to_bytes(4, "big"),
            self.core_round_lookup_messages.to_bytes(4, "big"),
            self.absorb_xor_lookups.to_bytes(4, "big"),
            self.first_round_lookup_messages.to_bytes(4, "big"),
            self.round_xor_lookups.to_bytes(4, "big"),
            self.round_and_not_lookups.to_bytes(4, "big"),
            self.round_split_lookups.to_bytes(4, "big"),
            self.direct_maximum_degree.to_bytes(2, "big"),
            self.composed_maximum_degree.to_bytes(2, "big"),
            bytes((self.activation_allowed, self.interaction_packing_selected)),
        ]
        chunks.extend(value.to_bytes(8, "big") for value in _ROUND_CONSTANTS)
        chunks.extend(bytes(row) for row in _ROTATION_OFFSETS)
        return b"".join(chunks)

    @property
    def commitment_sha3_512(self) -> bytes:
        return sha3_512(self.canonical_bytes).digest()


@dataclass(frozen=True, slots=True)
class KeccakRoundWitness:
    round_index: int
    state_bytes: tuple[int, ...]
    theta_parity_steps: tuple[int, ...]
    theta_d: tuple[int, ...]
    theta_state: tuple[int, ...]
    rotation_splits: tuple[tuple[int, int], ...]
    chi_and_not: tuple[int, ...]
    chi_raw: tuple[int, ...]
    output_bytes: tuple[int, ...]

    def __post_init__(self) -> None:
        if type(self.round_index) is not int or not 0 <= self.round_index < KECCAK_ROUNDS:
            raise ValueError("sha3_air_round_index_invalid")
        _byte_tuple("state", self.state_bytes, 200)
        _byte_tuple("theta_parity", self.theta_parity_steps, 160)
        _byte_tuple("theta_d", self.theta_d, 40)
        _byte_tuple("theta_state", self.theta_state, 200)
        if not isinstance(self.rotation_splits, tuple) or len(self.rotation_splits) != 216:
            raise ValueError("sha3_air_rotation_split_count_invalid")
        for split in self.rotation_splits:
            if not isinstance(split, tuple) or len(split) != 2:
                raise ValueError("sha3_air_rotation_split_shape_invalid")
            _byte("rotation_split_low", split[0])
            _byte("rotation_split_high", split[1])
        _byte_tuple("chi_and_not", self.chi_and_not, 200)
        _byte_tuple("chi_raw", self.chi_raw, 200)
        _byte_tuple("output", self.output_bytes, 200)


@dataclass(frozen=True, slots=True)
class Sha3ByteAirTrace:
    message_length: int
    padded_blocks: tuple[bytes, ...]
    rounds: tuple[tuple[KeccakRoundWitness, ...], ...]
    digest: bytes
    status: str = SHA3_BYTE_AIR_STATUS
    proof_suite_id: None = None
    activation_allowed: bool = False

    def __post_init__(self) -> None:
        if type(self.message_length) is not int or self.message_length < 0:
            raise ValueError("sha3_air_message_length_invalid")
        if not self.padded_blocks or any(
            type(block) is not bytes or len(block) != RATE_BYTES
            for block in self.padded_blocks
        ):
            raise ValueError("sha3_air_padded_blocks_invalid")
        if len(self.rounds) != len(self.padded_blocks) or any(
            len(block_rounds) != KECCAK_ROUNDS for block_rounds in self.rounds
        ):
            raise ValueError("sha3_air_trace_round_shape_invalid")
        if type(self.digest) is not bytes or len(self.digest) != 64:
            raise ValueError("sha3_air_digest_length_invalid")
        if (
            self.status != SHA3_BYTE_AIR_STATUS
            or self.proof_suite_id is not None
            or self.activation_allowed
        ):
            raise ValueError("sha3_air_trace_nonactivating_boundary_violated")


def padded_block_count(message_length: int) -> int:
    if type(message_length) is not int or message_length < 0:
        raise ValueError("sha3_air_message_length_invalid")
    return (message_length + RATE_BYTES) // RATE_BYTES


def _pad_message(message: bytes) -> tuple[bytes, ...]:
    if type(message) is not bytes:
        raise TypeError("sha3_air_message_must_be_exact_bytes")
    padded = bytearray(message)
    padded.append(0x06)
    padded.extend(b"\x00" * ((-len(padded)) % RATE_BYTES))
    padded[-1] ^= 0x80
    return tuple(
        bytes(padded[offset : offset + RATE_BYTES])
        for offset in range(0, len(padded), RATE_BYTES)
    )


def _build_round(state: Sequence[int], round_index: int) -> KeccakRoundWitness:
    state_values = tuple(_byte("state", value) for value in state)
    if len(state_values) != STATE_BYTES:
        raise ValueError("sha3_air_state_byte_count_invalid")
    if type(round_index) is not int or not 0 <= round_index < KECCAK_ROUNDS:
        raise ValueError("sha3_air_round_index_invalid")

    parity_steps: list[int] = []
    c_lanes: list[tuple[int, ...]] = []
    for x in range(5):
        c_lane = []
        for byte_index in range(8):
            values = [_lane(state_values, x, y)[byte_index] for y in range(5)]
            accumulator = values[0]
            for value in values[1:]:
                accumulator = _xor8(accumulator, value)
                parity_steps.append(accumulator)
            c_lane.append(accumulator)
        c_lanes.append(tuple(c_lane))

    rotation_splits: list[tuple[int, int]] = []
    rotated_c: list[tuple[int, ...]] = []
    for lane in c_lanes:
        rotated, splits = _rotate_lane_bytes(lane, 1)
        rotated_c.append(rotated)
        rotation_splits.extend(splits)

    d_lanes = tuple(
        tuple(
            _xor8(c_lanes[(x - 1) % 5][byte_index], rotated_c[(x + 1) % 5][byte_index])
            for byte_index in range(8)
        )
        for x in range(5)
    )
    theta_d = tuple(value for lane in d_lanes for value in lane)

    theta_state = [0] * STATE_BYTES
    for x in range(5):
        for y in range(5):
            _store_lane(
                theta_state,
                x,
                y,
                tuple(
                    _xor8(value, d_lanes[x][byte_index])
                    for byte_index, value in enumerate(_lane(state_values, x, y))
                ),
            )

    b_state = [0] * STATE_BYTES
    for x in range(5):
        for y in range(5):
            rotated, splits = _rotate_lane_bytes(
                _lane(theta_state, x, y), _ROTATION_OFFSETS[x][y]
            )
            rotation_splits.extend(splits)
            _store_lane(b_state, y, (2 * x + 3 * y) % 5, rotated)

    chi_and_not = [0] * STATE_BYTES
    chi_raw = [0] * STATE_BYTES
    for x in range(5):
        for y in range(5):
            current = _lane(b_state, x, y)
            next_lane = _lane(b_state, (x + 1) % 5, y)
            next_next = _lane(b_state, (x + 2) % 5, y)
            and_lane = tuple(
                _and_not8(left, right)
                for left, right in zip(next_lane, next_next, strict=True)
            )
            raw_lane = tuple(
                _xor8(left, right)
                for left, right in zip(current, and_lane, strict=True)
            )
            _store_lane(chi_and_not, x, y, and_lane)
            _store_lane(chi_raw, x, y, raw_lane)

    output = list(chi_raw)
    round_constant = _ROUND_CONSTANTS[round_index].to_bytes(8, "little")
    _store_lane(
        output,
        0,
        0,
        tuple(
            _xor8(value, constant)
            for value, constant in zip(_lane(chi_raw, 0, 0), round_constant, strict=True)
        ),
    )
    witness = KeccakRoundWitness(
        round_index=round_index,
        state_bytes=state_values,
        theta_parity_steps=tuple(parity_steps),
        theta_d=theta_d,
        theta_state=tuple(theta_state),
        rotation_splits=tuple(rotation_splits),
        chi_and_not=tuple(chi_and_not),
        chi_raw=tuple(chi_raw),
        output_bytes=tuple(output),
    )
    if len(witness.rotation_splits) != ROUND_SPLIT_LOOKUPS:
        raise AssertionError("sha3_air_internal_split_inventory_mismatch")
    return witness


def verify_round_witness(witness: KeccakRoundWitness) -> None:
    if type(witness) is not KeccakRoundWitness:
        raise TypeError("sha3_air_round_witness_required")
    expected = _build_round(witness.state_bytes, witness.round_index)
    if witness != expected:
        raise ValueError("sha3_air_round_witness_constraint_mismatch")


def round_lookup_rows(
    witness: KeccakRoundWitness,
) -> tuple[tuple[str, int, int, int], ...]:
    """Return the exact 1,024 fixed-table lookup messages for one round."""

    verify_round_witness(witness)
    expected = _build_round(witness.state_bytes, witness.round_index)
    rows: list[tuple[str, int, int, int]] = []

    # Rebuild operation rows in canonical witness order.  The verifier above
    # makes this an auditable inventory function rather than a second prover.
    state = expected.state_bytes
    parity_index = 0
    c_lanes: list[tuple[int, ...]] = []
    for x in range(5):
        c_lane = []
        for byte_index in range(8):
            values = [_lane(state, x, y)[byte_index] for y in range(5)]
            accumulator = values[0]
            for value in values[1:]:
                output = expected.theta_parity_steps[parity_index]
                rows.append(("XOR8", accumulator, value, output))
                accumulator = output
                parity_index += 1
            c_lane.append(accumulator)
        c_lanes.append(tuple(c_lane))

    split_index = 0
    rotated_c = []
    for lane in c_lanes:
        rotated, _ = _rotate_lane_bytes(lane, 1)
        rotated_c.append(rotated)
        for value in lane:
            low, high = expected.rotation_splits[split_index]
            rows.append(("SPLIT8_1", value, low, high))
            split_index += 1
    for x in range(5):
        for byte_index in range(8):
            rows.append(
                (
                    "XOR8",
                    c_lanes[(x - 1) % 5][byte_index],
                    rotated_c[(x + 1) % 5][byte_index],
                    _five_lane(expected.theta_d, x)[byte_index],
                )
            )
    for x in range(5):
        for y in range(5):
            for byte_index, value in enumerate(_lane(state, x, y)):
                rows.append(
                    (
                        "XOR8",
                        value,
                        _five_lane(expected.theta_d, x)[byte_index],
                        _lane(expected.theta_state, x, y)[byte_index],
                    )
                )

    b_state = [0] * STATE_BYTES
    for x in range(5):
        for y in range(5):
            source = _lane(expected.theta_state, x, y)
            rotation = _ROTATION_OFFSETS[x][y]
            rotated, _ = _rotate_lane_bytes(source, rotation)
            bit_shift = rotation % 8
            if bit_shift:
                for value in source:
                    low, high = expected.rotation_splits[split_index]
                    rows.append((f"SPLIT8_{bit_shift}", value, low, high))
                    split_index += 1
            _store_lane(b_state, y, (2 * x + 3 * y) % 5, rotated)

    for x in range(5):
        for y in range(5):
            current = _lane(b_state, x, y)
            next_lane = _lane(b_state, (x + 1) % 5, y)
            next_next = _lane(b_state, (x + 2) % 5, y)
            and_lane = _lane(expected.chi_and_not, x, y)
            raw_lane = _lane(expected.chi_raw, x, y)
            for index in range(8):
                rows.append(
                    (
                        "AND_NOT8",
                        next_lane[index],
                        next_next[index],
                        and_lane[index],
                    )
                )
                rows.append(("XOR8", current[index], and_lane[index], raw_lane[index]))

    round_constant = _ROUND_CONSTANTS[witness.round_index].to_bytes(8, "little")
    for index in range(8):
        rows.append(
            (
                "XOR8",
                _lane(expected.chi_raw, 0, 0)[index],
                round_constant[index],
                _lane(expected.output_bytes, 0, 0)[index],
            )
        )
    if split_index != ROUND_SPLIT_LOOKUPS:
        raise AssertionError("sha3_air_split_lookup_inventory_mismatch")
    if len(rows) != CORE_ROUND_LOOKUP_MESSAGES:
        raise AssertionError("sha3_air_lookup_inventory_mismatch")
    return tuple(rows)


def block_absorb_lookup_rows(
    prior_state: Sequence[int], block: bytes
) -> tuple[tuple[str, int, int, int], ...]:
    """Return the exact 72 XOR8 rows linking one rate block into the state."""

    prior = tuple(_byte("absorb_state", value) for value in prior_state)
    if len(prior) != STATE_BYTES:
        raise ValueError("sha3_air_absorb_state_length_invalid")
    if type(block) is not bytes or len(block) != RATE_BYTES:
        raise ValueError("sha3_air_absorb_block_length_invalid")
    rows = tuple(
        ("XOR8", prior[index], value, _xor8(prior[index], value))
        for index, value in enumerate(block)
    )
    if len(rows) != ABSORB_XOR_LOOKUPS:
        raise AssertionError("sha3_air_absorb_lookup_inventory_mismatch")
    return rows


def build_sha3_512_air_trace(message: bytes) -> Sha3ByteAirTrace:
    blocks = _pad_message(message)
    state = bytearray(STATE_BYTES)
    all_rounds: list[tuple[KeccakRoundWitness, ...]] = []
    for block in blocks:
        for index, value in enumerate(block):
            state[index] ^= value
        block_rounds = []
        for round_index in range(KECCAK_ROUNDS):
            witness = _build_round(state, round_index)
            block_rounds.append(witness)
            state[:] = bytes(witness.output_bytes)
        all_rounds.append(tuple(block_rounds))
    return Sha3ByteAirTrace(
        message_length=len(message),
        padded_blocks=blocks,
        rounds=tuple(all_rounds),
        digest=bytes(state[:64]),
    )


def verify_sha3_512_air_trace(message: bytes, trace: Sha3ByteAirTrace) -> None:
    if type(message) is not bytes or type(trace) is not Sha3ByteAirTrace:
        raise TypeError("sha3_air_exact_message_and_trace_required")
    expected_blocks = _pad_message(message)
    if trace.message_length != len(message) or trace.padded_blocks != expected_blocks:
        raise ValueError("sha3_air_message_or_padding_mismatch")
    state = bytearray(STATE_BYTES)
    for block, block_rounds in zip(trace.padded_blocks, trace.rounds, strict=True):
        for index, value in enumerate(block):
            state[index] ^= value
        for round_index, witness in enumerate(block_rounds):
            if witness.round_index != round_index or witness.state_bytes != tuple(state):
                raise ValueError("sha3_air_round_chain_mismatch")
            verify_round_witness(witness)
            state[:] = bytes(witness.output_bytes)
    if trace.digest != bytes(state[:64]):
        raise ValueError("sha3_air_digest_trace_mismatch")
    if trace.digest != sha3_512(message).digest():
        raise ValueError("sha3_air_hashlib_differential_mismatch")


__all__ = [
    "CAPACITY_BYTES",
    "COMPOSED_MAXIMUM_DEGREE",
    "DIRECT_MAXIMUM_DEGREE",
    "KECCAK_ROUNDS",
    "RATE_BYTES",
    "ABSORB_XOR_LOOKUPS",
    "CORE_ROUND_BASE_COLUMNS",
    "CORE_ROUND_LOOKUP_MESSAGES",
    "FIRST_ROUND_LOOKUP_MESSAGES",
    "SHA3_BYTE_AIR_STATUS",
    "STATE_BYTES",
    "SPONGE_BLOCK_COLUMNS",
    "TRACE_BASE_COLUMNS",
    "KeccakRoundWitness",
    "Sha3ByteAirShape",
    "Sha3ByteAirTrace",
    "build_sha3_512_air_trace",
    "block_absorb_lookup_rows",
    "padded_block_count",
    "round_lookup_rows",
    "verify_round_witness",
    "verify_sha3_512_air_trace",
]
