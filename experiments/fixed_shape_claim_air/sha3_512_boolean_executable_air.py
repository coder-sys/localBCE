"""Degree-16 direct-boolean Keccak-f AIR without wide lookup interactions.

The historical byte AIR allocated one LogUp accumulator for each unrolled
truth-table port.  At the complete K128 schedule that interaction alone is a
multi-terabyte oracle.  This sibling expresses Keccak directly over canonical
boolean M31 cells.  Five-lane theta parities are explicit witness columns;
rho/pi is wiring; chi and iota remain degree at most ten before the fixed row
selector.  No bitwise truth-table lookup or interaction column is required.

This module currently owns the permutation core.  Sponge absorption and the
global application links are separate tables so they do not widen every round.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Mapping, Sequence

from experiments.bl_pq512_crypto_foundation.sha3_512_air_reference import (
    KECCAK_ROUNDS,
    RATE_BYTES,
    STATE_BYTES,
    _ROTATION_OFFSETS,
    _ROUND_CONSTANTS,
    _build_round,
    _pad_message,
    padded_block_count,
)

from .executable_air import (
    AirProgram,
    AirTable,
    FixedColumnPeriodic,
    FixedColumnRuns,
    Identity,
    LookupArgument,
    LookupSide,
    TraceTable,
    cell,
    const,
    freeze_columns,
)
from .semantics import StructuralError


PROGRAM_ID: Final[str] = "BL-WAVE1A-SHA3-512-BOOLEAN-PERMUTATION-AIR-v1"
STATE_BITS: Final[int] = 1_600
PARITY_BITS: Final[int] = 320
ROWS_PER_PERMUTATION: Final[int] = KECCAK_ROUNDS + 1
MAXIMUM_DEGREE: Final[int] = 11


def _xor(left, right):
    return left + right - 2 * left * right


def _xor_many(values: Sequence):
    if not values:
        raise StructuralError("sha3_boolean_xor_values_required")
    result = values[0]
    for value in values[1:]:
        result = _xor(result, value)
    return result


def _balanced_sum(values: Sequence):
    level = list(values)
    if not level:
        return const(0)
    while len(level) > 1:
        level = [
            level[index] + level[index + 1]
            if index + 1 < len(level)
            else level[index]
            for index in range(0, len(level), 2)
        ]
    return level[0]


def _state_index(x: int, y: int, z: int) -> int:
    return 64 * (x + 5 * y) + z


def _parity_index(x: int, z: int) -> int:
    return 64 * x + z


def _state(x: int, y: int, z: int, shift: int = 0):
    return cell(f"state_{_state_index(x, y, z)}", shift)


def _parity(x: int, z: int):
    return cell(f"parity_{_parity_index(x, z)}")


def _theta(x: int, y: int, z: int):
    d = _xor(_parity((x - 1) % 5, z), _parity((x + 1) % 5, (z - 1) % 64))
    return _xor(_state(x, y, z), d)


def _b(x: int, y: int, z: int):
    source_y = x
    source_x = (3 * (y - 3 * source_y)) % 5
    rotation = _ROTATION_OFFSETS[source_x][source_y]
    return _theta(source_x, source_y, (z - rotation) % 64)


def _round_output(x: int, y: int, z: int):
    current = _b(x, y, z)
    and_not = (1 - _b((x + 1) % 5, y, z)) * _b((x + 2) % 5, y, z)
    chi = _xor(current, and_not)
    return _xor(chi, cell(f"round_constant_{z}")) if x == 0 and y == 0 else chi


def _bits_from_state_bytes(state: bytes) -> tuple[int, ...]:
    if type(state) is not bytes or len(state) != STATE_BYTES:
        raise StructuralError("sha3_boolean_state_invalid")
    return tuple((state[index // 8] >> (index % 8)) & 1 for index in range(STATE_BITS))


def _parities(bits: Sequence[int]) -> tuple[int, ...]:
    if len(bits) != STATE_BITS:
        raise StructuralError("sha3_boolean_state_bits_invalid")
    return tuple(
        bits[_state_index(x, 0, z)]
        ^ bits[_state_index(x, 1, z)]
        ^ bits[_state_index(x, 2, z)]
        ^ bits[_state_index(x, 3, z)]
        ^ bits[_state_index(x, 4, z)]
        for x in range(5)
        for z in range(64)
    )


def _coalesced_runs(values: Sequence[tuple[int, int]]) -> tuple[tuple[int, int], ...]:
    runs: list[tuple[int, int]] = []
    for value, count in values:
        if runs and runs[-1][0] == value:
            runs[-1] = (value, runs[-1][1] + count)
        else:
            runs.append((value, count))
    return tuple(runs)


def _permutation_geometry(
    call_block_counts: Sequence[int],
) -> tuple[tuple[int, int, bool], ...]:
    counts = tuple(call_block_counts)
    if (
        not counts
        or any(type(count) is not int or count <= 0 for count in counts)
        or sum(counts) > 0xFFFF_FFFF
    ):
        raise StructuralError("sha3_boolean_call_block_counts_invalid")
    return tuple(
        (call_index, block_index, block_index + 1 == block_count)
        for call_index, block_count in enumerate(counts)
        for block_index in range(block_count)
    )


def _build_permutation_program(call_block_counts: Sequence[int]) -> AirProgram:
    geometry = _permutation_geometry(call_block_counts)
    permutation_count = len(geometry)
    rows = permutation_count * ROWS_PER_PERMUTATION
    state_columns = tuple(f"state_{index}" for index in range(STATE_BITS))
    parity_columns = tuple(f"parity_{index}" for index in range(PARITY_BITS))
    control_columns = (
        "permutation_index",
        "call_index",
        "block_index",
        "round_index",
        "is_round",
        "is_first_round",
        "is_final",
        "block_active",
        "actual_last",
        "link_next_block",
        "is_call_final",
        *(f"round_constant_{z}" for z in range(64)),
    )
    identities = tuple(
        Identity(
            f"state_boolean_{index}",
            cell(name) * (cell(name) - 1),
            0,
            rows,
            "local",
        )
        for index, name in enumerate(state_columns)
    )
    identities += tuple(
        Identity(
            f"theta_parity_{index}",
            cell("is_round")
            * (
                cell(name)
                - _xor_many(tuple(_state(x, y, z) for y in range(5)))
            ),
            0,
            rows,
            "local",
        )
        for x in range(5)
        for z in range(64)
        for index, name in ((_parity_index(x, z), f"parity_{_parity_index(x, z)}"),)
    )
    for name in ("block_active", "actual_last"):
        identities += (
            Identity(
                f"{name}_boolean",
                cell(name) * (cell(name) - 1),
                0,
                rows,
                "local",
            ),
            Identity(
                f"{name}_within_permutation",
                cell("is_round") * (cell(name, 1) - cell(name)),
                0,
                rows - 1,
                "transition",
            ),
        )
    identities += (
        Identity(
            "actual_last_requires_active",
            cell("actual_last") * (1 - cell("block_active")),
            0,
            rows,
            "local",
        ),
        Identity(
            "link_next_block_derived",
            cell("link_next_block")
            - cell("is_final") * cell("block_active") * (1 - cell("actual_last")),
            0,
            rows,
            "local",
        ),
        Identity(
            "is_call_final_derived",
            cell("is_call_final") - cell("is_final") * cell("actual_last"),
            0,
            rows,
            "local",
        ),
    )
    identities += tuple(
        Identity(
            f"round_transition_{index}",
            cell("is_round") * (_state(x, y, z, 1) - _round_output(x, y, z)),
            0,
            rows - 1,
            "transition",
        )
        for x in range(5)
        for y in range(5)
        for z in range(64)
        for index in (_state_index(x, y, z),)
    )
    rc_patterns = tuple(
        tuple(
            ((_ROUND_CONSTANTS[round_index] >> z) & 1)
            if round_index < KECCAK_ROUNDS
            else 0
            for round_index in range(ROWS_PER_PERMUTATION)
        )
        for z in range(64)
    )
    fixed = {
        "permutation_index": FixedColumnRuns(
            tuple((index, ROWS_PER_PERMUTATION) for index in range(permutation_count))
        ),
        "call_index": FixedColumnRuns(
            tuple(
                (call_index, block_count * ROWS_PER_PERMUTATION)
                for call_index, block_count in enumerate(call_block_counts)
            )
        ),
        "block_index": FixedColumnRuns(
            _coalesced_runs(
                tuple(
                    (block_index, ROWS_PER_PERMUTATION)
                    for _, block_index, _ in geometry
                )
            )
        ),
        "round_index": FixedColumnPeriodic(tuple(range(KECCAK_ROUNDS)) + (0,), rows),
        "is_round": FixedColumnPeriodic((1,) * KECCAK_ROUNDS + (0,), rows),
        "is_first_round": FixedColumnPeriodic((1,) + (0,) * KECCAK_ROUNDS, rows),
        "is_final": FixedColumnPeriodic((0,) * KECCAK_ROUNDS + (1,), rows),
        **{
            f"round_constant_{z}": FixedColumnPeriodic(rc_patterns[z], rows)
            for z in range(64)
        },
    }
    table = AirTable(
        "sha3_boolean_round",
        state_columns + parity_columns + control_columns,
        rows,
        identities,
        fixed,
    )
    program = AirProgram(PROGRAM_ID, (table,), ())
    if program.maximum_degree != MAXIMUM_DEGREE:
        raise AssertionError("sha3_boolean_degree_inventory_mismatch")
    return program


def build_sha3_boolean_permutation_program(permutation_count: int) -> AirProgram:
    if type(permutation_count) is not int or permutation_count <= 0:
        raise StructuralError("sha3_boolean_permutation_count_invalid")
    return _build_permutation_program((1,) * permutation_count)


@dataclass(frozen=True, slots=True)
class Sha3BooleanPermutationAirInstance:
    program: AirProgram
    traces: Mapping[str, TraceTable]
    outputs: tuple[bytes, ...]


def _build_permutation_air(
    initial_states: Sequence[bytes],
    call_block_counts: Sequence[int],
    actual_block_counts: Sequence[int] | None = None,
) -> Sha3BooleanPermutationAirInstance:
    states = tuple(initial_states)
    geometry = _permutation_geometry(call_block_counts)
    actual_counts = (
        tuple(call_block_counts)
        if actual_block_counts is None
        else tuple(actual_block_counts)
    )
    if not states or len(states) != len(geometry):
        raise StructuralError("sha3_boolean_initial_states_required")
    if len(actual_counts) != len(call_block_counts) or any(
        type(actual) is not int or not 1 <= actual <= capacity
        for actual, capacity in zip(actual_counts, call_block_counts, strict=True)
    ):
        raise StructuralError("sha3_boolean_actual_block_counts_invalid")
    program = _build_permutation_program(call_block_counts)
    columns: dict[str, list[int]] = {
        name: [] for name in program.tables[0].columns
    }
    outputs: list[bytes] = []
    for permutation_index, (initial, item) in enumerate(zip(states, geometry, strict=True)):
        call_index, block_index, is_last = item
        block_active = int(block_index < actual_counts[call_index])
        actual_last = int(block_index + 1 == actual_counts[call_index])
        if type(initial) is not bytes or len(initial) != STATE_BYTES:
            raise StructuralError("sha3_boolean_state_invalid")
        state = tuple(initial)
        for round_index in range(KECCAK_ROUNDS):
            bits = _bits_from_state_bytes(bytes(state))
            parity = _parities(bits)
            for index, value in enumerate(bits):
                columns[f"state_{index}"].append(value)
            for index, value in enumerate(parity):
                columns[f"parity_{index}"].append(value)
            columns["permutation_index"].append(permutation_index)
            columns["call_index"].append(call_index)
            columns["block_index"].append(block_index)
            columns["round_index"].append(round_index)
            columns["is_round"].append(1)
            columns["is_first_round"].append(int(round_index == 0))
            columns["is_final"].append(0)
            columns["block_active"].append(block_active)
            columns["actual_last"].append(actual_last)
            columns["link_next_block"].append(0)
            columns["is_call_final"].append(0)
            for z in range(64):
                columns[f"round_constant_{z}"].append(
                    (_ROUND_CONSTANTS[round_index] >> z) & 1
                )
            state = _build_round(state, round_index).output_bytes
        output = bytes(state)
        outputs.append(output)
        bits = _bits_from_state_bytes(output)
        parity = _parities(bits)
        for index, value in enumerate(bits):
            columns[f"state_{index}"].append(value)
        for index, value in enumerate(parity):
            columns[f"parity_{index}"].append(value)
        columns["permutation_index"].append(permutation_index)
        columns["call_index"].append(call_index)
        columns["block_index"].append(block_index)
        columns["round_index"].append(0)
        columns["is_round"].append(0)
        columns["is_first_round"].append(0)
        columns["is_final"].append(1)
        columns["block_active"].append(block_active)
        columns["actual_last"].append(actual_last)
        columns["link_next_block"].append(int(block_active and not actual_last))
        columns["is_call_final"].append(actual_last)
        for z in range(64):
            columns[f"round_constant_{z}"].append(0)
    trace = TraceTable("sha3_boolean_round", freeze_columns(columns))
    return Sha3BooleanPermutationAirInstance(
        program,
        MappingProxyType({trace.name: trace}),
        tuple(outputs),
    )


def build_sha3_boolean_permutation_air(
    initial_states: Sequence[bytes],
) -> Sha3BooleanPermutationAirInstance:
    states = tuple(initial_states)
    return _build_permutation_air(states, (1,) * len(states))


@dataclass(frozen=True, slots=True)
class Sha3BooleanCall:
    call_id: str
    message: bytes
    capacity: int

    def __post_init__(self) -> None:
        if (
            type(self.call_id) is not str
            or not self.call_id
            or type(self.message) is not bytes
            or type(self.capacity) is not int
            or self.capacity < 0
            or len(self.message) > self.capacity
        ):
            raise StructuralError("sha3_boolean_fixed_call_invalid")


@dataclass(frozen=True, slots=True)
class Sha3BooleanAirInstance:
    program: AirProgram
    traces: Mapping[str, TraceTable]
    digests: Mapping[str, bytes]
    block_counts: tuple[int, ...]


def _absorb_table(capacities: Sequence[int]) -> AirTable:
    call_block_counts = tuple(padded_block_count(value) for value in capacities)
    geometry = _permutation_geometry(call_block_counts)
    rows = len(geometry)
    prior_columns = tuple(f"prior_{index}" for index in range(STATE_BITS))
    byte_columns = tuple(f"block_byte_{index}" for index in range(RATE_BYTES))
    bit_columns = tuple(f"block_bit_{index}" for index in range(RATE_BYTES * 8))
    live_columns = tuple(f"message_live_{index}" for index in range(RATE_BYTES))
    slack_columns = tuple(f"capacity_slack_{index}" for index in range(7))
    controls = (
        "permutation_index",
        "call_index",
        "block_index",
        "is_first_block",
        "is_capacity_last",
        "same_call_next",
        "block_active",
        "actual_last",
        "link_prior",
        "capacity_remaining",
    )
    identities = tuple(
        Identity(
            f"first_prior_zero_{index}",
            (
                cell("is_first_block")
                + (1 - cell("block_active"))
                - cell("is_first_block") * (1 - cell("block_active"))
            )
            * cell(name),
            0,
            rows,
            "local",
        )
        for index, name in enumerate(prior_columns)
    )
    identities += tuple(
        Identity(
            f"block_bit_boolean_{index}",
            cell(name) * (cell(name) - 1),
            0,
            rows,
            "local",
        )
        for index, name in enumerate(bit_columns)
    )
    identities += tuple(
        Identity(
            f"message_live_boolean_{index}",
            cell(name) * (cell(name) - 1),
            0,
            rows,
            "local",
        )
        for index, name in enumerate(live_columns)
    )
    identities += tuple(
        Identity(
            f"capacity_slack_boolean_{index}",
            cell(name) * (cell(name) - 1),
            0,
            rows,
            "local",
        )
        for index, name in enumerate(slack_columns)
    )
    identities += (
        Identity(
            "message_within_capacity",
            _balanced_sum(tuple(cell(name) for name in live_columns))
            + _balanced_sum(
                tuple((1 << index) * cell(name) for index, name in enumerate(slack_columns))
            )
            - cell("capacity_remaining"),
            0,
            rows,
            "local",
        ),
    )
    identities += tuple(
        Identity(
            f"message_live_prefix_{index}",
            cell(live_columns[index + 1]) * (1 - cell(live_columns[index])),
            0,
            rows,
            "local",
        )
        for index in range(RATE_BYTES - 1)
    )
    pad_expressions = (cell("actual_last") * (1 - cell(live_columns[0])),) + tuple(
        cell(live_columns[index - 1]) * (1 - cell(live_columns[index]))
        for index in range(1, RATE_BYTES)
    )
    identities += tuple(
        Identity(
            f"padded_block_byte_{index}",
            cell(byte_columns[index])
            - cell(live_columns[index]) * cell(byte_columns[index])
            - 6 * pad_expressions[index]
            - (128 * cell("actual_last") if index == RATE_BYTES - 1 else 0),
            0,
            rows,
            "local",
        )
        for index in range(RATE_BYTES)
    )
    identities += (
        Identity(
            "block_active_boolean",
            cell("block_active") * (cell("block_active") - 1),
            0,
            rows,
            "local",
        ),
        Identity(
            "actual_last_boolean",
            cell("actual_last") * (cell("actual_last") - 1),
            0,
            rows,
            "local",
        ),
        Identity(
            "actual_last_requires_active",
            cell("actual_last") * (1 - cell("block_active")),
            0,
            rows,
            "local",
        ),
        Identity(
            "link_prior_derived",
            cell("link_prior")
            - cell("block_active") * (1 - cell("is_first_block")),
            0,
            rows,
            "local",
        ),
        Identity(
            "block_active_derived",
            cell("block_active")
            - (
                cell(live_columns[0])
                + cell("actual_last")
                - cell(live_columns[0]) * cell("actual_last")
            ),
            0,
            rows,
            "local",
        ),
        Identity(
            "unique_padding_byte",
            _balanced_sum(pad_expressions) - cell("actual_last"),
            0,
            rows,
            "local",
        ),
        Identity(
            "first_block_active",
            cell("is_first_block") * (cell("block_active") - 1),
            0,
            rows,
            "local",
        ),
        Identity(
            "active_block_prefix",
            cell("same_call_next")
            * (cell("block_active", 1) - cell("block_active") + cell("actual_last")),
            0,
            rows - 1,
            "transition",
        ),
        Identity(
            "capacity_terminal_closes_message",
            cell("is_capacity_last") * (cell("block_active") - cell("actual_last")),
            0,
            rows,
            "local",
        ),
    )
    identities += tuple(
        Identity(
            f"block_byte_pack_{byte_index}",
            cell(f"block_byte_{byte_index}")
            - sum(
                (1 << bit) * cell(f"block_bit_{8 * byte_index + bit}")
                for bit in range(8)
            ),
            0,
            rows,
            "local",
        )
        for byte_index in range(RATE_BYTES)
    )
    fixed = {
        "permutation_index": FixedColumnRuns(
            tuple((index, 1) for index in range(rows))
        ),
        "call_index": FixedColumnRuns(
            tuple((index, count) for index, count in enumerate(call_block_counts))
        ),
        "block_index": FixedColumnRuns(
            _coalesced_runs(tuple((block_index, 1) for _, block_index, _ in geometry))
        ),
        "is_first_block": FixedColumnRuns(
            _coalesced_runs(
                tuple((int(block_index == 0), 1) for _, block_index, _ in geometry)
            )
        ),
        "is_capacity_last": FixedColumnRuns(
            _coalesced_runs(
                tuple((int(is_last), 1) for _, _, is_last in geometry)
            )
        ),
        "same_call_next": FixedColumnRuns(
            _coalesced_runs(
                tuple((int(not is_last), 1) for _, _, is_last in geometry)
            )
        ),
        "capacity_remaining": FixedColumnRuns(
            _coalesced_runs(
                tuple(
                    (
                        min(
                            RATE_BYTES,
                            max(0, capacities[call_index] - block_index * RATE_BYTES),
                        ),
                        1,
                    )
                    for call_index, block_index, _ in geometry
                )
            )
        ),
    }
    return AirTable(
        "sha3_boolean_absorb",
        prior_columns
        + byte_columns
        + bit_columns
        + live_columns
        + slack_columns
        + controls,
        rows,
        identities,
        fixed,
    )


def _digest_table(call_count: int) -> AirTable:
    byte_columns = tuple(f"digest_byte_{index}" for index in range(64))
    bit_columns = tuple(f"digest_bit_{index}" for index in range(512))
    identities = tuple(
        Identity(
            f"digest_bit_boolean_{index}",
            cell(name) * (cell(name) - 1),
            0,
            call_count,
            "local",
        )
        for index, name in enumerate(bit_columns)
    )
    identities += tuple(
        Identity(
            f"digest_byte_pack_{byte_index}",
            cell(f"digest_byte_{byte_index}")
            - sum(
                (1 << bit) * cell(f"digest_bit_{8 * byte_index + bit}")
                for bit in range(8)
            ),
            0,
            call_count,
            "local",
        )
        for byte_index in range(64)
    )
    return AirTable(
        "sha3_boolean_digest",
        ("call_index",) + byte_columns + bit_columns,
        call_count,
        identities,
        {"call_index": FixedColumnRuns(tuple((index, 1) for index in range(call_count)))},
    )


def _sponge_lookups(round_rows: int, absorb_rows: int, digest_rows: int) -> tuple[LookupArgument, ...]:
    absorbed = tuple(
        _xor(cell(f"prior_{index}"), cell(f"block_bit_{index}"))
        if index < RATE_BYTES * 8
        else cell(f"prior_{index}")
        for index in range(STATE_BITS)
    )
    return (
        LookupArgument(
            "sha3_boolean_absorb_to_round",
            (
                LookupSide(
                    "sha3_boolean_absorb",
                    const(1),
                    (
                        cell("permutation_index"),
                        cell("block_active"),
                        cell("actual_last"),
                    )
                    + absorbed,
                    0,
                    absorb_rows,
                ),
            ),
            (
                LookupSide(
                    "sha3_boolean_round",
                    cell("is_first_round"),
                    (
                        cell("permutation_index"),
                        cell("block_active"),
                        cell("actual_last"),
                    )
                    + tuple(cell(f"state_{index}") for index in range(STATE_BITS)),
                    0,
                    round_rows,
                ),
            ),
        ),
        LookupArgument(
            "sha3_boolean_round_to_next_absorb",
            (
                LookupSide(
                    "sha3_boolean_round",
                    cell("link_next_block"),
                    (cell("call_index"), cell("block_index") + 1)
                    + tuple(cell(f"state_{index}") for index in range(STATE_BITS)),
                    0,
                    round_rows,
                ),
            ),
            (
                LookupSide(
                    "sha3_boolean_absorb",
                    cell("link_prior"),
                    (cell("call_index"), cell("block_index"))
                    + tuple(cell(f"prior_{index}") for index in range(STATE_BITS)),
                    0,
                    absorb_rows,
                ),
            ),
        ),
        LookupArgument(
            "sha3_boolean_round_to_digest",
            (
                LookupSide(
                    "sha3_boolean_round",
                    cell("is_call_final"),
                    (cell("call_index"),)
                    + tuple(cell(f"state_{index}") for index in range(512)),
                    0,
                    round_rows,
                ),
            ),
            (
                LookupSide(
                    "sha3_boolean_digest",
                    const(1),
                    (cell("call_index"),)
                    + tuple(cell(f"digest_bit_{index}") for index in range(512)),
                    0,
                    digest_rows,
                ),
            ),
        ),
    )


def build_sha3_boolean_sponge_program(capacities: Sequence[int]) -> AirProgram:
    materialized = tuple(capacities)
    if not materialized or any(type(value) is not int or value < 0 for value in materialized):
        raise StructuralError("sha3_boolean_capacities_invalid")
    block_counts = tuple(padded_block_count(value) for value in materialized)
    round_table = _build_permutation_program(block_counts).tables[0]
    absorb_table = _absorb_table(materialized)
    digest_table = _digest_table(len(materialized))
    lookups = _sponge_lookups(round_table.rows, absorb_table.rows, digest_table.rows)
    return AirProgram(
        "BL-WAVE1A-SHA3-512-BOOLEAN-SPONGE-AIR-v1",
        (round_table, absorb_table, digest_table),
        lookups,
    )


def build_sha3_boolean_executable_air(
    calls: Sequence[Sha3BooleanCall],
) -> Sha3BooleanAirInstance:
    materialized = tuple(calls)
    if not materialized or any(not isinstance(call, Sha3BooleanCall) for call in materialized):
        raise StructuralError("sha3_boolean_calls_invalid")
    if len({call.call_id for call in materialized}) != len(materialized):
        raise StructuralError("sha3_boolean_call_id_duplicate")
    block_counts = tuple(padded_block_count(call.capacity) for call in materialized)
    initial_states: list[bytes] = []
    prior_states: list[bytes] = []
    blocks: list[bytes] = []
    live_blocks: list[tuple[int, ...]] = []
    actual_block_counts: list[int] = []
    digests: dict[str, bytes] = {}
    for call in materialized:
        state = bytes(STATE_BYTES)
        padded = _pad_message(call.message)
        capacity_blocks = padded_block_count(call.capacity)
        if len(padded) > capacity_blocks:
            raise AssertionError("sha3_boolean_padding_inventory_mismatch")
        actual_block_counts.append(len(padded))
        digest: bytes | None = None
        for block_index in range(capacity_blocks):
            active = block_index < len(padded)
            block = padded[block_index] if active else bytes(RATE_BYTES)
            prior = state if active else bytes(STATE_BYTES)
            prior_states.append(prior)
            blocks.append(block)
            live_blocks.append(
                tuple(
                    int(block_index * RATE_BYTES + byte_index < len(call.message))
                    for byte_index in range(RATE_BYTES)
                )
            )
            absorbed = bytearray(prior)
            for index, value in enumerate(block):
                absorbed[index] ^= value
            initial_states.append(bytes(absorbed))
            round_state: Sequence[int] = tuple(absorbed)
            for round_index in range(KECCAK_ROUNDS):
                round_state = _build_round(round_state, round_index).output_bytes
            if active:
                state = bytes(round_state)
                if block_index + 1 == len(padded):
                    digest = state[:64]
        if digest is None:
            raise AssertionError("sha3_boolean_digest_missing")
        digests[call.call_id] = digest

    round_instance = _build_permutation_air(
        initial_states,
        block_counts,
        actual_block_counts,
    )
    program = build_sha3_boolean_sponge_program(tuple(call.capacity for call in materialized))
    absorb_columns: dict[str, list[int]] = {
        name: [] for name in program.tables[1].columns
    }
    geometry = _permutation_geometry(block_counts)
    for permutation_index, ((call_index, block_index, _), prior, block, live) in enumerate(
        zip(geometry, prior_states, blocks, live_blocks, strict=True)
    ):
        prior_bits = _bits_from_state_bytes(prior)
        block_bits = tuple(
            (block[index // 8] >> (index % 8)) & 1
            for index in range(RATE_BYTES * 8)
        )
        for index, value in enumerate(prior_bits):
            absorb_columns[f"prior_{index}"].append(value)
        for index, value in enumerate(block):
            absorb_columns[f"block_byte_{index}"].append(value)
        for index, value in enumerate(block_bits):
            absorb_columns[f"block_bit_{index}"].append(value)
        for index, value in enumerate(live):
            absorb_columns[f"message_live_{index}"].append(value)
        capacity_remaining = min(
            RATE_BYTES,
            max(
                0,
                materialized[call_index].capacity - block_index * RATE_BYTES,
            ),
        )
        capacity_slack = capacity_remaining - sum(live)
        for index in range(7):
            absorb_columns[f"capacity_slack_{index}"].append(
                (capacity_slack >> index) & 1
            )
        absorb_columns["permutation_index"].append(permutation_index)
        absorb_columns["call_index"].append(call_index)
        absorb_columns["block_index"].append(block_index)
        absorb_columns["is_first_block"].append(int(block_index == 0))
        absorb_columns["is_capacity_last"].append(
            int(block_index + 1 == block_counts[call_index])
        )
        absorb_columns["same_call_next"].append(
            int(block_index + 1 < block_counts[call_index])
        )
        absorb_columns["block_active"].append(
            int(block_index < actual_block_counts[call_index])
        )
        absorb_columns["actual_last"].append(
            int(block_index + 1 == actual_block_counts[call_index])
        )
        absorb_columns["link_prior"].append(
            int(block_index > 0 and block_index < actual_block_counts[call_index])
        )
        absorb_columns["capacity_remaining"].append(capacity_remaining)
    absorb_trace = TraceTable("sha3_boolean_absorb", freeze_columns(absorb_columns))

    digest_columns: dict[str, list[int]] = {
        name: [] for name in program.tables[2].columns
    }
    for call_index, call in enumerate(materialized):
        digest = digests[call.call_id]
        digest_columns["call_index"].append(call_index)
        for index, value in enumerate(digest):
            digest_columns[f"digest_byte_{index}"].append(value)
        for index in range(512):
            digest_columns[f"digest_bit_{index}"].append(
                (digest[index // 8] >> (index % 8)) & 1
            )
    digest_trace = TraceTable("sha3_boolean_digest", freeze_columns(digest_columns))
    traces = {
        "sha3_boolean_round": round_instance.traces["sha3_boolean_round"],
        absorb_trace.name: absorb_trace,
        digest_trace.name: digest_trace,
    }
    return Sha3BooleanAirInstance(
        program,
        MappingProxyType(traces),
        MappingProxyType(digests),
        block_counts,
    )


__all__ = (
    "MAXIMUM_DEGREE",
    "PARITY_BITS",
    "PROGRAM_ID",
    "ROWS_PER_PERMUTATION",
    "STATE_BITS",
    "Sha3BooleanPermutationAirInstance",
    "Sha3BooleanAirInstance",
    "Sha3BooleanCall",
    "build_sha3_boolean_executable_air",
    "build_sha3_boolean_permutation_air",
    "build_sha3_boolean_permutation_program",
    "build_sha3_boolean_sponge_program",
)
