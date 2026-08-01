"""Executable byte/lookup AIR for SHA3-512.

The historical Wave 1B witness generator remains the prover-side trace oracle.
This module independently wires its cells into fixed XOR8, AND_NOT8, and
SPLIT8 truth tables, transition identities, absorb constraints, padding, and a
message table.  Evaluation never calls the historical witness verifier.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from functools import lru_cache
from hashlib import sha3_512
from types import MappingProxyType
from typing import Final, Mapping

from experiments.bl_pq512_crypto_foundation.sha3_512_air_reference import (
    KECCAK_ROUNDS,
    RATE_BYTES,
    ROUND_AND_NOT_LOOKUPS,
    ROUND_SPLIT_LOOKUPS,
    ROUND_XOR_LOOKUPS,
    STATE_BYTES,
    _ROTATION_OFFSETS,
    _ROUND_CONSTANTS,
    _build_round,
    block_absorb_lookup_rows,
    build_sha3_512_air_trace,
    round_lookup_rows,
)

from .executable_air import (
    M31,
    AirProgram,
    AirTable,
    Expr,
    Identity,
    LookupArgument,
    LookupSide,
    TraceTable,
    cell,
    const,
    freeze_columns,
)
from .semantics import StructuralError


PROGRAM_ID: Final[str] = "BL-WAVE1A-SHA3-512-EXECUTABLE-AIR-v1"
TRACE_ROWS_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE1A/SHA3-512-TRACE-ROWS/v1"
XOR8_ID: Final[int] = 1
AND_NOT8_ID: Final[int] = 2
SPLIT8_BASE_ID: Final[int] = 2
TRUTH_ROWS: Final[int] = 2 * 256 * 256 + 7 * 256


@dataclass(frozen=True, slots=True)
class Sha3ExecutableAirInstance:
    program: AirProgram
    traces: Mapping[str, TraceTable]
    message: bytes
    digest: bytes
    capacity: int | None = None


def _append(columns: dict[str, list[int]], name: str, value: int) -> None:
    columns.setdefault(name, []).append(value % M31)


def _lane_index(x: int, y: int, byte: int) -> int:
    return 8 * (x + 5 * y) + byte


def _parity_index(x: int, byte: int, step: int) -> int:
    return (x * 8 + byte) * 4 + step


def _b_state_expressions() -> tuple[dict[tuple[int, int, int], Expr], tuple[LookupSide, ...]]:
    mapping: dict[tuple[int, int, int], Expr] = {}
    split_sides: list[LookupSide] = []
    split_index = 40
    for x in range(5):
        for y in range(5):
            rotation = _ROTATION_OFFSETS[x][y]
            byte_shift, bit_shift = divmod(rotation, 8)
            destination_x, destination_y = y, (2 * x + 3 * y) % 5
            if bit_shift:
                lane_start = split_index
                for source_byte in range(8):
                    split_sides.append(
                        LookupSide(
                            "sha3_round",
                            const(1),
                            (
                                const(SPLIT8_BASE_ID + bit_shift),
                                cell(f"theta_state_{_lane_index(x, y, source_byte)}"),
                                cell(f"rotation_low_{split_index}"),
                                cell(f"rotation_high_{split_index}"),
                            ),
                            0,
                            1,  # expanded to the concrete row count by the caller
                        )
                    )
                    split_index += 1
                for destination_byte in range(8):
                    source_byte = (destination_byte - byte_shift) % 8
                    previous_byte = (source_byte - 1) % 8
                    mapping[(destination_x, destination_y, destination_byte)] = (
                        (1 << bit_shift) * cell(f"rotation_low_{lane_start + source_byte}")
                        + cell(f"rotation_high_{lane_start + previous_byte}")
                    )
            else:
                for destination_byte in range(8):
                    source_byte = (destination_byte - byte_shift) % 8
                    mapping[(destination_x, destination_y, destination_byte)] = cell(
                        f"theta_state_{_lane_index(x, y, source_byte)}"
                    )
    if split_index != ROUND_SPLIT_LOOKUPS:
        raise StructuralError("sha3_executable_split_inventory_mismatch")
    return mapping, tuple(split_sides)


@lru_cache(maxsize=1)
def _truth_table() -> tuple[tuple[int, ...], tuple[int, ...], tuple[int, ...], tuple[int, ...]]:
    kinds: list[int] = []
    lefts: list[int] = []
    rights: list[int] = []
    outputs: list[int] = []
    for left in range(256):
        for right in range(256):
            kinds.append(XOR8_ID)
            lefts.append(left)
            rights.append(right)
            outputs.append(left ^ right)
    for left in range(256):
        for right in range(256):
            kinds.append(AND_NOT8_ID)
            lefts.append(left)
            rights.append(right)
            outputs.append(((~left) & 0xFF) & right)
    for shift in range(1, 8):
        low_width = 8 - shift
        for value in range(256):
            kinds.append(SPLIT8_BASE_ID + shift)
            lefts.append(value)
            rights.append(value & ((1 << low_width) - 1))
            outputs.append(value >> low_width)
    if len(kinds) != TRUTH_ROWS:
        raise StructuralError("sha3_executable_truth_table_size_mismatch")
    return tuple(kinds), tuple(lefts), tuple(rights), tuple(outputs)


def _build_sha3_512_trace_only(
    message: bytes,
    *,
    capacity: int,
    template: Sha3ExecutableAirInstance,
) -> Sha3ExecutableAirInstance:
    """Build one trace while reusing an immutable same-capacity AIR program."""

    if type(message) is not bytes:
        raise StructuralError("sha3_executable_message_must_be_bytes")
    if type(capacity) is not int or capacity < 0 or len(message) > capacity:
        raise StructuralError("sha3_executable_capacity_invalid")
    if template.capacity != capacity:
        raise StructuralError("sha3_executable_trace_template_capacity_mismatch")

    historical = build_sha3_512_air_trace(message)
    block_capacity = capacity // RATE_BYTES + 1
    padded_blocks = list(historical.padded_blocks)
    rounds = list(historical.rounds)
    while len(padded_blocks) < block_capacity:
        state = (0,) * STATE_BYTES
        dummy_rounds = []
        for round_index in range(KECCAK_ROUNDS):
            witness = _build_round(state, round_index)
            dummy_rounds.append(witness)
            state = witness.output_bytes
        padded_blocks.append(bytes(RATE_BYTES))
        rounds.append(tuple(dummy_rounds))

    columns: dict[str, list[int]] = {}
    active_blocks = len(historical.padded_blocks)
    for block_index, block_rounds in enumerate(rounds):
        padded_block = padded_blocks[block_index]
        for round_index, witness in enumerate(block_rounds):
            is_first_round = round_index == 0
            schedule = {
                "block_index": block_index,
                "round_index": round_index,
                "is_first_round": int(is_first_round),
                "is_first_block": int(block_index == 0 and is_first_round),
                "has_next_round": int(round_index != KECCAK_ROUNDS - 1),
                "has_next_block": int(
                    round_index == KECCAK_ROUNDS - 1
                    and block_index + 1 < active_blocks
                ),
                "block_start": block_index * RATE_BYTES,
                "has_next_capacity_block": int(
                    round_index == KECCAK_ROUNDS - 1
                    and block_index != block_capacity - 1
                ),
                "is_capacity_terminal": int(
                    round_index == KECCAK_ROUNDS - 1
                    and block_index == block_capacity - 1
                ),
            }
            round_constant = _ROUND_CONSTANTS[round_index].to_bytes(8, "little")
            for index, value in enumerate(round_constant):
                schedule[f"round_constant_{index}"] = value
            for name, value in schedule.items():
                _append(columns, name, value)

            active = int(block_index < active_blocks)
            actual_last = int(block_index == active_blocks - 1)
            _append(columns, "block_active", active)
            _append(columns, "actual_last", actual_last)
            _append(
                columns,
                "digest_select",
                int(actual_last and round_index == KECCAK_ROUNDS - 1),
            )
            _append(
                columns,
                "dummy_first",
                int(not active and is_first_round),
            )

            witness_values = {
                **{
                    f"state_{i}": value
                    for i, value in enumerate(witness.state_bytes)
                },
                **{
                    f"theta_parity_{i}": value
                    for i, value in enumerate(witness.theta_parity_steps)
                },
                **{f"theta_d_{i}": value for i, value in enumerate(witness.theta_d)},
                **{
                    f"theta_state_{i}": value
                    for i, value in enumerate(witness.theta_state)
                },
                **{
                    f"rotation_low_{i}": value[0]
                    for i, value in enumerate(witness.rotation_splits)
                },
                **{
                    f"rotation_high_{i}": value[1]
                    for i, value in enumerate(witness.rotation_splits)
                },
                **{
                    f"chi_and_{i}": value
                    for i, value in enumerate(witness.chi_and_not)
                },
                **{
                    f"chi_raw_{i}": value
                    for i, value in enumerate(witness.chi_raw)
                },
                **{
                    f"output_{i}": value
                    for i, value in enumerate(witness.output_bytes)
                },
                **{
                    f"block_{i}": padded_block[i] if is_first_round else 0
                    for i in range(RATE_BYTES)
                },
            }
            for name, value in witness_values.items():
                _append(columns, name, value)

    frozen_round = freeze_columns(columns)
    layout_rows = block_capacity * RATE_BYTES
    layout_columns: dict[str, tuple[int, ...]] = {
        "position": tuple(range(layout_rows)),
        "block_index": tuple(index // RATE_BYTES for index in range(layout_rows)),
        "byte_index": tuple(index % RATE_BYTES for index in range(layout_rows)),
        "is_first": tuple(int(index == 0) for index in range(layout_rows)),
        "has_next": tuple(int(index + 1 < layout_rows) for index in range(layout_rows)),
        "within_block_next": tuple(
            int(index % RATE_BYTES != RATE_BYTES - 1)
            for index in range(layout_rows)
        ),
        "block_end": tuple(
            int(index % RATE_BYTES == RATE_BYTES - 1)
            for index in range(layout_rows)
        ),
        "capacity_allowed": tuple(int(index < capacity) for index in range(layout_rows)),
        "live": tuple(int(index < len(message)) for index in range(layout_rows)),
        "value": tuple(
            message[index] if index < len(message) else 0
            for index in range(layout_rows)
        ),
        "pad_start": tuple(int(index == len(message)) for index in range(layout_rows)),
        "pad_end": tuple(
            int(
                index % RATE_BYTES == RATE_BYTES - 1
                and index // RATE_BYTES == len(message) // RATE_BYTES
            )
            for index in range(layout_rows)
        ),
        "active": tuple(
            int(index // RATE_BYTES <= len(message) // RATE_BYTES)
            for index in range(layout_rows)
        ),
        "active_after": tuple(
            int(
                index // RATE_BYTES <= len(message) // RATE_BYTES
                and not (
                    index % RATE_BYTES == RATE_BYTES - 1
                    and index // RATE_BYTES == len(message) // RATE_BYTES
                )
            )
            for index in range(layout_rows)
        ),
        "padded": tuple(
            padded_blocks[index // RATE_BYTES][index % RATE_BYTES]
            for index in range(layout_rows)
        ),
    }
    frozen_layout = freeze_columns(layout_columns)
    digest_trace = TraceTable(
        "sha3_digest",
        freeze_columns(
            {
                f"value_{index}": (historical.digest[index],)
                for index in range(64)
            }
        ),
    )

    kind_ids = {"XOR8": XOR8_ID, "AND_NOT8": AND_NOT8_ID}
    counts: Counter[tuple[int, int, int, int]] = Counter()
    previous = (0,) * STATE_BYTES
    for block_index, block_rounds in enumerate(rounds):
        for witness in block_rounds:
            for kind, left, right, output in round_lookup_rows(witness):
                kind_id = kind_ids.get(kind)
                if kind_id is None:
                    kind_id = SPLIT8_BASE_ID + int(kind.rsplit("_", 1)[1])
                counts[(kind_id, left, right, output)] += 1
        if block_index < active_blocks:
            for kind, left, right, output in block_absorb_lookup_rows(
                previous,
                padded_blocks[block_index],
            ):
                counts[(kind_ids[kind], left, right, output)] += 1
            previous = block_rounds[-1].output_bytes

    truth_kind, truth_left, truth_right, truth_output = _truth_table()
    multiplicities = tuple(
        counts[(kind, left, right, output)]
        for kind, left, right, output in zip(
            truth_kind,
            truth_left,
            truth_right,
            truth_output,
            strict=True,
        )
    )
    expected_lookups = (
        block_capacity * 1024 * KECCAK_ROUNDS
        + active_blocks * RATE_BYTES
    )
    if sum(multiplicities) != expected_lookups:
        raise StructuralError("sha3_executable_lookup_multiplicity_mismatch")

    byte_counts = Counter((*frozen_layout["value"], *frozen_layout["padded"]))
    byte_values = tuple(range(256))
    traces = MappingProxyType(
        {
            "sha3_round": TraceTable("sha3_round", frozen_round),
            "sha3_message": TraceTable("sha3_message", frozen_layout),
            "sha3_truth": TraceTable(
                "sha3_truth",
                freeze_columns(
                    {
                        "kind": truth_kind,
                        "left": truth_left,
                        "right": truth_right,
                        "output": truth_output,
                        "multiplicity": multiplicities,
                    }
                ),
            ),
            "sha3_digest": digest_trace,
            "sha3_byte_range": TraceTable(
                "sha3_byte_range",
                freeze_columns(
                    {
                        "value": byte_values,
                        "multiplicity": tuple(
                            byte_counts[value] for value in byte_values
                        ),
                    }
                ),
            ),
        }
    )
    for name, trace in traces.items():
        template_trace = template.traces[name]
        if (
            trace.rows != template_trace.rows
            or tuple(trace.columns) != tuple(template_trace.columns)
        ):
            raise StructuralError("sha3_executable_trace_template_schema_mismatch")
    return Sha3ExecutableAirInstance(
        template.program,
        traces,
        message,
        historical.digest,
        capacity,
    )


def sha3_512_trace_rows_commitment(message: bytes, *, capacity: int) -> bytes:
    """Commit exact fixed-capacity row witnesses for Python/Rust parity KATs."""

    if type(message) is not bytes:
        raise StructuralError("sha3_executable_message_must_be_bytes")
    if type(capacity) is not int or capacity < 0 or len(message) > capacity:
        raise StructuralError("sha3_executable_capacity_invalid")
    historical = build_sha3_512_air_trace(message)
    block_capacity = capacity // RATE_BYTES + 1
    padded_blocks = list(historical.padded_blocks)
    rounds = list(historical.rounds)
    while len(padded_blocks) < block_capacity:
        state = (0,) * STATE_BYTES
        dummy_rounds = []
        for round_index in range(KECCAK_ROUNDS):
            witness = _build_round(state, round_index)
            dummy_rounds.append(witness)
            state = witness.output_bytes
        padded_blocks.append(bytes(RATE_BYTES))
        rounds.append(tuple(dummy_rounds))

    active_blocks = len(historical.padded_blocks)
    digest = sha3_512()
    digest.update(TRACE_ROWS_DOMAIN)
    digest.update(capacity.to_bytes(8, "big"))
    digest.update(len(message).to_bytes(8, "big"))
    digest.update(block_capacity.to_bytes(8, "big"))
    for block_index, block_rounds in enumerate(rounds):
        active = block_index < active_blocks
        actual_last = block_index == active_blocks - 1
        for round_index, witness in enumerate(block_rounds):
            digest.update(block_index.to_bytes(4, "big"))
            digest.update(bytes((round_index, active, actual_last)))
            digest.update(
                padded_blocks[block_index]
                if round_index == 0
                else bytes(RATE_BYTES)
            )
            digest.update(bytes(witness.state_bytes))
            digest.update(bytes(witness.theta_parity_steps))
            digest.update(bytes(witness.theta_d))
            digest.update(bytes(witness.theta_state))
            digest.update(
                bytes(value for split in witness.rotation_splits for value in split)
            )
            digest.update(bytes(witness.chi_and_not))
            digest.update(bytes(witness.chi_raw))
            digest.update(bytes(witness.output_bytes))
    digest.update(historical.digest)
    return digest.digest()


def build_sha3_512_executable_air(
    message: bytes, *, capacity: int | None = None
) -> Sha3ExecutableAirInstance:
    if type(message) is not bytes:
        raise StructuralError("sha3_executable_message_must_be_bytes")
    if capacity is not None and (
        type(capacity) is not int or capacity < 0 or len(message) > capacity
    ):
        raise StructuralError("sha3_executable_capacity_invalid")
    historical = build_sha3_512_air_trace(message)
    fixed_capacity = capacity is not None
    block_capacity = (
        len(historical.padded_blocks)
        if capacity is None
        else capacity // RATE_BYTES + 1
    )
    padded_blocks = list(historical.padded_blocks)
    rounds = list(historical.rounds)
    while len(padded_blocks) < block_capacity:
        state = (0,) * STATE_BYTES
        dummy_rounds = []
        for round_index in range(KECCAK_ROUNDS):
            witness = _build_round(state, round_index)
            dummy_rounds.append(witness)
            state = witness.output_bytes
        padded_blocks.append(bytes(RATE_BYTES))
        rounds.append(tuple(dummy_rounds))
    round_rows = block_capacity * KECCAK_ROUNDS
    columns: dict[str, list[int]] = {}
    fixed: dict[str, list[int]] = {}
    geometry_fixed_names = (
        "block_index",
        "round_index",
        "is_first_round",
        "is_first_block",
        "has_next_round",
        "block_start",
        *(f"round_constant_{i}" for i in range(8)),
    ) + (("has_next_capacity_block", "is_capacity_terminal") if fixed_capacity else ())
    witness_schedule_names = (
        "has_next_block",
        *(f"message_live_{i}" for i in range(RATE_BYTES)),
        *(f"padding_live_{i}" for i in range(RATE_BYTES)),
        *(f"padding_byte_{i}" for i in range(RATE_BYTES)),
    )
    fixed_names = geometry_fixed_names + (() if fixed_capacity else witness_schedule_names)
    fixed = {name: [] for name in fixed_names}

    active_blocks = len(historical.padded_blocks)
    for block_index, block_rounds in enumerate(rounds):
        padded_block = padded_blocks[block_index]
        for round_index, witness in enumerate(block_rounds):
            is_first_round = round_index == 0
            schedule = {
                "block_index": block_index,
                "round_index": round_index,
                "is_first_round": int(is_first_round),
                "is_first_block": int(block_index == 0 and is_first_round),
                "has_next_round": int(round_index != KECCAK_ROUNDS - 1),
                "has_next_block": int(
                    round_index == KECCAK_ROUNDS - 1
                    and block_index + 1 < active_blocks
                ),
                "block_start": block_index * RATE_BYTES,
            }
            if fixed_capacity:
                schedule.update(
                    {
                        "has_next_capacity_block": int(
                            round_index == KECCAK_ROUNDS - 1
                            and block_index != block_capacity - 1
                        ),
                        "is_capacity_terminal": int(
                            round_index == KECCAK_ROUNDS - 1
                            and block_index == block_capacity - 1
                        ),
                    }
                )
            round_constant = _ROUND_CONSTANTS[round_index].to_bytes(8, "little")
            for index, value in enumerate(round_constant):
                schedule[f"round_constant_{index}"] = value
            for byte_index in range(RATE_BYTES):
                global_index = block_index * RATE_BYTES + byte_index
                live = int(is_first_round and global_index < len(message))
                if not fixed_capacity:
                    schedule[f"message_live_{byte_index}"] = live
                    schedule[f"padding_live_{byte_index}"] = 1 - live
                    schedule[f"padding_byte_{byte_index}"] = (
                        padded_block[byte_index] if is_first_round and not live else 0
                    )
            for name, value in schedule.items():
                _append(columns, name, value)
                if name in fixed:
                    fixed[name].append(value % M31)

            if fixed_capacity:
                active = int(block_index < active_blocks)
                actual_last = int(block_index == active_blocks - 1)
                _append(columns, "block_active", active)
                _append(columns, "actual_last", actual_last)
                _append(
                    columns,
                    "digest_select",
                    int(actual_last and round_index == KECCAK_ROUNDS - 1),
                )
                _append(
                    columns,
                    "dummy_first",
                    int(not active and is_first_round),
                )

            witness_values = {
                **{f"state_{i}": value for i, value in enumerate(witness.state_bytes)},
                **{f"theta_parity_{i}": value for i, value in enumerate(witness.theta_parity_steps)},
                **{f"theta_d_{i}": value for i, value in enumerate(witness.theta_d)},
                **{f"theta_state_{i}": value for i, value in enumerate(witness.theta_state)},
                **{f"rotation_low_{i}": value[0] for i, value in enumerate(witness.rotation_splits)},
                **{f"rotation_high_{i}": value[1] for i, value in enumerate(witness.rotation_splits)},
                **{f"chi_and_{i}": value for i, value in enumerate(witness.chi_and_not)},
                **{f"chi_raw_{i}": value for i, value in enumerate(witness.chi_raw)},
                **{f"output_{i}": value for i, value in enumerate(witness.output_bytes)},
                **{
                    f"block_{i}": padded_block[i] if is_first_round else 0
                    for i in range(RATE_BYTES)
                },
            }
            for name, value in witness_values.items():
                _append(columns, name, value)

    identities: list[Identity] = []
    for index in range(STATE_BYTES):
        identities.append(
            Identity(
                f"round_transition_{index}",
                cell("has_next_round") * (cell(f"output_{index}") - cell(f"state_{index}", 1)),
                0,
                round_rows - 1,
                "transition",
            )
        )
        if index >= 8:
            identities.append(
                Identity(
                    f"iota_copy_{index}", cell(f"output_{index}") - cell(f"chi_raw_{index}"), 0, round_rows
                )
            )
        if index >= RATE_BYTES:
            identities.extend(
                (
                    Identity(
                        f"initial_capacity_zero_{index}",
                        cell("is_first_block") * cell(f"state_{index}"),
                        0,
                        round_rows,
                    ),
                    Identity(
                        f"next_block_capacity_{index}",
                        cell("has_next_block")
                        * (cell(f"output_{index}") - cell(f"state_{index}", 1)),
                        0,
                        round_rows - 1,
                        "transition",
                    ),
                )
            )
    if not fixed_capacity:
        for index in range(RATE_BYTES):
            identities.append(
                Identity(
                    f"padding_{index}",
                    cell(f"padding_live_{index}")
                    * (cell(f"block_{index}") - cell(f"padding_byte_{index}")),
                    0,
                    round_rows,
                )
            )
    if fixed_capacity:
        for name in (
            "block_active",
            "actual_last",
            "digest_select",
            "dummy_first",
            "has_next_block",
        ):
            identities.append(
                Identity(
                    f"{name}_boolean",
                    cell(name) * (cell(name) - 1),
                    0,
                    round_rows,
                )
            )
        identities.extend(
            (
                Identity(
                    "active_constant_within_block",
                    cell("has_next_round")
                    * (cell("block_active") - cell("block_active", 1)),
                    0,
                    round_rows - 1,
                    "transition",
                ),
                Identity(
                    "last_constant_within_block",
                    cell("has_next_round")
                    * (cell("actual_last") - cell("actual_last", 1)),
                    0,
                    round_rows - 1,
                    "transition",
                ),
                Identity(
                    "digest_selector",
                    cell("digest_select")
                    - cell("actual_last") * (1 - cell("has_next_round")),
                    0,
                    round_rows,
                ),
                Identity(
                    "dummy_first_selector",
                    cell("dummy_first")
                    - cell("is_first_round") * (1 - cell("block_active")),
                    0,
                    round_rows,
                ),
                Identity(
                    "next_block_selector_round",
                    cell("has_next_round") * cell("has_next_block"),
                    0,
                    round_rows,
                ),
                Identity(
                    "next_block_selector_transition",
                    cell("has_next_capacity_block")
                    * (cell("has_next_block") - cell("block_active", 1)),
                    0,
                    round_rows - 1,
                    "transition",
                ),
                Identity(
                    "next_block_selector_terminal",
                    cell("is_capacity_terminal") * cell("has_next_block"),
                    0,
                    round_rows,
                ),
            )
        )
        for index in range(STATE_BYTES):
            identities.append(
                Identity(
                    f"dummy_initial_state_zero_{index}",
                    cell("dummy_first") * cell(f"state_{index}"),
                    0,
                    round_rows,
                )
            )

    core_sources: list[LookupSide] = []
    # Theta parity: 160 XOR operations.
    for x in range(5):
        for byte in range(8):
            accumulator: Expr = cell(f"state_{_lane_index(x, 0, byte)}")
            for step, y in enumerate(range(1, 5)):
                output = cell(f"theta_parity_{_parity_index(x, byte, step)}")
                core_sources.append(
                    LookupSide(
                        "sha3_round",
                        const(1),
                        (const(XOR8_ID), accumulator, cell(f"state_{_lane_index(x, y, byte)}"), output),
                        0,
                        round_rows,
                    )
                )
                accumulator = output

    # First 40 split rows rotate the five C lanes by one bit.
    for x in range(5):
        for byte in range(8):
            split = x * 8 + byte
            core_sources.append(
                LookupSide(
                    "sha3_round",
                    const(1),
                    (
                        const(SPLIT8_BASE_ID + 1),
                        cell(f"theta_parity_{_parity_index(x, byte, 3)}"),
                        cell(f"rotation_low_{split}"),
                        cell(f"rotation_high_{split}"),
                    ),
                    0,
                    round_rows,
                )
            )

    def c_lane(x: int, byte: int) -> Expr:
        return cell(f"theta_parity_{_parity_index(x, byte, 3)}")

    def rotated_c(x: int, destination_byte: int) -> Expr:
        source_byte = destination_byte
        previous_byte = (source_byte - 1) % 8
        return 2 * cell(f"rotation_low_{x * 8 + source_byte}") + cell(
            f"rotation_high_{x * 8 + previous_byte}"
        )

    # Theta D and state: 40 + 200 XOR operations.
    for x in range(5):
        for byte in range(8):
            core_sources.append(
                LookupSide(
                    "sha3_round",
                    const(1),
                    (
                        const(XOR8_ID),
                        c_lane((x - 1) % 5, byte),
                        rotated_c((x + 1) % 5, byte),
                        cell(f"theta_d_{x * 8 + byte}"),
                    ),
                    0,
                    round_rows,
                )
            )
    for x in range(5):
        for y in range(5):
            for byte in range(8):
                index = _lane_index(x, y, byte)
                core_sources.append(
                    LookupSide(
                        "sha3_round",
                        const(1),
                        (
                            const(XOR8_ID),
                            cell(f"state_{index}"),
                            cell(f"theta_d_{x * 8 + byte}"),
                            cell(f"theta_state_{index}"),
                        ),
                        0,
                        round_rows,
                    )
                )

    b_state, split_templates = _b_state_expressions()
    core_sources.extend(
        LookupSide(side.table, side.selector, side.values, 0, round_rows, side.weight)
        for side in split_templates
    )

    # Chi: 200 AND-NOT and 200 XOR operations.
    for x in range(5):
        for y in range(5):
            for byte in range(8):
                index = _lane_index(x, y, byte)
                and_output = cell(f"chi_and_{index}")
                core_sources.extend(
                    (
                        LookupSide(
                            "sha3_round",
                            const(1),
                            (
                                const(AND_NOT8_ID),
                                b_state[((x + 1) % 5, y, byte)],
                                b_state[((x + 2) % 5, y, byte)],
                                and_output,
                            ),
                            0,
                            round_rows,
                        ),
                        LookupSide(
                            "sha3_round",
                            const(1),
                            (
                                const(XOR8_ID),
                                b_state[(x, y, byte)],
                                and_output,
                                cell(f"chi_raw_{index}"),
                            ),
                            0,
                            round_rows,
                        ),
                    )
                )

    # Iota: eight XOR operations.
    for byte in range(8):
        core_sources.append(
            LookupSide(
                "sha3_round",
                const(1),
                (
                    const(XOR8_ID),
                    cell(f"chi_raw_{byte}"),
                    cell(f"round_constant_{byte}"),
                    cell(f"output_{byte}"),
                ),
                0,
                round_rows,
            )
        )
    if len(core_sources) != 1024:
        raise StructuralError("sha3_executable_core_lookup_count_mismatch")

    absorb_sources: list[LookupSide] = []
    for byte in range(RATE_BYTES):
        absorb_sources.extend(
            (
                LookupSide(
                    "sha3_round",
                    cell("is_first_block"),
                    (const(XOR8_ID), const(0), cell(f"block_{byte}"), cell(f"state_{byte}")),
                    0,
                    round_rows,
                ),
                LookupSide(
                    "sha3_round",
                    cell("has_next_block"),
                    (
                        const(XOR8_ID),
                        cell(f"output_{byte}"),
                        cell(f"block_{byte}", 1),
                        cell(f"state_{byte}", 1),
                    ),
                    0,
                    round_rows,
                ),
            )
        )

    # Build multiplicities from the independently generated operation rows.
    kind_ids = {"XOR8": XOR8_ID, "AND_NOT8": AND_NOT8_ID}
    counts: Counter[tuple[int, int, int, int]] = Counter()
    previous = (0,) * STATE_BYTES
    for block_index, block_rounds in enumerate(rounds):
        for witness in block_rounds:
            for kind, left, right, output in round_lookup_rows(witness):
                kind_id = kind_ids.get(kind)
                if kind_id is None:
                    kind_id = SPLIT8_BASE_ID + int(kind.rsplit("_", 1)[1])
                counts[(kind_id, left, right, output)] += 1
        if block_index < active_blocks:
            for kind, left, right, output in block_absorb_lookup_rows(
                previous, padded_blocks[block_index]
            ):
                counts[(kind_ids[kind], left, right, output)] += 1
            previous = block_rounds[-1].output_bytes

    truth_kind, truth_left, truth_right, truth_output = _truth_table()
    multiplicities = tuple(
        counts[(kind, left, right, output)]
        for kind, left, right, output in zip(
            truth_kind, truth_left, truth_right, truth_output, strict=True
        )
    )
    expected_lookups = block_capacity * 1024 * KECCAK_ROUNDS + active_blocks * RATE_BYTES
    if sum(multiplicities) != expected_lookups:
        raise StructuralError("sha3_executable_lookup_multiplicity_mismatch")

    frozen_round = freeze_columns(columns)
    round_trace = TraceTable("sha3_round", frozen_round)
    round_table = AirTable(
        "sha3_round",
        tuple(frozen_round),
        round_rows,
        tuple(identities),
        MappingProxyType({name: tuple(values) for name, values in fixed.items()}),
    )

    extra_tables: list[AirTable] = []
    extra_traces: dict[str, TraceTable] = {}
    extra_lookups: list[LookupArgument] = []
    if fixed_capacity:
        assert capacity is not None
        layout_rows = block_capacity * RATE_BYTES
        layout_columns: dict[str, tuple[int, ...]] = {
            "position": tuple(range(layout_rows)),
            "block_index": tuple(index // RATE_BYTES for index in range(layout_rows)),
            "byte_index": tuple(index % RATE_BYTES for index in range(layout_rows)),
            "is_first": tuple(int(index == 0) for index in range(layout_rows)),
            "has_next": tuple(int(index + 1 < layout_rows) for index in range(layout_rows)),
            "within_block_next": tuple(
                int(index % RATE_BYTES != RATE_BYTES - 1) for index in range(layout_rows)
            ),
            "block_end": tuple(
                int(index % RATE_BYTES == RATE_BYTES - 1) for index in range(layout_rows)
            ),
            "capacity_allowed": tuple(int(index < capacity) for index in range(layout_rows)),
            "live": tuple(int(index < len(message)) for index in range(layout_rows)),
            "value": tuple(message[index] if index < len(message) else 0 for index in range(layout_rows)),
            "pad_start": tuple(int(index == len(message)) for index in range(layout_rows)),
            "pad_end": tuple(
                int(
                    index % RATE_BYTES == RATE_BYTES - 1
                    and index // RATE_BYTES == len(message) // RATE_BYTES
                )
                for index in range(layout_rows)
            ),
            "active": tuple(
                int(index // RATE_BYTES <= len(message) // RATE_BYTES)
                for index in range(layout_rows)
            ),
            "active_after": tuple(
                int(
                    index // RATE_BYTES <= len(message) // RATE_BYTES
                    and not (
                        index % RATE_BYTES == RATE_BYTES - 1
                        and index // RATE_BYTES == len(message) // RATE_BYTES
                    )
                )
                for index in range(layout_rows)
            ),
            "padded": tuple(
                padded_blocks[index // RATE_BYTES][index % RATE_BYTES]
                for index in range(layout_rows)
            ),
        }
        frozen_layout = freeze_columns(layout_columns)
        layout_identities: list[Identity] = []
        for name in ("live", "pad_start", "pad_end", "active", "active_after"):
            layout_identities.append(
                Identity(f"{name}_boolean", cell(name) * (cell(name) - 1), 0, layout_rows)
            )
        layout_identities.extend(
            (
                Identity("live_outside_capacity", (1 - cell("capacity_allowed")) * cell("live"), 0, layout_rows),
                Identity("padding_value_zero", (1 - cell("live")) * cell("value"), 0, layout_rows),
                Identity("pad_end_at_block_end", (1 - cell("block_end")) * cell("pad_end"), 0, layout_rows),
                Identity("live_requires_active", cell("live") * (1 - cell("active")), 0, layout_rows),
                Identity("pad_requires_active", cell("pad_start") * (1 - cell("active")), 0, layout_rows),
                Identity(
                    "active_after_derivation",
                    cell("active_after") - cell("active") * (1 - cell("pad_end")),
                    0,
                    layout_rows,
                ),
                Identity(
                    "padded_byte",
                    cell("padded")
                    - cell("live") * cell("value")
                    - 6 * cell("pad_start")
                    - 128 * cell("pad_end"),
                    0,
                    layout_rows,
                ),
                Identity("initial_pad_start", cell("pad_start") - (1 - cell("live")), 0, 1, "boundary"),
                Identity("initial_active", cell("active") - 1, 0, 1, "boundary"),
            )
        )
        if layout_rows > 1:
            layout_identities.extend(
                (
                    Identity(
                        "live_prefix",
                        cell("live", 1) * (1 - cell("live")),
                        0,
                        layout_rows - 1,
                        "transition",
                    ),
                    Identity(
                        "pad_start_transition",
                        cell("pad_start", 1) - (1 - cell("live", 1)) * cell("live"),
                        0,
                        layout_rows - 1,
                        "transition",
                    ),
                    Identity(
                        "active_within_block",
                        cell("within_block_next") * (cell("active") - cell("active", 1)),
                        0,
                        layout_rows - 1,
                        "transition",
                    ),
                    Identity(
                        "active_block_transition",
                        cell("block_end")
                        * (cell("active", 1) - cell("active_after")),
                        0,
                        layout_rows - 1,
                        "transition",
                    ),
                )
            )
        message_trace = TraceTable("sha3_message", frozen_layout)
        message_table = AirTable(
            "sha3_message",
            tuple(frozen_layout),
            layout_rows,
            tuple(layout_identities),
            MappingProxyType(
                {
                    name: frozen_layout[name]
                    for name in (
                        "position",
                        "block_index",
                        "byte_index",
                        "is_first",
                        "has_next",
                        "within_block_next",
                        "block_end",
                        "capacity_allowed",
                    )
                }
            ),
        )
        digest_columns = {f"value_{index}": (historical.digest[index],) for index in range(64)}
        digest_trace = TraceTable("sha3_digest", freeze_columns(digest_columns))
        digest_table = AirTable("sha3_digest", tuple(digest_trace.columns), 1, ())
        extra_tables.append(digest_table)
        extra_traces["sha3_digest"] = digest_trace

        byte_counts = Counter((*frozen_layout["value"], *frozen_layout["padded"]))
        byte_values = tuple(range(256))
        byte_trace = TraceTable(
            "sha3_byte_range",
            freeze_columns(
                {
                    "value": byte_values,
                    "multiplicity": tuple(byte_counts[value] for value in byte_values),
                }
            ),
        )
        byte_table = AirTable(
            "sha3_byte_range",
            ("value", "multiplicity"),
            256,
            (),
            MappingProxyType({"value": byte_values}),
        )
        extra_tables.append(byte_table)
        extra_traces["sha3_byte_range"] = byte_trace
        extra_lookups.extend(
            (
                LookupArgument(
                    "sha3_fixed_capacity_byte_range",
                    (
                        LookupSide("sha3_message", const(1), (cell("value"),), 0, layout_rows),
                        LookupSide("sha3_message", const(1), (cell("padded"),), 0, layout_rows),
                    ),
                    (
                        LookupSide(
                            "sha3_byte_range",
                            const(1),
                            (cell("value"),),
                            0,
                            256,
                            cell("multiplicity"),
                        ),
                    ),
                ),
                LookupArgument(
                    "sha3_padding_block_binding",
                    (
                        LookupSide(
                            "sha3_message",
                            const(1),
                            (cell("block_index"), cell("byte_index"), cell("padded")),
                            0,
                            layout_rows,
                        ),
                    ),
                    tuple(
                        LookupSide(
                            "sha3_round",
                            cell("is_first_round"),
                            (cell("block_index"), const(index), cell(f"block_{index}")),
                            0,
                            round_rows,
                        )
                        for index in range(RATE_BYTES)
                    ),
                ),
                LookupArgument(
                    "sha3_padding_endpoint",
                    (
                        LookupSide(
                            "sha3_message",
                            cell("pad_start"),
                            (cell("block_index"),),
                            0,
                            layout_rows,
                        ),
                    ),
                    (
                        LookupSide(
                            "sha3_message",
                            cell("pad_end"),
                            (cell("block_index"),),
                            0,
                            layout_rows,
                        ),
                    ),
                ),
                LookupArgument(
                    "sha3_block_activity_binding",
                    (
                        LookupSide(
                            "sha3_message",
                            cell("block_end"),
                            (cell("block_index"), cell("active"), cell("pad_end")),
                            0,
                            layout_rows,
                        ),
                    ),
                    (
                        LookupSide(
                            "sha3_round",
                            const(1) - cell("has_next_round"),
                            (cell("block_index"), cell("block_active"), cell("actual_last")),
                            0,
                            round_rows,
                        ),
                    ),
                ),
                LookupArgument(
                    "sha3_digest_binding",
                    (
                        LookupSide(
                            "sha3_round",
                            cell("digest_select"),
                            tuple(cell(f"output_{index}") for index in range(64)),
                            0,
                            round_rows,
                        ),
                    ),
                    (
                        LookupSide(
                            "sha3_digest",
                            const(1),
                            tuple(cell(f"value_{index}") for index in range(64)),
                            0,
                            1,
                        ),
                    ),
                ),
            )
        )
    else:
        message_rows = max(1, len(message))
        message_trace = TraceTable(
            "sha3_message",
            freeze_columns(
                {
                    "position": tuple(range(message_rows)),
                    "live": tuple(1 if index < len(message) else 0 for index in range(message_rows)),
                    "value": tuple(message[index] if index < len(message) else 0 for index in range(message_rows)),
                }
            ),
        )
        message_table = AirTable(
            "sha3_message",
            ("position", "live", "value"),
            message_rows,
            (),
            MappingProxyType(
                {
                    "position": tuple(range(message_rows)),
                    "live": tuple(1 if index < len(message) else 0 for index in range(message_rows)),
                }
            ),
        )
    truth_trace = TraceTable(
        "sha3_truth",
        freeze_columns(
            {
                "kind": truth_kind,
                "left": truth_left,
                "right": truth_right,
                "output": truth_output,
                "multiplicity": multiplicities,
            }
        ),
    )
    truth_table = AirTable(
        "sha3_truth",
        ("kind", "left", "right", "output", "multiplicity"),
        TRUTH_ROWS,
        (),
        MappingProxyType(
            {
                "kind": truth_kind,
                "left": truth_left,
                "right": truth_right,
                "output": truth_output,
            }
        ),
    )
    truth_lookup = LookupArgument(
        "sha3_fixed_truth",
        tuple(core_sources + absorb_sources),
        (
            LookupSide(
                "sha3_truth",
                const(1),
                (cell("kind"), cell("left"), cell("right"), cell("output")),
                0,
                TRUTH_ROWS,
                cell("multiplicity"),
            ),
        ),
    )
    lookups: list[LookupArgument] = [truth_lookup]
    if fixed_capacity:
        lookups.extend(extra_lookups)
    else:
        message_sources = tuple(
            LookupSide(
                "sha3_round",
                cell(f"message_live_{byte}"),
                (cell("block_start") + byte, cell(f"block_{byte}")),
                0,
                round_rows,
            )
            for byte in range(RATE_BYTES)
        )
        message_lookup = LookupArgument(
            "sha3_message_binding",
            message_sources,
            (
                LookupSide(
                    "sha3_message",
                    cell("live"),
                    (cell("position"), cell("value")),
                    0,
                    message_rows,
                ),
            ),
        )
        lookups.append(message_lookup)
    program = AirProgram(
        PROGRAM_ID,
        (round_table, message_table, truth_table, *extra_tables),
        tuple(lookups),
    )
    return Sha3ExecutableAirInstance(
        program,
        MappingProxyType(
            {
                "sha3_round": round_trace,
                "sha3_message": message_trace,
                "sha3_truth": truth_trace,
                **extra_traces,
            }
        ),
        message,
        historical.digest,
        capacity,
    )


__all__ = [
    "Sha3ExecutableAirInstance",
    "build_sha3_512_executable_air",
    "sha3_512_trace_rows_commitment",
]
