"""Executable M31 AIR for one fixed-schedule ordered-map batch transition.

This component constrains operation semantics, insert-only cursor movement,
sorted sequential memory, authenticated endpoint leaves, canonical multiproof
consumption, node topology, endpoint roots, and typed fixed-count SHA3 ports.
The returned hash calls must be composed with the exact SHA3-512 AIR; the
component deliberately reports that boundary instead of trusting a host hash.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from hashlib import sha3_512
from types import MappingProxyType
from typing import Final, Mapping, Sequence

from .application_sha3_executable_air import (
    Sha3Call,
    build_application_sha3_executable_air,
    build_application_sha3_interface_air,
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
    boolean,
    cell,
    const,
    freeze_columns,
)
from .ordered_map_batch_reference import (
    OrderedMapBatchSchedule,
    OrderedMapBatchWitness,
    OrderedMapHashCall,
    build_ordered_map_hash_schedule,
    require_ordered_map_batch_fits_schedule,
)
from .ordered_map_reference import (
    MAX_512,
    ZERO_512,
    OrderedMapLeaf,
    ordered_map_leaf_preimage,
    ordered_map_node_preimage,
    ordered_map_state_preimage,
)
from .semantics import StructuralError


PROGRAM_ID: Final[str] = "BL-WAVE1A-ORDERED-MAP-BATCH-AIR-v1"
COMPOSED_PROGRAM_ID: Final[str] = "BL-WAVE1A-ORDERED-MAP-BATCH-SHA3-AIR-v1"
_LEAF_TAG_BYTES: Final[int] = 212
_NODE_TAG_BYTES: Final[int] = 141
_HEADER_TAG_BYTES: Final[int] = 84
_HASH_MESSAGE_CAPACITY: Final[int] = _LEAF_TAG_BYTES


@dataclass(frozen=True, slots=True)
class OrderedMapBatchAirInstance:
    program: AirProgram
    traces: Mapping[str, TraceTable]
    witness: OrderedMapBatchWitness
    schedule: OrderedMapBatchSchedule
    hash_calls: tuple[OrderedMapHashCall, ...]
    hashes_constrained: bool = False
    hash_ports_constrained: bool = False
    sha3_interface_only: bool = False

    def __post_init__(self) -> None:
        if self.hashes_constrained:
            table_names = {table.name for table in self.program.tables}
            lookup_names = {lookup.name for lookup in self.program.lookups}
            required_tables = {
                "sha3_round_batch",
                "sha3_message_batch",
                "sha3_digest_batch",
                "sha3_truth_shared",
                "sha3_byte_range_shared",
            }
            required_lookups = {
                "ordered_map_sha3_message_binding",
                "ordered_map_sha3_digest_binding",
            }
            if (
                self.program.program_id != COMPOSED_PROGRAM_ID
                or not required_tables.issubset(table_names)
                or not required_lookups.issubset(lookup_names)
                or self.traces["sha3_digest_batch"].rows != len(self.hash_calls)
            ):
                raise StructuralError("ordered_map_air_hash_boundary_false_claim")
        if self.hash_ports_constrained:
            lookup_names = {lookup.name for lookup in self.program.lookups}
            if (
                not self.sha3_interface_only
                or self.hashes_constrained
                or not {
                    "ordered_map_sha3_message_binding",
                    "ordered_map_sha3_digest_binding",
                }.issubset(lookup_names)
            ):
                raise StructuralError("ordered_map_air_hash_boundary_false_claim")


@dataclass(frozen=True, slots=True)
class _NodeRow:
    phase: int
    height: int
    parent: int
    left: bytes
    right: bytes
    digest: bytes


def _append(columns: dict[str, list[int]], name: str, value: int) -> None:
    columns.setdefault(name, []).append(value)


def _balanced_sum(values: Sequence[Expr]) -> Expr:
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


def _append_bytes(
    columns: dict[str, list[int]],
    byte_names: set[str],
    prefix: str,
    value: bytes,
) -> None:
    for index, byte in enumerate(value):
        name = f"{prefix}_{index}"
        _append(columns, name, byte)
        byte_names.add(name)


def _append_u32(
    columns: dict[str, list[int]],
    byte_names: set[str],
    prefix: str,
    value: int,
) -> None:
    if type(value) is not int or not 0 <= value <= 0xFFFF_FFFF:
        raise StructuralError("ordered_map_air_u32_invalid")
    _append(columns, prefix, value)
    _append_bytes(columns, byte_names, f"{prefix}_byte", value.to_bytes(4, "big"))


def _zero_leaf_columns(
    columns: dict[str, list[int]],
    byte_names: set[str],
    prefix: str,
) -> None:
    _append(columns, f"{prefix}_present", 0)
    _append_u32(columns, byte_names, f"{prefix}_index", 0)
    _append_bytes(columns, byte_names, f"{prefix}_key", ZERO_512)
    _append_bytes(columns, byte_names, f"{prefix}_value", ZERO_512)
    _append_bytes(columns, byte_names, f"{prefix}_next_key", ZERO_512)
    _append_u32(columns, byte_names, f"{prefix}_next_index", 0)
    _append_bytes(columns, byte_names, f"{prefix}_next_index_u64", bytes(8))


def _append_leaf(
    columns: dict[str, list[int]],
    byte_names: set[str],
    prefix: str,
    leaf: OrderedMapLeaf | None,
) -> None:
    if leaf is None:
        _zero_leaf_columns(columns, byte_names, prefix)
        return
    _append(columns, f"{prefix}_present", 1)
    _append_u32(columns, byte_names, f"{prefix}_index", leaf.index)
    _append_bytes(columns, byte_names, f"{prefix}_key", leaf.key_512)
    _append_bytes(columns, byte_names, f"{prefix}_value", leaf.value_512)
    _append_bytes(columns, byte_names, f"{prefix}_next_key", leaf.next_key_512)
    _append_u32(columns, byte_names, f"{prefix}_next_index", leaf.next_index)
    _append_bytes(
        columns,
        byte_names,
        f"{prefix}_next_index_u64",
        leaf.next_index.to_bytes(8, "big"),
    )


def _leaf_expr(prefix: str) -> tuple[Expr, ...]:
    return (
        cell(f"{prefix}_present"),
        cell(f"{prefix}_index"),
        *(cell(f"{prefix}_key_{index}") for index in range(64)),
        *(cell(f"{prefix}_value_{index}") for index in range(64)),
        *(cell(f"{prefix}_next_key_{index}") for index in range(64)),
        cell(f"{prefix}_next_index"),
    )


def _leaf_columns(prefix: str) -> tuple[str, ...]:
    return (
        f"{prefix}_present",
        f"{prefix}_index",
        *(f"{prefix}_index_byte_{index}" for index in range(4)),
        *(f"{prefix}_key_{index}" for index in range(64)),
        *(f"{prefix}_value_{index}" for index in range(64)),
        *(f"{prefix}_next_key_{index}" for index in range(64)),
        f"{prefix}_next_index",
        *(f"{prefix}_next_index_byte_{index}" for index in range(4)),
        *(f"{prefix}_next_index_u64_{index}" for index in range(8)),
    )


def _u32_identities(prefix: str, rows: int) -> tuple[Identity, ...]:
    expression: Expr = const(0)
    for index in range(4):
        expression += (1 << (8 * (3 - index))) * cell(f"{prefix}_byte_{index}")
    return (
        Identity(f"{prefix}_bytes", cell(prefix) - expression, 0, rows),
    )


def _u24_identities(prefix: str, rows: int) -> tuple[Identity, ...]:
    """Bind a canonical integer in ``[0, 2**24)``.

    Merely reconstructing four bytes in M31 is not sufficient: a malicious
    prover could add the field modulus to the byte representation.  Requiring
    the high byte to be zero makes the representation canonical.
    """

    return (
        *_u32_identities(prefix, rows),
        Identity(f"{prefix}_u24", cell(f"{prefix}_byte_0"), 0, rows),
    )


def _cursor_identities(prefix: str, rows: int) -> tuple[Identity, ...]:
    """Bind an allocator cursor in ``[0, 2**24]`` canonically."""

    high = cell(f"{prefix}_byte_0")
    return (
        *_u32_identities(prefix, rows),
        Identity(f"{prefix}_capacity_bit", boolean(high), 0, rows),
        Identity(
            f"{prefix}_capacity_boundary",
            high
            * (
                cell(f"{prefix}_byte_1")
                + cell(f"{prefix}_byte_2")
                + cell(f"{prefix}_byte_3")
            ),
            0,
            rows,
        ),
    )


def _append_u6(columns: dict[str, list[int]], prefix: str, value: int) -> None:
    if type(value) is not int or not 0 <= value < 64:
        raise StructuralError("ordered_map_air_u6_invalid")
    _append(columns, prefix, value)
    for index in range(6):
        _append(columns, f"{prefix}_bit_{index}", (value >> index) & 1)


def _u6_identities(prefix: str, rows: int) -> tuple[Identity, ...]:
    reconstructed: Expr = const(0)
    identities: list[Identity] = []
    for index in range(6):
        bit = cell(f"{prefix}_bit_{index}")
        reconstructed += (1 << index) * bit
        identities.append(
            Identity(f"{prefix}_bit_{index}_boolean", boolean(bit), 0, rows)
        )
    identities.append(
        Identity(f"{prefix}_u6", cell(prefix) - reconstructed, 0, rows)
    )
    return tuple(identities)


def _leaf_identities(prefix: str, rows: int) -> tuple[Identity, ...]:
    identities = [
        Identity(
            f"{prefix}_present_boolean",
            boolean(cell(f"{prefix}_present")),
            0,
            rows,
        ),
        *_u24_identities(f"{prefix}_index", rows),
        *_u24_identities(f"{prefix}_next_index", rows),
    ]
    reconstructed: Expr = const(0)
    for index in range(8):
        reconstructed += (1 << (8 * (7 - index))) * cell(
            f"{prefix}_next_index_u64_{index}"
        )
    identities.append(
        Identity(
            f"{prefix}_next_index_u64_binding",
            cell(f"{prefix}_next_index") - reconstructed,
            0,
            rows,
        )
    )
    for index in range(4):
        identities.append(
            Identity(
                f"{prefix}_next_index_u64_zero_{index}",
                cell(f"{prefix}_next_index_u64_{index}"),
                0,
                rows,
            )
        )
    for index in range(4):
        identities.append(
            Identity(
                f"{prefix}_next_index_u64_byte_{index}",
                cell(f"{prefix}_next_index_u64_{index + 4}")
                - cell(f"{prefix}_next_index_byte_{index}"),
                0,
                rows,
            )
        )
    absent = 1 - cell(f"{prefix}_present")
    for name in _leaf_columns(prefix):
        if name == f"{prefix}_present":
            continue
        identities.append(
            Identity(f"{prefix}_absent_{name}", absent * cell(name), 0, rows)
        )
    return tuple(identities)


def _strict_difference(left: bytes, right: bytes) -> tuple[bytes, bytes]:
    if not left or len(left) != len(right) or not left < right:
        raise StructuralError("ordered_map_air_strict_difference_invalid")
    difference = (int.from_bytes(right, "big") - int.from_bytes(left, "big") - 1).to_bytes(
        len(left),
        "big",
    )
    borrows = [0] * len(left)
    incoming = 1
    for index in range(len(left) - 1, -1, -1):
        raw = right[index] - left[index] - incoming
        borrow = int(raw < 0)
        borrows[index] = borrow
        incoming = borrow
    if incoming:
        raise StructuralError("ordered_map_air_strict_difference_underflow")
    return difference, bytes(borrows)


def _append_u31(
    columns: dict[str, list[int]],
    byte_names: set[str],
    prefix: str,
    value: int,
) -> None:
    """Append a canonical integer strictly below the M31 modulus."""

    if type(value) is not int or not 0 <= value < M31:
        raise StructuralError("ordered_map_air_u31_invalid")
    _append_u32(columns, byte_names, prefix, value)
    difference, borrows = _strict_difference(
        value.to_bytes(4, "big"),
        M31.to_bytes(4, "big"),
    )
    _append_bytes(columns, byte_names, f"{prefix}_modulus_diff", difference)
    _append_bytes(columns, byte_names, f"{prefix}_modulus_borrow", borrows)


def _u31_identities(prefix: str, rows: int) -> tuple[Identity, ...]:
    identities: list[Identity] = [*_u32_identities(prefix, rows)]
    modulus = M31.to_bytes(4, "big")
    for index in range(4):
        borrow = cell(f"{prefix}_modulus_borrow_{index}")
        incoming: Expr = (
            const(1)
            if index == 3
            else cell(f"{prefix}_modulus_borrow_{index + 1}")
        )
        identities.extend(
            (
                Identity(
                    f"{prefix}_modulus_borrow_{index}_boolean",
                    boolean(borrow),
                    0,
                    rows,
                ),
                Identity(
                    f"{prefix}_below_modulus_{index}",
                    const(modulus[index])
                    - cell(f"{prefix}_byte_{index}")
                    - incoming
                    + 256 * borrow
                    - cell(f"{prefix}_modulus_diff_{index}"),
                    0,
                    rows,
                ),
            )
        )
    identities.append(
        Identity(
            f"{prefix}_below_modulus_no_underflow",
            cell(f"{prefix}_modulus_borrow_0"),
            0,
            rows,
        )
    )
    return tuple(identities)


def _operation_table(
    witness: OrderedMapBatchWitness,
) -> tuple[AirTable, TraceTable, set[str]]:
    columns: dict[str, list[int]] = {}
    byte_names: set[str] = set()
    for index, operation in enumerate(witness.operations):
        insert = operation.mode == "insert"
        _append(columns, "operation_index", index)
        _append(columns, "is_insert", int(insert))
        _append_u32(
            columns,
            byte_names,
            "cursor_before",
            operation.next_append_index_before,
        )
        _append_u32(
            columns,
            byte_names,
            "cursor_after",
            operation.next_append_index_after,
        )
        _append_bytes(columns, byte_names, "key", operation.key_512)
        key_nonzero = tuple(int(value != 0) for value in operation.key_512)
        key_not_max = tuple(int(value != 0xFF) for value in operation.key_512)
        for byte, (nonzero, not_max) in enumerate(
            zip(key_nonzero, key_not_max, strict=True)
        ):
            _append(columns, f"key_nonzero_{byte}", nonzero)
            _append(columns, f"key_not_max_{byte}", not_max)
            value = operation.key_512[byte]
            _append(
                columns,
                f"key_nonzero_inverse_{byte}",
                pow(value, -1, M31) if value else 0,
            )
            not_max_difference = 0xFF - value
            _append(
                columns,
                f"key_not_max_inverse_{byte}",
                pow(not_max_difference, -1, M31) if not_max_difference else 0,
            )
        nonzero_sum = sum(key_nonzero)
        not_max_sum = sum(key_not_max)
        _append(columns, "key_nonzero_sum", nonzero_sum)
        _append(columns, "key_not_max_sum", not_max_sum)
        _append(columns, "key_nonzero_sum_inverse", pow(nonzero_sum, -1, M31))
        _append(columns, "key_not_max_sum_inverse", pow(not_max_sum, -1, M31))
        _append_bytes(columns, byte_names, "value_before", operation.value_before_512)
        _append_bytes(columns, byte_names, "value_after", operation.value_after_512)
        _append_leaf(columns, byte_names, "target_before", operation.target_before)
        _append_leaf(columns, byte_names, "target_after", operation.target_after)
        _append_leaf(columns, byte_names, "allocated_after", operation.allocated_after)
        gap = operation.next_append_index_before - operation.target_before.index - 1
        _append_u32(columns, byte_names, "target_cursor_gap", gap)
        if insert:
            lower_diff, lower_borrow = _strict_difference(
                operation.target_before.key_512,
                operation.key_512,
            )
            upper_diff, upper_borrow = _strict_difference(
                operation.key_512,
                operation.target_before.next_key_512,
            )
        else:
            lower_diff = lower_borrow = upper_diff = upper_borrow = bytes(64)
        for prefix, raw in (
            ("lower_diff", lower_diff),
            ("lower_borrow", lower_borrow),
            ("upper_diff", upper_diff),
            ("upper_borrow", upper_borrow),
        ):
            _append_bytes(columns, byte_names, prefix, raw)

    rows = len(witness.operations)
    identities: list[Identity] = [
        Identity("is_insert_boolean", boolean(cell("is_insert")), 0, rows),
        Identity(
            "key_nonzero_sum",
            cell("key_nonzero_sum")
            - _balanced_sum(
                tuple(cell(f"key_nonzero_{byte}") for byte in range(64))
            ),
            0,
            rows,
        ),
        Identity(
            "key_not_max_sum",
            cell("key_not_max_sum")
            - _balanced_sum(
                tuple(cell(f"key_not_max_{byte}") for byte in range(64))
            ),
            0,
            rows,
        ),
        Identity(
            "key_not_zero",
            cell("key_nonzero_sum") * cell("key_nonzero_sum_inverse") - 1,
            0,
            rows,
        ),
        Identity(
            "key_not_max",
            cell("key_not_max_sum") * cell("key_not_max_sum_inverse") - 1,
            0,
            rows,
        ),
        *(
            identity
            for byte in range(64)
            for identity in (
                Identity(
                    f"key_byte_zero_flag_{byte}",
                    cell(f"key_{byte}") * (1 - cell(f"key_nonzero_{byte}")),
                    0,
                    rows,
                ),
                Identity(
                    f"key_byte_nonzero_inverse_{byte}",
                    cell(f"key_{byte}") * cell(f"key_nonzero_inverse_{byte}")
                    - cell(f"key_nonzero_{byte}"),
                    0,
                    rows,
                ),
                Identity(
                    f"key_byte_max_flag_{byte}",
                    (255 - cell(f"key_{byte}")) * (1 - cell(f"key_not_max_{byte}")),
                    0,
                    rows,
                ),
                Identity(
                    f"key_byte_not_max_inverse_{byte}",
                    (255 - cell(f"key_{byte}"))
                    * cell(f"key_not_max_inverse_{byte}")
                    - cell(f"key_not_max_{byte}"),
                    0,
                    rows,
                ),
            )
        ),
        Identity(
            "cursor_transition",
            cell("cursor_after") - cell("cursor_before") - cell("is_insert"),
            0,
            rows,
        ),
        Identity(
            "target_below_cursor",
            cell("cursor_before")
            - cell("target_before_index")
            - 1
            - cell("target_cursor_gap"),
            0,
            rows,
        ),
        *_cursor_identities("cursor_before", rows),
        *_cursor_identities("cursor_after", rows),
        *_u24_identities("target_cursor_gap", rows),
        *_leaf_identities("target_before", rows),
        *_leaf_identities("target_after", rows),
        *_leaf_identities("allocated_after", rows),
    ]
    if rows > 1:
        identities.append(
            Identity(
                "ordered_cursor_chain",
                cell("cursor_after") - cell("cursor_before", 1),
                0,
                rows - 1,
                "transition",
            )
        )
    insert = cell("is_insert")
    update = 1 - insert
    identities.extend(
        (
            Identity(
                "target_index_stable",
                cell("target_after_index") - cell("target_before_index"),
                0,
                rows,
            ),
            Identity(
                "target_before_present",
                cell("target_before_present") - 1,
                0,
                rows,
            ),
            Identity(
                "target_after_present",
                cell("target_after_present") - 1,
                0,
                rows,
            ),
            Identity(
                "allocated_selector",
                cell("allocated_after_present") - insert,
                0,
                rows,
            ),
            Identity(
                "insert_allocated_index",
                insert * (cell("allocated_after_index") - cell("cursor_before")),
                0,
                rows,
            ),
            Identity(
                "insert_target_next_index",
                insert * (cell("target_after_next_index") - cell("cursor_before")),
                0,
                rows,
            ),
        )
    )
    for byte in range(64):
        identities.extend(
            (
                Identity(
                    f"insert_value_before_zero_{byte}",
                    insert * cell(f"value_before_{byte}"),
                    0,
                    rows,
                ),
                Identity(
                    f"insert_target_key_stable_{byte}",
                    insert
                    * (
                        cell(f"target_after_key_{byte}")
                        - cell(f"target_before_key_{byte}")
                    ),
                    0,
                    rows,
                ),
                Identity(
                    f"insert_target_value_stable_{byte}",
                    insert
                    * (
                        cell(f"target_after_value_{byte}")
                        - cell(f"target_before_value_{byte}")
                    ),
                    0,
                    rows,
                ),
                Identity(
                    f"insert_target_next_key_{byte}",
                    insert * (cell(f"target_after_next_key_{byte}") - cell(f"key_{byte}")),
                    0,
                    rows,
                ),
                Identity(
                    f"insert_allocated_key_{byte}",
                    insert * (cell(f"allocated_after_key_{byte}") - cell(f"key_{byte}")),
                    0,
                    rows,
                ),
                Identity(
                    f"insert_allocated_value_{byte}",
                    insert
                    * (cell(f"allocated_after_value_{byte}") - cell(f"value_after_{byte}")),
                    0,
                    rows,
                ),
                Identity(
                    f"insert_allocated_next_key_{byte}",
                    insert
                    * (
                        cell(f"allocated_after_next_key_{byte}")
                        - cell(f"target_before_next_key_{byte}")
                    ),
                    0,
                    rows,
                ),
                Identity(
                    f"update_key_{byte}",
                    update * (cell(f"target_before_key_{byte}") - cell(f"key_{byte}")),
                    0,
                    rows,
                ),
                Identity(
                    f"update_target_after_key_{byte}",
                    update * (cell(f"target_after_key_{byte}") - cell(f"key_{byte}")),
                    0,
                    rows,
                ),
                Identity(
                    f"update_value_before_{byte}",
                    update
                    * (cell(f"target_before_value_{byte}") - cell(f"value_before_{byte}")),
                    0,
                    rows,
                ),
                Identity(
                    f"update_value_after_{byte}",
                    update
                    * (cell(f"target_after_value_{byte}") - cell(f"value_after_{byte}")),
                    0,
                    rows,
                ),
                Identity(
                    f"update_next_key_{byte}",
                    update
                    * (
                        cell(f"target_after_next_key_{byte}")
                        - cell(f"target_before_next_key_{byte}")
                    ),
                    0,
                    rows,
                ),
            )
        )
        incoming_lower: Expr = const(1) if byte == 63 else cell(f"lower_borrow_{byte + 1}")
        incoming_upper: Expr = const(1) if byte == 63 else cell(f"upper_borrow_{byte + 1}")
        identities.extend(
            (
                Identity(
                    f"lower_borrow_boolean_{byte}",
                    boolean(cell(f"lower_borrow_{byte}")),
                    0,
                    rows,
                ),
                Identity(
                    f"upper_borrow_boolean_{byte}",
                    boolean(cell(f"upper_borrow_{byte}")),
                    0,
                    rows,
                ),
                Identity(
                    f"insert_lower_order_{byte}",
                    insert
                    * (
                        cell(f"key_{byte}")
                        - cell(f"target_before_key_{byte}")
                        - incoming_lower
                        + 256 * cell(f"lower_borrow_{byte}")
                        - cell(f"lower_diff_{byte}")
                    ),
                    0,
                    rows,
                ),
                Identity(
                    f"insert_upper_order_{byte}",
                    insert
                    * (
                        cell(f"target_before_next_key_{byte}")
                        - cell(f"key_{byte}")
                        - incoming_upper
                        + 256 * cell(f"upper_borrow_{byte}")
                        - cell(f"upper_diff_{byte}")
                    ),
                    0,
                    rows,
                ),
                Identity(
                    f"update_lower_witness_zero_{byte}",
                    update
                    * (
                        cell(f"lower_diff_{byte}") + cell(f"lower_borrow_{byte}")
                    ),
                    0,
                    rows,
                ),
                Identity(
                    f"update_upper_witness_zero_{byte}",
                    update
                    * (
                        cell(f"upper_diff_{byte}") + cell(f"upper_borrow_{byte}")
                    ),
                    0,
                    rows,
                ),
            )
        )
    identities.extend(
        (
            Identity("insert_lower_no_underflow", insert * cell("lower_borrow_0"), 0, rows),
            Identity("insert_upper_no_underflow", insert * cell("upper_borrow_0"), 0, rows),
            Identity(
                "insert_allocated_next_index",
                insert
                * (
                    cell("allocated_after_next_index")
                    - cell("target_before_next_index")
                ),
                0,
                rows,
            ),
            Identity(
                "update_next_index",
                update
                * (
                    cell("target_after_next_index")
                    - cell("target_before_next_index")
                ),
                0,
                rows,
            ),
        )
    )
    trace = TraceTable("ordered_map_operation", freeze_columns(columns))
    table = AirTable(
        trace.name,
        tuple(trace.columns),
        rows,
        tuple(identities),
        MappingProxyType({"operation_index": tuple(range(rows))}),
    )
    return table, trace, byte_names


def _memory_table(
    witness: OrderedMapBatchWitness,
) -> tuple[AirTable, TraceTable, set[str]]:
    columns: dict[str, list[int]] = {}
    byte_names: set[str] = set()
    accesses = witness.memory_accesses
    for row, access in enumerate(accesses):
        _append_u32(columns, byte_names, "position", access.position)
        _append(columns, "operation_index", access.operation_index)
        _append(columns, "access_kind", access.access_kind)
        _append(columns, "access_order", 2 * access.operation_index + access.access_kind)
        _append_leaf(columns, byte_names, "before", access.before)
        _append_leaf(columns, byte_names, "after", access.after)
        same_next = row + 1 < len(accesses) and accesses[row + 1].position == access.position
        _append(columns, "same_next", int(same_next))
        _append(columns, "first", int(row == 0 or accesses[row - 1].position != access.position))
        _append(columns, "last", int(not same_next))
        if row + 1 < len(accesses) and not same_next:
            position_delta = accesses[row + 1].position - access.position
        else:
            position_delta = 0
        _append_u32(columns, byte_names, "position_delta", position_delta)
        _append(
            columns,
            "position_delta_inverse",
            0 if position_delta == 0 else pow(position_delta, -1, (1 << 31) - 1),
        )
        if same_next:
            access_delta = (
                2 * accesses[row + 1].operation_index
                + accesses[row + 1].access_kind
                - (2 * access.operation_index + access.access_kind)
            )
        else:
            access_delta = 0
        _append_u32(columns, byte_names, "access_delta", access_delta)
        _append(
            columns,
            "access_delta_inverse",
            0 if access_delta == 0 else pow(access_delta, -1, (1 << 31) - 1),
        )

    rows = len(accesses)
    identities: list[Identity] = [
        Identity("access_kind_boolean", boolean(cell("access_kind")), 0, rows),
        Identity("same_next_boolean", boolean(cell("same_next")), 0, rows),
        Identity("first_boolean", boolean(cell("first")), 0, rows),
        Identity("last_boolean", boolean(cell("last")), 0, rows),
        Identity("last_derivation", cell("last") - (1 - cell("same_next")), 0, rows),
        Identity(
            "access_order_derivation",
            cell("access_order") - 2 * cell("operation_index") - cell("access_kind"),
            0,
            rows,
        ),
        *_u24_identities("position", rows),
        *_u24_identities("position_delta", rows),
        *_u24_identities("access_delta", rows),
        *_leaf_identities("before", rows),
        *_leaf_identities("after", rows),
        Identity("memory_first_boundary", cell("first") - 1, 0, 1, "boundary"),
        Identity("memory_last_boundary", cell("last") - 1, rows - 1, rows, "boundary"),
        Identity(
            "memory_terminal_position_delta",
            cell("position_delta"),
            rows - 1,
            rows,
            "boundary",
        ),
        Identity(
            "memory_terminal_position_inverse",
            cell("position_delta_inverse"),
            rows - 1,
            rows,
            "boundary",
        ),
        Identity(
            "memory_terminal_access_delta",
            cell("access_delta"),
            rows - 1,
            rows,
            "boundary",
        ),
        Identity(
            "memory_terminal_access_inverse",
            cell("access_delta_inverse"),
            rows - 1,
            rows,
            "boundary",
        ),
    ]
    if rows > 1:
        identities.extend(
            (
                Identity(
                    "memory_position_order",
                    cell("position", 1) - cell("position") - cell("position_delta"),
                    0,
                    rows - 1,
                    "transition",
                ),
                Identity(
                    "memory_position_delta_zero_iff_same",
                    cell("position_delta") * cell("position_delta_inverse")
                    - (1 - cell("same_next")),
                    0,
                    rows - 1,
                ),
                Identity(
                    "memory_same_position_inverse_zero",
                    cell("same_next") * cell("position_delta_inverse"),
                    0,
                    rows - 1,
                ),
                Identity(
                    "memory_access_order",
                    cell("same_next")
                    * (
                        cell("access_order", 1)
                        - cell("access_order")
                        - cell("access_delta")
                    ),
                    0,
                    rows - 1,
                    "transition",
                ),
                Identity(
                    "memory_access_delta_nonzero",
                    cell("same_next")
                    * (
                        cell("access_delta") * cell("access_delta_inverse") - 1
                    ),
                    0,
                    rows - 1,
                ),
                Identity(
                    "memory_access_delta_padding",
                    (1 - cell("same_next")) * cell("access_delta"),
                    0,
                    rows - 1,
                ),
                Identity(
                    "memory_access_inverse_padding",
                    (1 - cell("same_next")) * cell("access_delta_inverse"),
                    0,
                    rows - 1,
                ),
                Identity(
                    "memory_first_transition",
                    cell("first", 1) - (1 - cell("same_next")),
                    0,
                    rows - 1,
                    "transition",
                ),
            )
        )
        for column in _leaf_columns("after"):
            before_column = column.replace("after", "before", 1)
            identities.append(
                Identity(
                    f"memory_chain_{column}",
                    cell("same_next")
                    * (cell(column) - cell(before_column, 1)),
                    0,
                    rows - 1,
                    "transition",
                )
            )
    trace = TraceTable("ordered_map_memory", freeze_columns(columns))
    return (
        AirTable(trace.name, tuple(trace.columns), rows, tuple(identities)),
        trace,
        byte_names,
    )


def _endpoint_table(
    witness: OrderedMapBatchWitness,
    schedule: OrderedMapBatchSchedule,
) -> tuple[AirTable, TraceTable, set[str]]:
    columns: dict[str, list[int]] = {}
    byte_names: set[str] = set()
    for row in range(schedule.position_rows):
        live = row < len(witness.positions)
        _append(columns, "live", int(live))
        position = witness.positions[row] if live else 0
        _append_u32(columns, byte_names, "position", position)
        before = witness.before_leaves[row] if live else None
        after = witness.after_leaves[row] if live else None
        _append_leaf(columns, byte_names, "before", before)
        _append_leaf(columns, byte_names, "after", after)
        before_digest = ZERO_512 if before is None else before.digest(witness.map_domain)
        after_digest = ZERO_512 if after is None else after.digest(witness.map_domain)
        _append_bytes(columns, byte_names, "before_digest", before_digest)
        _append_bytes(columns, byte_names, "after_digest", after_digest)
        if live and row + 1 < len(witness.positions):
            gap = witness.positions[row + 1] - position - 1
        else:
            gap = 0
        _append_u32(columns, byte_names, "sort_gap", gap)
    rows = schedule.position_rows
    identities: list[Identity] = [
        Identity("endpoint_live_boolean", boolean(cell("live")), 0, rows),
        *_u24_identities("position", rows),
        *_u24_identities("sort_gap", rows),
        *_leaf_identities("before", rows),
        *_leaf_identities("after", rows),
    ]
    for phase in ("before", "after"):
        absent = 1 - cell(f"{phase}_present")
        for byte in range(64):
            identities.append(
                Identity(
                    f"endpoint_{phase}_absent_digest_{byte}",
                    absent * cell(f"{phase}_digest_{byte}"),
                    0,
                    rows,
                )
            )
    padding_columns = (
        "position",
        *(_leaf_columns("before")),
        *(_leaf_columns("after")),
        *(f"before_digest_{index}" for index in range(64)),
        *(f"after_digest_{index}" for index in range(64)),
        "sort_gap",
    )
    for name in padding_columns:
        identities.append(
            Identity(f"endpoint_padding_{name}", (1 - cell("live")) * cell(name), 0, rows)
        )
    if rows > 1:
        identities.extend(
            (
                Identity(
                    "endpoint_live_prefix",
                    cell("live", 1) * (1 - cell("live")),
                    0,
                    rows - 1,
                    "transition",
                ),
                Identity(
                    "endpoint_position_order",
                    cell("live", 1)
                    * (
                        cell("position", 1)
                        - cell("position")
                        - 1
                        - cell("sort_gap")
                    ),
                    0,
                    rows - 1,
                    "transition",
                ),
                Identity(
                    "endpoint_terminal_gap_transition",
                    (1 - cell("live", 1)) * cell("sort_gap"),
                    0,
                    rows - 1,
                    "transition",
                ),
            )
        )
    identities.append(
        Identity(
            "endpoint_terminal_gap_boundary",
            cell("sort_gap"),
            rows - 1,
            rows,
            "boundary",
        )
    )
    trace = TraceTable("ordered_map_endpoint", freeze_columns(columns))
    return (
        AirTable(trace.name, tuple(trace.columns), rows, tuple(identities)),
        trace,
        byte_names,
    )


def _node_rows(
    witness: OrderedMapBatchWitness,
) -> tuple[_NodeRow, ...]:
    proof = {(value.height, value.index): value.digest_512 for value in witness.proof_nodes}
    rows: list[_NodeRow] = []
    for phase, leaves in enumerate((witness.before_leaves, witness.after_leaves)):
        current = {
            position: ZERO_512 if leaf is None else leaf.digest(witness.map_domain)
            for position, leaf in zip(witness.positions, leaves, strict=True)
        }
        for height in range(64):
            next_level: dict[int, bytes] = {}
            for parent in sorted({index >> 1 for index in current}):
                children = []
                for child in (parent * 2, parent * 2 + 1):
                    children.append(
                        current[child]
                        if child in current
                        else proof[(height, child)]
                    )
                digest = sha3_512(
                    ordered_map_node_preimage(
                        witness.map_domain,
                        children[0],
                        children[1],
                        height,
                    )
                ).digest()
                rows.append(_NodeRow(phase, height, parent, children[0], children[1], digest))
                next_level[parent] = digest
            current = next_level
        expected = witness.inner_root_before if phase == 0 else witness.inner_root_after
        if current != {0: expected}:
            raise StructuralError("ordered_map_air_node_root_mismatch")
    return tuple(rows)


def _proof_table(
    witness: OrderedMapBatchWitness,
    schedule: OrderedMapBatchSchedule,
) -> tuple[AirTable, TraceTable, set[str]]:
    columns: dict[str, list[int]] = {}
    byte_names: set[str] = set()
    for row in range(schedule.proof_node_rows):
        live = row < len(witness.proof_nodes)
        node = witness.proof_nodes[row] if live else None
        height = 0 if node is None else node.height
        index = 0 if node is None else node.index
        _append(columns, "live", int(live))
        _append_u6(columns, "height", height)
        _append_u32(columns, byte_names, "index", index)
        _append(columns, "sort_key", (height << 24) + index if live else 0)
        _append_bytes(
            columns,
            byte_names,
            "digest",
            ZERO_512 if node is None else node.digest_512,
        )
        if live and row + 1 < len(witness.proof_nodes):
            next_node = witness.proof_nodes[row + 1]
            gap = ((next_node.height << 24) + next_node.index) - ((height << 24) + index) - 1
        else:
            gap = 0
        _append_u31(columns, byte_names, "sort_gap", gap)
    rows = schedule.proof_node_rows
    identities: list[Identity] = [
        Identity("proof_live_boolean", boolean(cell("live")), 0, rows),
        Identity(
            "proof_sort_key",
            cell("live") * (cell("sort_key") - (1 << 24) * cell("height") - cell("index")),
            0,
            rows,
        ),
        *_u6_identities("height", rows),
        *_u24_identities("index", rows),
        *_u31_identities("sort_gap", rows),
    ]
    for name in (
        "height",
        *(f"height_bit_{index}" for index in range(6)),
        "index",
        *(f"index_byte_{index}" for index in range(4)),
        "sort_key",
        *(f"digest_{index}" for index in range(64)),
        "sort_gap",
        *(f"sort_gap_byte_{index}" for index in range(4)),
    ):
        identities.append(
            Identity(f"proof_padding_{name}", (1 - cell("live")) * cell(name), 0, rows)
        )
    if rows > 1:
        identities.extend(
            (
                Identity(
                    "proof_live_prefix",
                    cell("live", 1) * (1 - cell("live")),
                    0,
                    rows - 1,
                    "transition",
                ),
                Identity(
                    "proof_canonical_order",
                    cell("live", 1)
                    * (
                        cell("sort_key", 1)
                        - cell("sort_key")
                        - 1
                        - cell("sort_gap")
                    ),
                    0,
                    rows - 1,
                    "transition",
                ),
                Identity(
                    "proof_terminal_gap_transition",
                    (1 - cell("live", 1)) * cell("sort_gap"),
                    0,
                    rows - 1,
                    "transition",
                ),
            )
        )
    identities.append(
        Identity(
            "proof_terminal_gap_boundary",
            cell("sort_gap"),
            rows - 1,
            rows,
            "boundary",
        )
    )
    trace = TraceTable("ordered_map_proof", freeze_columns(columns))
    return (
        AirTable(trace.name, tuple(trace.columns), rows, tuple(identities)),
        trace,
        byte_names,
    )


def _node_table(
    witness: OrderedMapBatchWitness,
    schedule: OrderedMapBatchSchedule,
) -> tuple[AirTable, TraceTable, set[str], tuple[_NodeRow, ...]]:
    materialized = _node_rows(witness)
    if len(materialized) > schedule.node_hash_rows:
        raise StructuralError("ordered_map_air_node_schedule_exceeded")
    columns: dict[str, list[int]] = {}
    byte_names: set[str] = set()
    for row in range(schedule.node_hash_rows):
        live = row < len(materialized)
        node = materialized[row] if live else None
        phase = 0 if node is None else node.phase
        height = 0 if node is None else node.height
        parent = 0 if node is None else node.parent
        _append(columns, "live", int(live))
        _append(columns, "phase", phase)
        _append_u6(columns, "height", height)
        _append_u32(columns, byte_names, "parent", parent)
        _append_u32(columns, byte_names, "left_index", 2 * parent if live else 0)
        _append_u32(columns, byte_names, "right_index", 2 * parent + 1 if live else 0)
        _append(columns, "is_root", int(live and height == 63))
        _append(columns, "root_live", int(live and height == 63))
        _append(columns, "non_root_live", int(live and height != 63))
        sort_key = (((phase * 64 + height) << 24) + parent) if live else 0
        _append(columns, "sort_key", sort_key)
        _append_bytes(columns, byte_names, "left", ZERO_512 if node is None else node.left)
        _append_bytes(columns, byte_names, "right", ZERO_512 if node is None else node.right)
        _append_bytes(columns, byte_names, "digest", ZERO_512 if node is None else node.digest)
        if live and row + 1 < len(materialized):
            next_node = materialized[row + 1]
            next_key = ((next_node.phase * 64 + next_node.height) << 24) + next_node.parent
            gap = next_key - sort_key - 1
        else:
            gap = 0
        _append_u31(columns, byte_names, "sort_gap", gap)
    rows = schedule.node_hash_rows
    identities: list[Identity] = [
        Identity("node_live_boolean", boolean(cell("live")), 0, rows),
        Identity("node_phase_boolean", boolean(cell("phase")), 0, rows),
        Identity("node_root_boolean", boolean(cell("is_root")), 0, rows),
        Identity(
            "node_root_live",
            cell("root_live") - cell("live") * cell("is_root"),
            0,
            rows,
        ),
        Identity(
            "node_non_root_live",
            cell("non_root_live") - cell("live") * (1 - cell("is_root")),
            0,
            rows,
        ),
        Identity(
            "node_left_index",
            cell("live") * (cell("left_index") - 2 * cell("parent")),
            0,
            rows,
        ),
        Identity(
            "node_right_index",
            cell("live") * (cell("right_index") - 2 * cell("parent") - 1),
            0,
            rows,
        ),
        Identity(
            "node_root_height",
            cell("is_root") * (cell("height") - 63),
            0,
            rows,
        ),
        Identity(
            "node_sort_key",
            cell("live")
            * (
                cell("sort_key")
                - (1 << 24) * (64 * cell("phase") + cell("height"))
                - cell("parent")
            ),
            0,
            rows,
        ),
        *_u6_identities("height", rows),
        *_u24_identities("parent", rows),
        *_u24_identities("left_index", rows),
        *_u24_identities("right_index", rows),
        *_u31_identities("sort_gap", rows),
    ]
    for name in (
        "phase",
        "height",
        *(f"height_bit_{index}" for index in range(6)),
        "parent",
        *(f"parent_byte_{index}" for index in range(4)),
        "left_index",
        *(f"left_index_byte_{index}" for index in range(4)),
        "right_index",
        *(f"right_index_byte_{index}" for index in range(4)),
        "is_root",
        "root_live",
        "non_root_live",
        "sort_key",
        *(f"left_{index}" for index in range(64)),
        *(f"right_{index}" for index in range(64)),
        *(f"digest_{index}" for index in range(64)),
        "sort_gap",
        *(f"sort_gap_byte_{index}" for index in range(4)),
    ):
        identities.append(
            Identity(f"node_padding_{name}", (1 - cell("live")) * cell(name), 0, rows)
        )
    if rows > 1:
        identities.extend(
            (
                Identity(
                    "node_live_prefix",
                    cell("live", 1) * (1 - cell("live")),
                    0,
                    rows - 1,
                    "transition",
                ),
                Identity(
                    "node_canonical_order",
                    cell("live", 1)
                    * (
                        cell("sort_key", 1)
                        - cell("sort_key")
                        - 1
                        - cell("sort_gap")
                    ),
                    0,
                    rows - 1,
                    "transition",
                ),
                Identity(
                    "node_terminal_gap_transition",
                    (1 - cell("live", 1)) * cell("sort_gap"),
                    0,
                    rows - 1,
                    "transition",
                ),
            )
        )
    identities.append(
        Identity(
            "node_terminal_gap_boundary",
            cell("sort_gap"),
            rows - 1,
            rows,
            "boundary",
        )
    )
    trace = TraceTable("ordered_map_node", freeze_columns(columns))
    return (
        AirTable(trace.name, tuple(trace.columns), rows, tuple(identities)),
        trace,
        byte_names,
        materialized,
    )


def _state_table(
    witness: OrderedMapBatchWitness,
) -> tuple[AirTable, TraceTable, set[str]]:
    columns: dict[str, list[int]] = {}
    byte_names: set[str] = set()
    _append(columns, "map_domain", witness.map_domain[0])
    _append_u32(columns, byte_names, "cursor_before", witness.next_append_index_before)
    _append_u32(columns, byte_names, "cursor_after", witness.next_append_index_after)
    for prefix, value in (
        ("inner_root_before", witness.inner_root_before),
        ("inner_root_after", witness.inner_root_after),
        ("root_before", witness.root_before),
        ("root_after", witness.root_after),
    ):
        _append_bytes(columns, byte_names, prefix, value)
    trace = TraceTable("ordered_map_state", freeze_columns(columns))
    identities = (
        *_cursor_identities("cursor_before", 1),
        *_cursor_identities("cursor_after", 1),
    )
    return (
        AirTable(
            trace.name,
            tuple(trace.columns),
            1,
            identities,
            MappingProxyType({"map_domain": (witness.map_domain[0],)}),
        ),
        trace,
        byte_names,
    )


def _hash_table(
    witness: OrderedMapBatchWitness,
    calls: tuple[OrderedMapHashCall, ...],
    schedule: OrderedMapBatchSchedule,
) -> tuple[AirTable, TraceTable, set[str]]:
    columns: dict[str, list[int]] = {}
    byte_names: set[str] = set()
    fixed: dict[str, list[int]] = {
        "call_index": [],
        "family_leaf": [],
        "family_node": [],
        "family_header": [],
        "message_length": [],
        "same_family_next": [],
        **{f"message_enabled_{index}": [] for index in range(_HASH_MESSAGE_CAPACITY)},
        **{f"dummy_message_{index}": [] for index in range(_HASH_MESSAGE_CAPACITY)},
    }
    dummy_leaf = OrderedMapLeaf(0, ZERO_512, ZERO_512, MAX_512, 1)
    dummy_messages = {
        "leaf": ordered_map_leaf_preimage(witness.map_domain, dummy_leaf),
        "node": ordered_map_node_preimage(witness.map_domain, ZERO_512, ZERO_512, 0),
        "header": bytes(_HEADER_TAG_BYTES),
    }
    lengths = {"leaf": 212, "node": 141, "header": 84}
    for index, call in enumerate(calls):
        family_flags = {
            "family_leaf": int(call.family == "leaf"),
            "family_node": int(call.family == "node"),
            "family_header": int(call.family == "header"),
        }
        _append(columns, "call_index", index)
        _append(columns, "live", int(call.live))
        for name, value in family_flags.items():
            _append(columns, name, value)
        _append(columns, "message_length", lengths[call.family])
        padded = call.message + bytes(_HASH_MESSAGE_CAPACITY - len(call.message))
        _append_bytes(columns, byte_names, "message", padded)
        _append_bytes(columns, byte_names, "digest", call.digest_512)

        fixed["call_index"].append(index)
        for name, value in family_flags.items():
            fixed[name].append(value)
        fixed["message_length"].append(lengths[call.family])
        same_family_next = int(
            index + 1 < len(calls) and calls[index + 1].family == call.family
        )
        _append(columns, "same_family_next", same_family_next)
        fixed["same_family_next"].append(same_family_next)
        dummy = dummy_messages[call.family] + bytes(
            _HASH_MESSAGE_CAPACITY - len(dummy_messages[call.family])
        )
        for byte in range(_HASH_MESSAGE_CAPACITY):
            enabled = int(byte < lengths[call.family])
            _append(columns, f"message_enabled_{byte}", enabled)
            _append(columns, f"dummy_message_{byte}", dummy[byte])
            fixed[f"message_enabled_{byte}"].append(enabled)
            fixed[f"dummy_message_{byte}"].append(dummy[byte])
    rows = schedule.sha3_call_rows
    identities: list[Identity] = [
        Identity("hash_live_boolean", boolean(cell("live")), 0, rows),
        Identity(
            "hash_family_one_hot",
            cell("family_leaf") + cell("family_node") + cell("family_header") - 1,
            0,
            rows,
        ),
        Identity(
            "hash_header_always_live",
            cell("family_header") * (cell("live") - 1),
            0,
            rows,
        ),
    ]
    for byte in range(_HASH_MESSAGE_CAPACITY):
        identities.extend(
            (
                Identity(
                    f"hash_message_padding_{byte}",
                    (1 - cell(f"message_enabled_{byte}")) * cell(f"message_{byte}"),
                    0,
                    rows,
                ),
                Identity(
                    f"hash_dummy_message_{byte}",
                    (1 - cell("live"))
                    * (cell(f"message_{byte}") - cell(f"dummy_message_{byte}")),
                    0,
                    rows,
                ),
            )
        )
    if rows > 1:
        identities.append(
            Identity(
                "hash_family_live_prefix",
                cell("same_family_next")
                * cell("live", 1)
                * (1 - cell("live")),
                0,
                rows - 1,
                "transition",
            )
        )
    trace = TraceTable("ordered_map_hash_port", freeze_columns(columns))
    return (
        AirTable(
            trace.name,
            tuple(trace.columns),
            rows,
            tuple(identities),
            MappingProxyType({name: tuple(values) for name, values in fixed.items()}),
        ),
        trace,
        byte_names,
    )


def _padded_message(values: Sequence[Expr]) -> tuple[Expr, ...]:
    if len(values) > _HASH_MESSAGE_CAPACITY:
        raise StructuralError("ordered_map_air_hash_message_too_long")
    return (*values, *(const(0) for _ in range(_HASH_MESSAGE_CAPACITY - len(values))))


def _leaf_preimage_expr(prefix: str, map_domain: int) -> tuple[Expr, ...]:
    tag = b"BL/PQ/MAP4\x00" + bytes((map_domain,))
    values: tuple[Expr, ...] = (
        *(const(value) for value in tag),
        *(cell(f"{prefix}_key_{index}") for index in range(64)),
        *(cell(f"{prefix}_value_{index}") for index in range(64)),
        *(cell(f"{prefix}_next_key_{index}") for index in range(64)),
        *(cell(f"{prefix}_next_index_u64_{index}") for index in range(8)),
    )
    if len(values) != _LEAF_TAG_BYTES:
        raise AssertionError("ordered_map_air_leaf_preimage_width")
    return _padded_message(values)


def _node_preimage_expr(map_domain: int) -> tuple[Expr, ...]:
    tag = b"BL/PQ/MAP4\x01" + bytes((map_domain,))
    values: tuple[Expr, ...] = (
        *(const(value) for value in tag),
        cell("height"),
        *(cell(f"left_{index}") for index in range(64)),
        *(cell(f"right_{index}") for index in range(64)),
    )
    if len(values) != _NODE_TAG_BYTES:
        raise AssertionError("ordered_map_air_node_preimage_width")
    return _padded_message(values)


def _header_preimage_expr(phase: str, map_domain: int) -> tuple[Expr, ...]:
    tag = b"BL/PQ/MAP4\x02" + bytes((map_domain,))
    values: tuple[Expr, ...] = (
        *(const(value) for value in tag),
        *(const(0) for _ in range(4)),
        *(cell(f"cursor_{phase}_byte_{index}") for index in range(4)),
        *(cell(f"inner_root_{phase}_{index}") for index in range(64)),
    )
    if len(values) != _HEADER_TAG_BYTES:
        raise AssertionError("ordered_map_air_header_preimage_width")
    return _padded_message(values)


def _hash_values(message: tuple[Expr, ...], digest_prefix: str, length: int) -> tuple[Expr, ...]:
    return (
        const(length),
        *message,
        *(cell(f"{digest_prefix}_{index}") for index in range(64)),
    )


def _lookups(
    witness: OrderedMapBatchWitness,
    schedule: OrderedMapBatchSchedule,
    traces: Mapping[str, TraceTable],
    byte_columns: Mapping[str, set[str]],
) -> tuple[LookupArgument, ...]:
    operation_rows = traces["ordered_map_operation"].rows
    memory_rows = traces["ordered_map_memory"].rows
    endpoint_rows = traces["ordered_map_endpoint"].rows
    proof_rows = traces["ordered_map_proof"].rows
    node_rows = traces["ordered_map_node"].rows
    hash_rows = traces["ordered_map_hash_port"].rows
    domain = witness.map_domain[0]

    empty_leaf = (const(0), const(0), *(const(0) for _ in range(64 * 3)), const(0))
    operation_memory = LookupArgument(
        "ordered_map_operation_memory",
        (
            LookupSide(
                "ordered_map_operation",
                const(1),
                (
                    cell("operation_index"),
                    const(0),
                    cell("target_before_index"),
                    *_leaf_expr("target_before"),
                    *_leaf_expr("target_after"),
                ),
                0,
                operation_rows,
            ),
            LookupSide(
                "ordered_map_operation",
                const(1),
                (
                    cell("operation_index"),
                    const(1),
                    cell("cursor_before"),
                    *empty_leaf,
                    *_leaf_expr("allocated_after"),
                ),
                0,
                operation_rows,
            ),
        ),
        (
            LookupSide(
                "ordered_map_memory",
                const(1),
                (
                    cell("operation_index"),
                    cell("access_kind"),
                    cell("position"),
                    *_leaf_expr("before"),
                    *_leaf_expr("after"),
                ),
                0,
                memory_rows,
            ),
        ),
    )
    cursor_binding = LookupArgument(
        "ordered_map_cursor_binding",
        (
            LookupSide(
                "ordered_map_operation",
                const(1),
                (const(0), cell("cursor_before")),
                0,
                1,
            ),
            LookupSide(
                "ordered_map_operation",
                const(1),
                (const(1), cell("cursor_after")),
                operation_rows - 1,
                operation_rows,
            ),
        ),
        (
            LookupSide(
                "ordered_map_state",
                const(1),
                (const(0), cell("cursor_before")),
                0,
                1,
            ),
            LookupSide(
                "ordered_map_state",
                const(1),
                (const(1), cell("cursor_after")),
                0,
                1,
            ),
        ),
    )
    endpoint_before = LookupArgument(
        "ordered_map_endpoint_before",
        (
            LookupSide(
                "ordered_map_endpoint",
                cell("live"),
                (cell("position"), *_leaf_expr("before")),
                0,
                endpoint_rows,
            ),
        ),
        (
            LookupSide(
                "ordered_map_memory",
                cell("first"),
                (cell("position"), *_leaf_expr("before")),
                0,
                memory_rows,
            ),
        ),
    )
    endpoint_after = LookupArgument(
        "ordered_map_endpoint_after",
        (
            LookupSide(
                "ordered_map_endpoint",
                cell("live"),
                (cell("position"), *_leaf_expr("after")),
                0,
                endpoint_rows,
            ),
        ),
        (
            LookupSide(
                "ordered_map_memory",
                cell("last"),
                (cell("position"), *_leaf_expr("after")),
                0,
                memory_rows,
            ),
        ),
    )

    child_sources = (
        LookupSide(
            "ordered_map_node",
            cell("live"),
            (
                cell("phase"),
                cell("height"),
                cell("left_index"),
                *(cell(f"left_{index}") for index in range(64)),
            ),
            0,
            node_rows,
        ),
        LookupSide(
            "ordered_map_node",
            cell("live"),
            (
                cell("phase"),
                cell("height"),
                cell("right_index"),
                *(cell(f"right_{index}") for index in range(64)),
            ),
            0,
            node_rows,
        ),
    )
    child_destinations = (
        LookupSide(
            "ordered_map_endpoint",
            cell("live"),
            (
                const(0),
                const(0),
                cell("position"),
                *(cell(f"before_digest_{index}") for index in range(64)),
            ),
            0,
            endpoint_rows,
        ),
        LookupSide(
            "ordered_map_endpoint",
            cell("live"),
            (
                const(1),
                const(0),
                cell("position"),
                *(cell(f"after_digest_{index}") for index in range(64)),
            ),
            0,
            endpoint_rows,
        ),
        LookupSide(
            "ordered_map_proof",
            cell("live"),
            (
                const(0),
                cell("height"),
                cell("index"),
                *(cell(f"digest_{index}") for index in range(64)),
            ),
            0,
            proof_rows,
        ),
        LookupSide(
            "ordered_map_proof",
            cell("live"),
            (
                const(1),
                cell("height"),
                cell("index"),
                *(cell(f"digest_{index}") for index in range(64)),
            ),
            0,
            proof_rows,
        ),
        LookupSide(
            "ordered_map_node",
            cell("non_root_live"),
            (
                cell("phase"),
                cell("height") + 1,
                cell("parent"),
                *(cell(f"digest_{index}") for index in range(64)),
            ),
            0,
            node_rows,
        ),
    )
    node_topology = LookupArgument(
        "ordered_map_node_topology",
        child_sources,
        child_destinations,
    )
    root_binding = LookupArgument(
        "ordered_map_inner_root_binding",
        (
            LookupSide(
                "ordered_map_node",
                cell("root_live"),
                (
                    cell("phase"),
                    *(cell(f"digest_{index}") for index in range(64)),
                ),
                0,
                node_rows,
            ),
        ),
        (
            LookupSide(
                "ordered_map_state",
                const(1),
                (const(0), *(cell(f"inner_root_before_{index}") for index in range(64))),
                0,
                1,
            ),
            LookupSide(
                "ordered_map_state",
                const(1),
                (const(1), *(cell(f"inner_root_after_{index}") for index in range(64))),
                0,
                1,
            ),
        ),
    )

    hash_values = (
        cell("message_length"),
        *(cell(f"message_{index}") for index in range(_HASH_MESSAGE_CAPACITY)),
        *(cell(f"digest_{index}") for index in range(64)),
    )
    leaf_hash_destination = LookupSide(
        "ordered_map_hash_port",
        cell("live"),
        hash_values,
        0,
        schedule.leaf_hash_rows,
    )
    node_hash_destination = LookupSide(
        "ordered_map_hash_port",
        cell("live"),
        hash_values,
        schedule.leaf_hash_rows,
        schedule.leaf_hash_rows + schedule.node_hash_rows,
    )
    header_hash_destination = LookupSide(
        "ordered_map_hash_port",
        cell("live"),
        hash_values,
        schedule.leaf_hash_rows + schedule.node_hash_rows,
        hash_rows,
    )
    leaf_hashes = LookupArgument(
        "ordered_map_leaf_hash_ports",
        tuple(
            LookupSide(
                "ordered_map_endpoint",
                cell(f"{phase}_present"),
                _hash_values(
                    _leaf_preimage_expr(phase, domain),
                    f"{phase}_digest",
                    _LEAF_TAG_BYTES,
                ),
                0,
                endpoint_rows,
            )
            for phase in ("before", "after")
        ),
        (leaf_hash_destination,),
    )
    node_hashes = LookupArgument(
        "ordered_map_node_hash_ports",
        (
            LookupSide(
                "ordered_map_node",
                cell("live"),
                _hash_values(_node_preimage_expr(domain), "digest", _NODE_TAG_BYTES),
                0,
                node_rows,
            ),
        ),
        (node_hash_destination,),
    )
    header_hashes = LookupArgument(
        "ordered_map_header_hash_ports",
        tuple(
            LookupSide(
                "ordered_map_state",
                const(1),
                _hash_values(
                    _header_preimage_expr(phase, domain),
                    f"root_{phase}",
                    _HEADER_TAG_BYTES,
                ),
                0,
                1,
            )
            for phase in ("before", "after")
        ),
        (header_hash_destination,),
    )

    byte_sources = tuple(
        LookupSide(
            table,
            const(1),
            (cell(column),),
            0,
            traces[table].rows,
        )
        for table, columns in byte_columns.items()
        for column in sorted(columns)
    )
    byte_range = LookupArgument(
        "ordered_map_byte_range",
        byte_sources,
        (
            LookupSide(
                "ordered_map_byte",
                const(1),
                (cell("value"),),
                0,
                256,
                cell("multiplicity"),
            ),
        ),
    )
    return (
        operation_memory,
        cursor_binding,
        endpoint_before,
        endpoint_after,
        node_topology,
        root_binding,
        leaf_hashes,
        node_hashes,
        header_hashes,
        byte_range,
    )


def build_ordered_map_batch_executable_air(
    witness: OrderedMapBatchWitness,
    schedule: OrderedMapBatchSchedule,
) -> OrderedMapBatchAirInstance:
    require_ordered_map_batch_fits_schedule(witness, schedule)
    hash_calls = build_ordered_map_hash_schedule(witness, schedule)

    tables: list[AirTable] = []
    traces: dict[str, TraceTable] = {}
    byte_columns: dict[str, set[str]] = {}
    operation_builder = _operation_table(witness)
    builders = (
        operation_builder,
        _memory_table(witness),
        _endpoint_table(witness, schedule),
        _proof_table(witness, schedule),
        _node_table(witness, schedule)[:3],
        _state_table(witness),
        _hash_table(witness, hash_calls, schedule),
    )
    for table, trace, byte_names in builders:
        tables.append(table)
        traces[trace.name] = trace
        byte_columns[trace.name] = byte_names

    byte_counts: Counter[int] = Counter()
    for table_name, names in byte_columns.items():
        trace = traces[table_name]
        for name in names:
            byte_counts.update(trace.columns[name])
    byte_values = tuple(range(256))
    byte_trace = TraceTable(
        "ordered_map_byte",
        freeze_columns(
            {
                "value": byte_values,
                "multiplicity": tuple(byte_counts[value] for value in byte_values),
            }
        ),
    )
    byte_table = AirTable(
        byte_trace.name,
        tuple(byte_trace.columns),
        256,
        (),
        MappingProxyType({"value": byte_values}),
    )
    tables.append(byte_table)
    traces[byte_trace.name] = byte_trace

    frozen_traces = MappingProxyType(traces)
    return OrderedMapBatchAirInstance(
        AirProgram(
            PROGRAM_ID,
            tuple(tables),
            _lookups(witness, schedule, frozen_traces, byte_columns),
        ),
        frozen_traces,
        witness,
        schedule,
        hash_calls,
    )


def build_ordered_map_batch_sha3_executable_air(
    witness: OrderedMapBatchWitness,
    schedule: OrderedMapBatchSchedule,
    *,
    interface_only: bool = False,
) -> OrderedMapBatchAirInstance:
    """Compose every fixed hash-port row with the exact SHA3-512 AIR.

    The composition includes dummy rows.  Consequently the schedule does not
    reveal the number of live leaves or nodes through the number of Keccak
    calls, and no host-computed digest remains a trusted relation boundary.
    Large K128 traces should be streamed by the Rust backend; this Python
    builder is the executable, independently serializable specification.
    """

    ordered_map = build_ordered_map_batch_executable_air(witness, schedule)
    calls = tuple(
        Sha3Call(
            f"map_hash_{call.ordinal}",
            call.message,
            len(call.message),
        )
        for call in ordered_map.hash_calls
    )
    sha3 = (
        build_application_sha3_interface_air(calls)
        if interface_only
        else build_application_sha3_executable_air(calls)
    )

    message_sources: list[LookupSide] = []
    family_ranges = (
        (0, schedule.leaf_hash_rows, _LEAF_TAG_BYTES),
        (
            schedule.leaf_hash_rows,
            schedule.leaf_hash_rows + schedule.node_hash_rows,
            _NODE_TAG_BYTES,
        ),
        (
            schedule.leaf_hash_rows + schedule.node_hash_rows,
            schedule.sha3_call_rows,
            _HEADER_TAG_BYTES,
        ),
    )
    for row_start, row_stop, message_length in family_ranges:
        for position in range(message_length):
            message_sources.append(
                LookupSide(
                    "ordered_map_hash_port",
                    const(1),
                    (
                        cell("call_index"),
                        const(position),
                        cell(f"message_{position}"),
                    ),
                    row_start,
                    row_stop,
                )
            )
    composition_lookups = (
        LookupArgument(
            "ordered_map_sha3_message_binding",
            tuple(message_sources),
            (
                LookupSide(
                    "sha3_message_batch",
                    cell("live"),
                    (cell("call_index"), cell("position"), cell("value")),
                    0,
                    sha3.traces["sha3_message_batch"].rows,
                ),
            ),
        ),
        LookupArgument(
            "ordered_map_sha3_digest_binding",
            (
                LookupSide(
                    "ordered_map_hash_port",
                    const(1),
                    (
                        cell("call_index"),
                        *(cell(f"digest_{index}") for index in range(64)),
                    ),
                    0,
                    schedule.sha3_call_rows,
                ),
            ),
            (
                LookupSide(
                    "sha3_digest_batch",
                    const(1),
                    (
                        cell("call_index"),
                        *(cell(f"value_{index}") for index in range(64)),
                    ),
                    0,
                    sha3.traces["sha3_digest_batch"].rows,
                ),
            ),
        ),
    )
    traces = MappingProxyType({**dict(ordered_map.traces), **dict(sha3.traces)})
    return OrderedMapBatchAirInstance(
        AirProgram(
            COMPOSED_PROGRAM_ID,
            (*ordered_map.program.tables, *sha3.program.tables),
            (
                *ordered_map.program.lookups,
                *sha3.program.lookups,
                *composition_lookups,
            ),
        ),
        traces,
        witness,
        schedule,
        ordered_map.hash_calls,
        hashes_constrained=not interface_only,
        hash_ports_constrained=interface_only,
        sha3_interface_only=interface_only,
    )


__all__ = [
    "OrderedMapBatchAirInstance",
    "build_ordered_map_batch_executable_air",
    "build_ordered_map_batch_sha3_executable_air",
]
