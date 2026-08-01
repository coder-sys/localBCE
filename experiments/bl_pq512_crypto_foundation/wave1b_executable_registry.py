"""Exact Wave 1B registry derived only from executable Wave 1A AIR objects.

This module is the replacement for the historical R33 16-table worksheet.
It inventories actual trace cells, derived identity degrees, lookup sides,
public bindings, JSON program commitments, trace commitments, and the bounded
cross-language binary IR.  It deliberately does not guess PCS expansion,
interaction packing, hiding columns, FRI parameters, or a proof-suite ID.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
from typing import Final, Mapping, Sequence

from experiments.fixed_shape_claim_air.air_binary_ir import (
    air_binary_commitment,
    encode_air_execution,
)
from experiments.fixed_shape_claim_air.executable_air import (
    AirProgram,
    TraceTable,
    evaluate_program,
)
from experiments.fixed_shape_claim_air.semantics import StructuralError


EXECUTABLE_REGISTRY_STATUS: Final[str] = (
    "WAVE1B_EXECUTABLE_AIR_REGISTRY_EXACT_PRE_PCS_NONACTIVATING"
)
EXECUTABLE_REGISTRY_DOMAIN: Final[bytes] = (
    b"BL/PQ512/WAVE1B/EXECUTABLE-AIR-REGISTRY/v1\x00"
)


def _ascii(label: str, value: object) -> bytes:
    if type(value) is not str:
        raise TypeError(f"wave1b_registry_{label}_string_required")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError(f"wave1b_registry_{label}_ascii_required") from exc
    if not encoded or len(encoded) > 0xFFFF:
        raise ValueError(f"wave1b_registry_{label}_length_invalid")
    return encoded


def _wide(label: str, value: object) -> bytes:
    if type(value) is not bytes:
        raise TypeError(f"wave1b_registry_{label}_bytes_required")
    if len(value) != 64 or not any(value):
        raise ValueError(f"wave1b_registry_{label}_invalid")
    return value


def _next_power_of_two(value: int) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError("wave1b_registry_row_count_invalid")
    return 1 << (value - 1).bit_length()


@dataclass(frozen=True, slots=True)
class ExecutableTableDimensions:
    segment_id: str
    table_name: str
    logical_rows: int
    padded_rows: int
    trace_columns: int
    fixed_columns: int
    identity_count: int
    maximum_identity_degree: int
    lookup_argument_count: int
    lookup_side_count: int
    lookup_coordinate_width_sum: int
    maximum_lookup_coordinate_width: int
    lookup_row_capacity: int
    public_input_count: int
    private: bool

    def __post_init__(self) -> None:
        _ascii("segment_id", self.segment_id)
        _ascii("table_name", self.table_name)
        integers = (
            self.logical_rows,
            self.padded_rows,
            self.trace_columns,
            self.fixed_columns,
            self.identity_count,
            self.maximum_identity_degree,
            self.lookup_argument_count,
            self.lookup_side_count,
            self.lookup_coordinate_width_sum,
            self.maximum_lookup_coordinate_width,
            self.lookup_row_capacity,
            self.public_input_count,
        )
        if any(type(value) is not int or value < 0 for value in integers):
            raise ValueError("wave1b_registry_table_dimension_invalid")
        if (
            self.logical_rows == 0
            or self.padded_rows != _next_power_of_two(self.logical_rows)
            or self.trace_columns == 0
            or self.fixed_columns > self.trace_columns
            or type(self.private) is not bool
        ):
            raise ValueError("wave1b_registry_table_shape_invalid")

    @property
    def qualified_name(self) -> str:
        return f"{self.segment_id}/{self.table_name}"

    def canonical_bytes(self) -> bytes:
        segment = self.segment_id.encode("ascii")
        table = self.table_name.encode("ascii")
        return b"".join(
            (
                len(segment).to_bytes(2, "big"),
                segment,
                len(table).to_bytes(2, "big"),
                table,
                self.logical_rows.to_bytes(8, "big"),
                self.padded_rows.to_bytes(8, "big"),
                self.trace_columns.to_bytes(4, "big"),
                self.fixed_columns.to_bytes(4, "big"),
                self.identity_count.to_bytes(8, "big"),
                self.maximum_identity_degree.to_bytes(4, "big"),
                self.lookup_argument_count.to_bytes(4, "big"),
                self.lookup_side_count.to_bytes(4, "big"),
                self.lookup_coordinate_width_sum.to_bytes(8, "big"),
                self.maximum_lookup_coordinate_width.to_bytes(4, "big"),
                self.lookup_row_capacity.to_bytes(8, "big"),
                self.public_input_count.to_bytes(4, "big"),
                bytes((int(self.private),)),
            )
        )


@dataclass(frozen=True, slots=True)
class ExecutableAirSegment:
    segment_id: str
    program_id: str
    program_commitment_512: bytes
    trace_commitment_512: bytes
    binary_ir_commitment_512: bytes
    binary_ir_length: int
    identities_evaluated: int
    lookup_messages_evaluated: int
    maximum_degree: int
    tables: tuple[ExecutableTableDimensions, ...]

    def __post_init__(self) -> None:
        _ascii("segment_id", self.segment_id)
        _ascii("program_id", self.program_id)
        _wide("program_commitment", self.program_commitment_512)
        _wide("trace_commitment", self.trace_commitment_512)
        _wide("binary_ir_commitment", self.binary_ir_commitment_512)
        if (
            type(self.binary_ir_length) is not int
            or self.binary_ir_length <= 0
            or type(self.identities_evaluated) is not int
            or self.identities_evaluated < 0
            or type(self.lookup_messages_evaluated) is not int
            or self.lookup_messages_evaluated < 0
            or type(self.maximum_degree) is not int
            or self.maximum_degree < 0
            or type(self.tables) is not tuple
            or not self.tables
            or any(table.segment_id != self.segment_id for table in self.tables)
            or len({table.table_name for table in self.tables}) != len(self.tables)
            or max(table.maximum_identity_degree for table in self.tables)
            != self.maximum_degree
        ):
            raise ValueError("wave1b_registry_segment_invalid")

    def canonical_bytes(self) -> bytes:
        segment = self.segment_id.encode("ascii")
        program = self.program_id.encode("ascii")
        return b"".join(
            (
                len(segment).to_bytes(2, "big"),
                segment,
                len(program).to_bytes(2, "big"),
                program,
                self.program_commitment_512,
                self.trace_commitment_512,
                self.binary_ir_commitment_512,
                self.binary_ir_length.to_bytes(8, "big"),
                self.identities_evaluated.to_bytes(8, "big"),
                self.lookup_messages_evaluated.to_bytes(8, "big"),
                self.maximum_degree.to_bytes(4, "big"),
                len(self.tables).to_bytes(4, "big"),
                *(table.canonical_bytes() for table in self.tables),
            )
        )


def build_executable_air_segment(
    segment_id: str,
    program: AirProgram,
    traces: Mapping[str, TraceTable],
    public_inputs: Sequence[int] | None = None,
    *,
    public_table_names: frozenset[str] = frozenset(),
) -> ExecutableAirSegment:
    """Evaluate and inventory one real executable AIR segment."""

    _ascii("segment_id", segment_id)
    if type(program) is not AirProgram:
        raise TypeError("wave1b_registry_air_program_required")
    if type(public_table_names) is not frozenset:
        raise TypeError("wave1b_registry_public_table_names_frozenset_required")
    known_tables = {table.name for table in program.tables}
    if not public_table_names.issubset(known_tables):
        raise StructuralError("wave1b_registry_public_table_unknown")
    report = evaluate_program(program, traces, public_inputs)
    encoded = encode_air_execution(program, traces, public_inputs)
    dimensions: list[ExecutableTableDimensions] = []
    for table in program.tables:
        touching = tuple(
            lookup
            for lookup in program.lookups
            if any(
                side.table == table.name
                for side in (*lookup.sources, *lookup.destinations)
            )
        )
        sides = tuple(
            side
            for lookup in touching
            for side in (*lookup.sources, *lookup.destinations)
            if side.table == table.name
        )
        widths = tuple(len(side.values) for side in sides)
        dimensions.append(
            ExecutableTableDimensions(
                segment_id=segment_id,
                table_name=table.name,
                logical_rows=table.rows,
                padded_rows=_next_power_of_two(table.rows),
                trace_columns=len(table.columns),
                fixed_columns=len(table.fixed_columns or ()),
                identity_count=len(table.identities),
                maximum_identity_degree=table.maximum_degree,
                lookup_argument_count=len(touching),
                lookup_side_count=len(sides),
                lookup_coordinate_width_sum=sum(widths),
                maximum_lookup_coordinate_width=max(widths, default=0),
                lookup_row_capacity=sum(
                    side.row_stop - side.row_start for side in sides
                ),
                public_input_count=sum(
                    binding.table == table.name for binding in program.public_inputs
                ),
                private=table.name not in public_table_names,
            )
        )
    return ExecutableAirSegment(
        segment_id=segment_id,
        program_id=program.program_id,
        program_commitment_512=report.program_commitment,
        trace_commitment_512=report.trace_commitment,
        binary_ir_commitment_512=air_binary_commitment(encoded),
        binary_ir_length=len(encoded),
        identities_evaluated=report.identities_evaluated,
        lookup_messages_evaluated=report.lookup_messages_evaluated,
        maximum_degree=report.maximum_degree,
        tables=tuple(dimensions),
    )


@dataclass(frozen=True, slots=True)
class Wave1BExecutableRegistry:
    profile_id: str
    global_sha3_schedule_commitment_512: bytes
    segments: tuple[ExecutableAirSegment, ...]
    complete_segment_set: bool = False
    pcs_expansion_substituted: bool = False
    proof_suite_id: None = None
    activation_allowed: bool = False
    status: str = EXECUTABLE_REGISTRY_STATUS

    def __post_init__(self) -> None:
        _ascii("profile_id", self.profile_id)
        _wide("global_sha3_schedule", self.global_sha3_schedule_commitment_512)
        if (
            type(self.segments) is not tuple
            or not self.segments
            or len({segment.segment_id for segment in self.segments})
            != len(self.segments)
            or type(self.complete_segment_set) is not bool
            or self.pcs_expansion_substituted
            or self.proof_suite_id is not None
            or self.activation_allowed
            or self.status != EXECUTABLE_REGISTRY_STATUS
        ):
            raise ValueError("wave1b_executable_registry_invalid")

    @property
    def tables(self) -> tuple[ExecutableTableDimensions, ...]:
        return tuple(table for segment in self.segments for table in segment.tables)

    def canonical_bytes(self) -> bytes:
        profile = self.profile_id.encode("ascii")
        return b"".join(
            (
                EXECUTABLE_REGISTRY_DOMAIN,
                len(profile).to_bytes(2, "big"),
                profile,
                self.global_sha3_schedule_commitment_512,
                bytes((int(self.complete_segment_set), 0, 0)),
                len(self.segments).to_bytes(4, "big"),
                *(segment.canonical_bytes() for segment in self.segments),
            )
        )

    @property
    def commitment_sha3_512(self) -> bytes:
        return sha3_512(self.canonical_bytes()).digest()


__all__ = (
    "EXECUTABLE_REGISTRY_DOMAIN",
    "EXECUTABLE_REGISTRY_STATUS",
    "ExecutableAirSegment",
    "ExecutableTableDimensions",
    "Wave1BExecutableRegistry",
    "build_executable_air_segment",
)
