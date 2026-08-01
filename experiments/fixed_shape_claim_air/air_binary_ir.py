"""Canonical bounded binary transport for the executable Wave 1A AIR.

The existing JSON encoding remains the human-auditable program commitment.
This transport binds that commitment and carries the same typed program,
trace, and public inputs to the ``no_std`` Rust evaluator without adding a
JSON dependency to the cryptographic crate.  All lengths are explicit and
all field elements are canonical M31 words.
"""

from __future__ import annotations

from hashlib import sha3_512
from typing import Final, Mapping, Sequence

from .executable_air import (
    M31,
    AirProgram,
    Expr,
    FixedColumnPeriodic,
    FixedColumnRuns,
    LookupSide,
    TraceTable,
)
from .semantics import StructuralError


AIR_BINARY_MAGIC: Final[bytes] = b"BLPQAIR1"
AIR_BINARY_VERSION: Final[int] = 1
AIR_BINARY_COMPACT_FIXED_VERSION: Final[int] = 2
AIR_BINARY_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE1A/AIR-BINARY-IR/v1\x00"
AIR_PROGRAM_MAGIC: Final[bytes] = b"BLPQARP1"
AIR_PROGRAM_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE1B/AIR-PROGRAM-IR/v1\x00"
MAX_AIR_BINARY_BYTES: Final[int] = 512 * 1024 * 1024

_EXPR_TAGS: Final[dict[str, int]] = {
    "const": 0,
    "cell": 1,
    "add": 2,
    "sub": 3,
    "mul": 4,
}
_FAMILY_TAGS: Final[dict[str, int]] = {
    "local": 0,
    "transition": 1,
    "boundary": 2,
}


class _Writer:
    __slots__ = ("parts", "length")

    def __init__(self) -> None:
        self.parts: list[bytes] = []
        self.length = 0

    def raw(self, value: bytes) -> None:
        if type(value) is not bytes:
            raise TypeError("air_binary_raw_exact_bytes_required")
        self.length += len(value)
        if self.length > MAX_AIR_BINARY_BYTES:
            raise StructuralError("air_binary_size_cap_exceeded")
        self.parts.append(value)

    def u8(self, value: int) -> None:
        self.raw(value.to_bytes(1, "big"))

    def u16(self, value: int) -> None:
        self.raw(value.to_bytes(2, "big"))

    def u32(self, value: int) -> None:
        self.raw(value.to_bytes(4, "big"))

    def text(self, value: str) -> None:
        if type(value) is not str:
            raise TypeError("air_binary_text_string_required")
        try:
            encoded = value.encode("ascii")
        except UnicodeEncodeError as exc:
            raise StructuralError("air_binary_text_not_ascii") from exc
        if not encoded or len(encoded) > 0xFFFF:
            raise StructuralError("air_binary_text_length_invalid")
        self.u16(len(encoded))
        self.raw(encoded)

    def finish(self) -> bytes:
        return b"".join(self.parts)


def _u32(value: int, label: str) -> int:
    if type(value) is not int or not 0 <= value <= 0xFFFF_FFFF:
        raise StructuralError(f"air_binary_{label}_not_u32")
    return value


def _encode_expr(
    writer: _Writer,
    expression: Expr,
    column_indices: Mapping[str, int],
    *,
    depth: int = 0,
) -> None:
    if depth > 64:
        raise StructuralError("air_binary_expression_too_deep")
    try:
        tag = _EXPR_TAGS[expression.kind]
    except (AttributeError, KeyError) as exc:
        raise StructuralError("air_binary_expression_invalid") from exc
    writer.u8(tag)
    if expression.kind == "const":
        assert type(expression.value) is int
        writer.u32(expression.value % M31)
        return
    if expression.kind == "cell":
        assert type(expression.value) is str
        try:
            column = column_indices[expression.value]
        except KeyError as exc:
            raise StructuralError("air_binary_expression_unknown_column") from exc
        writer.u32(column)
        writer.u8(expression.shift)
        return
    assert expression.left is not None and expression.right is not None
    _encode_expr(writer, expression.left, column_indices, depth=depth + 1)
    _encode_expr(writer, expression.right, column_indices, depth=depth + 1)


def _encode_lookup_side(
    writer: _Writer,
    side: LookupSide,
    table_indices: Mapping[str, int],
    column_indices: Mapping[str, Mapping[str, int]],
) -> None:
    try:
        table_index = table_indices[side.table]
        columns = column_indices[side.table]
    except KeyError as exc:
        raise StructuralError("air_binary_lookup_unknown_table") from exc
    writer.u32(table_index)
    writer.u32(_u32(side.row_start, "lookup_row_start"))
    writer.u32(_u32(side.row_stop, "lookup_row_stop"))
    _encode_expr(writer, side.selector, columns)
    _encode_expr(writer, side.weight, columns)
    writer.u32(len(side.values))
    for value in side.values:
        _encode_expr(writer, value, columns)


def _program_binary_version(program: AirProgram) -> int:
    return (
        AIR_BINARY_COMPACT_FIXED_VERSION
        if any(
            type(values) is not tuple
            for table in program.tables
            for values in (table.fixed_columns or {}).values()
        )
        else AIR_BINARY_VERSION
    )


def _encode_program_body(writer: _Writer, program: AirProgram, version: int) -> None:
    if type(program) is not AirProgram:
        raise TypeError("air_binary_program_exact_type_required")
    writer.raw(program.commitment())
    writer.text(program.program_id)

    table_indices = {table.name: index for index, table in enumerate(program.tables)}
    column_indices = {
        table.name: {name: index for index, name in enumerate(table.columns)}
        for table in program.tables
    }
    writer.u32(len(program.tables))
    for table in program.tables:
        writer.text(table.name)
        writer.u32(_u32(table.rows, "table_rows"))
        writer.u32(len(table.columns))
        for column in table.columns:
            writer.text(column)
        fixed = () if table.fixed_columns is None else tuple(table.fixed_columns.items())
        writer.u32(len(fixed))
        for name, values in fixed:
            writer.u32(column_indices[table.name][name])
            if version == AIR_BINARY_VERSION:
                if type(values) is not tuple:
                    raise StructuralError("air_binary_compact_fixed_requires_v2")
                writer.u32(len(values))
                for value in values:
                    writer.u32(_u32(value, "fixed_value"))
            elif type(values) is tuple:
                writer.u8(0)
                writer.u32(len(values))
                for value in values:
                    writer.u32(_u32(value, "fixed_value"))
            elif isinstance(values, FixedColumnRuns):
                writer.u8(1)
                writer.u32(len(values.runs))
                for value, count in values.runs:
                    writer.u32(_u32(value, "fixed_value"))
                    writer.u32(_u32(count, "fixed_run_count"))
            elif isinstance(values, FixedColumnPeriodic):
                writer.u8(2)
                writer.u32(len(values.pattern))
                for value in values.pattern:
                    writer.u32(_u32(value, "fixed_value"))
            else:
                raise StructuralError("air_binary_fixed_encoding_invalid")
        writer.u32(len(table.identities))
        for identity in table.identities:
            writer.text(identity.name)
            writer.u8(_FAMILY_TAGS[identity.family])
            writer.u32(_u32(identity.row_start, "identity_row_start"))
            writer.u32(_u32(identity.row_stop, "identity_row_stop"))
            _encode_expr(writer, identity.expression, column_indices[table.name])

    writer.u32(len(program.lookups))
    for lookup in program.lookups:
        writer.text(lookup.name)
        writer.u32(len(lookup.sources))
        for side in lookup.sources:
            _encode_lookup_side(writer, side, table_indices, column_indices)
        writer.u32(len(lookup.destinations))
        for side in lookup.destinations:
            _encode_lookup_side(writer, side, table_indices, column_indices)

    writer.u32(len(program.public_inputs))
    for binding in program.public_inputs:
        writer.text(binding.name)
        writer.u32(table_indices[binding.table])
        writer.u32(column_indices[binding.table][binding.column])
        writer.u32(_u32(binding.row, "public_input_row"))


def encode_air_program(program: AirProgram) -> bytes:
    """Encode verifier-visible AIR metadata without carrying private traces."""

    writer = _Writer()
    writer.raw(AIR_PROGRAM_MAGIC)
    version = _program_binary_version(program)
    writer.u16(version)
    _encode_program_body(writer, program, version)
    return writer.finish()


def encode_air_execution(
    program: AirProgram,
    traces: Mapping[str, TraceTable],
    public_inputs: Sequence[int] | None = None,
) -> bytes:
    """Encode one exact typed program and trace for independent Rust evaluation."""

    if type(program) is not AirProgram:
        raise TypeError("air_binary_program_exact_type_required")
    if set(traces) != {table.name for table in program.tables}:
        raise StructuralError("air_binary_trace_table_set_mismatch")
    supplied = () if public_inputs is None else tuple(public_inputs)
    if len(supplied) != len(program.public_inputs):
        raise StructuralError("air_binary_public_input_count_mismatch")
    if any(type(value) is not int or not 0 <= value < M31 for value in supplied):
        raise StructuralError("air_binary_public_input_not_canonical")

    writer = _Writer()
    writer.raw(AIR_BINARY_MAGIC)
    version = _program_binary_version(program)
    writer.u16(version)
    _encode_program_body(writer, program, version)

    writer.u32(len(program.tables))
    for table_index, table in enumerate(program.tables):
        trace = traces[table.name]
        if (
            trace.name != table.name
            or trace.rows != table.rows
            or set(trace.columns) != set(table.columns)
        ):
            raise StructuralError("air_binary_trace_schema_mismatch")
        writer.u32(table_index)
        writer.u32(len(table.columns))
        writer.u32(table.rows)
        for column in table.columns:
            for value in trace.columns[column]:
                writer.u32(_u32(value, "trace_value"))

    writer.u32(len(supplied))
    for value in supplied:
        writer.u32(value)
    return writer.finish()


def air_binary_commitment(encoded: bytes) -> bytes:
    if type(encoded) is not bytes or not 0 < len(encoded) <= MAX_AIR_BINARY_BYTES:
        raise StructuralError("air_binary_encoding_invalid")
    return sha3_512(AIR_BINARY_DOMAIN + encoded).digest()


def air_program_commitment(encoded: bytes) -> bytes:
    if type(encoded) is not bytes or not 0 < len(encoded) <= MAX_AIR_BINARY_BYTES:
        raise StructuralError("air_program_encoding_invalid")
    return sha3_512(AIR_PROGRAM_DOMAIN + encoded).digest()


__all__ = (
    "AIR_BINARY_DOMAIN",
    "AIR_BINARY_MAGIC",
    "AIR_BINARY_COMPACT_FIXED_VERSION",
    "AIR_BINARY_VERSION",
    "AIR_PROGRAM_DOMAIN",
    "AIR_PROGRAM_MAGIC",
    "MAX_AIR_BINARY_BYTES",
    "air_binary_commitment",
    "air_program_commitment",
    "encode_air_execution",
    "encode_air_program",
)
