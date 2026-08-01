"""Canonical program-bound manifest for out-of-core AIR executions."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
from typing import Final, Mapping, Sequence

from .air_binary_ir import air_program_commitment, encode_air_program
from .executable_air import M31, AirProgram, TraceTable
from .semantics import StructuralError


STREAMING_MANIFEST_MAGIC: Final[bytes] = b"BLPQAIM1"
STREAMING_MANIFEST_VERSION: Final[int] = 1
STREAMING_COLUMN_DOMAIN: Final[bytes] = (
    b"BL/PQ512/WAVE1B/STREAMING-AIR-COLUMN/v1\x00"
)
STREAMING_MANIFEST_DOMAIN: Final[bytes] = (
    b"BL/PQ512/WAVE1B/STREAMING-AIR-MANIFEST/v1\x00"
)
MAX_STREAMING_MANIFEST_BYTES: Final[int] = 64 << 20
STREAMING_VALUE_CHUNK_MAGIC: Final[bytes] = b"BLPQAIC1"
STREAMING_VALUE_CHUNK_VERSION: Final[int] = 1
MAX_STREAMING_CHUNK_VALUES: Final[int] = 1 << 20


@dataclass(frozen=True, slots=True)
class StreamingColumnManifest:
    table_index: int
    column_index: int
    value_count: int
    commitment_512: bytes

    def __post_init__(self) -> None:
        if (
            type(self.table_index) is not int
            or not 0 <= self.table_index <= 0xFFFF_FFFF
            or type(self.column_index) is not int
            or not 0 <= self.column_index <= 0xFFFF_FFFF
            or type(self.value_count) is not int
            or not 0 < self.value_count <= 0xFFFF_FFFF_FFFF_FFFF
            or type(self.commitment_512) is not bytes
            or len(self.commitment_512) != 64
            or not any(self.commitment_512)
        ):
            raise StructuralError("streaming_air_column_manifest_invalid")


@dataclass(frozen=True, slots=True)
class StreamingTableManifest:
    table_index: int
    row_count: int
    columns: tuple[StreamingColumnManifest, ...]

    def __post_init__(self) -> None:
        if (
            type(self.table_index) is not int
            or not 0 <= self.table_index <= 0xFFFF_FFFF
            or type(self.row_count) is not int
            or not 0 < self.row_count <= 0xFFFF_FFFF_FFFF_FFFF
            or type(self.columns) is not tuple
            or tuple(value.table_index for value in self.columns)
            != (self.table_index,) * len(self.columns)
            or any(
                left.column_index >= right.column_index
                for left, right in zip(self.columns, self.columns[1:])
            )
            or any(value.value_count != self.row_count for value in self.columns)
        ):
            raise StructuralError("streaming_air_table_manifest_invalid")


@dataclass(frozen=True, slots=True)
class StreamingAirManifest:
    program_binary_commitment_512: bytes
    public_inputs: tuple[int, ...]
    tables: tuple[StreamingTableManifest, ...]

    def __post_init__(self) -> None:
        if (
            type(self.program_binary_commitment_512) is not bytes
            or len(self.program_binary_commitment_512) != 64
            or not any(self.program_binary_commitment_512)
            or type(self.public_inputs) is not tuple
            or any(type(value) is not int or not 0 <= value < M31 for value in self.public_inputs)
            or type(self.tables) is not tuple
            or not self.tables
            or tuple(value.table_index for value in self.tables)
            != tuple(range(len(self.tables)))
        ):
            raise StructuralError("streaming_air_manifest_invalid")

    @property
    def encoded(self) -> bytes:
        parts = [
            STREAMING_MANIFEST_MAGIC,
            STREAMING_MANIFEST_VERSION.to_bytes(2, "big"),
            self.program_binary_commitment_512,
            len(self.public_inputs).to_bytes(4, "big"),
            *(value.to_bytes(4, "big") for value in self.public_inputs),
            len(self.tables).to_bytes(4, "big"),
        ]
        for table in self.tables:
            parts.extend(
                (
                    table.table_index.to_bytes(4, "big"),
                    table.row_count.to_bytes(8, "big"),
                    len(table.columns).to_bytes(4, "big"),
                )
            )
            for column in table.columns:
                parts.extend(
                    (
                        column.column_index.to_bytes(4, "big"),
                        column.value_count.to_bytes(8, "big"),
                        column.commitment_512,
                    )
                )
        encoded = b"".join(parts)
        if len(encoded) > MAX_STREAMING_MANIFEST_BYTES:
            raise StructuralError("streaming_air_manifest_size_cap_exceeded")
        return encoded

    @property
    def commitment_512(self) -> bytes:
        return sha3_512(STREAMING_MANIFEST_DOMAIN + self.encoded).digest()


def streaming_column_commitment(
    program_binary_commitment_512: bytes,
    table_index: int,
    column_index: int,
    values: Sequence[int],
) -> bytes:
    if type(values) not in {tuple, list} or not values:
        raise StructuralError("streaming_air_column_values_invalid")
    digest = sha3_512(STREAMING_COLUMN_DOMAIN)
    digest.update(program_binary_commitment_512)
    digest.update(table_index.to_bytes(4, "big"))
    digest.update(column_index.to_bytes(4, "big"))
    digest.update(len(values).to_bytes(8, "big"))
    for value in values:
        if type(value) is not int or not 0 <= value < M31:
            raise StructuralError("streaming_air_column_value_noncanonical")
        digest.update(value.to_bytes(4, "big"))
    return digest.digest()


def build_streaming_air_manifest(
    program: AirProgram,
    traces: Mapping[str, TraceTable],
    public_inputs: Sequence[int] | None = None,
) -> StreamingAirManifest:
    if type(program) is not AirProgram or set(traces) != {
        table.name for table in program.tables
    }:
        raise StructuralError("streaming_air_program_trace_shape_invalid")
    supplied = () if public_inputs is None else tuple(public_inputs)
    if len(supplied) != len(program.public_inputs):
        raise StructuralError("streaming_air_public_input_count_invalid")
    for binding, value in zip(program.public_inputs, supplied, strict=True):
        if (
            type(value) is not int
            or not 0 <= value < M31
            or traces[binding.table].columns[binding.column][binding.row] != value
        ):
            raise StructuralError("streaming_air_public_input_invalid")
    program_commitment = air_program_commitment(encode_air_program(program))
    tables = []
    for table_index, table in enumerate(program.tables):
        trace = traces[table.name]
        if (
            trace.name != table.name
            or trace.rows != table.rows
            or tuple(trace.columns) != table.columns
        ):
            raise StructuralError("streaming_air_trace_schema_invalid")
        fixed = set(table.fixed_columns or ())
        columns = tuple(
            StreamingColumnManifest(
                table_index,
                column_index,
                table.rows,
                streaming_column_commitment(
                    program_commitment,
                    table_index,
                    column_index,
                    trace.columns[column_name],
                ),
            )
            for column_index, column_name in enumerate(table.columns)
            if column_name not in fixed
        )
        tables.append(StreamingTableManifest(table_index, table.rows, columns))
    return StreamingAirManifest(program_commitment, supplied, tuple(tables))


def encode_streaming_value_chunk(
    manifest: StreamingAirManifest,
    table_index: int,
    column_index: int,
    row_start: int,
    values: Sequence[int],
) -> bytes:
    if (
        type(manifest) is not StreamingAirManifest
        or type(table_index) is not int
        or not 0 <= table_index <= 0xFFFF_FFFF
        or type(column_index) is not int
        or not 0 <= column_index <= 0xFFFF_FFFF
        or type(row_start) is not int
        or not 0 <= row_start <= 0xFFFF_FFFF_FFFF_FFFF
        or type(values) not in {tuple, list}
        or not 0 < len(values) <= MAX_STREAMING_CHUNK_VALUES
    ):
        raise StructuralError("streaming_air_value_chunk_invalid")
    encoded_values = []
    for value in values:
        if type(value) is not int or not 0 <= value < M31:
            raise StructuralError("streaming_air_column_value_noncanonical")
        encoded_values.append(value.to_bytes(4, "big"))
    return b"".join(
        (
            STREAMING_VALUE_CHUNK_MAGIC,
            STREAMING_VALUE_CHUNK_VERSION.to_bytes(2, "big"),
            manifest.program_binary_commitment_512,
            manifest.commitment_512,
            table_index.to_bytes(4, "big"),
            column_index.to_bytes(4, "big"),
            row_start.to_bytes(8, "big"),
            len(values).to_bytes(4, "big"),
            *encoded_values,
        )
    )


def iter_streaming_air_chunks(
    program: AirProgram,
    traces: Mapping[str, TraceTable],
    manifest: StreamingAirManifest,
    *,
    chunk_values: int,
):
    if (
        type(chunk_values) is not int
        or not 0 < chunk_values <= MAX_STREAMING_CHUNK_VALUES
        or manifest
        != build_streaming_air_manifest(program, traces, manifest.public_inputs)
    ):
        raise StructuralError("streaming_air_chunk_source_invalid")
    for table_index, table in enumerate(program.tables):
        trace = traces[table.name]
        for column in manifest.tables[table_index].columns:
            column_index = column.column_index
            column_name = table.columns[column_index]
            values = trace.columns[column_name]
            for row_start in range(0, table.rows, chunk_values):
                yield encode_streaming_value_chunk(
                    manifest,
                    table_index,
                    column_index,
                    row_start,
                    values[row_start : row_start + chunk_values],
                )


__all__ = (
    "MAX_STREAMING_MANIFEST_BYTES",
    "MAX_STREAMING_CHUNK_VALUES",
    "STREAMING_COLUMN_DOMAIN",
    "STREAMING_MANIFEST_DOMAIN",
    "STREAMING_MANIFEST_MAGIC",
    "STREAMING_MANIFEST_VERSION",
    "STREAMING_VALUE_CHUNK_MAGIC",
    "STREAMING_VALUE_CHUNK_VERSION",
    "StreamingAirManifest",
    "StreamingColumnManifest",
    "StreamingTableManifest",
    "build_streaming_air_manifest",
    "encode_streaming_value_chunk",
    "iter_streaming_air_chunks",
    "streaming_column_commitment",
)
