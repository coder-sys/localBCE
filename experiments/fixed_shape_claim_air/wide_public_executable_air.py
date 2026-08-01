"""Executable ordered Privacy V2 public binding for wide-authoritative values.

The verifier supplies the twelve ABI fields as 384 ordered bytes.  Every field
is proved canonical in Stark252, and fields 3..11 are linked to exact nonzero
projections of nine full SHA3-512 authoritative values.  The projected fields
are compatibility aliases only.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Mapping, Sequence

from .executable_air import (
    M31,
    AirProgram,
    AirTable,
    Identity,
    LookupArgument,
    LookupSide,
    PublicInputBinding,
    TraceTable,
    boolean,
    cell,
    const,
    freeze_columns,
)
from .semantics import StructuralError
from .stark252_projection_air import (
    STARK252_PRIME,
    Stark252ProjectionRequest,
    build_stark252_projection_air,
    compatibility_felt_from_sha3_512,
)


PROGRAM_ID: Final[str] = "BL-WAVE1A-WIDE-AUTHORITATIVE-PUBLIC-AIR-v1"
PROGRAM_ID_V2: Final[str] = "BL-WAVE1A-WIDE-AUTHORITATIVE-PUBLIC-AIR-v2"
PUBLIC_FIELD_NAMES: Final[tuple[str, ...]] = (
    "protocolVersion",
    "settlementDomain",
    "batchNonce",
    "nullifierRootBefore",
    "nullifierRootAfter",
    "claimSourceRoot",
    "oracleFactsRoot",
    "policyRoot",
    "rulesetRoot",
    "opaqueBatchCommitment",
    "valueConservationCommitment",
    "settlementCommitment",
)
WIDE_FIELD_NAMES: Final[tuple[str, ...]] = PUBLIC_FIELD_NAMES[3:]
WIDE_FIELD_NAMES_V2: Final[tuple[str, ...]] = PUBLIC_FIELD_NAMES[1:]
FIELD_BYTES: Final[int] = 32
BYTE_BASE: Final[int] = 256
P_MINUS_ONE_LE: Final[tuple[int, ...]] = tuple(
    (STARK252_PRIME - 1).to_bytes(FIELD_BYTES, "little")
)


@dataclass(frozen=True, slots=True)
class WidePublicAirInstance:
    program: AirProgram
    traces: Mapping[str, TraceTable]
    public_input_bytes: tuple[int, ...]
    public_outputs: tuple[int, ...]
    wide_values: tuple[bytes, ...]


def _canonical_field_witness(value: int) -> tuple[tuple[int, ...], tuple[int, ...]]:
    if type(value) is not int or not 0 <= value < STARK252_PRIME:
        raise StructuralError("wide_public_value_not_canonical_stark252")
    delta = STARK252_PRIME - 1 - value
    delta_le = tuple(delta.to_bytes(FIELD_BYTES, "little"))
    value_le = tuple(value.to_bytes(FIELD_BYTES, "little"))
    carries = [0]
    for index in range(FIELD_BYTES):
        numerator = value_le[index] + delta_le[index] + carries[-1] - P_MINUS_ONE_LE[index]
        if numerator % BYTE_BASE:
            raise StructuralError("wide_public_range_carry_not_integral")
        carry = numerator // BYTE_BASE
        if carry not in {0, 1}:
            raise StructuralError("wide_public_range_carry_invalid")
        carries.append(carry)
    if carries[-1] != 0:
        raise StructuralError("wide_public_range_terminal_carry_nonzero")
    return delta_le, tuple(carries)


def _build_wide_public_executable_air(
    outputs: tuple[int, ...],
    wide: tuple[bytes, ...],
    projection_names: tuple[str, ...],
    projection_public_start: int,
    program_id: str,
) -> WidePublicAirInstance:
    if (
        len(outputs) != len(PUBLIC_FIELD_NAMES)
        or outputs[0] != 2
        or len(wide) != len(projection_names)
        or any(type(value) is not bytes or len(value) != 64 for value in wide)
    ):
        raise StructuralError("wide_public_inputs_invalid")

    columns: dict[str, list[int]] = {
        "field_index": list(range(len(PUBLIC_FIELD_NAMES)))
    }
    byte_counts: Counter[int] = Counter()
    for value in outputs:
        delta, carries = _canonical_field_witness(value)
        encoded = value.to_bytes(FIELD_BYTES, "big")
        columns.setdefault("nonzero_inverse", []).append(pow(sum(encoded), -1, M31))
        for index, byte in enumerate(encoded):
            columns.setdefault(f"value_{index}", []).append(byte)
            byte_counts[byte] += 1
        for index, byte in enumerate(delta):
            columns.setdefault(f"delta_{index}", []).append(byte)
            byte_counts[byte] += 1
        for index, carry in enumerate(carries):
            columns.setdefault(f"carry_{index}", []).append(carry)

    rows = len(PUBLIC_FIELD_NAMES)
    identities: list[Identity] = [
        Identity("protocol_version", cell("value_31") - 2, 0, 1, "boundary"),
        Identity(
            "public_value_nonzero",
            sum((cell(f"value_{index}") for index in range(FIELD_BYTES)), const(0))
            * cell("nonzero_inverse")
            - 1,
            0,
            rows,
        ),
        *(
            Identity(
                f"protocol_high_byte_zero_{index}",
                cell(f"value_{index}"),
                0,
                1,
                "boundary",
            )
            for index in range(FIELD_BYTES - 1)
        ),
    ]
    for index in range(FIELD_BYTES + 1):
        identities.append(
            Identity(
                f"carry_boolean_{index}", boolean(cell(f"carry_{index}")), 0, rows
            )
        )
    identities.extend(
        (
            Identity("range_initial_carry", cell("carry_0"), 0, rows),
            Identity(
                "range_terminal_carry", cell(f"carry_{FIELD_BYTES}"), 0, rows
            ),
        )
    )
    for index in range(FIELD_BYTES):
        identities.append(
            Identity(
                f"canonical_field_{index}",
                cell(f"value_{FIELD_BYTES - 1 - index}")
                + cell(f"delta_{index}")
                + cell(f"carry_{index}")
                - P_MINUS_ONE_LE[index]
                - BYTE_BASE * cell(f"carry_{index + 1}"),
                0,
                rows,
            )
        )

    public_trace = TraceTable("wide_public", freeze_columns(columns))
    public_table = AirTable(
        "wide_public",
        tuple(public_trace.columns),
        rows,
        tuple(identities),
        MappingProxyType({"field_index": tuple(range(rows))}),
    )
    range_trace = TraceTable(
        "wide_public_byte_range",
        freeze_columns(
            {
                "value": tuple(range(256)),
                "multiplicity": tuple(byte_counts[value] for value in range(256)),
            }
        ),
    )
    range_table = AirTable(
        "wide_public_byte_range",
        ("value", "multiplicity"),
        256,
        (),
        MappingProxyType({"value": tuple(range(256))}),
    )
    range_lookup = LookupArgument(
        "wide_public_byte_range",
        tuple(
            LookupSide("wide_public", const(1), (cell(name),), 0, rows)
            for name in (
                *(f"value_{index}" for index in range(FIELD_BYTES)),
                *(f"delta_{index}" for index in range(FIELD_BYTES)),
            )
        ),
        (
            LookupSide(
                "wide_public_byte_range",
                const(1),
                (cell("value"),),
                0,
                256,
                cell("multiplicity"),
            ),
        ),
    )

    projection = build_stark252_projection_air(
        tuple(
            Stark252ProjectionRequest(name, value)
            for name, value in zip(projection_names, wide, strict=True)
        )
    )
    projection_link = LookupArgument(
        "wide_public_projection_link",
        (
            LookupSide(
                "stark252_projection",
                const(1),
                (
                    cell("operation_index"),
                    *(cell(f"alias_{FIELD_BYTES - 1 - index}") for index in range(FIELD_BYTES)),
                ),
                0,
                len(wide),
            ),
        ),
        (
            LookupSide(
                "wide_public",
                const(1),
                (
                    cell("field_index") - projection_public_start,
                    *(cell(f"value_{index}") for index in range(FIELD_BYTES)),
                ),
                projection_public_start,
                rows,
            ),
        ),
    )

    bindings = tuple(
        PublicInputBinding(
            f"{field_name}.byte{byte_index:02d}",
            "wide_public",
            f"value_{byte_index}",
            field_index,
        )
        for field_index, field_name in enumerate(PUBLIC_FIELD_NAMES)
        for byte_index in range(FIELD_BYTES)
    )
    program = AirProgram(
        program_id,
        (*projection.program.tables, public_table, range_table),
        (*projection.program.lookups, range_lookup, projection_link),
        bindings,
    )
    return WidePublicAirInstance(
        program,
        MappingProxyType(
            {
                **dict(projection.traces),
                "wide_public": public_trace,
                "wide_public_byte_range": range_trace,
            }
        ),
        tuple(byte for value in outputs for byte in value.to_bytes(FIELD_BYTES, "big")),
        outputs,
        wide,
    )


def build_wide_public_executable_air(
    protocol_version: int,
    settlement_domain: int,
    batch_nonce: int,
    wide_values: Sequence[bytes],
) -> WidePublicAirInstance:
    """Legacy reference builder; raw felt domain/nonce are not authoritative."""

    wide = tuple(wide_values)
    if type(protocol_version) is not int or protocol_version != 2:
        raise StructuralError("wide_public_inputs_invalid")
    outputs = (
        protocol_version,
        settlement_domain,
        batch_nonce,
        *(compatibility_felt_from_sha3_512(value) for value in wide),
    )
    return _build_wide_public_executable_air(
        outputs,
        wide,
        WIDE_FIELD_NAMES,
        3,
        PROGRAM_ID,
    )


def build_wide_public_executable_air_v2(
    protocol_version: int,
    strong_settlement_domain_id_512: bytes,
    strong_batch_nonce_512: bytes,
    wide_values: Sequence[bytes],
) -> WidePublicAirInstance:
    """Bind all eleven compatibility aliases to 512-bit authorities."""

    wide = (
        strong_settlement_domain_id_512,
        strong_batch_nonce_512,
        *tuple(wide_values),
    )
    if type(protocol_version) is not int or protocol_version != 2:
        raise StructuralError("wide_public_inputs_invalid")
    outputs = (
        protocol_version,
        *(compatibility_felt_from_sha3_512(value) for value in wide),
    )
    return _build_wide_public_executable_air(
        outputs,
        wide,
        WIDE_FIELD_NAMES_V2,
        1,
        PROGRAM_ID_V2,
    )
__all__ = [
    "PUBLIC_FIELD_NAMES",
    "WIDE_FIELD_NAMES",
    "WIDE_FIELD_NAMES_V2",
    "WidePublicAirInstance",
    "build_wide_public_executable_air",
    "build_wide_public_executable_air_v2",
]
