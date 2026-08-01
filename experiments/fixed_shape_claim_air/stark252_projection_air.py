"""Exact SHA3-512-to-Stark252 compatibility projection AIR over M31.

The projected felt is deliberately non-authoritative and never zero.  It is a compact adapter
value for interfaces that can carry only one Stark252 felt; the complete
SHA3-512 value remains the replay and settlement authority.  The AIR proves the
integer equation ``digest = quotient * (p - 1) + remainder`` without a
non-native witness-by-witness multiplication: the modulus is fixed, all
radix-256 coefficients are bounded below M31, the remainder is constrained to
``[0, p - 1)``, and the exported alias is ``remainder + 1``.
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
    TraceTable,
    boolean,
    cell,
    const,
    freeze_columns,
)
from .semantics import StructuralError
STARK252_PRIME: Final[int] = (1 << 251) + (17 << 192) + 1
PROJECTION_MODULUS: Final[int] = STARK252_PRIME - 1
BYTE_BASE: Final[int] = 256
LIMBS: Final[int] = 32
MODULUS_BYTES: Final[tuple[int, ...]] = tuple(PROJECTION_MODULUS.to_bytes(LIMBS, "little"))
MODULUS_MINUS_ONE_BYTES: Final[tuple[int, ...]] = tuple(
    (PROJECTION_MODULUS - 1).to_bytes(LIMBS, "little")
)
DIGEST_BYTES: Final[int] = 64
QUOTIENT_BYTES: Final[int] = 33
PRODUCT_BYTES: Final[int] = QUOTIENT_BYTES + LIMBS
PROJECTION_CARRY_BIAS: Final[int] = 1 << 14
PROGRAM_ID: Final[str] = "BL-WAVE1A-SHA3-STARK252-COMPATIBILITY-PROJECTION-AIR-v1"


def compatibility_felt_from_sha3_512(digest: bytes) -> int:
    """Return the non-authoritative one-felt projection of a SHA3-512 value."""

    if type(digest) is not bytes or len(digest) != DIGEST_BYTES:
        raise StructuralError("stark252_projection_digest_invalid")
    return int.from_bytes(digest, "big") % PROJECTION_MODULUS + 1


@dataclass(frozen=True, slots=True)
class Stark252ProjectionRequest:
    operation_id: str
    digest: bytes

    def __post_init__(self) -> None:
        if type(self.operation_id) is not str or not self.operation_id:
            raise StructuralError("stark252_projection_operation_id_invalid")
        if type(self.digest) is not bytes or len(self.digest) != DIGEST_BYTES:
            raise StructuralError("stark252_projection_digest_invalid")


@dataclass(frozen=True, slots=True)
class Stark252ProjectionAirInstance:
    program: AirProgram
    traces: Mapping[str, TraceTable]
    operation_ids: tuple[str, ...]
    aliases: tuple[int, ...]


def _bytes_le(value: int, width: int) -> tuple[int, ...]:
    if type(value) is not int or not 0 <= value < 1 << (8 * width):
        raise StructuralError("stark252_projection_integer_out_of_range")
    return tuple(value.to_bytes(width, "little"))


def _less_than_witness(value: int) -> tuple[tuple[int, ...], tuple[int, ...]]:
    difference = PROJECTION_MODULUS - 1 - value
    if difference < 0:
        raise StructuralError("stark252_projection_remainder_noncanonical")
    value_bytes = _bytes_le(value, LIMBS)
    delta = _bytes_le(difference, LIMBS)
    carries = [0]
    for index in range(LIMBS):
        total = (
            value_bytes[index]
            + delta[index]
            + carries[-1]
            - MODULUS_MINUS_ONE_BYTES[index]
        )
        if total % BYTE_BASE:
            raise StructuralError("stark252_projection_lt_carry_not_integral")
        carry = total // BYTE_BASE
        if carry not in {0, 1}:
            raise StructuralError("stark252_projection_lt_carry_invalid")
        carries.append(carry)
    if carries[-1] != 0:
        raise StructuralError("stark252_projection_lt_terminal_carry_nonzero")
    return delta, tuple(carries)


def _fixed_product_coefficient(quotient: tuple[int, ...], index: int) -> int:
    return sum(
        quotient[position] * MODULUS_BYTES[index - position]
        for position in range(QUOTIENT_BYTES)
        if 0 <= index - position < LIMBS
    )


def _append(columns: dict[str, list[int]], name: str, value: int) -> None:
    columns.setdefault(name, []).append(value % M31)


def build_stark252_projection_air(
    requests: Sequence[Stark252ProjectionRequest],
) -> Stark252ProjectionAirInstance:
    materialized = tuple(requests)
    if not materialized or len({request.operation_id for request in materialized}) != len(materialized):
        raise StructuralError("stark252_projection_requests_invalid")

    columns: dict[str, list[int]] = {}
    byte_columns: list[str] = []
    aliases: list[int] = []
    for operation_index, request in enumerate(materialized):
        digest_integer = int.from_bytes(request.digest, "big")
        remainder = digest_integer % PROJECTION_MODULUS
        alias = remainder + 1
        quotient = (digest_integer - remainder) // PROJECTION_MODULUS
        quotient_bytes = _bytes_le(quotient, QUOTIENT_BYTES)
        remainder_bytes = _bytes_le(remainder, LIMBS)
        digest_le = tuple(reversed(request.digest))
        delta, lt_carries = _less_than_witness(remainder)
        aliases.append(alias)

        _append(columns, "operation_index", operation_index)
        for index, value in enumerate(request.digest):
            name = f"digest_{index}"
            _append(columns, name, value)
            if name not in byte_columns:
                byte_columns.append(name)
        for prefix, values in (
            ("quotient", quotient_bytes),
            ("remainder", remainder_bytes),
            ("remainder_delta", delta),
            ("alias", _bytes_le(alias, LIMBS)),
        ):
            for index, value in enumerate(values):
                name = f"{prefix}_{index}"
                _append(columns, name, value)
                if name not in byte_columns:
                    byte_columns.append(name)
        for index, value in enumerate(lt_carries):
            _append(columns, f"remainder_lt_carry_{index}", value)
        alias_carries = [0]
        alias_bytes = _bytes_le(alias, LIMBS)
        for index in range(LIMBS):
            numerator = remainder_bytes[index] + int(index == 0) + alias_carries[-1] - alias_bytes[index]
            if numerator % BYTE_BASE:
                raise StructuralError("stark252_projection_alias_carry_not_integral")
            carry = numerator // BYTE_BASE
            if carry not in {0, 1}:
                raise StructuralError("stark252_projection_alias_carry_invalid")
            alias_carries.append(carry)
        if alias_carries[-1] != 0:
            raise StructuralError("stark252_projection_alias_terminal_carry_nonzero")
        for index, value in enumerate(alias_carries):
            _append(columns, f"alias_carry_{index}", value)

        carries = [0]
        for index in range(PRODUCT_BYTES):
            coefficient = (
                _fixed_product_coefficient(quotient_bytes, index)
                + (remainder_bytes[index] if index < LIMBS else 0)
                - (digest_le[index] if index < DIGEST_BYTES else 0)
            )
            numerator = coefficient + carries[-1]
            if numerator % BYTE_BASE:
                raise StructuralError("stark252_projection_carry_not_integral")
            carry = numerator // BYTE_BASE
            if not -PROJECTION_CARRY_BIAS <= carry < PROJECTION_CARRY_BIAS:
                raise StructuralError("stark252_projection_carry_bound_exceeded")
            carries.append(carry)
        if carries[-1] != 0:
            raise StructuralError("stark252_projection_terminal_carry_nonzero")
        for index, carry in enumerate(carries):
            biased = carry + PROJECTION_CARRY_BIAS
            _append(columns, f"projection_carry_bias_{index}", biased)
            _append(columns, f"projection_carry_lo_{index}", biased & 0xFF)
            _append(columns, f"projection_carry_hi_{index}", biased >> 8)
            for name in (f"projection_carry_lo_{index}", f"projection_carry_hi_{index}"):
                if name not in byte_columns:
                    byte_columns.append(name)

    rows = len(materialized)
    identities: list[Identity] = []
    for index in range(PRODUCT_BYTES):
        product = const(0)
        for position in range(QUOTIENT_BYTES):
            prime_index = index - position
            if 0 <= prime_index < LIMBS:
                product += cell(f"quotient_{position}") * MODULUS_BYTES[prime_index]
        digest = cell(f"digest_{DIGEST_BYTES - 1 - index}") if index < DIGEST_BYTES else const(0)
        remainder = cell(f"remainder_{index}") if index < LIMBS else const(0)
        identities.append(
            Identity(
                f"projection_coefficient_{index}",
                product
                + remainder
                - digest
                + (cell(f"projection_carry_bias_{index}") - PROJECTION_CARRY_BIAS)
                - BYTE_BASE
                * (cell(f"projection_carry_bias_{index + 1}") - PROJECTION_CARRY_BIAS),
                0,
                rows,
            )
        )
    identities.extend(
        (
            Identity(
                "projection_initial_carry",
                cell("projection_carry_bias_0") - PROJECTION_CARRY_BIAS,
                0,
                rows,
            ),
            Identity(
                "projection_terminal_carry",
                cell(f"projection_carry_bias_{PRODUCT_BYTES}") - PROJECTION_CARRY_BIAS,
                0,
                rows,
            ),
            Identity("remainder_lt_initial", cell("remainder_lt_carry_0"), 0, rows),
            Identity(
                "remainder_lt_terminal", cell(f"remainder_lt_carry_{LIMBS}"), 0, rows
            ),
            Identity("alias_initial_carry", cell("alias_carry_0"), 0, rows),
            Identity("alias_terminal_carry", cell(f"alias_carry_{LIMBS}"), 0, rows),
        )
    )
    for index in range(PRODUCT_BYTES + 1):
        identities.append(
            Identity(
                f"projection_carry_decomposition_{index}",
                cell(f"projection_carry_bias_{index}")
                - cell(f"projection_carry_lo_{index}")
                - BYTE_BASE * cell(f"projection_carry_hi_{index}"),
                0,
                rows,
            )
        )
    for index in range(LIMBS + 1):
        identities.append(
            Identity(
                f"remainder_lt_carry_boolean_{index}",
                boolean(cell(f"remainder_lt_carry_{index}")),
                0,
                rows,
            )
        )
        identities.append(
            Identity(
                f"alias_carry_boolean_{index}",
                boolean(cell(f"alias_carry_{index}")),
                0,
                rows,
            )
        )
    for index in range(LIMBS):
        identities.append(
            Identity(
                f"remainder_canonical_{index}",
                cell(f"remainder_{index}")
                + cell(f"remainder_delta_{index}")
                + cell(f"remainder_lt_carry_{index}")
                - MODULUS_MINUS_ONE_BYTES[index]
                - BYTE_BASE * cell(f"remainder_lt_carry_{index + 1}"),
                0,
                rows,
            )
        )
        identities.append(
            Identity(
                f"alias_increment_{index}",
                cell(f"remainder_{index}")
                + int(index == 0)
                + cell(f"alias_carry_{index}")
                - cell(f"alias_{index}")
                - BYTE_BASE * cell(f"alias_carry_{index + 1}"),
                0,
                rows,
            )
        )

    frozen = freeze_columns(columns)
    projection_trace = TraceTable("stark252_projection", frozen)
    projection_table = AirTable(
        "stark252_projection",
        tuple(frozen),
        rows,
        tuple(identities),
        MappingProxyType({"operation_index": tuple(range(rows))}),
    )
    counts: Counter[int] = Counter()
    for name in byte_columns:
        counts.update(frozen[name])
    byte_trace = TraceTable(
        "projection_byte_range",
        freeze_columns(
            {
                "value": tuple(range(256)),
                "multiplicity": tuple(counts[value] for value in range(256)),
            }
        ),
    )
    byte_table = AirTable(
        "projection_byte_range",
        ("value", "multiplicity"),
        256,
        (),
        MappingProxyType({"value": tuple(range(256))}),
    )
    lookup = LookupArgument(
        "stark252_projection_byte_range",
        tuple(
            LookupSide("stark252_projection", const(1), (cell(name),), 0, rows)
            for name in byte_columns
        ),
        (
            LookupSide(
                "projection_byte_range",
                const(1),
                (cell("value"),),
                0,
                256,
                cell("multiplicity"),
            ),
        ),
    )
    return Stark252ProjectionAirInstance(
        AirProgram(PROGRAM_ID, (projection_table, byte_table), (lookup,)),
        MappingProxyType(
            {
                "stark252_projection": projection_trace,
                "projection_byte_range": byte_trace,
            }
        ),
        tuple(request.operation_id for request in materialized),
        tuple(aliases),
    )


__all__ = [
    "Stark252ProjectionAirInstance",
    "Stark252ProjectionRequest",
    "PROJECTION_MODULUS",
    "STARK252_PRIME",
    "build_stark252_projection_air",
    "compatibility_felt_from_sha3_512",
]
