"""Executable AIR for the canonical 42-byte base-37 identifier rank.

The wire rank is the authoritative compact form used by the packed oracle and
compact claim-source candidates.  This component proves that every rank is in
``[0, 37**64)`` and that fields marked required are nonzero.  Character-to-rank
conversion belongs to the signed ingestion adapter; the proof relation consumes
the unique reversible rank representation.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Mapping, Sequence

from experiments.bl_pq512_crypto_foundation.oracle_bundle_commitment import (
    TOKEN_ENCODED_BYTES,
    encode_authorization_token,
)

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


PROGRAM_ID: Final[str] = "BL-WAVE1A-CANONICAL-TOKEN-RANK-AIR-v1"
TOKEN_RANK_LIMIT: Final[int] = 37**64
TOKEN_RANK_MAX_BYTES: Final[bytes] = (TOKEN_RANK_LIMIT - 1).to_bytes(
    TOKEN_ENCODED_BYTES, "big"
)


@dataclass(frozen=True, slots=True)
class TokenRankInput:
    group: int
    index: int
    token: str
    required: bool

    def __post_init__(self) -> None:
        if type(self.group) is not int or not 0 <= self.group < M31:
            raise StructuralError("token_rank_group_invalid")
        if type(self.index) is not int or not 0 <= self.index < M31:
            raise StructuralError("token_rank_index_invalid")
        if type(self.required) is not bool:
            raise StructuralError("token_rank_required_not_boolean")
        encoded = encode_authorization_token(self.token)
        if self.required and not any(encoded):
            raise StructuralError("token_rank_required_token_empty")


@dataclass(frozen=True, slots=True)
class TokenRankAirInstance:
    program: AirProgram
    traces: Mapping[str, TraceTable]
    encoded_ranks: tuple[bytes, ...]


def _comparison_witness(rank: bytes) -> tuple[bytes, tuple[int, ...]]:
    if type(rank) is not bytes or len(rank) != TOKEN_ENCODED_BYTES:
        raise StructuralError("token_rank_encoding_invalid")
    difference = bytearray(TOKEN_ENCODED_BYTES)
    borrows = [0]
    borrow = 0
    for offset in range(TOKEN_ENCODED_BYTES - 1, -1, -1):
        value = TOKEN_RANK_MAX_BYTES[offset] - rank[offset] - borrow
        if value < 0:
            value += 256
            borrow = 1
        else:
            borrow = 0
        difference[offset] = value
        borrows.append(borrow)
    if borrow:
        raise StructuralError("token_rank_out_of_range")
    return bytes(difference), tuple(borrows)


def build_token_rank_executable_air(
    tokens: Sequence[TokenRankInput],
) -> TokenRankAirInstance:
    materialized = tuple(tokens)
    if not materialized:
        raise StructuralError("token_rank_inputs_required")
    if any(not isinstance(value, TokenRankInput) for value in materialized):
        raise StructuralError("token_rank_input_type_invalid")
    coordinates = tuple((value.group, value.index) for value in materialized)
    if len(set(coordinates)) != len(coordinates):
        raise StructuralError("token_rank_coordinate_duplicate")

    encoded = tuple(encode_authorization_token(value.token) for value in materialized)
    comparisons = tuple(_comparison_witness(value) for value in encoded)
    columns: dict[str, tuple[int, ...]] = {
        "group": tuple(value.group for value in materialized),
        "index": tuple(value.index for value in materialized),
        "required": tuple(int(value.required) for value in materialized),
    }
    for offset in range(TOKEN_ENCODED_BYTES):
        columns[f"rank_byte_{offset}"] = tuple(value[offset] for value in encoded)
        columns[f"difference_byte_{offset}"] = tuple(
            value[0][offset] for value in comparisons
        )
    for step in range(TOKEN_ENCODED_BYTES + 1):
        columns[f"borrow_{step}"] = tuple(value[1][step] for value in comparisons)
    sums = tuple(sum(value) for value in encoded)
    nonzero = tuple(int(value != 0) for value in sums)
    columns["byte_sum"] = sums
    columns["nonzero"] = nonzero
    columns["sum_inverse"] = tuple(
        pow(value, M31 - 2, M31) if value else 0 for value in sums
    )
    frozen = freeze_columns(columns)
    rows = len(materialized)

    identities: list[Identity] = [
        Identity("required_boolean", boolean(cell("required")), 0, rows),
        Identity("nonzero_boolean", boolean(cell("nonzero")), 0, rows),
        Identity("initial_borrow_zero", cell("borrow_0"), 0, rows),
        Identity(
            "terminal_borrow_zero",
            cell(f"borrow_{TOKEN_ENCODED_BYTES}"),
            0,
            rows,
        ),
        Identity(
            "byte_sum",
            cell("byte_sum")
            - sum((cell(f"rank_byte_{offset}") for offset in range(TOKEN_ENCODED_BYTES)), const(0)),
            0,
            rows,
        ),
        Identity(
            "nonzero_inverse",
            cell("byte_sum") * cell("sum_inverse") - cell("nonzero"),
            0,
            rows,
        ),
        Identity(
            "zero_sum_when_zero",
            cell("byte_sum") * (1 - cell("nonzero")),
            0,
            rows,
        ),
        Identity(
            "required_nonzero",
            cell("required") * (1 - cell("nonzero")),
            0,
            rows,
        ),
    ]
    for step in range(TOKEN_ENCODED_BYTES):
        identities.append(
            Identity(
                f"borrow_{step}_boolean",
                boolean(cell(f"borrow_{step}")),
                0,
                rows,
            )
        )
        offset = TOKEN_ENCODED_BYTES - 1 - step
        identities.append(
            Identity(
                f"rank_bound_step_{step}",
                TOKEN_RANK_MAX_BYTES[offset]
                - cell(f"rank_byte_{offset}")
                - cell(f"borrow_{step}")
                - cell(f"difference_byte_{offset}")
                + 256 * cell(f"borrow_{step + 1}"),
                0,
                rows,
            )
        )
    identities.append(
        Identity(
            f"borrow_{TOKEN_ENCODED_BYTES}_boolean",
            boolean(cell(f"borrow_{TOKEN_ENCODED_BYTES}")),
            0,
            rows,
        )
    )
    token_table = AirTable(
        "token_rank",
        tuple(frozen),
        rows,
        tuple(identities),
        MappingProxyType(
            {
                "group": frozen["group"],
                "index": frozen["index"],
            }
        ),
    )
    token_trace = TraceTable("token_rank", frozen)

    multiplicity = Counter(
        byte
        for rank, (difference, _) in zip(encoded, comparisons, strict=True)
        for byte in (*rank, *difference)
    )
    byte_trace = TraceTable(
        "token_byte_range",
        freeze_columns(
            {
                "value": tuple(range(256)),
                "multiplicity": tuple(multiplicity[value] for value in range(256)),
            }
        ),
    )
    byte_table = AirTable(
        "token_byte_range",
        tuple(byte_trace.columns),
        256,
        (),
        MappingProxyType({"value": tuple(range(256))}),
    )
    byte_sources = tuple(
        LookupSide("token_rank", const(1), (cell(name),), 0, rows)
        for prefix in ("rank_byte", "difference_byte")
        for name in (f"{prefix}_{offset}" for offset in range(TOKEN_ENCODED_BYTES))
    )
    byte_lookup = LookupArgument(
        "token_rank_bytes_are_bytes",
        byte_sources,
        (
            LookupSide(
                "token_byte_range",
                const(1),
                (cell("value"),),
                0,
                256,
                cell("multiplicity"),
            ),
        ),
    )
    return TokenRankAirInstance(
        AirProgram(PROGRAM_ID, (token_table, byte_table), (byte_lookup,)),
        MappingProxyType(
            {
                "token_rank": token_trace,
                "token_byte_range": byte_trace,
            }
        ),
        encoded,
    )


__all__ = [
    "TOKEN_RANK_LIMIT",
    "TOKEN_RANK_MAX_BYTES",
    "TokenRankAirInstance",
    "TokenRankInput",
    "build_token_rank_executable_air",
]
