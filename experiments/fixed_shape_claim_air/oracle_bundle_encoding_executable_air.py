"""Executable packed-oracle bundle encoding AIR.

One row family constrains claim facts, another constrains the fixed 50-entry
authorization schedule, and a third packs the 150 authorization bits into the
exact 19 little-endian flag bytes.  Canonical authorization ranks reuse the
shared token-rank AIR and are linked to their exact bundle offsets.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Mapping, Sequence

from experiments.bl_pq512_crypto_foundation.oracle_bundle_commitment import (
    AUTHORIZATION_FLAGS_BYTES,
    BUNDLE_BYTES,
    BUNDLE_MAGIC,
    FACT_NAMES,
    TOKEN_ENCODED_BYTES,
    OracleCommitments,
    build_oracle_commitments,
    encode_oracle_bundle,
    oracle_bundle_from_slot,
)

from .executable_air import (
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
    namespace_air_program,
)
from .profile import AUTHORIZATIONS_PER_CLAIM, CalibrationProfile
from .semantics import ClaimSlot, SlotKind, StructuralError, validate_batch
from .token_rank_executable_air import (
    TokenRankAirInstance,
    TokenRankInput,
    build_token_rank_executable_air,
)


PROGRAM_ID: Final[str] = "BL-WAVE1A-PACKED-ORACLE-BUNDLE-ENCODING-AIR-v1"
_TOKEN_NAMESPACE: Final[str] = "oracle_token"
_PROFILE_CODES: Final[dict[str, int]] = {
    "K128_CALIBRATION": 1,
    "K256_DESIGN_POINT": 2,
    "K512_CALIBRATION": 3,
}
_FACT_FLAGS_OFFSET: Final[int] = 13
_AUTH_FLAGS_OFFSET: Final[int] = 14
_TOKEN_BASE: Final[int] = 33


@dataclass(frozen=True, slots=True)
class OracleBundleEncodingAirInstance:
    program: AirProgram
    traces: Mapping[str, TraceTable]
    bundles: tuple[bytes, ...]
    commitments: OracleCommitments
    token_air: TokenRankAirInstance
    token_ranks_constrained: bool = True
    fact_flags_constrained: bool = True
    authorization_flags_constrained: bool = True
    claim_semantics_links_constrained: bool = False
    hashes_constrained: bool = False
    signer_epoch_constrained: bool = False


def _token_inputs(slots: tuple[ClaimSlot, ...]) -> tuple[TokenRankInput, ...]:
    return tuple(
        TokenRankInput(
            slot.slot_index,
            index,
            slot.service_lines[index].prior_authorization
            if index < len(slot.service_lines)
            else "",
            slot.service_lines[index].authorization_present
            if index < len(slot.service_lines)
            else False,
        )
        for slot in slots
        for index in range(AUTHORIZATIONS_PER_CLAIM)
    )


def build_oracle_bundle_encoding_executable_air(
    profile: CalibrationProfile,
    slots: Sequence[ClaimSlot],
) -> OracleBundleEncodingAirInstance:
    if not isinstance(profile, CalibrationProfile):
        raise StructuralError("oracle_bundle_encoding_profile_invalid")
    materialized = tuple(slots)
    validate_batch(profile, materialized)
    oracle_bundles = tuple(
        oracle_bundle_from_slot(profile, slot) for slot in materialized
    )
    bundles = tuple(encode_oracle_bundle(value) for value in oracle_bundles)
    commitments = build_oracle_commitments(profile, oracle_bundles)
    token_inputs = _token_inputs(materialized)
    token_air = build_token_rank_executable_air(token_inputs)
    token_namespace = namespace_air_program(
        token_air.program, token_air.traces, _TOKEN_NAMESPACE
    )
    token_table_name = token_namespace.table_names["token_rank"]
    token_trace = token_namespace.traces[token_table_name]

    fact_columns: dict[str, tuple[int, ...]] = {
        "slot_index": tuple(slot.slot_index for slot in materialized),
        "real": tuple(int(slot.slot_kind is SlotKind.REAL) for slot in materialized),
        "fact_flags": tuple(bundle[_FACT_FLAGS_OFFSET] for bundle in bundles),
    }
    for byte_index in range(4):
        fact_columns[f"slot_byte_{byte_index}"] = tuple(
            bundle[9 + byte_index] for bundle in bundles
        )
    for name in FACT_NAMES:
        fact_columns[name] = tuple(int(getattr(slot, name)) for slot in materialized)
    frozen_fact = freeze_columns(fact_columns)
    fact_rows = profile.claim_slots
    fact_identities: list[Identity] = [
        Identity("real_boolean", boolean(cell("real")), 0, fact_rows),
        Identity(
            "slot_index_bytes",
            cell("slot_index")
            - 256 * cell("slot_byte_2")
            - cell("slot_byte_3"),
            0,
            fact_rows,
        ),
        Identity("slot_byte_0_zero", cell("slot_byte_0"), 0, fact_rows),
        Identity("slot_byte_1_zero", cell("slot_byte_1"), 0, fact_rows),
        Identity(
            "fact_flag_packing",
            cell("fact_flags")
            - cell("real")
            - sum(
                (
                    (1 << offset) * cell(name)
                    for offset, name in enumerate(FACT_NAMES, start=1)
                ),
                const(0),
            ),
            0,
            fact_rows,
        ),
    ]
    for name in FACT_NAMES:
        fact_identities.extend(
            (
                Identity(f"{name}_boolean", boolean(cell(name)), 0, fact_rows),
                Identity(
                    f"cover_{name}_zero",
                    (1 - cell("real")) * cell(name),
                    0,
                    fact_rows,
                ),
            )
        )
    fact_trace = TraceTable("oracle_fact", frozen_fact)
    fact_table = AirTable(
        "oracle_fact",
        tuple(frozen_fact),
        fact_rows,
        tuple(fact_identities),
        MappingProxyType({"slot_index": frozen_fact["slot_index"]}),
    )

    auth: dict[str, list[int]] = {
        name: []
        for name in (
            "slot_index",
            "authorization_index",
            "slot_real",
            "line_enabled",
            "required",
            "present",
            "enabled_prefix_before",
            "enabled_prefix_after",
            "is_first",
            "has_next",
            "gap_then_enabled",
        )
    }
    for slot in materialized:
        prefix = 0
        for index in range(AUTHORIZATIONS_PER_CLAIM):
            live = index < len(slot.service_lines)
            line = slot.service_lines[index] if live else None
            required = int(line.requires_prior_authorization) if line else 0
            present = int(line.authorization_present) if line else 0
            auth["slot_index"].append(slot.slot_index)
            auth["authorization_index"].append(index)
            auth["slot_real"].append(int(slot.slot_kind is SlotKind.REAL))
            auth["line_enabled"].append(int(live))
            auth["required"].append(required)
            auth["present"].append(present)
            auth["enabled_prefix_before"].append(prefix)
            prefix += int(live)
            auth["enabled_prefix_after"].append(prefix)
            auth["is_first"].append(int(index == 0))
            auth["has_next"].append(int(index + 1 < AUTHORIZATIONS_PER_CLAIM))
    auth["gap_then_enabled"] = [
        (1 - auth["line_enabled"][row]) * auth["line_enabled"][row + 1]
        if row + 1 < len(auth["line_enabled"])
        else 0
        for row in range(len(auth["line_enabled"]))
    ]
    frozen_auth = freeze_columns({name: tuple(values) for name, values in auth.items()})
    auth_rows = profile.claim_slots * AUTHORIZATIONS_PER_CLAIM
    auth_identities: list[Identity] = []
    for name in ("slot_real", "line_enabled", "required", "present"):
        auth_identities.append(
            Identity(f"{name}_boolean", boolean(cell(name)), 0, auth_rows)
        )
    auth_identities.extend(
        (
            Identity(
                "disabled_required_zero",
                (1 - cell("line_enabled")) * cell("required"),
                0,
                auth_rows,
            ),
            Identity(
                "disabled_present_zero",
                (1 - cell("line_enabled")) * cell("present"),
                0,
                auth_rows,
            ),
            Identity(
                "cover_line_zero",
                (1 - cell("slot_real")) * cell("line_enabled"),
                0,
                auth_rows,
            ),
            Identity(
                "enabled_prefix",
                cell("enabled_prefix_after")
                - cell("enabled_prefix_before")
                - cell("line_enabled"),
                0,
                auth_rows,
            ),
            Identity(
                "enabled_prefix_start",
                cell("is_first") * cell("enabled_prefix_before"),
                0,
                auth_rows,
            ),
            Identity(
                "enabled_prefix_transition",
                cell("has_next")
                * (
                    cell("enabled_prefix_before", 1)
                    - cell("enabled_prefix_after")
                ),
                0,
                auth_rows - 1,
                "transition",
            ),
            Identity(
                "gap_then_enabled_product",
                cell("gap_then_enabled")
                - cell("line_enabled", 1) * (1 - cell("line_enabled")),
                0,
                auth_rows - 1,
                "transition",
            ),
            Identity(
                "enabled_rows_are_prefix",
                cell("has_next") * cell("gap_then_enabled"),
                0,
                auth_rows,
            ),
        )
    )
    auth_trace = TraceTable("oracle_authorization", frozen_auth)
    auth_table = AirTable(
        "oracle_authorization",
        tuple(frozen_auth),
        auth_rows,
        tuple(auth_identities),
        MappingProxyType(
            {
                name: frozen_auth[name]
                for name in (
                    "slot_index",
                    "authorization_index",
                    "is_first",
                    "has_next",
                )
            }
        ),
    )

    flag_columns: dict[str, tuple[int, ...]] = {
        "slot_index": tuple(
            slot.slot_index
            for slot in materialized
            for _ in range(AUTHORIZATION_FLAGS_BYTES)
        ),
        "byte_index": tuple(
            index
            for _ in materialized
            for index in range(AUTHORIZATION_FLAGS_BYTES)
        ),
        "value": tuple(
            bundle[_AUTH_FLAGS_OFFSET + index]
            for bundle in bundles
            for index in range(AUTHORIZATION_FLAGS_BYTES)
        ),
    }
    for bit in range(8):
        flag_columns[f"bit_{bit}"] = tuple(
            (bundle[_AUTH_FLAGS_OFFSET + index] >> bit) & 1
            for bundle in bundles
            for index in range(AUTHORIZATION_FLAGS_BYTES)
        )
        flag_columns[f"active_bit_{bit}"] = tuple(
            int(index < AUTHORIZATION_FLAGS_BYTES - 1 or bit < 6)
            for _ in materialized
            for index in range(AUTHORIZATION_FLAGS_BYTES)
        )
    frozen_flag = freeze_columns(flag_columns)
    flag_rows = profile.claim_slots * AUTHORIZATION_FLAGS_BYTES
    flag_identities: list[Identity] = [
        Identity(
            "flag_byte_packing",
            cell("value")
            - sum(
                ((1 << bit) * cell(f"bit_{bit}") for bit in range(8)),
                const(0),
            ),
            0,
            flag_rows,
        ),
    ]
    for bit in range(8):
        flag_identities.extend(
            (
                Identity(
                    f"bit_{bit}_boolean",
                    boolean(cell(f"bit_{bit}")),
                    0,
                    flag_rows,
                ),
                Identity(
                    f"inactive_bit_{bit}_zero",
                    (1 - cell(f"active_bit_{bit}")) * cell(f"bit_{bit}"),
                    0,
                    flag_rows,
                ),
            )
        )
    flag_trace = TraceTable("oracle_authorization_flag_byte", frozen_flag)
    flag_table = AirTable(
        "oracle_authorization_flag_byte",
        tuple(frozen_flag),
        flag_rows,
        tuple(flag_identities),
        MappingProxyType(
            {
                name: frozen_flag[name]
                for name in (
                    "slot_index",
                    "byte_index",
                    *(f"active_bit_{bit}" for bit in range(8)),
                )
            }
        ),
    )

    link_columns: dict[str, tuple[int, ...]] = {
        "slot_index": tuple(
            slot.slot_index
            for slot in materialized
            for _ in range(AUTHORIZATIONS_PER_CLAIM)
        ),
        "token_index": tuple(
            index
            for _ in materialized
            for index in range(AUTHORIZATIONS_PER_CLAIM)
        ),
        "bundle_offset": tuple(
            _TOKEN_BASE + index * TOKEN_ENCODED_BYTES
            for _ in materialized
            for index in range(AUTHORIZATIONS_PER_CLAIM)
        ),
        "required": tuple(int(value.required) for value in token_inputs),
        "nonzero": tuple(int(any(value)) for value in token_air.encoded_ranks),
    }
    for byte_index in range(TOKEN_ENCODED_BYTES):
        link_columns[f"rank_byte_{byte_index}"] = tuple(
            bundle[_TOKEN_BASE + token_index * TOKEN_ENCODED_BYTES + byte_index]
            for bundle in bundles
            for token_index in range(AUTHORIZATIONS_PER_CLAIM)
        )
    frozen_link = freeze_columns(link_columns)
    link_rows = auth_rows
    link_trace = TraceTable("oracle_token_link", frozen_link)
    link_table = AirTable(
        "oracle_token_link",
        tuple(frozen_link),
        link_rows,
        (),
        MappingProxyType(
            {
                name: frozen_link[name]
                for name in ("slot_index", "token_index", "bundle_offset")
            }
        ),
    )

    token_positions = set(range(_TOKEN_BASE, BUNDLE_BYTES))
    scalar_positions = set(range(9, 14))
    flag_positions = set(range(_AUTH_FLAGS_OFFSET, _TOKEN_BASE))
    bundle_columns = freeze_columns(
        {
            "slot_index": tuple(
                slot.slot_index for slot in materialized for _ in range(BUNDLE_BYTES)
            ),
            "byte_index": tuple(
                index for _ in materialized for index in range(BUNDLE_BYTES)
            ),
            "is_token_byte": tuple(
                int(index in token_positions)
                for _ in materialized
                for index in range(BUNDLE_BYTES)
            ),
            "is_scalar_byte": tuple(
                int(index in scalar_positions)
                for _ in materialized
                for index in range(BUNDLE_BYTES)
            ),
            "is_flag_byte": tuple(
                int(index in flag_positions)
                for _ in materialized
                for index in range(BUNDLE_BYTES)
            ),
            "fixed_active": tuple(
                int(index < len(BUNDLE_MAGIC) or index == 8)
                for _ in materialized
                for index in range(BUNDLE_BYTES)
            ),
            "fixed_value": tuple(
                (
                    BUNDLE_MAGIC[index]
                    if index < len(BUNDLE_MAGIC)
                    else _PROFILE_CODES[profile.profile_id]
                    if index == 8
                    else 0
                )
                for _ in materialized
                for index in range(BUNDLE_BYTES)
            ),
            "value": tuple(byte for bundle in bundles for byte in bundle),
        }
    )
    bundle_rows = profile.claim_slots * BUNDLE_BYTES
    bundle_trace = TraceTable("oracle_bundle_byte", bundle_columns)
    bundle_table = AirTable(
        "oracle_bundle_byte",
        tuple(bundle_columns),
        bundle_rows,
        (
            Identity(
                "fixed_header_value",
                cell("fixed_active") * (cell("value") - cell("fixed_value")),
                0,
                bundle_rows,
            ),
        ),
        MappingProxyType(
            {
                name: bundle_columns[name]
                for name in (
                    "slot_index",
                    "byte_index",
                    "is_token_byte",
                    "is_scalar_byte",
                    "is_flag_byte",
                    "fixed_active",
                    "fixed_value",
                )
            }
        ),
    )

    byte_multiplicity = Counter(bundle_columns["value"])
    for prefix in ("rank_byte", "difference_byte"):
        for byte_index in range(TOKEN_ENCODED_BYTES):
            byte_multiplicity.update(token_trace.columns[f"{prefix}_{byte_index}"])
    byte_trace = TraceTable(
        "oracle_byte_range",
        freeze_columns(
            {
                "value": tuple(range(256)),
                "multiplicity": tuple(
                    byte_multiplicity[value] for value in range(256)
                ),
            }
        ),
    )
    byte_table = AirTable(
        "oracle_byte_range",
        tuple(byte_trace.columns),
        256,
        (),
        MappingProxyType({"value": tuple(range(256))}),
    )

    rank_values = tuple(
        cell(f"rank_byte_{index}") for index in range(TOKEN_ENCODED_BYTES)
    )
    token_equality = LookupArgument(
        "oracle_token_ranks_match_links",
        (
            LookupSide(
                token_table_name,
                const(1),
                (
                    cell("group"),
                    cell("index"),
                    cell("required"),
                    cell("nonzero"),
                    *rank_values,
                ),
                0,
                link_rows,
            ),
        ),
        (
            LookupSide(
                "oracle_token_link",
                const(1),
                (
                    cell("slot_index"),
                    cell("token_index"),
                    cell("required"),
                    cell("nonzero"),
                    *rank_values,
                ),
                0,
                link_rows,
            ),
        ),
    )
    token_presence_link = LookupArgument(
        "oracle_token_presence_matches_authorization",
        (
            LookupSide(
                "oracle_token_link",
                const(1),
                (
                    cell("slot_index"),
                    cell("token_index"),
                    cell("required"),
                    cell("nonzero"),
                ),
                0,
                link_rows,
            ),
        ),
        (
            LookupSide(
                "oracle_authorization",
                const(1),
                (
                    cell("slot_index"),
                    cell("authorization_index"),
                    cell("present"),
                    cell("present"),
                ),
                0,
                auth_rows,
            ),
        ),
    )
    auth_real_link = LookupArgument(
        "oracle_authorization_real_matches_fact",
        (
            LookupSide(
                "oracle_authorization",
                const(1),
                (cell("slot_index"), cell("slot_real")),
                0,
                auth_rows,
            ),
        ),
        (
            LookupSide(
                "oracle_fact",
                const(1),
                (cell("slot_index"), cell("real")),
                0,
                fact_rows,
                const(AUTHORIZATIONS_PER_CLAIM),
            ),
        ),
    )
    token_bundle_link = LookupArgument(
        "oracle_token_bytes_match_bundle",
        tuple(
            LookupSide(
                "oracle_token_link",
                const(1),
                (
                    cell("slot_index"),
                    cell("bundle_offset") + byte_index,
                    cell(f"rank_byte_{byte_index}"),
                ),
                0,
                link_rows,
            )
            for byte_index in range(TOKEN_ENCODED_BYTES)
        ),
        (
            LookupSide(
                "oracle_bundle_byte",
                cell("is_token_byte"),
                (cell("slot_index"), cell("byte_index"), cell("value")),
                0,
                bundle_rows,
            ),
        ),
    )
    fact_bundle_link = LookupArgument(
        "oracle_fact_bytes_match_bundle",
        (
            LookupSide(
                "oracle_fact",
                const(1),
                (cell("slot_index"), const(9), cell("slot_byte_0")),
                0,
                fact_rows,
            ),
            LookupSide(
                "oracle_fact",
                const(1),
                (cell("slot_index"), const(10), cell("slot_byte_1")),
                0,
                fact_rows,
            ),
            LookupSide(
                "oracle_fact",
                const(1),
                (cell("slot_index"), const(11), cell("slot_byte_2")),
                0,
                fact_rows,
            ),
            LookupSide(
                "oracle_fact",
                const(1),
                (cell("slot_index"), const(12), cell("slot_byte_3")),
                0,
                fact_rows,
            ),
            LookupSide(
                "oracle_fact",
                const(1),
                (cell("slot_index"), const(13), cell("fact_flags")),
                0,
                fact_rows,
            ),
        ),
        (
            LookupSide(
                "oracle_bundle_byte",
                cell("is_scalar_byte"),
                (cell("slot_index"), cell("byte_index"), cell("value")),
                0,
                bundle_rows,
            ),
        ),
    )
    flag_bundle_link = LookupArgument(
        "oracle_authorization_flag_bytes_match_bundle",
        (
            LookupSide(
                "oracle_authorization_flag_byte",
                const(1),
                (
                    cell("slot_index"),
                    cell("byte_index") + _AUTH_FLAGS_OFFSET,
                    cell("value"),
                ),
                0,
                flag_rows,
            ),
        ),
        (
            LookupSide(
                "oracle_bundle_byte",
                cell("is_flag_byte"),
                (cell("slot_index"), cell("byte_index"), cell("value")),
                0,
                bundle_rows,
            ),
        ),
    )
    auth_bit_link = LookupArgument(
        "oracle_authorization_bits_match_flag_bytes",
        tuple(
            LookupSide(
                "oracle_authorization",
                const(1),
                (
                    cell("slot_index"),
                    3 * cell("authorization_index") + offset,
                    cell(name),
                ),
                0,
                auth_rows,
            )
            for offset, name in enumerate(("line_enabled", "required", "present"))
        ),
        tuple(
            LookupSide(
                "oracle_authorization_flag_byte",
                cell(f"active_bit_{bit}"),
                (
                    cell("slot_index"),
                    8 * cell("byte_index") + bit,
                    cell(f"bit_{bit}"),
                ),
                0,
                flag_rows,
            )
            for bit in range(8)
        ),
    )
    shared_byte_range = LookupArgument(
        "oracle_values_are_bytes",
        (
            *(
                LookupSide(
                    token_table_name,
                    const(1),
                    (cell(f"{prefix}_{byte_index}"),),
                    0,
                    link_rows,
                )
                for prefix in ("rank_byte", "difference_byte")
                for byte_index in range(TOKEN_ENCODED_BYTES)
            ),
            LookupSide(
                "oracle_bundle_byte",
                const(1),
                (cell("value"),),
                0,
                bundle_rows,
            ),
        ),
        (
            LookupSide(
                "oracle_byte_range",
                const(1),
                (cell("value"),),
                0,
                256,
                cell("multiplicity"),
            ),
        ),
    )
    traces = MappingProxyType(
        {
            token_table_name: token_trace,
            "oracle_fact": fact_trace,
            "oracle_authorization": auth_trace,
            "oracle_authorization_flag_byte": flag_trace,
            "oracle_token_link": link_trace,
            "oracle_bundle_byte": bundle_trace,
            "oracle_byte_range": byte_trace,
        }
    )
    program = AirProgram(
        PROGRAM_ID,
        (
            next(
                table
                for table in token_namespace.program.tables
                if table.name == token_table_name
            ),
            fact_table,
            auth_table,
            flag_table,
            link_table,
            bundle_table,
            byte_table,
        ),
        (
            token_equality,
            token_presence_link,
            auth_real_link,
            token_bundle_link,
            fact_bundle_link,
            flag_bundle_link,
            auth_bit_link,
            shared_byte_range,
        ),
    )
    return OracleBundleEncodingAirInstance(
        program, traces, bundles, commitments, token_air
    )


__all__ = [
    "OracleBundleEncodingAirInstance",
    "build_oracle_bundle_encoding_executable_air",
]
