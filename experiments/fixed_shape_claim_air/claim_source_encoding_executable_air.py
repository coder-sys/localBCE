"""Executable compact claim-source token/bundle binding AIR.

This component binds every canonical 42-byte identifier rank to its exact byte
offset in the reversible 5,648-byte claim-source bundle.  It deliberately keeps
the remaining scalar/text fields and the SHA3 tree as explicit open flags until
their semantic tables and streamed hash rows are composed into the same backend.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Mapping, Sequence

from experiments.bl_pq512_crypto_foundation.claim_source_commitment import (
    BUNDLE_MAGIC,
    CLAIM_SOURCE_BUNDLE_BYTES,
    ClaimSourceCommitments,
    build_claim_source_commitments,
    claim_source_bundle_from_slot,
    encode_claim_source_bundle,
)
from experiments.bl_pq512_crypto_foundation.oracle_bundle_commitment import (
    TOKEN_ENCODED_BYTES,
)

from .executable_air import (
    M31,
    AirProgram,
    AirTable,
    Identity,
    LookupArgument,
    LookupSide,
    TraceTable,
    cell,
    const,
    boolean,
    freeze_columns,
    namespace_air_program,
)
from .profile import SERVICE_LINES_PER_CLAIM, CalibrationProfile
from .semantics import ClaimSlot, SlotKind, StructuralError, validate_batch
from .token_rank_executable_air import (
    TokenRankAirInstance,
    TokenRankInput,
    build_token_rank_executable_air,
)


PROGRAM_ID: Final[str] = "BL-WAVE1A-COMPACT-CLAIM-SOURCE-ENCODING-AIR-v2"
_TOKEN_NAMESPACE: Final[str] = "source_token"
_TOKEN_COUNT_PER_SLOT: Final[int] = 3 + 2 * SERVICE_LINES_PER_CLAIM
_LINE_BASE: Final[int] = 448
_LINE_BYTES: Final[int] = 104
_AUTHORITY_OFFSET: Final[int] = 12
_CLAIM_ID_OFFSET: Final[int] = 62
_MEMBER_ID_OFFSET: Final[int] = 104
_LINE_ID_OFFSET: Final[int] = 1
_LINE_AUTHORIZATION_OFFSET: Final[int] = 62
_PROFILE_CODES: Final[dict[str, int]] = {
    "K128_CALIBRATION": 1,
    "K256_DESIGN_POINT": 2,
    "K512_CALIBRATION": 3,
}
_SCALAR_SPECS: Final[tuple[tuple[str, int, int], ...]] = (
    ("slot", 9, 2),
    ("real", 11, 1),
    ("sequence", 54, 8),
    ("npi_length", 146, 1),
    ("npi", 147, 10),
    ("attempt", 157, 4),
    ("revision", 161, 1),
    ("parent", 162, 4),
    ("total_charge", 166, 4),
    ("patient_responsibility", 170, 4),
    ("diagnosis_count", 174, 1),
    ("service_count", 447, 1),
)


@dataclass(frozen=True, slots=True)
class ClaimSourceEncodingAirInstance:
    program: AirProgram
    traces: Mapping[str, TraceTable]
    bundles: tuple[bytes, ...]
    commitments: ClaimSourceCommitments
    token_air: TokenRankAirInstance
    token_ranks_constrained: bool = True
    bundle_token_links_constrained: bool = True
    scalar_fields_constrained: bool = True
    bundle_other_fields_constrained: bool = False
    hashes_constrained: bool = False
    source_authority_constrained: bool = False


def _token_offsets() -> tuple[int, ...]:
    offsets = [_AUTHORITY_OFFSET, _CLAIM_ID_OFFSET, _MEMBER_ID_OFFSET]
    for index in range(SERVICE_LINES_PER_CLAIM):
        base = _LINE_BASE + index * _LINE_BYTES
        offsets.extend((base + _LINE_ID_OFFSET, base + _LINE_AUTHORIZATION_OFFSET))
    result = tuple(offsets)
    if len(result) != _TOKEN_COUNT_PER_SLOT:
        raise AssertionError("claim_source_token_offset_count_invalid")
    if any(
        not 0 <= value <= CLAIM_SOURCE_BUNDLE_BYTES - TOKEN_ENCODED_BYTES
        for value in result
    ):
        raise AssertionError("claim_source_token_offset_out_of_range")
    return result


def _token_inputs(
    slots: tuple[ClaimSlot, ...],
) -> tuple[TokenRankInput, ...]:
    values: list[TokenRankInput] = []
    for slot in slots:
        real = slot.slot_kind is SlotKind.REAL
        values.extend(
            (
                TokenRankInput(slot.slot_index, 0, slot.source_authority_id, real),
                TokenRankInput(slot.slot_index, 1, slot.claim_id, real),
                TokenRankInput(slot.slot_index, 2, slot.member_id, False),
            )
        )
        for index in range(SERVICE_LINES_PER_CLAIM):
            live = index < len(slot.service_lines)
            line_id = slot.service_lines[index].line_id if live else ""
            authorization = (
                slot.service_lines[index].prior_authorization if live else ""
            )
            values.extend(
                (
                    TokenRankInput(
                        slot.slot_index,
                        3 + 2 * index,
                        line_id,
                        live,
                    ),
                    TokenRankInput(
                        slot.slot_index,
                        4 + 2 * index,
                        authorization,
                        False,
                    ),
                )
            )
    return tuple(values)


def _scalar_columns(
    materialized: tuple[ClaimSlot, ...], bundles: tuple[bytes, ...]
) -> dict[str, tuple[int, ...]]:
    columns: dict[str, tuple[int, ...]] = {
        "slot_index": tuple(slot.slot_index for slot in materialized),
    }
    for name, offset, count in _SCALAR_SPECS:
        for byte_index in range(count):
            columns[f"{name}_byte_{byte_index}"] = tuple(
                bundle[offset + byte_index] for bundle in bundles
            )
    npi_present = tuple(int(bundle[146] == 10) for bundle in bundles)
    sequence_sums = tuple(sum(bundle[54:62]) for bundle in bundles)
    columns["npi_present"] = npi_present
    for index in range(10):
        columns[f"npi_digit_{index}"] = tuple(
            bundle[147 + index] - 48 if present else 0
            for bundle, present in zip(bundles, npi_present, strict=True)
        )
    for index in range(9):
        columns[f"npi_contribution_{index}"] = tuple(
            (
                (2 * (bundle[147 + index] - 48))
                - (9 if bundle[147 + index] - 48 >= 5 else 0)
                if index % 2 == 0
                else bundle[147 + index] - 48
            )
            if present
            else 0
            for bundle, present in zip(bundles, npi_present, strict=True)
        )
    luhn_totals = tuple(
        24
        + sum(
            (
                (2 * (bundle[147 + index] - 48))
                - (9 if bundle[147 + index] - 48 >= 5 else 0)
                if index % 2 == 0
                else bundle[147 + index] - 48
            )
            for index in range(9)
        )
        if present
        else 0
        for bundle, present in zip(bundles, npi_present, strict=True)
    )
    columns["npi_luhn_total"] = luhn_totals
    columns["npi_luhn_quotient"] = tuple(
        (total + (bundle[156] - 48)) // 10 if present else 0
        for bundle, present, total in zip(
            bundles, npi_present, luhn_totals, strict=True
        )
    )
    columns["sequence_sum"] = sequence_sums
    columns["sequence_inverse"] = tuple(
        pow(value, M31 - 2, M31) if value else 0 for value in sequence_sums
    )
    return columns


def build_claim_source_encoding_executable_air(
    profile: CalibrationProfile,
    slots: Sequence[ClaimSlot],
) -> ClaimSourceEncodingAirInstance:
    if not isinstance(profile, CalibrationProfile):
        raise StructuralError("claim_source_encoding_profile_invalid")
    materialized = tuple(slots)
    validate_batch(profile, materialized)
    bundles = tuple(
        encode_claim_source_bundle(claim_source_bundle_from_slot(profile, slot))
        for slot in materialized
    )
    commitments = build_claim_source_commitments(profile, materialized)
    token_inputs = _token_inputs(materialized)
    token_air = build_token_rank_executable_air(token_inputs)
    token_namespace = namespace_air_program(
        token_air.program,
        token_air.traces,
        _TOKEN_NAMESPACE,
    )

    offsets = _token_offsets()
    link_columns: dict[str, tuple[int, ...]] = {
        "slot_index": tuple(
            slot.slot_index
            for slot in materialized
            for _ in range(_TOKEN_COUNT_PER_SLOT)
        ),
        "token_index": tuple(
            index
            for _ in materialized
            for index in range(_TOKEN_COUNT_PER_SLOT)
        ),
        "bundle_offset": tuple(
            offsets[index]
            for _ in materialized
            for index in range(_TOKEN_COUNT_PER_SLOT)
        ),
        "required": tuple(int(value.required) for value in token_inputs),
        "nonzero": tuple(int(any(value)) for value in token_air.encoded_ranks),
        "requires_real": tuple(
            int(index in (0, 1))
            for _ in materialized
            for index in range(_TOKEN_COUNT_PER_SLOT)
        ),
        "is_authority": tuple(
            int(index == 0)
            for _ in materialized
            for index in range(_TOKEN_COUNT_PER_SLOT)
        ),
        "is_claim_id": tuple(
            int(index == 1)
            for _ in materialized
            for index in range(_TOKEN_COUNT_PER_SLOT)
        ),
        "is_member": tuple(
            int(index == 2)
            for _ in materialized
            for index in range(_TOKEN_COUNT_PER_SLOT)
        ),
        "requires_nonzero": tuple(
            int(index >= 3 and index % 2 == 1)
            for _ in materialized
            for index in range(_TOKEN_COUNT_PER_SLOT)
        ),
        "is_line_authorization": tuple(
            int(index >= 4 and index % 2 == 0)
            for _ in materialized
            for index in range(_TOKEN_COUNT_PER_SLOT)
        ),
        "is_service_token": tuple(
            int(index >= 3)
            for _ in materialized
            for index in range(_TOKEN_COUNT_PER_SLOT)
        ),
    }
    for byte_index in range(TOKEN_ENCODED_BYTES):
        link_columns[f"rank_byte_{byte_index}"] = tuple(
            bundle[offsets[token_index] + byte_index]
            for bundle in bundles
            for token_index in range(_TOKEN_COUNT_PER_SLOT)
        )
    frozen_link = freeze_columns(link_columns)
    link_rows = len(token_inputs)
    link_trace = TraceTable("claim_source_token_link", frozen_link)
    link_table = AirTable(
        "claim_source_token_link",
        tuple(frozen_link),
        link_rows,
        (
            Identity(
                "optional_token_not_required",
                (1 - cell("requires_real") - cell("requires_nonzero"))
                * cell("required"),
                0,
                link_rows,
            ),
            Identity(
                "line_identifier_required_iff_nonzero",
                cell("requires_nonzero")
                * (cell("required") - cell("nonzero")),
                0,
                link_rows,
            ),
        ),
        MappingProxyType(
            {
                name: frozen_link[name]
                for name in (
                    "slot_index",
                    "token_index",
                    "bundle_offset",
                    "requires_real",
                    "is_authority",
                    "is_claim_id",
                    "is_member",
                    "requires_nonzero",
                    "is_line_authorization",
                    "is_service_token",
                )
            }
        ),
    )

    frozen_scalar = freeze_columns(_scalar_columns(materialized, bundles))
    scalar_rows = profile.claim_slots
    real = cell("real_byte_0")
    scalar_identities: list[Identity] = [
        Identity("real_boolean", boolean(real), 0, scalar_rows),
        Identity("npi_present_boolean", boolean(cell("npi_present")), 0, scalar_rows),
        Identity(
            "slot_index_bytes",
            cell("slot_index")
            - 256 * cell("slot_byte_0")
            - cell("slot_byte_1"),
            0,
            scalar_rows,
        ),
        Identity(
            "npi_length",
            cell("npi_length_byte_0") - 10 * cell("npi_present"),
            0,
            scalar_rows,
        ),
        Identity(
            "sequence_sum",
            cell("sequence_sum")
            - sum(
                (cell(f"sequence_byte_{index}") for index in range(8)),
                const(0),
            ),
            0,
            scalar_rows,
        ),
        Identity(
            "real_sequence_nonzero",
            cell("sequence_sum") * cell("sequence_inverse") - real,
            0,
            scalar_rows,
        ),
        Identity(
            "cover_sequence_zero",
            cell("sequence_sum") * (1 - real),
            0,
            scalar_rows,
        ),
    ]
    for index in range(10):
        scalar_identities.append(
            Identity(
                f"absent_npi_byte_{index}",
                (1 - cell("npi_present")) * cell(f"npi_byte_{index}"),
                0,
                scalar_rows,
            )
        )
        scalar_identities.append(
            Identity(
                f"npi_digit_byte_{index}",
                cell(f"npi_byte_{index}")
                - 48 * cell("npi_present")
                - cell(f"npi_digit_{index}"),
                0,
                scalar_rows,
            )
        )
    scalar_identities.extend(
        (
            Identity(
                "npi_luhn_total",
                cell("npi_luhn_total")
                - 24 * cell("npi_present")
                - sum(
                    (
                        cell(f"npi_contribution_{index}")
                        for index in range(9)
                    ),
                    const(0),
                ),
                0,
                scalar_rows,
            ),
            Identity(
                "npi_luhn_check_digit",
                cell("npi_luhn_total")
                + cell("npi_digit_9")
                - 10 * cell("npi_luhn_quotient"),
                0,
                scalar_rows,
            ),
            Identity(
                "absent_npi_luhn_quotient_zero",
                (1 - cell("npi_present")) * cell("npi_luhn_quotient"),
                0,
                scalar_rows,
            ),
        )
    )
    cover_columns = (
        *(f"sequence_byte_{index}" for index in range(8)),
        "npi_length_byte_0",
        *(f"npi_byte_{index}" for index in range(10)),
        *(f"attempt_byte_{index}" for index in range(4)),
        "revision_byte_0",
        *(f"parent_byte_{index}" for index in range(4)),
        *(f"total_charge_byte_{index}" for index in range(4)),
        *(f"patient_responsibility_byte_{index}" for index in range(4)),
        "diagnosis_count_byte_0",
        "service_count_byte_0",
    )
    scalar_identities.extend(
        Identity(
            f"cover_{name}_zero",
            (1 - real) * cell(name),
            0,
            scalar_rows,
        )
        for name in cover_columns
    )
    for index, expected in enumerate((0, 0, 0, 1)):
        scalar_identities.append(
            Identity(
                f"real_attempt_byte_{index}",
                real * (cell(f"attempt_byte_{index}") - expected),
                0,
                scalar_rows,
            )
        )
    scalar_identities.append(
        Identity(
            "real_revision_original",
            real * (cell("revision_byte_0") - 1),
            0,
            scalar_rows,
        )
    )
    scalar_identities.extend(
        Identity(
            f"real_parent_byte_{index}_zero",
            real * cell(f"parent_byte_{index}"),
            0,
            scalar_rows,
        )
        for index in range(4)
    )
    scalar_trace = TraceTable("claim_source_scalar", frozen_scalar)
    scalar_table = AirTable(
        "claim_source_scalar",
        tuple(frozen_scalar),
        scalar_rows,
        tuple(scalar_identities),
        MappingProxyType({"slot_index": frozen_scalar["slot_index"]}),
    )

    token_positions = {
        offset + byte_index
        for offset in offsets
        for byte_index in range(TOKEN_ENCODED_BYTES)
    }
    diagnosis_positions = set(range(175, 447))
    service_non_token_positions = {
        _LINE_BASE + line_index * _LINE_BYTES + relative
        for line_index in range(SERVICE_LINES_PER_CLAIM)
        for relative in (0, *range(43, 62))
    }
    bundle_columns = freeze_columns(
        {
            "slot_index": tuple(
                slot.slot_index
                for slot in materialized
                for _ in range(CLAIM_SOURCE_BUNDLE_BYTES)
            ),
            "byte_index": tuple(
                index
                for _ in materialized
                for index in range(CLAIM_SOURCE_BUNDLE_BYTES)
            ),
            "is_token_byte": tuple(
                int(index in token_positions)
                for _ in materialized
                for index in range(CLAIM_SOURCE_BUNDLE_BYTES)
            ),
            "is_scalar_byte": tuple(
                int(
                    any(
                        offset <= index < offset + count
                        for _, offset, count in _SCALAR_SPECS
                    )
                )
                for _ in materialized
                for index in range(CLAIM_SOURCE_BUNDLE_BYTES)
            ),
            "is_diagnosis_byte": tuple(
                int(index in diagnosis_positions)
                for _ in materialized
                for index in range(CLAIM_SOURCE_BUNDLE_BYTES)
            ),
            "is_service_non_token_byte": tuple(
                int(index in service_non_token_positions)
                for _ in materialized
                for index in range(CLAIM_SOURCE_BUNDLE_BYTES)
            ),
            "fixed_value_active": tuple(
                int(index < len(BUNDLE_MAGIC) or index == 8)
                for _ in materialized
                for index in range(CLAIM_SOURCE_BUNDLE_BYTES)
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
                for index in range(CLAIM_SOURCE_BUNDLE_BYTES)
            ),
            "value": tuple(byte for bundle in bundles for byte in bundle),
        }
    )
    bundle_rows = profile.claim_slots * CLAIM_SOURCE_BUNDLE_BYTES
    bundle_trace = TraceTable("claim_source_bundle_byte", bundle_columns)
    bundle_table = AirTable(
        "claim_source_bundle_byte",
        tuple(bundle_columns),
        bundle_rows,
        (
            Identity(
                "fixed_header_value",
                cell("fixed_value_active") * (cell("value") - cell("fixed_value")),
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
                    "is_diagnosis_byte",
                    "is_service_non_token_byte",
                    "fixed_value_active",
                    "fixed_value",
                )
            }
        ),
    )

    token_table_name = token_namespace.table_names["token_rank"]
    token_trace = token_namespace.traces[token_table_name]
    byte_multiplicity = Counter(bundle_columns["value"])
    for prefix in ("rank_byte", "difference_byte"):
        for byte_index in range(TOKEN_ENCODED_BYTES):
            byte_multiplicity.update(
                token_trace.columns[f"{prefix}_{byte_index}"]
            )
    byte_trace = TraceTable(
        "claim_source_byte_range",
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
        "claim_source_byte_range",
        tuple(byte_trace.columns),
        256,
        (),
        MappingProxyType({"value": tuple(range(256))}),
    )

    doubled_positions = (0, 2, 4, 6, 8)
    normal_positions = (1, 3, 5, 7, 9)
    doubled_multiplicity = Counter(
        frozen_scalar[f"npi_digit_{index}"][row]
        for row in range(scalar_rows)
        if frozen_scalar["npi_present"][row]
        for index in doubled_positions
    )
    normal_multiplicity = Counter(
        frozen_scalar[f"npi_digit_{index}"][row]
        for row in range(scalar_rows)
        if frozen_scalar["npi_present"][row]
        for index in normal_positions
    )
    digit_trace = TraceTable(
        "claim_source_luhn_digit",
        freeze_columns(
            {
                "digit": tuple(range(10)),
                "doubled": tuple(
                    2 * value - (9 if value >= 5 else 0) for value in range(10)
                ),
                "normal": tuple(range(10)),
                "doubled_multiplicity": tuple(
                    doubled_multiplicity[value] for value in range(10)
                ),
                "normal_multiplicity": tuple(
                    normal_multiplicity[value] for value in range(10)
                ),
            }
        ),
    )
    digit_table = AirTable(
        "claim_source_luhn_digit",
        tuple(digit_trace.columns),
        10,
        (),
        MappingProxyType(
            {
                "digit": tuple(range(10)),
                "doubled": tuple(
                    2 * value - (9 if value >= 5 else 0)
                    for value in range(10)
                ),
                "normal": tuple(range(10)),
            }
        ),
    )

    diagnosis_multiplicity = Counter(frozen_scalar["diagnosis_count_byte_0"])
    service_multiplicity = Counter(frozen_scalar["service_count_byte_0"])
    count_trace = TraceTable(
        "claim_source_count_range",
        freeze_columns(
            {
                "value": tuple(range(SERVICE_LINES_PER_CLAIM + 1)),
                "diagnosis_multiplicity": tuple(
                    diagnosis_multiplicity[value]
                    if value <= 16
                    else 0
                    for value in range(SERVICE_LINES_PER_CLAIM + 1)
                ),
                "service_multiplicity": tuple(
                    service_multiplicity[value]
                    for value in range(SERVICE_LINES_PER_CLAIM + 1)
                ),
            }
        ),
    )
    count_table = AirTable(
        "claim_source_count_range",
        tuple(count_trace.columns),
        SERVICE_LINES_PER_CLAIM + 1,
        (),
        MappingProxyType({"value": tuple(range(SERVICE_LINES_PER_CLAIM + 1))}),
    )

    rank_values = tuple(
        cell(f"rank_byte_{index}") for index in range(TOKEN_ENCODED_BYTES)
    )
    token_equality = LookupArgument(
        "claim_source_token_ranks_match_bundle_links",
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
                "claim_source_token_link",
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
    token_required_real = LookupArgument(
        "claim_source_required_tokens_match_real_slots",
        (
            LookupSide(
                "claim_source_token_link",
                cell("requires_real"),
                (cell("slot_index"), cell("required")),
                0,
                link_rows,
            ),
        ),
        (
            LookupSide(
                "claim_source_scalar",
                const(1),
                (cell("slot_index"), cell("real_byte_0")),
                0,
                scalar_rows,
                const(2),
            ),
        ),
    )
    token_bundle_link = LookupArgument(
        "claim_source_token_bytes_match_bundle",
        tuple(
            LookupSide(
                "claim_source_token_link",
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
                "claim_source_bundle_byte",
                cell("is_token_byte"),
                (cell("slot_index"), cell("byte_index"), cell("value")),
                0,
                bundle_rows,
            ),
        ),
    )
    scalar_bundle_link = LookupArgument(
        "claim_source_scalar_bytes_match_bundle",
        tuple(
            LookupSide(
                "claim_source_scalar",
                const(1),
                (
                    cell("slot_index"),
                    const(offset + byte_index),
                    cell(f"{name}_byte_{byte_index}"),
                ),
                0,
                scalar_rows,
            )
            for name, offset, count in _SCALAR_SPECS
            for byte_index in range(count)
        ),
        (
            LookupSide(
                "claim_source_bundle_byte",
                cell("is_scalar_byte"),
                (cell("slot_index"), cell("byte_index"), cell("value")),
                0,
                bundle_rows,
            ),
        ),
    )
    npi_digits = LookupArgument(
        "claim_source_npi_digits_and_luhn_contributions",
        (
            *(
                LookupSide(
                    "claim_source_scalar",
                    cell("npi_present"),
                    (
                        cell(f"npi_digit_{index}"),
                        cell(f"npi_contribution_{index}"),
                    ),
                    0,
                    scalar_rows,
                )
                for index in doubled_positions
            ),
            *(
                LookupSide(
                    "claim_source_scalar",
                    cell("npi_present"),
                    (
                        cell(f"npi_digit_{index}"),
                        cell(f"npi_contribution_{index}"),
                    ),
                    0,
                    scalar_rows,
                )
                for index in normal_positions[:-1]
            ),
            LookupSide(
                "claim_source_scalar",
                cell("npi_present"),
                (cell("npi_digit_9"), cell("npi_digit_9")),
                0,
                scalar_rows,
            ),
        ),
        (
            LookupSide(
                "claim_source_luhn_digit",
                const(1),
                (cell("digit"), cell("doubled")),
                0,
                10,
                cell("doubled_multiplicity"),
            ),
            LookupSide(
                "claim_source_luhn_digit",
                const(1),
                (cell("digit"), cell("normal")),
                0,
                10,
                cell("normal_multiplicity"),
            ),
        ),
    )
    count_bounds = (
        LookupArgument(
            "claim_source_diagnosis_count_bounded",
            (
                LookupSide(
                    "claim_source_scalar",
                    const(1),
                    (cell("diagnosis_count_byte_0"),),
                    0,
                    scalar_rows,
                ),
            ),
            (
                LookupSide(
                    "claim_source_count_range",
                    const(1),
                    (cell("value"),),
                    0,
                    17,
                    cell("diagnosis_multiplicity"),
                ),
            ),
        ),
        LookupArgument(
            "claim_source_service_count_bounded",
            (
                LookupSide(
                    "claim_source_scalar",
                    const(1),
                    (cell("service_count_byte_0"),),
                    0,
                    scalar_rows,
                ),
            ),
            (
                LookupSide(
                    "claim_source_count_range",
                    const(1),
                    (cell("value"),),
                    0,
                    SERVICE_LINES_PER_CLAIM + 1,
                    cell("service_multiplicity"),
                ),
            ),
        ),
    )
    shared_byte_range = LookupArgument(
        "claim_source_values_are_bytes",
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
                "claim_source_bundle_byte",
                const(1),
                (cell("value"),),
                0,
                bundle_rows,
            ),
        ),
        (
            LookupSide(
                "claim_source_byte_range",
                const(1),
                (cell("value"),),
                0,
                256,
                cell("multiplicity"),
            ),
        ),
    )
    traces = {
        token_table_name: token_trace,
        "claim_source_token_link": link_trace,
        "claim_source_scalar": scalar_trace,
        "claim_source_bundle_byte": bundle_trace,
        "claim_source_byte_range": byte_trace,
        "claim_source_luhn_digit": digit_trace,
        "claim_source_count_range": count_trace,
    }
    program = AirProgram(
        PROGRAM_ID,
        (
            next(
                table
                for table in token_namespace.program.tables
                if table.name == token_table_name
            ),
            link_table,
            scalar_table,
            bundle_table,
            byte_table,
            digit_table,
            count_table,
        ),
        (
            token_equality,
            token_required_real,
            token_bundle_link,
            scalar_bundle_link,
            npi_digits,
            *count_bounds,
            shared_byte_range,
        ),
    )
    return ClaimSourceEncodingAirInstance(
        program,
        MappingProxyType(traces),
        bundles,
        commitments,
        token_air,
    )


__all__ = [
    "ClaimSourceEncodingAirInstance",
    "build_claim_source_encoding_executable_air",
]
