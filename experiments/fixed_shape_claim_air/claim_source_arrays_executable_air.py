"""Executable diagnosis and service-array constraints for compact claim source."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Mapping, Sequence

from .claim_source_encoding_executable_air import (
    ClaimSourceEncodingAirInstance,
    build_claim_source_encoding_executable_air,
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
from .profile import DIAGNOSES_PER_CLAIM, SERVICE_LINES_PER_CLAIM, CalibrationProfile
from .semantics import ClaimSlot
from experiments.bl_pq512_crypto_foundation.oracle_bundle_commitment import TOKEN_ENCODED_BYTES


PROGRAM_ID: Final[str] = "BL-WAVE1A-CLAIM-SOURCE-ARRAYS-AIR-v2"
_DIAGNOSIS_BASE: Final[int] = 175
_DIAGNOSIS_BYTES: Final[int] = 17
_LINE_BASE: Final[int] = 448
_LINE_BYTES: Final[int] = 104
_DIAGNOSIS_ALPHABET: Final[tuple[int, ...]] = tuple(
    sorted({ord("."), *range(ord("0"), ord("9") + 1), *range(ord("A"), ord("Z") + 1)})
)
_PROCEDURE_ALPHABET: Final[tuple[int, ...]] = tuple(
    (*range(ord("0"), ord("9") + 1), *range(ord("A"), ord("Z") + 1))
)


@dataclass(frozen=True, slots=True)
class ClaimSourceArraysAirInstance:
    program: AirProgram
    traces: Mapping[str, TraceTable]
    source: ClaimSourceEncodingAirInstance
    diagnosis_canonicality_constrained: bool = True
    service_framing_constrained: bool = True
    original_line_index_uniqueness_constrained: bool = True
    service_sort_order_constrained: bool = True
    line_id_uniqueness_constrained: bool = True
    source_hashes_constrained: bool = False
    source_authority_constrained: bool = False


def _append(columns: dict[str, list[int]], name: str, value: int) -> None:
    columns.setdefault(name, []).append(value)


def _add_chunk_comparator(
    columns: dict[str, list[int]],
    key_byte_names: tuple[str, ...],
    *,
    rows: int,
    label: str,
) -> tuple[list[Identity], int]:
    padded = (*key_byte_names, *(None for _ in range((-len(key_byte_names)) % 3)))
    chunks = tuple(tuple(padded[index : index + 3]) for index in range(0, len(padded), 3))
    for chunk_index, names in enumerate(chunks):
        for row in range(rows):
            value = sum(
                (1 << (8 * (2 - index))) * (columns[name][row] if name else 0)
                for index, name in enumerate(names)
            )
            _append(columns, f"{label}_chunk_{chunk_index}", value)
    for row in range(rows):
        next_row = row + 1 if row + 1 < rows else row
        pair_active = (
            columns["has_next"][row] * columns["live"][next_row]
            if row + 1 < rows
            else 0
        )
        _append(columns, f"{label}_pair_active", pair_active)
        prefix = pair_active
        _append(columns, f"{label}_prefix_0", prefix)
        for chunk_index in range(len(chunks)):
            raw = (
                columns[f"{label}_chunk_{chunk_index}"][next_row]
                - columns[f"{label}_chunk_{chunk_index}"][row]
            )
            borrow = int(raw < 0)
            difference = raw + (1 << 24) * borrow
            difference_bytes = difference.to_bytes(3, "big")
            equal = int(difference == 0)
            first = prefix * (1 - equal)
            for byte_index, value in enumerate(difference_bytes):
                _append(columns, f"{label}_difference_{chunk_index}_{byte_index}", value)
            _append(columns, f"{label}_borrow_{chunk_index}", borrow)
            _append(columns, f"{label}_equal_{chunk_index}", equal)
            _append(
                columns,
                f"{label}_inverse_{chunk_index}",
                pow(difference, M31 - 2, M31) if difference else 0,
            )
            _append(columns, f"{label}_first_{chunk_index}", first)
            prefix *= equal
            _append(columns, f"{label}_prefix_{chunk_index + 1}", prefix)

    identities: list[Identity] = [
        Identity(
            f"{label}_pair_active",
            cell(f"{label}_pair_active") - cell("has_next") * cell("live", 1),
            0,
            rows - 1,
            "transition",
        ),
        Identity(
            f"{label}_prefix_start",
            cell(f"{label}_prefix_0") - cell(f"{label}_pair_active"),
            0,
            rows,
        ),
        Identity(
            f"{label}_strict",
            sum(
                (cell(f"{label}_first_{index}") for index in range(len(chunks))),
                const(0),
            )
            - cell(f"{label}_pair_active"),
            0,
            rows,
        ),
    ]
    for chunk_index, names in enumerate(chunks):
        chunk_expression = sum(
            (
                (1 << (8 * (2 - index))) * (cell(name) if name else const(0))
                for index, name in enumerate(names)
            ),
            const(0),
        )
        difference = sum(
            (
                (1 << (8 * (2 - index)))
                * cell(f"{label}_difference_{chunk_index}_{index}")
                for index in range(3)
            ),
            const(0),
        )
        identities.extend(
            (
                Identity(
                    f"{label}_chunk_{chunk_index}",
                    cell(f"{label}_chunk_{chunk_index}") - chunk_expression,
                    0,
                    rows,
                ),
                Identity(
                    f"{label}_difference_{chunk_index}",
                    cell(f"{label}_chunk_{chunk_index}", 1)
                    - cell(f"{label}_chunk_{chunk_index}")
                    - difference
                    + (1 << 24) * cell(f"{label}_borrow_{chunk_index}"),
                    0,
                    rows - 1,
                    "transition",
                ),
                Identity(
                    f"{label}_borrow_{chunk_index}_boolean",
                    boolean(cell(f"{label}_borrow_{chunk_index}")),
                    0,
                    rows,
                ),
                Identity(
                    f"{label}_equal_{chunk_index}_boolean",
                    boolean(cell(f"{label}_equal_{chunk_index}")),
                    0,
                    rows,
                ),
                Identity(
                    f"{label}_inverse_{chunk_index}",
                    difference * cell(f"{label}_inverse_{chunk_index}")
                    - (1 - cell(f"{label}_equal_{chunk_index}")),
                    0,
                    rows,
                ),
                Identity(
                    f"{label}_equal_zero_{chunk_index}",
                    difference * cell(f"{label}_equal_{chunk_index}"),
                    0,
                    rows,
                ),
                Identity(
                    f"{label}_first_{chunk_index}",
                    cell(f"{label}_first_{chunk_index}")
                    - cell(f"{label}_prefix_{chunk_index}")
                    * (1 - cell(f"{label}_equal_{chunk_index}")),
                    0,
                    rows,
                ),
                Identity(
                    f"{label}_direction_{chunk_index}",
                    cell(f"{label}_first_{chunk_index}")
                    * cell(f"{label}_borrow_{chunk_index}"),
                    0,
                    rows,
                ),
                Identity(
                    f"{label}_prefix_{chunk_index}",
                    cell(f"{label}_prefix_{chunk_index + 1}")
                    - cell(f"{label}_prefix_{chunk_index}")
                    * cell(f"{label}_equal_{chunk_index}"),
                    0,
                    rows,
                ),
            )
        )
        for name, expected in (
            (f"{label}_borrow_{chunk_index}", 0),
            (f"{label}_equal_{chunk_index}", 1),
            (f"{label}_inverse_{chunk_index}", 0),
            (f"{label}_first_{chunk_index}", 0),
            *(
                (f"{label}_difference_{chunk_index}_{byte_index}", 0)
                for byte_index in range(3)
            ),
        ):
            identities.append(
                Identity(
                    f"{label}_terminal_{name}",
                    cell(name) - expected,
                    rows - 1,
                    rows,
                    "boundary",
                )
            )
    return identities, len(chunks)


def build_claim_source_arrays_executable_air(
    profile: CalibrationProfile,
    slots: Sequence[ClaimSlot],
) -> ClaimSourceArraysAirInstance:
    materialized = tuple(slots)
    source = build_claim_source_encoding_executable_air(profile, materialized)
    bundles = source.bundles

    diagnosis: dict[str, list[int]] = {}
    for slot, bundle in zip(materialized, bundles, strict=True):
        running = 0
        for index in range(DIAGNOSES_PER_CLAIM):
            offset = _DIAGNOSIS_BASE + index * _DIAGNOSIS_BYTES
            length = bundle[offset]
            live = int(index < len(slot.diagnoses))
            _append(diagnosis, "slot_index", slot.slot_index)
            _append(diagnosis, "diagnosis_index", index)
            _append(diagnosis, "has_next", int(index + 1 < DIAGNOSES_PER_CLAIM))
            _append(diagnosis, "is_last", int(index + 1 == DIAGNOSES_PER_CLAIM))
            _append(diagnosis, "live", live)
            _append(diagnosis, "length", length)
            _append(diagnosis, "count_before", running)
            running += live
            _append(diagnosis, "count_after", running)
            for char_index in range(16):
                value = bundle[offset + 1 + char_index]
                _append(diagnosis, f"char_{char_index}", value)
                _append(diagnosis, f"active_{char_index}", int(char_index < length))

    diagnosis_rows = profile.claim_slots * DIAGNOSES_PER_CLAIM
    key_names = ("length", *(f"char_{index}" for index in range(16)))
    for row in range(diagnosis_rows):
        next_row = row + 1 if row + 1 < diagnosis_rows else row
        pair_active = (
            diagnosis["has_next"][row] * diagnosis["live"][next_row]
            if row + 1 < diagnosis_rows
            else 0
        )
        _append(diagnosis, "pair_active", pair_active)
        prefix = pair_active
        _append(diagnosis, "compare_prefix_0", prefix)
        for key_index, name in enumerate(key_names):
            left = diagnosis[name][row]
            right = diagnosis[name][next_row]
            raw = right - left
            borrow = int(raw < 0)
            difference = raw + 256 * borrow
            equal = int(difference == 0)
            first = prefix * (1 - equal)
            _append(diagnosis, f"difference_{key_index}", difference)
            _append(diagnosis, f"borrow_{key_index}", borrow)
            _append(diagnosis, f"equal_{key_index}", equal)
            _append(
                diagnosis,
                f"difference_inverse_{key_index}",
                pow(difference, M31 - 2, M31) if difference else 0,
            )
            _append(diagnosis, f"first_difference_{key_index}", first)
            prefix *= equal
            _append(diagnosis, f"compare_prefix_{key_index + 1}", prefix)

    frozen_diagnosis = freeze_columns(
        {name: tuple(values) for name, values in diagnosis.items()}
    )
    diagnosis_identities: list[Identity] = [
        Identity("diagnosis_live_boolean", boolean(cell("live")), 0, diagnosis_rows),
        Identity(
            "diagnosis_live_matches_first_character",
            cell("live") - cell("active_0"),
            0,
            diagnosis_rows,
        ),
        Identity(
            "diagnosis_length",
            cell("length")
            - sum((cell(f"active_{index}") for index in range(16)), const(0)),
            0,
            diagnosis_rows,
        ),
        Identity(
            "diagnosis_count_step",
            cell("count_after") - cell("count_before") - cell("live"),
            0,
            diagnosis_rows,
        ),
        Identity(
            "diagnosis_pair_active",
            cell("pair_active") - cell("has_next") * cell("live", 1),
            0,
            diagnosis_rows - 1,
            "transition",
        ),
        Identity(
            "diagnosis_compare_starts_at_pair",
            cell("compare_prefix_0") - cell("pair_active"),
            0,
            diagnosis_rows,
        ),
        Identity(
            "diagnosis_strict_order",
            sum(
                (cell(f"first_difference_{index}") for index in range(len(key_names))),
                const(0),
            )
            - cell("pair_active"),
            0,
            diagnosis_rows,
        ),
    ]
    for slot_index in range(profile.claim_slots):
        start = slot_index * DIAGNOSES_PER_CLAIM
        diagnosis_identities.extend(
            (
                Identity(
                    f"diagnosis_count_start_{slot_index}",
                    cell("count_before"),
                    start,
                    start + 1,
                ),
                Identity(
                    f"diagnosis_live_prefix_{slot_index}",
                    cell("live", 1) * (1 - cell("live")),
                    start,
                    start + DIAGNOSES_PER_CLAIM - 1,
                    "transition",
                ),
                Identity(
                    f"diagnosis_count_transition_{slot_index}",
                    cell("count_before", 1) - cell("count_after"),
                    start,
                    start + DIAGNOSES_PER_CLAIM - 1,
                    "transition",
                ),
            )
        )
    for char_index in range(16):
        diagnosis_identities.extend(
            (
                Identity(
                    f"diagnosis_active_{char_index}_boolean",
                    boolean(cell(f"active_{char_index}")),
                    0,
                    diagnosis_rows,
                ),
                Identity(
                    f"diagnosis_padding_{char_index}_zero",
                    (1 - cell(f"active_{char_index}")) * cell(f"char_{char_index}"),
                    0,
                    diagnosis_rows,
                ),
            )
        )
        if char_index:
            diagnosis_identities.append(
                Identity(
                    f"diagnosis_active_prefix_{char_index}",
                    cell(f"active_{char_index}")
                    * (1 - cell(f"active_{char_index - 1}")),
                    0,
                    diagnosis_rows,
                )
            )
    for key_index, name in enumerate(key_names):
        stop = diagnosis_rows - 1
        diagnosis_identities.extend(
            (
                Identity(
                    f"diagnosis_difference_{key_index}",
                    cell(name, 1)
                    - cell(name)
                    - cell(f"difference_{key_index}")
                    + 256 * cell(f"borrow_{key_index}"),
                    0,
                    stop,
                    "transition",
                ),
                Identity(
                    f"diagnosis_borrow_{key_index}_boolean",
                    boolean(cell(f"borrow_{key_index}")),
                    0,
                    diagnosis_rows,
                ),
                Identity(
                    f"diagnosis_equal_{key_index}_boolean",
                    boolean(cell(f"equal_{key_index}")),
                    0,
                    diagnosis_rows,
                ),
                Identity(
                    f"diagnosis_difference_inverse_{key_index}",
                    cell(f"difference_{key_index}")
                    * cell(f"difference_inverse_{key_index}")
                    - (1 - cell(f"equal_{key_index}")),
                    0,
                    diagnosis_rows,
                ),
                Identity(
                    f"diagnosis_equal_zero_{key_index}",
                    cell(f"difference_{key_index}") * cell(f"equal_{key_index}"),
                    0,
                    diagnosis_rows,
                ),
                Identity(
                    f"diagnosis_first_difference_{key_index}",
                    cell(f"first_difference_{key_index}")
                    - cell(f"compare_prefix_{key_index}")
                    * (1 - cell(f"equal_{key_index}")),
                    0,
                    diagnosis_rows,
                ),
                Identity(
                    f"diagnosis_order_direction_{key_index}",
                    cell(f"first_difference_{key_index}")
                    * cell(f"borrow_{key_index}"),
                    0,
                    diagnosis_rows,
                ),
                Identity(
                    f"diagnosis_compare_prefix_{key_index}",
                    cell(f"compare_prefix_{key_index + 1}")
                    - cell(f"compare_prefix_{key_index}")
                    * cell(f"equal_{key_index}"),
                    0,
                    diagnosis_rows,
                ),
                Identity(
                    f"diagnosis_terminal_difference_{key_index}",
                    cell(f"difference_{key_index}"),
                    diagnosis_rows - 1,
                    diagnosis_rows,
                    "boundary",
                ),
                Identity(
                    f"diagnosis_terminal_borrow_{key_index}",
                    cell(f"borrow_{key_index}"),
                    diagnosis_rows - 1,
                    diagnosis_rows,
                    "boundary",
                ),
                Identity(
                    f"diagnosis_terminal_equal_{key_index}",
                    cell(f"equal_{key_index}") - 1,
                    diagnosis_rows - 1,
                    diagnosis_rows,
                    "boundary",
                ),
                Identity(
                    f"diagnosis_terminal_inverse_{key_index}",
                    cell(f"difference_inverse_{key_index}"),
                    diagnosis_rows - 1,
                    diagnosis_rows,
                    "boundary",
                ),
                Identity(
                    f"diagnosis_terminal_first_difference_{key_index}",
                    cell(f"first_difference_{key_index}"),
                    diagnosis_rows - 1,
                    diagnosis_rows,
                    "boundary",
                ),
            )
        )
    diagnosis_table = AirTable(
        "claim_source_diagnosis",
        tuple(frozen_diagnosis),
        diagnosis_rows,
        tuple(diagnosis_identities),
        MappingProxyType(
            {
                name: frozen_diagnosis[name]
                for name in ("slot_index", "diagnosis_index", "has_next", "is_last")
            }
        ),
    )
    diagnosis_trace = TraceTable("claim_source_diagnosis", frozen_diagnosis)

    service: dict[str, list[int]] = {}
    for slot, bundle in zip(materialized, bundles, strict=True):
        running = 0
        running_charge = 0
        for index in range(SERVICE_LINES_PER_CLAIM):
            offset = _LINE_BASE + index * _LINE_BYTES
            live = int(index < len(slot.service_lines))
            _append(service, "slot_index", slot.slot_index)
            _append(service, "line_index", index)
            _append(service, "is_last", int(index + 1 == SERVICE_LINES_PER_CLAIM))
            _append(service, "has_next", int(index + 1 < SERVICE_LINES_PER_CLAIM))
            _append(service, "live", live)
            _append(service, "count_before", running)
            running += live
            _append(service, "count_after", running)
            _append(service, "original_line_index", bundle[offset])
            _append(service, "procedure_length", bundle[offset + 43])
            for char_index in range(10):
                value = bundle[offset + 44 + char_index]
                _append(service, f"procedure_char_{char_index}", value)
                _append(
                    service,
                    f"procedure_active_{char_index}",
                    int(char_index < bundle[offset + 43]),
                )
            for prefix, base in (("charge", 54), ("units", 58)):
                for byte_index in range(4):
                    _append(service, f"{prefix}_byte_{byte_index}", bundle[offset + base + byte_index])
            charge = int.from_bytes(bundle[offset + 54 : offset + 58], "big")
            next_charge = running_charge + charge
            before_bytes = running_charge.to_bytes(4, "big")
            after_bytes = next_charge.to_bytes(4, "big")
            carries = [0] * 5
            carry = 0
            for byte_index in range(3, -1, -1):
                total = before_bytes[byte_index] + bundle[offset + 54 + byte_index] + carry
                carry = total >> 8
                carries[byte_index] = carry
            carries[4] = 0
            for byte_index in range(4):
                _append(service, f"charge_sum_before_{byte_index}", before_bytes[byte_index])
                _append(service, f"charge_sum_after_{byte_index}", after_bytes[byte_index])
            for carry_index, value in enumerate(carries):
                _append(service, f"charge_sum_carry_{carry_index}", value)
            running_charge = next_charge
            for prefix, base in (("line_id_rank", 1), ("authorization_rank", 62)):
                for byte_index in range(TOKEN_ENCODED_BYTES):
                    _append(service, f"{prefix}_{byte_index}", bundle[offset + base + byte_index])

    service_rows = profile.claim_slots * SERVICE_LINES_PER_CLAIM
    service_key_names = (
        "procedure_length",
        *(f"procedure_char_{index}" for index in range(10)),
        *(f"charge_byte_{index}" for index in range(4)),
        *(f"units_byte_{index}" for index in range(4)),
        *(f"authorization_rank_{index}" for index in range(TOKEN_ENCODED_BYTES)),
        *(f"line_id_rank_{index}" for index in range(TOKEN_ENCODED_BYTES)),
    )
    service_order_identities, service_order_chunks = _add_chunk_comparator(
        service,
        service_key_names,
        rows=service_rows,
        label="service_order",
    )
    frozen_service = freeze_columns({name: tuple(values) for name, values in service.items()})
    service_identities: list[Identity] = [
        Identity("service_live_boolean", boolean(cell("live")), 0, service_rows),
        Identity(
            "service_count_step",
            cell("count_after") - cell("count_before") - cell("live"),
            0,
            service_rows,
        ),
        Identity(
            "procedure_length",
            cell("procedure_length")
            - sum(
                (cell(f"procedure_active_{index}") for index in range(10)),
                const(0),
            ),
            0,
            service_rows,
        ),
        Identity(
            "live_procedure_first_character",
            cell("procedure_active_0") - cell("live"),
            0,
            service_rows,
        ),
        Identity(
            "live_procedure_second_character",
            cell("procedure_active_1") - cell("live"),
            0,
            service_rows,
        ),
        Identity(
            "charge_sum_input_carry_zero",
            cell("charge_sum_carry_4"),
            0,
            service_rows,
        ),
        Identity(
            "charge_sum_overflow_zero",
            cell("charge_sum_carry_0"),
            0,
            service_rows,
        ),
    ]
    for byte_index in range(4):
        service_identities.extend(
            (
                Identity(
                    f"charge_sum_byte_{byte_index}",
                    cell(f"charge_sum_before_{byte_index}")
                    + cell(f"charge_byte_{byte_index}")
                    + cell(f"charge_sum_carry_{byte_index + 1}")
                    - cell(f"charge_sum_after_{byte_index}")
                    - 256 * cell(f"charge_sum_carry_{byte_index}"),
                    0,
                    service_rows,
                ),
                Identity(
                    f"charge_sum_carry_{byte_index}_boolean",
                    boolean(cell(f"charge_sum_carry_{byte_index}")),
                    0,
                    service_rows,
                ),
            )
        )
    for slot_index in range(profile.claim_slots):
        start = slot_index * SERVICE_LINES_PER_CLAIM
        service_identities.extend(
            (
                Identity(
                    f"service_count_start_{slot_index}",
                    cell("count_before"),
                    start,
                    start + 1,
                ),
                *(
                    Identity(
                        f"service_charge_start_{slot_index}_{byte_index}",
                        cell(f"charge_sum_before_{byte_index}"),
                        start,
                        start + 1,
                    )
                    for byte_index in range(4)
                ),
                Identity(
                    f"service_live_prefix_{slot_index}",
                    cell("live", 1) * (1 - cell("live")),
                    start,
                    start + SERVICE_LINES_PER_CLAIM - 1,
                    "transition",
                ),
                Identity(
                    f"service_count_transition_{slot_index}",
                    cell("count_before", 1) - cell("count_after"),
                    start,
                    start + SERVICE_LINES_PER_CLAIM - 1,
                    "transition",
                ),
                *(
                    Identity(
                        f"service_charge_transition_{slot_index}_{byte_index}",
                        cell(f"charge_sum_before_{byte_index}", 1)
                        - cell(f"charge_sum_after_{byte_index}"),
                        start,
                        start + SERVICE_LINES_PER_CLAIM - 1,
                        "transition",
                    )
                    for byte_index in range(4)
                ),
            )
        )
    for name in (
        "original_line_index",
        *(f"procedure_char_{index}" for index in range(10)),
        *(f"charge_byte_{index}" for index in range(4)),
        *(f"units_byte_{index}" for index in range(4)),
    ):
        service_identities.append(
            Identity(
                f"disabled_{name}_zero",
                (1 - cell("live")) * cell(name),
                0,
                service_rows,
            )
        )
    for char_index in range(10):
        service_identities.extend(
            (
                Identity(
                    f"procedure_active_{char_index}_boolean",
                    boolean(cell(f"procedure_active_{char_index}")),
                    0,
                    service_rows,
                ),
                Identity(
                    f"procedure_padding_{char_index}_zero",
                    (1 - cell(f"procedure_active_{char_index}"))
                    * cell(f"procedure_char_{char_index}"),
                    0,
                    service_rows,
                ),
            )
        )
        if char_index:
            service_identities.append(
                Identity(
                    f"procedure_active_prefix_{char_index}",
                    cell(f"procedure_active_{char_index}")
                    * (1 - cell(f"procedure_active_{char_index - 1}")),
                    0,
                    service_rows,
                )
            )
    service_identities.extend(service_order_identities)
    service_table = AirTable(
        "claim_source_service",
        tuple(frozen_service),
        service_rows,
        tuple(service_identities),
        MappingProxyType(
            {
                name: frozen_service[name]
                for name in ("slot_index", "line_index", "is_last", "has_next")
            }
        ),
    )
    service_trace = TraceTable("claim_source_service", frozen_service)

    used_values = [
        int(candidate in {line.original_line_index for line in slot.service_lines})
        for slot in materialized
        for candidate in range(SERVICE_LINES_PER_CLAIM)
    ]
    original_trace = TraceTable(
        "claim_source_original_line_index",
        freeze_columns(
            {
                "slot_index": tuple(
                    slot.slot_index
                    for slot in materialized
                    for _ in range(SERVICE_LINES_PER_CLAIM)
                ),
                "candidate": tuple(
                    candidate
                    for _ in materialized
                    for candidate in range(SERVICE_LINES_PER_CLAIM)
                ),
                "used": tuple(used_values),
            }
        ),
    )
    original_table = AirTable(
        "claim_source_original_line_index",
        tuple(original_trace.columns),
        service_rows,
        (Identity("original_index_used_boolean", boolean(cell("used")), 0, service_rows),),
        MappingProxyType(
            {
                "slot_index": original_trace.columns["slot_index"],
                "candidate": original_trace.columns["candidate"],
            }
        ),
    )

    sorted_line_id: dict[str, list[int]] = {}
    for slot_index in range(profile.claim_slots):
        start = slot_index * SERVICE_LINES_PER_CLAIM
        ranks = sorted(
            bytes(
                frozen_service[f"line_id_rank_{byte_index}"][row]
                for byte_index in range(TOKEN_ENCODED_BYTES)
            )
            for row in range(start, start + SERVICE_LINES_PER_CLAIM)
            if frozen_service["live"][row]
        )
        for index in range(SERVICE_LINES_PER_CLAIM):
            live = int(index < len(ranks))
            rank = ranks[index] if live else bytes(TOKEN_ENCODED_BYTES)
            _append(sorted_line_id, "slot_index", slot_index)
            _append(sorted_line_id, "line_index", index)
            _append(sorted_line_id, "has_next", int(index + 1 < SERVICE_LINES_PER_CLAIM))
            _append(sorted_line_id, "live", live)
            for byte_index, value in enumerate(rank):
                _append(sorted_line_id, f"rank_byte_{byte_index}", value)
    line_id_order_identities, line_id_order_chunks = _add_chunk_comparator(
        sorted_line_id,
        tuple(f"rank_byte_{index}" for index in range(TOKEN_ENCODED_BYTES)),
        rows=service_rows,
        label="line_id_order",
    )
    frozen_sorted_line_id = freeze_columns(
        {name: tuple(values) for name, values in sorted_line_id.items()}
    )
    sorted_line_id_identities: list[Identity] = [
        Identity("sorted_line_id_live_boolean", boolean(cell("live")), 0, service_rows)
    ]
    for slot_index in range(profile.claim_slots):
        start = slot_index * SERVICE_LINES_PER_CLAIM
        sorted_line_id_identities.append(
            Identity(
                f"sorted_line_id_live_prefix_{slot_index}",
                cell("live", 1) * (1 - cell("live")),
                start,
                start + SERVICE_LINES_PER_CLAIM - 1,
                "transition",
            )
        )
    for byte_index in range(TOKEN_ENCODED_BYTES):
        sorted_line_id_identities.append(
            Identity(
                f"sorted_line_id_padding_{byte_index}_zero",
                (1 - cell("live")) * cell(f"rank_byte_{byte_index}"),
                0,
                service_rows,
            )
        )
    sorted_line_id_identities.extend(line_id_order_identities)
    sorted_line_id_trace = TraceTable("claim_source_sorted_line_id", frozen_sorted_line_id)
    sorted_line_id_table = AirTable(
        "claim_source_sorted_line_id",
        tuple(frozen_sorted_line_id),
        service_rows,
        tuple(sorted_line_id_identities),
        MappingProxyType(
            {
                name: frozen_sorted_line_id[name]
                for name in ("slot_index", "line_index", "has_next")
            }
        ),
    )

    diagnosis_character_counts = Counter(
        frozen_diagnosis[f"char_{index}"][row]
        for row in range(diagnosis_rows)
        for index in range(16)
        if frozen_diagnosis[f"active_{index}"][row]
    )
    procedure_character_counts = Counter(
        frozen_service[f"procedure_char_{index}"][row]
        for row in range(service_rows)
        for index in range(10)
        if frozen_service[f"procedure_active_{index}"][row]
    )
    grammar_values = tuple(sorted(set(_DIAGNOSIS_ALPHABET) | set(_PROCEDURE_ALPHABET)))
    grammar_trace = TraceTable(
        "claim_source_array_character",
        freeze_columns(
            {
                "value": grammar_values,
                "diagnosis_multiplicity": tuple(
                    diagnosis_character_counts[value] for value in grammar_values
                ),
                "procedure_multiplicity": tuple(
                    procedure_character_counts[value] for value in grammar_values
                ),
                "diagnosis_allowed": tuple(int(value in _DIAGNOSIS_ALPHABET) for value in grammar_values),
                "procedure_allowed": tuple(int(value in _PROCEDURE_ALPHABET) for value in grammar_values),
            }
        ),
    )
    grammar_table = AirTable(
        "claim_source_array_character",
        tuple(grammar_trace.columns),
        len(grammar_values),
        (),
        MappingProxyType(
            {
                "value": grammar_values,
                "diagnosis_allowed": grammar_trace.columns["diagnosis_allowed"],
                "procedure_allowed": grammar_trace.columns["procedure_allowed"],
            }
        ),
    )

    difference_counts = Counter(
        frozen_diagnosis[f"difference_{index}"][row]
        for row in range(diagnosis_rows - 1)
        for index in range(len(key_names))
    )
    difference_counts.update(
        frozen_service[f"service_order_difference_{chunk_index}_{byte_index}"][row]
        for row in range(service_rows - 1)
        for chunk_index in range(service_order_chunks)
        for byte_index in range(3)
    )
    difference_counts.update(
        frozen_sorted_line_id[f"line_id_order_difference_{chunk_index}_{byte_index}"][row]
        for row in range(service_rows - 1)
        for chunk_index in range(line_id_order_chunks)
        for byte_index in range(3)
    )
    difference_counts.update(
        frozen_service[f"charge_sum_{phase}_{byte_index}"][row]
        for row in range(service_rows)
        for phase in ("before", "after")
        for byte_index in range(4)
    )
    difference_trace = TraceTable(
        "claim_source_array_byte_range",
        freeze_columns(
            {
                "value": tuple(range(256)),
                "multiplicity": tuple(difference_counts[value] for value in range(256)),
            }
        ),
    )
    difference_table = AirTable(
        "claim_source_array_byte_range",
        tuple(difference_trace.columns),
        256,
        (),
        MappingProxyType({"value": tuple(range(256))}),
    )

    diagnosis_grammar = LookupArgument(
        "claim_source_diagnosis_character_grammar",
        tuple(
            LookupSide(
                "claim_source_diagnosis",
                cell(f"active_{index}"),
                (cell(f"char_{index}"),),
                0,
                diagnosis_rows,
            )
            for index in range(16)
        ),
        (
            LookupSide(
                "claim_source_array_character",
                cell("diagnosis_allowed"),
                (cell("value"),),
                0,
                len(grammar_values),
                cell("diagnosis_multiplicity"),
            ),
        ),
    )
    procedure_grammar = LookupArgument(
        "claim_source_procedure_character_grammar",
        tuple(
            LookupSide(
                "claim_source_service",
                cell(f"procedure_active_{index}"),
                (cell(f"procedure_char_{index}"),),
                0,
                service_rows,
            )
            for index in range(10)
        ),
        (
            LookupSide(
                "claim_source_array_character",
                cell("procedure_allowed"),
                (cell("value"),),
                0,
                len(grammar_values),
                cell("procedure_multiplicity"),
            ),
        ),
    )
    difference_range = LookupArgument(
        "claim_source_diagnosis_differences_are_bytes",
        (
            *(
            LookupSide(
                "claim_source_diagnosis",
                const(1),
                (cell(f"difference_{index}"),),
                0,
                diagnosis_rows - 1,
            )
            for index in range(len(key_names))
            ),
            *(
                LookupSide(
                    "claim_source_service",
                    const(1),
                    (cell(f"service_order_difference_{chunk_index}_{byte_index}"),),
                    0,
                    service_rows - 1,
                )
                for chunk_index in range(service_order_chunks)
                for byte_index in range(3)
            ),
            *(
                LookupSide(
                    "claim_source_service",
                    const(1),
                    (cell(f"charge_sum_{phase}_{byte_index}"),),
                    0,
                    service_rows,
                )
                for phase in ("before", "after")
                for byte_index in range(4)
            ),
            *(
                LookupSide(
                    "claim_source_sorted_line_id",
                    const(1),
                    (cell(f"line_id_order_difference_{chunk_index}_{byte_index}"),),
                    0,
                    service_rows - 1,
                )
                for chunk_index in range(line_id_order_chunks)
                for byte_index in range(3)
            ),
        ),
        (
            LookupSide(
                "claim_source_array_byte_range",
                const(1),
                (cell("value"),),
                0,
                256,
                cell("multiplicity"),
            ),
        ),
    )
    diagnosis_bundle = LookupArgument(
        "claim_source_diagnosis_bytes_match_bundle",
        tuple(
            LookupSide(
                "claim_source_diagnosis",
                const(1),
                (
                    cell("slot_index"),
                    _DIAGNOSIS_BASE + _DIAGNOSIS_BYTES * cell("diagnosis_index") + relative,
                    cell("length") if relative == 0 else cell(f"char_{relative - 1}"),
                ),
                0,
                diagnosis_rows,
            )
            for relative in range(_DIAGNOSIS_BYTES)
        ),
        (
            LookupSide(
                "claim_source_bundle_byte",
                cell("is_diagnosis_byte"),
                (cell("slot_index"), cell("byte_index"), cell("value")),
                0,
                profile.claim_slots * 5_648,
            ),
        ),
    )
    service_sources = (
        (0, cell("original_line_index")),
        (43, cell("procedure_length")),
        *((44 + index, cell(f"procedure_char_{index}")) for index in range(10)),
        *((54 + index, cell(f"charge_byte_{index}")) for index in range(4)),
        *((58 + index, cell(f"units_byte_{index}")) for index in range(4)),
    )
    service_bundle = LookupArgument(
        "claim_source_service_bytes_match_bundle",
        tuple(
            LookupSide(
                "claim_source_service",
                const(1),
                (
                    cell("slot_index"),
                    _LINE_BASE + _LINE_BYTES * cell("line_index") + relative,
                    value,
                ),
                0,
                service_rows,
            )
            for relative, value in service_sources
        ),
        (
            LookupSide(
                "claim_source_bundle_byte",
                cell("is_service_non_token_byte"),
                (cell("slot_index"), cell("byte_index"), cell("value")),
                0,
                profile.claim_slots * 5_648,
            ),
        ),
    )
    count_links = (
        LookupArgument(
            "claim_source_diagnosis_count_matches_scalar",
            (
                LookupSide(
                    "claim_source_diagnosis",
                    cell("is_last"),
                    (cell("slot_index"), cell("count_after")),
                    0,
                    diagnosis_rows,
                ),
            ),
            (
                LookupSide(
                    "claim_source_scalar",
                    const(1),
                    (cell("slot_index"), cell("diagnosis_count_byte_0")),
                    0,
                    profile.claim_slots,
                ),
            ),
        ),
        LookupArgument(
            "claim_source_service_count_matches_scalar",
            (
                LookupSide(
                    "claim_source_service",
                    cell("is_last"),
                    (cell("slot_index"), cell("count_after")),
                    0,
                    service_rows,
                ),
            ),
            (
                LookupSide(
                    "claim_source_scalar",
                    const(1),
                    (cell("slot_index"), cell("service_count_byte_0")),
                    0,
                    profile.claim_slots,
                ),
            ),
        ),
        LookupArgument(
            "claim_source_service_charge_sum_matches_scalar",
            (
                LookupSide(
                    "claim_source_service",
                    cell("is_last"),
                    (
                        cell("slot_index"),
                        *(cell(f"charge_sum_after_{index}") for index in range(4)),
                    ),
                    0,
                    service_rows,
                ),
            ),
            (
                LookupSide(
                    "claim_source_scalar",
                    const(1),
                    (
                        cell("slot_index"),
                        *(cell(f"total_charge_byte_{index}") for index in range(4)),
                    ),
                    0,
                    profile.claim_slots,
                ),
            ),
        ),
    )
    original_uniqueness = LookupArgument(
        "claim_source_original_line_indices_unique",
        (
            LookupSide(
                "claim_source_service",
                cell("live"),
                (cell("slot_index"), cell("original_line_index")),
                0,
                service_rows,
            ),
        ),
        (
            LookupSide(
                "claim_source_original_line_index",
                cell("used"),
                (cell("slot_index"), cell("candidate")),
                0,
                service_rows,
            ),
        ),
    )
    line_token_live = LookupArgument(
        "claim_source_line_identifier_presence_matches_live_rows",
        (
            LookupSide(
                "claim_source_service",
                const(1),
                (
                    cell("slot_index"),
                    3 + 2 * cell("line_index"),
                    cell("live"),
                ),
                0,
                service_rows,
            ),
        ),
        (
            LookupSide(
                "claim_source_token_link",
                cell("requires_nonzero"),
                (cell("slot_index"), cell("token_index"), cell("required")),
                0,
                profile.claim_slots * 103,
            ),
        ),
    )
    service_token_ranks = LookupArgument(
        "claim_source_service_token_ranks_match_shared_tokens",
        (
            LookupSide(
                "claim_source_service",
                const(1),
                (
                    cell("slot_index"),
                    3 + 2 * cell("line_index"),
                    *(cell(f"line_id_rank_{index}") for index in range(TOKEN_ENCODED_BYTES)),
                ),
                0,
                service_rows,
            ),
            LookupSide(
                "claim_source_service",
                const(1),
                (
                    cell("slot_index"),
                    4 + 2 * cell("line_index"),
                    *(cell(f"authorization_rank_{index}") for index in range(TOKEN_ENCODED_BYTES)),
                ),
                0,
                service_rows,
            ),
        ),
        (
            LookupSide(
                "claim_source_token_link",
                cell("is_service_token"),
                (
                    cell("slot_index"),
                    cell("token_index"),
                    *(cell(f"rank_byte_{index}") for index in range(TOKEN_ENCODED_BYTES)),
                ),
                0,
                profile.claim_slots * 103,
            ),
        ),
    )
    line_id_permutation = LookupArgument(
        "claim_source_line_identifiers_unique_sorted_permutation",
        (
            LookupSide(
                "claim_source_service",
                cell("live"),
                (
                    cell("slot_index"),
                    *(cell(f"line_id_rank_{index}") for index in range(TOKEN_ENCODED_BYTES)),
                ),
                0,
                service_rows,
            ),
        ),
        (
            LookupSide(
                "claim_source_sorted_line_id",
                cell("live"),
                (
                    cell("slot_index"),
                    *(cell(f"rank_byte_{index}") for index in range(TOKEN_ENCODED_BYTES)),
                ),
                0,
                service_rows,
            ),
        ),
    )

    traces = MappingProxyType(
        {
            **dict(source.traces),
            "claim_source_diagnosis": diagnosis_trace,
            "claim_source_service": service_trace,
            "claim_source_original_line_index": original_trace,
            "claim_source_sorted_line_id": sorted_line_id_trace,
            "claim_source_array_character": grammar_trace,
            "claim_source_array_byte_range": difference_trace,
        }
    )
    program = AirProgram(
        PROGRAM_ID,
        (
            *source.program.tables,
            diagnosis_table,
            service_table,
            original_table,
            sorted_line_id_table,
            grammar_table,
            difference_table,
        ),
        (
            *source.program.lookups,
            diagnosis_grammar,
            procedure_grammar,
            difference_range,
            diagnosis_bundle,
            service_bundle,
            *count_links,
            original_uniqueness,
            line_token_live,
            service_token_ranks,
            line_id_permutation,
        ),
    )
    return ClaimSourceArraysAirInstance(program, traces, source)


__all__ = [
    "ClaimSourceArraysAirInstance",
    "build_claim_source_arrays_executable_air",
]
