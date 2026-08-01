"""Executable derivation of all 13 claim gates from bounded slot/service inputs."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Mapping, Sequence

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
)
from .profile import SERVICE_LINES_PER_CLAIM
from .semantics import ClaimSlot, SlotKind, StructuralError, evaluate_slot


PROGRAM_ID: Final[str] = "BL-WAVE1A-CLAIM-GATE-AIR-v1"


@dataclass(frozen=True, slots=True)
class ClaimGateAirInstance:
    program: AirProgram
    traces: Mapping[str, TraceTable]


def _append(columns: dict[str, list[int]], name: str, value: int) -> None:
    columns.setdefault(name, []).append(value)


def _bytes4(value: int) -> tuple[int, int, int, int]:
    return tuple(value.to_bytes(4, "little"))  # type: ignore[return-value]


def build_claim_gate_executable_air(slots: Sequence[ClaimSlot]) -> ClaimGateAirInstance:
    materialized = tuple(slots)
    if not materialized or tuple(value.slot_index for value in materialized) != tuple(range(len(materialized))):
        raise StructuralError("claim_gate_air_slot_order_invalid")
    results = tuple(evaluate_slot(slot) for slot in materialized)

    service: dict[str, list[int]] = {}
    service_fixed: dict[str, list[int]] = {
        name: [] for name in ("slot_index", "line_index", "is_first", "is_last", "has_next")
    }
    byte_property_counts: Counter[tuple[int, int]] = Counter()
    final_aggregates: list[tuple[int, int, int]] = []

    for slot in materialized:
        auth_prefix = valid_prefix = policy_prefix = 1
        authorization_count = 0
        for line_index in range(SERVICE_LINES_PER_CLAIM):
            live = int(line_index < len(slot.service_lines))
            if live:
                line = slot.service_lines[line_index]
                requires = int(line.requires_prior_authorization)
                authorization = int(line.authorization_present)
                policy = int(line.policy_present)
                charge_bytes = _bytes4(line.charge_cents)
                units_bytes = _bytes4(line.units_cents)
            else:
                requires = authorization = policy = 0
                charge_bytes = units_bytes = (0, 0, 0, 0)
            charge_nz = tuple(int(value != 0) for value in charge_bytes)
            units_nz = tuple(int(value != 0) for value in units_bytes)
            charge_zero = [1]
            units_zero = [1]
            for value in charge_nz:
                charge_zero.append(charge_zero[-1] * (1 - value))
            for value in units_nz:
                units_zero.append(units_zero[-1] * (1 - value))
            charge_positive = 1 - charge_zero[-1]
            units_positive = 1 - units_zero[-1]
            auth_factor = 1 - requires * (1 - authorization)
            valid_factor = (1 - live) + charge_positive * units_positive
            policy_factor = (1 - live) + policy
            authorization_use = requires * authorization
            auth_after = auth_prefix * auth_factor
            valid_after = valid_prefix * valid_factor
            policy_after = policy_prefix * policy_factor

            fixed_values = {
                "slot_index": slot.slot_index,
                "line_index": line_index,
                "is_first": int(line_index == 0),
                "is_last": int(line_index == SERVICE_LINES_PER_CLAIM - 1),
                "has_next": int(line_index != SERVICE_LINES_PER_CLAIM - 1),
                "live": live,
            }
            for name, value in fixed_values.items():
                _append(service, name, value)
                if name in service_fixed:
                    service_fixed[name].append(value)
            for name, value in (
                ("requires_authorization", requires),
                ("authorization_present", authorization),
                ("authorization_use", authorization_use),
                ("authorization_count_before", authorization_count),
                ("authorization_count_after", authorization_count + authorization_use),
                ("policy_present", policy),
                ("charge_positive", charge_positive),
                ("units_positive", units_positive),
                ("auth_factor", auth_factor),
                ("valid_factor", valid_factor),
                ("policy_factor", policy_factor),
                ("auth_prefix", auth_prefix),
                ("valid_prefix", valid_prefix),
                ("policy_prefix", policy_prefix),
                ("auth_after", auth_after),
                ("valid_after", valid_after),
                ("policy_after", policy_after),
            ):
                _append(service, name, value)
            for byte_index in range(4):
                for prefix, values, nonzero in (
                    ("charge", charge_bytes, charge_nz),
                    ("units", units_bytes, units_nz),
                ):
                    _append(service, f"{prefix}_byte_{byte_index}", values[byte_index])
                    _append(service, f"{prefix}_nonzero_{byte_index}", nonzero[byte_index])
                    byte_property_counts[(values[byte_index], nonzero[byte_index])] += 1
                _append(service, f"charge_zero_prefix_{byte_index}", charge_zero[byte_index])
                _append(service, f"units_zero_prefix_{byte_index}", units_zero[byte_index])
            _append(service, "charge_zero_prefix_4", charge_zero[4])
            _append(service, "units_zero_prefix_4", units_zero[4])
            authorization_count += authorization_use
            auth_prefix, valid_prefix, policy_prefix = auth_after, valid_after, policy_after
        final_aggregates.append((auth_prefix, valid_prefix, policy_prefix))

    service_rows = len(materialized) * SERVICE_LINES_PER_CLAIM
    service_identities: list[Identity] = []
    boolean_columns = (
        "live",
        "requires_authorization",
        "authorization_present",
        "authorization_use",
        "policy_present",
        "charge_positive",
        "units_positive",
        "auth_factor",
        "valid_factor",
        "policy_factor",
        "auth_prefix",
        "valid_prefix",
        "policy_prefix",
        "auth_after",
        "valid_after",
        "policy_after",
        *(f"charge_nonzero_{i}" for i in range(4)),
        *(f"units_nonzero_{i}" for i in range(4)),
        *(f"charge_zero_prefix_{i}" for i in range(5)),
        *(f"units_zero_prefix_{i}" for i in range(5)),
    )
    for name in boolean_columns:
        service_identities.append(Identity(f"{name}_boolean", boolean(cell(name)), 0, service_rows))
    for slot_index in range(len(materialized)):
        start = slot_index * SERVICE_LINES_PER_CLAIM
        service_identities.append(
            Identity(
                f"live_prefix_{slot_index}",
                cell("live", 1) * (1 - cell("live")),
                start,
                start + SERVICE_LINES_PER_CLAIM - 1,
                "transition",
            )
        )
    for name in ("requires_authorization", "authorization_present", "policy_present"):
        service_identities.append(
            Identity(f"disabled_{name}", (1 - cell("live")) * cell(name), 0, service_rows)
        )
    for prefix in ("charge", "units"):
        for index in range(4):
            service_identities.extend(
                (
                    Identity(
                        f"disabled_{prefix}_{index}",
                        (1 - cell("live")) * cell(f"{prefix}_byte_{index}"),
                        0,
                        service_rows,
                    ),
                    Identity(
                        f"{prefix}_zero_step_{index}",
                        cell(f"{prefix}_zero_prefix_{index + 1}")
                        - cell(f"{prefix}_zero_prefix_{index}")
                        * (1 - cell(f"{prefix}_nonzero_{index}")),
                        0,
                        service_rows,
                    ),
                )
            )
        service_identities.extend(
            (
                Identity(f"{prefix}_zero_initial", cell(f"{prefix}_zero_prefix_0") - 1, 0, service_rows),
                Identity(
                    f"{prefix}_positive",
                    cell(f"{prefix}_positive") - (1 - cell(f"{prefix}_zero_prefix_4")),
                    0,
                    service_rows,
                ),
            )
        )
    service_identities.extend(
        (
            Identity(
                "authorization_use",
                cell("authorization_use")
                - cell("requires_authorization") * cell("authorization_present"),
                0,
                service_rows,
            ),
            Identity(
                "authorization_count_initial",
                cell("is_first") * cell("authorization_count_before"),
                0,
                service_rows,
            ),
            Identity(
                "authorization_count_step",
                cell("authorization_count_after")
                - cell("authorization_count_before")
                - cell("authorization_use"),
                0,
                service_rows,
            ),
            Identity(
                "authorization_count_transition",
                cell("has_next")
                * (
                    cell("authorization_count_after")
                    - cell("authorization_count_before", 1)
                ),
                0,
                service_rows - 1,
                "transition",
            ),
            Identity(
                "auth_factor",
                cell("auth_factor")
                - (1 - cell("requires_authorization") * (1 - cell("authorization_present"))),
                0,
                service_rows,
            ),
            Identity(
                "valid_factor",
                cell("valid_factor")
                - ((1 - cell("live")) + cell("charge_positive") * cell("units_positive")),
                0,
                service_rows,
            ),
            Identity(
                "policy_factor",
                cell("policy_factor") - ((1 - cell("live")) + cell("policy_present")),
                0,
                service_rows,
            ),
        )
    )
    for prefix in ("auth", "valid", "policy"):
        service_identities.extend(
            (
                Identity(
                    f"{prefix}_initial",
                    cell("is_first") * (cell(f"{prefix}_prefix") - 1),
                    0,
                    service_rows,
                ),
                Identity(
                    f"{prefix}_after",
                    cell(f"{prefix}_after") - cell(f"{prefix}_prefix") * cell(f"{prefix}_factor"),
                    0,
                    service_rows,
                ),
                Identity(
                    f"{prefix}_transition",
                    cell("has_next")
                    * (cell(f"{prefix}_after") - cell(f"{prefix}_prefix", 1)),
                    0,
                    service_rows - 1,
                    "transition",
                ),
            )
        )

    slot: dict[str, list[int]] = {}
    slot_fixed: dict[str, list[int]] = {"slot_index": []}
    length_counts: Counter[tuple[int, int]] = Counter()
    for claim, result, aggregates in zip(materialized, results, final_aggregates, strict=True):
        raw = tuple(int(value) for value in result.raw_gate_predicates)
        lengths = (
            ("member", len(claim.member_id), int(bool(claim.member_id))),
            ("provider", len(claim.provider_npi), int(bool(claim.provider_npi))),
            ("lines", len(claim.service_lines), int(bool(claim.service_lines))),
            ("diagnoses", len(claim.diagnoses), int(bool(claim.diagnoses))),
        )
        _append(slot, "slot_index", claim.slot_index)
        slot_fixed["slot_index"].append(claim.slot_index)
        for name, length, present in lengths:
            _append(slot, f"{name}_length", length)
            _append(slot, f"{name}_present", present)
            length_counts[(length, present)] += 1
        for name, value in (
            ("eligibility_active", int(claim.eligibility_active)),
            ("not_deceased", int(claim.not_deceased)),
            ("provider_enrolled", int(claim.provider_enrolled)),
            ("provider_not_suspended", int(claim.provider_not_suspended)),
            ("duplicate_claim", int(claim.duplicate_claim)),
            ("program_integrity_hold", int(claim.program_integrity_hold)),
            ("auth_all", aggregates[0]),
            ("line_values_valid", aggregates[1]),
            ("policy_all", aggregates[2]),
        ):
            _append(slot, name, value)
        total_bytes = _bytes4(claim.total_charge_cents)
        total_nz = tuple(int(value != 0) for value in total_bytes)
        total_zero = [1]
        for value in total_nz:
            total_zero.append(total_zero[-1] * (1 - value))
        for index, value in enumerate(total_bytes):
            _append(slot, f"total_byte_{index}", value)
            _append(slot, f"total_nonzero_{index}", total_nz[index])
            _append(slot, f"total_zero_prefix_{index}", total_zero[index])
            byte_property_counts[(value, total_nz[index])] += 1
        _append(slot, "total_zero_prefix_4", total_zero[4])
        _append(slot, "total_positive", 1 - total_zero[4])
        _append(slot, "charge_valid_prefix", int(bool(claim.service_lines)) * (1 - total_zero[4]))
        for index, value in enumerate(raw):
            _append(slot, f"raw_gate_{index}", value)

    slot_rows = len(materialized)
    slot_identities: list[Identity] = []
    for name in (
        "member_present",
        "provider_present",
        "lines_present",
        "diagnoses_present",
        "eligibility_active",
        "not_deceased",
        "provider_enrolled",
        "provider_not_suspended",
        "duplicate_claim",
        "program_integrity_hold",
        "auth_all",
        "line_values_valid",
        "policy_all",
        "total_positive",
        "charge_valid_prefix",
        *(f"total_nonzero_{i}" for i in range(4)),
        *(f"total_zero_prefix_{i}" for i in range(5)),
        *(f"raw_gate_{i}" for i in range(13)),
    ):
        slot_identities.append(Identity(f"{name}_boolean", boolean(cell(name)), 0, slot_rows))
    slot_identities.append(Identity("total_zero_initial", cell("total_zero_prefix_0") - 1, 0, slot_rows))
    for index in range(4):
        slot_identities.append(
            Identity(
                f"total_zero_step_{index}",
                cell(f"total_zero_prefix_{index + 1}")
                - cell(f"total_zero_prefix_{index}") * (1 - cell(f"total_nonzero_{index}")),
                0,
                slot_rows,
            )
        )
    slot_identities.extend(
        (
            Identity("total_positive", cell("total_positive") - (1 - cell("total_zero_prefix_4")), 0, slot_rows),
            Identity(
                "charge_valid_prefix",
                cell("charge_valid_prefix") - cell("lines_present") * cell("total_positive"),
                0,
                slot_rows,
            ),
        )
    )
    raw_expected = (
        cell("member_present"),
        cell("eligibility_active"),
        cell("not_deceased"),
        cell("provider_present"),
        cell("provider_enrolled"),
        cell("provider_not_suspended"),
        cell("lines_present"),
        cell("diagnoses_present"),
        cell("auth_all"),
        cell("charge_valid_prefix") * cell("line_values_valid"),
        cell("policy_all"),
        1 - cell("duplicate_claim"),
        1 - cell("program_integrity_hold"),
    )
    for index, expected in enumerate(raw_expected):
        slot_identities.append(
            Identity(f"raw_gate_derivation_{index}", cell(f"raw_gate_{index}") - expected, 0, slot_rows)
        )

    frozen_service = freeze_columns(service)
    frozen_slot = freeze_columns(slot)
    service_trace = TraceTable("claim_service", frozen_service)
    slot_trace = TraceTable("claim_gate", frozen_slot)
    service_table = AirTable(
        "claim_service",
        tuple(frozen_service),
        service_rows,
        tuple(service_identities),
        MappingProxyType({name: tuple(values) for name, values in service_fixed.items()}),
    )
    slot_table = AirTable(
        "claim_gate",
        tuple(frozen_slot),
        slot_rows,
        tuple(slot_identities),
        MappingProxyType({"slot_index": tuple(slot_fixed["slot_index"])}),
    )

    byte_value = tuple(range(256))
    byte_nonzero = tuple(int(value != 0) for value in byte_value)
    byte_multiplicity = tuple(byte_property_counts[(value, int(value != 0))] for value in byte_value)
    byte_trace = TraceTable(
        "claim_byte_property",
        freeze_columns({"value": byte_value, "nonzero": byte_nonzero, "multiplicity": byte_multiplicity}),
    )
    byte_table = AirTable(
        "claim_byte_property",
        ("value", "nonzero", "multiplicity"),
        256,
        (),
        MappingProxyType({"value": byte_value, "nonzero": byte_nonzero}),
    )
    byte_sources = []
    for prefix in ("charge", "units"):
        for index in range(4):
            byte_sources.append(
                LookupSide(
                    "claim_service",
                    const(1),
                    (cell(f"{prefix}_byte_{index}"), cell(f"{prefix}_nonzero_{index}")),
                    0,
                    service_rows,
                )
            )
    for index in range(4):
        byte_sources.append(
            LookupSide(
                "claim_gate",
                const(1),
                (cell(f"total_byte_{index}"), cell(f"total_nonzero_{index}")),
                0,
                slot_rows,
            )
        )
    byte_lookup = LookupArgument(
        "claim_byte_nonzero",
        tuple(byte_sources),
        (
            LookupSide(
                "claim_byte_property",
                const(1),
                (cell("value"), cell("nonzero")),
                0,
                256,
                cell("multiplicity"),
            ),
        ),
    )

    length_value = tuple(range(65))
    length_present = tuple(int(value != 0) for value in length_value)
    length_multiplicity = tuple(length_counts[(value, int(value != 0))] for value in length_value)
    length_trace = TraceTable(
        "claim_length_presence",
        freeze_columns(
            {"value": length_value, "present": length_present, "multiplicity": length_multiplicity}
        ),
    )
    length_table = AirTable(
        "claim_length_presence",
        ("value", "present", "multiplicity"),
        65,
        (),
        MappingProxyType({"value": length_value, "present": length_present}),
    )
    length_lookup = LookupArgument(
        "claim_length_presence",
        tuple(
            LookupSide(
                "claim_gate",
                const(1),
                (cell(f"{name}_length"), cell(f"{name}_present")),
                0,
                slot_rows,
            )
            for name in ("member", "provider", "lines", "diagnoses")
        ),
        (
            LookupSide(
                "claim_length_presence",
                const(1),
                (cell("value"), cell("present")),
                0,
                65,
                cell("multiplicity"),
            ),
        ),
    )
    aggregate_lookup = LookupArgument(
        "claim_service_aggregates",
        (
            LookupSide(
                "claim_service",
                cell("is_last"),
                (cell("slot_index"), cell("auth_after"), cell("valid_after"), cell("policy_after")),
                0,
                service_rows,
            ),
        ),
        (
            LookupSide(
                "claim_gate",
                const(1),
                (cell("slot_index"), cell("auth_all"), cell("line_values_valid"), cell("policy_all")),
                0,
                slot_rows,
            ),
        ),
    )
    live_count_lookup = LookupArgument(
        "claim_service_live_count",
        (
            LookupSide(
                "claim_service",
                cell("live"),
                (cell("slot_index"),),
                0,
                service_rows,
            ),
        ),
        (
            LookupSide(
                "claim_gate",
                const(1),
                (cell("slot_index"),),
                0,
                slot_rows,
                cell("lines_length"),
            ),
        ),
    )
    program = AirProgram(
        PROGRAM_ID,
        (service_table, slot_table, byte_table, length_table),
        (byte_lookup, length_lookup, aggregate_lookup, live_count_lookup),
    )
    return ClaimGateAirInstance(
        program,
        MappingProxyType(
            {
                "claim_service": service_trace,
                "claim_gate": slot_trace,
                "claim_byte_property": byte_trace,
                "claim_length_presence": length_trace,
            }
        ),
    )


__all__ = ["ClaimGateAirInstance", "build_claim_gate_executable_air"]
