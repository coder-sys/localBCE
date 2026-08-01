"""Composed executable claim-gate, first-failure, and payment-result AIR."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Mapping, Sequence

from .claim_gate_executable_air import build_claim_gate_executable_air
from .claim_result_executable_air import build_claim_result_executable_air
from .executable_air import AirProgram, LookupArgument, LookupSide, TraceTable, cell, const
from .fee_arithmetic_executable_air import build_fee_arithmetic_executable_air
from .semantics import ClaimSlot


PROGRAM_ID: Final[str] = "BL-WAVE1A-CLAIM-SEMANTICS-AIR-v1"


@dataclass(frozen=True, slots=True)
class ClaimSemanticsAirInstance:
    program: AirProgram
    traces: Mapping[str, TraceTable]


def build_claim_semantics_executable_air(
    slots: Sequence[ClaimSlot],
) -> ClaimSemanticsAirInstance:
    gate = build_claim_gate_executable_air(slots)
    result = build_claim_result_executable_air(slots)
    fee = build_fee_arithmetic_executable_air(slots)
    rows = len(tuple(slots))
    values = (cell("slot_index"), *(cell(f"raw_gate_{index}") for index in range(13)))
    link = LookupArgument(
        "claim_gate_result_link",
        (LookupSide("claim_gate", const(1), values, 0, rows),),
        (LookupSide("claim_result", const(1), values, 0, rows),),
    )
    fee_service_link = LookupArgument(
        "claim_service_fee_link",
        (
            LookupSide(
                "claim_service",
                const(1),
                (
                    cell("slot_index"),
                    cell("line_index"),
                    cell("live"),
                    cell("policy_present"),
                    *(cell(f"charge_byte_{index}") for index in range(4)),
                ),
                0,
                rows * 50,
            ),
        ),
        (
            LookupSide(
                "claim_fee",
                const(1),
                (
                    cell("slot_index"),
                    cell("line_index"),
                    cell("live"),
                    cell("policy_present"),
                    *(cell(f"charge_byte_{index}") for index in range(4)),
                ),
                0,
                rows * 50,
            ),
        ),
    )
    fee_gate_link = LookupArgument(
        "claim_fee_gate_total_link",
        (
            LookupSide(
                "claim_gate",
                const(1),
                (cell("slot_index"), *(cell(f"total_byte_{index}") for index in range(4))),
                0,
                rows,
            ),
        ),
        (
            LookupSide(
                "claim_fee_slot",
                const(1),
                (
                    cell("slot_index"),
                    *(cell(f"declared_total_byte_{index}") for index in range(4)),
                ),
                0,
                rows,
            ),
        ),
    )
    fee_result_link = LookupArgument(
        "claim_fee_result_link",
        (
            LookupSide(
                "claim_result",
                const(1),
                (
                    cell("slot_index"),
                    cell("decision"),
                    cell("allowed_limb_0"),
                    cell("allowed_limb_1"),
                ),
                0,
                rows,
            ),
        ),
        (
            LookupSide(
                "claim_fee_slot",
                const(1),
                (
                    cell("slot_index"),
                    cell("decision"),
                    cell("result_allowed_limb_0"),
                    cell("result_allowed_limb_1"),
                ),
                0,
                rows,
            ),
        ),
    )
    program = AirProgram(
        PROGRAM_ID,
        (*gate.program.tables, *result.program.tables, *fee.program.tables),
        (
            *gate.program.lookups,
            *result.program.lookups,
            *fee.program.lookups,
            link,
            fee_service_link,
            fee_gate_link,
            fee_result_link,
        ),
    )
    return ClaimSemanticsAirInstance(
        program,
        MappingProxyType({**dict(gate.traces), **dict(result.traces), **dict(fee.traces)}),
    )


__all__ = ["ClaimSemanticsAirInstance", "build_claim_semantics_executable_air"]
