"""Executable fixed-shape claim fee arithmetic over M31.

The table makes the semantic ``sum(min(charge, policy_allowed))`` rule and the
declared total-charge equality explicit.  It uses one linear row per service
line; there is no per-line authentication path or host-language arithmetic in
the verifier relation.
"""

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
from .semantics import ClaimSlot, StructuralError, evaluate_slot


PROGRAM_ID: Final[str] = "BL-WAVE1A-FEE-ARITHMETIC-AIR-v1"
BYTE_BASE: Final[int] = 1 << 8
LIMB_BASE: Final[int] = 1 << 16


@dataclass(frozen=True, slots=True)
class FeeArithmeticAirInstance:
    program: AirProgram
    traces: Mapping[str, TraceTable]


def _append(columns: dict[str, list[int]], name: str, value: int) -> None:
    columns.setdefault(name, []).append(value)


def _bytes4(value: int) -> tuple[int, int, int, int]:
    return tuple(value.to_bytes(4, "little"))  # type: ignore[return-value]


def _limbs2(value: int) -> tuple[int, int]:
    return value & 0xFFFF, value >> 16


def _append_limb_bytes(
    columns: dict[str, list[int]],
    byte_counts: Counter[int],
    prefix: str,
    values: tuple[int, int],
) -> None:
    for limb_index, value in enumerate(values):
        _append(columns, f"{prefix}_limb_{limb_index}", value)
        for byte_index, byte in enumerate(value.to_bytes(2, "little")):
            _append(columns, f"{prefix}_limb_{limb_index}_byte_{byte_index}", byte)
            byte_counts[byte] += 1


def _limb_recomposition(prefix: str, limb_index: int):
    return (
        cell(f"{prefix}_limb_{limb_index}")
        - cell(f"{prefix}_limb_{limb_index}_byte_0")
        - BYTE_BASE * cell(f"{prefix}_limb_{limb_index}_byte_1")
    )


def build_fee_arithmetic_executable_air(
    slots: Sequence[ClaimSlot],
) -> FeeArithmeticAirInstance:
    materialized = tuple(slots)
    if not materialized or tuple(slot.slot_index for slot in materialized) != tuple(
        range(len(materialized))
    ):
        raise StructuralError("fee_air_slot_order_invalid")
    results = tuple(evaluate_slot(slot) for slot in materialized)

    fee: dict[str, list[int]] = {}
    fixed: dict[str, list[int]] = {
        name: []
        for name in ("slot_index", "line_index", "is_first", "is_last", "has_next")
    }
    byte_counts: Counter[int] = Counter()
    final_values: list[tuple[int, int]] = []

    for slot in materialized:
        charge_running = 0
        candidate_running = 0
        for line_index in range(SERVICE_LINES_PER_CLAIM):
            live = int(line_index < len(slot.service_lines))
            if live:
                line = slot.service_lines[line_index]
                policy_present = int(line.policy_present)
                charge = line.charge_cents
                allowed = line.allowed_cents
            else:
                policy_present = charge = allowed = 0
            charge_bytes = _bytes4(charge)
            allowed_bytes = _bytes4(allowed)

            borrows = [0]
            differences: list[int] = []
            for charge_byte, allowed_byte in zip(charge_bytes, allowed_bytes, strict=True):
                signed = charge_byte - allowed_byte - borrows[-1]
                borrow = int(signed < 0)
                differences.append(signed + BYTE_BASE * borrow)
                borrows.append(borrow)
            charge_less = borrows[-1]
            minimum_bytes = tuple(
                charge_less * charge_byte + (1 - charge_less) * allowed_byte
                for charge_byte, allowed_byte in zip(charge_bytes, allowed_bytes, strict=True)
            )
            minimum = int.from_bytes(bytes(minimum_bytes), "little")
            candidate = policy_present * minimum
            candidate_bytes = _bytes4(candidate)

            charge_before = charge_running
            candidate_before = candidate_running
            charge_running += charge
            candidate_running += candidate
            charge_before_limbs = _limbs2(charge_before)
            candidate_before_limbs = _limbs2(candidate_before)
            charge_limbs = _limbs2(charge)
            candidate_limbs = _limbs2(candidate)
            charge_after_limbs = _limbs2(charge_running)
            candidate_after_limbs = _limbs2(candidate_running)
            charge_carry = (charge_before_limbs[0] + charge_limbs[0]) // LIMB_BASE
            candidate_carry = (candidate_before_limbs[0] + candidate_limbs[0]) // LIMB_BASE
            charge_overflow = (
                charge_before_limbs[1] + charge_limbs[1] + charge_carry
            ) // LIMB_BASE
            candidate_overflow = (
                candidate_before_limbs[1] + candidate_limbs[1] + candidate_carry
            ) // LIMB_BASE

            fixed_values = {
                "slot_index": slot.slot_index,
                "line_index": line_index,
                "is_first": int(line_index == 0),
                "is_last": int(line_index == SERVICE_LINES_PER_CLAIM - 1),
                "has_next": int(line_index != SERVICE_LINES_PER_CLAIM - 1),
                "live": live,
            }
            for name, value in fixed_values.items():
                _append(fee, name, value)
                if name in fixed:
                    fixed[name].append(value)
            _append(fee, "policy_present", policy_present)
            _append(fee, "charge_less", charge_less)
            for index in range(5):
                _append(fee, f"borrow_{index}", borrows[index])
            for index in range(4):
                values = {
                    "charge": charge_bytes[index],
                    "allowed": allowed_bytes[index],
                    "difference": differences[index],
                    "minimum": minimum_bytes[index],
                    "candidate": candidate_bytes[index],
                }
                for prefix, value in values.items():
                    _append(fee, f"{prefix}_byte_{index}", value)
                    byte_counts[value] += 1
            for prefix, values in (
                ("charge_before", charge_before_limbs),
                ("charge_value", charge_limbs),
                ("charge_after", charge_after_limbs),
                ("candidate_before", candidate_before_limbs),
                ("candidate_value", candidate_limbs),
                ("candidate_after", candidate_after_limbs),
            ):
                _append_limb_bytes(fee, byte_counts, prefix, values)
            for name, value in (
                ("charge_carry", charge_carry),
                ("candidate_carry", candidate_carry),
                ("charge_overflow", charge_overflow),
                ("candidate_overflow", candidate_overflow),
            ):
                _append(fee, name, value)
        final_values.append((charge_running, candidate_running))

    rows = len(materialized) * SERVICE_LINES_PER_CLAIM
    identities: list[Identity] = []
    for name in (
        "live",
        "policy_present",
        "charge_less",
        *(f"borrow_{index}" for index in range(5)),
        "charge_carry",
        "candidate_carry",
        "charge_overflow",
        "candidate_overflow",
    ):
        identities.append(Identity(f"{name}_boolean", boolean(cell(name)), 0, rows))
    for slot_index in range(len(materialized)):
        start = slot_index * SERVICE_LINES_PER_CLAIM
        identities.append(
            Identity(
                f"live_prefix_{slot_index}",
                cell("live", 1) * (1 - cell("live")),
                start,
                start + SERVICE_LINES_PER_CLAIM - 1,
                "transition",
            )
        )
    identities.extend(
        (
            Identity("borrow_initial_zero", cell("borrow_0"), 0, rows),
            Identity("charge_less_final_borrow", cell("charge_less") - cell("borrow_4"), 0, rows),
            Identity("charge_overflow_zero", cell("charge_overflow"), 0, rows),
            Identity("candidate_overflow_zero", cell("candidate_overflow"), 0, rows),
            Identity(
                "disabled_policy_zero",
                (1 - cell("live")) * cell("policy_present"),
                0,
                rows,
            ),
        )
    )
    for index in range(4):
        identities.extend(
            (
                Identity(
                    f"comparison_byte_{index}",
                    cell(f"charge_byte_{index}")
                    - cell(f"allowed_byte_{index}")
                    - cell(f"borrow_{index}")
                    - cell(f"difference_byte_{index}")
                    + BYTE_BASE * cell(f"borrow_{index + 1}"),
                    0,
                    rows,
                ),
                Identity(
                    f"minimum_byte_{index}",
                    cell(f"minimum_byte_{index}")
                    - cell("charge_less") * cell(f"charge_byte_{index}")
                    - (1 - cell("charge_less")) * cell(f"allowed_byte_{index}"),
                    0,
                    rows,
                ),
                Identity(
                    f"candidate_byte_{index}",
                    cell(f"candidate_byte_{index}")
                    - cell("policy_present") * cell(f"minimum_byte_{index}"),
                    0,
                    rows,
                ),
                Identity(
                    f"disabled_charge_{index}",
                    (1 - cell("live")) * cell(f"charge_byte_{index}"),
                    0,
                    rows,
                ),
                Identity(
                    f"disabled_allowed_{index}",
                    (1 - cell("live")) * cell(f"allowed_byte_{index}"),
                    0,
                    rows,
                ),
                Identity(
                    f"absent_policy_allowed_{index}",
                    (1 - cell("policy_present")) * cell(f"allowed_byte_{index}"),
                    0,
                    rows,
                ),
            )
        )
    for prefix in (
        "charge_before",
        "charge_value",
        "charge_after",
        "candidate_before",
        "candidate_value",
        "candidate_after",
    ):
        for limb_index in range(2):
            identities.append(
                Identity(
                    f"{prefix}_limb_recomposition_{limb_index}",
                    _limb_recomposition(prefix, limb_index),
                    0,
                    rows,
                )
            )
    for value_prefix, byte_prefix in (("charge_value", "charge"), ("candidate_value", "candidate")):
        for limb_index in range(2):
            identities.append(
                Identity(
                    f"{value_prefix}_bytes_{limb_index}",
                    cell(f"{value_prefix}_limb_{limb_index}")
                    - cell(f"{byte_prefix}_byte_{2 * limb_index}")
                    - BYTE_BASE * cell(f"{byte_prefix}_byte_{2 * limb_index + 1}"),
                    0,
                    rows,
                )
            )
    for prefix in ("charge", "candidate"):
        identities.extend(
            (
                Identity(
                    f"{prefix}_initial_low",
                    cell("is_first") * cell(f"{prefix}_before_limb_0"),
                    0,
                    rows,
                ),
                Identity(
                    f"{prefix}_initial_high",
                    cell("is_first") * cell(f"{prefix}_before_limb_1"),
                    0,
                    rows,
                ),
                Identity(
                    f"{prefix}_addition_low",
                    cell(f"{prefix}_before_limb_0")
                    + cell(f"{prefix}_value_limb_0")
                    - cell(f"{prefix}_after_limb_0")
                    - LIMB_BASE * cell(f"{prefix}_carry"),
                    0,
                    rows,
                ),
                Identity(
                    f"{prefix}_addition_high",
                    cell(f"{prefix}_before_limb_1")
                    + cell(f"{prefix}_value_limb_1")
                    + cell(f"{prefix}_carry")
                    - cell(f"{prefix}_after_limb_1")
                    - LIMB_BASE * cell(f"{prefix}_overflow"),
                    0,
                    rows,
                ),
                Identity(
                    f"{prefix}_transition_low",
                    cell("has_next")
                    * (cell(f"{prefix}_after_limb_0") - cell(f"{prefix}_before_limb_0", 1)),
                    0,
                    rows - 1,
                    "transition",
                ),
                Identity(
                    f"{prefix}_transition_high",
                    cell("has_next")
                    * (cell(f"{prefix}_after_limb_1") - cell(f"{prefix}_before_limb_1", 1)),
                    0,
                    rows - 1,
                    "transition",
                ),
            )
        )

    frozen_fee = freeze_columns(fee)
    fee_trace = TraceTable("claim_fee", frozen_fee)
    fee_table = AirTable(
        "claim_fee",
        tuple(frozen_fee),
        rows,
        tuple(identities),
        MappingProxyType({name: tuple(values) for name, values in fixed.items()}),
    )

    slot_columns: dict[str, list[int]] = {}
    for slot, result, (charge_total, candidate_total) in zip(
        materialized, results, final_values, strict=True
    ):
        _append(slot_columns, "slot_index", slot.slot_index)
        _append(slot_columns, "decision", result.decision)
        for prefix, value in (
            ("declared_total", slot.total_charge_cents),
            ("computed_total", charge_total),
            ("candidate", candidate_total),
            ("result_allowed", result.allowed_cents),
        ):
            for limb_index, limb in enumerate(_limbs2(value)):
                _append(slot_columns, f"{prefix}_limb_{limb_index}", limb)
        for index, value in enumerate(_bytes4(slot.total_charge_cents)):
            _append(slot_columns, f"declared_total_byte_{index}", value)
            byte_counts[value] += 1
    slot_rows = len(materialized)
    slot_identities: list[Identity] = [
        Identity("decision_boolean", boolean(cell("decision")), 0, slot_rows)
    ]
    for limb_index in range(2):
        slot_identities.extend(
            (
                Identity(
                    f"declared_total_bytes_{limb_index}",
                    cell(f"declared_total_limb_{limb_index}")
                    - cell(f"declared_total_byte_{2 * limb_index}")
                    - BYTE_BASE * cell(f"declared_total_byte_{2 * limb_index + 1}"),
                    0,
                    slot_rows,
                ),
                Identity(
                    f"declared_matches_computed_{limb_index}",
                    cell(f"declared_total_limb_{limb_index}")
                    - cell(f"computed_total_limb_{limb_index}"),
                    0,
                    slot_rows,
                ),
                Identity(
                    f"allowed_from_candidate_{limb_index}",
                    cell(f"result_allowed_limb_{limb_index}")
                    - cell("decision") * cell(f"candidate_limb_{limb_index}"),
                    0,
                    slot_rows,
                ),
            )
        )
    frozen_slot = freeze_columns(slot_columns)
    slot_trace = TraceTable("claim_fee_slot", frozen_slot)
    slot_table = AirTable(
        "claim_fee_slot",
        tuple(frozen_slot),
        slot_rows,
        tuple(slot_identities),
        MappingProxyType({"slot_index": tuple(range(slot_rows))}),
    )

    byte_values = tuple(range(256))
    byte_trace = TraceTable(
        "fee_byte_range",
        freeze_columns(
            {
                "value": byte_values,
                "multiplicity": tuple(byte_counts[value] for value in byte_values),
            }
        ),
    )
    byte_table = AirTable(
        "fee_byte_range",
        ("value", "multiplicity"),
        256,
        (),
        MappingProxyType({"value": byte_values}),
    )
    byte_sources: list[LookupSide] = []
    for prefix in ("charge", "allowed", "difference", "minimum", "candidate"):
        for index in range(4):
            byte_sources.append(
                LookupSide("claim_fee", const(1), (cell(f"{prefix}_byte_{index}"),), 0, rows)
            )
    for prefix in (
        "charge_before",
        "charge_value",
        "charge_after",
        "candidate_before",
        "candidate_value",
        "candidate_after",
    ):
        for limb_index in range(2):
            for byte_index in range(2):
                byte_sources.append(
                    LookupSide(
                        "claim_fee",
                        const(1),
                        (cell(f"{prefix}_limb_{limb_index}_byte_{byte_index}"),),
                        0,
                        rows,
                    )
                )
    for index in range(4):
        byte_sources.append(
            LookupSide("claim_fee_slot", const(1), (cell(f"declared_total_byte_{index}"),), 0, slot_rows)
        )
    byte_lookup = LookupArgument(
        "fee_byte_range",
        tuple(byte_sources),
        (
            LookupSide(
                "fee_byte_range",
                const(1),
                (cell("value"),),
                0,
                256,
                cell("multiplicity"),
            ),
        ),
    )
    final_lookup = LookupArgument(
        "fee_final_accumulators",
        (
            LookupSide(
                "claim_fee",
                cell("is_last"),
                (
                    cell("slot_index"),
                    cell("charge_after_limb_0"),
                    cell("charge_after_limb_1"),
                    cell("candidate_after_limb_0"),
                    cell("candidate_after_limb_1"),
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
                    cell("computed_total_limb_0"),
                    cell("computed_total_limb_1"),
                    cell("candidate_limb_0"),
                    cell("candidate_limb_1"),
                ),
                0,
                slot_rows,
            ),
        ),
    )
    program = AirProgram(
        PROGRAM_ID,
        (fee_table, slot_table, byte_table),
        (byte_lookup, final_lookup),
    )
    return FeeArithmeticAirInstance(
        program,
        MappingProxyType(
            {
                "claim_fee": fee_trace,
                "claim_fee_slot": slot_trace,
                "fee_byte_range": byte_trace,
            }
        ),
    )


__all__ = ["FeeArithmeticAirInstance", "build_fee_arithmetic_executable_air"]
