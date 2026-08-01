"""Executable Wave 1A first-failure and payment-result AIR."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Mapping, Sequence

from .executable_air import (
    AirProgram,
    AirTable,
    Identity,
    TraceTable,
    boolean,
    cell,
    const,
    freeze_columns,
)
from .semantics import FAILURE_GATES, ClaimSlot, SlotKind, StructuralError, evaluate_slot


PROGRAM_ID: Final[str] = "BL-WAVE1A-CLAIM-RESULT-AIR-v1"
LIMB_BITS: Final[int] = 16
LIMB_BASE: Final[int] = 1 << LIMB_BITS
MONEY_LABELS: Final[tuple[str, ...]] = (
    "allowed",
    "responsibility",
    "payment",
    "payer_debit",
    "provider_credit",
)
COVER_RAW_GATES: Final[tuple[int, ...]] = (
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    1,
    0,
    1,
    1,
    1,
)


@dataclass(frozen=True, slots=True)
class ClaimResultAirInstance:
    program: AirProgram
    traces: Mapping[str, TraceTable]


def _append(columns: dict[str, list[int]], name: str, value: int) -> None:
    columns.setdefault(name, []).append(value)


def _recompose_bits(prefix: str, limb: int):
    expression = const(0)
    for bit in range(LIMB_BITS):
        expression += (1 << bit) * cell(f"{prefix}_bit_{limb}_{bit}")
    return expression


def build_claim_result_executable_air(slots: Sequence[ClaimSlot]) -> ClaimResultAirInstance:
    materialized = tuple(slots)
    if not materialized:
        raise StructuralError("claim_result_air_slots_required")
    if tuple(slot.slot_index for slot in materialized) != tuple(range(len(materialized))):
        raise StructuralError("claim_result_air_slot_order_invalid")
    results = tuple(evaluate_slot(slot) for slot in materialized)
    columns: dict[str, list[int]] = {}

    for slot, result in zip(materialized, results, strict=True):
        is_real = int(slot.slot_kind is SlotKind.REAL)
        raw = tuple(int(value) for value in result.raw_gate_predicates)
        effective = tuple(int(value) for value in result.effective_gate_predicates)
        prefixes = [1]
        selectors = []
        for gate in effective:
            selectors.append(prefixes[-1] * (1 - gate))
            prefixes.append(prefixes[-1] * gate)
        money = (
            result.allowed_cents,
            slot.patient_responsibility_cents,
            result.payment_cents,
            result.payment_cents,
            result.payment_cents,
        )
        payment_carry = ((money[1] & 0xFFFF) + (money[2] & 0xFFFF)) // LIMB_BASE

        _append(columns, "slot_index", slot.slot_index)
        _append(columns, "is_real", is_real)
        _append(columns, "claimed_decision", slot.claimed_decision)
        _append(columns, "claimed_failure_code", slot.claimed_failure_code)
        _append(columns, "claimed_allowed", slot.claimed_allowed_cents)
        _append(columns, "claimed_payment", slot.claimed_payment_cents)
        _append(columns, "decision", result.decision)
        _append(columns, "failure_code", result.failure_code)
        _append(columns, "payment_carry", payment_carry)
        for index, value in enumerate(raw):
            _append(columns, f"raw_gate_{index}", value)
        for index, value in enumerate(effective):
            _append(columns, f"effective_gate_{index}", value)
        for index, value in enumerate(prefixes):
            _append(columns, f"prefix_{index}", value)
        for index, value in enumerate(selectors):
            _append(columns, f"failure_selector_{index}", value)
        for label, value in zip(MONEY_LABELS, money, strict=True):
            for limb in range(2):
                limb_value = (value >> (limb * LIMB_BITS)) & 0xFFFF
                _append(columns, f"{label}_limb_{limb}", limb_value)
                for bit in range(LIMB_BITS):
                    _append(columns, f"{label}_bit_{limb}_{bit}", (limb_value >> bit) & 1)

    rows = len(materialized)
    identities: list[Identity] = [Identity("is_real_boolean", boolean(cell("is_real")), 0, rows)]
    for index, cover_expected in enumerate(COVER_RAW_GATES):
        raw = cell(f"raw_gate_{index}")
        effective = cell(f"effective_gate_{index}")
        prefix = cell(f"prefix_{index}")
        selector = cell(f"failure_selector_{index}")
        identities.extend(
            (
                Identity(f"raw_gate_boolean_{index}", boolean(raw), 0, rows),
                Identity(f"effective_gate_boolean_{index}", boolean(effective), 0, rows),
                Identity(f"prefix_boolean_{index}", boolean(prefix), 0, rows),
                Identity(f"selector_boolean_{index}", boolean(selector), 0, rows),
                Identity(
                    f"cover_raw_gate_{index}",
                    (1 - cell("is_real")) * (raw - cover_expected),
                    0,
                    rows,
                ),
                Identity(
                    f"effective_gate_{index}",
                    effective - ((1 - cell("is_real")) + cell("is_real") * raw),
                    0,
                    rows,
                ),
                Identity(
                    f"first_failure_selector_{index}",
                    selector - prefix * (1 - effective),
                    0,
                    rows,
                ),
                Identity(
                    f"prefix_step_{index}",
                    cell(f"prefix_{index + 1}") - prefix * effective,
                    0,
                    rows,
                ),
            )
        )
    identities.extend(
        (
            Identity("prefix_initial", cell("prefix_0") - 1, 0, rows),
            Identity(
                f"prefix_boolean_{len(FAILURE_GATES)}",
                boolean(cell(f"prefix_{len(FAILURE_GATES)}")),
                0,
                rows,
            ),
            Identity("decision_boolean", boolean(cell("decision")), 0, rows),
            Identity(
                "decision_from_prefix",
                cell("decision") - cell("is_real") * cell(f"prefix_{len(FAILURE_GATES)}"),
                0,
                rows,
            ),
        )
    )
    expected_failure = const(0)
    terminal = cell(f"prefix_{len(FAILURE_GATES)}")
    for index in range(len(FAILURE_GATES)):
        expected_failure += (index + 1) * cell(f"failure_selector_{index}")
        terminal += cell(f"failure_selector_{index}")
    identities.extend(
        (
            Identity("failure_code", cell("failure_code") - expected_failure, 0, rows),
            Identity("failure_partition", terminal - 1, 0, rows),
            Identity("claimed_decision", cell("claimed_decision") - cell("decision"), 0, rows),
            Identity("claimed_failure", cell("claimed_failure_code") - cell("failure_code"), 0, rows),
            Identity("claimed_allowed", cell("claimed_allowed") - cell("allowed_limb_0") - LIMB_BASE * cell("allowed_limb_1"), 0, rows),
            Identity("claimed_payment", cell("claimed_payment") - cell("payment_limb_0") - LIMB_BASE * cell("payment_limb_1"), 0, rows),
            Identity("payment_carry_boolean", boolean(cell("payment_carry")), 0, rows),
        )
    )
    for label in MONEY_LABELS:
        for limb in range(2):
            identities.append(
                Identity(
                    f"{label}_limb_recomposition_{limb}",
                    cell(f"{label}_limb_{limb}") - _recompose_bits(label, limb),
                    0,
                    rows,
                )
            )
            for bit in range(LIMB_BITS):
                value = cell(f"{label}_bit_{limb}_{bit}")
                identities.extend(
                    (
                        Identity(f"{label}_bit_boolean_{limb}_{bit}", boolean(value), 0, rows),
                        Identity(
                            f"{label}_denial_zero_{limb}_{bit}",
                            (1 - cell("decision")) * value,
                            0,
                            rows,
                        ),
                    )
                )
    identities.extend(
        (
            Identity(
                "payment_low",
                cell("responsibility_limb_0")
                + cell("payment_limb_0")
                - cell("allowed_limb_0")
                - LIMB_BASE * cell("payment_carry"),
                0,
                rows,
            ),
            Identity(
                "payment_high",
                cell("responsibility_limb_1")
                + cell("payment_limb_1")
                + cell("payment_carry")
                - cell("allowed_limb_1"),
                0,
                rows,
            ),
        )
    )
    for limb in range(2):
        identities.extend(
            (
                Identity(
                    f"payer_debit_{limb}",
                    cell(f"payer_debit_limb_{limb}") - cell(f"payment_limb_{limb}"),
                    0,
                    rows,
                ),
                Identity(
                    f"provider_credit_{limb}",
                    cell(f"provider_credit_limb_{limb}") - cell(f"payment_limb_{limb}"),
                    0,
                    rows,
                ),
            )
        )

    trace = TraceTable("claim_result", freeze_columns(columns))
    table = AirTable(
        "claim_result",
        tuple(trace.columns),
        rows,
        tuple(identities),
        MappingProxyType({"slot_index": tuple(range(rows))}),
    )
    program = AirProgram(PROGRAM_ID, (table,))
    return ClaimResultAirInstance(program, MappingProxyType({"claim_result": trace}))


__all__ = ["ClaimResultAirInstance", "build_claim_result_executable_air"]
