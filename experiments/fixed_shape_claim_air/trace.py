"""Logical fixed-shape trace schedule; not a physical AIR."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Mapping, Sequence

from .profile import (
    AUTHORIZATIONS_PER_CLAIM,
    DIAGNOSES_PER_CLAIM,
    FACTS_PER_CLAIM,
    LEGACY_NULLIFIER_TREE_DEPTH,
    SERVICE_LINES_PER_CLAIM,
    STRONG_NULLIFIER_TREE_DEPTH,
    CalibrationProfile,
)
from .semantics import (
    FAILURE_GATES,
    ClaimSlot,
    SlotKind,
    SlotResult,
    evaluate_slot,
    validate_batch,
)


PER_SLOT_OPERATION_SCHEDULE: Final[tuple[tuple[str, int], ...]] = (
    ("claim_rows", 1),
    ("service_line_rows", SERVICE_LINES_PER_CLAIM),
    ("diagnosis_rows", DIAGNOSES_PER_CLAIM),
    ("fact_rows", FACTS_PER_CLAIM),
    ("authorization_rows", AUTHORIZATIONS_PER_CLAIM),
    ("policy_query_rows", SERVICE_LINES_PER_CLAIM),
    ("claim_source_leaves", 1),
    ("oracle_leaves", 1 + AUTHORIZATIONS_PER_CLAIM),
    ("legacy_nullifier_path_nodes", 2 * LEGACY_NULLIFIER_TREE_DEPTH),
    ("strong_nullifier_path_nodes", 2 * STRONG_NULLIFIER_TREE_DEPTH),
    ("legacy_nullifier_transitions", 1),
    ("strong_nullifier_transitions", 1),
    ("benefit_state_path_operations", 1),
    ("obligation_state_path_operations", 1),
    ("private_asset_ledger_path_operations", 1),
    ("payment_state_transitions", 1),
    ("operation_log_appends", 1),
)
BATCH_FINAL_OPERATION_SCHEDULE: Final[
    tuple[tuple[str, int], ...]
] = (("salt_use_transitions", 1),)


@dataclass(frozen=True, slots=True)
class LogicalTraceSlot:
    slot_index: int
    witness_class: str
    result: SlotResult
    failure_selector: tuple[int, ...]
    operation_schedule: tuple[tuple[str, int], ...]


@dataclass(frozen=True, slots=True)
class LogicalTrace:
    profile_id: str
    logical_dimensions: Mapping[str, int]
    slots: tuple[LogicalTraceSlot, ...]
    batch_final_operations: tuple[tuple[str, int], ...]
    physical_air_rows: None = None
    physical_air_columns: None = None

    def assert_uniform_operation_schedule(self) -> None:
        if any(
            slot.operation_schedule != PER_SLOT_OPERATION_SCHEDULE
            for slot in self.slots
        ):
            raise AssertionError(
                "r25_witness_class_changed_operation_schedule"
            )
        if self.batch_final_operations != BATCH_FINAL_OPERATION_SCHEDULE:
            raise AssertionError("r25_batch_final_schedule_changed")


def _witness_class(slot: ClaimSlot, result: SlotResult) -> str:
    if slot.slot_kind is SlotKind.COVER:
        return "cover"
    return "approval" if result.decision == 1 else "denial"


def build_logical_trace(
    profile: CalibrationProfile,
    slots: Sequence[ClaimSlot],
) -> LogicalTrace:
    materialized = tuple(slots)
    validate_batch(profile, materialized)
    trace_slots: list[LogicalTraceSlot] = []
    for slot in materialized:
        result = evaluate_slot(slot)
        selector = tuple(
            int(result.failure_code == gate.code)
            for gate in FAILURE_GATES
        )
        if sum(selector) not in (0, 1):
            raise AssertionError("r25_failure_selector_not_one_hot")
        trace_slots.append(
            LogicalTraceSlot(
                slot_index=slot.slot_index,
                witness_class=_witness_class(slot, result),
                result=result,
                failure_selector=selector,
                operation_schedule=PER_SLOT_OPERATION_SCHEDULE,
            )
        )
    trace = LogicalTrace(
        profile_id=profile.profile_id,
        logical_dimensions=profile.logical_dimensions(),
        slots=tuple(trace_slots),
        batch_final_operations=BATCH_FINAL_OPERATION_SCHEDULE,
    )
    trace.assert_uniform_operation_schedule()
    return trace
