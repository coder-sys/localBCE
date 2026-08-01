"""Exact synthetic payment economics; no map, root, or settlement claim."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from .profile import CalibrationProfile, get_profile
from .semantics import (
    UINT32_MAX,
    ClaimSlot,
    SlotKind,
    StructuralError,
    evaluate_slot,
    validate_batch,
)


def _exact_uint(label: str, value: object, maximum: int) -> int:
    if type(value) is not int or value < 0 or value > maximum:
        raise StructuralError(f"r25_{label}_out_of_range")
    return value


@dataclass(frozen=True, slots=True)
class SlotEconomics:
    slot_index: int
    slot_kind: SlotKind
    decision: int
    gross_allowed_cents: int
    patient_responsibility_cents: int
    plan_payable_cents: int
    payer_reserve_debit_cents: int
    provider_payable_credit_cents: int

    def __post_init__(self) -> None:
        _exact_uint("economic_slot_index", self.slot_index, 511)
        if type(self.slot_kind) is not SlotKind:
            raise StructuralError("r25_economic_slot_kind_invalid")
        _exact_uint("economic_decision", self.decision, 1)
        values = (
            self.gross_allowed_cents,
            self.patient_responsibility_cents,
            self.plan_payable_cents,
            self.payer_reserve_debit_cents,
            self.provider_payable_credit_cents,
        )
        for label, value in zip(
            (
                "gross_allowed_cents",
                "patient_responsibility_cents",
                "plan_payable_cents",
                "payer_reserve_debit_cents",
                "provider_payable_credit_cents",
            ),
            values,
            strict=True,
        ):
            _exact_uint(f"economic_{label}", value, UINT32_MAX)
        if self.decision == 1:
            if self.slot_kind is not SlotKind.REAL:
                raise StructuralError("r25_approval_requires_real_slot")
            if self.gross_allowed_cents != (
                self.patient_responsibility_cents + self.plan_payable_cents
            ):
                raise StructuralError("r25_plan_payable_relation_mismatch")
            if (
                self.payer_reserve_debit_cents != self.plan_payable_cents
                or self.provider_payable_credit_cents != self.plan_payable_cents
            ):
                raise StructuralError("r25_slot_conservation_mismatch")
        elif any(values):
            raise StructuralError("r25_nonapproval_economics_must_be_zero")


@dataclass(frozen=True, slots=True)
class BatchEconomics:
    profile_id: str
    slots: tuple[SlotEconomics, ...]
    total_plan_payable_cents: int
    total_debits_cents: int
    total_credits_cents: int

    def __post_init__(self) -> None:
        profile = get_profile(self.profile_id)
        if type(self.slots) is not tuple or len(self.slots) != profile.claim_slots:
            raise StructuralError("r25_batch_economics_slot_count_mismatch")
        if any(
            not isinstance(slot, SlotEconomics)
            or slot.slot_index != index
            for index, slot in enumerate(self.slots)
        ):
            raise StructuralError("r25_batch_economics_slot_order_invalid")
        maximum = profile.claim_slots * UINT32_MAX
        payable = sum(slot.plan_payable_cents for slot in self.slots)
        debits = sum(slot.payer_reserve_debit_cents for slot in self.slots)
        credits = sum(slot.provider_payable_credit_cents for slot in self.slots)
        for label, supplied, observed in (
            ("plan_payable", self.total_plan_payable_cents, payable),
            ("debits", self.total_debits_cents, debits),
            ("credits", self.total_credits_cents, credits),
        ):
            _exact_uint(f"batch_{label}_cents", supplied, maximum)
            if supplied != observed:
                raise StructuralError(f"r25_batch_{label}_total_mismatch")
        if payable != debits or payable != credits:
            raise StructuralError("r25_batch_conservation_mismatch")


def derive_slot_economics(slot: ClaimSlot) -> SlotEconomics:
    result = evaluate_slot(slot)
    approved = result.decision == 1
    gross = result.allowed_cents if approved else 0
    responsibility = slot.patient_responsibility_cents if approved else 0
    payable = result.payment_cents if approved else 0
    return SlotEconomics(
        slot_index=slot.slot_index,
        slot_kind=slot.slot_kind,
        decision=result.decision,
        gross_allowed_cents=gross,
        patient_responsibility_cents=responsibility,
        plan_payable_cents=payable,
        payer_reserve_debit_cents=payable,
        provider_payable_credit_cents=payable,
    )


def derive_batch_economics(
    profile: CalibrationProfile,
    slots: Sequence[ClaimSlot],
) -> BatchEconomics:
    materialized = tuple(slots)
    validate_batch(profile, materialized)
    economics = tuple(derive_slot_economics(slot) for slot in materialized)
    payable = sum(slot.plan_payable_cents for slot in economics)
    debits = sum(slot.payer_reserve_debit_cents for slot in economics)
    credits = sum(slot.provider_payable_credit_cents for slot in economics)
    return BatchEconomics(
        profile.profile_id,
        economics,
        payable,
        debits,
        credits,
    )
