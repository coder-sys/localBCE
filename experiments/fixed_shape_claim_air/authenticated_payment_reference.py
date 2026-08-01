"""Authenticated fixed-shape aggregate payment transition for Wave 1A.

Every slot, including denial and cover, advances the operation log and state
root. Approved slots additionally debit payer reserve and credit the provider
obligation/paid aggregates by exactly the plan-payable amount. This is an
executable SHA3-512 state transition, not yet the future per-member/provider
authenticated map or a production settlement implementation.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
import hmac
from typing import Final, Sequence

from app.batch.pq_tree_reference import require_synthetic_reference_enabled

from .payment import SlotEconomics
from .profile import CalibrationProfile
from .semantics import StructuralError


AUTHENTICATED_PAYMENT_STATUS: Final[str] = (
    "SYNTHETIC_AUTHENTICATED_AGGREGATE_PAYMENT_STATE_V1_NOT_PRODUCTION_MAP"
)
_STATE_DOMAIN: Final[bytes] = b"BL/PQ512/PAYMENT-AGGREGATE/STATE/REFERENCE/v1"
_OPERATION_DOMAIN: Final[bytes] = b"BL/PQ512/PAYMENT-AGGREGATE/OPERATION/REFERENCE/v1"
_LOG_DOMAIN: Final[bytes] = b"BL/PQ512/PAYMENT-AGGREGATE/LOG/REFERENCE/v1"
_U64_MAX: Final[int] = (1 << 64) - 1


def _u64(label: str, value: object) -> int:
    if type(value) is not int or not 0 <= value <= _U64_MAX:
        raise StructuralError(f"wave1a_payment_{label}_out_of_range")
    return value


def _digest(label: str, value: object, *, nonzero: bool = True) -> bytes:
    if type(value) is not bytes or len(value) != 64:
        raise StructuralError(f"wave1a_payment_{label}_must_be_64_bytes")
    if nonzero and not any(value):
        raise StructuralError(f"wave1a_payment_{label}_must_be_nonzero")
    return value


@dataclass(frozen=True, slots=True)
class AuthenticatedPaymentState:
    epoch: int
    sequence: int
    next_slot_index: int
    payer_reserve_cents: int
    provider_obligation_cents: int
    total_paid_cents: int
    patient_responsibility_cents: int
    operation_log_root_sha3_512: bytes
    status: str = AUTHENTICATED_PAYMENT_STATUS

    def __post_init__(self) -> None:
        require_synthetic_reference_enabled()
        if self.status != AUTHENTICATED_PAYMENT_STATUS:
            raise StructuralError("wave1a_payment_state_status_invalid")
        if _u64("epoch", self.epoch) == 0:
            raise StructuralError("wave1a_payment_epoch_zero")
        _u64("sequence", self.sequence)
        _u64("next_slot_index", self.next_slot_index)
        _u64("payer_reserve_cents", self.payer_reserve_cents)
        _u64("provider_obligation_cents", self.provider_obligation_cents)
        _u64("total_paid_cents", self.total_paid_cents)
        _u64(
            "patient_responsibility_cents",
            self.patient_responsibility_cents,
        )
        _digest("operation_log_root", self.operation_log_root_sha3_512)

    def root(self) -> bytes:
        return sha3_512(
            _STATE_DOMAIN
            + self.epoch.to_bytes(8, "big")
            + self.sequence.to_bytes(8, "big")
            + self.next_slot_index.to_bytes(8, "big")
            + self.payer_reserve_cents.to_bytes(8, "big")
            + self.provider_obligation_cents.to_bytes(8, "big")
            + self.total_paid_cents.to_bytes(8, "big")
            + self.patient_responsibility_cents.to_bytes(8, "big")
            + self.operation_log_root_sha3_512
        ).digest()


def payment_operation_commitment(operation: SlotEconomics) -> bytes:
    if not isinstance(operation, SlotEconomics):
        raise TypeError("wave1a_payment_operation_required")
    return sha3_512(
        _OPERATION_DOMAIN
        + operation.slot_index.to_bytes(2, "big")
        + (b"R" if operation.slot_kind.value == "REAL" else b"C")
        + operation.decision.to_bytes(1, "big")
        + operation.gross_allowed_cents.to_bytes(4, "big")
        + operation.patient_responsibility_cents.to_bytes(4, "big")
        + operation.plan_payable_cents.to_bytes(4, "big")
        + operation.payer_reserve_debit_cents.to_bytes(4, "big")
        + operation.provider_payable_credit_cents.to_bytes(4, "big")
    ).digest()


def _next_payment_state(
    profile: CalibrationProfile,
    before: AuthenticatedPaymentState,
    operation: SlotEconomics,
) -> AuthenticatedPaymentState:
    if before.next_slot_index != operation.slot_index:
        raise StructuralError("wave1a_payment_slot_cursor_mismatch")
    payable = operation.plan_payable_cents
    if before.payer_reserve_cents < payable:
        raise StructuralError("wave1a_payment_reserve_underflow")
    obligation = before.provider_obligation_cents + operation.provider_payable_credit_cents
    paid = before.total_paid_cents + payable
    responsibility = (
        before.patient_responsibility_cents
        + operation.patient_responsibility_cents
    )
    for label, value in (
        ("provider_obligation_cents", obligation),
        ("total_paid_cents", paid),
        ("patient_responsibility_cents", responsibility),
    ):
        _u64(label, value)
    commitment = payment_operation_commitment(operation)
    next_log = sha3_512(
        _LOG_DOMAIN
        + before.operation_log_root_sha3_512
        + before.sequence.to_bytes(8, "big")
        + operation.slot_index.to_bytes(2, "big")
        + commitment
    ).digest()
    last = operation.slot_index == profile.claim_slots - 1
    if last and before.sequence == _U64_MAX:
        raise StructuralError("wave1a_payment_sequence_overflow")
    return AuthenticatedPaymentState(
        epoch=before.epoch,
        sequence=before.sequence + 1 if last else before.sequence,
        next_slot_index=0 if last else before.next_slot_index + 1,
        payer_reserve_cents=before.payer_reserve_cents - payable,
        provider_obligation_cents=obligation,
        total_paid_cents=paid,
        patient_responsibility_cents=responsibility,
        operation_log_root_sha3_512=next_log,
    )


@dataclass(frozen=True, slots=True)
class AuthenticatedSlotPaymentTransition:
    slot_index: int
    operation: SlotEconomics
    state_before: AuthenticatedPaymentState
    state_after: AuthenticatedPaymentState
    root_before_sha3_512: bytes
    root_after_sha3_512: bytes

    def __post_init__(self) -> None:
        if type(self.slot_index) is not int or self.slot_index < 0:
            raise StructuralError("wave1a_payment_transition_slot_invalid")
        if not isinstance(self.operation, SlotEconomics):
            raise TypeError("wave1a_payment_transition_operation_required")
        if self.operation.slot_index != self.slot_index:
            raise StructuralError("wave1a_payment_transition_operation_order_invalid")
        if not isinstance(self.state_before, AuthenticatedPaymentState) or not isinstance(
            self.state_after, AuthenticatedPaymentState
        ):
            raise TypeError("wave1a_payment_transition_states_required")
        if not hmac.compare_digest(self.state_before.root(), self.root_before_sha3_512):
            raise StructuralError("wave1a_payment_transition_root_before_mismatch")
        if not hmac.compare_digest(self.state_after.root(), self.root_after_sha3_512):
            raise StructuralError("wave1a_payment_transition_root_after_mismatch")
        if hmac.compare_digest(self.root_before_sha3_512, self.root_after_sha3_512):
            raise StructuralError("wave1a_payment_transition_root_unchanged")


@dataclass(frozen=True, slots=True)
class AuthenticatedBatchPaymentTransition:
    profile_id: str
    transitions: tuple[AuthenticatedSlotPaymentTransition, ...]
    root_before_sha3_512: bytes
    root_after_sha3_512: bytes
    total_plan_payable_cents: int
    total_debits_cents: int
    total_credits_cents: int

    def __post_init__(self) -> None:
        if type(self.transitions) is not tuple or not self.transitions:
            raise StructuralError("wave1a_payment_batch_transitions_required")
        if tuple(value.slot_index for value in self.transitions) != tuple(
            range(len(self.transitions))
        ):
            raise StructuralError("wave1a_payment_batch_transition_order_invalid")
        if not hmac.compare_digest(
            self.root_before_sha3_512,
            self.transitions[0].root_before_sha3_512,
        ):
            raise StructuralError("wave1a_payment_batch_root_before_mismatch")
        if not hmac.compare_digest(
            self.root_after_sha3_512,
            self.transitions[-1].root_after_sha3_512,
        ):
            raise StructuralError("wave1a_payment_batch_root_after_mismatch")
        for left, right in zip(self.transitions, self.transitions[1:]):
            if not hmac.compare_digest(
                left.root_after_sha3_512, right.root_before_sha3_512
            ):
                raise StructuralError("wave1a_payment_batch_root_chain_mismatch")
        payable = sum(value.operation.plan_payable_cents for value in self.transitions)
        debits = sum(value.operation.payer_reserve_debit_cents for value in self.transitions)
        credits = sum(value.operation.provider_payable_credit_cents for value in self.transitions)
        if (payable, debits, credits) != (
            self.total_plan_payable_cents,
            self.total_debits_cents,
            self.total_credits_cents,
        ):
            raise StructuralError("wave1a_payment_batch_totals_mismatch")
        if payable != debits or payable != credits:
            raise StructuralError("wave1a_payment_batch_conservation_mismatch")


def build_authenticated_payment_transition(
    profile: CalibrationProfile,
    operations: Sequence[SlotEconomics],
    before: AuthenticatedPaymentState,
) -> AuthenticatedBatchPaymentTransition:
    if not isinstance(profile, CalibrationProfile):
        raise TypeError("wave1a_payment_profile_required")
    if not isinstance(before, AuthenticatedPaymentState):
        raise TypeError("wave1a_payment_before_state_required")
    materialized = tuple(operations)
    if len(materialized) != profile.claim_slots:
        raise StructuralError("wave1a_payment_operation_count_mismatch")
    if before.next_slot_index != 0:
        raise StructuralError("wave1a_payment_batch_must_start_at_slot_zero")
    transitions: list[AuthenticatedSlotPaymentTransition] = []
    current = before
    for position, operation in enumerate(materialized):
        if not isinstance(operation, SlotEconomics) or operation.slot_index != position:
            raise StructuralError("wave1a_payment_operation_order_invalid")
        after = _next_payment_state(profile, current, operation)
        transitions.append(
            AuthenticatedSlotPaymentTransition(
                position,
                operation,
                current,
                after,
                current.root(),
                after.root(),
            )
        )
        current = after
    if current.sequence != before.sequence + 1 or current.next_slot_index != 0:
        raise AssertionError("wave1a_payment_batch_finalization_invalid")
    payable = sum(value.plan_payable_cents for value in materialized)
    return AuthenticatedBatchPaymentTransition(
        profile.profile_id,
        tuple(transitions),
        transitions[0].root_before_sha3_512,
        transitions[-1].root_after_sha3_512,
        payable,
        sum(value.payer_reserve_debit_cents for value in materialized),
        sum(value.provider_payable_credit_cents for value in materialized),
    )


def verify_authenticated_payment_transition(
    profile: CalibrationProfile,
    transition: AuthenticatedBatchPaymentTransition,
) -> bool:
    if not isinstance(transition, AuthenticatedBatchPaymentTransition):
        raise TypeError("wave1a_payment_batch_transition_required")
    if transition.profile_id != profile.profile_id:
        raise StructuralError("wave1a_payment_profile_mismatch")
    observed = build_authenticated_payment_transition(
        profile,
        tuple(value.operation for value in transition.transitions),
        transition.transitions[0].state_before,
    )
    if observed != transition:
        raise StructuralError("wave1a_payment_transition_recomputation_mismatch")
    return True
