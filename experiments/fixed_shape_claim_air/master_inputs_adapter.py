"""Narrow fail-closed adapter from Wave 1A components to master v2 inputs."""

from __future__ import annotations

from typing import Sequence

from experiments.bl_pq512_crypto_foundation.master_commitments_v2 import (
    MasterCommitmentInputsV2,
    MasterEconomicTotalsV2,
    MasterSlotRecordV2,
)

from .a12_nullifier_executable_air import A12NullifierAirInstance
from .authenticated_payment_maps_reference import (
    AuthenticatedPaymentMapBatchTransition,
)
from .claim_truth_authority_executable_air import ClaimTruthAuthorityAirInstance
from .payment import derive_slot_economics
from .profile import CalibrationProfile
from .replay_ordered_map_executable_air import ReplayOrderedMapAirInstance
from .salt_use_tag_executable_air import SaltUseTagAirInstance
from .semantics import ClaimSlot, StructuralError, evaluate_slot


def _root(trace, prefix: str) -> bytes:
    return bytes(trace.columns[f"{prefix}_{index}"][0] for index in range(64))


def build_master_commitment_inputs_v2(
    profile: CalibrationProfile,
    slots: Sequence[ClaimSlot],
    authority: ClaimTruthAuthorityAirInstance,
    a12: A12NullifierAirInstance,
    salt_use: SaltUseTagAirInstance,
    replay: ReplayOrderedMapAirInstance,
    payment: AuthenticatedPaymentMapBatchTransition,
    *,
    epoch: int,
    strong_settlement_domain_id_512: bytes,
    strong_batch_nonce_512: bytes,
) -> MasterCommitmentInputsV2:
    materialized = tuple(slots)
    if (
        not isinstance(profile, CalibrationProfile)
        or len(materialized) != profile.claim_slots
        or not isinstance(authority, ClaimTruthAuthorityAirInstance)
        or not isinstance(a12, A12NullifierAirInstance)
        or len(a12.strong_nullifiers) != profile.claim_slots
        or not isinstance(salt_use, SaltUseTagAirInstance)
        or not isinstance(replay, ReplayOrderedMapAirInstance)
        or replay.nullifiers != (*a12.strong_nullifiers, salt_use.tag_512)
        or not isinstance(payment, AuthenticatedPaymentMapBatchTransition)
        or payment.profile_id != profile.profile_id
        or len(payment.transitions) != profile.claim_slots
    ):
        raise StructuralError("master_inputs_adapter_components_invalid")
    if (
        payment.before.epoch != epoch
        or payment.after.epoch != epoch
        or payment.before.strong_settlement_domain_id_512
        != strong_settlement_domain_id_512
        or payment.after.strong_settlement_domain_id_512
        != strong_settlement_domain_id_512
        or authority.envelope.epoch != epoch
        or authority.envelope.profile_id != profile.profile_id
    ):
        raise StructuralError("master_inputs_adapter_authority_context_mismatch")
    replay_state = replay.traces["replay_map__ordered_map_state"]
    slot_records: list[MasterSlotRecordV2] = []
    economics = []
    for index, (slot, nullifier) in enumerate(
        zip(materialized, a12.strong_nullifiers, strict=True)
    ):
        if slot.slot_index != index:
            raise StructuralError("master_inputs_adapter_slot_order_invalid")
        result = evaluate_slot(slot)
        economics.append(derive_slot_economics(slot))
        slot_records.append(
            MasterSlotRecordV2(
                slot_index=index,
                decision=result.decision,
                failure_code=result.failure_code,
                allowed_cents=result.allowed_cents,
                payment_cents=result.payment_cents,
                raw_gate_bits=sum(
                    int(bit) << position
                    for position, bit in enumerate(result.raw_gate_predicates)
                ),
                effective_gate_bits=sum(
                    int(bit) << position
                    for position, bit in enumerate(
                        result.effective_gate_predicates
                    )
                ),
                strong_nullifier_512=nullifier,
            )
        )
    totals = MasterEconomicTotalsV2(
        sum(value.gross_allowed_cents for value in economics),
        sum(value.patient_responsibility_cents for value in economics),
        sum(value.plan_payable_cents for value in economics),
        sum(value.payer_reserve_debit_cents for value in economics),
        sum(value.provider_payable_credit_cents for value in economics),
    )
    return MasterCommitmentInputsV2(
        profile_id=profile.profile_id,
        epoch=epoch,
        strong_settlement_domain_id_512=strong_settlement_domain_id_512,
        strong_batch_nonce_512=strong_batch_nonce_512,
        claim_truth_roots_512=authority.envelope.roots.ordered(),
        claim_truth_authority_digest_512=authority.envelope.message_digest,
        nullifier_authority_id_512=a12.authority_id_512,
        pepper_commitment_512=a12.pepper_commitment,
        replay_root_before_512=_root(replay_state, "root_before"),
        replay_root_after_512=_root(replay_state, "root_after"),
        payment_lane_roots_before_512=(
            payment.before.benefit_root_512,
            payment.before.obligation_root_512,
            payment.before.private_asset_ledger_root_512,
        ),
        payment_lane_roots_after_512=(
            payment.after.benefit_root_512,
            payment.after.obligation_root_512,
            payment.after.private_asset_ledger_root_512,
        ),
        operation_log_root_before_512=payment.before.operation_log_root_512,
        operation_log_root_after_512=payment.after.operation_log_root_512,
        salt_use_tag_512=salt_use.tag_512,
        economic_totals=totals,
        slots=tuple(slot_records),
    )


__all__ = ("build_master_commitment_inputs_v2",)
