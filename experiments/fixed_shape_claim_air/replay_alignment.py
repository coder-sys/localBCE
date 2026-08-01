"""K256 logical slot/replay alignment; not a tree or hash construction."""

from __future__ import annotations

from typing import Sequence

from app.batch.pq_replay_schedule_r25 import (
    SLOT_OPERATION_COUNT,
    FixedReplaySchedule,
    ReplayOperationKind,
    validate_fixed_replay_operations,
)

from .profile import CalibrationProfile
from .semantics import ClaimSlot, SlotKind, StructuralError, validate_batch


def validate_k256_replay_alignment(
    profile: CalibrationProfile,
    slots: Sequence[ClaimSlot],
    schedule: FixedReplaySchedule,
) -> None:
    """Bind each logical claim kind to its position-matched replay operation.

    Replay keys remain opaque 512-bit synthetic inputs.  This function does not
    derive a nullifier, build a tree, authenticate a root, or qualify a hash.
    """

    materialized = tuple(slots)
    validate_batch(profile, materialized)
    if profile.profile_id != "K256_DESIGN_POINT" or profile.claim_slots != SLOT_OPERATION_COUNT:
        raise StructuralError("r25_replay_alignment_requires_k256")
    if not isinstance(schedule, FixedReplaySchedule):
        raise StructuralError("r25_replay_schedule_type_invalid")
    operations = validate_fixed_replay_operations(schedule.operations)
    for slot, operation in zip(
        materialized,
        operations[:SLOT_OPERATION_COUNT],
        strict=True,
    ):
        expected_kind = (
            ReplayOperationKind.ATTEMPT_NULLIFIER
            if slot.slot_kind is SlotKind.REAL
            else ReplayOperationKind.COVER_NULLIFIER
        )
        if operation.position != slot.slot_index:
            raise StructuralError("r25_replay_slot_position_mismatch")
        if operation.kind is not expected_kind:
            raise StructuralError("r25_replay_slot_kind_mismatch")
        if slot.slot_kind is SlotKind.REAL and (
            operation.attempt_version != slot.attempt_version
            or operation.revision_kind != slot.revision_kind.value
            or operation.parent_attempt_version != slot.parent_attempt_version
        ):
            raise StructuralError("r25_replay_revision_binding_mismatch")
