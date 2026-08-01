"""Synthetic-only R25 fixed-shape claim foundation."""

from .profile import CalibrationProfile, PROFILES, get_profile
from .semantics import (
    FAILURE_GATES,
    ClaimSlot,
    RevisionKind,
    ServiceLine,
    SlotKind,
    SlotResult,
    StructuralError,
    canonical_line_sort_key,
    evaluate_slot,
    require_original_attempt,
    validate_batch,
    validate_slot_shape,
)
from .trace import (
    BATCH_FINAL_OPERATION_SCHEDULE,
    PER_SLOT_OPERATION_SCHEDULE,
    LogicalTrace,
    LogicalTraceSlot,
    build_logical_trace,
)
from .replay_alignment import validate_k256_replay_alignment
from .payment import (
    BatchEconomics,
    SlotEconomics,
    derive_batch_economics,
    derive_slot_economics,
)
from .payment_state import (
    PaymentStateRootPairReference,
    StrongPaymentStateV1Reference,
    append_reference_operation_log,
    build_reference_payment_root_pair,
    decode_reference_payment_state,
    encode_reference_payment_state,
    reference_payment_state_root,
    reference_slot_operation_commitment,
)

__all__ = [
    "BATCH_FINAL_OPERATION_SCHEDULE",
    "BatchEconomics",
    "CalibrationProfile",
    "ClaimSlot",
    "FAILURE_GATES",
    "LogicalTrace",
    "LogicalTraceSlot",
    "PER_SLOT_OPERATION_SCHEDULE",
    "PaymentStateRootPairReference",
    "PROFILES",
    "RevisionKind",
    "ServiceLine",
    "SlotKind",
    "SlotEconomics",
    "SlotResult",
    "StructuralError",
    "StrongPaymentStateV1Reference",
    "append_reference_operation_log",
    "build_logical_trace",
    "build_reference_payment_root_pair",
    "canonical_line_sort_key",
    "derive_batch_economics",
    "derive_slot_economics",
    "decode_reference_payment_state",
    "encode_reference_payment_state",
    "evaluate_slot",
    "get_profile",
    "require_original_attempt",
    "reference_payment_state_root",
    "reference_slot_operation_commitment",
    "validate_batch",
    "validate_k256_replay_alignment",
    "validate_slot_shape",
]
