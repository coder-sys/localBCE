"""Synthetic-only fixed-shape semantic reference.

This module defines logical semantics, not an AIR or cryptographic security.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
from typing import Final, Sequence

from .profile import DIAGNOSES_PER_CLAIM, SERVICE_LINES_PER_CLAIM


UINT32_MAX: Final[int] = (1 << 32) - 1
UINT64_MAX: Final[int] = (1 << 64) - 1
_TOKEN = re.compile(r"^[A-Z0-9][A-Z0-9-]{0,63}$")
_PROCEDURE = re.compile(r"^[A-Z0-9]{2,10}$")
_DIAGNOSIS = re.compile(r"^[A-Z0-9.]{1,16}$")
_TOKEN_FIRST_ORDER: Final[dict[str, int]] = {
    value: index for index, value in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
}
_TOKEN_TAIL_ORDER: Final[dict[str, int]] = {
    value: index for index, value in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-")
}


class StructuralError(ValueError):
    """A malformed witness, distinct from a valid private denial."""


class SlotKind(str, Enum):
    REAL = "REAL"
    COVER = "COVER"


class RevisionKind(str, Enum):
    ORIGINAL = "ORIGINAL"
    COVER = "COVER"
    CORRECTION = "CORRECTION"
    REPLACEMENT = "REPLACEMENT"
    VOID = "VOID"


@dataclass(frozen=True, slots=True)
class GateDefinition:
    code: int
    gate_id: str
    reason: str


FAILURE_GATES: Final[tuple[GateDefinition, ...]] = (
    GateDefinition(1, "G1_MEMBER_ID_PRESENT", "member_id_missing"),
    GateDefinition(2, "G2_ELIGIBILITY_ACTIVE", "eligibility_inactive"),
    GateDefinition(3, "G2B_PATIENT_NOT_DECEASED", "patient_deceased"),
    GateDefinition(4, "G3_PROVIDER_NPI_PRESENT", "provider_npi_missing"),
    GateDefinition(5, "G4_PROVIDER_ENROLLED", "provider_not_enrolled"),
    GateDefinition(6, "G4B_PROVIDER_NOT_SUSPENDED", "provider_suspended"),
    GateDefinition(7, "G5_SERVICE_LINES_PRESENT", "service_line_missing"),
    GateDefinition(8, "G6_DIAGNOSIS_PRESENT", "diagnosis_missing"),
    GateDefinition(
        9, "G7_PRIOR_AUTH_WHEN_REQUIRED", "prior_authorization_required"
    ),
    GateDefinition(10, "G8A_CHARGE_VALID", "invalid_charge"),
    GateDefinition(11, "G8B_FEE_SCHEDULE_PRESENT", "fee_schedule_missing"),
    GateDefinition(12, "G9_NOT_DUPLICATE", "duplicate_claim"),
    GateDefinition(
        13, "G10_NO_PROGRAM_INTEGRITY_HOLD", "program_integrity_hold"
    ),
)


@dataclass(frozen=True, slots=True)
class ServiceLine:
    original_line_index: int
    line_id: str
    procedure_code: str
    charge_cents: int
    units_cents: int
    prior_authorization: str
    policy_present: bool
    allowed_cents: int
    requires_prior_authorization: bool
    authorization_present: bool


@dataclass(frozen=True, slots=True)
class ClaimSlot:
    slot_index: int
    slot_kind: SlotKind
    source_authority_id: str
    source_sequence: int
    claim_id: str
    member_id: str
    provider_npi: str
    attempt_version: int
    revision_kind: RevisionKind
    parent_attempt_version: int
    diagnoses: tuple[str, ...]
    service_lines: tuple[ServiceLine, ...]
    eligibility_active: bool
    provider_enrolled: bool
    provider_not_suspended: bool
    not_deceased: bool
    duplicate_claim: bool
    program_integrity_hold: bool
    total_charge_cents: int
    patient_responsibility_cents: int
    claimed_decision: int
    claimed_failure_code: int
    claimed_allowed_cents: int
    claimed_payment_cents: int


@dataclass(frozen=True, slots=True)
class SlotResult:
    decision: int
    failure_code: int
    allowed_cents: int
    payment_cents: int
    raw_gate_predicates: tuple[bool, ...]
    effective_gate_predicates: tuple[bool, ...]


def _integer(label: str, value: object, maximum: int) -> int:
    if type(value) is not int or value < 0 or value > maximum:
        raise StructuralError(f"r25_{label}_out_of_range")
    return value


def _boolean(label: str, value: object) -> bool:
    if type(value) is not bool:
        raise StructuralError(f"r25_{label}_not_boolean")
    return value


def _ascii_key(
    value: str,
    *,
    label: str,
    allow_empty: bool = False,
    maximum: int = 64,
) -> tuple[int, bytes]:
    if type(value) is not str:
        raise StructuralError(f"r25_{label}_not_text")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise StructuralError(f"r25_{label}_not_ascii") from exc
    if (not allow_empty and not encoded) or len(encoded) > maximum:
        raise StructuralError(f"r25_{label}_length_invalid")
    return len(encoded), encoded


def _token(value: str, *, label: str, allow_empty: bool = False) -> None:
    _ascii_key(value, label=label, allow_empty=allow_empty)
    if value == "" and allow_empty:
        return
    if _TOKEN.fullmatch(value) is None:
        raise StructuralError(f"r25_{label}_not_canonical_token")


def _npi_check_digit_ok(value: str) -> bool:
    if len(value) != 10 or not value.isascii() or not value.isdigit():
        return False
    payload = f"80840{value[:9]}"
    total = 0
    for index, character in enumerate(reversed(payload)):
        digit = int(character)
        if index % 2 == 0:
            doubled = digit * 2
            total += doubled // 10 + doubled % 10
        else:
            total += digit
    return (10 - total % 10) % 10 == int(value[9])


def canonical_line_sort_key(
    line: ServiceLine,
) -> tuple[
    tuple[int, bytes], int, int, tuple[int, tuple[int, ...]], tuple[int, tuple[int, ...]]
]:
    """Return the exact key with line_id as the deterministic final tie-breaker."""

    return (
        _ascii_key(
            line.procedure_code, label="procedure_code", maximum=10
        ),
        _integer("line_charge_cents", line.charge_cents, UINT32_MAX),
        _integer("line_units_cents", line.units_cents, UINT32_MAX),
        canonical_token_rank_sort_key(line.prior_authorization, allow_empty=True),
        canonical_token_rank_sort_key(line.line_id),
    )


def canonical_token_rank_sort_key(
    value: str, *, allow_empty: bool = False
) -> tuple[int, tuple[int, ...]]:
    """Order tokens exactly as their unique base-37 rank encoding orders them."""

    _token(value, label="canonical_sort_token", allow_empty=allow_empty)
    if not value:
        return (0, ())
    return (
        len(value),
        (
            _TOKEN_FIRST_ORDER[value[0]],
            *(_TOKEN_TAIL_ORDER[character] for character in value[1:]),
        ),
    )


def canonical_claim_sort_key(
    slot: ClaimSlot,
) -> tuple[tuple[int, bytes], int, int, str, tuple[int, bytes]]:
    return (
        _ascii_key(
            slot.source_authority_id, label="source_authority_id"
        ),
        _integer("source_sequence", slot.source_sequence, UINT64_MAX),
        _integer("attempt_version", slot.attempt_version, UINT32_MAX),
        slot.revision_kind.value,
        _ascii_key(slot.claim_id, label="claim_id"),
    )


def require_original_attempt(slot: ClaimSlot) -> None:
    if slot.slot_kind is not SlotKind.REAL:
        raise StructuralError("r25_original_attempt_requires_real_slot")
    if (
        slot.attempt_version != 1
        or slot.revision_kind is not RevisionKind.ORIGINAL
        or slot.parent_attempt_version != 0
    ):
        raise StructuralError("r25_revision_not_authorized")


def _checked_u32_sum(label: str, values: Sequence[int]) -> int:
    total = 0
    for value in values:
        total += _integer(label, value, UINT32_MAX)
        if total > UINT32_MAX:
            raise StructuralError(f"r25_{label}_aggregate_overflow")
    return total


def _validate_line(line: ServiceLine) -> None:
    if not isinstance(line, ServiceLine):
        raise StructuralError("r25_service_line_type_invalid")
    _integer(
        "original_line_index",
        line.original_line_index,
        SERVICE_LINES_PER_CLAIM - 1,
    )
    _token(line.line_id, label="line_id")
    if _PROCEDURE.fullmatch(line.procedure_code) is None:
        raise StructuralError("r25_procedure_code_not_canonical")
    _integer("line_charge_cents", line.charge_cents, UINT32_MAX)
    _integer("line_units_cents", line.units_cents, UINT32_MAX)
    _token(
        line.prior_authorization,
        label="prior_authorization",
        allow_empty=True,
    )
    _boolean("policy_present", line.policy_present)
    _integer("allowed_cents", line.allowed_cents, UINT32_MAX)
    _boolean(
        "requires_prior_authorization",
        line.requires_prior_authorization,
    )
    _boolean("authorization_present", line.authorization_present)
    if not line.policy_present and (
        line.allowed_cents != 0
        or line.requires_prior_authorization
        or line.authorization_present
    ):
        raise StructuralError("r25_absent_policy_row_not_canonical")
    if line.authorization_present and not line.prior_authorization:
        raise StructuralError(
            "r25_authenticated_authorization_token_missing"
        )


def _validate_cover(slot: ClaimSlot) -> None:
    if (
        type(slot.source_authority_id) is not str
        or slot.source_authority_id != ""
        or type(slot.source_sequence) is not int
        or slot.source_sequence != 0
        or type(slot.claim_id) is not str
        or slot.claim_id != ""
        or type(slot.member_id) is not str
        or slot.member_id != ""
        or type(slot.provider_npi) is not str
        or slot.provider_npi != ""
        or type(slot.attempt_version) is not int
        or slot.attempt_version != 0
        or slot.revision_kind is not RevisionKind.COVER
        or type(slot.parent_attempt_version) is not int
        or slot.parent_attempt_version != 0
        or type(slot.diagnoses) is not tuple
        or slot.diagnoses != ()
        or type(slot.service_lines) is not tuple
        or slot.service_lines != ()
        or slot.eligibility_active
        or slot.provider_enrolled
        or slot.provider_not_suspended
        or slot.not_deceased
        or slot.duplicate_claim
        or slot.program_integrity_hold
        or type(slot.total_charge_cents) is not int
        or slot.total_charge_cents != 0
        or slot.patient_responsibility_cents != 0
    ):
        raise StructuralError("r25_cover_payload_not_canonical")


def _validate_slot_shape_only(slot: ClaimSlot) -> None:
    if not isinstance(slot, ClaimSlot):
        raise StructuralError("r25_slot_type_invalid")
    _integer("slot_index", slot.slot_index, 511)
    if type(slot.slot_kind) is not SlotKind:
        raise StructuralError("r25_slot_kind_invalid")
    for field_name in (
        "eligibility_active",
        "provider_enrolled",
        "provider_not_suspended",
        "not_deceased",
        "duplicate_claim",
        "program_integrity_hold",
    ):
        _boolean(field_name, getattr(slot, field_name))
    for label, value in (
        ("claimed_decision", slot.claimed_decision),
        ("claimed_failure_code", slot.claimed_failure_code),
        ("claimed_allowed_cents", slot.claimed_allowed_cents),
        ("claimed_payment_cents", slot.claimed_payment_cents),
    ):
        maximum = (
            1
            if label == "claimed_decision"
            else 13
            if label == "claimed_failure_code"
            else UINT32_MAX
        )
        _integer(label, value, maximum)
    _integer(
        "patient_responsibility_cents",
        slot.patient_responsibility_cents,
        UINT32_MAX,
    )
    if slot.slot_kind is SlotKind.COVER:
        _validate_cover(slot)
        return
    require_original_attempt(slot)
    _token(slot.source_authority_id, label="source_authority_id")
    _token(slot.claim_id, label="claim_id")
    _token(slot.member_id, label="member_id", allow_empty=True)
    _integer("source_sequence", slot.source_sequence, UINT64_MAX)
    if slot.source_sequence == 0:
        raise StructuralError("r25_source_sequence_zero")
    if slot.provider_npi and not _npi_check_digit_ok(slot.provider_npi):
        raise StructuralError("r25_provider_npi_not_canonical")
    diagnoses = tuple(slot.diagnoses)
    if len(diagnoses) > DIAGNOSES_PER_CLAIM:
        raise StructuralError("r25_diagnosis_capacity_exceeded")
    for diagnosis in diagnoses:
        if (
            type(diagnosis) is not str
            or _DIAGNOSIS.fullmatch(diagnosis) is None
        ):
            raise StructuralError("r25_diagnosis_not_canonical")
    expected_diagnoses = tuple(
        sorted(
            diagnoses,
            key=lambda value: _ascii_key(
                value, label="diagnosis", maximum=16
            ),
        )
    )
    if diagnoses != expected_diagnoses:
        raise StructuralError("r25_diagnoses_not_canonical_order")
    if len(set(diagnoses)) != len(diagnoses):
        raise StructuralError("r25_diagnosis_duplicate")
    lines = tuple(slot.service_lines)
    if len(lines) > SERVICE_LINES_PER_CLAIM:
        raise StructuralError("r25_service_line_capacity_exceeded")
    for line in lines:
        _validate_line(line)
    if lines != tuple(sorted(lines, key=canonical_line_sort_key)):
        raise StructuralError("r25_service_lines_not_canonical_order")
    line_ids = [line.line_id for line in lines]
    if len(set(line_ids)) != len(line_ids):
        raise StructuralError("r25_service_line_id_duplicate")
    original_indices = [line.original_line_index for line in lines]
    if len(set(original_indices)) != len(original_indices):
        raise StructuralError("r25_original_line_index_duplicate")
    charge_sum = _checked_u32_sum(
        "line_charge_cents", [line.charge_cents for line in lines]
    )
    _integer("total_charge_cents", slot.total_charge_cents, UINT32_MAX)
    if charge_sum != slot.total_charge_cents:
        raise StructuralError("r25_claim_total_mismatch")


def _evaluate_unchecked(slot: ClaimSlot) -> SlotResult:
    lines = tuple(slot.service_lines)
    raw = (
        bool(slot.member_id),
        slot.eligibility_active,
        slot.not_deceased,
        bool(slot.provider_npi),
        slot.provider_enrolled,
        slot.provider_not_suspended,
        bool(lines),
        bool(slot.diagnoses),
        all(
            (not line.requires_prior_authorization)
            or line.authorization_present
            for line in lines
        ),
        (
            bool(lines)
            and slot.total_charge_cents > 0
            and all(
                line.charge_cents > 0 and line.units_cents > 0
                for line in lines
            )
        ),
        all(line.policy_present for line in lines),
        not slot.duplicate_claim,
        not slot.program_integrity_hold,
    )
    effective = (
        tuple(True for _ in FAILURE_GATES)
        if slot.slot_kind is SlotKind.COVER
        else raw
    )
    failure_code = next(
        (
            gate.code
            for gate, passed in zip(FAILURE_GATES, effective, strict=True)
            if not passed
        ),
        0,
    )
    decision = int(
        slot.slot_kind is SlotKind.REAL and failure_code == 0
    )
    candidate_allowed = _checked_u32_sum(
        "allowed_cents",
        [
            min(line.charge_cents, line.allowed_cents)
            if line.policy_present
            else 0
            for line in lines
        ],
    )
    responsibility = slot.patient_responsibility_cents
    if responsibility > candidate_allowed:
        raise StructuralError(
            "r25_patient_responsibility_exceeds_allowed"
        )
    if decision == 0 and responsibility != 0:
        raise StructuralError(
            "r25_denied_patient_responsibility_must_be_zero"
        )
    allowed = candidate_allowed if decision else 0
    payment = allowed - responsibility if decision else 0
    return SlotResult(
        decision,
        failure_code,
        allowed,
        payment,
        raw,
        effective,
    )


def validate_slot_shape(slot: ClaimSlot) -> None:
    _validate_slot_shape_only(slot)
    result = _evaluate_unchecked(slot)
    claimed = (
        slot.claimed_decision,
        slot.claimed_failure_code,
        slot.claimed_allowed_cents,
        slot.claimed_payment_cents,
    )
    observed = (
        result.decision,
        result.failure_code,
        result.allowed_cents,
        result.payment_cents,
    )
    if claimed != observed:
        raise StructuralError("r25_claimed_result_mismatch")


def evaluate_slot(slot: ClaimSlot) -> SlotResult:
    validate_slot_shape(slot)
    return _evaluate_unchecked(slot)


def validate_batch(profile: object, slots: Sequence[ClaimSlot]) -> None:
    from .profile import CalibrationProfile

    if not isinstance(profile, CalibrationProfile):
        raise StructuralError("r25_profile_type_invalid")
    materialized = tuple(slots)
    if len(materialized) != profile.claim_slots:
        raise StructuralError("r25_batch_slot_count_mismatch")
    seen_cover = False
    real_slots: list[ClaimSlot] = []
    for expected_index, slot in enumerate(materialized):
        if not isinstance(slot, ClaimSlot):
            raise StructuralError("r25_slot_type_invalid")
        if slot.slot_index != expected_index:
            raise StructuralError("r25_slot_index_mismatch")
        validate_slot_shape(slot)
        if slot.slot_kind is SlotKind.COVER:
            seen_cover = True
        else:
            if seen_cover:
                raise StructuralError("r25_real_slot_after_cover")
            real_slots.append(slot)
    if real_slots != sorted(real_slots, key=canonical_claim_sort_key):
        raise StructuralError("r25_real_claims_not_canonical_order")
    attempt_identities = tuple(
        canonical_claim_sort_key(slot) for slot in real_slots
    )
    if len(set(attempt_identities)) != len(attempt_identities):
        raise StructuralError("r25_duplicate_attempt_identity")
