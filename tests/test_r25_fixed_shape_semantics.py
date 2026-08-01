from __future__ import annotations

from dataclasses import replace

import pytest

from experiments.fixed_shape_claim_air.semantics import (
    FAILURE_GATES,
    ClaimSlot,
    RevisionKind,
    ServiceLine,
    SlotKind,
    StructuralError,
    evaluate_slot,
    validate_batch,
    validate_slot_shape,
)
from experiments.fixed_shape_claim_air.profile import get_profile


def _line(
    line_id: str = "LINE-A",
    *,
    original_line_index: int = 0,
) -> ServiceLine:
    return ServiceLine(
        original_line_index=original_line_index,
        line_id=line_id,
        procedure_code="T1019",
        charge_cents=100,
        units_cents=1,
        prior_authorization="",
        policy_present=True,
        allowed_cents=100,
        requires_prior_authorization=False,
        authorization_present=False,
    )


def _approved(
    slot_index: int = 0, *, line: ServiceLine | None = None
) -> ClaimSlot:
    selected = line or _line()
    allowed = min(selected.charge_cents, selected.allowed_cents)
    return ClaimSlot(
        slot_index=slot_index,
        slot_kind=SlotKind.REAL,
        source_authority_id="BL-SYNTH-GOV-INTAKE-V1",
        source_sequence=slot_index + 1,
        claim_id=f"BL-SYNTH-CLAIM-{slot_index + 1:04d}",
        member_id="SYNTH-MEMBER-001",
        provider_npi="1999999984",
        attempt_version=1,
        revision_kind=RevisionKind.ORIGINAL,
        parent_attempt_version=0,
        diagnoses=("F840",),
        service_lines=(selected,),
        eligibility_active=True,
        provider_enrolled=True,
        provider_not_suspended=True,
        not_deceased=True,
        duplicate_claim=False,
        program_integrity_hold=False,
        total_charge_cents=selected.charge_cents,
        patient_responsibility_cents=20,
        claimed_decision=1,
        claimed_failure_code=0,
        claimed_allowed_cents=allowed,
        claimed_payment_cents=allowed - 20,
    )


def _denied(slot: ClaimSlot, code: int, **changes: object) -> ClaimSlot:
    return replace(
        slot,
        patient_responsibility_cents=0,
        claimed_decision=0,
        claimed_failure_code=code,
        claimed_allowed_cents=0,
        claimed_payment_cents=0,
        **changes,
    )


def _cover(slot_index: int) -> ClaimSlot:
    return ClaimSlot(
        slot_index=slot_index,
        slot_kind=SlotKind.COVER,
        source_authority_id="",
        source_sequence=0,
        claim_id="",
        member_id="",
        provider_npi="",
        attempt_version=0,
        revision_kind=RevisionKind.COVER,
        parent_attempt_version=0,
        diagnoses=(),
        service_lines=(),
        eligibility_active=False,
        provider_enrolled=False,
        provider_not_suspended=False,
        not_deceased=False,
        duplicate_claim=False,
        program_integrity_hold=False,
        total_charge_cents=0,
        patient_responsibility_cents=0,
        claimed_decision=0,
        claimed_failure_code=0,
        claimed_allowed_cents=0,
        claimed_payment_cents=0,
    )


def test_exact_thirteen_gate_order_and_plan_payable() -> None:
    assert [gate.code for gate in FAILURE_GATES] == list(range(1, 14))
    result = evaluate_slot(_approved())
    assert (
        result.decision,
        result.failure_code,
        result.allowed_cents,
        result.payment_cents,
    ) == (1, 0, 100, 80)
    assert result.effective_gate_predicates == (True,) * 13


@pytest.mark.parametrize(
    ("code", "mutator"),
    [
        (1, lambda slot: _denied(slot, 1, member_id="")),
        (2, lambda slot: _denied(slot, 2, eligibility_active=False)),
        (3, lambda slot: _denied(slot, 3, not_deceased=False)),
        (4, lambda slot: _denied(slot, 4, provider_npi="")),
        (5, lambda slot: _denied(slot, 5, provider_enrolled=False)),
        (
            6,
            lambda slot: _denied(
                slot, 6, provider_not_suspended=False
            ),
        ),
        (
            7,
            lambda slot: _denied(
                slot, 7, service_lines=(), total_charge_cents=0
            ),
        ),
        (8, lambda slot: _denied(slot, 8, diagnoses=())),
        (
            9,
            lambda slot: _denied(
                slot,
                9,
                service_lines=(
                    replace(
                        slot.service_lines[0],
                        prior_authorization="PA-1",
                        requires_prior_authorization=True,
                    ),
                ),
            ),
        ),
        (
            10,
            lambda slot: _denied(
                slot,
                10,
                service_lines=(
                    replace(slot.service_lines[0], charge_cents=0),
                ),
                total_charge_cents=0,
            ),
        ),
        (
            11,
            lambda slot: _denied(
                slot,
                11,
                service_lines=(
                    replace(
                        slot.service_lines[0],
                        policy_present=False,
                        allowed_cents=0,
                    ),
                ),
            ),
        ),
        (12, lambda slot: _denied(slot, 12, duplicate_claim=True)),
        (
            13,
            lambda slot: _denied(
                slot, 13, program_integrity_hold=True
            ),
        ),
    ],
)
def test_each_private_denial_uses_exact_first_code(
    code: int, mutator
) -> None:
    result = evaluate_slot(mutator(_approved()))
    assert (
        result.decision,
        result.failure_code,
        result.payment_cents,
    ) == (0, code, 0)


def test_multiple_failures_select_first_without_early_semantic_exit() -> None:
    slot = _denied(
        _approved(),
        1,
        member_id="",
        eligibility_active=False,
        provider_enrolled=False,
        program_integrity_hold=True,
    )
    result = evaluate_slot(slot)
    assert result.failure_code == 1
    assert len(result.raw_gate_predicates) == 13
    assert result.raw_gate_predicates[0] is False
    assert result.raw_gate_predicates[1] is False
    assert result.raw_gate_predicates[4] is False
    assert result.raw_gate_predicates[12] is False


def test_cover_has_reserved_result_but_all_effective_gates_execute() -> None:
    result = evaluate_slot(_cover(0))
    assert (
        result.decision,
        result.failure_code,
        result.allowed_cents,
    ) == (0, 0, 0)
    assert len(result.raw_gate_predicates) == 13
    assert result.effective_gate_predicates == (True,) * 13


@pytest.mark.parametrize(
    ("field_name", "falsey_impostor"),
    [
        ("source_authority_id", 0),
        ("source_sequence", False),
        ("claim_id", []),
        ("member_id", None),
        ("provider_npi", ()),
        ("attempt_version", False),
        ("parent_attempt_version", False),
        ("diagnoses", []),
        ("service_lines", []),
        ("total_charge_cents", False),
    ],
)
def test_cover_rejects_falsey_noncanonical_types(
    field_name: str, falsey_impostor: object
) -> None:
    with pytest.raises(StructuralError, match="cover_payload_not_canonical"):
        validate_slot_shape(
            replace(_cover(0), **{field_name: falsey_impostor})
        )


def test_exact_duplicate_attempt_identity_is_structural_replay_error() -> None:
    profile = get_profile("K128_CALIBRATION")
    first = _approved(0)
    duplicate = replace(first, slot_index=1)
    slots = [first, duplicate]
    slots.extend(_cover(index) for index in range(2, profile.claim_slots))
    with pytest.raises(StructuralError, match="duplicate_attempt_identity"):
        validate_batch(profile, slots)


def test_malformed_batch_slot_uses_stable_structural_error() -> None:
    profile = get_profile("K128_CALIBRATION")
    slots: list[object] = [object()]
    slots.extend(_cover(index) for index in range(1, profile.claim_slots))
    with pytest.raises(StructuralError, match="slot_type_invalid"):
        validate_batch(profile, slots)  # type: ignore[arg-type]


def test_real_claims_are_original_attempt_only() -> None:
    with pytest.raises(StructuralError, match="revision_not_authorized"):
        validate_slot_shape(
            replace(
                _approved(),
                attempt_version=2,
                revision_kind=RevisionKind.CORRECTION,
                parent_attempt_version=1,
            )
        )


def test_line_id_is_the_final_canonical_tiebreaker() -> None:
    line_a = _line("LINE-A", original_line_index=1)
    line_b = _line("LINE-B", original_line_index=0)
    canonical = replace(
        _approved(line=line_a),
        service_lines=(line_a, line_b),
        total_charge_cents=200,
        claimed_allowed_cents=200,
        claimed_payment_cents=180,
    )
    validate_slot_shape(canonical)
    with pytest.raises(
        StructuralError, match="service_lines_not_canonical_order"
    ):
        validate_slot_shape(
            replace(canonical, service_lines=(line_b, line_a))
        )


def test_patient_responsibility_cannot_exceed_allowed_or_affect_denial() -> None:
    with pytest.raises(
        StructuralError, match="patient_responsibility_exceeds_allowed"
    ):
        validate_slot_shape(
            replace(
                _approved(),
                patient_responsibility_cents=101,
                claimed_payment_cents=0,
            )
        )
    with pytest.raises(
        StructuralError,
        match="denied_patient_responsibility_must_be_zero",
    ):
        validate_slot_shape(
            replace(
                _denied(_approved(), 2, eligibility_active=False),
                patient_responsibility_cents=1,
            )
        )
