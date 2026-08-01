from __future__ import annotations

from dataclasses import replace

import pytest

from experiments.fixed_shape_claim_air.profile import PROFILES, get_profile
from experiments.fixed_shape_claim_air.semantics import (
    ClaimSlot,
    RevisionKind,
    ServiceLine,
    SlotKind,
    StructuralError,
)
from experiments.fixed_shape_claim_air.trace import (
    BATCH_FINAL_OPERATION_SCHEDULE,
    PER_SLOT_OPERATION_SCHEDULE,
    build_logical_trace,
)


def _real(slot_index: int, *, denied: bool = False) -> ClaimSlot:
    line = ServiceLine(
        original_line_index=0,
        line_id=f"LINE-{slot_index + 1:04d}",
        procedure_code="T1019",
        charge_cents=100,
        units_cents=1,
        prior_authorization="",
        policy_present=True,
        allowed_cents=100,
        requires_prior_authorization=False,
        authorization_present=False,
    )
    return ClaimSlot(
        slot_index=slot_index,
        slot_kind=SlotKind.REAL,
        source_authority_id="BL-SYNTH-GOV-INTAKE-V1",
        source_sequence=slot_index + 1,
        claim_id=f"BL-SYNTH-CLAIM-{slot_index + 1:04d}",
        member_id="" if denied else "SYNTH-MEMBER-001",
        provider_npi="1999999984",
        attempt_version=1,
        revision_kind=RevisionKind.ORIGINAL,
        parent_attempt_version=0,
        diagnoses=("F840",),
        service_lines=(line,),
        eligibility_active=True,
        provider_enrolled=True,
        provider_not_suspended=True,
        not_deceased=True,
        duplicate_claim=False,
        program_integrity_hold=False,
        total_charge_cents=100,
        patient_responsibility_cents=0 if denied else 20,
        claimed_decision=0 if denied else 1,
        claimed_failure_code=1 if denied else 0,
        claimed_allowed_cents=0 if denied else 100,
        claimed_payment_cents=0 if denied else 80,
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


@pytest.mark.parametrize(
    ("profile_id", "expected"),
    [
        (
            "K128_CALIBRATION",
            {
                "claim_slots": 128,
                "service_line_rows": 6_400,
                "service_line_padded_rows": 8_192,
                "diagnosis_rows": 2_048,
                "fact_rows": 768,
                "fact_padded_rows": 1_024,
                "oracle_leaves": 6_528,
                "oracle_padded_leaves": 8_192,
                "legacy_nullifier_path_nodes": 8_192,
                "strong_nullifier_path_nodes": 16_384,
                "strong_replay_transitions": 129,
            },
        ),
        (
            "K256_DESIGN_POINT",
            {
                "claim_slots": 256,
                "service_line_rows": 12_800,
                "service_line_padded_rows": 16_384,
                "diagnosis_rows": 4_096,
                "fact_rows": 1_536,
                "fact_padded_rows": 2_048,
                "oracle_leaves": 13_056,
                "oracle_padded_leaves": 16_384,
                "legacy_nullifier_path_nodes": 16_384,
                "strong_nullifier_path_nodes": 32_768,
                "strong_replay_transitions": 257,
            },
        ),
        (
            "K512_CALIBRATION",
            {
                "claim_slots": 512,
                "service_line_rows": 25_600,
                "service_line_padded_rows": 32_768,
                "diagnosis_rows": 8_192,
                "fact_rows": 3_072,
                "fact_padded_rows": 4_096,
                "oracle_leaves": 26_112,
                "oracle_padded_leaves": 32_768,
                "legacy_nullifier_path_nodes": 32_768,
                "strong_nullifier_path_nodes": 65_536,
                "strong_replay_transitions": 513,
            },
        ),
    ],
)
def test_three_profiles_have_exact_fixed_logical_dimensions(
    profile_id: str, expected: dict[str, int]
) -> None:
    dimensions = get_profile(profile_id).logical_dimensions()
    for name, value in expected.items():
        assert dimensions[name] == value


@pytest.mark.parametrize("profile_id", tuple(PROFILES))
def test_profile_dimensions_cover_every_scheduled_payment_operation(
    profile_id: str,
) -> None:
    profile = get_profile(profile_id)
    dimensions = profile.logical_dimensions()
    for name in (
        "benefit_state_path_operations",
        "obligation_state_path_operations",
        "private_asset_ledger_path_operations",
        "payment_state_transitions",
        "operation_log_appends",
    ):
        assert (name, 1) in PER_SLOT_OPERATION_SCHEDULE
        assert dimensions[name] == profile.claim_slots


def test_approval_denial_and_cover_have_identical_operation_schedules() -> None:
    profile = get_profile("K128_CALIBRATION")
    slots = [_real(0), _real(1, denied=True)]
    slots.extend(
        _cover(index) for index in range(2, profile.claim_slots)
    )
    trace = build_logical_trace(profile, slots)
    assert [slot.witness_class for slot in trace.slots[:3]] == [
        "approval",
        "denial",
        "cover",
    ]
    assert all(
        slot.operation_schedule == PER_SLOT_OPERATION_SCHEDULE
        for slot in trace.slots
    )
    assert trace.batch_final_operations == BATCH_FINAL_OPERATION_SCHEDULE
    assert trace.slots[1].failure_selector == (1,) + (0,) * 12
    assert trace.slots[0].failure_selector == (0,) * 13
    assert trace.slots[2].failure_selector == (0,) * 13
    assert trace.physical_air_rows is None
    assert trace.physical_air_columns is None


@pytest.mark.parametrize("profile_id", tuple(PROFILES))
def test_every_profile_requires_exact_k(profile_id: str) -> None:
    profile = get_profile(profile_id)
    slots = [
        _cover(index) for index in range(profile.claim_slots - 1)
    ]
    with pytest.raises(
        StructuralError, match="batch_slot_count_mismatch"
    ):
        build_logical_trace(profile, slots)


def test_real_slots_cannot_follow_cover_slots() -> None:
    profile = get_profile("K128_CALIBRATION")
    slots = [_cover(0), replace(_real(1), source_sequence=2)]
    slots.extend(
        _cover(index) for index in range(2, profile.claim_slots)
    )
    with pytest.raises(StructuralError, match="real_slot_after_cover"):
        build_logical_trace(profile, slots)
