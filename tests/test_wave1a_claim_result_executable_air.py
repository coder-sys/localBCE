from __future__ import annotations

from dataclasses import replace

from experiments.fixed_shape_claim_air.claim_result_executable_air import (
    build_claim_result_executable_air,
)
from experiments.fixed_shape_claim_air.executable_air import evaluate_program, evaluate_serialized
from experiments.fixed_shape_claim_air.semantics import ClaimSlot, RevisionKind, ServiceLine, SlotKind


def _line() -> ServiceLine:
    return ServiceLine(0, "LINE-A", "T1019", 100, 1, "", True, 100, False, False)


def _approved() -> ClaimSlot:
    return ClaimSlot(
        0,
        SlotKind.REAL,
        "BL-SYNTH-GOV-INTAKE-V1",
        1,
        "BL-SYNTH-CLAIM-0001",
        "SYNTH-MEMBER-001",
        "1999999984",
        1,
        RevisionKind.ORIGINAL,
        0,
        ("F840",),
        (_line(),),
        True,
        True,
        True,
        True,
        False,
        False,
        100,
        20,
        1,
        0,
        100,
        80,
    )


def _denied() -> ClaimSlot:
    return replace(
        _approved(),
        slot_index=1,
        claim_id="BL-SYNTH-CLAIM-0002",
        member_id="",
        patient_responsibility_cents=0,
        claimed_decision=0,
        claimed_failure_code=1,
        claimed_allowed_cents=0,
        claimed_payment_cents=0,
    )


def _cover() -> ClaimSlot:
    return ClaimSlot(
        2,
        SlotKind.COVER,
        "",
        0,
        "",
        "",
        "",
        0,
        RevisionKind.COVER,
        0,
        (),
        (),
        False,
        False,
        False,
        False,
        False,
        False,
        0,
        0,
        0,
        0,
        0,
        0,
    )


def test_claim_result_air_constrains_approval_denial_and_cover() -> None:
    instance = build_claim_result_executable_air((_approved(), _denied(), _cover()))
    direct = evaluate_program(instance.program, instance.traces)
    serialized = evaluate_serialized(instance.program.canonical_bytes(), instance.traces)
    assert direct == serialized
    assert direct.maximum_degree == 2
    trace = instance.traces["claim_result"].columns
    assert trace["decision"] == (1, 0, 0)
    assert trace["failure_code"] == (0, 1, 0)
    assert trace["payment_limb_0"] == (80, 0, 0)

