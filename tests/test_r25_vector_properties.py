from __future__ import annotations

from dataclasses import replace

from experiments.fixed_shape_claim_air.profile import get_profile
from experiments.fixed_shape_claim_air.semantics import evaluate_slot, validate_batch
from tests.test_r25_fixed_shape_trace import _cover, _real


def _with_failure_set(slot, failed: set[int]):
    changes: dict[str, object] = {
        "patient_responsibility_cents": 0,
        "claimed_decision": 0,
        "claimed_failure_code": min(failed),
        "claimed_allowed_cents": 0,
        "claimed_payment_cents": 0,
    }
    if 1 in failed:
        changes["member_id"] = ""
    if 2 in failed:
        changes["eligibility_active"] = False
    if 3 in failed:
        changes["not_deceased"] = False
    if 4 in failed:
        changes["provider_npi"] = ""
    if 5 in failed:
        changes["provider_enrolled"] = False
    if 6 in failed:
        changes["provider_not_suspended"] = False
    if 8 in failed:
        changes["diagnoses"] = ()
    if 12 in failed:
        changes["duplicate_claim"] = True
    if 13 in failed:
        changes["program_integrity_hold"] = True
    if 7 in failed:
        changes["service_lines"] = ()
        changes["total_charge_cents"] = 0
    else:
        line = slot.service_lines[0]
        if 9 in failed:
            line = replace(
                line,
                prior_authorization="PA-1",
                requires_prior_authorization=True,
                authorization_present=False,
            )
        if 10 in failed:
            line = replace(line, charge_cents=0)
            changes["total_charge_cents"] = 0
        if 11 in failed and 9 not in failed:
            line = replace(
                line,
                policy_present=False,
                allowed_cents=0,
                requires_prior_authorization=False,
                authorization_present=False,
            )
        changes["service_lines"] = (line,)
    return replace(slot, **changes)


def test_all_8191_nonempty_failure_subsets_select_the_first_gate() -> None:
    observed = 0
    for mask in range(1, 1 << 13):
        failed = {code for code in range(1, 14) if mask & (1 << (code - 1))}
        result = evaluate_slot(_with_failure_set(_real(0), failed))
        assert result.failure_code == min(failed)
        assert result.decision == result.payment_cents == 0
        assert len(result.raw_gate_predicates) == 13
        observed += 1
    assert observed == 8191


def test_all_3840_k256_semantic_placements_are_structurally_valid() -> None:
    profile = get_profile("K256_DESIGN_POINT")
    observed = 0
    for failure_code in range(0, 14):
        for position in range(profile.claim_slots):
            slots = [_real(index) for index in range(profile.claim_slots)]
            if failure_code:
                slots[position] = _with_failure_set(
                    slots[position], {failure_code}
                )
            validate_batch(profile, slots)
            observed += 1
    for cover_boundary in range(profile.claim_slots):
        slots = [_real(index) for index in range(cover_boundary)]
        slots.extend(
            _cover(index)
            for index in range(cover_boundary, profile.claim_slots)
        )
        validate_batch(profile, slots)
        observed += 1
    assert observed == 3840
