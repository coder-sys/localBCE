from __future__ import annotations

from dataclasses import replace
import os
from unittest import mock

import pytest

from experiments.bl_pq512_crypto_foundation.scalar_state_relation_controls import (
    ACTIVATION_ALLOWED,
    CANDIDATE_IDS,
    PROFILE_CLAIM_SLOTS,
    PROOF_SUITE_ID,
    STATUS,
    ScalarRelationError,
    build_scalar_control_batch,
    evaluate_candidate,
    independently_verify_candidate,
    run_all_scalar_controls,
    scalar_parity_summary,
)
FLAGS = {
    "BL_ENV": "test",
    "BL_DEV": "1",
    "BL_ALLOW_SYNTHETIC_PQ_TREE_REFERENCE": "1",
}


@pytest.fixture(scope="module", autouse=True)
def _synthetic_environment():
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        yield


def test_scalar_controls_cover_both_profiles_and_are_independently_verified() -> None:
    for profile_id, claim_slots in PROFILE_CLAIM_SLOTS.items():
        batch = build_scalar_control_batch(profile_id)
        results = run_all_scalar_controls(batch)
        assert tuple(result.candidate_id for result in results) == CANDIDATE_IDS
        assert all(result.status == STATUS for result in results)
        assert all(result.accepted is True for result in results)
        assert all(result.profile_id == profile_id for result in results)
        assert all(result.claim_slots == claim_slots for result in results)
        assert len({result.semantic_digest_512 for result in results}) == 1
        assert len({result.economic_digest_512 for result in results}) == 1
        for result in results:
            independently_verify_candidate(result.candidate_id, batch, result)
            summary = scalar_parity_summary(batch, result)
            assert summary["claim_slots"] == claim_slots
            assert summary["map_geometry"] == (
                ("replay", claim_slots + 1, 2 * (claim_slots + 1), claim_slots + 2),
                ("benefit", claim_slots, 2 * claim_slots, 4),
                ("obligation", claim_slots, 2 * claim_slots, 3),
                ("ledger", 2 * claim_slots, 4 * claim_slots, 5),
            )
            assert summary["membership_absence"] == (
                ("replay", True, True),
                ("benefit", True, True),
                ("obligation", True, True),
                ("ledger", True, True),
            )
            assert summary["case_outcomes"] == (
                ("approved", "accepted", "0"),
                ("duplicate", "denied", "12"),
                ("conflict", "denied", "13"),
                ("denial", "denied", "1"),
                ("cover", "cover", "0"),
                ("correction", "rejected", "r25_revision_not_authorized"),
            )
            assert summary["money"] == (80, 80, 80)


def test_scalar_controls_expose_derived_candidate_risk_without_claiming_measurements() -> None:
    batch = build_scalar_control_batch("K128_CALIBRATION")
    results = {result.candidate_id: result for result in run_all_scalar_controls(batch)}
    assert results["C1_DENSE"].candidate_work_units > results["C1_SPARSE"].candidate_work_units
    assert all(
        lane.candidate_requires_persistent_scan
        for lane in results["C1_DENSE"].lanes
    )
    assert all(not lane.candidate_requires_persistent_scan for lane in results["C1_SPARSE"].lanes)
    assert all(
        lane.candidate_online_work_units == len(lane.touched_keys) ** 2
        for lane in results["C3"].lanes
    )
    assert all(lane.candidate_requires_persistent_scan for lane in results["C4"].lanes)
    permutation = results["C4"].lanes[0].shuffle_permutation
    assert set(permutation) == set(range(len(permutation)))
    assert results["C4"].lanes[0].shuffle_challenge_512 != b"\x00" * 64


def test_result_root_mutation_is_rejected_by_independent_verifier() -> None:
    batch = build_scalar_control_batch("K128_CALIBRATION")
    result = evaluate_candidate("C2", batch)
    forged_lane = replace(
        result.lanes[0],
        state_root_before_512=b"\x01" * 64,
    )
    forged = replace(result, lanes=(forged_lane, *result.lanes[1:]))
    with pytest.raises(ScalarRelationError, match="s2_verifier_state_root_before_512_mismatch"):
        independently_verify_candidate("C2", batch, forged)


def test_scalar_control_is_fail_closed_outside_explicit_synthetic_environment() -> None:
    with mock.patch.dict(
        os.environ,
        {**FLAGS, "BL_ENV": "production"},
        clear=False,
    ):
        with pytest.raises(RuntimeError, match="synthetic_pq_tree_reference_forbidden"):
            build_scalar_control_batch("K128_CALIBRATION")
    assert PROOF_SUITE_ID is None
    assert ACTIVATION_ALLOWED is False
