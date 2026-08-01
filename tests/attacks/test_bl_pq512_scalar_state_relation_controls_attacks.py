from __future__ import annotations

from dataclasses import replace
import os
from unittest import mock

import pytest

from experiments.bl_pq512_crypto_foundation.scalar_state_relation_controls import (
    CANDIDATE_IDS,
    ScalarRelationError,
    build_scalar_control_batch,
    build_scalar_negative_corpus,
    evaluate_candidate,
    independently_verify_candidate,
    verify_negative_case,
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


@pytest.mark.parametrize("profile_id", ("K128_CALIBRATION", "K512_CALIBRATION"))
def test_every_c0_negative_case_rejects_for_every_scalar_candidate(profile_id: str) -> None:
    cases = build_scalar_negative_corpus(profile_id)
    assert {case.name for case in cases} == {
        "stale_read",
        "omitted_write",
        "reordered_write",
        "duplicate_identity",
        "collision",
        "conflicting_update",
        "root_substitution",
    }
    for case in cases:
        for candidate_id in CANDIDATE_IDS:
            rejection = verify_negative_case(candidate_id, case)
            assert rejection


@pytest.mark.parametrize(
    ("candidate_id", "field_name"),
    (
        ("C1_DENSE", "candidate_payload_digest_512"),
        ("C1_SPARSE", "touched_keys"),
        ("C2", "dictionary_rows"),
        ("C3", "projection_positions"),
        ("C4", "shuffle_permutation"),
        ("C4", "shuffle_digest_512"),
    ),
)
def test_candidate_specific_witness_mutations_are_not_accepted(
    candidate_id: str,
    field_name: str,
) -> None:
    batch = build_scalar_control_batch("K128_CALIBRATION")
    result = evaluate_candidate(candidate_id, batch)
    lane = result.lanes[0]
    if field_name == "candidate_payload_digest_512":
        forged_lane = replace(lane, candidate_payload_digest_512=b"\x02" * 64)
    elif field_name == "touched_keys":
        forged_lane = replace(lane, touched_keys=tuple(reversed(lane.touched_keys)))
    elif field_name == "dictionary_rows":
        forged_lane = replace(lane, dictionary_rows=tuple(reversed(lane.dictionary_rows)))
    elif field_name == "projection_positions":
        forged_lane = replace(lane, projection_positions=tuple(reversed(lane.projection_positions)))
    elif field_name == "shuffle_permutation":
        forged_lane = replace(lane, shuffle_permutation=tuple(reversed(lane.shuffle_permutation)))
    else:
        forged_lane = replace(lane, shuffle_digest_512=b"\x03" * 64)
    forged = replace(result, lanes=(forged_lane, *result.lanes[1:]))
    with pytest.raises(ScalarRelationError, match="s2_verifier_"):
        independently_verify_candidate(candidate_id, batch, forged)


def test_malformed_outcome_and_state_shapes_fail_closed() -> None:
    batch = build_scalar_control_batch("K128_CALIBRATION")
    with pytest.raises(ScalarRelationError, match="s2_slot_order_mismatch"):
        from dataclasses import replace

        independently_verify_candidate(
            "C1_SPARSE",
            replace(batch, outcomes=tuple(reversed(batch.outcomes))),
            evaluate_candidate("C1_SPARSE", batch),
        )
