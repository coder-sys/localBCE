from __future__ import annotations

from dataclasses import replace
from hashlib import sha3_512

import pytest

from experiments.bl_pq512_crypto_foundation.selected_proof_parameters import (
    MINIMUM_TRACE_ROWS,
    QUERY_COUNT,
    SELECTED_PARAMETER_COMMITMENT,
    TRACE_MASK_COEFFICIENT_COUNT,
    derive_selected_proof_geometry,
    legacy_wide_sha3_lower_bound,
    proof_suite_id,
    selected_parameter_bytes,
)


def test_k128_legacy_wide_sha3_is_rejected_by_exact_resource_floor() -> None:
    bound = legacy_wide_sha3_lower_bound(46_858)
    assert bound.minimum_round_rows == 1_124_592
    assert bound.evaluation_rows == 33_554_432
    assert bound.main_evaluation_bytes == 229_378_097_152
    assert bound.interaction_evaluation_bytes == 2_201_170_739_200
    assert bound.combined_evaluation_bytes == 2_430_548_836_352
from experiments.fixed_shape_claim_air.semantics import StructuralError
from tests.fixtures.selected_air import selected_air_fixture


def test_selected_parameters_are_exact_and_derive_from_executable_air() -> None:
    program, _ = selected_air_fixture()
    geometry = derive_selected_proof_geometry(program)

    assert len(selected_parameter_bytes()) == 99
    assert SELECTED_PARAMETER_COMMITMENT.hex() == (
        "f92ae6507de5865a04de5f18f4f5d34aca05f21a3075644e3e58f88a0088b67"
        "a7a7500f7de81de8a29000eaa500a2b014db434a034e7aa9228ea980a13e79115"
    )
    assert QUERY_COUNT == 945
    assert TRACE_MASK_COEFFICIENT_COUNT == 4_789
    assert MINIMUM_TRACE_ROWS == 8_192
    assert geometry.maximum_evaluation_log_size == 16
    assert geometry.query_domain_size == 1 << 16
    assert geometry.fold_round_count == 15
    assert geometry.minimum_term_soundness_bits >= 256
    assert geometry.total_soundness_bits >= 256
    assert geometry.proof_suite_selected is True
    assert geometry.activation_allowed is False


def test_selected_geometry_and_suite_binding_fail_closed() -> None:
    program, _ = selected_air_fixture()
    geometry = derive_selected_proof_geometry(program)
    schedule = sha3_512(b"selected-schedule").digest()
    suite = proof_suite_id(geometry.program_binary_commitment, schedule)
    assert suite != proof_suite_id(sha3_512(b"other-program").digest(), schedule)
    assert suite != proof_suite_id(
        geometry.program_binary_commitment, sha3_512(b"other-schedule").digest()
    )
    with pytest.raises(StructuralError, match="program_commitment_invalid"):
        proof_suite_id(bytes(64), schedule)
    with pytest.raises(StructuralError, match="activation_boundary_invalid"):
        replace(geometry, activation_allowed=True)
