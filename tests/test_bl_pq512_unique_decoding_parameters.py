from __future__ import annotations

import os
import json
from pathlib import Path

import pytest

os.environ.setdefault("BL_ENV", "test")
os.environ.setdefault("BL_DEV", "1")
os.environ.setdefault("BL_ALLOW_SYNTHETIC_PQ_TREE_REFERENCE", "1")

from experiments.bl_pq512_crypto_foundation.unique_decoding_parameters import (
    INTERFACE_STATUS,
    PER_TERM_SECURITY_BITS,
    InterfaceTableDimensions,
    InterfaceTheoremEnvelope,
    build_candidate_sweep,
    meets_per_term_budget,
    soundness_bits_floor,
)
from experiments.fixed_shape_claim_air.physical_air_reference import (
    build_wave1a_physical_air_program,
)
from experiments.fixed_shape_claim_air.profile import PROFILES


ROOT = Path(__file__).resolve().parents[1]
VECTOR_PATH = ROOT / "test_data" / "bl_pq512_wave1b_udr_vectors_v1.json"


def _envelope(profile_id: str) -> InterfaceTheoremEnvelope:
    program = build_wave1a_physical_air_program(PROFILES[profile_id])
    return InterfaceTheoremEnvelope(
        profile_id=program.profile_id,
        tables=tuple(
            InterfaceTableDimensions(
                name=table.name,
                padded_rows=table.padded_rows,
                trace_columns=table.trace_columns,
                constraint_count=table.constraint_count,
                maximum_constraint_degree=table.maximum_degree,
                lookup_coordinate_width=table.lookup_message_width,
            )
            for table in program.tables
        ),
        commitment_group_count=program.commitment_count,
    )


@pytest.mark.parametrize("profile_id", tuple(PROFILES))
def test_interface_envelope_matches_sealed_relation_dimensions(profile_id: str) -> None:
    program = build_wave1a_physical_air_program(PROFILES[profile_id])
    envelope = _envelope(profile_id)

    assert INTERFACE_STATUS.endswith("NONACTIVATING")
    assert envelope.final_expansion_substituted is False
    assert envelope.proof_suite_id is None
    assert envelope.activation_allowed is False
    assert envelope.total_trace_columns == program.total_trace_columns == 2279
    assert envelope.total_constraints == program.total_constraints == 4844
    assert envelope.total_lookup_coordinate_width == program.total_lookup_message_width == 276
    assert envelope.maximum_constraint_degree == program.maximum_constraint_degree == 3
    assert len(envelope.commitment_sha3_512) == 64


def test_k512_unique_decoding_candidate_sweep_is_exact_and_unselected() -> None:
    envelope = _envelope("K512_CALIBRATION")
    candidates = build_candidate_sweep(envelope)

    assert [candidate.log_blowup for candidate in candidates] == [1, 2, 3, 4, 5, 6]
    assert [candidate.query_count for candidate in candidates] == [617, 378, 309, 281, 268, 262]
    assert [candidate.evaluation_domain_size for candidate in candidates] == [
        1 << 20,
        1 << 21,
        1 << 22,
        1 << 23,
        1 << 24,
        1 << 25,
    ]
    assert all(candidate.unique_decoding_regime for candidate in candidates)
    assert all(candidate.degree_correction_condition for candidate in candidates)
    assert all(candidate.all_terms_meet_budget for candidate in candidates)
    assert all(candidate.final_expansion_substituted is False for candidate in candidates)
    assert all(candidate.selected is False for candidate in candidates)
    assert [candidate.fold_round_count for candidate in candidates] == [16] * 6
    assert [candidate.final_line_domain_size for candidate in candidates] == [
        16,
        32,
        64,
        128,
        256,
        512,
    ]

    for candidate in candidates:
        query_error = candidate.query_error
        assert meets_per_term_budget(query_error)
        assert not meets_per_term_budget(query_error / (1 - candidate.theta))
        assert soundness_bits_floor(query_error) >= PER_TERM_SECURITY_BITS


def test_machine_readable_interface_vectors_match_exact_calculation() -> None:
    vector = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
    assert vector["status"] == INTERFACE_STATUS
    assert vector["proofSuiteId"] is None
    assert vector["activationAllowed"] is False
    assert vector["finalExpansionSubstituted"] is False
    assert vector["challengeField"]["perTermSecurityBits"] == PER_TERM_SECURITY_BITS

    by_profile = {entry["profileId"]: entry for entry in vector["profiles"]}
    for profile_id in PROFILES:
        envelope = _envelope(profile_id)
        expected = by_profile[profile_id]
        assert envelope.commitment_sha3_512.hex() == expected["interfaceEnvelopeSha3_512"]
        assert envelope.maximum_rows == expected["maximumRows"]
        assert envelope.minimum_rows == expected["minimumRows"]
        assert envelope.logup_numerator_upper_bound == expected["logupNumeratorUpperBound"]
        assert (
            envelope.composition_numerator_upper_bound
            == expected["compositionNumeratorUpperBound"]
        )
        assert envelope.deep_numerator_upper_bound == expected["deepNumeratorUpperBound"]
        assert (
            envelope.interface_batch_width_upper_bound
            == expected["interfaceBatchWidthUpperBound"]
        )

    sweep = build_candidate_sweep(_envelope("K512_CALIBRATION"))
    assert [
        {"logBlowup": candidate.log_blowup, "queryCount": candidate.query_count}
        for candidate in sweep
    ] == vector["candidateSweep"]


def test_interface_error_terms_are_positive_named_and_below_budget() -> None:
    candidate = build_candidate_sweep(_envelope("K512_CALIBRATION"), (1,))[0]
    terms = dict(candidate.interface_error_terms)

    assert tuple(terms) == (
        "logup",
        "composition",
        "deep",
        "fri_batch",
        "fri_fold",
        "fri_query",
    )
    assert all(value > 0 for value in terms.values())
    assert all(meets_per_term_budget(value) for value in terms.values())
    assert soundness_bits_floor(candidate.interface_error_total) >= PER_TERM_SECURITY_BITS


def test_invalid_or_final_claims_fail_closed() -> None:
    envelope = _envelope("K128_CALIBRATION")
    table = envelope.tables[0]

    with pytest.raises(ValueError, match="cannot_claim_final_expansion"):
        InterfaceTheoremEnvelope(
            profile_id=envelope.profile_id,
            tables=envelope.tables,
            commitment_group_count=envelope.commitment_group_count,
            final_expansion_substituted=True,
        )
    with pytest.raises(ValueError, match="cannot_activate"):
        InterfaceTheoremEnvelope(
            profile_id=envelope.profile_id,
            tables=envelope.tables,
            commitment_group_count=envelope.commitment_group_count,
            activation_allowed=True,
        )
    with pytest.raises(ValueError, match="not_power_of_two"):
        InterfaceTableDimensions(
            name=table.name,
            padded_rows=3,
            trace_columns=table.trace_columns,
            constraint_count=table.constraint_count,
            maximum_constraint_degree=table.maximum_constraint_degree,
            lookup_coordinate_width=table.lookup_coordinate_width,
        )
    with pytest.raises(ValueError, match="log_blowup_too_large"):
        build_candidate_sweep(envelope, (17,))
