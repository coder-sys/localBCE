from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
from unittest import mock

import pytest

from experiments.fixed_shape_claim_air.physical_air_reference import (
    ACTIVATION_ALLOWED,
    MAX_D_EFF_ENVELOPE,
    PROOF_SUITE_ID,
    build_wave1a_physical_air_program,
    build_wave1a_physical_relation_trace,
    calibration_dimension_ledger,
    verify_wave1a_physical_relation_trace,
)
from experiments.fixed_shape_claim_air.profile import get_profile
from experiments.fixed_shape_claim_air.semantics import StructuralError
from tests import test_wave1a_relation_reference as relation_support


FLAGS = {
    "BL_ENV": "test",
    "BL_DEV": "1",
    "BL_ALLOW_SYNTHETIC_PQ_TREE_REFERENCE": "1",
}
ROOT = Path(__file__).resolve().parents[1]

EXPECTED_DIMENSIONS = {
    "K128_CALIBRATION": {
        "tables": 16,
        "commitments": 4,
        "logical_rows": 294_412,
        "padded_rows": 389_520,
        "trace_columns_across_tables": 2_279,
        "constraints": 4_844,
        "maximum_constraint_degree": 3,
        "lookup_message_width_across_tables": 276,
        "padded_cells": 44_205_824,
        "d_eff_upper_bound": 713_641_951_232,
    },
    "K256_DESIGN_POINT": {
        "tables": 16,
        "commitments": 4,
        "logical_rows": 601_996,
        "padded_rows": 779_024,
        "trace_columns_across_tables": 2_279,
        "constraints": 4_844,
        "maximum_constraint_degree": 3,
        "lookup_message_width_across_tables": 276,
        "padded_cells": 88_410_240,
        "d_eff_upper_bound": 1_427_283_902_464,
    },
    "K512_CALIBRATION": {
        "tables": 16,
        "commitments": 4,
        "logical_rows": 1_230_476,
        "padded_rows": 1_562_128,
        "trace_columns_across_tables": 2_279,
        "constraints": 4_844,
        "maximum_constraint_degree": 3,
        "lookup_message_width_across_tables": 276,
        "padded_cells": 177_212_288,
        "d_eff_upper_bound": 2_854_567_804_928,
    },
}

EXPECTED_PROGRAM_COMMITMENTS = {
    "K128_CALIBRATION": (
        "0d3544a1038006667f5ab795540c3ecd8ec83991d3e647e2106770d023c6a2f2"
        "dda783fb3ac6fc916b261922e6ef10b67c692909fc25e918d8021e5527aa9c81"
    ),
    "K256_DESIGN_POINT": (
        "5581a2307e693341b95baeabc87b90943f0775babed6937fb3cae580e59af2164"
        "d83d9626b3538ec0076bf5e71fa92fe11e6b4bace14593a21dc4c955b293067"
    ),
    "K512_CALIBRATION": (
        "c6dd66f955a86a3d490311c45338acbc29bee5487ed0dd77a275bd414582668eaa"
        "2b75489492ec8ee6c4d6bc1d3415e02025bfc4489d6f315b1b416063ff8b38"
    ),
}


@pytest.fixture(scope="module", autouse=True)
def _synthetic_environment():
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        yield


@pytest.fixture(scope="module")
def k128_relation():
    profile = relation_support.profile.__wrapped__()
    slots = relation_support.slots.__wrapped__(profile)
    replay = relation_support.replay.__wrapped__(profile)
    context = relation_support.context.__wrapped__()
    return relation_support.relation.__wrapped__(profile, slots, replay, context)


def test_exact_calibration_dimension_ledger_and_program_kats() -> None:
    profiles = tuple(
        get_profile(profile_id)
        for profile_id in (
            "K128_CALIBRATION",
            "K256_DESIGN_POINT",
            "K512_CALIBRATION",
        )
    )
    ledger = calibration_dimension_ledger(profiles)
    assert {key: dict(value) for key, value in ledger.items()} == EXPECTED_DIMENSIONS
    for profile in profiles:
        program = build_wave1a_physical_air_program(profile)
        assert program.program_commitment_sha3_512.hex() == (
            EXPECTED_PROGRAM_COMMITMENTS[profile.profile_id]
        )
        assert program.d_eff_upper_bound < MAX_D_EFF_ENVELOPE
        assert program.proof_suite_id is PROOF_SUITE_ID is None
        assert program.activation_allowed is ACTIVATION_ALLOWED is False
        assert program.table_count == 16
        assert program.commitment_count == 4


def test_machine_readable_dimension_vectors_match_executable_programs() -> None:
    vector = json.loads(
        (ROOT / "test_data" / "bl_wave1a_physical_relation_vectors_v1.json").read_text(
            encoding="utf-8"
        )
    )
    assert vector["activationAllowed"] is False
    assert vector["proofSuiteId"] is None
    assert vector["proofGenerated"] is False
    assert len(vector["profiles"]) == 3
    for item in vector["profiles"]:
        profile = get_profile(item["profileId"])
        program = build_wave1a_physical_air_program(profile)
        assert item["programCommitmentSha3_512"] == (
            program.program_commitment_sha3_512.hex()
        )
        dimensions = item["dimensions"]
        assert dimensions == {
            "tables": program.table_count,
            "commitments": program.commitment_count,
            "logicalRows": program.total_logical_rows,
            "paddedRows": program.total_padded_rows,
            "traceColumnsAcrossTables": program.total_trace_columns,
            "constraints": program.total_constraints,
            "maximumConstraintDegree": program.maximum_constraint_degree,
            "lookupMessageWidthAcrossTables": program.total_lookup_message_width,
            "paddedCells": program.total_padded_cells,
            "dEffUpperBound": program.d_eff_upper_bound,
        }


def test_complete_relation_binds_approval_denial_cover_and_all_public_fields(
    k128_relation,
) -> None:
    profile = get_profile("K128_CALIBRATION")
    trace = build_wave1a_physical_relation_trace(profile, k128_relation)
    assert verify_wave1a_physical_relation_trace(profile, trace)
    assert trace.physical_relation_constrained is False
    assert trace.concrete_stark_backend_selected is False
    assert trace.proof_generated is False
    assert trace.production_usable is False
    assert tuple(value.witness_class for value in trace.slot_bindings[:3]) == (
        "approval",
        "denial",
        "cover",
    )
    assert len(trace.slot_bindings) == profile.claim_slots
    assert len(k128_relation.public_outputs) == 12
    assert len({value.binding_sha3_512 for value in trace.slot_bindings}) == (
        profile.claim_slots
    )


def test_program_or_trace_mutation_fails_closed(k128_relation) -> None:
    profile = get_profile("K128_CALIBRATION")
    trace = build_wave1a_physical_relation_trace(profile, k128_relation)
    mutated_program = replace(
        trace.program,
        program_commitment_sha3_512=bytes.fromhex("01" * 64),
    )
    mutated_trace = replace(trace, program=mutated_program)
    with pytest.raises(StructuralError, match="recomputation_mismatch"):
        verify_wave1a_physical_relation_trace(profile, mutated_trace)
    with pytest.raises(StructuralError, match="security_boundary_invalid"):
        replace(trace, proof_generated=True)


def test_physical_relation_is_disabled_in_production() -> None:
    with mock.patch.dict(os.environ, {**FLAGS, "BL_ENV": "production"}, clear=False):
        with pytest.raises(RuntimeError, match="synthetic_pq_tree_reference_forbidden"):
            build_wave1a_physical_air_program(get_profile("K128_CALIBRATION"))
