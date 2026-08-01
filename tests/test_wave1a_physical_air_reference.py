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
        "logical_rows": 753_164,
        "padded_rows": 848_272,
        "trace_columns_across_tables": 2_279,
        "constraints": 4_844,
        "maximum_constraint_degree": 3,
        "lookup_message_width_across_tables": 276,
        "padded_cells": 114_853_632,
        "d_eff_upper_bound": 1_427_283_902_464,
    },
    "K256_DESIGN_POINT": {
        "tables": 16,
        "commitments": 4,
        "logical_rows": 1_519_500,
        "padded_rows": 1_696_528,
        "trace_columns_across_tables": 2_279,
        "constraints": 4_844,
        "maximum_constraint_degree": 3,
        "lookup_message_width_across_tables": 276,
        "padded_cells": 229_705_856,
        "d_eff_upper_bound": 2_854_567_804_928,
    },
    "K512_CALIBRATION": {
        "tables": 16,
        "commitments": 4,
        "logical_rows": 3_065_484,
        "padded_rows": 3_397_136,
        "trace_columns_across_tables": 2_279,
        "constraints": 4_844,
        "maximum_constraint_degree": 3,
        "lookup_message_width_across_tables": 276,
        "padded_cells": 459_803_520,
        "d_eff_upper_bound": 5_709_135_609_856,
    },
}

EXPECTED_PROGRAM_COMMITMENTS = {
    "K128_CALIBRATION": (
        "d5df3ac6795e534bb6bb2ae090ff2dc9282a3dcf76c2602997e3b7cd304a9542"
        "2d9c791dcd36ca5ae635afb3b6a11791d66b4ae3a194999de523247f353dd161"
    ),
    "K256_DESIGN_POINT": (
        "2f0029505286c35976c50dcb747605e72c31b34de0463c3093621d6936b8b63d"
        "e62369302ca84a583bad6e6d365db9460870c6b0c4cb973bcb55f0af4de01860"
    ),
    "K512_CALIBRATION": (
        "60cb58cc01fdb445b83b919cae2f30d00fbe4842cd2b60fea8bff4943cbc8378"
        "2f878c252f8d4ff1e7950c68fab141ffcb784ec141a7ffd612544929de406e70"
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
