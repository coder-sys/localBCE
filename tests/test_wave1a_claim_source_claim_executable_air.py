from __future__ import annotations

from functools import lru_cache
from types import MappingProxyType

import pytest

from experiments.fixed_shape_claim_air.claim_oracle_executable_air import (
    build_claim_oracle_executable_air,
)
from experiments.fixed_shape_claim_air.claim_source_claim_executable_air import (
    build_claim_source_claim_executable_air,
)
from experiments.fixed_shape_claim_air.executable_air import evaluate_program
from experiments.fixed_shape_claim_air.measurement import build_synthetic_measurement_slots
from experiments.fixed_shape_claim_air.profile import PROFILES
from experiments.fixed_shape_claim_air.semantics import StructuralError


@lru_cache(maxsize=1)
def _instance():
    profile = PROFILES["K128_CALIBRATION"]
    return build_claim_source_claim_executable_air(
        profile,
        build_synthetic_measurement_slots(profile, "mixed_half_real"),
    )


def test_k128_claim_source_claim_oracle_composition_kat() -> None:
    instance = _instance()
    report = evaluate_program(instance.program, instance.traces)
    assert report.identities_evaluated == 8_394_717
    assert report.lookup_messages_evaluated == 10_696_120
    assert report.maximum_degree == 2
    assert report.program_commitment.hex() == (
        "3689233458f4a9fd389dc6fb8995b4873af8aa5ec1ad58509bdf5a193e7dc437"
        "ed151a812b4e539c69a88d124ef5c843a3a8daf7dd696d1792406032a93671e0"
    )
    assert report.trace_commitment.hex() == (
        "ec03759f815a8cfb142fa99edc4ede46797b170936f7fc21ff06ab723045c923b"
        "39c3a95a0a590704feb6f80bf5bde08f880a73931017cee2d8fcb35fa2182b6"
    )
    assert instance.source_claim_semantics_constrained is True
    assert instance.source_oracle_authorization_token_constrained is True
    assert instance.policy_claim_semantics_constrained is True
    assert instance.source_hashes_constrained is False
    assert instance.source_authority_constrained is False


def test_coherent_but_conflicting_claim_oracle_trace_fails_source_bridge() -> None:
    profile = PROFILES["K128_CALIBRATION"]
    instance = _instance()
    covers = build_claim_oracle_executable_air(
        profile,
        build_synthetic_measurement_slots(profile, "all_cover"),
    )
    traces = MappingProxyType(
        {
            **dict(instance.source.traces),
            **dict(covers.traces),
            **dict(instance.policy.traces),
        }
    )
    with pytest.raises(StructuralError, match="lookup_multiset_mismatch"):
        evaluate_program(instance.program, traces)


def test_program_commitment_is_witness_shape_independent() -> None:
    profile = PROFILES["K128_CALIBRATION"]
    covers = build_claim_source_claim_executable_air(
        profile,
        build_synthetic_measurement_slots(profile, "all_cover"),
    )
    assert _instance().program.commitment() == covers.program.commitment()
