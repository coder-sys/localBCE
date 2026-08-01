from __future__ import annotations

from dataclasses import replace
from types import MappingProxyType

import pytest

from experiments.fixed_shape_claim_air.claim_oracle_executable_air import (
    build_claim_oracle_executable_air,
)
from experiments.fixed_shape_claim_air.executable_air import evaluate_program
from experiments.fixed_shape_claim_air.measurement import (
    build_synthetic_measurement_slots,
)
from experiments.fixed_shape_claim_air.oracle_bundle_encoding_executable_air import (
    build_oracle_bundle_encoding_executable_air,
)
from experiments.fixed_shape_claim_air.profile import PROFILES
from experiments.fixed_shape_claim_air.semantics import StructuralError


def _slots(shape: str = "mixed_half_real"):
    profile = PROFILES["K128_CALIBRATION"]
    return profile, build_synthetic_measurement_slots(profile, shape)


def _hybrid_oracle_traces(instance, alternate_slots):
    alternate = build_oracle_bundle_encoding_executable_air(
        PROFILES["K128_CALIBRATION"], alternate_slots
    )
    traces = dict(instance.traces)
    traces.update(alternate.traces)
    return MappingProxyType(traces)


def test_k128_claim_oracle_composition_kat() -> None:
    profile, slots = _slots()
    instance = build_claim_oracle_executable_air(profile, slots)
    report = evaluate_program(instance.program, instance.traces)
    assert report.maximum_degree == 2
    assert report.identities_evaluated == 1_975_926
    assert report.lookup_messages_evaluated == 2_937_984
    assert report.program_commitment.hex() == (
        "5d63849fb4fc2f687a08308c8e3f9adae8e43303012f71535a696f8b8bbbdd5e"
        "176ee86c601369b0a98dd90f6467f1935cc98ce642adf7f52f0180d2a618efba"
    )
    assert report.trace_commitment.hex() == (
        "65e735ad2825d37bab604a51a098adf5d7a41eeedad33c8ee5c8fa6bf14ffe432"
        "3281e548d744c3464b0a4e00ded36f51eb56720417f92b298fff13401d85f6e"
    )
    assert instance.oracle_claim_semantics_constrained is True
    assert instance.oracle_hashes_constrained is False
    assert instance.oracle_signer_epoch_constrained is False


def test_program_commitment_is_independent_of_claim_and_oracle_witness() -> None:
    profile, mixed_slots = _slots()
    _, cover_slots = _slots("all_cover")
    mixed = build_claim_oracle_executable_air(profile, mixed_slots)
    covers = build_claim_oracle_executable_air(profile, cover_slots)
    assert mixed.program.commitment() == covers.program.commitment()


def test_coherent_conflicting_oracle_fact_trace_fails_only_at_composition() -> None:
    profile, slots = _slots()
    instance = build_claim_oracle_executable_air(profile, slots)
    alternate_slots = (replace(slots[0], eligibility_active=False), *slots[1:])
    hybrid = _hybrid_oracle_traces(instance, alternate_slots)
    with pytest.raises(
        StructuralError,
        match="air_lookup_multiset_mismatch:claim_oracle_fact_link",
    ):
        evaluate_program(instance.program, hybrid)


def test_coherent_conflicting_authorization_trace_fails_only_at_composition() -> None:
    profile, slots = _slots()
    instance = build_claim_oracle_executable_air(profile, slots)
    line = replace(
        slots[0].service_lines[0],
        prior_authorization="AUTH-1",
        requires_prior_authorization=True,
        authorization_present=True,
    )
    alternate_slots = (
        replace(slots[0], service_lines=(line,)),
        *slots[1:],
    )
    hybrid = _hybrid_oracle_traces(instance, alternate_slots)
    with pytest.raises(
        StructuralError,
        match="air_lookup_multiset_mismatch:claim_oracle_authorization_link",
    ):
        evaluate_program(instance.program, hybrid)
