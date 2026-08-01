from __future__ import annotations

from dataclasses import replace
from hashlib import sha3_512
import os
from unittest import mock

import pytest

from experiments.fixed_shape_claim_air.physical_air_reference import (
    build_wave1a_physical_relation_trace,
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


@pytest.fixture(scope="module", autouse=True)
def _synthetic_environment():
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        yield


@pytest.fixture(scope="module")
def trace():
    profile = relation_support.profile.__wrapped__()
    slots = relation_support.slots.__wrapped__(profile)
    replay = relation_support.replay.__wrapped__(profile)
    context = relation_support.context.__wrapped__()
    relation = relation_support.relation.__wrapped__(profile, slots, replay, context)
    return build_wave1a_physical_relation_trace(profile, relation)


def test_attack_mutated_slot_binding_is_rejected(trace) -> None:
    forged_binding = replace(
        trace.slot_bindings[0],
        binding_sha3_512=sha3_512(b"FORGED-PHYSICAL-SLOT").digest(),
    )
    forged = replace(trace, slot_bindings=(forged_binding, *trace.slot_bindings[1:]))
    with pytest.raises(StructuralError, match="recomputation_mismatch"):
        verify_wave1a_physical_relation_trace(
            get_profile("K128_CALIBRATION"), forged
        )


def test_attack_wrong_profile_and_fake_backend_activation_are_rejected(trace) -> None:
    with pytest.raises(StructuralError, match="relation_profile_mismatch"):
        build_wave1a_physical_relation_trace(
            get_profile("K256_DESIGN_POINT"), trace.relation
        )
    with pytest.raises(StructuralError, match="security_boundary_invalid"):
        replace(trace, concrete_stark_backend_selected=True)
    with pytest.raises(StructuralError, match="security_boundary_invalid"):
        replace(trace, production_usable=True)
