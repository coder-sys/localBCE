from __future__ import annotations

from dataclasses import replace
import os
from hashlib import sha3_512
from unittest import mock

import pytest

from experiments.bl_pq512_crypto_foundation.gate_2e_selection import (
    ACTIVATION_ALLOWED,
    C0_CONTROL_ID,
    COMPLETE_BOUNDARY_STATUS,
    MEASUREMENT_LABEL,
    PROOF_SUITE_ID,
    SELECTION_STATUS,
    CandidateMeasurement,
    SelectionDecision,
    build_selection_handoff,
    measure_all_reference_components,
    select_reference_candidates,
)
from experiments.bl_pq512_crypto_foundation.pq_commitment_screening import CANDIDATE_IDS
from experiments.bl_pq512_crypto_foundation.pq_signature_adapters import (
    MlDsa87PqcryptoAdapter,
    SphincsShake256fSimplePqcryptoAdapter,
)
from experiments.bl_pq512_crypto_foundation.scalar_state_relation_controls import PROFILE_CLAIM_SLOTS


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
def authority_material():
    ml = MlDsa87PqcryptoAdapter()
    slh = SphincsShake256fSimplePqcryptoAdapter()
    material = {}
    for adapter, label in ((ml, b"ml"), (slh, b"slh")):
        public_key, secret_key = adapter.generate_keypair()
        material[adapter.suite_id] = (
            sha3_512(b"BL/S6/authority/" + label).digest(),
            adapter,
            public_key,
            secret_key,
        )
    return material


@pytest.fixture(scope="module")
def measurements(authority_material):
    return measure_all_reference_components(authority_material, repetitions=2)


def test_s6_measures_all_screened_backends_and_profiles(measurements) -> None:
    assert len(measurements) == len(CANDIDATE_IDS) * len(PROFILE_CLAIM_SLOTS) * 2
    assert {
        (item.backend_id, item.profile_id, item.repetition) for item in measurements
    } == {
        (backend_id, profile_id, repetition)
        for backend_id in CANDIDATE_IDS
        for profile_id in PROFILE_CLAIM_SLOTS
        for repetition in range(2)
    }
    for item in measurements:
        assert isinstance(item, CandidateMeasurement)
        assert item.screening_accepted is False
        assert item.rejection_reasons
        assert item.elapsed_ns > 0
        assert item.verifier_elapsed_ns > 0
        assert item.independent_reference_verified is True
        assert item.complete_boundary_verified is False
        assert item.proof_bytes == 0
        assert item.external_monitor_status == COMPLETE_BOUNDARY_STATUS
        assert item.measurement_label == MEASUREMENT_LABEL


def test_s7_rejects_all_candidates_and_retains_c0_without_timing_credit(measurements) -> None:
    fastest = replace(measurements[0], elapsed_ns=1, verifier_elapsed_ns=1, measurement_digest_512=b"")
    decision = select_reference_candidates((fastest, *measurements[1:]))
    assert isinstance(decision, SelectionDecision)
    assert decision.selection_status == SELECTION_STATUS
    assert decision.selected_backend_id is None
    assert decision.selected_relation_candidate_id is None
    assert decision.fallback_control_id == C0_CONTROL_ID
    assert decision.warmup_status == COMPLETE_BOUNDARY_STATUS
    assert decision.complete_boundary_status == COMPLETE_BOUNDARY_STATUS
    assert decision.proof_suite_id is None
    assert decision.activation_allowed is ACTIVATION_ALLOWED is False
    assert tuple(item.backend_id for item in decision.rejections) == CANDIDATE_IDS
    for rejection in decision.rejections:
        assert "complete_boundary_not_authorized_for_rejected_candidate" in rejection.screening_reasons


def test_s7_handoff_is_explicitly_unsealed_and_records_blockers(measurements) -> None:
    decision = select_reference_candidates(measurements)
    handoff = build_selection_handoff(
        decision,
        commit_id="ea053b6823ea357e99465bd4dce392d84204e0e0",
        tree_id="d182a2c5d7558abe0d1b7a982a80148ca7690aab",
        git_clean=True,
        protected_paths_clean=True,
        canonical_ops_available=False,
    )
    public = handoff.as_public_dict()
    assert handoff.sealed is False
    assert public["status"] == "UNSEALED_BLOCKED_SELECTION_HANDOFF"
    assert "no_backend_admitted" in handoff.blockers
    assert "complete_boundary_not_authorized" in handoff.blockers
    assert "h4_atomic_binding_deferred" in handoff.blockers
    assert "canonical_ops_missing" in handoff.blockers
