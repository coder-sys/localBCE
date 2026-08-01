from __future__ import annotations

from dataclasses import replace
import os
from hashlib import sha3_512
from unittest import mock

import pytest

from experiments.bl_pq512_crypto_foundation.gate_2e_selection import (
    SelectionEvidenceError,
    build_selection_handoff,
    measure_all_reference_components,
    select_reference_candidates,
)
from experiments.bl_pq512_crypto_foundation.pq_signature_adapters import (
    MlDsa87PqcryptoAdapter,
    SphincsShake256fSimplePqcryptoAdapter,
)
FLAGS = {
    "BL_ENV": "test",
    "BL_DEV": "1",
    "BL_ALLOW_SYNTHETIC_PQ_TREE_REFERENCE": "1",
}


@pytest.fixture(scope="module", autouse=True)
def _attack_synthetic_environment():
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
            sha3_512(b"BL/S6/attack-authority/" + label).digest(),
            adapter,
            public_key,
            secret_key,
        )
    return material


@pytest.fixture(scope="module")
def measurements(authority_material):
    return measure_all_reference_components(authority_material, repetitions=2)


def test_s6_measurement_mutations_fail_closed(measurements) -> None:
    with pytest.raises(SelectionEvidenceError, match="screening_reasons_not_recomputed"):
        replace(measurements[0], rejection_reasons=("forged_reason",), measurement_digest_512=b"")
    with pytest.raises(SelectionEvidenceError, match="relation_candidate_not_frozen"):
        replace(measurements[0], relation_candidate_id="C4", measurement_digest_512=b"")
    with pytest.raises(SelectionEvidenceError, match="complete_boundary_not_available"):
        replace(measurements[0], complete_boundary_verified=True, measurement_digest_512=b"")
    with pytest.raises(SelectionEvidenceError, match="independent_reference_verification_required"):
        replace(measurements[0], independent_reference_verified=False, measurement_digest_512=b"")


def test_s7_missing_duplicate_and_unknown_measurements_cannot_select(measurements) -> None:
    with pytest.raises(SelectionEvidenceError, match="measurement_count_invalid"):
        select_reference_candidates(measurements[:-1])
    duplicate = (*measurements[:-1], measurements[0])
    with pytest.raises(SelectionEvidenceError, match="measurement_identity_set_invalid"):
        select_reference_candidates(duplicate)
    with pytest.raises(SelectionEvidenceError, match="s6_backend_unknown"):
        replace(
            measurements[0],
            backend_id="UNKNOWN_BACKEND",
            measurement_digest_512=b"",
        )


def test_s7_handoff_cannot_be_sealed_or_hide_dirty_protected_state(measurements) -> None:
    decision = select_reference_candidates(measurements)
    dirty = build_selection_handoff(
        decision,
        commit_id="ea053b6823ea357e99465bd4dce392d84204e0e0",
        tree_id="d182a2c5d7558abe0d1b7a982a80148ca7690aab",
        git_clean=False,
        protected_paths_clean=False,
        canonical_ops_available=False,
    )
    assert "git_dirty" in dirty.blockers
    assert "protected_path_changed" in dirty.blockers
    with pytest.raises(SelectionEvidenceError, match="must_remain_unsealed"):
        replace(dirty, sealed=True, handoff_digest_512=b"")
