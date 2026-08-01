from __future__ import annotations

from dataclasses import replace
import os
from hashlib import sha3_512
from unittest import mock

import pytest

from experiments.bl_pq512_crypto_foundation.atomic_state_composition import (
    AtomicCompositionError,
    build_atomic_composition,
    independently_verify_composition,
)
from experiments.bl_pq512_crypto_foundation.pq_commitment_screening import (
    AUTHORITY_SUITE_IDS,
    AuthenticatedPublicCoinRound,
    PublicCoinAttestation,
    build_commitment,
    build_opening,
    derive_pre_challenge_digest,
    derive_public_coin_message_digest,
)
from experiments.bl_pq512_crypto_foundation.pq_signature_adapters import (
    MlDsa87PqcryptoAdapter,
    SphincsShake256fSimplePqcryptoAdapter,
)
from experiments.bl_pq512_crypto_foundation.scalar_state_relation_controls import (
    build_scalar_control_batch,
    evaluate_candidate,
)
from tests.test_bl_pq512_atomic_state_composition import _build_case


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
            sha3_512(b"BL/S4/attack-authority/" + label).digest(),
            adapter,
            public_key,
            secret_key,
        )
    return material


def test_transition_root_mutation_fails_before_composition_acceptance(authority_material) -> None:
    batch, result, _, _, opening, adapters, composition = _build_case(
        authority_material, "K128_CALIBRATION", "TRANSPARENT_HASH_CODE"
    )
    forged_transition = replace(
        composition.transition,
        old_root=sha3_512(b"BL/S4/forged-old-root").digest(),
    )
    forged = replace(composition, transition=forged_transition)
    with pytest.raises(AtomicCompositionError, match="transition_mismatch"):
        independently_verify_composition(forged, batch, result, opening, adapters)


def test_commitment_mutation_and_opening_mutation_fail_closed(authority_material) -> None:
    batch, result, projection, artifact, opening, adapters, composition = _build_case(
        authority_material, "K512_CALIBRATION", "TRANSPARENT_HASH_CODE"
    )
    forged_artifact = replace(
        artifact,
        commitment_512=sha3_512(b"BL/S4/forged-commitment").digest(),
    )
    forged = replace(composition, commitment=forged_artifact)
    with pytest.raises(AtomicCompositionError, match="commitment_rejected"):
        independently_verify_composition(forged, batch, result, opening, adapters)
    with pytest.raises(AtomicCompositionError, match="commitment_opening_rejected"):
        build_atomic_composition(
            batch,
            result,
            projection,
            artifact,
            replace(opening, payload=b"BL-SYNTHETIC-FORGED-RELATION"),
            adapters,
            epoch=7,
            sequence_before=22,
        )


def test_projection_candidate_and_receipt_identity_mutations_fail(authority_material) -> None:
    batch, result, projection, _, opening, adapters, composition = _build_case(
        authority_material, "K128_CALIBRATION", "TRANSPARENT_HASH_CODE"
    )
    forged_projection = replace(
        composition,
        projection_12=(sha3_512(b"BL/S4/forged-projection").digest()[:32], *projection[1:]),
    )
    with pytest.raises(AtomicCompositionError, match="transition_mismatch"):
        independently_verify_composition(forged_projection, batch, result, opening, adapters)
    forged_candidate = replace(composition, candidate_id="MODULE_SIS")
    with pytest.raises(AtomicCompositionError, match="identity_mismatch|commitment_rejected"):
        independently_verify_composition(forged_candidate, batch, result, opening, adapters)
    forged_proof = sha3_512(b"BL/S4/forged-proof-id").digest()
    forged_receipt = replace(
        composition.receipt,
        proof_identity_512=forged_proof,
        receipt_digest_512=b"",
    )
    forged_both = replace(
        composition,
        proof_identity_512=forged_proof,
        receipt=forged_receipt,
    )
    with pytest.raises(AtomicCompositionError, match="proof_identity_mismatch"):
        independently_verify_composition(forged_both, batch, result, opening, adapters)


def test_relation_result_mutation_is_not_repaired_by_host_receipt(authority_material) -> None:
    batch, result, _, _, opening, adapters, composition = _build_case(
        authority_material, "K128_CALIBRATION", "TRANSPARENT_HASH_CODE"
    )
    forged_result = replace(
        result,
        semantic_digest_512=sha3_512(b"BL/S4/forged-relation").digest(),
    )
    with pytest.raises((AtomicCompositionError, ValueError), match="s2_verifier|relation|commitment"):
        independently_verify_composition(composition, batch, forged_result, opening, adapters)
