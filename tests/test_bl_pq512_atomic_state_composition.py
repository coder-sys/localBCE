from __future__ import annotations

from dataclasses import replace
import os
from hashlib import sha3_512
from unittest import mock

import pytest

from experiments.bl_pq512_crypto_foundation.atomic_state_composition import (
    ACTIVATION_ALLOWED,
    H4_PARENT_BINDING_STATUS,
    PROOF_SUITE_ID,
    AtomicComposition,
    STATUS,
    build_atomic_composition,
    canonical_relation_payload,
    derive_composition_statement,
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
    PROFILE_CLAIM_SLOTS,
    build_scalar_control_batch,
    evaluate_candidate,
)
from experiments.bl_pq512_crypto_foundation.state_interface import (
    decode_transition_envelope,
    encode_transition_envelope,
)


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
            sha3_512(b"BL/S4/authority/" + label).digest(),
            adapter,
            public_key,
            secret_key,
        )
    return material


def _build_case(
    authority_material,
    profile_id: str,
    backend_id: str,
    relation_candidate_id: str = "C1_SPARSE",
):
    batch = build_scalar_control_batch(profile_id)
    result = evaluate_candidate(relation_candidate_id, batch)
    projection = tuple(
        sha3_512(b"BL/S4/projection/" + index.to_bytes(1, "big")).digest()[:32]
        for index in range(12)
    )
    statement = derive_composition_statement(
        batch, result, projection, epoch=7, sequence_before=22
    )
    payload = canonical_relation_payload(result)
    mask = sha3_512(
        b"BL/S4/mask/"
        + profile_id.encode("ascii")
        + relation_candidate_id.encode("ascii")
        + backend_id.encode("ascii")
    ).digest()
    pre = derive_pre_challenge_digest(backend_id, statement, payload, mask)
    session_id = sha3_512(
        b"BL/S4/session/"
        + profile_id.encode("ascii")
        + relation_candidate_id.encode("ascii")
        + backend_id.encode("ascii")
    ).digest()
    message = derive_public_coin_message_digest(session_id, 0, pre)
    attestations = []
    adapters = {}
    for suite_id in AUTHORITY_SUITE_IDS:
        authority_id, adapter, public_key, secret_key = authority_material[suite_id]
        attestations.append(
            PublicCoinAttestation(
                authority_id,
                suite_id,
                public_key,
                message,
                adapter.sign(secret_key=secret_key, message=message),
            )
        )
        adapters[suite_id] = adapter
    attestations.sort(key=lambda item: item.authority_id_512)
    coin_round = AuthenticatedPublicCoinRound(session_id, 0, pre, tuple(attestations))
    artifact = build_commitment(
        backend_id, statement, payload, mask, coin_round, adapters
    )
    opening = build_opening(artifact, payload, mask, adapters)
    composition = build_atomic_composition(
        batch,
        result,
        projection,
        artifact,
        opening,
        adapters,
        epoch=7,
        sequence_before=22,
    )
    return batch, result, projection, artifact, opening, adapters, composition


def test_s4_composes_both_profiles_and_all_screened_references(authority_material) -> None:
    for profile_id in PROFILE_CLAIM_SLOTS:
        for candidate_id in (
            "JINDO_STYLE_LATTICE",
            "MODULE_SIS",
            "ROKOKO_STYLE_LATTICE",
            "TRANSPARENT_HASH_CODE",
        ):
            batch, result, projection, _, opening, adapters, composition = _build_case(
                authority_material, profile_id, candidate_id
            )
            independently_verify_composition(
                composition, batch, result, opening, adapters
            )
            assert isinstance(composition, AtomicComposition)
            assert composition.as_public_dict()["status"] == STATUS
            assert composition.acceptance_status == "REFERENCE_VERIFIED_ONLY"
            assert composition.candidate_id == "C1_SPARSE"
            assert composition.commitment_backend_id == candidate_id
            assert composition.projection_12 == projection
            assert composition.receipt.receipt_digest_512


def test_s4_transition_is_canonical_and_relation_payload_excludes_raw_keys(
    authority_material,
) -> None:
    batch, result, _, _, opening, adapters, composition = _build_case(
        authority_material, "K128_CALIBRATION", "TRANSPARENT_HASH_CODE"
    )
    encoded = encode_transition_envelope(composition.transition)
    assert decode_transition_envelope(encoded) == composition.transition
    payload = canonical_relation_payload(result)
    for lane in result.lanes:
        assert lane.membership_key_512 not in payload
        assert lane.absence_key_512 not in payload
        assert lane.membership_value_512 not in payload
    public = composition.as_public_dict()
    assert public["status"] == STATUS
    assert H4_PARENT_BINDING_STATUS == "DEFERRED_H4_REFERENCE_IDENTITY_ONLY"
    assert PROOF_SUITE_ID is None
    assert ACTIVATION_ALLOWED is False
    independently_verify_composition(composition, batch, result, opening, adapters)
