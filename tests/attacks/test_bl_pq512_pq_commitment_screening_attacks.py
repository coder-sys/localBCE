from __future__ import annotations

from dataclasses import replace
import os
from hashlib import sha3_512
from unittest import mock

import pytest

from experiments.bl_pq512_crypto_foundation.pq_commitment_screening import (
    AUTHORITY_SUITE_IDS,
    AuthenticatedPublicCoinRound,
    CommitmentBackendDescriptor,
    CommitmentStatement,
    PublicCoinAttestation,
    build_commitment,
    build_opening,
    derive_pre_challenge_digest,
    derive_public_coin_message_digest,
    screen_backend,
    verify_opening,
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
def _synthetic_environment():
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        yield


@pytest.fixture(scope="module")
def material():
    ml = MlDsa87PqcryptoAdapter()
    slh = SphincsShake256fSimplePqcryptoAdapter()
    result = {}
    for adapter, label in ((ml, b"ml"), (slh, b"slh")):
        public_key, secret_key = adapter.generate_keypair()
        result[adapter.suite_id] = (
            sha3_512(b"BL/S3/attack-authority/" + label).digest(),
            adapter,
            public_key,
            secret_key,
        )
    return result


def _statement() -> CommitmentStatement:
    return CommitmentStatement(
        "K512_CALIBRATION",
        sha3_512(b"attack-layout").digest(),
        3,
        9,
        10,
        sha3_512(b"attack-old").digest(),
        sha3_512(b"attack-new").digest(),
        sha3_512(b"attack-relation").digest(),
        sha3_512(b"attack-manifest").digest(),
    )


def _round(backend_id: str, statement, payload, mask, material):
    pre = derive_pre_challenge_digest(backend_id, statement, payload, mask)
    session_id = sha3_512(b"attack-session").digest()
    message = derive_public_coin_message_digest(session_id, 1, pre)
    attestations = []
    adapters = {}
    for suite_id in AUTHORITY_SUITE_IDS:
        authority_id, adapter, public_key, secret_key = material[suite_id]
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
    return (
        AuthenticatedPublicCoinRound(session_id, 1, pre, tuple(attestations)),
        adapters,
    )


def test_reordered_or_duplicate_authorities_fail_closed() -> None:
    statement = _statement()
    material = {}
    ml = MlDsa87PqcryptoAdapter()
    slh = SphincsShake256fSimplePqcryptoAdapter()
    for adapter, label in ((ml, b"ml"), (slh, b"slh")):
        public_key, secret_key = adapter.generate_keypair()
        material[adapter.suite_id] = (
            sha3_512(b"authority-" + label).digest(),
            adapter,
            public_key,
            secret_key,
        )
    payload = b"BL-SYNTHETIC-ATTACK-PAYLOAD"
    mask = sha3_512(b"attack-mask").digest()
    coin_round, _ = _round("TRANSPARENT_HASH_CODE", statement, payload, mask, material)
    with pytest.raises(ValueError, match="attestation_order"):
        AuthenticatedPublicCoinRound(
            coin_round.session_id_512,
            coin_round.round_ordinal,
            coin_round.pre_challenge_digest_512,
            tuple(reversed(coin_round.attestations)),
        )
    with pytest.raises(ValueError, match="authority_duplicate"):
        AuthenticatedPublicCoinRound(
            coin_round.session_id_512,
            coin_round.round_ordinal,
            coin_round.pre_challenge_digest_512,
            (coin_round.attestations[0], replace(coin_round.attestations[0], suite_id=AUTHORITY_SUITE_IDS[1])),
        )


def test_prechallenge_rebinding_and_adapter_substitution_are_rejected(material) -> None:
    statement = _statement()
    payload = b"BL-SYNTHETIC-ATTACK-PAYLOAD"
    mask = sha3_512(b"attack-mask-2").digest()
    coin_round, adapters = _round("TRANSPARENT_HASH_CODE", statement, payload, mask, material)
    wrong_pre = sha3_512(b"wrong-pre").digest()
    wrong_message = derive_public_coin_message_digest(
        coin_round.session_id_512, coin_round.round_ordinal, wrong_pre
    )
    wrong_attestations = []
    for suite_id in AUTHORITY_SUITE_IDS:
        authority_id, adapter, public_key, secret_key = material[suite_id]
        wrong_attestations.append(
            PublicCoinAttestation(
                authority_id,
                suite_id,
                public_key,
                wrong_message,
                adapter.sign(secret_key=secret_key, message=wrong_message),
            )
        )
    wrong_attestations.sort(key=lambda item: item.authority_id_512)
    wrong_round = AuthenticatedPublicCoinRound(
        coin_round.session_id_512,
        coin_round.round_ordinal,
        wrong_pre,
        tuple(wrong_attestations),
    )
    with pytest.raises(ValueError, match="pre_challenge_binding"):
        build_commitment(
            "TRANSPARENT_HASH_CODE",
            statement,
            payload,
            mask,
            wrong_round,
            adapters,
        )
    with pytest.raises(ValueError, match="exact_adapter"):
        coin_round.verify({AUTHORITY_SUITE_IDS[0]: adapters[AUTHORITY_SUITE_IDS[0]]})


def test_screening_metadata_mutation_cannot_create_admission() -> None:
    descriptor = screen_backend("TRANSPARENT_HASH_CODE").descriptor
    with pytest.raises(ValueError, match="parameter_commitment_mismatch"):
        replace(descriptor, parameter_commitment_512=b"\x01" * 64)
    result = screen_backend("TRANSPARENT_HASH_CODE")
    assert result.accepted is False
    assert "complete_composition_missing" in result.rejection_reasons


def test_opening_cannot_be_rebound_to_another_backend(material) -> None:
    statement = _statement()
    payload = b"BL-SYNTHETIC-ATTACK-PAYLOAD"
    mask = sha3_512(b"attack-mask-3").digest()
    coin_round, adapters = _round("TRANSPARENT_HASH_CODE", statement, payload, mask, material)
    artifact = build_commitment(
        "TRANSPARENT_HASH_CODE", statement, payload, mask, coin_round, adapters
    )
    opening = build_opening(artifact, payload, mask, adapters)
    with pytest.raises(ValueError, match="opening_backend_mismatch|parameter_identity"):
        verify_opening(
            replace(artifact, backend_id="MODULE_SIS"),
            statement,
            opening,
            adapters,
        )
