from __future__ import annotations

from dataclasses import replace
import os
from hashlib import sha3_512
from unittest import mock

import pytest

from experiments.bl_pq512_crypto_foundation.pq_commitment_screening import (
    ACTIVATION_ALLOWED,
    AUTHORITY_SUITE_IDS,
    CANDIDATE_IDS,
    AuthenticatedPublicCoinRound,
    CommitmentStatement,
    PublicCoinAttestation,
    STATUS,
    build_commitment,
    build_opening,
    derive_pre_challenge_digest,
    derive_public_coin_message_digest,
    screen_all_backends,
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
def authority_material():
    ml = MlDsa87PqcryptoAdapter()
    slh = SphincsShake256fSimplePqcryptoAdapter()
    material = {}
    for adapter, label in ((ml, b"ml"), (slh, b"slh")):
        public_key, secret_key = adapter.generate_keypair()
        material[adapter.suite_id] = (
            sha3_512(b"BL/S3/authority/" + label).digest(),
            adapter,
            public_key,
            secret_key,
        )
    return material


def _statement(profile_id: str = "K128_CALIBRATION") -> CommitmentStatement:
    return CommitmentStatement(
        profile_id=profile_id,
        layout_id_512=sha3_512(b"BL/S3/layout/v1").digest(),
        epoch=4,
        sequence_before=17,
        sequence_after=18,
        state_root_before_512=sha3_512(b"BL/S3/old-state").digest(),
        state_root_after_512=sha3_512(b"BL/S3/new-state").digest(),
        relation_digest_512=sha3_512(b"BL/S3/relation").digest(),
        manifest_digest_512=sha3_512(b"BL/S3/manifest").digest(),
    )


def _coin_round(
    backend_id: str,
    statement: CommitmentStatement,
    payload: bytes,
    mask: bytes,
    authority_material,
) -> tuple[AuthenticatedPublicCoinRound, dict[str, object]]:
    pre_challenge = derive_pre_challenge_digest(backend_id, statement, payload, mask)
    session_id = sha3_512(b"BL/S3/session/" + backend_id.encode("ascii")).digest()
    message_digest = derive_public_coin_message_digest(session_id, 0, pre_challenge)
    attestations = []
    adapters = {}
    for suite_id in AUTHORITY_SUITE_IDS:
        authority_id, adapter, public_key, secret_key = authority_material[suite_id]
        attestations.append(
            PublicCoinAttestation(
                authority_id,
                suite_id,
                public_key,
                message_digest,
                adapter.sign(secret_key=secret_key, message=message_digest),
            )
        )
        adapters[suite_id] = adapter
    attestations.sort(key=lambda item: item.authority_id_512)
    return (
        AuthenticatedPublicCoinRound(
            session_id,
            0,
            pre_challenge,
            tuple(attestations),
        ),
        adapters,
    )


def test_all_admitted_backend_descriptors_are_screened_and_fail_closed() -> None:
    results = screen_all_backends()
    assert tuple(item.descriptor.backend_id for item in results) == CANDIDATE_IDS
    assert all(item.accepted is False for item in results)
    assert all(item.rejection_reasons for item in results)
    transparent = next(
        item for item in results if item.descriptor.backend_id == "TRANSPARENT_HASH_CODE"
    )
    assert "native_hiding_theorem_unreviewed" in transparent.rejection_reasons
    assert "complete_composition_missing" in transparent.rejection_reasons
    assert all("parameter_commitment_sha3_512_hex" in item.as_public_dict() for item in results)


def test_common_reference_commitment_roundtrip_uses_dual_pq_authenticated_coin(
    authority_material,
) -> None:
    statement = _statement()
    payload = b"BL-SYNTHETIC-STATE-RELATION-PAYLOAD-v1"
    mask = sha3_512(b"BL/S3/fresh-mask").digest()
    for backend_id in CANDIDATE_IDS:
        coin_round, adapters = _coin_round(
            backend_id, statement, payload, mask, authority_material
        )
        artifact = build_commitment(
            backend_id,
            statement,
            payload,
            mask,
            coin_round,
            adapters,
        )
        opening = build_opening(artifact, payload, mask, adapters)
        verify_opening(artifact, statement, opening, adapters)
        public = artifact.as_public_dict()
        assert public["status"] == STATUS
        assert "payload" not in public
        assert "mask" not in public
        assert artifact.challenge_512 != bytes(64)
        assert artifact.public_transcript_digest_512 != bytes(64)


def test_commitment_is_bound_to_statement_payload_mask_and_coin(
    authority_material,
) -> None:
    statement = _statement()
    payload = b"BL-SYNTHETIC-STATE-RELATION-PAYLOAD-v1"
    mask = sha3_512(b"BL/S3/fresh-mask-2").digest()
    coin_round, adapters = _coin_round(
        "TRANSPARENT_HASH_CODE", statement, payload, mask, authority_material
    )
    artifact = build_commitment(
        "TRANSPARENT_HASH_CODE", statement, payload, mask, coin_round, adapters
    )
    opening = build_opening(artifact, payload, mask, adapters)
    with pytest.raises(ValueError, match="opening_payload|pre_challenge|commitment"):
        verify_opening(artifact, statement, replace(opening, payload=b"BL-SYNTHETIC-TAMPER"), adapters)
    with pytest.raises(ValueError, match="opening_mask|pre_challenge|mask_commitment|commitment"):
        verify_opening(
            artifact,
            statement,
            replace(opening, mask_512=sha3_512(b"BL/S3/wrong-mask").digest()),
            adapters,
        )
    with pytest.raises(ValueError, match="statement"):
        verify_opening(artifact, replace(statement, epoch=5), opening, adapters)
    bad_attestation = replace(
        coin_round.attestations[0],
        signature=bytes((coin_round.attestations[0].signature[0] ^ 1,))
        + coin_round.attestations[0].signature[1:],
    )
    bad_round = replace(coin_round, attestations=(bad_attestation, coin_round.attestations[1]))
    bad_artifact = replace(artifact, coin_round=bad_round)
    with pytest.raises(ValueError, match="signature_invalid"):
        verify_opening(bad_artifact, statement, opening, adapters)


def test_s3_reference_is_not_activation_or_proof_suite_evidence() -> None:
    assert ACTIVATION_ALLOWED is False
