from __future__ import annotations

from dataclasses import replace
from hashlib import sha3_512

import pytest

from experiments.bl_pq512_crypto_foundation.pq_signature_adapters import (
    MlDsa87PqcryptoAdapter,
    SphincsShake256fSimplePqcryptoAdapter,
)
from experiments.bl_pq512_crypto_foundation.public_coin_reference import (
    Contributor,
    EnvelopeKind,
    ProverMessageKind,
    PublicCoinSession,
    RoundKind,
    SignedEnvelope,
    TheoremProverMessage,
    build_selected_theorem_round_schedule,
)
from experiments.bl_pq512_crypto_foundation.selected_proof_parameters import (
    derive_selected_proof_geometry,
)
from experiments.bl_pq512_crypto_foundation.selected_public_coin import (
    SelectedPublicCoinTranscript,
    capture_selected_transcript,
    decode_selected_challenge_bundle,
    encode_selected_challenge_bundle,
    verify_selected_transcript,
)
from tests.test_wave1a_executable_air import _fixture


@pytest.fixture(scope="module")
def completed_selected_session():
    program, _ = _fixture()
    geometry = derive_selected_proof_geometry(program)
    schedule = build_selected_theorem_round_schedule(geometry)
    ml = MlDsa87PqcryptoAdapter()
    slh = SphincsShake256fSimplePqcryptoAdapter()
    adapters = {ml.suite_id: ml, slh.suite_id: slh}
    material = []
    for ordinal, adapter in enumerate((ml, slh), 1):
        public, secret = adapter.generate_keypair()
        material.append(
            (
                Contributor(
                    sha3_512(f"selected-contributor-{ordinal}".encode()).digest(),
                    sha3_512(f"selected-key-{ordinal}".encode()).digest(),
                    adapter.suite_id,
                    public,
                ),
                secret,
            )
        )
    material.sort(key=lambda item: item[0].contributor_id)
    contributors = tuple(item[0] for item in material)
    secrets = {item[0].contributor_id: item[1] for item in material}
    session = PublicCoinSession(
        session_id=sha3_512(b"selected-public-coin-session").digest(),
        public_outputs=bytes(384),
        sidecar=bytes(744),
        candidate_descriptor_sha3_512=schedule.proof_suite_id,
        schedule=schedule.descriptors,
        contributors=contributors,
        verifiers=adapters,
        production_mode=True,
        theorem_schedule=schedule,
    )
    for descriptor in schedule.descriptors:
        if descriptor.kind is RoundKind.INTERACTION_CHALLENGE:
            kind, ordinal = ProverMessageKind.MAIN_TRACE_ROOT, 0
        elif descriptor.kind is RoundKind.COMPOSITION_COEFFICIENT:
            kind, ordinal = ProverMessageKind.INTERACTION_TRACE_ROOT, 0
        elif descriptor.kind is RoundKind.OODS_POINT_PARAMETER:
            kind, ordinal = ProverMessageKind.COMPOSITION_ROOT, 0
        elif descriptor.kind is RoundKind.FRI_BATCH_COEFFICIENT:
            kind, ordinal = ProverMessageKind.OODS_CLAIMS_AND_FRI_MASK_ROOT, 0
        elif descriptor.kind is RoundKind.FRI_FOLD_COEFFICIENT:
            kind = (
                ProverMessageKind.FRI_BATCH_DERIVATION
                if descriptor.ordinal == 0
                else ProverMessageKind.FRI_LAYER_ROOT
            )
            ordinal = 0 if descriptor.ordinal == 0 else descriptor.ordinal - 1
        else:
            kind, ordinal = (
                ProverMessageKind.FRI_LAYER_ROOT,
                schedule.fold_round_count - 1,
            )
        primary = sha3_512(
            b"selected-prover-message"
            + int(kind).to_bytes(2, "big")
            + ordinal.to_bytes(2, "big")
        ).digest()
        secondary = (
            sha3_512(b"selected-fri-mask-root").digest()
            if kind is ProverMessageKind.OODS_CLAIMS_AND_FRI_MASK_ROOT
            else bytes(64)
        )
        session.begin_round(
            descriptor,
            TheoremProverMessage(kind, ordinal, primary, secondary).encode(),
        )
        reveals = {
            item.contributor_id: sha3_512(
                b"selected-reveal"
                + descriptor.encode()
                + item.contributor_id
            ).digest()
            for item in contributors
        }
        for contributor in contributors:
            payload = session.commitment_for(
                contributor.contributor_id, reveals[contributor.contributor_id]
            )
            message = session.signature_message(
                EnvelopeKind.RANDOMNESS_COMMITMENT,
                contributor.contributor_id,
                payload,
            )
            session.submit_commitment(
                SignedEnvelope(
                    contributor.contributor_id,
                    payload,
                    adapters[contributor.suite_id].sign(
                        secret_key=secrets[contributor.contributor_id], message=message
                    ),
                )
            )
        for contributor in contributors:
            payload = reveals[contributor.contributor_id]
            message = session.signature_message(
                EnvelopeKind.RANDOMNESS_REVEAL,
                contributor.contributor_id,
                payload,
            )
            session.submit_reveal(
                SignedEnvelope(
                    contributor.contributor_id,
                    payload,
                    adapters[contributor.suite_id].sign(
                        secret_key=secrets[contributor.contributor_id], message=message
                    ),
                )
            )
        session.finalize_round()
    return session, adapters


def test_full_selected_transcript_uses_real_dual_pq_and_derives_exact_bundle(
    completed_selected_session,
) -> None:
    session, adapters = completed_selected_session
    transcript = capture_selected_transcript(session)
    bundle = verify_selected_transcript(transcript, adapters)

    assert session.complete
    assert len(transcript.evidence) == 20
    assert bundle.proof_suite_id == transcript.schedule.proof_suite_id
    assert bundle.final_transcript_root == session.transcript_root
    assert len(bundle.fri_fold_coefficients) == len(bundle.fri_layer_roots) == 15
    assert len(bundle.query_positions) == 945
    assert all(0 <= value < 1 << 17 for value in bundle.query_positions)
    assert len(bundle.evidence_commitment) == 64
    encoded = encode_selected_challenge_bundle(bundle)
    assert decode_selected_challenge_bundle(encoded) == bundle
    with pytest.raises(Exception, match="truncated"):
        decode_selected_challenge_bundle(encoded[:-1])
    with pytest.raises(Exception, match="trailing_bytes"):
        decode_selected_challenge_bundle(encoded + b"X")


def test_selected_transcript_rejects_signature_and_root_order_tampering(
    completed_selected_session,
) -> None:
    session, adapters = completed_selected_session
    transcript = capture_selected_transcript(session)
    first = transcript.evidence[0]
    envelope = first.commitments[0]
    bad_signature = bytes((envelope.signature[0] ^ 1,)) + envelope.signature[1:]
    bad_first = replace(
        first,
        commitments=(replace(envelope, signature=bad_signature), *first.commitments[1:]),
    )
    forged = replace(transcript, evidence=(bad_first, *transcript.evidence[1:]))
    with pytest.raises(ValueError, match="signature_invalid"):
        verify_selected_transcript(forged, adapters)

    second = transcript.evidence[1]
    reordered = replace(
        transcript,
        evidence=(
            replace(first, prover_message=second.prover_message),
            *transcript.evidence[1:],
        ),
    )
    with pytest.raises(ValueError, match="prover_message_order_mismatch"):
        verify_selected_transcript(reordered, adapters)


def test_selected_transcript_requires_exact_locked_adapter_types(
    completed_selected_session,
) -> None:
    session, adapters = completed_selected_session
    transcript: SelectedPublicCoinTranscript = capture_selected_transcript(session)
    wrong = dict(adapters)
    wrong.pop(next(iter(wrong)))
    with pytest.raises(Exception, match="exact_locked_adapters_required"):
        verify_selected_transcript(transcript, wrong)
