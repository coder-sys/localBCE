from __future__ import annotations

from hashlib import sha3_512
from unittest.mock import patch

import pytest

from experiments.bl_pq512_crypto_foundation.field16_reference import (
    ACCEPTANCE_LIMIT,
    Fp16,
    sample_uniform_fp16,
)
from experiments.bl_pq512_crypto_foundation.oods_reference import (
    OodsParameter,
    sample_oods_parameter,
)
from experiments.bl_pq512_crypto_foundation.public_coin_reference import (
    Contributor,
    EnvelopeKind,
    OutputKind,
    PublicCoinSession,
    RoundDescriptor,
    RoundKind,
    SignedEnvelope,
)


SUITES = ("FIPS204-ML-DSA-87", "FIPS205-SLH-DSA-SHAKE-256F")


class _SyntheticOnlyVerifier:
    synthetic_only = True

    def __init__(self, suite_id: str, *, raises: bool = False) -> None:
        self.suite_id = suite_id
        self.raises = raises

    @staticmethod
    def sign(public_key: bytes, message: bytes) -> bytes:
        return sha3_512(b"TEST-ONLY" + public_key + message).digest()

    def verify(self, *, public_key: bytes, message: bytes, signature: bytes) -> bool:
        if self.raises:
            raise RuntimeError("synthetic verifier failure")
        return signature == self.sign(public_key, message)


def _parts(*, same_suite: bool = False, verifier_raises: bool = False):
    suites = (SUITES[0], SUITES[0] if same_suite else SUITES[1])
    contributors = tuple(
        sorted(
            (
                Contributor(sha3_512(b"A").digest(), sha3_512(b"KA").digest(), suites[0], b"A" * 64),
                Contributor(sha3_512(b"B").digest(), sha3_512(b"KB").digest(), suites[1], b"B" * 64),
            ),
            key=lambda contributor: contributor.contributor_id,
        )
    )
    verifiers = {
        suite: _SyntheticOnlyVerifier(suite, raises=verifier_raises) for suite in set(suites)
    }
    return contributors, verifiers


def _session(*, same_suite: bool = False, verifier_raises: bool = False, production: bool = False):
    contributors, verifiers = _parts(same_suite=same_suite, verifier_raises=verifier_raises)
    descriptor = RoundDescriptor(RoundKind.COMPOSITION_COEFFICIENT, 0, OutputKind.FIELD16, 1)
    session = PublicCoinSession(
        session_id=sha3_512(b"ATTACK-SESSION").digest(),
        public_outputs=bytes(384),
        sidecar=bytes(744),
        candidate_descriptor_sha3_512=sha3_512(b"ATTACK-CANDIDATE").digest(),
        schedule=(descriptor,),
        contributors=contributors,
        verifiers=verifiers,
        production_mode=production,
    )
    return session, verifiers, descriptor


def _signed(session, verifier, contributor, kind, payload):
    message = session.signature_message(kind, contributor.contributor_id, payload)
    return SignedEnvelope(
        contributor.contributor_id,
        payload,
        verifier.sign(contributor.public_key, message),
    )


def test_synthetic_verifiers_and_single_suite_are_forbidden_in_production() -> None:
    with pytest.raises(ValueError, match="synthetic_signature_verifier_forbidden"):
        _session(production=True)
    with pytest.raises(ValueError, match="requires_pq_suite_diversity"):
        _session(same_suite=True, production=True)


def test_wrong_round_order_aborts_permanently() -> None:
    session, _, _ = _session()
    wrong = RoundDescriptor(RoundKind.OODS_POINT_PARAMETER, 0, OutputKind.FIELD16, 1)
    with pytest.raises(ValueError, match="unexpected_round_descriptor"):
        session.begin_round(wrong, b"prover")
    assert session.phase == "ABORTED"
    with pytest.raises(RuntimeError, match="session_aborted"):
        session.begin_round(session.schedule[0], b"prover")


def test_reveal_before_all_commitments_and_invalid_signatures_are_rejected() -> None:
    session, verifiers, descriptor = _session()
    session.begin_round(descriptor, b"prover")
    contributor = session.contributors[0]
    reveal = sha3_512(b"REVEAL").digest()
    premature = _signed(
        session,
        verifiers[contributor.suite_id],
        contributor,
        EnvelopeKind.RANDOMNESS_REVEAL,
        reveal,
    )
    with pytest.raises(RuntimeError, match="reveal_before_all_commitments"):
        session.submit_reveal(premature)

    commitment = session.commitment_for(contributor.contributor_id, reveal)
    with pytest.raises(ValueError, match="signature_invalid"):
        session.submit_commitment(SignedEnvelope(contributor.contributor_id, commitment, b"X" * 64))
    assert session.phase == "COMMIT"


def test_commit_reveal_mismatch_and_missing_reveal_abort_instead_of_biasing() -> None:
    session, verifiers, descriptor = _session()
    session.begin_round(descriptor, b"prover")
    reveals = {c.contributor_id: sha3_512(b"R" + c.contributor_id).digest() for c in session.contributors}
    for contributor in session.contributors:
        commitment = session.commitment_for(contributor.contributor_id, reveals[contributor.contributor_id])
        session.submit_commitment(
            _signed(
                session,
                verifiers[contributor.suite_id],
                contributor,
                EnvelopeKind.RANDOMNESS_COMMITMENT,
                commitment,
            )
        )
    first = session.contributors[0]
    forged = bytes([reveals[first.contributor_id][0] ^ 1]) + reveals[first.contributor_id][1:]
    with pytest.raises(ValueError, match="commitment_reveal_mismatch"):
        session.submit_reveal(
            _signed(
                session,
                verifiers[first.suite_id],
                first,
                EnvelopeKind.RANDOMNESS_REVEAL,
                forged,
            )
        )
    assert session.phase == "ABORTED"

    session, verifiers, descriptor = _session()
    session.begin_round(descriptor, b"prover")
    reveals = {c.contributor_id: sha3_512(b"R2" + c.contributor_id).digest() for c in session.contributors}
    for contributor in session.contributors:
        commitment = session.commitment_for(contributor.contributor_id, reveals[contributor.contributor_id])
        session.submit_commitment(
            _signed(
                session,
                verifiers[contributor.suite_id],
                contributor,
                EnvelopeKind.RANDOMNESS_COMMITMENT,
                commitment,
            )
        )
    contributor = session.contributors[0]
    session.submit_reveal(
        _signed(
            session,
            verifiers[contributor.suite_id],
            contributor,
            EnvelopeKind.RANDOMNESS_REVEAL,
            reveals[contributor.contributor_id],
        )
    )
    with pytest.raises(RuntimeError, match="missing_reveal_aborts"):
        session.finalize_round()
    assert session.phase == "ABORTED"


def test_signature_verifier_exceptions_fail_closed() -> None:
    session, verifiers, descriptor = _session(verifier_raises=True)
    session.begin_round(descriptor, b"prover")
    contributor = session.contributors[0]
    reveal = sha3_512(b"R").digest()
    commitment = session.commitment_for(contributor.contributor_id, reveal)
    envelope = _signed(
        session,
        verifiers[contributor.suite_id],
        contributor,
        EnvelopeKind.RANDOMNESS_COMMITMENT,
        commitment,
    )
    with pytest.raises(ValueError, match="verifier_failed_closed"):
        session.submit_commitment(envelope)


def test_randomness_commitment_binds_prior_root_and_prover_message() -> None:
    first, _, descriptor = _session()
    second, _, _ = _session()
    first.begin_round(descriptor, b"prover-message-a")
    second.begin_round(descriptor, b"prover-message-b")
    contributor_id = first.contributors[0].contributor_id
    reveal = sha3_512(b"SAME-REVEAL").digest()
    assert first.commitment_for(contributor_id, reveal) != second.commitment_for(contributor_id, reveal)


def test_field_parser_and_rejection_sampler_fail_closed() -> None:
    malformed = bytearray(Fp16.one().encode())
    malformed[0:4] = ((1 << 31) - 1).to_bytes(4, "big")
    with pytest.raises(ValueError, match="coefficient_not_canonical"):
        Fp16.decode(bytes(malformed))
    with pytest.raises(ValueError, match="encoding_length_mismatch"):
        Fp16.decode(bytes(63))

    class _Digest:
        def digest(self) -> bytes:
            return ACCEPTANCE_LIMIT.to_bytes(64, "big")

    with patch(
        "experiments.bl_pq512_crypto_foundation.field16_reference.sha3_512",
        return_value=_Digest(),
    ):
        with pytest.raises(RuntimeError, match="attempt_cap_exhausted"):
            sample_uniform_fp16(
                bytes(64),
                session_id=bytes([1]) * 64,
                round_index=0,
                draw_index=0,
                max_attempts=2,
            )


def test_oods_parameter_rejects_fixed_subfield_and_malformed_descriptors() -> None:
    fixed_subfield = Fp16((1, 2, 3, 4, 5, 6, 7, 8) + (0,) * 8)
    with pytest.raises(ValueError, match="oods_parameter_in_fp8_fixed_subfield"):
        OodsParameter(fixed_subfield)
    with pytest.raises(ValueError, match="oods_output_must_be_one_field16"):
        RoundDescriptor(RoundKind.OODS_POINT_PARAMETER, 0, OutputKind.FIELD16, 2)
    with pytest.raises(ValueError, match="oods_output_must_be_one_field16"):
        RoundDescriptor(RoundKind.OODS_POINT_PARAMETER, 0, OutputKind.QUERY_SEED, 1)


def test_oods_parameter_round_uses_theorem_matched_sampler() -> None:
    contributors, verifiers = _parts()
    descriptor = RoundDescriptor(RoundKind.OODS_POINT_PARAMETER, 0, OutputKind.FIELD16, 1)
    session = PublicCoinSession(
        session_id=sha3_512(b"OODS-STOP-SESSION").digest(),
        public_outputs=bytes(384),
        sidecar=bytes(744),
        candidate_descriptor_sha3_512=sha3_512(b"OODS-STOP-CANDIDATE").digest(),
        schedule=(descriptor,),
        contributors=contributors,
        verifiers=verifiers,
        production_mode=False,
    )
    session.begin_round(descriptor, b"prover")
    reveals = {
        contributor.contributor_id: sha3_512(b"OODS-REVEAL" + contributor.contributor_id).digest()
        for contributor in session.contributors
    }
    for contributor in session.contributors:
        commitment = session.commitment_for(
            contributor.contributor_id, reveals[contributor.contributor_id]
        )
        session.submit_commitment(
            _signed(
                session,
                verifiers[contributor.suite_id],
                contributor,
                EnvelopeKind.RANDOMNESS_COMMITMENT,
                commitment,
            )
        )
    for contributor in session.contributors:
        session.submit_reveal(
            _signed(
                session,
                verifiers[contributor.suite_id],
                contributor,
                EnvelopeKind.RANDOMNESS_REVEAL,
                reveals[contributor.contributor_id],
            )
        )

    challenge = session.finalize_round()
    assert session.phase == "COMPLETE"
    assert challenge.oods_sample is not None
    assert challenge.field_elements == (challenge.oods_sample.parameter.element,)
    assert challenge.field_elements[0].coefficients[8:] != (0,) * 8


def test_oods_attempt_cap_exhaustion_fails_closed() -> None:
    class _Digest:
        def digest(self) -> bytes:
            return ACCEPTANCE_LIMIT.to_bytes(64, "big")

    with patch(
        "experiments.bl_pq512_crypto_foundation.oods_reference.sha3_512",
        return_value=_Digest(),
    ):
        with pytest.raises(RuntimeError, match="attempt_cap_exhausted"):
            sample_oods_parameter(
                bytes(64),
                session_id=bytes([1]) * 64,
                round_index=0,
                max_attempts=2,
            )
