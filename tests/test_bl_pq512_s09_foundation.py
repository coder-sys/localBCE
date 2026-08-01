from __future__ import annotations

from hashlib import sha3_512
import json
from pathlib import Path

from experiments.bl_pq512_crypto_foundation.field16_reference import (
    ACCEPTANCE_MULTIPLIER,
    BASIS,
    FIELD_ORDER,
    HASH_SPACE,
    M31_MODULUS,
    REJECTION_COUNT,
    SAMPLE_DOMAIN_CODE,
    Fp16,
    rejection_failure_fraction,
    sample_uniform_fp16,
    tower_irreducibility_report,
)
from experiments.bl_pq512_crypto_foundation.oods_reference import (
    OODS_DEFAULT_MAX_ATTEMPTS,
    OODS_SAMPLE_DOMAIN_CODE,
    OodsParameter,
    oods_rejection_failure_fraction,
    sample_oods_parameter,
    stereographic_circle_point,
)
from experiments.bl_pq512_crypto_foundation.public_coin_reference import (
    AUDIT_DOMAIN,
    COMMITMENT_DOMAIN,
    Contributor,
    EnvelopeKind,
    OutputKind,
    PublicCoinSession,
    REVEAL_DOMAIN,
    ROUND_DOMAIN,
    RoundDescriptor,
    RoundKind,
    SCHEDULE_DOMAIN,
    SEED_DOMAIN,
    SignedEnvelope,
    sample_query_positions,
)


ROOT = Path(__file__).resolve().parents[1]
VECTORS = json.loads(
    (ROOT / "test_data" / "bl_pq512_s09_foundation_vectors.json").read_text(encoding="utf-8")
)
SUITES = ("FIPS204-ML-DSA-87", "FIPS205-SLH-DSA-SHAKE-256F")


class _SyntheticOnlyVerifier:
    synthetic_only = True

    def __init__(self, suite_id: str) -> None:
        self.suite_id = suite_id

    @staticmethod
    def sign(public_key: bytes, message: bytes) -> bytes:
        return sha3_512(b"TEST-ONLY" + len(public_key).to_bytes(2, "big") + public_key + message).digest()

    def verify(self, *, public_key: bytes, message: bytes, signature: bytes) -> bool:
        return signature == self.sign(public_key, message)


def _fixture() -> tuple[PublicCoinSession, dict[str, _SyntheticOnlyVerifier]]:
    verifiers = {suite: _SyntheticOnlyVerifier(suite) for suite in SUITES}
    contributors = tuple(
        sorted(
            (
                Contributor(
                    sha3_512(b"CONTRIBUTOR-A").digest(),
                    sha3_512(b"KEY-A").digest(),
                    SUITES[0],
                    b"A" * 64,
                ),
                Contributor(
                    sha3_512(b"CONTRIBUTOR-B").digest(),
                    sha3_512(b"KEY-B").digest(),
                    SUITES[1],
                    b"B" * 64,
                ),
            ),
            key=lambda contributor: contributor.contributor_id,
        )
    )
    schedule = (
        RoundDescriptor(RoundKind.COMPOSITION_COEFFICIENT, 0, OutputKind.FIELD16, 2),
        RoundDescriptor(RoundKind.QUERY_POSITIONS, 0, OutputKind.QUERY_SEED, 1),
    )
    return (
        PublicCoinSession(
            session_id=sha3_512(b"SESSION").digest(),
            public_outputs=bytes(384),
            sidecar=bytes(744),
            candidate_descriptor_sha3_512=sha3_512(b"CANDIDATE").digest(),
            schedule=schedule,
            contributors=contributors,
            verifiers=verifiers,
            production_mode=False,
        ),
        verifiers,
    )


def _complete_round(
    session: PublicCoinSession,
    verifiers: dict[str, _SyntheticOnlyVerifier],
    descriptor: RoundDescriptor,
    round_index: int,
):
    session.begin_round(descriptor, b"PROVER-MESSAGE-" + bytes([round_index]))
    reveals = {
        contributor.contributor_id: sha3_512(
            b"REVEAL-" + bytes([round_index]) + contributor.contributor_id
        ).digest()
        for contributor in session.contributors
    }
    for contributor in session.contributors:
        payload = session.commitment_for(contributor.contributor_id, reveals[contributor.contributor_id])
        message = session.signature_message(
            EnvelopeKind.RANDOMNESS_COMMITMENT, contributor.contributor_id, payload
        )
        signature = verifiers[contributor.suite_id].sign(contributor.public_key, message)
        session.submit_commitment(SignedEnvelope(contributor.contributor_id, payload, signature))
    for contributor in session.contributors:
        payload = reveals[contributor.contributor_id]
        message = session.signature_message(
            EnvelopeKind.RANDOMNESS_REVEAL, contributor.contributor_id, payload
        )
        signature = verifiers[contributor.suite_id].sign(contributor.public_key, message)
        session.submit_reveal(SignedEnvelope(contributor.contributor_id, payload, signature))
    return session.finalize_round()


def test_vector_is_nonactivating_and_algebra_is_exact() -> None:
    assert VECTORS["status"] == "SYNTHETIC_NONACTIVATING_REFERENCE"
    assert VECTORS["activationAllowed"] is False
    assert VECTORS["proofSuiteId"] is None
    assert VECTORS["algebra"]["baseModulus"] == M31_MODULUS
    assert VECTORS["algebra"]["extensionDegree"] == 16
    assert VECTORS["algebra"]["fieldOrderBitLength"] == FIELD_ORDER.bit_length() == 496
    assert tuple(VECTORS["algebra"]["basis"]) == BASIS
    assert tower_irreducibility_report() == VECTORS["algebra"]["irreducibilityEulerCriteria"]
    assert all(tower_irreducibility_report().values())
    registry = json.loads(
        (ROOT / "docs" / "bl_pq512_suite_candidate_v1.json").read_text(encoding="utf-8")
    )
    domains = {entry["code"]: entry["name"] for entry in registry["domainRegistry"]}
    assert {
        ROUND_DOMAIN: "BL/PQ512/v1/TRANSCRIPT/PUBLIC-COIN-ROUND",
        COMMITMENT_DOMAIN: "BL/PQ512/v1/TRANSCRIPT/RANDOMNESS-COMMITMENT",
        REVEAL_DOMAIN: "BL/PQ512/v1/TRANSCRIPT/RANDOMNESS-REVEAL",
        SEED_DOMAIN: "BL/PQ512/v1/TRANSCRIPT/PUBLIC-CHALLENGE-SEED",
        SAMPLE_DOMAIN_CODE: "BL/PQ512/v1/TRANSCRIPT/FIELD16-REJECTION-DRAW",
        AUDIT_DOMAIN: "BL/PQ512/v1/TRANSCRIPT/AUDIT-ROOT",
        SCHEDULE_DOMAIN: "BL/PQ512/v1/TRANSCRIPT/SCHEDULE",
        OODS_SAMPLE_DOMAIN_CODE: "BL/PQ512/v1/TRANSCRIPT/OODS-FP8-EXCLUDING-DRAW",
    }.items() <= domains.items()


def test_field_multiplication_inverse_encoding_and_identities_match_kat() -> None:
    kat = VECTORS["fieldKat"]
    left = Fp16(tuple(kat["leftCoefficients"]))
    right = Fp16(tuple(kat["rightCoefficients"]))
    assert (left * right).encode().hex() == kat["productHex"]
    assert left.inverse().encode().hex() == kat["leftInverseHex"]
    assert left * left.inverse() == Fp16.one()
    assert Fp16.decode(left.encode()) == left

    values = tuple(
        Fp16(tuple(((seed + 1) * (index + 3) * 7919) % M31_MODULUS for index in range(16)))
        for seed in range(12)
    )
    for index in range(10):
        a, b, c = values[index : index + 3]
        assert (a + b) + c == a + (b + c)
        assert (a * b) * c == a * (b * c)
        assert a * (b + c) == (a * b) + (a * c)
        assert a * a.inverse() == Fp16.one()


def test_uniform_sampler_and_exact_abort_bound_match_kat() -> None:
    kat = VECTORS["samplerKat"]
    sampled = sample_uniform_fp16(
        bytes.fromhex(kat["seedHex"]),
        session_id=bytes.fromhex(kat["sessionIdHex"]),
        round_index=kat["roundIndex"],
        draw_index=kat["drawIndex"],
    )
    assert sampled.accepted_attempt == kat["acceptedAttempt"]
    assert sampled.digest.hex() == kat["digestHex"]
    assert sampled.element.encode().hex() == kat["elementHex"]
    assert ACCEPTANCE_MULTIPLIER == kat["acceptanceMultiplier"] == 65536
    assert REJECTION_COUNT == kat["rejectionCount"]
    assert HASH_SPACE == ACCEPTANCE_MULTIPLIER * FIELD_ORDER + REJECTION_COUNT
    numerator, denominator = rejection_failure_fraction(kat["attemptCap"])
    assert numerator * (1 << 432) < denominator


def test_oods_sampler_excludes_fp8_and_matches_cross_language_kat() -> None:
    kat = VECTORS["oodsSamplerKat"]
    sampled = sample_oods_parameter(
        bytes.fromhex(kat["seedHex"]),
        session_id=bytes.fromhex(kat["sessionIdHex"]),
        round_index=kat["roundIndex"],
    )
    assert sampled.accepted_attempt == kat["acceptedAttempt"]
    assert sampled.digest.hex() == kat["digestHex"]
    assert sampled.parameter.element.encode().hex() == kat["elementHex"]
    assert sampled.parameter.element.coefficients[8:] != (0,) * 8
    assert sampled.parameter.element != sampled.parameter.element.conjugate()

    point = stereographic_circle_point(sampled.parameter)
    assert point.x.encode().hex() == kat["circleXHex"]
    assert point.y.encode().hex() == kat["circleYHex"]
    assert point.x * point.x + point.y * point.y == Fp16.one()

    numerator, denominator = oods_rejection_failure_fraction(OODS_DEFAULT_MAX_ATTEMPTS)
    assert numerator * (1 << 432) < denominator


def test_oods_round_is_authenticated_and_audit_replayable() -> None:
    kat = VECTORS["publicCoinOodsKat"]
    session, verifiers = _fixture_with_oods_round()
    output = _complete_round(session, verifiers, session.schedule[0], 0)
    assert output.seed.hex() == kat["seedHex"]
    assert len(output.field_elements) == 1
    assert output.field_elements[0].encode().hex() == kat["elementHex"]
    assert output.oods_sample is not None
    assert output.oods_sample.accepted_attempt == kat["acceptedAttempt"]
    assert output.oods_sample.digest.hex() == kat["digestHex"]
    assert session.transcript_root.hex() == kat["finalRootHex"]
    assert session.complete


def test_public_coin_transcript_and_query_positions_match_kat() -> None:
    kat = VECTORS["publicCoinKat"]
    session, verifiers = _fixture()
    assert session.transcript_root.hex() == kat["initialRootHex"]
    assert session.schedule_digest.hex() == kat["scheduleDigestHex"]

    first = _complete_round(session, verifiers, session.schedule[0], 0)
    assert first.seed.hex() == kat["round0SeedHex"]
    assert session.transcript_root.hex() == kat["round0RootHex"]
    assert [element.encode().hex() for element in first.field_elements] == kat["round0FieldElementsHex"]

    second = _complete_round(session, verifiers, session.schedule[1], 1)
    assert second.seed.hex() == kat["round1SeedHex"]
    assert session.transcript_root.hex() == kat["finalRootHex"]
    assert session.complete
    assert len(session.evidence) == 2
    assert session.evidence[1].prior_root == session.evidence[0].resulting_root
    assert sample_query_positions(
        second.seed,
        session_id=session.session_id,
        domain_size=1 << 20,
        query_count=16,
        with_replacement=False,
    ) == tuple(kat["queryPositionsDomain2Pow20"])


def _fixture_with_oods_round() -> tuple[PublicCoinSession, dict[str, _SyntheticOnlyVerifier]]:
    _, verifiers = _fixture()
    contributors = tuple(
        sorted(
            (
                Contributor(
                    sha3_512(b"CONTRIBUTOR-A").digest(),
                    sha3_512(b"KEY-A").digest(),
                    SUITES[0],
                    b"A" * 64,
                ),
                Contributor(
                    sha3_512(b"CONTRIBUTOR-B").digest(),
                    sha3_512(b"KEY-B").digest(),
                    SUITES[1],
                    b"B" * 64,
                ),
            ),
            key=lambda contributor: contributor.contributor_id,
        )
    )
    descriptor = RoundDescriptor(RoundKind.OODS_POINT_PARAMETER, 0, OutputKind.FIELD16, 1)
    return (
        PublicCoinSession(
            session_id=sha3_512(b"OODS-KAT-SESSION").digest(),
            public_outputs=bytes(384),
            sidecar=bytes(744),
            candidate_descriptor_sha3_512=sha3_512(b"OODS-KAT-CANDIDATE").digest(),
            schedule=(descriptor,),
            contributors=contributors,
            verifiers=verifiers,
            production_mode=False,
        ),
        verifiers,
    )
