"""Fixed-shape authenticated interactive public-coin transcript prototype.

This module implements exact challenge sampling and SHA3-512 transcript
binding. The caller must supply a real 392-bit-PQ authentication verifier;
this prototype deliberately does not select or simulate that backend.
"""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from hashlib import sha3_512
from typing import Protocol

from experiments.bl_pq512_hint_mlwe_392.challenge_space import (
    autostable_coefficients,
    conservative_challenge_bits,
)


DOMAIN = b"BL-HINT-MLWE-INTERACTIVE-PUBLIC-COIN-v1"
COIN_BLOCK_BYTES = 64
COIN_BLOCK_COUNT = 4
DIGEST_BYTES = 64
ID_BYTES = 64


class AuthenticationVerifier(Protocol):
    def verify(
        self,
        authenticator_id: bytes,
        parameter_id: bytes,
        signed_payload: bytes,
        authentication_evidence: bytes,
    ) -> bool: ...


@dataclass(frozen=True, slots=True)
class CoinProfile:
    degree: int
    omega: int
    prover_commitment_bytes: int
    authentication_evidence_bytes: int


@dataclass(frozen=True, slots=True)
class CoinEnvelope:
    session_id: bytes
    prior_transcript_digest: bytes
    authenticator_id: bytes
    parameter_id: bytes
    round_index: int
    coin_blocks: tuple[bytes, ...]
    authentication_evidence: bytes


@dataclass(frozen=True, slots=True)
class PublicChallenge:
    independent_coefficients: tuple[int, ...]
    autostable_coefficients: tuple[int, ...]
    selected_block_index: int
    conservative_bits: int
    all_blocks_rejected_probability: Fraction


def _u32(value: int) -> bytes:
    if type(value) is not int or not 0 <= value < (1 << 32):
        raise ValueError("u32_out_of_range")
    return value.to_bytes(4, "big")


def _length_prefixed(value: bytes) -> bytes:
    return _u32(len(value)) + value


def _bits_floor(probability: Fraction) -> int:
    if not 0 < probability <= 1:
        raise ValueError("probability_must_be_in_zero_one")
    numerator = probability.numerator
    denominator = probability.denominator
    result = denominator.bit_length() - numerator.bit_length()
    if numerator << result > denominator:
        result -= 1
    return result


def signed_coin_payload(envelope: CoinEnvelope) -> bytes:
    if len(envelope.session_id) != ID_BYTES:
        raise ValueError("session_id_must_be_64_bytes")
    if len(envelope.prior_transcript_digest) != DIGEST_BYTES:
        raise ValueError("prior_digest_must_be_64_bytes")
    if len(envelope.authenticator_id) != ID_BYTES:
        raise ValueError("authenticator_id_must_be_64_bytes")
    if len(envelope.parameter_id) != ID_BYTES:
        raise ValueError("parameter_id_must_be_64_bytes")
    if len(envelope.coin_blocks) != COIN_BLOCK_COUNT:
        raise ValueError("coin_block_count_mismatch")
    if any(len(block) != COIN_BLOCK_BYTES for block in envelope.coin_blocks):
        raise ValueError("coin_block_width_mismatch")
    return b"".join(
        (
            _length_prefixed(DOMAIN),
            envelope.session_id,
            envelope.prior_transcript_digest,
            envelope.authenticator_id,
            envelope.parameter_id,
            _u32(envelope.round_index),
            b"".join(envelope.coin_blocks),
        )
    )


def sample_exact_challenge(
    coin_blocks: tuple[bytes, ...], degree: int, omega: int
) -> PublicChallenge:
    if type(degree) is not int or degree <= 0 or degree % 2:
        raise ValueError("degree_must_be_positive_even")
    if type(omega) is not int or omega <= 0:
        raise ValueError("omega_must_be_positive_integer")
    if len(coin_blocks) != COIN_BLOCK_COUNT:
        raise ValueError("coin_block_count_mismatch")
    if any(len(block) != COIN_BLOCK_BYTES for block in coin_blocks):
        raise ValueError("coin_block_width_mismatch")

    base = 2 * omega + 1
    independent_count = degree // 2
    cardinality = base**independent_count
    source_size = 1 << (8 * COIN_BLOCK_BYTES)
    accepted_size = (source_size // cardinality) * cardinality
    tail_size = source_size - accepted_size
    block_failure = Fraction(tail_size, source_size)

    selected_index: int | None = None
    selected_value: int | None = None
    for index, block in enumerate(coin_blocks):
        value = int.from_bytes(block, "big")
        if value < accepted_size:
            selected_index = index
            selected_value = value % cardinality
            break
    if selected_index is None or selected_value is None:
        raise ValueError(
            "all_public_coin_blocks_rejected:"
            f"failure_bits={_bits_floor(block_failure**COIN_BLOCK_COUNT)}"
        )

    independent: list[int] = []
    for _ in range(independent_count):
        digit = selected_value % base
        selected_value //= base
        independent.append(digit - omega)
    independent_tuple = tuple(independent)
    return PublicChallenge(
        independent_coefficients=independent_tuple,
        autostable_coefficients=autostable_coefficients(
            independent_tuple
        ),
        selected_block_index=selected_index,
        conservative_bits=conservative_challenge_bits(degree, omega),
        all_blocks_rejected_probability=(
            block_failure**COIN_BLOCK_COUNT
        ),
    )


class InteractivePublicCoinTranscript:
    def __init__(
        self,
        *,
        profile: CoinProfile,
        session_id: bytes,
        statement_digest: bytes,
        authenticator: AuthenticationVerifier,
    ) -> None:
        if len(session_id) != ID_BYTES:
            raise ValueError("session_id_must_be_64_bytes")
        if len(statement_digest) != DIGEST_BYTES:
            raise ValueError("statement_digest_must_be_64_bytes")
        if profile.prover_commitment_bytes <= 0:
            raise ValueError("prover_commitment_bytes_must_be_positive")
        if profile.authentication_evidence_bytes <= 0:
            raise ValueError(
                "authentication_evidence_bytes_must_be_positive"
            )
        self._profile = profile
        self._session_id = session_id
        self._authenticator = authenticator
        self._state = "awaiting_prover_commitment"
        self._digest = sha3_512(
            b"".join(
                (
                    _length_prefixed(DOMAIN),
                    session_id,
                    statement_digest,
                    _u32(profile.degree),
                    _u32(profile.omega),
                    _u32(profile.prover_commitment_bytes),
                    _u32(profile.authentication_evidence_bytes),
                )
            )
        ).digest()

    @property
    def digest(self) -> bytes:
        return self._digest

    @property
    def state(self) -> str:
        return self._state

    def absorb_prover_commitment(self, commitment: bytes) -> bytes:
        if self._state != "awaiting_prover_commitment":
            raise ValueError("prover_commitment_wrong_transcript_state")
        if len(commitment) != self._profile.prover_commitment_bytes:
            raise ValueError("prover_commitment_width_mismatch")
        self._digest = sha3_512(
            self._digest
            + _length_prefixed(b"prover-commitment")
            + commitment
        ).digest()
        self._state = "awaiting_authenticated_coin"
        return self._digest

    def accept_coin(self, envelope: CoinEnvelope) -> PublicChallenge:
        if self._state != "awaiting_authenticated_coin":
            raise ValueError("public_coin_wrong_transcript_state")
        if envelope.session_id != self._session_id:
            raise ValueError("public_coin_session_mismatch")
        if envelope.prior_transcript_digest != self._digest:
            raise ValueError("public_coin_prior_digest_mismatch")
        if envelope.round_index != 0:
            raise ValueError("public_coin_round_mismatch")
        if (
            len(envelope.authentication_evidence)
            != self._profile.authentication_evidence_bytes
        ):
            raise ValueError("authentication_evidence_width_mismatch")
        payload = signed_coin_payload(envelope)
        if not self._authenticator.verify(
            envelope.authenticator_id,
            envelope.parameter_id,
            payload,
            envelope.authentication_evidence,
        ):
            raise ValueError("public_coin_authentication_failed")
        challenge = sample_exact_challenge(
            envelope.coin_blocks,
            self._profile.degree,
            self._profile.omega,
        )
        self._digest = sha3_512(
            self._digest
            + _length_prefixed(b"authenticated-verifier-coin")
            + _length_prefixed(payload)
            + _length_prefixed(envelope.authentication_evidence)
        ).digest()
        self._state = "challenge_accepted"
        return challenge

