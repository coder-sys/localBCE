"""Fail-closed evidence gate for a 392-bit Hint-MLWE redesign.

This module does not select or activate a proof system.  It prevents a
published 128-bit parameter set, a Fiat--Shamir transcript, or an unpinned
estimator result from being mistaken for a BL-PQ512 candidate.
"""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from typing import Final


PER_TERM_BITS: Final[int] = 392
TOTAL_BITS: Final[int] = 384
MAX_COMPOSED_TERMS_AT_FLOOR: Final[int] = 1 << (PER_TERM_BITS - TOTAL_BITS)
EXPECTED_UPSTREAM_COMMIT: Final[str] = (
    "c86212e45af9e957d1ae2be58c111e2d85b253be"
)
REQUIRED_SECURITY_TERMS: Final[tuple[str, ...]] = (
    "challenge_knowledge_error",
    "hint_mlwe_to_mlwe_reduction_loss",
    "mlwe_quantum_attack",
    "msis_binding_quantum_attack",
    "msis_knowledge_quantum_attack",
    "statistical_hiding_and_simulation",
)


def _bits_floor(probability: Fraction) -> int:
    if not isinstance(probability, Fraction) or not 0 < probability <= 1:
        raise ValueError("failure_probability_must_be_in_zero_one")
    numerator = probability.numerator
    denominator = probability.denominator
    result = denominator.bit_length() - numerator.bit_length()
    if numerator << result > denominator:
        result -= 1
    return result


def power_of_two_failure(bits: int) -> Fraction:
    if type(bits) is not int or bits < 0:
        raise ValueError("security_bits_must_be_nonnegative_integer")
    return Fraction(1, 1 << bits)


def minimum_independent_repetitions(single_challenge_bits: int) -> int:
    """Arithmetic lower bound only; this is not a repetition theorem."""

    if type(single_challenge_bits) is not int or single_challenge_bits <= 0:
        raise ValueError("challenge_bits_must_be_positive_integer")
    return (PER_TERM_BITS + single_challenge_bits - 1) // single_challenge_bits


@dataclass(frozen=True, slots=True)
class SecurityTerm:
    name: str
    failure_probability: Fraction | None
    theorem_reference: str
    derivation_artifact: str


@dataclass(frozen=True, slots=True)
class TranscriptProfile:
    mode: str
    authoritative_hash: str
    digest_bytes: int
    authenticated_public_coin: bool
    fiat_shamir_used: bool
    public_coin_security_bits: int


@dataclass(frozen=True, slots=True)
class Provenance:
    upstream_commit: str
    parameter_generator_commit: str
    estimator_name: str
    estimator_commit: str
    estimator_input_artifact: str
    estimator_output_artifact: str
    estimator_model_reviewed: bool


@dataclass(frozen=True, slots=True)
class CandidateEvidence:
    candidate_id: str
    terms: tuple[SecurityTerm, ...]
    transcript: TranscriptProfile
    provenance: Provenance
    composed_invocation_count: int


@dataclass(frozen=True, slots=True)
class GateResult:
    status: str
    minimum_term_bits: int | None
    total_bits: int | None
    failures: tuple[str, ...]


def evaluate_candidate(candidate: CandidateEvidence) -> GateResult:
    """Return BLOCKED or FEASIBILITY_ONLY; never return qualified/activated."""

    if type(candidate) is not CandidateEvidence:
        raise TypeError("candidate_evidence_required")
    failures: list[str] = []

    if not candidate.candidate_id:
        failures.append("candidate_id_missing")

    term_by_name: dict[str, SecurityTerm] = {}
    for term in candidate.terms:
        if term.name in term_by_name:
            failures.append(f"security_term_duplicate:{term.name}")
        term_by_name[term.name] = term
    unexpected = sorted(set(term_by_name).difference(REQUIRED_SECURITY_TERMS))
    for name in unexpected:
        failures.append(f"security_term_unexpected:{name}")

    probabilities: list[Fraction] = []
    minimum_term_bits: int | None = None
    for name in REQUIRED_SECURITY_TERMS:
        term = term_by_name.get(name)
        if term is None:
            failures.append(f"security_term_missing:{name}")
            continue
        if term.failure_probability is None:
            failures.append(f"security_probability_missing:{name}")
            continue
        try:
            bits = _bits_floor(term.failure_probability)
        except ValueError:
            failures.append(f"security_probability_invalid:{name}")
            continue
        probabilities.append(term.failure_probability)
        minimum_term_bits = bits if minimum_term_bits is None else min(
            minimum_term_bits, bits
        )
        if bits < PER_TERM_BITS:
            failures.append(f"security_term_below_392:{name}:{bits}")
        if not term.theorem_reference:
            failures.append(f"theorem_reference_missing:{name}")
        if not term.derivation_artifact:
            failures.append(f"derivation_artifact_missing:{name}")

    if (
        type(candidate.composed_invocation_count) is not int
        or candidate.composed_invocation_count <= 0
    ):
        failures.append("composed_invocation_count_invalid")
        total_bits = None
    elif len(probabilities) != len(REQUIRED_SECURITY_TERMS):
        total_bits = None
    else:
        one_invocation_error = sum(probabilities, Fraction())
        total_error = one_invocation_error * candidate.composed_invocation_count
        if total_error > 1:
            total_bits = 0
        else:
            total_bits = _bits_floor(total_error)
        if total_bits < TOTAL_BITS:
            failures.append(f"composed_security_below_384:{total_bits}")

    transcript = candidate.transcript
    if transcript.mode != "interactive":
        failures.append("transcript_not_interactive")
    if transcript.authoritative_hash != "sha3-512":
        failures.append("authoritative_hash_not_sha3_512")
    if transcript.digest_bytes != 64:
        failures.append("authoritative_digest_not_64_bytes")
    if not transcript.authenticated_public_coin:
        failures.append("public_coin_not_authenticated")
    if transcript.fiat_shamir_used:
        failures.append("fiat_shamir_forbidden")
    if transcript.public_coin_security_bits < PER_TERM_BITS:
        failures.append(
            "public_coin_below_392:"
            f"{transcript.public_coin_security_bits}"
        )

    provenance = candidate.provenance
    if provenance.upstream_commit != EXPECTED_UPSTREAM_COMMIT:
        failures.append("upstream_commit_mismatch")
    for label, value in (
        ("parameter_generator_commit", provenance.parameter_generator_commit),
        ("estimator_name", provenance.estimator_name),
        ("estimator_commit", provenance.estimator_commit),
        ("estimator_input_artifact", provenance.estimator_input_artifact),
        ("estimator_output_artifact", provenance.estimator_output_artifact),
    ):
        if not value:
            failures.append(f"{label}_missing")
    if not provenance.estimator_model_reviewed:
        failures.append("estimator_model_not_reviewed")

    return GateResult(
        status="BLOCKED" if failures else "FEASIBILITY_ONLY",
        minimum_term_bits=minimum_term_bits,
        total_bits=total_bits,
        failures=tuple(failures),
    )
