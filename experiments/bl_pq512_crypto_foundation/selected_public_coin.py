"""Authenticated selected-suite transcript replay and verifier bundle.

The Rust proof verifier consumes only challenges that have first passed this
exact dual-suite PQ transcript replay.  All signatures, commitments, reveals,
prover-message order, roots, and query positions are re-derived here.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
from typing import Final, Mapping

from experiments.bl_pq512_crypto_foundation.field16_reference import Fp16
from experiments.bl_pq512_crypto_foundation.oods_reference import (
    CirclePoint,
    stereographic_circle_point,
)
from experiments.bl_pq512_crypto_foundation.pq_signature_adapters import (
    is_exact_supported_adapter,
)
from experiments.bl_pq512_crypto_foundation.public_coin_reference import (
    Contributor,
    PublicCoinSession,
    RoundEvidence,
    SelectedTheoremRoundSchedule,
    TheoremProverMessage,
    sample_query_positions,
)
from experiments.bl_pq512_crypto_foundation.selected_proof_parameters import proof_suite_id
from experiments.fixed_shape_claim_air.semantics import StructuralError


TRANSCRIPT_EVIDENCE_DOMAIN: Final[bytes] = (
    b"BL/PQ512/WAVE1B/SELECTED-PUBLIC-COIN-EVIDENCE/v1\x00"
)
PRODUCTION_STATEMENT_EVIDENCE_DOMAIN: Final[bytes] = (
    b"BL/PQ512/PRODUCTION-CANDIDATE/EVIDENCE/v1\x00"
)
CHALLENGE_BUNDLE_MAGIC: Final[bytes] = b"BLPQSCB1"
CHALLENGE_BUNDLE_VERSION: Final[int] = 1
MAX_CHALLENGE_BUNDLE_BYTES: Final[int] = 1 << 20
SELECTED_TRANSCRIPT_MAGIC: Final[bytes] = b"BLPQTR01"
SELECTED_TRANSCRIPT_VERSION: Final[int] = 1
MAX_SELECTED_TRANSCRIPT_BYTES: Final[int] = 16 << 20

_PQ_SUITE_CODES: Final[dict[str, int]] = {
    "FIPS204-ML-DSA-87": 1,
    "FIPS205-SLH-DSA-SHAKE-256F": 2,
}


def _framed_hash_domain(domain: bytes, *parts: bytes) -> bytes:
    digest = sha3_512(domain)
    for part in parts:
        if type(part) is not bytes or len(part) > 0xFFFF_FFFF:
            raise StructuralError("selected_public_coin_evidence_part_invalid")
        digest.update(len(part).to_bytes(4, "big"))
        digest.update(part)
    return digest.digest()


def _framed_hash(*parts: bytes) -> bytes:
    return _framed_hash_domain(TRANSCRIPT_EVIDENCE_DOMAIN, *parts)


@dataclass(frozen=True, slots=True)
class SelectedPublicCoinTranscript:
    session_id: bytes
    public_outputs: bytes
    sidecar: bytes
    schedule: SelectedTheoremRoundSchedule
    contributors: tuple[Contributor, ...]
    evidence: tuple[RoundEvidence, ...]
    final_transcript_root: bytes

    def __post_init__(self) -> None:
        if type(self.schedule) is not SelectedTheoremRoundSchedule:
            raise TypeError("selected_public_coin_schedule_required")
        if type(self.evidence) is not tuple or len(self.evidence) != len(
            self.schedule.descriptors
        ):
            raise StructuralError("selected_public_coin_evidence_count_mismatch")
        if tuple(item.round_index for item in self.evidence) != tuple(
            range(len(self.evidence))
        ):
            raise StructuralError("selected_public_coin_evidence_order_invalid")
        for label, value in (
            ("session", self.session_id),
            ("final_root", self.final_transcript_root),
        ):
            if type(value) is not bytes or len(value) != 64 or not any(value):
                raise StructuralError(f"selected_public_coin_{label}_invalid")


@dataclass(frozen=True, slots=True)
class SelectedChallengeBundle:
    proof_suite_id: bytes
    parameter_commitment: bytes
    program_binary_commitment: bytes
    schedule_commitment: bytes
    session_id: bytes
    final_transcript_root: bytes
    evidence_commitment: bytes
    main_trace_root: bytes
    interaction_trace_root: bytes
    composition_root: bytes
    oods_claims_commitment: bytes
    fri_mask_root: bytes
    fri_batch_derivation_commitment: bytes
    fri_layer_roots: tuple[bytes, ...]
    logup_beta: Fp16
    logup_gamma: Fp16
    composition_alpha: Fp16
    oods_point: CirclePoint
    fri_batch_coefficient: Fp16
    fri_fold_coefficients: tuple[Fp16, ...]
    query_seed: bytes
    query_positions: tuple[int, ...]

    def __post_init__(self) -> None:
        for name in (
            "proof_suite_id",
            "parameter_commitment",
            "program_binary_commitment",
            "schedule_commitment",
            "session_id",
            "final_transcript_root",
            "evidence_commitment",
            "main_trace_root",
            "interaction_trace_root",
            "composition_root",
            "oods_claims_commitment",
            "fri_mask_root",
            "fri_batch_derivation_commitment",
            "query_seed",
        ):
            value = getattr(self, name)
            if type(value) is not bytes or len(value) != 64 or not any(value):
                raise StructuralError(f"selected_challenge_bundle_{name}_invalid")
        if (
            type(self.fri_layer_roots) is not tuple
            or not self.fri_layer_roots
            or any(type(value) is not bytes or len(value) != 64 for value in self.fri_layer_roots)
            or len(self.fri_fold_coefficients) != len(self.fri_layer_roots)
            or type(self.query_positions) is not tuple
            or not self.query_positions
        ):
            raise StructuralError("selected_challenge_bundle_shape_invalid")


def encode_selected_challenge_bundle(bundle: SelectedChallengeBundle) -> bytes:
    if type(bundle) is not SelectedChallengeBundle:
        raise TypeError("selected_challenge_bundle_required")
    roots = (
        bundle.proof_suite_id,
        bundle.parameter_commitment,
        bundle.program_binary_commitment,
        bundle.schedule_commitment,
        bundle.session_id,
        bundle.final_transcript_root,
        bundle.evidence_commitment,
        bundle.main_trace_root,
        bundle.interaction_trace_root,
        bundle.composition_root,
        bundle.oods_claims_commitment,
        bundle.fri_mask_root,
        bundle.fri_batch_derivation_commitment,
    )
    encoded = b"".join(
        (
            CHALLENGE_BUNDLE_MAGIC,
            CHALLENGE_BUNDLE_VERSION.to_bytes(2, "big"),
            *roots,
            len(bundle.fri_layer_roots).to_bytes(2, "big"),
            *bundle.fri_layer_roots,
            bundle.logup_beta.encode(),
            bundle.logup_gamma.encode(),
            bundle.composition_alpha.encode(),
            bundle.oods_point.x.encode(),
            bundle.oods_point.y.encode(),
            bundle.fri_batch_coefficient.encode(),
            len(bundle.fri_fold_coefficients).to_bytes(2, "big"),
            *(value.encode() for value in bundle.fri_fold_coefficients),
            bundle.query_seed,
            len(bundle.query_positions).to_bytes(2, "big"),
            *(value.to_bytes(8, "big") for value in bundle.query_positions),
        )
    )
    if len(encoded) > MAX_CHALLENGE_BUNDLE_BYTES:
        raise StructuralError("selected_challenge_bundle_size_cap_exceeded")
    return encoded


def encode_selected_transcript_evidence(
    transcript: SelectedPublicCoinTranscript,
) -> bytes:
    """Encode the complete private transcript for Rust-authoritative replay.

    This is proof-private evidence.  It is never a public output, calldata,
    log, or telemetry field.  Challenges are intentionally omitted because
    the Rust verifier derives them from the authenticated seed and checks
    them against the selected challenge bundle.
    """

    if type(transcript) is not SelectedPublicCoinTranscript:
        raise TypeError("selected_public_coin_transcript_required")
    expected_suite = proof_suite_id(
        transcript.schedule.program_binary_commitment,
        transcript.schedule.schedule_commitment,
    )
    if transcript.schedule.proof_suite_id != expected_suite:
        raise StructuralError("selected_public_coin_transcript_suite_mismatch")
    encoded = bytearray(
        b"".join(
            (
                SELECTED_TRANSCRIPT_MAGIC,
                SELECTED_TRANSCRIPT_VERSION.to_bytes(2, "big"),
                transcript.session_id,
                transcript.public_outputs,
                transcript.sidecar,
                transcript.schedule.proof_suite_id,
                transcript.schedule.schedule_commitment,
                len(transcript.contributors).to_bytes(2, "big"),
            )
        )
    )
    for contributor in transcript.contributors:
        try:
            suite_code = _PQ_SUITE_CODES[contributor.suite_id]
        except KeyError as exc:
            raise StructuralError("selected_public_coin_transcript_suite_invalid") from exc
        encoded.extend(contributor.contributor_id)
        encoded.extend(contributor.key_id)
        encoded.extend(suite_code.to_bytes(2, "big"))
        encoded.extend(len(contributor.public_key).to_bytes(4, "big"))
        encoded.extend(contributor.public_key)
    encoded.extend(len(transcript.evidence).to_bytes(4, "big"))
    for evidence in transcript.evidence:
        encoded.extend(evidence.descriptor.encode())
        encoded.extend(len(evidence.prover_message).to_bytes(4, "big"))
        encoded.extend(evidence.prover_message)
        for envelopes in (evidence.commitments, evidence.reveals):
            encoded.extend(len(envelopes).to_bytes(2, "big"))
            for envelope in envelopes:
                encoded.extend(envelope.contributor_id)
                encoded.extend(envelope.payload)
                encoded.extend(len(envelope.signature).to_bytes(4, "big"))
                encoded.extend(envelope.signature)
        encoded.extend(evidence.resulting_root)
    encoded.extend(transcript.final_transcript_root)
    if len(encoded) > MAX_SELECTED_TRANSCRIPT_BYTES:
        raise StructuralError("selected_public_coin_transcript_size_cap_exceeded")
    return bytes(encoded)


def decode_selected_challenge_bundle(encoded: bytes) -> SelectedChallengeBundle:
    if type(encoded) is not bytes or not 10 <= len(encoded) <= MAX_CHALLENGE_BUNDLE_BYTES:
        raise StructuralError("selected_challenge_bundle_encoding_length_invalid")
    offset = 0

    def take(length: int) -> bytes:
        nonlocal offset
        end = offset + length
        if end > len(encoded):
            raise StructuralError("selected_challenge_bundle_truncated")
        value = encoded[offset:end]
        offset = end
        return value

    if take(8) != CHALLENGE_BUNDLE_MAGIC:
        raise StructuralError("selected_challenge_bundle_magic_mismatch")
    if int.from_bytes(take(2), "big") != CHALLENGE_BUNDLE_VERSION:
        raise StructuralError("selected_challenge_bundle_version_mismatch")
    roots = tuple(take(64) for _ in range(13))
    layer_count = int.from_bytes(take(2), "big")
    if not 1 <= layer_count <= 29:
        raise StructuralError("selected_challenge_bundle_layer_count_invalid")
    layer_roots = tuple(take(64) for _ in range(layer_count))
    field_values = tuple(Fp16.decode(take(64)) for _ in range(6))
    fold_count = int.from_bytes(take(2), "big")
    if fold_count != layer_count:
        raise StructuralError("selected_challenge_bundle_fold_count_mismatch")
    folds = tuple(Fp16.decode(take(64)) for _ in range(fold_count))
    query_seed = take(64)
    query_count = int.from_bytes(take(2), "big")
    if query_count != 945:
        raise StructuralError("selected_challenge_bundle_query_count_mismatch")
    positions = tuple(int.from_bytes(take(8), "big") for _ in range(query_count))
    if offset != len(encoded):
        raise StructuralError("selected_challenge_bundle_trailing_bytes")
    return SelectedChallengeBundle(
        proof_suite_id=roots[0],
        parameter_commitment=roots[1],
        program_binary_commitment=roots[2],
        schedule_commitment=roots[3],
        session_id=roots[4],
        final_transcript_root=roots[5],
        evidence_commitment=roots[6],
        main_trace_root=roots[7],
        interaction_trace_root=roots[8],
        composition_root=roots[9],
        oods_claims_commitment=roots[10],
        fri_mask_root=roots[11],
        fri_batch_derivation_commitment=roots[12],
        fri_layer_roots=layer_roots,
        logup_beta=field_values[0],
        logup_gamma=field_values[1],
        composition_alpha=field_values[2],
        oods_point=CirclePoint(field_values[3], field_values[4]),
        fri_batch_coefficient=field_values[5],
        fri_fold_coefficients=folds,
        query_seed=query_seed,
        query_positions=positions,
    )


def capture_selected_transcript(session: PublicCoinSession) -> SelectedPublicCoinTranscript:
    if type(session) is not PublicCoinSession:
        raise TypeError("selected_public_coin_session_required")
    if type(session.theorem_schedule) is not SelectedTheoremRoundSchedule:
        raise StructuralError("selected_public_coin_selected_schedule_required")
    if not session.complete or len(session.evidence) != len(session.schedule):
        raise StructuralError("selected_public_coin_session_incomplete")
    if session.candidate_descriptor_sha3_512 != session.theorem_schedule.proof_suite_id:
        raise StructuralError("selected_public_coin_suite_descriptor_mismatch")
    return SelectedPublicCoinTranscript(
        session_id=session.session_id,
        public_outputs=session.public_outputs,
        sidecar=session.sidecar,
        schedule=session.theorem_schedule,
        contributors=session.contributors,
        evidence=session.evidence,
        final_transcript_root=session.transcript_root,
    )


def _evidence_commitment(transcript: SelectedPublicCoinTranscript) -> bytes:
    """Bind the exported proof bundle to the exact public statement.

    The Python coordinator has already replayed every dual-PQ round before it
    emits this bundle.  The outer Rust verifier can recompute this compact
    binding from the twelve public fields, the fixed sidecar, and the
    authenticated final transcript root without receiving caller-supplied
    proof results.
    """

    return _framed_hash_domain(
        PRODUCTION_STATEMENT_EVIDENCE_DOMAIN,
        transcript.public_outputs,
        transcript.sidecar,
        transcript.final_transcript_root,
        transcript.schedule.schedule_commitment,
        transcript.schedule.proof_suite_id,
    )


def verify_selected_transcript(
    transcript: SelectedPublicCoinTranscript,
    adapters: Mapping[str, object],
) -> SelectedChallengeBundle:
    """Replay all dual-PQ evidence and return the only accepted challenge bundle."""

    if type(transcript) is not SelectedPublicCoinTranscript:
        raise TypeError("selected_public_coin_transcript_required")
    if type(adapters) is not dict:
        raise TypeError("selected_public_coin_adapter_map_must_be_dict")
    suites = {item.suite_id for item in transcript.contributors}
    if set(adapters) != suites or any(
        not is_exact_supported_adapter(adapters[suite], suite) for suite in suites
    ):
        raise StructuralError("selected_public_coin_exact_locked_adapters_required")

    replay = PublicCoinSession(
        session_id=transcript.session_id,
        public_outputs=transcript.public_outputs,
        sidecar=transcript.sidecar,
        candidate_descriptor_sha3_512=transcript.schedule.proof_suite_id,
        schedule=transcript.schedule.descriptors,
        contributors=transcript.contributors,
        verifiers=adapters,
        production_mode=True,
        theorem_schedule=transcript.schedule,
    )
    for expected in transcript.evidence:
        if expected.prior_root != replay.transcript_root:
            raise StructuralError("selected_public_coin_prior_root_mismatch")
        replay.begin_round(expected.descriptor, expected.prover_message)
        for envelope in expected.commitments:
            replay.submit_commitment(envelope)
        for envelope in expected.reveals:
            replay.submit_reveal(envelope)
        observed = replay.finalize_round()
        replayed = replay.evidence[-1]
        if observed != expected.challenge or replayed != expected:
            raise StructuralError("selected_public_coin_evidence_replay_mismatch")
    if not replay.complete or replay.transcript_root != transcript.final_transcript_root:
        raise StructuralError("selected_public_coin_final_root_mismatch")

    messages = tuple(
        TheoremProverMessage.decode(item.prover_message) for item in transcript.evidence
    )
    challenges = tuple(item.challenge for item in transcript.evidence)
    folds = transcript.schedule.fold_round_count
    oods_sample = challenges[2].oods_sample
    if oods_sample is None:
        raise StructuralError("selected_public_coin_oods_sample_missing")
    layer_roots = tuple(message.primary_digest for message in messages[5:])
    if len(layer_roots) != folds:
        raise StructuralError("selected_public_coin_layer_root_count_mismatch")
    query_seed = challenges[-1].seed
    positions = sample_query_positions(
        query_seed,
        session_id=transcript.session_id,
        domain_size=transcript.schedule.query_domain_size,
        query_count=transcript.schedule.query_count,
        with_replacement=True,
        maximum_attempts_per_position=1,
    )
    return SelectedChallengeBundle(
        proof_suite_id=transcript.schedule.proof_suite_id,
        parameter_commitment=transcript.schedule.parameter_commitment,
        program_binary_commitment=transcript.schedule.program_binary_commitment,
        schedule_commitment=transcript.schedule.schedule_commitment,
        session_id=transcript.session_id,
        final_transcript_root=transcript.final_transcript_root,
        evidence_commitment=_evidence_commitment(transcript),
        main_trace_root=messages[0].primary_digest,
        interaction_trace_root=messages[1].primary_digest,
        composition_root=messages[2].primary_digest,
        oods_claims_commitment=messages[3].primary_digest,
        fri_mask_root=messages[3].secondary_digest,
        fri_batch_derivation_commitment=messages[4].primary_digest,
        fri_layer_roots=layer_roots,
        logup_beta=challenges[0].field_elements[0],
        logup_gamma=challenges[0].field_elements[1],
        composition_alpha=challenges[1].field_elements[0],
        oods_point=stereographic_circle_point(oods_sample.parameter),
        fri_batch_coefficient=challenges[3].field_elements[0],
        fri_fold_coefficients=tuple(
            value.field_elements[0] for value in challenges[4 : 4 + folds]
        ),
        query_seed=query_seed,
        query_positions=positions,
    )


__all__ = (
    "MAX_SELECTED_TRANSCRIPT_BYTES",
    "SelectedChallengeBundle",
    "SelectedPublicCoinTranscript",
    "SELECTED_TRANSCRIPT_MAGIC",
    "SELECTED_TRANSCRIPT_VERSION",
    "capture_selected_transcript",
    "decode_selected_challenge_bundle",
    "encode_selected_challenge_bundle",
    "encode_selected_transcript_evidence",
    "verify_selected_transcript",
)
