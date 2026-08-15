"""Byte-exact producer/reference replay for the two-segment semantic-v3 coin.

The parent-anchor frame is producer guidance, never verifier authority.  A
Rust verifier must replay the signed prefix and parent bundle, reconstruct its
opaque parent anchor, compare all fourteen frame fields, and only then replay
the continuation.  This module is nonactivating and assigns no proof suite.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
from secrets import token_bytes
from typing import Callable, Final, Mapping

from experiments.bl_pq512_crypto_foundation.field16_reference import (
    Fp16,
    sample_uniform_fp16,
)
from experiments.bl_pq512_crypto_foundation.oods_reference import CirclePoint
from experiments.bl_pq512_crypto_foundation.pq_signature_adapters import (
    is_exact_supported_adapter,
)
from experiments.bl_pq512_crypto_foundation.public_coin_reference import Contributor
from experiments.fixed_shape_claim_air.semantics import StructuralError


SEMANTIC_V3_PREFIX_MAGIC: Final[bytes] = b"BLV3SP01"
SEMANTIC_V3_CONTINUATION_MAGIC: Final[bytes] = b"BLV3SC01"
SEMANTIC_V3_TRANSCRIPT_VERSION: Final[int] = 1
SEMANTIC_V3_TOPOLOGY_TAG: Final[bytes] = b"TWO-SEGMENT-R0-R1-PARENT-R2-PLUS/v1"
SEMANTIC_V3_PARENT_ANCHOR_SEAM_TAG: Final[bytes] = (
    b"PARENT-KIND900-KIND901-AUTHENTICATED-ANCHOR-SEAM/v1"
)
SEMANTIC_V3_PARENT_ANCHOR_COMMAND: Final[str] = "V3_PARENT_ANCHOR"
SEMANTIC_V3_PARENT_ANCHOR_FIELD_COUNT: Final[int] = 14
SEMANTIC_V3_FIELD16_OUTPUT_KIND: Final[int] = 1
SEMANTIC_V3_QUERY_SEED_OUTPUT_KIND: Final[int] = 2
SEMANTIC_V3_QUERY_COUNT: Final[int] = 945
SEMANTIC_V3_CONTEXT_MAGIC: Final[bytes] = b"BLV3CX01"
SEMANTIC_V3_CONTEXT_VERSION: Final[int] = 1
SEMANTIC_V3_CONTEXT_BYTES: Final[int] = 348

SEMANTIC_V3_SCHEDULE_DOMAIN: Final[bytes] = (
    b"BL/PQ512/SELECTED/SEMANTIC-V3/SCHEDULE/v1\x00"
)
SEMANTIC_V3_CONTRIBUTOR_SET_DOMAIN: Final[bytes] = (
    b"BL/PQ512/SELECTED/SEMANTIC-V3/CONTRIBUTOR-SET/v1\x00"
)
SEMANTIC_V3_PREFIX_INIT_DOMAIN: Final[bytes] = (
    b"BL/PQ512/SELECTED/SEMANTIC-V3/PREFIX-INIT/v1\x00"
)
SEMANTIC_V3_COMMITMENT_HASH_DOMAIN: Final[bytes] = (
    b"BL/PQ512/SELECTED/SEMANTIC-V3/ROUND-COMMITMENT/v1\x00"
)
SEMANTIC_V3_COMMITMENT_SIGNATURE_DOMAIN: Final[bytes] = (
    b"BL/PQ512/SELECTED/SEMANTIC-V3/COMMITMENT-SIGNATURE/v1\x00"
)
SEMANTIC_V3_REVEAL_SIGNATURE_DOMAIN: Final[bytes] = (
    b"BL/PQ512/SELECTED/SEMANTIC-V3/REVEAL-SIGNATURE/v1\x00"
)
SEMANTIC_V3_ROUND_SEED_DOMAIN: Final[bytes] = (
    b"BL/PQ512/SELECTED/SEMANTIC-V3/ROUND-SEED/v1\x00"
)
SEMANTIC_V3_AUDIT_ROOT_DOMAIN: Final[bytes] = (
    b"BL/PQ512/SELECTED/SEMANTIC-V3/AUDIT-ROOT/v1\x00"
)
SEMANTIC_V3_PREFIX_RECEIPT_DOMAIN: Final[bytes] = (
    b"BL/PQ512/SELECTED/SEMANTIC-V3/PREFIX-RECEIPT/v1\x00"
)
SEMANTIC_V3_CONTINUATION_ANCHOR_DOMAIN: Final[bytes] = (
    b"BL/PQ512/SELECTED/SEMANTIC-V3/PARENT-ANCHOR/v1\x00"
)
SEMANTIC_V3_PARENT_ANCHOR_FRAME_COMMITMENT_DOMAIN: Final[bytes] = (
    b"BL/PQ512/SELECTED/SEMANTIC-V3/PRODUCER-ANCHOR-FRAME/v1\x00"
)
SEMANTIC_V3_EVIDENCE_DOMAIN: Final[bytes] = (
    b"BL/PQ512/SELECTED/SEMANTIC-V3/COMPLETE-EVIDENCE/v1\x00"
)

MAX_ARTIFACT_BYTES: Final[int] = 16 << 20
MAX_CONTRIBUTORS: Final[int] = 16
MAX_SIGNATURE_BYTES: Final[int] = 64 << 10

_SUITE_CODES: Final[dict[str, int]] = {
    "FIPS204-ML-DSA-87": 1,
    "FIPS205-SLH-DSA-SHAKE-256F": 2,
}
_SUITE_IDS: Final[dict[int, str]] = {value: key for key, value in _SUITE_CODES.items()}
_PUBLIC_KEY_BYTES: Final[dict[str, int]] = {
    "FIPS204-ML-DSA-87": 2_592,
    "FIPS205-SLH-DSA-SHAKE-256F": 64,
}
_SIGNATURE_BYTES: Final[dict[str, int]] = {
    "FIPS204-ML-DSA-87": 4_627,
    "FIPS205-SLH-DSA-SHAKE-256F": 49_856,
}


def _hash(domain: bytes, *parts: bytes) -> bytes:
    digest = sha3_512(domain)
    for part in parts:
        if type(part) is not bytes or len(part) > 0xFFFF_FFFF_FFFF_FFFF:
            raise StructuralError("semantic_v3_hash_part_invalid")
        digest.update(len(part).to_bytes(8, "big"))
        digest.update(part)
    return digest.digest()


def _digest(label: str, value: bytes, *, nonzero: bool = True) -> bytes:
    if type(value) is not bytes or len(value) != 64 or (nonzero and not any(value)):
        raise StructuralError(f"semantic_v3_{label}_invalid")
    return value


def _on_circle(point: CirclePoint) -> bool:
    return point.x * point.x + point.y * point.y == Fp16.one()


def _descriptor(kind: int, ordinal: int, output_kind: int, output_count: int) -> bytes:
    return b"".join(
        value.to_bytes(2, "big")
        for value in (kind, ordinal, output_kind, output_count)
    )


@dataclass(frozen=True, slots=True)
class SemanticV3Geometry:
    fold_round_count: int
    query_domain_log_size: int
    log_blowup: int

    def __post_init__(self) -> None:
        if (
            type(self.fold_round_count) is not int
            or not 1 <= self.fold_round_count <= 0xFFFF
            or type(self.query_domain_log_size) is not int
            or not 1 <= self.query_domain_log_size <= 30
            or type(self.log_blowup) is not int
            or not 1 <= self.log_blowup <= 0xFF
        ):
            raise StructuralError("semantic_v3_geometry_invalid")


@dataclass(frozen=True, slots=True)
class SemanticV3GovernedContext:
    profile_code: int
    semantic_program_commitment: bytes
    parameter_commitment: bytes
    statement_commitment: bytes
    composite_parent_schedule_commitment: bytes
    contributor_set_commitment: bytes
    geometry: SemanticV3Geometry

    def __post_init__(self) -> None:
        if self.profile_code not in (1, 3) or type(self.geometry) is not SemanticV3Geometry:
            raise StructuralError("semantic_v3_context_profile_invalid")
        for label in (
            "semantic_program_commitment",
            "parameter_commitment",
            "statement_commitment",
            "composite_parent_schedule_commitment",
            "contributor_set_commitment",
        ):
            _digest(label, getattr(self, label))

    def encode(self) -> bytes:
        """Encode the canonical Rust-owned strict-coin context transport."""
        encoded = b"".join(
            (
                SEMANTIC_V3_CONTEXT_MAGIC,
                SEMANTIC_V3_CONTEXT_VERSION.to_bytes(2, "big"),
                bytes(2),
                bytes((self.profile_code,)),
                bytes(7),
                self.semantic_program_commitment,
                self.parameter_commitment,
                self.statement_commitment,
                self.composite_parent_schedule_commitment,
                self.contributor_set_commitment,
                self.geometry.fold_round_count.to_bytes(2, "big"),
                bytes(
                    (
                        self.geometry.query_domain_log_size,
                        self.geometry.log_blowup,
                    )
                ),
                bytes(4),
            )
        )
        if len(encoded) != SEMANTIC_V3_CONTEXT_BYTES:
            raise StructuralError("semantic_v3_context_encoding_invalid")
        return encoded


def semantic_v3_descriptors(geometry: SemanticV3Geometry) -> tuple[bytes, ...]:
    if type(geometry) is not SemanticV3Geometry:
        raise TypeError("semantic_v3_geometry_required")
    return (
        _descriptor(1, 0, SEMANTIC_V3_FIELD16_OUTPUT_KIND, 2),
        _descriptor(2, 0, SEMANTIC_V3_FIELD16_OUTPUT_KIND, 1),
        _descriptor(4, 0, SEMANTIC_V3_FIELD16_OUTPUT_KIND, 1),
        *(
            _descriptor(5, ordinal, SEMANTIC_V3_FIELD16_OUTPUT_KIND, 1)
            for ordinal in range(geometry.fold_round_count)
        ),
        _descriptor(6, 0, SEMANTIC_V3_QUERY_SEED_OUTPUT_KIND, 1),
    )


def semantic_v3_schedule_commitment(context: SemanticV3GovernedContext) -> bytes:
    if type(context) is not SemanticV3GovernedContext:
        raise TypeError("semantic_v3_context_required")
    descriptors = semantic_v3_descriptors(context.geometry)
    return _hash(
        SEMANTIC_V3_SCHEDULE_DOMAIN,
        (3).to_bytes(2, "big"),
        SEMANTIC_V3_TOPOLOGY_TAG,
        bytes((context.profile_code,)),
        context.semantic_program_commitment,
        context.parameter_commitment,
        context.statement_commitment,
        context.composite_parent_schedule_commitment,
        bytes((context.geometry.query_domain_log_size, context.geometry.log_blowup)),
        context.geometry.fold_round_count.to_bytes(2, "big"),
        SEMANTIC_V3_QUERY_COUNT.to_bytes(2, "big"),
        descriptors[0],
        descriptors[1],
        SEMANTIC_V3_PARENT_ANCHOR_SEAM_TAG,
        *descriptors[2:],
    )


def semantic_v3_contributor_set_commitment(
    contributors: tuple[Contributor, ...],
) -> bytes:
    _validate_contributors(contributors)
    entries = tuple(
        _hash(
            SEMANTIC_V3_CONTRIBUTOR_SET_DOMAIN,
            contributor.contributor_id,
            contributor.key_id,
            _SUITE_CODES[contributor.suite_id].to_bytes(2, "big"),
            contributor.public_key,
        )
        for contributor in contributors
    )
    return _hash(SEMANTIC_V3_CONTRIBUTOR_SET_DOMAIN, *entries)


def _validate_contributors(contributors: tuple[Contributor, ...]) -> None:
    if (
        type(contributors) is not tuple
        or not 2 <= len(contributors) <= MAX_CONTRIBUTORS
        or any(type(value) is not Contributor for value in contributors)
        or tuple(sorted(contributors, key=lambda value: value.contributor_id)) != contributors
        or len({value.contributor_id for value in contributors}) != len(contributors)
        or len({value.key_id for value in contributors}) != len(contributors)
        or {value.suite_id for value in contributors} != set(_SUITE_CODES)
        or any(
            len(value.public_key) != _PUBLIC_KEY_BYTES[value.suite_id]
            for value in contributors
        )
    ):
        raise StructuralError("semantic_v3_contributors_invalid")


@dataclass(frozen=True, slots=True)
class SemanticV3SignedEnvelope:
    contributor_id: bytes
    payload: bytes
    signature: bytes

    def __post_init__(self) -> None:
        _digest("envelope_contributor", self.contributor_id)
        _digest("envelope_payload", self.payload, nonzero=False)
        if type(self.signature) is not bytes or not 1 <= len(self.signature) <= MAX_SIGNATURE_BYTES:
            raise StructuralError("semantic_v3_signature_invalid")


@dataclass(frozen=True, slots=True)
class SemanticV3RoundChallenge:
    seed: bytes
    field_elements: tuple[Fp16, ...]


@dataclass(frozen=True, slots=True)
class SemanticV3SignedRound:
    descriptor: bytes
    prover_message: bytes
    commitments: tuple[SemanticV3SignedEnvelope, ...]
    reveals: tuple[SemanticV3SignedEnvelope, ...]
    resulting_root: bytes

    def encode(self) -> bytes:
        encoded = bytearray(self.descriptor)
        encoded.extend(len(self.prover_message).to_bytes(4, "big"))
        encoded.extend(self.prover_message)
        for envelopes in (self.commitments, self.reveals):
            encoded.extend(len(envelopes).to_bytes(2, "big"))
            for envelope in envelopes:
                encoded.extend(envelope.contributor_id)
                encoded.extend(envelope.payload)
                encoded.extend(len(envelope.signature).to_bytes(4, "big"))
                encoded.extend(envelope.signature)
        encoded.extend(self.resulting_root)
        return bytes(encoded)


def _signature_message(
    domain: bytes,
    session_id: bytes,
    global_round: int,
    descriptor: bytes,
    prior_root: bytes,
    prover_message: bytes,
    contributor: Contributor,
    payload: bytes,
) -> bytes:
    return _hash(
        domain,
        session_id,
        global_round.to_bytes(4, "big"),
        descriptor,
        prior_root,
        sha3_512(prover_message).digest(),
        contributor.contributor_id,
        contributor.key_id,
        payload,
    )


def _expected_commitment(
    session_id: bytes,
    global_round: int,
    descriptor: bytes,
    prior_root: bytes,
    prover_message: bytes,
    contributor_id: bytes,
    reveal: bytes,
) -> bytes:
    return _hash(
        SEMANTIC_V3_COMMITMENT_HASH_DOMAIN,
        session_id,
        global_round.to_bytes(4, "big"),
        descriptor,
        prior_root,
        sha3_512(prover_message).digest(),
        contributor_id,
        reveal,
    )


def _round_seed(
    session_id: bytes,
    global_round: int,
    descriptor: bytes,
    prior_root: bytes,
    prover_message: bytes,
    commitments: tuple[SemanticV3SignedEnvelope, ...],
    reveals: tuple[SemanticV3SignedEnvelope, ...],
) -> bytes:
    contributions: list[bytes] = []
    for commitment, reveal in zip(commitments, reveals, strict=True):
        contributions.extend((commitment.contributor_id, commitment.payload, reveal.payload))
    return _hash(
        SEMANTIC_V3_ROUND_SEED_DOMAIN,
        session_id,
        global_round.to_bytes(4, "big"),
        descriptor,
        prior_root,
        prover_message,
        *contributions,
    )


def _audit_root(
    session_id: bytes,
    global_round: int,
    descriptor: bytes,
    prior_root: bytes,
    prover_message: bytes,
    seed: bytes,
    commitments: tuple[SemanticV3SignedEnvelope, ...],
    reveals: tuple[SemanticV3SignedEnvelope, ...],
    fields: tuple[Fp16, ...],
) -> bytes:
    evidence: list[bytes] = []
    for commitment, reveal in zip(commitments, reveals, strict=True):
        evidence.extend(
            (
                commitment.payload,
                commitment.signature,
                reveal.payload,
                reveal.signature,
            )
        )
    return _hash(
        SEMANTIC_V3_AUDIT_ROOT_DOMAIN,
        session_id,
        global_round.to_bytes(4, "big"),
        descriptor,
        prior_root,
        prover_message,
        seed,
        *evidence,
        *(value.encode() for value in fields),
    )


def _verify_round(
    round_evidence: SemanticV3SignedRound,
    *,
    expected_descriptor: bytes,
    expected_message_bytes: int,
    session_id: bytes,
    global_round: int,
    prior_root: bytes,
    contributors: tuple[Contributor, ...],
    adapters: Mapping[str, object],
    draw_count: int,
) -> SemanticV3RoundChallenge:
    if (
        round_evidence.descriptor != expected_descriptor
        or len(round_evidence.prover_message) != expected_message_bytes
        or any(
            not any(chunk)
            for chunk in (
                round_evidence.prover_message[index : index + 64]
                for index in range(0, expected_message_bytes, 64)
            )
        )
        or len(round_evidence.commitments) != len(contributors)
        or len(round_evidence.reveals) != len(contributors)
    ):
        raise StructuralError("semantic_v3_round_shape_invalid")
    for contributor, commitment, reveal in zip(
        contributors,
        round_evidence.commitments,
        round_evidence.reveals,
        strict=True,
    ):
        if (
            commitment.contributor_id != contributor.contributor_id
            or reveal.contributor_id != contributor.contributor_id
            or len(commitment.signature) != _SIGNATURE_BYTES[contributor.suite_id]
            or len(reveal.signature) != _SIGNATURE_BYTES[contributor.suite_id]
            or commitment.payload
            != _expected_commitment(
                session_id,
                global_round,
                expected_descriptor,
                prior_root,
                round_evidence.prover_message,
                contributor.contributor_id,
                reveal.payload,
            )
        ):
            raise StructuralError("semantic_v3_round_commitment_invalid")
        adapter = adapters[contributor.suite_id]
        for domain, envelope in (
            (SEMANTIC_V3_COMMITMENT_SIGNATURE_DOMAIN, commitment),
            (SEMANTIC_V3_REVEAL_SIGNATURE_DOMAIN, reveal),
        ):
            message = _signature_message(
                domain,
                session_id,
                global_round,
                expected_descriptor,
                prior_root,
                round_evidence.prover_message,
                contributor,
                envelope.payload,
            )
            if not adapter.verify(
                public_key=contributor.public_key,
                message=message,
                signature=envelope.signature,
            ):
                raise StructuralError("semantic_v3_round_signature_invalid")
    seed = _round_seed(
        session_id,
        global_round,
        expected_descriptor,
        prior_root,
        round_evidence.prover_message,
        round_evidence.commitments,
        round_evidence.reveals,
    )
    fields = tuple(
        sample_uniform_fp16(
            seed,
            session_id=session_id,
            round_index=global_round,
            draw_index=draw,
        ).element
        for draw in range(draw_count)
    )
    root = _audit_root(
        session_id,
        global_round,
        expected_descriptor,
        prior_root,
        round_evidence.prover_message,
        seed,
        round_evidence.commitments,
        round_evidence.reveals,
        fields,
    )
    if root != round_evidence.resulting_root:
        raise StructuralError("semantic_v3_round_root_invalid")
    return SemanticV3RoundChallenge(seed, fields)


class _Reader:
    __slots__ = ("encoded", "offset")

    def __init__(self, encoded: bytes) -> None:
        if type(encoded) is not bytes or not 10 <= len(encoded) <= MAX_ARTIFACT_BYTES:
            raise StructuralError("semantic_v3_encoding_length_invalid")
        self.encoded = encoded
        self.offset = 0

    def take(self, length: int) -> bytes:
        end = self.offset + length
        if end > len(self.encoded):
            raise StructuralError("semantic_v3_truncated")
        value = self.encoded[self.offset : end]
        self.offset = end
        return value

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.take(2), "big")

    def u32(self) -> int:
        return int.from_bytes(self.take(4), "big")

    def digest(self) -> bytes:
        return self.take(64)

    def bounded(self, maximum: int) -> bytes:
        length = self.u32()
        if length > maximum:
            raise StructuralError("semantic_v3_bounded_bytes_invalid")
        return self.take(length)


def _encode_contributors(contributors: tuple[Contributor, ...]) -> bytes:
    encoded = bytearray(len(contributors).to_bytes(2, "big"))
    for contributor in contributors:
        encoded.extend(contributor.contributor_id)
        encoded.extend(contributor.key_id)
        encoded.extend(_SUITE_CODES[contributor.suite_id].to_bytes(2, "big"))
        encoded.extend(len(contributor.public_key).to_bytes(4, "big"))
        encoded.extend(contributor.public_key)
    return bytes(encoded)


def _decode_contributors(reader: _Reader) -> tuple[Contributor, ...]:
    count = reader.u16()
    if not 2 <= count <= MAX_CONTRIBUTORS:
        raise StructuralError("semantic_v3_contributor_count_invalid")
    contributors = []
    for _ in range(count):
        contributor_id = reader.digest()
        key_id = reader.digest()
        try:
            suite_id = _SUITE_IDS[reader.u16()]
        except KeyError as exc:
            raise StructuralError("semantic_v3_contributor_suite_invalid") from exc
        public_key = reader.bounded(MAX_SIGNATURE_BYTES)
        contributors.append(Contributor(contributor_id, key_id, suite_id, public_key))
    result = tuple(contributors)
    _validate_contributors(result)
    return result


def _decode_envelope(reader: _Reader) -> SemanticV3SignedEnvelope:
    return SemanticV3SignedEnvelope(
        reader.digest(), reader.digest(), reader.bounded(MAX_SIGNATURE_BYTES)
    )


def _decode_round(reader: _Reader, contributor_count: int) -> SemanticV3SignedRound:
    descriptor = reader.take(8)
    prover_message = reader.bounded(256)
    if reader.u16() != contributor_count:
        raise StructuralError("semantic_v3_commitment_count_invalid")
    commitments = tuple(_decode_envelope(reader) for _ in range(contributor_count))
    if reader.u16() != contributor_count:
        raise StructuralError("semantic_v3_reveal_count_invalid")
    reveals = tuple(_decode_envelope(reader) for _ in range(contributor_count))
    return SemanticV3SignedRound(
        descriptor, prover_message, commitments, reveals, reader.digest()
    )


@dataclass(frozen=True, slots=True)
class SemanticV3PrefixEvidence:
    encoded: bytes
    semantic_session_id: bytes
    semantic_schedule_commitment: bytes
    contributor_set_commitment: bytes
    round_1_transcript_root: bytes
    main_trace_root: bytes
    interaction_trace_root: bytes
    logup_beta: Fp16
    logup_gamma: Fp16
    composition_alpha: Fp16
    receipt_commitment: bytes
    contributors: tuple[Contributor, ...]
    rounds: tuple[SemanticV3SignedRound, SemanticV3SignedRound]


def _prefix_init_root(
    context: SemanticV3GovernedContext,
    session_id: bytes,
    schedule: bytes,
    contributors_commitment: bytes,
) -> bytes:
    return _hash(
        SEMANTIC_V3_PREFIX_INIT_DOMAIN,
        session_id,
        schedule,
        contributors_commitment,
        context.semantic_program_commitment,
        context.parameter_commitment,
        context.statement_commitment,
        bytes((context.profile_code,)),
    )


def _encode_prefix(
    context: SemanticV3GovernedContext,
    session_id: bytes,
    schedule: bytes,
    contributors: tuple[Contributor, ...],
    rounds: tuple[SemanticV3SignedRound, SemanticV3SignedRound],
) -> bytes:
    encoded = b"".join(
        (
            SEMANTIC_V3_PREFIX_MAGIC,
            SEMANTIC_V3_TRANSCRIPT_VERSION.to_bytes(2, "big"),
            bytes(2),
            session_id,
            schedule,
            context.semantic_program_commitment,
            context.parameter_commitment,
            context.statement_commitment,
            bytes((context.profile_code,)),
            bytes(7),
            _encode_contributors(contributors),
            (2).to_bytes(2, "big"),
            *(round_evidence.encode() for round_evidence in rounds),
            rounds[-1].resulting_root,
        )
    )
    if len(encoded) > MAX_ARTIFACT_BYTES:
        raise StructuralError("semantic_v3_prefix_size_cap_exceeded")
    return encoded


def verify_semantic_v3_prefix(
    encoded: bytes,
    context: SemanticV3GovernedContext,
    adapters: Mapping[str, object],
) -> SemanticV3PrefixEvidence:
    reader = _Reader(encoded)
    if reader.take(8) != SEMANTIC_V3_PREFIX_MAGIC:
        raise StructuralError("semantic_v3_prefix_magic_invalid")
    if reader.u16() != SEMANTIC_V3_TRANSCRIPT_VERSION or reader.u16() != 0:
        raise StructuralError("semantic_v3_prefix_version_invalid")
    session_id = _digest("prefix_session", reader.digest())
    schedule = reader.digest()
    semantic_program = reader.digest()
    parameters = reader.digest()
    statement = reader.digest()
    profile = reader.u8()
    if any(reader.take(7)):
        raise StructuralError("semantic_v3_prefix_reserved_nonzero")
    contributors = _decode_contributors(reader)
    contributor_commitment = semantic_v3_contributor_set_commitment(contributors)
    if (
        type(context) is not SemanticV3GovernedContext
        or profile != context.profile_code
        or semantic_program != context.semantic_program_commitment
        or parameters != context.parameter_commitment
        or statement != context.statement_commitment
        or schedule != semantic_v3_schedule_commitment(context)
        or contributor_commitment != context.contributor_set_commitment
        or set(adapters) != set(_SUITE_CODES)
        or any(
            not is_exact_supported_adapter(adapters[suite], suite)
            for suite in _SUITE_CODES
        )
    ):
        raise StructuralError("semantic_v3_prefix_context_invalid")
    if reader.u16() != 2:
        raise StructuralError("semantic_v3_prefix_round_count_invalid")
    rounds = (_decode_round(reader, len(contributors)), _decode_round(reader, len(contributors)))
    final_root = reader.digest()
    if reader.offset != len(encoded):
        raise StructuralError("semantic_v3_prefix_trailing")
    descriptors = semantic_v3_descriptors(context.geometry)
    init_root = _prefix_init_root(context, session_id, schedule, contributor_commitment)
    round_0 = _verify_round(
        rounds[0],
        expected_descriptor=descriptors[0],
        expected_message_bytes=64,
        session_id=session_id,
        global_round=0,
        prior_root=init_root,
        contributors=contributors,
        adapters=adapters,
        draw_count=2,
    )
    round_1 = _verify_round(
        rounds[1],
        expected_descriptor=descriptors[1],
        expected_message_bytes=64,
        session_id=session_id,
        global_round=1,
        prior_root=rounds[0].resulting_root,
        contributors=contributors,
        adapters=adapters,
        draw_count=1,
    )
    if final_root != rounds[1].resulting_root:
        raise StructuralError("semantic_v3_prefix_final_root_invalid")
    receipt = _hash(
        SEMANTIC_V3_PREFIX_RECEIPT_DOMAIN,
        sha3_512(encoded).digest(),
        session_id,
        schedule,
        contributor_commitment,
        final_root,
        rounds[0].prover_message,
        rounds[1].prover_message,
        round_0.field_elements[0].encode(),
        round_0.field_elements[1].encode(),
        round_1.field_elements[0].encode(),
    )
    return SemanticV3PrefixEvidence(
        encoded,
        session_id,
        schedule,
        contributor_commitment,
        final_root,
        rounds[0].prover_message,
        rounds[1].prover_message,
        round_0.field_elements[0],
        round_0.field_elements[1],
        round_1.field_elements[0],
        receipt,
        contributors,
        rounds,
    )


@dataclass(frozen=True, slots=True)
class SemanticV3ParentAnchorState:
    parent_session_id: bytes
    parent_round_901_transcript_root: bytes
    composition_root: bytes
    z: CirclePoint
    bridge_program_commitment: bytes
    answer_aggregate_root: bytes
    message_direct_q_commitment: bytes
    digest_direct_q_commitment: bytes

    def __post_init__(self) -> None:
        for label in (
            "parent_session_id",
            "parent_round_901_transcript_root",
            "composition_root",
            "bridge_program_commitment",
            "answer_aggregate_root",
            "message_direct_q_commitment",
            "digest_direct_q_commitment",
        ):
            _digest(label, getattr(self, label))
        if type(self.z) is not CirclePoint or not _on_circle(self.z):
            raise StructuralError("semantic_v3_parent_oods_point_invalid")


@dataclass(frozen=True, slots=True)
class SemanticV3ParentProducerState:
    parent_bundle: bytes
    parent_session_id: bytes
    parent_round_901_transcript_root: bytes
    composition_root: bytes
    z: CirclePoint
    bridge_program_commitment: bytes
    answer_aggregate_root: bytes
    message_direct_q_commitment: bytes
    digest_direct_q_commitment: bytes

    def __post_init__(self) -> None:
        if (
            type(self.parent_bundle) is not bytes
            or not 0 < len(self.parent_bundle) <= MAX_ARTIFACT_BYTES
        ):
            raise StructuralError("semantic_v3_parent_bundle_invalid")
        self.anchor_state

    @property
    def anchor_state(self) -> SemanticV3ParentAnchorState:
        return SemanticV3ParentAnchorState(
            parent_session_id=self.parent_session_id,
            parent_round_901_transcript_root=self.parent_round_901_transcript_root,
            composition_root=self.composition_root,
            z=self.z,
            bridge_program_commitment=self.bridge_program_commitment,
            answer_aggregate_root=self.answer_aggregate_root,
            message_direct_q_commitment=self.message_direct_q_commitment,
            digest_direct_q_commitment=self.digest_direct_q_commitment,
        )


def _continuation_initial_root(fields: tuple[bytes, ...]) -> bytes:
    if len(fields) != 13:
        raise StructuralError("semantic_v3_parent_anchor_field_count_invalid")
    return _hash(
        SEMANTIC_V3_CONTINUATION_ANCHOR_DOMAIN,
        (3).to_bytes(2, "big"),
        *fields,
    )


@dataclass(frozen=True, slots=True)
class SemanticV3ParentAnchorFrame:
    fields: tuple[bytes, ...]

    def __post_init__(self) -> None:
        if (
            type(self.fields) is not tuple
            or len(self.fields) != SEMANTIC_V3_PARENT_ANCHOR_FIELD_COUNT
            or any(type(value) is not bytes or len(value) != 64 for value in self.fields)
            or any(not any(self.fields[index]) for index in (*range(7), *range(9, 14)))
        ):
            raise StructuralError("semantic_v3_parent_anchor_frame_invalid")
        point = CirclePoint(Fp16.decode(self.fields[7]), Fp16.decode(self.fields[8]))
        if not _on_circle(point):
            raise StructuralError("semantic_v3_parent_anchor_circle_invalid")
        if self.fields[13] != _continuation_initial_root(self.fields[:13]):
            raise StructuralError("semantic_v3_parent_anchor_root_invalid")

    @classmethod
    def from_parent(
        cls,
        prefix: SemanticV3PrefixEvidence,
        parent: SemanticV3ParentProducerState,
    ) -> "SemanticV3ParentAnchorFrame":
        if type(parent) is not SemanticV3ParentProducerState:
            raise TypeError("semantic_v3_parent_required")
        return cls.from_anchor(prefix, parent.anchor_state)

    @classmethod
    def from_anchor(
        cls,
        prefix: SemanticV3PrefixEvidence,
        parent: SemanticV3ParentAnchorState,
    ) -> "SemanticV3ParentAnchorFrame":
        if (
            type(prefix) is not SemanticV3PrefixEvidence
            or type(parent) is not SemanticV3ParentAnchorState
        ):
            raise TypeError("semantic_v3_prefix_and_parent_required")
        first = (
            parent.parent_session_id,
            parent.parent_round_901_transcript_root,
            prefix.semantic_session_id,
            prefix.semantic_schedule_commitment,
            prefix.contributor_set_commitment,
            prefix.round_1_transcript_root,
            parent.composition_root,
            parent.z.x.encode(),
            parent.z.y.encode(),
            parent.bridge_program_commitment,
            parent.answer_aggregate_root,
            parent.message_direct_q_commitment,
            parent.digest_direct_q_commitment,
        )
        return cls((*first, _continuation_initial_root(first)))

    @classmethod
    def from_command_tokens(cls, tokens: tuple[str, ...]) -> "SemanticV3ParentAnchorFrame":
        if type(tokens) is not tuple or len(tokens) != SEMANTIC_V3_PARENT_ANCHOR_FIELD_COUNT:
            raise StructuralError("semantic_v3_parent_anchor_token_count_invalid")
        if any(
            type(value) is not str
            or len(value) != 128
            or any(character not in "0123456789abcdef" for character in value)
            for value in tokens
        ):
            raise StructuralError("semantic_v3_parent_anchor_token_invalid")
        return cls(tuple(bytes.fromhex(value) for value in tokens))

    @property
    def z(self) -> CirclePoint:
        return CirclePoint(Fp16.decode(self.fields[7]), Fp16.decode(self.fields[8]))

    @property
    def continuation_initial_root(self) -> bytes:
        return self.fields[13]

    @property
    def command_fields(self) -> tuple[str, ...]:
        return (SEMANTIC_V3_PARENT_ANCHOR_COMMAND, *(value.hex() for value in self.fields))

    @property
    def encoded(self) -> bytes:
        """Canonical Rust-compatible binary transport for closed witnesses."""
        return b"".join((b"BLV3PAF1", (1).to_bytes(2, "big"), bytes(2), *self.fields))

    @property
    def commitment(self) -> bytes:
        return _hash(
            SEMANTIC_V3_PARENT_ANCHOR_FRAME_COMMITMENT_DOMAIN,
            SEMANTIC_V3_PARENT_ANCHOR_COMMAND.encode("ascii"),
            *self.fields,
        )


@dataclass(frozen=True, slots=True)
class SemanticV3ContinuationEvidence:
    encoded: bytes
    final_transcript_root: bytes
    fri_batch_coefficient: Fp16
    fri_fold_coefficients: tuple[Fp16, ...]
    query_seed: bytes
    rounds: tuple[SemanticV3SignedRound, ...]


def _encode_continuation(
    frame: SemanticV3ParentAnchorFrame,
    prefix: SemanticV3PrefixEvidence,
    rounds: tuple[SemanticV3SignedRound, ...],
) -> bytes:
    encoded = b"".join(
        (
            SEMANTIC_V3_CONTINUATION_MAGIC,
            SEMANTIC_V3_TRANSCRIPT_VERSION.to_bytes(2, "big"),
            bytes(2),
            prefix.semantic_session_id,
            prefix.semantic_schedule_commitment,
            prefix.contributor_set_commitment,
            frame.continuation_initial_root,
            len(rounds).to_bytes(2, "big"),
            *(round_evidence.encode() for round_evidence in rounds),
            rounds[-1].resulting_root,
        )
    )
    if len(encoded) > MAX_ARTIFACT_BYTES:
        raise StructuralError("semantic_v3_continuation_size_cap_exceeded")
    return encoded


def verify_semantic_v3_continuation(
    encoded: bytes,
    *,
    prefix: SemanticV3PrefixEvidence,
    frame: SemanticV3ParentAnchorFrame,
    geometry: SemanticV3Geometry,
    adapters: Mapping[str, object],
) -> SemanticV3ContinuationEvidence:
    reader = _Reader(encoded)
    if reader.take(8) != SEMANTIC_V3_CONTINUATION_MAGIC:
        raise StructuralError("semantic_v3_continuation_magic_invalid")
    if reader.u16() != SEMANTIC_V3_TRANSCRIPT_VERSION or reader.u16() != 0:
        raise StructuralError("semantic_v3_continuation_version_invalid")
    if (
        reader.digest() != prefix.semantic_session_id
        or reader.digest() != prefix.semantic_schedule_commitment
        or reader.digest() != prefix.contributor_set_commitment
        or reader.digest() != frame.continuation_initial_root
    ):
        raise StructuralError("semantic_v3_continuation_context_invalid")
    count = reader.u16()
    if count != geometry.fold_round_count + 2:
        raise StructuralError("semantic_v3_continuation_round_count_invalid")
    rounds = tuple(_decode_round(reader, len(prefix.contributors)) for _ in range(count))
    final_root = reader.digest()
    if reader.offset != len(encoded):
        raise StructuralError("semantic_v3_continuation_trailing")
    descriptors = semantic_v3_descriptors(geometry)
    prior_root = frame.continuation_initial_root
    fields: list[Fp16] = []
    query_seed = b""
    for offset, round_evidence in enumerate(rounds):
        final = offset + 1 == len(rounds)
        challenge = _verify_round(
            round_evidence,
            expected_descriptor=descriptors[offset + 2],
            expected_message_bytes=128 if offset == 0 else 64,
            session_id=prefix.semantic_session_id,
            global_round=offset + 2,
            prior_root=prior_root,
            contributors=prefix.contributors,
            adapters=adapters,
            draw_count=0 if final else 1,
        )
        if final:
            query_seed = challenge.seed
        else:
            fields.append(challenge.field_elements[0])
        prior_root = round_evidence.resulting_root
    if prior_root != final_root or len(fields) != geometry.fold_round_count + 1:
        raise StructuralError("semantic_v3_continuation_final_root_invalid")
    return SemanticV3ContinuationEvidence(
        encoded,
        final_root,
        fields[0],
        tuple(fields[1:]),
        query_seed,
        rounds,
    )


@dataclass(frozen=True, slots=True)
class SemanticV3TranscriptEvidence:
    prefix: SemanticV3PrefixEvidence
    parent_bundle: bytes
    parent_anchor: SemanticV3ParentAnchorFrame
    continuation: SemanticV3ContinuationEvidence
    evidence_commitment: bytes


class SemanticV3TranscriptProducer:
    """Append-only signed producer for semantic rounds 0/1 and 2+."""

    __slots__ = (
        "context",
        "session_id",
        "contributors",
        "adapters",
        "secret_keys",
        "reveal_source",
        "schedule_commitment",
        "descriptors",
        "prefix_rounds",
        "continuation_rounds",
        "continuation",
        "prior_root",
        "prefix",
        "parent_anchor",
        "parent",
        "frame",
    )

    def __init__(
        self,
        *,
        context: SemanticV3GovernedContext,
        session_id: bytes,
        contributors: tuple[Contributor, ...],
        adapters: Mapping[str, object],
        secret_keys: Mapping[bytes, bytes],
        reveal_source: Callable[[int, Contributor], bytes] | None = None,
    ) -> None:
        _digest("producer_session", session_id)
        _validate_contributors(contributors)
        if (
            type(context) is not SemanticV3GovernedContext
            or semantic_v3_contributor_set_commitment(contributors)
            != context.contributor_set_commitment
            or type(adapters) is not dict
            or set(adapters) != set(_SUITE_CODES)
            or any(
                not is_exact_supported_adapter(adapters[suite], suite)
                for suite in _SUITE_CODES
            )
            or set(secret_keys) != {value.contributor_id for value in contributors}
            or (reveal_source is not None and not callable(reveal_source))
        ):
            raise StructuralError("semantic_v3_producer_authority_invalid")
        self.context = context
        self.session_id = session_id
        self.contributors = contributors
        self.adapters = adapters
        self.secret_keys = secret_keys
        self.reveal_source = reveal_source or (lambda _round, _contributor: token_bytes(64))
        self.schedule_commitment = semantic_v3_schedule_commitment(context)
        self.descriptors = semantic_v3_descriptors(context.geometry)
        self.prefix_rounds: list[SemanticV3SignedRound] = []
        self.continuation_rounds: list[SemanticV3SignedRound] = []
        self.continuation: SemanticV3ContinuationEvidence | None = None
        self.prior_root = _prefix_init_root(
            context,
            session_id,
            self.schedule_commitment,
            context.contributor_set_commitment,
        )
        self.prefix: SemanticV3PrefixEvidence | None = None
        self.parent_anchor: SemanticV3ParentAnchorState | None = None
        self.parent: SemanticV3ParentProducerState | None = None
        self.frame: SemanticV3ParentAnchorFrame | None = None

    def _signed_round(
        self,
        *,
        descriptor: bytes,
        global_round: int,
        prover_message: bytes,
        draw_count: int,
    ) -> tuple[SemanticV3SignedRound, SemanticV3RoundChallenge]:
        reveals = []
        commitments = []
        for contributor in self.contributors:
            reveal = self.reveal_source(global_round, contributor)
            _digest("producer_reveal", reveal)
            payload = _expected_commitment(
                self.session_id,
                global_round,
                descriptor,
                self.prior_root,
                prover_message,
                contributor.contributor_id,
                reveal,
            )
            adapter = self.adapters[contributor.suite_id]
            commitments.append(
                SemanticV3SignedEnvelope(
                    contributor.contributor_id,
                    payload,
                    adapter.sign(
                        secret_key=self.secret_keys[contributor.contributor_id],
                        message=_signature_message(
                            SEMANTIC_V3_COMMITMENT_SIGNATURE_DOMAIN,
                            self.session_id,
                            global_round,
                            descriptor,
                            self.prior_root,
                            prover_message,
                            contributor,
                            payload,
                        ),
                    ),
                )
            )
            reveals.append(
                SemanticV3SignedEnvelope(
                    contributor.contributor_id,
                    reveal,
                    adapter.sign(
                        secret_key=self.secret_keys[contributor.contributor_id],
                        message=_signature_message(
                            SEMANTIC_V3_REVEAL_SIGNATURE_DOMAIN,
                            self.session_id,
                            global_round,
                            descriptor,
                            self.prior_root,
                            prover_message,
                            contributor,
                            reveal,
                        ),
                    ),
                )
            )
        commitments_tuple = tuple(commitments)
        reveals_tuple = tuple(reveals)
        seed = _round_seed(
            self.session_id,
            global_round,
            descriptor,
            self.prior_root,
            prover_message,
            commitments_tuple,
            reveals_tuple,
        )
        fields = tuple(
            sample_uniform_fp16(
                seed,
                session_id=self.session_id,
                round_index=global_round,
                draw_index=draw,
            ).element
            for draw in range(draw_count)
        )
        root = _audit_root(
            self.session_id,
            global_round,
            descriptor,
            self.prior_root,
            prover_message,
            seed,
            commitments_tuple,
            reveals_tuple,
            fields,
        )
        round_evidence = SemanticV3SignedRound(
            descriptor,
            prover_message,
            commitments_tuple,
            reveals_tuple,
            root,
        )
        self.prior_root = root
        return round_evidence, SemanticV3RoundChallenge(seed, fields)

    def record_main_root(self, root: bytes) -> tuple[Fp16, Fp16]:
        if self.prefix_rounds or self.prefix is not None:
            raise StructuralError("semantic_v3_main_round_order_invalid")
        _digest("main_root", root)
        round_evidence, challenge = self._signed_round(
            descriptor=self.descriptors[0],
            global_round=0,
            prover_message=root,
            draw_count=2,
        )
        self.prefix_rounds.append(round_evidence)
        return challenge.field_elements[0], challenge.field_elements[1]

    def record_interaction_root(self, root: bytes) -> Fp16:
        if len(self.prefix_rounds) != 1 or self.prefix is not None:
            raise StructuralError("semantic_v3_interaction_round_order_invalid")
        _digest("interaction_root", root)
        round_evidence, challenge = self._signed_round(
            descriptor=self.descriptors[1],
            global_round=1,
            prover_message=root,
            draw_count=1,
        )
        self.prefix_rounds.append(round_evidence)
        return challenge.field_elements[0]

    def finish_prefix(self) -> SemanticV3PrefixEvidence:
        if len(self.prefix_rounds) != 2 or self.prefix is not None:
            raise StructuralError("semantic_v3_prefix_finish_order_invalid")
        rounds = (self.prefix_rounds[0], self.prefix_rounds[1])
        encoded = _encode_prefix(
            self.context,
            self.session_id,
            self.schedule_commitment,
            self.contributors,
            rounds,
        )
        self.prefix = verify_semantic_v3_prefix(encoded, self.context, self.adapters)
        return self.prefix

    def bind_parent(
        self,
        parent: SemanticV3ParentProducerState,
        *,
        worker_composition_root: bytes,
    ) -> SemanticV3ParentAnchorFrame:
        frame = self.bind_parent_anchor(
            parent.anchor_state,
            worker_composition_root=worker_composition_root,
        )
        self.finalize_parent(parent)
        return frame

    def bind_parent_anchor(
        self,
        parent: SemanticV3ParentAnchorState,
        *,
        worker_composition_root: bytes,
    ) -> SemanticV3ParentAnchorFrame:
        if (
            self.prefix is None
            or self.parent_anchor is not None
            or type(parent) is not SemanticV3ParentAnchorState
            or parent.composition_root != worker_composition_root
        ):
            raise StructuralError("semantic_v3_parent_bind_invalid")
        self.parent_anchor = parent
        self.frame = SemanticV3ParentAnchorFrame.from_anchor(self.prefix, parent)
        self.prior_root = self.frame.continuation_initial_root
        return self.frame

    def finalize_parent(self, parent: SemanticV3ParentProducerState) -> None:
        if (
            self.parent_anchor is None
            or self.parent is not None
            or type(parent) is not SemanticV3ParentProducerState
            or parent.anchor_state != self.parent_anchor
        ):
            raise StructuralError("semantic_v3_parent_finalize_invalid")
        self.parent = parent

    def record_continuation_message(self, prover_message: bytes) -> SemanticV3RoundChallenge:
        if self.prefix is None or self.frame is None or self.continuation is not None:
            raise StructuralError("semantic_v3_continuation_before_parent")
        offset = len(self.continuation_rounds)
        count = self.context.geometry.fold_round_count + 2
        if offset >= count:
            raise StructuralError("semantic_v3_continuation_already_complete")
        expected_bytes = 128 if offset == 0 else 64
        if (
            type(prover_message) is not bytes
            or len(prover_message) != expected_bytes
            or any(
                not any(prover_message[index : index + 64])
                for index in range(0, expected_bytes, 64)
            )
        ):
            raise StructuralError("semantic_v3_continuation_message_invalid")
        round_evidence, challenge = self._signed_round(
            descriptor=self.descriptors[offset + 2],
            global_round=offset + 2,
            prover_message=prover_message,
            draw_count=0 if offset + 1 == count else 1,
        )
        self.continuation_rounds.append(round_evidence)
        return challenge

    def finish_continuation(self) -> SemanticV3ContinuationEvidence:
        if self.prefix is None or self.frame is None:
            raise StructuralError("semantic_v3_continuation_before_parent")
        if self.continuation is not None:
            return self.continuation
        rounds = tuple(self.continuation_rounds)
        if len(rounds) != self.context.geometry.fold_round_count + 2:
            raise StructuralError("semantic_v3_continuation_incomplete")
        encoded = _encode_continuation(self.frame, self.prefix, rounds)
        self.continuation = verify_semantic_v3_continuation(
            encoded,
            prefix=self.prefix,
            frame=self.frame,
            geometry=self.context.geometry,
            adapters=self.adapters,
        )
        return self.continuation

    def finish_evidence(self) -> SemanticV3TranscriptEvidence:
        if self.prefix is None or self.parent is None or self.frame is None:
            raise StructuralError("semantic_v3_evidence_before_parent")
        continuation = self.finish_continuation()
        commitment = _hash(
            SEMANTIC_V3_EVIDENCE_DOMAIN,
            self.prefix.encoded,
            self.parent.parent_bundle,
            self.frame.commitment,
            continuation.encoded,
        )
        return SemanticV3TranscriptEvidence(
            self.prefix,
            self.parent.parent_bundle,
            self.frame,
            continuation,
            commitment,
        )


def replay_semantic_v3_producer_evidence(
    evidence: SemanticV3TranscriptEvidence,
    *,
    context: SemanticV3GovernedContext,
    parent: SemanticV3ParentProducerState,
    adapters: Mapping[str, object],
) -> SemanticV3TranscriptEvidence:
    """Replay producer evidence without claiming parent-verifier authority.

    This catches transport and orchestration mismatches.  The Rust verifier
    still has to authenticate ``parent_bundle`` and derive its opaque parent
    anchor before this evidence can contribute to proof acceptance.
    """

    if (
        type(evidence) is not SemanticV3TranscriptEvidence
        or type(parent) is not SemanticV3ParentProducerState
        or evidence.parent_bundle != parent.parent_bundle
    ):
        raise StructuralError("semantic_v3_producer_evidence_parent_invalid")
    prefix = verify_semantic_v3_prefix(evidence.prefix.encoded, context, adapters)
    expected_frame = SemanticV3ParentAnchorFrame.from_parent(prefix, parent)
    if evidence.parent_anchor != expected_frame:
        raise StructuralError("semantic_v3_producer_evidence_anchor_mismatch")
    continuation = verify_semantic_v3_continuation(
        evidence.continuation.encoded,
        prefix=prefix,
        frame=expected_frame,
        geometry=context.geometry,
        adapters=adapters,
    )
    expected_commitment = _hash(
        SEMANTIC_V3_EVIDENCE_DOMAIN,
        prefix.encoded,
        parent.parent_bundle,
        expected_frame.commitment,
        continuation.encoded,
    )
    if evidence.evidence_commitment != expected_commitment:
        raise StructuralError("semantic_v3_producer_evidence_commitment_mismatch")
    return SemanticV3TranscriptEvidence(
        prefix,
        parent.parent_bundle,
        expected_frame,
        continuation,
        expected_commitment,
    )


__all__ = (
    "SEMANTIC_V3_PARENT_ANCHOR_COMMAND",
    "SEMANTIC_V3_PARENT_ANCHOR_FIELD_COUNT",
    "SemanticV3ContinuationEvidence",
    "SemanticV3Geometry",
    "SemanticV3GovernedContext",
    "SemanticV3ParentAnchorFrame",
    "SemanticV3ParentAnchorState",
    "SemanticV3ParentProducerState",
    "SemanticV3PrefixEvidence",
    "SemanticV3TranscriptEvidence",
    "SemanticV3TranscriptProducer",
    "replay_semantic_v3_producer_evidence",
    "semantic_v3_contributor_set_commitment",
    "semantic_v3_descriptors",
    "semantic_v3_schedule_commitment",
    "verify_semantic_v3_continuation",
    "verify_semantic_v3_prefix",
)
