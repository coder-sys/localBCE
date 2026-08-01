"""Fail-closed public-coin transcript foundation for interactive BL-PQ512.

The authoritative design does not apply Fiat--Shamir.  For every registered
round the prover message is fixed first, then all registered randomness
contributors commit, then all reveal.  Successful rounds require every reveal;
withholding aborts rather than selecting a favorable contributor subset.

PQ signatures are supplied through a narrow verifier protocol.  This module
contains no signature implementation and cannot activate a proof suite.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from hashlib import sha3_512
from typing import Final, Mapping, Protocol, runtime_checkable

from experiments.bl_pq512_crypto_foundation.field16_reference import Fp16, sample_uniform_fp16
from experiments.bl_pq512_crypto_foundation.oods_reference import (
    OODS_DEFAULT_MAX_ATTEMPTS,
    OODS_SAMPLE_DOMAIN_CODE,
    SampledOodsParameter,
    sample_oods_parameter,
)
from experiments.bl_pq512_crypto_foundation.unique_decoding_parameters import (
    UniqueDecodingCandidate,
)
from experiments.bl_pq512_crypto_foundation.selected_proof_parameters import (
    QUERY_COUNT as SELECTED_QUERY_COUNT,
    SELECTED_PARAMETER_COMMITMENT,
    SelectedProofGeometry,
    proof_suite_id,
)


TRANSCRIPT_MAGIC: Final[bytes] = b"BLPQPC01"
TRANSCRIPT_VERSION: Final[int] = 1
INIT_DOMAIN: Final[int] = 768
ROUND_DOMAIN: Final[int] = 772
COMMITMENT_DOMAIN: Final[int] = 773
REVEAL_DOMAIN: Final[int] = 774
SEED_DOMAIN: Final[int] = 775
AUDIT_DOMAIN: Final[int] = 777
SCHEDULE_DOMAIN: Final[int] = 778
QUERY_DOMAIN: Final[int] = 784
SELECTED_SCHEDULE_DOMAIN: Final[int] = 787

PUBLIC_OUTPUTS_LENGTH: Final[int] = 384
SIDECAR_LENGTH: Final[int] = 744
MAX_PROVER_MESSAGE_LENGTH: Final[int] = 64 * 1024 * 1024
MAX_PUBLIC_KEY_LENGTH: Final[int] = 32 * 1024
MAX_SIGNATURE_LENGTH: Final[int] = 64 * 1024
THEOREM_PROVER_MESSAGE_MAGIC: Final[bytes] = b"BLPQPM01"
THEOREM_PROVER_MESSAGE_VERSION: Final[int] = 1
THEOREM_PROVER_MESSAGE_LENGTH: Final[int] = 144

APPROVED_PQ_AUTH_SUITES: Final[frozenset[str]] = frozenset(
    {
        "FIPS204-ML-DSA-87",
        "FIPS205-SLH-DSA-SHAKE-256F",
    }
)


def _bytes_exact(label: str, value: object, length: int, *, nonzero: bool = False) -> bytes:
    if type(value) is not bytes or len(value) != length:
        raise ValueError(f"public_coin_{label}_must_be_{length}_bytes")
    if nonzero and not any(value):
        raise ValueError(f"public_coin_{label}_must_be_nonzero")
    return value


def _bounded_bytes(label: str, value: object, minimum: int, maximum: int) -> bytes:
    if type(value) is not bytes or len(value) < minimum or len(value) > maximum:
        raise ValueError(f"public_coin_{label}_length_invalid")
    return value


def _frame(domain: int, *parts: bytes) -> bytes:
    if type(domain) is not int or domain < 0 or domain > 0xFFFF:
        raise ValueError("public_coin_domain_not_u16")
    framed = bytearray(TRANSCRIPT_MAGIC)
    framed.extend(TRANSCRIPT_VERSION.to_bytes(2, "big"))
    framed.extend(domain.to_bytes(2, "big"))
    for part in parts:
        if type(part) is not bytes or len(part) > 0xFFFFFFFF:
            raise ValueError("public_coin_frame_part_invalid")
        framed.extend(len(part).to_bytes(4, "big"))
        framed.extend(part)
    return bytes(framed)


def _digest(domain: int, *parts: bytes) -> bytes:
    return sha3_512(_frame(domain, *parts)).digest()


class RoundKind(IntEnum):
    INTERACTION_CHALLENGE = 1
    COMPOSITION_COEFFICIENT = 2
    OODS_POINT_PARAMETER = 3
    FRI_BATCH_COEFFICIENT = 4
    FRI_FOLD_COEFFICIENT = 5
    QUERY_POSITIONS = 6


class OutputKind(IntEnum):
    FIELD16 = 1
    QUERY_SEED = 2


class EnvelopeKind(IntEnum):
    RANDOMNESS_COMMITMENT = 1
    RANDOMNESS_REVEAL = 2


class ProverMessageKind(IntEnum):
    MAIN_TRACE_ROOT = 1
    INTERACTION_TRACE_ROOT = 2
    COMPOSITION_ROOT = 3
    OODS_CLAIMS_AND_FRI_MASK_ROOT = 4
    FRI_BATCH_DERIVATION = 5
    FRI_LAYER_ROOT = 6


@dataclass(frozen=True, slots=True)
class TheoremProverMessage:
    """Fixed prover message at one theorem-schedule suspension boundary."""

    kind: ProverMessageKind
    ordinal: int
    primary_digest: bytes
    secondary_digest: bytes = bytes(64)

    def __post_init__(self) -> None:
        if not isinstance(self.kind, ProverMessageKind):
            raise ValueError("public_coin_prover_message_kind_invalid")
        if type(self.ordinal) is not int or not 0 <= self.ordinal <= 0xFFFF:
            raise ValueError("public_coin_prover_message_ordinal_invalid")
        _bytes_exact("prover_message_primary_digest", self.primary_digest, 64, nonzero=True)
        _bytes_exact("prover_message_secondary_digest", self.secondary_digest, 64)
        if self.kind is ProverMessageKind.OODS_CLAIMS_AND_FRI_MASK_ROOT:
            if not any(self.secondary_digest):
                raise ValueError("public_coin_fri_batch_mask_root_required")
        elif any(self.secondary_digest):
            raise ValueError("public_coin_unexpected_secondary_prover_digest")

    def encode(self) -> bytes:
        encoded = b"".join(
            (
                THEOREM_PROVER_MESSAGE_MAGIC,
                THEOREM_PROVER_MESSAGE_VERSION.to_bytes(2, "big"),
                int(self.kind).to_bytes(2, "big"),
                self.ordinal.to_bytes(2, "big"),
                bytes(2),
                self.primary_digest,
                self.secondary_digest,
            )
        )
        if len(encoded) != THEOREM_PROVER_MESSAGE_LENGTH:
            raise AssertionError("public_coin_prover_message_internal_length_mismatch")
        return encoded

    @classmethod
    def decode(cls, encoded: bytes) -> "TheoremProverMessage":
        if type(encoded) is not bytes or len(encoded) != THEOREM_PROVER_MESSAGE_LENGTH:
            raise ValueError("public_coin_theorem_prover_message_length_invalid")
        if encoded[:8] != THEOREM_PROVER_MESSAGE_MAGIC:
            raise ValueError("public_coin_theorem_prover_message_magic_mismatch")
        if int.from_bytes(encoded[8:10], "big") != THEOREM_PROVER_MESSAGE_VERSION:
            raise ValueError("public_coin_theorem_prover_message_version_mismatch")
        try:
            kind = ProverMessageKind(int.from_bytes(encoded[10:12], "big"))
        except ValueError as exc:
            raise ValueError("public_coin_prover_message_kind_invalid") from exc
        if encoded[14:16] != bytes(2):
            raise ValueError("public_coin_theorem_prover_message_flags_nonzero")
        return cls(
            kind=kind,
            ordinal=int.from_bytes(encoded[12:14], "big"),
            primary_digest=encoded[16:80],
            secondary_digest=encoded[80:144],
        )


def validate_theorem_prover_message(
    descriptor: RoundDescriptor,
    *,
    fold_round_count: int,
    encoded: bytes,
) -> TheoremProverMessage:
    """Require the exact commitment/message kind before each challenge.

    In particular, the OODS-claims digest and independent FRI batch-mask root
    are both fixed before the batching coefficient is generated.
    """

    if type(descriptor) is not RoundDescriptor:
        raise TypeError("public_coin_round_descriptor_required")
    if type(fold_round_count) is not int or fold_round_count < 1:
        raise ValueError("public_coin_fold_round_count_invalid")
    message = TheoremProverMessage.decode(encoded)
    if descriptor.kind is RoundKind.INTERACTION_CHALLENGE:
        expected = (ProverMessageKind.MAIN_TRACE_ROOT, 0)
    elif descriptor.kind is RoundKind.COMPOSITION_COEFFICIENT:
        expected = (ProverMessageKind.INTERACTION_TRACE_ROOT, 0)
    elif descriptor.kind is RoundKind.OODS_POINT_PARAMETER:
        expected = (ProverMessageKind.COMPOSITION_ROOT, 0)
    elif descriptor.kind is RoundKind.FRI_BATCH_COEFFICIENT:
        expected = (ProverMessageKind.OODS_CLAIMS_AND_FRI_MASK_ROOT, 0)
    elif descriptor.kind is RoundKind.FRI_FOLD_COEFFICIENT:
        expected = (
            ProverMessageKind.FRI_BATCH_DERIVATION
            if descriptor.ordinal == 0
            else ProverMessageKind.FRI_LAYER_ROOT,
            0 if descriptor.ordinal == 0 else descriptor.ordinal - 1,
        )
    elif descriptor.kind is RoundKind.QUERY_POSITIONS:
        expected = (ProverMessageKind.FRI_LAYER_ROOT, fold_round_count - 1)
    else:
        raise ValueError("public_coin_theorem_descriptor_kind_invalid")
    if (message.kind, message.ordinal) != expected:
        raise ValueError("public_coin_theorem_prover_message_order_mismatch")
    return message


@dataclass(frozen=True, slots=True)
class RoundDescriptor:
    kind: RoundKind
    ordinal: int
    output_kind: OutputKind
    output_count: int

    def __post_init__(self) -> None:
        if not isinstance(self.kind, RoundKind):
            raise ValueError("public_coin_round_kind_invalid")
        if type(self.ordinal) is not int or self.ordinal < 0 or self.ordinal > 0xFFFF:
            raise ValueError("public_coin_round_ordinal_not_u16")
        if not isinstance(self.output_kind, OutputKind):
            raise ValueError("public_coin_output_kind_invalid")
        if type(self.output_count) is not int or self.output_count < 1 or self.output_count > 4096:
            raise ValueError("public_coin_output_count_invalid")
        if self.output_kind is OutputKind.QUERY_SEED and self.output_count != 1:
            raise ValueError("public_coin_query_seed_output_count_must_be_one")
        if self.kind is RoundKind.OODS_POINT_PARAMETER and (
            self.output_kind is not OutputKind.FIELD16 or self.output_count != 1
        ):
            raise ValueError("public_coin_oods_output_must_be_one_field16")

    def encode(self) -> bytes:
        return b"".join(
            (
                int(self.kind).to_bytes(2, "big"),
                self.ordinal.to_bytes(2, "big"),
                int(self.output_kind).to_bytes(2, "big"),
                self.output_count.to_bytes(2, "big"),
            )
        )


@dataclass(frozen=True, slots=True)
class TheoremRoundSchedule:
    """Exact Protocol 1/3/4 public-coin order for one unselected candidate."""

    descriptors: tuple[RoundDescriptor, ...]
    query_domain_size: int
    query_count: int
    query_with_replacement: bool
    maximum_attempts_per_query: int
    final_expansion_substituted: bool = False
    selected: bool = False
    proof_suite_id: None = None
    activation_allowed: bool = False

    def __post_init__(self) -> None:
        if type(self.descriptors) is not tuple or not self.descriptors:
            raise ValueError("public_coin_theorem_schedule_descriptors_required")
        if any(type(value) is not RoundDescriptor for value in self.descriptors):
            raise TypeError("public_coin_theorem_schedule_descriptor_invalid")
        if len(set(self.descriptors)) != len(self.descriptors):
            raise ValueError("public_coin_theorem_schedule_descriptor_duplicate")
        expected_prefix = (
            RoundDescriptor(RoundKind.INTERACTION_CHALLENGE, 0, OutputKind.FIELD16, 2),
            RoundDescriptor(RoundKind.COMPOSITION_COEFFICIENT, 0, OutputKind.FIELD16, 1),
            RoundDescriptor(RoundKind.OODS_POINT_PARAMETER, 0, OutputKind.FIELD16, 1),
            RoundDescriptor(RoundKind.FRI_BATCH_COEFFICIENT, 0, OutputKind.FIELD16, 1),
        )
        expected_suffix = RoundDescriptor(
            RoundKind.QUERY_POSITIONS, 0, OutputKind.QUERY_SEED, 1
        )
        if len(self.descriptors) < 6 or self.descriptors[:4] != expected_prefix:
            raise ValueError("public_coin_theorem_schedule_prefix_invalid")
        if self.descriptors[-1] != expected_suffix:
            raise ValueError("public_coin_theorem_schedule_suffix_invalid")
        fold_descriptors = self.descriptors[4:-1]
        if tuple(descriptor.ordinal for descriptor in fold_descriptors) != tuple(
            range(len(fold_descriptors))
        ) or any(
            descriptor.kind is not RoundKind.FRI_FOLD_COEFFICIENT
            or descriptor.output_kind is not OutputKind.FIELD16
            or descriptor.output_count != 1
            for descriptor in fold_descriptors
        ):
            raise ValueError("public_coin_theorem_schedule_fold_sequence_invalid")
        if type(self.query_domain_size) is not int or not (
            2 <= self.query_domain_size <= 1 << 64
        ):
            raise ValueError("public_coin_theorem_query_domain_invalid")
        if self.query_domain_size & (self.query_domain_size - 1):
            raise ValueError("public_coin_theorem_query_domain_not_power_of_two")
        if self.query_domain_size >> len(fold_descriptors) < 2:
            raise ValueError("public_coin_theorem_fold_count_exhausts_domain")
        if type(self.query_count) is not int or not 1 <= self.query_count <= 0xFFFF:
            raise ValueError("public_coin_theorem_query_count_invalid")
        if self.query_with_replacement is not True:
            raise ValueError("public_coin_theorem_queries_must_use_replacement")
        if self.maximum_attempts_per_query != 1:
            raise ValueError("public_coin_theorem_power_of_two_query_attempt_cap_must_be_one")
        if self.final_expansion_substituted or self.selected or self.proof_suite_id is not None:
            raise ValueError("public_coin_theorem_schedule_cannot_claim_selection")
        if self.activation_allowed:
            raise ValueError("public_coin_theorem_schedule_cannot_activate")

    @property
    def digest(self) -> bytes:
        return schedule_digest(self.descriptors)

    @property
    def fold_round_count(self) -> int:
        return sum(
            descriptor.kind is RoundKind.FRI_FOLD_COEFFICIENT
            for descriptor in self.descriptors
        )

    @property
    def final_line_domain_size(self) -> int:
        return self.query_domain_size >> self.fold_round_count


@dataclass(frozen=True, slots=True)
class SelectedTheoremRoundSchedule:
    """Executable-AIR-bound schedule for the selected local prototype suite."""

    descriptors: tuple[RoundDescriptor, ...]
    query_domain_size: int
    query_count: int
    query_with_replacement: bool
    maximum_attempts_per_query: int
    program_binary_commitment: bytes
    parameter_commitment: bytes = SELECTED_PARAMETER_COMMITMENT
    final_expansion_substituted: bool = True
    selected: bool = True
    activation_allowed: bool = False
    proof_suite_id: bytes = b""

    def __post_init__(self) -> None:
        # Reuse the historical schedule's strict structural checks without
        # weakening its deliberate non-selection gate.
        if type(self.descriptors) is not tuple or len(self.descriptors) < 6:
            raise ValueError("public_coin_selected_schedule_descriptors_invalid")
        expected_prefix = (
            RoundDescriptor(RoundKind.INTERACTION_CHALLENGE, 0, OutputKind.FIELD16, 2),
            RoundDescriptor(RoundKind.COMPOSITION_COEFFICIENT, 0, OutputKind.FIELD16, 1),
            RoundDescriptor(RoundKind.OODS_POINT_PARAMETER, 0, OutputKind.FIELD16, 1),
            RoundDescriptor(RoundKind.FRI_BATCH_COEFFICIENT, 0, OutputKind.FIELD16, 1),
        )
        expected_suffix = RoundDescriptor(
            RoundKind.QUERY_POSITIONS, 0, OutputKind.QUERY_SEED, 1
        )
        folds = self.descriptors[4:-1]
        if (
            self.descriptors[:4] != expected_prefix
            or self.descriptors[-1] != expected_suffix
            or tuple(item.ordinal for item in folds) != tuple(range(len(folds)))
            or any(
                item.kind is not RoundKind.FRI_FOLD_COEFFICIENT
                or item.output_kind is not OutputKind.FIELD16
                or item.output_count != 1
                for item in folds
            )
            or len(set(self.descriptors)) != len(self.descriptors)
        ):
            raise ValueError("public_coin_selected_schedule_order_invalid")
        if (
            type(self.query_domain_size) is not int
            or not 4 <= self.query_domain_size <= 1 << 30
            or self.query_domain_size & (self.query_domain_size - 1)
            or self.query_domain_size >> len(folds) != 2
            or self.query_count != SELECTED_QUERY_COUNT
            or self.query_with_replacement is not True
            or self.maximum_attempts_per_query != 1
        ):
            raise ValueError("public_coin_selected_schedule_geometry_invalid")
        _bytes_exact(
            "selected_program_binary_commitment",
            self.program_binary_commitment,
            64,
            nonzero=True,
        )
        _bytes_exact(
            "selected_parameter_commitment",
            self.parameter_commitment,
            64,
            nonzero=True,
        )
        if self.parameter_commitment != SELECTED_PARAMETER_COMMITMENT:
            raise ValueError("public_coin_selected_parameter_commitment_mismatch")
        if (
            self.final_expansion_substituted is not True
            or self.selected is not True
            or self.activation_allowed
        ):
            raise ValueError("public_coin_selected_schedule_status_invalid")
        expected_suite = proof_suite_id(
            self.program_binary_commitment, self.schedule_commitment
        )
        if self.proof_suite_id == b"":
            object.__setattr__(self, "proof_suite_id", expected_suite)
        elif self.proof_suite_id != expected_suite:
            raise ValueError("public_coin_selected_proof_suite_id_mismatch")

    @property
    def fold_round_count(self) -> int:
        return len(self.descriptors) - 5

    @property
    def final_line_domain_size(self) -> int:
        return self.query_domain_size >> self.fold_round_count

    @property
    def schedule_commitment(self) -> bytes:
        return _digest(
            SELECTED_SCHEDULE_DOMAIN,
            self.parameter_commitment,
            self.program_binary_commitment,
            self.query_domain_size.to_bytes(8, "big"),
            self.query_count.to_bytes(4, "big"),
            bytes((int(self.query_with_replacement),)),
            self.maximum_attempts_per_query.to_bytes(2, "big"),
            self.fold_round_count.to_bytes(2, "big"),
            *(item.encode() for item in self.descriptors),
        )

    @property
    def digest(self) -> bytes:
        return self.schedule_commitment


def schedule_digest(schedule: tuple[RoundDescriptor, ...]) -> bytes:
    if type(schedule) is not tuple or not schedule:
        raise ValueError("public_coin_schedule_must_be_nonempty_tuple")
    if any(type(item) is not RoundDescriptor for item in schedule):
        raise TypeError("public_coin_schedule_descriptor_invalid")
    if len(set(schedule)) != len(schedule):
        raise ValueError("public_coin_schedule_duplicate_descriptor")
    return _digest(SCHEDULE_DOMAIN, *(item.encode() for item in schedule))


def build_theorem_round_schedule(candidate: UniqueDecodingCandidate) -> TheoremRoundSchedule:
    """Bind the exact theorem round order without selecting a rate candidate."""

    if type(candidate) is not UniqueDecodingCandidate:
        raise TypeError("public_coin_unique_decoding_candidate_required")
    if candidate.final_expansion_substituted or candidate.selected:
        raise ValueError("public_coin_candidate_selection_boundary_invalid")
    descriptors = (
        RoundDescriptor(RoundKind.INTERACTION_CHALLENGE, 0, OutputKind.FIELD16, 2),
        RoundDescriptor(RoundKind.COMPOSITION_COEFFICIENT, 0, OutputKind.FIELD16, 1),
        RoundDescriptor(RoundKind.OODS_POINT_PARAMETER, 0, OutputKind.FIELD16, 1),
        RoundDescriptor(RoundKind.FRI_BATCH_COEFFICIENT, 0, OutputKind.FIELD16, 1),
        *(
            RoundDescriptor(RoundKind.FRI_FOLD_COEFFICIENT, ordinal, OutputKind.FIELD16, 1)
            for ordinal in range(candidate.fold_round_count)
        ),
        RoundDescriptor(RoundKind.QUERY_POSITIONS, 0, OutputKind.QUERY_SEED, 1),
    )
    return TheoremRoundSchedule(
        descriptors=descriptors,
        query_domain_size=candidate.evaluation_domain_size,
        query_count=candidate.query_count,
        query_with_replacement=True,
        maximum_attempts_per_query=1,
    )


def build_selected_theorem_round_schedule(
    geometry: SelectedProofGeometry,
) -> SelectedTheoremRoundSchedule:
    if type(geometry) is not SelectedProofGeometry:
        raise TypeError("public_coin_selected_proof_geometry_required")
    descriptors = (
        RoundDescriptor(RoundKind.INTERACTION_CHALLENGE, 0, OutputKind.FIELD16, 2),
        RoundDescriptor(RoundKind.COMPOSITION_COEFFICIENT, 0, OutputKind.FIELD16, 1),
        RoundDescriptor(RoundKind.OODS_POINT_PARAMETER, 0, OutputKind.FIELD16, 1),
        RoundDescriptor(RoundKind.FRI_BATCH_COEFFICIENT, 0, OutputKind.FIELD16, 1),
        *(
            RoundDescriptor(
                RoundKind.FRI_FOLD_COEFFICIENT, ordinal, OutputKind.FIELD16, 1
            )
            for ordinal in range(geometry.fold_round_count)
        ),
        RoundDescriptor(RoundKind.QUERY_POSITIONS, 0, OutputKind.QUERY_SEED, 1),
    )
    return SelectedTheoremRoundSchedule(
        descriptors=descriptors,
        query_domain_size=geometry.query_domain_size,
        query_count=SELECTED_QUERY_COUNT,
        query_with_replacement=True,
        maximum_attempts_per_query=1,
        program_binary_commitment=geometry.program_binary_commitment,
    )


@dataclass(frozen=True, slots=True)
class Contributor:
    contributor_id: bytes
    key_id: bytes
    suite_id: str
    public_key: bytes

    def __post_init__(self) -> None:
        _bytes_exact("contributor_id", self.contributor_id, 64, nonzero=True)
        _bytes_exact("key_id", self.key_id, 64, nonzero=True)
        if self.suite_id not in APPROVED_PQ_AUTH_SUITES:
            raise ValueError("public_coin_contributor_suite_not_approved_pq")
        _bounded_bytes("public_key", self.public_key, 1, MAX_PUBLIC_KEY_LENGTH)

    def encode(self) -> bytes:
        suite = self.suite_id.encode("ascii")
        return _frame(
            SCHEDULE_DOMAIN,
            self.contributor_id,
            self.key_id,
            suite,
            self.public_key,
        )


@runtime_checkable
class PqSignatureVerifier(Protocol):
    """Adapter contract; implementations must verify the named standardized suite."""

    suite_id: str
    synthetic_only: bool

    def verify(self, *, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Return true only for a valid signature under ``public_key``."""


@dataclass(frozen=True, slots=True)
class SignedEnvelope:
    contributor_id: bytes
    payload: bytes
    signature: bytes

    def __post_init__(self) -> None:
        _bytes_exact("envelope_contributor_id", self.contributor_id, 64, nonzero=True)
        _bytes_exact("envelope_payload", self.payload, 64)
        _bounded_bytes("signature", self.signature, 1, MAX_SIGNATURE_LENGTH)


@dataclass(frozen=True, slots=True)
class ChallengeOutput:
    seed: bytes
    field_elements: tuple[Fp16, ...]
    oods_sample: SampledOodsParameter | None = None

    def __post_init__(self) -> None:
        _bytes_exact("challenge_seed", self.seed, 64)
        if self.oods_sample is not None:
            if type(self.oods_sample) is not SampledOodsParameter:
                raise TypeError("public_coin_oods_sample_type_invalid")
            if self.field_elements != (self.oods_sample.parameter.element,):
                raise ValueError("public_coin_oods_sample_output_mismatch")


@dataclass(frozen=True, slots=True)
class RoundEvidence:
    round_index: int
    descriptor: RoundDescriptor
    prior_root: bytes
    prover_message: bytes
    commitments: tuple[SignedEnvelope, ...]
    reveals: tuple[SignedEnvelope, ...]
    challenge: ChallengeOutput
    resulting_root: bytes


def randomness_commitment(
    *,
    session_id: bytes,
    round_index: int,
    descriptor: RoundDescriptor,
    prior_root: bytes,
    prover_message_sha3_512: bytes,
    contributor_id: bytes,
    reveal: bytes,
) -> bytes:
    _bytes_exact("session_id", session_id, 64, nonzero=True)
    _bytes_exact("prior_root", prior_root, 64, nonzero=True)
    _bytes_exact("prover_message_digest", prover_message_sha3_512, 64)
    _bytes_exact("commitment_contributor_id", contributor_id, 64, nonzero=True)
    _bytes_exact("randomness_reveal", reveal, 64)
    if type(round_index) is not int or round_index < 0 or round_index > 0xFFFFFFFF:
        raise ValueError("public_coin_round_index_not_u32")
    return _digest(
        COMMITMENT_DOMAIN,
        session_id,
        round_index.to_bytes(4, "big"),
        descriptor.encode(),
        prior_root,
        prover_message_sha3_512,
        contributor_id,
        reveal,
    )


class PublicCoinSession:
    """One exact, append-only public-coin challenge session."""

    def __init__(
        self,
        *,
        session_id: bytes,
        public_outputs: bytes,
        sidecar: bytes,
        candidate_descriptor_sha3_512: bytes,
        schedule: tuple[RoundDescriptor, ...],
        contributors: tuple[Contributor, ...],
        verifiers: Mapping[str, PqSignatureVerifier],
        production_mode: bool,
        theorem_schedule: TheoremRoundSchedule | SelectedTheoremRoundSchedule | None = None,
    ) -> None:
        self.session_id = _bytes_exact("session_id", session_id, 64, nonzero=True)
        _bytes_exact("public_outputs", public_outputs, PUBLIC_OUTPUTS_LENGTH)
        _bytes_exact("sidecar", sidecar, SIDECAR_LENGTH)
        _bytes_exact("candidate_descriptor_digest", candidate_descriptor_sha3_512, 64, nonzero=True)
        if type(production_mode) is not bool:
            raise ValueError("public_coin_production_mode_must_be_bool")
        if not isinstance(schedule, tuple) or not schedule:
            raise ValueError("public_coin_schedule_must_be_nonempty_tuple")
        if any(not isinstance(descriptor, RoundDescriptor) for descriptor in schedule):
            raise ValueError("public_coin_schedule_descriptor_invalid")
        if len(set(schedule)) != len(schedule):
            raise ValueError("public_coin_schedule_duplicate_descriptor")
        if theorem_schedule is not None:
            if type(theorem_schedule) not in {
                TheoremRoundSchedule,
                SelectedTheoremRoundSchedule,
            }:
                raise TypeError("public_coin_theorem_schedule_exact_type_required")
            if schedule != theorem_schedule.descriptors:
                raise ValueError("public_coin_theorem_schedule_descriptor_mismatch")
        if not isinstance(contributors, tuple) or len(contributors) < 2:
            raise ValueError("public_coin_requires_at_least_two_contributors")
        if any(not isinstance(contributor, Contributor) for contributor in contributors):
            raise ValueError("public_coin_contributor_invalid")
        ids = tuple(contributor.contributor_id for contributor in contributors)
        if ids != tuple(sorted(ids)) or len(set(ids)) != len(ids):
            raise ValueError("public_coin_contributors_must_be_unique_and_sorted")
        key_ids = tuple(contributor.key_id for contributor in contributors)
        if len(set(key_ids)) != len(key_ids):
            raise ValueError("public_coin_contributor_key_id_duplicate")
        if production_mode and len({contributor.suite_id for contributor in contributors}) < 2:
            raise ValueError("public_coin_production_requires_pq_suite_diversity")

        checked_verifiers: dict[str, PqSignatureVerifier] = {}
        for suite_id in {contributor.suite_id for contributor in contributors}:
            verifier = verifiers.get(suite_id)
            if not isinstance(verifier, PqSignatureVerifier) or verifier.suite_id != suite_id:
                raise ValueError("public_coin_signature_verifier_missing_or_mismatched")
            if type(verifier.synthetic_only) is not bool:
                raise ValueError("public_coin_signature_verifier_mode_invalid")
            if production_mode and verifier.synthetic_only:
                raise ValueError("public_coin_synthetic_signature_verifier_forbidden_in_production")
            checked_verifiers[suite_id] = verifier

        self.schedule = schedule
        self.public_outputs = public_outputs
        self.sidecar = sidecar
        self.candidate_descriptor_sha3_512 = candidate_descriptor_sha3_512
        self.contributors = contributors
        self.verifiers = checked_verifiers
        self.production_mode = production_mode
        self.theorem_schedule = theorem_schedule
        self.schedule_digest = (
            theorem_schedule.digest
            if theorem_schedule is not None
            else schedule_digest(schedule)
        )
        contributor_digest = _digest(SCHEDULE_DOMAIN, *(item.encode() for item in contributors))
        self.transcript_root = _digest(
            INIT_DOMAIN,
            self.session_id,
            public_outputs,
            sidecar,
            candidate_descriptor_sha3_512,
            self.schedule_digest,
            contributor_digest,
        )
        self._contributor_by_id = {item.contributor_id: item for item in contributors}
        self._round_index = 0
        self._phase = "READY"
        self._descriptor: RoundDescriptor | None = None
        self._prover_message: bytes | None = None
        self._prior_root: bytes | None = None
        self._commitments: dict[bytes, SignedEnvelope] = {}
        self._reveals: dict[bytes, SignedEnvelope] = {}
        self._evidence: list[RoundEvidence] = []
        self._abort_reason: str | None = None

    @property
    def phase(self) -> str:
        return self._phase

    @property
    def abort_reason(self) -> str | None:
        return self._abort_reason

    @property
    def evidence(self) -> tuple[RoundEvidence, ...]:
        return tuple(self._evidence)

    @property
    def complete(self) -> bool:
        return self._phase == "COMPLETE"

    def _ensure_live(self) -> None:
        if self._phase == "ABORTED":
            raise RuntimeError(f"public_coin_session_aborted:{self._abort_reason}")

    def _abort(self, reason: str) -> None:
        self._phase = "ABORTED"
        self._abort_reason = reason

    def begin_round(self, descriptor: RoundDescriptor, prover_message: bytes) -> None:
        self._ensure_live()
        if self._phase != "READY":
            raise RuntimeError("public_coin_round_begin_wrong_phase")
        if self._round_index >= len(self.schedule):
            raise RuntimeError("public_coin_schedule_already_complete")
        if descriptor != self.schedule[self._round_index]:
            self._abort("unexpected_round_descriptor")
            raise ValueError("public_coin_unexpected_round_descriptor")
        message = _bounded_bytes("prover_message", prover_message, 1, MAX_PROVER_MESSAGE_LENGTH)
        if self.theorem_schedule is not None:
            try:
                validate_theorem_prover_message(
                    descriptor,
                    fold_round_count=self.theorem_schedule.fold_round_count,
                    encoded=message,
                )
            except (TypeError, ValueError):
                self._abort("invalid_theorem_prover_message")
                raise
        self._descriptor = descriptor
        self._prover_message = message
        self._prior_root = self.transcript_root
        self._commitments.clear()
        self._reveals.clear()
        self._phase = "COMMIT"

    def signature_message(
        self,
        kind: EnvelopeKind,
        contributor_id: bytes,
        payload: bytes,
    ) -> bytes:
        self._ensure_live()
        if not isinstance(kind, EnvelopeKind):
            raise ValueError("public_coin_envelope_kind_invalid")
        contributor = self._contributor(contributor_id)
        _bytes_exact("signed_payload", payload, 64)
        if self._descriptor is None or self._prior_root is None or self._prover_message is None:
            raise RuntimeError("public_coin_no_active_round")
        domain = COMMITMENT_DOMAIN if kind is EnvelopeKind.RANDOMNESS_COMMITMENT else REVEAL_DOMAIN
        return _frame(
            domain,
            self.session_id,
            self._round_index.to_bytes(4, "big"),
            self._descriptor.encode(),
            self._prior_root,
            sha3_512(self._prover_message).digest(),
            contributor.contributor_id,
            contributor.key_id,
            payload,
        )

    def commitment_for(self, contributor_id: bytes, reveal: bytes) -> bytes:
        self._ensure_live()
        if self._descriptor is None or self._prior_root is None or self._prover_message is None:
            raise RuntimeError("public_coin_no_active_round")
        return randomness_commitment(
            session_id=self.session_id,
            round_index=self._round_index,
            descriptor=self._descriptor,
            prior_root=self._prior_root,
            prover_message_sha3_512=sha3_512(self._prover_message).digest(),
            contributor_id=contributor_id,
            reveal=reveal,
        )

    def _contributor(self, contributor_id: bytes) -> Contributor:
        _bytes_exact("contributor_id", contributor_id, 64, nonzero=True)
        contributor = self._contributor_by_id.get(contributor_id)
        if contributor is None:
            raise ValueError("public_coin_unknown_contributor")
        return contributor

    def _verify_envelope(self, kind: EnvelopeKind, envelope: SignedEnvelope) -> Contributor:
        contributor = self._contributor(envelope.contributor_id)
        message = self.signature_message(kind, envelope.contributor_id, envelope.payload)
        verifier = self.verifiers[contributor.suite_id]
        try:
            verified = verifier.verify(
                public_key=contributor.public_key,
                message=message,
                signature=envelope.signature,
            )
        except Exception as exc:
            raise ValueError("public_coin_signature_verifier_failed_closed") from exc
        if verified is not True:
            raise ValueError("public_coin_signature_invalid")
        return contributor

    def submit_commitment(self, envelope: SignedEnvelope) -> None:
        self._ensure_live()
        if self._phase != "COMMIT":
            raise RuntimeError("public_coin_commitment_wrong_phase")
        if not isinstance(envelope, SignedEnvelope):
            raise TypeError("public_coin_signed_envelope_required")
        contributor = self._verify_envelope(EnvelopeKind.RANDOMNESS_COMMITMENT, envelope)
        if contributor.contributor_id in self._commitments:
            self._abort("duplicate_commitment")
            raise ValueError("public_coin_duplicate_commitment")
        self._commitments[contributor.contributor_id] = envelope
        if len(self._commitments) == len(self.contributors):
            self._phase = "REVEAL"

    def submit_reveal(self, envelope: SignedEnvelope) -> None:
        self._ensure_live()
        if self._phase != "REVEAL":
            raise RuntimeError("public_coin_reveal_before_all_commitments")
        if not isinstance(envelope, SignedEnvelope):
            raise TypeError("public_coin_signed_envelope_required")
        contributor = self._verify_envelope(EnvelopeKind.RANDOMNESS_REVEAL, envelope)
        contributor_id = contributor.contributor_id
        if contributor_id in self._reveals:
            self._abort("duplicate_reveal")
            raise ValueError("public_coin_duplicate_reveal")
        expected = self.commitment_for(contributor_id, envelope.payload)
        if expected != self._commitments[contributor_id].payload:
            self._abort("commitment_reveal_mismatch")
            raise ValueError("public_coin_commitment_reveal_mismatch")
        self._reveals[contributor_id] = envelope

    def finalize_round(self) -> ChallengeOutput:
        self._ensure_live()
        if self._phase not in {"COMMIT", "REVEAL"}:
            raise RuntimeError("public_coin_finalize_wrong_phase")
        if len(self._commitments) != len(self.contributors):
            self._abort("missing_commitment")
            raise RuntimeError("public_coin_missing_commitment_aborts")
        if len(self._reveals) != len(self.contributors):
            self._abort("missing_reveal")
            raise RuntimeError("public_coin_missing_reveal_aborts")
        if self._descriptor is None or self._prior_root is None or self._prover_message is None:
            raise AssertionError("public_coin_active_round_state_incomplete")

        ordered_commitments = tuple(self._commitments[item.contributor_id] for item in self.contributors)
        ordered_reveals = tuple(self._reveals[item.contributor_id] for item in self.contributors)
        contribution_parts: list[bytes] = []
        for contributor, commitment, reveal in zip(
            self.contributors, ordered_commitments, ordered_reveals, strict=True
        ):
            contribution_parts.extend((contributor.contributor_id, commitment.payload, reveal.payload))
        seed = _digest(
            SEED_DOMAIN,
            self.session_id,
            self._round_index.to_bytes(4, "big"),
            self._descriptor.encode(),
            self._prior_root,
            self._prover_message,
            *contribution_parts,
        )
        oods_sample: SampledOodsParameter | None = None
        try:
            if self._descriptor.kind is RoundKind.OODS_POINT_PARAMETER:
                oods_sample = sample_oods_parameter(
                    seed,
                    session_id=self.session_id,
                    round_index=self._round_index,
                )
                field_elements = (oods_sample.parameter.element,)
            elif self._descriptor.output_kind is OutputKind.FIELD16:
                field_elements = tuple(
                    sample_uniform_fp16(
                        seed,
                        session_id=self.session_id,
                        round_index=self._round_index,
                        draw_index=draw,
                    ).element
                    for draw in range(self._descriptor.output_count)
                )
            else:
                field_elements = ()
        except RuntimeError as exc:
            self._abort("challenge_sampling_attempt_cap_exhausted")
            raise RuntimeError("public_coin_challenge_sampling_attempt_cap_exhausted") from exc
        challenge = ChallengeOutput(
            seed=seed,
            field_elements=field_elements,
            oods_sample=oods_sample,
        )

        audit_parts = [
            self.session_id,
            self._round_index.to_bytes(4, "big"),
            self._descriptor.encode(),
            self._prior_root,
            self._prover_message,
            seed,
        ]
        for commitment, reveal in zip(ordered_commitments, ordered_reveals, strict=True):
            audit_parts.extend(
                (
                    commitment.contributor_id,
                    commitment.payload,
                    commitment.signature,
                    reveal.payload,
                    reveal.signature,
                )
            )
        if oods_sample is not None:
            audit_parts.extend(
                (
                    OODS_SAMPLE_DOMAIN_CODE.to_bytes(2, "big"),
                    OODS_DEFAULT_MAX_ATTEMPTS.to_bytes(2, "big"),
                    oods_sample.accepted_attempt.to_bytes(2, "big"),
                    oods_sample.digest,
                )
            )
        audit_parts.extend(element.encode() for element in field_elements)
        resulting_root = _digest(AUDIT_DOMAIN, *audit_parts)
        self._evidence.append(
            RoundEvidence(
                round_index=self._round_index,
                descriptor=self._descriptor,
                prior_root=self._prior_root,
                prover_message=self._prover_message,
                commitments=ordered_commitments,
                reveals=ordered_reveals,
                challenge=challenge,
                resulting_root=resulting_root,
            )
        )
        self.transcript_root = resulting_root
        self._round_index += 1
        self._descriptor = None
        self._prover_message = None
        self._prior_root = None
        self._commitments.clear()
        self._reveals.clear()
        self._phase = "COMPLETE" if self._round_index == len(self.schedule) else "READY"
        return challenge


def sample_query_positions(
    seed: bytes,
    *,
    session_id: bytes,
    domain_size: int,
    query_count: int,
    with_replacement: bool,
    maximum_attempts_per_position: int = 1024,
) -> tuple[int, ...]:
    """Uniformly map a public query seed to positions with explicit rejection."""

    _bytes_exact("query_seed", seed, 64)
    _bytes_exact("session_id", session_id, 64, nonzero=True)
    if type(domain_size) is not int or domain_size < 2 or domain_size > (1 << 64):
        raise ValueError("public_coin_query_domain_size_invalid")
    if type(query_count) is not int or query_count < 1 or query_count > 0xFFFF:
        raise ValueError("public_coin_query_count_invalid")
    if type(with_replacement) is not bool:
        raise ValueError("public_coin_query_replacement_policy_must_be_bool")
    if not with_replacement and query_count > domain_size:
        raise ValueError("public_coin_unique_query_count_exceeds_domain")
    if (
        type(maximum_attempts_per_position) is not int
        or maximum_attempts_per_position < 1
        or maximum_attempts_per_position > 0xFFFF
    ):
        raise ValueError("public_coin_query_attempt_cap_invalid")

    limit = ((1 << 512) // domain_size) * domain_size
    selected: list[int] = []
    seen: set[int] = set()
    for draw in range(query_count):
        accepted = False
        for attempt in range(maximum_attempts_per_position):
            digest = _digest(
                QUERY_DOMAIN,
                session_id,
                seed,
                draw.to_bytes(4, "big"),
                attempt.to_bytes(2, "big"),
            )
            candidate = int.from_bytes(digest, "big")
            if candidate >= limit:
                continue
            position = candidate % domain_size
            if not with_replacement and position in seen:
                continue
            selected.append(position)
            seen.add(position)
            accepted = True
            break
        if not accepted:
            raise RuntimeError("public_coin_query_sampling_attempt_cap_exhausted")
    return tuple(selected)
