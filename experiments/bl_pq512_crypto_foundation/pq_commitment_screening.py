"""Gate 2E-3/S3 PQ commitment screening reference.

This module is a bounded, synthetic-only admission boundary for the state
commitment bake-off.  It deliberately separates four things that are often
mistaken for one another:

* a common fixed-width commitment/opening interface;
* a dual-PQ authenticated public-coin round;
* a candidate's exact parameter and theorem metadata; and
* actual admission to the Blind Ledger proof suite.

The reference envelope can exercise every candidate through the same masked
SHA3-512 interface, but that envelope is not a lattice PCS, a production
commitment, a complete zero-knowledge proof, or activation evidence.  A
candidate is admitted only when its exact source, parameters, native hiding
theorem, public-coin composition, independent verifier, migration behavior,
and complete-boundary evidence all pass.  The current descriptors therefore
fail closed and keep ``proofSuiteId`` unset.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
from typing import Final, Mapping

from app.batch.pq_tree_reference import require_synthetic_reference_enabled
from experiments.bl_pq512_crypto_foundation.pq_signature_adapters import (
    ML_DSA_87_SUITE_ID,
    SPHINCS_SHAKE_256F_SIMPLE_SUITE_ID,
    is_exact_supported_adapter,
)
from experiments.bl_pq512_crypto_foundation.hash_pad_security_review import (
    hash_pad_security_review,
)


STATUS: Final[str] = "S3_PQ_COMMITMENT_SCREENING_V1_SYNTHETIC_REFERENCE_NONPRODUCTION"
PROOF_SUITE_ID: None = None
ACTIVATION_ALLOWED: Final[bool] = False
COMMITMENT_MAGIC: Final[bytes] = b"BLPQCM01"
COMMITMENT_VERSION: Final[int] = 1
SHA3_512_LENGTH: Final[int] = 64
MAX_PAYLOAD_BYTES: Final[int] = 1 << 20
MAX_SIGNATURE_BYTES: Final[int] = 64 * 1024
MAX_TEXT_LENGTH: Final[int] = 192
ZERO_512: Final[bytes] = bytes(SHA3_512_LENGTH)
MAX_512: Final[bytes] = b"\xff" * SHA3_512_LENGTH

CANDIDATE_IDS: Final[tuple[str, ...]] = (
    "JINDO_STYLE_LATTICE",
    "MODULE_SIS",
    "ROKOKO_STYLE_LATTICE",
    "TRANSPARENT_HASH_CODE",
)
AUTHORITY_SUITE_IDS: Final[tuple[str, ...]] = (
    ML_DSA_87_SUITE_ID,
    SPHINCS_SHAKE_256F_SIMPLE_SUITE_ID,
)

_DESCRIPTOR_DOMAIN = b"BL/PQ512/S3/DESCRIPTOR/v1\x00"
_STATEMENT_DOMAIN = b"BL/PQ512/S3/STATEMENT/v1\x00"
_MASK_DOMAIN = b"BL/PQ512/S3/MASK/v1\x00"
_PRECHALLENGE_DOMAIN = b"BL/PQ512/S3/PRECHALLENGE/v1\x00"
_COMMITMENT_DOMAIN = b"BL/PQ512/S3/COMMITMENT/v1\x00"
_OPENING_DOMAIN = b"BL/PQ512/S3/OPENING/v1\x00"
_COIN_MESSAGE_DOMAIN = b"BL/PQ512/S3/AUTHENTICATED-COIN-MESSAGE/v1\x00"
_COIN_CHALLENGE_DOMAIN = b"BL/PQ512/S3/AUTHENTICATED-COIN-CHALLENGE/v1\x00"
_COIN_TRANSCRIPT_DOMAIN = b"BL/PQ512/S3/AUTHENTICATED-COIN-TRANSCRIPT/v1\x00"
_PUBLIC_TRANSCRIPT_DOMAIN = b"BL/PQ512/S3/PUBLIC-TRANSCRIPT/v1\x00"


class CommitmentScreeningError(ValueError):
    """Stable fail-closed error for the S3 reference boundary."""


def _synthetic() -> None:
    require_synthetic_reference_enabled()


def _ascii(label: str, value: object, maximum: int = MAX_TEXT_LENGTH) -> str:
    if type(value) is not str or not value or len(value) > maximum:
        raise CommitmentScreeningError(f"s3_{label}_invalid")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise CommitmentScreeningError(f"s3_{label}_not_ascii") from exc
    if b"\x00" in encoded:
        raise CommitmentScreeningError(f"s3_{label}_nul")
    return value


def _bytes_exact(
    label: str,
    value: object,
    length: int,
    *,
    nonzero: bool = False,
    allow_max: bool = False,
) -> bytes:
    if type(value) is not bytes or len(value) != length:
        raise CommitmentScreeningError(f"s3_{label}_length_invalid")
    if not allow_max and value == MAX_512:
        raise CommitmentScreeningError(f"s3_{label}_reserved")
    if nonzero and value == ZERO_512:
        raise CommitmentScreeningError(f"s3_{label}_zero")
    return value


def _bounded_bytes(label: str, value: object, maximum: int) -> bytes:
    if type(value) is not bytes or not value or len(value) > maximum:
        raise CommitmentScreeningError(f"s3_{label}_length_invalid")
    return value


def _uint(label: str, value: object, maximum: int) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise CommitmentScreeningError(f"s3_{label}_invalid")
    return value


def _hash(domain: bytes, *parts: bytes) -> bytes:
    if type(domain) is not bytes or not domain:
        raise CommitmentScreeningError("s3_hash_domain_invalid")
    hasher = sha3_512(domain)
    for part in parts:
        if type(part) is not bytes or len(part) > 0xFFFFFFFF:
            raise CommitmentScreeningError("s3_hash_part_invalid")
        hasher.update(len(part).to_bytes(4, "big"))
        hasher.update(part)
    return hasher.digest()


def _text_bytes(value: str) -> bytes:
    return _ascii("text", value).encode("ascii")


def _bool(label: str, value: object) -> bool:
    if type(value) is not bool:
        raise CommitmentScreeningError(f"s3_{label}_bool_invalid")
    return value


@dataclass(frozen=True, slots=True)
class CommitmentBackendDescriptor:
    """Exact candidate metadata required before a backend can be admitted."""

    backend_id: str
    family: str
    source_status: str
    license_status: str
    assumption_status: str
    implementation_status: str
    parameter_identity: str
    field_mapping: str
    parameter_bits: int
    encryption_bits: int
    security_bits: int
    native_hiding_reference: bool
    native_hiding_theorem_reviewed: bool
    authenticated_public_coin_reference: bool
    authenticated_public_coin_reviewed: bool
    independent_verifier: bool
    complete_composition: bool
    trusted_setup: bool
    forbidden_primitive: bool
    fiat_shamir_or_qrom_credit: bool
    external_service: bool
    update_model: str
    proof_grammar: str
    parameter_commitment_512: bytes = b""

    def __post_init__(self) -> None:
        _ascii("backend_id", self.backend_id, 64)
        _ascii("family", self.family, 96)
        for label, value in (
            ("source_status", self.source_status),
            ("license_status", self.license_status),
            ("assumption_status", self.assumption_status),
            ("implementation_status", self.implementation_status),
            ("parameter_identity", self.parameter_identity),
            ("field_mapping", self.field_mapping),
            ("update_model", self.update_model),
            ("proof_grammar", self.proof_grammar),
        ):
            _ascii(label, value, 192)
        for label, value in (
            ("parameter_bits", self.parameter_bits),
            ("encryption_bits", self.encryption_bits),
            ("security_bits", self.security_bits),
        ):
            _uint(label, value, 4096)
        for label, value in (
            ("native_hiding_reference", self.native_hiding_reference),
            ("native_hiding_theorem_reviewed", self.native_hiding_theorem_reviewed),
            ("authenticated_public_coin_reference", self.authenticated_public_coin_reference),
            ("authenticated_public_coin_reviewed", self.authenticated_public_coin_reviewed),
            ("independent_verifier", self.independent_verifier),
            ("complete_composition", self.complete_composition),
            ("trusted_setup", self.trusted_setup),
            ("forbidden_primitive", self.forbidden_primitive),
            ("fiat_shamir_or_qrom_credit", self.fiat_shamir_or_qrom_credit),
            ("external_service", self.external_service),
        ):
            _bool(label, value)
        expected = _hash(
            _DESCRIPTOR_DOMAIN,
            _text_bytes(self.backend_id),
            _text_bytes(self.family),
            _text_bytes(self.source_status),
            _text_bytes(self.license_status),
            _text_bytes(self.assumption_status),
            _text_bytes(self.implementation_status),
            _text_bytes(self.parameter_identity),
            _text_bytes(self.field_mapping),
            self.parameter_bits.to_bytes(2, "big"),
            self.encryption_bits.to_bytes(2, "big"),
            self.security_bits.to_bytes(2, "big"),
            bytes(
                int(value)
                for value in (
                    self.native_hiding_reference,
                    self.native_hiding_theorem_reviewed,
                    self.authenticated_public_coin_reference,
                    self.authenticated_public_coin_reviewed,
                    self.independent_verifier,
                    self.complete_composition,
                    self.trusted_setup,
                    self.forbidden_primitive,
                    self.fiat_shamir_or_qrom_credit,
                    self.external_service,
                )
            ),
            _text_bytes(self.update_model),
            _text_bytes(self.proof_grammar),
        )
        if self.parameter_commitment_512 not in (b"", expected):
            raise CommitmentScreeningError("s3_parameter_commitment_mismatch")
        object.__setattr__(self, "parameter_commitment_512", expected)


def _descriptor(
    backend_id: str,
    family: str,
    *,
    source_status: str,
    license_status: str,
    assumption_status: str,
    implementation_status: str,
    parameter_identity: str,
    field_mapping: str,
    parameter_bits: int,
    encryption_bits: int,
    security_bits: int,
    native_hiding_reviewed: bool,
    public_coin_reviewed: bool,
    complete_composition: bool,
    forbidden_primitive: bool = False,
    trusted_setup: bool = False,
    fiat_shamir_or_qrom_credit: bool = False,
) -> CommitmentBackendDescriptor:
    return CommitmentBackendDescriptor(
        backend_id=backend_id,
        family=family,
        source_status=source_status,
        license_status=license_status,
        assumption_status=assumption_status,
        implementation_status=implementation_status,
        parameter_identity=parameter_identity,
        field_mapping=field_mapping,
        parameter_bits=parameter_bits,
        encryption_bits=encryption_bits,
        security_bits=security_bits,
        native_hiding_reference=True,
        native_hiding_theorem_reviewed=native_hiding_reviewed,
        authenticated_public_coin_reference=True,
        authenticated_public_coin_reviewed=public_coin_reviewed,
        independent_verifier=True,
        complete_composition=complete_composition,
        trusted_setup=trusted_setup,
        forbidden_primitive=forbidden_primitive,
        fiat_shamir_or_qrom_credit=fiat_shamir_or_qrom_credit,
        external_service=False,
        update_model="BL-PQ512-S3-reference-fixed-shape-update-v1",
        proof_grammar="BLPQCM01/versioned-fixed-width-reference-opening-v1",
    )


BACKEND_DESCRIPTORS: Final[tuple[CommitmentBackendDescriptor, ...]] = (
    _descriptor(
        "JINDO_STYLE_LATTICE",
        "lattice_evaluation_hiding",
        source_status="SOURCE_NOT_PINNED",
        license_status="LICENSE_NOT_REVIEWED",
        assumption_status="ASSUMPTION_NOT_REVIEWED",
        implementation_status="REFERENCE_ENVELOPE_ONLY",
        parameter_identity="S3-JINDO-UNPINNED",
        field_mapping="M31-to-Fp16-mapping-not-frozen",
        parameter_bits=0,
        encryption_bits=0,
        security_bits=0,
        native_hiding_reviewed=False,
        public_coin_reviewed=False,
        complete_composition=False,
    ),
    _descriptor(
        "MODULE_SIS",
        "module_sis_commitment",
        source_status="SOURCE_NOT_PINNED",
        license_status="LICENSE_NOT_REVIEWED",
        assumption_status="ASSUMPTION_NOT_REVIEWED",
        implementation_status="REFERENCE_ENVELOPE_ONLY",
        parameter_identity="S3-MODULE-SIS-UNPINNED",
        field_mapping="M31-to-module-SIS-mapping-not-frozen",
        parameter_bits=0,
        encryption_bits=0,
        security_bits=0,
        native_hiding_reviewed=False,
        public_coin_reviewed=False,
        complete_composition=False,
    ),
    _descriptor(
        "ROKOKO_STYLE_LATTICE",
        "lattice_tensor_argument",
        source_status="SOURCE_NOT_PINNED",
        license_status="LICENSE_NOT_REVIEWED",
        assumption_status="ASSUMPTION_NOT_REVIEWED",
        implementation_status="REFERENCE_ENVELOPE_ONLY",
        parameter_identity="S3-ROKOKO-UNPINNED",
        field_mapping="M31-to-tensor-argument-mapping-not-frozen",
        parameter_bits=0,
        encryption_bits=0,
        security_bits=0,
        native_hiding_reviewed=False,
        public_coin_reviewed=False,
        complete_composition=False,
    ),
    _descriptor(
        "TRANSPARENT_HASH_CODE",
        "transparent_hash_code",
        source_status="INTERNAL_REFERENCE_ONLY",
        license_status="INTERNAL_REFERENCE",
        assumption_status="SHA3-512-reference-not-composed-theorem",
        implementation_status="REFERENCE_ENVELOPE_ONLY",
        parameter_identity="S3-SHA3-512-MASKED-REFERENCE-v1",
        field_mapping="raw-byte-records-to-SHA3-512-domain-separated-leaves",
        parameter_bits=512,
        encryption_bits=256,
        security_bits=256,
        native_hiding_reviewed=False,
        public_coin_reviewed=False,
        complete_composition=False,
    ),
)

_DESCRIPTORS_BY_ID: Final[dict[str, CommitmentBackendDescriptor]] = {
    item.backend_id: item for item in BACKEND_DESCRIPTORS
}


@dataclass(frozen=True, slots=True)
class BackendScreenResult:
    descriptor: CommitmentBackendDescriptor
    accepted: bool
    rejection_reasons: tuple[str, ...]
    screening_digest_512: bytes

    def __post_init__(self) -> None:
        _synthetic()
        if type(self.descriptor) is not CommitmentBackendDescriptor:
            raise CommitmentScreeningError("s3_screen_descriptor_type_invalid")
        if type(self.accepted) is not bool:
            raise CommitmentScreeningError("s3_screen_acceptance_type_invalid")
        if type(self.rejection_reasons) is not tuple or any(
            type(item) is not str or not item for item in self.rejection_reasons
        ):
            raise CommitmentScreeningError("s3_screen_reasons_invalid")
        _bytes_exact("screening_digest", self.screening_digest_512, 64, nonzero=True)
        if self.accepted and self.rejection_reasons:
            raise CommitmentScreeningError("s3_accepted_candidate_has_rejection")
        if not self.accepted and not self.rejection_reasons:
            raise CommitmentScreeningError("s3_rejected_candidate_without_reason")

    def as_public_dict(self) -> dict[str, object]:
        return {
            "status": STATUS,
            "backend_id": self.descriptor.backend_id,
            "accepted": self.accepted,
            "rejection_reasons": self.rejection_reasons,
            "parameter_commitment_sha3_512_hex": self.descriptor.parameter_commitment_512.hex(),
            "screening_digest_sha3_512_hex": self.screening_digest_512.hex(),
        }


def backend_descriptor(backend_id: str) -> CommitmentBackendDescriptor:
    _synthetic()
    _ascii("backend_id", backend_id, 64)
    try:
        return _DESCRIPTORS_BY_ID[backend_id]
    except KeyError as exc:
        raise CommitmentScreeningError("s3_backend_unknown") from exc


def screen_backend(backend_id: str) -> BackendScreenResult:
    _synthetic()
    descriptor = backend_descriptor(backend_id)
    reasons: list[str] = []
    if descriptor.source_status != "INTERNAL_REFERENCE_ONLY":
        reasons.append("source_not_pinned_to_reviewed_primary_material")
    if descriptor.license_status not in {"INTERNAL_REFERENCE", "LICENSE_REVIEWED"}:
        reasons.append("license_not_reviewed")
    if descriptor.assumption_status != "REVIEWED_STRICT_PQ_ASSUMPTION":
        reasons.append("strict_pq_assumption_not_reviewed")
    if descriptor.parameter_bits < 256:
        reasons.append("parameter_security_floor_not_met")
    if descriptor.encryption_bits < 256:
        reasons.append("encryption_floor_not_met")
    if descriptor.security_bits < 256:
        reasons.append("per_term_security_floor_not_met")
    if not descriptor.native_hiding_reference:
        reasons.append("native_hiding_reference_missing")
    if not descriptor.native_hiding_theorem_reviewed:
        reasons.append("native_hiding_theorem_unreviewed")
    if not descriptor.authenticated_public_coin_reference:
        reasons.append("authenticated_public_coin_reference_missing")
    if not descriptor.authenticated_public_coin_reviewed:
        reasons.append("authenticated_public_coin_composition_unreviewed")
    if not descriptor.independent_verifier:
        reasons.append("independent_verifier_missing")
    if descriptor.trusted_setup:
        reasons.append("trusted_setup_forbidden")
    if descriptor.forbidden_primitive:
        reasons.append("forbidden_primitive")
    if descriptor.fiat_shamir_or_qrom_credit:
        reasons.append("fiat_shamir_or_qrom_credit_forbidden")
    if descriptor.external_service:
        reasons.append("external_service_forbidden")
    if descriptor.implementation_status != "COMPLETE_REVIEWED_REFERENCE":
        reasons.append("implementation_not_complete_reviewed_reference")
    if not descriptor.complete_composition:
        reasons.append("complete_composition_missing")
    if descriptor.backend_id == "TRANSPARENT_HASH_CODE":
        review = hash_pad_security_review()
        if review.decision != "ADMITTED_GATE_2E_BACKEND":
            reasons.append("hash_pad_security_review_rejected")
    reasons_tuple = tuple(dict.fromkeys(reasons))
    digest = _hash(
        _DESCRIPTOR_DOMAIN,
        descriptor.parameter_commitment_512,
        b"ACCEPTED" if not reasons_tuple else b"REJECTED",
        b"".join(_text_bytes(reason) for reason in reasons_tuple),
    )
    return BackendScreenResult(descriptor, not reasons_tuple, reasons_tuple, digest)


def screen_all_backends() -> tuple[BackendScreenResult, ...]:
    _synthetic()
    return tuple(screen_backend(backend_id) for backend_id in CANDIDATE_IDS)


@dataclass(frozen=True, slots=True)
class CommitmentStatement:
    profile_id: str
    layout_id_512: bytes
    epoch: int
    sequence_before: int
    sequence_after: int
    state_root_before_512: bytes
    state_root_after_512: bytes
    relation_digest_512: bytes
    manifest_digest_512: bytes

    def __post_init__(self) -> None:
        _synthetic()
        _ascii("statement_profile_id", self.profile_id, 64)
        _bytes_exact("statement_layout_id", self.layout_id_512, 64, nonzero=True)
        _uint("statement_epoch", self.epoch, (1 << 64) - 1)
        _uint("statement_sequence_before", self.sequence_before, (1 << 64) - 2)
        _uint("statement_sequence_after", self.sequence_after, (1 << 64) - 1)
        if self.sequence_after != self.sequence_before + 1:
            raise CommitmentScreeningError("s3_statement_sequence_not_sequential")
        for label, value in (
            ("statement_state_root_before", self.state_root_before_512),
            ("statement_state_root_after", self.state_root_after_512),
            ("statement_relation_digest", self.relation_digest_512),
            ("statement_manifest_digest", self.manifest_digest_512),
        ):
            _bytes_exact(label, value, 64, nonzero=True)

    @property
    def canonical_bytes(self) -> bytes:
        profile = _text_bytes(self.profile_id)
        return b"".join(
            (
                COMMITMENT_MAGIC,
                bytes((COMMITMENT_VERSION, len(profile))),
                profile,
                self.layout_id_512,
                self.epoch.to_bytes(8, "big"),
                self.sequence_before.to_bytes(8, "big"),
                self.sequence_after.to_bytes(8, "big"),
                self.state_root_before_512,
                self.state_root_after_512,
                self.relation_digest_512,
                self.manifest_digest_512,
            )
        )

    @property
    def statement_digest_512(self) -> bytes:
        return _hash(_STATEMENT_DOMAIN, self.canonical_bytes)


@dataclass(frozen=True, slots=True)
class PublicCoinAttestation:
    authority_id_512: bytes
    suite_id: str
    public_key: bytes
    message_digest_512: bytes
    signature: bytes

    def __post_init__(self) -> None:
        _synthetic()
        _bytes_exact("coin_authority_id", self.authority_id_512, 64, nonzero=True)
        _ascii("coin_suite_id", self.suite_id, 96)
        if self.suite_id not in AUTHORITY_SUITE_IDS:
            raise CommitmentScreeningError("s3_coin_suite_not_approved")
        _bounded_bytes("coin_public_key", self.public_key, 32 * 1024)
        _bytes_exact("coin_message_digest", self.message_digest_512, 64, nonzero=True)
        _bounded_bytes("coin_signature", self.signature, MAX_SIGNATURE_BYTES)


def derive_public_coin_message_digest(
    session_id_512: bytes,
    round_ordinal: int,
    pre_challenge_digest_512: bytes,
) -> bytes:
    _synthetic()
    _bytes_exact("coin_session_id", session_id_512, 64, nonzero=True)
    _uint("coin_round_ordinal", round_ordinal, (1 << 32) - 1)
    _bytes_exact("coin_pre_challenge", pre_challenge_digest_512, 64, nonzero=True)
    return _hash(
        _COIN_MESSAGE_DOMAIN,
        session_id_512,
        round_ordinal.to_bytes(4, "big"),
        pre_challenge_digest_512,
    )


@dataclass(frozen=True, slots=True)
class AuthenticatedPublicCoinRound:
    session_id_512: bytes
    round_ordinal: int
    pre_challenge_digest_512: bytes
    attestations: tuple[PublicCoinAttestation, ...]

    def __post_init__(self) -> None:
        _synthetic()
        _bytes_exact("coin_session_id", self.session_id_512, 64, nonzero=True)
        _uint("coin_round_ordinal", self.round_ordinal, (1 << 32) - 1)
        _bytes_exact("coin_pre_challenge", self.pre_challenge_digest_512, 64, nonzero=True)
        if type(self.attestations) is not tuple or len(self.attestations) != 2:
            raise CommitmentScreeningError("s3_coin_attestation_count_invalid")
        if any(type(item) is not PublicCoinAttestation for item in self.attestations):
            raise CommitmentScreeningError("s3_coin_attestation_type_invalid")
        if tuple(item.authority_id_512 for item in self.attestations) != tuple(
            sorted(item.authority_id_512 for item in self.attestations)
        ):
            raise CommitmentScreeningError("s3_coin_attestation_order_invalid")
        if len({item.authority_id_512 for item in self.attestations}) != 2:
            raise CommitmentScreeningError("s3_coin_authority_duplicate")
        if {item.suite_id for item in self.attestations} != set(AUTHORITY_SUITE_IDS):
            raise CommitmentScreeningError("s3_coin_dual_pq_suite_set_invalid")
        expected_message = self.message_digest_512
        if any(item.message_digest_512 != expected_message for item in self.attestations):
            raise CommitmentScreeningError("s3_coin_message_digest_mismatch")

    @property
    def message_digest_512(self) -> bytes:
        return derive_public_coin_message_digest(
            self.session_id_512,
            self.round_ordinal,
            self.pre_challenge_digest_512,
        )

    def verify(self, adapters: Mapping[str, object]) -> "VerifiedPublicCoinRound":
        _synthetic()
        if type(adapters) is not dict or set(adapters) != set(AUTHORITY_SUITE_IDS):
            raise CommitmentScreeningError("s3_coin_exact_adapter_set_required")
        for attestation in self.attestations:
            adapter = adapters.get(attestation.suite_id)
            if not is_exact_supported_adapter(adapter, attestation.suite_id):
                raise CommitmentScreeningError("s3_coin_exact_adapter_type_required")
            if not adapter.verify(
                public_key=attestation.public_key,
                message=attestation.message_digest_512,
                signature=attestation.signature,
            ):
                raise CommitmentScreeningError("s3_coin_signature_invalid")
        signature_bytes = b"".join(item.signature for item in self.attestations)
        challenge = _hash(
            _COIN_CHALLENGE_DOMAIN,
            self.session_id_512,
            self.round_ordinal.to_bytes(4, "big"),
            self.pre_challenge_digest_512,
            signature_bytes,
        )
        transcript = _hash(
            _COIN_TRANSCRIPT_DOMAIN,
            self.session_id_512,
            self.round_ordinal.to_bytes(4, "big"),
            self.pre_challenge_digest_512,
            self.message_digest_512,
            signature_bytes,
            challenge,
        )
        return VerifiedPublicCoinRound(self, challenge, transcript)


@dataclass(frozen=True, slots=True)
class VerifiedPublicCoinRound:
    source: AuthenticatedPublicCoinRound
    challenge_512: bytes
    transcript_digest_512: bytes

    def __post_init__(self) -> None:
        _synthetic()
        if type(self.source) is not AuthenticatedPublicCoinRound:
            raise CommitmentScreeningError("s3_verified_coin_source_invalid")
        _bytes_exact("verified_coin_challenge", self.challenge_512, 64, nonzero=True)
        _bytes_exact("verified_coin_transcript", self.transcript_digest_512, 64, nonzero=True)


def derive_pre_challenge_digest(
    backend_id: str,
    statement: CommitmentStatement,
    payload: bytes,
    mask_512: bytes,
) -> bytes:
    """Derive the only S3 pre-challenge value accepted by the opening path."""

    _synthetic()
    descriptor = backend_descriptor(backend_id)
    payload = _bounded_bytes("payload", payload, MAX_PAYLOAD_BYTES)
    _bytes_exact("mask", mask_512, 64, nonzero=True)
    payload_digest = _hash(_OPENING_DOMAIN, payload)
    mask_commitment = _hash(_MASK_DOMAIN, mask_512)
    return _hash(
        _PRECHALLENGE_DOMAIN,
        _text_bytes(descriptor.backend_id),
        descriptor.parameter_commitment_512,
        statement.statement_digest_512,
        payload_digest,
        mask_commitment,
    )


@dataclass(frozen=True, slots=True)
class CommitmentOpening:
    backend_id: str
    statement_digest_512: bytes
    payload: bytes
    mask_512: bytes
    challenge_512: bytes
    transcript_digest_512: bytes

    def __post_init__(self) -> None:
        _synthetic()
        backend_descriptor(self.backend_id)
        _bytes_exact("opening_statement_digest", self.statement_digest_512, 64, nonzero=True)
        _bounded_bytes("opening_payload", self.payload, MAX_PAYLOAD_BYTES)
        _bytes_exact("opening_mask", self.mask_512, 64, nonzero=True)
        _bytes_exact("opening_challenge", self.challenge_512, 64, nonzero=True)
        _bytes_exact("opening_transcript", self.transcript_digest_512, 64, nonzero=True)


@dataclass(frozen=True, slots=True)
class CommitmentArtifact:
    backend_id: str
    parameter_commitment_512: bytes
    statement_digest_512: bytes
    mask_commitment_512: bytes
    commitment_512: bytes
    pre_challenge_digest_512: bytes
    challenge_512: bytes
    public_transcript_digest_512: bytes
    coin_round: AuthenticatedPublicCoinRound

    def __post_init__(self) -> None:
        _synthetic()
        descriptor = backend_descriptor(self.backend_id)
        if self.parameter_commitment_512 != descriptor.parameter_commitment_512:
            raise CommitmentScreeningError("s3_artifact_parameter_identity_mismatch")
        for label, value in (
            ("artifact_statement_digest", self.statement_digest_512),
            ("artifact_mask_commitment", self.mask_commitment_512),
            ("artifact_commitment", self.commitment_512),
            ("artifact_pre_challenge", self.pre_challenge_digest_512),
            ("artifact_challenge", self.challenge_512),
            ("artifact_public_transcript", self.public_transcript_digest_512),
        ):
            _bytes_exact(label, value, 64, nonzero=True)
        if type(self.coin_round) is not AuthenticatedPublicCoinRound:
            raise CommitmentScreeningError("s3_artifact_coin_round_invalid")

    def as_public_dict(self) -> dict[str, object]:
        return {
            "status": STATUS,
            "backend_id": self.backend_id,
            "parameter_commitment_sha3_512_hex": self.parameter_commitment_512.hex(),
            "statement_digest_sha3_512_hex": self.statement_digest_512.hex(),
            "mask_commitment_sha3_512_hex": self.mask_commitment_512.hex(),
            "commitment_sha3_512_hex": self.commitment_512.hex(),
            "pre_challenge_digest_sha3_512_hex": self.pre_challenge_digest_512.hex(),
            "challenge_sha3_512_hex": self.challenge_512.hex(),
            "public_transcript_digest_sha3_512_hex": self.public_transcript_digest_512.hex(),
            "coin_authority_count": len(self.coin_round.attestations),
        }


def build_commitment(
    backend_id: str,
    statement: CommitmentStatement,
    payload: bytes,
    mask_512: bytes,
    coin_round: AuthenticatedPublicCoinRound,
    adapters: Mapping[str, object],
) -> CommitmentArtifact:
    """Build one reference commitment without exposing payload or mask publicly."""

    _synthetic()
    descriptor = backend_descriptor(backend_id)
    payload = _bounded_bytes("payload", payload, MAX_PAYLOAD_BYTES)
    _bytes_exact("mask", mask_512, 64, nonzero=True)
    verified_coin = coin_round.verify(adapters)
    expected_pre_challenge = derive_pre_challenge_digest(
        descriptor.backend_id, statement, payload, mask_512
    )
    if coin_round.pre_challenge_digest_512 != expected_pre_challenge:
        raise CommitmentScreeningError("s3_coin_pre_challenge_binding_mismatch")
    payload_digest = _hash(_OPENING_DOMAIN, payload)
    mask_commitment = _hash(_MASK_DOMAIN, mask_512)
    commitment = _hash(
        _COMMITMENT_DOMAIN,
        _text_bytes(descriptor.backend_id),
        descriptor.parameter_commitment_512,
        statement.statement_digest_512,
        payload_digest,
        mask_commitment,
    )
    public_transcript = _hash(
        _PUBLIC_TRANSCRIPT_DOMAIN,
        descriptor.parameter_commitment_512,
        statement.statement_digest_512,
        commitment,
        expected_pre_challenge,
        verified_coin.challenge_512,
        verified_coin.transcript_digest_512,
    )
    return CommitmentArtifact(
        descriptor.backend_id,
        descriptor.parameter_commitment_512,
        statement.statement_digest_512,
        mask_commitment,
        commitment,
        expected_pre_challenge,
        verified_coin.challenge_512,
        public_transcript,
        coin_round,
    )


def build_opening(
    artifact: CommitmentArtifact,
    payload: bytes,
    mask_512: bytes,
    adapters: Mapping[str, object],
) -> CommitmentOpening:
    _synthetic()
    artifact.coin_round.verify(adapters)
    return CommitmentOpening(
        artifact.backend_id,
        artifact.statement_digest_512,
        _bounded_bytes("opening_payload", payload, MAX_PAYLOAD_BYTES),
        _bytes_exact("opening_mask", mask_512, 64, nonzero=True),
        artifact.challenge_512,
        artifact.public_transcript_digest_512,
    )


def verify_opening(
    artifact: CommitmentArtifact,
    statement: CommitmentStatement,
    opening: CommitmentOpening,
    adapters: Mapping[str, object],
) -> None:
    """Independently recompute the complete commitment and transcript binding."""

    _synthetic()
    if type(artifact) is not CommitmentArtifact or type(opening) is not CommitmentOpening:
        raise CommitmentScreeningError("s3_opening_artifact_type_invalid")
    descriptor = backend_descriptor(artifact.backend_id)
    if opening.backend_id != descriptor.backend_id:
        raise CommitmentScreeningError("s3_opening_backend_mismatch")
    if statement.statement_digest_512 != artifact.statement_digest_512:
        raise CommitmentScreeningError("s3_opening_statement_mismatch")
    verified_coin = artifact.coin_round.verify(adapters)
    expected_pre_challenge = derive_pre_challenge_digest(
        descriptor.backend_id, statement, opening.payload, opening.mask_512
    )
    if expected_pre_challenge != artifact.pre_challenge_digest_512:
        raise CommitmentScreeningError("s3_opening_pre_challenge_mismatch")
    if verified_coin.challenge_512 != artifact.challenge_512:
        raise CommitmentScreeningError("s3_opening_challenge_mismatch")
    if verified_coin.transcript_digest_512 != artifact.coin_round.verify(adapters).transcript_digest_512:
        raise CommitmentScreeningError("s3_opening_transcript_replay_mismatch")
    payload_digest = _hash(_OPENING_DOMAIN, opening.payload)
    mask_commitment = _hash(_MASK_DOMAIN, opening.mask_512)
    if mask_commitment != artifact.mask_commitment_512:
        raise CommitmentScreeningError("s3_opening_mask_commitment_mismatch")
    expected_commitment = _hash(
        _COMMITMENT_DOMAIN,
        _text_bytes(descriptor.backend_id),
        descriptor.parameter_commitment_512,
        statement.statement_digest_512,
        payload_digest,
        mask_commitment,
    )
    if expected_commitment != artifact.commitment_512:
        raise CommitmentScreeningError("s3_opening_commitment_mismatch")
    expected_public_transcript = _hash(
        _PUBLIC_TRANSCRIPT_DOMAIN,
        descriptor.parameter_commitment_512,
        statement.statement_digest_512,
        expected_commitment,
        expected_pre_challenge,
        verified_coin.challenge_512,
        verified_coin.transcript_digest_512,
    )
    if expected_public_transcript != artifact.public_transcript_digest_512:
        raise CommitmentScreeningError("s3_opening_public_transcript_mismatch")
    if opening.challenge_512 != artifact.challenge_512:
        raise CommitmentScreeningError("s3_opening_stale_challenge")
    if opening.transcript_digest_512 != artifact.public_transcript_digest_512:
        raise CommitmentScreeningError("s3_opening_stale_transcript")


__all__ = (
    "ACTIVATION_ALLOWED",
    "AUTHORITY_SUITE_IDS",
    "BACKEND_DESCRIPTORS",
    "CANDIDATE_IDS",
    "COMMITMENT_MAGIC",
    "COMMITMENT_VERSION",
    "PROOF_SUITE_ID",
    "STATUS",
    "AuthenticatedPublicCoinRound",
    "BackendScreenResult",
    "CommitmentArtifact",
    "CommitmentBackendDescriptor",
    "CommitmentOpening",
    "CommitmentScreeningError",
    "CommitmentStatement",
    "PublicCoinAttestation",
    "VerifiedPublicCoinRound",
    "backend_descriptor",
    "build_commitment",
    "build_opening",
    "derive_pre_challenge_digest",
    "derive_public_coin_message_digest",
    "screen_all_backends",
    "screen_backend",
    "verify_opening",
)
