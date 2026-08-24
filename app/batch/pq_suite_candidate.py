"""Synthetic-only reference parser for the unqualified BL-PQ512 candidate.

This module makes the R24 registry and 744-byte sidecar grammar executable. It
does not implement or identify a proof suite, verify a proof, or authorize
activation. Production code must not promote this reference by renaming it.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512

from app.batch.poseidon import FIELD_MODULUS


SIDECAR_MAGIC = b"BLPQSC01"
SIDECAR_VERSION = 1
SIDECAR_FLAGS = 0
SIDECAR_LENGTH = 744
_UINT64_MAX = (1 << 64) - 1
SALT_USE_MAGIC = b"BLPQSALT"
SALT_USE_VERSION = 1
SALT_USE_DOMAIN_CODE = 259
SALT_USE_LENGTH = 78

SIDECAR_LAYOUT_SPEC = (
    ("magic", 0, 8, "ASCII_FIXED"),
    ("encodingVersion", 8, 2, "U16BE"),
    ("flags", 10, 2, "U16BE"),
    ("encodedLength", 12, 4, "U32BE"),
    ("profileId", 16, 64, "NONZERO_BYTES64"),
    ("proofSuiteId", 80, 64, "NONZERO_BYTES64"),
    ("schemaId", 144, 64, "NONZERO_BYTES64"),
    ("verifierArtifactIdentity", 208, 64, "NONZERO_BYTES64"),
    ("strongSettlementDomainId", 272, 64, "NONZERO_BYTES64"),
    ("epoch", 336, 8, "NONZERO_U64BE"),
    ("sequenceBefore", 344, 8, "U64BE"),
    ("sequenceAfter", 352, 8, "U64BE_SUCCESSOR"),
    ("strongNullifierRootBefore", 360, 64, "NONZERO_BYTES64"),
    ("strongNullifierRootAfter", 424, 64, "NONZERO_BYTES64"),
    ("strongGovernanceCommitment", 488, 64, "NONZERO_BYTES64"),
    ("strongPaymentStateRootBefore", 552, 64, "NONZERO_BYTES64"),
    ("strongPaymentStateRootAfter", 616, 64, "NONZERO_BYTES64"),
    ("strongBatchCommitment", 680, 64, "NONZERO_BYTES64"),
)
SIDECAR_LAYOUT = tuple((name, offset, length) for name, offset, length, _ in SIDECAR_LAYOUT_SPEC)

def _bytes64(label: str, value: object) -> bytes:
    if not isinstance(value, bytes) or len(value) != 64:
        raise ValueError(f"candidate_sidecar_{label}_must_be_64_bytes")
    if not any(value):
        raise ValueError(f"candidate_sidecar_{label}_must_be_nonzero")
    return value


def _u64(label: str, value: object, *, nonzero: bool = False) -> int:
    if type(value) is not int or value < 0 or value > _UINT64_MAX:
        raise ValueError(f"candidate_sidecar_{label}_not_u64")
    if nonzero and value == 0:
        raise ValueError(f"candidate_sidecar_{label}_must_be_nonzero")
    return value


def candidate_salt_use_tag(master_salt: bytes) -> bytes:
    """Return the context-free hidden replay tag for one raw master salt."""

    salt = _bytes64("master_salt", master_salt)
    preimage = b"".join(
        (
            SALT_USE_MAGIC,
            SALT_USE_VERSION.to_bytes(2, "big"),
            SALT_USE_DOMAIN_CODE.to_bytes(2, "big"),
            len(salt).to_bytes(2, "big"),
            salt,
        )
    )
    if len(preimage) != SALT_USE_LENGTH:
        raise AssertionError("candidate_salt_use_internal_length_mismatch")
    return sha3_512(preimage).digest()


@dataclass(frozen=True)
class CandidateSidecarV1:
    profile_id: bytes
    proof_suite_id: bytes
    schema_id: bytes
    verifier_artifact_identity: bytes
    strong_settlement_domain_id: bytes
    epoch: int
    sequence_before: int
    sequence_after: int
    strong_nullifier_root_before: bytes
    strong_nullifier_root_after: bytes
    strong_governance_commitment: bytes
    strong_payment_state_root_before: bytes
    strong_payment_state_root_after: bytes
    strong_batch_commitment: bytes

    def __post_init__(self) -> None:
        for label, value in (
            ("profile_id", self.profile_id),
            ("proof_suite_id", self.proof_suite_id),
            ("schema_id", self.schema_id),
            ("verifier_artifact_identity", self.verifier_artifact_identity),
            ("strong_settlement_domain_id", self.strong_settlement_domain_id),
            ("strong_nullifier_root_before", self.strong_nullifier_root_before),
            ("strong_nullifier_root_after", self.strong_nullifier_root_after),
            ("strong_governance_commitment", self.strong_governance_commitment),
            ("strong_payment_state_root_before", self.strong_payment_state_root_before),
            ("strong_payment_state_root_after", self.strong_payment_state_root_after),
            ("strong_batch_commitment", self.strong_batch_commitment),
        ):
            _bytes64(label, value)
        _u64("epoch", self.epoch, nonzero=True)
        before = _u64("sequence_before", self.sequence_before)
        after = _u64("sequence_after", self.sequence_after)
        if before == _UINT64_MAX or after != before + 1:
            raise ValueError("candidate_sidecar_sequence_transition_invalid")
        if self.strong_nullifier_root_before == self.strong_nullifier_root_after:
            raise ValueError("candidate_sidecar_nullifier_root_unchanged")
        if self.strong_payment_state_root_before == self.strong_payment_state_root_after:
            raise ValueError("candidate_sidecar_payment_state_root_unchanged")

    def encode(self) -> bytes:
        encoded = b"".join(
            (
                SIDECAR_MAGIC,
                SIDECAR_VERSION.to_bytes(2, "big"),
                SIDECAR_FLAGS.to_bytes(2, "big"),
                SIDECAR_LENGTH.to_bytes(4, "big"),
                self.profile_id,
                self.proof_suite_id,
                self.schema_id,
                self.verifier_artifact_identity,
                self.strong_settlement_domain_id,
                self.epoch.to_bytes(8, "big"),
                self.sequence_before.to_bytes(8, "big"),
                self.sequence_after.to_bytes(8, "big"),
                self.strong_nullifier_root_before,
                self.strong_nullifier_root_after,
                self.strong_governance_commitment,
                self.strong_payment_state_root_before,
                self.strong_payment_state_root_after,
                self.strong_batch_commitment,
            )
        )
        if len(encoded) != SIDECAR_LENGTH:
            raise AssertionError("candidate_sidecar_internal_length_mismatch")
        return encoded

    @classmethod
    def decode(cls, encoded: bytes) -> "CandidateSidecarV1":
        if not isinstance(encoded, bytes):
            raise TypeError("candidate_sidecar_must_be_bytes")
        if len(encoded) != SIDECAR_LENGTH:
            raise ValueError("candidate_sidecar_length_mismatch")
        if encoded[0:8] != SIDECAR_MAGIC:
            raise ValueError("candidate_sidecar_magic_mismatch")
        if int.from_bytes(encoded[8:10], "big") != SIDECAR_VERSION:
            raise ValueError("candidate_sidecar_version_mismatch")
        if int.from_bytes(encoded[10:12], "big") != SIDECAR_FLAGS:
            raise ValueError("candidate_sidecar_flags_mismatch")
        if int.from_bytes(encoded[12:16], "big") != SIDECAR_LENGTH:
            raise ValueError("candidate_sidecar_declared_length_mismatch")
        return cls(
            profile_id=encoded[16:80],
            proof_suite_id=encoded[80:144],
            schema_id=encoded[144:208],
            verifier_artifact_identity=encoded[208:272],
            strong_settlement_domain_id=encoded[272:336],
            epoch=int.from_bytes(encoded[336:344], "big"),
            sequence_before=int.from_bytes(encoded[344:352], "big"),
            sequence_after=int.from_bytes(encoded[352:360], "big"),
            strong_nullifier_root_before=encoded[360:424],
            strong_nullifier_root_after=encoded[424:488],
            strong_governance_commitment=encoded[488:552],
            strong_payment_state_root_before=encoded[552:616],
            strong_payment_state_root_after=encoded[616:680],
            strong_batch_commitment=encoded[680:744],
        )


@dataclass(frozen=True)
class ActiveSuiteIdentityV1:
    profile_id: bytes
    proof_suite_id: bytes
    schema_id: bytes
    verifier_artifact_identity: bytes
    strong_settlement_domain_id: bytes
    epoch: int
    legacy_protocol_version_alias: bytes
    legacy_settlement_domain_alias: bytes

    def __post_init__(self) -> None:
        for label, value in (
            ("profile_id", self.profile_id),
            ("proof_suite_id", self.proof_suite_id),
            ("schema_id", self.schema_id),
            ("verifier_artifact_identity", self.verifier_artifact_identity),
            ("strong_settlement_domain_id", self.strong_settlement_domain_id),
        ):
            _bytes64(label, value)
        _u64("epoch", self.epoch, nonzero=True)
        if self.legacy_protocol_version_alias != (2).to_bytes(32, "big"):
            raise ValueError("active_legacy_protocol_version_alias_invalid")
        _canonical_felt_alias("legacy_settlement_domain_alias", self.legacy_settlement_domain_alias, nonzero=True)


def _canonical_felt_alias(label: str, value: object, *, nonzero: bool = False) -> bytes:
    if not isinstance(value, bytes) or len(value) != 32:
        raise ValueError(f"{label}_must_be_32_bytes")
    integer = int.from_bytes(value, "big")
    if integer >= FIELD_MODULUS or (nonzero and integer == 0):
        raise ValueError(f"{label}_not_canonical_stark_felt")
    return value


def validate_active_binding(
    encoded_sidecar: bytes,
    public_outputs: object,
    active: ActiveSuiteIdentityV1,
) -> CandidateSidecarV1:
    """Validate structural bytes and the indivisible authenticated ACTIVE identity tuple."""

    if not isinstance(active, ActiveSuiteIdentityV1):
        raise TypeError("candidate_active_identity_required")
    sidecar = CandidateSidecarV1.decode(encoded_sidecar)
    for label, observed, expected in (
        ("profile_id", sidecar.profile_id, active.profile_id),
        ("proof_suite_id", sidecar.proof_suite_id, active.proof_suite_id),
        ("schema_id", sidecar.schema_id, active.schema_id),
        ("verifier_artifact_identity", sidecar.verifier_artifact_identity, active.verifier_artifact_identity),
        ("strong_settlement_domain_id", sidecar.strong_settlement_domain_id, active.strong_settlement_domain_id),
        ("epoch", sidecar.epoch, active.epoch),
    ):
        if observed != expected:
            raise ValueError(f"candidate_active_{label}_mismatch")
    if not isinstance(public_outputs, (tuple, list)) or len(public_outputs) != 12:
        raise ValueError("candidate_public_outputs_must_have_12_fields")
    canonical = tuple(
        _canonical_felt_alias(f"public_output_{index}", value)
        for index, value in enumerate(public_outputs)
    )
    if canonical[0] != active.legacy_protocol_version_alias:
        raise ValueError("candidate_active_protocol_alias_mismatch")
    if canonical[1] != active.legacy_settlement_domain_alias:
        raise ValueError("candidate_active_settlement_domain_alias_mismatch")
    return sidecar
