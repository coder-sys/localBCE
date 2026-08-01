"""Synthetic-only strong verifier-interface reference for BL-PQ512.

This module joins the exact Privacy V2 ``bytes32[12]`` statement, the sole
744-byte candidate sidecar, and a separate opaque proof body.  It is a local
capability model, not a STARK verifier, an activated suite, or production
state.  It deliberately cannot run without three explicit local/test flags.

The candidate strong-batch helper implements only the fixed preimage inventory
already frozen for review: the 680-byte sidecar prefix, all twelve ordered
public fields, two private 512-bit commitments, and one raw 512-bit master
salt.  The proof suite, transcript, and production typed-hash grammar remain
unselected and this REFERENCE/v0 helper must not be promoted as that choice.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from hashlib import sha3_512
import hmac
from itertools import islice
import os
import secrets
import threading
from typing import Final, Sequence

from app.batch.poseidon import FIELD_MODULUS
from app.batch.pq_suite_candidate import (
    ActiveSuiteIdentityV1,
    CandidateSidecarV1,
    SIDECAR_LENGTH,
    candidate_salt_use_tag,
    validate_active_binding,
)


REFERENCE_STATUS: Final[str] = (
    "SYNTHETIC_REFERENCE_V0_NOT_A_STARK_VERIFIER_NOT_ACTIVATABLE"
)
SYNTHETIC_VERIFIER_REFERENCE_ENABLE_ENV: Final[str] = (
    "BL_ALLOW_SYNTHETIC_PQ_VERIFIER_REFERENCE"
)
VERIFICATION_KIND: Final[str] = "SYNTHETIC_CAPABILITY_REFERENCE_ONLY"
PUBLIC_OUTPUT_COUNT: Final[int] = 12
PUBLIC_OUTPUT_BYTES: Final[int] = 32
WIDE_BYTES: Final[int] = 64
SIDECAR_PREFIX_BYTES: Final[int] = 680
MAX_SYNTHETIC_PROOF_BODY_BYTES: Final[int] = 1024 * 1024
MAX_SYNTHETIC_ISSUED_PROOFS: Final[int] = 4096

_UINT64_MAX: Final[int] = (1 << 64) - 1
_SYNTHETIC_ENVS: Final[frozenset[str]] = frozenset({"local", "test", "unit", "ci"})
_ACTIVE_REGISTRY_DOMAIN: Final[bytes] = b"BL/PQ512/ACTIVE-REGISTRY/REFERENCE/v0"
_STRONG_BATCH_DOMAIN: Final[bytes] = b"BL/BATCH/PQ512/REFERENCE/v0"
_STATEMENT_DOMAIN: Final[bytes] = b"BL/PQ512/VERIFIER-STATEMENT/REFERENCE/v0"
_RECEIPT_DOMAIN: Final[bytes] = b"BL/PQ512/VERIFIED-OUTPUTS/REFERENCE/v0"
_SYNTHETIC_PROOF_MAGIC: Final[bytes] = b"BLPQSYNPROOFv0\x00"


def require_synthetic_verifier_reference_enabled() -> None:
    environment = os.environ.get("BL_ENV", "").strip().lower()
    if (
        environment not in _SYNTHETIC_ENVS
        or os.environ.get("BL_DEV") != "1"
        or os.environ.get(SYNTHETIC_VERIFIER_REFERENCE_ENABLE_ENV) != "1"
    ):
        raise RuntimeError(
            "synthetic_pq_verifier_reference_forbidden:"
            "requires_local_test_env_and_explicit_dev_flags"
        )


def _exact_bytes(
    label: str,
    value: object,
    *,
    length: int,
    nonzero: bool = False,
) -> bytes:
    if type(value) is not bytes:
        raise TypeError(f"{label}_must_be_exact_bytes")
    if len(value) != length:
        raise ValueError(f"{label}_length_invalid")
    if nonzero and not any(value):
        raise ValueError(f"{label}_must_be_nonzero")
    return value


def _u64(label: str, value: object, *, nonzero: bool = False) -> int:
    if type(value) is not int:
        raise TypeError(f"{label}_must_be_integer")
    if value < 0 or value > _UINT64_MAX or (nonzero and value == 0):
        raise ValueError(f"{label}_out_of_range")
    return value


def canonical_public_outputs_v2(values: Sequence[bytes]) -> tuple[bytes, ...]:
    """Freeze the exact ordered twelve-field ABI as canonical Stark felts."""

    require_synthetic_verifier_reference_enabled()
    if isinstance(values, (str, bytes, bytearray, memoryview)):
        raise TypeError("synthetic_verifier_public_outputs_must_be_sequence")
    try:
        iterator = iter(values)
    except TypeError as exc:
        raise TypeError("synthetic_verifier_public_outputs_must_be_iterable") from exc
    materialized = tuple(islice(iterator, PUBLIC_OUTPUT_COUNT + 1))
    if len(materialized) != PUBLIC_OUTPUT_COUNT:
        raise ValueError("synthetic_verifier_public_output_count_mismatch")
    canonical = tuple(
        _exact_bytes(
            f"synthetic_verifier_public_output_{index}",
            value,
            length=PUBLIC_OUTPUT_BYTES,
        )
        for index, value in enumerate(materialized)
    )
    for index, value in enumerate(canonical):
        if int.from_bytes(value, "big") >= FIELD_MODULUS:
            raise ValueError(f"synthetic_verifier_public_output_not_stark_felt:{index}")
    if int.from_bytes(canonical[0], "big") != 2:
        raise ValueError("synthetic_verifier_protocol_version_mismatch")
    if not any(canonical[1]):
        raise ValueError("synthetic_verifier_settlement_domain_zero")
    if not any(canonical[2]):
        raise ValueError("synthetic_verifier_batch_nonce_zero")
    return canonical


@dataclass(frozen=True, slots=True)
class SyntheticActiveSuiteTupleV1:
    """One registry-owned synthetic tuple; never caller-selected per request."""

    profile_id: bytes
    proof_suite_id: bytes
    schema_id: bytes
    verifier_artifact_identity: bytes
    strong_settlement_domain_id: bytes
    epoch: int
    legacy_protocol_version_alias: bytes
    legacy_settlement_domain_alias: bytes
    reference_status: str = REFERENCE_STATUS

    def __post_init__(self) -> None:
        require_synthetic_verifier_reference_enabled()
        if self.reference_status != REFERENCE_STATUS:
            raise ValueError("synthetic_active_tuple_reference_status_invalid")
        for label, value in (
            ("profile_id", self.profile_id),
            ("proof_suite_id", self.proof_suite_id),
            ("schema_id", self.schema_id),
            ("verifier_artifact_identity", self.verifier_artifact_identity),
            ("strong_settlement_domain_id", self.strong_settlement_domain_id),
        ):
            _exact_bytes(f"synthetic_active_{label}", value, length=WIDE_BYTES, nonzero=True)
        _u64("synthetic_active_epoch", self.epoch, nonzero=True)
        protocol = _exact_bytes(
            "synthetic_active_legacy_protocol_alias",
            self.legacy_protocol_version_alias,
            length=PUBLIC_OUTPUT_BYTES,
        )
        settlement = _exact_bytes(
            "synthetic_active_legacy_settlement_alias",
            self.legacy_settlement_domain_alias,
            length=PUBLIC_OUTPUT_BYTES,
            nonzero=True,
        )
        if int.from_bytes(protocol, "big") != 2:
            raise ValueError("synthetic_active_protocol_alias_invalid")
        if int.from_bytes(settlement, "big") >= FIELD_MODULUS:
            raise ValueError("synthetic_active_settlement_alias_not_stark_felt")

    def candidate_identity(self) -> ActiveSuiteIdentityV1:
        require_synthetic_verifier_reference_enabled()
        return ActiveSuiteIdentityV1(
            profile_id=self.profile_id,
            proof_suite_id=self.proof_suite_id,
            schema_id=self.schema_id,
            verifier_artifact_identity=self.verifier_artifact_identity,
            strong_settlement_domain_id=self.strong_settlement_domain_id,
            epoch=self.epoch,
            legacy_protocol_version_alias=self.legacy_protocol_version_alias,
            legacy_settlement_domain_alias=self.legacy_settlement_domain_alias,
        )

    def encode(self) -> bytes:
        require_synthetic_verifier_reference_enabled()
        return b"".join(
            (
                self.profile_id,
                self.proof_suite_id,
                self.schema_id,
                self.verifier_artifact_identity,
                self.strong_settlement_domain_id,
                self.epoch.to_bytes(8, "big"),
                self.legacy_protocol_version_alias,
                self.legacy_settlement_domain_alias,
            )
        )


@dataclass(frozen=True, slots=True)
class SyntheticActiveRegistryV1:
    """Pins one synthetic active tuple outside every untrusted request."""

    _active: SyntheticActiveSuiteTupleV1
    _commitment: bytes = field(init=False, repr=False)

    def __post_init__(self) -> None:
        require_synthetic_verifier_reference_enabled()
        if type(self._active) is not SyntheticActiveSuiteTupleV1:
            raise TypeError("synthetic_active_registry_tuple_required")
        object.__setattr__(
            self,
            "_commitment",
            sha3_512(_ACTIVE_REGISTRY_DOMAIN + self._active.encode()).digest(),
        )

    def _validate_integrity(self) -> None:
        if type(self._active) is not SyntheticActiveSuiteTupleV1:
            raise ValueError("synthetic_active_registry_integrity_mismatch")
        expected = sha3_512(_ACTIVE_REGISTRY_DOMAIN + self._active.encode()).digest()
        if not hmac.compare_digest(self._commitment, expected):
            raise ValueError("synthetic_active_registry_integrity_mismatch")

    @property
    def active(self) -> SyntheticActiveSuiteTupleV1:
        require_synthetic_verifier_reference_enabled()
        self._validate_integrity()
        return self._active

    @property
    def commitment_sha3_512(self) -> bytes:
        require_synthetic_verifier_reference_enabled()
        self._validate_integrity()
        return self._commitment

    def validate_statement(
        self,
        encoded_sidecar: bytes,
        public_outputs: Sequence[bytes],
    ) -> tuple[tuple[bytes, ...], CandidateSidecarV1]:
        require_synthetic_verifier_reference_enabled()
        self._validate_integrity()
        canonical = canonical_public_outputs_v2(public_outputs)
        sidecar = validate_active_binding(
            _exact_bytes(
                "synthetic_verifier_sidecar",
                encoded_sidecar,
                length=SIDECAR_LENGTH,
            ),
            canonical,
            self._active.candidate_identity(),
        )
        return canonical, sidecar


def reference_candidate_strong_batch_commitment(
    sidecar_prefix: bytes,
    public_outputs: Sequence[bytes],
    *,
    canonical_private_batch_commitment: bytes,
    hidden_strong_value_commitment: bytes,
    raw_master_salt: bytes,
) -> bytes:
    """Hash the frozen candidate inventory under an explicit REFERENCE/v0 domain."""

    require_synthetic_verifier_reference_enabled()
    prefix = _exact_bytes(
        "reference_candidate_sidecar_prefix",
        sidecar_prefix,
        length=SIDECAR_PREFIX_BYTES,
    )
    public = canonical_public_outputs_v2(public_outputs)
    private_batch = _exact_bytes(
        "reference_candidate_private_batch_commitment",
        canonical_private_batch_commitment,
        length=WIDE_BYTES,
        nonzero=True,
    )
    strong_value = _exact_bytes(
        "reference_candidate_hidden_strong_value_commitment",
        hidden_strong_value_commitment,
        length=WIDE_BYTES,
        nonzero=True,
    )
    salt = _exact_bytes(
        "reference_candidate_raw_master_salt",
        raw_master_salt,
        length=WIDE_BYTES,
        nonzero=True,
    )
    hasher = sha3_512()
    for component in (
        _STRONG_BATCH_DOMAIN,
        prefix,
        *public,
        private_batch,
        strong_value,
        salt,
    ):
        hasher.update(component)
    return hasher.digest()


def sidecar_with_reference_candidate_strong_batch(
    sidecar: CandidateSidecarV1,
    public_outputs: Sequence[bytes],
    *,
    canonical_private_batch_commitment: bytes,
    hidden_strong_value_commitment: bytes,
    raw_master_salt: bytes,
) -> CandidateSidecarV1:
    require_synthetic_verifier_reference_enabled()
    if type(sidecar) is not CandidateSidecarV1:
        raise TypeError("reference_candidate_sidecar_required")
    prefix = sidecar.encode()[:SIDECAR_PREFIX_BYTES]
    commitment = reference_candidate_strong_batch_commitment(
        prefix,
        public_outputs,
        canonical_private_batch_commitment=canonical_private_batch_commitment,
        hidden_strong_value_commitment=hidden_strong_value_commitment,
        raw_master_salt=raw_master_salt,
    )
    return replace(sidecar, strong_batch_commitment=commitment)


def validate_reference_candidate_strong_batch(
    sidecar: CandidateSidecarV1,
    public_outputs: Sequence[bytes],
    *,
    canonical_private_batch_commitment: bytes,
    hidden_strong_value_commitment: bytes,
    raw_master_salt: bytes,
) -> None:
    require_synthetic_verifier_reference_enabled()
    if type(sidecar) is not CandidateSidecarV1:
        raise TypeError("reference_candidate_sidecar_required")
    expected = reference_candidate_strong_batch_commitment(
        sidecar.encode()[:SIDECAR_PREFIX_BYTES],
        public_outputs,
        canonical_private_batch_commitment=canonical_private_batch_commitment,
        hidden_strong_value_commitment=hidden_strong_value_commitment,
        raw_master_salt=raw_master_salt,
    )
    if not hmac.compare_digest(sidecar.strong_batch_commitment, expected):
        raise ValueError("reference_candidate_strong_batch_commitment_mismatch")


@dataclass(frozen=True, slots=True)
class SyntheticStrongVerificationRequestV1:
    public_outputs: tuple[bytes, ...]
    encoded_sidecar: bytes
    proof_body: bytes = field(repr=False)
    reference_status: str = REFERENCE_STATUS

    @classmethod
    def create(
        cls,
        *,
        public_outputs: Sequence[bytes],
        encoded_sidecar: bytes,
        proof_body: bytes,
    ) -> "SyntheticStrongVerificationRequestV1":
        require_synthetic_verifier_reference_enabled()
        return cls(
            canonical_public_outputs_v2(public_outputs),
            _exact_bytes(
                "synthetic_verifier_sidecar",
                encoded_sidecar,
                length=SIDECAR_LENGTH,
            ),
            proof_body,
        )

    def __post_init__(self) -> None:
        require_synthetic_verifier_reference_enabled()
        if self.reference_status != REFERENCE_STATUS:
            raise ValueError("synthetic_verification_request_reference_status_invalid")
        if type(self.public_outputs) is not tuple:
            raise TypeError("synthetic_verifier_public_outputs_must_be_tuple")
        if canonical_public_outputs_v2(self.public_outputs) != self.public_outputs:
            raise ValueError("synthetic_verifier_public_outputs_noncanonical")
        _exact_bytes(
            "synthetic_verifier_sidecar",
            self.encoded_sidecar,
            length=SIDECAR_LENGTH,
        )
        if type(self.proof_body) is not bytes or not self.proof_body:
            raise ValueError("synthetic_verifier_proof_body_must_be_nonempty_exact_bytes")
        if len(self.proof_body) > MAX_SYNTHETIC_PROOF_BODY_BYTES:
            raise ValueError("synthetic_verifier_proof_body_exceeds_reference_limit")


@dataclass(frozen=True, slots=True)
class SyntheticVerifiedStrongOutputsV1:
    public_outputs: tuple[bytes, ...]
    sidecar: CandidateSidecarV1
    proof_digest_sha3_512: bytes
    active_registry_commitment_sha3_512: bytes
    verification_kind: str
    authority_tag_sha3_512: bytes = field(repr=False)
    reference_status: str = REFERENCE_STATUS

    def __post_init__(self) -> None:
        require_synthetic_verifier_reference_enabled()
        if self.reference_status != REFERENCE_STATUS:
            raise ValueError("synthetic_verified_outputs_reference_status_invalid")
        if type(self.public_outputs) is not tuple:
            raise TypeError("synthetic_verified_outputs_public_outputs_must_be_tuple")
        if canonical_public_outputs_v2(self.public_outputs) != self.public_outputs:
            raise ValueError("synthetic_verified_outputs_public_outputs_noncanonical")
        if type(self.sidecar) is not CandidateSidecarV1:
            raise TypeError("synthetic_verified_outputs_sidecar_type_invalid")
        if len(self.sidecar.encode()) != SIDECAR_LENGTH:
            raise ValueError("synthetic_verified_outputs_sidecar_length_invalid")
        _exact_bytes(
            "synthetic_verified_outputs_proof_digest",
            self.proof_digest_sha3_512,
            length=WIDE_BYTES,
        )
        _exact_bytes(
            "synthetic_verified_outputs_registry_commitment",
            self.active_registry_commitment_sha3_512,
            length=WIDE_BYTES,
            nonzero=True,
        )
        if self.verification_kind != VERIFICATION_KIND:
            raise ValueError("synthetic_verified_outputs_kind_invalid")
        _exact_bytes(
            "synthetic_verified_outputs_authority_tag",
            self.authority_tag_sha3_512,
            length=WIDE_BYTES,
        )


def _statement_bytes(public_outputs: Sequence[bytes], encoded_sidecar: bytes) -> bytes:
    public = canonical_public_outputs_v2(public_outputs)
    sidecar = _exact_bytes(
        "synthetic_verifier_sidecar",
        encoded_sidecar,
        length=SIDECAR_LENGTH,
    )
    return _STATEMENT_DOMAIN + b"".join(public) + sidecar


def _verified_outputs_payload(receipt: SyntheticVerifiedStrongOutputsV1) -> bytes:
    return b"".join(
        (
            _RECEIPT_DOMAIN,
            b"".join(receipt.public_outputs),
            receipt.sidecar.encode(),
            receipt.proof_digest_sha3_512,
            receipt.active_registry_commitment_sha3_512,
            VERIFICATION_KIND.encode("ascii"),
            REFERENCE_STATUS.encode("ascii"),
        )
    )


class SyntheticStrongVerifierAuthorityV1:
    """Local capability issuer with no production registration or activation path."""

    def __init__(
        self,
        registry: SyntheticActiveRegistryV1,
        *,
        verifier_artifact_bytes: bytes,
    ) -> None:
        require_synthetic_verifier_reference_enabled()
        if type(registry) is not SyntheticActiveRegistryV1:
            raise TypeError("synthetic_verifier_active_registry_required")
        artifact = verifier_artifact_bytes
        if type(artifact) is not bytes or not artifact:
            raise ValueError("synthetic_verifier_artifact_must_be_nonempty_exact_bytes")
        if sha3_512(artifact).digest() != registry.active.verifier_artifact_identity:
            raise ValueError("synthetic_verifier_artifact_identity_mismatch")
        self._registry = registry
        self._pinned_active_tuple = registry.active.encode()
        self._pinned_registry_commitment = registry.commitment_sha3_512
        self._proof_key = secrets.token_bytes(WIDE_BYTES)
        self._authority_key = secrets.token_bytes(WIDE_BYTES)
        self._issued_salt_use_tags: dict[bytes, bytes] = {}
        self._issuance_lock = threading.Lock()

    def _validate_registry_pin(self) -> None:
        if (
            self._registry.active.encode() != self._pinned_active_tuple
            or not hmac.compare_digest(
                self._registry.commitment_sha3_512,
                self._pinned_registry_commitment,
            )
        ):
            raise ValueError("synthetic_verifier_registry_drift")

    @property
    def registry(self) -> SyntheticActiveRegistryV1:
        require_synthetic_verifier_reference_enabled()
        self._validate_registry_pin()
        return self._registry

    def build_synthetic_proof(
        self,
        *,
        public_outputs: Sequence[bytes],
        encoded_sidecar: bytes,
        canonical_private_batch_commitment: bytes,
        hidden_strong_value_commitment: bytes,
        raw_master_salt: bytes,
    ) -> bytes:
        """Issue a test capability only after the candidate master binding recomputes."""

        require_synthetic_verifier_reference_enabled()
        self._validate_registry_pin()
        canonical, sidecar = self._registry.validate_statement(encoded_sidecar, public_outputs)
        validate_reference_candidate_strong_batch(
            sidecar,
            canonical,
            canonical_private_batch_commitment=canonical_private_batch_commitment,
            hidden_strong_value_commitment=hidden_strong_value_commitment,
            raw_master_salt=raw_master_salt,
        )
        proof_tag = hmac.new(
            self._proof_key,
            _statement_bytes(canonical, sidecar.encode()),
            sha3_512,
        ).digest()
        proof_body = _SYNTHETIC_PROOF_MAGIC + proof_tag
        proof_digest = sha3_512(proof_body).digest()
        salt_use_tag = candidate_salt_use_tag(
            _exact_bytes(
                "synthetic_verifier_raw_master_salt",
                raw_master_salt,
                length=WIDE_BYTES,
                nonzero=True,
            )
        )
        with self._issuance_lock:
            existing = self._issued_salt_use_tags.get(proof_digest)
            if existing is not None and not hmac.compare_digest(existing, salt_use_tag):
                raise ValueError("synthetic_proof_salt_tag_rebinding_forbidden")
            if existing is None and len(self._issued_salt_use_tags) >= MAX_SYNTHETIC_ISSUED_PROOFS:
                raise RuntimeError("synthetic_proof_issuance_capacity_exhausted")
            self._issued_salt_use_tags[proof_digest] = salt_use_tag
        return proof_body

    def verify(
        self,
        request: SyntheticStrongVerificationRequestV1,
    ) -> SyntheticVerifiedStrongOutputsV1:
        require_synthetic_verifier_reference_enabled()
        self._validate_registry_pin()
        if type(request) is not SyntheticStrongVerificationRequestV1:
            raise TypeError("synthetic_strong_verification_request_required")
        request.__post_init__()
        canonical, sidecar = self._registry.validate_statement(
            request.encoded_sidecar,
            request.public_outputs,
        )
        expected = _SYNTHETIC_PROOF_MAGIC + hmac.new(
            self._proof_key,
            _statement_bytes(canonical, sidecar.encode()),
            sha3_512,
        ).digest()
        if not hmac.compare_digest(request.proof_body, expected):
            raise ValueError("synthetic_strong_proof_invalid")
        proof_digest = sha3_512(request.proof_body).digest()
        with self._issuance_lock:
            salt_use_tag = self._issued_salt_use_tags.get(proof_digest)
        if salt_use_tag is None:
            raise ValueError("synthetic_strong_proof_was_not_locally_issued")
        provisional = SyntheticVerifiedStrongOutputsV1(
            public_outputs=canonical,
            sidecar=sidecar,
            proof_digest_sha3_512=proof_digest,
            active_registry_commitment_sha3_512=self._registry.commitment_sha3_512,
            verification_kind=VERIFICATION_KIND,
            authority_tag_sha3_512=bytes(WIDE_BYTES),
        )
        tag = hmac.new(
            self._authority_key,
            _verified_outputs_payload(provisional),
            sha3_512,
        ).digest()
        return replace(provisional, authority_tag_sha3_512=tag)

    def validate_verified_outputs(
        self,
        receipt: SyntheticVerifiedStrongOutputsV1,
        *,
        expected_salt_use_tag_512: bytes,
    ) -> tuple[tuple[bytes, ...], CandidateSidecarV1]:
        require_synthetic_verifier_reference_enabled()
        self._validate_registry_pin()
        if type(receipt) is not SyntheticVerifiedStrongOutputsV1:
            raise TypeError("synthetic_verified_strong_outputs_required")
        receipt.__post_init__()
        if receipt.active_registry_commitment_sha3_512 != self._registry.commitment_sha3_512:
            raise ValueError("synthetic_verified_outputs_registry_mismatch")
        canonical, sidecar = self._registry.validate_statement(
            receipt.sidecar.encode(),
            receipt.public_outputs,
        )
        if canonical != receipt.public_outputs or sidecar != receipt.sidecar:
            raise ValueError("synthetic_verified_outputs_statement_mismatch")
        expected_tag = hmac.new(
            self._authority_key,
            _verified_outputs_payload(receipt),
            sha3_512,
        ).digest()
        if not hmac.compare_digest(receipt.authority_tag_sha3_512, expected_tag):
            raise ValueError("synthetic_verified_outputs_authority_mismatch")
        expected_salt_use_tag = _exact_bytes(
            "synthetic_verified_outputs_expected_salt_use_tag",
            expected_salt_use_tag_512,
            length=WIDE_BYTES,
            nonzero=True,
        )
        with self._issuance_lock:
            issued_salt_use_tag = self._issued_salt_use_tags.get(
                receipt.proof_digest_sha3_512
            )
        if issued_salt_use_tag is None:
            raise ValueError("synthetic_verified_outputs_proof_was_not_locally_issued")
        if not hmac.compare_digest(issued_salt_use_tag, expected_salt_use_tag):
            raise ValueError("synthetic_verified_outputs_salt_use_tag_mismatch")
        return canonical, sidecar
