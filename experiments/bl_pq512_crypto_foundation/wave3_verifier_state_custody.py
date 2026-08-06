"""Wave 3 verifier, state, custody, and migration boundary.

This module is the internal, nonactivating P04-P12 continuation of the P01-P03
nullifier boundary. It keeps the authoritative wide roots and raw A12
preimages in a private state file, binds governed roots to two independent PQ
signatures, uses the frozen 744-byte sidecar, and exposes a fail-closed typed
verifier port with atomic proof/state binding.

The ML-KEM/AES envelope is a real software/reference implementation.  The
signature and KEM ports deliberately expose their software/HSM qualification
state: a software adapter cannot become an active production custody path by
being renamed.  The repository still has no selected proof suite, so the
verifier rejects every proof while ``proofSuiteId`` is unset and activation is
false.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from hashlib import sha3_512
import hmac
from importlib.metadata import version
import os
from pathlib import Path
import secrets
from threading import RLock
from typing import Final, Iterable, Mapping, Protocol, Sequence

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pqcrypto.kem import ml_kem_1024

from app.batch.poseidon import FIELD_MODULUS
from app.batch.pq_suite_candidate import (
    ActiveSuiteIdentityV1,
    CandidateSidecarV1,
    candidate_salt_use_tag,
)
from experiments.bl_pq512_crypto_foundation.master_commitments_v2 import (
    MasterCommitmentInputsV2,
    MasterCommitmentsV2,
    build_master_commitments_v2,
)
from experiments.bl_pq512_crypto_foundation.pq_signature_adapters import (
    LOCKED_PQCRYPTO_VERSION,
    ML_DSA_87_SUITE_ID,
    SPHINCS_SHAKE_256F_SIMPLE_SUITE_ID,
    expected_public_key_size,
)
from experiments.bl_pq512_crypto_foundation.wave3_nullifier_authority import (
    TREE_DEPTH,
    WIDE_BYTES,
    Wave3NullifierAuthorityV1,
    Wave3NullifierError,
    Wave3StateSnapshotV1,
    Wave3StateTransitionV1,
    independently_verify_wave3_transition,
)


MODULE_STATUS: Final[str] = "WAVE3_VERIFIER_STATE_CUSTODY_INTERNAL_NONACTIVATING"
ACTIVATION_ALLOWED: Final[bool] = False
PROOF_SUITE_ID: None = None

UINT64_MAX: Final[int] = (1 << 64) - 1
IDENTITY_BYTES: Final[int] = 64
PUBLIC_FIELD_BYTES: Final[int] = 32
MAX_ROOT_KIND_BYTES: Final[int] = 64
MAX_RAW_PREIMAGE_BYTES: Final[int] = 16_384
MAX_STATE_RECORDS: Final[int] = 512
MAX_HISTORY: Final[int] = 16
MAX_STATE_FILE_BYTES: Final[int] = 64 * 1024 * 1024
MAX_MANIFEST_RECORDS: Final[int] = 4_096
MAX_MANIFEST_RECORD_BYTES: Final[int] = 16_384

STATE_MAGIC: Final[bytes] = b"BLW3ST01"
STATE_VERSION: Final[int] = 2
STATE_HEADER_BYTES: Final[int] = 20
STATE_PAYLOAD_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE3/STATE-PAYLOAD/v2\x00"
STATE_FILE_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE3/STATE-FILE/v1\x00"
ROOT_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE3/GOVERNED-ROOT/v1\x00"
MANIFEST_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE3/GOVERNED-MANIFEST/v1\x00"
REGISTRY_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE3/GOVERNED-REGISTRY/v1\x00"
AUTHORITY_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE3/DUAL-PQ-AUTHORITY/v1\x00"
ROTATION_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE3/AUTHORITY-ROTATION/v1\x00"
COMMITMENT_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE3/COMMITMENTS/v1\x00"
VERIFIER_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE3/VERIFIER/v1\x00"
ATOMIC_BINDING_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE3/ATOMIC-BINDING/v1\x00"
MIGRATION_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE3/MIGRATION/v1\x00"
ROLLBACK_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE3/ROLLBACK/v1\x00"
RECOVERY_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE3/RECOVERY/v1\x00"
ACTIVATION_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE3/ACTIVATION/v1\x00"
UPGRADE_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE3/UPGRADE/v1\x00"

KEM_MAGIC: Final[bytes] = b"BLW3KE01"
KEM_VERSION: Final[int] = 1
KEM_NONCE_BYTES: Final[int] = 12
KEM_KEY_ID_BYTES: Final[int] = 64
KEM_MAX_PLAINTEXT_BYTES: Final[int] = 1_048_576
KEM_CIPHERTEXT_BYTES: Final[int] = ml_kem_1024.CIPHERTEXT_SIZE
KEM_PUBLIC_KEY_BYTES: Final[int] = ml_kem_1024.PUBLIC_KEY_SIZE
KEM_SECRET_KEY_BYTES: Final[int] = ml_kem_1024.SECRET_KEY_SIZE
KEM_SHARED_SECRET_BYTES: Final[int] = ml_kem_1024.PLAINTEXT_SIZE

SIGNATURE_SIZES: Final[dict[str, int]] = {
    ML_DSA_87_SUITE_ID: 4_627,
    SPHINCS_SHAKE_256F_SIMPLE_SUITE_ID: 49_856,
}
DUAL_PQ_SUITES: Final[tuple[str, str]] = (
    ML_DSA_87_SUITE_ID,
    SPHINCS_SHAKE_256F_SIMPLE_SUITE_ID,
)
ZERO_ID_512: Final[bytes] = b"\x00" * IDENTITY_BYTES


class Wave3BoundaryError(ValueError):
    """Fail-closed error for the Wave 3 boundary."""


def _bytes(label: str, value: object, length: int, *, nonzero: bool = False) -> bytes:
    if type(value) is not bytes or len(value) != length:
        raise Wave3BoundaryError(f"wave3_{label}_must_be_{length}_bytes")
    if nonzero and not any(value):
        raise Wave3BoundaryError(f"wave3_{label}_must_be_nonzero")
    return value


def _u64(label: str, value: object, *, nonzero: bool = False) -> int:
    if type(value) is not int or not 0 <= value <= UINT64_MAX:
        raise Wave3BoundaryError(f"wave3_{label}_out_of_range")
    if nonzero and value == 0:
        raise Wave3BoundaryError(f"wave3_{label}_must_be_nonzero")
    return value


def _ascii(label: str, value: object, maximum: int = MAX_ROOT_KIND_BYTES) -> bytes:
    if type(value) is not str:
        raise Wave3BoundaryError(f"wave3_{label}_must_be_text")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise Wave3BoundaryError(f"wave3_{label}_must_be_ascii") from exc
    if not encoded or len(encoded) > maximum or b"\x00" in encoded:
        raise Wave3BoundaryError(f"wave3_{label}_length_invalid")
    return encoded


def _frame(domain: bytes, *parts: bytes) -> bytes:
    if type(domain) is not bytes or not domain or len(domain) > 0xFFFF:
        raise Wave3BoundaryError("wave3_domain_invalid")
    encoded = bytearray(domain)
    for part in parts:
        if type(part) is not bytes or len(part) > 0xFFFFFFFF:
            raise Wave3BoundaryError("wave3_frame_part_invalid")
        encoded.extend(len(part).to_bytes(4, "big"))
        encoded.extend(part)
    return bytes(encoded)


def _digest(domain: bytes, *parts: bytes) -> bytes:
    return sha3_512(_frame(domain, *parts)).digest()


def _alias_for_root(root_512: bytes) -> bytes:
    root = _bytes("root_for_alias", root_512, WIDE_BYTES, nonzero=True)
    alias = int.from_bytes(root, "big") % (FIELD_MODULUS - 1) + 1
    return alias.to_bytes(PUBLIC_FIELD_BYTES, "big")


def _identity_tuple(values: Sequence[bytes], label: str) -> tuple[bytes, ...]:
    if type(values) not in (tuple, list):
        raise Wave3BoundaryError(f"wave3_{label}_must_be_sequence")
    return tuple(
        _bytes(f"{label}_{index}", value, IDENTITY_BYTES, nonzero=True)
        for index, value in enumerate(values)
    )


class PqSignaturePort(Protocol):
    """Provider-neutral verification/signing surface for PQ custody."""

    suite_id: str
    key_id: bytes
    public_key: bytes
    hsm_backed: bool
    fips_validated: bool

    def sign(self, *, message: bytes) -> bytes: ...

    def verify(self, *, public_key: bytes, message: bytes, signature: bytes) -> bool: ...


class PqHsmPort(PqSignaturePort, Protocol):
    """Provider-neutral HSM/KMS port used by the eventual activation path."""

    provider_id: str
    key_handle: str
    attestation: bytes


class PqKemPort(Protocol):
    """Provider-neutral KEM custody surface; no RSA fallback is permitted."""

    kem_id: str
    version: int
    software_only: bool
    hsm_backed: bool
    production_usable: bool

    def seal(
        self,
        *,
        key_id: bytes,
        public_key: bytes,
        plaintext: bytes,
        associated_data: bytes,
    ) -> bytes: ...

    def open(
        self,
        *,
        secret_key: bytes,
        envelope: bytes,
        associated_data: bytes,
        expected_key_id: bytes,
    ) -> bytes: ...


@dataclass(frozen=True, slots=True)
class PqProviderConformanceV1:
    suite_id: str
    key_id: bytes
    provider_id: str
    hsm_backed: bool
    fips_validated: bool
    production_usable: bool
    failure_code: str | None = None

    def __post_init__(self) -> None:
        if self.suite_id not in DUAL_PQ_SUITES:
            raise Wave3BoundaryError("wave3_conformance_suite_not_approved")
        _bytes("conformance_key_id", self.key_id, IDENTITY_BYTES, nonzero=True)
        _ascii("conformance_provider_id", self.provider_id, 128)
        if type(self.hsm_backed) is not bool or type(self.fips_validated) is not bool:
            raise Wave3BoundaryError("wave3_conformance_flags_invalid")
        if type(self.production_usable) is not bool:
            raise Wave3BoundaryError("wave3_conformance_production_flag_invalid")
        if self.production_usable != (self.hsm_backed and self.fips_validated and self.failure_code is None):
            raise Wave3BoundaryError("wave3_conformance_production_derivation_invalid")


def assess_pq_provider_port(
    port: PqSignaturePort,
    *,
    expected_suite_id: str,
    expected_key_id: bytes,
) -> PqProviderConformanceV1:
    """Check the provider-neutral contract without treating software as HSM custody."""

    expected_key = _bytes("conformance_expected_key_id", expected_key_id, IDENTITY_BYTES, nonzero=True)
    suite_id = getattr(port, "suite_id", None)
    key_id = getattr(port, "key_id", None)
    hsm_backed = getattr(port, "hsm_backed", False) is True
    fips_validated = getattr(port, "fips_validated", False) is True
    provider_id = getattr(port, "provider_id", "software-reference")
    failure: str | None = None
    if suite_id != expected_suite_id or expected_suite_id not in DUAL_PQ_SUITES:
        failure = "suite_mismatch"
    elif key_id != expected_key:
        failure = "key_id_mismatch"
    elif not callable(getattr(port, "sign", None)) or not callable(getattr(port, "verify", None)):
        failure = "sign_verify_port_missing"
    elif not hsm_backed:
        failure = "hsm_backing_missing"
    elif not fips_validated:
        failure = "fips_validation_missing"
    return PqProviderConformanceV1(
        expected_suite_id,
        expected_key,
        provider_id if type(provider_id) is str else "invalid-provider",
        hsm_backed,
        fips_validated,
        failure is None,
        failure,
    )


@dataclass(frozen=True, slots=True)
class PqAuthorityKeyV1:
    suite_id: str
    key_id: bytes
    public_key: bytes

    def __post_init__(self) -> None:
        if self.suite_id not in DUAL_PQ_SUITES:
            raise Wave3BoundaryError("wave3_authority_suite_not_approved")
        _bytes("authority_key_id", self.key_id, IDENTITY_BYTES, nonzero=True)
        expected = expected_public_key_size(self.suite_id)
        _bytes("authority_public_key", self.public_key, expected, nonzero=True)

    def canonical_bytes(self) -> bytes:
        suite = _ascii("authority_suite", self.suite_id, 128)
        return b"".join(
            (
                len(suite).to_bytes(2, "big"),
                suite,
                self.key_id,
                len(self.public_key).to_bytes(4, "big"),
                self.public_key,
            )
        )


@dataclass(frozen=True, slots=True)
class PqSignatureEnvelopeV1:
    suite_id: str
    key_id: bytes
    signature: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if self.suite_id not in DUAL_PQ_SUITES:
            raise Wave3BoundaryError("wave3_signature_suite_not_approved")
        _bytes("signature_key_id", self.key_id, IDENTITY_BYTES, nonzero=True)
        _bytes(
            "signature",
            self.signature,
            SIGNATURE_SIZES[self.suite_id],
            nonzero=True,
        )

    def canonical_bytes(self) -> bytes:
        suite = _ascii("signature_suite", self.suite_id, 128)
        return b"".join(
            (
                len(suite).to_bytes(2, "big"),
                suite,
                self.key_id,
                self.signature,
            )
        )


class DualPqAuthorityV1:
    """Verify exactly one ML-DSA and one SLH-DSA authority signature."""

    def __init__(
        self,
        *,
        authority_id_512: bytes,
        keys: Sequence[PqAuthorityKeyV1],
        verifiers: Mapping[str, PqSignaturePort],
    ) -> None:
        self.authority_id_512 = _bytes(
            "authority_id", authority_id_512, IDENTITY_BYTES, nonzero=True
        )
        if type(keys) not in (tuple, list) or len(keys) != 2:
            raise Wave3BoundaryError("wave3_authority_requires_two_keys")
        checked_keys = tuple(keys)
        if any(type(item) is not PqAuthorityKeyV1 for item in checked_keys):
            raise Wave3BoundaryError("wave3_authority_key_type_invalid")
        if tuple(item.suite_id for item in checked_keys) != DUAL_PQ_SUITES:
            raise Wave3BoundaryError("wave3_authority_requires_dual_pq_keys")
        if len({item.key_id for item in checked_keys}) != 2:
            raise Wave3BoundaryError("wave3_authority_key_id_duplicate")
        if type(verifiers) is not dict or set(verifiers) != set(DUAL_PQ_SUITES):
            raise Wave3BoundaryError("wave3_authority_verifier_set_invalid")
        for suite_id, verifier in verifiers.items():
            if getattr(verifier, "suite_id", None) != suite_id or not callable(
                getattr(verifier, "verify", None)
            ):
                raise Wave3BoundaryError("wave3_authority_verifier_port_invalid")
        self.keys = checked_keys
        self.verifiers = dict(verifiers)
        self.hsm_backed = all(
            getattr(verifiers[suite_id], "hsm_backed", False)
            is True
            for suite_id in DUAL_PQ_SUITES
        )
        self.fips_validated = all(
            getattr(verifiers[suite_id], "fips_validated", False)
            is True
            for suite_id in DUAL_PQ_SUITES
        )
        self.authority_commitment_512 = _digest(
            AUTHORITY_DOMAIN,
            self.authority_id_512,
            *(item.canonical_bytes() for item in self.keys),
        )

    def authorization_message(self, unsigned_root: bytes) -> bytes:
        return _digest(AUTHORITY_DOMAIN, self.authority_commitment_512, unsigned_root)

    def verify(
        self,
        *,
        unsigned_root: bytes,
        signatures: Sequence[PqSignatureEnvelopeV1],
    ) -> bool:
        if type(signatures) not in (tuple, list) or len(signatures) != 2:
            raise Wave3BoundaryError("wave3_authority_signature_count_invalid")
        by_suite = {item.suite_id: item for item in signatures if type(item) is PqSignatureEnvelopeV1}
        if set(by_suite) != set(DUAL_PQ_SUITES):
            raise Wave3BoundaryError("wave3_authority_signature_suite_set_invalid")
        message = self.authorization_message(_bytes("unsigned_root", unsigned_root, 64, nonzero=True))
        key_by_suite = {item.suite_id: item for item in self.keys}
        for suite_id in DUAL_PQ_SUITES:
            signature = by_suite[suite_id]
            key = key_by_suite[suite_id]
            if signature.key_id != key.key_id:
                raise Wave3BoundaryError("wave3_authority_signature_key_mismatch")
            verifier = self.verifiers[suite_id]
            if not verifier.verify(
                public_key=key.public_key,
                message=message,
                signature=signature.signature,
            ):
                raise Wave3BoundaryError("wave3_authority_signature_invalid")
        return True

    def sign(self, *, unsigned_root: bytes) -> tuple[PqSignatureEnvelopeV1, ...]:
        message = self.authorization_message(
            _bytes("unsigned_root", unsigned_root, 64, nonzero=True)
        )
        envelopes = []
        for suite_id in DUAL_PQ_SUITES:
            signer = getattr(self.verifiers[suite_id], "sign", None)
            if not callable(signer):
                raise Wave3BoundaryError("wave3_authority_signer_unavailable")
            try:
                signature = signer(message=message)
            except Exception as exc:
                raise Wave3BoundaryError("wave3_authority_sign_failed_closed") from exc
            envelopes.append(PqSignatureEnvelopeV1(suite_id, next(
                key.key_id for key in self.keys if key.suite_id == suite_id
            ), signature))
        return tuple(envelopes)


@dataclass(frozen=True, slots=True)
class PqAuthorityRotationV1:
    """Dual-signed, monotonic authority rotation record."""

    old_authority_id_512: bytes
    new_authority_id_512: bytes
    old_commitment_512: bytes
    new_commitment_512: bytes
    old_epoch: int
    new_epoch: int
    old_signatures: tuple[PqSignatureEnvelopeV1, ...] = field(repr=False)
    new_signatures: tuple[PqSignatureEnvelopeV1, ...] = field(repr=False)
    rotation_digest_512: bytes = field(init=False)

    def __post_init__(self) -> None:
        old_id = _bytes("rotation_old_authority_id", self.old_authority_id_512, IDENTITY_BYTES, nonzero=True)
        new_id = _bytes("rotation_new_authority_id", self.new_authority_id_512, IDENTITY_BYTES, nonzero=True)
        if old_id == new_id:
            raise Wave3BoundaryError("wave3_authority_rotation_identity_unchanged")
        old_commitment = _bytes("rotation_old_commitment", self.old_commitment_512, IDENTITY_BYTES, nonzero=True)
        new_commitment = _bytes("rotation_new_commitment", self.new_commitment_512, IDENTITY_BYTES, nonzero=True)
        if old_commitment == new_commitment:
            raise Wave3BoundaryError("wave3_authority_rotation_commitment_unchanged")
        old_epoch = _u64("rotation_old_epoch", self.old_epoch, nonzero=True)
        new_epoch = _u64("rotation_new_epoch", self.new_epoch, nonzero=True)
        if new_epoch != old_epoch + 1:
            raise Wave3BoundaryError("wave3_authority_rotation_epoch_not_successor")
        for label, signatures in (("old", self.old_signatures), ("new", self.new_signatures)):
            if type(signatures) is not tuple or len(signatures) != 2:
                raise Wave3BoundaryError(f"wave3_authority_rotation_{label}_signature_count_invalid")
            if any(type(item) is not PqSignatureEnvelopeV1 for item in signatures):
                raise Wave3BoundaryError(f"wave3_authority_rotation_{label}_signature_type_invalid")
        object.__setattr__(self, "rotation_digest_512", _digest(
            ROTATION_DOMAIN,
            old_id,
            new_id,
            old_commitment,
            new_commitment,
            old_epoch.to_bytes(8, "big"),
            new_epoch.to_bytes(8, "big"),
        ))

    @classmethod
    def issue(
        cls,
        *,
        old_authority: DualPqAuthorityV1,
        new_authority: DualPqAuthorityV1,
        old_epoch: int,
        new_epoch: int,
    ) -> "PqAuthorityRotationV1":
        if type(old_authority) is not DualPqAuthorityV1 or type(new_authority) is not DualPqAuthorityV1:
            raise TypeError("wave3_rotation_authorities_required")
        unsigned = cls(
            old_authority.authority_id_512,
            new_authority.authority_id_512,
            old_authority.authority_commitment_512,
            new_authority.authority_commitment_512,
            old_epoch,
            new_epoch,
            tuple(PqSignatureEnvelopeV1(suite, old_authority.keys[index].key_id, b"\x01" * SIGNATURE_SIZES[suite]) for index, suite in enumerate(DUAL_PQ_SUITES)),
            tuple(PqSignatureEnvelopeV1(suite, new_authority.keys[index].key_id, b"\x01" * SIGNATURE_SIZES[suite]) for index, suite in enumerate(DUAL_PQ_SUITES)),
        )
        return replace(
            unsigned,
            old_signatures=old_authority.sign(unsigned_root=unsigned.rotation_digest_512),
            new_signatures=new_authority.sign(unsigned_root=unsigned.rotation_digest_512),
        )

    def verify(
        self,
        *,
        old_authority: DualPqAuthorityV1,
        new_authority: DualPqAuthorityV1,
    ) -> bool:
        if type(old_authority) is not DualPqAuthorityV1 or type(new_authority) is not DualPqAuthorityV1:
            raise TypeError("wave3_rotation_authorities_required")
        if self.old_authority_id_512 != old_authority.authority_id_512 or self.new_authority_id_512 != new_authority.authority_id_512:
            raise Wave3BoundaryError("wave3_authority_rotation_identity_mismatch")
        if self.old_commitment_512 != old_authority.authority_commitment_512 or self.new_commitment_512 != new_authority.authority_commitment_512:
            raise Wave3BoundaryError("wave3_authority_rotation_commitment_mismatch")
        old_authority.verify(unsigned_root=self.rotation_digest_512, signatures=self.old_signatures)
        new_authority.verify(unsigned_root=self.rotation_digest_512, signatures=self.new_signatures)
        return True


@dataclass(frozen=True, slots=True)
class GovernedRootManifestV1:
    """Canonical synthetic manifest from which one governed root is derived."""

    root_kind: str
    profile_id: bytes
    epoch: int
    schema_id: bytes
    records: tuple[bytes, ...]
    manifest_id_512: bytes = field(init=False)
    root_512: bytes = field(init=False, repr=False)
    compatibility_alias: bytes = field(init=False)

    def __post_init__(self) -> None:
        kind = _ascii("manifest_root_kind", self.root_kind)
        if kind.upper() != kind or any(char not in b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for char in kind):
            raise Wave3BoundaryError("wave3_manifest_root_kind_not_canonical")
        profile = _bytes("manifest_profile_id", self.profile_id, IDENTITY_BYTES, nonzero=True)
        epoch = _u64("manifest_epoch", self.epoch, nonzero=True)
        schema = _bytes("manifest_schema_id", self.schema_id, IDENTITY_BYTES, nonzero=True)
        if type(self.records) not in (tuple, list) or len(self.records) > MAX_MANIFEST_RECORDS:
            raise Wave3BoundaryError("wave3_manifest_record_count_invalid")
        records = tuple(self.records)
        for index, record in enumerate(records):
            if type(record) is not bytes or not record or len(record) > MAX_MANIFEST_RECORD_BYTES:
                raise Wave3BoundaryError(f"wave3_manifest_record_{index}_invalid")
        encoded = b"".join(
            (
                MANIFEST_DOMAIN,
                len(kind).to_bytes(2, "big"),
                kind,
                profile,
                epoch.to_bytes(8, "big"),
                schema,
                len(records).to_bytes(4, "big"),
                *(len(record).to_bytes(4, "big") + record for record in records),
            )
        )
        manifest_id = sha3_512(encoded).digest()
        root = _digest(
            ROOT_DOMAIN,
            manifest_id,
            kind,
            profile,
            epoch.to_bytes(8, "big"),
            schema,
        )
        object.__setattr__(self, "records", records)
        object.__setattr__(self, "manifest_id_512", manifest_id)
        object.__setattr__(self, "root_512", root)
        object.__setattr__(self, "compatibility_alias", _alias_for_root(root))

    def canonical_bytes(self) -> bytes:
        kind = _ascii("manifest_root_kind", self.root_kind)
        return b"".join(
            (
                MANIFEST_DOMAIN,
                len(kind).to_bytes(2, "big"),
                kind,
                self.profile_id,
                self.epoch.to_bytes(8, "big"),
                self.schema_id,
                len(self.records).to_bytes(4, "big"),
                *(len(record).to_bytes(4, "big") + record for record in self.records),
            )
        )


@dataclass(frozen=True, slots=True)
class GovernedRootRecordV1:
    root_kind: str
    profile_id: bytes
    epoch: int
    compatibility_alias: bytes
    root_512: bytes = field(repr=False)
    manifest_id: bytes
    schema_id: bytes
    authority_id_512: bytes
    signatures: tuple[PqSignatureEnvelopeV1, ...] = field(repr=False)

    def __post_init__(self) -> None:
        kind = _ascii("root_kind", self.root_kind)
        if kind.upper() != kind or not all(char in b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for char in kind):
            raise Wave3BoundaryError("wave3_root_kind_not_canonical")
        _bytes("root_profile_id", self.profile_id, IDENTITY_BYTES, nonzero=True)
        _u64("root_epoch", self.epoch, nonzero=True)
        _bytes("root_alias", self.compatibility_alias, PUBLIC_FIELD_BYTES, nonzero=True)
        root = _bytes("governed_root", self.root_512, WIDE_BYTES, nonzero=True)
        if self.compatibility_alias != _alias_for_root(root):
            raise Wave3BoundaryError("wave3_root_alias_mismatch")
        _bytes("root_manifest_id", self.manifest_id, IDENTITY_BYTES, nonzero=True)
        _bytes("root_schema_id", self.schema_id, IDENTITY_BYTES, nonzero=True)
        _bytes("root_authority_id", self.authority_id_512, IDENTITY_BYTES, nonzero=True)
        if type(self.signatures) is not tuple or len(self.signatures) != 2:
            raise Wave3BoundaryError("wave3_root_signature_count_invalid")
        if any(type(item) is not PqSignatureEnvelopeV1 for item in self.signatures):
            raise Wave3BoundaryError("wave3_root_signature_type_invalid")

    @classmethod
    def from_manifest(
        cls,
        manifest: GovernedRootManifestV1,
        *,
        authority: DualPqAuthorityV1,
    ) -> "GovernedRootRecordV1":
        if type(manifest) is not GovernedRootManifestV1 or type(authority) is not DualPqAuthorityV1:
            raise TypeError("wave3_manifest_and_authority_required")
        unsigned = cls(
            root_kind=manifest.root_kind,
            profile_id=manifest.profile_id,
            epoch=manifest.epoch,
            compatibility_alias=manifest.compatibility_alias,
            root_512=manifest.root_512,
            manifest_id=manifest.manifest_id_512,
            schema_id=manifest.schema_id,
            authority_id_512=authority.authority_id_512,
            signatures=tuple(
                PqSignatureEnvelopeV1(
                    suite_id,
                    authority.keys[index].key_id,
                    b"\x01" * SIGNATURE_SIZES[suite_id],
                )
                for index, suite_id in enumerate(DUAL_PQ_SUITES)
            ),
        )
        return replace(unsigned, signatures=authority.sign(unsigned_root=unsigned.root_id_512))

    def unsigned_bytes(self) -> bytes:
        kind = _ascii("root_kind", self.root_kind)
        return b"".join(
            (
                ROOT_DOMAIN,
                len(kind).to_bytes(2, "big"),
                kind,
                self.profile_id,
                self.epoch.to_bytes(8, "big"),
                self.compatibility_alias,
                self.root_512,
                self.manifest_id,
                self.schema_id,
                self.authority_id_512,
            )
        )

    @property
    def root_id_512(self) -> bytes:
        return sha3_512(self.unsigned_bytes()).digest()

    def canonical_bytes(self) -> bytes:
        return self.unsigned_bytes() + b"".join(item.canonical_bytes() for item in self.signatures)


class GovernedRootRegistryV1:
    """Append-only governed root registry with no overwrite or downgrade path."""

    def __init__(self, *, authority: DualPqAuthorityV1) -> None:
        if type(authority) is not DualPqAuthorityV1:
            raise TypeError("wave3_governed_root_authority_required")
        self.authority = authority
        self._lock = RLock()
        self._records: dict[tuple[str, int], GovernedRootRecordV1] = {}

    @property
    def records(self) -> tuple[GovernedRootRecordV1, ...]:
        with self._lock:
            return tuple(self._records[key] for key in sorted(self._records))

    @property
    def commitment_sha3_512(self) -> bytes:
        return _digest(
            REGISTRY_DOMAIN,
            self.authority.authority_commitment_512,
            len(self.records).to_bytes(4, "big"),
            *(item.canonical_bytes() for item in self.records),
        )

    def register(self, record: GovernedRootRecordV1) -> bytes:
        if type(record) is not GovernedRootRecordV1:
            raise TypeError("wave3_governed_root_record_required")
        if record.authority_id_512 != self.authority.authority_id_512:
            raise Wave3BoundaryError("wave3_root_authority_id_mismatch")
        self.authority.verify(
            unsigned_root=record.root_id_512,
            signatures=record.signatures,
        )
        key = (record.root_kind, record.epoch)
        with self._lock:
            if key in self._records:
                raise Wave3BoundaryError("wave3_governed_root_overwrite_rejected")
            prior_epochs = [epoch for kind, epoch in self._records if kind == record.root_kind]
            if prior_epochs and record.epoch <= max(prior_epochs):
                raise Wave3BoundaryError("wave3_governed_root_epoch_downgrade_rejected")
            self._records[key] = record
            return record.root_id_512

    def register_manifest(
        self,
        manifest: GovernedRootManifestV1,
        *,
        record: GovernedRootRecordV1 | None = None,
    ) -> bytes:
        if type(manifest) is not GovernedRootManifestV1:
            raise TypeError("wave3_governed_root_manifest_required")
        observed = record if record is not None else GovernedRootRecordV1.from_manifest(
            manifest,
            authority=self.authority,
        )
        if type(observed) is not GovernedRootRecordV1:
            raise TypeError("wave3_governed_root_record_required")
        if (
            observed.root_kind != manifest.root_kind
            or observed.profile_id != manifest.profile_id
            or observed.epoch != manifest.epoch
            or observed.compatibility_alias != manifest.compatibility_alias
            or observed.root_512 != manifest.root_512
            or observed.manifest_id != manifest.manifest_id_512
            or observed.schema_id != manifest.schema_id
        ):
            raise Wave3BoundaryError("wave3_governed_root_manifest_mismatch")
        return self.register(observed)

    def resolve(self, *, root_kind: str, epoch: int) -> GovernedRootRecordV1:
        _ascii("resolve_root_kind", root_kind)
        _u64("resolve_root_epoch", epoch, nonzero=True)
        with self._lock:
            try:
                return self._records[(root_kind, epoch)]
            except KeyError as exc:
                raise Wave3BoundaryError("wave3_governed_root_not_registered") from exc


@dataclass(frozen=True, slots=True)
class Wave3CommitmentBundleV1:
    master_salt_use_tag_512: bytes
    commitments: MasterCommitmentsV2
    bundle_digest_512: bytes = field(init=False)

    def __post_init__(self) -> None:
        salt_tag = _bytes("commitment_salt_use_tag", self.master_salt_use_tag_512, 64, nonzero=True)
        if type(self.commitments) is not MasterCommitmentsV2:
            raise TypeError("wave3_commitments_required")
        for label, value in (
            ("governance", self.commitments.governance_512),
            ("batch", self.commitments.batch_512),
            ("value", self.commitments.value_conservation_512),
            ("settlement", self.commitments.settlement_512),
        ):
            _bytes(f"commitment_{label}", value, 64, nonzero=True)
        object.__setattr__(
            self,
            "bundle_digest_512",
            sha3_512(self.canonical_bytes()).digest(),
        )

    def canonical_bytes(self) -> bytes:
        return b"".join(
            (
                COMMITMENT_DOMAIN,
                self.master_salt_use_tag_512,
                self.commitments.governance_512,
                self.commitments.batch_512,
                self.commitments.value_conservation_512,
                self.commitments.settlement_512,
            )
        )


def build_wave3_commitments(
    inputs: MasterCommitmentInputsV2,
    *,
    master_salt_512: bytes,
) -> Wave3CommitmentBundleV1:
    if type(inputs) is not MasterCommitmentInputsV2:
        raise TypeError("wave3_master_commitment_inputs_required")
    salt = _bytes("master_salt", master_salt_512, 64, nonzero=True)
    expected_tag = candidate_salt_use_tag(salt)
    if inputs.salt_use_tag_512 != expected_tag:
        raise Wave3BoundaryError("wave3_master_salt_use_tag_mismatch")
    return Wave3CommitmentBundleV1(expected_tag, build_master_commitments_v2(inputs))


def build_wave3_sidecar(
    *,
    profile_id: bytes,
    proof_suite_id: bytes,
    schema_id: bytes,
    verifier_artifact_identity: bytes,
    strong_settlement_domain_id: bytes,
    epoch: int,
    sequence_before: int,
    sequence_after: int,
    strong_nullifier_root_before: bytes,
    strong_nullifier_root_after: bytes,
    strong_governance_commitment: bytes,
    strong_payment_state_root_before: bytes,
    strong_payment_state_root_after: bytes,
    strong_batch_commitment: bytes,
) -> CandidateSidecarV1:
    return CandidateSidecarV1(
        profile_id=profile_id,
        proof_suite_id=proof_suite_id,
        schema_id=schema_id,
        verifier_artifact_identity=verifier_artifact_identity,
        strong_settlement_domain_id=strong_settlement_domain_id,
        epoch=epoch,
        sequence_before=sequence_before,
        sequence_after=sequence_after,
        strong_nullifier_root_before=strong_nullifier_root_before,
        strong_nullifier_root_after=strong_nullifier_root_after,
        strong_governance_commitment=strong_governance_commitment,
        strong_payment_state_root_before=strong_payment_state_root_before,
        strong_payment_state_root_after=strong_payment_state_root_after,
        strong_batch_commitment=strong_batch_commitment,
    )


def wave3_batch_commitment(raw_preimage: bytes) -> bytes:
    """Bind the private canonical A12 preimage to the public sidecar digest."""

    if type(raw_preimage) is not bytes or not raw_preimage or len(raw_preimage) > MAX_RAW_PREIMAGE_BYTES:
        raise Wave3BoundaryError("wave3_batch_preimage_invalid")
    return _digest(ATOMIC_BINDING_DOMAIN, raw_preimage)


class ProofVerifierPort(Protocol):
    def verify(
        self,
        *,
        proof: bytes,
        public_fields: tuple[bytes, ...],
        sidecar: CandidateSidecarV1,
    ) -> bytes: ...


@dataclass(frozen=True, slots=True)
class ActiveVerifierProfileV1:
    identity: ActiveSuiteIdentityV1
    activation_allowed: bool = False

    def __post_init__(self) -> None:
        if type(self.identity) is not ActiveSuiteIdentityV1:
            raise TypeError("wave3_active_identity_required")
        if type(self.activation_allowed) is not bool:
            raise TypeError("wave3_activation_flag_invalid")
        if self.activation_allowed and not ACTIVATION_ALLOWED:
            raise Wave3BoundaryError("wave3_activation_globally_closed")


@dataclass(frozen=True, slots=True)
class VerifiedStrongOutputsV1:
    """Typed copy of the fixed public boundary after structural verification."""

    sidecar: CandidateSidecarV1
    public_fields: tuple[bytes, ...]

    def __post_init__(self) -> None:
        if type(self.sidecar) is not CandidateSidecarV1:
            raise TypeError("wave3_verified_sidecar_required")
        if type(self.public_fields) is not tuple or len(self.public_fields) != 12:
            raise Wave3BoundaryError("wave3_verified_public_field_count_invalid")
        for index, value in enumerate(self.public_fields):
            _bytes(f"verified_public_field_{index}", value, PUBLIC_FIELD_BYTES)

    def canonical_bytes(self) -> bytes:
        return self.sidecar.encode() + b"".join(self.public_fields)

    @property
    def strong_nullifier_root_before(self) -> bytes:
        return self.sidecar.strong_nullifier_root_before

    @property
    def strong_nullifier_root_after(self) -> bytes:
        return self.sidecar.strong_nullifier_root_after

    @property
    def epoch(self) -> int:
        return self.sidecar.epoch

    @property
    def sequence_before(self) -> int:
        return self.sidecar.sequence_before

    @property
    def sequence_after(self) -> int:
        return self.sidecar.sequence_after


@dataclass(frozen=True, slots=True)
class VerifiedProofContextV1:
    sidecar: CandidateSidecarV1
    public_fields: tuple[bytes, ...]
    proof_digest_512: bytes
    verifier_identity_512: bytes
    strong_outputs: VerifiedStrongOutputsV1 = field(init=False)

    def __post_init__(self) -> None:
        if type(self.sidecar) is not CandidateSidecarV1:
            raise TypeError("wave3_verified_context_sidecar_invalid")
        if type(self.public_fields) is not tuple or len(self.public_fields) != 12:
            raise Wave3BoundaryError("wave3_verified_context_public_fields_invalid")
        _bytes("verified_context_proof_digest", self.proof_digest_512, IDENTITY_BYTES, nonzero=True)
        _bytes("verified_context_verifier_identity", self.verifier_identity_512, IDENTITY_BYTES, nonzero=True)
        outputs = VerifiedStrongOutputsV1(self.sidecar, self.public_fields)
        object.__setattr__(self, "strong_outputs", outputs)

    @property
    def sidecar_digest_512(self) -> bytes:
        return sha3_512(self.sidecar.encode()).digest()

    @property
    def atomic_binding_512(self) -> bytes:
        return _digest(
            ATOMIC_BINDING_DOMAIN,
            self.strong_outputs.canonical_bytes(),
            self.proof_digest_512,
            self.verifier_identity_512,
        )


class Wave3VerifierV1:
    """Production-shaped verifier port; inactive profiles reject before proof work."""

    def __init__(
        self,
        *,
        active_profile: ActiveVerifierProfileV1 | None = None,
        proof_verifier: ProofVerifierPort | None = None,
    ) -> None:
        if active_profile is not None and type(active_profile) is not ActiveVerifierProfileV1:
            raise TypeError("wave3_active_profile_type_invalid")
        self.active_profile = active_profile
        self.proof_verifier = proof_verifier

    def verify(
        self,
        *,
        encoded_sidecar: bytes,
        public_fields: Sequence[bytes],
        proof: bytes,
    ) -> VerifiedProofContextV1:
        return self._verify(
            encoded_sidecar=encoded_sidecar,
            public_fields=public_fields,
            proof=proof,
            require_activation=True,
        )

    def verify_candidate(
        self,
        *,
        encoded_sidecar: bytes,
        public_fields: Sequence[bytes],
        proof: bytes,
    ) -> VerifiedProofContextV1:
        """Run the complete local/reference interface without enabling production."""

        return self._verify(
            encoded_sidecar=encoded_sidecar,
            public_fields=public_fields,
            proof=proof,
            require_activation=False,
        )

    def _verify(
        self,
        *,
        encoded_sidecar: bytes,
        public_fields: Sequence[bytes],
        proof: bytes,
        require_activation: bool,
    ) -> VerifiedProofContextV1:
        try:
            sidecar = CandidateSidecarV1.decode(encoded_sidecar)
        except (TypeError, ValueError) as exc:
            raise Wave3BoundaryError("wave3_sidecar_rejected") from exc
        if type(public_fields) not in (tuple, list) or len(public_fields) != 12:
            raise Wave3BoundaryError("wave3_public_field_count_invalid")
        fields = tuple(
            _bytes(f"public_field_{index}", value, PUBLIC_FIELD_BYTES)
            for index, value in enumerate(public_fields)
        )
        if self.active_profile is None:
            raise Wave3BoundaryError("wave3_proof_suite_unselected")
        if require_activation and not self.active_profile.activation_allowed:
            raise Wave3BoundaryError("wave3_proof_suite_unselected")
        active = self.active_profile.identity
        try:
            from app.batch.pq_suite_candidate import validate_active_binding

            validate_active_binding(encoded_sidecar, fields, active)
        except (TypeError, ValueError) as exc:
            raise Wave3BoundaryError("wave3_active_binding_rejected") from exc
        if self.proof_verifier is None:
            raise Wave3BoundaryError("wave3_production_verifier_unavailable")
        if type(proof) is not bytes or not proof:
            raise Wave3BoundaryError("wave3_proof_bytes_invalid")
        try:
            digest = self.proof_verifier.verify(
                proof=proof,
                public_fields=fields,
                sidecar=sidecar,
            )
        except Exception as exc:
            raise Wave3BoundaryError("wave3_proof_verification_rejected") from exc
        _bytes("verified_proof_digest", digest, 64, nonzero=True)
        return VerifiedProofContextV1(
            sidecar,
            fields,
            digest,
            active.verifier_artifact_identity,
        )


@dataclass(frozen=True, slots=True)
class Wave3StatePayloadV1:
    profile_id: bytes
    authority_id_512: bytes
    registry_commitment_512: bytes
    epoch: int
    sequence: int
    raw_preimages: tuple[bytes, ...]
    atomic_binding_512: bytes = ZERO_ID_512

    def __post_init__(self) -> None:
        _bytes("state_profile_id", self.profile_id, IDENTITY_BYTES, nonzero=True)
        _bytes("state_authority_id", self.authority_id_512, IDENTITY_BYTES, nonzero=True)
        _bytes("state_registry_commitment", self.registry_commitment_512, IDENTITY_BYTES, nonzero=True)
        _u64("state_epoch", self.epoch, nonzero=True)
        _u64("state_sequence", self.sequence)
        _bytes("state_atomic_binding", self.atomic_binding_512, IDENTITY_BYTES)
        if type(self.raw_preimages) is not tuple or len(self.raw_preimages) > MAX_STATE_RECORDS:
            raise Wave3BoundaryError("wave3_state_record_count_invalid")
        for raw in self.raw_preimages:
            if type(raw) is not bytes:
                raise Wave3BoundaryError("wave3_state_raw_preimage_type_invalid")
            _bytes("state_raw_preimage", raw, len(raw))
            if not raw or len(raw) > MAX_RAW_PREIMAGE_BYTES:
                raise Wave3BoundaryError("wave3_state_raw_preimage_invalid")

    def canonical_bytes(self) -> bytes:
        return b"".join(
            (
                STATE_PAYLOAD_DOMAIN,
                self.profile_id,
                self.authority_id_512,
                self.registry_commitment_512,
                self.epoch.to_bytes(8, "big"),
                self.sequence.to_bytes(8, "big"),
                len(self.raw_preimages).to_bytes(4, "big"),
                *(len(raw).to_bytes(4, "big") + raw for raw in self.raw_preimages),
                self.atomic_binding_512,
            )
        )

    @property
    def digest_512(self) -> bytes:
        return sha3_512(self.canonical_bytes()).digest()


@dataclass(frozen=True, slots=True)
class Wave3StateEnvelopeV1:
    current: Wave3StatePayloadV1
    history: tuple[Wave3StatePayloadV1, ...] = ()

    def __post_init__(self) -> None:
        if type(self.current) is not Wave3StatePayloadV1:
            raise TypeError("wave3_state_current_payload_invalid")
        if type(self.history) is not tuple or len(self.history) > MAX_HISTORY:
            raise Wave3BoundaryError("wave3_state_history_invalid")
        if any(type(item) is not Wave3StatePayloadV1 for item in self.history):
            raise Wave3BoundaryError("wave3_state_history_payload_invalid")
        digests = (self.current.digest_512, *(item.digest_512 for item in self.history))
        if len(set(digests)) != len(digests):
            raise Wave3BoundaryError("wave3_state_duplicate_checkpoint")
        previous_position = (self.current.epoch, self.current.sequence)
        for item in self.history:
            position = (item.epoch, item.sequence)
            if position >= previous_position:
                raise Wave3BoundaryError("wave3_state_history_order_invalid")
            previous_position = position

    def encode(self) -> bytes:
        body = self.current.canonical_bytes()
        body += len(self.history).to_bytes(2, "big")
        body += b"".join(
            len(item.canonical_bytes()).to_bytes(4, "big") + item.canonical_bytes()
            for item in self.history
        )
        digest = sha3_512(STATE_FILE_DOMAIN + body).digest()
        encoded = b"".join(
            (
                STATE_MAGIC,
                STATE_VERSION.to_bytes(2, "big"),
                (0).to_bytes(2, "big"),
                (STATE_HEADER_BYTES + len(body) + len(digest)).to_bytes(8, "big"),
                body,
                digest,
            )
        )
        if len(encoded) > MAX_STATE_FILE_BYTES:
            raise Wave3BoundaryError("wave3_state_file_size_limit_exceeded")
        if len(encoded) != int.from_bytes(encoded[12:20], "big"):
            raise AssertionError("wave3_state_file_internal_length_mismatch")
        return encoded

    @classmethod
    def decode(cls, encoded: bytes) -> "Wave3StateEnvelopeV1":
        if (
            type(encoded) is not bytes
            or len(encoded) < STATE_HEADER_BYTES + 64
            or len(encoded) > MAX_STATE_FILE_BYTES
        ):
            raise Wave3BoundaryError("wave3_state_file_length_invalid")
        if encoded[:8] != STATE_MAGIC:
            raise Wave3BoundaryError("wave3_state_file_magic_invalid")
        if int.from_bytes(encoded[8:10], "big") != STATE_VERSION:
            raise Wave3BoundaryError("wave3_state_file_version_invalid")
        if int.from_bytes(encoded[10:12], "big") != 0:
            raise Wave3BoundaryError("wave3_state_file_flags_invalid")
        if int.from_bytes(encoded[12:20], "big") != len(encoded):
            raise Wave3BoundaryError("wave3_state_file_declared_length_invalid")
        body = encoded[STATE_HEADER_BYTES:-64]
        expected = sha3_512(STATE_FILE_DOMAIN + body).digest()
        if not hmac.compare_digest(encoded[-64:], expected):
            raise Wave3BoundaryError("wave3_state_file_digest_invalid")

        def payload(raw: bytes) -> Wave3StatePayloadV1:
            cursor = 0

            def take(length: int, label: str) -> bytes:
                nonlocal cursor
                if length < 0 or cursor + length > len(raw):
                    raise Wave3BoundaryError(f"wave3_state_{label}_truncated")
                value = raw[cursor : cursor + length]
                cursor += length
                return value

            domain = take(len(STATE_PAYLOAD_DOMAIN), "payload_domain")
            if domain != STATE_PAYLOAD_DOMAIN:
                raise Wave3BoundaryError("wave3_state_payload_domain_invalid")
            profile = take(64, "profile")
            authority = take(64, "authority")
            registry = take(64, "registry")
            epoch = int.from_bytes(take(8, "epoch"), "big")
            sequence = int.from_bytes(take(8, "sequence"), "big")
            count = int.from_bytes(take(4, "record_count"), "big")
            if count > MAX_STATE_RECORDS:
                raise Wave3BoundaryError("wave3_state_record_count_invalid")
            records = []
            for index in range(count):
                length = int.from_bytes(take(4, f"record_{index}_length"), "big")
                if length == 0 or length > MAX_RAW_PREIMAGE_BYTES:
                    raise Wave3BoundaryError("wave3_state_record_length_invalid")
                records.append(take(length, f"record_{index}"))
            binding = take(IDENTITY_BYTES, "atomic_binding")
            if cursor != len(raw):
                raise Wave3BoundaryError("wave3_state_payload_trailing_data")
            value = cls._payload(
                profile,
                authority,
                registry,
                epoch,
                sequence,
                tuple(records),
                binding,
            )
            if value.canonical_bytes() != raw:
                raise Wave3BoundaryError("wave3_state_payload_noncanonical")
            return value

        cursor = 0
        if len(body) < len(STATE_PAYLOAD_DOMAIN) + 64 * 3 + 8 + 8 + 4 + 2:
            raise Wave3BoundaryError("wave3_state_body_truncated")
        domain_end = len(STATE_PAYLOAD_DOMAIN)
        cursor = domain_end + 64 * 3 + 8 + 8
        count_end = cursor + 4
        record_count = int.from_bytes(body[cursor:count_end], "big")
        if record_count > MAX_STATE_RECORDS:
            raise Wave3BoundaryError("wave3_state_record_count_invalid")
        cursor = count_end
        for index in range(record_count):
            if cursor + 4 > len(body):
                raise Wave3BoundaryError(f"wave3_state_record_{index}_length_truncated")
            length = int.from_bytes(body[cursor : cursor + 4], "big")
            cursor += 4 + length
            if length == 0 or length > MAX_RAW_PREIMAGE_BYTES or cursor > len(body):
                raise Wave3BoundaryError("wave3_state_record_length_invalid")
        if cursor + IDENTITY_BYTES > len(body):
            raise Wave3BoundaryError("wave3_state_atomic_binding_truncated")
        cursor += IDENTITY_BYTES
        if cursor + 2 > len(body):
            raise Wave3BoundaryError("wave3_state_history_count_truncated")
        current = payload(body[:cursor])
        history_count = int.from_bytes(body[cursor : cursor + 2], "big")
        cursor += 2
        if history_count > MAX_HISTORY:
            raise Wave3BoundaryError("wave3_state_history_count_invalid")
        history = []
        for index in range(history_count):
            if cursor + 4 > len(body):
                raise Wave3BoundaryError(f"wave3_state_history_{index}_length_truncated")
            length = int.from_bytes(body[cursor : cursor + 4], "big")
            cursor += 4
            if length == 0 or cursor + length > len(body):
                raise Wave3BoundaryError("wave3_state_history_length_invalid")
            history.append(payload(body[cursor : cursor + length]))
            cursor += length
        if cursor != len(body):
            raise Wave3BoundaryError("wave3_state_file_trailing_data")
        envelope = cls(current, tuple(history))
        for payload_value in (envelope.current, *envelope.history):
            _replay_payload(payload_value)
        return envelope

    @staticmethod
    def _payload(
        profile: bytes,
        authority: bytes,
        registry: bytes,
        epoch: int,
        sequence: int,
        records: tuple[bytes, ...],
        atomic_binding: bytes = ZERO_ID_512,
    ) -> Wave3StatePayloadV1:
        return Wave3StatePayloadV1(profile, authority, registry, epoch, sequence, records, atomic_binding)


@dataclass(frozen=True, slots=True)
class Wave3CustodySnapshotV1:
    profile_id: bytes
    authority_id_512: bytes
    registry_commitment_512: bytes
    state: Wave3StateSnapshotV1
    state_digest_512: bytes
    atomic_binding_512: bytes = ZERO_ID_512


@dataclass(frozen=True, slots=True)
class Wave3MigrationRecordV1:
    old_checkpoint_512: bytes
    new_checkpoint_512: bytes
    old_epoch: int
    new_epoch: int
    sequence: int
    root_512: bytes
    migration_digest_512: bytes = field(init=False)

    def __post_init__(self) -> None:
        old = _bytes("migration_old_checkpoint", self.old_checkpoint_512, 64, nonzero=True)
        new = _bytes("migration_new_checkpoint", self.new_checkpoint_512, 64, nonzero=True)
        if old == new:
            raise Wave3BoundaryError("wave3_migration_checkpoint_unchanged")
        old_epoch = _u64("migration_old_epoch", self.old_epoch, nonzero=True)
        new_epoch = _u64("migration_new_epoch", self.new_epoch, nonzero=True)
        if new_epoch != old_epoch + 1:
            raise Wave3BoundaryError("wave3_migration_epoch_not_successor")
        _u64("migration_sequence", self.sequence)
        root = _bytes("migration_root", self.root_512, 64, nonzero=True)
        object.__setattr__(
            self,
            "migration_digest_512",
            _digest(MIGRATION_DOMAIN, old, new, old_epoch.to_bytes(8, "big"), new_epoch.to_bytes(8, "big"), self.sequence.to_bytes(8, "big"), root),
        )


@dataclass(frozen=True, slots=True)
class Wave3RollbackRecordV1:
    target_checkpoint_512: bytes
    new_checkpoint_512: bytes
    old_epoch: int
    new_epoch: int
    sequence: int
    root_512: bytes
    rollback_digest_512: bytes = field(init=False)

    def __post_init__(self) -> None:
        target = _bytes("rollback_target_checkpoint", self.target_checkpoint_512, 64, nonzero=True)
        new = _bytes("rollback_new_checkpoint", self.new_checkpoint_512, 64, nonzero=True)
        if target == new:
            raise Wave3BoundaryError("wave3_rollback_checkpoint_unchanged")
        old_epoch = _u64("rollback_old_epoch", self.old_epoch, nonzero=True)
        new_epoch = _u64("rollback_new_epoch", self.new_epoch, nonzero=True)
        if new_epoch <= old_epoch:
            raise Wave3BoundaryError("wave3_rollback_epoch_not_newer")
        _u64("rollback_sequence", self.sequence)
        root = _bytes("rollback_root", self.root_512, 64, nonzero=True)
        object.__setattr__(
            self,
            "rollback_digest_512",
            _digest(ROLLBACK_DOMAIN, target, new, old_epoch.to_bytes(8, "big"), new_epoch.to_bytes(8, "big"), self.sequence.to_bytes(8, "big"), root),
        )


@dataclass(frozen=True, slots=True)
class Wave3UpgradeRecordV1:
    old_checkpoint_512: bytes
    new_checkpoint_512: bytes
    old_profile_id: bytes
    new_profile_id: bytes
    old_authority_id_512: bytes
    new_authority_id_512: bytes
    old_registry_commitment_512: bytes
    new_registry_commitment_512: bytes
    old_epoch: int
    new_epoch: int
    sequence: int
    root_512: bytes
    upgrade_digest_512: bytes = field(init=False)

    def __post_init__(self) -> None:
        old_checkpoint = _bytes("upgrade_old_checkpoint", self.old_checkpoint_512, IDENTITY_BYTES, nonzero=True)
        new_checkpoint = _bytes("upgrade_new_checkpoint", self.new_checkpoint_512, IDENTITY_BYTES, nonzero=True)
        if old_checkpoint == new_checkpoint:
            raise Wave3BoundaryError("wave3_upgrade_checkpoint_unchanged")
        old_profile = _bytes("upgrade_old_profile", self.old_profile_id, IDENTITY_BYTES, nonzero=True)
        new_profile = _bytes("upgrade_new_profile", self.new_profile_id, IDENTITY_BYTES, nonzero=True)
        old_authority = _bytes("upgrade_old_authority", self.old_authority_id_512, IDENTITY_BYTES, nonzero=True)
        new_authority = _bytes("upgrade_new_authority", self.new_authority_id_512, IDENTITY_BYTES, nonzero=True)
        if old_profile == new_profile or old_authority == new_authority:
            raise Wave3BoundaryError("wave3_upgrade_profile_authority_change_required")
        old_registry = _bytes("upgrade_old_registry", self.old_registry_commitment_512, IDENTITY_BYTES, nonzero=True)
        new_registry = _bytes("upgrade_new_registry", self.new_registry_commitment_512, IDENTITY_BYTES, nonzero=True)
        old_epoch = _u64("upgrade_old_epoch", self.old_epoch, nonzero=True)
        new_epoch = _u64("upgrade_new_epoch", self.new_epoch, nonzero=True)
        if new_epoch != old_epoch + 1:
            raise Wave3BoundaryError("wave3_upgrade_epoch_not_successor")
        sequence = _u64("upgrade_sequence", self.sequence)
        root = _bytes("upgrade_root", self.root_512, WIDE_BYTES, nonzero=True)
        object.__setattr__(self, "upgrade_digest_512", _digest(
            UPGRADE_DOMAIN,
            old_checkpoint,
            new_checkpoint,
            old_profile,
            new_profile,
            old_authority,
            new_authority,
            old_registry,
            new_registry,
            old_epoch.to_bytes(8, "big"),
            new_epoch.to_bytes(8, "big"),
            sequence.to_bytes(8, "big"),
            root,
        ))


@dataclass(frozen=True, slots=True)
class Wave3ActivationConfigV1:
    identity: ActiveSuiteIdentityV1
    authority_id_512: bytes
    registry_commitment_512: bytes
    hsm_backed: bool
    fips_validated: bool
    activation_requested: bool = True

    def __post_init__(self) -> None:
        if type(self.identity) is not ActiveSuiteIdentityV1:
            raise TypeError("wave3_activation_identity_required")
        _bytes("activation_authority_id", self.authority_id_512, IDENTITY_BYTES, nonzero=True)
        _bytes("activation_registry_commitment", self.registry_commitment_512, IDENTITY_BYTES, nonzero=True)
        if type(self.hsm_backed) is not bool or type(self.fips_validated) is not bool:
            raise Wave3BoundaryError("wave3_activation_provider_flags_invalid")
        if type(self.activation_requested) is not bool:
            raise Wave3BoundaryError("wave3_activation_request_flag_invalid")

    def canonical_bytes(self) -> bytes:
        return b"".join(
            (
                ACTIVATION_DOMAIN,
                self.identity.profile_id,
                self.identity.proof_suite_id,
                self.identity.schema_id,
                self.identity.verifier_artifact_identity,
                self.identity.strong_settlement_domain_id,
                self.identity.epoch.to_bytes(8, "big"),
                self.identity.legacy_protocol_version_alias,
                self.identity.legacy_settlement_domain_alias,
                self.authority_id_512,
                self.registry_commitment_512,
                bytes((int(self.hsm_backed), int(self.fips_validated), int(self.activation_requested))),
            )
        )

    def validate_for_activation(self) -> bytes:
        if not self.activation_requested:
            raise Wave3BoundaryError("wave3_activation_not_requested")
        if not ACTIVATION_ALLOWED:
            raise Wave3BoundaryError("wave3_activation_globally_closed")
        if not self.hsm_backed or not self.fips_validated:
            raise Wave3BoundaryError("wave3_activation_provider_not_qualified")
        return sha3_512(self.canonical_bytes()).digest()


@dataclass(frozen=True, slots=True)
class Wave3RecoveryAnchorV1:
    checkpoint_512: bytes
    profile_id: bytes
    authority_id_512: bytes
    registry_commitment_512: bytes
    epoch: int
    sequence: int
    root_512: bytes
    signatures: tuple[PqSignatureEnvelopeV1, ...] = field(repr=False)

    def __post_init__(self) -> None:
        _bytes("recovery_checkpoint", self.checkpoint_512, IDENTITY_BYTES, nonzero=True)
        _bytes("recovery_profile", self.profile_id, IDENTITY_BYTES, nonzero=True)
        _bytes("recovery_authority", self.authority_id_512, IDENTITY_BYTES, nonzero=True)
        _bytes("recovery_registry", self.registry_commitment_512, IDENTITY_BYTES, nonzero=True)
        _u64("recovery_epoch", self.epoch, nonzero=True)
        _u64("recovery_sequence", self.sequence)
        _bytes("recovery_root", self.root_512, WIDE_BYTES, nonzero=True)
        if type(self.signatures) is not tuple or len(self.signatures) != 2:
            raise Wave3BoundaryError("wave3_recovery_signature_count_invalid")
        if any(type(item) is not PqSignatureEnvelopeV1 for item in self.signatures):
            raise Wave3BoundaryError("wave3_recovery_signature_type_invalid")

    def unsigned_bytes(self) -> bytes:
        return b"".join(
            (
                RECOVERY_DOMAIN,
                self.checkpoint_512,
                self.profile_id,
                self.authority_id_512,
                self.registry_commitment_512,
                self.epoch.to_bytes(8, "big"),
                self.sequence.to_bytes(8, "big"),
                self.root_512,
            )
        )

    @property
    def anchor_digest_512(self) -> bytes:
        return sha3_512(self.unsigned_bytes()).digest()

    @classmethod
    def issue(
        cls,
        *,
        payload: Wave3StatePayloadV1,
        authority: DualPqAuthorityV1,
        root_512: bytes,
    ) -> "Wave3RecoveryAnchorV1":
        if type(payload) is not Wave3StatePayloadV1 or type(authority) is not DualPqAuthorityV1:
            raise TypeError("wave3_recovery_payload_and_authority_required")
        unsigned = cls(
            payload.digest_512,
            payload.profile_id,
            payload.authority_id_512,
            payload.registry_commitment_512,
            payload.epoch,
            payload.sequence,
            root_512,
            tuple(
                PqSignatureEnvelopeV1(suite, authority.keys[index].key_id, b"\x01" * SIGNATURE_SIZES[suite])
                for index, suite in enumerate(DUAL_PQ_SUITES)
            ),
        )
        return replace(unsigned, signatures=authority.sign(unsigned_root=unsigned.anchor_digest_512))

    def verify(
        self,
        *,
        authority: DualPqAuthorityV1,
        registry: GovernedRootRegistryV1,
    ) -> bool:
        if type(authority) is not DualPqAuthorityV1 or type(registry) is not GovernedRootRegistryV1:
            raise TypeError("wave3_recovery_authority_and_registry_required")
        if self.authority_id_512 != authority.authority_id_512:
            raise Wave3BoundaryError("wave3_recovery_authority_mismatch")
        if self.registry_commitment_512 != registry.commitment_sha3_512:
            raise Wave3BoundaryError("wave3_recovery_registry_mismatch")
        authority.verify(unsigned_root=self.anchor_digest_512, signatures=self.signatures)
        return True


def _replay_payload(payload: Wave3StatePayloadV1) -> tuple[Wave3NullifierAuthorityV1, Wave3StateSnapshotV1]:
    authority = Wave3NullifierAuthorityV1(epoch=payload.epoch)
    for raw in payload.raw_preimages:
        transition = authority.prepare_transition(raw)
        independently_verify_wave3_transition(transition)
        authority.commit(transition)
    snapshot = authority.snapshot()
    if snapshot.sequence != payload.sequence:
        raise Wave3BoundaryError("wave3_state_sequence_replay_mismatch")
    return authority, snapshot


@contextmanager
def _exclusive_lock(path: Path):
    lock_path = path.with_name(path.name + ".lock")
    try:
        descriptor = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError as exc:
        raise Wave3BoundaryError("wave3_state_lock_busy") from exc
    try:
        os.write(descriptor, str(os.getpid()).encode("ascii"))
        yield
    finally:
        os.close(descriptor)
        try:
            lock_path.unlink()
        except FileNotFoundError:
            pass


def _atomic_write(path: Path, encoded: bytes) -> None:
    temporary = path.with_name(f"{path.name}.tmp.{os.getpid()}")
    if temporary.exists():
        raise Wave3BoundaryError("wave3_state_temporary_path_exists")
    descriptor = os.open(str(temporary), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if descriptor != -1:
            os.close(descriptor)
        if temporary.exists():
            temporary.unlink()


class Wave3DurableStateV1:
    """Private file-backed state with atomic dual-root publication."""

    def __init__(
        self,
        path: Path,
        *,
        registry: GovernedRootRegistryV1,
        profile_id: bytes,
        authority_id_512: bytes,
    ) -> None:
        if not isinstance(path, Path):
            raise TypeError("wave3_state_path_required")
        if type(registry) is not GovernedRootRegistryV1:
            raise TypeError("wave3_state_registry_required")
        self.path = path
        self._registry = registry
        self._profile_id = _bytes("state_profile_id", profile_id, 64, nonzero=True)
        self._authority_id = _bytes("state_authority_id", authority_id_512, 64, nonzero=True)
        self._lock = RLock()
        if not self.path.is_file():
            raise Wave3BoundaryError("wave3_state_file_missing")
        self._validate_current(self._read())

    @classmethod
    def create(
        cls,
        path: Path,
        *,
        registry: GovernedRootRegistryV1,
        profile_id: bytes,
        authority_id_512: bytes,
        epoch: int = 1,
    ) -> "Wave3DurableStateV1":
        if not isinstance(path, Path) or type(registry) is not GovernedRootRegistryV1:
            raise TypeError("wave3_state_create_arguments_invalid")
        if path.exists():
            raise Wave3BoundaryError("wave3_state_file_already_exists")
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = Wave3StatePayloadV1(
            _bytes("state_profile_id", profile_id, 64, nonzero=True),
            _bytes("state_authority_id", authority_id_512, 64, nonzero=True),
            registry.commitment_sha3_512,
            _u64("state_epoch", epoch, nonzero=True),
            0,
            (),
        )
        with _exclusive_lock(path):
            _atomic_write(path, Wave3StateEnvelopeV1(payload).encode())
        return cls(path, registry=registry, profile_id=profile_id, authority_id_512=authority_id_512)

    @classmethod
    def recover(
        cls,
        path: Path,
        *,
        payload: Wave3StatePayloadV1,
        anchor: Wave3RecoveryAnchorV1,
        registry: GovernedRootRegistryV1,
        authority: DualPqAuthorityV1,
        replace_existing: bool = False,
    ) -> "Wave3DurableStateV1":
        if not isinstance(path, Path) or type(payload) is not Wave3StatePayloadV1:
            raise TypeError("wave3_recovery_path_and_payload_required")
        if type(anchor) is not Wave3RecoveryAnchorV1 or type(registry) is not GovernedRootRegistryV1:
            raise TypeError("wave3_recovery_anchor_and_registry_required")
        if type(authority) is not DualPqAuthorityV1 or type(replace_existing) is not bool:
            raise TypeError("wave3_recovery_arguments_invalid")
        anchor.verify(authority=authority, registry=registry)
        if anchor.checkpoint_512 != payload.digest_512:
            raise Wave3BoundaryError("wave3_recovery_checkpoint_mismatch")
        if (
            anchor.profile_id != payload.profile_id
            or anchor.authority_id_512 != payload.authority_id_512
            or anchor.registry_commitment_512 != payload.registry_commitment_512
            or anchor.epoch != payload.epoch
            or anchor.sequence != payload.sequence
        ):
            raise Wave3BoundaryError("wave3_recovery_payload_identity_mismatch")
        _, snapshot = _replay_payload(payload)
        if snapshot.strong_nullifier_root_512 != anchor.root_512:
            raise Wave3BoundaryError("wave3_recovery_root_mismatch")
        if path.exists() and not replace_existing:
            raise Wave3BoundaryError("wave3_recovery_file_already_exists")
        path.parent.mkdir(parents=True, exist_ok=True)
        with _exclusive_lock(path):
            _atomic_write(path, Wave3StateEnvelopeV1(payload).encode())
        return cls(
            path,
            registry=registry,
            profile_id=payload.profile_id,
            authority_id_512=payload.authority_id_512,
        )

    def _read(self) -> Wave3StateEnvelopeV1:
        try:
            encoded = self.path.read_bytes()
        except OSError as exc:
            raise Wave3BoundaryError("wave3_state_file_read_failed") from exc
        try:
            return Wave3StateEnvelopeV1.decode(encoded)
        except (TypeError, ValueError) as exc:
            raise Wave3BoundaryError("wave3_state_file_rejected") from exc

    def _validate_current(self, envelope: Wave3StateEnvelopeV1) -> Wave3StateSnapshotV1:
        current = envelope.current
        if current.profile_id != self._profile_id or current.authority_id_512 != self._authority_id:
            raise Wave3BoundaryError("wave3_state_identity_mismatch")
        if current.registry_commitment_512 != self._registry.commitment_sha3_512:
            raise Wave3BoundaryError("wave3_state_registry_mismatch")
        _, snapshot = _replay_payload(current)
        return snapshot

    def snapshot(self) -> Wave3CustodySnapshotV1:
        with self._lock:
            envelope = self._read()
            state = self._validate_current(envelope)
            return Wave3CustodySnapshotV1(
                envelope.current.profile_id,
                envelope.current.authority_id_512,
                envelope.current.registry_commitment_512,
                state,
                envelope.current.digest_512,
                envelope.current.atomic_binding_512,
            )

    def apply(self, raw_preimage: bytes) -> Wave3CustodySnapshotV1:
        if type(raw_preimage) is not bytes:
            raise Wave3BoundaryError("wave3_apply_raw_preimage_type_invalid")
        _bytes("apply_raw_preimage", raw_preimage, len(raw_preimage))
        with self._lock, _exclusive_lock(self.path):
            envelope = self._read()
            before = self._validate_current(envelope)
            if envelope.current.atomic_binding_512 != ZERO_ID_512:
                raise Wave3BoundaryError("wave3_raw_apply_would_drop_atomic_binding")
            authority, _ = _replay_payload(envelope.current)
            transition = authority.prepare_transition(raw_preimage)
            independently_verify_wave3_transition(transition)
            after = authority.commit(transition)
            if transition.before != before or transition.after != after:
                raise Wave3BoundaryError("wave3_state_transition_snapshot_mismatch")
            payload = Wave3StatePayloadV1(
                envelope.current.profile_id,
                envelope.current.authority_id_512,
                envelope.current.registry_commitment_512,
                envelope.current.epoch,
                after.sequence,
                envelope.current.raw_preimages + (raw_preimage,),
                ZERO_ID_512,
            )
            next_envelope = Wave3StateEnvelopeV1(
                payload,
                (envelope.current, *envelope.history)[:MAX_HISTORY],
            )
            _atomic_write(self.path, next_envelope.encode())
            readback = self._read()
            observed = self._validate_current(readback)
            if observed != after or readback.current.digest_512 != payload.digest_512:
                raise Wave3BoundaryError("wave3_state_readback_mismatch")
            return Wave3CustodySnapshotV1(
                payload.profile_id,
                payload.authority_id_512,
                payload.registry_commitment_512,
                observed,
                payload.digest_512,
                payload.atomic_binding_512,
            )

    def apply_verified_batch(
        self,
        context: VerifiedProofContextV1,
        raw_preimage: bytes,
    ) -> Wave3CustodySnapshotV1:
        """Atomically publish one proof-bound dual-root transition."""

        if type(context) is not VerifiedProofContextV1:
            raise TypeError("wave3_verified_context_required")
        if type(raw_preimage) is not bytes or not raw_preimage:
            raise Wave3BoundaryError("wave3_verified_raw_preimage_invalid")
        _bytes("verified_raw_preimage", raw_preimage, len(raw_preimage))
        sidecar = context.sidecar
        with self._lock, _exclusive_lock(self.path):
            envelope = self._read()
            before = self._validate_current(envelope)
            current = envelope.current
            if sidecar.profile_id != current.profile_id or sidecar.epoch != current.epoch:
                raise Wave3BoundaryError("wave3_verified_context_state_identity_mismatch")
            if sidecar.sequence_before != current.sequence:
                raise Wave3BoundaryError("wave3_verified_context_sequence_before_mismatch")
            if sidecar.strong_nullifier_root_before != before.strong_nullifier_root_512:
                raise Wave3BoundaryError("wave3_verified_context_root_before_mismatch")
            if sidecar.strong_batch_commitment != wave3_batch_commitment(raw_preimage):
                raise Wave3BoundaryError("wave3_verified_context_batch_binding_mismatch")
            authority, _ = _replay_payload(current)
            transition = authority.prepare_transition(raw_preimage)
            independently_verify_wave3_transition(transition)
            after = authority.commit(transition)
            if sidecar.sequence_after != after.sequence:
                raise Wave3BoundaryError("wave3_verified_context_sequence_after_mismatch")
            if sidecar.strong_nullifier_root_after != after.strong_nullifier_root_512:
                raise Wave3BoundaryError("wave3_verified_context_root_after_mismatch")
            payload = Wave3StatePayloadV1(
                current.profile_id,
                current.authority_id_512,
                current.registry_commitment_512,
                current.epoch,
                after.sequence,
                current.raw_preimages + (raw_preimage,),
                context.atomic_binding_512,
            )
            next_envelope = Wave3StateEnvelopeV1(
                payload,
                (current, *envelope.history)[:MAX_HISTORY],
            )
            _atomic_write(self.path, next_envelope.encode())
            readback = self._read()
            observed = self._validate_current(readback)
            if (
                observed != after
                or readback.current.digest_512 != payload.digest_512
                or readback.current.atomic_binding_512 != context.atomic_binding_512
            ):
                raise Wave3BoundaryError("wave3_verified_state_readback_mismatch")
            return Wave3CustodySnapshotV1(
                payload.profile_id,
                payload.authority_id_512,
                payload.registry_commitment_512,
                observed,
                payload.digest_512,
                payload.atomic_binding_512,
            )

    def migrate(
        self,
        *,
        registry: GovernedRootRegistryV1,
        profile_id: bytes,
        authority_id_512: bytes,
    ) -> Wave3MigrationRecordV1:
        if type(registry) is not GovernedRootRegistryV1:
            raise TypeError("wave3_migration_registry_required")
        new_profile = _bytes("migration_profile_id", profile_id, 64, nonzero=True)
        new_authority = _bytes("migration_authority_id", authority_id_512, 64, nonzero=True)
        with self._lock, _exclusive_lock(self.path):
            envelope = self._read()
            before = self._validate_current(envelope)
            current = envelope.current
            new_epoch = current.epoch + 1
            if new_epoch > UINT64_MAX:
                raise Wave3BoundaryError("wave3_migration_epoch_exhausted")
            migrated = Wave3StatePayloadV1(
                new_profile,
                new_authority,
                registry.commitment_sha3_512,
                new_epoch,
                current.sequence,
                current.raw_preimages,
                current.atomic_binding_512,
            )
            _, after = _replay_payload(migrated)
            if (
                after.sequence != before.sequence
                or after.record_count != before.record_count
                or after.next_append_index != before.next_append_index
                or after.legacy_root_felt != before.legacy_root_felt
                or after.strong_nullifier_root_512 != before.strong_nullifier_root_512
            ):
                raise Wave3BoundaryError("wave3_migration_root_equivalence_failed")
            next_envelope = Wave3StateEnvelopeV1(
                migrated,
                (current, *envelope.history)[:MAX_HISTORY],
            )
            _atomic_write(self.path, next_envelope.encode())
            self._registry = registry
            self._profile_id = new_profile
            self._authority_id = new_authority
            record = Wave3MigrationRecordV1(
                current.digest_512,
                migrated.digest_512,
                current.epoch,
                new_epoch,
                current.sequence,
                after.strong_nullifier_root_512,
            )
            self._validate_current(self._read())
            return record

    def upgrade(
        self,
        *,
        registry: GovernedRootRegistryV1,
        profile_id: bytes,
        authority_id_512: bytes,
    ) -> Wave3UpgradeRecordV1:
        """Perform a monotonic profile/authority upgrade with one atomic publication."""

        if type(registry) is not GovernedRootRegistryV1:
            raise TypeError("wave3_upgrade_registry_required")
        new_profile = _bytes("upgrade_profile_id", profile_id, IDENTITY_BYTES, nonzero=True)
        new_authority = _bytes("upgrade_authority_id", authority_id_512, IDENTITY_BYTES, nonzero=True)
        if registry.authority.authority_id_512 != new_authority:
            raise Wave3BoundaryError("wave3_upgrade_registry_authority_mismatch")
        with self._lock, _exclusive_lock(self.path):
            envelope = self._read()
            before = self._validate_current(envelope)
            current = envelope.current
            if new_profile == current.profile_id or new_authority == current.authority_id_512:
                raise Wave3BoundaryError("wave3_upgrade_profile_authority_change_required")
            new_epoch = current.epoch + 1
            if new_epoch > UINT64_MAX:
                raise Wave3BoundaryError("wave3_upgrade_epoch_exhausted")
            upgraded = Wave3StatePayloadV1(
                new_profile,
                new_authority,
                registry.commitment_sha3_512,
                new_epoch,
                current.sequence,
                current.raw_preimages,
                current.atomic_binding_512,
            )
            _, after = _replay_payload(upgraded)
            if (
                after.sequence != before.sequence
                or after.record_count != before.record_count
                or after.next_append_index != before.next_append_index
                or after.legacy_root_felt != before.legacy_root_felt
                or after.strong_nullifier_root_512 != before.strong_nullifier_root_512
            ):
                raise Wave3BoundaryError("wave3_upgrade_root_equivalence_failed")
            next_envelope = Wave3StateEnvelopeV1(
                upgraded,
                (current, *envelope.history)[:MAX_HISTORY],
            )
            _atomic_write(self.path, next_envelope.encode())
            self._registry = registry
            self._profile_id = new_profile
            self._authority_id = new_authority
            record = Wave3UpgradeRecordV1(
                current.digest_512,
                upgraded.digest_512,
                current.profile_id,
                new_profile,
                current.authority_id_512,
                new_authority,
                current.registry_commitment_512,
                registry.commitment_sha3_512,
                current.epoch,
                new_epoch,
                current.sequence,
                after.strong_nullifier_root_512,
            )
            self._validate_current(self._read())
            return record

    def rollback(
        self,
        *,
        target_checkpoint_512: bytes,
        registry: GovernedRootRegistryV1,
    ) -> Wave3RollbackRecordV1:
        target_digest = _bytes("rollback_target_checkpoint", target_checkpoint_512, 64, nonzero=True)
        if type(registry) is not GovernedRootRegistryV1:
            raise TypeError("wave3_rollback_registry_required")
        with self._lock, _exclusive_lock(self.path):
            envelope = self._read()
            self._validate_current(envelope)
            target = next(
                (item for item in envelope.history if hmac.compare_digest(item.digest_512, target_digest)),
                None,
            )
            if target is None:
                raise Wave3BoundaryError("wave3_rollback_checkpoint_unknown")
            if target.registry_commitment_512 != registry.commitment_sha3_512:
                raise Wave3BoundaryError("wave3_rollback_registry_mismatch")
            current = envelope.current
            new_epoch = current.epoch + 1
            if new_epoch > UINT64_MAX:
                raise Wave3BoundaryError("wave3_rollback_epoch_exhausted")
            restored = Wave3StatePayloadV1(
                target.profile_id,
                target.authority_id_512,
                target.registry_commitment_512,
                new_epoch,
                target.sequence,
                target.raw_preimages,
                target.atomic_binding_512,
            )
            _, after = _replay_payload(restored)
            target_state = _replay_payload(target)[1]
            if after.strong_nullifier_root_512 != target_state.strong_nullifier_root_512:
                raise Wave3BoundaryError("wave3_rollback_root_mismatch")
            next_envelope = Wave3StateEnvelopeV1(
                restored,
                (current, *envelope.history)[:MAX_HISTORY],
            )
            _atomic_write(self.path, next_envelope.encode())
            self._registry = registry
            self._profile_id = target.profile_id
            self._authority_id = target.authority_id_512
            record = Wave3RollbackRecordV1(
                target.digest_512,
                restored.digest_512,
                current.epoch,
                new_epoch,
                target.sequence,
                after.strong_nullifier_root_512,
            )
            self._validate_current(self._read())
            return record

    @property
    def checkpoint_history(self) -> tuple[bytes, ...]:
        with self._lock:
            envelope = self._read()
            self._validate_current(envelope)
            return tuple(item.digest_512 for item in envelope.history)


class MlKem1024Aes256ReferenceV1:
    """Locked software ML-KEM-1024 plus AES-256-GCM envelope."""

    kem_id: Final[str] = "ML-KEM-1024-AES-256-GCM"
    version: Final[int] = KEM_VERSION
    software_only: Final[bool] = True
    hsm_backed: Final[bool] = False
    production_usable: Final[bool] = False

    @staticmethod
    def _require_locked_dependencies() -> None:
        try:
            if version("pqcrypto") != LOCKED_PQCRYPTO_VERSION or version("cryptography") != "49.0.0":
                raise Wave3BoundaryError("wave3_kem_dependency_version_not_locked")
        except Wave3BoundaryError:
            raise
        except Exception as exc:
            raise Wave3BoundaryError("wave3_kem_dependency_version_unavailable") from exc

    @staticmethod
    def generate_keypair() -> tuple[bytes, bytes]:
        MlKem1024Aes256ReferenceV1._require_locked_dependencies()
        try:
            public_key, secret_key = ml_kem_1024.generate_keypair()
        except Exception as exc:
            raise Wave3BoundaryError("wave3_kem_keygen_failed_closed") from exc
        return (
            _bytes("kem_public_key", public_key, KEM_PUBLIC_KEY_BYTES, nonzero=True),
            _bytes("kem_secret_key", secret_key, KEM_SECRET_KEY_BYTES, nonzero=True),
        )

    @staticmethod
    def _aes_key(shared_secret: bytes, associated_data: bytes) -> bytes:
        return _digest(
            COMMITMENT_DOMAIN,
            b"ML-KEM-1024/AES-256-GCM",
            _bytes("kem_shared_secret", shared_secret, KEM_SHARED_SECRET_BYTES, nonzero=True),
            sha3_512(_bytes("kem_associated_data", associated_data, len(associated_data))).digest(),
        )[:32]

    @staticmethod
    def seal(
        *,
        key_id: bytes,
        public_key: bytes,
        plaintext: bytes,
        associated_data: bytes,
    ) -> bytes:
        MlKem1024Aes256ReferenceV1._require_locked_dependencies()
        _bytes("kem_key_id", key_id, KEM_KEY_ID_BYTES, nonzero=True)
        public = _bytes("kem_public_key", public_key, KEM_PUBLIC_KEY_BYTES, nonzero=True)
        if type(plaintext) is not bytes or not plaintext or len(plaintext) > KEM_MAX_PLAINTEXT_BYTES:
            raise Wave3BoundaryError("wave3_kem_plaintext_bounds_invalid")
        aad = _bytes("kem_associated_data", associated_data, len(associated_data))
        try:
            kem_ciphertext, shared_secret = ml_kem_1024.encrypt(public)
            nonce = secrets.token_bytes(KEM_NONCE_BYTES)
            aes_ciphertext = AESGCM(MlKem1024Aes256ReferenceV1._aes_key(shared_secret, aad)).encrypt(
                nonce,
                plaintext,
                KEM_MAGIC + key_id + aad,
            )
        except Exception as exc:
            raise Wave3BoundaryError("wave3_kem_seal_failed_closed") from exc
        encoded = b"".join(
            (
                KEM_MAGIC,
                KEM_VERSION.to_bytes(2, "big"),
                (0).to_bytes(2, "big"),
                key_id,
                kem_ciphertext,
                nonce,
                len(aes_ciphertext).to_bytes(4, "big"),
                aes_ciphertext,
            )
        )
        return encoded

    @staticmethod
    def open(
        *,
        secret_key: bytes,
        envelope: bytes,
        associated_data: bytes,
        expected_key_id: bytes,
    ) -> bytes:
        MlKem1024Aes256ReferenceV1._require_locked_dependencies()
        secret = _bytes("kem_secret_key", secret_key, KEM_SECRET_KEY_BYTES, nonzero=True)
        aad = _bytes("kem_associated_data", associated_data, len(associated_data))
        expected = _bytes("kem_expected_key_id", expected_key_id, KEM_KEY_ID_BYTES, nonzero=True)
        if type(envelope) is not bytes or len(envelope) < 8 + 2 + 2 + KEM_KEY_ID_BYTES + KEM_CIPHERTEXT_BYTES + KEM_NONCE_BYTES + 4 + 16:
            raise Wave3BoundaryError("wave3_kem_envelope_invalid")
        cursor = 0
        if envelope[:8] != KEM_MAGIC:
            raise Wave3BoundaryError("wave3_kem_magic_invalid")
        cursor = 8
        if int.from_bytes(envelope[cursor : cursor + 2], "big") != KEM_VERSION:
            raise Wave3BoundaryError("wave3_kem_version_invalid")
        cursor += 2
        if int.from_bytes(envelope[cursor : cursor + 2], "big") != 0:
            raise Wave3BoundaryError("wave3_kem_flags_invalid")
        cursor += 2
        key_id = envelope[cursor : cursor + KEM_KEY_ID_BYTES]
        cursor += KEM_KEY_ID_BYTES
        if not hmac.compare_digest(key_id, expected):
            raise Wave3BoundaryError("wave3_kem_key_id_mismatch")
        kem_ciphertext = envelope[cursor : cursor + KEM_CIPHERTEXT_BYTES]
        cursor += KEM_CIPHERTEXT_BYTES
        nonce = envelope[cursor : cursor + KEM_NONCE_BYTES]
        cursor += KEM_NONCE_BYTES
        ciphertext_length = int.from_bytes(envelope[cursor : cursor + 4], "big")
        cursor += 4
        if ciphertext_length < 16 or ciphertext_length > KEM_MAX_PLAINTEXT_BYTES + 16:
            raise Wave3BoundaryError("wave3_kem_ciphertext_bounds_invalid")
        if cursor + ciphertext_length != len(envelope):
            raise Wave3BoundaryError("wave3_kem_envelope_length_invalid")
        ciphertext = envelope[cursor:]
        try:
            shared_secret = ml_kem_1024.decrypt(secret, kem_ciphertext)
            return AESGCM(MlKem1024Aes256ReferenceV1._aes_key(shared_secret, aad)).decrypt(
                nonce,
                ciphertext,
                KEM_MAGIC + key_id + aad,
            )
        except Exception as exc:
            raise Wave3BoundaryError("wave3_kem_open_rejected") from exc


__all__: tuple[str, ...] = (
    "ACTIVATION_ALLOWED",
    "ActiveVerifierProfileV1",
    "Wave3ActivationConfigV1",
    "COMMITMENT_DOMAIN",
    "DUAL_PQ_SUITES",
    "DualPqAuthorityV1",
    "GovernedRootManifestV1",
    "GovernedRootRecordV1",
    "GovernedRootRegistryV1",
    "MlKem1024Aes256ReferenceV1",
    "MODULE_STATUS",
    "PqAuthorityKeyV1",
    "PqAuthorityRotationV1",
    "PqHsmPort",
    "PqKemPort",
    "PqProviderConformanceV1",
    "PqSignatureEnvelopeV1",
    "PqSignaturePort",
    "PROOF_SUITE_ID",
    "Wave3RecoveryAnchorV1",
    "Wave3BoundaryError",
    "Wave3CommitmentBundleV1",
    "Wave3CustodySnapshotV1",
    "Wave3DurableStateV1",
    "Wave3MigrationRecordV1",
    "Wave3RollbackRecordV1",
    "Wave3StateEnvelopeV1",
    "Wave3StatePayloadV1",
    "Wave3UpgradeRecordV1",
    "Wave3VerifierV1",
    "VerifiedProofContextV1",
    "VerifiedStrongOutputsV1",
    "assess_pq_provider_port",
    "build_wave3_commitments",
    "build_wave3_sidecar",
    "wave3_batch_commitment",
)
