"""Dual-family PQ authority envelope for claim/oracle/policy roots.

The envelope is deliberately outside the arithmetic AIR: the proof binds the
signed roots and envelope digest, while the verifier calls this narrow port.
That keeps government/HSM adapters replaceable without making signature
verification a private witness or cloning a huge signature circuit.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
import hmac
from typing import Final, Protocol, Sequence

from experiments.fixed_shape_claim_air.profile import CalibrationProfile
from experiments.fixed_shape_claim_air.semantics import ClaimSlot

from .claim_source_commitment import build_claim_source_commitments
from .oracle_bundle_commitment import build_oracle_commitments, oracle_bundle_from_slot
from .policy_bundle_commitment import build_policy_commitments
from .ruleset_commitment import ruleset_root

from .pq_signature_adapters import (
    ML_DSA_87_SUITE_ID,
    SPHINCS_SHAKE_256F_SIMPLE_SUITE_ID,
    MlDsa87PqcryptoAdapter,
    SphincsShake256fSimplePqcryptoAdapter,
)


STATUS: Final[str] = "BL_PQ_CLAIM_TRUTH_AUTHORITY_V1_NONACTIVATING"
MESSAGE_MAGIC: Final[bytes] = b"BLPQAUT1"
ENVELOPE_MAGIC: Final[bytes] = b"BLPQENV1"
_PROFILE_CODES: Final[dict[str, int]] = {
    "K128_CALIBRATION": 1,
    "K256_DESIGN_POINT": 2,
    "K512_CALIBRATION": 3,
}
_CODE_PROFILES: Final[dict[int, str]] = {value: key for key, value in _PROFILE_CODES.items()}
ENVELOPE_BYTES: Final[int] = (
    8 + 1 + 8 + 64 + 1 + 64 + 6 * 64 + 64
    + MlDsa87PqcryptoAdapter.signature_size
    + SphincsShake256fSimplePqcryptoAdapter.signature_size
)


class SignatureAdapter(Protocol):
    suite_id: str
    public_key_size: int
    secret_key_size: int
    signature_size: int

    def sign(self, *, secret_key: bytes, message: bytes) -> bytes: ...

    def verify(self, *, public_key: bytes, message: bytes, signature: bytes) -> bool: ...


def _bytes64(label: str, value: object) -> bytes:
    if type(value) is not bytes or len(value) != 64:
        raise ValueError(f"claim_truth_authority_{label}_not_64_bytes")
    return value


def _authority_id(value: object) -> bytes:
    if type(value) is not str:
        raise TypeError("claim_truth_authority_id_not_text")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("claim_truth_authority_id_not_ascii") from exc
    if not 1 <= len(encoded) <= 64:
        raise ValueError("claim_truth_authority_id_length_invalid")
    return encoded


@dataclass(frozen=True, slots=True)
class ClaimTruthRootsV1:
    claim_source_root: bytes
    oracle_execution_root: bytes
    oracle_audit_root: bytes
    policy_execution_root: bytes
    policy_audit_root: bytes
    ruleset_root: bytes

    def __post_init__(self) -> None:
        for name in self.__dataclass_fields__:
            _bytes64(name, getattr(self, name))

    def ordered(self) -> tuple[bytes, ...]:
        return tuple(getattr(self, name) for name in self.__dataclass_fields__)


@dataclass(frozen=True, slots=True)
class ClaimTruthAuthorityRegistryV1:
    profile_id: str
    authority_id: str
    epoch: int
    snapshot_id: bytes
    ml_dsa_87_public_key: bytes
    slh_dsa_shake_256f_public_key: bytes

    def __post_init__(self) -> None:
        if self.profile_id not in _PROFILE_CODES:
            raise ValueError("claim_truth_authority_profile_unknown")
        _authority_id(self.authority_id)
        if type(self.epoch) is not int or not 1 <= self.epoch <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("claim_truth_authority_epoch_invalid")
        _bytes64("snapshot_id", self.snapshot_id)
        if (
            type(self.ml_dsa_87_public_key) is not bytes
            or len(self.ml_dsa_87_public_key) != MlDsa87PqcryptoAdapter.public_key_size
        ):
            raise ValueError("claim_truth_authority_ml_public_key_invalid")
        if (
            type(self.slh_dsa_shake_256f_public_key) is not bytes
            or len(self.slh_dsa_shake_256f_public_key)
            != SphincsShake256fSimplePqcryptoAdapter.public_key_size
        ):
            raise ValueError("claim_truth_authority_slh_public_key_invalid")


@dataclass(frozen=True, slots=True)
class ClaimTruthAuthorityEnvelopeV1:
    profile_id: str
    authority_id: str
    epoch: int
    snapshot_id: bytes
    roots: ClaimTruthRootsV1
    message_digest: bytes
    ml_dsa_87_signature: bytes
    slh_dsa_shake_256f_signature: bytes

    def __post_init__(self) -> None:
        if self.profile_id not in _PROFILE_CODES:
            raise ValueError("claim_truth_envelope_profile_unknown")
        _authority_id(self.authority_id)
        if type(self.epoch) is not int or not 1 <= self.epoch <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("claim_truth_envelope_epoch_invalid")
        _bytes64("snapshot_id", self.snapshot_id)
        if not isinstance(self.roots, ClaimTruthRootsV1):
            raise TypeError("claim_truth_envelope_roots_invalid")
        _bytes64("message_digest", self.message_digest)
        if (
            type(self.ml_dsa_87_signature) is not bytes
            or len(self.ml_dsa_87_signature) != MlDsa87PqcryptoAdapter.signature_size
        ):
            raise ValueError("claim_truth_envelope_ml_signature_invalid")
        if (
            type(self.slh_dsa_shake_256f_signature) is not bytes
            or len(self.slh_dsa_shake_256f_signature)
            != SphincsShake256fSimplePqcryptoAdapter.signature_size
        ):
            raise ValueError("claim_truth_envelope_slh_signature_invalid")


def build_claim_truth_roots(
    profile: CalibrationProfile, slots: Sequence[ClaimSlot]
) -> ClaimTruthRootsV1:
    if not isinstance(profile, CalibrationProfile):
        raise TypeError("claim_truth_roots_profile_required")
    materialized = tuple(slots)
    source = build_claim_source_commitments(profile, materialized)
    oracle = build_oracle_commitments(
        profile,
        tuple(oracle_bundle_from_slot(profile, slot) for slot in materialized),
    )
    policy = build_policy_commitments(profile, materialized)
    return ClaimTruthRootsV1(
        source.root,
        oracle.execution_root,
        oracle.audit_root,
        policy.execution_root,
        policy.audit_root,
        ruleset_root(profile),
    )


def claim_truth_authority_message(
    *,
    profile_id: str,
    authority_id: str,
    epoch: int,
    snapshot_id: bytes,
    roots: ClaimTruthRootsV1,
) -> bytes:
    if profile_id not in _PROFILE_CODES:
        raise ValueError("claim_truth_authority_profile_unknown")
    authority = _authority_id(authority_id)
    if type(epoch) is not int or not 1 <= epoch <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("claim_truth_authority_epoch_invalid")
    snapshot = _bytes64("snapshot_id", snapshot_id)
    if not isinstance(roots, ClaimTruthRootsV1):
        raise TypeError("claim_truth_authority_roots_invalid")
    return b"".join(
        (
            MESSAGE_MAGIC,
            bytes((_PROFILE_CODES[profile_id],)),
            epoch.to_bytes(8, "big"),
            snapshot,
            len(authority).to_bytes(1, "big"),
            authority.ljust(64, b"\x00"),
            *roots.ordered(),
        )
    )


def encode_claim_truth_authority_envelope(
    envelope: ClaimTruthAuthorityEnvelopeV1,
) -> bytes:
    if not isinstance(envelope, ClaimTruthAuthorityEnvelopeV1):
        raise TypeError("claim_truth_authority_envelope_required")
    authority = _authority_id(envelope.authority_id)
    encoded = b"".join(
        (
            ENVELOPE_MAGIC,
            bytes((_PROFILE_CODES[envelope.profile_id],)),
            envelope.epoch.to_bytes(8, "big"),
            envelope.snapshot_id,
            len(authority).to_bytes(1, "big"),
            authority.ljust(64, b"\x00"),
            *envelope.roots.ordered(),
            envelope.message_digest,
            envelope.ml_dsa_87_signature,
            envelope.slh_dsa_shake_256f_signature,
        )
    )
    if len(encoded) != ENVELOPE_BYTES:
        raise AssertionError("claim_truth_authority_envelope_length_changed")
    return encoded


def decode_claim_truth_authority_envelope(
    encoded: bytes,
) -> ClaimTruthAuthorityEnvelopeV1:
    if type(encoded) is not bytes or len(encoded) != ENVELOPE_BYTES:
        raise ValueError("claim_truth_authority_envelope_length_invalid")
    if not encoded.startswith(ENVELOPE_MAGIC):
        raise ValueError("claim_truth_authority_envelope_magic_invalid")
    cursor = len(ENVELOPE_MAGIC)

    def take(count: int) -> bytes:
        nonlocal cursor
        value = encoded[cursor : cursor + count]
        if len(value) != count:
            raise ValueError("claim_truth_authority_envelope_truncated")
        cursor += count
        return value

    profile_code = take(1)[0]
    try:
        profile_id = _CODE_PROFILES[profile_code]
    except KeyError as exc:
        raise ValueError("claim_truth_authority_envelope_profile_invalid") from exc
    epoch = int.from_bytes(take(8), "big")
    snapshot = take(64)
    authority_length = take(1)[0]
    authority_field = take(64)
    if not 1 <= authority_length <= 64 or any(authority_field[authority_length:]):
        raise ValueError("claim_truth_authority_envelope_authority_padding_invalid")
    try:
        authority_id = authority_field[:authority_length].decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("claim_truth_authority_envelope_authority_not_ascii") from exc
    roots = ClaimTruthRootsV1(*(take(64) for _ in range(6)))
    digest = take(64)
    ml_signature = take(MlDsa87PqcryptoAdapter.signature_size)
    slh_signature = take(SphincsShake256fSimplePqcryptoAdapter.signature_size)
    if cursor != len(encoded):
        raise ValueError("claim_truth_authority_envelope_trailing_bytes")
    return ClaimTruthAuthorityEnvelopeV1(
        profile_id,
        authority_id,
        epoch,
        snapshot,
        roots,
        digest,
        ml_signature,
        slh_signature,
    )


def sign_claim_truth_roots(
    registry: ClaimTruthAuthorityRegistryV1,
    roots: ClaimTruthRootsV1,
    *,
    ml_adapter: SignatureAdapter,
    ml_secret_key: bytes,
    slh_adapter: SignatureAdapter,
    slh_secret_key: bytes,
) -> ClaimTruthAuthorityEnvelopeV1:
    if not isinstance(registry, ClaimTruthAuthorityRegistryV1):
        raise TypeError("claim_truth_authority_registry_required")
    if (
        type(ml_adapter) is not MlDsa87PqcryptoAdapter
        or ml_adapter.suite_id != ML_DSA_87_SUITE_ID
        or type(slh_adapter) is not SphincsShake256fSimplePqcryptoAdapter
        or slh_adapter.suite_id != SPHINCS_SHAKE_256F_SIMPLE_SUITE_ID
    ):
        raise TypeError("claim_truth_authority_exact_dual_pq_adapters_required")
    message = claim_truth_authority_message(
        profile_id=registry.profile_id,
        authority_id=registry.authority_id,
        epoch=registry.epoch,
        snapshot_id=registry.snapshot_id,
        roots=roots,
    )
    digest = sha3_512(ENVELOPE_MAGIC + message).digest()
    return ClaimTruthAuthorityEnvelopeV1(
        registry.profile_id,
        registry.authority_id,
        registry.epoch,
        registry.snapshot_id,
        roots,
        digest,
        ml_adapter.sign(secret_key=ml_secret_key, message=message),
        slh_adapter.sign(secret_key=slh_secret_key, message=message),
    )


def verify_claim_truth_authority(
    registry: ClaimTruthAuthorityRegistryV1,
    envelope: ClaimTruthAuthorityEnvelopeV1,
    *,
    ml_adapter: SignatureAdapter,
    slh_adapter: SignatureAdapter,
) -> bool:
    if not isinstance(registry, ClaimTruthAuthorityRegistryV1) or not isinstance(
        envelope, ClaimTruthAuthorityEnvelopeV1
    ):
        return False
    if (
        type(ml_adapter) is not MlDsa87PqcryptoAdapter
        or ml_adapter.suite_id != ML_DSA_87_SUITE_ID
        or type(slh_adapter) is not SphincsShake256fSimplePqcryptoAdapter
        or slh_adapter.suite_id != SPHINCS_SHAKE_256F_SIMPLE_SUITE_ID
    ):
        return False
    if (
        envelope.profile_id != registry.profile_id
        or envelope.authority_id != registry.authority_id
        or envelope.epoch != registry.epoch
        or not hmac.compare_digest(envelope.snapshot_id, registry.snapshot_id)
    ):
        return False
    try:
        message = claim_truth_authority_message(
            profile_id=envelope.profile_id,
            authority_id=envelope.authority_id,
            epoch=envelope.epoch,
            snapshot_id=envelope.snapshot_id,
            roots=envelope.roots,
        )
    except (TypeError, ValueError):
        return False
    expected_digest = sha3_512(ENVELOPE_MAGIC + message).digest()
    return (
        hmac.compare_digest(expected_digest, envelope.message_digest)
        and ml_adapter.verify(
            public_key=registry.ml_dsa_87_public_key,
            message=message,
            signature=envelope.ml_dsa_87_signature,
        )
        and slh_adapter.verify(
            public_key=registry.slh_dsa_shake_256f_public_key,
            message=message,
            signature=envelope.slh_dsa_shake_256f_signature,
        )
    )


__all__ = (
    "ClaimTruthAuthorityEnvelopeV1",
    "ClaimTruthAuthorityRegistryV1",
    "ClaimTruthRootsV1",
    "ENVELOPE_BYTES",
    "build_claim_truth_roots",
    "claim_truth_authority_message",
    "decode_claim_truth_authority_envelope",
    "encode_claim_truth_authority_envelope",
    "sign_claim_truth_roots",
    "verify_claim_truth_authority",
)
