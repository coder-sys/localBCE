"""Exact A12 application nullifier derivation for the BL-PQ512 successor relation.

This module freezes replay identity and byte framing.  It does not implement a
proof-system hash, AIR constraints, durable state, or production activation.
The legacy Poseidon value and the strong SHA3-512 value are independently
derived from the same canonical preimage; neither is derived from the other.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha3_512
import hmac
import re
from typing import Final

from app.batch.poseidon import FIELD_MODULUS, domain_poseidon_hash


ENCODING_MAGIC: Final[bytes] = b"BLPQNF01"
ENCODING_VERSION: Final[int] = 1
ENCODING_MAGIC_V2: Final[bytes] = b"BLPQNF02"
ENCODING_VERSION_V2: Final[int] = 2
ATTEMPT_DOMAIN_CODE: Final[int] = 257
COVER_DOMAIN_CODE: Final[int] = 258
COVER_DOMAIN_CODE_V2: Final[int] = 514
PEPPER_COMMITMENT_MAGIC: Final[bytes] = b"BLPQPEP1"
PEPPER_COMMITMENT_VERSION: Final[int] = 1
PEPPER_BYTES: Final[int] = 64
COVER_NONCE_BYTES: Final[int] = 64
STRONG_DOMAIN_BYTES: Final[int] = 64
STRONG_NONCE_BYTES: Final[int] = 64
AUTHORITY_ID_BYTES: Final[int] = 64
MAX_SLOT_INDEX: Final[int] = 511
MAX_NULLIFIER: Final[int] = FIELD_MODULUS - 1
REFERENCE_STATUS: Final[str] = (
    "A12_DERIVATION_FROZEN_APPLICATION_REFERENCE_NOT_AIR_NOT_PRODUCTION"
)

REVISION_KIND_ORIGINAL: Final[int] = 1
REVISION_KIND_CORRECTION: Final[int] = 2
REVISION_KIND_REPLACEMENT: Final[int] = 3
REVISION_KIND_VOID: Final[int] = 4
_REVISION_KINDS: Final[frozenset[int]] = frozenset(
    {
        REVISION_KIND_ORIGINAL,
        REVISION_KIND_CORRECTION,
        REVISION_KIND_REPLACEMENT,
        REVISION_KIND_VOID,
    }
)
_TOKEN: Final[re.Pattern[str]] = re.compile(r"[A-Z0-9][A-Z0-9-]{0,63}\Z")
_UINT32_MAX: Final[int] = (1 << 32) - 1
_UINT64_MAX: Final[int] = (1 << 64) - 1


def _exact_bytes(label: str, value: object, length: int, *, nonzero: bool = True) -> bytes:
    if type(value) is not bytes or len(value) != length:
        raise ValueError(f"a12_{label}_must_be_{length}_bytes")
    if nonzero and not any(value):
        raise ValueError(f"a12_{label}_must_be_nonzero")
    return value


def _uint(label: str, value: object, maximum: int, *, nonzero: bool = False) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError(f"a12_{label}_out_of_range")
    if nonzero and value == 0:
        raise ValueError(f"a12_{label}_must_be_nonzero")
    return value


def _token(label: str, value: object) -> bytes:
    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        raise ValueError(f"a12_{label}_not_canonical_token")
    return value.encode("ascii")


def _profile(value: object) -> bytes:
    if type(value) is not str:
        raise ValueError("a12_profile_id_not_text")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("a12_profile_id_not_ascii") from exc
    if not encoded or len(encoded) > 0xFFFF:
        raise ValueError("a12_profile_id_length_invalid")
    return encoded


def _lp16(value: bytes) -> bytes:
    if len(value) > 0xFFFF:
        raise ValueError("a12_length_prefix_overflow")
    return len(value).to_bytes(2, "big") + value


def _header(domain_code: int, body: bytes) -> bytes:
    total_length = len(ENCODING_MAGIC) + 2 + 2 + 4 + len(body)
    return b"".join(
        (
            ENCODING_MAGIC,
            ENCODING_VERSION.to_bytes(2, "big"),
            domain_code.to_bytes(2, "big"),
            total_length.to_bytes(4, "big"),
            body,
        )
    )


def _header_v2(domain_code: int, body: bytes) -> bytes:
    total_length = len(ENCODING_MAGIC_V2) + 2 + 2 + 4 + len(body)
    return b"".join(
        (
            ENCODING_MAGIC_V2,
            ENCODING_VERSION_V2.to_bytes(2, "big"),
            domain_code.to_bytes(2, "big"),
            total_length.to_bytes(4, "big"),
            body,
        )
    )


def pepper_commitment_sha3_512(pepper_512: bytes) -> bytes:
    """Commit to the registry-lifetime replay pepper without exposing it."""

    pepper = _exact_bytes("replay_pepper", pepper_512, PEPPER_BYTES)
    return sha3_512(
        PEPPER_COMMITMENT_MAGIC
        + PEPPER_COMMITMENT_VERSION.to_bytes(2, "big")
        + PEPPER_BYTES.to_bytes(2, "big")
        + pepper
    ).digest()


@dataclass(frozen=True, slots=True)
class AttemptReplayIdentityV1:
    """Stable authority-issued identity for exactly one real attempt.

    Mutable claim content and execution context are intentionally absent.  The
    same governed attempt therefore keeps one replay key across retries,
    batches, decisions, policy/oracle changes, and proof rerandomization.
    """

    source_authority_id: str
    source_claim_id: str
    attempt_version: int
    revision_kind: int
    parent_attempt_version: int

    def __post_init__(self) -> None:
        _token("source_authority_id", self.source_authority_id)
        _token("source_claim_id", self.source_claim_id)
        version = _uint("attempt_version", self.attempt_version, _UINT32_MAX, nonzero=True)
        parent = _uint("parent_attempt_version", self.parent_attempt_version, _UINT32_MAX)
        kind = _uint("revision_kind", self.revision_kind, 0xFF, nonzero=True)
        if kind not in _REVISION_KINDS:
            raise ValueError("a12_revision_kind_invalid")
        if kind == REVISION_KIND_ORIGINAL:
            if version != 1 or parent != 0:
                raise ValueError("a12_original_lifecycle_invalid")
        elif version <= 1 or parent != version - 1:
            raise ValueError("a12_revision_lifecycle_invalid")

    def require_bl_pq512_v1(self) -> None:
        if (
            self.attempt_version != 1
            or self.revision_kind != REVISION_KIND_ORIGINAL
            or self.parent_attempt_version != 0
        ):
            raise ValueError("a12_revision_not_authorized")


@dataclass(frozen=True, slots=True)
class NullifierDerivationAuthorityV1:
    """Authenticated secret authority for one complete replay registry lifetime.

    Changing this pepper without an atomic full-registry rekey would change
    every real-attempt key and is therefore forbidden by the A12 lifecycle.
    """

    authority_id_512: bytes
    pepper_commitment_512: bytes
    pepper_512: bytes = field(repr=False)

    def __post_init__(self) -> None:
        _exact_bytes("authority_id", self.authority_id_512, AUTHORITY_ID_BYTES)
        commitment = _exact_bytes(
            "pepper_commitment", self.pepper_commitment_512, PEPPER_BYTES
        )
        pepper = _exact_bytes("replay_pepper", self.pepper_512, PEPPER_BYTES)
        if not hmac.compare_digest(commitment, pepper_commitment_sha3_512(pepper)):
            raise ValueError("a12_pepper_commitment_mismatch")

    @classmethod
    def from_secret(
        cls,
        authority_id_512: bytes,
        pepper_512: bytes,
    ) -> "NullifierDerivationAuthorityV1":
        pepper = _exact_bytes("replay_pepper", pepper_512, PEPPER_BYTES)
        return cls(
            authority_id_512,
            pepper_commitment_sha3_512(pepper),
            pepper,
        )


@dataclass(frozen=True, slots=True)
class ReplayRegistryAuthorityBindingV1:
    """Public authority binding persisted with one replay-registry generation.

    A batch may use an authority only when it matches this authenticated
    registry binding.  Changing either field is a registry migration, not a
    batch-level key rotation; A12-v1 deliberately provides no implicit or
    partial migration path.
    """

    authority_id_512: bytes
    pepper_commitment_512: bytes

    def __post_init__(self) -> None:
        _exact_bytes("registry_authority_id", self.authority_id_512, AUTHORITY_ID_BYTES)
        _exact_bytes(
            "registry_pepper_commitment",
            self.pepper_commitment_512,
            PEPPER_BYTES,
        )

    @classmethod
    def from_authority(
        cls,
        authority: NullifierDerivationAuthorityV1,
    ) -> "ReplayRegistryAuthorityBindingV1":
        if not isinstance(authority, NullifierDerivationAuthorityV1):
            raise TypeError("a12_nullifier_authority_required")
        return cls(authority.authority_id_512, authority.pepper_commitment_512)

    def require_current_authority(
        self,
        authority: NullifierDerivationAuthorityV1,
    ) -> None:
        if not isinstance(authority, NullifierDerivationAuthorityV1):
            raise TypeError("a12_nullifier_authority_required")
        if not hmac.compare_digest(self.authority_id_512, authority.authority_id_512):
            raise ValueError("a12_registry_authority_rotation_requires_atomic_migration")
        if not hmac.compare_digest(
            self.pepper_commitment_512,
            authority.pepper_commitment_512,
        ):
            raise ValueError("a12_registry_pepper_rotation_requires_atomic_migration")


@dataclass(frozen=True, slots=True)
class CoverReplayContextV1:
    profile_id: str
    strong_settlement_domain_id_512: bytes
    epoch: int
    batch_nonce_felt: int
    slot_index: int

    def __post_init__(self) -> None:
        _profile(self.profile_id)
        _exact_bytes(
            "strong_settlement_domain_id",
            self.strong_settlement_domain_id_512,
            STRONG_DOMAIN_BYTES,
        )
        _uint("epoch", self.epoch, _UINT64_MAX, nonzero=True)
        _uint("batch_nonce_felt", self.batch_nonce_felt, FIELD_MODULUS - 1, nonzero=True)
        _uint("slot_index", self.slot_index, MAX_SLOT_INDEX)


@dataclass(frozen=True, slots=True)
class CoverReplayContextV2:
    """Cover uniqueness context with full post-quantum batch entropy."""

    profile_id: str
    strong_settlement_domain_id_512: bytes
    epoch: int
    strong_batch_nonce_512: bytes
    slot_index: int

    def __post_init__(self) -> None:
        _profile(self.profile_id)
        _exact_bytes(
            "strong_settlement_domain_id",
            self.strong_settlement_domain_id_512,
            STRONG_DOMAIN_BYTES,
        )
        _uint("epoch", self.epoch, _UINT64_MAX, nonzero=True)
        _exact_bytes(
            "strong_batch_nonce",
            self.strong_batch_nonce_512,
            STRONG_NONCE_BYTES,
        )
        _uint("slot_index", self.slot_index, MAX_SLOT_INDEX)


@dataclass(frozen=True, slots=True)
class DerivedNullifierV1:
    kind: str
    canonical_preimage: bytes = field(repr=False)
    legacy_felt: int
    strong_sha3_512: bytes = field(repr=False)
    status: str = REFERENCE_STATUS

    def __post_init__(self) -> None:
        if self.kind not in {"ATTEMPT", "COVER"}:
            raise ValueError("a12_derived_kind_invalid")
        if type(self.canonical_preimage) is not bytes or not self.canonical_preimage:
            raise ValueError("a12_derived_preimage_invalid")
        if type(self.legacy_felt) is not int or not 0 < self.legacy_felt < MAX_NULLIFIER:
            raise ValueError("a12_derived_legacy_reserved")
        _exact_bytes("derived_strong", self.strong_sha3_512, 64)
        if self.status != REFERENCE_STATUS:
            raise ValueError("a12_derived_status_invalid")


def encode_attempt_preimage_v1(
    identity: AttemptReplayIdentityV1,
    authority: NullifierDerivationAuthorityV1,
) -> bytes:
    if not isinstance(identity, AttemptReplayIdentityV1):
        raise TypeError("a12_attempt_identity_required")
    if not isinstance(authority, NullifierDerivationAuthorityV1):
        raise TypeError("a12_nullifier_authority_required")
    identity.require_bl_pq512_v1()
    body = b"".join(
        (
            _lp16(_token("source_authority_id", identity.source_authority_id)),
            _lp16(_token("source_claim_id", identity.source_claim_id)),
            identity.attempt_version.to_bytes(4, "big"),
            identity.revision_kind.to_bytes(1, "big"),
            identity.parent_attempt_version.to_bytes(4, "big"),
            PEPPER_BYTES.to_bytes(2, "big"),
            authority.pepper_512,
        )
    )
    return _header(ATTEMPT_DOMAIN_CODE, body)


def encode_cover_preimage_v1(
    context: CoverReplayContextV1,
    private_cover_nonce_512: bytes,
) -> bytes:
    if not isinstance(context, CoverReplayContextV1):
        raise TypeError("a12_cover_context_required")
    nonce = _exact_bytes("private_cover_nonce", private_cover_nonce_512, COVER_NONCE_BYTES)
    body = b"".join(
        (
            _lp16(_profile(context.profile_id)),
            context.strong_settlement_domain_id_512,
            context.epoch.to_bytes(8, "big"),
            context.batch_nonce_felt.to_bytes(32, "big"),
            context.slot_index.to_bytes(2, "big"),
            COVER_NONCE_BYTES.to_bytes(2, "big"),
            nonce,
        )
    )
    return _header(COVER_DOMAIN_CODE, body)


def encode_cover_preimage_v2(
    context: CoverReplayContextV2,
    private_cover_nonce_512: bytes,
) -> bytes:
    if not isinstance(context, CoverReplayContextV2):
        raise TypeError("a12_cover_context_v2_required")
    nonce = _exact_bytes("private_cover_nonce", private_cover_nonce_512, COVER_NONCE_BYTES)
    body = b"".join(
        (
            _lp16(_profile(context.profile_id)),
            context.strong_settlement_domain_id_512,
            context.epoch.to_bytes(8, "big"),
            context.strong_batch_nonce_512,
            context.slot_index.to_bytes(2, "big"),
            COVER_NONCE_BYTES.to_bytes(2, "big"),
            nonce,
        )
    )
    return _header_v2(COVER_DOMAIN_CODE_V2, body)


def _legacy_felt_from_preimage(
    preimage: bytes,
    *,
    domain_code: int,
    encoding_version: int = ENCODING_VERSION,
) -> int:
    if type(preimage) is not bytes or not preimage:
        raise ValueError("a12_legacy_preimage_invalid")
    chunks = tuple(
        int.from_bytes(preimage[offset : offset + 30], "big")
        for offset in range(0, len(preimage), 30)
    )
    accumulator = domain_poseidon_hash(
        "nullifier",
        [encoding_version, domain_code, len(preimage), len(chunks)],
    )
    for index, chunk in enumerate(chunks):
        accumulator = domain_poseidon_hash(
            "nullifier",
            [
                encoding_version,
                domain_code,
                len(preimage),
                len(chunks),
                index,
                accumulator,
                chunk,
            ],
        )
    if not 0 < accumulator < MAX_NULLIFIER:
        raise ValueError("a12_legacy_nullifier_reserved")
    return accumulator


def derive_attempt_nullifiers_v1(
    identity: AttemptReplayIdentityV1,
    authority: NullifierDerivationAuthorityV1,
) -> DerivedNullifierV1:
    preimage = encode_attempt_preimage_v1(identity, authority)
    return DerivedNullifierV1(
        "ATTEMPT",
        preimage,
        _legacy_felt_from_preimage(preimage, domain_code=ATTEMPT_DOMAIN_CODE),
        sha3_512(preimage).digest(),
    )


def derive_cover_nullifiers_v1(
    context: CoverReplayContextV1,
    private_cover_nonce_512: bytes,
) -> DerivedNullifierV1:
    preimage = encode_cover_preimage_v1(context, private_cover_nonce_512)
    return DerivedNullifierV1(
        "COVER",
        preimage,
        _legacy_felt_from_preimage(preimage, domain_code=COVER_DOMAIN_CODE),
        sha3_512(preimage).digest(),
    )


def derive_cover_nullifiers_v2(
    context: CoverReplayContextV2,
    private_cover_nonce_512: bytes,
) -> DerivedNullifierV1:
    preimage = encode_cover_preimage_v2(context, private_cover_nonce_512)
    return DerivedNullifierV1(
        "COVER",
        preimage,
        _legacy_felt_from_preimage(
            preimage,
            domain_code=COVER_DOMAIN_CODE_V2,
            encoding_version=ENCODING_VERSION_V2,
        ),
        sha3_512(preimage).digest(),
    )
