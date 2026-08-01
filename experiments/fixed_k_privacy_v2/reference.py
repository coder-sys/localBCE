"""Fail-closed, synthetic-only reference for a fixed-K private slot schedule.

This module is deliberately isolated from the live batch builder and verifier.  It
does not select K, derive cover nullifiers, authenticate governance, or implement
an AIR.  It only makes the already-selected structural invariants executable:

* exactly K fixed-width private slots;
* an explicit, committed real/cover discriminator;
* inert cover amounts and payloads;
* one nonzero, unique legacy and strong nullifier per slot; and
* preservation of the exact 12-field Privacy V2 external ABI.

The SHA3-512 encoding below is a versioned synthetic reference commitment, not
the unresolved BL-PQ512-v1 production sidecar or proof encoding.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
import hashlib
import hmac
import os
from typing import Sequence

from app.batch.poseidon import FIELD_MODULUS
from app.money import MAX_AMOUNT_CENTS_EXCLUSIVE
from app.privacy_v2 import PRIVACY_V2_PROTOCOL_VERSION, PRIVACY_V2_PUBLIC_OUTPUT_NAMES


SYNTHETIC_REFERENCE_ENABLE_ENV = "BL_ALLOW_SYNTHETIC_FIXED_K_REFERENCE"
_SYNTHETIC_ENVS = {"local", "test", "unit", "ci"}
_MAGIC = b"BLFKREF0"
_SCHEDULE_DOMAIN = b"BL/FIXED-K/SYNTHETIC-REFERENCE/v0/SCHEDULE"
_SLOT_BYTES = 1 + 1 + 4 + 32 + 64 + 64 + 8 + 8
_MAX_PRIVATE_CENTS = MAX_AMOUNT_CENTS_EXCLUSIVE
_ZERO_512 = bytes(64)


class SlotKind(IntEnum):
    COVER = 0
    REAL = 1


def _require_synthetic_reference_enabled() -> None:
    environment = os.environ.get("BL_ENV", "").strip().lower()
    if (
        environment not in _SYNTHETIC_ENVS
        or os.environ.get("BL_DEV") != "1"
        or os.environ.get(SYNTHETIC_REFERENCE_ENABLE_ENV) != "1"
    ):
        raise RuntimeError(
            "synthetic_fixed_k_reference_forbidden:requires_local_test_env_and_explicit_dev_flags"
        )


def _fixed_bytes(name: str, value: object, length: int, *, nonzero: bool = False) -> bytes:
    if not isinstance(value, bytes) or len(value) != length:
        raise ValueError(f"fixed_k_{name}_must_be_{length}_bytes")
    if nonzero and not any(value):
        raise ValueError(f"fixed_k_{name}_must_be_nonzero")
    return value


def _felt(name: str, value: object, *, nonzero: bool = False) -> int:
    if type(value) is not int:
        raise ValueError(f"fixed_k_{name}_not_canonical_felt")
    integer = value
    if integer < 0 or integer >= FIELD_MODULUS:
        raise ValueError(f"fixed_k_{name}_not_canonical_felt")
    if nonzero and integer == 0:
        raise ValueError(f"fixed_k_{name}_must_be_nonzero")
    return integer


def _u32(name: str, value: object) -> int:
    if type(value) is not int:
        raise ValueError(f"fixed_k_{name}_not_u32")
    integer = value
    if integer < 0 or integer >= 1 << 32:
        raise ValueError(f"fixed_k_{name}_not_u32")
    return integer


def _cents(name: str, value: object) -> int:
    if type(value) is not int:
        raise ValueError(f"fixed_k_{name}_out_of_range")
    integer = value
    if integer < 0 or integer >= _MAX_PRIVATE_CENTS:
        raise ValueError(f"fixed_k_{name}_out_of_range")
    return integer


@dataclass(frozen=True)
class FixedKPrivateSlot:
    """One fixed-width private slot.  Never serialize this object publicly."""

    kind: SlotKind
    approved: bool
    slot_index: int
    legacy_nullifier: int
    strong_nullifier: bytes
    private_claim_commitment: bytes
    allowed_cents: int
    payment_cents: int

    def __post_init__(self) -> None:
        if type(self.kind) is not SlotKind:
            raise ValueError("fixed_k_slot_kind_invalid")
        kind = self.kind
        if not isinstance(self.approved, bool):
            raise ValueError("fixed_k_slot_approved_not_bool")
        _u32("slot_index", self.slot_index)
        _felt("legacy_nullifier", self.legacy_nullifier, nonzero=True)
        _fixed_bytes("strong_nullifier", self.strong_nullifier, 64, nonzero=True)
        _fixed_bytes("private_claim_commitment", self.private_claim_commitment, 64)
        allowed = _cents("allowed_cents", self.allowed_cents)
        payment = _cents("payment_cents", self.payment_cents)

        if kind is SlotKind.COVER:
            if self.approved or self.private_claim_commitment != _ZERO_512 or allowed != 0 or payment != 0:
                raise ValueError("fixed_k_cover_slot_not_inert")
        else:
            if self.private_claim_commitment == _ZERO_512:
                raise ValueError("fixed_k_real_slot_missing_claim_commitment")
            if self.approved:
                if allowed == 0 or payment != allowed:
                    raise ValueError("fixed_k_approved_value_mismatch")
            elif payment != 0:
                raise ValueError("fixed_k_denied_slot_has_payment")

    def to_private_bytes(self) -> bytes:
        _require_synthetic_reference_enabled()
        encoded = b"".join(
            (
                int(SlotKind(self.kind)).to_bytes(1, "big"),
                int(self.approved).to_bytes(1, "big"),
                _u32("slot_index", self.slot_index).to_bytes(4, "big"),
                _felt("legacy_nullifier", self.legacy_nullifier, nonzero=True).to_bytes(32, "big"),
                _fixed_bytes("strong_nullifier", self.strong_nullifier, 64, nonzero=True),
                _fixed_bytes("private_claim_commitment", self.private_claim_commitment, 64),
                _cents("allowed_cents", self.allowed_cents).to_bytes(8, "big"),
                _cents("payment_cents", self.payment_cents).to_bytes(8, "big"),
            )
        )
        if len(encoded) != _SLOT_BYTES:
            raise AssertionError("fixed_k_internal_slot_width_mismatch")
        return encoded


@dataclass(frozen=True)
class SyntheticFixedKSchedule:
    """A private reference witness whose byte length depends only on reviewed K."""

    reviewed_fixed_k: int
    reviewed_profile_digest: bytes
    settlement_domain: int
    batch_nonce: int
    fresh_private_salt: bytes
    slots: tuple[FixedKPrivateSlot, ...]
    public_fields: tuple[int, ...]

    def __post_init__(self) -> None:
        _require_synthetic_reference_enabled()
        fixed_k = _u32("reviewed_fixed_k", self.reviewed_fixed_k)
        if fixed_k == 0:
            raise ValueError("fixed_k_reviewed_fixed_k_must_be_positive")
        _fixed_bytes("reviewed_profile_digest", self.reviewed_profile_digest, 64, nonzero=True)
        _felt("settlement_domain", self.settlement_domain, nonzero=True)
        _felt("batch_nonce", self.batch_nonce, nonzero=True)
        _fixed_bytes("fresh_private_salt", self.fresh_private_salt, 64, nonzero=True)
        canonical_public_fields = validate_privacy_v2_public_fields(self.public_fields)
        if canonical_public_fields[1] != self.settlement_domain:
            raise ValueError("fixed_k_public_settlement_domain_mismatch")
        if canonical_public_fields[2] != self.batch_nonce:
            raise ValueError("fixed_k_public_batch_nonce_mismatch")
        slots = tuple(self.slots)
        object.__setattr__(self, "slots", slots)
        object.__setattr__(self, "public_fields", canonical_public_fields)
        if len(slots) != fixed_k:
            raise ValueError("fixed_k_slot_count_mismatch")

        legacy_nullifiers: set[int] = set()
        strong_nullifiers: set[bytes] = set()
        for expected_index, slot in enumerate(slots):
            if not isinstance(slot, FixedKPrivateSlot):
                raise ValueError("fixed_k_slot_type_invalid")
            if slot.slot_index != expected_index:
                raise ValueError("fixed_k_slot_index_mismatch")
            if slot.legacy_nullifier in legacy_nullifiers:
                raise ValueError("fixed_k_duplicate_legacy_nullifier")
            if slot.strong_nullifier in strong_nullifiers:
                raise ValueError("fixed_k_duplicate_strong_nullifier")
            legacy_nullifiers.add(slot.legacy_nullifier)
            strong_nullifiers.add(slot.strong_nullifier)

    def to_private_bytes(self) -> bytes:
        _require_synthetic_reference_enabled()
        public_statement = b"".join(
            _felt(f"public_field_{index}", value).to_bytes(32, "big")
            for index, value in enumerate(self.public_fields)
        )
        header = b"".join(
            (
                _MAGIC,
                _fixed_bytes("reviewed_profile_digest", self.reviewed_profile_digest, 64, nonzero=True),
                _u32("reviewed_fixed_k", self.reviewed_fixed_k).to_bytes(4, "big"),
                _felt("settlement_domain", self.settlement_domain, nonzero=True).to_bytes(32, "big"),
                _felt("batch_nonce", self.batch_nonce, nonzero=True).to_bytes(32, "big"),
                public_statement,
                _fixed_bytes("fresh_private_salt", self.fresh_private_salt, 64, nonzero=True),
            )
        )
        encoded = header + b"".join(slot.to_private_bytes() for slot in self.slots)
        expected_length = len(header) + self.reviewed_fixed_k * _SLOT_BYTES
        if len(encoded) != expected_length:
            raise AssertionError("fixed_k_internal_schedule_width_mismatch")
        return encoded

    def reference_commitment(self) -> bytes:
        _require_synthetic_reference_enabled()
        return hashlib.sha3_512(_SCHEDULE_DOMAIN + self.to_private_bytes()).digest()


def validate_privacy_v2_public_fields(public_fields: Sequence[object]) -> tuple[int, ...]:
    if len(PRIVACY_V2_PUBLIC_OUTPUT_NAMES) != 12:
        raise AssertionError("fixed_k_privacy_v2_abi_definition_changed")
    if len(public_fields) != 12:
        raise ValueError("fixed_k_privacy_v2_public_field_count_mismatch")
    canonical = tuple(_felt(f"public_field_{index}", value) for index, value in enumerate(public_fields))
    if canonical[0] != PRIVACY_V2_PROTOCOL_VERSION:
        raise ValueError("fixed_k_privacy_v2_protocol_version_mismatch")
    return canonical


def build_synthetic_fixed_k_schedule(
    *,
    reviewed_fixed_k: int,
    reviewed_profile_digest: bytes,
    settlement_domain: int,
    batch_nonce: int,
    fresh_private_salt: bytes,
    slots: Sequence[FixedKPrivateSlot],
    public_fields: Sequence[object],
) -> SyntheticFixedKSchedule:
    """Build a guarded reference schedule from already-derived slot nullifiers."""

    return SyntheticFixedKSchedule(
        reviewed_fixed_k=reviewed_fixed_k,
        reviewed_profile_digest=reviewed_profile_digest,
        settlement_domain=settlement_domain,
        batch_nonce=batch_nonce,
        fresh_private_salt=fresh_private_salt,
        slots=tuple(slots),
        public_fields=validate_privacy_v2_public_fields(public_fields),
    )


def verify_synthetic_fixed_k_schedule(
    schedule: SyntheticFixedKSchedule,
    authenticated_reference_commitment: bytes,
) -> bool:
    """Compare the complete private schedule with a separately authenticated digest."""

    _require_synthetic_reference_enabled()
    expected = _fixed_bytes(
        "authenticated_reference_commitment",
        authenticated_reference_commitment,
        64,
        nonzero=True,
    )
    if not hmac.compare_digest(schedule.reference_commitment(), expected):
        raise ValueError("fixed_k_authenticated_reference_commitment_mismatch")
    return True
