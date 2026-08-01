"""Synthetic-only BL-PQ512 state-transition reference primitives.

This module is intentionally isolated from live settlement.  It demonstrates
canonical SHA3-512 encodings, full-width nullifier state, and atomic transition
checks without changing the external Privacy V2 ``bytes32[12]`` ABI.  Its
434-byte legacy internal state record is not the frozen 744-byte candidate
proof sidecar and must never be accepted as one.

It is not a production verifier, proof transcript, governed-root registry,
durable database transaction, or independently reviewed tree construction.
Real PHI and production settlement are forbidden.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha3_512
import os
import re
import threading
from typing import Final, Iterable, Sequence

from app.batch.poseidon import FIELD_MODULUS


PROFILE_ID: Final[bytes] = b"BL-PQ512-v1"
REFERENCE_SCHEMA_ID: Final[bytes] = b"BL-PQ512-REFERENCE-STATE-v1"
REFERENCE_ONLY_STATUS: Final[str] = "SYNTHETIC_REFERENCE_NOT_PRODUCTION"
SYNTHETIC_REFERENCE_ENABLE_ENV: Final[str] = "BL_ALLOW_SYNTHETIC_PQ_STATE_REFERENCE"
LEGACY_PUBLIC_FIELD_COUNT: Final[int] = 12
PRIVACY_V2_PROTOCOL_VERSION: Final[int] = 2
WIDE_LIMB_BYTES: Final[int] = 32
WIDE_DIGEST_BYTES: Final[int] = 64
RAW_PRIVACY_SALT_BYTES: Final[int] = 64

_UINT32_MAX: Final[int] = (1 << 32) - 1
_UINT64_MAX: Final[int] = (1 << 64) - 1
_CANONICAL_MAGIC: Final[bytes] = b"BL/PQ512/CANONICAL/REFERENCE/v1"
# Historical bytes are frozen by the 434-byte KAT; the identifier is corrected
# so this record cannot be mistaken for the sole 744-byte candidate sidecar.
_LEGACY_INTERNAL_STATE_RECORD_MAGIC: Final[bytes] = b"BLPQ512-SIDECAR-REFERENCE-v1"
_LABEL_PATTERN: Final[re.Pattern[str]] = re.compile(r"[a-z][a-z0-9_.-]{0,127}\Z")
_SYNTHETIC_ENVS: Final[frozenset[str]] = frozenset({"local", "test", "unit", "ci"})

_RAW_RECORD_DOMAIN: Final[bytes] = b"BL/PQ512/RAW-RECORD/REFERENCE/v1"
_ATTEMPT_NULLIFIER_DOMAIN: Final[bytes] = b"BL/PQ512/ATTEMPT-NULLIFIER/REFERENCE/v1"
_NULLIFIER_EMPTY_DOMAIN: Final[bytes] = b"BL/PQ512/NULLIFIER-TREE/EMPTY/REFERENCE/v1"
_NULLIFIER_LEAF_DOMAIN: Final[bytes] = b"BL/PQ512/NULLIFIER-TREE/LEAF/REFERENCE/v1"
_NULLIFIER_NODE_DOMAIN: Final[bytes] = b"BL/PQ512/NULLIFIER-TREE/NODE/REFERENCE/v1"
_NULLIFIER_ROOT_DOMAIN: Final[bytes] = b"BL/PQ512/NULLIFIER-TREE/ROOT/REFERENCE/v1"
_BATCH_DOMAIN: Final[bytes] = b"BL/BATCH/PQ512/REFERENCE/v1"
_SALT_TAG_DOMAIN: Final[bytes] = b"BL/PQ512/PRIVACY-SALT-TAG/REFERENCE/v1"
_REGISTRY_INIT_DOMAIN: Final[bytes] = b"BL/PQ512/REGISTRY/INIT/REFERENCE/v1"
_REGISTRY_STEP_DOMAIN: Final[bytes] = b"BL/PQ512/REGISTRY/STEP/REFERENCE/v1"
_REGISTRY_ROOT_DOMAIN: Final[bytes] = b"BL/PQ512/REGISTRY/ROOT/REFERENCE/v1"
_STATE_DOMAIN: Final[bytes] = b"BL/PQ512/AUTHORITATIVE-STATE/REFERENCE/v1"


def _require_synthetic_reference_enabled() -> None:
    environment = os.environ.get("BL_ENV", "").strip().lower()
    if (
        environment not in _SYNTHETIC_ENVS
        or os.environ.get("BL_DEV") != "1"
        or os.environ.get(SYNTHETIC_REFERENCE_ENABLE_ENV) != "1"
    ):
        raise RuntimeError(
            "synthetic_pq_state_reference_forbidden:requires_local_test_env_and_explicit_dev_flags"
        )


def _require_bytes(label: str, value: object, *, exact_length: int | None = None) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError(f"{label}_must_be_bytes")
    if exact_length is not None and len(value) != exact_length:
        raise ValueError(f"{label}_length_invalid")
    return value


def _require_uint(label: str, value: object, *, bits: int, nonzero: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{label}_must_be_integer")
    upper = 1 << bits
    if value < 0 or value >= upper or (nonzero and value == 0):
        raise ValueError(f"{label}_out_of_range")
    return value


def _label_bytes(label: str) -> bytes:
    if not isinstance(label, str) or _LABEL_PATTERN.fullmatch(label) is None:
        raise ValueError("canonical_label_invalid")
    return label.encode("ascii")


def _canonical_felt_bytes(label: str, value: object, *, nonzero: bool = False) -> bytes:
    raw = _require_bytes(label, value, exact_length=32)
    integer = int.from_bytes(raw, "big")
    if integer >= FIELD_MODULUS or (nonzero and integer == 0):
        raise ValueError(f"{label}_not_canonical_stark_field")
    return raw


@dataclass(frozen=True, slots=True)
class WideDigest:
    """One SHA3-512 value represented as two explicit, unreduced limbs."""

    high_256: bytes
    low_256: bytes

    def __post_init__(self) -> None:
        _require_synthetic_reference_enabled()
        _require_bytes("wide_digest_high_256", self.high_256, exact_length=WIDE_LIMB_BYTES)
        _require_bytes("wide_digest_low_256", self.low_256, exact_length=WIDE_LIMB_BYTES)

    @classmethod
    def from_bytes(cls, value: bytes) -> "WideDigest":
        _require_synthetic_reference_enabled()
        raw = _require_bytes("wide_digest", value, exact_length=WIDE_DIGEST_BYTES)
        return cls(raw[:WIDE_LIMB_BYTES], raw[WIDE_LIMB_BYTES:])

    @classmethod
    def from_hex(cls, value: str) -> "WideDigest":
        _require_synthetic_reference_enabled()
        if not isinstance(value, str) or len(value) != WIDE_DIGEST_BYTES * 2:
            raise ValueError("wide_digest_hex_length_invalid")
        try:
            raw = bytes.fromhex(value)
        except ValueError as exc:
            raise ValueError("wide_digest_hex_invalid") from exc
        if value != value.lower():
            raise ValueError("wide_digest_hex_not_canonical_lowercase")
        return cls.from_bytes(raw)

    def to_bytes(self) -> bytes:
        _require_synthetic_reference_enabled()
        return self.high_256 + self.low_256

    def to_hex(self) -> str:
        _require_synthetic_reference_enabled()
        return self.to_bytes().hex()

    @property
    def limbs(self) -> tuple[bytes, bytes]:
        _require_synthetic_reference_enabled()
        return self.high_256, self.low_256

    @property
    def is_zero(self) -> bool:
        _require_synthetic_reference_enabled()
        return self.high_256 == bytes(WIDE_LIMB_BYTES) and self.low_256 == bytes(WIDE_LIMB_BYTES)


CanonicalField = tuple[str, bytes, bytes]


def _canonical_field(label: str, type_tag: bytes, payload: bytes) -> CanonicalField:
    _label_bytes(label)
    tag = _require_bytes("canonical_type_tag", type_tag, exact_length=1)
    raw = _require_bytes("canonical_payload", payload)
    if len(raw) > _UINT32_MAX:
        raise ValueError("canonical_payload_too_long")
    return label, tag, raw


def _bytes_field(label: str, value: bytes) -> CanonicalField:
    return _canonical_field(label, b"b", _require_bytes(label, value))


def _ascii_field(label: str, value: bytes) -> CanonicalField:
    raw = _require_bytes(label, value)
    try:
        raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label}_must_be_ascii") from exc
    return _canonical_field(label, b"a", raw)


def _u32_field(label: str, value: int) -> CanonicalField:
    return _canonical_field(label, b"4", _require_uint(label, value, bits=32).to_bytes(4, "big"))


def _u64_field(label: str, value: int) -> CanonicalField:
    return _canonical_field(label, b"8", _require_uint(label, value, bits=64).to_bytes(8, "big"))


def _wide_fields(label: str, value: WideDigest) -> tuple[CanonicalField, CanonicalField]:
    if not isinstance(value, WideDigest):
        raise TypeError(f"{label}_must_be_wide_digest")
    return (
        _canonical_field(f"{label}.high256", b"h", value.high_256),
        _canonical_field(f"{label}.low256", b"l", value.low_256),
    )


def _canonical_record(domain: bytes, fields: Sequence[CanonicalField]) -> bytes:
    domain_bytes = _require_bytes("canonical_domain", domain)
    if not domain_bytes or len(domain_bytes) > 0xFFFF:
        raise ValueError("canonical_domain_length_invalid")
    if len(fields) > 0xFFFF:
        raise ValueError("canonical_field_count_invalid")
    out = bytearray(_CANONICAL_MAGIC)
    out.extend(len(domain_bytes).to_bytes(2, "big"))
    out.extend(domain_bytes)
    out.extend(len(fields).to_bytes(2, "big"))
    seen_labels: set[str] = set()
    for label, type_tag, payload in fields:
        if label in seen_labels:
            raise ValueError("canonical_field_label_duplicate")
        seen_labels.add(label)
        label_raw = _label_bytes(label)
        out.extend(len(label_raw).to_bytes(2, "big"))
        out.extend(label_raw)
        out.extend(_require_bytes("canonical_type_tag", type_tag, exact_length=1))
        out.extend(len(payload).to_bytes(4, "big"))
        out.extend(payload)
    return bytes(out)


def _decode_canonical_record(encoded: bytes, *, expected_domain: bytes) -> tuple[CanonicalField, ...]:
    raw = _require_bytes("canonical_record", encoded)
    cursor = 0

    def take(length: int, label: str) -> bytes:
        nonlocal cursor
        end = cursor + length
        if end > len(raw):
            raise ValueError(f"canonical_record_{label}_truncated")
        value = raw[cursor:end]
        cursor = end
        return value

    if take(len(_CANONICAL_MAGIC), "magic") != _CANONICAL_MAGIC:
        raise ValueError("canonical_record_magic_mismatch")
    domain_length = int.from_bytes(take(2, "domain_length"), "big")
    domain = take(domain_length, "domain")
    if domain != expected_domain:
        raise ValueError("canonical_record_domain_mismatch")
    field_count = int.from_bytes(take(2, "field_count"), "big")
    fields: list[CanonicalField] = []
    seen_labels: set[str] = set()
    for _ in range(field_count):
        label_length = int.from_bytes(take(2, "label_length"), "big")
        label_raw = take(label_length, "label")
        try:
            label = label_raw.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError("canonical_record_label_not_ascii") from exc
        _label_bytes(label)
        if label in seen_labels:
            raise ValueError("canonical_record_field_label_duplicate")
        seen_labels.add(label)
        type_tag = take(1, "type_tag")
        if type_tag not in {b"a", b"b", b"4", b"8", b"h", b"l"}:
            raise ValueError("canonical_record_type_tag_unknown")
        payload_length = int.from_bytes(take(4, "payload_length"), "big")
        payload = take(payload_length, "payload")
        if type_tag == b"a":
            try:
                payload.decode("ascii")
            except UnicodeDecodeError as exc:
                raise ValueError("canonical_record_ascii_payload_invalid") from exc
        elif type_tag == b"4" and payload_length != 4:
            raise ValueError("canonical_record_u32_payload_length_invalid")
        elif type_tag == b"8" and payload_length != 8:
            raise ValueError("canonical_record_u64_payload_length_invalid")
        elif type_tag in {b"h", b"l"} and payload_length != WIDE_LIMB_BYTES:
            raise ValueError("canonical_record_wide_limb_payload_length_invalid")
        fields.append((label, type_tag, payload))
    if cursor != len(raw):
        raise ValueError("canonical_record_trailing_data")
    decoded = tuple(fields)
    if _canonical_record(domain, decoded) != raw:
        raise ValueError("canonical_record_reencoding_mismatch")
    return decoded


def _validate_synthetic_attempt_record(encoded: bytes) -> bytes:
    fields = _decode_canonical_record(encoded, expected_domain=_RAW_RECORD_DOMAIN)
    if len(fields) < 4:
        raise ValueError("canonical_attempt_record_field_count_invalid")
    if fields[0] != ("profile_id", b"a", PROFILE_ID):
        raise ValueError("canonical_attempt_record_profile_mismatch")
    if fields[1] != ("schema_id", b"a", REFERENCE_SCHEMA_ID):
        raise ValueError("canonical_attempt_record_schema_mismatch")
    if fields[2] != ("record_type", b"a", b"synthetic_attempt"):
        raise ValueError("canonical_attempt_record_type_mismatch")
    for label, type_tag, _ in fields[3:]:
        if not label.startswith("field.") or type_tag != b"b":
            raise ValueError("canonical_attempt_record_field_encoding_invalid")
        try:
            _label_bytes(label.removeprefix("field."))
        except ValueError as exc:
            raise ValueError("canonical_attempt_record_field_label_invalid") from exc
    attempt_labels = tuple(label for label, _, _ in fields[3:])
    if attempt_labels != tuple(sorted(attempt_labels)):
        raise ValueError("canonical_attempt_record_fields_not_strictly_sorted")
    return encoded


def _hash_record(domain: bytes, fields: Sequence[CanonicalField]) -> WideDigest:
    return WideDigest.from_bytes(sha3_512(_canonical_record(domain, fields)).digest())


def canonical_reference_record(
    record_type: str,
    fields: Sequence[tuple[str, bytes]],
) -> bytes:
    """Encode a labelled synthetic raw record without JSON or implicit text conversion."""

    _require_synthetic_reference_enabled()
    record_type_raw = _label_bytes(record_type)
    supplied_fields = tuple(fields)
    labels = tuple(label for label, _ in supplied_fields)
    for label in labels:
        _label_bytes(label)
    if len(set(labels)) != len(labels):
        raise ValueError("canonical_reference_field_label_duplicate")
    if labels != tuple(sorted(labels)):
        raise ValueError("canonical_reference_fields_not_strictly_sorted")
    encoded_fields: list[CanonicalField] = [
        _ascii_field("profile_id", PROFILE_ID),
        _ascii_field("schema_id", REFERENCE_SCHEMA_ID),
        _ascii_field("record_type", record_type_raw),
    ]
    for label, value in supplied_fields:
        encoded_fields.append(_bytes_field(f"field.{label}", _require_bytes(label, value)))
    return _canonical_record(_RAW_RECORD_DOMAIN, encoded_fields)


def derive_strong_attempt_nullifier(
    canonical_attempt_record: bytes,
    *,
    governed_attempt_version: int,
    private_pepper: bytes,
) -> WideDigest:
    """Derive a wide nullifier directly from a canonical raw attempt record.

    There is deliberately no legacy-felt argument.  Hashing a felt nullifier
    would preserve its collision ceiling and is forbidden by the architecture.
    """

    _require_synthetic_reference_enabled()
    record = _validate_synthetic_attempt_record(
        _require_bytes("canonical_attempt_record", canonical_attempt_record)
    )
    if not record:
        raise ValueError("canonical_attempt_record_empty")
    pepper = _require_bytes("private_pepper", private_pepper, exact_length=RAW_PRIVACY_SALT_BYTES)
    if not any(pepper):
        raise ValueError("private_pepper_must_be_nonzero")
    version = _require_uint("governed_attempt_version", governed_attempt_version, bits=32, nonzero=True)
    return _hash_record(
        _ATTEMPT_NULLIFIER_DOMAIN,
        [
            _ascii_field("profile_id", PROFILE_ID),
            _ascii_field("schema_id", REFERENCE_SCHEMA_ID),
            _bytes_field("canonical_attempt_record", record),
            _u32_field("governed_attempt_version", version),
            _bytes_field("private_pepper_512", pepper),
        ],
    )


def _canonical_wide_values(values: Iterable[WideDigest], *, label: str) -> tuple[WideDigest, ...]:
    materialized: list[WideDigest] = []
    for value in values:
        if not isinstance(value, WideDigest):
            raise TypeError(f"{label}_must_contain_wide_digests")
        if value.is_zero:
            raise ValueError(f"{label}_contains_zero_digest")
        materialized.append(value)
    ordered = tuple(sorted(materialized, key=WideDigest.to_bytes))
    for index in range(1, len(ordered)):
        if ordered[index - 1] == ordered[index]:
            raise ValueError(f"{label}_contains_duplicate")
    return ordered


def _nullifier_empty(*, child_height: int, position: int) -> WideDigest:
    return _hash_record(
        _NULLIFIER_EMPTY_DOMAIN,
        [
            _ascii_field("profile_id", PROFILE_ID),
            _ascii_field("schema_id", REFERENCE_SCHEMA_ID),
            _ascii_field("tree_kind", b"strong_nullifier_set"),
            _u32_field("child_height", child_height),
            _u64_field("position", position),
        ],
    )


def strong_nullifier_set_root(values: Iterable[WideDigest]) -> WideDigest:
    """Return the full-width root of a deterministic sorted synthetic set.

    The tree is a review/KAT construction, not the unresolved production
    Patricia-or-bucket choice.  It never reduces children modulo a field.
    """

    _require_synthetic_reference_enabled()
    ordered = _canonical_wide_values(values, label="strong_nullifier_values")
    count = len(ordered)
    if count == 0:
        top = _nullifier_empty(child_height=0, position=0)
        height = 0
    else:
        nodes = [
            _hash_record(
                _NULLIFIER_LEAF_DOMAIN,
                [
                    _ascii_field("profile_id", PROFILE_ID),
                    _ascii_field("schema_id", REFERENCE_SCHEMA_ID),
                    _ascii_field("tree_kind", b"strong_nullifier_set"),
                    _ascii_field("record_type", b"attempt_nullifier_sha3_512"),
                    _u64_field("set_length", count),
                    _u64_field("position", position),
                    *_wide_fields("nullifier", value),
                ],
            )
            for position, value in enumerate(ordered)
        ]
        height = 0
        while len(nodes) > 1:
            parents: list[WideDigest] = []
            for offset in range(0, len(nodes), 2):
                left = nodes[offset]
                right = (
                    nodes[offset + 1]
                    if offset + 1 < len(nodes)
                    else _nullifier_empty(child_height=height, position=offset + 1)
                )
                parents.append(
                    _hash_record(
                        _NULLIFIER_NODE_DOMAIN,
                        [
                            _ascii_field("profile_id", PROFILE_ID),
                            _ascii_field("schema_id", REFERENCE_SCHEMA_ID),
                            _ascii_field("tree_kind", b"strong_nullifier_set"),
                            _u32_field("child_height", height),
                            _u64_field("position", offset // 2),
                            *_wide_fields("left_child", left),
                            *_wide_fields("right_child", right),
                        ],
                    )
                )
            nodes = parents
            height += 1
        top = nodes[0]
    return _hash_record(
        _NULLIFIER_ROOT_DOMAIN,
        [
            _ascii_field("profile_id", PROFILE_ID),
            _ascii_field("schema_id", REFERENCE_SCHEMA_ID),
            _ascii_field("tree_kind", b"strong_nullifier_set"),
            _u64_field("set_length", count),
            _u32_field("tree_height", height),
            *_wide_fields("top", top),
        ],
    )


@dataclass(frozen=True, slots=True)
class StrongNullifierTransition:
    existing_values: tuple[WideDigest, ...]
    additions: tuple[WideDigest, ...]
    merged_values: tuple[WideDigest, ...]
    root_before: WideDigest
    root_after: WideDigest

    def __post_init__(self) -> None:
        _require_synthetic_reference_enabled()


def build_strong_nullifier_transition(
    existing_values: Iterable[WideDigest],
    additions: Iterable[WideDigest],
) -> StrongNullifierTransition:
    _require_synthetic_reference_enabled()
    existing = _canonical_wide_values(existing_values, label="existing_strong_nullifiers")
    new_values = _canonical_wide_values(additions, label="strong_nullifier_additions")
    if not new_values:
        raise ValueError("strong_nullifier_additions_empty")
    existing_set = set(existing)
    if any(value in existing_set for value in new_values):
        raise ValueError("strong_nullifier_already_spent")
    merged = _canonical_wide_values((*existing, *new_values), label="merged_strong_nullifiers")
    before = strong_nullifier_set_root(existing)
    after = strong_nullifier_set_root(merged)
    if before == after:
        raise ValueError("strong_nullifier_root_unchanged")
    return StrongNullifierTransition(existing, new_values, merged, before, after)


def canonical_legacy_public_inputs(public_inputs: Sequence[bytes]) -> tuple[bytes, ...]:
    """Validate the unchanged Privacy V2 ``bytes32[12]`` wire statement."""

    _require_synthetic_reference_enabled()
    values = tuple(public_inputs)
    if len(values) != LEGACY_PUBLIC_FIELD_COUNT:
        raise ValueError("privacy_v2_public_field_count_mismatch")
    canonical = tuple(
        _canonical_felt_bytes(f"privacy_v2_public_field_{index}", value)
        for index, value in enumerate(values)
    )
    if int.from_bytes(canonical[0], "big") != PRIVACY_V2_PROTOCOL_VERSION:
        raise ValueError("privacy_v2_protocol_version_mismatch")
    if int.from_bytes(canonical[1], "big") == 0:
        raise ValueError("privacy_v2_settlement_domain_zero")
    if int.from_bytes(canonical[2], "big") == 0:
        raise ValueError("privacy_v2_batch_nonce_zero")
    return canonical


def _require_fresh_privacy_salt(value: object, *, label: str) -> bytes:
    salt = _require_bytes(label, value, exact_length=RAW_PRIVACY_SALT_BYTES)
    if not any(salt):
        raise ValueError(f"{label}_must_be_nonzero")
    return salt


def build_strong_batch_commitment(
    public_inputs: Sequence[bytes],
    *,
    epoch: int,
    sequence_before: int,
    sequence_after: int,
    strong_nullifier_root_before: WideDigest,
    strong_nullifier_root_after: WideDigest,
    strong_governance_commitment: WideDigest,
    verifier_identity: WideDigest,
    canonical_private_batch_commitment: WideDigest,
    fresh_privacy_salt: bytes,
) -> WideDigest:
    _require_synthetic_reference_enabled()
    legacy = canonical_legacy_public_inputs(public_inputs)
    epoch_value = _require_uint("epoch", epoch, bits=64, nonzero=True)
    before = _require_uint("sequence_before", sequence_before, bits=64)
    after = _require_uint("sequence_after", sequence_after, bits=64)
    if before == _UINT64_MAX or after != before + 1:
        raise ValueError("sequence_transition_invalid")
    for label, value in (
        ("strong_nullifier_root_before", strong_nullifier_root_before),
        ("strong_nullifier_root_after", strong_nullifier_root_after),
        ("strong_governance_commitment", strong_governance_commitment),
        ("verifier_identity", verifier_identity),
        ("canonical_private_batch_commitment", canonical_private_batch_commitment),
    ):
        if not isinstance(value, WideDigest):
            raise TypeError(f"{label}_must_be_wide_digest")
        if value.is_zero:
            raise ValueError(f"{label}_must_be_nonzero")
    salt = _require_fresh_privacy_salt(fresh_privacy_salt, label="fresh_privacy_salt")
    fields: list[CanonicalField] = [
        _ascii_field("profile_id", PROFILE_ID),
        _ascii_field("schema_id", REFERENCE_SCHEMA_ID),
        _u64_field("epoch", epoch_value),
        _u64_field("sequence_before", before),
        _u64_field("sequence_after", after),
        _u32_field("legacy_public_field_count", LEGACY_PUBLIC_FIELD_COUNT),
    ]
    fields.extend(
        _bytes_field(f"legacy_public_field_{index:02d}", value)
        for index, value in enumerate(legacy)
    )
    fields.extend(_wide_fields("strong_nullifier_root_before", strong_nullifier_root_before))
    fields.extend(_wide_fields("strong_nullifier_root_after", strong_nullifier_root_after))
    fields.extend(_wide_fields("strong_governance_commitment", strong_governance_commitment))
    fields.extend(_wide_fields("verifier_identity", verifier_identity))
    fields.extend(_wide_fields("canonical_private_batch_commitment", canonical_private_batch_commitment))
    fields.append(_bytes_field("fresh_privacy_salt_512", salt))
    return _hash_record(_BATCH_DOMAIN, fields)


@dataclass(frozen=True, slots=True)
class LegacyInternalStateRecord:
    """Legacy 434-byte transition record; never a proof sidecar or envelope."""

    profile_id: bytes
    schema_id: bytes
    epoch: int
    sequence_before: int
    sequence_after: int
    strong_nullifier_root_before: WideDigest
    strong_nullifier_root_after: WideDigest
    strong_governance_commitment: WideDigest
    verifier_identity: WideDigest
    strong_batch_commitment: WideDigest

    def __post_init__(self) -> None:
        _require_synthetic_reference_enabled()
        if _require_bytes("legacy_internal_state_record_profile_id", self.profile_id) != PROFILE_ID:
            raise ValueError("legacy_internal_state_record_profile_mismatch")
        if _require_bytes("legacy_internal_state_record_schema_id", self.schema_id) != REFERENCE_SCHEMA_ID:
            raise ValueError("legacy_internal_state_record_schema_mismatch")
        _require_uint("legacy_internal_state_record_epoch", self.epoch, bits=64, nonzero=True)
        before = _require_uint("legacy_internal_state_record_sequence_before", self.sequence_before, bits=64)
        after = _require_uint("legacy_internal_state_record_sequence_after", self.sequence_after, bits=64)
        if before == _UINT64_MAX or after != before + 1:
            raise ValueError("legacy_internal_state_record_sequence_transition_invalid")
        for label, value in (
            ("legacy_internal_state_record_strong_nullifier_root_before", self.strong_nullifier_root_before),
            ("legacy_internal_state_record_strong_nullifier_root_after", self.strong_nullifier_root_after),
            ("legacy_internal_state_record_strong_governance_commitment", self.strong_governance_commitment),
            ("legacy_internal_state_record_verifier_identity", self.verifier_identity),
            ("legacy_internal_state_record_strong_batch_commitment", self.strong_batch_commitment),
        ):
            if not isinstance(value, WideDigest):
                raise TypeError(f"{label}_must_be_wide_digest")
            if value.is_zero:
                raise ValueError(f"{label}_must_be_nonzero")
        if self.strong_nullifier_root_before == self.strong_nullifier_root_after:
            raise ValueError("legacy_internal_state_record_strong_root_unchanged")

    @staticmethod
    def _encode_wide(marker: bytes, value: WideDigest) -> bytes:
        return marker + b"H" + value.high_256 + b"L" + value.low_256

    def encode(self) -> bytes:
        _require_synthetic_reference_enabled()
        encoded = b"".join(
            (
                _LEGACY_INTERNAL_STATE_RECORD_MAGIC,
                b"P" + len(self.profile_id).to_bytes(2, "big") + self.profile_id,
                b"S" + len(self.schema_id).to_bytes(2, "big") + self.schema_id,
                b"E" + self.epoch.to_bytes(8, "big"),
                b"Q" + self.sequence_before.to_bytes(8, "big"),
                b"R" + self.sequence_after.to_bytes(8, "big"),
                self._encode_wide(b"N", self.strong_nullifier_root_before),
                self._encode_wide(b"A", self.strong_nullifier_root_after),
                self._encode_wide(b"G", self.strong_governance_commitment),
                self._encode_wide(b"V", self.verifier_identity),
                self._encode_wide(b"M", self.strong_batch_commitment),
            )
        )
        if len(encoded) != LEGACY_INTERNAL_STATE_RECORD_ENCODED_LENGTH:
            raise RuntimeError("legacy_internal_state_record_internal_length_mismatch")
        return encoded

    @classmethod
    def decode(cls, encoded: bytes) -> "LegacyInternalStateRecord":
        _require_synthetic_reference_enabled()
        raw = _require_bytes("legacy_internal_state_record", encoded)
        if len(raw) != LEGACY_INTERNAL_STATE_RECORD_ENCODED_LENGTH:
            raise ValueError("legacy_internal_state_record_length_mismatch")
        cursor = 0

        def take(length: int) -> bytes:
            nonlocal cursor
            end = cursor + length
            if end > len(raw):
                raise ValueError("legacy_internal_state_record_truncated")
            value = raw[cursor:end]
            cursor = end
            return value

        def expect(value: bytes, label: str) -> None:
            if take(len(value)) != value:
                raise ValueError(f"legacy_internal_state_record_{label}_mismatch")

        def sized(marker: bytes, label: str) -> bytes:
            expect(marker, f"{label}_marker")
            length = int.from_bytes(take(2), "big")
            return take(length)

        def uint64(marker: bytes, label: str) -> int:
            expect(marker, f"{label}_marker")
            return int.from_bytes(take(8), "big")

        def wide(marker: bytes, label: str) -> WideDigest:
            expect(marker, f"{label}_marker")
            expect(b"H", f"{label}_high_limb_marker")
            high = take(WIDE_LIMB_BYTES)
            expect(b"L", f"{label}_low_limb_marker")
            low = take(WIDE_LIMB_BYTES)
            return WideDigest(high, low)

        expect(_LEGACY_INTERNAL_STATE_RECORD_MAGIC, "magic")
        profile = sized(b"P", "profile")
        schema = sized(b"S", "schema")
        epoch = uint64(b"E", "epoch")
        sequence_before = uint64(b"Q", "sequence_before")
        sequence_after = uint64(b"R", "sequence_after")
        root_before = wide(b"N", "strong_root_before")
        root_after = wide(b"A", "strong_root_after")
        governance = wide(b"G", "strong_governance")
        verifier_identity = wide(b"V", "verifier_identity")
        batch = wide(b"M", "strong_batch")
        if cursor != len(raw):
            raise ValueError("legacy_internal_state_record_trailing_data")
        return cls(
            profile,
            schema,
            epoch,
            sequence_before,
            sequence_after,
            root_before,
            root_after,
            governance,
            verifier_identity,
            batch,
        )


LEGACY_INTERNAL_STATE_RECORD_ENCODED_LENGTH: Final[int] = (
    len(_LEGACY_INTERNAL_STATE_RECORD_MAGIC)
    + 1
    + 2
    + len(PROFILE_ID)
    + 1
    + 2
    + len(REFERENCE_SCHEMA_ID)
    + 3 * (1 + 8)
    + 5 * (1 + 1 + WIDE_LIMB_BYTES + 1 + WIDE_LIMB_BYTES)
)


@dataclass(frozen=True, slots=True)
class ReferenceTransition:
    legacy_state_record: LegacyInternalStateRecord
    public_inputs: tuple[bytes, ...]
    nullifier_additions: tuple[WideDigest, ...]
    canonical_private_batch_commitment: WideDigest
    fresh_privacy_salt: bytes = field(repr=False)

    def __post_init__(self) -> None:
        _require_synthetic_reference_enabled()
        if not isinstance(self.legacy_state_record, LegacyInternalStateRecord):
            raise TypeError("reference_transition_legacy_state_record_invalid")
        canonical_public_inputs = canonical_legacy_public_inputs(self.public_inputs)
        object.__setattr__(self, "public_inputs", canonical_public_inputs)
        additions = _canonical_wide_values(
            self.nullifier_additions,
            label="reference_transition_nullifier_additions",
        )
        if not additions:
            raise ValueError("reference_transition_nullifier_additions_empty")
        if additions != self.nullifier_additions:
            raise ValueError("reference_transition_nullifier_additions_not_canonical_order")
        if not isinstance(self.canonical_private_batch_commitment, WideDigest):
            raise TypeError("reference_private_batch_commitment_must_be_wide_digest")
        if self.canonical_private_batch_commitment.is_zero:
            raise ValueError("reference_private_batch_commitment_zero")
        _require_fresh_privacy_salt(
            self.fresh_privacy_salt,
            label="reference_fresh_privacy_salt",
        )


def build_reference_transition(
    existing_nullifiers: Iterable[WideDigest],
    nullifier_additions: Iterable[WideDigest],
    public_inputs: Sequence[bytes],
    *,
    epoch: int,
    sequence_before: int,
    strong_governance_commitment: WideDigest,
    canonical_private_batch_commitment: WideDigest,
    fresh_privacy_salt: bytes,
    verifier_identity: WideDigest,
) -> ReferenceTransition:
    _require_synthetic_reference_enabled()
    legacy = canonical_legacy_public_inputs(public_inputs)
    if legacy[3] == legacy[4]:
        raise ValueError("legacy_nullifier_root_unchanged")
    epoch_value = _require_uint("reference_epoch", epoch, bits=64, nonzero=True)
    before = _require_uint("reference_sequence_before", sequence_before, bits=64)
    if before == _UINT64_MAX:
        raise ValueError("reference_sequence_exhausted")
    if not isinstance(strong_governance_commitment, WideDigest):
        raise TypeError("strong_governance_commitment_must_be_wide_digest")
    if strong_governance_commitment.is_zero:
        raise ValueError("strong_governance_commitment_zero")
    if not isinstance(verifier_identity, WideDigest):
        raise TypeError("verifier_identity_must_be_wide_digest")
    if verifier_identity.is_zero:
        raise ValueError("verifier_identity_zero")
    strong_transition = build_strong_nullifier_transition(existing_nullifiers, nullifier_additions)
    batch_commitment = build_strong_batch_commitment(
        legacy,
        epoch=epoch_value,
        sequence_before=before,
        sequence_after=before + 1,
        strong_nullifier_root_before=strong_transition.root_before,
        strong_nullifier_root_after=strong_transition.root_after,
        strong_governance_commitment=strong_governance_commitment,
        verifier_identity=verifier_identity,
        canonical_private_batch_commitment=canonical_private_batch_commitment,
        fresh_privacy_salt=fresh_privacy_salt,
    )
    legacy_state_record = LegacyInternalStateRecord(
        PROFILE_ID,
        REFERENCE_SCHEMA_ID,
        epoch_value,
        before,
        before + 1,
        strong_transition.root_before,
        strong_transition.root_after,
        strong_governance_commitment,
        verifier_identity,
        batch_commitment,
    )
    return ReferenceTransition(
        legacy_state_record,
        legacy,
        strong_transition.additions,
        canonical_private_batch_commitment,
        fresh_privacy_salt,
    )


def _salt_tag(salt: bytes) -> WideDigest:
    return _hash_record(
        _SALT_TAG_DOMAIN,
        [
            _ascii_field("profile_id", PROFILE_ID),
            _ascii_field("schema_id", REFERENCE_SCHEMA_ID),
            _bytes_field(
                "fresh_privacy_salt_512",
                _require_fresh_privacy_salt(salt, label="fresh_privacy_salt"),
            ),
        ],
    )


def _registry_root(kind: bytes, entries: Sequence[bytes], *, entry_length: int) -> WideDigest:
    kind_value = _require_bytes("registry_kind", kind)
    ordered = tuple(sorted(_require_bytes("registry_entry", item, exact_length=entry_length) for item in entries))
    for index in range(1, len(ordered)):
        if ordered[index - 1] == ordered[index]:
            raise ValueError("registry_entry_duplicate")
    acc = _hash_record(
        _REGISTRY_INIT_DOMAIN,
        [
            _ascii_field("profile_id", PROFILE_ID),
            _ascii_field("schema_id", REFERENCE_SCHEMA_ID),
            _ascii_field("registry_kind", kind_value),
            _u64_field("entry_count", len(ordered)),
        ],
    )
    for position, entry in enumerate(ordered):
        acc = _hash_record(
            _REGISTRY_STEP_DOMAIN,
            [
                _ascii_field("profile_id", PROFILE_ID),
                _ascii_field("schema_id", REFERENCE_SCHEMA_ID),
                _ascii_field("registry_kind", kind_value),
                _u64_field("entry_count", len(ordered)),
                _u64_field("position", position),
                *_wide_fields("previous", acc),
                _bytes_field("entry", entry),
            ],
        )
    return _hash_record(
        _REGISTRY_ROOT_DOMAIN,
        [
            _ascii_field("profile_id", PROFILE_ID),
            _ascii_field("schema_id", REFERENCE_SCHEMA_ID),
            _ascii_field("registry_kind", kind_value),
            _u64_field("entry_count", len(ordered)),
            *_wide_fields("accumulator", acc),
        ],
    )


@dataclass(frozen=True, slots=True)
class _StateData:
    epoch: int
    sequence: int
    settlement_domain: bytes
    legacy_nullifier_root: bytes
    legacy_governed_roots: tuple[bytes, bytes, bytes, bytes]
    strong_nullifiers: tuple[WideDigest, ...]
    strong_governance_commitment: WideDigest
    verifier_identity: WideDigest
    recorded_batch_commitments: tuple[WideDigest, ...]
    consumed_nonces: tuple[bytes, ...]
    consumed_salt_tags: tuple[WideDigest, ...]


@dataclass(frozen=True, slots=True)
class ReferenceStateSnapshot:
    profile_id: bytes
    schema_id: bytes
    epoch: int
    sequence: int
    settlement_domain: bytes
    legacy_nullifier_root: bytes
    legacy_governed_roots: tuple[bytes, bytes, bytes, bytes]
    strong_nullifier_root: WideDigest
    strong_governance_commitment: WideDigest
    verifier_identity: WideDigest
    nullifier_count: int
    recorded_batch_count: int
    consumed_nonce_count: int
    state_commitment: WideDigest

    def __post_init__(self) -> None:
        _require_synthetic_reference_enabled()


def _snapshot_for(data: _StateData) -> ReferenceStateSnapshot:
    strong_root = strong_nullifier_set_root(data.strong_nullifiers)
    batch_registry = _registry_root(
        b"recorded_batch_commitments",
        tuple(item.to_bytes() for item in data.recorded_batch_commitments),
        entry_length=WIDE_DIGEST_BYTES,
    )
    nonce_registry = _registry_root(
        b"consumed_batch_nonces",
        data.consumed_nonces,
        entry_length=32,
    )
    salt_registry = _registry_root(
        b"consumed_privacy_salt_tags",
        tuple(item.to_bytes() for item in data.consumed_salt_tags),
        entry_length=WIDE_DIGEST_BYTES,
    )
    fields: list[CanonicalField] = [
        _ascii_field("profile_id", PROFILE_ID),
        _ascii_field("schema_id", REFERENCE_SCHEMA_ID),
        _u64_field("epoch", data.epoch),
        _u64_field("sequence", data.sequence),
        _bytes_field("settlement_domain", data.settlement_domain),
        _bytes_field("legacy_nullifier_root", data.legacy_nullifier_root),
    ]
    fields.extend(
        _bytes_field(f"legacy_governed_root_{index}", value)
        for index, value in enumerate(data.legacy_governed_roots)
    )
    fields.extend(_wide_fields("strong_nullifier_root", strong_root))
    fields.extend(_wide_fields("strong_governance_commitment", data.strong_governance_commitment))
    fields.extend(_wide_fields("verifier_identity", data.verifier_identity))
    fields.extend(_wide_fields("recorded_batch_registry", batch_registry))
    fields.extend(_wide_fields("consumed_nonce_registry", nonce_registry))
    fields.extend(_wide_fields("consumed_salt_registry", salt_registry))
    fields.extend(
        (
            _u64_field("nullifier_count", len(data.strong_nullifiers)),
            _u64_field("recorded_batch_count", len(data.recorded_batch_commitments)),
            _u64_field("consumed_nonce_count", len(data.consumed_nonces)),
        )
    )
    state_commitment = _hash_record(_STATE_DOMAIN, fields)
    return ReferenceStateSnapshot(
        PROFILE_ID,
        REFERENCE_SCHEMA_ID,
        data.epoch,
        data.sequence,
        data.settlement_domain,
        data.legacy_nullifier_root,
        data.legacy_governed_roots,
        strong_root,
        data.strong_governance_commitment,
        data.verifier_identity,
        len(data.strong_nullifiers),
        len(data.recorded_batch_commitments),
        len(data.consumed_nonces),
        state_commitment,
    )


class SyntheticAuthoritativeState:
    """In-memory atomic reference state for synthetic attack tests only.

    A transition is validated completely and then installed through one
    immutable-state pointer swap under a lock.  This models atomic semantics;
    it is not durable transaction or crash-consistency evidence.
    """

    def __init__(
        self,
        *,
        epoch: int,
        sequence: int,
        settlement_domain: bytes,
        legacy_nullifier_root: bytes,
        legacy_governed_roots: Sequence[bytes],
        strong_nullifiers: Iterable[WideDigest],
        strong_governance_commitment: WideDigest,
        verifier_identity: WideDigest,
    ) -> None:
        _require_synthetic_reference_enabled()
        epoch_value = _require_uint("state_epoch", epoch, bits=64, nonzero=True)
        sequence_value = _require_uint("state_sequence", sequence, bits=64)
        domain = _canonical_felt_bytes("state_settlement_domain", settlement_domain, nonzero=True)
        legacy_root = _canonical_felt_bytes("state_legacy_nullifier_root", legacy_nullifier_root)
        governed_values = tuple(legacy_governed_roots)
        if len(governed_values) != 4:
            raise ValueError("state_legacy_governed_root_count_mismatch")
        governed = tuple(
            _canonical_felt_bytes(f"state_legacy_governed_root_{index}", value)
            for index, value in enumerate(governed_values)
        )
        if not isinstance(strong_governance_commitment, WideDigest):
            raise TypeError("state_strong_governance_commitment_must_be_wide_digest")
        if strong_governance_commitment.is_zero:
            raise ValueError("state_strong_governance_commitment_zero")
        if not isinstance(verifier_identity, WideDigest):
            raise TypeError("state_verifier_identity_must_be_wide_digest")
        if verifier_identity.is_zero:
            raise ValueError("state_verifier_identity_zero")
        nullifiers = _canonical_wide_values(strong_nullifiers, label="state_strong_nullifiers")
        self._lock = threading.Lock()
        self._data = _StateData(
            epoch_value,
            sequence_value,
            domain,
            legacy_root,
            governed,  # type: ignore[arg-type]
            nullifiers,
            strong_governance_commitment,
            verifier_identity,
            (),
            (),
            (),
        )

    def snapshot(self) -> ReferenceStateSnapshot:
        _require_synthetic_reference_enabled()
        with self._lock:
            return _snapshot_for(self._data)

    def commit_reference_transition(self, transition: ReferenceTransition) -> ReferenceStateSnapshot:
        _require_synthetic_reference_enabled()
        if not isinstance(transition, ReferenceTransition):
            raise TypeError("reference_transition_invalid")
        if (
            LegacyInternalStateRecord.decode(transition.legacy_state_record.encode())
            != transition.legacy_state_record
        ):
            raise ValueError("legacy_internal_state_record_round_trip_mismatch")
        with self._lock:
            current = self._data
            legacy_state_record = transition.legacy_state_record
            legacy = canonical_legacy_public_inputs(transition.public_inputs)
            if legacy_state_record.profile_id != PROFILE_ID:
                raise ValueError("state_profile_mismatch")
            if legacy_state_record.schema_id != REFERENCE_SCHEMA_ID:
                raise ValueError("state_schema_mismatch")
            if legacy_state_record.epoch != current.epoch:
                raise ValueError("state_epoch_mismatch")
            if legacy_state_record.sequence_before != current.sequence:
                raise ValueError("stale_strong_state_sequence")
            if (
                current.sequence == _UINT64_MAX
                or legacy_state_record.sequence_after != current.sequence + 1
            ):
                raise ValueError("state_sequence_transition_invalid")
            if legacy[1] != current.settlement_domain:
                raise ValueError("state_settlement_domain_mismatch")
            if legacy[3] != current.legacy_nullifier_root:
                raise ValueError("stale_legacy_nullifier_root")
            if legacy[3] == legacy[4]:
                raise ValueError("legacy_nullifier_root_unchanged")
            if legacy[5:9] != current.legacy_governed_roots:
                raise ValueError("state_legacy_governed_roots_mismatch")
            if legacy_state_record.strong_governance_commitment != current.strong_governance_commitment:
                raise ValueError("state_strong_governance_mismatch")
            if legacy_state_record.verifier_identity != current.verifier_identity:
                raise ValueError("state_verifier_identity_mismatch")

            expected_transition = build_strong_nullifier_transition(
                current.strong_nullifiers,
                transition.nullifier_additions,
            )
            if legacy_state_record.strong_nullifier_root_before != expected_transition.root_before:
                raise ValueError("stale_strong_nullifier_root")
            if legacy_state_record.strong_nullifier_root_after != expected_transition.root_after:
                raise ValueError("strong_nullifier_root_after_mismatch")
            expected_batch = build_strong_batch_commitment(
                legacy,
                epoch=current.epoch,
                sequence_before=current.sequence,
                sequence_after=current.sequence + 1,
                strong_nullifier_root_before=expected_transition.root_before,
                strong_nullifier_root_after=expected_transition.root_after,
                strong_governance_commitment=current.strong_governance_commitment,
                verifier_identity=current.verifier_identity,
                canonical_private_batch_commitment=transition.canonical_private_batch_commitment,
                fresh_privacy_salt=transition.fresh_privacy_salt,
            )
            if legacy_state_record.strong_batch_commitment != expected_batch:
                raise ValueError("strong_batch_commitment_mismatch")
            if legacy_state_record.strong_batch_commitment in current.recorded_batch_commitments:
                raise ValueError("strong_batch_commitment_already_recorded")
            nonce = legacy[2]
            if nonce in current.consumed_nonces:
                raise ValueError("batch_nonce_already_consumed")
            salt_tag = _salt_tag(transition.fresh_privacy_salt)
            if salt_tag in current.consumed_salt_tags:
                raise ValueError("privacy_salt_already_consumed")

            prospective = _StateData(
                current.epoch,
                current.sequence + 1,
                current.settlement_domain,
                legacy[4],
                current.legacy_governed_roots,
                expected_transition.merged_values,
                current.strong_governance_commitment,
                current.verifier_identity,
                tuple(
                    sorted(
                        (*current.recorded_batch_commitments, legacy_state_record.strong_batch_commitment),
                        key=WideDigest.to_bytes,
                    )
                ),
                tuple(sorted((*current.consumed_nonces, nonce))),
                tuple(sorted((*current.consumed_salt_tags, salt_tag), key=WideDigest.to_bytes)),
            )
            prospective_snapshot = _snapshot_for(prospective)
            if (
                prospective_snapshot.strong_nullifier_root
                != legacy_state_record.strong_nullifier_root_after
            ):
                raise ValueError("prospective_strong_state_root_mismatch")
            self._data = prospective
            return prospective_snapshot
