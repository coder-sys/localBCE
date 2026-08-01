"""Synthetic-only P01/P02/T01 SHA3-512 reference construction.

Every domain in this module is explicitly ``REFERENCE/v0``.  Nothing here is
a production tree, a proof-system parameter selection, an S09 decision, or an
authorization to process real records.  The module exists to make candidate
encodings and cross-language vectors precise enough to review.

The dual-tree API materializes and strictly parses one immutable sequence of
canonical raw records.  The legacy field tree and the wide SHA3-512 tree then
consume those same bytes through separate functions.  The wide path has no
legacy-leaf or legacy-root input.

The complete-tree helper is bounded at depth 16, enough for the independent
provisional A01 policy tree and the largest batch-local oracle tree.  It is not the future sparse
32/64-level authoritative nullifier construction; that remains P03 work.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
import hmac
from itertools import islice
import json
import os
import re
from typing import Final, Iterable, Sequence

from app.batch.poseidon import (
    FIELD_MODULUS,
    domain_poseidon_hash,
    domain_poseidon_many,
)
from app.multipart_ascii import encode_multipart_ascii64


PROFILE_ID: Final[bytes] = b"BL-PQ512-v1"
REFERENCE_SCHEMA_ID: Final[bytes] = b"BL-PQ512-TREE-REFERENCE-v0"
FOUNDATION_STATEMENT_SCHEMA_ID: Final[str] = "TBD-S12-P06-NOT-FROZEN"
UNSELECTED_PROOF_SUITE_ID: Final[str] = "TBD-S07-S08-S09-NOT-SELECTED"
UNRESOLVED_PAYMENT_BINDING_STATUS: Final[str] = "UNRESOLVED-A11-P05"
REFERENCE_STATUS: Final[str] = "SYNTHETIC_T01_STRUCTURE_AND_P01_P02_TREE_KAT_NOT_T02"
REFERENCE_DOMAIN_SUITE: Final[str] = "BL-PQ512-REFERENCE/v0"
SYNTHETIC_REFERENCE_ENABLE_ENV: Final[str] = "BL_ALLOW_SYNTHETIC_PQ_TREE_REFERENCE"

CANONICAL_MAGIC: Final[bytes] = b"BL/PQ512/CANONICAL/REFERENCE/v0"
RAW_RECORD_DOMAIN: Final[bytes] = b"BL/PQ512/RAW-RECORD/REFERENCE/v0"
TREE_OPERATION_MAGIC: Final[bytes] = b"BL/PQ512/TREE-OP/REFERENCE/v0"
WIDE_LEAF_DOMAIN: Final[bytes] = b"BL/PQ512/TREE/LEAF/REFERENCE/v0"
WIDE_NODE_DOMAIN: Final[bytes] = b"BL/PQ512/TREE/NODE/REFERENCE/v0"
WIDE_EMPTY_DOMAIN: Final[bytes] = b"BL/PQ512/TREE/EMPTY/REFERENCE/v0"
WIDE_ROOT_DOMAIN: Final[bytes] = b"BL/PQ512/TREE/ROOT/REFERENCE/v0"
RECORD_MANIFEST_DOMAIN: Final[bytes] = b"BL/PQ512/TREE/RECORD-MANIFEST/REFERENCE/v0"
LEGACY_REFERENCE_POSEIDON_DOMAIN: Final[bytes] = b"BL/PQ512/TREE/LEGACY-FIELD/REFERENCE/v0"
LEGACY_REFERENCE_POSEIDON_TAG: Final[int] = int.from_bytes(
    sha3_512(LEGACY_REFERENCE_POSEIDON_DOMAIN).digest(), "big"
) % FIELD_MODULUS
# The protected helper admits only its reviewed outer-domain allowlist.  This
# reference branch uses the existing claim-source outer framing and places the
# full REFERENCE/v0 tag inside every payload.  It does not add or select a
# production domain.
_LEGACY_REFERENCE_OUTER_DOMAIN: Final[str] = "claim_source"

FOUNDATION_VECTOR_SCHEMA: Final[str] = "blind-ledger-bl-pq512-foundation-vector-v1"
PUBLIC_OUTPUT_NAMES: Final[tuple[str, ...]] = (
    "protocolVersion",
    "settlementDomain",
    "batchNonce",
    "nullifierRootBefore",
    "nullifierRootAfter",
    "claimSourceRoot",
    "oracleFactsRoot",
    "policyRoot",
    "rulesetRoot",
    "opaqueBatchCommitment",
    "valueConservationCommitment",
    "settlementCommitment",
)

MAX_CANONICAL_RECORD_BYTES: Final[int] = 16_384
MAX_CANONICAL_FIELDS: Final[int] = 128
# Covers the largest provisional batch-local A01 oracle tree (K512: depth 15)
# and the independent provisional policy tree (depth 16).
# Persistent 32/64-level nullifier trees require a sparse/path reference under
# P03 and are deliberately not materialized by this complete-tree helper.
MAX_REFERENCE_TREE_HEIGHT: Final[int] = 16
MAX_FOUNDATION_VECTOR_BYTES: Final[int] = 2 * 1024 * 1024
MAX_FOUNDATION_OPERATIONS: Final[int] = 128
MAX_FOUNDATION_VECTOR_RECORDS: Final[int] = 256
MAX_PROOF_IDENTIFIER_BYTES: Final[int] = 64
SYNTHETIC_BYTES_MAGIC: Final[bytes] = b"BL-SYNTHETIC\x00"

_SYNTHETIC_ENVS: Final[frozenset[str]] = frozenset({"local", "test", "unit", "ci"})
_IDENTIFIER_PATTERN: Final[re.Pattern[str]] = re.compile(r"[a-z][a-z0-9_.-]{0,63}\Z")
_LOWER_HEX_32: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_LOWER_HEX_64: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{128}\Z")
_LOWER_HEX_8: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{16}\Z")
_LOWER_EVEN_HEX: Final[re.Pattern[str]] = re.compile(r"(?:[0-9a-f]{2})+\Z")
_DECIMAL_PATTERN: Final[re.Pattern[str]] = re.compile(r"0|[1-9][0-9]*\Z")
_TYPE_TO_TAG: Final[dict[str, bytes]] = {
    "ascii": b"a",
    "bytes": b"b",
    "u32": b"4",
    "u64": b"8",
    "bool": b"?",
}
_TAG_TO_TYPE: Final[dict[bytes, str]] = {value: key for key, value in _TYPE_TO_TAG.items()}

# Synthetic reference records are closed profiles, not an extensible ingestion
# format.  Exact field/type allowlists prevent a real-looking identifier from
# bypassing the guard merely by using an unfamiliar field name or a numeric
# representation.  The first two profiles exist only for isolated hash-domain
# tests; the four government profiles are emitted by the reference adapter.
_SYNTHETIC_RECORD_FIELD_PROFILES: Final[dict[str, dict[str, str]]] = {
    "synthetic_claim": {
        "claim_id": "ascii",
        "verified": "bool",
        "total_cents": "u64",
    },
    "synthetic_oracle": {
        "claim_id": "ascii",
        "verified": "bool",
        "total_cents": "u64",
    },
    "synthetic_government_auth": {
        "meta.adapter_id": "ascii",
        "meta.record_id": "ascii",
        "meta.snapshot_id": "ascii",
        "meta.snapshot_version": "u64",
        "meta.source_system": "ascii",
        "payload.authorization_present": "bool",
        "payload.authorization_reference": "ascii",
    },
    "synthetic_government_claim": {
        "meta.adapter_id": "ascii",
        "meta.record_id": "ascii",
        "meta.snapshot_id": "ascii",
        "meta.snapshot_version": "u64",
        "meta.source_system": "ascii",
        "payload.claim_id": "ascii",
        "payload.total_cents": "u64",
    },
    "synthetic_government_oracle": {
        "meta.adapter_id": "ascii",
        "meta.record_id": "ascii",
        "meta.snapshot_id": "ascii",
        "meta.snapshot_version": "u64",
        "meta.source_system": "ascii",
        "payload.provider_enrolled": "bool",
        "payload.eligibility_active": "bool",
    },
    "synthetic_government_policy": {
        "meta.adapter_id": "ascii",
        "meta.record_id": "ascii",
        "meta.snapshot_id": "ascii",
        "meta.snapshot_version": "u64",
        "meta.source_system": "ascii",
        "payload.fee_cents": "u64",
        "payload.policy_version": "ascii",
    },
    "synthetic_claim_truth_source": {
        "payload": "bytes",
        "slot_index": "u32",
    },
    "synthetic_claim_truth_oracle_fact": {
        "payload": "bytes",
        "slot_index": "u32",
    },
    "synthetic_claim_truth_oracle_authorization": {
        "payload": "bytes",
        "slot_index": "u32",
    },
    "synthetic_claim_truth_policy": {
        "payload": "bytes",
        "slot_index": "u32",
    },
    "synthetic_claim_truth_ruleset": {
        "payload": "bytes",
    },
}


def require_synthetic_reference_enabled() -> None:
    environment = os.environ.get("BL_ENV", "").strip().lower()
    if (
        environment not in _SYNTHETIC_ENVS
        or os.environ.get("BL_DEV") != "1"
        or os.environ.get(SYNTHETIC_REFERENCE_ENABLE_ENV) != "1"
    ):
        raise RuntimeError(
            "synthetic_pq_tree_reference_forbidden:requires_local_test_env_and_explicit_dev_flags"
        )


def _identifier(label: str, value: object) -> str:
    if not isinstance(value, str) or _IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{label}_invalid")
    return value


def _proof_identifier(label: str, value: object) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label}_must_be_string")
    encode_multipart_ascii64(value, label=label, allow_empty=False)
    return value


def _canonical_ascii_key(value: str) -> tuple[int, bytes]:
    raw = value.encode("ascii")
    return len(raw), raw


def _bytes(label: str, value: object, *, exact_length: int | None = None) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError(f"{label}_must_be_bytes")
    if exact_length is not None and len(value) != exact_length:
        raise ValueError(f"{label}_length_invalid")
    return value


def _uint(label: str, value: object, *, bits: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{label}_must_be_integer")
    if value < 0 or value >= 1 << bits:
        raise ValueError(f"{label}_out_of_range")
    return value


def _lp16(value: bytes) -> bytes:
    if len(value) > 0xFFFF:
        raise ValueError("reference_length_exceeds_u16")
    return len(value).to_bytes(2, "big") + value


def _lp32(value: bytes) -> bytes:
    if len(value) > 0xFFFFFFFF:
        raise ValueError("reference_length_exceeds_u32")
    return len(value).to_bytes(4, "big") + value


@dataclass(frozen=True, slots=True)
class CanonicalField:
    name: str
    type_name: str
    payload: bytes

    def __post_init__(self) -> None:
        require_synthetic_reference_enabled()
        _identifier("canonical_field_name", self.name)
        if self.type_name not in _TYPE_TO_TAG:
            raise ValueError("canonical_field_type_unknown")
        payload = _bytes("canonical_field_payload", self.payload)
        if self.type_name == "ascii":
            try:
                payload.decode("ascii")
            except UnicodeDecodeError as exc:
                raise ValueError("canonical_ascii_payload_invalid") from exc
            if len(payload) > MAX_PROOF_IDENTIFIER_BYTES:
                raise ValueError("canonical_ascii_payload_exceeds_64_bytes")
            if b"\x00" in payload:
                raise ValueError("canonical_ascii_payload_embedded_zero")
        elif self.type_name == "u32" and len(payload) != 4:
            raise ValueError("canonical_u32_payload_length_invalid")
        elif self.type_name == "u64" and len(payload) != 8:
            raise ValueError("canonical_u64_payload_length_invalid")
        elif self.type_name == "bool" and payload not in {b"\x00", b"\x01"}:
            raise ValueError("canonical_bool_payload_invalid")

    @classmethod
    def ascii(cls, name: str, value: str) -> "CanonicalField":
        if not isinstance(value, str):
            raise TypeError(f"{name}_must_be_string")
        try:
            payload = value.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ValueError(f"{name}_must_be_ascii") from exc
        return cls(name, "ascii", payload)

    @classmethod
    def identifier(cls, name: str, value: str, *, allow_empty: bool = False) -> "CanonicalField":
        if not isinstance(value, str):
            raise TypeError(f"{name}_must_be_string")
        encoded = encode_multipart_ascii64(value, label=name, allow_empty=allow_empty)
        if encoded.byte_length != len(value.encode("ascii")):
            raise ValueError(f"{name}_multipart_length_mismatch")
        return cls(name, "ascii", value.encode("ascii"))

    @classmethod
    def raw_bytes(cls, name: str, value: bytes) -> "CanonicalField":
        return cls(name, "bytes", _bytes(name, value))

    @classmethod
    def u32(cls, name: str, value: int) -> "CanonicalField":
        return cls(name, "u32", _uint(name, value, bits=32).to_bytes(4, "big"))

    @classmethod
    def u64(cls, name: str, value: int) -> "CanonicalField":
        return cls(name, "u64", _uint(name, value, bits=64).to_bytes(8, "big"))

    @classmethod
    def boolean(cls, name: str, value: bool) -> "CanonicalField":
        if not isinstance(value, bool):
            raise TypeError(f"{name}_must_be_boolean")
        return cls(name, "bool", b"\x01" if value else b"\x00")


@dataclass(frozen=True, slots=True)
class CanonicalRecord:
    record_type: str
    fields: tuple[CanonicalField, ...]
    encoded: bytes

    def __post_init__(self) -> None:
        require_synthetic_reference_enabled()
        _identifier("canonical_record_type", self.record_type)
        _bytes("canonical_record_encoded", self.encoded)


def encode_canonical_record(record_type: str, fields: Sequence[CanonicalField]) -> bytes:
    """Encode one strict typed raw record; caller field order is normative."""

    require_synthetic_reference_enabled()
    record_type_value = _identifier("canonical_record_type", record_type).encode("ascii")
    supplied = tuple(fields)
    if len(supplied) > MAX_CANONICAL_FIELDS:
        raise ValueError("canonical_record_field_count_exceeds_reference_limit")
    if any(not isinstance(field, CanonicalField) for field in supplied):
        raise TypeError("canonical_record_fields_must_be_canonical_fields")
    names = tuple(field.name for field in supplied)
    if names != tuple(sorted(names, key=_canonical_ascii_key)):
        raise ValueError("canonical_record_fields_not_strictly_sorted")
    if len(set(names)) != len(names):
        raise ValueError("canonical_record_field_duplicate")
    out = bytearray(CANONICAL_MAGIC)
    out.extend(_lp16(RAW_RECORD_DOMAIN))
    out.extend(_lp16(PROFILE_ID))
    out.extend(_lp16(REFERENCE_SCHEMA_ID))
    out.extend(_lp16(record_type_value))
    out.extend(len(supplied).to_bytes(2, "big"))
    for field in supplied:
        out.extend(_lp16(field.name.encode("ascii")))
        out.extend(_TYPE_TO_TAG[field.type_name])
        out.extend(_lp32(field.payload))
    encoded = bytes(out)
    if len(encoded) > MAX_CANONICAL_RECORD_BYTES:
        raise ValueError("canonical_record_exceeds_reference_size_limit")
    return encoded


def parse_canonical_record(encoded: bytes) -> CanonicalRecord:
    """Parse one encoding, reject every alternate form, and require exact re-encoding."""

    require_synthetic_reference_enabled()
    raw = _bytes("canonical_record", encoded)
    if len(raw) > MAX_CANONICAL_RECORD_BYTES:
        raise ValueError("canonical_record_exceeds_reference_size_limit")
    cursor = 0

    def take(length: int, label: str) -> bytes:
        nonlocal cursor
        if length < 0 or cursor + length > len(raw):
            raise ValueError(f"canonical_record_{label}_truncated")
        value = raw[cursor : cursor + length]
        cursor += length
        return value

    def take_lp16(label: str) -> bytes:
        return take(int.from_bytes(take(2, f"{label}_length"), "big"), label)

    def take_lp32(label: str) -> bytes:
        return take(int.from_bytes(take(4, f"{label}_length"), "big"), label)

    if take(len(CANONICAL_MAGIC), "magic") != CANONICAL_MAGIC:
        raise ValueError("canonical_record_magic_mismatch")
    if take_lp16("domain") != RAW_RECORD_DOMAIN:
        raise ValueError("canonical_record_domain_mismatch")
    if take_lp16("profile") != PROFILE_ID:
        raise ValueError("canonical_record_profile_mismatch")
    if take_lp16("schema") != REFERENCE_SCHEMA_ID:
        raise ValueError("canonical_record_schema_mismatch")
    try:
        record_type = take_lp16("record_type").decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("canonical_record_type_not_ascii") from exc
    _identifier("canonical_record_type", record_type)
    field_count = int.from_bytes(take(2, "field_count"), "big")
    if field_count > MAX_CANONICAL_FIELDS:
        raise ValueError("canonical_record_field_count_exceeds_reference_limit")
    fields: list[CanonicalField] = []
    for _ in range(field_count):
        try:
            name = take_lp16("field_name").decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError("canonical_record_field_name_not_ascii") from exc
        tag = take(1, "field_type")
        type_name = _TAG_TO_TYPE.get(tag)
        if type_name is None:
            raise ValueError("canonical_record_field_type_unknown")
        fields.append(CanonicalField(name, type_name, take_lp32("field_payload")))
    if cursor != len(raw):
        raise ValueError("canonical_record_trailing_data")
    parsed = CanonicalRecord(record_type, tuple(fields), raw)
    if encode_canonical_record(parsed.record_type, parsed.fields) != raw:
        raise ValueError("canonical_record_reencoding_mismatch")
    return parsed


def require_synthetic_canonical_record(record: CanonicalRecord) -> None:
    if not isinstance(record, CanonicalRecord):
        raise TypeError("synthetic_record_must_be_canonical_record")
    expected = _SYNTHETIC_RECORD_FIELD_PROFILES.get(record.record_type)
    if expected is None:
        raise ValueError("synthetic_record_profile_not_allowlisted")
    observed = {field.name: field.type_name for field in record.fields}
    if observed != expected:
        raise ValueError("synthetic_record_fields_not_allowlisted")
    fields_by_name = {field.name: field for field in record.fields}
    authenticated_absence = False
    if record.record_type == "synthetic_government_auth":
        present = fields_by_name["payload.authorization_present"].payload == b"\x01"
        reference_present = bool(fields_by_name["payload.authorization_reference"].payload)
        if present != reference_present:
            raise ValueError("synthetic_authorization_reference_inconsistent")
        authenticated_absence = not present
    for field in record.fields:
        if field.type_name == "ascii":
            if not field.payload:
                if authenticated_absence and field.name == "payload.authorization_reference":
                    continue
                raise ValueError(f"synthetic_ascii_empty:{field.name}")
            try:
                value = field.payload.decode("ascii")
            except UnicodeDecodeError as exc:
                raise ValueError("synthetic_ascii_not_ascii") from exc
            if not value.startswith("SYNTHETIC-") or value == "SYNTHETIC-":
                raise ValueError(f"synthetic_marker_missing:{field.name}")
            _proof_identifier(f"synthetic_{field.name}", value)
        elif field.type_name == "bytes" and not field.payload.startswith(SYNTHETIC_BYTES_MAGIC):
            raise ValueError(f"synthetic_bytes_marker_missing:{field.name}")


def _tree_operation_preimage(
    domain: bytes,
    *,
    tree_kind: str,
    item_type: str,
    record_type: str,
    position: int,
    length: int,
    tree_height: int,
    child_height: int,
    payloads: Sequence[bytes],
) -> bytes:
    tree_kind_value = _identifier("reference_tree_kind", tree_kind).encode("ascii")
    item_type_value = _identifier("reference_tree_item_type", item_type).encode("ascii")
    record_type_value = _identifier("reference_tree_record_type", record_type).encode("ascii")
    position_value = _uint("reference_tree_position", position, bits=64)
    length_value = _uint("reference_tree_length", length, bits=64)
    height_value = _uint("reference_tree_height", tree_height, bits=32)
    child_height_value = _uint("reference_tree_child_height", child_height, bits=32)
    if len(payloads) > 0xFFFF:
        raise ValueError("reference_tree_payload_count_invalid")
    if height_value > MAX_REFERENCE_TREE_HEIGHT:
        raise ValueError("reference_tree_height_exceeds_synthetic_limit")
    capacity = 1 << height_value
    if length_value > capacity:
        raise ValueError("reference_tree_length_exceeds_capacity")
    if item_type == "leaf":
        if domain != WIDE_LEAF_DOMAIN or child_height_value != 0 or len(payloads) != 1:
            raise ValueError("reference_tree_leaf_shape_invalid")
        if position_value >= length_value:
            raise ValueError("reference_tree_leaf_position_invalid")
    elif item_type == "empty":
        if domain != WIDE_EMPTY_DOMAIN or child_height_value != 0 or payloads:
            raise ValueError("reference_tree_empty_shape_invalid")
        if position_value < length_value or position_value >= capacity:
            raise ValueError("reference_tree_empty_position_invalid")
    elif item_type == "node":
        if domain != WIDE_NODE_DOMAIN or len(payloads) != 2:
            raise ValueError("reference_tree_node_shape_invalid")
        if child_height_value >= height_value:
            raise ValueError("reference_tree_node_child_height_invalid")
        node_count = 1 << (height_value - child_height_value - 1)
        if position_value >= node_count:
            raise ValueError("reference_tree_node_position_invalid")
    elif item_type == "root":
        if (
            domain != WIDE_ROOT_DOMAIN
            or position_value != 0
            or child_height_value != height_value
            or len(payloads) != 1
        ):
            raise ValueError("reference_tree_root_shape_invalid")
    elif item_type == "manifest":
        if (
            domain != RECORD_MANIFEST_DOMAIN
            or position_value != 0
            or child_height_value != 0
            or len(payloads) != length_value
        ):
            raise ValueError("reference_tree_manifest_shape_invalid")
    else:
        raise ValueError("reference_tree_item_type_invalid")
    out = bytearray(TREE_OPERATION_MAGIC)
    for value in (
        _bytes("reference_tree_domain", domain),
        PROFILE_ID,
        REFERENCE_SCHEMA_ID,
        tree_kind_value,
        item_type_value,
        record_type_value,
    ):
        out.extend(_lp16(value))
    out.extend(position_value.to_bytes(8, "big"))
    out.extend(length_value.to_bytes(8, "big"))
    out.extend(height_value.to_bytes(4, "big"))
    out.extend(child_height_value.to_bytes(4, "big"))
    out.extend(len(payloads).to_bytes(2, "big"))
    for payload in payloads:
        out.extend(_lp32(_bytes("reference_tree_payload", payload)))
    return bytes(out)


def _wide_digest(preimage: bytes) -> bytes:
    return sha3_512(_bytes("wide_preimage", preimage)).digest()


def _legacy_felt(preimage: bytes) -> int:
    """Reference field hash over raw bytes; independent of every wide value."""

    raw = _bytes("legacy_reference_preimage", preimage)
    chunks = tuple(int.from_bytes(raw[index : index + 30], "big") for index in range(0, len(raw), 30))
    acc = domain_poseidon_hash(
        _LEGACY_REFERENCE_OUTER_DOMAIN,
        [LEGACY_REFERENCE_POSEIDON_TAG, len(raw), len(chunks)],
    )
    for index, chunk in enumerate(chunks):
        acc = domain_poseidon_hash(
            _LEGACY_REFERENCE_OUTER_DOMAIN,
            [
                LEGACY_REFERENCE_POSEIDON_TAG,
                len(raw),
                len(chunks),
                index,
                acc,
                chunk,
            ],
        )
    return acc


def _legacy_felt_many(preimages: Sequence[bytes]) -> tuple[int, ...]:
    """Hash independent legacy preimages in bulk without changing semantics.

    ``_legacy_felt`` is intentionally sequential within one preimage because
    every chunk absorbs the previous accumulator.  Complete trees contain many
    independent preimages at each level, however, so those equal-depth absorbs
    can be sent to the reviewed Poseidon helper in bounded batches.  This keeps
    the exact scalar construction while avoiding one IPC round trip per node.
    """

    raws = tuple(_bytes("legacy_reference_preimage", value) for value in preimages)
    if not raws:
        return ()
    chunks_by_preimage = tuple(
        tuple(
            int.from_bytes(raw[index : index + 30], "big")
            for index in range(0, len(raw), 30)
        )
        for raw in raws
    )
    accumulators = domain_poseidon_many(
        _LEGACY_REFERENCE_OUTER_DOMAIN,
        (
            [LEGACY_REFERENCE_POSEIDON_TAG, len(raw), len(chunks)]
            for raw, chunks in zip(raws, chunks_by_preimage, strict=True)
        ),
    )
    maximum_chunks = max((len(chunks) for chunks in chunks_by_preimage), default=0)
    for chunk_index in range(maximum_chunks):
        active_indices = tuple(
            index
            for index, chunks in enumerate(chunks_by_preimage)
            if chunk_index < len(chunks)
        )
        next_values = domain_poseidon_many(
            _LEGACY_REFERENCE_OUTER_DOMAIN,
            (
                [
                    LEGACY_REFERENCE_POSEIDON_TAG,
                    len(raws[index]),
                    len(chunks_by_preimage[index]),
                    chunk_index,
                    accumulators[index],
                    chunks_by_preimage[index][chunk_index],
                ]
                for index in active_indices
            ),
        )
        for index, value in zip(active_indices, next_values, strict=True):
            accumulators[index] = value
    return tuple(accumulators)


def reference_legacy_felts(preimages: Sequence[bytes]) -> tuple[int, ...]:
    """Public synthetic-only bulk form of the exact legacy byte reference."""

    require_synthetic_reference_enabled()
    return _legacy_felt_many(preimages)


def reference_legacy_felt(preimage: bytes) -> int:
    """Public synthetic-only scalar form used to verify bulk equivalence."""

    require_synthetic_reference_enabled()
    return _legacy_felt(preimage)


def reference_wide_leaf(
    canonical_record: bytes,
    *,
    tree_kind: str,
    position: int,
    length: int,
    tree_height: int,
) -> bytes:
    record = parse_canonical_record(canonical_record)
    require_synthetic_canonical_record(record)
    return _wide_digest(
        _tree_operation_preimage(
            WIDE_LEAF_DOMAIN,
            tree_kind=tree_kind,
            item_type="leaf",
            record_type=record.record_type,
            position=position,
            length=length,
            tree_height=tree_height,
            child_height=0,
            payloads=(record.encoded,),
        )
    )


def reference_wide_empty(*, tree_kind: str, position: int, length: int, tree_height: int) -> bytes:
    require_synthetic_reference_enabled()
    return _wide_digest(
        _tree_operation_preimage(
            WIDE_EMPTY_DOMAIN,
            tree_kind=tree_kind,
            item_type="empty",
            record_type="empty",
            position=position,
            length=length,
            tree_height=tree_height,
            child_height=0,
            payloads=(),
        )
    )


def reference_wide_node(
    left: bytes,
    right: bytes,
    *,
    tree_kind: str,
    position: int,
    length: int,
    tree_height: int,
    child_height: int,
) -> bytes:
    require_synthetic_reference_enabled()
    return _wide_digest(
        _tree_operation_preimage(
            WIDE_NODE_DOMAIN,
            tree_kind=tree_kind,
            item_type="node",
            record_type="aggregate",
            position=position,
            length=length,
            tree_height=tree_height,
            child_height=child_height,
            payloads=(
                _bytes("wide_left_child", left, exact_length=64),
                _bytes("wide_right_child", right, exact_length=64),
            ),
        )
    )


def reference_wide_root(
    top: bytes,
    *,
    tree_kind: str,
    length: int,
    tree_height: int,
) -> bytes:
    require_synthetic_reference_enabled()
    return _wide_digest(
        _tree_operation_preimage(
            WIDE_ROOT_DOMAIN,
            tree_kind=tree_kind,
            item_type="root",
            record_type="tree_root",
            position=0,
            length=length,
            tree_height=tree_height,
            child_height=tree_height,
            payloads=(_bytes("wide_top", top, exact_length=64),),
        )
    )


def _legacy_leaf(record: CanonicalRecord, *, tree_kind: str, position: int, length: int, tree_height: int) -> int:
    return _legacy_felt(
        _tree_operation_preimage(
            WIDE_LEAF_DOMAIN,
            tree_kind=tree_kind,
            item_type="leaf",
            record_type=record.record_type,
            position=position,
            length=length,
            tree_height=tree_height,
            child_height=0,
            payloads=(record.encoded,),
        )
    )


def _legacy_empty(*, tree_kind: str, position: int, length: int, tree_height: int) -> int:
    return _legacy_felt(
        _tree_operation_preimage(
            WIDE_EMPTY_DOMAIN,
            tree_kind=tree_kind,
            item_type="empty",
            record_type="empty",
            position=position,
            length=length,
            tree_height=tree_height,
            child_height=0,
            payloads=(),
        )
    )


def _legacy_node(
    left: int,
    right: int,
    *,
    tree_kind: str,
    position: int,
    length: int,
    tree_height: int,
    child_height: int,
) -> int:
    return _legacy_felt(
        _tree_operation_preimage(
            WIDE_NODE_DOMAIN,
            tree_kind=tree_kind,
            item_type="node",
            record_type="aggregate",
            position=position,
            length=length,
            tree_height=tree_height,
            child_height=child_height,
            payloads=(int(left).to_bytes(32, "big"), int(right).to_bytes(32, "big")),
        )
    )


def _legacy_root(top: int, *, tree_kind: str, length: int, tree_height: int) -> int:
    return _legacy_felt(
        _tree_operation_preimage(
            WIDE_ROOT_DOMAIN,
            tree_kind=tree_kind,
            item_type="root",
            record_type="tree_root",
            position=0,
            length=length,
            tree_height=tree_height,
            child_height=tree_height,
            payloads=(int(top).to_bytes(32, "big"),),
        )
    )


@dataclass(frozen=True, slots=True)
class DualTreeReference:
    tree_kind: str
    tree_height: int
    canonical_records: tuple[bytes, ...]
    record_manifest_sha3_512: bytes
    legacy_leaf_felts: tuple[int, ...]
    wide_leaf_digests: tuple[bytes, ...]
    legacy_root_felt: int
    wide_root_sha3_512: bytes

    def __post_init__(self) -> None:
        require_synthetic_reference_enabled()


@dataclass(frozen=True, slots=True)
class DualTreeMembershipProof:
    """Exact independent legacy/wide membership path for one canonical record."""

    tree_kind: str
    tree_height: int
    record_count: int
    position: int
    canonical_record: bytes
    legacy_leaf_felt: int
    wide_leaf_sha3_512: bytes
    legacy_siblings: tuple[int, ...]
    wide_siblings_sha3_512: tuple[bytes, ...]
    legacy_root_felt: int
    wide_root_sha3_512: bytes

    def __post_init__(self) -> None:
        require_synthetic_reference_enabled()
        _identifier("membership_tree_kind", self.tree_kind)
        height = _uint("membership_tree_height", self.tree_height, bits=32)
        if height > MAX_REFERENCE_TREE_HEIGHT:
            raise ValueError("membership_tree_height_exceeds_synthetic_limit")
        count = _uint("membership_record_count", self.record_count, bits=64)
        position = _uint("membership_position", self.position, bits=64)
        if count == 0 or count > (1 << height) or position >= count:
            raise ValueError("membership_position_or_count_invalid")
        record = parse_canonical_record(
            _bytes("membership_canonical_record", self.canonical_record)
        )
        require_synthetic_canonical_record(record)
        if (
            type(self.legacy_leaf_felt) is not int
            or not 0 <= self.legacy_leaf_felt < FIELD_MODULUS
            or type(self.legacy_root_felt) is not int
            or not 0 <= self.legacy_root_felt < FIELD_MODULUS
        ):
            raise ValueError("membership_legacy_value_not_canonical_felt")
        _bytes(
            "membership_wide_leaf",
            self.wide_leaf_sha3_512,
            exact_length=64,
        )
        _bytes(
            "membership_wide_root",
            self.wide_root_sha3_512,
            exact_length=64,
        )
        if (
            type(self.legacy_siblings) is not tuple
            or len(self.legacy_siblings) != height
            or any(
                type(value) is not int or not 0 <= value < FIELD_MODULUS
                for value in self.legacy_siblings
            )
        ):
            raise ValueError("membership_legacy_siblings_invalid")
        if (
            type(self.wide_siblings_sha3_512) is not tuple
            or len(self.wide_siblings_sha3_512) != height
            or any(
                type(value) is not bytes or len(value) != 64
                for value in self.wide_siblings_sha3_512
            )
        ):
            raise ValueError("membership_wide_siblings_invalid")


def _derive_dual_tree_reference_and_levels(
    canonical_records: Iterable[bytes],
    *,
    tree_kind: str,
    tree_height: int,
) -> tuple[
    DualTreeReference,
    tuple[tuple[int, ...], ...],
    tuple[tuple[bytes, ...], ...],
]:
    """Build independent field and SHA3-512 trees from one exact raw record tuple."""

    require_synthetic_reference_enabled()
    kind = _identifier("reference_tree_kind", tree_kind)
    height = _uint("reference_tree_height", tree_height, bits=32)
    if height > MAX_REFERENCE_TREE_HEIGHT:
        raise ValueError("reference_tree_height_exceeds_synthetic_limit")
    capacity = 1 << height
    supplied = tuple(islice(iter(canonical_records), capacity + 1))
    if len(supplied) > capacity:
        raise ValueError("reference_tree_capacity_exceeded")
    parsed = tuple(parse_canonical_record(_bytes("canonical_record", item)) for item in supplied)
    for record in parsed:
        require_synthetic_canonical_record(record)
    ordered = tuple(sorted((record.encoded for record in parsed)))
    if len(set(ordered)) != len(ordered):
        raise ValueError("reference_tree_duplicate_canonical_record")
    reparsed = tuple(parse_canonical_record(item) for item in ordered)
    length = len(reparsed)

    leaf_preimages: list[bytes] = []
    wide_level: list[bytes] = []
    wide_leaves: list[bytes] = []
    for position in range(capacity):
        if position < length:
            record = reparsed[position]
            preimage = _tree_operation_preimage(
                WIDE_LEAF_DOMAIN,
                tree_kind=kind,
                item_type="leaf",
                record_type=record.record_type,
                position=position,
                length=length,
                tree_height=height,
                child_height=0,
                payloads=(record.encoded,),
            )
            wide = _wide_digest(preimage)
            wide_leaves.append(wide)
        else:
            preimage = _tree_operation_preimage(
                WIDE_EMPTY_DOMAIN,
                tree_kind=kind,
                item_type="empty",
                record_type="empty",
                position=position,
                length=length,
                tree_height=height,
                child_height=0,
                payloads=(),
            )
            wide = _wide_digest(preimage)
        leaf_preimages.append(preimage)
        wide_level.append(wide)
    legacy_level = list(_legacy_felt_many(leaf_preimages))
    legacy_leaves = legacy_level[:length]
    legacy_levels: list[tuple[int, ...]] = [tuple(legacy_level)]
    wide_levels: list[tuple[bytes, ...]] = [tuple(wide_level)]

    for child_height in range(height):
        node_preimages: list[bytes] = []
        next_wide: list[bytes] = []
        for offset in range(0, len(legacy_level), 2):
            position = offset // 2
            legacy_preimage = _tree_operation_preimage(
                WIDE_NODE_DOMAIN,
                tree_kind=kind,
                item_type="node",
                record_type="aggregate",
                position=position,
                length=length,
                tree_height=height,
                child_height=child_height,
                payloads=(
                    int(legacy_level[offset]).to_bytes(32, "big"),
                    int(legacy_level[offset + 1]).to_bytes(32, "big"),
                ),
            )
            wide_preimage = _tree_operation_preimage(
                WIDE_NODE_DOMAIN,
                tree_kind=kind,
                item_type="node",
                record_type="aggregate",
                position=position,
                length=length,
                tree_height=height,
                child_height=child_height,
                payloads=(wide_level[offset], wide_level[offset + 1]),
            )
            node_preimages.append(legacy_preimage)
            next_wide.append(_wide_digest(wide_preimage))
        legacy_level = list(_legacy_felt_many(node_preimages))
        wide_level = next_wide
        legacy_levels.append(tuple(legacy_level))
        wide_levels.append(tuple(wide_level))

    manifest_preimage = _tree_operation_preimage(
        RECORD_MANIFEST_DOMAIN,
        tree_kind=kind,
        item_type="manifest",
        record_type="raw_record_manifest",
        position=0,
        length=length,
        tree_height=height,
        child_height=0,
        payloads=ordered,
    )
    reference = DualTreeReference(
        tree_kind=kind,
        tree_height=height,
        canonical_records=ordered,
        record_manifest_sha3_512=sha3_512(manifest_preimage).digest(),
        legacy_leaf_felts=tuple(legacy_leaves),
        wide_leaf_digests=tuple(wide_leaves),
        legacy_root_felt=_legacy_root(
            legacy_level[0], tree_kind=kind, length=length, tree_height=height
        ),
        wide_root_sha3_512=reference_wide_root(
            wide_level[0], tree_kind=kind, length=length, tree_height=height
        ),
    )
    return reference, tuple(legacy_levels), tuple(wide_levels)


def derive_dual_tree_reference(
    canonical_records: Iterable[bytes],
    *,
    tree_kind: str,
    tree_height: int,
) -> DualTreeReference:
    """Build independent field and SHA3-512 trees from one exact raw record tuple."""

    return _derive_dual_tree_reference_and_levels(
        canonical_records,
        tree_kind=tree_kind,
        tree_height=tree_height,
    )[0]


def _dual_tree_levels(
    reference: DualTreeReference,
) -> tuple[tuple[tuple[int, ...], ...], tuple[tuple[bytes, ...], ...]]:
    """Rebuild every level for path extraction and assert root agreement."""

    if not isinstance(reference, DualTreeReference):
        raise TypeError("membership_reference_type_invalid")
    require_synthetic_reference_enabled()
    kind = _identifier("membership_tree_kind", reference.tree_kind)
    height = _uint("membership_tree_height", reference.tree_height, bits=32)
    if height > MAX_REFERENCE_TREE_HEIGHT:
        raise ValueError("membership_tree_height_exceeds_synthetic_limit")
    capacity = 1 << height
    ordered = reference.canonical_records
    if type(ordered) is not tuple or not 0 < len(ordered) <= capacity:
        raise ValueError("membership_reference_record_count_invalid")
    if tuple(sorted(ordered)) != ordered or len(set(ordered)) != len(ordered):
        raise ValueError("membership_reference_records_not_canonical")
    parsed = tuple(parse_canonical_record(value) for value in ordered)
    for record in parsed:
        require_synthetic_canonical_record(record)
    length = len(parsed)

    leaf_preimages: list[bytes] = []
    wide_level: list[bytes] = []
    for position in range(capacity):
        if position < length:
            record = parsed[position]
            preimage = _tree_operation_preimage(
                WIDE_LEAF_DOMAIN,
                tree_kind=kind,
                item_type="leaf",
                record_type=record.record_type,
                position=position,
                length=length,
                tree_height=height,
                child_height=0,
                payloads=(record.encoded,),
            )
        else:
            preimage = _tree_operation_preimage(
                WIDE_EMPTY_DOMAIN,
                tree_kind=kind,
                item_type="empty",
                record_type="empty",
                position=position,
                length=length,
                tree_height=height,
                child_height=0,
                payloads=(),
            )
        leaf_preimages.append(preimage)
        wide_level.append(_wide_digest(preimage))
    legacy_level = list(_legacy_felt_many(leaf_preimages))
    legacy_levels: list[tuple[int, ...]] = [tuple(legacy_level)]
    wide_levels: list[tuple[bytes, ...]] = [tuple(wide_level)]

    for child_height in range(height):
        legacy_preimages: list[bytes] = []
        next_wide: list[bytes] = []
        for offset in range(0, len(legacy_level), 2):
            position = offset // 2
            legacy_preimages.append(
                _tree_operation_preimage(
                    WIDE_NODE_DOMAIN,
                    tree_kind=kind,
                    item_type="node",
                    record_type="aggregate",
                    position=position,
                    length=length,
                    tree_height=height,
                    child_height=child_height,
                    payloads=(
                        legacy_level[offset].to_bytes(32, "big"),
                        legacy_level[offset + 1].to_bytes(32, "big"),
                    ),
                )
            )
            next_wide.append(
                _wide_digest(
                    _tree_operation_preimage(
                        WIDE_NODE_DOMAIN,
                        tree_kind=kind,
                        item_type="node",
                        record_type="aggregate",
                        position=position,
                        length=length,
                        tree_height=height,
                        child_height=child_height,
                        payloads=(wide_level[offset], wide_level[offset + 1]),
                    )
                )
            )
        legacy_level = list(_legacy_felt_many(legacy_preimages))
        wide_level = next_wide
        legacy_levels.append(tuple(legacy_level))
        wide_levels.append(tuple(wide_level))

    observed_legacy_root = _legacy_root(
        legacy_level[0], tree_kind=kind, length=length, tree_height=height
    )
    observed_wide_root = reference_wide_root(
        wide_level[0], tree_kind=kind, length=length, tree_height=height
    )
    if observed_legacy_root != reference.legacy_root_felt:
        raise ValueError("membership_reference_legacy_root_mismatch")
    if not hmac.compare_digest(observed_wide_root, reference.wide_root_sha3_512):
        raise ValueError("membership_reference_wide_root_mismatch")
    return tuple(legacy_levels), tuple(wide_levels)


def derive_dual_tree_membership_proof(
    reference: DualTreeReference,
    canonical_record: bytes,
) -> DualTreeMembershipProof:
    """Extract one exact membership path from a previously derived dual tree."""

    if not isinstance(reference, DualTreeReference):
        raise TypeError("membership_reference_type_invalid")
    record = parse_canonical_record(
        _bytes("membership_canonical_record", canonical_record)
    )
    require_synthetic_canonical_record(record)
    try:
        position = reference.canonical_records.index(record.encoded)
    except ValueError as exc:
        raise ValueError("membership_record_not_in_reference") from exc
    legacy_levels, wide_levels = _dual_tree_levels(reference)
    return _dual_membership_proof_at(
        reference, position, legacy_levels, wide_levels
    )


def _dual_membership_proof_at(
    reference: DualTreeReference,
    position: int,
    legacy_levels: tuple[tuple[int, ...], ...],
    wide_levels: tuple[tuple[bytes, ...], ...],
) -> DualTreeMembershipProof:
    return DualTreeMembershipProof(
        tree_kind=reference.tree_kind,
        tree_height=reference.tree_height,
        record_count=len(reference.canonical_records),
        position=position,
        canonical_record=reference.canonical_records[position],
        legacy_leaf_felt=legacy_levels[0][position],
        wide_leaf_sha3_512=wide_levels[0][position],
        legacy_siblings=tuple(
            legacy_levels[child_height][(position >> child_height) ^ 1]
            for child_height in range(reference.tree_height)
        ),
        wide_siblings_sha3_512=tuple(
            wide_levels[child_height][(position >> child_height) ^ 1]
            for child_height in range(reference.tree_height)
        ),
        legacy_root_felt=reference.legacy_root_felt,
        wide_root_sha3_512=reference.wide_root_sha3_512,
    )


def derive_all_dual_tree_membership_proofs(
    reference: DualTreeReference,
) -> tuple[DualTreeMembershipProof, ...]:
    """Extract all paths with one level rebuild rather than one rebuild per record."""

    if not isinstance(reference, DualTreeReference):
        raise TypeError("membership_reference_type_invalid")
    legacy_levels, wide_levels = _dual_tree_levels(reference)
    return tuple(
        _dual_membership_proof_at(reference, position, legacy_levels, wide_levels)
        for position in range(len(reference.canonical_records))
    )


def derive_dual_tree_reference_with_membership_proofs(
    canonical_records: Iterable[bytes],
    *,
    tree_kind: str,
    tree_height: int,
) -> tuple[DualTreeReference, tuple[DualTreeMembershipProof, ...]]:
    """Build one dual tree and all paths in the same level traversal."""

    reference, legacy_levels, wide_levels = _derive_dual_tree_reference_and_levels(
        canonical_records,
        tree_kind=tree_kind,
        tree_height=tree_height,
    )
    return reference, tuple(
        _dual_membership_proof_at(reference, position, legacy_levels, wide_levels)
        for position in range(len(reference.canonical_records))
    )


def verify_dual_tree_membership_proof(
    proof: DualTreeMembershipProof,
    *,
    expected_legacy_root_felt: int,
    expected_wide_root_sha3_512: bytes,
) -> bool:
    """Verify both paths against separately governed roots, failing closed."""

    if not isinstance(proof, DualTreeMembershipProof):
        raise TypeError("membership_proof_type_invalid")
    proof.__post_init__()
    if (
        type(expected_legacy_root_felt) is not int
        or not 0 <= expected_legacy_root_felt < FIELD_MODULUS
    ):
        raise ValueError("membership_expected_legacy_root_invalid")
    expected_wide = _bytes(
        "membership_expected_wide_root",
        expected_wide_root_sha3_512,
        exact_length=64,
    )
    record = parse_canonical_record(proof.canonical_record)
    legacy = _legacy_leaf(
        record,
        tree_kind=proof.tree_kind,
        position=proof.position,
        length=proof.record_count,
        tree_height=proof.tree_height,
    )
    wide = reference_wide_leaf(
        record.encoded,
        tree_kind=proof.tree_kind,
        position=proof.position,
        length=proof.record_count,
        tree_height=proof.tree_height,
    )
    if legacy != proof.legacy_leaf_felt:
        raise ValueError("membership_legacy_leaf_mismatch")
    if not hmac.compare_digest(wide, proof.wide_leaf_sha3_512):
        raise ValueError("membership_wide_leaf_mismatch")

    cursor = proof.position
    for child_height, (legacy_sibling, wide_sibling) in enumerate(
        zip(
            proof.legacy_siblings,
            proof.wide_siblings_sha3_512,
            strict=True,
        )
    ):
        parent_position = cursor >> 1
        if cursor & 1:
            legacy_left, legacy_right = legacy_sibling, legacy
            wide_left, wide_right = wide_sibling, wide
        else:
            legacy_left, legacy_right = legacy, legacy_sibling
            wide_left, wide_right = wide, wide_sibling
        legacy = _legacy_node(
            legacy_left,
            legacy_right,
            tree_kind=proof.tree_kind,
            position=parent_position,
            length=proof.record_count,
            tree_height=proof.tree_height,
            child_height=child_height,
        )
        wide = reference_wide_node(
            wide_left,
            wide_right,
            tree_kind=proof.tree_kind,
            position=parent_position,
            length=proof.record_count,
            tree_height=proof.tree_height,
            child_height=child_height,
        )
        cursor = parent_position

    legacy_root = _legacy_root(
        legacy,
        tree_kind=proof.tree_kind,
        length=proof.record_count,
        tree_height=proof.tree_height,
    )
    wide_root = reference_wide_root(
        wide,
        tree_kind=proof.tree_kind,
        length=proof.record_count,
        tree_height=proof.tree_height,
    )
    if legacy_root != proof.legacy_root_felt:
        raise ValueError("membership_proof_legacy_root_mismatch")
    if not hmac.compare_digest(wide_root, proof.wide_root_sha3_512):
        raise ValueError("membership_proof_wide_root_mismatch")
    if legacy_root != expected_legacy_root_felt:
        raise ValueError("membership_governed_legacy_root_mismatch")
    if not hmac.compare_digest(wide_root, expected_wide):
        raise ValueError("membership_governed_wide_root_mismatch")
    return True


def _strict_object(value: object, *, label: str, keys: set[str]) -> dict[str, object]:
    if not isinstance(value, dict):
        raise TypeError(f"{label}_must_be_object")
    actual = set(value)
    if actual != keys:
        missing = sorted(keys - actual)
        extra = sorted(actual - keys)
        raise ValueError(f"{label}_keys_invalid:missing={missing}:extra={extra}")
    return value


def _strict_json(raw: bytes) -> object:
    if len(raw) > MAX_FOUNDATION_VECTOR_BYTES:
        raise ValueError("foundation_vector_exceeds_size_limit")

    def pairs_hook(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"foundation_vector_duplicate_key:{key}")
            result[key] = value
        return result

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("foundation_vector_not_utf8") from exc
    try:
        return json.loads(text, object_pairs_hook=pairs_hook)
    except json.JSONDecodeError as exc:
        raise ValueError("foundation_vector_json_invalid") from exc


def _hex_value(label: str, value: object, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ValueError(f"{label}_not_canonical_hex")
    return value


def _decimal_value(label: str, value: object, *, bits: int) -> int:
    if not isinstance(value, str) or _DECIMAL_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{label}_not_canonical_decimal")
    return _uint(label, int(value), bits=bits)


def _u64_hex_value(label: str, value: object) -> int:
    canonical = _hex_value(label, value, _LOWER_HEX_8)
    return int(canonical, 16)


def parse_foundation_vector_json(raw: bytes) -> dict[str, object]:
    """Strictly parse and recompute the synthetic T01 foundation vector."""

    require_synthetic_reference_enabled()
    data = _strict_object(
        _strict_json(_bytes("foundation_vector", raw)),
        label="foundation_vector",
        keys={
            "vectorSchema",
            "referenceStatus",
            "profileId",
            "referenceSchemaId",
            "domainSuite",
            "caseId",
            "privateSemantics",
            "compatibilityOutputs",
            "wideSidecar",
        },
    )
    expected_constants = {
        "vectorSchema": FOUNDATION_VECTOR_SCHEMA,
        "referenceStatus": REFERENCE_STATUS,
        "profileId": PROFILE_ID.decode("ascii"),
        "referenceSchemaId": REFERENCE_SCHEMA_ID.decode("ascii"),
        "domainSuite": REFERENCE_DOMAIN_SUITE,
    }
    for key, expected in expected_constants.items():
        if data[key] != expected:
            raise ValueError(f"foundation_vector_{key}_mismatch")
    case_id = data["caseId"]
    if (
        not isinstance(case_id, str)
        or not case_id.startswith("synthetic-")
        or case_id == "synthetic-"
    ):
        raise ValueError("foundation_vector_case_id_not_synthetic")
    _identifier("foundation_vector_case_id", case_id)

    private = _strict_object(
        data["privateSemantics"],
        label="foundation_vector_private_semantics",
        keys={
            "syntheticOnly",
            "snapshotId",
            "snapshotVersion",
            "decision",
            "failureCode",
            "allowedCents",
            "payableCents",
            "canonicalRecordsHex",
            "orderedOperations",
            "recordManifestSha3_512",
            "legacyTree",
            "wideTree",
        },
    )
    if private["syntheticOnly"] is not True:
        raise ValueError("foundation_vector_must_be_synthetic")
    snapshot_id = private["snapshotId"]
    if (
        not isinstance(snapshot_id, str)
        or not snapshot_id.startswith("SYNTHETIC-")
        or snapshot_id == "SYNTHETIC-"
    ):
        raise ValueError("foundation_vector_snapshot_id_not_synthetic")
    _proof_identifier("foundation_vector_snapshot_id", snapshot_id)
    snapshot_version = _uint(
        "foundation_vector_snapshot_version", private["snapshotVersion"], bits=32
    )
    if snapshot_version != 0:
        raise ValueError("foundation_vector_snapshot_version_mismatch")
    if private["decision"] not in {"approved", "denied", "padding"}:
        raise ValueError("foundation_vector_decision_invalid")
    failure_code = _uint("foundation_vector_failure_code", private["failureCode"], bits=32)
    if failure_code > 13:
        raise ValueError("foundation_vector_failure_code_out_of_taxonomy")
    allowed_cents = _u64_hex_value("foundation_vector_allowed_cents", private["allowedCents"])
    payable_cents = _u64_hex_value("foundation_vector_payable_cents", private["payableCents"])
    if private["decision"] == "approved" and (
        failure_code != 0 or payable_cents != allowed_cents
    ):
        raise ValueError("foundation_vector_approved_semantics_invalid")
    if private["decision"] == "denied" and (
        failure_code == 0 or payable_cents != 0
    ):
        raise ValueError("foundation_vector_denied_semantics_invalid")
    if private["decision"] == "padding" and (
        failure_code != 0 or allowed_cents != 0 or payable_cents != 0
    ):
        raise ValueError("foundation_vector_padding_semantics_invalid")
    operations = private["orderedOperations"]
    if (
        not isinstance(operations, list)
        or not operations
        or len(operations) > MAX_FOUNDATION_OPERATIONS
        or any(
        not isinstance(item, str) or _IDENTIFIER_PATTERN.fullmatch(item) is None for item in operations
        )
    ):
        raise ValueError("foundation_vector_ordered_operations_invalid")
    record_hex = private["canonicalRecordsHex"]
    if (
        not isinstance(record_hex, list)
        or not record_hex
        or len(record_hex) > MAX_FOUNDATION_VECTOR_RECORDS
    ):
        raise ValueError("foundation_vector_canonical_records_invalid")
    records = tuple(
        bytes.fromhex(_hex_value("foundation_vector_canonical_record", item, _LOWER_EVEN_HEX))
        for item in record_hex
    )
    for record in records:
        require_synthetic_canonical_record(parse_canonical_record(record))

    legacy_tree = _strict_object(
        private["legacyTree"],
        label="foundation_vector_legacy_tree",
        keys={"treeKind", "treeHeight", "leafFeltHex", "rootFeltHex"},
    )
    wide_tree = _strict_object(
        private["wideTree"],
        label="foundation_vector_wide_tree",
        keys={"treeKind", "treeHeight", "leafSha3_512", "rootSha3_512"},
    )
    legacy_kind = _identifier("foundation_vector_legacy_tree_kind", legacy_tree["treeKind"])
    wide_kind = _identifier("foundation_vector_wide_tree_kind", wide_tree["treeKind"])
    if legacy_kind != wide_kind:
        raise ValueError("foundation_vector_tree_kind_mismatch")
    legacy_height = _uint(
        "foundation_vector_legacy_tree_height", legacy_tree["treeHeight"], bits=32
    )
    wide_height = _uint(
        "foundation_vector_wide_tree_height", wide_tree["treeHeight"], bits=32
    )
    if legacy_height != wide_height:
        raise ValueError("foundation_vector_tree_height_mismatch")
    derived = derive_dual_tree_reference(
        records,
        tree_kind=legacy_kind,
        tree_height=legacy_height,
    )
    legacy_leaves = legacy_tree["leafFeltHex"]
    wide_leaves = wide_tree["leafSha3_512"]
    if not isinstance(legacy_leaves, list) or not isinstance(wide_leaves, list):
        raise TypeError("foundation_vector_tree_leaves_must_be_arrays")
    expected_legacy_leaves = [f"{value:064x}" for value in derived.legacy_leaf_felts]
    expected_wide_leaves = [value.hex() for value in derived.wide_leaf_digests]
    if legacy_leaves != expected_legacy_leaves or wide_leaves != expected_wide_leaves:
        raise ValueError("foundation_vector_tree_leaf_mismatch")
    if _hex_value("foundation_vector_legacy_root", legacy_tree["rootFeltHex"], _LOWER_HEX_32) != f"{derived.legacy_root_felt:064x}":
        raise ValueError("foundation_vector_legacy_root_mismatch")
    if _hex_value("foundation_vector_wide_root", wide_tree["rootSha3_512"], _LOWER_HEX_64) != derived.wide_root_sha3_512.hex():
        raise ValueError("foundation_vector_wide_root_mismatch")
    if _hex_value(
        "foundation_vector_record_manifest",
        private["recordManifestSha3_512"],
        _LOWER_HEX_64,
    ) != derived.record_manifest_sha3_512.hex():
        raise ValueError("foundation_vector_record_manifest_mismatch")
    if [item.hex() for item in derived.canonical_records] != record_hex:
        raise ValueError("foundation_vector_records_not_canonical_order")

    outputs = data["compatibilityOutputs"]
    if not isinstance(outputs, list) or len(outputs) != len(PUBLIC_OUTPUT_NAMES):
        raise ValueError("foundation_vector_public_output_count_mismatch")
    output_felts: list[int] = []
    for index, (item, expected_name) in enumerate(zip(outputs, PUBLIC_OUTPUT_NAMES)):
        output = _strict_object(
            item,
            label=f"foundation_vector_public_output_{index}",
            keys={"index", "name", "feltHex"},
        )
        output_index = _uint(
            "foundation_vector_public_output_index", output["index"], bits=8
        )
        if output_index != index or output["name"] != expected_name:
            raise ValueError("foundation_vector_public_output_order_mismatch")
        felt_hex = _hex_value("foundation_vector_public_output", output["feltHex"], _LOWER_HEX_32)
        felt = int(felt_hex, 16)
        if felt >= FIELD_MODULUS:
            raise ValueError("foundation_vector_public_output_not_canonical_felt")
        output_felts.append(felt)
    if output_felts[0] != 2:
        raise ValueError("foundation_vector_protocol_version_mismatch")
    if output_felts[1] == 0 or output_felts[2] == 0:
        raise ValueError("foundation_vector_domain_or_nonce_zero")
    if output_felts[3] == output_felts[4]:
        raise ValueError("foundation_vector_nullifier_root_unchanged")

    sidecar = _strict_object(
        data["wideSidecar"],
        label="foundation_vector_wide_sidecar",
        keys={
            "profileId",
            "proofSuiteId",
            "schemaId",
            "epoch",
            "sequenceBefore",
            "sequenceAfter",
            "strongNullifierRootBefore",
            "strongNullifierRootAfter",
            "strongGovernanceCommitment",
            "strongPaymentStateBinding",
            "verifierArtifactIdentity",
            "strongBatchCommitment",
            "encodingStatus",
        },
    )
    if sidecar["profileId"] != PROFILE_ID.decode("ascii"):
        raise ValueError("foundation_vector_sidecar_profile_mismatch")
    if sidecar["proofSuiteId"] != UNSELECTED_PROOF_SUITE_ID:
        raise ValueError("foundation_vector_sidecar_proof_suite_mismatch")
    if sidecar["schemaId"] != FOUNDATION_STATEMENT_SCHEMA_ID:
        raise ValueError("foundation_vector_sidecar_schema_mismatch")
    if sidecar["encodingStatus"] != "LOGICAL_PLACEHOLDERS_S04_P06_OPEN_NOT_AUTHENTICATED":
        raise ValueError("foundation_vector_sidecar_encoding_status_mismatch")
    payment_binding = _strict_object(
        sidecar["strongPaymentStateBinding"],
        label="foundation_vector_strong_payment_state_binding",
        keys={"status", "bindingKind", "bindingValue"},
    )
    if (
        payment_binding["status"] != UNRESOLVED_PAYMENT_BINDING_STATUS
        or payment_binding["bindingKind"] != "TBD"
        or payment_binding["bindingValue"] is not None
    ):
        raise ValueError("foundation_vector_payment_state_binding_not_explicitly_unresolved")
    epoch = _u64_hex_value("foundation_vector_sidecar_epoch", sidecar["epoch"])
    before = _u64_hex_value(
        "foundation_vector_sidecar_sequence_before", sidecar["sequenceBefore"]
    )
    after = _u64_hex_value(
        "foundation_vector_sidecar_sequence_after", sidecar["sequenceAfter"]
    )
    if epoch == 0 or before == (1 << 64) - 1 or after != before + 1:
        raise ValueError("foundation_vector_sidecar_sequence_invalid")
    wide_names = (
        "strongNullifierRootBefore",
        "strongNullifierRootAfter",
        "strongGovernanceCommitment",
        "verifierArtifactIdentity",
        "strongBatchCommitment",
    )
    for name in wide_names:
        wide_value = _hex_value(
            f"foundation_vector_sidecar_{name}", sidecar[name], _LOWER_HEX_64
        )
        if int(wide_value, 16) == 0:
            raise ValueError(f"foundation_vector_sidecar_{name}_zero")
    if sidecar["strongNullifierRootBefore"] == sidecar["strongNullifierRootAfter"]:
        raise ValueError("foundation_vector_sidecar_root_unchanged")
    return data
