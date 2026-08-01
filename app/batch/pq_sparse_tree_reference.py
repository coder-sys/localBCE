"""Synthetic sparse dual-tree reference for persistent governed maps.

The complete-tree P01/P02 reference intentionally binds every physical empty
position and is suitable for small dense batch trees.  A governed depth-16
policy map must instead have reusable level-specific empty hashes, or rebuilding
one snapshot costs O(2**depth) even when only a few rows exist.  This module
defines that isolated synthetic candidate with O(entries * depth) work.

It is not a production tree, AIR constraint, proof-system choice, or activation
artifact.  Both legacy and SHA3-512 roots consume the same canonical records
and keys but are computed independently.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
import hmac
import re
from typing import Final, Iterable

from app.batch.poseidon import FIELD_MODULUS
from app.batch.pq_tree_reference import (
    CanonicalRecord,
    parse_canonical_record,
    reference_legacy_felts,
    require_synthetic_canonical_record,
    require_synthetic_reference_enabled,
)


SPARSE_REFERENCE_STATUS: Final[str] = (
    "SYNTHETIC_SPARSE_DUAL_TREE_REFERENCE_V0_NOT_PRODUCTION"
)
SPARSE_MAGIC: Final[bytes] = b"BL/PQ512/SPARSE-TREE/REFERENCE/v0"
SPARSE_LEAF_DOMAIN: Final[bytes] = b"BL/PQ512/SPARSE-TREE/LEAF/REFERENCE/v0"
SPARSE_EMPTY_DOMAIN: Final[bytes] = b"BL/PQ512/SPARSE-TREE/EMPTY/REFERENCE/v0"
SPARSE_NODE_DOMAIN: Final[bytes] = b"BL/PQ512/SPARSE-TREE/NODE/REFERENCE/v0"
SPARSE_ROOT_DOMAIN: Final[bytes] = b"BL/PQ512/SPARSE-TREE/ROOT/REFERENCE/v0"
SPARSE_MANIFEST_DOMAIN: Final[bytes] = b"BL/PQ512/SPARSE-TREE/MANIFEST/REFERENCE/v0"
MAX_SPARSE_REFERENCE_DEPTH: Final[int] = 64
MAX_SPARSE_REFERENCE_ENTRIES: Final[int] = 65_536
_IDENTIFIER: Final[re.Pattern[str]] = re.compile(r"[a-z][a-z0-9_.-]{0,63}\Z")


def _lp16(value: bytes) -> bytes:
    if len(value) > 0xFFFF:
        raise ValueError("sparse_reference_value_exceeds_u16")
    return len(value).to_bytes(2, "big") + value


def _lp32(value: bytes) -> bytes:
    if len(value) > 0xFFFFFFFF:
        raise ValueError("sparse_reference_value_exceeds_u32")
    return len(value).to_bytes(4, "big") + value


def _identifier(label: str, value: object) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"sparse_reference_{label}_invalid")
    return value


def _preimage(
    domain: bytes,
    *,
    tree_kind: str,
    record_type: str,
    tree_depth: int,
    child_height: int,
    payloads: tuple[bytes, ...],
) -> bytes:
    out = bytearray(SPARSE_MAGIC)
    out.extend(_lp16(domain))
    out.extend(_lp16(tree_kind.encode("ascii")))
    out.extend(_lp16(record_type.encode("ascii")))
    out.extend(tree_depth.to_bytes(1, "big"))
    out.extend(child_height.to_bytes(1, "big"))
    out.extend(len(payloads).to_bytes(4, "big"))
    for payload in payloads:
        out.extend(_lp32(payload))
    return bytes(out)


def _wide(preimage: bytes) -> bytes:
    return sha3_512(preimage).digest()


@dataclass(frozen=True, slots=True)
class SparseDualTreeReference:
    status: str
    tree_kind: str
    tree_depth: int
    keyed_records: tuple[tuple[int, bytes], ...]
    record_manifest_sha3_512: bytes
    legacy_leaf_felts: tuple[int, ...]
    wide_leaf_digests: tuple[bytes, ...]
    legacy_root_felt: int
    wide_root_sha3_512: bytes


@dataclass(frozen=True, slots=True)
class SparseDualMembershipProof:
    tree_kind: str
    tree_depth: int
    entry_count: int
    key: int
    canonical_record: bytes
    legacy_leaf_felt: int
    wide_leaf_sha3_512: bytes
    legacy_siblings: tuple[int, ...]
    wide_siblings_sha3_512: tuple[bytes, ...]
    legacy_root_felt: int
    wide_root_sha3_512: bytes

    def __post_init__(self) -> None:
        require_synthetic_reference_enabled()
        _validate_sparse_proof_shape(
            tree_kind=self.tree_kind,
            tree_depth=self.tree_depth,
            entry_count=self.entry_count,
            key=self.key,
            legacy_siblings=self.legacy_siblings,
            wide_siblings=self.wide_siblings_sha3_512,
            legacy_root=self.legacy_root_felt,
            wide_root=self.wide_root_sha3_512,
        )
        if self.entry_count == 0:
            raise ValueError("sparse_membership_entry_count_zero")
        record = parse_canonical_record(self.canonical_record)
        require_synthetic_canonical_record(record)
        if (
            type(self.legacy_leaf_felt) is not int
            or not 0 <= self.legacy_leaf_felt < FIELD_MODULUS
        ):
            raise ValueError("sparse_membership_legacy_leaf_invalid")
        if type(self.wide_leaf_sha3_512) is not bytes or len(self.wide_leaf_sha3_512) != 64:
            raise ValueError("sparse_membership_wide_leaf_invalid")


@dataclass(frozen=True, slots=True)
class SparseDualNonMembershipProof:
    tree_kind: str
    tree_depth: int
    entry_count: int
    key: int
    legacy_siblings: tuple[int, ...]
    wide_siblings_sha3_512: tuple[bytes, ...]
    legacy_root_felt: int
    wide_root_sha3_512: bytes

    def __post_init__(self) -> None:
        require_synthetic_reference_enabled()
        _validate_sparse_proof_shape(
            tree_kind=self.tree_kind,
            tree_depth=self.tree_depth,
            entry_count=self.entry_count,
            key=self.key,
            legacy_siblings=self.legacy_siblings,
            wide_siblings=self.wide_siblings_sha3_512,
            legacy_root=self.legacy_root_felt,
            wide_root=self.wide_root_sha3_512,
        )


def _validate_sparse_proof_shape(
    *,
    tree_kind: object,
    tree_depth: object,
    entry_count: object,
    key: object,
    legacy_siblings: object,
    wide_siblings: object,
    legacy_root: object,
    wide_root: object,
) -> None:
    _identifier("tree_kind", tree_kind)
    if type(tree_depth) is not int or not 1 <= tree_depth <= MAX_SPARSE_REFERENCE_DEPTH:
        raise ValueError("sparse_proof_tree_depth_invalid")
    if type(entry_count) is not int or not 0 <= entry_count <= MAX_SPARSE_REFERENCE_ENTRIES:
        raise ValueError("sparse_proof_entry_count_invalid")
    if type(key) is not int or not 0 <= key < (1 << tree_depth):
        raise ValueError("sparse_proof_key_out_of_range")
    if (
        type(legacy_siblings) is not tuple
        or len(legacy_siblings) != tree_depth
        or any(
            type(value) is not int or not 0 <= value < FIELD_MODULUS
            for value in legacy_siblings
        )
    ):
        raise ValueError("sparse_proof_legacy_siblings_invalid")
    if (
        type(wide_siblings) is not tuple
        or len(wide_siblings) != tree_depth
        or any(type(value) is not bytes or len(value) != 64 for value in wide_siblings)
    ):
        raise ValueError("sparse_proof_wide_siblings_invalid")
    if type(legacy_root) is not int or not 0 <= legacy_root < FIELD_MODULUS:
        raise ValueError("sparse_proof_legacy_root_invalid")
    if type(wide_root) is not bytes or len(wide_root) != 64:
        raise ValueError("sparse_proof_wide_root_invalid")


def _derive_sparse_dual_tree_reference_and_levels(
    keyed_records: Iterable[tuple[int, bytes]],
    *,
    tree_kind: str,
    tree_depth: int,
) -> tuple[
    SparseDualTreeReference,
    tuple[int, ...],
    tuple[bytes, ...],
    tuple[dict[int, int], ...],
    tuple[dict[int, bytes], ...],
]:
    """Build a level-default sparse tree from canonical keyed records."""

    require_synthetic_reference_enabled()
    kind = _identifier("tree_kind", tree_kind)
    if type(tree_depth) is not int or not 1 <= tree_depth <= MAX_SPARSE_REFERENCE_DEPTH:
        raise ValueError("sparse_reference_tree_depth_invalid")
    supplied = tuple(keyed_records)
    if len(supplied) > MAX_SPARSE_REFERENCE_ENTRIES:
        raise ValueError("sparse_reference_entry_count_exceeded")

    parsed: list[tuple[int, CanonicalRecord]] = []
    for entry in supplied:
        if type(entry) is not tuple or len(entry) != 2:
            raise TypeError("sparse_reference_entry_shape_invalid")
        key, encoded = entry
        if type(key) is not int or not 0 <= key < (1 << tree_depth):
            raise ValueError("sparse_reference_key_out_of_range")
        if type(encoded) is not bytes:
            raise TypeError("sparse_reference_record_not_bytes")
        record = parse_canonical_record(encoded)
        require_synthetic_canonical_record(record)
        parsed.append((key, record))
    parsed.sort(key=lambda item: item[0])
    keys = tuple(key for key, _ in parsed)
    if len(set(keys)) != len(keys):
        raise ValueError("sparse_reference_key_duplicate")

    empty_preimages: list[bytes] = [
        _preimage(
            SPARSE_EMPTY_DOMAIN,
            tree_kind=kind,
            record_type="empty",
            tree_depth=tree_depth,
            child_height=0,
            payloads=(),
        )
    ]
    legacy_empty: list[int] = [reference_legacy_felts(empty_preimages)[0]]
    wide_empty: list[bytes] = [_wide(empty_preimages[0])]
    for child_height in range(tree_depth):
        legacy_preimage = _preimage(
            SPARSE_NODE_DOMAIN,
            tree_kind=kind,
            record_type="aggregate",
            tree_depth=tree_depth,
            child_height=child_height,
            payloads=(
                legacy_empty[-1].to_bytes(32, "big"),
                legacy_empty[-1].to_bytes(32, "big"),
            ),
        )
        wide_preimage = _preimage(
            SPARSE_NODE_DOMAIN,
            tree_kind=kind,
            record_type="aggregate",
            tree_depth=tree_depth,
            child_height=child_height,
            payloads=(wide_empty[-1], wide_empty[-1]),
        )
        legacy_empty.append(reference_legacy_felts((legacy_preimage,))[0])
        wide_empty.append(_wide(wide_preimage))

    legacy_leaf_preimages = tuple(
        _preimage(
            SPARSE_LEAF_DOMAIN,
            tree_kind=kind,
            record_type=record.record_type,
            tree_depth=tree_depth,
            child_height=0,
            payloads=(key.to_bytes(8, "big"), record.encoded),
        )
        for key, record in parsed
    )
    wide_leaf_preimages = legacy_leaf_preimages
    legacy_leaves = reference_legacy_felts(legacy_leaf_preimages)
    wide_leaves = tuple(_wide(value) for value in wide_leaf_preimages)
    legacy_level = {
        key: value for key, value in zip(keys, legacy_leaves, strict=True)
    }
    wide_level = {
        key: value for key, value in zip(keys, wide_leaves, strict=True)
    }
    legacy_levels: list[dict[int, int]] = [legacy_level]
    wide_levels: list[dict[int, bytes]] = [wide_level]

    for child_height in range(tree_depth):
        parents = sorted({key >> 1 for key in legacy_level})
        legacy_preimages = tuple(
            _preimage(
                SPARSE_NODE_DOMAIN,
                tree_kind=kind,
                record_type="aggregate",
                tree_depth=tree_depth,
                child_height=child_height,
                payloads=(
                    legacy_level.get(parent * 2, legacy_empty[child_height]).to_bytes(32, "big"),
                    legacy_level.get(parent * 2 + 1, legacy_empty[child_height]).to_bytes(32, "big"),
                ),
            )
            for parent in parents
        )
        wide_preimages = tuple(
            _preimage(
                SPARSE_NODE_DOMAIN,
                tree_kind=kind,
                record_type="aggregate",
                tree_depth=tree_depth,
                child_height=child_height,
                payloads=(
                    wide_level.get(parent * 2, wide_empty[child_height]),
                    wide_level.get(parent * 2 + 1, wide_empty[child_height]),
                ),
            )
            for parent in parents
        )
        legacy_values = reference_legacy_felts(legacy_preimages)
        legacy_level = {
            parent: value
            for parent, value in zip(parents, legacy_values, strict=True)
        }
        wide_level = {
            parent: _wide(value)
            for parent, value in zip(parents, wide_preimages, strict=True)
        }
        legacy_levels.append(legacy_level)
        wide_levels.append(wide_level)

    legacy_top = legacy_level.get(0, legacy_empty[tree_depth])
    wide_top = wide_level.get(0, wide_empty[tree_depth])
    count = len(parsed).to_bytes(8, "big")
    legacy_root_preimage = _preimage(
        SPARSE_ROOT_DOMAIN,
        tree_kind=kind,
        record_type="tree_root",
        tree_depth=tree_depth,
        child_height=tree_depth,
        payloads=(count, legacy_top.to_bytes(32, "big")),
    )
    wide_root_preimage = _preimage(
        SPARSE_ROOT_DOMAIN,
        tree_kind=kind,
        record_type="tree_root",
        tree_depth=tree_depth,
        child_height=tree_depth,
        payloads=(count, wide_top),
    )
    manifest_preimage = _preimage(
        SPARSE_MANIFEST_DOMAIN,
        tree_kind=kind,
        record_type="record_manifest",
        tree_depth=tree_depth,
        child_height=0,
        payloads=tuple(
            key.to_bytes(8, "big") + _lp32(record.encoded)
            for key, record in parsed
        ),
    )
    reference = SparseDualTreeReference(
        SPARSE_REFERENCE_STATUS,
        kind,
        tree_depth,
        tuple((key, record.encoded) for key, record in parsed),
        _wide(manifest_preimage),
        legacy_leaves,
        wide_leaves,
        reference_legacy_felts((legacy_root_preimage,))[0],
        _wide(wide_root_preimage),
    )
    return (
        reference,
        tuple(legacy_empty),
        tuple(wide_empty),
        tuple(legacy_levels),
        tuple(wide_levels),
    )


def derive_sparse_dual_tree_reference(
    keyed_records: Iterable[tuple[int, bytes]],
    *,
    tree_kind: str,
    tree_depth: int,
) -> SparseDualTreeReference:
    """Build a level-default sparse tree from canonical keyed records."""

    return _derive_sparse_dual_tree_reference_and_levels(
        keyed_records,
        tree_kind=tree_kind,
        tree_depth=tree_depth,
    )[0]


def _sparse_levels(
    reference: SparseDualTreeReference,
) -> tuple[
    tuple[int, ...],
    tuple[bytes, ...],
    tuple[dict[int, int], ...],
    tuple[dict[int, bytes], ...],
]:
    if not isinstance(reference, SparseDualTreeReference):
        raise TypeError("sparse_proof_reference_type_invalid")
    require_synthetic_reference_enabled()
    kind = _identifier("tree_kind", reference.tree_kind)
    depth = reference.tree_depth
    if type(depth) is not int or not 1 <= depth <= MAX_SPARSE_REFERENCE_DEPTH:
        raise ValueError("sparse_proof_tree_depth_invalid")
    keyed = reference.keyed_records
    if type(keyed) is not tuple or len(keyed) > MAX_SPARSE_REFERENCE_ENTRIES:
        raise ValueError("sparse_proof_reference_entries_invalid")
    parsed: list[tuple[int, CanonicalRecord]] = []
    for entry in keyed:
        if type(entry) is not tuple or len(entry) != 2:
            raise ValueError("sparse_proof_reference_entry_shape_invalid")
        key, encoded = entry
        if type(key) is not int or not 0 <= key < (1 << depth):
            raise ValueError("sparse_proof_reference_key_invalid")
        record = parse_canonical_record(encoded)
        require_synthetic_canonical_record(record)
        parsed.append((key, record))
    if parsed != sorted(parsed, key=lambda item: item[0]):
        raise ValueError("sparse_proof_reference_entries_not_sorted")
    if len({key for key, _ in parsed}) != len(parsed):
        raise ValueError("sparse_proof_reference_key_duplicate")

    empty_preimage = _preimage(
        SPARSE_EMPTY_DOMAIN,
        tree_kind=kind,
        record_type="empty",
        tree_depth=depth,
        child_height=0,
        payloads=(),
    )
    legacy_empty: list[int] = [reference_legacy_felts((empty_preimage,))[0]]
    wide_empty: list[bytes] = [_wide(empty_preimage)]
    for child_height in range(depth):
        legacy_node = _preimage(
            SPARSE_NODE_DOMAIN,
            tree_kind=kind,
            record_type="aggregate",
            tree_depth=depth,
            child_height=child_height,
            payloads=(
                legacy_empty[-1].to_bytes(32, "big"),
                legacy_empty[-1].to_bytes(32, "big"),
            ),
        )
        wide_node = _preimage(
            SPARSE_NODE_DOMAIN,
            tree_kind=kind,
            record_type="aggregate",
            tree_depth=depth,
            child_height=child_height,
            payloads=(wide_empty[-1], wide_empty[-1]),
        )
        legacy_empty.append(reference_legacy_felts((legacy_node,))[0])
        wide_empty.append(_wide(wide_node))

    leaf_preimages = tuple(
        _preimage(
            SPARSE_LEAF_DOMAIN,
            tree_kind=kind,
            record_type=record.record_type,
            tree_depth=depth,
            child_height=0,
            payloads=(key.to_bytes(8, "big"), record.encoded),
        )
        for key, record in parsed
    )
    legacy_values = reference_legacy_felts(leaf_preimages)
    legacy_level = {
        key: value
        for (key, _), value in zip(parsed, legacy_values, strict=True)
    }
    wide_level = {
        key: _wide(preimage)
        for (key, _), preimage in zip(parsed, leaf_preimages, strict=True)
    }
    legacy_levels: list[dict[int, int]] = [legacy_level]
    wide_levels: list[dict[int, bytes]] = [wide_level]
    for child_height in range(depth):
        parents = sorted({key >> 1 for key in legacy_level})
        legacy_preimages = tuple(
            _preimage(
                SPARSE_NODE_DOMAIN,
                tree_kind=kind,
                record_type="aggregate",
                tree_depth=depth,
                child_height=child_height,
                payloads=(
                    legacy_level.get(parent * 2, legacy_empty[child_height]).to_bytes(32, "big"),
                    legacy_level.get(parent * 2 + 1, legacy_empty[child_height]).to_bytes(32, "big"),
                ),
            )
            for parent in parents
        )
        wide_preimages = tuple(
            _preimage(
                SPARSE_NODE_DOMAIN,
                tree_kind=kind,
                record_type="aggregate",
                tree_depth=depth,
                child_height=child_height,
                payloads=(
                    wide_level.get(parent * 2, wide_empty[child_height]),
                    wide_level.get(parent * 2 + 1, wide_empty[child_height]),
                ),
            )
            for parent in parents
        )
        next_legacy_values = reference_legacy_felts(legacy_preimages)
        legacy_level = {
            parent: value
            for parent, value in zip(parents, next_legacy_values, strict=True)
        }
        wide_level = {
            parent: _wide(preimage)
            for parent, preimage in zip(parents, wide_preimages, strict=True)
        }
        legacy_levels.append(legacy_level)
        wide_levels.append(wide_level)

    count = len(parsed).to_bytes(8, "big")
    legacy_top = legacy_level.get(0, legacy_empty[depth])
    wide_top = wide_level.get(0, wide_empty[depth])
    observed_legacy_root = reference_legacy_felts(
        (
            _preimage(
                SPARSE_ROOT_DOMAIN,
                tree_kind=kind,
                record_type="tree_root",
                tree_depth=depth,
                child_height=depth,
                payloads=(count, legacy_top.to_bytes(32, "big")),
            ),
        )
    )[0]
    observed_wide_root = _wide(
        _preimage(
            SPARSE_ROOT_DOMAIN,
            tree_kind=kind,
            record_type="tree_root",
            tree_depth=depth,
            child_height=depth,
            payloads=(count, wide_top),
        )
    )
    if observed_legacy_root != reference.legacy_root_felt:
        raise ValueError("sparse_proof_reference_legacy_root_mismatch")
    if not hmac.compare_digest(observed_wide_root, reference.wide_root_sha3_512):
        raise ValueError("sparse_proof_reference_wide_root_mismatch")
    return (
        tuple(legacy_empty),
        tuple(wide_empty),
        tuple(legacy_levels),
        tuple(wide_levels),
    )


def derive_sparse_dual_membership_proof(
    reference: SparseDualTreeReference,
    key: int,
) -> SparseDualMembershipProof:
    """Extract an exact membership path for an occupied sparse key."""

    if not isinstance(reference, SparseDualTreeReference):
        raise TypeError("sparse_proof_reference_type_invalid")
    if type(key) is not int or not 0 <= key < (1 << reference.tree_depth):
        raise ValueError("sparse_proof_key_out_of_range")
    records = dict(reference.keyed_records)
    if key not in records:
        raise ValueError("sparse_membership_key_absent")
    legacy_empty, wide_empty, legacy_levels, wide_levels = _sparse_levels(reference)
    return _sparse_membership_proof_at(
        reference,
        key,
        legacy_empty,
        wide_empty,
        legacy_levels,
        wide_levels,
    )


def _sparse_membership_proof_at(
    reference: SparseDualTreeReference,
    key: int,
    legacy_empty: tuple[int, ...],
    wide_empty: tuple[bytes, ...],
    legacy_levels: tuple[dict[int, int], ...],
    wide_levels: tuple[dict[int, bytes], ...],
) -> SparseDualMembershipProof:
    records = dict(reference.keyed_records)
    return SparseDualMembershipProof(
        tree_kind=reference.tree_kind,
        tree_depth=reference.tree_depth,
        entry_count=len(reference.keyed_records),
        key=key,
        canonical_record=records[key],
        legacy_leaf_felt=legacy_levels[0][key],
        wide_leaf_sha3_512=wide_levels[0][key],
        legacy_siblings=tuple(
            legacy_levels[height].get((key >> height) ^ 1, legacy_empty[height])
            for height in range(reference.tree_depth)
        ),
        wide_siblings_sha3_512=tuple(
            wide_levels[height].get((key >> height) ^ 1, wide_empty[height])
            for height in range(reference.tree_depth)
        ),
        legacy_root_felt=reference.legacy_root_felt,
        wide_root_sha3_512=reference.wide_root_sha3_512,
    )


def derive_all_sparse_dual_membership_proofs(
    reference: SparseDualTreeReference,
) -> tuple[SparseDualMembershipProof, ...]:
    """Extract every occupied-key path with one sparse level rebuild."""

    if not isinstance(reference, SparseDualTreeReference):
        raise TypeError("sparse_proof_reference_type_invalid")
    legacy_empty, wide_empty, legacy_levels, wide_levels = _sparse_levels(reference)
    return tuple(
        _sparse_membership_proof_at(
            reference,
            key,
            legacy_empty,
            wide_empty,
            legacy_levels,
            wide_levels,
        )
        for key, _ in reference.keyed_records
    )


def derive_sparse_dual_tree_reference_with_membership_proofs(
    keyed_records: Iterable[tuple[int, bytes]],
    *,
    tree_kind: str,
    tree_depth: int,
) -> tuple[SparseDualTreeReference, tuple[SparseDualMembershipProof, ...]]:
    """Build one sparse dual tree and every occupied-key path in one traversal."""

    (
        reference,
        legacy_empty,
        wide_empty,
        legacy_levels,
        wide_levels,
    ) = _derive_sparse_dual_tree_reference_and_levels(
        keyed_records,
        tree_kind=tree_kind,
        tree_depth=tree_depth,
    )
    return reference, tuple(
        _sparse_membership_proof_at(
            reference,
            key,
            legacy_empty,
            wide_empty,
            legacy_levels,
            wide_levels,
        )
        for key, _ in reference.keyed_records
    )


def derive_sparse_dual_nonmembership_proof(
    reference: SparseDualTreeReference,
    key: int,
) -> SparseDualNonMembershipProof:
    """Extract an empty-leaf path proving that one sparse key is unoccupied."""

    if not isinstance(reference, SparseDualTreeReference):
        raise TypeError("sparse_proof_reference_type_invalid")
    if type(key) is not int or not 0 <= key < (1 << reference.tree_depth):
        raise ValueError("sparse_proof_key_out_of_range")
    if key in dict(reference.keyed_records):
        raise ValueError("sparse_nonmembership_key_occupied")
    legacy_empty, wide_empty, legacy_levels, wide_levels = _sparse_levels(reference)
    return SparseDualNonMembershipProof(
        tree_kind=reference.tree_kind,
        tree_depth=reference.tree_depth,
        entry_count=len(reference.keyed_records),
        key=key,
        legacy_siblings=tuple(
            legacy_levels[height].get((key >> height) ^ 1, legacy_empty[height])
            for height in range(reference.tree_depth)
        ),
        wide_siblings_sha3_512=tuple(
            wide_levels[height].get((key >> height) ^ 1, wide_empty[height])
            for height in range(reference.tree_depth)
        ),
        legacy_root_felt=reference.legacy_root_felt,
        wide_root_sha3_512=reference.wide_root_sha3_512,
    )


def _verify_sparse_path(
    *,
    tree_kind: str,
    tree_depth: int,
    entry_count: int,
    key: int,
    legacy: int,
    wide: bytes,
    legacy_siblings: tuple[int, ...],
    wide_siblings: tuple[bytes, ...],
) -> tuple[int, bytes]:
    cursor = key
    for child_height, (legacy_sibling, wide_sibling) in enumerate(
        zip(legacy_siblings, wide_siblings, strict=True)
    ):
        if cursor & 1:
            legacy_children = (legacy_sibling, legacy)
            wide_children = (wide_sibling, wide)
        else:
            legacy_children = (legacy, legacy_sibling)
            wide_children = (wide, wide_sibling)
        legacy = reference_legacy_felts(
            (
                _preimage(
                    SPARSE_NODE_DOMAIN,
                    tree_kind=tree_kind,
                    record_type="aggregate",
                    tree_depth=tree_depth,
                    child_height=child_height,
                    payloads=(
                        legacy_children[0].to_bytes(32, "big"),
                        legacy_children[1].to_bytes(32, "big"),
                    ),
                ),
            )
        )[0]
        wide = _wide(
            _preimage(
                SPARSE_NODE_DOMAIN,
                tree_kind=tree_kind,
                record_type="aggregate",
                tree_depth=tree_depth,
                child_height=child_height,
                payloads=wide_children,
            )
        )
        cursor >>= 1
    count = entry_count.to_bytes(8, "big")
    legacy_root = reference_legacy_felts(
        (
            _preimage(
                SPARSE_ROOT_DOMAIN,
                tree_kind=tree_kind,
                record_type="tree_root",
                tree_depth=tree_depth,
                child_height=tree_depth,
                payloads=(count, legacy.to_bytes(32, "big")),
            ),
        )
    )[0]
    wide_root = _wide(
        _preimage(
            SPARSE_ROOT_DOMAIN,
            tree_kind=tree_kind,
            record_type="tree_root",
            tree_depth=tree_depth,
            child_height=tree_depth,
            payloads=(count, wide),
        )
    )
    return legacy_root, wide_root


def verify_sparse_dual_membership_proof(
    proof: SparseDualMembershipProof,
    *,
    expected_legacy_root_felt: int,
    expected_wide_root_sha3_512: bytes,
) -> bool:
    if not isinstance(proof, SparseDualMembershipProof):
        raise TypeError("sparse_membership_proof_type_invalid")
    proof.__post_init__()
    record = parse_canonical_record(proof.canonical_record)
    require_synthetic_canonical_record(record)
    leaf_preimage = _preimage(
        SPARSE_LEAF_DOMAIN,
        tree_kind=proof.tree_kind,
        record_type=record.record_type,
        tree_depth=proof.tree_depth,
        child_height=0,
        payloads=(proof.key.to_bytes(8, "big"), record.encoded),
    )
    legacy_leaf = reference_legacy_felts((leaf_preimage,))[0]
    wide_leaf = _wide(leaf_preimage)
    if legacy_leaf != proof.legacy_leaf_felt:
        raise ValueError("sparse_membership_legacy_leaf_mismatch")
    if not hmac.compare_digest(wide_leaf, proof.wide_leaf_sha3_512):
        raise ValueError("sparse_membership_wide_leaf_mismatch")
    legacy_root, wide_root = _verify_sparse_path(
        tree_kind=proof.tree_kind,
        tree_depth=proof.tree_depth,
        entry_count=proof.entry_count,
        key=proof.key,
        legacy=legacy_leaf,
        wide=wide_leaf,
        legacy_siblings=proof.legacy_siblings,
        wide_siblings=proof.wide_siblings_sha3_512,
    )
    _require_sparse_roots(
        observed_legacy=legacy_root,
        observed_wide=wide_root,
        proof_legacy=proof.legacy_root_felt,
        proof_wide=proof.wide_root_sha3_512,
        expected_legacy=expected_legacy_root_felt,
        expected_wide=expected_wide_root_sha3_512,
    )
    return True


def verify_sparse_dual_nonmembership_proof(
    proof: SparseDualNonMembershipProof,
    *,
    expected_legacy_root_felt: int,
    expected_wide_root_sha3_512: bytes,
) -> bool:
    if not isinstance(proof, SparseDualNonMembershipProof):
        raise TypeError("sparse_nonmembership_proof_type_invalid")
    proof.__post_init__()
    empty_preimage = _preimage(
        SPARSE_EMPTY_DOMAIN,
        tree_kind=proof.tree_kind,
        record_type="empty",
        tree_depth=proof.tree_depth,
        child_height=0,
        payloads=(),
    )
    legacy_root, wide_root = _verify_sparse_path(
        tree_kind=proof.tree_kind,
        tree_depth=proof.tree_depth,
        entry_count=proof.entry_count,
        key=proof.key,
        legacy=reference_legacy_felts((empty_preimage,))[0],
        wide=_wide(empty_preimage),
        legacy_siblings=proof.legacy_siblings,
        wide_siblings=proof.wide_siblings_sha3_512,
    )
    _require_sparse_roots(
        observed_legacy=legacy_root,
        observed_wide=wide_root,
        proof_legacy=proof.legacy_root_felt,
        proof_wide=proof.wide_root_sha3_512,
        expected_legacy=expected_legacy_root_felt,
        expected_wide=expected_wide_root_sha3_512,
    )
    return True


def _require_sparse_roots(
    *,
    observed_legacy: int,
    observed_wide: bytes,
    proof_legacy: int,
    proof_wide: bytes,
    expected_legacy: int,
    expected_wide: bytes,
) -> None:
    if type(expected_legacy) is not int or not 0 <= expected_legacy < FIELD_MODULUS:
        raise ValueError("sparse_proof_expected_legacy_root_invalid")
    if type(expected_wide) is not bytes or len(expected_wide) != 64:
        raise ValueError("sparse_proof_expected_wide_root_invalid")
    if observed_legacy != proof_legacy:
        raise ValueError("sparse_proof_legacy_root_mismatch")
    if not hmac.compare_digest(observed_wide, proof_wide):
        raise ValueError("sparse_proof_wide_root_mismatch")
    if observed_legacy != expected_legacy:
        raise ValueError("sparse_proof_governed_legacy_root_mismatch")
    if not hmac.compare_digest(observed_wide, expected_wide):
        raise ValueError("sparse_proof_governed_wide_root_mismatch")
