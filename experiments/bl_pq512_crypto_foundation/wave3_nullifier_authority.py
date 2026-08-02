"""Nonactivating Wave 3 P01-P03 nullifier-authority candidate.

This is the smallest useful implementation of the state boundary described in
the PQ architecture contract:

* A12 canonical preimages are the only input.  The legacy felt and the full
  SHA3-512 key are derived independently from those same bytes.
* The wide tree is a depth-64 append-indexed ordered tree.  Leaf, empty,
  internal-node, and root encodings bind type, position, height, and payload
  shape before hashing.
* A transition carries an authenticated predecessor/nonmembership witness and
  verifies both the old and new authoritative wide roots.
* The in-memory authority stages cloned legacy and wide trees, then swaps both
  pointers together.  This is a reference custody boundary, not durable
  storage or a proof verifier.

The module deliberately does not select a proof suite, consume PHI/payment
records, or enable activation.  Gate 2E/H5/H6 and the production verifier
remain prerequisites for promotion.
"""

from __future__ import annotations

from bisect import bisect_left, insort
from dataclasses import dataclass, field
from hashlib import sha3_512
import hmac
import re
from threading import RLock
from typing import Final, Iterable

from app.batch.nullifier import IndexedNullifierTree, NonMembershipWitness, verify_nonmembership_witness
from app.batch.poseidon import FIELD_MODULUS, domain_poseidon_hash


CANDIDATE_STATUS: Final[str] = "WAVE3_P01_P02_P03_CANDIDATE_NONACTIVATING"
ACTIVATION_ALLOWED: Final[bool] = False
PROOF_SUITE_ID: None = None

TREE_MAGIC: Final[bytes] = b"BLPQW301"
TREE_VERSION: Final[int] = 1
TREE_DEPTH: Final[int] = 64
WIDE_BYTES: Final[int] = 64
MAX_RAW_PREIMAGE_BYTES: Final[int] = 16_384
UINT64_MAX: Final[int] = (1 << 64) - 1
MAX_LEGACY_NULLIFIER: Final[int] = FIELD_MODULUS - 1
_A12_TOKEN: Final[re.Pattern[bytes]] = re.compile(rb"[A-Z0-9][A-Z0-9-]{0,63}\Z")

A12_MAGIC_V1: Final[bytes] = b"BLPQNF01"
A12_MAGIC_V2: Final[bytes] = b"BLPQNF02"
A12_HEADER_BYTES: Final[int] = 16
A12_ATTEMPT_DOMAIN: Final[int] = 257
A12_COVER_V2_DOMAIN: Final[int] = 514

RECORD_SENTINEL: Final[int] = 0
RECORD_ATTEMPT: Final[int] = 1
RECORD_COVER: Final[int] = 2

ITEM_LEAF: Final[int] = 1
ITEM_EMPTY: Final[int] = 2
ITEM_NODE: Final[int] = 3
ITEM_ROOT: Final[int] = 4

ZERO_512: Final[bytes] = bytes(WIDE_BYTES)
MAX_512: Final[bytes] = b"\xff" * WIDE_BYTES


class Wave3NullifierError(ValueError):
    """Fail-closed error for the candidate state boundary."""


def _bytes(label: str, value: object, length: int, *, nonzero: bool = False) -> bytes:
    if type(value) is not bytes or len(value) != length:
        raise Wave3NullifierError(f"wave3_{label}_must_be_{length}_bytes")
    if nonzero and not any(value):
        raise Wave3NullifierError(f"wave3_{label}_must_be_nonzero")
    return value


def _u64(label: str, value: object, *, nonzero: bool = False) -> int:
    if type(value) is not int or not 0 <= value <= UINT64_MAX:
        raise Wave3NullifierError(f"wave3_{label}_out_of_range")
    if nonzero and value == 0:
        raise Wave3NullifierError(f"wave3_{label}_must_be_nonzero")
    return value


def _index(label: str, value: object) -> int:
    return _u64(label, value)


def _item_encoding(
    item_type: int,
    record_type: int,
    position: int,
    child_height: int,
    payloads: tuple[bytes, ...],
) -> bytes:
    if item_type not in {ITEM_LEAF, ITEM_EMPTY, ITEM_NODE, ITEM_ROOT}:
        raise Wave3NullifierError("wave3_item_type_invalid")
    if record_type not in {RECORD_SENTINEL, RECORD_ATTEMPT, RECORD_COVER}:
        raise Wave3NullifierError("wave3_record_type_invalid")
    _index("item_position", position)
    if type(child_height) is not int or not 0 <= child_height <= TREE_DEPTH:
        raise Wave3NullifierError("wave3_item_height_invalid")
    if len(payloads) > 0xFF:
        raise Wave3NullifierError("wave3_item_payload_count_invalid")
    if any(type(payload) is not bytes or len(payload) > 0xFFFFFFFF for payload in payloads):
        raise Wave3NullifierError("wave3_item_payload_invalid")
    return b"".join(
        (
            TREE_MAGIC,
            TREE_VERSION.to_bytes(2, "big"),
            bytes((item_type, record_type, TREE_DEPTH, child_height)),
            position.to_bytes(8, "big"),
            bytes((len(payloads),)),
            *(len(payload).to_bytes(4, "big") + payload for payload in payloads),
        )
    )


def _hash_item(*args: object) -> bytes:
    return sha3_512(_item_encoding(*args)).digest()  # type: ignore[arg-type]


def _empty_subtree_hash(height: int, position: int) -> bytes:
    if type(height) is not int or not 0 <= height <= TREE_DEPTH:
        raise Wave3NullifierError("wave3_empty_height_invalid")
    return _hash_item(ITEM_EMPTY, RECORD_SENTINEL, position, height, ())


def _node_hash(left: bytes, right: bytes, *, parent_position: int, child_height: int) -> bytes:
    return _hash_item(
        ITEM_NODE,
        RECORD_SENTINEL,
        parent_position,
        child_height,
        (_bytes("node_left", left, WIDE_BYTES), _bytes("node_right", right, WIDE_BYTES)),
    )


def _root_hash(*, entry_count: int, next_append_index: int, top: bytes) -> bytes:
    _u64("root_entry_count", entry_count)
    _u64("root_next_append_index", next_append_index)
    return _hash_item(
        ITEM_ROOT,
        RECORD_SENTINEL,
        0,
        TREE_DEPTH,
        (
            entry_count.to_bytes(8, "big"),
            next_append_index.to_bytes(8, "big"),
            _bytes("root_top", top, WIDE_BYTES),
        ),
    )


def _a12_header(raw_preimage: bytes) -> tuple[int, int, int]:
    if type(raw_preimage) is not bytes:
        raise Wave3NullifierError("wave3_raw_preimage_must_be_bytes")
    if len(raw_preimage) < A12_HEADER_BYTES:
        raise Wave3NullifierError("wave3_a12_preimage_truncated")
    magic = raw_preimage[:8]
    version = int.from_bytes(raw_preimage[8:10], "big")
    domain = int.from_bytes(raw_preimage[10:12], "big")
    total_length = int.from_bytes(raw_preimage[12:16], "big")
    if total_length != len(raw_preimage):
        raise Wave3NullifierError("wave3_a12_preimage_length_mismatch")
    if (magic, version, domain) == (A12_MAGIC_V1, 1, A12_ATTEMPT_DOMAIN):
        _validate_a12_body(raw_preimage, record_type=RECORD_ATTEMPT)
        return version, domain, RECORD_ATTEMPT
    if (magic, version, domain) == (A12_MAGIC_V2, 2, A12_COVER_V2_DOMAIN):
        _validate_a12_body(raw_preimage, record_type=RECORD_COVER)
        return version, domain, RECORD_COVER
    raise Wave3NullifierError("wave3_a12_profile_or_domain_not_authorized")


def _read_lp16(raw: bytes, cursor: int, label: str) -> tuple[bytes, int]:
    if cursor + 2 > len(raw):
        raise Wave3NullifierError(f"wave3_a12_{label}_length_truncated")
    length = int.from_bytes(raw[cursor : cursor + 2], "big")
    cursor += 2
    end = cursor + length
    if end > len(raw):
        raise Wave3NullifierError(f"wave3_a12_{label}_truncated")
    return raw[cursor:end], end


def _validate_a12_body(raw_preimage: bytes, *, record_type: int) -> None:
    cursor = A12_HEADER_BYTES
    if record_type == RECORD_ATTEMPT:
        authority_id, cursor = _read_lp16(raw_preimage, cursor, "authority_id")
        claim_id, cursor = _read_lp16(raw_preimage, cursor, "claim_id")
        if _A12_TOKEN.fullmatch(authority_id) is None or _A12_TOKEN.fullmatch(claim_id) is None:
            raise Wave3NullifierError("wave3_a12_attempt_identity_not_canonical")
        if cursor + 4 + 1 + 4 + 2 + 64 != len(raw_preimage):
            raise Wave3NullifierError("wave3_a12_attempt_body_length_invalid")
        attempt_version = int.from_bytes(raw_preimage[cursor : cursor + 4], "big")
        revision_kind = raw_preimage[cursor + 4]
        parent_attempt_version = int.from_bytes(raw_preimage[cursor + 5 : cursor + 9], "big")
        pepper_length = int.from_bytes(raw_preimage[cursor + 9 : cursor + 11], "big")
        pepper = raw_preimage[cursor + 11 : cursor + 11 + 64]
        if (attempt_version, revision_kind, parent_attempt_version, pepper_length) != (1, 1, 0, 64):
            raise Wave3NullifierError("wave3_a12_attempt_lifecycle_invalid")
        if not any(pepper):
            raise Wave3NullifierError("wave3_a12_attempt_pepper_zero")
        return
    if record_type == RECORD_COVER:
        profile, cursor = _read_lp16(raw_preimage, cursor, "profile")
        if not profile:
            raise Wave3NullifierError("wave3_a12_cover_profile_invalid")
        try:
            profile.decode("ascii")
        except UnicodeDecodeError as exc:
            raise Wave3NullifierError("wave3_a12_cover_profile_not_ascii") from exc
        if cursor + 64 + 8 + 64 + 2 + 2 + 64 != len(raw_preimage):
            raise Wave3NullifierError("wave3_a12_cover_body_length_invalid")
        domain_id = raw_preimage[cursor : cursor + 64]
        epoch = int.from_bytes(raw_preimage[cursor + 64 : cursor + 72], "big")
        batch_nonce = raw_preimage[cursor + 72 : cursor + 136]
        slot_index = int.from_bytes(raw_preimage[cursor + 136 : cursor + 138], "big")
        nonce_length = int.from_bytes(raw_preimage[cursor + 138 : cursor + 140], "big")
        nonce = raw_preimage[cursor + 140 : cursor + 204]
        if not any(domain_id) or epoch == 0 or not any(batch_nonce) or slot_index > 511:
            raise Wave3NullifierError("wave3_a12_cover_context_invalid")
        if nonce_length != 64 or not any(nonce):
            raise Wave3NullifierError("wave3_a12_cover_nonce_invalid")
        return
    raise Wave3NullifierError("wave3_a12_record_type_invalid")


def _legacy_felt_from_a12(raw_preimage: bytes) -> int:
    version, domain, _ = _a12_header(raw_preimage)
    chunks = tuple(
        int.from_bytes(raw_preimage[offset : offset + 30], "big")
        for offset in range(0, len(raw_preimage), 30)
    )
    accumulator = domain_poseidon_hash(
        "nullifier",
        [version, domain, len(raw_preimage), len(chunks)],
    )
    for index, chunk in enumerate(chunks):
        accumulator = domain_poseidon_hash(
            "nullifier",
            [version, domain, len(raw_preimage), len(chunks), index, accumulator, chunk],
        )
    if not 0 < accumulator < MAX_LEGACY_NULLIFIER:
        raise Wave3NullifierError("wave3_legacy_felt_reserved")
    return accumulator


@dataclass(frozen=True, slots=True)
class Wave3NullifierRecordV1:
    """One already-canonical A12 preimage, never a caller-supplied digest."""

    raw_preimage: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.raw_preimage) is not bytes or not self.raw_preimage:
            raise Wave3NullifierError("wave3_raw_preimage_invalid")
        if len(self.raw_preimage) > MAX_RAW_PREIMAGE_BYTES:
            raise Wave3NullifierError("wave3_raw_preimage_too_large")
        _a12_header(self.raw_preimage)

    @property
    def record_type(self) -> int:
        return _a12_header(self.raw_preimage)[2]

    @property
    def legacy_felt(self) -> int:
        return _legacy_felt_from_a12(self.raw_preimage)

    @property
    def strong_key_512(self) -> bytes:
        return sha3_512(self.raw_preimage).digest()


@dataclass(frozen=True, slots=True)
class Wave3DualDerivedRecordV1:
    record: Wave3NullifierRecordV1
    legacy_felt: int
    strong_key_512: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.record) is not Wave3NullifierRecordV1:
            raise Wave3NullifierError("wave3_dual_record_type_invalid")
        if type(self.legacy_felt) is not int or not 0 < self.legacy_felt < MAX_LEGACY_NULLIFIER:
            raise Wave3NullifierError("wave3_dual_legacy_felt_invalid")
        _bytes("dual_strong_key", self.strong_key_512, WIDE_BYTES, nonzero=True)
        if self.legacy_felt != self.record.legacy_felt:
            raise Wave3NullifierError("wave3_dual_legacy_derivation_mismatch")
        if not hmac.compare_digest(self.strong_key_512, self.record.strong_key_512):
            raise Wave3NullifierError("wave3_dual_strong_derivation_mismatch")


def derive_dual_record(raw_preimage: bytes) -> Wave3DualDerivedRecordV1:
    record = Wave3NullifierRecordV1(raw_preimage)
    return Wave3DualDerivedRecordV1(record, record.legacy_felt, record.strong_key_512)


@dataclass(frozen=True, slots=True)
class Wave3WideLeafV1:
    index: int
    value: bytes
    next_value: bytes
    next_index: int
    record_type: int

    def __post_init__(self) -> None:
        if self.record_type not in {RECORD_SENTINEL, RECORD_ATTEMPT, RECORD_COVER}:
            raise Wave3NullifierError("wave3_leaf_record_type_invalid")
        _index("leaf_index", self.index)
        _bytes("leaf_value", self.value, WIDE_BYTES, nonzero=self.record_type != RECORD_SENTINEL)
        _bytes("leaf_next_value", self.next_value, WIDE_BYTES)
        _index("leaf_next_index", self.next_index)
        if self.record_type == RECORD_SENTINEL:
            if self.index == 0 and self.value != ZERO_512:
                raise Wave3NullifierError("wave3_zero_sentinel_shape_invalid")
            if self.index == 1 and (self.value, self.next_value, self.next_index) != (MAX_512, MAX_512, 1):
                raise Wave3NullifierError("wave3_max_sentinel_shape_invalid")
            if self.index not in {0, 1}:
                raise Wave3NullifierError("wave3_sentinel_index_invalid")
        elif self.value in {ZERO_512, MAX_512}:
            raise Wave3NullifierError("wave3_leaf_value_reserved")
        if self.next_value == ZERO_512:
            raise Wave3NullifierError("wave3_leaf_successor_zero_reserved")
        if self.next_value == MAX_512 and self.next_index != 1:
            raise Wave3NullifierError("wave3_leaf_successor_sentinel_index_invalid")

    @property
    def digest(self) -> bytes:
        return _hash_item(
            ITEM_LEAF,
            self.record_type,
            self.index,
            0,
            (
                self.value,
                self.next_value,
                self.next_index.to_bytes(8, "big"),
            ),
        )


@dataclass(frozen=True, slots=True)
class Wave3WideTransitionWitnessV1:
    root_before_512: bytes
    root_after_512: bytes
    nullifier_512: bytes = field(repr=False)
    record_type: int
    predecessor_index: int
    predecessor_value: bytes = field(repr=False)
    predecessor_record_type: int
    successor_value: bytes = field(repr=False)
    successor_index: int
    inserted_index: int
    entry_count_before: int
    entry_count_after: int
    next_append_index_before: int
    next_append_index_after: int
    predecessor_path: tuple[bytes, ...] = field(repr=False)
    insertion_path: tuple[bytes, ...] = field(repr=False)
    status: str = CANDIDATE_STATUS

    def __post_init__(self) -> None:
        if self.status != CANDIDATE_STATUS:
            raise Wave3NullifierError("wave3_witness_status_invalid")
        _bytes("witness_root_before", self.root_before_512, WIDE_BYTES, nonzero=True)
        _bytes("witness_root_after", self.root_after_512, WIDE_BYTES, nonzero=True)
        _bytes("witness_nullifier", self.nullifier_512, WIDE_BYTES, nonzero=True)
        if self.nullifier_512 in {ZERO_512, MAX_512}:
            raise Wave3NullifierError("wave3_witness_nullifier_reserved")
        _bytes("witness_predecessor_value", self.predecessor_value, WIDE_BYTES)
        _bytes("witness_successor_value", self.successor_value, WIDE_BYTES)
        if self.record_type not in {RECORD_ATTEMPT, RECORD_COVER}:
            raise Wave3NullifierError("wave3_witness_record_type_invalid")
        if self.predecessor_record_type not in {RECORD_SENTINEL, RECORD_ATTEMPT, RECORD_COVER}:
            raise Wave3NullifierError("wave3_witness_predecessor_record_type_invalid")
        _index("witness_predecessor_index", self.predecessor_index)
        _index("witness_successor_index", self.successor_index)
        _index("witness_inserted_index", self.inserted_index)
        if self.inserted_index <= 1 or self.inserted_index != self.next_append_index_before:
            raise Wave3NullifierError("wave3_witness_inserted_index_invalid")
        _u64("witness_entry_count_before", self.entry_count_before)
        _u64("witness_entry_count_after", self.entry_count_after)
        _u64("witness_next_append_index_before", self.next_append_index_before)
        _u64("witness_next_append_index_after", self.next_append_index_after)
        if self.entry_count_after != self.entry_count_before + 1:
            raise Wave3NullifierError("wave3_witness_entry_count_transition_invalid")
        if self.next_append_index_after != self.next_append_index_before + 1:
            raise Wave3NullifierError("wave3_witness_append_index_transition_invalid")
        for label, path in (("predecessor", self.predecessor_path), ("insertion", self.insertion_path)):
            if type(path) is not tuple or len(path) != TREE_DEPTH or any(
                type(value) is not bytes or len(value) != WIDE_BYTES for value in path
            ):
                raise Wave3NullifierError(f"wave3_witness_{label}_path_invalid")


def _path_step(current: bytes, sibling: bytes, bit: int, height: int, parent_position: int) -> bytes:
    if bit not in {0, 1}:
        raise Wave3NullifierError("wave3_path_bit_invalid")
    left, right = (current, sibling) if bit == 0 else (sibling, current)
    return _node_hash(left, right, parent_position=parent_position, child_height=height)


def _transition_roots(witness: Wave3WideTransitionWitnessV1) -> tuple[bytes, bytes]:
    predecessor_old = Wave3WideLeafV1(
        witness.predecessor_index,
        witness.predecessor_value,
        witness.successor_value,
        witness.successor_index,
        witness.predecessor_record_type,
    ).digest
    predecessor_new = Wave3WideLeafV1(
        witness.predecessor_index,
        witness.predecessor_value,
        witness.nullifier_512,
        witness.inserted_index,
        witness.predecessor_record_type,
    ).digest
    insertion_new = Wave3WideLeafV1(
        witness.inserted_index,
        witness.nullifier_512,
        witness.successor_value,
        witness.successor_index,
        witness.record_type,
    ).digest
    predecessor_cursor = witness.predecessor_index
    insertion_cursor = witness.inserted_index
    predecessor_old_cursor = predecessor_old
    predecessor_new_cursor = predecessor_new
    insertion_old_cursor = _empty_subtree_hash(0, witness.inserted_index)
    insertion_branch_empty = True
    insertion_new_cursor = insertion_new
    joined = False
    height = 0
    while height < TREE_DEPTH:
        predecessor_bit = predecessor_cursor & 1
        insertion_bit = insertion_cursor & 1
        predecessor_parent = predecessor_cursor >> 1
        insertion_parent = insertion_cursor >> 1
        if predecessor_parent == insertion_parent:
            if predecessor_bit == insertion_bit:
                raise Wave3NullifierError("wave3_transition_indices_do_not_join")
            expected_empty = insertion_old_cursor
            if not hmac.compare_digest(witness.predecessor_path[height], expected_empty):
                raise Wave3NullifierError("wave3_transition_predecessor_empty_sibling_mismatch")
            if not hmac.compare_digest(witness.insertion_path[height], predecessor_new_cursor):
                raise Wave3NullifierError("wave3_transition_insertion_sibling_mismatch")
            if predecessor_bit == 0:
                predecessor_old_cursor = _node_hash(
                    predecessor_old_cursor,
                    expected_empty,
                    parent_position=predecessor_parent,
                    child_height=height,
                )
                predecessor_new_cursor = _node_hash(
                    predecessor_new_cursor,
                    insertion_new_cursor,
                    parent_position=predecessor_parent,
                    child_height=height,
                )
            else:
                predecessor_old_cursor = _node_hash(
                    expected_empty,
                    predecessor_old_cursor,
                    parent_position=predecessor_parent,
                    child_height=height,
                )
                predecessor_new_cursor = _node_hash(
                    insertion_new_cursor,
                    predecessor_new_cursor,
                    parent_position=predecessor_parent,
                    child_height=height,
                )
            predecessor_cursor = predecessor_parent
            insertion_cursor = insertion_parent
            height += 1
            joined = True
            break
        predecessor_old_cursor = _path_step(
            predecessor_old_cursor,
            witness.predecessor_path[height],
            predecessor_bit,
            height,
            predecessor_parent,
        )
        predecessor_new_cursor = _path_step(
            predecessor_new_cursor,
            witness.predecessor_path[height],
            predecessor_bit,
            height,
            predecessor_parent,
        )
        insertion_new_cursor = _path_step(
            insertion_new_cursor,
            witness.insertion_path[height],
            insertion_bit,
            height,
            insertion_parent,
        )
        sibling_is_empty = hmac.compare_digest(
            witness.insertion_path[height],
            _empty_subtree_hash(height, insertion_cursor ^ 1),
        )
        if insertion_branch_empty and sibling_is_empty:
            insertion_old_cursor = _empty_subtree_hash(height + 1, insertion_parent)
        else:
            insertion_old_cursor = _path_step(
                insertion_old_cursor,
                witness.insertion_path[height],
                insertion_bit,
                height,
                insertion_parent,
            )
            insertion_branch_empty = False
        predecessor_cursor = predecessor_parent
        insertion_cursor = insertion_parent
        height += 1
    if not joined or predecessor_cursor != insertion_cursor:
        raise Wave3NullifierError("wave3_transition_shared_path_join_mismatch")
    while height < TREE_DEPTH:
        if predecessor_cursor != insertion_cursor:
            raise Wave3NullifierError("wave3_transition_shared_path_position_mismatch")
        bit = predecessor_cursor & 1
        parent = predecessor_cursor >> 1
        if not hmac.compare_digest(witness.predecessor_path[height], witness.insertion_path[height]):
            raise Wave3NullifierError("wave3_transition_shared_sibling_mismatch")
        predecessor_old_cursor = _path_step(
            predecessor_old_cursor,
            witness.predecessor_path[height],
            bit,
            height,
            parent,
        )
        predecessor_new_cursor = _path_step(
            predecessor_new_cursor,
            witness.predecessor_path[height],
            bit,
            height,
            parent,
        )
        predecessor_cursor = parent
        insertion_cursor = parent
        height += 1
    if predecessor_cursor != 0 or insertion_cursor != 0:
        raise Wave3NullifierError("wave3_transition_path_capacity_exceeded")
    return (
        _root_hash(
            entry_count=witness.entry_count_before,
            next_append_index=witness.next_append_index_before,
            top=predecessor_old_cursor,
        ),
        _root_hash(
            entry_count=witness.entry_count_after,
            next_append_index=witness.next_append_index_after,
            top=predecessor_new_cursor,
        ),
    )


def verify_wave3_wide_transition(witness: Wave3WideTransitionWitnessV1) -> bool:
    if type(witness) is not Wave3WideTransitionWitnessV1:
        raise TypeError("wave3_witness_type_invalid")
    witness.__post_init__()
    if not witness.predecessor_value < witness.nullifier_512 < witness.successor_value:
        raise Wave3NullifierError("wave3_witness_ordering_invalid")
    if witness.predecessor_index == 0 and witness.predecessor_record_type != RECORD_SENTINEL:
        raise Wave3NullifierError("wave3_zero_sentinel_type_invalid")
    if witness.successor_value == MAX_512 and witness.successor_index != 1:
        raise Wave3NullifierError("wave3_successor_sentinel_invalid")
    observed_before, observed_after = _transition_roots(witness)
    if not hmac.compare_digest(observed_before, witness.root_before_512):
        raise Wave3NullifierError("wave3_witness_root_before_mismatch")
    if not hmac.compare_digest(observed_after, witness.root_after_512):
        raise Wave3NullifierError("wave3_witness_root_after_mismatch")
    return True


class Wave3WideNullifierTreeV1:
    """Sparse depth-64 full-width tree with append-indexed ordered leaves."""

    def __init__(self, values: Iterable[tuple[bytes, int]] = ()) -> None:
        self._nodes: dict[int, Wave3WideLeafV1] = {
            0: Wave3WideLeafV1(0, ZERO_512, MAX_512, 1, RECORD_SENTINEL),
            1: Wave3WideLeafV1(1, MAX_512, MAX_512, 1, RECORD_SENTINEL),
        }
        self._value_to_index: dict[bytes, int] = {ZERO_512: 0, MAX_512: 1}
        self._sorted_values: list[bytes] = [ZERO_512, MAX_512]
        self._next_append_index = 2
        self._root_cache: bytes | None = None
        for value, record_type in values:
            self.insert(value, record_type=record_type)

    def clone(self) -> "Wave3WideNullifierTreeV1":
        clone = object.__new__(Wave3WideNullifierTreeV1)
        clone._nodes = dict(self._nodes)
        clone._value_to_index = dict(self._value_to_index)
        clone._sorted_values = list(self._sorted_values)
        clone._next_append_index = self._next_append_index
        clone._root_cache = self._root_cache
        return clone

    @property
    def entry_count(self) -> int:
        return len(self._nodes) - 2

    @property
    def next_append_index(self) -> int:
        return self._next_append_index

    @property
    def root_512(self) -> bytes:
        if self._root_cache is None:
            self._root_cache = self._root_and_path(0)[0]
        return self._root_cache

    def contains(self, value: bytes) -> bool:
        return _bytes("contains_value", value, WIDE_BYTES) in self._value_to_index

    def _predecessor_successor(self, value: bytes) -> tuple[Wave3WideLeafV1, Wave3WideLeafV1]:
        position = bisect_left(self._sorted_values, value)
        predecessor_value = self._sorted_values[position - 1]
        successor_value = self._sorted_values[position]
        return (
            self._nodes[self._value_to_index[predecessor_value]],
            self._nodes[self._value_to_index[successor_value]],
        )

    def _root_and_path(self, target_index: int) -> tuple[bytes, tuple[bytes, ...]]:
        cursor = _index("target_index", target_index)
        nodes = {index: leaf.digest for index, leaf in self._nodes.items()}
        path: list[bytes] = []
        for height in range(TREE_DEPTH):
            sibling_position = cursor ^ 1
            path.append(nodes.get(sibling_position, _empty_subtree_hash(height, sibling_position)))
            parents = sorted({index >> 1 for index in nodes})
            nodes = {
                parent: _node_hash(
                    nodes.get(parent * 2, _empty_subtree_hash(height, parent * 2)),
                    nodes.get(parent * 2 + 1, _empty_subtree_hash(height, parent * 2 + 1)),
                    parent_position=parent,
                    child_height=height,
                )
                for parent in parents
            }
            cursor >>= 1
        top = nodes.get(0, _empty_subtree_hash(TREE_DEPTH, 0))
        return (
            _root_hash(
                entry_count=self.entry_count,
                next_append_index=self.next_append_index,
                top=top,
            ),
            tuple(path),
        )

    def prove_nonmembership(self, record: Wave3DualDerivedRecordV1) -> Wave3WideTransitionWitnessV1:
        if type(record) is not Wave3DualDerivedRecordV1:
            raise TypeError("wave3_dual_record_required")
        nullifier = record.strong_key_512
        if self.contains(nullifier):
            raise Wave3NullifierError("wave3_strong_nullifier_already_present")
        predecessor, successor = self._predecessor_successor(nullifier)
        root_before, predecessor_path = self._root_and_path(predecessor.index)
        inserted_index = self.next_append_index
        middle = self.clone()
        middle._nodes[predecessor.index] = Wave3WideLeafV1(
            predecessor.index,
            predecessor.value,
            nullifier,
            inserted_index,
            predecessor.record_type,
        )
        middle._root_cache = None
        _, insertion_path = middle._root_and_path(inserted_index)
        after = middle.clone()
        after._nodes[inserted_index] = Wave3WideLeafV1(
            inserted_index,
            nullifier,
            successor.value,
            successor.index,
            record.record.record_type,
        )
        after._value_to_index[nullifier] = inserted_index
        insort(after._sorted_values, nullifier)
        after._next_append_index = inserted_index + 1
        after._root_cache = None
        root_after, verified_insertion_path = after._root_and_path(inserted_index)
        if insertion_path != verified_insertion_path:
            raise Wave3NullifierError("wave3_insertion_path_changed")
        witness = Wave3WideTransitionWitnessV1(
            root_before,
            root_after,
            nullifier,
            record.record.record_type,
            predecessor.index,
            predecessor.value,
            predecessor.record_type,
            successor.value,
            successor.index,
            inserted_index,
            self.entry_count,
            after.entry_count,
            self.next_append_index,
            after.next_append_index,
            predecessor_path,
            insertion_path,
        )
        verify_wave3_wide_transition(witness)
        return witness

    def insert(self, value: bytes, *, record_type: int) -> None:
        value = _bytes("insert_value", value, WIDE_BYTES, nonzero=True)
        if value in {ZERO_512, MAX_512}:
            raise Wave3NullifierError("wave3_insert_value_reserved")
        if record_type not in {RECORD_ATTEMPT, RECORD_COVER}:
            raise Wave3NullifierError("wave3_insert_record_type_invalid")
        if value in self._value_to_index:
            raise Wave3NullifierError("wave3_strong_nullifier_already_present")
        if self.next_append_index == UINT64_MAX:
            raise Wave3NullifierError("wave3_append_index_exhausted")
        predecessor, successor = self._predecessor_successor(value)
        inserted_index = self.next_append_index
        self._nodes[predecessor.index] = Wave3WideLeafV1(
            predecessor.index,
            predecessor.value,
            value,
            inserted_index,
            predecessor.record_type,
        )
        self._nodes[inserted_index] = Wave3WideLeafV1(
            inserted_index,
            value,
            successor.value,
            successor.index,
            record_type,
        )
        self._value_to_index[value] = inserted_index
        insort(self._sorted_values, value)
        self._next_append_index = inserted_index + 1
        self._root_cache = None


@dataclass(frozen=True, slots=True)
class Wave3StateSnapshotV1:
    epoch: int
    sequence: int
    record_count: int
    next_append_index: int
    legacy_root_felt: int
    strong_nullifier_root_512: bytes = field(repr=False)
    status: str = CANDIDATE_STATUS

    def __post_init__(self) -> None:
        if self.status != CANDIDATE_STATUS:
            raise Wave3NullifierError("wave3_snapshot_status_invalid")
        _u64("snapshot_epoch", self.epoch, nonzero=True)
        _u64("snapshot_sequence", self.sequence)
        _u64("snapshot_record_count", self.record_count)
        _index("snapshot_next_append_index", self.next_append_index)
        if self.next_append_index != self.record_count + 2:
            raise Wave3NullifierError("wave3_snapshot_append_index_count_mismatch")
        if type(self.legacy_root_felt) is not int or not 0 <= self.legacy_root_felt < FIELD_MODULUS:
            raise Wave3NullifierError("wave3_snapshot_legacy_root_invalid")
        _bytes("snapshot_strong_root", self.strong_nullifier_root_512, WIDE_BYTES, nonzero=True)


@dataclass(frozen=True, slots=True)
class Wave3StateTransitionV1:
    before: Wave3StateSnapshotV1
    after: Wave3StateSnapshotV1
    record: Wave3DualDerivedRecordV1
    wide_witness: Wave3WideTransitionWitnessV1
    legacy_witness: NonMembershipWitness
    status: str = CANDIDATE_STATUS

    def __post_init__(self) -> None:
        if self.status != CANDIDATE_STATUS:
            raise Wave3NullifierError("wave3_transition_status_invalid")
        if type(self.before) is not Wave3StateSnapshotV1 or type(self.after) is not Wave3StateSnapshotV1:
            raise Wave3NullifierError("wave3_transition_snapshot_type_invalid")
        if self.after.epoch != self.before.epoch or self.after.sequence != self.before.sequence + 1:
            raise Wave3NullifierError("wave3_transition_sequence_invalid")
        if self.after.record_count != self.before.record_count + 1:
            raise Wave3NullifierError("wave3_transition_record_count_invalid")
        if self.after.next_append_index != self.before.next_append_index + 1:
            raise Wave3NullifierError("wave3_transition_append_index_invalid")
        if type(self.record) is not Wave3DualDerivedRecordV1:
            raise Wave3NullifierError("wave3_transition_record_invalid")
        if type(self.wide_witness) is not Wave3WideTransitionWitnessV1:
            raise Wave3NullifierError("wave3_transition_wide_witness_invalid")
        if type(self.legacy_witness) is not NonMembershipWitness:
            raise Wave3NullifierError("wave3_transition_legacy_witness_invalid")
        if self.wide_witness.root_before_512 != self.before.strong_nullifier_root_512:
            raise Wave3NullifierError("wave3_transition_wide_before_root_mismatch")
        if self.wide_witness.root_after_512 != self.after.strong_nullifier_root_512:
            raise Wave3NullifierError("wave3_transition_wide_after_root_mismatch")
        if self.legacy_witness.root != self.before.legacy_root_felt:
            raise Wave3NullifierError("wave3_transition_legacy_before_root_mismatch")
        if self.legacy_witness.rootAfter != self.after.legacy_root_felt:
            raise Wave3NullifierError("wave3_transition_legacy_after_root_mismatch")
        if self.legacy_witness.nullifier != self.record.legacy_felt:
            raise Wave3NullifierError("wave3_transition_legacy_key_mismatch")
        if self.wide_witness.nullifier_512 != self.record.strong_key_512:
            raise Wave3NullifierError("wave3_transition_wide_key_mismatch")
        verify_wave3_wide_transition(self.wide_witness)
        if not verify_nonmembership_witness(self.legacy_witness):
            raise Wave3NullifierError("wave3_transition_legacy_verification_failed")


def independently_verify_wave3_transition(transition: Wave3StateTransitionV1) -> bool:
    if type(transition) is not Wave3StateTransitionV1:
        raise TypeError("wave3_transition_type_invalid")
    transition.__post_init__()
    return True


class Wave3NullifierAuthorityV1:
    """Atomic in-memory dual-root candidate; durable P08 custody is separate."""

    def __init__(self, *, epoch: int = 1) -> None:
        _u64("authority_epoch", epoch, nonzero=True)
        self._lock = RLock()
        self._epoch = epoch
        self._sequence = 0
        self._wide = Wave3WideNullifierTreeV1()
        self._legacy = IndexedNullifierTree()
        self._records: dict[bytes, Wave3DualDerivedRecordV1] = {}

    def _snapshot_unlocked(self) -> Wave3StateSnapshotV1:
        return Wave3StateSnapshotV1(
            self._epoch,
            self._sequence,
            self._wide.entry_count,
            self._wide.next_append_index,
            self._legacy.root,
            self._wide.root_512,
        )

    def snapshot(self) -> Wave3StateSnapshotV1:
        with self._lock:
            return self._snapshot_unlocked()

    def prepare_transition(self, raw_preimage: bytes) -> Wave3StateTransitionV1:
        record = derive_dual_record(raw_preimage)
        with self._lock:
            if record.strong_key_512 in self._records:
                raise Wave3NullifierError("wave3_strong_nullifier_already_present")
            before = self._snapshot_unlocked()
            wide_witness = self._wide.prove_nonmembership(record)
            legacy_witness = self._legacy.prove_nonmembership(record.legacy_felt)
            after = Wave3StateSnapshotV1(
                self._epoch,
                self._sequence + 1,
                before.record_count + 1,
                before.next_append_index + 1,
                legacy_witness.rootAfter,
                wide_witness.root_after_512,
            )
            return Wave3StateTransitionV1(
                before,
                after,
                record,
                wide_witness,
                legacy_witness,
            )

    def commit(self, transition: Wave3StateTransitionV1) -> Wave3StateSnapshotV1:
        independently_verify_wave3_transition(transition)
        with self._lock:
            current = self._snapshot_unlocked()
            if current != transition.before:
                raise Wave3NullifierError("wave3_state_stale_snapshot")
            if transition.record.strong_key_512 in self._records:
                raise Wave3NullifierError("wave3_strong_nullifier_already_present")
            staged_wide = self._wide.clone()
            staged_legacy = self._legacy.clone()
            staged_wide.insert(
                transition.record.strong_key_512,
                record_type=transition.record.record.record_type,
            )
            staged_legacy.insert(transition.record.legacy_felt)
            staged = Wave3StateSnapshotV1(
                self._epoch,
                self._sequence + 1,
                staged_wide.entry_count,
                staged_wide.next_append_index,
                staged_legacy.root,
                staged_wide.root_512,
            )
            if staged != transition.after:
                raise Wave3NullifierError("wave3_staged_state_mismatch")
            self._wide = staged_wide
            self._legacy = staged_legacy
            self._records[transition.record.strong_key_512] = transition.record
            self._sequence += 1
            return staged


__all__: tuple[str, ...] = (
    "ACTIVATION_ALLOWED",
    "CANDIDATE_STATUS",
    "PROOF_SUITE_ID",
    "RECORD_ATTEMPT",
    "RECORD_COVER",
    "RECORD_SENTINEL",
    "TREE_DEPTH",
    "TREE_MAGIC",
    "Wave3DualDerivedRecordV1",
    "Wave3NullifierAuthorityV1",
    "Wave3NullifierError",
    "Wave3NullifierRecordV1",
    "Wave3StateSnapshotV1",
    "Wave3StateTransitionV1",
    "Wave3WideLeafV1",
    "Wave3WideNullifierTreeV1",
    "Wave3WideTransitionWitnessV1",
    "derive_dual_record",
    "independently_verify_wave3_transition",
    "verify_wave3_wide_transition",
)
