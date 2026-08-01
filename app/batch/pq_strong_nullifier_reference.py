"""Synthetic SHA3-512 indexed nullifier tree with authenticated transitions.

This is the wide, independent counterpart to the protected legacy Poseidon
indexed tree.  It consumes full 512-bit nullifiers derived from raw canonical
attempt material and never hashes a legacy felt.  Every domain is explicitly
REFERENCE/v0; this module is not an activated production tree or an AIR.
"""

from __future__ import annotations

from bisect import bisect_left, insort
from dataclasses import dataclass
from functools import lru_cache
from hashlib import sha3_512
import hmac
from typing import Final, Iterable

from app.batch.pq_tree_reference import require_synthetic_reference_enabled


STRONG_INDEXED_REFERENCE_STATUS: Final[str] = (
    "SYNTHETIC_STRONG_INDEXED_NULLIFIER_REFERENCE_V0_NOT_PRODUCTION"
)
STRONG_NULLIFIER_DEPTH: Final[int] = 64
STRONG_NULLIFIER_BYTES: Final[int] = 64
STRONG_NULLIFIER_MAX: Final[bytes] = b"\xff" * STRONG_NULLIFIER_BYTES
STRONG_NULLIFIER_ZERO: Final[bytes] = b"\x00" * STRONG_NULLIFIER_BYTES
_MAGIC: Final[bytes] = b"BL/PQ512/STRONG-INDEXED-NULLIFIER/REFERENCE/v0"
_LEAF_DOMAIN: Final[bytes] = _MAGIC + b"\x00LEAF\x00"
_NODE_DOMAIN: Final[bytes] = _MAGIC + b"\x00NODE\x00"


class DuplicateStrongNullifierError(ValueError):
    pass


def _wide_value(label: str, value: object, *, allow_sentinel: bool = False) -> bytes:
    if type(value) is not bytes or len(value) != STRONG_NULLIFIER_BYTES:
        raise TypeError(f"strong_nullifier_{label}_must_be_64_bytes")
    if not allow_sentinel and value in (STRONG_NULLIFIER_ZERO, STRONG_NULLIFIER_MAX):
        raise ValueError(f"strong_nullifier_{label}_reserved")
    return value


def _index(label: str, value: object) -> int:
    if type(value) is not int or not 0 <= value < (1 << STRONG_NULLIFIER_DEPTH):
        raise ValueError(f"strong_nullifier_{label}_out_of_range")
    return value


def _leaf_hash(value: bytes, next_value: bytes, next_index: int, index: int) -> bytes:
    current = _wide_value("leaf_value", value, allow_sentinel=True)
    successor = _wide_value("leaf_next_value", next_value, allow_sentinel=True)
    successor_index = _index("leaf_next_index", next_index)
    leaf_index = _index("leaf_index", index)
    return sha3_512(
        _LEAF_DOMAIN
        + leaf_index.to_bytes(8, "big")
        + current
        + successor
        + successor_index.to_bytes(8, "big")
    ).digest()


def _node_hash(left: bytes, right: bytes, child_height: int) -> bytes:
    if type(left) is not bytes or len(left) != 64 or type(right) is not bytes or len(right) != 64:
        raise TypeError("strong_nullifier_node_children_must_be_64_bytes")
    if type(child_height) is not int or not 0 <= child_height < STRONG_NULLIFIER_DEPTH:
        raise ValueError("strong_nullifier_child_height_invalid")
    return sha3_512(
        _NODE_DOMAIN + child_height.to_bytes(1, "big") + left + right
    ).digest()


@lru_cache(maxsize=1)
def _zero_hashes() -> tuple[bytes, ...]:
    values = [STRONG_NULLIFIER_ZERO]
    for height in range(STRONG_NULLIFIER_DEPTH):
        values.append(_node_hash(values[-1], values[-1], height))
    return tuple(values)


@dataclass(frozen=True, slots=True)
class StrongIndexedLeaf:
    index: int
    value: bytes
    next_value: bytes
    next_index: int

    def __post_init__(self) -> None:
        _index("leaf_index", self.index)
        _wide_value("leaf_value", self.value, allow_sentinel=True)
        _wide_value("leaf_next_value", self.next_value, allow_sentinel=True)
        _index("leaf_next_index", self.next_index)

    @property
    def digest(self) -> bytes:
        return _leaf_hash(
            self.value, self.next_value, self.next_index, self.index
        )


@dataclass(frozen=True, slots=True)
class StrongNonMembershipWitness:
    status: str
    root_before: bytes
    root_after: bytes
    nullifier: bytes
    predecessor_index: int
    predecessor_value: bytes
    successor_value: bytes
    successor_index: int
    inserted_index: int
    predecessor_path: tuple[bytes, ...]
    insertion_path: tuple[bytes, ...]

    def __post_init__(self) -> None:
        require_synthetic_reference_enabled()
        if self.status != STRONG_INDEXED_REFERENCE_STATUS:
            raise ValueError("strong_nullifier_witness_status_invalid")
        for label, value in (
            ("root_before", self.root_before),
            ("root_after", self.root_after),
        ):
            if type(value) is not bytes or len(value) != 64 or not any(value):
                raise ValueError(f"strong_nullifier_{label}_invalid")
        _wide_value("witness_nullifier", self.nullifier)
        _wide_value(
            "witness_predecessor", self.predecessor_value, allow_sentinel=True
        )
        _wide_value(
            "witness_successor", self.successor_value, allow_sentinel=True
        )
        _index("witness_predecessor_index", self.predecessor_index)
        _index("witness_successor_index", self.successor_index)
        _index("witness_inserted_index", self.inserted_index)
        if self.inserted_index <= 1 or self.inserted_index == self.predecessor_index:
            raise ValueError("strong_nullifier_inserted_index_invalid")
        for label, path in (
            ("predecessor_path", self.predecessor_path),
            ("insertion_path", self.insertion_path),
        ):
            if (
                type(path) is not tuple
                or len(path) != STRONG_NULLIFIER_DEPTH
                or any(type(value) is not bytes or len(value) != 64 for value in path)
            ):
                raise ValueError(f"strong_nullifier_{label}_invalid")


class StrongIndexedNullifierTree:
    """In-memory full-width indexed tree used only by synthetic references."""

    def __init__(self, values: Iterable[bytes] | None = None):
        require_synthetic_reference_enabled()
        self._nodes: dict[int, StrongIndexedLeaf] = {
            0: StrongIndexedLeaf(0, STRONG_NULLIFIER_ZERO, STRONG_NULLIFIER_MAX, 1),
            1: StrongIndexedLeaf(1, STRONG_NULLIFIER_MAX, STRONG_NULLIFIER_MAX, 1),
        }
        self._value_to_index: dict[bytes, int] = {
            STRONG_NULLIFIER_ZERO: 0,
            STRONG_NULLIFIER_MAX: 1,
        }
        self._sorted_values: list[bytes] = [
            STRONG_NULLIFIER_ZERO,
            STRONG_NULLIFIER_MAX,
        ]
        self._next_index = 2
        self._root_cache: bytes | None = None
        for value in values or ():
            self.insert(value)

    def clone(self) -> "StrongIndexedNullifierTree":
        clone = object.__new__(StrongIndexedNullifierTree)
        clone._nodes = dict(self._nodes)
        clone._value_to_index = dict(self._value_to_index)
        clone._sorted_values = list(self._sorted_values)
        clone._next_index = self._next_index
        clone._root_cache = self._root_cache
        return clone

    @property
    def root(self) -> bytes:
        if self._root_cache is None:
            self._root_cache = self._root_and_path(0)[0]
        return self._root_cache

    def contains(self, value: bytes) -> bool:
        return _wide_value("contains_value", value) in self._value_to_index

    def _predecessor_successor(
        self, value: bytes
    ) -> tuple[StrongIndexedLeaf, StrongIndexedLeaf]:
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
        zeros = _zero_hashes()
        for height in range(STRONG_NULLIFIER_DEPTH):
            path.append(nodes.get(cursor ^ 1, zeros[height]))
            parents = sorted({index >> 1 for index in nodes})
            nodes = {
                parent: _node_hash(
                    nodes.get(parent * 2, zeros[height]),
                    nodes.get(parent * 2 + 1, zeros[height]),
                    height,
                )
                for parent in parents
            }
            cursor >>= 1
        return nodes.get(0, zeros[STRONG_NULLIFIER_DEPTH]), tuple(path)

    def prove_nonmembership(self, value: bytes) -> StrongNonMembershipWitness:
        nullifier = _wide_value("proof_value", value)
        if nullifier in self._value_to_index:
            raise DuplicateStrongNullifierError("strong nullifier already present")
        predecessor, successor = self._predecessor_successor(nullifier)
        root_before, predecessor_path = self._root_and_path(predecessor.index)
        inserted_index = self._next_index

        middle = self.clone()
        middle._nodes[predecessor.index] = StrongIndexedLeaf(
            predecessor.index,
            predecessor.value,
            nullifier,
            inserted_index,
        )
        middle._root_cache = None
        middle_root, insertion_path = middle._root_and_path(inserted_index)

        after = middle.clone()
        after._nodes[inserted_index] = StrongIndexedLeaf(
            inserted_index,
            nullifier,
            successor.value,
            successor.index,
        )
        after._value_to_index[nullifier] = inserted_index
        insort(after._sorted_values, nullifier)
        after._next_index += 1
        after._root_cache = None
        root_after, verified_insertion_path = after._root_and_path(inserted_index)
        if insertion_path != verified_insertion_path:
            raise AssertionError("strong_nullifier_insertion_path_changed_unexpectedly")
        if _path_root(
            STRONG_NULLIFIER_ZERO, inserted_index, insertion_path
        ) != middle_root:
            raise AssertionError("strong_nullifier_empty_insertion_path_mismatch")
        if _path_root(
            after._nodes[inserted_index].digest,
            inserted_index,
            insertion_path,
        ) != root_after:
            raise AssertionError("strong_nullifier_after_path_mismatch")
        return StrongNonMembershipWitness(
            STRONG_INDEXED_REFERENCE_STATUS,
            root_before,
            root_after,
            nullifier,
            predecessor.index,
            predecessor.value,
            successor.value,
            successor.index,
            inserted_index,
            predecessor_path,
            insertion_path,
        )

    def insert(self, value: bytes) -> None:
        nullifier = _wide_value("insert_value", value)
        if nullifier in self._value_to_index:
            raise DuplicateStrongNullifierError("strong nullifier already present")
        predecessor, successor = self._predecessor_successor(nullifier)
        new_index = self._next_index
        self._next_index += 1
        self._nodes[predecessor.index] = StrongIndexedLeaf(
            predecessor.index,
            predecessor.value,
            nullifier,
            new_index,
        )
        self._nodes[new_index] = StrongIndexedLeaf(
            new_index,
            nullifier,
            successor.value,
            successor.index,
        )
        self._value_to_index[nullifier] = new_index
        insort(self._sorted_values, nullifier)
        self._root_cache = None


def _path_step(current: bytes, sibling: bytes, bit: int, height: int) -> bytes:
    if bit == 0:
        return _node_hash(current, sibling, height)
    if bit == 1:
        return _node_hash(sibling, current, height)
    raise ValueError("strong_nullifier_path_bit_invalid")


def _path_root(leaf: bytes, index: int, siblings: tuple[bytes, ...]) -> bytes:
    if type(leaf) is not bytes or len(leaf) != 64:
        raise TypeError("strong_nullifier_path_leaf_invalid")
    cursor = _index("path_index", index)
    if type(siblings) is not tuple or len(siblings) != STRONG_NULLIFIER_DEPTH:
        raise ValueError("strong_nullifier_path_depth_mismatch")
    current = leaf
    for height, sibling in enumerate(siblings):
        if type(sibling) is not bytes or len(sibling) != 64:
            raise ValueError("strong_nullifier_path_sibling_invalid")
        current = _path_step(current, sibling, cursor & 1, height)
        cursor >>= 1
    if cursor != 0:
        raise ValueError("strong_nullifier_path_index_out_of_capacity")
    return current


def _two_leaf_transition_roots(
    witness: StrongNonMembershipWitness,
) -> tuple[bytes, bytes]:
    predecessor_old = _leaf_hash(
        witness.predecessor_value,
        witness.successor_value,
        witness.successor_index,
        witness.predecessor_index,
    )
    predecessor_new = _leaf_hash(
        witness.predecessor_value,
        witness.nullifier,
        witness.inserted_index,
        witness.predecessor_index,
    )
    insertion_old = STRONG_NULLIFIER_ZERO
    insertion_new = _leaf_hash(
        witness.nullifier,
        witness.successor_value,
        witness.successor_index,
        witness.inserted_index,
    )
    predecessor_cursor = witness.predecessor_index
    insertion_cursor = witness.inserted_index
    height = 0
    joined = False
    while height < STRONG_NULLIFIER_DEPTH:
        predecessor_bit = predecessor_cursor & 1
        insertion_bit = insertion_cursor & 1
        if predecessor_cursor >> 1 == insertion_cursor >> 1:
            if predecessor_cursor == insertion_cursor or predecessor_bit == insertion_bit:
                raise ValueError("strong_nullifier_multiproof_indices_invalid")
            if not hmac.compare_digest(
                witness.predecessor_path[height], insertion_old
            ):
                raise ValueError("strong_nullifier_predecessor_sibling_mismatch")
            if not hmac.compare_digest(
                witness.insertion_path[height], predecessor_new
            ):
                raise ValueError("strong_nullifier_insertion_sibling_mismatch")
            if predecessor_bit == 0:
                predecessor_old = _node_hash(
                    predecessor_old, insertion_old, height
                )
                predecessor_new = _node_hash(
                    predecessor_new, insertion_new, height
                )
            else:
                predecessor_old = _node_hash(
                    insertion_old, predecessor_old, height
                )
                predecessor_new = _node_hash(
                    insertion_new, predecessor_new, height
                )
            predecessor_cursor >>= 1
            insertion_cursor >>= 1
            height += 1
            joined = True
            break
        predecessor_old = _path_step(
            predecessor_old,
            witness.predecessor_path[height],
            predecessor_bit,
            height,
        )
        predecessor_new = _path_step(
            predecessor_new,
            witness.predecessor_path[height],
            predecessor_bit,
            height,
        )
        insertion_old = _path_step(
            insertion_old,
            witness.insertion_path[height],
            insertion_bit,
            height,
        )
        insertion_new = _path_step(
            insertion_new,
            witness.insertion_path[height],
            insertion_bit,
            height,
        )
        predecessor_cursor >>= 1
        insertion_cursor >>= 1
        height += 1
    if not joined or predecessor_cursor != insertion_cursor:
        raise ValueError("strong_nullifier_multiproof_join_mismatch")

    root_before = predecessor_old
    root_after = predecessor_new
    while height < STRONG_NULLIFIER_DEPTH:
        if predecessor_cursor != insertion_cursor:
            raise ValueError("strong_nullifier_shared_path_mismatch")
        bit = predecessor_cursor & 1
        if not hmac.compare_digest(
            witness.predecessor_path[height], witness.insertion_path[height]
        ):
            raise ValueError("strong_nullifier_shared_sibling_mismatch")
        root_before = _path_step(
            root_before, witness.predecessor_path[height], bit, height
        )
        root_after = _path_step(
            root_after, witness.predecessor_path[height], bit, height
        )
        predecessor_cursor >>= 1
        insertion_cursor >>= 1
        height += 1
    if predecessor_cursor != 0 or insertion_cursor != 0:
        raise ValueError("strong_nullifier_index_out_of_capacity")
    return root_before, root_after


def verify_strong_nonmembership_witness(
    witness: StrongNonMembershipWitness,
) -> bool:
    if not isinstance(witness, StrongNonMembershipWitness):
        raise TypeError("strong_nullifier_witness_type_invalid")
    witness.__post_init__()
    if not (
        witness.predecessor_value
        < witness.nullifier
        < witness.successor_value
    ):
        raise ValueError("strong_nullifier_not_between_predecessor_and_successor")
    root_before, root_after = _two_leaf_transition_roots(witness)
    if not hmac.compare_digest(root_before, witness.root_before):
        raise ValueError("strong_nullifier_predecessor_membership_mismatch")
    if not hmac.compare_digest(root_after, witness.root_after):
        raise ValueError("strong_nullifier_inserted_membership_mismatch")
    return True
