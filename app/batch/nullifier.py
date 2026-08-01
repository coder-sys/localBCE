from __future__ import annotations

from bisect import bisect_left, insort
from dataclasses import asdict, dataclass, field
from functools import lru_cache
from typing import Dict, Iterable, List

from app.batch.poseidon import FIELD_MODULUS, domain_poseidon_hash, domain_tag, poseidon_many


DEPTH = 32
MAX_NULLIFIER = FIELD_MODULUS - 1


class DuplicateNullifierError(ValueError):
    pass


def field_to_hex(value: int) -> str:
    return f"{int(value):064x}"


@dataclass(frozen=True)
class IndexedLeaf:
    index: int
    value: int
    next_value: int
    next_index: int

    @property
    def hash(self) -> int:
        return _indexed_leaf_hash(self.value, self.next_value, self.next_index, self.index)


_PAIR_HASH_CACHE: Dict[tuple[int, int], int] = {}
_LEAF_HASH_CACHE: Dict[tuple[int, int, int, int], int] = {}


def _indexed_leaf_hash(value: int, next_value: int, next_index: int, index: int) -> int:
    key = (int(value), int(next_value), int(next_index), int(index))
    cached = _LEAF_HASH_CACHE.get(key)
    if cached is not None:
        return cached
    hashed = domain_poseidon_hash("nullifier", key)
    _LEAF_HASH_CACHE[key] = hashed
    return hashed


def _pair_hashes(rows: List[List[int]]) -> List[int]:
    out: List[int | None] = [None] * len(rows)
    missing_keys: List[tuple[int, int]] = []
    missing_rows: List[List[int]] = []
    for index, row in enumerate(rows):
        key = (int(row[0]), int(row[1]))
        cached = _PAIR_HASH_CACHE.get(key)
        if cached is None:
            missing_keys.append(key)
            missing_rows.append([domain_tag("nullifier"), 2, key[0], key[1]])
        else:
            out[index] = cached
    if missing_rows:
        hashed = poseidon_many(missing_rows)
        for key, value in zip(missing_keys, hashed):
            _PAIR_HASH_CACHE[key] = value
    for index, row in enumerate(rows):
        if out[index] is None:
            key = (int(row[0]), int(row[1]))
            out[index] = _PAIR_HASH_CACHE[key]
    return [int(value) for value in out]


@dataclass(frozen=True)
class NonMembershipWitness:
    root: int
    nullifier: int
    leafIndex: int
    leafValue: int
    nextValue: int
    nextIndex: int
    pathElements: List[int]
    pathIndices: List[int]
    rootAfter: int = 0
    insertedIndex: int = 0
    insertedPathElements: List[int] = field(default_factory=list)
    insertedPathIndices: List[int] = field(default_factory=list)

    def to_circuit_input(self) -> Dict[str, object]:
        data = asdict(self)
        return {
            key: [str(item) for item in value] if isinstance(value, list) else str(value)
            for key, value in data.items()
        }


@lru_cache(maxsize=None)
def _zero_hashes(depth: int = DEPTH) -> tuple[int, ...]:
    zeros = [0]
    current = 0
    for _ in range(depth):
        current = _pair_hashes([[current, current]])[0]
        zeros.append(current)
    return tuple(zeros)


class IndexedNullifierTree:
    """Sparse indexed Merkle tree for the native STARK settlement path.

    The tree uses STARK-field Poseidon elements end to end. The maximum field
    element is reserved as the ordered-tree successor sentinel.
    """

    def __init__(self, leaves: Iterable[int] | None = None):
        self._nodes: Dict[int, IndexedLeaf] = {
            0: IndexedLeaf(0, 0, MAX_NULLIFIER, 1),
            1: IndexedLeaf(1, MAX_NULLIFIER, MAX_NULLIFIER, 1),
        }
        self._value_to_index: Dict[int, int] = {0: 0, MAX_NULLIFIER: 1}
        self._sorted_values_list: List[int] = [0, MAX_NULLIFIER]
        self._root_cache: int | None = None
        self._next_index = 2
        self._zeros = _zero_hashes()
        for value in leaves or []:
            self.insert(value)

    def clone(self) -> "IndexedNullifierTree":
        cloned = IndexedNullifierTree()
        cloned._nodes = dict(self._nodes)
        cloned._value_to_index = dict(self._value_to_index)
        cloned._sorted_values_list = list(self._sorted_values_list)
        cloned._root_cache = self._root_cache
        cloned._next_index = self._next_index
        cloned._zeros = self._zeros
        return cloned

    @property
    def root(self) -> int:
        if self._root_cache is None:
            self._root_cache = self._root_and_path(0)[0]
        return self._root_cache

    @property
    def root_hex(self) -> str:
        return field_to_hex(self.root)

    def contains(self, value: int) -> bool:
        return int(value) in self._value_to_index

    def _validate_value(self, value: int) -> int:
        value = int(value)
        if value <= 0 or value >= MAX_NULLIFIER:
            raise ValueError("nullifier must be in the full-field non-sentinel range")
        return value

    def _sorted_values(self) -> List[int]:
        return list(self._sorted_values_list)

    def _predecessor_successor(self, value: int) -> tuple[IndexedLeaf, IndexedLeaf]:
        pos = bisect_left(self._sorted_values_list, value)
        pred_value = self._sorted_values_list[pos - 1]
        succ_value = self._sorted_values_list[pos]
        return self._nodes[self._value_to_index[pred_value]], self._nodes[self._value_to_index[succ_value]]

    def _root_and_path(self, target_index: int) -> tuple[int, List[int], List[int]]:
        nodes = {index: leaf.hash for index, leaf in self._nodes.items()}
        path_elements: List[int] = []
        path_indices: List[int] = []
        cursor = int(target_index)

        for level in range(DEPTH):
            path_elements.append(nodes.get(cursor ^ 1, self._zeros[level]))
            path_indices.append(cursor & 1)
            parent_rows = []
            parent_indices = []
            for parent in sorted({index // 2 for index in nodes}):
                left = nodes.get(parent * 2, self._zeros[level])
                right = nodes.get(parent * 2 + 1, self._zeros[level])
                parent_indices.append(parent)
                parent_rows.append([left, right])
            nodes = dict(zip(parent_indices, _pair_hashes(parent_rows))) if parent_rows else {}
            cursor //= 2

        return nodes.get(0, self._zeros[DEPTH]), path_elements, path_indices

    def prove_nonmembership(self, value: int) -> NonMembershipWitness:
        value = self._validate_value(value)
        if self.contains(value):
            raise DuplicateNullifierError(f"nullifier already present: {value}")
        predecessor, successor = self._predecessor_successor(value)
        root, path_elements, path_indices = self._root_and_path(predecessor.index)
        inserted_index = self._next_index
        mid_tree = self.clone()
        mid_tree._nodes[predecessor.index] = IndexedLeaf(predecessor.index, predecessor.value, value, inserted_index)
        mid_tree._root_cache = None
        root_mid, inserted_path, inserted_indices = mid_tree._root_and_path(inserted_index)
        after_tree = mid_tree.clone()
        after_tree._nodes[inserted_index] = IndexedLeaf(inserted_index, value, successor.value, successor.index)
        after_tree._value_to_index[value] = inserted_index
        insort(after_tree._sorted_values_list, value)
        after_tree._next_index = inserted_index + 1
        after_tree._root_cache = None
        inserted_root_after, inserted_path, inserted_indices = after_tree._root_and_path(inserted_index)
        empty_slot_root_mid = _path_root(0, inserted_index, inserted_path, inserted_indices)
        if empty_slot_root_mid != root_mid:
            raise ValueError("nullifier_empty_slot_path_mismatch")
        root_after = _path_root(_indexed_leaf_hash(value, successor.value, successor.index, inserted_index), inserted_index, inserted_path, inserted_indices)
        if root_after != inserted_root_after:
            raise ValueError("nullifier_after_path_roots_disagree")
        return NonMembershipWitness(
            root=root,
            nullifier=value,
            leafIndex=predecessor.index,
            leafValue=predecessor.value,
            nextValue=successor.value,
            nextIndex=successor.index,
            pathElements=path_elements,
            pathIndices=path_indices,
            rootAfter=root_after,
            insertedIndex=inserted_index,
            insertedPathElements=inserted_path,
            insertedPathIndices=inserted_indices,
        )

    def duplicate_rejection_witness(self, value: int) -> NonMembershipWitness:
        value = self._validate_value(value)
        if not self.contains(value):
            raise ValueError("duplicate rejection witness requires a present nullifier")
        pos = bisect_left(self._sorted_values_list, value)
        predecessor_value = self._sorted_values_list[max(pos - 1, 0)]
        predecessor = self._nodes[self._value_to_index[predecessor_value]]
        root, path_elements, path_indices = self._root_and_path(predecessor.index)
        return NonMembershipWitness(
            root=root,
            nullifier=value,
            leafIndex=predecessor.index,
            leafValue=predecessor.value,
            nextValue=predecessor.next_value,
            nextIndex=predecessor.next_index,
            pathElements=path_elements,
            pathIndices=path_indices,
        )

    def insert(self, value: int) -> None:
        value = self._validate_value(value)
        if self.contains(value):
            raise DuplicateNullifierError(f"nullifier already present: {value}")
        predecessor, successor = self._predecessor_successor(value)
        new_index = self._next_index
        self._next_index += 1
        self._nodes[predecessor.index] = IndexedLeaf(predecessor.index, predecessor.value, value, new_index)
        self._nodes[new_index] = IndexedLeaf(new_index, value, successor.value, successor.index)
        self._value_to_index[value] = new_index
        insort(self._sorted_values_list, value)
        self._root_cache = None


def _path_root(leaf_hash: int, leaf_index: int, path_elements: Iterable[int], path_indices: Iterable[int]) -> int:
    elements = list(path_elements)
    indices = list(path_indices)
    if len(elements) != DEPTH or len(indices) != DEPTH:
        raise ValueError("nullifier_path_depth_mismatch")
    current = int(leaf_hash)
    cursor = leaf_index
    for sibling, bit in zip(elements, indices):
        if int(bit) not in (0, 1):
            raise ValueError("nullifier_path_index_invalid")
        expected_bit = cursor & 1
        if int(bit) != expected_bit:
            raise ValueError("nullifier_path_index_mismatch")
        sibling = int(sibling)
        current = _pair_hashes([[current, sibling] if expected_bit == 0 else [sibling, current]])[0]
        cursor //= 2
    return current


def _path_step(current: int, sibling: int, bit: int) -> int:
    if int(bit) not in (0, 1):
        raise ValueError("nullifier_path_index_invalid")
    if int(bit) == 0:
        return _pair_hashes([[int(current), int(sibling)]])[0]
    return _pair_hashes([[int(sibling), int(current)]])[0]


def _two_leaf_transition_roots(
    *,
    predecessor_leaf_hash: int,
    updated_predecessor_leaf_hash: int,
    inserted_leaf_hash: int,
    predecessor_index: int,
    inserted_index: int,
    predecessor_path_elements: Iterable[int],
    predecessor_path_indices: Iterable[int],
    inserted_path_elements: Iterable[int],
    inserted_path_indices: Iterable[int],
) -> tuple[int, int]:
    pred_elements = [int(item) for item in predecessor_path_elements]
    pred_indices = [int(item) for item in predecessor_path_indices]
    ins_elements = [int(item) for item in inserted_path_elements]
    ins_indices = [int(item) for item in inserted_path_indices]
    if len(pred_elements) != DEPTH or len(pred_indices) != DEPTH:
        raise ValueError("nullifier_predecessor_path_depth_mismatch")
    if len(ins_elements) != DEPTH or len(ins_indices) != DEPTH:
        raise ValueError("nullifier_inserted_path_depth_mismatch")
    predecessor_index = int(predecessor_index)
    inserted_index = int(inserted_index)
    if predecessor_index == inserted_index:
        raise ValueError("nullifier_inserted_index_invalid")

    pred_old = int(predecessor_leaf_hash)
    pred_new = int(updated_predecessor_leaf_hash)
    ins_old = 0
    ins_new = int(inserted_leaf_hash)
    pred_cursor = predecessor_index
    ins_cursor = inserted_index
    level = 0
    joined = False

    while level < DEPTH:
        pred_bit = pred_cursor & 1
        ins_bit = ins_cursor & 1
        if pred_indices[level] != pred_bit:
            raise ValueError("nullifier_predecessor_path_index_mismatch")
        if ins_indices[level] != ins_bit:
            raise ValueError("nullifier_inserted_path_index_mismatch")
        if pred_cursor // 2 == ins_cursor // 2:
            if pred_cursor == ins_cursor or pred_bit == ins_bit:
                raise ValueError("nullifier_multiproof_indices_invalid")
            if pred_elements[level] != ins_old:
                raise ValueError("nullifier_predecessor_sibling_mismatch")
            if ins_elements[level] != pred_new:
                raise ValueError("nullifier_inserted_sibling_mismatch")
            if pred_bit == 0:
                pred_old = _pair_hashes([[pred_old, ins_old]])[0]
                pred_new = _pair_hashes([[pred_new, ins_new]])[0]
            else:
                pred_old = _pair_hashes([[ins_old, pred_old]])[0]
                pred_new = _pair_hashes([[ins_new, pred_new]])[0]
            pred_cursor //= 2
            ins_cursor //= 2
            level += 1
            joined = True
            break
        pred_old = _path_step(pred_old, pred_elements[level], pred_bit)
        pred_new = _path_step(pred_new, pred_elements[level], pred_bit)
        ins_old = _path_step(ins_old, ins_elements[level], ins_bit)
        ins_new = _path_step(ins_new, ins_elements[level], ins_bit)
        pred_cursor //= 2
        ins_cursor //= 2
        level += 1

    if not joined or pred_cursor != ins_cursor:
        raise ValueError("nullifier_multiproof_join_mismatch")

    root_before = pred_old
    root_after = pred_new
    while level < DEPTH:
        pred_bit = pred_cursor & 1
        ins_bit = ins_cursor & 1
        if pred_cursor != ins_cursor or pred_bit != ins_bit:
            raise ValueError("nullifier_shared_path_mismatch")
        if pred_indices[level] != pred_bit:
            raise ValueError("nullifier_predecessor_path_index_mismatch")
        if ins_indices[level] != ins_bit:
            raise ValueError("nullifier_inserted_path_index_mismatch")
        if pred_elements[level] != ins_elements[level]:
            raise ValueError("nullifier_shared_sibling_mismatch")
        root_before = _path_step(root_before, pred_elements[level], pred_bit)
        root_after = _path_step(root_after, pred_elements[level], pred_bit)
        pred_cursor //= 2
        ins_cursor //= 2
        level += 1

    if pred_cursor != 0 or ins_cursor != 0:
        raise ValueError("nullifier_index_out_of_capacity")
    return root_before, root_after


def verify_nonmembership_witness(witness: NonMembershipWitness) -> bool:
    nullifier = int(witness.nullifier)
    leaf_value = int(witness.leafValue)
    next_value = int(witness.nextValue)
    leaf_index = int(witness.leafIndex)
    next_index = int(witness.nextIndex)
    if nullifier <= 0 or nullifier >= MAX_NULLIFIER:
        raise ValueError("nullifier_out_of_range")
    if not (leaf_value < nullifier < next_value):
        raise ValueError("nullifier_not_between_predecessor_and_successor")
    if leaf_index < 0 or next_index < 0:
        raise ValueError("nullifier_index_out_of_range")
    if int(witness.rootAfter) == 0:
        raise ValueError("nullifier_root_after_required")
    predecessor_leaf_hash = _indexed_leaf_hash(leaf_value, next_value, next_index, leaf_index)
    inserted_index = int(witness.insertedIndex)
    if inserted_index <= 0:
        raise ValueError("nullifier_inserted_index_invalid")
    try:
        root_before, root_after = _two_leaf_transition_roots(
            predecessor_leaf_hash=predecessor_leaf_hash,
            updated_predecessor_leaf_hash=_indexed_leaf_hash(leaf_value, nullifier, inserted_index, leaf_index),
            inserted_leaf_hash=_indexed_leaf_hash(nullifier, next_value, next_index, inserted_index),
            predecessor_index=leaf_index,
            inserted_index=inserted_index,
            predecessor_path_elements=witness.pathElements,
            predecessor_path_indices=witness.pathIndices,
            inserted_path_elements=witness.insertedPathElements,
            inserted_path_indices=witness.insertedPathIndices,
        )
    except ValueError as exc:
        if str(exc) in {
            "nullifier_predecessor_sibling_mismatch",
            "nullifier_inserted_sibling_mismatch",
            "nullifier_shared_sibling_mismatch",
        }:
            raise ValueError("nullifier_predecessor_membership_mismatch") from exc
        raise
    if root_before != int(witness.root):
        raise ValueError("nullifier_predecessor_membership_mismatch")
    if root_after != int(witness.rootAfter):
        raise ValueError("nullifier_inserted_membership_mismatch")
    return True
