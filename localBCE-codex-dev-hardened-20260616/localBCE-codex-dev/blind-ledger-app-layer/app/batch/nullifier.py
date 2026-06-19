from __future__ import annotations

from dataclasses import asdict, dataclass
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
        self._next_index = 2
        self._zeros = _zero_hashes()
        for value in leaves or []:
            self.insert(value)

    def clone(self) -> "IndexedNullifierTree":
        cloned = IndexedNullifierTree()
        cloned._nodes = dict(self._nodes)
        cloned._value_to_index = dict(self._value_to_index)
        cloned._next_index = self._next_index
        cloned._zeros = self._zeros
        return cloned

    @property
    def root(self) -> int:
        return self._root_and_path(0)[0]

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
        return sorted(self._value_to_index)

    def _predecessor_successor(self, value: int) -> tuple[IndexedLeaf, IndexedLeaf]:
        values = self._sorted_values()
        pred_value = values[0]
        succ_value = values[-1]
        for current in values:
            if current < value:
                pred_value = current
            elif current > value:
                succ_value = current
                break
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
        return NonMembershipWitness(
            root=root,
            nullifier=value,
            leafIndex=predecessor.index,
            leafValue=predecessor.value,
            nextValue=successor.value,
            nextIndex=successor.index,
            pathElements=path_elements,
            pathIndices=path_indices,
        )

    def duplicate_rejection_witness(self, value: int) -> NonMembershipWitness:
        value = self._validate_value(value)
        if not self.contains(value):
            raise ValueError("duplicate rejection witness requires a present nullifier")
        values = self._sorted_values()
        pos = values.index(value)
        predecessor_value = values[max(pos - 1, 0)]
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
    if len(witness.pathElements) != DEPTH or len(witness.pathIndices) != DEPTH:
        raise ValueError("nullifier_path_depth_mismatch")
    current = _indexed_leaf_hash(leaf_value, next_value, next_index, leaf_index)
    cursor = leaf_index
    for sibling, bit in zip(witness.pathElements, witness.pathIndices):
        if int(bit) not in (0, 1):
            raise ValueError("nullifier_path_index_invalid")
        expected_bit = cursor & 1
        if int(bit) != expected_bit:
            raise ValueError("nullifier_path_index_mismatch")
        sibling = int(sibling)
        current = _pair_hashes([[current, sibling] if expected_bit == 0 else [sibling, current]])[0]
        cursor //= 2
    if current != int(witness.root):
        raise ValueError("nullifier_predecessor_membership_mismatch")
    return True
