from __future__ import annotations

import hashlib
from dataclasses import dataclass
from functools import lru_cache
from typing import Iterable, List

from app.batch.poseidon import FIELD_MODULUS, domain_poseidon_hash


ZERO_LEAF = "00" * 32


def _clean_hex32(value: str) -> str:
    clean = value[2:] if value.startswith("0x") else value
    if len(clean) != 64:
        raise ValueError("expected 32-byte hex value")
    bytes.fromhex(clean)
    return clean.lower()


def _hex32(value: str) -> bytes:
    clean = _clean_hex32(value)
    return bytes.fromhex(clean)


@lru_cache(maxsize=131_072)
def _hash_pair(left: str, right: str) -> str:
    return hashlib.sha256(_hex32(left) + _hex32(right)).hexdigest()


@lru_cache(maxsize=64)
def _zero_hashes(depth: int) -> tuple[str, ...]:
    zeros = [ZERO_LEAF]
    current = ZERO_LEAF
    for _ in range(depth):
        current = _hash_pair(current, current)
        zeros.append(current)
    return tuple(zeros)


def _hex32_words(value: str) -> tuple[int, int]:
    clean = _clean_hex32(value)
    return int(clean[:32], 16), int(clean[32:], 16)


def _node_felt(value: str) -> int:
    clean = _clean_hex32(value)
    felt = int(clean, 16)
    if felt < 0 or felt >= FIELD_MODULUS:
        raise ValueError("Poseidon tree node must be a canonical field element")
    return felt


@lru_cache(maxsize=131_072)
def _poseidon_leaf_hash(hash_domain: str, leaf: str) -> str:
    high, low = _hex32_words(leaf)
    return f"{domain_poseidon_hash(hash_domain, [high, low]):064x}"


@lru_cache(maxsize=131_072)
def _poseidon_hash_pair(hash_domain: str, left: str, right: str) -> str:
    return f"{domain_poseidon_hash(hash_domain, [_node_felt(left), _node_felt(right)]):064x}"


@lru_cache(maxsize=256)
def _poseidon_zero_hashes(hash_domain: str, depth: int) -> tuple[str, ...]:
    zeros = [ZERO_LEAF]
    current = ZERO_LEAF
    for _ in range(depth):
        current = _poseidon_hash_pair(hash_domain, current, current)
        zeros.append(current)
    return tuple(zeros)


@dataclass(frozen=True)
class InclusionProof:
    leaf: str
    leaf_index: int
    siblings: List[str]
    root: str
    hash_domain: str | None = None
    leaf_is_hashed: bool = False


class MerkleTree:
    def __init__(self, leaves: Iterable[str], depth: int = 10):
        if depth <= 0:
            raise ValueError("depth must be positive")
        self.depth = depth
        self.capacity = 2**depth
        self.original_leaves = [leaf[2:] if leaf.startswith("0x") else leaf for leaf in leaves]
        if len(self.original_leaves) > self.capacity:
            raise ValueError("too many leaves for configured depth")
        for leaf in self.original_leaves:
            _hex32(leaf)
        self._zeros = _zero_hashes(depth)
        current = {
            index: leaf
            for index, leaf in enumerate(self.original_leaves)
            if leaf != ZERO_LEAF
        }
        self._sparse_levels: List[dict[int, str]] = [current]
        for level in range(depth):
            parents: dict[int, str] = {}
            for parent in sorted({index // 2 for index in current}):
                left = current.get(parent * 2, self._zeros[level])
                right = current.get(parent * 2 + 1, self._zeros[level])
                parent_hash = _hash_pair(left, right)
                if parent_hash != self._zeros[level + 1]:
                    parents[parent] = parent_hash
            current = parents
            self._sparse_levels.append(current)

    @property
    def levels(self) -> List[List[str]]:
        return [
            [sparse.get(index, self._zeros[level]) for index in range(2 ** (self.depth - level))]
            for level, sparse in enumerate(self._sparse_levels)
        ]

    @property
    def root(self) -> str:
        return self._sparse_levels[-1].get(0, self._zeros[self.depth])

    def prove(self, leaf_index: int) -> InclusionProof:
        if leaf_index < 0 or leaf_index >= len(self.original_leaves):
            raise IndexError("leaf index out of range")
        siblings: List[str] = []
        index = leaf_index
        for level, sparse in enumerate(self._sparse_levels[:-1]):
            siblings.append(sparse.get(index ^ 1, self._zeros[level]))
            index //= 2
        return InclusionProof(
            leaf=self.original_leaves[leaf_index],
            leaf_index=leaf_index,
            siblings=siblings,
            root=self.root,
        )


class PoseidonMerkleTree:
    def __init__(self, leaves: Iterable[str], depth: int = 10, hash_domain: str = "claim"):
        if depth <= 0:
            raise ValueError("depth must be positive")
        self.depth = depth
        self.capacity = 2**depth
        self.hash_domain = hash_domain
        self.original_leaves = [_clean_hex32(leaf) for leaf in leaves]
        if len(self.original_leaves) > self.capacity:
            raise ValueError("too many leaves for configured depth")
        for leaf in self.original_leaves:
            if leaf == ZERO_LEAF:
                raise ValueError("zero leaf is reserved as the sparse Poseidon tree empty sentinel")
        self._zeros = _poseidon_zero_hashes(hash_domain, depth)
        current = {
            index: _poseidon_leaf_hash(hash_domain, leaf)
            for index, leaf in enumerate(self.original_leaves)
        }
        self._sparse_levels: List[dict[int, str]] = [current]
        for level in range(depth):
            parents: dict[int, str] = {}
            for parent in sorted({index // 2 for index in current}):
                left = current.get(parent * 2, self._zeros[level])
                right = current.get(parent * 2 + 1, self._zeros[level])
                parent_hash = _poseidon_hash_pair(hash_domain, left, right)
                if parent_hash != self._zeros[level + 1]:
                    parents[parent] = parent_hash
            current = parents
            self._sparse_levels.append(current)

    @property
    def levels(self) -> List[List[str]]:
        return [
            [sparse.get(index, self._zeros[level]) for index in range(2 ** (self.depth - level))]
            for level, sparse in enumerate(self._sparse_levels)
        ]

    @property
    def root(self) -> str:
        return self._sparse_levels[-1].get(0, self._zeros[self.depth])

    def prove(self, leaf_index: int) -> InclusionProof:
        if leaf_index < 0 or leaf_index >= len(self.original_leaves):
            raise IndexError("leaf index out of range")
        siblings: List[str] = []
        index = leaf_index
        for level, sparse in enumerate(self._sparse_levels[:-1]):
            siblings.append(sparse.get(index ^ 1, self._zeros[level]))
            index //= 2
        return InclusionProof(
            leaf=self.original_leaves[leaf_index],
            leaf_index=leaf_index,
            siblings=siblings,
            root=self.root,
            hash_domain=self.hash_domain,
            leaf_is_hashed=False,
        )


class PoseidonFieldMerkleTree:
    def __init__(self, leaves: Iterable[int | str], depth: int = 10, hash_domain: str = "claim"):
        if depth <= 0:
            raise ValueError("depth must be positive")
        self.depth = depth
        self.capacity = 2**depth
        self.hash_domain = hash_domain
        self.original_leaves = [self._leaf_hex(leaf) for leaf in leaves]
        if len(self.original_leaves) > self.capacity:
            raise ValueError("too many leaves for configured depth")
        for leaf in self.original_leaves:
            if leaf == ZERO_LEAF:
                raise ValueError("zero leaf is reserved as the sparse Poseidon tree empty sentinel")
            _node_felt(leaf)
        self._zeros = _poseidon_zero_hashes(hash_domain, depth)
        current = {
            index: leaf
            for index, leaf in enumerate(self.original_leaves)
        }
        self._sparse_levels: List[dict[int, str]] = [current]
        for level in range(depth):
            parents: dict[int, str] = {}
            for parent in sorted({index // 2 for index in current}):
                left = current.get(parent * 2, self._zeros[level])
                right = current.get(parent * 2 + 1, self._zeros[level])
                parent_hash = _poseidon_hash_pair(hash_domain, left, right)
                if parent_hash != self._zeros[level + 1]:
                    parents[parent] = parent_hash
            current = parents
            self._sparse_levels.append(current)

    @staticmethod
    def _leaf_hex(value: int | str) -> str:
        if isinstance(value, str):
            clean = _clean_hex32(value)
            _node_felt(clean)
            return clean
        felt = int(value)
        if felt <= 0 or felt >= FIELD_MODULUS:
            raise ValueError("Poseidon field tree leaf must be a nonzero canonical field element")
        return f"{felt:064x}"

    @property
    def levels(self) -> List[List[str]]:
        return [
            [sparse.get(index, self._zeros[level]) for index in range(2 ** (self.depth - level))]
            for level, sparse in enumerate(self._sparse_levels)
        ]

    @property
    def root(self) -> str:
        return self._sparse_levels[-1].get(0, self._zeros[self.depth])

    def prove(self, leaf_index: int) -> InclusionProof:
        if leaf_index < 0 or leaf_index >= len(self.original_leaves):
            raise IndexError("leaf index out of range")
        siblings: List[str] = []
        index = leaf_index
        for level, sparse in enumerate(self._sparse_levels[:-1]):
            siblings.append(sparse.get(index ^ 1, self._zeros[level]))
            index //= 2
        return InclusionProof(
            leaf=self.original_leaves[leaf_index],
            leaf_index=leaf_index,
            siblings=siblings,
            root=self.root,
            hash_domain=self.hash_domain,
            leaf_is_hashed=True,
        )


def verify_inclusion(
    leaf: str,
    leaf_index: int,
    siblings: Iterable[str],
    root: str,
    leaf_count: int | None = None,
    hash_domain: str | None = None,
    leaf_is_hashed: bool = False,
) -> bool:
    try:
        sibling_list = list(siblings)
        capacity = 2 ** len(sibling_list)
        if leaf_index < 0 or leaf_index >= capacity:
            return False
        if leaf_count is not None:
            if leaf_count < 0 or leaf_count > capacity or leaf_index >= leaf_count:
                return False
        if hash_domain is None:
            computed = _clean_hex32(leaf)
        elif leaf_is_hashed:
            computed = _clean_hex32(leaf)
        else:
            computed = _poseidon_leaf_hash(hash_domain, leaf)
        index = leaf_index
        for sibling in sibling_list:
            sib = _clean_hex32(sibling)
            if index % 2 == 0:
                computed = _hash_pair(computed, sib) if hash_domain is None else _poseidon_hash_pair(hash_domain, computed, sib)
            else:
                computed = _hash_pair(sib, computed) if hash_domain is None else _poseidon_hash_pair(hash_domain, sib, computed)
            index //= 2
        expected = _clean_hex32(root)
        return computed == expected
    except Exception:
        return False


def build_root(leaves: Iterable[str], depth: int = 10) -> str:
    return MerkleTree(leaves, depth).root


def build_poseidon_root(leaves: Iterable[str], depth: int = 10, hash_domain: str = "claim") -> str:
    return PoseidonMerkleTree(leaves, depth, hash_domain).root
