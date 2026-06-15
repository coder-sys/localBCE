from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Iterable, List


ZERO_LEAF = "00" * 32


def _hex32(value: str) -> bytes:
    clean = value[2:] if value.startswith("0x") else value
    if len(clean) != 64:
        raise ValueError("expected 32-byte hex value")
    return bytes.fromhex(clean)


def _hash_pair(left: str, right: str) -> str:
    return hashlib.sha256(_hex32(left) + _hex32(right)).hexdigest()


@dataclass(frozen=True)
class InclusionProof:
    leaf: str
    leaf_index: int
    siblings: List[str]
    root: str


class MerkleTree:
    def __init__(self, leaves: Iterable[str], depth: int = 10):
        if depth <= 0:
            raise ValueError("depth must be positive")
        self.depth = depth
        self.capacity = 2**depth
        self.original_leaves = [leaf[2:] if leaf.startswith("0x") else leaf for leaf in leaves]
        if len(self.original_leaves) > self.capacity:
            raise ValueError("too many leaves for configured depth")
        padded = self.original_leaves + [ZERO_LEAF] * (self.capacity - len(self.original_leaves))
        for leaf in padded:
            _hex32(leaf)
        self.levels: List[List[str]] = [padded]
        current = padded
        for _ in range(depth):
            current = [_hash_pair(current[i], current[i + 1]) for i in range(0, len(current), 2)]
            self.levels.append(current)

    @property
    def root(self) -> str:
        return self.levels[-1][0]

    def prove(self, leaf_index: int) -> InclusionProof:
        if leaf_index < 0 or leaf_index >= len(self.original_leaves):
            raise IndexError("leaf index out of range")
        siblings: List[str] = []
        index = leaf_index
        for level in self.levels[:-1]:
            siblings.append(level[index ^ 1])
            index //= 2
        return InclusionProof(
            leaf=self.original_leaves[leaf_index],
            leaf_index=leaf_index,
            siblings=siblings,
            root=self.root,
        )


def verify_inclusion(leaf: str, leaf_index: int, siblings: Iterable[str], root: str, leaf_count: int | None = None) -> bool:
    try:
        sibling_list = list(siblings)
        capacity = 2 ** len(sibling_list)
        if leaf_index < 0 or leaf_index >= capacity:
            return False
        if leaf_count is not None:
            if leaf_count < 0 or leaf_count > capacity or leaf_index >= leaf_count:
                return False
        computed = leaf[2:] if leaf.startswith("0x") else leaf
        _hex32(computed)
        index = leaf_index
        for sibling in sibling_list:
            sib = sibling[2:] if sibling.startswith("0x") else sibling
            _hex32(sib)
            if index % 2 == 0:
                computed = _hash_pair(computed, sib)
            else:
                computed = _hash_pair(sib, computed)
            index //= 2
        expected = root[2:] if root.startswith("0x") else root
        return computed == expected
    except Exception:
        return False


def build_root(leaves: Iterable[str], depth: int = 10) -> str:
    return MerkleTree(leaves, depth).root
