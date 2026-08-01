from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence

from app.batch.nullifier import DEPTH, MAX_NULLIFIER, _zero_hashes
from app.batch.poseidon import FIELD_MODULUS, domain_poseidon_hash


@dataclass(frozen=True)
class EpochRootResult:
    root: int
    hash_count: int


@dataclass(frozen=True)
class EpochSetTransition:
    root_before: int
    root_after: int
    existing_values: tuple[int, ...]
    batch_values: tuple[int, ...]
    merged_values: tuple[int, ...]
    hash_count: int


def nullifier_words(value: int) -> tuple[int, int]:
    value = _canonical_nullifier(value)
    return value >> 128, value & ((1 << 128) - 1)


def nullifier_from_words(high: int, low: int) -> int:
    high = int(high)
    low = int(low)
    if high < 0 or high >= 2**128 or low < 0 or low >= 2**128:
        raise ValueError("nullifier_word_out_of_range")
    return _canonical_nullifier((high << 128) + low)


def _canonical_nullifier(value: int) -> int:
    value = int(value)
    if value <= 0 or value >= MAX_NULLIFIER or value >= FIELD_MODULUS:
        raise ValueError("nullifier_out_of_range")
    return value


def _strict_sorted(values: Sequence[int], *, label: str) -> tuple[int, ...]:
    ordered = tuple(_canonical_nullifier(value) for value in values)
    for index in range(1, len(ordered)):
        if ordered[index - 1] >= ordered[index]:
            raise ValueError(f"{label}_not_strictly_sorted")
    return ordered


def _merge_disjoint(existing: Sequence[int], batch: Sequence[int]) -> tuple[int, ...]:
    merged: list[int] = []
    left = 0
    right = 0
    while left < len(existing) or right < len(batch):
        if left == len(existing):
            candidate = batch[right]
            right += 1
        elif right == len(batch):
            candidate = existing[left]
            left += 1
        elif existing[left] < batch[right]:
            candidate = existing[left]
            left += 1
        elif batch[right] < existing[left]:
            candidate = batch[right]
            right += 1
        else:
            raise ValueError("epoch_nullifier_already_spent")
        if merged and merged[-1] >= candidate:
            raise ValueError("epoch_nullifier_merge_not_strict")
        merged.append(candidate)
    return tuple(merged)


def _epoch_nullifier_set_root_with_empty(values: Sequence[int], *, depth: int, empty_subtree_root: int, depth_hash_count: int = 0) -> EpochRootResult:
    ordered = _strict_sorted(tuple(values), label="epoch_values")
    acc = domain_poseidon_hash("nullifier", [int(depth), len(ordered), empty_subtree_root])
    hash_count = depth_hash_count + 1
    for index, value in enumerate(ordered):
        acc = domain_poseidon_hash("nullifier", [acc, index, value])
        hash_count += 1
    return EpochRootResult(root=acc, hash_count=hash_count)


def epoch_nullifier_set_root(values: Iterable[int], *, depth: int = DEPTH) -> EpochRootResult:
    if depth <= 0:
        raise ValueError("depth_must_be_positive")
    return _epoch_nullifier_set_root_with_empty(
        tuple(values),
        depth=depth,
        empty_subtree_root=_zero_hashes(depth)[depth],
        depth_hash_count=depth,
    )


def build_epoch_set_transition(
    existing_values: Iterable[int],
    batch_values: Iterable[int],
    *,
    depth: int = DEPTH,
) -> EpochSetTransition:
    existing = _strict_sorted(tuple(existing_values), label="existing_epoch_values")
    batch = _strict_sorted(tuple(batch_values), label="batch_epoch_values")
    if not batch:
        raise ValueError("batch_epoch_values_empty")
    merged = _merge_disjoint(existing, batch)
    empty_subtree_root = _zero_hashes(depth)[depth]
    before = _epoch_nullifier_set_root_with_empty(
        existing,
        depth=depth,
        empty_subtree_root=empty_subtree_root,
        depth_hash_count=depth,
    )
    after = _epoch_nullifier_set_root_with_empty(
        merged,
        depth=depth,
        empty_subtree_root=empty_subtree_root,
        depth_hash_count=0,
    )
    return EpochSetTransition(
        root_before=before.root,
        root_after=after.root,
        existing_values=existing,
        batch_values=batch,
        merged_values=merged,
        hash_count=before.hash_count + after.hash_count,
    )


def assert_epoch_set_transition(
    existing_values: Iterable[int],
    batch_values: Iterable[int],
    root_before: int,
    root_after: int,
    *,
    depth: int = DEPTH,
) -> EpochSetTransition:
    transition = build_epoch_set_transition(existing_values, batch_values, depth=depth)
    if transition.root_before != int(root_before):
        raise ValueError("epoch_nullifier_root_before_mismatch")
    if transition.root_after != int(root_after):
        raise ValueError("epoch_nullifier_root_after_mismatch")
    return transition
