"""Depth-64 authenticated ordered map with fixed-shape upsert witnesses.

Keys and values are complete 512-bit strings.  Sequential append indices are
only tree positions; they never replace or truncate keys.  Every operation
supplies two paths.  Inserts consume ``nextAppendIndex``, update a predecessor,
and fill the allocated leaf; updates change the existing leaf and prove the
allocated leaf remains empty without consuming it.  This gives both modes the
same path and hash schedule while keeping the allocator deterministic without
durable dummy records or allocator holes.

This module is a synthetic semantic reference, not a production verifier.
"""

from __future__ import annotations

from bisect import bisect_left, insort
from dataclasses import dataclass
from hashlib import sha3_512
import hmac
from typing import Final, Iterable

from app.batch.pq_tree_reference import require_synthetic_reference_enabled


ORDERED_MAP_STATUS: Final[str] = "SYNTHETIC_DEPTH64_ORDERED_MAP_V2_COMPACT_NOT_PRODUCTION"
ORDERED_MAP_DEPTH: Final[int] = 64
ORDERED_MAP_SHARD_INDEX_BITS: Final[int] = 24
ORDERED_MAP_SHARD_CAPACITY: Final[int] = 1 << ORDERED_MAP_SHARD_INDEX_BITS
ZERO_512: Final[bytes] = bytes(64)
MAX_512: Final[bytes] = b"\xff" * 64
_MAGIC: Final[bytes] = b"BL/PQ/MAP4"
_LEAF_TAG: Final[bytes] = _MAGIC + b"\x00"
_NODE_TAG: Final[bytes] = _MAGIC + b"\x01"
_ROOT_TAG: Final[bytes] = _MAGIC + b"\x02"
_U64_LIMIT: Final[int] = 1 << 64


def _domain(value: object) -> bytes:
    if type(value) is not bytes or len(value) != 1 or value == b"\x00":
        raise ValueError("ordered_map_domain_invalid")
    return value


def _wide(label: str, value: object, *, sentinel: bool = False) -> bytes:
    if type(value) is not bytes or len(value) != 64:
        raise ValueError(f"ordered_map_{label}_not_bytes64")
    if not sentinel and value in {ZERO_512, MAX_512}:
        raise ValueError(f"ordered_map_{label}_reserved")
    return value


def _index(label: str, value: object) -> int:
    if type(value) is not int or not 0 <= value < _U64_LIMIT:
        raise ValueError(f"ordered_map_{label}_invalid")
    return value


@dataclass(frozen=True, slots=True, order=True)
class OrderedMapLeaf:
    index: int
    key_512: bytes
    value_512: bytes
    next_key_512: bytes
    next_index: int

    def __post_init__(self) -> None:
        _index("leaf_index", self.index)
        _wide("leaf_key", self.key_512, sentinel=True)
        _wide("leaf_value", self.value_512, sentinel=True)
        _wide("leaf_next_key", self.next_key_512, sentinel=True)
        _index("leaf_next_index", self.next_index)

    def digest(self, map_domain: bytes) -> bytes:
        return sha3_512(ordered_map_leaf_preimage(map_domain, self)).digest()


def ordered_map_leaf_preimage(
    map_domain: bytes,
    leaf: OrderedMapLeaf,
) -> bytes:
    domain = _domain(map_domain)
    if type(leaf) is not OrderedMapLeaf:
        raise TypeError("ordered_map_leaf_required")
    leaf.__post_init__()
    return (
        _LEAF_TAG
        + domain
        + leaf.key_512
        + leaf.value_512
        + leaf.next_key_512
        + leaf.next_index.to_bytes(8, "big")
    )


def _require_operation_semantics(
    mode: str,
    next_append_index_before: int,
    next_append_index_after: int,
    key_512: bytes,
    value_before_512: bytes,
    value_after_512: bytes,
    target_before: OrderedMapLeaf,
    target_after: OrderedMapLeaf,
    allocated_after: OrderedMapLeaf | None,
) -> None:
    if mode not in {"insert", "update"}:
        raise ValueError("ordered_map_operation_mode_invalid")
    expected_next = next_append_index_before + int(mode == "insert")
    if next_append_index_after != expected_next:
        raise ValueError("ordered_map_cursor_transition_invalid")
    if not 2 <= next_append_index_before < ORDERED_MAP_SHARD_CAPACITY:
        raise ValueError("ordered_map_cursor_invalid")
    if next_append_index_after > ORDERED_MAP_SHARD_CAPACITY:
        raise ValueError("ordered_map_cursor_shard_capacity_exceeded")
    _wide("operation_key", key_512)
    _wide("operation_value_before", value_before_512, sentinel=True)
    _wide("operation_value_after", value_after_512, sentinel=True)
    if (
        target_before.index >= next_append_index_before
        or target_after.index >= next_append_index_before
    ):
        raise ValueError("ordered_map_target_index_not_below_cursor")
    if mode == "insert":
        if allocated_after is None:
            raise ValueError("ordered_map_insert_leaf_missing")
        if (
            target_before.key_512 >= key_512
            or key_512 >= target_before.next_key_512
            or target_after.index != target_before.index
            or target_after.key_512 != target_before.key_512
            or target_after.value_512 != target_before.value_512
            or target_after.next_key_512 != key_512
            or target_after.next_index != next_append_index_before
            or allocated_after.index != next_append_index_before
            or allocated_after.key_512 != key_512
            or allocated_after.value_512 != value_after_512
            or allocated_after.next_key_512 != target_before.next_key_512
            or allocated_after.next_index != target_before.next_index
            or value_before_512 != ZERO_512
        ):
            raise ValueError("ordered_map_insert_semantics_invalid")
        return
    if allocated_after is not None:
        raise ValueError("ordered_map_update_allocated_leaf_forbidden")
    if (
        target_before.key_512 != key_512
        or target_after.index != target_before.index
        or target_after.key_512 != key_512
        or target_after.next_key_512 != target_before.next_key_512
        or target_after.next_index != target_before.next_index
        or target_before.value_512 != value_before_512
        or target_after.value_512 != value_after_512
    ):
        raise ValueError("ordered_map_update_semantics_invalid")


@dataclass(frozen=True, slots=True)
class OrderedMapOperation:
    map_domain: bytes
    mode: str
    next_append_index_before: int
    next_append_index_after: int
    key_512: bytes
    value_before_512: bytes
    value_after_512: bytes
    target_before: OrderedMapLeaf
    target_after: OrderedMapLeaf
    allocated_after: OrderedMapLeaf | None

    def __post_init__(self) -> None:
        require_synthetic_reference_enabled()
        _domain(self.map_domain)
        _require_operation_semantics(
            self.mode,
            self.next_append_index_before,
            self.next_append_index_after,
            self.key_512,
            self.value_before_512,
            self.value_after_512,
            self.target_before,
            self.target_after,
            self.allocated_after,
        )


def _node_hash(map_domain: bytes, left: bytes, right: bytes, height: int) -> bytes:
    return sha3_512(
        ordered_map_node_preimage(map_domain, left, right, height)
    ).digest()


def ordered_map_node_preimage(
    map_domain: bytes,
    left: bytes,
    right: bytes,
    height: int,
) -> bytes:
    domain = _domain(map_domain)
    _wide("node_left", left, sentinel=True)
    _wide("node_right", right, sentinel=True)
    if type(height) is not int or not 0 <= height < ORDERED_MAP_DEPTH:
        raise ValueError("ordered_map_node_height_invalid")
    return _NODE_TAG + domain + height.to_bytes(1, "big") + left + right


def ordered_map_node_hash(
    map_domain: bytes, left: bytes, right: bytes, height: int
) -> bytes:
    return _node_hash(map_domain, left, right, height)


def _zero_hashes(map_domain: bytes) -> tuple[bytes, ...]:
    values = [ZERO_512]
    for height in range(ORDERED_MAP_DEPTH):
        values.append(_node_hash(map_domain, values[-1], values[-1], height))
    return tuple(values)


def ordered_map_zero_hashes(map_domain: bytes) -> tuple[bytes, ...]:
    return _zero_hashes(map_domain)


def ordered_map_state_root(
    map_domain: bytes, next_append_index: int, inner_root: bytes
) -> bytes:
    return sha3_512(
        ordered_map_state_preimage(map_domain, next_append_index, inner_root)
    ).digest()


def ordered_map_state_preimage(
    map_domain: bytes,
    next_append_index: int,
    inner_root: bytes,
) -> bytes:
    domain = _domain(map_domain)
    if not 2 <= _index("next_append_index", next_append_index) <= ORDERED_MAP_SHARD_CAPACITY:
        raise ValueError("ordered_map_next_append_index_invalid")
    _wide("inner_root", inner_root)
    return (
        _ROOT_TAG
        + domain
        + next_append_index.to_bytes(8, "big")
        + inner_root
    )


@dataclass(frozen=True, slots=True)
class OrderedMapSnapshot:
    map_domain: bytes
    next_append_index: int
    leaves: tuple[OrderedMapLeaf, ...]
    inner_root: bytes
    root: bytes

    def __post_init__(self) -> None:
        require_synthetic_reference_enabled()
        domain = _domain(self.map_domain)
        if not 2 <= _index("snapshot_next_append_index", self.next_append_index) <= ORDERED_MAP_SHARD_CAPACITY:
            raise ValueError("ordered_map_snapshot_cursor_invalid")
        if type(self.leaves) is not tuple or len(self.leaves) < 2:
            raise ValueError("ordered_map_snapshot_leaves_invalid")
        if any(type(value) is not OrderedMapLeaf for value in self.leaves):
            raise ValueError("ordered_map_snapshot_leaf_type_invalid")
        if len({value.index for value in self.leaves}) != len(self.leaves):
            raise ValueError("ordered_map_snapshot_index_duplicate")
        if len({value.key_512 for value in self.leaves}) != len(self.leaves):
            raise ValueError("ordered_map_snapshot_key_duplicate")
        by_key = sorted(self.leaves, key=lambda value: value.key_512)
        if by_key[0].key_512 != ZERO_512 or by_key[-1].key_512 != MAX_512:
            raise ValueError("ordered_map_snapshot_sentinels_missing")
        if (
            by_key[0].index != 0
            or by_key[0].key_512 != ZERO_512
            or by_key[0].value_512 != ZERO_512
        ):
            raise ValueError("ordered_map_snapshot_min_sentinel_invalid")
        if by_key[-1] != OrderedMapLeaf(1, MAX_512, ZERO_512, MAX_512, 1):
            raise ValueError("ordered_map_snapshot_max_sentinel_invalid")
        if any(
            value.index >= self.next_append_index
            or value.index >= ORDERED_MAP_SHARD_CAPACITY
            for value in self.leaves
        ):
            raise ValueError("ordered_map_snapshot_index_not_below_cursor")
        if self.next_append_index in {value.index for value in self.leaves}:
            raise ValueError("ordered_map_snapshot_cursor_occupied")
        for left, right in zip(by_key, by_key[1:], strict=False):
            if left.next_key_512 != right.key_512 or left.next_index != right.index:
                raise ValueError("ordered_map_snapshot_link_invalid")
        if by_key[-1].next_key_512 != MAX_512 or by_key[-1].next_index != by_key[-1].index:
            raise ValueError("ordered_map_snapshot_max_link_invalid")
        builder = object.__new__(OrderedMapBuilder)
        builder.map_domain = domain
        builder._nodes = {value.index: value for value in self.leaves}
        builder._keys = [value.key_512 for value in by_key]
        builder._key_to_index = {value.key_512: value.index for value in by_key}
        builder._next_index = self.next_append_index
        builder._initialize_levels()
        observed = builder._root_and_path(0)[0]
        if not hmac.compare_digest(observed, _wide("snapshot_inner_root", self.inner_root)):
            raise ValueError("ordered_map_snapshot_inner_root_mismatch")
        if not hmac.compare_digest(
            ordered_map_state_root(domain, self.next_append_index, observed),
            _wide("snapshot_root", self.root),
        ):
            raise ValueError("ordered_map_snapshot_root_mismatch")


@dataclass(frozen=True, slots=True)
class OrderedMapUpsertWitness:
    status: str
    map_domain: bytes
    mode: str
    next_append_index_before: int
    next_append_index_after: int
    inner_root_before: bytes
    inner_root_after: bytes
    root_before: bytes
    root_after: bytes
    key_512: bytes
    value_before_512: bytes
    value_after_512: bytes
    target_before: OrderedMapLeaf
    target_after: OrderedMapLeaf
    allocated_after: OrderedMapLeaf | None
    target_path: tuple[bytes, ...]
    allocated_path: tuple[bytes, ...]

    def __post_init__(self) -> None:
        require_synthetic_reference_enabled()
        if self.status != ORDERED_MAP_STATUS or self.mode not in {"insert", "update"}:
            raise ValueError("ordered_map_witness_status_or_mode_invalid")
        domain = _domain(self.map_domain)
        _require_operation_semantics(
            self.mode,
            self.next_append_index_before,
            self.next_append_index_after,
            self.key_512,
            self.value_before_512,
            self.value_after_512,
            self.target_before,
            self.target_after,
            self.allocated_after,
        )
        if len(self.target_path) != ORDERED_MAP_DEPTH or len(self.allocated_path) != ORDERED_MAP_DEPTH:
            raise ValueError("ordered_map_path_depth_invalid")
        for sibling in (*self.target_path, *self.allocated_path):
            _wide("path_sibling", sibling, sentinel=True)
        _wide("witness_inner_root_before", self.inner_root_before, sentinel=True)
        _wide("witness_inner_root_after", self.inner_root_after, sentinel=True)
        _wide("witness_root_before", self.root_before, sentinel=True)
        _wide("witness_root_after", self.root_after, sentinel=True)
        if not hmac.compare_digest(
            self.root_before,
            ordered_map_state_root(domain, self.next_append_index_before, self.inner_root_before),
        ) or not hmac.compare_digest(
            self.root_after,
            ordered_map_state_root(domain, self.next_append_index_after, self.inner_root_after),
        ):
            raise ValueError("ordered_map_header_root_invalid")

    def operation(self) -> OrderedMapOperation:
        return OrderedMapOperation(
            self.map_domain,
            self.mode,
            self.next_append_index_before,
            self.next_append_index_after,
            self.key_512,
            self.value_before_512,
            self.value_after_512,
            self.target_before,
            self.target_after,
            self.allocated_after,
        )


class OrderedMapBuilder:
    def __init__(
        self,
        map_domain: bytes,
        entries: Iterable[tuple[bytes, bytes]] = (),
        *,
        snapshot: OrderedMapSnapshot | None = None,
    ):
        require_synthetic_reference_enabled()
        self.map_domain = _domain(map_domain)
        if snapshot is not None:
            snapshot.__post_init__()
            if snapshot.map_domain != self.map_domain or tuple(entries):
                raise ValueError("ordered_map_snapshot_constructor_invalid")
            self._nodes = {value.index: value for value in snapshot.leaves}
            ordered = sorted(snapshot.leaves, key=lambda value: value.key_512)
            self._keys = [value.key_512 for value in ordered]
            self._key_to_index = {value.key_512: value.index for value in ordered}
            self._next_index = snapshot.next_append_index
            self._initialize_levels()
            return
        self._nodes = {
            0: OrderedMapLeaf(0, ZERO_512, ZERO_512, MAX_512, 1),
            1: OrderedMapLeaf(1, MAX_512, ZERO_512, MAX_512, 1),
        }
        self._keys = [ZERO_512, MAX_512]
        self._key_to_index = {ZERO_512: 0, MAX_512: 1}
        self._next_index = 2
        self._initialize_levels()
        for key, value in sorted(tuple(entries), key=lambda item: item[0]):
            witness = self.prove_upsert(key, value)
            if witness.mode != "insert":
                raise ValueError("ordered_map_initial_entry_duplicate")
            self.apply(witness)

    @property
    def next_append_index(self) -> int:
        return self._next_index

    @property
    def inner_root(self) -> bytes:
        return self._levels[ORDERED_MAP_DEPTH].get(0, self._zeros[-1])

    @property
    def root(self) -> bytes:
        return ordered_map_state_root(self.map_domain, self._next_index, self.inner_root)

    def get(self, key_512: bytes) -> bytes | None:
        key = _wide("get_key", key_512)
        index = self._key_to_index.get(key)
        return None if index is None else self._nodes[index].value_512

    def _initialize_levels(self) -> None:
        self._zeros = _zero_hashes(self.map_domain)
        self._levels: list[dict[int, bytes]] = [
            {} for _ in range(ORDERED_MAP_DEPTH + 1)
        ]
        self._levels[0] = {
            index: leaf.digest(self.map_domain) for index, leaf in self._nodes.items()
        }
        active = set(self._levels[0])
        for height in range(ORDERED_MAP_DEPTH):
            parents = {index >> 1 for index in active}
            for parent in parents:
                digest = _node_hash(
                    self.map_domain,
                    self._levels[height].get(parent * 2, self._zeros[height]),
                    self._levels[height].get(parent * 2 + 1, self._zeros[height]),
                    height,
                )
                if digest != self._zeros[height + 1]:
                    self._levels[height + 1][parent] = digest
            active = parents

    def _rehash_path(self, target_index: int) -> None:
        cursor = _index("rehash_index", target_index)
        leaf = self._nodes.get(cursor)
        if leaf is None:
            self._levels[0].pop(cursor, None)
        else:
            self._levels[0][cursor] = leaf.digest(self.map_domain)
        for height in range(ORDERED_MAP_DEPTH):
            parent = cursor >> 1
            digest = _node_hash(
                self.map_domain,
                self._levels[height].get(parent * 2, self._zeros[height]),
                self._levels[height].get(parent * 2 + 1, self._zeros[height]),
                height,
            )
            if digest == self._zeros[height + 1]:
                self._levels[height + 1].pop(parent, None)
            else:
                self._levels[height + 1][parent] = digest
            cursor = parent

    def _set_leaf(self, index: int, leaf: OrderedMapLeaf | None) -> None:
        if leaf is None:
            self._nodes.pop(index, None)
        else:
            if leaf.index != index:
                raise ValueError("ordered_map_set_leaf_index_mismatch")
            self._nodes[index] = leaf
        self._rehash_path(index)

    def _root_and_path(self, target_index: int) -> tuple[bytes, tuple[bytes, ...]]:
        cursor = _index("path_index", target_index)
        path: list[bytes] = []
        for height in range(ORDERED_MAP_DEPTH):
            path.append(self._levels[height].get(cursor ^ 1, self._zeros[height]))
            cursor >>= 1
        return self.inner_root, tuple(path)

    def prove_upsert(self, key_512: bytes, value_512: bytes) -> OrderedMapUpsertWitness:
        key = _wide("upsert_key", key_512)
        value = _wide("upsert_value", value_512, sentinel=True)
        cursor = self._next_index
        if cursor >= ORDERED_MAP_SHARD_CAPACITY:
            raise ValueError("ordered_map_shard_capacity_exhausted")
        if cursor in self._nodes:
            raise ValueError("ordered_map_cursor_occupied")
        root_before = self.root
        existing_index = self._key_to_index.get(key)
        if existing_index is None:
            position = bisect_left(self._keys, key)
            target_before = self._nodes[self._key_to_index[self._keys[position - 1]]]
            target_after = OrderedMapLeaf(
                target_before.index,
                target_before.key_512,
                target_before.value_512,
                key,
                cursor,
            )
            allocated_after = OrderedMapLeaf(
                cursor,
                key,
                value,
                target_before.next_key_512,
                target_before.next_index,
            )
            value_before = ZERO_512
            mode = "insert"
        else:
            target_before = self._nodes[existing_index]
            target_after = OrderedMapLeaf(
                target_before.index,
                key,
                value,
                target_before.next_key_512,
                target_before.next_index,
            )
            allocated_after = None
            value_before = target_before.value_512
            mode = "update"
        inner_before, target_path = self._root_and_path(target_before.index)
        self._set_leaf(target_before.index, target_after)
        _, allocated_path = self._root_and_path(cursor)
        if allocated_after is not None:
            self._set_leaf(cursor, allocated_after)
        inner_after = self.inner_root
        if allocated_after is not None:
            self._set_leaf(cursor, None)
        self._set_leaf(target_before.index, target_before)
        return OrderedMapUpsertWitness(
            ORDERED_MAP_STATUS,
            self.map_domain,
            mode,
            cursor,
            cursor + int(mode == "insert"),
            inner_before,
            inner_after,
            root_before,
            ordered_map_state_root(
                self.map_domain,
                cursor + int(mode == "insert"),
                inner_after,
            ),
            key,
            value_before,
            value,
            target_before,
            target_after,
            allocated_after,
            target_path,
            allocated_path,
        )

    def apply(self, witness: OrderedMapUpsertWitness) -> None:
        require_ordered_map_upsert(witness)
        if witness.map_domain != self.map_domain or witness.next_append_index_before != self._next_index:
            raise ValueError("ordered_map_apply_state_mismatch")
        if not hmac.compare_digest(witness.root_before, self.root):
            raise ValueError("ordered_map_apply_root_before_mismatch")
        current_target = self._nodes.get(witness.target_before.index)
        if current_target != witness.target_before:
            raise ValueError("ordered_map_apply_target_before_mismatch")
        if self._key_to_index.get(witness.target_before.key_512) != witness.target_before.index:
            raise ValueError("ordered_map_apply_target_index_mismatch")
        if self._next_index in self._nodes:
            raise ValueError("ordered_map_apply_cursor_occupied")
        if witness.mode == "insert" and witness.key_512 in self._key_to_index:
            raise ValueError("ordered_map_apply_insert_key_exists")
        if witness.mode == "update" and self._key_to_index.get(witness.key_512) != witness.target_before.index:
            raise ValueError("ordered_map_apply_update_key_missing")
        self._set_leaf(witness.target_after.index, witness.target_after)
        if witness.allocated_after is not None:
            leaf = witness.allocated_after
            self._set_leaf(leaf.index, leaf)
            self._key_to_index[leaf.key_512] = leaf.index
            insort(self._keys, leaf.key_512)
        self._next_index += int(witness.mode == "insert")
        if not hmac.compare_digest(witness.root_after, self.root):
            raise ValueError("ordered_map_apply_root_after_mismatch")

    def snapshot(self) -> OrderedMapSnapshot:
        leaves = tuple(sorted(self._nodes.values(), key=lambda value: value.index))
        return OrderedMapSnapshot(
            self.map_domain,
            self._next_index,
            leaves,
            self.inner_root,
            self.root,
        )


def _step(map_domain: bytes, current: bytes, sibling: bytes, bit: int, height: int) -> bytes:
    if bit == 0:
        return _node_hash(map_domain, current, sibling, height)
    if bit == 1:
        return _node_hash(map_domain, sibling, current, height)
    raise ValueError("ordered_map_path_bit_invalid")


def _two_path_roots(witness: OrderedMapUpsertWitness) -> tuple[bytes, bytes]:
    target_old = witness.target_before.digest(witness.map_domain)
    target_new = witness.target_after.digest(witness.map_domain)
    allocated_old = ZERO_512
    allocated_new = (
        ZERO_512
        if witness.allocated_after is None
        else witness.allocated_after.digest(witness.map_domain)
    )
    target_cursor = witness.target_before.index
    allocated_cursor = witness.next_append_index_before
    height = 0
    while height < ORDERED_MAP_DEPTH:
        target_bit = target_cursor & 1
        allocated_bit = allocated_cursor & 1
        if target_cursor >> 1 == allocated_cursor >> 1:
            if target_cursor == allocated_cursor or target_bit == allocated_bit:
                raise ValueError("ordered_map_multiproof_indices_invalid")
            if witness.target_path[height] != allocated_old:
                raise ValueError("ordered_map_target_sibling_mismatch")
            if witness.allocated_path[height] != target_new:
                raise ValueError("ordered_map_allocated_sibling_mismatch")
            if target_bit == 0:
                target_old = _node_hash(witness.map_domain, target_old, allocated_old, height)
                target_new = _node_hash(witness.map_domain, target_new, allocated_new, height)
            else:
                target_old = _node_hash(witness.map_domain, allocated_old, target_old, height)
                target_new = _node_hash(witness.map_domain, allocated_new, target_new, height)
            target_cursor >>= 1
            allocated_cursor >>= 1
            height += 1
            break
        target_old = _step(
            witness.map_domain, target_old, witness.target_path[height], target_bit, height
        )
        target_new = _step(
            witness.map_domain, target_new, witness.target_path[height], target_bit, height
        )
        allocated_old = _step(
            witness.map_domain,
            allocated_old,
            witness.allocated_path[height],
            allocated_bit,
            height,
        )
        allocated_new = _step(
            witness.map_domain,
            allocated_new,
            witness.allocated_path[height],
            allocated_bit,
            height,
        )
        target_cursor >>= 1
        allocated_cursor >>= 1
        height += 1
    else:
        raise ValueError("ordered_map_multiproof_join_missing")
    if target_cursor != allocated_cursor:
        raise ValueError("ordered_map_multiproof_join_invalid")
    root_before = target_old
    root_after = target_new
    while height < ORDERED_MAP_DEPTH:
        if witness.target_path[height] != witness.allocated_path[height]:
            raise ValueError("ordered_map_shared_path_mismatch")
        bit = target_cursor & 1
        root_before = _step(
            witness.map_domain, root_before, witness.target_path[height], bit, height
        )
        root_after = _step(
            witness.map_domain, root_after, witness.target_path[height], bit, height
        )
        target_cursor >>= 1
        allocated_cursor >>= 1
        height += 1
    if target_cursor or allocated_cursor:
        raise ValueError("ordered_map_path_index_overflow")
    return root_before, root_after


def require_ordered_map_upsert(witness: OrderedMapUpsertWitness) -> None:
    if not isinstance(witness, OrderedMapUpsertWitness):
        raise TypeError("ordered_map_upsert_witness_required")
    witness.__post_init__()
    root_before, root_after = _two_path_roots(witness)
    if not hmac.compare_digest(root_before, witness.inner_root_before):
        raise ValueError("ordered_map_inner_root_before_mismatch")
    if not hmac.compare_digest(root_after, witness.inner_root_after):
        raise ValueError("ordered_map_inner_root_after_mismatch")


__all__ = [
    "MAX_512",
    "ORDERED_MAP_DEPTH",
    "ORDERED_MAP_SHARD_CAPACITY",
    "ORDERED_MAP_SHARD_INDEX_BITS",
    "ORDERED_MAP_STATUS",
    "OrderedMapBuilder",
    "OrderedMapLeaf",
    "OrderedMapOperation",
    "OrderedMapSnapshot",
    "OrderedMapUpsertWitness",
    "ZERO_512",
    "ordered_map_state_root",
    "ordered_map_node_hash",
    "ordered_map_leaf_preimage",
    "ordered_map_node_preimage",
    "ordered_map_state_preimage",
    "ordered_map_zero_hashes",
    "require_ordered_map_upsert",
]
