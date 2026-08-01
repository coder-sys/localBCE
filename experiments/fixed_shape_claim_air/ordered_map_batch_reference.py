"""Batch multiproof for sequential depth-64 ordered-map operations.

The endpoint multiproof authenticates every position read or written by the
batch exactly once.  A sorted memory-access table separately proves that the
per-operation before/after leaves form the same sequential transition as the
reviewed single-upsert semantics.  This shares upper Merkle work without
changing duplicate detection, predecessor insertion, allocator consumption,
or final roots.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha3_512
import hmac
from typing import Final, Sequence

from app.batch.pq_tree_reference import require_synthetic_reference_enabled

from .ordered_map_reference import (
    ORDERED_MAP_DEPTH,
    ORDERED_MAP_SHARD_INDEX_BITS,
    ZERO_512,
    OrderedMapBuilder,
    OrderedMapLeaf,
    OrderedMapOperation,
    OrderedMapSnapshot,
    OrderedMapUpsertWitness,
    MAX_512,
    ordered_map_node_hash,
    ordered_map_leaf_preimage,
    ordered_map_node_preimage,
    ordered_map_state_preimage,
    ordered_map_state_root,
    ordered_map_zero_hashes,
    require_ordered_map_upsert,
)


BATCH_STATUS: Final[str] = (
    "SYNTHETIC_DEPTH64_ORDERED_MAP_BATCH_MULTIPROOF_V1_NOT_PRODUCTION"
)
ORDERED_MAP_BATCH_SCHEDULE_DOMAIN: Final[bytes] = (
    b"BL/PQ512/WAVE1A/ORDERED-MAP-BATCH-SCHEDULE/v1\x00"
)
ORDERED_MAP_HASH_SCHEDULE_DOMAIN: Final[bytes] = (
    b"BL/PQ512/WAVE1A/ORDERED-MAP-HASH-SCHEDULE/v1\x00"
)
_U64_LIMIT: Final[int] = 1 << 64


@dataclass(frozen=True, slots=True)
class OrderedMapBatchSchedule:
    """Fixed privacy envelope for one map's endpoint transition.

    The bounds depend only on the governed operation capacity and shard class,
    never on keys, insert/update selectors, or the decision mix.  Empty rows
    remain explicit AIR padding; these counts are not host estimates.
    """

    operation_rows: int
    shard_index_bits: int
    position_rows: int
    memory_rows: int
    proof_node_rows: int
    node_hash_rows: int
    leaf_hash_rows: int
    header_hash_rows: int
    sha3_call_rows: int
    sha3_permutations: int

    def __post_init__(self) -> None:
        if type(self.operation_rows) is not int or self.operation_rows <= 0:
            raise ValueError("ordered_map_batch_schedule_operations_invalid")
        if (
            type(self.shard_index_bits) is not int
            or not 1 <= self.shard_index_bits <= ORDERED_MAP_DEPTH
        ):
            raise ValueError("ordered_map_batch_schedule_shard_bits_invalid")
        if any(
            type(value) is not int or value <= 0
            for value in (
                self.position_rows,
                self.memory_rows,
                self.proof_node_rows,
                self.node_hash_rows,
                self.leaf_hash_rows,
                self.header_hash_rows,
                self.sha3_call_rows,
                self.sha3_permutations,
            )
        ):
            raise ValueError("ordered_map_batch_schedule_dimension_invalid")


@dataclass(frozen=True, slots=True)
class OrderedMapHashCall:
    ordinal: int
    family: str
    live: bool
    message: bytes = field(repr=False)
    digest_512: bytes

    def __post_init__(self) -> None:
        if type(self.ordinal) is not int or self.ordinal < 0:
            raise ValueError("ordered_map_hash_call_ordinal_invalid")
        if self.family not in {"leaf", "node", "header"}:
            raise ValueError("ordered_map_hash_call_family_invalid")
        if type(self.live) is not bool:
            raise ValueError("ordered_map_hash_call_live_invalid")
        expected_lengths = {"leaf": 212, "node": 141, "header": 84}
        if type(self.message) is not bytes or len(self.message) != expected_lengths[self.family]:
            raise ValueError("ordered_map_hash_call_message_invalid")
        if (
            type(self.digest_512) is not bytes
            or len(self.digest_512) != 64
            or not hmac.compare_digest(
                self.digest_512,
                sha3_512(self.message).digest(),
            )
        ):
            raise ValueError("ordered_map_hash_call_digest_invalid")


def build_ordered_map_batch_schedule(
    operation_rows: int,
    *,
    shard_index_bits: int = ORDERED_MAP_SHARD_INDEX_BITS,
) -> OrderedMapBatchSchedule:
    if type(operation_rows) is not int or operation_rows <= 0:
        raise ValueError("ordered_map_batch_schedule_operations_invalid")
    if (
        type(shard_index_bits) is not int
        or not 1 <= shard_index_bits <= ORDERED_MAP_DEPTH
    ):
        raise ValueError("ordered_map_batch_schedule_shard_bits_invalid")
    positions = 2 * operation_rows
    upper_levels = ORDERED_MAP_DEPTH - shard_index_bits
    proof_nodes = upper_levels + sum(
        min(positions, 1 << (shard_index_bits - height))
        for height in range(shard_index_bits)
    )
    parents_per_root = upper_levels + sum(
        min(positions, 1 << (shard_index_bits - height - 1))
        for height in range(shard_index_bits)
    )
    node_hashes = 2 * parents_per_root
    leaf_hashes = 2 * positions
    header_hashes = 2
    sha3_calls = node_hashes + leaf_hashes + header_hashes
    # Compact MAP4 nodes and headers use two rate blocks; leaves use three.
    permutations = 2 * node_hashes + 3 * leaf_hashes + 2 * header_hashes
    return OrderedMapBatchSchedule(
        operation_rows,
        shard_index_bits,
        positions,
        2 * operation_rows,
        proof_nodes,
        node_hashes,
        leaf_hashes,
        header_hashes,
        sha3_calls,
        permutations,
    )


def require_ordered_map_batch_fits_schedule(
    witness: "OrderedMapBatchWitness",
    schedule: OrderedMapBatchSchedule,
) -> None:
    if not isinstance(witness, OrderedMapBatchWitness):
        raise TypeError("ordered_map_batch_witness_required")
    if not isinstance(schedule, OrderedMapBatchSchedule):
        raise TypeError("ordered_map_batch_schedule_required")
    if len(witness.operations) != schedule.operation_rows:
        raise ValueError("ordered_map_batch_schedule_operation_count_mismatch")
    if witness.next_append_index_after > 1 << schedule.shard_index_bits:
        raise ValueError("ordered_map_batch_schedule_shard_capacity_exceeded")
    observed = (
        len(witness.positions),
        len(witness.memory_accesses),
        len(witness.proof_nodes),
        witness.inner_node_hash_count,
    )
    bounds = (
        schedule.position_rows,
        schedule.memory_rows,
        schedule.proof_node_rows,
        schedule.node_hash_rows,
    )
    if any(value > bound for value, bound in zip(observed, bounds, strict=True)):
        raise ValueError("ordered_map_batch_schedule_bound_exceeded")


def ordered_map_batch_schedule_commitment(
    lanes: Sequence[tuple[bytes, OrderedMapBatchSchedule]],
) -> bytes:
    """Commit ordered map-domain/schedule pairs for Rust parameter parity."""

    materialized = tuple(lanes)
    if not materialized:
        raise ValueError("ordered_map_batch_schedule_lanes_required")
    if len(materialized) > 0xFFFF_FFFF:
        raise ValueError("ordered_map_batch_schedule_lane_count_invalid")
    digest = sha3_512()
    digest.update(ORDERED_MAP_BATCH_SCHEDULE_DOMAIN)
    digest.update(len(materialized).to_bytes(4, "big"))
    for map_domain, schedule in materialized:
        if type(map_domain) is not bytes or len(map_domain) != 1:
            raise ValueError("ordered_map_batch_schedule_domain_invalid")
        if not isinstance(schedule, OrderedMapBatchSchedule):
            raise TypeError("ordered_map_batch_schedule_required")
        digest.update(map_domain)
        for value in (
            schedule.operation_rows,
            schedule.shard_index_bits,
            schedule.position_rows,
            schedule.memory_rows,
            schedule.proof_node_rows,
            schedule.node_hash_rows,
            schedule.leaf_hash_rows,
            schedule.header_hash_rows,
            schedule.sha3_call_rows,
            schedule.sha3_permutations,
        ):
            digest.update(value.to_bytes(8, "big"))
    return digest.digest()


def ordered_map_hash_schedule_commitment(
    calls: Sequence[OrderedMapHashCall],
) -> bytes:
    """Commit all fixed hash rows without retaining their Keccak traces."""

    materialized = tuple(calls)
    if not materialized:
        raise ValueError("ordered_map_hash_schedule_calls_required")
    if len(materialized) > 0xFFFF_FFFF:
        raise ValueError("ordered_map_hash_schedule_call_count_invalid")
    family_codes = {"leaf": 1, "node": 2, "header": 3}
    digest = sha3_512()
    digest.update(ORDERED_MAP_HASH_SCHEDULE_DOMAIN)
    digest.update(len(materialized).to_bytes(4, "big"))
    for ordinal, call in enumerate(materialized):
        if not isinstance(call, OrderedMapHashCall) or call.ordinal != ordinal:
            raise ValueError("ordered_map_hash_schedule_order_invalid")
        digest.update(ordinal.to_bytes(8, "big"))
        digest.update(bytes((family_codes[call.family], int(call.live))))
        digest.update(len(call.message).to_bytes(2, "big"))
        digest.update(call.message)
        digest.update(call.digest_512)
    return digest.digest()


def _bytes64(label: str, value: object) -> bytes:
    if type(value) is not bytes or len(value) != 64:
        raise ValueError(f"ordered_map_batch_{label}_not_bytes64")
    return value


def _position(label: str, value: object) -> int:
    if type(value) is not int or not 0 <= value < _U64_LIMIT:
        raise ValueError(f"ordered_map_batch_{label}_invalid")
    return value


def _leaf_at(
    leaves: dict[int, OrderedMapLeaf], position: int
) -> OrderedMapLeaf | None:
    return leaves.get(position)


def _leaf_digest(
    map_domain: bytes,
    position: int,
    leaf: OrderedMapLeaf | None,
) -> bytes:
    if leaf is None:
        return ZERO_512
    if type(leaf) is not OrderedMapLeaf or leaf.index != position:
        raise ValueError("ordered_map_batch_leaf_position_mismatch")
    return leaf.digest(map_domain)


@dataclass(frozen=True, slots=True, order=True)
class OrderedMapProofNode:
    height: int
    index: int
    digest_512: bytes

    def __post_init__(self) -> None:
        if type(self.height) is not int or not 0 <= self.height < ORDERED_MAP_DEPTH:
            raise ValueError("ordered_map_batch_proof_height_invalid")
        index = _position("proof_index", self.index)
        if index >= 1 << (ORDERED_MAP_DEPTH - self.height):
            raise ValueError("ordered_map_batch_proof_index_out_of_level")
        _bytes64("proof_digest", self.digest_512)


@dataclass(frozen=True, slots=True)
class OrderedMapMemoryAccess:
    position: int
    operation_index: int
    access_kind: int
    before: OrderedMapLeaf | None = field(repr=False)
    after: OrderedMapLeaf | None = field(repr=False)

    def __post_init__(self) -> None:
        _position("memory_position", self.position)
        if type(self.operation_index) is not int or self.operation_index < 0:
            raise ValueError("ordered_map_batch_memory_operation_invalid")
        if self.access_kind not in {0, 1}:
            raise ValueError("ordered_map_batch_memory_kind_invalid")
        for label, leaf in (("before", self.before), ("after", self.after)):
            if leaf is not None and (
                type(leaf) is not OrderedMapLeaf or leaf.index != self.position
            ):
                raise ValueError(f"ordered_map_batch_memory_{label}_invalid")


def _snapshot_levels(
    snapshot: OrderedMapSnapshot,
) -> tuple[tuple[dict[int, bytes], ...], tuple[bytes, ...]]:
    zeros = ordered_map_zero_hashes(snapshot.map_domain)
    levels: list[dict[int, bytes]] = [
        {} for _ in range(ORDERED_MAP_DEPTH + 1)
    ]
    levels[0] = {
        leaf.index: leaf.digest(snapshot.map_domain) for leaf in snapshot.leaves
    }
    active = set(levels[0])
    for height in range(ORDERED_MAP_DEPTH):
        parents = {index >> 1 for index in active}
        for parent in parents:
            levels[height + 1][parent] = ordered_map_node_hash(
                snapshot.map_domain,
                levels[height].get(parent * 2, zeros[height]),
                levels[height].get(parent * 2 + 1, zeros[height]),
                height,
            )
        active = parents
    return tuple(levels), zeros


def _build_proof(
    snapshot: OrderedMapSnapshot,
    positions: tuple[int, ...],
) -> tuple[OrderedMapProofNode, ...]:
    levels, zeros = _snapshot_levels(snapshot)
    frontier = set(positions)
    proof: list[OrderedMapProofNode] = []
    for height in range(ORDERED_MAP_DEPTH):
        for index in sorted(frontier):
            sibling = index ^ 1
            if sibling not in frontier:
                proof.append(
                    OrderedMapProofNode(
                        height,
                        sibling,
                        levels[height].get(sibling, zeros[height]),
                    )
                )
        frontier = {index >> 1 for index in frontier}
    return tuple(sorted(proof))


def _multiproof_root(
    map_domain: bytes,
    positions: tuple[int, ...],
    leaves: tuple[OrderedMapLeaf | None, ...],
    proof_nodes: tuple[OrderedMapProofNode, ...],
    hash_calls: list[tuple[bytes, bytes]] | None = None,
) -> tuple[bytes, int]:
    current = {
        position: _leaf_digest(map_domain, position, leaf)
        for position, leaf in zip(positions, leaves, strict=True)
    }
    proof = {
        (node.height, node.index): node.digest_512 for node in proof_nodes
    }
    if len(proof) != len(proof_nodes):
        raise ValueError("ordered_map_batch_proof_node_duplicate")
    consumed: set[tuple[int, int]] = set()
    hashes = 0
    for height in range(ORDERED_MAP_DEPTH):
        parents = {index >> 1 for index in current}
        next_level: dict[int, bytes] = {}
        for parent in sorted(parents):
            children: list[bytes] = []
            for child in (parent * 2, parent * 2 + 1):
                digest = current.get(child)
                if digest is None:
                    key = (height, child)
                    try:
                        digest = proof[key]
                    except KeyError as exc:
                        raise ValueError("ordered_map_batch_proof_node_missing") from exc
                    consumed.add(key)
                children.append(digest)
            message = ordered_map_node_preimage(
                map_domain,
                children[0],
                children[1],
                height,
            )
            digest = sha3_512(message).digest()
            if hash_calls is not None:
                hash_calls.append((message, digest))
            next_level[parent] = digest
            hashes += 1
        current = next_level
    if set(proof) != consumed:
        raise ValueError("ordered_map_batch_proof_node_redundant")
    if set(current) != {0}:
        raise ValueError("ordered_map_batch_root_frontier_invalid")
    return current[0], hashes


def build_ordered_map_hash_schedule(
    witness: "OrderedMapBatchWitness",
    schedule: OrderedMapBatchSchedule,
) -> tuple[OrderedMapHashCall, ...]:
    require_ordered_map_batch_fits_schedule(witness, schedule)
    leaf_calls: list[tuple[bool, bytes, bytes]] = []
    for leaves in (witness.before_leaves, witness.after_leaves):
        for leaf in leaves:
            if leaf is not None:
                message = ordered_map_leaf_preimage(witness.map_domain, leaf)
                leaf_calls.append((True, message, sha3_512(message).digest()))
    dummy_leaf = OrderedMapLeaf(0, ZERO_512, ZERO_512, MAX_512, 1)
    dummy_leaf_message = ordered_map_leaf_preimage(
        witness.map_domain,
        dummy_leaf,
    )
    dummy_leaf_digest = sha3_512(dummy_leaf_message).digest()
    while len(leaf_calls) < schedule.leaf_hash_rows:
        leaf_calls.append((False, dummy_leaf_message, dummy_leaf_digest))
    if len(leaf_calls) != schedule.leaf_hash_rows:
        raise ValueError("ordered_map_hash_schedule_leaf_bound_exceeded")

    node_calls: list[tuple[bytes, bytes]] = []
    before_root, _ = _multiproof_root(
        witness.map_domain,
        witness.positions,
        witness.before_leaves,
        witness.proof_nodes,
        node_calls,
    )
    after_root, _ = _multiproof_root(
        witness.map_domain,
        witness.positions,
        witness.after_leaves,
        witness.proof_nodes,
        node_calls,
    )
    if before_root != witness.inner_root_before or after_root != witness.inner_root_after:
        raise ValueError("ordered_map_hash_schedule_inner_root_mismatch")
    live_node_calls = len(node_calls)
    dummy_node_message = ordered_map_node_preimage(
        witness.map_domain,
        ZERO_512,
        ZERO_512,
        0,
    )
    dummy_node_digest = sha3_512(dummy_node_message).digest()
    while len(node_calls) < schedule.node_hash_rows:
        node_calls.append((dummy_node_message, dummy_node_digest))
    if len(node_calls) != schedule.node_hash_rows:
        raise ValueError("ordered_map_hash_schedule_node_bound_exceeded")

    headers = (
        (
            ordered_map_state_preimage(
                witness.map_domain,
                witness.next_append_index_before,
                witness.inner_root_before,
            ),
            witness.root_before,
        ),
        (
            ordered_map_state_preimage(
                witness.map_domain,
                witness.next_append_index_after,
                witness.inner_root_after,
            ),
            witness.root_after,
        ),
    )
    calls: list[OrderedMapHashCall] = []
    for live, message, digest in leaf_calls:
        calls.append(OrderedMapHashCall(len(calls), "leaf", live, message, digest))
    for index, (message, digest) in enumerate(node_calls):
        calls.append(
            OrderedMapHashCall(
                len(calls),
                "node",
                index < live_node_calls,
                message,
                digest,
            )
        )
    for message, digest in headers:
        calls.append(OrderedMapHashCall(len(calls), "header", True, message, digest))
    if len(calls) != schedule.sha3_call_rows:
        raise ValueError("ordered_map_hash_schedule_call_count_mismatch")
    return tuple(calls)


def _memory_accesses(
    operations: tuple[OrderedMapOperation, ...],
) -> tuple[OrderedMapMemoryAccess, ...]:
    accesses: list[OrderedMapMemoryAccess] = []
    for index, operation in enumerate(operations):
        accesses.append(
            OrderedMapMemoryAccess(
                operation.target_before.index,
                index,
                0,
                operation.target_before,
                operation.target_after,
            )
        )
        accesses.append(
            OrderedMapMemoryAccess(
                operation.next_append_index_before,
                index,
                1,
                None,
                operation.allocated_after,
            )
        )
    return tuple(
        sorted(
            accesses,
            key=lambda value: (
                value.position,
                value.operation_index,
                value.access_kind,
            ),
        )
    )


def _validate_memory(
    positions: tuple[int, ...],
    before_leaves: tuple[OrderedMapLeaf | None, ...],
    after_leaves: tuple[OrderedMapLeaf | None, ...],
    operations: tuple[OrderedMapOperation, ...],
    accesses: tuple[OrderedMapMemoryAccess, ...],
) -> None:
    expected = _memory_accesses(operations)
    if accesses != expected:
        raise ValueError("ordered_map_batch_memory_access_mismatch")
    before = dict(zip(positions, before_leaves, strict=True))
    after = dict(zip(positions, after_leaves, strict=True))
    grouped: dict[int, list[OrderedMapMemoryAccess]] = {}
    for access in accesses:
        grouped.setdefault(access.position, []).append(access)
    if set(grouped) != set(positions):
        raise ValueError("ordered_map_batch_memory_position_set_mismatch")
    for position, sequence in grouped.items():
        current = before[position]
        for access in sequence:
            if access.before != current:
                raise ValueError("ordered_map_batch_memory_chain_before_mismatch")
            current = access.after
        if current != after[position]:
            raise ValueError("ordered_map_batch_memory_chain_after_mismatch")


@dataclass(frozen=True, slots=True)
class OrderedMapBatchWitness:
    status: str
    map_domain: bytes
    next_append_index_before: int
    next_append_index_after: int
    inner_root_before: bytes
    inner_root_after: bytes
    root_before: bytes
    root_after: bytes
    operations: tuple[OrderedMapOperation, ...] = field(repr=False)
    positions: tuple[int, ...]
    before_leaves: tuple[OrderedMapLeaf | None, ...] = field(repr=False)
    after_leaves: tuple[OrderedMapLeaf | None, ...] = field(repr=False)
    proof_nodes: tuple[OrderedMapProofNode, ...] = field(repr=False)
    memory_accesses: tuple[OrderedMapMemoryAccess, ...] = field(repr=False)

    def __post_init__(self) -> None:
        require_synthetic_reference_enabled()
        if self.status != BATCH_STATUS or type(self.map_domain) is not bytes or len(self.map_domain) != 1:
            raise ValueError("ordered_map_batch_status_or_domain_invalid")
        if type(self.operations) is not tuple or not self.operations:
            raise ValueError("ordered_map_batch_operations_required")
        if any(type(value) is not OrderedMapOperation for value in self.operations):
            raise ValueError("ordered_map_batch_operation_type_invalid")
        if any(value.map_domain != self.map_domain for value in self.operations):
            raise ValueError("ordered_map_batch_operation_domain_mismatch")
        inserts = sum(value.mode == "insert" for value in self.operations)
        if self.next_append_index_after != self.next_append_index_before + inserts:
            raise ValueError("ordered_map_batch_cursor_span_invalid")
        expected_cursor = self.next_append_index_before
        for operation in self.operations:
            if (
                operation.next_append_index_before != expected_cursor
                or operation.next_append_index_after
                != expected_cursor + int(operation.mode == "insert")
            ):
                raise ValueError("ordered_map_batch_operation_cursor_chain_invalid")
            expected_cursor = operation.next_append_index_after
        if (
            type(self.positions) is not tuple
            or not self.positions
            or tuple(sorted(set(self.positions))) != self.positions
            or any(type(value) is not int or not 0 <= value < _U64_LIMIT for value in self.positions)
        ):
            raise ValueError("ordered_map_batch_positions_invalid")
        expected_positions = tuple(
            sorted(
                {
                    value
                    for operation in self.operations
                    for value in (
                        operation.target_before.index,
                        operation.next_append_index_before,
                    )
                }
            )
        )
        if self.positions != expected_positions:
            raise ValueError("ordered_map_batch_position_set_invalid")
        if not (
            type(self.before_leaves) is tuple
            and type(self.after_leaves) is tuple
            and len(self.before_leaves) == len(self.after_leaves) == len(self.positions)
        ):
            raise ValueError("ordered_map_batch_endpoint_leaves_invalid")
        if type(self.proof_nodes) is not tuple or tuple(sorted(self.proof_nodes)) != self.proof_nodes:
            raise ValueError("ordered_map_batch_proof_not_canonical")
        if type(self.memory_accesses) is not tuple:
            raise ValueError("ordered_map_batch_memory_not_tuple")
        _validate_memory(
            self.positions,
            self.before_leaves,
            self.after_leaves,
            self.operations,
            self.memory_accesses,
        )
        inner_before, _ = _multiproof_root(
            self.map_domain,
            self.positions,
            self.before_leaves,
            self.proof_nodes,
        )
        inner_after, _ = _multiproof_root(
            self.map_domain,
            self.positions,
            self.after_leaves,
            self.proof_nodes,
        )
        if not hmac.compare_digest(inner_before, _bytes64("inner_root_before", self.inner_root_before)):
            raise ValueError("ordered_map_batch_inner_root_before_mismatch")
        if not hmac.compare_digest(inner_after, _bytes64("inner_root_after", self.inner_root_after)):
            raise ValueError("ordered_map_batch_inner_root_after_mismatch")
        if not hmac.compare_digest(
            ordered_map_state_root(
                self.map_domain, self.next_append_index_before, inner_before
            ),
            _bytes64("root_before", self.root_before),
        ):
            raise ValueError("ordered_map_batch_root_before_mismatch")
        if not hmac.compare_digest(
            ordered_map_state_root(
                self.map_domain, self.next_append_index_after, inner_after
            ),
            _bytes64("root_after", self.root_after),
        ):
            raise ValueError("ordered_map_batch_root_after_mismatch")

    @property
    def inner_node_hash_count(self) -> int:
        _, before = _multiproof_root(
            self.map_domain, self.positions, self.before_leaves, self.proof_nodes
        )
        _, after = _multiproof_root(
            self.map_domain, self.positions, self.after_leaves, self.proof_nodes
        )
        return before + after


def build_ordered_map_batch_witness(
    before: OrderedMapSnapshot,
    after: OrderedMapSnapshot,
    transitions: Sequence[OrderedMapUpsertWitness],
) -> OrderedMapBatchWitness:
    require_synthetic_reference_enabled()
    if not isinstance(before, OrderedMapSnapshot) or not isinstance(after, OrderedMapSnapshot):
        raise TypeError("ordered_map_batch_snapshots_required")
    before.__post_init__()
    after.__post_init__()
    materialized = tuple(transitions)
    if not materialized:
        raise ValueError("ordered_map_batch_transitions_required")
    for transition in materialized:
        require_ordered_map_upsert(transition)
    if before.map_domain != after.map_domain or any(
        value.map_domain != before.map_domain for value in materialized
    ):
        raise ValueError("ordered_map_batch_domain_mismatch")
    if (
        materialized[0].root_before != before.root
        or materialized[-1].root_after != after.root
        or materialized[0].next_append_index_before != before.next_append_index
        or materialized[-1].next_append_index_after != after.next_append_index
    ):
        raise ValueError("ordered_map_batch_endpoint_transition_mismatch")
    for left, right in zip(materialized, materialized[1:], strict=False):
        if (
            left.root_after != right.root_before
            or left.next_append_index_after != right.next_append_index_before
        ):
            raise ValueError("ordered_map_batch_transition_chain_invalid")

    operations = tuple(value.operation() for value in materialized)
    positions = tuple(
        sorted(
            {
                value
                for operation in operations
                for value in (
                    operation.target_before.index,
                    operation.next_append_index_before,
                )
            }
        )
    )
    before_by_index = {leaf.index: leaf for leaf in before.leaves}
    after_by_index = {leaf.index: leaf for leaf in after.leaves}
    outside = (set(before_by_index) | set(after_by_index)) - set(positions)
    if any(before_by_index.get(index) != after_by_index.get(index) for index in outside):
        raise ValueError("ordered_map_batch_unproven_position_changed")
    before_leaves = tuple(_leaf_at(before_by_index, index) for index in positions)
    after_leaves = tuple(_leaf_at(after_by_index, index) for index in positions)
    proof_nodes = _build_proof(before, positions)
    return OrderedMapBatchWitness(
        BATCH_STATUS,
        before.map_domain,
        before.next_append_index,
        after.next_append_index,
        before.inner_root,
        after.inner_root,
        before.root,
        after.root,
        operations,
        positions,
        before_leaves,
        after_leaves,
        proof_nodes,
        _memory_accesses(operations),
    )


__all__ = [
    "BATCH_STATUS",
    "ORDERED_MAP_BATCH_SCHEDULE_DOMAIN",
    "ORDERED_MAP_HASH_SCHEDULE_DOMAIN",
    "OrderedMapBatchSchedule",
    "OrderedMapBatchWitness",
    "OrderedMapHashCall",
    "OrderedMapMemoryAccess",
    "OrderedMapProofNode",
    "build_ordered_map_batch_schedule",
    "build_ordered_map_batch_witness",
    "build_ordered_map_hash_schedule",
    "ordered_map_batch_schedule_commitment",
    "ordered_map_hash_schedule_commitment",
    "require_ordered_map_batch_fits_schedule",
]
