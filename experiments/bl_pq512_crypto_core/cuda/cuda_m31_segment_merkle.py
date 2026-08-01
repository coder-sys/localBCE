"""Typed SHA3-512 Merkle commitments for segmented M31 codewords.

The top systematic segment may remain B=16 packed while recursive parity
segments use canonical little-endian M31 words.  Segment metadata, exact data
length, padding, and position are bound into every leaf.  The GPU is an
untrusted accelerator: gathered leaves and paths are independently verified
with Python's SHA3-512 implementation.
"""

import array
import ctypes
import hashlib
import time
from dataclasses import dataclass

from cuda_dag_packed_accumulator_benchmark import copy
from cuda_fp16_tower_kat import ck
from cuda_m31_brakedown_factor_benchmark import arguments, function, launch
from cuda_pcs_sha3_merkle_benchmark import (
    MAGIC,
    NODE_DOMAIN,
    ROOT_DOMAIN,
    VERSION,
    sha3_parts,
)


SEGMENT_LEAF_DOMAIN = 516
SEGMENT_SET_DOMAIN = 517
QUERY_DOMAIN = 518
LEAF_SIZE = 1024
LEAVES_PER_LAUNCH = 1 << 10
PACKED_SEGMENT = 0
INNER_SEGMENT = 1
OUTER_SEGMENT = 2
SIMULATED_COIN = hashlib.sha3_512(
    b"Blind Ledger authenticated public coin integration fixture v1"
).digest()


KERNEL = r"""
extern "C" __global__ void hash_segment_leaves(
    const u8 *data,
    u8 *digests,
    u64 data_size,
    u64 tree_leaves,
    u32 leaf_size,
    u32 boundary,
    u32 segment,
    u64 leaf_offset
) {
    u64 leaf =
        leaf_offset + (u64)blockIdx.x * blockDim.x + threadIdx.x;
    if (leaf >= tree_leaves) return;
    u64 state[25];
    unsigned int position;
    begin_typed_hash(state, &position, 516U);
    absorb_u64_be(state, &position, (u64)boundary);
    absorb_u64_be(state, &position, (u64)segment);
    absorb_u64_be(state, &position, data_size);
    absorb_u64_be(state, &position, (u64)leaf_size);
    absorb_u64_be(state, &position, leaf);
    u64 start = leaf * (u64)leaf_size;
    for (u32 offset = 0U; offset < leaf_size; ++offset) {
        u64 index = start + (u64)offset;
        absorb_byte(
            state,
            &position,
            index < data_size ? data[index] : (u8)0U
        );
    }
    finish_sha3_512(state, position, digests + leaf * 64ULL);
}

extern "C" __global__ void gather_segment_leaves(
    const u8 *data,
    u8 *leaves,
    const u32 *queries,
    u64 data_size,
    u32 leaf_size,
    u32 query_count
) {
    u64 index = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    u64 output_size = (u64)query_count * leaf_size;
    if (index >= output_size) return;
    u32 query = (u32)(index / leaf_size);
    u32 offset = (u32)(index % leaf_size);
    u64 source = (u64)queries[query] * leaf_size + offset;
    leaves[index] = source < data_size ? data[source] : (u8)0U;
}
"""


@dataclass(frozen=True)
class Segment:
    boundary: int
    kind: int
    buffer: object

    @property
    def data_size(self):
        return self.buffer.size

    @property
    def actual_leaves(self):
        return (self.data_size + LEAF_SIZE - 1) // LEAF_SIZE

    @property
    def tree_leaves(self):
        return 1 << (self.actual_leaves - 1).bit_length()

    @property
    def depth(self):
        return self.tree_leaves.bit_length() - 1


@dataclass(frozen=True)
class SegmentOpening:
    root: bytes
    leaves: bytes
    paths: bytes
    queries: tuple[int, ...]
    proof_mb: float


def functions(runtime):
    return {
        "hash_leaves": function(runtime, "hash_segment_leaves"),
        "hash_nodes": function(runtime, "hash_nodes"),
        "hash_root": function(runtime, "hash_root"),
        "gather_paths": function(runtime, "gather_paths"),
        "gather_leaves": function(runtime, "gather_segment_leaves"),
    }


def copy_to_host(runtime, pointer, size, name):
    output = (ctypes.c_ubyte * size)()
    ck(
        runtime.cuda.cuMemcpyDtoH_v2(
            ctypes.cast(output, ctypes.c_void_p),
            pointer,
            size,
        ),
        name,
    )
    return bytes(output)


def build_tree(
    runtime,
    allocator,
    kernel_functions,
    segment,
    queries=(),
):
    level_a = allocator.allocate_count(segment.tree_leaves, 64)
    level_b = allocator.allocate_count(max(1, segment.tree_leaves // 2), 64)
    for leaf_offset in range(
        0,
        segment.tree_leaves,
        LEAVES_PER_LAUNCH,
    ):
        leaf_count = min(
            LEAVES_PER_LAUNCH,
            segment.tree_leaves - leaf_offset,
        )
        launch(
            runtime,
            kernel_functions["hash_leaves"],
            leaf_count,
            arguments(
                ctypes.c_uint64(segment.buffer.pointer),
                ctypes.c_uint64(level_a.pointer),
                ctypes.c_uint64(segment.data_size),
                ctypes.c_uint64(segment.tree_leaves),
                ctypes.c_uint32(LEAF_SIZE),
                ctypes.c_uint32(segment.boundary),
                ctypes.c_uint32(segment.kind),
                ctypes.c_uint64(leaf_offset),
            ),
            f"hash_segment_leaves_{leaf_offset}",
        )
        ck(
            runtime.cuda.cuCtxSynchronize(),
            "hash_segment_leaves_sync_"
            f"{segment.boundary}_{segment.kind}_{leaf_offset}",
        )

    query_buffer = None
    path_buffer = None
    leaf_buffer = None
    if queries:
        query_words = array.array("I", queries)
        query_buffer = allocator.allocate(
            len(query_words) * query_words.itemsize
        )
        ck(
            runtime.cuda.cuMemcpyHtoD_v2(
                query_buffer.pointer,
                ctypes.c_void_p(query_words.buffer_info()[0]),
                len(query_words) * query_words.itemsize,
            ),
            "copy_segment_queries",
        )
        path_buffer = allocator.allocate_count(
            segment.depth * len(queries),
            64,
        )
        leaf_buffer = allocator.allocate_count(
            len(queries),
            LEAF_SIZE,
        )
        launch(
            runtime,
            kernel_functions["gather_leaves"],
            len(queries) * LEAF_SIZE,
            arguments(
                ctypes.c_uint64(segment.buffer.pointer),
                ctypes.c_uint64(leaf_buffer.pointer),
                ctypes.c_uint64(query_buffer.pointer),
                ctypes.c_uint64(segment.data_size),
                ctypes.c_uint32(LEAF_SIZE),
                ctypes.c_uint32(len(queries)),
            ),
            "gather_segment_leaves",
        )

    current = level_a
    scratch = level_b
    level_count = segment.tree_leaves
    for level in range(segment.depth):
        if queries:
            launch(
                runtime,
                kernel_functions["gather_paths"],
                len(queries),
                arguments(
                    ctypes.c_uint64(current.pointer),
                    ctypes.c_uint64(query_buffer.pointer),
                    ctypes.c_uint64(path_buffer.pointer),
                    ctypes.c_uint32(len(queries)),
                    ctypes.c_uint32(level),
                ),
                f"gather_segment_paths_{level}",
            )
        parent_count = level_count // 2
        launch(
            runtime,
            kernel_functions["hash_nodes"],
            parent_count,
            arguments(
                ctypes.c_uint64(current.pointer),
                ctypes.c_uint64(scratch.pointer),
                ctypes.c_uint64(parent_count),
            ),
            f"hash_segment_nodes_{level}",
        )
        ck(
            runtime.cuda.cuCtxSynchronize(),
            "hash_segment_nodes_sync_"
            f"{segment.boundary}_{segment.kind}_{level}",
        )
        current, scratch = scratch, current
        level_count = parent_count

    root_buffer = allocator.allocate(64)
    launch(
        runtime,
        kernel_functions["hash_root"],
        1,
        arguments(
            ctypes.c_uint64(current.pointer),
            ctypes.c_uint64(root_buffer.pointer),
            ctypes.c_uint64(segment.tree_leaves),
        ),
        "hash_segment_root",
    )
    ck(runtime.cuda.cuCtxSynchronize(), "hash_segment_tree_sync")
    root = copy_to_host(
        runtime,
        root_buffer.pointer,
        64,
        "copy_segment_root",
    )
    leaves = b""
    paths = b""
    if queries:
        leaves = copy_to_host(
            runtime,
            leaf_buffer.pointer,
            len(queries) * LEAF_SIZE,
            "copy_segment_leaves",
        )
        paths = copy_to_host(
            runtime,
            path_buffer.pointer,
            segment.depth * len(queries) * 64,
            "copy_segment_paths",
        )

    allocator.free(root_buffer)
    if leaf_buffer is not None:
        allocator.free(leaf_buffer)
        allocator.free(path_buffer)
        allocator.free(query_buffer)
    allocator.free(level_b)
    allocator.free(level_a)
    return root, leaves, paths


def segment_set_root(segments, roots):
    parts = []
    for segment, root in zip(segments, roots):
        parts.extend(
            (
                segment.boundary.to_bytes(8, "big"),
                segment.kind.to_bytes(8, "big"),
                segment.data_size.to_bytes(8, "big"),
                segment.tree_leaves.to_bytes(8, "big"),
                root,
            )
        )
    return sha3_parts(SEGMENT_SET_DOMAIN, parts)


def uniform_below(random_word, bound):
    product = random_word * bound
    low = product & 0xFFFF_FFFF_FFFF_FFFF
    threshold = ((1 << 64) - bound) % bound
    if low < threshold:
        return None
    return product >> 64


def derive_queries(segment, set_root, count):
    selected = []
    seen = set()
    draw = 0
    while len(selected) < count:
        retry = 0
        while True:
            digest = sha3_parts(
                QUERY_DOMAIN,
                (
                    set_root,
                    SIMULATED_COIN,
                    segment.boundary.to_bytes(8, "big"),
                    segment.kind.to_bytes(8, "big"),
                    draw.to_bytes(8, "big"),
                    retry.to_bytes(8, "big"),
                ),
            )
            candidate = uniform_below(
                int.from_bytes(digest[:8], "little"),
                segment.actual_leaves,
            )
            if candidate is not None and candidate not in seen:
                selected.append(candidate)
                seen.add(candidate)
                break
            retry += 1
        draw += 1
    return tuple(selected)


def leaf_digest(segment, leaf, payload):
    return sha3_parts(
        SEGMENT_LEAF_DOMAIN,
        (
            segment.boundary.to_bytes(8, "big"),
            segment.kind.to_bytes(8, "big"),
            segment.data_size.to_bytes(8, "big"),
            LEAF_SIZE.to_bytes(8, "big"),
            leaf.to_bytes(8, "big"),
            payload,
        ),
    )


def verify_opening(segment, opening):
    for query_position, leaf in enumerate(opening.queries):
        payload_start = query_position * LEAF_SIZE
        current = leaf_digest(
            segment,
            leaf,
            opening.leaves[payload_start : payload_start + LEAF_SIZE],
        )
        node_index = leaf
        for level in range(segment.depth):
            path_start = (
                level * len(opening.queries) + query_position
            ) * 64
            sibling = opening.paths[path_start : path_start + 64]
            if node_index & 1:
                current = sha3_parts(NODE_DOMAIN, (sibling, current))
            else:
                current = sha3_parts(NODE_DOMAIN, (current, sibling))
            node_index >>= 1
        reconstructed = sha3_parts(
            ROOT_DOMAIN,
            (segment.tree_leaves.to_bytes(8, "big"), current),
        )
        if reconstructed != opening.root:
            return False
    return True


def mutation_tests(segment, opening):
    if not opening.queries:
        raise AssertionError("mutation_tests_need_queries")
    mutated_leaves = bytearray(opening.leaves)
    mutated_leaves[0] ^= 1
    leaf_mutation = SegmentOpening(
        opening.root,
        bytes(mutated_leaves),
        opening.paths,
        opening.queries,
        opening.proof_mb,
    )
    if verify_opening(segment, leaf_mutation):
        raise SystemExit("mutated_segment_leaf_accepted")
    mutated_paths = bytearray(opening.paths)
    mutated_paths[0] ^= 1
    path_mutation = SegmentOpening(
        opening.root,
        opening.leaves,
        bytes(mutated_paths),
        opening.queries,
        opening.proof_mb,
    )
    if verify_opening(segment, path_mutation):
        raise SystemExit("mutated_segment_path_accepted")
    mutated_root = bytearray(opening.root)
    mutated_root[0] ^= 1
    root_mutation = SegmentOpening(
        bytes(mutated_root),
        opening.leaves,
        opening.paths,
        opening.queries,
        opening.proof_mb,
    )
    if verify_opening(segment, root_mutation):
        raise SystemExit("mutated_segment_root_accepted")


def commit_segments(runtime, allocator, kernel_functions, segments):
    roots = []
    started = time.perf_counter()
    for segment in segments:
        root, _, _ = build_tree(
            runtime,
            allocator,
            kernel_functions,
            segment,
        )
        roots.append(root)
    return tuple(roots), time.perf_counter() - started


def open_segments(
    runtime,
    allocator,
    kernel_functions,
    segments,
    committed_roots,
    query_count,
):
    set_root = segment_set_root(segments, committed_roots)
    openings = []
    verify_seconds = 0.0
    started = time.perf_counter()
    for segment, committed_root in zip(segments, committed_roots):
        queries = derive_queries(segment, set_root, query_count)
        replay_root, leaves, paths = build_tree(
            runtime,
            allocator,
            kernel_functions,
            segment,
            queries,
        )
        if replay_root != committed_root:
            raise SystemExit(
                "segment_replay_root_mismatch_"
                f"{segment.boundary}_{segment.kind}"
            )
        proof_mb = (
            len(leaves) + len(paths) + len(queries) * 4 + 64
        ) / 1_000_000.0
        opening = SegmentOpening(
            replay_root,
            leaves,
            paths,
            queries,
            proof_mb,
        )
        verify_started = time.perf_counter()
        if not verify_opening(segment, opening):
            raise SystemExit(
                "independent_segment_opening_failed_"
                f"{segment.boundary}_{segment.kind}"
            )
        mutation_tests(segment, opening)
        verify_seconds += time.perf_counter() - verify_started
        openings.append(opening)
    return (
        set_root,
        tuple(openings),
        time.perf_counter() - started,
        verify_seconds,
    )
