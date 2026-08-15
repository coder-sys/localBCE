"""Incremental native-128 Binding Merkle commitments for CUDA buffers.

The source tensor is emitted as 32 independently encoded 1 KiB slices per
row.  This module absorbs those slices into one canonical 32 KiB H4-v2 leaf
without ever materializing the 4 GiB tensor.  Node and root framing is byte
identical to ``binding_root_v2.rs``.
"""

import array
import ctypes
from dataclasses import dataclass


BINDING_BYTES = 128
STATE_BYTES = 2 * 25 * 8
LEAF_FRAME = b"BLH4SL02" + (2).to_bytes(2, "big") + b"\0\0"
LEFT_DOMAIN = b"BL/PQ512/WAVE2/BINDING/LEFT/v2\0"
RIGHT_DOMAIN = b"BL/PQ512/WAVE2/BINDING/RIGHT/v2\0"


def _cuda_bytes(name, value):
    return f"__device__ __constant__ u8 {name}[{len(value)}] = {{{','.join(str(x) for x in value)}}};"


KERNEL = (
    _cuda_bytes("binding_left_domain", LEFT_DOMAIN)
    + _cuda_bytes("binding_right_domain", RIGHT_DOMAIN)
    + r'''
__device__ __forceinline__ void binding_absorb_bytes(
    u64 state[25], unsigned int *position, const u8 *value, u32 count
) {
    for (u32 i = 0; i < count; ++i) absorb_byte(state, position, value[i]);
}

__device__ __forceinline__ void binding_begin(
    u64 state[25], unsigned int *position, u32 lane, u32 role, u64 payload_len
) {
    #pragma unroll
    for (u32 i = 0; i < 25U; ++i) state[i] = 0ULL;
    *position = 0U;
    if (lane == 0U) {
        binding_absorb_bytes(state, position, binding_left_domain, sizeof(binding_left_domain));
    } else {
        binding_absorb_bytes(state, position, binding_right_domain, sizeof(binding_right_domain));
    }
    const u8 magic[8] = {'B','L','B','I','N','D','0','2'};
    binding_absorb_bytes(state, position, magic, 8U);
    absorb_u16_be(state, position, 2U);
    absorb_u16_be(state, position, role);
    absorb_u64_be(state, position, payload_len);
}

__device__ __forceinline__ void binding_copy_state(u64 *target, const u64 state[25]) {
    #pragma unroll
    for (u32 i = 0; i < 25U; ++i) target[i] = state[i];
}

extern "C" __global__ void binding_source_init(
    u64 *states, u32 *positions, u64 leaf_count, u64 leaf_bytes,
    u64 boundary, u64 kind
) {
    u64 leaf = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    if (leaf >= leaf_count) return;
    const u64 frame_bytes = 44ULL;
    const u64 payload_len = 8ULL + frame_bytes + leaf_bytes;
    for (u32 lane = 0U; lane < 2U; ++lane) {
        u64 state[25]; unsigned int position;
        binding_begin(state, &position, lane, 0x0101U, payload_len);
        absorb_u64_be(state, &position, leaf);
        const u8 frame_magic[8] = {'B','L','H','4','S','L','0','2'};
        binding_absorb_bytes(state, &position, frame_magic, 8U);
        absorb_u16_be(state, &position, 2U);
        absorb_u16_be(state, &position, 0U);
        absorb_u64_be(state, &position, boundary);
        absorb_u64_be(state, &position, kind);
        absorb_u64_be(state, &position, leaf_count * leaf_bytes);
        absorb_u64_be(state, &position, leaf_bytes);
        binding_copy_state(states + (leaf * 2ULL + lane) * 25ULL, state);
        positions[leaf * 2ULL + lane] = position;
    }
}

extern "C" __global__ void binding_source_absorb(
    u64 *states, u32 *positions, const u8 *slice, u64 leaf_count, u32 slice_bytes
) {
    u64 leaf = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    if (leaf >= leaf_count) return;
    const u8 *payload = slice + leaf * (u64)slice_bytes;
    for (u32 lane = 0U; lane < 2U; ++lane) {
        u64 state[25];
        const u64 *saved = states + (leaf * 2ULL + lane) * 25ULL;
        #pragma unroll
        for (u32 i = 0; i < 25U; ++i) state[i] = saved[i];
        unsigned int position = positions[leaf * 2ULL + lane];
        binding_absorb_bytes(state, &position, payload, slice_bytes);
        binding_copy_state(states + (leaf * 2ULL + lane) * 25ULL, state);
        positions[leaf * 2ULL + lane] = position;
    }
}

extern "C" __global__ void binding_source_finish(
    const u64 *states, const u32 *positions, u8 *digests, u64 leaf_count
) {
    u64 leaf = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    if (leaf >= leaf_count) return;
    for (u32 lane = 0U; lane < 2U; ++lane) {
        u64 state[25];
        const u64 *saved = states + (leaf * 2ULL + lane) * 25ULL;
        #pragma unroll
        for (u32 i = 0; i < 25U; ++i) state[i] = saved[i];
        finish_sha3_512(state, positions[leaf * 2ULL + lane],
                        digests + leaf * 128ULL + lane * 64ULL);
    }
}

extern "C" __global__ void binding_hash_nodes(
    const u8 *children, u8 *parents, u64 parent_count, u32 level
) {
    u64 parent = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    if (parent >= parent_count) return;
    const u8 *payload = children + parent * 256ULL;
    for (u32 lane = 0U; lane < 2U; ++lane) {
        u64 state[25]; unsigned int position;
        binding_begin(state, &position, lane, 0x0102U, 268ULL);
        absorb_byte(state, &position, (u8)(level >> 24U));
        absorb_byte(state, &position, (u8)(level >> 16U));
        absorb_byte(state, &position, (u8)(level >> 8U));
        absorb_byte(state, &position, (u8)level);
        absorb_u64_be(state, &position, parent);
        binding_absorb_bytes(state, &position, payload, 256U);
        finish_sha3_512(state, position, parents + parent * 128ULL + lane * 64ULL);
    }
}

extern "C" __global__ void binding_hash_root(
    const u8 *top, u8 *root, u64 leaf_count, u32 height
) {
    if (blockIdx.x != 0 || threadIdx.x != 0) return;
    for (u32 lane = 0U; lane < 2U; ++lane) {
        u64 state[25]; unsigned int position;
        binding_begin(state, &position, lane, 0x0103U, 140ULL);
        absorb_u64_be(state, &position, leaf_count);
        absorb_byte(state, &position, (u8)(height >> 24U));
        absorb_byte(state, &position, (u8)(height >> 16U));
        absorb_byte(state, &position, (u8)(height >> 8U));
        absorb_byte(state, &position, (u8)height);
        binding_absorb_bytes(state, &position, top, 128U);
        finish_sha3_512(state, position, root + lane * 64ULL);
    }
}

extern "C" __global__ void binding_gather_nodes(
    const u8 *nodes, const u32 *indices, u8 *output, u32 count
) {
    u64 offset = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    if (offset >= (u64)count * 128ULL) return;
    u32 item = (u32)(offset >> 7U);
    output[offset] = nodes[(u64)indices[item] * 128ULL + (offset & 127ULL)];
}
'''
)


@dataclass(frozen=True)
class BindingTreeV2:
    root: bytes
    levels: tuple
    leaf_count: int


class IncrementalSourceCommitmentV2:
    def __init__(self, core, runtime, allocator, functions, leaf_count, leaf_bytes, boundary, kind):
        self.core = core
        self.runtime = runtime
        self.allocator = allocator
        self.functions = functions
        self.leaf_count = leaf_count
        self.leaf_bytes = leaf_bytes
        self.states = allocator.allocate_count(leaf_count, STATE_BYTES)
        self.positions = allocator.allocate_count(leaf_count * 2, 4)
        core.launch(runtime, functions["source_init"], leaf_count, core.arguments(
            ctypes.c_uint64(self.states.pointer), ctypes.c_uint64(self.positions.pointer),
            ctypes.c_uint64(leaf_count), ctypes.c_uint64(leaf_bytes),
            ctypes.c_uint64(boundary), ctypes.c_uint64(kind)), "binding_source_init")
        core.ck(runtime.cuda.cuCtxSynchronize(), "binding_source_init_sync")
        self.absorbed = 0

    def absorb(self, buffer, slice_bytes):
        self.core.launch(self.runtime, self.functions["source_absorb"], self.leaf_count,
                         self.core.arguments(ctypes.c_uint64(self.states.pointer),
                         ctypes.c_uint64(self.positions.pointer), ctypes.c_uint64(buffer.pointer),
                         ctypes.c_uint64(self.leaf_count), ctypes.c_uint32(slice_bytes)),
                         "binding_source_absorb")
        self.core.ck(self.runtime.cuda.cuCtxSynchronize(), "binding_source_absorb_sync")
        self.absorbed += slice_bytes

    def finish(self):
        if self.absorbed != self.leaf_bytes:
            raise RuntimeError(f"binding_source_absorbed={self.absorbed}/{self.leaf_bytes}")
        leaf_level = self.allocator.allocate_count(self.leaf_count, BINDING_BYTES)
        self.core.launch(self.runtime, self.functions["source_finish"], self.leaf_count,
                         self.core.arguments(ctypes.c_uint64(self.states.pointer),
                         ctypes.c_uint64(self.positions.pointer), ctypes.c_uint64(leaf_level.pointer),
                         ctypes.c_uint64(self.leaf_count)), "binding_source_finish")
        self.core.ck(self.runtime.cuda.cuCtxSynchronize(), "binding_source_finish_sync")
        self.allocator.free(self.states); self.allocator.free(self.positions)
        levels = [leaf_level]
        count = self.leaf_count
        level = 1
        while count > 1:
            parent_count = count // 2
            parent = self.allocator.allocate_count(parent_count, BINDING_BYTES)
            self.core.launch(self.runtime, self.functions["hash_nodes"], parent_count,
                             self.core.arguments(ctypes.c_uint64(levels[-1].pointer),
                             ctypes.c_uint64(parent.pointer), ctypes.c_uint64(parent_count),
                             ctypes.c_uint32(level)), "binding_hash_nodes")
            self.core.ck(self.runtime.cuda.cuCtxSynchronize(), "binding_hash_nodes_sync")
            levels.append(parent); count = parent_count; level += 1
        root_buffer = self.allocator.allocate(BINDING_BYTES)
        self.core.launch(self.runtime, self.functions["hash_root"], 1,
                         self.core.arguments(ctypes.c_uint64(levels[-1].pointer),
                         ctypes.c_uint64(root_buffer.pointer), ctypes.c_uint64(self.leaf_count),
                         ctypes.c_uint32(self.leaf_count.bit_length() - 1)), "binding_hash_root")
        self.core.ck(self.runtime.cuda.cuCtxSynchronize(), "binding_hash_root_sync")
        root = self.core.copy_to_host(self.runtime, root_buffer, "copy_binding_root")
        self.allocator.free(root_buffer)
        return BindingTreeV2(root, tuple(levels), self.leaf_count)


def functions(core, runtime):
    return {
        "source_init": core.function(runtime, "binding_source_init"),
        "source_absorb": core.function(runtime, "binding_source_absorb"),
        "source_finish": core.function(runtime, "binding_source_finish"),
        "hash_nodes": core.function(runtime, "binding_hash_nodes"),
        "hash_root": core.function(runtime, "binding_hash_root"),
        "gather_nodes": core.function(runtime, "binding_gather_nodes"),
    }


def frontier_payload(core, runtime, allocator, function, tree, indices):
    payload = bytearray()
    for level, positions in enumerate(core.canonical_frontier(indices, tree.leaf_count.bit_length() - 1)):
        if not positions:
            continue
        words = array.array("I", positions)
        query = core.upload(runtime, allocator, words.tobytes(), "upload_binding_frontier")
        output = allocator.allocate_count(len(positions), BINDING_BYTES)
        core.launch(runtime, function, len(positions) * BINDING_BYTES,
                    core.arguments(ctypes.c_uint64(tree.levels[level].pointer),
                    ctypes.c_uint64(query.pointer), ctypes.c_uint64(output.pointer),
                    ctypes.c_uint32(len(positions))), "binding_gather_nodes")
        core.ck(runtime.cuda.cuCtxSynchronize(), "binding_gather_nodes_sync")
        payload.extend(core.copy_to_host(runtime, output, "copy_binding_frontier"))
        allocator.free(output); allocator.free(query)
    return bytes(payload)


def gather_rows(core, runtime, allocator, gather_function, buffer, indices, leaf_bytes):
    words = array.array("I", indices)
    query = core.upload(runtime, allocator, words.tobytes(), "upload_binding_rows")
    output = allocator.allocate_count(len(indices), leaf_bytes)
    core.launch(runtime, gather_function, len(indices) * leaf_bytes,
                core.arguments(ctypes.c_uint64(buffer.pointer), ctypes.c_uint64(output.pointer),
                ctypes.c_uint64(query.pointer), ctypes.c_uint64(buffer.size),
                ctypes.c_uint32(leaf_bytes), ctypes.c_uint32(len(indices))),
                "gather_binding_rows")
    core.ck(runtime.cuda.cuCtxSynchronize(), "gather_binding_rows_sync")
    payload = core.copy_to_host(runtime, output, "copy_binding_rows")
    allocator.free(output); allocator.free(query)
    return payload


def interleave_opened_slices(slices, row_bytes, opening_count):
    if not slices or any(len(value) != opening_count * row_bytes for value in slices):
        raise ValueError("binding_opened_slices_shape")
    output = bytearray(opening_count * len(slices) * row_bytes)
    leaf_bytes = len(slices) * row_bytes
    for opening in range(opening_count):
        for segment, value in enumerate(slices):
            source = opening * row_bytes
            target = opening * leaf_bytes + segment * row_bytes
            output[target:target + row_bytes] = value[source:source + row_bytes]
    return bytes(output)


def encode_segment(tree, boundary, kind, leaf_bytes, indices, opened_payloads, frontier):
    if len(opened_payloads) != len(indices) * leaf_bytes or len(frontier) % BINDING_BYTES:
        raise ValueError("binding_segment_shape")
    header = (
        boundary.to_bytes(8, "big") + kind.to_bytes(8, "big")
        + (tree.leaf_count * leaf_bytes).to_bytes(8, "big")
        + tree.leaf_count.to_bytes(8, "big") + leaf_bytes.to_bytes(8, "big")
        + len(indices).to_bytes(4, "big") + (len(frontier) // BINDING_BYTES).to_bytes(4, "big")
        + tree.root
    )
    return header + b"".join(i.to_bytes(4, "big") for i in indices) + opened_payloads + frontier
