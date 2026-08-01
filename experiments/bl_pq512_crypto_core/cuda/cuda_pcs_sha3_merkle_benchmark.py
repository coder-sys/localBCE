"""Exact-geometry CUDA SHA3-512 Merkle commit/replay benchmark.

The GPU is treated as an untrusted accelerator: every gathered query path is
independently reconstructed with Python's SHA3-512 and must reproduce the
device root.  The benchmark retains all initial codewords on the device, but
reuses one bounded pair of Merkle-level buffers and one query-path buffer.
It is nonactivating and does not implement BaseFold or a complete proof.
"""

import array
import ctypes
import hashlib
import os
import sys
import time
from pathlib import Path

from cuda_dag_packed_accumulator_benchmark import copy, process_peak_mb
from cuda_fp16_tower_kat import Runtime, ck


THREADS = 128
MAGIC = b"BLPQPCS1"
VERSION = 1
LEAF_DOMAIN = 513
NODE_DOMAIN = 514
ROOT_DOMAIN = 515
PATTERN_ADD = 0xD6E8_FEB8_6659_FD93
PATTERN_MUL = 0x9E37_79B9_7F4A_7C15

KERNEL = r"""
typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

__device__ __forceinline__ u64 rol64(u64 value, unsigned int shift) {
    return shift == 0U ? value : (value << shift) | (value >> (64U - shift));
}

__device__ __forceinline__ void keccak_f1600(u64 state[25]) {
    const u64 rc[24] = {
        0x0000000000000001ULL, 0x0000000000008082ULL,
        0x800000000000808aULL, 0x8000000080008000ULL,
        0x000000000000808bULL, 0x0000000080000001ULL,
        0x8000000080008081ULL, 0x8000000000008009ULL,
        0x000000000000008aULL, 0x0000000000000088ULL,
        0x0000000080008009ULL, 0x000000008000000aULL,
        0x000000008000808bULL, 0x800000000000008bULL,
        0x8000000000008089ULL, 0x8000000000008003ULL,
        0x8000000000008002ULL, 0x8000000000000080ULL,
        0x000000000000800aULL, 0x800000008000000aULL,
        0x8000000080008081ULL, 0x8000000000008080ULL,
        0x0000000080000001ULL, 0x8000000080008008ULL
    };
    const unsigned int rho[25] = {
         0U,  1U, 62U, 28U, 27U,
        36U, 44U,  6U, 55U, 20U,
         3U, 10U, 43U, 25U, 39U,
        41U, 45U, 15U, 21U,  8U,
        18U,  2U, 61U, 56U, 14U
    };
    for (unsigned int round = 0; round < 24U; ++round) {
        u64 c[5], d[5], b[25];
        #pragma unroll
        for (unsigned int x = 0; x < 5U; ++x) {
            c[x] = state[x] ^ state[x + 5U] ^ state[x + 10U]
                ^ state[x + 15U] ^ state[x + 20U];
        }
        #pragma unroll
        for (unsigned int x = 0; x < 5U; ++x) {
            d[x] = c[(x + 4U) % 5U] ^ rol64(c[(x + 1U) % 5U], 1U);
        }
        #pragma unroll
        for (unsigned int y = 0; y < 5U; ++y) {
            #pragma unroll
            for (unsigned int x = 0; x < 5U; ++x) {
                state[x + 5U * y] ^= d[x];
            }
        }
        #pragma unroll
        for (unsigned int y = 0; y < 5U; ++y) {
            #pragma unroll
            for (unsigned int x = 0; x < 5U; ++x) {
                b[y + 5U * ((2U * x + 3U * y) % 5U)] =
                    rol64(state[x + 5U * y], rho[x + 5U * y]);
            }
        }
        #pragma unroll
        for (unsigned int y = 0; y < 5U; ++y) {
            #pragma unroll
            for (unsigned int x = 0; x < 5U; ++x) {
                state[x + 5U * y] = b[x + 5U * y]
                    ^ ((~b[(x + 1U) % 5U + 5U * y])
                    & b[(x + 2U) % 5U + 5U * y]);
            }
        }
        state[0] ^= rc[round];
    }
}

__device__ __forceinline__ void absorb_byte(
    u64 state[25],
    unsigned int *position,
    u8 value
) {
    unsigned int offset = *position;
    state[offset >> 3U] ^= ((u64)value) << (8U * (offset & 7U));
    offset += 1U;
    if (offset == 72U) {
        keccak_f1600(state);
        offset = 0U;
    }
    *position = offset;
}

__device__ __forceinline__ void absorb_u16_be(
    u64 state[25],
    unsigned int *position,
    unsigned int value
) {
    absorb_byte(state, position, (u8)(value >> 8U));
    absorb_byte(state, position, (u8)value);
}

__device__ __forceinline__ void absorb_u64_be(
    u64 state[25],
    unsigned int *position,
    u64 value
) {
    #pragma unroll
    for (int shift = 56; shift >= 0; shift -= 8) {
        absorb_byte(state, position, (u8)(value >> shift));
    }
}

__device__ __forceinline__ void begin_typed_hash(
    u64 state[25],
    unsigned int *position,
    unsigned int domain
) {
    #pragma unroll
    for (unsigned int i = 0; i < 25U; ++i) state[i] = 0ULL;
    *position = 0U;
    const u8 magic[8] = {'B','L','P','Q','P','C','S','1'};
    #pragma unroll
    for (unsigned int i = 0; i < 8U; ++i) {
        absorb_byte(state, position, magic[i]);
    }
    absorb_u16_be(state, position, 1U);
    absorb_u16_be(state, position, domain);
}

__device__ __forceinline__ void finish_sha3_512(
    u64 state[25],
    unsigned int position,
    u8 *output
) {
    state[position >> 3U] ^= 0x06ULL << (8U * (position & 7U));
    state[8] ^= 0x80ULL << 56U;
    keccak_f1600(state);
    #pragma unroll
    for (unsigned int lane = 0; lane < 8U; ++lane) {
        u64 value = state[lane];
        #pragma unroll
        for (unsigned int byte = 0; byte < 8U; ++byte) {
            output[8U * lane + byte] = (u8)(value >> (8U * byte));
        }
    }
}

extern "C" __global__ void fill_codeword(
    u8 *codeword,
    u64 byte_count,
    u64 oracle_index
) {
    u64 index = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    if (index >= byte_count) return;
    u64 value = (index + oracle_index * 0xd6e8feb86659fd93ULL)
        * 0x9e3779b97f4a7c15ULL;
    unsigned int shift = (unsigned int)(index & 63ULL);
    codeword[index] = (u8)rol64(value, shift);
}

extern "C" __global__ void hash_leaves(
    const u8 *codeword,
    u8 *digests,
    u64 leaf_count,
    unsigned int leaf_bytes
) {
    u64 leaf = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    if (leaf >= leaf_count) return;
    u64 state[25];
    unsigned int position;
    begin_typed_hash(state, &position, 513U);
    absorb_u64_be(state, &position, (u64)leaf_bytes);
    const u8 *payload = codeword + leaf * (u64)leaf_bytes;
    for (unsigned int i = 0; i < leaf_bytes; ++i) {
        absorb_byte(state, &position, payload[i]);
    }
    finish_sha3_512(state, position, digests + leaf * 64ULL);
}

extern "C" __global__ void hash_nodes(
    const u8 *children,
    u8 *parents,
    u64 parent_count
) {
    u64 parent = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    if (parent >= parent_count) return;
    u64 state[25];
    unsigned int position;
    begin_typed_hash(state, &position, 514U);
    const u8 *input = children + parent * 128ULL;
    #pragma unroll 4
    for (unsigned int i = 0; i < 128U; ++i) {
        absorb_byte(state, &position, input[i]);
    }
    finish_sha3_512(state, position, parents + parent * 64ULL);
}

extern "C" __global__ void hash_root(
    const u8 *top,
    u8 *root,
    u64 leaf_count
) {
    if (blockIdx.x != 0 || threadIdx.x != 0) return;
    u64 state[25];
    unsigned int position;
    begin_typed_hash(state, &position, 515U);
    absorb_u64_be(state, &position, leaf_count);
    #pragma unroll
    for (unsigned int i = 0; i < 64U; ++i) {
        absorb_byte(state, &position, top[i]);
    }
    finish_sha3_512(state, position, root);
}

extern "C" __global__ void gather_paths(
    const u8 *nodes,
    const u32 *queries,
    u8 *paths,
    unsigned int query_count,
    unsigned int level
) {
    unsigned int query = blockIdx.x * blockDim.x + threadIdx.x;
    if (query >= query_count) return;
    u64 sibling = ((u64)queries[query] >> level) ^ 1ULL;
    const u8 *source = nodes + sibling * 64ULL;
    u8 *destination =
        paths + ((u64)level * query_count + query) * 64ULL;
    #pragma unroll
    for (unsigned int i = 0; i < 64U; ++i) destination[i] = source[i];
}
"""


def function(runtime, name):
    result = ctypes.c_void_p()
    ck(
        runtime.cuda.cuModuleGetFunction(
            ctypes.byref(result), runtime.module, name.encode()
        ),
        f"{name}_function",
    )
    return result


def arguments(*values):
    return (ctypes.c_void_p * len(values))(
        *(ctypes.cast(ctypes.byref(value), ctypes.c_void_p) for value in values)
    )


def launch(runtime, fn, count, params, name):
    blocks = (count + THREADS - 1) // THREADS
    ck(
        runtime.cuda.cuLaunchKernel(
            fn, blocks, 1, 1, THREADS, 1, 1, 0, None, params, None
        ),
        name,
    )


def sha3_parts(domain, parts):
    digest = hashlib.sha3_512()
    digest.update(MAGIC)
    digest.update(VERSION.to_bytes(2, "big"))
    digest.update(domain.to_bytes(2, "big"))
    for part in parts:
        digest.update(part)
    return digest.digest()


def pattern_payload(oracle, leaf, leaf_bytes):
    start = leaf * leaf_bytes
    payload = bytearray(leaf_bytes)
    for offset in range(leaf_bytes):
        index = start + offset
        value = (
            (index + oracle * PATTERN_ADD) * PATTERN_MUL
        ) & 0xFFFF_FFFF_FFFF_FFFF
        shift = index & 63
        if shift:
            value = (
                (value << shift) | (value >> (64 - shift))
            ) & 0xFFFF_FFFF_FFFF_FFFF
        payload[offset] = value & 0xFF
    return bytes(payload)


def verify_paths(oracle, roots, paths, queries, leaf_count, leaf_bytes, depth):
    for query_position, leaf in enumerate(queries):
        payload = pattern_payload(oracle, leaf, leaf_bytes)
        current = sha3_parts(
            LEAF_DOMAIN, [len(payload).to_bytes(8, "big"), payload]
        )
        node_index = leaf
        for level in range(depth):
            start = (level * len(queries) + query_position) * 64
            sibling = paths[start : start + 64]
            if node_index & 1:
                current = sha3_parts(NODE_DOMAIN, [sibling, current])
            else:
                current = sha3_parts(NODE_DOMAIN, [current, sibling])
            node_index >>= 1
        reconstructed = sha3_parts(
            ROOT_DOMAIN, [leaf_count.to_bytes(8, "big"), current]
        )
        if reconstructed != roots[oracle]:
            raise SystemExit(
                f"independent_query_path_mismatch_oracle_{oracle}_query_{query_position}"
            )


def main():
    oracle_count = int(sys.argv[1]) if len(sys.argv) > 1 else 6
    log_codeword_values = int(sys.argv[2]) if len(sys.argv) > 2 else 23
    log_values_per_leaf = int(sys.argv[3]) if len(sys.argv) > 3 else 4
    query_count = int(sys.argv[4]) if len(sys.argv) > 4 else 640
    value_bytes = int(sys.argv[5]) if len(sys.argv) > 5 else 16
    if len(sys.argv) > 6:
        raise SystemExit(
            "usage: cuda_pcs_sha3_merkle_benchmark.py "
            "[oracles] [log_values] [log_values_per_leaf] [queries] "
            "[value_bytes]"
        )
    if not 1 <= oracle_count <= 8:
        raise SystemExit("oracle_count must be in 1..=8")
    if not 5 <= log_codeword_values <= 24:
        raise SystemExit("log_codeword_values must be in 5..=24")
    if not 0 <= log_values_per_leaf < log_codeword_values:
        raise SystemExit("invalid log_values_per_leaf")
    if not 1 <= query_count <= 2048:
        raise SystemExit("query_count must be in 1..=2048")
    if value_bytes not in {16, 64}:
        raise SystemExit("value_bytes must be 16 or 64")

    value_count = 1 << log_codeword_values
    codeword_size = value_count * value_bytes
    leaf_bytes = (1 << log_values_per_leaf) * value_bytes
    leaf_count = codeword_size // leaf_bytes
    depth = leaf_count.bit_length() - 1
    queries = [
        (
            ((draw * PATTERN_ADD) & 0xFFFF_FFFF_FFFF_FFFF)
            << (draw & 63)
            | ((draw * PATTERN_ADD) & 0xFFFF_FFFF_FFFF_FFFF)
            >> ((64 - (draw & 63)) & 63)
        )
        & (leaf_count - 1)
        for draw in range(query_count)
    ]
    query_words = array.array("I", queries)
    path_size = depth * query_count * 64

    nvrtc = Path(
        os.environ.get(
            "BL_NVRTC_BIN",
            Path(__file__).parent
            / "cuda_nvrtc"
            / "nvidia"
            / "cuda_nvrtc"
            / "bin",
        )
    )
    if not (nvrtc / "nvrtc64_120_0.dll").is_file():
        raise SystemExit("nvrtc_runtime_missing")

    runtime = Runtime(nvrtc)
    try:
        compile_started = time.perf_counter()
        runtime.compile(KERNEL, b"fill_codeword")
        compile_seconds = time.perf_counter() - compile_started
        fill_fn = function(runtime, "fill_codeword")
        leaf_fn = function(runtime, "hash_leaves")
        node_fn = function(runtime, "hash_nodes")
        root_fn = function(runtime, "hash_root")
        gather_fn = function(runtime, "gather_paths")

        codewords = [runtime.alloc(codeword_size) for _ in range(oracle_count)]
        digest_a = runtime.alloc(leaf_count * 64)
        digest_b = runtime.alloc((leaf_count // 2) * 64)
        queries_d = runtime.alloc(len(query_words) * query_words.itemsize)
        paths_d = runtime.alloc(path_size)
        root_d = runtime.alloc(oracle_count * 64)
        copy(runtime, queries_d, query_words, "copy_queries")

        fill_started = time.perf_counter()
        for oracle, codeword in enumerate(codewords):
            launch(
                runtime,
                fill_fn,
                codeword_size,
                arguments(
                    ctypes.c_uint64(codeword),
                    ctypes.c_uint64(codeword_size),
                    ctypes.c_uint64(oracle),
                ),
                f"fill_oracle_{oracle}",
            )
        ck(runtime.cuda.cuCtxSynchronize(), "fill_synchronize")
        fill_seconds = time.perf_counter() - fill_started

        def build_tree(codeword, root_pointer, collect_paths):
            launch(
                runtime,
                leaf_fn,
                leaf_count,
                arguments(
                    ctypes.c_uint64(codeword),
                    ctypes.c_uint64(digest_a),
                    ctypes.c_uint64(leaf_count),
                    ctypes.c_uint32(leaf_bytes),
                ),
                "hash_leaves",
            )
            current = digest_a
            current_count = leaf_count
            if collect_paths:
                launch(
                    runtime,
                    gather_fn,
                    query_count,
                    arguments(
                        ctypes.c_uint64(current),
                        ctypes.c_uint64(queries_d),
                        ctypes.c_uint64(paths_d),
                        ctypes.c_uint32(query_count),
                        ctypes.c_uint32(0),
                    ),
                    "gather_level_0",
                )
            for level in range(1, depth + 1):
                next_count = current_count // 2
                output = digest_b if current == digest_a else digest_a
                launch(
                    runtime,
                    node_fn,
                    next_count,
                    arguments(
                        ctypes.c_uint64(current),
                        ctypes.c_uint64(output),
                        ctypes.c_uint64(next_count),
                    ),
                    f"hash_nodes_level_{level}",
                )
                current = output
                current_count = next_count
                if collect_paths and level < depth:
                    launch(
                        runtime,
                        gather_fn,
                        query_count,
                        arguments(
                            ctypes.c_uint64(current),
                            ctypes.c_uint64(queries_d),
                            ctypes.c_uint64(paths_d),
                            ctypes.c_uint32(query_count),
                            ctypes.c_uint32(level),
                        ),
                        f"gather_level_{level}",
                    )
            launch(
                runtime,
                root_fn,
                1,
                arguments(
                    ctypes.c_uint64(current),
                    ctypes.c_uint64(root_pointer),
                    ctypes.c_uint64(leaf_count),
                ),
                "hash_root",
            )
            ck(runtime.cuda.cuCtxSynchronize(), "tree_synchronize")

        commit_started = time.perf_counter()
        for oracle, codeword in enumerate(codewords):
            build_tree(codeword, root_d + oracle * 64, False)
        commit_seconds = time.perf_counter() - commit_started

        root_host = (ctypes.c_ubyte * (oracle_count * 64))()
        ck(
            runtime.cuda.cuMemcpyDtoH_v2(
                ctypes.cast(root_host, ctypes.c_void_p),
                root_d,
                oracle_count * 64,
            ),
            "copy_roots",
        )
        roots = [
            bytes(root_host[oracle * 64 : (oracle + 1) * 64])
            for oracle in range(oracle_count)
        ]

        path_host = (ctypes.c_ubyte * path_size)()
        replay_seconds = 0.0
        verify_seconds = 0.0
        replay_roots_match = 0
        for oracle, codeword in enumerate(codewords):
            replay_started = time.perf_counter()
            build_tree(codeword, root_d + oracle * 64, True)
            ck(
                runtime.cuda.cuMemcpyDtoH_v2(
                    ctypes.cast(path_host, ctypes.c_void_p),
                    paths_d,
                    path_size,
                ),
                f"copy_paths_{oracle}",
            )
            replay_root = (ctypes.c_ubyte * 64)()
            ck(
                runtime.cuda.cuMemcpyDtoH_v2(
                    ctypes.cast(replay_root, ctypes.c_void_p),
                    root_d + oracle * 64,
                    64,
                ),
                f"copy_replay_root_{oracle}",
            )
            replay_seconds += time.perf_counter() - replay_started
            if bytes(replay_root) != roots[oracle]:
                raise SystemExit(f"replay_root_mismatch_oracle_{oracle}")
            replay_roots_match += 1

            verify_started = time.perf_counter()
            verify_paths(
                oracle,
                roots,
                bytes(path_host),
                queries,
                leaf_count,
                leaf_bytes,
                depth,
            )
            verify_seconds += time.perf_counter() - verify_started

        device_working_set = (
            oracle_count * codeword_size
            + leaf_count * 64
            + (leaf_count // 2) * 64
            + len(query_words) * query_words.itemsize
            + path_size
            + oracle_count * 64
        )
        print("benchmark=pcs_sha3_512_merkle_cuda_v1")
        print("evidence_class=exact_geometry_synthetic_payload_differential")
        print(f"oracle_count={oracle_count}")
        print(f"value_size_mb={value_bytes / 1_000_000:.6f}")
        print(f"codeword_mb={codeword_size / 1_000_000:.6f}")
        print(
            f"total_committed_volume_mb="
            f"{oracle_count * codeword_size / 1_000_000:.6f}"
        )
        print(f"leaf_bytes={leaf_bytes}")
        print(f"leaf_count={leaf_count}")
        print(f"tree_depth={depth}")
        print(f"query_count={query_count}")
        print(f"compile_seconds={compile_seconds:.6f}")
        print(f"synthetic_fill_seconds={fill_seconds:.6f}")
        print(f"commit_seconds={commit_seconds:.6f}")
        print(f"replay_seconds={replay_seconds:.6f}")
        print(f"independent_verify_seconds={verify_seconds:.6f}")
        print(f"device_working_set_mb={device_working_set / 1_000_000:.6f}")
        print(f"host_peak_mb={process_peak_mb():.3f}")
        print(f"replay_roots_matched={replay_roots_match}")
        print(f"independently_verified_paths={oracle_count * query_count}")
        print("all_query_paths_verified=true")
        print("qualification=false")
    finally:
        runtime.close()


if __name__ == "__main__":
    main()
