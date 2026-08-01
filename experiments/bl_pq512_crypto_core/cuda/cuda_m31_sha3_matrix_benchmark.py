"""SHA3-512-generated M31 sparse-matrix benchmark.

This nonactivating benchmark replaces the earlier ``mix64`` matrix placeholder
with a public SHA3-512 generator.  Every matrix row samples a fixed-size subset
without replacement, and every nonzero M31 entry is sampled without modulo
bias.  A reduced CPU implementation independently checks the CUDA result
before the requested geometry runs.

The benchmark measures one factor map.  It does not by itself certify code
distance, implement an IOPP, or qualify a proof system.
"""

import array
import ctypes
import hashlib
import os
import sys
import time
from pathlib import Path

from cuda_dag_packed_accumulator_benchmark import copy, process_peak_mb
from cuda_fp16_tower_kat import Q, Runtime, ck
from cuda_m31_brakedown_factor_benchmark import (
    INTERLEAVE,
    THREADS,
    arguments,
    function,
    launch,
)
from cuda_pcs_sha3_merkle_benchmark import KERNEL as SHA3_KERNEL


DEFAULT_INPUT_LOG = 24
DEFAULT_DEGREE = 26
ALPHA_NUMERATOR = 11
ALPHA_DENOMINATOR = 100
MAX_DEGREE = 128
MATRIX_DOMAIN = b"BLM31MX1"
MATRIX_SEED = hashlib.sha3_512(
    b"Blind Ledger public M31 Brakedown matrix seed v1"
).digest()
MATRIX_PREFIX = MATRIX_DOMAIN + MATRIX_SEED

if len(MATRIX_PREFIX) != 72:
    raise AssertionError("matrix_prefix_must_fill_one_sha3_512_rate_block")


MATRIX_KERNEL = rf"""
typedef unsigned short u16;

#define MATRIX_MAX_DEGREE {MAX_DEGREE}U
#define M31_NONZERO_COUNT 2147483646ULL

extern "C" __global__ void initialize_matrix_iv(
    const u8 *prefix,
    u64 *iv
) {{
    if (blockIdx.x != 0U || threadIdx.x != 0U) return;
    u64 state[25] = {{0ULL}};
    unsigned int position = 0U;
    for (unsigned int index = 0U; index < 72U; ++index) {{
        absorb_byte(state, &position, prefix[index]);
    }}
    for (unsigned int index = 0U; index < 25U; ++index) {{
        iv[index] = state[index];
    }}
}}

__device__ __forceinline__ void matrix_digest(
    const u64 *iv,
    u64 context,
    u64 row,
    u64 group,
    u64 words[8]
) {{
    u64 state[25];
    #pragma unroll
    for (unsigned int index = 0U; index < 25U; ++index) {{
        state[index] = iv[index];
    }}
    unsigned int position = 0U;
    absorb_u64_be(state, &position, context);
    absorb_u64_be(state, &position, row);
    absorb_u64_be(state, &position, group);
    state[position >> 3U] ^= 0x06ULL << (8U * (position & 7U));
    state[8U] ^= 0x8000000000000000ULL;
    keccak_f1600(state);
    #pragma unroll
    for (unsigned int index = 0U; index < 8U; ++index) {{
        words[index] = state[index];
    }}
}}

__device__ __forceinline__ bool uniform_below(
    u64 random_word,
    u64 bound,
    u64 *sample
) {{
    u64 low = random_word * bound;
    u64 threshold = (0ULL - bound) % bound;
    if (low < threshold) return false;
    *sample = __umul64hi(random_word, bound);
    return true;
}}

__device__ __forceinline__ bool already_selected(
    const u32 selected[MATRIX_MAX_DEGREE],
    u32 count,
    u32 candidate
) {{
    for (u32 index = 0U; index < count; ++index) {{
        if (selected[index] == candidate) return true;
    }}
    return false;
}}

extern "C" __global__ void fill_matrix_packed_source(
    u16 *packed,
    u64 rows,
    u64 source_seed
) {{
    u64 row = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= rows) return;
    u64 value = row ^ source_seed;
    value ^= value >> 30U;
    value *= 0xbf58476d1ce4e5b9ULL;
    value ^= value >> 27U;
    value *= 0x94d049bb133111ebULL;
    value ^= value >> 31U;
    packed[row] = (u16)(value ^ (value >> 16U) ^ (value >> 32U));
}}

extern "C" __global__ void fill_matrix_dense_source(
    u32 *values,
    u64 count,
    u64 source_seed
) {{
    u64 index = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    if (index >= count) return;
    u64 value = index ^ source_seed;
    value ^= value >> 30U;
    value *= 0xbf58476d1ce4e5b9ULL;
    value ^= value >> 27U;
    value *= 0x94d049bb133111ebULL;
    value ^= value >> 31U;
    values[index] = (u32)(value % 2147483647ULL);
}}

extern "C" __global__ void factor_sha3_packed(
    const u16 *packed,
    u64 *accumulators,
    const u64 *iv,
    u64 input_rows,
    u64 output_rows,
    u32 degree,
    u64 context
) {{
    u64 row = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= input_rows) return;
    u16 bits = packed[row];
    u32 selected[MATRIX_MAX_DEGREE];
    u32 accepted = 0U;
    u64 group = 0ULL;
    while (accepted < degree) {{
        u64 words[8];
        matrix_digest(iv, context, row, group, words);
        group += 1ULL;
        #pragma unroll
        for (u32 slot = 0U; slot < 4U; ++slot) {{
            if (accepted >= degree) break;
            u64 target;
            u64 weight;
            if (!uniform_below(words[2U * slot], output_rows, &target)) {{
                continue;
            }}
            if (already_selected(selected, accepted, (u32)target)) {{
                continue;
            }}
            if (!uniform_below(
                words[2U * slot + 1U],
                M31_NONZERO_COUNT,
                &weight
            )) {{
                continue;
            }}
            selected[accepted] = (u32)target;
            accepted += 1U;
            u64 nonzero_weight = weight + 1ULL;
            u16 remaining = bits;
            while (remaining != 0U) {{
                u32 bit = (u32)(__ffs((int)remaining) - 1);
                atomicAdd(
                    accumulators + target * 16ULL + (u64)bit,
                    nonzero_weight
                );
                remaining = (u16)(remaining & (u16)(remaining - 1U));
            }}
        }}
    }}
}}

__device__ __forceinline__ u32 matrix_mulp(u32 left, u32 right) {{
    u64 product = (u64)left * (u64)right;
    u64 folded = (product & 2147483647ULL) + (product >> 31U);
    u32 result = (u32)folded;
    return result >= 2147483647U
        ? result - 2147483647U
        : result;
}}

extern "C" __global__ void factor_sha3_dense(
    const u32 *input,
    u64 *accumulators,
    const u64 *iv,
    u64 input_rows,
    u64 output_rows,
    u32 degree,
    u64 context
) {{
    u64 row = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= input_rows) return;
    const u32 *input_row = input + row * 16ULL;
    u32 selected[MATRIX_MAX_DEGREE];
    u32 accepted = 0U;
    u64 group = 0ULL;
    while (accepted < degree) {{
        u64 words[8];
        matrix_digest(iv, context, row, group, words);
        group += 1ULL;
        #pragma unroll
        for (u32 slot = 0U; slot < 4U; ++slot) {{
            if (accepted >= degree) break;
            u64 target;
            u64 weight;
            if (!uniform_below(words[2U * slot], output_rows, &target)) {{
                continue;
            }}
            if (already_selected(selected, accepted, (u32)target)) {{
                continue;
            }}
            if (!uniform_below(
                words[2U * slot + 1U],
                M31_NONZERO_COUNT,
                &weight
            )) {{
                continue;
            }}
            selected[accepted] = (u32)target;
            accepted += 1U;
            u32 nonzero_weight = (u32)(weight + 1ULL);
            u64 *output_row = accumulators + target * 16ULL;
            #pragma unroll
            for (u32 coordinate = 0U; coordinate < 16U; ++coordinate) {{
                atomicAdd(
                    output_row + coordinate,
                    (u64)matrix_mulp(
                        input_row[coordinate],
                        nonzero_weight
                    )
                );
            }}
        }}
    }}
}}

extern "C" __global__ void reduce_matrix_accumulators(
    const u64 *accumulators,
    u32 *output,
    u64 count
) {{
    u64 index = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    if (index < count) {{
        output[index] = (u32)(accumulators[index] % 2147483647ULL);
    }}
}}
"""


def source_word(row, source_seed):
    value = (row ^ source_seed) & 0xFFFF_FFFF_FFFF_FFFF
    value ^= value >> 30
    value = (value * 0xBF58_476D_1CE4_E5B9) & 0xFFFF_FFFF_FFFF_FFFF
    value ^= value >> 27
    value = (value * 0x94D0_49BB_1331_11EB) & 0xFFFF_FFFF_FFFF_FFFF
    value ^= value >> 31
    return (value ^ (value >> 16) ^ (value >> 32)) & 0xFFFF


def dense_source_word(index, source_seed):
    value = (index ^ source_seed) & 0xFFFF_FFFF_FFFF_FFFF
    value ^= value >> 30
    value = (value * 0xBF58_476D_1CE4_E5B9) & 0xFFFF_FFFF_FFFF_FFFF
    value ^= value >> 27
    value = (value * 0x94D0_49BB_1331_11EB) & 0xFFFF_FFFF_FFFF_FFFF
    value ^= value >> 31
    return value % Q


def matrix_words(context, row, group):
    message = (
        MATRIX_PREFIX
        + context.to_bytes(8, "big")
        + row.to_bytes(8, "big")
        + group.to_bytes(8, "big")
    )
    digest = hashlib.sha3_512(message).digest()
    return [
        int.from_bytes(digest[index : index + 8], "little")
        for index in range(0, 64, 8)
    ]


def uniform_below(random_word, bound):
    product = random_word * bound
    low = product & 0xFFFF_FFFF_FFFF_FFFF
    threshold = ((1 << 64) - bound) % bound
    if low < threshold:
        return None
    return product >> 64


def matrix_row(output_rows, degree, context, row):
    selected = []
    group = 0
    while len(selected) < degree:
        words = matrix_words(context, row, group)
        group += 1
        for slot in range(4):
            if len(selected) == degree:
                break
            target = uniform_below(words[2 * slot], output_rows)
            if target is None or target in (item[0] for item in selected):
                continue
            weight = uniform_below(words[2 * slot + 1], Q - 1)
            if weight is None:
                continue
            selected.append((target, weight + 1))
    return selected


def cpu_factor(input_rows, output_rows, degree, source_seed, context):
    output = [0] * (output_rows * INTERLEAVE)
    for row in range(input_rows):
        bits = source_word(row, source_seed)
        for target, weight in matrix_row(output_rows, degree, context, row):
            for coordinate in range(INTERLEAVE):
                if bits & (1 << coordinate):
                    position = target * INTERLEAVE + coordinate
                    output[position] = (output[position] + weight) % Q
    return output


def cpu_dense_factor(input_rows, output_rows, degree, source_seed, context):
    input_values = [
        dense_source_word(index, source_seed)
        for index in range(input_rows * INTERLEAVE)
    ]
    output = [0] * (output_rows * INTERLEAVE)
    for row in range(input_rows):
        for target, weight in matrix_row(output_rows, degree, context, row):
            for coordinate in range(INTERLEAVE):
                position = target * INTERLEAVE + coordinate
                output[position] = (
                    output[position]
                    + input_values[row * INTERLEAVE + coordinate] * weight
                ) % Q
    return input_values, output


def bind_driver(runtime):
    runtime.cuda.cuMemsetD8_v2.argtypes = [
        ctypes.c_uint64,
        ctypes.c_ubyte,
        ctypes.c_size_t,
    ]


def prepare_iv(runtime, prefix_function):
    prefix = array.array("B", MATRIX_PREFIX)
    prefix_device = runtime.alloc(len(prefix))
    iv_device = runtime.alloc(25 * 8)
    copy(runtime, prefix_device, prefix, "copy_matrix_prefix")
    launch(
        runtime,
        prefix_function,
        1,
        arguments(
            ctypes.c_uint64(prefix_device),
            ctypes.c_uint64(iv_device),
        ),
        "initialize_matrix_iv",
    )
    ck(runtime.cuda.cuCtxSynchronize(), "initialize_matrix_iv_sync")
    ck(runtime.cuda.cuMemFree_v2(prefix_device), "free_matrix_prefix")
    runtime.allocs.remove(prefix_device)
    return iv_device


def run_factor(
    runtime,
    functions,
    iv_device,
    input_log,
    degree,
    source_seed,
    context,
):
    input_rows = 1 << input_log
    output_rows = (
        input_rows * ALPHA_NUMERATOR + ALPHA_DENOMINATOR // 2
    ) // ALPHA_DENOMINATOR
    if not 1 <= degree <= min(MAX_DEGREE, output_rows):
        raise SystemExit("degree_out_of_range")
    output_count = output_rows * INTERLEAVE
    packed_size = input_rows * 2
    accumulator_size = output_count * 8
    output_size = output_count * 4
    packed = runtime.alloc(packed_size)
    accumulators = runtime.alloc(accumulator_size)
    output = runtime.alloc(output_size)
    ck(
        runtime.cuda.cuMemsetD8_v2(accumulators, 0, accumulator_size),
        "zero_accumulators",
    )
    launch(
        runtime,
        functions[0],
        input_rows,
        arguments(
            ctypes.c_uint64(packed),
            ctypes.c_uint64(input_rows),
            ctypes.c_uint64(source_seed),
        ),
        "fill_matrix_packed_source",
    )
    ck(runtime.cuda.cuCtxSynchronize(), "fill_matrix_packed_source_sync")
    started = time.perf_counter()
    launch(
        runtime,
        functions[1],
        input_rows,
        arguments(
            ctypes.c_uint64(packed),
            ctypes.c_uint64(accumulators),
            ctypes.c_uint64(iv_device),
            ctypes.c_uint64(input_rows),
            ctypes.c_uint64(output_rows),
            ctypes.c_uint32(degree),
            ctypes.c_uint64(context),
        ),
        "factor_sha3_packed",
    )
    ck(runtime.cuda.cuCtxSynchronize(), "factor_sha3_packed_sync")
    factor_seconds = time.perf_counter() - started
    reduction_started = time.perf_counter()
    launch(
        runtime,
        functions[2],
        output_count,
        arguments(
            ctypes.c_uint64(accumulators),
            ctypes.c_uint64(output),
            ctypes.c_uint64(output_count),
        ),
        "reduce_matrix_accumulators",
    )
    ck(runtime.cuda.cuCtxSynchronize(), "reduce_matrix_accumulators_sync")
    reduction_seconds = time.perf_counter() - reduction_started
    return {
        "input_rows": input_rows,
        "output_rows": output_rows,
        "packed": packed,
        "accumulators": accumulators,
        "output": output,
        "packed_mb": packed_size / 1_000_000.0,
        "accumulator_mb": accumulator_size / 1_000_000.0,
        "output_mb": output_size / 1_000_000.0,
        "factor_seconds": factor_seconds,
        "reduction_seconds": reduction_seconds,
    }


def free_run(runtime, result):
    for name in ("output", "accumulators", "packed"):
        pointer = result[name]
        ck(runtime.cuda.cuMemFree_v2(pointer), f"free_{name}")
        runtime.allocs.remove(pointer)


def verify_reduced_kat(runtime, functions, iv_device):
    input_log = 8
    degree = 11
    source_seed = 0x6A09_E667_F3BC_C908
    context = 0x0000_0001_0000_0000
    result = run_factor(
        runtime,
        functions,
        iv_device,
        input_log,
        degree,
        source_seed,
        context,
    )
    output_type = ctypes.c_uint32 * (
        result["output_rows"] * INTERLEAVE
    )
    actual = output_type()
    ck(
        runtime.cuda.cuMemcpyDtoH_v2(
            ctypes.cast(actual, ctypes.c_void_p),
            result["output"],
            ctypes.sizeof(actual),
        ),
        "copy_reduced_kat",
    )
    expected = cpu_factor(
        result["input_rows"],
        result["output_rows"],
        degree,
        source_seed,
        context,
    )
    if list(actual) != expected:
        mismatch = next(
            index
            for index, (left, right) in enumerate(zip(actual, expected))
            if left != right
        )
        raise SystemExit(
            f"sha3_matrix_kat_mismatch_index={mismatch} "
            f"gpu={actual[mismatch]} cpu={expected[mismatch]}"
        )
    for row in range(result["input_rows"]):
        supports = [
            target
            for target, _ in matrix_row(
                result["output_rows"], degree, context, row
            )
        ]
        if len(supports) != len(set(supports)):
            raise SystemExit(f"duplicate_support_in_kat_row={row}")
    free_run(runtime, result)

    dense_input_rows = 53
    dense_output_rows = 17
    dense_degree = 11
    dense_source_seed = 0x510E_527F_ADE6_82D1
    dense_context = 0x0000_0002_0000_0001
    dense_input_count = dense_input_rows * INTERLEAVE
    dense_output_count = dense_output_rows * INTERLEAVE
    dense_input = runtime.alloc(dense_input_count * 4)
    dense_accumulators = runtime.alloc(dense_output_count * 8)
    dense_output = runtime.alloc(dense_output_count * 4)
    ck(
        runtime.cuda.cuMemsetD8_v2(
            dense_accumulators, 0, dense_output_count * 8
        ),
        "zero_dense_kat_accumulators",
    )
    launch(
        runtime,
        functions[3],
        dense_input_count,
        arguments(
            ctypes.c_uint64(dense_input),
            ctypes.c_uint64(dense_input_count),
            ctypes.c_uint64(dense_source_seed),
        ),
        "fill_matrix_dense_source",
    )
    launch(
        runtime,
        functions[4],
        dense_input_rows,
        arguments(
            ctypes.c_uint64(dense_input),
            ctypes.c_uint64(dense_accumulators),
            ctypes.c_uint64(iv_device),
            ctypes.c_uint64(dense_input_rows),
            ctypes.c_uint64(dense_output_rows),
            ctypes.c_uint32(dense_degree),
            ctypes.c_uint64(dense_context),
        ),
        "factor_sha3_dense_kat",
    )
    launch(
        runtime,
        functions[2],
        dense_output_count,
        arguments(
            ctypes.c_uint64(dense_accumulators),
            ctypes.c_uint64(dense_output),
            ctypes.c_uint64(dense_output_count),
        ),
        "reduce_matrix_accumulators_dense_kat",
    )
    ck(runtime.cuda.cuCtxSynchronize(), "dense_matrix_kat_sync")
    dense_type = ctypes.c_uint32 * dense_output_count
    dense_actual = dense_type()
    ck(
        runtime.cuda.cuMemcpyDtoH_v2(
            ctypes.cast(dense_actual, ctypes.c_void_p),
            dense_output,
            ctypes.sizeof(dense_actual),
        ),
        "copy_dense_matrix_kat",
    )
    _, dense_expected = cpu_dense_factor(
        dense_input_rows,
        dense_output_rows,
        dense_degree,
        dense_source_seed,
        dense_context,
    )
    if list(dense_actual) != dense_expected:
        mismatch = next(
            index
            for index, (left, right) in enumerate(
                zip(dense_actual, dense_expected)
            )
            if left != right
        )
        raise SystemExit(
            f"sha3_dense_matrix_kat_mismatch_index={mismatch} "
            f"gpu={dense_actual[mismatch]} cpu={dense_expected[mismatch]}"
        )
    for pointer, name in (
        (dense_output, "dense_kat_output"),
        (dense_accumulators, "dense_kat_accumulators"),
        (dense_input, "dense_kat_input"),
    ):
        ck(runtime.cuda.cuMemFree_v2(pointer), f"free_{name}")
        runtime.allocs.remove(pointer)


def main():
    if len(sys.argv) not in (1, 3):
        raise SystemExit(
            "usage: cuda_m31_sha3_matrix_benchmark.py [input_log degree]"
        )
    input_log = int(sys.argv[1]) if len(sys.argv) == 3 else DEFAULT_INPUT_LOG
    degree = int(sys.argv[2]) if len(sys.argv) == 3 else DEFAULT_DEGREE
    if not 1 <= input_log <= 24:
        raise SystemExit("input_log_out_of_range")
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
        bind_driver(runtime)
        compile_started = time.perf_counter()
        runtime.compile(
            SHA3_KERNEL + MATRIX_KERNEL,
            b"fill_matrix_packed_source",
        )
        compile_seconds = time.perf_counter() - compile_started
        functions = (
            function(runtime, "fill_matrix_packed_source"),
            function(runtime, "factor_sha3_packed"),
            function(runtime, "reduce_matrix_accumulators"),
            function(runtime, "fill_matrix_dense_source"),
            function(runtime, "factor_sha3_dense"),
        )
        prefix_function = function(runtime, "initialize_matrix_iv")
        iv_device = prepare_iv(runtime, prefix_function)
        verify_reduced_kat(runtime, functions, iv_device)
        source_seed = 0x510E_527F_ADE6_82D1
        context = 0x0000_0001_0000_0000
        result = run_factor(
            runtime,
            functions,
            iv_device,
            input_log,
            degree,
            source_seed,
            context,
        )
        working_set_mb = (
            result["packed_mb"]
            + result["accumulator_mb"]
            + result["output_mb"]
            + (25 * 8) / 1_000_000.0
        )
        print("benchmark=m31_sha3_512_sparse_matrix_cuda_v1")
        print("evidence_class=real_geometry_with_reduced_cpu_differential_kat")
        print("activation=false")
        print("proof_suite_id=null")
        print(f"input_log={input_log}")
        print(f"input_rows={result['input_rows']}")
        print(f"output_rows={result['output_rows']}")
        print(f"interleave={INTERLEAVE}")
        print(f"matrix_degree={degree}")
        print("matrix_generator=sha3_512")
        print("support_sampling=uniform_without_replacement")
        print("entry_sampling=uniform_nonzero_m31")
        print("modulo_bias=false")
        print(f"packed_source_mb={result['packed_mb']:.6f}")
        print(f"factor_accumulators_mb={result['accumulator_mb']:.6f}")
        print(f"factor_output_mb={result['output_mb']:.6f}")
        print(f"device_working_set_mb={working_set_mb:.6f}")
        print(f"host_peak_mb={process_peak_mb():.3f}")
        print(f"nvrtc_compile_seconds={compile_seconds:.6f}")
        print(f"factor_seconds={result['factor_seconds']:.6f}")
        print(f"reduction_seconds={result['reduction_seconds']:.6f}")
        print(
            "total_seconds="
            f"{result['factor_seconds'] + result['reduction_seconds']:.6f}"
        )
        print(f"matrix_seed_sha3_512={MATRIX_SEED.hex()}")
        print("reduced_cpu_differential_kat=true")
        print("reduced_dense_cpu_differential_kat=true")
        print("distinct_support_kat=true")
        print("distance_certificate_attached=false")
        print("complete_proof_qualification=false")
        free_run(runtime, result)
        ck(runtime.cuda.cuMemFree_v2(iv_device), "free_matrix_iv")
        runtime.allocs.remove(iv_device)
    finally:
        runtime.close()


if __name__ == "__main__":
    main()
