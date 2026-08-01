"""Nonactivating real-geometry M31 Brakedown factor-map benchmark.

The full run consumes the packed B=16 K128 boundary directly.  It never
materializes the 16 Boolean coordinates as a full M31 source table.  Matrix
support and nonzero M31 entries are regenerated deterministically per row.

This measures one factor matrix only.  A reduced differential KAT runs first;
the result is not a PCS, distance certificate, or proof qualification.
"""

import ctypes
import os
import sys
import time
from pathlib import Path

from cuda_dag_packed_accumulator_benchmark import process_peak_mb
from cuda_fp16_tower_kat import Q, Runtime, ck


THREADS = 128
DEFAULT_INPUT_LOG = 24
DEFAULT_DEGREE = 26
INTERLEAVE = 16
ALPHA_NUMERATOR = 11
ALPHA_DENOMINATOR = 100

KERNEL = r"""
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

__device__ __forceinline__ u64 mix64(u64 value) {
    value ^= value >> 30U;
    value *= 0xbf58476d1ce4e5b9ULL;
    value ^= value >> 27U;
    value *= 0x94d049bb133111ebULL;
    value ^= value >> 31U;
    return value;
}

__device__ __forceinline__ u16 source_word(u64 row, u64 source_seed) {
    u64 value = mix64(row ^ source_seed);
    value ^= mix64(row + 0xd6e8feb86659fd93ULL);
    return (u16)(value ^ (value >> 16U) ^ (value >> 32U));
}

extern "C" __global__ void fill_packed(
    u16 *packed,
    u64 rows,
    u64 source_seed
) {
    u64 row = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    if (row < rows) packed[row] = source_word(row, source_seed);
}

extern "C" __global__ void fill_dense(
    u32 *values,
    u64 count,
    u64 source_seed
) {
    u64 index = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    if (index < count) values[index] =
        (u32)(mix64(index ^ source_seed) % 2147483647ULL);
}

extern "C" __global__ void factor_packed(
    const u16 *packed,
    u64 *accumulators,
    u64 input_rows,
    u64 output_rows,
    u32 degree,
    u64 matrix_seed
) {
    u64 row = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= input_rows) return;
    u16 bits = packed[row];
    for (u32 edge = 0; edge < degree; ++edge) {
        u64 counter = row * (u64)degree + (u64)edge;
        u64 support = mix64(counter ^ matrix_seed);
        u64 target = support % output_rows;
        u32 weight = (u32)(
            mix64(counter ^ matrix_seed ^ 0xa4093822299f31d0ULL)
            % 2147483646ULL
        ) + 1U;
        u16 remaining = bits;
        while (remaining != 0U) {
            u32 bit = (u32)(__ffs((int)remaining) - 1);
            atomicAdd(
                accumulators + target * 16ULL + (u64)bit,
                (u64)weight
            );
            remaining = (u16)(remaining & (u16)(remaining - 1U));
        }
    }
}

__device__ __forceinline__ u32 mulp(u32 a, u32 b) {
    u64 product = (u64)a * (u64)b;
    u64 folded = (product & 2147483647ULL) + (product >> 31U);
    u32 result = (u32)folded;
    return result >= 2147483647U
        ? result - 2147483647U
        : result;
}

extern "C" __global__ void factor_dense(
    const u32 *input,
    u64 *accumulators,
    u64 input_rows,
    u64 output_rows,
    u32 degree,
    u64 matrix_seed
) {
    u64 row = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= input_rows) return;
    const u32 *input_row = input + row * 16ULL;
    for (u32 edge = 0; edge < degree; ++edge) {
        u64 counter = row * (u64)degree + (u64)edge;
        u64 target = mix64(counter ^ matrix_seed) % output_rows;
        u32 weight = (u32)(
            mix64(counter ^ matrix_seed ^ 0xa4093822299f31d0ULL)
            % 2147483646ULL
        ) + 1U;
        u64 *output_row = accumulators + target * 16ULL;
        #pragma unroll
        for (u32 coordinate = 0; coordinate < 16U; ++coordinate) {
            atomicAdd(
                output_row + coordinate,
                (u64)mulp(input_row[coordinate], weight)
            );
        }
    }
}

extern "C" __global__ void reduce_accumulators(
    const u64 *accumulators,
    u32 *output,
    u64 count
) {
    u64 index = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    if (index < count) output[index] =
        (u32)(accumulators[index] % 2147483647ULL);
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
    parameters = (ctypes.c_void_p * len(values))(
        *(
            ctypes.cast(ctypes.byref(value), ctypes.c_void_p)
            for value in values
        )
    )
    # cuLaunchKernel receives pointers to the scalar parameter storage.  The
    # pointer array itself does not retain the ctypes scalar objects, so keep
    # them alive until the launch call returns.
    parameters._parameter_values = values
    return parameters


def launch(runtime, fn, count, params, name):
    blocks = (count + THREADS - 1) // THREADS
    ck(
        runtime.cuda.cuLaunchKernel(
            fn, blocks, 1, 1, THREADS, 1, 1, 0, None, params, None
        ),
        name,
    )


def mix64(value):
    value &= 0xFFFF_FFFF_FFFF_FFFF
    value ^= value >> 30
    value = (value * 0xBF58_476D_1CE4_E5B9) & 0xFFFF_FFFF_FFFF_FFFF
    value ^= value >> 27
    value = (value * 0x94D0_49BB_1331_11EB) & 0xFFFF_FFFF_FFFF_FFFF
    value ^= value >> 31
    return value


def source_word(row, seed):
    value = mix64(row ^ seed)
    value ^= mix64((row + 0xD6E8_FEB8_6659_FD93) & 0xFFFF_FFFF_FFFF_FFFF)
    return (value ^ (value >> 16) ^ (value >> 32)) & 0xFFFF


def cpu_factor(input_rows, output_rows, degree, source_seed, matrix_seed):
    output = [0] * (output_rows * INTERLEAVE)
    for row in range(input_rows):
        bits = source_word(row, source_seed)
        for edge in range(degree):
            counter = row * degree + edge
            target = mix64(counter ^ matrix_seed) % output_rows
            weight = (
                mix64(
                    counter
                    ^ matrix_seed
                    ^ 0xA409_3822_299F_31D0
                )
                % (Q - 1)
            ) + 1
            for bit in range(INTERLEAVE):
                if bits & (1 << bit):
                    position = target * INTERLEAVE + bit
                    output[position] = (output[position] + weight) % Q
    return output


def cpu_dense_factor(input_values, output_rows, degree, matrix_seed):
    input_rows = len(input_values) // INTERLEAVE
    output = [0] * (output_rows * INTERLEAVE)
    for row in range(input_rows):
        for edge in range(degree):
            counter = row * degree + edge
            target = mix64(counter ^ matrix_seed) % output_rows
            weight = (
                mix64(
                    counter
                    ^ matrix_seed
                    ^ 0xA409_3822_299F_31D0
                )
                % (Q - 1)
            ) + 1
            for coordinate in range(INTERLEAVE):
                source = input_values[row * INTERLEAVE + coordinate]
                position = target * INTERLEAVE + coordinate
                output[position] = (
                    output[position] + source * weight
                ) % Q
    return output


def bind_memset(runtime):
    runtime.cuda.cuMemsetD8_v2.argtypes = [
        ctypes.c_uint64,
        ctypes.c_ubyte,
        ctypes.c_size_t,
    ]


def run_geometry(runtime, functions, input_log, degree, source_seed, matrix_seed):
    input_rows = 1 << input_log
    output_rows = (
        input_rows * ALPHA_NUMERATOR // ALPHA_DENOMINATOR
    )
    value_count = output_rows * INTERLEAVE
    packed_mb = input_rows * 2 / 1_000_000.0
    accumulator_mb = value_count * 8 / 1_000_000.0
    output_mb = value_count * 4 / 1_000_000.0

    packed = runtime.alloc(input_rows * 2)
    accumulators = runtime.alloc(value_count * 8)
    output = runtime.alloc(value_count * 4)
    ck(
        runtime.cuda.cuMemsetD8_v2(
            accumulators, 0, value_count * 8
        ),
        "zero_accumulators",
    )
    fill_fn, factor_fn, reduce_fn = functions
    launch(
        runtime,
        fill_fn,
        input_rows,
        arguments(
            ctypes.c_uint64(packed),
            ctypes.c_uint64(input_rows),
            ctypes.c_uint64(source_seed),
        ),
        "fill_packed",
    )
    ck(runtime.cuda.cuCtxSynchronize(), "fill_sync")

    factor_started = time.perf_counter()
    launch(
        runtime,
        factor_fn,
        input_rows,
        arguments(
            ctypes.c_uint64(packed),
            ctypes.c_uint64(accumulators),
            ctypes.c_uint64(input_rows),
            ctypes.c_uint64(output_rows),
            ctypes.c_uint32(degree),
            ctypes.c_uint64(matrix_seed),
        ),
        "factor_packed",
    )
    ck(runtime.cuda.cuCtxSynchronize(), "factor_sync")
    factor_seconds = time.perf_counter() - factor_started

    reduce_started = time.perf_counter()
    launch(
        runtime,
        reduce_fn,
        value_count,
        arguments(
            ctypes.c_uint64(accumulators),
            ctypes.c_uint64(output),
            ctypes.c_uint64(value_count),
        ),
        "reduce_accumulators",
    )
    ck(runtime.cuda.cuCtxSynchronize(), "reduce_sync")
    reduce_seconds = time.perf_counter() - reduce_started
    return {
        "input_rows": input_rows,
        "output_rows": output_rows,
        "value_count": value_count,
        "packed": packed,
        "output": output,
        "packed_mb": packed_mb,
        "accumulator_mb": accumulator_mb,
        "output_mb": output_mb,
        "factor_seconds": factor_seconds,
        "reduce_seconds": reduce_seconds,
    }


def run_dense_geometry(
    runtime,
    functions,
    input_rows,
    output_rows,
    degree,
    source_seed,
    matrix_seed,
):
    value_count = output_rows * INTERLEAVE
    input_count = input_rows * INTERLEAVE
    input_mb = input_count * 4 / 1_000_000.0
    accumulator_mb = value_count * 8 / 1_000_000.0
    output_mb = value_count * 4 / 1_000_000.0
    dense_input = runtime.alloc(input_count * 4)
    accumulators = runtime.alloc(value_count * 8)
    output = runtime.alloc(value_count * 4)
    ck(
        runtime.cuda.cuMemsetD8_v2(
            accumulators, 0, value_count * 8
        ),
        "zero_dense_accumulators",
    )
    fill_fn, factor_fn, reduce_fn = functions
    launch(
        runtime,
        fill_fn,
        input_count,
        arguments(
            ctypes.c_uint64(dense_input),
            ctypes.c_uint64(input_count),
            ctypes.c_uint64(source_seed),
        ),
        "fill_dense",
    )
    ck(runtime.cuda.cuCtxSynchronize(), "fill_dense_sync")
    factor_started = time.perf_counter()
    launch(
        runtime,
        factor_fn,
        input_rows,
        arguments(
            ctypes.c_uint64(dense_input),
            ctypes.c_uint64(accumulators),
            ctypes.c_uint64(input_rows),
            ctypes.c_uint64(output_rows),
            ctypes.c_uint32(degree),
            ctypes.c_uint64(matrix_seed),
        ),
        "factor_dense",
    )
    ck(runtime.cuda.cuCtxSynchronize(), "factor_dense_sync")
    factor_seconds = time.perf_counter() - factor_started
    reduce_started = time.perf_counter()
    launch(
        runtime,
        reduce_fn,
        value_count,
        arguments(
            ctypes.c_uint64(accumulators),
            ctypes.c_uint64(output),
            ctypes.c_uint64(value_count),
        ),
        "reduce_dense_accumulators",
    )
    ck(runtime.cuda.cuCtxSynchronize(), "reduce_dense_sync")
    reduce_seconds = time.perf_counter() - reduce_started
    return {
        "input_rows": input_rows,
        "output_rows": output_rows,
        "value_count": value_count,
        "input": dense_input,
        "output": output,
        "input_mb": input_mb,
        "accumulator_mb": accumulator_mb,
        "output_mb": output_mb,
        "factor_seconds": factor_seconds,
        "reduce_seconds": reduce_seconds,
    }


def main():
    input_log = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_INPUT_LOG
    degree = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_DEGREE
    mode = sys.argv[3] if len(sys.argv) > 3 else "factor"
    if len(sys.argv) > 4:
        raise SystemExit(
            "usage: cuda_m31_brakedown_factor_benchmark.py "
            "[input_log] [degree] [factor|outer]"
        )
    if not 10 <= input_log <= 24:
        raise SystemExit("input_log must be in 10..=24")
    if not 5 <= degree <= 64:
        raise SystemExit("degree must be in 5..=64")
    if mode not in {"factor", "outer"}:
        raise SystemExit("mode must be factor or outer")

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

    source_seed = 0x6A09_E667_F3BC_C908
    matrix_seed = 0xBB67_AE85_84CA_A73B
    runtime = Runtime(nvrtc)
    try:
        bind_memset(runtime)
        compile_started = time.perf_counter()
        runtime.compile(KERNEL, b"fill_packed")
        compile_seconds = time.perf_counter() - compile_started
        functions = (
            function(runtime, "fill_packed"),
            function(runtime, "factor_packed"),
            function(runtime, "reduce_accumulators"),
        )
        dense_functions = (
            function(runtime, "fill_dense"),
            function(runtime, "factor_dense"),
            function(runtime, "reduce_accumulators"),
        )

        if mode == "factor":
            kat = run_geometry(
                runtime, functions, 10, degree, source_seed, matrix_seed
            )
            observed_type = ctypes.c_uint32 * kat["value_count"]
            observed = observed_type()
            ck(
                runtime.cuda.cuMemcpyDtoH_v2(
                    ctypes.cast(observed, ctypes.c_void_p),
                    kat["output"],
                    kat["value_count"] * 4,
                ),
                "copy_kat",
            )
            expected = cpu_factor(
                kat["input_rows"],
                kat["output_rows"],
                degree,
                source_seed,
                matrix_seed,
            )
            if list(observed) != expected:
                for index, (actual, wanted) in enumerate(zip(observed, expected)):
                    if actual != wanted:
                        raise SystemExit(
                            f"kat_mismatch_index={index} "
                            f"actual={actual} expected={wanted}"
                        )
                raise SystemExit("kat_shape_mismatch")
            result = kat
            if input_log != 10:
                result = run_geometry(
                    runtime,
                    functions,
                    input_log,
                    degree,
                    source_seed,
                    matrix_seed,
                )
            source_mb = result["packed_mb"]
        else:
            kat_input_rows = 64
            kat_output_rows = 109
            kat = run_dense_geometry(
                runtime,
                dense_functions,
                kat_input_rows,
                kat_output_rows,
                degree,
                source_seed,
                matrix_seed,
            )
            kat_input_type = ctypes.c_uint32 * (
                kat_input_rows * INTERLEAVE
            )
            kat_output_type = ctypes.c_uint32 * kat["value_count"]
            kat_input = kat_input_type()
            observed = kat_output_type()
            ck(
                runtime.cuda.cuMemcpyDtoH_v2(
                    ctypes.cast(kat_input, ctypes.c_void_p),
                    kat["input"],
                    ctypes.sizeof(kat_input),
                ),
                "copy_dense_kat_input",
            )
            ck(
                runtime.cuda.cuMemcpyDtoH_v2(
                    ctypes.cast(observed, ctypes.c_void_p),
                    kat["output"],
                    ctypes.sizeof(observed),
                ),
                "copy_dense_kat_output",
            )
            expected = cpu_dense_factor(
                list(kat_input),
                kat_output_rows,
                degree,
                matrix_seed,
            )
            if list(observed) != expected:
                for index, (actual, wanted) in enumerate(zip(observed, expected)):
                    if actual != wanted:
                        raise SystemExit(
                            f"dense_kat_mismatch_index={index} "
                            f"actual={actual} expected={wanted}"
                        )
                raise SystemExit("dense_kat_shape_mismatch")
            top_rows = 1 << input_log
            inner_codeword_rows = round(
                top_rows * 0.11 / 0.704
            )
            outer_rows = round(
                top_rows * (1.0 - 0.704 - 0.11) / 0.704
            )
            result = run_dense_geometry(
                runtime,
                dense_functions,
                inner_codeword_rows,
                outer_rows,
                degree,
                source_seed,
                matrix_seed,
            )
            source_mb = result["input_mb"]

        total_seconds = (
            result["factor_seconds"] + result["reduce_seconds"]
        )
        device_mb = (
            source_mb
            + result["accumulator_mb"]
            + result["output_mb"]
        )
        print("benchmark=m31_brakedown_factor_cuda_v1")
        print("evidence_class=real_geometry_factor_map_with_reduced_kat")
        print("activation=false")
        print("reduced_differential_kat=true")
        print(f"input_log={input_log}")
        print(f"interleave={INTERLEAVE}")
        print(f"matrix_role={mode}")
        print(f"matrix_degree={degree}")
        print(f"source_segment_mb={source_mb:.6f}")
        print(
            f"factor_accumulators_mb={result['accumulator_mb']:.6f}"
        )
        print(f"factor_output_mb={result['output_mb']:.6f}")
        print(f"device_working_set_mb={device_mb:.6f}")
        print(f"host_peak_mb={process_peak_mb():.3f}")
        print(f"nvrtc_compile_seconds={compile_seconds:.6f}")
        print(f"factor_seconds={result['factor_seconds']:.6f}")
        print(f"reduction_seconds={result['reduce_seconds']:.6f}")
        print(f"total_seconds={total_seconds:.6f}")
        print("distance_certificate=false")
        print("pcs_qualification=false")
    finally:
        runtime.close()


if __name__ == "__main__":
    main()
