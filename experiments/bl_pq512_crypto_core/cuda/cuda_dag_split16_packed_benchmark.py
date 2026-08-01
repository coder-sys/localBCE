"""Calibration-only split-packed round for the relay-free Keccak DAG.

Each interpolation is split into eight-bit Lagrange pieces. A bilinear gate
then needs one product histogram per ordered pair of pieces. This measures the
exact K128 layer and claim-independent term counts for B=8/16/32/64; it stops
before polynomial reconstruction and later GKR rounds.
"""

import array
import ctypes
import os
import sys
import time
from pathlib import Path

from cuda_fp16_tower_kat import CUDA, Runtime, ck
from cuda_dag_packed_accumulator_benchmark import (
    ProcessMemoryCounters,
    copy,
    fp16_ones,
    process_peak_mb,
)


KERNEL = r"""
extern "C" __global__ void dag_split16_accumulate(
    const unsigned long long *left_packed,
    const unsigned long long *right_packed,
    const unsigned int *wire_weights,
    const unsigned int *group_weights,
    const unsigned int *base_left,
    const unsigned int *base_right,
    const unsigned int *formulas,
    unsigned long long *product,
    unsigned long long *left_histogram,
    unsigned long long *right_histogram,
    unsigned int raw_width,
    unsigned int group_count,
    unsigned int words_per_plane,
    unsigned int packed_bits,
    unsigned int chunk_count
) {
    unsigned int index = blockIdx.x * blockDim.x + threadIdx.x;
    unsigned int term_count = raw_width * group_count;
    if (index >= term_count) return;
    unsigned int group = index / raw_width;
    unsigned int output = index - group * raw_width;
    unsigned int first_instance = group * packed_bits;
    unsigned int shift = first_instance & 63U;
    unsigned int word = first_instance >> 6;
    unsigned long long packed_mask =
        packed_bits == 64U ? ~0ULL : ((1ULL << packed_bits) - 1ULL);
    unsigned int left_wire = base_left[output];
    unsigned int right_wire = base_right[output];
    unsigned long long left_word =
        (left_packed[(unsigned long long)left_wire * words_per_plane + word] >> shift)
        & packed_mask
    ;
    unsigned long long right_word =
        (right_packed[(unsigned long long)right_wire * words_per_plane + word] >> shift)
        & packed_mask
    ;
    unsigned int left_bytes[8];
    unsigned int right_bytes[8];
    for (unsigned int chunk = 0; chunk < chunk_count; ++chunk) {
        left_bytes[chunk] = (left_word >> (8U * chunk)) & 255U;
        right_bytes[chunk] = (right_word >> (8U * chunk)) & 255U;
    }
    F16 weight = m16(
        l16(wire_weights + 16ULL * output),
        l16(group_weights + 16ULL * group)
    );
    unsigned int coordinates[16];
    st16(coordinates, weight);
    for (unsigned int coordinate = 0; coordinate < 16U; ++coordinate) {
        unsigned long long value = coordinates[coordinate];
        for (unsigned int left_chunk = 0; left_chunk < chunk_count; ++left_chunk) {
            for (unsigned int right_chunk = 0; right_chunk < chunk_count; ++right_chunk) {
                unsigned int table = chunk_count * left_chunk + right_chunk;
                unsigned int bucket =
                    256U * left_bytes[left_chunk] + right_bytes[right_chunk];
                atomicAdd(
                    product + 16ULL * (65536ULL * table + bucket) + coordinate,
                    value
                );
            }
        }
        unsigned int formula = formulas[output];
        if (formula == 0U || formula == 2U) {
            for (unsigned int chunk = 0; chunk < chunk_count; ++chunk) {
                atomicAdd(
                    left_histogram
                        + 16ULL * (256ULL * chunk + left_bytes[chunk])
                        + coordinate,
                    value
                );
            }
        }
        if (formula != 1U || formula == 2U) {
            for (unsigned int chunk = 0; chunk < chunk_count; ++chunk) {
                atomicAdd(
                    right_histogram
                        + 16ULL * (256ULL * chunk + right_bytes[chunk])
                        + coordinate,
                    value
                );
            }
        }
    }
}
"""


LAYERS = (
    (640, 2_048, 2_048, 0),
    (320, 1_024, 1_024, 0),
    (320, 512, 2_048, 0),
    (320, 512, 512, 0),
    (1_600, 2_048, 512, 0),
    (1_600, 2_048, 2_048, 1),
    (1_600, 2_048, 2_048, 2),
)
PACKED_INSTANCES = 131_072
WORDS_PER_PLANE = PACKED_INSTANCES // 64
MAX_WIDTH = 2_048


def main():
    repeats = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    packed_bits = int(sys.argv[2]) if len(sys.argv) > 2 else 16
    if repeats < 1 or repeats > 24 or packed_bits not in (8, 16, 32, 64):
        raise SystemExit(
            "usage: cuda_dag_split16_packed_benchmark.py [1..24] [8|16|32|64]"
        )
    chunk_count = packed_bits // 8
    group_count = PACKED_INSTANCES // packed_bits
    product_coordinates = chunk_count * chunk_count * 65_536 * 16
    linear_coordinates = chunk_count * 256 * 16
    nvrtc = Path(
        os.environ.get(
            "BL_NVRTC_BIN",
            Path(__file__).parent / "cuda_nvrtc" / "nvidia" / "cuda_nvrtc" / "bin",
        )
    )
    if not (nvrtc / "nvrtc64_120_0.dll").is_file():
        raise SystemExit("nvrtc_runtime_missing")
    runtime = Runtime(nvrtc)
    runtime.cuda.cuMemsetD8_v2.argtypes = [
        ctypes.c_uint64,
        ctypes.c_ubyte,
        ctypes.c_size_t,
    ]
    try:
        compile_started = time.perf_counter()
        runtime.compile(CUDA + KERNEL, b"dag_split16_accumulate")
        compile_seconds = time.perf_counter() - compile_started

        packed_words = MAX_WIDTH * WORDS_PER_PLANE
        left_packed = array.array("Q", [0]) * packed_words
        right_packed = array.array("Q", [0]) * packed_words
        state = 0x243F6A8885A308D3
        for index in range(packed_words):
            state = (
                state * 6364136223846793005 + 1442695040888963407
            ) & ((1 << 64) - 1)
            left_packed[index] = state
            state = (
                state * 6364136223846793005 + 1442695040888963407
            ) & ((1 << 64) - 1)
            right_packed[index] = state
        left_packed_d = runtime.alloc(len(left_packed) * left_packed.itemsize)
        right_packed_d = runtime.alloc(len(right_packed) * right_packed.itemsize)
        left_packed_size = copy(
            runtime, left_packed_d, left_packed, "copy_left_packed"
        )
        right_packed_size = copy(
            runtime, right_packed_d, right_packed, "copy_right_packed"
        )

        wire_weights = fp16_ones(max(layer[0] for layer in LAYERS))
        group_weights = fp16_ones(group_count)
        wire_weights_d = runtime.alloc(len(wire_weights) * wire_weights.itemsize)
        group_weights_d = runtime.alloc(len(group_weights) * group_weights.itemsize)
        wire_weight_size = copy(
            runtime, wire_weights_d, wire_weights, "copy_wire_weights"
        )
        group_weight_size = copy(
            runtime, group_weights_d, group_weights, "copy_group_weights"
        )
        max_raw = max(layer[0] for layer in LAYERS)
        base_left = array.array("I", [0]) * max_raw
        base_right = array.array("I", [0]) * max_raw
        formulas = array.array("I", [0]) * max_raw
        base_left_d = runtime.alloc(len(base_left) * base_left.itemsize)
        base_right_d = runtime.alloc(len(base_right) * base_right.itemsize)
        formulas_d = runtime.alloc(len(formulas) * formulas.itemsize)

        accumulator_size = (
            product_coordinates + 2 * linear_coordinates
        ) * 8
        accumulator_d = runtime.alloc(accumulator_size)
        block = 256
        total_terms = 0
        layer_seconds = []
        started = time.perf_counter()
        for _ in range(repeats):
            for layer_index, (
                raw_width,
                left_width,
                right_width,
                formula,
            ) in enumerate(LAYERS):
                for output in range(raw_width):
                    base_left[output] = (
                        output * 17 + 31 * layer_index
                    ) % left_width
                    base_right[output] = (
                        output * 29 + 47 * layer_index + 1
                    ) % right_width
                    formulas[output] = formula
                copy(runtime, base_left_d, base_left, "copy_base_left")
                copy(runtime, base_right_d, base_right, "copy_base_right")
                copy(runtime, formulas_d, formulas, "copy_formulas")
                ck(
                    runtime.cuda.cuMemsetD8_v2(
                        accumulator_d, 0, accumulator_size
                    ),
                    "accumulator_zero",
                )
                pointers = [
                    ctypes.c_uint64(left_packed_d),
                    ctypes.c_uint64(right_packed_d),
                    ctypes.c_uint64(wire_weights_d),
                    ctypes.c_uint64(group_weights_d),
                    ctypes.c_uint64(base_left_d),
                    ctypes.c_uint64(base_right_d),
                    ctypes.c_uint64(formulas_d),
                    ctypes.c_uint64(accumulator_d),
                    ctypes.c_uint64(
                        accumulator_d + product_coordinates * 8
                    ),
                    ctypes.c_uint64(
                        accumulator_d
                        + (product_coordinates + linear_coordinates) * 8
                    ),
                ]
                raw_value = ctypes.c_uint32(raw_width)
                group_value = ctypes.c_uint32(group_count)
                words_value = ctypes.c_uint32(WORDS_PER_PLANE)
                packed_value = ctypes.c_uint32(packed_bits)
                chunks_value = ctypes.c_uint32(chunk_count)
                parameters = (ctypes.c_void_p * 15)(
                    *(
                        ctypes.cast(ctypes.byref(pointer), ctypes.c_void_p)
                        for pointer in pointers
                    ),
                    ctypes.cast(ctypes.byref(raw_value), ctypes.c_void_p),
                    ctypes.cast(ctypes.byref(group_value), ctypes.c_void_p),
                    ctypes.cast(ctypes.byref(words_value), ctypes.c_void_p),
                    ctypes.cast(ctypes.byref(packed_value), ctypes.c_void_p),
                    ctypes.cast(ctypes.byref(chunks_value), ctypes.c_void_p),
                )
                terms = raw_width * group_count
                layer_started = time.perf_counter()
                ck(
                    runtime.cuda.cuLaunchKernel(
                        runtime.fn,
                        (terms + block - 1) // block,
                        1,
                        1,
                        block,
                        1,
                        1,
                        0,
                        None,
                        parameters,
                        None,
                    ),
                    "dag_split16_accumulate",
                )
                ck(runtime.cuda.cuCtxSynchronize(), "dag_split16_sync")
                layer_seconds.append(time.perf_counter() - layer_started)
                total_terms += terms
        total_seconds = time.perf_counter() - started

        final_layer = len(LAYERS) - 1
        sample_left_wire = (31 * final_layer) % LAYERS[final_layer][1]
        sample_right_wire = (47 * final_layer + 1) % LAYERS[final_layer][2]
        sample_left = left_packed[sample_left_wire * WORDS_PER_PLANE] & 255
        sample_right = right_packed[sample_right_wire * WORDS_PER_PLANE] & 255
        sample_bucket = 256 * sample_left + sample_right
        sample = (ctypes.c_uint64 * 16)()
        ck(
            runtime.cuda.cuMemcpyDtoH_v2(
                ctypes.cast(sample, ctypes.c_void_p),
                accumulator_d + 16 * sample_bucket * 8,
                ctypes.sizeof(sample),
            ),
            "copy_sample",
        )
        if not any(sample):
            raise SystemExit("accumulator_sample_zero")
        device_working_set = (
            left_packed_size
            + right_packed_size
            + wire_weight_size
            + group_weight_size
            + 3 * max_raw * 4
            + accumulator_size
        )
        ordered = sorted(layer_seconds)
        print(f"repeats={repeats}")
        print(f"packed_bits={packed_bits}")
        print(f"padded_instances={PACKED_INSTANCES}")
        print(f"group_count={group_count}")
        print(f"layers={len(LAYERS) * repeats}")
        print(f"packed_terms={total_terms}")
        print(f"product_histograms={chunk_count * chunk_count}")
        print(f"compile_seconds={compile_seconds:.6f}")
        print(f"kernel_total_seconds={total_seconds:.6f}")
        print(f"packed_terms_per_second={total_terms / total_seconds:.3f}")
        print(f"layer_min_seconds={ordered[0]:.6f}")
        print(f"layer_median_seconds={ordered[len(ordered) // 2]:.6f}")
        print(f"layer_max_seconds={ordered[-1]:.6f}")
        print(f"host_peak_mb={process_peak_mb():.3f}")
        print(f"device_working_set_mb={device_working_set / 1_000_000:.3f}")
        print(f"accumulator_sample={list(sample)}")
    finally:
        runtime.close()


if __name__ == "__main__":
    main()
