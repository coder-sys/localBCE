"""Calibration-only fused packed histogram for the relay-free Keccak DAG.

This benchmark deliberately stops before the remaining GKR wire rounds. It
measures the exact K128 padded group count without materializing per-term Fp16
weights, labels, or factor arrays. The kernel computes each repeated weight
from one public wire weight and one public group weight.
"""

import array
import ctypes
import os
import sys
import time
from pathlib import Path

from cuda_fp16_tower_kat import CUDA, Q, Runtime, ck


KERNEL = r"""
extern "C" __global__ void dag_packed_accumulate(
    const unsigned long long *packed,
    const unsigned int *wire_weights,
    const unsigned int *group_weights,
    const unsigned int *base_left,
    const unsigned int *base_right,
    unsigned long long *product,
    unsigned long long *left_histogram,
    unsigned long long *right_histogram,
    unsigned int raw_width,
    unsigned int group_count,
    unsigned int input_width,
    unsigned int words_per_plane,
    unsigned int max_raw,
    unsigned int max_groups,
    unsigned int claim_count
) {
    unsigned int index = blockIdx.x * blockDim.x + threadIdx.x;
    unsigned int term_count = raw_width * group_count;
    unsigned int claim_term_count = term_count * claim_count;
    if (index >= claim_term_count) return;
    unsigned int claim = index / term_count;
    unsigned int term = index - claim * term_count;
    unsigned int group = term / raw_width;
    unsigned int wire = term - group * raw_width;
    unsigned int first_instance = group * 8;
    unsigned int shift = first_instance & 63;
    unsigned int word = first_instance >> 6;
    unsigned int left_wire = base_left[wire];
    unsigned int right_wire = base_right[wire];
    unsigned int left_byte =
        (unsigned int)((packed[left_wire * words_per_plane + word] >> shift) & 255ULL);
    unsigned int right_byte =
        (unsigned int)((packed[right_wire * words_per_plane + word] >> shift) & 255ULL);
    unsigned int bucket = left_byte * 256U + right_byte;
    F16 weight = m16(
        l16(wire_weights + 16ULL * (claim * max_raw + wire)),
        l16(group_weights + 16ULL * (claim * max_groups + group))
    );
    unsigned int coordinates[16];
    st16(coordinates, weight);
    bool is_and = (wire & 1U) == 0U;
    for (unsigned int coordinate = 0; coordinate < 16; ++coordinate) {
        unsigned long long value = coordinates[coordinate];
        if (is_and) {
            atomicAdd(
                product + 16ULL * (claim * 65536ULL + bucket) + coordinate,
                value
            );
        } else {
            atomicAdd(
                product + 16ULL * (claim * 65536ULL + bucket) + coordinate,
                2ULL * (2147483647ULL - value)
            );
            atomicAdd(
                left_histogram + 16ULL * (claim * 256ULL + left_byte) + coordinate,
                value
            );
            atomicAdd(
                right_histogram + 16ULL * (claim * 256ULL + right_byte) + coordinate,
                value
            );
        }
    }
}
"""


LAYERS = (
    (640, 2048, 2048),
    (320, 1024, 1024),
    (320, 512, 2048),
    (320, 512, 512),
    (1600, 2048, 512),
    (1600, 2048, 2048),
    (1600, 2048, 2048),
)
CLAIM_SCHEDULE = (2, 1, 2, 1, 3, 1, 4)
MAX_CLAIMS = max(CLAIM_SCHEDULE)
GROUP_COUNT = 16_384
PACKED_INSTANCES = GROUP_COUNT * 8
WORDS_PER_PLANE = PACKED_INSTANCES // 64
MAX_WIDTH = 2_048
ACCUMULATOR_COORDINATES = MAX_CLAIMS * (65_536 + 256 + 256) * 16


class ProcessMemoryCounters(ctypes.Structure):
    _fields_ = [
        ("cb", ctypes.c_ulong),
        ("page_fault_count", ctypes.c_ulong),
        ("peak_working_set_size", ctypes.c_size_t),
        ("working_set_size", ctypes.c_size_t),
        ("quota_peak_paged_pool_usage", ctypes.c_size_t),
        ("quota_paged_pool_usage", ctypes.c_size_t),
        ("quota_peak_nonpaged_pool_usage", ctypes.c_size_t),
        ("quota_nonpaged_pool_usage", ctypes.c_size_t),
        ("pagefile_usage", ctypes.c_size_t),
        ("peak_pagefile_usage", ctypes.c_size_t),
    ]


def process_memory_mb():
    counters = ProcessMemoryCounters()
    counters.cb = ctypes.sizeof(counters)
    get_current_process = ctypes.windll.kernel32.GetCurrentProcess
    get_current_process.argtypes = []
    get_current_process.restype = ctypes.c_void_p
    get_process_memory_info = ctypes.windll.psapi.GetProcessMemoryInfo
    get_process_memory_info.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ProcessMemoryCounters),
        ctypes.c_ulong,
    ]
    get_process_memory_info.restype = ctypes.c_int
    if not get_process_memory_info(
        get_current_process(), ctypes.byref(counters), counters.cb
    ):
        raise SystemExit("process_memory_query_failed")
    return (
        counters.working_set_size / 1_000_000,
        counters.peak_working_set_size / 1_000_000,
    )


def process_peak_mb():
    return process_memory_mb()[1]


def copy(runtime, destination, value, label):
    size = len(value) * value.itemsize
    view = (ctypes.c_ubyte * size).from_buffer(value)
    ck(
        runtime.cuda.cuMemcpyHtoD_v2(
            destination, ctypes.cast(view, ctypes.c_void_p), size
        ),
        label,
    )
    return size


def fp16_ones(count):
    values = array.array("I", [0]) * (count * 16)
    for index in range(count):
        values[16 * index] = 1
    return values


def main():
    repeats = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    if repeats < 1 or repeats > 24:
        raise SystemExit("usage: cuda_dag_packed_accumulator_benchmark.py [1..24]")

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
        runtime.compile(CUDA + KERNEL, b"dag_packed_accumulate")
        compile_seconds = time.perf_counter() - compile_started

        packed = array.array("Q", [0]) * (MAX_WIDTH * WORDS_PER_PLANE)
        value = 0x243F6A8885A308D3
        for index in range(len(packed)):
            value = (value * 6364136223846793005 + 1442695040888963407) & ((1 << 64) - 1)
            packed[index] = value
        packed_d = runtime.alloc(len(packed) * packed.itemsize)
        packed_size = copy(runtime, packed_d, packed, "copy_packed")

        wire_weights = fp16_ones(MAX_CLAIMS * max(layer[0] for layer in LAYERS))
        group_weights = fp16_ones(MAX_CLAIMS * GROUP_COUNT)
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
        base_left_d = runtime.alloc(len(base_left) * base_left.itemsize)
        base_right_d = runtime.alloc(len(base_right) * base_right.itemsize)
        accumulator_d = runtime.alloc(ACCUMULATOR_COORDINATES * 8)

        block = 256
        layer_seconds = []
        total_terms = 0
        started = time.perf_counter()
        for repeat in range(repeats):
            for layer_index, ((raw_width, left_width, right_width), claim_count) in enumerate(
                zip(LAYERS, CLAIM_SCHEDULE)
            ):
                for wire in range(raw_width):
                    base_left[wire] = (wire * 17 + 31 * layer_index) % left_width
                    base_right[wire] = (wire * 29 + 47 * layer_index + 1) % right_width
                left_size = copy(runtime, base_left_d, base_left, "copy_left_geometry")
                right_size = copy(runtime, base_right_d, base_right, "copy_right_geometry")
                ck(
                    runtime.cuda.cuMemsetD8_v2(
                        accumulator_d, 0, ACCUMULATOR_COORDINATES * 8
                    ),
                    "accumulator_zero",
                )
                raw_value = ctypes.c_uint32(raw_width)
                group_value = ctypes.c_uint32(GROUP_COUNT)
                input_value = ctypes.c_uint32(MAX_WIDTH)
                words_value = ctypes.c_uint32(WORDS_PER_PLANE)
                max_raw_value = ctypes.c_uint32(max_raw)
                max_groups_value = ctypes.c_uint32(GROUP_COUNT)
                claim_value = ctypes.c_uint32(claim_count)
                product_bytes = MAX_CLAIMS * 65_536 * 16 * 8
                linear_bytes = MAX_CLAIMS * 256 * 16 * 8
                pointers = [
                    ctypes.c_uint64(packed_d),
                    ctypes.c_uint64(wire_weights_d),
                    ctypes.c_uint64(group_weights_d),
                    ctypes.c_uint64(base_left_d),
                    ctypes.c_uint64(base_right_d),
                    ctypes.c_uint64(accumulator_d),
                    ctypes.c_uint64(accumulator_d + product_bytes),
                    ctypes.c_uint64(accumulator_d + product_bytes + linear_bytes),
                ]
                parameters = (ctypes.c_void_p * 15)(
                    *(ctypes.cast(ctypes.byref(pointer), ctypes.c_void_p) for pointer in pointers),
                    ctypes.cast(ctypes.byref(raw_value), ctypes.c_void_p),
                    ctypes.cast(ctypes.byref(group_value), ctypes.c_void_p),
                    ctypes.cast(ctypes.byref(input_value), ctypes.c_void_p),
                    ctypes.cast(ctypes.byref(words_value), ctypes.c_void_p),
                    ctypes.cast(ctypes.byref(max_raw_value), ctypes.c_void_p),
                    ctypes.cast(ctypes.byref(max_groups_value), ctypes.c_void_p),
                    ctypes.cast(ctypes.byref(claim_value), ctypes.c_void_p),
                )
                terms = raw_width * GROUP_COUNT
                claim_terms = terms * claim_count
                layer_started = time.perf_counter()
                ck(
                    runtime.cuda.cuLaunchKernel(
                        runtime.fn,
                        (claim_terms + block - 1) // block,
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
                    "dag_packed_accumulate",
                )
                ck(runtime.cuda.cuCtxSynchronize(), "dag_packed_accumulate_sync")
                layer_seconds.append(time.perf_counter() - layer_started)
                total_terms += claim_terms
        total_seconds = time.perf_counter() - started

        sample = (ctypes.c_uint64 * 16)()
        ck(
            runtime.cuda.cuMemcpyDtoH_v2(
                ctypes.cast(sample, ctypes.c_void_p),
                accumulator_d,
                ctypes.sizeof(sample),
            ),
            "copy_sample",
        )
        if not any(sample):
            raise SystemExit("accumulator_sample_zero")

        device_working_set = (
            packed_size
            + wire_weight_size
            + group_weight_size
            + left_size
            + right_size
            + ACCUMULATOR_COORDINATES * 8
        )
        print(f"repeats={repeats}")
        print(f"padded_instances={PACKED_INSTANCES}")
        print(f"group_count={GROUP_COUNT}")
        print(f"layers={len(LAYERS) * repeats}")
        print("steady_state_claim_schedule=2,1,2,1,3,1,4")
        print(f"packed_terms={total_terms}")
        print(f"compile_seconds={compile_seconds:.6f}")
        print(f"kernel_total_seconds={total_seconds:.6f}")
        print(f"packed_terms_per_second={total_terms / total_seconds:.3f}")
        print(f"layer_min_seconds={min(layer_seconds):.6f}")
        print(f"layer_median_seconds={sorted(layer_seconds)[len(layer_seconds)//2]:.6f}")
        print(f"layer_max_seconds={max(layer_seconds):.6f}")
        print(f"host_peak_mb={process_peak_mb():.3f}")
        print(f"device_working_set_mb={device_working_set / 1_000_000:.3f}")
        print(f"accumulator_sample={list(sample)}")
    finally:
        runtime.close()


if __name__ == "__main__":
    main()
