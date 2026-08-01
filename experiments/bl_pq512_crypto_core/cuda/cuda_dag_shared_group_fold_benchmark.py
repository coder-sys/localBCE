"""Calibration-only shared-group folds for the relay-free Keccak DAG.

This runs the exact K128 group geometry for all seven DAG source pairs. The
first fold reads B=8 packed source bits through a deterministic Fp16 lookup;
the remaining thirteen folds operate on Fp16 source values. Buffers stay on
the GPU and are reused across layers. This measures source folding only: it
does not claim to include group-round messages, masks, PCS work, or I/O.
"""

import array
import ctypes
import os
import sys
import time
from pathlib import Path

from cuda_fp16_tower_kat import CUDA, Q, Runtime, ck
from cuda_dag_packed_accumulator_benchmark import process_peak_mb


KERNEL = r"""
__device__ __forceinline__ F16 a16(F16 x,F16 y){return {a8(x.a,y.a),a8(x.b,y.b)};}
__device__ __forceinline__ F16 s16(F16 x,F16 y){return {s8(x.a,y.a),s8(x.b,y.b)};}

extern "C" __global__ void packed_first_group_fold(
    const unsigned long long *packed,
    const unsigned int *lookup,
    const unsigned int *challenge,
    unsigned int *output,
    unsigned int width,
    unsigned int output_groups,
    unsigned int words_per_plane
) {
    unsigned long long index =
        (unsigned long long)blockIdx.x * blockDim.x + threadIdx.x;
    unsigned long long count = (unsigned long long)width * output_groups;
    if (index >= count) return;
    unsigned int group = (unsigned int)(index / width);
    unsigned int wire = (unsigned int)(index - (unsigned long long)group * width);
    unsigned int packed_group_zero = 2U * group;
    unsigned int first_instance = packed_group_zero * 8U;
    unsigned int shift = first_instance & 63U;
    unsigned int word = first_instance >> 6;
    unsigned long long bits = packed[
        (unsigned long long)wire * words_per_plane + word
    ];
    unsigned int zero_byte = (unsigned int)((bits >> shift) & 255ULL);
    unsigned int one_byte = (unsigned int)((bits >> (shift + 8U)) & 255ULL);
    F16 zero = l16(lookup + 16ULL * zero_byte);
    F16 one = l16(lookup + 16ULL * one_byte);
    F16 folded = a16(zero, m16(l16(challenge), s16(one, zero)));
    st16(output + 16ULL * index, folded);
}

extern "C" __global__ void fp16_group_fold(
    const unsigned int *input,
    const unsigned int *challenge,
    unsigned int *output,
    unsigned int width,
    unsigned int output_groups
) {
    unsigned long long index =
        (unsigned long long)blockIdx.x * blockDim.x + threadIdx.x;
    unsigned long long count = (unsigned long long)width * output_groups;
    if (index >= count) return;
    unsigned int group = (unsigned int)(index / width);
    unsigned int wire = (unsigned int)(index - (unsigned long long)group * width);
    unsigned long long zero_index =
        2ULL * (unsigned long long)group * width + wire;
    unsigned long long one_index = zero_index + width;
    F16 zero = l16(input + 16ULL * zero_index);
    F16 one = l16(input + 16ULL * one_index);
    F16 folded = a16(zero, m16(l16(challenge), s16(one, zero)));
    st16(output + 16ULL * index, folded);
}
"""


LAYERS = (
    (2_048, 2_048),
    (1_024, 1_024),
    (512, 2_048),
    (512, 512),
    (2_048, 512),
    (2_048, 2_048),
    (2_048, 2_048),
)
GROUP_COUNT = 16_384
WORDS_PER_PLANE = GROUP_COUNT * 8 // 64
MAX_WIDTH = 2_048
FP16_BYTES = 16 * 4


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


def kernel_arguments(*values):
    return (ctypes.c_void_p * len(values))(
        *(ctypes.cast(ctypes.byref(value), ctypes.c_void_p) for value in values)
    )


def launch_first(runtime, function, packed, lookup, challenge, output, width, groups):
    count = width * groups
    arguments = kernel_arguments(
        ctypes.c_uint64(packed),
        ctypes.c_uint64(lookup),
        ctypes.c_uint64(challenge),
        ctypes.c_uint64(output),
        ctypes.c_uint32(width),
        ctypes.c_uint32(groups),
        ctypes.c_uint32(WORDS_PER_PLANE),
    )
    ck(
        runtime.cuda.cuLaunchKernel(
            function,
            (count + 255) // 256,
            1,
            1,
            256,
            1,
            1,
            0,
            None,
            arguments,
            None,
        ),
        "packed_first_group_fold",
    )


def launch_fold(runtime, function, source, challenge, output, width, groups):
    count = width * groups
    arguments = kernel_arguments(
        ctypes.c_uint64(source),
        ctypes.c_uint64(challenge),
        ctypes.c_uint64(output),
        ctypes.c_uint32(width),
        ctypes.c_uint32(groups),
    )
    ck(
        runtime.cuda.cuLaunchKernel(
            function,
            (count + 255) // 256,
            1,
            1,
            256,
            1,
            1,
            0,
            None,
            arguments,
            None,
        ),
        "fp16_group_fold",
    )


def main():
    repeats = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    if repeats < 1 or repeats > 24:
        raise SystemExit("usage: cuda_dag_shared_group_fold_benchmark.py [1..24]")

    nvrtc = Path(
        os.environ.get(
            "BL_NVRTC_BIN",
            Path(__file__).parent / "cuda_nvrtc" / "nvidia" / "cuda_nvrtc" / "bin",
        )
    )
    if not (nvrtc / "nvrtc64_120_0.dll").is_file():
        raise SystemExit("nvrtc_runtime_missing")
    runtime = Runtime(nvrtc)
    try:
        compile_started = time.perf_counter()
        runtime.compile(CUDA + KERNEL, b"packed_first_group_fold")
        compile_seconds = time.perf_counter() - compile_started
        fold_function = ctypes.c_void_p()
        ck(
            runtime.cuda.cuModuleGetFunction(
                ctypes.byref(fold_function), runtime.module, b"fp16_group_fold"
            ),
            "fp16_group_fold_function",
        )

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

        lookup = array.array("I", [0]) * (256 * 16)
        for byte in range(256):
            for coordinate in range(16):
                lookup[16 * byte + coordinate] = (
                    1 + 65_537 * byte + 1_000_003 * coordinate
                ) % Q
        challenge = array.array(
            "I", ((17 + 2_000_033 * coordinate) % Q for coordinate in range(16))
        )
        lookup_d = runtime.alloc(len(lookup) * lookup.itemsize)
        challenge_d = runtime.alloc(len(challenge) * challenge.itemsize)
        lookup_size = copy(runtime, lookup_d, lookup, "copy_lookup")
        challenge_size = copy(runtime, challenge_d, challenge, "copy_challenge")

        main_elements = MAX_WIDTH * (GROUP_COUNT // 2)
        scratch_elements = MAX_WIDTH * (GROUP_COUNT // 4)
        main_size = main_elements * FP16_BYTES
        scratch_size = scratch_elements * FP16_BYTES
        left_main_d = runtime.alloc(main_size)
        right_main_d = runtime.alloc(main_size)
        left_scratch_d = runtime.alloc(scratch_size)
        right_scratch_d = runtime.alloc(scratch_size)

        total_folds = 0
        layer_seconds = []
        started = time.perf_counter()
        for _ in range(repeats):
            for left_width, right_width in LAYERS:
                layer_started = time.perf_counter()
                groups = GROUP_COUNT // 2
                launch_first(
                    runtime,
                    runtime.fn,
                    left_packed_d,
                    lookup_d,
                    challenge_d,
                    left_main_d,
                    left_width,
                    groups,
                )
                launch_first(
                    runtime,
                    runtime.fn,
                    right_packed_d,
                    lookup_d,
                    challenge_d,
                    right_main_d,
                    right_width,
                    groups,
                )
                total_folds += (left_width + right_width) * groups
                left_source, left_output = left_main_d, left_scratch_d
                right_source, right_output = right_main_d, right_scratch_d
                while groups > 1:
                    groups //= 2
                    launch_fold(
                        runtime,
                        fold_function,
                        left_source,
                        challenge_d,
                        left_output,
                        left_width,
                        groups,
                    )
                    launch_fold(
                        runtime,
                        fold_function,
                        right_source,
                        challenge_d,
                        right_output,
                        right_width,
                        groups,
                    )
                    total_folds += (left_width + right_width) * groups
                    left_source, left_output = left_output, left_source
                    right_source, right_output = right_output, right_source
                ck(runtime.cuda.cuCtxSynchronize(), "layer_group_fold_sync")
                layer_seconds.append(time.perf_counter() - layer_started)
        total_seconds = time.perf_counter() - started

        sample = (ctypes.c_uint32 * 16)()
        ck(
            runtime.cuda.cuMemcpyDtoH_v2(
                ctypes.cast(sample, ctypes.c_void_p),
                left_source,
                ctypes.sizeof(sample),
            ),
            "copy_terminal_sample",
        )
        if not any(sample):
            raise SystemExit("terminal_sample_zero")
        device_working_set = (
            left_packed_size
            + right_packed_size
            + lookup_size
            + challenge_size
            + 2 * main_size
            + 2 * scratch_size
        )
        ordered = sorted(layer_seconds)
        print(f"repeats={repeats}")
        print(f"group_count={GROUP_COUNT}")
        print(f"layers={len(LAYERS) * repeats}")
        print(f"fp16_group_folds={total_folds}")
        print(f"compile_seconds={compile_seconds:.6f}")
        print(f"kernel_total_seconds={total_seconds:.6f}")
        print(f"fp16_group_folds_per_second={total_folds / total_seconds:.3f}")
        print(f"layer_min_seconds={ordered[0]:.6f}")
        print(f"layer_median_seconds={ordered[len(ordered) // 2]:.6f}")
        print(f"layer_max_seconds={ordered[-1]:.6f}")
        print(f"host_peak_mb={process_peak_mb():.3f}")
        print(f"device_working_set_mb={device_working_set / 1_000_000:.3f}")
        print(f"terminal_sample={list(sample)}")
    finally:
        runtime.close()


if __name__ == "__main__":
    main()
