"""CUDA KAT and throughput calibration for three independent GF(2^128) lanes.

The polynomial basis uses x^128 + x^7 + x^2 + x + 1. Three independently
challenged lanes provide the candidate algebraic soundness profile; SHA3-512
remains the transcript/commitment hash. This kernel is intentionally simple
and branch-free so the first result is a conservative implementation baseline.
"""

import array
import ctypes
import os
import random
import sys
import time
from pathlib import Path

from cuda_fp16_tower_kat import Runtime, ck
from cuda_dag_packed_accumulator_benchmark import process_peak_mb


KERNEL = r"""
struct Gf128 { unsigned long long low, high; };

__device__ __forceinline__ Gf128 gf128_mul(Gf128 left, Gf128 right) {
    Gf128 result = {0ULL, 0ULL};
    #pragma unroll 128
    for (unsigned int bit = 0; bit < 128U; ++bit) {
        unsigned long long mask = 0ULL - (right.low & 1ULL);
        result.low ^= left.low & mask;
        result.high ^= left.high & mask;
        unsigned long long carry = left.high >> 63;
        left.high = (left.high << 1) | (left.low >> 63);
        left.low <<= 1;
        left.low ^= 0x87ULL & (0ULL - carry);
        right.low = (right.low >> 1) | (right.high << 63);
        right.high >>= 1;
    }
    return result;
}

extern "C" __global__ void gf128_triple_mul(
    const unsigned long long *left,
    const unsigned long long *right,
    unsigned long long *output,
    unsigned long long count
) {
    unsigned long long index =
        (unsigned long long)blockIdx.x * blockDim.x + threadIdx.x;
    if (index >= count) return;
    #pragma unroll
    for (unsigned int lane = 0; lane < 3U; ++lane) {
        unsigned long long offset = 6ULL * index + 2ULL * lane;
        Gf128 value = gf128_mul(
            {left[offset], left[offset + 1]},
            {right[offset], right[offset + 1]}
        );
        output[offset] = value.low;
        output[offset + 1] = value.high;
    }
}
"""


MASK = (1 << 128) - 1
REDUCTION = 0x87


def multiply(left, right):
    result = 0
    for _ in range(128):
        if right & 1:
            result ^= left
        carry = left >> 127
        left = (left << 1) & MASK
        if carry:
            left ^= REDUCTION
        right >>= 1
    return result


def main():
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 1_048_576
    if count < 1 or count > 4_194_304:
        raise SystemExit("usage: cuda_gf128_triple_kat.py [1..4194304]")
    nvrtc = Path(
        os.environ.get(
            "BL_NVRTC_BIN",
            Path(__file__).parent / "cuda_nvrtc" / "nvidia" / "cuda_nvrtc" / "bin",
        )
    )
    if not (nvrtc / "nvrtc64_120_0.dll").is_file():
        raise SystemExit("nvrtc_runtime_missing")
    rng = random.Random(0xB11D1ED6E)
    words = count * 6
    left = array.array("Q", (rng.getrandbits(64) for _ in range(words)))
    right = array.array("Q", (rng.getrandbits(64) for _ in range(words)))
    output = array.array("Q", [0]) * words

    runtime = Runtime(nvrtc)
    try:
        compile_started = time.perf_counter()
        runtime.compile(KERNEL, b"gf128_triple_mul")
        compile_seconds = time.perf_counter() - compile_started
        size = len(left) * left.itemsize
        left_d = runtime.alloc(size)
        right_d = runtime.alloc(size)
        output_d = runtime.alloc(size)
        left_view = (ctypes.c_ubyte * size).from_buffer(left)
        right_view = (ctypes.c_ubyte * size).from_buffer(right)
        ck(
            runtime.cuda.cuMemcpyHtoD_v2(
                left_d, ctypes.cast(left_view, ctypes.c_void_p), size
            ),
            "copy_left",
        )
        ck(
            runtime.cuda.cuMemcpyHtoD_v2(
                right_d, ctypes.cast(right_view, ctypes.c_void_p), size
            ),
            "copy_right",
        )
        left_pointer = ctypes.c_uint64(left_d)
        right_pointer = ctypes.c_uint64(right_d)
        output_pointer = ctypes.c_uint64(output_d)
        count_value = ctypes.c_uint64(count)
        arguments = (ctypes.c_void_p * 4)(
            ctypes.cast(ctypes.byref(left_pointer), ctypes.c_void_p),
            ctypes.cast(ctypes.byref(right_pointer), ctypes.c_void_p),
            ctypes.cast(ctypes.byref(output_pointer), ctypes.c_void_p),
            ctypes.cast(ctypes.byref(count_value), ctypes.c_void_p),
        )
        block = 256
        times = []
        for _ in range(5):
            started = time.perf_counter()
            ck(
                runtime.cuda.cuLaunchKernel(
                    runtime.fn,
                    (count + block - 1) // block,
                    1,
                    1,
                    block,
                    1,
                    1,
                    0,
                    None,
                    arguments,
                    None,
                ),
                "gf128_triple_mul",
            )
            ck(runtime.cuda.cuCtxSynchronize(), "gf128_triple_mul_sync")
            times.append(time.perf_counter() - started)
        output_view = (ctypes.c_ubyte * size).from_buffer(output)
        ck(
            runtime.cuda.cuMemcpyDtoH_v2(
                ctypes.cast(output_view, ctypes.c_void_p), output_d, size
            ),
            "copy_output",
        )
        kat = min(count, 257)
        for index in range(kat):
            for lane in range(3):
                offset = 6 * index + 2 * lane
                left_value = left[offset] | (left[offset + 1] << 64)
                right_value = right[offset] | (right[offset + 1] << 64)
                expected = multiply(left_value, right_value)
                actual = output[offset] | (output[offset + 1] << 64)
                if actual != expected:
                    raise SystemExit(
                        f"mismatch index={index} lane={lane} "
                        f"expected={expected:032x} actual={actual:032x}"
                    )
        times.sort()
        median = times[len(times) // 2]
        print(f"kat_elements={kat}")
        print("kat_match=true")
        print(f"triple_elements={count}")
        print(f"gf128_multiplications={3 * count}")
        print(f"compile_seconds={compile_seconds:.6f}")
        print(f"kernel_median_seconds={median:.9f}")
        print(
            "gf128_multiplications_per_second="
            f"{3 * count / median:.3f}"
        )
        print(f"host_peak_mb={process_peak_mb():.3f}")
        print(f"device_working_set_mb={3 * size / 1_000_000:.3f}")
    finally:
        runtime.close()


if __name__ == "__main__":
    main()
