"""Exact-Fp16 CUDA control for all 168 relay-free DAG wire tails.

The packed and shared-group coordinates are already fixed. Each layer then
performs the standard two-source sparse reduction over its left and right wire
labels. A small end-to-end first-round fixture is independently recomputed with
the Python Fp16 tower. Real Keccak wiring is covered by the Rust full-schedule
reference; this CUDA control fixes the exact widths, formulas, round counts,
and field arithmetic for the accelerated layout.
"""

import array
import ctypes
import os
import sys
import time
from pathlib import Path

from cuda_dag_packed_accumulator_benchmark import (
    copy,
    process_memory_mb,
)
from cuda_fp16_tower_kat import CUDA, Q, Runtime, add, ck, mul16, sub


KERNEL = (
    CUDA
    + r"""
__device__ __forceinline__ F16 a16(F16 x,F16 y){return {a8(x.a,y.a),a8(x.b,y.b)};}
__device__ __forceinline__ F16 s16(F16 x,F16 y){return {s8(x.a,y.a),s8(x.b,y.b)};}
__device__ __forceinline__ F16 z16(){F16 value={};return value;}
__device__ __forceinline__ F16 n16(F16 x){return s16(z16(),x);}
__device__ __forceinline__ F16 d16(F16 x){return a16(x,x);}

struct Quadratic { F16 c0, c1, c2; };

__device__ __forceinline__ void gate_line(
    unsigned int formula,
    bool vary_left,
    F16 zero,
    F16 delta,
    F16 fixed,
    F16 *q0,
    F16 *q1
) {
    F16 zero_fixed = m16(zero, fixed);
    F16 delta_fixed = m16(delta, fixed);
    if (formula == 1U) {
        if (vary_left) {
            *q0 = s16(fixed, zero_fixed);
            *q1 = n16(delta_fixed);
        } else {
            *q0 = s16(zero, zero_fixed);
            *q1 = s16(delta, delta_fixed);
        }
    } else if (formula == 2U) {
        F16 one = z16();
        one.a.a.a.a = 1U;
        *q0 = a16(s16(s16(one, zero), fixed), d16(zero_fixed));
        *q1 = a16(n16(delta), d16(delta_fixed));
    } else {
        *q0 = s16(a16(zero, fixed), d16(zero_fixed));
        *q1 = s16(delta, d16(delta_fixed));
    }
}

__device__ __forceinline__ Quadratic weighted_line(
    F16 weight,
    unsigned int bit,
    F16 q0,
    F16 q1
) {
    if (bit == 0U) {
        return {
            m16(weight, q0),
            m16(weight, s16(q1, q0)),
            m16(weight, n16(q1))
        };
    }
    return {z16(), m16(weight, q0), m16(weight, q1)};
}

extern "C" __global__ void wire_message(
    const unsigned int *source,
    const unsigned int *other,
    const unsigned int *output_weights,
    const unsigned int *left_factors,
    const unsigned int *right_factors,
    const unsigned int *left_indices,
    const unsigned int *right_indices,
    const unsigned int *formulas,
    unsigned int *message,
    unsigned int term_count,
    unsigned int round,
    unsigned int left_phase
) {
    Quadratic total = {z16(), z16(), z16()};
    for (unsigned int term = threadIdx.x; term < term_count; term += blockDim.x) {
        unsigned int wire = left_phase != 0U ? left_indices[term] : right_indices[term];
        unsigned int suffix = wire >> (round + 1U);
        F16 zero = l16(source + 16ULL * (2U * suffix));
        F16 delta = s16(
            l16(source + 16ULL * (2U * suffix + 1U)),
            zero
        );
        F16 fixed = left_phase != 0U
            ? l16(other + 16ULL * right_indices[term])
            : l16(other);
        F16 q0, q1;
        gate_line(formulas[term], left_phase != 0U, zero, delta, fixed, &q0, &q1);
        F16 weight = m16(
            l16(output_weights + 16ULL * term),
            l16(left_factors + 16ULL * term)
        );
        if (left_phase == 0U) {
            weight = m16(weight, l16(right_factors + 16ULL * term));
        }
        Quadratic value = weighted_line(weight, (wire >> round) & 1U, q0, q1);
        total.c0 = a16(total.c0, value.c0);
        total.c1 = a16(total.c1, value.c1);
        total.c2 = a16(total.c2, value.c2);
    }

    __shared__ unsigned int sums[128 * 48];
    unsigned int *slot = sums + 48U * threadIdx.x;
    st16(slot, total.c0);
    st16(slot + 16, total.c1);
    st16(slot + 32, total.c2);
    __syncthreads();
    for (unsigned int stride = 64U; stride > 0U; stride >>= 1U) {
        if (threadIdx.x < stride) {
            unsigned int *other_slot = sums + 48U * (threadIdx.x + stride);
            #pragma unroll
            for (unsigned int coordinate = 0; coordinate < 48U; ++coordinate) {
                slot[coordinate] = addp(slot[coordinate], other_slot[coordinate]);
            }
        }
        __syncthreads();
    }
    if (threadIdx.x == 0U) {
        #pragma unroll
        for (unsigned int coordinate = 0; coordinate < 48U; ++coordinate) {
            message[coordinate] = sums[coordinate];
        }
    }
}

extern "C" __global__ void update_factors(
    unsigned int *factors,
    const unsigned int *indices,
    const unsigned int *challenge,
    unsigned int term_count,
    unsigned int round
) {
    unsigned int term = blockIdx.x * blockDim.x + threadIdx.x;
    if (term >= term_count) return;
    F16 challenge_value = l16(challenge);
    F16 one = z16();
    one.a.a.a.a = 1U;
    F16 basis = ((indices[term] >> round) & 1U) != 0U
        ? challenge_value
        : s16(one, challenge_value);
    st16(
        factors + 16ULL * term,
        m16(l16(factors + 16ULL * term), basis)
    );
}

extern "C" __global__ void fold_source(
    const unsigned int *input,
    const unsigned int *challenge,
    unsigned int *output,
    unsigned int output_count
) {
    unsigned int index = blockIdx.x * blockDim.x + threadIdx.x;
    if (index >= output_count) return;
    F16 zero = l16(input + 16ULL * (2U * index));
    F16 one = l16(input + 16ULL * (2U * index + 1U));
    st16(
        output + 16ULL * index,
        a16(zero, m16(l16(challenge), s16(one, zero)))
    );
}
"""
)


LAYERS = (
    (640, 2_048, 2_048, 0),
    (320, 1_024, 1_024, 0),
    (320, 512, 2_048, 0),
    (320, 512, 512, 0),
    (1_600, 2_048, 512, 0),
    (1_600, 2_048, 2_048, 1),
    (1_600, 2_048, 2_048, 2),
)
KECCAK_ROUNDS = 24
MAX_WIDTH = 2_048
MAX_RAW = 1_600
THREADS = 128


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


def launch(runtime, fn, blocks, threads, params, label):
    ck(
        runtime.cuda.cuLaunchKernel(
            fn, blocks, 1, 1, threads, 1, 1, 0, None, params, None
        ),
        label,
    )


def fp16_values(count, salt):
    values = array.array("I", [0]) * (count * 16)
    for index in range(count):
        for coordinate in range(16):
            values[16 * index + coordinate] = (
                1 + salt + 65_537 * index + 1_000_003 * coordinate
            ) % Q
    return values


def fp16_at(values, index):
    return tuple(values[16 * index : 16 * (index + 1)])


def neg(value):
    return tuple(0 if coordinate == 0 else Q - coordinate for coordinate in value)


def gate_line_cpu(formula, vary_left, zero, delta, fixed):
    zero_fixed = mul16(zero, fixed)
    delta_fixed = mul16(delta, fixed)
    if formula == 1:
        return (
            (sub(fixed, zero_fixed), neg(delta_fixed))
            if vary_left
            else (sub(zero, zero_fixed), sub(delta, delta_fixed))
        )
    if formula == 2:
        one = (1,) + (0,) * 15
        return (
            add(sub(sub(one, zero), fixed), add(zero_fixed, zero_fixed)),
            add(neg(delta), add(delta_fixed, delta_fixed)),
        )
    return (
        sub(add(zero, fixed), add(zero_fixed, zero_fixed)),
        sub(delta, add(delta_fixed, delta_fixed)),
    )


def expected_first_message(
    left,
    right,
    weights,
    left_indices,
    right_indices,
    formulas,
    term_count,
):
    result = [(0,) * 16 for _ in range(3)]
    for term in range(term_count):
        wire = left_indices[term]
        zero = fp16_at(left, 2 * (wire >> 1))
        delta = sub(fp16_at(left, 2 * (wire >> 1) + 1), zero)
        q0, q1 = gate_line_cpu(
            formulas[term],
            True,
            zero,
            delta,
            fp16_at(right, right_indices[term]),
        )
        weight = fp16_at(weights, term)
        if wire & 1:
            coefficients = ((0,) * 16, mul16(weight, q0), mul16(weight, q1))
        else:
            coefficients = (
                mul16(weight, q0),
                mul16(weight, sub(q1, q0)),
                mul16(weight, neg(q1)),
            )
        result = [add(actual, value) for actual, value in zip(result, coefficients)]
    return result


def read_message(runtime, message_d):
    words = array.array("I", [0]) * 48
    view = (ctypes.c_ubyte * (len(words) * words.itemsize)).from_buffer(words)
    ck(
        runtime.cuda.cuMemcpyDtoH_v2(
            ctypes.cast(view, ctypes.c_void_p),
            message_d,
            len(words) * words.itemsize,
        ),
        "copy_wire_message",
    )
    return [tuple(words[16 * index : 16 * (index + 1)]) for index in range(3)]


def main():
    repeats = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    if repeats < 1 or repeats > 10:
        raise SystemExit("usage: cuda_fp16_dag_wire_tail_benchmark.py [1..10]")
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
        runtime.compile(KERNEL, b"wire_message")
        compile_seconds = time.perf_counter() - compile_started
        message_fn = function(runtime, "wire_message")
        update_fn = function(runtime, "update_factors")
        fold_fn = function(runtime, "fold_source")

        def upload(values, label):
            pointer = runtime.alloc(len(values) * values.itemsize)
            size = copy(runtime, pointer, values, label)
            return pointer, size

        left_host = fp16_values(MAX_WIDTH, 11)
        right_host = fp16_values(MAX_WIDTH, 23)
        weights_host = fp16_values(MAX_RAW, 37)
        factors_host = array.array("I", [0]) * (MAX_RAW * 16)
        for term in range(MAX_RAW):
            factors_host[16 * term] = 1
        left_indices = array.array("I", [0]) * MAX_RAW
        right_indices = array.array("I", [0]) * MAX_RAW
        formulas = array.array("I", [0]) * MAX_RAW
        challenge_host = fp16_values(22, 53)

        left_a_d, left_size = upload(left_host, "copy_left_source")
        left_b_d = runtime.alloc(left_size)
        right_a_d, right_size = upload(right_host, "copy_right_source")
        right_b_d = runtime.alloc(right_size)
        weights_d, weight_size = upload(weights_host, "copy_output_weights")
        left_factors_d, factor_size = upload(factors_host, "copy_left_factors")
        right_factors_d, _ = upload(factors_host, "copy_right_factors")
        left_indices_d, index_size = upload(left_indices, "copy_left_indices")
        right_indices_d, _ = upload(right_indices, "copy_right_indices")
        formulas_d, formula_size = upload(formulas, "copy_formulas")
        challenges_d, challenge_size = upload(challenge_host, "copy_challenges")
        message_d = runtime.alloc(48 * 4)

        # Differential first-round KAT.
        kat_terms = 7
        for term in range(kat_terms):
            left_indices[term] = (3 * term + 1) % 16
            right_indices[term] = (5 * term + 2) % 16
            formulas[term] = term % 3
        copy(runtime, left_indices_d, left_indices, "kat_copy_left_indices")
        copy(runtime, right_indices_d, right_indices, "kat_copy_right_indices")
        copy(runtime, formulas_d, formulas, "kat_copy_formulas")
        launch(
            runtime,
            message_fn,
            1,
            THREADS,
            arguments(
                ctypes.c_uint64(left_a_d),
                ctypes.c_uint64(right_a_d),
                ctypes.c_uint64(weights_d),
                ctypes.c_uint64(left_factors_d),
                ctypes.c_uint64(right_factors_d),
                ctypes.c_uint64(left_indices_d),
                ctypes.c_uint64(right_indices_d),
                ctypes.c_uint64(formulas_d),
                ctypes.c_uint64(message_d),
                ctypes.c_uint32(kat_terms),
                ctypes.c_uint32(0),
                ctypes.c_uint32(1),
            ),
            "kat_wire_message",
        )
        ck(runtime.cuda.cuCtxSynchronize(), "kat_wire_message_sync")
        actual = read_message(runtime, message_d)
        expected = expected_first_message(
            left_host,
            right_host,
            weights_host,
            left_indices,
            right_indices,
            formulas,
            kat_terms,
        )
        if actual != expected:
            raise SystemExit(f"wire_tail_differential_kat_mismatch actual={actual} expected={expected}")

        total_layers = 0
        total_rounds = 0
        total_message_coefficients = 0
        proof_host_start_mb, _ = process_memory_mb()
        started = time.perf_counter()
        for repetition in range(repeats):
            for round_index in range(KECCAK_ROUNDS):
                for layer_index, (
                    raw_width,
                    left_width,
                    right_width,
                    formula,
                ) in enumerate(LAYERS):
                    for output in range(raw_width):
                        left_indices[output] = (
                            17 * output + 31 * layer_index + round_index
                        ) % left_width
                        right_indices[output] = (
                            29 * output + 47 * layer_index + round_index + 1
                        ) % right_width
                        formulas[output] = (
                            2
                            if formula == 2 and output % 32 == 0
                            else (0 if formula == 2 else formula)
                        )
                    copy(runtime, left_indices_d, left_indices, "copy_left_indices")
                    copy(runtime, right_indices_d, right_indices, "copy_right_indices")
                    copy(runtime, formulas_d, formulas, "copy_formulas")
                    copy(runtime, left_a_d, left_host, "reset_left_source")
                    copy(runtime, right_a_d, right_host, "reset_right_source")
                    copy(runtime, left_factors_d, factors_host, "reset_left_factors")
                    copy(runtime, right_factors_d, factors_host, "reset_right_factors")

                    left_source, left_output = left_a_d, left_b_d
                    current_width = left_width
                    challenge_offset = 0
                    for wire_round in range(left_width.bit_length() - 1):
                        challenge = challenges_d + 64 * challenge_offset
                        launch(
                            runtime,
                            message_fn,
                            1,
                            THREADS,
                            arguments(
                                ctypes.c_uint64(left_source),
                                ctypes.c_uint64(right_a_d),
                                ctypes.c_uint64(weights_d),
                                ctypes.c_uint64(left_factors_d),
                                ctypes.c_uint64(right_factors_d),
                                ctypes.c_uint64(left_indices_d),
                                ctypes.c_uint64(right_indices_d),
                                ctypes.c_uint64(formulas_d),
                                ctypes.c_uint64(message_d),
                                ctypes.c_uint32(raw_width),
                                ctypes.c_uint32(wire_round),
                                ctypes.c_uint32(1),
                            ),
                            "left_wire_message",
                        )
                        launch(
                            runtime,
                            update_fn,
                            (raw_width + 255) // 256,
                            256,
                            arguments(
                                ctypes.c_uint64(left_factors_d),
                                ctypes.c_uint64(left_indices_d),
                                ctypes.c_uint64(challenge),
                                ctypes.c_uint32(raw_width),
                                ctypes.c_uint32(wire_round),
                            ),
                            "update_left_factors",
                        )
                        next_width = current_width // 2
                        launch(
                            runtime,
                            fold_fn,
                            (next_width + 255) // 256,
                            256,
                            arguments(
                                ctypes.c_uint64(left_source),
                                ctypes.c_uint64(challenge),
                                ctypes.c_uint64(left_output),
                                ctypes.c_uint32(next_width),
                            ),
                            "fold_left_source",
                        )
                        left_source, left_output = left_output, left_source
                        current_width = next_width
                        challenge_offset += 1

                    right_source, right_output = right_a_d, right_b_d
                    current_width = right_width
                    for wire_round in range(right_width.bit_length() - 1):
                        challenge = challenges_d + 64 * challenge_offset
                        launch(
                            runtime,
                            message_fn,
                            1,
                            THREADS,
                            arguments(
                                ctypes.c_uint64(right_source),
                                ctypes.c_uint64(left_source),
                                ctypes.c_uint64(weights_d),
                                ctypes.c_uint64(left_factors_d),
                                ctypes.c_uint64(right_factors_d),
                                ctypes.c_uint64(left_indices_d),
                                ctypes.c_uint64(right_indices_d),
                                ctypes.c_uint64(formulas_d),
                                ctypes.c_uint64(message_d),
                                ctypes.c_uint32(raw_width),
                                ctypes.c_uint32(wire_round),
                                ctypes.c_uint32(0),
                            ),
                            "right_wire_message",
                        )
                        launch(
                            runtime,
                            update_fn,
                            (raw_width + 255) // 256,
                            256,
                            arguments(
                                ctypes.c_uint64(right_factors_d),
                                ctypes.c_uint64(right_indices_d),
                                ctypes.c_uint64(challenge),
                                ctypes.c_uint32(raw_width),
                                ctypes.c_uint32(wire_round),
                            ),
                            "update_right_factors",
                        )
                        next_width = current_width // 2
                        launch(
                            runtime,
                            fold_fn,
                            (next_width + 255) // 256,
                            256,
                            arguments(
                                ctypes.c_uint64(right_source),
                                ctypes.c_uint64(challenge),
                                ctypes.c_uint64(right_output),
                                ctypes.c_uint32(next_width),
                            ),
                            "fold_right_source",
                        )
                        right_source, right_output = right_output, right_source
                        current_width = next_width
                        challenge_offset += 1
                    total_layers += 1
                    total_rounds += challenge_offset
                    total_message_coefficients += 3 * challenge_offset
        ck(runtime.cuda.cuCtxSynchronize(), "full_wire_tail_sync")
        kernel_seconds = time.perf_counter() - started
        proof_host_end_mb, build_and_proof_host_peak_mb = process_memory_mb()
        sample = read_message(runtime, message_d)
        if not any(any(coefficient) for coefficient in sample):
            raise SystemExit("wire_tail_message_zero")

        device_working_set = (
            2 * left_size
            + 2 * right_size
            + weight_size
            + 2 * factor_size
            + 2 * index_size
            + formula_size
            + challenge_size
            + 48 * 4
        )
        print("scope=fp16_relay_free_dag_wire_tail_cuda")
        print("evidence_class=exact_field_exact_schedule_with_differential_kat")
        print(f"repeats={repeats}")
        print(f"keccak_rounds={KECCAK_ROUNDS}")
        print("layers_per_round=7")
        print(f"layers={total_layers}")
        print(f"wire_sumcheck_rounds={total_rounds}")
        print(f"wire_message_coefficients={total_message_coefficients}")
        print("shared_packed_group_coordinate_fixed=true")
        print("wire_tail_differential_kat=true")
        print(f"compile_seconds={compile_seconds:.6f}")
        print(f"kernel_seconds={kernel_seconds:.6f}")
        print(f"per_k128_proof_seconds={kernel_seconds / repeats:.6f}")
        print(
            "proof_runtime_observed_host_mb="
            f"{max(proof_host_start_mb, proof_host_end_mb):.3f}"
        )
        print(f"build_and_proof_host_peak_mb={build_and_proof_host_peak_mb:.3f}")
        print(f"device_working_set_mb={device_working_set / 1_000_000:.6f}")
        print(f"message_sample={sample}")
        print("complete_gkr_qualification=false")
        print("complete_proof_qualification=false")
    finally:
        runtime.close()


if __name__ == "__main__":
    main()
