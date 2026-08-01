"""Exact-geometry CUDA calibration for the two-layer binary Keccak DAG.

This nonactivating benchmark covers, for every K128 Keccak round:

* split-B=16 packed-message accumulation with the exact theta/chi wiring and
  backward claim multiplicities (theta=3, chi=1);
* exact B=16 multilinear materialization into three GF(2^128) lanes;
* all thirteen remaining shared-group messages and source folds.

The modulus is x^128+x^7+x^2+x+1. Public equality values are deterministic
synthetic inputs. The benchmark is not a proof and excludes masks, the small
wire-label tail, checkpoint I/O, transcript serialization, and the PCS.
"""

import array
import ctypes
import os
import sys
import time
from pathlib import Path

from cuda_fp16_tower_kat import Runtime, ck
from cuda_dag_packed_accumulator_benchmark import copy, process_peak_mb


KERNEL = r"""
struct Gf128 { unsigned long long low, high; };
struct Triple { Gf128 lane[3]; };

__device__ __forceinline__ Gf128 gf_add(Gf128 a, Gf128 b) {
    return {a.low ^ b.low, a.high ^ b.high};
}

__device__ __noinline__ Gf128 gf_mul(Gf128 left, Gf128 right) {
    Gf128 result = {0ULL, 0ULL};
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

__device__ __forceinline__ Triple t_zero() {
    Triple value = {};
    return value;
}

__device__ __forceinline__ Triple t_add(Triple a, Triple b) {
    Triple value;
    #pragma unroll
    for (unsigned int lane = 0; lane < 3U; ++lane) {
        value.lane[lane] = gf_add(a.lane[lane], b.lane[lane]);
    }
    return value;
}

__device__ __forceinline__ Triple t_mul(Triple a, Triple b) {
    Triple value;
    #pragma unroll
    for (unsigned int lane = 0; lane < 3U; ++lane) {
        value.lane[lane] = gf_mul(a.lane[lane], b.lane[lane]);
    }
    return value;
}

__device__ __forceinline__ Triple t_load(const unsigned long long *source) {
    Triple value;
    #pragma unroll
    for (unsigned int lane = 0; lane < 3U; ++lane) {
        value.lane[lane] = {source[2U * lane], source[2U * lane + 1U]};
    }
    return value;
}

__device__ __forceinline__ void t_store(
    unsigned long long *destination,
    Triple value
) {
    #pragma unroll
    for (unsigned int lane = 0; lane < 3U; ++lane) {
        destination[2U * lane] = value.lane[lane].low;
        destination[2U * lane + 1U] = value.lane[lane].high;
    }
}

__device__ __forceinline__ unsigned int packed16(
    const unsigned long long *packed,
    unsigned int wire,
    unsigned int group,
    unsigned int words_per_wire
) {
    unsigned int first = group << 4;
    unsigned int word = first >> 6;
    unsigned int shift = first & 63U;
    return (unsigned int)(
        (packed[(unsigned long long)wire * words_per_wire + word] >> shift)
        & 65535ULL
    );
}

extern "C" __global__ void packed_histogram(
    const unsigned long long *packed,
    const unsigned int *theta_sources,
    const unsigned int *chi_sources,
    const unsigned long long *wire_weights,
    const unsigned long long *group_weights,
    unsigned long long *histogram,
    unsigned int layer_kind,
    unsigned int claim_count,
    unsigned int raw_width,
    unsigned int group_count,
    unsigned int words_per_wire,
    unsigned int constant_salt
) {
    unsigned int index = blockIdx.x * blockDim.x + threadIdx.x;
    unsigned int term_count = raw_width * group_count;
    if (index >= term_count) return;
    unsigned int group = index / raw_width;
    unsigned int output = index - group * raw_width;
    unsigned int pattern = 0U;
    if (layer_kind == 0U) {
        #pragma unroll
        for (unsigned int input = 0; input < 11U; ++input) {
            unsigned int wire = theta_sources[11ULL * output + input];
            pattern ^= packed16(packed, wire, group, words_per_wire);
        }
    } else {
        unsigned int a = packed16(
            packed, chi_sources[3ULL * output], group, words_per_wire
        );
        unsigned int b = packed16(
            packed, chi_sources[3ULL * output + 1ULL], group, words_per_wire
        );
        unsigned int c = packed16(
            packed, chi_sources[3ULL * output + 2ULL], group, words_per_wire
        );
        pattern = a ^ c ^ (b & c);
        if (((output + constant_salt) & 127U) == 0U) pattern ^= 65535U;
    }
    for (unsigned int claim = 0; claim < claim_count; ++claim) {
        Triple wire = t_load(
            wire_weights + 6ULL * (claim * raw_width + output)
        );
        Triple group_weight = t_load(
            group_weights + 6ULL * (claim * group_count + group)
        );
        Triple weight = t_mul(wire, group_weight);
        unsigned long long *bucket = histogram
            + 6ULL * (claim * 65536ULL + pattern);
        #pragma unroll
        for (unsigned int lane = 0; lane < 3U; ++lane) {
            atomicXor(bucket + 2U * lane, weight.lane[lane].low);
            atomicXor(bucket + 2U * lane + 1U, weight.lane[lane].high);
        }
    }
}

extern "C" __global__ void materialize_b16(
    const unsigned long long *packed,
    const unsigned long long *lookup,
    unsigned long long *output,
    unsigned int width,
    unsigned int group_count,
    unsigned int words_per_wire
) {
    unsigned int index = blockIdx.x * blockDim.x + threadIdx.x;
    unsigned int count = width * group_count;
    if (index >= count) return;
    unsigned int wire = index / group_count;
    unsigned int group = index - wire * group_count;
    unsigned int pattern = packed16(packed, wire, group, words_per_wire);
    t_store(output + 6ULL * index, t_load(lookup + 6ULL * pattern));
}

__device__ __forceinline__ void reduce_coefficients(
    Triple c0,
    Triple c1,
    Triple c2,
    Triple c3,
    unsigned int coefficient_count,
    unsigned long long *messages
) {
    __shared__ unsigned long long sums[128][24];
    unsigned int thread = threadIdx.x;
    Triple values[4] = {c0, c1, c2, c3};
    #pragma unroll
    for (unsigned int coefficient = 0; coefficient < 4U; ++coefficient) {
        #pragma unroll
        for (unsigned int lane = 0; lane < 3U; ++lane) {
            sums[thread][6U * coefficient + 2U * lane] =
                values[coefficient].lane[lane].low;
            sums[thread][6U * coefficient + 2U * lane + 1U] =
                values[coefficient].lane[lane].high;
        }
    }
    __syncthreads();
    for (unsigned int stride = 64U; stride > 0U; stride >>= 1U) {
        if (thread < stride) {
            #pragma unroll
            for (unsigned int word = 0; word < 24U; ++word) {
                sums[thread][word] ^= sums[thread + stride][word];
            }
        }
        __syncthreads();
    }
    if (thread == 0U) {
        for (unsigned int word = 0; word < 6U * coefficient_count; ++word) {
            atomicXor(messages + word, sums[0][word]);
        }
    }
}

extern "C" __global__ void theta_group_message(
    const unsigned long long *source,
    const unsigned int *theta_sources,
    const unsigned long long *wire_weights,
    const unsigned long long *group_zero,
    const unsigned long long *group_delta,
    unsigned long long *messages,
    unsigned int raw_width,
    unsigned int current_groups,
    unsigned int suffix_groups,
    unsigned int max_groups,
    unsigned int claim_count
) {
    unsigned int index = blockIdx.x * blockDim.x + threadIdx.x;
    unsigned int terms = raw_width * suffix_groups;
    Triple q0 = t_zero(), q1 = t_zero();
    Triple w0 = t_zero(), wd = t_zero();
    if (index < terms) {
        unsigned int suffix = index / raw_width;
        unsigned int output = index - suffix * raw_width;
        #pragma unroll
        for (unsigned int input = 0; input < 11U; ++input) {
            unsigned int wire = theta_sources[11ULL * output + input];
            Triple v0 = t_load(
                source + 6ULL * (wire * current_groups + 2U * suffix)
            );
            Triple v1 = t_load(
                source + 6ULL * (wire * current_groups + 2U * suffix + 1U)
            );
            q0 = t_add(q0, v0);
            q1 = t_add(q1, t_add(v0, v1));
        }
        for (unsigned int claim = 0; claim < claim_count; ++claim) {
            Triple wire = t_load(
                wire_weights + 6ULL * (claim * raw_width + output)
            );
            w0 = t_add(
                w0,
                t_mul(
                    wire,
                    t_load(group_zero + 6ULL * (claim * max_groups + suffix))
                )
            );
            wd = t_add(
                wd,
                t_mul(
                    wire,
                    t_load(group_delta + 6ULL * (claim * max_groups + suffix))
                )
            );
        }
    }
    Triple c0 = t_mul(q0, w0);
    Triple c1 = t_add(t_mul(q0, wd), t_mul(q1, w0));
    Triple c2 = t_mul(q1, wd);
    reduce_coefficients(c0, c1, c2, t_zero(), 3U, messages);
}

extern "C" __global__ void chi_group_message(
    const unsigned long long *source,
    const unsigned int *chi_sources,
    const unsigned long long *wire_weights,
    const unsigned long long *group_zero,
    const unsigned long long *group_delta,
    unsigned long long *messages,
    unsigned int raw_width,
    unsigned int current_groups,
    unsigned int suffix_groups,
    unsigned int max_groups
) {
    unsigned int index = blockIdx.x * blockDim.x + threadIdx.x;
    unsigned int terms = raw_width * suffix_groups;
    Triple q0 = t_zero(), q1 = t_zero(), q2 = t_zero();
    Triple w0 = t_zero(), wd = t_zero();
    if (index < terms) {
        unsigned int suffix = index / raw_width;
        unsigned int output = index - suffix * raw_width;
        Triple values0[3], values_delta[3];
        #pragma unroll
        for (unsigned int input = 0; input < 3U; ++input) {
            unsigned int wire = chi_sources[3ULL * output + input];
            values0[input] = t_load(
                source + 6ULL * (wire * current_groups + 2U * suffix)
            );
            Triple value1 = t_load(
                source + 6ULL * (wire * current_groups + 2U * suffix + 1U)
            );
            values_delta[input] = t_add(values0[input], value1);
        }
        q0 = t_add(
            t_add(values0[0], values0[2]),
            t_mul(values0[1], values0[2])
        );
        q1 = t_add(
            t_add(values_delta[0], values_delta[2]),
            t_add(
                t_mul(values0[1], values_delta[2]),
                t_mul(values_delta[1], values0[2])
            )
        );
        q2 = t_mul(values_delta[1], values_delta[2]);
        Triple wire = t_load(wire_weights + 6ULL * output);
        w0 = t_mul(wire, t_load(group_zero + 6ULL * suffix));
        wd = t_mul(wire, t_load(group_delta + 6ULL * suffix));
    }
    Triple c0 = t_mul(q0, w0);
    Triple c1 = t_add(t_mul(q0, wd), t_mul(q1, w0));
    Triple c2 = t_add(t_mul(q1, wd), t_mul(q2, w0));
    Triple c3 = t_mul(q2, wd);
    reduce_coefficients(c0, c1, c2, c3, 4U, messages);
}

extern "C" __global__ void fold_source(
    const unsigned long long *source,
    const unsigned long long *challenge,
    unsigned long long *output,
    unsigned int width,
    unsigned int current_groups
) {
    unsigned int suffix_groups = current_groups >> 1;
    unsigned int index = blockIdx.x * blockDim.x + threadIdx.x;
    unsigned int count = width * suffix_groups;
    if (index >= count) return;
    unsigned int wire = index / suffix_groups;
    unsigned int suffix = index - wire * suffix_groups;
    Triple v0 = t_load(
        source + 6ULL * (wire * current_groups + 2U * suffix)
    );
    Triple v1 = t_load(
        source + 6ULL * (wire * current_groups + 2U * suffix + 1U)
    );
    Triple folded = t_add(
        v0,
        t_mul(t_load(challenge), t_add(v0, v1))
    );
    t_store(output + 6ULL * index, folded);
}

extern "C" __global__ void materialize_theta_wire_factor(
    const unsigned long long *source,
    const unsigned int *theta_sources,
    unsigned long long *factors,
    unsigned int raw_width,
    unsigned int padded_width
) {
    unsigned int output = blockIdx.x * blockDim.x + threadIdx.x;
    if (output >= padded_width) return;
    Triple value = t_zero();
    if (output < raw_width) {
        #pragma unroll
        for (unsigned int input = 0; input < 11U; ++input) {
            unsigned int wire = theta_sources[11ULL * output + input];
            value = t_add(value, t_load(source + 6ULL * wire));
        }
    }
    t_store(factors + 6ULL * output, value);
}

extern "C" __global__ void materialize_chi_wire_factors(
    const unsigned long long *source,
    const unsigned int *chi_sources,
    unsigned long long *factors,
    unsigned int raw_width,
    unsigned int padded_width,
    unsigned int round_index
) {
    unsigned int output = blockIdx.x * blockDim.x + threadIdx.x;
    if (output >= padded_width) return;
    Triple zero = t_zero();
    Triple a = zero, b = zero, c = zero, constant = zero;
    if (output < raw_width) {
        a = t_load(source + 6ULL * chi_sources[3ULL * output]);
        b = t_load(source + 6ULL * chi_sources[3ULL * output + 1ULL]);
        c = t_load(source + 6ULL * chi_sources[3ULL * output + 2ULL]);
        if (((output + round_index) & 7U) == 0U) constant = t_load(
            source + 6ULL * 0U
        );
    }
    t_store(factors + 6ULL * output, a);
    t_store(factors + 6ULL * (padded_width + output), b);
    t_store(factors + 6ULL * (2U * padded_width + output), c);
    t_store(factors + 6ULL * (3U * padded_width + output), constant);
}

extern "C" __global__ void theta_wire_message(
    const unsigned long long *factors,
    const unsigned long long *weights,
    unsigned long long *messages,
    unsigned int current_width
) {
    unsigned int suffix = blockIdx.x * blockDim.x + threadIdx.x;
    unsigned int suffix_width = current_width >> 1;
    Triple c0 = t_zero(), c1 = t_zero(), c2 = t_zero();
    if (suffix < suffix_width) {
        Triple q0 = t_load(factors + 6ULL * (2U * suffix));
        Triple qd = t_add(
            q0, t_load(factors + 6ULL * (2U * suffix + 1U))
        );
        Triple w0 = t_load(weights + 6ULL * (2U * suffix));
        Triple wd = t_add(
            w0, t_load(weights + 6ULL * (2U * suffix + 1U))
        );
        c0 = t_mul(q0, w0);
        c1 = t_add(t_mul(q0, wd), t_mul(qd, w0));
        c2 = t_mul(qd, wd);
    }
    reduce_coefficients(c0, c1, c2, t_zero(), 3U, messages);
}

extern "C" __global__ void chi_wire_message(
    const unsigned long long *factors,
    const unsigned long long *weights,
    unsigned long long *messages,
    unsigned int current_width,
    unsigned int factor_stride
) {
    unsigned int suffix = blockIdx.x * blockDim.x + threadIdx.x;
    unsigned int suffix_width = current_width >> 1;
    Triple c0 = t_zero(), c1 = t_zero(), c2 = t_zero(), c3 = t_zero();
    if (suffix < suffix_width) {
        Triple a0 = t_load(factors + 6ULL * (2U * suffix));
        Triple ad = t_add(
            a0, t_load(factors + 6ULL * (2U * suffix + 1U))
        );
        Triple b0 = t_load(
            factors + 6ULL * (factor_stride + 2U * suffix)
        );
        Triple bd = t_add(
            b0,
            t_load(factors + 6ULL * (factor_stride + 2U * suffix + 1U))
        );
        Triple d0 = t_load(
            factors + 6ULL * (2U * factor_stride + 2U * suffix)
        );
        Triple dd = t_add(
            d0,
            t_load(factors + 6ULL * (2U * factor_stride + 2U * suffix + 1U))
        );
        Triple k0 = t_load(
            factors + 6ULL * (3U * factor_stride + 2U * suffix)
        );
        Triple kd = t_add(
            k0,
            t_load(factors + 6ULL * (3U * factor_stride + 2U * suffix + 1U))
        );
        Triple q0 = t_add(t_add(a0, d0), t_add(t_mul(b0, d0), k0));
        Triple q1 = t_add(
            t_add(ad, dd),
            t_add(t_add(t_mul(b0, dd), t_mul(bd, d0)), kd)
        );
        Triple q2 = t_mul(bd, dd);
        Triple w0 = t_load(weights + 6ULL * (2U * suffix));
        Triple wd = t_add(
            w0, t_load(weights + 6ULL * (2U * suffix + 1U))
        );
        c0 = t_mul(q0, w0);
        c1 = t_add(t_mul(q0, wd), t_mul(q1, w0));
        c2 = t_add(t_mul(q1, wd), t_mul(q2, w0));
        c3 = t_mul(q2, wd);
    }
    reduce_coefficients(c0, c1, c2, c3, 4U, messages);
}

extern "C" __global__ void fold_wire_tables(
    const unsigned long long *source,
    const unsigned long long *challenge,
    unsigned long long *output,
    unsigned int current_width,
    unsigned int table_count,
    unsigned int table_stride
) {
    unsigned int next_width = current_width >> 1;
    unsigned int index = blockIdx.x * blockDim.x + threadIdx.x;
    unsigned int count = table_count * next_width;
    if (index >= count) return;
    unsigned int table = index / next_width;
    unsigned int suffix = index - table * next_width;
    unsigned int source_index = table * table_stride + 2U * suffix;
    unsigned int output_index = table * table_stride + suffix;
    Triple v0 = t_load(source + 6ULL * source_index);
    Triple v1 = t_load(source + 6ULL * (source_index + 1U));
    Triple folded = t_add(
        v0,
        t_mul(t_load(challenge), t_add(v0, v1))
    );
    t_store(output + 6ULL * output_index, folded);
}
"""


STATE_BITS = 1_600
WIDTH = 2_048
GROUP_COUNT = 8_192
INSTANCES = GROUP_COUNT * 16
WORDS_PER_WIRE = INSTANCES // 64
MAX_CLAIMS = 3
THREADS = 128
TRIPLE_BYTES = 48
MASK = (1 << 128) - 1
REDUCTION = 0x87
ROTATIONS = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)


def gf_mul(left, right):
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


def bit(x, y, z):
    return 64 * (x + 5 * y) + z


def wiring():
    inverse = [-1] * STATE_BITS
    for x in range(5):
        for y in range(5):
            rotation = ROTATIONS[x][y]
            destination_x = y
            destination_y = (2 * x + 3 * y) % 5
            for z in range(64):
                destination_z = (z + rotation) % 64
                inverse[bit(destination_x, destination_y, destination_z)] = bit(
                    x, y, z
                )
    if any(value < 0 for value in inverse):
        raise SystemExit("rho_pi_inverse_incomplete")

    theta = array.array("I")
    for destination in range(STATE_BITS):
        source = inverse[destination]
        lane, z = divmod(source, 64)
        x, y = lane % 5, lane // 5
        theta.append(bit(x, y, z))
        theta.extend(bit((x + 4) % 5, source_y, z) for source_y in range(5))
        theta.extend(
            bit((x + 1) % 5, source_y, (z + 63) % 64)
            for source_y in range(5)
        )
    chi = array.array("I")
    for y in range(5):
        for x in range(5):
            for z in range(64):
                chi.extend(
                    (
                        bit(x, y, z),
                        bit((x + 1) % 5, y, z),
                        bit((x + 2) % 5, y, z),
                    )
                )
    return theta, chi


def gf_words(values):
    words = array.array("Q")
    for value in values:
        words.extend((value & ((1 << 64) - 1), value >> 64))
    return words


def deterministic_triples(count, salt):
    state = (0x243F6A8885A308D3 ^ salt) & ((1 << 64) - 1)
    words = array.array("Q")
    for _ in range(count * 6):
        state = (
            state * 6364136223846793005 + 1442695040888963407
        ) & ((1 << 64) - 1)
        words.append(state)
    return words


def load_host_triple(words, index):
    base = 6 * index
    return tuple(
        words[base + 2 * lane] | (words[base + 2 * lane + 1] << 64)
        for lane in range(3)
    )


def host_array_buffer(values):
    word = ctypes.c_uint64 if values.itemsize == 8 else ctypes.c_uint32
    return (word * len(values))()


def message_host_buffer():
    word = ctypes.c_uint64 if TRIPLE_BYTES == 48 else ctypes.c_uint32
    return (word * (4 * TRIPLE_BYTES // ctypes.sizeof(word)))()


def add_host_triple(left, right):
    return tuple(a ^ b for a, b in zip(left, right))


def mul_host_triple(left, right):
    return tuple(gf_mul(a, b) for a, b in zip(left, right))


def wire_tail_differential_kat(
    runtime,
    theta_message_fn,
    chi_message_fn,
    fold_wire_fn,
):
    width = 8
    factors = deterministic_triples(4 * width, 201)
    weights = deterministic_triples(width, 211)
    challenge = deterministic_triples(1, 223)
    allocations = []

    def upload(values, label):
        pointer = runtime.alloc(len(values) * values.itemsize)
        allocations.append(len(values) * values.itemsize)
        copy(runtime, pointer, values, label)
        return pointer

    factors_d = upload(factors, "wire_kat_factors")
    weights_d = upload(weights, "wire_kat_weights")
    challenge_d = upload(challenge, "wire_kat_challenge")
    factor_output_d = runtime.alloc(len(factors) * factors.itemsize)
    weight_output_d = runtime.alloc(len(weights) * weights.itemsize)
    message_d = runtime.alloc(4 * TRIPLE_BYTES)
    allocations.extend(
        (
            len(factors) * factors.itemsize,
            len(weights) * weights.itemsize,
            4 * TRIPLE_BYTES,
        )
    )

    zero = (0, 0, 0)
    for kind, message_fn, table_count, coefficient_count in (
        ("theta", theta_message_fn, 1, 3),
        ("chi", chi_message_fn, 4, 4),
    ):
        expected = [zero] * coefficient_count
        for suffix in range(width // 2):
            weight0 = load_host_triple(weights, 2 * suffix)
            weight_delta = add_host_triple(
                weight0, load_host_triple(weights, 2 * suffix + 1)
            )
            if kind == "theta":
                q0 = load_host_triple(factors, 2 * suffix)
                q1 = add_host_triple(
                    q0, load_host_triple(factors, 2 * suffix + 1)
                )
                coefficients = (
                    mul_host_triple(q0, weight0),
                    add_host_triple(
                        mul_host_triple(q0, weight_delta),
                        mul_host_triple(q1, weight0),
                    ),
                    mul_host_triple(q1, weight_delta),
                )
            else:
                values0 = [
                    load_host_triple(factors, table * width + 2 * suffix)
                    for table in range(4)
                ]
                deltas = [
                    add_host_triple(
                        values0[table],
                        load_host_triple(
                            factors, table * width + 2 * suffix + 1
                        ),
                    )
                    for table in range(4)
                ]
                q0 = add_host_triple(
                    add_host_triple(values0[0], values0[2]),
                    add_host_triple(
                        mul_host_triple(values0[1], values0[2]), values0[3]
                    ),
                )
                q1 = add_host_triple(
                    add_host_triple(deltas[0], deltas[2]),
                    add_host_triple(
                        add_host_triple(
                            mul_host_triple(values0[1], deltas[2]),
                            mul_host_triple(deltas[1], values0[2]),
                        ),
                        deltas[3],
                    ),
                )
                q2 = mul_host_triple(deltas[1], deltas[2])
                coefficients = (
                    mul_host_triple(q0, weight0),
                    add_host_triple(
                        mul_host_triple(q0, weight_delta),
                        mul_host_triple(q1, weight0),
                    ),
                    add_host_triple(
                        mul_host_triple(q1, weight_delta),
                        mul_host_triple(q2, weight0),
                    ),
                    mul_host_triple(q2, weight_delta),
                )
            expected = [
                add_host_triple(accumulator, coefficient)
                for accumulator, coefficient in zip(expected, coefficients)
            ]

        ck(
            runtime.cuda.cuMemsetD8_v2(message_d, 0, 4 * TRIPLE_BYTES),
            f"wire_kat_{kind}_message_zero",
        )
        params = (
            arguments(
                ctypes.c_uint64(factors_d),
                ctypes.c_uint64(weights_d),
                ctypes.c_uint64(message_d),
                ctypes.c_uint32(width),
            )
            if kind == "theta"
            else arguments(
                ctypes.c_uint64(factors_d),
                ctypes.c_uint64(weights_d),
                ctypes.c_uint64(message_d),
                ctypes.c_uint32(width),
                ctypes.c_uint32(width),
            )
        )
        launch(runtime, message_fn, 1, params, f"wire_kat_{kind}_message")
        message_host = message_host_buffer()
        ck(
            runtime.cuda.cuMemcpyDtoH_v2(
                ctypes.cast(message_host, ctypes.c_void_p),
                message_d,
                ctypes.sizeof(message_host),
            ),
            f"wire_kat_{kind}_message_copy",
        )
        actual = [
            load_host_triple(message_host, index)
            for index in range(coefficient_count)
        ]
        if actual != expected:
            raise SystemExit(f"wire_kat_{kind}_message_mismatch")

        params = arguments(
            ctypes.c_uint64(factors_d),
            ctypes.c_uint64(challenge_d),
            ctypes.c_uint64(factor_output_d),
            ctypes.c_uint32(width),
            ctypes.c_uint32(table_count),
            ctypes.c_uint32(width),
        )
        launch(
            runtime,
            fold_wire_fn,
            1,
            params,
            f"wire_kat_{kind}_factor_fold",
        )
        params = arguments(
            ctypes.c_uint64(weights_d),
            ctypes.c_uint64(challenge_d),
            ctypes.c_uint64(weight_output_d),
            ctypes.c_uint32(width),
            ctypes.c_uint32(1),
            ctypes.c_uint32(width),
        )
        launch(runtime, fold_wire_fn, 1, params, f"wire_kat_{kind}_weight_fold")
        factor_host = host_array_buffer(factors)
        weight_host = host_array_buffer(weights)
        ck(
            runtime.cuda.cuMemcpyDtoH_v2(
                ctypes.cast(factor_host, ctypes.c_void_p),
                factor_output_d,
                ctypes.sizeof(factor_host),
            ),
            f"wire_kat_{kind}_factor_copy",
        )
        ck(
            runtime.cuda.cuMemcpyDtoH_v2(
                ctypes.cast(weight_host, ctypes.c_void_p),
                weight_output_d,
                ctypes.sizeof(weight_host),
            ),
            f"wire_kat_{kind}_weight_copy",
        )
        challenge_value = load_host_triple(challenge, 0)
        for table in range(table_count):
            for suffix in range(width // 2):
                value0 = load_host_triple(
                    factors, table * width + 2 * suffix
                )
                value1 = load_host_triple(
                    factors, table * width + 2 * suffix + 1
                )
                expected_fold = add_host_triple(
                    value0,
                    mul_host_triple(
                        challenge_value, add_host_triple(value0, value1)
                    ),
                )
                if (
                    load_host_triple(factor_host, table * width + suffix)
                    != expected_fold
                ):
                    raise SystemExit(f"wire_kat_{kind}_factor_fold_mismatch")
        for suffix in range(width // 2):
            value0 = load_host_triple(weights, 2 * suffix)
            value1 = load_host_triple(weights, 2 * suffix + 1)
            expected_fold = add_host_triple(
                value0,
                mul_host_triple(
                    challenge_value, add_host_triple(value0, value1)
                ),
            )
            if load_host_triple(weight_host, suffix) != expected_fold:
                raise SystemExit(f"wire_kat_{kind}_weight_fold_mismatch")
    return sum(allocations)


def b16_lookup():
    challenges = [
        [
            (
                (0x9E3779B97F4A7C15 * (1 + lane + 3 * variable))
                << (17 * variable)
            )
            & MASK
            for variable in range(4)
        ]
        for lane in range(3)
    ]
    position_weights = [[0] * 16 for _ in range(3)]
    for lane in range(3):
        for position in range(16):
            weight = 1
            for variable in range(4):
                challenge = challenges[lane][variable]
                factor = challenge if (position >> variable) & 1 else 1 ^ challenge
                weight = gf_mul(weight, factor)
            position_weights[lane][position] = weight
    tables = [[0] * 65536 for _ in range(3)]
    for pattern in range(1, 65536):
        least = pattern & -pattern
        position = least.bit_length() - 1
        previous = pattern ^ least
        for lane in range(3):
            tables[lane][pattern] = (
                tables[lane][previous] ^ position_weights[lane][position]
            )
    words = array.array("Q")
    for pattern in range(65536):
        for lane in range(3):
            value = tables[lane][pattern]
            words.extend((value & ((1 << 64) - 1), value >> 64))
    return words


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
        *(
            ctypes.cast(ctypes.byref(value), ctypes.c_void_p)
            for value in values
        )
    )


def launch(runtime, fn, blocks, params, name):
    ck(
        runtime.cuda.cuLaunchKernel(
            fn, blocks, 1, 1, THREADS, 1, 1, 0, None, params, None
        ),
        name,
    )


def main():
    repeats = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    if repeats < 1 or repeats > 24:
        raise SystemExit("usage: cuda_binary_dag_full_benchmark.py [1..24]")
    nvrtc = Path(
        os.environ.get(
            "BL_NVRTC_BIN",
            Path(__file__).parent / "cuda_nvrtc" / "nvidia" / "cuda_nvrtc" / "bin",
        )
    )
    if not (nvrtc / "nvrtc64_120_0.dll").is_file():
        raise SystemExit("nvrtc_runtime_missing")

    theta, chi = wiring()
    packed = array.array("Q", [0]) * (WIDTH * WORDS_PER_WIRE)
    state = 0x13198A2E03707344
    for index in range(len(packed)):
        state = (
            state * 6364136223846793005 + 1442695040888963407
        ) & ((1 << 64) - 1)
        packed[index] = state
    lookup = b16_lookup()
    wire_weights = deterministic_triples(MAX_CLAIMS * STATE_BITS, 17)
    group_weights = deterministic_triples(MAX_CLAIMS * GROUP_COUNT, 31)
    group_zero = deterministic_triples(MAX_CLAIMS * (GROUP_COUNT // 2), 47)
    group_delta = deterministic_triples(MAX_CLAIMS * (GROUP_COUNT // 2), 59)
    challenge = deterministic_triples(1, 71)
    wire_tail_weights = deterministic_triples(WIDTH, 83)

    runtime = Runtime(nvrtc)
    runtime.cuda.cuMemsetD8_v2.argtypes = [
        ctypes.c_uint64,
        ctypes.c_ubyte,
        ctypes.c_size_t,
    ]
    try:
        compile_started = time.perf_counter()
        runtime.compile(KERNEL, b"packed_histogram")
        compile_seconds = time.perf_counter() - compile_started
        packed_fn = function(runtime, "packed_histogram")
        materialize_fn = function(runtime, "materialize_b16")
        theta_fn = function(runtime, "theta_group_message")
        chi_fn = function(runtime, "chi_group_message")
        fold_fn = function(runtime, "fold_source")
        theta_wire_factor_fn = function(runtime, "materialize_theta_wire_factor")
        chi_wire_factor_fn = function(runtime, "materialize_chi_wire_factors")
        theta_wire_message_fn = function(runtime, "theta_wire_message")
        chi_wire_message_fn = function(runtime, "chi_wire_message")
        fold_wire_fn = function(runtime, "fold_wire_tables")
        wire_kat_size = wire_tail_differential_kat(
            runtime,
            theta_wire_message_fn,
            chi_wire_message_fn,
            fold_wire_fn,
        )

        def upload(values, name):
            pointer = runtime.alloc(len(values) * values.itemsize)
            size = copy(runtime, pointer, values, name)
            return pointer, size

        packed_d, packed_size = upload(packed, "copy_packed")
        lookup_d, lookup_size = upload(lookup, "copy_lookup")
        theta_d, theta_size = upload(theta, "copy_theta")
        chi_d, chi_size = upload(chi, "copy_chi")
        wire_d, wire_size = upload(wire_weights, "copy_wire_weights")
        group_d, group_size = upload(group_weights, "copy_group_weights")
        zero_d, zero_size = upload(group_zero, "copy_group_zero")
        delta_d, delta_size = upload(group_delta, "copy_group_delta")
        challenge_d, challenge_size = upload(challenge, "copy_challenge")
        wire_tail_d, wire_tail_size = upload(
            wire_tail_weights, "copy_wire_tail_weights"
        )

        histogram_size = MAX_CLAIMS * 65536 * TRIPLE_BYTES
        histogram_d = runtime.alloc(histogram_size)
        message_size = 4 * TRIPLE_BYTES
        messages_d = runtime.alloc(message_size)
        main_size = WIDTH * GROUP_COUNT * TRIPLE_BYTES
        scratch_size = WIDTH * (GROUP_COUNT // 2) * TRIPLE_BYTES
        main_d = runtime.alloc(main_size)
        scratch_d = runtime.alloc(scratch_size)
        factor_size = 4 * WIDTH * TRIPLE_BYTES
        factor_a_d = runtime.alloc(factor_size)
        factor_b_d = runtime.alloc(factor_size)
        weight_size = WIDTH * TRIPLE_BYTES
        weight_a_d = runtime.alloc(weight_size)
        weight_b_d = runtime.alloc(weight_size)

        packed_terms = 0
        packed_claim_terms = 0
        group_terms = 0
        group_fold_values = 0
        materialized_values = 0
        packed_seconds = 0.0
        group_seconds = 0.0
        wire_seconds = 0.0
        wire_message_terms = 0
        wire_fold_values = 0
        layer_seconds = []
        started = time.perf_counter()
        for round_index in range(repeats):
            for layer_kind, claim_count in ((0, 3), (1, 1)):
                layer_started = time.perf_counter()
                ck(
                    runtime.cuda.cuMemsetD8_v2(
                        histogram_d, 0, histogram_size
                    ),
                    "histogram_zero",
                )
                terms = STATE_BITS * GROUP_COUNT
                packed_started = time.perf_counter()
                params = arguments(
                    ctypes.c_uint64(packed_d),
                    ctypes.c_uint64(theta_d),
                    ctypes.c_uint64(chi_d),
                    ctypes.c_uint64(wire_d),
                    ctypes.c_uint64(group_d),
                    ctypes.c_uint64(histogram_d),
                    ctypes.c_uint32(layer_kind),
                    ctypes.c_uint32(claim_count),
                    ctypes.c_uint32(STATE_BITS),
                    ctypes.c_uint32(GROUP_COUNT),
                    ctypes.c_uint32(WORDS_PER_WIRE),
                    ctypes.c_uint32(round_index),
                )
                launch(
                    runtime,
                    packed_fn,
                    (terms + THREADS - 1) // THREADS,
                    params,
                    "packed_histogram",
                )
                ck(runtime.cuda.cuCtxSynchronize(), "packed_histogram_sync")
                packed_seconds += time.perf_counter() - packed_started
                packed_terms += terms
                packed_claim_terms += claim_count * terms

                count = WIDTH * GROUP_COUNT
                params = arguments(
                    ctypes.c_uint64(packed_d),
                    ctypes.c_uint64(lookup_d),
                    ctypes.c_uint64(main_d),
                    ctypes.c_uint32(WIDTH),
                    ctypes.c_uint32(GROUP_COUNT),
                    ctypes.c_uint32(WORDS_PER_WIRE),
                )
                launch(
                    runtime,
                    materialize_fn,
                    (count + THREADS - 1) // THREADS,
                    params,
                    "materialize_b16",
                )
                materialized_values += count

                source, output = main_d, scratch_d
                current_groups = GROUP_COUNT
                group_started = time.perf_counter()
                while current_groups > 1:
                    suffix_groups = current_groups // 2
                    ck(
                        runtime.cuda.cuMemsetD8_v2(
                            messages_d, 0, message_size
                        ),
                        "messages_zero",
                    )
                    terms = STATE_BITS * suffix_groups
                    common = (
                        ctypes.c_uint64(source),
                        ctypes.c_uint64(theta_d if layer_kind == 0 else chi_d),
                        ctypes.c_uint64(wire_d),
                        ctypes.c_uint64(zero_d),
                        ctypes.c_uint64(delta_d),
                        ctypes.c_uint64(messages_d),
                        ctypes.c_uint32(STATE_BITS),
                        ctypes.c_uint32(current_groups),
                        ctypes.c_uint32(suffix_groups),
                        ctypes.c_uint32(GROUP_COUNT // 2),
                    )
                    if layer_kind == 0:
                        params = arguments(
                            *common, ctypes.c_uint32(claim_count)
                        )
                        message_fn = theta_fn
                    else:
                        params = arguments(*common)
                        message_fn = chi_fn
                    launch(
                        runtime,
                        message_fn,
                        (terms + THREADS - 1) // THREADS,
                        params,
                        "group_message",
                    )
                    fold_count = WIDTH * suffix_groups
                    params = arguments(
                        ctypes.c_uint64(source),
                        ctypes.c_uint64(challenge_d),
                        ctypes.c_uint64(output),
                        ctypes.c_uint32(WIDTH),
                        ctypes.c_uint32(current_groups),
                    )
                    launch(
                        runtime,
                        fold_fn,
                        (fold_count + THREADS - 1) // THREADS,
                        params,
                        "fold_source",
                    )
                    group_terms += terms
                    group_fold_values += fold_count
                    source, output = output, source
                    current_groups = suffix_groups
                ck(runtime.cuda.cuCtxSynchronize(), "group_and_fold_sync")
                group_seconds += time.perf_counter() - group_started

                wire_started = time.perf_counter()
                if layer_kind == 0:
                    params = arguments(
                        ctypes.c_uint64(source),
                        ctypes.c_uint64(theta_d),
                        ctypes.c_uint64(factor_a_d),
                        ctypes.c_uint32(STATE_BITS),
                        ctypes.c_uint32(WIDTH),
                    )
                    factor_count = 1
                    factor_fn = theta_wire_factor_fn
                else:
                    params = arguments(
                        ctypes.c_uint64(source),
                        ctypes.c_uint64(chi_d),
                        ctypes.c_uint64(factor_a_d),
                        ctypes.c_uint32(STATE_BITS),
                        ctypes.c_uint32(WIDTH),
                        ctypes.c_uint32(round_index),
                    )
                    factor_count = 4
                    factor_fn = chi_wire_factor_fn
                launch(
                    runtime,
                    factor_fn,
                    (WIDTH + THREADS - 1) // THREADS,
                    params,
                    "materialize_wire_factors",
                )

                factor_source, factor_output = factor_a_d, factor_b_d
                weight_source, weight_output = wire_tail_d, weight_a_d
                current_width = WIDTH
                while current_width > 1:
                    next_width = current_width // 2
                    ck(
                        runtime.cuda.cuMemsetD8_v2(
                            messages_d, 0, message_size
                        ),
                        "wire_messages_zero",
                    )
                    if layer_kind == 0:
                        params = arguments(
                            ctypes.c_uint64(factor_source),
                            ctypes.c_uint64(weight_source),
                            ctypes.c_uint64(messages_d),
                            ctypes.c_uint32(current_width),
                        )
                        wire_message_fn = theta_wire_message_fn
                    else:
                        params = arguments(
                            ctypes.c_uint64(factor_source),
                            ctypes.c_uint64(weight_source),
                            ctypes.c_uint64(messages_d),
                            ctypes.c_uint32(current_width),
                            ctypes.c_uint32(WIDTH),
                        )
                        wire_message_fn = chi_wire_message_fn
                    launch(
                        runtime,
                        wire_message_fn,
                        (next_width + THREADS - 1) // THREADS,
                        params,
                        "wire_message",
                    )
                    params = arguments(
                        ctypes.c_uint64(factor_source),
                        ctypes.c_uint64(challenge_d),
                        ctypes.c_uint64(factor_output),
                        ctypes.c_uint32(current_width),
                        ctypes.c_uint32(factor_count),
                        ctypes.c_uint32(WIDTH),
                    )
                    launch(
                        runtime,
                        fold_wire_fn,
                        (factor_count * next_width + THREADS - 1) // THREADS,
                        params,
                        "fold_wire_factors",
                    )
                    params = arguments(
                        ctypes.c_uint64(weight_source),
                        ctypes.c_uint64(challenge_d),
                        ctypes.c_uint64(weight_output),
                        ctypes.c_uint32(current_width),
                        ctypes.c_uint32(1),
                        ctypes.c_uint32(WIDTH),
                    )
                    launch(
                        runtime,
                        fold_wire_fn,
                        (next_width + THREADS - 1) // THREADS,
                        params,
                        "fold_wire_weights",
                    )
                    wire_message_terms += next_width
                    wire_fold_values += (factor_count + 1) * next_width
                    factor_source, factor_output = factor_output, factor_source
                    weight_source = weight_output
                    weight_output = (
                        weight_b_d
                        if weight_output == weight_a_d
                        else weight_a_d
                    )
                    current_width = next_width
                ck(runtime.cuda.cuCtxSynchronize(), "wire_tail_sync")
                wire_seconds += time.perf_counter() - wire_started
                layer_seconds.append(time.perf_counter() - layer_started)
        total_seconds = time.perf_counter() - started

        sample = message_host_buffer()
        ck(
            runtime.cuda.cuMemcpyDtoH_v2(
                ctypes.cast(sample, ctypes.c_void_p),
                messages_d,
                ctypes.sizeof(sample),
            ),
            "copy_message_sample",
        )
        if not any(sample):
            raise SystemExit("message_sample_zero")

        device_working_set = (
            packed_size
            + lookup_size
            + theta_size
            + chi_size
            + wire_size
            + group_size
            + zero_size
            + delta_size
            + challenge_size
            + wire_tail_size
            + histogram_size
            + message_size
            + main_size
            + scratch_size
            + 2 * factor_size
            + 2 * weight_size
            + wire_kat_size
        )
        ordered = sorted(layer_seconds)
        print(f"repeats={repeats}")
        print(f"padded_instances={INSTANCES}")
        print("packed_bits=16")
        print("layers_per_round=2")
        print("claim_schedule=3,1")
        print(f"layers={2 * repeats}")
        print(f"packed_terms={packed_terms}")
        print(f"packed_claim_terms={packed_claim_terms}")
        print(f"materialized_triple_values={materialized_values}")
        print(f"group_message_terms={group_terms}")
        print(f"group_fold_triple_values={group_fold_values}")
        print(f"wire_message_terms={wire_message_terms}")
        print(f"wire_fold_triple_values={wire_fold_values}")
        print("wire_rounds_per_layer=11")
        print("authenticated_sumcheck_rounds_per_layer=25")
        print("wire_tail_differential_kat=true")
        print(f"compile_seconds={compile_seconds:.6f}")
        print(f"packed_seconds={packed_seconds:.6f}")
        print(f"group_seconds={group_seconds:.6f}")
        print(f"wire_seconds={wire_seconds:.6f}")
        print(f"kernel_total_seconds={total_seconds:.6f}")
        print(f"layer_min_seconds={ordered[0]:.6f}")
        print(f"layer_median_seconds={ordered[len(ordered) // 2]:.6f}")
        print(f"layer_max_seconds={ordered[-1]:.6f}")
        print(f"host_peak_mb={process_peak_mb():.3f}")
        print(f"device_working_set_mb={device_working_set / 1_000_000:.3f}")
        print(f"message_sample={list(sample)}")
    finally:
        runtime.close()


if __name__ == "__main__":
    main()
