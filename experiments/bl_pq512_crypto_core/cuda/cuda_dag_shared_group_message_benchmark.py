"""Exact-geometry calibration for shared-group DAG messages plus source folds.

The kernels cover every shared-group round for every relay-free DAG layer at
the K128 group count. B=8 and B=16 both publish the first group message
directly from packed bits and fold directly to the half-sized Fp16 table.
The B=16 lookup is the exact degree-15 Lagrange evaluation at the packed
challenge; no full 8,192-group Fp16 source table is materialized.

Public equality weights and wiring are deterministic synthetic calibration
inputs. This is not a proof and excludes masks, wire-label rounds, PCS work,
checkpoint I/O, and transcript serialization.
"""

import array
import ctypes
import os
import sys
import time
from pathlib import Path

from cuda_fp16_tower_kat import CUDA, Q, Runtime, add, ck, mul16, p_add, sub
from cuda_fp16_b16_binary_bridge_benchmark import (
    lagrange_evaluations,
    m31_basis,
)
from cuda_dag_packed_accumulator_benchmark import process_peak_mb
from cuda_dag_shared_group_fold_benchmark import (
    FP16_BYTES,
    GROUP_COUNT,
    KERNEL as FOLD_KERNEL,
    LAYERS,
    MAX_WIDTH,
    WORDS_PER_PLANE,
    copy,
    kernel_arguments,
    launch_first,
    launch_fold,
)


MESSAGE_KERNEL = r"""
enum Formula : unsigned int {
    XOR_GATE = 0U, NOT_LEFT_AND_RIGHT = 1U, NOT_XOR = 2U,
    COMPLEMENT_LEFT = 3U, SUBTRACT_GATE = 4U, MULTIPLY_GATE = 5U,
    ADD_GATE = 6U, RELAY_LEFT = 7U, ZERO_GATE = 8U
};

__device__ __forceinline__ F16 z16(){F16 value={};return value;}
__device__ __forceinline__ F16 n16(F16 x){return s16(z16(),x);}

struct Cubic { F16 c0, c1, c2, c3; };

__device__ __forceinline__ unsigned int halfp(unsigned int x) {
    return (x + ((x & 1U) * 2147483647U)) >> 1U;
}
__device__ __forceinline__ F2 half2(F2 x) {
    return {halfp(x.a), halfp(x.b)};
}
__device__ __forceinline__ F4 half4(F4 x) {
    return {half2(x.a), half2(x.b)};
}
__device__ __forceinline__ F8 half8(F8 x) {
    return {half4(x.a), half4(x.b)};
}
__device__ __forceinline__ F16 half16(F16 x) {
    return {half8(x.a), half8(x.b)};
}

// Exact four-multiplication product of a linear and a quadratic polynomial.
// Evaluation at 0, 1, -1, and infinity replaces the six schoolbook Fp16
// products; division by two is coordinate-wise in the M31 base field.
__device__ __forceinline__ Cubic linear_times_quadratic(
    F16 e0,
    F16 e1,
    F16 q0,
    F16 q1,
    F16 q2
) {
    F16 c0 = m16(e0, q0);
    F16 c3 = m16(e1, q2);
    F16 plus = m16(a16(e0, e1), a16(a16(q0, q1), q2));
    F16 minus = m16(s16(e0, e1), a16(s16(q0, q1), q2));
    F16 c1 = half16(s16(s16(plus, minus), a16(c3, c3)));
    F16 c2 = half16(s16(a16(plus, minus), a16(c0, c0)));
    return {c0, c1, c2, c3};
}

__device__ __forceinline__ Cubic term_cubic(
    F16 left_zero,
    F16 left_one,
    F16 right_zero,
    F16 right_one,
    unsigned int formula,
    const unsigned int *wire_weights,
    const unsigned int *group_zero_weights,
    const unsigned int *group_delta_weights,
    unsigned int output,
    unsigned int suffix,
    unsigned int max_raw,
    unsigned int max_suffix,
    unsigned int claim_count
) {
    F16 left_delta = s16(left_one, left_zero);
    F16 right_delta = s16(right_one, right_zero);
    F16 left_zero_right_zero = m16(left_zero, right_zero);
    F16 left_delta_right_delta = m16(left_delta, right_delta);
    F16 cross_linear = s16(
        s16(m16(left_one, right_one), left_zero_right_zero),
        left_delta_right_delta
    );
    F16 q0, q1, q2;
    if (formula == ZERO_GATE) {
        q0 = z16(); q1 = z16(); q2 = z16();
    } else if (formula == RELAY_LEFT) {
        q0 = left_zero; q1 = left_delta; q2 = z16();
    } else if (formula == COMPLEMENT_LEFT) {
        F16 one = z16(); one.a.a.a.a = 1U;
        q0 = s16(one, left_zero); q1 = n16(left_delta); q2 = z16();
    } else if (formula == ADD_GATE) {
        q0 = a16(left_zero, right_zero);
        q1 = a16(left_delta, right_delta);
        q2 = z16();
    } else if (formula == SUBTRACT_GATE) {
        q0 = s16(left_zero, right_zero);
        q1 = s16(left_delta, right_delta);
        q2 = z16();
    } else if (formula == MULTIPLY_GATE) {
        q0 = left_zero_right_zero;
        q1 = cross_linear;
        q2 = left_delta_right_delta;
    } else if (formula == NOT_LEFT_AND_RIGHT) {
        q0 = s16(right_zero, left_zero_right_zero);
        q1 = s16(right_delta, cross_linear);
        q2 = n16(left_delta_right_delta);
    } else if (formula == NOT_XOR) {
        F16 one = z16();
        one.a.a.a.a = 1U;
        q0 = a16(
            s16(s16(one, left_zero), right_zero),
            a16(left_zero_right_zero, left_zero_right_zero)
        );
        q1 = a16(
            s16(n16(left_delta), right_delta),
            a16(cross_linear, cross_linear)
        );
        q2 = a16(left_delta_right_delta, left_delta_right_delta);
    } else {
        q0 = s16(
            a16(left_zero, right_zero),
            a16(left_zero_right_zero, left_zero_right_zero)
        );
        q1 = s16(
            a16(left_delta, right_delta),
            a16(cross_linear, cross_linear)
        );
        q2 = n16(a16(left_delta_right_delta, left_delta_right_delta));
    }
    F16 equality_zero = z16();
    F16 equality_delta = z16();
    for (unsigned int claim = 0; claim < claim_count; ++claim) {
        F16 wire = l16(wire_weights + 16ULL * (claim * max_raw + output));
        equality_zero = a16(
            equality_zero,
            m16(
                wire,
                l16(group_zero_weights + 16ULL * (claim * max_suffix + suffix))
            )
        );
        equality_delta = a16(
            equality_delta,
            m16(
                wire,
                l16(group_delta_weights + 16ULL * (claim * max_suffix + suffix))
            )
        );
    }
    return linear_times_quadratic(equality_zero, equality_delta, q0, q1, q2);
}

__device__ __forceinline__ void reduce_cubic(
    Cubic value,
    unsigned int *partial,
    unsigned int block_output
) {
    __shared__ unsigned int sums[128 * 64];
    unsigned int thread = threadIdx.x;
    unsigned int *slot = sums + thread * 64U;
    st16(slot, value.c0);
    st16(slot + 16, value.c1);
    st16(slot + 32, value.c2);
    st16(slot + 48, value.c3);
    __syncthreads();
    for (unsigned int stride = 64U; stride > 0U; stride >>= 1U) {
        if (thread < stride) {
            unsigned int *destination = sums + thread * 64U;
            const unsigned int *source = sums + (thread + stride) * 64U;
            for (unsigned int coordinate = 0; coordinate < 64U; ++coordinate) {
                destination[coordinate] =
                    addp(destination[coordinate], source[coordinate]);
            }
        }
        __syncthreads();
    }
    if (thread == 0U) {
        for (unsigned int coordinate = 0; coordinate < 64U; ++coordinate) {
            partial[64ULL * block_output + coordinate] = sums[coordinate];
        }
    }
}

__device__ __forceinline__ void reduce_quadratic_to_cubic(
    F16 q0,
    F16 q1,
    F16 q2,
    F16 group_zero,
    F16 group_delta,
    unsigned int *partial,
    unsigned int suffix
) {
    __shared__ unsigned int sums[128 * 48];
    unsigned int thread = threadIdx.x;
    unsigned int *slot = sums + thread * 48U;
    st16(slot, q0);
    st16(slot + 16, q1);
    st16(slot + 32, q2);
    __syncthreads();
    for (unsigned int stride = 64U; stride > 0U; stride >>= 1U) {
        if (thread < stride) {
            unsigned int *destination = sums + thread * 48U;
            const unsigned int *source = sums + (thread + stride) * 48U;
            for (unsigned int coordinate = 0; coordinate < 48U; ++coordinate) {
                destination[coordinate] =
                    addp(destination[coordinate], source[coordinate]);
            }
        }
        __syncthreads();
    }
    if (thread == 0U) {
        F16 aggregate0 = l16(sums);
        F16 aggregate1 = l16(sums + 16);
        F16 aggregate2 = l16(sums + 32);
        Cubic product = linear_times_quadratic(
            group_zero,
            group_delta,
            aggregate0,
            aggregate1,
            aggregate2
        );
        st16(partial + 64ULL * suffix, product.c0);
        st16(partial + 64ULL * suffix + 16, product.c1);
        st16(partial + 64ULL * suffix + 32, product.c2);
        st16(partial + 64ULL * suffix + 48, product.c3);
    }
}

extern "C" __global__ void packed_group_message(
    const unsigned long long *left_packed,
    const unsigned long long *right_packed,
    const unsigned int *lookup,
    const unsigned int *base_left,
    const unsigned int *base_right,
    const unsigned int *formulas,
    const unsigned int *wire_weights,
    const unsigned int *group_zero_weights,
    const unsigned int *group_delta_weights,
    unsigned int *partial,
    unsigned int raw_width,
    unsigned int left_width,
    unsigned int right_width,
    unsigned int suffix_groups,
    unsigned int words_per_plane,
    unsigned int max_raw,
    unsigned int max_suffix,
    unsigned int claim_count
) {
    unsigned long long term_count = (unsigned long long)raw_width * suffix_groups;
    unsigned long long first =
        ((unsigned long long)blockIdx.x * blockDim.x + threadIdx.x) * 8ULL;
    Cubic total = {z16(), z16(), z16(), z16()};
    for (unsigned int local = 0; local < 8U; ++local) {
        unsigned long long index = first + local;
        if (index >= term_count) break;
        unsigned int suffix = (unsigned int)(index / raw_width);
        unsigned int output = (unsigned int)(index - (unsigned long long)suffix * raw_width);
        unsigned int left_wire = base_left[output];
        unsigned int right_wire = base_right[output];
        unsigned int first_instance = 16U * suffix;
        unsigned int shift = first_instance & 63U;
        unsigned int word = first_instance >> 6;
        unsigned long long left_bits = left_packed[
            (unsigned long long)left_wire * words_per_plane + word
        ];
        unsigned long long right_bits = right_packed[
            (unsigned long long)right_wire * words_per_plane + word
        ];
        F16 left_zero = l16(lookup + 16ULL * ((left_bits >> shift) & 255ULL));
        F16 left_one = l16(lookup + 16ULL * ((left_bits >> (shift + 8U)) & 255ULL));
        F16 right_zero = l16(lookup + 16ULL * ((right_bits >> shift) & 255ULL));
        F16 right_one = l16(lookup + 16ULL * ((right_bits >> (shift + 8U)) & 255ULL));
        Cubic term = term_cubic(
            left_zero,
            left_one,
            right_zero,
            right_one,
            formulas[output],
            wire_weights,
            group_zero_weights,
            group_delta_weights,
            output,
            suffix,
            max_raw,
            max_suffix,
            claim_count
        );
        total.c0 = a16(total.c0, term.c0);
        total.c1 = a16(total.c1, term.c1);
        total.c2 = a16(total.c2, term.c2);
        total.c3 = a16(total.c3, term.c3);
    }
    reduce_cubic(total, partial, blockIdx.x);
}

__device__ __forceinline__ F16 fold_pair(
    F16 zero,
    F16 one,
    F16 challenge
) {
    return a16(zero, m16(challenge, s16(one, zero)));
}

extern "C" __global__ void packed_b8_second_group_message(
    const unsigned long long *left_packed,
    const unsigned long long *right_packed,
    const unsigned int *lookup,
    const unsigned int *first_challenge,
    const unsigned int *base_left,
    const unsigned int *base_right,
    const unsigned int *formulas,
    const unsigned int *wire_weights,
    const unsigned int *group_zero_weights,
    const unsigned int *group_delta_weights,
    unsigned int *partial,
    unsigned int raw_width,
    unsigned int suffix_groups,
    unsigned int words_per_plane,
    unsigned int max_raw,
    unsigned int max_suffix,
    unsigned int claim_count
) {
    unsigned long long term_count = (unsigned long long)raw_width * suffix_groups;
    unsigned long long first =
        ((unsigned long long)blockIdx.x * blockDim.x + threadIdx.x) * 8ULL;
    Cubic total = {z16(), z16(), z16(), z16()};
    F16 challenge = l16(first_challenge);
    for (unsigned int local = 0; local < 8U; ++local) {
        unsigned long long index = first + local;
        if (index >= term_count) break;
        unsigned int suffix = (unsigned int)(index / raw_width);
        unsigned int output =
            (unsigned int)(index - (unsigned long long)suffix * raw_width);
        unsigned int first_instance = 32U * suffix;
        unsigned int shift = first_instance & 63U;
        unsigned int word = first_instance >> 6;
        unsigned long long left_bits = left_packed[
            (unsigned long long)base_left[output] * words_per_plane + word
        ] >> shift;
        unsigned long long right_bits = right_packed[
            (unsigned long long)base_right[output] * words_per_plane + word
        ] >> shift;
        F16 left_zero = fold_pair(
            l16(lookup + 16ULL * (left_bits & 255ULL)),
            l16(lookup + 16ULL * ((left_bits >> 8U) & 255ULL)),
            challenge
        );
        F16 left_one = fold_pair(
            l16(lookup + 16ULL * ((left_bits >> 16U) & 255ULL)),
            l16(lookup + 16ULL * ((left_bits >> 24U) & 255ULL)),
            challenge
        );
        F16 right_zero = fold_pair(
            l16(lookup + 16ULL * (right_bits & 255ULL)),
            l16(lookup + 16ULL * ((right_bits >> 8U) & 255ULL)),
            challenge
        );
        F16 right_one = fold_pair(
            l16(lookup + 16ULL * ((right_bits >> 16U) & 255ULL)),
            l16(lookup + 16ULL * ((right_bits >> 24U) & 255ULL)),
            challenge
        );
        Cubic term = term_cubic(
            left_zero,
            left_one,
            right_zero,
            right_one,
            formulas[output],
            wire_weights,
            group_zero_weights,
            group_delta_weights,
            output,
            suffix,
            max_raw,
            max_suffix,
            claim_count
        );
        total.c0 = a16(total.c0, term.c0);
        total.c1 = a16(total.c1, term.c1);
        total.c2 = a16(total.c2, term.c2);
        total.c3 = a16(total.c3, term.c3);
    }
    reduce_cubic(total, partial, blockIdx.x);
}

extern "C" __global__ void packed_b8_two_group_fold(
    const unsigned long long *packed,
    const unsigned int *lookup,
    const unsigned int *first_challenge,
    const unsigned int *second_challenge,
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
    unsigned int wire =
        (unsigned int)(index - (unsigned long long)group * width);
    unsigned int first_instance = 32U * group;
    unsigned int shift = first_instance & 63U;
    unsigned int word = first_instance >> 6;
    unsigned long long bits = packed[
        (unsigned long long)wire * words_per_plane + word
    ] >> shift;
    F16 first = l16(first_challenge);
    F16 zero = fold_pair(
        l16(lookup + 16ULL * (bits & 255ULL)),
        l16(lookup + 16ULL * ((bits >> 8U) & 255ULL)),
        first
    );
    F16 one = fold_pair(
        l16(lookup + 16ULL * ((bits >> 16U) & 255ULL)),
        l16(lookup + 16ULL * ((bits >> 24U) & 255ULL)),
        first
    );
    st16(
        output + 16ULL * index,
        fold_pair(zero, one, l16(second_challenge))
    );
}

extern "C" __global__ void packed_b16_group_message(
    const unsigned short *left_packed,
    const unsigned short *right_packed,
    const unsigned int *lookup,
    const unsigned int *base_left,
    const unsigned int *base_right,
    const unsigned int *formulas,
    const unsigned int *wire_weights,
    const unsigned int *group_zero_weights,
    const unsigned int *group_delta_weights,
    unsigned int *partial,
    unsigned int raw_width,
    unsigned int suffix_groups,
    unsigned int words_per_plane,
    unsigned int max_raw,
    unsigned int max_suffix,
    unsigned int claim_count
) {
    unsigned long long term_count = (unsigned long long)raw_width * suffix_groups;
    unsigned long long first =
        ((unsigned long long)blockIdx.x * blockDim.x + threadIdx.x) * 8ULL;
    Cubic total = {z16(), z16(), z16(), z16()};
    for (unsigned int local = 0; local < 8U; ++local) {
        unsigned long long index = first + local;
        if (index >= term_count) break;
        unsigned int suffix = (unsigned int)(index / raw_width);
        unsigned int output =
            (unsigned int)(index - (unsigned long long)suffix * raw_width);
        unsigned int packed_groups = words_per_plane * 4U;
        unsigned int first_group = 2U * suffix;
        unsigned int left_base = base_left[output] * packed_groups;
        unsigned int right_base = base_right[output] * packed_groups;
        unsigned int left_zero_pattern =
            left_packed[left_base + first_group];
        unsigned int left_one_pattern =
            left_packed[left_base + first_group + 1U];
        unsigned int right_zero_pattern =
            right_packed[right_base + first_group];
        unsigned int right_one_pattern =
            right_packed[right_base + first_group + 1U];
        Cubic term = term_cubic(
            l16(lookup + 16ULL * left_zero_pattern),
            l16(lookup + 16ULL * left_one_pattern),
            l16(lookup + 16ULL * right_zero_pattern),
            l16(lookup + 16ULL * right_one_pattern),
            formulas[output],
            wire_weights,
            group_zero_weights,
            group_delta_weights,
            output,
            suffix,
            max_raw,
            max_suffix,
            claim_count
        );
        total.c0 = a16(total.c0, term.c0);
        total.c1 = a16(total.c1, term.c1);
        total.c2 = a16(total.c2, term.c2);
        total.c3 = a16(total.c3, term.c3);
    }
    reduce_cubic(total, partial, blockIdx.x);
}

extern "C" __global__ void packed_b16_group_message_factored_one_claim(
    const unsigned short *left_packed,
    const unsigned short *right_packed,
    const unsigned int *lookup,
    const unsigned int *base_left,
    const unsigned int *base_right,
    const unsigned int *formulas,
    const unsigned int *wire_weights,
    const unsigned int *group_zero_weights,
    const unsigned int *group_delta_weights,
    unsigned int *partial,
    unsigned int raw_width,
    unsigned int tile_suffix_groups,
    unsigned int suffix_offset,
    unsigned int words_per_plane,
    unsigned int max_suffix
) {
    unsigned int local_suffix = blockIdx.x;
    if (local_suffix >= tile_suffix_groups) return;
    unsigned int suffix = suffix_offset + local_suffix;
    F16 aggregate0 = z16();
    F16 aggregate1 = z16();
    F16 aggregate2 = z16();
    unsigned int packed_groups = words_per_plane * 4U;
    unsigned int first_group = 2U * suffix;
    for (unsigned int output = threadIdx.x; output < raw_width; output += blockDim.x) {
        unsigned int left_base = base_left[output] * packed_groups;
        unsigned int right_base = base_right[output] * packed_groups;
        F16 left_zero = l16(
            lookup + 16ULL * left_packed[left_base + first_group]
        );
        F16 left_one = l16(
            lookup + 16ULL * left_packed[left_base + first_group + 1U]
        );
        F16 right_zero = l16(
            lookup + 16ULL * right_packed[right_base + first_group]
        );
        F16 right_one = l16(
            lookup + 16ULL * right_packed[right_base + first_group + 1U]
        );
        F16 left_delta = s16(left_one, left_zero);
        F16 right_delta = s16(right_one, right_zero);
        F16 left_zero_right_zero = m16(left_zero, right_zero);
        F16 left_delta_right_delta = m16(left_delta, right_delta);
        F16 cross_linear = s16(
            s16(m16(left_one, right_one), left_zero_right_zero),
            left_delta_right_delta
        );
        F16 q0, q1, q2;
        unsigned int formula = formulas[output];
        if (formula == NOT_LEFT_AND_RIGHT) {
            q0 = s16(right_zero, left_zero_right_zero);
            q1 = s16(right_delta, cross_linear);
            q2 = n16(left_delta_right_delta);
        } else if (formula == NOT_XOR) {
            F16 one = z16();
            one.a.a.a.a = 1U;
            q0 = a16(
                s16(s16(one, left_zero), right_zero),
                a16(left_zero_right_zero, left_zero_right_zero)
            );
            q1 = a16(
                s16(n16(left_delta), right_delta),
                a16(cross_linear, cross_linear)
            );
            q2 = a16(left_delta_right_delta, left_delta_right_delta);
        } else {
            q0 = s16(
                a16(left_zero, right_zero),
                a16(left_zero_right_zero, left_zero_right_zero)
            );
            q1 = s16(
                a16(left_delta, right_delta),
                a16(cross_linear, cross_linear)
            );
            q2 = n16(a16(left_delta_right_delta, left_delta_right_delta));
        }
        F16 wire = l16(wire_weights + 16ULL * output);
        aggregate0 = a16(aggregate0, m16(wire, q0));
        aggregate1 = a16(aggregate1, m16(wire, q1));
        aggregate2 = a16(aggregate2, m16(wire, q2));
    }
    reduce_quadratic_to_cubic(
        aggregate0,
        aggregate1,
        aggregate2,
        l16(group_zero_weights + 16ULL * suffix),
        l16(group_delta_weights + 16ULL * suffix),
        partial,
        suffix
    );
}

extern "C" __global__ void packed_b16_first_group_fold(
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
    unsigned int wire =
        (unsigned int)(index - (unsigned long long)group * width);
    unsigned int first_instance = 32U * group;
    unsigned int shift = first_instance & 63U;
    unsigned int word = first_instance >> 6;
    unsigned long long bits = packed[
        (unsigned long long)wire * words_per_plane + word
    ];
    F16 zero = l16(lookup + 16ULL * ((bits >> shift) & 65535ULL));
    F16 one = l16(lookup + 16ULL * ((bits >> (shift + 16U)) & 65535ULL));
    st16(
        output + 16ULL * index,
        a16(zero, m16(l16(challenge), s16(one, zero)))
    );
}

extern "C" __global__ void fp16_group_message(
    const unsigned int *left,
    const unsigned int *right,
    const unsigned int *base_left,
    const unsigned int *base_right,
    const unsigned int *formulas,
    const unsigned int *wire_weights,
    const unsigned int *group_zero_weights,
    const unsigned int *group_delta_weights,
    unsigned int *partial,
    unsigned int raw_width,
    unsigned int left_width,
    unsigned int right_width,
    unsigned int suffix_groups,
    unsigned int source_nonuniform_groups,
    unsigned int max_raw,
    unsigned int max_suffix,
    unsigned int claim_count
) {
    unsigned long long term_count = (unsigned long long)raw_width * suffix_groups;
    unsigned long long first =
        ((unsigned long long)blockIdx.x * blockDim.x + threadIdx.x) * 8ULL;
    Cubic total = {z16(), z16(), z16(), z16()};
    for (unsigned int local = 0; local < 8U; ++local) {
        unsigned long long index = first + local;
        if (index >= term_count) break;
        unsigned int suffix = (unsigned int)(index / raw_width);
        unsigned int output = (unsigned int)(index - (unsigned long long)suffix * raw_width);
        unsigned int left_wire = base_left[output];
        unsigned int right_wire = base_right[output];
        unsigned int zero_group =
            min(2U * suffix, source_nonuniform_groups);
        unsigned int one_group =
            min(2U * suffix + 1U, source_nonuniform_groups);
        unsigned long long left_zero_index =
            (unsigned long long)zero_group * left_width + left_wire;
        unsigned long long left_one_index =
            (unsigned long long)one_group * left_width + left_wire;
        unsigned long long right_zero_index =
            (unsigned long long)zero_group * right_width + right_wire;
        unsigned long long right_one_index =
            (unsigned long long)one_group * right_width + right_wire;
        Cubic term = term_cubic(
            l16(left + 16ULL * left_zero_index),
            l16(left + 16ULL * left_one_index),
            l16(right + 16ULL * right_zero_index),
            l16(right + 16ULL * right_one_index),
            formulas[output],
            wire_weights,
            group_zero_weights,
            group_delta_weights,
            output,
            suffix,
            max_raw,
            max_suffix,
            claim_count
        );
        total.c0 = a16(total.c0, term.c0);
        total.c1 = a16(total.c1, term.c1);
        total.c2 = a16(total.c2, term.c2);
        total.c3 = a16(total.c3, term.c3);
    }
    reduce_cubic(total, partial, blockIdx.x);
}

extern "C" __global__ void fp16_group_message_factored_one_claim(
    const unsigned int *left,
    const unsigned int *right,
    const unsigned int *base_left,
    const unsigned int *base_right,
    const unsigned int *formulas,
    const unsigned int *wire_weights,
    const unsigned int *group_zero_weights,
    const unsigned int *group_delta_weights,
    unsigned int *partial,
    unsigned int raw_width,
    unsigned int left_width,
    unsigned int right_width,
    unsigned int suffix_groups,
    unsigned int source_nonuniform_groups,
    unsigned int max_suffix
) {
    unsigned int suffix = blockIdx.x;
    if (suffix >= suffix_groups) return;
    F16 aggregate0 = z16();
    F16 aggregate1 = z16();
    F16 aggregate2 = z16();
    for (unsigned int output = threadIdx.x; output < raw_width; output += blockDim.x) {
        unsigned int left_wire = base_left[output];
        unsigned int right_wire = base_right[output];
        unsigned int zero_group =
            min(2U * suffix, source_nonuniform_groups);
        unsigned int one_group =
            min(2U * suffix + 1U, source_nonuniform_groups);
        unsigned long long left_zero_index =
            (unsigned long long)zero_group * left_width + left_wire;
        unsigned long long left_one_index =
            (unsigned long long)one_group * left_width + left_wire;
        unsigned long long right_zero_index =
            (unsigned long long)zero_group * right_width + right_wire;
        unsigned long long right_one_index =
            (unsigned long long)one_group * right_width + right_wire;
        F16 left_zero = l16(left + 16ULL * left_zero_index);
        F16 left_one = l16(left + 16ULL * left_one_index);
        F16 right_zero = l16(right + 16ULL * right_zero_index);
        F16 right_one = l16(right + 16ULL * right_one_index);
        F16 left_delta = s16(left_one, left_zero);
        F16 right_delta = s16(right_one, right_zero);
        F16 left_zero_right_zero = m16(left_zero, right_zero);
        F16 left_delta_right_delta = m16(left_delta, right_delta);
        F16 cross_linear = s16(
            s16(m16(left_one, right_one), left_zero_right_zero),
            left_delta_right_delta
        );
        F16 q0, q1, q2;
        unsigned int formula = formulas[output];
        if (formula == NOT_LEFT_AND_RIGHT) {
            q0 = s16(right_zero, left_zero_right_zero);
            q1 = s16(right_delta, cross_linear);
            q2 = n16(left_delta_right_delta);
        } else if (formula == NOT_XOR) {
            F16 one = z16();
            one.a.a.a.a = 1U;
            q0 = a16(
                s16(s16(one, left_zero), right_zero),
                a16(left_zero_right_zero, left_zero_right_zero)
            );
            q1 = a16(
                s16(n16(left_delta), right_delta),
                a16(cross_linear, cross_linear)
            );
            q2 = a16(left_delta_right_delta, left_delta_right_delta);
        } else {
            q0 = s16(
                a16(left_zero, right_zero),
                a16(left_zero_right_zero, left_zero_right_zero)
            );
            q1 = s16(
                a16(left_delta, right_delta),
                a16(cross_linear, cross_linear)
            );
            q2 = n16(a16(left_delta_right_delta, left_delta_right_delta));
        }
        F16 wire = l16(wire_weights + 16ULL * output);
        aggregate0 = a16(aggregate0, m16(wire, q0));
        aggregate1 = a16(aggregate1, m16(wire, q1));
        aggregate2 = a16(aggregate2, m16(wire, q2));
    }
    reduce_quadratic_to_cubic(
        aggregate0,
        aggregate1,
        aggregate2,
        l16(group_zero_weights + 16ULL * suffix),
        l16(group_delta_weights + 16ULL * suffix),
        partial,
        suffix
    );
}

extern "C" __global__ void reduce_cubic_partials(
    const unsigned int *input,
    unsigned int *output,
    unsigned int count
) {
    unsigned int first = (blockIdx.x * blockDim.x + threadIdx.x) * 8U;
    Cubic total = {z16(), z16(), z16(), z16()};
    for (unsigned int local = 0; local < 8U; ++local) {
        unsigned int index = first + local;
        if (index >= count) break;
        const unsigned int *value = input + 64ULL * index;
        total.c0 = a16(total.c0, l16(value));
        total.c1 = a16(total.c1, l16(value + 16));
        total.c2 = a16(total.c2, l16(value + 32));
        total.c3 = a16(total.c3, l16(value + 48));
    }
    reduce_cubic(total, output, blockIdx.x);
}
"""


RAW_WIDTHS = (640, 320, 320, 320, 1_600, 1_600, 1_600)
# Exact backward claim multiplicities induced by the seven-layer DAG.
LAYER_CLAIMS = (2, 1, 2, 1, 3, 1, 4)
MAX_RAW = max(RAW_WIDTHS)
MAX_SUFFIX = GROUP_COUNT // 2
THREADS = 128
TERMS_PER_THREAD = 8


def function(runtime, name):
    result = ctypes.c_void_p()
    ck(
        runtime.cuda.cuModuleGetFunction(
            ctypes.byref(result), runtime.module, name.encode()
        ),
        f"{name}_function",
    )
    return result


def reduce_partials(runtime, reduce_function, source, scratch, count):
    while count > 1:
        output_count = (count + THREADS * TERMS_PER_THREAD - 1) // (
            THREADS * TERMS_PER_THREAD
        )
        arguments = kernel_arguments(
            ctypes.c_uint64(source),
            ctypes.c_uint64(scratch),
            ctypes.c_uint32(count),
        )
        ck(
            runtime.cuda.cuLaunchKernel(
                reduce_function,
                output_count,
                1,
                1,
                THREADS,
                1,
                1,
                0,
                None,
                arguments,
                None,
            ),
            "reduce_cubic_partials",
        )
        source, scratch = scratch, source
        count = output_count
    return source


def launch_packed_message(
    runtime,
    message_function,
    reduce_function,
    left_packed,
    right_packed,
    lookup,
    base_left,
    base_right,
    formulas,
    wire_weights,
    group_zero,
    group_delta,
    partial,
    scratch,
    raw_width,
    left_width,
    right_width,
    suffix_groups,
    claim_count,
):
    terms = raw_width * suffix_groups
    blocks = (terms + THREADS * TERMS_PER_THREAD - 1) // (
        THREADS * TERMS_PER_THREAD
    )
    arguments = kernel_arguments(
        ctypes.c_uint64(left_packed),
        ctypes.c_uint64(right_packed),
        ctypes.c_uint64(lookup),
        ctypes.c_uint64(base_left),
        ctypes.c_uint64(base_right),
        ctypes.c_uint64(formulas),
        ctypes.c_uint64(wire_weights),
        ctypes.c_uint64(group_zero),
        ctypes.c_uint64(group_delta),
        ctypes.c_uint64(partial),
        ctypes.c_uint32(raw_width),
        ctypes.c_uint32(left_width),
        ctypes.c_uint32(right_width),
        ctypes.c_uint32(suffix_groups),
        ctypes.c_uint32(WORDS_PER_PLANE),
        ctypes.c_uint32(MAX_RAW),
        ctypes.c_uint32(MAX_SUFFIX),
        ctypes.c_uint32(claim_count),
    )
    ck(
        runtime.cuda.cuLaunchKernel(
            message_function,
            blocks,
            1,
            1,
            THREADS,
            1,
            1,
            0,
            None,
            arguments,
            None,
        ),
        "packed_group_message",
    )
    return reduce_partials(runtime, reduce_function, partial, scratch, blocks)


def launch_b16_packed_message(
    runtime,
    message_function,
    reduce_function,
    left_packed,
    right_packed,
    lookup,
    base_left,
    base_right,
    formulas,
    wire_weights,
    group_zero,
    group_delta,
    partial,
    scratch,
    raw_width,
    suffix_groups,
    words_per_plane,
    claim_count,
    factored_one_claim_function=None,
):
    if claim_count == 1 and factored_one_claim_function is not None:
        arguments = kernel_arguments(
            ctypes.c_uint64(left_packed),
            ctypes.c_uint64(right_packed),
            ctypes.c_uint64(lookup),
            ctypes.c_uint64(base_left),
            ctypes.c_uint64(base_right),
            ctypes.c_uint64(formulas),
            ctypes.c_uint64(wire_weights),
            ctypes.c_uint64(group_zero),
            ctypes.c_uint64(group_delta),
            ctypes.c_uint64(partial),
            ctypes.c_uint32(raw_width),
            ctypes.c_uint32(suffix_groups),
            ctypes.c_uint32(0),
            ctypes.c_uint32(words_per_plane),
            ctypes.c_uint32(MAX_SUFFIX),
        )
        ck(
            runtime.cuda.cuLaunchKernel(
                factored_one_claim_function,
                suffix_groups,
                1,
                1,
                THREADS,
                1,
                1,
                0,
                None,
                arguments,
                None,
            ),
            "packed_b16_group_message_factored_one_claim",
        )
        result = reduce_partials(
            runtime, reduce_function, partial, scratch, suffix_groups
        )
        return result
    terms = raw_width * suffix_groups
    blocks = (terms + THREADS * TERMS_PER_THREAD - 1) // (
        THREADS * TERMS_PER_THREAD
    )
    arguments = kernel_arguments(
        ctypes.c_uint64(left_packed),
        ctypes.c_uint64(right_packed),
        ctypes.c_uint64(lookup),
        ctypes.c_uint64(base_left),
        ctypes.c_uint64(base_right),
        ctypes.c_uint64(formulas),
        ctypes.c_uint64(wire_weights),
        ctypes.c_uint64(group_zero),
        ctypes.c_uint64(group_delta),
        ctypes.c_uint64(partial),
        ctypes.c_uint32(raw_width),
        ctypes.c_uint32(suffix_groups),
        ctypes.c_uint32(words_per_plane),
        ctypes.c_uint32(MAX_RAW),
        ctypes.c_uint32(MAX_SUFFIX),
        ctypes.c_uint32(claim_count),
    )
    ck(
        runtime.cuda.cuLaunchKernel(
            message_function,
            blocks,
            1,
            1,
            THREADS,
            1,
            1,
            0,
            None,
            arguments,
            None,
        ),
        "packed_b16_group_message",
    )
    result = reduce_partials(runtime, reduce_function, partial, scratch, blocks)
    return result


def launch_b8_second_packed_message(
    runtime,
    message_function,
    reduce_function,
    left_packed,
    right_packed,
    lookup,
    first_challenge,
    base_left,
    base_right,
    formulas,
    wire_weights,
    group_zero,
    group_delta,
    partial,
    scratch,
    raw_width,
    suffix_groups,
    claim_count,
):
    terms = raw_width * suffix_groups
    blocks = (terms + THREADS * TERMS_PER_THREAD - 1) // (
        THREADS * TERMS_PER_THREAD
    )
    arguments = kernel_arguments(
        ctypes.c_uint64(left_packed),
        ctypes.c_uint64(right_packed),
        ctypes.c_uint64(lookup),
        ctypes.c_uint64(first_challenge),
        ctypes.c_uint64(base_left),
        ctypes.c_uint64(base_right),
        ctypes.c_uint64(formulas),
        ctypes.c_uint64(wire_weights),
        ctypes.c_uint64(group_zero),
        ctypes.c_uint64(group_delta),
        ctypes.c_uint64(partial),
        ctypes.c_uint32(raw_width),
        ctypes.c_uint32(suffix_groups),
        ctypes.c_uint32(WORDS_PER_PLANE),
        ctypes.c_uint32(MAX_RAW),
        ctypes.c_uint32(MAX_SUFFIX),
        ctypes.c_uint32(claim_count),
    )
    ck(
        runtime.cuda.cuLaunchKernel(
            message_function,
            blocks,
            1,
            1,
            THREADS,
            1,
            1,
            0,
            None,
            arguments,
            None,
        ),
        "packed_b8_second_group_message",
    )
    return reduce_partials(runtime, reduce_function, partial, scratch, blocks)


def launch_b8_two_group_fold(
    runtime,
    fold_function,
    packed,
    lookup,
    first_challenge,
    second_challenge,
    output,
    width,
    groups,
):
    count = width * groups
    arguments = kernel_arguments(
        ctypes.c_uint64(packed),
        ctypes.c_uint64(lookup),
        ctypes.c_uint64(first_challenge),
        ctypes.c_uint64(second_challenge),
        ctypes.c_uint64(output),
        ctypes.c_uint32(width),
        ctypes.c_uint32(groups),
        ctypes.c_uint32(WORDS_PER_PLANE),
    )
    ck(
        runtime.cuda.cuLaunchKernel(
            fold_function,
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
        "packed_b8_two_group_fold",
    )


def launch_b16_first(
    runtime,
    fold_function,
    packed,
    lookup,
    challenge,
    output,
    width,
    groups,
    words_per_plane,
):
    count = width * groups
    arguments = kernel_arguments(
        ctypes.c_uint64(packed),
        ctypes.c_uint64(lookup),
        ctypes.c_uint64(challenge),
        ctypes.c_uint64(output),
        ctypes.c_uint32(width),
        ctypes.c_uint32(groups),
        ctypes.c_uint32(words_per_plane),
    )
    ck(
        runtime.cuda.cuLaunchKernel(
            fold_function,
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
        "packed_b16_first_group_fold",
    )


def launch_fp16_message(
    runtime,
    message_function,
    factored_one_claim_function,
    reduce_function,
    left,
    right,
    base_left,
    base_right,
    formulas,
    wire_weights,
    group_zero,
    group_delta,
    partial,
    scratch,
    raw_width,
    left_width,
    right_width,
    suffix_groups,
    source_nonuniform_groups,
    claim_count,
):
    terms = raw_width * suffix_groups
    if claim_count == 1:
        arguments = kernel_arguments(
            ctypes.c_uint64(left),
            ctypes.c_uint64(right),
            ctypes.c_uint64(base_left),
            ctypes.c_uint64(base_right),
            ctypes.c_uint64(formulas),
            ctypes.c_uint64(wire_weights),
            ctypes.c_uint64(group_zero),
            ctypes.c_uint64(group_delta),
            ctypes.c_uint64(partial),
            ctypes.c_uint32(raw_width),
            ctypes.c_uint32(left_width),
            ctypes.c_uint32(right_width),
            ctypes.c_uint32(suffix_groups),
            ctypes.c_uint32(source_nonuniform_groups),
            ctypes.c_uint32(MAX_SUFFIX),
        )
        ck(
            runtime.cuda.cuLaunchKernel(
                factored_one_claim_function,
                suffix_groups,
                1,
                1,
                THREADS,
                1,
                1,
                0,
                None,
                arguments,
                None,
            ),
            "fp16_group_message_factored_one_claim",
        )
        return reduce_partials(
            runtime, reduce_function, partial, scratch, suffix_groups
        )
    blocks = (terms + THREADS * TERMS_PER_THREAD - 1) // (
        THREADS * TERMS_PER_THREAD
    )
    arguments = kernel_arguments(
        ctypes.c_uint64(left),
        ctypes.c_uint64(right),
        ctypes.c_uint64(base_left),
        ctypes.c_uint64(base_right),
        ctypes.c_uint64(formulas),
        ctypes.c_uint64(wire_weights),
        ctypes.c_uint64(group_zero),
        ctypes.c_uint64(group_delta),
        ctypes.c_uint64(partial),
        ctypes.c_uint32(raw_width),
        ctypes.c_uint32(left_width),
        ctypes.c_uint32(right_width),
        ctypes.c_uint32(suffix_groups),
        ctypes.c_uint32(source_nonuniform_groups),
        ctypes.c_uint32(MAX_RAW),
        ctypes.c_uint32(MAX_SUFFIX),
        ctypes.c_uint32(claim_count),
    )
    ck(
        runtime.cuda.cuLaunchKernel(
            message_function,
            blocks,
            1,
            1,
            THREADS,
            1,
            1,
            0,
            None,
            arguments,
            None,
        ),
        "fp16_group_message",
    )
    return reduce_partials(runtime, reduce_function, partial, scratch, blocks)


def fp16_values(count, salt):
    values = array.array("I", [0]) * (count * 16)
    for index in range(count):
        for coordinate in range(16):
            values[16 * index + coordinate] = (
                1 + salt + 65_537 * index + 1_000_003 * coordinate
            ) % Q
    return values


def exact_b16_lookup(query):
    evaluations = lagrange_evaluations(m31_basis(), query)
    values = array.array("I", [0]) * (65_536 * 16)
    for pattern in range(1, 65_536):
        bit = (pattern & -pattern).bit_length() - 1
        prior = pattern & (pattern - 1)
        prior_offset = 16 * prior
        output_offset = 16 * pattern
        evaluation = evaluations[bit]
        for coordinate in range(16):
            values[output_offset + coordinate] = p_add(
                values[prior_offset + coordinate],
                evaluation[coordinate],
            )
    return values


def fp16_at(values, index):
    return tuple(values[16 * index : 16 * (index + 1)])


def packed_pattern(packed, wire, group):
    first = 16 * group
    word = first // 64
    shift = first & 63
    return (
        packed[wire * WORDS_PER_PLANE + word] >> shift
    ) & 65_535


def packed_byte(packed, wire, group):
    first = 8 * group
    word = first // 64
    shift = first & 63
    return (packed[wire * WORDS_PER_PLANE + word] >> shift) & 255


def expected_cubic(left_zero, left_one, right_zero, right_one, formula, e0, ed):
    left_delta = sub(left_one, left_zero)
    right_delta = sub(right_one, right_zero)
    cross = add(
        mul16(left_zero, right_delta),
        mul16(left_delta, right_zero),
    )
    product_delta = mul16(left_delta, right_delta)
    if formula == 1:
        q0 = sub(right_zero, mul16(left_zero, right_zero))
        q1 = sub(right_delta, cross)
        q2 = sub((0,) * 16, product_delta)
    elif formula == 2:
        one = (1,) + (0,) * 15
        q0 = add(
            sub(sub(one, left_zero), right_zero),
            add(mul16(left_zero, right_zero), mul16(left_zero, right_zero)),
        )
        q1 = add(
            sub(sub((0,) * 16, left_delta), right_delta),
            add(cross, cross),
        )
        q2 = add(product_delta, product_delta)
    else:
        q0 = sub(
            add(left_zero, right_zero),
            add(mul16(left_zero, right_zero), mul16(left_zero, right_zero)),
        )
        q1 = sub(
            add(left_delta, right_delta),
            add(cross, cross),
        )
        q2 = sub((0,) * 16, add(product_delta, product_delta))
    return (
        mul16(e0, q0),
        add(mul16(e0, q1), mul16(ed, q0)),
        add(mul16(e0, q2), mul16(ed, q1)),
        mul16(ed, q2),
    )


def main():
    repeats = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    claim_argument = sys.argv[2] if len(sys.argv) > 2 else "dag"
    packed_bits = int(sys.argv[3]) if len(sys.argv) > 3 else 8
    source_mode = sys.argv[4] if len(sys.argv) > 4 else "separate"
    shared_source = source_mode == "shared"
    actual_source = source_mode == "actual"
    if claim_argument == "dag":
        claim_schedule = LAYER_CLAIMS
        allocated_claims = max(claim_schedule)
    else:
        allocated_claims = int(claim_argument)
        claim_schedule = (allocated_claims,) * len(LAYERS)
    if (
        repeats < 1
        or repeats > 24
        or allocated_claims < 1
        or allocated_claims > 4
        or packed_bits not in (8, 16)
        or source_mode not in ("separate", "shared", "actual")
    ):
        raise SystemExit(
            "usage: cuda_dag_shared_group_message_benchmark.py "
            "[1..24] [dag|1..4] [8|16] [separate|shared|actual]"
        )

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
        runtime.compile(CUDA + FOLD_KERNEL + MESSAGE_KERNEL, b"packed_first_group_fold")
        compile_seconds = time.perf_counter() - compile_started
        fold_function = function(runtime, "fp16_group_fold")
        packed_message_function = function(runtime, "packed_group_message")
        b8_second_message_function = function(
            runtime, "packed_b8_second_group_message"
        )
        b8_two_group_fold_function = function(
            runtime, "packed_b8_two_group_fold"
        )
        b16_fold_function = function(runtime, "packed_b16_first_group_fold")
        b16_message_function = function(runtime, "packed_b16_group_message")
        fp16_message_function = function(runtime, "fp16_group_message")
        factored_one_claim_function = function(
            runtime, "fp16_group_message_factored_one_claim"
        )
        reduce_function = function(runtime, "reduce_cubic_partials")

        packed_words = MAX_WIDTH * WORDS_PER_PLANE
        left_packed = array.array("Q", [0]) * packed_words
        right_packed = (
            None if shared_source else array.array("Q", [0]) * packed_words
        )
        state = 0x243F6A8885A308D3
        for index in range(packed_words):
            state = (
                state * 6364136223846793005 + 1442695040888963407
            ) & ((1 << 64) - 1)
            left_packed[index] = state
            if right_packed is not None:
                state = (
                    state * 6364136223846793005 + 1442695040888963407
                ) & ((1 << 64) - 1)
                right_packed[index] = state
        left_packed_d = runtime.alloc(len(left_packed) * left_packed.itemsize)
        left_packed_size = copy(
            runtime, left_packed_d, left_packed, "copy_left_packed"
        )
        if right_packed is None:
            right_packed_d = left_packed_d
            right_packed_size = 0
        else:
            right_packed_d = runtime.alloc(
                len(right_packed) * right_packed.itemsize
            )
            right_packed_size = copy(
                runtime, right_packed_d, right_packed, "copy_right_packed"
            )

        packed_query = tuple(fp16_values(1, 17))
        lookup = (
            fp16_values(256, 17)
            if packed_bits == 8
            else exact_b16_lookup(packed_query)
        )
        challenge = fp16_values(1, 31)
        second_challenge = fp16_values(1, 37)
        wire_weights = fp16_values(allocated_claims * MAX_RAW, 43)
        group_zero = fp16_values(allocated_claims * MAX_SUFFIX, 59)
        group_delta = fp16_values(allocated_claims * MAX_SUFFIX, 71)
        lookup_d = runtime.alloc(len(lookup) * lookup.itemsize)
        challenge_d = runtime.alloc(len(challenge) * challenge.itemsize)
        second_challenge_d = runtime.alloc(
            len(second_challenge) * second_challenge.itemsize
        )
        wire_weights_d = runtime.alloc(len(wire_weights) * wire_weights.itemsize)
        group_zero_d = runtime.alloc(len(group_zero) * group_zero.itemsize)
        group_delta_d = runtime.alloc(len(group_delta) * group_delta.itemsize)
        lookup_size = copy(runtime, lookup_d, lookup, "copy_lookup")
        challenge_size = copy(runtime, challenge_d, challenge, "copy_challenge")
        second_challenge_size = copy(
            runtime,
            second_challenge_d,
            second_challenge,
            "copy_second_challenge",
        )
        wire_weight_size = copy(
            runtime, wire_weights_d, wire_weights, "copy_wire_weights"
        )
        group_zero_size = copy(
            runtime, group_zero_d, group_zero, "copy_group_zero"
        )
        group_delta_size = copy(
            runtime, group_delta_d, group_delta, "copy_group_delta"
        )

        base_left = array.array("I", [0]) * MAX_RAW
        base_right = array.array("I", [0]) * MAX_RAW
        formulas = array.array("I", [0]) * MAX_RAW
        base_left_d = runtime.alloc(len(base_left) * base_left.itemsize)
        base_right_d = runtime.alloc(len(base_right) * base_right.itemsize)
        formulas_d = runtime.alloc(len(formulas) * formulas.itemsize)

        first_fold_groups = GROUP_COUNT // 4
        main_elements = MAX_WIDTH * first_fold_groups
        scratch_elements = MAX_WIDTH * (first_fold_groups // 2)
        main_size = main_elements * FP16_BYTES
        scratch_size = scratch_elements * FP16_BYTES
        left_main_d = runtime.alloc(main_size)
        left_scratch_d = runtime.alloc(scratch_size)
        if shared_source:
            right_main_d = left_main_d
            right_scratch_d = left_scratch_d
        else:
            right_main_d = runtime.alloc(main_size)
            right_scratch_d = runtime.alloc(scratch_size)

        max_terms = MAX_RAW * MAX_SUFFIX
        max_blocks = (max_terms + THREADS * TERMS_PER_THREAD - 1) // (
            THREADS * TERMS_PER_THREAD
        )
        partial_size = max_blocks * 64 * 4
        partial_d = runtime.alloc(partial_size)
        reduction_scratch_d = runtime.alloc(partial_size)

        if packed_bits == 8:
            kat_right_packed = left_packed if right_packed is None else right_packed
            kat_raw = 3
            kat_suffix_groups = 2
            kat_claims = allocated_claims
            for output in range(kat_raw):
                base_left[output] = (3 * output + 1) % 17
                base_right[output] = (5 * output + 2) % 19
                formulas[output] = output
            copy(runtime, base_left_d, base_left, "b8_kat_copy_base_left")
            copy(runtime, base_right_d, base_right, "b8_kat_copy_base_right")
            copy(runtime, formulas_d, formulas, "b8_kat_copy_formulas")
            kat_message_d = launch_b8_second_packed_message(
                runtime,
                b8_second_message_function,
                reduce_function,
                left_packed_d,
                right_packed_d,
                lookup_d,
                challenge_d,
                base_left_d,
                base_right_d,
                formulas_d,
                wire_weights_d,
                group_zero_d,
                group_delta_d,
                partial_d,
                reduction_scratch_d,
                kat_raw,
                kat_suffix_groups,
                kat_claims,
            )
            launch_b8_two_group_fold(
                runtime,
                b8_two_group_fold_function,
                left_packed_d,
                lookup_d,
                challenge_d,
                second_challenge_d,
                left_main_d,
                3,
                2,
            )
            ck(runtime.cuda.cuCtxSynchronize(), "b8_delayed_differential_kat_sync")
            actual_message_words = array.array("I", [0]) * 64
            actual_message_view = (
                ctypes.c_ubyte
                * (len(actual_message_words) * actual_message_words.itemsize)
            ).from_buffer(actual_message_words)
            ck(
                runtime.cuda.cuMemcpyDtoH_v2(
                    ctypes.cast(actual_message_view, ctypes.c_void_p),
                    kat_message_d,
                    len(actual_message_words) * actual_message_words.itemsize,
                ),
                "b8_second_message_kat_copy",
            )
            first_group_challenge = tuple(challenge)

            def folded_pair(source, wire, first_group):
                zero = fp16_at(
                    lookup, packed_byte(source, wire, 2 * first_group)
                )
                one = fp16_at(
                    lookup, packed_byte(source, wire, 2 * first_group + 1)
                )
                return add(
                    zero,
                    mul16(first_group_challenge, sub(one, zero)),
                )

            expected_message = [(0,) * 16 for _ in range(4)]
            for suffix in range(kat_suffix_groups):
                for output in range(kat_raw):
                    left_zero = folded_pair(
                        left_packed, base_left[output], 2 * suffix
                    )
                    left_one = folded_pair(
                        left_packed, base_left[output], 2 * suffix + 1
                    )
                    right_zero = folded_pair(
                        kat_right_packed, base_right[output], 2 * suffix
                    )
                    right_one = folded_pair(
                        kat_right_packed, base_right[output], 2 * suffix + 1
                    )
                    e0 = (0,) * 16
                    ed = (0,) * 16
                    for claim in range(kat_claims):
                        wire = fp16_at(
                            wire_weights, claim * MAX_RAW + output
                        )
                        e0 = add(
                            e0,
                            mul16(
                                wire,
                                fp16_at(
                                    group_zero,
                                    claim * MAX_SUFFIX + suffix,
                                ),
                            ),
                        )
                        ed = add(
                            ed,
                            mul16(
                                wire,
                                fp16_at(
                                    group_delta,
                                    claim * MAX_SUFFIX + suffix,
                                ),
                            ),
                        )
                    cubic = expected_cubic(
                        left_zero,
                        left_one,
                        right_zero,
                        right_one,
                        formulas[output],
                        e0,
                        ed,
                    )
                    expected_message = [
                        add(total, contribution)
                        for total, contribution in zip(expected_message, cubic)
                    ]
            actual_message = [
                fp16_at(actual_message_words, coefficient)
                for coefficient in range(4)
            ]
            if actual_message != expected_message:
                raise SystemExit(
                    "b8_second_group_message_differential_kat_mismatch "
                    f"actual={actual_message} expected={expected_message}"
                )

            actual_fold_words = array.array("I", [0]) * (6 * 16)
            actual_fold_view = (
                ctypes.c_ubyte
                * (len(actual_fold_words) * actual_fold_words.itemsize)
            ).from_buffer(actual_fold_words)
            ck(
                runtime.cuda.cuMemcpyDtoH_v2(
                    ctypes.cast(actual_fold_view, ctypes.c_void_p),
                    left_main_d,
                    len(actual_fold_words) * actual_fold_words.itemsize,
                ),
                "b8_two_group_fold_kat_copy",
            )
            second_group_challenge = tuple(second_challenge)
            expected_fold = []
            for group in range(2):
                for wire in range(3):
                    zero = folded_pair(left_packed, wire, 2 * group)
                    one = folded_pair(left_packed, wire, 2 * group + 1)
                    expected_fold.append(
                        add(
                            zero,
                            mul16(
                                second_group_challenge,
                                sub(one, zero),
                            ),
                        )
                    )
            actual_fold = [
                fp16_at(actual_fold_words, index) for index in range(6)
            ]
            if actual_fold != expected_fold:
                raise SystemExit(
                    "b8_two_group_fold_differential_kat_mismatch "
                    f"actual={actual_fold} expected={expected_fold}"
                )

        if packed_bits == 16:
            kat_right_packed = left_packed if right_packed is None else right_packed
            kat_raw = 3
            kat_suffix_groups = 2
            for output in range(kat_raw):
                base_left[output] = (3 * output + 1) % 17
                base_right[output] = (5 * output + 2) % 19
                formulas[output] = output
            copy(runtime, base_left_d, base_left, "kat_copy_base_left")
            copy(runtime, base_right_d, base_right, "kat_copy_base_right")
            copy(runtime, formulas_d, formulas, "kat_copy_formulas")
            kat_message_d = launch_b16_packed_message(
                runtime,
                b16_message_function,
                reduce_function,
                left_packed_d,
                right_packed_d,
                lookup_d,
                base_left_d,
                base_right_d,
                formulas_d,
                wire_weights_d,
                group_zero_d,
                group_delta_d,
                partial_d,
                reduction_scratch_d,
                kat_raw,
                kat_suffix_groups,
                WORDS_PER_PLANE,
                1,
            )
            launch_b16_first(
                runtime,
                b16_fold_function,
                left_packed_d,
                lookup_d,
                challenge_d,
                left_main_d,
                3,
                2,
                WORDS_PER_PLANE,
            )
            ck(runtime.cuda.cuCtxSynchronize(), "b16_differential_kat_sync")
            actual_message_words = array.array("I", [0]) * 64
            actual_message_view = (
                ctypes.c_ubyte
                * (len(actual_message_words) * actual_message_words.itemsize)
            ).from_buffer(actual_message_words)
            ck(
                runtime.cuda.cuMemcpyDtoH_v2(
                    ctypes.cast(actual_message_view, ctypes.c_void_p),
                    kat_message_d,
                    len(actual_message_words) * actual_message_words.itemsize,
                ),
                "b16_message_kat_copy",
            )
            expected_message = [(0,) * 16 for _ in range(4)]
            for suffix in range(kat_suffix_groups):
                for output in range(kat_raw):
                    left_zero = fp16_at(
                        lookup,
                        packed_pattern(
                            left_packed,
                            base_left[output],
                            2 * suffix,
                        ),
                    )
                    left_one = fp16_at(
                        lookup,
                        packed_pattern(
                            left_packed,
                            base_left[output],
                            2 * suffix + 1,
                        ),
                    )
                    right_zero = fp16_at(
                        lookup,
                        packed_pattern(
                            kat_right_packed,
                            base_right[output],
                            2 * suffix,
                        ),
                    )
                    right_one = fp16_at(
                        lookup,
                        packed_pattern(
                            kat_right_packed,
                            base_right[output],
                            2 * suffix + 1,
                        ),
                    )
                    wire = fp16_at(wire_weights, output)
                    e0 = mul16(wire, fp16_at(group_zero, suffix))
                    ed = mul16(wire, fp16_at(group_delta, suffix))
                    cubic = expected_cubic(
                        left_zero,
                        left_one,
                        right_zero,
                        right_one,
                        formulas[output],
                        e0,
                        ed,
                    )
                    expected_message = [
                        add(total, contribution)
                        for total, contribution in zip(expected_message, cubic)
                    ]
            actual_message = [
                fp16_at(actual_message_words, coefficient)
                for coefficient in range(4)
            ]
            if actual_message != expected_message:
                raise SystemExit(
                    "b16_group_message_differential_kat_mismatch "
                    f"actual={actual_message} expected={expected_message}"
                )

            actual_fold_words = array.array("I", [0]) * (6 * 16)
            actual_fold_view = (
                ctypes.c_ubyte
                * (len(actual_fold_words) * actual_fold_words.itemsize)
            ).from_buffer(actual_fold_words)
            ck(
                runtime.cuda.cuMemcpyDtoH_v2(
                    ctypes.cast(actual_fold_view, ctypes.c_void_p),
                    left_main_d,
                    len(actual_fold_words) * actual_fold_words.itemsize,
                ),
                "b16_fold_kat_copy",
            )
            group_challenge = tuple(challenge)
            expected_fold = []
            for group in range(2):
                for wire in range(3):
                    zero = fp16_at(
                        lookup,
                        packed_pattern(left_packed, wire, 2 * group),
                    )
                    one = fp16_at(
                        lookup,
                        packed_pattern(left_packed, wire, 2 * group + 1),
                    )
                    expected_fold.append(
                        add(zero, mul16(group_challenge, sub(one, zero)))
                    )
            actual_fold = [
                fp16_at(actual_fold_words, index)
                for index in range(6)
            ]
            if actual_fold != expected_fold:
                raise SystemExit(
                    "b16_first_fold_differential_kat_mismatch "
                    f"actual={actual_fold} expected={expected_fold}"
                )

        message_terms = 0
        fold_values = 0
        materialized_values = 0
        layer_seconds = []
        final_message = partial_d
        started = time.perf_counter()
        for _ in range(repeats):
            for layer_index, ((left_width, right_width), raw_width) in enumerate(
                zip(LAYERS, RAW_WIDTHS)
            ):
                layer_shared = shared_source or (
                    actual_source and layer_index in (0, 1, 3, 5)
                )
                layer_right_packed_d = (
                    left_packed_d if layer_shared else right_packed_d
                )
                claim_count = claim_schedule[layer_index]
                for output in range(raw_width):
                    base_left[output] = (
                        output * 17 + 31 * layer_index
                    ) % left_width
                    base_right[output] = (
                        output * 29 + 47 * layer_index + 1
                    ) % right_width
                    if layer_index == 5:
                        formulas[output] = 1
                    elif layer_index == 6 and output % 32 == 0:
                        formulas[output] = 2
                    else:
                        formulas[output] = 0
                copy(runtime, base_left_d, base_left, "copy_base_left")
                copy(runtime, base_right_d, base_right, "copy_base_right")
                copy(runtime, formulas_d, formulas, "copy_formulas")

                layer_started = time.perf_counter()
                suffix_groups = (
                    GROUP_COUNT // 2 if packed_bits == 8 else first_fold_groups
                )
                if packed_bits == 8:
                    final_message = launch_packed_message(
                        runtime,
                        packed_message_function,
                        reduce_function,
                        left_packed_d,
                        layer_right_packed_d,
                        lookup_d,
                        base_left_d,
                        base_right_d,
                        formulas_d,
                        wire_weights_d,
                        group_zero_d,
                        group_delta_d,
                        partial_d,
                        reduction_scratch_d,
                        raw_width,
                        left_width,
                        right_width,
                        suffix_groups,
                        claim_count,
                    )
                    message_terms += raw_width * suffix_groups
                    suffix_groups = first_fold_groups
                    final_message = launch_b8_second_packed_message(
                        runtime,
                        b8_second_message_function,
                        reduce_function,
                        left_packed_d,
                        layer_right_packed_d,
                        lookup_d,
                        challenge_d,
                        base_left_d,
                        base_right_d,
                        formulas_d,
                        wire_weights_d,
                        group_zero_d,
                        group_delta_d,
                        partial_d,
                        reduction_scratch_d,
                        raw_width,
                        suffix_groups,
                        claim_count,
                    )
                else:
                    final_message = launch_b16_packed_message(
                        runtime,
                        b16_message_function,
                        reduce_function,
                        left_packed_d,
                        layer_right_packed_d,
                        lookup_d,
                        base_left_d,
                        base_right_d,
                        formulas_d,
                        wire_weights_d,
                        group_zero_d,
                        group_delta_d,
                        partial_d,
                        reduction_scratch_d,
                        raw_width,
                        suffix_groups,
                        WORDS_PER_PLANE,
                        claim_count,
                    )
                message_terms += raw_width * suffix_groups
                source_width = max(left_width, right_width) if layer_shared else 0
                if packed_bits == 8:
                    launch_b8_two_group_fold(
                        runtime,
                        b8_two_group_fold_function,
                        left_packed_d,
                        lookup_d,
                        challenge_d,
                        second_challenge_d,
                        left_main_d,
                        source_width if layer_shared else left_width,
                        suffix_groups,
                    )
                else:
                    launch_b16_first(
                        runtime,
                        b16_fold_function,
                        left_packed_d,
                        lookup_d,
                        challenge_d,
                        left_main_d,
                        source_width if layer_shared else left_width,
                        suffix_groups,
                        WORDS_PER_PLANE,
                    )
                if not layer_shared:
                    if packed_bits == 8:
                        launch_b8_two_group_fold(
                            runtime,
                            b8_two_group_fold_function,
                            right_packed_d,
                            lookup_d,
                            challenge_d,
                            second_challenge_d,
                            right_main_d,
                            right_width,
                            suffix_groups,
                        )
                    else:
                        launch_b16_first(
                            runtime,
                            b16_fold_function,
                            right_packed_d,
                            lookup_d,
                            challenge_d,
                            right_main_d,
                            right_width,
                            suffix_groups,
                            WORDS_PER_PLANE,
                        )
                fold_values += (
                    source_width if layer_shared else left_width + right_width
                ) * suffix_groups
                left_source, left_output = left_main_d, left_scratch_d
                right_source, right_output = (
                    (left_main_d, left_scratch_d)
                    if layer_shared
                    else (right_main_d, right_scratch_d)
                )
                current_groups = suffix_groups
                while current_groups > 1:
                    suffix_groups = current_groups // 2
                    final_message = launch_fp16_message(
                        runtime,
                        fp16_message_function,
                        factored_one_claim_function,
                        reduce_function,
                        left_source,
                        right_source,
                        base_left_d,
                        base_right_d,
                        formulas_d,
                        wire_weights_d,
                        group_zero_d,
                        group_delta_d,
                        partial_d,
                        reduction_scratch_d,
                        raw_width,
                        source_width if layer_shared else left_width,
                        source_width if layer_shared else right_width,
                        suffix_groups,
                        current_groups,
                        claim_count,
                    )
                    message_terms += raw_width * suffix_groups
                    launch_fold(
                        runtime,
                        fold_function,
                        left_source,
                        challenge_d,
                        left_output,
                        source_width if layer_shared else left_width,
                        suffix_groups,
                    )
                    if not layer_shared:
                        launch_fold(
                            runtime,
                            fold_function,
                            right_source,
                            challenge_d,
                            right_output,
                            right_width,
                            suffix_groups,
                        )
                    fold_values += (
                        source_width if layer_shared else left_width + right_width
                    ) * suffix_groups
                    left_source, left_output = left_output, left_source
                    right_source, right_output = right_output, right_source
                    current_groups = suffix_groups
                ck(runtime.cuda.cuCtxSynchronize(), "layer_message_and_fold_sync")
                layer_seconds.append(time.perf_counter() - layer_started)
        total_seconds = time.perf_counter() - started

        sample = (ctypes.c_uint32 * 64)()
        ck(
            runtime.cuda.cuMemcpyDtoH_v2(
                ctypes.cast(sample, ctypes.c_void_p),
                final_message,
                ctypes.sizeof(sample),
            ),
            "copy_message_sample",
        )
        if not any(sample):
            raise SystemExit("message_sample_zero")
        device_working_set = (
            left_packed_size
            + right_packed_size
            + lookup_size
            + challenge_size
            + second_challenge_size
            + wire_weight_size
            + group_zero_size
            + group_delta_size
            + 3 * MAX_RAW * 4
            + (1 if shared_source else 2) * main_size
            + (1 if shared_source else 2) * scratch_size
            + 2 * partial_size
        )
        ordered = sorted(layer_seconds)
        print(f"repeats={repeats}")
        print(f"packed_bits={packed_bits}")
        print(f"source_mode={source_mode}")
        print(f"claim_schedule={','.join(map(str, claim_schedule))}")
        print(f"group_count={GROUP_COUNT if packed_bits == 8 else GROUP_COUNT // 2}")
        print(f"layers={len(LAYERS) * repeats}")
        print(f"group_message_terms={message_terms}")
        print(f"fp16_group_folds={fold_values}")
        print(f"fp16_materialized_values={materialized_values}")
        print(f"b8_delayed_materialization={str(packed_bits == 8).lower()}")
        print(f"b16_differential_kat={str(packed_bits == 16).lower()}")
        print(f"b8_delayed_differential_kat={str(packed_bits == 8).lower()}")
        print(f"compile_seconds={compile_seconds:.6f}")
        print(f"kernel_total_seconds={total_seconds:.6f}")
        print(f"group_message_terms_per_second={message_terms / total_seconds:.3f}")
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
