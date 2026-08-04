"""Exact K128 B=16 binary-gate bridge in the frozen M31/Fp16 field.

This closes the operation omitted by the earlier split-packed timing screen:
it accumulates every claim, reconstructs the degree-30 binary-gate relation,
multiplies it by the degree-15 packed equality selector, and emits all 46
coefficients of the required degree-45 message before a challenge.

The CUDA result is checked against an independent CPU calculation on a small
fixture. The production-geometry run uses the exact seven-layer widths, claim
schedule, gate formulas, and B=16 group count with deterministic synthetic
public wiring and weights. It is nonactivating and is not a complete proof.
"""

import array
import ctypes
import os
import sys
import time
from pathlib import Path

from cuda_dag_packed_accumulator_benchmark import copy, process_peak_mb
from cuda_fp16_tower_kat import (
    CUDA,
    Q,
    Runtime,
    add,
    ck,
    mul16,
    p_add,
    p_mul,
    p_sub,
    sub,
)


KERNEL = (
    CUDA
    + r"""
__device__ __forceinline__ F16 a16(F16 x,F16 y){return {a8(x.a,y.a),a8(x.b,y.b)};}
__device__ __forceinline__ F16 s16(F16 x,F16 y){return {s8(x.a,y.a),s8(x.b,y.b)};}
__device__ __forceinline__ F16 z16(){F16 value={};return value;}
__device__ __forceinline__ F16 n16(F16 x){return s16(z16(),x);}
__device__ __forceinline__ F16 d16(F16 x){return a16(x,x);}

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

__device__ __forceinline__ void atomic_f16(
    unsigned int *low,
    unsigned int *carry,
    unsigned long long offset,
    F16 value
) {
    unsigned int coordinates[16];
    st16(coordinates, value);
    #pragma unroll
    for (unsigned int coordinate = 0; coordinate < 16U; ++coordinate) {
        unsigned int addend = coordinates[coordinate];
        unsigned int prior = atomicAdd(low + offset + coordinate, addend);
        if (prior > 0xffffffffU - addend) {
            atomicAdd(carry + offset + coordinate, 1U);
        }
    }
}

__device__ __forceinline__ void atomic_f16_u64(
    unsigned long long *destination,
    unsigned long long offset,
    F16 value
) {
    unsigned int coordinates[16];
    st16(coordinates, value);
    #pragma unroll
    for (unsigned int coordinate = 0; coordinate < 16U; ++coordinate) {
        atomicAdd(destination + offset + coordinate, (unsigned long long)coordinates[coordinate]);
    }
}

extern "C" __global__ void accumulate_b16_binary_bridge(
    const unsigned long long *left_packed,
    const unsigned long long *right_packed,
    const unsigned int *wire_weights,
    const unsigned int *group_weights,
    const unsigned int *base_left,
    const unsigned int *base_right,
    const unsigned int *formulas,
    unsigned long long *product_sum,
    unsigned int *linear_low,
    unsigned int *linear_carry,
    unsigned int *constant_low,
    unsigned int *constant_carry,
    unsigned int raw_width,
    unsigned int group_count,
    unsigned int words_per_wire,
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
    unsigned int output = term - group * raw_width;
    unsigned int left_pattern = packed16(
        left_packed, base_left[output], group, words_per_wire
    );
    unsigned int right_pattern = packed16(
        right_packed, base_right[output], group, words_per_wire
    );
    unsigned int left_bytes[2] = {left_pattern & 255U, left_pattern >> 8};
    unsigned int right_bytes[2] = {right_pattern & 255U, right_pattern >> 8};
    unsigned int formula = formulas[output];

    {
        F16 weight = m16(
            l16(wire_weights + 16ULL * (claim * max_raw + output)),
            l16(group_weights + 16ULL * (claim * max_groups + group))
        );
        F16 product_weight;
        F16 left_weight = z16();
        F16 right_weight = z16();
        F16 constant_weight = z16();
        if (formula == 1U) {
            product_weight = n16(weight);
            right_weight = weight;
        } else if (formula == 2U) {
            product_weight = d16(weight);
            left_weight = n16(weight);
            right_weight = n16(weight);
            constant_weight = weight;
        } else {
            product_weight = n16(d16(weight));
            left_weight = weight;
            right_weight = weight;
        }

        for (unsigned int left_chunk = 0; left_chunk < 2U; ++left_chunk) {
            for (unsigned int right_chunk = 0; right_chunk < 2U; ++right_chunk) {
                unsigned int table = 2U * left_chunk + right_chunk;
                unsigned int bucket =
                    256U * left_bytes[left_chunk] + right_bytes[right_chunk];
                atomic_f16_u64(
                    product_sum,
                    16ULL * ((claim * 4ULL + table) * 65536ULL + bucket),
                    product_weight
                );
            }
        }
        for (unsigned int chunk = 0; chunk < 2U; ++chunk) {
            if (formula != 1U) {
                atomic_f16(
                    linear_low,
                    linear_carry,
                    16ULL * (
                        (claim * 4ULL + chunk) * 256ULL + left_bytes[chunk]
                    ),
                    left_weight
                );
            }
            atomic_f16(
                linear_low,
                linear_carry,
                16ULL * (
                    (claim * 4ULL + 2ULL + chunk) * 256ULL + right_bytes[chunk]
                ),
                right_weight
            );
        }
        if (formula == 2U) {
            atomic_f16(
                constant_low, constant_carry, 16ULL * claim, constant_weight
            );
        }
    }
}

extern "C" __global__ void materialize_b16_term_weights(
    const unsigned int *wire_weights,
    const unsigned int *group_weights,
    unsigned int *term_weights,
    unsigned int raw_width,
    unsigned int tile_groups,
    unsigned int group_offset,
    unsigned int max_raw,
    unsigned int max_groups,
    unsigned int claim_count
) {
    unsigned int index = blockIdx.x * blockDim.x + threadIdx.x;
    unsigned int tile_terms = raw_width * tile_groups;
    unsigned int count = claim_count * tile_terms;
    if (index >= count) return;
    unsigned int claim = index / tile_terms;
    unsigned int term = index - claim * tile_terms;
    unsigned int group = term / raw_width;
    unsigned int output = term - group * raw_width;
    st16(
        term_weights + 16ULL * index,
        m16(
            l16(wire_weights + 16ULL * (claim * max_raw + output)),
            l16(
                group_weights
                    + 16ULL * (claim * max_groups + group_offset + group)
            )
        )
    );
}

extern "C" __global__ void accumulate_b16_bridge_coordinates(
    const unsigned long long *left_packed,
    const unsigned long long *right_packed,
    const unsigned int *term_weights,
    const unsigned int *base_left,
    const unsigned int *base_right,
    const unsigned int *formulas,
    unsigned long long *product_sum,
    unsigned int *linear_low,
    unsigned int *linear_carry,
    unsigned int *constant_low,
    unsigned int *constant_carry,
    unsigned int raw_width,
    unsigned int tile_groups,
    unsigned int group_offset,
    unsigned int words_per_wire,
    unsigned int claim_count
) {
    unsigned int index = blockIdx.x * blockDim.x + threadIdx.x;
    unsigned int tile_terms = raw_width * tile_groups;
    unsigned int scalar_count = claim_count * tile_terms * 16U;
    if (index >= scalar_count) return;
    unsigned int coordinate = index & 15U;
    unsigned int claim_term = index >> 4;
    unsigned int claim = claim_term / tile_terms;
    unsigned int term = claim_term - claim * tile_terms;
    unsigned int local_group = term / raw_width;
    unsigned int output = term - local_group * raw_width;
    unsigned int group = group_offset + local_group;
    unsigned int left_pattern = packed16(
        left_packed, base_left[output], group, words_per_wire
    );
    unsigned int right_pattern = packed16(
        right_packed, base_right[output], group, words_per_wire
    );
    unsigned int left_bytes[2] = {left_pattern & 255U, left_pattern >> 8};
    unsigned int right_bytes[2] = {right_pattern & 255U, right_pattern >> 8};
    unsigned int formula = formulas[output];
    unsigned int weight = term_weights[16ULL * claim_term + coordinate];
    unsigned int negative = weight == 0U ? 0U : 2147483647U - weight;
    unsigned int doubled = addp(weight, weight);
    unsigned int product_weight =
        formula == 1U ? negative : (formula == 2U ? doubled : subp(0U, doubled));
    unsigned int left_weight =
        formula == 1U ? 0U : (formula == 2U ? negative : weight);
    unsigned int right_weight =
        formula == 2U ? negative : weight;

    for (unsigned int left_chunk = 0; left_chunk < 2U; ++left_chunk) {
        for (unsigned int right_chunk = 0; right_chunk < 2U; ++right_chunk) {
            unsigned int table = 2U * left_chunk + right_chunk;
            unsigned int bucket =
                256U * left_bytes[left_chunk] + right_bytes[right_chunk];
            atomicAdd(
                product_sum
                    + 16ULL * ((claim * 4ULL + table) * 65536ULL + bucket)
                    + coordinate,
                (unsigned long long)product_weight
            );
        }
    }
    for (unsigned int chunk = 0; chunk < 2U; ++chunk) {
        if (formula != 1U) {
            unsigned long long offset =
                16ULL * ((claim * 4ULL + chunk) * 256ULL + left_bytes[chunk])
                + coordinate;
            unsigned int prior = atomicAdd(linear_low + offset, left_weight);
            if (prior > 0xffffffffU - left_weight) {
                atomicAdd(linear_carry + offset, 1U);
            }
        }
        unsigned long long offset =
            16ULL * (
                (claim * 4ULL + 2ULL + chunk) * 256ULL + right_bytes[chunk]
            ) + coordinate;
        unsigned int prior = atomicAdd(linear_low + offset, right_weight);
        if (prior > 0xffffffffU - right_weight) {
            atomicAdd(linear_carry + offset, 1U);
        }
    }
    if (formula == 2U) {
        unsigned long long offset = 16ULL * claim + coordinate;
        unsigned int prior = atomicAdd(constant_low + offset, weight);
        if (prior > 0xffffffffU - weight) {
            atomicAdd(constant_carry + offset, 1U);
        }
    }
}

extern "C" __global__ void accumulate_b16_bridge_fused_shared(
    const unsigned long long *left_packed,
    const unsigned long long *right_packed,
    const unsigned int *wire_weights,
    const unsigned int *group_weights,
    const unsigned int *tail_group_weights,
    const unsigned int *base_left,
    const unsigned int *base_right,
    const unsigned int *formulas,
    unsigned long long *product_sum,
    unsigned int *constant_low,
    unsigned int *constant_carry,
    unsigned int raw_width,
    unsigned int tile_groups,
    unsigned int group_offset,
    unsigned int words_per_wire,
    unsigned int max_raw,
    unsigned int max_groups,
    unsigned int dense_groups,
    unsigned int claim_count
) {
    __shared__ unsigned int weights[128 * 16];
    __shared__ unsigned int left_patterns[128];
    __shared__ unsigned int right_patterns[128];
    __shared__ unsigned int gate_formulas[128];

    unsigned int tile_terms = raw_width * tile_groups;
    unsigned int count = claim_count * tile_terms;
    unsigned int local = threadIdx.x;
    unsigned int index = blockIdx.x * blockDim.x + local;
    bool active = index < count;
    unsigned int claim = 0U;
    unsigned int term = 0U;
    unsigned int output = 0U;
    unsigned int group = 0U;
    F16 weight = z16();
    if (active) {
        claim = index / tile_terms;
        term = index - claim * tile_terms;
        unsigned int local_group = term / raw_width;
        output = term - local_group * raw_width;
        group = group_offset + local_group;
        F16 group_weight =
            dense_groups < max_groups && group == dense_groups
                ? l16(tail_group_weights + 16ULL * claim)
                : l16(group_weights + 16ULL * (claim * max_groups + group));
        weight = m16(
            l16(wire_weights + 16ULL * (claim * max_raw + output)),
            group_weight
        );
        left_patterns[local] = packed16(
            left_packed, base_left[output], group, words_per_wire
        );
        right_patterns[local] = packed16(
            right_packed, base_right[output], group, words_per_wire
        );
        gate_formulas[local] = formulas[output];
    } else {
        left_patterns[local] = 0U;
        right_patterns[local] = 0U;
        gate_formulas[local] = 0U;
    }
    st16(weights + 16U * local, weight);
    __syncthreads();

    unsigned int coordinate = local & 15U;
    unsigned int first_term = local >> 4U;
    #pragma unroll
    for (unsigned int batch = 0U; batch < 16U; ++batch) {
        unsigned int block_term = first_term + 8U * batch;
        unsigned int global_term = blockIdx.x * blockDim.x + block_term;
        if (global_term >= count) continue;
        unsigned int scalar_claim = global_term / tile_terms;
        unsigned int scalar = weights[16U * block_term + coordinate];
        unsigned int negative =
            scalar == 0U ? 0U : 2147483647U - scalar;
        unsigned int doubled = addp(scalar, scalar);
        unsigned int formula = gate_formulas[block_term];
        unsigned int product_weight = formula == 1U
            ? negative
            : (formula == 2U ? doubled : subp(0U, doubled));
        unsigned int left_pattern = left_patterns[block_term];
        unsigned int right_pattern = right_patterns[block_term];
        unsigned int left_bytes[2] = {
            left_pattern & 255U, left_pattern >> 8
        };
        unsigned int right_bytes[2] = {
            right_pattern & 255U, right_pattern >> 8
        };

        #pragma unroll
        for (unsigned int left_chunk = 0U; left_chunk < 2U; ++left_chunk) {
            #pragma unroll
            for (
                unsigned int right_chunk = 0U;
                right_chunk < 2U;
                ++right_chunk
            ) {
                unsigned int table = 2U * left_chunk + right_chunk;
                unsigned int bucket =
                    256U * left_bytes[left_chunk] + right_bytes[right_chunk];
                atomicAdd(
                    product_sum
                        + 16ULL * (
                            (scalar_claim * 4ULL + table) * 65536ULL + bucket
                        )
                        + coordinate,
                    (unsigned long long)product_weight
                );
            }
        }
        if (formula == 2U) {
            unsigned long long offset =
                16ULL * scalar_claim + coordinate;
            unsigned int prior =
                atomicAdd(constant_low + offset, scalar);
            if (prior > 0xffffffffU - scalar) {
                atomicAdd(constant_carry + offset, 1U);
            }
        }
    }
}

extern "C" __global__ void product_left_transform(
    const unsigned long long *product_sum,
    const unsigned int *basis,
    unsigned int *temporary,
    unsigned int claim_count,
    unsigned int block_offset
) {
    unsigned int global_block = block_offset + blockIdx.x;
    unsigned int right_byte = global_block & 255U;
    unsigned int packed = global_block >> 8;
    unsigned int left_coefficient = packed % 17U;
    packed /= 17U;
    unsigned int table = packed & 3U;
    unsigned int claim = packed >> 2;
    if (claim >= claim_count) return;
    unsigned int left_byte = threadIdx.x;
    unsigned int left_chunk = table >> 1;
    unsigned int scalar = left_coefficient == 16U
        ? 1U
        : basis[
            16ULL * (left_chunk * 256ULL + left_byte) + left_coefficient
        ];
    unsigned long long source_offset = 16ULL * (
        (claim * 4ULL + table) * 65536ULL
        + 256ULL * left_byte
        + right_byte
    );
    __shared__ unsigned int sums[256 * 16];
    unsigned int *slot = sums + 16U * threadIdx.x;
    #pragma unroll
    for (unsigned int coordinate = 0; coordinate < 16U; ++coordinate) {
        slot[coordinate] = mulp(
            (unsigned int)(product_sum[source_offset + coordinate] % 2147483647ULL),
            scalar
        );
    }
    __syncthreads();
    for (unsigned int stride = 128U; stride > 0U; stride >>= 1U) {
        if (threadIdx.x < stride) {
            unsigned int *other = sums + 16U * (threadIdx.x + stride);
            #pragma unroll
            for (unsigned int coordinate = 0; coordinate < 16U; ++coordinate) {
                slot[coordinate] = addp(slot[coordinate], other[coordinate]);
            }
        }
        __syncthreads();
    }
    if (threadIdx.x == 0U) {
        unsigned int *destination = temporary
            + 16ULL * (
                ((claim * 4ULL + table) * 17ULL + left_coefficient) * 256ULL
                + right_byte
            );
        #pragma unroll
        for (unsigned int coordinate = 0; coordinate < 16U; ++coordinate) {
            destination[coordinate] = sums[coordinate];
        }
    }
}

extern "C" __global__ void product_right_transform(
    const unsigned int *temporary,
    const unsigned int *basis,
    unsigned int *matrix,
    unsigned int claim_count,
    unsigned int block_offset
) {
    unsigned int global_block = block_offset + blockIdx.x;
    unsigned int right_coefficient = global_block % 17U;
    unsigned int packed = global_block / 17U;
    unsigned int left_coefficient = packed % 17U;
    packed /= 17U;
    unsigned int table = packed & 3U;
    unsigned int claim = packed >> 2;
    if (claim >= claim_count) return;
    unsigned int right_byte = threadIdx.x;
    unsigned int right_chunk = table & 1U;
    unsigned int scalar = right_coefficient == 16U
        ? 1U
        : basis[
            16ULL * (right_chunk * 256ULL + right_byte) + right_coefficient
        ];
    const unsigned int *source = temporary
        + 16ULL * (
            ((claim * 4ULL + table) * 17ULL + left_coefficient) * 256ULL
            + right_byte
        );
    __shared__ unsigned int sums[256 * 16];
    unsigned int *slot = sums + 16U * threadIdx.x;
    #pragma unroll
    for (unsigned int coordinate = 0; coordinate < 16U; ++coordinate) {
        slot[coordinate] = mulp(source[coordinate], scalar);
    }
    __syncthreads();
    for (unsigned int stride = 128U; stride > 0U; stride >>= 1U) {
        if (threadIdx.x < stride) {
            unsigned int *other = sums + 16U * (threadIdx.x + stride);
            #pragma unroll
            for (unsigned int coordinate = 0; coordinate < 16U; ++coordinate) {
                slot[coordinate] = addp(slot[coordinate], other[coordinate]);
            }
        }
        __syncthreads();
    }
    if (threadIdx.x == 0U) {
        unsigned int *destination = matrix
            + 16ULL * (
                ((claim * 4ULL + table) * 17ULL + left_coefficient) * 17ULL
                + right_coefficient
            );
        #pragma unroll
        for (unsigned int coordinate = 0; coordinate < 16U; ++coordinate) {
            destination[coordinate] = sums[coordinate];
        }
    }
}

extern "C" __global__ void linear_transform(
    const unsigned int *linear_low,
    const unsigned int *linear_carry,
    const unsigned int *basis,
    unsigned int *coefficients,
    unsigned int claim_count
) {
    unsigned int coefficient = blockIdx.x & 15U;
    unsigned int packed = blockIdx.x >> 4;
    unsigned int table = packed & 3U;
    unsigned int claim = packed >> 2;
    if (claim >= claim_count) return;
    unsigned int byte = threadIdx.x;
    unsigned int chunk = table & 1U;
    unsigned int scalar = basis[
        16ULL * (chunk * 256ULL + byte) + coefficient
    ];
    unsigned long long source_offset =
        16ULL * ((claim * 4ULL + table) * 256ULL + byte);
    __shared__ unsigned int sums[256 * 16];
    unsigned int *slot = sums + 16U * threadIdx.x;
    #pragma unroll
    for (unsigned int coordinate = 0; coordinate < 16U; ++coordinate) {
        slot[coordinate] = mulp(
            (unsigned int)(
                (
                    (unsigned long long)linear_low[source_offset + coordinate]
                    + 2ULL * linear_carry[source_offset + coordinate]
                ) % 2147483647ULL
            ),
            scalar
        );
    }
    __syncthreads();
    for (unsigned int stride = 128U; stride > 0U; stride >>= 1U) {
        if (threadIdx.x < stride) {
            unsigned int *other = sums + 16U * (threadIdx.x + stride);
            #pragma unroll
            for (unsigned int coordinate = 0; coordinate < 16U; ++coordinate) {
                slot[coordinate] = addp(slot[coordinate], other[coordinate]);
            }
        }
        __syncthreads();
    }
    if (threadIdx.x == 0U) {
        unsigned int *destination = coefficients
            + 16ULL * ((claim * 4ULL + table) * 16ULL + coefficient);
        #pragma unroll
        for (unsigned int coordinate = 0; coordinate < 16U; ++coordinate) {
            destination[coordinate] = sums[coordinate];
        }
    }
}

extern "C" __global__ void assemble_relation(
    const unsigned int *matrix,
    const unsigned int *constant_low,
    const unsigned int *constant_carry,
    unsigned int *relation,
    unsigned int claim_count,
    unsigned int formula_family
) {
    unsigned int coefficient = blockIdx.x % 31U;
    unsigned int claim = blockIdx.x / 31U;
    unsigned int coordinate = threadIdx.x;
    if (claim >= claim_count || coordinate >= 16U) return;
    unsigned int value = 0U;
    for (unsigned int table = 0; table < 4U; ++table) {
        for (unsigned int left = 0; left < 16U; ++left) {
            if (coefficient < left || coefficient - left >= 16U) continue;
            unsigned int right = coefficient - left;
            value = addp(
                value,
                matrix[
                    16ULL * (
                        ((claim * 4ULL + table) * 17ULL + left) * 17ULL
                        + right
                    )
                    + coordinate
                ]
            );
        }
    }
    if (coefficient < 16U) {
        unsigned int left_marginal = addp(
            matrix[
                16ULL * (
                    ((claim * 4ULL) * 17ULL + coefficient) * 17ULL + 16ULL
                )
                + coordinate
            ],
            matrix[
                16ULL * (
                    ((claim * 4ULL + 2ULL) * 17ULL + coefficient) * 17ULL
                    + 16ULL
                )
                + coordinate
            ]
        );
        unsigned int right_marginal = addp(
            matrix[
                16ULL * (
                    ((claim * 4ULL) * 17ULL + 16ULL) * 17ULL + coefficient
                )
                + coordinate
            ],
            matrix[
                16ULL * (
                    ((claim * 4ULL + 1ULL) * 17ULL + 16ULL) * 17ULL
                    + coefficient
                )
                + coordinate
            ]
        );
        if (formula_family == 1U) {
            value = subp(value, right_marginal);
        } else {
            const unsigned int NEGATIVE_INVERSE_TWO = 1073741823U;
            value = addp(
                value,
                mulp(
                    addp(left_marginal, right_marginal),
                    NEGATIVE_INVERSE_TWO
                )
            );
        }
    }
    if (coefficient == 0U && formula_family == 0U) {
        value = addp(
            value,
            (unsigned int)(
                (
                    (unsigned long long)constant_low[16ULL * claim + coordinate]
                    + 2ULL * constant_carry[16ULL * claim + coordinate]
                ) % 2147483647ULL
            )
        );
    }
    relation[16ULL * (claim * 31ULL + coefficient) + coordinate] = value;
}

extern "C" __global__ void compose_degree45_message(
    const unsigned int *relation,
    const unsigned int *selectors,
    unsigned int *message,
    unsigned int claim_count
) {
    unsigned int output_coefficient = blockIdx.x;
    F16 total = z16();
    unsigned int pair_count = claim_count * 31U;
    for (unsigned int pair = threadIdx.x; pair < pair_count; pair += blockDim.x) {
        unsigned int claim = pair / 31U;
        unsigned int relation_coefficient = pair - 31U * claim;
        if (
            output_coefficient >= relation_coefficient
            && output_coefficient - relation_coefficient < 16U
        ) {
            unsigned int selector_coefficient =
                output_coefficient - relation_coefficient;
            total = a16(
                total,
                m16(
                    l16(relation + 16ULL * (claim * 31ULL + relation_coefficient)),
                    l16(selectors + 16ULL * (claim * 16ULL + selector_coefficient))
                )
            );
        }
    }
    __shared__ unsigned int sums[128 * 16];
    unsigned int *slot = sums + 16U * threadIdx.x;
    st16(slot, total);
    __syncthreads();
    for (unsigned int stride = 64U; stride > 0U; stride >>= 1U) {
        if (threadIdx.x < stride) {
            unsigned int *other = sums + 16U * (threadIdx.x + stride);
            #pragma unroll
            for (unsigned int coordinate = 0; coordinate < 16U; ++coordinate) {
                slot[coordinate] = addp(slot[coordinate], other[coordinate]);
            }
        }
        __syncthreads();
    }
    if (threadIdx.x == 0U) {
        #pragma unroll
        for (unsigned int coordinate = 0; coordinate < 16U; ++coordinate) {
            message[16ULL * output_coefficient + coordinate] = sums[coordinate];
        }
    }
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
CLAIM_SCHEDULE = (2, 1, 2, 1, 3, 1, 4)
PACKED_INSTANCES = 131_072
GROUP_COUNT = PACKED_INSTANCES // 16
WORDS_PER_WIRE = PACKED_INSTANCES // 64
MAX_WIDTH = 2_048
MAX_RAW = 1_600
MAX_CLAIMS = max(CLAIM_SCHEDULE)
THREADS = 256
FP16_MB = 0.000064


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
    result = (ctypes.c_void_p * len(values))(
        *(ctypes.cast(ctypes.byref(value), ctypes.c_void_p) for value in values)
    )
    result._keepalive = values
    return result


def launch(runtime, fn, blocks, threads, params, label):
    ck(
        runtime.cuda.cuLaunchKernel(
            fn, blocks, 1, 1, threads, 1, 1, 0, None, params, None
        ),
        label,
    )


PRODUCT_LEFT_TILE_BLOCKS = 512
PRODUCT_RIGHT_TILE_BLOCKS = 256


def m31_basis():
    basis = [[0] * 16 for _ in range(16)]
    for point in range(16):
        polynomial = [0] * 16
        polynomial[0] = 1
        degree = 0
        denominator = 1
        for other in range(16):
            if other == point:
                continue
            for coefficient in range(degree, -1, -1):
                polynomial[coefficient + 1] = p_add(
                    polynomial[coefficient + 1], polynomial[coefficient]
                )
                polynomial[coefficient] = p_mul(
                    polynomial[coefficient], (-other) % Q
                )
            degree += 1
            denominator = p_mul(denominator, (point - other) % Q)
        inverse = pow(denominator, Q - 2, Q)
        basis[point] = [p_mul(value, inverse) for value in polynomial]
    return basis


def chunk_basis_table(basis):
    table = array.array("I", [0]) * (2 * 256 * 16)
    for chunk in range(2):
        for byte in range(256):
            for bit in range(8):
                if (byte >> bit) & 1 == 0:
                    continue
                position = 8 * chunk + bit
                for coefficient in range(16):
                    index = 16 * (256 * chunk + byte) + coefficient
                    table[index] = p_add(table[index], basis[position][coefficient])
    return table


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


def scalar_mul(value, scalar):
    return tuple(p_mul(coordinate, scalar) for coordinate in value)


def lagrange_evaluations(basis, query):
    evaluations = []
    for point in range(16):
        numerator = (1,) + (0,) * 15
        denominator = 1
        for other in range(16):
            if other == point:
                continue
            node = (other,) + (0,) * 15
            numerator = mul16(numerator, sub(query, node))
            denominator = p_mul(denominator, (point - other) % Q)
        evaluations.append(scalar_mul(numerator, pow(denominator, Q - 2, Q)))
    return evaluations


def selector_table(basis, queries):
    selectors = array.array("I")
    for query in queries:
        evaluations = lagrange_evaluations(basis, query)
        coefficients = [(0,) * 16 for _ in range(16)]
        for position in range(16):
            for coefficient in range(16):
                coefficients[coefficient] = add(
                    coefficients[coefficient],
                    scalar_mul(evaluations[position], basis[position][coefficient]),
                )
        for coefficient in coefficients:
            selectors.extend(coefficient)
    return selectors


def pattern_polynomial(basis, pattern):
    result = [0] * 16
    for position in range(16):
        if (pattern >> position) & 1 == 0:
            continue
        for coefficient in range(16):
            result[coefficient] = p_add(
                result[coefficient], basis[position][coefficient]
            )
    return result


def polynomial_product(left, right):
    result = [0] * 31
    for left_index, left_value in enumerate(left):
        for right_index, right_value in enumerate(right):
            result[left_index + right_index] = p_add(
                result[left_index + right_index],
                p_mul(left_value, right_value),
            )
    return result


def gate_relation(basis, formula, left_pattern, right_pattern):
    left = pattern_polynomial(basis, left_pattern)
    right = pattern_polynomial(basis, right_pattern)
    product = polynomial_product(left, right)
    result = [0] * 31
    if formula == 1:
        result[:16] = right
        for coefficient in range(31):
            result[coefficient] = p_sub(result[coefficient], product[coefficient])
    elif formula == 2:
        result[0] = 1
        for coefficient in range(16):
            result[coefficient] = p_sub(
                p_sub(result[coefficient], left[coefficient]), right[coefficient]
            )
        for coefficient in range(31):
            result[coefficient] = p_add(
                result[coefficient],
                p_add(product[coefficient], product[coefficient]),
            )
    else:
        for coefficient in range(16):
            result[coefficient] = p_add(left[coefficient], right[coefficient])
        for coefficient in range(31):
            result[coefficient] = p_sub(
                result[coefficient],
                p_add(product[coefficient], product[coefficient]),
            )
    return result


def packed16(packed, wire, group):
    first = 16 * group
    word = first // 64
    shift = first % 64
    return (
        packed[wire * WORDS_PER_WIRE + word] >> shift
    ) & 65_535


def expected_message(
    basis,
    packed,
    base_left,
    base_right,
    formulas,
    wire_weights,
    group_weights,
    raw_width,
    groups,
    claims,
    selectors,
):
    relations = [[(0,) * 16 for _ in range(31)] for _ in range(claims)]
    for group in range(groups):
        for output in range(raw_width):
            relation = gate_relation(
                basis,
                formulas[output],
                packed16(packed, base_left[output], group),
                packed16(packed, base_right[output], group),
            )
            for claim in range(claims):
                weight = mul16(
                    fp16_at(wire_weights, claim * MAX_RAW + output),
                    fp16_at(group_weights, claim * GROUP_COUNT + group),
                )
                for coefficient in range(31):
                    relations[claim][coefficient] = add(
                        relations[claim][coefficient],
                        scalar_mul(weight, relation[coefficient]),
                    )
    message = [(0,) * 16 for _ in range(46)]
    for claim in range(claims):
        for relation_coefficient in range(31):
            for selector_coefficient in range(16):
                output = relation_coefficient + selector_coefficient
                message[output] = add(
                    message[output],
                    mul16(
                        relations[claim][relation_coefficient],
                        selectors[claim][selector_coefficient],
                    ),
                )
    return message


def read_message(runtime, message_d):
    words = array.array("I", [0]) * (46 * 16)
    view = (ctypes.c_ubyte * (len(words) * words.itemsize)).from_buffer(words)
    ck(
        runtime.cuda.cuMemcpyDtoH_v2(
            ctypes.cast(view, ctypes.c_void_p),
            message_d,
            len(words) * words.itemsize,
        ),
        "copy_degree45_message",
    )
    return [tuple(words[16 * index : 16 * (index + 1)]) for index in range(46)]


def main():
    repeats = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    accumulation_mode = sys.argv[2] if len(sys.argv) > 2 else "direct"
    if repeats < 1 or repeats > 5 or accumulation_mode not in (
        "direct",
        "tiled",
        "fused",
    ):
        raise SystemExit(
            "usage: cuda_fp16_b16_binary_bridge_benchmark.py "
            "[1..5] [direct|tiled|fused]"
        )

    nvrtc = Path(
        os.environ.get(
            "BL_NVRTC_BIN",
            Path(__file__).parent / "cuda_nvrtc" / "nvidia" / "cuda_nvrtc" / "bin",
        )
    )
    if not (nvrtc / "nvrtc64_120_0.dll").is_file():
        raise SystemExit("nvrtc_runtime_missing")

    basis = m31_basis()
    basis_table = chunk_basis_table(basis)
    queries = [fp16_at(fp16_values(1, 101 + 37 * claim), 0) for claim in range(MAX_CLAIMS)]
    selectors_by_claim = [
        [tuple(selector_table(basis, [query])[16 * coefficient : 16 * (coefficient + 1)])
         for coefficient in range(16)]
        for query in queries
    ]
    selectors = selector_table(basis, queries)

    packed_words = MAX_WIDTH * WORDS_PER_WIRE
    packed = array.array("Q", [0]) * packed_words
    state = 0x243F6A8885A308D3
    for index in range(packed_words):
        state = (
            state * 6_364_136_223_846_793_005 + 1_442_695_040_888_963_407
        ) & ((1 << 64) - 1)
        packed[index] = state

    wire_weights = fp16_values(MAX_CLAIMS * MAX_RAW, 211)
    group_weights = fp16_values(MAX_CLAIMS * GROUP_COUNT, 307)
    base_left = array.array("I", [0]) * MAX_RAW
    base_right = array.array("I", [0]) * MAX_RAW
    formulas = array.array("I", [0]) * MAX_RAW

    product_plane_size = MAX_CLAIMS * 4 * 65_536 * 16 * 4
    linear_plane_size = MAX_CLAIMS * 4 * 256 * 16 * 4
    constant_plane_size = MAX_CLAIMS * 16 * 4
    temporary_size = MAX_CLAIMS * 4 * 17 * 256 * 16 * 4
    matrix_size = MAX_CLAIMS * 4 * 17 * 17 * 16 * 4
    linear_coefficients_size = MAX_CLAIMS * 4 * 16 * 16 * 4
    relation_size = MAX_CLAIMS * 31 * 16 * 4
    message_size = 46 * 16 * 4

    runtime = Runtime(nvrtc)
    runtime.cuda.cuMemsetD8_v2.argtypes = [
        ctypes.c_uint64,
        ctypes.c_ubyte,
        ctypes.c_size_t,
    ]
    try:
        compile_started = time.perf_counter()
        runtime.compile(KERNEL, b"accumulate_b16_binary_bridge")
        compile_seconds = time.perf_counter() - compile_started
        accumulate_fn = function(runtime, "accumulate_b16_binary_bridge")
        materialize_weights_fn = function(runtime, "materialize_b16_term_weights")
        coordinate_accumulate_fn = function(
            runtime, "accumulate_b16_bridge_coordinates"
        )
        fused_accumulate_fn = function(
            runtime, "accumulate_b16_bridge_fused_shared"
        )
        left_transform_fn = function(runtime, "product_left_transform")
        right_transform_fn = function(runtime, "product_right_transform")
        linear_transform_fn = function(runtime, "linear_transform")
        assemble_fn = function(runtime, "assemble_relation")
        compose_fn = function(runtime, "compose_degree45_message")

        def upload(values, label):
            pointer = runtime.alloc(len(values) * values.itemsize)
            size = copy(runtime, pointer, values, label)
            return pointer, size

        packed_d, packed_size = upload(packed, "copy_packed")
        wire_d, wire_size = upload(wire_weights, "copy_wire_weights")
        group_d, group_size = upload(group_weights, "copy_group_weights")
        basis_d, basis_size = upload(basis_table, "copy_chunk_basis")
        selectors_d, selector_size = upload(selectors, "copy_selectors")
        base_left_d, base_left_size = upload(base_left, "copy_base_left_initial")
        base_right_d, base_right_size = upload(base_right, "copy_base_right_initial")
        formulas_d, formula_size = upload(formulas, "copy_formulas_initial")

        product_sum_size = 2 * product_plane_size
        product_sum_d = runtime.alloc(product_sum_size)
        linear_low_d = runtime.alloc(linear_plane_size)
        linear_carry_d = runtime.alloc(linear_plane_size)
        constant_low_d = runtime.alloc(constant_plane_size)
        constant_carry_d = runtime.alloc(constant_plane_size)
        temporary_d = runtime.alloc(temporary_size)
        matrix_d = runtime.alloc(matrix_size)
        linear_coefficients_d = runtime.alloc(linear_coefficients_size)
        relation_d = runtime.alloc(relation_size)
        message_d = runtime.alloc(message_size)
        tile_group_count = 256
        term_weight_size = (
            MAX_CLAIMS * MAX_RAW * tile_group_count * 16 * 4
        )
        term_weights_d = (
            runtime.alloc(term_weight_size)
            if accumulation_mode == "tiled"
            else 0
        )

        def zero_accumulators():
            for pointer, size, label in (
                (product_sum_d, product_sum_size, "zero_product_sum"),
                (linear_low_d, linear_plane_size, "zero_linear_low"),
                (linear_carry_d, linear_plane_size, "zero_linear_carry"),
                (constant_low_d, constant_plane_size, "zero_constant_low"),
                (constant_carry_d, constant_plane_size, "zero_constant_carry"),
            ):
                ck(runtime.cuda.cuMemsetD8_v2(pointer, 0, size), label)

        def finalize(claim_count, formula_family):
            left_blocks = claim_count * 4 * 17 * 256
            for block_offset in range(
                0, left_blocks, PRODUCT_LEFT_TILE_BLOCKS
            ):
                tile_blocks = min(
                    PRODUCT_LEFT_TILE_BLOCKS,
                    left_blocks - block_offset,
                )
                launch(
                    runtime,
                    left_transform_fn,
                    tile_blocks,
                    THREADS,
                    arguments(
                        ctypes.c_uint64(product_sum_d),
                        ctypes.c_uint64(basis_d),
                        ctypes.c_uint64(temporary_d),
                        ctypes.c_uint32(claim_count),
                        ctypes.c_uint32(block_offset),
                    ),
                    "product_left_transform",
                )
            right_blocks = claim_count * 4 * 17 * 17
            for block_offset in range(
                0, right_blocks, PRODUCT_RIGHT_TILE_BLOCKS
            ):
                tile_blocks = min(
                    PRODUCT_RIGHT_TILE_BLOCKS,
                    right_blocks - block_offset,
                )
                launch(
                    runtime,
                    right_transform_fn,
                    tile_blocks,
                    THREADS,
                    arguments(
                        ctypes.c_uint64(temporary_d),
                        ctypes.c_uint64(basis_d),
                        ctypes.c_uint64(matrix_d),
                        ctypes.c_uint32(claim_count),
                        ctypes.c_uint32(block_offset),
                    ),
                    "product_right_transform",
                )
            launch(
                runtime,
                assemble_fn,
                claim_count * 31,
                16,
                arguments(
                    ctypes.c_uint64(matrix_d),
                    ctypes.c_uint64(constant_low_d),
                    ctypes.c_uint64(constant_carry_d),
                    ctypes.c_uint64(relation_d),
                    ctypes.c_uint32(claim_count),
                    ctypes.c_uint32(formula_family),
                ),
                "assemble_relation",
            )
            launch(
                runtime,
                compose_fn,
                46,
                128,
                arguments(
                    ctypes.c_uint64(relation_d),
                    ctypes.c_uint64(selectors_d),
                    ctypes.c_uint64(message_d),
                    ctypes.c_uint32(claim_count),
                ),
                "compose_degree45_message",
            )

        def run_layer(raw_width, left_width, right_width, formula, claim_count, layer):
            for output in range(raw_width):
                base_left[output] = (17 * output + 31 * layer) % left_width
                base_right[output] = (29 * output + 47 * layer + 1) % right_width
                formulas[output] = (
                    2 if formula == 2 and output % 32 == 0 else (0 if formula == 2 else formula)
                )
            copy(runtime, base_left_d, base_left, "copy_base_left")
            copy(runtime, base_right_d, base_right, "copy_base_right")
            copy(runtime, formulas_d, formulas, "copy_formulas")
            zero_accumulators()
            terms = raw_width * GROUP_COUNT
            claim_terms = terms * claim_count
            accumulate_started = time.perf_counter()
            if accumulation_mode == "direct":
                launch(
                    runtime,
                    accumulate_fn,
                    (claim_terms + THREADS - 1) // THREADS,
                    THREADS,
                    arguments(
                        ctypes.c_uint64(packed_d),
                        ctypes.c_uint64(packed_d),
                        ctypes.c_uint64(wire_d),
                        ctypes.c_uint64(group_d),
                        ctypes.c_uint64(base_left_d),
                        ctypes.c_uint64(base_right_d),
                        ctypes.c_uint64(formulas_d),
                        ctypes.c_uint64(product_sum_d),
                        ctypes.c_uint64(linear_low_d),
                        ctypes.c_uint64(linear_carry_d),
                        ctypes.c_uint64(constant_low_d),
                        ctypes.c_uint64(constant_carry_d),
                        ctypes.c_uint32(raw_width),
                        ctypes.c_uint32(GROUP_COUNT),
                        ctypes.c_uint32(WORDS_PER_WIRE),
                        ctypes.c_uint32(MAX_RAW),
                        ctypes.c_uint32(GROUP_COUNT),
                        ctypes.c_uint32(claim_count),
                    ),
                    "accumulate_b16_binary_bridge",
                )
            elif accumulation_mode == "tiled":
                for group_offset in range(0, GROUP_COUNT, tile_group_count):
                    groups = min(tile_group_count, GROUP_COUNT - group_offset)
                    tile_terms = raw_width * groups * claim_count
                    launch(
                        runtime,
                        materialize_weights_fn,
                        (tile_terms + THREADS - 1) // THREADS,
                        THREADS,
                        arguments(
                            ctypes.c_uint64(wire_d),
                            ctypes.c_uint64(group_d),
                            ctypes.c_uint64(term_weights_d),
                            ctypes.c_uint32(raw_width),
                            ctypes.c_uint32(groups),
                            ctypes.c_uint32(group_offset),
                            ctypes.c_uint32(MAX_RAW),
                            ctypes.c_uint32(GROUP_COUNT),
                            ctypes.c_uint32(claim_count),
                        ),
                        "materialize_b16_term_weights",
                    )
                    scalar_terms = tile_terms * 16
                    launch(
                        runtime,
                        coordinate_accumulate_fn,
                        (scalar_terms + THREADS - 1) // THREADS,
                        THREADS,
                        arguments(
                            ctypes.c_uint64(packed_d),
                            ctypes.c_uint64(packed_d),
                            ctypes.c_uint64(term_weights_d),
                            ctypes.c_uint64(base_left_d),
                            ctypes.c_uint64(base_right_d),
                            ctypes.c_uint64(formulas_d),
                            ctypes.c_uint64(product_sum_d),
                            ctypes.c_uint64(linear_low_d),
                            ctypes.c_uint64(linear_carry_d),
                            ctypes.c_uint64(constant_low_d),
                            ctypes.c_uint64(constant_carry_d),
                            ctypes.c_uint32(raw_width),
                            ctypes.c_uint32(groups),
                            ctypes.c_uint32(group_offset),
                            ctypes.c_uint32(WORDS_PER_WIRE),
                            ctypes.c_uint32(claim_count),
                        ),
                        "accumulate_b16_bridge_coordinates",
                    )
            else:
                fused_threads = 128
                for group_offset in range(0, GROUP_COUNT, tile_group_count):
                    groups = min(tile_group_count, GROUP_COUNT - group_offset)
                    tile_terms = raw_width * groups * claim_count
                    launch(
                        runtime,
                        fused_accumulate_fn,
                        (tile_terms + fused_threads - 1) // fused_threads,
                        fused_threads,
                        arguments(
                            ctypes.c_uint64(packed_d),
                            ctypes.c_uint64(packed_d),
                            ctypes.c_uint64(wire_d),
                            ctypes.c_uint64(group_d),
                            ctypes.c_uint64(0),
                            ctypes.c_uint64(base_left_d),
                            ctypes.c_uint64(base_right_d),
                            ctypes.c_uint64(formulas_d),
                            ctypes.c_uint64(product_sum_d),
                            ctypes.c_uint64(constant_low_d),
                            ctypes.c_uint64(constant_carry_d),
                            ctypes.c_uint32(raw_width),
                            ctypes.c_uint32(groups),
                            ctypes.c_uint32(group_offset),
                            ctypes.c_uint32(WORDS_PER_WIRE),
                            ctypes.c_uint32(MAX_RAW),
                            ctypes.c_uint32(GROUP_COUNT),
                            ctypes.c_uint32(GROUP_COUNT),
                            ctypes.c_uint32(claim_count),
                        ),
                        "accumulate_b16_bridge_fused_shared",
                    )
            ck(runtime.cuda.cuCtxSynchronize(), "production_accumulate_sync")
            accumulate_seconds = time.perf_counter() - accumulate_started
            finalize_started = time.perf_counter()
            finalize(claim_count, 1 if formula == 1 else 0)
            ck(runtime.cuda.cuCtxSynchronize(), "production_finalize_sync")
            finalize_seconds = time.perf_counter() - finalize_started
            return terms, accumulate_seconds, finalize_seconds

        # End-to-end differential KAT, including transforms and degree-45 composition.
        kat_raw = 5
        kat_groups = 4
        kat_claims = MAX_CLAIMS
        for output in range(kat_raw):
            base_left[output] = (3 * output + 1) % 17
            base_right[output] = (5 * output + 2) % 19
            formulas[output] = 0
        copy(runtime, base_left_d, base_left, "kat_copy_base_left")
        copy(runtime, base_right_d, base_right, "kat_copy_base_right")
        copy(runtime, formulas_d, formulas, "kat_copy_formulas")
        zero_accumulators()
        kat_terms = kat_raw * kat_groups
        kat_claim_terms = kat_terms * kat_claims
        launch(
            runtime,
            accumulate_fn,
            (kat_claim_terms + THREADS - 1) // THREADS,
            THREADS,
            arguments(
                ctypes.c_uint64(packed_d),
                ctypes.c_uint64(packed_d),
                ctypes.c_uint64(wire_d),
                ctypes.c_uint64(group_d),
                ctypes.c_uint64(base_left_d),
                ctypes.c_uint64(base_right_d),
                ctypes.c_uint64(formulas_d),
                ctypes.c_uint64(product_sum_d),
                ctypes.c_uint64(linear_low_d),
                ctypes.c_uint64(linear_carry_d),
                ctypes.c_uint64(constant_low_d),
                ctypes.c_uint64(constant_carry_d),
                ctypes.c_uint32(kat_raw),
                ctypes.c_uint32(kat_groups),
                ctypes.c_uint32(WORDS_PER_WIRE),
                ctypes.c_uint32(MAX_RAW),
                ctypes.c_uint32(GROUP_COUNT),
                ctypes.c_uint32(kat_claims),
            ),
            "kat_accumulate_b16_binary_bridge",
        )
        finalize(kat_claims, 0)
        ck(runtime.cuda.cuCtxSynchronize(), "kat_degree45_sync")
        actual_kat = read_message(runtime, message_d)
        expected_kat = expected_message(
            basis,
            packed,
            base_left,
            base_right,
            formulas,
            wire_weights,
            group_weights,
            kat_raw,
            kat_groups,
            kat_claims,
            selectors_by_claim,
        )
        if actual_kat != expected_kat:
            mismatch = next(
                index
                for index, (actual, expected) in enumerate(zip(actual_kat, expected_kat))
                if actual != expected
            )
            raise SystemExit(
                "degree45_differential_kat_mismatch "
                f"coefficient={mismatch} actual={actual_kat[mismatch]} "
                f"expected={expected_kat[mismatch]}"
            )
        if accumulation_mode in ("tiled", "fused"):
            direct_kat = actual_kat
            zero_accumulators()
            tile_terms = kat_raw * kat_groups * kat_claims
            if accumulation_mode == "tiled":
                launch(
                    runtime,
                    materialize_weights_fn,
                    (tile_terms + THREADS - 1) // THREADS,
                    THREADS,
                    arguments(
                        ctypes.c_uint64(wire_d),
                        ctypes.c_uint64(group_d),
                        ctypes.c_uint64(term_weights_d),
                        ctypes.c_uint32(kat_raw),
                        ctypes.c_uint32(kat_groups),
                        ctypes.c_uint32(0),
                        ctypes.c_uint32(MAX_RAW),
                        ctypes.c_uint32(GROUP_COUNT),
                        ctypes.c_uint32(kat_claims),
                    ),
                    "kat_materialize_b16_term_weights",
                )
                launch(
                    runtime,
                    coordinate_accumulate_fn,
                    (tile_terms * 16 + THREADS - 1) // THREADS,
                    THREADS,
                    arguments(
                        ctypes.c_uint64(packed_d),
                        ctypes.c_uint64(packed_d),
                        ctypes.c_uint64(term_weights_d),
                        ctypes.c_uint64(base_left_d),
                        ctypes.c_uint64(base_right_d),
                        ctypes.c_uint64(formulas_d),
                        ctypes.c_uint64(product_sum_d),
                        ctypes.c_uint64(linear_low_d),
                        ctypes.c_uint64(linear_carry_d),
                        ctypes.c_uint64(constant_low_d),
                        ctypes.c_uint64(constant_carry_d),
                        ctypes.c_uint32(kat_raw),
                        ctypes.c_uint32(kat_groups),
                        ctypes.c_uint32(0),
                        ctypes.c_uint32(WORDS_PER_WIRE),
                        ctypes.c_uint32(kat_claims),
                    ),
                    "kat_accumulate_b16_bridge_coordinates",
                )
            else:
                fused_threads = 128
                launch(
                    runtime,
                    fused_accumulate_fn,
                    (tile_terms + fused_threads - 1) // fused_threads,
                    fused_threads,
                    arguments(
                        ctypes.c_uint64(packed_d),
                        ctypes.c_uint64(packed_d),
                        ctypes.c_uint64(wire_d),
                        ctypes.c_uint64(group_d),
                        ctypes.c_uint64(0),
                        ctypes.c_uint64(base_left_d),
                        ctypes.c_uint64(base_right_d),
                        ctypes.c_uint64(formulas_d),
                        ctypes.c_uint64(product_sum_d),
                        ctypes.c_uint64(constant_low_d),
                        ctypes.c_uint64(constant_carry_d),
                        ctypes.c_uint32(kat_raw),
                        ctypes.c_uint32(kat_groups),
                        ctypes.c_uint32(0),
                        ctypes.c_uint32(WORDS_PER_WIRE),
                        ctypes.c_uint32(MAX_RAW),
                        ctypes.c_uint32(GROUP_COUNT),
                        ctypes.c_uint32(GROUP_COUNT),
                        ctypes.c_uint32(kat_claims),
                    ),
                    "kat_accumulate_b16_bridge_fused_shared",
                )
            finalize(kat_claims, 0)
            ck(runtime.cuda.cuCtxSynchronize(), "kat_tiled_degree45_sync")
            tiled_kat = read_message(runtime, message_d)
            if tiled_kat != direct_kat or tiled_kat != expected_kat:
                raise SystemExit(
                    "degree45_tiled_differential_kat_mismatch "
                    f"direct={direct_kat} tiled={tiled_kat} "
                    f"expected={expected_kat}"
                )

        # The selected DAG uses one formula per layer. Exercise every accepted
        # uniform formula independently because the marginal reconstruction
        # deliberately rejects a mixed-formula layer.
        for kat_formula in (1, 2):
            for output in range(kat_raw):
                formulas[output] = kat_formula
            copy(
                runtime,
                formulas_d,
                formulas,
                f"kat_copy_uniform_formula_{kat_formula}",
            )
            zero_accumulators()
            fused_threads = 128
            launch(
                runtime,
                fused_accumulate_fn,
                (kat_claim_terms + fused_threads - 1) // fused_threads,
                fused_threads,
                arguments(
                    ctypes.c_uint64(packed_d),
                    ctypes.c_uint64(packed_d),
                    ctypes.c_uint64(wire_d),
                    ctypes.c_uint64(group_d),
                    ctypes.c_uint64(0),
                    ctypes.c_uint64(base_left_d),
                    ctypes.c_uint64(base_right_d),
                    ctypes.c_uint64(formulas_d),
                    ctypes.c_uint64(product_sum_d),
                    ctypes.c_uint64(constant_low_d),
                    ctypes.c_uint64(constant_carry_d),
                    ctypes.c_uint32(kat_raw),
                    ctypes.c_uint32(kat_groups),
                    ctypes.c_uint32(0),
                    ctypes.c_uint32(WORDS_PER_WIRE),
                    ctypes.c_uint32(MAX_RAW),
                    ctypes.c_uint32(GROUP_COUNT),
                    ctypes.c_uint32(GROUP_COUNT),
                    ctypes.c_uint32(kat_claims),
                ),
                f"kat_accumulate_uniform_formula_{kat_formula}",
            )
            finalize(kat_claims, 1 if kat_formula == 1 else 0)
            ck(
                runtime.cuda.cuCtxSynchronize(),
                f"kat_uniform_formula_{kat_formula}_sync",
            )
            actual_uniform = read_message(runtime, message_d)
            expected_uniform = expected_message(
                basis,
                packed,
                base_left,
                base_right,
                formulas,
                wire_weights,
                group_weights,
                kat_raw,
                kat_groups,
                kat_claims,
                selectors_by_claim,
            )
            if actual_uniform != expected_uniform:
                mismatch = next(
                    index
                    for index, (actual, expected) in enumerate(
                        zip(actual_uniform, expected_uniform)
                    )
                    if actual != expected
                )
                raise SystemExit(
                    "degree45_uniform_formula_kat_mismatch "
                    f"formula={kat_formula} coefficient={mismatch} "
                    f"actual={actual_uniform[mismatch]} "
                    f"expected={expected_uniform[mismatch]}"
                )

        layer_seconds = []
        accumulate_seconds = []
        finalize_seconds = []
        total_terms = 0
        total_claim_terms = 0
        started = time.perf_counter()
        for _ in range(repeats):
            for layer, ((raw_width, left_width, right_width, formula), claims) in enumerate(
                zip(LAYERS, CLAIM_SCHEDULE)
            ):
                layer_started = time.perf_counter()
                terms, layer_accumulate_seconds, layer_finalize_seconds = run_layer(
                    raw_width, left_width, right_width, formula, claims, layer
                )
                layer_seconds.append(time.perf_counter() - layer_started)
                accumulate_seconds.append(layer_accumulate_seconds)
                finalize_seconds.append(layer_finalize_seconds)
                total_terms += terms
                total_claim_terms += claims * terms
        kernel_total_seconds = time.perf_counter() - started
        sample = read_message(runtime, message_d)
        if not any(any(coefficient) for coefficient in sample):
            raise SystemExit("degree45_message_zero")

        bridge_working_set = (
            packed_size
            + wire_size
            + group_size
            + basis_size
            + selector_size
            + base_left_size
            + base_right_size
            + formula_size
            + product_sum_size
            + 2 * linear_plane_size
            + 2 * constant_plane_size
            + temporary_size
            + matrix_size
            + linear_coefficients_size
            + relation_size
            + message_size
            + (term_weight_size if accumulation_mode == "tiled" else 0)
        )
        # Sequential post-bridge materialization/folding layout: one shared
        # source table, one half-sized scratch table, packed source, lookup,
        # challenges, and bounded weights. Accumulators are released first.
        group_phase_working_set = (
            packed_size
            + MAX_WIDTH * GROUP_COUNT * 64
            + MAX_WIDTH * (GROUP_COUNT // 2) * 64
            + 65_536 * 64
            + wire_size
            + group_size
            + selector_size
        )
        ordered = sorted(layer_seconds)
        per_round_seconds = kernel_total_seconds / repeats
        print("scope=fp16_b16_binary_gate_bridge")
        print("evidence_class=exact_field_exact_geometry_with_independent_differential_kat")
        print(f"repeats={repeats}")
        print("layers_per_round=7")
        print("steady_state_claim_schedule=2,1,2,1,3,1,4")
        print("final_round_layer_6_claim_count=1")
        print("distinct_shard_queries_preserved=true")
        print(f"packed_instances={PACKED_INSTANCES}")
        print("packed_bits=16")
        print(f"group_count={GROUP_COUNT}")
        print(f"packed_terms={total_terms}")
        print(f"packed_claim_terms={total_claim_terms}")
        print("binary_relation_degree=30")
        print("packed_selector_degree=15")
        print("message_degree=45")
        print("message_coefficients=46")
        print("degree30_nonlinear_bridge_rejected=true")
        print("all_claims_accumulated=true")
        print(f"accumulation_mode={accumulation_mode}")
        print("product_histograms=4")
        print("product_histogram_accumulator=u64_exact_sum")
        print("linear_histograms=4")
        print("linear_histogram_accumulator=u32_low_carry_exact_sum")
        print("histogram_transform=two_stage_exact_m31_basis")
        print("message_before_challenge_required=true")
        print("degree45_differential_kat=true")
        print(
            "degree45_direct_tiled_differential_kat="
            f"{str(accumulation_mode == 'tiled').lower()}"
        )
        print(
            "degree45_direct_fused_differential_kat="
            f"{str(accumulation_mode == 'fused').lower()}"
        )
        print(f"compile_seconds={compile_seconds:.6f}")
        print(f"kernel_total_seconds={kernel_total_seconds:.6f}")
        print(f"accumulate_seconds={sum(accumulate_seconds):.6f}")
        print(f"finalize_seconds={sum(finalize_seconds):.6f}")
        print(f"per_keccak_round_seconds={per_round_seconds:.6f}")
        print(f"k128_24_round_projection_seconds={24 * per_round_seconds:.6f}")
        print(f"layer_min_seconds={ordered[0]:.6f}")
        print(f"layer_median_seconds={ordered[len(ordered) // 2]:.6f}")
        print(f"layer_max_seconds={ordered[-1]:.6f}")
        print(f"host_peak_mb={process_peak_mb():.3f}")
        print(f"device_bridge_working_set_mb={bridge_working_set / 1_000_000:.6f}")
        print(
            "calculated_sequential_group_phase_working_set_mb="
            f"{group_phase_working_set / 1_000_000:.6f}"
        )
        print(
            "calculated_sequential_device_peak_mb="
            f"{max(bridge_working_set, group_phase_working_set) / 1_000_000:.6f}"
        )
        print(f"message_sample_coefficient_45={sample[45]}")
        print("complete_gkr_qualification=false")
        print("complete_proof_qualification=false")
    finally:
        runtime.close()


if __name__ == "__main__":
    main()
