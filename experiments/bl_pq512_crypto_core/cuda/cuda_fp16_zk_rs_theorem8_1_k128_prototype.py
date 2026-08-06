"""Production-geometry nonactivating prototype of paper Construction 8.2.

This composes the streamed 512-way initial RS oracle with nine zero-knowledge
sumcheck-mask codewords and the non-succinct base protocol.  It preserves exact
row query counts by using 1,024-, 576-, and 64-byte typed Merkle leaves for the
initial, auxiliary, and single-main-codeword oracles respectively.

Native processes independently verify every canonical Merkle multiproof,
re-encode the full answer over Fp16, and verify the target/spotcheck arithmetic.
The authenticated transcript uses the real dual-PQ public coin and the native
masked GKR prelude. It fixes one output, four relay-free inputs, two
state-relation inputs, and twelve square-free state inputs before two batching
challenges, folds the exact row relation in compact GPU state, and
requires the independent Rust answer verifier to re-establish the final
Construction 7.2 target. It remains nonactivating and receives no qualification
credit until a complete fresh proof and the containing security gates pass.
"""

import array
import ctypes
import hashlib
import os
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import cuda_fp16_zk_rs_interleaved_k128_prototype as core
from cuda_fp16_tower_kat import add, mul16, sub
from cuda_m31_brakedown_factor_benchmark import arguments, function, launch


AUX_MESSAGE_VALUES = 2_048
AUX_RANDOMNESS_VALUES = 1_218
AUX_DIMENSION = AUX_MESSAGE_VALUES + AUX_RANDOMNESS_VALUES
AUX_CODE_LOG = 13
AUX_CODE_VALUES = 1 << AUX_CODE_LOG
SUMCHECK_ROUNDS = 9
MAIN_DIMENSION = core.BASE_MESSAGE_VALUES + core.MASK_COEFFICIENTS
INITIAL_SEGMENT_COUNT = (
    core.BOUNDARY_COUNT * core.SEGMENTS_PER_BOUNDARY
)
THEOREM_SEGMENT_COUNT = INITIAL_SEGMENT_COUNT + 5
SUMCHECK_MASK_KIND = 64
BASE_MAIN_MASK_KIND = 65
BASE_AUX_MASK_KIND = 66
GKR_MASK_KIND = 67
STATE_SQUAREFREE_COEFFICIENT_KIND = 68
STATE_SQUAREFREE_COEFFICIENT_CLAIMS = 2
STATE_SQUAREFREE_COEFFICIENT_VARIABLES = 11
GKR_MASK_DIMENSION = 32_768
MAIN_LEAF_SIZE = core.FP16_BYTES
MAIN_QUERY_COUNT = 1_600
AUX_QUERY_COUNT = 1_218
QUERY_DOMAIN = 524
ZERO = (0,) * 16
ONE = (1,) + (0,) * 15
GKR_CLAIM_COUNT = 19
PACKED_GKR_CLAIM_COUNT = 5
DIRECT_GKR_CLAIM_START = PACKED_GKR_CLAIM_COUNT
GKR_POINT_VARIABLES = 24
GKR_LOW_VARIABLES = 16
GKR_HIGH_VARIABLES = 8
GLOBAL_WORDS = 512
GKR_MASK_STATES = GKR_MASK_DIMENSION // GLOBAL_WORDS
GKR_ROW_STATES = GKR_CLAIM_COUNT * 16
ROW_STATES = GKR_ROW_STATES + GKR_MASK_STATES
AUXILIARY_WORDS = SUMCHECK_ROUNDS + GKR_MASK_STATES + 1
SUMCHECK_LEAF_SIZE = SUMCHECK_ROUNDS * core.FP16_BYTES
GKR_MASK_LEAF_SIZE = GKR_MASK_STATES * core.FP16_BYTES
STATE_SQUAREFREE_COEFFICIENT_LEAF_SIZE = core.FP16_BYTES
AUXILIARY_LEAF_SIZE = AUXILIARY_WORDS * core.FP16_BYTES
WORDS_PER_BOUNDARY = 256
HASH_BUS_B16_HEADER_BYTES = 215
HASH_BUS_B16_SHARD_BYTES = 2 * 1_600 * 8_192 * 2
STATE_RELATION_TRANSCRIPT_ROUNDS = 26
STATE_COMPOSED_MASK_BATCH_ROUNDS = 1
GKR_PRELUDE_ROUNDS = (
    6_073
    + STATE_RELATION_TRANSCRIPT_ROUNDS
    + STATE_COMPOSED_MASK_BATCH_ROUNDS
)
STATE_SQUAREFREE_ROUNDS = {1: 614, 3: 882}


IOPP_KERNEL = r"""
/*
 * Exact semantic B16 source initializer. The canonical shard payload stores
 * input then output, wire-major, with 8,192 groups on the minor axis. The
 * low 16 coefficient variables are wire[0..11) || group[0..5), while the
 * interleaving word supplies group[5..13). Fixed-zero padding wires are not
 * serialized and remain zero here.
 */
extern "C" __global__ void initialize_b16_semantic_rs_coefficients(
    u32 *values,
    const u32 *masks,
    u32 log_code,
    u32 message_values,
    u32 mask_coefficients,
    u32 batch,
    u32 boundary,
    u32 segment,
    const unsigned short *patterns,
    const u32 *state_values
) {
    u64 code_values = 1ULL << log_code;
    u64 count = (u64)batch * code_values;
    u64 index = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    if (index >= count || boundary >= 2U) return;
    u32 word = (u32)(index >> log_code);
    u32 position = (u32)(index & (code_values - 1ULL));
    u32 *output = values + 16ULL * index;
    #pragma unroll
    for (u32 coordinate = 0U; coordinate < 16U; ++coordinate) {
        output[coordinate] = 0U;
    }
    if (position < message_values) {
        u32 wire = position & 2047U;
        u32 group_low = position >> 11U;
        if (wire < 1600U && group_low < 32U) {
            u32 global_word = segment * batch + word;
            u32 group = (global_word << 5U) | group_low;
            u64 source =
                ((u64)boundary * 1600ULL + wire) * 8192ULL + group;
            u32 pattern = patterns[source];
            #pragma unroll
            for (u32 coordinate = 0U; coordinate < 16U; ++coordinate) {
                output[coordinate] = (pattern >> coordinate) & 1U;
            }
        } else if (
            state_values != NULL
            && boundary == 1U
            && wire < 1664U
            && group_low < 32U
        ) {
            u32 global_word = segment * batch + word;
            u32 group = (global_word << 5U) | group_low;
            if (group < 4096U) {
                u64 source =
                    ((u64)(wire - 1600U) * 4096ULL + group) * 16ULL;
                #pragma unroll
                for (u32 coordinate = 0U; coordinate < 16U; ++coordinate) {
                    output[coordinate] = state_values[source + coordinate];
                }
            }
        }
    } else if (position < message_values + mask_coefficients) {
        u32 coefficient = position - message_values;
        u64 mask_offset =
            ((u64)word * mask_coefficients + coefficient) * 16ULL;
        #pragma unroll
        for (u32 coordinate = 0U; coordinate < 16U; ++coordinate) {
            output[coordinate] = masks[mask_offset + coordinate];
        }
    }
}

extern "C" __global__ void multilinear_coefficient_weights(
    const u32 *points,
    u32 *weights,
    u32 variables,
    u32 message_values,
    u32 point_count
) {
    u32 position = blockIdx.x * blockDim.x + threadIdx.x;
    u32 point = blockIdx.y;
    if (point >= point_count || position >= message_values) return;
    F16 one = z16();
    one.a.a.a.a = 1U;
    F16 weight = one;
    for (u32 variable = 0U; variable < variables; ++variable) {
        F16 challenge = l16(
            points + 16ULL * (point * variables + variable)
        );
        weight = m16(
            weight,
            ((position >> variable) & 1U)
                ? challenge
                : s16(one, challenge)
        );
    }
    st16(
        weights + 16ULL * (point * message_values + position),
        weight
    );
}

/*
 * Evaluate the exact low-16-variable component polynomial for every selected
 * claim and high-word position directly from the packed semantic boundary.
 * Claims 0..4 are the hash GKR output/input claims and use the packed B16
 * patterns; claims 5..18 are the state-relation/square-free claims and use
 * only the embedded state lane. One block owns one (claim, word, component);
 * no full Fp16 source replay is materialized.
 */
extern "C" __global__ void semantic_component_multilinear_evaluations(
    const unsigned short *patterns,
    const u32 *state_values,
    const u32 *weights,
    u32 *output,
    u32 point_count
) {
    u32 global_word = blockIdx.x;
    u32 point = blockIdx.y;
    u32 component = blockIdx.z;
    u32 lane = threadIdx.x;
    if (
        global_word >= 512U
        || point >= point_count
        || component >= 16U
        || lane >= 256U
    ) return;
    __shared__ F16 partial[256];
    F16 accumulator = z16();
    u32 boundary = global_word >> 8U;
    u32 word = global_word & 255U;
    for (u32 position = lane; position < 65536U; position += 256U) {
        u32 wire = position & 2047U;
        u32 group_low = position >> 11U;
        if (point < 5U && wire < 1600U) {
            u32 group = (word << 5U) | group_low;
            u64 source =
                ((u64)boundary * 1600ULL + wire) * 8192ULL + group;
            u32 pattern = patterns[source];
            if (((pattern >> component) & 1U) != 0U) {
                accumulator = a16(
                    accumulator,
                    l16(
                        weights
                        + 16ULL * ((u64)point * 65536ULL + position)
                    )
                );
            }
        } else if (
            point >= 5U
            &&
            state_values != NULL
            && boundary == 1U
            && wire >= 1600U
            && wire < 1664U
            && group_low < 32U
        ) {
            u32 group = (word << 5U) | group_low;
            if (group < 4096U) {
                u64 source =
                    ((u64)(wire - 1600U) * 4096ULL + group) * 16ULL;
                F16 packed = l16(state_values + source);
                accumulator = a16(
                    accumulator,
                    m16(
                        l16(
                            weights
                            + 16ULL * ((u64)point * 65536ULL + position)
                        ),
                        packed
                    )
                );
            }
        }
    }
    partial[lane] = accumulator;
    __syncthreads();
    for (u32 stride = 128U; stride > 0U; stride >>= 1U) {
        if (lane < stride) {
            partial[lane] = a16(partial[lane], partial[lane + stride]);
        }
        __syncthreads();
    }
    if (lane == 0U) {
        st16(
            output
            + 16ULL
                * (
                    ((u64)point * 512ULL + global_word) * 16ULL
                    + component
                ),
            partial[0]
        );
    }
}

__device__ __forceinline__ F16 row_pow_q(F16 value) {
    F16 result = z16();
    result.a.a.a.a = 1U;
    u32 exponent = 2147483647U;
    while (exponent != 0U) {
        if ((exponent & 1U) != 0U) result = m16(result, value);
        value = m16(value, value);
        exponent >>= 1U;
    }
    return result;
}

/*
 * Evaluate the sixteen M31 component polynomials directly from one live
 * commitment tile. The production launch grid is row by claim by component.
 * No unpacked coefficient table is materialized.
 */
extern "C" __global__ void compact_component_multilinear_evaluations(
    const u32 *coefficients,
    const u32 *weights,
    u32 *output,
    u32 dimension,
    u32 batch,
    u32 message_values,
    u32 point_count,
    u32 output_words,
    u32 global_word_base
) {
    u32 word = blockIdx.x;
    u32 point = blockIdx.y;
    u32 component = blockIdx.z;
    u32 lane = threadIdx.x;
    if (
        word >= batch
        || point >= point_count
        || component >= 16U
        || lane >= 256U
    ) return;
    __shared__ F16 partial[256];
    F16 accumulator = z16();
    for (u32 position = lane; position < message_values; position += 256U) {
        F16 packed = l16(
            coefficients
            + 16ULL * ((u64)word * dimension + position)
        );
        F2 scalar = {((u32 *)&packed)[component], 0U};
        F16 weight = l16(
            weights
            + 16ULL * ((u64)point * message_values + position)
        );
        accumulator = a16(
            accumulator,
            rs_m16f2(weight, scalar)
        );
    }
    partial[lane] = accumulator;
    __syncthreads();
    for (u32 stride = 128U; stride > 0U; stride >>= 1U) {
        if (lane < stride) {
            partial[lane] = a16(partial[lane], partial[lane + stride]);
        }
        __syncthreads();
    }
    if (lane == 0U) {
        st16(
            output
            + 16ULL
                * (
                    (
                        (u64)point * output_words
                        + global_word_base
                        + word
                    )
                    * 16U
                    + component
                ),
            partial[0]
        );
    }
}

/*
 * The selected fixed zero-trace source has one public message polynomial per
 * boundary; every interleaving changes only the hiding tail. Extract that
 * message evaluation from the first live commitment tile of each boundary,
 * then copy it across the 256 public high-word positions. This removes no
 * witness-dependent work and never copies a hiding coefficient.
 */
extern "C" __global__ void broadcast_boundary_component_evaluations(
    u32 *output,
    u32 boundary_word_base,
    u32 point_count,
    u32 output_words
) {
    u32 index = blockIdx.x * blockDim.x + threadIdx.x;
    u32 count = point_count * 256U * 16U;
    if (index >= count) return;
    u32 component = index & 15U;
    u32 row = index >> 4U;
    u32 word = row & 255U;
    u32 point = row >> 8U;
    if (word == 0U) return;
    u64 source =
        ((u64)point * output_words + boundary_word_base) * 16U
        + component;
    u64 destination =
        (
            (u64)point * output_words
            + boundary_word_base
            + word
        ) * 16U
        + component;
    st16(
        output + 16ULL * destination,
        l16(output + 16ULL * source)
    );
}

/*
 * Collapse the selected half of each claim's 512 high-word component rows to
 * the exact sixteen component evaluations carried by the GKR claim.  Keeping
 * this reduction on the untrusted GPU avoids expanding all 40,960 Fp16 row
 * values into Python objects.  The reconstructed packed claim and the later
 * independently verified row relation still reject any incorrect result.
 */
extern "C" __global__ void reduce_claim_component_evaluations(
    const u32 *rows,
    const u32 *weights,
    const u32 *boundaries,
    u32 *output,
    u32 claim_count,
    u32 output_words
) {
    u32 claim = blockIdx.y;
    u32 component = blockIdx.z;
    u32 lane = threadIdx.x;
    if (
        claim >= claim_count
        || component >= 16U
        || lane >= 256U
    ) return;
    __shared__ F16 partial[256];
    u32 word = boundaries[claim] * 256U + lane;
    F16 value = l16(
        rows
        + 16ULL
            * (
                ((u64)claim * output_words + word) * 16U
                + component
            )
    );
    F16 weight = l16(weights + 16ULL * (claim * 256U + lane));
    partial[lane] = m16(value, weight);
    __syncthreads();
    for (u32 stride = 128U; stride > 0U; stride >>= 1U) {
        if (lane < stride) {
            partial[lane] = a16(partial[lane], partial[lane + stride]);
        }
        __syncthreads();
    }
    if (lane == 0U) {
        st16(output + 16ULL * (claim * 16U + component), partial[0]);
    }
}

/*
 * Convert five by 512 by sixteen row evaluations into eighty independently
 * folded source/relation states. Source entries remain present on both
 * boundaries; only the relation is boundary-supported. This preserves the
 * cross-boundary terms at the ninth non-Boolean challenge.
 */
extern "C" __global__ void initialize_compact_row_states(
    const u32 *component_rows,
    const u32 *high_points,
    const u32 *coordinate_map,
    const u32 *claim_powers,
    const u32 *claim_boundaries,
    u32 *source_states,
    u32 *relation_states
) {
    u32 global_word = blockIdx.x;
    u32 claim = blockIdx.y;
    u32 component = threadIdx.x;
    if (global_word >= 512U || claim >= 19U || component >= 16U) return;
    if (claim >= 5U) {
        if (component != 0U) return;
        u32 boundary = global_word >> 8U;
        u32 word = global_word & 255U;
        F16 high = z16();
        if (boundary == claim_boundaries[claim]) {
            high.a.a.a.a = 1U;
            F16 one = high;
            for (u32 variable = 0U; variable < 8U; ++variable) {
                F16 challenge = l16(
                    high_points + 16ULL * (claim * 8U + variable)
                );
                high = m16(
                    high,
                    ((word >> variable) & 1U)
                        ? challenge
                        : s16(one, challenge)
                );
            }
        }
        u64 component_row =
            16ULL * (((u64)claim * 512U + global_word) * 16U);
        u64 direct_state = (u64)(claim * 16U) * 512U + global_word;
        st16(source_states + 16ULL * direct_state, l16(component_rows + component_row));
        st16(
            relation_states + 16ULL * direct_state,
            m16(l16(claim_powers + 16ULL * claim), high)
        );
        return;
    }
    __shared__ F16 partial[16];
    __shared__ F16 high;
    F16 value = l16(
        component_rows
        + 16ULL * (((u64)claim * 512U + global_word) * 16U + component)
    );
    if (component == 0U) {
        u32 boundary = global_word >> 8U;
        u32 word = global_word & 255U;
        high = z16();
        if (boundary == claim_boundaries[claim]) {
            high.a.a.a.a = 1U;
            F16 one = high;
            for (u32 variable = 0U; variable < 8U; ++variable) {
                F16 challenge = l16(
                    high_points + 16ULL * (claim * 8U + variable)
                );
                high = m16(
                    high,
                    ((word >> variable) & 1U)
                        ? challenge
                        : s16(one, challenge)
                );
            }
        }
    }
    __syncthreads();
    for (u32 conjugate = 0U; conjugate < 16U; ++conjugate) {
        F16 basis = z16();
        ((u32 *)&basis)[component] = 1U;
        partial[component] = m16(basis, value);
        __syncthreads();
        for (u32 stride = 8U; stride > 0U; stride >>= 1U) {
            if (component < stride) {
                partial[component] = a16(
                    partial[component],
                    partial[component + stride]
                );
            }
            __syncthreads();
        }
        if (component == 0U) {
            u64 state = (u64)(claim * 16U + conjugate) * 512U
                + global_word;
            st16(source_states + 16ULL * state, partial[0]);
            st16(
                relation_states + 16ULL * state,
                m16(
                    m16(
                        l16(claim_powers + 16ULL * claim),
                        l16(coordinate_map + 16ULL * conjugate)
                    ),
                    high
                )
            );
            high = row_pow_q(high);
        }
        value = row_pow_q(value);
        __syncthreads();
    }
}

extern "C" __global__ void compact_row_quadratic_message(
    const u32 *source_states,
    const u32 *relation_states,
    u32 *message,
    u32 active_words,
    u32 state_count
) {
    u32 lane = threadIdx.x;
    if (blockIdx.x != 0U || lane >= 128U) return;
    __shared__ F16 constants[128];
    __shared__ F16 linears[128];
    __shared__ F16 quadratics[128];
    F16 constant = z16();
    F16 linear = z16();
    F16 quadratic = z16();
    u32 pairs = active_words >> 1U;
    u32 count = state_count * pairs;
    for (u32 index = lane; index < count; index += 128U) {
        u32 state = index / pairs;
        u32 pair = index - state * pairs;
        u64 offset = (u64)state * 512U + 2U * pair;
        F16 source_left = l16(source_states + 16ULL * offset);
        F16 source_right = l16(
            source_states + 16ULL * (offset + 1U)
        );
        F16 relation_left = l16(
            relation_states + 16ULL * offset
        );
        F16 relation_right = l16(
            relation_states + 16ULL * (offset + 1U)
        );
        F16 source_delta = s16(source_right, source_left);
        F16 relation_delta = s16(relation_right, relation_left);
        constant = a16(constant, m16(source_left, relation_left));
        linear = a16(
            linear,
            a16(
                m16(source_left, relation_delta),
                m16(source_delta, relation_left)
            )
        );
        quadratic = a16(
            quadratic,
            m16(source_delta, relation_delta)
        );
    }
    constants[lane] = constant;
    linears[lane] = linear;
    quadratics[lane] = quadratic;
    __syncthreads();
    for (u32 stride = 64U; stride > 0U; stride >>= 1U) {
        if (lane < stride) {
            constants[lane] = a16(
                constants[lane],
                constants[lane + stride]
            );
            linears[lane] = a16(
                linears[lane],
                linears[lane + stride]
            );
            quadratics[lane] = a16(
                quadratics[lane],
                quadratics[lane + stride]
            );
        }
        __syncthreads();
    }
    if (lane == 0U) {
        st16(message, constants[0]);
        st16(message + 16U, linears[0]);
        st16(message + 32U, quadratics[0]);
    }
}

extern "C" __global__ void fold_compact_row_states(
    u32 *source_states,
    u32 *relation_states,
    F16 challenge,
    u32 active_words,
    u32 state_count
) {
    u32 next_words = active_words >> 1U;
    u32 state = blockIdx.x;
    u32 destination = threadIdx.x;
    if (state >= state_count) return;
    u64 base = (u64)state * 512U;
    u64 source = base + 2U * destination;
    F16 source_left = z16();
    F16 source_right = z16();
    F16 relation_left = z16();
    F16 relation_right = z16();
    if (destination < next_words) {
        source_left = l16(source_states + 16ULL * source);
        source_right = l16(
            source_states + 16ULL * (source + 1U)
        );
        relation_left = l16(relation_states + 16ULL * source);
        relation_right = l16(
            relation_states + 16ULL * (source + 1U)
        );
    }
    __syncthreads();
    if (destination >= next_words) return;
    st16(
        source_states + 16ULL * (base + destination),
        a16(
            source_left,
            m16(s16(source_right, source_left), challenge)
        )
    );
    st16(
        relation_states + 16ULL * (base + destination),
        a16(
            relation_left,
            m16(s16(relation_right, relation_left), challenge)
        )
    );
}

extern "C" __global__ void compact_row_terminal(
    const u32 *source_states,
    const u32 *relation_states,
    u32 *terminal,
    u32 state_count
) {
    u32 lane = threadIdx.x;
    if (blockIdx.x != 0U || lane >= 128U) return;
    __shared__ F16 partial[128];
    F16 value = z16();
    for (u32 state = lane; state < state_count; state += 128U) {
        u64 offset = (u64)state * 512U;
        value = a16(
            value,
            m16(
                l16(source_states + 16ULL * offset),
                l16(relation_states + 16ULL * offset)
            )
        );
    }
    partial[lane] = value;
    __syncthreads();
    for (u32 stride = 64U; stride > 0U; stride >>= 1U) {
        if (lane < stride) {
            partial[lane] = a16(
                partial[lane],
                partial[lane + stride]
            );
        }
        __syncthreads();
    }
    if (lane == 0U) st16(terminal, partial[0]);
}

extern "C" __global__ void copy_gkr_mask_row_terminals(
    const u32 *source_states,
    const u32 *relation_states,
    u32 *terminals,
    u32 state_base
) {
    u32 state = blockIdx.x * blockDim.x + threadIdx.x;
    if (state >= 64U) return;
    u64 source = ((u64)state_base + state) * 512ULL;
    st16(
        terminals + 16ULL * state,
        l16(source_states + 16ULL * source)
    );
    st16(
        terminals + 16ULL * (64ULL + state),
        l16(relation_states + 16ULL * source)
    );
}

extern "C" __global__ void accumulate_folded_real_gkr_coefficients(
    u32 *output,
    const u32 *masks,
    const u32 *weights,
    u32 global_word_base,
    u32 boundary,
    u32 segment,
    u32 batch,
    u32 message_values,
    u32 randomness_values
) {
    u32 position = blockIdx.x * blockDim.x + threadIdx.x;
    u32 dimension = message_values + randomness_values;
    if (position >= dimension) return;
    F16 accumulator = l16(output + 16ULL * position);
    for (u32 word = 0U; word < batch; ++word) {
        F16 value = z16();
        if (position < message_values) {
            u32 *coordinates = (u32 *)&value;
            u32 wire = position & 2047U;
            u32 bit = 0U;
            if (boundary == 0U && wire < 1600U) {
                bit = (u32)(
                    (rs_keccak_f_zero[wire >> 6] >> (wire & 63U)) & 1ULL
                );
            }
            #pragma unroll
            for (u32 coordinate = 0U; coordinate < 16U; ++coordinate) {
                coordinates[coordinate] = bit;
            }
        } else {
            u32 randomness = position - message_values;
            value = l16(
                masks
                + 16ULL * ((u64)word * randomness_values + randomness)
            );
        }
        F16 weight = l16(
            weights + 16ULL * (global_word_base + word)
        );
        accumulator = a16(accumulator, m16(value, weight));
    }
    st16(output + 16ULL * position, accumulator);
    (void)segment;
}

extern "C" __global__ void accumulate_folded_semantic_gkr_coefficients(
    u32 *output,
    const u32 *masks,
    const u32 *weights,
    u32 global_word_base,
    u32 boundary,
    u32 segment,
    u32 batch,
    u32 message_values,
    u32 randomness_values,
    const unsigned short *patterns,
    const u32 *state_values
) {
    u32 position = blockIdx.x * blockDim.x + threadIdx.x;
    u32 dimension = message_values + randomness_values;
    if (position >= dimension || boundary >= 2U) return;
    F16 accumulator = l16(output + 16ULL * position);
    for (u32 word = 0U; word < batch; ++word) {
        F16 value = z16();
        if (position < message_values) {
            u32 wire = position & 2047U;
            u32 group_low = position >> 11U;
            if (wire < 1600U && group_low < 32U) {
                u32 global_source_word = segment * batch + word;
                u32 group =
                    (global_source_word << 5U) | group_low;
                u64 source =
                    ((u64)boundary * 1600ULL + wire) * 8192ULL
                    + group;
                u32 pattern = patterns[source];
                u32 *coordinates = (u32 *)&value;
                #pragma unroll
                for (u32 coordinate = 0U; coordinate < 16U; ++coordinate) {
                    coordinates[coordinate] =
                        (pattern >> coordinate) & 1U;
                }
            } else if (
                state_values != NULL
                && boundary == 1U
                && wire < 1664U
                && group_low < 32U
            ) {
                u32 global_source_word = segment * batch + word;
                u32 group =
                    (global_source_word << 5U) | group_low;
                if (group < 4096U) {
                    u64 source =
                        ((u64)(wire - 1600U) * 4096ULL + group) * 16ULL;
                    value = l16(state_values + source);
                }
            }
        } else {
            u32 randomness = position - message_values;
            value = l16(
                masks
                + 16ULL * ((u64)word * randomness_values + randomness)
            );
        }
        F16 weight = l16(
            weights + 16ULL * (global_word_base + word)
        );
        accumulator = a16(accumulator, m16(value, weight));
    }
    st16(output + 16ULL * position, accumulator);
}

extern "C" __global__ void linear_combine_coefficients(
    u32 *output,
    const u32 *mask,
    const u32 *witness,
    F16 challenge,
    u64 count
) {
    u64 index = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    if (index >= count) return;
    st16(
        output + 16ULL * index,
        a16(
            l16(mask + 16ULL * index),
            m16(challenge, l16(witness + 16ULL * index))
        )
    );
}

extern "C" __global__ void initialize_gkr_mask_row_states(
    const u32 *mask,
    const u32 *weights,
    const u32 *scale,
    u32 *source_states,
    u32 *relation_states,
    u32 state_base
) {
    u32 position = blockIdx.x * blockDim.x + threadIdx.x;
    if (position >= 32768U) return;
    u64 destination = (u64)state_base * 512ULL + position;
    st16(
        source_states + 16ULL * destination,
        l16(mask + 16ULL * position)
    );
    st16(
        relation_states + 16ULL * destination,
        m16(
            l16(weights + 16ULL * position),
            l16(scale)
        )
    );
}

extern "C" __global__ void assemble_complete_auxiliary_source(
    const u32 *sumcheck_masks,
    const u32 *gkr_mask,
    const u32 *state_squarefree_coefficients,
    u32 *output
) {
    u32 index = blockIdx.x * blockDim.x + threadIdx.x;
    u32 count = 74U * 3266U;
    if (index >= count) return;
    u32 word = index / 3266U;
    u32 position = index - word * 3266U;
    F16 value = z16();
    if (word < 9U) {
        value = l16(
            sumcheck_masks
            + 16ULL * ((u64)word * 3266ULL + position)
        );
    } else if (word < 73U && position < 512U) {
        value = l16(
            gkr_mask
            + 16ULL * ((u64)(word - 9U) * 512ULL + position)
        );
    } else if (word == 73U) {
        value = l16(
            state_squarefree_coefficients + 16ULL * position
        );
    }
    st16(output + 16ULL * index, value);
}
"""


def scale(value, scalar):
    return mul16(value, scalar)


def fp16_bytes(value):
    return b"".join(coordinate.to_bytes(4, "big") for coordinate in value)


def fp16_value(value, coordinate=0):
    result = [0] * 16
    result[coordinate] = value % core.Q
    return tuple(result)


def encode_gkr_claim(claim):
    (
        boundary,
        coefficient,
        value,
        shard_query,
        point,
        component_evaluations,
    ) = claim
    if (
        boundary not in (0, 1)
        or len(point) != GKR_POINT_VARIABLES
        or len(component_evaluations) != 16
    ):
        raise SystemExit("gkr_component_claim_shape")
    return (
        boundary.to_bytes(4, "big")
        + fp16_bytes(coefficient)
        + fp16_bytes(value)
        + fp16_bytes(shard_query)
        + b"".join(fp16_bytes(coordinate) for coordinate in point)
        + b"".join(
            fp16_bytes(evaluation)
            for evaluation in component_evaluations
        )
    )


def gkr_claims_digest(claims):
    return core.sha3_parts(
        525,
        (
            b"BL/PQ512/FP16-ZK-RS/GKR-MIXED-CLAIMS/HASH-PACKED-STATE-DIRECT/v3\0",
            b"".join(encode_gkr_claim(claim) for claim in claims),
        ),
    )


def gkr_binding_digest(
    claims_digest,
    claim_challenge,
    coordinate_challenge,
    target,
):
    return core.sha3_parts(
        526,
        (
            b"BL/PQ512/FP16-ZK-RS/ROW-BATCHED-BINDING/MIXED-v3\0",
            claims_digest,
            fp16_bytes(claim_challenge),
            fp16_bytes(coordinate_challenge),
            fp16_bytes(target),
        ),
    )


def lagrange_weights(query):
    weights = []
    for node in range(16):
        numerator = ONE
        denominator = 1
        for other in range(16):
            if other == node:
                continue
            numerator = mul16(
                numerator,
                sub(query, fp16_value(other)),
            )
            denominator = denominator * (node - other) % core.Q
        weights.append(
            mul16(
                numerator,
                fp16_value(pow(denominator, core.Q - 2, core.Q)),
            )
        )
    return tuple(weights)


def verify_constant_shard_lagrange_kat():
    query = fp16_value(137, 3)
    weights = lagrange_weights(query)
    if sum_fp16(weights) != ONE:
        raise SystemExit("constant_shard_lagrange_partition")
    if sum_fp16(mul16(ONE, weight) for weight in weights) != ONE:
        raise SystemExit("constant_shard_lagrange_one")
    legacy = sum_fp16(
        mul16(ONE if index == 0 else ZERO, weight)
        for index, weight in enumerate(weights)
    )
    if legacy == ONE:
        raise SystemExit("constant_shard_legacy_encoding_not_distinguished")


def fixture_gkr_points():
    return tuple(
        tuple(
            fp16_value(
                101 + 1_009 * ordinal + 37 * coordinate,
                (ordinal + coordinate) % 16,
            )
            for coordinate in range(GKR_POINT_VARIABLES)
        )
        for ordinal in range(GKR_CLAIM_COUNT)
    )


def component_rows_from_words(words):
    expected = (
        GKR_CLAIM_COUNT
        * GLOBAL_WORDS
        * 16
        * 16
    )
    if len(words) != expected:
        raise SystemExit(
            f"component_row_word_count={len(words)}/{expected}"
        )
    return tuple(
        tuple(
            tuple(
                fp16_from_words(
                    words,
                    (claim * GLOBAL_WORDS + word) * 16 + component,
                )
                for component in range(16)
            )
            for word in range(GLOBAL_WORDS)
        )
        for claim in range(GKR_CLAIM_COUNT)
    )


def component_evaluations_from_words(words):
    expected = GKR_CLAIM_COUNT * 16 * 16
    if len(words) != expected:
        raise SystemExit(
            f"component_evaluation_word_count={len(words)}/{expected}"
        )
    return tuple(
        tuple(
            fp16_from_words(words, claim * 16 + component)
            for component in range(16)
        )
        for claim in range(GKR_CLAIM_COUNT)
    )


def build_fixture_gkr_claims(points, component_rows):
    claims = []
    for ordinal, point in enumerate(points):
        boundary = 0 if ordinal == 0 else 1
        high_weights = full_fold_weights(point[GKR_LOW_VARIABLES:])
        component_evaluations = []
        for component in range(16):
            evaluation = ZERO
            for word, weight in enumerate(high_weights):
                evaluation = add(
                    evaluation,
                    mul16(
                        component_rows[ordinal][
                            boundary * WORDS_PER_BOUNDARY + word
                        ][component],
                        weight,
                    ),
                )
            component_evaluations.append(evaluation)
        shard_query = fp16_value(31 + 17 * ordinal)
        claim_value = ZERO
        for evaluation, weight in zip(
            component_evaluations,
            lagrange_weights(shard_query),
        ):
            claim_value = add(
                claim_value,
                mul16(evaluation, weight),
            )
        claims.append(
            (
                boundary,
                ONE if ordinal == 0 else fp16_value(701 + ordinal),
                claim_value,
                shard_query,
                point,
                tuple(component_evaluations),
            )
        )
    return tuple(claims)


def build_real_gkr_claims(raw_claims, component_evaluations_by_claim):
    claims = []
    for ordinal, raw in enumerate(raw_claims):
        boundary, coefficient, value, shard_query, point = raw
        component_evaluations = component_evaluations_by_claim[ordinal]
        if ordinal >= DIRECT_GKR_CLAIM_START:
            if any(evaluation != value for evaluation in component_evaluations):
                raise SystemExit(
                    f"real_gkr_direct_claim_replication_mismatch={ordinal}"
                )
            reconstructed = component_evaluations[0]
        else:
            reconstructed = sum_fp16(
                mul16(evaluation, weight)
                for evaluation, weight in zip(
                    component_evaluations,
                    lagrange_weights(shard_query),
                )
            )
        if reconstructed != value:
            raise SystemExit(
                f"real_gkr_component_claim_mismatch={ordinal}"
            )
        claims.append(
            (
                boundary,
                coefficient,
                value,
                shard_query,
                point,
                tuple(component_evaluations),
            )
        )
    return tuple(claims)


def expected_binding_target(
    claims,
    claim_challenge,
    coordinate_challenge,
):
    target = ZERO
    claim_power = ONE
    for ordinal, claim in enumerate(claims):
        if ordinal >= DIRECT_GKR_CLAIM_START:
            target = add(target, mul16(claim_power, claim[2]))
        else:
            coordinate_power = ONE
            for coordinate in range(16):
                packed_coordinate = tuple(
                    evaluation[coordinate]
                    for evaluation in claim[5]
                )
                target = add(
                    target,
                    mul16(
                        claim_power,
                        mul16(coordinate_power, packed_coordinate),
                    ),
                )
                coordinate_power = mul16(
                    coordinate_power,
                    coordinate_challenge,
                )
        claim_power = mul16(claim_power, claim_challenge)
    return target


def fp16_from_words(words, value_index):
    start = 16 * value_index
    return tuple(words[start : start + 16])


def copy_fp16_words(runtime, buffer, label):
    payload = core.copy_to_host(runtime, buffer, label)
    words = array.array("I")
    words.frombytes(payload)
    return words


def copy_canonical_fp16_payload(runtime, buffer, label):
    if sys.byteorder != "little":
        raise SystemExit("canonical_fp16_host_endianness")
    payload = core.copy_to_host(runtime, buffer, label)
    words = array.array("I")
    words.frombytes(payload)
    del payload
    words.byteswap()
    canonical = words.tobytes()
    del words
    return canonical


def exact_queries(state, label, bound, count):
    queries = []
    seen = set()
    draw = 0
    threshold = ((1 << 64) - bound) % bound
    while len(queries) < count:
        retry = 0
        while True:
            digest = core.sha3_parts(
                QUERY_DOMAIN,
                (
                    state,
                    label,
                    draw.to_bytes(8, "big"),
                    retry.to_bytes(8, "big"),
                ),
            )
            random_word = int.from_bytes(digest[:8], "little")
            product = random_word * bound
            if (
                product & 0xFFFF_FFFF_FFFF_FFFF
            ) >= threshold:
                candidate = product >> 64
                if candidate not in seen:
                    queries.append(candidate)
                    seen.add(candidate)
                    break
            retry += 1
        draw += 1
    return tuple(sorted(queries))


def encode_random_batch(
    runtime,
    allocator,
    kernel_functions,
    root_powers,
    coset_powers,
    coefficients,
    log_code,
    dimension,
    batch,
):
    return core.encode_segment(
        runtime,
        allocator,
        kernel_functions,
        root_powers,
        coset_powers,
        coefficients,
        0,
        0,
        log_code=log_code,
        message_values=0,
        mask_coefficients=dimension,
        batch=batch,
    )


def full_fold_weights(challenges):
    weights = []
    for word in range(1 << len(challenges)):
        weight = ONE
        for bit, challenge in enumerate(challenges):
            factor = challenge if word & (1 << bit) else sub(ONE, challenge)
            weight = scale(weight, factor)
        weights.append(weight)
    return tuple(weights)


def upload_fp16_values(runtime, allocator, values, label):
    words = array.array(
        "I",
        (coordinate for value in values for coordinate in value),
    )
    return core.upload(runtime, allocator, words.tobytes(), label)


def canonical_fp16_word_array(payload, expected_values, label):
    expected_size = expected_values * core.FP16_BYTES
    if len(payload) != expected_size or sys.byteorder != "little":
        raise SystemExit(
            f"{label}_shape={len(payload)}/{expected_size}"
        )
    words = array.array("I")
    words.frombytes(payload)
    words.byteswap()
    if any(coordinate >= core.Q for coordinate in words):
        raise SystemExit(f"{label}_noncanonical")
    return words


def native_gkr_mask_commit(executable):
    started = time.perf_counter()
    process = subprocess.run(
        [str(executable), "--gkr-mask-commit"],
        check=False,
        capture_output=True,
    )
    wall_seconds = time.perf_counter() - started
    expected_size = 8 + 4 + 8 + 4 + 64 + (
        GKR_MASK_DIMENSION * core.FP16_BYTES
    )
    if process.returncode or process.stderr:
        raise SystemExit(
            "gkr_mask_commit_process="
            f"{process.returncode};stderr={process.stderr!r}"
        )
    if len(process.stdout) != expected_size:
        raise SystemExit(
            "gkr_mask_commit_output_shape="
            f"{len(process.stdout)}/{expected_size}"
        )
    if process.stdout[:8] != b"BLRSMO01":
        raise SystemExit("gkr_mask_commit_output_magic")
    sampling_attempts = int.from_bytes(process.stdout[8:12], "big")
    compute_seconds = struct.unpack(">d", process.stdout[12:20])[0]
    workers = int.from_bytes(process.stdout[20:24], "big")
    root = process.stdout[24:88]
    payload = process.stdout[88:]
    if (
        not 1 <= sampling_attempts <= 32
        or not 0.0 < compute_seconds < 60.0
        or not 1 <= workers <= 16
        or not any(root)
    ):
        raise SystemExit(
            "gkr_mask_commit_metadata="
            f"{sampling_attempts}/{compute_seconds}/{workers}"
        )
    words = canonical_fp16_word_array(
        payload,
        GKR_MASK_DIMENSION,
        "gkr_mask_commit_payload",
    )
    return (
        root,
        payload,
        words,
        sampling_attempts,
        compute_seconds,
        wall_seconds,
        workers,
    )


def upload_fp16_word_array(runtime, allocator, words, label):
    if not isinstance(words, array.array) or words.typecode != "I":
        raise SystemExit(f"{label}_word_array")
    return core.upload(runtime, allocator, words.tobytes(), label)


def gather_rows(
    runtime,
    allocator,
    gather_function,
    segment,
    queries,
    label,
):
    query_words = array.array("I", queries)
    query_buffer = core.upload(
        runtime,
        allocator,
        query_words.tobytes(),
        f"{label}_queries",
    )
    leaf_size = core.segment_leaf_size(segment)
    output = allocator.allocate_count(len(queries), leaf_size)
    launch(
        runtime,
        gather_function,
        len(queries) * leaf_size,
        arguments(
            ctypes.c_uint64(segment.buffer.pointer),
            ctypes.c_uint64(output.pointer),
            ctypes.c_uint64(query_buffer.pointer),
            ctypes.c_uint64(segment.data_size),
            ctypes.c_uint32(leaf_size),
            ctypes.c_uint32(len(queries)),
        ),
        label,
    )
    core.ck(runtime.cuda.cuCtxSynchronize(), f"{label}_sync")
    payload = core.copy_to_host(
        runtime,
        output,
        f"{label}_copy",
    )
    allocator.free(output)
    allocator.free(query_buffer)
    return payload


def decode_canonical_fp16(payload, offset):
    start = offset * core.FP16_BYTES
    value = payload[start : start + core.FP16_BYTES]
    if len(value) != core.FP16_BYTES:
        raise AssertionError("canonical_fp16_offset")
    return tuple(
        int.from_bytes(value[4 * index : 4 * index + 4], "big")
        for index in range(16)
    )


def canonical_mask_messages(words):
    encoded = bytearray(
        SUMCHECK_ROUNDS
        * AUX_MESSAGE_VALUES
        * core.FP16_BYTES
    )
    offset = 0
    for mask in range(SUMCHECK_ROUNDS):
        for degree in range(AUX_MESSAGE_VALUES):
            value = fp16_from_words(
                words,
                mask * AUX_DIMENSION + degree,
            )
            encoded[offset : offset + core.FP16_BYTES] = fp16_bytes(
                value
            )
            offset += core.FP16_BYTES
    return bytes(encoded)


def read_exact_pipe(stream, length, label):
    payload = bytearray()
    while len(payload) < length:
        chunk = stream.read(length - len(payload))
        if not chunk:
            break
        payload.extend(chunk)
    if len(payload) != length:
        raise SystemExit(
            f"{label}_short_read={len(payload)}/{length}"
        )
    return bytes(payload)


def state_squarefree_claims_payload(root, capacity, claims, payload):
    if capacity == 0 and root == b"\0" * 64 and not claims:
        if payload != b"BLSQCL00" + root + b"\0" * 4:
            raise SystemExit("state_squarefree_claim_payload_zero")
        return payload
    if (
        len(root) != 64
        or capacity not in (128, 512)
        or len(claims) != STATE_SQUAREFREE_COEFFICIENT_CLAIMS
        or len(payload) != 140
        or payload[:8] != b"BLSQCL02"
        or payload[8:72] != root
        or int.from_bytes(payload[72:74], "big") != capacity
        or int.from_bytes(payload[74:76], "big") != len(claims)
    ):
        raise SystemExit("state_squarefree_claim_payload_shape")
    for point, value in claims:
        if len(point) != STATE_SQUAREFREE_COEFFICIENT_VARIABLES:
            raise SystemExit("state_squarefree_claim_point")
    return payload


def state_squarefree_answer_binding(capacity, claims, mixing):
    if capacity == 0 and not claims:
        encoded = bytearray(b"BLSQAB01" + b"\0" * 8)
        for scalar in mixing:
            encoded.extend(fp16_bytes(scalar))
        return bytes(encoded), ZERO
    if (
        len(claims) != STATE_SQUAREFREE_COEFFICIENT_CLAIMS
        or len(mixing) != STATE_SQUAREFREE_COEFFICIENT_CLAIMS
        or any(
        value == ZERO for value in mixing
        )
    ):
        raise SystemExit("state_squarefree_functional_shape")
    encoded = bytearray(
        b"BLSQAB01"
        + capacity.to_bytes(2, "big")
        + len(claims).to_bytes(2, "big")
        + b"\0" * 4
    )
    target = ZERO
    for point, value in claims:
        if len(point) != STATE_SQUAREFREE_COEFFICIENT_VARIABLES:
            raise SystemExit("state_squarefree_answer_point")
        encoded.extend(len(point).to_bytes(2, "big") + b"\0" * 6)
        for coordinate in point:
            encoded.extend(fp16_bytes(coordinate))
        encoded.extend(fp16_bytes(value))
    for scalar in mixing:
        encoded.extend(fp16_bytes(scalar))
    for (_, value), scalar in zip(claims, mixing):
        target = add(target, mul16(scalar, value))
    return bytes(encoded), target


def copy_device(runtime, destination, source, size, label):
    core.ck(
        runtime.cuda.cuMemcpyDtoD_v2(destination, source, size),
        label,
    )


class NativePublicCoinBridge:
    @staticmethod
    def _command(
        executable,
        semantic_boundary,
        semantic_shard,
        semantic_python,
        semantic_worker,
        state_relation_source,
        gkr_prelude,
        eager,
    ):
        command = [str(executable)]
        if not gkr_prelude:
            return command
        if semantic_boundary is not None:
            command.extend(
                (
                    "--gkr-prelude-nonuniform-eager"
                    if eager
                    else "--gkr-prelude-nonuniform",
                    str(semantic_boundary),
                    str(semantic_shard),
                    str(semantic_python),
                    str(semantic_worker),
                )
            )
            if state_relation_source is not None:
                command.extend(
                    (
                        str(state_relation_source["path"]),
                        state_relation_source["digest"].hex(),
                    )
                )
        else:
            command.append("--gkr-prelude")
        return command

    @staticmethod
    def _spawn(command):
        return subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            creationflags=getattr(subprocess, "HIGH_PRIORITY_CLASS", 0),
        )

    @classmethod
    def prepare_nonuniform(
        cls,
        executable,
        semantic_boundary,
        semantic_shard,
        semantic_python,
        semantic_worker,
        state_relation_source,
    ):
        command = cls._command(
            executable,
            semantic_boundary,
            semantic_shard,
            semantic_python,
            semantic_worker,
            state_relation_source,
            True,
            True,
        )
        started = time.perf_counter()
        return cls._spawn(command), started

    @staticmethod
    def abort_prepared(prepared):
        if prepared is None:
            return
        process, _ = prepared
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=10)

    def __init__(
        self,
        executable,
        session_id,
        schedule_commitment,
        round_count,
        gkr_mask_commitment=None,
        gkr_mask_coefficients=None,
        defer_gkr_prelude=False,
        semantic_boundary=None,
        semantic_shard=0,
        semantic_python=None,
        semantic_worker=None,
        state_relation_source=None,
        prepared=None,
    ):
        gkr_prelude = gkr_mask_commitment is not None
        if gkr_prelude != (gkr_mask_coefficients is not None):
            raise SystemExit("public_coin_gkr_prelude_shape")
        semantic_gkr = semantic_boundary is not None
        if semantic_gkr and (
            semantic_python is None or semantic_worker is None
        ):
            raise SystemExit("public_coin_semantic_worker_shape")
        if gkr_prelude:
            if (
                len(gkr_mask_commitment) != 64
                or len(gkr_mask_coefficients)
                != 32_768 * core.FP16_BYTES
            ):
                raise SystemExit("public_coin_gkr_mask_shape")
        command = self._command(
            executable,
            semantic_boundary,
            semantic_shard,
            semantic_python,
            semantic_worker,
            state_relation_source,
            gkr_prelude,
            prepared is not None,
        )
        if prepared is None:
            self.started = time.perf_counter()
            self.process = self._spawn(command)
        else:
            if not semantic_gkr:
                raise SystemExit("public_coin_prepared_uniform")
            self.process, self.started = prepared
            if (
                tuple(str(value) for value in self.process.args)
                != tuple(command)
                or self.process.poll() is not None
            ):
                self.abort_prepared(prepared)
                raise SystemExit("public_coin_prepared_state")
        self.closed = False
        self.round = 0
        self.round_count = round_count
        self.gkr_prelude = gkr_prelude
        self.prelude_complete = False
        self.head_seconds = None
        self.gkr_mask_opening = None
        self.gkr_claim_challenge = None
        self.gkr_mask_weights = None
        self.gkr_raw_claims = None
        self.gkr_state_relation_digest = b"\0" * 64
        self.state_squarefree_coefficient_root = b"\0" * 64
        self.state_squarefree_coefficient_claims = ()
        self.state_squarefree_public_claims_payload = b""
        self.state_squarefree_capacity = 0
        try:
            self.process.stdin.write(
                b"BLPCCN01"
                + session_id
                + (0).to_bytes(2, "big")
                + schedule_commitment
                + round_count.to_bytes(4, "big")
            )
            if gkr_prelude:
                self.process.stdin.write(gkr_mask_commitment)
                self.process.stdin.write(gkr_mask_coefficients)
            self.process.stdin.flush()
        except BrokenPipeError as error:
            status = self.process.wait(timeout=30)
            stderr = self.process.stderr.read()
            self.closed = True
            raise SystemExit(
                "public_coin_prelude_pipe="
                f"status={status};stderr={stderr!r}"
            ) from error
        if not defer_gkr_prelude:
            self.complete_prelude()

    def begin_prelude(self, initial_root=None):
        if self.closed or self.prelude_complete:
            raise SystemExit("public_coin_prelude_state")
        try:
            ready = read_exact_pipe(
                self.process.stdout,
                16,
                "public_coin_ready",
            )
        except SystemExit as error:
            status = self.process.wait(timeout=30)
            stderr = self.process.stderr.read()
            self.closed = True
            raise SystemExit(
                f"{error};status={status};stderr={stderr!r}"
            ) from error
        if ready[:8] == b"BLPCCB01":
            if initial_root is None or len(initial_root) != 64:
                self.abort()
                raise SystemExit("public_coin_squarefree_initial_root")
            self.process.stdin.write(b"BLPCCB02" + initial_root)
            self.process.stdin.flush()
            witness_header = read_exact_pipe(
                self.process.stdout,
                16,
                "public_coin_squarefree_witness_header",
            )
            if (
                witness_header[:8] != b"BLPCCW01"
                or witness_header[10:] != b"\0" * 6
            ):
                self.abort()
                raise SystemExit(
                    f"public_coin_squarefree_witness={witness_header!r}"
                )
            self.state_squarefree_capacity = int.from_bytes(
                witness_header[8:10], "big"
            )
            if self.state_squarefree_capacity not in (128, 512):
                self.abort()
                raise SystemExit("public_coin_squarefree_capacity")
            beta = read_exact_pipe(
                self.process.stdout,
                core.FP16_BYTES,
                "public_coin_squarefree_beta",
            )
            coefficients = read_exact_pipe(
                self.process.stdout,
                AUX_MESSAGE_VALUES * core.FP16_BYTES,
                "public_coin_squarefree_coefficients",
            )
            self.head_seconds = struct.unpack(">d", ready[8:])[0]
            return beta, coefficients
        expected_ready = b"BLPCCG01" if self.gkr_prelude else b"BLPCCRD1"
        if ready[:8] != expected_ready:
            self.abort()
            raise SystemExit(f"public_coin_ready={ready!r}")
        self._complete_ready(ready)
        return None

    def finish_squarefree_prelude(self, coefficient_root):
        if (
            self.closed
            or self.prelude_complete
            or self.state_squarefree_capacity not in (128, 512)
            or len(coefficient_root) != 64
            or coefficient_root == b"\0" * 64
        ):
            raise SystemExit("public_coin_squarefree_commit_state")
        self.process.stdin.write(b"BLPCCC01" + coefficient_root)
        self.process.stdin.flush()
        try:
            ready = read_exact_pipe(
                self.process.stdout,
                16,
                "public_coin_squarefree_final_ready",
            )
        except SystemExit as error:
            status = self.process.wait(timeout=30)
            stderr = self.process.stderr.read()
            self.closed = True
            raise SystemExit(
                f"{error};status={status};stderr={stderr!r}"
            ) from error
        if ready[:8] != b"BLPCCG01":
            self.abort()
            raise SystemExit(f"public_coin_squarefree_ready={ready!r}")
        self._complete_ready(ready)

    def complete_prelude(self):
        if self.begin_prelude() is not None:
            self.abort()
            raise SystemExit("public_coin_squarefree_requires_initial_root")

    def _complete_ready(self, ready):
        self.head_seconds = struct.unpack(">d", ready[8:])[0]
        if self.gkr_prelude:
            self.gkr_mask_opening = decode_canonical_fp16(
                read_exact_pipe(
                    self.process.stdout,
                    core.FP16_BYTES,
                    "public_coin_gkr_opening",
                ),
                0,
            )
            self.gkr_claim_challenge = decode_canonical_fp16(
                read_exact_pipe(
                    self.process.stdout,
                    core.FP16_BYTES,
                    "public_coin_gkr_claim_challenge",
                ),
                0,
            )
            weights_payload = read_exact_pipe(
                self.process.stdout,
                32_768 * core.FP16_BYTES,
                "public_coin_gkr_weights",
            )
            self.gkr_mask_weights = canonical_fp16_word_array(
                weights_payload,
                32_768,
                "public_coin_gkr_weights",
            )
            claim_size = 4 + 27 * core.FP16_BYTES
            claims_payload = read_exact_pipe(
                self.process.stdout,
                GKR_CLAIM_COUNT * claim_size,
                "public_coin_gkr_claims",
            )
            claims = []
            for claim_index in range(GKR_CLAIM_COUNT):
                payload = claims_payload[
                    claim_index * claim_size :
                    (claim_index + 1) * claim_size
                ]
                boundary = int.from_bytes(payload[:4], "big")
                fields = tuple(
                    decode_canonical_fp16(payload[4:], index)
                    for index in range(27)
                )
                claims.append(
                    (
                        boundary,
                        fields[0],
                        fields[1],
                        fields[2],
                        fields[3:],
                    )
                )
            self.gkr_raw_claims = tuple(claims)
            self.gkr_state_relation_digest = read_exact_pipe(
                self.process.stdout,
                64,
                "public_coin_state_relation_digest",
            )
            if self.gkr_state_relation_digest == b"\0" * 64:
                if os.environ.get("BL_STATE_RELATION_SOURCE_PATH") is not None:
                    self.abort()
                    raise SystemExit("public_coin_state_relation_digest_missing")
            self.state_squarefree_coefficient_root = read_exact_pipe(
                self.process.stdout,
                64,
                "public_coin_squarefree_coefficient_root",
            )
            claim_header = read_exact_pipe(
                self.process.stdout,
                8,
                "public_coin_squarefree_claim_header",
            )
            coefficient_claim_count = int.from_bytes(
                claim_header[:2], "big"
            )
            if claim_header[2:] != b"\0" * 6 or coefficient_claim_count not in (0, 2):
                self.abort()
                raise SystemExit("public_coin_squarefree_claim_count")
            coefficient_claims = []
            for _ in range(coefficient_claim_count):
                point_header = read_exact_pipe(
                    self.process.stdout,
                    8,
                    "public_coin_squarefree_point_header",
                )
                point_length = int.from_bytes(point_header[:2], "big")
                if (
                    point_header[2:] != b"\0" * 6
                    or point_length != STATE_SQUAREFREE_COEFFICIENT_VARIABLES
                ):
                    self.abort()
                    raise SystemExit("public_coin_squarefree_point_length")
                payload = read_exact_pipe(
                    self.process.stdout,
                    (STATE_SQUAREFREE_COEFFICIENT_VARIABLES + 1)
                    * core.FP16_BYTES,
                    "public_coin_squarefree_claim",
                )
                point = tuple(
                    decode_canonical_fp16(payload, index)
                    for index in range(point_length)
                )
                phase = len(coefficient_claims)
                if (
                    self.state_squarefree_capacity == 128
                    and any(
                        decode_canonical_fp16(payload, index) != ZERO
                        for index in range(7, 9)
                    )
                ) or decode_canonical_fp16(payload, 10) != (
                    ZERO if phase == 0 else ONE
                ):
                    self.abort()
                    raise SystemExit("public_coin_squarefree_point_padding")
                coefficient_claims.append(
                    (
                        point,
                        decode_canonical_fp16(
                            payload,
                            STATE_SQUAREFREE_COEFFICIENT_VARIABLES,
                        ),
                    )
                )
            self.state_squarefree_coefficient_claims = tuple(
                coefficient_claims
            )
            public_claims_payload_length = (
                140 if self.state_squarefree_capacity else 76
            )
            self.state_squarefree_public_claims_payload = read_exact_pipe(
                self.process.stdout,
                public_claims_payload_length,
                "public_coin_squarefree_public_claims_payload",
            )
            if self.state_squarefree_capacity:
                expected = STATE_SQUAREFREE_ROUNDS[
                    1 if self.state_squarefree_capacity == 128 else 3
                ]
                self.round = GKR_PRELUDE_ROUNDS + expected
            else:
                self.round = GKR_PRELUDE_ROUNDS
        self.prelude_complete = True

    def challenge(self, kind, message, output_count=1):
        if (
            self.closed
            or not self.prelude_complete
            or self.round >= self.round_count
            or not message
            or len(message) > 1 << 20
            or output_count < 1
            or output_count > 65_535
        ):
            raise SystemExit("public_coin_challenge_shape")
        ordinal = self.round
        self.process.stdin.write(
            b"BLPCCRQ1"
            + kind.to_bytes(2, "big")
            + ordinal.to_bytes(4, "big")
            + output_count.to_bytes(2, "big")
            + len(message).to_bytes(4, "big")
            + message
        )
        self.process.stdin.flush()
        response = read_exact_pipe(
            self.process.stdout,
            14 + output_count * core.FP16_BYTES,
            "public_coin_round",
        )
        if (
            response[:8] != b"BLPCCRS1"
            or int.from_bytes(response[8:12], "big") != ordinal
            or int.from_bytes(response[12:14], "big") != output_count
        ):
            self.abort()
            raise SystemExit(
                f"public_coin_round_response={response[:14]!r}"
            )
        self.round += 1
        challenges = tuple(
            decode_canonical_fp16(response[14:], index)
            for index in range(output_count)
        )
        return challenges[0] if output_count == 1 else challenges

    def finish(self):
        if self.closed or self.round != self.round_count:
            raise SystemExit(
                f"public_coin_finish_rounds={self.round}/{self.round_count}"
            )
        self.process.stdin.close()
        header = read_exact_pipe(
            self.process.stdout,
            12,
            "public_coin_finish",
        )
        if header[:8] != b"BLPCCFN1":
            self.abort()
            raise SystemExit(f"public_coin_finish_header={header!r}")
        bundle_length = int.from_bytes(header[8:], "big")
        bundle = read_exact_pipe(
            self.process.stdout,
            bundle_length,
            "public_coin_bundle",
        )
        finish_seconds = struct.unpack(
            ">d",
            read_exact_pipe(
                self.process.stdout,
                8,
                "public_coin_finish_timing",
            ),
        )[0]
        trailing = self.process.stdout.read()
        status = self.process.wait(timeout=30)
        stderr = self.process.stderr.read()
        self.closed = True
        if status != 0 or stderr or trailing:
            raise SystemExit(
                "public_coin_finish_failed="
                f"status={status};stderr={stderr!r};trailing={trailing!r}"
            )
        return {
            "bundle": bundle,
            "bundle_mb": len(bundle) / 1_000_000,
            "head_seconds": self.head_seconds,
            "finish_seconds": finish_seconds,
            "wall_seconds": time.perf_counter() - self.started,
        }

    def abort(self):
        if self.closed:
            return
        self.closed = True
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(timeout=10)


def run_authenticated_sumcheck(
    executable,
    parameter_executable,
    public_coin,
    initial_root,
    mask_root,
    gkr_mask_root,
    gkr_mask_opening,
    gkr_claims,
    state_squarefree_coefficient_root,
    state_squarefree_capacity,
    state_squarefree_coefficient_claims,
    state_squarefree_public_claims_payload,
    mask_words,
    runtime,
    allocator,
    row_kernels,
    component_rows,
    gkr_mask,
    gkr_mask_weights,
):
    if len(gkr_claims) != GKR_CLAIM_COUNT:
        raise SystemExit("authenticated_sumcheck_claim_count")
    process = subprocess.Popen(
        [str(executable), "--stream"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
    )
    started = time.perf_counter()
    source_states = None
    relation_states = None
    high_points = None
    coordinate_map_buffer = None
    claim_powers_buffer = None
    claim_boundaries_buffer = None
    gkr_weight_buffer = None
    gkr_scale_buffer = None
    gkr_terminal_buffer = None
    message_buffer = None
    try:
        process.stdin.write(b"BLT8SI06")
        process.stdin.write(initial_root)
        process.stdin.write(mask_root)
        process.stdin.write(gkr_mask_root)
        process.stdin.write(fp16_bytes(gkr_mask_opening))
        for claim in gkr_claims:
            process.stdin.write(encode_gkr_claim(claim))
        process.stdin.write(canonical_mask_messages(mask_words))
        process.stdin.flush()

        claims_message = read_exact_pipe(
            process.stdout,
            392,
            "authenticated_sumcheck_claims",
        )
        claims_digest = gkr_claims_digest(gkr_claims)
        if (
            claims_message[:8] != b"BLT8GC06"
            or claims_message[8:72] != initial_root
            or claims_message[72:136] != mask_root
            or claims_message[136:200] != gkr_mask_root
            or decode_canonical_fp16(claims_message[200:264], 0)
            != gkr_mask_opening
            or claims_message[264:328] != claims_digest
        ):
            raise SystemExit(
                f"authenticated_sumcheck_claims={claims_message[:200]!r}"
            )
        squarefree_claims = state_squarefree_claims_payload(
            state_squarefree_coefficient_root,
            state_squarefree_capacity,
            state_squarefree_coefficient_claims,
            state_squarefree_public_claims_payload,
        )
        batching = public_coin.challenge(
            799,
            claims_message + squarefree_claims,
            output_count=6,
        )
        claim_challenge = batching[0]
        coordinate_challenge = batching[1]
        coefficient_mixing = (
            batching[2:4]
            if state_squarefree_capacity
            else batching[2:]
        )
        process.stdin.write(
            b"BLT8CH01"
            + (0).to_bytes(4, "big")
            + fp16_bytes(claim_challenge)
        )
        process.stdin.flush()
        process.stdin.write(
            b"BLT8CH01"
            + (1).to_bytes(4, "big")
            + fp16_bytes(coordinate_challenge)
        )
        process.stdin.flush()

        (
            row_target,
            coordinate_map,
            claim_powers,
            row_parameter_seconds,
        ) = run_row_parameters(
            parameter_executable,
            claim_challenge,
            coordinate_challenge,
            gkr_claims,
        )
        expected_binding_target_value = expected_binding_target(
            gkr_claims,
            claim_challenge,
            coordinate_challenge,
        )
        if row_target != expected_binding_target_value:
            raise SystemExit("row_parameter_target")
        gkr_scale = ONE
        for _ in range(GKR_CLAIM_COUNT):
            gkr_scale = mul16(gkr_scale, claim_challenge)
        expected_target = add(
            expected_binding_target_value,
            mul16(gkr_scale, gkr_mask_opening),
        )

        high_points = upload_fp16_values(
            runtime,
            allocator,
            tuple(
                coordinate
                for claim in gkr_claims
                for coordinate in claim[4][GKR_LOW_VARIABLES:]
            ),
            "upload_compact_row_high_points",
        )
        coordinate_map_buffer = upload_fp16_values(
            runtime,
            allocator,
            coordinate_map,
            "upload_compact_row_coordinate_map",
        )
        claim_powers_buffer = upload_fp16_values(
            runtime,
            allocator,
            claim_powers,
            "upload_compact_row_claim_powers",
        )
        claim_boundaries = array.array(
            "I",
            (claim[0] for claim in gkr_claims),
        )
        claim_boundaries_buffer = core.upload(
            runtime,
            allocator,
            claim_boundaries.tobytes(),
            "upload_compact_row_claim_boundaries",
        )
        source_states = allocator.allocate_count(
            ROW_STATES * GLOBAL_WORDS,
            core.FP16_BYTES,
        )
        relation_states = allocator.allocate_count(
            ROW_STATES * GLOBAL_WORDS,
            core.FP16_BYTES,
        )
        message_buffer = allocator.allocate_count(3, core.FP16_BYTES)
        for buffer, label in (
            (source_states, "clear_compact_row_source_states"),
            (relation_states, "clear_compact_row_relation_states"),
        ):
            core.ck(
                runtime.cuda.cuMemsetD8_v2(
                    buffer.pointer,
                    0,
                    buffer.size,
                ),
                label,
            )
        row_started = time.perf_counter()
        core.ck(
            runtime.cuda.cuLaunchKernel(
                row_kernels["initialize"],
                GLOBAL_WORDS,
                GKR_CLAIM_COUNT,
                1,
                16,
                1,
                1,
                0,
                None,
                arguments(
                    ctypes.c_uint64(component_rows.pointer),
                    ctypes.c_uint64(high_points.pointer),
                    ctypes.c_uint64(coordinate_map_buffer.pointer),
                    ctypes.c_uint64(claim_powers_buffer.pointer),
                    ctypes.c_uint64(claim_boundaries_buffer.pointer),
                    ctypes.c_uint64(source_states.pointer),
                    ctypes.c_uint64(relation_states.pointer),
                ),
                None,
            ),
            "initialize_compact_row_states",
        )
        core.ck(
            runtime.cuda.cuCtxSynchronize(),
            "initialize_compact_row_states_sync",
        )
        launch_row_message(
            runtime,
            row_kernels,
            source_states,
            relation_states,
            message_buffer,
            GLOBAL_WORDS,
            GKR_ROW_STATES,
        )
        component_message_words = copy_fp16_words(
            runtime,
            message_buffer,
            "copy_compact_component_initial_message",
        )
        component_quadratic = tuple(
            fp16_from_words(component_message_words, index)
            for index in range(3)
        )
        component_initial_target = add(
            component_quadratic[0],
            sum_fp16(component_quadratic),
        )
        if component_initial_target != expected_binding_target_value:
            raise SystemExit("compact_component_initial_target_mismatch")
        gkr_weight_buffer = upload_fp16_word_array(
            runtime,
            allocator,
            gkr_mask_weights,
            "upload_gkr_mask_functional_weights",
        )
        gkr_scale_buffer = upload_fp16_values(
            runtime,
            allocator,
            (mul16(claim_powers[-1], claim_challenge),),
            "upload_gkr_mask_functional_scale",
        )
        launch(
            runtime,
            row_kernels["initialize_gkr_mask"],
            GKR_MASK_DIMENSION,
            arguments(
                ctypes.c_uint64(gkr_mask.pointer),
                ctypes.c_uint64(gkr_weight_buffer.pointer),
                ctypes.c_uint64(gkr_scale_buffer.pointer),
                ctypes.c_uint64(source_states.pointer),
                ctypes.c_uint64(relation_states.pointer),
                ctypes.c_uint32(GKR_ROW_STATES),
            ),
            "initialize_gkr_mask_row_states",
        )
        core.ck(
            runtime.cuda.cuCtxSynchronize(),
            "initialize_gkr_mask_row_states_sync",
        )
        launch_row_message(
            runtime,
            row_kernels,
            source_states,
            relation_states,
            message_buffer,
            GLOBAL_WORDS,
            ROW_STATES,
        )
        complete_message_words = copy_fp16_words(
            runtime,
            message_buffer,
            "copy_compact_complete_initial_message",
        )
        complete_quadratic = tuple(
            fp16_from_words(complete_message_words, index)
            for index in range(3)
        )
        complete_initial_target = add(
            complete_quadratic[0],
            sum_fp16(complete_quadratic),
        )
        if complete_initial_target != expected_target:
            raise SystemExit("compact_gkr_mask_initial_target_mismatch")

        initial = read_exact_pipe(
            process.stdout,
            456,
            "authenticated_sumcheck_initial",
        )
        if (
            initial[:8] != b"BLT8SO06"
            or initial[8:72] != initial_root
            or initial[72:136] != mask_root
            or initial[136:200] != gkr_mask_root
            or decode_canonical_fp16(initial[200:264], 0)
            != gkr_mask_opening
        ):
            raise SystemExit(
                f"authenticated_sumcheck_initial={initial[:136]!r}"
            )
        expected_binding_digest = gkr_binding_digest(
            claims_digest,
            claim_challenge,
            coordinate_challenge,
            expected_target,
        )
        if initial[264:328] != expected_binding_digest:
            raise SystemExit("authenticated_sumcheck_gkr_binding_digest")
        initial_target = decode_canonical_fp16(initial[328:392], 0)
        if initial_target != expected_target:
            raise SystemExit("authenticated_sumcheck_gkr_target")
        mask_target = decode_canonical_fp16(initial[392:456], 0)
        epsilon = public_coin.challenge(800, initial)
        process.stdin.write(
            b"BLT8CH01"
            + (2).to_bytes(4, "big")
            + fp16_bytes(epsilon)
        )
        process.stdin.flush()
        challenges = []
        message_mb = 0.0
        endpoints = []
        for mask in range(SUMCHECK_ROUNDS):
            endpoint = fp16_from_words(
                mask_words,
                mask * AUX_DIMENSION,
            )
            for coefficient in range(AUX_MESSAGE_VALUES):
                endpoint = add(
                    endpoint,
                    fp16_from_words(
                        mask_words,
                        mask * AUX_DIMENSION + coefficient,
                    ),
                )
            endpoints.append(endpoint)
        endpoints = tuple(endpoints)
        local_mask_target = scale(
            sum_fp16(endpoints),
            fp16_value(1 << (SUMCHECK_ROUNDS - 1)),
        )
        if local_mask_target != mask_target:
            raise SystemExit("sumcheck_mask_layout_target_mismatch")
        active_words = GLOBAL_WORDS
        for round_ordinal in range(SUMCHECK_ROUNDS):
            launch_row_message(
                runtime,
                row_kernels,
                source_states,
                relation_states,
                message_buffer,
                active_words,
                ROW_STATES,
            )
            source_words = copy_fp16_words(
                runtime,
                message_buffer,
                f"copy_compact_row_message_{round_ordinal}",
            )
            source_quadratic = tuple(
                fp16_from_words(source_words, index)
                for index in range(3)
            )
            process.stdin.write(
                b"BLT8SQ01"
                + round_ordinal.to_bytes(4, "big")
                + b"".join(
                    fp16_bytes(coefficient)
                    for coefficient in source_quadratic
                )
            )
            process.stdin.flush()
            try:
                header = read_exact_pipe(
                    process.stdout,
                    16,
                    "authenticated_sumcheck_round_header_"
                    f"{round_ordinal}",
                )
            except SystemExit as error:
                status = process.wait(timeout=10)
                stderr = process.stderr.read()
                raise SystemExit(
                    "authenticated_sumcheck_round_eof="
                    f"{round_ordinal};status={status};"
                    f"stderr={stderr!r};read={error}"
                ) from error
            if (
                header[:8] != b"BLT8HR04"
                or int.from_bytes(header[8:12], "big")
                != round_ordinal
            ):
                raise SystemExit(
                    "authenticated_sumcheck_round_header="
                    f"{round_ordinal}:{header!r}"
                )
            message_length = int.from_bytes(header[12:], "big")
            if message_length != AUX_MESSAGE_VALUES * core.FP16_BYTES:
                raise SystemExit(
                    "authenticated_sumcheck_message_size="
                    f"{message_length}"
                )
            message = read_exact_pipe(
                process.stdout,
                message_length,
                "authenticated_sumcheck_message",
            )
            challenge = public_coin.challenge(
                801,
                header + message,
            )
            process.stdin.write(
                b"BLT8CH01"
                + (round_ordinal + 3).to_bytes(4, "big")
                + fp16_bytes(challenge)
            )
            process.stdin.flush()
            mask_evaluation_message = read_exact_pipe(
                process.stdout,
                12 + core.FP16_BYTES,
                f"authenticated_sumcheck_mask_evaluation_{round_ordinal}",
            )
            if (
                mask_evaluation_message[:8] != b"BLT8ME01"
                or int.from_bytes(
                    mask_evaluation_message[8:12],
                    "big",
                )
                != round_ordinal
            ):
                raise SystemExit(
                    "authenticated_sumcheck_mask_evaluation_header="
                    f"{round_ordinal}:{mask_evaluation_message[:12]!r}"
            )
            challenges.append(challenge)
            decode_canonical_fp16(
                mask_evaluation_message[12:],
                0,
            )
            launch_row_fold(
                runtime,
                row_kernels["fold"],
                source_states,
                relation_states,
                challenge,
                active_words,
                ROW_STATES,
            )
            active_words //= 2
            message_mb += message_length / 1_000_000
        final = read_exact_pipe(
            process.stdout,
            208,
            "authenticated_sumcheck_final",
        )
        if final[:8] != b"BLT8SF04":
            raise SystemExit(
                f"authenticated_sumcheck_final={final[:8]!r}"
            )
        terminal_target = decode_canonical_fp16(final[8:72], 0)
        source_terminal = decode_canonical_fp16(final[72:136], 0)
        mask_terminal = decode_canonical_fp16(final[136:200], 0)
        compute_seconds = struct.unpack(">d", final[200:])[0]
        launch_row_terminal(
            runtime,
            row_kernels["terminal"],
            source_states,
            relation_states,
            message_buffer,
            ROW_STATES,
        )
        terminal_words = copy_fp16_words(
            runtime,
            message_buffer,
            "copy_compact_row_terminal",
        )
        if fp16_from_words(terminal_words, 0) != source_terminal:
            raise SystemExit("compact_row_terminal_mismatch")
        gkr_terminal_buffer = allocator.allocate_count(
            2 * GKR_MASK_STATES,
            core.FP16_BYTES,
        )
        launch(
            runtime,
            row_kernels["gkr_terminals"],
            GKR_MASK_STATES,
            arguments(
                ctypes.c_uint64(source_states.pointer),
                ctypes.c_uint64(relation_states.pointer),
                ctypes.c_uint64(gkr_terminal_buffer.pointer),
                ctypes.c_uint32(GKR_ROW_STATES),
            ),
            "copy_gkr_mask_row_terminals",
        )
        core.ck(
            runtime.cuda.cuCtxSynchronize(),
            "copy_gkr_mask_row_terminals_sync",
        )
        gkr_terminal_words = copy_fp16_words(
            runtime,
            gkr_terminal_buffer,
            "copy_gkr_mask_row_terminal_values",
        )
        gkr_source_terminals = tuple(
            fp16_from_words(gkr_terminal_words, index)
            for index in range(GKR_MASK_STATES)
        )
        gkr_relation_terminals = tuple(
            fp16_from_words(
                gkr_terminal_words,
                GKR_MASK_STATES + index,
            )
            for index in range(GKR_MASK_STATES)
        )
        row_seconds = time.perf_counter() - row_started
        process.stdin.close()
        trailing = process.stdout.read()
        status = process.wait(timeout=10)
        stderr = process.stderr.read()
        if status != 0 or stderr or trailing:
            raise SystemExit(
                "authenticated_sumcheck_finish="
                f"status={status};stderr={stderr!r};trailing={trailing!r}"
            )
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)
        for buffer in (
            message_buffer,
            gkr_terminal_buffer,
            relation_states,
            source_states,
            claim_boundaries_buffer,
            claim_powers_buffer,
            gkr_scale_buffer,
            gkr_weight_buffer,
            coordinate_map_buffer,
            high_points,
        ):
            if buffer is not None and buffer.pointer in allocator.sizes:
                allocator.free(buffer)
    return {
            "claim_challenge": claim_challenge,
            "coordinate_challenge": coordinate_challenge,
            "coefficient_mixing": coefficient_mixing,
        "initial_target": initial_target,
        "mask_target": mask_target,
        "epsilon": epsilon,
        "challenges": tuple(challenges),
        "terminal_target": terminal_target,
        "source_terminal": source_terminal,
        "mask_terminal": mask_terminal,
        "compute_seconds": compute_seconds,
        "row_parameter_seconds": row_parameter_seconds,
        "row_seconds": row_seconds,
        "wall_seconds": time.perf_counter() - started,
        "message_mb": message_mb,
        "gkr_source_terminals": gkr_source_terminals,
        "gkr_relation_terminals": gkr_relation_terminals,
    }


def run_row_parameters(
    executable,
    claim_challenge,
    coordinate_challenge,
    claims,
):
    payload = (
        b"BLRSPA01"
        + fp16_bytes(claim_challenge)
        + fp16_bytes(coordinate_challenge)
        + b"".join(encode_gkr_claim(claim) for claim in claims)
    )
    result = subprocess.run(
        [str(executable), "--parameters"],
        input=payload,
        capture_output=True,
        check=False,
    )
    expected_size = (
        8
        + core.FP16_BYTES
        + 16 * core.FP16_BYTES
        + GKR_CLAIM_COUNT * core.FP16_BYTES
        + 8
    )
    if (
        result.returncode
        or result.stderr
        or len(result.stdout) != expected_size
        or result.stdout[:8] != b"BLRSPA02"
    ):
        raise SystemExit(
            "row_parameter_derivation_failed="
            f"{result.returncode};size={len(result.stdout)}/"
            f"{expected_size};stderr={result.stderr!r}"
        )
    offset = 8
    target = decode_canonical_fp16(
        result.stdout[offset : offset + core.FP16_BYTES],
        0,
    )
    offset += core.FP16_BYTES
    coordinate_map = tuple(
        decode_canonical_fp16(
            result.stdout[
                offset + index * core.FP16_BYTES :
                offset + (index + 1) * core.FP16_BYTES
            ],
            0,
        )
        for index in range(16)
    )
    offset += 16 * core.FP16_BYTES
    claim_powers = tuple(
        decode_canonical_fp16(
            result.stdout[
                offset + index * core.FP16_BYTES :
                offset + (index + 1) * core.FP16_BYTES
            ],
            0,
        )
        for index in range(GKR_CLAIM_COUNT)
    )
    return (
        target,
        coordinate_map,
        claim_powers,
        struct.unpack(">d", result.stdout[-8:])[0],
    )


def sum_fp16(values):
    result = ZERO
    for value in values:
        result = add(result, value)
    return result


def polynomial_eval(coefficients, point):
    value = ZERO
    for coefficient in reversed(coefficients):
        value = add(mul16(value, point), coefficient)
    return value


def launch_row_message(
    runtime,
    kernels,
    source,
    relation,
    message,
    active_words,
    state_count,
):
    core.ck(
        runtime.cuda.cuLaunchKernel(
            kernels["message"],
            1,
            1,
            1,
            128,
            1,
            1,
            0,
            None,
            arguments(
                ctypes.c_uint64(source.pointer),
                ctypes.c_uint64(relation.pointer),
                ctypes.c_uint64(message.pointer),
                ctypes.c_uint32(active_words),
                ctypes.c_uint32(state_count),
            ),
            None,
        ),
        "compact_row_quadratic_message",
    )
    core.ck(
        runtime.cuda.cuCtxSynchronize(),
        "compact_row_quadratic_message_sync",
    )


def launch_row_fold(
    runtime,
    kernel,
    source,
    relation,
    challenge,
    active_words,
    state_count,
):
    core.ck(
        runtime.cuda.cuLaunchKernel(
            kernel,
            state_count,
            1,
            1,
            256,
            1,
            1,
            0,
            None,
            arguments(
                ctypes.c_uint64(source.pointer),
                ctypes.c_uint64(relation.pointer),
                (ctypes.c_uint32 * 16)(*challenge),
                ctypes.c_uint32(active_words),
                ctypes.c_uint32(state_count),
            ),
            None,
        ),
        "fold_compact_row_states",
    )
    core.ck(
        runtime.cuda.cuCtxSynchronize(),
        "fold_compact_row_states_sync",
    )


def launch_row_terminal(
    runtime,
    kernel,
    source,
    relation,
    terminal,
    state_count,
):
    core.ck(
        runtime.cuda.cuLaunchKernel(
            kernel,
            1,
            1,
            1,
            128,
            1,
            1,
            0,
            None,
            arguments(
                ctypes.c_uint64(source.pointer),
                ctypes.c_uint64(relation.pointer),
                ctypes.c_uint64(terminal.pointer),
                ctypes.c_uint32(state_count),
            ),
            None,
        ),
        "compact_row_terminal",
    )
    core.ck(
        runtime.cuda.cuCtxSynchronize(),
        "compact_row_terminal_sync",
    )


class NativeAnswerCodeVerifier:
    def __init__(
        self,
        executable,
        main_queries,
        auxiliary_queries,
        claim_challenge,
        coordinate_challenge,
        gkr_claims,
        challenges,
        gkr_relation_terminals,
        main_scale,
        state_squarefree_answer_binding,
        expected_target,
        main_coefficients,
        auxiliary_coefficients,
    ):
        expected_main_size = MAIN_DIMENSION * core.FP16_BYTES
        expected_auxiliary_size = (
            AUXILIARY_WORDS * AUX_DIMENSION * core.FP16_BYTES
        )
        if (
            len(main_queries) != MAIN_QUERY_COUNT
            or len(auxiliary_queries) != AUX_QUERY_COUNT
            or tuple(sorted(set(main_queries))) != tuple(main_queries)
            or tuple(sorted(set(auxiliary_queries)))
            != tuple(auxiliary_queries)
            or len(main_coefficients) != expected_main_size
            or len(auxiliary_coefficients) != expected_auxiliary_size
            or len(gkr_relation_terminals) != GKR_MASK_STATES
            or not state_squarefree_answer_binding
        ):
            raise SystemExit("native_answer_code_input_shape")
        self.process = subprocess.Popen(
            [str(executable)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )
        self.closed = False
        self.started = time.perf_counter()
        self.output = None
        self.stderr = None
        self.status = None
        self.ended = None
        self.collection_error = None
        self.collector = None
        try:
            self.process.stdin.write(b"BLRSCV04")
            self.process.stdin.write(
                struct.pack(
                    ">7I",
                    core.BASE_CODE_LOG,
                    MAIN_DIMENSION,
                    AUX_CODE_LOG,
                    AUX_DIMENSION,
                    AUXILIARY_WORDS,
                    MAIN_QUERY_COUNT,
                    AUX_QUERY_COUNT,
                )
            )
            self.process.stdin.write(
                struct.pack(
                    f">{MAIN_QUERY_COUNT}I",
                    *main_queries,
                )
            )
            self.process.stdin.write(
                struct.pack(
                    f">{AUX_QUERY_COUNT}I",
                    *auxiliary_queries,
                )
            )
            self.process.stdin.write(fp16_bytes(claim_challenge))
            self.process.stdin.write(fp16_bytes(coordinate_challenge))
            for claim in gkr_claims:
                self.process.stdin.write(encode_gkr_claim(claim))
            for challenge in challenges:
                self.process.stdin.write(fp16_bytes(challenge))
            for terminal in gkr_relation_terminals:
                self.process.stdin.write(fp16_bytes(terminal))
            self.process.stdin.write(fp16_bytes(main_scale))
            self.process.stdin.write(state_squarefree_answer_binding)
            self.process.stdin.write(fp16_bytes(expected_target))
            self.process.stdin.write(main_coefficients)
            self.process.stdin.write(auxiliary_coefficients)
            self.process.stdin.close()
            self.process.stdin = None
            self.collector = threading.Thread(
                target=self._collect,
                name="native-answer-code-verifier",
                daemon=True,
            )
            self.collector.start()
        except BaseException:
            self.abort()
            raise

    def _collect(self):
        try:
            self.output, self.stderr = self.process.communicate()
            self.status = self.process.returncode
        except BaseException as error:
            self.collection_error = error
        finally:
            self.ended = time.perf_counter()

    def finish(self):
        if self.closed or self.collector is None:
            raise SystemExit("native_answer_code_state")
        self.collector.join(timeout=30)
        if self.collector.is_alive():
            self.abort()
            raise SystemExit("native_answer_code_timeout")
        self.closed = True
        if self.collection_error is not None:
            raise self.collection_error
        wall_seconds = self.ended - self.started
        expected_output_size = (
            20
            + MAIN_QUERY_COUNT * core.FP16_BYTES
            + AUX_QUERY_COUNT
            * AUXILIARY_WORDS
            * core.FP16_BYTES
        )
        if (
            self.status != 0
            or self.stderr
            or len(self.output) != expected_output_size
            or self.output[:8] != b"BLRSCO01"
        ):
            raise SystemExit(
                "native_answer_code_failed="
                f"status={self.status};"
                f"size={len(self.output)}/{expected_output_size};"
                f"magic={self.output[:8]!r};stderr={self.stderr!r}"
            )
        compute_seconds = struct.unpack(">d", self.output[8:16])[0]
        workers = int.from_bytes(self.output[16:20], "big")
        main_end = 20 + MAIN_QUERY_COUNT * core.FP16_BYTES
        return (
            self.output[20:main_end],
            self.output[main_end:],
            compute_seconds,
            wall_seconds,
            workers,
        )

    def abort(self):
        if self.closed:
            return
        self.closed = True
        if self.process.poll() is None:
            self.process.kill()
        if self.collector is not None:
            self.collector.join(timeout=10)
        else:
            self.process.wait(timeout=10)


def run_native_answer_target(
    executable,
    claim_challenge,
    coordinate_challenge,
    gkr_claims,
    challenges,
    gkr_relation_terminals,
    main_scale,
    state_squarefree_answer_binding,
    main_coefficients,
    auxiliary_coefficients,
    memory,
):
    expected_main_size = MAIN_DIMENSION * core.FP16_BYTES
    expected_auxiliary_size = (
        AUXILIARY_WORDS * AUX_DIMENSION * core.FP16_BYTES
    )
    if (
        len(gkr_claims) != GKR_CLAIM_COUNT
        or len(challenges) != SUMCHECK_ROUNDS
        or len(gkr_relation_terminals) != GKR_MASK_STATES
        or len(main_coefficients) != expected_main_size
        or len(auxiliary_coefficients) != expected_auxiliary_size
        or not state_squarefree_answer_binding
    ):
        raise SystemExit("native_answer_target_input_shape")
    process = subprocess.Popen(
        [str(executable)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
    )
    memory.child_process_id = process.pid
    started = time.perf_counter()
    try:
        process.stdin.write(b"BLRSTA02")
        process.stdin.write(fp16_bytes(claim_challenge))
        process.stdin.write(fp16_bytes(coordinate_challenge))
        for claim in gkr_claims:
            process.stdin.write(encode_gkr_claim(claim))
        for challenge in challenges:
            process.stdin.write(fp16_bytes(challenge))
        for terminal in gkr_relation_terminals:
            process.stdin.write(fp16_bytes(terminal))
        process.stdin.write(fp16_bytes(main_scale))
        process.stdin.write(state_squarefree_answer_binding)
        process.stdin.write(main_coefficients)
        process.stdin.write(auxiliary_coefficients)
        process.stdin.close()
        output = process.stdout.read()
        stderr = process.stderr.read()
        status = process.wait(timeout=30)
    except BaseException:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=10)
        raise
    finally:
        memory.child_process_id = None
    wall_seconds = time.perf_counter() - started
    if (
        status != 0
        or stderr
        or len(output) != 84
        or output[:8] != b"BLRSTO01"
    ):
        raise SystemExit(
            "native_answer_target_failed="
            f"status={status};size={len(output)}/84;"
            f"magic={output[:8]!r};stderr={stderr!r}"
        )
    return (
        decode_canonical_fp16(output[8:72], 0),
        struct.unpack(">d", output[72:80])[0],
        wall_seconds,
        int.from_bytes(output[80:84], "big"),
    )


class NativeSpotcheckVerifier:
    def __init__(self, executable, weights, combination):
        self.process = subprocess.Popen(
            [str(executable)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )
        self.closed = False
        self.initial_segments = 0
        self.started = time.perf_counter()
        self.process.stdin.write(
            b"BLSPOT03"
            + struct.pack(
                ">2I",
                INITIAL_SEGMENT_COUNT,
                core.INTERLEAVINGS_PER_SEGMENT,
            )
        )
        for weight in weights:
            self.process.stdin.write(fp16_bytes(weight))
        self.process.stdin.write(fp16_bytes(combination))
        self.process.stdin.flush()

    def write_initial_segment(self, leaves):
        if self.initial_segments >= INITIAL_SEGMENT_COUNT:
            raise SystemExit("native_spotcheck_initial_overflow")
        if len(leaves) != MAIN_QUERY_COUNT * core.ROW_BYTES:
            raise SystemExit(
                "native_spotcheck_initial_size="
                f"{len(leaves)}"
            )
        self.process.stdin.write(leaves)
        self.process.stdin.flush()
        self.initial_segments += 1

    def finish(
        self,
        sumcheck,
        gkr_mask,
        state_squarefree_coefficients,
        base_main,
        base_auxiliary,
        answer_main,
        answer_auxiliary,
    ):
        finish_started = time.perf_counter()
        if self.initial_segments != INITIAL_SEGMENT_COUNT:
            raise SystemExit(
                "native_spotcheck_initial_count="
                f"{self.initial_segments}"
            )
        for payload in (
            sumcheck,
            gkr_mask,
            state_squarefree_coefficients,
            base_main,
            base_auxiliary,
            answer_main,
            answer_auxiliary,
        ):
            self.process.stdin.write(payload)
        self.process.stdin.close()
        output = self.process.stdout.read()
        status = self.process.wait(timeout=10)
        stderr = self.process.stderr.read()
        self.closed = True
        wall_seconds = time.perf_counter() - self.started
        if (
            status != 0
            or stderr
            or len(output) != 16
            or output[:8] != b"BLSPOUT1"
        ):
            raise SystemExit(
                "native_spotcheck_failed="
                f"status={status};output={output!r};stderr={stderr!r}"
            )
        return (
            struct.unpack(">d", output[8:])[0],
            wall_seconds,
            time.perf_counter() - finish_started,
        )

    def abort(self):
        if self.closed:
            return
        self.closed = True
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(timeout=10)


def launch_256(runtime, kernel, blocks, parameters, label):
    core.ck(
        runtime.cuda.cuLaunchKernel(
            kernel,
            blocks,
            1,
            1,
            256,
            1,
            1,
            0,
            None,
            parameters,
            None,
        ),
        label,
    )


def launch_2d_256(
    runtime,
    kernel,
    count,
    parameters,
    label,
    grid_y,
):
    blocks = (count + 255) // 256
    core.ck(
        runtime.cuda.cuLaunchKernel(
            kernel,
            blocks,
            grid_y,
            1,
            256,
            1,
            1,
            0,
            None,
            parameters,
            None,
        ),
        label,
    )


def launch_3d_256(
    runtime,
    kernel,
    grid_x,
    grid_y,
    grid_z,
    parameters,
    label,
):
    core.ck(
        runtime.cuda.cuLaunchKernel(
            kernel,
            grid_x,
            grid_y,
            grid_z,
            256,
            1,
            1,
            0,
            None,
            parameters,
            None,
        ),
        label,
    )


def compile_runtime(nvrtc):
    precompiled = os.environ.get("BL_PRECOMPILED_CUDA_MODULE")
    expected_hash = os.environ.get(
        "BL_PRECOMPILED_CUDA_MODULE_SHA256"
    )
    if precompiled is not None or expected_hash is not None:
        if not precompiled or not expected_hash:
            raise SystemExit("precompiled_cuda_module_hash_gate_incomplete")
        path = Path(precompiled)
        if not path.is_file():
            raise SystemExit("precompiled_cuda_module_missing")
        started = time.perf_counter()
        module_image = path.read_bytes()
        actual_hash = hashlib.sha256(module_image).hexdigest()
        if actual_hash != expected_hash.lower():
            raise SystemExit(
                "precompiled_cuda_module_hash_mismatch="
                f"{actual_hash}/{expected_hash.lower()}"
            )
        if module_image[:4] != b"\x7fELF":
            raise SystemExit("precompiled_cuda_module_not_cubin")
        return (
            core.DriverRuntime(module_image),
            time.perf_counter() - started,
        )
    descriptor, name = tempfile.mkstemp(
        prefix="bl-fp16-zk-rs-theorem8-",
        suffix=".cubin",
    )
    os.close(descriptor)
    path = Path(name)
    started = time.perf_counter()
    try:
        process = subprocess.run(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "--compile-cubin",
                str(path),
            ],
            check=False,
            capture_output=True,
            env=os.environ.copy(),
        )
        if process.returncode:
            raise SystemExit(
                "isolated_nvrtc_theorem8_compile_failed="
                f"{process.returncode};stderr={process.stderr!r}"
            )
        module_image = path.read_bytes()
    finally:
        path.unlink(missing_ok=True)
    if module_image[:4] != b"\x7fELF":
        raise SystemExit("compiled_cuda_module_not_cubin")
    return (
        core.DriverRuntime(module_image),
        time.perf_counter() - started,
    )


def compile_child(nvrtc, output, module_format):
    compile_function = (
        core.compile_source_to_ptx
        if module_format == "ptx"
        else core.compile_source_to_cubin
    )
    compile_function(
        nvrtc,
        core.CUDA
        + core.EXTRA
        + core.SHA3_KERNEL
        + core.SEGMENT_MERKLE_KERNEL
        + core.RS_KERNEL
        + IOPP_KERNEL,
        output,
    )


def load_semantic_b16_shard(path, shard):
    path = Path(path)
    if not path.is_file() or shard < 0 or shard > 0xFFFF:
        raise SystemExit("semantic_b16_path_or_shard")
    with path.open("rb") as source:
        header = source.read(HASH_BUS_B16_HEADER_BYTES)
        if len(header) != HASH_BUS_B16_HEADER_BYTES:
            raise SystemExit("semantic_b16_header_short")
        state_composed = header[:8] == b"BLHBB102" and int.from_bytes(
            header[8:10], "big"
        ) == 2
        if not (
            (header[:8] == b"BLHBB101" and int.from_bytes(header[8:10], "big") == 1)
            or state_composed
        ):
            raise SystemExit("semantic_b16_header_magic")
        profile = header[10]
        commitments = (
            header[11:75],
            header[75:139],
            header[139:203],
        )
        shards = int.from_bytes(header[203:205], "big")
        padded_permutations = int.from_bytes(
            header[205:213], "big"
        )
        live_wires = int.from_bytes(header[213:215], "big")
        expected_bytes = (
            HASH_BUS_B16_HEADER_BYTES
            + shards * HASH_BUS_B16_SHARD_BYTES
        )
        actual_bytes = path.stat().st_size
        if (
            profile not in (1, 3)
            or shards not in (1, 4)
            or shard >= shards
            or padded_permutations != shards * 131_072
            or live_wires != 1_600
            or actual_bytes != expected_bytes
            or any(
                len(commitment) != 64 or not any(commitment)
                for commitment in commitments
            )
        ):
            raise SystemExit("semantic_b16_header_shape")
        source.seek(0)
        digest = hashlib.sha3_512()
        shard_start = (
            HASH_BUS_B16_HEADER_BYTES
            + shard * HASH_BUS_B16_SHARD_BYTES
        )
        shard_end = shard_start + HASH_BUS_B16_SHARD_BYTES
        payload = bytearray(HASH_BUS_B16_SHARD_BYTES)
        position = 0
        captured = 0
        while True:
            chunk = source.read(1 << 20)
            if not chunk:
                break
            digest.update(chunk)
            chunk_end = position + len(chunk)
            overlap_start = max(position, shard_start)
            overlap_end = min(chunk_end, shard_end)
            if overlap_start < overlap_end:
                source_start = overlap_start - position
                destination_start = overlap_start - shard_start
                length = overlap_end - overlap_start
                payload[
                    destination_start : destination_start + length
                ] = chunk[source_start : source_start + length]
                captured += length
            position = chunk_end
        if position != expected_bytes or captured != HASH_BUS_B16_SHARD_BYTES:
            raise SystemExit("semantic_b16_shard_short")
    # BLHBB101 is canonical input-then-output. The selected PCS grammar is
    # intentionally output boundary 0 and input boundary 1. Reorder only the
    # private in-process view; the authenticated file bytes remain unchanged.
    boundary_bytes = HASH_BUS_B16_SHARD_BYTES // 2
    payload = bytes(payload[boundary_bytes:] + payload[:boundary_bytes])
    return {
        "path": path,
        "shard": shard,
        "profile": profile,
        "shards": shards,
        "state_composed": state_composed,
        "commitments": commitments,
        "file_sha3_512": digest.digest(),
        "payload": payload,
    }


def load_state_relation_source():
    if os.environ.get("BL_TYPED_STATE_BINDING") == "1":
        return None
    encoded_path = os.environ.get("BL_STATE_RELATION_SOURCE_PATH")
    encoded_digest = os.environ.get("BL_STATE_RELATION_SOURCE_SHA3_512")
    if encoded_path is None and encoded_digest is None:
        return None
    if encoded_path is None or encoded_digest is None:
        raise SystemExit("state_relation_source_environment")
    path = Path(encoded_path)
    if path.is_symlink() or not path.is_file():
        raise SystemExit("state_relation_source_path")
    if len(encoded_digest) != 128:
        raise SystemExit("state_relation_source_digest_length")
    try:
        expected_digest = bytes.fromhex(encoded_digest)
    except ValueError as error:
        raise SystemExit("state_relation_source_digest_encoding") from error
    if len(expected_digest) != 64 or not any(expected_digest):
        raise SystemExit("state_relation_source_digest_shape")
    expected_bytes = 4_096 * 64 * core.FP16_BYTES
    if path.stat().st_size != expected_bytes:
        raise SystemExit("state_relation_source_size")
    digest = hashlib.sha3_512(
        b"BL/PQ512/WAVE2/STATE-RELATION-SOURCE/v2\0"
        + expected_bytes.to_bytes(8, "big")
    )
    payload = bytearray()
    with path.open("rb") as source:
        while True:
            chunk = source.read(1 << 20)
            if not chunk:
                break
            digest.update(chunk)
            payload.extend(chunk)
    actual_digest = digest.digest()
    if actual_digest != expected_digest:
        raise SystemExit("state_relation_source_digest_mismatch")
    return {
        "path": path,
        "digest": expected_digest,
        "words": canonical_fp16_word_array(
            bytes(payload),
            expected_bytes // core.FP16_BYTES,
            "state_relation_source",
        ),
    }


def atomic_parent_binding():
    encoded = os.environ.get("BL_ATOMIC_PARENT_BINDING")
    if encoded is None:
        return None
    if len(encoded) != 128:
        raise SystemExit("atomic_parent_binding_length")
    try:
        binding = bytes.fromhex(encoded)
    except ValueError as error:
        raise SystemExit("atomic_parent_binding_encoding") from error
    if len(binding) != 64 or not any(binding):
        raise SystemExit("atomic_parent_binding_shape")
    return binding


def qualified_proof_suite_id():
    encoded = os.environ.get("BL_PROOF_SUITE_ID")
    if encoded is None:
        return None
    if len(encoded) != 128:
        raise SystemExit("proof_suite_id_length")
    try:
        value = bytes.fromhex(encoded)
    except ValueError as error:
        raise SystemExit("proof_suite_id_encoding") from error
    if len(value) != 64 or not any(value):
        raise SystemExit("proof_suite_id_shape")
    return value


def atomic_state_binding():
    typed_state = os.environ.get("BL_TYPED_STATE_BINDING") == "1"
    digest_fields = [
        ("statement", "BL_STATE_PLANE_STATEMENT_DIGEST"),
        ("binding", "BL_STATE_PLANE_BINDING_DIGEST"),
        ("projection_digest", "BL_STATE_PLANE_PROJECTION_DIGEST"),
        ("public_coin", "BL_STATE_PLANE_PUBLIC_COIN"),
        ("transition", "BL_STATE_PLANE_TRANSITION_DIGEST"),
        ("commitment", "BL_STATE_PLANE_COMMITMENT_DIGEST"),
        ("proof", "BL_STATE_PLANE_PROOF_IDENTITY"),
        ("verifier", "BL_STATE_PLANE_VERIFIER_IDENTITY"),
        ("attempt", "BL_STATE_PLANE_ATTEMPT_ID"),
        ("receipt", "BL_STATE_PLANE_RECEIPT_DIGEST"),
        ("composition", "BL_STATE_PLANE_COMPOSITION_DIGEST"),
        ("state_air_program", "BL_STATE_AIR_PROGRAM_COMMITMENT"),
        ("state_air_execution", "BL_STATE_AIR_EXECUTION_COMMITMENT"),
        ("state_air_fragment", "BL_STATE_AIR_FRAGMENT_DIGEST"),
    ]
    if typed_state:
        digest_fields.extend(
            (
                ("typed_state_root_before", "BL_TYPED_STATE_ROOT_BEFORE"),
                ("typed_state_root_after", "BL_TYPED_STATE_ROOT_AFTER"),
            )
        )
    else:
        digest_fields.append(("state_relation_source", "BL_STATE_RELATION_SOURCE_SHA3_512"))
    public_abi_environments = tuple(
        f"BL_STATE_PLANE_PUBLIC_ABI_{index:02}" for index in range(12)
    )
    attached = any(
        os.environ.get(environment) is not None
        for _, environment in digest_fields
    ) or typed_state or any(os.environ.get(environment) is not None for environment in public_abi_environments)
    if not attached:
        return None

    def decode(label, encoded):
        if encoded is None:
            raise SystemExit(f"{label}_missing")
        if len(encoded) != 128:
            raise SystemExit(f"{label}_length")
        try:
            value = bytes.fromhex(encoded)
        except ValueError as error:
            raise SystemExit(f"{label}_encoding") from error
        if len(value) != 64 or not any(value):
            raise SystemExit(f"{label}_shape")
        return value

    result = {
        label: decode(label, os.environ.get(environment))
        for label, environment in digest_fields
    }
    public_abi = []
    for index in range(12):
        label = f"state_plane_public_abi_{index:02}"
        encoded = os.environ.get(f"BL_STATE_PLANE_PUBLIC_ABI_{index:02}")
        if encoded is None:
            raise SystemExit(f"{label}_missing")
        if len(encoded) != 64:
            raise SystemExit(f"{label}_length")
        try:
            value = bytes.fromhex(encoded)
        except ValueError as error:
            raise SystemExit(f"{label}_encoding") from error
        if len(value) != 32 or not any(value):
            raise SystemExit(f"{label}_shape")
        public_abi.append(value)
    result["public_abi"] = tuple(public_abi)
    result["typed_state"] = typed_state
    if atomic_parent_binding() is None:
        raise SystemExit("state_plane_binding_without_parent")
    return result


def public_coin_identity(gkr_mask_root, state_binding, public_coin_rounds):
    parent_binding = atomic_parent_binding()
    parent_suffix = (
        b""
        if parent_binding is None
        else b"BL/PQ512/FP16-ZK-RS/ATOMIC-PARENT/v1\0"
        + parent_binding
    )
    state_suffix = b""
    if state_binding is not None:
        state_suffix = (
            b"BL/PQ512/STATE-PLANE/AUTHENTIC-TRANSCRIPT/v1\0"
            + state_binding["statement"]
            + state_binding["binding"]
            + state_binding["projection_digest"]
            + b"".join(state_binding["public_abi"])
            + state_binding["public_coin"]
            + state_binding["transition"]
            + state_binding["commitment"]
            + state_binding["proof"]
            + state_binding["verifier"]
            + state_binding["attempt"]
            + state_binding["receipt"]
            + state_binding["composition"]
            + state_binding["state_air_program"]
            + state_binding["state_air_execution"]
            + state_binding["state_air_fragment"]
            + (
                state_binding["typed_state_root_before"]
                + state_binding["typed_state_root_after"]
                if state_binding.get("typed_state")
                else state_binding["state_relation_source"]
            )
        )
    session = hashlib.sha3_512(
        b"BL/PQ512/FP16-ZK-RS/COMPLETE-SESSION/v1"
        + gkr_mask_root
        + parent_suffix
        + state_suffix
    ).digest()
    schedule = hashlib.sha3_512(
        b"BL/PQ512/FP16-ZK-RS/COMPLETE-SCHEDULE/v1"
        + struct.pack(
            ">10I",
            SUMCHECK_ROUNDS,
            MAIN_DIMENSION,
            AUX_DIMENSION,
            MAIN_QUERY_COUNT,
            AUX_QUERY_COUNT,
            core.BASE_CODE_VALUES,
            AUX_CODE_VALUES,
            THEOREM_SEGMENT_COUNT,
            GKR_CLAIM_COUNT,
            public_coin_rounds,
        )
        + parent_suffix
        + state_suffix
    ).digest()
    return session, schedule


def main():
    nvrtc = Path(os.environ.get("BL_NVRTC_BIN", ""))
    if len(sys.argv) == 3 and sys.argv[1] in (
        "--compile-ptx",
        "--compile-cubin",
    ):
        compile_child(
            nvrtc,
            sys.argv[2],
            "ptx" if sys.argv[1] == "--compile-ptx" else "cubin",
        )
        return
    if len(sys.argv) != 1:
        raise SystemExit("usage: cuda_fp16_zk_rs_theorem8_1_k128_prototype.py")
    proof_process_started = time.perf_counter()
    state_binding = atomic_state_binding()
    state_relation_source = load_state_relation_source()
    if (
        state_binding is not None
        and not state_binding.get("typed_state", False)
    ) != (state_relation_source is not None):
        raise SystemExit("state_relation_source_binding_mismatch")
    if state_binding is not None and state_relation_source is not None and (
        state_binding["state_relation_source"] != state_relation_source["digest"]
    ):
        raise SystemExit("state_relation_source_binding_digest_mismatch")
    semantic_boundary_path = os.environ.get(
        "BL_HASH_BUS_B16_BOUNDARY"
    )
    semantic_source = None
    semantic_shard = 0
    semantic_worker_path = None
    if semantic_boundary_path:
        try:
            semantic_shard = int(
                os.environ.get("BL_HASH_BUS_B16_SHARD", "0")
            )
        except ValueError as error:
            raise SystemExit("semantic_b16_shard_encoding") from error
        semantic_worker_path = Path(
            os.environ.get(
                "BL_HASH_BUS_GKR_WORKER",
                Path(__file__).resolve().with_name(
                    "cuda_hash_bus_b16_gkr_worker.py"
                ),
            )
        )
        if not semantic_worker_path.is_file():
            raise SystemExit(
                f"semantic_gkr_worker_missing={semantic_worker_path}"
            )
    if not (nvrtc / "nvrtc64_120_0.dll").is_file():
        raise SystemExit("nvrtc_runtime_missing")
    native_release_directory = Path(
        os.environ.get(
            "BL_NATIVE_RELEASE_DIR",
            Path(__file__).resolve().parents[1] / "target" / "release",
        )
    )
    verifier_path = (
        Path(
            os.environ.get(
                "BL_MULTIPROOF_VERIFIER",
                native_release_directory
                / "fp16_zk_rs_interleaved_verify.exe",
            )
        )
    )
    transcript_path = (
        native_release_directory
        / "fp16_zk_rs_theorem8_1_transcript.exe"
    )
    spotcheck_path = (
        Path(
            os.environ.get(
                "BL_SPOTCHECK_VERIFIER",
                native_release_directory
                / "fp16_zk_rs_spotcheck_verify.exe",
            )
        )
    )
    answer_code_path = (
        native_release_directory
        / "fp16_zk_rs_answer_code_verify.exe"
    )
    answer_target_path = (
        native_release_directory
        / "fp16_zk_rs_answer_target.exe"
    )
    row_parameter_path = (
        native_release_directory
        / "fp16_zk_rs_row_sumcheck_prover.exe"
    )
    public_coin_path = (
        native_release_directory
        / "fp16_zk_rs_public_coin_bridge.exe"
    )
    for label, path in (
        ("verifier", verifier_path),
        ("transcript", transcript_path),
        ("spotcheck", spotcheck_path),
        ("answer_code", answer_code_path),
        ("answer_target", answer_target_path),
        ("row_parameter", row_parameter_path),
        ("public_coin", public_coin_path),
    ):
        if not path.is_file():
            raise SystemExit(f"native_{label}_missing={path}")

    public_coin = None
    prepared_public_coin = None
    semantic_prelude_started = None
    semantic_prelude_wall_seconds = 0.0
    if semantic_boundary_path:
        semantic_prelude_started = time.perf_counter()
        prepared_public_coin = NativePublicCoinBridge.prepare_nonuniform(
            public_coin_path,
            Path(semantic_boundary_path),
            semantic_shard,
            Path(sys.executable),
            semantic_worker_path,
            state_relation_source,
        )
        try:
            semantic_source = load_semantic_b16_shard(
                semantic_boundary_path,
                semantic_shard,
            )
        except BaseException:
            NativePublicCoinBridge.abort_prepared(
                prepared_public_coin
            )
            prepared_public_coin = None
            raise
        if (state_binding is not None) != semantic_source["state_composed"]:
            NativePublicCoinBridge.abort_prepared(prepared_public_coin)
            prepared_public_coin = None
            raise SystemExit("semantic_b16_state_composition_mismatch")
    elif state_binding is not None:
        raise SystemExit("state_binding_requires_semantic_boundary")
    path_gate_seconds = time.perf_counter() - proof_process_started

    gkr_mask_cpu_root = None
    gkr_mask_cpu_words = None
    gkr_mask_sampling_attempts = 0
    gkr_mask_cpu_compute_seconds = 0.0
    gkr_mask_cpu_commit_seconds = 0.0
    gkr_mask_cpu_workers = 0

    # The driver is currently reset-sensitive on this Windows build. All
    # orchestration below is fail-closed; no measurement is printed on error.
    try:
        (
            gkr_mask_cpu_root,
            gkr_mask_payload,
            gkr_mask_cpu_words,
            gkr_mask_sampling_attempts,
            gkr_mask_cpu_compute_seconds,
            gkr_mask_cpu_commit_seconds,
            gkr_mask_cpu_workers,
        ) = native_gkr_mask_commit(answer_code_path)
        public_coin_rounds = GKR_PRELUDE_ROUNDS + 13
        if state_relation_source is not None:
            if semantic_source is None or semantic_source["profile"] not in STATE_SQUAREFREE_ROUNDS:
                raise SystemExit("state_squarefree_profile")
            public_coin_rounds += STATE_SQUAREFREE_ROUNDS[
                semantic_source["profile"]
            ]
        public_coin_session, public_coin_schedule = public_coin_identity(
            gkr_mask_cpu_root,
            state_binding,
            public_coin_rounds,
        )
        if semantic_source is None:
            public_coin = NativePublicCoinBridge(
                public_coin_path,
                public_coin_session,
                public_coin_schedule,
                public_coin_rounds,
                gkr_mask_cpu_root,
                gkr_mask_payload,
                defer_gkr_prelude=True,
            )
        else:
            public_coin = NativePublicCoinBridge(
                public_coin_path,
                public_coin_session,
                public_coin_schedule,
                public_coin_rounds,
                gkr_mask_cpu_root,
                gkr_mask_payload,
                defer_gkr_prelude=True,
                semantic_boundary=semantic_source["path"],
                semantic_shard=semantic_source["shard"],
                semantic_python=Path(sys.executable),
                semantic_worker=semantic_worker_path,
                state_relation_source=state_relation_source,
                prepared=prepared_public_coin,
            )
            prepared_public_coin = None
        del gkr_mask_payload
        runtime, compile_seconds = compile_runtime(nvrtc)
    except BaseException:
        if public_coin is not None:
            public_coin.abort()
            public_coin = None
        NativePublicCoinBridge.abort_prepared(prepared_public_coin)
        raise
    verifier = None
    spotcheck_verifier = None
    answer_code_verifier = None
    memory = None
    semantic_source_buffer = None
    state_relation_source_buffer = None
    state_squarefree_coefficient_source = None
    state_squarefree_coefficient_tree = None
    try:
        core.bind_driver(runtime)
        runtime.cuda.cuMemcpyDtoD_v2.argtypes = [
            ctypes.c_uint64,
            ctypes.c_uint64,
            ctypes.c_size_t,
        ]
        allocator = core.Allocator(runtime)
        memory = core.ProofPhaseMemorySampler()
        memory.start()
        memory.child_process_id = public_coin.process.pid
        kernel_lookup_started = time.perf_counter()
        kernels = {
            "initialize": function(
                runtime,
                "initialize_batched_rs_coefficients",
            ),
            "initialize_real_gkr_source": function(
                runtime,
                "initialize_b16_zero_trace_rs_coefficients",
            ),
            "initialize_semantic_gkr_source": function(
                runtime,
                "initialize_b16_semantic_rs_coefficients",
            ),
            "coset": function(runtime, "apply_rs_coset"),
            "reverse": function(runtime, "bit_reverse_batched_rs"),
            "stage": function(runtime, "ntt_stage_batched_rs"),
            "transpose": function(
                runtime,
                "transpose_rs_rows_big_endian",
            ),
            "gather_nodes": function(runtime, "gather_rs_nodes"),
            "canonicalize_masks": function(
                runtime,
                "canonicalize_rs_mask_randomness",
            ),
        }
        expand = function(runtime, "expand_rs_powers")
        merkle = core.segment_merkle_functions(runtime)
        fixture_weights = function(
            runtime,
            "multilinear_coefficient_weights",
        )
        accumulate_folded = function(
            runtime,
            "accumulate_folded_real_gkr_coefficients",
        )
        accumulate_folded_semantic = function(
            runtime,
            "accumulate_folded_semantic_gkr_coefficients",
        )
        linear_combine = function(
            runtime,
            "linear_combine_coefficients",
        )
        component_evaluations = function(
            runtime,
            "compact_component_multilinear_evaluations",
        )
        semantic_component_evaluations = function(
            runtime,
            "semantic_component_multilinear_evaluations",
        )
        broadcast_component_evaluations = function(
            runtime,
            "broadcast_boundary_component_evaluations",
        )
        reduce_component_evaluations = function(
            runtime,
            "reduce_claim_component_evaluations",
        )
        row_kernels = {
            "initialize": function(
                runtime,
                "initialize_compact_row_states",
            ),
            "initialize_gkr_mask": function(
                runtime,
                "initialize_gkr_mask_row_states",
            ),
            "message": function(
                runtime,
                "compact_row_quadratic_message",
            ),
            "fold": function(
                runtime,
                "fold_compact_row_states",
            ),
            "terminal": function(
                runtime,
                "compact_row_terminal",
            ),
            "gkr_terminals": function(
                runtime,
                "copy_gkr_mask_row_terminals",
            ),
            "assemble_auxiliary": function(
                runtime,
                "assemble_complete_auxiliary_source",
            ),
        }
        kernel_lookup_seconds = (
            time.perf_counter() - kernel_lookup_started
        )
        if semantic_source is not None:
            semantic_source_buffer = core.upload(
                runtime,
                allocator,
                semantic_source["payload"],
                "upload_semantic_b16_shard",
            )
            del semantic_source["payload"]
        if state_relation_source is not None:
            state_relation_source_buffer = upload_fp16_word_array(
                runtime,
                allocator,
                state_relation_source["words"],
                "upload_state_relation_source",
            )
            del state_relation_source["words"]
        power_table_started = time.perf_counter()
        main_root_powers = core.power_table(
            runtime,
            allocator,
            expand,
            core.BASE_CODE_VALUES // 2,
            core.root_for_log(core.BASE_CODE_LOG),
            "theorem8_main_root_powers",
        )
        main_coset_powers = core.power_table(
            runtime,
            allocator,
            expand,
            core.BASE_CODE_VALUES,
            core.COSET,
            "theorem8_main_coset_powers",
        )
        aux_root_powers = core.power_table(
            runtime,
            allocator,
            expand,
            AUX_CODE_VALUES // 2,
            core.root_for_log(AUX_CODE_LOG),
            "theorem8_aux_root_powers",
        )
        aux_coset_powers = core.power_table(
            runtime,
            allocator,
            expand,
            AUX_CODE_VALUES,
            core.COSET,
            "theorem8_aux_coset_powers",
        )
        power_table_seconds = time.perf_counter() - power_table_started
        if gkr_mask_cpu_root is None or gkr_mask_cpu_words is None:
            raise SystemExit("gkr_mask_cpu_commit_state")
        gkr_mask_gpu_commit_started = time.perf_counter()
        gkr_mask = upload_fp16_word_array(
            runtime,
            allocator,
            gkr_mask_cpu_words,
            "upload_theorem8_gkr_mask",
        )
        del gkr_mask_cpu_words
        gkr_mask_cpu_words = None
        random_host = (ctypes.c_ubyte * 65_536)()
        sampling_attempts = gkr_mask_sampling_attempts
        gkr_mask_rows, _ = encode_random_batch(
            runtime,
            allocator,
            kernels,
            aux_root_powers,
            aux_coset_powers,
            gkr_mask,
            AUX_CODE_LOG,
            GLOBAL_WORDS,
            GKR_MASK_STATES,
        )
        gkr_mask_segment = core.OracleSegment(
            2,
            GKR_MASK_KIND,
            gkr_mask_rows,
            GKR_MASK_LEAF_SIZE,
        )
        gkr_mask_tree = core.retain_tree(
            runtime,
            allocator,
            merkle,
            gkr_mask_segment,
        )
        allocator.free(gkr_mask_rows)
        gkr_mask_gpu_commit_seconds = (
            time.perf_counter() - gkr_mask_gpu_commit_started
        )
        if gkr_mask_tree.root != gkr_mask_cpu_root:
            raise SystemExit(
                "gkr_mask_cpu_gpu_root_mismatch="
                f"{gkr_mask_cpu_root.hex()}/{gkr_mask_tree.root.hex()}"
            )
        gkr_mask_commit_seconds = (
            gkr_mask_cpu_commit_seconds
            + gkr_mask_gpu_commit_seconds
        )

        initial_randomness = []
        for index in range(INITIAL_SEGMENT_COUNT):
            buffer, attempts = core.exact_uniform_mask_buffer(
                runtime,
                allocator,
                kernels["canonicalize_masks"],
                core.INTERLEAVINGS_PER_SEGMENT,
                core.MASK_COEFFICIENTS,
                f"theorem8_initial_randomness_{index}",
                random_host,
            )
            initial_randomness.append(buffer)
            sampling_attempts += attempts
        sumcheck_randomness, attempts = core.exact_uniform_mask_buffer(
            runtime,
            allocator,
            kernels["canonicalize_masks"],
            SUMCHECK_ROUNDS,
            AUX_DIMENSION,
            "theorem8_sumcheck_masks",
            random_host,
        )
        sampling_attempts += attempts
        base_main, attempts = core.exact_uniform_mask_buffer(
            runtime,
            allocator,
            kernels["canonicalize_masks"],
            1,
            MAIN_DIMENSION,
            "theorem8_base_main_mask",
            random_host,
        )
        sampling_attempts += attempts
        base_aux, attempts = core.exact_uniform_mask_buffer(
            runtime,
            allocator,
            kernels["canonicalize_masks"],
            AUXILIARY_WORDS,
            AUX_DIMENSION,
            "theorem8_base_aux_masks",
            random_host,
        )
        sampling_attempts += attempts
        captured_component_sources = (
            allocator.allocate_count(
                core.BOUNDARY_COUNT * core.BASE_MESSAGE_VALUES,
                core.FP16_BYTES,
            )
            if semantic_source is None
            else None
        )
        component_evaluation_seconds = [0.0]

        started = time.perf_counter()
        initial_trees = []
        seed = 0
        global_word_base = 0
        for boundary in range(core.BOUNDARY_COUNT):
            for segment_index in range(core.SEGMENTS_PER_BOUNDARY):
                captured_word_base = global_word_base

                def capture_component_rows(
                    coefficient_buffer,
                    dimension,
                    word_base=captured_word_base,
                ):
                    if captured_component_sources is None:
                        return
                    if word_base not in (0, WORDS_PER_BOUNDARY):
                        return
                    capture_started = time.perf_counter()
                    boundary_offset = (
                        (word_base // WORDS_PER_BOUNDARY)
                        * core.BASE_MESSAGE_VALUES
                        * core.FP16_BYTES
                    )
                    copy_device(
                        runtime,
                        captured_component_sources.pointer
                        + boundary_offset,
                        coefficient_buffer.pointer,
                        core.BASE_MESSAGE_VALUES * core.FP16_BYTES,
                        "capture_live_component_source_"
                        f"{word_base // WORDS_PER_BOUNDARY}",
                    )
                    component_evaluation_seconds[0] += (
                        time.perf_counter() - capture_started
                    )

                row_major, _ = core.encode_segment(
                    runtime,
                    allocator,
                    kernels,
                    main_root_powers,
                    main_coset_powers,
                    initial_randomness[seed],
                    boundary,
                    segment_index,
                    initialized_callback=capture_component_rows,
                    initializer=(
                        kernels["initialize_semantic_gkr_source"]
                        if semantic_source is not None
                        else kernels["initialize_real_gkr_source"]
                    ),
                    initializer_context=(
                        semantic_source_buffer.pointer
                        if semantic_source_buffer is not None
                        else None
                    ),
                    initializer_auxiliary_context=(
                        state_relation_source_buffer.pointer
                        if state_relation_source_buffer is not None
                        else (0 if semantic_source_buffer is not None else None)
                    ),
                )
                segment = core.OracleSegment(
                    boundary,
                    core.SEGMENT_KIND_BASE + segment_index,
                    row_major,
                    core.ROW_BYTES,
                )
                initial_trees.append(
                    core.retain_tree(
                        runtime,
                        allocator,
                        merkle,
                        segment,
                    )
                )
                allocator.free(row_major)
                seed += 1
                global_word_base += (
                    core.INTERLEAVINGS_PER_SEGMENT
                )
        initial_commit_seconds = time.perf_counter() - started
        initial_set_root = core.segment_set_root(
            tuple(tree.segment for tree in initial_trees),
            tuple(tree.root for tree in initial_trees),
        )
        started = time.perf_counter()
        sumcheck_rows, _ = encode_random_batch(
            runtime,
            allocator,
            kernels,
            aux_root_powers,
            aux_coset_powers,
            sumcheck_randomness,
            AUX_CODE_LOG,
            AUX_DIMENSION,
            SUMCHECK_ROUNDS,
        )
        sumcheck_segment = core.OracleSegment(
            2,
            SUMCHECK_MASK_KIND,
            sumcheck_rows,
            SUMCHECK_LEAF_SIZE,
        )
        sumcheck_tree = core.retain_tree(
            runtime,
            allocator,
            merkle,
            sumcheck_segment,
        )
        allocator.free(sumcheck_rows)
        mask_commit_seconds = time.perf_counter() - started

        base_commit_started = time.perf_counter()
        base_main_rows, _ = encode_random_batch(
            runtime,
            allocator,
            kernels,
            main_root_powers,
            main_coset_powers,
            base_main,
            core.BASE_CODE_LOG,
            MAIN_DIMENSION,
            1,
        )
        base_main_segment = core.OracleSegment(
            2,
            BASE_MAIN_MASK_KIND,
            base_main_rows,
            MAIN_LEAF_SIZE,
        )
        base_main_tree = core.retain_tree(
            runtime,
            allocator,
            merkle,
            base_main_segment,
        )
        allocator.free(base_main_rows)
        base_aux_rows, _ = encode_random_batch(
            runtime,
            allocator,
            kernels,
            aux_root_powers,
            aux_coset_powers,
            base_aux,
            AUX_CODE_LOG,
            AUX_DIMENSION,
            AUXILIARY_WORDS,
        )
        base_aux_segment = core.OracleSegment(
            2,
            BASE_AUX_MASK_KIND,
            base_aux_rows,
            AUXILIARY_LEAF_SIZE,
        )
        base_aux_tree = core.retain_tree(
            runtime,
            allocator,
            merkle,
            base_aux_segment,
        )
        allocator.free(base_aux_rows)
        base_commit_seconds = time.perf_counter() - base_commit_started

        if not public_coin.prelude_complete:
            squarefree_prelude = public_coin.begin_prelude(
                initial_set_root
                if state_relation_source is not None
                else None
            )
            if squarefree_prelude is not None:
                _, coefficient_payload = squarefree_prelude
                coefficient_words = canonical_fp16_word_array(
                    coefficient_payload,
                    AUX_MESSAGE_VALUES,
                    "state_squarefree_coefficients",
                )
                state_squarefree_coefficient_source, attempts = (
                    core.exact_uniform_mask_buffer(
                        runtime,
                        allocator,
                        kernels["canonicalize_masks"],
                        1,
                        AUX_DIMENSION,
                        "state_squarefree_auxiliary_randomness",
                        random_host,
                    )
                )
                sampling_attempts += attempts
                coefficient_prefix = upload_fp16_word_array(
                    runtime,
                    allocator,
                    coefficient_words,
                    "upload_state_squarefree_coefficients",
                )
                copy_device(
                    runtime,
                    state_squarefree_coefficient_source.pointer,
                    coefficient_prefix.pointer,
                    AUX_MESSAGE_VALUES * core.FP16_BYTES,
                    "copy_state_squarefree_coefficients",
                )
                allocator.free(coefficient_prefix)
                del coefficient_words
            else:
                state_squarefree_coefficient_source = (
                    allocator.allocate_count(
                        AUX_DIMENSION,
                        core.FP16_BYTES,
                    )
                )
                core.ck(
                    runtime.cuda.cuMemsetD8_v2(
                        state_squarefree_coefficient_source.pointer,
                        0,
                        state_squarefree_coefficient_source.size,
                    ),
                    "zero_state_squarefree_coefficients",
                )
            coefficient_rows, _ = encode_random_batch(
                runtime,
                allocator,
                kernels,
                aux_root_powers,
                aux_coset_powers,
                state_squarefree_coefficient_source,
                AUX_CODE_LOG,
                AUX_DIMENSION,
                1,
            )
            coefficient_segment = core.OracleSegment(
                2,
                STATE_SQUAREFREE_COEFFICIENT_KIND,
                coefficient_rows,
                STATE_SQUAREFREE_COEFFICIENT_LEAF_SIZE,
            )
            state_squarefree_coefficient_tree = core.retain_tree(
                runtime,
                allocator,
                merkle,
                coefficient_segment,
            )
            allocator.free(coefficient_rows)
            if squarefree_prelude is not None:
                public_coin.finish_squarefree_prelude(
                    state_squarefree_coefficient_tree.root
                )
                if (
                    public_coin.state_squarefree_coefficient_root
                    != state_squarefree_coefficient_tree.root
                ):
                    raise SystemExit(
                        "state_squarefree_coefficient_root_mismatch"
                    )
        del random_host
        if semantic_source is not None:
            if semantic_prelude_started is None:
                raise SystemExit("semantic_gkr_prelude_start_missing")
            semantic_prelude_wall_seconds = (
                time.perf_counter() - semantic_prelude_started
            )
        public_coin_overlap_wall_seconds = (
            semantic_prelude_wall_seconds
            if semantic_source is not None
            else time.perf_counter() - public_coin.started
        )
        gkr_raw_claims = public_coin.gkr_raw_claims
        gkr_points = tuple(claim[4] for claim in gkr_raw_claims)
        low_point_buffer = upload_fp16_values(
            runtime,
            allocator,
            tuple(
                coordinate
                for point in gkr_points
                for coordinate in point[:GKR_LOW_VARIABLES]
            ),
            "upload_gkr_low_points",
        )
        low_weights = allocator.allocate_count(
            GKR_CLAIM_COUNT * core.BASE_MESSAGE_VALUES,
            core.FP16_BYTES,
        )
        launch_2d_256(
            runtime,
            fixture_weights,
            core.BASE_MESSAGE_VALUES,
            arguments(
                ctypes.c_uint64(low_point_buffer.pointer),
                ctypes.c_uint64(low_weights.pointer),
                ctypes.c_uint32(GKR_LOW_VARIABLES),
                ctypes.c_uint32(core.BASE_MESSAGE_VALUES),
                ctypes.c_uint32(GKR_CLAIM_COUNT),
            ),
            "gkr_low_point_weights",
            GKR_CLAIM_COUNT,
        )
        core.ck(
            runtime.cuda.cuCtxSynchronize(),
            "gkr_low_point_weights_sync",
        )
        allocator.free(low_point_buffer)
        component_rows_buffer = allocator.allocate_count(
            GKR_CLAIM_COUNT * GLOBAL_WORDS * 16,
            core.FP16_BYTES,
        )
        core.ck(
            runtime.cuda.cuMemsetD8_v2(
                component_rows_buffer.pointer,
                0,
                component_rows_buffer.size,
            ),
            "clear_component_rows",
        )
        claim_boundaries = array.array(
            "I",
            (claim[0] for claim in gkr_raw_claims),
        )
        claim_boundary_buffer = core.upload(
            runtime,
            allocator,
            claim_boundaries.tobytes(),
            "upload_gkr_claim_boundaries",
        )
        if semantic_source_buffer is not None:
            capture_started = time.perf_counter()
            launch_3d_256(
                runtime,
                semantic_component_evaluations,
                GLOBAL_WORDS,
                GKR_CLAIM_COUNT,
                16,
                arguments(
                    ctypes.c_uint64(semantic_source_buffer.pointer),
                    ctypes.c_uint64(
                        state_relation_source_buffer.pointer
                        if state_relation_source_buffer is not None
                        else 0
                    ),
                    ctypes.c_uint64(low_weights.pointer),
                    ctypes.c_uint64(component_rows_buffer.pointer),
                    ctypes.c_uint32(GKR_CLAIM_COUNT),
                ),
                "semantic_component_multilinear_evaluations",
            )
            core.ck(
                runtime.cuda.cuCtxSynchronize(),
                "semantic_component_multilinear_evaluations_sync",
            )
            component_evaluation_seconds[0] += (
                time.perf_counter() - capture_started
            )
        else:
            for boundary in range(core.BOUNDARY_COUNT):
                word_base = boundary * WORDS_PER_BOUNDARY
                capture_started = time.perf_counter()
                launch_3d_256(
                    runtime,
                    component_evaluations,
                    1,
                    GKR_CLAIM_COUNT,
                    16,
                    arguments(
                        ctypes.c_uint64(
                            captured_component_sources.pointer
                            + boundary
                            * core.BASE_MESSAGE_VALUES
                            * core.FP16_BYTES
                        ),
                        ctypes.c_uint64(low_weights.pointer),
                        ctypes.c_uint64(component_rows_buffer.pointer),
                        ctypes.c_uint32(core.BASE_MESSAGE_VALUES),
                        ctypes.c_uint32(1),
                        ctypes.c_uint32(core.BASE_MESSAGE_VALUES),
                        ctypes.c_uint32(GKR_CLAIM_COUNT),
                        ctypes.c_uint32(GLOBAL_WORDS),
                        ctypes.c_uint32(word_base),
                    ),
                    "compact_component_multilinear_evaluations",
                )
                core.ck(
                    runtime.cuda.cuCtxSynchronize(),
                    "compact_component_multilinear_evaluations_sync_"
                    f"{boundary}",
                )
                launch(
                    runtime,
                    broadcast_component_evaluations,
                    GKR_CLAIM_COUNT
                    * WORDS_PER_BOUNDARY
                    * 16,
                    arguments(
                        ctypes.c_uint64(
                            component_rows_buffer.pointer
                        ),
                        ctypes.c_uint32(word_base),
                        ctypes.c_uint32(GKR_CLAIM_COUNT),
                        ctypes.c_uint32(GLOBAL_WORDS),
                    ),
                    "broadcast_boundary_component_evaluations",
                )
                core.ck(
                    runtime.cuda.cuCtxSynchronize(),
                    "broadcast_boundary_component_evaluations_sync_"
                    f"{boundary}",
                )
                component_evaluation_seconds[0] += (
                    time.perf_counter() - capture_started
                )
        allocator.free(low_weights)
        if captured_component_sources is not None:
            allocator.free(captured_component_sources)
        reduction_started = time.perf_counter()
        high_point_buffer = upload_fp16_values(
            runtime,
            allocator,
            tuple(
                coordinate
                for point in gkr_points
                for coordinate in point[GKR_LOW_VARIABLES:]
            ),
            "upload_gkr_high_points",
        )
        high_weight_buffer = allocator.allocate_count(
            GKR_CLAIM_COUNT * WORDS_PER_BOUNDARY,
            core.FP16_BYTES,
        )
        launch_2d_256(
            runtime,
            fixture_weights,
            WORDS_PER_BOUNDARY,
            arguments(
                ctypes.c_uint64(high_point_buffer.pointer),
                ctypes.c_uint64(high_weight_buffer.pointer),
                ctypes.c_uint32(GKR_HIGH_VARIABLES),
                ctypes.c_uint32(WORDS_PER_BOUNDARY),
                ctypes.c_uint32(GKR_CLAIM_COUNT),
            ),
            "gkr_high_point_weights",
            GKR_CLAIM_COUNT,
        )
        core.ck(
            runtime.cuda.cuCtxSynchronize(),
            "gkr_high_point_weights_sync",
        )
        allocator.free(high_point_buffer)
        reduced_component_buffer = allocator.allocate_count(
            GKR_CLAIM_COUNT * 16,
            core.FP16_BYTES,
        )
        launch_3d_256(
            runtime,
            reduce_component_evaluations,
            1,
            GKR_CLAIM_COUNT,
            16,
            arguments(
                ctypes.c_uint64(component_rows_buffer.pointer),
                ctypes.c_uint64(high_weight_buffer.pointer),
                ctypes.c_uint64(claim_boundary_buffer.pointer),
                ctypes.c_uint64(reduced_component_buffer.pointer),
                ctypes.c_uint32(GKR_CLAIM_COUNT),
                ctypes.c_uint32(GLOBAL_WORDS),
            ),
            "reduce_claim_component_evaluations",
        )
        core.ck(
            runtime.cuda.cuCtxSynchronize(),
            "reduce_claim_component_evaluations_sync",
        )
        reduced_component_words = copy_fp16_words(
            runtime,
            reduced_component_buffer,
            "copy_reduced_gkr_component_evaluations",
        )
        component_evaluations = component_evaluations_from_words(
            reduced_component_words
        )
        allocator.free(reduced_component_buffer)
        allocator.free(claim_boundary_buffer)
        allocator.free(high_weight_buffer)
        del reduced_component_words
        component_evaluation_seconds[0] += (
            time.perf_counter() - reduction_started
        )
        gkr_claims = build_real_gkr_claims(
            gkr_raw_claims,
            component_evaluations,
        )
        mask_words = copy_fp16_words(
            runtime,
            sumcheck_randomness,
            "copy_theorem8_sumcheck_masks",
        )
        sumcheck = run_authenticated_sumcheck(
            transcript_path,
            row_parameter_path,
            public_coin,
            initial_set_root,
            sumcheck_tree.root,
            gkr_mask_tree.root,
            public_coin.gkr_mask_opening,
            gkr_claims,
            public_coin.state_squarefree_coefficient_root,
            public_coin.state_squarefree_capacity,
            public_coin.state_squarefree_coefficient_claims,
            public_coin.state_squarefree_public_claims_payload,
            mask_words,
            runtime,
            allocator,
            row_kernels,
            component_rows_buffer,
            gkr_mask,
            public_coin.gkr_mask_weights,
        )
        allocator.free(component_rows_buffer)
        del component_evaluations
        initial_target = sumcheck["initial_target"]
        mask_target = sumcheck["mask_target"]
        claim_challenge = sumcheck["claim_challenge"]
        coordinate_challenge = sumcheck[
            "coordinate_challenge"
        ]
        state_squarefree_answer_binding_payload, state_squarefree_coefficient_target = (
            state_squarefree_answer_binding(
                public_coin.state_squarefree_capacity,
                public_coin.state_squarefree_coefficient_claims,
                sumcheck["coefficient_mixing"],
            )
        )
        epsilon = sumcheck["epsilon"]
        challenges = sumcheck["challenges"]
        gkr_source_terminals = sumcheck[
            "gkr_source_terminals"
        ]
        gkr_relation_terminals = sumcheck[
            "gkr_relation_terminals"
        ]
        terminal_target = sumcheck["terminal_target"]
        source_terminal = sumcheck["source_terminal"]
        mask_terminal = sumcheck["mask_terminal"]
        sumcheck_seconds = sumcheck["wall_seconds"]
        sumcheck_compute_seconds = sumcheck["compute_seconds"]
        row_parameter_seconds = sumcheck[
            "row_parameter_seconds"
        ]
        compact_row_sumcheck_seconds = sumcheck["row_seconds"]
        sumcheck_message_mb = sumcheck["message_mb"]

        complete_aux_source = allocator.allocate_count(
            AUXILIARY_WORDS * AUX_DIMENSION,
            core.FP16_BYTES,
        )
        launch(
            runtime,
            row_kernels["assemble_auxiliary"],
            AUXILIARY_WORDS * AUX_DIMENSION,
            arguments(
                ctypes.c_uint64(sumcheck_randomness.pointer),
                ctypes.c_uint64(gkr_mask.pointer),
                ctypes.c_uint64(
                    state_squarefree_coefficient_source.pointer
                ),
                ctypes.c_uint64(complete_aux_source.pointer),
            ),
            "assemble_complete_auxiliary_source",
        )
        core.ck(
            runtime.cuda.cuCtxSynchronize(),
            "assemble_complete_auxiliary_source_sync",
        )

        fold_point_buffer = upload_fp16_values(
            runtime,
            allocator,
            challenges,
            "upload_theorem8_fold_point",
        )
        weight_buffer = allocator.allocate_count(
            GLOBAL_WORDS,
            core.FP16_BYTES,
        )
        launch_2d_256(
            runtime,
            fixture_weights,
            GLOBAL_WORDS,
            arguments(
                ctypes.c_uint64(fold_point_buffer.pointer),
                ctypes.c_uint64(weight_buffer.pointer),
                ctypes.c_uint32(SUMCHECK_ROUNDS),
                ctypes.c_uint32(GLOBAL_WORDS),
                ctypes.c_uint32(1),
            ),
            "theorem8_fold_weights",
            1,
        )
        core.ck(
            runtime.cuda.cuCtxSynchronize(),
            "theorem8_fold_weights_sync",
        )
        allocator.free(fold_point_buffer)
        weight_words = copy_fp16_words(
            runtime,
            weight_buffer,
            "copy_theorem8_fold_weights",
        )
        weights = tuple(
            fp16_from_words(weight_words, index)
            for index in range(GLOBAL_WORDS)
        )
        del weight_words
        folded = allocator.allocate_count(
            MAIN_DIMENSION,
            core.FP16_BYTES,
        )
        core.ck(
            runtime.cuda.cuMemsetD8_v2(
                folded.pointer,
                0,
                folded.size,
            ),
            "zero_theorem8_folded_coefficients",
        )
        seed = 0
        global_word = 0
        fold_started = time.perf_counter()
        for boundary in range(core.BOUNDARY_COUNT):
            for segment_index in range(core.SEGMENTS_PER_BOUNDARY):
                fold_arguments = [
                    ctypes.c_uint64(folded.pointer),
                    ctypes.c_uint64(
                        initial_randomness[seed].pointer
                    ),
                    ctypes.c_uint64(weight_buffer.pointer),
                    ctypes.c_uint32(global_word),
                    ctypes.c_uint32(boundary),
                    ctypes.c_uint32(segment_index),
                    ctypes.c_uint32(
                        core.INTERLEAVINGS_PER_SEGMENT
                    ),
                    ctypes.c_uint32(core.BASE_MESSAGE_VALUES),
                    ctypes.c_uint32(core.MASK_COEFFICIENTS),
                ]
                if semantic_source_buffer is not None:
                    fold_arguments.append(
                        ctypes.c_uint64(
                            semantic_source_buffer.pointer
                        )
                    )
                    fold_arguments.append(
                        ctypes.c_uint64(
                            state_relation_source_buffer.pointer
                            if state_relation_source_buffer is not None
                            else 0
                        )
                    )
                launch(
                    runtime,
                    (
                        accumulate_folded_semantic
                        if semantic_source_buffer is not None
                        else accumulate_folded
                    ),
                    MAIN_DIMENSION,
                    arguments(*fold_arguments),
                    "accumulate_theorem8_folded_coefficients",
                )
                core.ck(
                    runtime.cuda.cuCtxSynchronize(),
                    "accumulate_theorem8_folded_coefficients_sync",
                )
                seed += 1
                global_word += core.INTERLEAVINGS_PER_SEGMENT
        fold_seconds = time.perf_counter() - fold_started
        allocator.free(weight_buffer)

        base_main_payload = copy_canonical_fp16_payload(
            runtime,
            base_main,
            "copy_theorem8_base_main_coefficients",
        )
        base_aux_payload = copy_canonical_fp16_payload(
            runtime,
            base_aux,
            "copy_theorem8_base_aux_coefficients",
        )
        (
            base_target,
            base_target_compute_seconds,
            base_target_wall_seconds,
            base_target_workers,
        ) = run_native_answer_target(
            answer_target_path,
            claim_challenge,
            coordinate_challenge,
            gkr_claims,
            challenges,
            gkr_relation_terminals,
            epsilon,
            state_squarefree_answer_binding_payload,
            base_main_payload,
            base_aux_payload,
            memory,
        )
        del base_main_payload
        del base_aux_payload
        base_coin_started = time.perf_counter()
        combination = public_coin.challenge(
            802,
            b"BL/PQ512/FP16-ZK-RS/BASE-MASKS/v2"
            + base_main_tree.root
            + base_aux_tree.root
            + gkr_mask_tree.root
            + public_coin.state_squarefree_coefficient_root
            + hashlib.sha3_512(
                b"".join(
                    fp16_bytes(terminal)
                    for terminal in gkr_relation_terminals
                )
            ).digest()
            + fp16_bytes(base_target),
        )
        base_coin_seconds = time.perf_counter() - base_coin_started
        main_answer = allocator.allocate_count(
            MAIN_DIMENSION,
            core.FP16_BYTES,
        )
        aux_answer = allocator.allocate_count(
            AUXILIARY_WORDS * AUX_DIMENSION,
            core.FP16_BYTES,
        )
        answer_started = time.perf_counter()
        launch(
            runtime,
            linear_combine,
            MAIN_DIMENSION,
            arguments(
                ctypes.c_uint64(main_answer.pointer),
                ctypes.c_uint64(base_main.pointer),
                ctypes.c_uint64(folded.pointer),
                (ctypes.c_uint32 * 16)(*combination),
                ctypes.c_uint64(MAIN_DIMENSION),
            ),
            "theorem8_main_answer",
        )
        launch(
            runtime,
            linear_combine,
            AUXILIARY_WORDS * AUX_DIMENSION,
            arguments(
                ctypes.c_uint64(aux_answer.pointer),
                ctypes.c_uint64(base_aux.pointer),
                ctypes.c_uint64(complete_aux_source.pointer),
                (ctypes.c_uint32 * 16)(*combination),
                ctypes.c_uint64(
                    AUXILIARY_WORDS * AUX_DIMENSION
                ),
            ),
            "theorem8_aux_answer",
        )
        core.ck(
            runtime.cuda.cuCtxSynchronize(),
            "theorem8_answers_sync",
        )
        answer_seconds = time.perf_counter() - answer_started
        allocator.free(complete_aux_source)
        allocator.free(folded)
        complete_terminal_target = add(
            terminal_target,
            state_squarefree_coefficient_target,
        )
        answer_target = add(
            base_target,
            scale(complete_terminal_target, combination),
        )
        if terminal_target != add(
            scale(source_terminal, epsilon),
            mask_terminal,
        ):
            raise SystemExit("production_sumcheck_terminal_decomposition")
        main_answer_payload = copy_canonical_fp16_payload(
            runtime,
            main_answer,
            "copy_theorem8_main_answer",
        )
        aux_answer_payload = copy_canonical_fp16_payload(
            runtime,
            aux_answer,
            "copy_theorem8_aux_answer",
        )
        allocator.free(main_answer)
        allocator.free(aux_answer)
        answer_message_mb = (
            len(main_answer_payload) + len(aux_answer_payload)
        ) / 1_000_000
        query_coin_started = time.perf_counter()
        query_seed = public_coin.challenge(
            803,
            b"BL/PQ512/FP16-ZK-RS/ANSWERS/v1"
            + len(main_answer_payload).to_bytes(8, "big")
            + hashlib.sha3_512(main_answer_payload).digest()
            + len(aux_answer_payload).to_bytes(8, "big")
            + hashlib.sha3_512(aux_answer_payload).digest(),
        )
        main_queries = exact_queries(
            fp16_bytes(query_seed),
            b"main_queries",
            core.BASE_CODE_VALUES,
            MAIN_QUERY_COUNT,
        )
        aux_queries = exact_queries(
            fp16_bytes(query_seed),
            b"aux_queries",
            AUX_CODE_VALUES,
            AUX_QUERY_COUNT,
        )
        state_squarefree_coefficient_root = (
            public_coin.state_squarefree_coefficient_root
        )
        public_coin_summary = public_coin.finish()
        gkr_state_relation_digest = public_coin.gkr_state_relation_digest
        public_coin = None
        memory.child_process_id = None
        query_coin_seconds = (
            time.perf_counter() - query_coin_started
        )

        answer_opening_started = time.perf_counter()
        answer_code_verifier = NativeAnswerCodeVerifier(
            answer_code_path,
            main_queries,
            aux_queries,
            claim_challenge,
            coordinate_challenge,
            gkr_claims,
            challenges,
            gkr_relation_terminals,
            epsilon,
            state_squarefree_answer_binding_payload,
            answer_target,
            main_answer_payload,
            aux_answer_payload,
        )
        del main_answer_payload
        del aux_answer_payload

        verifier = core.NativeMultiproofVerifier(
            verifier_path,
            THEOREM_SEGMENT_COUNT,
            deferred=True,
        )
        spotcheck_verifier = NativeSpotcheckVerifier(
            spotcheck_path,
            weights,
            combination,
        )
        memory.child_process_id = None
        memory.child_process_ids = (
            answer_code_verifier.process.pid,
            verifier.process.pid,
            spotcheck_verifier.process.pid,
        )
        opening_started = time.perf_counter()
        opening_mb = 0.0
        native_seconds = 0.0
        sumcheck_openings = None
        gkr_mask_openings = None
        base_main_openings = None
        base_aux_openings = None
        state_squarefree_coefficient_openings = None
        seed = 0
        for tree in initial_trees:
            replay, _ = core.encode_segment(
                runtime,
                allocator,
                kernels,
                main_root_powers,
                main_coset_powers,
                initial_randomness[seed],
                tree.segment.boundary,
                tree.segment.kind - core.SEGMENT_KIND_BASE,
                initializer=(
                    kernels["initialize_semantic_gkr_source"]
                    if semantic_source is not None
                    else kernels["initialize_real_gkr_source"]
                ),
                initializer_context=(
                    semantic_source_buffer.pointer
                    if semantic_source_buffer is not None
                    else None
                ),
                initializer_auxiliary_context=(
                    state_relation_source_buffer.pointer
                    if state_relation_source_buffer is not None
                    else (0 if semantic_source_buffer is not None else None)
                ),
            )
            result = core.open_retained_tree(
                runtime,
                allocator,
                kernels["gather_nodes"],
                merkle,
                verifier,
                tree,
                core.OracleSegment(
                    tree.segment.boundary,
                    tree.segment.kind,
                    replay,
                    core.ROW_BYTES,
                ),
                main_queries,
                return_leaves=True,
            )
            opening_mb += result[0]
            native_seconds += result[3]
            spotcheck_verifier.write_initial_segment(result[7])
            allocator.free(replay)
            seed += 1
        for tree, coefficients, log_code, dimension, batch, queries in (
            (
                sumcheck_tree,
                sumcheck_randomness,
                AUX_CODE_LOG,
                AUX_DIMENSION,
                SUMCHECK_ROUNDS,
                aux_queries,
            ),
            (
                gkr_mask_tree,
                gkr_mask,
                AUX_CODE_LOG,
                GLOBAL_WORDS,
                GKR_MASK_STATES,
                aux_queries,
            ),
            (
                base_main_tree,
                base_main,
                core.BASE_CODE_LOG,
                MAIN_DIMENSION,
                1,
                main_queries,
            ),
            (
                base_aux_tree,
                base_aux,
                AUX_CODE_LOG,
                AUX_DIMENSION,
                AUXILIARY_WORDS,
                aux_queries,
            ),
            (
                state_squarefree_coefficient_tree,
                state_squarefree_coefficient_source,
                AUX_CODE_LOG,
                AUX_DIMENSION,
                1,
                aux_queries,
            ),
        ):
            roots = (
                aux_root_powers
                if log_code == AUX_CODE_LOG
                else main_root_powers
            )
            cosets = (
                aux_coset_powers
                if log_code == AUX_CODE_LOG
                else main_coset_powers
            )
            replay, _ = encode_random_batch(
                runtime,
                allocator,
                kernels,
                roots,
                cosets,
                coefficients,
                log_code,
                dimension,
                batch,
            )
            replay_segment = core.OracleSegment(
                tree.segment.boundary,
                tree.segment.kind,
                replay,
                core.segment_leaf_size(tree.segment),
            )
            result = core.open_retained_tree(
                runtime,
                allocator,
                kernels["gather_nodes"],
                merkle,
                verifier,
                tree,
                replay_segment,
                queries,
                return_leaves=True,
            )
            opening_mb += result[0]
            native_seconds += result[3]
            if tree.segment.kind == SUMCHECK_MASK_KIND:
                sumcheck_openings = result[7]
            elif tree.segment.kind == GKR_MASK_KIND:
                gkr_mask_openings = result[7]
            elif tree.segment.kind == BASE_MAIN_MASK_KIND:
                base_main_openings = result[7]
            elif tree.segment.kind == BASE_AUX_MASK_KIND:
                base_aux_openings = result[7]
            elif tree.segment.kind == STATE_SQUAREFREE_COEFFICIENT_KIND:
                state_squarefree_coefficient_openings = result[7]
            allocator.free(replay)
        verifier_summary = verifier.finish()
        native_verify_compute_seconds = verifier_summary[
            "verify_compute_seconds"
        ]
        native_verify_tail_seconds = verifier_summary["tail_seconds"]
        (
            main_answer_openings,
            aux_answer_openings,
            answer_code_compute_seconds,
            answer_code_wall_seconds,
            answer_code_workers,
        ) = answer_code_verifier.finish()
        answer_code_verifier = None
        if (
            sumcheck_openings is None
            or gkr_mask_openings is None
            or base_main_openings is None
            or base_aux_openings is None
            or state_squarefree_coefficient_openings is None
        ):
            raise SystemExit("production_spotcheck_openings_missing")
        (
            spotcheck_compute_seconds,
            spotcheck_wall_seconds,
            spotcheck_tail_seconds,
        ) = spotcheck_verifier.finish(
            sumcheck_openings,
            gkr_mask_openings,
            state_squarefree_coefficient_openings,
            base_main_openings,
            base_aux_openings,
            main_answer_openings,
            aux_answer_openings,
        )
        answer_opening_joined_seconds = (
            time.perf_counter() - answer_opening_started
        )
        memory.stop()
        proof_host_peak_mb = memory.maximum_mb
        native_verifier_peak_mb = memory.maximum_child_mb
        memory = None
        opening_seconds = time.perf_counter() - opening_started

        joined_gkr_pcs_mechanics_seconds = (
            public_coin_overlap_wall_seconds
            + component_evaluation_seconds[0]
            + sumcheck_seconds
            + fold_seconds
            + base_coin_seconds
            + base_target_wall_seconds
            + answer_seconds
            + query_coin_seconds
            + answer_opening_joined_seconds
        )
        pcs_seconds = (
            joined_gkr_pcs_mechanics_seconds
            - semantic_prelude_wall_seconds
            if semantic_source is not None
            else joined_gkr_pcs_mechanics_seconds
        )
        print("prototype=fp16_zk_rs_theorem8_1_k128_v2")
        print("activation=false")
        qualified_suite = qualified_proof_suite_id()
        parallel_shards = os.environ.get("BL_SHARD_CONCURRENCY") == "2"
        print(
            "proof_suite_id="
            + ("null" if qualified_suite is None else qualified_suite.hex())
        )
        print("paper_construction=8.2")
        print("sumcheck_rounds=9")
        print("standalone_public_coin_rounds=14")
        print(f"gkr_claim_count={GKR_CLAIM_COUNT}")
        print("initial_interleaving=512")
        print(f"oracle_tree_count={THEOREM_SEGMENT_COUNT}")
        print("main_queries=1600")
        print("auxiliary_queries=1218")
        print(f"sampling_attempts={sampling_attempts}")
        print(f"tracked_device_peak_mb={allocator.peak_mb:.6f}")
        print(f"proof_phase_host_peak_mb={proof_host_peak_mb:.3f}")
        print(
            "native_verifier_peak_mb="
            f"{native_verifier_peak_mb:.3f}"
        )
        print(
            "parent_process_lifetime_host_peak_mb="
            f"{core.process_peak_mb():.3f}"
        )
        print("scratch_mb=0.000000")
        print(
            "complete_process_wall_seconds="
            f"{time.perf_counter() - proof_process_started:.6f}"
        )
        print(f"path_gate_seconds={path_gate_seconds:.6f}")
        print(f"cuda_module_load_seconds={compile_seconds:.6f}")
        print(f"kernel_lookup_seconds={kernel_lookup_seconds:.6f}")
        print(f"power_table_seconds={power_table_seconds:.6f}")
        print(
            "gkr_mask_commit_seconds="
            f"{gkr_mask_commit_seconds:.6f}"
        )
        print(
            "gkr_mask_cpu_commit_seconds="
            f"{gkr_mask_cpu_commit_seconds:.6f}"
        )
        print(
            "gkr_mask_cpu_compute_seconds="
            f"{gkr_mask_cpu_compute_seconds:.6f}"
        )
        print(f"gkr_mask_cpu_workers={gkr_mask_cpu_workers}")
        print(
            "gkr_mask_gpu_commit_seconds="
            f"{gkr_mask_gpu_commit_seconds:.6f}"
        )
        print("gkr_mask_cpu_gpu_root_parity=true")
        print(f"initial_commit_seconds={initial_commit_seconds:.6f}")
        print(
            "gkr_component_evaluation_seconds="
            f"{component_evaluation_seconds[0]:.6f}"
        )
        print(f"mask_commit_seconds={mask_commit_seconds:.6f}")
        print(
            "mask_prelude_and_coin_head_overlap_seconds="
            f"{public_coin_overlap_wall_seconds:.6f}"
        )
        print(
            "public_coin_head_auth_seconds="
            f"{public_coin_summary['head_seconds']:.6f}"
        )
        print(
            "public_coin_base_challenge_seconds="
            f"{base_coin_seconds:.6f}"
        )
        print(
            "public_coin_query_and_finish_seconds="
            f"{query_coin_seconds:.6f}"
        )
        print(
            "public_coin_finish_replay_seconds="
            f"{public_coin_summary['finish_seconds']:.6f}"
        )
        print(
            "public_coin_bundle_mb="
            f"{public_coin_summary['bundle_mb']:.6f}"
        )
        print(
            "public_coin_bundle_sha3_512="
            f"{hashlib.sha3_512(public_coin_summary['bundle']).hexdigest()}"
        )
        parent_binding = atomic_parent_binding()
        print(
            "atomic_parent_binding_sha3_512="
            + ("none" if parent_binding is None else parent_binding.hex())
        )
        print(
            "state_plane_binding_attached="
            + ("false" if state_binding is None else "true")
        )
        print(
            "state_plane_statement_sha3_512="
            + ("00" * 64 if state_binding is None else state_binding["statement"].hex())
        )
        print(
            "state_plane_binding_digest_sha3_512="
            + ("00" * 64 if state_binding is None else state_binding["binding"].hex())
        )
        print("state_plane_public_abi_count=" + ("0" if state_binding is None else "12"))
        print("state_air_fragment_verified=" + ("false" if state_binding is None else "true"))
        state_zero = "00" * 64
        state_field_zero = "00" * 32
        for label, key in (
            ("state_plane_projection_digest_sha3_512", "projection_digest"),
            ("state_plane_public_coin_sha3_512", "public_coin"),
            ("state_plane_transition_digest_sha3_512", "transition"),
            ("state_plane_commitment_digest_sha3_512", "commitment"),
            ("state_plane_proof_identity_sha3_512", "proof"),
            ("state_plane_verifier_identity_sha3_512", "verifier"),
            ("state_plane_attempt_id_sha3_512", "attempt"),
            ("state_plane_receipt_digest_sha3_512", "receipt"),
            ("state_plane_composition_digest_sha3_512", "composition"),
            ("state_air_program_commitment_sha3_512", "state_air_program"),
            ("state_air_execution_commitment_sha3_512", "state_air_execution"),
            ("state_air_fragment_digest_sha3_512", "state_air_fragment"),
        ):
            print(label + "=" + (state_zero if state_binding is None else state_binding[key].hex()))
        for index in range(12):
            print(
                f"state_plane_public_abi_{index:02}="
                + (
                    state_field_zero
                    if state_binding is None
                    else state_binding["public_abi"][index].hex()
                )
            )
        print(f"sumcheck_seconds={sumcheck_seconds:.6f}")
        print(
            "sumcheck_compute_seconds="
            f"{sumcheck_compute_seconds:.6f}"
        )
        print(f"fold_seconds={fold_seconds:.6f}")
        print(f"base_commit_seconds={base_commit_seconds:.6f}")
        print(
            "compact_row_parameter_seconds="
            f"{row_parameter_seconds:.6f}"
        )
        print(
            "compact_row_sumcheck_seconds="
            f"{compact_row_sumcheck_seconds:.6f}"
        )
        print(
            "base_target_compute_seconds="
            f"{base_target_compute_seconds:.6f}"
        )
        print(
            "base_target_wall_seconds="
            f"{base_target_wall_seconds:.6f}"
        )
        print(
            "base_target_workers="
            f"{base_target_workers}"
        )
        print(f"answer_seconds={answer_seconds:.6f}")
        print(
            "independent_answer_code_compute_seconds="
            f"{answer_code_compute_seconds:.6f}"
        )
        print(
            "independent_answer_code_wall_seconds="
            f"{answer_code_wall_seconds:.6f}"
        )
        print(f"independent_answer_code_workers={answer_code_workers}")
        print(f"opening_seconds={opening_seconds:.6f}")
        print(
            "answer_code_and_opening_joined_seconds="
            f"{answer_opening_joined_seconds:.6f}"
        )
        print(
            "spotcheck_compute_seconds="
            f"{spotcheck_compute_seconds:.6f}"
        )
        print(
            "spotcheck_wall_seconds="
            f"{spotcheck_wall_seconds:.6f}"
        )
        print(
            "spotcheck_tail_seconds="
            f"{spotcheck_tail_seconds:.6f}"
        )
        print(
            "native_opening_submit_seconds="
            f"{native_seconds:.6f}"
        )
        print(
            "native_opening_verify_compute_seconds="
            f"{native_verify_compute_seconds:.6f}"
        )
        print(
            "native_opening_verify_tail_seconds="
            f"{native_verify_tail_seconds:.6f}"
        )
        print(f"pcs_mechanics_seconds={pcs_seconds:.6f}")
        print(
            "joined_gkr_pcs_mechanics_seconds="
            f"{joined_gkr_pcs_mechanics_seconds:.6f}"
        )
        print(f"sumcheck_message_mb={sumcheck_message_mb:.6f}")
        print(f"answer_message_mb={answer_message_mb:.6f}")
        print(f"canonical_openings_mb={opening_mb:.6f}")
        print("compact_claim_row_state_mb=7.864320")
        print("gkr_mask_row_state_mb=4.194304")
        print("compact_row_gpu_state_mb=12.058624")
        print("gkr_mask_coefficients_mb=2.097152")
        print("gkr_mask_codewords_mb=33.554432")
        print("complete_auxiliary_coefficients_mb=15.467776")
        print("complete_auxiliary_codewords_mb=38.797312")
        print("sumcheck_chain_verified=true")
        print("terminal_target_verified=true")
        print("base_target_verified=true")
        print("main_spotchecks_verified=true")
        print("auxiliary_spotchecks_verified=true")
        print("native_spotcheck_verifier_attached=true")
        print("all_merkle_roots_independently_verified=true")
        print("per_proof_merkle_mutation_replays=false")
        print("exact_candidate_soundness_parameter_ledger_closed=true")
        print("implementation_theorem_binding_closed=true")
        print("construction_8_2_hiding_simulator_gate_attached=true")
        print("nineteen_claim_row_binding_attached=true")
        print("gkr_row_parameters_derived_in_rust=true")
        print(
            "component_rows_extracted_from_live_commitment_tile="
            f"{str(semantic_source is None).lower()}"
        )
        print(
            "component_rows_extracted_from_packed_semantic_source="
            f"{str(semantic_source is not None).lower()}"
        )
        print(
            "semantic_hash_bus_statement_bound="
            f"{str(semantic_source is not None).lower()}"
        )
        print(
            "state_hash_bus_calls_verified="
            f"{str(state_binding is not None and semantic_source is not None).lower()}"
        )
        print(
            "state_relation_gkr_attached="
            f"{str(state_relation_source is not None).lower()}"
        )
        print(
            "typed_state_component_verified="
            f"{str(state_binding is not None and state_binding.get('typed_state', False)).lower()}"
        )
        print(
            "state_relation_source_sha3_512="
            + (
                state_zero
                if state_relation_source is None
                else state_relation_source["digest"].hex()
            )
        )
        print(
            "state_relation_gkr_digest_sha3_512="
            + (
                state_zero
                if state_relation_source is None
                else gkr_state_relation_digest.hex()
            )
        )
        print(
            "state_relation_interactive_verified="
            f"{str(state_relation_source is not None).lower()}"
        )
        print(
            "state_squarefree_gkr_attached="
            f"{str(state_relation_source is not None).lower()}"
        )
        print(
            "state_squarefree_interactive_verified="
            f"{str(state_relation_source is not None).lower()}"
        )
        print(
            "state_squarefree_coefficient_root_sha3_512="
            f"{state_squarefree_coefficient_root.hex()}"
        )
        print(
            "state_squarefree_h4_claim_count="
            f"{12 if state_relation_source is not None else 0}"
        )
        print(
            "state_squarefree_coefficient_claim_count="
            f"{2 if state_relation_source is not None else 0}"
        )
        print(f"authenticated_public_coin_rounds={public_coin_rounds}")
        if semantic_source is not None:
            print(
                "semantic_hash_bus_file_sha3_512="
                f"{semantic_source['file_sha3_512'].hex()}"
            )
            print(
                "semantic_hash_bus_profile="
                f"{semantic_source['profile']}"
            )
            print(
                "semantic_hash_bus_shard="
                f"{semantic_source['shard']}"
            )
            print(
                "semantic_gkr_prelude_wall_seconds="
                f"{semantic_prelude_wall_seconds:.6f}"
            )
        print("duplicate_full_source_replay=false")
        print("gpu_compact_row_sumcheck_attached=true")
        print("independent_final_answer_target_attached=true")
        print("real_gkr_producer_attached=true")
        print("gkr_boundary_claims_fixture_only=false")
        print("independent_fp16_arithmetic_verifier_attached=true")
        print("launch_authenticated_public_coin=true")
        print("atomic_gkr_pcs_coordinator_attached=true")
        print("atomic_gkr_pcs_verifier_attached=true")
        print("complete_fresh_proof_independently_verified=true")
        print("complete_pcs_qualification=false")
        print(
            "complete_proof_qualification="
            + str(qualified_suite is not None and not parallel_shards).lower()
        )
    finally:
        if memory is not None:
            memory.stop()
        if state_relation_source_buffer is not None:
            allocator.free(state_relation_source_buffer)
        if (
            state_squarefree_coefficient_source is not None
            and state_squarefree_coefficient_source.pointer
            in allocator.sizes
        ):
            allocator.free(state_squarefree_coefficient_source)
        if verifier is not None:
            verifier.abort()
        if spotcheck_verifier is not None:
            spotcheck_verifier.abort()
        if answer_code_verifier is not None:
            answer_code_verifier.abort()
        if public_coin is not None:
            public_coin.abort()
        NativePublicCoinBridge.abort_prepared(prepared_public_coin)
        runtime.close()


if __name__ == "__main__":
    main()
