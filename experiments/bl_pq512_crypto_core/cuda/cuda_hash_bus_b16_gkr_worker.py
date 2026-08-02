"""Untrusted CUDA arithmetic worker for the real nonuniform B16 hash-bus GKR.

Rust owns topology, transcript order, native masks, authenticated challenges,
recurrence checks, terminal evaluations, terminal checks, and final
verification. This process only evaluates the verifier-supplied topology over
one canonical B16 boundary shard and returns raw bridge/group/wire messages
plus group-folded sources.
"""

import array
import ctypes
import hashlib
import os
import struct
import sys
import time
from pathlib import Path

from cuda_dag_packed_accumulator_benchmark import copy
from cuda_dag_shared_group_fold_benchmark import (
    FP16_BYTES,
    KERNEL as FOLD_KERNEL,
    kernel_arguments,
)
from cuda_dag_shared_group_message_benchmark import (
    MAX_RAW,
    MAX_SUFFIX,
    MESSAGE_KERNEL,
    TERMS_PER_THREAD,
    THREADS,
    launch_b16_first,
    launch_b16_packed_message,
    launch_fp16_message,
    reduce_partials,
)
from cuda_fp16_b16_binary_bridge_benchmark import (
    KERNEL as BRIDGE_KERNEL,
    arguments,
    chunk_basis_table,
    launch,
    m31_basis,
)
from cuda_fp16_tower_kat import CUDA, Q, Runtime, add, ck, mul16


READY = b"BLGKRW05"
PLAN = b"BLGKRPL5"
PLAN_ACCEPTED = b"BLGKRPK5"
OUTPUT_REQUEST = b"BLGKRO05"
OUTPUT_RESPONSE = b"BLGKROK5"
LAYER_REQUEST = b"BLGKRL05"
LAYER_RESPONSE = b"BLGKRLK5"
BRIDGE_CHALLENGE = b"BLGKRB05"
BRIDGE_ACCEPTED = b"BLGKRBK5"
GROUP_CHALLENGE = b"BLGKRC05"
GROUP_ACCEPTED = b"BLGKRCK5"
FOLDED_REQUEST = b"BLGKRF05"
FOLDED_RESPONSE = b"BLGKRFK5"
WIRE_REQUEST = b"BLGKRWQ5"
WIRE_RESPONSE = b"BLGKRWR5"
WIRE_CHALLENGE = b"BLGKRWC5"
WIRE_ACCEPTED = b"BLGKRWA5"
FINISH = b"BLGKRFI5"
FINISHED = b"BLGKRDN5"

BOUNDARY_MAGIC = b"BLHBB101"
STATE_BOUNDARY_MAGIC = b"BLHBB102"
BOUNDARY_HEADER_BYTES = 215
GROUP_COUNT = 8_192
LIVE_WIRES = 1_600
PADDED_WIRES = 2_048
MAX_CLAIMS = 4
RATE_BYTES = 136
STATE_ROOT_ENTRY_WIDTH = 137
STATE_ROOT_CAPACITY_BASE = 512
BRIDGE_COEFFICIENTS = 46
PERMUTATIONS_PER_SHARD = GROUP_COUNT * 16
PROFILE_TOTAL_PERMUTATIONS = {
    1: 113_730,
    3: 411_406,
}
PROFILE_CLAIM_SLOTS = {
    1: 128,
    3: 512,
}
PROFILE_STATE_TOTAL_PERMUTATIONS = {
    profile: PROFILE_TOTAL_PERMUTATIONS[profile]
    + 2
    * (
        (
            PROFILE_CLAIM_SLOTS[profile] * STATE_ROOT_ENTRY_WIDTH
            + STATE_ROOT_CAPACITY_BASE
        )
        // RATE_BYTES
        + 1
    )
    for profile in PROFILE_TOTAL_PERMUTATIONS
}


def evaluate_polynomial(polynomial, point):
    value = (0,) * 16
    for coefficient in reversed(polynomial):
        term = coefficient if isinstance(coefficient, tuple) else (coefficient,) + (0,) * 15
        value = add(mul16(value, point), term)
    return value


WORKER_KERNEL = CUDA + r"""
__device__ __forceinline__ F16 a16(F16 x,F16 y){return {a8(x.a,y.a),a8(x.b,y.b)};}
__device__ __forceinline__ F16 s16(F16 x,F16 y){return {s8(x.a,y.a),s8(x.b,y.b)};}
__device__ __forceinline__ F16 z16(){F16 value={};return value;}

extern "C" __global__ void evaluate_b16_dag_layer(
    const unsigned short *left,
    const unsigned short *right,
    const unsigned int *base_left,
    const unsigned int *base_right,
    const unsigned int *formulas,
    unsigned short *output,
    unsigned int raw_width,
    unsigned int padded_width,
    unsigned int group_count
) {
    unsigned int index = blockIdx.x * blockDim.x + threadIdx.x;
    unsigned int count = padded_width * group_count;
    if (index >= count) return;
    unsigned int wire = index / group_count;
    unsigned int group = index - wire * group_count;
    if (wire >= raw_width) {
        output[index] = 0;
        return;
    }
    unsigned short x = left[base_left[wire] * group_count + group];
    unsigned short y = right[base_right[wire] * group_count + group];
    unsigned int formula = formulas[wire];
    output[index] = formula == 1U
        ? (unsigned short)(~x & y)
        : (unsigned short)(x ^ y ^ (formula == 2U ? 65535U : 0U));
}

extern "C" __global__ void equality_table(
    const unsigned int *points,
    const unsigned int *coefficients,
    unsigned int *output,
    unsigned int point_stride,
    unsigned int point_offset,
    unsigned int variable_count,
    unsigned int value_count,
    unsigned int output_stride,
    unsigned int claim_count
) {
    unsigned int index = blockIdx.x * blockDim.x + threadIdx.x;
    unsigned int count = claim_count * value_count;
    if (index >= count) return;
    unsigned int claim = index / value_count;
    unsigned int position = index - claim * value_count;
    F16 value = l16(coefficients + 16ULL * claim);
    F16 one = z16();
    one.a.a.a.a = 1U;
    for (unsigned int variable = 0; variable < variable_count; ++variable) {
        F16 coordinate = l16(
            points
                + 16ULL * (
                    claim * point_stride + point_offset + variable
                )
        );
        F16 factor = ((position >> variable) & 1U) != 0U
            ? coordinate
            : s16(one, coordinate);
        value = m16(value, factor);
    }
    st16(output + 16ULL * (claim * output_stride + position), value);
}

extern "C" __global__ void ranked_wire_equality_table(
    const unsigned int *points,
    const unsigned int *coefficients,
    unsigned int *output,
    unsigned int point_stride,
    unsigned int variable_count,
    unsigned int value_count,
    unsigned int output_stride,
    unsigned int claim_count,
    unsigned int class_count,
    unsigned int packed_classes
) {
    unsigned int index = blockIdx.x * blockDim.x + threadIdx.x;
    unsigned int count = class_count * value_count;
    if (index >= count) return;
    unsigned int rank = index / value_count;
    unsigned int position = index - rank * value_count;
    F16 total = z16();
    F16 one = z16();
    one.a.a.a.a = 1U;
    for (unsigned int claim = 0; claim < claim_count; ++claim) {
        if (((packed_classes >> (2U * claim)) & 3U) != rank) continue;
        F16 value = l16(coefficients + 16ULL * claim);
        for (unsigned int variable = 0; variable < variable_count; ++variable) {
            F16 coordinate = l16(
                points + 16ULL * (claim * point_stride + variable)
            );
            F16 factor = ((position >> variable) & 1U) != 0U
                ? coordinate
                : s16(one, coordinate);
            value = m16(value, factor);
        }
        total = a16(total, value);
    }
    st16(output + 16ULL * (rank * output_stride + position), total);
}

extern "C" __global__ void scale_wire_weights(
    unsigned int *weights,
    const unsigned int *scales,
    unsigned int stride,
    unsigned int value_count,
    unsigned int claim_count
) {
    unsigned int index = blockIdx.x * blockDim.x + threadIdx.x;
    unsigned int count = claim_count * value_count;
    if (index >= count) return;
    unsigned int claim = index / value_count;
    unsigned int position = index - claim * value_count;
    u64 offset = (u64)claim * stride + position;
    st16(
        weights + 16ULL * offset,
        m16(
            l16(weights + 16ULL * offset),
            l16(scales + 16ULL * claim)
        )
    );
}

extern "C" __global__ void split_group_weights(
    const unsigned int *current,
    unsigned int *zero,
    unsigned int *delta,
    unsigned int current_groups,
    unsigned int max_suffix,
    unsigned int claim_count
) {
    unsigned int index = blockIdx.x * blockDim.x + threadIdx.x;
    unsigned int suffix_groups = current_groups >> 1;
    unsigned int count = claim_count * suffix_groups;
    if (index >= count) return;
    unsigned int claim = index / suffix_groups;
    unsigned int suffix = index - claim * suffix_groups;
    F16 left = l16(current + 16ULL * (claim * current_groups + 2U * suffix));
    F16 right = l16(
        current + 16ULL * (claim * current_groups + 2U * suffix + 1U)
    );
    st16(zero + 16ULL * (claim * max_suffix + suffix), left);
    st16(delta + 16ULL * (claim * max_suffix + suffix), s16(right, left));
}

extern "C" __global__ void sum_tail_group_weights(
    const unsigned int *current,
    unsigned int *output,
    unsigned int first_tail_group,
    unsigned int current_groups,
    unsigned int claim_count
) {
    unsigned int index = blockIdx.x * blockDim.x + threadIdx.x;
    if (index >= claim_count * 16U) return;
    unsigned int claim = index >> 4U;
    unsigned int coordinate = index & 15U;
    unsigned int total = 0U;
    for (
        unsigned int group = first_tail_group;
        group < current_groups;
        ++group
    ) {
        total = addp(
            total,
            current[16ULL * (claim * current_groups + group) + coordinate]
        );
    }
    output[index] = total;
}

extern "C" __global__ void aggregate_group_weight_tail(
    unsigned int *zero,
    unsigned int *delta,
    unsigned int first_uniform_pair,
    unsigned int suffix_groups,
    unsigned int max_suffix,
    unsigned int claim_count
) {
    unsigned int index = blockIdx.x * blockDim.x + threadIdx.x;
    if (index >= claim_count * 32U) return;
    unsigned int claim = index >> 5U;
    unsigned int plane = (index >> 4U) & 1U;
    unsigned int coordinate = index & 15U;
    unsigned int *values = plane == 0U ? zero : delta;
    unsigned int total = 0U;
    for (
        unsigned int suffix = first_uniform_pair;
        suffix < suffix_groups;
        ++suffix
    ) {
        total = addp(
            total,
            values[
                16ULL * (claim * max_suffix + suffix) + coordinate
            ]
        );
    }
    values[
        16ULL * (claim * max_suffix + first_uniform_pair) + coordinate
    ] = total;
}

extern "C" __global__ void fold_group_weights(
    const unsigned int *current,
    const unsigned int *challenge,
    unsigned int *output,
    unsigned int current_groups,
    unsigned int claim_count
) {
    unsigned int index = blockIdx.x * blockDim.x + threadIdx.x;
    unsigned int output_groups = current_groups >> 1;
    unsigned int count = claim_count * output_groups;
    if (index >= count) return;
    unsigned int claim = index / output_groups;
    unsigned int suffix = index - claim * output_groups;
    F16 left = l16(current + 16ULL * (claim * current_groups + 2U * suffix));
    F16 right = l16(
        current + 16ULL * (claim * current_groups + 2U * suffix + 1U)
    );
    st16(
        output + 16ULL * index,
        a16(left, m16(l16(challenge), s16(right, left)))
    );
}

extern "C" __global__ void compact_fp16_group_fold(
    const unsigned int *input,
    const unsigned int *challenge,
    unsigned int *output,
    unsigned int width,
    unsigned int output_groups,
    unsigned int input_nonuniform_groups
) {
    unsigned long long index =
        (unsigned long long)blockIdx.x * blockDim.x + threadIdx.x;
    unsigned long long count = (unsigned long long)width * output_groups;
    if (index >= count) return;
    unsigned int group = (unsigned int)(index / width);
    unsigned int wire =
        (unsigned int)(index - (unsigned long long)group * width);
    unsigned int zero_group = min(2U * group, input_nonuniform_groups);
    unsigned int one_group = min(2U * group + 1U, input_nonuniform_groups);
    F16 zero = l16(input + 16ULL * (zero_group * width + wire));
    F16 one = l16(input + 16ULL * (one_group * width + wire));
    st16(
        output + 16ULL * index,
        a16(zero, m16(l16(challenge), s16(one, zero)))
    );
}

extern "C" __global__ void build_b16_lookup(
    const unsigned int *node_values,
    unsigned int *lookup
) {
    unsigned int pattern = blockIdx.x * blockDim.x + threadIdx.x;
    if (pattern >= 65536U) return;
    F16 value = z16();
    for (unsigned int node = 0; node < 16U; ++node) {
        if ((pattern >> node) & 1U) {
            value = a16(value, l16(node_values + 16ULL * node));
        }
    }
    st16(lookup + 16ULL * pattern, value);
}

extern "C" __global__ void combine_wire_weights(
    const unsigned int *wire_weights,
    const unsigned int *group_weights,
    unsigned int *effective_weights,
    unsigned int raw_width,
    unsigned int max_raw,
    unsigned int claim_count
) {
    unsigned int output = blockIdx.x * blockDim.x + threadIdx.x;
    if (output >= raw_width) return;
    F16 total = z16();
    for (unsigned int claim = 0; claim < claim_count; ++claim) {
        total = a16(
            total,
            m16(
                l16(wire_weights + 16ULL * (claim * max_raw + output)),
                l16(group_weights + 16ULL * claim)
            )
        );
    }
    st16(effective_weights + 16ULL * output, total);
}

extern "C" __global__ void initialize_wire_factors(
    unsigned int *left_factors,
    unsigned int *right_factors,
    unsigned int raw_width
) {
    unsigned int output = blockIdx.x * blockDim.x + threadIdx.x;
    if (output >= raw_width) return;
    F16 one = z16();
    one.a.a.a.a = 1U;
    st16(left_factors + 16ULL * output, one);
    st16(right_factors + 16ULL * output, one);
}

__device__ __forceinline__ void reduce_wire_quadratic(
    F16 c0,
    F16 c1,
    F16 c2,
    unsigned int *output,
    unsigned int block_output
) {
    __shared__ unsigned int sums[128 * 48];
    unsigned int thread = threadIdx.x;
    unsigned int *slot = sums + 48U * thread;
    st16(slot, c0);
    st16(slot + 16, c1);
    st16(slot + 32, c2);
    __syncthreads();
    for (unsigned int stride = 64U; stride > 0U; stride >>= 1U) {
        if (thread < stride) {
            unsigned int *destination = sums + 48U * thread;
            const unsigned int *source = sums + 48U * (thread + stride);
            for (unsigned int coordinate = 0; coordinate < 48U; ++coordinate) {
                destination[coordinate] =
                    addp(destination[coordinate], source[coordinate]);
            }
        }
        __syncthreads();
    }
    if (thread == 0U) {
        for (unsigned int coordinate = 0; coordinate < 48U; ++coordinate) {
            output[48ULL * block_output + coordinate] = sums[coordinate];
        }
    }
}

extern "C" __global__ void wire_round_message(
    const unsigned int *varying_values,
    const unsigned int *fixed_right_values,
    const unsigned int *masked_terminal_left,
    const unsigned int *base_left,
    const unsigned int *base_right,
    const unsigned int *formulas,
    const unsigned int *effective_weights,
    const unsigned int *left_factors,
    const unsigned int *right_factors,
    unsigned int *partial,
    unsigned int raw_width,
    unsigned int round,
    unsigned int varying_left
) {
    F16 total0 = z16();
    F16 total1 = z16();
    F16 total2 = z16();
    F16 one = z16();
    one.a.a.a.a = 1U;
    for (
        unsigned int output = threadIdx.x;
        output < raw_width;
        output += blockDim.x
    ) {
        unsigned int wire = varying_left != 0U
            ? base_left[output]
            : base_right[output];
        unsigned int suffix = wire >> (round + 1U);
        F16 zero = l16(varying_values + 16ULL * (2U * suffix));
        F16 delta = s16(
            l16(varying_values + 16ULL * (2U * suffix + 1U)),
            zero
        );
        F16 fixed = varying_left != 0U
            ? l16(fixed_right_values + 16ULL * base_right[output])
            : l16(masked_terminal_left);
        F16 twice_fixed = a16(fixed, fixed);
        F16 gate_zero;
        F16 gate_delta;
        unsigned int formula = formulas[output];
        if (formula == 1U) {
            if (varying_left != 0U) {
                gate_zero = s16(fixed, m16(zero, fixed));
                gate_delta = s16(z16(), m16(delta, fixed));
            } else {
                F16 complement = s16(one, fixed);
                gate_zero = m16(zero, complement);
                gate_delta = m16(delta, complement);
            }
        } else if (formula == 2U) {
            gate_zero = a16(
                s16(s16(one, zero), fixed),
                m16(zero, twice_fixed)
            );
            gate_delta = m16(delta, s16(twice_fixed, one));
        } else {
            gate_zero = s16(a16(zero, fixed), m16(zero, twice_fixed));
            gate_delta = m16(delta, s16(one, twice_fixed));
        }
        F16 weight = m16(
            m16(
                l16(effective_weights + 16ULL * output),
                l16(left_factors + 16ULL * output)
            ),
            l16(right_factors + 16ULL * output)
        );
        F16 c0;
        F16 c1;
        F16 c2;
        if (((wire >> round) & 1U) == 0U) {
            c0 = m16(weight, gate_zero);
            c1 = m16(weight, s16(gate_delta, gate_zero));
            c2 = s16(z16(), m16(weight, gate_delta));
        } else {
            c0 = z16();
            c1 = m16(weight, gate_zero);
            c2 = m16(weight, gate_delta);
        }
        total0 = a16(total0, c0);
        total1 = a16(total1, c1);
        total2 = a16(total2, c2);
    }
    reduce_wire_quadratic(total0, total1, total2, partial, 0U);
}

extern "C" __global__ void fold_and_update_wire(
    unsigned int *factors,
    const unsigned int *wire_indices,
    const unsigned int *input,
    unsigned int *output,
    const unsigned int *challenge,
    unsigned int raw_width,
    unsigned int current_width,
    unsigned int round
) {
    unsigned int index = blockIdx.x * blockDim.x + threadIdx.x;
    F16 point = l16(challenge);
    if (index < raw_width) {
        F16 one = z16();
        one.a.a.a.a = 1U;
        F16 basis = ((wire_indices[index] >> round) & 1U) != 0U
            ? point
            : s16(one, point);
        st16(
            factors + 16ULL * index,
            m16(l16(factors + 16ULL * index), basis)
        );
    }
    unsigned int output_width = current_width >> 1U;
    if (index < output_width) {
        F16 zero = l16(input + 16ULL * (2U * index));
        F16 one = l16(input + 16ULL * (2U * index + 1U));
        st16(
            output + 16ULL * index,
            a16(zero, m16(point, s16(one, zero)))
        );
    }
}
"""


def read_exact(stream, count):
    value = stream.read(count)
    if len(value) != count:
        raise EOFError(f"short_read:{len(value)}:{count}")
    return value


def read_field(stream):
    encoded = read_exact(stream, 64)
    coordinates = struct.unpack(">16I", encoded)
    if any(value >= Q for value in coordinates):
        raise ValueError("noncanonical_field")
    return coordinates


def write_field(stream, value):
    if len(value) != 16 or any(coordinate < 0 or coordinate >= Q for coordinate in value):
        raise ValueError("invalid_field")
    stream.write(struct.pack(">16I", *value))


def write_field_words(stream, words):
    if (
        not isinstance(words, array.array)
        or words.typecode != "I"
        or len(words) % 16 != 0
        or any(coordinate >= Q for coordinate in words)
    ):
        raise ValueError("invalid_field_words")
    if sys.byteorder == "little":
        words.byteswap()
    stream.write(words)


def upload(runtime, values, label):
    pointer = runtime.alloc(len(values) * values.itemsize)
    return pointer, copy(runtime, pointer, values, label)


def module_function(runtime, module, name):
    return runtime.module_function(module, name.encode())


def read_fp16_words(runtime, pointer, count, label, output_count=None):
    output_count = count if output_count is None else output_count
    if count < 0 or output_count < count:
        raise ValueError("fp16_word_count")
    words = array.array("I", [0]) * (output_count * 16)
    view = (ctypes.c_ubyte * (len(words) * words.itemsize)).from_buffer(words)
    ck(
        runtime.cuda.cuMemcpyDtoH_v2(
            ctypes.cast(view, ctypes.c_void_p),
            pointer,
            count * 16 * words.itemsize,
        ),
        label,
    )
    del view
    return words


def read_fp16_values(runtime, pointer, count, label):
    words = read_fp16_words(runtime, pointer, count, label)
    return [tuple(words[16 * index : 16 * (index + 1)]) for index in range(count)]


def write_device_u16(runtime, pointer, values, label):
    return copy(runtime, pointer, values, label)


class LayerPlan:
    def __init__(
        self,
        left_source,
        right_source,
        left_width,
        right_width,
        left_live_width,
        right_live_width,
        raw_width,
        base_left,
        base_right,
        formulas,
    ):
        self.left_source = left_source
        self.right_source = right_source
        self.left_width = left_width
        self.right_width = right_width
        self.left_live_width = left_live_width
        self.right_live_width = right_live_width
        self.raw_width = raw_width
        self.padded_width = 1 << (raw_width - 1).bit_length()
        self.base_left = base_left
        self.base_right = base_right
        self.formulas = formulas


def read_plan(stream):
    rounds = []
    for round_index in range(24):
        layers = []
        for layer_index in range(7):
            left_source, right_source = read_exact(stream, 2)
            left_width, right_width, raw_width = struct.unpack(
                ">HHH", read_exact(stream, 6)
            )
            if (
                left_source > layer_index
                or right_source > layer_index
                or left_width not in (512, 1_024, 2_048)
                or right_width not in (512, 1_024, 2_048)
                or raw_width <= 0
                or raw_width > 1_600
            ):
                raise ValueError("plan_shape")
            left_live_width = (
                LIVE_WIRES
                if left_source == 0
                else layers[left_source - 1].raw_width
            )
            right_live_width = (
                LIVE_WIRES
                if right_source == 0
                else layers[right_source - 1].raw_width
            )
            if (
                left_live_width > left_width
                or right_live_width > right_width
            ):
                raise ValueError("plan_live_width")
            gate_payload = read_exact(stream, raw_width * 5)
            base_left = array.array("I")
            base_right = array.array("I")
            formulas = array.array("B")
            for left, right, formula in struct.iter_unpack(
                ">HHB", gate_payload
            ):
                if (
                    left >= left_live_width
                    or right >= right_live_width
                    or formula > 3
                ):
                    raise ValueError("plan_gate")
                base_left.append(left)
                base_right.append(right)
                formulas.append(formula)
            layers.append(
                LayerPlan(
                    left_source,
                    right_source,
                    left_width,
                    right_width,
                    left_live_width,
                    right_live_width,
                    raw_width,
                    base_left,
                    base_right,
                    formulas,
                )
            )
        rounds.append(layers)
    return rounds


def compact_boundary_plane(values, nonuniform_groups, packed_groups):
    if (
        len(values) != LIVE_WIRES * GROUP_COUNT
        or nonuniform_groups <= 0
        or nonuniform_groups > GROUP_COUNT
        or packed_groups < nonuniform_groups
        or packed_groups > GROUP_COUNT
        or packed_groups % 4 != 0
    ):
        raise ValueError("boundary_compact_shape")
    if nonuniform_groups == GROUP_COUNT:
        return values
    compact = array.array("H", [0]) * (LIVE_WIRES * packed_groups)
    for wire in range(LIVE_WIRES):
        source_start = wire * GROUP_COUNT
        destination_start = wire * packed_groups
        representative = values[source_start + nonuniform_groups]
        if any(
            value != representative
            for value in values[
                source_start + nonuniform_groups : source_start + GROUP_COUNT
            ]
        ):
            raise ValueError("boundary_dummy_tail")
        compact[
            destination_start : destination_start + nonuniform_groups
        ] = values[source_start : source_start + nonuniform_groups]
        compact[
            destination_start + nonuniform_groups :
            destination_start + packed_groups
        ] = array.array(
            "H", [representative]
        ) * (packed_groups - nonuniform_groups)
    return compact


def read_boundary(path, shard):
    file_bytes = path.stat().st_size
    with path.open("rb") as source:
        header = read_exact(source, BOUNDARY_HEADER_BYTES)
        magic = header[:8]
        version = header[8:10]
        state_composed = magic == STATE_BOUNDARY_MAGIC and version == b"\x00\x02"
        if not (
            (magic == BOUNDARY_MAGIC and version == b"\x00\x01")
            or state_composed
        ):
            raise ValueError("boundary_header")
        profile = header[10]
        shards = int.from_bytes(header[203:205], "big")
        padded = int.from_bytes(header[205:213], "big")
        live_wires = int.from_bytes(header[213:215], "big")
        profile_totals = (
            PROFILE_STATE_TOTAL_PERMUTATIONS
            if state_composed
            else PROFILE_TOTAL_PERMUTATIONS
        )
        expected = BOUNDARY_HEADER_BYTES + shards * 2 * LIVE_WIRES * GROUP_COUNT * 2
        if (
            profile not in profile_totals
            or shard < 0
            or shard >= shards
            or padded != shards * GROUP_COUNT * 16
            or live_wires != LIVE_WIRES
            or file_bytes != expected
        ):
            raise ValueError("boundary_shape")
        boundary_bytes = LIVE_WIRES * GROUP_COUNT * 2
        source.seek(BOUNDARY_HEADER_BYTES + shard * 2 * boundary_bytes)
        input_values = array.array("H")
        input_values.fromfile(source, LIVE_WIRES * GROUP_COUNT)
        output_values = array.array("H")
        output_values.fromfile(source, LIVE_WIRES * GROUP_COUNT)
    if sys.byteorder != "little":
        input_values.byteswap()
        output_values.byteswap()
    shard_start = shard * PERMUTATIONS_PER_SHARD
    shard_permutations = min(
        PERMUTATIONS_PER_SHARD,
        max(0, profile_totals[profile] - shard_start),
    )
    if shard_permutations <= 0:
        raise ValueError("boundary_live_shard")
    nonuniform_groups = (shard_permutations + 15) // 16
    if nonuniform_groups == GROUP_COUNT:
        packed_groups = GROUP_COUNT
    else:
        first_message_groups = (nonuniform_groups + 1) // 2 + 1
        packed_groups = (2 * first_message_groups + 3) & ~3
    return (
        compact_boundary_plane(input_values, nonuniform_groups, packed_groups),
        compact_boundary_plane(output_values, nonuniform_groups, packed_groups),
        nonuniform_groups,
        packed_groups,
    )


class Worker:
    def __init__(self):
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
            raise ValueError("nvrtc_runtime_missing")
        self.nvrtc = nvrtc
        self.profile_enabled = os.environ.get("BL_HASH_BUS_GKR_PROFILE") == "1"
        self.profile = {}
        self.module_images = self._precompiled_module_images()
        self.basis_host = m31_basis()
        self._create_runtime()
        self.activated = False

    @staticmethod
    def _precompiled_module_images():
        directory = os.environ.get("BL_HASH_BUS_GKR_MODULE_DIR")
        expected_hashes = tuple(
            os.environ.get(name)
            for name in (
                "BL_HASH_BUS_GKR_BRIDGE_MODULE_SHA256",
                "BL_HASH_BUS_GKR_GROUP_MODULE_SHA256",
                "BL_HASH_BUS_GKR_WORKER_MODULE_SHA256",
            )
        )
        if directory is None and all(value is None for value in expected_hashes):
            return None
        if directory is None or any(value is None for value in expected_hashes):
            raise ValueError("precompiled_gkr_module_gate_incomplete")
        images = []
        for name, expected_hash in zip(
            (
                "hash-bus-gkr-bridge-sm89.cubin",
                "hash-bus-gkr-group-sm89.cubin",
                "hash-bus-gkr-worker-sm89.cubin",
            ),
            expected_hashes,
        ):
            path = Path(directory) / name
            if not path.is_file():
                raise ValueError(f"precompiled_gkr_module_missing={name}")
            image = path.read_bytes()
            if (
                not image
                or len(image) > 16_000_000
                or image[:4] != b"\x7fELF"
                or hashlib.sha256(image).hexdigest()
                != expected_hash.lower()
            ):
                raise ValueError(f"precompiled_gkr_module_identity={name}")
            images.append(image)
        return tuple(images)

    def activate(self, boundary, shard, plans):
        if self.activated:
            raise ValueError("worker_already_activated")
        self.plans = plans
        (
            self.input_host,
            self.output_host,
            self.initial_nonuniform_groups,
            self.packed_group_count,
        ) = read_boundary(boundary, shard)
        self.words_per_wire = self.packed_group_count // 4
        started = time.perf_counter()
        self._allocate()
        self._profile_add("allocate", started)
        started = time.perf_counter()
        self._build_checkpoints()
        self._profile_add("build_checkpoints", started)
        self.prepared_round = None
        self.group_weight_current = self.group_weight_a
        self.group_weight_output = self.group_weight_b
        self.completed_layers = 0
        self.cached_output = None
        self.claims = None
        self.plan = None
        self.left_packed = 0
        self.right_packed = 0
        self.current_groups = 0
        self.current_left = 0
        self.current_right = 0
        self.left_output = 0
        self.right_output = 0
        self.next_group_round = 0
        self.next_left_wire_round = 0
        self.next_right_wire_round = 0
        self.wire_ready = False
        self.pending_wire = None
        self.activated = True

    def _profile_add(self, name, started):
        if self.profile_enabled:
            self.profile[name] = self.profile.get(name, 0.0) + (
                time.perf_counter() - started
            )

    def _create_runtime(self):
        started = time.perf_counter()
        self.runtime = Runtime(self.nvrtc)
        self._profile_add("runtime_create", started)
        self.runtime.cuda.cuMemsetD8_v2.argtypes = [
            ctypes.c_uint64,
            ctypes.c_ubyte,
            ctypes.c_size_t,
        ]
        self.runtime.cuda.cuMemcpyDtoD_v2.argtypes = [
            ctypes.c_uint64,
            ctypes.c_uint64,
            ctypes.c_size_t,
        ]
        started = time.perf_counter()
        self._compile()
        self._profile_add("module_compile_or_load", started)

    def _compile(self):
        runtime = self.runtime
        if self.module_images is None:
            self.module_images = (
                runtime.compile_ptx(BRIDGE_KERNEL),
                runtime.compile_ptx(CUDA + FOLD_KERNEL + MESSAGE_KERNEL),
                runtime.compile_ptx(WORKER_KERNEL),
            )
        (
            self.bridge_module,
            self.group_module,
            self.worker_module,
        ) = tuple(
            runtime.load_module(image) for image in self.module_images
        )
        for name in (
            "accumulate_b16_bridge_fused_shared",
            "product_left_transform",
            "product_right_transform",
            "assemble_relation",
            "compose_degree45_message",
        ):
            setattr(
                self,
                name,
                module_function(runtime, self.bridge_module, name),
            )
        for name in (
            "packed_b16_group_message",
            "packed_b16_group_message_factored_one_claim",
            "packed_b16_first_group_fold",
            "fp16_group_message",
            "fp16_group_message_factored_one_claim",
            "reduce_cubic_partials",
        ):
            setattr(
                self,
                name,
                module_function(runtime, self.group_module, name),
            )
        for name in (
            "evaluate_b16_dag_layer",
            "equality_table",
            "ranked_wire_equality_table",
            "scale_wire_weights",
            "split_group_weights",
            "sum_tail_group_weights",
            "aggregate_group_weight_tail",
            "fold_group_weights",
            "compact_fp16_group_fold",
            "build_b16_lookup",
            "combine_wire_weights",
            "initialize_wire_factors",
            "wire_round_message",
            "fold_and_update_wire",
        ):
            setattr(
                self,
                name,
                module_function(runtime, self.worker_module, name),
            )

    def _allocate(self):
        runtime = self.runtime
        state_bytes = LIVE_WIRES * self.packed_group_count * 2
        self.round_input_d = runtime.alloc(state_bytes)
        layer_live_widths = [
            max(round_plans[layer_index].raw_width for round_plans in self.plans)
            for layer_index in range(7)
        ]
        if any(width <= 0 or width > LIVE_WIRES for width in layer_live_widths):
            raise ValueError("layer_live_width")
        self.layer_d = [
            runtime.alloc(width * self.packed_group_count * 2)
            for width in layer_live_widths
        ]
        self.state_bytes = state_bytes

        geometry_slots = len(self.plans) * len(self.plans[0])
        base_left = array.array("I", [0]) * (geometry_slots * MAX_RAW)
        base_right = array.array("I", [0]) * (geometry_slots * MAX_RAW)
        formulas = array.array("I", [0]) * (geometry_slots * MAX_RAW)
        for round_index, round_plans in enumerate(self.plans):
            if len(round_plans) != 7:
                raise ValueError("geometry_layer_count")
            for layer_index, plan in enumerate(round_plans):
                slot = round_index * 7 + layer_index
                start = slot * MAX_RAW
                end = start + plan.raw_width
                base_left[start:end] = plan.base_left
                base_right[start:end] = plan.base_right
                converted_formulas = array.array(
                    "I",
                    (
                        2 if formula == 3 else (1 if formula == 1 else 0)
                        for formula in plan.formulas
                    ),
                )
                formulas[start:end] = converted_formulas
                families = set(converted_formulas)
                if families.issubset({0, 2}):
                    plan.formula_family = 0
                elif families == {1}:
                    plan.formula_family = 1
                else:
                    raise ValueError("bridge_formula_family")
                plan.geometry_offset = start * 4
        self.base_left_geometry_d, _ = upload(
            runtime, base_left, "copy_all_base_left_geometry"
        )
        self.base_right_geometry_d, _ = upload(
            runtime, base_right, "copy_all_base_right_geometry"
        )
        self.formulas_geometry_d, _ = upload(
            runtime, formulas, "copy_all_formula_geometry"
        )
        self.points_d = runtime.alloc(MAX_CLAIMS * 24 * FP16_BYTES)
        self.coefficients_d = runtime.alloc(MAX_CLAIMS * FP16_BYTES)
        self.wire_weights_d = runtime.alloc(MAX_CLAIMS * MAX_RAW * FP16_BYTES)
        self.group_weight_a = runtime.alloc(MAX_CLAIMS * GROUP_COUNT * FP16_BYTES)
        self.group_weight_b = runtime.alloc(MAX_CLAIMS * GROUP_COUNT * FP16_BYTES)
        self.group_zero_d = runtime.alloc(MAX_CLAIMS * MAX_SUFFIX * FP16_BYTES)
        self.group_delta_d = runtime.alloc(MAX_CLAIMS * MAX_SUFFIX * FP16_BYTES)
        self.tail_group_weights_d = runtime.alloc(MAX_CLAIMS * FP16_BYTES)
        self.challenge_d = runtime.alloc(FP16_BYTES)
        self.lookup_d = runtime.alloc(65_536 * FP16_BYTES)
        self.selectors_d = runtime.alloc(MAX_CLAIMS * 16 * FP16_BYTES)
        self.basis_d, _ = upload(
            runtime, chunk_basis_table(self.basis_host), "copy_bridge_basis"
        )

        product_plane = MAX_CLAIMS * 4 * 65_536 * 16 * 4
        constant_plane = MAX_CLAIMS * 16 * 4
        self.product_sum_d = runtime.alloc(2 * product_plane)
        self.constant_low_d = runtime.alloc(constant_plane)
        self.constant_carry_d = runtime.alloc(constant_plane)
        self.temporary_d = runtime.alloc(MAX_CLAIMS * 4 * 17 * 256 * 16 * 4)
        self.matrix_d = runtime.alloc(MAX_CLAIMS * 4 * 17 * 17 * 16 * 4)
        self.relation_d = runtime.alloc(MAX_CLAIMS * 31 * FP16_BYTES)
        self.message_d = runtime.alloc(BRIDGE_COEFFICIENTS * FP16_BYTES)
        self.product_sum_size = 2 * product_plane
        self.constant_plane_size = constant_plane

        first_nonuniform = (self.initial_nonuniform_groups + 1) // 2
        first_groups = first_nonuniform + (
            1 if first_nonuniform < GROUP_COUNT // 2 else 0
        )
        second_nonuniform = (first_nonuniform + 1) // 2
        second_groups = second_nonuniform + (
            1 if second_nonuniform < GROUP_COUNT // 4 else 0
        )
        main_size = LIVE_WIRES * first_groups * FP16_BYTES
        scratch_size = LIVE_WIRES * second_groups * FP16_BYTES
        self.left_main_d = runtime.alloc(main_size)
        self.right_main_d = runtime.alloc(main_size)
        self.left_scratch_d = runtime.alloc(scratch_size)
        self.right_scratch_d = runtime.alloc(scratch_size)
        max_terms = MAX_RAW * MAX_SUFFIX
        max_blocks = (
            max_terms + THREADS * TERMS_PER_THREAD - 1
        ) // (THREADS * TERMS_PER_THREAD)
        self.partial_size = max_blocks * 64 * 4
        self.partial_d = runtime.alloc(self.partial_size)
        self.reduction_scratch_d = runtime.alloc(self.partial_size)

        wire_vector_size = PADDED_WIRES * FP16_BYTES
        self.effective_wire_weights_d = runtime.alloc(MAX_RAW * FP16_BYTES)
        self.left_wire_factors_d = runtime.alloc(MAX_RAW * FP16_BYTES)
        self.right_wire_factors_d = runtime.alloc(MAX_RAW * FP16_BYTES)
        self.wire_left_a_d = runtime.alloc(wire_vector_size)
        self.wire_left_b_d = runtime.alloc(wire_vector_size)
        self.wire_right_a_d = runtime.alloc(wire_vector_size)
        self.wire_right_b_d = runtime.alloc(wire_vector_size)
        self.masked_terminal_left_d = runtime.alloc(FP16_BYTES)

    def _source_pointer(self, sources, tag):
        return sources[0] if tag == 0 else sources[tag]

    def _copy_geometry(self, plan):
        self.base_left_d = (
            self.base_left_geometry_d + plan.geometry_offset
        )
        self.base_right_d = (
            self.base_right_geometry_d + plan.geometry_offset
        )
        self.formulas_d = (
            self.formulas_geometry_d + plan.geometry_offset
        )
        self.formula_family = plan.formula_family

    def _evaluate_round(self, round_index, round_input):
        sources = [round_input]
        for layer_index, plan in enumerate(self.plans[round_index]):
            self._copy_geometry(plan)
            left = self._source_pointer(sources, plan.left_source)
            right = self._source_pointer(sources, plan.right_source)
            output = self.layer_d[layer_index]
            count = plan.raw_width * self.packed_group_count
            launch(
                self.runtime,
                self.evaluate_b16_dag_layer,
                (count + 255) // 256,
                256,
                arguments(
                    ctypes.c_uint64(left),
                    ctypes.c_uint64(right),
                    ctypes.c_uint64(self.base_left_d),
                    ctypes.c_uint64(self.base_right_d),
                    ctypes.c_uint64(self.formulas_d),
                    ctypes.c_uint64(output),
                    ctypes.c_uint32(plan.raw_width),
                    ctypes.c_uint32(plan.raw_width),
                    ctypes.c_uint32(self.packed_group_count),
                ),
                "evaluate_b16_dag_layer",
            )
            sources.append(output)
        return sources

    def _upload_live_state(self, values):
        ck(
            self.runtime.cuda.cuMemsetD8_v2(
                self.round_input_d, 0, self.state_bytes
            ),
            "zero_round_input",
        )
        write_device_u16(
            self.runtime, self.round_input_d, values, "copy_round_input"
        )

    def _read_live_state(self, pointer):
        values = array.array("H", [0]) * (
            LIVE_WIRES * self.packed_group_count
        )
        view = (ctypes.c_ubyte * (len(values) * 2)).from_buffer(values)
        ck(
            self.runtime.cuda.cuMemcpyDtoH_v2(
                ctypes.cast(view, ctypes.c_void_p),
                pointer,
                len(values) * 2,
            ),
            "copy_live_state",
        )
        return values

    def _build_checkpoints(self):
        self.checkpoints = {0: self.input_host}
        self._upload_live_state(self.input_host)
        current = self.round_input_d
        for round_index in range(24):
            sources = self._evaluate_round(round_index, current)
            current = sources[7]
            if round_index + 1 < 24 and (round_index + 1) % 4 == 0:
                self.checkpoints[round_index + 1] = self._read_live_state(current)
        final = self._read_live_state(current)
        if final != self.output_host:
            raise ValueError("boundary_trace_mismatch")

    def prepare_round(self, target):
        if self.prepared_round == target:
            return
        started = time.perf_counter()
        checkpoint = target - target % 4
        self._upload_live_state(self.checkpoints[checkpoint])
        current = self.round_input_d
        for round_index in range(checkpoint, target):
            sources = self._evaluate_round(round_index, current)
            current = sources[7]
        if current != self.round_input_d:
            ck(
                self.runtime.cuda.cuMemcpyDtoD_v2(
                    self.round_input_d, current, self.state_bytes
                ),
                "preserve_target_round_input",
            )
        sources = self._evaluate_round(target, self.round_input_d)
        self.prepared_sources = sources
        self.prepared_round = target
        self._profile_add("prepare_round", started)

    def _claim_arrays(self, claims, coefficient_values):
        points = array.array("I", [0]) * (MAX_CLAIMS * 24 * 16)
        coefficients = array.array("I", [0]) * (MAX_CLAIMS * 16)
        for claim_index, claim in enumerate(claims):
            for point_index, value in enumerate(claim["point"]):
                points[
                    16 * (claim_index * 24 + point_index) :
                    16 * (claim_index * 24 + point_index + 1)
                ] = array.array("I", value)
            coefficients[
                16 * claim_index : 16 * (claim_index + 1)
            ] = array.array("I", coefficient_values[claim_index])
        copy(self.runtime, self.points_d, points, "copy_claim_points")
        copy(
            self.runtime,
            self.coefficients_d,
            coefficients,
            "copy_claim_coefficients",
        )

    def _rank_claims(self, claims, output_variables):
        class_by_key = {}
        representatives = []
        classes = []
        for claim in claims:
            key = (
                tuple(claim["point"][output_variables:]),
                claim["query"],
                tuple(claim["selector"]),
            )
            rank = class_by_key.get(key)
            if rank is None:
                rank = len(representatives)
                class_by_key[key] = rank
                representatives.append(claim)
            classes.append(rank)
        if not representatives or len(representatives) > len(claims):
            raise ValueError("claim_rank")
        return representatives, classes

    def _generate_equality_weights(
        self,
        claims,
        coefficients,
        output_variables,
        ranked_claims,
        classes,
    ):
        self._claim_arrays(claims, coefficients)
        claim_count = len(claims)
        rank_count = len(ranked_claims)
        packed_classes = sum(
            rank << (2 * claim) for claim, rank in enumerate(classes)
        )
        launch(
            self.runtime,
            self.ranked_wire_equality_table,
            (rank_count * self.plan.raw_width + 255) // 256,
            256,
            arguments(
                ctypes.c_uint64(self.points_d),
                ctypes.c_uint64(self.coefficients_d),
                ctypes.c_uint64(self.wire_weights_d),
                ctypes.c_uint32(24),
                ctypes.c_uint32(output_variables),
                ctypes.c_uint32(self.plan.raw_width),
                ctypes.c_uint32(MAX_RAW),
                ctypes.c_uint32(claim_count),
                ctypes.c_uint32(rank_count),
                ctypes.c_uint32(packed_classes),
            ),
            "materialize_ranked_wire_equality",
        )
        one_coefficients = array.array("I", [0]) * (MAX_CLAIMS * 16)
        for claim in range(rank_count):
            one_coefficients[16 * claim] = 1
        self._claim_arrays(
            ranked_claims,
            [
                tuple(one_coefficients[16 * claim : 16 * (claim + 1)])
                for claim in range(rank_count)
            ],
        )
        launch(
            self.runtime,
            self.equality_table,
            (rank_count * GROUP_COUNT + 255) // 256,
            256,
            arguments(
                ctypes.c_uint64(self.points_d),
                ctypes.c_uint64(self.coefficients_d),
                ctypes.c_uint64(self.group_weight_a),
                ctypes.c_uint32(24),
                ctypes.c_uint32(output_variables),
                ctypes.c_uint32(13),
                ctypes.c_uint32(GROUP_COUNT),
                ctypes.c_uint32(GROUP_COUNT),
                ctypes.c_uint32(rank_count),
            ),
            "materialize_group_equality",
        )

    def _zero_bridge(self):
        for pointer, size, label in (
            (self.product_sum_d, self.product_sum_size, "zero_product"),
            (self.constant_low_d, self.constant_plane_size, "zero_constant_low"),
            (self.constant_carry_d, self.constant_plane_size, "zero_constant_carry"),
        ):
            ck(self.runtime.cuda.cuMemsetD8_v2(pointer, 0, size), label)

    def _finalize_bridge(self, claim_count, formula_family):
        launch(
            self.runtime,
            self.product_left_transform,
            claim_count * 4 * 17 * 256,
            256,
            arguments(
                ctypes.c_uint64(self.product_sum_d),
                ctypes.c_uint64(self.basis_d),
                ctypes.c_uint64(self.temporary_d),
                ctypes.c_uint32(claim_count),
            ),
            "product_left_transform",
        )
        launch(
            self.runtime,
            self.product_right_transform,
            claim_count * 4 * 17 * 17,
            256,
            arguments(
                ctypes.c_uint64(self.temporary_d),
                ctypes.c_uint64(self.basis_d),
                ctypes.c_uint64(self.matrix_d),
                ctypes.c_uint32(claim_count),
            ),
            "product_right_transform",
        )
        launch(
            self.runtime,
            self.assemble_relation,
            claim_count * 31,
            16,
            arguments(
                ctypes.c_uint64(self.matrix_d),
                ctypes.c_uint64(self.constant_low_d),
                ctypes.c_uint64(self.constant_carry_d),
                ctypes.c_uint64(self.relation_d),
                ctypes.c_uint32(claim_count),
                ctypes.c_uint32(formula_family),
            ),
            "assemble_relation",
        )
        launch(
            self.runtime,
            self.compose_degree45_message,
            BRIDGE_COEFFICIENTS,
            128,
            arguments(
                ctypes.c_uint64(self.relation_d),
                ctypes.c_uint64(self.selectors_d),
                ctypes.c_uint64(self.message_d),
                ctypes.c_uint32(claim_count),
            ),
            "compose_degree45_message",
        )

    def begin_layer(self, round_index, layer_index, claims):
        started = time.perf_counter()
        if (
            not claims
            or len(claims) > MAX_CLAIMS
            or self.wire_ready
            or self.pending_wire is not None
        ):
            raise ValueError("claim_count")
        self.prepare_round(round_index)
        self.current_context = (round_index, layer_index)
        self.plan = self.plans[round_index][layer_index]
        self._copy_geometry(self.plan)
        self.left_packed = self._source_pointer(
            self.prepared_sources, self.plan.left_source
        )
        self.right_packed = self._source_pointer(
            self.prepared_sources, self.plan.right_source
        )
        if (
            self.left_packed == self.right_packed
            and self.plan.left_live_width != self.plan.right_live_width
        ):
            raise ValueError("shared_source_live_width")
        output_variables = self.plan.padded_width.bit_length() - 1
        if any(
            len(claim["point"]) != output_variables + 13
            for claim in claims
        ):
            raise ValueError("claim_point_shape")
        ranked_claims, claim_classes = self._rank_claims(
            claims, output_variables
        )
        self.original_claim_count = len(claims)
        self.claim_classes = claim_classes
        coefficients = [claim["coefficient"] for claim in claims]
        phase_started = time.perf_counter()
        self._generate_equality_weights(
            claims,
            coefficients,
            output_variables,
            ranked_claims,
            claim_classes,
        )
        self._profile_add("begin_equality", phase_started)
        phase_started = time.perf_counter()
        selectors = array.array(
            "I",
            (
                coordinate
                for claim in ranked_claims
                for coefficient in claim["selector"]
                for coordinate in coefficient
            ),
        )
        padded_selectors = array.array("I", [0]) * (MAX_CLAIMS * 16 * 16)
        padded_selectors[: len(selectors)] = selectors
        copy(self.runtime, self.selectors_d, padded_selectors, "copy_selectors")
        self._profile_add("begin_selector", phase_started)
        phase_started = time.perf_counter()
        self._zero_bridge()
        self._profile_add("begin_zero_bridge", phase_started)
        claim_count = len(ranked_claims)
        phase_started = time.perf_counter()
        bridge_groups = GROUP_COUNT
        if self.initial_nonuniform_groups < GROUP_COUNT:
            bridge_groups = self.initial_nonuniform_groups + 1
            launch(
                self.runtime,
                self.sum_tail_group_weights,
                1,
                128,
                arguments(
                    ctypes.c_uint64(self.group_weight_a),
                    ctypes.c_uint64(self.tail_group_weights_d),
                    ctypes.c_uint32(self.initial_nonuniform_groups),
                    ctypes.c_uint32(GROUP_COUNT),
                    ctypes.c_uint32(claim_count),
                ),
                "sum_bridge_tail_group_weights",
            )
        bridge_terms = self.plan.raw_width * bridge_groups * claim_count
        launch(
            self.runtime,
            self.accumulate_b16_bridge_fused_shared,
            (bridge_terms + 127) // 128,
            128,
            arguments(
                ctypes.c_uint64(self.left_packed),
                ctypes.c_uint64(self.right_packed),
                ctypes.c_uint64(self.wire_weights_d),
                ctypes.c_uint64(self.group_weight_a),
                ctypes.c_uint64(self.tail_group_weights_d),
                ctypes.c_uint64(self.base_left_d),
                ctypes.c_uint64(self.base_right_d),
                ctypes.c_uint64(self.formulas_d),
                ctypes.c_uint64(self.product_sum_d),
                ctypes.c_uint64(self.constant_low_d),
                ctypes.c_uint64(self.constant_carry_d),
                ctypes.c_uint32(self.plan.raw_width),
                ctypes.c_uint32(bridge_groups),
                ctypes.c_uint32(0),
                ctypes.c_uint32(self.words_per_wire),
                ctypes.c_uint32(MAX_RAW),
                ctypes.c_uint32(GROUP_COUNT),
                ctypes.c_uint32(self.initial_nonuniform_groups),
                ctypes.c_uint32(claim_count),
            ),
            "accumulate_bridge_fused_shared",
        )
        if self.profile_enabled:
            ck(
                self.runtime.cuda.cuCtxSynchronize(),
                "profile_bridge_accumulate_sync",
            )
        self._profile_add("begin_bridge_tiles", phase_started)
        phase_started = time.perf_counter()
        self._finalize_bridge(claim_count, self.formula_family)
        self._profile_add("begin_bridge_finalize", phase_started)
        self.claims = ranked_claims
        phase_started = time.perf_counter()
        self.bridge_message = read_fp16_values(
            self.runtime, self.message_d, BRIDGE_COEFFICIENTS, "copy_bridge_message"
        )
        self._profile_add("begin_bridge_readcheck", phase_started)
        self.next_group_round = 0
        self.next_left_wire_round = 0
        self.next_right_wire_round = 0
        self._profile_add("begin_layer", started)
        return self.bridge_message

    def output_claim(self, query, point, selector):
        claim = {
            "coefficient": (1,) + (0,) * 15,
            "value": (0,) * 16,
            "query": query,
            "point": point,
            "selector": selector,
        }
        message = self.begin_layer(23, 6, [claim])
        total = (0,) * 16
        for node in range(16):
            node_value = (node,) + (0,) * 15
            total = add(total, evaluate_polynomial(message, node_value))
        claim["value"] = total
        self.cached_output = (claim, message)
        return total

    def accept_bridge(self, challenge, selector_scales, node_values):
        started = time.perf_counter()
        if self.claims is None or self.plan is None:
            raise ValueError("bridge_state")
        if (
            len(selector_scales) != self.original_claim_count
            or len(node_values) != 16
        ):
            raise ValueError("bridge_public_shape")
        ranked_scales = [None] * len(self.claims)
        for claim, rank in enumerate(self.claim_classes):
            scale = selector_scales[claim]
            if ranked_scales[rank] is None:
                ranked_scales[rank] = scale
            elif ranked_scales[rank] != scale:
                raise ValueError("bridge_rank_scale")
        padded_scales = array.array("I", [0]) * (MAX_CLAIMS * 16)
        for claim_index, selector in enumerate(ranked_scales):
            padded_scales[
                16 * claim_index : 16 * (claim_index + 1)
            ] = array.array("I", selector)
        copy(
            self.runtime,
            self.coefficients_d,
            padded_scales,
            "copy_bridge_selector_scales",
        )
        weight_count = len(self.claims) * self.plan.raw_width
        launch(
            self.runtime,
            self.scale_wire_weights,
            (weight_count + 255) // 256,
            256,
            arguments(
                ctypes.c_uint64(self.wire_weights_d),
                ctypes.c_uint64(self.coefficients_d),
                ctypes.c_uint32(MAX_RAW),
                ctypes.c_uint32(self.plan.raw_width),
                ctypes.c_uint32(len(self.claims)),
            ),
            "scale_bridge_wire_weights",
        )
        lookup_values = array.array("I")
        for value in node_values:
            lookup_values.extend(value)
        copy(
            self.runtime,
            self.selectors_d,
            lookup_values,
            "copy_b16_node_values",
        )
        launch(
            self.runtime,
            self.build_b16_lookup,
            256,
            256,
            arguments(
                ctypes.c_uint64(self.selectors_d),
                ctypes.c_uint64(self.lookup_d),
            ),
            "build_b16_lookup",
        )
        self.group_weight_current = self.group_weight_a
        self.group_weight_output = self.group_weight_b
        self.current_groups = GROUP_COUNT
        self.nonuniform_groups = self.initial_nonuniform_groups
        self.current_left = self.left_packed
        self.current_right = self.right_packed
        self.next_group_round = 0
        self._profile_add("accept_bridge", started)

    def _split_weights(self):
        suffix_groups = self.current_groups // 2
        count = len(self.claims) * suffix_groups
        launch(
            self.runtime,
            self.split_group_weights,
            (count + 255) // 256,
            256,
            arguments(
                ctypes.c_uint64(self.group_weight_current),
                ctypes.c_uint64(self.group_zero_d),
                ctypes.c_uint64(self.group_delta_d),
                ctypes.c_uint32(self.current_groups),
                ctypes.c_uint32(MAX_SUFFIX),
                ctypes.c_uint32(len(self.claims)),
            ),
            "split_group_weights",
        )
        first_uniform_pair = (self.nonuniform_groups + 1) // 2
        if first_uniform_pair < suffix_groups:
            launch(
                self.runtime,
                self.aggregate_group_weight_tail,
                1,
                128,
                arguments(
                    ctypes.c_uint64(self.group_zero_d),
                    ctypes.c_uint64(self.group_delta_d),
                    ctypes.c_uint32(first_uniform_pair),
                    ctypes.c_uint32(suffix_groups),
                    ctypes.c_uint32(MAX_SUFFIX),
                    ctypes.c_uint32(len(self.claims)),
                ),
                "aggregate_group_weight_tail",
            )
            return first_uniform_pair + 1
        return suffix_groups

    def raw_group_round(self, round_index):
        started = time.perf_counter()
        if round_index != self.next_group_round:
            raise ValueError("group_round_order")
        message_suffix_groups = self._split_weights()
        if round_index == 0:
            result = launch_b16_packed_message(
                self.runtime,
                self.packed_b16_group_message,
                self.packed_b16_group_message_factored_one_claim,
                self.reduce_cubic_partials,
                self.left_packed,
                self.right_packed,
                self.lookup_d,
                self.base_left_d,
                self.base_right_d,
                self.formulas_d,
                self.wire_weights_d,
                self.group_zero_d,
                self.group_delta_d,
                self.partial_d,
                self.reduction_scratch_d,
                self.plan.raw_width,
                message_suffix_groups,
                self.words_per_wire,
                len(self.claims),
            )
        else:
            result = launch_fp16_message(
                self.runtime,
                self.fp16_group_message,
                self.fp16_group_message_factored_one_claim,
                self.reduce_cubic_partials,
                self.current_left,
                self.current_right,
                self.base_left_d,
                self.base_right_d,
                self.formulas_d,
                self.wire_weights_d,
                self.group_zero_d,
                self.group_delta_d,
                self.partial_d,
                self.reduction_scratch_d,
                self.plan.raw_width,
                self.plan.left_live_width,
                self.plan.right_live_width,
                message_suffix_groups,
                self.nonuniform_groups,
                len(self.claims),
            )
        message = read_fp16_values(
            self.runtime, result, 4, "copy_group_message"
        )
        self._profile_add("raw_group_round", started)
        self._profile_add(f"raw_group_round_{round_index}", started)
        return message

    def accept_group(self, round_index, challenge):
        started = time.perf_counter()
        if round_index != self.next_group_round:
            raise ValueError("group_challenge_order")
        challenge_values = array.array("I", challenge)
        copy(self.runtime, self.challenge_d, challenge_values, "copy_group_challenge")
        logical_output_groups = self.current_groups // 2
        next_nonuniform_groups = (self.nonuniform_groups + 1) // 2
        source_output_groups = next_nonuniform_groups + (
            1 if next_nonuniform_groups < logical_output_groups else 0
        )
        if round_index == 0:
            launch_b16_first(
                self.runtime,
                self.packed_b16_first_group_fold,
                self.left_packed,
                self.lookup_d,
                self.challenge_d,
                self.left_main_d,
                self.plan.left_live_width,
                source_output_groups,
                self.words_per_wire,
            )
            if self.left_packed == self.right_packed:
                self.current_right = self.left_main_d
            else:
                launch_b16_first(
                    self.runtime,
                    self.packed_b16_first_group_fold,
                    self.right_packed,
                    self.lookup_d,
                    self.challenge_d,
                    self.right_main_d,
                    self.plan.right_live_width,
                    source_output_groups,
                    self.words_per_wire,
                )
                self.current_right = self.right_main_d
            self.current_left = self.left_main_d
            self.left_output = self.left_scratch_d
            self.right_output = (
                self.left_scratch_d
                if self.left_packed == self.right_packed
                else self.right_scratch_d
            )
        else:
            left_count = self.plan.left_live_width * source_output_groups
            launch(
                self.runtime,
                self.compact_fp16_group_fold,
                (left_count + 255) // 256,
                256,
                arguments(
                    ctypes.c_uint64(self.current_left),
                    ctypes.c_uint64(self.challenge_d),
                    ctypes.c_uint64(self.left_output),
                    ctypes.c_uint32(self.plan.left_live_width),
                    ctypes.c_uint32(source_output_groups),
                    ctypes.c_uint32(self.nonuniform_groups),
                ),
                "compact_left_group_fold",
            )
            if self.current_left == self.current_right:
                next_right = self.left_output
            else:
                right_count = self.plan.right_live_width * source_output_groups
                launch(
                    self.runtime,
                    self.compact_fp16_group_fold,
                    (right_count + 255) // 256,
                    256,
                    arguments(
                        ctypes.c_uint64(self.current_right),
                        ctypes.c_uint64(self.challenge_d),
                        ctypes.c_uint64(self.right_output),
                        ctypes.c_uint32(self.plan.right_live_width),
                        ctypes.c_uint32(source_output_groups),
                        ctypes.c_uint32(self.nonuniform_groups),
                    ),
                    "compact_right_group_fold",
                )
                next_right = self.right_output
            self.current_left, self.left_output = self.left_output, self.current_left
            if self.current_left == next_right:
                self.current_right = self.current_left
                self.right_output = self.left_output
            else:
                self.current_right, self.right_output = next_right, self.current_right
        weight_count = len(self.claims) * logical_output_groups
        launch(
            self.runtime,
            self.fold_group_weights,
            (weight_count + 255) // 256,
            256,
            arguments(
                ctypes.c_uint64(self.group_weight_current),
                ctypes.c_uint64(self.challenge_d),
                ctypes.c_uint64(self.group_weight_output),
                ctypes.c_uint32(self.current_groups),
                ctypes.c_uint32(len(self.claims)),
            ),
            "fold_group_weights",
        )
        self.group_weight_current, self.group_weight_output = (
            self.group_weight_output,
            self.group_weight_current,
        )
        self.current_groups = logical_output_groups
        self.nonuniform_groups = next_nonuniform_groups
        self.next_group_round += 1
        next_message = None
        if self.next_group_round < 13:
            next_message = self.raw_group_round(self.next_group_round)
        self._profile_add("accept_group", started)
        self._profile_add(f"accept_group_{round_index}", started)
        return next_message

    def folded_sources(self):
        started = time.perf_counter()
        if (
            self.next_group_round != 13
            or self.current_groups != 1
            or self.wire_ready
            or self.pending_wire is not None
        ):
            raise ValueError("folded_source_state")
        raw_width = self.plan.raw_width
        launch(
            self.runtime,
            self.combine_wire_weights,
            (raw_width + 255) // 256,
            256,
            arguments(
                ctypes.c_uint64(self.wire_weights_d),
                ctypes.c_uint64(self.group_weight_current),
                ctypes.c_uint64(self.effective_wire_weights_d),
                ctypes.c_uint32(raw_width),
                ctypes.c_uint32(MAX_RAW),
                ctypes.c_uint32(len(self.claims)),
            ),
            "combine_wire_weights",
        )
        launch(
            self.runtime,
            self.initialize_wire_factors,
            (raw_width + 255) // 256,
            256,
            arguments(
                ctypes.c_uint64(self.left_wire_factors_d),
                ctypes.c_uint64(self.right_wire_factors_d),
                ctypes.c_uint32(raw_width),
            ),
            "initialize_wire_factors",
        )
        wire_vector_size = PADDED_WIRES * FP16_BYTES
        ck(
            self.runtime.cuda.cuMemsetD8_v2(
                self.wire_left_a_d, 0, wire_vector_size
            ),
            "zero_wire_left_padding",
        )
        ck(
            self.runtime.cuda.cuMemcpyDtoD_v2(
                self.wire_left_a_d,
                self.current_left,
                self.plan.left_live_width * FP16_BYTES,
            ),
            "preserve_wire_left",
        )
        ck(
            self.runtime.cuda.cuMemsetD8_v2(
                self.wire_right_a_d, 0, wire_vector_size
            ),
            "zero_wire_right_padding",
        )
        ck(
            self.runtime.cuda.cuMemcpyDtoD_v2(
                self.wire_right_a_d,
                self.current_right,
                self.plan.right_live_width * FP16_BYTES,
            ),
            "preserve_wire_right",
        )
        self.wire_left_current = self.wire_left_a_d
        self.wire_left_output = self.wire_left_b_d
        self.wire_right_current = self.wire_right_a_d
        self.wire_right_output = self.wire_right_b_d
        self.wire_left_width = self.plan.left_width
        self.wire_right_width = self.plan.right_width
        self.next_left_wire_round = 0
        self.next_right_wire_round = 0
        self.wire_ready = True
        left = read_fp16_words(
            self.runtime,
            self.current_left,
            self.plan.left_live_width,
            "copy_folded_left",
            self.plan.left_width,
        )
        same_source = self.plan.left_source == self.plan.right_source
        if (self.current_left == self.current_right) != same_source:
            raise ValueError("folded_source_alias")
        if same_source:
            if self.plan.left_width != self.plan.right_width:
                raise ValueError("folded_source_alias_width")
            right = None
        else:
            right = read_fp16_words(
                self.runtime,
                self.current_right,
                self.plan.right_live_width,
                "copy_folded_right",
                self.plan.right_width,
            )
        first_wire_message = self.raw_wire_round(0, 0, (0,) * 16)
        self._profile_add("folded_sources", started)
        return left, right, first_wire_message

    def raw_wire_round(self, side, round_index, masked_terminal_left):
        started = time.perf_counter()
        if not self.wire_ready or self.pending_wire is not None:
            raise ValueError("wire_round_state")
        if side == 0:
            if (
                round_index != self.next_left_wire_round
                or self.next_right_wire_round != 0
                or masked_terminal_left != (0,) * 16
            ):
                raise ValueError("left_wire_round_order")
            current = self.wire_left_current
        elif side == 1:
            if (
                round_index != self.next_right_wire_round
                or self.next_left_wire_round
                != self.plan.left_width.bit_length() - 1
            ):
                raise ValueError("right_wire_round_order")
            if round_index == 0:
                self.masked_terminal_left = masked_terminal_left
                copy(
                    self.runtime,
                    self.masked_terminal_left_d,
                    array.array("I", masked_terminal_left),
                    "copy_masked_terminal_left",
                )
            elif masked_terminal_left != self.masked_terminal_left:
                raise ValueError("masked_terminal_left_changed")
            current = self.wire_right_current
        else:
            raise ValueError("wire_side")
        launch(
            self.runtime,
            self.wire_round_message,
            1,
            THREADS,
            arguments(
                ctypes.c_uint64(current),
                ctypes.c_uint64(self.wire_right_a_d),
                ctypes.c_uint64(self.masked_terminal_left_d),
                ctypes.c_uint64(self.base_left_d),
                ctypes.c_uint64(self.base_right_d),
                ctypes.c_uint64(self.formulas_d),
                ctypes.c_uint64(self.effective_wire_weights_d),
                ctypes.c_uint64(self.left_wire_factors_d),
                ctypes.c_uint64(self.right_wire_factors_d),
                ctypes.c_uint64(self.partial_d),
                ctypes.c_uint32(self.plan.raw_width),
                ctypes.c_uint32(round_index),
                ctypes.c_uint32(1 if side == 0 else 0),
            ),
            "wire_round_message",
        )
        result = read_fp16_values(
            self.runtime,
            self.partial_d,
            3,
            "copy_wire_message_"
            f"{self.current_context}_{side}_{round_index}_"
            f"{self.plan.raw_width}_{self.plan.left_width}_"
            f"{self.plan.right_width}",
        )
        self.pending_wire = (side, round_index)
        self._profile_add("raw_wire_round", started)
        self._profile_add(f"raw_wire_round_{side}_{round_index}", started)
        return result

    def accept_wire(self, side, round_index, challenge):
        started = time.perf_counter()
        if self.pending_wire != (side, round_index):
            raise ValueError("wire_challenge_order")
        copy(
            self.runtime,
            self.challenge_d,
            array.array("I", challenge),
            "copy_wire_challenge",
        )
        if side == 0:
            factors = self.left_wire_factors_d
            indices = self.base_left_d
            current = self.wire_left_current
            output = self.wire_left_output
            current_width = self.wire_left_width
        elif side == 1:
            factors = self.right_wire_factors_d
            indices = self.base_right_d
            current = self.wire_right_current
            output = self.wire_right_output
            current_width = self.wire_right_width
        else:
            raise ValueError("wire_side")
        if current_width < 2:
            raise ValueError("wire_width")
        terminal_right = side == 1 and current_width == 2
        if not terminal_right:
            work_items = max(self.plan.raw_width, current_width // 2)
            launch(
                self.runtime,
                self.fold_and_update_wire,
                (work_items + 255) // 256,
                256,
                arguments(
                    ctypes.c_uint64(factors),
                    ctypes.c_uint64(indices),
                    ctypes.c_uint64(current),
                    ctypes.c_uint64(output),
                    ctypes.c_uint64(self.challenge_d),
                    ctypes.c_uint32(self.plan.raw_width),
                    ctypes.c_uint32(current_width),
                    ctypes.c_uint32(round_index),
                ),
                "fold_and_update_wire",
            )
        if side == 0:
            self.wire_left_current, self.wire_left_output = output, current
            self.wire_left_width //= 2
            self.next_left_wire_round += 1
        else:
            self.wire_right_current, self.wire_right_output = output, current
            self.wire_right_width //= 2
            self.next_right_wire_round += 1
            if self.wire_right_width == 1:
                self.wire_ready = False
                self.claims = None
                self.completed_layers += 1
        self.pending_wire = None
        next_message = None
        next_round = round_index + 1
        variable_count = self.plan.left_width.bit_length() - 1 if side == 0 else self.plan.right_width.bit_length() - 1
        if next_round < variable_count:
            next_message = self.raw_wire_round(
                side,
                next_round,
                (0,) * 16 if side == 0 else self.masked_terminal_left,
            )
        self._profile_add("accept_wire", started)
        self._profile_add(f"accept_wire_{side}_{round_index}", started)
        return next_message

    def close(self):
        if self.profile_enabled:
            print(
                "gkr_worker_profile="
                + ",".join(
                    f"{name}:{value:.6f}"
                    for name, value in sorted(self.profile.items())
                ),
                file=sys.stderr,
                flush=True,
            )
        self.runtime.close()


def read_claim(stream):
    coefficient = read_field(stream)
    value = read_field(stream)
    query = read_field(stream)
    point_count = read_exact(stream, 1)[0]
    if point_count == 0 or point_count > 24:
        raise ValueError("claim_point_count")
    return {
        "coefficient": coefficient,
        "value": value,
        "query": query,
        "point": [read_field(stream) for _ in range(point_count)],
        "selector": [read_field(stream) for _ in range(16)],
    }


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: cuda_hash_bus_b16_gkr_worker.py BOUNDARY SHARD")
    boundary = Path(sys.argv[1]).resolve()
    shard = int(sys.argv[2])
    source = sys.stdin.buffer
    sink = sys.stdout.buffer
    worker = Worker()
    sink.write(READY)
    sink.flush()
    if read_exact(source, 8) != PLAN:
        raise ValueError("plan_magic")
    plans = read_plan(source)
    worker.activate(boundary, shard, plans)
    sink.write(PLAN_ACCEPTED)
    sink.flush()
    try:
        while True:
            command = read_exact(source, 8)
            if command == OUTPUT_REQUEST:
                query = read_field(source)
                point = [read_field(source) for _ in range(24)]
                selector = [read_field(source) for _ in range(16)]
                value = worker.output_claim(query, point, selector)
                sink.write(OUTPUT_RESPONSE)
                write_field(sink, value)
            elif command == LAYER_REQUEST:
                round_index, layer_index, claim_count = read_exact(source, 3)
                claims = [read_claim(source) for _ in range(claim_count)]
                if (
                    worker.cached_output is not None
                    and round_index == 23
                    and layer_index == 6
                    and claim_count == 1
                    and claims[0] == worker.cached_output[0]
                ):
                    message = worker.cached_output[1]
                    worker.claims = claims
                    worker.plan = worker.plans[round_index][layer_index]
                    worker.cached_output = None
                else:
                    message = worker.begin_layer(round_index, layer_index, claims)
                sink.write(LAYER_RESPONSE)
                for coefficient in message:
                    write_field(sink, coefficient)
            elif command == BRIDGE_CHALLENGE:
                challenge = read_field(source)
                claim_count = read_exact(source, 1)[0]
                selector_scales = [
                    read_field(source) for _ in range(claim_count)
                ]
                node_values = [read_field(source) for _ in range(16)]
                worker.accept_bridge(challenge, selector_scales, node_values)
                sink.write(BRIDGE_ACCEPTED)
                message = worker.raw_group_round(0)
                for coefficient in message:
                    write_field(sink, coefficient)
            elif command == GROUP_CHALLENGE:
                round_index = read_exact(source, 1)[0]
                message = worker.accept_group(round_index, read_field(source))
                sink.write(GROUP_ACCEPTED)
                if message is not None:
                    for coefficient in message:
                        write_field(sink, coefficient)
            elif command == FOLDED_REQUEST:
                left, right, message = worker.folded_sources()
                sink.write(FOLDED_RESPONSE)
                write_field_words(sink, left)
                if right is not None:
                    write_field_words(sink, right)
                for coefficient in message:
                    write_field(sink, coefficient)
            elif command == WIRE_REQUEST:
                side, round_index = read_exact(source, 2)
                masked_terminal_left = read_field(source)
                message = worker.raw_wire_round(
                    side,
                    round_index,
                    masked_terminal_left,
                )
                sink.write(WIRE_RESPONSE)
                for coefficient in message:
                    write_field(sink, coefficient)
            elif command == WIRE_CHALLENGE:
                side, round_index = read_exact(source, 2)
                challenge = read_field(source)
                message = worker.accept_wire(side, round_index, challenge)
                sink.write(WIRE_ACCEPTED)
                if message is not None:
                    for coefficient in message:
                        write_field(sink, coefficient)
            elif command == FINISH:
                sink.write(FINISHED)
                sink.flush()
                break
            else:
                raise ValueError(f"command:{command!r}")
            sink.flush()
    finally:
        worker.close()


if __name__ == "__main__":
    main()
