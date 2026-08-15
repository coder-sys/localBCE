"""Untrusted bounded-memory accelerator for the varying semantic/H4 GKR.

Rust authenticates the same boundary/snapshot join, owns every transcript
challenge, checks every recurrence, and verifies source openings.  This file
only loads the canonical compact source and evaluates algebra.
"""

import array
import ctypes
import hashlib
import os
import struct
import sys
import time
from dataclasses import dataclass
from pathlib import Path


READY = b"BLSHBW01"
OUTPUT = b"BLSHBO01"
OUTPUT_OK = b"BLSHBOA1"
BEGIN = b"BLSHBL01"
BEGIN_OK = b"BLSHBLA1"
GROUP = b"BLSHBG01"
GROUP_OK = b"BLSHBGA1"
CHALLENGE = b"BLSHBC01"
CHALLENGE_OK = b"BLSHBCA1"
FOLDED = b"BLSHBF01"
FOLDED_OK = b"BLSHBFA1"
FINISH = b"BLSHBX01"
FINISHED = b"BLSHBXA1"
BOUNDARY_HEADER_BYTES = 215
BOUNDARY_MAGIC = b"BLHBB102"
SNAPSHOT_MAGIC = b"BLHBSN02"
LIVE_WIRES = 1600
PACKED_GROUPS_PER_SHARD = 8192
PERMUTATIONS_PER_SHARD = PACKED_GROUPS_PER_SHARD * 16
RATE_BYTES = 72
M31 = 2147483647
RETAINED_ACCUMULATOR_BYTES = 3 * 1024 * 1024 * 1024

RATE_LIVE = 0
RATE_PREVIOUS_LIVE = 1
RATE_BLOCK_ACTIVE = 2
RATE_NEXT_BLOCK_ACTIVE = 3
RATE_VALUE = 4
RATE_FINAL_BYTE_SELECTOR = 5
RATE_INPUT_BITS_START = 6
RATE_PREDECESSOR_BITS_START = 14
RATE_BIT_WEIGHTS_START = 22
RATE_SIX = 30
RATE_128 = 31
RATE_ONE = 32
BLOCK_ACTIVE = 2048
DIGEST_NEXT_ACTIVE_START = 1024
DIGEST_OUTPUT_BYTES_START = 2048
DIGEST_EXPECTED_BYTE = 3072

CIRCUIT_RATE = 1
CIRCUIT_INACTIVE = 2
CIRCUIT_CAPACITY = 3
CIRCUIT_DIGEST = 4

SOURCE_KERNEL = r"""
extern "C" __global__ void semantic_source_requests(
    unsigned int *requests,
    unsigned int circuit,
    unsigned int width,
    unsigned int group_start,
    unsigned int groups
) {
    unsigned long long index = (unsigned long long)blockIdx.x * blockDim.x + threadIdx.x;
    unsigned long long count = (unsigned long long)width * groups;
    if (index >= count) return;
    unsigned int group = (unsigned int)(index / width);
    unsigned int wire = (unsigned int)(index - (unsigned long long)group * width);
    requests[3ULL * index] = circuit;
    requests[3ULL * index + 1ULL] = wire;
    requests[3ULL * index + 2ULL] = group_start + group;
}

extern "C" __global__ void semantic_source_values(
    const unsigned short *input_patterns,
    const unsigned short *output_patterns,
    const unsigned int *permutation_calls,
    const unsigned int *permutation_blocks,
    const unsigned int *call_first,
    const unsigned int *call_blocks,
    const unsigned int *message_offsets,
    const unsigned int *message_lengths,
    const unsigned char *messages,
    const unsigned char *digests,
    const unsigned int *requests,
    unsigned int *results,
    unsigned int request_count,
    unsigned int total_permutations,
    unsigned int total_calls
) {
    unsigned int index = blockIdx.x * blockDim.x + threadIdx.x;
    if (index >= request_count) return;
    unsigned int circuit = requests[3U * index];
    unsigned int wire = requests[3U * index + 1U];
    unsigned int group = requests[3U * index + 2U];
    auto bit = [](const unsigned short *plane, unsigned int permutation, unsigned int source_wire) {
        unsigned int shard = permutation >> 17U;
        unsigned int local = permutation & 131071U;
        unsigned long long pattern =
            ((unsigned long long)shard * 1600ULL + source_wire) * 8192ULL + (local >> 4U);
        return (unsigned int)((plane[pattern] >> (local & 15U)) & 1U);
    };
    unsigned int value = 0U;
    if (circuit == 1U) {
        unsigned int permutation = group / 72U, byte = group % 72U;
        if (permutation < total_permutations) {
            unsigned int call = permutation_calls[permutation];
            unsigned int block = permutation_blocks[permutation];
            unsigned int position = block * 72U + byte;
            unsigned int length = message_lengths[call];
            unsigned int live = position < length;
            unsigned int previous = position > 0U && position - 1U < length;
            if (wire == 0U) value = live;
            else if (wire == 1U) value = previous;
            else if (wire == 2U) value = block == 0U || (block * 72U - 1U < length);
            else if (wire == 3U) value = block * 72U + 71U < length;
            else if (wire == 4U) value = live ? messages[message_offsets[call] + position] : 0U;
            else if (wire == 5U) value = byte == 71U;
            else if (wire >= 6U && wire < 14U) value = bit(input_patterns, permutation, 8U * byte + wire - 6U);
            else if (wire >= 14U && wire < 22U && block > 0U) value = bit(output_patterns, permutation - 1U, 8U * byte + wire - 14U);
            else if (wire >= 22U && wire < 30U) value = 1U << (wire - 22U);
            else if (wire == 30U) value = 6U;
            else if (wire == 31U) value = 128U;
            else if (wire == 32U) value = 1U;
        } else if (wire >= 22U && wire < 30U) value = 1U << (wire - 22U);
        else if (wire == 30U) value = 6U;
        else if (wire == 31U) value = 128U;
        else if (wire == 32U) value = 1U;
        else if (wire == 5U && group % 72U == 71U) value = 1U;
    } else if (circuit == 2U || circuit == 3U) {
        if (group < total_permutations) {
            unsigned int block = permutation_blocks[group];
            unsigned int call = permutation_calls[group];
            unsigned int length = message_lengths[call];
            if (wire == 2048U) value = block == 0U || block * 72U - 1U < length;
            else if (circuit == 2U && wire < 1600U) value = bit(input_patterns, group, wire);
            else if (circuit == 3U && wire < 1024U) value = bit(input_patterns, group, 576U + wire);
            else if (circuit == 3U && wire >= 1024U && wire < 2048U && block > 0U) value = bit(output_patterns, group - 1U, 576U + wire - 1024U);
        }
    } else if (circuit == 4U) {
        unsigned int call = group / 64U, byte = group % 64U;
        if (call < total_calls) {
            unsigned int blocks = call_blocks[call];
            if (wire < 1024U) value = wire < blocks && (wire == 0U || wire * 72U - 1U < message_lengths[call]);
            else if (wire >= 1024U && wire < 2048U) {
                unsigned int block = wire - 1024U + 1U;
                value = block < blocks && (block == 0U || block * 72U - 1U < message_lengths[call]);
            } else if (wire >= 2048U && wire < 3072U) {
                unsigned int block = wire - 2048U;
                if (block < blocks) {
                    unsigned int permutation = call_first[call] + block;
                    for (unsigned int b = 0; b < 8U; ++b) value |= bit(output_patterns, permutation, 8U * byte + b) << b;
                }
            } else if (wire == 3072U) value = digests[64U * call + byte];
        }
    }
    results[index] = value;
}

"""

DAG_KERNEL = r"""
__device__ __forceinline__ unsigned int add31(unsigned int a, unsigned int b) {
    unsigned long long value = (unsigned long long)a + b;
    value = (value & 2147483647ULL) + (value >> 31U);
    return value >= 2147483647ULL ? (unsigned int)(value - 2147483647ULL) : (unsigned int)value;
}
__device__ __forceinline__ unsigned int sub31(unsigned int a, unsigned int b) {
    return a >= b ? a - b : a + 2147483647U - b;
}
__device__ __forceinline__ unsigned int mul31(unsigned int a, unsigned int b) {
    unsigned long long value = (unsigned long long)a * b;
    value = (value & 2147483647ULL) + (value >> 31U);
    value = (value & 2147483647ULL) + (value >> 31U);
    return value >= 2147483647ULL ? (unsigned int)(value - 2147483647ULL) : (unsigned int)value;
}
extern "C" __global__ void semantic_dag_layer_base(
    const unsigned int *left,
    const unsigned int *right,
    const unsigned short *left_indices,
    const unsigned short *right_indices,
    const unsigned char *kinds,
    unsigned int *output,
    unsigned int groups,
    unsigned int left_width,
    unsigned int right_width,
    unsigned int raw_width,
    unsigned int padded_width
) {
    unsigned long long index = (unsigned long long)blockIdx.x * blockDim.x + threadIdx.x;
    unsigned long long count = (unsigned long long)groups * padded_width;
    if (index >= count) return;
    unsigned int group = (unsigned int)(index / padded_width);
    unsigned int wire = (unsigned int)(index - (unsigned long long)group * padded_width);
    if (wire >= raw_width) { output[index] = 0U; return; }
    unsigned int a = left[(unsigned long long)group * left_width + left_indices[wire]];
    unsigned int b = right[(unsigned long long)group * right_width + right_indices[wire]];
    unsigned int kind = kinds[wire], value;
    if (kind == 0U) value = sub31(add31(a, b), add31(mul31(a, b), mul31(a, b)));
    else if (kind == 1U) value = sub31(b, mul31(a, b));
    else if (kind == 2U || kind == 7U) value = a;
    else if (kind == 3U) value = sub31(1U, a);
    else if (kind == 4U) value = sub31(a, b);
    else if (kind == 5U) value = mul31(a, b);
    else if (kind == 6U) value = add31(a, b);
    else value = 0U;
    output[index] = value;
}
"""

FP16_LINEAR_KERNEL = r"""
__device__ __forceinline__ F16 a16(F16 x,F16 y){return {a8(x.a,y.a),a8(x.b,y.b)};}
__device__ __forceinline__ F16 s16(F16 x,F16 y){return {s8(x.a,y.a),s8(x.b,y.b)};}
"""

# Production kernels deliberately keep the original semantic rows in M31 and
# expand only the bounded reductions into Fp16.  No group-expanded Fp16 table
# exists at any point.
STREAM_KERNEL = r"""
__device__ __forceinline__ F16 embed31(unsigned int value) {
    F16 result = z16(); result.a.a.a.a = value; return result;
}

extern "C" __global__ void semantic_equality_weights(
    const unsigned int *point,
    unsigned int point_len,
    unsigned int first_index,
    unsigned int count,
    unsigned int *weights
) {
    unsigned int local = blockIdx.x * blockDim.x + threadIdx.x;
    if (local >= count) return;
    unsigned int index = first_index + local;
    F16 value = embed31(1U);
    for (unsigned int bit = 0; bit < point_len; ++bit) {
        F16 coordinate = l16(point + 16ULL * bit);
        value = m16(value, ((index >> bit) & 1U) ? coordinate : s16(embed31(1U), coordinate));
    }
    st16(weights + 16ULL * local, value);
}

extern "C" __global__ void semantic_wire_weights(
    const unsigned int *claims,
    unsigned int claim_count,
    unsigned int point_len,
    unsigned int output_variables,
    unsigned int raw_width,
    unsigned int *weights
) {
    unsigned long long index = (unsigned long long)blockIdx.x * blockDim.x + threadIdx.x;
    unsigned long long count = (unsigned long long)claim_count * raw_width;
    if (index >= count) return;
    unsigned int claim = (unsigned int)(index / raw_width);
    unsigned int output = (unsigned int)(index - (unsigned long long)claim * raw_width);
    const unsigned int *record = claims + 16ULL * claim * (point_len + 2U);
    F16 value = embed31(1U);
    for (unsigned int bit = 0; bit < output_variables; ++bit) {
        F16 coordinate = l16(record + 16ULL * (2U + bit));
        value = m16(value, ((output >> bit) & 1U) ? coordinate : s16(embed31(1U), coordinate));
    }
    st16(weights + 16ULL * index, value);
}

extern "C" __global__ void semantic_group_weights(
    const unsigned int *claims,
    const unsigned int *prefixes,
    unsigned int claim_count,
    unsigned int point_len,
    unsigned int output_variables,
    unsigned int group_rounds,
    unsigned int round,
    unsigned int suffix_start,
    unsigned int suffix_count,
    unsigned int *zero_weights,
    unsigned int *delta_weights
) {
    unsigned long long index = (unsigned long long)blockIdx.x * blockDim.x + threadIdx.x;
    unsigned long long count = (unsigned long long)claim_count * suffix_count;
    if (index >= count) return;
    unsigned int claim = (unsigned int)(index / suffix_count);
    unsigned int suffix = (unsigned int)(index - (unsigned long long)claim * suffix_count);
    unsigned int global_suffix = suffix_start + suffix;
    const unsigned int *record = claims + 16ULL * claim * (point_len + 2U);
    F16 remaining = embed31(1U);
    for (unsigned int bit = round + 1U; bit < group_rounds; ++bit) {
        F16 coordinate = l16(record + 16ULL * (2U + output_variables + bit));
        unsigned int suffix_bit = bit - round - 1U;
        remaining = m16(remaining, ((global_suffix >> suffix_bit) & 1U)
            ? coordinate : s16(embed31(1U), coordinate));
    }
    F16 base = m16(l16(prefixes + 16ULL * claim), remaining);
    F16 coordinate = l16(record + 16ULL * (2U + output_variables + round));
    st16(zero_weights + 16ULL * index, m16(base, s16(embed31(1U), coordinate)));
    st16(delta_weights + 16ULL * index,
         m16(base, s16(a16(coordinate, coordinate), embed31(1U))));
}

extern "C" __global__ void semantic_accumulate_gate_inputs(
    const unsigned int *left,
    const unsigned int *right,
    const unsigned short *base_left,
    const unsigned short *base_right,
    const unsigned int *prefix_weights,
    unsigned int *accumulator,
    unsigned int raw_width,
    unsigned int left_width,
    unsigned int right_width,
    unsigned int suffix_count,
    unsigned int prefix_count,
    unsigned int material_prefix_count,
    unsigned int low_offset,
    unsigned int material_bit,
    unsigned int accumulator_bit
) {
    unsigned long long index = (unsigned long long)blockIdx.x * blockDim.x + threadIdx.x;
    unsigned long long count = (unsigned long long)suffix_count * raw_width;
    if (index >= count) return;
    unsigned int suffix = (unsigned int)(index / raw_width);
    unsigned int output = (unsigned int)(index - (unsigned long long)suffix * raw_width);
    F16 left_sum = z16(), right_sum = z16();
    unsigned long long group_base = ((unsigned long long)suffix * 2ULL + material_bit) * material_prefix_count;
    for (unsigned int low = 0; low < prefix_count; ++low) {
        F16 weight = l16(prefix_weights + 16ULL * low);
        unsigned long long group = group_base + low;
        left_sum = a16(left_sum, m16(weight, embed31(left[group * left_width + base_left[output]])));
        right_sum = a16(right_sum, m16(weight, embed31(right[group * right_width + base_right[output]])));
    }
    unsigned long long slot = 4ULL * index + 2ULL * accumulator_bit;
    st16(accumulator + 16ULL * slot, a16(l16(accumulator + 16ULL * slot), left_sum));
    st16(accumulator + 16ULL * (slot + 1ULL), a16(l16(accumulator + 16ULL * (slot + 1ULL)), right_sum));
}

extern "C" __global__ void semantic_accumulated_message(
    const unsigned int *accumulator,
    const unsigned char *formulas,
    const unsigned int *wire_weights,
    const unsigned int *group_zero_weights,
    const unsigned int *group_delta_weights,
    unsigned int *partial,
    unsigned int raw_width,
    unsigned int suffix_count,
    unsigned int claim_count
) {
    unsigned long long terms = (unsigned long long)raw_width * suffix_count;
    unsigned long long first = ((unsigned long long)blockIdx.x * blockDim.x + threadIdx.x) * 8ULL;
    Cubic total = {z16(), z16(), z16(), z16()};
    for (unsigned int local = 0; local < 8U; ++local) {
        unsigned long long index = first + local;
        if (index >= terms) break;
        unsigned int suffix = (unsigned int)(index / raw_width);
        unsigned int output = (unsigned int)(index - (unsigned long long)suffix * raw_width);
        const unsigned int *values = accumulator + 64ULL * index;
        Cubic term = term_cubic(
            l16(values), l16(values + 32), l16(values + 16), l16(values + 48),
            formulas[output], wire_weights, group_zero_weights, group_delta_weights,
            output, suffix, raw_width, suffix_count, claim_count
        );
        total.c0 = a16(total.c0, term.c0); total.c1 = a16(total.c1, term.c1);
        total.c2 = a16(total.c2, term.c2); total.c3 = a16(total.c3, term.c3);
    }
    reduce_cubic(total, partial, blockIdx.x);
}

extern "C" __global__ void semantic_fold_source_chunk(
    const unsigned int *source,
    const unsigned int *weights,
    unsigned int *output,
    unsigned int width,
    unsigned int groups
) {
    unsigned int wire = blockIdx.x * blockDim.x + threadIdx.x;
    if (wire >= width) return;
    F16 sum = l16(output + 16ULL * wire);
    for (unsigned int group = 0; group < groups; ++group)
        sum = a16(sum, m16(l16(weights + 16ULL * group), embed31(source[(unsigned long long)group * width + wire])));
    st16(output + 16ULL * wire, sum);
}

extern "C" __global__ void semantic_fold_accumulator(
    const unsigned int *input,
    const unsigned int *challenge,
    unsigned int *output,
    unsigned int raw_width,
    unsigned long long input_records,
    unsigned long long output_records
) {
    unsigned long long index = (unsigned long long)blockIdx.x * blockDim.x + threadIdx.x;
    unsigned long long count = output_records * 4ULL;
    if (index >= count) return;
    unsigned long long output_record = index >> 2U;
    unsigned int slot = (unsigned int)(index & 3ULL);
    unsigned int next_bit = slot >> 1U;
    unsigned int side = slot & 1U;
    unsigned long long suffix = output_record / raw_width;
    unsigned int wire = (unsigned int)(output_record - suffix * raw_width);
    unsigned long long input_record =
        (2ULL * suffix + next_bit) * raw_width + wire;
    F16 zero = z16(), one = z16();
    if (input_record < input_records) {
        const unsigned int *record = input + 64ULL * input_record;
        zero = l16(record + 16ULL * side);
        one = l16(record + 16ULL * (side + 2U));
    }
    F16 folded = a16(zero, m16(l16(challenge), s16(one, zero)));
    st16(output + 16ULL * index, folded);
}

extern "C" __global__ void semantic_count_nonzero(
    const unsigned int *values, unsigned long long count, unsigned long long *counter
) {
    unsigned long long index = (unsigned long long)blockIdx.x * blockDim.x + threadIdx.x;
    if (index < count && values[index] != 0U) atomicAdd(counter, 1ULL);
}
"""


@dataclass(frozen=True)
class Snapshot:
    profile: int
    semantic_program: bytes
    descriptor: bytes
    semantic_port: bytes
    messages: tuple
    capacities: tuple
    digests: tuple


@dataclass(frozen=True)
class CompactSource:
    profile: int
    shards: int
    padded_permutations: int
    input_patterns: array.array
    output_patterns: array.array
    snapshot: Snapshot
    call_first_permutations: tuple
    call_blocks: tuple
    permutation_calls: tuple
    permutation_blocks: tuple
    total_permutations: int


def take(encoded, offset, count, label):
    end = offset + count
    if end > len(encoded):
        raise ValueError(f"{label}_truncated")
    return encoded[offset:end], end


def read_snapshot(path):
    encoded = path.read_bytes()
    if len(encoded) < 211 or encoded[:8] != SNAPSHOT_MAGIC or encoded[8:10] != b"\x00\x02":
        raise ValueError("snapshot_header")
    profile = encoded[10]
    semantic_program = encoded[11:75]
    descriptor = encoded[75:139]
    semantic_port = encoded[139:203]
    count = int.from_bytes(encoded[203:211], "big")
    offset = 211
    messages, capacities, digests = [], [], []
    for index in range(count):
        header, offset = take(encoded, offset, 12, f"snapshot_message_{index}")
        capacity = int.from_bytes(header[:8], "big")
        length = int.from_bytes(header[8:12], "big")
        if length > capacity or length > (1 << 20):
            raise ValueError("snapshot_capacity")
        message, offset = take(encoded, offset, length, f"snapshot_message_{index}")
        digest, offset = take(encoded, offset, 64, f"snapshot_digest_{index}")
        if hashlib.sha3_512(message).digest() != digest:
            raise ValueError("snapshot_digest")
        messages.append(message)
        capacities.append(capacity)
        digests.append(digest)
    if offset != len(encoded):
        raise ValueError("snapshot_trailing_bytes")
    semantic = hashlib.sha3_512()
    semantic.update(b"BL/PQ512/WAVE2/HASH-BUS-SEMANTIC-PORT/STATE/v1\0")
    semantic.update(b"\x00\x02")
    semantic.update(bytes([profile]))
    semantic.update(semantic_program)
    semantic.update(descriptor)
    semantic.update(count.to_bytes(8, "big"))
    for index, (capacity, message, digest) in enumerate(zip(capacities, messages, digests)):
        semantic.update(index.to_bytes(8, "big"))
        semantic.update(capacity.to_bytes(8, "big"))
        semantic.update(len(message).to_bytes(4, "big"))
        semantic.update(message)
        semantic.update(digest)
    if semantic.digest() != semantic_port:
        raise ValueError("snapshot_semantic_port")
    return Snapshot(
        profile,
        semantic_program,
        descriptor,
        semantic_port,
        tuple(messages),
        tuple(capacities),
        tuple(digests),
    )


def read_source(boundary_path, snapshot_path, expected_profile):
    snapshot = read_snapshot(snapshot_path)
    file_bytes = boundary_path.stat().st_size
    with boundary_path.open("rb") as source:
        header = source.read(BOUNDARY_HEADER_BYTES)
        if len(header) != BOUNDARY_HEADER_BYTES or header[:8] != BOUNDARY_MAGIC or header[8:10] != b"\x00\x02":
            raise ValueError("boundary_header")
        profile = header[10]
        shards = int.from_bytes(header[203:205], "big")
        padded = int.from_bytes(header[205:213], "big")
        live_wires = int.from_bytes(header[213:215], "big")
        plane_patterns = shards * LIVE_WIRES * PACKED_GROUPS_PER_SHARD
        expected_bytes = BOUNDARY_HEADER_BYTES + 2 * plane_patterns * 2
        if (
            profile != expected_profile
            or profile != snapshot.profile
            or header[11:75] != snapshot.semantic_program
            or header[75:139] != snapshot.descriptor
            or header[139:203] != snapshot.semantic_port
            or shards == 0
            or padded != shards * PERMUTATIONS_PER_SHARD
            or live_wires != LIVE_WIRES
            or file_bytes != expected_bytes
        ):
            raise ValueError("boundary_snapshot_join")
        shard_plane_patterns = LIVE_WIRES * PACKED_GROUPS_PER_SHARD
        input_patterns = array.array("H")
        output_patterns = array.array("H")
        for _ in range(shards):
            input_patterns.fromfile(source, shard_plane_patterns)
            output_patterns.fromfile(source, shard_plane_patterns)
    if sys.byteorder != "little":
        input_patterns.byteswap()
        output_patterns.byteswap()

    first, blocks, permutation_calls, permutation_blocks = [], [], [], []
    permutation = 0
    for capacity in snapshot.capacities:
        count = capacity // RATE_BYTES + 1
        first.append(permutation)
        blocks.append(count)
        permutation_calls.extend([len(first) - 1] * count)
        permutation_blocks.extend(range(count))
        permutation += count
    if permutation <= 0 or permutation > padded:
        raise ValueError("snapshot_permutation_geometry")
    return CompactSource(
        profile,
        shards,
        padded,
        input_patterns,
        output_patterns,
        snapshot,
        tuple(first),
        tuple(blocks),
        tuple(permutation_calls),
        tuple(permutation_blocks),
        permutation,
    )


def packed_bit(source, output, permutation, wire):
    shard, local = divmod(permutation, PERMUTATIONS_PER_SHARD)
    index = (shard * LIVE_WIRES + wire) * PACKED_GROUPS_PER_SHARD + local // 16
    plane = source.output_patterns if output else source.input_patterns
    return (plane[index] >> (local % 16)) & 1


def source_value(source, circuit, wire, group):
    if circuit == CIRCUIT_RATE:
        permutation, byte = divmod(group, RATE_BYTES)
        if permutation >= source.total_permutations:
            if RATE_BIT_WEIGHTS_START <= wire < RATE_BIT_WEIGHTS_START + 8:
                return 1 << (wire - RATE_BIT_WEIGHTS_START)
            return {RATE_SIX: 6, RATE_128: 128, RATE_ONE: 1}.get(wire, 0)
        call = source.permutation_calls[permutation]
        block = source.permutation_blocks[permutation]
        position = block * RATE_BYTES + byte
        message = source.snapshot.messages[call]
        if wire == RATE_LIVE:
            return int(position < len(message))
        if wire == RATE_PREVIOUS_LIVE:
            return int(position > 0 and position - 1 < len(message))
        if wire == RATE_BLOCK_ACTIVE:
            return int(block == 0 or block * RATE_BYTES - 1 < len(message))
        if wire == RATE_NEXT_BLOCK_ACTIVE:
            return int(block * RATE_BYTES + 71 < len(message))
        if wire == RATE_VALUE:
            return message[position] if position < len(message) else 0
        if wire == RATE_FINAL_BYTE_SELECTOR:
            return int(byte == 71)
        if RATE_INPUT_BITS_START <= wire < RATE_INPUT_BITS_START + 8:
            return packed_bit(source, False, permutation, 8 * byte + wire - RATE_INPUT_BITS_START)
        if RATE_PREDECESSOR_BITS_START <= wire < RATE_PREDECESSOR_BITS_START + 8:
            return 0 if block == 0 else packed_bit(source, True, permutation - 1, 8 * byte + wire - RATE_PREDECESSOR_BITS_START)
        if RATE_BIT_WEIGHTS_START <= wire < RATE_BIT_WEIGHTS_START + 8:
            return 1 << (wire - RATE_BIT_WEIGHTS_START)
        return {RATE_SIX: 6, RATE_128: 128, RATE_ONE: 1}.get(wire, 0)
    if circuit in (CIRCUIT_INACTIVE, CIRCUIT_CAPACITY):
        if group >= source.total_permutations:
            return 0
        call = source.permutation_calls[group]
        block = source.permutation_blocks[group]
        length = len(source.snapshot.messages[call])
        if wire == BLOCK_ACTIVE:
            return int(block == 0 or block * RATE_BYTES - 1 < length)
        if circuit == CIRCUIT_INACTIVE and wire < LIVE_WIRES:
            return packed_bit(source, False, group, wire)
        if circuit == CIRCUIT_CAPACITY and wire < 1024:
            return packed_bit(source, False, group, 576 + wire)
        if circuit == CIRCUIT_CAPACITY and 1024 <= wire < 2048 and block > 0:
            return packed_bit(source, True, group - 1, 576 + wire - 1024)
        return 0
    if circuit == CIRCUIT_DIGEST:
        call, byte = divmod(group, 64)
        if call >= len(source.snapshot.messages):
            return 0
        blocks = source.call_blocks[call]
        length = len(source.snapshot.messages[call])
        if wire < 1024:
            return int(wire < blocks and (wire == 0 or wire * RATE_BYTES - 1 < length))
        if DIGEST_NEXT_ACTIVE_START <= wire < DIGEST_NEXT_ACTIVE_START + 1024:
            block = wire - DIGEST_NEXT_ACTIVE_START + 1
            return int(block < blocks and block * RATE_BYTES - 1 < length)
        if DIGEST_OUTPUT_BYTES_START <= wire < DIGEST_OUTPUT_BYTES_START + 1024:
            block = wire - DIGEST_OUTPUT_BYTES_START
            if block >= blocks:
                return 0
            permutation = source.call_first_permutations[call] + block
            return sum(packed_bit(source, True, permutation, 8 * byte + bit) << bit for bit in range(8))
        if wire == DIGEST_EXPECTED_BYTE:
            return source.snapshot.digests[call][byte]
        return 0
    raise ValueError("source_circuit")


def layer_value(source, circuit, layer, wire, group):
    """Base-field executable topology used to differential-test GPU layers."""
    if circuit == CIRCUIT_RATE:
        row0 = [
            (source_value(source, circuit, RATE_INPUT_BITS_START + bit, group)
             + source_value(source, circuit, RATE_PREDECESSOR_BITS_START + bit, group)
             - 2 * source_value(source, circuit, RATE_INPUT_BITS_START + bit, group)
             * source_value(source, circuit, RATE_PREDECESSOR_BITS_START + bit, group)) % M31
            for bit in range(8)
        ]
        live = source_value(source, circuit, RATE_LIVE, group)
        previous = source_value(source, circuit, RATE_PREVIOUS_LIVE, group)
        next_active = source_value(source, circuit, RATE_NEXT_BLOCK_ACTIVE, group)
        active = source_value(source, circuit, RATE_BLOCK_ACTIVE, group)
        row0.extend([(previous * (1 - live)) % M31, (active * (1 - next_active)) % M31,
                     source_value(source, circuit, RATE_VALUE, group), active])
        rows = [row0 + [0] * 4]
        row1 = [rows[0][bit] * (1 << bit) % M31 for bit in range(8)]
        row1.extend([
            rows[0][8] * 6 % M31,
            rows[0][9] * source_value(source, circuit, RATE_FINAL_BYTE_SELECTOR, group) % M31,
            rows[0][10], rows[0][11],
        ])
        rows.append(row1 + [0] * 4)
        row2 = row1[:9] + [row1[9] * 128 % M31, row1[10], row1[11]]
        rows.append(row2 + [0] * 4)
        rows.append([(row2[0] + row2[1]) % M31, (row2[2] + row2[3]) % M31,
                     (row2[4] + row2[5]) % M31, (row2[6] + row2[7]) % M31,
                     (row2[8] + row2[9]) % M31, row2[10], row2[11], 0])
        rows.append([(rows[3][0] + rows[3][1]) % M31, (rows[3][2] + rows[3][3]) % M31,
                     (rows[3][4] + rows[3][5]) % M31, rows[3][6]])
        rows.append([(rows[4][0] + rows[4][1]) % M31, rows[4][2], rows[4][3]])
        rows[-1].append(0)
        rows.append([(rows[5][0] - rows[5][1]) % M31, rows[5][2]])
        rows.append([rows[6][1] * rows[6][0] % M31])
        return rows[layer][wire] if wire < len(rows[layer]) else 0
    if circuit == CIRCUIT_INACTIVE:
        if layer != 0 or wire >= 2048:
            return 0
        return (1 - source_value(source, circuit, BLOCK_ACTIVE, group)) * source_value(source, circuit, wire, group) % M31
    if circuit == CIRCUIT_CAPACITY:
        if wire >= 1024:
            return 0
        difference = (source_value(source, circuit, wire, group) - source_value(source, circuit, 1024 + wire, group)) % M31
        return difference if layer == 0 else difference * source_value(source, circuit, BLOCK_ACTIVE, group) % M31
    if circuit == CIRCUIT_DIGEST:
        if layer == 0:
            return 0 if wire >= 1024 else (1 - source_value(source, circuit, DIGEST_NEXT_ACTIVE_START + wire, group)) * source_value(source, circuit, wire, group) % M31
        if layer == 1:
            return 0 if wire >= 1024 else layer_value(source, circuit, 0, wire, group) * source_value(source, circuit, DIGEST_OUTPUT_BYTES_START + wire, group) % M31
        if 2 <= layer <= 11:
            raw_width = 1 << (11 - layer)
            if wire >= raw_width:
                return 0
            span = 1 << (layer - 1)
            start = wire * span
            return sum(layer_value(source, circuit, 1, block, group) for block in range(start, start + span)) % M31
        if layer == 12 and wire == 0:
            return (layer_value(source, circuit, 11, 0, group) - source_value(source, circuit, DIGEST_EXPECTED_BYTE, group)) % M31
        return 0
    raise ValueError("layer_circuit")


def _layer(left_source, right_source, left_width, right_width, gates):
    padded = 1 << (len(gates) - 1).bit_length()
    return (left_source, right_source, left_width, right_width, tuple(gates), padded)


def circuit_topology(circuit):
    if circuit == CIRCUIT_RATE:
        first = [(RATE_INPUT_BITS_START + bit, RATE_PREDECESSOR_BITS_START + bit, 0) for bit in range(8)]
        first += [(RATE_LIVE, RATE_PREVIOUS_LIVE, 1), (RATE_NEXT_BLOCK_ACTIVE, RATE_BLOCK_ACTIVE, 1),
                  (RATE_VALUE, RATE_VALUE, 7), (RATE_BLOCK_ACTIVE, RATE_BLOCK_ACTIVE, 7)]
        weighted = [(bit, RATE_BIT_WEIGHTS_START + bit, 5) for bit in range(8)]
        weighted += [(8, RATE_SIX, 5), (9, RATE_FINAL_BYTE_SELECTOR, 5), (10, RATE_ONE, 5), (11, RATE_ONE, 5)]
        final_weight = [(index, index, 7) for index in range(9)] + [(9, RATE_128, 5), (10, 10, 7), (11, 11, 7)]
        return (
            _layer(-1, -1, 64, 64, first), _layer(0, -1, 16, 64, weighted),
            _layer(1, -1, 16, 64, final_weight),
            _layer(2, 2, 16, 16, [(0,1,6),(2,3,6),(4,5,6),(6,7,6),(8,9,6),(10,10,7),(11,11,7)]),
            _layer(3, 3, 8, 8, [(0,1,6),(2,3,6),(4,5,6),(6,6,7)]),
            _layer(4, 4, 4, 4, [(0,1,6),(2,2,7),(3,3,7)]),
            _layer(5, 5, 4, 4, [(0,1,4),(2,2,7)]), _layer(6, 6, 2, 2, [(1,0,5)]),
        )
    if circuit == CIRCUIT_INACTIVE:
        return (_layer(-1, -1, 4096, 4096, [(BLOCK_ACTIVE, wire, 1) for wire in range(2048)]),)
    if circuit == CIRCUIT_CAPACITY:
        return (
            _layer(-1, -1, 4096, 4096, [(wire, 1024 + wire, 4) for wire in range(1024)]),
            _layer(0, -1, 1024, 4096, [(wire, BLOCK_ACTIVE, 5) for wire in range(1024)]),
        )
    if circuit == CIRCUIT_DIGEST:
        layers = [
            _layer(-1, -1, 4096, 4096, [(DIGEST_NEXT_ACTIVE_START + block, block, 1) for block in range(1024)]),
            _layer(0, -1, 1024, 4096, [(block, DIGEST_OUTPUT_BYTES_START + block, 5) for block in range(1024)]),
        ]
        width = 1024
        while width > 1:
            gates = [(2 * index, 2 * index + 1, 6) for index in range(width // 2)]
            if width == 2:
                gates += [(0, 0, 8)] * 3
            prior = len(layers) - 1
            layers.append(_layer(prior, prior, width, width, gates))
            width //= 2
        prior = len(layers) - 1
        layers.append(_layer(prior, -1, layers[prior][5], 4096, [(0, DIGEST_EXPECTED_BYTE, 4)]))
        return tuple(layers)
    raise ValueError("topology_circuit")


def cpu_relation_preflight(source):
    checks = 0
    for circuit, final_layer, group_limit in (
        (CIRCUIT_RATE, 7, 1 << (23 if source.profile == 1 else 25)),
        (CIRCUIT_INACTIVE, 0, 1 << 19),
        (CIRCUIT_CAPACITY, 1, 1 << 19),
        (CIRCUIT_DIGEST, 12, 1 << 24),
    ):
        state = 0xC001D00D ^ circuit
        for _ in range(1024):
            state = (1103515245 * state + 12345) & 0xFFFFFFFF
            group = state % group_limit
            if circuit == CIRCUIT_INACTIVE:
                wire = (state >> 9) % 2048
            elif circuit == CIRCUIT_CAPACITY:
                wire = (state >> 9) % 1024
            else:
                wire = 0
            value = layer_value(source, circuit, final_layer, wire, group)
            if value != 0:
                raise ValueError(f"relation_nonzero:{circuit}:{group}:{wire}:{value}")
            checks += 1
    return checks


def _upload(runtime, values):
    view = (ctypes.c_ubyte * (len(values) * values.itemsize)).from_buffer(values)
    device = runtime.alloc(len(view))
    from cuda_fp16_tower_kat import ck
    ck(runtime.cuda.cuMemcpyHtoD_v2(device, ctypes.cast(view, ctypes.c_void_p), len(view)), "semantic_source_upload")
    return device


def _free(runtime, device):
    from cuda_fp16_tower_kat import ck
    ck(runtime.cuda.cuMemFree_v2(device), "semantic_temporary_free")
    runtime.allocs.remove(device)


def _arguments(values):
    return (ctypes.c_void_p * len(values))(*(
        ctypes.cast(ctypes.byref(value), ctypes.c_void_p) for value in values
    ))


def _read_exact(stream, count, label):
    value = stream.read(count)
    if len(value) != count:
        raise ValueError(f"{label}_truncated")
    return value


def _read_fp16(stream):
    encoded = _read_exact(stream, 64, "fp16")
    result = tuple(int.from_bytes(encoded[4 * i:4 * i + 4], "big") for i in range(16))
    if any(value >= M31 for value in result):
        raise ValueError("fp16_noncanonical")
    return result


def _write_fp16(stream, value):
    stream.write(b"".join(int(coordinate).to_bytes(4, "big") for coordinate in value))


def _fp16_words(values):
    return array.array("I", (coordinate for value in values for coordinate in value))


def _fp16_zero():
    return (0,) * 16


def _fp16_one():
    return (1,) + (0,) * 15


def _fp16_add(left, right):
    return tuple((a + b) % M31 for a, b in zip(left, right))


def _fp16_sub(left, right):
    return tuple((a - b) % M31 for a, b in zip(left, right))


def _fp16_mul(left, right):
    from cuda_fp16_tower_kat import mul16
    return tuple(mul16(left, right))


def _equality_line(point, query):
    one = _fp16_one()
    return _fp16_add(_fp16_sub(_fp16_sub(one, point), query),
                     _fp16_add(_fp16_mul(point, query), _fp16_mul(point, query)))


class ProductionBridgeEngine:
    """Bounded CUDA algebra engine; transcript ownership remains in Rust."""

    def __init__(self, source):
        from cuda_fp16_tower_kat import CUDA, Runtime, ck
        from cuda_dag_shared_group_message_benchmark import MESSAGE_KERNEL, function
        configured = os.environ.get("BL_NVRTC_BIN")
        nvrtc = Path(configured) if configured else Path(__file__).parent / "cuda_nvrtc" / "nvidia" / "cuda_nvrtc" / "bin"
        self.ck = ck
        self.function = function
        self.runtime = Runtime(nvrtc)
        self.runtime.compile(CUDA + FP16_LINEAR_KERNEL + SOURCE_KERNEL + DAG_KERNEL + MESSAGE_KERNEL + STREAM_KERNEL,
                             b"semantic_source_values")
        self.runtime.cuda.cuMemsetD8_v2.argtypes = [ctypes.c_uint64, ctypes.c_ubyte, ctypes.c_size_t]
        self.runtime.cuda.cuMemcpyDtoD_v2.argtypes = [
            ctypes.c_uint64, ctypes.c_uint64, ctypes.c_size_t
        ]
        self.f = {name: function(self.runtime, name) for name in (
            "semantic_source_requests", "semantic_source_values", "semantic_dag_layer_base",
            "semantic_equality_weights", "semantic_wire_weights", "semantic_group_weights",
            "semantic_accumulate_gate_inputs", "semantic_accumulated_message",
            "reduce_cubic_partials", "semantic_fold_source_chunk",
            "semantic_fold_accumulator", "semantic_count_nonzero")}
        self.source = source
        offsets, lengths, flat_messages, flat_digests = array.array("I"), array.array("I"), array.array("B"), array.array("B")
        for message, digest in zip(source.snapshot.messages, source.snapshot.digests):
            offsets.append(len(flat_messages)); lengths.append(len(message))
            flat_messages.extend(message); flat_digests.extend(digest)
        persistent = (
            source.input_patterns, source.output_patterns,
            array.array("I", source.permutation_calls), array.array("I", source.permutation_blocks),
            array.array("I", source.call_first_permutations), array.array("I", source.call_blocks),
            offsets, lengths, flat_messages, flat_digests,
        )
        self.source_devices = tuple(_upload(self.runtime, values) for values in persistent)
        self.active = None

    def close(self):
        self.runtime.close()

    def _launch(self, name, blocks, threads, values, label=None):
        self.ck(self.runtime.cuda.cuLaunchKernel(
            self.f[name], blocks, 1, 1, threads, 1, 1, 0, None, _arguments(values), None),
            label or name)

    def _copy_fp16(self, device, count=1):
        words = array.array("I", [0]) * (16 * count)
        view = (ctypes.c_ubyte * (len(words) * 4)).from_buffer(words)
        self.ck(self.runtime.cuda.cuMemcpyDtoH_v2(ctypes.cast(view, ctypes.c_void_p), device, len(view)), "semantic_fp16_copy")
        return [tuple(words[16 * i:16 * (i + 1)]) for i in range(count)]

    def _topology_devices(self, topology):
        gates = topology[4]
        return tuple(_upload(self.runtime, values) for values in (
            array.array("H", (gate[0] for gate in gates)),
            array.array("H", (gate[1] for gate in gates)),
            array.array("B", (gate[2] for gate in gates)),
        ))

    def _materialize(self, circuit, through_layer, group_start, groups):
        source_width = 64 if circuit == CIRCUIT_RATE else 4096
        count = groups * source_width
        requests = self.runtime.alloc(count * 12)
        values = self.runtime.alloc(count * 4)
        args = [ctypes.c_uint64(requests), ctypes.c_uint32(circuit), ctypes.c_uint32(source_width),
                ctypes.c_uint32(group_start), ctypes.c_uint32(groups)]
        self._launch("semantic_source_requests", (count + 127) // 128, 128, args)
        scalar = [count, self.source.total_permutations, len(self.source.snapshot.messages)]
        args = [ctypes.c_uint64(value) for value in self.source_devices] + [ctypes.c_uint64(requests), ctypes.c_uint64(values)] + [ctypes.c_uint32(value) for value in scalar]
        self._launch("semantic_source_values", (count + 127) // 128, 128, args)
        rows = [values]
        temporaries = [requests, values]
        for topology in circuit_topology(circuit)[:through_layer + 1]:
            left_source, right_source, left_width, right_width, gates, padded = topology
            left = rows[0 if left_source == -1 else left_source + 1]
            right = rows[0 if right_source == -1 else right_source + 1]
            gate_devices = self._topology_devices(topology)
            output = self.runtime.alloc(groups * padded * 4)
            temporaries.extend(gate_devices); temporaries.append(output)
            args = [ctypes.c_uint64(left), ctypes.c_uint64(right),
                    ctypes.c_uint64(gate_devices[0]), ctypes.c_uint64(gate_devices[1]), ctypes.c_uint64(gate_devices[2]),
                    ctypes.c_uint64(output), ctypes.c_uint32(groups), ctypes.c_uint32(left_width),
                    ctypes.c_uint32(right_width), ctypes.c_uint32(len(gates)), ctypes.c_uint32(padded)]
            self._launch("semantic_dag_layer_base", (groups * padded + 127) // 128, 128, args)
            rows.append(output)
        return rows, temporaries

    def _release(self, temporaries):
        for device in reversed(temporaries):
            _free(self.runtime, device)

    def output_claim(self, circuit, point):
        layers = circuit_topology(circuit)
        group_rounds = {CIRCUIT_RATE: 23 if self.source.profile == 1 else 25,
                        CIRCUIT_INACTIVE: 19, CIRCUIT_CAPACITY: 19, CIRCUIT_DIGEST: 24}[circuit]
        final_width = layers[-1][5]
        if len(point) != final_width.bit_length() - 1 + group_rounds:
            raise ValueError("output_point_shape")
        # The four public bridge relations are zero constraints.  This process
        # is an untrusted oracle, so eagerly evaluating the entire padded
        # relation here adds no proof authority: Rust subsequently binds this
        # claim into the transcript, checks every sumcheck recurrence, and
        # verifies the terminal source openings.  In particular, scanning the
        # 2^24-by-4096 digest source before beginning that proof is redundant.
        return _fp16_zero()

    def begin(self, circuit, layer_index, topology, claims):
        canonical = circuit_topology(circuit)[layer_index]
        canonical_raw = len(canonical[4])
        topology_matches = (
            topology[:4] == canonical[:4]
            and topology[5] == canonical[5]
            and topology[4][:canonical_raw] == canonical[4]
            and all(gate == (0, 0, 8) for gate in topology[4][canonical_raw:])
        )
        if not topology_matches or not claims:
            raise ValueError("rust_topology_mismatch")
        point_len = len(claims[0][2])
        if any(len(claim[2]) != point_len for claim in claims):
            raise ValueError("claim_shape")
        group_rounds = {CIRCUIT_RATE: 23 if self.source.profile == 1 else 25,
                        CIRCUIT_INACTIVE: 19, CIRCUIT_CAPACITY: 19, CIRCUIT_DIGEST: 24}[circuit]
        output_variables = topology[5].bit_length() - 1
        if point_len != output_variables + group_rounds:
            raise ValueError("claim_point_shape")
        records = _fp16_words([value for claim in claims for value in (claim[0], claim[1], *claim[2])])
        claims_d = _upload(self.runtime, records)
        prefixes = [_fp16_mul(claim[1], _fp16_one()) for claim in claims]
        prefixes_d = _upload(self.runtime, _fp16_words(prefixes))
        gate_d = self._topology_devices(topology)
        wire_d = self.runtime.alloc(len(claims) * topology[5] * 64)
        count = len(claims) * topology[5]
        self._launch("semantic_wire_weights", (count + 127) // 128, 128,
                     [ctypes.c_uint64(claims_d), ctypes.c_uint32(len(claims)), ctypes.c_uint32(point_len),
                      ctypes.c_uint32(output_variables), ctypes.c_uint32(topology[5]), ctypes.c_uint64(wire_d)])
        self.active = dict(circuit=circuit, layer=layer_index, topology=topology, claims=claims,
                           point_len=point_len, group_rounds=group_rounds, output_variables=output_variables,
                           accepted=[], prefixes=prefixes, claims_d=claims_d, prefixes_d=prefixes_d,
                           gate_d=gate_d, wire_d=wire_d, round_message_ready=False,
                           retained_accumulator=None, retained_suffix_count=0,
                           active_groups=(
                               (1 << group_rounds) if circuit == CIRCUIT_RATE
                               else self.source.total_permutations
                               if circuit in (CIRCUIT_INACTIVE, CIRCUIT_CAPACITY)
                               else len(self.source.snapshot.messages) * 64
                           ))

    def _prefix_weights(self, first, count):
        state = self.active
        point_words = _fp16_words(state["accepted"])
        if not point_words:
            point_words = array.array("I", [0]) * 16
        point_d = _upload(self.runtime, point_words)
        result = self.runtime.alloc(count * 64)
        self._launch("semantic_equality_weights", (count + 127) // 128, 128,
                     [ctypes.c_uint64(point_d), ctypes.c_uint32(len(state["accepted"])),
                      ctypes.c_uint32(first), ctypes.c_uint32(count), ctypes.c_uint64(result)])
        _free(self.runtime, point_d)
        return result

    def raw_group_round(self, round_index):
        started_at = time.perf_counter()
        state = self.active
        if state is None or round_index != len(state["accepted"]) or state["round_message_ready"]:
            raise ValueError("group_round_schedule")
        topology = state["topology"]
        raw_width, total_suffix = len(topology[4]), 1 << (state["group_rounds"] - round_index - 1)
        prefix = 1 << round_index
        active_suffix = min(
            total_suffix,
            (state["active_groups"] + 2 * prefix - 1) // (2 * prefix),
        )
        max_groups = 65536 if state["circuit"] == CIRCUIT_RATE else 4096
        max_suffix_batch = max(1, min(max_groups // (2 * prefix), (1 << 20) // raw_width))
        total = [_fp16_zero()] * 4
        from cuda_dag_shared_group_message_benchmark import reduce_partials
        retained = state["retained_accumulator"]
        if retained is not None:
            if state["retained_suffix_count"] != active_suffix:
                raise ValueError("retained_suffix_shape")
            for suffix_start in range(0, active_suffix, max_suffix_batch):
                suffix_count = min(max_suffix_batch, active_suffix - suffix_start)
                group_zero = self.runtime.alloc(len(state["claims"]) * suffix_count * 64)
                group_delta = self.runtime.alloc(len(state["claims"]) * suffix_count * 64)
                count = len(state["claims"]) * suffix_count
                self._launch("semantic_group_weights", (count + 127) // 128, 128,
                             [ctypes.c_uint64(state["claims_d"]), ctypes.c_uint64(state["prefixes_d"]),
                              ctypes.c_uint32(len(state["claims"])), ctypes.c_uint32(state["point_len"]),
                              ctypes.c_uint32(state["output_variables"]), ctypes.c_uint32(state["group_rounds"]),
                              ctypes.c_uint32(round_index), ctypes.c_uint32(suffix_start), ctypes.c_uint32(suffix_count),
                              ctypes.c_uint64(group_zero), ctypes.c_uint64(group_delta)])
                terms = raw_width * suffix_count
                blocks = (terms + 1023) // 1024
                partial = self.runtime.alloc(max(1, blocks) * 256)
                scratch = self.runtime.alloc(max(1, blocks) * 256)
                accumulator_offset = retained + suffix_start * raw_width * 4 * 64
                self._launch("semantic_accumulated_message", blocks, 128,
                             [ctypes.c_uint64(accumulator_offset), ctypes.c_uint64(state["gate_d"][2]),
                              ctypes.c_uint64(state["wire_d"]), ctypes.c_uint64(group_zero), ctypes.c_uint64(group_delta),
                              ctypes.c_uint64(partial), ctypes.c_uint32(raw_width), ctypes.c_uint32(suffix_count),
                              ctypes.c_uint32(len(state["claims"]))])
                result_d = reduce_partials(self.runtime, self.f["reduce_cubic_partials"], partial, scratch, blocks)
                self.ck(self.runtime.cuda.cuCtxSynchronize(), "semantic_retained_round_sync")
                words = array.array("I", [0]) * 64
                view = (ctypes.c_ubyte * 256).from_buffer(words)
                self.ck(self.runtime.cuda.cuMemcpyDtoH_v2(ctypes.cast(view, ctypes.c_void_p), result_d, 256),
                        "semantic_retained_message_copy")
                for i in range(4):
                    total[i] = _fp16_add(total[i], tuple(words[16 * i:16 * (i + 1)]))
                for device in (scratch, partial, group_delta, group_zero):
                    _free(self.runtime, device)
            state["round_message_ready"] = True
            if os.environ.get("BL_BRIDGE_PROFILE") == "1":
                print(
                    f"bridge_profile circuit={state['circuit']} layer={state['layer']} "
                    f"round={round_index} mode=retained suffixes={active_suffix}/{total_suffix} "
                    f"seconds={time.perf_counter() - started_at:.6f}",
                    file=sys.stderr,
                    flush=True,
                )
            return total

        retain_bytes = active_suffix * raw_width * 4 * 64
        retain_this_round = retain_bytes <= RETAINED_ACCUMULATOR_BYTES
        retained = None
        if retain_this_round:
            try:
                retained = self.runtime.alloc(retain_bytes)
            except RuntimeError:
                # Retention is a performance cache, never proof authority.
                # Continue on the canonical streamed path if current device
                # fragmentation cannot satisfy this optional allocation.
                retained = None
        for suffix_start in range(0, active_suffix, max_suffix_batch):
            suffix_count = min(max_suffix_batch, active_suffix - suffix_start)
            accumulator = self.runtime.alloc(suffix_count * raw_width * 4 * 64)
            accumulator_bytes = suffix_count * raw_width * 4 * 64
            self.ck(self.runtime.cuda.cuMemsetD8_v2(accumulator, 0, accumulator_bytes), "semantic_accumulator_zero")
            if prefix <= max_groups // 2:
                groups = suffix_count * 2 * prefix
                rows, temporary = self._materialize(state["circuit"], state["layer"] - 1,
                                                     suffix_start * 2 * prefix, groups)
                left_source, right_source = topology[0], topology[1]
                left = rows[0 if left_source == -1 else left_source + 1]
                right = rows[0 if right_source == -1 else right_source + 1]
                weights = self._prefix_weights(0, prefix)
                for bit in (0, 1):
                    count = suffix_count * raw_width
                    args = [ctypes.c_uint64(left), ctypes.c_uint64(right), ctypes.c_uint64(state["gate_d"][0]),
                            ctypes.c_uint64(state["gate_d"][1]), ctypes.c_uint64(weights), ctypes.c_uint64(accumulator),
                            ctypes.c_uint32(raw_width), ctypes.c_uint32(topology[2]), ctypes.c_uint32(topology[3]),
                            ctypes.c_uint32(suffix_count), ctypes.c_uint32(prefix), ctypes.c_uint32(prefix),
                            ctypes.c_uint32(0), ctypes.c_uint32(bit), ctypes.c_uint32(bit)]
                    self._launch("semantic_accumulate_gate_inputs", (count + 127) // 128, 128, args)
                _free(self.runtime, weights); self._release(temporary)
            else:
                if suffix_count != 1:
                    raise ValueError("late_suffix_batch")
                global_suffix = suffix_start
                for bit in (0, 1):
                    for low in range(0, prefix, max_groups):
                        groups = min(max_groups, prefix - low)
                        start = (2 * global_suffix + bit) * prefix + low
                        rows, temporary = self._materialize(state["circuit"], state["layer"] - 1, start, groups)
                        left_source, right_source = topology[0], topology[1]
                        left = rows[0 if left_source == -1 else left_source + 1]
                        right = rows[0 if right_source == -1 else right_source + 1]
                        weights = self._prefix_weights(low, groups)
                        args = [ctypes.c_uint64(left), ctypes.c_uint64(right), ctypes.c_uint64(state["gate_d"][0]),
                                ctypes.c_uint64(state["gate_d"][1]), ctypes.c_uint64(weights), ctypes.c_uint64(accumulator),
                                ctypes.c_uint32(raw_width), ctypes.c_uint32(topology[2]), ctypes.c_uint32(topology[3]),
                                ctypes.c_uint32(1), ctypes.c_uint32(groups), ctypes.c_uint32(groups),
                                ctypes.c_uint32(low), ctypes.c_uint32(0), ctypes.c_uint32(bit)]
                        self._launch("semantic_accumulate_gate_inputs", (raw_width + 127) // 128, 128, args)
                        _free(self.runtime, weights); self._release(temporary)
            group_zero = self.runtime.alloc(len(state["claims"]) * suffix_count * 64)
            group_delta = self.runtime.alloc(len(state["claims"]) * suffix_count * 64)
            count = len(state["claims"]) * suffix_count
            self._launch("semantic_group_weights", (count + 127) // 128, 128,
                         [ctypes.c_uint64(state["claims_d"]), ctypes.c_uint64(state["prefixes_d"]),
                          ctypes.c_uint32(len(state["claims"])), ctypes.c_uint32(state["point_len"]),
                          ctypes.c_uint32(state["output_variables"]), ctypes.c_uint32(state["group_rounds"]),
                          ctypes.c_uint32(round_index), ctypes.c_uint32(suffix_start), ctypes.c_uint32(suffix_count),
                          ctypes.c_uint64(group_zero), ctypes.c_uint64(group_delta)])
            terms = raw_width * suffix_count
            blocks = (terms + 1023) // 1024
            partial = self.runtime.alloc(max(1, blocks) * 256)
            scratch = self.runtime.alloc(max(1, blocks) * 256)
            self._launch("semantic_accumulated_message", blocks, 128,
                         [ctypes.c_uint64(accumulator), ctypes.c_uint64(state["gate_d"][2]),
                          ctypes.c_uint64(state["wire_d"]), ctypes.c_uint64(group_zero), ctypes.c_uint64(group_delta),
                          ctypes.c_uint64(partial), ctypes.c_uint32(raw_width), ctypes.c_uint32(suffix_count),
                          ctypes.c_uint32(len(state["claims"]))])
            result_d = reduce_partials(self.runtime, self.f["reduce_cubic_partials"], partial, scratch, blocks)
            self.ck(self.runtime.cuda.cuCtxSynchronize(), "semantic_group_round_sync")
            value = self._copy_fp16(result_d, 4) if False else None
            words = array.array("I", [0]) * 64
            view = (ctypes.c_ubyte * 256).from_buffer(words)
            self.ck(self.runtime.cuda.cuMemcpyDtoH_v2(ctypes.cast(view, ctypes.c_void_p), result_d, 256), "semantic_group_message_copy")
            for i in range(4): total[i] = _fp16_add(total[i], tuple(words[16 * i:16 * (i + 1)]))
            if retained is not None:
                self.ck(self.runtime.cuda.cuMemcpyDtoD_v2(
                    retained + suffix_start * raw_width * 4 * 64,
                    accumulator,
                    accumulator_bytes,
                ), "semantic_retain_accumulator")
            for device in (scratch, partial, group_delta, group_zero, accumulator): _free(self.runtime, device)
        if retained is not None:
            state["retained_accumulator"] = retained
            state["retained_suffix_count"] = active_suffix
        state["round_message_ready"] = True
        if os.environ.get("BL_BRIDGE_PROFILE") == "1":
            print(
                f"bridge_profile circuit={state['circuit']} layer={state['layer']} "
                f"round={round_index} mode={'retain' if retained is not None else 'stream'} "
                f"suffixes={active_suffix}/{total_suffix} seconds={time.perf_counter() - started_at:.6f}",
                file=sys.stderr,
                flush=True,
            )
        return total

    def accept(self, round_index, challenge):
        state = self.active
        if state is None or round_index != len(state["accepted"]) or not state["round_message_ready"]:
            raise ValueError("challenge_schedule")
        state["accepted"].append(challenge)
        state["round_message_ready"] = False
        retained = state["retained_accumulator"]
        if retained is not None:
            current_suffix = state["retained_suffix_count"]
            if current_suffix <= 0:
                raise ValueError("retained_fold_shape")
            next_suffix = (current_suffix + 1) // 2
            raw_width = len(state["topology"][4])
            output = self.runtime.alloc(next_suffix * raw_width * 4 * 64)
            challenge_d = _upload(self.runtime, _fp16_words([challenge]))
            count = next_suffix * raw_width * 4
            self._launch("semantic_fold_accumulator", (count + 127) // 128, 128,
                         [ctypes.c_uint64(retained), ctypes.c_uint64(challenge_d),
                          ctypes.c_uint64(output), ctypes.c_uint32(raw_width),
                          ctypes.c_uint64(current_suffix * raw_width),
                          ctypes.c_uint64(next_suffix * raw_width)])
            _free(self.runtime, challenge_d)
            _free(self.runtime, retained)
            state["retained_accumulator"] = output
            state["retained_suffix_count"] = next_suffix
        state["prefixes"] = [_fp16_mul(prefix, _equality_line(claim[2][state["output_variables"] + round_index], challenge))
                             for prefix, claim in zip(state["prefixes"], state["claims"])]
        words = _fp16_words(state["prefixes"])
        view = (ctypes.c_ubyte * (len(words) * 4)).from_buffer(words)
        self.ck(self.runtime.cuda.cuMemcpyHtoD_v2(state["prefixes_d"], ctypes.cast(view, ctypes.c_void_p), len(view)), "semantic_prefix_update")

    def folded_sources(self):
        state = self.active
        if state is None or len(state["accepted"]) != state["group_rounds"]:
            raise ValueError("folded_schedule")
        topology = state["topology"]
        widths = [topology[2]] if topology[0] == topology[1] else [topology[2], topology[3]]
        outputs = [self.runtime.alloc(width * 64) for width in widths]
        for output, width in zip(outputs, widths):
            self.ck(self.runtime.cuda.cuMemsetD8_v2(output, 0, width * 64), "semantic_fold_zero")
        total_groups = state["active_groups"]
        chunk = 65536 if state["circuit"] == CIRCUIT_RATE else 4096
        for start in range(0, total_groups, chunk):
            groups = min(chunk, total_groups - start)
            rows, temporary = self._materialize(state["circuit"], state["layer"] - 1, start, groups)
            weights = self._prefix_weights(start, groups)
            sources = [rows[0 if topology[0] == -1 else topology[0] + 1]]
            if topology[0] != topology[1]: sources.append(rows[0 if topology[1] == -1 else topology[1] + 1])
            for source_d, output, width in zip(sources, outputs, widths):
                self._launch("semantic_fold_source_chunk", (width + 127) // 128, 128,
                             [ctypes.c_uint64(source_d), ctypes.c_uint64(weights), ctypes.c_uint64(output),
                              ctypes.c_uint32(width), ctypes.c_uint32(groups)])
            _free(self.runtime, weights); self._release(temporary)
        self.ck(self.runtime.cuda.cuCtxSynchronize(), "semantic_folded_sources_sync")
        result = [self._copy_fp16(output, width) for output, width in zip(outputs, widths)]
        for output in outputs: _free(self.runtime, output)
        same_sources = len(result) == 1
        if same_sources: result.append(list(result[0]))
        retained = state["retained_accumulator"]
        if retained is not None:
            _free(self.runtime, retained)
        for device in (*state["gate_d"], state["wire_d"], state["prefixes_d"], state["claims_d"]): _free(self.runtime, device)
        self.active = None
        return result[0], result[1], same_sources


def gpu_source_preflight(source):
    from cuda_fp16_tower_kat import Runtime, ck
    configured = os.environ.get("BL_NVRTC_BIN")
    nvrtc = Path(configured) if configured else Path(__file__).parent / "cuda_nvrtc" / "nvidia" / "cuda_nvrtc" / "bin"
    runtime = Runtime(nvrtc)
    try:
        runtime.compile(SOURCE_KERNEL, b"semantic_source_values")
        offsets, lengths, flat_messages = array.array("I"), array.array("I"), array.array("B")
        flat_digests = array.array("B")
        for message, digest in zip(source.snapshot.messages, source.snapshot.digests):
            offsets.append(len(flat_messages))
            lengths.append(len(message))
            flat_messages.extend(message)
            flat_digests.extend(digest)
        requests = [
            (CIRCUIT_RATE, RATE_LIVE, 0),
            (CIRCUIT_RATE, RATE_VALUE, 0),
            (CIRCUIT_RATE, RATE_NEXT_BLOCK_ACTIVE, 0),
            (CIRCUIT_RATE, RATE_INPUT_BITS_START + 7, 71),
            (CIRCUIT_RATE, RATE_PREDECESSOR_BITS_START, 72),
            (CIRCUIT_RATE, RATE_128, (1 << (23 if source.profile == 1 else 25)) - 1),
            (CIRCUIT_INACTIVE, BLOCK_ACTIVE, 0),
            (CIRCUIT_INACTIVE, 1599, source.total_permutations - 1),
            (CIRCUIT_CAPACITY, 0, 0),
            (CIRCUIT_CAPACITY, 1024, 1),
            (CIRCUIT_DIGEST, 0, 0),
            (CIRCUIT_DIGEST, DIGEST_NEXT_ACTIVE_START, 0),
            (CIRCUIT_DIGEST, DIGEST_OUTPUT_BYTES_START, 0),
            (CIRCUIT_DIGEST, DIGEST_EXPECTED_BYTE, 0),
            (CIRCUIT_DIGEST, DIGEST_EXPECTED_BYTE, len(source.snapshot.messages) * 64 - 1),
            (CIRCUIT_DIGEST, DIGEST_EXPECTED_BYTE, (1 << 24) - 1),
        ]
        widths = {CIRCUIT_RATE: 64, CIRCUIT_INACTIVE: 4096, CIRCUIT_CAPACITY: 4096, CIRCUIT_DIGEST: 4096}
        logs = {CIRCUIT_RATE: 23 if source.profile == 1 else 25, CIRCUIT_INACTIVE: 19, CIRCUIT_CAPACITY: 19, CIRCUIT_DIGEST: 24}
        state = 0xB11D1ED6
        for circuit in (CIRCUIT_RATE, CIRCUIT_INACTIVE, CIRCUIT_CAPACITY, CIRCUIT_DIGEST):
            for _ in range(1024):
                state = (1664525 * state + 1013904223) & 0xFFFFFFFF
                wire = state % widths[circuit]
                state = (1664525 * state + 1013904223) & 0xFFFFFFFF
                group = state & ((1 << logs[circuit]) - 1)
                requests.append((circuit, wire, group))
        request_words = array.array("I", (value for request in requests for value in request))
        call_first = array.array("I", source.call_first_permutations)
        call_blocks = array.array("I", source.call_blocks)
        permutation_calls = array.array("I", source.permutation_calls)
        permutation_blocks = array.array("I", source.permutation_blocks)
        results = array.array("I", [0]) * len(requests)
        result_device = runtime.alloc(len(results) * results.itemsize)
        devices = [
            _upload(runtime, source.input_patterns), _upload(runtime, source.output_patterns),
            _upload(runtime, permutation_calls), _upload(runtime, permutation_blocks),
            _upload(runtime, call_first), _upload(runtime, call_blocks),
            _upload(runtime, offsets), _upload(runtime, lengths),
            _upload(runtime, flat_messages), _upload(runtime, flat_digests),
            _upload(runtime, request_words), result_device,
        ]
        scalar_values = [len(requests), source.total_permutations, len(source.snapshot.messages)]
        arguments_values = [ctypes.c_uint64(value) for value in devices] + [ctypes.c_uint32(value) for value in scalar_values]
        arguments = (ctypes.c_void_p * len(arguments_values))(*(ctypes.cast(ctypes.byref(value), ctypes.c_void_p) for value in arguments_values))
        blocks = (len(requests) + 127) // 128
        ck(runtime.cuda.cuLaunchKernel(runtime.fn, blocks, 1, 1, 128, 1, 1, 0, None, arguments, None), "semantic_source_launch")
        ck(runtime.cuda.cuCtxSynchronize(), "semantic_source_sync")
        result_view = (ctypes.c_ubyte * (len(results) * results.itemsize)).from_buffer(results)
        ck(runtime.cuda.cuMemcpyDtoH_v2(ctypes.cast(result_view, ctypes.c_void_p), result_device, len(result_view)), "semantic_source_copy")
        expected = tuple(source_value(source, *request) for request in requests)
        if tuple(results) != expected:
            raise ValueError(f"gpu_source_mismatch:{tuple(results)}:{expected}")
        return len(requests)
    finally:
        runtime.close()


def gpu_layer_preflight(source):
    from cuda_fp16_tower_kat import Runtime, ck
    configured = os.environ.get("BL_NVRTC_BIN")
    nvrtc = Path(configured) if configured else Path(__file__).parent / "cuda_nvrtc" / "nvidia" / "cuda_nvrtc" / "bin"
    runtime = Runtime(nvrtc)
    checked = 0
    try:
        runtime.compile(DAG_KERNEL, b"semantic_dag_layer_base")
        for circuit, source_width, group_limit in (
            (CIRCUIT_RATE, 64, 1 << (23 if source.profile == 1 else 25)),
            (CIRCUIT_INACTIVE, 4096, 1 << 19),
            (CIRCUIT_CAPACITY, 4096, 1 << 19),
            (CIRCUIT_DIGEST, 4096, 1 << 24),
        ):
            groups = [0, group_limit - 1]
            state = 0x51A7E000 + circuit
            for _ in range(30):
                state = (1664525 * state + 1013904223) & 0xFFFFFFFF
                groups.append(state % group_limit)
            host_source = array.array("I", (
                source_value(source, circuit, wire, group)
                for group in groups for wire in range(source_width)
            ))
            row_hosts = [host_source]
            row_devices = [_upload(runtime, host_source)]
            for layer_index, topology in enumerate(circuit_topology(circuit)):
                left_source, right_source, left_width, right_width, gates, padded = topology
                left_slot = 0 if left_source == -1 else left_source + 1
                right_slot = 0 if right_source == -1 else right_source + 1
                left_indices = array.array("H", [gate[0] for gate in gates])
                right_indices = array.array("H", [gate[1] for gate in gates])
                kinds = array.array("B", [gate[2] for gate in gates])
                output = array.array("I", [0]) * (len(groups) * padded)
                output_device = runtime.alloc(len(output) * output.itemsize)
                values = [
                    ctypes.c_uint64(row_devices[left_slot]), ctypes.c_uint64(row_devices[right_slot]),
                    ctypes.c_uint64(_upload(runtime, left_indices)), ctypes.c_uint64(_upload(runtime, right_indices)),
                    ctypes.c_uint64(_upload(runtime, kinds)), ctypes.c_uint64(output_device),
                    ctypes.c_uint32(len(groups)), ctypes.c_uint32(left_width), ctypes.c_uint32(right_width),
                    ctypes.c_uint32(len(gates)), ctypes.c_uint32(padded),
                ]
                arguments = (ctypes.c_void_p * len(values))(*(ctypes.cast(ctypes.byref(value), ctypes.c_void_p) for value in values))
                count = len(output)
                ck(runtime.cuda.cuLaunchKernel(runtime.fn, (count + 127) // 128, 1, 1, 128, 1, 1, 0, None, arguments, None), "semantic_layer_launch")
                ck(runtime.cuda.cuCtxSynchronize(), "semantic_layer_sync")
                view = (ctypes.c_ubyte * (len(output) * output.itemsize)).from_buffer(output)
                ck(runtime.cuda.cuMemcpyDtoH_v2(ctypes.cast(view, ctypes.c_void_p), output_device, len(view)), "semantic_layer_copy")
                for local_group, group in enumerate(groups):
                    for wire in range(padded):
                        expected = layer_value(source, circuit, layer_index, wire, group)
                        actual = output[local_group * padded + wire]
                        if actual != expected:
                            raise ValueError(f"gpu_layer_mismatch:{circuit}:{layer_index}:{group}:{wire}:{actual}:{expected}")
                        checked += 1
                row_hosts.append(output)
                row_devices.append(output_device)
        return checked
    finally:
        runtime.close()


def preflight(boundary, snapshot, profile):
    source = read_source(boundary, snapshot, profile)
    print("status=verified")
    print(f"profile_code={source.profile}")
    print(f"calls={len(source.snapshot.messages)}")
    print(f"permutations={source.total_permutations}")
    print(f"shards={source.shards}")
    print(f"boundary_patterns={len(source.input_patterns) + len(source.output_patterns)}")
    print(f"semantic_port_commitment={source.snapshot.semantic_port.hex()}")
    print("gpu_authority=none")
    print("proofSuiteId=null")
    print("production_usable=false")
    print("activation=false")


def gpu_preflight(boundary, snapshot, profile):
    source = read_source(boundary, snapshot, profile)
    samples = gpu_source_preflight(source)
    print("status=verified")
    print(f"profile_code={source.profile}")
    print(f"gpu_source_samples={samples}")
    print("gpu_authority=none")
    print("proofSuiteId=null")
    print("production_usable=false")
    print("activation=false")


def relation_preflight(boundary, snapshot, profile):
    source = read_source(boundary, snapshot, profile)
    checks = cpu_relation_preflight(source)
    print("status=verified")
    print(f"profile_code={source.profile}")
    print(f"relation_samples={checks}")
    print("proofSuiteId=null")
    print("production_usable=false")
    print("activation=false")


def layer_preflight(boundary, snapshot, profile):
    source = read_source(boundary, snapshot, profile)
    checks = gpu_layer_preflight(source)
    print("status=verified")
    print(f"profile_code={source.profile}")
    print(f"gpu_layer_cells={checks}")
    print("gpu_authority=none")
    print("proofSuiteId=null")
    print("production_usable=false")
    print("activation=false")


def compile_preflight(boundary, snapshot, profile):
    engine = ProductionBridgeEngine(read_source(boundary, snapshot, profile))
    engine.close()
    print("status=verified")
    print("production_worker_cuda_module=compiled")
    print("gpu_authority=none")
    print("proofSuiteId=null")
    print("production_usable=false")
    print("activation=false")


def stream_kernel_kat(boundary, snapshot, profile):
    """Hand fixture: (2+3, 4+5) evaluated at group point 7 is 33."""
    from cuda_dag_shared_group_message_benchmark import reduce_partials
    engine = ProductionBridgeEngine(read_source(boundary, snapshot, profile))
    runtime = engine.runtime
    devices = []
    try:
        left = _upload(runtime, array.array("I", [2, 4])); devices.append(left)
        right = _upload(runtime, array.array("I", [3, 5])); devices.append(right)
        base_left = _upload(runtime, array.array("H", [0])); devices.append(base_left)
        base_right = _upload(runtime, array.array("H", [0])); devices.append(base_right)
        formulas = _upload(runtime, array.array("B", [6])); devices.append(formulas)
        one = _fp16_one(); point = (7,) + (0,) * 15; claim_value = (33,) + (0,) * 15
        claims = _upload(runtime, _fp16_words([claim_value, one, point])); devices.append(claims)
        prefixes = _upload(runtime, _fp16_words([one])); devices.append(prefixes)
        wire = runtime.alloc(64); devices.append(wire)
        engine._launch("semantic_wire_weights", 1, 128,
                       [ctypes.c_uint64(claims), ctypes.c_uint32(1), ctypes.c_uint32(1),
                        ctypes.c_uint32(0), ctypes.c_uint32(1), ctypes.c_uint64(wire)])
        zero_weight = runtime.alloc(64); delta_weight = runtime.alloc(64)
        devices.extend([zero_weight, delta_weight])
        engine._launch("semantic_group_weights", 1, 128,
                       [ctypes.c_uint64(claims), ctypes.c_uint64(prefixes), ctypes.c_uint32(1),
                        ctypes.c_uint32(1), ctypes.c_uint32(0), ctypes.c_uint32(1), ctypes.c_uint32(0),
                        ctypes.c_uint32(0), ctypes.c_uint32(1), ctypes.c_uint64(zero_weight), ctypes.c_uint64(delta_weight)])
        prefix_weight = _upload(runtime, _fp16_words([one])); devices.append(prefix_weight)
        accumulator = runtime.alloc(256); devices.append(accumulator)
        engine.ck(runtime.cuda.cuMemsetD8_v2(accumulator, 0, 256), "kat_accumulator_zero")
        for bit in (0, 1):
            engine._launch("semantic_accumulate_gate_inputs", 1, 128,
                           [ctypes.c_uint64(left), ctypes.c_uint64(right), ctypes.c_uint64(base_left),
                            ctypes.c_uint64(base_right), ctypes.c_uint64(prefix_weight), ctypes.c_uint64(accumulator),
                            ctypes.c_uint32(1), ctypes.c_uint32(1), ctypes.c_uint32(1), ctypes.c_uint32(1),
                            ctypes.c_uint32(1), ctypes.c_uint32(1), ctypes.c_uint32(0),
                            ctypes.c_uint32(bit), ctypes.c_uint32(bit)])
        partial = runtime.alloc(256); scratch = runtime.alloc(256); devices.extend([partial, scratch])
        engine._launch("semantic_accumulated_message", 1, 128,
                       [ctypes.c_uint64(accumulator), ctypes.c_uint64(formulas), ctypes.c_uint64(wire),
                        ctypes.c_uint64(zero_weight), ctypes.c_uint64(delta_weight), ctypes.c_uint64(partial),
                        ctypes.c_uint32(1), ctypes.c_uint32(1), ctypes.c_uint32(1)])
        result_d = reduce_partials(runtime, engine.f["reduce_cubic_partials"], partial, scratch, 1)
        engine.ck(runtime.cuda.cuCtxSynchronize(), "stream_kernel_kat_sync")
        words = array.array("I", [0]) * 64
        view = (ctypes.c_ubyte * 256).from_buffer(words)
        engine.ck(runtime.cuda.cuMemcpyDtoH_v2(ctypes.cast(view, ctypes.c_void_p), result_d, 256), "stream_kernel_kat_copy")
        actual = [tuple(words[16 * i:16 * (i + 1)]) for i in range(4)]
        expected = [((-30) % M31,) + (0,) * 15, (41,) + (0,) * 15,
                    (52,) + (0,) * 15, _fp16_zero()]
        if actual != expected:
            raise ValueError(f"stream_kernel_kat_mismatch:{actual}:{expected}")
        recurrence = _fp16_add(_fp16_add(actual[0], actual[0]),
                               _fp16_add(_fp16_add(actual[1], actual[2]), actual[3]))
        if recurrence != claim_value:
            raise ValueError(f"stream_kernel_recurrence:{recurrence}:{claim_value}")
    finally:
        for device in reversed(devices):
            if device in runtime.allocs: _free(runtime, device)
        engine.close()
    print("status=verified")
    print("hand_fixture=left(2,4)_right(3,5)_add_point7")
    print("cubic=-30,41,52,0")
    print("claim=33")
    print("proofSuiteId=null")
    print("production_usable=false")
    print("activation=false")


def retained_fold_kat(boundary, snapshot, profile):
    engine = ProductionBridgeEngine(read_source(boundary, snapshot, profile))
    runtime = engine.runtime
    devices = []
    try:
        records = (
            (2, 3, 4, 5), (7, 11, 13, 17),
            (19, 23, 29, 31), (37, 41, 43, 47),
        )
        encoded = _fp16_words([
            (value,) + (0,) * 15
            for record in records
            for value in record
        ])
        source = _upload(runtime, encoded)
        challenge = _upload(runtime, _fp16_words([((3,) + (0,) * 15)]))
        retained_copy = runtime.alloc(len(encoded) * 4)
        output = runtime.alloc(2 * 4 * 64)
        devices.extend((source, challenge, retained_copy, output))
        engine.ck(runtime.cuda.cuMemcpyDtoD_v2(
            retained_copy, source, len(encoded) * 4
        ), "retained_fold_kat_device_copy")
        engine._launch(
            "semantic_fold_accumulator", 1, 128,
            [ctypes.c_uint64(retained_copy), ctypes.c_uint64(challenge),
             ctypes.c_uint64(output), ctypes.c_uint32(2),
             ctypes.c_uint64(4), ctypes.c_uint64(2)],
        )
        engine.ck(runtime.cuda.cuCtxSynchronize(), "retained_fold_kat_sync")
        actual = engine._copy_fp16(output, 8)
        expected_base = (8, 9, 49, 47, 25, 29, 55, 59)
        expected = [(value,) + (0,) * 15 for value in expected_base]
        if actual != expected:
            raise ValueError(f"retained_fold_kat_mismatch:{actual}:{expected}")

        # This is the largest common retained input shape used by the worker:
        # 2^20 records x four Fp16 slots = 256 MiB, folded to 128 MiB.
        benchmark_records = 1 << 20
        benchmark_source = runtime.alloc(benchmark_records * 4 * 64)
        benchmark_output = runtime.alloc((benchmark_records // 2) * 4 * 64)
        devices.extend((benchmark_source, benchmark_output))
        engine.ck(runtime.cuda.cuMemsetD8_v2(
            benchmark_source, 0, benchmark_records * 4 * 64
        ), "retained_fold_benchmark_zero")
        started = time.perf_counter()
        engine._launch(
            "semantic_fold_accumulator",
            ((benchmark_records // 2) * 4 + 127) // 128,
            128,
            [ctypes.c_uint64(benchmark_source), ctypes.c_uint64(challenge),
             ctypes.c_uint64(benchmark_output), ctypes.c_uint32(1024),
             ctypes.c_uint64(benchmark_records),
             ctypes.c_uint64(benchmark_records // 2)],
        )
        engine.ck(runtime.cuda.cuCtxSynchronize(), "retained_fold_benchmark_sync")
        seconds = time.perf_counter() - started
        if seconds <= 0 or seconds > 10:
            raise ValueError(f"retained_fold_benchmark_slow:{seconds:.6f}")
    finally:
        for device in reversed(devices):
            if device in runtime.allocs:
                _free(runtime, device)
        engine.close()
    print("status=verified")
    print("hand_fixture=two_suffixes_two_wires_challenge_3")
    print("folded=8,9,49,47,25,29,55,59")
    print(f"benchmark_input_bytes={benchmark_records * 4 * 64}")
    print(f"benchmark_seconds={seconds:.6f}")
    print("proofSuiteId=null")
    print("production_usable=false")
    print("activation=false")


def _read_topology(stream):
    sources = _read_exact(stream, 2, "topology_sources")
    widths = struct.unpack(">HHHH", _read_exact(stream, 8, "topology_widths"))
    left_width, right_width, raw_width, padded = widths
    if not raw_width or not padded or raw_width > padded or (padded & (padded - 1)) != 0:
        raise ValueError("topology_widths")
    gates = []
    for _ in range(padded):
        left, right, kind = struct.unpack(">HHB", _read_exact(stream, 5, "topology_gate"))
        gates.append((left, right, kind))
    source = lambda value: -1 if value == 0 else value - 1
    return (source(sources[0]), source(sources[1]), left_width, right_width, tuple(gates), padded)


def _read_claim(stream):
    point_len = _read_exact(stream, 1, "claim_length")[0]
    value, coefficient = _read_fp16(stream), _read_fp16(stream)
    point = tuple(_read_fp16(stream) for _ in range(point_len))
    return value, coefficient, point


def serve(boundary, snapshot, profile):
    source = read_source(boundary, snapshot, profile)
    engine = ProductionBridgeEngine(source)
    reader, writer = sys.stdin.buffer, sys.stdout.buffer
    try:
        writer.write(READY); writer.flush()
        while True:
            command = _read_exact(reader, 8, "command")
            if command == OUTPUT:
                circuit, point_len = _read_exact(reader, 2, "output_header")
                point = tuple(_read_fp16(reader) for _ in range(point_len))
                value = engine.output_claim(circuit, point)
                writer.write(OUTPUT_OK); _write_fp16(writer, value); writer.flush()
            elif command == BEGIN:
                circuit, layer, claim_count = _read_exact(reader, 3, "begin_header")
                topology = _read_topology(reader)
                claims = tuple(_read_claim(reader) for _ in range(claim_count))
                engine.begin(circuit, layer, topology, claims)
                writer.write(BEGIN_OK); writer.flush()
            elif command == GROUP:
                round_index = _read_exact(reader, 1, "group_round")[0]
                values = engine.raw_group_round(round_index)
                writer.write(GROUP_OK)
                for value in values: _write_fp16(writer, value)
                writer.flush()
            elif command == CHALLENGE:
                round_index = _read_exact(reader, 1, "challenge_round")[0]
                challenge = _read_fp16(reader)
                engine.accept(round_index, challenge)
                writer.write(CHALLENGE_OK); writer.flush()
            elif command == FOLDED:
                left, right, same_sources = engine.folded_sources()
                writer.write(FOLDED_OK)
                for value in left: _write_fp16(writer, value)
                if not same_sources:
                    for value in right: _write_fp16(writer, value)
                writer.flush()
            elif command == FINISH:
                if engine.active is not None:
                    raise ValueError("finish_during_layer")
                writer.write(FINISHED); writer.flush()
                return
            else:
                raise ValueError(f"unknown_command:{command.hex()}")
    finally:
        engine.close()


def main(argv):
    if len(argv) == 5 and argv[1] == "--preflight":
        preflight(Path(argv[2]), Path(argv[3]), int(argv[4]))
        return
    if len(argv) == 5 and argv[1] == "--gpu-source-preflight":
        gpu_preflight(Path(argv[2]), Path(argv[3]), int(argv[4]))
        return
    if len(argv) == 5 and argv[1] == "--relation-preflight":
        relation_preflight(Path(argv[2]), Path(argv[3]), int(argv[4]))
        return
    if len(argv) == 5 and argv[1] == "--gpu-layer-preflight":
        layer_preflight(Path(argv[2]), Path(argv[3]), int(argv[4]))
        return
    if len(argv) == 5 and argv[1] == "--compile-preflight":
        compile_preflight(Path(argv[2]), Path(argv[3]), int(argv[4]))
        return
    if len(argv) == 5 and argv[1] == "--stream-kernel-kat":
        stream_kernel_kat(Path(argv[2]), Path(argv[3]), int(argv[4]))
        return
    if len(argv) == 5 and argv[1] == "--retained-fold-kat":
        retained_fold_kat(Path(argv[2]), Path(argv[3]), int(argv[4]))
        return
    if len(argv) != 4:
        raise SystemExit("usage: cuda_semantic_h4_bridge_gkr_worker.py [--preflight] BOUNDARY SNAPSHOT PROFILE")
    serve(Path(argv[1]), Path(argv[2]), int(argv[3]))


if __name__ == "__main__":
    main(sys.argv)
