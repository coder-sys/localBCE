"""Exact CUDA oracle for H4 booleanity rounds after component folding.

The process is an untrusted arithmetic accelerator. Rust retains transcript,
claim-transition, and terminal checks. This worker never emits proof authority.
"""

import array
import ctypes
import os
import struct
import sys
from pathlib import Path

from cuda_fp16_tower_kat import CUDA, Q, Runtime, add, ck, mul16, sub
from cuda_dag_packed_accumulator_benchmark import copy
from cuda_dag_shared_group_fold_benchmark import KERNEL as FOLD_KERNEL
from cuda_dag_shared_group_message_benchmark import MESSAGE_KERNEL
from cuda_hash_bus_b16_gkr_worker import read_boundary

FP16_BYTES = 64
COEFFICIENTS = 1 << 16
WORDS = 1 << 9
VALUES = COEFFICIENTS * WORDS
READY = b"BLH4CW01"
INIT = b"BLH4CI01"
INIT_OK = b"BLH4CK01"
RAW = b"BLH4CR01"
RAW_OK = b"BLH4CO01"
ACCEPT = b"BLH4CA01"
ACCEPT_OK = b"BLH4CY01"
FOLDED = b"BLH4CF01"
FOLDED_OK = b"BLH4CV01"
FINISH = b"BLH4CX01"
FINISHED = b"BLH4CZ01"

KERNEL = r"""
extern "C" __global__ void build_h4_lookup(
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

extern "C" __global__ void expand_equality(
    const unsigned int *input,
    unsigned int *output,
    const unsigned int *coordinate,
    unsigned int count
) {
    unsigned int index = blockIdx.x * blockDim.x + threadIdx.x;
    if (index >= count) return;
    F16 value = l16(input + 16ULL * index);
    F16 r = l16(coordinate);
    F16 one = z16(); one.a.a.a.a = 1U;
    st16(output + 16ULL * (2U * index), m16(value, s16(one, r)));
    st16(output + 16ULL * (2U * index + 1U), m16(value, r));
}

extern "C" __global__ void materialize_h4(
    const unsigned short *input,
    const unsigned short *output,
    const unsigned int *lookup,
    unsigned int *values,
    unsigned long long count
) {
    unsigned long long index =
        (unsigned long long)blockIdx.x * blockDim.x + threadIdx.x;
    if (index >= count) return;
    unsigned int coefficient = (unsigned int)(index & 65535ULL);
    unsigned int word = (unsigned int)(index >> 16);
    unsigned int wire = coefficient & 2047U;
    if (wire >= 1600U) { st16(values + 16ULL * index, z16()); return; }
    unsigned int group_low = coefficient >> 11;
    unsigned int group = ((word & 255U) << 5) | group_low;
    const unsigned short *plane = word < 256U ? input : output;
    unsigned int pattern = plane[wire * 8192U + group];
    st16(values + 16ULL * index, l16(lookup + 16ULL * pattern));
}

extern "C" __global__ void booleanity_message(
    const unsigned int *values,
    const unsigned int *weights,
    const unsigned int *equality_coordinate,
    const unsigned int *prefix,
    unsigned int *partial,
    unsigned long long pairs
) {
    unsigned long long first =
        ((unsigned long long)blockIdx.x * blockDim.x + threadIdx.x) * 8ULL;
    Cubic total = {z16(), z16(), z16(), z16()};
    F16 a = l16(equality_coordinate);
    F16 one = z16(); one.a.a.a.a = 1U;
    F16 equality0 = s16(one, a);
    F16 equality1 = s16(a, equality0);
    F16 scale_prefix = l16(prefix);
    for (unsigned int local = 0; local < 8U; ++local) {
        unsigned long long suffix = first + local;
        if (suffix >= pairs) break;
        F16 left = l16(values + 16ULL * (2ULL * suffix));
        F16 right = l16(values + 16ULL * (2ULL * suffix + 1ULL));
        F16 delta = s16(right, left);
        F16 product0 = m16(left, s16(left, one));
        F16 product1 = m16(delta, s16(a16(left, left), one));
        F16 product2 = m16(delta, delta);
        F16 scale = m16(scale_prefix, l16(weights + 16ULL * suffix));
        total.c0 = a16(total.c0, m16(scale, m16(equality0, product0)));
        total.c1 = a16(total.c1, m16(scale, a16(m16(equality0, product1), m16(equality1, product0))));
        total.c2 = a16(total.c2, m16(scale, a16(m16(equality0, product2), m16(equality1, product1))));
        total.c3 = a16(total.c3, m16(scale, m16(equality1, product2)));
    }
    reduce_cubic(total, partial, blockIdx.x);
}

extern "C" __global__ void fold_values(
    const unsigned int *input,
    unsigned int *output,
    const unsigned int *challenge,
    unsigned long long pairs
) {
    unsigned long long index =
        (unsigned long long)blockIdx.x * blockDim.x + threadIdx.x;
    if (index >= pairs) return;
    F16 left = l16(input + 16ULL * (2ULL * index));
    F16 right = l16(input + 16ULL * (2ULL * index + 1ULL));
    st16(output + 16ULL * index, a16(left, m16(l16(challenge), s16(right, left))));
}

extern "C" __global__ void collapse_equality(
    const unsigned int *input,
    unsigned int *output,
    unsigned int pairs
) {
    unsigned int index = blockIdx.x * blockDim.x + threadIdx.x;
    if (index >= pairs) return;
    st16(output + 16ULL * index,
         a16(l16(input + 32ULL * index), l16(input + 32ULL * index + 16ULL)));
}
"""


def exact(stream, count):
    value = stream.read(count)
    if len(value) != count:
        raise EOFError(f"short_read:{len(value)}:{count}")
    return value


def read_field(stream):
    value = struct.unpack(">16I", exact(stream, FP16_BYTES))
    if any(x >= Q for x in value):
        raise ValueError("noncanonical_field")
    return value


def write_field(stream, value):
    stream.write(struct.pack(">16I", *value))


def args(*values):
    return (ctypes.c_void_p * len(values))(
        *(ctypes.cast(ctypes.byref(value), ctypes.c_void_p) for value in values)
    )


def launch(runtime, function, count, arguments, label, threads=256):
    ck(runtime.cuda.cuLaunchKernel(function, (count + threads - 1) // threads, 1, 1,
        threads, 1, 1, 0, None, arguments, None), label)


def upload_field(runtime, pointer, value, label):
    words = array.array("I", value)
    copy(runtime, pointer, words, label)


def read_fields(runtime, pointer, count, label):
    words = array.array("I", [0]) * (count * 16)
    view = (ctypes.c_ubyte * (len(words) * 4)).from_buffer(words)
    ck(runtime.cuda.cuMemcpyDtoH_v2(ctypes.cast(view, ctypes.c_void_p), pointer,
        len(words) * 4), label)
    del view
    return [tuple(words[16*i:16*(i+1)]) for i in range(count)]


def self_test():
    """Four-value, hand-computed KAT; no boundary or proof machinery."""
    nvrtc = Path(os.environ.get("BL_NVRTC_BIN",
        Path(__file__).parent / "cuda_nvrtc" / "nvidia" / "cuda_nvrtc" / "bin"))
    runtime = Runtime(nvrtc)
    try:
        module = runtime.compile_module(CUDA + FOLD_KERNEL + MESSAGE_KERNEL + KERNEL)
        message = runtime.module_function(module, b"booleanity_message")
        zero = (0,) * 16
        one = (1,) + (0,) * 15
        values = array.array("I", [x for value in (zero, one, one, zero) for x in value])
        weights = array.array("I", [x for value in (one, zero) for x in value])
        values_d = runtime.alloc(len(values) * 4)
        weights_d = runtime.alloc(len(weights) * 4)
        equality_d = runtime.alloc(FP16_BYTES)
        prefix_d = runtime.alloc(FP16_BYTES)
        partial_d = runtime.alloc(4 * FP16_BYTES)
        copy(runtime, values_d, values, "kat_values")
        copy(runtime, weights_d, weights, "kat_weights")
        upload_field(runtime, equality_d, zero, "kat_equality")
        upload_field(runtime, prefix_d, one, "kat_prefix")
        launch(runtime, message, 1,
            args(ctypes.c_uint64(values_d), ctypes.c_uint64(weights_d),
                 ctypes.c_uint64(equality_d), ctypes.c_uint64(prefix_d),
                 ctypes.c_uint64(partial_d), ctypes.c_uint64(2)),
            "kat_message", threads=128)
        actual = read_fields(runtime, partial_d, 4, "kat_read")
        expected = [zero, sub(zero, one), add(one, one), sub(zero, one)]
        if actual != expected:
            raise SystemExit(f"h4_cuda_kat_mismatch expected={expected} actual={actual}")
        print("h4_cuda_kat=true")
        print("kat_values=4")
        print("proof_credit=false")
    finally:
        runtime.close()


def main():
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return
    if len(sys.argv) != 3:
        raise SystemExit("usage: cuda_h4_booleanity_worker.py BOUNDARY SHARD")
    boundary = Path(sys.argv[1]).resolve()
    shard = int(sys.argv[2])
    source, sink = sys.stdin.buffer, sys.stdout.buffer
    input_host, output_host, _, packed_groups = read_boundary(boundary, shard)
    if packed_groups <= 0 or packed_groups > 8192:
        raise ValueError("h4_boundary_group_shape")
    if packed_groups != 8192:
        def restore_zero_tail(compact):
            full = array.array("H", [0]) * (1600 * 8192)
            for wire in range(1600):
                compact_start = wire * packed_groups
                full_start = wire * 8192
                full[full_start : full_start + packed_groups] = compact[
                    compact_start : compact_start + packed_groups
                ]
            return full
        input_host = restore_zero_tail(input_host)
        output_host = restore_zero_tail(output_host)
        packed_groups = 8192
    nvrtc = Path(os.environ.get("BL_NVRTC_BIN",
        Path(__file__).parent / "cuda_nvrtc" / "nvidia" / "cuda_nvrtc" / "bin"))
    runtime = Runtime(nvrtc)
    try:
        module = runtime.compile_module(CUDA + FOLD_KERNEL + MESSAGE_KERNEL + KERNEL)
        fn = lambda name: runtime.module_function(module, name.encode())
        expand = fn("expand_equality")
        materialize = fn("materialize_h4")
        message = fn("booleanity_message")
        reduce = fn("reduce_cubic_partials")
        fold = fn("fold_values")
        collapse = fn("collapse_equality")
        build_lookup = fn("build_h4_lookup")
        input_d = runtime.alloc(len(input_host) * 2)
        output_d = runtime.alloc(len(output_host) * 2)
        copy(runtime, input_d, input_host, "h4_input")
        copy(runtime, output_d, output_host, "h4_output")
        sink.write(READY); sink.flush()
        if exact(source, 8) != INIT:
            raise ValueError("init_magic")
        equality = [read_field(source) for _ in range(29)]
        component = [read_field(source) for _ in range(4)]
        scalar_d = runtime.alloc(FP16_BYTES)
        lookup_d = runtime.alloc((1 << 16) * FP16_BYTES)
        node_d = runtime.alloc(16 * FP16_BYTES)
        # Component-fold lookup weights are built recursively on the host for
        # just 16 values; source-scale work remains on the GPU.
        one = (1,) + (0,) * 15
        nodes = [one]
        for challenge in component:
            left = sub(one, challenge)
            nodes = [mul16(value, left) for value in nodes] + [
                mul16(value, challenge) for value in nodes
            ]
        node_words = array.array("I", [x for value in nodes for x in value])
        copy(runtime, node_d, node_words, "h4_nodes")
        launch(runtime, build_lookup, 1 << 16,
            args(ctypes.c_uint64(node_d), ctypes.c_uint64(lookup_d)), "h4_lookup")
        value_a = runtime.alloc(VALUES * FP16_BYTES)
        value_b = runtime.alloc((VALUES // 2) * FP16_BYTES)
        launch(runtime, materialize, VALUES,
            args(ctypes.c_uint64(input_d), ctypes.c_uint64(output_d),
                 ctypes.c_uint64(lookup_d), ctypes.c_uint64(value_a),
                 ctypes.c_uint64(VALUES)), "h4_materialize")
        # Equality suffix for round 4 uses coordinates 5..28 (24 variables).
        weight_a = runtime.alloc((1 << 24) * FP16_BYTES)
        weight_b = runtime.alloc((1 << 23) * FP16_BYTES)
        upload_field(runtime, weight_a, one, "h4_weight_one")
        current_weight, scratch_weight, weight_count = weight_a, weight_b, 1
        # Expand in reverse so equality[5] remains table bit zero, matching
        # Rust's LSB-first multilinear convention and adjacent-pair folds.
        for coordinate in reversed(equality[5:]):
            upload_field(runtime, scalar_d, coordinate, "h4_equality_coordinate")
            destination = scratch_weight
            launch(runtime, expand, weight_count,
                args(ctypes.c_uint64(current_weight), ctypes.c_uint64(destination),
                     ctypes.c_uint64(scalar_d), ctypes.c_uint32(weight_count)),
                "h4_expand_equality")
            current_weight, scratch_weight = destination, current_weight
            weight_count *= 2
        active = VALUES
        current_value, scratch_value = value_a, value_b
        partial = runtime.alloc((1 << 14) * 4 * FP16_BYTES)
        reduction = runtime.alloc((1 << 11) * 4 * FP16_BYTES)
        sink.write(INIT_OK); sink.flush()
        while True:
            command = exact(source, 8)
            if command == RAW:
                round_index = exact(source, 1)[0]
                if round_index < 4 or round_index >= 29 or active != 1 << (29-round_index):
                    raise ValueError("raw_round")
                equality_coordinate = read_field(source)
                prefix = read_field(source)
                upload_field(runtime, scalar_d, equality_coordinate, "h4_eq")
                prefix_d = runtime.alloc(FP16_BYTES)
                upload_field(runtime, prefix_d, prefix, "h4_prefix")
                pairs = active // 2
                message_threads = (pairs + 7) // 8
                launch(runtime, message, message_threads,
                    args(ctypes.c_uint64(current_value), ctypes.c_uint64(current_weight),
                         ctypes.c_uint64(scalar_d), ctypes.c_uint64(prefix_d),
                         ctypes.c_uint64(partial), ctypes.c_uint64(pairs)),
                    "h4_message", threads=128)
                count = (message_threads + 127) // 128
                src, dst = partial, reduction
                while count > 1:
                    reduction_threads = (count + 7) // 8
                    launch(runtime, reduce, reduction_threads,
                        args(ctypes.c_uint64(src), ctypes.c_uint64(dst), ctypes.c_uint32(count)),
                        "h4_reduce", threads=128)
                    src, dst, count = dst, src, (reduction_threads + 127) // 128
                sink.write(RAW_OK)
                for value in read_fields(runtime, src, 4, "h4_message_read"):
                    write_field(sink, value)
            elif command == ACCEPT:
                round_index = exact(source, 1)[0]
                challenge = read_field(source)
                if round_index < 4 or round_index >= 29:
                    raise ValueError("accept_round")
                upload_field(runtime, scalar_d, challenge, "h4_challenge")
                pairs = active // 2
                launch(runtime, fold, pairs,
                    args(ctypes.c_uint64(current_value), ctypes.c_uint64(scratch_value),
                         ctypes.c_uint64(scalar_d), ctypes.c_uint64(pairs)), "h4_fold")
                current_value, scratch_value, active = scratch_value, current_value, pairs
                if round_index < 28:
                    next_weights = weight_count // 2
                    launch(runtime, collapse, next_weights,
                        args(ctypes.c_uint64(current_weight), ctypes.c_uint64(scratch_weight),
                             ctypes.c_uint32(next_weights)), "h4_collapse_equality")
                    current_weight, scratch_weight, weight_count = (
                        scratch_weight, current_weight, next_weights)
                sink.write(ACCEPT_OK)
            elif command == FOLDED:
                if active != 1:
                    raise ValueError("folded_state")
                sink.write(FOLDED_OK)
                write_field(sink, read_fields(runtime, current_value, 1, "h4_folded_read")[0])
            elif command == FINISH:
                sink.write(FINISHED); sink.flush(); break
            else:
                raise ValueError(f"command:{command!r}")
            sink.flush()
    finally:
        runtime.close()


if __name__ == "__main__":
    main()
