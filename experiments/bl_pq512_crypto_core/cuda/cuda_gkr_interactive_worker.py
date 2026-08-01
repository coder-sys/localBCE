"""Pinned interactive CUDA sparse-GKR worker for the bounded Rust host."""

import ctypes
import hashlib
import json
import os
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cuda_fp16_tower_kat import CUDA, Q, Runtime, ck
from cuda_sparse_all_rounds_kat import KERNELS, host_array, ptr
from cuda_sparse_round_kat import EXTRA

SOURCE = None
SINK = None
SESSIONS_REMAINING = 0
PERSISTENT_RUNTIME = None
PERSISTENT_FUNCTIONS = None
PERSISTENT_PRODUCT_TABLE = None
PERSISTENT_MASK_TABLE = None
PERSISTENT_SESSION_BUFFERS = []
TELEMETRY_RECORDS = []

PACKED_EXPANSION = r"""
extern "C" __global__ void initialize_one_factors(
    unsigned int *left,
    unsigned int *right,
    unsigned int term_count
) {
    unsigned int index = blockIdx.x * blockDim.x + threadIdx.x;
    if (index >= term_count) return;
    unsigned int offset = index * 16;
    left[offset] = 1;
    right[offset] = 1;
    #pragma unroll
    for (unsigned int coordinate = 1; coordinate < 16; ++coordinate) {
        left[offset + coordinate] = 0;
        right[offset + coordinate] = 0;
    }
}

extern "C" __global__ void add_fp16_in_place(
    unsigned int *value,
    const unsigned int *delta
) {
    if (blockIdx.x == 0 && threadIdx.x == 0) {
        st16(value, a16(l16(value), l16(delta)));
    }
}

extern "C" __global__ void derive_equality_table(
    const unsigned int *points,
    unsigned int point_variables,
    unsigned int coordinate_offset,
    unsigned int coordinate_count,
    unsigned int claim_count,
    unsigned int table_size,
    unsigned int *table
) {
    unsigned int index = blockIdx.x * blockDim.x + threadIdx.x;
    unsigned int count = claim_count * table_size;
    if (index >= count) return;
    unsigned int claim = index / table_size;
    unsigned int entry = index - claim * table_size;
    F16 value = o16();
    for (unsigned int coordinate = 0; coordinate < coordinate_count; ++coordinate) {
        F16 challenge = l16(
            points + 16ULL * (
                claim * point_variables + coordinate_offset + coordinate
            )
        );
        F16 factor = ((entry >> coordinate) & 1U)
            ? challenge
            : s16(o16(), challenge);
        value = m16(value, factor);
    }
    st16(table + 16ULL * index, value);
}

__device__ __forceinline__ F16 libra_left_slope(
    unsigned char formula,
    F16 opposite
) {
    F16 z=z16(),o=o16();
    if(formula==0) return s16(o,a16(opposite,opposite));
    if(formula==1) return opposite;
    if(formula==2) return o;
    if(formula==4) return n16(o);
    return z;
}

__device__ __forceinline__ F16 libra_right_slope(
    unsigned char formula,
    F16 opposite
) {
    F16 z=z16(),o=o16();
    if(formula==0) return s16(o,a16(opposite,opposite));
    if(formula==1) return opposite;
    if(formula==3) return o;
    if(formula==5) return n16(o);
    return z;
}

extern "C" __global__ void sparse_left_round_libra(
    const u32* weights,const u32* factors,const u32* input,const u32* folded,
    const u32* left,const u32* right,const unsigned char* formula,
    u32 round,u64 count,u32 sensitivity,u32 direct,u64* partial
){
    __shared__ u64 sums[96];
    if(threadIdx.x<96) sums[threadIdx.x]=0;
    __syncthreads();
    u64 i=(u64)blockIdx.x*blockDim.x+threadIdx.x;
    u32 values[96];
    #pragma unroll
    for(int c=0;c<96;c++) values[c]=0;
    if(i<count){
        u32 li=left[i],suffix=li>>(round+1U);
        F16 zero=l16(folded+16ULL*(2ULL*suffix));
        F16 one=l16(folded+16ULL*(2ULL*suffix+1ULL));
        F16 opposite=l16(input+16ULL*right[i]);
        F16 g0,gd;
        gate_line16(formula[i],zero,s16(one,zero),opposite,&g0,&gd);
        F16 weight=m16(l16(weights+16ULL*i),l16(factors+16ULL*i));
        F16 wg0=m16(weight,g0),wgd=m16(weight,gd),c0,c1,c2;
        if(((li>>round)&1U)==0U){
            c0=wg0; c1=s16(wgd,wg0); c2=n16(wgd);
        } else {
            c0=z16(); c1=wg0; c2=wgd;
        }
        st16(values,c0);st16(values+16,c1);st16(values+32,c2);
        if(sensitivity){
            F16 scale=m16(weight,libra_left_slope(formula[i],opposite));
            F16 s1=z16(),s2=z16(),s3=z16();
            if(((li>>round)&1U)==0U){
                s1=scale;s2=n16(a16(scale,scale));s3=scale;
            } else {
                s2=scale;s3=n16(scale);
            }
            st16(values+48,s1);st16(values+64,s2);st16(values+80,s3);
        }
    }
    unsigned lane=threadIdx.x&31U;
    #pragma unroll
    for(int c=0;c<96;c++){
        u64 value=values[c];
        #pragma unroll
        for(int offset=16;offset>0;offset>>=1)
            value+=__shfl_down_sync(0xffffffffU,value,offset);
        if(lane==0) atomicAdd(&sums[c],value);
    }
    __syncthreads();
    if(threadIdx.x<96){
        if(direct) atomicAdd(partial+threadIdx.x,sums[threadIdx.x]);
        else partial[(u64)blockIdx.x*96ULL+threadIdx.x]=sums[threadIdx.x];
    }
}

extern "C" __global__ void sparse_right_round_libra(
    const u32* weights,const u32* left_factors,const u32* right_factors,
    const u32* folded,const u32* terminal_left,const u32* left,const u32* right,
    const unsigned char* formula,u32 round,u64 count,u32 sensitivity,u32 direct,u64* partial
){
    __shared__ u64 sums[96];
    if(threadIdx.x<96) sums[threadIdx.x]=0;
    __syncthreads();
    u64 i=(u64)blockIdx.x*blockDim.x+threadIdx.x;
    u32 values[96];
    #pragma unroll
    for(int c=0;c<96;c++) values[c]=0;
    if(i<count){
        u32 ri=right[i],suffix=ri>>(round+1U);
        F16 zero=l16(folded+16ULL*(2ULL*suffix));
        F16 one=l16(folded+16ULL*(2ULL*suffix+1ULL));
        F16 fixed=l16(terminal_left),g0,gd;
        gate_line_right16(formula[i],zero,s16(one,zero),fixed,&g0,&gd);
        F16 weight=m16(
            m16(l16(weights+16ULL*i),l16(left_factors+16ULL*i)),
            l16(right_factors+16ULL*i)
        );
        F16 wg0=m16(weight,g0),wgd=m16(weight,gd),c0,c1,c2;
        if(((ri>>round)&1U)==0U){
            c0=wg0; c1=s16(wgd,wg0); c2=n16(wgd);
        } else {
            c0=z16(); c1=wg0; c2=wgd;
        }
        st16(values,c0);st16(values+16,c1);st16(values+32,c2);
        if(sensitivity){
            F16 scale=m16(weight,libra_right_slope(formula[i],fixed));
            F16 s1=z16(),s2=z16(),s3=z16();
            if(((ri>>round)&1U)==0U){
                s1=scale;s2=n16(a16(scale,scale));s3=scale;
            } else {
                s2=scale;s3=n16(scale);
            }
            st16(values+48,s1);st16(values+64,s2);st16(values+80,s3);
        }
    }
    unsigned lane=threadIdx.x&31U;
    #pragma unroll
    for(int c=0;c<96;c++){
        u64 value=values[c];
        #pragma unroll
        for(int offset=16;offset>0;offset>>=1)
            value+=__shfl_down_sync(0xffffffffU,value,offset);
        if(lane==0) atomicAdd(&sums[c],value);
    }
    __syncthreads();
    if(threadIdx.x<96){
        if(direct) atomicAdd(partial+threadIdx.x,sums[threadIdx.x]);
        else partial[(u64)blockIdx.x*96ULL+threadIdx.x]=sums[threadIdx.x];
    }
}

extern "C" __global__ void reduce_partial_libra(
    const u64* partial,u32 block_count,u32* output
){
    u32 coordinate=threadIdx.x;
    if(coordinate<96U){
        u64 sum=0;
        for(u32 block=0;block<block_count;block++)
            sum+=partial[(u64)block*96ULL+coordinate];
        output[coordinate]=(u32)(sum%2147483647ULL);
    }
}

extern "C" __global__ void packed_accumulate(
    const unsigned long long *packed,
    const unsigned int *weights,
    const unsigned int *left,
    const unsigned int *right,
    const unsigned char *formula,
    unsigned long long *product,
    unsigned long long *left_histogram,
    unsigned long long *right_histogram,
    unsigned int term_count,
    unsigned int input_width,
    unsigned int words_per_plane
) {
    unsigned int index = blockIdx.x * blockDim.x + threadIdx.x;
    if (index >= term_count) return;
    unsigned int group = left[index] / input_width;
    unsigned int first_instance = group * 8;
    unsigned int shift = first_instance & 63;
    unsigned int word = first_instance / 64;
    unsigned int left_wire = left[index] - group * input_width;
    unsigned int right_wire = right[index] - group * input_width;
    unsigned int left_byte =
        (unsigned int)((packed[left_wire * words_per_plane + word] >> shift) & 255ULL);
    unsigned int right_byte =
        (unsigned int)((packed[right_wire * words_per_plane + word] >> shift) & 255ULL);
    unsigned int kind = formula[index];
    bool is_and = kind == 1;
    if (kind == 2) right_byte = 0;
    else if (kind == 3) left_byte = 0;
    else if (kind == 4) right_byte = 255;
    else if (kind == 5) left_byte = 255;
    else if (kind == 6) { left_byte = 0; right_byte = 255; }
    else if (kind == 7) { left_byte = 0; right_byte = 0; }
    unsigned int bucket = left_byte * 256 + right_byte;
    for (unsigned int coordinate = 0; coordinate < 16; ++coordinate) {
        unsigned long long value = weights[index * 16 + coordinate];
        if (is_and) {
            atomicAdd(product + bucket * 16 + coordinate, value);
        } else {
            atomicAdd(
                product + bucket * 16 + coordinate,
                2ULL * (2147483647ULL - value)
            );
            atomicAdd(left_histogram + left_byte * 16 + coordinate, value);
            atomicAdd(right_histogram + right_byte * 16 + coordinate, value);
        }
    }
}

extern "C" __global__ void finalize_combined(
    const unsigned long long *accumulators,
    const unsigned int *product_table,
    const unsigned int *mask_table,
    unsigned int *output
) {
    unsigned int index = blockIdx.x * blockDim.x + threadIdx.x;
    if (index < 15 * 16) {
        unsigned int coefficient = index / 16;
        unsigned int coordinate = index - coefficient * 16;
        unsigned long long sum = 0;
        for (unsigned int bucket = 0; bucket < 65536; ++bucket) {
            unsigned long long weight =
                accumulators[bucket * 16 + coordinate] % 2147483647ULL;
            sum = (sum + weight * product_table[bucket * 15 + coefficient])
                % 2147483647ULL;
        }
        if (coefficient < 8) {
            const unsigned long long *left = accumulators + 65536 * 16;
            const unsigned long long *right = left + 256 * 16;
            for (unsigned int mask = 0; mask < 256; ++mask) {
                unsigned long long weight =
                    (left[mask * 16 + coordinate] +
                     right[mask * 16 + coordinate]) % 2147483647ULL;
                sum = (sum + weight * mask_table[mask * 8 + coefficient])
                    % 2147483647ULL;
            }
        }
        output[index] = (unsigned int)sum;
    }
    if (index == 0) {
        unsigned int nonzero = 0;
        for (unsigned int bucket = 0; bucket < 65536; ++bucket) {
            bool present = false;
            for (unsigned int coordinate = 0; coordinate < 16; ++coordinate)
                present |= accumulators[bucket * 16 + coordinate] != 0;
            nonzero += present;
        }
        output[15 * 16] = nonzero;
    }
}

extern "C" __global__ void expand_packed_inputs(
    const unsigned long long *packed,
    const unsigned int *node_weights,
    unsigned int *output,
    unsigned int input_width,
    unsigned int group_count,
    unsigned int words_per_plane
) {
    unsigned int index = blockIdx.x * blockDim.x + threadIdx.x;
    unsigned int input_count = input_width * group_count;
    if (index >= input_count) return;
    unsigned int group = index / input_width;
    unsigned int wire = index - group * input_width;
    unsigned int first_instance = group * 8;
    for (unsigned int coordinate = 0; coordinate < 16; ++coordinate) {
        unsigned long long sum = 0;
        for (unsigned int shard = 0; shard < 8; ++shard) {
            unsigned int instance = first_instance + shard;
            unsigned long long value =
                packed[wire * words_per_plane + instance / 64];
            if ((value >> (instance & 63)) & 1ULL) {
                sum += node_weights[shard * 16 + coordinate];
            }
        }
        output[index * 16 + coordinate] = (unsigned int)(sum % 2147483647ULL);
    }
}

extern "C" __global__ void derive_compact_terms(
    const unsigned int *coefficients,
    const unsigned int *wire_weights,
    const unsigned int *group_weights,
    const unsigned int *base_left,
    const unsigned int *base_right,
    const unsigned char *base_formula,
    unsigned int *weights,
    unsigned int *left,
    unsigned int *right,
    unsigned char *formula,
    unsigned int claim_count,
    unsigned int raw_width,
    unsigned int group_count,
    unsigned int input_width
) {
    unsigned int index = blockIdx.x * blockDim.x + threadIdx.x;
    unsigned int term_count = raw_width * group_count;
    if (index >= term_count) return;
    unsigned int group = index / raw_width;
    unsigned int wire = index - group * raw_width;
    F16 weight = z16();
    for (unsigned int claim = 0; claim < claim_count; ++claim) {
        F16 coefficient = l16(coefficients + claim * 16);
        F16 wire_weight =
            l16(wire_weights + (claim * raw_width + wire) * 16);
        F16 group_weight =
            l16(group_weights + (claim * group_count + group) * 16);
        weight = a16(weight, m16(coefficient, m16(wire_weight, group_weight)));
    }
    st16(weights + index * 16, weight);
    left[index] = group * input_width + base_left[wire];
    right[index] = group * input_width + base_right[wire];
    formula[index] = base_formula[wire];
}
"""


def compile_cached(runtime, source, cache_dir):
    source_digest = hashlib.sha3_512(source.encode()).hexdigest()
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_path = cache_dir / f"{source_digest}.ptx"
    if cache_path.exists():
        encoded = cache_path.read_bytes()
        if len(encoded) < 65:
            raise SystemExit("ptx_cache_truncated")
        expected = encoded[:64]
        ptx = encoded[64:]
        if hashlib.sha3_512(ptx).digest() != expected:
            raise SystemExit("ptx_cache_digest")
        runtime.ptx = ctypes.create_string_buffer(ptx)
        runtime.module = ctypes.c_void_p()
        ck(
            runtime.cuda.cuModuleLoadData(
                ctypes.byref(runtime.module),
                ctypes.cast(runtime.ptx, ctypes.c_void_p),
            ),
            "module",
        )
        runtime.fn = ctypes.c_void_p()
        ck(
            runtime.cuda.cuModuleGetFunction(
                ctypes.byref(runtime.fn), runtime.module, b"sparse_left_round"
            ),
            "function",
        )
        return
    runtime.compile(source, b"sparse_left_round")
    ptx = runtime.ptx.raw
    encoded = hashlib.sha3_512(ptx).digest() + ptx
    temporary = cache_path.with_suffix(f".tmp-{os.getpid()}")
    temporary.write_bytes(encoded)
    os.replace(temporary, cache_path)


def read_exact(stream, length):
    data = bytearray()
    while len(data) < length:
        chunk = stream.read(length - len(data))
        if not chunk:
            raise SystemExit("unexpected_eof")
        data.extend(chunk)
    return bytes(data)


def packed_tables():
    q = 2_147_483_647
    basis = []
    for point in range(8):
        polynomial = [1] + [0] * 7
        degree = 0
        denominator = 1
        for other in range(8):
            if other == point:
                continue
            root = other
            for coefficient in range(degree, -1, -1):
                polynomial[coefficient + 1] = (
                    polynomial[coefficient + 1] + polynomial[coefficient]
                ) % q
                polynomial[coefficient] = (
                    polynomial[coefficient] * (q - root)
                ) % q
            degree += 1
            denominator = denominator * (point - other) % q
        inverse = pow(denominator, q - 2, q)
        basis.append([(value * inverse) % q for value in polynomial])
    masks = []
    for mask in range(256):
        polynomial = [0] * 8
        for point in range(8):
            if (mask >> point) & 1:
                polynomial = [
                    (value + basis[point][coefficient]) % q
                    for coefficient, value in enumerate(polynomial)
                ]
        masks.append(polynomial)
    product = (ctypes.c_uint32 * (65_536 * 15))()
    for left in range(256):
        for right in range(256):
            offset = (left * 256 + right) * 15
            for i in range(8):
                for j in range(8):
                    product[offset + i + j] = (
                        product[offset + i + j] + masks[left][i] * masks[right][j]
                    ) % q
    mask = (ctypes.c_uint32 * (256 * 8))(
        *(value for polynomial in masks for value in polynomial)
    )
    return product, mask


def main():
    global SOURCE, SINK, SESSIONS_REMAINING, PERSISTENT_RUNTIME, PERSISTENT_FUNCTIONS
    global PERSISTENT_PRODUCT_TABLE, PERSISTENT_MASK_TABLE, PERSISTENT_SESSION_BUFFERS
    process_started = time.perf_counter()
    if SOURCE is None:
        if len(sys.argv) != 2:
            raise SystemExit("runtime_root_required")
        SOURCE = sys.stdin.buffer
        SINK = sys.stdout.buffer
        SINK.write(b"BLGKRP2\0")
        SINK.flush()
        SESSIONS_REMAINING = struct.unpack("<I", read_exact(SOURCE, 4))[0]
        if SESSIONS_REMAINING == 0 or SESSIONS_REMAINING > 216:
            raise SystemExit("session_count")
    source = SOURCE
    sink = SINK
    magic = read_exact(source, 8)
    if magic == b"BLGKRQ2\0":
        input_count, term_count, round_count = struct.unpack(
            "<III", read_exact(source, 12)
        )
        packed_instances = None
        packed_width = None
        compact_claims = None
    elif magic == b"BLGKRQ3\0":
        input_count, term_count, round_count, packed_instances, packed_width = (
            struct.unpack("<IIIII", read_exact(source, 20))
        )
        compact_claims = None
    elif magic in (b"BLGKRQ4\0", b"BLGKRQ5\0"):
        (
            input_count,
            term_count,
            round_count,
            packed_instances,
            packed_width,
            compact_raw_width,
            compact_claims,
        ) = struct.unpack("<IIIIIII", read_exact(source, 28))
        compact_wire_variables = None
    elif magic == b"BLGKRQ6\0":
        (
            input_count,
            term_count,
            round_count,
            packed_instances,
            packed_width,
            compact_raw_width,
            compact_claims,
            compact_wire_variables,
        ) = struct.unpack("<IIIIIIII", read_exact(source, 32))
    else:
        raise SystemExit("request_magic")
    point_compact = magic == b"BLGKRQ6\0"
    if (
        input_count == 0
        or input_count & (input_count - 1)
        or input_count > (1 << 19)
        or term_count == 0
        or term_count > 409_600
        or round_count != 2 * (input_count.bit_length() - 1)
        or round_count > 38
    ):
        raise SystemExit("request_shape")
    if packed_instances is None:
        input_words = (ctypes.c_uint32 * (input_count * 16)).from_buffer_copy(
            read_exact(source, input_count * 64)
        )
        packed_words = None
        node_weights = None
    else:
        if (
            packed_instances == 0
            or packed_instances & (packed_instances - 1)
            or packed_instances % 8
            or packed_width == 0
            or packed_width & (packed_width - 1)
            or input_count != packed_width * (packed_instances // 8)
        ):
            raise SystemExit("packed_shape")
        words_per_plane = (packed_instances + 63) // 64
        packed_count = packed_width * words_per_plane
        packed_words = (ctypes.c_uint64 * packed_count).from_buffer_copy(
            read_exact(source, packed_count * 8)
        )
        if compact_claims is None:
            node_weights = (ctypes.c_uint32 * (8 * 16)).from_buffer_copy(
                read_exact(source, 8 * 64)
            )
            if any(value >= Q for value in node_weights):
                raise SystemExit("packed_weight_noncanonical")
        else:
            node_weights = None
        input_words = None
    if compact_claims is None:
        weights = (ctypes.c_uint32 * (term_count * 16)).from_buffer_copy(
            read_exact(source, term_count * 64)
        )
        left = (ctypes.c_uint32 * term_count).from_buffer_copy(
            read_exact(source, term_count * 4)
        )
        right = (ctypes.c_uint32 * term_count).from_buffer_copy(
            read_exact(source, term_count * 4)
        )
        formula = (ctypes.c_ubyte * term_count).from_buffer_copy(
            read_exact(source, term_count)
        )
        if (
            any(index >= input_count for index in left)
            or any(index >= input_count for index in right)
            or any(gate > 7 for gate in formula)
        ):
            raise SystemExit("term_shape")
        compact_arrays = None
    else:
        group_count = packed_instances // 8
        if (
            compact_claims == 0
            or compact_claims > 2
            or compact_raw_width == 0
            or term_count != compact_raw_width * group_count
            or (
                point_compact
                and (
                    compact_wire_variables == 0
                    or compact_raw_width > (1 << compact_wire_variables)
                )
            )
        ):
            raise SystemExit("compact_shape")
        coefficients = (
            ctypes.c_uint32 * (compact_claims * 16)
        ).from_buffer_copy(read_exact(source, compact_claims * 64))
        if point_compact:
            point_variables = compact_wire_variables + group_count.bit_length() - 1
            compact_points = (
                ctypes.c_uint32 * (compact_claims * point_variables * 16)
            ).from_buffer_copy(
                read_exact(source, compact_claims * point_variables * 64)
            )
            compact_wire_weights = None
            compact_group_weights = None
        else:
            compact_points = None
            compact_wire_weights = (
                ctypes.c_uint32 * (compact_claims * compact_raw_width * 16)
            ).from_buffer_copy(
                read_exact(source, compact_claims * compact_raw_width * 64)
            )
            compact_group_weights = (
                ctypes.c_uint32 * (compact_claims * group_count * 16)
            ).from_buffer_copy(
                read_exact(source, compact_claims * group_count * 64)
            )
        base_left = (ctypes.c_uint32 * compact_raw_width).from_buffer_copy(
            read_exact(source, compact_raw_width * 4)
        )
        base_right = (ctypes.c_uint32 * compact_raw_width).from_buffer_copy(
            read_exact(source, compact_raw_width * 4)
        )
        base_formula = (ctypes.c_ubyte * compact_raw_width).from_buffer_copy(
            read_exact(source, compact_raw_width)
        )
        if (
            any(value >= Q for value in coefficients)
            or (
                point_compact
                and any(value >= Q for value in compact_points)
            )
            or (
                not point_compact
                and any(value >= Q for value in compact_wire_weights)
            )
            or (
                not point_compact
                and any(value >= Q for value in compact_group_weights)
            )
            or any(index >= packed_width for index in base_left)
            or any(index >= packed_width for index in base_right)
            or any(gate > 7 for gate in base_formula)
        ):
            raise SystemExit("compact_term_shape")
        weights = None
        left = None
        right = None
        formula = None
        compact_arrays = (
            [
                coefficients,
                compact_points,
                base_left,
                base_right,
                base_formula,
            ]
            if point_compact
            else [
                coefficients,
                compact_wire_weights,
                compact_group_weights,
                base_left,
                base_right,
                base_formula,
            ]
        )
    request_parsed = time.perf_counter()

    block = 256
    term_blocks = (term_count + block - 1) // block
    arrays = [] if compact_arrays is not None else [weights, left, right, formula]
    runtime = PERSISTENT_RUNTIME
    session_buffer_cursor = 0
    session_succeeded = False
    response_sent = False
    try:
        if runtime is None:
            runtime = Runtime(Path(sys.argv[1]))
            runtime.cuda.cuMemsetD8_v2.argtypes = [
                ctypes.c_uint64,
                ctypes.c_ubyte,
                ctypes.c_size_t,
            ]
            cache_root = Path(
                os.environ.get(
                    "BL_GKR_NVRTC_CACHE",
                    Path(__file__).parent / "nvrtc-cache",
                )
            )
            compile_cached(
                runtime,
                CUDA + EXTRA + KERNELS + PACKED_EXPANSION,
                cache_root,
            )
            functions = {}
            for name in (
                b"sparse_right_round",
                b"update_factors",
                b"fold_values",
                b"reduce_partial",
                b"expand_packed_inputs",
                b"derive_compact_terms",
                b"initialize_one_factors",
                b"packed_accumulate",
                b"finalize_combined",
                b"add_fp16_in_place",
                b"sparse_left_round_libra",
                b"sparse_right_round_libra",
                b"reduce_partial_libra",
                b"derive_equality_table",
            ):
                function = ctypes.c_void_p()
                ck(
                    runtime.cuda.cuModuleGetFunction(
                        ctypes.byref(function), runtime.module, name
                    ),
                    f"function_{name.decode()}",
                )
                functions[name] = function
            PERSISTENT_RUNTIME = runtime
            PERSISTENT_FUNCTIONS = functions
            product_table, mask_table = packed_tables()
            PERSISTENT_PRODUCT_TABLE = runtime.alloc(ctypes.sizeof(product_table))
            PERSISTENT_MASK_TABLE = runtime.alloc(ctypes.sizeof(mask_table))
            ck(
                runtime.cuda.cuMemcpyHtoD_v2(
                    PERSISTENT_PRODUCT_TABLE,
                    ctypes.cast(product_table, ctypes.c_void_p),
                    ctypes.sizeof(product_table),
                ),
                "product_table_copy",
            )
            ck(
                runtime.cuda.cuMemcpyHtoD_v2(
                    PERSISTENT_MASK_TABLE,
                    ctypes.cast(mask_table, ctypes.c_void_p),
                    ctypes.sizeof(mask_table),
                ),
                "mask_table_copy",
            )
        else:
            functions = PERSISTENT_FUNCTIONS
        runtime_ready = time.perf_counter()
        def session_alloc(size):
            nonlocal session_buffer_cursor
            slot = session_buffer_cursor
            session_buffer_cursor += 1
            if slot == len(PERSISTENT_SESSION_BUFFERS):
                pointer = runtime.alloc(size)
                PERSISTENT_SESSION_BUFFERS.append((pointer, size))
                return pointer
            pointer, capacity = PERSISTENT_SESSION_BUFFERS[slot]
            if capacity < size:
                ck(runtime.cuda.cuMemFree_v2(pointer), "session_buffer_grow_free")
                runtime.allocs.remove(pointer)
                pointer = runtime.alloc(size)
                PERSISTENT_SESSION_BUFFERS[slot] = (pointer, size)
            return pointer

        device = []
        for array in arrays:
            size = ctypes.sizeof(array)
            pointer = session_alloc(size)
            ck(
                runtime.cuda.cuMemcpyHtoD_v2(
                    pointer, ctypes.cast(array, ctypes.c_void_p), size
                ),
                "copy_input",
            )
            device.append(pointer)
        if compact_arrays is None:
            weight_d, left_d, right_d, formula_d = device
        else:
            compact_device = []
            for array in compact_arrays:
                size = ctypes.sizeof(array)
                pointer = session_alloc(size)
                ck(
                    runtime.cuda.cuMemcpyHtoD_v2(
                        pointer, ctypes.cast(array, ctypes.c_void_p), size
                    ),
                    "copy_compact_terms",
                )
                compact_device.append(pointer)
            if point_compact:
                (
                    coefficients_d,
                    compact_points_d,
                    base_left_d,
                    base_right_d,
                    base_formula_d,
                ) = compact_device
                wire_variables = compact_wire_variables
                group_variables = group_count.bit_length() - 1
                point_variables = wire_variables + group_variables
                compact_wire_weights_d = session_alloc(
                    compact_claims * compact_raw_width * 64
                )
                compact_group_weights_d = session_alloc(
                    compact_claims * group_count * 64
                )
                point_value = ctypes.c_uint64(compact_points_d)
                point_variables_value = ctypes.c_uint32(point_variables)
                claim_count_value = ctypes.c_uint32(compact_claims)
                wire_offset_value = ctypes.c_uint32(0)
                wire_variables_value = ctypes.c_uint32(wire_variables)
                wire_table_size_value = ctypes.c_uint32(compact_raw_width)
                wire_table_value = ctypes.c_uint64(compact_wire_weights_d)
                wire_parameters = (ctypes.c_void_p * 7)(
                    ptr(point_value),
                    ptr(point_variables_value),
                    ptr(wire_offset_value),
                    ptr(wire_variables_value),
                    ptr(claim_count_value),
                    ptr(wire_table_size_value),
                    ptr(wire_table_value),
                )
                wire_entries = compact_claims * compact_raw_width
                ck(
                    runtime.cuda.cuLaunchKernel(
                        functions[b"derive_equality_table"],
                        (wire_entries + block - 1) // block,
                        1,
                        1,
                        block,
                        1,
                        1,
                        0,
                        None,
                        wire_parameters,
                        None,
                    ),
                    "derive_wire_equality",
                )
                group_offset_value = ctypes.c_uint32(wire_variables)
                group_variables_value = ctypes.c_uint32(group_variables)
                group_table_size_value = ctypes.c_uint32(group_count)
                group_table_value = ctypes.c_uint64(compact_group_weights_d)
                group_parameters = (ctypes.c_void_p * 7)(
                    ptr(point_value),
                    ptr(point_variables_value),
                    ptr(group_offset_value),
                    ptr(group_variables_value),
                    ptr(claim_count_value),
                    ptr(group_table_size_value),
                    ptr(group_table_value),
                )
                group_entries = compact_claims * group_count
                ck(
                    runtime.cuda.cuLaunchKernel(
                        functions[b"derive_equality_table"],
                        (group_entries + block - 1) // block,
                        1,
                        1,
                        block,
                        1,
                        1,
                        0,
                        None,
                        group_parameters,
                        None,
                    ),
                    "derive_group_equality",
                )
            else:
                (
                    coefficients_d,
                    compact_wire_weights_d,
                    compact_group_weights_d,
                    base_left_d,
                    base_right_d,
                    base_formula_d,
                ) = compact_device
            weight_d = session_alloc(term_count * 64)
            left_d = session_alloc(term_count * 4)
            right_d = session_alloc(term_count * 4)
            formula_d = session_alloc(term_count)
            compact_values = [
                ctypes.c_uint64(coefficients_d),
                ctypes.c_uint64(compact_wire_weights_d),
                ctypes.c_uint64(compact_group_weights_d),
                ctypes.c_uint64(base_left_d),
                ctypes.c_uint64(base_right_d),
                ctypes.c_uint64(base_formula_d),
                ctypes.c_uint64(weight_d),
                ctypes.c_uint64(left_d),
                ctypes.c_uint64(right_d),
                ctypes.c_uint64(formula_d),
            ]
            claim_count_value = ctypes.c_uint32(compact_claims)
            raw_width_value = ctypes.c_uint32(compact_raw_width)
            group_count_value = ctypes.c_uint32(packed_instances // 8)
            compact_input_width_value = ctypes.c_uint32(packed_width)
            compact_parameters = (ctypes.c_void_p * 14)(
                *(ptr(value) for value in compact_values),
                ptr(claim_count_value),
                ptr(raw_width_value),
                ptr(group_count_value),
                ptr(compact_input_width_value),
            )
            ck(
                runtime.cuda.cuLaunchKernel(
                    functions[b"derive_compact_terms"],
                    term_blocks,
                    1,
                    1,
                    block,
                    1,
                    1,
                    0,
                    None,
                    compact_parameters,
                    None,
                ),
                "derive_compact_terms",
            )
            ck(runtime.cuda.cuCtxSynchronize(), "derive_compact_sync")
        if input_words is not None:
            input_size = ctypes.sizeof(input_words)
            input_d = session_alloc(input_size)
            ck(
                runtime.cuda.cuMemcpyHtoD_v2(
                    input_d, ctypes.cast(input_words, ctypes.c_void_p), input_size
                ),
                "copy_expanded_input",
            )
        else:
            packed_size = ctypes.sizeof(packed_words)
            packed_d = session_alloc(packed_size)
            ck(
                runtime.cuda.cuMemcpyHtoD_v2(
                    packed_d, ctypes.cast(packed_words, ctypes.c_void_p), packed_size
                ),
                "copy_packed_input",
            )
            if compact_arrays is not None:
                accumulator_coordinates = (65_536 + 256 + 256) * 16
                accumulator_u64 = session_alloc(accumulator_coordinates * 8)
                runtime.cuda.cuMemsetD8_v2.argtypes = [
                    ctypes.c_uint64,
                    ctypes.c_ubyte,
                    ctypes.c_size_t,
                ]
                ck(
                    runtime.cuda.cuMemsetD8_v2(
                        accumulator_u64, 0, accumulator_coordinates * 8
                    ),
                    "accumulator_zero",
                )
                product_d = accumulator_u64
                left_histogram_d = accumulator_u64 + 65_536 * 16 * 8
                right_histogram_d = left_histogram_d + 256 * 16 * 8
                packed_accumulator_values = [
                    ctypes.c_uint64(packed_d),
                    ctypes.c_uint64(weight_d),
                    ctypes.c_uint64(left_d),
                    ctypes.c_uint64(right_d),
                    ctypes.c_uint64(formula_d),
                    ctypes.c_uint64(product_d),
                    ctypes.c_uint64(left_histogram_d),
                    ctypes.c_uint64(right_histogram_d),
                ]
                term_count_value = ctypes.c_uint32(term_count)
                compact_input_width_value = ctypes.c_uint32(packed_width)
                words_per_plane_value = ctypes.c_uint32(
                    (packed_instances + 63) // 64
                )
                packed_accumulator_parameters = (ctypes.c_void_p * 11)(
                    *(ptr(value) for value in packed_accumulator_values),
                    ptr(term_count_value),
                    ptr(compact_input_width_value),
                    ptr(words_per_plane_value),
                )
                ck(
                    runtime.cuda.cuLaunchKernel(
                        functions[b"packed_accumulate"],
                        term_blocks,
                        1,
                        1,
                        block,
                        1,
                        1,
                        0,
                        None,
                        packed_accumulator_parameters,
                        None,
                    ),
                    "packed_accumulator_launch",
                )
                canonical_d = session_alloc((15 * 16 + 1) * 4)
                accumulator_input_value = ctypes.c_uint64(accumulator_u64)
                product_table_value = ctypes.c_uint64(PERSISTENT_PRODUCT_TABLE)
                mask_table_value = ctypes.c_uint64(PERSISTENT_MASK_TABLE)
                accumulator_output_value = ctypes.c_uint64(canonical_d)
                canonical_parameters = (ctypes.c_void_p * 4)(
                    ptr(accumulator_input_value),
                    ptr(product_table_value),
                    ptr(mask_table_value),
                    ptr(accumulator_output_value),
                )
                ck(
                    runtime.cuda.cuLaunchKernel(
                        functions[b"finalize_combined"],
                        1,
                        1,
                        1,
                        block,
                        1,
                        1,
                        0,
                        None,
                        canonical_parameters,
                        None,
                    ),
                    "accumulator_canonical_launch",
                )
                ck(runtime.cuda.cuCtxSynchronize(), "accumulator_sync")
                canonical_host = (ctypes.c_uint32 * (15 * 16 + 1))()
                ck(
                    runtime.cuda.cuMemcpyDtoH_v2(
                        ctypes.cast(canonical_host, ctypes.c_void_p),
                        canonical_d,
                        (15 * 16 + 1) * 4,
                    ),
                    "accumulator_copy",
                )
                sink.write(b"BLGKRW2\0")
                sink.write(bytes(canonical_host))
                sink.flush()
                response_sent = True
                node_weights = (ctypes.c_uint32 * (8 * 16)).from_buffer_copy(
                    read_exact(source, 8 * 64)
                )
                if any(value >= Q for value in node_weights):
                    raise SystemExit("packed_weight_noncanonical")
            node_weight_size = ctypes.sizeof(node_weights)
            node_weights_d = session_alloc(node_weight_size)
            ck(
                runtime.cuda.cuMemcpyHtoD_v2(
                    node_weights_d,
                    ctypes.cast(node_weights, ctypes.c_void_p),
                    node_weight_size,
                ),
                "copy_node_weights",
            )
            input_d = session_alloc(input_count * 64)
            packed_value = ctypes.c_uint64(packed_d)
            node_weights_value = ctypes.c_uint64(node_weights_d)
            input_value = ctypes.c_uint64(input_d)
            packed_width_value = ctypes.c_uint32(packed_width)
            group_count_value = ctypes.c_uint32(packed_instances // 8)
            words_per_plane_value = ctypes.c_uint32(
                (packed_instances + 63) // 64
            )
            expansion_parameters = (ctypes.c_void_p * 6)(
                ptr(packed_value),
                ptr(node_weights_value),
                ptr(input_value),
                ptr(packed_width_value),
                ptr(group_count_value),
                ptr(words_per_plane_value),
            )
            ck(
                runtime.cuda.cuLaunchKernel(
                    functions[b"expand_packed_inputs"],
                    (input_count + block - 1) // block,
                    1,
                    1,
                    block,
                    1,
                    1,
                    0,
                    None,
                    expansion_parameters,
                    None,
                ),
                "expand_packed_inputs",
            )
            ck(runtime.cuda.cuCtxSynchronize(), "expand_sync")
        challenge_d = session_alloc(64)
        factor_bytes = term_count * 64
        left_factors = session_alloc(factor_bytes)
        right_factors = session_alloc(factor_bytes)
        left_factors_value = ctypes.c_uint64(left_factors)
        right_factors_value = ctypes.c_uint64(right_factors)
        term_count_u32 = ctypes.c_uint32(term_count)
        factor_init_parameters = (ctypes.c_void_p * 3)(
            ptr(left_factors_value),
            ptr(right_factors_value),
            ptr(term_count_u32),
        )
        ck(
            runtime.cuda.cuLaunchKernel(
                functions[b"initialize_one_factors"],
                term_blocks,
                1,
                1,
                block,
                1,
                1,
                0,
                None,
                factor_init_parameters,
                None,
            ),
            "initialize_one_factors_launch",
        )
        fold_bytes = input_count * 64
        fold_a = session_alloc(fold_bytes)
        fold_b = session_alloc(fold_bytes)
        terminal_left_store = session_alloc(64)
        libra_compact = magic in (b"BLGKRQ5\0", b"BLGKRQ6\0")
        direct_reduction = point_compact
        partial_coordinates = 96 if libra_compact else 48
        partial_bytes = (
            partial_coordinates * 8
            if direct_reduction
            else term_blocks * partial_coordinates * 8
        )
        partial = session_alloc(partial_bytes)
        reduced = session_alloc(partial_coordinates * 4)
        host_reduced = (ctypes.c_uint32 * partial_coordinates)()
        host_direct = (ctypes.c_uint64 * partial_coordinates)()
        count_value = ctypes.c_uint64(term_count)
        partial_value = ctypes.c_uint64(partial)
        reduced_value = ctypes.c_uint64(reduced)
        block_count_value = ctypes.c_uint32(term_blocks)

        device_ready = time.perf_counter()
        if not response_sent:
            sink.write(b"BLGKRW2\0")
            sink.flush()
        current = input_d
        current_count = input_count
        terminal_left_d = None
        terminal_left_host = None
        input_variables = input_count.bit_length() - 1
        for global_round in range(round_count):
            phase_right = global_round >= input_variables
            local_round = global_round % input_variables
            round_value = ctypes.c_uint32(local_round)
            sensitivity_value = ctypes.c_uint32(
                libra_compact and local_round + 1 == input_variables
            )
            direct_value = ctypes.c_uint32(direct_reduction)
            current_value = ctypes.c_uint64(current)
            if phase_right:
                parameter_values = [
                    ctypes.c_uint64(weight_d),
                    ctypes.c_uint64(left_factors),
                    ctypes.c_uint64(right_factors),
                    current_value,
                    ctypes.c_uint64(terminal_left_d),
                    ctypes.c_uint64(left_d),
                    ctypes.c_uint64(right_d),
                    ctypes.c_uint64(formula_d),
                ]
                if libra_compact:
                    parameters = (ctypes.c_void_p * 13)(
                        *(ptr(value) for value in parameter_values),
                        ptr(round_value),
                        ptr(count_value),
                        ptr(sensitivity_value),
                        ptr(direct_value),
                        ptr(partial_value),
                    )
                    round_function = functions[b"sparse_right_round_libra"]
                else:
                    parameters = (ctypes.c_void_p * 11)(
                        *(ptr(value) for value in parameter_values),
                        ptr(round_value),
                        ptr(count_value),
                        ptr(partial_value),
                    )
                    round_function = functions[b"sparse_right_round"]
                labels_d, factors_d = right_d, right_factors
            else:
                parameter_values = [
                    ctypes.c_uint64(weight_d),
                    ctypes.c_uint64(left_factors),
                    ctypes.c_uint64(input_d),
                    current_value,
                    ctypes.c_uint64(left_d),
                    ctypes.c_uint64(right_d),
                    ctypes.c_uint64(formula_d),
                ]
                if libra_compact:
                    parameters = (ctypes.c_void_p * 12)(
                        *(ptr(value) for value in parameter_values),
                        ptr(round_value),
                        ptr(count_value),
                        ptr(sensitivity_value),
                        ptr(direct_value),
                        ptr(partial_value),
                    )
                    round_function = functions[b"sparse_left_round_libra"]
                else:
                    parameters = (ctypes.c_void_p * 10)(
                        *(ptr(value) for value in parameter_values),
                        ptr(round_value),
                        ptr(count_value),
                        ptr(partial_value),
                    )
                    round_function = runtime.fn
                labels_d, factors_d = left_d, left_factors
            if direct_reduction:
                ck(
                    runtime.cuda.cuMemsetD8_v2(
                        partial, 0, partial_coordinates * 8
                    ),
                    "direct_partial_zero",
                )
            ck(
                runtime.cuda.cuLaunchKernel(
                    round_function,
                    term_blocks,
                    1,
                    1,
                    block,
                    1,
                    1,
                    0,
                    None,
                    parameters,
                    None,
                ),
                "round_launch",
            )
            if direct_reduction:
                ck(runtime.cuda.cuCtxSynchronize(), "direct_round_sync")
                ck(
                    runtime.cuda.cuMemcpyDtoH_v2(
                        ctypes.cast(host_direct, ctypes.c_void_p),
                        partial,
                        partial_coordinates * 8,
                    ),
                    "copy_direct",
                )
                message = tuple(value % Q for value in host_direct)
            else:
                reduction_parameters = (ctypes.c_void_p * 3)(
                    ptr(partial_value),
                    ptr(block_count_value),
                    ptr(reduced_value),
                )
                reduction_function = (
                    functions[b"reduce_partial_libra"]
                    if libra_compact
                    else functions[b"reduce_partial"]
                )
                ck(
                    runtime.cuda.cuLaunchKernel(
                        reduction_function,
                        1,
                        1,
                        1,
                        partial_coordinates,
                        1,
                        1,
                        0,
                        None,
                        reduction_parameters,
                        None,
                    ),
                    "reduction_launch",
                )
                ck(runtime.cuda.cuCtxSynchronize(), "round_sync")
                ck(
                    runtime.cuda.cuMemcpyDtoH_v2(
                        ctypes.cast(host_reduced, ctypes.c_void_p),
                        reduced,
                        partial_coordinates * 4,
                    ),
                    "copy_reduced",
                )
                message = tuple(host_reduced)
            sink.write(struct.pack(f"<{partial_coordinates}I", *message))
            sink.flush()

            encoded_challenge = read_exact(source, 64)
            challenge_host = (ctypes.c_uint32 * 16).from_buffer_copy(encoded_challenge)
            if any(value >= Q for value in challenge_host):
                raise SystemExit("challenge_noncanonical")
            ck(
                runtime.cuda.cuMemcpyHtoD_v2(
                    challenge_d,
                    ctypes.cast(challenge_host, ctypes.c_void_p),
                    64,
                ),
                "challenge_copy",
            )
            challenge_value = ctypes.c_uint64(challenge_d)
            factors_value = ctypes.c_uint64(factors_d)
            labels_value = ctypes.c_uint64(labels_d)
            bit_value = ctypes.c_uint32(local_round)
            update_parameters = (ctypes.c_void_p * 5)(
                ptr(factors_value),
                ptr(labels_value),
                ptr(challenge_value),
                ptr(bit_value),
                ptr(count_value),
            )
            ck(
                runtime.cuda.cuLaunchKernel(
                    functions[b"update_factors"],
                    term_blocks,
                    1,
                    1,
                    block,
                    1,
                    1,
                    0,
                    None,
                    update_parameters,
                    None,
                ),
                "factor_launch",
            )
            next_count = current_count // 2
            next_buffer = fold_a if local_round & 1 == 0 else fold_b
            input_value = ctypes.c_uint64(current)
            output_value = ctypes.c_uint64(next_buffer)
            output_count_value = ctypes.c_uint64(next_count)
            fold_parameters = (ctypes.c_void_p * 4)(
                ptr(input_value),
                ptr(output_value),
                ptr(challenge_value),
                ptr(output_count_value),
            )
            ck(
                runtime.cuda.cuLaunchKernel(
                    functions[b"fold_values"],
                    (next_count + block - 1) // block,
                    1,
                    1,
                    block,
                    1,
                    1,
                    0,
                    None,
                    fold_parameters,
                    None,
                ),
                "fold_launch",
            )
            ck(runtime.cuda.cuCtxSynchronize(), "update_sync")
            current, current_count = next_buffer, next_count
            if not phase_right and local_round + 1 == input_variables:
                if libra_compact:
                    terminal_delta = read_exact(source, 64)
                    terminal_delta_host = (ctypes.c_uint32 * 16).from_buffer_copy(
                        terminal_delta
                    )
                    if any(value >= Q for value in terminal_delta_host):
                        raise SystemExit("terminal_delta_noncanonical")
                    ck(
                        runtime.cuda.cuMemcpyHtoD_v2(
                            challenge_d,
                            ctypes.cast(terminal_delta_host, ctypes.c_void_p),
                            64,
                        ),
                        "terminal_delta_copy",
                    )
                    current_value = ctypes.c_uint64(current)
                    delta_value = ctypes.c_uint64(challenge_d)
                    add_parameters = (ctypes.c_void_p * 2)(
                        ptr(current_value),
                        ptr(delta_value),
                    )
                    ck(
                        runtime.cuda.cuLaunchKernel(
                            functions[b"add_fp16_in_place"],
                            1,
                            1,
                            1,
                            1,
                            1,
                            1,
                            0,
                            None,
                            add_parameters,
                            None,
                        ),
                        "terminal_delta_launch",
                    )
                    ck(runtime.cuda.cuCtxSynchronize(), "terminal_delta_sync")
                terminal_left_host = (ctypes.c_uint32 * 16)()
                ck(
                    runtime.cuda.cuMemcpyDtoH_v2(
                        ctypes.cast(terminal_left_host, ctypes.c_void_p),
                        current,
                        64,
                    ),
                    "terminal_left_copy",
                )
                ck(
                    runtime.cuda.cuMemcpyHtoD_v2(
                        terminal_left_store,
                        ctypes.cast(terminal_left_host, ctypes.c_void_p),
                        64,
                    ),
                    "terminal_left_store",
                )
                terminal_left_d = terminal_left_store
                current, current_count = input_d, input_count
        terminal_right_host = (ctypes.c_uint32 * 16)()
        ck(
            runtime.cuda.cuMemcpyDtoH_v2(
                ctypes.cast(terminal_right_host, ctypes.c_void_p), current, 64
            ),
            "terminal_right_copy",
        )
        sink.write(bytes(terminal_left_host))
        sink.write(bytes(terminal_right_host))
        sink.flush()
        session_succeeded = True
        completed = time.perf_counter()
        telemetry_path = os.environ.get("BL_GKR_WORKER_TELEMETRY")
        if telemetry_path:
            TELEMETRY_RECORDS.append(
                {
                    "request_parse_seconds": request_parsed - process_started,
                    "runtime_ready_seconds": runtime_ready - request_parsed,
                    "device_setup_seconds": device_ready - runtime_ready,
                    "rounds_seconds": completed - device_ready,
                    "total_seconds": completed - process_started,
                    "runtime_reused": len(TELEMETRY_RECORDS) > 0,
                }
            )
            Path(telemetry_path).write_text(
                json.dumps(TELEMETRY_RECORDS, sort_keys=True),
                encoding="utf-8",
            )
    finally:
        if session_succeeded:
            SESSIONS_REMAINING -= 1
            if SESSIONS_REMAINING == 0:
                runtime.close()
                PERSISTENT_RUNTIME = None
                PERSISTENT_FUNCTIONS = None
                PERSISTENT_SESSION_BUFFERS = []
        elif runtime is not None and hasattr(runtime, "module"):
            runtime.close()
            PERSISTENT_RUNTIME = None
            PERSISTENT_FUNCTIONS = None
            PERSISTENT_SESSION_BUFFERS = []
            SESSIONS_REMAINING = 0
if __name__ == "__main__":
    while SOURCE is None or SESSIONS_REMAINING:
        main()
