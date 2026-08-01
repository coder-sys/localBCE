"""Bounded production-geometry CUDA worker for the selected MLPCS fold path."""

import ctypes
import msvcrt
import os
import struct
import sys
from array import array
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cuda_fp16_tower_kat import CUDA, Runtime, ck, mul2
from cuda_sparse_round_kat import EXTRA

COUNT = 1 << 25
VALUE_BYTES = COUNT * 64
AUXILIARY_COUNT = 1 << 21
AUXILIARY_BYTES = AUXILIARY_COUNT * 64
ROOT25 = (1_905_033_081, 454_651_505)
READY = b"BLMLGPU1"
STREAM = b"S"
FOLD = b"F"
RESET = b"R"
FINISH = b"X"

KERNELS = r"""
__device__ __forceinline__ F4 m4f2(F4 x,F2 y){return {m2(x.a,y),m2(x.b,y)};}
__device__ __forceinline__ F8 m8f2(F8 x,F2 y){return {m4f2(x.a,y),m4f2(x.b,y)};}
__device__ __forceinline__ F16 m16f2(F16 x,F2 y){return {m8f2(x.a,y),m8f2(x.b,y)};}

extern "C" __global__ void expand_root_powers(F2 *powers,u64 step,F2 factor){
    u64 i=(u64)blockIdx.x*blockDim.x+threadIdx.x;
    if(i<step)powers[step+i]=m2(powers[i],factor);
}

extern "C" __global__ void mix_codeword(
    u32 *values,const u32 *other,const u32 *mixing,u64 count
){
    u64 i=(u64)blockIdx.x*blockDim.x+threadIdx.x;
    if(i<count){
        F16 x=l16(values+16ULL*i);
        F16 y=l16(other+16ULL*i);
        st16(values+16ULL*i,a16(x,m16(l16(mixing),y)));
    }
}

__device__ __forceinline__ F16 m16m31(F16 x,u32 y){
    u32 words[16]; st16(words,x);
    #pragma unroll
    for(u32 c=0;c<16;c++)words[c]=mulp(words[c],y);
    return l16(words);
}

extern "C" __global__ void fold_fri_layer(
    u32 *values,const F2 *inverse_powers,const u32 *challenge,
    const u32 *auxiliary,const u32 *auxiliary_mixing,
    u32 round,u64 half,u32 inject_auxiliary
){
    u64 i=(u64)blockIdx.x*blockDim.x+threadIdx.x;
    if(i>=half)return;
    F16 at_x=l16(values+16ULL*i);
    F16 at_negative_x=l16(values+16ULL*(i+half));
    F16 even=m16m31(a16(at_x,at_negative_x),1073741824U);
    F16 odd=m16m31(
        m16f2(s16(at_x,at_negative_x),inverse_powers[i<<round]),
        1073741824U
    );
    F16 folded=a16(even,m16(l16(challenge),odd));
    if(inject_auxiliary){
        folded=a16(folded,m16(l16(auxiliary_mixing),l16(auxiliary+16ULL*i)));
    }
    st16(values+16ULL*i,folded);
}

extern "C" __global__ void byte_swap_words(u32 *values,u64 count){
    u64 i=(u64)blockIdx.x*blockDim.x+threadIdx.x;
    if(i<count){
        u32 x=values[i];
        values[i]=(x>>24)|((x>>8)&0x0000ff00U)|
                  ((x<<8)&0x00ff0000U)|(x<<24);
    }
}
"""


def exact_read(source, length):
    data = source.read(length)
    if len(data) != length:
        raise RuntimeError("truncated_command")
    return data


def function(runtime, name):
    result = ctypes.c_void_p()
    ck(
        runtime.cuda.cuModuleGetFunction(
            ctypes.byref(result), runtime.module, name.encode()
        ),
        name,
    )
    return result


def launch(runtime, fn, count, args):
    ck(
        runtime.cuda.cuLaunchKernel(
            fn, (count + 255) // 256, 1, 1, 256, 1, 1, 0, None, args, None
        ),
        "launch",
    )


def fp2_square(value):
    return mul2(value, value)


def inverse_fp2(value):
    modulus = 2_147_483_647
    denominator = (value[0] * value[0] + value[1] * value[1]) % modulus
    inverse_denominator = pow(denominator, modulus - 2, modulus)
    return (
        value[0] * inverse_denominator % modulus,
        (-value[1] * inverse_denominator) % modulus,
    )


def load_chunk(runtime, destination, encoded):
    canonical = array("I")
    canonical.frombytes(encoded)
    if sys.byteorder == "little":
        canonical.byteswap()
    host = ctypes.create_string_buffer(canonical.tobytes())
    ck(
        runtime.cuda.cuMemcpyHtoD_v2(
            destination, ctypes.cast(host, ctypes.c_void_p), len(encoded)
        ),
        "load_chunk",
    )


def validate_file(path, expected):
    if path.stat().st_size != expected:
        raise RuntimeError("codeword_size")


def main():
    if len(sys.argv) != 4:
        raise SystemExit(
            "usage: cuda_mlpcs_fold_worker.py <nvrtc-bin> "
            "<input-codeword> <output-codeword>"
        )
    msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
    msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
    runtime_path = Path(sys.argv[1])
    input_path = Path(sys.argv[2])
    output_path = Path(sys.argv[3])
    validate_file(input_path, VALUE_BYTES)
    validate_file(output_path, VALUE_BYTES)
    runtime = Runtime(runtime_path)
    try:
        runtime.compile(CUDA + EXTRA + KERNELS, b"expand_root_powers")
        expand_fn = function(runtime, "expand_root_powers")
        mix_fn = function(runtime, "mix_codeword")
        fold_fn = function(runtime, "fold_fri_layer")
        swap_fn = function(runtime, "byte_swap_words")
        values = runtime.alloc(VALUE_BYTES)
        auxiliary = runtime.alloc(AUXILIARY_BYTES)
        inverse_powers = runtime.alloc((COUNT // 2) * 8)
        temporary_bytes = 16 << 20
        temporary = runtime.alloc(temporary_bytes)
        challenge_device = runtime.alloc(64)
        mixing_device = runtime.alloc(64)
        auxiliary_mixing_device = runtime.alloc(64)

        one = (ctypes.c_uint32 * 2)(1, 0)
        ck(
            runtime.cuda.cuMemcpyHtoD_v2(
                inverse_powers, ctypes.cast(one, ctypes.c_void_p), ctypes.sizeof(one)
            ),
            "inverse_power_one",
        )
        factor = inverse_fp2(ROOT25)
        step = 1
        while step < COUNT // 2:
            destination = ctypes.c_uint64(inverse_powers)
            size = ctypes.c_uint64(step)
            factor_words = (ctypes.c_uint32 * 2)(*factor)
            args = (ctypes.c_void_p * 3)(
                ctypes.cast(ctypes.byref(destination), ctypes.c_void_p),
                ctypes.cast(ctypes.byref(size), ctypes.c_void_p),
                ctypes.cast(factor_words, ctypes.c_void_p),
            )
            launch(runtime, expand_fn, step, args)
            factor = fp2_square(factor)
            step *= 2

        def reset(mixing_encoded):
            load_chunk(runtime, mixing_device, mixing_encoded)
            with input_path.open("rb") as source:
                offset = 0
                while offset < VALUE_BYTES:
                    encoded = exact_read(source, min(temporary_bytes, VALUE_BYTES - offset))
                    load_chunk(runtime, values + offset, encoded)
                    offset += len(encoded)
            with output_path.open("rb") as source:
                offset = 0
                while offset < VALUE_BYTES:
                    encoded = exact_read(source, min(temporary_bytes, VALUE_BYTES - offset))
                    load_chunk(runtime, temporary, encoded)
                    count = len(encoded) // 64
                    destination = ctypes.c_uint64(values + offset)
                    other = ctypes.c_uint64(temporary)
                    mixing = ctypes.c_uint64(mixing_device)
                    count_value = ctypes.c_uint64(count)
                    args = (ctypes.c_void_p * 4)(
                        ctypes.cast(ctypes.byref(destination), ctypes.c_void_p),
                        ctypes.cast(ctypes.byref(other), ctypes.c_void_p),
                        ctypes.cast(ctypes.byref(mixing), ctypes.c_void_p),
                        ctypes.cast(ctypes.byref(count_value), ctypes.c_void_p),
                    )
                    launch(runtime, mix_fn, count, args)
                    offset += len(encoded)
            ck(runtime.cuda.cuCtxSynchronize(), "reset_sync")

        stdin = sys.stdin.buffer
        stdout = sys.stdout.buffer
        main_mixing = exact_read(stdin, 64)
        auxiliary_mixing = exact_read(stdin, 64)
        load_chunk(runtime, auxiliary_mixing_device, auxiliary_mixing)
        offset = 0
        while offset < AUXILIARY_BYTES:
            encoded = exact_read(stdin, min(temporary_bytes, AUXILIARY_BYTES - offset))
            load_chunk(runtime, auxiliary + offset, encoded)
            offset += len(encoded)
        reset(main_mixing)
        stdout.write(READY)
        stdout.flush()
        current_count = COUNT
        while True:
            command = exact_read(stdin, 1)
            if command == FINISH:
                break
            if command == RESET:
                reset(exact_read(stdin, 64))
                current_count = COUNT
                stdout.write(READY)
                stdout.flush()
                continue
            if command == FOLD:
                round_number = struct.unpack(">I", exact_read(stdin, 4))[0]
                if round_number >= 22 or current_count != COUNT >> round_number:
                    raise RuntimeError("fold_sequence")
                load_chunk(runtime, challenge_device, exact_read(stdin, 64))
                half = current_count // 2
                values_pointer = ctypes.c_uint64(values)
                powers_pointer = ctypes.c_uint64(inverse_powers)
                challenge_pointer = ctypes.c_uint64(challenge_device)
                auxiliary_pointer = ctypes.c_uint64(auxiliary)
                auxiliary_mixing_pointer = ctypes.c_uint64(auxiliary_mixing_device)
                round_value = ctypes.c_uint32(round_number)
                half_value = ctypes.c_uint64(half)
                inject = ctypes.c_uint32(1 if round_number == 3 else 0)
                args = (ctypes.c_void_p * 8)(
                    ctypes.cast(ctypes.byref(values_pointer), ctypes.c_void_p),
                    ctypes.cast(ctypes.byref(powers_pointer), ctypes.c_void_p),
                    ctypes.cast(ctypes.byref(challenge_pointer), ctypes.c_void_p),
                    ctypes.cast(ctypes.byref(auxiliary_pointer), ctypes.c_void_p),
                    ctypes.cast(ctypes.byref(auxiliary_mixing_pointer), ctypes.c_void_p),
                    ctypes.cast(ctypes.byref(round_value), ctypes.c_void_p),
                    ctypes.cast(ctypes.byref(half_value), ctypes.c_void_p),
                    ctypes.cast(ctypes.byref(inject), ctypes.c_void_p),
                )
                launch(runtime, fold_fn, half, args)
                ck(runtime.cuda.cuCtxSynchronize(), "fold_sync")
                current_count = half
                stdout.write(READY)
                stdout.flush()
                continue
            if command == STREAM:
                stdout.write(struct.pack(">Q", current_count))
                word_count = current_count * 16
                values_pointer = ctypes.c_uint64(values)
                words = ctypes.c_uint64(word_count)
                args = (ctypes.c_void_p * 2)(
                    ctypes.cast(ctypes.byref(values_pointer), ctypes.c_void_p),
                    ctypes.cast(ctypes.byref(words), ctypes.c_void_p),
                )
                launch(runtime, swap_fn, word_count, args)
                ck(runtime.cuda.cuCtxSynchronize(), "stream_swap")
                offset = 0
                while offset < current_count * 64:
                    current = min(temporary_bytes, current_count * 64 - offset)
                    host = ctypes.create_string_buffer(current)
                    ck(
                        runtime.cuda.cuMemcpyDtoH_v2(
                            ctypes.cast(host, ctypes.c_void_p), values + offset, current
                        ),
                        "stream_copy",
                    )
                    stdout.write(host.raw)
                    offset += current
                launch(runtime, swap_fn, word_count, args)
                ck(runtime.cuda.cuCtxSynchronize(), "stream_restore")
                stdout.flush()
                continue
            raise RuntimeError("unknown_command")
    finally:
        runtime.close()


if __name__ == "__main__":
    main()
