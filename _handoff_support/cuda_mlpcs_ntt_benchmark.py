"""Bounded RTX 4060 speed/KAT control for the Fp16 zkDeepFold NTT."""

import ctypes
import hashlib
import msvcrt
import os
import struct
import sys
import time
from array import array
from pathlib import Path

from cuda_fp16_tower_kat import CUDA, Q, Runtime, add, ck, mul16, mul2, p_mul, sub
from cuda_sparse_round_kat import EXTRA

ROOT25 = (1_905_033_081, 454_651_505)

KERNELS = r"""
__device__ __forceinline__ F4 m4f2(F4 x,F2 y){return {m2(x.a,y),m2(x.b,y)};}
__device__ __forceinline__ F8 m8f2(F8 x,F2 y){return {m4f2(x.a,y),m4f2(x.b,y)};}
__device__ __forceinline__ F16 m16f2(F16 x,F2 y){return {m8f2(x.a,y),m8f2(x.b,y)};}

extern "C" __global__ void initialize_hidden_coefficients(
    u32 *values,u64 count,u64 witness_count,u64 hidden_count
) {
    u64 i=(u64)blockIdx.x*blockDim.x+threadIdx.x;
    if(i>=count)return;
    u32 *out=values+16ULL*i;
    #pragma unroll
    for(u32 c=0;c<16;c++)out[c]=0;
    if(i<witness_count){
        out[0]=(u32)((i*2654435761ULL+17ULL)%2147483647ULL);
    }else if(i<hidden_count){
        #pragma unroll
        for(u32 c=0;c<16;c++)
            out[c]=(u32)((i*1140071481ULL+(u64)(c+1)*977ULL)
                         %2147483647ULL);
    }
}

extern "C" __global__ void expand_root_powers(
    F2 *powers,u64 step,F2 factor
) {
    u64 i=(u64)blockIdx.x*blockDim.x+threadIdx.x;
    if(i<step)powers[step+i]=m2(powers[i],factor);
}

extern "C" __global__ void bit_reverse_fp16(u32 *values,u32 log_size,u64 count){
    u64 i=(u64)blockIdx.x*blockDim.x+threadIdx.x;
    if(i>=count)return;
    u64 reversed=(u64)__brev((u32)i)>>(32U-log_size);
    if(i>=reversed)return;
    #pragma unroll
    for(u32 c=0;c<16;c++){
        u32 t=values[16ULL*i+c];
        values[16ULL*i+c]=values[16ULL*reversed+c];
        values[16ULL*reversed+c]=t;
    }
}

extern "C" __global__ void byte_swap_words(u32 *values,u64 count){
    u64 i=(u64)blockIdx.x*blockDim.x+threadIdx.x;
    if(i>=count)return;
    u32 x=values[i];
    values[i]=(x>>24)|((x>>8)&0x0000ff00U)|
              ((x<<8)&0x00ff0000U)|(x<<24);
}

extern "C" __global__ void ntt_stage_fp16(
    u32 *values,const F2 *powers,u32 log_size,u32 stage_log,u64 count
) {
    u64 butterfly=(u64)blockIdx.x*blockDim.x+threadIdx.x;
    if(butterfly>=count/2ULL)return;
    u64 half=1ULL<<(stage_log-1U);
    u64 j=butterfly&(half-1ULL);
    u64 block=butterfly>>(stage_log-1U);
    u64 left_index=(block<<stage_log)+j;
    u64 right_index=left_index+half;
    u64 twiddle_index=j<<(log_size-stage_log);
    F16 left=l16(values+16ULL*left_index);
    F16 right=m16f2(l16(values+16ULL*right_index),powers[twiddle_index]);
    st16(values+16ULL*left_index,a16(left,right));
    st16(values+16ULL*right_index,s16(left,right));
}

__device__ __forceinline__ F16 m16m31(F16 x,u32 y){
    u32 words[16]; st16(words,x);
    #pragma unroll
    for(u32 c=0;c<16;c++)words[c]=mulp(words[c],y);
    return l16(words);
}

extern "C" __global__ void fold_fri_layer(
    u32 *values,const F2 *inverse_powers,const u32 *challenge,
    u32 round,u64 half
) {
    u64 i=(u64)blockIdx.x*blockDim.x+threadIdx.x;
    if(i>=half)return;
    F16 at_x=l16(values+16ULL*i);
    F16 at_negative_x=l16(values+16ULL*(i+half));
    F16 even=m16m31(a16(at_x,at_negative_x),1073741824U);
    F16 odd=m16m31(
        m16f2(s16(at_x,at_negative_x),inverse_powers[i<<round]),
        1073741824U
    );
    st16(values+16ULL*i,a16(even,m16(l16(challenge),odd)));
}
"""


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


def root_for_log(log_size):
    root = ROOT25
    for _ in range(log_size, 25):
        root = fp2_square(root)
    return root


def inverse_fp2(value):
    denominator = (value[0] * value[0] + value[1] * value[1]) % Q
    inverse_denominator = pow(denominator, Q - 2, Q)
    return (
        value[0] * inverse_denominator % Q,
        (-value[1] * inverse_denominator) % Q,
    )


def scale_fp16(value, scalar):
    return tuple(p_mul(coordinate, scalar % Q) for coordinate in value)


def cpu_ntt(values, root):
    count = len(values)
    log_size = count.bit_length() - 1
    for index in range(1, count):
        reversed_index = int(f"{index:0{log_size}b}"[::-1], 2)
        if index < reversed_index:
            values[index], values[reversed_index] = values[reversed_index], values[index]
    length = 2
    while length <= count:
        stage_log = length.bit_length() - 1
        stage_root = root
        for _ in range(stage_log, log_size):
            stage_root = fp2_square(stage_root)
        for base in range(0, count, length):
            twiddle = (1, 0)
            for index in range(length // 2):
                left = values[base + index]
                scalar = twiddle + (0,) * 14
                right = mul16(values[base + length // 2 + index], scalar)
                values[base + index] = add(left, right)
                values[base + length // 2 + index] = sub(left, right)
                twiddle = mul2(twiddle, stage_root)
        length *= 2
    return values


def main():
    log_size = int(sys.argv[1]) if len(sys.argv) >= 2 else 25
    mode = sys.argv[2] if len(sys.argv) >= 3 else "main"
    output_path = (
        None
        if len(sys.argv) < 4 or sys.argv[3] == "none"
        else Path(sys.argv[3])
    )
    coefficient_path = Path(sys.argv[4]) if len(sys.argv) >= 5 else None
    endpoint_path = Path(sys.argv[5]) if len(sys.argv) >= 6 else None
    if len(sys.argv) > 6 or mode not in {"main", "aux"}:
        raise SystemExit(
            "usage: cuda_mlpcs_ntt_benchmark.py [log_size] [main|aux] "
            "[output] [coefficients] [endpoint-manifest]"
        )
    if not 3 <= log_size <= 25:
        raise SystemExit("log_size_must_be_3_through_25")
    if mode == "aux" and log_size != 21:
        raise SystemExit("aux_mode_requires_log_size_21")
    if mode == "aux" and coefficient_path is not None:
        raise SystemExit("aux_mode_forbids_coefficient_input")
    if (coefficient_path is None) != (endpoint_path is None):
        raise SystemExit("external_coefficients_require_endpoints")
    count = 1 << log_size
    if mode == "main":
        witness_count = min(1 << 21, count // 2)
        hidden_count = min(1 << 22, count)
    else:
        witness_count = 0
        hidden_count = 1 << 18
    value_bytes = count * 64
    power_count = count // 2
    nvrtc = Path(__file__).parent / "cuda_nvrtc" / "nvidia" / "cuda_nvrtc" / "bin"
    runtime = Runtime(nvrtc)
    try:
        compile_started = time.perf_counter()
        runtime.compile(CUDA + EXTRA + KERNELS, b"initialize_hidden_coefficients")
        compile_seconds = time.perf_counter() - compile_started
        init_fn = function(runtime, "initialize_hidden_coefficients")
        expand_fn = function(runtime, "expand_root_powers")
        reverse_fn = function(runtime, "bit_reverse_fp16")
        byte_swap_fn = function(runtime, "byte_swap_words")
        stage_fn = function(runtime, "ntt_stage_fp16")
        fold_fn = function(runtime, "fold_fri_layer")
        values = runtime.alloc(value_bytes)
        powers = runtime.alloc(power_count * 8)
        inverse_powers = runtime.alloc(power_count * 8)

        dv, dc, dw, dh = (
            ctypes.c_uint64(values),
            ctypes.c_uint64(count),
            ctypes.c_uint64(witness_count),
            ctypes.c_uint64(hidden_count),
        )
        init_args = (ctypes.c_void_p * 4)(
            ctypes.cast(ctypes.byref(dv), ctypes.c_void_p),
            ctypes.cast(ctypes.byref(dc), ctypes.c_void_p),
            ctypes.cast(ctypes.byref(dw), ctypes.c_void_p),
            ctypes.cast(ctypes.byref(dh), ctypes.c_void_p),
        )
        started = time.perf_counter()
        if coefficient_path is None:
            launch(runtime, init_fn, count, init_args)
            ck(runtime.cuda.cuCtxSynchronize(), "init_sync")
        else:
            expected = hidden_count * 64
            if coefficient_path.stat().st_size != expected:
                raise SystemExit("coefficient_file_size")
            runtime.cuda.cuMemsetD8_v2.argtypes = [
                ctypes.c_uint64,
                ctypes.c_ubyte,
                ctypes.c_size_t,
            ]
            ck(runtime.cuda.cuMemsetD8_v2(values, 0, value_bytes), "coefficient_zero")
            offset = 0
            with coefficient_path.open("rb") as source:
                while offset < expected:
                    encoded = source.read(min(16 << 20, expected - offset))
                    if not encoded:
                        raise SystemExit("coefficient_file_truncated")
                    canonical = array("I")
                    canonical.frombytes(encoded)
                    if sys.byteorder == "little":
                        canonical.byteswap()
                    host = ctypes.create_string_buffer(canonical.tobytes())
                    ck(
                        runtime.cuda.cuMemcpyHtoD_v2(
                            values + offset,
                            ctypes.cast(host, ctypes.c_void_p),
                            len(encoded),
                        ),
                        "coefficient_copy",
                    )
                    offset += len(encoded)
                if source.read(1):
                    raise SystemExit("coefficient_file_trailing")
            ck(runtime.cuda.cuCtxSynchronize(), "coefficient_sync")
        init_seconds = time.perf_counter() - started

        one = (ctypes.c_uint32 * 2)(1, 0)
        ck(
            runtime.cuda.cuMemcpyHtoD_v2(
                powers, ctypes.cast(one, ctypes.c_void_p), ctypes.sizeof(one)
            ),
            "power_one",
        )
        root = root_for_log(log_size)
        started = time.perf_counter()
        for destination, initial_factor in [
            (powers, root),
            (inverse_powers, inverse_fp2(root)),
        ]:
            ck(
                runtime.cuda.cuMemcpyHtoD_v2(
                    destination, ctypes.cast(one, ctypes.c_void_p), ctypes.sizeof(one)
                ),
                "power_one",
            )
            factor = initial_factor
            step = 1
            while step < power_count:
                dp = ctypes.c_uint64(destination)
                ds = ctypes.c_uint64(step)
                df = (ctypes.c_uint32 * 2)(*factor)
                args = (ctypes.c_void_p * 3)(
                    ctypes.cast(ctypes.byref(dp), ctypes.c_void_p),
                    ctypes.cast(ctypes.byref(ds), ctypes.c_void_p),
                    ctypes.cast(df, ctypes.c_void_p),
                )
                launch(runtime, expand_fn, step, args)
                factor = fp2_square(factor)
                step *= 2
        ck(runtime.cuda.cuCtxSynchronize(), "powers_sync")
        power_seconds = time.perf_counter() - started

        dl = ctypes.c_uint32(log_size)
        reverse_args = (ctypes.c_void_p * 3)(
            ctypes.cast(ctypes.byref(dv), ctypes.c_void_p),
            ctypes.cast(ctypes.byref(dl), ctypes.c_void_p),
            ctypes.cast(ctypes.byref(dc), ctypes.c_void_p),
        )
        started = time.perf_counter()
        launch(runtime, reverse_fn, count, reverse_args)
        for stage_log in range(1, log_size + 1):
            ds = ctypes.c_uint32(stage_log)
            dp = ctypes.c_uint64(powers)
            args = (ctypes.c_void_p * 5)(
                ctypes.cast(ctypes.byref(dv), ctypes.c_void_p),
                ctypes.cast(ctypes.byref(dp), ctypes.c_void_p),
                ctypes.cast(ctypes.byref(dl), ctypes.c_void_p),
                ctypes.cast(ctypes.byref(ds), ctypes.c_void_p),
                ctypes.cast(ctypes.byref(dc), ctypes.c_void_p),
            )
            launch(runtime, stage_fn, count // 2, args)
        ck(runtime.cuda.cuCtxSynchronize(), "ntt_sync")
        ntt_seconds = time.perf_counter() - started

        sample_count = min(count, 1024)
        output = (ctypes.c_uint32 * (sample_count * 16))()
        ck(
            runtime.cuda.cuMemcpyDtoH_v2(
                ctypes.cast(output, ctypes.c_void_p),
                values,
                ctypes.sizeof(output),
            ),
            "copy_sample",
        )
        kat = "production_geometry"
        if count <= 1024:
            inputs = []
            for index in range(count):
                if index < witness_count:
                    inputs.append(((index * 2654435761 + 17) % Q,) + (0,) * 15)
                elif index < hidden_count:
                    inputs.append(
                        tuple(
                            (
                                index * 1140071481 + (coordinate + 1) * 977
                            )
                            % Q
                            for coordinate in range(16)
                        )
                    )
                else:
                    inputs.append((0,) * 16)
            expected = cpu_ntt(inputs, root)
            actual = [
                tuple(output[16 * index : 16 * index + 16])
                for index in range(count)
            ]
            if actual != expected:
                raise SystemExit(f"ntt_mismatch_at={next(i for i in range(count) if actual[i] != expected[i])}")
            kat = "cpu_gpu_equal"
        else:
            minus_one = (ctypes.c_uint32 * 16)()
            ck(
                runtime.cuda.cuMemcpyDtoH_v2(
                    ctypes.cast(minus_one, ctypes.c_void_p),
                    values + (count // 2) * 64,
                    ctypes.sizeof(minus_one),
                ),
                "copy_minus_one",
            )

            def linear_sum(start, length, slope, intercept):
                return (
                    slope * length * (2 * start + length - 1) // 2
                    + intercept * length
                ) % Q

            def alternating_linear_sum(start, length, slope):
                signed = -slope * (length // 2) if start % 2 == 0 else slope * (length // 2)
                return signed % Q

            witness_length = witness_count
            mask_start = witness_count
            mask_length = hidden_count - witness_count
            expected_one = []
            expected_minus_one = []
            for coordinate in range(16):
                one = linear_sum(
                    mask_start, mask_length, 1140071481, (coordinate + 1) * 977
                )
                minus = alternating_linear_sum(
                    mask_start, mask_length, 1140071481
                )
                if coordinate == 0:
                    one = (
                        one + linear_sum(0, witness_length, 2654435761, 17)
                    ) % Q
                    minus = (
                        minus
                        + alternating_linear_sum(0, witness_length, 2654435761)
                    ) % Q
                expected_one.append(one)
                expected_minus_one.append(minus)
            if coefficient_path is not None:
                endpoints = endpoint_path.read_bytes()
                if len(endpoints) < 192:
                    raise SystemExit("endpoint_manifest_truncated")
                expected_one = list(struct.unpack(">16I", endpoints[-192:-128]))
                expected_minus_one = list(struct.unpack(">16I", endpoints[-128:-64]))
            actual_one = list(output[:16])
            if actual_one != expected_one or list(minus_one) != expected_minus_one:
                raise SystemExit("production_endpoint_kat_mismatch")
            kat = (
                "external_production_endpoints_equal"
                if coefficient_path is not None
                else "production_endpoints_equal"
            )
        checksum = 0
        for value in output:
            checksum = ((checksum << 1) ^ value) & ((1 << 64) - 1)
        transfer_seconds = 0.0
        output_sha3_512 = "not_written"
        if output_path is not None:
            pipe_output = str(output_path) == "-"
            if not pipe_output:
                output_path.parent.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha3_512()
            chunk_elements = 1 << 18
            started = time.perf_counter()
            word_count = count * 16
            dwords = ctypes.c_uint64(word_count)
            swap_args = (ctypes.c_void_p * 2)(
                ctypes.cast(ctypes.byref(dv), ctypes.c_void_p),
                ctypes.cast(ctypes.byref(dwords), ctypes.c_void_p),
            )
            launch(runtime, byte_swap_fn, word_count, swap_args)
            ck(runtime.cuda.cuCtxSynchronize(), "byte_swap_output_sync")
            if pipe_output:
                msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
                output = sys.stdout.buffer
            else:
                output = output_path.open("wb")
            try:
                for start in range(0, count, chunk_elements):
                    current = min(chunk_elements, count - start)
                    host = (ctypes.c_uint32 * (current * 16))()
                    ck(
                        runtime.cuda.cuMemcpyDtoH_v2(
                            ctypes.cast(host, ctypes.c_void_p),
                            values + start * 64,
                            ctypes.sizeof(host),
                        ),
                        "copy_output_chunk",
                    )
                    encoded = ctypes.string_at(host, ctypes.sizeof(host))
                    output.write(encoded)
                    if not pipe_output:
                        digest.update(encoded)
                output.flush()
            finally:
                if not pipe_output:
                    output.close()
            launch(runtime, byte_swap_fn, word_count, swap_args)
            ck(runtime.cuda.cuCtxSynchronize(), "byte_swap_restore_sync")
            transfer_seconds = time.perf_counter() - started
            if pipe_output:
                return
            output_sha3_512 = digest.hexdigest()
        elif log_size == 25 and os.environ.get("BL_SKIP_FULL_COPY") != "1":
            started = time.perf_counter()
            if os.environ.get("BL_STREAM_COPY") == "1":
                chunk_bytes = 16 << 20
                host = ctypes.create_string_buffer(chunk_bytes)
                for offset in range(0, value_bytes, chunk_bytes):
                    current = min(chunk_bytes, value_bytes - offset)
                    ck(
                        runtime.cuda.cuMemcpyDtoH_v2(
                            ctypes.cast(host, ctypes.c_void_p),
                            values + offset,
                            current,
                        ),
                        "stream_copy_codeword",
                    )
            else:
                full_output = ctypes.create_string_buffer(value_bytes)
                ck(
                    runtime.cuda.cuMemcpyDtoH_v2(
                        ctypes.cast(full_output, ctypes.c_void_p), values, value_bytes
                    ),
                    "copy_full_codeword",
                )
                del full_output
            transfer_seconds = time.perf_counter() - started
        fold_seconds = 0.0
        fold_kat = "not_run"
        if log_size == 25:
            challenges = [
                tuple(
                    ((round + 1) * 131 + (coordinate + 3) * 977) % Q
                    for coordinate in range(16)
                )
                for round in range(22)
            ]
            challenge_host = (ctypes.c_uint32 * (22 * 16))(
                *(coordinate for challenge in challenges for coordinate in challenge)
            )
            challenge_device = runtime.alloc(ctypes.sizeof(challenge_host))
            ck(
                runtime.cuda.cuMemcpyHtoD_v2(
                    challenge_device,
                    ctypes.cast(challenge_host, ctypes.c_void_p),
                    ctypes.sizeof(challenge_host),
                ),
                "copy_challenges",
            )
            started = time.perf_counter()
            current_count = count
            for round in range(22):
                half = current_count // 2
                di = ctypes.c_uint64(inverse_powers)
                dcptr = ctypes.c_uint64(challenge_device + round * 64)
                dr = ctypes.c_uint32(round)
                dh = ctypes.c_uint64(half)
                args = (ctypes.c_void_p * 5)(
                    ctypes.cast(ctypes.byref(dv), ctypes.c_void_p),
                    ctypes.cast(ctypes.byref(di), ctypes.c_void_p),
                    ctypes.cast(ctypes.byref(dcptr), ctypes.c_void_p),
                    ctypes.cast(ctypes.byref(dr), ctypes.c_void_p),
                    ctypes.cast(ctypes.byref(dh), ctypes.c_void_p),
                )
                launch(runtime, fold_fn, half, args)
                current_count = half
            ck(runtime.cuda.cuCtxSynchronize(), "fold_sync")
            fold_seconds = time.perf_counter() - started
            final_host = (ctypes.c_uint32 * (8 * 16))()
            ck(
                runtime.cuda.cuMemcpyDtoH_v2(
                    ctypes.cast(final_host, ctypes.c_void_p),
                    values,
                    ctypes.sizeof(final_host),
                ),
                "copy_final",
            )
            final_values = [
                tuple(final_host[16 * index : 16 * index + 16])
                for index in range(8)
            ]
            if any(value != final_values[0] for value in final_values[1:]):
                raise SystemExit("final_repetition_kat_mismatch")

            if coefficient_path is not None:
                expected_final = tuple(struct.unpack(">16I", endpoints[-64:]))
            else:
                lower = challenges[:21]
                product = (1,) + (0,) * 15
                weighted = (0,) * 16
                for bit, challenge in enumerate(lower):
                    others = (1,) + (0,) * 15
                    for other_bit, other in enumerate(lower):
                        if other_bit != bit:
                            others = mul16(others, add((1,) + (0,) * 15, other))
                    weighted = add(
                        weighted,
                        scale_fp16(mul16(challenge, others), 1 << bit),
                    )
                    product = mul16(product, add((1,) + (0,) * 15, challenge))
                witness_eval = add(
                    scale_fp16(weighted, 2654435761),
                    scale_fp16(product, 17),
                )
                mask_eval_coordinates = []
                top = challenges[21]
                for coordinate in range(16):
                    shifted = add(
                        scale_fp16(
                            product,
                            (1140071481 * (1 << 21) + (coordinate + 1) * 977),
                        ),
                        scale_fp16(weighted, 1140071481),
                    )
                    basis = tuple(1 if index == coordinate else 0 for index in range(16))
                    mask_eval_coordinates.append(mul16(top, mul16(shifted, basis)))
                expected = list(mask_eval_coordinates)
                expected[0] = add(expected[0], witness_eval)
                expected_final = (0,) * 16
                for value in expected:
                    expected_final = add(expected_final, value)
            if final_values[0] != expected_final:
                raise SystemExit("final_multilinear_kat_mismatch")
            fold_kat = "final_repetition_and_multilinear_equal"
        print(f"log_size={log_size}")
        print(f"mode={mode}")
        print(f"elements={count}")
        print(f"value_bytes={value_bytes}")
        print(f"power_bytes={power_count * 8}")
        print(f"nvrtc_compile_seconds={compile_seconds:.6f}")
        print(f"initialize_seconds={init_seconds:.9f}")
        print(f"root_power_seconds={power_seconds:.9f}")
        print(f"bit_reverse_plus_ntt_seconds={ntt_seconds:.9f}")
        print(f"device_to_host_seconds={transfer_seconds:.9f}")
        print(f"twenty_two_folds_seconds={fold_seconds:.9f}")
        print(f"fold_kat={fold_kat}")
        print(f"kat={kat}")
        print(f"sample_checksum={checksum:016x}")
        print(f"output_path={output_path if output_path is not None else 'not_written'}")
        print(f"output_sha3_512={output_sha3_512}")
    finally:
        runtime.close()


if __name__ == "__main__":
    main()
