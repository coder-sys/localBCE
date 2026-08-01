"""Pinned all-round CUDA kernels for one full repeated Chi GKR layer."""

import ctypes
import struct
import time
from pathlib import Path

from cuda_fp16_tower_kat import CUDA, Q, Runtime, ck
from cuda_sparse_round_kat import EXTRA

KERNELS = r"""
__device__ __forceinline__ void gate_line_right16(
    unsigned char formula,F16 zero,F16 delta,F16 fixed,F16* g0,F16* gd
){
    F16 z=z16(),o=o16();
    if(formula==0){
        F16 twice=a16(fixed,fixed);
        *g0=s16(a16(zero,fixed),m16(zero,twice));
        *gd=m16(delta,s16(o,twice));
    } else if(formula==1){
        *g0=m16(zero,fixed); *gd=m16(delta,fixed);
    } else if(formula==2){
        *g0=fixed; *gd=z;
    } else if(formula==3){
        *g0=zero; *gd=delta;
    } else if(formula==4){
        *g0=s16(o,fixed); *gd=z;
    } else if(formula==5){
        *g0=s16(o,zero); *gd=n16(delta);
    } else if(formula==6){
        *g0=o; *gd=z;
    } else {
        *g0=z; *gd=z;
    }
}

extern "C" __global__ void sparse_left_round(
    const u32* weights,const u32* factors,const u32* input,const u32* folded,
    const u32* left,const u32* right,const unsigned char* formula,
    u32 round,u64 count,u64* partial
){
    __shared__ u64 sums[48];
    if(threadIdx.x<48) sums[threadIdx.x]=0;
    __syncthreads();
    u64 i=(u64)blockIdx.x*blockDim.x+threadIdx.x;
    u32 values[48];
    #pragma unroll
    for(int c=0;c<48;c++) values[c]=0;
    if(i<count){
        u32 li=left[i],suffix=li>>(round+1U);
        F16 zero=l16(folded+16ULL*(2ULL*suffix));
        F16 one=l16(folded+16ULL*(2ULL*suffix+1ULL));
        F16 g0,gd;
        gate_line16(
            formula[i],zero,s16(one,zero),l16(input+16ULL*right[i]),&g0,&gd
        );
        F16 weight=m16(l16(weights+16ULL*i),l16(factors+16ULL*i));
        F16 wg0=m16(weight,g0),wgd=m16(weight,gd),c0,c1,c2;
        if(((li>>round)&1U)==0U){
            c0=wg0; c1=s16(wgd,wg0); c2=n16(wgd);
        } else {
            c0=z16(); c1=wg0; c2=wgd;
        }
        st16(values,c0);st16(values+16,c1);st16(values+32,c2);
    }
    unsigned lane=threadIdx.x&31U;
    #pragma unroll
    for(int c=0;c<48;c++){
        u64 value=values[c];
        #pragma unroll
        for(int offset=16;offset>0;offset>>=1)
            value+=__shfl_down_sync(0xffffffffU,value,offset);
        if(lane==0) atomicAdd(&sums[c],value);
    }
    __syncthreads();
    if(threadIdx.x<48) partial[(u64)blockIdx.x*48ULL+threadIdx.x]=sums[threadIdx.x];
}

extern "C" __global__ void sparse_right_round(
    const u32* weights,const u32* left_factors,const u32* right_factors,
    const u32* folded,const u32* terminal_left,const u32* left,const u32* right,
    const unsigned char* formula,u32 round,u64 count,u64* partial
){
    __shared__ u64 sums[48];
    if(threadIdx.x<48) sums[threadIdx.x]=0;
    __syncthreads();
    u64 i=(u64)blockIdx.x*blockDim.x+threadIdx.x;
    u32 values[48];
    #pragma unroll
    for(int c=0;c<48;c++) values[c]=0;
    if(i<count){
        u32 ri=right[i],suffix=ri>>(round+1U);
        F16 zero=l16(folded+16ULL*(2ULL*suffix));
        F16 one=l16(folded+16ULL*(2ULL*suffix+1ULL));
        F16 g0,gd;
        gate_line_right16(
            formula[i],zero,s16(one,zero),l16(terminal_left),&g0,&gd
        );
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
    }
    unsigned lane=threadIdx.x&31U;
    #pragma unroll
    for(int c=0;c<48;c++){
        u64 value=values[c];
        #pragma unroll
        for(int offset=16;offset>0;offset>>=1)
            value+=__shfl_down_sync(0xffffffffU,value,offset);
        if(lane==0) atomicAdd(&sums[c],value);
    }
    __syncthreads();
    if(threadIdx.x<48) partial[(u64)blockIdx.x*48ULL+threadIdx.x]=sums[threadIdx.x];
}

extern "C" __global__ void update_factors(
    u32* factors,const u32* labels,const u32* challenge,u32 bit,u64 count
){
    u64 i=(u64)blockIdx.x*blockDim.x+threadIdx.x;
    if(i<count){
        F16 coin=l16(challenge);
        F16 basis=((labels[i]>>bit)&1U)?coin:s16(o16(),coin);
        st16(factors+16ULL*i,m16(l16(factors+16ULL*i),basis));
    }
}

extern "C" __global__ void fold_values(
    const u32* input,u32* output,const u32* challenge,u64 output_count
){
    u64 i=(u64)blockIdx.x*blockDim.x+threadIdx.x;
    if(i<output_count){
        F16 zero=l16(input+32ULL*i);
        F16 one=l16(input+32ULL*i+16ULL);
        st16(output+16ULL*i,a16(zero,m16(l16(challenge),s16(one,zero))));
    }
}

extern "C" __global__ void reduce_partial(
    const u64* partial,u32 block_count,u32* output
){
    u32 coordinate=threadIdx.x;
    if(coordinate<48U){
        u64 sum=0;
        for(u32 block=0;block<block_count;block++)
            sum+=partial[(u64)block*48ULL+coordinate];
        output[coordinate]=(u32)(sum%2147483647ULL);
    }
}
"""


def read_fixture(path):
    data = path.read_bytes()
    if data[:8] != b"BLGKR3\0\0":
        raise SystemExit("fixture_magic_mismatch")
    input_count, term_count, round_count = struct.unpack_from("<III", data, 8)
    offset = 20
    challenges = []
    for _ in range(round_count):
        challenges.append(struct.unpack_from("<16I", data, offset))
        offset += 64
    rounds = []
    for _ in range(round_count):
        rounds.append(struct.unpack_from("<48I", data, offset))
        offset += 192
    terminal_left = struct.unpack_from("<16I", data, offset)
    offset += 64
    terminal_right = struct.unpack_from("<16I", data, offset)
    offset += 64
    input_words = struct.unpack_from(f"<{input_count * 16}I", data, offset)
    offset += input_count * 64
    weights, left, right, formula = [], [], [], []
    for _ in range(term_count):
        weights.extend(struct.unpack_from("<16I", data, offset))
        offset += 64
        li, ri = struct.unpack_from("<II", data, offset)
        left.append(li)
        right.append(ri)
        formula.append(data[offset + 8])
        offset += 12
    if offset != len(data):
        raise SystemExit("fixture_trailing_bytes")
    return (
        input_count,
        challenges,
        rounds,
        terminal_left,
        terminal_right,
        input_words,
        weights,
        left,
        right,
        formula,
    )


def host_array(ctype, values):
    return (ctype * len(values))(*values)


def ptr(value):
    return ctypes.cast(ctypes.byref(value), ctypes.c_void_p)


def main():
    root = Path(__file__).parent
    (
        input_count,
        challenges,
        expected_rounds,
        expected_terminal_left,
        expected_terminal_right,
        input_words,
        weights,
        left,
        right,
        formula,
    ) = read_fixture(root / "gkr-round.fixture")
    term_count = len(left)
    input_variables = input_count.bit_length() - 1
    if len(challenges) != 2 * input_variables:
        raise SystemExit("fixture_round_geometry")
    block = 256
    term_blocks = (term_count + block - 1) // block
    arrays = [
        host_array(ctypes.c_uint32, weights),
        host_array(ctypes.c_uint32, input_words),
        host_array(ctypes.c_uint32, left),
        host_array(ctypes.c_uint32, right),
        host_array(ctypes.c_ubyte, formula),
        host_array(ctypes.c_uint32, [word for challenge in challenges for word in challenge]),
        host_array(
            ctypes.c_uint32,
            [1] + [0] * 15,
        ),
    ]
    rt = Runtime(root / "cuda_nvrtc" / "nvidia" / "cuda_nvrtc" / "bin")
    try:
        compile_start = time.perf_counter()
        rt.compile(CUDA + EXTRA + KERNELS, b"sparse_left_round")
        compile_seconds = time.perf_counter() - compile_start
        functions = {}
        for name in (b"sparse_right_round", b"update_factors", b"fold_values"):
            function = ctypes.c_void_p()
            ck(
                rt.cuda.cuModuleGetFunction(
                    ctypes.byref(function), rt.module, name
                ),
                f"function_{name.decode()}",
            )
            functions[name] = function
        device = []
        for array in arrays:
            size = ctypes.sizeof(array)
            pointer = rt.alloc(size)
            ck(
                rt.cuda.cuMemcpyHtoD_v2(
                    pointer, ctypes.cast(array, ctypes.c_void_p), size
                ),
                "copy_input",
            )
            device.append(pointer)
        weight_d, input_d, left_d, right_d, formula_d, challenges_d, one_d = device
        factor_bytes = term_count * 64
        one_host = arrays[6]
        one_factor_host = (ctypes.c_uint32 * (term_count * 16))()
        for index in range(term_count):
            one_factor_host[16 * index] = 1
        left_factors = rt.alloc(factor_bytes)
        right_factors = rt.alloc(factor_bytes)
        for target in (left_factors, right_factors):
            ck(
                rt.cuda.cuMemcpyHtoD_v2(
                    target, ctypes.cast(one_factor_host, ctypes.c_void_p), factor_bytes
                ),
                "copy_factors",
            )
        fold_bytes = input_count * 64
        fold_a, fold_b = rt.alloc(fold_bytes), rt.alloc(fold_bytes)
        terminal_left_store = rt.alloc(64)
        partial_bytes = term_blocks * 48 * 8
        partial = rt.alloc(partial_bytes)
        host_partial = (ctypes.c_uint64 * (term_blocks * 48))()
        count_v, partial_v = ctypes.c_uint64(term_count), ctypes.c_uint64(partial)
        total_start = time.perf_counter()
        current = input_d
        current_count = input_count
        round_times = []
        actual_rounds = []
        terminal_left_d = None
        for global_round in range(2 * input_variables):
            phase_right = global_round >= input_variables
            local_round = global_round % input_variables
            round_v = ctypes.c_uint32(local_round)
            current_v = ctypes.c_uint64(current)
            if phase_right:
                params_values = [
                    ctypes.c_uint64(weight_d),
                    ctypes.c_uint64(left_factors),
                    ctypes.c_uint64(right_factors),
                    current_v,
                    ctypes.c_uint64(terminal_left_d),
                    ctypes.c_uint64(left_d),
                    ctypes.c_uint64(right_d),
                    ctypes.c_uint64(formula_d),
                ]
                params = (ctypes.c_void_p * 11)(
                    *(ptr(value) for value in params_values),
                    ptr(round_v),
                    ptr(count_v),
                    ptr(partial_v),
                )
                round_fn = functions[b"sparse_right_round"]
                labels_d, factors_d = right_d, right_factors
            else:
                params_values = [
                    ctypes.c_uint64(weight_d),
                    ctypes.c_uint64(left_factors),
                    ctypes.c_uint64(input_d),
                    current_v,
                    ctypes.c_uint64(left_d),
                    ctypes.c_uint64(right_d),
                    ctypes.c_uint64(formula_d),
                ]
                params = (ctypes.c_void_p * 10)(
                    *(ptr(value) for value in params_values),
                    ptr(round_v),
                    ptr(count_v),
                    ptr(partial_v),
                )
                round_fn = rt.fn
                labels_d, factors_d = left_d, left_factors
            start = time.perf_counter()
            ck(
                rt.cuda.cuLaunchKernel(
                    round_fn,
                    term_blocks,
                    1,
                    1,
                    block,
                    1,
                    1,
                    0,
                    None,
                    params,
                    None,
                ),
                "round_launch",
            )
            ck(rt.cuda.cuCtxSynchronize(), "round_sync")
            round_times.append(time.perf_counter() - start)
            ck(
                rt.cuda.cuMemcpyDtoH_v2(
                    ctypes.cast(host_partial, ctypes.c_void_p),
                    partial,
                    partial_bytes,
                ),
                "copy_partial",
            )
            actual = tuple(
                sum(
                    host_partial[block_index * 48 + coordinate]
                    for block_index in range(term_blocks)
                )
                % Q
                for coordinate in range(48)
            )
            actual_rounds.append(actual)
            expected = expected_rounds[global_round]
            if actual != expected:
                for coordinate, (want, got) in enumerate(zip(expected, actual)):
                    if want != got:
                        raise SystemExit(
                            f"round={global_round} coordinate={coordinate} expected={want} actual={got}"
                        )
            challenge_d = challenges_d + 64 * global_round
            challenge_v = ctypes.c_uint64(challenge_d)
            factors_v = ctypes.c_uint64(factors_d)
            labels_v = ctypes.c_uint64(labels_d)
            bit_v = ctypes.c_uint32(local_round)
            update_params = (ctypes.c_void_p * 5)(
                ptr(factors_v), ptr(labels_v), ptr(challenge_v), ptr(bit_v), ptr(count_v)
            )
            ck(
                rt.cuda.cuLaunchKernel(
                    functions[b"update_factors"],
                    term_blocks,
                    1,
                    1,
                    block,
                    1,
                    1,
                    0,
                    None,
                    update_params,
                    None,
                ),
                "factor_launch",
            )
            next_count = current_count // 2
            next_buffer = fold_a if (local_round & 1) == 0 else fold_b
            input_v = ctypes.c_uint64(current)
            output_v = ctypes.c_uint64(next_buffer)
            output_count_v = ctypes.c_uint64(next_count)
            fold_params = (ctypes.c_void_p * 4)(
                ptr(input_v), ptr(output_v), ptr(challenge_v), ptr(output_count_v)
            )
            ck(
                rt.cuda.cuLaunchKernel(
                    functions[b"fold_values"],
                    (next_count + block - 1) // block,
                    1,
                    1,
                    block,
                    1,
                    1,
                    0,
                    None,
                    fold_params,
                    None,
                ),
                "fold_launch",
            )
            ck(rt.cuda.cuCtxSynchronize(), "update_sync")
            current, current_count = next_buffer, next_count
            if not phase_right and local_round + 1 == input_variables:
                terminal_left_d = current
                terminal_host = (ctypes.c_uint32 * 16)()
                ck(
                    rt.cuda.cuMemcpyDtoH_v2(
                        ctypes.cast(terminal_host, ctypes.c_void_p), current, 64
                    ),
                    "terminal_left_copy",
                )
                if tuple(terminal_host) != expected_terminal_left:
                    raise SystemExit("terminal_left_mismatch")
                ck(
                    rt.cuda.cuMemcpyHtoD_v2(
                        terminal_left_store,
                        ctypes.cast(terminal_host, ctypes.c_void_p),
                        64,
                    ),
                    "terminal_left_store",
                )
                terminal_left_d = terminal_left_store
                current, current_count = input_d, input_count
        terminal_right_host = (ctypes.c_uint32 * 16)()
        ck(
            rt.cuda.cuMemcpyDtoH_v2(
                ctypes.cast(terminal_right_host, ctypes.c_void_p), current, 64
            ),
            "terminal_right_copy",
        )
        if tuple(terminal_right_host) != expected_terminal_right:
            raise SystemExit("terminal_right_mismatch")
        total_seconds = time.perf_counter() - total_start
        ordered = sorted(round_times)
        print(f"terms={term_count}")
        print(f"rounds={len(actual_rounds)}")
        print("all_round_coordinates_match=true")
        print("terminal_left_match=true")
        print("terminal_right_match=true")
        print(f"nvrtc_compile_seconds={compile_seconds:.6f}")
        print(f"round_kernel_median_seconds={ordered[len(ordered)//2]:.9f}")
        print(f"round_kernel_maximum_seconds={max(round_times):.9f}")
        print(f"all_rounds_host_checked_seconds={total_seconds:.9f}")
        print(
            f"device_bytes={sum(ctypes.sizeof(array) for array in arrays) + 2*factor_bytes + 2*fold_bytes + partial_bytes + 64}"
        )
    finally:
        rt.close()


if __name__ == "__main__":
    main()
