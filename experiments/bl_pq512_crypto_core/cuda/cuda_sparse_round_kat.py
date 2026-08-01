"""Pinned CUDA kernels for the first repeated-pack sparse GKR round."""

import ctypes
import struct
import time
from pathlib import Path

from cuda_fp16_tower_kat import CUDA, Q, Runtime, ck

EXTRA = r"""
__device__ __forceinline__ F16 a16(F16 x,F16 y){return {a8(x.a,y.a),a8(x.b,y.b)};}
__device__ __forceinline__ F16 s16(F16 x,F16 y){return {s8(x.a,y.a),s8(x.b,y.b)};}
__device__ __forceinline__ F16 z16(){
    F2 z2={0,0}; F4 z4={z2,z2}; F8 z8={z4,z4}; return {z8,z8};
}
__device__ __forceinline__ F16 o16(){
    F2 a={1,0},z2={0,0}; F4 z4={z2,z2}; F8 z8={z4,z4};
    F4 a4v={a,z2}; F8 a8v={a4v,z4}; return {a8v,z8};
}
__device__ __forceinline__ F16 n16(F16 x){return s16(z16(),x);}

__device__ __forceinline__ void gate_line16(
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
        *g0=zero; *gd=delta;
    } else if(formula==3){
        *g0=fixed; *gd=z;
    } else if(formula==4){
        *g0=s16(o,zero); *gd=n16(delta);
    } else if(formula==5){
        *g0=s16(o,fixed); *gd=z;
    } else if(formula==6){
        *g0=o; *gd=z;
    } else {
        *g0=z; *gd=z;
    }
}

extern "C" __global__ void sparse_first_left_round(
    const u32* weights,const u32* input,const u32* left,const u32* right,
    const unsigned char* formula,u64 count,u64* partial
){
    __shared__ u64 sums[48];
    if(threadIdx.x<48) sums[threadIdx.x]=0;
    __syncthreads();
    u64 i=(u64)blockIdx.x*blockDim.x+threadIdx.x;
    u32 values[48];
    #pragma unroll
    for(int c=0;c<48;c++) values[c]=0;
    if(i<count){
        u32 li=left[i],ri=right[i],suffix=li>>1;
        F16 zero=l16(input+16ULL*(2ULL*suffix));
        F16 one=l16(input+16ULL*(2ULL*suffix+1ULL));
        F16 delta=s16(one,zero),fixed=l16(input+16ULL*ri);
        F16 g0,gd;
        gate_line16(formula[i],zero,delta,fixed,&g0,&gd);
        F16 weight=l16(weights+16ULL*i);
        F16 wg0=m16(weight,g0),wgd=m16(weight,gd);
        F16 c0,c1,c2;
        if((li&1U)==0U){
            c0=wg0; c1=s16(wgd,wg0); c2=n16(wgd);
        } else {
            c0=z16(); c1=wg0; c2=wgd;
        }
        st16(values,c0); st16(values+16,c1); st16(values+32,c2);
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

extern "C" __global__ void fold_left_once(
    const u32* input,u32* folded,const u32* challenge,u64 output_count
){
    u64 i=(u64)blockIdx.x*blockDim.x+threadIdx.x;
    if(i<output_count){
        F16 zero=l16(input+32ULL*i);
        F16 one=l16(input+32ULL*i+16ULL);
        st16(folded+16ULL*i,a16(zero,m16(l16(challenge),s16(one,zero))));
    }
}

extern "C" __global__ void sparse_second_left_round(
    const u32* weights,const u32* input,const u32* folded,
    const u32* left,const u32* right,const unsigned char* formula,
    const u32* challenge,u64 count,u64* partial
){
    __shared__ u64 sums[48];
    if(threadIdx.x<48) sums[threadIdx.x]=0;
    __syncthreads();
    u64 i=(u64)blockIdx.x*blockDim.x+threadIdx.x;
    u32 values[48];
    #pragma unroll
    for(int c=0;c<48;c++) values[c]=0;
    if(i<count){
        u32 li=left[i],ri=right[i],suffix=li>>2;
        F16 zero=l16(folded+16ULL*(2ULL*suffix));
        F16 one=l16(folded+16ULL*(2ULL*suffix+1ULL));
        F16 delta=s16(one,zero),fixed=l16(input+16ULL*ri);
        F16 g0,gd;
        gate_line16(formula[i],zero,delta,fixed,&g0,&gd);
        F16 coin=l16(challenge);
        F16 factor=(li&1U)?coin:s16(o16(),coin);
        F16 weight=m16(l16(weights+16ULL*i),factor);
        F16 wg0=m16(weight,g0),wgd=m16(weight,gd);
        F16 c0,c1,c2;
        if(((li>>1)&1U)==0U){
            c0=wg0; c1=s16(wgd,wg0); c2=n16(wgd);
        } else {
            c0=z16(); c1=wg0; c2=wgd;
        }
        st16(values,c0); st16(values+16,c1); st16(values+32,c2);
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
"""


def read_fixture(path):
    data = path.read_bytes()
    if data[:8] != b"BLGKR2\0\0":
        raise SystemExit("fixture_magic_mismatch")
    input_count, term_count = struct.unpack_from("<II", data, 8)
    offset = 16
    expected_first = struct.unpack_from("<48I", data, offset)
    offset += 48 * 4
    challenge = struct.unpack_from("<16I", data, offset)
    offset += 16 * 4
    expected_second = struct.unpack_from("<48I", data, offset)
    offset += 48 * 4
    input_words = struct.unpack_from(f"<{input_count * 16}I", data, offset)
    offset += input_count * 16 * 4
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
        expected_first,
        challenge,
        expected_second,
        input_words,
        weights,
        left,
        right,
        formula,
    )


def host_array(ctype, values):
    return (ctype * len(values))(*values)


def main():
    root = Path(__file__).parent
    (
        expected_first,
        challenge,
        expected_second,
        input_words,
        weights,
        left,
        right,
        formula,
    ) = read_fixture(root / "gkr-round.fixture")
    count = len(left)
    block = 256
    blocks = (count + block - 1) // block
    arrays = [
        host_array(ctypes.c_uint32, weights),
        host_array(ctypes.c_uint32, input_words),
        host_array(ctypes.c_uint32, left),
        host_array(ctypes.c_uint32, right),
        host_array(ctypes.c_ubyte, formula),
        host_array(ctypes.c_uint32, challenge),
    ]
    rt = Runtime(root / "cuda_nvrtc" / "nvidia" / "cuda_nvrtc" / "bin")
    try:
        start = time.perf_counter()
        rt.compile(CUDA + EXTRA, b"sparse_first_left_round")
        compile_seconds = time.perf_counter() - start
        fold_fn = ctypes.c_void_p()
        second_fn = ctypes.c_void_p()
        ck(
            rt.cuda.cuModuleGetFunction(
                ctypes.byref(fold_fn), rt.module, b"fold_left_once"
            ),
            "fold_function",
        )
        ck(
            rt.cuda.cuModuleGetFunction(
                ctypes.byref(second_fn), rt.module, b"sparse_second_left_round"
            ),
            "second_function",
        )
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
        partial_size = blocks * 48 * 8
        partial = rt.alloc(partial_size)
        folded_size = len(input_words) * 2
        folded = rt.alloc(folded_size)
        params_values = [ctypes.c_uint64(value) for value in device[:5]]
        count_value = ctypes.c_uint64(count)
        partial_value = ctypes.c_uint64(partial)
        params = (ctypes.c_void_p * 7)(
            *(ctypes.cast(ctypes.byref(value), ctypes.c_void_p) for value in params_values),
            ctypes.cast(ctypes.byref(count_value), ctypes.c_void_p),
            ctypes.cast(ctypes.byref(partial_value), ctypes.c_void_p),
        )
        first_times = []
        for run in range(11):
            start = time.perf_counter()
            ck(
                rt.cuda.cuLaunchKernel(
                    rt.fn, blocks, 1, 1, block, 1, 1, 0, None, params, None
                ),
                "launch",
            )
            ck(rt.cuda.cuCtxSynchronize(), "sync")
            if run:
                first_times.append(time.perf_counter() - start)
        host_partial = (ctypes.c_uint64 * (blocks * 48))()
        def read_partial():
            ck(
                rt.cuda.cuMemcpyDtoH_v2(
                    ctypes.cast(host_partial, ctypes.c_void_p), partial, partial_size
                ),
                "copy_partial",
            )
            return tuple(
                sum(
                    host_partial[block_index * 48 + coordinate]
                    for block_index in range(blocks)
                )
                % Q
                for coordinate in range(48)
            )

        actual_first = read_partial()
        if actual_first != expected_first:
            for index, (want, got) in enumerate(zip(expected_first, actual_first)):
                if want != got:
                    raise SystemExit(
                        f"first_round_mismatch_coordinate={index} expected={want} actual={got}"
                    )

        input_value = ctypes.c_uint64(device[1])
        folded_value = ctypes.c_uint64(folded)
        challenge_value = ctypes.c_uint64(device[5])
        folded_count_value = ctypes.c_uint64(len(input_words) // 32)
        fold_params = (ctypes.c_void_p * 4)(
            ctypes.cast(ctypes.byref(input_value), ctypes.c_void_p),
            ctypes.cast(ctypes.byref(folded_value), ctypes.c_void_p),
            ctypes.cast(ctypes.byref(challenge_value), ctypes.c_void_p),
            ctypes.cast(ctypes.byref(folded_count_value), ctypes.c_void_p),
        )
        second_values = [
            ctypes.c_uint64(device[0]),
            ctypes.c_uint64(device[1]),
            ctypes.c_uint64(folded),
            ctypes.c_uint64(device[2]),
            ctypes.c_uint64(device[3]),
            ctypes.c_uint64(device[4]),
            ctypes.c_uint64(device[5]),
        ]
        second_params = (ctypes.c_void_p * 9)(
            *(ctypes.cast(ctypes.byref(value), ctypes.c_void_p) for value in second_values),
            ctypes.cast(ctypes.byref(count_value), ctypes.c_void_p),
            ctypes.cast(ctypes.byref(partial_value), ctypes.c_void_p),
        )
        second_times = []
        for run in range(11):
            start = time.perf_counter()
            ck(
                rt.cuda.cuLaunchKernel(
                    fold_fn,
                    (folded_count_value.value + block - 1) // block,
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
            ck(
                rt.cuda.cuLaunchKernel(
                    second_fn, blocks, 1, 1, block, 1, 1, 0, None, second_params, None
                ),
                "second_launch",
            )
            ck(rt.cuda.cuCtxSynchronize(), "second_sync")
            if run:
                second_times.append(time.perf_counter() - start)
        actual_second = read_partial()
        if actual_second != expected_second:
            for index, (want, got) in enumerate(zip(expected_second, actual_second)):
                if want != got:
                    raise SystemExit(
                        f"second_round_mismatch_coordinate={index} expected={want} actual={got}"
                    )
        first_times.sort()
        second_times.sort()
        first_median = first_times[len(first_times) // 2]
        second_median = second_times[len(second_times) // 2]
        print(f"terms={count}")
        print("first_round_all_48_coordinates_match=true")
        print("second_round_all_48_coordinates_match=true")
        print(f"blocks={blocks}")
        print(f"nvrtc_compile_seconds={compile_seconds:.6f}")
        print(f"first_round_kernel_median_seconds={first_median:.9f}")
        print(f"fold_plus_second_round_median_seconds={second_median:.9f}")
        print(f"first_round_terms_per_second={count / first_median:.3f}")
        print(
            f"device_bytes={sum(ctypes.sizeof(a) for a in arrays) + partial_size + folded_size}"
        )
    finally:
        rt.close()


if __name__ == "__main__":
    main()
