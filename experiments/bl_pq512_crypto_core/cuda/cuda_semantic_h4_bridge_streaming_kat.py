"""Sub-second GPU KAT for the semantic/H4 streaming group polynomial."""

import array
import ctypes
import os
from pathlib import Path

from cuda_dag_shared_group_fold_benchmark import kernel_arguments
from cuda_fp16_tower_kat import CUDA, Q, Runtime, ck


KERNEL = CUDA + r"""
__device__ __forceinline__ F16 a16(F16 x,F16 y){return {a8(x.a,y.a),a8(x.b,y.b)};}
__device__ __forceinline__ F16 s16(F16 x,F16 y){return {s8(x.a,y.a),s8(x.b,y.b)};}
__device__ __forceinline__ F16 z16(){F16 value={};return value;}
__device__ __forceinline__ F16 b16(unsigned int value){F16 x={};x.a.a.a.a=value;return x;}
extern "C" __global__ void semantic_bridge_two_group_kat(unsigned int *out) {
    if (blockIdx.x != 0U || threadIdx.x != 0U) return;
    F16 left0=b16(2U), left_delta=b16(2U);
    F16 right0=b16(3U), right_delta=b16(2U);
    F16 eq0=s16(b16(1U),b16(7U)), eq_delta=s16(b16(14U),b16(1U));
    F16 q0=m16(left0,right0);
    F16 q1=a16(m16(left0,right_delta),m16(left_delta,right0));
    F16 q2=m16(left_delta,right_delta);
    st16(out,m16(eq0,q0));
    st16(out+16,a16(m16(eq0,q1),m16(eq_delta,q0)));
    st16(out+32,a16(m16(eq0,q2),m16(eq_delta,q1)));
    st16(out+48,m16(eq_delta,q2));
}

__device__ __forceinline__ unsigned int packed_bit(
    const unsigned short *plane,
    unsigned int permutation,
    unsigned int wire
) {
    return (plane[wire + 1600U * (permutation >> 4U)] >> (permutation & 15U)) & 1U;
}

extern "C" __global__ void semantic_bridge_source_kat(
    const unsigned short *input,
    const unsigned short *output,
    const unsigned char *message,
    const unsigned char *digest,
    unsigned int *out
) {
    if (blockIdx.x != 0U || threadIdx.x != 0U) return;
    // One 75-byte call occupies two rate blocks. These checks pin the exact
    // source coordinates used by the Rust adapter without a boundary file.
    unsigned int byte = 3U;
    unsigned int rate[7] = {
        1U, // live
        1U, // previous live
        1U, // block active
        1U, // next block active: current block's final byte is live
        message[byte],
        packed_bit(input, 0U, 8U * byte + 0U),
        0U  // block-zero predecessor is verifier-fixed zero
    };
    for (unsigned int i = 0; i < 7U; ++i) st16(out + 16U * i, b16(rate[i]));

    unsigned int digest_byte = 5U;
    unsigned int actual = 0U;
    for (unsigned int bit = 0; bit < 8U; ++bit) {
        actual |= packed_bit(output, 1U, 8U * digest_byte + bit) << bit;
    }
    unsigned int values[6] = {
        1U, // active block zero
        1U, // active block one
        1U, // next-active from block zero
        0U, // next-active from block one
        actual,
        digest[digest_byte]
    };
    for (unsigned int i = 0; i < 6U; ++i) st16(out + 16U * (7U + i), b16(values[i]));
    unsigned int block_values[4] = {
        1U, // second block active because message byte 71 is live
        packed_bit(input, 1U, 17U),
        packed_bit(input, 1U, 576U + 9U),
        packed_bit(output, 0U, 576U + 9U)
    };
    for (unsigned int i = 0; i < 4U; ++i) st16(out + 16U * (13U + i), b16(block_values[i]));
}
"""


def upload(runtime, values):
    view = (ctypes.c_ubyte * (len(values) * values.itemsize)).from_buffer(values)
    device = runtime.alloc(len(view))
    ck(
        runtime.cuda.cuMemcpyHtoD_v2(
            device, ctypes.cast(view, ctypes.c_void_p), len(view)
        ),
        "upload_source_kat",
    )
    return device


def main():
    configured_nvrtc = os.environ.get("BL_NVRTC_BIN")
    nvrtc = Path(configured_nvrtc) if configured_nvrtc else Path("__missing_nvrtc__")
    if not nvrtc.is_dir():
        nvrtc = Path(__file__).parent / "cuda_nvrtc" / "nvidia" / "cuda_nvrtc" / "bin"
    runtime = Runtime(nvrtc)
    try:
        module = runtime.compile_module(KERNEL)
        polynomial_function = runtime.module_function(module, b"semantic_bridge_two_group_kat")
        source_function = runtime.module_function(module, b"semantic_bridge_source_kat")
        device = runtime.alloc(4 * 64)
        arguments = kernel_arguments(ctypes.c_uint64(device))
        ck(runtime.cuda.cuLaunchKernel(polynomial_function, 1, 1, 1, 1, 1, 1, 0, None, arguments, None), "launch")
        ck(runtime.cuda.cuCtxSynchronize(), "sync")
        output = array.array("I", [0]) * 64
        view = (ctypes.c_ubyte * (len(output) * output.itemsize)).from_buffer(output)
        ck(runtime.cuda.cuMemcpyDtoH_v2(ctypes.cast(view, ctypes.c_void_p), device, len(view)), "copy_output")
        expected = ((Q - 36) % Q, 18, 106, 52)
        actual = tuple(output[16 * index] for index in range(4))
        if actual != expected or any(
            output[16 * index + coordinate] != 0
            for index in range(4)
            for coordinate in range(1, 16)
        ):
            raise RuntimeError(f"semantic_bridge_streaming_kat:{actual}/{expected}")

        input_plane = array.array("H", [0]) * (1600 * 2)
        output_plane = array.array("H", [0]) * (1600 * 2)
        # input permutation zero, byte three, low bit = 1
        input_plane[8 * 3] = 1
        input_plane[17] |= 2
        input_plane[576 + 9] |= 2
        output_plane[576 + 9] |= 1
        # output permutation one, byte five = 0xa6
        for bit in range(8):
            if (0xA6 >> bit) & 1:
                output_plane[8 * 5 + bit] = 2
        message = array.array("B", range(75))
        digest = array.array("B", [0]) * 64
        digest[5] = 0x5C
        source_output = runtime.alloc(17 * 64)
        source_args_values = [
            ctypes.c_uint64(upload(runtime, input_plane)),
            ctypes.c_uint64(upload(runtime, output_plane)),
            ctypes.c_uint64(upload(runtime, message)),
            ctypes.c_uint64(upload(runtime, digest)),
            ctypes.c_uint64(source_output),
        ]
        source_args = (ctypes.c_void_p * len(source_args_values))(
            *(ctypes.cast(ctypes.byref(value), ctypes.c_void_p) for value in source_args_values)
        )
        ck(runtime.cuda.cuLaunchKernel(source_function, 1, 1, 1, 1, 1, 1, 0, None, source_args, None), "source_launch")
        ck(runtime.cuda.cuCtxSynchronize(), "source_sync")
        source_words = array.array("I", [0]) * (17 * 16)
        source_view = (ctypes.c_ubyte * (len(source_words) * source_words.itemsize)).from_buffer(source_words)
        ck(runtime.cuda.cuMemcpyDtoH_v2(ctypes.cast(source_view, ctypes.c_void_p), source_output, len(source_view)), "source_copy")
        source_actual = tuple(source_words[16 * index] for index in range(17))
        source_expected = (1, 1, 1, 1, 3, 1, 0, 1, 1, 1, 0, 0xA6, 0x5C, 1, 1, 1, 1)
        if source_actual != source_expected or any(
            source_words[16 * index + coordinate] != 0
            for index in range(17)
            for coordinate in range(1, 16)
        ):
            raise RuntimeError(f"semantic_bridge_source_kat:{source_actual}/{source_expected}")
        print("status=verified")
        print("polynomial=-36,18,106,52")
        print("source_mapping=rate_inactive_capacity_digest_verified")
        print("gpu_authority=none")
        print("proofSuiteId=null")
        print("production_usable=false")
        print("activation=false")
    finally:
        runtime.close()


if __name__ == "__main__":
    main()
