"""Nonactivating exact-Fp16 arithmetic screen for two Keccak GKR schedules.

This measures the canonical K128 group-term counts with the frozen M31/Fp16
tower. It compares the merged two-layer schedule (degree-11 theta) with the
relay-free seven-layer fan-in-two schedule. It is an arithmetic schedule
screen, not a proof or a transcript/PCS qualification.
"""

import ctypes
import os
import statistics
import time
from pathlib import Path

from cuda_fp16_tower_kat import CUDA, Runtime, ck


GROUP_COUNT = 8_192
STATE_BITS = 1_600
RELAY_FREE_RAW_WIDTH_PER_ROUND = 6_400
RELAY_FREE_SOURCE_WIDTH_PER_ROUND = 20_480
TERNARY_THETA_RAW_WIDTH_PER_ROUND = 1_600
TERNARY_THETA_FANIN_TWO_RAW_WIDTH_PER_ROUND = 4_480
TERNARY_THETA_TOTAL_RAW_WIDTH_PER_ROUND = 6_080
TERNARY_THETA_SOURCE_WIDTH_PER_ROUND = 19_456
KECCAK_ROUNDS = 24
SOURCE_VALUES = 2_048 * GROUP_COUNT
CHUNK_TERMS = 2_097_152
THREADS = 256

KERNEL = (
    CUDA
    + r"""
__device__ __forceinline__ F16 a16(F16 x,F16 y){return {a8(x.a,y.a),a8(x.b,y.b)};}
__device__ __forceinline__ F16 s16(F16 x,F16 y){return {s8(x.a,y.a),s8(x.b,y.b)};}
__device__ __forceinline__ F16 n16(F16 x){
    F16 z={};
    return s16(z,x);
}
__device__ __forceinline__ F16 d16(F16 x){return a16(x,x);}

__device__ __forceinline__ F16 source_at(
    const u32* source,
    u64 term,
    u32 salt,
    u32 side
) {
    u64 mixed = term * 11400714819323198485ULL
        + (u64)salt * 7046029254386353131ULL
        + (u64)side * 1609587929392839161ULL;
    return l16(source + 16ULL * (mixed & (16777216ULL - 1ULL)));
}

extern "C" __global__ void init_source(u32* source,u64 count) {
    u64 index=(u64)blockIdx.x*blockDim.x+threadIdx.x;
    if(index>=count) return;
    u32 words[16];
    u64 state=index*6364136223846793005ULL+1442695040888963407ULL;
    #pragma unroll
    for(u32 coordinate=0;coordinate<16U;++coordinate){
        state=state*6364136223846793005ULL+1442695040888963407ULL;
        words[coordinate]=(u32)((state^(state>>31))%2147483647ULL);
    }
    st16(source+16ULL*index,l16(words));
}

extern "C" __global__ void theta_terms(
    const u32* source,
    u32* output,
    u64 first_term,
    u64 term_count
) {
    u64 local=(u64)blockIdx.x*blockDim.x+threadIdx.x;
    if(local>=term_count) return;
    u64 term=first_term+local;
    F16 polynomial[12];
    #pragma unroll
    for(u32 degree=0;degree<12U;++degree) polynomial[degree]=F16{};
    F16 first_zero=source_at(source,term,0U,0U);
    F16 first_one=source_at(source,term,0U,1U);
    polynomial[0]=first_zero;
    polynomial[1]=s16(first_one,first_zero);
    u32 degree=1U;
    for(u32 input=1U;input<11U;++input){
        F16 zero=source_at(source,term,input,0U);
        F16 one=source_at(source,term,input,1U);
        F16 delta=s16(one,zero);
        F16 next[12];
        #pragma unroll
        for(u32 d=0;d<12U;++d) next[d]=F16{};
        for(u32 d=0;d<=degree+1U;++d){
            F16 value=F16{};
            if(d<=degree) value=a16(value,polynomial[d]);
            if(d==0U) value=a16(value,zero);
            if(d==1U) value=a16(value,delta);
            F16 product=F16{};
            if(d<=degree) product=a16(product,m16(polynomial[d],zero));
            if(d>0U) product=a16(product,m16(polynomial[d-1U],delta));
            next[d]=s16(value,d16(product));
        }
        #pragma unroll
        for(u32 d=0;d<12U;++d) polynomial[d]=next[d];
        ++degree;
    }
    F16 weight_zero=source_at(source,term,29U,0U);
    F16 weight_delta=s16(
        source_at(source,term,29U,1U),
        weight_zero
    );
    F16 checksum=F16{};
    for(u32 d=0;d<13U;++d){
        F16 coefficient=F16{};
        if(d<=11U) coefficient=a16(
            coefficient,m16(polynomial[d],weight_zero)
        );
        if(d>0U) coefficient=a16(
            coefficient,m16(polynomial[d-1U],weight_delta)
        );
        checksum=a16(checksum,coefficient);
    }
    st16(output+16ULL*local,checksum);
}

extern "C" __global__ void chi_terms(
    const u32* source,
    u32* output,
    u64 first_term,
    u64 term_count
) {
    u64 local=(u64)blockIdx.x*blockDim.x+threadIdx.x;
    if(local>=term_count) return;
    u64 term=first_term+local;
    F16 a0=source_at(source,term,41U,0U);
    F16 ad=s16(source_at(source,term,41U,1U),a0);
    F16 b0=source_at(source,term,43U,0U);
    F16 bd=s16(source_at(source,term,43U,1U),b0);
    F16 c0=source_at(source,term,47U,0U);
    F16 cd=s16(source_at(source,term,47U,1U),c0);

    F16 y0=s16(c0,m16(b0,c0));
    F16 y1=s16(cd,a16(m16(b0,cd),m16(bd,c0)));
    F16 y2=n16(m16(bd,cd));
    F16 q0=s16(a16(a0,y0),d16(m16(a0,y0)));
    F16 q1=s16(
        a16(ad,y1),
        d16(a16(m16(a0,y1),m16(ad,y0)))
    );
    F16 q2=s16(
        y2,
        d16(a16(m16(a0,y2),m16(ad,y1)))
    );
    F16 q3=n16(d16(m16(ad,y2)));
    if((term&127ULL)==0ULL){
        F16 one=F16{};
        one.a.a.a.a=1U;
        q0=s16(one,q0);
        q1=n16(q1);q2=n16(q2);q3=n16(q3);
    }
    F16 weight_zero=source_at(source,term,53U,0U);
    F16 weight_delta=s16(
        source_at(source,term,53U,1U),
        weight_zero
    );
    F16 q[4]={q0,q1,q2,q3};
    F16 checksum=F16{};
    for(u32 d=0;d<5U;++d){
        F16 coefficient=F16{};
        if(d<4U) coefficient=a16(coefficient,m16(q[d],weight_zero));
        if(d>0U) coefficient=a16(
            coefficient,m16(q[d-1U],weight_delta)
        );
        checksum=a16(checksum,coefficient);
    }
    st16(output+16ULL*local,checksum);
}

extern "C" __global__ void fanin_two_terms(
    const u32* source,
    u32* output,
    u64 first_term,
    u64 term_count
) {
    u64 local=(u64)blockIdx.x*blockDim.x+threadIdx.x;
    if(local>=term_count) return;
    u64 term=first_term+local;
    F16 x0=source_at(source,term,61U,0U);
    F16 xd=s16(source_at(source,term,61U,1U),x0);
    F16 y0=source_at(source,term,67U,0U);
    F16 yd=s16(source_at(source,term,67U,1U),y0);
    u32 kind=(u32)(term%3ULL);
    F16 q0,q1,q2;
    if(kind==0U){
        q0=s16(a16(x0,y0),d16(m16(x0,y0)));
        q1=s16(
            a16(xd,yd),
            d16(a16(m16(x0,yd),m16(xd,y0)))
        );
        q2=n16(d16(m16(xd,yd)));
    } else if(kind==1U) {
        q0=s16(y0,m16(x0,y0));
        q1=s16(yd,a16(m16(x0,yd),m16(xd,y0)));
        q2=n16(m16(xd,yd));
    } else {
        F16 one=F16{};
        one.a.a.a.a=1U;
        q0=s16(one,s16(a16(x0,y0),d16(m16(x0,y0))));
        q1=n16(s16(
            a16(xd,yd),
            d16(a16(m16(x0,yd),m16(xd,y0)))
        ));
        q2=d16(m16(xd,yd));
    }
    F16 weight_zero=source_at(source,term,71U,0U);
    F16 weight_delta=s16(
        source_at(source,term,71U,1U),
        weight_zero
    );
    F16 q[3]={q0,q1,q2};
    F16 checksum=F16{};
    for(u32 d=0;d<4U;++d){
        F16 coefficient=F16{};
        if(d<3U) coefficient=a16(coefficient,m16(q[d],weight_zero));
        if(d>0U) coefficient=a16(
            coefficient,m16(q[d-1U],weight_delta)
        );
        checksum=a16(checksum,coefficient);
    }
    st16(output+16ULL*local,checksum);
}

extern "C" __global__ void fanin_three_xor_terms(
    const u32* source,
    u32* output,
    u64 first_term,
    u64 term_count
) {
    u64 local=(u64)blockIdx.x*blockDim.x+threadIdx.x;
    if(local>=term_count) return;
    u64 term=first_term+local;
    F16 x0=source_at(source,term,101U,0U);
    F16 xd=s16(source_at(source,term,101U,1U),x0);
    F16 y0=source_at(source,term,103U,0U);
    F16 yd=s16(source_at(source,term,103U,1U),y0);
    F16 z0=source_at(source,term,107U,0U);
    F16 zd=s16(source_at(source,term,107U,1U),z0);

    F16 pair0=a16(a16(m16(x0,y0),m16(x0,z0)),m16(y0,z0));
    F16 pair1=a16(
        a16(
            a16(m16(x0,yd),m16(xd,y0)),
            a16(m16(x0,zd),m16(xd,z0))
        ),
        a16(m16(y0,zd),m16(yd,z0))
    );
    F16 pair2=a16(a16(m16(xd,yd),m16(xd,zd)),m16(yd,zd));
    F16 triple0=m16(m16(x0,y0),z0);
    F16 triple1=a16(
        a16(m16(m16(xd,y0),z0),m16(m16(x0,yd),z0)),
        m16(m16(x0,y0),zd)
    );
    F16 triple2=a16(
        a16(m16(m16(xd,yd),z0),m16(m16(xd,y0),zd)),
        m16(m16(x0,yd),zd)
    );
    F16 triple3=m16(m16(xd,yd),zd);
    F16 q[4]={
        a16(
            s16(a16(a16(x0,y0),z0),d16(pair0)),
            d16(d16(triple0))
        ),
        a16(
            s16(a16(a16(xd,yd),zd),d16(pair1)),
            d16(d16(triple1))
        ),
        a16(n16(d16(pair2)),d16(d16(triple2))),
        d16(d16(triple3))
    };
    F16 weight_zero=source_at(source,term,109U,0U);
    F16 weight_delta=s16(
        source_at(source,term,109U,1U),
        weight_zero
    );
    F16 checksum=F16{};
    for(u32 d=0;d<5U;++d){
        F16 coefficient=F16{};
        if(d<4U) coefficient=a16(coefficient,m16(q[d],weight_zero));
        if(d>0U) coefficient=a16(
            coefficient,m16(q[d-1U],weight_delta)
        );
        checksum=a16(checksum,coefficient);
    }
    st16(output+16ULL*local,checksum);
}

extern "C" __global__ void fold_terms(
    const u32* source,
    u32* output,
    u64 first_term,
    u64 term_count
) {
    u64 local=(u64)blockIdx.x*blockDim.x+threadIdx.x;
    if(local>=term_count) return;
    u64 term=first_term+local;
    u64 pair=term&((16777216ULL/2ULL)-1ULL);
    F16 zero=l16(source+16ULL*(2ULL*pair));
    F16 one=l16(source+16ULL*(2ULL*pair+1ULL));
    F16 challenge=l16(source);
    st16(output+16ULL*local,a16(zero,m16(challenge,s16(one,zero))));
}

extern "C" __global__ void packed_weight_terms(
    const u32* source,
    u32* output,
    u64 first_term,
    u64 term_count
) {
    u64 local=(u64)blockIdx.x*blockDim.x+threadIdx.x;
    if(local>=term_count) return;
    u64 term=first_term+local;
    F16 wire=source_at(source,term,89U,0U);
    F16 group=source_at(source,term,97U,0U);
    st16(output+16ULL*local,m16(wire,group));
}
"""
)


def function(runtime, name):
    result = ctypes.c_void_p()
    ck(
        runtime.cuda.cuModuleGetFunction(
            ctypes.byref(result), runtime.module, name.encode()
        ),
        f"{name}_function",
    )
    return result


def arguments(*values):
    return (ctypes.c_void_p * len(values))(
        *(ctypes.cast(ctypes.byref(value), ctypes.c_void_p) for value in values)
    )


def launch(runtime, function_handle, blocks, parameters, label):
    ck(
        runtime.cuda.cuLaunchKernel(
            function_handle,
            blocks,
            1,
            1,
            THREADS,
            1,
            1,
            0,
            None,
            parameters,
            None,
        ),
        label,
    )


def measure_terms(runtime, function_handle, source, output, count, label):
    elapsed = []
    for repetition in range(3):
        started = time.perf_counter()
        first = 0
        while first < count:
            chunk = min(CHUNK_TERMS, count - first)
            parameters = arguments(
                ctypes.c_uint64(source),
                ctypes.c_uint64(output),
                ctypes.c_uint64(first),
                ctypes.c_uint64(chunk),
            )
            launch(
                runtime,
                function_handle,
                (chunk + THREADS - 1) // THREADS,
                parameters,
                label,
            )
            first += chunk
        ck(runtime.cuda.cuCtxSynchronize(), f"{label}_sync")
        elapsed.append(time.perf_counter() - started)
    return statistics.median(elapsed), elapsed


def main():
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
        raise SystemExit("nvrtc_runtime_missing")

    merged_terms = STATE_BITS * (GROUP_COUNT - 1)
    relay_terms = RELAY_FREE_RAW_WIDTH_PER_ROUND * (GROUP_COUNT - 1)
    relay_fold_values = RELAY_FREE_SOURCE_WIDTH_PER_ROUND * (GROUP_COUNT - 1)
    relay_packed_terms = RELAY_FREE_RAW_WIDTH_PER_ROUND * GROUP_COUNT
    ternary_theta_fanin_two_terms = (
        TERNARY_THETA_FANIN_TWO_RAW_WIDTH_PER_ROUND * (GROUP_COUNT - 1)
    )
    ternary_theta_terms = TERNARY_THETA_RAW_WIDTH_PER_ROUND * (GROUP_COUNT - 1)
    ternary_theta_fold_values = (
        TERNARY_THETA_SOURCE_WIDTH_PER_ROUND * (GROUP_COUNT - 1)
    )
    ternary_theta_packed_terms = (
        TERNARY_THETA_TOTAL_RAW_WIDTH_PER_ROUND * GROUP_COUNT
    )
    runtime = Runtime(nvrtc)
    try:
        compile_started = time.perf_counter()
        runtime.compile(KERNEL, b"init_source")
        compile_seconds = time.perf_counter() - compile_started
        init = function(runtime, "init_source")
        theta = function(runtime, "theta_terms")
        chi = function(runtime, "chi_terms")
        fanin = function(runtime, "fanin_two_terms")
        fanin_three = function(runtime, "fanin_three_xor_terms")
        fold = function(runtime, "fold_terms")
        packed = function(runtime, "packed_weight_terms")

        source_size = SOURCE_VALUES * 64
        output_size = CHUNK_TERMS * 64
        source = runtime.alloc(source_size)
        output = runtime.alloc(output_size)
        parameters = arguments(
            ctypes.c_uint64(source), ctypes.c_uint64(SOURCE_VALUES)
        )
        launch(
            runtime,
            init,
            (SOURCE_VALUES + THREADS - 1) // THREADS,
            parameters,
            "init_source",
        )
        ck(runtime.cuda.cuCtxSynchronize(), "init_source_sync")

        theta_seconds, theta_runs = measure_terms(
            runtime, theta, source, output, merged_terms, "theta_terms"
        )
        chi_seconds, chi_runs = measure_terms(
            runtime, chi, source, output, merged_terms, "chi_terms"
        )
        fanin_seconds, fanin_runs = measure_terms(
            runtime, fanin, source, output, relay_terms, "fanin_two_terms"
        )
        fold_seconds, fold_runs = measure_terms(
            runtime, fold, source, output, relay_fold_values, "fold_terms"
        )
        packed_seconds, packed_runs = measure_terms(
            runtime,
            packed,
            source,
            output,
            relay_packed_terms,
            "packed_weight_terms",
        )
        ternary_fanin_seconds, ternary_fanin_runs = measure_terms(
            runtime,
            fanin,
            source,
            output,
            ternary_theta_fanin_two_terms,
            "ternary_theta_fanin_two_terms",
        )
        ternary_theta_seconds, ternary_theta_runs = measure_terms(
            runtime,
            fanin_three,
            source,
            output,
            ternary_theta_terms,
            "fanin_three_xor_terms",
        )
        ternary_fold_seconds, ternary_fold_runs = measure_terms(
            runtime,
            fold,
            source,
            output,
            ternary_theta_fold_values,
            "ternary_theta_fold_terms",
        )
        ternary_packed_seconds, ternary_packed_runs = measure_terms(
            runtime,
            packed,
            source,
            output,
            ternary_theta_packed_terms,
            "ternary_theta_packed_terms",
        )

        merged_projection = KECCAK_ROUNDS * (theta_seconds + chi_seconds)
        relay_arithmetic_projection = KECCAK_ROUNDS * fanin_seconds
        relay_fold_projection = KECCAK_ROUNDS * fold_seconds
        relay_packed_projection = KECCAK_ROUNDS * packed_seconds
        relay_projection = (
            relay_arithmetic_projection
            + relay_fold_projection
            + relay_packed_projection
        )
        ternary_relation_projection = KECCAK_ROUNDS * (
            ternary_fanin_seconds + ternary_theta_seconds
        )
        ternary_fold_projection = KECCAK_ROUNDS * ternary_fold_seconds
        ternary_packed_projection = KECCAK_ROUNDS * ternary_packed_seconds
        ternary_projection = (
            ternary_relation_projection
            + ternary_fold_projection
            + ternary_packed_projection
        )
        print("scope=fp16_keccak_gkr_schedule_arithmetic_screen")
        print("evidence_class=measured_exact_field_exact_canonical_group_term_counts")
        print(f"group_count={GROUP_COUNT}")
        print(f"keccak_rounds={KECCAK_ROUNDS}")
        print(f"merged_terms_per_layer={merged_terms}")
        print(f"relay_free_terms_per_round={relay_terms}")
        print(f"relay_free_fold_values_per_round={relay_fold_values}")
        print(f"relay_free_packed_terms_per_round={relay_packed_terms}")
        print(
            "ternary_theta_fanin_two_terms_per_round="
            f"{ternary_theta_fanin_two_terms // (GROUP_COUNT - 1)}"
        )
        print(
            "ternary_theta_terms_per_round="
            f"{ternary_theta_terms // (GROUP_COUNT - 1)}"
        )
        print(
            "ternary_theta_fold_values_per_round="
            f"{ternary_theta_fold_values // (GROUP_COUNT - 1)}"
        )
        print(
            "ternary_theta_packed_terms_per_round="
            f"{ternary_theta_packed_terms // GROUP_COUNT}"
        )
        print(f"source_mb={source_size / 1_000_000:.6f}")
        print(f"output_chunk_mb={output_size / 1_000_000:.6f}")
        print(f"device_working_set_mb={(source_size + output_size) / 1_000_000:.6f}")
        print(f"compile_seconds={compile_seconds:.6f}")
        print(f"merged_theta_median_seconds={theta_seconds:.6f}")
        print("merged_theta_runs=" + ",".join(f"{value:.6f}" for value in theta_runs))
        print(f"merged_chi_median_seconds={chi_seconds:.6f}")
        print("merged_chi_runs=" + ",".join(f"{value:.6f}" for value in chi_runs))
        print(f"relay_free_median_seconds={fanin_seconds:.6f}")
        print("relay_free_runs=" + ",".join(f"{value:.6f}" for value in fanin_runs))
        print(f"relay_free_fold_median_seconds={fold_seconds:.6f}")
        print("relay_free_fold_runs=" + ",".join(f"{value:.6f}" for value in fold_runs))
        print(f"relay_free_packed_median_seconds={packed_seconds:.6f}")
        print("relay_free_packed_runs=" + ",".join(f"{value:.6f}" for value in packed_runs))
        print(f"ternary_theta_fanin_two_median_seconds={ternary_fanin_seconds:.6f}")
        print(
            "ternary_theta_fanin_two_runs="
            + ",".join(f"{value:.6f}" for value in ternary_fanin_runs)
        )
        print(f"ternary_theta_layer_median_seconds={ternary_theta_seconds:.6f}")
        print(
            "ternary_theta_layer_runs="
            + ",".join(f"{value:.6f}" for value in ternary_theta_runs)
        )
        print(f"ternary_theta_fold_median_seconds={ternary_fold_seconds:.6f}")
        print(
            "ternary_theta_fold_runs="
            + ",".join(f"{value:.6f}" for value in ternary_fold_runs)
        )
        print(f"ternary_theta_packed_median_seconds={ternary_packed_seconds:.6f}")
        print(
            "ternary_theta_packed_runs="
            + ",".join(f"{value:.6f}" for value in ternary_packed_runs)
        )
        print(f"merged_48_layer_arithmetic_projection_seconds={merged_projection:.6f}")
        print(
            "relay_free_168_layer_relation_projection_seconds="
            f"{relay_arithmetic_projection:.6f}"
        )
        print(
            "relay_free_168_layer_fold_projection_seconds="
            f"{relay_fold_projection:.6f}"
        )
        print(
            "relay_free_168_layer_packed_projection_seconds="
            f"{relay_packed_projection:.6f}"
        )
        print(f"relay_free_168_layer_combined_projection_seconds={relay_projection:.6f}")
        print(
            "ternary_theta_144_layer_relation_projection_seconds="
            f"{ternary_relation_projection:.6f}"
        )
        print(
            "ternary_theta_144_layer_fold_projection_seconds="
            f"{ternary_fold_projection:.6f}"
        )
        print(
            "ternary_theta_144_layer_packed_projection_seconds="
            f"{ternary_packed_projection:.6f}"
        )
        print(
            "ternary_theta_144_layer_combined_projection_seconds="
            f"{ternary_projection:.6f}"
        )
        print("frozen_fp16_field=true")
        print("proof_system_qualification=false")
    finally:
        runtime.close()


if __name__ == "__main__":
    main()
