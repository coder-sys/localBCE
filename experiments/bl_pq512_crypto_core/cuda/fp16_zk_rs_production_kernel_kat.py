"""Standalone differential KATs for the production RS kernels.

These checks deliberately run outside each fresh proof.  Production binds the
exact Python, dependency, CUDA-module, and native-verifier identities, and Rust
independently verifies every proof result, so repeating deterministic kernel
KATs inside every receipt adds latency without strengthening acceptance.
"""

import os
import time
from pathlib import Path

import cuda_fp16_zk_rs_theorem8_1_k128_prototype as proof


def main():
    started = time.perf_counter()
    proof.verify_constant_shard_lagrange_kat()

    nvrtc = Path(os.environ.get("BL_NVRTC_BIN", ""))
    if not (nvrtc / "nvrtc64_120_0.dll").is_file():
        raise SystemExit("nvrtc_runtime_missing")
    runtime, compile_seconds = proof.compile_runtime(nvrtc)
    try:
        proof.core.bind_driver(runtime)
        allocator = proof.core.Allocator(runtime)
        kernels = {
            "initialize": proof.function(
                runtime,
                "initialize_batched_rs_coefficients",
            ),
            "coset": proof.function(runtime, "apply_rs_coset"),
            "reverse": proof.function(runtime, "bit_reverse_batched_rs"),
            "stage": proof.function(runtime, "ntt_stage_batched_rs"),
            "transpose": proof.function(
                runtime,
                "transpose_rs_rows_big_endian",
            ),
            "gather_nodes": proof.function(runtime, "gather_rs_nodes"),
            "canonicalize_masks": proof.function(
                runtime,
                "canonicalize_rs_mask_randomness",
            ),
        }
        expand = proof.function(runtime, "expand_rs_powers")
        proof.core.verify_small_batched_kat(
            runtime,
            allocator,
            kernels,
            expand,
        )
    finally:
        runtime.close()

    print("status=verified")
    print("evidence_class=production_rs_kernel_differential_kat")
    print("constant_shard_lagrange_kat=true")
    print("small_batched_rs_ntt_kat=true")
    print(f"runtime_compile_or_load_seconds={compile_seconds:.6f}")
    print(f"total_seconds={time.perf_counter() - started:.6f}")


if __name__ == "__main__":
    main()
