"""Measure the bounded host/device transfer schedule for initial PCS oracles.

This is a nonactivating resource and throughput benchmark.  It models the
release schedule in which one host codeword buffer is reused while each
committed codeword remains resident in a distinct device allocation.  The
benchmark does not implement BaseFold, Merkle commitments, or a proof.
"""

import array
import ctypes
import os
import sys
import time
from pathlib import Path

from cuda_dag_packed_accumulator_benchmark import copy, process_peak_mb
from cuda_fp16_tower_kat import Runtime, ck


KERNEL = r"""
extern "C" __global__ void no_op(unsigned long long *value) {
    if (blockIdx.x == 0 && threadIdx.x == 0) value[0] ^= 0ULL;
}
"""


def main():
    oracle_count = int(sys.argv[1]) if len(sys.argv) > 1 else 6
    log_codeword_values = int(sys.argv[2]) if len(sys.argv) > 2 else 23
    if oracle_count < 1 or oracle_count > 16:
        raise SystemExit(
            "usage: cuda_pcs_oracle_residency_benchmark.py "
            "[oracle_count=1..16] [log_codeword_values=1..27]"
        )
    if log_codeword_values < 1 or log_codeword_values > 27:
        raise SystemExit(
            "usage: cuda_pcs_oracle_residency_benchmark.py "
            "[oracle_count=1..16] [log_codeword_values=1..27]"
        )

    value_count = 1 << log_codeword_values
    words_per_value = 2
    word_count = value_count * words_per_value
    host = array.array("Q", [0]) * word_count
    codeword_size = len(host) * host.itemsize
    nvrtc_override = os.environ.get("BL_CUDA_NVRTC_DIR")
    nvrtc = (
        Path(nvrtc_override)
        if nvrtc_override
        else Path(__file__).parent
        / "cuda_nvrtc"
        / "nvidia"
        / "cuda_nvrtc"
        / "bin"
    )

    runtime = Runtime(nvrtc)
    try:
        runtime.compile(KERNEL, b"no_op")
        device = [runtime.alloc(codeword_size) for _ in range(oracle_count)]

        upload_started = time.perf_counter()
        for oracle in range(oracle_count):
            marker = 0xB11D_0000_0000_0000 | oracle
            host[0] = marker
            host[-1] = marker ^ 0xFFFF_FFFF_FFFF_FFFF
            copy(runtime, device[oracle], host, f"upload_oracle_{oracle}")
        upload_seconds = time.perf_counter() - upload_started

        host_view = (ctypes.c_ubyte * codeword_size).from_buffer(host)
        replay_started = time.perf_counter()
        verified = 0
        for oracle in range(oracle_count):
            ck(
                runtime.cuda.cuMemcpyDtoH_v2(
                    ctypes.cast(host_view, ctypes.c_void_p),
                    device[oracle],
                    codeword_size,
                ),
                f"replay_oracle_{oracle}",
            )
            marker = 0xB11D_0000_0000_0000 | oracle
            if host[0] != marker:
                raise SystemExit(f"first_marker_mismatch_oracle_{oracle}")
            if host[-1] != marker ^ 0xFFFF_FFFF_FFFF_FFFF:
                raise SystemExit(f"last_marker_mismatch_oracle_{oracle}")
            verified += 1
        replay_seconds = time.perf_counter() - replay_started

        total_size = oracle_count * codeword_size
        total_seconds = upload_seconds + replay_seconds
        print("benchmark=pcs_oracle_residency_transfer_v1")
        print(f"oracle_count={oracle_count}")
        print(f"values_per_oracle={value_count}")
        print(f"codeword_mb={codeword_size / 1_000_000:.6f}")
        print(f"device_resident_mb={total_size / 1_000_000:.6f}")
        print(f"host_reused_buffer_mb={codeword_size / 1_000_000:.6f}")
        print(f"upload_seconds={upload_seconds:.6f}")
        print(f"replay_seconds={replay_seconds:.6f}")
        print(f"transfer_total_seconds={total_seconds:.6f}")
        print(f"host_peak_mb={process_peak_mb():.3f}")
        print(f"verified_oracles={verified}")
        print("qualification=false")
    finally:
        runtime.close()


if __name__ == "__main__":
    main()
