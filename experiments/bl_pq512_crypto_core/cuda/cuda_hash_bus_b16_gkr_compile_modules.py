"""Build deterministic sm_89 CUBINs for the production B16 GKR worker."""

import hashlib
import os
import sys
from pathlib import Path

import cuda_fp16_zk_rs_interleaved_k128_prototype as core
import cuda_hash_bus_b16_gkr_worker as worker


MODULES = (
    ("hash-bus-gkr-bridge-sm89.cubin", worker.BRIDGE_KERNEL),
    (
        "hash-bus-gkr-group-sm89.cubin",
        worker.CUDA + worker.FOLD_KERNEL + worker.MESSAGE_KERNEL,
    ),
    ("hash-bus-gkr-worker-sm89.cubin", worker.WORKER_KERNEL),
)


def main():
    if len(sys.argv) != 2:
        raise SystemExit(
            "usage: cuda_hash_bus_b16_gkr_compile_modules.py OUTPUT_DIRECTORY"
        )
    nvrtc = Path(os.environ.get("BL_NVRTC_BIN", ""))
    if not (nvrtc / "nvrtc64_120_0.dll").is_file():
        raise SystemExit("nvrtc_runtime_missing")
    output_directory = Path(sys.argv[1])
    if not output_directory.is_dir():
        raise SystemExit("output_directory_missing")
    for name, source in MODULES:
        path = output_directory / name
        core.compile_source_to_cubin(nvrtc, source, path)
        image = path.read_bytes()
        if image[:4] != b"\x7fELF":
            raise SystemExit(f"cuda_module_not_cubin={name}")
        print(
            f"{name}_sha256={hashlib.sha256(image).hexdigest()}"
        )
        print(f"{name}_bytes={len(image)}")


if __name__ == "__main__":
    main()
