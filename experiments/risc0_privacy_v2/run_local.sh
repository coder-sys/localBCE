#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/blind-ledger-risc0-privacy-v2-target}"
unset RISC0_DEV_MODE BONSAI_API_KEY BONSAI_API_URL

cd "$ROOT_DIR"

case "${1:-all}" in
    test)
        cargo test --workspace
        ;;
    prove)
        cargo run --release -p host
        ;;
    prove-cuda)
        if ! command -v nvcc >/dev/null 2>&1; then
            echo "CUDA toolkit unavailable: nvcc is not on PATH" >&2
            exit 2
        fi
        cargo run --release -p host --features cuda
        ;;
    all)
        cargo test --workspace
        cargo run --release -p host
        ;;
    *)
        echo "usage: $0 [test|prove|prove-cuda|all]" >&2
        exit 2
        ;;
esac
