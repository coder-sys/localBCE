#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

export PATH="${HOME}/.foundry/bin:${HOME}/.cargo/bin:${PATH}"

run_step() {
  local label="$1"
  shift

  echo
  echo "==> ${label}"
  "$@"
}

run_in_dir() {
  local label="$1"
  local dir="$2"
  shift 2

  echo
  echo "==> ${label}"
  (
    cd "${ROOT_DIR}/${dir}"
    "$@"
  )
}

run_step "Validate ops scaffold" python3 "${ROOT_DIR}/scripts/validate_ops_scaffold.py"

run_in_dir "Rust engine tests" "rust-engine" cargo test
run_in_dir "Rust engine check" "rust-engine" cargo check

run_in_dir "STARK engine tests" "stark-engine" cargo test
run_in_dir "STARK engine check" "stark-engine" cargo check

run_in_dir "Foundry tests" "blind-ledger" forge test
run_in_dir "Foundry build" "blind-ledger" forge build

echo
echo "==> localBCE validation passed"
