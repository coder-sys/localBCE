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
run_step "Validate governed policy manifest" python3 "${ROOT_DIR}/scripts/validate_policy_manifest.py" "${ROOT_DIR}/ops/policy_manifest.example.json"
run_step "Validate OpenZeppelin source pin" python3 "${ROOT_DIR}/scripts/validate_openzeppelin_pin.py"
run_step "Scan tracked files for secrets" python3 "${ROOT_DIR}/scripts/scan_secrets.py"
run_step "Validate deterministic rules pipeline" bash "${ROOT_DIR}/scripts/validate_rules_pipeline.sh"

run_in_dir "Rust engine tests" "rust-engine" cargo test
run_in_dir "Rust engine check" "rust-engine" cargo check

run_in_dir "STARK engine tests" "stark-engine" cargo test
run_in_dir "STARK engine check" "stark-engine" cargo check
run_step "STARK bridge CLI chain smoke test" bash "${ROOT_DIR}/scripts/validate_stark_bridge_chain.sh"
run_step "STARK Solidity preview tests" bash "${ROOT_DIR}/scripts/validate_stark_solidity_preview.sh"

if [[ "${RUN_STARK_RUNTIME_SETTLEMENT:-0}" == "1" ]]; then
  run_step "Live STARK runtime settlement" \
    bash "${ROOT_DIR}/scripts/validate_stark_runtime_settlement.sh"
else
  echo
  echo "==> Live STARK runtime settlement skipped"
  echo "    Run with RUN_STARK_RUNTIME_SETTLEMENT=1 for disposable-chain integration."
fi

run_in_dir "Foundry tests" "blind-ledger" forge test
run_in_dir "Foundry build" "blind-ledger" forge build

echo
echo "==> localBCE validation passed"
