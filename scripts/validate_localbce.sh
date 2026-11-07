#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

export PATH="${HOME}/.cargo/bin:${PATH}"

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

# Proof and chain validation (STARK, Foundry, Sepolia, OpenZeppelin) is parked
# with its code under parked/localbce/; see docs/integration/RIGHTRAIL_BASE_PLAN.md.
run_step "Parking guard and script tests" python3 -m unittest discover -s "${ROOT_DIR}/scripts/tests" -p 'test_*.py'
run_step "Integration tests" python3 -m unittest discover -s "${ROOT_DIR}/tests" -p 'test_*.py'
run_step "Validate ops scaffold" python3 "${ROOT_DIR}/scripts/validate_ops_scaffold.py"
run_step "Scan tracked files for secrets" python3 "${ROOT_DIR}/scripts/scan_secrets.py"
run_step "Validate deterministic rules pipeline" bash "${ROOT_DIR}/scripts/validate_rules_pipeline.sh"

run_in_dir "Rust engine tests" "rust-engine" cargo test
run_in_dir "Rust engine check" "rust-engine" cargo check

echo
echo "==> localBCE validation passed"
