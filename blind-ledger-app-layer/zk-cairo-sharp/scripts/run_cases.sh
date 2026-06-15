#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.asdf/shims:$HOME/.local/bin:$HOME/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

cd "$(dirname "$0")/.."

run_case() {
  local name="$1"
  local args="$2"
  echo "===== CASE ${name} ====="
  scarb execute \
    --arguments "${args}" \
    --target standalone \
    --output standard \
    --print-program-output \
    --print-resource-usage
}

run_case "approved" "8001,1001,9001,9002,20260615,7001,1,1,1,1,1,1,1,12500,12500,12500,0,0,0,0,0,0,0,0,0"
run_case "ineligible_denied" "8002,1001,9001,9002,20260615,7001,1,0,1,1,1,1,1,12500,12500,12500,0,0,0,0,0,0,0,0,0"
run_case "duplicate_denied" "8003,1001,9001,9002,20260615,7001,1,1,1,1,1,1,1,12500,12500,12500,0,0,0,7001,0,0,0,0,0"
run_case "excessive_charge_denied" "8004,1001,9001,9002,20260615,7001,1,1,1,1,1,1,1,500001,500001,500001,0,0,0,0,0,0,0,0,0"
