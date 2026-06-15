#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.asdf/shims:$HOME/.local/bin:$HOME/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

cd "$(dirname "$0")/.."

run_case() {
  local name="$1"
  local args="$2"
  echo "===== ATTACK ${name} ====="
  scarb execute \
    --arguments "${args}" \
    --target standalone \
    --output standard \
    --print-program-output \
    --print-resource-usage
}

run_case_expect_reject() {
  local name="$1"
  local args="$2"
  echo "===== ATTACK ${name} EXPECT_REJECT ====="
  set +e
  scarb execute \
    --arguments "${args}" \
    --target standalone \
    --output standard \
    --print-program-output \
    --print-resource-usage
  local rc=$?
  set -e
  if [ "${rc}" -eq 0 ]; then
    echo "UNEXPECTED_ACCEPT"
    exit 1
  fi
  echo "REJECTED_AS_EXPECTED"
}

# Non-canonical truthy values should be rejected or canonicalized before proving.
run_case_expect_reject "noncanonical_truthy_presence_values" "8101,1001,9001,9002,20260615,7001,2,1,999,1,42,7,1,12500,12500,12500,0,0,0,0,0,0,0,0,0"

# A missing raw claim root means the normalized decision is not tied to a batch.
run_case_expect_reject "missing_raw_claim_root" "8102,1001,0,9002,20260615,7001,1,1,1,1,1,1,1,12500,12500,12500,0,0,0,0,0,0,0,0,0"

# A missing batch id means a copied proof could be replayed under fresh
# attribution, so it must be rejected before proving.
run_case_expect_reject "missing_batch_id" "0,1001,9001,9002,20260615,7001,1,1,1,1,1,1,1,12500,12500,12500,0,0,0,0,0,0,0,0,0"

# A malicious adapter can claim the normalized summary is clean even if raw claim
# data had a missing member/provider/service detail. This demonstrates that the
# Cairo executable still cannot derive normalized fields from raw claim bytes.
run_case "adapter_lies_clean_flags" "8103,1001,9001,9002,20260615,7001,1,1,1,1,1,1,1,12500,12500,12500,0,0,0,0,0,0,0,0,0"

# u32 max cents is accepted as input shape. It should deny as excessive, but any
# upstream cents conversion must fail closed instead of wrapping or truncating.
run_case "u32_max_charge_denies_excessive" "8104,1001,9001,9002,20260615,7001,1,1,1,1,1,1,1,4294967295,4294967295,4294967295,0,0,0,0,0,0,0,0,0"

# Zero service lines with positive total: G5 fails first. This checks the current
# first-failure behavior when downstream charge gates are underspecified.
run_case "zero_service_lines_positive_total" "8105,1001,9001,9002,20260615,7001,1,1,1,1,0,1,1,12500,0,0,0,0,0,0,0,0,0,0,0"

# The duplicate gate is now derived from the spent-nullifier witness. If the
# claim nullifier is already in the spent set, G9 fails with code 10.
run_case "spent_nullifier_replay_denied" "8106,1001,9001,9002,20260615,7001,1,1,1,1,1,1,1,12500,12500,12500,0,0,0,7001,0,0,0,0,0"
