#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/localbce-stark-runtime.XXXXXX")"
RPC_PORT="${LOCALBCE_STARK_TEST_PORT:-18546}"
RPC_URL="http://127.0.0.1:${RPC_PORT}"
SUBMITTER_PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
ATTESTOR_PRIVATE_KEY="0x00000000000000000000000000000000000000000000000000000000000a11ce"
export PATH="${HOME}/.cargo/bin:${HOME}/.foundry/bin:${PATH}"

if [[ -n "${CARGO_TARGET_DIR:-}" ]]; then
  mkdir -p "${CARGO_TARGET_DIR}"
  SHARED_TARGET_DIR="$(cd "${CARGO_TARGET_DIR}" && pwd)"
  STARK_EXECUTOR="${SHARED_TARGET_DIR}/debug/execute_production_stark_settlement"
  NULLIFIER_INITIALIZER="${SHARED_TARGET_DIR}/debug/initialize_production_nullifier_state"
  RUST_ENGINE="${SHARED_TARGET_DIR}/debug/rust-engine"
else
  STARK_EXECUTOR="${ROOT_DIR}/stark-engine/target/debug/execute_production_stark_settlement"
  NULLIFIER_INITIALIZER="${ROOT_DIR}/stark-engine/target/debug/initialize_production_nullifier_state"
  RUST_ENGINE="${ROOT_DIR}/rust-engine/target/debug/rust-engine"
fi

ANVIL_PID=""
cleanup() {
  if [[ -n "${ANVIL_PID}" ]]; then
    kill "${ANVIL_PID}" >/dev/null 2>&1 || true
    wait "${ANVIL_PID}" >/dev/null 2>&1 || true
  fi
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

for command in anvil cast cargo forge python3; do
  command -v "${command}" >/dev/null || {
    echo "missing required command: ${command}" >&2
    exit 1
  }
done

anvil --silent --port "${RPC_PORT}" >"${TMP_DIR}/anvil.log" 2>&1 &
ANVIL_PID=$!
for _ in $(seq 1 30); do
  if cast chain-id --rpc-url "${RPC_URL}" >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done
[[ "$(cast chain-id --rpc-url "${RPC_URL}")" == "31337" ]]

echo "==> Build STARK executor and Rust adjudicator"
(
  cd "${ROOT_DIR}/stark-engine"
  cargo build --features production-air-winterfell --bin execute_production_stark_settlement --jobs 1
  cargo build --features production-air-winterfell --bin initialize_production_nullifier_state --jobs 1
)
(
  cd "${ROOT_DIR}/rust-engine"
  cargo build --jobs 1
)

"${NULLIFIER_INITIALIZER}" \
  "${TMP_DIR}/nullifier_state.json"
INITIAL_ROOT="$(python3 - "${TMP_DIR}/nullifier_state.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    print(json.load(source)["root_bytes32"])
PY
)"
OWNER="$(cast wallet address --private-key "${SUBMITTER_PRIVATE_KEY}")"
ATTESTOR="$(cast wallet address --private-key "${ATTESTOR_PRIVATE_KEY}")"

echo "==> Deploy controlled-attestation STARK contracts"
(
  cd "${ROOT_DIR}/blind-ledger"
  forge create --rpc-url "${RPC_URL}" --private-key "${SUBMITTER_PRIVATE_KEY}" --broadcast --json \
    src/StarkAttestationVerifier.sol:StarkAttestationVerifier \
    --constructor-args "${OWNER}" "${ATTESTOR}" >"${TMP_DIR}/verifier_deployment.json"
)
VERIFIER="$(python3 - "${TMP_DIR}/verifier_deployment.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    print(json.load(source)["deployedTo"])
PY
)"
(
  cd "${ROOT_DIR}/blind-ledger"
  forge create --rpc-url "${RPC_URL}" --private-key "${SUBMITTER_PRIVATE_KEY}" --broadcast --json \
    src/StarkClaimsRegistry.sol:StarkClaimsRegistry \
    --constructor-args "${OWNER}" "${VERIFIER}" "${INITIAL_ROOT}" \
    >"${TMP_DIR}/registry_deployment.json"
)
REGISTRY="$(python3 - "${TMP_DIR}/registry_deployment.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    print(json.load(source)["deployedTo"])
PY
)"
cast send "${VERIFIER}" 'setRegistry(address)' "${REGISTRY}" \
  --private-key "${SUBMITTER_PRIVATE_KEY}" --rpc-url "${RPC_URL}" >/dev/null

python3 - \
  "${ROOT_DIR}/rust-engine/claim_input.json" \
  "${TMP_DIR}/approved_claim.json" \
  "${TMP_DIR}/denied_claim.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    approved = json.load(source)
approved["claim_id"] = "CLAIM-STARK-RUNTIME-APPROVED"
approved["is_duplicate"] = 0
approved["recipient_not_deceased"] = 1
with open(sys.argv[2], "w", encoding="utf-8") as target:
    json.dump(approved, target, indent=2)
    target.write("\n")

denied = dict(approved)
denied["claim_id"] = "CLAIM-STARK-RUNTIME-DENIED"
denied["recipient_not_deceased"] = 0
with open(sys.argv[3], "w", encoding="utf-8") as target:
    json.dump(denied, target, indent=2)
    target.write("\n")
PY

python3 - \
  "${TMP_DIR}/config.json" \
  "${STARK_EXECUTOR}" \
  "${REGISTRY}" "${VERIFIER}" "${TMP_DIR}/nullifier_state.json" \
  "${TMP_DIR}/runtime_artifacts" "${RPC_URL}" "${SUBMITTER_PRIVATE_KEY}" \
  "${ROOT_DIR}/rust-engine/rules_active_v1.json" \
  "95d38b6d8fc9c44b65feace024a07c22b4f11771fe6b23283ce73bbe0a7cb8e3" <<'PY'
import json
import sys

config = {
    "claims_registry_address": "0x0000000000000000000000000000000000000000",
    "private_key": sys.argv[8],
    "rpc_url": sys.argv[7],
    "transaction_value": "0.001ether",
    "enable_stark_sidecar_artifacts": False,
    "proof_backend": "stark_attested",
    "stark_engine_binary": sys.argv[2],
    "stark_claims_registry_address": sys.argv[3],
    "stark_attestation_verifier_address": sys.argv[4],
    "stark_nullifier_state_path": sys.argv[5],
    "stark_artifacts_directory": sys.argv[6],
    "stark_chain_id": 31337,
    "stark_runtime_mode": "local_test",
    "stark_attestor_mode": "local_private_key",
    "stark_finality_mode": "mined",
    "stark_finality_timeout_seconds": 30,
    "stark_finality_poll_seconds": 1,
    "stark_allow_test_mined_finality": False,
    "rules_backend": "versioned_g1_g10",
    "rules_file": sys.argv[9],
    "rules_sha256": sys.argv[10],
}
with open(sys.argv[1], "w", encoding="utf-8") as target:
    json.dump(config, target, indent=2)
    target.write("\n")
PY

run_claim() {
  local claim_path="$1"
  (
    cd "${TMP_DIR}"
    LOCALBCE_CONFIG_PATH="${TMP_DIR}/config.json" \
    LOCALBCE_CLAIM_INPUT_PATH="${claim_path}" \
    STARK_ATTESTOR_PRIVATE_KEY="${ATTESTOR_PRIVATE_KEY}" \
      "${RUST_ENGINE}"
  )
}

echo "==> Approved claim through rust-engine STARK runtime"
run_claim "${TMP_DIR}/approved_claim.json"
python3 - "${TMP_DIR}/adjudication_result.json" "${TMP_DIR}/nullifier_state.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    result = json.load(source)
with open(sys.argv[2], encoding="utf-8") as source:
    state = json.load(source)
assert result["status"] == "APPROVED"
assert result["tx_submitted"] is True
assert result["tx_hash"].startswith("0x")
assert state["generation"] == 1
assert len(state["leaves"]) == 1
PY

echo "==> Denied claim through rust-engine STARK runtime"
run_claim "${TMP_DIR}/denied_claim.json"
python3 - "${TMP_DIR}/adjudication_result.json" "${TMP_DIR}/nullifier_state.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    result = json.load(source)
with open(sys.argv[2], encoding="utf-8") as source:
    state = json.load(source)
assert result["status"] == "DENIED"
assert result["reason"] == "G9_RECIPIENT_DECEASED"
assert result["tx_submitted"] is True
assert result["tx_hash"].startswith("0x")
assert state["generation"] == 1
assert len(state["leaves"]) == 1
PY

[[ "$(cast call "${REGISTRY}" 'approvedClaims()(uint256)' --rpc-url "${RPC_URL}")" == "1" ]]
[[ "$(cast call "${REGISTRY}" 'deniedClaims()(uint256)' --rpc-url "${RPC_URL}")" == "1" ]]
ON_CHAIN_ROOT="$(cast call "${REGISTRY}" 'currentNullifierRoot()(bytes32)' --rpc-url "${RPC_URL}")"
LOCAL_ROOT="$(python3 - "${TMP_DIR}/nullifier_state.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    print(json.load(source)["root_bytes32"])
PY
)"
[[ "${ON_CHAIN_ROOT,,}" == "${LOCAL_ROOT,,}" ]]

echo "==> Replay rejected before settlement/state mutation"
if run_claim "${TMP_DIR}/approved_claim.json" >"${TMP_DIR}/replay.log" 2>&1; then
  echo "approved claim replay unexpectedly succeeded" >&2
  exit 1
fi
grep -Eq "duplicate|nullifier|collision" "${TMP_DIR}/replay.log"
[[ "$(cast call "${REGISTRY}" 'approvedClaims()(uint256)' --rpc-url "${RPC_URL}")" == "1" ]]

echo
echo "STARK runtime settlement validation passed"
echo "- real Winterfell proof generated and locally verified"
echo "- approved and denied claims settled through rust-engine"
echo "- controlled attestation verified on-chain"
echo "- persistent nullifier state matches the registry"
echo "- replay rejected"
echo "- Groth16 was not executed"
