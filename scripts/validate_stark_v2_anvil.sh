#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/localbce-stark-v2.XXXXXX")"
RPC_PORT="${LOCALBCE_STARK_V2_TEST_PORT:-18547}"
RPC_URL="http://127.0.0.1:${RPC_PORT}"
CHAIN_ID=31337
DEPLOYER_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
ATTESTOR_KEY="0x00000000000000000000000000000000000000000000000000000000000a11ce"
export PATH="${HOME}/.cargo/bin:${HOME}/.foundry/bin:${PATH}"

ANVIL_PID=""
cleanup() {
  if [[ -n "${ANVIL_PID}" ]]; then
    kill "${ANVIL_PID}" >/dev/null 2>&1 || true
    wait "${ANVIL_PID}" >/dev/null 2>&1 || true
  fi
  rm -rf "${TMP_DIR}"
  rm -f "${ROOT_DIR}/blind-ledger/stark_v2_deployment.json"
}
trap cleanup EXIT

for command in anvil cast cargo forge python3; do
  command -v "${command}" >/dev/null || { echo "missing required command: ${command}" >&2; exit 1; }
done
POLICY_HASH="$(python3 - "${ROOT_DIR}/ops/policy_manifest.example.json" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["canonical_hash"])
PY
)"

anvil --silent --chain-id "${CHAIN_ID}" --port "${RPC_PORT}" >"${TMP_DIR}/anvil.log" 2>&1 &
ANVIL_PID=$!
ANVIL_READY=0
for _ in $(seq 1 5000); do
  if (: >"/dev/tcp/127.0.0.1/${RPC_PORT}") 2>/dev/null; then
    ANVIL_READY=1
    break
  fi
  kill -0 "${ANVIL_PID}" >/dev/null 2>&1 || break
done
if [[ "${ANVIL_READY}" != "1" ]]; then
  cat "${TMP_DIR}/anvil.log" >&2
  echo "disposable Anvil did not become ready on port ${RPC_PORT}" >&2
  exit 1
fi
[[ "$(cast chain-id --rpc-url "${RPC_URL}")" == "${CHAIN_ID}" ]]

echo "==> Build governed STARK runtime"
(
  cd "${ROOT_DIR}/stark-engine"
  cargo build --features production-air-winterfell \
    --bin execute_production_stark_settlement \
    --bin initialize_production_nullifier_state \
    --bin reconcile_production_stark_settlement --jobs 1
)
(
  cd "${ROOT_DIR}/rust-engine"
  cargo build --jobs 1
)
STARK_EXECUTOR="${ROOT_DIR}/stark-engine/target/debug/execute_production_stark_settlement"
STATE_INITIALIZER="${ROOT_DIR}/stark-engine/target/debug/initialize_production_nullifier_state"
RUST_ENGINE="${ROOT_DIR}/rust-engine/target/debug/rust-engine"
RECONCILER="${ROOT_DIR}/stark-engine/target/debug/reconcile_production_stark_settlement"

"${STATE_INITIALIZER}" "${TMP_DIR}/nullifier_state.json"
INITIAL_ROOT="$(python3 - "${TMP_DIR}/nullifier_state.json" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["root_bytes32"])
PY
)"
DEPLOYER="$(cast wallet address --private-key "${DEPLOYER_KEY}")"
ATTESTOR="$(cast wallet address --private-key "${ATTESTOR_KEY}")"

echo "==> Deploy governed V2 contracts"
(
  cd "${ROOT_DIR}/blind-ledger"
  STARK_GOVERNANCE_SAFE="${DEPLOYER}" \
  STARK_EMERGENCY_SAFE="${DEPLOYER}" \
  STARK_TREASURY="${DEPLOYER}" \
  STARK_ATTESTOR="${ATTESTOR}" \
  STARK_POLICY_MANIFEST_HASH="${POLICY_HASH}" \
  STARK_INITIAL_NULLIFIER_ROOT="${INITIAL_ROOT}" \
  STARK_DEPLOYER_PRIVATE_KEY="${DEPLOYER_KEY}" \
  STARK_ALLOW_LOCAL_TEST_CHAIN=true \
    forge script script/DeployStarkGovernedV2.s.sol:DeployStarkGovernedV2 \
      --rpc-url "${RPC_URL}" --broadcast >/dev/null
)
readarray -t DEPLOYED < <(python3 - "${ROOT_DIR}/blind-ledger/stark_v2_deployment.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
print(value["timelock"])
print(value["starkAttestationVerifierV2"])
print(value["starkClaimsRegistryV2"])
PY
)
TIMELOCK="${DEPLOYED[0]}"
VERIFIER="${DEPLOYED[1]}"
REGISTRY="${DEPLOYED[2]}"

echo "==> Execute delayed registry authorization"
CALLDATA="$(cast calldata 'setRegistryAuthorization(address,bool)' "${REGISTRY}" true)"
ZERO="0x$(printf '00%.0s' {1..32})"
SALT="0x$(printf '00%.0s' {1..31})01"
cast send "${TIMELOCK}" 'schedule(address,uint256,bytes,bytes32,bytes32,uint256)' \
  "${VERIFIER}" 0 "${CALLDATA}" "${ZERO}" "${SALT}" 259200 \
  --private-key "${DEPLOYER_KEY}" --rpc-url "${RPC_URL}" >/dev/null
cast rpc evm_increaseTime 259200 --rpc-url "${RPC_URL}" >/dev/null
cast rpc evm_mine --rpc-url "${RPC_URL}" >/dev/null
cast send "${TIMELOCK}" 'execute(address,uint256,bytes,bytes32,bytes32)' \
  "${VERIFIER}" 0 "${CALLDATA}" "${ZERO}" "${SALT}" \
  --private-key "${DEPLOYER_KEY}" --rpc-url "${RPC_URL}" >/dev/null
[[ "$(cast call "${VERIFIER}" 'authorizedRegistries(address)(bool)' "${REGISTRY}" --rpc-url "${RPC_URL}")" == "true" ]]

python3 - "${ROOT_DIR}/rust-engine/claim_input.json" "${TMP_DIR}" <<'PY'
import json, pathlib, sys
source = json.load(open(sys.argv[1], encoding="utf-8"))
out = pathlib.Path(sys.argv[2])
approved = dict(source)
approved.update(claim_id="CLAIM-STARK-V2-APPROVED", is_duplicate=0, recipient_not_deceased=1)
denied = dict(approved)
denied.update(claim_id="CLAIM-STARK-V2-DENIED", recipient_not_deceased=0)
for name, value in (("approved.json", approved), ("denied.json", denied)):
    (out / name).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
PY

python3 - "${TMP_DIR}/config.json" "${STARK_EXECUTOR}" "${REGISTRY}" "${VERIFIER}" \
  "${TMP_DIR}/nullifier_state.json" "${TMP_DIR}/runtime-artifacts" "${RPC_URL}" \
  "${DEPLOYER_KEY}" "${POLICY_HASH}" "${ATTESTOR}" "${ROOT_DIR}" <<'PY'
import json, sys
config = {
  "claims_registry_address": "0x0000000000000000000000000000000000000000",
  "private_key": sys.argv[8], "rpc_url": sys.argv[7], "transaction_value": "0.001ether",
  "enable_stark_sidecar_artifacts": False, "proof_backend": "stark_attested",
  "stark_engine_binary": sys.argv[2], "stark_claims_registry_address": sys.argv[3],
  "stark_attestation_verifier_address": sys.argv[4], "stark_nullifier_state_path": sys.argv[5],
  "stark_artifacts_directory": sys.argv[6], "stark_chain_id": 31337,
  "stark_attestor_mode": "external_command", "stark_attestor_signer_program": "/usr/bin/python3",
  "stark_attestor_signer_args": [sys.argv[11] + "/scripts/mock_mpc_attestation_signer.py", "--key-id", "anvil-mock-attestor-v1"],
  "stark_attestor_allowed_key_ids": ["anvil-mock-attestor-v1"], "stark_attestor_address": sys.argv[10],
  "stark_attestor_signer_timeout_seconds": 15, "stark_policy_manifest_hash": sys.argv[9],
  "stark_finality_mode": "test_mined", "stark_finality_timeout_seconds": 30,
  "stark_finality_poll_seconds": 1, "stark_allow_test_mined_finality": True,
  "rules_backend": "versioned_g1_g10",
  "rules_file": sys.argv[11] + "/rust-engine/rules_active_v1.json",
  "rules_sha256": "95d38b6d8fc9c44b65feace024a07c22b4f11771fe6b23283ce73bbe0a7cb8e3"
}
open(sys.argv[1], "w", encoding="utf-8").write(json.dumps(config, indent=2) + "\n")
PY

run_claim() {
  local claim="$1"
  (
    cd "${TMP_DIR}"
    LOCALBCE_CONFIG_PATH="${TMP_DIR}/config.json" \
    LOCALBCE_CLAIM_INPUT_PATH="${claim}" \
    STARK_MOCK_SIGNER_ACKNOWLEDGE_TEST_ONLY=1 \
    STARK_MOCK_ATTESTOR_PRIVATE_KEY="${ATTESTOR_KEY}" \
      "${RUST_ENGINE}"
  )
}

run_claim_with_finality() {
  local claim="$1"
  run_claim "${claim}"
}

echo "==> Approved and denied governed canaries"
run_claim_with_finality "${TMP_DIR}/approved.json" >/dev/null
python3 - "${TMP_DIR}/adjudication_result.json" "${TMP_DIR}/nullifier_state.json" <<'PY'
import json, sys
result = json.load(open(sys.argv[1], encoding="utf-8")); state = json.load(open(sys.argv[2], encoding="utf-8"))
assert result["status"] == "APPROVED" and result["tx_submitted"] is True
assert state["generation"] == 1 and len(state["leaves"]) == 1
PY

echo "==> Restart reconciliation and reorg failure injection"
APPROVED_CLAIM_HASH="$(python3 - "${TMP_DIR}/adjudication_result.json" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["claim_hash"])
PY
)"
APPROVED_ARTIFACT_DIR="${TMP_DIR}/runtime-artifacts/${APPROVED_CLAIM_HASH#0x}"
cp "${APPROVED_ARTIFACT_DIR}/settlement_journal.json" "${TMP_DIR}/approved_journal.json"
cp "${APPROVED_ARTIFACT_DIR}/nullifier_transition.json" "${TMP_DIR}/approved_transition.json"
STARK_CHAIN_ID="${CHAIN_ID}" STARK_FINALITY_MODE=test_mined \
  STARK_FINALITY_TIMEOUT_SECONDS=30 STARK_FINALITY_POLL_SECONDS=1 \
  "${RECONCILER}" \
    "${TMP_DIR}/approved_journal.json" \
    "${TMP_DIR}/approved_transition.json" \
    "${TMP_DIR}/nullifier_state.json" \
    "${TMP_DIR}/approved_reconciliation_report.json" \
    "${REGISTRY}" "${RPC_URL}" >/dev/null
python3 - "${TMP_DIR}/approved_reconciliation_report.json" <<'PY'
import json, sys
report = json.load(open(sys.argv[1], encoding="utf-8"))
assert report["status"] == "finalized_chain_and_local_state_reconciled"
assert report["journal_status_before"] == "local_state_committed"
assert report["journal_status_after"] == "local_state_committed"
assert report["local_state_committed_now"] is False
assert report["retry_count"] == 1
PY

cp "${TMP_DIR}/approved_journal.json" "${TMP_DIR}/reorg_journal.json"
python3 - "${TMP_DIR}/reorg_journal.json" <<'PY'
import json, sys
path = sys.argv[1]
journal = json.load(open(path, encoding="utf-8"))
journal["transaction_block_hash"] = "0x" + "99" * 32
open(path, "w", encoding="utf-8").write(json.dumps(journal, indent=2) + "\n")
PY
if STARK_CHAIN_ID="${CHAIN_ID}" STARK_FINALITY_MODE=test_mined \
  STARK_FINALITY_TIMEOUT_SECONDS=30 STARK_FINALITY_POLL_SECONDS=1 \
  "${RECONCILER}" \
    "${TMP_DIR}/reorg_journal.json" \
    "${TMP_DIR}/approved_transition.json" \
    "${TMP_DIR}/nullifier_state.json" \
    "${TMP_DIR}/reorg_report.json" \
    "${REGISTRY}" "${RPC_URL}" >"${TMP_DIR}/reorg.out" 2>&1; then
  echo "reorg-injected journal was unexpectedly accepted" >&2
  exit 1
fi
grep -q "possible reorg or wrong RPC chain" "${TMP_DIR}/reorg.out"

run_claim_with_finality "${TMP_DIR}/denied.json" >/dev/null
python3 - "${TMP_DIR}/adjudication_result.json" "${TMP_DIR}/nullifier_state.json" <<'PY'
import json, sys
result = json.load(open(sys.argv[1], encoding="utf-8")); state = json.load(open(sys.argv[2], encoding="utf-8"))
assert result["status"] == "DENIED" and result["reason"] == "G9_RECIPIENT_DECEASED"
assert result["tx_submitted"] is True and state["generation"] == 1 and len(state["leaves"]) == 1
PY
[[ "$(cast call "${REGISTRY}" 'approvedClaims()(uint256)' --rpc-url "${RPC_URL}")" == "1" ]]
[[ "$(cast call "${REGISTRY}" 'deniedClaims()(uint256)' --rpc-url "${RPC_URL}")" == "1" ]]
[[ "$(cast call "${VERIFIER}" 'policyManifestHash()(bytes32)' --rpc-url "${RPC_URL}" | tr '[:upper:]' '[:lower:]')" == "${POLICY_HASH}" ]]

echo "STARK governed V2 disposable-Anvil settlement passed"
