#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"

export PATH="${HOME}/.cargo/bin:${PATH}"

cleanup() {
  rm -rf "${TMP_DIR}"
  rm -f "${ROOT_DIR}/rust-engine/stark_bridge_input.json"
  rm -rf "${ROOT_DIR}/rust-engine/target" "${ROOT_DIR}/stark-engine/target"
}

trap cleanup EXIT

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

BRIDGE_INPUT="${TMP_DIR}/stark_bridge_input.json"
STARK_PROOF_ARTIFACT_V1_CANDIDATE="${TMP_DIR}/stark_proof_artifact_v1_candidate.json"
STARK_PROOF_ARTIFACT_V1_BOUNDARY_SPEC="${TMP_DIR}/stark_proof_artifact_v1_boundary_spec.json"
CLAIM_SOURCE_ROOT_INPUT="${TMP_DIR}/claim_source_root_input.json"
ORACLE_FACTS_ROOT_INPUT="${TMP_DIR}/oracle_facts_root_input.json"
FEE_SCHEDULE_ROOT_INPUT="${TMP_DIR}/fee_schedule_root_input.json"
NULLIFIER_ROOT_TRANSITION_INPUT="${TMP_DIR}/nullifier_root_transition_input.json"
BATCH_ROOT_PLAN="${TMP_DIR}/batch_root_plan.json"
BATCH_ROOT_GAP_REPORT="${TMP_DIR}/batch_root_gap_report.json"
PROOF_INTENT="${TMP_DIR}/proof_intent.json"
WITNESS_PLAN="${TMP_DIR}/witness_plan.json"
MOCK_TRACE="${TMP_DIR}/mock_trace.json"
WINTERFELL_REPORT="${TMP_DIR}/winterfell_compat_report.json"
WINTERFELL_GAP_PLAN="${TMP_DIR}/winterfell_gap_plan.json"
WINTERFELL_WITNESS_CANDIDATE="${TMP_DIR}/winterfell_witness_candidate.json"
WINTERFELL_WITNESS_GAP_REPORT="${TMP_DIR}/winterfell_witness_gap_report.json"
WINTERFELL_SOURCE_DATA_REQUIREMENTS="${TMP_DIR}/winterfell_source_data_requirements.json"
WINTERFELL_SOURCE_DATA_FIXTURE="${TMP_DIR}/winterfell_source_data_fixture.json"
COMPLETE_WINTERFELL_WITNESS_CANDIDATE="${TMP_DIR}/complete_winterfell_witness_candidate.json"
WINTERFELL_PROOF_PREVIEW="${TMP_DIR}/winterfell_proof_preview.json"
STARK_SETTLEMENT_BOUNDARY_ARTIFACT="${TMP_DIR}/stark_settlement_boundary_artifact.json"
STARK_SOLIDITY_VERIFIER_INTERFACE_PLAN="${TMP_DIR}/stark_solidity_verifier_interface_plan.json"
STARK_SETTLEMENT_INTEGRATION_GAP_REPORT="${TMP_DIR}/stark_settlement_integration_gap_report.json"
STARK_SETTLEMENT_IMPLEMENTATION_PLAN="${TMP_DIR}/stark_settlement_implementation_plan.json"
STARK_SETTLEMENT_RUNTIME_READINESS_REPORT="${TMP_DIR}/stark_settlement_runtime_readiness_report.json"

run_in_dir "Generate STARK bridge input dry-run" "rust-engine" \
  cargo run -- stark-bridge-input-dry-run

mv "${ROOT_DIR}/rust-engine/stark_bridge_input.json" "${BRIDGE_INPUT}"

run_in_dir "Validate STARK bridge input" "stark-engine" \
  cargo run --bin validate_bridge_input -- "${BRIDGE_INPUT}"

run_in_dir "Generate STARK proof artifact V1 candidate" "stark-engine" \
  cargo run --bin generate_stark_proof_artifact_v1_candidate -- "${BRIDGE_INPUT}" "${STARK_PROOF_ARTIFACT_V1_CANDIDATE}"

run_in_dir "Validate STARK proof artifact V1 candidate" "stark-engine" \
  cargo run --bin validate_stark_proof_artifact_v1_candidate -- "${STARK_PROOF_ARTIFACT_V1_CANDIDATE}"

run_in_dir "Generate STARK proof artifact V1 boundary spec" "stark-engine" \
  cargo run --bin generate_stark_proof_artifact_v1_boundary_spec -- "${STARK_PROOF_ARTIFACT_V1_CANDIDATE}" "${STARK_PROOF_ARTIFACT_V1_BOUNDARY_SPEC}"

run_in_dir "Validate STARK proof artifact V1 boundary spec" "stark-engine" \
  cargo run --bin validate_stark_proof_artifact_v1_boundary_spec -- "${STARK_PROOF_ARTIFACT_V1_BOUNDARY_SPEC}"

run_in_dir "Generate Winterfell witness candidate" "stark-engine" \
  cargo run --bin generate_winterfell_witness_candidate -- "${BRIDGE_INPUT}" "${WINTERFELL_WITNESS_CANDIDATE}"

run_in_dir "Validate Winterfell witness candidate" "stark-engine" \
  cargo run --bin validate_winterfell_witness_candidate -- "${WINTERFELL_WITNESS_CANDIDATE}"

run_in_dir "Generate Winterfell witness gap report" "stark-engine" \
  cargo run --bin generate_winterfell_witness_gap_report -- "${WINTERFELL_WITNESS_CANDIDATE}" "${WINTERFELL_WITNESS_GAP_REPORT}"

run_in_dir "Generate Winterfell source data requirements" "stark-engine" \
  cargo run --bin generate_winterfell_source_data_requirements -- "${WINTERFELL_WITNESS_GAP_REPORT}" "${WINTERFELL_SOURCE_DATA_REQUIREMENTS}"

run_in_dir "Generate Winterfell source data fixture" "stark-engine" \
  cargo run --bin generate_winterfell_source_data_fixture -- "${WINTERFELL_SOURCE_DATA_REQUIREMENTS}" "${WINTERFELL_SOURCE_DATA_FIXTURE}"

run_in_dir "Generate complete Winterfell witness candidate" "stark-engine" \
  cargo run --bin generate_complete_winterfell_witness_candidate -- "${WINTERFELL_WITNESS_CANDIDATE}" "${WINTERFELL_SOURCE_DATA_FIXTURE}" "${COMPLETE_WINTERFELL_WITNESS_CANDIDATE}"

run_in_dir "Validate complete Winterfell witness candidate" "stark-engine" \
  cargo run --bin validate_complete_winterfell_witness_candidate -- "${COMPLETE_WINTERFELL_WITNESS_CANDIDATE}"

run_in_dir "Generate Winterfell proof preview" "stark-engine" \
  cargo run --features winterfell-poc --bin generate_winterfell_proof_preview -- "${COMPLETE_WINTERFELL_WITNESS_CANDIDATE}" "${WINTERFELL_PROOF_PREVIEW}"

run_in_dir "Validate Winterfell proof preview" "stark-engine" \
  cargo run --features winterfell-poc --bin validate_winterfell_proof_preview -- "${WINTERFELL_PROOF_PREVIEW}"

run_in_dir "Generate STARK settlement boundary artifact" "stark-engine" \
  cargo run --features winterfell-poc --bin generate_stark_settlement_boundary_artifact -- "${WINTERFELL_PROOF_PREVIEW}" "${STARK_SETTLEMENT_BOUNDARY_ARTIFACT}"

run_in_dir "Validate STARK settlement boundary artifact" "stark-engine" \
  cargo run --features winterfell-poc --bin validate_stark_settlement_boundary_artifact -- "${STARK_SETTLEMENT_BOUNDARY_ARTIFACT}"

run_in_dir "Generate STARK Solidity verifier interface plan" "stark-engine" \
  cargo run --features winterfell-poc --bin generate_stark_solidity_verifier_interface_plan -- "${STARK_SETTLEMENT_BOUNDARY_ARTIFACT}" "${STARK_SOLIDITY_VERIFIER_INTERFACE_PLAN}"

run_in_dir "Validate STARK Solidity verifier interface plan" "stark-engine" \
  cargo run --features winterfell-poc --bin validate_stark_solidity_verifier_interface_plan -- "${STARK_SOLIDITY_VERIFIER_INTERFACE_PLAN}"

run_in_dir "Validate STARK verifier ABI candidate alignment" "stark-engine" \
  cargo run --features winterfell-poc --bin validate_stark_verifier_abi_candidate_alignment -- "${STARK_SOLIDITY_VERIFIER_INTERFACE_PLAN}"

run_in_dir "Generate STARK settlement integration gap report" "stark-engine" \
  cargo run --features winterfell-poc --bin generate_stark_settlement_integration_gap_report -- "${STARK_SOLIDITY_VERIFIER_INTERFACE_PLAN}" "${STARK_SETTLEMENT_INTEGRATION_GAP_REPORT}"

run_in_dir "Validate STARK settlement integration gap report" "stark-engine" \
  cargo run --features winterfell-poc --bin validate_stark_settlement_integration_gap_report -- "${STARK_SETTLEMENT_INTEGRATION_GAP_REPORT}"

run_in_dir "Generate STARK settlement implementation plan" "stark-engine" \
  cargo run --features winterfell-poc --bin generate_stark_settlement_implementation_plan -- "${STARK_SETTLEMENT_INTEGRATION_GAP_REPORT}" "${STARK_SETTLEMENT_IMPLEMENTATION_PLAN}"

run_in_dir "Validate STARK settlement implementation plan" "stark-engine" \
  cargo run --features winterfell-poc --bin validate_stark_settlement_implementation_plan -- "${STARK_SETTLEMENT_IMPLEMENTATION_PLAN}"

run_in_dir "Generate STARK settlement runtime readiness report" "stark-engine" \
  cargo run --features winterfell-poc --bin generate_stark_settlement_runtime_readiness_report -- "${STARK_SETTLEMENT_IMPLEMENTATION_PLAN}" "${STARK_SETTLEMENT_RUNTIME_READINESS_REPORT}"

run_in_dir "Validate STARK settlement runtime readiness report" "stark-engine" \
  cargo run --features winterfell-poc --bin validate_stark_settlement_runtime_readiness_report -- "${STARK_SETTLEMENT_RUNTIME_READINESS_REPORT}"

run_in_dir "Generate STARK claim source root input" "stark-engine" \
  cargo run --bin generate_claim_source_root_input -- "${BRIDGE_INPUT}" "${CLAIM_SOURCE_ROOT_INPUT}"

run_in_dir "Validate STARK claim source root input" "stark-engine" \
  cargo run --bin validate_claim_source_root_input -- "${CLAIM_SOURCE_ROOT_INPUT}"

run_in_dir "Generate STARK oracle facts root input" "stark-engine" \
  cargo run --bin generate_oracle_facts_root_input -- "${BRIDGE_INPUT}" "${ORACLE_FACTS_ROOT_INPUT}"

run_in_dir "Validate STARK oracle facts root input" "stark-engine" \
  cargo run --bin validate_oracle_facts_root_input -- "${ORACLE_FACTS_ROOT_INPUT}"

run_in_dir "Generate STARK fee schedule root input" "stark-engine" \
  cargo run --bin generate_fee_schedule_root_input -- "${BRIDGE_INPUT}" "${FEE_SCHEDULE_ROOT_INPUT}"

run_in_dir "Validate STARK fee schedule root input" "stark-engine" \
  cargo run --bin validate_fee_schedule_root_input -- "${FEE_SCHEDULE_ROOT_INPUT}"

run_in_dir "Generate STARK nullifier root transition input" "stark-engine" \
  cargo run --bin generate_nullifier_root_transition_input -- "${BRIDGE_INPUT}" "${NULLIFIER_ROOT_TRANSITION_INPUT}"

run_in_dir "Validate STARK nullifier root transition input" "stark-engine" \
  cargo run --bin validate_nullifier_root_transition_input -- "${NULLIFIER_ROOT_TRANSITION_INPUT}"

run_in_dir "Generate STARK batch root compatibility plan" "stark-engine" \
  cargo run --bin generate_batch_root_plan -- "${BRIDGE_INPUT}" "${BATCH_ROOT_PLAN}"

run_in_dir "Validate STARK batch root compatibility plan" "stark-engine" \
  cargo run --bin validate_batch_root_plan -- "${BATCH_ROOT_PLAN}"

run_in_dir "Generate STARK batch root gap report" "stark-engine" \
  cargo run --bin generate_batch_root_gap_report -- "${BATCH_ROOT_PLAN}" "${BATCH_ROOT_GAP_REPORT}"

run_in_dir "Generate STARK proof intent" "stark-engine" \
  cargo run --bin generate_proof_intent -- "${BRIDGE_INPUT}" "${PROOF_INTENT}"

run_in_dir "Generate STARK witness plan" "stark-engine" \
  cargo run --bin generate_witness_plan -- "${PROOF_INTENT}" "${WITNESS_PLAN}"

run_in_dir "Validate STARK witness plan" "stark-engine" \
  cargo run --bin validate_witness_plan -- "${WITNESS_PLAN}"

run_in_dir "Generate STARK mock trace" "stark-engine" \
  cargo run --bin generate_mock_trace -- "${WITNESS_PLAN}" "${MOCK_TRACE}"

run_in_dir "Validate STARK mock trace" "stark-engine" \
  cargo run --bin validate_mock_trace -- "${MOCK_TRACE}"

run_in_dir "Generate Winterfell compatibility report" "stark-engine" \
  cargo run --bin generate_winterfell_compat_report -- "${MOCK_TRACE}" "${WINTERFELL_REPORT}"

run_in_dir "Generate Winterfell adapter gap plan" "stark-engine" \
  cargo run --bin generate_winterfell_gap_plan -- "${WINTERFELL_REPORT}" "${WINTERFELL_GAP_PLAN}"

echo
echo "==> STARK bridge CLI chain smoke test passed"
echo "    temporary artifacts were written under ${TMP_DIR} and will be removed"
