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
PUBLIC_INPUT_ROOT_ASSEMBLY_PLAN="${TMP_DIR}/public_input_root_assembly_plan.json"
PUBLIC_INPUT_ROOT_DIGEST_CANDIDATE="${TMP_DIR}/public_input_root_digest_candidate.json"
PROOF_COMMITMENT_PREIMAGE_PLAN="${TMP_DIR}/proof_commitment_preimage_plan.json"
PROOF_ARTIFACT_FIXTURE_EXPECTATIONS="${TMP_DIR}/proof_artifact_fixture_expectations.json"
SELECTED_PROVER_BYTE_ENCODING_PLAN="${TMP_DIR}/selected_prover_byte_encoding_plan.json"
CLAIM_SOURCE_ROOT_INPUT="${TMP_DIR}/claim_source_root_input.json"
CLAIM_SOURCE_IDENTITY_EVIDENCE="${TMP_DIR}/claim_source_identity_evidence.json"
CLAIM_SOURCE_ROOT_DIGEST_CANDIDATE="${TMP_DIR}/claim_source_root_digest_candidate.json"
ORACLE_FACTS_ROOT_INPUT="${TMP_DIR}/oracle_facts_root_input.json"
ORACLE_FACTS_ROOT_DIGEST_CANDIDATE="${TMP_DIR}/oracle_facts_root_digest_candidate.json"
FEE_SCHEDULE_ROOT_INPUT="${TMP_DIR}/fee_schedule_root_input.json"
FEE_SCHEDULE_ROOT_DIGEST_CANDIDATE="${TMP_DIR}/fee_schedule_root_digest_candidate.json"
NULLIFIER_ROOT_TRANSITION_INPUT="${TMP_DIR}/nullifier_root_transition_input.json"
NULLIFIER_ROOT_TRANSITION_DIGEST_CANDIDATE="${TMP_DIR}/nullifier_root_transition_digest_candidate.json"
SOURCE_ROOT_AGGREGATION_PLAN="${TMP_DIR}/source_root_aggregation_plan.json"
PHASE8_PRE_PROVER_BUNDLE_CHECKPOINT="${TMP_DIR}/phase8_pre_prover_bundle_checkpoint.json"
PHASE8_REAL_PROVER_IMPLEMENTATION_CHECKLIST="${TMP_DIR}/phase8_real_prover_implementation_checklist.json"
PHASE8_TEST_ONLY_PROVER_HARNESS_PLAN="${TMP_DIR}/phase8_test_only_prover_harness_plan.json"
PHASE8_TEST_ONLY_PROVER_HARNESS_EXECUTION_REPORT="${TMP_DIR}/phase8_test_only_prover_harness_execution_report.json"
PHASE8_REAL_PROVER_BOUNDARY_ADAPTER_PLAN="${TMP_DIR}/phase8_real_prover_boundary_adapter_plan.json"
PHASE8_REAL_PROOF_ARTIFACT_READINESS_GATE="${TMP_DIR}/phase8_real_proof_artifact_readiness_gate.json"
PHASE8_IMPLEMENTATION_SOURCE_REGISTRY="${TMP_DIR}/phase8_implementation_source_registry.json"
PHASE8_IMPLEMENTATION_EVIDENCE_SLOTS="${TMP_DIR}/phase8_implementation_evidence_slots.json"
PHASE8_EVIDENCE_READINESS_REPORT="${TMP_DIR}/phase8_evidence_readiness_report.json"
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
PHASE8_TEST_ONLY_PROOF_BYTES="${TMP_DIR}/phase8_test_only_proof_bytes.json"
PHASE8_TEST_ONLY_REAL_PROOF_BYTES_FIXTURE="${TMP_DIR}/phase8_test_only_real_proof_bytes_fixture.json"
PHASE8_TEST_ONLY_LOCAL_REAL_PROOF_VALIDATION_LOG_FIXTURE="${TMP_DIR}/phase8_test_only_local_real_proof_validation_log_fixture.json"
PHASE8_TEST_ONLY_EVIDENCE_SATISFACTION_REHEARSAL_REPORT="${TMP_DIR}/phase8_test_only_evidence_satisfaction_rehearsal_report.json"
PHASE8_REAL_PROOF_BYTES_FIXTURE_PROMOTION_PLAN="${TMP_DIR}/phase8_real_proof_bytes_fixture_promotion_plan.json"
PHASE8_LOCAL_REAL_PROOF_VALIDATION_LOG_PROMOTION_PLAN="${TMP_DIR}/phase8_local_real_proof_validation_log_promotion_plan.json"
PHASE8_REAL_PROVER_EVIDENCE_RECORD="${TMP_DIR}/phase8_real_prover_evidence_record.json"
PHASE8_REAL_PROVER_ATTEMPT_ARTIFACT="${TMP_DIR}/phase8_real_prover_attempt_artifact.json"
PHASE8_REAL_PROVER_ADAPTER_INVOCATION="${TMP_DIR}/phase8_real_prover_adapter_invocation.json"
PHASE8_REAL_PROVER_CODE_PATH_EVIDENCE="${TMP_DIR}/phase8_real_prover_code_path_evidence.json"
PHASE8_REAL_PROVER_UNIT_TESTS_EVIDENCE="${TMP_DIR}/phase8_real_prover_unit_tests_evidence.json"
PHASE8_LOCAL_REAL_PROOF_VALIDATION_LOG_EVIDENCE="${TMP_DIR}/phase8_local_real_proof_validation_log_evidence.json"
PHASE8_REAL_PROOF_BYTES_FIXTURE_EVIDENCE="${TMP_DIR}/phase8_real_proof_bytes_fixture_evidence.json"
PHASE8_REAL_PROVER_EVIDENCE_SUMMARY="${TMP_DIR}/phase8_real_prover_evidence_summary.json"
PHASE8_REAL_PROVER_READINESS_ROLLUP="${TMP_DIR}/phase8_real_prover_readiness_rollup.json"
WINTERFELL_PROOF_PREVIEW="${TMP_DIR}/winterfell_proof_preview.json"
WINTERFELL_POC_REAL_PROOF_FIXTURE="${TMP_DIR}/winterfell_poc_real_proof_fixture.json"
WINTERFELL_POC_SEMANTIC_EQUIVALENCE_REPORT="${TMP_DIR}/winterfell_poc_semantic_equivalence_report.json"
WINTERFELL_POC_SEMANTIC_GAP_NORMALIZATION_REPORT="${TMP_DIR}/winterfell_poc_semantic_gap_normalization_report.json"
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

run_in_dir "Generate public input root assembly plan" "stark-engine" \
  cargo run --bin generate_public_input_root_assembly_plan -- "${STARK_PROOF_ARTIFACT_V1_BOUNDARY_SPEC}" "${PUBLIC_INPUT_ROOT_ASSEMBLY_PLAN}"

run_in_dir "Validate public input root assembly plan" "stark-engine" \
  cargo run --bin validate_public_input_root_assembly_plan -- "${PUBLIC_INPUT_ROOT_ASSEMBLY_PLAN}"

run_in_dir "Generate public input root digest candidate" "stark-engine" \
  cargo run --bin generate_public_input_root_digest_candidate -- "${PUBLIC_INPUT_ROOT_ASSEMBLY_PLAN}" "${PUBLIC_INPUT_ROOT_DIGEST_CANDIDATE}"

run_in_dir "Validate public input root digest candidate" "stark-engine" \
  cargo run --bin validate_public_input_root_digest_candidate -- "${PUBLIC_INPUT_ROOT_DIGEST_CANDIDATE}"

run_in_dir "Generate proof commitment preimage plan" "stark-engine" \
  cargo run --bin generate_proof_commitment_preimage_plan -- "${STARK_PROOF_ARTIFACT_V1_BOUNDARY_SPEC}" "${PROOF_COMMITMENT_PREIMAGE_PLAN}"

run_in_dir "Validate proof commitment preimage plan" "stark-engine" \
  cargo run --bin validate_proof_commitment_preimage_plan -- "${PROOF_COMMITMENT_PREIMAGE_PLAN}"

run_in_dir "Generate proof artifact fixture expectations" "stark-engine" \
  cargo run --bin generate_proof_artifact_fixture_expectations -- "${STARK_PROOF_ARTIFACT_V1_BOUNDARY_SPEC}" "${PROOF_ARTIFACT_FIXTURE_EXPECTATIONS}"

run_in_dir "Validate proof artifact fixture expectations" "stark-engine" \
  cargo run --bin validate_proof_artifact_fixture_expectations -- "${PROOF_ARTIFACT_FIXTURE_EXPECTATIONS}"

run_in_dir "Generate selected prover byte encoding plan" "stark-engine" \
  cargo run --bin generate_selected_prover_byte_encoding_plan -- "${STARK_PROOF_ARTIFACT_V1_BOUNDARY_SPEC}" "${SELECTED_PROVER_BYTE_ENCODING_PLAN}"

run_in_dir "Validate selected prover byte encoding plan" "stark-engine" \
  cargo run --bin validate_selected_prover_byte_encoding_plan -- "${SELECTED_PROVER_BYTE_ENCODING_PLAN}"

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

run_in_dir "Generate Phase 8 test-only proof bytes" "stark-engine" \
  cargo run --bin generate_phase8_test_only_proof_bytes -- "${COMPLETE_WINTERFELL_WITNESS_CANDIDATE}" "${PHASE8_TEST_ONLY_PROOF_BYTES}"

run_in_dir "Validate Phase 8 test-only proof bytes" "stark-engine" \
  cargo run --bin validate_phase8_test_only_proof_bytes -- "${PHASE8_TEST_ONLY_PROOF_BYTES}"

run_in_dir "Generate Phase 8 test-only real proof bytes fixture" "stark-engine" \
  cargo run --bin generate_phase8_test_only_real_proof_bytes_fixture -- "${PHASE8_TEST_ONLY_PROOF_BYTES}" "${PHASE8_TEST_ONLY_REAL_PROOF_BYTES_FIXTURE}"

run_in_dir "Validate Phase 8 test-only real proof bytes fixture" "stark-engine" \
  cargo run --bin validate_phase8_test_only_real_proof_bytes_fixture -- "${PHASE8_TEST_ONLY_REAL_PROOF_BYTES_FIXTURE}"

run_in_dir "Generate Phase 8 test-only local real proof validation log fixture" "stark-engine" \
  cargo run --bin generate_phase8_test_only_local_real_proof_validation_log_fixture -- "${PHASE8_TEST_ONLY_REAL_PROOF_BYTES_FIXTURE}" "${PHASE8_TEST_ONLY_LOCAL_REAL_PROOF_VALIDATION_LOG_FIXTURE}"

run_in_dir "Validate Phase 8 test-only local real proof validation log fixture" "stark-engine" \
  cargo run --bin validate_phase8_test_only_local_real_proof_validation_log_fixture -- "${PHASE8_TEST_ONLY_LOCAL_REAL_PROOF_VALIDATION_LOG_FIXTURE}"

run_in_dir "Generate Phase 8 test-only evidence satisfaction rehearsal report" "stark-engine" \
  cargo run --bin generate_phase8_test_only_evidence_satisfaction_rehearsal_report -- "${PHASE8_TEST_ONLY_REAL_PROOF_BYTES_FIXTURE}" "${PHASE8_TEST_ONLY_LOCAL_REAL_PROOF_VALIDATION_LOG_FIXTURE}" "${PHASE8_TEST_ONLY_EVIDENCE_SATISFACTION_REHEARSAL_REPORT}"

run_in_dir "Validate Phase 8 test-only evidence satisfaction rehearsal report" "stark-engine" \
  cargo run --bin validate_phase8_test_only_evidence_satisfaction_rehearsal_report -- "${PHASE8_TEST_ONLY_EVIDENCE_SATISFACTION_REHEARSAL_REPORT}"

run_in_dir "Generate Phase 8 real proof bytes fixture promotion plan" "stark-engine" \
  cargo run --bin generate_phase8_real_proof_bytes_fixture_promotion_plan -- "${PHASE8_TEST_ONLY_EVIDENCE_SATISFACTION_REHEARSAL_REPORT}" "${PHASE8_REAL_PROOF_BYTES_FIXTURE_PROMOTION_PLAN}"

run_in_dir "Validate Phase 8 real proof bytes fixture promotion plan" "stark-engine" \
  cargo run --bin validate_phase8_real_proof_bytes_fixture_promotion_plan -- "${PHASE8_REAL_PROOF_BYTES_FIXTURE_PROMOTION_PLAN}"

run_in_dir "Generate Phase 8 local real proof validation log promotion plan" "stark-engine" \
  cargo run --bin generate_phase8_local_real_proof_validation_log_promotion_plan -- "${PHASE8_TEST_ONLY_EVIDENCE_SATISFACTION_REHEARSAL_REPORT}" "${PHASE8_LOCAL_REAL_PROOF_VALIDATION_LOG_PROMOTION_PLAN}"

run_in_dir "Validate Phase 8 local real proof validation log promotion plan" "stark-engine" \
  cargo run --bin validate_phase8_local_real_proof_validation_log_promotion_plan -- "${PHASE8_LOCAL_REAL_PROOF_VALIDATION_LOG_PROMOTION_PLAN}"

run_in_dir "Generate Phase 8 real prover evidence record" "stark-engine" \
  cargo run --bin generate_phase8_real_prover_evidence_record -- "${PHASE8_TEST_ONLY_PROOF_BYTES}" "${PHASE8_REAL_PROVER_EVIDENCE_RECORD}"

run_in_dir "Validate Phase 8 real prover evidence record" "stark-engine" \
  cargo run --bin validate_phase8_real_prover_evidence_record -- "${PHASE8_REAL_PROVER_EVIDENCE_RECORD}"

run_in_dir "Generate Phase 8 real prover attempt artifact" "stark-engine" \
  cargo run --bin generate_phase8_real_prover_attempt_artifact -- "${PHASE8_REAL_PROVER_EVIDENCE_RECORD}" "${PHASE8_REAL_PROVER_ATTEMPT_ARTIFACT}"

run_in_dir "Validate Phase 8 real prover attempt artifact" "stark-engine" \
  cargo run --bin validate_phase8_real_prover_attempt_artifact -- "${PHASE8_REAL_PROVER_ATTEMPT_ARTIFACT}"

run_in_dir "Generate Phase 8 real prover adapter invocation" "stark-engine" \
  cargo run --bin generate_phase8_real_prover_adapter_invocation -- "${PHASE8_REAL_PROVER_ATTEMPT_ARTIFACT}" "${PHASE8_REAL_PROVER_ADAPTER_INVOCATION}"

run_in_dir "Validate Phase 8 real prover adapter invocation" "stark-engine" \
  cargo run --bin validate_phase8_real_prover_adapter_invocation -- "${PHASE8_REAL_PROVER_ADAPTER_INVOCATION}"

run_in_dir "Generate Phase 8 real prover code path evidence" "stark-engine" \
  cargo run --bin generate_phase8_real_prover_code_path_evidence -- "${PHASE8_REAL_PROVER_ADAPTER_INVOCATION}" "${PHASE8_REAL_PROVER_CODE_PATH_EVIDENCE}"

run_in_dir "Validate Phase 8 real prover code path evidence" "stark-engine" \
  cargo run --bin validate_phase8_real_prover_code_path_evidence -- "${PHASE8_REAL_PROVER_CODE_PATH_EVIDENCE}"

run_in_dir "Generate Phase 8 real prover unit tests evidence" "stark-engine" \
  cargo run --bin generate_phase8_real_prover_unit_tests_evidence -- "${PHASE8_REAL_PROVER_CODE_PATH_EVIDENCE}" "${PHASE8_REAL_PROVER_UNIT_TESTS_EVIDENCE}"

run_in_dir "Validate Phase 8 real prover unit tests evidence" "stark-engine" \
  cargo run --bin validate_phase8_real_prover_unit_tests_evidence -- "${PHASE8_REAL_PROVER_UNIT_TESTS_EVIDENCE}"

run_in_dir "Generate Phase 8 local real proof validation log evidence" "stark-engine" \
  cargo run --bin generate_phase8_local_real_proof_validation_log_evidence -- "${PHASE8_REAL_PROVER_UNIT_TESTS_EVIDENCE}" "${PHASE8_LOCAL_REAL_PROOF_VALIDATION_LOG_EVIDENCE}"

run_in_dir "Validate Phase 8 local real proof validation log evidence" "stark-engine" \
  cargo run --bin validate_phase8_local_real_proof_validation_log_evidence -- "${PHASE8_LOCAL_REAL_PROOF_VALIDATION_LOG_EVIDENCE}"

run_in_dir "Generate Phase 8 real proof bytes fixture evidence" "stark-engine" \
  cargo run --bin generate_phase8_real_proof_bytes_fixture_evidence -- "${PHASE8_LOCAL_REAL_PROOF_VALIDATION_LOG_EVIDENCE}" "${PHASE8_REAL_PROOF_BYTES_FIXTURE_EVIDENCE}"

run_in_dir "Validate Phase 8 real proof bytes fixture evidence" "stark-engine" \
  cargo run --bin validate_phase8_real_proof_bytes_fixture_evidence -- "${PHASE8_REAL_PROOF_BYTES_FIXTURE_EVIDENCE}"

run_in_dir "Generate Phase 8 real prover evidence summary" "stark-engine" \
  cargo run --bin generate_phase8_real_prover_evidence_summary -- \
    "${PHASE8_REAL_PROVER_CODE_PATH_EVIDENCE}" \
    "${PHASE8_REAL_PROVER_UNIT_TESTS_EVIDENCE}" \
    "${PHASE8_LOCAL_REAL_PROOF_VALIDATION_LOG_EVIDENCE}" \
    "${PHASE8_REAL_PROOF_BYTES_FIXTURE_EVIDENCE}" \
    "${PHASE8_REAL_PROVER_EVIDENCE_SUMMARY}"

run_in_dir "Validate Phase 8 real prover evidence summary" "stark-engine" \
  cargo run --bin validate_phase8_real_prover_evidence_summary -- "${PHASE8_REAL_PROVER_EVIDENCE_SUMMARY}"

run_in_dir "Generate Phase 8 real prover readiness rollup" "stark-engine" \
  cargo run --bin generate_phase8_real_prover_readiness_rollup -- \
    "${PHASE8_REAL_PROVER_EVIDENCE_SUMMARY}" \
    "${PHASE8_REAL_PROOF_BYTES_FIXTURE_PROMOTION_PLAN}" \
    "${PHASE8_LOCAL_REAL_PROOF_VALIDATION_LOG_PROMOTION_PLAN}" \
    "${PHASE8_REAL_PROVER_READINESS_ROLLUP}"

run_in_dir "Validate Phase 8 real prover readiness rollup" "stark-engine" \
  cargo run --bin validate_phase8_real_prover_readiness_rollup -- "${PHASE8_REAL_PROVER_READINESS_ROLLUP}"

run_in_dir "Generate Winterfell proof preview" "stark-engine" \
  cargo run --features winterfell-poc --bin generate_winterfell_proof_preview -- "${COMPLETE_WINTERFELL_WITNESS_CANDIDATE}" "${WINTERFELL_PROOF_PREVIEW}"

run_in_dir "Validate Winterfell proof preview" "stark-engine" \
  cargo run --features winterfell-poc --bin validate_winterfell_proof_preview -- "${WINTERFELL_PROOF_PREVIEW}"

run_in_dir "Generate Winterfell PoC real proof fixture" "stark-engine" \
  cargo run --features winterfell-poc --bin generate_winterfell_poc_real_proof_fixture -- "${COMPLETE_WINTERFELL_WITNESS_CANDIDATE}" "${WINTERFELL_POC_REAL_PROOF_FIXTURE}"

run_in_dir "Validate Winterfell PoC real proof fixture" "stark-engine" \
  cargo run --features winterfell-poc --bin validate_winterfell_poc_real_proof_fixture -- "${WINTERFELL_POC_REAL_PROOF_FIXTURE}"

run_in_dir "Generate Winterfell PoC semantic equivalence report" "stark-engine" \
  cargo run --features winterfell-poc --bin generate_winterfell_poc_semantic_equivalence_report -- "${BRIDGE_INPUT}" "${WINTERFELL_POC_REAL_PROOF_FIXTURE}" "${WINTERFELL_POC_SEMANTIC_EQUIVALENCE_REPORT}"

run_in_dir "Validate Winterfell PoC semantic equivalence report" "stark-engine" \
  cargo run --features winterfell-poc --bin validate_winterfell_poc_semantic_equivalence_report -- "${WINTERFELL_POC_SEMANTIC_EQUIVALENCE_REPORT}"

run_in_dir "Generate Winterfell PoC semantic gap normalization report" "stark-engine" \
  cargo run --features winterfell-poc --bin generate_winterfell_poc_semantic_gap_normalization_report -- "${BRIDGE_INPUT}" "${COMPLETE_WINTERFELL_WITNESS_CANDIDATE}" "${WINTERFELL_POC_SEMANTIC_EQUIVALENCE_REPORT}" "${WINTERFELL_POC_SEMANTIC_GAP_NORMALIZATION_REPORT}"

run_in_dir "Validate Winterfell PoC semantic gap normalization report" "stark-engine" \
  cargo run --features winterfell-poc --bin validate_winterfell_poc_semantic_gap_normalization_report -- "${WINTERFELL_POC_SEMANTIC_GAP_NORMALIZATION_REPORT}"

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

run_in_dir "Generate claim source identity evidence" "stark-engine" \
  cargo run --bin generate_claim_source_identity_evidence -- "${CLAIM_SOURCE_ROOT_INPUT}" "${COMPLETE_WINTERFELL_WITNESS_CANDIDATE}" "${CLAIM_SOURCE_IDENTITY_EVIDENCE}"

run_in_dir "Validate claim source identity evidence" "stark-engine" \
  cargo run --bin validate_claim_source_identity_evidence -- "${CLAIM_SOURCE_IDENTITY_EVIDENCE}"

run_in_dir "Generate STARK claim source root digest candidate" "stark-engine" \
  cargo run --bin generate_source_root_digest_candidate -- "${CLAIM_SOURCE_ROOT_INPUT}" "${CLAIM_SOURCE_ROOT_DIGEST_CANDIDATE}"

run_in_dir "Validate STARK claim source root digest candidate" "stark-engine" \
  cargo run --bin validate_source_root_digest_candidate -- "${CLAIM_SOURCE_ROOT_DIGEST_CANDIDATE}"

run_in_dir "Generate STARK oracle facts root input" "stark-engine" \
  cargo run --bin generate_oracle_facts_root_input -- "${BRIDGE_INPUT}" "${ORACLE_FACTS_ROOT_INPUT}"

run_in_dir "Validate STARK oracle facts root input" "stark-engine" \
  cargo run --bin validate_oracle_facts_root_input -- "${ORACLE_FACTS_ROOT_INPUT}"

run_in_dir "Generate STARK oracle facts root digest candidate" "stark-engine" \
  cargo run --bin generate_source_root_digest_candidate -- "${ORACLE_FACTS_ROOT_INPUT}" "${ORACLE_FACTS_ROOT_DIGEST_CANDIDATE}"

run_in_dir "Validate STARK oracle facts root digest candidate" "stark-engine" \
  cargo run --bin validate_source_root_digest_candidate -- "${ORACLE_FACTS_ROOT_DIGEST_CANDIDATE}"

run_in_dir "Generate STARK fee schedule root input" "stark-engine" \
  cargo run --bin generate_fee_schedule_root_input -- "${BRIDGE_INPUT}" "${FEE_SCHEDULE_ROOT_INPUT}"

run_in_dir "Validate STARK fee schedule root input" "stark-engine" \
  cargo run --bin validate_fee_schedule_root_input -- "${FEE_SCHEDULE_ROOT_INPUT}"

run_in_dir "Generate STARK fee schedule root digest candidate" "stark-engine" \
  cargo run --bin generate_source_root_digest_candidate -- "${FEE_SCHEDULE_ROOT_INPUT}" "${FEE_SCHEDULE_ROOT_DIGEST_CANDIDATE}"

run_in_dir "Validate STARK fee schedule root digest candidate" "stark-engine" \
  cargo run --bin validate_source_root_digest_candidate -- "${FEE_SCHEDULE_ROOT_DIGEST_CANDIDATE}"

run_in_dir "Generate STARK nullifier root transition input" "stark-engine" \
  cargo run --bin generate_nullifier_root_transition_input -- "${BRIDGE_INPUT}" "${NULLIFIER_ROOT_TRANSITION_INPUT}"

run_in_dir "Validate STARK nullifier root transition input" "stark-engine" \
  cargo run --bin validate_nullifier_root_transition_input -- "${NULLIFIER_ROOT_TRANSITION_INPUT}"

run_in_dir "Generate STARK nullifier root transition digest candidate" "stark-engine" \
  cargo run --bin generate_source_root_digest_candidate -- "${NULLIFIER_ROOT_TRANSITION_INPUT}" "${NULLIFIER_ROOT_TRANSITION_DIGEST_CANDIDATE}"

run_in_dir "Validate STARK nullifier root transition digest candidate" "stark-engine" \
  cargo run --bin validate_source_root_digest_candidate -- "${NULLIFIER_ROOT_TRANSITION_DIGEST_CANDIDATE}"

run_in_dir "Generate STARK source root aggregation plan" "stark-engine" \
  cargo run --bin generate_source_root_aggregation_plan -- "${PUBLIC_INPUT_ROOT_DIGEST_CANDIDATE}" "${SOURCE_ROOT_AGGREGATION_PLAN}" \
    "${CLAIM_SOURCE_ROOT_DIGEST_CANDIDATE}" \
    "${ORACLE_FACTS_ROOT_DIGEST_CANDIDATE}" \
    "${FEE_SCHEDULE_ROOT_DIGEST_CANDIDATE}" \
    "${NULLIFIER_ROOT_TRANSITION_DIGEST_CANDIDATE}"

run_in_dir "Validate STARK source root aggregation plan" "stark-engine" \
  cargo run --bin validate_source_root_aggregation_plan -- "${SOURCE_ROOT_AGGREGATION_PLAN}"

run_in_dir "Generate Phase 8 pre-prover bundle checkpoint" "stark-engine" \
  cargo run --bin generate_phase8_pre_prover_bundle_checkpoint -- \
    "${STARK_PROOF_ARTIFACT_V1_BOUNDARY_SPEC}" \
    "${PUBLIC_INPUT_ROOT_DIGEST_CANDIDATE}" \
    "${SOURCE_ROOT_AGGREGATION_PLAN}" \
    "${PROOF_COMMITMENT_PREIMAGE_PLAN}" \
    "${PROOF_ARTIFACT_FIXTURE_EXPECTATIONS}" \
    "${SELECTED_PROVER_BYTE_ENCODING_PLAN}" \
    "${PHASE8_PRE_PROVER_BUNDLE_CHECKPOINT}"

run_in_dir "Validate Phase 8 pre-prover bundle checkpoint" "stark-engine" \
  cargo run --bin validate_phase8_pre_prover_bundle_checkpoint -- "${PHASE8_PRE_PROVER_BUNDLE_CHECKPOINT}"

run_in_dir "Generate Phase 8 real prover implementation checklist" "stark-engine" \
  cargo run --bin generate_phase8_real_prover_implementation_checklist -- "${PHASE8_PRE_PROVER_BUNDLE_CHECKPOINT}" "${PHASE8_REAL_PROVER_IMPLEMENTATION_CHECKLIST}"

run_in_dir "Validate Phase 8 real prover implementation checklist" "stark-engine" \
  cargo run --bin validate_phase8_real_prover_implementation_checklist -- "${PHASE8_REAL_PROVER_IMPLEMENTATION_CHECKLIST}"

run_in_dir "Generate Phase 8 test-only prover harness plan" "stark-engine" \
  cargo run --bin generate_phase8_test_only_prover_harness_plan -- "${PHASE8_REAL_PROVER_IMPLEMENTATION_CHECKLIST}" "${PHASE8_TEST_ONLY_PROVER_HARNESS_PLAN}"

run_in_dir "Validate Phase 8 test-only prover harness plan" "stark-engine" \
  cargo run --bin validate_phase8_test_only_prover_harness_plan -- "${PHASE8_TEST_ONLY_PROVER_HARNESS_PLAN}"

run_in_dir "Generate Phase 8 test-only prover harness execution report" "stark-engine" \
  cargo run --bin generate_phase8_test_only_prover_harness_execution_report -- \
    "${PHASE8_TEST_ONLY_PROVER_HARNESS_PLAN}" \
    "${COMPLETE_WINTERFELL_WITNESS_CANDIDATE}" \
    "${SELECTED_PROVER_BYTE_ENCODING_PLAN}" \
    "${PHASE8_REAL_PROVER_IMPLEMENTATION_CHECKLIST}" \
    "${WINTERFELL_PROOF_PREVIEW}" \
    "${STARK_PROOF_ARTIFACT_V1_CANDIDATE}" \
    "${STARK_SETTLEMENT_BOUNDARY_ARTIFACT}" \
    "${PHASE8_TEST_ONLY_PROVER_HARNESS_EXECUTION_REPORT}"

run_in_dir "Validate Phase 8 test-only prover harness execution report" "stark-engine" \
  cargo run --bin validate_phase8_test_only_prover_harness_execution_report -- "${PHASE8_TEST_ONLY_PROVER_HARNESS_EXECUTION_REPORT}"

run_in_dir "Generate Phase 8 real prover boundary adapter plan" "stark-engine" \
  cargo run --bin generate_phase8_real_prover_boundary_adapter_plan -- "${PHASE8_TEST_ONLY_PROVER_HARNESS_EXECUTION_REPORT}" "${PHASE8_REAL_PROVER_BOUNDARY_ADAPTER_PLAN}"

run_in_dir "Validate Phase 8 real prover boundary adapter plan" "stark-engine" \
  cargo run --bin validate_phase8_real_prover_boundary_adapter_plan -- "${PHASE8_REAL_PROVER_BOUNDARY_ADAPTER_PLAN}"

run_in_dir "Generate Phase 8 real proof artifact readiness gate" "stark-engine" \
  cargo run --bin generate_phase8_real_proof_artifact_readiness_gate -- "${PHASE8_REAL_PROVER_BOUNDARY_ADAPTER_PLAN}" "${PHASE8_REAL_PROOF_ARTIFACT_READINESS_GATE}"

run_in_dir "Validate Phase 8 real proof artifact readiness gate" "stark-engine" \
  cargo run --bin validate_phase8_real_proof_artifact_readiness_gate -- "${PHASE8_REAL_PROOF_ARTIFACT_READINESS_GATE}"

run_in_dir "Generate Phase 8 implementation source registry" "stark-engine" \
  cargo run --bin generate_phase8_implementation_source_registry -- "${PHASE8_REAL_PROOF_ARTIFACT_READINESS_GATE}" "${PHASE8_IMPLEMENTATION_SOURCE_REGISTRY}"

run_in_dir "Validate Phase 8 implementation source registry" "stark-engine" \
  cargo run --bin validate_phase8_implementation_source_registry -- "${PHASE8_IMPLEMENTATION_SOURCE_REGISTRY}"

run_in_dir "Generate Phase 8 implementation evidence slots" "stark-engine" \
  cargo run --bin generate_phase8_implementation_evidence_slots -- "${PHASE8_IMPLEMENTATION_SOURCE_REGISTRY}" "${PHASE8_IMPLEMENTATION_EVIDENCE_SLOTS}"

run_in_dir "Validate Phase 8 implementation evidence slots" "stark-engine" \
  cargo run --bin validate_phase8_implementation_evidence_slots -- "${PHASE8_IMPLEMENTATION_EVIDENCE_SLOTS}"

run_in_dir "Generate Phase 8 evidence readiness report" "stark-engine" \
  cargo run --bin generate_phase8_evidence_readiness_report -- "${PHASE8_IMPLEMENTATION_EVIDENCE_SLOTS}" "${PHASE8_EVIDENCE_READINESS_REPORT}"

run_in_dir "Validate Phase 8 evidence readiness report" "stark-engine" \
  cargo run --bin validate_phase8_evidence_readiness_report -- "${PHASE8_EVIDENCE_READINESS_REPORT}"

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
