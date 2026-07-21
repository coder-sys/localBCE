use stark_engine::{
    Phase8HarnessArtifact, Phase8RealProverBoundaryAdapterPlan,
    Phase8TestOnlyProverHarnessExecutionReport, Phase8TestOnlyProverHarnessPlan,
};

fn execution_report() -> Phase8TestOnlyProverHarnessExecutionReport {
    Phase8TestOnlyProverHarnessExecutionReport {
        schema_version: Phase8TestOnlyProverHarnessExecutionReport::SCHEMA_VERSION.to_string(),
        source_schema_version: Phase8TestOnlyProverHarnessExecutionReport::SOURCE_SCHEMA_VERSION
            .to_string(),
        execution_status: Phase8TestOnlyProverHarnessExecutionReport::EXECUTION_STATUS.to_string(),
        selected_preview_prover: Phase8TestOnlyProverHarnessPlan::SELECTED_PREVIEW_PROVER
            .to_string(),
        execution_mode: Phase8TestOnlyProverHarnessPlan::EXECUTION_MODE.to_string(),
        input_artifacts: vec![
            harness_artifact(
                "complete_winterfell_witness_candidate",
                "winterfell-complete-witness-candidate-v0",
                "complete_winterfell_witness_candidate.json",
                "required_before_test_only_harness_execution",
            ),
            harness_artifact(
                "selected_prover_byte_encoding_plan",
                "selected-prover-byte-encoding-plan-v0",
                "selected_prover_byte_encoding_plan.json",
                "required_before_test_only_harness_execution",
            ),
            harness_artifact(
                "phase8_real_prover_implementation_checklist",
                "phase8-real-prover-implementation-checklist-v0",
                "phase8_real_prover_implementation_checklist.json",
                "required_before_test_only_harness_execution",
            ),
        ],
        expected_input_count: 3,
        output_artifacts: vec![
            harness_artifact(
                "winterfell_proof_preview",
                "winterfell-poc-proof-preview-v0",
                "winterfell_proof_preview.json",
                "expected_from_test_only_harness_execution",
            ),
            harness_artifact(
                "stark_proof_artifact_v1_candidate",
                "stark-proof-artifact-v1-candidate",
                "stark_proof_artifact_v1_candidate.json",
                "expected_from_test_only_harness_execution",
            ),
            harness_artifact(
                "stark_settlement_boundary_artifact",
                "stark-settlement-boundary-artifact-v0",
                "stark_settlement_boundary_artifact.json",
                "expected_from_test_only_harness_execution",
            ),
            harness_artifact(
                "phase8_harness_execution_log",
                "phase8-harness-execution-log-v0",
                "phase8_harness_execution_log.json",
                "expected_from_test_only_harness_execution",
            ),
        ],
        expected_output_count: 4,
        feature_gate_used: true,
        proof_preview_status: "winterfell_poc_proof_generated_and_verified_feature_only"
            .to_string(),
        proof_size_bytes: 4096,
        prove_ms: 17,
        verify_ms: 3,
        local_verification_status:
            Phase8TestOnlyProverHarnessExecutionReport::LOCAL_VERIFICATION_STATUS.to_string(),
        proof_bytes_status: Phase8TestOnlyProverHarnessExecutionReport::PROOF_BYTES_STATUS
            .to_string(),
        runtime_cutover_allowed: false,
        on_chain_submission_allowed: false,
        groth16_flow_unchanged: true,
        notes: vec!["test execution report".to_string()],
    }
}

fn harness_artifact(
    artifact_id: &str,
    schema_version: &str,
    path_hint: &str,
    requirement_status: &str,
) -> Phase8HarnessArtifact {
    Phase8HarnessArtifact {
        artifact_id: artifact_id.to_string(),
        schema_version: schema_version.to_string(),
        path_hint: path_hint.to_string(),
        requirement_status: requirement_status.to_string(),
    }
}

fn adapter_plan() -> Phase8RealProverBoundaryAdapterPlan {
    Phase8RealProverBoundaryAdapterPlan::from_execution_report(&execution_report()).unwrap()
}

#[test]
fn real_prover_boundary_adapter_generates_from_execution_report() {
    let plan = adapter_plan();

    plan.validate().unwrap();
    assert_eq!(
        plan.schema_version,
        Phase8RealProverBoundaryAdapterPlan::SCHEMA_VERSION
    );
    assert_eq!(plan.source_preview_prover, "winterfell_poc_preview");
    assert_eq!(plan.required_transformations.len(), 7);
    assert_eq!(plan.blocked_runtime_cutover_conditions.len(), 6);
    assert_eq!(
        plan.target_artifact_schema_version,
        "stark-proof-artifact-v1"
    );
    assert!(!plan.preview_artifact_reusable_for_runtime);
    assert!(!plan.real_proof_generation_allowed);
    assert!(plan.local_verification_required);
    assert!(!plan.runtime_cutover_allowed);
    assert!(!plan.on_chain_submission_allowed);
    assert!(plan.groth16_flow_unchanged);
}

#[test]
fn real_prover_boundary_adapter_json_round_trips() {
    let plan = adapter_plan();
    let json = serde_json::to_string_pretty(&plan).unwrap();
    let decoded: Phase8RealProverBoundaryAdapterPlan = serde_json::from_str(&json).unwrap();

    assert_eq!(decoded, plan);
    decoded.validate().unwrap();
}

#[test]
fn real_prover_boundary_adapter_rejects_preview_runtime_reuse() {
    let mut plan = adapter_plan();
    plan.preview_artifact_reusable_for_runtime = true;
    plan.real_proof_generation_allowed = true;

    let errors = plan.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error == "preview_artifact_reusable_for_runtime must be false")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "real_proof_generation_allowed must be false")
    );
}

#[test]
fn real_prover_boundary_adapter_rejects_runtime_cutover() {
    let mut plan = adapter_plan();
    plan.runtime_cutover_allowed = true;
    plan.on_chain_submission_allowed = true;

    let errors = plan.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error == "runtime_cutover_allowed must be false")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "on_chain_submission_allowed must be false")
    );
}

#[test]
fn real_prover_boundary_adapter_rejects_reordered_transformations() {
    let mut plan = adapter_plan();
    plan.required_transformations.swap(0, 1);

    let errors = plan.validate().unwrap_err();
    assert!(errors.iter().any(|error| {
        error
            == "required_transformations[0].transformation_id must be replace_preview_proof_bytes_with_real_proof_bytes"
    }));
}
