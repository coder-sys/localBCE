use stark_engine::{
    Phase8HarnessArtifact, Phase8ReadinessTransformationGate, Phase8RealProofArtifactReadinessGate,
    Phase8RealProverBoundaryAdapterPlan, Phase8TestOnlyProverHarnessExecutionReport,
    Phase8TestOnlyProverHarnessPlan,
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

fn boundary_adapter_plan() -> Phase8RealProverBoundaryAdapterPlan {
    Phase8RealProverBoundaryAdapterPlan::from_execution_report(&execution_report()).unwrap()
}

fn readiness_gate() -> Phase8RealProofArtifactReadinessGate {
    Phase8RealProofArtifactReadinessGate::from_boundary_adapter_plan(&boundary_adapter_plan())
        .unwrap()
}

#[test]
fn readiness_gate_generates_from_boundary_adapter_plan() {
    let gate = readiness_gate();

    gate.validate().unwrap();
    assert_eq!(
        gate.schema_version,
        Phase8RealProofArtifactReadinessGate::SCHEMA_VERSION
    );
    assert_eq!(
        gate.readiness_status,
        Phase8RealProofArtifactReadinessGate::READINESS_STATUS
    );
    assert_eq!(gate.transformation_gates.len(), 7);
    assert_eq!(gate.expected_transformation_gate_count, 7);
    assert_eq!(gate.satisfied_gate_count, 0);
    assert_eq!(gate.unsatisfied_gate_count, 7);
    assert_eq!(gate.blockers.len(), 6);
    assert_eq!(gate.expected_blocker_count, 6);
    assert!(!gate.real_proof_generation_allowed);
    assert!(!gate.real_artifact_emission_allowed);
    assert!(!gate.runtime_cutover_allowed);
    assert!(!gate.on_chain_submission_allowed);
    assert!(gate.groth16_flow_unchanged);
}

#[test]
fn readiness_gate_json_round_trips() {
    let gate = readiness_gate();
    let json = serde_json::to_string_pretty(&gate).unwrap();
    let decoded: Phase8RealProofArtifactReadinessGate = serde_json::from_str(&json).unwrap();

    assert_eq!(decoded, gate);
    decoded.validate().unwrap();
}

#[test]
fn readiness_gate_rejects_real_proof_or_runtime_enablement() {
    let mut gate = readiness_gate();
    gate.real_proof_generation_allowed = true;
    gate.real_artifact_emission_allowed = true;
    gate.runtime_cutover_allowed = true;
    gate.on_chain_submission_allowed = true;

    let errors = gate.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error == "real_proof_generation_allowed must be false")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "real_artifact_emission_allowed must be false")
    );
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
fn readiness_gate_rejects_premature_satisfied_gate() {
    let mut gate = readiness_gate();
    gate.satisfied_gate_count = 1;
    gate.unsatisfied_gate_count = 6;
    gate.transformation_gates[0] = Phase8ReadinessTransformationGate {
        transformation_id: "replace_preview_proof_bytes_with_real_proof_bytes".to_string(),
        implementation_source: Some("stark-engine/src/real_prover.rs".to_string()),
        readiness_status: "implementation_source_present".to_string(),
        blocks_real_proof_generation: false,
    };

    let errors = gate.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error == "satisfied_gate_count must be 0")
    );
    assert!(
        errors
            .iter()
            .any(|error| { error == "unsatisfied_gate_count must be 7" })
    );
    assert!(errors.iter().any(|error| {
        error
            == "replace_preview_proof_bytes_with_real_proof_bytes.implementation_source must be null"
    }));
    assert!(errors.iter().any(|error| {
        error
            == "replace_preview_proof_bytes_with_real_proof_bytes.readiness_status must be implementation_source_missing"
    }));
    assert!(errors.iter().any(|error| {
        error
            == "replace_preview_proof_bytes_with_real_proof_bytes.blocks_real_proof_generation must be true"
    }));
}

#[test]
fn readiness_gate_rejects_missing_required_blocker() {
    let mut gate = readiness_gate();
    gate.blockers.pop();

    let errors = gate.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error == "blockers must contain exactly 6 values")
    );
}
