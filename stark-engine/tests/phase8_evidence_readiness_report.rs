use stark_engine::{
    Phase8EvidenceReadinessReport, Phase8HarnessArtifact, Phase8ImplementationEvidenceSlots,
    Phase8ImplementationSourceRegistry, Phase8RealProofArtifactReadinessGate,
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

fn evidence_slots() -> Phase8ImplementationEvidenceSlots {
    let plan =
        Phase8RealProverBoundaryAdapterPlan::from_execution_report(&execution_report()).unwrap();
    let gate = Phase8RealProofArtifactReadinessGate::from_boundary_adapter_plan(&plan).unwrap();
    let registry = Phase8ImplementationSourceRegistry::from_readiness_gate(&gate).unwrap();

    Phase8ImplementationEvidenceSlots::from_registry(&registry).unwrap()
}

fn readiness_report() -> Phase8EvidenceReadinessReport {
    Phase8EvidenceReadinessReport::from_evidence_slots(&evidence_slots()).unwrap()
}

#[test]
fn evidence_readiness_report_generates_from_evidence_slots() {
    let report = readiness_report();

    report.validate().unwrap();
    assert_eq!(
        report.schema_version,
        Phase8EvidenceReadinessReport::SCHEMA_VERSION
    );
    assert_eq!(
        report.report_status,
        Phase8EvidenceReadinessReport::REPORT_STATUS
    );
    assert_eq!(report.expected_transformation_count, 7);
    assert_eq!(report.populated_slot_count, 0);
    assert_eq!(report.missing_slot_count, 7);
    assert_eq!(report.missing_evidence_total, 28);
    assert_eq!(report.ready_transformation_count, 0);
    assert_eq!(report.blocked_transformation_count, 7);
    assert!(!report.real_proof_generation_allowed);
    assert!(!report.real_artifact_emission_allowed);
    assert!(!report.runtime_cutover_allowed);
    assert!(!report.on_chain_submission_allowed);
    assert!(report.groth16_flow_unchanged);
}

#[test]
fn evidence_readiness_report_json_round_trips() {
    let report = readiness_report();
    let json = serde_json::to_string_pretty(&report).unwrap();
    let decoded: Phase8EvidenceReadinessReport = serde_json::from_str(&json).unwrap();

    assert_eq!(decoded, report);
    decoded.validate().unwrap();
}

#[test]
fn evidence_readiness_report_summarizes_missing_real_prover_evidence() {
    let report = readiness_report();
    let real_prover_report = &report.transformation_reports[0];

    assert_eq!(
        real_prover_report.transformation_id,
        "replace_preview_proof_bytes_with_real_proof_bytes"
    );
    assert_eq!(
        real_prover_report.planned_module,
        "stark-engine/src/real_prover.rs"
    );
    assert_eq!(real_prover_report.required_evidence_count, 4);
    assert_eq!(
        real_prover_report.missing_evidence,
        vec![
            "real_prover_code_path",
            "real_proof_bytes_fixture",
            "real_prover_unit_tests",
            "local_real_proof_validation_log",
        ]
    );
    assert_eq!(real_prover_report.evidence_status, "evidence_missing");
    assert_eq!(
        real_prover_report.readiness_status,
        Phase8EvidenceReadinessReport::TRANSFORMATION_READINESS_STATUS
    );
    assert!(real_prover_report.blocks_real_proof_generation);
}

#[test]
fn evidence_readiness_report_rejects_runtime_enablement() {
    let mut report = readiness_report();
    report.real_proof_generation_allowed = true;
    report.real_artifact_emission_allowed = true;
    report.runtime_cutover_allowed = true;
    report.on_chain_submission_allowed = true;
    report.groth16_flow_unchanged = false;

    let errors = report.validate().unwrap_err();
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
    assert!(
        errors
            .iter()
            .any(|error| error == "groth16_flow_unchanged must be true")
    );
}

#[test]
fn evidence_readiness_report_rejects_premature_ready_transformation() {
    let mut report = readiness_report();
    report.ready_transformation_count = 1;
    report.blocked_transformation_count = 6;
    report.transformation_reports[0].missing_evidence.clear();
    report.transformation_reports[0].required_evidence_count = 0;
    report.transformation_reports[0].evidence_status = "evidence_present".to_string();
    report.transformation_reports[0].readiness_status = "ready".to_string();
    report.transformation_reports[0].blocks_real_proof_generation = false;

    let errors = report.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error == "ready_transformation_count must be 0")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "blocked_transformation_count must be 7")
    );
    assert!(errors.iter().any(|error| {
        error
            == "replace_preview_proof_bytes_with_real_proof_bytes.required_evidence_count must be 4"
    }));
    assert!(errors.iter().any(|error| {
        error
            == "replace_preview_proof_bytes_with_real_proof_bytes.missing_evidence must match the required evidence contract"
    }));
    assert!(errors.iter().any(|error| {
        error
            == "replace_preview_proof_bytes_with_real_proof_bytes.evidence_status must be evidence_missing"
    }));
    assert!(errors.iter().any(|error| {
        error
            == "replace_preview_proof_bytes_with_real_proof_bytes.readiness_status must be blocked_missing_evidence"
    }));
    assert!(errors.iter().any(|error| {
        error
            == "replace_preview_proof_bytes_with_real_proof_bytes.blocks_real_proof_generation must be true"
    }));
}
