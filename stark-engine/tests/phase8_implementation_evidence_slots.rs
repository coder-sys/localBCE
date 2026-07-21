use stark_engine::{
    Phase8HarnessArtifact, Phase8ImplementationEvidenceSlots, Phase8ImplementationSourceRegistry,
    Phase8RealProofArtifactReadinessGate, Phase8RealProverBoundaryAdapterPlan,
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

fn registry() -> Phase8ImplementationSourceRegistry {
    let plan =
        Phase8RealProverBoundaryAdapterPlan::from_execution_report(&execution_report()).unwrap();
    let gate = Phase8RealProofArtifactReadinessGate::from_boundary_adapter_plan(&plan).unwrap();

    Phase8ImplementationSourceRegistry::from_readiness_gate(&gate).unwrap()
}

fn evidence_slots() -> Phase8ImplementationEvidenceSlots {
    Phase8ImplementationEvidenceSlots::from_registry(&registry()).unwrap()
}

#[test]
fn implementation_evidence_slots_generate_from_registry() {
    let slots = evidence_slots();

    slots.validate().unwrap();
    assert_eq!(
        slots.schema_version,
        Phase8ImplementationEvidenceSlots::SCHEMA_VERSION
    );
    assert_eq!(
        slots.evidence_status,
        Phase8ImplementationEvidenceSlots::EVIDENCE_STATUS
    );
    assert_eq!(slots.evidence_slots.len(), 7);
    assert_eq!(slots.expected_slot_count, 7);
    assert_eq!(slots.populated_slot_count, 0);
    assert_eq!(slots.missing_slot_count, 7);
    assert!(!slots.real_proof_generation_allowed);
    assert!(!slots.real_artifact_emission_allowed);
    assert!(!slots.runtime_cutover_allowed);
    assert!(!slots.on_chain_submission_allowed);
    assert!(slots.groth16_flow_unchanged);
}

#[test]
fn implementation_evidence_slots_json_round_trips() {
    let slots = evidence_slots();
    let json = serde_json::to_string_pretty(&slots).unwrap();
    let decoded: Phase8ImplementationEvidenceSlots = serde_json::from_str(&json).unwrap();

    assert_eq!(decoded, slots);
    decoded.validate().unwrap();
}

#[test]
fn implementation_evidence_slots_name_required_evidence_for_real_prover() {
    let slots = evidence_slots();
    let real_prover_slot = &slots.evidence_slots[0];

    assert_eq!(
        real_prover_slot.transformation_id,
        "replace_preview_proof_bytes_with_real_proof_bytes"
    );
    assert_eq!(
        real_prover_slot.required_evidence,
        vec![
            "real_prover_code_path",
            "real_proof_bytes_fixture",
            "real_prover_unit_tests",
            "local_real_proof_validation_log",
        ]
    );
    assert!(real_prover_slot.evidence_artifacts.is_empty());
    assert_eq!(
        real_prover_slot.evidence_status,
        Phase8ImplementationEvidenceSlots::SLOT_EVIDENCE_STATUS
    );
    assert!(real_prover_slot.blocks_real_proof_generation);
}

#[test]
fn implementation_evidence_slots_reject_populated_evidence() {
    let mut slots = evidence_slots();
    slots.populated_slot_count = 1;
    slots.missing_slot_count = 6;
    slots.evidence_slots[0]
        .evidence_artifacts
        .push("stark-engine/src/real_prover.rs".to_string());
    slots.evidence_slots[0].evidence_status = "evidence_present".to_string();
    slots.evidence_slots[0].blocks_real_proof_generation = false;

    let errors = slots.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error == "populated_slot_count must be 0")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "missing_slot_count must be 7")
    );
    assert!(errors.iter().any(|error| {
        error
            == "replace_preview_proof_bytes_with_real_proof_bytes.evidence_artifacts must be empty"
    }));
    assert!(errors.iter().any(|error| {
        error
            == "replace_preview_proof_bytes_with_real_proof_bytes.evidence_status must be evidence_missing"
    }));
    assert!(errors.iter().any(|error| {
        error
            == "replace_preview_proof_bytes_with_real_proof_bytes.blocks_real_proof_generation must be true"
    }));
}

#[test]
fn implementation_evidence_slots_reject_runtime_enablement() {
    let mut slots = evidence_slots();
    slots.real_proof_generation_allowed = true;
    slots.real_artifact_emission_allowed = true;
    slots.runtime_cutover_allowed = true;
    slots.on_chain_submission_allowed = true;

    let errors = slots.validate().unwrap_err();
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
