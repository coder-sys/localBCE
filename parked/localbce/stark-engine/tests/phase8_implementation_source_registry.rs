use stark_engine::{
    Phase8HarnessArtifact, Phase8ImplementationSourceRegistry,
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

fn readiness_gate() -> Phase8RealProofArtifactReadinessGate {
    let plan =
        Phase8RealProverBoundaryAdapterPlan::from_execution_report(&execution_report()).unwrap();

    Phase8RealProofArtifactReadinessGate::from_boundary_adapter_plan(&plan).unwrap()
}

fn implementation_source_registry() -> Phase8ImplementationSourceRegistry {
    Phase8ImplementationSourceRegistry::from_readiness_gate(&readiness_gate()).unwrap()
}

#[test]
fn implementation_source_registry_generates_from_readiness_gate() {
    let registry = implementation_source_registry();

    registry.validate().unwrap();
    assert_eq!(
        registry.schema_version,
        Phase8ImplementationSourceRegistry::SCHEMA_VERSION
    );
    assert_eq!(
        registry.registry_status,
        Phase8ImplementationSourceRegistry::REGISTRY_STATUS
    );
    assert_eq!(registry.planned_sources.len(), 7);
    assert_eq!(registry.expected_source_count, 7);
    assert_eq!(registry.satisfied_gate_count, 0);
    assert_eq!(registry.unsatisfied_gate_count, 7);
    assert_eq!(
        registry.implementation_evidence_status,
        Phase8ImplementationSourceRegistry::IMPLEMENTATION_EVIDENCE_STATUS
    );
    assert!(!registry.real_proof_generation_allowed);
    assert!(!registry.real_artifact_emission_allowed);
    assert!(!registry.runtime_cutover_allowed);
    assert!(!registry.on_chain_submission_allowed);
    assert!(registry.groth16_flow_unchanged);
}

#[test]
fn implementation_source_registry_json_round_trips() {
    let registry = implementation_source_registry();
    let json = serde_json::to_string_pretty(&registry).unwrap();
    let decoded: Phase8ImplementationSourceRegistry = serde_json::from_str(&json).unwrap();

    assert_eq!(decoded, registry);
    decoded.validate().unwrap();
}

#[test]
fn implementation_source_registry_names_all_planned_modules() {
    let registry = implementation_source_registry();
    let planned_modules = registry
        .planned_sources
        .iter()
        .map(|entry| entry.planned_module.as_str())
        .collect::<Vec<_>>();

    assert_eq!(
        planned_modules,
        vec![
            "stark-engine/src/real_prover.rs",
            "stark-engine/src/root_semantics.rs",
            "stark-engine/src/public_inputs.rs",
            "stark-engine/src/source_roots.rs",
            "stark-engine/src/proof_commitment.rs",
            "stark-engine/src/local_verifier.rs",
            "stark-engine/src/proof_artifact.rs",
        ]
    );
}

#[test]
fn implementation_source_registry_rejects_premature_evidence() {
    let mut registry = implementation_source_registry();
    registry.satisfied_gate_count = 1;
    registry.unsatisfied_gate_count = 6;
    registry.implementation_evidence_status = "implemented_with_evidence".to_string();
    registry.planned_sources[0].implementation_status = "implemented".to_string();
    registry.planned_sources[0].blocks_real_proof_generation = false;

    let errors = registry.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error == "satisfied_gate_count must be 0")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "unsatisfied_gate_count must be 7")
    );
    assert!(errors.iter().any(|error| {
        error == "implementation_evidence_status must be planned_not_implemented_no_evidence"
    }));
    assert!(errors.iter().any(|error| {
        error
            == "replace_preview_proof_bytes_with_real_proof_bytes.implementation_status must be planned_not_implemented"
    }));
    assert!(errors.iter().any(|error| {
        error
            == "replace_preview_proof_bytes_with_real_proof_bytes.blocks_real_proof_generation must be true"
    }));
}

#[test]
fn implementation_source_registry_rejects_runtime_enablement() {
    let mut registry = implementation_source_registry();
    registry.real_proof_generation_allowed = true;
    registry.real_artifact_emission_allowed = true;
    registry.runtime_cutover_allowed = true;
    registry.on_chain_submission_allowed = true;

    let errors = registry.validate().unwrap_err();
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
