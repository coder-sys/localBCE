use serde_json::json;
use stark_engine::{
    Phase8RealProverImplementationChecklist, Phase8RealProverWorkItem,
    Phase8TestOnlyProverHarnessExecutionReport, Phase8TestOnlyProverHarnessPlan,
    SelectedProverByteEncodingPlan, StarkProofArtifactV1Candidate,
    WinterfellCompleteWitnessCandidate,
};

fn checklist() -> Phase8RealProverImplementationChecklist {
    Phase8RealProverImplementationChecklist {
        schema_version: Phase8RealProverImplementationChecklist::SCHEMA_VERSION.to_string(),
        source_schema_version: Phase8RealProverImplementationChecklist::SOURCE_SCHEMA_VERSION
            .to_string(),
        checklist_status: Phase8RealProverImplementationChecklist::CHECKLIST_STATUS.to_string(),
        source_checkpoint_status: stark_engine::Phase8PreProverBundleCheckpoint::CHECKPOINT_STATUS
            .to_string(),
        work_items: Phase8RealProverImplementationChecklist::EXPECTED_WORK_ITEM_IDS
            .iter()
            .map(|item_id| Phase8RealProverWorkItem {
                item_id: (*item_id).to_string(),
                category: "test_category".to_string(),
                description: "test work item".to_string(),
                required_before: "runtime_cutover".to_string(),
                current_status: "pending".to_string(),
                blocks_runtime_cutover: true,
            })
            .collect(),
        expected_work_item_count: Phase8RealProverImplementationChecklist::EXPECTED_WORK_ITEM_IDS
            .len(),
        all_pre_prover_artifacts_validated: true,
        runtime_cutover_allowed: false,
        groth16_flow_unchanged: true,
        completion_gate: Phase8RealProverImplementationChecklist::COMPLETION_GATE.to_string(),
        notes: vec!["test checklist".to_string()],
    }
}

fn harness_plan() -> Phase8TestOnlyProverHarnessPlan {
    Phase8TestOnlyProverHarnessPlan::from_checklist(&checklist()).unwrap()
}

fn complete_witness_candidate_json() -> serde_json::Value {
    json!({
        "schema_version": WinterfellCompleteWitnessCandidate::SCHEMA_VERSION
    })
}

fn selected_prover_byte_encoding_plan_json() -> serde_json::Value {
    json!({
        "schema_version": SelectedProverByteEncodingPlan::SCHEMA_VERSION,
        "plan_status": SelectedProverByteEncodingPlan::PLAN_STATUS
    })
}

fn checklist_json() -> serde_json::Value {
    json!({
        "schema_version": Phase8RealProverImplementationChecklist::SCHEMA_VERSION,
        "checklist_status": Phase8RealProverImplementationChecklist::CHECKLIST_STATUS
    })
}

fn proof_preview_json() -> serde_json::Value {
    json!({
        "schema_version": "winterfell-poc-proof-preview-v0",
        "proof_status": "winterfell_poc_proof_generated_and_verified_feature_only",
        "proof_size_bytes": 4096,
        "prove_ms": 17,
        "verify_ms": 3,
        "verified": true,
        "proof_generation_enabled": true,
        "runtime_wired": false,
        "on_chain_submission": false
    })
}

fn proof_artifact_candidate_json() -> serde_json::Value {
    json!({
        "schema_version": StarkProofArtifactV1Candidate::SCHEMA_VERSION,
        "artifact_status": StarkProofArtifactV1Candidate::ARTIFACT_STATUS
    })
}

fn settlement_boundary_artifact_json() -> serde_json::Value {
    json!({
        "schema_version": "stark-settlement-boundary-artifact-v0",
        "artifact_status": "settlement_boundary_preview_not_runtime",
        "runtime_wired": false,
        "on_chain_submission": false,
        "groth16_flow_unchanged": true
    })
}

fn execution_report() -> Phase8TestOnlyProverHarnessExecutionReport {
    Phase8TestOnlyProverHarnessExecutionReport::from_artifact_json_values(
        &harness_plan(),
        &complete_witness_candidate_json(),
        &selected_prover_byte_encoding_plan_json(),
        &checklist_json(),
        &proof_preview_json(),
        &proof_artifact_candidate_json(),
        &settlement_boundary_artifact_json(),
    )
    .unwrap()
}

#[test]
fn test_only_prover_harness_execution_report_generates_from_artifacts() {
    let report = execution_report();

    report.validate().unwrap();
    assert_eq!(
        report.schema_version,
        Phase8TestOnlyProverHarnessExecutionReport::SCHEMA_VERSION
    );
    assert_eq!(report.input_artifacts.len(), 3);
    assert_eq!(report.output_artifacts.len(), 4);
    assert!(report.feature_gate_used);
    assert_eq!(report.proof_size_bytes, 4096);
    assert_eq!(
        report.local_verification_status,
        "winterfell_preview_verified_locally"
    );
    assert!(!report.runtime_cutover_allowed);
    assert!(!report.on_chain_submission_allowed);
    assert!(report.groth16_flow_unchanged);
}

#[test]
fn test_only_prover_harness_execution_report_json_round_trips() {
    let report = execution_report();
    let json = serde_json::to_string_pretty(&report).unwrap();
    let decoded: Phase8TestOnlyProverHarnessExecutionReport = serde_json::from_str(&json).unwrap();

    assert_eq!(decoded, report);
    decoded.validate().unwrap();
}

#[test]
fn test_only_prover_harness_execution_report_rejects_runtime_cutover() {
    let mut report = execution_report();
    report.runtime_cutover_allowed = true;
    report.on_chain_submission_allowed = true;

    let errors = report.validate().unwrap_err();
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
fn test_only_prover_harness_execution_report_rejects_missing_feature_gate() {
    let mut report = execution_report();
    report.feature_gate_used = false;

    let errors = report.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error == "feature_gate_used must be true")
    );
}

#[test]
fn test_only_prover_harness_execution_report_rejects_unverified_preview() {
    let mut proof_preview = proof_preview_json();
    proof_preview["verified"] = json!(false);

    let errors = Phase8TestOnlyProverHarnessExecutionReport::from_artifact_json_values(
        &harness_plan(),
        &complete_witness_candidate_json(),
        &selected_prover_byte_encoding_plan_json(),
        &checklist_json(),
        &proof_preview,
        &proof_artifact_candidate_json(),
        &settlement_boundary_artifact_json(),
    )
    .unwrap_err();

    assert!(
        errors
            .iter()
            .any(|error| error == "winterfell_proof_preview.verified must be true")
    );
}
