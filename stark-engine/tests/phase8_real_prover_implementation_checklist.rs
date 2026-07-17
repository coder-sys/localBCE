use stark_engine::{
    Phase8CheckpointArtifact, Phase8PreProverBundleCheckpoint,
    Phase8RealProverImplementationChecklist,
};

fn checkpoint() -> Phase8PreProverBundleCheckpoint {
    Phase8PreProverBundleCheckpoint {
        schema_version: Phase8PreProverBundleCheckpoint::SCHEMA_VERSION.to_string(),
        source_schema_version: Phase8PreProverBundleCheckpoint::SOURCE_SCHEMA_VERSION.to_string(),
        checkpoint_status: Phase8PreProverBundleCheckpoint::CHECKPOINT_STATUS.to_string(),
        artifacts: Phase8PreProverBundleCheckpoint::EXPECTED_ARTIFACT_IDS
            .iter()
            .map(|artifact_id| Phase8CheckpointArtifact {
                artifact_id: (*artifact_id).to_string(),
                schema_version: format!("{artifact_id}-schema"),
                status: "planning_status".to_string(),
                validation_status: "validated".to_string(),
            })
            .collect(),
        expected_artifact_count: Phase8PreProverBundleCheckpoint::EXPECTED_ARTIFACT_IDS.len(),
        all_artifacts_validated: true,
        all_source_roots_bound: true,
        production_hash_selected: false,
        runtime_wiring_allowed: false,
        proof_generation_enabled: false,
        groth16_flow_unchanged: true,
        recommended_next_steps: vec!["test next step".to_string()],
        notes: vec!["test checkpoint".to_string()],
    }
}

#[test]
fn real_prover_checklist_generates_from_valid_checkpoint() {
    let checklist =
        Phase8RealProverImplementationChecklist::from_checkpoint(&checkpoint()).unwrap();

    checklist.validate().unwrap();
    assert_eq!(
        checklist.schema_version,
        Phase8RealProverImplementationChecklist::SCHEMA_VERSION
    );
    assert_eq!(checklist.work_items.len(), 7);
    assert!(checklist.all_pre_prover_artifacts_validated);
    assert!(!checklist.runtime_cutover_allowed);
    assert!(checklist.groth16_flow_unchanged);
    assert!(
        checklist
            .work_items
            .iter()
            .all(|item| item.blocks_runtime_cutover)
    );
}

#[test]
fn real_prover_checklist_json_round_trips() {
    let checklist =
        Phase8RealProverImplementationChecklist::from_checkpoint(&checkpoint()).unwrap();
    let json = serde_json::to_string_pretty(&checklist).unwrap();
    let decoded: Phase8RealProverImplementationChecklist = serde_json::from_str(&json).unwrap();

    assert_eq!(decoded, checklist);
    decoded.validate().unwrap();
}

#[test]
fn real_prover_checklist_rejects_runtime_cutover() {
    let mut checklist =
        Phase8RealProverImplementationChecklist::from_checkpoint(&checkpoint()).unwrap();
    checklist.runtime_cutover_allowed = true;

    let errors = checklist.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error == "runtime_cutover_allowed must be false")
    );
}

#[test]
fn real_prover_checklist_rejects_unvalidated_pre_prover_bundle() {
    let mut bad_checkpoint = checkpoint();
    bad_checkpoint.all_artifacts_validated = false;

    let errors =
        Phase8RealProverImplementationChecklist::from_checkpoint(&bad_checkpoint).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error == "all_artifacts_validated must be true")
    );
}

#[test]
fn real_prover_checklist_rejects_nonblocking_work_item() {
    let mut checklist =
        Phase8RealProverImplementationChecklist::from_checkpoint(&checkpoint()).unwrap();
    checklist.work_items[0].blocks_runtime_cutover = false;

    let errors = checklist.validate().unwrap_err();
    assert!(errors.iter().any(|error| {
        error == "select_production_hash_and_root_semantics.blocks_runtime_cutover must be true"
    }));
}
