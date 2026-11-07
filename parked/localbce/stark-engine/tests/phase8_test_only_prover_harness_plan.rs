use stark_engine::{
    Phase8RealProverImplementationChecklist, Phase8RealProverWorkItem,
    Phase8TestOnlyProverHarnessPlan,
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

#[test]
fn test_only_prover_harness_plan_generates_from_checklist() {
    let plan = Phase8TestOnlyProverHarnessPlan::from_checklist(&checklist()).unwrap();

    plan.validate().unwrap();
    assert_eq!(
        plan.schema_version,
        Phase8TestOnlyProverHarnessPlan::SCHEMA_VERSION
    );
    assert_eq!(plan.selected_preview_prover, "winterfell_poc_preview");
    assert_eq!(plan.required_inputs.len(), 3);
    assert_eq!(plan.expected_outputs.len(), 4);
    assert!(plan.feature_gate_required);
    assert!(plan.test_only_proof_generation_allowed);
    assert!(!plan.runtime_cutover_allowed);
    assert!(!plan.on_chain_submission_allowed);
    assert!(plan.groth16_flow_unchanged);
}

#[test]
fn test_only_prover_harness_plan_json_round_trips() {
    let plan = Phase8TestOnlyProverHarnessPlan::from_checklist(&checklist()).unwrap();
    let json = serde_json::to_string_pretty(&plan).unwrap();
    let decoded: Phase8TestOnlyProverHarnessPlan = serde_json::from_str(&json).unwrap();

    assert_eq!(decoded, plan);
    decoded.validate().unwrap();
}

#[test]
fn test_only_prover_harness_plan_rejects_runtime_cutover() {
    let mut plan = Phase8TestOnlyProverHarnessPlan::from_checklist(&checklist()).unwrap();
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
fn test_only_prover_harness_plan_rejects_missing_feature_gate() {
    let mut plan = Phase8TestOnlyProverHarnessPlan::from_checklist(&checklist()).unwrap();
    plan.feature_gate_required = false;

    let errors = plan.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error == "feature_gate_required must be true")
    );
}

#[test]
fn test_only_prover_harness_plan_rejects_reordered_outputs() {
    let mut plan = Phase8TestOnlyProverHarnessPlan::from_checklist(&checklist()).unwrap();
    plan.expected_outputs.swap(0, 1);

    let errors = plan.validate().unwrap_err();
    assert!(errors.iter().any(|error| {
        error == "expected_outputs[0].artifact_id must be winterfell_proof_preview"
    }));
}
