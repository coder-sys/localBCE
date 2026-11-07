#![cfg(feature = "production-air-winterfell")]

use stark_engine::{
    StarkBridgeInput,
    production_nullifier_root_transition::{
        NULLIFIER_ROOT_TREE_DEPTH, ProductionNullifierRootTransitionArtifactV1,
        canonical_nullifier_leaf_index,
    },
};

fn sample_bridge_input() -> StarkBridgeInput {
    serde_json::from_str(
        r#"{
          "schema_version":"stark-bridge-input-v0","producer":"rust-engine",
          "purpose":"stark_engine_compatibility_input","runtime_mode":"dry_run_or_optional_sidecar",
          "claim":{
            "claim_id":"CLAIM-NULLIFIER-001","claim_amount":1000,
            "claim_hash":"0x1c1b60223d4f3ffd351887f834b31a4260508b1602a5a9e16a447ea40e386607",
            "member_id":"MEMBER-FIXTURE-001","provider_npi":"1234567893",
            "diagnosis_count":1,"max_charge_cents":150000,
            "diagnosis_codes":["Z00.00"],
            "service_lines":[{"procedure_code":"99213","charge_cents":100000,"units":1}],
            "fee_schedule_id":"DEMO-FEE-SCHEDULE-V1",
            "fee_schedule_entries":[{"fee_code":"99213","unit_amount_cents":100000,"currency":"USD","effective_from":19000,"effective_thru":21000,"source_url":"https://example.gov/demo/99213","verification_status":"verified"}]
          },
          "adjudication":{"decision":1,"failure_code":0,"failure_reason":null,"ruleset_id":"current_g1_g10_denial_reason"},
          "active_rust_facts":{"eligibility_active":1,"aid_code":53,"benefit_level_exists":1,"date_of_service_from":20000,"eligibility_period_from":19900,"eligibility_period_thru":21000,"soc_amount":0,"soc_met":1,"provider_enrolled":1,"provider_type_valid":1,"billing_code_valid":1,"units_valid":1,"is_duplicate":0,"disability_determination_valid":1,"recipient_not_deceased":1,"physician_certification_valid":1},
          "winterfell_poc_mapping":{"direct":{"eligibility_active":1,"provider_enrolled":1,"duplicate_flag":0},"partial":{"service_line_count":{"source":["billing_code_valid","units_valid"],"status":"not_equivalent"},"prior_auth_ok":{"source":["physician_certification_valid"],"status":"not_equivalent"},"charge_cents":{"source":["claim_amount"],"status":"requires_unit_normalization"},"program_integrity_hold":{"source":["disability_determination_valid","recipient_not_deceased"],"status":"not_equivalent"}},"unmapped":{"member_id":6252503343996011870,"provider_npi":1234567893,"diagnosis_count":1,"max_charge_cents":150000}},
          "public_inputs":{"claim_hash":"0x1c1b60223d4f3ffd351887f834b31a4260508b1602a5a9e16a447ea40e386607","decision":1,"failure_code":0,"ruleset_id":"current_g1_g10_denial_reason"},
          "proof_status":{"stark_proof_generated":false,"winterfell_poc_compatible":false,"groth16_flow_unchanged":true,"on_chain_submission":false}
        }"#,
    )
    .unwrap()
}

#[test]
fn approved_claim_produces_canonical_bootstrap_transition() {
    let bridge = sample_bridge_input();
    let artifact = ProductionNullifierRootTransitionArtifactV1::from_bridge_input(&bridge).unwrap();

    assert_eq!(artifact.validate(), Ok(()));
    assert_eq!(artifact.tree_depth, NULLIFIER_ROOT_TREE_DEPTH);
    assert_eq!(
        artifact.leaf_index,
        canonical_nullifier_leaf_index(&bridge.claim.claim_hash).unwrap()
    );
    assert_eq!(
        artifact.merkle_path_elements.len(),
        NULLIFIER_ROOT_TREE_DEPTH
    );
    assert_eq!(
        artifact.merkle_path_indices.len(),
        NULLIFIER_ROOT_TREE_DEPTH
    );
    assert!(artifact.transition_applied);
    assert_ne!(
        artifact.nullifier_root_before_bytes32,
        artifact.nullifier_root_after_bytes32
    );
    assert!(!artifact.runtime_wired);
    assert!(!artifact.on_chain_verifier_wired);
    assert!(!artifact.on_chain_submission);
    assert!(artifact.groth16_flow_unchanged);

    let json = serde_json::to_string_pretty(&artifact).unwrap();
    let decoded: ProductionNullifierRootTransitionArtifactV1 = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, artifact);
    assert_eq!(decoded.validate(), Ok(()));
}

#[test]
fn denied_claim_leaves_bootstrap_root_unchanged() {
    let mut bridge = sample_bridge_input();
    bridge.adjudication.decision = 0;
    bridge.adjudication.failure_code = 7;
    bridge.adjudication.failure_reason = Some("G7_DUPLICATE_CLAIM".to_string());
    bridge.active_rust_facts.is_duplicate = 1;
    bridge.winterfell_poc_mapping.direct.duplicate_flag = 1;
    bridge.public_inputs.decision = 0;
    bridge.public_inputs.failure_code = 7;

    let artifact = ProductionNullifierRootTransitionArtifactV1::from_bridge_input(&bridge).unwrap();

    assert_eq!(artifact.validate(), Ok(()));
    assert!(!artifact.transition_applied);
    assert_eq!(
        artifact.nullifier_root_before_bytes32,
        artifact.nullifier_root_after_bytes32
    );
}

#[test]
fn claim_hash_changes_nullifier_and_transition_root() {
    let bridge = sample_bridge_input();
    let first = ProductionNullifierRootTransitionArtifactV1::from_bridge_input(&bridge).unwrap();
    let mut changed = bridge;
    changed.claim.claim_hash =
        "0x1c1b60223d4f3ffd351887f834b31a4260508b1602a5a9e16a447ea40e3865ab".to_string();
    changed.public_inputs.claim_hash = changed.claim.claim_hash.clone();
    let second = ProductionNullifierRootTransitionArtifactV1::from_bridge_input(&changed).unwrap();

    assert_ne!(first.nullifier_bytes32, second.nullifier_bytes32);
    assert_ne!(first.leaf_index, second.leaf_index);
    assert_ne!(
        first.nullifier_root_after_bytes32,
        second.nullifier_root_after_bytes32
    );
}

#[test]
fn tampered_digest_path_and_roots_are_rejected() {
    let artifact =
        ProductionNullifierRootTransitionArtifactV1::from_bridge_input(&sample_bridge_input())
            .unwrap();

    let mut digest = artifact.clone();
    digest.nullifier_digest_elements[0] = "123".to_string();
    assert!(digest.validate().is_err());

    let mut path = artifact.clone();
    path.merkle_path_elements[0][0] = "123".to_string();
    assert!(path.validate().is_err());

    let mut before = artifact.clone();
    before.nullifier_root_before_elements[0] = "123".to_string();
    assert!(before.validate().is_err());

    let mut after = artifact;
    after.nullifier_root_after_elements[0] = "123".to_string();
    assert!(after.validate().is_err());
}

#[test]
fn bootstrap_artifact_cannot_claim_runtime_or_governance_readiness() {
    let artifact =
        ProductionNullifierRootTransitionArtifactV1::from_bridge_input(&sample_bridge_input())
            .unwrap();

    let mut runtime = artifact.clone();
    runtime.runtime_wired = true;
    assert!(runtime.validate().is_err());

    let mut governance = artifact;
    governance.governance_status = "approved".to_string();
    assert!(governance.validate().is_err());
}
