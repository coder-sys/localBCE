#![cfg(feature = "production-air-winterfell")]

use std::time::{SystemTime, UNIX_EPOCH};

use stark_engine::{
    StarkBridgeInput,
    production_nullifier_state::{
        ProductionNullifierStateV1, acquire_production_nullifier_state_lock,
        load_production_nullifier_state, write_production_nullifier_state_atomic,
    },
};

fn sample_bridge_input() -> StarkBridgeInput {
    serde_json::from_str(
        r#"{
          "schema_version":"stark-bridge-input-v0","producer":"rust-engine",
          "purpose":"stark_engine_compatibility_input","runtime_mode":"dry_run_or_optional_sidecar",
          "claim":{
            "claim_id":"CLAIM-NULLIFIER-STATE-001","claim_amount":1000,
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

fn bridge_with_hash(suffix_hash: &str, claim_id: &str) -> StarkBridgeInput {
    let mut bridge = sample_bridge_input();
    bridge.claim.claim_id = claim_id.to_string();
    bridge.claim.claim_hash = suffix_hash.to_string();
    bridge.public_inputs.claim_hash = suffix_hash.to_string();
    bridge
}

#[test]
fn approved_transition_persists_and_advances_generation() {
    let bridge = sample_bridge_input();
    let mut state = ProductionNullifierStateV1::empty().unwrap();
    let transition = state.prepare_transition(&bridge).unwrap();
    let receipt = state.apply_transition(&transition).unwrap();

    assert_eq!(state.validate(), Ok(()));
    assert_eq!(state.generation, 1);
    assert_eq!(state.leaves.len(), 1);
    assert_eq!(receipt.generation_before, 0);
    assert_eq!(receipt.generation_after, 1);
    assert_eq!(receipt.root_after_bytes32, state.root_bytes32);
    assert_ne!(receipt.root_before_bytes32, receipt.root_after_bytes32);
}

#[test]
fn duplicate_and_deterministic_index_collision_are_rejected() {
    let bridge = sample_bridge_input();
    let mut state = ProductionNullifierStateV1::empty().unwrap();
    let transition = state.prepare_transition(&bridge).unwrap();
    state.apply_transition(&transition).unwrap();

    assert!(state.prepare_transition(&bridge).is_err());
    let collision = bridge_with_hash(
        "0x2c1b60223d4f3ffd351887f834b31a4260508b1602a5a9e16a447ea40e386607",
        "CLAIM-NULLIFIER-STATE-COLLISION",
    );
    assert!(state.prepare_transition(&collision).is_err());
}

#[test]
fn stale_transition_fails_compare_and_swap() {
    let first_bridge = sample_bridge_input();
    let second_bridge = bridge_with_hash(
        "0x1c1b60223d4f3ffd351887f834b31a4260508b1602a5a9e16a447ea40e3865ab",
        "CLAIM-NULLIFIER-STATE-002",
    );
    let state = ProductionNullifierStateV1::empty().unwrap();
    let first = state.prepare_transition(&first_bridge).unwrap();
    let stale = state.prepare_transition(&second_bridge).unwrap();
    let mut advanced = state;
    advanced.apply_transition(&first).unwrap();

    let errors = advanced.apply_transition(&stale).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.contains("stale transition"))
    );
}

#[test]
fn denied_transition_is_a_valid_no_op() {
    let mut bridge = sample_bridge_input();
    bridge.adjudication.decision = 0;
    bridge.adjudication.failure_code = 7;
    bridge.adjudication.failure_reason = Some("G7_DUPLICATE_CLAIM".to_string());
    bridge.active_rust_facts.is_duplicate = 1;
    bridge.winterfell_poc_mapping.direct.duplicate_flag = 1;
    bridge.public_inputs.decision = 0;
    bridge.public_inputs.failure_code = 7;
    let mut state = ProductionNullifierStateV1::empty().unwrap();
    let before = state.clone();
    let transition = state.prepare_transition(&bridge).unwrap();
    let receipt = state.apply_transition(&transition).unwrap();

    assert_eq!(state, before);
    assert!(!receipt.transition_applied);
    assert_eq!(receipt.generation_before, receipt.generation_after);
    assert_eq!(receipt.root_before_bytes32, receipt.root_after_bytes32);
}

#[test]
fn file_provider_is_atomic_and_exclusive() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "localbce-nullifier-state-{}-{unique}.json",
        std::process::id()
    ));
    let state = ProductionNullifierStateV1::empty().unwrap();
    write_production_nullifier_state_atomic(&path, &state).unwrap();
    assert_eq!(load_production_nullifier_state(&path).unwrap(), state);

    let first_lock = acquire_production_nullifier_state_lock(&path).unwrap();
    assert!(acquire_production_nullifier_state_lock(&path).is_err());
    drop(first_lock);
    let second_lock = acquire_production_nullifier_state_lock(&path).unwrap();
    drop(second_lock);
    std::fs::remove_file(path).unwrap();
}
