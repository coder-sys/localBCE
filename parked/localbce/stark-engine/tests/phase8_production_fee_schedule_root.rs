#![cfg(feature = "production-air-winterfell")]

use stark_engine::{
    StarkBridgeInput,
    production_fee_schedule_root::{
        FEE_SCHEDULE_ROOT_LEAF_INDEX, FEE_SCHEDULE_ROOT_TREE_DEPTH,
        ProductionFeeScheduleRootArtifactV1,
    },
    source_roots::ProductionClaimSourceRootArtifactV1,
};

fn sample_bridge_input() -> StarkBridgeInput {
    serde_json::from_str(
        r#"{
          "schema_version":"stark-bridge-input-v0","producer":"rust-engine",
          "purpose":"stark_engine_compatibility_input","runtime_mode":"dry_run_or_optional_sidecar",
          "claim":{
            "claim_id":"CLAIM-FEE-ROOT-001","claim_amount":1000,
            "claim_hash":"0x1c1b60223d4f3ffd351887f834b31a4260508b1602a5a9e16a447ea40e386607",
            "member_id":"MEMBER-FIXTURE-001","provider_npi":"1234567893",
            "diagnosis_count":1,"max_charge_cents":150000,
            "diagnosis_codes":["Z00.00"],
            "service_lines":[{"procedure_code":"99213","charge_cents":100000,"units":1}],
            "fee_schedule_id":"DEMO-FEE-SCHEDULE-V1",
            "fee_schedule_entries":[
              {"fee_code":"99213","unit_amount_cents":100000,"currency":"USD","effective_from":19000,"effective_thru":21000,"source_url":"https://example.gov/demo/99213","verification_status":"verified"},
              {"fee_code":"99214","unit_amount_cents":125000,"currency":"USD","effective_from":19000,"effective_thru":21000,"source_url":"https://example.gov/demo/99214","verification_status":"verified"}
            ]
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
fn production_fee_schedule_root_round_trips_and_matches_claim_source_digest() {
    let bridge = sample_bridge_input();
    let artifact = ProductionFeeScheduleRootArtifactV1::from_bridge_input(&bridge).unwrap();
    let claim_source = ProductionClaimSourceRootArtifactV1::from_bridge_input(&bridge).unwrap();

    assert_eq!(artifact.validate(), Ok(()));
    assert_eq!(artifact.tree_depth, FEE_SCHEDULE_ROOT_TREE_DEPTH);
    assert_eq!(artifact.leaf_index, FEE_SCHEDULE_ROOT_LEAF_INDEX);
    assert_eq!(artifact.entry_count, 2);
    assert_eq!(artifact.verified_entry_count, 2);
    assert_eq!(artifact.matched_service_line_count, 1);
    assert_eq!(artifact.total_allowed_cents, 100_000);
    assert_eq!(artifact.total_charged_cents, 100_000);
    assert_eq!(
        &artifact.leaf_preimage_decimal[20..24],
        &claim_source.leaf_preimage_decimal[28..32]
    );
    assert!(!artifact.runtime_wired);
    assert!(!artifact.on_chain_submission);
    assert!(artifact.groth16_flow_unchanged);

    let json = serde_json::to_string_pretty(&artifact).unwrap();
    let decoded: ProductionFeeScheduleRootArtifactV1 = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, artifact);
    assert_eq!(decoded.validate(), Ok(()));
}

#[test]
fn fee_entry_order_does_not_change_the_root() {
    let bridge = sample_bridge_input();
    let expected = ProductionFeeScheduleRootArtifactV1::from_bridge_input(&bridge).unwrap();
    let mut reordered = bridge;
    reordered.claim.fee_schedule_entries.reverse();
    let actual = ProductionFeeScheduleRootArtifactV1::from_bridge_input(&reordered).unwrap();
    assert_eq!(
        actual.fee_schedule_root_bytes32,
        expected.fee_schedule_root_bytes32
    );
}

#[test]
fn fee_schedule_source_changes_change_the_root() {
    let bridge = sample_bridge_input();
    let expected = ProductionFeeScheduleRootArtifactV1::from_bridge_input(&bridge).unwrap();

    let mut schedule = bridge.clone();
    schedule.claim.fee_schedule_id = Some("DEMO-FEE-SCHEDULE-V2".to_string());
    let mut amount = bridge.clone();
    amount.claim.fee_schedule_entries[0].unit_amount_cents = 110_000;
    let mut source = bridge;
    source.claim.fee_schedule_entries[0].source_url =
        Some("https://example.gov/demo/99213-v2".to_string());

    for mutation in [schedule, amount, source] {
        let actual = ProductionFeeScheduleRootArtifactV1::from_bridge_input(&mutation).unwrap();
        assert_ne!(
            actual.fee_schedule_root_bytes32,
            expected.fee_schedule_root_bytes32
        );
    }
}

#[test]
fn tampered_fee_leaf_path_and_root_are_rejected() {
    let artifact =
        ProductionFeeScheduleRootArtifactV1::from_bridge_input(&sample_bridge_input()).unwrap();
    let mut leaf = artifact.clone();
    leaf.leaf_preimage_decimal[16] = "123".to_string();
    assert!(leaf.validate().is_err());
    let mut path = artifact.clone();
    path.merkle_path_elements[0][0] = "123".to_string();
    assert!(path.validate().is_err());
    let mut root = artifact;
    root.root_elements[0] = "123".to_string();
    assert!(root.validate().is_err());
}

#[test]
fn missing_unverified_insecure_ambiguous_and_underpriced_entries_are_rejected() {
    let mut missing = sample_bridge_input();
    missing.claim.fee_schedule_id = None;
    assert!(ProductionFeeScheduleRootArtifactV1::from_bridge_input(&missing).is_err());

    let mut unverified = sample_bridge_input();
    unverified.claim.fee_schedule_entries[0].verification_status = "candidate".to_string();
    assert!(ProductionFeeScheduleRootArtifactV1::from_bridge_input(&unverified).is_err());

    let mut insecure = sample_bridge_input();
    insecure.claim.fee_schedule_entries[0].source_url = Some("http://example.gov/fee".to_string());
    assert!(ProductionFeeScheduleRootArtifactV1::from_bridge_input(&insecure).is_err());

    let mut ambiguous = sample_bridge_input();
    ambiguous
        .claim
        .fee_schedule_entries
        .push(ambiguous.claim.fee_schedule_entries[0].clone());
    ambiguous.claim.fee_schedule_entries[2].source_url =
        Some("https://example.gov/demo/99213-copy".to_string());
    assert!(ProductionFeeScheduleRootArtifactV1::from_bridge_input(&ambiguous).is_err());

    let mut underpriced = sample_bridge_input();
    underpriced.claim.fee_schedule_entries[0].unit_amount_cents = 99_999;
    assert!(ProductionFeeScheduleRootArtifactV1::from_bridge_input(&underpriced).is_err());
}
