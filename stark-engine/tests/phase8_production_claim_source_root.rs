#![cfg(feature = "production-air-winterfell")]

use stark_engine::{
    StarkBridgeInput,
    source_roots::{
        CLAIM_SOURCE_ROOT_LEAF_INDEX, CLAIM_SOURCE_ROOT_TREE_DEPTH,
        ProductionClaimSourceRootArtifactV1,
    },
};

fn sample_bridge_input() -> StarkBridgeInput {
    serde_json::from_str(
        r#"{
          "schema_version": "stark-bridge-input-v0",
          "producer": "rust-engine",
          "purpose": "stark_engine_compatibility_input",
          "runtime_mode": "dry_run_or_optional_sidecar",
          "claim": {
            "claim_id": "CLAIM-SOURCE-ROOT-001",
            "claim_amount": 1000,
            "claim_hash": "0x1c1b60223d4f3ffd351887f834b31a4260508b1602a5a9e16a447ea40e386607",
            "member_id": "MEMBER-FIXTURE-001",
            "provider_npi": "1234567893",
            "diagnosis_count": 1,
            "max_charge_cents": 150000,
            "diagnosis_codes": ["Z00.00"],
            "service_lines": [
              {
                "procedure_code": "99213",
                "charge_cents": 100000,
                "units": 1
              }
            ]
          },
          "adjudication": {
            "decision": 1,
            "failure_code": 0,
            "failure_reason": null,
            "ruleset_id": "current_g1_g10_denial_reason"
          },
          "active_rust_facts": {
            "eligibility_active": 1,
            "aid_code": 53,
            "benefit_level_exists": 1,
            "date_of_service_from": 20000,
            "eligibility_period_from": 19900,
            "eligibility_period_thru": 21000,
            "soc_amount": 0,
            "soc_met": 1,
            "provider_enrolled": 1,
            "provider_type_valid": 1,
            "billing_code_valid": 1,
            "units_valid": 1,
            "is_duplicate": 0,
            "disability_determination_valid": 1,
            "recipient_not_deceased": 1,
            "physician_certification_valid": 1
          },
          "winterfell_poc_mapping": {
            "direct": {
              "eligibility_active": 1,
              "provider_enrolled": 1,
              "duplicate_flag": 0
            },
            "partial": {
              "service_line_count": {
                "source": ["billing_code_valid", "units_valid"],
                "status": "not_equivalent"
              },
              "prior_auth_ok": {
                "source": ["physician_certification_valid"],
                "status": "not_equivalent"
              },
              "charge_cents": {
                "source": ["claim_amount"],
                "status": "requires_unit_normalization"
              },
              "program_integrity_hold": {
                "source": ["disability_determination_valid", "recipient_not_deceased"],
                "status": "not_equivalent"
              }
            },
            "unmapped": {
              "member_id": 6252503343996011870,
              "provider_npi": 1234567893,
              "diagnosis_count": 1,
              "max_charge_cents": 150000
            }
          },
          "public_inputs": {
            "claim_hash": "0x1c1b60223d4f3ffd351887f834b31a4260508b1602a5a9e16a447ea40e386607",
            "decision": 1,
            "failure_code": 0,
            "ruleset_id": "current_g1_g10_denial_reason"
          },
          "proof_status": {
            "stark_proof_generated": false,
            "winterfell_poc_compatible": false,
            "groth16_flow_unchanged": true,
            "on_chain_submission": false
          }
        }"#,
    )
    .unwrap()
}

#[test]
fn production_claim_source_root_round_trips_and_preserves_safety_boundaries() {
    let artifact =
        ProductionClaimSourceRootArtifactV1::from_bridge_input(&sample_bridge_input()).unwrap();

    assert_eq!(artifact.validate(), Ok(()));
    assert_eq!(artifact.tree_depth, CLAIM_SOURCE_ROOT_TREE_DEPTH);
    assert_eq!(artifact.leaf_index, CLAIM_SOURCE_ROOT_LEAF_INDEX);
    assert_eq!(
        artifact.merkle_path_elements.len(),
        CLAIM_SOURCE_ROOT_TREE_DEPTH
    );
    assert_eq!(
        artifact.merkle_path_indices,
        vec![1, 0, 1, 0, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(artifact.service_line_count, 1);
    assert_eq!(artifact.diagnosis_count, 1);
    assert_eq!(artifact.total_charge_cents, 100_000);
    assert_eq!(
        artifact.claim_source_root_bytes32,
        "0x784ddb9d5eb5e9aa0a5c0e997dcfd91e38418cd14bc9501436eb124d745a84b1"
    );
    assert_eq!(artifact.governance_status, "not_registered_or_approved");
    assert_eq!(
        artifact.air_binding_status,
        "not_constrained_by_production_air"
    );
    assert!(!artifact.runtime_wired);
    assert!(!artifact.on_chain_verifier_wired);
    assert!(!artifact.on_chain_submission);
    assert!(artifact.groth16_flow_unchanged);

    let json = serde_json::to_string(&artifact).unwrap();
    let decoded: ProductionClaimSourceRootArtifactV1 = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, artifact);
    assert_eq!(decoded.validate(), Ok(()));
}

#[test]
fn every_normalized_claim_source_changes_the_root() {
    let base = sample_bridge_input();
    let expected = ProductionClaimSourceRootArtifactV1::from_bridge_input(&base)
        .unwrap()
        .claim_source_root_bytes32;

    let mut variants = Vec::new();

    let mut member = base.clone();
    member.claim.member_id = Some("MEMBER-FIXTURE-002".to_string());
    variants.push(member);

    let mut provider = base.clone();
    provider.claim.provider_npi = Some("1234567894".to_string());
    variants.push(provider);

    let mut procedure = base.clone();
    procedure.claim.service_lines[0].procedure_code = "99214".to_string();
    variants.push(procedure);

    let mut diagnosis = base.clone();
    diagnosis.claim.diagnosis_codes[0] = "Z00.01".to_string();
    variants.push(diagnosis);

    let mut service_date = base.clone();
    service_date.active_rust_facts.date_of_service_from += 1;
    variants.push(service_date);

    for variant in variants {
        let actual = ProductionClaimSourceRootArtifactV1::from_bridge_input(&variant)
            .unwrap()
            .claim_source_root_bytes32;
        assert_ne!(actual, expected);
    }
}

#[test]
fn procedure_and_diagnosis_code_normalization_is_stable() {
    let base = sample_bridge_input();
    let expected = ProductionClaimSourceRootArtifactV1::from_bridge_input(&base)
        .unwrap()
        .claim_source_root_bytes32;

    let mut normalized_equivalent = base;
    normalized_equivalent.claim.service_lines[0].procedure_code = " 99213 ".to_string();
    normalized_equivalent.claim.diagnosis_codes[0] = " z00.00 ".to_string();

    let actual = ProductionClaimSourceRootArtifactV1::from_bridge_input(&normalized_equivalent)
        .unwrap()
        .claim_source_root_bytes32;
    assert_eq!(actual, expected);
}

#[test]
fn missing_or_inconsistent_claim_sources_are_rejected() {
    let mut no_lines = sample_bridge_input();
    no_lines.claim.service_lines.clear();
    let errors = ProductionClaimSourceRootArtifactV1::from_bridge_input(&no_lines).unwrap_err();
    assert!(errors.iter().any(|error| error.contains("service_lines")));

    let mut count_mismatch = sample_bridge_input();
    count_mismatch.claim.diagnosis_count = Some(2);
    let errors =
        ProductionClaimSourceRootArtifactV1::from_bridge_input(&count_mismatch).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.contains("does not match diagnosis_codes"))
    );

    let mut charge_mismatch = sample_bridge_input();
    charge_mismatch.claim.service_lines[0].charge_cents = 99_999;
    let errors =
        ProductionClaimSourceRootArtifactV1::from_bridge_input(&charge_mismatch).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.contains("normalized claim total"))
    );
}

#[test]
fn tampered_leaf_path_and_root_are_rejected() {
    let artifact =
        ProductionClaimSourceRootArtifactV1::from_bridge_input(&sample_bridge_input()).unwrap();

    let mut leaf = artifact.clone();
    leaf.leaf_preimage_decimal[28] = "1".to_string();
    assert!(
        leaf.validate()
            .unwrap_err()
            .iter()
            .any(|error| error.contains("leaf_digest_elements"))
    );

    let mut path = artifact.clone();
    path.merkle_path_elements[0][0] = "1".to_string();
    let errors = path.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.contains("merkle_path_elements"))
    );

    let mut root = artifact;
    root.root_elements[0] = "1".to_string();
    let errors = root.validate().unwrap_err();
    assert!(errors.iter().any(|error| error.contains("root_elements")));
}
