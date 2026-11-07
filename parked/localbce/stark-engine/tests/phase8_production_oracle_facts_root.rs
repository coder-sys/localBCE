#![cfg(feature = "production-air-winterfell")]

use stark_engine::{
    StarkBridgeInput,
    source_roots::{
        ORACLE_FACTS_ROOT_LEAF_INDEX, ORACLE_FACTS_ROOT_TREE_DEPTH,
        ProductionOracleFactsRootArtifactV1,
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
            "claim_id": "CLAIM-ORACLE-ROOT-001",
            "claim_amount": 1000,
            "claim_hash": "0x1c1b60223d4f3ffd351887f834b31a4260508b1602a5a9e16a447ea40e386607",
            "member_id": "MEMBER-FIXTURE-001",
            "provider_npi": "1234567893",
            "diagnosis_count": 1,
            "max_charge_cents": 150000,
            "diagnosis_codes": ["Z00.00"],
            "service_lines": [{
              "procedure_code": "99213",
              "charge_cents": 100000,
              "units": 1
            }],
            "oracle_source_manifest_id": "DEMO-OFFICIAL-SOURCES-V1",
            "oracle_facts": [
              {
                "fact_type": "program_eligibility_status",
                "fact_key": "eligibility_active",
                "fact_value": "1",
                "source_url": "https://example.gov/demo/eligibility",
                "source_label": "Demo eligibility source",
                "verification_status": "verified"
              },
              {
                "fact_type": "provider_enrollment_status",
                "fact_key": "provider_enrolled",
                "fact_value": "1",
                "source_url": "https://example.gov/demo/providers",
                "source_label": "Demo provider source",
                "verification_status": "verified"
              }
            ],
            "oracle_attestation_refs": [
              "demo-attestation:eligibility:v1",
              "demo-attestation:provider:v1"
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
              "service_line_count": {"source": ["billing_code_valid", "units_valid"], "status": "not_equivalent"},
              "prior_auth_ok": {"source": ["physician_certification_valid"], "status": "not_equivalent"},
              "charge_cents": {"source": ["claim_amount"], "status": "requires_unit_normalization"},
              "program_integrity_hold": {"source": ["disability_determination_valid", "recipient_not_deceased"], "status": "not_equivalent"}
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
fn production_oracle_facts_root_round_trips_and_preserves_safety_boundaries() {
    let artifact =
        ProductionOracleFactsRootArtifactV1::from_bridge_input(&sample_bridge_input()).unwrap();

    assert_eq!(artifact.validate(), Ok(()));
    assert_eq!(artifact.tree_depth, ORACLE_FACTS_ROOT_TREE_DEPTH);
    assert_eq!(artifact.leaf_index, ORACLE_FACTS_ROOT_LEAF_INDEX);
    assert_eq!(
        artifact.merkle_path_elements.len(),
        ORACLE_FACTS_ROOT_TREE_DEPTH
    );
    assert_eq!(artifact.fact_count, 2);
    assert_eq!(artifact.attestation_count, 2);
    assert_eq!(artifact.verified_fact_count, 2);
    assert_eq!(artifact.governance_status, "not_registered_or_approved");
    assert_eq!(
        artifact.attestation_status,
        "references_committed_not_cryptographically_verified"
    );
    assert_eq!(
        artifact.air_binding_status,
        "production_air_v3_constrains_canonical_leaf_path_and_root"
    );
    assert!(!artifact.runtime_wired);
    assert!(!artifact.on_chain_verifier_wired);
    assert!(!artifact.on_chain_submission);
    assert!(artifact.groth16_flow_unchanged);

    let json = serde_json::to_string_pretty(&artifact).unwrap();
    let decoded: ProductionOracleFactsRootArtifactV1 = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, artifact);
    assert_eq!(decoded.validate(), Ok(()));
}

#[test]
fn oracle_fact_and_attestation_order_do_not_change_the_root() {
    let bridge = sample_bridge_input();
    let expected = ProductionOracleFactsRootArtifactV1::from_bridge_input(&bridge).unwrap();

    let mut reordered = bridge;
    reordered.claim.oracle_facts.reverse();
    reordered.claim.oracle_attestation_refs.reverse();
    let actual = ProductionOracleFactsRootArtifactV1::from_bridge_input(&reordered).unwrap();

    assert_eq!(
        actual.oracle_facts_root_bytes32,
        expected.oracle_facts_root_bytes32
    );
}

#[test]
fn every_oracle_source_component_changes_the_root() {
    let bridge = sample_bridge_input();
    let expected = ProductionOracleFactsRootArtifactV1::from_bridge_input(&bridge).unwrap();

    let mut mutations = Vec::new();
    let mut manifest = bridge.clone();
    manifest.claim.oracle_source_manifest_id = Some("DEMO-OFFICIAL-SOURCES-V2".to_string());
    mutations.push(manifest);
    let mut fact = bridge.clone();
    fact.claim.oracle_facts[0].fact_value = "0".to_string();
    mutations.push(fact);
    let mut source = bridge.clone();
    source.claim.oracle_facts[0].source_url =
        Some("https://example.gov/demo/eligibility-v2".to_string());
    mutations.push(source);
    let mut attestation = bridge;
    attestation.claim.oracle_attestation_refs[0].push_str("-reissued");
    mutations.push(attestation);

    for mutation in mutations {
        let actual = ProductionOracleFactsRootArtifactV1::from_bridge_input(&mutation).unwrap();
        assert_ne!(
            actual.oracle_facts_root_bytes32,
            expected.oracle_facts_root_bytes32
        );
    }
}

#[test]
fn tampered_oracle_leaf_path_and_root_are_rejected() {
    let artifact =
        ProductionOracleFactsRootArtifactV1::from_bridge_input(&sample_bridge_input()).unwrap();

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
fn missing_or_unverified_oracle_sources_are_rejected() {
    let mut missing_manifest = sample_bridge_input();
    missing_manifest.claim.oracle_source_manifest_id = None;
    assert!(ProductionOracleFactsRootArtifactV1::from_bridge_input(&missing_manifest).is_err());

    let mut unverified = sample_bridge_input();
    unverified.claim.oracle_facts[0].verification_status = "candidate".to_string();
    assert!(ProductionOracleFactsRootArtifactV1::from_bridge_input(&unverified).is_err());

    let mut insecure_source = sample_bridge_input();
    insecure_source.claim.oracle_facts[0].source_url = Some("http://example.gov/demo".to_string());
    assert!(ProductionOracleFactsRootArtifactV1::from_bridge_input(&insecure_source).is_err());

    let mut missing_attestation = sample_bridge_input();
    missing_attestation.claim.oracle_attestation_refs.clear();
    assert!(ProductionOracleFactsRootArtifactV1::from_bridge_input(&missing_attestation).is_err());
}
