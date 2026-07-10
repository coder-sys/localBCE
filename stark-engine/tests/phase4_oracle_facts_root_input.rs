use stark_engine::{OracleFactInput, OracleFactsRootInput, StarkBridgeInput};

fn sample_bridge_input_json() -> &'static str {
    r#"{
      "schema_version": "stark-bridge-input-v0",
      "producer": "rust-engine",
      "purpose": "stark_engine_compatibility_input",
      "runtime_mode": "dry_run_or_optional_sidecar",
      "claim": {
        "claim_id": "CLAIM-PHASE4-ORACLE",
        "claim_amount": 1000,
        "claim_hash": "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
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
          "member_id": null,
          "provider_npi": null,
          "diagnosis_count": null,
          "max_charge_cents": null
        }
      },
      "public_inputs": {
        "claim_hash": "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
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
    }"#
}

fn sample_bridge_input() -> StarkBridgeInput {
    serde_json::from_str(sample_bridge_input_json()).unwrap()
}

#[test]
fn oracle_facts_root_input_from_bridge_is_schema_only() {
    let input = sample_bridge_input();
    let oracle = OracleFactsRootInput::from_bridge_input(&input).unwrap();

    assert_eq!(oracle.schema_version, OracleFactsRootInput::SCHEMA_VERSION);
    assert_eq!(
        oracle.source_schema_version,
        OracleFactsRootInput::SOURCE_SCHEMA_VERSION
    );
    assert_eq!(oracle.input_status, OracleFactsRootInput::INPUT_STATUS);
    assert_eq!(
        oracle.root_generation_status,
        OracleFactsRootInput::ROOT_GENERATION_STATUS
    );
    assert_eq!(oracle.claim_id, "CLAIM-PHASE4-ORACLE");
    assert!(oracle.source_manifest_id.is_none());
    assert!(oracle.facts.is_empty());
    assert!(oracle.attestation_refs.is_empty());
    assert_eq!(oracle.validate(), Ok(()));
}

#[test]
fn oracle_facts_root_input_accepts_future_enriched_facts() {
    let input = sample_bridge_input();
    let mut oracle = OracleFactsRootInput::from_bridge_input(&input).unwrap();
    oracle.source_manifest_id = Some("oracle-source-manifest-demo-v0".to_string());
    oracle.facts = vec![
        OracleFactInput {
            fact_type: "eligibility".to_string(),
            fact_key: "eligibility_active".to_string(),
            fact_value: "true".to_string(),
            source_url: Some("https://example.gov/eligibility".to_string()),
            source_label: Some("Example official eligibility source".to_string()),
            verification_status: "source_attested".to_string(),
        },
        OracleFactInput {
            fact_type: "provider".to_string(),
            fact_key: "provider_enrolled".to_string(),
            fact_value: "true".to_string(),
            source_url: Some("https://example.gov/provider".to_string()),
            source_label: None,
            verification_status: "source_attested".to_string(),
        },
    ];
    oracle.attestation_refs = vec!["attestation-demo-001".to_string()];

    assert_eq!(oracle.validate(), Ok(()));

    let json = serde_json::to_string_pretty(&oracle).unwrap();
    assert!(json.contains("\"schema_version\": \"oracle-facts-root-input-v0\""));
    assert!(json.contains("\"root_generation_status\": \"not_generated\""));
    assert!(!json.contains("oracle_facts_root"));
    assert!(!json.contains("root_hash"));
}

#[test]
fn oracle_facts_root_input_json_round_trips() {
    let input = sample_bridge_input();
    let oracle = OracleFactsRootInput::from_bridge_input(&input).unwrap();
    let json = serde_json::to_string_pretty(&oracle).unwrap();
    let round_tripped: OracleFactsRootInput = serde_json::from_str(&json).unwrap();

    assert_eq!(round_tripped, oracle);
    assert_eq!(round_tripped.validate(), Ok(()));
}

#[test]
fn oracle_facts_root_input_rejects_http_source_url() {
    let input = sample_bridge_input();
    let mut oracle = OracleFactsRootInput::from_bridge_input(&input).unwrap();
    oracle.facts = vec![OracleFactInput {
        fact_type: "eligibility".to_string(),
        fact_key: "eligibility_active".to_string(),
        fact_value: "true".to_string(),
        source_url: Some("http://example.gov/eligibility".to_string()),
        source_label: Some("Example source".to_string()),
        verification_status: "source_attested".to_string(),
    }];

    let errors = oracle.validate().unwrap_err();

    assert!(errors
        .iter()
        .any(|error| error.contains("source_url must use https")));
}

#[test]
fn oracle_facts_root_input_rejects_empty_fact_fields() {
    let input = sample_bridge_input();
    let mut oracle = OracleFactsRootInput::from_bridge_input(&input).unwrap();
    oracle.facts = vec![OracleFactInput {
        fact_type: "".to_string(),
        fact_key: " ".to_string(),
        fact_value: "".to_string(),
        source_url: None,
        source_label: Some(" ".to_string()),
        verification_status: "".to_string(),
    }];

    let errors = oracle.validate().unwrap_err();

    assert!(errors
        .iter()
        .any(|error| error.contains("facts[0].fact_type must be present")));
    assert!(errors
        .iter()
        .any(|error| error.contains("facts[0].fact_key must be present")));
    assert!(errors
        .iter()
        .any(|error| error.contains("facts[0].fact_value must be present")));
    assert!(errors
        .iter()
        .any(|error| error.contains("facts[0].verification_status must be present")));
    assert!(errors
        .iter()
        .any(|error| error.contains("facts[0].source_label must be non-empty")));
}

#[test]
fn oracle_facts_root_input_rejects_root_generation_status() {
    let input = sample_bridge_input();
    let mut oracle = OracleFactsRootInput::from_bridge_input(&input).unwrap();
    oracle.root_generation_status = "generated".to_string();

    let errors = oracle.validate().unwrap_err();

    assert!(errors
        .iter()
        .any(|error| error.contains("root_generation_status must be not_generated")));
}
