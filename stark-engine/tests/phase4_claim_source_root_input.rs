use stark_engine::{ClaimSourceRootInput, StarkBridgeInput};

fn sample_bridge_input_json() -> &'static str {
    r#"{
      "schema_version": "stark-bridge-input-v0",
      "producer": "rust-engine",
      "purpose": "stark_engine_compatibility_input",
      "runtime_mode": "dry_run_or_optional_sidecar",
      "claim": {
        "claim_id": "CLAIM-PHASE4-SOURCE",
        "claim_amount": 1000,
        "claim_hash": "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
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
        "claim_hash": "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
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
fn claim_source_root_input_from_bridge_is_schema_only() {
    let input = sample_bridge_input();
    let source = ClaimSourceRootInput::from_bridge_input(&input).unwrap();

    assert_eq!(source.schema_version, ClaimSourceRootInput::SCHEMA_VERSION);
    assert_eq!(
        source.source_schema_version,
        ClaimSourceRootInput::SOURCE_SCHEMA_VERSION
    );
    assert_eq!(source.input_status, ClaimSourceRootInput::INPUT_STATUS);
    assert_eq!(source.root_generation_status, "not_generated");
    assert_eq!(source.claim_id, "CLAIM-PHASE4-SOURCE");
    assert_eq!(source.claim_amount, 1000);
    assert_eq!(source.service_date, Some(20000));
    assert_eq!(source.member_id, None);
    assert_eq!(source.provider_npi, None);
    assert!(source.procedure_codes.is_empty());
    assert!(source.diagnosis_codes.is_empty());
    assert_eq!(source.service_line_count, None);
    assert_eq!(source.validate(), Ok(()));
}

#[test]
fn claim_source_root_input_accepts_future_enriched_source_data() {
    let input = sample_bridge_input();
    let mut source = ClaimSourceRootInput::from_bridge_input(&input).unwrap();
    source.member_id = Some("MEMBER-123".to_string());
    source.provider_npi = Some("1234567890".to_string());
    source.procedure_codes = vec!["T1019".to_string(), "A0428".to_string()];
    source.diagnosis_codes = vec!["Z00.00".to_string()];
    source.service_line_count = Some(2);

    assert_eq!(source.validate(), Ok(()));

    let json = serde_json::to_string_pretty(&source).unwrap();
    assert!(json.contains("\"schema_version\": \"claim-source-root-input-v0\""));
    assert!(json.contains("\"root_generation_status\": \"not_generated\""));
    assert!(!json.contains("claim_source_root"));
    assert!(!json.contains("root_hash"));
}

#[test]
fn claim_source_root_input_carries_optional_identity_fields_from_bridge_claim() {
    let mut input = sample_bridge_input();
    input.claim.member_id = Some("MEMBER-FIXTURE-001".to_string());
    input.claim.provider_npi = Some("1234567893".to_string());

    let source = ClaimSourceRootInput::from_bridge_input(&input).unwrap();

    assert_eq!(source.validate(), Ok(()));
    assert_eq!(source.member_id, Some("MEMBER-FIXTURE-001".to_string()));
    assert_eq!(source.provider_npi, Some("1234567893".to_string()));
    assert_eq!(source.root_generation_status, "not_generated");
}

#[test]
fn claim_source_root_input_json_round_trips_for_cli_output() {
    let input = sample_bridge_input();
    let source = ClaimSourceRootInput::from_bridge_input(&input).unwrap();
    let json = serde_json::to_string_pretty(&source).unwrap();
    let round_tripped: ClaimSourceRootInput = serde_json::from_str(&json).unwrap();

    assert_eq!(round_tripped, source);
    assert_eq!(round_tripped.validate(), Ok(()));
    assert_eq!(round_tripped.schema_version, "claim-source-root-input-v0");
    assert_eq!(
        round_tripped.input_status,
        "source_schema_only_no_root_generation"
    );
    assert_eq!(round_tripped.root_generation_status, "not_generated");
}

#[test]
fn claim_source_root_input_validation_accepts_cli_generated_shape() {
    let input = sample_bridge_input();
    let source = ClaimSourceRootInput::from_bridge_input(&input).unwrap();

    assert_eq!(source.validate(), Ok(()));
    assert_eq!(source.schema_version, ClaimSourceRootInput::SCHEMA_VERSION);
    assert_eq!(source.input_status, ClaimSourceRootInput::INPUT_STATUS);
    assert_eq!(
        source.root_generation_status,
        ClaimSourceRootInput::ROOT_GENERATION_STATUS
    );
}

#[test]
fn claim_source_root_input_rejects_invalid_input_status() {
    let input = sample_bridge_input();
    let mut source = ClaimSourceRootInput::from_bridge_input(&input).unwrap();
    source.input_status = "runtime_root_input".to_string();

    let errors = source.validate().unwrap_err();

    assert!(
        errors
            .iter()
            .any(|error| error
                .contains("input_status must be source_schema_only_no_root_generation"))
    );
}

#[test]
fn claim_source_root_input_rejects_root_generation_status() {
    let input = sample_bridge_input();
    let mut source = ClaimSourceRootInput::from_bridge_input(&input).unwrap();
    source.root_generation_status = "generated".to_string();

    let errors = source.validate().unwrap_err();

    assert!(
        errors
            .iter()
            .any(|error| error.contains("root_generation_status must be not_generated"))
    );
}

#[test]
fn claim_source_root_input_rejects_invalid_provider_npi() {
    let input = sample_bridge_input();
    let mut source = ClaimSourceRootInput::from_bridge_input(&input).unwrap();
    source.provider_npi = Some("not-a-npi".to_string());

    let errors = source.validate().unwrap_err();

    assert!(
        errors
            .iter()
            .any(|error| error.contains("provider_npi must be exactly 10 decimal digits"))
    );
}

#[test]
fn claim_source_root_input_rejects_service_line_count_mismatch() {
    let input = sample_bridge_input();
    let mut source = ClaimSourceRootInput::from_bridge_input(&input).unwrap();
    source.procedure_codes = vec!["T1019".to_string(), "A0428".to_string()];
    source.service_line_count = Some(1);

    let errors = source.validate().unwrap_err();

    assert!(
        errors
            .iter()
            .any(|error| error.contains("service_line_count must match procedure_codes length"))
    );
}

#[test]
fn claim_source_root_input_rejects_bad_claim_hash() {
    let input = sample_bridge_input();
    let mut source = ClaimSourceRootInput::from_bridge_input(&input).unwrap();
    source.claim_hash = "dddd".to_string();

    let errors = source.validate().unwrap_err();

    assert!(
        errors
            .iter()
            .any(|error| error.contains("claim_hash must be a 0x-prefixed 32-byte hex string"))
    );
}

#[test]
fn claim_source_root_input_validation_rejects_empty_claim_id() {
    let input = sample_bridge_input();
    let mut source = ClaimSourceRootInput::from_bridge_input(&input).unwrap();
    source.claim_id = " ".to_string();

    let errors = source.validate().unwrap_err();

    assert!(
        errors
            .iter()
            .any(|error| error.contains("claim_id must be present"))
    );
}
