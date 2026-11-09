use stark_engine::{FeeScheduleEntryInput, FeeScheduleRootInput, StarkBridgeInput};

fn sample_bridge_input_json() -> &'static str {
    r#"{
      "schema_version": "stark-bridge-input-v0",
      "producer": "rust-engine",
      "purpose": "stark_engine_compatibility_input",
      "runtime_mode": "dry_run_or_optional_sidecar",
      "claim": {
        "claim_id": "CLAIM-PHASE4-FEE",
        "claim_amount": 1000,
        "claim_hash": "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
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
        "claim_hash": "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
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
fn fee_schedule_root_input_from_bridge_is_schema_only() {
    let input = sample_bridge_input();
    let fee_schedule = FeeScheduleRootInput::from_bridge_input(&input).unwrap();

    assert_eq!(
        fee_schedule.schema_version,
        FeeScheduleRootInput::SCHEMA_VERSION
    );
    assert_eq!(
        fee_schedule.source_schema_version,
        FeeScheduleRootInput::SOURCE_SCHEMA_VERSION
    );
    assert_eq!(
        fee_schedule.input_status,
        FeeScheduleRootInput::INPUT_STATUS
    );
    assert_eq!(
        fee_schedule.root_generation_status,
        FeeScheduleRootInput::ROOT_GENERATION_STATUS
    );
    assert_eq!(fee_schedule.claim_id, "CLAIM-PHASE4-FEE");
    assert!(fee_schedule.fee_schedule_id.is_none());
    assert!(fee_schedule.entries.is_empty());
    assert_eq!(fee_schedule.validate(), Ok(()));
}

#[test]
fn fee_schedule_root_input_accepts_future_enriched_entries() {
    let input = sample_bridge_input();
    let mut fee_schedule = FeeScheduleRootInput::from_bridge_input(&input).unwrap();
    fee_schedule.fee_schedule_id = Some("fee-schedule-demo-v0".to_string());
    fee_schedule.entries = vec![FeeScheduleEntryInput {
        fee_code: "T1019".to_string(),
        unit_amount_cents: 2500,
        currency: "USD".to_string(),
        effective_from: 20260101,
        effective_thru: Some(20261231),
        source_url: Some("https://example.gov/fee-schedule".to_string()),
        verification_status: "source_attested".to_string(),
    }];

    assert_eq!(fee_schedule.validate(), Ok(()));

    let json = serde_json::to_string_pretty(&fee_schedule).unwrap();
    assert!(json.contains("\"schema_version\": \"fee-schedule-root-input-v0\""));
    assert!(json.contains("\"root_generation_status\": \"not_generated\""));
    assert!(!json.contains("fee_schedule_root"));
    assert!(!json.contains("root_hash"));
}

#[test]
fn fee_schedule_root_input_json_round_trips_for_cli_output() {
    let input = sample_bridge_input();
    let fee_schedule = FeeScheduleRootInput::from_bridge_input(&input).unwrap();
    let json = serde_json::to_string_pretty(&fee_schedule).unwrap();
    let round_tripped: FeeScheduleRootInput = serde_json::from_str(&json).unwrap();

    assert_eq!(round_tripped, fee_schedule);
    assert_eq!(round_tripped.validate(), Ok(()));
    assert_eq!(round_tripped.schema_version, "fee-schedule-root-input-v0");
    assert_eq!(
        round_tripped.input_status,
        "source_schema_only_no_root_generation"
    );
    assert_eq!(round_tripped.root_generation_status, "not_generated");
}

#[test]
fn fee_schedule_root_input_validation_accepts_cli_generated_shape() {
    let input = sample_bridge_input();
    let fee_schedule = FeeScheduleRootInput::from_bridge_input(&input).unwrap();

    assert_eq!(fee_schedule.validate(), Ok(()));
    assert_eq!(
        fee_schedule.schema_version,
        FeeScheduleRootInput::SCHEMA_VERSION
    );
    assert_eq!(
        fee_schedule.input_status,
        FeeScheduleRootInput::INPUT_STATUS
    );
    assert_eq!(
        fee_schedule.root_generation_status,
        FeeScheduleRootInput::ROOT_GENERATION_STATUS
    );
    assert!(fee_schedule.fee_schedule_id.is_none());
    assert!(fee_schedule.entries.is_empty());
}

#[test]
fn fee_schedule_root_input_rejects_invalid_input_status() {
    let input = sample_bridge_input();
    let mut fee_schedule = FeeScheduleRootInput::from_bridge_input(&input).unwrap();
    fee_schedule.input_status = "runtime_root_input".to_string();

    let errors = fee_schedule.validate().unwrap_err();

    assert!(
        errors
            .iter()
            .any(|error| error
                .contains("input_status must be source_schema_only_no_root_generation"))
    );
}

#[test]
fn fee_schedule_root_input_rejects_empty_claim_id() {
    let input = sample_bridge_input();
    let mut fee_schedule = FeeScheduleRootInput::from_bridge_input(&input).unwrap();
    fee_schedule.claim_id = " ".to_string();

    let errors = fee_schedule.validate().unwrap_err();

    assert!(
        errors
            .iter()
            .any(|error| error.contains("claim_id must be present"))
    );
}

#[test]
fn fee_schedule_root_input_rejects_bad_entry_fields() {
    let input = sample_bridge_input();
    let mut fee_schedule = FeeScheduleRootInput::from_bridge_input(&input).unwrap();
    fee_schedule.entries = vec![FeeScheduleEntryInput {
        fee_code: " ".to_string(),
        unit_amount_cents: 0,
        currency: "usd".to_string(),
        effective_from: 20261231,
        effective_thru: Some(20260101),
        source_url: Some("http://example.gov/fee-schedule".to_string()),
        verification_status: "".to_string(),
    }];

    let errors = fee_schedule.validate().unwrap_err();

    assert!(
        errors
            .iter()
            .any(|error| error.contains("entries[0].fee_code must be present"))
    );
    assert!(
        errors
            .iter()
            .any(|error| error.contains("unit_amount_cents must be greater than zero"))
    );
    assert!(
        errors
            .iter()
            .any(|error| error.contains("currency must be a 3-letter uppercase code"))
    );
    assert!(
        errors
            .iter()
            .any(|error| error.contains("effective_thru must be greater than or equal"))
    );
    assert!(
        errors
            .iter()
            .any(|error| error.contains("source_url must use https"))
    );
    assert!(
        errors
            .iter()
            .any(|error| error.contains("verification_status must be present"))
    );
}

#[test]
fn fee_schedule_root_input_rejects_root_generation_status() {
    let input = sample_bridge_input();
    let mut fee_schedule = FeeScheduleRootInput::from_bridge_input(&input).unwrap();
    fee_schedule.root_generation_status = "generated".to_string();

    let errors = fee_schedule.validate().unwrap_err();

    assert!(
        errors
            .iter()
            .any(|error| error.contains("root_generation_status must be not_generated"))
    );
}
