use stark_engine::{NullifierRootTransitionInput, StarkBridgeInput};

fn sample_bridge_input_json() -> &'static str {
    r#"{
      "schema_version": "stark-bridge-input-v0",
      "producer": "rust-engine",
      "purpose": "stark_engine_compatibility_input",
      "runtime_mode": "dry_run_or_optional_sidecar",
      "claim": {
        "claim_id": "CLAIM-PHASE4-NULLIFIER",
        "claim_amount": 1000,
        "claim_hash": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
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
        "claim_hash": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
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
fn nullifier_root_transition_input_from_bridge_is_schema_only() {
    let input = sample_bridge_input();
    let transition = NullifierRootTransitionInput::from_bridge_input(&input).unwrap();

    assert_eq!(
        transition.schema_version,
        NullifierRootTransitionInput::SCHEMA_VERSION
    );
    assert_eq!(
        transition.source_schema_version,
        NullifierRootTransitionInput::SOURCE_SCHEMA_VERSION
    );
    assert_eq!(
        transition.input_status,
        NullifierRootTransitionInput::INPUT_STATUS
    );
    assert_eq!(
        transition.transition_status,
        NullifierRootTransitionInput::TRANSITION_STATUS
    );
    assert_eq!(
        transition.root_generation_status,
        NullifierRootTransitionInput::ROOT_GENERATION_STATUS
    );
    assert_eq!(transition.claim_id, "CLAIM-PHASE4-NULLIFIER");
    assert!(transition.nullifier_candidate.is_none());
    assert!(transition.nullifier_root_before.is_none());
    assert!(transition.nullifier_root_after.is_none());
    assert_eq!(transition.validate(), Ok(()));
}

#[test]
fn nullifier_root_transition_input_accepts_future_enriched_transition_data() {
    let input = sample_bridge_input();
    let mut transition = NullifierRootTransitionInput::from_bridge_input(&input).unwrap();
    transition.nullifier_candidate =
        Some("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string());
    transition.nullifier_root_before =
        Some("0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string());
    transition.nullifier_root_after =
        Some("0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_string());

    assert_eq!(transition.validate(), Ok(()));

    let json = serde_json::to_string_pretty(&transition).unwrap();
    assert!(json.contains("\"schema_version\": \"nullifier-root-transition-input-v0\""));
    assert!(json.contains("\"transition_status\": \"not_applied\""));
    assert!(json.contains("\"root_generation_status\": \"not_generated\""));
    assert!(!json.contains("nullifier_root_transition_proof"));
    assert!(!json.contains("root_hash"));
}

#[test]
fn nullifier_root_transition_input_json_round_trips_for_cli_output() {
    let input = sample_bridge_input();
    let transition = NullifierRootTransitionInput::from_bridge_input(&input).unwrap();
    let json = serde_json::to_string_pretty(&transition).unwrap();
    let round_tripped: NullifierRootTransitionInput = serde_json::from_str(&json).unwrap();

    assert_eq!(round_tripped, transition);
    assert_eq!(round_tripped.validate(), Ok(()));
    assert_eq!(
        round_tripped.schema_version,
        "nullifier-root-transition-input-v0"
    );
    assert_eq!(
        round_tripped.input_status,
        "transition_schema_only_no_root_generation"
    );
    assert_eq!(round_tripped.transition_status, "not_applied");
    assert_eq!(round_tripped.root_generation_status, "not_generated");
}

#[test]
fn nullifier_root_transition_input_validation_accepts_cli_generated_shape() {
    let input = sample_bridge_input();
    let transition = NullifierRootTransitionInput::from_bridge_input(&input).unwrap();

    assert_eq!(transition.validate(), Ok(()));
    assert_eq!(
        transition.schema_version,
        NullifierRootTransitionInput::SCHEMA_VERSION
    );
    assert_eq!(
        transition.input_status,
        NullifierRootTransitionInput::INPUT_STATUS
    );
    assert_eq!(
        transition.root_generation_status,
        NullifierRootTransitionInput::ROOT_GENERATION_STATUS
    );
    assert!(transition.nullifier_candidate.is_none());
    assert!(transition.nullifier_root_before.is_none());
    assert!(transition.nullifier_root_after.is_none());
}

#[test]
fn nullifier_root_transition_input_rejects_invalid_input_status() {
    let input = sample_bridge_input();
    let mut transition = NullifierRootTransitionInput::from_bridge_input(&input).unwrap();
    transition.input_status = "runtime_transition_input".to_string();

    let errors = transition.validate().unwrap_err();

    assert!(errors.iter().any(|error| {
        error.contains("input_status must be transition_schema_only_no_root_generation")
    }));
}

#[test]
fn nullifier_root_transition_input_rejects_empty_claim_id() {
    let input = sample_bridge_input();
    let mut transition = NullifierRootTransitionInput::from_bridge_input(&input).unwrap();
    transition.claim_id = " ".to_string();

    let errors = transition.validate().unwrap_err();

    assert!(
        errors
            .iter()
            .any(|error| error.contains("claim_id must be present"))
    );
}

#[test]
fn nullifier_root_transition_input_rejects_bad_hex_fields() {
    let input = sample_bridge_input();
    let mut transition = NullifierRootTransitionInput::from_bridge_input(&input).unwrap();
    transition.nullifier_candidate = Some("bad-nullifier".to_string());
    transition.nullifier_root_before = Some("0x1234".to_string());
    transition.nullifier_root_after = Some("root-after".to_string());

    let errors = transition.validate().unwrap_err();

    assert!(
        errors
            .iter()
            .any(|error| error.contains("nullifier_candidate must be a 0x-prefixed 32-byte"))
    );
    assert!(
        errors
            .iter()
            .any(|error| error.contains("nullifier_root_before must be a 0x-prefixed 32-byte"))
    );
    assert!(
        errors
            .iter()
            .any(|error| error.contains("nullifier_root_after must be a 0x-prefixed 32-byte"))
    );
}

#[test]
fn nullifier_root_transition_input_rejects_transition_and_root_generation_status() {
    let input = sample_bridge_input();
    let mut transition = NullifierRootTransitionInput::from_bridge_input(&input).unwrap();
    transition.transition_status = "applied".to_string();
    transition.root_generation_status = "generated".to_string();

    let errors = transition.validate().unwrap_err();

    assert!(
        errors
            .iter()
            .any(|error| error.contains("transition_status must be not_applied"))
    );
    assert!(
        errors
            .iter()
            .any(|error| error.contains("root_generation_status must be not_generated"))
    );
}
