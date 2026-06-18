use stark_engine::{ActiveClaimToStarkBridge, MappingClass, MappingCounts, StarkBridgeInput};

fn sample_bridge_input_json() -> &'static str {
    r#"{
      "schema_version": "stark-bridge-input-v0",
      "producer": "rust-engine",
      "purpose": "stark_engine_compatibility_input",
      "runtime_mode": "dry_run_or_optional_sidecar",
      "claim": {
        "claim_id": "CLAIM-DEMO-011",
        "claim_amount": 1000,
        "claim_hash": "0x1c1b60223d4f3ffd351887f834b31a4260508b1602a5a9e16a447ea40e386607"
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
            "source": [
              "disability_determination_valid",
              "recipient_not_deceased"
            ],
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
    }"#
}

fn sample_bridge_input() -> StarkBridgeInput {
    serde_json::from_str(sample_bridge_input_json()).unwrap()
}

#[test]
fn imported_winterfell_stark_fields_are_all_classified() {
    let mappings = ActiveClaimToStarkBridge::field_mappings();

    assert_eq!(
        mappings.len(),
        ActiveClaimToStarkBridge::IMPORTED_STARK_FIELDS.len()
    );

    for expected_field in ActiveClaimToStarkBridge::IMPORTED_STARK_FIELDS {
        assert!(
            mappings
                .iter()
                .any(|mapping| mapping.imported_stark_field == expected_field),
            "missing imported STARK field mapping for {expected_field}"
        );
    }
}

#[test]
fn imported_winterfell_mapping_classes_match_phase_5a() {
    let mappings = ActiveClaimToStarkBridge::field_mappings();

    assert_eq!(
        mappings
            .iter()
            .filter(|mapping| mapping.class == MappingClass::Direct)
            .count(),
        3
    );
    assert_eq!(
        mappings
            .iter()
            .filter(|mapping| mapping.class == MappingClass::Partial)
            .count(),
        4
    );
    assert_eq!(
        mappings
            .iter()
            .filter(|mapping| mapping.class == MappingClass::Unmapped)
            .count(),
        4
    );
}

#[test]
fn direct_mappings_are_the_only_safe_initial_bridge_fields() {
    let direct_fields: Vec<&str> = ActiveClaimToStarkBridge::direct_mappings()
        .iter()
        .map(|mapping| mapping.imported_stark_field)
        .collect();

    assert_eq!(
        direct_fields,
        vec!["eligibility_active", "provider_enrolled", "duplicate_flag"]
    );
}

#[test]
fn direct_mappings_point_to_existing_active_rust_sources() {
    for mapping in ActiveClaimToStarkBridge::direct_mappings() {
        let source = mapping
            .active_rust_source
            .expect("direct mapping must name an active Rust source field");

        assert!(
            ActiveClaimToStarkBridge::ACTIVE_RUST_FIELDS.contains(&source),
            "direct mapping source field is not in active Rust model: {source}"
        );
    }
}

#[test]
fn stark_bridge_input_deserializes_proposed_schema() {
    let input = sample_bridge_input();

    assert_eq!(input.schema_version, StarkBridgeInput::SCHEMA_VERSION);
    assert_eq!(input.producer, "rust-engine");
    assert_eq!(input.purpose, "stark_engine_compatibility_input");
    assert_eq!(input.claim.claim_id, "CLAIM-DEMO-011");
    assert_eq!(input.claim.claim_amount, 1000);
    assert_eq!(input.adjudication.decision, 1);
    assert_eq!(input.adjudication.failure_code, 0);
    assert_eq!(input.adjudication.failure_reason, None);
    assert_eq!(input.active_rust_facts.eligibility_active, 1);
    assert_eq!(input.active_rust_facts.provider_enrolled, 1);
    assert_eq!(input.active_rust_facts.is_duplicate, 0);
    assert!(!input.proof_status.stark_proof_generated);
    assert!(!input.proof_status.winterfell_poc_compatible);
    assert!(input.proof_status.groth16_flow_unchanged);
    assert!(!input.proof_status.on_chain_submission);
}

#[test]
fn stark_bridge_input_validates_mapping_counts() {
    let input = sample_bridge_input();

    assert_eq!(
        input.mapping_counts(),
        MappingCounts {
            direct: 3,
            partial: 4,
            unmapped: 4,
        }
    );
}

#[test]
fn stark_bridge_input_direct_fields_match_active_facts() {
    let input = sample_bridge_input();

    assert_eq!(
        input.winterfell_poc_mapping.direct.eligibility_active,
        input.active_rust_facts.eligibility_active
    );
    assert_eq!(
        input.winterfell_poc_mapping.direct.provider_enrolled,
        input.active_rust_facts.provider_enrolled
    );
    assert_eq!(
        input.winterfell_poc_mapping.direct.duplicate_flag,
        input.active_rust_facts.is_duplicate
    );
}

#[test]
fn stark_bridge_input_validation_accepts_sample() {
    let input = sample_bridge_input();

    assert_eq!(input.validate(), Ok(()));
}

#[test]
fn stark_bridge_input_validation_rejects_bad_schema_version() {
    let mut input = sample_bridge_input();
    input.schema_version = "wrong-schema".to_string();

    let errors = input.validate().unwrap_err();

    assert!(
        errors
            .iter()
            .any(|error| error.contains("schema_version must be stark-bridge-input-v0"))
    );
}

#[test]
fn stark_bridge_input_validation_rejects_invalid_decision() {
    let mut input = sample_bridge_input();
    input.adjudication.decision = 2;

    let errors = input.validate().unwrap_err();

    assert!(
        errors
            .iter()
            .any(|error| error.contains("adjudication.decision must be 0 or 1"))
    );
}

#[test]
fn stark_bridge_input_validation_rejects_generated_proof_status() {
    let mut input = sample_bridge_input();
    input.proof_status.stark_proof_generated = true;

    let errors = input.validate().unwrap_err();

    assert!(
        errors
            .iter()
            .any(|error| error.contains("proof_status.stark_proof_generated must be false"))
    );
}

#[test]
fn validated_bridge_input_converts_to_proof_intent() {
    let input = sample_bridge_input();
    let intent = input.to_proof_intent().unwrap();

    assert_eq!(intent.schema_version, "stark-proof-intent-v0");
    assert_eq!(
        intent.source_schema_version,
        StarkBridgeInput::SCHEMA_VERSION
    );
    assert_eq!(intent.intent_status, "validated_no_prover_selected");
    assert_eq!(intent.claim_id, "CLAIM-DEMO-011");
    assert_eq!(
        intent.claim_hash,
        "0x1c1b60223d4f3ffd351887f834b31a4260508b1602a5a9e16a447ea40e386607"
    );
    assert_eq!(intent.decision, 1);
    assert_eq!(intent.failure_code, 0);
    assert_eq!(intent.failure_reason, None);
    assert_eq!(intent.ruleset_id, "current_g1_g10_denial_reason");
    assert_eq!(intent.direct_facts.eligibility_active, 1);
    assert_eq!(intent.direct_facts.provider_enrolled, 1);
    assert_eq!(intent.direct_facts.duplicate_flag, 0);
    assert!(intent.proof_readiness.bridge_validated);
    assert!(!intent.proof_readiness.prover_selected);
    assert!(!intent.proof_readiness.witness_generated);
    assert!(!intent.proof_readiness.proof_generated);
    assert!(!intent.proof_readiness.on_chain_submission);
}

#[test]
fn invalid_bridge_input_does_not_convert_to_proof_intent() {
    let mut input = sample_bridge_input();
    input.public_inputs.claim_hash = String::new();

    let errors = input.to_proof_intent().unwrap_err();

    assert!(
        errors
            .iter()
            .any(|error| error.contains("public_inputs.claim_hash must be present"))
    );
}
