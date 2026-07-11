use stark_engine::{
    ActiveClaimToStarkBridge, MappingClass, StarkBridgeInput, WinterfellWitnessCandidate,
};

fn sample_bridge_input_json() -> &'static str {
    r#"{
      "schema_version": "stark-bridge-input-v0",
      "producer": "rust-engine",
      "purpose": "stark_engine_compatibility_input",
      "runtime_mode": "dry_run_or_optional_sidecar",
      "claim": {
        "claim_id": "CLAIM-PHASE5-WITNESS",
        "claim_amount": 1000,
        "claim_hash": "0xabababababababababababababababababababababababababababababababab"
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
        "claim_hash": "0xabababababababababababababababababababababababababababababababab",
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
fn winterfell_witness_candidate_contains_all_imported_fields() {
    let input = sample_bridge_input();
    let candidate = WinterfellWitnessCandidate::from_bridge_input(&input).unwrap();

    assert_eq!(candidate.validate(), Ok(()));
    assert_eq!(
        candidate.schema_version,
        WinterfellWitnessCandidate::SCHEMA_VERSION
    );
    assert_eq!(
        candidate.candidate_status,
        WinterfellWitnessCandidate::CANDIDATE_STATUS
    );
    assert_eq!(candidate.fields.len(), 11);
    assert_eq!(
        candidate
            .fields
            .iter()
            .map(|field| field.winterfell_field.as_str())
            .collect::<Vec<_>>(),
        ActiveClaimToStarkBridge::IMPORTED_STARK_FIELDS.to_vec()
    );
}

#[test]
fn winterfell_witness_candidate_populates_direct_fields_only() {
    let input = sample_bridge_input();
    let candidate = WinterfellWitnessCandidate::from_bridge_input(&input).unwrap();

    for (field, expected_value) in [
        ("eligibility_active", 1),
        ("provider_enrolled", 1),
        ("duplicate_flag", 0),
    ] {
        let actual = candidate
            .fields
            .iter()
            .find(|candidate_field| candidate_field.winterfell_field == field)
            .unwrap();
        assert_eq!(actual.class, MappingClass::Direct);
        assert_eq!(actual.value, Some(expected_value));
        assert_eq!(actual.value_status, "populated_direct");
    }
}

#[test]
fn winterfell_witness_candidate_leaves_partial_and_unmapped_fields_empty() {
    let input = sample_bridge_input();
    let candidate = WinterfellWitnessCandidate::from_bridge_input(&input).unwrap();

    for field in candidate
        .fields
        .iter()
        .filter(|field| field.class == MappingClass::Partial)
    {
        assert_eq!(field.value, None, "{}", field.winterfell_field);
        assert_eq!(field.value_status, "needs_normalization");
    }

    for field in candidate
        .fields
        .iter()
        .filter(|field| field.class == MappingClass::Unmapped)
    {
        assert_eq!(field.value, None, "{}", field.winterfell_field);
        assert_eq!(field.value_status, "needs_source_data");
    }
}

#[test]
fn winterfell_witness_candidate_counts_match_boundary_plan() {
    let input = sample_bridge_input();
    let candidate = WinterfellWitnessCandidate::from_bridge_input(&input).unwrap();

    assert_eq!(candidate.counts.direct, 3);
    assert_eq!(candidate.counts.partial, 4);
    assert_eq!(candidate.counts.unmapped, 4);
    assert!(!candidate.winterfell_dependency_imported);
    assert!(!candidate.proof_generation_enabled);
}

#[test]
fn winterfell_witness_candidate_json_round_trips() {
    let input = sample_bridge_input();
    let candidate = WinterfellWitnessCandidate::from_bridge_input(&input).unwrap();
    let json = serde_json::to_string_pretty(&candidate).unwrap();
    let round_tripped: WinterfellWitnessCandidate = serde_json::from_str(&json).unwrap();

    assert_eq!(round_tripped, candidate);
    assert_eq!(round_tripped.validate(), Ok(()));
    assert!(json.contains("\"schema_version\": \"winterfell-witness-candidate-v0\""));
    assert!(!json.contains("proof_generation_enabled\": true"));
}

#[test]
fn winterfell_witness_candidate_phase5c_output_contract_is_stable() {
    let input = sample_bridge_input();
    let candidate = WinterfellWitnessCandidate::from_bridge_input(&input).unwrap();
    let value = serde_json::to_value(&candidate).unwrap();

    assert_eq!(
        value["schema_version"],
        WinterfellWitnessCandidate::SCHEMA_VERSION
    );
    assert_eq!(value["source_schema_version"], "stark-bridge-input-v0");
    assert_eq!(
        value["candidate_status"],
        WinterfellWitnessCandidate::CANDIDATE_STATUS
    );
    assert_eq!(value["counts"]["direct"], 3);
    assert_eq!(value["counts"]["partial"], 4);
    assert_eq!(value["counts"]["unmapped"], 4);
    assert_eq!(value["winterfell_dependency_imported"], false);
    assert_eq!(value["proof_generation_enabled"], false);
    assert_eq!(value["fields"].as_array().unwrap().len(), 11);
}

#[test]
fn winterfell_witness_candidate_rejects_partial_field_value() {
    let input = sample_bridge_input();
    let mut candidate = WinterfellWitnessCandidate::from_bridge_input(&input).unwrap();
    let service_line_count = candidate
        .fields
        .iter_mut()
        .find(|field| field.winterfell_field == "service_line_count")
        .unwrap();
    service_line_count.value = Some(1);

    let errors = candidate.validate().unwrap_err();

    assert!(
        errors
            .iter()
            .any(|error| error.contains("service_line_count partial field must not be populated"))
    );
}

#[test]
fn winterfell_witness_candidate_rejects_missing_direct_field_value() {
    let input = sample_bridge_input();
    let mut candidate = WinterfellWitnessCandidate::from_bridge_input(&input).unwrap();
    let eligibility_active = candidate
        .fields
        .iter_mut()
        .find(|field| field.winterfell_field == "eligibility_active")
        .unwrap();
    eligibility_active.value = None;

    let errors = candidate.validate().unwrap_err();

    assert!(errors.iter().any(|error| {
        error.contains("eligibility_active direct field must have a candidate value")
    }));
}

#[test]
fn winterfell_witness_candidate_rejects_runtime_like_flags() {
    let input = sample_bridge_input();
    let mut candidate = WinterfellWitnessCandidate::from_bridge_input(&input).unwrap();
    candidate.winterfell_dependency_imported = true;
    candidate.proof_generation_enabled = true;

    let errors = candidate.validate().unwrap_err();

    assert!(
        errors
            .iter()
            .any(|error| error.contains("winterfell_dependency_imported must be false"))
    );
    assert!(
        errors
            .iter()
            .any(|error| error.contains("proof_generation_enabled must be false"))
    );
}
