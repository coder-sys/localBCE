use stark_engine::{
    ActiveClaimToStarkBridge, MappingClass, StarkBridgeInput, WinterfellCompleteWitnessCandidate,
    WinterfellSourceDataFixture, WinterfellSourceDataRequirements, WinterfellWitnessCandidate,
    WinterfellWitnessImplementationGapReport,
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
fn winterfell_witness_candidate_phase5d_validator_contract_is_stable() {
    let input = sample_bridge_input();
    let candidate = WinterfellWitnessCandidate::from_bridge_input(&input).unwrap();
    let round_tripped: WinterfellWitnessCandidate =
        serde_json::from_value(serde_json::to_value(&candidate).unwrap()).unwrap();

    assert_eq!(round_tripped.validate(), Ok(()));
    assert_eq!(round_tripped.fields.len(), 11);
    assert_eq!(round_tripped.counts.direct, 3);
    assert_eq!(round_tripped.counts.partial, 4);
    assert_eq!(round_tripped.counts.unmapped, 4);
    assert_eq!(
        round_tripped
            .fields
            .iter()
            .filter(|field| field.value.is_some())
            .count(),
        3
    );
    assert!(!round_tripped.winterfell_dependency_imported);
    assert!(!round_tripped.proof_generation_enabled);
}

#[test]
fn winterfell_witness_gap_report_groups_implementation_work() {
    let input = sample_bridge_input();
    let candidate = WinterfellWitnessCandidate::from_bridge_input(&input).unwrap();
    let report = candidate.to_implementation_gap_report().unwrap();

    assert_eq!(report.validate(), Ok(()));
    assert_eq!(
        report.schema_version,
        WinterfellWitnessImplementationGapReport::SCHEMA_VERSION
    );
    assert_eq!(
        report.source_schema_version,
        WinterfellWitnessCandidate::SCHEMA_VERSION
    );
    assert_eq!(report.direct_ready_fields.len(), 3);
    assert_eq!(report.partial_fields_requiring_normalization.len(), 4);
    assert_eq!(report.unmapped_fields_requiring_source_data.len(), 4);
    assert_eq!(
        report.unsupported_constraints_requiring_prover_work.len(),
        11
    );
    assert_eq!(report.recommended_next_steps.len(), 5);
    assert!(!report.winterfell_dependency_imported);
    assert!(!report.proof_generation_enabled);
}

#[test]
fn winterfell_witness_gap_report_names_ready_normalization_and_source_gaps() {
    let input = sample_bridge_input();
    let candidate = WinterfellWitnessCandidate::from_bridge_input(&input).unwrap();
    let report = candidate.to_implementation_gap_report().unwrap();

    assert_eq!(
        report
            .direct_ready_fields
            .iter()
            .map(|field| field.winterfell_field.as_str())
            .collect::<Vec<_>>(),
        vec!["eligibility_active", "provider_enrolled", "duplicate_flag"]
    );
    assert!(
        report
            .partial_fields_requiring_normalization
            .iter()
            .any(|field| field.winterfell_field == "charge_cents")
    );
    assert!(
        report
            .unmapped_fields_requiring_source_data
            .iter()
            .any(|field| field.winterfell_field == "member_id")
    );
    assert!(
        report
            .unsupported_constraints_requiring_prover_work
            .iter()
            .any(|task| task == "trace_width_172_and_trace_length_16")
    );
}

#[test]
fn winterfell_witness_gap_report_json_round_trips() {
    let input = sample_bridge_input();
    let candidate = WinterfellWitnessCandidate::from_bridge_input(&input).unwrap();
    let report = candidate.to_implementation_gap_report().unwrap();
    let json = serde_json::to_string_pretty(&report).unwrap();
    let round_tripped: WinterfellWitnessImplementationGapReport =
        serde_json::from_str(&json).unwrap();

    assert_eq!(round_tripped, report);
    assert_eq!(round_tripped.validate(), Ok(()));
    assert!(json.contains("winterfell-witness-implementation-gap-report-v0"));
    assert!(!json.contains("proof_generation_enabled\": true"));
}

#[test]
fn winterfell_witness_gap_report_rejects_runtime_like_flags() {
    let input = sample_bridge_input();
    let candidate = WinterfellWitnessCandidate::from_bridge_input(&input).unwrap();
    let mut report = candidate.to_implementation_gap_report().unwrap();
    report.winterfell_dependency_imported = true;
    report.proof_generation_enabled = true;

    let errors = report.validate().unwrap_err();

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

#[test]
fn winterfell_source_data_requirements_capture_all_missing_upstream_fields() {
    let input = sample_bridge_input();
    let candidate = WinterfellWitnessCandidate::from_bridge_input(&input).unwrap();
    let gap_report = candidate.to_implementation_gap_report().unwrap();
    let requirements = gap_report.to_source_data_requirements().unwrap();

    assert_eq!(requirements.validate(), Ok(()));
    assert_eq!(
        requirements.schema_version,
        WinterfellSourceDataRequirements::SCHEMA_VERSION
    );
    assert_eq!(
        requirements.source_schema_version,
        WinterfellWitnessImplementationGapReport::SCHEMA_VERSION
    );
    assert_eq!(requirements.required_fields_total, 8);
    assert_eq!(requirements.normalized_fields_total, 4);
    assert_eq!(requirements.source_data_fields_total, 4);
    assert!(!requirements.winterfell_dependency_imported);
    assert!(!requirements.proof_generation_enabled);
}

#[test]
fn winterfell_source_data_requirements_name_normalized_and_source_fields() {
    let input = sample_bridge_input();
    let candidate = WinterfellWitnessCandidate::from_bridge_input(&input).unwrap();
    let gap_report = candidate.to_implementation_gap_report().unwrap();
    let requirements = gap_report.to_source_data_requirements().unwrap();

    assert_eq!(
        requirements
            .normalized_field_requirements
            .iter()
            .map(|requirement| requirement.winterfell_field.as_str())
            .collect::<Vec<_>>(),
        vec![
            "service_line_count",
            "prior_auth_ok",
            "charge_cents",
            "program_integrity_hold"
        ]
    );
    assert_eq!(
        requirements
            .source_data_requirements
            .iter()
            .map(|requirement| requirement.winterfell_field.as_str())
            .collect::<Vec<_>>(),
        vec![
            "member_id",
            "provider_npi",
            "diagnosis_count",
            "max_charge_cents"
        ]
    );
    assert!(
        requirements
            .normalized_field_requirements
            .iter()
            .all(|requirement| requirement.requirement_type == "deterministic_normalization")
    );
    assert!(
        requirements
            .source_data_requirements
            .iter()
            .all(|requirement| requirement.requirement_type == "missing_source_data")
    );
}

#[test]
fn winterfell_source_data_requirements_json_round_trips() {
    let input = sample_bridge_input();
    let candidate = WinterfellWitnessCandidate::from_bridge_input(&input).unwrap();
    let gap_report = candidate.to_implementation_gap_report().unwrap();
    let requirements = gap_report.to_source_data_requirements().unwrap();
    let json = serde_json::to_string_pretty(&requirements).unwrap();
    let round_tripped: WinterfellSourceDataRequirements = serde_json::from_str(&json).unwrap();

    assert_eq!(round_tripped, requirements);
    assert_eq!(round_tripped.validate(), Ok(()));
    assert!(json.contains("winterfell-source-data-requirements-v0"));
    assert!(!json.contains("proof_generation_enabled\": true"));
}

#[test]
fn winterfell_source_data_requirements_reject_bad_totals_and_runtime_flags() {
    let input = sample_bridge_input();
    let candidate = WinterfellWitnessCandidate::from_bridge_input(&input).unwrap();
    let gap_report = candidate.to_implementation_gap_report().unwrap();
    let mut requirements = gap_report.to_source_data_requirements().unwrap();
    requirements.required_fields_total = 99;
    requirements.winterfell_dependency_imported = true;
    requirements.proof_generation_enabled = true;

    let errors = requirements.validate().unwrap_err();

    assert!(
        errors
            .iter()
            .any(|error| error.contains("required_fields_total must equal"))
    );
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

fn sample_source_data_requirements() -> WinterfellSourceDataRequirements {
    let input = sample_bridge_input();
    let candidate = WinterfellWitnessCandidate::from_bridge_input(&input).unwrap();
    let gap_report = candidate.to_implementation_gap_report().unwrap();
    gap_report.to_source_data_requirements().unwrap()
}

#[test]
fn winterfell_source_data_fixture_satisfies_phase5f_requirements() {
    let requirements = sample_source_data_requirements();
    let fixture = WinterfellSourceDataFixture::demo_from_requirements(&requirements).unwrap();

    assert_eq!(fixture.validate(), Ok(()));
    assert_eq!(
        fixture.schema_version,
        WinterfellSourceDataFixture::SCHEMA_VERSION
    );
    assert_eq!(
        fixture.source_schema_version,
        WinterfellSourceDataRequirements::SCHEMA_VERSION
    );
    assert_eq!(
        fixture.source_requirements_satisfied,
        WinterfellSourceDataFixture::REQUIRED_FIELDS
            .iter()
            .map(|field| (*field).to_string())
            .collect::<Vec<_>>()
    );
    assert_eq!(fixture.member_id, "MEMBER-FIXTURE-001");
    assert_eq!(fixture.provider_npi, "1234567893");
    assert_eq!(fixture.diagnosis_count, 1);
    assert_eq!(fixture.service_line_count, 1);
    assert_eq!(fixture.prior_auth_ok, 1);
    assert_eq!(fixture.charge_cents, 100_000);
    assert_eq!(fixture.max_charge_cents, 150_000);
    assert_eq!(fixture.program_integrity_hold, 0);
    assert!(!fixture.winterfell_dependency_imported);
    assert!(!fixture.proof_generation_enabled);
}

#[test]
fn winterfell_source_data_fixture_json_round_trips() {
    let requirements = sample_source_data_requirements();
    let fixture = WinterfellSourceDataFixture::demo_from_requirements(&requirements).unwrap();
    let json = serde_json::to_string_pretty(&fixture).unwrap();
    let round_tripped: WinterfellSourceDataFixture = serde_json::from_str(&json).unwrap();

    assert_eq!(round_tripped, fixture);
    assert_eq!(round_tripped.validate(), Ok(()));
    assert!(json.contains("winterfell-source-data-fixture-v0"));
    assert!(!json.contains("proof_generation_enabled\": true"));
}

#[test]
fn winterfell_source_data_fixture_rejects_invalid_values() {
    let requirements = sample_source_data_requirements();
    let mut fixture = WinterfellSourceDataFixture::demo_from_requirements(&requirements).unwrap();
    fixture.provider_npi = "BAD-NPI".to_string();
    fixture.charge_cents = fixture.max_charge_cents + 1;
    fixture.prior_auth_ok = 2;
    fixture.source_requirements_satisfied.pop();

    let errors = fixture.validate().unwrap_err();

    assert!(
        errors
            .iter()
            .any(|error| error.contains("provider_npi must be a 10-digit"))
    );
    assert!(
        errors
            .iter()
            .any(|error| error.contains("charge_cents must be less than or equal"))
    );
    assert!(
        errors
            .iter()
            .any(|error| error.contains("prior_auth_ok must be 0 or 1"))
    );
    assert!(
        errors
            .iter()
            .any(|error| error.contains("source_requirements_satisfied missing"))
    );
}

#[test]
fn winterfell_source_data_fixture_rejects_runtime_like_flags() {
    let requirements = sample_source_data_requirements();
    let mut fixture = WinterfellSourceDataFixture::demo_from_requirements(&requirements).unwrap();
    fixture.winterfell_dependency_imported = true;
    fixture.proof_generation_enabled = true;

    let errors = fixture.validate().unwrap_err();

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

fn sample_source_data_fixture() -> WinterfellSourceDataFixture {
    let requirements = sample_source_data_requirements();
    WinterfellSourceDataFixture::demo_from_requirements(&requirements).unwrap()
}

#[test]
fn complete_winterfell_witness_candidate_merges_candidate_and_fixture() {
    let input = sample_bridge_input();
    let candidate = WinterfellWitnessCandidate::from_bridge_input(&input).unwrap();
    let fixture = sample_source_data_fixture();
    let complete = fixture.to_complete_witness_candidate(&candidate).unwrap();

    assert_eq!(complete.validate(), Ok(()));
    assert_eq!(
        complete.schema_version,
        WinterfellCompleteWitnessCandidate::SCHEMA_VERSION
    );
    assert_eq!(
        complete.candidate_status,
        WinterfellCompleteWitnessCandidate::CANDIDATE_STATUS
    );
    assert_eq!(complete.field_count, 11);
    assert!(complete.all_fields_populated);
    assert!(!complete.winterfell_dependency_imported);
    assert!(!complete.proof_generation_enabled);
}

#[test]
fn complete_winterfell_witness_candidate_populates_all_imported_fields() {
    let input = sample_bridge_input();
    let candidate = WinterfellWitnessCandidate::from_bridge_input(&input).unwrap();
    let fixture = sample_source_data_fixture();
    let complete = fixture.to_complete_witness_candidate(&candidate).unwrap();

    assert_eq!(
        complete
            .fields
            .iter()
            .map(|field| field.winterfell_field.as_str())
            .collect::<Vec<_>>(),
        ActiveClaimToStarkBridge::IMPORTED_STARK_FIELDS.to_vec()
    );
    assert!(
        complete
            .fields
            .iter()
            .all(|field| field.value_status == "populated_adapter_ready_fixture")
    );
    assert_eq!(
        complete
            .fields
            .iter()
            .find(|field| field.winterfell_field == "provider_npi")
            .unwrap()
            .value,
        1_234_567_893
    );
    assert_eq!(
        complete
            .fields
            .iter()
            .find(|field| field.winterfell_field == "charge_cents")
            .unwrap()
            .value,
        100_000
    );
}

#[test]
fn complete_winterfell_witness_candidate_json_round_trips() {
    let input = sample_bridge_input();
    let candidate = WinterfellWitnessCandidate::from_bridge_input(&input).unwrap();
    let fixture = sample_source_data_fixture();
    let complete = fixture.to_complete_witness_candidate(&candidate).unwrap();
    let json = serde_json::to_string_pretty(&complete).unwrap();
    let round_tripped: WinterfellCompleteWitnessCandidate = serde_json::from_str(&json).unwrap();

    assert_eq!(round_tripped, complete);
    assert_eq!(round_tripped.validate(), Ok(()));
    assert!(json.contains("winterfell-complete-witness-candidate-v0"));
    assert!(!json.contains("proof_generation_enabled\": true"));
}

#[test]
fn complete_winterfell_witness_candidate_rejects_mismatched_fixture() {
    let input = sample_bridge_input();
    let candidate = WinterfellWitnessCandidate::from_bridge_input(&input).unwrap();
    let mut fixture = sample_source_data_fixture();
    fixture.claim_id = "OTHER-CLAIM".to_string();

    let errors = fixture
        .to_complete_witness_candidate(&candidate)
        .unwrap_err();

    assert!(
        errors
            .iter()
            .any(|error| error.contains("fixture claim_id"))
    );
}

#[test]
fn complete_winterfell_witness_candidate_rejects_runtime_like_flags() {
    let input = sample_bridge_input();
    let candidate = WinterfellWitnessCandidate::from_bridge_input(&input).unwrap();
    let fixture = sample_source_data_fixture();
    let mut complete = fixture.to_complete_witness_candidate(&candidate).unwrap();
    complete.winterfell_dependency_imported = true;
    complete.proof_generation_enabled = true;

    let errors = complete.validate().unwrap_err();

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
