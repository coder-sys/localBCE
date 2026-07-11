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
fn complete_winterfell_witness_candidate_phase5i_validator_contract_is_stable() {
    let input = sample_bridge_input();
    let candidate = WinterfellWitnessCandidate::from_bridge_input(&input).unwrap();
    let fixture = sample_source_data_fixture();
    let complete = fixture.to_complete_witness_candidate(&candidate).unwrap();
    let round_tripped: WinterfellCompleteWitnessCandidate =
        serde_json::from_value(serde_json::to_value(&complete).unwrap()).unwrap();

    assert_eq!(round_tripped.validate(), Ok(()));
    assert_eq!(round_tripped.field_count, 11);
    assert!(round_tripped.all_fields_populated);
    assert_eq!(
        round_tripped.candidate_status,
        WinterfellCompleteWitnessCandidate::CANDIDATE_STATUS
    );
    assert!(!round_tripped.winterfell_dependency_imported);
    assert!(!round_tripped.proof_generation_enabled);
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

#[cfg(feature = "winterfell-poc")]
#[test]
fn winterfell_poc_feature_maps_complete_candidate_into_imported_claim_input() {
    use stark_engine::winterfell_poc_adapter::to_poc_claim_input;

    let input = sample_bridge_input();
    let candidate = WinterfellWitnessCandidate::from_bridge_input(&input).unwrap();
    let fixture = sample_source_data_fixture();
    let complete = fixture.to_complete_witness_candidate(&candidate).unwrap();
    let poc_input = to_poc_claim_input(&complete).unwrap();

    assert_eq!(poc_input.eligibility_active, 1);
    assert_eq!(poc_input.provider_enrolled, 1);
    assert_eq!(poc_input.duplicate_flag, 0);
    assert_eq!(
        poc_input.service_line_count,
        fixture.service_line_count as u32
    );
    assert_eq!(poc_input.diagnosis_count, fixture.diagnosis_count as u32);
    assert_eq!(poc_input.prior_auth_ok, fixture.prior_auth_ok as u32);
    assert_eq!(poc_input.charge_cents, fixture.charge_cents as u32);
    assert_eq!(poc_input.max_charge_cents, fixture.max_charge_cents as u32);
    assert_eq!(
        poc_input.program_integrity_hold,
        fixture.program_integrity_hold as u32
    );
}

#[cfg(feature = "winterfell-poc")]
#[test]
fn winterfell_poc_feature_generates_adapter_preview_without_proof_generation() {
    use stark_engine::winterfell_poc_adapter::WinterfellPocAdapterPreview;

    let input = sample_bridge_input();
    let candidate = WinterfellWitnessCandidate::from_bridge_input(&input).unwrap();
    let fixture = sample_source_data_fixture();
    let complete = fixture.to_complete_witness_candidate(&candidate).unwrap();
    let preview = WinterfellPocAdapterPreview::from_complete_candidate(&complete).unwrap();

    assert_eq!(preview.validate(), Ok(()));
    assert_eq!(preview.poc_decision, 1);
    assert_eq!(preview.poc_failure_code, 0);
    assert_eq!(preview.poc_gates, [1; 10]);
    assert_eq!(preview.field_count, 11);
    assert!(preview.winterfell_dependency_imported);
    assert!(!preview.proof_generation_enabled);
}

#[cfg(feature = "winterfell-poc")]
#[test]
fn winterfell_poc_feature_generates_settlement_boundary_artifact() {
    use stark_engine::winterfell_poc_adapter::WinterfellPocProofPreview;

    let input = sample_bridge_input();
    let candidate = WinterfellWitnessCandidate::from_bridge_input(&input).unwrap();
    let fixture = sample_source_data_fixture();
    let complete = fixture.to_complete_witness_candidate(&candidate).unwrap();
    let preview = WinterfellPocProofPreview::from_complete_candidate(&complete).unwrap();
    let artifact = preview.to_settlement_boundary_artifact().unwrap();

    assert_eq!(artifact.validate(), Ok(()));
    assert_eq!(
        artifact.schema_version,
        "stark-settlement-boundary-artifact-v0"
    );
    assert_eq!(
        artifact.source_schema_version,
        "winterfell-poc-proof-preview-v0"
    );
    assert_eq!(artifact.claim_id, preview.claim_id);
    assert_eq!(artifact.claim_hash, preview.claim_hash);
    assert_eq!(artifact.decision, preview.decision);
    assert_eq!(artifact.failure_code, preview.failure_code);
    assert!(artifact.proof_verified);
    assert!(artifact.proof_size_bytes > 0);
    assert!(!artifact.runtime_wired);
    assert!(!artifact.on_chain_submission);
    assert!(artifact.groth16_flow_unchanged);
    assert!(!artifact.settlement_contract_ready);
}

#[cfg(feature = "winterfell-poc")]
#[test]
fn settlement_boundary_artifact_rejects_runtime_like_flags() {
    use stark_engine::winterfell_poc_adapter::WinterfellPocProofPreview;

    let input = sample_bridge_input();
    let candidate = WinterfellWitnessCandidate::from_bridge_input(&input).unwrap();
    let fixture = sample_source_data_fixture();
    let complete = fixture.to_complete_witness_candidate(&candidate).unwrap();
    let preview = WinterfellPocProofPreview::from_complete_candidate(&complete).unwrap();
    let mut artifact = preview.to_settlement_boundary_artifact().unwrap();

    artifact.runtime_wired = true;
    artifact.on_chain_submission = true;
    artifact.groth16_flow_unchanged = false;
    artifact.settlement_contract_ready = true;

    let errors = artifact.validate().unwrap_err();

    assert!(
        errors
            .iter()
            .any(|error| error.contains("runtime_wired must remain false"))
    );
    assert!(
        errors
            .iter()
            .any(|error| error.contains("on_chain_submission must remain false"))
    );
    assert!(
        errors
            .iter()
            .any(|error| error.contains("groth16_flow_unchanged must be true"))
    );
    assert!(
        errors
            .iter()
            .any(|error| error.contains("settlement_contract_ready must remain false"))
    );
}

#[cfg(feature = "winterfell-poc")]
#[test]
fn settlement_boundary_artifact_generates_solidity_verifier_interface_plan() {
    use stark_engine::winterfell_poc_adapter::WinterfellPocProofPreview;

    let input = sample_bridge_input();
    let candidate = WinterfellWitnessCandidate::from_bridge_input(&input).unwrap();
    let fixture = sample_source_data_fixture();
    let complete = fixture.to_complete_witness_candidate(&candidate).unwrap();
    let preview = WinterfellPocProofPreview::from_complete_candidate(&complete).unwrap();
    let artifact = preview.to_settlement_boundary_artifact().unwrap();
    let plan = artifact.to_solidity_verifier_interface_plan().unwrap();

    assert_eq!(plan.validate(), Ok(()));
    assert_eq!(
        plan.schema_version,
        "stark-solidity-verifier-interface-plan-v0"
    );
    assert_eq!(
        plan.source_schema_version,
        "stark-settlement-boundary-artifact-v0"
    );
    assert_eq!(
        plan.interface_status,
        "solidity_interface_plan_only_no_contract_changes"
    );
    assert_eq!(plan.interface_name, "IStarkClaimsVerifierPreview");
    assert!(plan.function_signature.contains("verifyClaim("));
    assert_eq!(
        plan.solidity_inputs
            .iter()
            .map(|input| input.name.as_str())
            .collect::<Vec<_>>(),
        vec!["claimHash", "decision", "failureCode", "proofCommitment"]
    );
    assert!(!plan.contract_modification_allowed);
    assert!(!plan.runtime_wired);
    assert!(!plan.on_chain_submission);
}

#[cfg(feature = "winterfell-poc")]
#[test]
fn solidity_verifier_interface_plan_rejects_contract_activation_flags() {
    use stark_engine::winterfell_poc_adapter::WinterfellPocProofPreview;

    let input = sample_bridge_input();
    let candidate = WinterfellWitnessCandidate::from_bridge_input(&input).unwrap();
    let fixture = sample_source_data_fixture();
    let complete = fixture.to_complete_witness_candidate(&candidate).unwrap();
    let preview = WinterfellPocProofPreview::from_complete_candidate(&complete).unwrap();
    let artifact = preview.to_settlement_boundary_artifact().unwrap();
    let mut plan = artifact.to_solidity_verifier_interface_plan().unwrap();

    plan.contract_modification_allowed = true;
    plan.runtime_wired = true;
    plan.on_chain_submission = true;

    let errors = plan.validate().unwrap_err();

    assert!(
        errors
            .iter()
            .any(|error| error.contains("contract_modification_allowed must remain false"))
    );
    assert!(
        errors
            .iter()
            .any(|error| error.contains("runtime_wired must remain false"))
    );
    assert!(
        errors
            .iter()
            .any(|error| error.contains("on_chain_submission must remain false"))
    );
}

#[cfg(feature = "winterfell-poc")]
#[test]
fn solidity_verifier_interface_plan_generates_settlement_gap_report() {
    use stark_engine::winterfell_poc_adapter::WinterfellPocProofPreview;

    let input = sample_bridge_input();
    let candidate = WinterfellWitnessCandidate::from_bridge_input(&input).unwrap();
    let fixture = sample_source_data_fixture();
    let complete = fixture.to_complete_witness_candidate(&candidate).unwrap();
    let preview = WinterfellPocProofPreview::from_complete_candidate(&complete).unwrap();
    let artifact = preview.to_settlement_boundary_artifact().unwrap();
    let plan = artifact.to_solidity_verifier_interface_plan().unwrap();
    let report = plan.to_settlement_integration_gap_report().unwrap();

    assert_eq!(report.validate(), Ok(()));
    assert_eq!(
        report.schema_version,
        "stark-settlement-integration-gap-report-v0"
    );
    assert_eq!(
        report.source_schema_version,
        "stark-solidity-verifier-interface-plan-v0"
    );
    assert_eq!(
        report.report_status,
        "settlement_integration_gap_report_no_runtime"
    );
    assert!(!report.verifier_contract_gaps.is_empty());
    assert!(!report.claims_registry_integration_gaps.is_empty());
    assert!(!report.governance_gaps.is_empty());
    assert!(!report.calldata_public_input_gaps.is_empty());
    assert!(!report.test_requirements.is_empty());
    assert!(!report.contract_modification_allowed);
    assert!(!report.runtime_wired);
    assert!(!report.on_chain_submission);
}

#[cfg(feature = "winterfell-poc")]
#[test]
fn settlement_gap_report_rejects_contract_activation_flags() {
    use stark_engine::winterfell_poc_adapter::WinterfellPocProofPreview;

    let input = sample_bridge_input();
    let candidate = WinterfellWitnessCandidate::from_bridge_input(&input).unwrap();
    let fixture = sample_source_data_fixture();
    let complete = fixture.to_complete_witness_candidate(&candidate).unwrap();
    let preview = WinterfellPocProofPreview::from_complete_candidate(&complete).unwrap();
    let artifact = preview.to_settlement_boundary_artifact().unwrap();
    let plan = artifact.to_solidity_verifier_interface_plan().unwrap();
    let mut report = plan.to_settlement_integration_gap_report().unwrap();

    report.contract_modification_allowed = true;
    report.runtime_wired = true;
    report.on_chain_submission = true;

    let errors = report.validate().unwrap_err();

    assert!(
        errors
            .iter()
            .any(|error| error.contains("contract_modification_allowed must remain false"))
    );
    assert!(
        errors
            .iter()
            .any(|error| error.contains("runtime_wired must remain false"))
    );
    assert!(
        errors
            .iter()
            .any(|error| error.contains("on_chain_submission must remain false"))
    );
}

#[cfg(feature = "winterfell-poc")]
#[test]
fn settlement_gap_report_generates_implementation_plan() {
    use stark_engine::winterfell_poc_adapter::WinterfellPocProofPreview;

    let input = sample_bridge_input();
    let candidate = WinterfellWitnessCandidate::from_bridge_input(&input).unwrap();
    let fixture = sample_source_data_fixture();
    let complete = fixture.to_complete_witness_candidate(&candidate).unwrap();
    let preview = WinterfellPocProofPreview::from_complete_candidate(&complete).unwrap();
    let artifact = preview.to_settlement_boundary_artifact().unwrap();
    let interface_plan = artifact.to_solidity_verifier_interface_plan().unwrap();
    let gap_report = interface_plan
        .to_settlement_integration_gap_report()
        .unwrap();
    let implementation_plan = gap_report.to_settlement_implementation_plan().unwrap();

    assert_eq!(implementation_plan.validate(), Ok(()));
    assert_eq!(
        implementation_plan.schema_version,
        "stark-settlement-integration-implementation-plan-v0"
    );
    assert_eq!(
        implementation_plan.source_schema_version,
        "stark-settlement-integration-gap-report-v0"
    );
    assert_eq!(
        implementation_plan.plan_status,
        "settlement_integration_implementation_plan_no_runtime"
    );
    assert_eq!(implementation_plan.phases.len(), 5);
    assert!(
        implementation_plan
            .phases
            .iter()
            .any(|phase| phase.phase_id == "phase_1_interface_fixtures")
    );
    assert!(
        implementation_plan
            .safety_invariants
            .iter()
            .any(|invariant| invariant.contains("Groth16 workflow remains unchanged"))
    );
    assert!(!implementation_plan.contract_modification_allowed);
    assert!(!implementation_plan.runtime_wired);
    assert!(!implementation_plan.on_chain_submission);
}

#[cfg(feature = "winterfell-poc")]
#[test]
fn settlement_implementation_plan_rejects_runtime_like_flags() {
    use stark_engine::winterfell_poc_adapter::WinterfellPocProofPreview;

    let input = sample_bridge_input();
    let candidate = WinterfellWitnessCandidate::from_bridge_input(&input).unwrap();
    let fixture = sample_source_data_fixture();
    let complete = fixture.to_complete_witness_candidate(&candidate).unwrap();
    let preview = WinterfellPocProofPreview::from_complete_candidate(&complete).unwrap();
    let artifact = preview.to_settlement_boundary_artifact().unwrap();
    let interface_plan = artifact.to_solidity_verifier_interface_plan().unwrap();
    let gap_report = interface_plan
        .to_settlement_integration_gap_report()
        .unwrap();
    let mut implementation_plan = gap_report.to_settlement_implementation_plan().unwrap();

    implementation_plan.contract_modification_allowed = true;
    implementation_plan.runtime_wired = true;
    implementation_plan.on_chain_submission = true;

    let errors = implementation_plan.validate().unwrap_err();

    assert!(
        errors
            .iter()
            .any(|error| error.contains("contract_modification_allowed must remain false"))
    );
    assert!(
        errors
            .iter()
            .any(|error| error.contains("runtime_wired must remain false"))
    );
    assert!(
        errors
            .iter()
            .any(|error| error.contains("on_chain_submission must remain false"))
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
