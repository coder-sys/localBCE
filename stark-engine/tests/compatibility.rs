use stark_engine::{
    ActiveClaimToStarkBridge, MappingClass, MappingCounts, StarkBridgeInput, StarkProofIntent,
};

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

fn denied_bridge_input() -> StarkBridgeInput {
    let mut input = sample_bridge_input();
    input.adjudication.decision = 0;
    input.adjudication.failure_code = 5;
    input.adjudication.failure_reason = Some("G5_PROVIDER_NOT_ENROLLED".to_string());
    input.active_rust_facts.provider_enrolled = 0;
    input.winterfell_poc_mapping.direct.provider_enrolled = 0;
    input.public_inputs.decision = 0;
    input.public_inputs.failure_code = 5;
    input
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

#[test]
fn approved_proof_intent_converts_to_witness_plan() {
    let intent = sample_bridge_input().to_proof_intent().unwrap();
    let plan = intent.to_witness_plan();

    assert_eq!(plan.schema_version, "stark-witness-plan-v0");
    assert_eq!(plan.source_schema_version, "stark-proof-intent-v0");
    assert_eq!(
        plan.claim_hash,
        "0x1c1b60223d4f3ffd351887f834b31a4260508b1602a5a9e16a447ea40e386607"
    );
    assert_eq!(plan.decision, 1);
    assert_eq!(plan.failure_code, 0);
    assert_eq!(plan.direct_facts.eligibility_active, 1);
    assert_eq!(plan.direct_facts.provider_enrolled, 1);
    assert_eq!(plan.direct_facts.duplicate_flag, 0);
    assert_eq!(plan.constraint_groups.len(), 3);
    assert_eq!(
        plan.constraint_groups[0].group_id,
        "public_adjudication_inputs"
    );
    assert_eq!(
        plan.constraint_groups[1].group_id,
        "direct_fact_constraints"
    );
    assert_eq!(plan.constraint_groups[2].group_id, "decision_consistency");
    assert_eq!(plan.witness_status, "planned_not_generated");
}

#[test]
fn proof_intent_json_round_trips_before_witness_planning() {
    let intent = sample_bridge_input().to_proof_intent().unwrap();
    let json = serde_json::to_string_pretty(&intent).unwrap();
    let parsed: StarkProofIntent = serde_json::from_str(&json).unwrap();
    let plan = parsed.to_witness_plan();

    assert_eq!(parsed, intent);
    assert_eq!(plan.schema_version, "stark-witness-plan-v0");
    assert_eq!(plan.source_schema_version, "stark-proof-intent-v0");
    assert_eq!(plan.witness_status, "planned_not_generated");
}

#[test]
fn denied_proof_intent_converts_to_witness_plan() {
    let intent = denied_bridge_input().to_proof_intent().unwrap();
    let plan = intent.to_witness_plan();

    assert_eq!(plan.schema_version, "stark-witness-plan-v0");
    assert_eq!(plan.source_schema_version, "stark-proof-intent-v0");
    assert_eq!(plan.decision, 0);
    assert_eq!(plan.failure_code, 5);
    assert_eq!(plan.direct_facts.eligibility_active, 1);
    assert_eq!(plan.direct_facts.provider_enrolled, 0);
    assert_eq!(plan.direct_facts.duplicate_flag, 0);
    assert!(plan.constraint_groups.iter().any(|group| {
        group.group_id == "decision_consistency"
            && group
                .constraints
                .contains(&"denied_claim_requires_failure_code".to_string())
    }));
    assert_eq!(plan.witness_status, "planned_not_generated");
}

#[test]
fn witness_plan_validation_accepts_valid_approved_plan() {
    let plan = sample_bridge_input()
        .to_proof_intent()
        .unwrap()
        .to_witness_plan();

    assert_eq!(plan.validate(), Ok(()));
}

#[test]
fn witness_plan_validation_accepts_valid_denied_plan() {
    let plan = denied_bridge_input()
        .to_proof_intent()
        .unwrap()
        .to_witness_plan();

    assert_eq!(plan.validate(), Ok(()));
}

#[test]
fn witness_plan_validation_rejects_invalid_boolean_fact() {
    let mut plan = sample_bridge_input()
        .to_proof_intent()
        .unwrap()
        .to_witness_plan();
    plan.direct_facts.provider_enrolled = 2;

    let errors = plan.validate().unwrap_err();

    assert!(
        errors
            .iter()
            .any(|error| error.contains("direct_facts.provider_enrolled must be 0 or 1"))
    );
}

#[test]
fn witness_plan_validation_rejects_decision_failure_code_mismatch() {
    let mut approved_plan = sample_bridge_input()
        .to_proof_intent()
        .unwrap()
        .to_witness_plan();
    approved_plan.failure_code = 5;

    let approved_errors = approved_plan.validate().unwrap_err();

    assert!(
        approved_errors
            .iter()
            .any(|error| error.contains("approved claim requires failure_code = 0"))
    );

    let mut denied_plan = denied_bridge_input()
        .to_proof_intent()
        .unwrap()
        .to_witness_plan();
    denied_plan.failure_code = 0;

    let denied_errors = denied_plan.validate().unwrap_err();

    assert!(
        denied_errors
            .iter()
            .any(|error| error.contains("denied claim requires failure_code != 0"))
    );
}

#[test]
fn witness_plan_validation_rejects_missing_required_group() {
    let mut plan = sample_bridge_input()
        .to_proof_intent()
        .unwrap()
        .to_witness_plan();
    plan.constraint_groups
        .retain(|group| group.group_id != "decision_consistency");

    let errors = plan.validate().unwrap_err();

    assert!(
        errors
            .iter()
            .any(|error| error.contains("missing required constraint group: decision_consistency"))
    );
}

#[test]
fn approved_witness_plan_generates_mock_trace_rows() {
    let plan = sample_bridge_input()
        .to_proof_intent()
        .unwrap()
        .to_witness_plan();
    let trace = plan.to_mock_trace().unwrap();

    assert_eq!(trace.schema_version, "stark-mock-trace-v0");
    assert_eq!(trace.source_schema_version, "stark-witness-plan-v0");
    assert_eq!(
        trace.claim_hash,
        "0x1c1b60223d4f3ffd351887f834b31a4260508b1602a5a9e16a447ea40e386607"
    );
    assert_eq!(trace.rows.len(), 8);
    assert_eq!(trace.trace_status, "mock_trace_generated_no_proof");
    assert!(trace.rows.iter().all(|row| row.satisfied));

    assert_eq!(trace.rows[0].step_index, 0);
    assert_eq!(trace.rows[0].constraint_group, "public_adjudication_inputs");
    assert_eq!(trace.rows[0].constraint_name, "claim_hash_is_public_input");
    assert_eq!(trace.rows[7].step_index, 7);
    assert_eq!(trace.rows[7].constraint_group, "decision_consistency");
    assert_eq!(
        trace.rows[7].constraint_name,
        "denied_claim_requires_failure_code"
    );
}

#[test]
fn denied_witness_plan_generates_mock_trace_rows() {
    let plan = denied_bridge_input()
        .to_proof_intent()
        .unwrap()
        .to_witness_plan();
    let trace = plan.to_mock_trace().unwrap();

    assert_eq!(trace.rows.len(), 8);
    assert!(trace.rows.iter().all(|row| row.satisfied));

    let provider_row = trace
        .rows
        .iter()
        .find(|row| row.constraint_name == "provider_enrolled_is_boolean")
        .unwrap();
    assert_eq!(provider_row.input_value, "0");
    assert_eq!(provider_row.expected_value, "0_or_1");
    assert!(provider_row.satisfied);

    let denied_consistency_row = trace
        .rows
        .iter()
        .find(|row| row.constraint_name == "denied_claim_requires_failure_code")
        .unwrap();
    assert_eq!(
        denied_consistency_row.input_value,
        "decision=0,failure_code=5"
    );
    assert!(denied_consistency_row.satisfied);
}

#[test]
fn invalid_witness_plan_does_not_generate_mock_trace() {
    let mut plan = sample_bridge_input()
        .to_proof_intent()
        .unwrap()
        .to_witness_plan();
    plan.direct_facts.duplicate_flag = 2;

    let errors = plan.to_mock_trace().unwrap_err();

    assert!(
        errors
            .iter()
            .any(|error| error.contains("direct_facts.duplicate_flag must be 0 or 1"))
    );
}

#[test]
fn mock_trace_generates_winterfell_poc_compatibility_report() {
    let trace = sample_bridge_input()
        .to_proof_intent()
        .unwrap()
        .to_witness_plan()
        .to_mock_trace()
        .unwrap();
    let report = trace.winterfell_poc_compatibility_report();

    assert_eq!(
        report.schema_version,
        "winterfell-poc-compatibility-report-v0"
    );
    assert_eq!(report.source_schema_version, "stark-mock-trace-v0");
    assert_eq!(
        report.verdict,
        "compatible_subset_not_full_winterfell_trace"
    );
    assert_eq!(report.mock_trace_rows, 8);
    assert!(report.all_mock_rows_satisfied);
    assert!(report.required_mock_constraint_groups_present);
    assert_eq!(report.imported_winterfell_input_fields.len(), 11);
    assert_eq!(report.direct_compatible_fields.len(), 3);
    assert_eq!(report.partial_fields.len(), 4);
    assert_eq!(report.unmapped_fields.len(), 4);
    assert!(
        report
            .direct_compatible_fields
            .iter()
            .any(|field| field.imported_stark_field == "eligibility_active")
    );
    assert!(
        report
            .direct_compatible_fields
            .iter()
            .any(|field| field.imported_stark_field == "provider_enrolled")
    );
    assert!(
        report
            .direct_compatible_fields
            .iter()
            .any(|field| field.imported_stark_field == "duplicate_flag")
    );
    assert!(
        report
            .unsupported_winterfell_constraints
            .contains(&"winterfell_commitment_hash_chain".to_string())
    );
}

#[test]
fn winterfell_poc_compatibility_report_is_not_full_prover_compatibility() {
    let trace = denied_bridge_input()
        .to_proof_intent()
        .unwrap()
        .to_witness_plan()
        .to_mock_trace()
        .unwrap();
    let report = trace.winterfell_poc_compatibility_report();

    assert_eq!(
        report.verdict,
        "compatible_subset_not_full_winterfell_trace"
    );
    assert!(!report.unsupported_winterfell_constraints.is_empty());
    assert!(
        report
            .notes
            .iter()
            .any(|note| note.contains("not a STARK proof"))
    );
    assert!(
        report
            .partial_fields
            .iter()
            .any(|field| field.imported_stark_field == "charge_cents")
    );
    assert!(
        report
            .unmapped_fields
            .iter()
            .any(|field| field.imported_stark_field == "member_id")
    );
}
