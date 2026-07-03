use stark_engine::StarkBridgeInput;

const APPROVED_BRIDGE_INPUT_JSON: &str = r#"{
  "schema_version": "stark-bridge-input-v0",
  "producer": "rust-engine",
  "purpose": "stark_engine_compatibility_input",
  "runtime_mode": "dry_run_or_optional_sidecar",
  "claim": {
    "claim_id": "CLAIM-PHASE2-APPROVED",
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
}"#;

const DENIED_BRIDGE_INPUT_JSON: &str = r#"{
  "schema_version": "stark-bridge-input-v0",
  "producer": "rust-engine",
  "purpose": "stark_engine_compatibility_input",
  "runtime_mode": "dry_run_or_optional_sidecar",
  "claim": {
    "claim_id": "CLAIM-PHASE2-DENIED",
    "claim_amount": 1000,
    "claim_hash": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  },
  "adjudication": {
    "decision": 0,
    "failure_code": 5,
    "failure_reason": "G5_PROVIDER_NOT_ENROLLED",
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
    "provider_enrolled": 0,
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
      "provider_enrolled": 0,
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
    "claim_hash": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "decision": 0,
    "failure_code": 5,
    "ruleset_id": "current_g1_g10_denial_reason"
  },
  "proof_status": {
    "stark_proof_generated": false,
    "winterfell_poc_compatible": false,
    "groth16_flow_unchanged": true,
    "on_chain_submission": false
  }
}"#;

#[test]
fn approved_fixture_runs_full_stark_bridge_pre_prover_chain() {
    let input: StarkBridgeInput = serde_json::from_str(APPROVED_BRIDGE_INPUT_JSON).unwrap();

    input.validate().unwrap();

    let intent = input.to_proof_intent().unwrap();
    assert_eq!(intent.schema_version, "stark-proof-intent-v0");
    assert_eq!(intent.intent_status, "validated_no_prover_selected");
    assert_eq!(intent.decision, 1);
    assert_eq!(intent.failure_code, 0);
    assert!(intent.proof_readiness.bridge_validated);
    assert!(!intent.proof_readiness.prover_selected);
    assert!(!intent.proof_readiness.witness_generated);
    assert!(!intent.proof_readiness.proof_generated);
    assert!(!intent.proof_readiness.on_chain_submission);

    let witness_plan = intent.to_witness_plan();
    witness_plan.validate().unwrap();
    assert_eq!(witness_plan.schema_version, "stark-witness-plan-v0");
    assert_eq!(witness_plan.witness_status, "planned_not_generated");
    assert_eq!(witness_plan.decision, 1);
    assert_eq!(witness_plan.failure_code, 0);

    let mock_trace = witness_plan.to_mock_trace().unwrap();
    assert_eq!(mock_trace.schema_version, "stark-mock-trace-v0");
    assert_eq!(mock_trace.trace_status, "mock_trace_generated_no_proof");
    assert_eq!(mock_trace.rows.len(), 8);
    assert!(mock_trace.rows.iter().all(|row| row.satisfied));

    let compatibility_report = mock_trace.winterfell_poc_compatibility_report();
    assert_eq!(
        compatibility_report.verdict,
        "compatible_subset_not_full_winterfell_trace"
    );
    assert!(compatibility_report.all_mock_rows_satisfied);
}

#[test]
fn denied_fixture_runs_full_stark_bridge_pre_prover_chain() {
    let input: StarkBridgeInput = serde_json::from_str(DENIED_BRIDGE_INPUT_JSON).unwrap();

    input.validate().unwrap();

    let intent = input.to_proof_intent().unwrap();
    assert_eq!(intent.schema_version, "stark-proof-intent-v0");
    assert_eq!(intent.intent_status, "validated_no_prover_selected");
    assert_eq!(intent.decision, 0);
    assert_eq!(intent.failure_code, 5);
    assert_eq!(
        intent.failure_reason,
        Some("G5_PROVIDER_NOT_ENROLLED".to_string())
    );
    assert!(intent.proof_readiness.bridge_validated);
    assert!(!intent.proof_readiness.prover_selected);
    assert!(!intent.proof_readiness.witness_generated);
    assert!(!intent.proof_readiness.proof_generated);
    assert!(!intent.proof_readiness.on_chain_submission);

    let witness_plan = intent.to_witness_plan();
    witness_plan.validate().unwrap();
    assert_eq!(witness_plan.schema_version, "stark-witness-plan-v0");
    assert_eq!(witness_plan.witness_status, "planned_not_generated");
    assert_eq!(witness_plan.decision, 0);
    assert_eq!(witness_plan.failure_code, 5);

    let mock_trace = witness_plan.to_mock_trace().unwrap();
    assert_eq!(mock_trace.schema_version, "stark-mock-trace-v0");
    assert_eq!(mock_trace.trace_status, "mock_trace_generated_no_proof");
    assert_eq!(mock_trace.rows.len(), 8);
    assert!(mock_trace.rows.iter().all(|row| row.satisfied));

    let denied_consistency_row = mock_trace
        .rows
        .iter()
        .find(|row| row.constraint_name == "denied_claim_requires_failure_code")
        .unwrap();
    assert_eq!(
        denied_consistency_row.input_value,
        "decision=0,failure_code=5"
    );
    assert!(denied_consistency_row.satisfied);

    let compatibility_report = mock_trace.winterfell_poc_compatibility_report();
    assert_eq!(
        compatibility_report.verdict,
        "compatible_subset_not_full_winterfell_trace"
    );
    assert!(compatibility_report.all_mock_rows_satisfied);
    assert!(
        compatibility_report
            .notes
            .iter()
            .any(|note| note.contains("not a STARK proof"))
    );
}
