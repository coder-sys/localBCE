use stark_engine::{BatchRootCompatibilityPlan, MappingClass, MappingCounts, StarkBridgeInput};

fn sample_bridge_input_json() -> &'static str {
    r#"{
      "schema_version": "stark-bridge-input-v0",
      "producer": "rust-engine",
      "purpose": "stark_engine_compatibility_input",
      "runtime_mode": "dry_run_or_optional_sidecar",
      "claim": {
        "claim_id": "CLAIM-PHASE3-BATCH-ROOT",
        "claim_amount": 1000,
        "claim_hash": "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
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
        "claim_hash": "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
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
fn batch_root_plan_classifies_target_public_inputs() {
    let input = sample_bridge_input();
    let plan = BatchRootCompatibilityPlan::from_bridge_input(&input).unwrap();

    assert_eq!(
        plan.schema_version,
        BatchRootCompatibilityPlan::SCHEMA_VERSION
    );
    assert_eq!(plan.source_schema_version, StarkBridgeInput::SCHEMA_VERSION);
    assert_eq!(plan.plan_status, BatchRootCompatibilityPlan::PLAN_STATUS);
    assert_eq!(
        plan.counts,
        MappingCounts {
            direct: 3,
            partial: 5,
            unmapped: 9,
        }
    );
    assert_eq!(plan.counts, BatchRootCompatibilityPlan::EXPECTED_COUNTS);
    assert_eq!(plan.target_fields.len(), 17);
    assert_eq!(plan.validate(), Ok(()));
}

#[test]
fn batch_root_plan_keeps_current_single_claim_public_inputs_direct() {
    let input = sample_bridge_input();
    let plan = BatchRootCompatibilityPlan::from_bridge_input(&input).unwrap();

    let direct_fields: Vec<&str> = plan
        .target_fields
        .iter()
        .filter(|field| field.class == MappingClass::Direct)
        .map(|field| field.target_field.as_str())
        .collect();

    assert_eq!(direct_fields, vec!["claim_hash", "decision", "failure_code"]);
}

#[test]
fn batch_root_plan_marks_future_roots_as_partial_or_unmapped() {
    let input = sample_bridge_input();
    let plan = BatchRootCompatibilityPlan::from_bridge_input(&input).unwrap();

    for partial_field in [
        "claimSourceRoot",
        "adjudicationResultRoot",
        "rulesetRoot",
        "claimCount",
        "combinedPublicInputVector",
    ] {
        let mapping = plan
            .target_fields
            .iter()
            .find(|field| field.target_field == partial_field)
            .unwrap();
        assert_eq!(mapping.class, MappingClass::Partial);
        assert!(mapping.active_bridge_source.is_some());
    }

    for unmapped_field in [
        "oracleFactsRoot",
        "feeScheduleRoot",
        "addressBookRoot",
        "paymentRoot",
        "nullifierRootBefore",
        "nullifierRootAfter",
        "batchNullifierCommitment",
        "verifierKeyId",
        "paymentCount",
    ] {
        let mapping = plan
            .target_fields
            .iter()
            .find(|field| field.target_field == unmapped_field)
            .unwrap();
        assert_eq!(mapping.class, MappingClass::Unmapped);
        assert_eq!(mapping.active_bridge_source, None);
    }
}

#[test]
fn batch_root_plan_rejects_invalid_bridge_input() {
    let mut input = sample_bridge_input();
    input.proof_status.stark_proof_generated = true;

    let errors = BatchRootCompatibilityPlan::from_bridge_input(&input).unwrap_err();

    assert!(errors
        .iter()
        .any(|error| error.contains("proof_status.stark_proof_generated must be false")));
}

#[test]
fn batch_root_plan_serializes_as_planning_artifact_only() {
    let input = sample_bridge_input();
    let plan = BatchRootCompatibilityPlan::from_bridge_input(&input).unwrap();
    let json = serde_json::to_string_pretty(&plan).unwrap();

    assert!(json.contains("\"schema_version\": \"batch-root-compatibility-plan-v0\""));
    assert!(json.contains("\"plan_status\": \"planning_only_no_root_generation\""));
    assert!(json.contains("\"class\": \"partial\""));
    assert!(json.contains("\"class\": \"unmapped\""));
    assert!(!json.contains("proof_generated"));
    assert!(!json.contains("root_generated"));
}

#[test]
fn batch_root_plan_json_round_trips_before_any_root_generation() {
    let input = sample_bridge_input();
    let plan = BatchRootCompatibilityPlan::from_bridge_input(&input).unwrap();
    let json = serde_json::to_string_pretty(&plan).unwrap();
    let round_tripped: BatchRootCompatibilityPlan = serde_json::from_str(&json).unwrap();

    assert_eq!(round_tripped, plan);
    assert_eq!(round_tripped.validate(), Ok(()));
    assert_eq!(round_tripped.counts.direct, 3);
    assert_eq!(round_tripped.counts.partial, 5);
    assert_eq!(round_tripped.counts.unmapped, 9);
}

#[test]
fn batch_root_plan_validation_rejects_bad_counts() {
    let input = sample_bridge_input();
    let mut plan = BatchRootCompatibilityPlan::from_bridge_input(&input).unwrap();
    plan.counts.direct = 99;

    let errors = plan.validate().unwrap_err();

    assert!(errors
        .iter()
        .any(|error| error.contains("counts must match target_fields classification")));
}

#[test]
fn batch_root_plan_validation_rejects_runtime_like_status() {
    let input = sample_bridge_input();
    let mut plan = BatchRootCompatibilityPlan::from_bridge_input(&input).unwrap();
    plan.plan_status = "root_generation_ready".to_string();

    let errors = plan.validate().unwrap_err();

    assert!(errors.iter().any(|error| error.contains(
        "plan_status must be planning_only_no_root_generation"
    )));
}
