use stark_engine::{
    ProofArtifactFixtureExpectationSet, ProofCommitmentPreimagePlan, PublicInputRootAssemblyPlan,
    PublicInputRootDigestCandidate, SelectedProverByteEncodingPlan, StarkBridgeInput,
    StarkProofArtifactV1BoundarySpec, StarkProofArtifactV1Candidate,
};

fn sample_bridge_input_json(decision: u8, failure_code: u32) -> String {
    format!(
        r#"{{
      "schema_version": "stark-bridge-input-v0",
      "producer": "rust-engine",
      "purpose": "stark_engine_compatibility_input",
      "runtime_mode": "dry_run_or_optional_sidecar",
      "claim": {{
        "claim_id": "CLAIM-PHASE8-PROOF",
        "claim_amount": 1000,
        "claim_hash": "0xabababababababababababababababababababababababababababababababab"
      }},
      "adjudication": {{
        "decision": {decision},
        "failure_code": {failure_code},
        "failure_reason": null,
        "ruleset_id": "current_g1_g10_denial_reason"
      }},
      "active_rust_facts": {{
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
      }},
      "winterfell_poc_mapping": {{
        "direct": {{
          "eligibility_active": 1,
          "provider_enrolled": 1,
          "duplicate_flag": 0
        }},
        "partial": {{
          "service_line_count": {{
            "source": ["billing_code_valid", "units_valid"],
            "status": "not_equivalent"
          }},
          "prior_auth_ok": {{
            "source": ["physician_certification_valid"],
            "status": "not_equivalent"
          }},
          "charge_cents": {{
            "source": ["claim_amount"],
            "status": "requires_unit_normalization"
          }},
          "program_integrity_hold": {{
            "source": ["disability_determination_valid", "recipient_not_deceased"],
            "status": "not_equivalent"
          }}
        }},
        "unmapped": {{
          "member_id": null,
          "provider_npi": null,
          "diagnosis_count": null,
          "max_charge_cents": null
        }}
      }},
      "public_inputs": {{
        "claim_hash": "0xabababababababababababababababababababababababababababababababab",
        "decision": {decision},
        "failure_code": {failure_code},
        "ruleset_id": "current_g1_g10_denial_reason"
      }},
      "proof_status": {{
        "stark_proof_generated": false,
        "winterfell_poc_compatible": false,
        "groth16_flow_unchanged": true,
        "on_chain_submission": false
      }}
    }}"#
    )
}

fn sample_bridge_input(decision: u8, failure_code: u32) -> StarkBridgeInput {
    serde_json::from_str(&sample_bridge_input_json(decision, failure_code)).unwrap()
}

#[test]
fn approved_bridge_input_converts_to_phase8_proof_artifact_candidate() {
    let input = sample_bridge_input(1, 0);
    let artifact = input.to_proof_artifact_v1_candidate().unwrap();

    assert_eq!(artifact.validate(), Ok(()));
    assert_eq!(
        artifact.schema_version,
        StarkProofArtifactV1Candidate::SCHEMA_VERSION
    );
    assert_eq!(artifact.decision, 1);
    assert_eq!(artifact.failure_code, 0);
    assert_eq!(
        artifact.solidity_abi_candidate,
        StarkProofArtifactV1Candidate::SOLIDITY_ABI_CANDIDATE
    );
    assert!(!artifact.runtime_wired);
    assert!(!artifact.on_chain_submission);
    assert!(artifact.groth16_flow_unchanged);
}

#[test]
fn denied_bridge_input_converts_to_phase8_proof_artifact_candidate() {
    let input = sample_bridge_input(0, 7);
    let artifact = input.to_proof_artifact_v1_candidate().unwrap();

    assert_eq!(artifact.validate(), Ok(()));
    assert_eq!(artifact.decision, 0);
    assert_eq!(artifact.failure_code, 7);
}

#[test]
fn phase8_candidate_keeps_roots_and_proof_absent_until_real_generation() {
    let input = sample_bridge_input(1, 0);
    let artifact = input.to_proof_artifact_v1_candidate().unwrap();

    assert_eq!(
        artifact.public_inputs.root_status,
        "requires_root_generation"
    );
    assert_eq!(artifact.public_inputs.public_input_root, None);
    assert_eq!(artifact.public_inputs.claim_source_root, None);
    assert_eq!(artifact.public_inputs.oracle_facts_root, None);
    assert_eq!(artifact.public_inputs.fee_schedule_root, None);
    assert_eq!(artifact.public_inputs.nullifier_root_before, None);
    assert_eq!(artifact.public_inputs.nullifier_root_after, None);
    assert_eq!(artifact.public_inputs.batch_root, None);

    assert_eq!(artifact.proof.proof_bytes, None);
    assert_eq!(artifact.proof.proof_bytes_status, "not_generated");
    assert_eq!(artifact.proof.proof_commitment, None);
    assert_eq!(artifact.proof.proof_commitment_status, "not_generated");
    assert_eq!(artifact.proof.prover, None);
    assert_eq!(artifact.proof.prover_status, "not_selected");

    assert!(!artifact.local_verification.verified);
    assert_eq!(
        artifact.local_verification.verification_status,
        "not_verified_no_real_proof"
    );
}

#[test]
fn phase8_candidate_rejects_runtime_like_artifacts() {
    let input = sample_bridge_input(1, 0);
    let mut artifact = input.to_proof_artifact_v1_candidate().unwrap();

    artifact.runtime_wired = true;
    artifact.on_chain_submission = true;
    artifact.proof.proof_bytes = Some("0x1234".to_string());
    artifact.local_verification.verified = true;

    let errors = artifact.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error == "runtime_wired must remain false"),
        "{errors:?}"
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "on_chain_submission must remain false"),
        "{errors:?}"
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "proof.proof_bytes must remain absent in candidate artifact"),
        "{errors:?}"
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "local_verification.verified must be false before real proof"),
        "{errors:?}"
    );
}

#[test]
fn phase8_candidate_rejects_decision_failure_code_mismatch() {
    let input = sample_bridge_input(1, 0);
    let mut artifact = input.to_proof_artifact_v1_candidate().unwrap();

    artifact.failure_code = 7;
    artifact.public_inputs.failure_code = 7;

    let errors = artifact.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error == "approved proof artifact candidate requires failure_code = 0"),
        "{errors:?}"
    );
}

#[test]
fn phase8_candidate_json_round_trips() {
    let input = sample_bridge_input(1, 0);
    let artifact = input.to_proof_artifact_v1_candidate().unwrap();
    let json = serde_json::to_string_pretty(&artifact).unwrap();
    let round_tripped: StarkProofArtifactV1Candidate = serde_json::from_str(&json).unwrap();

    assert_eq!(round_tripped, artifact);
    assert_eq!(round_tripped.validate(), Ok(()));
    assert!(json.contains("\"schema_version\": \"stark-proof-artifact-v1-candidate\""));
    assert!(json.contains("\"solidity_abi_candidate\": \"IStarkClaimsVerifierV1Candidate\""));
}

#[test]
fn phase8_candidate_generates_real_artifact_boundary_spec() {
    let input = sample_bridge_input(1, 0);
    let artifact = input.to_proof_artifact_v1_candidate().unwrap();
    let boundary_spec = artifact.to_v1_boundary_spec().unwrap();

    assert_eq!(boundary_spec.validate(), Ok(()));
    assert_eq!(
        boundary_spec.schema_version,
        StarkProofArtifactV1BoundarySpec::SCHEMA_VERSION
    );
    assert_eq!(
        boundary_spec.source_schema_version,
        StarkProofArtifactV1Candidate::SCHEMA_VERSION
    );
    assert_eq!(
        boundary_spec.target_artifact_schema_version,
        StarkProofArtifactV1BoundarySpec::TARGET_ARTIFACT_SCHEMA_VERSION
    );
    assert_eq!(
        boundary_spec.boundary_status,
        StarkProofArtifactV1BoundarySpec::BOUNDARY_STATUS
    );
    assert_eq!(boundary_spec.required_public_inputs.len(), 10);
    assert_eq!(boundary_spec.required_proof_fields.len(), 3);
    assert_eq!(boundary_spec.required_local_verification_fields.len(), 3);
    assert_eq!(
        boundary_spec.solidity_abi_candidate,
        StarkProofArtifactV1Candidate::SOLIDITY_ABI_CANDIDATE
    );
    assert_eq!(
        boundary_spec.runtime_wiring_status,
        "not_wired_boundary_only"
    );
    assert!(boundary_spec.groth16_flow_unchanged);
}

#[test]
fn phase8_boundary_spec_requires_all_real_artifact_public_inputs() {
    let input = sample_bridge_input(1, 0);
    let artifact = input.to_proof_artifact_v1_candidate().unwrap();
    let boundary_spec = artifact.to_v1_boundary_spec().unwrap();
    let public_input_names: Vec<&str> = boundary_spec
        .required_public_inputs
        .iter()
        .map(|requirement| requirement.field_name.as_str())
        .collect();

    assert_eq!(
        public_input_names,
        vec![
            "claim_hash",
            "decision",
            "failure_code",
            "public_input_root",
            "claim_source_root",
            "oracle_facts_root",
            "fee_schedule_root",
            "nullifier_root_before",
            "nullifier_root_after",
            "batch_root",
        ]
    );

    for requirement in &boundary_spec.required_public_inputs {
        assert!(!requirement.encoding.is_empty());
        assert!(!requirement.source.is_empty());
        assert_eq!(
            requirement.requirement_status,
            "required_before_runtime_wiring"
        );
    }
}

#[test]
fn phase8_boundary_spec_requires_proof_and_local_verification_fields() {
    let input = sample_bridge_input(1, 0);
    let artifact = input.to_proof_artifact_v1_candidate().unwrap();
    let boundary_spec = artifact.to_v1_boundary_spec().unwrap();
    let proof_field_names: Vec<&str> = boundary_spec
        .required_proof_fields
        .iter()
        .map(|requirement| requirement.field_name.as_str())
        .collect();
    let local_verification_names: Vec<&str> = boundary_spec
        .required_local_verification_fields
        .iter()
        .map(|requirement| requirement.field_name.as_str())
        .collect();

    assert_eq!(
        proof_field_names,
        vec!["proof_bytes", "proof_commitment", "prover"]
    );
    assert_eq!(
        local_verification_names,
        vec!["verified", "verification_status", "verifier"]
    );
}

#[test]
fn phase8_boundary_spec_rejects_runtime_wiring_claims() {
    let input = sample_bridge_input(1, 0);
    let artifact = input.to_proof_artifact_v1_candidate().unwrap();
    let mut boundary_spec = artifact.to_v1_boundary_spec().unwrap();

    boundary_spec.runtime_wiring_status = "wired".to_string();
    boundary_spec.groth16_flow_unchanged = false;

    let errors = boundary_spec.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error == "runtime_wiring_status must be not_wired_boundary_only"),
        "{errors:?}"
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "groth16_flow_unchanged must be true"),
        "{errors:?}"
    );
}

#[test]
fn phase8_boundary_spec_rejects_missing_required_fields() {
    let input = sample_bridge_input(1, 0);
    let artifact = input.to_proof_artifact_v1_candidate().unwrap();
    let mut boundary_spec = artifact.to_v1_boundary_spec().unwrap();

    boundary_spec
        .required_public_inputs
        .retain(|requirement| requirement.field_name != "batch_root");
    boundary_spec.required_proof_fields[0].requirement_status = "optional".to_string();

    let errors = boundary_spec.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error == "required_public_inputs missing field: batch_root"),
        "{errors:?}"
    );
    assert!(
        errors.iter().any(|error| error
            == "proof_bytes.requirement_status must be required_before_runtime_wiring"),
        "{errors:?}"
    );
}

#[test]
fn phase8_boundary_spec_json_round_trips() {
    let input = sample_bridge_input(1, 0);
    let artifact = input.to_proof_artifact_v1_candidate().unwrap();
    let boundary_spec = artifact.to_v1_boundary_spec().unwrap();
    let json = serde_json::to_string_pretty(&boundary_spec).unwrap();
    let round_tripped: StarkProofArtifactV1BoundarySpec = serde_json::from_str(&json).unwrap();

    assert_eq!(round_tripped, boundary_spec);
    assert_eq!(round_tripped.validate(), Ok(()));
    assert!(json.contains("\"schema_version\": \"stark-proof-artifact-v1-boundary-spec\""));
    assert!(json.contains("\"target_artifact_schema_version\": \"stark-proof-artifact-v1\""));
}

#[test]
fn phase8_boundary_spec_generates_public_input_root_assembly_plan() {
    let input = sample_bridge_input(1, 0);
    let artifact = input.to_proof_artifact_v1_candidate().unwrap();
    let boundary_spec = artifact.to_v1_boundary_spec().unwrap();
    let plan = boundary_spec.to_public_input_root_assembly_plan().unwrap();

    assert_eq!(plan.validate(), Ok(()));
    assert_eq!(
        plan.schema_version,
        PublicInputRootAssemblyPlan::SCHEMA_VERSION
    );
    assert_eq!(
        plan.source_schema_version,
        StarkProofArtifactV1BoundarySpec::SCHEMA_VERSION
    );
    assert_eq!(plan.plan_status, PublicInputRootAssemblyPlan::PLAN_STATUS);
    assert_eq!(plan.expected_field_count, 10);
    assert_eq!(plan.ordered_fields.len(), 10);
    assert_eq!(plan.public_input_root, None);
    assert_eq!(plan.root_generation_status, "not_generated");
    assert!(plan.groth16_flow_unchanged);
}

#[test]
fn public_input_root_assembly_plan_locks_canonical_field_order() {
    let input = sample_bridge_input(1, 0);
    let artifact = input.to_proof_artifact_v1_candidate().unwrap();
    let boundary_spec = artifact.to_v1_boundary_spec().unwrap();
    let plan = boundary_spec.to_public_input_root_assembly_plan().unwrap();
    let ordered_names: Vec<&str> = plan
        .ordered_fields
        .iter()
        .map(|field| field.field_name.as_str())
        .collect();

    assert_eq!(
        ordered_names,
        vec![
            "claim_hash",
            "decision",
            "failure_code",
            "public_input_root",
            "claim_source_root",
            "oracle_facts_root",
            "fee_schedule_root",
            "nullifier_root_before",
            "nullifier_root_after",
            "batch_root",
        ]
    );

    for (index, field) in plan.ordered_fields.iter().enumerate() {
        assert_eq!(field.position, index);
        assert!(!field.encoding.is_empty());
        assert!(!field.source.is_empty());
    }
}

#[test]
fn public_input_root_assembly_plan_marks_available_and_future_fields() {
    let input = sample_bridge_input(1, 0);
    let artifact = input.to_proof_artifact_v1_candidate().unwrap();
    let boundary_spec = artifact.to_v1_boundary_spec().unwrap();
    let plan = boundary_spec.to_public_input_root_assembly_plan().unwrap();

    for field in &plan.ordered_fields {
        if matches!(
            field.field_name.as_str(),
            "claim_hash" | "decision" | "failure_code"
        ) {
            assert_eq!(field.value_status, "available_from_bridge_input");
        } else {
            assert_eq!(field.value_status, "requires_future_root_generation");
        }
    }
}

#[test]
fn public_input_root_assembly_plan_rejects_root_generation_claims() {
    let input = sample_bridge_input(1, 0);
    let artifact = input.to_proof_artifact_v1_candidate().unwrap();
    let boundary_spec = artifact.to_v1_boundary_spec().unwrap();
    let mut plan = boundary_spec.to_public_input_root_assembly_plan().unwrap();

    plan.public_input_root =
        Some("0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd".to_string());
    plan.root_generation_status = "generated".to_string();
    plan.groth16_flow_unchanged = false;

    let errors = plan.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error
                == "public_input_root must remain absent until root generation exists"),
        "{errors:?}"
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "root_generation_status must be not_generated"),
        "{errors:?}"
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "groth16_flow_unchanged must be true"),
        "{errors:?}"
    );
}

#[test]
fn public_input_root_assembly_plan_rejects_reordered_fields() {
    let input = sample_bridge_input(1, 0);
    let artifact = input.to_proof_artifact_v1_candidate().unwrap();
    let boundary_spec = artifact.to_v1_boundary_spec().unwrap();
    let mut plan = boundary_spec.to_public_input_root_assembly_plan().unwrap();

    plan.ordered_fields.swap(0, 1);

    let errors = plan.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error == "ordered_fields[0] must be claim_hash"),
        "{errors:?}"
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "ordered_fields[1] must be decision"),
        "{errors:?}"
    );
}

#[test]
fn public_input_root_assembly_plan_json_round_trips() {
    let input = sample_bridge_input(1, 0);
    let artifact = input.to_proof_artifact_v1_candidate().unwrap();
    let boundary_spec = artifact.to_v1_boundary_spec().unwrap();
    let plan = boundary_spec.to_public_input_root_assembly_plan().unwrap();
    let json = serde_json::to_string_pretty(&plan).unwrap();
    let round_tripped: PublicInputRootAssemblyPlan = serde_json::from_str(&json).unwrap();

    assert_eq!(round_tripped, plan);
    assert_eq!(round_tripped.validate(), Ok(()));
    assert!(json.contains("\"schema_version\": \"public-input-root-assembly-plan-v0\""));
    assert!(json.contains("\"root_generation_status\": \"not_generated\""));
}

#[test]
fn phase8_boundary_spec_generates_proof_commitment_preimage_plan() {
    let input = sample_bridge_input(1, 0);
    let artifact = input.to_proof_artifact_v1_candidate().unwrap();
    let boundary_spec = artifact.to_v1_boundary_spec().unwrap();
    let plan = boundary_spec.to_proof_commitment_preimage_plan().unwrap();

    assert_eq!(plan.validate(), Ok(()));
    assert_eq!(
        plan.schema_version,
        ProofCommitmentPreimagePlan::SCHEMA_VERSION
    );
    assert_eq!(
        plan.source_schema_version,
        StarkProofArtifactV1BoundarySpec::SCHEMA_VERSION
    );
    assert_eq!(plan.plan_status, ProofCommitmentPreimagePlan::PLAN_STATUS);
    assert_eq!(plan.expected_component_count, 8);
    assert_eq!(plan.ordered_components.len(), 8);
    assert_eq!(plan.proof_commitment, None);
    assert_eq!(plan.commitment_generation_status, "not_generated");
    assert!(plan.groth16_flow_unchanged);
}

#[test]
fn proof_commitment_preimage_plan_locks_canonical_component_order() {
    let input = sample_bridge_input(1, 0);
    let artifact = input.to_proof_artifact_v1_candidate().unwrap();
    let boundary_spec = artifact.to_v1_boundary_spec().unwrap();
    let plan = boundary_spec.to_proof_commitment_preimage_plan().unwrap();
    let ordered_names: Vec<&str> = plan
        .ordered_components
        .iter()
        .map(|component| component.component_name.as_str())
        .collect();

    assert_eq!(
        ordered_names,
        vec![
            "target_artifact_schema_version",
            "solidity_abi_candidate",
            "prover",
            "proof_bytes",
            "public_input_root",
            "claim_hash",
            "decision",
            "failure_code",
        ]
    );

    for (index, component) in plan.ordered_components.iter().enumerate() {
        assert_eq!(component.position, index);
        assert!(!component.encoding.is_empty());
        assert!(!component.source.is_empty());
    }
}

#[test]
fn proof_commitment_preimage_plan_marks_available_and_future_components() {
    let input = sample_bridge_input(1, 0);
    let artifact = input.to_proof_artifact_v1_candidate().unwrap();
    let boundary_spec = artifact.to_v1_boundary_spec().unwrap();
    let plan = boundary_spec.to_proof_commitment_preimage_plan().unwrap();

    for component in &plan.ordered_components {
        match component.component_name.as_str() {
            "target_artifact_schema_version" | "solidity_abi_candidate" => {
                assert_eq!(component.value_status, "available_from_boundary_spec");
            }
            "prover" => assert_eq!(component.value_status, "requires_selected_prover"),
            "proof_bytes" => assert_eq!(component.value_status, "requires_real_proof_bytes"),
            "public_input_root" => {
                assert_eq!(
                    component.value_status,
                    "requires_public_input_root_generation"
                );
            }
            "claim_hash" | "decision" | "failure_code" => {
                assert_eq!(
                    component.value_status,
                    "available_from_future_artifact_public_inputs"
                );
            }
            other => panic!("unexpected component: {other}"),
        }
    }
}

#[test]
fn proof_commitment_preimage_plan_rejects_commitment_generation_claims() {
    let input = sample_bridge_input(1, 0);
    let artifact = input.to_proof_artifact_v1_candidate().unwrap();
    let boundary_spec = artifact.to_v1_boundary_spec().unwrap();
    let mut plan = boundary_spec.to_proof_commitment_preimage_plan().unwrap();

    plan.proof_commitment =
        Some("0xefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef".to_string());
    plan.commitment_generation_status = "generated".to_string();
    plan.groth16_flow_unchanged = false;

    let errors = plan.validate().unwrap_err();
    assert!(
        errors.iter().any(|error| error
            == "proof_commitment must remain absent until commitment generation exists"),
        "{errors:?}"
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "commitment_generation_status must be not_generated"),
        "{errors:?}"
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "groth16_flow_unchanged must be true"),
        "{errors:?}"
    );
}

#[test]
fn proof_commitment_preimage_plan_rejects_reordered_components() {
    let input = sample_bridge_input(1, 0);
    let artifact = input.to_proof_artifact_v1_candidate().unwrap();
    let boundary_spec = artifact.to_v1_boundary_spec().unwrap();
    let mut plan = boundary_spec.to_proof_commitment_preimage_plan().unwrap();

    plan.ordered_components.swap(0, 1);

    let errors = plan.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error == "ordered_components[0] must be target_artifact_schema_version"),
        "{errors:?}"
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "ordered_components[1] must be solidity_abi_candidate"),
        "{errors:?}"
    );
}

#[test]
fn proof_commitment_preimage_plan_json_round_trips() {
    let input = sample_bridge_input(1, 0);
    let artifact = input.to_proof_artifact_v1_candidate().unwrap();
    let boundary_spec = artifact.to_v1_boundary_spec().unwrap();
    let plan = boundary_spec.to_proof_commitment_preimage_plan().unwrap();
    let json = serde_json::to_string_pretty(&plan).unwrap();
    let round_tripped: ProofCommitmentPreimagePlan = serde_json::from_str(&json).unwrap();

    assert_eq!(round_tripped, plan);
    assert_eq!(round_tripped.validate(), Ok(()));
    assert!(json.contains("\"schema_version\": \"proof-commitment-preimage-plan-v0\""));
    assert!(json.contains("\"commitment_generation_status\": \"not_generated\""));
}

#[test]
fn phase8_boundary_spec_generates_fixture_expectation_set() {
    let input = sample_bridge_input(1, 0);
    let artifact = input.to_proof_artifact_v1_candidate().unwrap();
    let boundary_spec = artifact.to_v1_boundary_spec().unwrap();
    let expectations = boundary_spec.to_fixture_expectation_set().unwrap();

    assert_eq!(expectations.validate(), Ok(()));
    assert_eq!(
        expectations.schema_version,
        ProofArtifactFixtureExpectationSet::SCHEMA_VERSION
    );
    assert_eq!(
        expectations.source_schema_version,
        StarkProofArtifactV1BoundarySpec::SCHEMA_VERSION
    );
    assert_eq!(
        expectations.expectation_set_status,
        ProofArtifactFixtureExpectationSet::EXPECTATION_SET_STATUS
    );
    assert_eq!(expectations.expected_fixtures.len(), 2);
    assert!(expectations.groth16_flow_unchanged);
}

#[test]
fn fixture_expectations_require_approved_and_denied_shapes() {
    let input = sample_bridge_input(1, 0);
    let artifact = input.to_proof_artifact_v1_candidate().unwrap();
    let boundary_spec = artifact.to_v1_boundary_spec().unwrap();
    let expectations = boundary_spec.to_fixture_expectation_set().unwrap();

    let approved = expectations
        .expected_fixtures
        .iter()
        .find(|fixture| fixture.fixture_id == "approved_claim")
        .unwrap();
    let denied = expectations
        .expected_fixtures
        .iter()
        .find(|fixture| fixture.fixture_id == "denied_claim")
        .unwrap();

    assert_eq!(approved.decision, 1);
    assert_eq!(approved.failure_code, 0);
    assert_eq!(denied.decision, 0);
    assert_ne!(denied.failure_code, 0);
}

#[test]
fn fixture_expectations_require_all_real_artifact_dependencies() {
    let input = sample_bridge_input(1, 0);
    let artifact = input.to_proof_artifact_v1_candidate().unwrap();
    let boundary_spec = artifact.to_v1_boundary_spec().unwrap();
    let expectations = boundary_spec.to_fixture_expectation_set().unwrap();

    for fixture in &expectations.expected_fixtures {
        assert_eq!(
            fixture.required_public_input_root_status,
            "required_before_runtime_wiring"
        );
        assert_eq!(
            fixture.required_proof_bytes_status,
            "required_before_runtime_wiring"
        );
        assert_eq!(
            fixture.required_proof_commitment_status,
            "required_before_runtime_wiring"
        );
        assert_eq!(
            fixture.required_local_verification_status,
            "required_before_runtime_wiring"
        );
        assert!(!fixture.runtime_wiring_allowed);
    }
}

#[test]
fn fixture_expectations_reject_runtime_wiring_claims() {
    let input = sample_bridge_input(1, 0);
    let artifact = input.to_proof_artifact_v1_candidate().unwrap();
    let boundary_spec = artifact.to_v1_boundary_spec().unwrap();
    let mut expectations = boundary_spec.to_fixture_expectation_set().unwrap();

    expectations.groth16_flow_unchanged = false;
    expectations.expected_fixtures[0].runtime_wiring_allowed = true;
    expectations.expected_fixtures[0].required_proof_bytes_status = "generated".to_string();

    let errors = expectations.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error == "groth16_flow_unchanged must be true"),
        "{errors:?}"
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "approved_claim.runtime_wiring_allowed must be false"),
        "{errors:?}"
    );
    assert!(
        errors.iter().any(|error| error
            == "approved_claim.required_proof_bytes_status must be required_before_runtime_wiring"),
        "{errors:?}"
    );
}

#[test]
fn fixture_expectations_reject_bad_decision_failure_code_shapes() {
    let input = sample_bridge_input(1, 0);
    let artifact = input.to_proof_artifact_v1_candidate().unwrap();
    let boundary_spec = artifact.to_v1_boundary_spec().unwrap();
    let mut expectations = boundary_spec.to_fixture_expectation_set().unwrap();

    let approved = expectations
        .expected_fixtures
        .iter_mut()
        .find(|fixture| fixture.fixture_id == "approved_claim")
        .unwrap();
    approved.decision = 0;
    approved.failure_code = 7;

    let denied = expectations
        .expected_fixtures
        .iter_mut()
        .find(|fixture| fixture.fixture_id == "denied_claim")
        .unwrap();
    denied.decision = 1;
    denied.failure_code = 0;

    let errors = expectations.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error == "approved_claim decision must be 1"),
        "{errors:?}"
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "approved_claim failure_code must be 0"),
        "{errors:?}"
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "denied_claim decision must be 0"),
        "{errors:?}"
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "denied_claim failure_code must be non-zero"),
        "{errors:?}"
    );
}

#[test]
fn fixture_expectations_json_round_trips() {
    let input = sample_bridge_input(1, 0);
    let artifact = input.to_proof_artifact_v1_candidate().unwrap();
    let boundary_spec = artifact.to_v1_boundary_spec().unwrap();
    let expectations = boundary_spec.to_fixture_expectation_set().unwrap();
    let json = serde_json::to_string_pretty(&expectations).unwrap();
    let round_tripped: ProofArtifactFixtureExpectationSet = serde_json::from_str(&json).unwrap();

    assert_eq!(round_tripped, expectations);
    assert_eq!(round_tripped.validate(), Ok(()));
    assert!(json.contains("\"schema_version\": \"proof-artifact-fixture-expectations-v0\""));
    assert!(json.contains("\"fixture_id\": \"approved_claim\""));
    assert!(json.contains("\"fixture_id\": \"denied_claim\""));
}

#[test]
fn phase8_boundary_spec_generates_selected_prover_byte_encoding_plan() {
    let input = sample_bridge_input(1, 0);
    let artifact = input.to_proof_artifact_v1_candidate().unwrap();
    let boundary_spec = artifact.to_v1_boundary_spec().unwrap();
    let plan = boundary_spec
        .to_selected_prover_byte_encoding_plan()
        .unwrap();

    assert_eq!(plan.validate(), Ok(()));
    assert_eq!(
        plan.schema_version,
        SelectedProverByteEncodingPlan::SCHEMA_VERSION
    );
    assert_eq!(
        plan.source_schema_version,
        StarkProofArtifactV1BoundarySpec::SCHEMA_VERSION
    );
    assert_eq!(
        plan.plan_status,
        SelectedProverByteEncodingPlan::PLAN_STATUS
    );
    assert_eq!(plan.selected_prover, "winterfell_poc_preview");
    assert_eq!(
        plan.proof_bytes_encoding,
        "0x_prefixed_canonical_stark_proof_bytes"
    );
    assert_eq!(
        plan.proof_bytes_status,
        "not_generated_encoding_contract_only"
    );
    assert!(!plan.runtime_wiring_allowed);
    assert!(plan.groth16_flow_unchanged);
}

#[test]
fn selected_prover_byte_encoding_plan_locks_commitment_binding_order() {
    let input = sample_bridge_input(1, 0);
    let artifact = input.to_proof_artifact_v1_candidate().unwrap();
    let boundary_spec = artifact.to_v1_boundary_spec().unwrap();
    let plan = boundary_spec
        .to_selected_prover_byte_encoding_plan()
        .unwrap();

    assert_eq!(
        plan.commitment_binding_fields,
        vec![
            "selected_prover",
            "proof_bytes_encoding",
            "canonical_byte_order",
            "serialization_format",
            "proof_bytes",
        ]
    );
    assert_eq!(plan.expected_binding_field_count, 5);
}

#[test]
fn selected_prover_byte_encoding_plan_rejects_runtime_or_generated_claims() {
    let input = sample_bridge_input(1, 0);
    let artifact = input.to_proof_artifact_v1_candidate().unwrap();
    let boundary_spec = artifact.to_v1_boundary_spec().unwrap();
    let mut plan = boundary_spec
        .to_selected_prover_byte_encoding_plan()
        .unwrap();

    plan.proof_bytes_status = "generated".to_string();
    plan.runtime_wiring_allowed = true;
    plan.groth16_flow_unchanged = false;

    let errors = plan.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error == "proof_bytes_status must be not_generated_encoding_contract_only"),
        "{errors:?}"
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "runtime_wiring_allowed must be false"),
        "{errors:?}"
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "groth16_flow_unchanged must be true"),
        "{errors:?}"
    );
}

#[test]
fn selected_prover_byte_encoding_plan_rejects_binding_reorder() {
    let input = sample_bridge_input(1, 0);
    let artifact = input.to_proof_artifact_v1_candidate().unwrap();
    let boundary_spec = artifact.to_v1_boundary_spec().unwrap();
    let mut plan = boundary_spec
        .to_selected_prover_byte_encoding_plan()
        .unwrap();

    plan.commitment_binding_fields.swap(0, 1);

    let errors = plan.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error == "commitment_binding_fields[0] must be selected_prover"),
        "{errors:?}"
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "commitment_binding_fields[1] must be proof_bytes_encoding"),
        "{errors:?}"
    );
}

#[test]
fn selected_prover_byte_encoding_plan_json_round_trips() {
    let input = sample_bridge_input(1, 0);
    let artifact = input.to_proof_artifact_v1_candidate().unwrap();
    let boundary_spec = artifact.to_v1_boundary_spec().unwrap();
    let plan = boundary_spec
        .to_selected_prover_byte_encoding_plan()
        .unwrap();
    let json = serde_json::to_string_pretty(&plan).unwrap();
    let round_tripped: SelectedProverByteEncodingPlan = serde_json::from_str(&json).unwrap();

    assert_eq!(round_tripped, plan);
    assert_eq!(round_tripped.validate(), Ok(()));
    assert!(json.contains("\"schema_version\": \"selected-prover-byte-encoding-plan-v0\""));
    assert!(json.contains("\"selected_prover\": \"winterfell_poc_preview\""));
    assert!(json.contains("\"proof_bytes_status\": \"not_generated_encoding_contract_only\""));
}

#[test]
fn public_input_root_assembly_plan_generates_digest_candidate() {
    let input = sample_bridge_input(1, 0);
    let artifact = input.to_proof_artifact_v1_candidate().unwrap();
    let boundary_spec = artifact.to_v1_boundary_spec().unwrap();
    let plan = boundary_spec.to_public_input_root_assembly_plan().unwrap();
    let candidate = plan.to_digest_candidate().unwrap();

    assert_eq!(candidate.validate(), Ok(()));
    assert_eq!(
        candidate.schema_version,
        PublicInputRootDigestCandidate::SCHEMA_VERSION
    );
    assert_eq!(
        candidate.source_schema_version,
        PublicInputRootAssemblyPlan::SCHEMA_VERSION
    );
    assert_eq!(
        candidate.candidate_status,
        PublicInputRootDigestCandidate::CANDIDATE_STATUS
    );
    assert_eq!(
        candidate.hash_algorithm,
        PublicInputRootDigestCandidate::HASH_ALGORITHM
    );
    assert_eq!(candidate.ordered_fields.len(), 10);
    assert_eq!(candidate.expected_field_count, 10);
    assert_eq!(candidate.public_input_root_candidate.len(), 66);
    assert!(candidate.public_input_root_candidate.starts_with("0x"));
    assert_eq!(
        candidate.root_generation_status,
        "candidate_generated_not_runtime"
    );
    assert!(!candidate.production_hash_selected);
    assert!(!candidate.runtime_wiring_allowed);
    assert!(candidate.groth16_flow_unchanged);
}

#[test]
fn public_input_root_digest_candidate_is_stable_for_same_plan() {
    let input = sample_bridge_input(1, 0);
    let artifact = input.to_proof_artifact_v1_candidate().unwrap();
    let boundary_spec = artifact.to_v1_boundary_spec().unwrap();
    let plan = boundary_spec.to_public_input_root_assembly_plan().unwrap();

    let first = plan.to_digest_candidate().unwrap();
    let second = plan.to_digest_candidate().unwrap();

    assert_eq!(
        first.public_input_root_candidate,
        second.public_input_root_candidate
    );
    assert_eq!(first.canonical_preimage, second.canonical_preimage);
}

#[test]
fn public_input_root_digest_candidate_locks_canonical_preimage_order() {
    let input = sample_bridge_input(1, 0);
    let artifact = input.to_proof_artifact_v1_candidate().unwrap();
    let boundary_spec = artifact.to_v1_boundary_spec().unwrap();
    let plan = boundary_spec.to_public_input_root_assembly_plan().unwrap();
    let candidate = plan.to_digest_candidate().unwrap();

    assert!(candidate.canonical_preimage.starts_with(
        "canonical_encoding:ordered_field_name_colon_canonical_value_utf8_joined_by_newline"
    ));
    assert!(candidate.canonical_preimage.contains(
        "0:claim_hash:available_from_bridge_input:__available_from_bridge_input__::claim_hash"
    ));
    assert!(candidate.canonical_preimage.contains(
        "3:public_input_root:requires_future_root_generation:__requires_future_root_generation__::public_input_root"
    ));
    assert!(candidate.canonical_preimage.contains(
        "9:batch_root:requires_future_root_generation:__requires_future_root_generation__::batch_root"
    ));
}

#[test]
fn public_input_root_digest_candidate_rejects_tampered_digest() {
    let input = sample_bridge_input(1, 0);
    let artifact = input.to_proof_artifact_v1_candidate().unwrap();
    let boundary_spec = artifact.to_v1_boundary_spec().unwrap();
    let plan = boundary_spec.to_public_input_root_assembly_plan().unwrap();
    let mut candidate = plan.to_digest_candidate().unwrap();

    candidate.public_input_root_candidate =
        "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string();

    let errors = candidate.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error
                == "public_input_root_candidate must equal sha2_256(canonical_preimage)"),
        "{errors:?}"
    );
}

#[test]
fn public_input_root_digest_candidate_rejects_runtime_or_production_claims() {
    let input = sample_bridge_input(1, 0);
    let artifact = input.to_proof_artifact_v1_candidate().unwrap();
    let boundary_spec = artifact.to_v1_boundary_spec().unwrap();
    let plan = boundary_spec.to_public_input_root_assembly_plan().unwrap();
    let mut candidate = plan.to_digest_candidate().unwrap();

    candidate.root_generation_status = "production_generated".to_string();
    candidate.production_hash_selected = true;
    candidate.runtime_wiring_allowed = true;
    candidate.groth16_flow_unchanged = false;

    let errors = candidate.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error == "root_generation_status must be candidate_generated_not_runtime"),
        "{errors:?}"
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "production_hash_selected must be false"),
        "{errors:?}"
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "runtime_wiring_allowed must be false"),
        "{errors:?}"
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "groth16_flow_unchanged must be true"),
        "{errors:?}"
    );
}

#[test]
fn public_input_root_digest_candidate_json_round_trips() {
    let input = sample_bridge_input(1, 0);
    let artifact = input.to_proof_artifact_v1_candidate().unwrap();
    let boundary_spec = artifact.to_v1_boundary_spec().unwrap();
    let plan = boundary_spec.to_public_input_root_assembly_plan().unwrap();
    let candidate = plan.to_digest_candidate().unwrap();
    let json = serde_json::to_string_pretty(&candidate).unwrap();
    let round_tripped: PublicInputRootDigestCandidate = serde_json::from_str(&json).unwrap();

    assert_eq!(round_tripped, candidate);
    assert_eq!(round_tripped.validate(), Ok(()));
    assert!(json.contains("\"schema_version\": \"public-input-root-digest-candidate-v0\""));
    assert!(json.contains("\"hash_algorithm\": \"sha2_256_candidate_not_production_hash\""));
    assert!(json.contains("\"root_generation_status\": \"candidate_generated_not_runtime\""));
}
