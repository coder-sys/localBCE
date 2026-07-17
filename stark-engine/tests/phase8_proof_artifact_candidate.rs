use stark_engine::{
    StarkBridgeInput, StarkProofArtifactV1BoundarySpec, StarkProofArtifactV1Candidate,
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
