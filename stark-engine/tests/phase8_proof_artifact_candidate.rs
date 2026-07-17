use stark_engine::{StarkBridgeInput, StarkProofArtifactV1Candidate};

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

    assert_eq!(artifact.public_inputs.root_status, "requires_root_generation");
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
        errors.iter().any(|error| error == "runtime_wired must remain false"),
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
