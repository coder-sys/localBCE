use stark_engine::{
    ClaimSourceRootInput, FeeScheduleRootInput, NullifierRootTransitionInput, OracleFactsRootInput,
    Phase8PreProverBundleCheckpoint, ProofArtifactFixtureExpectationSet,
    ProofCommitmentPreimagePlan, PublicInputRootDigestCandidate, SelectedProverByteEncodingPlan,
    SourceRootAggregationPlan, SourceRootDigestCandidate, StarkBridgeInput,
    StarkProofArtifactV1BoundarySpec,
};

const CLAIM_HASH: &str = "0x1c1b60223d4f3ffd351887f834b31a4260508b1602a5a9e16a447ea40e386607";

struct BundleArtifacts {
    boundary_spec: StarkProofArtifactV1BoundarySpec,
    public_input_root: PublicInputRootDigestCandidate,
    source_root_aggregation: SourceRootAggregationPlan,
    proof_commitment: ProofCommitmentPreimagePlan,
    fixture_expectations: ProofArtifactFixtureExpectationSet,
    byte_encoding: SelectedProverByteEncodingPlan,
}

fn sample_bridge_input() -> StarkBridgeInput {
    serde_json::from_str(&format!(
        r#"{{
      "schema_version": "stark-bridge-input-v0",
      "producer": "rust-engine",
      "purpose": "stark_engine_compatibility_input",
      "runtime_mode": "dry_run_or_optional_sidecar",
      "claim": {{
        "claim_id": "CLAIM-PHASE8-BUNDLE",
        "claim_amount": 1000,
        "claim_hash": "{CLAIM_HASH}"
      }},
      "adjudication": {{
        "decision": 1,
        "failure_code": 0,
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
        "claim_hash": "{CLAIM_HASH}",
        "decision": 1,
        "failure_code": 0,
        "ruleset_id": "current_g1_g10_denial_reason"
      }},
      "proof_status": {{
        "stark_proof_generated": false,
        "winterfell_poc_compatible": false,
        "groth16_flow_unchanged": true,
        "on_chain_submission": false
      }}
    }}"#
    ))
    .unwrap()
}

fn source_root_digest_candidates() -> Vec<SourceRootDigestCandidate> {
    let claim_source = ClaimSourceRootInput {
        schema_version: ClaimSourceRootInput::SCHEMA_VERSION.to_string(),
        source_schema_version: ClaimSourceRootInput::SOURCE_SCHEMA_VERSION.to_string(),
        input_status: ClaimSourceRootInput::INPUT_STATUS.to_string(),
        claim_id: "CLAIM-PHASE8-BUNDLE".to_string(),
        claim_hash: CLAIM_HASH.to_string(),
        claim_amount: 1000,
        member_id: None,
        provider_npi: None,
        service_date: Some(20260615),
        procedure_codes: Vec::new(),
        diagnosis_codes: Vec::new(),
        service_line_count: None,
        root_generation_status: ClaimSourceRootInput::ROOT_GENERATION_STATUS.to_string(),
        notes: vec!["test fixture".to_string()],
    }
    .to_digest_candidate()
    .unwrap();

    let oracle_facts = OracleFactsRootInput {
        schema_version: OracleFactsRootInput::SCHEMA_VERSION.to_string(),
        source_schema_version: OracleFactsRootInput::SOURCE_SCHEMA_VERSION.to_string(),
        input_status: OracleFactsRootInput::INPUT_STATUS.to_string(),
        claim_id: "CLAIM-PHASE8-BUNDLE".to_string(),
        claim_hash: CLAIM_HASH.to_string(),
        source_manifest_id: None,
        facts: Vec::new(),
        attestation_refs: Vec::new(),
        root_generation_status: OracleFactsRootInput::ROOT_GENERATION_STATUS.to_string(),
        notes: vec!["test fixture".to_string()],
    }
    .to_digest_candidate()
    .unwrap();

    let fee_schedule = FeeScheduleRootInput {
        schema_version: FeeScheduleRootInput::SCHEMA_VERSION.to_string(),
        source_schema_version: FeeScheduleRootInput::SOURCE_SCHEMA_VERSION.to_string(),
        input_status: FeeScheduleRootInput::INPUT_STATUS.to_string(),
        claim_id: "CLAIM-PHASE8-BUNDLE".to_string(),
        claim_hash: CLAIM_HASH.to_string(),
        fee_schedule_id: None,
        entries: Vec::new(),
        root_generation_status: FeeScheduleRootInput::ROOT_GENERATION_STATUS.to_string(),
        notes: vec!["test fixture".to_string()],
    }
    .to_digest_candidate()
    .unwrap();

    let nullifier = NullifierRootTransitionInput {
        schema_version: NullifierRootTransitionInput::SCHEMA_VERSION.to_string(),
        source_schema_version: NullifierRootTransitionInput::SOURCE_SCHEMA_VERSION.to_string(),
        input_status: NullifierRootTransitionInput::INPUT_STATUS.to_string(),
        claim_id: "CLAIM-PHASE8-BUNDLE".to_string(),
        claim_hash: CLAIM_HASH.to_string(),
        nullifier_candidate: None,
        nullifier_root_before: None,
        nullifier_root_after: None,
        transition_status: NullifierRootTransitionInput::TRANSITION_STATUS.to_string(),
        root_generation_status: NullifierRootTransitionInput::ROOT_GENERATION_STATUS.to_string(),
        notes: vec!["test fixture".to_string()],
    }
    .to_digest_candidate()
    .unwrap();

    vec![claim_source, oracle_facts, fee_schedule, nullifier]
}

fn bundle_artifacts() -> BundleArtifacts {
    let artifact = sample_bridge_input()
        .to_proof_artifact_v1_candidate()
        .unwrap();
    let boundary_spec = artifact.to_v1_boundary_spec().unwrap();
    let public_input_root = boundary_spec
        .to_public_input_root_assembly_plan()
        .unwrap()
        .to_digest_candidate()
        .unwrap();
    let source_root_aggregation = SourceRootAggregationPlan::from_candidates(
        &public_input_root,
        &source_root_digest_candidates(),
    )
    .unwrap();
    let proof_commitment = boundary_spec.to_proof_commitment_preimage_plan().unwrap();
    let fixture_expectations = boundary_spec.to_fixture_expectation_set().unwrap();
    let byte_encoding = boundary_spec
        .to_selected_prover_byte_encoding_plan()
        .unwrap();

    BundleArtifacts {
        boundary_spec,
        public_input_root,
        source_root_aggregation,
        proof_commitment,
        fixture_expectations,
        byte_encoding,
    }
}

fn checkpoint_from_artifacts(
    artifacts: &BundleArtifacts,
) -> Result<Phase8PreProverBundleCheckpoint, Vec<String>> {
    Phase8PreProverBundleCheckpoint::from_artifacts(
        &artifacts.boundary_spec,
        &artifacts.public_input_root,
        &artifacts.source_root_aggregation,
        &artifacts.proof_commitment,
        &artifacts.fixture_expectations,
        &artifacts.byte_encoding,
    )
}

#[test]
fn phase8_pre_prover_bundle_checkpoint_validates_complete_bundle() {
    let artifacts = bundle_artifacts();
    let checkpoint = checkpoint_from_artifacts(&artifacts).unwrap();

    checkpoint.validate().unwrap();
    assert_eq!(
        checkpoint.schema_version,
        Phase8PreProverBundleCheckpoint::SCHEMA_VERSION
    );
    assert_eq!(checkpoint.artifacts.len(), 6);
    assert!(checkpoint.all_artifacts_validated);
    assert!(checkpoint.all_source_roots_bound);
    assert!(!checkpoint.production_hash_selected);
    assert!(!checkpoint.runtime_wiring_allowed);
    assert!(!checkpoint.proof_generation_enabled);
    assert!(checkpoint.groth16_flow_unchanged);
}

#[test]
fn phase8_pre_prover_bundle_checkpoint_json_round_trips() {
    let artifacts = bundle_artifacts();
    let checkpoint = checkpoint_from_artifacts(&artifacts).unwrap();
    let json = serde_json::to_string_pretty(&checkpoint).unwrap();
    let decoded: Phase8PreProverBundleCheckpoint = serde_json::from_str(&json).unwrap();

    assert_eq!(decoded, checkpoint);
    decoded.validate().unwrap();
}

#[test]
fn phase8_pre_prover_bundle_checkpoint_rejects_unbound_source_roots() {
    let artifacts = bundle_artifacts();
    let mut checkpoint = checkpoint_from_artifacts(&artifacts).unwrap();
    checkpoint.all_source_roots_bound = false;

    let errors = checkpoint.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error == "all_source_roots_bound must be true")
    );
}

#[test]
fn phase8_pre_prover_bundle_checkpoint_rejects_runtime_claims() {
    let artifacts = bundle_artifacts();
    let mut checkpoint = checkpoint_from_artifacts(&artifacts).unwrap();
    checkpoint.production_hash_selected = true;
    checkpoint.runtime_wiring_allowed = true;
    checkpoint.proof_generation_enabled = true;

    let errors = checkpoint.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error == "production_hash_selected must be false")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "runtime_wiring_allowed must be false")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "proof_generation_enabled must be false")
    );
}

#[test]
fn phase8_pre_prover_bundle_checkpoint_rejects_mismatched_public_root_candidate() {
    let mut artifacts = bundle_artifacts();
    artifacts
        .source_root_aggregation
        .public_input_root_candidate =
        "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string();

    let errors = checkpoint_from_artifacts(&artifacts).unwrap_err();
    assert!(errors.iter().any(|error| error
        == "public_input_root_digest_candidate must match source_root_aggregation_plan"));
}
