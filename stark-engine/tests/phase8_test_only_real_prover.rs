use stark_engine::{
    ActiveClaimToStarkBridge, WinterfellCompleteWitnessCandidate, WinterfellCompleteWitnessField,
    real_prover,
};

fn complete_candidate() -> WinterfellCompleteWitnessCandidate {
    WinterfellCompleteWitnessCandidate {
        schema_version: WinterfellCompleteWitnessCandidate::SCHEMA_VERSION.to_string(),
        source_schema_version: WinterfellCompleteWitnessCandidate::SOURCE_SCHEMA_VERSION
            .to_string(),
        candidate_status: WinterfellCompleteWitnessCandidate::CANDIDATE_STATUS.to_string(),
        claim_id: "CLAIM-PHASE8-TEST-PROVER".to_string(),
        claim_hash: "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
            .to_string(),
        fields: ActiveClaimToStarkBridge::IMPORTED_STARK_FIELDS
            .iter()
            .enumerate()
            .map(|(index, field)| WinterfellCompleteWitnessField {
                winterfell_field: (*field).to_string(),
                value: (index as u64) + 1,
                value_status: "populated_adapter_ready_fixture".to_string(),
                source_artifact: "winterfell_source_data_fixture".to_string(),
                source_field: (*field).to_string(),
                note: "test-only complete witness field".to_string(),
            })
            .collect(),
        field_count: ActiveClaimToStarkBridge::IMPORTED_STARK_FIELDS.len(),
        all_fields_populated: true,
        winterfell_dependency_imported: false,
        proof_generation_enabled: false,
        notes: vec!["test-only complete witness candidate".to_string()],
    }
}

#[test]
fn test_only_proof_bytes_generate_from_complete_candidate() {
    let candidate = complete_candidate();
    let bytes = real_prover::TestOnlyProofBytes::from_complete_witness_candidate(&candidate)
        .expect("test-only bytes should generate from a valid complete candidate");

    bytes.validate().unwrap();
    assert_eq!(
        bytes.schema_version,
        real_prover::TestOnlyProofBytes::SCHEMA_VERSION
    );
    assert_eq!(
        bytes.byte_status,
        real_prover::TestOnlyProofBytes::BYTE_STATUS
    );
    assert_eq!(bytes.claim_id, candidate.claim_id);
    assert_eq!(bytes.claim_hash, candidate.claim_hash);
    assert_eq!(bytes.transformation_id, real_prover::TRANSFORMATION_ID);
    assert_eq!(bytes.byte_length, 32);
    assert!(!bytes.runtime_wiring_allowed);
    assert!(!bytes.real_proof_generation_allowed);
    assert!(!bytes.accepted_as_implementation_evidence);
}

#[test]
fn test_only_proof_bytes_are_deterministic_for_same_candidate() {
    let candidate = complete_candidate();
    let first =
        real_prover::TestOnlyProofBytes::from_complete_witness_candidate(&candidate).unwrap();
    let second =
        real_prover::TestOnlyProofBytes::from_complete_witness_candidate(&candidate).unwrap();

    assert_eq!(first, second);
    assert_eq!(first.bytes_hex, first.deterministic_digest);
}

#[test]
fn test_only_proof_bytes_change_when_candidate_changes() {
    let candidate = complete_candidate();
    let first =
        real_prover::TestOnlyProofBytes::from_complete_witness_candidate(&candidate).unwrap();

    let mut changed_candidate = complete_candidate();
    changed_candidate.fields[0].value += 1;
    let second =
        real_prover::TestOnlyProofBytes::from_complete_witness_candidate(&changed_candidate)
            .unwrap();

    assert_ne!(first.bytes_hex, second.bytes_hex);
}

#[test]
fn test_only_proof_bytes_reject_runtime_like_flags() {
    let candidate = complete_candidate();
    let mut bytes =
        real_prover::TestOnlyProofBytes::from_complete_witness_candidate(&candidate).unwrap();
    bytes.runtime_wiring_allowed = true;
    bytes.real_proof_generation_allowed = true;
    bytes.accepted_as_implementation_evidence = true;

    let errors = bytes.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error == "runtime_wiring_allowed must be false")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "real_proof_generation_allowed must be false")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "accepted_as_implementation_evidence must be false")
    );
}

#[test]
fn test_only_proof_bytes_reject_invalid_complete_candidate() {
    let mut candidate = complete_candidate();
    candidate.proof_generation_enabled = true;

    let errors =
        real_prover::TestOnlyProofBytes::from_complete_witness_candidate(&candidate).unwrap_err();

    assert!(
        errors
            .iter()
            .any(|error| error.contains("proof_generation_enabled must be false"))
    );
}

fn test_only_proof_bytes() -> real_prover::TestOnlyProofBytes {
    real_prover::TestOnlyProofBytes::from_complete_witness_candidate(&complete_candidate()).unwrap()
}

#[test]
fn real_prover_evidence_record_generates_unsatisfied_contract() {
    let bytes = test_only_proof_bytes();
    let record = real_prover::RealProverEvidenceRecord::from_test_only_proof_bytes(&bytes)
        .expect("evidence record should generate from valid test-only bytes");

    record.validate().unwrap();
    assert_eq!(
        record.schema_version,
        real_prover::RealProverEvidenceRecord::SCHEMA_VERSION
    );
    assert_eq!(
        record.evidence_status,
        real_prover::RealProverEvidenceRecord::EVIDENCE_STATUS
    );
    assert_eq!(record.transformation_id, real_prover::TRANSFORMATION_ID);
    assert_eq!(record.planned_module, real_prover::MODULE_PATH);
    assert_eq!(record.required_evidence, real_prover::REQUIRED_EVIDENCE);
    assert_eq!(record.populated_evidence_count, 0);
    assert_eq!(record.missing_evidence_count, 4);
    assert!(!record.implementation_satisfied);
    assert!(!record.test_only_bytes_are_evidence);
    assert!(!record.runtime_wiring_allowed);
    assert!(!record.real_proof_generation_allowed);
    assert!(!record.accepted_as_implementation_evidence);
}

#[test]
fn real_prover_evidence_record_json_round_trips() {
    let bytes = test_only_proof_bytes();
    let record = real_prover::RealProverEvidenceRecord::from_test_only_proof_bytes(&bytes).unwrap();
    let json = serde_json::to_string_pretty(&record).unwrap();
    let decoded: real_prover::RealProverEvidenceRecord = serde_json::from_str(&json).unwrap();

    assert_eq!(decoded, record);
    decoded.validate().unwrap();
}

#[test]
fn real_prover_evidence_record_rejects_test_only_bytes_as_evidence() {
    let bytes = test_only_proof_bytes();
    let mut record =
        real_prover::RealProverEvidenceRecord::from_test_only_proof_bytes(&bytes).unwrap();
    record.real_proof_bytes_fixture = Some(bytes.bytes_hex);
    record.populated_evidence_count = 1;
    record.missing_evidence_count = 3;
    record.implementation_satisfied = true;
    record.test_only_bytes_are_evidence = true;
    record.runtime_wiring_allowed = true;
    record.real_proof_generation_allowed = true;
    record.accepted_as_implementation_evidence = true;

    let errors = record.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error
                == "real_proof_bytes_fixture must be empty until real evidence exists")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "populated_evidence_count must be 0")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "missing_evidence_count must be 4")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "implementation_satisfied must be false")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "test_only_bytes_are_evidence must be false")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "runtime_wiring_allowed must be false")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "real_proof_generation_allowed must be false")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "accepted_as_implementation_evidence must be false")
    );
}
