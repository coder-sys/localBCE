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

fn real_prover_evidence_record() -> real_prover::RealProverEvidenceRecord {
    real_prover::RealProverEvidenceRecord::from_test_only_proof_bytes(&test_only_proof_bytes())
        .unwrap()
}

#[test]
fn real_prover_attempt_artifact_is_blocked_by_missing_evidence() {
    let record = real_prover_evidence_record();
    let artifact = real_prover::RealProverAttemptArtifact::blocked_from_evidence_record(&record)
        .expect("blocked attempt artifact should generate from valid evidence record");

    artifact.validate().unwrap();
    assert_eq!(
        artifact.schema_version,
        real_prover::RealProverAttemptArtifact::SCHEMA_VERSION
    );
    assert_eq!(
        artifact.source_schema_version,
        real_prover::RealProverEvidenceRecord::SCHEMA_VERSION
    );
    assert_eq!(
        artifact.attempt_status,
        real_prover::RealProverAttemptArtifact::ATTEMPT_STATUS
    );
    assert_eq!(
        artifact.blocker_status,
        real_prover::RealProverAttemptArtifact::BLOCKER_STATUS
    );
    assert_eq!(artifact.missing_evidence, real_prover::REQUIRED_EVIDENCE);
    assert_eq!(artifact.missing_evidence_count, 4);
    assert_eq!(artifact.populated_evidence_count, 0);
    assert!(!artifact.implementation_satisfied);
    assert!(!artifact.attempted_real_proof_generation);
    assert!(!artifact.emitted_real_proof_bytes);
    assert!(!artifact.local_real_proof_verified);
    assert!(!artifact.runtime_wiring_allowed);
    assert!(!artifact.real_proof_generation_allowed);
    assert!(!artifact.accepted_as_implementation_evidence);
}

#[test]
fn real_prover_attempt_artifact_json_round_trips() {
    let artifact = real_prover::RealProverAttemptArtifact::blocked_from_evidence_record(
        &real_prover_evidence_record(),
    )
    .unwrap();
    let json = serde_json::to_string_pretty(&artifact).unwrap();
    let decoded: real_prover::RealProverAttemptArtifact = serde_json::from_str(&json).unwrap();

    assert_eq!(decoded, artifact);
    decoded.validate().unwrap();
}

#[test]
fn real_prover_attempt_artifact_rejects_fake_success() {
    let mut artifact = real_prover::RealProverAttemptArtifact::blocked_from_evidence_record(
        &real_prover_evidence_record(),
    )
    .unwrap();
    artifact.missing_evidence.clear();
    artifact.missing_evidence_count = 0;
    artifact.populated_evidence_count = 4;
    artifact.implementation_satisfied = true;
    artifact.attempted_real_proof_generation = true;
    artifact.emitted_real_proof_bytes = true;
    artifact.local_real_proof_verified = true;
    artifact.runtime_wiring_allowed = true;
    artifact.real_proof_generation_allowed = true;
    artifact.accepted_as_implementation_evidence = true;

    let errors = artifact.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error == "missing_evidence must match the real prover evidence contract")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "missing_evidence_count must be 4")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "populated_evidence_count must be 0")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "implementation_satisfied must be false")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "attempted_real_proof_generation must be false")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "emitted_real_proof_bytes must be false")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "local_real_proof_verified must be false")
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

fn real_prover_attempt_artifact() -> real_prover::RealProverAttemptArtifact {
    real_prover::RealProverAttemptArtifact::blocked_from_evidence_record(
        &real_prover_evidence_record(),
    )
    .unwrap()
}

#[test]
fn real_prover_adapter_invocation_is_default_blocked() {
    let artifact = real_prover_attempt_artifact();
    let invocation = real_prover::RealProverAdapterInvocation::from_attempt_artifact(&artifact)
        .expect("adapter invocation should generate from a valid blocked attempt artifact");

    invocation.validate().unwrap();
    assert_eq!(
        invocation.schema_version,
        real_prover::RealProverAdapterInvocation::SCHEMA_VERSION
    );
    assert_eq!(
        invocation.source_schema_version,
        real_prover::RealProverAttemptArtifact::SCHEMA_VERSION
    );
    assert_eq!(
        invocation.feature_gate,
        real_prover::RealProverAdapterInvocation::FEATURE_GATE
    );
    assert_eq!(
        invocation.feature_enabled,
        real_prover::REAL_PROVER_ADAPTER_FEATURE_ENABLED
    );
    assert_eq!(
        invocation.adapter_status,
        real_prover::RealProverAdapterInvocation::ADAPTER_STATUS_FEATURE_DISABLED
    );
    assert_eq!(
        invocation.blocker_status,
        "real_prover_adapter_feature_disabled"
    );
    assert_eq!(
        invocation.source_attempt_status,
        real_prover::RealProverAttemptArtifact::ATTEMPT_STATUS
    );
    assert!(!invocation.implementation_satisfied);
    assert!(!invocation.attempted_real_proof_generation);
    assert!(!invocation.emitted_real_proof_bytes);
    assert!(!invocation.local_real_proof_verified);
    assert!(!invocation.runtime_wiring_allowed);
    assert!(!invocation.real_proof_generation_allowed);
    assert!(!invocation.accepted_as_implementation_evidence);
}

#[test]
fn real_prover_adapter_invocation_json_round_trips() {
    let invocation = real_prover::RealProverAdapterInvocation::from_attempt_artifact(
        &real_prover_attempt_artifact(),
    )
    .unwrap();
    let json = serde_json::to_string_pretty(&invocation).unwrap();
    let decoded: real_prover::RealProverAdapterInvocation = serde_json::from_str(&json).unwrap();

    assert_eq!(decoded, invocation);
    decoded.validate().unwrap();
}

#[test]
fn real_prover_adapter_invocation_rejects_fake_success() {
    let mut invocation = real_prover::RealProverAdapterInvocation::from_attempt_artifact(
        &real_prover_attempt_artifact(),
    )
    .unwrap();
    invocation.implementation_satisfied = true;
    invocation.attempted_real_proof_generation = true;
    invocation.emitted_real_proof_bytes = true;
    invocation.local_real_proof_verified = true;
    invocation.runtime_wiring_allowed = true;
    invocation.real_proof_generation_allowed = true;
    invocation.accepted_as_implementation_evidence = true;

    let errors = invocation.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error == "implementation_satisfied must be false")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "attempted_real_proof_generation must be false")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "emitted_real_proof_bytes must be false")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "local_real_proof_verified must be false")
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

fn real_prover_adapter_invocation() -> real_prover::RealProverAdapterInvocation {
    real_prover::RealProverAdapterInvocation::from_attempt_artifact(&real_prover_attempt_artifact())
        .unwrap()
}

#[test]
fn real_prover_code_path_evidence_validates_planned_source_path_only() {
    let evidence = real_prover::RealProverCodePathEvidence::from_adapter_invocation(
        &real_prover_adapter_invocation(),
    )
    .expect("code path evidence should generate from a valid adapter invocation");

    evidence.validate().unwrap();
    assert_eq!(
        evidence.schema_version,
        real_prover::RealProverCodePathEvidence::SCHEMA_VERSION
    );
    assert_eq!(
        evidence.source_schema_version,
        real_prover::RealProverAdapterInvocation::SCHEMA_VERSION
    );
    assert_eq!(
        evidence.evidence_slot,
        real_prover::RealProverCodePathEvidence::EVIDENCE_SLOT
    );
    assert_eq!(
        evidence.evidence_status,
        real_prover::RealProverCodePathEvidence::EVIDENCE_STATUS
    );
    assert_eq!(evidence.candidate_code_path, real_prover::MODULE_PATH);
    assert_eq!(evidence.expected_code_path, real_prover::MODULE_PATH);
    assert!(evidence.path_matches_expected);
    assert_eq!(
        evidence.source_module_status,
        real_prover::IMPLEMENTATION_STATUS
    );
    assert!(!evidence.implementation_satisfied);
    assert!(!evidence.accepted_as_complete_evidence);
    assert!(!evidence.runtime_wiring_allowed);
    assert!(!evidence.real_proof_generation_allowed);
}

#[test]
fn real_prover_code_path_evidence_json_round_trips() {
    let evidence = real_prover::RealProverCodePathEvidence::from_adapter_invocation(
        &real_prover_adapter_invocation(),
    )
    .unwrap();
    let json = serde_json::to_string_pretty(&evidence).unwrap();
    let decoded: real_prover::RealProverCodePathEvidence = serde_json::from_str(&json).unwrap();

    assert_eq!(decoded, evidence);
    decoded.validate().unwrap();
}

#[test]
fn real_prover_code_path_evidence_rejects_wrong_path_or_fake_completion() {
    let mut evidence = real_prover::RealProverCodePathEvidence::from_adapter_invocation(
        &real_prover_adapter_invocation(),
    )
    .unwrap();
    evidence.candidate_code_path = "stark-engine/src/not_real_prover.rs".to_string();
    evidence.path_matches_expected = false;
    evidence.source_module_status = "implemented".to_string();
    evidence.implementation_satisfied = true;
    evidence.accepted_as_complete_evidence = true;
    evidence.runtime_wiring_allowed = true;
    evidence.real_proof_generation_allowed = true;

    let errors = evidence.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error == "candidate_code_path must be stark-engine/src/real_prover.rs")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "path_matches_expected must be true")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "source_module_status must be scaffold_only_not_implemented")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "implementation_satisfied must be false")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "accepted_as_complete_evidence must be false")
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
}

fn real_prover_code_path_evidence() -> real_prover::RealProverCodePathEvidence {
    real_prover::RealProverCodePathEvidence::from_adapter_invocation(
        &real_prover_adapter_invocation(),
    )
    .unwrap()
}

#[test]
fn real_prover_unit_tests_evidence_declares_focused_boundary_tests_only() {
    let evidence = real_prover::RealProverUnitTestsEvidence::from_code_path_evidence(
        &real_prover_code_path_evidence(),
    )
    .expect("unit-test evidence should generate from valid code-path evidence");

    evidence.validate().unwrap();
    assert_eq!(
        evidence.schema_version,
        real_prover::RealProverUnitTestsEvidence::SCHEMA_VERSION
    );
    assert_eq!(
        evidence.source_schema_version,
        real_prover::RealProverCodePathEvidence::SCHEMA_VERSION
    );
    assert_eq!(
        evidence.evidence_slot,
        real_prover::RealProverUnitTestsEvidence::EVIDENCE_SLOT
    );
    assert_eq!(
        evidence.evidence_status,
        real_prover::RealProverUnitTestsEvidence::EVIDENCE_STATUS
    );
    assert_eq!(
        evidence.candidate_test_path,
        real_prover::REAL_PROVER_UNIT_TEST_PATH
    );
    assert_eq!(
        evidence.expected_test_path,
        real_prover::REAL_PROVER_UNIT_TEST_PATH
    );
    assert!(evidence.path_matches_expected);
    assert_eq!(
        evidence.required_tests,
        real_prover::REQUIRED_REAL_PROVER_UNIT_TESTS
    );
    assert_eq!(evidence.required_test_count, 3);
    assert_eq!(
        evidence.coverage_status,
        real_prover::RealProverUnitTestsEvidence::COVERAGE_STATUS
    );
    assert!(!evidence.implementation_satisfied);
    assert!(!evidence.accepted_as_complete_evidence);
    assert!(!evidence.runtime_wiring_allowed);
    assert!(!evidence.real_proof_generation_allowed);
}

#[test]
fn real_prover_unit_tests_evidence_json_round_trips() {
    let evidence = real_prover::RealProverUnitTestsEvidence::from_code_path_evidence(
        &real_prover_code_path_evidence(),
    )
    .unwrap();
    let json = serde_json::to_string_pretty(&evidence).unwrap();
    let decoded: real_prover::RealProverUnitTestsEvidence = serde_json::from_str(&json).unwrap();

    assert_eq!(decoded, evidence);
    decoded.validate().unwrap();
}

#[test]
fn real_prover_unit_tests_evidence_rejects_missing_tests_or_fake_completion() {
    let mut evidence = real_prover::RealProverUnitTestsEvidence::from_code_path_evidence(
        &real_prover_code_path_evidence(),
    )
    .unwrap();
    evidence.candidate_test_path = "stark-engine/tests/wrong.rs".to_string();
    evidence.path_matches_expected = false;
    evidence.required_tests.pop();
    evidence.required_test_count = 2;
    evidence.coverage_status = "complete".to_string();
    evidence.implementation_satisfied = true;
    evidence.accepted_as_complete_evidence = true;
    evidence.runtime_wiring_allowed = true;
    evidence.real_proof_generation_allowed = true;

    let errors = evidence.validate().unwrap_err();
    assert!(errors.iter().any(|error| error
        == "candidate_test_path must be stark-engine/tests/phase8_test_only_real_prover.rs"));
    assert!(
        errors
            .iter()
            .any(|error| error == "path_matches_expected must be true")
    );
    assert!(
        errors.iter().any(
            |error| error == "required_tests must match the real prover boundary test contract"
        )
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "required_test_count must be 3")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "coverage_status must be focused_boundary_tests_declared")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "implementation_satisfied must be false")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "accepted_as_complete_evidence must be false")
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
}

fn real_prover_unit_tests_evidence() -> real_prover::RealProverUnitTestsEvidence {
    real_prover::RealProverUnitTestsEvidence::from_code_path_evidence(
        &real_prover_code_path_evidence(),
    )
    .unwrap()
}

#[test]
fn local_real_proof_validation_log_evidence_declares_required_future_log_only() {
    let evidence = real_prover::LocalRealProofValidationLogEvidence::from_unit_tests_evidence(
        &real_prover_unit_tests_evidence(),
    )
    .expect("validation-log evidence should generate from valid unit-tests evidence");

    evidence.validate().unwrap();
    assert_eq!(
        evidence.schema_version,
        real_prover::LocalRealProofValidationLogEvidence::SCHEMA_VERSION
    );
    assert_eq!(
        evidence.source_schema_version,
        real_prover::RealProverUnitTestsEvidence::SCHEMA_VERSION
    );
    assert_eq!(
        evidence.evidence_slot,
        real_prover::LocalRealProofValidationLogEvidence::EVIDENCE_SLOT
    );
    assert_eq!(
        evidence.evidence_status,
        real_prover::LocalRealProofValidationLogEvidence::EVIDENCE_STATUS
    );
    assert_eq!(
        evidence.candidate_log_path,
        real_prover::LOCAL_REAL_PROOF_VALIDATION_LOG_PATH
    );
    assert_eq!(
        evidence.expected_log_path,
        real_prover::LOCAL_REAL_PROOF_VALIDATION_LOG_PATH
    );
    assert!(evidence.path_matches_expected);
    assert_eq!(
        evidence.validation_log_status,
        real_prover::LocalRealProofValidationLogEvidence::VALIDATION_LOG_STATUS
    );
    assert!(!evidence.local_real_proof_verified);
    assert_eq!(
        evidence.required_log_fields,
        real_prover::LocalRealProofValidationLogEvidence::REQUIRED_LOG_FIELDS
    );
    assert_eq!(evidence.required_log_field_count, 5);
    assert!(!evidence.implementation_satisfied);
    assert!(!evidence.accepted_as_complete_evidence);
    assert!(!evidence.runtime_wiring_allowed);
    assert!(!evidence.real_proof_generation_allowed);
}

#[test]
fn local_real_proof_validation_log_evidence_json_round_trips() {
    let evidence = real_prover::LocalRealProofValidationLogEvidence::from_unit_tests_evidence(
        &real_prover_unit_tests_evidence(),
    )
    .unwrap();
    let json = serde_json::to_string_pretty(&evidence).unwrap();
    let decoded: real_prover::LocalRealProofValidationLogEvidence =
        serde_json::from_str(&json).unwrap();

    assert_eq!(decoded, evidence);
    decoded.validate().unwrap();
}

#[test]
fn local_real_proof_validation_log_evidence_rejects_fake_verification() {
    let mut evidence = real_prover::LocalRealProofValidationLogEvidence::from_unit_tests_evidence(
        &real_prover_unit_tests_evidence(),
    )
    .unwrap();
    evidence.candidate_log_path = "stark-engine/reports/fake.log".to_string();
    evidence.path_matches_expected = false;
    evidence.validation_log_status = "verified".to_string();
    evidence.local_real_proof_verified = true;
    evidence.required_log_fields.pop();
    evidence.required_log_field_count = 4;
    evidence.implementation_satisfied = true;
    evidence.accepted_as_complete_evidence = true;
    evidence.runtime_wiring_allowed = true;
    evidence.real_proof_generation_allowed = true;

    let errors = evidence.validate().unwrap_err();
    assert!(errors.iter().any(|error| error
        == "candidate_log_path must be stark-engine/reports/local_real_proof_validation.log"));
    assert!(
        errors
            .iter()
            .any(|error| error == "path_matches_expected must be true")
    );
    assert!(
        errors
            .iter()
            .any(|error| error
                == "validation_log_status must be real_proof_validation_log_missing")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "local_real_proof_verified must be false")
    );
    assert!(errors.iter().any(|error| error
        == "required_log_fields must match the local real proof validation log contract"));
    assert!(
        errors
            .iter()
            .any(|error| error == "required_log_field_count must be 5")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "implementation_satisfied must be false")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "accepted_as_complete_evidence must be false")
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
}
