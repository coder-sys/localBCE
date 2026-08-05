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
fn test_only_real_proof_bytes_fixture_has_future_fixture_shape() {
    let bytes = test_only_proof_bytes();
    let fixture = real_prover::TestOnlyRealProofBytesFixture::from_test_only_proof_bytes(&bytes)
        .expect("test-only fixture should generate from valid test-only proof bytes");

    fixture.validate().unwrap();
    assert_eq!(
        fixture.schema_version,
        real_prover::TestOnlyRealProofBytesFixture::SCHEMA_VERSION
    );
    assert_eq!(
        fixture.source_schema_version,
        real_prover::TestOnlyProofBytes::SCHEMA_VERSION
    );
    assert_eq!(
        fixture.fixture_status,
        real_prover::TestOnlyRealProofBytesFixture::FIXTURE_STATUS
    );
    assert_eq!(
        fixture.fixture_path,
        real_prover::REAL_PROOF_BYTES_FIXTURE_PATH
    );
    assert_eq!(
        fixture.expected_fixture_path,
        real_prover::REAL_PROOF_BYTES_FIXTURE_PATH
    );
    assert!(fixture.path_matches_expected);
    assert_eq!(fixture.claim_id, bytes.claim_id);
    assert_eq!(fixture.claim_hash, bytes.claim_hash);
    assert_eq!(fixture.proof_bytes_digest, bytes.deterministic_digest);
    assert_eq!(fixture.proof_bytes_hex, bytes.bytes_hex);
    assert_eq!(fixture.proof_bytes_length, bytes.byte_length);
    assert!(fixture.proof_bytes_present);
    assert!(fixture.test_only_fixture);
    assert!(!fixture.local_real_proof_verified);
    assert!(!fixture.accepted_as_complete_evidence);
    assert!(!fixture.implementation_satisfied);
    assert!(!fixture.runtime_wiring_allowed);
    assert!(!fixture.real_proof_generation_allowed);
}

#[test]
fn test_only_real_proof_bytes_fixture_json_round_trips() {
    let fixture = real_prover::TestOnlyRealProofBytesFixture::from_test_only_proof_bytes(
        &test_only_proof_bytes(),
    )
    .unwrap();
    let json = serde_json::to_string_pretty(&fixture).unwrap();
    let decoded: real_prover::TestOnlyRealProofBytesFixture = serde_json::from_str(&json).unwrap();

    assert_eq!(decoded, fixture);
    decoded.validate().unwrap();
}

#[test]
fn test_only_real_proof_bytes_fixture_rejects_real_evidence_flags() {
    let mut fixture = real_prover::TestOnlyRealProofBytesFixture::from_test_only_proof_bytes(
        &test_only_proof_bytes(),
    )
    .unwrap();
    fixture.local_real_proof_verified = true;
    fixture.test_only_fixture = false;
    fixture.accepted_as_complete_evidence = true;
    fixture.implementation_satisfied = true;
    fixture.runtime_wiring_allowed = true;
    fixture.real_proof_generation_allowed = true;

    let errors = fixture.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error == "local_real_proof_verified must be false")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "test_only_fixture must be true")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "accepted_as_complete_evidence must be false")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "implementation_satisfied must be false")
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

fn test_only_real_proof_bytes_fixture() -> real_prover::TestOnlyRealProofBytesFixture {
    real_prover::TestOnlyRealProofBytesFixture::from_test_only_proof_bytes(&test_only_proof_bytes())
        .unwrap()
}

#[test]
fn test_only_local_real_proof_validation_log_fixture_has_future_log_shape() {
    let fixture = test_only_real_proof_bytes_fixture();
    let log_fixture =
        real_prover::TestOnlyLocalRealProofValidationLogFixture::from_test_only_fixture(&fixture)
            .expect("test-only validation log fixture should generate from fixture-shaped bytes");

    log_fixture.validate().unwrap();
    assert_eq!(
        log_fixture.schema_version,
        real_prover::TestOnlyLocalRealProofValidationLogFixture::SCHEMA_VERSION
    );
    assert_eq!(
        log_fixture.source_schema_version,
        real_prover::TestOnlyRealProofBytesFixture::SCHEMA_VERSION
    );
    assert_eq!(
        log_fixture.log_status,
        real_prover::TestOnlyLocalRealProofValidationLogFixture::LOG_STATUS
    );
    assert_eq!(
        log_fixture.log_path,
        real_prover::LOCAL_REAL_PROOF_VALIDATION_LOG_PATH
    );
    assert_eq!(
        log_fixture.expected_log_path,
        real_prover::LOCAL_REAL_PROOF_VALIDATION_LOG_PATH
    );
    assert!(log_fixture.path_matches_expected);
    assert_eq!(
        log_fixture.prover_name,
        real_prover::TestOnlyLocalRealProofValidationLogFixture::PROVER_NAME
    );
    assert_eq!(
        log_fixture.proof_artifact_schema_version,
        real_prover::TestOnlyLocalRealProofValidationLogFixture::PROOF_ARTIFACT_SCHEMA_VERSION
    );
    assert_eq!(log_fixture.proof_bytes_digest, fixture.proof_bytes_digest);
    assert_eq!(
        log_fixture.local_verification_status,
        real_prover::TestOnlyLocalRealProofValidationLogFixture::LOCAL_VERIFICATION_STATUS
    );
    assert_eq!(
        log_fixture.verification_timestamp,
        real_prover::TestOnlyLocalRealProofValidationLogFixture::VERIFICATION_TIMESTAMP
    );
    assert_eq!(log_fixture.claim_id, fixture.claim_id);
    assert_eq!(log_fixture.claim_hash, fixture.claim_hash);
    assert!(log_fixture.test_only_fixture);
    assert!(!log_fixture.local_real_proof_verified);
    assert!(!log_fixture.accepted_as_complete_evidence);
    assert!(!log_fixture.implementation_satisfied);
    assert!(!log_fixture.runtime_wiring_allowed);
    assert!(!log_fixture.real_proof_generation_allowed);
}

#[test]
fn test_only_local_real_proof_validation_log_fixture_json_round_trips() {
    let log_fixture =
        real_prover::TestOnlyLocalRealProofValidationLogFixture::from_test_only_fixture(
            &test_only_real_proof_bytes_fixture(),
        )
        .unwrap();
    let json = serde_json::to_string_pretty(&log_fixture).unwrap();
    let decoded: real_prover::TestOnlyLocalRealProofValidationLogFixture =
        serde_json::from_str(&json).unwrap();

    assert_eq!(decoded, log_fixture);
    decoded.validate().unwrap();
}

#[test]
fn test_only_local_real_proof_validation_log_fixture_rejects_real_verification_flags() {
    let mut log_fixture =
        real_prover::TestOnlyLocalRealProofValidationLogFixture::from_test_only_fixture(
            &test_only_real_proof_bytes_fixture(),
        )
        .unwrap();
    log_fixture.test_only_fixture = false;
    log_fixture.local_real_proof_verified = true;
    log_fixture.accepted_as_complete_evidence = true;
    log_fixture.implementation_satisfied = true;
    log_fixture.runtime_wiring_allowed = true;
    log_fixture.real_proof_generation_allowed = true;

    let errors = log_fixture.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error == "test_only_fixture must be true")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "local_real_proof_verified must be false")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "accepted_as_complete_evidence must be false")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "implementation_satisfied must be false")
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

fn test_only_local_real_proof_validation_log_fixture()
-> real_prover::TestOnlyLocalRealProofValidationLogFixture {
    real_prover::TestOnlyLocalRealProofValidationLogFixture::from_test_only_fixture(
        &test_only_real_proof_bytes_fixture(),
    )
    .unwrap()
}

#[test]
fn test_only_evidence_satisfaction_rehearsal_report_keeps_real_evidence_blocked() {
    let proof_fixture = test_only_real_proof_bytes_fixture();
    let validation_log_fixture = test_only_local_real_proof_validation_log_fixture();
    let report = real_prover::TestOnlyEvidenceSatisfactionRehearsalReport::from_test_only_fixtures(
        &proof_fixture,
        &validation_log_fixture,
    )
    .expect("rehearsal report should generate from matching test-only fixtures");

    report.validate().unwrap();
    assert_eq!(
        report.schema_version,
        real_prover::TestOnlyEvidenceSatisfactionRehearsalReport::SCHEMA_VERSION
    );
    assert_eq!(
        report.rehearsal_status,
        real_prover::TestOnlyEvidenceSatisfactionRehearsalReport::REHEARSAL_STATUS
    );
    assert!(report.proof_bytes_fixture_shape_present);
    assert!(report.validation_log_shape_present);
    assert!(report.proof_bytes_digest_matches_log);
    assert!(report.claim_hash_matches);
    assert!(report.test_only_fixtures);
    assert!(!report.real_proof_verified);
    assert!(!report.real_evidence_slots_satisfied);
    assert!(report.satisfied_real_evidence_slots.is_empty());
    assert_eq!(report.satisfied_real_evidence_slot_count, 0);
    assert_eq!(
        report.blocked_real_evidence_slots,
        real_prover::REQUIRED_EVIDENCE
    );
    assert_eq!(report.blocked_real_evidence_slot_count, 4);
    assert!(!report.runtime_cutover_allowed);
    assert!(!report.real_proof_generation_allowed);
    assert!(!report.accepted_as_complete_evidence);
}

#[test]
fn test_only_evidence_satisfaction_rehearsal_report_json_round_trips() {
    let report = real_prover::TestOnlyEvidenceSatisfactionRehearsalReport::from_test_only_fixtures(
        &test_only_real_proof_bytes_fixture(),
        &test_only_local_real_proof_validation_log_fixture(),
    )
    .unwrap();
    let json = serde_json::to_string_pretty(&report).unwrap();
    let decoded: real_prover::TestOnlyEvidenceSatisfactionRehearsalReport =
        serde_json::from_str(&json).unwrap();

    assert_eq!(decoded, report);
    decoded.validate().unwrap();
}

#[test]
fn test_only_evidence_satisfaction_rehearsal_report_rejects_fake_completion() {
    let mut report =
        real_prover::TestOnlyEvidenceSatisfactionRehearsalReport::from_test_only_fixtures(
            &test_only_real_proof_bytes_fixture(),
            &test_only_local_real_proof_validation_log_fixture(),
        )
        .unwrap();
    report.real_proof_verified = true;
    report.real_evidence_slots_satisfied = true;
    report.satisfied_real_evidence_slots = real_prover::REQUIRED_EVIDENCE
        .iter()
        .map(|slot| (*slot).to_string())
        .collect();
    report.satisfied_real_evidence_slot_count = 4;
    report.blocked_real_evidence_slots.clear();
    report.blocked_real_evidence_slot_count = 0;
    report.runtime_cutover_allowed = true;
    report.real_proof_generation_allowed = true;
    report.accepted_as_complete_evidence = true;

    let errors = report.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error == "real_proof_verified must be false")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "real_evidence_slots_satisfied must be false")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "satisfied_real_evidence_slots must be empty")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "satisfied_real_evidence_slot_count must be 0")
    );
    assert!(
        errors.iter().any(|error| error
            == "blocked_real_evidence_slots must match the real prover evidence contract")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "blocked_real_evidence_slot_count must be 4")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "runtime_cutover_allowed must be false")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "real_proof_generation_allowed must be false")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "accepted_as_complete_evidence must be false")
    );
}

fn test_only_evidence_satisfaction_rehearsal_report()
-> real_prover::TestOnlyEvidenceSatisfactionRehearsalReport {
    real_prover::TestOnlyEvidenceSatisfactionRehearsalReport::from_test_only_fixtures(
        &test_only_real_proof_bytes_fixture(),
        &test_only_local_real_proof_validation_log_fixture(),
    )
    .unwrap()
}

#[test]
fn real_proof_bytes_fixture_promotion_plan_defines_future_gate_only() {
    let plan = real_prover::RealProofBytesFixturePromotionPlan::from_rehearsal_report(
        &test_only_evidence_satisfaction_rehearsal_report(),
    )
    .expect("promotion plan should generate from a valid rehearsal report");

    plan.validate().unwrap();
    assert_eq!(
        plan.schema_version,
        real_prover::RealProofBytesFixturePromotionPlan::SCHEMA_VERSION
    );
    assert_eq!(
        plan.source_schema_version,
        real_prover::TestOnlyEvidenceSatisfactionRehearsalReport::SCHEMA_VERSION
    );
    assert_eq!(
        plan.promotion_status,
        real_prover::RealProofBytesFixturePromotionPlan::PROMOTION_STATUS
    );
    assert_eq!(
        plan.target_evidence_slot,
        real_prover::RealProofBytesFixturePromotionPlan::TARGET_EVIDENCE_SLOT
    );
    assert_eq!(
        plan.target_fixture_path,
        real_prover::REAL_PROOF_BYTES_FIXTURE_PATH
    );
    assert_eq!(
        plan.required_conditions,
        real_prover::RealProofBytesFixturePromotionPlan::REQUIRED_CONDITIONS
    );
    assert_eq!(plan.required_condition_count, 5);
    assert!(plan.current_fixture_shape_present);
    assert!(plan.current_validation_log_shape_present);
    assert!(plan.current_digest_matches_log);
    assert!(plan.required_proof_bytes_present);
    assert!(plan.required_proof_bytes_digest_present);
    assert!(plan.required_test_only_bytes_rejected);
    assert!(plan.required_local_real_proof_verified);
    assert!(plan.required_accepted_as_complete_evidence);
    assert!(!plan.slot_promotion_ready);
    assert!(!plan.runtime_cutover_allowed);
    assert!(!plan.real_proof_generation_allowed);
}

#[test]
fn real_proof_bytes_fixture_promotion_plan_json_round_trips() {
    let plan = real_prover::RealProofBytesFixturePromotionPlan::from_rehearsal_report(
        &test_only_evidence_satisfaction_rehearsal_report(),
    )
    .unwrap();
    let json = serde_json::to_string_pretty(&plan).unwrap();
    let decoded: real_prover::RealProofBytesFixturePromotionPlan =
        serde_json::from_str(&json).unwrap();

    assert_eq!(decoded, plan);
    decoded.validate().unwrap();
}

#[test]
fn real_proof_bytes_fixture_promotion_plan_rejects_runtime_cutover() {
    let mut plan = real_prover::RealProofBytesFixturePromotionPlan::from_rehearsal_report(
        &test_only_evidence_satisfaction_rehearsal_report(),
    )
    .unwrap();
    plan.slot_promotion_ready = true;
    plan.runtime_cutover_allowed = true;
    plan.real_proof_generation_allowed = true;

    let errors = plan.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error == "slot_promotion_ready must be false")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "runtime_cutover_allowed must be false")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "real_proof_generation_allowed must be false")
    );
}

#[test]
fn local_real_proof_validation_log_promotion_plan_defines_future_gate_only() {
    let plan = real_prover::LocalRealProofValidationLogPromotionPlan::from_rehearsal_report(
        &test_only_evidence_satisfaction_rehearsal_report(),
    )
    .expect("promotion plan should generate from a valid rehearsal report");

    plan.validate().unwrap();
    assert_eq!(
        plan.schema_version,
        real_prover::LocalRealProofValidationLogPromotionPlan::SCHEMA_VERSION
    );
    assert_eq!(
        plan.source_schema_version,
        real_prover::TestOnlyEvidenceSatisfactionRehearsalReport::SCHEMA_VERSION
    );
    assert_eq!(
        plan.promotion_status,
        real_prover::LocalRealProofValidationLogPromotionPlan::PROMOTION_STATUS
    );
    assert_eq!(
        plan.target_evidence_slot,
        real_prover::LocalRealProofValidationLogPromotionPlan::TARGET_EVIDENCE_SLOT
    );
    assert_eq!(
        plan.target_log_path,
        real_prover::LOCAL_REAL_PROOF_VALIDATION_LOG_PATH
    );
    assert_eq!(
        plan.required_conditions,
        real_prover::LocalRealProofValidationLogPromotionPlan::REQUIRED_CONDITIONS
    );
    assert_eq!(plan.required_condition_count, 6);
    assert!(plan.current_validation_log_shape_present);
    assert!(plan.current_digest_matches_fixture);
    assert!(plan.current_claim_hash_matches_fixture);
    assert!(plan.required_real_prover_name);
    assert!(plan.required_real_proof_artifact_schema_version);
    assert!(plan.required_proof_bytes_digest);
    assert!(plan.required_local_verification_status_verified);
    assert!(plan.required_verification_timestamp);
    assert!(plan.required_matching_claim_hash);
    assert!(!plan.slot_promotion_ready);
    assert!(!plan.runtime_cutover_allowed);
    assert!(!plan.real_proof_generation_allowed);
}

#[test]
fn local_real_proof_validation_log_promotion_plan_json_round_trips() {
    let plan = real_prover::LocalRealProofValidationLogPromotionPlan::from_rehearsal_report(
        &test_only_evidence_satisfaction_rehearsal_report(),
    )
    .unwrap();
    let json = serde_json::to_string_pretty(&plan).unwrap();
    let decoded: real_prover::LocalRealProofValidationLogPromotionPlan =
        serde_json::from_str(&json).unwrap();

    assert_eq!(decoded, plan);
    decoded.validate().unwrap();
}

#[test]
fn local_real_proof_validation_log_promotion_plan_rejects_runtime_cutover() {
    let mut plan = real_prover::LocalRealProofValidationLogPromotionPlan::from_rehearsal_report(
        &test_only_evidence_satisfaction_rehearsal_report(),
    )
    .unwrap();
    plan.slot_promotion_ready = true;
    plan.runtime_cutover_allowed = true;
    plan.real_proof_generation_allowed = true;

    let errors = plan.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error == "slot_promotion_ready must be false")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "runtime_cutover_allowed must be false")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "real_proof_generation_allowed must be false")
    );
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
    let expected_adapter_status = if real_prover::REAL_PROVER_ADAPTER_FEATURE_ENABLED {
        real_prover::RealProverAdapterInvocation::ADAPTER_STATUS_EVIDENCE_MISSING
    } else {
        real_prover::RealProverAdapterInvocation::ADAPTER_STATUS_FEATURE_DISABLED
    };
    let expected_blocker_status = if real_prover::REAL_PROVER_ADAPTER_FEATURE_ENABLED {
        real_prover::RealProverAttemptArtifact::BLOCKER_STATUS
    } else {
        "real_prover_adapter_feature_disabled"
    };
    assert_eq!(invocation.adapter_status, expected_adapter_status);
    assert_eq!(invocation.blocker_status, expected_blocker_status);
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

fn local_real_proof_validation_log_evidence() -> real_prover::LocalRealProofValidationLogEvidence {
    real_prover::LocalRealProofValidationLogEvidence::from_unit_tests_evidence(
        &real_prover_unit_tests_evidence(),
    )
    .unwrap()
}

#[test]
fn real_proof_bytes_fixture_evidence_declares_missing_future_fixture_only() {
    let evidence = real_prover::RealProofBytesFixtureEvidence::from_validation_log_evidence(
        &local_real_proof_validation_log_evidence(),
    )
    .expect("fixture evidence should generate from valid validation-log evidence");

    evidence.validate().unwrap();
    assert_eq!(
        evidence.schema_version,
        real_prover::RealProofBytesFixtureEvidence::SCHEMA_VERSION
    );
    assert_eq!(
        evidence.source_schema_version,
        real_prover::LocalRealProofValidationLogEvidence::SCHEMA_VERSION
    );
    assert_eq!(
        evidence.evidence_slot,
        real_prover::RealProofBytesFixtureEvidence::EVIDENCE_SLOT
    );
    assert_eq!(
        evidence.evidence_status,
        real_prover::RealProofBytesFixtureEvidence::EVIDENCE_STATUS
    );
    assert_eq!(
        evidence.candidate_fixture_path,
        real_prover::REAL_PROOF_BYTES_FIXTURE_PATH
    );
    assert_eq!(
        evidence.expected_fixture_path,
        real_prover::REAL_PROOF_BYTES_FIXTURE_PATH
    );
    assert!(evidence.path_matches_expected);
    assert_eq!(
        evidence.fixture_status,
        real_prover::RealProofBytesFixtureEvidence::FIXTURE_STATUS
    );
    assert!(!evidence.proof_bytes_present);
    assert!(!evidence.proof_bytes_digest_present);
    assert!(evidence.test_only_bytes_rejected);
    assert!(!evidence.local_real_proof_verified);
    assert_eq!(
        evidence.required_fixture_fields,
        real_prover::RealProofBytesFixtureEvidence::REQUIRED_FIXTURE_FIELDS
    );
    assert_eq!(evidence.required_fixture_field_count, 5);
    assert!(!evidence.implementation_satisfied);
    assert!(!evidence.accepted_as_complete_evidence);
    assert!(!evidence.runtime_wiring_allowed);
    assert!(!evidence.real_proof_generation_allowed);
}

#[test]
fn real_proof_bytes_fixture_evidence_json_round_trips() {
    let evidence = real_prover::RealProofBytesFixtureEvidence::from_validation_log_evidence(
        &local_real_proof_validation_log_evidence(),
    )
    .unwrap();
    let json = serde_json::to_string_pretty(&evidence).unwrap();
    let decoded: real_prover::RealProofBytesFixtureEvidence = serde_json::from_str(&json).unwrap();

    assert_eq!(decoded, evidence);
    decoded.validate().unwrap();
}

#[test]
fn real_proof_bytes_fixture_evidence_rejects_fake_fixture_completion() {
    let mut evidence = real_prover::RealProofBytesFixtureEvidence::from_validation_log_evidence(
        &local_real_proof_validation_log_evidence(),
    )
    .unwrap();
    evidence.candidate_fixture_path = "stark-engine/fixtures/test_only.bin".to_string();
    evidence.path_matches_expected = false;
    evidence.fixture_status = "fixture_present".to_string();
    evidence.proof_bytes_present = true;
    evidence.proof_bytes_digest_present = true;
    evidence.test_only_bytes_rejected = false;
    evidence.local_real_proof_verified = true;
    evidence.required_fixture_fields.pop();
    evidence.required_fixture_field_count = 4;
    evidence.implementation_satisfied = true;
    evidence.accepted_as_complete_evidence = true;
    evidence.runtime_wiring_allowed = true;
    evidence.real_proof_generation_allowed = true;

    let errors = evidence.validate().unwrap_err();
    assert!(errors.iter().any(|error| error
        == "candidate_fixture_path must be stark-engine/fixtures/real_proof_bytes_fixture.bin"));
    assert!(
        errors
            .iter()
            .any(|error| error == "path_matches_expected must be true")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "fixture_status must be real_proof_bytes_fixture_missing")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "proof_bytes_present must be false")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "proof_bytes_digest_present must be false")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "test_only_bytes_rejected must be true")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "local_real_proof_verified must be false")
    );
    assert!(
        errors.iter().any(|error| error
            == "required_fixture_fields must match the real proof bytes fixture contract")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "required_fixture_field_count must be 5")
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

fn real_proof_bytes_fixture_evidence() -> real_prover::RealProofBytesFixtureEvidence {
    real_prover::RealProofBytesFixtureEvidence::from_validation_log_evidence(
        &local_real_proof_validation_log_evidence(),
    )
    .unwrap()
}

fn real_proof_bytes_fixture_promotion_plan() -> real_prover::RealProofBytesFixturePromotionPlan {
    real_prover::RealProofBytesFixturePromotionPlan::from_rehearsal_report(
        &test_only_evidence_satisfaction_rehearsal_report(),
    )
    .unwrap()
}

fn local_real_proof_validation_log_promotion_plan()
-> real_prover::LocalRealProofValidationLogPromotionPlan {
    real_prover::LocalRealProofValidationLogPromotionPlan::from_rehearsal_report(
        &test_only_evidence_satisfaction_rehearsal_report(),
    )
    .unwrap()
}

fn real_prover_evidence_summary() -> real_prover::RealProverEvidenceSummary {
    real_prover::RealProverEvidenceSummary::from_evidence_slots(
        &real_prover_code_path_evidence(),
        &real_prover_unit_tests_evidence(),
        &local_real_proof_validation_log_evidence(),
        &real_proof_bytes_fixture_evidence(),
    )
    .unwrap()
}

#[test]
fn real_prover_evidence_summary_reports_all_slots_declared_zero_satisfied() {
    let summary = real_prover::RealProverEvidenceSummary::from_evidence_slots(
        &real_prover_code_path_evidence(),
        &real_prover_unit_tests_evidence(),
        &local_real_proof_validation_log_evidence(),
        &real_proof_bytes_fixture_evidence(),
    )
    .expect("summary should generate from valid slot evidence");

    summary.validate().unwrap();
    assert_eq!(
        summary.schema_version,
        real_prover::RealProverEvidenceSummary::SCHEMA_VERSION
    );
    assert_eq!(
        summary.summary_status,
        real_prover::RealProverEvidenceSummary::SUMMARY_STATUS
    );
    assert_eq!(summary.declared_slots, real_prover::REQUIRED_EVIDENCE);
    assert_eq!(summary.declared_slot_count, 4);
    assert!(summary.satisfied_slots.is_empty());
    assert_eq!(summary.satisfied_slot_count, 0);
    assert_eq!(
        summary.missing_or_unsatisfied_slots,
        real_prover::REQUIRED_EVIDENCE
    );
    assert_eq!(summary.missing_or_unsatisfied_slot_count, 4);
    assert_eq!(
        summary.blockers,
        real_prover::RealProverEvidenceSummary::BLOCKERS
    );
    assert_eq!(summary.blocker_count, 4);
    assert!(summary.all_slots_declared);
    assert!(!summary.all_slots_satisfied);
    assert!(!summary.implementation_satisfied);
    assert!(!summary.runtime_cutover_allowed);
    assert!(!summary.real_proof_generation_allowed);
    assert!(!summary.real_proof_bytes_fixture_present);
    assert!(!summary.local_real_proof_verified);
    assert!(summary.test_only_bytes_rejected);
}

#[test]
fn real_prover_evidence_summary_json_round_trips() {
    let summary = real_prover::RealProverEvidenceSummary::from_evidence_slots(
        &real_prover_code_path_evidence(),
        &real_prover_unit_tests_evidence(),
        &local_real_proof_validation_log_evidence(),
        &real_proof_bytes_fixture_evidence(),
    )
    .unwrap();
    let json = serde_json::to_string_pretty(&summary).unwrap();
    let decoded: real_prover::RealProverEvidenceSummary = serde_json::from_str(&json).unwrap();

    assert_eq!(decoded, summary);
    decoded.validate().unwrap();
}

#[test]
fn real_prover_evidence_summary_rejects_fake_readiness() {
    let mut summary = real_prover::RealProverEvidenceSummary::from_evidence_slots(
        &real_prover_code_path_evidence(),
        &real_prover_unit_tests_evidence(),
        &local_real_proof_validation_log_evidence(),
        &real_proof_bytes_fixture_evidence(),
    )
    .unwrap();
    summary.satisfied_slots = real_prover::REQUIRED_EVIDENCE
        .iter()
        .map(|slot| (*slot).to_string())
        .collect();
    summary.satisfied_slot_count = 4;
    summary.missing_or_unsatisfied_slots.clear();
    summary.missing_or_unsatisfied_slot_count = 0;
    summary.blockers.clear();
    summary.blocker_count = 0;
    summary.all_slots_satisfied = true;
    summary.implementation_satisfied = true;
    summary.runtime_cutover_allowed = true;
    summary.real_proof_generation_allowed = true;
    summary.real_proof_bytes_fixture_present = true;
    summary.local_real_proof_verified = true;
    summary.test_only_bytes_rejected = false;

    let errors = summary.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error == "satisfied_slots must be empty")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "satisfied_slot_count must be 0")
    );
    assert!(errors.iter().any(|error| error
        == "missing_or_unsatisfied_slots must match the real prover evidence contract"));
    assert!(
        errors
            .iter()
            .any(|error| error == "missing_or_unsatisfied_slot_count must be 4")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "blockers must match the Phase 8 evidence summary contract")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "blocker_count must be 4")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "all_slots_satisfied must be false")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "implementation_satisfied must be false")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "runtime_cutover_allowed must be false")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "real_proof_generation_allowed must be false")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "real_proof_bytes_fixture_present must be false")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "local_real_proof_verified must be false")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "test_only_bytes_rejected must be true")
    );
}

#[test]
fn phase8_real_prover_readiness_rollup_reports_blocked_cutover() {
    let rollup = real_prover::Phase8RealProverReadinessRollup::from_inputs(
        &real_prover_evidence_summary(),
        &real_proof_bytes_fixture_promotion_plan(),
        &local_real_proof_validation_log_promotion_plan(),
    )
    .expect("readiness rollup should generate from valid Phase 8 inputs");

    rollup.validate().unwrap();
    assert_eq!(
        rollup.schema_version,
        real_prover::Phase8RealProverReadinessRollup::SCHEMA_VERSION
    );
    assert_eq!(
        rollup.rollup_status,
        real_prover::Phase8RealProverReadinessRollup::ROLLUP_STATUS
    );
    assert_eq!(rollup.evidence_slots_declared, 4);
    assert_eq!(rollup.evidence_slots_satisfied, 0);
    assert_eq!(rollup.evidence_slots_blocked, 4);
    assert!(rollup.fixture_promotion_plan_present);
    assert!(rollup.validation_log_promotion_plan_present);
    assert!(!rollup.fixture_promotion_ready);
    assert!(!rollup.validation_log_promotion_ready);
    assert!(rollup.test_only_shapes_present);
    assert!(!rollup.real_evidence_complete);
    assert!(!rollup.implementation_satisfied);
    assert!(!rollup.runtime_cutover_allowed);
    assert!(!rollup.real_proof_generation_allowed);
    assert_eq!(
        rollup.remaining_blockers,
        real_prover::Phase8RealProverReadinessRollup::REMAINING_BLOCKERS
    );
    assert_eq!(rollup.remaining_blocker_count, 7);
    assert_eq!(
        rollup.next_required_actions,
        real_prover::Phase8RealProverReadinessRollup::NEXT_REQUIRED_ACTIONS
    );
    assert_eq!(rollup.next_required_action_count, 5);
}

#[test]
fn phase8_real_prover_readiness_rollup_json_round_trips() {
    let rollup = real_prover::Phase8RealProverReadinessRollup::from_inputs(
        &real_prover_evidence_summary(),
        &real_proof_bytes_fixture_promotion_plan(),
        &local_real_proof_validation_log_promotion_plan(),
    )
    .unwrap();
    let json = serde_json::to_string_pretty(&rollup).unwrap();
    let decoded: real_prover::Phase8RealProverReadinessRollup =
        serde_json::from_str(&json).unwrap();

    assert_eq!(decoded, rollup);
    decoded.validate().unwrap();
}

#[test]
fn phase8_real_prover_readiness_rollup_rejects_fake_completion() {
    let mut rollup = real_prover::Phase8RealProverReadinessRollup::from_inputs(
        &real_prover_evidence_summary(),
        &real_proof_bytes_fixture_promotion_plan(),
        &local_real_proof_validation_log_promotion_plan(),
    )
    .unwrap();
    rollup.evidence_slots_satisfied = 4;
    rollup.evidence_slots_blocked = 0;
    rollup.fixture_promotion_ready = true;
    rollup.validation_log_promotion_ready = true;
    rollup.real_evidence_complete = true;
    rollup.implementation_satisfied = true;
    rollup.runtime_cutover_allowed = true;
    rollup.real_proof_generation_allowed = true;
    rollup.remaining_blockers.clear();
    rollup.remaining_blocker_count = 0;
    rollup.next_required_actions.clear();
    rollup.next_required_action_count = 0;

    let errors = rollup.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error == "evidence_slots_satisfied must be 0")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "evidence_slots_blocked must be 4")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "fixture_promotion_ready must be false")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "validation_log_promotion_ready must be false")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "real_evidence_complete must be false")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "implementation_satisfied must be false")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "runtime_cutover_allowed must be false")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "real_proof_generation_allowed must be false")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "remaining_blockers must match the Phase 8 readiness contract")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "remaining_blocker_count must be 7")
    );
    assert!(errors.iter().any(
        |error| error == "next_required_actions must match the Phase 8 readiness contract"
    ));
    assert!(
        errors
            .iter()
            .any(|error| error == "next_required_action_count must be 5")
    );
}
