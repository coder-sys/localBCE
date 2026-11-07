use stark_engine::{
    ClaimSourceRootInput, FeeScheduleEntryInput, FeeScheduleRootInput,
    NullifierRootTransitionInput, OracleFactInput, OracleFactsRootInput, SourceRootDigestCandidate,
};

const CLAIM_HASH: &str = "0x1c1b60223d4f3ffd351887f834b31a4260508b1602a5a9e16a447ea40e386607";
const OTHER_HASH: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn claim_source_root_input() -> ClaimSourceRootInput {
    ClaimSourceRootInput {
        schema_version: ClaimSourceRootInput::SCHEMA_VERSION.to_string(),
        source_schema_version: ClaimSourceRootInput::SOURCE_SCHEMA_VERSION.to_string(),
        input_status: ClaimSourceRootInput::INPUT_STATUS.to_string(),
        claim_id: "CLAIM-DEMO-011".to_string(),
        claim_hash: CLAIM_HASH.to_string(),
        claim_amount: 125_000,
        member_id: Some("member-demo-001".to_string()),
        provider_npi: Some("1234567890".to_string()),
        service_date: Some(20260615),
        procedure_codes: vec!["T1019".to_string()],
        diagnosis_codes: vec!["Z00.00".to_string()],
        service_line_count: Some(1),
        root_generation_status: ClaimSourceRootInput::ROOT_GENERATION_STATUS.to_string(),
        notes: vec!["test fixture".to_string()],
    }
}

fn oracle_facts_root_input() -> OracleFactsRootInput {
    OracleFactsRootInput {
        schema_version: OracleFactsRootInput::SCHEMA_VERSION.to_string(),
        source_schema_version: OracleFactsRootInput::SOURCE_SCHEMA_VERSION.to_string(),
        input_status: OracleFactsRootInput::INPUT_STATUS.to_string(),
        claim_id: "CLAIM-DEMO-011".to_string(),
        claim_hash: CLAIM_HASH.to_string(),
        source_manifest_id: Some("official-source-fixture".to_string()),
        facts: vec![OracleFactInput {
            fact_type: "eligibility".to_string(),
            fact_key: "program_eligibility_passed".to_string(),
            fact_value: "1".to_string(),
            source_url: Some("https://www.medicaid.gov/".to_string()),
            source_label: Some("Medicaid fixture".to_string()),
            verification_status: "fixture_only".to_string(),
        }],
        attestation_refs: vec!["attestation-fixture-001".to_string()],
        root_generation_status: OracleFactsRootInput::ROOT_GENERATION_STATUS.to_string(),
        notes: vec!["test fixture".to_string()],
    }
}

fn fee_schedule_root_input() -> FeeScheduleRootInput {
    FeeScheduleRootInput {
        schema_version: FeeScheduleRootInput::SCHEMA_VERSION.to_string(),
        source_schema_version: FeeScheduleRootInput::SOURCE_SCHEMA_VERSION.to_string(),
        input_status: FeeScheduleRootInput::INPUT_STATUS.to_string(),
        claim_id: "CLAIM-DEMO-011".to_string(),
        claim_hash: CLAIM_HASH.to_string(),
        fee_schedule_id: Some("fee-schedule-fixture".to_string()),
        entries: vec![FeeScheduleEntryInput {
            fee_code: "T1019".to_string(),
            unit_amount_cents: 2_500,
            currency: "USD".to_string(),
            effective_from: 20260101,
            effective_thru: Some(20261231),
            source_url: Some("https://www.medicaid.gov/".to_string()),
            verification_status: "fixture_only".to_string(),
        }],
        root_generation_status: FeeScheduleRootInput::ROOT_GENERATION_STATUS.to_string(),
        notes: vec!["test fixture".to_string()],
    }
}

fn nullifier_root_transition_input() -> NullifierRootTransitionInput {
    NullifierRootTransitionInput {
        schema_version: NullifierRootTransitionInput::SCHEMA_VERSION.to_string(),
        source_schema_version: NullifierRootTransitionInput::SOURCE_SCHEMA_VERSION.to_string(),
        input_status: NullifierRootTransitionInput::INPUT_STATUS.to_string(),
        claim_id: "CLAIM-DEMO-011".to_string(),
        claim_hash: CLAIM_HASH.to_string(),
        nullifier_candidate: Some(OTHER_HASH.to_string()),
        nullifier_root_before: Some(CLAIM_HASH.to_string()),
        nullifier_root_after: Some(OTHER_HASH.to_string()),
        transition_status: NullifierRootTransitionInput::TRANSITION_STATUS.to_string(),
        root_generation_status: NullifierRootTransitionInput::ROOT_GENERATION_STATUS.to_string(),
        notes: vec!["test fixture".to_string()],
    }
}

#[test]
fn claim_source_root_digest_candidate_validates() {
    let candidate = claim_source_root_input().to_digest_candidate().unwrap();

    candidate.validate().unwrap();
    assert_eq!(
        candidate.schema_version,
        SourceRootDigestCandidate::SCHEMA_VERSION
    );
    assert_eq!(
        candidate.source_schema_version,
        "claim-source-root-input-v0"
    );
    assert_eq!(candidate.source_root_kind, "claim_source_root");
    assert_eq!(
        candidate.hash_algorithm,
        "sha2_256_candidate_not_production_hash"
    );
    assert!(candidate.source_root_candidate.starts_with("0x"));
    assert_eq!(candidate.source_root_candidate.len(), 66);
    assert!(!candidate.production_hash_selected);
    assert!(!candidate.runtime_wiring_allowed);
    assert!(candidate.groth16_flow_unchanged);
}

#[test]
fn oracle_facts_root_digest_candidate_validates() {
    let candidate = oracle_facts_root_input().to_digest_candidate().unwrap();

    candidate.validate().unwrap();
    assert_eq!(
        candidate.source_schema_version,
        "oracle-facts-root-input-v0"
    );
    assert_eq!(candidate.source_root_kind, "oracle_facts_root");
}

#[test]
fn fee_schedule_root_digest_candidate_validates() {
    let candidate = fee_schedule_root_input().to_digest_candidate().unwrap();

    candidate.validate().unwrap();
    assert_eq!(
        candidate.source_schema_version,
        "fee-schedule-root-input-v0"
    );
    assert_eq!(candidate.source_root_kind, "fee_schedule_root");
}

#[test]
fn nullifier_root_transition_digest_candidate_validates() {
    let candidate = nullifier_root_transition_input()
        .to_digest_candidate()
        .unwrap();

    candidate.validate().unwrap();
    assert_eq!(
        candidate.source_schema_version,
        "nullifier-root-transition-input-v0"
    );
    assert_eq!(candidate.source_root_kind, "nullifier_root_transition");
}

#[test]
fn source_root_digest_candidate_round_trips_json() {
    let candidate = claim_source_root_input().to_digest_candidate().unwrap();
    let json = serde_json::to_string_pretty(&candidate).unwrap();
    let decoded: SourceRootDigestCandidate = serde_json::from_str(&json).unwrap();

    assert_eq!(decoded, candidate);
    decoded.validate().unwrap();
}

#[test]
fn source_root_digest_candidate_rejects_tampered_digest() {
    let mut candidate = claim_source_root_input().to_digest_candidate().unwrap();
    candidate.source_root_candidate = OTHER_HASH.to_string();

    let errors = candidate.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.contains("sha2_256(canonical_preimage)"))
    );
}

#[test]
fn source_root_digest_candidate_rejects_production_or_runtime_claims() {
    let mut candidate = oracle_facts_root_input().to_digest_candidate().unwrap();
    candidate.production_hash_selected = true;
    candidate.runtime_wiring_allowed = true;

    let errors = candidate.validate().unwrap_err();
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
}
