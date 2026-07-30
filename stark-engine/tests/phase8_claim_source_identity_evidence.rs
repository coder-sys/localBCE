use stark_engine::{
    ActiveClaimToStarkBridge, ClaimSourceIdentityEvidence, ClaimSourceRootInput,
    WinterfellCompleteWitnessCandidate, WinterfellCompleteWitnessField,
};

const CLAIM_ID: &str = "CLAIM-PHASE8-IDENTITY";
const CLAIM_HASH: &str = "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

fn sample_claim_source() -> ClaimSourceRootInput {
    ClaimSourceRootInput {
        schema_version: ClaimSourceRootInput::SCHEMA_VERSION.to_string(),
        source_schema_version: ClaimSourceRootInput::SOURCE_SCHEMA_VERSION.to_string(),
        input_status: ClaimSourceRootInput::INPUT_STATUS.to_string(),
        claim_id: CLAIM_ID.to_string(),
        claim_hash: CLAIM_HASH.to_string(),
        claim_amount: 1000,
        member_id: None,
        provider_npi: None,
        service_date: Some(20_000),
        procedure_codes: Vec::new(),
        diagnosis_codes: Vec::new(),
        service_line_count: None,
        root_generation_status: ClaimSourceRootInput::ROOT_GENERATION_STATUS.to_string(),
        notes: vec!["test claim-source identity input".to_string()],
    }
}

fn sample_complete_candidate() -> WinterfellCompleteWitnessCandidate {
    let fields = ActiveClaimToStarkBridge::IMPORTED_STARK_FIELDS
        .iter()
        .enumerate()
        .map(|(index, field)| {
            let value = match *field {
                "member_id" => stable_fixture_string_to_u64("MEMBER-FIXTURE-001"),
                "provider_npi" => 1_234_567_893,
                _ => (index as u64) + 1,
            };
            WinterfellCompleteWitnessField {
                winterfell_field: (*field).to_string(),
                value,
                value_status: "populated_adapter_ready_fixture".to_string(),
                source_artifact: if matches!(*field, "member_id" | "provider_npi") {
                    "WinterfellSourceDataFixture".to_string()
                } else {
                    "StarkBridgeInput".to_string()
                },
                source_field: (*field).to_string(),
                note: format!("test value for {field}"),
            }
        })
        .collect::<Vec<_>>();

    WinterfellCompleteWitnessCandidate {
        schema_version: WinterfellCompleteWitnessCandidate::SCHEMA_VERSION.to_string(),
        source_schema_version: WinterfellCompleteWitnessCandidate::SOURCE_SCHEMA_VERSION
            .to_string(),
        candidate_status: WinterfellCompleteWitnessCandidate::CANDIDATE_STATUS.to_string(),
        claim_id: CLAIM_ID.to_string(),
        claim_hash: CLAIM_HASH.to_string(),
        field_count: fields.len(),
        all_fields_populated: true,
        fields,
        winterfell_dependency_imported: false,
        proof_generation_enabled: false,
        notes: vec!["test complete Winterfell witness candidate".to_string()],
    }
}

#[test]
fn claim_source_identity_evidence_records_current_missing_active_exports() {
    let source = sample_claim_source();
    let candidate = sample_complete_candidate();
    let evidence =
        ClaimSourceIdentityEvidence::from_claim_source_and_candidate(&source, &candidate).unwrap();

    assert_eq!(evidence.validate(), Ok(()));
    assert_eq!(
        evidence.schema_version,
        ClaimSourceIdentityEvidence::SCHEMA_VERSION
    );
    assert_eq!(evidence.field_count, 2);
    assert!(!evidence.source_fields_present);
    assert!(evidence.candidate_fields_present);
    assert!(!evidence.identity_sources_match_candidate_values);
    assert!(!evidence.production_semantics_complete);
    assert!(!evidence.accepted_as_runtime_evidence);
    assert!(!evidence.runtime_wired);
    assert!(!evidence.on_chain_submission);
    assert!(evidence.fields.iter().all(|field| {
        field.claim_source_value.is_none()
            && field.claim_source_value_status == "missing_from_active_bridge_export"
            && field.binding_status == "claim_source_field_missing_active_bridge_export"
            && !field.runtime_equivalent
    }));
}

#[test]
fn claim_source_identity_evidence_can_match_future_enriched_identity_sources() {
    let mut source = sample_claim_source();
    source.member_id = Some("MEMBER-FIXTURE-001".to_string());
    source.provider_npi = Some("1234567893".to_string());
    let candidate = sample_complete_candidate();

    let evidence =
        ClaimSourceIdentityEvidence::from_claim_source_and_candidate(&source, &candidate).unwrap();

    assert_eq!(evidence.validate(), Ok(()));
    assert!(evidence.source_fields_present);
    assert!(evidence.identity_sources_match_candidate_values);
    assert!(evidence.fields.iter().all(|field| {
        field.claim_source_value.is_some()
            && field.claim_source_value_status == "present_in_claim_source_input"
            && field.binding_status == "source_value_matches_complete_candidate"
            && field.source_matches_candidate_value
            && !field.runtime_equivalent
    }));
}

#[test]
fn claim_source_identity_evidence_rejects_runtime_claims() {
    let source = sample_claim_source();
    let candidate = sample_complete_candidate();
    let mut evidence =
        ClaimSourceIdentityEvidence::from_claim_source_and_candidate(&source, &candidate).unwrap();

    evidence.production_semantics_complete = true;
    evidence.accepted_as_runtime_evidence = true;
    evidence.runtime_wired = true;
    evidence.on_chain_submission = true;

    let errors = evidence.validate().unwrap_err();

    assert!(
        errors
            .iter()
            .any(|error| error == "production_semantics_complete must remain false")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "accepted_as_runtime_evidence must remain false")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "runtime_wired must remain false")
    );
    assert!(
        errors
            .iter()
            .any(|error| error == "on_chain_submission must remain false")
    );
}

#[test]
fn claim_source_identity_evidence_rejects_claim_mismatch() {
    let source = sample_claim_source();
    let mut candidate = sample_complete_candidate();
    candidate.claim_id = "OTHER-CLAIM".to_string();

    let errors = ClaimSourceIdentityEvidence::from_claim_source_and_candidate(&source, &candidate)
        .unwrap_err();

    assert!(errors.iter().any(
        |error| error == "claim source claim_id must match complete witness candidate claim_id"
    ));
}

fn stable_fixture_string_to_u64(value: &str) -> u64 {
    value.bytes().fold(0xcbf29ce484222325u64, |hash, byte| {
        hash ^ (byte as u64).wrapping_mul(0x100000001b3)
    })
}
