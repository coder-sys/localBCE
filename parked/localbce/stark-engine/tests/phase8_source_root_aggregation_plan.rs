use stark_engine::{
    ClaimSourceRootInput, FeeScheduleRootInput, NullifierRootTransitionInput, OracleFactsRootInput,
    PublicInputRootAssemblyPlan, PublicInputRootDigestCandidate, PublicInputRootField,
    SourceRootAggregationPlan, SourceRootDigestCandidate,
};

const CLAIM_HASH: &str = "0x1c1b60223d4f3ffd351887f834b31a4260508b1602a5a9e16a447ea40e386607";

fn public_input_root_digest_candidate() -> PublicInputRootDigestCandidate {
    let ordered_fields = PublicInputRootAssemblyPlan::REQUIRED_ORDERED_FIELDS
        .iter()
        .enumerate()
        .map(|(position, field_name)| PublicInputRootField {
            position,
            field_name: (*field_name).to_string(),
            encoding: "fixture_encoding".to_string(),
            source: "fixture_source".to_string(),
            value_status: if matches!(*field_name, "claim_hash" | "decision" | "failure_code") {
                "available_from_bridge_input".to_string()
            } else {
                "requires_future_root_generation".to_string()
            },
        })
        .collect();

    let plan = PublicInputRootAssemblyPlan {
        schema_version: PublicInputRootAssemblyPlan::SCHEMA_VERSION.to_string(),
        source_schema_version: PublicInputRootAssemblyPlan::SOURCE_SCHEMA_VERSION.to_string(),
        plan_status: PublicInputRootAssemblyPlan::PLAN_STATUS.to_string(),
        hash_strategy: "canonical_preimage_defined_hash_not_selected".to_string(),
        canonical_encoding: "ordered_field_name_colon_canonical_value_utf8_joined_by_newline"
            .to_string(),
        ordered_fields,
        expected_field_count: PublicInputRootAssemblyPlan::REQUIRED_ORDERED_FIELDS.len(),
        public_input_root: None,
        root_generation_status: "not_generated".to_string(),
        groth16_flow_unchanged: true,
        notes: vec!["test fixture".to_string()],
    };

    plan.to_digest_candidate().unwrap()
}

fn claim_source_root_digest_candidate() -> SourceRootDigestCandidate {
    let input = ClaimSourceRootInput {
        schema_version: ClaimSourceRootInput::SCHEMA_VERSION.to_string(),
        source_schema_version: ClaimSourceRootInput::SOURCE_SCHEMA_VERSION.to_string(),
        input_status: ClaimSourceRootInput::INPUT_STATUS.to_string(),
        claim_id: "CLAIM-DEMO-011".to_string(),
        claim_hash: CLAIM_HASH.to_string(),
        claim_amount: 125_000,
        member_id: None,
        provider_npi: None,
        service_date: Some(20260615),
        procedure_codes: Vec::new(),
        diagnosis_codes: Vec::new(),
        service_line_count: None,
        root_generation_status: ClaimSourceRootInput::ROOT_GENERATION_STATUS.to_string(),
        notes: vec!["test fixture".to_string()],
    };
    input.to_digest_candidate().unwrap()
}

fn oracle_facts_root_digest_candidate() -> SourceRootDigestCandidate {
    let input = OracleFactsRootInput {
        schema_version: OracleFactsRootInput::SCHEMA_VERSION.to_string(),
        source_schema_version: OracleFactsRootInput::SOURCE_SCHEMA_VERSION.to_string(),
        input_status: OracleFactsRootInput::INPUT_STATUS.to_string(),
        claim_id: "CLAIM-DEMO-011".to_string(),
        claim_hash: CLAIM_HASH.to_string(),
        source_manifest_id: None,
        facts: Vec::new(),
        attestation_refs: Vec::new(),
        root_generation_status: OracleFactsRootInput::ROOT_GENERATION_STATUS.to_string(),
        notes: vec!["test fixture".to_string()],
    };
    input.to_digest_candidate().unwrap()
}

fn fee_schedule_root_digest_candidate() -> SourceRootDigestCandidate {
    let input = FeeScheduleRootInput {
        schema_version: FeeScheduleRootInput::SCHEMA_VERSION.to_string(),
        source_schema_version: FeeScheduleRootInput::SOURCE_SCHEMA_VERSION.to_string(),
        input_status: FeeScheduleRootInput::INPUT_STATUS.to_string(),
        claim_id: "CLAIM-DEMO-011".to_string(),
        claim_hash: CLAIM_HASH.to_string(),
        fee_schedule_id: None,
        entries: Vec::new(),
        root_generation_status: FeeScheduleRootInput::ROOT_GENERATION_STATUS.to_string(),
        notes: vec!["test fixture".to_string()],
    };
    input.to_digest_candidate().unwrap()
}

fn nullifier_root_transition_digest_candidate() -> SourceRootDigestCandidate {
    let input = NullifierRootTransitionInput {
        schema_version: NullifierRootTransitionInput::SCHEMA_VERSION.to_string(),
        source_schema_version: NullifierRootTransitionInput::SOURCE_SCHEMA_VERSION.to_string(),
        input_status: NullifierRootTransitionInput::INPUT_STATUS.to_string(),
        claim_id: "CLAIM-DEMO-011".to_string(),
        claim_hash: CLAIM_HASH.to_string(),
        nullifier_candidate: None,
        nullifier_root_before: None,
        nullifier_root_after: None,
        transition_status: NullifierRootTransitionInput::TRANSITION_STATUS.to_string(),
        root_generation_status: NullifierRootTransitionInput::ROOT_GENERATION_STATUS.to_string(),
        notes: vec!["test fixture".to_string()],
    };
    input.to_digest_candidate().unwrap()
}

fn source_root_digest_candidates() -> Vec<SourceRootDigestCandidate> {
    vec![
        claim_source_root_digest_candidate(),
        oracle_facts_root_digest_candidate(),
        fee_schedule_root_digest_candidate(),
        nullifier_root_transition_digest_candidate(),
    ]
}

#[test]
fn source_root_aggregation_plan_binds_all_required_roots() {
    let public_input_root = public_input_root_digest_candidate();
    let source_roots = source_root_digest_candidates();

    let plan = SourceRootAggregationPlan::from_candidates(&public_input_root, &source_roots)
        .expect("aggregation plan should build");

    plan.validate().unwrap();
    assert_eq!(
        plan.schema_version,
        SourceRootAggregationPlan::SCHEMA_VERSION
    );
    assert_eq!(
        plan.plan_status,
        "planning_only_source_roots_bound_no_public_root_rewrite"
    );
    assert_eq!(
        plan.public_input_root_candidate,
        public_input_root.public_input_root_candidate
    );
    assert_eq!(plan.source_root_bindings.len(), 4);
    assert_eq!(
        plan.source_root_bindings[0].source_root_kind,
        "claim_source_root"
    );
    assert_eq!(
        plan.source_root_bindings[0].public_input_fields,
        vec!["claim_source_root".to_string()]
    );
    assert_eq!(
        plan.source_root_bindings[3].public_input_fields,
        vec![
            "nullifier_root_before".to_string(),
            "nullifier_root_after".to_string()
        ]
    );
    assert!(plan.all_source_roots_bound);
    assert!(!plan.production_hash_selected);
    assert!(!plan.runtime_wiring_allowed);
    assert!(plan.groth16_flow_unchanged);
}

#[test]
fn source_root_aggregation_plan_json_round_trips() {
    let plan = SourceRootAggregationPlan::from_candidates(
        &public_input_root_digest_candidate(),
        &source_root_digest_candidates(),
    )
    .unwrap();

    let json = serde_json::to_string_pretty(&plan).unwrap();
    let decoded: SourceRootAggregationPlan = serde_json::from_str(&json).unwrap();

    assert_eq!(decoded, plan);
    decoded.validate().unwrap();
}

#[test]
fn source_root_aggregation_plan_rejects_missing_required_root() {
    let mut source_roots = source_root_digest_candidates();
    source_roots.retain(|candidate| candidate.source_root_kind != "fee_schedule_root");

    let errors = SourceRootAggregationPlan::from_candidates(
        &public_input_root_digest_candidate(),
        &source_roots,
    )
    .unwrap_err();

    assert!(
        errors
            .iter()
            .any(|error| error.contains("source_roots must contain exactly 4"))
    );
    assert!(
        errors
            .iter()
            .any(|error| error.contains("missing source root candidate: fee_schedule_root"))
    );
}

#[test]
fn source_root_aggregation_plan_rejects_reordered_bindings() {
    let mut plan = SourceRootAggregationPlan::from_candidates(
        &public_input_root_digest_candidate(),
        &source_root_digest_candidates(),
    )
    .unwrap();
    plan.source_root_bindings.swap(0, 1);

    let errors = plan.validate().unwrap_err();
    assert!(errors.iter().any(|error| {
        error.contains("source_root_bindings[0].source_root_kind must be claim_source_root")
    }));
}

#[test]
fn source_root_aggregation_plan_rejects_runtime_or_production_claims() {
    let mut plan = SourceRootAggregationPlan::from_candidates(
        &public_input_root_digest_candidate(),
        &source_root_digest_candidates(),
    )
    .unwrap();
    plan.production_hash_selected = true;
    plan.runtime_wiring_allowed = true;

    let errors = plan.validate().unwrap_err();
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
