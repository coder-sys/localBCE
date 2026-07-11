use stark_engine::{ActiveClaimToStarkBridge, MappingClass, WinterfellAdapterBoundaryPlan};

#[test]
fn winterfell_adapter_boundary_names_imported_poc_shape() {
    let plan = WinterfellAdapterBoundaryPlan::phase5a();

    assert_eq!(plan.validate(), Ok(()));
    assert_eq!(
        plan.schema_version,
        WinterfellAdapterBoundaryPlan::SCHEMA_VERSION
    );
    assert_eq!(plan.plan_status, WinterfellAdapterBoundaryPlan::PLAN_STATUS);
    assert_eq!(
        plan.imported_poc.crate_path,
        "blind-ledger-app-layer/zk-stark"
    );
    assert_eq!(
        plan.imported_poc.claim_input_fields,
        ActiveClaimToStarkBridge::IMPORTED_STARK_FIELDS
            .iter()
            .map(|field| (*field).to_string())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        plan.imported_poc.public_inputs,
        vec![
            "commitment".to_string(),
            "decision".to_string(),
            "failure_code".to_string()
        ]
    );
    assert_eq!(plan.imported_poc.gate_count, 10);
    assert_eq!(plan.imported_poc.trace_width, 172);
    assert_eq!(plan.imported_poc.trace_length, 16);
}

#[test]
fn winterfell_adapter_boundary_keeps_phase5a_planning_only() {
    let plan = WinterfellAdapterBoundaryPlan::phase5a();

    assert!(!plan.winterfell_dependency_imported);
    assert!(!plan.proof_generation_enabled);
    assert!(
        plan.imported_poc
            .commitment_strategy
            .contains("PoC commitment")
    );
    assert!(
        plan.recommended_next_steps
            .iter()
            .any(|step| step.contains("before importing the Winterfell crate"))
    );
}

#[test]
fn winterfell_adapter_boundary_requires_phase4_artifacts() {
    let plan = WinterfellAdapterBoundaryPlan::phase5a();

    for required in [
        "StarkBridgeInput",
        "ClaimSourceRootInput",
        "OracleFactsRootInput",
        "FeeScheduleRootInput",
        "NullifierRootTransitionInput",
        "BatchRootCompatibilityPlan",
        "BatchRootGapReport",
        "StarkProofIntent",
        "StarkWitnessPlan",
        "StarkMockTrace",
    ] {
        assert!(
            plan.required_phase4_artifacts
                .iter()
                .any(|artifact| artifact == required),
            "missing {required}"
        );
    }
}

#[test]
fn winterfell_adapter_boundary_classifies_all_claim_input_fields() {
    let plan = WinterfellAdapterBoundaryPlan::phase5a();
    let direct = plan
        .field_bindings
        .iter()
        .filter(|binding| binding.class == MappingClass::Direct)
        .count();
    let partial = plan
        .field_bindings
        .iter()
        .filter(|binding| binding.class == MappingClass::Partial)
        .count();
    let unmapped = plan
        .field_bindings
        .iter()
        .filter(|binding| binding.class == MappingClass::Unmapped)
        .count();

    assert_eq!(plan.field_bindings.len(), 11);
    assert_eq!(direct, 3);
    assert_eq!(partial, 4);
    assert_eq!(unmapped, 4);
    assert!(plan.field_bindings.iter().any(|binding| {
        binding.winterfell_field == "eligibility_active"
            && binding.phase4_source_field.as_deref()
                == Some("active_rust_facts.eligibility_active")
            && binding.class == MappingClass::Direct
    }));
    assert!(plan.field_bindings.iter().any(|binding| {
        binding.winterfell_field == "max_charge_cents"
            && binding.phase4_source_artifact.as_deref() == Some("FeeScheduleRootInput")
            && binding.class == MappingClass::Unmapped
    }));
}

#[test]
fn winterfell_adapter_boundary_classifies_public_inputs() {
    let plan = WinterfellAdapterBoundaryPlan::phase5a();

    assert_eq!(plan.public_input_bindings.len(), 3);
    assert!(plan.public_input_bindings.iter().any(|binding| {
        binding.winterfell_public_input == "commitment" && binding.class == MappingClass::Partial
    }));
    assert!(plan.public_input_bindings.iter().any(|binding| {
        binding.winterfell_public_input == "decision" && binding.class == MappingClass::Direct
    }));
    assert!(plan.public_input_bindings.iter().any(|binding| {
        binding.winterfell_public_input == "failure_code" && binding.class == MappingClass::Direct
    }));
}

#[test]
fn winterfell_adapter_boundary_names_unsupported_constraint_groups() {
    let plan = WinterfellAdapterBoundaryPlan::phase5a();

    for expected in [
        "member_id_nonzero_inverse_witness",
        "provider_npi_nonzero_inverse_witness",
        "charge_and_max_charge_bit_decomposition",
        "charge_lte_max_charge_comparison_witness",
        "winterfell_commitment_hash_chain",
        "public_commitment_binding_to_phase4_roots",
    ] {
        assert!(
            plan.unsupported_constraint_groups
                .iter()
                .any(|group| group == expected),
            "missing {expected}"
        );
    }
}

#[test]
fn winterfell_adapter_boundary_json_round_trips() {
    let plan = WinterfellAdapterBoundaryPlan::phase5a();
    let json = serde_json::to_string_pretty(&plan).unwrap();
    let round_tripped: WinterfellAdapterBoundaryPlan = serde_json::from_str(&json).unwrap();

    assert_eq!(round_tripped, plan);
    assert_eq!(round_tripped.validate(), Ok(()));
    assert!(json.contains("\"schema_version\": \"winterfell-adapter-boundary-plan-v0\""));
    assert!(!json.contains("proof_generated\": true"));
}

#[test]
fn winterfell_adapter_boundary_validation_rejects_runtime_like_flags() {
    let mut plan = WinterfellAdapterBoundaryPlan::phase5a();
    plan.winterfell_dependency_imported = true;
    plan.proof_generation_enabled = true;

    let errors = plan.validate().unwrap_err();

    assert!(
        errors
            .iter()
            .any(|error| error.contains("winterfell_dependency_imported must be false"))
    );
    assert!(
        errors
            .iter()
            .any(|error| error.contains("proof_generation_enabled must be false"))
    );
}

#[test]
fn winterfell_adapter_boundary_validation_rejects_missing_field_binding() {
    let mut plan = WinterfellAdapterBoundaryPlan::phase5a();
    plan.field_bindings
        .retain(|binding| binding.winterfell_field != "program_integrity_hold");

    let errors = plan.validate().unwrap_err();

    assert!(
        errors
            .iter()
            .any(|error| error.contains("field_bindings must contain 11 fields"))
    );
    assert!(errors
        .iter()
        .any(|error| error.contains("missing Winterfell field binding: program_integrity_hold")));
}
