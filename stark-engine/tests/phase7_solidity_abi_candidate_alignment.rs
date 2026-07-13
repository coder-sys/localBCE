#![cfg(feature = "winterfell-poc")]

use stark_engine::winterfell_poc_adapter::{
    SolidityVerifierInput, StarkSettlementBoundaryArtifact, StarkSolidityVerifierInterfacePlan,
    WinterfellPocProofPreview,
};

fn sample_settlement_boundary_artifact() -> StarkSettlementBoundaryArtifact {
    StarkSettlementBoundaryArtifact {
        schema_version: StarkSettlementBoundaryArtifact::SCHEMA_VERSION.to_string(),
        source_schema_version: WinterfellPocProofPreview::SCHEMA_VERSION.to_string(),
        artifact_status: StarkSettlementBoundaryArtifact::ARTIFACT_STATUS.to_string(),
        claim_id: "CLAIM-PHASE7-ABI".to_string(),
        claim_hash: "0xabababababababababababababababababababababababababababababababab"
            .to_string(),
        decision: 1,
        failure_code: 0,
        proof_preview_status: WinterfellPocProofPreview::PROOF_STATUS.to_string(),
        proof_verified: true,
        proof_size_bytes: 128,
        verifier_target: "future_stark_settlement_or_attestation_contract".to_string(),
        runtime_wired: false,
        on_chain_submission: false,
        groth16_flow_unchanged: true,
        settlement_contract_ready: false,
        notes: vec!["fixture settlement boundary artifact".to_string()],
    }
}

#[test]
fn solidity_interface_plan_matches_v1_candidate_public_inputs() {
    let artifact = sample_settlement_boundary_artifact();
    let plan = artifact.to_solidity_verifier_interface_plan().unwrap();

    assert_eq!(plan.validate(), Ok(()));
    assert_eq!(plan.validate_v1_candidate_alignment(), Ok(()));
    assert_eq!(
        plan.interface_name,
        "IStarkClaimsVerifierV1Candidate"
    );
    assert!(plan.function_signature.contains("verifyStarkClaim("));

    assert_eq!(
        plan.solidity_inputs
            .iter()
            .map(|input| input.name.as_str())
            .collect::<Vec<_>>(),
        vec![
            "claimHash",
            "decision",
            "failureCode",
            "publicInputRoot",
            "claimSourceRoot",
            "oracleFactsRoot",
            "feeScheduleRoot",
            "nullifierRootBefore",
            "nullifierRootAfter",
            "batchRoot",
            "proof",
        ]
    );
}

#[test]
fn solidity_interface_plan_uses_candidate_solidity_types() {
    let artifact = sample_settlement_boundary_artifact();
    let plan = artifact.to_solidity_verifier_interface_plan().unwrap();

    for (name, solidity_type) in [
        ("claimHash", "bytes32"),
        ("decision", "uint8"),
        ("failureCode", "uint32"),
        ("publicInputRoot", "bytes32"),
        ("claimSourceRoot", "bytes32"),
        ("oracleFactsRoot", "bytes32"),
        ("feeScheduleRoot", "bytes32"),
        ("nullifierRootBefore", "bytes32"),
        ("nullifierRootAfter", "bytes32"),
        ("batchRoot", "bytes32"),
        ("proof", "bytes"),
    ] {
        let input = find_input(&plan, name);
        assert_eq!(input.solidity_type, solidity_type, "{name}");
    }
}

#[test]
fn solidity_interface_plan_marks_future_roots_as_not_available_in_preview() {
    let artifact = sample_settlement_boundary_artifact();
    let plan = artifact.to_solidity_verifier_interface_plan().unwrap();

    for root_name in [
        "publicInputRoot",
        "claimSourceRoot",
        "oracleFactsRoot",
        "feeScheduleRoot",
        "nullifierRootBefore",
        "nullifierRootAfter",
        "batchRoot",
    ] {
        let input = find_input(&plan, root_name);
        assert_eq!(input.value_preview, "unavailable_in_preview", "{root_name}");
        assert_eq!(input.status, "requires_root_generation", "{root_name}");
    }

    let proof = find_input(&plan, "proof");
    assert_eq!(proof.value_preview, "unavailable_in_preview");
    assert_eq!(proof.status, "requires_real_verifier_artifact");
}

#[test]
fn solidity_interface_plan_validator_rejects_missing_candidate_field() {
    let artifact = sample_settlement_boundary_artifact();
    let mut plan = artifact.to_solidity_verifier_interface_plan().unwrap();

    plan.solidity_inputs
        .retain(|input| input.name != "oracleFactsRoot");

    let errors = plan.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.contains("missing Solidity verifier input: oracleFactsRoot")),
        "{errors:?}"
    );
}

#[test]
fn solidity_interface_plan_alignment_validator_rejects_wrong_type() {
    let artifact = sample_settlement_boundary_artifact();
    let mut plan = artifact.to_solidity_verifier_interface_plan().unwrap();

    find_input_mut(&mut plan, "decision").solidity_type = "uint256".to_string();

    let errors = plan.validate_v1_candidate_alignment().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.contains("decision") && error.contains("uint8")),
        "{errors:?}"
    );
}

fn find_input<'a>(
    plan: &'a StarkSolidityVerifierInterfacePlan,
    name: &str,
) -> &'a SolidityVerifierInput {
    plan.solidity_inputs
        .iter()
        .find(|input| input.name == name)
        .unwrap_or_else(|| panic!("missing input {name}"))
}

fn find_input_mut<'a>(
    plan: &'a mut StarkSolidityVerifierInterfacePlan,
    name: &str,
) -> &'a mut SolidityVerifierInput {
    plan.solidity_inputs
        .iter_mut()
        .find(|input| input.name == name)
        .unwrap_or_else(|| panic!("missing input {name}"))
}
