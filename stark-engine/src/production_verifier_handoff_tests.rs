use serde_json::json;

use super::{
    ProductionStarkVerifierHandoffV4, STARK_VERIFIER_V1_ABI_FIELDS,
    STARK_VERIFIER_V1_UNRESOLVED_ROOT_FIELDS,
};
use crate::{StarkBridgeInput, production_proof_artifact::ProductionStarkProofArtifactV4};

fn approved_bridge() -> StarkBridgeInput {
    serde_json::from_value(json!({
        "schema_version": "stark-bridge-input-v0",
        "producer": "rust-engine",
        "purpose": "stark_engine_compatibility_input",
        "runtime_mode": "dry_run_or_optional_sidecar",
        "claim": {
            "claim_id": "CLAIM-PRODUCTION-HANDOFF-001",
            "claim_amount": 1000,
            "claim_hash": "0xaaaaaaaaaaaaaaaa1111111111111111bbbbbbbbbbbbbbbb2222222222222222",
            "member_id": "MEMBER-001",
            "provider_npi": "1234567893",
            "diagnosis_count": 1,
            "max_charge_cents": 100000,
            "diagnosis_codes": ["Z00.00"],
            "service_lines": [{
                "procedure_code": "99213",
                "charge_cents": 100000,
                "units": 1
            }],
            "oracle_source_manifest_id": "DEMO-OFFICIAL-SOURCES-V1",
            "oracle_facts": [{
                "fact_type": "eligibility",
                "fact_key": "eligibility_active",
                "fact_value": "1",
                "source_url": "https://example.gov/demo/oracle-facts",
                "source_label": "Demo source - not production",
                "verification_status": "verified"
            }],
            "oracle_attestation_refs": [
                "demo-attestation:eligibility_active:CLAIM-PRODUCTION-HANDOFF-001"
            ],
            "fee_schedule_id": "DEMO-FEE-SCHEDULE-V1",
            "fee_schedule_entries": [{
                "fee_code": "99213",
                "unit_amount_cents": 100000,
                "currency": "USD",
                "effective_from": 19000,
                "effective_thru": 22000,
                "source_url": "https://example.gov/demo/fee-schedule/99213",
                "verification_status": "verified"
            }]
        },
        "adjudication": {
            "decision": 1,
            "failure_code": 0,
            "failure_reason": null,
            "ruleset_id": "current_g1_g10_denial_reason"
        },
        "active_rust_facts": {
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
        },
        "winterfell_poc_mapping": {
            "direct": {
                "eligibility_active": 1,
                "provider_enrolled": 1,
                "duplicate_flag": 0
            },
            "partial": {
                "service_line_count": {
                    "source": ["billing_code_valid", "units_valid"],
                    "status": "partial_not_semantically_equivalent"
                },
                "prior_auth_ok": {
                    "source": ["provider_type_valid", "physician_certification_valid"],
                    "status": "partial_not_semantically_equivalent"
                },
                "charge_cents": {
                    "source": ["claim_amount", "soc_amount", "soc_met"],
                    "status": "partial_not_semantically_equivalent"
                },
                "program_integrity_hold": {
                    "source": ["disability_determination_valid", "recipient_not_deceased"],
                    "status": "partial_not_semantically_equivalent"
                }
            },
            "unmapped": {
                "member_id": 1,
                "provider_npi": 1234567893,
                "diagnosis_count": 1,
                "max_charge_cents": 100000
            }
        },
        "public_inputs": {
            "claim_hash": "0xaaaaaaaaaaaaaaaa1111111111111111bbbbbbbbbbbbbbbb2222222222222222",
            "decision": 1,
            "failure_code": 0,
            "ruleset_id": "current_g1_g10_denial_reason"
        },
        "proof_status": {
            "stark_proof_generated": false,
            "winterfell_poc_compatible": false,
            "groth16_flow_unchanged": true,
            "on_chain_submission": false
        }
    }))
    .unwrap()
}

#[test]
fn approved_artifact_generates_strict_non_call_ready_abi_handoff() {
    let artifact = ProductionStarkProofArtifactV4::from_bridge_input(&approved_bridge()).unwrap();
    let handoff = ProductionStarkVerifierHandoffV4::from_proof_artifact(&artifact).unwrap();

    handoff.validate().unwrap();
    assert_eq!(
        handoff
            .abi_fields
            .iter()
            .map(|field| (field.name.as_str(), field.solidity_type.as_str()))
            .collect::<Vec<_>>(),
        STARK_VERIFIER_V1_ABI_FIELDS
    );
    assert_eq!(
        handoff.public_input_root,
        artifact.public_input_root_bytes32
    );
    assert_eq!(
        handoff.public_input_root_status,
        "air_constrained_rp64_256_packed_bytes32"
    );
    assert_eq!(
        handoff.claim_source_root,
        artifact.claim_source_root_bytes32
    );
    assert_eq!(
        handoff.claim_source_root_status,
        "air_constrained_canonical_leaf_and_depth_10_merkle_path"
    );
    assert_eq!(
        handoff.oracle_facts_root,
        artifact.oracle_facts_root_bytes32
    );
    assert_eq!(
        handoff.oracle_facts_root_status,
        "air_constrained_canonical_verified_fact_leaf_and_depth_10_merkle_path"
    );
    assert_eq!(
        handoff.fee_schedule_root,
        artifact.fee_schedule_root_bytes32
    );
    assert_eq!(
        handoff.fee_schedule_root_status,
        "air_constrained_canonical_verified_fee_leaf_depth_10_merkle_path_and_claim_source_links"
    );
    assert_eq!(handoff.air_public_input_count, 26);
    assert_eq!(handoff.proof_bytes_sha256, artifact.proof.sha256);
    assert!(!handoff.call_readiness.abi_call_ready);
    assert!(!handoff.call_readiness.runtime_activation_allowed);
    assert_eq!(
        handoff.call_readiness.unresolved_abi_fields,
        STARK_VERIFIER_V1_UNRESOLVED_ROOT_FIELDS
    );
    assert!(
        handoff
            .call_readiness
            .directly_available_abi_fields
            .contains(&"publicInputRoot".to_string())
    );
    assert!(
        handoff
            .call_readiness
            .directly_available_abi_fields
            .contains(&"claimSourceRoot".to_string())
    );
    assert!(
        handoff
            .call_readiness
            .directly_available_abi_fields
            .contains(&"oracleFactsRoot".to_string())
    );
    assert!(
        handoff
            .call_readiness
            .directly_available_abi_fields
            .contains(&"feeScheduleRoot".to_string())
    );
    assert!(
        handoff
            .call_readiness
            .derived_candidate_abi_fields
            .is_empty()
    );

    let encoded = serde_json::to_string_pretty(&handoff).unwrap();
    let decoded: ProductionStarkVerifierHandoffV4 = serde_json::from_str(&encoded).unwrap();
    decoded.validate().unwrap();

    let mut tampered_proof = decoded.clone();
    let replacement = if &tampered_proof.source_artifact.proof.bytes_hex[2..4] == "00" {
        "01"
    } else {
        "00"
    };
    tampered_proof
        .source_artifact
        .proof
        .bytes_hex
        .replace_range(2..4, replacement);
    assert!(tampered_proof.validate().is_err());

    let mut false_readiness = decoded.clone();
    false_readiness.call_readiness.abi_call_ready = true;
    false_readiness.call_readiness.runtime_activation_allowed = true;
    assert!(false_readiness.validate().is_err());

    let mut fake_root = decoded;
    fake_root.abi_fields[3].value =
        Some("0x1111111111111111111111111111111111111111111111111111111111111111".to_string());
    assert!(fake_root.validate().is_err());

    let mut fake_claim_source_root =
        ProductionStarkVerifierHandoffV4::from_proof_artifact(&artifact).unwrap();
    fake_claim_source_root.abi_fields[4].value =
        Some("0x2222222222222222222222222222222222222222222222222222222222222222".to_string());
    assert!(fake_claim_source_root.validate().is_err());

    let mut fake_oracle_facts_root =
        ProductionStarkVerifierHandoffV4::from_proof_artifact(&artifact).unwrap();
    fake_oracle_facts_root.abi_fields[5].value =
        Some("0x3333333333333333333333333333333333333333333333333333333333333333".to_string());
    assert!(fake_oracle_facts_root.validate().is_err());

    let mut fake_fee_schedule_root =
        ProductionStarkVerifierHandoffV4::from_proof_artifact(&artifact).unwrap();
    fake_fee_schedule_root.abi_fields[6].value =
        Some("0x4444444444444444444444444444444444444444444444444444444444444444".to_string());
    assert!(fake_fee_schedule_root.validate().is_err());
}

#[test]
fn denied_artifact_handoff_preserves_failure_semantics() {
    let mut bridge = approved_bridge();
    bridge.active_rust_facts.provider_enrolled = 0;
    bridge.adjudication.decision = 0;
    bridge.adjudication.failure_code = 501;
    bridge.adjudication.failure_reason = Some("G5_PROVIDER_NOT_ENROLLED".to_string());
    bridge.public_inputs.decision = 0;
    bridge.public_inputs.failure_code = 501;

    let artifact = ProductionStarkProofArtifactV4::from_bridge_input(&bridge).unwrap();
    let handoff = ProductionStarkVerifierHandoffV4::from_proof_artifact(&artifact).unwrap();

    assert_eq!(handoff.abi_fields[1].value.as_deref(), Some("0"));
    assert_eq!(handoff.abi_fields[2].value.as_deref(), Some("501"));
    handoff.validate().unwrap();
}

#[test]
fn rust_abi_lock_matches_the_solidity_candidate_source() {
    let source = include_str!("../../blind-ledger/src/IStarkClaimsVerifierV1Candidate.sol");
    assert!(source.contains("interface IStarkClaimsVerifierV1Candidate"));
    assert!(source.contains("function verifyStarkClaim("));

    let mut previous_position = 0;
    for (index, (name, solidity_type)) in STARK_VERIFIER_V1_ABI_FIELDS[..10].iter().enumerate() {
        let declaration = format!("{solidity_type} {name}");
        let position = source
            .find(&declaration)
            .unwrap_or_else(|| panic!("missing Solidity declaration: {declaration}"));
        if index > 0 {
            assert!(
                position > previous_position,
                "{declaration} is out of ABI order"
            );
        }
        previous_position = position;
    }
    assert!(source.contains("bytes calldata proof"));
}
