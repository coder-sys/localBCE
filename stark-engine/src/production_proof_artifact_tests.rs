use serde_json::json;

use super::{
    PRODUCTION_STARK_PUBLIC_INPUT_ORDER, ProductionStarkProofArtifactV2,
    ProductionStarkProofBytesV2,
};
use crate::{
    StarkBridgeInput,
    production_air_winterfell::{
        PUBLIC_INPUT_ROOT_ENCODING, PUBLIC_INPUT_ROOT_HASH_FUNCTION,
        PUBLIC_INPUT_ROOT_SCHEMA_VERSION, unpack_public_input_root_bytes32,
    },
};

fn approved_bridge() -> StarkBridgeInput {
    serde_json::from_value(json!({
        "schema_version": "stark-bridge-input-v0",
        "producer": "rust-engine",
        "purpose": "stark_engine_compatibility_input",
        "runtime_mode": "dry_run_or_optional_sidecar",
        "claim": {
            "claim_id": "CLAIM-PRODUCTION-ARTIFACT-001",
            "claim_amount": 1000,
            "claim_hash": "0xaaaaaaaaaaaaaaaa1111111111111111bbbbbbbbbbbbbbbb2222222222222222",
            "member_id": "MEMBER-001",
            "provider_npi": "1234567893",
            "diagnosis_count": 1,
            "max_charge_cents": 100000
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
fn approved_artifact_round_trips_and_reverifies_from_saved_bytes() {
    let artifact = ProductionStarkProofArtifactV2::from_bridge_input(&approved_bridge()).unwrap();

    assert_eq!(artifact.public_inputs.count, 14);
    assert_eq!(
        artifact.public_inputs.order,
        PRODUCTION_STARK_PUBLIC_INPUT_ORDER
    );
    assert_eq!(artifact.decision, 1);
    assert_eq!(artifact.failure_code, 0);
    assert_eq!(
        artifact.schema_version,
        "stark-production-proof-artifact-v2"
    );
    assert_eq!(
        artifact.public_inputs.schema_version,
        "stark-production-public-inputs-v2"
    );
    assert_eq!(
        artifact.public_input_root_schema_version,
        PUBLIC_INPUT_ROOT_SCHEMA_VERSION
    );
    assert_eq!(
        artifact.public_input_root_hash,
        PUBLIC_INPUT_ROOT_HASH_FUNCTION
    );
    assert_eq!(
        artifact.public_input_root_encoding,
        PUBLIC_INPUT_ROOT_ENCODING
    );
    assert_eq!(artifact.public_input_root_bytes32.len(), 66);
    let packed_root = unpack_public_input_root_bytes32(&artifact.public_input_root_bytes32)
        .unwrap()
        .map(|value| value.as_int().to_string());
    assert_eq!(&artifact.public_inputs.values_decimal[8..12], &packed_root);
    assert!(artifact.locally_verified);
    assert!(!artifact.runtime_wired);
    assert!(!artifact.on_chain_verifier_wired);
    assert!(artifact.groth16_flow_unchanged);
    assert!(artifact.proof.size_bytes > 0);

    let json = serde_json::to_string_pretty(&artifact).unwrap();
    let decoded: ProductionStarkProofArtifactV2 = serde_json::from_str(&json).unwrap();
    decoded.validate().unwrap();
    decoded.verify_serialized_proof().unwrap();

    let mut tampered_proof = decoded.clone();
    let replacement = if &tampered_proof.proof.bytes_hex[2..4] == "00" {
        "01"
    } else {
        "00"
    };
    tampered_proof
        .proof
        .bytes_hex
        .replace_range(2..4, replacement);
    assert!(tampered_proof.validate().is_err());

    let mut trailing_proof = decoded.clone();
    trailing_proof.proof.bytes_hex.push_str("00");
    trailing_proof.proof.size_bytes += 1;
    assert!(trailing_proof.validate().is_err());

    let mut tampered_public_input = decoded;
    tampered_public_input.public_inputs.values_decimal[12] = "0".to_string();
    assert!(tampered_public_input.validate().is_err());

    let mut tampered_root = artifact;
    tampered_root.public_input_root_bytes32 =
        "0x0000000000000000000000000000000000000000000000000000000000000000".to_string();
    assert!(tampered_root.validate().is_err());
}

#[test]
fn denied_artifact_preserves_and_proves_the_failure_code() {
    let mut bridge = approved_bridge();
    bridge.active_rust_facts.is_duplicate = 1;
    bridge.adjudication.decision = 0;
    bridge.adjudication.failure_code = 7;
    bridge.adjudication.failure_reason = Some("G7_DUPLICATE_CLAIM".to_string());
    bridge.public_inputs.decision = 0;
    bridge.public_inputs.failure_code = 7;

    let artifact = ProductionStarkProofArtifactV2::from_bridge_input(&bridge).unwrap();

    assert_eq!(artifact.decision, 0);
    assert_eq!(artifact.failure_code, 7);
    assert_eq!(artifact.public_inputs.values_decimal[12], "0");
    assert_eq!(artifact.public_inputs.values_decimal[13], "7");
    artifact.validate().unwrap();
}

#[test]
fn malformed_artifact_metadata_is_rejected_before_runtime_use() {
    let mut artifact =
        ProductionStarkProofArtifactV2::from_bridge_input(&approved_bridge()).unwrap();
    artifact.proof.encoding = "base64".to_string();
    artifact.runtime_wired = true;
    artifact.on_chain_verifier_wired = true;

    let errors = artifact.validate().unwrap_err();
    assert!(errors.iter().any(|error| error.contains("proof.encoding")));
    assert!(errors.iter().any(|error| error.contains("runtime_wired")));
    assert!(
        errors
            .iter()
            .any(|error| error.contains("on_chain_verifier_wired"))
    );
    assert_ne!(
        artifact.proof.encoding,
        ProductionStarkProofBytesV2::ENCODING
    );
}
