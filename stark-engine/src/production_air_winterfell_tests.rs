use serde_json::json;
use winterfell::{Trace, math::FieldElement};

use super::{
    ProductionFelt, TRACE_LENGTH, TRACE_WIDTH, build_production_air_trace, prove_production_air,
    verify_production_air,
};
use crate::{StarkBridgeInput, production_air::ProductionAirInputV1};

fn approved_bridge() -> StarkBridgeInput {
    serde_json::from_value(json!({
        "schema_version": "stark-bridge-input-v0",
        "producer": "rust-engine",
        "purpose": "stark_engine_compatibility_input",
        "runtime_mode": "dry_run_or_optional_sidecar",
        "claim": {
            "claim_id": "CLAIM-PRODUCTION-AIR-PROOF-001",
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
fn approved_input_builds_expected_trace_dimensions() {
    let input = ProductionAirInputV1::from_bridge_input(&approved_bridge()).unwrap();
    let trace = build_production_air_trace(&input).unwrap();

    assert_eq!(trace.width(), TRACE_WIDTH);
    assert_eq!(trace.length(), TRACE_LENGTH);
}

#[test]
fn approved_g1_g10_production_air_proof_verifies_locally() {
    let input = ProductionAirInputV1::from_bridge_input(&approved_bridge()).unwrap();
    let (proof, public_inputs) = prove_production_air(&input).unwrap();

    assert_eq!(public_inputs.decision, ProductionFelt::ONE);
    assert_eq!(public_inputs.failure_code, ProductionFelt::ZERO);
    assert!(verify_production_air(proof, public_inputs));
}

fn set_denial(bridge: &mut StarkBridgeInput, reason: &str, failure_code: u32) {
    bridge.adjudication.decision = 0;
    bridge.adjudication.failure_code = failure_code;
    bridge.adjudication.failure_reason = Some(reason.to_string());
    bridge.public_inputs.decision = 0;
    bridge.public_inputs.failure_code = failure_code;
}

#[test]
fn all_denied_g1_g10_production_air_proofs_verify_with_first_failure_codes() {
    type Mutate = fn(&mut StarkBridgeInput);
    let cases: [(&str, u32, Mutate); 13] = [
        ("G1_IDENTITY_VERIFICATION_FAILED", 1, |bridge| {
            bridge.active_rust_facts.eligibility_active = 0
        }),
        ("G2_PROGRAM_ELIGIBILITY_FAILED", 201, |bridge| {
            bridge.active_rust_facts.aid_code = 999
        }),
        ("G2_BENEFIT_LEVEL_MISSING", 202, |bridge| {
            bridge.active_rust_facts.benefit_level_exists = 0
        }),
        ("G3_MONTH_OF_SERVICE_FAILED", 3, |bridge| {
            bridge.active_rust_facts.date_of_service_from =
                bridge.active_rust_facts.eligibility_period_thru + 1
        }),
        ("G4_SHARE_OF_COST_FAILED", 4, |bridge| {
            bridge.active_rust_facts.soc_amount = 100;
            bridge.active_rust_facts.soc_met = 0;
        }),
        ("G5_PROVIDER_NOT_ENROLLED", 501, |bridge| {
            bridge.active_rust_facts.provider_enrolled = 0
        }),
        ("G5_PROVIDER_TYPE_INVALID", 502, |bridge| {
            bridge.active_rust_facts.provider_type_valid = 0
        }),
        ("G6_BILLING_CODE_INVALID", 601, |bridge| {
            bridge.active_rust_facts.billing_code_valid = 0
        }),
        ("G6_UNITS_INVALID", 602, |bridge| {
            bridge.active_rust_facts.units_valid = 0
        }),
        ("G7_DUPLICATE_CLAIM", 7, |bridge| {
            bridge.active_rust_facts.is_duplicate = 1
        }),
        ("G8_DISABILITY_DETERMINATION_FAILED", 8, |bridge| {
            bridge.active_rust_facts.disability_determination_valid = 0
        }),
        ("G9_RECIPIENT_DECEASED", 9, |bridge| {
            bridge.active_rust_facts.recipient_not_deceased = 0
        }),
        ("G10_PHYSICIAN_CERTIFICATION_FAILED", 10, |bridge| {
            bridge.active_rust_facts.physician_certification_valid = 0
        }),
    ];

    for (reason, failure_code, mutate) in cases {
        let mut bridge = approved_bridge();
        mutate(&mut bridge);
        set_denial(&mut bridge, reason, failure_code);

        let input = ProductionAirInputV1::from_bridge_input(&bridge).unwrap();
        let (proof, public_inputs) = prove_production_air(&input).unwrap();

        assert_eq!(public_inputs.decision, ProductionFelt::ZERO, "{reason}");
        assert_eq!(
            public_inputs.failure_code,
            ProductionFelt::from(failure_code),
            "{reason}"
        );
        assert!(verify_production_air(proof, public_inputs), "{reason}");
    }
}

#[test]
fn tampered_public_claim_hash_limb_is_rejected() {
    let input = ProductionAirInputV1::from_bridge_input(&approved_bridge()).unwrap();
    let (proof, mut public_inputs) = prove_production_air(&input).unwrap();
    public_inputs.claim_hash_limbs[0] += ProductionFelt::ONE;

    assert!(!verify_production_air(proof, public_inputs));
}

#[test]
fn mismatched_adjudication_cannot_enter_winterfell_trace() {
    let mut bridge = approved_bridge();
    bridge.active_rust_facts.provider_enrolled = 0;

    let errors = ProductionAirInputV1::from_bridge_input(&bridge).unwrap_err();

    assert!(
        errors
            .iter()
            .any(|error| error.contains("expected_outcome does not match G1-G10 semantics"))
    );
}
