use serde_json::json;
use winterfell::{
    Trace,
    math::{FieldElement, ToElements},
};

use super::{
    FACT_COMMITMENT_DOMAIN_TAG, FACT_COMMITMENT_FACT_ORDER, FACT_COMMITMENT_HASH_FUNCTION,
    FACT_COMMITMENT_RULESET_TAG, FACT_COMMITMENT_SCHEMA_VERSION, ProductionFelt, TRACE_LENGTH,
    TRACE_WIDTH, build_production_air_trace, canonical_claim_fact_commitment_preimage,
    compute_claim_fact_commitment, prove_production_air, verify_production_air,
    verify_production_air_result,
};
use crate::{
    StarkBridgeInput,
    production_air::{ProductionAirFactsV1, ProductionAirInputV1, evaluate_outcome},
};

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
    assert_eq!(
        public_inputs.fact_commitment,
        compute_claim_fact_commitment(&input).unwrap()
    );
    assert_eq!(
        public_inputs
            .fact_commitment
            .map(|element| element.as_int()),
        [
            16_061_359_094_615_131_833,
            3_238_905_742_128_385_486,
            15_582_228_309_714_766_258,
            7_389_683_813_284_618_181,
        ]
    );
    let serialized_public_inputs = public_inputs.to_elements();
    assert_eq!(serialized_public_inputs.len(), 14);
    assert_eq!(
        &serialized_public_inputs[..8],
        &public_inputs.claim_hash_limbs
    );
    assert_eq!(
        &serialized_public_inputs[8..12],
        &public_inputs.fact_commitment
    );
    assert_eq!(serialized_public_inputs[12], public_inputs.decision);
    assert_eq!(serialized_public_inputs[13], public_inputs.failure_code);
    verify_production_air_result(proof, public_inputs).unwrap();
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
fn tampered_public_fact_commitment_is_rejected() {
    let input = ProductionAirInputV1::from_bridge_input(&approved_bridge()).unwrap();
    let (proof, mut public_inputs) = prove_production_air(&input).unwrap();
    public_inputs.fact_commitment[0] += ProductionFelt::ONE;

    assert!(!verify_production_air(proof, public_inputs));
}

#[test]
fn canonical_commitment_encoding_has_stable_domain_order_and_lossless_hash_limbs() {
    let input = ProductionAirInputV1::from_bridge_input(&approved_bridge()).unwrap();
    let elements = canonical_claim_fact_commitment_preimage(&input).unwrap();

    assert_eq!(
        FACT_COMMITMENT_SCHEMA_VERSION,
        "stark-claim-fact-commitment-v1"
    );
    assert_eq!(FACT_COMMITMENT_HASH_FUNCTION, "winterfell-rp64-256");
    assert_eq!(
        FACT_COMMITMENT_FACT_ORDER,
        [
            "eligibility_active",
            "aid_code",
            "benefit_level_exists",
            "date_of_service_from",
            "eligibility_period_from",
            "eligibility_period_thru",
            "soc_amount",
            "soc_met",
            "provider_enrolled",
            "provider_type_valid",
            "billing_code_valid",
            "units_valid",
            "is_duplicate",
            "disability_determination_valid",
            "recipient_not_deceased",
            "physician_certification_valid",
        ]
    );
    assert_eq!(elements[0].as_int(), FACT_COMMITMENT_DOMAIN_TAG);
    assert_eq!(elements[1].as_int(), 1);
    assert_eq!(elements[2].as_int(), FACT_COMMITMENT_RULESET_TAG);
    assert_eq!(elements[3].as_int(), 16);
    assert_eq!(
        elements[4..12]
            .iter()
            .map(|element| element.as_int())
            .collect::<Vec<_>>(),
        vec![
            0xaaaa_aaaa,
            0xaaaa_aaaa,
            0x1111_1111,
            0x1111_1111,
            0xbbbb_bbbb,
            0xbbbb_bbbb,
            0x2222_2222,
            0x2222_2222,
        ]
    );
    assert_eq!(
        elements[12..]
            .iter()
            .map(|element| element.as_int())
            .collect::<Vec<_>>(),
        vec![
            1, 53, 1, 20_000, 19_900, 21_000, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1,
        ]
    );

    let mut max_limb_input = input;
    max_limb_input.claim_hash = format!("0x{}", "ffffffff".repeat(8));
    let max_limb_elements = canonical_claim_fact_commitment_preimage(&max_limb_input).unwrap();
    assert!(
        max_limb_elements[4..12]
            .iter()
            .all(|element| element.as_int() == u32::MAX as u64)
    );
}

fn refresh_outcome(input: &mut ProductionAirInputV1) {
    input.expected_outcome = evaluate_outcome(&input.facts);
}

#[test]
fn every_g1_g10_fact_is_bound_to_the_public_fact_commitment() {
    type Mutate = fn(&mut ProductionAirFactsV1);
    let mutations: [(&str, Mutate); 16] = [
        ("eligibility_active", |facts| facts.eligibility_active = 0),
        ("aid_code", |facts| facts.aid_code = 103),
        ("benefit_level_exists", |facts| {
            facts.benefit_level_exists = 0
        }),
        ("date_of_service_from", |facts| {
            facts.date_of_service_from += 1
        }),
        ("eligibility_period_from", |facts| {
            facts.eligibility_period_from -= 1
        }),
        ("eligibility_period_thru", |facts| {
            facts.eligibility_period_thru += 1
        }),
        ("soc_amount", |facts| facts.soc_amount = 1),
        ("soc_met", |facts| facts.soc_met = 0),
        ("provider_enrolled", |facts| facts.provider_enrolled = 0),
        ("provider_type_valid", |facts| facts.provider_type_valid = 0),
        ("billing_code_valid", |facts| facts.billing_code_valid = 0),
        ("units_valid", |facts| facts.units_valid = 0),
        ("is_duplicate", |facts| facts.is_duplicate = 1),
        ("disability_determination_valid", |facts| {
            facts.disability_determination_valid = 0
        }),
        ("recipient_not_deceased", |facts| {
            facts.recipient_not_deceased = 0
        }),
        ("physician_certification_valid", |facts| {
            facts.physician_certification_valid = 0
        }),
    ];

    let approved = ProductionAirInputV1::from_bridge_input(&approved_bridge()).unwrap();
    let original_commitment = compute_claim_fact_commitment(&approved).unwrap();

    for (field, mutate) in mutations {
        let mut mutated = approved.clone();
        mutate(&mut mutated.facts);
        refresh_outcome(&mut mutated);

        let (proof, mut public_inputs) = prove_production_air(&mutated).unwrap();
        assert_ne!(
            public_inputs.fact_commitment, original_commitment,
            "{field} must change the fact commitment"
        );

        public_inputs.fact_commitment = original_commitment;
        assert!(
            !verify_production_air(proof, public_inputs),
            "{field} must not verify against the original fact commitment"
        );
    }
}

#[test]
fn fact_commitment_binds_the_existing_claim_identity_hash() {
    let original = ProductionAirInputV1::from_bridge_input(&approved_bridge()).unwrap();
    let mut different_claim = original.clone();
    different_claim.claim_hash =
        "0xaaaaaaaaaaaaaaaa1111111111111111bbbbbbbbbbbbbbbb2222222222222223".to_string();

    assert_ne!(
        compute_claim_fact_commitment(&original).unwrap(),
        compute_claim_fact_commitment(&different_claim).unwrap()
    );
}

#[test]
fn values_outside_the_v1_32_bit_range_are_rejected_before_commitment_encoding() {
    let mut input = ProductionAirInputV1::from_bridge_input(&approved_bridge()).unwrap();
    input.facts.eligibility_period_thru = u64::MAX;
    refresh_outcome(&mut input);

    let errors = compute_claim_fact_commitment(&input).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.contains("must fit in 32 bits"))
    );
}

#[test]
fn v1_32_bit_date_boundary_proves_without_field_wraparound() {
    let mut input = ProductionAirInputV1::from_bridge_input(&approved_bridge()).unwrap();
    input.facts.date_of_service_from = u32::MAX as u64;
    input.facts.eligibility_period_from = 0;
    input.facts.eligibility_period_thru = u32::MAX as u64;
    refresh_outcome(&mut input);

    let (proof, public_inputs) = prove_production_air(&input).unwrap();
    assert!(verify_production_air(proof, public_inputs));
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
