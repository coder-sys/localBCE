use serde_json::json;
use winterfell::{
    Trace,
    math::{FieldElement, ToElements},
};

use super::{
    COL_NULLIFIER_PATH_DIRECTION, FACT_COMMITMENT_DOMAIN_TAG, FACT_COMMITMENT_FACT_ORDER,
    FACT_COMMITMENT_HASH_FUNCTION, FACT_COMMITMENT_RULESET_TAG, FACT_COMMITMENT_SCHEMA_VERSION,
    NULLIFIER_AFTER_MERKLE_TRACE_START, NULLIFIER_BEFORE_MERKLE_TRACE_START,
    NULLIFIER_MERKLE_LEVEL_LENGTH, PUBLIC_INPUT_ROOT_DOMAIN_TAG, PUBLIC_INPUT_ROOT_ENCODING,
    PUBLIC_INPUT_ROOT_HASH_FUNCTION, PUBLIC_INPUT_ROOT_PREIMAGE_ORDER,
    PUBLIC_INPUT_ROOT_RULESET_TAG, PUBLIC_INPUT_ROOT_SCHEMA_VERSION, ProductionAirProofInputV2,
    ProductionFelt, TRACE_LENGTH, TRACE_WIDTH, build_production_air_trace,
    canonical_claim_fact_commitment_preimage, canonical_public_input_root_preimage,
    compute_claim_fact_commitment, compute_public_input_root, compute_single_claim_batch_root,
    pack_public_input_root_bytes32, prove_production_air, unpack_public_input_root_bytes32,
    verify_production_air, verify_production_air_result,
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
                "demo-attestation:eligibility_active:CLAIM-PRODUCTION-AIR-PROOF-001"
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

fn approved_proof_input() -> ProductionAirProofInputV2 {
    ProductionAirProofInputV2::from_bridge_input(&approved_bridge()).unwrap()
}

#[test]
fn approved_input_builds_expected_trace_dimensions() {
    let input = approved_proof_input();
    let trace = build_production_air_trace(&input).unwrap();

    assert_eq!(trace.width(), TRACE_WIDTH);
    assert_eq!(trace.length(), TRACE_LENGTH);
}

#[test]
fn nullifier_merkle_directions_are_bound_to_public_claim_hash_bits() {
    let input = approved_proof_input();
    let trace = build_production_air_trace(&input).unwrap();
    let expected_index = (0x2222usize) & ((1 << 10) - 1);
    assert_eq!(input.nullifier.leaf_index, expected_index);
    assert_ne!(expected_index, 0);

    for level in 0..10 {
        let expected = ProductionFelt::from(((expected_index >> level) & 1) as u32);
        let before_step =
            NULLIFIER_BEFORE_MERKLE_TRACE_START - 1 + level * NULLIFIER_MERKLE_LEVEL_LENGTH;
        let after_step =
            NULLIFIER_AFTER_MERKLE_TRACE_START - 1 + level * NULLIFIER_MERKLE_LEVEL_LENGTH;
        assert_eq!(
            trace.get(COL_NULLIFIER_PATH_DIRECTION, before_step),
            expected
        );
        assert_eq!(
            trace.get(COL_NULLIFIER_PATH_DIRECTION, after_step),
            expected
        );
    }
}

#[test]
fn approved_g1_g10_production_air_proof_verifies_locally() {
    let input = approved_proof_input();
    let (proof, public_inputs) = prove_production_air(&input).unwrap();

    assert_eq!(public_inputs.decision, ProductionFelt::ONE);
    assert_eq!(public_inputs.failure_code, ProductionFelt::ZERO);
    assert_eq!(
        public_inputs.public_input_root,
        compute_public_input_root(&input).unwrap()
    );
    let serialized_public_inputs = public_inputs.to_elements();
    assert_eq!(serialized_public_inputs.len(), 38);
    assert_eq!(
        &serialized_public_inputs[..8],
        &public_inputs.claim_hash_limbs
    );
    assert_eq!(
        &serialized_public_inputs[8..12],
        &public_inputs.public_input_root
    );
    assert_eq!(
        &serialized_public_inputs[12..16],
        &public_inputs.claim_source_root
    );
    assert_eq!(
        &serialized_public_inputs[16..20],
        &public_inputs.oracle_facts_root
    );
    assert_eq!(
        &serialized_public_inputs[20..24],
        &public_inputs.fee_schedule_root
    );
    assert_eq!(
        &serialized_public_inputs[24..28],
        &public_inputs.nullifier_root_before
    );
    assert_eq!(
        &serialized_public_inputs[28..32],
        &public_inputs.nullifier_root_after
    );
    assert_eq!(
        public_inputs.batch_root,
        compute_single_claim_batch_root(&public_inputs.public_input_root)
    );
    assert_eq!(&serialized_public_inputs[32..36], &public_inputs.batch_root);
    assert_eq!(serialized_public_inputs[36], public_inputs.decision);
    assert_eq!(serialized_public_inputs[37], public_inputs.failure_code);
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

        let input = ProductionAirProofInputV2::from_bridge_input(&bridge).unwrap();
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
    let input = approved_proof_input();
    let (proof, mut public_inputs) = prove_production_air(&input).unwrap();
    public_inputs.claim_hash_limbs[0] += ProductionFelt::ONE;

    assert!(!verify_production_air(proof, public_inputs));
}

#[test]
fn tampered_public_input_root_is_rejected() {
    let input = approved_proof_input();
    let (proof, mut public_inputs) = prove_production_air(&input).unwrap();
    public_inputs.public_input_root[0] += ProductionFelt::ONE;

    assert!(!verify_production_air(proof, public_inputs));
}

#[test]
fn tampered_public_claim_source_root_is_rejected() {
    let input = approved_proof_input();
    let (proof, mut public_inputs) = prove_production_air(&input).unwrap();
    public_inputs.claim_source_root[0] += ProductionFelt::ONE;

    assert!(!verify_production_air(proof, public_inputs));
}

#[test]
fn tampered_public_oracle_facts_root_is_rejected() {
    let input = approved_proof_input();
    let (proof, mut public_inputs) = prove_production_air(&input).unwrap();
    public_inputs.oracle_facts_root[0] += ProductionFelt::ONE;

    assert!(!verify_production_air(proof, public_inputs));
}

#[test]
fn tampered_public_fee_schedule_root_is_rejected() {
    let input = approved_proof_input();
    let (proof, mut public_inputs) = prove_production_air(&input).unwrap();
    public_inputs.fee_schedule_root[0] += ProductionFelt::ONE;

    assert!(!verify_production_air(proof, public_inputs));
}

#[test]
fn tampered_public_nullifier_roots_are_rejected() {
    let input = approved_proof_input();
    let (proof, mut public_inputs) = prove_production_air(&input).unwrap();
    public_inputs.nullifier_root_before[0] += ProductionFelt::ONE;
    assert!(!verify_production_air(proof, public_inputs));

    let (proof, mut public_inputs) = prove_production_air(&input).unwrap();
    public_inputs.nullifier_root_after[0] += ProductionFelt::ONE;
    assert!(!verify_production_air(proof, public_inputs));
}

#[test]
fn forged_nullifier_preimage_path_and_roots_are_rejected_before_proving() {
    let original = approved_proof_input();

    let mut forged_preimage = original.clone();
    forged_preimage.nullifier.preimage[4] += ProductionFelt::ONE;
    assert!(prove_production_air(&forged_preimage).is_err());

    let mut forged_path = original.clone();
    forged_path.nullifier.merkle_path[0][0] += ProductionFelt::ONE;
    assert!(prove_production_air(&forged_path).is_err());

    let mut forged_before = original.clone();
    forged_before.nullifier.root_before[0] += ProductionFelt::ONE;
    assert!(prove_production_air(&forged_before).is_err());

    let mut forged_after = original;
    forged_after.nullifier.root_after[0] += ProductionFelt::ONE;
    assert!(prove_production_air(&forged_after).is_err());
}

#[test]
fn forged_claim_source_leaf_path_and_root_are_rejected_before_proving() {
    let original = approved_proof_input();

    let mut forged_leaf = original.clone();
    forged_leaf.claim_source.leaf_preimage[12] += ProductionFelt::ONE;
    assert!(prove_production_air(&forged_leaf).is_err());

    let mut forged_path = original.clone();
    forged_path.claim_source.merkle_path[0][0] += ProductionFelt::ONE;
    assert!(prove_production_air(&forged_path).is_err());

    let mut forged_root = original;
    forged_root.claim_source.root[0] += ProductionFelt::ONE;
    assert!(prove_production_air(&forged_root).is_err());
}

#[test]
fn forged_oracle_facts_leaf_path_and_root_are_rejected_before_proving() {
    let original = approved_proof_input();

    let mut forged_leaf = original.clone();
    forged_leaf.oracle_facts.leaf_preimage[12] += ProductionFelt::ONE;
    assert!(prove_production_air(&forged_leaf).is_err());

    let mut forged_path = original.clone();
    forged_path.oracle_facts.merkle_path[0][0] += ProductionFelt::ONE;
    assert!(prove_production_air(&forged_path).is_err());

    let mut forged_root = original;
    forged_root.oracle_facts.root[0] += ProductionFelt::ONE;
    assert!(prove_production_air(&forged_root).is_err());
}

#[test]
fn forged_fee_schedule_leaf_path_and_root_are_rejected_before_proving() {
    let original = approved_proof_input();

    let mut forged_leaf = original.clone();
    forged_leaf.fee_schedule.leaf_preimage[12] += ProductionFelt::ONE;
    assert!(prove_production_air(&forged_leaf).is_err());

    let mut forged_path = original.clone();
    forged_path.fee_schedule.merkle_path[0][0] += ProductionFelt::ONE;
    assert!(prove_production_air(&forged_path).is_err());

    let mut forged_root = original.clone();
    forged_root.fee_schedule.root[0] += ProductionFelt::ONE;
    assert!(prove_production_air(&forged_root).is_err());

    let mut forged_service_digest = original.clone();
    forged_service_digest.fee_schedule.leaf_preimage[20] += ProductionFelt::ONE;
    assert!(prove_production_air(&forged_service_digest).is_err());

    let mut forged_service_date = original.clone();
    forged_service_date.fee_schedule.leaf_preimage[29] += ProductionFelt::ONE;
    assert!(prove_production_air(&forged_service_date).is_err());

    let mut forged_total_charge = original;
    forged_total_charge.fee_schedule.leaf_preimage[31] += ProductionFelt::ONE;
    assert!(prove_production_air(&forged_total_charge).is_err());
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

fn refresh_outcome_and_nullifier(input: &mut ProductionAirProofInputV2) {
    refresh_outcome(&mut input.adjudication);
    if input.adjudication.expected_outcome.decision == 0 {
        input.nullifier.root_after = input.nullifier.root_before;
        input.nullifier.state_generation_after = input.nullifier.state_generation_before;
    }
}

#[test]
fn every_g1_g10_fact_is_bound_to_the_public_input_root() {
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

    let approved = approved_proof_input();
    let original_root = compute_public_input_root(&approved).unwrap();

    for (field, mutate) in mutations {
        let mut mutated = if field == "date_of_service_from" {
            let mut bridge = approved_bridge();
            bridge.active_rust_facts.date_of_service_from += 1;
            ProductionAirProofInputV2::from_bridge_input(&bridge).unwrap()
        } else {
            approved.clone()
        };
        if field != "date_of_service_from" {
            mutate(&mut mutated.adjudication.facts);
            refresh_outcome_and_nullifier(&mut mutated);
        }

        let (proof, mut public_inputs) = prove_production_air(&mutated).unwrap();
        assert_ne!(
            public_inputs.public_input_root, original_root,
            "{field} must change the public input root"
        );

        public_inputs.public_input_root = original_root;
        assert!(
            !verify_production_air(proof, public_inputs),
            "{field} must not verify against the original public input root"
        );
    }
}

#[test]
fn public_input_root_encoding_has_stable_domain_order_and_bytes32_round_trip() {
    let input = approved_proof_input();
    let elements = canonical_public_input_root_preimage(&input).unwrap();
    let fact_commitment = compute_claim_fact_commitment(&input.adjudication).unwrap();
    let root = compute_public_input_root(&input).unwrap();
    let packed = pack_public_input_root_bytes32(&root);

    assert!(root.iter().any(|element| *element != ProductionFelt::ZERO));
    assert_eq!(
        PUBLIC_INPUT_ROOT_SCHEMA_VERSION,
        "stark-public-input-root-v5"
    );
    assert_eq!(PUBLIC_INPUT_ROOT_HASH_FUNCTION, "winterfell-rp64-256");
    assert_eq!(
        PUBLIC_INPUT_ROOT_ENCODING,
        "bytes32-four-canonical-f64-big-endian"
    );
    assert_eq!(elements[0].as_int(), PUBLIC_INPUT_ROOT_DOMAIN_TAG);
    assert_eq!(elements[1].as_int(), 5);
    assert_eq!(elements[2].as_int(), PUBLIC_INPUT_ROOT_RULESET_TAG);
    assert_eq!(elements[3].as_int(), 34);
    assert_eq!(
        PUBLIC_INPUT_ROOT_PREIMAGE_ORDER,
        [
            "claim_hash_be_u32_limb_0",
            "claim_hash_be_u32_limb_1",
            "claim_hash_be_u32_limb_2",
            "claim_hash_be_u32_limb_3",
            "claim_hash_be_u32_limb_4",
            "claim_hash_be_u32_limb_5",
            "claim_hash_be_u32_limb_6",
            "claim_hash_be_u32_limb_7",
            "fact_commitment_element_0",
            "fact_commitment_element_1",
            "fact_commitment_element_2",
            "fact_commitment_element_3",
            "claim_source_root_element_0",
            "claim_source_root_element_1",
            "claim_source_root_element_2",
            "claim_source_root_element_3",
            "oracle_facts_root_element_0",
            "oracle_facts_root_element_1",
            "oracle_facts_root_element_2",
            "oracle_facts_root_element_3",
            "fee_schedule_root_element_0",
            "fee_schedule_root_element_1",
            "fee_schedule_root_element_2",
            "fee_schedule_root_element_3",
            "nullifier_root_before_element_0",
            "nullifier_root_before_element_1",
            "nullifier_root_before_element_2",
            "nullifier_root_before_element_3",
            "nullifier_root_after_element_0",
            "nullifier_root_after_element_1",
            "nullifier_root_after_element_2",
            "nullifier_root_after_element_3",
            "decision",
            "failure_code",
        ]
    );
    assert_eq!(
        elements[12..16]
            .iter()
            .map(|element| element.as_int())
            .collect::<Vec<_>>(),
        fact_commitment
            .iter()
            .map(|element| element.as_int())
            .collect::<Vec<_>>()
    );
    assert_eq!(&elements[16..20], &input.claim_source.root);
    assert_eq!(&elements[20..24], &input.oracle_facts.root);
    assert_eq!(&elements[24..28], &input.fee_schedule.root);
    assert_eq!(&elements[28..32], &input.nullifier.root_before);
    assert_eq!(&elements[32..36], &input.nullifier.root_after);
    assert_eq!(elements[36].as_int(), 1);
    assert_eq!(elements[37].as_int(), 0);
    assert_eq!(packed.len(), 66);
    assert_eq!(unpack_public_input_root_bytes32(&packed).unwrap(), root);
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
    let mut bridge = approved_bridge();
    bridge.active_rust_facts.date_of_service_from = u32::MAX as u64;
    bridge.active_rust_facts.eligibility_period_from = 0;
    bridge.active_rust_facts.eligibility_period_thru = u32::MAX as u64;
    bridge.claim.fee_schedule_entries[0].effective_from = 1;
    bridge.claim.fee_schedule_entries[0].effective_thru = Some(u32::MAX as u64);
    let input = ProductionAirProofInputV2::from_bridge_input(&bridge).unwrap();

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
