use fibonacci_lib::{
    abi_decode_public_values, abi_encode_public_values, expected_gates, expected_public_values,
    public_values_match_claim, public_values_match_context, ClaimInput,
};

fn approved_input() -> ClaimInput {
    ClaimInput {
        raw_claim_identity_commitment: claim_identity(0xA1),
        batch_context_commitment: batch_context(0xB1),
        member_id_present: true,
        eligibility_active: true,
        provider_npi_present: true,
        provider_enrolled: true,
        service_line_present: true,
        diagnosis_present: true,
        prior_auth_ok: true,
        charge_cents: 12_500,
        max_charge_cents: 500_000,
        duplicate_claim: false,
        program_integrity_hold: false,
    }
}

fn claim_identity(seed: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0] = seed;
    out[31] = seed ^ 0x5A;
    out
}

fn batch_context(seed: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0] = seed;
    out[1] = seed ^ 0x33;
    out[31] = seed ^ 0xC3;
    out
}

#[test]
fn native_rules_engine_outputs_match_guest_public_values_for_boundaries() {
    let mut cases = Vec::new();
    cases.push(("approved", approved_input(), (1, 0)));

    let mut all_zero = approved_input();
    all_zero.member_id_present = false;
    all_zero.eligibility_active = false;
    all_zero.provider_npi_present = false;
    all_zero.provider_enrolled = false;
    all_zero.service_line_present = false;
    all_zero.diagnosis_present = false;
    all_zero.prior_auth_ok = false;
    all_zero.charge_cents = 0;
    all_zero.duplicate_claim = true;
    all_zero.program_integrity_hold = true;
    cases.push(("all_zero_all_fail", all_zero, (0, 1)));

    let mut charge_zero = approved_input();
    charge_zero.charge_cents = 0;
    cases.push(("zero_charge", charge_zero, (0, 8)));

    let mut charge_at_limit = approved_input();
    charge_at_limit.charge_cents = 500_000;
    cases.push(("charge_at_native_limit", charge_at_limit, (1, 0)));

    let mut charge_over_limit = approved_input();
    charge_over_limit.charge_cents = 500_001;
    charge_over_limit.max_charge_cents = u32::MAX;
    cases.push(("attacker_high_max_charge_still_denied_by_native_engine", charge_over_limit, (0, 9)));

    let mut duplicate = approved_input();
    duplicate.duplicate_claim = true;
    cases.push(("duplicate", duplicate, (0, 10)));

    for (name, input, expected) in cases {
        assert_eq!(expected_public_values(&input), expected, "{name}");
    }
}

#[test]
fn public_values_bind_raw_claim_identity_and_reject_claim_swap() {
    let mut claim_a = approved_input();
    claim_a.raw_claim_identity_commitment = claim_identity(0xAA);
    let mut claim_b = claim_a;
    claim_b.raw_claim_identity_commitment = claim_identity(0xBB);
    let public_values = expected_public_values(&claim_a);
    let encoded = abi_encode_public_values(
        claim_a.raw_claim_identity_commitment,
        claim_a.batch_context_commitment,
        public_values.0,
        public_values.1,
    );

    assert!(public_values_match_claim(&encoded, claim_a.raw_claim_identity_commitment));
    assert!(!public_values_match_claim(&encoded, claim_b.raw_claim_identity_commitment));
}

#[test]
fn public_values_bind_batch_ruleset_payment_context_and_reject_context_swap() {
    let mut claim_a = approved_input();
    claim_a.batch_context_commitment = batch_context(0x11);
    let mut claim_b = claim_a;
    claim_b.batch_context_commitment = batch_context(0x22);
    let public_values = expected_public_values(&claim_a);
    let encoded = abi_encode_public_values(
        claim_a.raw_claim_identity_commitment,
        claim_a.batch_context_commitment,
        public_values.0,
        public_values.1,
    );

    assert!(public_values_match_context(
        &encoded,
        claim_a.raw_claim_identity_commitment,
        claim_a.batch_context_commitment
    ));
    assert!(!public_values_match_context(
        &encoded,
        claim_b.raw_claim_identity_commitment,
        claim_b.batch_context_commitment
    ));
}

#[test]
fn stale_max_charge_helper_is_canonically_aligned_to_real_engine() {
    let mut input = approved_input();
    input.charge_cents = 900_000;
    input.max_charge_cents = u32::MAX;

    let canonical_helper_gates = expected_gates(&input);
    let real_engine_public_values = expected_public_values(&input);

    assert!(!canonical_helper_gates[8]);
    assert_eq!(real_engine_public_values, (0, 9));
}

#[test]
fn public_value_decoder_rejects_out_of_range_values() {
    let bytes = abi_encode_public_values(claim_identity(0xCC), batch_context(0xCC), 2, 0);
    assert_eq!(abi_decode_public_values(&bytes), None);

    let bytes = abi_encode_public_values(claim_identity(0xCC), batch_context(0xCC), 1, 7);
    assert_eq!(abi_decode_public_values(&bytes), None);

    let bytes = abi_encode_public_values(claim_identity(0xCC), batch_context(0xCC), 0, 12);
    assert_eq!(abi_decode_public_values(&bytes), None);

    let bytes = abi_encode_public_values(claim_identity(0xCC), batch_context(0xCC), 1, 0);
    let decoded = abi_decode_public_values(&bytes).expect("valid public values rejected");
    assert_eq!(decoded.raw_claim_identity_commitment, claim_identity(0xCC));
    assert_eq!(decoded.batch_context_commitment, batch_context(0xCC));
    assert_eq!(decoded.decision, 1);
    assert_eq!(decoded.failure_code, 0);
}
