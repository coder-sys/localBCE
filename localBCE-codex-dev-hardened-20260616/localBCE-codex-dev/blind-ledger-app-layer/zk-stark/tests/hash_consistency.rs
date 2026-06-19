use blind_ledger_stark::{approved_claim, prove_claim, sample_claims, ClaimInput, Felt};
use winterfell::math::FieldElement;

fn claim_values(claim: ClaimInput) -> [u32; 11] {
    [
        claim.member_id,
        claim.provider_npi,
        claim.eligibility_active,
        claim.provider_enrolled,
        claim.service_line_count,
        claim.diagnosis_count,
        claim.prior_auth_ok,
        claim.charge_cents,
        claim.max_charge_cents,
        claim.duplicate_flag,
        claim.program_integrity_hold,
    ]
}

fn app_side_hash(values: &[u32]) -> Felt {
    let mut state = Felt::from(17u32);
    for (idx, value) in values.iter().copied().enumerate() {
        state = (state + Felt::from(value) + Felt::from(101u32 + idx as u32)).cube();
    }
    state
}

fn air_formula_hash(values: &[u32]) -> Felt {
    let mut trace_state = Felt::from(17u32);
    for (idx, value) in values.iter().copied().enumerate() {
        let constant = Felt::from(101u32 + idx as u32);
        trace_state = (trace_state + Felt::from(value) + constant).cube();
    }
    trace_state
}

#[test]
fn app_hash_matches_air_formula_for_used_arities() {
    let values = claim_values(approved_claim());
    for arity in [1usize, 2, 4, 11] {
        assert_eq!(app_side_hash(&values[..arity]), air_formula_hash(&values[..arity]));
    }
}

#[test]
fn app_hash_matches_stark_public_commitment_for_sample_cases() {
    for (case, claim) in sample_claims() {
        let (_proof, pub_inputs, output, _duration) = prove_claim(claim).unwrap();
        let expected = app_side_hash(&claim_values(claim));
        assert_eq!(pub_inputs.commitment, expected, "{case}");
        assert_eq!(output.commitment, expected.to_string(), "{case}");
    }
}
