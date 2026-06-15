use core::hash::{HashStateExTrait, HashStateTrait};
use core::poseidon::PoseidonTrait;

#[derive(Copy, Drop, Hash)]
pub struct ClaimInput {
    pub batch_id: felt252,
    pub raw_claim_leaf: felt252,
    pub raw_claim_root: felt252,
    pub ruleset_root: felt252,
    pub adjudicator_version: felt252,
    pub claim_nullifier: felt252,
    pub member_id_present: u32,
    pub eligibility_active: u32,
    pub provider_npi_present: u32,
    pub provider_enrolled: u32,
    pub service_line_count: u32,
    pub diagnosis_count: u32,
    pub prior_auth_ok: u32,
    pub total_charge_cents: u32,
    pub min_service_line_charge_cents: u32,
    pub max_service_line_charge_cents: u32,
    pub program_integrity_hold: u32,
    pub spent_nullifier_0: felt252,
    pub spent_nullifier_1: felt252,
    pub spent_nullifier_2: felt252,
    pub spent_nullifier_3: felt252,
    pub spent_nullifier_4: felt252,
    pub spent_nullifier_5: felt252,
    pub spent_nullifier_6: felt252,
    pub spent_nullifier_7: felt252,
}

#[derive(Copy, Drop, Serde)]
pub struct ClaimOutput {
    pub commitment: felt252,
    pub batch_id: felt252,
    pub raw_claim_leaf: felt252,
    pub raw_claim_root: felt252,
    pub ruleset_root: felt252,
    pub adjudicator_version: felt252,
    pub claim_nullifier: felt252,
    pub spent_nullifier_root: felt252,
    pub new_nullifier_root: felt252,
    pub decision: u32,
    pub failure_code: u32,
    pub g1_member_id_present: u32,
    pub g2_eligibility_active: u32,
    pub g3_provider_npi_present: u32,
    pub g4_provider_enrolled: u32,
    pub g5_service_lines_present: u32,
    pub g6_diagnosis_present: u32,
    pub g7_prior_auth_when_required: u32,
    pub g8a_charge_valid: u32,
    pub g8b_charge_within_allowable: u32,
    pub g9_not_duplicate: u32,
    pub g10_no_program_integrity_hold: u32,
}

const MAX_ALLOWABLE_LINE_CHARGE_CENTS: u32 = 500000;

fn bit(value: bool) -> u32 {
    if value {
        1
    } else {
        0
    }
}

fn assert_bool(value: u32, label: felt252) {
    assert(value == 0 || value == 1, label);
}

fn assert_nonzero_felt(value: felt252, label: felt252) {
    assert(value != 0, label);
}

fn validate_input(input: ClaimInput) {
    assert_nonzero_felt(input.batch_id, 'bad batch id');
    assert_nonzero_felt(input.raw_claim_leaf, 'bad raw leaf');
    assert_nonzero_felt(input.raw_claim_root, 'bad raw root');
    assert_nonzero_felt(input.ruleset_root, 'bad ruleset root');
    assert_nonzero_felt(input.adjudicator_version, 'bad version');
    assert_bool(input.member_id_present, 'bad member flag');
    assert_bool(input.eligibility_active, 'bad eligibility');
    assert_bool(input.provider_npi_present, 'bad npi flag');
    assert_bool(input.provider_enrolled, 'bad enrollment');
    assert_bool(input.prior_auth_ok, 'bad prior auth');
    assert_bool(input.program_integrity_hold, 'bad pi hold');
}

fn spent_nullifier_root_for_claim(input: ClaimInput) -> felt252 {
    PoseidonTrait::new()
        .update(input.spent_nullifier_0)
        .update(input.spent_nullifier_1)
        .update(input.spent_nullifier_2)
        .update(input.spent_nullifier_3)
        .update(input.spent_nullifier_4)
        .update(input.spent_nullifier_5)
        .update(input.spent_nullifier_6)
        .update(input.spent_nullifier_7)
        .finalize()
}

fn new_nullifier_root_for_claim(input: ClaimInput) -> felt252 {
    PoseidonTrait::new()
        .update(spent_nullifier_root_for_claim(input))
        .update(input.claim_nullifier)
        .finalize()
}

fn nullifier_not_spent(input: ClaimInput) -> u32 {
    if input.claim_nullifier == 0 {
        return 0;
    }
    if input.claim_nullifier == input.spent_nullifier_0 {
        return 0;
    }
    if input.claim_nullifier == input.spent_nullifier_1 {
        return 0;
    }
    if input.claim_nullifier == input.spent_nullifier_2 {
        return 0;
    }
    if input.claim_nullifier == input.spent_nullifier_3 {
        return 0;
    }
    if input.claim_nullifier == input.spent_nullifier_4 {
        return 0;
    }
    if input.claim_nullifier == input.spent_nullifier_5 {
        return 0;
    }
    if input.claim_nullifier == input.spent_nullifier_6 {
        return 0;
    }
    if input.claim_nullifier == input.spent_nullifier_7 {
        return 0;
    }
    1
}

fn first_failure_code(
    g1: u32,
    g2: u32,
    g3: u32,
    g4: u32,
    g5: u32,
    g6: u32,
    g7: u32,
    g8a: u32,
    g8b: u32,
    g9: u32,
    g10: u32,
) -> u32 {
    if g1 == 0 {
        return 1;
    }
    if g2 == 0 {
        return 2;
    }
    if g3 == 0 {
        return 3;
    }
    if g4 == 0 {
        return 4;
    }
    if g5 == 0 {
        return 5;
    }
    if g6 == 0 {
        return 6;
    }
    if g7 == 0 {
        return 7;
    }
    if g8a == 0 {
        return 8;
    }
    if g8b == 0 {
        return 9;
    }
    if g9 == 0 {
        return 10;
    }
    if g10 == 0 {
        return 11;
    }
    0
}

pub fn commitment_for_claim(input: ClaimInput) -> felt252 {
    PoseidonTrait::new().update_with(input).finalize()
}

pub fn adjudicate(input: ClaimInput) -> ClaimOutput {
    validate_input(input);

    let g1 = bit(input.member_id_present != 0);
    let g2 = bit(input.eligibility_active == 1);
    let g3 = bit(input.provider_npi_present != 0);
    let g4 = bit(input.provider_enrolled == 1);
    let g5 = bit(input.service_line_count != 0);
    let g6 = bit(input.diagnosis_count != 0);
    let g7 = bit(input.prior_auth_ok == 1);
    let g8a = bit(input.total_charge_cents != 0 && input.min_service_line_charge_cents != 0);
    let g8b = bit(input.max_service_line_charge_cents <= MAX_ALLOWABLE_LINE_CHARGE_CENTS);
    let g9 = nullifier_not_spent(input);
    let g10 = bit(input.program_integrity_hold == 0);
    let decision = g1 * g2 * g3 * g4 * g5 * g6 * g7 * g8a * g8b * g9 * g10;
    let failure_code = first_failure_code(g1, g2, g3, g4, g5, g6, g7, g8a, g8b, g9, g10);

    ClaimOutput {
        commitment: commitment_for_claim(input),
        batch_id: input.batch_id,
        raw_claim_leaf: input.raw_claim_leaf,
        raw_claim_root: input.raw_claim_root,
        ruleset_root: input.ruleset_root,
        adjudicator_version: input.adjudicator_version,
        claim_nullifier: input.claim_nullifier,
        spent_nullifier_root: spent_nullifier_root_for_claim(input),
        new_nullifier_root: new_nullifier_root_for_claim(input),
        decision,
        failure_code,
        g1_member_id_present: g1,
        g2_eligibility_active: g2,
        g3_provider_npi_present: g3,
        g4_provider_enrolled: g4,
        g5_service_lines_present: g5,
        g6_diagnosis_present: g6,
        g7_prior_auth_when_required: g7,
        g8a_charge_valid: g8a,
        g8b_charge_within_allowable: g8b,
        g9_not_duplicate: g9,
        g10_no_program_integrity_hold: g10,
    }
}

#[executable]
fn main(
    batch_id: felt252,
    raw_claim_leaf: felt252,
    raw_claim_root: felt252,
    ruleset_root: felt252,
    adjudicator_version: felt252,
    claim_nullifier: felt252,
    member_id_present: u32,
    eligibility_active: u32,
    provider_npi_present: u32,
    provider_enrolled: u32,
    service_line_count: u32,
    diagnosis_count: u32,
    prior_auth_ok: u32,
    total_charge_cents: u32,
    min_service_line_charge_cents: u32,
    max_service_line_charge_cents: u32,
    program_integrity_hold: u32,
    spent_nullifier_0: felt252,
    spent_nullifier_1: felt252,
    spent_nullifier_2: felt252,
    spent_nullifier_3: felt252,
    spent_nullifier_4: felt252,
    spent_nullifier_5: felt252,
    spent_nullifier_6: felt252,
    spent_nullifier_7: felt252,
) -> ClaimOutput {
    adjudicate(
        ClaimInput {
            batch_id,
            raw_claim_leaf,
            raw_claim_root,
            ruleset_root,
            adjudicator_version,
            claim_nullifier,
            member_id_present,
            eligibility_active,
            provider_npi_present,
            provider_enrolled,
            service_line_count,
            diagnosis_count,
            prior_auth_ok,
            total_charge_cents,
            min_service_line_charge_cents,
            max_service_line_charge_cents,
            program_integrity_hold,
            spent_nullifier_0,
            spent_nullifier_1,
            spent_nullifier_2,
            spent_nullifier_3,
            spent_nullifier_4,
            spent_nullifier_5,
            spent_nullifier_6,
            spent_nullifier_7,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::{ClaimInput, adjudicate};

    fn approved_claim() -> ClaimInput {
        ClaimInput {
            batch_id: 8001,
            raw_claim_leaf: 1001,
            raw_claim_root: 9001,
            ruleset_root: 9002,
            adjudicator_version: 20260615,
            claim_nullifier: 7001,
            member_id_present: 1,
            eligibility_active: 1,
            provider_npi_present: 1,
            provider_enrolled: 1,
            service_line_count: 1,
            diagnosis_count: 1,
            prior_auth_ok: 1,
            total_charge_cents: 12500,
            min_service_line_charge_cents: 12500,
            max_service_line_charge_cents: 12500,
            program_integrity_hold: 0,
            spent_nullifier_0: 0,
            spent_nullifier_1: 0,
            spent_nullifier_2: 0,
            spent_nullifier_3: 0,
            spent_nullifier_4: 0,
            spent_nullifier_5: 0,
            spent_nullifier_6: 0,
            spent_nullifier_7: 0,
        }
    }

    #[test]
    fn approved_claim_returns_decision_one() {
        let output = adjudicate(approved_claim());
        assert(output.decision == 1, 'approved decision');
        assert(output.failure_code == 0, 'approved failure');
        assert(output.g1_member_id_present == 1, 'g1');
        assert(output.g8a_charge_valid == 1, 'g8a');
        assert(output.g8b_charge_within_allowable == 1, 'g8b');
        assert(output.g10_no_program_integrity_hold == 1, 'g10');
    }

    #[test]
    fn ineligible_claim_denies_with_code_two() {
        let mut claim = approved_claim();
        claim.eligibility_active = 0;
        let output = adjudicate(claim);
        assert(output.decision == 0, 'ineligible decision');
        assert(output.failure_code == 2, 'ineligible code');
        assert(output.g2_eligibility_active == 0, 'g2');
    }

    #[test]
    fn duplicate_claim_denies_with_code_ten() {
        let mut claim = approved_claim();
        claim.spent_nullifier_2 = claim.claim_nullifier;
        let output = adjudicate(claim);
        assert(output.decision == 0, 'duplicate decision');
        assert(output.failure_code == 10, 'duplicate code');
        assert(output.g9_not_duplicate == 0, 'g9');
    }

    #[test]
    fn excessive_charge_denies_with_g8b_code_nine() {
        let mut claim = approved_claim();
        claim.total_charge_cents = 500001;
        claim.min_service_line_charge_cents = 500001;
        claim.max_service_line_charge_cents = 500001;
        let output = adjudicate(claim);
        assert(output.decision == 0, 'excessive decision');
        assert(output.failure_code == 9, 'excessive code');
        assert(output.g8a_charge_valid == 1, 'g8a should pass');
        assert(output.g8b_charge_within_allowable == 0, 'g8b should fail');
    }

    #[test]
    fn invalid_charge_denies_before_excessive_charge() {
        let mut claim = approved_claim();
        claim.total_charge_cents = 0;
        claim.min_service_line_charge_cents = 0;
        claim.max_service_line_charge_cents = 500001;
        let output = adjudicate(claim);
        assert(output.decision == 0, 'invalid charge decision');
        assert(output.failure_code == 8, 'invalid charge first');
        assert(output.g8a_charge_valid == 0, 'g8a');
        assert(output.g8b_charge_within_allowable == 0, 'g8b');
    }

    #[test]
    fn multi_gate_failure_uses_first_failed_gate() {
        let mut claim = approved_claim();
        claim.member_id_present = 0;
        claim.eligibility_active = 0;
        claim.provider_npi_present = 0;
        let output = adjudicate(claim);
        assert(output.decision == 0, 'multi decision');
        assert(output.failure_code == 1, 'first failed gate');
        assert(output.g1_member_id_present == 0, 'g1');
        assert(output.g2_eligibility_active == 0, 'g2');
        assert(output.g3_provider_npi_present == 0, 'g3');
    }

    #[test]
    #[should_panic(expected: ('bad member flag',))]
    fn noncanonical_boolean_witness_is_rejected() {
        let mut claim = approved_claim();
        claim.member_id_present = 2;
        adjudicate(claim);
    }

    #[test]
    #[should_panic(expected: ('bad raw root',))]
    fn missing_raw_claim_root_is_rejected() {
        let mut claim = approved_claim();
        claim.raw_claim_root = 0;
        adjudicate(claim);
    }

    #[test]
    fn commitment_changes_when_ruleset_root_changes() {
        let claim_a = approved_claim();
        let mut claim_b = approved_claim();
        claim_b.ruleset_root = 999999;
        let output_a = adjudicate(claim_a);
        let output_b = adjudicate(claim_b);
        assert(output_a.commitment != output_b.commitment, 'ruleset bound');
        assert(output_a.ruleset_root == 9002, 'ruleset output a');
        assert(output_b.ruleset_root == 999999, 'ruleset output b');
    }

    #[test]
    fn commitment_changes_when_raw_claim_leaf_changes() {
        let claim_a = approved_claim();
        let mut claim_b = approved_claim();
        claim_b.raw_claim_leaf = 1002;
        let output_a = adjudicate(claim_a);
        let output_b = adjudicate(claim_b);
        assert(output_a.commitment != output_b.commitment, 'raw leaf bound');
        assert(output_b.raw_claim_leaf == 1002, 'raw leaf output');
    }

    #[test]
    fn commitment_changes_when_batch_id_changes() {
        let claim_a = approved_claim();
        let mut claim_b = approved_claim();
        claim_b.batch_id = 8002;
        let output_a = adjudicate(claim_a);
        let output_b = adjudicate(claim_b);
        assert(output_a.commitment != output_b.commitment, 'batch id bound');
        assert(output_a.batch_id == 8001, 'batch id output a');
        assert(output_b.batch_id == 8002, 'batch id output b');
    }

    #[test]
    #[should_panic(expected: ('bad batch id',))]
    fn missing_batch_id_is_rejected() {
        let mut claim = approved_claim();
        claim.batch_id = 0;
        adjudicate(claim);
    }
}
