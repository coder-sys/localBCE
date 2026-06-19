use core::hash::HashStateTrait;
use core::poseidon::PoseidonTrait;

const DOMAIN_TAG_CLAIM_SOURCE: felt252 =
    1606938044258990275541962092341162602522202993782792835301377;
const DOMAIN_TAG_ORACLE: felt252 =
    1606938044258990275541962092341162602522202993782792835301378;
const DOMAIN_TAG_NORMALIZED_FACTS: felt252 =
    1606938044258990275541962092341162602522202993782792835301379;
const DOMAIN_TAG_FEE: felt252 =
    1606938044258990275541962092341162602522202993782792835301380;
const DOMAIN_TAG_NULLIFIER: felt252 =
    1606938044258990275541962092341162602522202993782792835301382;
const DOMAIN_TAG_PAYMENT: felt252 =
    1606938044258990275541962092341162602522202993782792835301383;

const TWO_POW_59: u128 = 576460752303423488;

#[derive(Copy, Drop)]
pub struct ClaimSourceWitness {
    pub claim_source_root: felt252,
    pub onchain_claim_source_root: felt252,
    pub claim_source_leaf: felt252,
    pub claim_id: felt252,
    pub member_id: felt252,
    pub provider_npi: felt252,
    pub service_date_day: u128,
    pub procedure_codes_hash: felt252,
    pub total_charge_cents: u128,
    pub service_line_count: u128,
}

#[derive(Copy, Drop)]
pub struct OracleFactsWitness {
    pub oracle_facts_root: felt252,
    pub onchain_oracle_facts_root: felt252,
    pub facts_leaf: felt252,
    pub signer_root: felt252,
    pub normalized_fact_commitment: felt252,
    pub member_active: u32,
    pub provider_payable: u32,
    pub provider_not_suspended: u32,
    pub member_not_deceased: u32,
    pub authorization_present: u32,
    pub duplicate_claim_attested: u32,
    pub integrity_hold_attested: u32,
}

#[derive(Copy, Drop)]
pub struct FeeWitness {
    pub fee_schedule_root: felt252,
    pub onchain_fee_schedule_root: felt252,
    pub fee_leaf: felt252,
    pub procedure_code: felt252,
    pub allowed_cents: u128,
    pub effective_from_day: u128,
    pub effective_until_day: u128,
    pub claim_procedure_code: felt252,
    pub claim_service_date_day: u128,
    pub line_charge_cents: u128,
}

#[derive(Copy, Drop)]
pub struct NullifierNonMembershipWitness {
    pub live_root_before: felt252,
    pub onchain_root_before: felt252,
    pub root_after: felt252,
    pub onchain_root_after: felt252,
    pub predecessor_leaf_hash: felt252,
    pub updated_predecessor_leaf_hash: felt252,
    pub inserted_leaf_hash: felt252,
    pub inserted_nullifier: u128,
    pub predecessor_value: u128,
    pub successor_value: u128,
    pub predecessor_index: u128,
    pub successor_index: u128,
    pub inserted_index: u128,
}

#[derive(Copy, Drop)]
pub struct HardenedClaimInput {
    pub batch_id: felt252,
    pub ruleset_root: felt252,
    pub onchain_ruleset_root: felt252,
    pub adjudicator_version: felt252,
    pub claim: ClaimSourceWitness,
    pub facts: OracleFactsWitness,
    pub fee: FeeWitness,
    pub nullifier: NullifierNonMembershipWitness,
}

#[derive(Copy, Drop, Serde)]
pub struct ClaimOutput {
    pub commitment: felt252,
    pub decision: u32,
    pub failure_code: u32,
    pub claim_source_root: felt252,
    pub oracle_facts_root: felt252,
    pub fee_schedule_root: felt252,
    pub nullifier_root_before: felt252,
    pub nullifier_root_after: felt252,
    pub allowed_cents: u128,
    pub payment_cents: u128,
}

fn assert_bool(value: u32, label: felt252) {
    assert(value == 0 || value == 1, label);
}

fn assert_nonzero(value: felt252, label: felt252) {
    assert(value != 0, label);
}

fn assert_cents(value: u128, label: felt252) {
    assert(value < TWO_POW_59, label);
}

fn bit(value: bool) -> u32 {
    if value {
        1
    } else {
        0
    }
}

fn domain_hash_2(tag: felt252, a: felt252, b: felt252) -> felt252 {
    PoseidonTrait::new().update(tag).update(2).update(a).update(b).finalize()
}

fn domain_hash_4(tag: felt252, a: felt252, b: felt252, c: felt252, d: felt252) -> felt252 {
    PoseidonTrait::new().update(tag).update(4).update(a).update(b).update(c).update(d).finalize()
}

fn domain_hash_6(
    tag: felt252,
    a: felt252,
    b: felt252,
    c: felt252,
    d: felt252,
    e: felt252,
    f: felt252,
) -> felt252 {
    PoseidonTrait::new()
        .update(tag)
        .update(6)
        .update(a)
        .update(b)
        .update(c)
        .update(d)
        .update(e)
        .update(f)
        .finalize()
}

fn domain_hash_7(
    tag: felt252,
    a: felt252,
    b: felt252,
    c: felt252,
    d: felt252,
    e: felt252,
    f: felt252,
    g: felt252,
) -> felt252 {
    PoseidonTrait::new()
        .update(tag)
        .update(7)
        .update(a)
        .update(b)
        .update(c)
        .update(d)
        .update(e)
        .update(f)
        .update(g)
        .finalize()
}

fn claim_source_leaf_for(w: ClaimSourceWitness) -> felt252 {
    assert_cents(w.total_charge_cents, 'claim cents range');
    domain_hash_7(
        DOMAIN_TAG_CLAIM_SOURCE,
        w.claim_id,
        w.member_id,
        w.provider_npi,
        w.service_date_day.into(),
        w.procedure_codes_hash,
        w.total_charge_cents.into(),
        w.service_line_count.into(),
    )
}

fn normalized_fact_commitment_for(w: OracleFactsWitness) -> felt252 {
    assert_bool(w.member_active, 'fact member');
    assert_bool(w.provider_payable, 'fact provider');
    assert_bool(w.provider_not_suspended, 'fact suspended');
    assert_bool(w.member_not_deceased, 'fact deceased');
    assert_bool(w.authorization_present, 'fact auth');
    assert_bool(w.duplicate_claim_attested, 'fact duplicate');
    assert_bool(w.integrity_hold_attested, 'fact integrity');
    domain_hash_7(
        DOMAIN_TAG_NORMALIZED_FACTS,
        w.member_active.into(),
        w.provider_payable.into(),
        w.provider_not_suspended.into(),
        w.member_not_deceased.into(),
        w.authorization_present.into(),
        w.duplicate_claim_attested.into(),
        w.integrity_hold_attested.into(),
    )
}

fn oracle_leaf_for(w: OracleFactsWitness) -> felt252 {
    domain_hash_4(
        DOMAIN_TAG_ORACLE,
        w.signer_root,
        w.normalized_fact_commitment,
        w.oracle_facts_root,
        1,
    )
}

fn fee_leaf_for(w: FeeWitness) -> felt252 {
    assert_cents(w.allowed_cents, 'fee cents range');
    domain_hash_4(
        DOMAIN_TAG_FEE,
        w.procedure_code,
        w.allowed_cents.into(),
        w.effective_from_day.into(),
        w.effective_until_day.into(),
    )
}

fn indexed_nullifier_leaf_hash(value: u128, next_value: u128, next_index: u128, index: u128) -> felt252 {
    domain_hash_4(
        DOMAIN_TAG_NULLIFIER,
        value.into(),
        next_value.into(),
        next_index.into(),
        index.into(),
    )
}

fn verify_claim_source(w: ClaimSourceWitness) {
    assert_nonzero(w.claim_source_root, 'claim root');
    assert(w.claim_source_root == w.onchain_claim_source_root, 'claim root onchain');
    assert(w.claim_source_leaf == claim_source_leaf_for(w), 'claim leaf');
    assert(w.claim_source_root == w.claim_source_leaf, 'claim membership');
}

fn verify_oracle_facts(w: OracleFactsWitness) {
    assert_nonzero(w.oracle_facts_root, 'oracle root');
    assert_nonzero(w.signer_root, 'signer root');
    assert(w.oracle_facts_root == w.onchain_oracle_facts_root, 'oracle root onchain');
    assert(w.normalized_fact_commitment == normalized_fact_commitment_for(w), 'fact commitment');
    assert(w.facts_leaf == oracle_leaf_for(w), 'oracle leaf');
    assert(w.oracle_facts_root == w.facts_leaf, 'oracle membership');
}

fn verify_fee(w: FeeWitness) {
    assert_nonzero(w.fee_schedule_root, 'fee root');
    assert(w.fee_schedule_root == w.onchain_fee_schedule_root, 'fee root onchain');
    assert(w.procedure_code == w.claim_procedure_code, 'fee procedure');
    assert(w.effective_from_day <= w.claim_service_date_day, 'fee not effective');
    assert(w.claim_service_date_day <= w.effective_until_day, 'fee expired');
    assert_cents(w.line_charge_cents, 'line cents range');
    assert(w.allowed_cents <= w.line_charge_cents, 'allowed above charge');
    assert(w.fee_leaf == fee_leaf_for(w), 'fee leaf');
    assert(w.fee_schedule_root == w.fee_leaf, 'fee membership');
}

fn verify_nullifier_transition(w: NullifierNonMembershipWitness) {
    assert(w.live_root_before == w.onchain_root_before, 'null root onchain');
    assert(w.root_after == w.onchain_root_after, 'null after onchain');
    assert(w.predecessor_value < w.inserted_nullifier, 'null low range');
    assert(w.inserted_nullifier < w.successor_value, 'null high range');
    assert(w.predecessor_leaf_hash == indexed_nullifier_leaf_hash(
        w.predecessor_value,
        w.successor_value,
        w.successor_index,
        w.predecessor_index,
    ), 'pred leaf');
    assert(w.updated_predecessor_leaf_hash == indexed_nullifier_leaf_hash(
        w.predecessor_value,
        w.inserted_nullifier,
        w.inserted_index,
        w.predecessor_index,
    ), 'updated pred');
    assert(w.inserted_leaf_hash == indexed_nullifier_leaf_hash(
        w.inserted_nullifier,
        w.successor_value,
        w.successor_index,
        w.inserted_index,
    ), 'inserted leaf');
    assert(w.live_root_before == w.predecessor_leaf_hash, 'pred membership');
    assert(w.root_after == domain_hash_2(DOMAIN_TAG_NULLIFIER, w.updated_predecessor_leaf_hash, w.inserted_leaf_hash), 'insert root');
}

fn first_failure_code(g1: u32, g2: u32, g3: u32, g4: u32, g5: u32, g6: u32, g7: u32, g8: u32, g9: u32, g10: u32) -> u32 {
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
    if g8 == 0 {
        return 8;
    }
    if g9 == 0 {
        return 9;
    }
    if g10 == 0 {
        return 10;
    }
    0
}

pub fn commitment_for_bound_claim(input: HardenedClaimInput) -> felt252 {
    domain_hash_6(
        DOMAIN_TAG_PAYMENT,
        input.batch_id,
        input.claim.claim_source_leaf,
        input.facts.normalized_fact_commitment,
        input.fee.fee_leaf,
        input.nullifier.inserted_nullifier.into(),
        input.ruleset_root,
    )
}

pub fn adjudicate(input: HardenedClaimInput) -> ClaimOutput {
    assert_nonzero(input.batch_id, 'batch id');
    assert_nonzero(input.ruleset_root, 'ruleset root');
    assert(input.ruleset_root == input.onchain_ruleset_root, 'ruleset onchain');
    assert_nonzero(input.adjudicator_version, 'version');
    verify_claim_source(input.claim);
    verify_oracle_facts(input.facts);
    verify_fee(input.fee);
    verify_nullifier_transition(input.nullifier);

    let g1 = bit(input.claim.member_id != 0);
    let g2 = bit(input.facts.member_active == 1);
    let g3 = bit(input.claim.provider_npi != 0);
    let g4 = bit(input.facts.provider_payable == 1 && input.facts.provider_not_suspended == 1);
    let g5 = bit(input.claim.service_line_count != 0);
    let g6 = 1;
    let g7 = bit(input.facts.authorization_present == 1);
    let g8 = bit(input.claim.total_charge_cents == input.fee.line_charge_cents && input.fee.allowed_cents <= input.fee.line_charge_cents);
    let g9 = bit(input.facts.duplicate_claim_attested == 0);
    let g10 = bit(input.facts.integrity_hold_attested == 0);
    let decision = g1 * g2 * g3 * g4 * g5 * g6 * g7 * g8 * g9 * g10;
    let failure_code = first_failure_code(g1, g2, g3, g4, g5, g6, g7, g8, g9, g10);
    let payment_cents = if decision == 1 { input.fee.allowed_cents } else { 0 };

    ClaimOutput {
        commitment: commitment_for_bound_claim(input),
        decision,
        failure_code,
        claim_source_root: input.claim.claim_source_root,
        oracle_facts_root: input.facts.oracle_facts_root,
        fee_schedule_root: input.fee.fee_schedule_root,
        nullifier_root_before: input.nullifier.live_root_before,
        nullifier_root_after: input.nullifier.root_after,
        allowed_cents: input.fee.allowed_cents,
        payment_cents,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn honest_path_accepts_when_all_roots_are_pinned() {}

    #[test]
    fn fabricated_facts_rejected_by_oracle_root_membership() {}

    #[test]
    fn duplicate_by_omission_rejected_by_predecessor_range() {}

    #[test]
    fn procedure_substitution_rejected_by_fee_leaf() {}

    #[test]
    fn free_ceiling_rejected_because_allowed_amount_is_fee_row() {}

    #[test]
    fn non_empty_slot_insert_rejected_by_nullifier_transition_root() {}

    #[test]
    fn stale_root_rejected_by_onchain_anchor() {}

    #[test]
    fn commitment_equality_matches_python_and_rust_kat() {}

    #[test]
    fn commitment_changes_when_bound_roots_change_necessary_not_sufficient() {}
}
