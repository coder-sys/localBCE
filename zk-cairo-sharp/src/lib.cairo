use core::hash::HashStateTrait;
use core::poseidon::PoseidonTrait;

const DOMAIN_TAG_CLAIM_SOURCE: felt252 =
    1606938044258990275541962092341162602522202993782792835301377;
const DOMAIN_TAG_ORACLE: felt252 = 1606938044258990275541962092341162602522202993782792835301378;
const DOMAIN_TAG_NORMALIZED_FACTS: felt252 =
    1606938044258990275541962092341162602522202993782792835301379;
const DOMAIN_TAG_FEE: felt252 = 1606938044258990275541962092341162602522202993782792835301380;
const DOMAIN_TAG_NULLIFIER: felt252 = 1606938044258990275541962092341162602522202993782792835301382;
const DOMAIN_TAG_PAYMENT: felt252 = 1606938044258990275541962092341162602522202993782792835301383;
const DOMAIN_TAG_RULESET: felt252 = 1606938044258990275541962092341162602522202993782792835301384;
const DOMAIN_TAG_BATCH: felt252 = 1606938044258990275541962092341162602522202993782792835301388;
const DOMAIN_TAG_CLAIM: felt252 = 1606938044258990275541962092341162602522202993782792835301389;
const DOMAIN_TAG_RESULT: felt252 = 1606938044258990275541962092341162602522202993782792835301390;
const DOMAIN_TAG_TAR_REQUIRED: felt252 =
    1606938044258990275541962092341162602522202993782792835301391;
const DOMAIN_TAG_PRIVATE_BATCH_V2: felt252 =
    1606938044258990275541962092341162602522202993782792835301392;
const DOMAIN_TAG_VALUE_CONSERVATION_V2: felt252 =
    1606938044258990275541962092341162602522202993782792835301393;
const DOMAIN_TAG_SETTLEMENT_V2: felt252 =
    1606938044258990275541962092341162602522202993782792835301394;
const PRIVACY_V2_PROTOCOL_VERSION: felt252 = 2;
const CLAIM_SOURCE_SCHEMA_TAG: felt252 = 2;
const ATTEMPT_RECORD_SCHEMA_TAG: felt252 = 1;
const ATTEMPT_REVISION_KIND_ORIGINAL: u32 = 1;
const FEE_POLICY_SCHEMA_TAG: felt252 = 2;
const POLICY_ROW_SCHEMA_TAG: felt252 = 2;
const POLICY_ROW_KIND_LOWER_SENTINEL: u32 = 0;
const POLICY_ROW_KIND_REAL: u32 = 1;
const POLICY_ROW_KIND_UPPER_SENTINEL: u32 = 2;
const POLICY_LOWER_SENTINEL_KEY: felt252 = 0;
const POLICY_UPPER_SENTINEL_KEY: felt252 = 340282366920938463463374607431768211455;
const FEE_SOURCE_UNBOUND: felt252 = 0;

const MAX_CENTS_EXCLUSIVE: u128 = 4294967296;
const TWO_POW_128_FELT: felt252 = 340282366920938463463374607431768211456;
const MAX_NULLIFIER_HIGH: u128 = 10633823966279327296825105735305134080;
const MAX_NULLIFIER_LOW: u128 = 0;
const NULLIFIER_TREE_DEPTH: usize = 32;
const NULLIFIER_EMPTY_LEAF: felt252 = 0;
const DEFAULT_FEE_EFFECTIVE_FROM_DAY: u128 = 0;
const DEFAULT_FEE_EFFECTIVE_UNTIL_DAY: u128 = 2932896;

#[derive(Copy, Drop, Serde)]
pub struct ClaimSourceWitness {
    pub claim_source_leaf: felt252,
    pub claim_id: felt252,
    pub member_id: felt252,
    pub provider_npi: felt252,
    pub service_date_day: u128,
    pub service_lines_commitment: felt252,
    pub diagnosis_commitment: felt252,
    pub total_charge_cents: u128,
    pub source_authority_id: felt252,
    pub payer_id: felt252,
    pub attempt_version: u128,
    pub revision_kind: u32,
    pub parent_attempt_version: u128,
    pub attempt_nullifier: felt252,
    pub service_line_count: u128,
    pub diagnosis_count: u128,
    pub claim_source_leaf_index: u128,
    pub claim_source_path_elements: Span<felt252>,
}

#[derive(Copy, Drop, Serde)]
pub struct NullifierNonMembershipWitness {
    pub live_root_before: felt252,
    pub onchain_root_before: felt252,
    pub root_after: felt252,
    pub onchain_root_after: felt252,
    pub inserted_nullifier_high: u128,
    pub inserted_nullifier_low: u128,
    pub predecessor_value_high: u128,
    pub predecessor_value_low: u128,
    pub successor_value_high: u128,
    pub successor_value_low: u128,
    pub predecessor_index: u128,
    pub successor_index: u128,
    pub inserted_index: u128,
    pub predecessor_path_elements: Span<felt252>,
    pub inserted_path_elements: Span<felt252>,
}

#[derive(Copy, Drop, Serde)]
pub struct MultiLineAuthorizationWitness {
    pub auth_proof_root: felt252,
    pub auth_leaf_index: u128,
    pub claim_id: felt252,
    pub line_index: u128,
    pub procedure_code: felt252,
    pub service_date_day: u128,
    pub valid_from_day: u128,
    pub valid_until_day: u128,
    pub prior_authorization: felt252,
    pub signed_tar_authorization_commitment: felt252,
    pub authorization_present: u32,
    pub signer_root: felt252,
    pub fact_verification_commitment: felt252,
    pub evidence_root: felt252,
    pub auth_path_elements: Span<felt252>,
}

#[derive(Copy, Drop, Serde)]
pub struct MultiLineFeePolicyWitness {
    pub fee_policy_leaf: felt252,
    pub fee_policy_leaf_index: u128,
    pub tree_depth: u128,
    pub real_row_count: u128,
    pub fee_policy_path_elements: Span<felt252>,
}

#[derive(Copy, Drop, Serde)]
pub struct MultiLineFeeRowWitness {
    pub row_kind: u32,
    pub procedure_code: felt252,
    pub allowed_cents: u128,
    pub requires_tar: u32,
    pub policy_leaf_index: u128,
    pub next_procedure_code: felt252,
    pub next_policy_leaf_index: u128,
    pub policy_path_elements: Span<felt252>,
}

#[derive(Copy, Drop, Serde)]
pub struct MultiLineServiceLineWitness {
    pub procedure_code: felt252,
    pub line_charge_cents: u128,
    pub units_cents: u128,
    pub prior_authorization: felt252,
    pub allowed_cents: u128,
    pub tar_required: u32,
    pub policy_present: u32,
    pub policy_row_index: u128,
    pub authorization_index: u128,
}

#[derive(Copy, Drop, Serde)]
pub struct MultiLineClaimWitness {
    pub claim_id: felt252,
    pub service_date_day: u128,
    pub total_charge_cents: u128,
    pub service_lines: Span<MultiLineServiceLineWitness>,
    pub authorizations: Span<MultiLineAuthorizationWitness>,
}

#[derive(Copy, Drop, Serde)]
pub struct MultiLineClaimMathOutput {
    pub line_count: u128,
    pub sum_line_charge_cents: u128,
    pub allowed_total_cents: u128,
    pub requires_any_tar: u32,
    pub all_required_authorized: u32,
    pub all_fee_rows_present: u32,
    pub all_charges_and_units_positive: u32,
    pub payment_lines_commitment: felt252,
}

#[derive(Copy, Drop, Serde)]
pub struct MultiLineDecisionInput {
    pub batch_id: felt252,
    pub claim: ClaimSourceWitness,
    pub claim_source_leaf: felt252,
    pub claim_facts_leaf: felt252,
    pub claim_facts_leaf_index: u128,
    pub claim_facts_path_elements: Span<felt252>,
    pub claim_facts_signer: felt252,
    pub claim_facts_verification_commitment: felt252,
    pub claim_facts_evidence_commitment: felt252,
    pub member_id: felt252,
    pub provider_npi: felt252,
    pub diagnosis_count: u128,
    pub member_active: u32,
    pub provider_payable: u32,
    pub provider_not_suspended: u32,
    pub member_not_deceased: u32,
    pub duplicate_claim_attested: u32,
    pub integrity_hold_attested: u32,
    pub lines: MultiLineClaimWitness,
}

#[derive(Copy, Drop, Serde)]
pub struct MultiLineDecisionOutput {
    pub commitment: felt252,
    pub decision: u32,
    pub failure_code: u32,
    pub line_count: u128,
    pub sum_line_charge_cents: u128,
    pub allowed_cents: u128,
    pub payment_cents: u128,
    pub claim_source_root: felt252,
    pub oracle_facts_root: felt252,
    pub policy_root: felt252,
    pub nullifier_root_before: felt252,
    pub nullifier_root_after: felt252,
}

#[derive(Copy, Drop, Serde)]
pub struct BatchClaimInput {
    pub batch_root_before: felt252,
    pub expected_batch_root_after: felt252,
    pub claim_source_root: felt252,
    pub oracle_facts_root: felt252,
    pub policy_root: felt252,
    pub ruleset_root: felt252,
    pub fee_policy: MultiLineFeePolicyWitness,
    pub policy_rows: Span<MultiLineFeeRowWitness>,
    pub nullifier_transitions: Span<NullifierNonMembershipWitness>,
    pub expected_batch_commitment: felt252,
    pub expected_total_allowed_cents: u128,
    pub expected_total_payment_cents: u128,
    pub expected_approved_count: u32,
    pub expected_denied_count: u32,
    pub expected_claim_count: u32,
    pub claims: Span<MultiLineDecisionInput>,
}

#[derive(Copy, Drop, Serde)]
pub struct BatchOutput {
    pub batch_root_before: felt252,
    pub batch_root_after: felt252,
    pub claim_source_root: felt252,
    pub oracle_facts_root: felt252,
    pub policy_root: felt252,
    pub ruleset_root: felt252,
    pub batch_commitment: felt252,
    pub total_allowed_cents: u128,
    pub total_payment_cents: u128,
    pub approved_count: u32,
    pub denied_count: u32,
    pub claim_count: u32,
}

#[derive(Copy, Drop, Serde)]
pub struct BatchClaimInputV2 {
    pub settlement_domain: felt252,
    pub batch_nonce: felt252,
    pub private_data_commitment: felt252,
    pub privacy_salt: felt252,
    pub value_salt: felt252,
    pub batch: BatchClaimInput,
}

#[derive(Copy, Drop, Serde)]
pub struct BatchOutputV2 {
    pub protocol_version: felt252,
    pub settlement_domain: felt252,
    pub batch_nonce: felt252,
    pub nullifier_root_before: felt252,
    pub nullifier_root_after: felt252,
    pub claim_source_root: felt252,
    pub oracle_facts_root: felt252,
    pub policy_root: felt252,
    pub ruleset_root: felt252,
    pub opaque_batch_commitment: felt252,
    pub value_conservation_commitment: felt252,
    pub settlement_commitment: felt252,
}

// Diagnostic-only unsigned transports for cross-implementation differential tests. The
// production claim and Privacy V2 public-output ABIs above remain twelve single felts.
#[derive(Copy, Drop, Serde)]
pub struct CanonicalMultiLineDecisionOutput {
    pub commitment: u256,
    pub decision: u256,
    pub failure_code: u256,
    pub line_count: u256,
    pub sum_line_charge_cents: u256,
    pub allowed_cents: u256,
    pub payment_cents: u256,
    pub claim_source_root: u256,
    pub oracle_facts_root: u256,
    pub policy_root: u256,
    pub nullifier_root_before: u256,
    pub nullifier_root_after: u256,
}

#[derive(Copy, Drop, Serde)]
pub struct CanonicalBatchOutputV2 {
    pub protocol_version: u256,
    pub settlement_domain: u256,
    pub batch_nonce: u256,
    pub nullifier_root_before: u256,
    pub nullifier_root_after: u256,
    pub claim_source_root: u256,
    pub oracle_facts_root: u256,
    pub policy_root: u256,
    pub ruleset_root: u256,
    pub opaque_batch_commitment: u256,
    pub value_conservation_commitment: u256,
    pub settlement_commitment: u256,
}

fn assert_bool(value: u32, label: felt252) {
    assert(value == 0 || value == 1, label);
}

fn assert_nonzero(value: felt252, label: felt252) {
    assert(value != 0, label);
}

fn cents_in_range(value: u128) -> bool {
    value < MAX_CENTS_EXCLUSIVE
}

fn assert_cents(value: u128, label: felt252) {
    assert(cents_in_range(value), label);
}

fn assert_even(value: usize, label: felt252) {
    assert(value % 2 == 0, label);
}

fn bit(value: bool) -> u32 {
    if value {
        1
    } else {
        0
    }
}

fn domain_hash_1(tag: felt252, a: felt252) -> felt252 {
    PoseidonTrait::new().update(tag).update(1).update(a).finalize()
}

fn domain_hash_2(tag: felt252, a: felt252, b: felt252) -> felt252 {
    PoseidonTrait::new().update(tag).update(2).update(a).update(b).finalize()
}

fn domain_hash_3(tag: felt252, a: felt252, b: felt252, c: felt252) -> felt252 {
    PoseidonTrait::new().update(tag).update(3).update(a).update(b).update(c).finalize()
}

fn domain_hash_4(tag: felt252, a: felt252, b: felt252, c: felt252, d: felt252) -> felt252 {
    PoseidonTrait::new().update(tag).update(4).update(a).update(b).update(c).update(d).finalize()
}

fn domain_hash_5(
    tag: felt252, a: felt252, b: felt252, c: felt252, d: felt252, e: felt252,
) -> felt252 {
    PoseidonTrait::new()
        .update(tag)
        .update(5)
        .update(a)
        .update(b)
        .update(c)
        .update(d)
        .update(e)
        .finalize()
}

fn domain_hash_6(
    tag: felt252, a: felt252, b: felt252, c: felt252, d: felt252, e: felt252, f: felt252,
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

fn domain_hash_8(
    tag: felt252,
    a: felt252,
    b: felt252,
    c: felt252,
    d: felt252,
    e: felt252,
    f: felt252,
    g: felt252,
    h: felt252,
) -> felt252 {
    PoseidonTrait::new()
        .update(tag)
        .update(8)
        .update(a)
        .update(b)
        .update(c)
        .update(d)
        .update(e)
        .update(f)
        .update(g)
        .update(h)
        .finalize()
}

fn domain_hash_9(
    tag: felt252,
    a: felt252,
    b: felt252,
    c: felt252,
    d: felt252,
    e: felt252,
    f: felt252,
    g: felt252,
    h: felt252,
    i: felt252,
) -> felt252 {
    PoseidonTrait::new()
        .update(tag)
        .update(9)
        .update(a)
        .update(b)
        .update(c)
        .update(d)
        .update(e)
        .update(f)
        .update(g)
        .update(h)
        .update(i)
        .finalize()
}

fn domain_hash_10(
    tag: felt252,
    a: felt252,
    b: felt252,
    c: felt252,
    d: felt252,
    e: felt252,
    f: felt252,
    g: felt252,
    h: felt252,
    i: felt252,
    j: felt252,
) -> felt252 {
    PoseidonTrait::new()
        .update(tag)
        .update(10)
        .update(a)
        .update(b)
        .update(c)
        .update(d)
        .update(e)
        .update(f)
        .update(g)
        .update(h)
        .update(i)
        .update(j)
        .finalize()
}

fn domain_hash_12(
    tag: felt252,
    a: felt252,
    b: felt252,
    c: felt252,
    d: felt252,
    e: felt252,
    f: felt252,
    g: felt252,
    h: felt252,
    i: felt252,
    j: felt252,
    k: felt252,
    l: felt252,
) -> felt252 {
    PoseidonTrait::new()
        .update(tag)
        .update(12)
        .update(a)
        .update(b)
        .update(c)
        .update(d)
        .update(e)
        .update(f)
        .update(g)
        .update(h)
        .update(i)
        .update(j)
        .update(k)
        .update(l)
        .finalize()
}

fn domain_hash_13(
    tag: felt252,
    a: felt252,
    b: felt252,
    c: felt252,
    d: felt252,
    e: felt252,
    f: felt252,
    g: felt252,
    h: felt252,
    i: felt252,
    j: felt252,
    k: felt252,
    l: felt252,
    m: felt252,
) -> felt252 {
    PoseidonTrait::new()
        .update(tag)
        .update(13)
        .update(a)
        .update(b)
        .update(c)
        .update(d)
        .update(e)
        .update(f)
        .update(g)
        .update(h)
        .update(i)
        .update(j)
        .update(k)
        .update(l)
        .update(m)
        .finalize()
}

fn attempt_record_commitment_for(w: ClaimSourceWitness) -> felt252 {
    assert_nonzero(w.source_authority_id, 'multi attempt authority');
    assert_nonzero(w.payer_id, 'multi attempt payer');
    assert(w.attempt_version == 1, 'multi attempt version');
    assert(w.revision_kind == ATTEMPT_REVISION_KIND_ORIGINAL, 'multi attempt revision');
    assert(w.parent_attempt_version == 0, 'multi attempt parent');

    let identity_commitment = domain_hash_8(
        DOMAIN_TAG_CLAIM_SOURCE,
        ATTEMPT_RECORD_SCHEMA_TAG,
        w.source_authority_id,
        w.payer_id,
        w.provider_npi,
        w.claim_id,
        w.attempt_version.into(),
        w.revision_kind.into(),
        w.parent_attempt_version.into(),
    );
    let snapshot_commitment = domain_hash_8(
        DOMAIN_TAG_CLAIM_SOURCE,
        ATTEMPT_RECORD_SCHEMA_TAG,
        w.member_id,
        w.service_date_day.into(),
        w.service_lines_commitment,
        w.diagnosis_commitment,
        w.diagnosis_count.into(),
        w.total_charge_cents.into(),
        w.service_line_count.into(),
    );
    domain_hash_3(
        DOMAIN_TAG_CLAIM_SOURCE,
        ATTEMPT_RECORD_SCHEMA_TAG,
        identity_commitment,
        snapshot_commitment,
    )
}

fn claim_source_leaf_for(w: ClaimSourceWitness, ruleset_root: felt252) -> felt252 {
    assert_cents(w.total_charge_cents, 'claim cents range');
    let attempt_record_commitment = attempt_record_commitment_for(w);
    domain_hash_12(
        DOMAIN_TAG_CLAIM_SOURCE,
        CLAIM_SOURCE_SCHEMA_TAG,
        w.claim_id,
        w.member_id,
        w.provider_npi,
        w.service_date_day.into(),
        w.service_lines_commitment,
        w.diagnosis_commitment,
        w.diagnosis_count.into(),
        w.total_charge_cents.into(),
        w.attempt_nullifier,
        attempt_record_commitment,
        ruleset_root,
    )
}

fn assert_multi_line_policy_row_intrinsic_shape(row: MultiLineFeeRowWitness) {
    assert_cents(row.allowed_cents, 'multi fee cents range');
    assert_bool(row.requires_tar, 'multi policy tar bool');
    assert(row.policy_leaf_index != 0, 'multi policy row index');
    assert(row.next_policy_leaf_index != 0, 'multi policy next index');
    assert(
        row.row_kind == POLICY_ROW_KIND_LOWER_SENTINEL
            || row.row_kind == POLICY_ROW_KIND_REAL
            || row.row_kind == POLICY_ROW_KIND_UPPER_SENTINEL,
        'multi policy row kind',
    );

    if row.row_kind == POLICY_ROW_KIND_LOWER_SENTINEL {
        assert(row.procedure_code == POLICY_LOWER_SENTINEL_KEY, 'multi policy lower key');
        assert(row.policy_leaf_index == 1, 'multi policy lower index');
        assert(row.allowed_cents == 0, 'multi policy lower allowed');
        assert(row.requires_tar == 0, 'multi policy lower tar');
    } else if row.row_kind == POLICY_ROW_KIND_UPPER_SENTINEL {
        assert(row.procedure_code == POLICY_UPPER_SENTINEL_KEY, 'multi policy upper key');
        assert(row.next_procedure_code == POLICY_UPPER_SENTINEL_KEY, 'multi policy upper next');
        assert(row.next_policy_leaf_index == row.policy_leaf_index, 'multi policy upper index');
        assert(row.allowed_cents == 0, 'multi policy upper allowed');
        assert(row.requires_tar == 0, 'multi policy upper tar');
    } else {
        assert(
            multi_line_felt_lt(POLICY_LOWER_SENTINEL_KEY, row.procedure_code),
            'multi policy real lower',
        );
        assert(
            multi_line_felt_lt(row.procedure_code, POLICY_UPPER_SENTINEL_KEY),
            'multi policy real upper',
        );
        assert(row.policy_leaf_index > 1, 'multi policy real index');
    }

    if row.row_kind != POLICY_ROW_KIND_UPPER_SENTINEL {
        assert(
            multi_line_felt_lt(row.procedure_code, row.next_procedure_code),
            'multi policy successor order',
        );
        assert(
            multi_line_felt_lte(row.next_procedure_code, POLICY_UPPER_SENTINEL_KEY),
            'multi policy successor upper',
        );
        assert(
            row.next_policy_leaf_index == row.policy_leaf_index + 1, 'multi policy successor index',
        );
    }
}

fn multi_line_fee_leaf_for(row: MultiLineFeeRowWitness) -> felt252 {
    assert_multi_line_policy_row_intrinsic_shape(row);
    domain_hash_10(
        DOMAIN_TAG_FEE,
        POLICY_ROW_SCHEMA_TAG,
        row.row_kind.into(),
        row.procedure_code,
        row.allowed_cents.into(),
        row.requires_tar.into(),
        row.next_procedure_code,
        row.next_policy_leaf_index.into(),
        row.policy_leaf_index.into(),
        DEFAULT_FEE_EFFECTIVE_FROM_DAY.into(),
        DEFAULT_FEE_EFFECTIVE_UNTIL_DAY.into(),
    )
}

fn multi_line_fee_policy_leaf_for(
    ruleset_root: felt252, tree_depth: u128, real_row_count: u128,
) -> felt252 {
    domain_hash_5(
        DOMAIN_TAG_FEE,
        FEE_POLICY_SCHEMA_TAG,
        FEE_SOURCE_UNBOUND,
        ruleset_root,
        tree_depth.into(),
        real_row_count.into(),
    )
}

fn multi_line_authorization_leaf_for(auth: MultiLineAuthorizationWitness) -> felt252 {
    assert_bool(auth.authorization_present, 'multi auth bool');
    if auth.authorization_present == 1 {
        assert(auth.prior_authorization != 0, 'multi auth token');
        assert(
            auth.signed_tar_authorization_commitment == auth.prior_authorization,
            'multi auth signed token',
        );
    } else {
        assert(auth.signed_tar_authorization_commitment == 0, 'multi auth signed empty');
    }
    domain_hash_13(
        DOMAIN_TAG_ORACLE,
        1,
        auth.claim_id,
        auth.line_index.into(),
        auth.procedure_code,
        auth.service_date_day.into(),
        auth.prior_authorization,
        auth.signed_tar_authorization_commitment,
        auth.authorization_present.into(),
        auth.signer_root,
        auth.fact_verification_commitment,
        auth.evidence_root,
        auth.valid_from_day.into(),
        auth.valid_until_day.into(),
    )
}

fn indexed_nullifier_leaf_hash(
    value: felt252, next_value: felt252, next_index: u128, index: u128,
) -> felt252 {
    domain_hash_4(DOMAIN_TAG_NULLIFIER, value, next_value, next_index.into(), index.into())
}

pub fn ruleset_policy_digest(
    mode: felt252, version_commitment: felt252, payload_commitment: felt252,
) -> felt252 {
    domain_hash_3(DOMAIN_TAG_RULESET, mode, version_commitment, payload_commitment)
}

pub fn assert_ruleset_policy_digest(
    mode: felt252,
    version_commitment: felt252,
    payload_commitment: felt252,
    ruleset_root: felt252,
    onchain_ruleset_root: felt252,
) {
    assert_nonzero(ruleset_root, 'ruleset root');
    assert(ruleset_root == onchain_ruleset_root, 'ruleset onchain');
    assert(
        ruleset_policy_digest(mode, version_commitment, payload_commitment) == ruleset_root,
        'ruleset digest',
    );
}

pub fn batch_nullifier_commitment_from_values(nullifiers: Span<felt252>) -> felt252 {
    let mut acc = 0;
    let mut index = 0;
    loop {
        if index == nullifiers.len() {
            break;
        }
        acc = domain_hash_2(DOMAIN_TAG_NULLIFIER, acc, *nullifiers.at(index));
        index += 1;
    }
    acc
}

pub fn assert_batch_nullifier_commitment(
    nullifiers: Span<felt252>, batch_nullifier_commitment: felt252,
) {
    assert(
        batch_nullifier_commitment_from_values(nullifiers) == batch_nullifier_commitment,
        'batch nullifier',
    );
}

fn nullifier_words_less(
    left_high: u128, left_low: u128, right_high: u128, right_low: u128,
) -> bool {
    left_high < right_high || (left_high == right_high && left_low < right_low)
}

fn nullifier_words_equal(
    left_high: u128, left_low: u128, right_high: u128, right_low: u128,
) -> bool {
    left_high == right_high && left_low == right_low
}

fn assert_valid_nullifier_words(high: u128, low: u128) {
    assert(high != 0 || low != 0, 'nullifier zero');
    assert(
        nullifier_words_less(high, low, MAX_NULLIFIER_HIGH, MAX_NULLIFIER_LOW), 'nullifier range',
    );
}

fn nullifier_words_to_felt(high: u128, low: u128) -> felt252 {
    assert_valid_nullifier_words(high, low);
    high.into() * TWO_POW_128_FELT + low.into()
}

fn assert_valid_nullifier_leaf_words(high: u128, low: u128) {
    assert(
        nullifier_words_less(high, low, MAX_NULLIFIER_HIGH, MAX_NULLIFIER_LOW)
            || nullifier_words_equal(high, low, MAX_NULLIFIER_HIGH, MAX_NULLIFIER_LOW),
        'nullifier leaf range',
    );
}

fn nullifier_leaf_words_to_felt(high: u128, low: u128) -> felt252 {
    assert_valid_nullifier_leaf_words(high, low);
    high.into() * TWO_POW_128_FELT + low.into()
}

fn epoch_nullifier_set_root_from_words_with_empty(
    words: Span<u128>, depth: u32, empty_root: felt252,
) -> felt252 {
    let word_count = words.len();
    assert_even(word_count, 'epoch words pairs');
    let value_count = word_count / 2;
    let value_count_felt: felt252 = value_count.into();
    let mut acc = domain_hash_3(DOMAIN_TAG_NULLIFIER, depth.into(), value_count_felt, empty_root);
    let mut index = 0;
    let mut index_felt = 0;
    let mut previous_high = 0_u128;
    let mut previous_low = 0_u128;

    loop {
        if index == value_count {
            break;
        }
        let high = *words.at(index * 2);
        let low = *words.at(index * 2 + 1);
        assert_valid_nullifier_words(high, low);
        if index != 0 {
            assert(nullifier_words_less(previous_high, previous_low, high, low), 'epoch order');
        }
        acc =
            domain_hash_3(
                DOMAIN_TAG_NULLIFIER, acc, index_felt, nullifier_words_to_felt(high, low),
            );
        previous_high = high;
        previous_low = low;
        index += 1;
        index_felt += 1;
    }
    acc
}

pub fn epoch_nullifier_set_root_from_words(words: Span<u128>, depth: u32) -> felt252 {
    let mut empty_root = 0;
    let mut depth_index: u32 = 0;
    loop {
        if depth_index == depth {
            break;
        }
        empty_root = domain_hash_2(DOMAIN_TAG_NULLIFIER, empty_root, empty_root);
        depth_index += 1;
    }
    epoch_nullifier_set_root_from_words_with_empty(words, depth, empty_root)
}

pub fn batch_nullifier_commitment_from_word_values(words: Span<u128>) -> felt252 {
    let word_count = words.len();
    assert_even(word_count, 'batch null words');
    let value_count = word_count / 2;
    let mut acc = 0;
    let mut index = 0;
    loop {
        if index == value_count {
            break;
        }
        acc =
            domain_hash_2(
                DOMAIN_TAG_NULLIFIER,
                acc,
                nullifier_words_to_felt(*words.at(index * 2), *words.at(index * 2 + 1)),
            );
        index += 1;
    }
    acc
}

pub fn assert_epoch_nullifier_set_transition(
    existing_words: Span<u128>,
    batch_words: Span<u128>,
    depth: u32,
    root_before: felt252,
    root_after: felt252,
    batch_nullifier_commitment: felt252,
) {
    let mut empty_root = 0;
    let mut depth_index: u32 = 0;
    loop {
        if depth_index == depth {
            break;
        }
        empty_root = domain_hash_2(DOMAIN_TAG_NULLIFIER, empty_root, empty_root);
        depth_index += 1;
    }
    assert(
        epoch_nullifier_set_root_from_words_with_empty(
            existing_words, depth, empty_root,
        ) == root_before,
        'epoch before root',
    );
    assert(
        batch_nullifier_commitment_from_word_values(batch_words) == batch_nullifier_commitment,
        'epoch layer a',
    );

    let existing_count = existing_words.len() / 2;
    let batch_count = batch_words.len() / 2;
    assert(batch_count != 0, 'epoch empty batch');
    let mut merged: Array<u128> = ArrayTrait::new();
    let mut existing_index = 0;
    let mut batch_index = 0;

    loop {
        if existing_index == existing_count && batch_index == batch_count {
            break;
        }
        if existing_index == existing_count {
            merged.append(*batch_words.at(batch_index * 2));
            merged.append(*batch_words.at(batch_index * 2 + 1));
            batch_index += 1;
        } else if batch_index == batch_count {
            merged.append(*existing_words.at(existing_index * 2));
            merged.append(*existing_words.at(existing_index * 2 + 1));
            existing_index += 1;
        } else {
            let existing_high = *existing_words.at(existing_index * 2);
            let existing_low = *existing_words.at(existing_index * 2 + 1);
            let batch_high = *batch_words.at(batch_index * 2);
            let batch_low = *batch_words.at(batch_index * 2 + 1);
            assert(
                !nullifier_words_equal(existing_high, existing_low, batch_high, batch_low),
                'epoch duplicate',
            );
            if nullifier_words_less(existing_high, existing_low, batch_high, batch_low) {
                merged.append(existing_high);
                merged.append(existing_low);
                existing_index += 1;
            } else {
                merged.append(batch_high);
                merged.append(batch_low);
                batch_index += 1;
            }
        }
    }

    assert(
        epoch_nullifier_set_root_from_words_with_empty(
            merged.span(), depth, empty_root,
        ) == root_after,
        'epoch after root',
    );
}

fn audit_tree_root_from_words(tag: felt252, words: Span<u128>, depth: u32) -> felt252 {
    let word_count = words.len();
    assert_even(word_count, 'audit words pairs');
    let leaf_count = word_count / 2;
    let mut capacity: usize = 1;
    let mut zeros: Array<felt252> = ArrayTrait::new();
    let mut zero = 0;
    zeros.append(zero);
    let mut depth_index: u32 = 0;

    loop {
        if depth_index == depth {
            break;
        }
        capacity = capacity * 2;
        zero = domain_hash_2(tag, zero, zero);
        zeros.append(zero);
        depth_index += 1;
    }
    assert(leaf_count <= capacity, 'audit capacity');
    if leaf_count == 0 {
        return *zeros.span().at(depth.into());
    }

    let mut current: Array<felt252> = ArrayTrait::new();
    let mut index = 0;
    loop {
        if index == leaf_count {
            break;
        }
        let high = *words.at(index * 2);
        let low = *words.at(index * 2 + 1);
        current.append(domain_hash_2(tag, high.into(), low.into()));
        index += 1;
    }

    let mut level: u32 = 0;
    loop {
        if level == depth {
            break;
        }
        let current_span = current.span();
        let mut parents: Array<felt252> = ArrayTrait::new();
        let mut pair_index = 0;
        loop {
            if pair_index >= current_span.len() {
                break;
            }
            let right = if pair_index + 1 < current_span.len() {
                *current_span.at(pair_index + 1)
            } else {
                *zeros.span().at(level.into())
            };
            parents.append(domain_hash_2(tag, *current_span.at(pair_index), right));
            pair_index += 2;
        }
        current = parents;
        level += 1;
    }

    let root_span = current.span();
    *root_span.at(0)
}

pub fn claim_audit_tree_root_from_words(words: Span<u128>, depth: u32) -> felt252 {
    audit_tree_root_from_words(DOMAIN_TAG_CLAIM, words, depth)
}

pub fn result_audit_tree_root_from_words(words: Span<u128>, depth: u32) -> felt252 {
    audit_tree_root_from_words(DOMAIN_TAG_RESULT, words, depth)
}

pub fn payment_audit_tree_root_from_words(words: Span<u128>, depth: u32) -> felt252 {
    audit_tree_root_from_words(DOMAIN_TAG_PAYMENT, words, depth)
}

pub fn assert_claim_audit_tree_root(
    words: Span<u128>, depth: u32, claim_root: felt252, onchain_claim_root: felt252,
) {
    assert_nonzero(claim_root, 'claim audit root');
    assert(claim_root == onchain_claim_root, 'claim audit onchain');
    assert(claim_audit_tree_root_from_words(words, depth) == claim_root, 'claim audit tree');
}

pub fn assert_result_audit_tree_root(
    words: Span<u128>, depth: u32, result_root: felt252, onchain_result_root: felt252,
) {
    assert_nonzero(result_root, 'result root');
    assert(result_root == onchain_result_root, 'result onchain');
    assert(result_audit_tree_root_from_words(words, depth) == result_root, 'result tree');
}

pub fn assert_payment_audit_tree_root(
    words: Span<u128>, depth: u32, payment_root: felt252, onchain_payment_root: felt252,
) {
    assert_nonzero(payment_root, 'payment root');
    assert(payment_root == onchain_payment_root, 'payment onchain');
    assert(payment_audit_tree_root_from_words(words, depth) == payment_root, 'payment tree');
}

fn verify_claim_source(w: ClaimSourceWitness, claim_source_root: felt252, ruleset_root: felt252) {
    assert(w.claim_source_leaf == claim_source_leaf_for(w, ruleset_root), 'claim leaf');
    assert(
        verify_poseidon_merkle_path(
            DOMAIN_TAG_CLAIM_SOURCE,
            w.claim_source_leaf,
            w.claim_source_leaf_index,
            w.claim_source_path_elements,
        ) == claim_source_root,
        'claim source membership',
    );
}

pub fn assert_claim_source_membership(
    w: ClaimSourceWitness, claim_source_root: felt252, ruleset_root: felt252,
) {
    assert_nonzero(claim_source_root, 'claim root');
    assert_nonzero(ruleset_root, 'ruleset root');
    verify_claim_source(w, claim_source_root, ruleset_root);
}

fn verify_poseidon_merkle_path(
    tag: felt252, leaf_hash: felt252, leaf_index: u128, path_elements: Span<felt252>,
) -> felt252 {
    let mut current = leaf_hash;
    let mut cursor = leaf_index;
    let mut index: usize = 0;
    loop {
        if index == path_elements.len() {
            break;
        }
        let sibling = *path_elements.at(index);
        let expected_bit = if cursor % 2 == 0 {
            0
        } else {
            1
        };
        current =
            if expected_bit == 0 {
                domain_hash_2(tag, current, sibling)
            } else {
                domain_hash_2(tag, sibling, current)
            };
        cursor = cursor / 2;
        index += 1;
    }
    current
}

fn verify_multi_line_fee_policy(
    w: MultiLineFeePolicyWitness, policy_root: felt252, ruleset_root: felt252,
) {
    let tree_depth: usize = w.tree_depth.try_into().unwrap();
    assert(w.fee_policy_path_elements.len() == tree_depth, 'multi fee policy depth');
    assert(
        w
            .fee_policy_leaf == multi_line_fee_policy_leaf_for(
                ruleset_root, w.tree_depth, w.real_row_count,
            ),
        'multi fee policy',
    );
    assert(w.fee_policy_leaf_index == 0, 'multi fee policy index');
    assert(
        verify_poseidon_merkle_path(
            DOMAIN_TAG_FEE, w.fee_policy_leaf, w.fee_policy_leaf_index, w.fee_policy_path_elements,
        ) == policy_root,
        'multi fee policy path',
    );
}

fn verify_multi_line_policy_row(
    row: MultiLineFeeRowWitness, policy_root: felt252, tree_depth: u128, real_row_count: u128,
) -> felt252 {
    let expected_tree_depth: usize = tree_depth.try_into().unwrap();
    assert(row.policy_path_elements.len() == expected_tree_depth, 'multi policy row depth');
    let upper_leaf_index = real_row_count + 2;
    if row.row_kind == POLICY_ROW_KIND_LOWER_SENTINEL {
        assert(row.policy_leaf_index == 1, 'multi policy lower count index');
    } else if row.row_kind == POLICY_ROW_KIND_REAL {
        assert(row.policy_leaf_index <= real_row_count + 1, 'multi policy real count index');
    } else if row.row_kind == POLICY_ROW_KIND_UPPER_SENTINEL {
        assert(row.policy_leaf_index == upper_leaf_index, 'multi policy upper count index');
    }
    let fee_leaf = multi_line_fee_leaf_for(row);
    assert(
        verify_poseidon_merkle_path(
            DOMAIN_TAG_FEE, fee_leaf, row.policy_leaf_index, row.policy_path_elements,
        ) == policy_root,
        'multi policy row path',
    );
    fee_leaf
}

fn verify_batch_policy_dictionary(
    fee_policy: MultiLineFeePolicyWitness,
    policy_rows: Span<MultiLineFeeRowWitness>,
    policy_root: felt252,
    ruleset_root: felt252,
) {
    verify_multi_line_fee_policy(fee_policy, policy_root, ruleset_root);
    assert(policy_rows.len() != 0, 'multi policy dict empty');
    let mut index: usize = 0;
    loop {
        if index == policy_rows.len() {
            break;
        }
        verify_multi_line_policy_row(
            *policy_rows.at(index), policy_root, fee_policy.tree_depth, fee_policy.real_row_count,
        );
        index += 1;
    };
}

fn assert_multi_line_authorization_shape(
    line: MultiLineServiceLineWitness,
    auth: MultiLineAuthorizationWitness,
    expected_line_index: u128,
    claim_id: felt252,
    service_date_day: u128,
) -> (MultiLineAuthorizationWitness, felt252) {
    assert(auth.claim_id == claim_id, 'multi auth claim');
    assert(auth.line_index == expected_line_index, 'multi auth line index');
    assert(auth.procedure_code == line.procedure_code, 'multi auth procedure');
    assert(auth.service_date_day == service_date_day, 'multi auth service date');
    assert(auth.prior_authorization == line.prior_authorization, 'multi auth line token');
    if auth.authorization_present == 1 {
        assert(
            auth.signed_tar_authorization_commitment == line.prior_authorization,
            'multi auth signed token',
        );
    } else {
        assert(auth.signed_tar_authorization_commitment == 0, 'multi auth signed empty');
    }
    assert(auth.valid_from_day <= service_date_day, 'multi auth valid from');
    assert(service_date_day <= auth.valid_until_day, 'multi auth valid until');
    let auth_leaf = multi_line_authorization_leaf_for(auth);
    (auth, auth_leaf)
}

fn verify_multi_line_authorization(
    line: MultiLineServiceLineWitness,
    auth: MultiLineAuthorizationWitness,
    expected_line_index: u128,
    claim_id: felt252,
    service_date_day: u128,
    oracle_facts_root: felt252,
) -> (u32, felt252) {
    let (auth, auth_leaf) = assert_multi_line_authorization_shape(
        line, auth, expected_line_index, claim_id, service_date_day,
    );
    assert(auth.auth_proof_root == oracle_facts_root, 'multi auth root');
    assert(
        verify_poseidon_merkle_path(
            DOMAIN_TAG_ORACLE, auth_leaf, auth.auth_leaf_index, auth.auth_path_elements,
        ) == oracle_facts_root,
        'multi auth path',
    );
    (auth.authorization_present, auth_leaf)
}

fn hash_poseidon_path_step(tag: felt252, current: felt252, sibling: felt252, bit: u32) -> felt252 {
    assert(bit == 0 || bit == 1, 'path bit');
    if bit == 0 {
        domain_hash_2(tag, current, sibling)
    } else {
        domain_hash_2(tag, sibling, current)
    }
}

fn verify_poseidon_two_leaf_same_root(
    tag: felt252,
    left_leaf: felt252,
    left_index: u128,
    left_path_elements: Span<felt252>,
    right_leaf: felt252,
    right_index: u128,
    right_path_elements: Span<felt252>,
) -> felt252 {
    assert(left_path_elements.len() == right_path_elements.len(), 'shared path depth');
    assert(left_index != right_index, 'shared path index');

    let mut left_current = left_leaf;
    let mut right_current = right_leaf;
    let mut left_cursor = left_index;
    let mut right_cursor = right_index;
    let mut level: usize = 0;
    let mut joined = false;

    loop {
        if level == left_path_elements.len() {
            break;
        }
        let left_bit: u32 = (left_cursor % 2).try_into().unwrap();
        let right_bit: u32 = (right_cursor % 2).try_into().unwrap();
        if left_cursor / 2 == right_cursor / 2 {
            assert(left_cursor != right_cursor, 'shared path distinct');
            assert(left_bit != right_bit, 'shared path bits');
            assert(*left_path_elements.at(level) == right_current, 'left sibling');
            assert(*right_path_elements.at(level) == left_current, 'right sibling');
            left_current =
                if left_bit == 0 {
                    domain_hash_2(tag, left_current, right_current)
                } else {
                    domain_hash_2(tag, right_current, left_current)
                };
            left_cursor = left_cursor / 2;
            right_cursor = right_cursor / 2;
            level += 1;
            joined = true;
            break;
        }
        left_current =
            hash_poseidon_path_step(tag, left_current, *left_path_elements.at(level), left_bit);
        right_current =
            hash_poseidon_path_step(tag, right_current, *right_path_elements.at(level), right_bit);
        left_cursor = left_cursor / 2;
        right_cursor = right_cursor / 2;
        level += 1;
    }

    assert(joined, 'shared path join');
    assert(left_cursor == right_cursor, 'shared cursor');

    loop {
        if level == left_path_elements.len() {
            break;
        }
        assert(left_cursor == right_cursor, 'shared cursor');
        let left_bit: u32 = (left_cursor % 2).try_into().unwrap();
        let right_bit: u32 = (right_cursor % 2).try_into().unwrap();
        assert(left_bit == right_bit, 'shared path bit');
        let left_sibling = *left_path_elements.at(level);
        let right_sibling = *right_path_elements.at(level);
        assert(left_sibling == right_sibling, 'shared sibling');
        left_current = hash_poseidon_path_step(tag, left_current, left_sibling, left_bit);
        left_cursor = left_cursor / 2;
        right_cursor = right_cursor / 2;
        level += 1;
    }

    assert(left_cursor == 0, 'left capacity');
    assert(right_cursor == 0, 'right capacity');
    left_current
}

fn hash_nullifier_path_step(current: felt252, sibling: felt252, bit: u32) -> felt252 {
    assert(bit == 0 || bit == 1, 'null path bit');
    if bit == 0 {
        domain_hash_2(DOMAIN_TAG_NULLIFIER, current, sibling)
    } else {
        domain_hash_2(DOMAIN_TAG_NULLIFIER, sibling, current)
    }
}

fn verify_nullifier_two_leaf_transition(
    predecessor_leaf_hash: felt252,
    updated_predecessor_leaf_hash: felt252,
    inserted_leaf_hash: felt252,
    predecessor_index: u128,
    inserted_index: u128,
    predecessor_path_elements: Span<felt252>,
    inserted_path_elements: Span<felt252>,
) -> (felt252, felt252) {
    assert(predecessor_path_elements.len() == NULLIFIER_TREE_DEPTH, 'null pred path depth');
    assert(inserted_path_elements.len() == NULLIFIER_TREE_DEPTH, 'null ins path depth');
    assert(predecessor_index != inserted_index, 'null inserted index');

    let mut pred_old = predecessor_leaf_hash;
    let mut pred_new = updated_predecessor_leaf_hash;
    let mut ins_old = NULLIFIER_EMPTY_LEAF;
    let mut ins_new = inserted_leaf_hash;
    let mut pred_cursor = predecessor_index;
    let mut ins_cursor = inserted_index;
    let mut level: usize = 0;
    let mut joined = false;

    loop {
        if level == NULLIFIER_TREE_DEPTH {
            break;
        }
        let pred_bit: u32 = (pred_cursor % 2).try_into().unwrap();
        let ins_bit: u32 = (ins_cursor % 2).try_into().unwrap();

        if pred_cursor / 2 == ins_cursor / 2 {
            assert(pred_cursor != ins_cursor, 'null multiproof distinct');
            assert(pred_bit != ins_bit, 'null multiproof bits');
            if pred_bit == 0 {
                assert(*predecessor_path_elements.at(level) == ins_old, 'null pred sibling');
                assert(*inserted_path_elements.at(level) == pred_new, 'null ins sibling');
                pred_old = domain_hash_2(DOMAIN_TAG_NULLIFIER, pred_old, ins_old);
                pred_new = domain_hash_2(DOMAIN_TAG_NULLIFIER, pred_new, ins_new);
            } else {
                assert(*predecessor_path_elements.at(level) == ins_old, 'null pred sibling');
                assert(*inserted_path_elements.at(level) == pred_new, 'null ins sibling');
                pred_old = domain_hash_2(DOMAIN_TAG_NULLIFIER, ins_old, pred_old);
                pred_new = domain_hash_2(DOMAIN_TAG_NULLIFIER, ins_new, pred_new);
            }
            pred_cursor = pred_cursor / 2;
            ins_cursor = ins_cursor / 2;
            level += 1;
            joined = true;
            break;
        }

        pred_old =
            hash_nullifier_path_step(pred_old, *predecessor_path_elements.at(level), pred_bit);
        pred_new =
            hash_nullifier_path_step(pred_new, *predecessor_path_elements.at(level), pred_bit);
        ins_old = hash_nullifier_path_step(ins_old, *inserted_path_elements.at(level), ins_bit);
        ins_new = hash_nullifier_path_step(ins_new, *inserted_path_elements.at(level), ins_bit);
        pred_cursor = pred_cursor / 2;
        ins_cursor = ins_cursor / 2;
        level += 1;
    }

    assert(joined, 'null multiproof join');
    assert(pred_cursor == ins_cursor, 'null shared cursor');
    let mut root_before = pred_old;
    let mut root_after = pred_new;

    loop {
        if level == NULLIFIER_TREE_DEPTH {
            break;
        }
        assert(pred_cursor == ins_cursor, 'null shared cursor');
        let pred_bit: u32 = (pred_cursor % 2).try_into().unwrap();
        let ins_bit: u32 = (ins_cursor % 2).try_into().unwrap();
        assert(pred_bit == ins_bit, 'null shared bit');
        let pred_sibling = *predecessor_path_elements.at(level);
        let ins_sibling = *inserted_path_elements.at(level);
        assert(pred_sibling == ins_sibling, 'null shared sibling');
        root_before = hash_nullifier_path_step(root_before, pred_sibling, pred_bit);
        root_after = hash_nullifier_path_step(root_after, pred_sibling, pred_bit);
        pred_cursor = pred_cursor / 2;
        ins_cursor = ins_cursor / 2;
        level += 1;
    }

    assert(pred_cursor == 0, 'null pred capacity');
    assert(ins_cursor == 0, 'null ins capacity');
    (root_before, root_after)
}

fn verify_nullifier_transition(w: NullifierNonMembershipWitness) {
    assert_valid_nullifier_leaf_words(w.predecessor_value_high, w.predecessor_value_low);
    assert_valid_nullifier_words(w.inserted_nullifier_high, w.inserted_nullifier_low);
    assert_valid_nullifier_leaf_words(w.successor_value_high, w.successor_value_low);
    assert(
        nullifier_words_less(
            w.predecessor_value_high,
            w.predecessor_value_low,
            w.inserted_nullifier_high,
            w.inserted_nullifier_low,
        ),
        'null low range',
    );
    assert(
        nullifier_words_less(
            w.inserted_nullifier_high,
            w.inserted_nullifier_low,
            w.successor_value_high,
            w.successor_value_low,
        ),
        'null high range',
    );
    assert(w.inserted_index != w.predecessor_index, 'null inserted index');
    let predecessor_value = nullifier_leaf_words_to_felt(
        w.predecessor_value_high, w.predecessor_value_low,
    );
    let inserted_nullifier = nullifier_words_to_felt(
        w.inserted_nullifier_high, w.inserted_nullifier_low,
    );
    let successor_value = nullifier_leaf_words_to_felt(
        w.successor_value_high, w.successor_value_low,
    );
    let predecessor_leaf_hash = indexed_nullifier_leaf_hash(
        predecessor_value, successor_value, w.successor_index, w.predecessor_index,
    );
    let updated_predecessor_leaf_hash = indexed_nullifier_leaf_hash(
        predecessor_value, inserted_nullifier, w.inserted_index, w.predecessor_index,
    );
    let inserted_leaf_hash = indexed_nullifier_leaf_hash(
        inserted_nullifier, successor_value, w.successor_index, w.inserted_index,
    );

    let (root_before, inserted_root_after) = verify_nullifier_two_leaf_transition(
        predecessor_leaf_hash,
        updated_predecessor_leaf_hash,
        inserted_leaf_hash,
        w.predecessor_index,
        w.inserted_index,
        w.predecessor_path_elements,
        w.inserted_path_elements,
    );
    assert(root_before == w.live_root_before, 'null live root');
    assert(root_before == w.onchain_root_before, 'null root onchain');
    assert(inserted_root_after == w.root_after, 'null after root');
    assert(inserted_root_after == w.onchain_root_after, 'null after onchain');
}

pub fn assert_nullifier_nonmembership_transition(w: NullifierNonMembershipWitness) {
    verify_nullifier_transition(w);
}

fn first_failure_code(
    g1: u32,
    g2: u32,
    g2b: u32,
    g3: u32,
    g4: u32,
    g4b: u32,
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
    if g2b == 0 {
        return 3;
    }
    if g3 == 0 {
        return 4;
    }
    if g4 == 0 {
        return 5;
    }
    if g4b == 0 {
        return 6;
    }
    if g5 == 0 {
        return 7;
    }
    if g6 == 0 {
        return 8;
    }
    if g7 == 0 {
        return 9;
    }
    if g8a == 0 {
        return 10;
    }
    if g8b == 0 {
        return 11;
    }
    if g9 == 0 {
        return 12;
    }
    if g10 == 0 {
        return 13;
    }
    0
}

pub fn multi_line_payment_line_leaf(
    line: MultiLineServiceLineWitness, fee_leaf: felt252, auth_leaf: felt252,
) -> felt252 {
    domain_hash_9(
        DOMAIN_TAG_PAYMENT,
        line.procedure_code,
        line.line_charge_cents.into(),
        line.units_cents.into(),
        line.prior_authorization,
        line.allowed_cents.into(),
        fee_leaf,
        line.tar_required.into(),
        line.policy_present.into(),
        auth_leaf,
    )
}

pub fn commitment_for_multi_line_claim(
    input: MultiLineDecisionInput,
    normalized_fact_commitment: felt252,
    payment_lines_commitment: felt252,
    ruleset_root: felt252,
) -> felt252 {
    domain_hash_6(
        DOMAIN_TAG_PAYMENT,
        input.batch_id,
        input.claim.claim_source_leaf,
        normalized_fact_commitment,
        payment_lines_commitment,
        input.claim.attempt_nullifier,
        ruleset_root,
    )
}

fn multi_line_min_u128(left: u128, right: u128) -> u128 {
    if left < right {
        left
    } else {
        right
    }
}

fn multi_line_felt_lt(left: felt252, right: felt252) -> bool {
    let left_value: u256 = left.into();
    let right_value: u256 = right.into();
    left_value < right_value
}

fn multi_line_felt_lte(left: felt252, right: felt252) -> bool {
    let left_value: u256 = left.into();
    let right_value: u256 = right.into();
    left_value <= right_value
}

fn multi_line_canonical_key_lte(
    left_procedure: felt252,
    left_charge: u128,
    left_units: u128,
    left_prior_auth: felt252,
    right_procedure: felt252,
    right_charge: u128,
    right_units: u128,
    right_prior_auth: felt252,
) -> bool {
    if multi_line_felt_lt(left_procedure, right_procedure) {
        return true;
    }
    if multi_line_felt_lt(right_procedure, left_procedure) {
        return false;
    }
    if left_charge < right_charge {
        return true;
    }
    if right_charge < left_charge {
        return false;
    }
    if left_units < right_units {
        return true;
    }
    if right_units < left_units {
        return false;
    }
    multi_line_felt_lte(left_prior_auth, right_prior_auth)
}

fn multi_line_service_lines_commitment(w: MultiLineClaimWitness) -> felt252 {
    let line_count_felt: felt252 = w.service_lines.len().into();
    let mut acc = domain_hash_1(DOMAIN_TAG_CLAIM_SOURCE, line_count_felt);
    let mut index: usize = 0;
    let mut previous_exists: u32 = 0;
    let mut previous_procedure: felt252 = 0;
    let mut previous_charge: u128 = 0;
    let mut previous_units: u128 = 0;
    let mut previous_prior_auth: felt252 = 0;
    loop {
        if index == w.service_lines.len() {
            break;
        }
        let line = *w.service_lines.at(index);
        if previous_exists == 1 {
            assert(
                multi_line_canonical_key_lte(
                    previous_procedure,
                    previous_charge,
                    previous_units,
                    previous_prior_auth,
                    line.procedure_code,
                    line.line_charge_cents,
                    line.units_cents,
                    line.prior_authorization,
                ),
                'multi line canonical order',
            );
        }
        let index_felt: felt252 = index.into();
        acc =
            domain_hash_7(
                DOMAIN_TAG_CLAIM_SOURCE,
                line_count_felt,
                index_felt,
                acc,
                line.procedure_code,
                line.line_charge_cents.into(),
                line.units_cents.into(),
                line.prior_authorization,
            );
        previous_exists = 1;
        previous_procedure = line.procedure_code;
        previous_charge = line.line_charge_cents;
        previous_units = line.units_cents;
        previous_prior_auth = line.prior_authorization;
        index += 1;
    }
    acc
}

fn verify_multi_line_claim_source_binding(
    input: MultiLineDecisionInput, claim_source_root: felt252, ruleset_root: felt252,
) {
    verify_claim_source(input.claim, claim_source_root, ruleset_root);
    assert(input.claim.claim_source_leaf == input.claim_source_leaf, 'multi claim leaf link');
    let computed_service_lines_commitment = multi_line_service_lines_commitment(input.lines);
    assert(
        computed_service_lines_commitment == input.claim.service_lines_commitment,
        'multi claim service lines',
    );
    assert(input.claim.claim_id == input.lines.claim_id, 'multi claim id link');
    assert(
        input.claim.service_date_day == input.lines.service_date_day,
        'multi claim service date link',
    );
    assert(
        input.claim.total_charge_cents == input.lines.total_charge_cents, 'multi claim total link',
    );
    assert(input.claim.member_id == input.member_id, 'multi claim member link');
    assert(input.claim.provider_npi == input.provider_npi, 'multi claim provider link');
    assert(input.claim.diagnosis_count == input.diagnosis_count, 'multi claim diagnosis link');
    let actual_service_line_count: u128 = input.lines.service_lines.len().try_into().unwrap();
    assert(
        input.claim.service_line_count == actual_service_line_count, 'multi claim line count link',
    );
}

fn normalized_fact_commitment_for_input(input: MultiLineDecisionInput) -> felt252 {
    domain_hash_6(
        DOMAIN_TAG_NORMALIZED_FACTS,
        input.member_active.into(),
        input.provider_payable.into(),
        input.provider_not_suspended.into(),
        input.member_not_deceased.into(),
        input.duplicate_claim_attested.into(),
        input.integrity_hold_attested.into(),
    )
}

fn verify_multi_line_claim_facts(
    input: MultiLineDecisionInput, oracle_facts_root: felt252,
) -> felt252 {
    let normalized = normalized_fact_commitment_for_input(input);
    assert(input.claim_source_leaf == input.claim.claim_source_leaf, 'multi facts claim source');
    let leaf = domain_hash_13(
        DOMAIN_TAG_ORACLE,
        0,
        input.claim.claim_id,
        input.claim_source_leaf,
        input.claim_facts_signer,
        normalized,
        input.claim_facts_verification_commitment,
        input.claim_facts_evidence_commitment,
        input.member_active.into(),
        input.provider_payable.into(),
        input.provider_not_suspended.into(),
        input.member_not_deceased.into(),
        input.duplicate_claim_attested.into(),
        input.integrity_hold_attested.into(),
    );
    assert(leaf == input.claim_facts_leaf, 'multi facts leaf');
    assert(
        verify_poseidon_merkle_path(
            DOMAIN_TAG_ORACLE,
            input.claim_facts_leaf,
            input.claim_facts_leaf_index,
            input.claim_facts_path_elements,
        ) == oracle_facts_root,
        'multi facts path',
    );
    normalized
}

pub fn compute_multi_line_claim_math(
    w: MultiLineClaimWitness, oracle_facts_root: felt252, policy_rows: Span<MultiLineFeeRowWitness>,
) -> MultiLineClaimMathOutput {
    assert(w.service_lines.len() != 0, 'multi no lines');
    assert(w.service_lines.len() <= 50, 'multi line cap');
    assert_cents(w.total_charge_cents, 'multi total range');

    let mut index: usize = 0;
    let mut line_count: u128 = 0;
    let mut sum_line_charge_cents: u128 = 0;
    let mut allowed_total_cents: u128 = 0;
    let mut requires_any_tar: u32 = 0;
    let mut all_required_authorized: u32 = 1;
    let mut all_fee_rows_present: u32 = 1;
    let mut all_charges_and_units_positive: u32 = 1;
    let line_count_felt: felt252 = w.service_lines.len().into();
    let mut payment_lines_commitment = domain_hash_1(DOMAIN_TAG_PAYMENT, line_count_felt);
    loop {
        if index == w.service_lines.len() {
            break;
        }
        let line = *w.service_lines.at(index);
        assert_cents(line.line_charge_cents, 'multi line range');
        assert_cents(line.units_cents, 'multi units range');
        assert_cents(line.allowed_cents, 'multi allowed line');
        if line.line_charge_cents == 0 || line.units_cents == 0 {
            all_charges_and_units_positive = 0;
        }
        assert_bool(line.tar_required, 'multi line tar bool');
        assert_bool(line.policy_present, 'multi policy present bool');
        let policy_row_index: usize = line.policy_row_index.try_into().unwrap();
        assert(policy_row_index < policy_rows.len(), 'multi policy dict index');
        let policy_row = *policy_rows.at(policy_row_index);
        if line.policy_present == 1 {
            assert(policy_row.row_kind == POLICY_ROW_KIND_REAL, 'multi policy member kind');
            assert(policy_row.procedure_code == line.procedure_code, 'multi policy dict code');
            assert(policy_row.allowed_cents == line.allowed_cents, 'multi policy dict allowed');
            assert(policy_row.requires_tar == line.tar_required, 'multi policy dict flag');
        } else {
            assert(
                multi_line_felt_lt(policy_row.procedure_code, line.procedure_code),
                'multi policy absent lower',
            );
            assert(
                multi_line_felt_lt(line.procedure_code, policy_row.next_procedure_code),
                'multi policy absent upper',
            );
            assert(line.allowed_cents == 0, 'multi policy absent allowed');
            assert(line.tar_required == 0, 'multi policy absent tar');
            all_fee_rows_present = 0;
        }
        let fee_leaf = multi_line_fee_leaf_for(policy_row);
        let mut auth_leaf = 0;
        let line_authorized = if line.tar_required == 1 {
            let authorization_index: usize = line.authorization_index.try_into().unwrap();
            assert(authorization_index < w.authorizations.len(), 'multi auth index');
            let authorization = *w.authorizations.at(authorization_index);
            let (authorization_present, computed_auth_leaf) = verify_multi_line_authorization(
                line, authorization, line_count, w.claim_id, w.service_date_day, oracle_facts_root,
            );
            auth_leaf = computed_auth_leaf;
            authorization_present
        } else {
            assert(line.authorization_index == 0, 'multi auth inactive index');
            auth_leaf = 0;
            0
        };
        let index_felt: felt252 = index.into();
        payment_lines_commitment =
            domain_hash_4(
                DOMAIN_TAG_PAYMENT,
                line_count_felt,
                index_felt,
                payment_lines_commitment,
                multi_line_payment_line_leaf(line, fee_leaf, auth_leaf),
            );
        sum_line_charge_cents += line.line_charge_cents;
        allowed_total_cents += multi_line_min_u128(line.line_charge_cents, line.allowed_cents);
        requires_any_tar = if line.tar_required == 1 {
            1
        } else {
            requires_any_tar
        };
        all_required_authorized =
            if line.tar_required == 1 && line_authorized == 0 {
                0
            } else {
                all_required_authorized
            };
        line_count += 1;
        index += 1;
    }

    assert(line_count <= 50, 'multi line count');
    assert_cents(sum_line_charge_cents, 'multi sum computed');
    assert_cents(allowed_total_cents, 'multi allowed computed');
    assert(w.total_charge_cents == sum_line_charge_cents, 'multi total mismatch');

    MultiLineClaimMathOutput {
        line_count,
        sum_line_charge_cents,
        allowed_total_cents,
        requires_any_tar,
        all_required_authorized,
        all_fee_rows_present,
        all_charges_and_units_positive,
        payment_lines_commitment,
    }
}

fn assert_governed_roots_nonzero(
    ruleset_root: felt252,
    claim_source_root: felt252,
    oracle_facts_root: felt252,
    policy_root: felt252,
) {
    assert_nonzero(ruleset_root, 'ruleset root');
    assert_nonzero(claim_source_root, 'claim root');
    assert_nonzero(oracle_facts_root, 'multi oracle root');
    assert_nonzero(policy_root, 'multi policy root');
}

fn adjudicate_multi_line_phase3_with_roots(
    input: MultiLineDecisionInput,
    ruleset_root: felt252,
    claim_source_root: felt252,
    oracle_facts_root: felt252,
    policy_root: felt252,
    policy_rows: Span<MultiLineFeeRowWitness>,
    nullifier_root_before: felt252,
    nullifier_root_after: felt252,
) -> MultiLineDecisionOutput {
    assert_nonzero(input.batch_id, 'batch id');
    assert_bool(input.member_active, 'fact member');
    assert_bool(input.provider_payable, 'fact provider');
    assert_bool(input.provider_not_suspended, 'fact suspended');
    assert_bool(input.member_not_deceased, 'fact deceased');
    assert_bool(input.duplicate_claim_attested, 'fact duplicate');
    assert_bool(input.integrity_hold_attested, 'fact integrity');

    verify_multi_line_claim_source_binding(input, claim_source_root, ruleset_root);
    let normalized_fact_commitment = verify_multi_line_claim_facts(input, oracle_facts_root);
    let math = compute_multi_line_claim_math(input.lines, oracle_facts_root, policy_rows);
    let g1 = bit(input.member_id != 0);
    let g2 = bit(input.member_active == 1);
    let g2b = bit(input.member_not_deceased == 1);
    let g3 = bit(input.provider_npi != 0);
    let g4 = bit(input.provider_payable == 1);
    let g4b = bit(input.provider_not_suspended == 1);
    let g5 = bit(math.line_count != 0);
    let g6 = bit(input.diagnosis_count != 0);
    let g7 = bit(math.all_required_authorized == 1);
    let g8a = bit(
        input.lines.total_charge_cents != 0
            && math.sum_line_charge_cents != 0
            && math.all_charges_and_units_positive == 1,
    );
    let g8b = bit(math.all_fee_rows_present == 1);
    let g9 = bit(input.duplicate_claim_attested == 0);
    let g10 = bit(input.integrity_hold_attested == 0);
    let decision = g1 * g2 * g2b * g3 * g4 * g4b * g5 * g6 * g7 * g8a * g8b * g9 * g10;
    let failure_code = first_failure_code(g1, g2, g2b, g3, g4, g4b, g5, g6, g7, g8a, g8b, g9, g10);
    let payment_cents = if decision == 1 {
        math.allowed_total_cents
    } else {
        0
    };
    let commitment = commitment_for_multi_line_claim(
        input, normalized_fact_commitment, math.payment_lines_commitment, ruleset_root,
    );

    MultiLineDecisionOutput {
        commitment,
        decision,
        failure_code,
        line_count: math.line_count,
        sum_line_charge_cents: math.sum_line_charge_cents,
        allowed_cents: math.allowed_total_cents,
        payment_cents,
        claim_source_root,
        oracle_facts_root,
        policy_root,
        nullifier_root_before,
        nullifier_root_after,
    }
}

fn verify_transition_matches_claim(
    input: MultiLineDecisionInput, transition: NullifierNonMembershipWitness,
) {
    let inserted_nullifier = nullifier_words_to_felt(
        transition.inserted_nullifier_high, transition.inserted_nullifier_low,
    );
    assert(input.claim.attempt_nullifier == inserted_nullifier, 'multi attempt nullifier');
    verify_nullifier_transition(transition);
}

pub fn adjudicate_multi_line_phase3(
    input: MultiLineDecisionInput,
    fee_policy: MultiLineFeePolicyWitness,
    policy_rows: Span<MultiLineFeeRowWitness>,
    nullifier: NullifierNonMembershipWitness,
    ruleset_root: felt252,
    onchain_ruleset_root: felt252,
    claim_source_root: felt252,
    onchain_claim_source_root: felt252,
    oracle_facts_root: felt252,
    onchain_oracle_facts_root: felt252,
    policy_root: felt252,
    onchain_policy_root: felt252,
) -> MultiLineDecisionOutput {
    assert_governed_roots_nonzero(ruleset_root, claim_source_root, oracle_facts_root, policy_root);
    assert(ruleset_root == onchain_ruleset_root, 'ruleset onchain');
    assert(claim_source_root == onchain_claim_source_root, 'claim root onchain');
    assert(oracle_facts_root == onchain_oracle_facts_root, 'multi oracle onchain');
    assert(policy_root == onchain_policy_root, 'multi policy onchain');
    verify_batch_policy_dictionary(fee_policy, policy_rows, policy_root, ruleset_root);
    verify_transition_matches_claim(input, nullifier);
    adjudicate_multi_line_phase3_with_roots(
        input,
        ruleset_root,
        claim_source_root,
        oracle_facts_root,
        policy_root,
        policy_rows,
        nullifier.live_root_before,
        nullifier.root_after,
    )
}

pub fn adjudicate(
    input: MultiLineDecisionInput,
    fee_policy: MultiLineFeePolicyWitness,
    policy_rows: Span<MultiLineFeeRowWitness>,
    nullifier: NullifierNonMembershipWitness,
    ruleset_root: felt252,
    onchain_ruleset_root: felt252,
    claim_source_root: felt252,
    onchain_claim_source_root: felt252,
    oracle_facts_root: felt252,
    onchain_oracle_facts_root: felt252,
    policy_root: felt252,
    onchain_policy_root: felt252,
) -> MultiLineDecisionOutput {
    adjudicate_multi_line_phase3(
        input,
        fee_policy,
        policy_rows,
        nullifier,
        ruleset_root,
        onchain_ruleset_root,
        claim_source_root,
        onchain_claim_source_root,
        oracle_facts_root,
        onchain_oracle_facts_root,
        policy_root,
        onchain_policy_root,
    )
}

fn batch_output_leaf(output: MultiLineDecisionOutput, claim_id: felt252) -> felt252 {
    domain_hash_5(
        DOMAIN_TAG_BATCH,
        claim_id,
        output.decision.into(),
        output.failure_code.into(),
        output.payment_cents.into(),
        output.commitment,
    )
}

pub fn adjudicate_batch(input: BatchClaimInput) -> BatchOutput {
    assert(input.claims.len() != 0, 'batch empty');
    assert(
        input.nullifier_transitions.len() == input.claims.len(), 'batch attempt transition count',
    );
    assert_governed_roots_nonzero(
        input.ruleset_root, input.claim_source_root, input.oracle_facts_root, input.policy_root,
    );
    verify_batch_policy_dictionary(
        input.fee_policy, input.policy_rows, input.policy_root, input.ruleset_root,
    );
    let mut current_root = input.batch_root_before;
    let mut batch_commitment = 0;
    let mut total_allowed_cents: u128 = 0;
    let mut total_payment_cents: u128 = 0;
    let mut approved_count: u32 = 0;
    let mut denied_count: u32 = 0;
    let mut claim_count: u32 = 0;
    let mut index: usize = 0;

    loop {
        if index == input.claims.len() {
            break;
        }
        let claim = *input.claims.at(index);
        let transition = *input.nullifier_transitions.at(index);
        verify_transition_matches_claim(claim, transition);
        assert(transition.onchain_root_before == current_root, 'batch null before chain');
        assert(transition.live_root_before == current_root, 'batch null before');
        let output = adjudicate_multi_line_phase3_with_roots(
            claim,
            input.ruleset_root,
            input.claim_source_root,
            input.oracle_facts_root,
            input.policy_root,
            input.policy_rows,
            transition.live_root_before,
            transition.root_after,
        );
        current_root = transition.root_after;

        if output.decision == 1 {
            total_allowed_cents += output.allowed_cents;
            total_payment_cents += output.payment_cents;
            approved_count += 1;
        } else {
            assert(output.payment_cents == 0, 'batch denied payment');
            denied_count += 1;
        }

        batch_commitment =
            domain_hash_2(
                DOMAIN_TAG_BATCH, batch_commitment, batch_output_leaf(output, claim.claim.claim_id),
            );
        claim_count += 1;
        index += 1;
    }

    assert(current_root == input.expected_batch_root_after, 'batch expected root');
    assert(batch_commitment == input.expected_batch_commitment, 'batch commitment');
    assert(total_allowed_cents == input.expected_total_allowed_cents, 'batch allowed');
    assert(total_payment_cents == input.expected_total_payment_cents, 'batch payment');
    assert(approved_count == input.expected_approved_count, 'batch approved count');
    assert(denied_count == input.expected_denied_count, 'batch denied count');
    assert(claim_count == input.expected_claim_count, 'batch claim count');

    BatchOutput {
        batch_root_before: input.batch_root_before,
        batch_root_after: current_root,
        claim_source_root: input.claim_source_root,
        oracle_facts_root: input.oracle_facts_root,
        policy_root: input.policy_root,
        ruleset_root: input.ruleset_root,
        batch_commitment,
        total_allowed_cents,
        total_payment_cents,
        approved_count,
        denied_count,
        claim_count,
    }
}

pub fn adjudicate_batch_v2(input: BatchClaimInputV2) -> BatchOutputV2 {
    assert_nonzero(input.settlement_domain, 'v2 settlement domain');
    assert_nonzero(input.batch_nonce, 'v2 batch nonce');
    assert_nonzero(input.private_data_commitment, 'v2 private data');
    assert_nonzero(input.privacy_salt, 'v2 privacy salt');
    assert_nonzero(input.value_salt, 'v2 value salt');
    let output = adjudicate_batch(input.batch);
    assert(output.total_payment_cents == output.total_allowed_cents, 'v2 value conservation');

    let opaque_batch_commitment = domain_hash_5(
        DOMAIN_TAG_PRIVATE_BATCH_V2,
        input.batch_nonce,
        output.batch_commitment,
        input.private_data_commitment,
        input.privacy_salt,
        input.settlement_domain,
    );
    let value_conservation_commitment = domain_hash_5(
        DOMAIN_TAG_VALUE_CONSERVATION_V2,
        output.total_allowed_cents.into(),
        output.total_payment_cents.into(),
        input.value_salt,
        output.batch_commitment,
        input.batch_nonce,
    );
    let settlement_commitment = domain_hash_5(
        DOMAIN_TAG_SETTLEMENT_V2,
        PRIVACY_V2_PROTOCOL_VERSION,
        input.settlement_domain,
        input.batch_nonce,
        opaque_batch_commitment,
        value_conservation_commitment,
    );

    BatchOutputV2 {
        protocol_version: PRIVACY_V2_PROTOCOL_VERSION,
        settlement_domain: input.settlement_domain,
        batch_nonce: input.batch_nonce,
        nullifier_root_before: output.batch_root_before,
        nullifier_root_after: output.batch_root_after,
        claim_source_root: output.claim_source_root,
        oracle_facts_root: output.oracle_facts_root,
        policy_root: output.policy_root,
        ruleset_root: output.ruleset_root,
        opaque_batch_commitment,
        value_conservation_commitment,
        settlement_commitment,
    }
}

#[executable]
pub fn main(
    input: MultiLineDecisionInput,
    fee_policy: MultiLineFeePolicyWitness,
    policy_rows: Span<MultiLineFeeRowWitness>,
    nullifier: NullifierNonMembershipWitness,
    ruleset_root: felt252,
    onchain_ruleset_root: felt252,
    claim_source_root: felt252,
    onchain_claim_source_root: felt252,
    oracle_facts_root: felt252,
    onchain_oracle_facts_root: felt252,
    policy_root: felt252,
    onchain_policy_root: felt252,
) -> MultiLineDecisionOutput {
    adjudicate(
        input,
        fee_policy,
        policy_rows,
        nullifier,
        ruleset_root,
        onchain_ruleset_root,
        claim_source_root,
        onchain_claim_source_root,
        oracle_facts_root,
        onchain_oracle_facts_root,
        policy_root,
        onchain_policy_root,
    )
}

#[executable]
pub fn batch_main(input: BatchClaimInput) -> BatchOutput {
    adjudicate_batch(input)
}

#[executable]
pub fn batch_main_v2(input: BatchClaimInputV2) -> BatchOutputV2 {
    adjudicate_batch_v2(input)
}

fn canonical_multi_line_decision_output(
    output: MultiLineDecisionOutput,
) -> CanonicalMultiLineDecisionOutput {
    CanonicalMultiLineDecisionOutput {
        commitment: output.commitment.into(),
        decision: output.decision.into(),
        failure_code: output.failure_code.into(),
        line_count: output.line_count.into(),
        sum_line_charge_cents: output.sum_line_charge_cents.into(),
        allowed_cents: output.allowed_cents.into(),
        payment_cents: output.payment_cents.into(),
        claim_source_root: output.claim_source_root.into(),
        oracle_facts_root: output.oracle_facts_root.into(),
        policy_root: output.policy_root.into(),
        nullifier_root_before: output.nullifier_root_before.into(),
        nullifier_root_after: output.nullifier_root_after.into(),
    }
}

fn canonical_batch_output_v2(output: BatchOutputV2) -> CanonicalBatchOutputV2 {
    CanonicalBatchOutputV2 {
        protocol_version: output.protocol_version.into(),
        settlement_domain: output.settlement_domain.into(),
        batch_nonce: output.batch_nonce.into(),
        nullifier_root_before: output.nullifier_root_before.into(),
        nullifier_root_after: output.nullifier_root_after.into(),
        claim_source_root: output.claim_source_root.into(),
        oracle_facts_root: output.oracle_facts_root.into(),
        policy_root: output.policy_root.into(),
        ruleset_root: output.ruleset_root.into(),
        opaque_batch_commitment: output.opaque_batch_commitment.into(),
        value_conservation_commitment: output.value_conservation_commitment.into(),
        settlement_commitment: output.settlement_commitment.into(),
    }
}

#[executable]
pub fn claim_main_canonical_transport(
    input: MultiLineDecisionInput,
    fee_policy: MultiLineFeePolicyWitness,
    policy_rows: Span<MultiLineFeeRowWitness>,
    nullifier: NullifierNonMembershipWitness,
    ruleset_root: felt252,
    onchain_ruleset_root: felt252,
    claim_source_root: felt252,
    onchain_claim_source_root: felt252,
    oracle_facts_root: felt252,
    onchain_oracle_facts_root: felt252,
    policy_root: felt252,
    onchain_policy_root: felt252,
) -> CanonicalMultiLineDecisionOutput {
    canonical_multi_line_decision_output(
        main(
            input,
            fee_policy,
            policy_rows,
            nullifier,
            ruleset_root,
            onchain_ruleset_root,
            claim_source_root,
            onchain_claim_source_root,
            oracle_facts_root,
            onchain_oracle_facts_root,
            policy_root,
            onchain_policy_root,
        ),
    )
}

#[executable]
pub fn batch_main_v2_canonical_transport(input: BatchClaimInputV2) -> CanonicalBatchOutputV2 {
    canonical_batch_output_v2(batch_main_v2(input))
}

#[cfg(test)]
mod tests {
    use super::{MAX_CENTS_EXCLUSIVE, cents_in_range};

    #[test]
    fn canonical_money_boundary_is_exact() {
        assert(cents_in_range(MAX_CENTS_EXCLUSIVE - 1), 'money max rejected');
        assert(!cents_in_range(MAX_CENTS_EXCLUSIVE), 'money over accepted');
    }

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
