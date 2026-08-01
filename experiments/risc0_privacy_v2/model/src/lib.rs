use blind_ledger_rules_engine::{
    adjudicate_for_proof, Flags, MoneyCents, Patient, ProofFeeRow, Provider, ServiceLine,
    SharedContext,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use starknet_crypto::{poseidon_hash_many, Felt};
use std::collections::{BTreeMap, BTreeSet};

pub type FeltBytes = [u8; 32];

pub const COMPLETE_CLAIM_WITNESS_VERSION: u32 = 3;
pub const PRIVACY_V2_PROTOCOL_VERSION: u64 = 2;
pub const PUBLIC_FIELD_COUNT: usize = 12;
pub const EXPECTED_SETTLEMENT_DOMAIN: u64 = 7001;
pub const RULESET_VERSION: &str = "rarc_mapping_v1_pending_domain_ratification";
pub const PINNED_RULESET_ROOT_DECIMAL: &str =
    "811249635049685414496776950484113105212027390810456466662218761987715243335";

const WIRE_MAGIC: &[u8; 8] = b"BLPV2C03";
const MAX_WIRE_BYTES: usize = 64 * 1024;
const CLAIM_TREE_DEPTH: usize = 10;
const ORACLE_TREE_DEPTH: usize = 10;
const POLICY_TREE_DEPTH: usize = 10;
const NULLIFIER_TREE_DEPTH: usize = 32;
const MAX_CENTS_EXCLUSIVE: u64 = 1 << 32;
const POLICY_SCHEMA_TAG: u64 = 2;
const POLICY_ROW_KIND_LOWER_SENTINEL: u32 = 0;
const POLICY_ROW_KIND_REAL: u32 = 1;
const POLICY_ROW_KIND_UPPER_SENTINEL: u32 = 2;
const POLICY_MAX_TREE_DEPTH: usize = 31;
const FIELD_MAX_DECIMAL: &str =
    "3618502788666131213697322783095070105623107215331596699973092056135872020480";

const CLAIM_SOURCE_SCHEMA: u64 = 2;
const ATTEMPT_RECORD_SCHEMA: u64 = 1;
const ATTEMPT_NULLIFIER_DOMAIN: &str = "BL/ATTEMPT-NULLIFIER/LEGACY/v1";
const ATTEMPT_NULLIFIER_PUBLIC_SALT: &str = "BL/ATTEMPT-NULLIFIER/PUBLIC-SALT/v1";
const REVISION_KIND_ORIGINAL: u32 = 1;
const REVISION_KIND_CORRECTION: u32 = 2;
const REVISION_KIND_REPLACEMENT: u32 = 3;
const REVISION_KIND_VOID: u32 = 4;
const KAT_SOURCE_AUTHORITY_ID: &str = "BL-SYNTH-GOV-INTAKE-V1";
const KAT_GOVERNED_PEPPER: &str = "BL_LOCAL_DEV_PEPPER_NOT_FOR_PRODUCTION";
const ORACLE_SIGNER_ROOT_HEX: &str =
    "fb41ca8ea7b64df6425fffd41826125bb726c1f472f9efe8a333d6640c1676fb";
const ORACLE_EVIDENCE_TEXT: &str = "synthetic-evidence";
const BATCH_ID_TEXT: &str = "BL-MONOLITHIC-BATCH-1";

const DOMAIN_CLAIM_SOURCE: u8 = 1;
const DOMAIN_ORACLE: u8 = 2;
const DOMAIN_NORMALIZED_FACTS: u8 = 3;
const DOMAIN_FEE: u8 = 4;
const DOMAIN_NULLIFIER: u8 = 6;
const DOMAIN_PAYMENT: u8 = 7;
const DOMAIN_BATCH: u8 = 12;
const DOMAIN_CLAIM: u8 = 13;
const DOMAIN_PRIVATE_BATCH_V2: u8 = 16;
const DOMAIN_VALUE_CONSERVATION_V2: u8 = 17;
const DOMAIN_SETTLEMENT_V2: u8 = 18;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivatePatient {
    pub name: String,
    pub id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateProvider {
    pub npi: String,
    pub name: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateServiceLine {
    pub line_id: String,
    pub procedure_code: String,
    pub charge_cents: u64,
    pub units_cents: u64,
    pub prior_authorization: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateFlags {
    pub eligibility_active: bool,
    pub provider_enrolled: bool,
    pub provider_not_suspended: bool,
    pub not_deceased: bool,
    pub duplicate_claim: bool,
    pub program_integrity_hold: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateClaim {
    pub claim_id: String,
    pub transaction_set: String,
    pub payer_id: String,
    pub member_id: String,
    pub patient: PrivatePatient,
    pub provider: PrivateProvider,
    pub service_date: String,
    pub diagnoses: Vec<String>,
    pub service_lines: Vec<PrivateServiceLine>,
    pub total_charge_cents: u64,
    pub flags: PrivateFlags,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactVerificationEntry {
    pub key: String,
    pub value: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MerklePath {
    pub leaf_index: u32,
    pub siblings: Vec<FeltBytes>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRowWitness {
    pub row_kind: u32,
    pub procedure_code: String,
    pub procedure_key: FeltBytes,
    pub allowed_cents: u64,
    pub requires_prior_authorization: bool,
    pub next_procedure_key: FeltBytes,
    pub next_policy_leaf_index: u32,
    pub path: MerklePath,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationWitness {
    pub line_index: u32,
    pub valid_from_day: u32,
    pub valid_until_day: u32,
    pub path: MerklePath,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NullifierTransitionWitness {
    pub root_before: FeltBytes,
    pub root_after: FeltBytes,
    pub predecessor_value: FeltBytes,
    pub successor_value: FeltBytes,
    pub predecessor_index: u32,
    pub successor_index: u32,
    pub inserted_index: u32,
    pub predecessor_path: MerklePath,
    pub inserted_path: MerklePath,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompleteClaimWitnessV1 {
    pub schema_version: u32,
    pub settlement_domain: FeltBytes,
    pub batch_nonce: FeltBytes,
    pub privacy_salt: FeltBytes,
    pub value_salt: FeltBytes,
    pub expected_total_allowed_cents: u64,
    pub expected_total_payment_cents: u64,
    pub rule_version: String,
    pub ruleset_root: FeltBytes,
    pub claim: PrivateClaim,
    pub fact_verification: Vec<FactVerificationEntry>,
    pub source_authority_id: String,
    pub attempt_version: u32,
    pub revision_kind: u32,
    pub parent_attempt_version: u32,
    pub governed_pepper: String,
    pub claim_source_root: FeltBytes,
    pub claim_source_path: MerklePath,
    pub oracle_facts_root: FeltBytes,
    pub claim_facts_path: MerklePath,
    pub authorizations: Vec<AuthorizationWitness>,
    pub policy_root: FeltBytes,
    pub policy_tree_depth: u32,
    pub policy_real_row_count: u32,
    pub fee_policy_path: MerklePath,
    pub policy_rows: Vec<PolicyRowWitness>,
    pub nullifier: NullifierTransitionWitness,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompleteClaimExecution {
    pub public_fields: [FeltBytes; PUBLIC_FIELD_COUNT],
    pub decision: u32,
    pub failure_code: u32,
    pub allowed_cents: u64,
    pub payment_cents: u64,
    pub claim_commitment: FeltBytes,
    pub batch_commitment: FeltBytes,
    pub private_data_commitment: FeltBytes,
}

fn fail<T>(message: impl Into<String>) -> Result<T, String> {
    Err(message.into())
}

fn felt_bytes(value: u64) -> FeltBytes {
    Felt::from(value).to_bytes_be()
}

fn decimal_felt(value: &str) -> Felt {
    Felt::from_dec_str(value).expect("pinned decimal field value")
}

fn canonical_felt(name: &str, bytes: &FeltBytes) -> Result<Felt, String> {
    let felt = Felt::from_bytes_be(bytes);
    if felt.to_bytes_be() != *bytes {
        return fail(format!("{name}_not_canonical_field"));
    }
    Ok(felt)
}

fn nonzero_felt(name: &str, bytes: &FeltBytes) -> Result<Felt, String> {
    let felt = canonical_felt(name, bytes)?;
    if felt == Felt::ZERO {
        return fail(format!("{name}_must_be_nonzero"));
    }
    Ok(felt)
}

fn domain_tag(offset: u8) -> Felt {
    let mut bytes = [0u8; 32];
    bytes[6] = 1;
    bytes[31] = offset;
    Felt::from_bytes_be(&bytes)
}

fn domain_hash(offset: u8, fields: &[Felt]) -> Felt {
    let mut row = Vec::with_capacity(fields.len() + 2);
    row.push(domain_tag(offset));
    row.push(Felt::from(fields.len() as u64));
    row.extend_from_slice(fields);
    poseidon_hash_many(&row)
}

fn pack_felt_text(value: &str) -> Result<Felt, String> {
    let raw = value.as_bytes();
    if raw.is_empty() || raw.len() > 31 {
        return fail("packed_text_length_out_of_range");
    }
    let mut bytes = [0u8; 32];
    let start = 31 - raw.len();
    bytes[start] = raw.len() as u8;
    bytes[start + 1..].copy_from_slice(raw);
    let felt = Felt::from_bytes_be(&bytes);
    if felt.to_bytes_be() != bytes {
        return fail("packed_text_out_of_field");
    }
    Ok(felt)
}

fn governed_procedure_key(value: &str) -> Result<Felt, String> {
    if !(2..=10).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    {
        return fail("service_line_procedure_code_not_canonical");
    }
    pack_felt_text(value)
}

fn policy_upper_sentinel_key() -> Felt {
    Felt::from(u128::MAX)
}

fn optional_packed_text(value: Option<&str>) -> Result<Felt, String> {
    match value {
        None | Some("") => Ok(Felt::ZERO),
        Some(text) => pack_felt_text(text),
    }
}

fn text_commitment(domain: u8, value: &str) -> Felt {
    let raw = value.as_bytes();
    let words: Vec<Felt> = if raw.is_empty() {
        vec![Felt::ZERO]
    } else {
        raw.chunks(16).map(Felt::from_bytes_be_slice).collect()
    };
    let mut acc = domain_hash(
        domain,
        &[Felt::from(raw.len() as u64), Felt::from(words.len() as u64)],
    );
    for (index, word) in words.iter().enumerate() {
        acc = domain_hash(
            domain,
            &[
                Felt::from(raw.len() as u64),
                Felt::from(words.len() as u64),
                Felt::from(index as u64),
                acc,
                *word,
            ],
        );
    }
    acc
}

fn parse_day(value: &str) -> Result<u32, String> {
    let bytes = value.as_bytes();
    let (year_text, month_text, day_text) =
        if bytes.len() == 8 && bytes.iter().all(u8::is_ascii_digit) {
            (&value[0..4], &value[4..6], &value[6..8])
        } else if bytes.len() == 10
            && bytes[4] == b'-'
            && bytes[7] == b'-'
            && bytes[0..4].iter().all(u8::is_ascii_digit)
            && bytes[5..7].iter().all(u8::is_ascii_digit)
            && bytes[8..10].iter().all(u8::is_ascii_digit)
        {
            (&value[0..4], &value[5..7], &value[8..10])
        } else {
            return fail("date_format_invalid");
        };
    let year: i64 = year_text.parse().map_err(|_| "date_year_invalid")?;
    let month: i64 = month_text.parse().map_err(|_| "date_month_invalid")?;
    let day: i64 = day_text.parse().map_err(|_| "date_day_invalid")?;
    if !(1..=12).contains(&month) {
        return fail("date_month_invalid");
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if day < 1 || day > month_days[(month - 1) as usize] {
        return fail("date_day_invalid");
    }
    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let shifted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146097 + day_of_era - 719468;
    u32::try_from(days).map_err(|_| "date_day_out_of_range".to_string())
}

fn npi_check_digit_ok(value: &str) -> bool {
    if value.len() != 10 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    let payload = format!("80840{}", &value[..9]);
    let total = payload
        .bytes()
        .rev()
        .enumerate()
        .map(|(index, byte)| {
            let digit = u32::from(byte - b'0');
            if index % 2 == 0 {
                let doubled = digit * 2;
                doubled / 10 + doubled % 10
            } else {
                digit
            }
        })
        .sum::<u32>();
    let expected = (10 - total % 10) % 10;
    expected == u32::from(value.as_bytes()[9] - b'0')
}

fn parse_npi(value: &str) -> Result<u64, String> {
    if value.len() != 10 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return fail("npi_must_be_10_decimal_digits");
    }
    let parsed = value
        .parse::<u64>()
        .map_err(|_| "npi_out_of_range".to_string())?;
    if parsed == 0 {
        return fail("npi_must_be_nonzero");
    }
    if !npi_check_digit_ok(value) {
        return fail("invalid_npi_check_digit");
    }
    Ok(parsed)
}

fn canonical_lines(claim: &PrivateClaim) -> Result<Vec<&PrivateServiceLine>, String> {
    if claim.service_lines.is_empty() || claim.service_lines.len() > 50 {
        return fail("service_line_count_out_of_range");
    }
    let mut lines: Vec<&PrivateServiceLine> = claim.service_lines.iter().collect();
    lines.sort_by(|left, right| {
        left.procedure_code
            .len()
            .cmp(&right.procedure_code.len())
            .then_with(|| {
                left.procedure_code
                    .as_bytes()
                    .cmp(right.procedure_code.as_bytes())
            })
            .then_with(|| left.charge_cents.cmp(&right.charge_cents))
            .then_with(|| left.units_cents.cmp(&right.units_cents))
            .then_with(|| {
                let left_auth = left.prior_authorization.as_deref().unwrap_or("");
                let right_auth = right.prior_authorization.as_deref().unwrap_or("");
                left_auth
                    .len()
                    .cmp(&right_auth.len())
                    .then_with(|| left_auth.as_bytes().cmp(right_auth.as_bytes()))
            })
    });
    if lines.iter().copied().ne(claim.service_lines.iter()) {
        return fail("service_lines_not_canonical");
    }
    for (index, line) in lines.iter().enumerate() {
        if line.line_id.is_empty() {
            return fail("service_line_identity_missing");
        }
        if lines[..index]
            .iter()
            .any(|prior| prior.line_id == line.line_id)
        {
            return fail("service_line_identity_duplicate");
        }
        governed_procedure_key(&line.procedure_code)?;
        if line.charge_cents >= MAX_CENTS_EXCLUSIVE || line.units_cents >= MAX_CENTS_EXCLUSIVE {
            return fail("service_line_money_out_of_range");
        }
    }
    Ok(lines)
}

fn diagnosis_commitment(claim: &PrivateClaim) -> Result<Felt, String> {
    if claim.diagnoses.is_empty() {
        return fail("diagnosis_missing");
    }
    let mut ordered = claim.diagnoses.clone();
    ordered.sort_by(|left, right| {
        left.len()
            .cmp(&right.len())
            .then_with(|| left.as_bytes().cmp(right.as_bytes()))
    });
    if ordered != claim.diagnoses || ordered.windows(2).any(|pair| pair[0] == pair[1]) {
        return fail("diagnoses_not_canonical");
    }
    let mut acc = domain_hash(DOMAIN_CLAIM_SOURCE, &[Felt::from(ordered.len() as u64)]);
    for (index, diagnosis) in ordered.iter().enumerate() {
        acc = domain_hash(
            DOMAIN_CLAIM_SOURCE,
            &[
                Felt::from(ordered.len() as u64),
                Felt::from(index as u64),
                acc,
                pack_felt_text(diagnosis)?,
            ],
        );
    }
    Ok(acc)
}

fn service_lines_commitment(claim: &PrivateClaim) -> Result<Felt, String> {
    let lines = canonical_lines(claim)?;
    let mut acc = domain_hash(DOMAIN_CLAIM_SOURCE, &[Felt::from(lines.len() as u64)]);
    for (index, line) in lines.iter().enumerate() {
        acc = domain_hash(
            DOMAIN_CLAIM_SOURCE,
            &[
                Felt::from(lines.len() as u64),
                Felt::from(index as u64),
                acc,
                pack_felt_text(&line.procedure_code)?,
                Felt::from(line.charge_cents),
                Felt::from(line.units_cents),
                optional_packed_text(line.prior_authorization.as_deref())?,
            ],
        );
    }
    Ok(acc)
}

fn normalized_fact_commitment(flags: &PrivateFlags) -> Felt {
    domain_hash(
        DOMAIN_NORMALIZED_FACTS,
        &[
            Felt::from(u64::from(flags.eligibility_active)),
            Felt::from(u64::from(flags.provider_enrolled)),
            Felt::from(u64::from(flags.provider_not_suspended)),
            Felt::from(u64::from(flags.not_deceased)),
            Felt::from(u64::from(flags.duplicate_claim)),
            Felt::from(u64::from(flags.program_integrity_hold)),
        ],
    )
}

fn fact_verification_commitment(entries: &[FactVerificationEntry]) -> Result<Felt, String> {
    if entries.windows(2).any(|pair| pair[0].key >= pair[1].key) {
        return fail("fact_verification_not_canonical");
    }
    let mut acc = domain_hash(DOMAIN_ORACLE, &[Felt::from(entries.len() as u64)]);
    for (index, entry) in entries.iter().enumerate() {
        if entry.key.is_empty() {
            return fail("fact_verification_key_empty");
        }
        acc = domain_hash(
            DOMAIN_ORACLE,
            &[
                Felt::from(entries.len() as u64),
                Felt::from(index as u64),
                acc,
                text_commitment(DOMAIN_ORACLE, &entry.key),
                text_commitment(DOMAIN_ORACLE, &entry.value),
            ],
        );
    }
    Ok(acc)
}

fn tar_authorization_verified(entries: &[FactVerificationEntry]) -> bool {
    entries
        .iter()
        .any(|entry| entry.key == "tar_authorization" && entry.value == "VERIFIED")
}

fn evidence_commitment(value: &str) -> Felt {
    let clean = value.strip_prefix("0x").unwrap_or(value);
    if clean.len() == 64 && clean.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        let high = u128::from_str_radix(&clean[..32], 16).expect("validated high hex limb");
        let low = u128::from_str_radix(&clean[32..], 16).expect("validated low hex limb");
        domain_hash(DOMAIN_ORACLE, &[Felt::from(high), Felt::from(low)])
    } else {
        text_commitment(DOMAIN_ORACLE, value)
    }
}

fn field_from_canonical_record(record_type: &str, fields: &[CanonicalField<'_>]) -> Felt {
    fn push_tagged(out: &mut Vec<u8>, tagged: &[u8]) {
        out.extend_from_slice(&(tagged.len() as u32).to_be_bytes());
        out.extend_from_slice(tagged);
    }
    let mut record = Vec::new();
    let mut tagged = Vec::from(&b"sBL_CANONICAL_RECORD_V2"[..]);
    push_tagged(&mut record, &tagged);
    tagged.clear();
    tagged.push(b's');
    tagged.extend_from_slice(record_type.as_bytes());
    push_tagged(&mut record, &tagged);
    for field in fields {
        tagged.clear();
        match field {
            CanonicalField::Text(value) => {
                tagged.push(b's');
                tagged.extend_from_slice(value.as_bytes());
            }
            CanonicalField::Unsigned(value) => {
                tagged.push(b'i');
                tagged.extend_from_slice(value.to_string().as_bytes());
            }
        }
        push_tagged(&mut record, &tagged);
    }
    let digest: [u8; 32] = Sha256::digest(record).into();
    Felt::from_bytes_be(&digest)
}

enum CanonicalField<'a> {
    Text(&'a str),
    Unsigned(u64),
}

fn validate_attempt_metadata(
    witness: &CompleteClaimWitnessV1,
    original_only: bool,
) -> Result<(), String> {
    pack_felt_text(&witness.source_authority_id)?;
    pack_felt_text(&witness.claim.claim_id)?;
    if witness.attempt_version == 0 {
        return fail("attempt_version_invalid");
    }
    if ![
        REVISION_KIND_ORIGINAL,
        REVISION_KIND_CORRECTION,
        REVISION_KIND_REPLACEMENT,
        REVISION_KIND_VOID,
    ]
    .contains(&witness.revision_kind)
    {
        return fail("attempt_revision_kind_invalid");
    }
    if witness.revision_kind == REVISION_KIND_ORIGINAL {
        if witness.attempt_version != 1 || witness.parent_attempt_version != 0 {
            return fail("attempt_original_lifecycle_invalid");
        }
    } else if witness.attempt_version <= 1
        || witness.parent_attempt_version != witness.attempt_version - 1
    {
        return fail("attempt_revision_lifecycle_invalid");
    }
    if original_only
        && (witness.revision_kind != REVISION_KIND_ORIGINAL
            || witness.attempt_version != 1
            || witness.parent_attempt_version != 0)
    {
        return fail("attempt_revision_pending_lifecycle_authority");
    }
    Ok(())
}

fn legacy_attempt_identity_commitment(witness: &CompleteClaimWitnessV1) -> Result<Felt, String> {
    validate_attempt_metadata(witness, false)?;
    Ok(domain_hash(
        DOMAIN_CLAIM_SOURCE,
        &[
            Felt::from(ATTEMPT_RECORD_SCHEMA),
            pack_felt_text(&witness.source_authority_id)?,
            pack_felt_text(&witness.claim.payer_id)?,
            Felt::from(parse_npi(&witness.claim.provider.npi)?),
            pack_felt_text(&witness.claim.claim_id)?,
            Felt::from(witness.attempt_version),
            Felt::from(witness.revision_kind),
            Felt::from(witness.parent_attempt_version),
        ],
    ))
}

fn legacy_attempt_claim_snapshot_commitment(claim: &PrivateClaim) -> Result<Felt, String> {
    Ok(domain_hash(
        DOMAIN_CLAIM_SOURCE,
        &[
            Felt::from(ATTEMPT_RECORD_SCHEMA),
            optional_packed_text(Some(&claim.member_id))?,
            Felt::from(parse_day(&claim.service_date)?),
            service_lines_commitment(claim)?,
            diagnosis_commitment(claim)?,
            Felt::from(claim.diagnoses.len() as u64),
            Felt::from(claim.total_charge_cents),
            Felt::from(claim.service_lines.len() as u64),
        ],
    ))
}

fn legacy_attempt_record_commitment(witness: &CompleteClaimWitnessV1) -> Result<Felt, String> {
    Ok(domain_hash(
        DOMAIN_CLAIM_SOURCE,
        &[
            Felt::from(ATTEMPT_RECORD_SCHEMA),
            legacy_attempt_identity_commitment(witness)?,
            legacy_attempt_claim_snapshot_commitment(&witness.claim)?,
        ],
    ))
}

fn legacy_attempt_nullifier(witness: &CompleteClaimWitnessV1) -> Result<Felt, String> {
    if witness.governed_pepper.is_empty() {
        return fail("attempt_governed_pepper_empty");
    }
    validate_attempt_metadata(witness, false)?;
    let domain_field = field_from_canonical_record(
        "attempt_nullifier_domain_field",
        &[
            CanonicalField::Text(ATTEMPT_NULLIFIER_DOMAIN),
            CanonicalField::Text(ATTEMPT_NULLIFIER_PUBLIC_SALT),
            CanonicalField::Text(&witness.governed_pepper),
        ],
    );
    let record_field = field_from_canonical_record(
        "attempt_nullifier_record_field",
        &[
            CanonicalField::Text(ATTEMPT_NULLIFIER_DOMAIN),
            CanonicalField::Text(ATTEMPT_NULLIFIER_PUBLIC_SALT),
            CanonicalField::Text(&witness.governed_pepper),
            CanonicalField::Text(&witness.source_authority_id),
            CanonicalField::Text(&witness.claim.claim_id),
            CanonicalField::Unsigned(u64::from(witness.attempt_version)),
            CanonicalField::Unsigned(u64::from(witness.revision_kind)),
            CanonicalField::Unsigned(u64::from(witness.parent_attempt_version)),
        ],
    );
    let value = domain_hash(DOMAIN_NULLIFIER, &[domain_field, record_field]);
    if value == Felt::ZERO || value == decimal_felt(FIELD_MAX_DECIMAL) {
        return fail("attempt_nullifier_reserved_value");
    }
    Ok(value)
}

fn claim_source_leaf(
    witness: &CompleteClaimWitnessV1,
    nullifier: Felt,
    attempt_record_commitment: Felt,
    ruleset_root: Felt,
) -> Result<Felt, String> {
    let claim = &witness.claim;
    Ok(domain_hash(
        DOMAIN_CLAIM_SOURCE,
        &[
            Felt::from(CLAIM_SOURCE_SCHEMA),
            pack_felt_text(&claim.claim_id)?,
            optional_packed_text(Some(&claim.member_id))?,
            Felt::from(parse_npi(&claim.provider.npi)?),
            Felt::from(parse_day(&claim.service_date)?),
            service_lines_commitment(claim)?,
            diagnosis_commitment(claim)?,
            Felt::from(claim.diagnoses.len() as u64),
            Felt::from(claim.total_charge_cents),
            nullifier,
            attempt_record_commitment,
            ruleset_root,
        ],
    ))
}

fn claim_facts_leaf(
    witness: &CompleteClaimWitnessV1,
    claim_source_leaf: Felt,
) -> Result<Felt, String> {
    let normalized = normalized_fact_commitment(&witness.claim.flags);
    let verification = fact_verification_commitment(&witness.fact_verification)?;
    let signer = evidence_commitment(ORACLE_SIGNER_ROOT_HEX);
    let evidence = evidence_commitment(ORACLE_EVIDENCE_TEXT);
    let flags = &witness.claim.flags;
    Ok(domain_hash(
        DOMAIN_ORACLE,
        &[
            Felt::ZERO,
            pack_felt_text(&witness.claim.claim_id)?,
            claim_source_leaf,
            signer,
            normalized,
            verification,
            evidence,
            Felt::from(u64::from(flags.eligibility_active)),
            Felt::from(u64::from(flags.provider_enrolled)),
            Felt::from(u64::from(flags.provider_not_suspended)),
            Felt::from(u64::from(flags.not_deceased)),
            Felt::from(u64::from(flags.duplicate_claim)),
            Felt::from(u64::from(flags.program_integrity_hold)),
        ],
    ))
}

fn fee_policy_leaf(ruleset_root: Felt, tree_depth: u32, real_row_count: u32) -> Felt {
    domain_hash(
        DOMAIN_FEE,
        &[
            Felt::from(POLICY_SCHEMA_TAG),
            Felt::ZERO,
            ruleset_root,
            Felt::from(tree_depth),
            Felt::from(real_row_count),
        ],
    )
}

fn fee_row_leaf(row: &PolicyRowWitness) -> Result<Felt, String> {
    let procedure_key = canonical_felt("policy_procedure_key", &row.procedure_key)?;
    let next_procedure_key = canonical_felt("policy_next_procedure_key", &row.next_procedure_key)?;
    Ok(domain_hash(
        DOMAIN_FEE,
        &[
            Felt::from(POLICY_SCHEMA_TAG),
            Felt::from(row.row_kind),
            procedure_key,
            Felt::from(row.allowed_cents),
            Felt::from(u64::from(row.requires_prior_authorization)),
            next_procedure_key,
            Felt::from(row.next_policy_leaf_index),
            Felt::from(row.path.leaf_index),
            Felt::from(parse_day("1970-01-01")?),
            Felt::from(parse_day("9999-12-31")?),
        ],
    ))
}

#[derive(Clone, Copy, Debug)]
struct VerifiedPolicyRow {
    procedure_key: Felt,
    next_procedure_key: Felt,
    leaf: Felt,
}

fn validate_policy_tree_shape(witness: &CompleteClaimWitnessV1) -> Result<usize, String> {
    let depth = usize::try_from(witness.policy_tree_depth)
        .map_err(|_| "policy_tree_depth_out_of_range".to_string())?;
    if depth == 0 || depth > POLICY_MAX_TREE_DEPTH {
        return fail("policy_tree_depth_out_of_range");
    }
    let capacity = 1usize
        .checked_shl(witness.policy_tree_depth)
        .ok_or_else(|| "policy_tree_depth_out_of_range".to_string())?;
    let required_leaves = usize::try_from(witness.policy_real_row_count)
        .map_err(|_| "policy_real_row_count_out_of_range".to_string())?
        .checked_add(3)
        .ok_or_else(|| "policy_real_row_count_out_of_range".to_string())?;
    if required_leaves > capacity {
        return fail("policy_tree_capacity_exceeded");
    }
    Ok(depth)
}

fn validate_policy_row(
    row: &PolicyRowWitness,
    real_row_count: u32,
) -> Result<VerifiedPolicyRow, String> {
    if row.allowed_cents >= MAX_CENTS_EXCLUSIVE {
        return fail("policy_allowed_out_of_range");
    }
    let procedure_key = canonical_felt("policy_procedure_key", &row.procedure_key)?;
    let next_procedure_key = canonical_felt("policy_next_procedure_key", &row.next_procedure_key)?;
    let upper_key = policy_upper_sentinel_key();
    let upper_index = real_row_count
        .checked_add(2)
        .ok_or_else(|| "policy_real_row_count_out_of_range".to_string())?;
    if row.path.leaf_index == 0 || row.path.leaf_index > upper_index {
        return fail("policy_row_index_out_of_range");
    }
    match row.row_kind {
        POLICY_ROW_KIND_LOWER_SENTINEL => {
            if !row.procedure_code.is_empty()
                || row.path.leaf_index != 1
                || procedure_key != Felt::ZERO
                || row.allowed_cents != 0
                || row.requires_prior_authorization
            {
                return fail("policy_lower_sentinel_invalid");
            }
        }
        POLICY_ROW_KIND_REAL => {
            if row.path.leaf_index < 2
                || row.path.leaf_index > real_row_count.saturating_add(1)
                || procedure_key == Felt::ZERO
                || procedure_key >= upper_key
                || governed_procedure_key(&row.procedure_code)? != procedure_key
            {
                return fail("policy_real_row_invalid");
            }
        }
        POLICY_ROW_KIND_UPPER_SENTINEL => {
            if !row.procedure_code.is_empty()
                || row.path.leaf_index != upper_index
                || procedure_key != upper_key
                || next_procedure_key != upper_key
                || row.next_policy_leaf_index != row.path.leaf_index
                || row.allowed_cents != 0
                || row.requires_prior_authorization
            {
                return fail("policy_upper_sentinel_invalid");
            }
        }
        _ => return fail("policy_row_kind_invalid"),
    }
    if row.row_kind != POLICY_ROW_KIND_UPPER_SENTINEL {
        if procedure_key >= next_procedure_key {
            return fail("policy_row_successor_order_invalid");
        }
        if row.next_policy_leaf_index != row.path.leaf_index.saturating_add(1)
            || row.next_policy_leaf_index > upper_index
        {
            return fail("policy_row_successor_index_invalid");
        }
    }
    Ok(VerifiedPolicyRow {
        procedure_key,
        next_procedure_key,
        leaf: fee_row_leaf(row)?,
    })
}

fn authorization_leaf(
    witness: &CompleteClaimWitnessV1,
    authorization: &AuthorizationWitness,
    line: &PrivateServiceLine,
) -> Result<Felt, String> {
    let service_day = parse_day(&witness.claim.service_date)?;
    if authorization.line_index as usize >= witness.claim.service_lines.len()
        || authorization.valid_from_day > service_day
        || authorization.valid_until_day < service_day
    {
        return fail("authorization_scope_invalid");
    }
    let prior = optional_packed_text(line.prior_authorization.as_deref())?;
    let present = tar_authorization_verified(&witness.fact_verification)
        && line
            .prior_authorization
            .as_ref()
            .map(|value| !value.is_empty())
            .unwrap_or(false);
    let signed_prior = if present { prior } else { Felt::ZERO };
    Ok(domain_hash(
        DOMAIN_ORACLE,
        &[
            Felt::ONE,
            pack_felt_text(&witness.claim.claim_id)?,
            Felt::from(authorization.line_index),
            pack_felt_text(&line.procedure_code)?,
            Felt::from(service_day),
            prior,
            signed_prior,
            Felt::from(u64::from(present)),
            evidence_commitment(ORACLE_SIGNER_ROOT_HEX),
            fact_verification_commitment(&witness.fact_verification)?,
            evidence_commitment(ORACLE_EVIDENCE_TEXT),
            Felt::from(authorization.valid_from_day),
            Felt::from(authorization.valid_until_day),
        ],
    ))
}

fn verify_inclusion(
    label: &str,
    domain: u8,
    leaf: Felt,
    path: &MerklePath,
    root: Felt,
    depth: usize,
) -> Result<(), String> {
    if path.siblings.len() != depth || path.leaf_index as usize >= (1usize << depth) {
        return fail(format!("{label}_path_shape_invalid"));
    }
    let mut current = leaf;
    let mut cursor = path.leaf_index as usize;
    for sibling_bytes in &path.siblings {
        let sibling = canonical_felt(&format!("{label}_sibling"), sibling_bytes)?;
        current = if cursor & 1 == 0 {
            domain_hash(domain, &[current, sibling])
        } else {
            domain_hash(domain, &[sibling, current])
        };
        cursor >>= 1;
    }
    if cursor != 0 || current != root {
        return fail(format!("{label}_membership_mismatch"));
    }
    Ok(())
}

fn indexed_leaf_hash(value: Felt, next_value: Felt, next_index: u32, index: u32) -> Felt {
    domain_hash(
        DOMAIN_NULLIFIER,
        &[value, next_value, Felt::from(next_index), Felt::from(index)],
    )
}

fn nullifier_path_step(current: Felt, sibling: Felt, bit: usize) -> Felt {
    if bit == 0 {
        domain_hash(DOMAIN_NULLIFIER, &[current, sibling])
    } else {
        domain_hash(DOMAIN_NULLIFIER, &[sibling, current])
    }
}

fn verify_nullifier_transition(
    derived_nullifier: Felt,
    witness: &NullifierTransitionWitness,
) -> Result<(Felt, Felt), String> {
    let root_before = nonzero_felt("nullifier_root_before", &witness.root_before)?;
    let root_after = nonzero_felt("nullifier_root_after", &witness.root_after)?;
    let predecessor_value = canonical_felt("predecessor_value", &witness.predecessor_value)?;
    let successor_value = canonical_felt("successor_value", &witness.successor_value)?;
    if !(predecessor_value < derived_nullifier && derived_nullifier < successor_value) {
        return fail("nullifier_not_between_predecessor_and_successor");
    }
    if witness.successor_index == witness.predecessor_index
        || witness.inserted_index == witness.predecessor_index
        || witness.inserted_index == 0
    {
        return fail("nullifier_indices_invalid");
    }
    if witness.predecessor_path.leaf_index != witness.predecessor_index
        || witness.inserted_path.leaf_index != witness.inserted_index
        || witness.predecessor_path.siblings.len() != NULLIFIER_TREE_DEPTH
        || witness.inserted_path.siblings.len() != NULLIFIER_TREE_DEPTH
    {
        return fail("nullifier_path_shape_invalid");
    }

    let mut pred_old = indexed_leaf_hash(
        predecessor_value,
        successor_value,
        witness.successor_index,
        witness.predecessor_index,
    );
    let mut pred_new = indexed_leaf_hash(
        predecessor_value,
        derived_nullifier,
        witness.inserted_index,
        witness.predecessor_index,
    );
    let mut ins_old = Felt::ZERO;
    let mut ins_new = indexed_leaf_hash(
        derived_nullifier,
        successor_value,
        witness.successor_index,
        witness.inserted_index,
    );
    let mut pred_cursor = witness.predecessor_index as usize;
    let mut ins_cursor = witness.inserted_index as usize;
    let mut level = 0usize;
    let mut joined = false;

    while level < NULLIFIER_TREE_DEPTH {
        let pred_bit = pred_cursor & 1;
        let ins_bit = ins_cursor & 1;
        let pred_sibling = canonical_felt(
            "nullifier_predecessor_sibling",
            &witness.predecessor_path.siblings[level],
        )?;
        let ins_sibling = canonical_felt(
            "nullifier_inserted_sibling",
            &witness.inserted_path.siblings[level],
        )?;
        if pred_cursor / 2 == ins_cursor / 2 {
            if pred_cursor == ins_cursor
                || pred_bit == ins_bit
                || pred_sibling != ins_old
                || ins_sibling != pred_new
            {
                return fail("nullifier_multiproof_join_mismatch");
            }
            if pred_bit == 0 {
                pred_old = domain_hash(DOMAIN_NULLIFIER, &[pred_old, ins_old]);
                pred_new = domain_hash(DOMAIN_NULLIFIER, &[pred_new, ins_new]);
            } else {
                pred_old = domain_hash(DOMAIN_NULLIFIER, &[ins_old, pred_old]);
                pred_new = domain_hash(DOMAIN_NULLIFIER, &[ins_new, pred_new]);
            }
            pred_cursor >>= 1;
            ins_cursor >>= 1;
            level += 1;
            joined = true;
            break;
        }
        pred_old = nullifier_path_step(pred_old, pred_sibling, pred_bit);
        pred_new = nullifier_path_step(pred_new, pred_sibling, pred_bit);
        ins_old = nullifier_path_step(ins_old, ins_sibling, ins_bit);
        ins_new = nullifier_path_step(ins_new, ins_sibling, ins_bit);
        pred_cursor >>= 1;
        ins_cursor >>= 1;
        level += 1;
    }
    if !joined || pred_cursor != ins_cursor {
        return fail("nullifier_multiproof_join_mismatch");
    }
    while level < NULLIFIER_TREE_DEPTH {
        if pred_cursor != ins_cursor || (pred_cursor & 1) != (ins_cursor & 1) {
            return fail("nullifier_shared_path_mismatch");
        }
        let pred_sibling = canonical_felt(
            "nullifier_predecessor_sibling",
            &witness.predecessor_path.siblings[level],
        )?;
        let ins_sibling = canonical_felt(
            "nullifier_inserted_sibling",
            &witness.inserted_path.siblings[level],
        )?;
        if pred_sibling != ins_sibling {
            return fail("nullifier_shared_sibling_mismatch");
        }
        let bit = pred_cursor & 1;
        pred_old = nullifier_path_step(pred_old, pred_sibling, bit);
        pred_new = nullifier_path_step(pred_new, pred_sibling, bit);
        pred_cursor >>= 1;
        ins_cursor >>= 1;
        level += 1;
    }
    if pred_cursor != 0 || ins_cursor != 0 || pred_old != root_before || pred_new != root_after {
        return fail("nullifier_transition_root_mismatch");
    }
    Ok((root_before, root_after))
}

fn private_claim_commitment(claim: &PrivateClaim, claim_source_leaf: Felt) -> Result<Felt, String> {
    let lines = canonical_lines(claim)?;
    let mut line_commitment = domain_hash(DOMAIN_CLAIM, &[Felt::from(lines.len() as u64)]);
    for (index, line) in lines.iter().enumerate() {
        line_commitment = domain_hash(
            DOMAIN_CLAIM,
            &[
                Felt::from(lines.len() as u64),
                Felt::from(index as u64),
                line_commitment,
                text_commitment(DOMAIN_CLAIM, &line.line_id),
                text_commitment(DOMAIN_CLAIM, &line.procedure_code),
                Felt::from(line.charge_cents),
                Felt::from(line.units_cents),
                text_commitment(
                    DOMAIN_CLAIM,
                    line.prior_authorization.as_deref().unwrap_or(""),
                ),
            ],
        );
    }
    Ok(domain_hash(
        DOMAIN_CLAIM,
        &[
            Felt::ONE,
            text_commitment(DOMAIN_CLAIM, &claim.claim_id),
            text_commitment(DOMAIN_CLAIM, &claim.transaction_set),
            text_commitment(DOMAIN_CLAIM, &claim.payer_id),
            text_commitment(DOMAIN_CLAIM, &claim.member_id),
            text_commitment(DOMAIN_CLAIM, &claim.patient.name),
            text_commitment(DOMAIN_CLAIM, &claim.patient.id),
            text_commitment(DOMAIN_CLAIM, &claim.provider.npi),
            text_commitment(DOMAIN_CLAIM, &claim.provider.name),
            text_commitment(DOMAIN_CLAIM, &claim.service_date),
            diagnosis_commitment(claim)?,
            line_commitment,
            Felt::from(claim.total_charge_cents),
            claim_source_leaf,
        ],
    ))
}

fn as_rules_context(
    claim: &PrivateClaim,
    tar_authorization_verified: bool,
) -> Result<SharedContext, String> {
    let to_i64 = |value: u64| i64::try_from(value).map_err(|_| "money_out_of_range".to_string());
    Ok(SharedContext {
        claim_id: claim.claim_id.clone(),
        transaction_set: claim.transaction_set.clone(),
        payer_id: claim.payer_id.clone(),
        member_id: claim.member_id.clone(),
        patient: Patient {
            name: claim.patient.name.clone(),
            id: claim.patient.id.clone(),
        },
        provider: Provider {
            npi: claim.provider.npi.clone(),
            name: claim.provider.name.clone(),
        },
        service_date: claim.service_date.clone(),
        diagnoses: claim.diagnoses.clone(),
        service_lines: claim
            .service_lines
            .iter()
            .map(|line| {
                Ok(ServiceLine {
                    line_id: line.line_id.clone(),
                    procedure_code: line.procedure_code.clone(),
                    charge_amount: MoneyCents::from_cents(to_i64(line.charge_cents)?),
                    units: MoneyCents::from_cents(to_i64(line.units_cents)?),
                    prior_authorization: line.prior_authorization.clone(),
                })
            })
            .collect::<Result<Vec<_>, String>>()?,
        total_charge: MoneyCents::from_cents(to_i64(claim.total_charge_cents)?),
        flags: Flags {
            eligibility_active: claim.flags.eligibility_active,
            provider_enrolled: claim.flags.provider_enrolled,
            provider_not_suspended: claim.flags.provider_not_suspended,
            not_deceased: claim.flags.not_deceased,
            duplicate_claim: claim.flags.duplicate_claim,
            program_integrity_hold: claim.flags.program_integrity_hold,
        },
        tar_authorization_verified,
    })
}

pub fn execute_complete_claim(
    witness: &CompleteClaimWitnessV1,
) -> Result<CompleteClaimExecution, String> {
    if witness.schema_version != COMPLETE_CLAIM_WITNESS_VERSION {
        return fail("witness_schema_version_mismatch");
    }
    if witness.rule_version != RULESET_VERSION {
        return fail("rule_version_mismatch");
    }
    let settlement_domain = nonzero_felt("settlement_domain", &witness.settlement_domain)?;
    if settlement_domain != Felt::from(EXPECTED_SETTLEMENT_DOMAIN) {
        return fail("settlement_domain_mismatch");
    }
    let batch_nonce = nonzero_felt("batch_nonce", &witness.batch_nonce)?;
    let privacy_salt = nonzero_felt("privacy_salt", &witness.privacy_salt)?;
    let value_salt = nonzero_felt("value_salt", &witness.value_salt)?;
    if privacy_salt == value_salt {
        return fail("privacy_salts_must_be_distinct");
    }
    let ruleset_root = nonzero_felt("ruleset_root", &witness.ruleset_root)?;
    if ruleset_root != decimal_felt(PINNED_RULESET_ROOT_DECIMAL) {
        return fail("ruleset_root_not_pinned");
    }
    if witness.claim.transaction_set != "837"
        || witness.claim.claim_id.is_empty()
        || witness.claim.payer_id.is_empty()
        || witness.claim.patient.id != witness.claim.member_id
        || witness.claim.total_charge_cents >= MAX_CENTS_EXCLUSIVE
    {
        return fail("canonical_claim_header_invalid");
    }
    canonical_lines(&witness.claim)?;
    diagnosis_commitment(&witness.claim)?;
    parse_day(&witness.claim.service_date)?;
    parse_npi(&witness.claim.provider.npi)?;
    let line_sum = witness
        .claim
        .service_lines
        .iter()
        .try_fold(0u64, |sum, line| sum.checked_add(line.charge_cents))
        .ok_or_else(|| "line_charge_overflow".to_string())?;
    if line_sum != witness.claim.total_charge_cents {
        return fail("claim_total_not_derived_from_lines");
    }

    validate_attempt_metadata(witness, true)?;
    let attempt_record_commitment = legacy_attempt_record_commitment(witness)?;
    let derived_nullifier = legacy_attempt_nullifier(witness)?;
    let claim_leaf = claim_source_leaf(
        witness,
        derived_nullifier,
        attempt_record_commitment,
        ruleset_root,
    )?;
    let claim_source_root = nonzero_felt("claim_source_root", &witness.claim_source_root)?;
    verify_inclusion(
        "claim_source",
        DOMAIN_CLAIM_SOURCE,
        claim_leaf,
        &witness.claim_source_path,
        claim_source_root,
        CLAIM_TREE_DEPTH,
    )?;

    let oracle_root = nonzero_felt("oracle_facts_root", &witness.oracle_facts_root)?;
    let facts_leaf = claim_facts_leaf(witness, claim_leaf)?;
    verify_inclusion(
        "claim_facts",
        DOMAIN_ORACLE,
        facts_leaf,
        &witness.claim_facts_path,
        oracle_root,
        ORACLE_TREE_DEPTH,
    )?;

    let policy_depth = validate_policy_tree_shape(witness)?;
    if witness.fee_policy_path.leaf_index != 0 {
        return fail("fee_policy_leaf_index_invalid");
    }
    let policy_root = nonzero_felt("policy_root", &witness.policy_root)?;
    verify_inclusion(
        "fee_policy",
        DOMAIN_FEE,
        fee_policy_leaf(
            ruleset_root,
            witness.policy_tree_depth,
            witness.policy_real_row_count,
        ),
        &witness.fee_policy_path,
        policy_root,
        policy_depth,
    )?;
    if witness.policy_rows.is_empty()
        || witness
            .policy_rows
            .windows(2)
            .any(|pair| pair[0].path.leaf_index >= pair[1].path.leaf_index)
    {
        return fail("policy_rows_not_canonical");
    }
    let mut verified_policy_rows = Vec::with_capacity(witness.policy_rows.len());
    for row in &witness.policy_rows {
        let verified = validate_policy_row(row, witness.policy_real_row_count)?;
        verify_inclusion(
            "fee_row",
            DOMAIN_FEE,
            verified.leaf,
            &row.path,
            policy_root,
            policy_depth,
        )?;
        verified_policy_rows.push(verified);
    }

    let tar_verified = tar_authorization_verified(&witness.fact_verification);
    let mut used_authorizations = vec![false; witness.authorizations.len()];
    let mut used_policy_rows = vec![false; witness.policy_rows.len()];
    let mut line_fee_leaves = Vec::with_capacity(witness.claim.service_lines.len());
    let mut line_auth_leaves = Vec::with_capacity(witness.claim.service_lines.len());
    let mut line_policy_present = Vec::with_capacity(witness.claim.service_lines.len());
    let mut line_allowed_cents = Vec::with_capacity(witness.claim.service_lines.len());
    let mut line_requires_tar = Vec::with_capacity(witness.claim.service_lines.len());
    let mut semantic_fee_rows = BTreeMap::<String, (u64, bool, bool)>::new();
    for (line_index, line) in witness.claim.service_lines.iter().enumerate() {
        let query_key = governed_procedure_key(&line.procedure_code)?;
        let candidates = verified_policy_rows
            .iter()
            .enumerate()
            .filter_map(|(row_index, verified)| {
                let row = &witness.policy_rows[row_index];
                let present =
                    row.row_kind == POLICY_ROW_KIND_REAL && verified.procedure_key == query_key;
                let absent =
                    verified.procedure_key < query_key && query_key < verified.next_procedure_key;
                (present || absent).then_some((row_index, present))
            })
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return fail(format!("policy_evidence_missing:{}", line.procedure_code));
        }
        if candidates.len() != 1 {
            return fail(format!("policy_evidence_ambiguous:{}", line.procedure_code));
        }
        let (row_index, policy_present) = candidates[0];
        let row = &witness.policy_rows[row_index];
        used_policy_rows[row_index] = true;
        let allowed_cents = if policy_present { row.allowed_cents } else { 0 };
        let requires_tar = policy_present && row.requires_prior_authorization;
        if let Some(existing) = semantic_fee_rows.insert(
            line.procedure_code.clone(),
            (allowed_cents, requires_tar, policy_present),
        ) {
            if existing != (allowed_cents, requires_tar, policy_present) {
                return fail("policy_semantic_row_conflict");
            }
        }
        line_policy_present.push(policy_present);
        line_allowed_cents.push(allowed_cents);
        line_requires_tar.push(requires_tar);
        line_fee_leaves.push(verified_policy_rows[row_index].leaf);
        if requires_tar {
            let (auth_index, auth) = witness
                .authorizations
                .iter()
                .enumerate()
                .find(|(_, auth)| auth.line_index as usize == line_index)
                .ok_or_else(|| "authorization_witness_missing".to_string())?;
            if used_authorizations[auth_index] {
                return fail("authorization_witness_reused");
            }
            used_authorizations[auth_index] = true;
            let leaf = authorization_leaf(witness, auth, line)?;
            verify_inclusion(
                "authorization",
                DOMAIN_ORACLE,
                leaf,
                &auth.path,
                oracle_root,
                ORACLE_TREE_DEPTH,
            )?;
            line_auth_leaves.push(leaf);
        } else {
            line_auth_leaves.push(Felt::ZERO);
        }
    }
    if used_authorizations.iter().any(|used| !used) {
        return fail("authorization_witness_unused");
    }
    if used_policy_rows.iter().any(|used| !used) {
        return fail("policy_witness_unused");
    }

    let proof_fee_rows = semantic_fee_rows
        .into_iter()
        .map(
            |(procedure_code, (allowed_cents, requires_prior_authorization, policy_present))| {
                Ok(ProofFeeRow {
                    procedure_code,
                    allowed_cents: i64::try_from(allowed_cents)
                        .map_err(|_| "policy_allowed_out_of_range".to_string())?,
                    requires_prior_authorization,
                    policy_present,
                })
            },
        )
        .collect::<Result<Vec<_>, String>>()?;
    let rules_context = as_rules_context(&witness.claim, tar_verified)?;
    let adjudication = adjudicate_for_proof(&rules_context, &proof_fee_rows)?;
    let decision = u32::from(adjudication.approved);
    let claim_allowed_cents = u64::try_from(adjudication.allowed_amount_cents)
        .map_err(|_| "allowed_amount_negative".to_string())?;
    let payment_cents = u64::try_from(adjudication.payment_amount_cents)
        .map_err(|_| "payment_amount_negative".to_string())?;
    let allowed_cents = if adjudication.approved {
        claim_allowed_cents
    } else {
        0
    };

    if !adjudication.approved && payment_cents != 0 {
        return fail("denied_claim_has_payment");
    }
    let (root_before, proven_root_after) =
        verify_nullifier_transition(derived_nullifier, &witness.nullifier)?;

    let normalized = normalized_fact_commitment(&witness.claim.flags);
    let mut payment_lines_commitment = domain_hash(
        DOMAIN_PAYMENT,
        &[Felt::from(witness.claim.service_lines.len() as u64)],
    );
    for (index, line) in witness.claim.service_lines.iter().enumerate() {
        let payment_line_leaf = domain_hash(
            DOMAIN_PAYMENT,
            &[
                pack_felt_text(&line.procedure_code)?,
                Felt::from(line.charge_cents),
                Felt::from(line.units_cents),
                optional_packed_text(line.prior_authorization.as_deref())?,
                Felt::from(line_allowed_cents[index]),
                line_fee_leaves[index],
                Felt::from(u64::from(line_requires_tar[index])),
                Felt::from(u64::from(line_policy_present[index])),
                line_auth_leaves[index],
            ],
        );
        payment_lines_commitment = domain_hash(
            DOMAIN_PAYMENT,
            &[
                Felt::from(witness.claim.service_lines.len() as u64),
                Felt::from(index as u64),
                payment_lines_commitment,
                payment_line_leaf,
            ],
        );
    }
    let claim_commitment = domain_hash(
        DOMAIN_PAYMENT,
        &[
            pack_felt_text(BATCH_ID_TEXT)?,
            claim_leaf,
            normalized,
            payment_lines_commitment,
            derived_nullifier,
            ruleset_root,
        ],
    );
    let output_leaf = domain_hash(
        DOMAIN_BATCH,
        &[
            pack_felt_text(&witness.claim.claim_id)?,
            Felt::from(decision),
            Felt::from(adjudication.failure_code),
            Felt::from(payment_cents),
            claim_commitment,
        ],
    );
    let batch_commitment = domain_hash(DOMAIN_BATCH, &[Felt::ZERO, output_leaf]);
    let private_data_commitment = private_claim_commitment(&witness.claim, claim_leaf)?;
    if private_data_commitment == Felt::ZERO {
        return fail("private_data_commitment_zero");
    }
    if witness.expected_total_allowed_cents != allowed_cents {
        return fail("expected_allowed_mismatch");
    }
    if witness.expected_total_payment_cents != payment_cents {
        return fail("expected_payment_mismatch");
    }
    if witness.expected_total_allowed_cents != witness.expected_total_payment_cents
        || allowed_cents != payment_cents
    {
        return fail("value_conservation_mismatch");
    }
    let opaque_batch_commitment = domain_hash(
        DOMAIN_PRIVATE_BATCH_V2,
        &[
            batch_nonce,
            batch_commitment,
            private_data_commitment,
            privacy_salt,
            settlement_domain,
        ],
    );
    let value_conservation_commitment = domain_hash(
        DOMAIN_VALUE_CONSERVATION_V2,
        &[
            Felt::from(allowed_cents),
            Felt::from(payment_cents),
            value_salt,
            batch_commitment,
            batch_nonce,
        ],
    );
    let settlement_commitment = domain_hash(
        DOMAIN_SETTLEMENT_V2,
        &[
            Felt::from(PRIVACY_V2_PROTOCOL_VERSION),
            settlement_domain,
            batch_nonce,
            opaque_batch_commitment,
            value_conservation_commitment,
        ],
    );
    let public_fields = [
        felt_bytes(PRIVACY_V2_PROTOCOL_VERSION),
        settlement_domain.to_bytes_be(),
        batch_nonce.to_bytes_be(),
        root_before.to_bytes_be(),
        proven_root_after.to_bytes_be(),
        claim_source_root.to_bytes_be(),
        oracle_root.to_bytes_be(),
        policy_root.to_bytes_be(),
        ruleset_root.to_bytes_be(),
        opaque_batch_commitment.to_bytes_be(),
        value_conservation_commitment.to_bytes_be(),
        settlement_commitment.to_bytes_be(),
    ];
    Ok(CompleteClaimExecution {
        public_fields,
        decision,
        failure_code: adjudication.failure_code,
        allowed_cents,
        payment_cents,
        claim_commitment: claim_commitment.to_bytes_be(),
        batch_commitment: batch_commitment.to_bytes_be(),
        private_data_commitment: private_data_commitment.to_bytes_be(),
    })
}

pub fn encode_witness(witness: &CompleteClaimWitnessV1) -> Result<Vec<u8>, String> {
    let payload =
        postcard::to_allocvec(witness).map_err(|error| format!("witness_encode:{error}"))?;
    let payload_len =
        u32::try_from(payload.len()).map_err(|_| "witness_wire_too_large".to_string())?;
    let mut wire = Vec::with_capacity(WIRE_MAGIC.len() + 4 + payload.len());
    wire.extend_from_slice(WIRE_MAGIC);
    wire.extend_from_slice(&payload_len.to_be_bytes());
    wire.extend_from_slice(&payload);
    if wire.len() > MAX_WIRE_BYTES {
        return fail("witness_wire_too_large");
    }
    Ok(wire)
}

pub fn decode_witness(wire: &[u8]) -> Result<CompleteClaimWitnessV1, String> {
    if wire.len() > MAX_WIRE_BYTES {
        return fail("witness_wire_too_large");
    }
    if wire.len() <= WIRE_MAGIC.len() + 4 || &wire[..WIRE_MAGIC.len()] != WIRE_MAGIC {
        return fail("witness_wire_magic_mismatch");
    }
    let declared = u32::from_be_bytes(
        wire[WIRE_MAGIC.len()..WIRE_MAGIC.len() + 4]
            .try_into()
            .expect("four-byte slice"),
    ) as usize;
    if declared != wire.len() - WIRE_MAGIC.len() - 4 {
        return fail("witness_wire_length_mismatch");
    }
    let (witness, trailing): (CompleteClaimWitnessV1, &[u8]) =
        postcard::take_from_bytes(&wire[WIRE_MAGIC.len() + 4..])
            .map_err(|error| format!("witness_decode:{error}"))?;
    if !trailing.is_empty() {
        return fail("witness_wire_trailing_bytes");
    }
    Ok(witness)
}

fn build_tree(leaves: &[Felt], depth: usize, domain: u8) -> (Felt, Vec<MerklePath>) {
    let capacity = 1usize << depth;
    assert!(!leaves.is_empty() && leaves.len() <= capacity);
    assert!(leaves.iter().all(|leaf| *leaf != Felt::ZERO));
    let mut zeros = vec![Felt::ZERO];
    for level in 0..depth {
        zeros.push(domain_hash(domain, &[zeros[level], zeros[level]]));
    }
    let mut sparse = leaves
        .iter()
        .copied()
        .enumerate()
        .collect::<BTreeMap<usize, Felt>>();
    let mut paths = (0..leaves.len())
        .map(|index| MerklePath {
            leaf_index: index as u32,
            siblings: Vec::with_capacity(depth),
        })
        .collect::<Vec<_>>();
    let mut cursors = (0..leaves.len()).collect::<Vec<_>>();
    for level in 0..depth {
        for (path, cursor) in paths.iter_mut().zip(cursors.iter_mut()) {
            path.siblings.push(
                sparse
                    .get(&(*cursor ^ 1))
                    .unwrap_or(&zeros[level])
                    .to_bytes_be(),
            );
            *cursor >>= 1;
        }
        let parents = sparse
            .keys()
            .map(|index| index / 2)
            .collect::<BTreeSet<_>>();
        sparse = parents
            .into_iter()
            .filter_map(|parent| {
                let left = *sparse.get(&(parent * 2)).unwrap_or(&zeros[level]);
                let right = *sparse.get(&(parent * 2 + 1)).unwrap_or(&zeros[level]);
                let value = domain_hash(domain, &[left, right]);
                (value != zeros[level + 1]).then_some((parent, value))
            })
            .collect();
    }
    (*sparse.get(&0).unwrap_or(&zeros[depth]), paths)
}

fn kat_private_claim() -> PrivateClaim {
    PrivateClaim {
        claim_id: "BL-RISC0-CLAIM-0001".into(),
        transaction_set: "837".into(),
        payer_id: "PAYER".into(),
        member_id: "M123456789".into(),
        patient: PrivatePatient {
            name: "Synthetic Jane".into(),
            id: "M123456789".into(),
        },
        provider: PrivateProvider {
            npi: "1999999984".into(),
            name: "Synthetic Provider".into(),
        },
        service_date: "20260601".into(),
        diagnoses: vec!["F840".into()],
        service_lines: vec![PrivateServiceLine {
            line_id: "1".into(),
            procedure_code: "T1019".into(),
            charge_cents: 29,
            units_cents: 100,
            prior_authorization: Some("PA-OK-123".into()),
        }],
        total_charge_cents: 29,
        flags: PrivateFlags {
            eligibility_active: true,
            provider_enrolled: true,
            provider_not_suspended: true,
            not_deceased: true,
            duplicate_claim: false,
            program_integrity_hold: false,
        },
    }
}

fn kat_policy_tree(ruleset_root: Felt) -> (Felt, MerklePath, Vec<PolicyRowWitness>) {
    let mut real_specs = vec![
        ("99213", false),
        ("H2015", true),
        ("S5102", true),
        ("T1019", true),
    ]
    .into_iter()
    .map(|(code, requires_tar)| {
        (
            code.to_string(),
            governed_procedure_key(code).expect("KAT governed procedure"),
            requires_tar,
        )
    })
    .collect::<Vec<_>>();
    real_specs.sort_by_key(|(_, key, _)| *key);
    let real_row_count = u32::try_from(real_specs.len()).expect("KAT policy row count");
    let mut raw_rows = vec![(
        POLICY_ROW_KIND_LOWER_SENTINEL,
        String::new(),
        Felt::ZERO,
        0,
        false,
    )];
    raw_rows.extend(
        real_specs.into_iter().map(|(code, key, requires_tar)| {
            (POLICY_ROW_KIND_REAL, code, key, 12_500, requires_tar)
        }),
    );
    raw_rows.push((
        POLICY_ROW_KIND_UPPER_SENTINEL,
        String::new(),
        policy_upper_sentinel_key(),
        0,
        false,
    ));

    let mut rows = Vec::with_capacity(raw_rows.len());
    for (offset, (row_kind, procedure_code, procedure_key, allowed_cents, requires_tar)) in
        raw_rows.iter().enumerate()
    {
        let leaf_index = u32::try_from(offset + 1).expect("KAT policy leaf index");
        let (next_procedure_key, next_policy_leaf_index) = if offset + 1 < raw_rows.len() {
            (
                raw_rows[offset + 1].2,
                leaf_index.checked_add(1).expect("KAT successor index"),
            )
        } else {
            (policy_upper_sentinel_key(), leaf_index)
        };
        rows.push(PolicyRowWitness {
            row_kind: *row_kind,
            procedure_code: procedure_code.clone(),
            procedure_key: procedure_key.to_bytes_be(),
            allowed_cents: *allowed_cents,
            requires_prior_authorization: *requires_tar,
            next_procedure_key: next_procedure_key.to_bytes_be(),
            next_policy_leaf_index,
            path: MerklePath {
                leaf_index,
                siblings: Vec::new(),
            },
        });
    }
    let mut leaves = vec![fee_policy_leaf(
        ruleset_root,
        POLICY_TREE_DEPTH as u32,
        real_row_count,
    )];
    leaves.extend(
        rows.iter()
            .map(|row| fee_row_leaf(row).expect("KAT policy row leaf")),
    );
    let (root, paths) = build_tree(&leaves, POLICY_TREE_DEPTH, DOMAIN_FEE);
    for (row, path) in rows.iter_mut().zip(paths.iter().skip(1)) {
        row.path = path.clone();
    }
    (root, paths[0].clone(), rows)
}

fn kat_nullifier_transition(nullifier: Felt) -> NullifierTransitionWitness {
    let predecessor_value = Felt::ZERO;
    let successor_value = decimal_felt(FIELD_MAX_DECIMAL);
    let before_leaves = [
        indexed_leaf_hash(predecessor_value, successor_value, 1, 0),
        indexed_leaf_hash(successor_value, successor_value, 1, 1),
    ];
    let (root_before, before_paths) =
        build_tree(&before_leaves, NULLIFIER_TREE_DEPTH, DOMAIN_NULLIFIER);
    let after_leaves = [
        indexed_leaf_hash(predecessor_value, nullifier, 2, 0),
        indexed_leaf_hash(successor_value, successor_value, 1, 1),
        indexed_leaf_hash(nullifier, successor_value, 1, 2),
    ];
    let (root_after, after_paths) =
        build_tree(&after_leaves, NULLIFIER_TREE_DEPTH, DOMAIN_NULLIFIER);
    NullifierTransitionWitness {
        root_before: root_before.to_bytes_be(),
        root_after: root_after.to_bytes_be(),
        predecessor_value: predecessor_value.to_bytes_be(),
        successor_value: successor_value.to_bytes_be(),
        predecessor_index: 0,
        successor_index: 1,
        inserted_index: 2,
        predecessor_path: before_paths[0].clone(),
        inserted_path: after_paths[2].clone(),
    }
}

pub fn kat_complete_claim_witness() -> CompleteClaimWitnessV1 {
    let claim = kat_private_claim();
    let fact_verification = vec![FactVerificationEntry {
        key: "tar_authorization".into(),
        value: "VERIFIED".into(),
    }];
    let ruleset_root = decimal_felt(PINNED_RULESET_ROOT_DECIMAL);
    let temporary = CompleteClaimWitnessV1 {
        schema_version: COMPLETE_CLAIM_WITNESS_VERSION,
        settlement_domain: felt_bytes(EXPECTED_SETTLEMENT_DOMAIN),
        batch_nonce: felt_bytes(9001),
        privacy_salt: felt_bytes(222),
        value_salt: felt_bytes(333),
        expected_total_allowed_cents: 29,
        expected_total_payment_cents: 29,
        rule_version: RULESET_VERSION.into(),
        ruleset_root: ruleset_root.to_bytes_be(),
        claim: claim.clone(),
        fact_verification: fact_verification.clone(),
        source_authority_id: KAT_SOURCE_AUTHORITY_ID.into(),
        attempt_version: 1,
        revision_kind: REVISION_KIND_ORIGINAL,
        parent_attempt_version: 0,
        governed_pepper: KAT_GOVERNED_PEPPER.into(),
        claim_source_root: felt_bytes(1),
        claim_source_path: MerklePath {
            leaf_index: 0,
            siblings: Vec::new(),
        },
        oracle_facts_root: felt_bytes(1),
        claim_facts_path: MerklePath {
            leaf_index: 0,
            siblings: Vec::new(),
        },
        authorizations: Vec::new(),
        policy_root: felt_bytes(1),
        policy_tree_depth: POLICY_TREE_DEPTH as u32,
        policy_real_row_count: 4,
        fee_policy_path: MerklePath {
            leaf_index: 0,
            siblings: Vec::new(),
        },
        policy_rows: Vec::new(),
        nullifier: NullifierTransitionWitness {
            root_before: felt_bytes(1),
            root_after: felt_bytes(1),
            predecessor_value: felt_bytes(0),
            successor_value: decimal_felt(FIELD_MAX_DECIMAL).to_bytes_be(),
            predecessor_index: 0,
            successor_index: 1,
            inserted_index: 2,
            predecessor_path: MerklePath {
                leaf_index: 0,
                siblings: Vec::new(),
            },
            inserted_path: MerklePath {
                leaf_index: 2,
                siblings: Vec::new(),
            },
        },
    };
    let attempt_record_commitment =
        legacy_attempt_record_commitment(&temporary).expect("KAT attempt record");
    let nullifier = legacy_attempt_nullifier(&temporary).expect("KAT attempt nullifier");
    let claim_leaf = claim_source_leaf(
        &temporary,
        nullifier,
        attempt_record_commitment,
        ruleset_root,
    )
    .expect("KAT claim leaf");
    let (claim_source_root, claim_paths) =
        build_tree(&[claim_leaf], CLAIM_TREE_DEPTH, DOMAIN_CLAIM_SOURCE);
    let facts_leaf = claim_facts_leaf(&temporary, claim_leaf).expect("KAT facts leaf");
    let auth = AuthorizationWitness {
        line_index: 0,
        valid_from_day: parse_day(&claim.service_date).unwrap(),
        valid_until_day: parse_day(&claim.service_date).unwrap(),
        path: MerklePath {
            leaf_index: 0,
            siblings: Vec::new(),
        },
    };
    let auth_leaf =
        authorization_leaf(&temporary, &auth, &claim.service_lines[0]).expect("KAT auth leaf");
    let mut oracle_leaves = [(facts_leaf, true), (auth_leaf, false)];
    oracle_leaves.sort_by_key(|(leaf, _)| *leaf);
    let (oracle_root, oracle_paths) = build_tree(
        &oracle_leaves
            .iter()
            .map(|(leaf, _)| *leaf)
            .collect::<Vec<_>>(),
        ORACLE_TREE_DEPTH,
        DOMAIN_ORACLE,
    );
    let facts_position = oracle_leaves.iter().position(|(_, facts)| *facts).unwrap();
    let auth_position = oracle_leaves.iter().position(|(_, facts)| !*facts).unwrap();

    let (policy_root, fee_policy_path, all_policy_rows) = kat_policy_tree(ruleset_root);
    let policy_row = all_policy_rows
        .iter()
        .find(|row| row.procedure_code == "T1019")
        .expect("KAT T1019 policy row")
        .clone();

    CompleteClaimWitnessV1 {
        schema_version: COMPLETE_CLAIM_WITNESS_VERSION,
        settlement_domain: felt_bytes(EXPECTED_SETTLEMENT_DOMAIN),
        batch_nonce: felt_bytes(9001),
        privacy_salt: felt_bytes(222),
        value_salt: felt_bytes(333),
        expected_total_allowed_cents: 29,
        expected_total_payment_cents: 29,
        rule_version: RULESET_VERSION.into(),
        ruleset_root: ruleset_root.to_bytes_be(),
        claim,
        fact_verification,
        source_authority_id: KAT_SOURCE_AUTHORITY_ID.into(),
        attempt_version: 1,
        revision_kind: REVISION_KIND_ORIGINAL,
        parent_attempt_version: 0,
        governed_pepper: KAT_GOVERNED_PEPPER.into(),
        claim_source_root: claim_source_root.to_bytes_be(),
        claim_source_path: claim_paths[0].clone(),
        oracle_facts_root: oracle_root.to_bytes_be(),
        claim_facts_path: oracle_paths[facts_position].clone(),
        authorizations: vec![AuthorizationWitness {
            path: oracle_paths[auth_position].clone(),
            ..auth
        }],
        policy_root: policy_root.to_bytes_be(),
        policy_tree_depth: POLICY_TREE_DEPTH as u32,
        policy_real_row_count: 4,
        fee_policy_path,
        policy_rows: vec![policy_row],
        nullifier: kat_nullifier_transition(nullifier),
    }
}

pub fn kat_expected_public_fields() -> [FeltBytes; PUBLIC_FIELD_COUNT] {
    [
        "2",
        "7001",
        "9001",
        "2556804241959708214775924503969299168294989458702588455565708918393934598799",
        "1421443270254595324481194992818839222756231569398423003283460624137579140919",
        "1696592756654962874190930328952169168566545546122012605749171024743955541215",
        "148911886983709353607376455509440083135115932565142773892400607112259112637",
        "2915219027288138473150606738911079378392766293574499679930621599575403076908",
        PINNED_RULESET_ROOT_DECIMAL,
        "531377237204389723637912887118218818021316662195318882723214596257514031960",
        "3412216423568285498900951567432867021794455205075167389875191543304487048366",
        "2750778986255053240227380612342299236645367883204303133614565806466562522673",
    ]
    .map(|value| decimal_felt(value).to_bytes_be())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_money_boundary_is_exact() {
        const { assert!(MAX_CENTS_EXCLUSIVE - 1 < MAX_CENTS_EXCLUSIVE) };
        let mut witness = kat_complete_claim_witness();
        witness.claim.total_charge_cents = MAX_CENTS_EXCLUSIVE;
        assert_eq!(
            execute_complete_claim(&witness).unwrap_err(),
            "canonical_claim_header_invalid"
        );
    }

    fn rebind_claim_and_oracle(witness: &mut CompleteClaimWitnessV1) {
        let ruleset_root = canonical_felt("ruleset_root", &witness.ruleset_root).unwrap();
        let attempt_record = legacy_attempt_record_commitment(witness).unwrap();
        let nullifier = legacy_attempt_nullifier(witness).unwrap();
        let claim_leaf =
            claim_source_leaf(witness, nullifier, attempt_record, ruleset_root).unwrap();
        let (claim_root, claim_paths) =
            build_tree(&[claim_leaf], CLAIM_TREE_DEPTH, DOMAIN_CLAIM_SOURCE);
        witness.claim_source_root = claim_root.to_bytes_be();
        witness.claim_source_path = claim_paths[0].clone();
        witness.nullifier = kat_nullifier_transition(nullifier);

        let facts_leaf = claim_facts_leaf(witness, claim_leaf).unwrap();
        let mut leaves = vec![(facts_leaf, None)];
        for (auth_index, auth) in witness.authorizations.iter().enumerate() {
            let line = &witness.claim.service_lines[auth.line_index as usize];
            leaves.push((
                authorization_leaf(witness, auth, line).unwrap(),
                Some(auth_index),
            ));
        }
        leaves.sort_by_key(|(leaf, _)| *leaf);
        let (oracle_root, oracle_paths) = build_tree(
            &leaves.iter().map(|(leaf, _)| *leaf).collect::<Vec<_>>(),
            ORACLE_TREE_DEPTH,
            DOMAIN_ORACLE,
        );
        witness.oracle_facts_root = oracle_root.to_bytes_be();
        let facts_index = leaves
            .iter()
            .position(|(_, owner)| owner.is_none())
            .unwrap();
        witness.claim_facts_path = oracle_paths[facts_index].clone();
        for (leaf_index, (_, owner)) in leaves.iter().enumerate() {
            if let Some(auth_index) = owner {
                witness.authorizations[*auth_index].path = oracle_paths[leaf_index].clone();
            }
        }
    }

    fn make_denied(mutate: impl FnOnce(&mut CompleteClaimWitnessV1)) -> CompleteClaimWitnessV1 {
        let mut witness = kat_complete_claim_witness();
        mutate(&mut witness);
        rebind_claim_and_oracle(&mut witness);
        witness.expected_total_allowed_cents = 0;
        witness.expected_total_payment_cents = 0;
        witness
    }

    fn assert_npi_rejected(value: &str, expected: &str) {
        assert_eq!(parse_npi(value).unwrap_err(), expected);
        let mut witness = kat_complete_claim_witness();
        witness.claim.provider.npi = value.into();
        assert_eq!(execute_complete_claim(&witness).unwrap_err(), expected);
    }

    fn assert_service_date_rejected(value: &str, expected: &str) {
        assert_eq!(parse_day(value).unwrap_err(), expected);
        let mut witness = kat_complete_claim_witness();
        witness.claim.service_date = value.into();
        assert_eq!(execute_complete_claim(&witness).unwrap_err(), expected);
    }

    fn policy_predecessor_for(procedure_code: &str) -> PolicyRowWitness {
        let query_key = governed_procedure_key(procedure_code).unwrap();
        let ruleset_root = decimal_felt(PINNED_RULESET_ROOT_DECIMAL);
        let (_, _, rows) = kat_policy_tree(ruleset_root);
        rows.into_iter()
            .find(|row| {
                let key = canonical_felt("policy_procedure_key", &row.procedure_key).unwrap();
                let next =
                    canonical_felt("policy_next_procedure_key", &row.next_procedure_key).unwrap();
                key < query_key && query_key < next
            })
            .expect("KAT query has an authenticated predecessor interval")
    }

    fn make_policy_absence(procedure_code: &str) -> CompleteClaimWitnessV1 {
        let mut witness = kat_complete_claim_witness();
        witness.claim.service_lines[0].procedure_code = procedure_code.into();
        witness.policy_rows = vec![policy_predecessor_for(procedure_code)];
        witness.authorizations.clear();
        rebind_claim_and_oracle(&mut witness);
        witness.expected_total_allowed_cents = 0;
        witness.expected_total_payment_cents = 0;
        witness
    }

    #[test]
    fn foundation_text_order_uses_length_then_ascii_bytes() {
        let mut claim = kat_complete_claim_witness().claim;
        let mut short = claim.service_lines[0].clone();
        short.line_id = "1".into();
        short.procedure_code = "Z9".into();
        short.prior_authorization = None;
        let mut long = short.clone();
        long.line_id = "2".into();
        long.procedure_code = "A10".into();
        claim.service_lines = vec![short, long];
        assert!(canonical_lines(&claim).is_ok());
        claim.service_lines.reverse();
        assert_eq!(
            canonical_lines(&claim).unwrap_err(),
            "service_lines_not_canonical"
        );
    }

    #[test]
    fn foundation_duplicate_line_ids_and_diagnoses_fail_closed() {
        let mut claim = kat_complete_claim_witness().claim;
        let duplicate = claim.service_lines[0].clone();
        claim.service_lines.push(duplicate);
        assert_eq!(
            canonical_lines(&claim).unwrap_err(),
            "service_line_identity_duplicate"
        );

        let mut diagnoses = kat_complete_claim_witness().claim;
        diagnoses.diagnoses = vec!["Z9".into(), "A10".into()];
        assert!(diagnosis_commitment(&diagnoses).is_ok());
        diagnoses.diagnoses = vec!["A10".into(), "Z9".into()];
        assert_eq!(
            diagnosis_commitment(&diagnoses).unwrap_err(),
            "diagnoses_not_canonical"
        );
        diagnoses.diagnoses = vec!["Z9".into(), "Z9".into()];
        assert_eq!(
            diagnosis_commitment(&diagnoses).unwrap_err(),
            "diagnoses_not_canonical"
        );
    }

    #[test]
    fn complete_claim_matches_python_cairo_private_semantics() {
        let execution = execute_complete_claim(&kat_complete_claim_witness()).unwrap();
        assert_eq!(PUBLIC_FIELD_COUNT, 12);
        assert_eq!(execution.public_fields.len(), 12);
        assert_eq!(execution.decision, 1);
        assert_eq!(execution.failure_code, 0);
        assert_eq!(execution.allowed_cents, 29);
        assert_eq!(execution.payment_cents, 29);
        assert_eq!(execution.public_fields, kat_expected_public_fields());
        assert_eq!(
            decimal_felt(
                "598817913772493792518451354714723885600521788519684488860027756480219862633"
            )
            .to_bytes_be(),
            execution.claim_commitment
        );
        assert_eq!(
            decimal_felt(
                "1856571629581991238116862944404670455739062457349312357412059600196600357886"
            )
            .to_bytes_be(),
            execution.batch_commitment
        );
    }

    #[test]
    fn governed_attempt_hashes_match_python_legacy_kat_exactly() {
        let witness = kat_complete_claim_witness();
        let identity = legacy_attempt_identity_commitment(&witness).unwrap();
        let snapshot = legacy_attempt_claim_snapshot_commitment(&witness.claim).unwrap();
        let record = legacy_attempt_record_commitment(&witness).unwrap();
        let nullifier = legacy_attempt_nullifier(&witness).unwrap();
        let ruleset_root = canonical_felt("ruleset_root", &witness.ruleset_root).unwrap();
        let leaf = claim_source_leaf(&witness, nullifier, record, ruleset_root).unwrap();
        assert_eq!(
            identity,
            decimal_felt(
                "2107348332775794051052545303096313043371385791672199663988498339633581739385"
            )
        );
        assert_eq!(
            snapshot,
            decimal_felt(
                "2943463548370776129911956343902907261536386896093321589767046108439169386789"
            )
        );
        assert_eq!(
            record,
            decimal_felt(
                "3071536578576274707571896893065765991262916119644431385166951145973756973307"
            )
        );
        assert_eq!(
            nullifier,
            decimal_felt(
                "2803046303380838580484408261874923165543787942339809658885540082145836050930"
            )
        );
        assert_eq!(
            leaf,
            decimal_felt(
                "2353052313618558482185397871882505396199949582779852874419840701935818967346"
            )
        );
    }

    #[test]
    fn witness_wire_round_trip_is_exact() {
        let witness = kat_complete_claim_witness();
        let wire = encode_witness(&witness).unwrap();
        assert_eq!(witness, decode_witness(&wire).unwrap());
    }

    #[test]
    fn full_width_oracle_signer_root_is_split_into_two_limbs() {
        assert_eq!(
            evidence_commitment(ORACLE_SIGNER_ROOT_HEX),
            decimal_felt(
                "2550139210646282851937903890346292004754752398079264055784675791567565471119"
            )
        );
    }

    #[test]
    fn canonical_oracle_leaves_match_the_application_kat() {
        let witness = kat_complete_claim_witness();
        let ruleset_root = canonical_felt("ruleset_root", &witness.ruleset_root).unwrap();
        let attempt_record = legacy_attempt_record_commitment(&witness).unwrap();
        let nullifier = legacy_attempt_nullifier(&witness).unwrap();
        assert_eq!(
            service_lines_commitment(&witness.claim).unwrap(),
            decimal_felt(
                "1102905664570150112913550316185449260110469371215389369029609486155026102513"
            )
        );
        assert_eq!(
            diagnosis_commitment(&witness.claim).unwrap(),
            decimal_felt(
                "80819912053356183396619885303867319772317151475604381550847745658201370588"
            )
        );
        let claim_leaf =
            claim_source_leaf(&witness, nullifier, attempt_record, ruleset_root).unwrap();
        assert_eq!(
            claim_leaf,
            decimal_felt(
                "2353052313618558482185397871882505396199949582779852874419840701935818967346"
            )
        );
        assert_eq!(
            pack_felt_text(&witness.claim.claim_id).unwrap(),
            decimal_felt("109949309784570719396977225830245160322746822705")
        );
        assert_eq!(
            normalized_fact_commitment(&witness.claim.flags),
            decimal_felt(
                "3221198546260712347666301627832848550123956590143848061940915891948520277334"
            )
        );
        assert_eq!(
            fact_verification_commitment(&witness.fact_verification).unwrap(),
            decimal_felt(
                "627461694130483417835886929132711567456735492239518625412380434342298559149"
            )
        );
        assert_eq!(
            evidence_commitment(ORACLE_EVIDENCE_TEXT),
            decimal_felt(
                "3256459273581194368449037840960621373473452630999358132045605326445485830393"
            )
        );
        let facts_leaf = claim_facts_leaf(&witness, claim_leaf).unwrap();
        assert_eq!(
            facts_leaf,
            decimal_felt(
                "2286089408910315454621599029806122615695894620218776157074139926108453368034"
            )
        );
        let authorization_leaf = authorization_leaf(
            &witness,
            &witness.authorizations[0],
            &witness.claim.service_lines[0],
        )
        .unwrap();
        assert_eq!(
            authorization_leaf,
            decimal_felt(
                "690205479713080336793646168023737008654379476773076137567432427347214160516"
            )
        );
        assert_eq!(
            canonical_felt("oracle_facts_root", &witness.oracle_facts_root).unwrap(),
            decimal_felt(
                "148911886983709353607376455509440083135115932565142773892400607112259112637"
            )
        );
    }

    #[test]
    fn witness_wire_rejects_postcard_trailing_bytes_when_declared_length_matches() {
        let mut wire = encode_witness(&kat_complete_claim_witness()).unwrap();
        let length_start = WIRE_MAGIC.len();
        let payload_len = u32::from_be_bytes(
            wire[length_start..length_start + 4]
                .try_into()
                .expect("four-byte length"),
        );
        wire.push(0);
        wire[length_start..length_start + 4]
            .copy_from_slice(&payload_len.checked_add(1).unwrap().to_be_bytes());
        assert_eq!(
            decode_witness(&wire).unwrap_err(),
            "witness_wire_trailing_bytes"
        );
    }

    #[test]
    fn legacy_internal_schema_is_rejected_before_execution() {
        let mut witness = kat_complete_claim_witness();
        witness.schema_version = 2;
        assert_eq!(
            execute_complete_claim(&witness).unwrap_err(),
            "witness_schema_version_mismatch"
        );
    }

    #[test]
    fn malformed_missing_and_extra_wire_data_is_rejected() {
        let wire = encode_witness(&kat_complete_claim_witness()).unwrap();
        assert_eq!(&wire[..WIRE_MAGIC.len()], b"BLPV2C03");
        assert!(decode_witness(&wire[..wire.len() - 1]).is_err());
        let mut extra = wire.clone();
        extra.push(0);
        assert!(decode_witness(&extra).is_err());
        let mut malformed = wire;
        malformed[0] ^= 1;
        assert_eq!(
            decode_witness(&malformed).unwrap_err(),
            "witness_wire_magic_mismatch"
        );
        let mut legacy = encode_witness(&kat_complete_claim_witness()).unwrap();
        legacy[..WIRE_MAGIC.len()].copy_from_slice(b"BLPV2C02");
        assert_eq!(
            decode_witness(&legacy).unwrap_err(),
            "witness_wire_magic_mismatch"
        );
    }

    #[test]
    fn fabricated_eligibility_is_rejected_by_oracle_membership() {
        let mut witness = kat_complete_claim_witness();
        witness.claim.flags.eligibility_active = false;
        assert_eq!(
            execute_complete_claim(&witness).unwrap_err(),
            "claim_facts_membership_mismatch"
        );
    }

    #[test]
    fn changed_fee_row_is_rejected_by_policy_membership() {
        let mut witness = kat_complete_claim_witness();
        witness.policy_rows[0].allowed_cents -= 1;
        assert_eq!(
            execute_complete_claim(&witness).unwrap_err(),
            "fee_row_membership_mismatch"
        );
    }

    #[test]
    fn authenticated_policy_absence_below_between_and_after_is_private_denial_11() {
        for procedure_code in ["00000", "A0000", "Z9999"] {
            let witness = make_policy_absence(procedure_code);
            let execution = execute_complete_claim(&witness).unwrap();
            assert_eq!(
                (execution.decision, execution.failure_code),
                (0, 11),
                "procedure {procedure_code}"
            );
            assert_eq!((execution.allowed_cents, execution.payment_cents), (0, 0));
            assert_ne!(execution.public_fields[3], execution.public_fields[4]);
            assert_eq!(execution.public_fields.len(), PUBLIC_FIELD_COUNT);
        }
    }

    #[test]
    fn omitted_policy_absence_evidence_is_a_hard_error() {
        let mut witness = make_policy_absence("A0000");
        witness.policy_rows.clear();
        assert_eq!(
            execute_complete_claim(&witness).unwrap_err(),
            "policy_rows_not_canonical"
        );
    }

    #[test]
    fn authenticated_predecessor_cannot_claim_false_absence_for_existing_key() {
        let ruleset_root = decimal_felt(PINNED_RULESET_ROOT_DECIMAL);
        let (_, _, rows) = kat_policy_tree(ruleset_root);
        let query_key = governed_procedure_key("T1019").unwrap();
        let predecessor = rows
            .into_iter()
            .find(|row| {
                canonical_felt("policy_next_procedure_key", &row.next_procedure_key).unwrap()
                    == query_key
            })
            .expect("KAT T1019 predecessor");
        let mut witness = kat_complete_claim_witness();
        witness.policy_rows = vec![predecessor];
        assert_eq!(
            execute_complete_claim(&witness).unwrap_err(),
            "policy_evidence_missing:T1019"
        );
    }

    #[test]
    fn forged_nonmembership_successor_is_rejected_by_policy_root() {
        let mut witness = make_policy_absence("A0000");
        witness.policy_rows[0].next_procedure_key =
            governed_procedure_key("Z9999").unwrap().to_bytes_be();
        assert_eq!(
            execute_complete_claim(&witness).unwrap_err(),
            "fee_row_membership_mismatch"
        );
    }

    #[test]
    fn stale_policy_shape_metadata_is_rejected_by_policy_root() {
        let mut witness = kat_complete_claim_witness();
        witness.policy_real_row_count += 1;
        assert_eq!(
            execute_complete_claim(&witness).unwrap_err(),
            "fee_policy_membership_mismatch"
        );
    }

    #[test]
    fn malformed_governed_procedure_code_is_structural_error() {
        let mut witness = kat_complete_claim_witness();
        witness.claim.service_lines[0].procedure_code = "bad-code".into();
        assert_eq!(
            execute_complete_claim(&witness).unwrap_err(),
            "service_line_procedure_code_not_canonical"
        );
    }

    #[test]
    fn original_only_attempt_lifecycle_is_fail_closed() {
        let mut witness = kat_complete_claim_witness();
        witness.attempt_version = 0;
        assert_eq!(
            execute_complete_claim(&witness).unwrap_err(),
            "attempt_version_invalid"
        );

        witness = kat_complete_claim_witness();
        witness.attempt_version = 2;
        assert_eq!(
            execute_complete_claim(&witness).unwrap_err(),
            "attempt_original_lifecycle_invalid"
        );

        witness = kat_complete_claim_witness();
        witness.attempt_version = 2;
        witness.revision_kind = REVISION_KIND_CORRECTION;
        witness.parent_attempt_version = 0;
        assert_eq!(
            execute_complete_claim(&witness).unwrap_err(),
            "attempt_revision_lifecycle_invalid"
        );

        witness = kat_complete_claim_witness();
        witness.attempt_version = 2;
        witness.revision_kind = REVISION_KIND_CORRECTION;
        witness.parent_attempt_version = 1;
        assert_eq!(
            execute_complete_claim(&witness).unwrap_err(),
            "attempt_revision_pending_lifecycle_authority"
        );

        witness = kat_complete_claim_witness();
        witness.revision_kind = 99;
        assert_eq!(
            execute_complete_claim(&witness).unwrap_err(),
            "attempt_revision_kind_invalid"
        );
    }

    #[test]
    fn empty_member_is_a_zero_encoded_private_denial() {
        let member_missing = make_denied(|witness| {
            witness.claim.member_id.clear();
            witness.claim.patient.id.clear();
        });
        assert_eq!(
            optional_packed_text(Some(&member_missing.claim.member_id)).unwrap(),
            Felt::ZERO
        );
        let member_nullifier = legacy_attempt_nullifier(&member_missing).unwrap();
        assert_eq!(
            legacy_attempt_claim_snapshot_commitment(&member_missing.claim).unwrap(),
            decimal_felt(
                "2545156635070659254193659211796381466946594743252897173655186110953309154536"
            )
        );
        assert_eq!(
            member_nullifier,
            decimal_felt(
                "2803046303380838580484408261874923165543787942339809658885540082145836050930"
            )
        );
        let member_execution = execute_complete_claim(&member_missing).unwrap();
        assert_eq!(
            (member_execution.decision, member_execution.failure_code),
            (0, 1)
        );
        assert_eq!(
            (
                member_execution.allowed_cents,
                member_execution.payment_cents
            ),
            (0, 0)
        );
        assert_ne!(
            member_execution.public_fields[3],
            member_execution.public_fields[4]
        );
    }

    #[test]
    fn npi_accepts_exact_ascii_digits_with_valid_check_digit() {
        assert_eq!(parse_npi("1999999984").unwrap(), 1_999_999_984);
        assert!(execute_complete_claim(&kat_complete_claim_witness()).is_ok());
    }

    #[test]
    fn npi_rejects_empty_non_ascii_and_non_ten_digit_forms() {
        for value in [
            "",
            "199999984",
            "19999999840",
            "199999998 ",
            "\u{0661}\u{0669}\u{0669}\u{0669}\u{0669}\u{0669}\u{0669}\u{0669}\u{0668}\u{0664}",
        ] {
            assert_npi_rejected(value, "npi_must_be_10_decimal_digits");
        }
    }

    #[test]
    fn npi_rejects_zero_value() {
        assert_npi_rejected("0000000000", "npi_must_be_nonzero");
    }

    #[test]
    fn npi_rejects_invalid_check_digit() {
        assert_npi_rejected("1999999987", "invalid_npi_check_digit");
    }

    #[test]
    fn service_date_accepts_only_the_two_exact_normal_forms() {
        let compact = parse_day("20260601").unwrap();
        assert_eq!(compact, parse_day("2026-06-01").unwrap());
        let mut hyphenated = kat_complete_claim_witness();
        hyphenated.claim.service_date = "2026-06-01".into();
        rebind_claim_and_oracle(&mut hyphenated);
        assert!(execute_complete_claim(&hyphenated).is_ok());
    }

    #[test]
    fn service_date_rejects_non_exact_separator_and_whitespace_forms() {
        for value in [
            "2026--06-01",
            "20-26-06-01",
            "202606-01",
            "2026-0601",
            " 20260601",
            "20260601 ",
        ] {
            assert_service_date_rejected(value, "date_format_invalid");
        }
    }

    #[test]
    fn service_date_rejects_invalid_calendar_day() {
        assert_service_date_rejected("2026-02-29", "date_day_invalid");
    }

    #[test]
    fn malformed_nonempty_provider_npi_is_structural_error() {
        let mut witness = kat_complete_claim_witness();
        witness.claim.provider.npi = "NOT-AN-NPI".into();
        assert_eq!(
            execute_complete_claim(&witness).unwrap_err(),
            "npi_must_be_10_decimal_digits"
        );
    }

    #[test]
    fn empty_governed_pepper_and_stale_attempt_binding_are_rejected() {
        let mut witness = kat_complete_claim_witness();
        witness.governed_pepper.clear();
        assert_eq!(
            execute_complete_claim(&witness).unwrap_err(),
            "attempt_governed_pepper_empty"
        );

        witness = kat_complete_claim_witness();
        witness.source_authority_id = "BL-SYNTH-OTHER-AUTH-V1".into();
        assert_eq!(
            execute_complete_claim(&witness).unwrap_err(),
            "claim_source_membership_mismatch"
        );
    }

    #[test]
    fn authenticated_absence_preserves_first_failure_order() {
        let mut witness = make_policy_absence("A0000");
        witness.claim.flags.eligibility_active = false;
        rebind_claim_and_oracle(&mut witness);
        let execution = execute_complete_claim(&witness).unwrap();
        assert_eq!((execution.decision, execution.failure_code), (0, 2));
        assert_eq!((execution.allowed_cents, execution.payment_cents), (0, 0));
    }

    #[test]
    fn claim_total_mismatch_remains_structural_error() {
        let mut witness = kat_complete_claim_witness();
        witness.claim.total_charge_cents += 1;
        assert_eq!(
            execute_complete_claim(&witness).unwrap_err(),
            "claim_total_not_derived_from_lines"
        );
    }

    #[test]
    fn zero_line_charge_and_zero_total_are_private_g8a_denial() {
        let witness = make_denied(|witness| {
            witness.claim.service_lines[0].charge_cents = 0;
            witness.claim.total_charge_cents = 0;
        });
        let execution = execute_complete_claim(&witness).unwrap();
        assert_eq!((execution.decision, execution.failure_code), (0, 10));
        assert_eq!((execution.allowed_cents, execution.payment_cents), (0, 0));
        assert_ne!(execution.public_fields[3], execution.public_fields[4]);
        assert_eq!(execution.public_fields.len(), PUBLIC_FIELD_COUNT);
    }

    #[test]
    fn zero_units_with_positive_total_are_private_g8a_denial() {
        let witness = make_denied(|witness| {
            witness.claim.service_lines[0].units_cents = 0;
        });
        let execution = execute_complete_claim(&witness).unwrap();
        assert_eq!((execution.decision, execution.failure_code), (0, 10));
        assert_eq!((execution.allowed_cents, execution.payment_cents), (0, 0));
        assert_ne!(execution.public_fields[3], execution.public_fields[4]);
        assert_eq!(execution.public_fields.len(), PUBLIC_FIELD_COUNT);
    }

    #[test]
    fn stale_claim_source_root_is_rejected() {
        let mut witness = kat_complete_claim_witness();
        witness.claim_source_root = felt_bytes(777);
        assert_eq!(
            execute_complete_claim(&witness).unwrap_err(),
            "claim_source_membership_mismatch"
        );
    }

    #[test]
    fn corrupted_authorization_path_is_rejected() {
        let mut witness = kat_complete_claim_witness();
        witness.authorizations[0].path.siblings[3] = felt_bytes(888);
        assert_eq!(
            execute_complete_claim(&witness).unwrap_err(),
            "authorization_membership_mismatch"
        );
    }

    #[test]
    fn corrupted_nullifier_path_is_rejected() {
        let mut witness = kat_complete_claim_witness();
        witness.nullifier.predecessor_path.siblings[7] = felt_bytes(1234);
        assert!(execute_complete_claim(&witness)
            .unwrap_err()
            .starts_with("nullifier_"));
    }

    #[test]
    fn wrong_domain_and_noncanonical_field_are_rejected() {
        let mut witness = kat_complete_claim_witness();
        witness.settlement_domain = felt_bytes(EXPECTED_SETTLEMENT_DOMAIN + 1);
        assert_eq!(
            execute_complete_claim(&witness).unwrap_err(),
            "settlement_domain_mismatch"
        );
        witness = kat_complete_claim_witness();
        witness.batch_nonce = [0xff; 32];
        assert_eq!(
            execute_complete_claim(&witness).unwrap_err(),
            "batch_nonce_not_canonical_field"
        );
    }

    #[test]
    fn wrong_rule_version_and_root_are_rejected() {
        let mut witness = kat_complete_claim_witness();
        witness.rule_version.push_str("-unauthorized");
        assert_eq!(
            execute_complete_claim(&witness).unwrap_err(),
            "rule_version_mismatch"
        );
        witness = kat_complete_claim_witness();
        witness.ruleset_root = felt_bytes(999);
        assert_eq!(
            execute_complete_claim(&witness).unwrap_err(),
            "ruleset_root_not_pinned"
        );
    }

    #[test]
    fn private_payment_mismatch_is_rejected() {
        let mut witness = kat_complete_claim_witness();
        witness.expected_total_payment_cents -= 1;
        assert_eq!(
            execute_complete_claim(&witness).unwrap_err(),
            "expected_payment_mismatch"
        );
    }

    #[test]
    fn changed_private_claim_cannot_reuse_old_authority_paths() {
        let mut witness = kat_complete_claim_witness();
        witness.claim.patient.name = "Different Synthetic Patient".into();
        let changed = execute_complete_claim(&witness).unwrap();
        let baseline = execute_complete_claim(&kat_complete_claim_witness()).unwrap();
        assert_ne!(changed.public_fields[9], baseline.public_fields[9]);
        assert_ne!(changed.public_fields[11], baseline.public_fields[11]);
    }

    #[test]
    fn authenticated_suspended_provider_is_denied_without_payment_and_advances_root() {
        let witness = make_denied(|witness| witness.claim.flags.provider_not_suspended = false);
        let execution = execute_complete_claim(&witness).unwrap();
        assert_eq!((execution.decision, execution.failure_code), (0, 6));
        assert_eq!((execution.allowed_cents, execution.payment_cents), (0, 0));
        assert_ne!(execution.public_fields[3], execution.public_fields[4]);
    }

    #[test]
    fn authenticated_missing_prior_authorization_is_denied() {
        let witness = make_denied(|witness| {
            witness.claim.service_lines[0].prior_authorization = None;
        });
        let execution = execute_complete_claim(&witness).unwrap();
        assert_eq!((execution.decision, execution.failure_code), (0, 9));
        assert_eq!((execution.allowed_cents, execution.payment_cents), (0, 0));
        assert_ne!(execution.public_fields[3], execution.public_fields[4]);
    }

    #[test]
    fn authenticated_unverified_prior_authorization_token_is_denied() {
        let witness = make_denied(|witness| {
            let tar_fact = witness
                .fact_verification
                .iter_mut()
                .find(|entry| entry.key == "tar_authorization")
                .expect("KAT tar authorization fact");
            tar_fact.value = "UNVERIFIED".into();
        });
        let execution = execute_complete_claim(&witness).unwrap();
        assert_eq!((execution.decision, execution.failure_code), (0, 9));
        assert_eq!((execution.allowed_cents, execution.payment_cents), (0, 0));
        assert_ne!(execution.public_fields[3], execution.public_fields[4]);
    }

    #[test]
    fn authenticated_duplicate_is_denied_and_advances_nullifier_root() {
        let witness = make_denied(|witness| witness.claim.flags.duplicate_claim = true);
        let execution = execute_complete_claim(&witness).unwrap();
        assert_eq!((execution.decision, execution.failure_code), (0, 12));
        assert_eq!((execution.allowed_cents, execution.payment_cents), (0, 0));
        assert_ne!(execution.public_fields[3], execution.public_fields[4]);
    }

    #[test]
    fn authenticated_program_integrity_hold_is_denial_13() {
        let witness = make_denied(|witness| witness.claim.flags.program_integrity_hold = true);
        let execution = execute_complete_claim(&witness).unwrap();
        assert_eq!((execution.decision, execution.failure_code), (0, 13));
        assert_eq!((execution.allowed_cents, execution.payment_cents), (0, 0));
        assert_ne!(execution.public_fields[3], execution.public_fields[4]);
    }

    #[test]
    fn authenticated_absence_precedes_duplicate_and_integrity_gates() {
        let mut witness = make_policy_absence("A0000");
        witness.claim.flags.duplicate_claim = true;
        witness.claim.flags.program_integrity_hold = true;
        rebind_claim_and_oracle(&mut witness);
        let execution = execute_complete_claim(&witness).unwrap();
        assert_eq!((execution.decision, execution.failure_code), (0, 11));
        assert_eq!((execution.allowed_cents, execution.payment_cents), (0, 0));
    }

    #[test]
    fn duplicate_without_nullifier_insertion_is_rejected() {
        let mut witness = kat_complete_claim_witness();
        witness.claim.flags.duplicate_claim = true;
        rebind_claim_and_oracle(&mut witness);
        witness.expected_total_allowed_cents = 0;
        witness.expected_total_payment_cents = 0;
        witness.nullifier.root_after = witness.nullifier.root_before;
        assert_eq!(
            execute_complete_claim(&witness).unwrap_err(),
            "nullifier_transition_root_mismatch"
        );
    }
}
