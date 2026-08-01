use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::{collections::BTreeMap, fmt};

const CODE_MAPPING_TSV: &str = include_str!("../../rarc_mapping.tsv");
const TAR_REQUIRED_POLICY_JSON: &str =
    include_str!("../../app/policy/tar_required_procedures_v1.json");
const MAX_CENTS_EXCLUSIVE: i64 = 1i64 << 32;

#[derive(Debug, Deserialize)]
struct TarRequiredPolicy {
    schema_version: String,
    tar_required_procedure_codes: Vec<String>,
}

fn default_tar_required_codes() -> Vec<String> {
    let policy: TarRequiredPolicy =
        serde_json::from_str(TAR_REQUIRED_POLICY_JSON).expect("valid tar required policy json");
    assert_eq!(
        policy.schema_version, "blind_ledger_tar_required_procedures_v1",
        "tar required policy schema mismatch"
    );
    policy.tar_required_procedure_codes
}

fn procedure_requires_prior_authorization_with_codes(
    procedure_code: &str,
    tar_required_codes: &[String],
) -> bool {
    tar_required_codes.iter().any(|code| code == procedure_code)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MoneyCents(i64);

impl MoneyCents {
    pub fn from_cents(cents: i64) -> Self {
        Self(cents)
    }

    pub fn from_decimal_str(raw: &str) -> Result<Self, String> {
        parse_money_cents(raw).map(Self)
    }

    pub fn cents(self) -> i64 {
        self.0
    }

    pub fn to_major_f64(self) -> f64 {
        self.0 as f64 / 100.0
    }
}

fn format_cents(cents: i64) -> String {
    let sign = if cents < 0 { "-" } else { "" };
    let magnitude = (cents as i128).abs();
    format!("{sign}{}.{:02}", magnitude / 100, magnitude % 100)
}

pub fn parse_money_cents(raw: &str) -> Result<i64, String> {
    if raw.is_empty() {
        return Err("invalid_money:empty".into());
    }
    if raw.trim() != raw || raw.starts_with('+') || raw.starts_with('-') {
        return Err(format!("invalid_money:{raw}"));
    }
    let parts: Vec<&str> = raw.split('.').collect();
    if parts.len() > 2 {
        return Err(format!("invalid_money:{raw}"));
    }
    let whole_part = parts[0];
    if whole_part.is_empty()
        || !whole_part.chars().all(|ch| ch.is_ascii_digit())
        || (whole_part.len() > 1 && whole_part.starts_with('0'))
    {
        return Err(format!("invalid_money:{raw}"));
    }
    let fractional_part = if parts.len() == 2 { parts[1] } else { "" };
    if parts.len() == 2
        && (fractional_part.is_empty()
            || fractional_part.len() > 2
            || !fractional_part.chars().all(|ch| ch.is_ascii_digit()))
    {
        return Err(format!("invalid_money:{raw}"));
    }
    if whole_part.len() > 8 {
        return Err(format!("money_out_of_range:{raw}"));
    }
    let whole = whole_part
        .parse::<i128>()
        .map_err(|_| format!("invalid_money:{raw}"))?;
    let mut cents = whole
        .checked_mul(100)
        .ok_or_else(|| format!("money_out_of_range:{raw}"))?;
    let mut fractional_digits = fractional_part.chars();
    let first_cent = fractional_digits
        .next()
        .and_then(|ch| ch.to_digit(10))
        .unwrap_or(0) as i128;
    let second_cent = fractional_digits
        .next()
        .and_then(|ch| ch.to_digit(10))
        .unwrap_or(0) as i128;
    cents += first_cent * 10 + second_cent;
    if cents < 0 || cents >= MAX_CENTS_EXCLUSIVE as i128 {
        return Err(format!("money_out_of_range:{raw}"));
    }
    Ok(cents as i64)
}

fn canonical_amount_cents(cents: i64) -> bool {
    (0..MAX_CENTS_EXCLUSIVE).contains(&cents)
}

fn canonical_context_money_fields(ctx: &SharedContext) -> bool {
    canonical_amount_cents(ctx.total_charge.cents())
        && ctx.service_lines.iter().all(|line| {
            canonical_amount_cents(line.charge_amount.cents())
                && canonical_amount_cents(line.units.cents())
        })
}

fn validate_context_money(ctx: &SharedContext) -> Result<(), &'static str> {
    if !canonical_context_money_fields(ctx) {
        return Err("money_out_of_range");
    }
    let sum_line_charge_cents = ctx
        .service_lines
        .iter()
        .try_fold(0i64, |total, line| {
            total.checked_add(line.charge_amount.cents())
        })
        .ok_or("claim_total_out_of_range")?;
    if !canonical_amount_cents(sum_line_charge_cents) {
        return Err("claim_total_out_of_range");
    }
    if ctx.total_charge.cents() != sum_line_charge_cents {
        return Err("claim_total_mismatch");
    }
    Ok(())
}

fn canonical_context_money(ctx: &SharedContext) -> bool {
    validate_context_money(ctx).is_ok()
}

impl Serialize for MoneyCents {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format_cents(self.0))
    }
}

struct MoneyCentsVisitor;

impl<'de> Visitor<'de> for MoneyCentsVisitor {
    type Value = MoneyCents;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a canonical decimal money string")
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let _ = value;
        Err(E::custom("noncanonical_money:json_number_forbidden"))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let _ = value;
        Err(E::custom("noncanonical_money:json_number_forbidden"))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let _ = value;
        Err(E::custom("noncanonical_money:json_number_forbidden"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        parse_money_cents(value).map(MoneyCents).map_err(E::custom)
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_str(&value)
    }
}

impl<'de> Deserialize<'de> for MoneyCents {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(MoneyCentsVisitor)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Patient {
    pub name: String,
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provider {
    pub npi: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceLine {
    pub line_id: String,
    pub procedure_code: String,
    pub charge_amount: MoneyCents,
    pub units: MoneyCents,
    pub prior_authorization: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Flags {
    pub eligibility_active: bool,
    pub provider_enrolled: bool,
    pub provider_not_suspended: bool,
    pub not_deceased: bool,
    pub duplicate_claim: bool,
    pub program_integrity_hold: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedContext {
    pub claim_id: String,
    pub transaction_set: String,
    pub payer_id: String,
    pub member_id: String,
    pub patient: Patient,
    pub provider: Provider,
    pub service_date: String,
    pub diagnoses: Vec<String>,
    pub service_lines: Vec<ServiceLine>,
    pub total_charge: MoneyCents,
    pub flags: Flags,
    #[serde(default)]
    pub tar_authorization_verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateResult {
    pub gate: String,
    pub passed: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdjudicationResult {
    pub claim_id: String,
    pub approved: bool,
    pub denial_reason: String,
    pub gates: Vec<GateResult>,
    pub carc: String,
    pub rarc: String,
    pub total_charge: f64,
    pub total_charge_cents: i64,
    pub payable_amount: f64,
    pub payable_amount_cents: i64,
}

/// Authenticated fee fact supplied by the proof witness.
///
/// This type deliberately contains integer money only. The proof path must not
/// consult the built-in development fee table or parse a local policy file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofFeeRow {
    pub procedure_code: String,
    /// True only after the proof backend authenticated exact policy membership.
    /// False represents authenticated non-membership for this procedure code.
    pub policy_present: bool,
    pub allowed_cents: i64,
    pub requires_prior_authorization: bool,
}

/// Deterministic adjudication result used inside the proof guest.
///
/// `failure_code` is the one-based index of the first failed denial gate and is
/// zero for an approval. Structural-invalidity errors are returned before this
/// result is constructed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofAdjudicationResult {
    pub approved: bool,
    pub denial_reason: String,
    pub failure_code: u32,
    pub allowed_amount_cents: i64,
    pub payment_amount_cents: i64,
}

fn proof_denial_reason(failure_code: u32) -> &'static str {
    match failure_code {
        1 => "member_id_missing",
        2 => "eligibility_inactive",
        3 => "patient_deceased",
        4 => "provider_npi_missing",
        5 => "provider_not_enrolled",
        6 => "provider_suspended",
        7 => "service_line_missing",
        8 => "diagnosis_missing",
        9 => "prior_authorization_required",
        10 => "invalid_charge",
        11 => "fee_schedule_missing",
        12 => "duplicate_claim",
        13 => "program_integrity_hold",
        _ => "",
    }
}

/// Evaluate the proof rule set using only authenticated inputs and integer
/// arithmetic. This function performs no filesystem, network, clock,
/// environment, fallback, JSON-policy, or floating-point work.
pub fn adjudicate_for_proof(
    ctx: &SharedContext,
    fee_rows: &[ProofFeeRow],
) -> Result<ProofAdjudicationResult, String> {
    if !canonical_context_money_fields(ctx) {
        return Err("proof_money_out_of_range".into());
    }
    if fee_rows.is_empty() {
        return Err("proof_fee_rows_empty".into());
    }
    for (index, row) in fee_rows.iter().enumerate() {
        if row.procedure_code.is_empty() {
            return Err("proof_fee_code_empty".into());
        }
        if !canonical_amount_cents(row.allowed_cents) {
            return Err("proof_fee_amount_out_of_range".into());
        }
        if !row.policy_present && (row.allowed_cents != 0 || row.requires_prior_authorization) {
            return Err("proof_fee_absence_payload_nonzero".into());
        }
        if fee_rows[..index]
            .iter()
            .any(|prior| prior.procedure_code == row.procedure_code)
        {
            return Err("proof_fee_code_duplicate".into());
        }
    }

    // A missing authenticated fee row is malformed proof input, not evidence
    // that a governed policy entry is absent. Keep the fee-schedule denial in
    // the shared gate order, but reject row omissions until the proof carries
    // an authenticated non-membership witness.
    let fee_row_coverage_complete = ctx.service_lines.iter().all(|line| {
        fee_rows
            .iter()
            .any(|row| row.procedure_code == line.procedure_code)
    });
    if !fee_row_coverage_complete {
        let missing_code = ctx
            .service_lines
            .iter()
            .find(|line| {
                !fee_rows
                    .iter()
                    .any(|row| row.procedure_code == line.procedure_code)
            })
            .map(|line| line.procedure_code.as_str())
            .expect("fee row coverage was checked above");
        return Err(format!("proof_fee_row_missing:{missing_code}"));
    }
    let fee_schedule_present = ctx.service_lines.iter().all(|line| {
        fee_rows
            .iter()
            .find(|row| row.procedure_code == line.procedure_code)
            .expect("fee row coverage was checked above")
            .policy_present
    });

    let mut sum_line_charge_cents = 0i64;
    let mut allowed_amount_cents = 0i64;
    let mut all_required_authorized = true;
    for line in &ctx.service_lines {
        let row = fee_rows
            .iter()
            .find(|candidate| candidate.procedure_code == line.procedure_code)
            .expect("fee row coverage was checked above");
        sum_line_charge_cents = sum_line_charge_cents
            .checked_add(line.charge_amount.cents())
            .ok_or_else(|| "proof_line_charge_overflow".to_string())?;
        allowed_amount_cents = allowed_amount_cents
            .checked_add(line.charge_amount.cents().min(row.allowed_cents))
            .ok_or_else(|| "proof_allowed_amount_overflow".to_string())?;
        if row.requires_prior_authorization
            && !(ctx.tar_authorization_verified
                && line
                    .prior_authorization
                    .as_ref()
                    .map(|value| !value.is_empty())
                    .unwrap_or(false))
        {
            all_required_authorized = false;
        }
    }

    if !canonical_amount_cents(sum_line_charge_cents)
        || !canonical_amount_cents(allowed_amount_cents)
    {
        return Err("proof_claim_total_out_of_range".into());
    }

    let charge_valid = ctx.total_charge.cents() > 0
        && canonical_context_money(ctx)
        && ctx
            .service_lines
            .iter()
            .all(|line| line.charge_amount.cents() > 0 && line.units.cents() > 0);
    if ctx.total_charge.cents() != sum_line_charge_cents
        || allowed_amount_cents > sum_line_charge_cents
    {
        return Err("claim_total_mismatch".into());
    }
    let gates = [
        !ctx.member_id.is_empty(),
        ctx.flags.eligibility_active,
        ctx.flags.not_deceased,
        !ctx.provider.npi.is_empty(),
        ctx.flags.provider_enrolled,
        ctx.flags.provider_not_suspended,
        !ctx.service_lines.is_empty(),
        !ctx.diagnoses.is_empty(),
        all_required_authorized,
        charge_valid,
        fee_schedule_present,
        !ctx.flags.duplicate_claim,
        !ctx.flags.program_integrity_hold,
    ];
    let failure_code = gates
        .iter()
        .position(|passed| !passed)
        .map(|index| index as u32 + 1)
        .unwrap_or(0);
    let approved = failure_code == 0;
    Ok(ProofAdjudicationResult {
        approved,
        denial_reason: proof_denial_reason(failure_code).into(),
        failure_code,
        allowed_amount_cents,
        payment_amount_cents: if approved { allowed_amount_cents } else { 0 },
    })
}

fn gate(name: &str, passed: bool, reason: &str) -> GateResult {
    GateResult {
        gate: name.to_string(),
        passed,
        reason: if passed { "".into() } else { reason.into() },
    }
}

fn default_fee_schedule_cents() -> BTreeMap<String, i64> {
    ["99213", "T1019", "S5102", "H2015"]
        .into_iter()
        .map(|procedure_code| (procedure_code.to_string(), 12_500))
        .collect()
}

fn governed_fee_allowed_cents(
    fee_schedule_cents: &BTreeMap<String, i64>,
    procedure_code: &str,
) -> Option<i64> {
    fee_schedule_cents
        .get(procedure_code)
        .copied()
        .filter(|amount| canonical_amount_cents(*amount))
}

pub fn allowed_amount_cents(ctx: &SharedContext) -> Result<i64, String> {
    allowed_amount_cents_with_fee_schedule(ctx, &default_fee_schedule_cents())
}

pub fn allowed_amount_cents_with_fee_schedule(
    ctx: &SharedContext,
    fee_schedule_cents: &BTreeMap<String, i64>,
) -> Result<i64, String> {
    validate_context_money(ctx).map_err(str::to_string)?;
    let mut total = 0i64;
    for line in &ctx.service_lines {
        let fee = governed_fee_allowed_cents(fee_schedule_cents, &line.procedure_code)
            .ok_or_else(|| format!("fee_schedule_missing:{}", line.procedure_code))?;
        total = total
            .checked_add(line.charge_amount.cents().min(fee))
            .ok_or_else(|| "allowed_amount_overflow".to_string())?;
        if !canonical_amount_cents(total) {
            return Err("allowed_amount_out_of_range".into());
        }
    }
    Ok(total)
}

pub fn evaluate_gates(ctx: &SharedContext) -> Vec<GateResult> {
    evaluate_gates_with_tar_required_codes(ctx, &default_tar_required_codes())
}

pub fn evaluate_gates_with_tar_required_codes(
    ctx: &SharedContext,
    tar_required_codes: &[String],
) -> Vec<GateResult> {
    evaluate_gates_with_policy(ctx, tar_required_codes, &default_fee_schedule_cents())
}

pub fn evaluate_gates_with_policy(
    ctx: &SharedContext,
    tar_required_codes: &[String],
    fee_schedule_cents: &BTreeMap<String, i64>,
) -> Vec<GateResult> {
    validate_context_money(ctx).unwrap_or_else(|error| panic!("structural_money:{error}"));
    let pa_ok = ctx.service_lines.iter().all(|line| {
        governed_fee_allowed_cents(fee_schedule_cents, &line.procedure_code).is_none()
            || !procedure_requires_prior_authorization_with_codes(
                &line.procedure_code,
                tar_required_codes,
            )
            || (ctx.tar_authorization_verified
                && line
                    .prior_authorization
                    .as_ref()
                    .map(|s| !s.is_empty())
                    .unwrap_or(false))
    });
    let charge_valid = canonical_context_money(ctx)
        && ctx.total_charge.cents() > 0
        && ctx
            .service_lines
            .iter()
            .all(|line| line.charge_amount.cents() > 0 && line.units.cents() > 0);
    let mut missing_fee_codes: Vec<String> = ctx
        .service_lines
        .iter()
        .filter(|line| {
            governed_fee_allowed_cents(fee_schedule_cents, &line.procedure_code).is_none()
        })
        .map(|line| line.procedure_code.clone())
        .collect();
    missing_fee_codes.sort();
    missing_fee_codes.dedup();
    let fee_schedule_present = missing_fee_codes.is_empty();
    let fee_schedule_reason = if fee_schedule_present {
        ""
    } else {
        "fee_schedule_missing"
    };
    vec![
        gate(
            "G1_MEMBER_ID_PRESENT",
            !ctx.member_id.is_empty(),
            "member_id_missing",
        ),
        gate(
            "G2_ELIGIBILITY_ACTIVE",
            ctx.flags.eligibility_active,
            "eligibility_inactive",
        ),
        gate(
            "G2B_PATIENT_NOT_DECEASED",
            ctx.flags.not_deceased,
            "patient_deceased",
        ),
        gate(
            "G3_PROVIDER_NPI_PRESENT",
            !ctx.provider.npi.is_empty(),
            "provider_npi_missing",
        ),
        gate(
            "G4_PROVIDER_ENROLLED",
            ctx.flags.provider_enrolled,
            "provider_not_enrolled",
        ),
        gate(
            "G4B_PROVIDER_NOT_SUSPENDED",
            ctx.flags.provider_not_suspended,
            "provider_suspended",
        ),
        gate(
            "G5_SERVICE_LINES_PRESENT",
            !ctx.service_lines.is_empty(),
            "service_line_missing",
        ),
        gate(
            "G6_DIAGNOSIS_PRESENT",
            !ctx.diagnoses.is_empty(),
            "diagnosis_missing",
        ),
        gate(
            "G7_PRIOR_AUTH_WHEN_REQUIRED",
            pa_ok,
            "prior_authorization_required",
        ),
        gate("G8A_CHARGE_VALID", charge_valid, "invalid_charge"),
        gate(
            "G8B_FEE_SCHEDULE_PRESENT",
            fee_schedule_present,
            fee_schedule_reason,
        ),
        gate(
            "G9_NOT_DUPLICATE",
            !ctx.flags.duplicate_claim,
            "duplicate_claim",
        ),
        gate(
            "G10_NO_PROGRAM_INTEGRITY_HOLD",
            !ctx.flags.program_integrity_hold,
            "program_integrity_hold",
        ),
    ]
}

fn codes(reason: &str) -> (&'static str, &'static str) {
    for line in CODE_MAPPING_TSV.lines().skip(1) {
        let mut cols = line.split('\t');
        let _gate = cols.next();
        let row_reason = cols.next();
        let carc = cols.next();
        let _carc_meaning = cols.next();
        let rarc = cols.next();
        if row_reason == Some(reason) {
            if let (Some(carc), Some(rarc)) = (carc, rarc) {
                return (carc, rarc);
            }
        }
    }
    ("16", "N130")
}

pub fn adjudicate(ctx: &SharedContext) -> AdjudicationResult {
    adjudicate_with_tar_required_codes(ctx, &default_tar_required_codes())
}

pub fn adjudicate_with_tar_required_codes(
    ctx: &SharedContext,
    tar_required_codes: &[String],
) -> AdjudicationResult {
    adjudicate_with_policy(ctx, tar_required_codes, &default_fee_schedule_cents())
}

pub fn adjudicate_with_fee_schedule(
    ctx: &SharedContext,
    fee_schedule_cents: &BTreeMap<String, i64>,
) -> AdjudicationResult {
    adjudicate_with_policy(ctx, &default_tar_required_codes(), fee_schedule_cents)
}

pub fn adjudicate_with_policy(
    ctx: &SharedContext,
    tar_required_codes: &[String],
    fee_schedule_cents: &BTreeMap<String, i64>,
) -> AdjudicationResult {
    let gates = evaluate_gates_with_policy(ctx, tar_required_codes, fee_schedule_cents);
    let failed = gates.iter().find(|g| !g.passed);
    let approved = failed.is_none();
    let reason = failed.map(|g| g.reason.clone()).unwrap_or_default();
    let (carc, rarc) = if approved { ("", "") } else { codes(&reason) };
    let payable_amount_cents = if approved {
        allowed_amount_cents_with_fee_schedule(ctx, fee_schedule_cents)
            .expect("fee schedule gate must pass before approval")
    } else {
        0
    };
    AdjudicationResult {
        claim_id: ctx.claim_id.clone(),
        approved,
        denial_reason: reason,
        gates,
        carc: carc.into(),
        rarc: rarc.into(),
        total_charge: ctx.total_charge.to_major_f64(),
        total_charge_cents: ctx.total_charge.cents(),
        payable_amount: payable_amount_cents as f64 / 100.0,
        payable_amount_cents,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> SharedContext {
        SharedContext {
            claim_id: "UNIT-CLAIM".into(),
            transaction_set: "837".into(),
            payer_id: "PAYER".into(),
            member_id: "M1".into(),
            patient: Patient {
                name: "Jane Doe".into(),
                id: "M1".into(),
            },
            provider: Provider {
                npi: "1999999987".into(),
                name: "Alice Adams".into(),
            },
            service_date: "20260601".into(),
            diagnoses: vec!["F840".into()],
            service_lines: vec![ServiceLine {
                line_id: "1".into(),
                procedure_code: "99213".into(),
                charge_amount: MoneyCents::from_cents(12_500),
                units: MoneyCents::from_cents(100),
                prior_authorization: Some("PA-OK".into()),
            }],
            total_charge: MoneyCents::from_cents(12_500),
            flags: Flags {
                eligibility_active: true,
                provider_enrolled: true,
                provider_not_suspended: true,
                not_deceased: true,
                duplicate_claim: false,
                program_integrity_hold: false,
            },
            tar_authorization_verified: true,
        }
    }

    fn mapping_for(reason: &str) -> (&'static str, &'static str) {
        for line in CODE_MAPPING_TSV.lines().skip(1) {
            let cols: Vec<&str> = line.split('\t').collect();
            if cols.len() >= 5 && cols[1] == reason {
                return (cols[2], cols[4]);
            }
        }
        panic!("missing mapping for {reason}");
    }

    fn gate<'a>(result: &'a AdjudicationResult, gate_name: &str) -> &'a GateResult {
        result
            .gates
            .iter()
            .find(|g| g.gate == gate_name)
            .expect("gate missing")
    }

    fn assert_gate_passes(ctx: SharedContext, gate_name: &str) {
        let result = adjudicate(&ctx);
        let gate = gate(&result, gate_name);
        assert!(gate.passed, "{gate_name} should pass");
        assert_eq!(
            gate.reason, "",
            "passing gates should not carry failure reasons"
        );
    }

    fn assert_gate_fails(ctx: SharedContext, gate_name: &str, reason: &str) {
        let result = adjudicate(&ctx);
        let gate = gate(&result, gate_name);
        let (carc, rarc) = mapping_for(reason);
        assert!(!gate.passed, "{gate_name} should fail");
        assert_eq!(gate.reason, reason);
        assert!(!result.approved);
        assert_eq!(result.denial_reason, reason);
        assert_eq!(result.carc, carc);
        assert_eq!(result.rarc, rarc);
        assert_eq!((result.carc.as_str(), result.rarc.as_str()), codes(reason));
    }

    #[test]
    fn g1_passes_when_member_id_present() {
        assert_gate_passes(ctx(), "G1_MEMBER_ID_PRESENT");
    }

    #[test]
    fn g1_fails_when_member_id_empty() {
        let mut c = ctx();
        c.member_id.clear();
        c.patient.id.clear();
        assert_gate_fails(c, "G1_MEMBER_ID_PRESENT", "member_id_missing");
    }

    #[test]
    fn g2_passes_when_eligibility_active() {
        assert_gate_passes(ctx(), "G2_ELIGIBILITY_ACTIVE");
    }

    #[test]
    fn g2_fails_when_eligibility_inactive() {
        let mut c = ctx();
        c.flags.eligibility_active = false;
        assert_gate_fails(c, "G2_ELIGIBILITY_ACTIVE", "eligibility_inactive");
    }

    #[test]
    fn g3_passes_when_provider_npi_present() {
        assert_gate_passes(ctx(), "G3_PROVIDER_NPI_PRESENT");
    }

    #[test]
    fn g3_fails_when_provider_npi_empty() {
        let mut c = ctx();
        c.provider.npi.clear();
        assert_gate_fails(c, "G3_PROVIDER_NPI_PRESENT", "provider_npi_missing");
    }

    #[test]
    fn g4_passes_when_provider_enrolled() {
        assert_gate_passes(ctx(), "G4_PROVIDER_ENROLLED");
    }

    #[test]
    fn g4_fails_when_provider_not_enrolled() {
        let mut c = ctx();
        c.flags.provider_enrolled = false;
        assert_gate_fails(c, "G4_PROVIDER_ENROLLED", "provider_not_enrolled");
    }

    #[test]
    fn g2b_fails_when_patient_deceased() {
        let mut c = ctx();
        c.flags.not_deceased = false;
        assert_gate_fails(c, "G2B_PATIENT_NOT_DECEASED", "patient_deceased");
    }

    #[test]
    fn g4b_fails_when_provider_suspended() {
        let mut c = ctx();
        c.flags.provider_not_suspended = false;
        assert_gate_fails(c, "G4B_PROVIDER_NOT_SUSPENDED", "provider_suspended");
    }

    #[test]
    fn g5_passes_when_service_line_present() {
        assert_gate_passes(ctx(), "G5_SERVICE_LINES_PRESENT");
    }

    #[test]
    fn g5_fails_when_service_lines_empty() {
        let mut c = ctx();
        c.service_lines.clear();
        c.total_charge = MoneyCents::from_cents(0);
        assert_gate_fails(c, "G5_SERVICE_LINES_PRESENT", "service_line_missing");
    }

    #[test]
    fn g6_passes_when_diagnosis_present() {
        assert_gate_passes(ctx(), "G6_DIAGNOSIS_PRESENT");
    }

    #[test]
    fn g6_fails_when_diagnoses_empty() {
        let mut c = ctx();
        c.diagnoses.clear();
        assert_gate_fails(c, "G6_DIAGNOSIS_PRESENT", "diagnosis_missing");
    }

    #[test]
    fn g7_passes_when_required_prior_auth_present() {
        let mut c = ctx();
        c.service_lines[0].procedure_code = "T1019".into();
        c.service_lines[0].prior_authorization = Some("PA-OK".into());
        assert_gate_passes(c, "G7_PRIOR_AUTH_WHEN_REQUIRED");
    }

    #[test]
    fn g7_fails_when_required_prior_auth_missing() {
        let mut c = ctx();
        c.service_lines[0].procedure_code = "T1019".into();
        c.service_lines[0].prior_authorization = None;
        assert_gate_fails(
            c,
            "G7_PRIOR_AUTH_WHEN_REQUIRED",
            "prior_authorization_required",
        );
    }

    #[test]
    fn g7_fails_when_prior_auth_token_is_not_verified() {
        let mut c = ctx();
        c.service_lines[0].procedure_code = "T1019".into();
        c.service_lines[0].prior_authorization = Some("PA-UNVERIFIED".into());
        c.tar_authorization_verified = false;
        assert_gate_fails(
            c,
            "G7_PRIOR_AUTH_WHEN_REQUIRED",
            "prior_authorization_required",
        );
    }

    #[test]
    fn g8_fails_when_total_and_line_charge_are_zero() {
        let mut c = ctx();
        c.total_charge = MoneyCents::from_cents(0);
        c.service_lines[0].charge_amount = MoneyCents::from_cents(0);
        assert_gate_fails(c, "G8A_CHARGE_VALID", "invalid_charge");
    }

    #[test]
    fn g8_fails_when_line_units_are_zero() {
        let mut c = ctx();
        c.service_lines[0].units = MoneyCents::from_cents(0);
        assert_gate_fails(c, "G8A_CHARGE_VALID", "invalid_charge");
    }

    #[test]
    #[should_panic(expected = "structural_money:claim_total_mismatch")]
    fn ordinary_adjudication_rejects_total_mismatch_structurally() {
        let mut c = ctx();
        c.total_charge = MoneyCents::from_cents(12_499);
        let _ = adjudicate(&c);
    }

    #[test]
    fn money_parser_accepts_only_exact_unsigned_canonical_cents() {
        let cases = [
            ("0", 0),
            ("0.00", 0),
            ("1", 100),
            ("1.2", 120),
            ("1.23", 123),
            ("42949672.94", 4_294_967_294),
            ("42949672.95", 4_294_967_295),
        ];
        for (raw, expected) in cases {
            assert_eq!(parse_money_cents(raw).unwrap(), expected);
        }

        for raw in [
            "0.145",
            "1.005",
            "+1",
            "-1",
            " 1",
            "1 ",
            "01",
            "1e2",
            "1,00",
            "1.",
            "42949672.96",
        ] {
            assert!(parse_money_cents(raw).is_err(), "accepted {raw}");
        }
        assert!(parse_money_cents("999999999999999999999999999999999999999")
            .unwrap_err()
            .starts_with("money_out_of_range:"));
    }

    #[test]
    fn money_json_boundary_rejects_numeric_tokens() {
        for raw in ["1", "1.0", "1.000", "1e2", "1E2"] {
            let error = serde_json::from_str::<MoneyCents>(raw)
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("json_number_forbidden"),
                "unexpected error for {raw}: {error}"
            );
        }
        assert_eq!(
            serde_json::from_str::<MoneyCents>("\"1.23\"")
                .unwrap()
                .cents(),
            123
        );
    }

    #[test]
    fn proof_money_bound_rejects_max_plus_one_without_rounding() {
        let mut c = ctx();
        c.service_lines[0].charge_amount = MoneyCents::from_cents(MAX_CENTS_EXCLUSIVE);
        c.total_charge = MoneyCents::from_cents(MAX_CENTS_EXCLUSIVE);
        let error = adjudicate_for_proof(
            &c,
            &[ProofFeeRow {
                procedure_code: "99213".into(),
                policy_present: true,
                allowed_cents: 12_500,
                requires_prior_authorization: false,
            }],
        )
        .unwrap_err();
        assert_eq!(error, "proof_money_out_of_range");
    }

    #[test]
    fn g9_passes_when_not_duplicate() {
        assert_gate_passes(ctx(), "G9_NOT_DUPLICATE");
    }

    #[test]
    fn g9_fails_when_duplicate_claim_flag_set() {
        let mut c = ctx();
        c.flags.duplicate_claim = true;
        assert_gate_fails(c, "G9_NOT_DUPLICATE", "duplicate_claim");
    }

    #[test]
    fn g10_passes_when_no_program_integrity_hold() {
        assert_gate_passes(ctx(), "G10_NO_PROGRAM_INTEGRITY_HOLD");
    }

    #[test]
    fn g10_fails_when_program_integrity_hold_set() {
        let mut c = ctx();
        c.flags.program_integrity_hold = true;
        assert_gate_fails(c, "G10_NO_PROGRAM_INTEGRITY_HOLD", "program_integrity_hold");
    }

    #[test]
    fn multi_gate_failure_uses_first_failed_gate_for_codes() {
        let mut c = ctx();
        c.member_id.clear();
        c.flags.eligibility_active = false;
        c.provider.npi.clear();
        let result = adjudicate(&c);
        let (carc, rarc) = mapping_for("member_id_missing");
        assert!(!result.approved);
        assert_eq!(result.denial_reason, "member_id_missing");
        assert_eq!(result.carc, carc);
        assert_eq!(result.rarc, rarc);
        assert!(!gate(&result, "G1_MEMBER_ID_PRESENT").passed);
        assert!(!gate(&result, "G2_ELIGIBILITY_ACTIVE").passed);
        assert!(!gate(&result, "G3_PROVIDER_NPI_PRESENT").passed);
    }

    #[test]
    fn proof_adjudicator_matches_approved_integer_semantics() {
        let mut c = ctx();
        c.service_lines[0].procedure_code = "T1019".into();
        let result = adjudicate_for_proof(
            &c,
            &[ProofFeeRow {
                procedure_code: "T1019".into(),
                policy_present: true,
                allowed_cents: 12_500,
                requires_prior_authorization: true,
            }],
        )
        .unwrap();
        assert!(result.approved);
        assert_eq!(result.failure_code, 0);
        assert_eq!(result.allowed_amount_cents, 12_500);
        assert_eq!(result.payment_amount_cents, 12_500);
    }

    #[test]
    fn proof_adjudicator_preserves_first_failure_order() {
        let mut c = ctx();
        c.flags.eligibility_active = false;
        c.flags.provider_not_suspended = false;
        let result = adjudicate_for_proof(
            &c,
            &[ProofFeeRow {
                procedure_code: "99213".into(),
                policy_present: true,
                allowed_cents: 12_500,
                requires_prior_authorization: false,
            }],
        )
        .unwrap();
        assert!(!result.approved);
        assert_eq!(result.failure_code, 2);
        assert_eq!(result.denial_reason, "eligibility_inactive");
        assert_eq!(result.payment_amount_cents, 0);
    }

    #[test]
    fn proof_adjudicator_denies_unverified_prior_auth_at_gate_9() {
        let mut c = ctx();
        c.service_lines[0].procedure_code = "T1019".into();
        c.service_lines[0].prior_authorization = Some("PA-UNVERIFIED".into());
        c.tar_authorization_verified = false;
        let result = adjudicate_for_proof(
            &c,
            &[ProofFeeRow {
                procedure_code: "T1019".into(),
                policy_present: true,
                allowed_cents: 12_500,
                requires_prior_authorization: true,
            }],
        )
        .unwrap();
        assert!(!result.approved);
        assert_eq!(result.failure_code, 9);
        assert_eq!(result.denial_reason, "prior_authorization_required");
        assert_eq!(result.payment_amount_cents, 0);
    }

    #[test]
    fn proof_adjudicator_rejects_unauthenticated_fee_gaps() {
        let error = adjudicate_for_proof(
            &ctx(),
            &[ProofFeeRow {
                procedure_code: "T1019".into(),
                policy_present: true,
                allowed_cents: 12_500,
                requires_prior_authorization: true,
            }],
        )
        .unwrap_err();
        assert_eq!(error, "proof_fee_row_missing:99213");
    }

    #[test]
    fn proof_adjudicator_accepts_authenticated_fee_absence_as_denial_11() {
        let result = adjudicate_for_proof(
            &ctx(),
            &[ProofFeeRow {
                procedure_code: "99213".into(),
                policy_present: false,
                allowed_cents: 0,
                requires_prior_authorization: false,
            }],
        )
        .unwrap();
        assert!(!result.approved);
        assert_eq!(result.failure_code, 11);
        assert_eq!(result.denial_reason, "fee_schedule_missing");
        assert_eq!(result.allowed_amount_cents, 0);
        assert_eq!(result.payment_amount_cents, 0);
    }

    #[test]
    fn proof_adjudicator_rejects_nonzero_authenticated_absence_payload() {
        let error = adjudicate_for_proof(
            &ctx(),
            &[ProofFeeRow {
                procedure_code: "99213".into(),
                policy_present: false,
                allowed_cents: 1,
                requires_prior_authorization: false,
            }],
        )
        .unwrap_err();
        assert_eq!(error, "proof_fee_absence_payload_nonzero");
    }

    #[test]
    fn proof_denial_codes_keep_fee_duplicate_and_integrity_order() {
        assert_eq!(proof_denial_reason(11), "fee_schedule_missing");
        assert_eq!(proof_denial_reason(12), "duplicate_claim");
        assert_eq!(proof_denial_reason(13), "program_integrity_hold");
    }

    #[test]
    fn proof_adjudicator_rejects_total_mismatch_before_denial_gates() {
        let mut c = ctx();
        c.total_charge = MoneyCents::from_cents(12_501);
        c.flags.duplicate_claim = true;
        let error = adjudicate_for_proof(
            &c,
            &[ProofFeeRow {
                procedure_code: "99213".into(),
                policy_present: true,
                allowed_cents: 12_500,
                requires_prior_authorization: false,
            }],
        )
        .unwrap_err();
        assert_eq!(error, "claim_total_mismatch");
    }

    #[test]
    fn proof_adjudicator_uses_shifted_duplicate_and_integrity_codes() {
        let fee_rows = [ProofFeeRow {
            procedure_code: "99213".into(),
            policy_present: true,
            allowed_cents: 12_500,
            requires_prior_authorization: false,
        }];

        let mut duplicate = ctx();
        duplicate.flags.duplicate_claim = true;
        duplicate.flags.program_integrity_hold = true;
        let duplicate_result = adjudicate_for_proof(&duplicate, &fee_rows).unwrap();
        assert_eq!(duplicate_result.failure_code, 12);
        assert_eq!(duplicate_result.denial_reason, "duplicate_claim");

        let mut integrity = ctx();
        integrity.flags.program_integrity_hold = true;
        let integrity_result = adjudicate_for_proof(&integrity, &fee_rows).unwrap();
        assert_eq!(integrity_result.failure_code, 13);
        assert_eq!(integrity_result.denial_reason, "program_integrity_hold");
    }

    #[test]
    fn ordinary_adjudicator_uses_the_supplied_governed_fee_schedule() {
        let tar_required_codes = default_tar_required_codes();
        let empty_schedule = BTreeMap::new();
        let denied = adjudicate_with_policy(&ctx(), &tar_required_codes, &empty_schedule);
        assert!(!denied.approved);
        assert_eq!(denied.denial_reason, "fee_schedule_missing");
        assert_eq!(denied.payable_amount_cents, 0);

        let mut absent_tar_ctx = ctx();
        absent_tar_ctx.service_lines[0].procedure_code = "T1019".into();
        absent_tar_ctx.service_lines[0].prior_authorization = None;
        let absent_tar =
            adjudicate_with_policy(&absent_tar_ctx, &tar_required_codes, &empty_schedule);
        assert_eq!(absent_tar.denial_reason, "fee_schedule_missing");
        assert!(absent_tar.gates[8].passed);
        assert!(!absent_tar.gates[10].passed);

        let mut custom_ctx = ctx();
        custom_ctx.service_lines[0].procedure_code = "ZZ999".into();
        let custom_schedule = BTreeMap::from([("ZZ999".to_string(), 5_000)]);
        let approved = adjudicate_with_policy(&custom_ctx, &tar_required_codes, &custom_schedule);
        assert!(approved.approved);
        assert_eq!(approved.payable_amount_cents, 5_000);

        let invalid_schedule = BTreeMap::from([("99213".to_string(), -1)]);
        let invalid = adjudicate_with_policy(&ctx(), &tar_required_codes, &invalid_schedule);
        assert!(!invalid.approved);
        assert_eq!(invalid.denial_reason, "fee_schedule_missing");
    }

    #[test]
    fn shared_mapping_has_expected_gate_count() {
        let rows = CODE_MAPPING_TSV
            .lines()
            .skip(1)
            .filter(|line| !line.trim().is_empty())
            .count();
        assert_eq!(rows, 12);
    }
}
