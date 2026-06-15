use serde::{Deserialize, Serialize};

const CODE_MAPPING_TSV: &str = include_str!("../../rarc_mapping.tsv");

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
    pub charge_amount: f64,
    pub units: f64,
    pub prior_authorization: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Flags {
    pub eligibility_active: bool,
    pub provider_enrolled: bool,
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
    pub total_charge: f64,
    pub flags: Flags,
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
    pub payable_amount: f64,
}

fn gate(name: &str, passed: bool, reason: &str) -> GateResult {
    GateResult { gate: name.to_string(), passed, reason: if passed { "".into() } else { reason.into() } }
}

pub fn evaluate_gates(ctx: &SharedContext) -> Vec<GateResult> {
    let pa_required = ["T1019", "S5102", "H2015"];
    let pa_ok = ctx.service_lines.iter().all(|line| {
        !pa_required.contains(&line.procedure_code.as_str()) || line.prior_authorization.as_ref().map(|s| !s.is_empty()).unwrap_or(false)
    });
    let charge_valid = ctx.total_charge > 0.0 && ctx.service_lines.iter().all(|line| line.charge_amount > 0.0);
    let charge_within_allowable = ctx.service_lines.iter().all(|line| line.charge_amount <= 5000.0);
    vec![
        gate("G1_MEMBER_ID_PRESENT", !ctx.member_id.is_empty(), "member_id_missing"),
        gate("G2_ELIGIBILITY_ACTIVE", ctx.flags.eligibility_active, "eligibility_inactive"),
        gate("G3_PROVIDER_NPI_PRESENT", !ctx.provider.npi.is_empty(), "provider_npi_missing"),
        gate("G4_PROVIDER_ENROLLED", ctx.flags.provider_enrolled, "provider_not_enrolled"),
        gate("G5_SERVICE_LINES_PRESENT", !ctx.service_lines.is_empty(), "service_line_missing"),
        gate("G6_DIAGNOSIS_PRESENT", !ctx.diagnoses.is_empty(), "diagnosis_missing"),
        gate("G7_PRIOR_AUTH_WHEN_REQUIRED", pa_ok, "prior_authorization_required"),
        gate("G8A_CHARGE_VALID", charge_valid, "invalid_charge"),
        gate("G8B_CHARGE_WITHIN_ALLOWABLE", charge_within_allowable, "excessive_charge"),
        gate("G9_NOT_DUPLICATE", !ctx.flags.duplicate_claim, "duplicate_claim"),
        gate("G10_NO_PROGRAM_INTEGRITY_HOLD", !ctx.flags.program_integrity_hold, "program_integrity_hold"),
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
    let gates = evaluate_gates(ctx);
    let failed = gates.iter().find(|g| !g.passed);
    let approved = failed.is_none();
    let reason = failed.map(|g| g.reason.clone()).unwrap_or_default();
    let (carc, rarc) = if approved { ("", "") } else { codes(&reason) };
    AdjudicationResult {
        claim_id: ctx.claim_id.clone(),
        approved,
        denial_reason: reason,
        gates,
        carc: carc.into(),
        rarc: rarc.into(),
        total_charge: ctx.total_charge,
        payable_amount: if approved { ctx.total_charge } else { 0.0 },
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
            patient: Patient { name: "Jane Doe".into(), id: "M1".into() },
            provider: Provider { npi: "1999999987".into(), name: "Alice Adams".into() },
            service_date: "20260601".into(),
            diagnoses: vec!["F840".into()],
            service_lines: vec![ServiceLine {
                line_id: "1".into(),
                procedure_code: "99213".into(),
                charge_amount: 125.0,
                units: 1.0,
                prior_authorization: Some("PA-OK".into()),
            }],
            total_charge: 125.0,
            flags: Flags {
                eligibility_active: true,
                provider_enrolled: true,
                duplicate_claim: false,
                program_integrity_hold: false,
            },
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
        result.gates.iter().find(|g| g.gate == gate_name).expect("gate missing")
    }

    fn assert_gate_passes(ctx: SharedContext, gate_name: &str) {
        let result = adjudicate(&ctx);
        let gate = gate(&result, gate_name);
        assert!(gate.passed, "{gate_name} should pass");
        assert_eq!(gate.reason, "", "passing gates should not carry failure reasons");
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
    fn g5_passes_when_service_line_present() {
        assert_gate_passes(ctx(), "G5_SERVICE_LINES_PRESENT");
    }

    #[test]
    fn g5_fails_when_service_lines_empty() {
        let mut c = ctx();
        c.service_lines.clear();
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
        assert_gate_fails(c, "G7_PRIOR_AUTH_WHEN_REQUIRED", "prior_authorization_required");
    }

    #[test]
    fn g8_passes_when_charge_at_threshold() {
        let mut c = ctx();
        c.service_lines[0].charge_amount = 5000.0;
        c.total_charge = 5000.0;
        assert_gate_passes(c.clone(), "G8A_CHARGE_VALID");
        assert_gate_passes(c, "G8B_CHARGE_WITHIN_ALLOWABLE");
    }

    #[test]
    fn g8_fails_when_charge_above_threshold() {
        let mut c = ctx();
        c.service_lines[0].charge_amount = 5000.01;
        c.total_charge = 5000.01;
        assert_gate_fails(c, "G8B_CHARGE_WITHIN_ALLOWABLE", "excessive_charge");
    }

    #[test]
    fn g8_fails_when_total_charge_zero() {
        let mut c = ctx();
        c.total_charge = 0.0;
        assert_gate_fails(c, "G8A_CHARGE_VALID", "invalid_charge");
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
    fn shared_mapping_has_expected_gate_count() {
        let rows = CODE_MAPPING_TSV.lines().skip(1).filter(|line| !line.trim().is_empty()).count();
        assert_eq!(rows, 11);
    }
}
