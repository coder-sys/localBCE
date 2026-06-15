use blind_ledger_rules_engine::{adjudicate, Flags, Patient, Provider, ServiceLine, SharedContext};

fn ctx() -> SharedContext {
    SharedContext {
        claim_id: "C1".into(),
        transaction_set: "837".into(),
        payer_id: "PAYER".into(),
        member_id: "M1".into(),
        patient: Patient { name: "Jane Doe".into(), id: "M1".into() },
        provider: Provider { npi: "1999999987".into(), name: "Alice Adams".into() },
        service_date: "20260601".into(),
        diagnoses: vec!["F840".into()],
        service_lines: vec![ServiceLine { line_id: "1".into(), procedure_code: "99213".into(), charge_amount: 125.0, units: 1.0, prior_authorization: Some("PA".into()) }],
        total_charge: 125.0,
        flags: Flags { eligibility_active: true, provider_enrolled: true, duplicate_claim: false, program_integrity_hold: false },
    }
}

#[test]
fn approves_clean_claim() {
    assert!(adjudicate(&ctx()).approved);
}

#[test]
fn g2_denies_inactive_eligibility() {
    let mut c = ctx();
    c.flags.eligibility_active = false;
    let result = adjudicate(&c);
    assert_eq!(result.denial_reason, "eligibility_inactive");
}

#[test]
fn g7_requires_prior_auth() {
    let mut c = ctx();
    c.service_lines[0].procedure_code = "T1019".into();
    c.service_lines[0].prior_authorization = None;
    let result = adjudicate(&c);
    assert_eq!(result.denial_reason, "prior_authorization_required");
}

#[test]
fn g10_program_integrity_hold() {
    let mut c = ctx();
    c.flags.program_integrity_hold = true;
    let result = adjudicate(&c);
    assert_eq!(result.denial_reason, "program_integrity_hold");
}

