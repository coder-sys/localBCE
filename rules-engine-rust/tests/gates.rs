use blind_ledger_rules_engine::{
    adjudicate, adjudicate_for_proof, evaluate_gates, Flags, MoneyCents, Patient, ProofFeeRow,
    Provider, ServiceLine, SharedContext,
};

fn ctx() -> SharedContext {
    SharedContext {
        claim_id: "C1".into(),
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
            prior_authorization: Some("PA".into()),
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

#[test]
fn approves_clean_claim() {
    let result = adjudicate(&ctx());
    assert!(result.approved);
    assert_eq!(result.payable_amount_cents, 12_500);
}

#[test]
fn g2_denies_inactive_eligibility() {
    let mut c = ctx();
    c.flags.eligibility_active = false;
    let result = adjudicate(&c);
    assert_eq!(result.denial_reason, "eligibility_inactive");
}

#[test]
fn g2b_denies_deceased_patient() {
    let mut c = ctx();
    c.flags.not_deceased = false;
    let result = adjudicate(&c);
    assert_eq!(result.denial_reason, "patient_deceased");
}

#[test]
fn g4b_denies_suspended_provider() {
    let mut c = ctx();
    c.flags.provider_not_suspended = false;
    let result = adjudicate(&c);
    assert_eq!(result.denial_reason, "provider_suspended");
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

#[test]
fn denial_gate_order_keeps_fee_duplicate_and_integrity_at_11_to_13() {
    let gates = evaluate_gates(&ctx());
    assert_eq!(gates.len(), 13);
    assert_eq!(gates[10].gate, "G8B_FEE_SCHEDULE_PRESENT");
    assert_eq!(gates[11].gate, "G9_NOT_DUPLICATE");
    assert_eq!(gates[12].gate, "G10_NO_PROGRAM_INTEGRITY_HOLD");
}

#[test]
fn proof_total_mismatch_is_structural_not_a_denial_code() {
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
fn unknown_procedure_denies_instead_of_approving_zero_payable() {
    let mut c = ctx();
    c.service_lines[0].procedure_code = "ZZZ999".into();
    let result = adjudicate(&c);
    assert!(!result.approved);
    assert_eq!(result.denial_reason, "fee_schedule_missing");
    assert_eq!(result.payable_amount_cents, 0);
    assert!(result.gates.iter().any(|gate| {
        gate.gate == "G8B_FEE_SCHEDULE_PRESENT"
            && !gate.passed
            && gate.reason == "fee_schedule_missing"
    }));
}
