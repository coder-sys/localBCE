use blind_ledger_stark::{approved_claim, prove_claim, sample_claims, ClaimInput, Felt};
use serde::Serialize;
use winterfell::math::FieldElement;

#[derive(Serialize)]
struct ArityCheck {
    arity: usize,
    app_hash: String,
    air_formula_hash: String,
    matched: bool,
}

#[derive(Serialize)]
struct CaseCheck {
    case: String,
    stark_public_commitment: String,
    app_hash: String,
    matched: bool,
}

#[derive(Serialize)]
struct HashConsistencyReport {
    claim_commitment_hash: &'static str,
    proof_merkle_hasher: &'static str,
    note: &'static str,
    arity_checks: Vec<ArityCheck>,
    case_checks: Vec<CaseCheck>,
}

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

fn rolling_hash(values: &[u32]) -> Felt {
    let mut state = Felt::from(17u32);
    for (idx, value) in values.iter().copied().enumerate() {
        state = (state + Felt::from(value) + Felt::from(101u32 + idx as u32)).cube();
    }
    state
}

fn air_formula_hash(values: &[u32]) -> Felt {
    let mut expected_trace_state = Felt::from(17u32);
    for (idx, value) in values.iter().copied().enumerate() {
        let constant = Felt::from(101u32 + idx as u32);
        expected_trace_state = (expected_trace_state + Felt::from(value) + constant).cube();
    }
    expected_trace_state
}

fn main() -> anyhow::Result<()> {
    let values = claim_values(approved_claim());
    let arity_checks = [1usize, 2, 4, 11]
        .into_iter()
        .map(|arity| {
            let app_hash = rolling_hash(&values[..arity]);
            let air_hash = air_formula_hash(&values[..arity]);
            ArityCheck {
                arity,
                app_hash: app_hash.to_string(),
                air_formula_hash: air_hash.to_string(),
                matched: app_hash == air_hash,
            }
        })
        .collect();

    let mut case_checks = Vec::new();
    for (case, claim) in sample_claims() {
        let (_proof, public_inputs, _output, _duration) = prove_claim(claim)?;
        let app_hash = rolling_hash(&claim_values(claim));
        case_checks.push(CaseCheck {
            case: case.to_string(),
            stark_public_commitment: public_inputs.commitment.to_string(),
            app_hash: app_hash.to_string(),
            matched: public_inputs.commitment == app_hash,
        });
    }

    let report = HashConsistencyReport {
        claim_commitment_hash:
            "Winterfell f128 BaseElement algebraic rolling cube over normalized u32 claim fields",
        proof_merkle_hasher: "Winterfell Blake3_256 for FRI/Merkle commitments",
        note: "This proves local Winterfell-stack parity only. Production target remains a reviewed STARK-native hash such as Poseidon2 over the chosen STARK field.",
        arity_checks,
        case_checks,
    };

    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
