use serde::{Deserialize, Serialize};

use blind_ledger_rules_engine::{
    adjudicate, Flags, Patient, Provider, ServiceLine, SharedContext,
};

pub const PUBLIC_VALUES_LEN: usize = 128;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct ClaimInput {
    pub raw_claim_identity_commitment: [u8; 32],
    pub batch_context_commitment: [u8; 32],
    pub member_id_present: bool,
    pub eligibility_active: bool,
    pub provider_npi_present: bool,
    pub provider_enrolled: bool,
    pub service_line_present: bool,
    pub diagnosis_present: bool,
    pub prior_auth_ok: bool,
    pub charge_cents: u32,
    pub max_charge_cents: u32,
    pub duplicate_claim: bool,
    pub program_integrity_hold: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicValues {
    pub raw_claim_identity_commitment: [u8; 32],
    pub batch_context_commitment: [u8; 32],
    pub decision: u32,
    pub failure_code: u32,
}

pub fn first_failed_gate(gates: &[bool; 11]) -> u32 {
    gates
        .iter()
        .position(|passed| !*passed)
        .map(|idx| (idx + 1) as u32)
        .unwrap_or(0)
}

pub fn expected_gates(input: &ClaimInput) -> [bool; 11] {
    let result = adjudicate(&shared_context_from_input(input));
    let mut gates = [false; 11];
    for (idx, gate) in result.gates.iter().take(11).enumerate() {
        gates[idx] = gate.passed;
    }
    gates
}

pub fn expected_public_values(input: &ClaimInput) -> (u32, u32) {
    let result = adjudicate(&shared_context_from_input(input));
    let decision = result.approved as u32;
    let failure_code = result
        .gates
        .iter()
        .position(|gate| !gate.passed)
        .map(|idx| (idx + 1) as u32)
        .unwrap_or(0);
    (decision, failure_code)
}

pub fn expected_bound_public_values(input: &ClaimInput) -> PublicValues {
    let (decision, failure_code) = expected_public_values(input);
    PublicValues {
        raw_claim_identity_commitment: input.raw_claim_identity_commitment,
        batch_context_commitment: input.batch_context_commitment,
        decision,
        failure_code,
    }
}

pub fn shared_context_from_input(input: &ClaimInput) -> SharedContext {
    let service_lines = if input.service_line_present {
        vec![ServiceLine {
            line_id: "1".to_string(),
            procedure_code: if input.prior_auth_ok {
                "99213".to_string()
            } else {
                "T1019".to_string()
            },
            charge_amount: input.charge_cents as f64 / 100.0,
            units: 1.0,
            prior_authorization: input.prior_auth_ok.then(|| "PA-OK".to_string()),
        }]
    } else {
        Vec::new()
    };
    SharedContext {
        claim_id: "SP1-CLAIM".to_string(),
        transaction_set: "837".to_string(),
        payer_id: "PAYER".to_string(),
        member_id: if input.member_id_present {
            "M123456789".to_string()
        } else {
            String::new()
        },
        patient: Patient {
            name: "Jane Doe".to_string(),
            id: if input.member_id_present {
                "M123456789".to_string()
            } else {
                String::new()
            },
        },
        provider: Provider {
            npi: if input.provider_npi_present {
                "1999999987".to_string()
            } else {
                String::new()
            },
            name: "Alice Adams".to_string(),
        },
        service_date: "20260601".to_string(),
        diagnoses: if input.diagnosis_present {
            vec!["F840".to_string()]
        } else {
            Vec::new()
        },
        service_lines,
        total_charge: input.charge_cents as f64 / 100.0,
        flags: Flags {
            eligibility_active: input.eligibility_active,
            provider_enrolled: input.provider_enrolled,
            duplicate_claim: input.duplicate_claim,
            program_integrity_hold: input.program_integrity_hold,
        },
    }
}

pub fn abi_encode_public_values(
    raw_claim_identity_commitment: [u8; 32],
    batch_context_commitment: [u8; 32],
    decision: u32,
    failure_code: u32,
) -> [u8; PUBLIC_VALUES_LEN] {
    let mut bytes = [0u8; PUBLIC_VALUES_LEN];
    bytes[0..32].copy_from_slice(&raw_claim_identity_commitment);
    bytes[32..64].copy_from_slice(&batch_context_commitment);
    bytes[92..96].copy_from_slice(&decision.to_be_bytes());
    bytes[124..128].copy_from_slice(&failure_code.to_be_bytes());
    bytes
}

pub fn abi_decode_public_values(bytes: &[u8]) -> Option<PublicValues> {
    if bytes.len() != PUBLIC_VALUES_LEN {
        return None;
    }
    let mut raw_claim_identity_commitment = [0u8; 32];
    raw_claim_identity_commitment.copy_from_slice(&bytes[0..32]);
    let mut batch_context_commitment = [0u8; 32];
    batch_context_commitment.copy_from_slice(&bytes[32..64]);
    let decision = u32::from_be_bytes(bytes[92..96].try_into().ok()?);
    let failure_code = u32::from_be_bytes(bytes[124..128].try_into().ok()?);
    if !valid_decision_failure(decision, failure_code) {
        return None;
    }
    Some(PublicValues {
        raw_claim_identity_commitment,
        batch_context_commitment,
        decision,
        failure_code,
    })
}

pub fn public_values_match_claim(bytes: &[u8], expected_claim_identity: [u8; 32]) -> bool {
    abi_decode_public_values(bytes)
        .map(|values| values.raw_claim_identity_commitment == expected_claim_identity)
        .unwrap_or(false)
}

pub fn public_values_match_context(
    bytes: &[u8],
    expected_claim_identity: [u8; 32],
    expected_batch_context: [u8; 32],
) -> bool {
    abi_decode_public_values(bytes)
        .map(|values| {
            values.raw_claim_identity_commitment == expected_claim_identity
                && values.batch_context_commitment == expected_batch_context
        })
        .unwrap_or(false)
}

fn valid_decision_failure(decision: u32, failure_code: u32) -> bool {
    match decision {
        0 => (1..=11).contains(&failure_code),
        1 => failure_code == 0,
        _ => false,
    }
}
