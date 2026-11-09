use std::time::{Duration, Instant};

use serde::Serialize;
use winterfell::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree},
    math::{fields::f128::BaseElement, FieldElement, ToElements},
    matrix::ColMatrix,
    AcceptableOptions, Air, AirContext, Assertion, AuxRandElements, BatchingMethod,
    CompositionPoly, CompositionPolyTrace, DefaultConstraintCommitment,
    DefaultConstraintEvaluator, DefaultTraceLde, EvaluationFrame, FieldExtension,
    PartitionOptions, Proof, ProofOptions, Prover, StarkDomain, TraceInfo, TracePolyTable,
    TraceTable, TransitionConstraintDegree,
};

pub type Felt = BaseElement;

const TRACE_LENGTH: usize = 16;

const COL_MEMBER_ID: usize = 0;
const COL_PROVIDER_NPI: usize = 1;
const COL_ELIGIBILITY_ACTIVE: usize = 2;
const COL_PROVIDER_ENROLLED: usize = 3;
const COL_SERVICE_LINE_COUNT: usize = 4;
const COL_DIAGNOSIS_COUNT: usize = 5;
const COL_PRIOR_AUTH_OK: usize = 6;
const COL_CHARGE_CENTS: usize = 7;
const COL_MAX_CHARGE_CENTS: usize = 8;
const COL_DUPLICATE_FLAG: usize = 9;
const COL_PROGRAM_INTEGRITY_HOLD: usize = 10;

const GATE_START: usize = 11;
const COL_DECISION: usize = 21;
const COL_FAILURE_CODE: usize = 22;
const COL_COMMITMENT: usize = 23;

const COL_INV_MEMBER_ID: usize = 24;
const COL_INV_PROVIDER_NPI: usize = 25;
const COL_INV_SERVICE_LINE_COUNT: usize = 26;
const COL_INV_DIAGNOSIS_COUNT: usize = 27;
const COL_INV_CHARGE_CENTS: usize = 28;
const COL_CHARGE_POSITIVE: usize = 29;
const COL_LE_MAX_CHARGE: usize = 30;
const COL_LE_DIFF: usize = 31;
const COL_GT_DIFF: usize = 32;

const CHARGE_BITS_START: usize = 33;
const MAX_BITS_START: usize = 65;
const LE_DIFF_BITS_START: usize = 97;
const GT_DIFF_BITS_START: usize = 129;
const HASH_START: usize = 161;
const HASH_STATES: usize = 11;
const TRACE_WIDTH: usize = HASH_START + HASH_STATES;

const INPUT_COLUMNS: [usize; 11] = [
    COL_MEMBER_ID,
    COL_PROVIDER_NPI,
    COL_ELIGIBILITY_ACTIVE,
    COL_PROVIDER_ENROLLED,
    COL_SERVICE_LINE_COUNT,
    COL_DIAGNOSIS_COUNT,
    COL_PRIOR_AUTH_OK,
    COL_CHARGE_CENTS,
    COL_MAX_CHARGE_CENTS,
    COL_DUPLICATE_FLAG,
    COL_PROGRAM_INTEGRITY_HOLD,
];

const BOOLEAN_COLUMNS: [usize; 19] = [
    COL_ELIGIBILITY_ACTIVE,
    COL_PROVIDER_ENROLLED,
    COL_PRIOR_AUTH_OK,
    COL_DUPLICATE_FLAG,
    COL_PROGRAM_INTEGRITY_HOLD,
    GATE_START,
    GATE_START + 1,
    GATE_START + 2,
    GATE_START + 3,
    GATE_START + 4,
    GATE_START + 5,
    GATE_START + 6,
    GATE_START + 7,
    GATE_START + 8,
    GATE_START + 9,
    COL_DECISION,
    COL_CHARGE_POSITIVE,
    COL_LE_MAX_CHARGE,
    GATE_START + 9,
];

#[derive(Clone, Copy, Debug, Serialize)]
pub struct ClaimInput {
    pub member_id: u32,
    pub provider_npi: u32,
    pub eligibility_active: u32,
    pub provider_enrolled: u32,
    pub service_line_count: u32,
    pub diagnosis_count: u32,
    pub prior_auth_ok: u32,
    pub charge_cents: u32,
    pub max_charge_cents: u32,
    pub duplicate_flag: u32,
    pub program_integrity_hold: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct ClaimPublicInputs {
    pub commitment: Felt,
    pub decision: Felt,
    pub failure_code: Felt,
}

impl ToElements<Felt> for ClaimPublicInputs {
    fn to_elements(&self) -> Vec<Felt> {
        vec![self.commitment, self.decision, self.failure_code]
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ClaimOutput {
    pub commitment: String,
    pub decision: u32,
    pub failure_code: u32,
    pub gates: [u32; 10],
}

#[derive(Clone, Debug, Serialize)]
pub struct ProofRun {
    pub case: String,
    pub decision: u32,
    pub failure_code: u32,
    pub gates: [u32; 10],
    pub proof_size_bytes: usize,
    pub prove_ms: u128,
    pub prove_us: u128,
    pub verify_ms: u128,
    pub verify_us: u128,
    pub verified: bool,
    pub proof_path: String,
    pub public_inputs_path: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct TamperRun {
    pub original_case: String,
    pub tamper: String,
    pub rejected: bool,
}

pub struct ClaimAir {
    context: AirContext<Felt>,
    pub_inputs: ClaimPublicInputs,
}

impl Air for ClaimAir {
    type BaseField = Felt;
    type PublicInputs = ClaimPublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: ClaimPublicInputs, options: ProofOptions) -> Self {
        assert_eq!(TRACE_WIDTH, trace_info.width());
        let degrees = transition_degrees();
        let num_assertions = 3;
        Self {
            context: AirContext::new(trace_info, degrees, num_assertions, options),
            pub_inputs,
        }
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let one = E::ONE;
        let zero = E::ZERO;
        let mut i = 0;

        for &col in BOOLEAN_COLUMNS.iter() {
            result[i] = current[col] * (current[col] - one);
            i += 1;
        }
        for start in [
            CHARGE_BITS_START,
            MAX_BITS_START,
            LE_DIFF_BITS_START,
            GT_DIFF_BITS_START,
        ] {
            for bit in 0..32 {
                let value = current[start + bit];
                result[i] = value * (value - one);
                i += 1;
            }
        }

        i = constrain_nonzero_gate(
            current,
            result,
            i,
            COL_MEMBER_ID,
            COL_INV_MEMBER_ID,
            gate_col(1),
        );
        i = constrain_nonzero_gate(
            current,
            result,
            i,
            COL_PROVIDER_NPI,
            COL_INV_PROVIDER_NPI,
            gate_col(3),
        );
        i = constrain_nonzero_gate(
            current,
            result,
            i,
            COL_SERVICE_LINE_COUNT,
            COL_INV_SERVICE_LINE_COUNT,
            gate_col(5),
        );
        i = constrain_nonzero_gate(
            current,
            result,
            i,
            COL_DIAGNOSIS_COUNT,
            COL_INV_DIAGNOSIS_COUNT,
            gate_col(6),
        );
        i = constrain_nonzero_gate(
            current,
            result,
            i,
            COL_CHARGE_CENTS,
            COL_INV_CHARGE_CENTS,
            COL_CHARGE_POSITIVE,
        );

        result[i] = current[gate_col(2)] - current[COL_ELIGIBILITY_ACTIVE];
        i += 1;
        result[i] = current[gate_col(4)] - current[COL_PROVIDER_ENROLLED];
        i += 1;
        result[i] = current[gate_col(7)] - current[COL_PRIOR_AUTH_OK];
        i += 1;
        result[i] = current[gate_col(9)] - (one - current[COL_DUPLICATE_FLAG]);
        i += 1;
        result[i] = current[gate_col(10)] - (one - current[COL_PROGRAM_INTEGRITY_HOLD]);
        i += 1;

        result[i] = current[COL_CHARGE_CENTS] - bits_to_value(current, CHARGE_BITS_START);
        i += 1;
        result[i] = current[COL_MAX_CHARGE_CENTS] - bits_to_value(current, MAX_BITS_START);
        i += 1;
        result[i] = current[COL_LE_DIFF] - bits_to_value(current, LE_DIFF_BITS_START);
        i += 1;
        result[i] = current[COL_GT_DIFF] - bits_to_value(current, GT_DIFF_BITS_START);
        i += 1;

        let le = current[COL_LE_MAX_CHARGE];
        result[i] =
            le * (current[COL_MAX_CHARGE_CENTS] - current[COL_CHARGE_CENTS] - current[COL_LE_DIFF]);
        i += 1;
        result[i] = (one - le)
            * (current[COL_CHARGE_CENTS]
                - current[COL_MAX_CHARGE_CENTS]
                - one
                - current[COL_GT_DIFF]);
        i += 1;

        result[i] = current[gate_col(8)] - (current[COL_CHARGE_POSITIVE] * le);
        i += 1;

        let mut decision = one;
        let mut failure_code = zero;
        let mut prefix = one;
        for gate_idx in 0..10 {
            let gate = current[gate_col(gate_idx + 1)];
            decision *= gate;
            failure_code += E::from((gate_idx + 1) as u32) * (one - gate) * prefix;
            prefix *= gate;
        }
        result[i] = current[COL_DECISION] - decision;
        i += 1;
        result[i] = current[COL_FAILURE_CODE] - failure_code;
        i += 1;

        let mut hash_state = E::from(17u32);
        for (hash_idx, &input_col) in INPUT_COLUMNS.iter().enumerate() {
            let constant = E::from(101u32 + hash_idx as u32);
            let expected = (hash_state + current[input_col] + constant).cube();
            result[i] = current[HASH_START + hash_idx] - expected;
            hash_state = current[HASH_START + hash_idx];
            i += 1;
        }
        result[i] = current[COL_COMMITMENT] - current[HASH_START + HASH_STATES - 1];
        i += 1;

        debug_assert_eq!(i, result.len());
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        vec![
            Assertion::single(COL_COMMITMENT, 0, self.pub_inputs.commitment),
            Assertion::single(COL_DECISION, 0, self.pub_inputs.decision),
            Assertion::single(COL_FAILURE_CODE, 0, self.pub_inputs.failure_code),
        ]
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}

pub struct ClaimProver {
    options: ProofOptions,
}

impl ClaimProver {
    pub fn new(options: ProofOptions) -> Self {
        Self { options }
    }
}

impl Prover for ClaimProver {
    type BaseField = Felt;
    type Air = ClaimAir;
    type Trace = TraceTable<Self::BaseField>;
    type HashFn = Blake3_256<Self::BaseField>;
    type VC = MerkleTree<Self::HashFn>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> ClaimPublicInputs {
        ClaimPublicInputs {
            commitment: trace.get(COL_COMMITMENT, 0),
            decision: trace.get(COL_DECISION, 0),
            failure_code: trace.get(COL_FAILURE_CODE, 0),
        }
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_options)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
        )
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: winterfell::ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}

pub fn default_options() -> ProofOptions {
    ProofOptions::new(
        32,
        16,
        0,
        FieldExtension::None,
        8,
        31,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

pub fn acceptable_options() -> AcceptableOptions {
    AcceptableOptions::MinConjecturedSecurity(80)
}

pub fn sample_claims() -> Vec<(&'static str, ClaimInput)> {
    vec![
        ("approved", approved_claim()),
        (
            "ineligible_denied",
            ClaimInput {
                eligibility_active: 0,
                ..approved_claim()
            },
        ),
        (
            "duplicate_denied",
            ClaimInput {
                duplicate_flag: 1,
                ..approved_claim()
            },
        ),
        (
            "excessive_charge_denied",
            ClaimInput {
                charge_cents: 700_000,
                max_charge_cents: 500_000,
                ..approved_claim()
            },
        ),
    ]
}

pub fn approved_claim() -> ClaimInput {
    ClaimInput {
        member_id: 123_456_789,
        provider_npi: 1_999_999_987,
        eligibility_active: 1,
        provider_enrolled: 1,
        service_line_count: 1,
        diagnosis_count: 1,
        prior_auth_ok: 1,
        charge_cents: 12_500,
        max_charge_cents: 500_000,
        duplicate_flag: 0,
        program_integrity_hold: 0,
    }
}

pub fn prove_claim(claim: ClaimInput) -> anyhow::Result<(Proof, ClaimPublicInputs, ClaimOutput, Duration)> {
    let trace = build_trace(claim);
    let prover = ClaimProver::new(default_options());
    let pub_inputs = prover.get_pub_inputs(&trace);
    let output = output_for_claim(claim);
    let started = Instant::now();
    let proof = prover.prove(trace)?;
    Ok((proof, pub_inputs, output, started.elapsed()))
}

pub fn verify_claim(proof: Proof, pub_inputs: ClaimPublicInputs) -> (bool, Duration) {
    let started = Instant::now();
    let result = winterfell::verify::<
        ClaimAir,
        Blake3_256<Felt>,
        DefaultRandomCoin<Blake3_256<Felt>>,
        MerkleTree<Blake3_256<Felt>>,
    >(proof, pub_inputs, &acceptable_options());
    (result.is_ok(), started.elapsed())
}

pub fn tampered_public_input_rejected(proof: Proof, pub_inputs: ClaimPublicInputs) -> bool {
    let tampered = ClaimPublicInputs {
        commitment: pub_inputs.commitment,
        decision: Felt::from(1u32) - pub_inputs.decision,
        failure_code: pub_inputs.failure_code,
    };
    !verify_claim(proof, tampered).0
}

pub fn output_for_claim(claim: ClaimInput) -> ClaimOutput {
    let gates = gates_for_claim(&claim);
    let decision = gates.iter().copied().product::<u32>();
    let failure_code = gates
        .iter()
        .position(|gate| *gate == 0)
        .map(|idx| (idx + 1) as u32)
        .unwrap_or(0);
    ClaimOutput {
        commitment: commitment_for_claim(&claim).to_string(),
        decision,
        failure_code,
        gates,
    }
}

fn transition_degrees() -> Vec<TransitionConstraintDegree> {
    let mut degrees = Vec::new();
    degrees.extend((0..(BOOLEAN_COLUMNS.len() + 32 * 4)).map(|_| TransitionConstraintDegree::new(2)));
    degrees.extend((0..(5 * 3)).map(|_| TransitionConstraintDegree::new(2)));
    degrees.extend((0..5).map(|_| TransitionConstraintDegree::new(1)));
    degrees.extend((0..4).map(|_| TransitionConstraintDegree::new(1)));
    degrees.extend((0..2).map(|_| TransitionConstraintDegree::new(2)));
    degrees.push(TransitionConstraintDegree::new(2));
    degrees.push(TransitionConstraintDegree::new(10));
    degrees.push(TransitionConstraintDegree::new(10));
    degrees.extend((0..HASH_STATES).map(|_| TransitionConstraintDegree::new(3)));
    degrees.push(TransitionConstraintDegree::new(1));
    degrees
}

fn build_trace(claim: ClaimInput) -> TraceTable<Felt> {
    let mut rows = Vec::with_capacity(TRACE_LENGTH);
    rows.push(build_row(claim));
    for filler in filler_claims() {
        rows.push(build_row(filler));
    }
    while rows.len() < TRACE_LENGTH {
        rows.push(build_row(approved_claim()));
    }

    let mut columns = vec![vec![Felt::ZERO; TRACE_LENGTH]; TRACE_WIDTH];
    for (step, row) in rows.iter().enumerate() {
        for col in 0..TRACE_WIDTH {
            columns[col][step] = row[col];
        }
    }
    TraceTable::init(columns)
}

fn filler_claims() -> Vec<ClaimInput> {
    vec![
        ClaimInput {
            member_id: 0,
            ..approved_claim()
        },
        ClaimInput {
            eligibility_active: 0,
            ..approved_claim()
        },
        ClaimInput {
            provider_npi: 0,
            ..approved_claim()
        },
        ClaimInput {
            provider_enrolled: 0,
            ..approved_claim()
        },
        ClaimInput {
            service_line_count: 0,
            ..approved_claim()
        },
        ClaimInput {
            diagnosis_count: 0,
            ..approved_claim()
        },
        ClaimInput {
            prior_auth_ok: 0,
            ..approved_claim()
        },
        ClaimInput {
            charge_cents: 0,
            ..approved_claim()
        },
        ClaimInput {
            duplicate_flag: 1,
            ..approved_claim()
        },
        ClaimInput {
            program_integrity_hold: 1,
            ..approved_claim()
        },
        ClaimInput {
            charge_cents: 0xAAAA_AAAA,
            max_charge_cents: 0xFFFF_FFFF,
            ..approved_claim()
        },
        ClaimInput {
            charge_cents: 0x5555_5555,
            max_charge_cents: 0xFFFF_FFFF,
            ..approved_claim()
        },
        ClaimInput {
            charge_cents: 0xAAAA_AAAB,
            max_charge_cents: 0,
            ..approved_claim()
        },
        ClaimInput {
            charge_cents: 0x5555_5556,
            max_charge_cents: 0,
            ..approved_claim()
        },
    ]
}

fn build_row(claim: ClaimInput) -> [Felt; TRACE_WIDTH] {
    let mut row = [Felt::ZERO; TRACE_WIDTH];
    let inputs = [
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
    ];
    for (idx, value) in inputs.iter().copied().enumerate() {
        row[idx] = Felt::from(value);
    }

    let gates = gates_for_claim(&claim);
    for (idx, gate) in gates.iter().copied().enumerate() {
        row[GATE_START + idx] = Felt::from(gate);
    }
    let output = output_for_claim(claim);
    row[COL_DECISION] = Felt::from(output.decision);
    row[COL_FAILURE_CODE] = Felt::from(output.failure_code);
    row[COL_COMMITMENT] = commitment_for_claim(&claim);

    row[COL_INV_MEMBER_ID] = inverse_or_zero(claim.member_id);
    row[COL_INV_PROVIDER_NPI] = inverse_or_zero(claim.provider_npi);
    row[COL_INV_SERVICE_LINE_COUNT] = inverse_or_zero(claim.service_line_count);
    row[COL_INV_DIAGNOSIS_COUNT] = inverse_or_zero(claim.diagnosis_count);
    row[COL_INV_CHARGE_CENTS] = inverse_or_zero(claim.charge_cents);
    row[COL_CHARGE_POSITIVE] = Felt::from((claim.charge_cents > 0) as u32);
    row[COL_LE_MAX_CHARGE] = Felt::from((claim.charge_cents <= claim.max_charge_cents) as u32);

    let le_diff = if claim.charge_cents <= claim.max_charge_cents {
        claim.max_charge_cents - claim.charge_cents
    } else {
        0
    };
    let gt_diff = if claim.charge_cents > claim.max_charge_cents {
        claim.charge_cents - claim.max_charge_cents - 1
    } else {
        0
    };
    row[COL_LE_DIFF] = Felt::from(le_diff);
    row[COL_GT_DIFF] = Felt::from(gt_diff);

    set_bits(&mut row, CHARGE_BITS_START, claim.charge_cents);
    set_bits(&mut row, MAX_BITS_START, claim.max_charge_cents);
    set_bits(&mut row, LE_DIFF_BITS_START, le_diff);
    set_bits(&mut row, GT_DIFF_BITS_START, gt_diff);

    let mut hash_state = Felt::from(17u32);
    for (hash_idx, value) in inputs.iter().copied().enumerate() {
        hash_state = (hash_state + Felt::from(value) + Felt::from(101u32 + hash_idx as u32)).cube();
        row[HASH_START + hash_idx] = hash_state;
    }

    row
}

fn gates_for_claim(claim: &ClaimInput) -> [u32; 10] {
    [
        (claim.member_id > 0) as u32,
        (claim.eligibility_active == 1) as u32,
        (claim.provider_npi > 0) as u32,
        (claim.provider_enrolled == 1) as u32,
        (claim.service_line_count > 0) as u32,
        (claim.diagnosis_count > 0) as u32,
        (claim.prior_auth_ok == 1) as u32,
        (claim.charge_cents > 0 && claim.charge_cents <= claim.max_charge_cents) as u32,
        (claim.duplicate_flag == 0) as u32,
        (claim.program_integrity_hold == 0) as u32,
    ]
}

fn commitment_for_claim(claim: &ClaimInput) -> Felt {
    let inputs = [
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
    ];
    let mut hash_state = Felt::from(17u32);
    for (idx, value) in inputs.iter().copied().enumerate() {
        hash_state = (hash_state + Felt::from(value) + Felt::from(101u32 + idx as u32)).cube();
    }
    hash_state
}

fn constrain_nonzero_gate<E: FieldElement + From<Felt>>(
    current: &[E],
    result: &mut [E],
    mut i: usize,
    value_col: usize,
    inverse_col: usize,
    gate_col: usize,
) -> usize {
    let one = E::ONE;
    let gate = current[gate_col];
    let value = current[value_col];
    result[i] = gate - value * current[inverse_col];
    i += 1;
    result[i] = (one - gate) * value;
    i += 1;
    result[i] = gate * (gate - one);
    i += 1;
    i
}

fn bits_to_value<E: FieldElement + From<Felt>>(current: &[E], start: usize) -> E {
    let mut value = E::ZERO;
    for bit in 0..32 {
        value += current[start + bit] * E::from(1u32 << bit);
    }
    value
}

fn set_bits(row: &mut [Felt; TRACE_WIDTH], start: usize, value: u32) {
    for bit in 0..32 {
        row[start + bit] = Felt::from((value >> bit) & 1);
    }
}

fn inverse_or_zero(value: u32) -> Felt {
    if value == 0 {
        Felt::ZERO
    } else {
        Felt::from(value).inv()
    }
}

fn gate_col(gate: usize) -> usize {
    GATE_START + gate - 1
}

pub fn format_public_inputs(pub_inputs: ClaimPublicInputs, output: &ClaimOutput) -> serde_json::Value {
    serde_json::json!({
        "commitment": pub_inputs.commitment.to_string(),
        "decision": output.decision,
        "failure_code": output.failure_code,
        "gates": output.gates,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approved_claim_proves_and_verifies() {
        let (proof, pub_inputs, output, _) = prove_claim(approved_claim()).unwrap();
        assert_eq!(output.decision, 1);
        assert_eq!(output.failure_code, 0);
        assert!(verify_claim(proof, pub_inputs).0);
    }

    #[test]
    fn denied_claims_prove_correct_failure_codes() {
        for (name, claim, expected_code) in [
            (
                "ineligible",
                ClaimInput {
                    eligibility_active: 0,
                    ..approved_claim()
                },
                2,
            ),
            (
                "duplicate",
                ClaimInput {
                    duplicate_flag: 1,
                    ..approved_claim()
                },
                9,
            ),
            (
                "excessive",
                ClaimInput {
                    charge_cents: 700_000,
                    max_charge_cents: 500_000,
                    ..approved_claim()
                },
                8,
            ),
        ] {
            let (proof, pub_inputs, output, _) = prove_claim(claim).unwrap();
            assert_eq!(output.decision, 0, "{name}");
            assert_eq!(output.failure_code, expected_code, "{name}");
            assert!(verify_claim(proof, pub_inputs).0, "{name}");
        }
    }

    #[test]
    fn tampered_public_input_rejects() {
        let (proof, pub_inputs, _output, _) = prove_claim(approved_claim()).unwrap();
        assert!(tampered_public_input_rejected(proof, pub_inputs));
    }

    #[test]
    fn all_gates_are_covered() {
        assert_eq!(gates_for_claim(&approved_claim()), [1; 10]);
        assert_eq!(
            output_for_claim(ClaimInput {
                member_id: 0,
                ..approved_claim()
            })
            .failure_code,
            1
        );
        assert_eq!(
            output_for_claim(ClaimInput {
                program_integrity_hold: 1,
                ..approved_claim()
            })
            .failure_code,
            10
        );
    }
}
