//! Synthetic-only physical AIR calibration for a narrow claim-decision kernel.
//!
//! This module deliberately uses the already-rejected QM31/Blake2s/default
//! Stwo configuration. It is validity-only measurement evidence. It does not
//! implement the 12-field statement, witness hiding, BL-PQ512, authenticated
//! roots, full claim semantics, or a production verifier.

use std::time::{Duration, Instant};

use itertools::Itertools;
use num_traits::{One, Zero};
use stwo::core::air::Component;
use stwo::core::channel::{Blake2sChannel, Channel};
use stwo::core::fields::m31::{BaseField, M31};
use stwo::core::fields::qm31::{SecureField, QM31};
use stwo::core::fri::FriConfig;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig, TreeVec};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::proof::StarkProof;
use stwo::core::utils::{bit_reverse_index, coset_index_to_circle_domain_index};
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher};
use stwo::core::verifier::verify;
use stwo::core::ColumnVec;
use stwo::prover::backend::simd::column::BaseColumn;
use stwo::prover::backend::simd::m31::{PackedM31, LOG_N_LANES};
use stwo::prover::backend::simd::qm31::PackedQM31;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::{prove, CommitmentSchemeProver, ComponentProver};
use stwo_constraint_framework::{
    relation, EvalAtRow, FrameworkComponent, FrameworkEval, InfoEvaluator, LogupTraceGenerator,
    Relation, RelationEntry, TraceLocationAllocator, PREPROCESSED_TRACE_IDX,
};

use crate::security_boundary::{enforce_before_trace, ProofSecurityRequirement};

pub const CALIBRATION_STATUS: &str = "REJECTED_VALIDITY_ONLY_CALIBRATION";
pub const CALIBRATION_SECURITY_SCOPE: &str = "decision_priority_and_limb_payment_conservation_only";
pub const FAILURE_GATE_COUNT: usize = 13;
pub const TRACE_COLUMNS: usize = 267;
pub const INTERACTION_COLUMNS: usize = 1;

const STATE_SIZE: usize = 3;
const LIMB_BITS: usize = 16;
const LIMB_BASE: u32 = 1 << LIMB_BITS;
const MONEY_VALUE_COUNT: usize = 5;
const MONEY_LIMBS_PER_VALUE: usize = 2;
const MONEY_BITS_PER_VALUE: usize = 32;

const IS_REAL: usize = 0;
const RAW_GATES: usize = 1;
const PREFIXES: usize = RAW_GATES + FAILURE_GATE_COUNT;
const SELECTORS: usize = PREFIXES + FAILURE_GATE_COUNT + 1;
const DECISION: usize = SELECTORS + FAILURE_GATE_COUNT;
const FAILURE_CODE: usize = DECISION + 1;
const MONEY_LIMBS: usize = FAILURE_CODE + 1;
const MONEY_BITS: usize = MONEY_LIMBS + MONEY_VALUE_COUNT * MONEY_LIMBS_PER_VALUE;
const STATE_LIMBS: usize = MONEY_BITS + MONEY_VALUE_COUNT * MONEY_BITS_PER_VALUE;
const STATE_BITS: usize = STATE_LIMBS + STATE_SIZE;
const PAYMENT_CARRY: usize = STATE_BITS + STATE_SIZE * LIMB_BITS;
const STATE_CARRY_LOW: usize = PAYMENT_CARRY + 1;
const STATE_CARRY_MID: usize = STATE_CARRY_LOW + 1;

const COVER_RAW_GATES: [bool; FAILURE_GATE_COUNT] = [
    false, false, false, false, false, false, false, false, true, false, true, true, true,
];

const fn money_limb_column(value: usize, limb: usize) -> usize {
    MONEY_LIMBS + value * MONEY_LIMBS_PER_VALUE + limb
}

const fn money_bit_column(value: usize, bit: usize) -> usize {
    MONEY_BITS + value * MONEY_BITS_PER_VALUE + bit
}

const fn state_limb_column(limb: usize) -> usize {
    STATE_LIMBS + limb
}

const fn state_bit_column(limb: usize, bit: usize) -> usize {
    STATE_BITS + limb * LIMB_BITS + bit
}

const MONEY_ALLOWED: usize = 0;
const MONEY_RESPONSIBILITY: usize = 1;
const MONEY_PAYABLE: usize = 2;
const MONEY_DEBIT: usize = 3;
const MONEY_CREDIT: usize = 4;

const _: () = assert!(STATE_CARRY_MID + 1 == TRACE_COLUMNS);

relation!(CalibrationStateElements, STATE_SIZE);

type CalibrationState = [M31; STATE_SIZE];
type CalibrationComponent = FrameworkComponent<PhysicalClaimEval>;
type Trace = ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CalibrationProfile {
    K128,
    K256,
    K512,
}

impl CalibrationProfile {
    pub const fn rows(self) -> usize {
        match self {
            Self::K128 => 128,
            Self::K256 => 256,
            Self::K512 => 512,
        }
    }

    pub const fn profile_id(self) -> &'static str {
        match self {
            Self::K128 => "K128_CALIBRATION",
            Self::K256 => "K256_DESIGN_POINT",
            Self::K512 => "K512_CALIBRATION",
        }
    }

    const fn transcript_code(self) -> u64 {
        match self {
            Self::K128 => 128,
            Self::K256 => 256,
            Self::K512 => 512,
        }
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "k128" => Ok(Self::K128),
            "k256" => Ok(Self::K256),
            "k512" => Ok(Self::K512),
            _ => Err("profile must be k128, k256, or k512".to_string()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CalibrationShape {
    Approval,
    Denial(u8),
    Cover,
    Mixed,
    MaximumApproval,
}

impl CalibrationShape {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "approval" => Ok(Self::Approval),
            "cover" => Ok(Self::Cover),
            "mixed" => Ok(Self::Mixed),
            "maximum-approval" => Ok(Self::MaximumApproval),
            _ => {
                let Some(code) = value.strip_prefix("denial-") else {
                    return Err(
                        "shape must be approval, denial-1..denial-13, cover, mixed, or maximum-approval"
                            .to_string(),
                    );
                };
                let parsed: u8 = code
                    .parse()
                    .map_err(|_| "denial code must be an integer from 1 through 13".to_string())?;
                if !(1..=FAILURE_GATE_COUNT as u8).contains(&parsed) {
                    return Err("denial code must be an integer from 1 through 13".to_string());
                }
                Ok(Self::Denial(parsed))
            }
        }
    }

    pub fn label(self) -> String {
        match self {
            Self::Approval => "approval".to_string(),
            Self::Denial(code) => format!("denial-{code}"),
            Self::Cover => "cover".to_string(),
            Self::Mixed => "mixed".to_string(),
            Self::MaximumApproval => "maximum-approval".to_string(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CalibrationRow {
    is_real: bool,
    raw_gates: [bool; FAILURE_GATE_COUNT],
    allowed_cents: u32,
    patient_responsibility_cents: u32,
    plan_payable_cents: u32,
    payer_reserve_debit_cents: u32,
    provider_payable_credit_cents: u32,
}

impl CalibrationRow {
    fn approval(allowed: u32, responsibility: u32, payable: u32) -> Result<Self, String> {
        if responsibility.checked_add(payable) != Some(allowed) {
            return Err("calibration approval money relation mismatch".to_string());
        }
        Ok(Self {
            is_real: true,
            raw_gates: [true; FAILURE_GATE_COUNT],
            allowed_cents: allowed,
            patient_responsibility_cents: responsibility,
            plan_payable_cents: payable,
            payer_reserve_debit_cents: payable,
            provider_payable_credit_cents: payable,
        })
    }

    fn denial(code: u8) -> Result<Self, String> {
        if !(1..=FAILURE_GATE_COUNT as u8).contains(&code) {
            return Err("calibration denial code out of range".to_string());
        }
        let mut raw_gates = [true; FAILURE_GATE_COUNT];
        raw_gates[usize::from(code - 1)] = false;
        Ok(Self {
            is_real: true,
            raw_gates,
            allowed_cents: 0,
            patient_responsibility_cents: 0,
            plan_payable_cents: 0,
            payer_reserve_debit_cents: 0,
            provider_payable_credit_cents: 0,
        })
    }

    const fn cover() -> Self {
        Self {
            is_real: false,
            raw_gates: COVER_RAW_GATES,
            allowed_cents: 0,
            patient_responsibility_cents: 0,
            plan_payable_cents: 0,
            payer_reserve_debit_cents: 0,
            provider_payable_credit_cents: 0,
        }
    }

    fn validate(self) -> Result<(), String> {
        if !self.is_real {
            if self.raw_gates != COVER_RAW_GATES {
                return Err("calibration cover raw gates are not canonical".to_string());
            }
            if self.money_values().iter().any(|value| *value != 0) {
                return Err("calibration cover economics must be zero".to_string());
            }
            return Ok(());
        }

        let approved = self.raw_gates.iter().all(|gate| *gate);
        if approved {
            if self
                .patient_responsibility_cents
                .checked_add(self.plan_payable_cents)
                != Some(self.allowed_cents)
            {
                return Err("calibration approval money relation mismatch".to_string());
            }
            if self.payer_reserve_debit_cents != self.plan_payable_cents
                || self.provider_payable_credit_cents != self.plan_payable_cents
            {
                return Err("calibration approval conservation mismatch".to_string());
            }
        } else if self.money_values().iter().any(|value| *value != 0) {
            return Err("calibration denial economics must be zero".to_string());
        }
        Ok(())
    }

    const fn money_values(self) -> [u32; MONEY_VALUE_COUNT] {
        [
            self.allowed_cents,
            self.patient_responsibility_cents,
            self.plan_payable_cents,
            self.payer_reserve_debit_cents,
            self.provider_payable_credit_cents,
        ]
    }
}

#[derive(Clone)]
struct PhysicalClaimEval {
    log_n_rows: u32,
    state_elements: CalibrationStateElements,
}

fn boolean_constraint<F>(value: F) -> F
where
    F: Clone + One + std::ops::Sub<F, Output = F> + std::ops::Mul<F, Output = F>,
{
    value.clone() * (value - F::one())
}

fn recompose_limb<F>(bits: &[F]) -> F
where
    F: Clone + Zero + std::ops::AddAssign + std::ops::Mul<BaseField, Output = F>,
{
    bits.iter()
        .enumerate()
        .fold(F::zero(), |mut value, (bit, item)| {
            value += item.clone() * BaseField::from_u32_unchecked(1 << bit);
            value
        })
}

impl FrameworkEval for PhysicalClaimEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let is_real = eval.next_trace_mask();
        eval.add_constraint(boolean_constraint(is_real.clone()));

        let raw_gates: [E::F; FAILURE_GATE_COUNT] = std::array::from_fn(|_| eval.next_trace_mask());
        for (index, gate) in raw_gates.iter().enumerate() {
            eval.add_constraint(boolean_constraint(gate.clone()));
            let cover_expected = E::F::from(BaseField::from_u32_unchecked(u32::from(
                COVER_RAW_GATES[index],
            )));
            eval.add_constraint((E::F::one() - is_real.clone()) * (gate.clone() - cover_expected));
        }

        let prefixes: [E::F; FAILURE_GATE_COUNT + 1] =
            std::array::from_fn(|_| eval.next_trace_mask());
        for prefix in &prefixes {
            eval.add_constraint(boolean_constraint(prefix.clone()));
        }
        let selectors: [E::F; FAILURE_GATE_COUNT] = std::array::from_fn(|_| eval.next_trace_mask());
        for selector in &selectors {
            eval.add_constraint(boolean_constraint(selector.clone()));
        }
        let decision = eval.next_trace_mask();
        eval.add_constraint(boolean_constraint(decision.clone()));
        let failure_code = eval.next_trace_mask();

        eval.add_constraint(prefixes[0].clone() - is_real.clone());
        for index in 0..FAILURE_GATE_COUNT {
            eval.add_constraint(
                selectors[index].clone()
                    - prefixes[index].clone() * (E::F::one() - raw_gates[index].clone()),
            );
            eval.add_constraint(
                prefixes[index + 1].clone() - prefixes[index].clone() * raw_gates[index].clone(),
            );
        }
        eval.add_constraint(decision.clone() - prefixes[FAILURE_GATE_COUNT].clone());
        let mut expected_failure = E::F::zero();
        let mut terminal_sum = decision.clone();
        for (index, selector) in selectors.iter().enumerate() {
            expected_failure +=
                selector.clone() * BaseField::from_u32_unchecked((index + 1) as u32);
            terminal_sum += selector.clone();
        }
        eval.add_constraint(failure_code - expected_failure);
        eval.add_constraint(terminal_sum - is_real.clone());

        let money_limbs: [[E::F; MONEY_LIMBS_PER_VALUE]; MONEY_VALUE_COUNT] =
            std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()));
        let money_bits: [[[E::F; LIMB_BITS]; MONEY_LIMBS_PER_VALUE]; MONEY_VALUE_COUNT] =
            std::array::from_fn(|_| {
                std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()))
            });
        for value in 0..MONEY_VALUE_COUNT {
            for limb in 0..MONEY_LIMBS_PER_VALUE {
                for bit in &money_bits[value][limb] {
                    eval.add_constraint(boolean_constraint(bit.clone()));
                    eval.add_constraint((E::F::one() - decision.clone()) * bit.clone());
                }
                eval.add_constraint(
                    money_limbs[value][limb].clone() - recompose_limb(&money_bits[value][limb]),
                );
            }
        }

        let state_limbs: [E::F; STATE_SIZE] = std::array::from_fn(|_| eval.next_trace_mask());
        let state_bits: [[E::F; LIMB_BITS]; STATE_SIZE] =
            std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()));
        for limb in 0..STATE_SIZE {
            for bit in &state_bits[limb] {
                eval.add_constraint(boolean_constraint(bit.clone()));
            }
            eval.add_constraint(state_limbs[limb].clone() - recompose_limb(&state_bits[limb]));
        }

        let payment_carry = eval.next_trace_mask();
        let state_carry_low = eval.next_trace_mask();
        let state_carry_mid = eval.next_trace_mask();
        for carry in [
            payment_carry.clone(),
            state_carry_low.clone(),
            state_carry_mid.clone(),
        ] {
            eval.add_constraint(boolean_constraint(carry));
        }

        let limb_base = BaseField::from_u32_unchecked(LIMB_BASE);
        let allowed = &money_limbs[MONEY_ALLOWED];
        let responsibility = &money_limbs[MONEY_RESPONSIBILITY];
        let payable = &money_limbs[MONEY_PAYABLE];
        let debit = &money_limbs[MONEY_DEBIT];
        let credit = &money_limbs[MONEY_CREDIT];
        eval.add_constraint(
            responsibility[0].clone() + payable[0].clone()
                - allowed[0].clone()
                - payment_carry.clone() * limb_base,
        );
        eval.add_constraint(
            responsibility[1].clone() + payable[1].clone() + payment_carry - allowed[1].clone(),
        );
        for limb in 0..MONEY_LIMBS_PER_VALUE {
            eval.add_constraint(debit[limb].clone() - payable[limb].clone());
            eval.add_constraint(credit[limb].clone() - payable[limb].clone());
        }

        let output_state: [E::F; STATE_SIZE] = [
            state_limbs[0].clone() + payable[0].clone() - state_carry_low.clone() * limb_base,
            state_limbs[1].clone() + payable[1].clone() + state_carry_low
                - state_carry_mid.clone() * limb_base,
            state_limbs[2].clone() + state_carry_mid,
        ];
        eval.add_to_relation(RelationEntry::new(
            &self.state_elements,
            E::EF::one(),
            &state_limbs,
        ));
        eval.add_to_relation(RelationEntry::new(
            &self.state_elements,
            -E::EF::one(),
            &output_state,
        ));
        eval.finalize_logup_in_pairs();
        eval
    }
}

#[derive(Clone)]
struct CalibrationStatement0 {
    profile: CalibrationProfile,
    log_n_rows: u32,
    initial_state: CalibrationState,
    final_state: CalibrationState,
}

impl CalibrationStatement0 {
    fn validate(&self) -> Result<(), String> {
        if self.log_n_rows != self.profile.rows().ilog2() {
            return Err("calibration statement profile/row mismatch".to_string());
        }
        if self.initial_state != [M31::zero(); STATE_SIZE] {
            return Err("calibration statement initial state must be zero".to_string());
        }
        let total = canonical_limbs_to_u64(self.final_state)?;
        let maximum = self.profile.rows() as u64 * u64::from(u32::MAX);
        if total > maximum {
            return Err("calibration statement total exceeds profile maximum".to_string());
        }
        Ok(())
    }

    fn log_sizes(&self) -> TreeVec<Vec<u32>> {
        let sizes = kernel_info()
            .mask_offsets
            .as_cols_ref()
            .map_cols(|_| self.log_n_rows);
        let mut log_sizes = TreeVec::concat_cols(std::iter::once(sizes));
        log_sizes[PREPROCESSED_TRACE_IDX] = vec![];
        log_sizes
    }

    fn mix_into(&self, channel: &mut impl Channel) {
        channel.mix_u64(0x424c_5232_3643_414c);
        channel.mix_u64(0x5245_4a45_4354_4544);
        channel.mix_u64(self.profile.transcript_code());
        channel.mix_u64(self.log_n_rows as u64);
        for value in self.initial_state.iter().chain(self.final_state.iter()) {
            channel.mix_u64(value.0 as u64);
        }
    }
}

#[derive(Clone)]
struct CalibrationStatement1 {
    claimed_sum: SecureField,
}

impl CalibrationStatement1 {
    fn mix_into(&self, channel: &mut impl Channel) {
        channel.mix_felts(&[self.claimed_sum]);
    }
}

struct CalibrationProof {
    statement0: CalibrationStatement0,
    statement1: CalibrationStatement1,
    stark_proof: StarkProof<Blake2sMerkleHasher>,
}

#[derive(Default)]
struct ProverTimings {
    fixture_and_trace: Duration,
    twiddles: Duration,
    commitments: Duration,
    interaction: Duration,
    prove: Duration,
}

#[derive(Clone, Debug)]
pub struct CalibrationReport {
    pub status: &'static str,
    pub security_scope: &'static str,
    pub profile_id: &'static str,
    pub fixture_shape: String,
    pub physical_air_rows: usize,
    pub physical_air_columns: usize,
    pub interaction_columns: usize,
    pub air_constraints: usize,
    pub public_total_plan_payable_cents: u64,
    pub proof_size_estimate_bytes: usize,
    pub fixture_and_trace_seconds: f64,
    pub twiddle_seconds: f64,
    pub commitment_seconds: f64,
    pub interaction_seconds: f64,
    pub prove_seconds: f64,
    pub verify_seconds: f64,
    pub witness_hiding: bool,
    pub proof_suite_id: Option<&'static str>,
    pub activation_allowed: bool,
    pub proof_discarded: bool,
    pub proof_artifact_written: bool,
}

fn rejected_calibration_config() -> PcsConfig {
    PcsConfig {
        pow_bits: 10,
        fri_config: FriConfig::new(0, 1, 3, 1),
        lifting_log_size: None,
    }
}

fn require_exact_rejected_config(config: PcsConfig) -> Result<(), String> {
    if config != rejected_calibration_config() {
        return Err(
            "calibration verifier rejected proof-selected PCS/FRI configuration".to_string(),
        );
    }
    Ok(())
}

fn kernel_info() -> InfoEvaluator {
    PhysicalClaimEval {
        log_n_rows: 7,
        state_elements: CalibrationStateElements::dummy(),
    }
    .evaluate(InfoEvaluator::empty())
}

fn build_component(
    allocator: &mut TraceLocationAllocator,
    log_n_rows: u32,
    state_elements: CalibrationStateElements,
    claimed_sum: SecureField,
) -> CalibrationComponent {
    CalibrationComponent::new(
        allocator,
        PhysicalClaimEval {
            log_n_rows,
            state_elements,
        },
        claimed_sum,
    )
}

fn build_rows(
    profile: CalibrationProfile,
    shape: CalibrationShape,
) -> Result<Vec<CalibrationRow>, String> {
    (0..profile.rows())
        .map(|index| match shape {
            CalibrationShape::Approval => CalibrationRow::approval(100, 20, 80),
            CalibrationShape::Denial(code) => CalibrationRow::denial(code),
            CalibrationShape::Cover => Ok(CalibrationRow::cover()),
            CalibrationShape::Mixed => match index % 3 {
                0 => CalibrationRow::approval(100, 20, 80),
                1 => CalibrationRow::denial((index % FAILURE_GATE_COUNT + 1) as u8),
                _ => Ok(CalibrationRow::cover()),
            },
            CalibrationShape::MaximumApproval => CalibrationRow::approval(u32::MAX, 0, u32::MAX),
        })
        .collect()
}

fn u16_limbs(value: u32) -> [u16; 2] {
    [value as u16, (value >> 16) as u16]
}

fn u48_limbs(value: u64) -> Result<[u16; STATE_SIZE], String> {
    if value >= (1_u64 << 48) {
        return Err("calibration aggregate exceeds 48-bit state".to_string());
    }
    Ok([value as u16, (value >> 16) as u16, (value >> 32) as u16])
}

fn canonical_limbs_to_u64(limbs: CalibrationState) -> Result<u64, String> {
    limbs
        .into_iter()
        .enumerate()
        .try_fold(0_u64, |total, (index, limb)| {
            let value = u64::from(limb.0);
            if value >= u64::from(LIMB_BASE) {
                return Err("calibration statement final state limb is noncanonical".to_string());
            }
            let weight = 1_u64 << (index * LIMB_BITS);
            let weighted = value
                .checked_mul(weight)
                .ok_or_else(|| "calibration statement final state overflow".to_string())?;
            total
                .checked_add(weighted)
                .ok_or_else(|| "calibration statement final state overflow".to_string())
        })
}

fn set_u32_bits(columns: &mut [Vec<M31>], value_index: usize, row: usize, value: u32) {
    let limbs = u16_limbs(value);
    for (limb, limb_value) in limbs.into_iter().enumerate() {
        columns[money_limb_column(value_index, limb)][row] =
            M31::from_u32_unchecked(u32::from(limb_value));
        for bit in 0..LIMB_BITS {
            columns[money_bit_column(value_index, limb * LIMB_BITS + bit)][row] =
                M31::from_u32_unchecked(u32::from((limb_value >> bit) & 1));
        }
    }
}

fn set_state_bits(columns: &mut [Vec<M31>], row: usize, state: u64) -> Result<(), String> {
    for (limb, limb_value) in u48_limbs(state)?.into_iter().enumerate() {
        columns[state_limb_column(limb)][row] = M31::from_u32_unchecked(u32::from(limb_value));
        for bit in 0..LIMB_BITS {
            columns[state_bit_column(limb, bit)][row] =
                M31::from_u32_unchecked(u32::from((limb_value >> bit) & 1));
        }
    }
    Ok(())
}

fn generate_trace(rows: &[CalibrationRow]) -> Result<(Trace, CalibrationState), String> {
    if !rows.len().is_power_of_two() || rows.len() < (1 << LOG_N_LANES) {
        return Err("calibration row count must be a supported power of two".to_string());
    }
    for row in rows {
        row.validate()?;
    }
    let log_n_rows = rows.len().ilog2();
    let domain = CanonicCoset::new(log_n_rows).circle_domain();
    let mut columns = (0..TRACE_COLUMNS)
        .map(|_| vec![M31::zero(); rows.len()])
        .collect_vec();
    let mut aggregate = 0_u64;

    for (natural_row, row) in rows.iter().copied().enumerate() {
        let trace_row = bit_reverse_index(
            coset_index_to_circle_domain_index(natural_row, log_n_rows),
            log_n_rows,
        );
        columns[IS_REAL][trace_row] = M31::from_u32_unchecked(u32::from(row.is_real));
        for (index, gate) in row.raw_gates.into_iter().enumerate() {
            columns[RAW_GATES + index][trace_row] = M31::from_u32_unchecked(u32::from(gate));
        }

        let mut prefix = row.is_real;
        columns[PREFIXES][trace_row] = M31::from_u32_unchecked(u32::from(prefix));
        let mut failure_code = 0_u32;
        for (index, gate) in row.raw_gates.into_iter().enumerate() {
            let selector = prefix && !gate;
            if selector {
                failure_code = (index + 1) as u32;
            }
            columns[SELECTORS + index][trace_row] = M31::from_u32_unchecked(u32::from(selector));
            prefix = prefix && gate;
            columns[PREFIXES + index + 1][trace_row] = M31::from_u32_unchecked(u32::from(prefix));
        }
        columns[DECISION][trace_row] = M31::from_u32_unchecked(u32::from(prefix));
        columns[FAILURE_CODE][trace_row] = M31::from_u32_unchecked(failure_code);

        for (value_index, value) in row.money_values().into_iter().enumerate() {
            set_u32_bits(&mut columns, value_index, trace_row, value);
        }
        set_state_bits(&mut columns, trace_row, aggregate)?;

        let responsibility_low = row.patient_responsibility_cents & 0xffff;
        let payable_low = row.plan_payable_cents & 0xffff;
        let payment_carry = u32::from(responsibility_low + payable_low >= LIMB_BASE);
        columns[PAYMENT_CARRY][trace_row] = M31::from_u32_unchecked(payment_carry);

        let state_low = (aggregate & 0xffff) as u32;
        let state_mid = ((aggregate >> 16) & 0xffff) as u32;
        let payable_limbs = u16_limbs(row.plan_payable_cents);
        let low_sum = state_low + u32::from(payable_limbs[0]);
        let state_carry_low = u32::from(low_sum >= LIMB_BASE);
        let mid_sum = state_mid + u32::from(payable_limbs[1]) + state_carry_low;
        let state_carry_mid = u32::from(mid_sum >= LIMB_BASE);
        columns[STATE_CARRY_LOW][trace_row] = M31::from_u32_unchecked(state_carry_low);
        columns[STATE_CARRY_MID][trace_row] = M31::from_u32_unchecked(state_carry_mid);
        aggregate = aggregate
            .checked_add(u64::from(row.plan_payable_cents))
            .ok_or_else(|| "calibration aggregate overflowed u64".to_string())?;
    }

    let trace = columns
        .into_iter()
        .map(|column| {
            CircleEvaluation::<SimdBackend, _, BitReversedOrder>::new(
                domain,
                BaseColumn::from_iter(column),
            )
        })
        .collect_vec();
    let final_state = u48_limbs(aggregate)?.map(|value| M31::from_u32_unchecked(u32::from(value)));
    Ok((trace, final_state))
}

fn generate_interaction_trace(
    trace: &Trace,
    state_elements: &CalibrationStateElements,
) -> (Trace, SecureField) {
    let log_n_rows = trace[0].domain.log_size();
    let mut logup = LogupTraceGenerator::new(log_n_rows);
    let mut column = logup.new_col();
    let limb_base = PackedM31::broadcast(M31::from_u32_unchecked(LIMB_BASE));
    for packed_row in 0..(1 << (log_n_rows - LOG_N_LANES)) {
        let input_state: [PackedM31; STATE_SIZE] =
            std::array::from_fn(|limb| trace[state_limb_column(limb)].data[packed_row]);
        let payable = [
            trace[money_limb_column(MONEY_PAYABLE, 0)].data[packed_row],
            trace[money_limb_column(MONEY_PAYABLE, 1)].data[packed_row],
        ];
        let carry_low = trace[STATE_CARRY_LOW].data[packed_row];
        let carry_mid = trace[STATE_CARRY_MID].data[packed_row];
        let output_state: [PackedM31; STATE_SIZE] = [
            input_state[0] + payable[0] - carry_low * limb_base,
            input_state[1] + payable[1] + carry_low - carry_mid * limb_base,
            input_state[2] + carry_mid,
        ];
        let input_denominator: PackedQM31 = state_elements.combine(&input_state);
        let output_denominator: PackedQM31 = state_elements.combine(&output_state);
        column.write_frac(
            packed_row,
            output_denominator - input_denominator,
            input_denominator * output_denominator,
        );
    }
    column.finalize_col();
    logup.finalize_last()
}

fn prove_calibration(
    profile: CalibrationProfile,
    shape: CalibrationShape,
) -> Result<(CalibrationProof, ProverTimings), String> {
    enforce_before_trace(ProofSecurityRequirement::ValidityOnly)?;
    let config = rejected_calibration_config();
    let mut timings = ProverTimings::default();

    let started = Instant::now();
    let rows = build_rows(profile, shape)?;
    let (trace, final_state) = generate_trace(&rows)?;
    timings.fixture_and_trace = started.elapsed();
    let statement0 = CalibrationStatement0 {
        profile,
        log_n_rows: profile.rows().ilog2(),
        initial_state: [M31::zero(); STATE_SIZE],
        final_state,
    };
    statement0.validate()?;

    let started = Instant::now();
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(statement0.log_n_rows + config.fri_config.log_blowup_factor + 1)
            .circle_domain()
            .half_coset,
    );
    timings.twiddles = started.elapsed();

    let prover_channel = &mut Blake2sChannel::default();
    config.mix_into(prover_channel);
    let mut commitment_scheme =
        CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(config, &twiddles);
    commitment_scheme.set_store_polynomials_coefficients();

    let started = Instant::now();
    commitment_scheme.tree_builder().commit(prover_channel);
    statement0.mix_into(prover_channel);
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(trace.clone());
    tree_builder.commit(prover_channel);
    timings.commitments += started.elapsed();

    let state_elements = CalibrationStateElements::draw(prover_channel);
    let started = Instant::now();
    let (interaction_trace, claimed_sum) = generate_interaction_trace(&trace, &state_elements);
    timings.interaction = started.elapsed();
    let statement1 = CalibrationStatement1 { claimed_sum };
    statement1.mix_into(prover_channel);

    let started = Instant::now();
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(interaction_trace);
    tree_builder.commit(prover_channel);
    timings.commitments += started.elapsed();

    let mut allocator = TraceLocationAllocator::default();
    let component = build_component(
        &mut allocator,
        statement0.log_n_rows,
        state_elements,
        claimed_sum,
    );
    let started = Instant::now();
    let stark_proof = prove::<SimdBackend, Blake2sMerkleChannel>(
        &[&component as &dyn ComponentProver<SimdBackend>],
        prover_channel,
        commitment_scheme,
    )
    .map_err(|error| format!("calibration Stwo proving failed: {error:?}"))?;
    timings.prove = started.elapsed();

    Ok((
        CalibrationProof {
            statement0,
            statement1,
            stark_proof,
        },
        timings,
    ))
}

fn verify_calibration(proof: CalibrationProof) -> Result<(), String> {
    // This exact check is deliberately first: no verifier channel, commitment
    // scheme, trace allocator, or component exists before proof-selected
    // parameters are rejected.
    require_exact_rejected_config(proof.stark_proof.config)?;
    proof.statement0.validate()?;

    let config = rejected_calibration_config();
    let verifier_channel = &mut Blake2sChannel::default();
    config.mix_into(verifier_channel);
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config);
    let sizes = proof.statement0.log_sizes();
    commitment_scheme.commit(
        proof.stark_proof.commitments[0],
        &sizes[0],
        verifier_channel,
    );
    proof.statement0.mix_into(verifier_channel);
    commitment_scheme.commit(
        proof.stark_proof.commitments[1],
        &sizes[1],
        verifier_channel,
    );

    let state_elements = CalibrationStateElements::draw(verifier_channel);
    let initial: QM31 = state_elements.combine(&proof.statement0.initial_state);
    let final_state: QM31 = state_elements.combine(&proof.statement0.final_state);
    if proof.statement1.claimed_sum * initial * final_state != final_state - initial {
        return Err("calibration LogUp sum does not match public limb total".to_string());
    }
    proof.statement1.mix_into(verifier_channel);
    commitment_scheme.commit(
        proof.stark_proof.commitments[2],
        &sizes[2],
        verifier_channel,
    );

    let mut allocator = TraceLocationAllocator::default();
    let component = build_component(
        &mut allocator,
        proof.statement0.log_n_rows,
        state_elements,
        proof.statement1.claimed_sum,
    );
    verify(
        &[&component as &dyn Component],
        verifier_channel,
        commitment_scheme,
        proof.stark_proof,
    )
    .map_err(|error| format!("calibration Stwo verification failed: {error:?}"))
}

pub fn run_calibration(
    profile: CalibrationProfile,
    shape: CalibrationShape,
) -> Result<CalibrationReport, String> {
    let (proof, timings) = prove_calibration(profile, shape)?;
    let total = canonical_limbs_to_u64(proof.statement0.final_state)?;
    let proof_size_estimate_bytes = proof.stark_proof.size_estimate();
    let started = Instant::now();
    verify_calibration(proof)?;
    let verify_seconds = started.elapsed().as_secs_f64();
    Ok(CalibrationReport {
        status: CALIBRATION_STATUS,
        security_scope: CALIBRATION_SECURITY_SCOPE,
        profile_id: profile.profile_id(),
        fixture_shape: shape.label(),
        physical_air_rows: profile.rows(),
        physical_air_columns: TRACE_COLUMNS,
        interaction_columns: INTERACTION_COLUMNS,
        air_constraints: kernel_info().n_constraints,
        public_total_plan_payable_cents: total,
        proof_size_estimate_bytes,
        fixture_and_trace_seconds: timings.fixture_and_trace.as_secs_f64(),
        twiddle_seconds: timings.twiddles.as_secs_f64(),
        commitment_seconds: timings.commitments.as_secs_f64(),
        interaction_seconds: timings.interaction.as_secs_f64(),
        prove_seconds: timings.prove.as_secs_f64(),
        verify_seconds,
        witness_hiding: false,
        proof_suite_id: None,
        activation_allowed: false,
        proof_discarded: true,
        proof_artifact_written: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn column_layout_is_exact_and_nonoverlapping() {
        assert_eq!(TRACE_COLUMNS, 267);
        assert_eq!(IS_REAL, 0);
        assert_eq!(FAILURE_CODE, 42);
        assert_eq!(MONEY_LIMBS, 43);
        assert_eq!(MONEY_BITS, 53);
        assert_eq!(STATE_LIMBS, 213);
        assert_eq!(STATE_BITS, 216);
        assert_eq!(PAYMENT_CARRY, 264);
        assert_eq!(STATE_CARRY_LOW, 265);
        assert_eq!(STATE_CARRY_MID, 266);
    }

    #[test]
    fn rejected_config_pin_is_exact_and_mutation_fails_before_verifier_allocation() {
        let exact = rejected_calibration_config();
        assert_eq!(exact.pow_bits, 10);
        assert_eq!(exact.fri_config.log_blowup_factor, 1);
        assert_eq!(exact.fri_config.n_queries, 3);
        assert_eq!(require_exact_rejected_config(exact), Ok(()));
        let mut changed = exact;
        changed.pow_bits += 1;
        assert_eq!(
            require_exact_rejected_config(changed),
            Err("calibration verifier rejected proof-selected PCS/FRI configuration".to_string())
        );
    }

    #[test]
    fn row_host_boundary_rejects_bad_money_and_cover_values() {
        assert!(CalibrationRow::approval(100, 20, 79).is_err());
        assert!(CalibrationRow::approval(0, u32::MAX, 1).is_err());
        let mut cover = CalibrationRow::cover();
        cover.plan_payable_cents = 1;
        assert!(cover.validate().is_err());
        for field in 0..MONEY_VALUE_COUNT {
            let mut changed = CalibrationRow::cover();
            match field {
                0 => changed.allowed_cents = 1,
                1 => changed.patient_responsibility_cents = 1,
                2 => changed.plan_payable_cents = 1,
                3 => changed.payer_reserve_debit_cents = 1,
                4 => changed.provider_payable_credit_cents = 1,
                _ => unreachable!(),
            }
            assert!(changed.validate().is_err());
        }
        let mut changed_cover_gate = CalibrationRow::cover();
        changed_cover_gate.raw_gates[0] = !changed_cover_gate.raw_gates[0];
        assert!(changed_cover_gate.validate().is_err());
        let mut denial = CalibrationRow::denial(1).unwrap();
        for field in 0..MONEY_VALUE_COUNT {
            let mut changed = denial;
            match field {
                0 => changed.allowed_cents = 1,
                1 => changed.patient_responsibility_cents = 1,
                2 => changed.plan_payable_cents = 1,
                3 => changed.payer_reserve_debit_cents = 1,
                4 => changed.provider_payable_credit_cents = 1,
                _ => unreachable!(),
            }
            assert!(changed.validate().is_err());
        }
        denial.raw_gates[8] = false;
        assert_eq!(denial.raw_gates.iter().position(|gate| !gate), Some(0));
    }

    #[test]
    fn simultaneous_gate_failures_select_only_the_earliest_failure() {
        let mut row = CalibrationRow::denial(3).unwrap();
        row.raw_gates[8] = false;
        let rows = vec![row; CalibrationProfile::K128.rows()];
        let (trace, _) = generate_trace(&rows).unwrap();
        let log_n_rows = CalibrationProfile::K128.rows().ilog2();
        let trace_row = bit_reverse_index(
            coset_index_to_circle_domain_index(0, log_n_rows),
            log_n_rows,
        );
        let failure_codes = trace[FAILURE_CODE].to_cpu();
        assert_eq!(failure_codes[trace_row], M31::from_u32_unchecked(3));
        for index in 0..FAILURE_GATE_COUNT {
            let selectors = trace[SELECTORS + index].to_cpu();
            assert_eq!(
                selectors[trace_row],
                M31::from_u32_unchecked(u32::from(index == 2))
            );
        }
        let decisions = trace[DECISION].to_cpu();
        assert_eq!(decisions[trace_row], M31::zero());
    }

    #[test]
    fn all_profiles_and_fixture_classes_keep_fixed_physical_dimensions() {
        let profiles = [
            CalibrationProfile::K128,
            CalibrationProfile::K256,
            CalibrationProfile::K512,
        ];
        let shapes = [
            CalibrationShape::Approval,
            CalibrationShape::Denial(7),
            CalibrationShape::Cover,
            CalibrationShape::Mixed,
            CalibrationShape::MaximumApproval,
        ];
        for profile in profiles {
            for shape in shapes {
                let rows = build_rows(profile, shape).unwrap();
                let (trace, final_state) = generate_trace(&rows).unwrap();
                assert_eq!(rows.len(), profile.rows());
                assert_eq!(trace.len(), TRACE_COLUMNS);
                assert_eq!(trace[0].domain.log_size(), profile.rows().ilog2());
                assert!(canonical_limbs_to_u64(final_state).is_ok());
            }
        }
    }

    #[test]
    fn payment_and_aggregate_carries_cross_limb_boundaries_without_narrowing() {
        let payable = u32::MAX - LIMB_BASE;
        let row = CalibrationRow::approval(payable + 1, 1, payable).unwrap();
        assert_eq!(
            (row.patient_responsibility_cents & 0xffff) + (row.plan_payable_cents & 0xffff),
            LIMB_BASE
        );
        let rows = vec![row; CalibrationProfile::K128.rows()];
        let (_, final_state) = generate_trace(&rows).unwrap();
        assert_eq!(
            canonical_limbs_to_u64(final_state).unwrap(),
            CalibrationProfile::K128.rows() as u64 * u64::from(payable)
        );
        assert_ne!(final_state[1], M31::zero());
        assert_ne!(final_state[2], M31::zero());
    }

    #[test]
    fn changed_public_total_and_profile_are_rejected() {
        let (mut proof, _) =
            prove_calibration(CalibrationProfile::K128, CalibrationShape::Approval).unwrap();
        proof.statement0.final_state[0] += M31::one();
        assert!(verify_calibration(proof).is_err());

        let (mut proof, _) =
            prove_calibration(CalibrationProfile::K128, CalibrationShape::Approval).unwrap();
        proof.statement0.profile = CalibrationProfile::K256;
        assert_eq!(
            verify_calibration(proof),
            Err("calibration statement profile/row mismatch".to_string())
        );
    }

    #[test]
    fn every_noncanonical_public_final_state_limb_is_rejected_before_verifier_allocation() {
        for limb in 0..STATE_SIZE {
            let (mut proof, _) =
                prove_calibration(CalibrationProfile::K128, CalibrationShape::Approval).unwrap();
            proof.statement0.final_state[limb] = M31::from_u32_unchecked(LIMB_BASE);
            assert_eq!(
                verify_calibration(proof),
                Err("calibration statement final state limb is noncanonical".to_string())
            );
        }
    }

    #[test]
    fn changed_proof_config_is_rejected_by_first_verifier_gate() {
        for mutation in 0..6 {
            let (mut proof, _) =
                prove_calibration(CalibrationProfile::K128, CalibrationShape::Approval).unwrap();
            match mutation {
                0 => proof.stark_proof.0.config.pow_bits += 1,
                1 => proof.stark_proof.0.config.fri_config.n_queries += 1,
                2 => proof.stark_proof.0.config.fri_config.log_blowup_factor += 1,
                3 => {
                    proof
                        .stark_proof
                        .0
                        .config
                        .fri_config
                        .log_last_layer_degree_bound += 1
                }
                4 => proof.stark_proof.0.config.fri_config.fold_step += 1,
                5 => proof.stark_proof.0.config.lifting_log_size = Some(31),
                _ => unreachable!(),
            }
            assert_eq!(
                verify_calibration(proof),
                Err(
                    "calibration verifier rejected proof-selected PCS/FRI configuration"
                        .to_string()
                )
            );
        }
    }

    #[test]
    fn changed_proof_commitment_is_rejected() {
        let (mut proof, _) =
            prove_calibration(CalibrationProfile::K128, CalibrationShape::Approval).unwrap();
        assert_ne!(
            proof.stark_proof.0.commitments[0],
            proof.stark_proof.0.commitments[1]
        );
        proof.stark_proof.0.commitments.swap(0, 1);
        assert!(verify_calibration(proof).is_err());
    }

    #[test]
    fn changed_claimed_sum_and_initial_state_are_rejected() {
        let (mut proof, _) =
            prove_calibration(CalibrationProfile::K128, CalibrationShape::Approval).unwrap();
        proof.statement1.claimed_sum += QM31::one();
        assert!(verify_calibration(proof).is_err());

        let (mut proof, _) =
            prove_calibration(CalibrationProfile::K128, CalibrationShape::Approval).unwrap();
        proof.statement0.initial_state[2] = M31::one();
        assert_eq!(
            verify_calibration(proof),
            Err("calibration statement initial state must be zero".to_string())
        );
    }

    #[test]
    fn maximum_k256_total_crosses_m31_without_narrowing() {
        let report =
            run_calibration(CalibrationProfile::K256, CalibrationShape::MaximumApproval).unwrap();
        assert_eq!(
            report.public_total_plan_payable_cents,
            256_u64 * u64::from(u32::MAX)
        );
        assert!(report.public_total_plan_payable_cents > u64::from(u32::MAX));
    }

    #[test]
    fn all_denial_priorities_round_trip() {
        for code in 1..=FAILURE_GATE_COUNT as u8 {
            let report =
                run_calibration(CalibrationProfile::K128, CalibrationShape::Denial(code)).unwrap();
            assert_eq!(report.public_total_plan_payable_cents, 0);
            assert!(report.proof_discarded);
            assert!(!report.proof_artifact_written);
        }
    }
}
