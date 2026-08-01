#![feature(portable_simd, iter_array_chunks, array_chunks)]

use std::env;
use std::time::{Duration, Instant};

use blind_ledger_stwo_batch_air::security_boundary::{
    enforce_before_trace, ProofSecurityRequirement,
};

use itertools::Itertools;
use num_traits::{One, Zero};
use rayon::prelude::*;
use stwo::core::air::Component;
use stwo::core::channel::{Blake2sChannel, Channel};
use stwo::core::fields::m31::{BaseField, M31};
use stwo::core::fields::qm31::{SecureField, QM31};
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

const STATE_SIZE: usize = 2;
const TRACE_COLUMNS: usize = 6;
const CURRENT_APPROVED: usize = 0;
const CURRENT_PAID: usize = 1;
const REQUESTED: usize = 2;
const APPROVED: usize = 3;
const PAID: usize = 4;
const DECISION: usize = 5;
const M31_MODULUS: u64 = 2_147_483_647;

relation!(BatchStateElements, STATE_SIZE);

type BatchState = [M31; STATE_SIZE];
type BatchComponent = FrameworkComponent<BatchEval>;

#[derive(Clone, Copy, Debug)]
struct Claim {
    requested_cents: u32,
    decision: u32,
}

#[derive(Clone)]
struct BatchEval {
    log_n_rows: u32,
    state_elements: BatchStateElements,
}

impl FrameworkEval for BatchEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let current_approved = eval.next_trace_mask();
        let current_paid = eval.next_trace_mask();
        let requested = eval.next_trace_mask();
        let approved = eval.next_trace_mask();
        let paid = eval.next_trace_mask();
        let decision = eval.next_trace_mask();

        eval.add_constraint(decision.clone() * (decision.clone() - E::F::one()));
        eval.add_constraint(approved.clone() - requested * decision);
        eval.add_constraint(paid.clone() - approved.clone());

        let input_state = [current_approved, current_paid];
        let output_state = [
            input_state[0].clone() + approved,
            input_state[1].clone() + paid,
        ];
        eval.add_to_relation(RelationEntry::new(
            &self.state_elements,
            E::EF::one(),
            &input_state,
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
struct BatchStatement0 {
    log_n_rows: u32,
    initial_state: BatchState,
    final_state: BatchState,
}

impl BatchStatement0 {
    fn log_sizes(&self) -> TreeVec<Vec<u32>> {
        let sizes = batch_info()
            .mask_offsets
            .as_cols_ref()
            .map_cols(|_| self.log_n_rows);
        let mut log_sizes = TreeVec::concat_cols(std::iter::once(sizes));
        log_sizes[PREPROCESSED_TRACE_IDX] = vec![];
        log_sizes
    }

    fn mix_into(&self, channel: &mut impl Channel) {
        channel.mix_u64(self.log_n_rows as u64);
        for value in self.initial_state.iter().chain(self.final_state.iter()) {
            channel.mix_u64(value.0 as u64);
        }
    }
}

#[derive(Clone)]
struct BatchStatement1 {
    claimed_sum: SecureField,
}

impl BatchStatement1 {
    fn mix_into(&self, channel: &mut impl Channel) {
        channel.mix_felts(&[self.claimed_sum]);
    }
}

struct BatchProof {
    statement0: BatchStatement0,
    statement1: BatchStatement1,
    stark_proof: StarkProof<Blake2sMerkleHasher>,
}

#[derive(Default)]
struct ProofTimings {
    twiddles: Duration,
    trace: Duration,
    commitments: Duration,
    interaction: Duration,
    prove: Duration,
}

fn batch_info() -> InfoEvaluator {
    BatchEval {
        log_n_rows: 1,
        state_elements: BatchStateElements::dummy(),
    }
    .evaluate(InfoEvaluator::empty())
}

fn generate_claims(claim_count: usize) -> Vec<Claim> {
    (0..claim_count)
        .into_par_iter()
        .map(|index| Claim {
            requested_cents: (index as u32 % 997) + 1,
            decision: u32::from(!index.is_multiple_of(5)),
        })
        .collect()
}

fn expected_totals(claims: &[Claim]) -> Result<(u32, u32), String> {
    let approved = claims.iter().try_fold(0_u64, |total, claim| {
        total
            .checked_add(claim.requested_cents as u64 * claim.decision as u64)
            .ok_or_else(|| "approved total overflowed u64".to_string())
    })?;
    if approved >= M31_MODULUS {
        return Err("approved total does not fit the M31 field".to_string());
    }
    Ok((approved as u32, approved as u32))
}

fn generate_trace(
    claims: &[Claim],
) -> (
    ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    BatchState,
) {
    let log_n_rows = claims.len().ilog2();
    let domain = CanonicCoset::new(log_n_rows).circle_domain();
    let mut columns = (0..TRACE_COLUMNS)
        .map(|_| vec![M31::zero(); claims.len()])
        .collect_vec();
    let mut state = [M31::zero(); STATE_SIZE];

    for (row, claim) in claims.iter().enumerate() {
        let trace_row = bit_reverse_index(
            coset_index_to_circle_domain_index(row, log_n_rows),
            log_n_rows,
        );
        let requested = M31::from_u32_unchecked(claim.requested_cents);
        let decision = M31::from_u32_unchecked(claim.decision);
        let approved = requested * decision;
        columns[CURRENT_APPROVED][trace_row] = state[0];
        columns[CURRENT_PAID][trace_row] = state[1];
        columns[REQUESTED][trace_row] = requested;
        columns[APPROVED][trace_row] = approved;
        columns[PAID][trace_row] = approved;
        columns[DECISION][trace_row] = decision;
        state[0] += approved;
        state[1] += approved;
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
    (trace, state)
}

fn generate_interaction_trace(
    trace: &ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    state_elements: &BatchStateElements,
) -> (
    ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    SecureField,
) {
    let log_n_rows = trace[0].domain.log_size();
    let mut logup = LogupTraceGenerator::new(log_n_rows);
    let mut column = logup.new_col();
    for packed_row in 0..(1 << (log_n_rows - LOG_N_LANES)) {
        let input_state = [
            trace[CURRENT_APPROVED].data[packed_row],
            trace[CURRENT_PAID].data[packed_row],
        ];
        let output_state: [PackedM31; STATE_SIZE] = [
            input_state[0] + trace[APPROVED].data[packed_row],
            input_state[1] + trace[PAID].data[packed_row],
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

fn build_component(
    allocator: &mut TraceLocationAllocator,
    log_n_rows: u32,
    state_elements: BatchStateElements,
    claimed_sum: SecureField,
) -> BatchComponent {
    BatchComponent::new(
        allocator,
        BatchEval {
            log_n_rows,
            state_elements,
        },
        claimed_sum,
    )
}

fn prove_batch(claims: &[Claim], config: PcsConfig) -> Result<(BatchProof, ProofTimings), String> {
    if !claims.len().is_power_of_two() || claims.len() < (1 << LOG_N_LANES) {
        return Err(format!(
            "claim count must be a power of two and at least {}",
            1 << LOG_N_LANES
        ));
    }
    let log_n_rows = claims.len().ilog2();
    let mut timings = ProofTimings::default();

    let started = Instant::now();
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(log_n_rows + config.fri_config.log_blowup_factor + 1)
            .circle_domain()
            .half_coset,
    );
    timings.twiddles = started.elapsed();

    let started = Instant::now();
    let (trace, final_state) = generate_trace(claims);
    timings.trace = started.elapsed();
    let statement0 = BatchStatement0 {
        log_n_rows,
        initial_state: [M31::zero(); STATE_SIZE],
        final_state,
    };

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

    let state_elements = BatchStateElements::draw(prover_channel);
    let started = Instant::now();
    let (interaction_trace, claimed_sum) = generate_interaction_trace(&trace, &state_elements);
    timings.interaction = started.elapsed();
    let statement1 = BatchStatement1 { claimed_sum };
    statement1.mix_into(prover_channel);

    let started = Instant::now();
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(interaction_trace);
    tree_builder.commit(prover_channel);
    timings.commitments += started.elapsed();

    let mut allocator = TraceLocationAllocator::default();
    let component = build_component(&mut allocator, log_n_rows, state_elements, claimed_sum);
    let started = Instant::now();
    let stark_proof = prove::<SimdBackend, Blake2sMerkleChannel>(
        &[&component as &dyn ComponentProver<SimdBackend>],
        prover_channel,
        commitment_scheme,
    )
    .map_err(|error| format!("Stwo proving failed: {error:?}"))?;
    timings.prove = started.elapsed();

    Ok((
        BatchProof {
            statement0,
            statement1,
            stark_proof,
        },
        timings,
    ))
}

fn verify_batch(proof: BatchProof) -> Result<(), String> {
    let config = proof.stark_proof.config;
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

    let state_elements = BatchStateElements::draw(verifier_channel);
    let initial: QM31 = state_elements.combine(&proof.statement0.initial_state);
    let final_state: QM31 = state_elements.combine(&proof.statement0.final_state);
    if proof.statement1.claimed_sum * initial * final_state != final_state - initial {
        return Err("LogUp claimed sum does not match the public batch totals".to_string());
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
    .map_err(|error| format!("Stwo verification failed: {error:?}"))
}

struct Options {
    claim_count: usize,
    threads: Option<usize>,
    security_requirement: ProofSecurityRequirement,
}

fn parse_options() -> Result<Options, String> {
    let mut claim_count = 1024_usize;
    let mut threads = None;
    let mut security_requirement = ProofSecurityRequirement::ValidityOnly;
    let mut security_mode_seen = false;
    let mut arguments = env::args().skip(1);
    while let Some(argument) = arguments.next() {
        let value = arguments
            .next()
            .ok_or_else(|| format!("missing value for {argument}"))?;
        match argument.as_str() {
            "--claim-count" => {
                claim_count = value
                    .parse()
                    .map_err(|_| "--claim-count must be an integer".to_string())?;
            }
            "--threads" => {
                let parsed: usize = value
                    .parse()
                    .map_err(|_| "--threads must be an integer".to_string())?;
                if parsed == 0 {
                    return Err("--threads must be positive".to_string());
                }
                threads = Some(parsed);
            }
            "--security-mode" => {
                if security_mode_seen {
                    return Err("--security-mode may be supplied only once".to_string());
                }
                security_requirement = ProofSecurityRequirement::parse(&value)?;
                security_mode_seen = true;
            }
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    Ok(Options {
        claim_count,
        threads,
        security_requirement,
    })
}

fn run() -> Result<(), String> {
    let options = parse_options()?;
    enforce_before_trace(options.security_requirement)?;
    if let Some(threads) = options.threads {
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build_global()
            .map_err(|error| format!("unable to configure Rayon: {error}"))?;
    }
    if !options.claim_count.is_power_of_two() || options.claim_count < (1 << LOG_N_LANES) {
        return Err(format!(
            "--claim-count must be a power of two and at least {}",
            1 << LOG_N_LANES
        ));
    }

    let started = Instant::now();
    let claims = generate_claims(options.claim_count);
    let claim_generation = started.elapsed();
    let (expected_approved, expected_paid) = expected_totals(&claims)?;
    let approved_claims = claims.iter().filter(|claim| claim.decision == 1).count();

    let (proof, timings) = prove_batch(&claims, PcsConfig::default())?;
    let public_final_state = proof.statement0.final_state;
    if public_final_state
        != [
            M31::from_u32_unchecked(expected_approved),
            M31::from_u32_unchecked(expected_paid),
        ]
    {
        return Err("generated public totals do not match the source claims".to_string());
    }
    let started = Instant::now();
    verify_batch(proof)?;
    let verify_seconds = started.elapsed();

    println!("claim_rows={}", options.claim_count);
    println!(
        "proof_security_mode={}",
        options.security_requirement.as_str()
    );
    println!("witness_hiding=false");
    println!("approved_claims={approved_claims}");
    println!("denied_claims={}", options.claim_count - approved_claims);
    println!("simd_lanes={}", 1 << LOG_N_LANES);
    println!("rayon_threads={}", rayon::current_num_threads());
    println!(
        "claim_generation_seconds={:.6}",
        claim_generation.as_secs_f64()
    );
    println!("twiddle_seconds={:.6}", timings.twiddles.as_secs_f64());
    println!("trace_seconds={:.6}", timings.trace.as_secs_f64());
    println!(
        "commitment_seconds={:.6}",
        timings.commitments.as_secs_f64()
    );
    println!(
        "logup_interaction_seconds={:.6}",
        timings.interaction.as_secs_f64()
    );
    println!("prove_seconds={:.6}", timings.prove.as_secs_f64());
    println!("verify_seconds={:.6}", verify_seconds.as_secs_f64());
    println!("public_total_approved_cents={expected_approved}");
    println!("public_total_paid_cents={expected_paid}");
    println!("proof_verified=true");
    println!("security_scope=aggregate_decision_and_value_conservation_only");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_batch_proof_round_trips() {
        let claims = generate_claims(1 << LOG_N_LANES);
        let (proof, _) = prove_batch(&claims, PcsConfig::default()).unwrap();
        verify_batch(proof).unwrap();
    }

    #[test]
    fn changed_public_total_is_rejected() {
        let claims = generate_claims(1 << LOG_N_LANES);
        let (mut proof, _) = prove_batch(&claims, PcsConfig::default()).unwrap();
        proof.statement0.final_state[0] += M31::one();
        assert!(verify_batch(proof).is_err());
    }

    #[test]
    fn non_boolean_decision_is_rejected() {
        let claims = vec![
            Claim {
                requested_cents: 100,
                decision: 2,
            };
            1 << LOG_N_LANES
        ];
        let error = prove_batch(&claims, PcsConfig::default())
            .err()
            .expect("non-Boolean decision must fail proving");
        assert!(error.contains("ConstraintsNotSatisfied"));
    }
}
