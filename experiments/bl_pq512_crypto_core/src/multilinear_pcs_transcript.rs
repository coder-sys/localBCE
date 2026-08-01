//! Fail-closed authenticated-public-coin prelude for the selected zkDeepFold PCS.
//!
//! This module freezes only the protocol segment justified directly by the
//! zkDeepFold construction and simulator: two interactive commitments followed
//! by the three-claim, different-size batch sumcheck. It deliberately stops at
//! `ReadyForFoldBatch`; no caller can mistake this state for a complete PCS
//! proof or verifier.

use alloc::vec::Vec;
use core::fmt;

use crate::field::Fp16;
use crate::multilinear_batch_sumcheck::{
    BatchProductSumcheckError, BatchProductSumcheckProof, BatchProductSumcheckState,
};
#[cfg(not(feature = "parallel"))]
use crate::multilinear_batch_sumcheck::{
    equality_evaluations, fold_table, product_round_coefficients, sum_product,
};
#[cfg(feature = "parallel")]
use crate::multilinear_batch_sumcheck::{
    equality_evaluations_parallel, fold_table_parallel, product_round_coefficients_parallel,
    sum_product_parallel,
};
use crate::multilinear_pcs::{
    MLPCS_AUXILIARY_INJECTION_FOLD, MLPCS_AUXILIARY_MASK_VARIABLES,
    MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE, MLPCS_INPUT_LOG_SIZE, PackedGkrInputClaims,
    PackedGkrOutputClaim,
};
use crate::packed_boolean_sumcheck::{PACK_BITS, packed_lagrange_node_weights};

pub const MLPCS_TRANSCRIPT_MAGIC: &[u8; 8] = b"BLPQMLP1";
pub const MLPCS_TRANSCRIPT_VERSION: u16 = 1;
pub const MLPCS_BATCH_CLAIM_COUNT: usize = 3;
pub const MLPCS_PRELUDE_PROOF_MAGIC: &[u8; 8] = b"BLPQMPP1";
pub const MLPCS_PRELUDE_PROOF_VERSION: u16 = 1;
pub const MLPCS_PRELUDE_PROOF_BYTES: usize =
    8 + 2 + 1 + 2 * 64 + MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE as usize * 3 * 64 + 6 * 64;

const MAIN_ROOT_TAG: u8 = 1;
const MAIN_BINDING_TAG: u8 = 2;
const AUXILIARY_ROOT_TAG: u8 = 3;
const AUXILIARY_BINDING_TAG: u8 = 4;
const BATCH_ROUND_TAG: u8 = 5;
const BATCH_TERMINALS_TAG: u8 = 6;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MultilinearPcsPreludeMessage {
    MainRoot([u8; 64]),
    MainBinding(Fp16),
    AuxiliaryRoot([u8; 64]),
    AuxiliaryBinding(Fp16),
    BatchRound {
        ordinal: u16,
        coefficients: [Fp16; 3],
    },
    BatchTerminals {
        left: [Fp16; MLPCS_BATCH_CLAIM_COUNT],
        right: [Fp16; MLPCS_BATCH_CLAIM_COUNT],
    },
}

impl MultilinearPcsPreludeMessage {
    /// Canonical bytes supplied as the prover message to the public-coin round.
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(MLPCS_TRANSCRIPT_MAGIC);
        encoded.extend_from_slice(&MLPCS_TRANSCRIPT_VERSION.to_be_bytes());
        match self {
            Self::MainRoot(root) => {
                encoded.push(MAIN_ROOT_TAG);
                encoded.extend_from_slice(root);
            }
            Self::MainBinding(value) => {
                encoded.push(MAIN_BINDING_TAG);
                encoded.extend_from_slice(&value.encode());
            }
            Self::AuxiliaryRoot(root) => {
                encoded.push(AUXILIARY_ROOT_TAG);
                encoded.extend_from_slice(root);
            }
            Self::AuxiliaryBinding(value) => {
                encoded.push(AUXILIARY_BINDING_TAG);
                encoded.extend_from_slice(&value.encode());
            }
            Self::BatchRound {
                ordinal,
                coefficients,
            } => {
                encoded.push(BATCH_ROUND_TAG);
                encoded.extend_from_slice(&ordinal.to_be_bytes());
                for coefficient in coefficients {
                    encoded.extend_from_slice(&coefficient.encode());
                }
            }
            Self::BatchTerminals { left, right } => {
                encoded.push(BATCH_TERMINALS_TAG);
                for value in left.iter().chain(right) {
                    encoded.extend_from_slice(&value.encode());
                }
            }
        }
        encoded
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MultilinearPcsPreludePhase {
    AwaitMainRoot,
    AwaitMainBindingChallenge,
    AwaitMainBinding,
    AwaitAuxiliaryRoot,
    AwaitAuxiliaryBindingChallenge,
    AwaitAuxiliaryBinding,
    AwaitOpeningClaim,
    AwaitOpeningMixingChallenge,
    AwaitBatchMixingChallenge,
    BatchSumcheck,
    ReadyForFoldBatch,
    Aborted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MultilinearPcsTranscriptError {
    Sequence,
    ZeroRoot,
    PointDimension { expected: usize, actual: usize },
    RoundOrdinal,
    Batch(BatchProductSumcheckError),
    EncodingLength,
    Truncated,
    NonZeroReserved,
    Magic,
    Version,
    Field,
}

impl From<BatchProductSumcheckError> for MultilinearPcsTranscriptError {
    fn from(value: BatchProductSumcheckError) -> Self {
        Self::Batch(value)
    }
}

impl fmt::Display for MultilinearPcsTranscriptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "BL-PQ512 multilinear PCS transcript error: {self:?}"
        )
    }
}

impl core::error::Error for MultilinearPcsTranscriptError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultilinearPcsPreludeProof {
    pub main_binding: Fp16,
    pub auxiliary_binding: Fp16,
    pub batch_rounds: Vec<[Fp16; 3]>,
    pub terminal_left: [Fp16; MLPCS_BATCH_CLAIM_COUNT],
    pub terminal_right: [Fp16; MLPCS_BATCH_CLAIM_COUNT],
}

impl MultilinearPcsPreludeProof {
    pub fn encode(&self) -> Result<Vec<u8>, MultilinearPcsTranscriptError> {
        if self.batch_rounds.len() != usize::from(MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE) {
            return Err(MultilinearPcsTranscriptError::EncodingLength);
        }
        let mut encoded = Vec::with_capacity(MLPCS_PRELUDE_PROOF_BYTES);
        encoded.extend_from_slice(MLPCS_PRELUDE_PROOF_MAGIC);
        encoded.extend_from_slice(&MLPCS_PRELUDE_PROOF_VERSION.to_be_bytes());
        encoded.push(0);
        encoded.extend_from_slice(&self.main_binding.encode());
        encoded.extend_from_slice(&self.auxiliary_binding.encode());
        for round in &self.batch_rounds {
            for coefficient in round {
                encoded.extend_from_slice(&coefficient.encode());
            }
        }
        for value in self.terminal_left.iter().chain(&self.terminal_right) {
            encoded.extend_from_slice(&value.encode());
        }
        if encoded.len() != MLPCS_PRELUDE_PROOF_BYTES {
            return Err(MultilinearPcsTranscriptError::EncodingLength);
        }
        Ok(encoded)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, MultilinearPcsTranscriptError> {
        if encoded.len() != MLPCS_PRELUDE_PROOF_BYTES {
            return Err(MultilinearPcsTranscriptError::EncodingLength);
        }
        let mut offset = 0_usize;
        let mut take = |length: usize| {
            let end = offset
                .checked_add(length)
                .ok_or(MultilinearPcsTranscriptError::Truncated)?;
            let value = encoded
                .get(offset..end)
                .ok_or(MultilinearPcsTranscriptError::Truncated)?;
            offset = end;
            Ok::<_, MultilinearPcsTranscriptError>(value)
        };
        if take(8)? != MLPCS_PRELUDE_PROOF_MAGIC {
            return Err(MultilinearPcsTranscriptError::Magic);
        }
        if u16::from_be_bytes(
            take(2)?
                .try_into()
                .map_err(|_| MultilinearPcsTranscriptError::Truncated)?,
        ) != MLPCS_PRELUDE_PROOF_VERSION
        {
            return Err(MultilinearPcsTranscriptError::Version);
        }
        if take(1)? != [0] {
            return Err(MultilinearPcsTranscriptError::NonZeroReserved);
        }
        let (main_binding, auxiliary_binding, batch_rounds, terminal_left, terminal_right) = {
            let mut field =
                || Fp16::decode(take(64)?).map_err(|_| MultilinearPcsTranscriptError::Field);
            let main_binding = field()?;
            let auxiliary_binding = field()?;
            let batch_rounds = (0..usize::from(MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE))
                .map(|_| Ok([field()?, field()?, field()?]))
                .collect::<Result<Vec<_>, MultilinearPcsTranscriptError>>()?;
            let terminal_left = [field()?, field()?, field()?];
            let terminal_right = [field()?, field()?, field()?];
            (
                main_binding,
                auxiliary_binding,
                batch_rounds,
                terminal_left,
                terminal_right,
            )
        };
        if offset != encoded.len() {
            return Err(MultilinearPcsTranscriptError::EncodingLength);
        }
        Ok(Self {
            main_binding,
            auxiliary_binding,
            batch_rounds,
            terminal_left,
            terminal_right,
        })
    }
}

/// Point `(alpha, alpha^2, alpha^4, ...)` binding a univariate twin polynomial
/// to its multilinear polynomial.
pub fn twin_multilinear_point(alpha: Fp16, variables: usize) -> Vec<Fp16> {
    let mut point = Vec::with_capacity(variables);
    let mut coordinate = alpha;
    for _ in 0..variables {
        point.push(coordinate);
        coordinate = coordinate.square();
    }
    point
}

/// Exact three claims reduced by the zkDeepFold simulator's batch sumcheck.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZkDeepFoldBatchClaimPoints {
    pub packed_opening: PackedGkrInputClaims,
    pub opening_mixing: Fp16,
    pub main_binding: Vec<Fp16>,
    pub auxiliary_binding: Vec<Fp16>,
}

pub struct MultilinearPcsPreludeState {
    phase: MultilinearPcsPreludePhase,
    main_binding_challenge: Option<Fp16>,
    main_binding_value: Option<Fp16>,
    auxiliary_binding_challenge: Option<Fp16>,
    auxiliary_binding_value: Option<Fp16>,
    opening_claims: Option<PackedGkrInputClaims>,
    opening_mixing_challenge: Option<Fp16>,
    batch_claim_points: Option<ZkDeepFoldBatchClaimPoints>,
    batch_challenges: Vec<Fp16>,
    batch_state: Option<BatchProductSumcheckState>,
    batch_round: usize,
}

impl MultilinearPcsPreludeState {
    pub fn new() -> Self {
        Self {
            phase: MultilinearPcsPreludePhase::AwaitMainRoot,
            main_binding_challenge: None,
            main_binding_value: None,
            auxiliary_binding_challenge: None,
            auxiliary_binding_value: None,
            opening_claims: None,
            opening_mixing_challenge: None,
            batch_claim_points: None,
            batch_challenges: Vec::with_capacity(usize::from(MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE)),
            batch_state: None,
            batch_round: 0,
        }
    }

    pub const fn phase(&self) -> MultilinearPcsPreludePhase {
        self.phase
    }

    fn require_phase(
        &mut self,
        expected: MultilinearPcsPreludePhase,
    ) -> Result<(), MultilinearPcsTranscriptError> {
        if self.phase != expected {
            self.phase = MultilinearPcsPreludePhase::Aborted;
            return Err(MultilinearPcsTranscriptError::Sequence);
        }
        Ok(())
    }

    fn require_root(root: &[u8; 64]) -> Result<(), MultilinearPcsTranscriptError> {
        if !root.iter().any(|byte| *byte != 0) {
            return Err(MultilinearPcsTranscriptError::ZeroRoot);
        }
        Ok(())
    }

    pub fn publish_main_root(
        &mut self,
        root: [u8; 64],
    ) -> Result<MultilinearPcsPreludeMessage, MultilinearPcsTranscriptError> {
        self.require_phase(MultilinearPcsPreludePhase::AwaitMainRoot)?;
        if let Err(error) = Self::require_root(&root) {
            self.phase = MultilinearPcsPreludePhase::Aborted;
            return Err(error);
        }
        self.phase = MultilinearPcsPreludePhase::AwaitMainBindingChallenge;
        Ok(MultilinearPcsPreludeMessage::MainRoot(root))
    }

    pub fn accept_main_binding_challenge(
        &mut self,
        challenge: Fp16,
    ) -> Result<(), MultilinearPcsTranscriptError> {
        self.require_phase(MultilinearPcsPreludePhase::AwaitMainBindingChallenge)?;
        self.main_binding_challenge = Some(challenge);
        self.phase = MultilinearPcsPreludePhase::AwaitMainBinding;
        Ok(())
    }

    pub fn publish_main_binding(
        &mut self,
        value: Fp16,
    ) -> Result<MultilinearPcsPreludeMessage, MultilinearPcsTranscriptError> {
        self.require_phase(MultilinearPcsPreludePhase::AwaitMainBinding)?;
        self.main_binding_value = Some(value);
        self.phase = MultilinearPcsPreludePhase::AwaitAuxiliaryRoot;
        Ok(MultilinearPcsPreludeMessage::MainBinding(value))
    }

    pub fn publish_auxiliary_root(
        &mut self,
        root: [u8; 64],
    ) -> Result<MultilinearPcsPreludeMessage, MultilinearPcsTranscriptError> {
        self.require_phase(MultilinearPcsPreludePhase::AwaitAuxiliaryRoot)?;
        if let Err(error) = Self::require_root(&root) {
            self.phase = MultilinearPcsPreludePhase::Aborted;
            return Err(error);
        }
        self.phase = MultilinearPcsPreludePhase::AwaitAuxiliaryBindingChallenge;
        Ok(MultilinearPcsPreludeMessage::AuxiliaryRoot(root))
    }

    pub fn accept_auxiliary_binding_challenge(
        &mut self,
        challenge: Fp16,
    ) -> Result<(), MultilinearPcsTranscriptError> {
        self.require_phase(MultilinearPcsPreludePhase::AwaitAuxiliaryBindingChallenge)?;
        self.auxiliary_binding_challenge = Some(challenge);
        self.phase = MultilinearPcsPreludePhase::AwaitAuxiliaryBinding;
        Ok(())
    }

    pub fn publish_auxiliary_binding(
        &mut self,
        value: Fp16,
    ) -> Result<MultilinearPcsPreludeMessage, MultilinearPcsTranscriptError> {
        self.require_phase(MultilinearPcsPreludePhase::AwaitAuxiliaryBinding)?;
        self.auxiliary_binding_value = Some(value);
        self.phase = MultilinearPcsPreludePhase::AwaitOpeningClaim;
        Ok(MultilinearPcsPreludeMessage::AuxiliaryBinding(value))
    }

    /// Fix both GKR terminal openings before their mixing challenge.
    pub fn fix_opening_claims(
        &mut self,
        claims: &PackedGkrInputClaims,
    ) -> Result<(), MultilinearPcsTranscriptError> {
        self.require_phase(MultilinearPcsPreludePhase::AwaitOpeningClaim)?;
        let expected = usize::from(MLPCS_INPUT_LOG_SIZE) - PACK_BITS.trailing_zeros() as usize;
        if usize::from(claims.wire_variables) > expected {
            self.phase = MultilinearPcsPreludePhase::Aborted;
            return Err(MultilinearPcsTranscriptError::PointDimension {
                expected,
                actual: usize::from(claims.wire_variables),
            });
        }
        if let Some(actual) = claims
            .claims
            .iter()
            .map(|claim| claim.point.len())
            .find(|actual| *actual != expected)
        {
            self.phase = MultilinearPcsPreludePhase::Aborted;
            return Err(MultilinearPcsTranscriptError::PointDimension { expected, actual });
        }
        self.opening_claims = Some(claims.clone());
        self.phase = MultilinearPcsPreludePhase::AwaitOpeningMixingChallenge;
        Ok(())
    }

    pub fn accept_opening_mixing_challenge(
        &mut self,
        challenge: Fp16,
    ) -> Result<(), MultilinearPcsTranscriptError> {
        self.require_phase(MultilinearPcsPreludePhase::AwaitOpeningMixingChallenge)?;
        self.opening_mixing_challenge = Some(challenge);
        self.phase = MultilinearPcsPreludePhase::AwaitBatchMixingChallenge;
        Ok(())
    }

    /// Accept the mix only after all three claims are fixed.
    pub fn accept_batch_mixing_challenge(
        &mut self,
        challenge: Fp16,
    ) -> Result<ZkDeepFoldBatchClaimPoints, MultilinearPcsTranscriptError> {
        self.require_phase(MultilinearPcsPreludePhase::AwaitBatchMixingChallenge)?;
        let openings = self
            .opening_claims
            .clone()
            .ok_or(MultilinearPcsTranscriptError::Sequence)?;
        let opening_mixing = self
            .opening_mixing_challenge
            .ok_or(MultilinearPcsTranscriptError::Sequence)?;
        let main_alpha = self
            .main_binding_challenge
            .ok_or(MultilinearPcsTranscriptError::Sequence)?;
        let auxiliary_alpha = self
            .auxiliary_binding_challenge
            .ok_or(MultilinearPcsTranscriptError::Sequence)?;
        let auxiliary_normalizer = auxiliary_lift_normalizer()?;
        let claimed_sums = [
            openings.claims[0].value + opening_mixing * openings.claims[1].value,
            self.main_binding_value
                .ok_or(MultilinearPcsTranscriptError::Sequence)?,
            self.auxiliary_binding_value
                .ok_or(MultilinearPcsTranscriptError::Sequence)?
                * auxiliary_normalizer,
        ];
        let variable_counts = [
            usize::from(MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE),
            usize::from(MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE),
            usize::from(MLPCS_AUXILIARY_MASK_VARIABLES),
        ];
        self.batch_state = Some(BatchProductSumcheckState::new(
            &claimed_sums,
            &variable_counts,
            usize::from(MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE),
            challenge,
        )?);
        let points = ZkDeepFoldBatchClaimPoints {
            packed_opening: openings,
            opening_mixing,
            main_binding: twin_multilinear_point(
                main_alpha,
                usize::from(MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE),
            ),
            auxiliary_binding: twin_multilinear_point(
                auxiliary_alpha,
                usize::from(MLPCS_AUXILIARY_MASK_VARIABLES),
            ),
        };
        self.batch_claim_points = Some(points.clone());
        self.phase = MultilinearPcsPreludePhase::BatchSumcheck;
        Ok(points)
    }

    pub fn publish_batch_round(
        &mut self,
        coefficients: [Fp16; 3],
    ) -> Result<MultilinearPcsPreludeMessage, MultilinearPcsTranscriptError> {
        self.require_phase(MultilinearPcsPreludePhase::BatchSumcheck)?;
        if self.batch_round >= usize::from(MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE) {
            self.phase = MultilinearPcsPreludePhase::Aborted;
            return Err(MultilinearPcsTranscriptError::RoundOrdinal);
        }
        if let Err(error) = self
            .batch_state
            .as_mut()
            .ok_or(MultilinearPcsTranscriptError::Sequence)?
            .publish_round(coefficients)
        {
            self.phase = MultilinearPcsPreludePhase::Aborted;
            return Err(error.into());
        }
        Ok(MultilinearPcsPreludeMessage::BatchRound {
            ordinal: self.batch_round as u16,
            coefficients,
        })
    }

    pub fn accept_batch_round_challenge(
        &mut self,
        challenge: Fp16,
    ) -> Result<(), MultilinearPcsTranscriptError> {
        self.require_phase(MultilinearPcsPreludePhase::BatchSumcheck)?;
        if let Err(error) = self
            .batch_state
            .as_mut()
            .ok_or(MultilinearPcsTranscriptError::Sequence)?
            .accept_authenticated_challenge(challenge)
        {
            self.phase = MultilinearPcsPreludePhase::Aborted;
            return Err(error.into());
        }
        self.batch_round += 1;
        self.batch_challenges.push(challenge);
        Ok(())
    }

    pub fn finish_batch_sumcheck(
        &mut self,
        left: [Fp16; MLPCS_BATCH_CLAIM_COUNT],
        right: [Fp16; MLPCS_BATCH_CLAIM_COUNT],
    ) -> Result<
        (MultilinearPcsPreludeMessage, BatchProductSumcheckProof),
        MultilinearPcsTranscriptError,
    > {
        self.require_phase(MultilinearPcsPreludePhase::BatchSumcheck)?;
        if self.batch_round != usize::from(MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE) {
            self.phase = MultilinearPcsPreludePhase::Aborted;
            return Err(MultilinearPcsTranscriptError::RoundOrdinal);
        }
        let points = self
            .batch_claim_points
            .as_ref()
            .ok_or(MultilinearPcsTranscriptError::Sequence)?;
        if left[0] != left[1]
            || right[0]
                != packed_opening_terminal(
                    &points.packed_opening,
                    points.opening_mixing,
                    &self.batch_challenges,
                )?
            || right[1] != equality_at_point(&points.main_binding, &self.batch_challenges)?
            || right[2]
                != equality_at_point(
                    &points.auxiliary_binding,
                    &self.batch_challenges[usize::from(MLPCS_AUXILIARY_INJECTION_FOLD)..],
                )? * auxiliary_lift_normalizer()?
        {
            self.phase = MultilinearPcsPreludePhase::Aborted;
            return Err(MultilinearPcsTranscriptError::Batch(
                BatchProductSumcheckError::Terminal,
            ));
        }
        let result = self
            .batch_state
            .take()
            .ok_or(MultilinearPcsTranscriptError::Sequence)?
            .finish(&left, &right);
        let proof = match result {
            Ok(proof) => proof,
            Err(error) => {
                self.phase = MultilinearPcsPreludePhase::Aborted;
                return Err(error.into());
            }
        };
        self.phase = MultilinearPcsPreludePhase::ReadyForFoldBatch;
        Ok((
            MultilinearPcsPreludeMessage::BatchTerminals { left, right },
            proof,
        ))
    }
}

/// Normalize an 18-variable claim lifted through four ignored prefix variables.
///
/// Without this factor the full 22-variable Boolean sum contains sixteen
/// copies of the auxiliary claim. Scaling by `2^-4` restores the exact
/// `mix^2 * c_aux` claim used by the zkDeepFold simulator.
fn auxiliary_lift_normalizer() -> Result<Fp16, MultilinearPcsTranscriptError> {
    let two = Fp16::ONE + Fp16::ONE;
    let lift = (0..MLPCS_AUXILIARY_INJECTION_FOLD).fold(Fp16::ONE, |value, _| value * two);
    lift.inverse()
        .map_err(|_| MultilinearPcsTranscriptError::Field)
}

fn equality_at_point(
    point: &[Fp16],
    challenge: &[Fp16],
) -> Result<Fp16, MultilinearPcsTranscriptError> {
    if point.len() != challenge.len() {
        return Err(MultilinearPcsTranscriptError::PointDimension {
            expected: point.len(),
            actual: challenge.len(),
        });
    }
    Ok(point.iter().copied().zip(challenge.iter().copied()).fold(
        Fp16::ONE,
        |value, (expected, observed)| {
            value * (expected * observed + (Fp16::ONE - expected) * (Fp16::ONE - observed))
        },
    ))
}

fn multilinear_table_evaluation(
    table: &[Fp16],
    point: &[Fp16],
) -> Result<Fp16, MultilinearPcsTranscriptError> {
    if table.len() != 1_usize << point.len() {
        return Err(MultilinearPcsTranscriptError::PointDimension {
            expected: 1_usize << point.len(),
            actual: table.len(),
        });
    }
    let mut folded = table.to_vec();
    let mut active = folded.len();
    for challenge in point {
        for index in 0..active / 2 {
            let left = folded[2 * index];
            let right = folded[2 * index + 1];
            folded[index] = left + *challenge * (right - left);
        }
        active /= 2;
    }
    Ok(folded[0])
}

fn packed_opening_terminal(
    claims: &PackedGkrInputClaims,
    opening_mixing: Fp16,
    challenge: &[Fp16],
) -> Result<Fp16, MultilinearPcsTranscriptError> {
    let input_variables = usize::from(MLPCS_INPUT_LOG_SIZE);
    let shard_variables = PACK_BITS.trailing_zeros() as usize;
    let wire_variables = usize::from(claims.wire_variables);
    if challenge.len() != input_variables + 1
        || claims
            .claims
            .iter()
            .any(|claim| claim.point.len() != input_variables - shard_variables)
        || wire_variables > input_variables - shard_variables
    {
        return Err(MultilinearPcsTranscriptError::PointDimension {
            expected: input_variables + 1,
            actual: challenge.len(),
        });
    }
    let mut base_challenge = Vec::with_capacity(input_variables - shard_variables);
    base_challenge.extend_from_slice(&challenge[..wire_variables]);
    base_challenge.extend_from_slice(&challenge[wire_variables + shard_variables..input_variables]);
    let lagrange = packed_lagrange_node_weights(claims.shard_query)
        .map_err(|_| MultilinearPcsTranscriptError::Field)?;
    let shard_factor = evaluate_small_multilinear(
        &lagrange,
        &challenge[wire_variables..wire_variables + shard_variables],
    )?;
    let base = equality_at_point(&claims.claims[0].point, &base_challenge)?
        + opening_mixing * equality_at_point(&claims.claims[1].point, &base_challenge)?;
    Ok(base * shard_factor * (Fp16::ONE - challenge[input_variables]))
}

fn evaluate_small_multilinear(
    evaluations: &[Fp16],
    point: &[Fp16],
) -> Result<Fp16, MultilinearPcsTranscriptError> {
    if evaluations.len() != 1_usize << point.len() {
        return Err(MultilinearPcsTranscriptError::PointDimension {
            expected: evaluations.len().ilog2() as usize,
            actual: point.len(),
        });
    }
    let mut folded = evaluations.to_vec();
    let mut active = folded.len();
    for challenge in point {
        for index in 0..active / 2 {
            folded[index] =
                folded[2 * index] + *challenge * (folded[2 * index + 1] - folded[2 * index]);
        }
        active /= 2;
    }
    Ok(folded[0])
}

fn packed_opening_weights(
    claims: &PackedGkrInputClaims,
    opening_mixing: Fp16,
    workers: usize,
) -> Result<Vec<Fp16>, MultilinearPcsTranscriptError> {
    let input_variables = usize::from(MLPCS_INPUT_LOG_SIZE);
    let shard_variables = PACK_BITS.trailing_zeros() as usize;
    let base_variables = input_variables - shard_variables;
    let wire_variables = usize::from(claims.wire_variables);
    if workers == 0
        || wire_variables > base_variables
        || claims
            .claims
            .iter()
            .any(|claim| claim.point.len() != base_variables)
    {
        return Err(MultilinearPcsTranscriptError::PointDimension {
            expected: base_variables,
            actual: claims.claims[0].point.len(),
        });
    }
    #[cfg(feature = "parallel")]
    let first = equality_evaluations_parallel(&claims.claims[0].point, workers)?;
    #[cfg(not(feature = "parallel"))]
    let first = equality_evaluations(&claims.claims[0].point)?;
    #[cfg(feature = "parallel")]
    let second = equality_evaluations_parallel(&claims.claims[1].point, workers)?;
    #[cfg(not(feature = "parallel"))]
    let second = equality_evaluations(&claims.claims[1].point)?;
    let lagrange = packed_lagrange_node_weights(claims.shard_query)
        .map_err(|_| MultilinearPcsTranscriptError::Field)?;
    let raw_count = 1_usize << input_variables;
    let mut weights = alloc::vec![Fp16::ZERO; 2 * raw_count];
    let wire_mask = (1_usize << wire_variables) - 1;
    #[cfg(feature = "parallel")]
    {
        let chunk = raw_count.div_ceil(workers.min(raw_count));
        std::thread::scope(|scope| {
            for (chunk_ordinal, output) in weights[..raw_count].chunks_mut(chunk).enumerate() {
                let start = chunk_ordinal * chunk;
                let first = &first;
                let second = &second;
                let lagrange = &lagrange;
                scope.spawn(move || {
                    for (offset, value) in output.iter_mut().enumerate() {
                        let raw_index = start + offset;
                        let wire = raw_index & wire_mask;
                        let shard = (raw_index >> wire_variables) & (PACK_BITS - 1);
                        let group = raw_index >> (wire_variables + shard_variables);
                        let base_index = wire | (group << wire_variables);
                        *value = (first[base_index] + opening_mixing * second[base_index])
                            * lagrange[shard];
                    }
                });
            }
        });
    }
    #[cfg(not(feature = "parallel"))]
    for (raw_index, value) in weights[..raw_count].iter_mut().enumerate() {
        let wire = raw_index & wire_mask;
        let shard = (raw_index >> wire_variables) & (PACK_BITS - 1);
        let group = raw_index >> (wire_variables + shard_variables);
        let base_index = wire | (group << wire_variables);
        *value = (first[base_index] + opening_mixing * second[base_index]) * lagrange[shard];
    }
    Ok(weights)
}

fn packed_output_terminal(
    claim: &PackedGkrOutputClaim,
    challenge: &[Fp16],
) -> Result<Fp16, MultilinearPcsTranscriptError> {
    let input_variables = usize::from(MLPCS_INPUT_LOG_SIZE);
    let shard_variables = PACK_BITS.trailing_zeros() as usize;
    let wire_variables = usize::from(claim.wire_variables);
    if challenge.len() != input_variables + 1
        || claim.claim.point.len() != input_variables - shard_variables
        || wire_variables > input_variables - shard_variables
    {
        return Err(MultilinearPcsTranscriptError::PointDimension {
            expected: input_variables + 1,
            actual: challenge.len(),
        });
    }
    let mut base_challenge = Vec::with_capacity(input_variables - shard_variables);
    base_challenge.extend_from_slice(&challenge[..wire_variables]);
    base_challenge.extend_from_slice(&challenge[wire_variables + shard_variables..input_variables]);
    let lagrange = packed_lagrange_node_weights(claim.shard_query)
        .map_err(|_| MultilinearPcsTranscriptError::Field)?;
    let shard_factor = evaluate_small_multilinear(
        &lagrange,
        &challenge[wire_variables..wire_variables + shard_variables],
    )?;
    Ok(equality_at_point(&claim.claim.point, &base_challenge)?
        * shard_factor
        * (Fp16::ONE - challenge[input_variables]))
}

fn packed_output_weights(
    claim: &PackedGkrOutputClaim,
    workers: usize,
) -> Result<Vec<Fp16>, MultilinearPcsTranscriptError> {
    let input_variables = usize::from(MLPCS_INPUT_LOG_SIZE);
    let shard_variables = PACK_BITS.trailing_zeros() as usize;
    let base_variables = input_variables - shard_variables;
    let wire_variables = usize::from(claim.wire_variables);
    if workers == 0 || wire_variables > base_variables || claim.claim.point.len() != base_variables
    {
        return Err(MultilinearPcsTranscriptError::PointDimension {
            expected: base_variables,
            actual: claim.claim.point.len(),
        });
    }
    #[cfg(feature = "parallel")]
    let equality = equality_evaluations_parallel(&claim.claim.point, workers)?;
    #[cfg(not(feature = "parallel"))]
    let equality = equality_evaluations(&claim.claim.point)?;
    let lagrange = packed_lagrange_node_weights(claim.shard_query)
        .map_err(|_| MultilinearPcsTranscriptError::Field)?;
    let raw_count = 1_usize << input_variables;
    let mut weights = alloc::vec![Fp16::ZERO; 2 * raw_count];
    let wire_mask = (1_usize << wire_variables) - 1;
    #[cfg(feature = "parallel")]
    {
        let chunk = raw_count.div_ceil(workers.min(raw_count));
        std::thread::scope(|scope| {
            for (chunk_ordinal, output) in weights[..raw_count].chunks_mut(chunk).enumerate() {
                let start = chunk_ordinal * chunk;
                let equality = &equality;
                let lagrange = &lagrange;
                scope.spawn(move || {
                    for (offset, value) in output.iter_mut().enumerate() {
                        let raw_index = start + offset;
                        let wire = raw_index & wire_mask;
                        let shard = (raw_index >> wire_variables) & (PACK_BITS - 1);
                        let group = raw_index >> (wire_variables + shard_variables);
                        let base_index = wire | (group << wire_variables);
                        *value = equality[base_index] * lagrange[shard];
                    }
                });
            }
        });
    }
    #[cfg(not(feature = "parallel"))]
    for (raw_index, value) in weights[..raw_count].iter_mut().enumerate() {
        let wire = raw_index & wire_mask;
        let shard = (raw_index >> wire_variables) & (PACK_BITS - 1);
        let group = raw_index >> (wire_variables + shard_variables);
        let base_index = wire | (group << wire_variables);
        *value = equality[base_index] * lagrange[shard];
    }
    Ok(weights)
}

pub const MLPCS_DUAL_BATCH_CLAIM_COUNT: usize = 6;
pub const MLPCS_DUAL_PRELUDE_MAGIC: &[u8; 8] = b"BLPQDPP1";
pub const MLPCS_DUAL_PRELUDE_VERSION: u16 = 2;
pub const MLPCS_DUAL_PRELUDE_BYTES: usize = 8
    + 2
    + 1
    + 3 * 64
    + MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE as usize * 3 * 64
    + 2 * MLPCS_DUAL_BATCH_CLAIM_COUNT * 64;

/// Fixed-shape hiding prelude for both semantic state boundaries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DualBoundaryMultilinearPcsPreludeProof {
    pub input_binding: Fp16,
    pub output_binding: Fp16,
    pub auxiliary_binding: Fp16,
    pub batch_rounds: Vec<[Fp16; 3]>,
    pub terminal_left: [Fp16; MLPCS_DUAL_BATCH_CLAIM_COUNT],
    pub terminal_right: [Fp16; MLPCS_DUAL_BATCH_CLAIM_COUNT],
}

impl DualBoundaryMultilinearPcsPreludeProof {
    pub fn encode(&self) -> Result<Vec<u8>, MultilinearPcsTranscriptError> {
        if self.batch_rounds.len() != usize::from(MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE) {
            return Err(MultilinearPcsTranscriptError::EncodingLength);
        }
        let mut encoded = Vec::with_capacity(MLPCS_DUAL_PRELUDE_BYTES);
        encoded.extend_from_slice(MLPCS_DUAL_PRELUDE_MAGIC);
        encoded.extend_from_slice(&MLPCS_DUAL_PRELUDE_VERSION.to_be_bytes());
        encoded.push(0);
        for value in [
            self.input_binding,
            self.output_binding,
            self.auxiliary_binding,
        ] {
            encoded.extend_from_slice(&value.encode());
        }
        for round in &self.batch_rounds {
            for coefficient in round {
                encoded.extend_from_slice(&coefficient.encode());
            }
        }
        for value in self.terminal_left.iter().chain(&self.terminal_right) {
            encoded.extend_from_slice(&value.encode());
        }
        if encoded.len() != MLPCS_DUAL_PRELUDE_BYTES {
            return Err(MultilinearPcsTranscriptError::EncodingLength);
        }
        Ok(encoded)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, MultilinearPcsTranscriptError> {
        if encoded.len() != MLPCS_DUAL_PRELUDE_BYTES {
            return Err(MultilinearPcsTranscriptError::EncodingLength);
        }
        let mut reader = super_reader::Reader::new(encoded);
        if reader.take(8)? != MLPCS_DUAL_PRELUDE_MAGIC {
            return Err(MultilinearPcsTranscriptError::Magic);
        }
        if u16::from_be_bytes(
            reader
                .take(2)?
                .try_into()
                .map_err(|_| MultilinearPcsTranscriptError::Truncated)?,
        ) != MLPCS_DUAL_PRELUDE_VERSION
        {
            return Err(MultilinearPcsTranscriptError::Version);
        }
        if reader.take(1)? != [0] {
            return Err(MultilinearPcsTranscriptError::NonZeroReserved);
        }
        let input_binding = reader.field()?;
        let output_binding = reader.field()?;
        let auxiliary_binding = reader.field()?;
        let batch_rounds = (0..usize::from(MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE))
            .map(|_| Ok([reader.field()?, reader.field()?, reader.field()?]))
            .collect::<Result<Vec<_>, MultilinearPcsTranscriptError>>()?;
        let mut terminal_left = [Fp16::ZERO; MLPCS_DUAL_BATCH_CLAIM_COUNT];
        let mut terminal_right = [Fp16::ZERO; MLPCS_DUAL_BATCH_CLAIM_COUNT];
        for value in &mut terminal_left {
            *value = reader.field()?;
        }
        for value in &mut terminal_right {
            *value = reader.field()?;
        }
        reader.finish()?;
        Ok(Self {
            input_binding,
            output_binding,
            auxiliary_binding,
            batch_rounds,
            terminal_left,
            terminal_right,
        })
    }
}

mod super_reader {
    use super::{Fp16, MultilinearPcsTranscriptError};

    pub(super) struct Reader<'a> {
        bytes: &'a [u8],
        offset: usize,
    }

    impl<'a> Reader<'a> {
        pub(super) fn new(bytes: &'a [u8]) -> Self {
            Self { bytes, offset: 0 }
        }

        pub(super) fn take(
            &mut self,
            length: usize,
        ) -> Result<&'a [u8], MultilinearPcsTranscriptError> {
            let end = self
                .offset
                .checked_add(length)
                .ok_or(MultilinearPcsTranscriptError::Truncated)?;
            let value = self
                .bytes
                .get(self.offset..end)
                .ok_or(MultilinearPcsTranscriptError::Truncated)?;
            self.offset = end;
            Ok(value)
        }

        pub(super) fn field(&mut self) -> Result<Fp16, MultilinearPcsTranscriptError> {
            Fp16::decode(self.take(64)?).map_err(|_| MultilinearPcsTranscriptError::Field)
        }

        pub(super) fn finish(self) -> Result<(), MultilinearPcsTranscriptError> {
            if self.offset != self.bytes.len() {
                return Err(MultilinearPcsTranscriptError::EncodingLength);
            }
            Ok(())
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn verify_dual_boundary_multilinear_pcs_prelude(
    proof: &DualBoundaryMultilinearPcsPreludeProof,
    input_root: [u8; 64],
    output_root: [u8; 64],
    auxiliary_root: [u8; 64],
    input_binding_challenge: Fp16,
    output_binding_challenge: Fp16,
    auxiliary_binding_challenge: Fp16,
    input_opening_claims: &PackedGkrInputClaims,
    input_opening_mixing_challenge: Fp16,
    output_opening_claim: &PackedGkrOutputClaim,
    batch_mixing_challenge: Fp16,
    batch_challenges: &[Fp16],
) -> Result<[Fp16; 3], MultilinearPcsTranscriptError> {
    let auxiliary_size = 1_usize << usize::from(MLPCS_AUXILIARY_MASK_VARIABLES);
    verify_dual_boundary_multilinear_pcs_prelude_with_gkr_mask_opening(
        proof,
        input_root,
        output_root,
        auxiliary_root,
        input_binding_challenge,
        output_binding_challenge,
        auxiliary_binding_challenge,
        input_opening_claims,
        input_opening_mixing_challenge,
        output_opening_claim,
        batch_mixing_challenge,
        batch_challenges,
        &alloc::vec![Fp16::ZERO; auxiliary_size],
        Fp16::ZERO,
    )
}

/// Verify the dual-boundary prelude and one GKR mask functional against the
/// same committed auxiliary polynomial.
#[allow(clippy::too_many_arguments)]
pub fn verify_dual_boundary_multilinear_pcs_prelude_with_gkr_mask_opening(
    proof: &DualBoundaryMultilinearPcsPreludeProof,
    input_root: [u8; 64],
    output_root: [u8; 64],
    auxiliary_root: [u8; 64],
    input_binding_challenge: Fp16,
    output_binding_challenge: Fp16,
    auxiliary_binding_challenge: Fp16,
    input_opening_claims: &PackedGkrInputClaims,
    input_opening_mixing_challenge: Fp16,
    output_opening_claim: &PackedGkrOutputClaim,
    batch_mixing_challenge: Fp16,
    batch_challenges: &[Fp16],
    gkr_mask_weights: &[Fp16],
    gkr_mask_opening: Fp16,
) -> Result<[Fp16; 3], MultilinearPcsTranscriptError> {
    if [&input_root, &output_root, &auxiliary_root]
        .into_iter()
        .any(|root| !root.iter().any(|byte| *byte != 0))
    {
        return Err(MultilinearPcsTranscriptError::ZeroRoot);
    }
    if proof.batch_rounds.len() != usize::from(MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE)
        || batch_challenges.len() != usize::from(MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE)
    {
        return Err(MultilinearPcsTranscriptError::RoundOrdinal);
    }
    let input_opening = input_opening_claims.claims[0].value
        + input_opening_mixing_challenge * input_opening_claims.claims[1].value;
    let normalizer = auxiliary_lift_normalizer()?;
    let main_variables = usize::from(MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE);
    let auxiliary_variables = usize::from(MLPCS_AUXILIARY_MASK_VARIABLES);
    if gkr_mask_weights.len() != 1_usize << auxiliary_variables {
        return Err(MultilinearPcsTranscriptError::PointDimension {
            expected: 1_usize << auxiliary_variables,
            actual: gkr_mask_weights.len(),
        });
    }
    let claimed_sums = [
        input_opening,
        proof.input_binding,
        output_opening_claim.claim.value,
        proof.output_binding,
        proof.auxiliary_binding * normalizer,
        gkr_mask_opening * normalizer,
    ];
    let variable_counts = [
        main_variables,
        main_variables,
        main_variables,
        main_variables,
        auxiliary_variables,
        auxiliary_variables,
    ];
    let mut verifier = BatchProductSumcheckState::new(
        &claimed_sums,
        &variable_counts,
        main_variables,
        batch_mixing_challenge,
    )?;
    for (round, challenge) in proof
        .batch_rounds
        .iter()
        .copied()
        .zip(batch_challenges.iter().copied())
    {
        verifier.publish_round(round)?;
        verifier.accept_authenticated_challenge(challenge)?;
    }
    let input_binding_point = twin_multilinear_point(input_binding_challenge, main_variables);
    let output_binding_point = twin_multilinear_point(output_binding_challenge, main_variables);
    let auxiliary_binding_point =
        twin_multilinear_point(auxiliary_binding_challenge, auxiliary_variables);
    let expected_right = [
        packed_opening_terminal(
            input_opening_claims,
            input_opening_mixing_challenge,
            batch_challenges,
        )?,
        equality_at_point(&input_binding_point, batch_challenges)?,
        packed_output_terminal(output_opening_claim, batch_challenges)?,
        equality_at_point(&output_binding_point, batch_challenges)?,
        equality_at_point(
            &auxiliary_binding_point,
            &batch_challenges[usize::from(MLPCS_AUXILIARY_INJECTION_FOLD)..],
        )? * normalizer,
        multilinear_table_evaluation(
            gkr_mask_weights,
            &batch_challenges[usize::from(MLPCS_AUXILIARY_INJECTION_FOLD)..],
        )? * normalizer,
    ];
    if proof.terminal_left[0] != proof.terminal_left[1]
        || proof.terminal_left[2] != proof.terminal_left[3]
        || proof.terminal_left[4] != proof.terminal_left[5]
        || proof.terminal_right != expected_right
    {
        return Err(MultilinearPcsTranscriptError::Batch(
            BatchProductSumcheckError::Terminal,
        ));
    }
    verifier.finish(&proof.terminal_left, &proof.terminal_right)?;
    Ok([
        proof.terminal_left[0],
        proof.terminal_left[2],
        proof.terminal_left[4],
    ])
}

/// Prepared two-boundary hiding algebra before the batch-mixing challenge.
///
/// The three binding values are fixed here. The caller must publish them before
/// supplying the batch-mixing challenge to [`Self::start`].
pub struct PreparedDualBoundaryMultilinearPcsPrelude {
    input_evaluations: Vec<Fp16>,
    output_evaluations: Vec<Fp16>,
    auxiliary_evaluations: Vec<Fp16>,
    input_weights: Vec<Fp16>,
    output_weights: Vec<Fp16>,
    auxiliary_weights: Vec<Fp16>,
    gkr_mask_weights: Vec<Fp16>,
    input_opening_claims: PackedGkrInputClaims,
    output_opening_claim: PackedGkrOutputClaim,
    input_opening_mixing_challenge: Fp16,
    input_binding_point: Vec<Fp16>,
    output_binding_point: Vec<Fp16>,
    auxiliary_binding_point: Vec<Fp16>,
    input_opening: Fp16,
    output_opening: Fp16,
    input_binding: Fp16,
    output_binding: Fp16,
    auxiliary_binding: Fp16,
    gkr_mask_opening: Fp16,
    #[cfg(feature = "parallel")]
    workers: usize,
}

impl PreparedDualBoundaryMultilinearPcsPrelude {
    #[allow(clippy::too_many_arguments)]
    pub fn prepare(
        input_evaluations: Vec<Fp16>,
        output_evaluations: Vec<Fp16>,
        auxiliary_evaluations: Vec<Fp16>,
        input_opening_claims: &PackedGkrInputClaims,
        input_opening_mixing_challenge: Fp16,
        output_opening_claim: &PackedGkrOutputClaim,
        input_binding_challenge: Fp16,
        output_binding_challenge: Fp16,
        auxiliary_binding_challenge: Fp16,
    ) -> Result<Self, MultilinearPcsTranscriptError> {
        let auxiliary_size = 1_usize << usize::from(MLPCS_AUXILIARY_MASK_VARIABLES);
        Self::prepare_with_gkr_mask_opening(
            input_evaluations,
            output_evaluations,
            auxiliary_evaluations,
            input_opening_claims,
            input_opening_mixing_challenge,
            output_opening_claim,
            input_binding_challenge,
            output_binding_challenge,
            auxiliary_binding_challenge,
            alloc::vec![Fp16::ZERO; auxiliary_size],
            Fp16::ZERO,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prepare_with_gkr_mask_opening(
        input_evaluations: Vec<Fp16>,
        output_evaluations: Vec<Fp16>,
        auxiliary_evaluations: Vec<Fp16>,
        input_opening_claims: &PackedGkrInputClaims,
        input_opening_mixing_challenge: Fp16,
        output_opening_claim: &PackedGkrOutputClaim,
        input_binding_challenge: Fp16,
        output_binding_challenge: Fp16,
        auxiliary_binding_challenge: Fp16,
        gkr_mask_weights: Vec<Fp16>,
        gkr_mask_opening: Fp16,
    ) -> Result<Self, MultilinearPcsTranscriptError> {
        let main_variables = usize::from(MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE);
        let auxiliary_variables = usize::from(MLPCS_AUXILIARY_MASK_VARIABLES);
        if input_evaluations.len() != 1_usize << main_variables
            || output_evaluations.len() != input_evaluations.len()
            || auxiliary_evaluations.len() != 1_usize << auxiliary_variables
            || gkr_mask_weights.len() != auxiliary_evaluations.len()
        {
            return Err(MultilinearPcsTranscriptError::PointDimension {
                expected: 1_usize << main_variables,
                actual: input_evaluations.len(),
            });
        }
        #[cfg(feature = "parallel")]
        let workers = std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1);
        #[cfg(not(feature = "parallel"))]
        let workers = 1;
        let input_weights = packed_opening_weights(
            input_opening_claims,
            input_opening_mixing_challenge,
            workers,
        )?;
        let output_weights = packed_output_weights(output_opening_claim, workers)?;
        #[cfg(feature = "parallel")]
        let input_opening = sum_product_parallel(&input_evaluations, &input_weights, workers)?;
        #[cfg(not(feature = "parallel"))]
        let input_opening = sum_product(&input_evaluations, &input_weights);
        #[cfg(feature = "parallel")]
        let output_opening = sum_product_parallel(&output_evaluations, &output_weights, workers)?;
        #[cfg(not(feature = "parallel"))]
        let output_opening = sum_product(&output_evaluations, &output_weights);
        if input_opening
            != input_opening_claims.claims[0].value
                + input_opening_mixing_challenge * input_opening_claims.claims[1].value
            || output_opening != output_opening_claim.claim.value
        {
            return Err(MultilinearPcsTranscriptError::Batch(
                BatchProductSumcheckError::Claim,
            ));
        }
        let input_binding_point = twin_multilinear_point(input_binding_challenge, main_variables);
        let output_binding_point = twin_multilinear_point(output_binding_challenge, main_variables);
        let auxiliary_binding_point =
            twin_multilinear_point(auxiliary_binding_challenge, auxiliary_variables);
        // These main-domain equality tables are each one full Fp16 hypercube.
        // Keep them in disjoint scopes so the output table cannot overlap the
        // input table in the prover's live allocation set.
        let input_binding = {
            #[cfg(feature = "parallel")]
            let weights = equality_evaluations_parallel(&input_binding_point, workers)?;
            #[cfg(not(feature = "parallel"))]
            let weights = equality_evaluations(&input_binding_point)?;
            #[cfg(feature = "parallel")]
            {
                sum_product_parallel(&input_evaluations, &weights, workers)?
            }
            #[cfg(not(feature = "parallel"))]
            {
                sum_product(&input_evaluations, &weights)
            }
        };
        let output_binding = {
            #[cfg(feature = "parallel")]
            let weights = equality_evaluations_parallel(&output_binding_point, workers)?;
            #[cfg(not(feature = "parallel"))]
            let weights = equality_evaluations(&output_binding_point)?;
            #[cfg(feature = "parallel")]
            {
                sum_product_parallel(&output_evaluations, &weights, workers)?
            }
            #[cfg(not(feature = "parallel"))]
            {
                sum_product(&output_evaluations, &weights)
            }
        };
        #[cfg(feature = "parallel")]
        let auxiliary_weights = equality_evaluations_parallel(&auxiliary_binding_point, workers)?;
        #[cfg(not(feature = "parallel"))]
        let auxiliary_weights = equality_evaluations(&auxiliary_binding_point)?;
        #[cfg(feature = "parallel")]
        let auxiliary_binding =
            sum_product_parallel(&auxiliary_evaluations, &auxiliary_weights, workers)?;
        #[cfg(not(feature = "parallel"))]
        let auxiliary_binding = sum_product(&auxiliary_evaluations, &auxiliary_weights);
        #[cfg(feature = "parallel")]
        let actual_gkr_mask_opening =
            sum_product_parallel(&auxiliary_evaluations, &gkr_mask_weights, workers)?;
        #[cfg(not(feature = "parallel"))]
        let actual_gkr_mask_opening = sum_product(&auxiliary_evaluations, &gkr_mask_weights);
        if actual_gkr_mask_opening != gkr_mask_opening {
            return Err(MultilinearPcsTranscriptError::Batch(
                BatchProductSumcheckError::Claim,
            ));
        }
        Ok(Self {
            input_evaluations,
            output_evaluations,
            auxiliary_evaluations,
            input_weights,
            output_weights,
            auxiliary_weights,
            gkr_mask_weights,
            input_opening_claims: input_opening_claims.clone(),
            output_opening_claim: output_opening_claim.clone(),
            input_opening_mixing_challenge,
            input_binding_point,
            output_binding_point,
            auxiliary_binding_point,
            input_opening,
            output_opening,
            input_binding,
            output_binding,
            auxiliary_binding,
            gkr_mask_opening,
            #[cfg(feature = "parallel")]
            workers,
        })
    }

    pub fn bindings(&self) -> [Fp16; 3] {
        [
            self.input_binding,
            self.output_binding,
            self.auxiliary_binding,
        ]
    }

    pub fn start(
        mut self,
        batch_mixing_challenge: Fp16,
    ) -> Result<DualBoundaryMultilinearPcsPreludeProver, MultilinearPcsTranscriptError> {
        let mix2 = batch_mixing_challenge * batch_mixing_challenge;
        let mix3 = mix2 * batch_mixing_challenge;
        let mix4 = mix3 * batch_mixing_challenge;
        let mix5 = mix4 * batch_mixing_challenge;
        #[cfg(feature = "parallel")]
        let input_binding_weights =
            equality_evaluations_parallel(&self.input_binding_point, self.workers)?;
        #[cfg(not(feature = "parallel"))]
        let input_binding_weights = equality_evaluations(&self.input_binding_point)?;
        for (opening, binding) in self.input_weights.iter_mut().zip(input_binding_weights) {
            *opening = *opening + batch_mixing_challenge * binding;
        }
        #[cfg(feature = "parallel")]
        let output_binding_weights =
            equality_evaluations_parallel(&self.output_binding_point, self.workers)?;
        #[cfg(not(feature = "parallel"))]
        let output_binding_weights = equality_evaluations(&self.output_binding_point)?;
        for (opening, binding) in self.output_weights.iter_mut().zip(output_binding_weights) {
            *opening = mix2 * *opening + mix3 * binding;
        }
        let normalizer = auxiliary_lift_normalizer()?;
        for (weight, gkr_mask_weight) in self
            .auxiliary_weights
            .iter_mut()
            .zip(self.gkr_mask_weights.iter())
        {
            *weight = (mix4 * *weight + mix5 * *gkr_mask_weight) * normalizer;
        }
        let main_variables = usize::from(MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE);
        let auxiliary_variables = usize::from(MLPCS_AUXILIARY_MASK_VARIABLES);
        let verifier = BatchProductSumcheckState::new(
            &[
                self.input_opening,
                self.input_binding,
                self.output_opening,
                self.output_binding,
                self.auxiliary_binding * normalizer,
                self.gkr_mask_opening * normalizer,
            ],
            &[
                main_variables,
                main_variables,
                main_variables,
                main_variables,
                auxiliary_variables,
                auxiliary_variables,
            ],
            main_variables,
            batch_mixing_challenge,
        )?;
        let inverse_two = (Fp16::ONE + Fp16::ONE)
            .inverse()
            .map_err(|_| MultilinearPcsTranscriptError::Field)?;
        Ok(DualBoundaryMultilinearPcsPreludeProver {
            input_evaluations: self.input_evaluations,
            output_evaluations: self.output_evaluations,
            auxiliary_evaluations: self.auxiliary_evaluations,
            input_weights: self.input_weights,
            output_weights: self.output_weights,
            auxiliary_weights: self.auxiliary_weights,
            gkr_mask_weights: self.gkr_mask_weights,
            input_opening_claims: self.input_opening_claims,
            output_opening_claim: self.output_opening_claim,
            input_opening_mixing_challenge: self.input_opening_mixing_challenge,
            input_binding_point: self.input_binding_point,
            output_binding_point: self.output_binding_point,
            auxiliary_binding_point: self.auxiliary_binding_point,
            input_binding: self.input_binding,
            output_binding: self.output_binding,
            auxiliary_binding: self.auxiliary_binding,
            normalizer,
            inverse_two,
            inactive_auxiliary_claim: mix4 * self.auxiliary_binding + mix5 * self.gkr_mask_opening,
            verifier,
            accepted_challenges: Vec::with_capacity(main_variables),
            pending_round: false,
            #[cfg(feature = "parallel")]
            workers: self.workers,
        })
    }
}

/// Stateful publish-then-challenge prover for the dual-boundary hiding prelude.
pub struct DualBoundaryMultilinearPcsPreludeProver {
    input_evaluations: Vec<Fp16>,
    output_evaluations: Vec<Fp16>,
    auxiliary_evaluations: Vec<Fp16>,
    input_weights: Vec<Fp16>,
    output_weights: Vec<Fp16>,
    auxiliary_weights: Vec<Fp16>,
    gkr_mask_weights: Vec<Fp16>,
    input_opening_claims: PackedGkrInputClaims,
    output_opening_claim: PackedGkrOutputClaim,
    input_opening_mixing_challenge: Fp16,
    input_binding_point: Vec<Fp16>,
    output_binding_point: Vec<Fp16>,
    auxiliary_binding_point: Vec<Fp16>,
    input_binding: Fp16,
    output_binding: Fp16,
    auxiliary_binding: Fp16,
    normalizer: Fp16,
    inverse_two: Fp16,
    inactive_auxiliary_claim: Fp16,
    verifier: BatchProductSumcheckState,
    accepted_challenges: Vec<Fp16>,
    pending_round: bool,
    #[cfg(feature = "parallel")]
    workers: usize,
}

impl DualBoundaryMultilinearPcsPreludeProver {
    pub fn round_ordinal(&self) -> usize {
        self.accepted_challenges.len()
    }

    pub fn publish_round(&mut self) -> Result<[Fp16; 3], MultilinearPcsTranscriptError> {
        let round = self.round_ordinal();
        if self.pending_round || round >= usize::from(MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE) {
            return Err(MultilinearPcsTranscriptError::Sequence);
        }
        #[cfg(feature = "parallel")]
        let mut coefficients = product_round_coefficients_parallel(
            &self.input_evaluations,
            &self.input_weights,
            self.workers,
        )?;
        #[cfg(not(feature = "parallel"))]
        let mut coefficients =
            product_round_coefficients(&self.input_evaluations, &self.input_weights)?;
        #[cfg(feature = "parallel")]
        let output = product_round_coefficients_parallel(
            &self.output_evaluations,
            &self.output_weights,
            self.workers,
        )?;
        #[cfg(not(feature = "parallel"))]
        let output = product_round_coefficients(&self.output_evaluations, &self.output_weights)?;
        for index in 0..3 {
            coefficients[index] = coefficients[index] + output[index];
        }
        if round < usize::from(MLPCS_AUXILIARY_INJECTION_FOLD) {
            coefficients[0] = coefficients[0] + self.inactive_auxiliary_claim * self.inverse_two;
        } else {
            #[cfg(feature = "parallel")]
            let auxiliary = product_round_coefficients_parallel(
                &self.auxiliary_evaluations,
                &self.auxiliary_weights,
                self.workers,
            )?;
            #[cfg(not(feature = "parallel"))]
            let auxiliary =
                product_round_coefficients(&self.auxiliary_evaluations, &self.auxiliary_weights)?;
            for index in 0..3 {
                coefficients[index] = coefficients[index] + auxiliary[index];
            }
        }
        self.verifier.publish_round(coefficients)?;
        self.pending_round = true;
        Ok(coefficients)
    }

    pub fn accept_authenticated_challenge(
        &mut self,
        challenge: Fp16,
    ) -> Result<(), MultilinearPcsTranscriptError> {
        if !self.pending_round {
            return Err(MultilinearPcsTranscriptError::Sequence);
        }
        let round = self.round_ordinal();
        self.verifier.accept_authenticated_challenge(challenge)?;
        #[cfg(feature = "parallel")]
        {
            fold_table_parallel(&mut self.input_evaluations, challenge, self.workers)?;
            fold_table_parallel(&mut self.input_weights, challenge, self.workers)?;
            fold_table_parallel(&mut self.output_evaluations, challenge, self.workers)?;
            fold_table_parallel(&mut self.output_weights, challenge, self.workers)?;
        }
        #[cfg(not(feature = "parallel"))]
        {
            fold_table(&mut self.input_evaluations, challenge);
            fold_table(&mut self.input_weights, challenge);
            fold_table(&mut self.output_evaluations, challenge);
            fold_table(&mut self.output_weights, challenge);
        }
        if round < usize::from(MLPCS_AUXILIARY_INJECTION_FOLD) {
            self.inactive_auxiliary_claim = self.inactive_auxiliary_claim * self.inverse_two;
        } else {
            #[cfg(feature = "parallel")]
            {
                fold_table_parallel(&mut self.auxiliary_evaluations, challenge, self.workers)?;
                fold_table_parallel(&mut self.auxiliary_weights, challenge, self.workers)?;
            }
            #[cfg(not(feature = "parallel"))]
            {
                fold_table(&mut self.auxiliary_evaluations, challenge);
                fold_table(&mut self.auxiliary_weights, challenge);
            }
        }
        self.accepted_challenges.push(challenge);
        self.pending_round = false;
        Ok(())
    }

    pub fn finish(
        self,
    ) -> Result<([Fp16; 3], DualBoundaryMultilinearPcsPreludeProof), MultilinearPcsTranscriptError>
    {
        if self.pending_round
            || self.accepted_challenges.len() != usize::from(MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE)
        {
            return Err(MultilinearPcsTranscriptError::Sequence);
        }
        let terminal_left = [
            self.input_evaluations[0],
            self.input_evaluations[0],
            self.output_evaluations[0],
            self.output_evaluations[0],
            self.auxiliary_evaluations[0],
            self.auxiliary_evaluations[0],
        ];
        let terminal_right = [
            packed_opening_terminal(
                &self.input_opening_claims,
                self.input_opening_mixing_challenge,
                &self.accepted_challenges,
            )?,
            equality_at_point(&self.input_binding_point, &self.accepted_challenges)?,
            packed_output_terminal(&self.output_opening_claim, &self.accepted_challenges)?,
            equality_at_point(&self.output_binding_point, &self.accepted_challenges)?,
            equality_at_point(
                &self.auxiliary_binding_point,
                &self.accepted_challenges[usize::from(MLPCS_AUXILIARY_INJECTION_FOLD)..],
            )? * self.normalizer,
            multilinear_table_evaluation(
                &self.gkr_mask_weights,
                &self.accepted_challenges[usize::from(MLPCS_AUXILIARY_INJECTION_FOLD)..],
            )? * self.normalizer,
        ];
        let batch_proof = self.verifier.finish(&terminal_left, &terminal_right)?;
        Ok((
            [
                self.input_opening_claims.claims[0].value,
                self.input_opening_claims.claims[1].value,
                self.output_opening_claim.claim.value,
            ],
            DualBoundaryMultilinearPcsPreludeProof {
                input_binding: self.input_binding,
                output_binding: self.output_binding,
                auxiliary_binding: self.auxiliary_binding,
                batch_rounds: batch_proof.rounds,
                terminal_left,
                terminal_right,
            },
        ))
    }
}

/// Executable two-boundary hiding algebra with externally authenticated coins.
#[allow(clippy::too_many_arguments)]
pub fn prove_dual_boundary_multilinear_pcs_prelude_control(
    input_evaluations: Vec<Fp16>,
    output_evaluations: Vec<Fp16>,
    auxiliary_evaluations: Vec<Fp16>,
    input_opening_claims: &PackedGkrInputClaims,
    input_opening_mixing_challenge: Fp16,
    output_opening_claim: &PackedGkrOutputClaim,
    input_binding_challenge: Fp16,
    output_binding_challenge: Fp16,
    auxiliary_binding_challenge: Fp16,
    batch_mixing_challenge: Fp16,
    batch_challenges: &[Fp16],
) -> Result<([Fp16; 3], DualBoundaryMultilinearPcsPreludeProof), MultilinearPcsTranscriptError> {
    if batch_challenges.len() != usize::from(MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE) {
        return Err(MultilinearPcsTranscriptError::PointDimension {
            expected: usize::from(MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE),
            actual: batch_challenges.len(),
        });
    }
    let prepared = PreparedDualBoundaryMultilinearPcsPrelude::prepare(
        input_evaluations,
        output_evaluations,
        auxiliary_evaluations,
        input_opening_claims,
        input_opening_mixing_challenge,
        output_opening_claim,
        input_binding_challenge,
        output_binding_challenge,
        auxiliary_binding_challenge,
    )?;
    let mut prover = prepared.start(batch_mixing_challenge)?;
    for challenge in batch_challenges {
        prover.publish_round()?;
        prover.accept_authenticated_challenge(*challenge)?;
    }
    prover.finish()
}

impl Default for MultilinearPcsPreludeState {
    fn default() -> Self {
        Self::new()
    }
}

/// Independently replay the fixed prelude against authenticated challenges.
///
/// The returned pair is `(main_terminal, auxiliary_terminal)` and must be
/// supplied to the fold-query verifier.
#[allow(clippy::too_many_arguments)]
pub fn verify_multilinear_pcs_prelude(
    proof: &MultilinearPcsPreludeProof,
    main_root: [u8; 64],
    auxiliary_root: [u8; 64],
    main_binding_challenge: Fp16,
    auxiliary_binding_challenge: Fp16,
    opening_claims: &PackedGkrInputClaims,
    opening_mixing_challenge: Fp16,
    batch_mixing_challenge: Fp16,
    batch_challenges: &[Fp16],
) -> Result<[Fp16; 2], MultilinearPcsTranscriptError> {
    if proof.batch_rounds.len() != usize::from(MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE)
        || batch_challenges.len() != usize::from(MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE)
    {
        return Err(MultilinearPcsTranscriptError::RoundOrdinal);
    }
    let mut state = MultilinearPcsPreludeState::new();
    state.publish_main_root(main_root)?;
    state.accept_main_binding_challenge(main_binding_challenge)?;
    state.publish_main_binding(proof.main_binding)?;
    state.publish_auxiliary_root(auxiliary_root)?;
    state.accept_auxiliary_binding_challenge(auxiliary_binding_challenge)?;
    state.publish_auxiliary_binding(proof.auxiliary_binding)?;
    state.fix_opening_claims(opening_claims)?;
    state.accept_opening_mixing_challenge(opening_mixing_challenge)?;
    state.accept_batch_mixing_challenge(batch_mixing_challenge)?;
    for (round, challenge) in proof
        .batch_rounds
        .iter()
        .copied()
        .zip(batch_challenges.iter().copied())
    {
        state.publish_batch_round(round)?;
        state.accept_batch_round_challenge(challenge)?;
    }
    state.finish_batch_sumcheck(proof.terminal_left, proof.terminal_right)?;
    Ok([proof.terminal_left[0], proof.terminal_left[2]])
}

/// Memory-bounded scalar prover for the exact selected hiding prelude.
///
/// This is an executable algebra reference. Authenticated public-coin callers
/// must still release each challenge only after the corresponding round
/// polynomial has been fixed; the completed challenge slice is accepted here
/// solely for deterministic controls and benchmarking.
#[allow(clippy::too_many_arguments)]
pub fn prove_selected_multilinear_pcs_prelude_control(
    mut main_evaluations: Vec<Fp16>,
    mut auxiliary_evaluations: Vec<Fp16>,
    opening_claims: &PackedGkrInputClaims,
    opening_mixing_challenge: Fp16,
    main_binding_challenge: Fp16,
    auxiliary_binding_challenge: Fp16,
    batch_mixing_challenge: Fp16,
    batch_challenges: &[Fp16],
) -> Result<([Fp16; 2], MultilinearPcsPreludeProof), MultilinearPcsTranscriptError> {
    let main_variables = usize::from(MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE);
    let auxiliary_variables = usize::from(MLPCS_AUXILIARY_MASK_VARIABLES);
    if main_evaluations.len() != 1_usize << main_variables
        || auxiliary_evaluations.len() != 1_usize << auxiliary_variables
        || batch_challenges.len() != main_variables
    {
        return Err(MultilinearPcsTranscriptError::PointDimension {
            expected: main_variables,
            actual: batch_challenges.len(),
        });
    }
    #[cfg(feature = "parallel")]
    let workers = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1);

    let main_binding_point = twin_multilinear_point(main_binding_challenge, main_variables);
    let auxiliary_binding_point =
        twin_multilinear_point(auxiliary_binding_challenge, auxiliary_variables);

    #[cfg(feature = "parallel")]
    let mut main_weights =
        packed_opening_weights(opening_claims, opening_mixing_challenge, workers)?;
    #[cfg(not(feature = "parallel"))]
    let mut main_weights = packed_opening_weights(opening_claims, opening_mixing_challenge, 1)?;
    #[cfg(feature = "parallel")]
    let opening_value = sum_product_parallel(&main_evaluations, &main_weights, workers)?;
    #[cfg(not(feature = "parallel"))]
    let opening_value = sum_product(&main_evaluations, &main_weights);
    let claimed_opening =
        opening_claims.claims[0].value + opening_mixing_challenge * opening_claims.claims[1].value;
    if opening_value != claimed_opening {
        return Err(MultilinearPcsTranscriptError::Batch(
            BatchProductSumcheckError::Claim,
        ));
    }
    #[cfg(feature = "parallel")]
    let main_binding_weights = equality_evaluations_parallel(&main_binding_point, workers)?;
    #[cfg(not(feature = "parallel"))]
    let main_binding_weights = equality_evaluations(&main_binding_point)?;
    #[cfg(feature = "parallel")]
    let main_binding = sum_product_parallel(&main_evaluations, &main_binding_weights, workers)?;
    #[cfg(not(feature = "parallel"))]
    let main_binding = sum_product(&main_evaluations, &main_binding_weights);
    for (opening, binding) in main_weights.iter_mut().zip(main_binding_weights) {
        *opening = *opening + batch_mixing_challenge * binding;
    }

    #[cfg(feature = "parallel")]
    let mut auxiliary_weights = equality_evaluations_parallel(&auxiliary_binding_point, workers)?;
    #[cfg(not(feature = "parallel"))]
    let mut auxiliary_weights = equality_evaluations(&auxiliary_binding_point)?;
    #[cfg(feature = "parallel")]
    let auxiliary_binding =
        sum_product_parallel(&auxiliary_evaluations, &auxiliary_weights, workers)?;
    #[cfg(not(feature = "parallel"))]
    let auxiliary_binding = sum_product(&auxiliary_evaluations, &auxiliary_weights);
    let normalizer = auxiliary_lift_normalizer()?;
    let auxiliary_weight = batch_mixing_challenge * batch_mixing_challenge * normalizer;
    for weight in &mut auxiliary_weights {
        *weight = *weight * auxiliary_weight;
    }

    let claimed_sums = [opening_value, main_binding, auxiliary_binding * normalizer];
    let mut verifier = BatchProductSumcheckState::new(
        &claimed_sums,
        &[main_variables, main_variables, auxiliary_variables],
        main_variables,
        batch_mixing_challenge,
    )?;
    let inverse_two = (Fp16::ONE + Fp16::ONE)
        .inverse()
        .map_err(|_| MultilinearPcsTranscriptError::Field)?;
    let mut inactive_auxiliary_claim =
        batch_mixing_challenge * batch_mixing_challenge * auxiliary_binding;
    for (round, challenge) in batch_challenges.iter().copied().enumerate() {
        #[cfg(feature = "parallel")]
        let mut coefficients =
            product_round_coefficients_parallel(&main_evaluations, &main_weights, workers)?;
        #[cfg(not(feature = "parallel"))]
        let mut coefficients = product_round_coefficients(&main_evaluations, &main_weights)?;
        if round < usize::from(MLPCS_AUXILIARY_INJECTION_FOLD) {
            coefficients[0] = coefficients[0] + inactive_auxiliary_claim * inverse_two;
            inactive_auxiliary_claim = inactive_auxiliary_claim * inverse_two;
        } else {
            #[cfg(feature = "parallel")]
            let auxiliary = product_round_coefficients_parallel(
                &auxiliary_evaluations,
                &auxiliary_weights,
                workers,
            )?;
            #[cfg(not(feature = "parallel"))]
            let auxiliary = product_round_coefficients(&auxiliary_evaluations, &auxiliary_weights)?;
            for index in 0..3 {
                coefficients[index] = coefficients[index] + auxiliary[index];
            }
        }
        verifier.publish_round(coefficients)?;
        verifier.accept_authenticated_challenge(challenge)?;
        #[cfg(feature = "parallel")]
        {
            fold_table_parallel(&mut main_evaluations, challenge, workers)?;
            fold_table_parallel(&mut main_weights, challenge, workers)?;
        }
        #[cfg(not(feature = "parallel"))]
        {
            fold_table(&mut main_evaluations, challenge);
            fold_table(&mut main_weights, challenge);
        }
        if round >= usize::from(MLPCS_AUXILIARY_INJECTION_FOLD) {
            #[cfg(feature = "parallel")]
            {
                fold_table_parallel(&mut auxiliary_evaluations, challenge, workers)?;
                fold_table_parallel(&mut auxiliary_weights, challenge, workers)?;
            }
            #[cfg(not(feature = "parallel"))]
            {
                fold_table(&mut auxiliary_evaluations, challenge);
                fold_table(&mut auxiliary_weights, challenge);
            }
        }
    }

    let right = [
        packed_opening_terminal(opening_claims, opening_mixing_challenge, batch_challenges)?,
        equality_at_point(&main_binding_point, batch_challenges)?,
        equality_at_point(
            &auxiliary_binding_point,
            &batch_challenges[usize::from(MLPCS_AUXILIARY_INJECTION_FOLD)..],
        )? * normalizer,
    ];
    let left = [
        main_evaluations[0],
        main_evaluations[0],
        auxiliary_evaluations[0],
    ];
    let sumcheck = verifier.finish(&left, &right)?;
    Ok((
        [
            opening_claims.claims[0].value,
            opening_claims.claims[1].value,
        ],
        MultilinearPcsPreludeProof {
            main_binding,
            auxiliary_binding,
            batch_rounds: sumcheck.rounds,
            terminal_left: left,
            terminal_right: right,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::M31;
    use crate::multilinear_batch_sumcheck::{
        multilinear_evaluation_product_claim, prove_batch_product_sumcheck_control,
    };
    use crate::multilinear_pcs::{MultilinearOpeningClaim, evaluate_multilinear};
    use alloc::vec;

    fn fp(value: u32) -> Fp16 {
        Fp16::from_m31(M31::from_canonical(value).unwrap())
    }

    #[test]
    fn prelude_enforces_exact_order_and_reaches_only_fold_ready() {
        let main_alpha = fp(47);
        let auxiliary_alpha = fp(53);

        let mut state = MultilinearPcsPreludeState::new();
        assert_eq!(
            state.accept_main_binding_challenge(main_alpha),
            Err(MultilinearPcsTranscriptError::Sequence)
        );

        let mut state = MultilinearPcsPreludeState::new();
        let main_root = [1; 64];
        let auxiliary_root = [2; 64];
        state.publish_main_root(main_root).unwrap();
        state.accept_main_binding_challenge(main_alpha).unwrap();
        state.publish_main_binding(Fp16::ZERO).unwrap();
        state.publish_auxiliary_root(auxiliary_root).unwrap();
        state
            .accept_auxiliary_binding_challenge(auxiliary_alpha)
            .unwrap();
        state.publish_auxiliary_binding(Fp16::ZERO).unwrap();
        let opening_claims = PackedGkrInputClaims {
            claims: core::array::from_fn(|_| MultilinearOpeningClaim {
                point: vec![Fp16::ZERO; 18],
                value: Fp16::ZERO,
            }),
            shard_query: fp(55),
            wire_variables: 11,
        };
        let opening_mixing = fp(57);
        state.fix_opening_claims(&opening_claims).unwrap();
        state
            .accept_opening_mixing_challenge(opening_mixing)
            .unwrap();
        let points = state.accept_batch_mixing_challenge(fp(59)).unwrap();
        assert_eq!(points.packed_opening, opening_claims);
        assert_eq!(points.main_binding.len(), 22);
        assert_eq!(points.auxiliary_binding.len(), 18);
        let challenges = (0..22)
            .map(|ordinal| fp(61 + ordinal as u32))
            .collect::<Vec<_>>();
        for (ordinal, challenge) in challenges.iter().copied().enumerate() {
            let message = state.publish_batch_round([Fp16::ZERO; 3]).unwrap();
            assert!(matches!(
                message,
                MultilinearPcsPreludeMessage::BatchRound {
                    ordinal: observed,
                    ..
                } if usize::from(observed) == ordinal
            ));
            state.accept_batch_round_challenge(challenge).unwrap();
        }
        let right = [
            packed_opening_terminal(&points.packed_opening, opening_mixing, &challenges).unwrap(),
            equality_at_point(&points.main_binding, &challenges).unwrap(),
            equality_at_point(&points.auxiliary_binding, &challenges[4..]).unwrap()
                * auxiliary_lift_normalizer().unwrap(),
        ];
        state.finish_batch_sumcheck([Fp16::ZERO; 3], right).unwrap();
        assert_eq!(state.phase(), MultilinearPcsPreludePhase::ReadyForFoldBatch);
        let proof = MultilinearPcsPreludeProof {
            main_binding: Fp16::ZERO,
            auxiliary_binding: Fp16::ZERO,
            batch_rounds: vec![[Fp16::ZERO; 3]; 22],
            terminal_left: [Fp16::ZERO; 3],
            terminal_right: right,
        };
        let encoded = proof.encode().unwrap();
        assert_eq!(encoded.len(), MLPCS_PRELUDE_PROOF_BYTES);
        assert_eq!(MultilinearPcsPreludeProof::decode(&encoded).unwrap(), proof);
        assert_eq!(
            verify_multilinear_pcs_prelude(
                &proof,
                main_root,
                auxiliary_root,
                main_alpha,
                auxiliary_alpha,
                &opening_claims,
                opening_mixing,
                fp(59),
                &challenges,
            )
            .unwrap(),
            [Fp16::ZERO; 2]
        );
        for claim_index in 0..2 {
            let mut changed = opening_claims.clone();
            changed.claims[claim_index].value = Fp16::ONE;
            assert!(matches!(
                verify_multilinear_pcs_prelude(
                    &proof,
                    main_root,
                    auxiliary_root,
                    main_alpha,
                    auxiliary_alpha,
                    &changed,
                    opening_mixing,
                    fp(59),
                    &challenges,
                ),
                Err(MultilinearPcsTranscriptError::Batch(
                    BatchProductSumcheckError::Claim
                ))
            ));
        }
    }

    #[test]
    fn canonical_message_frames_are_fixed_and_domain_separated() {
        let root = MultilinearPcsPreludeMessage::MainRoot([7; 64]).encode();
        let binding = MultilinearPcsPreludeMessage::MainBinding(fp(11)).encode();
        let round = MultilinearPcsPreludeMessage::BatchRound {
            ordinal: 9,
            coefficients: [fp(13), fp(17), fp(19)],
        }
        .encode();
        let terminals = MultilinearPcsPreludeMessage::BatchTerminals {
            left: [fp(23), fp(29), fp(31)],
            right: [fp(37), fp(41), fp(43)],
        }
        .encode();
        assert_eq!(root.len(), 8 + 2 + 1 + 64);
        assert_eq!(binding.len(), 8 + 2 + 1 + 64);
        assert_eq!(round.len(), 8 + 2 + 1 + 2 + 3 * 64);
        assert_eq!(terminals.len(), 8 + 2 + 1 + 6 * 64);
        assert_ne!(root, binding);
    }

    #[test]
    fn reduced_geometry_exercises_the_same_three_claim_algebra() {
        let hidden = (0..8).map(|index| fp(index + 2)).collect::<Vec<_>>();
        let auxiliary = (0..4).map(|index| fp(index + 31)).collect::<Vec<_>>();
        let main_point = [fp(41), fp(43), Fp16::ZERO];
        let main_binding_point = twin_multilinear_point(fp(47), 3);
        let auxiliary_binding_point = twin_multilinear_point(fp(53), 2);
        let claims = [
            multilinear_evaluation_product_claim(
                &hidden,
                &main_point,
                evaluate_multilinear(&hidden, &main_point).unwrap(),
            )
            .unwrap(),
            multilinear_evaluation_product_claim(
                &hidden,
                &main_binding_point,
                evaluate_multilinear(&hidden, &main_binding_point).unwrap(),
            )
            .unwrap(),
            multilinear_evaluation_product_claim(
                &auxiliary,
                &auxiliary_binding_point,
                evaluate_multilinear(&auxiliary, &auxiliary_binding_point).unwrap(),
            )
            .unwrap(),
        ];
        let proof =
            prove_batch_product_sumcheck_control(&claims, fp(59), &[fp(61), fp(67), fp(71)])
                .unwrap();
        assert_eq!(proof.rounds.len(), 3);
        assert_eq!(proof.terminal_left.len(), MLPCS_BATCH_CLAIM_COUNT);
    }
}
