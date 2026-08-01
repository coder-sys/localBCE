//! One fixed-length selected multilinear-PCS proof and independent verifier.
//!
//! Public-coin authentication remains an outer protocol responsibility. This
//! module consumes the already authenticated challenges and rejects any shape,
//! algebra, commitment, padding, or query mismatch.

use alloc::{vec, vec::Vec};
use core::fmt;

use crate::field::Fp16;
use crate::merkle::RootHash;
use crate::multilinear_pcs::{
    MLPCS_AUXILIARY_MASK_VARIABLES, MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE, MLPCS_INPUT_LOG_SIZE,
    MLPCS_UNIQUE_QUERY_COUNT, PackedGkrInputClaims, PackedGkrOutputClaim,
};
#[cfg(test)]
use crate::multilinear_pcs_query::selected_fold_query_proof_encoded_len;
use crate::multilinear_pcs_query::{
    BatchedMultilinearPcsFoldQueryProof, MultilinearPcsFoldQueryProof, MultilinearPcsQueryError,
    PreparedDualBoundaryFoldCommitments, SelectedFoldQueryExpectations,
    build_selected_batched_fold_query_proof, build_selected_fold_query_proof,
    decode_selected_batched_fold_query_proof, decode_selected_fold_query_proof,
    derive_selected_query_positions, encode_selected_batched_fold_query_proof,
    encode_selected_fold_query_proof, verify_selected_batched_fold_query_proof,
    verify_selected_fold_query_proof,
};
use crate::multilinear_pcs_transcript::{
    DualBoundaryMultilinearPcsPreludeProof, MLPCS_DUAL_PRELUDE_BYTES, MLPCS_PRELUDE_PROOF_BYTES,
    MultilinearPcsPreludeProof, MultilinearPcsTranscriptError,
    PreparedDualBoundaryMultilinearPcsPrelude, prove_dual_boundary_multilinear_pcs_prelude_control,
    prove_selected_multilinear_pcs_prelude_control,
    verify_dual_boundary_multilinear_pcs_prelude_with_gkr_mask_opening,
    verify_multilinear_pcs_prelude,
};

pub const SELECTED_MLPCS_PROOF_MAGIC: &[u8; 8] = b"BLPQMPF1";
pub const SELECTED_MLPCS_PROOF_VERSION: u16 = 1;
pub const SELECTED_MLPCS_PROOF_BYTES: usize = 17_524_065;
pub const DUAL_BOUNDARY_MLPCS_PROOF_MAGIC: &[u8; 8] = b"BLPQDPF1";
pub const DUAL_BOUNDARY_MLPCS_PROOF_VERSION: u16 = 2;
pub const DUAL_BOUNDARY_MLPCS_PROOF_BYTES: usize = 19_164_257;
pub const INTERACTIVE_DUAL_BOUNDARY_MLPCS_ROUNDS: u32 = 8 + MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE as u32;
const INTERACTIVE_DUAL_BOUNDARY_MLPCS_MAGIC: &[u8; 8] = b"BLPQDPI1";
const INTERACTIVE_DUAL_BOUNDARY_MLPCS_VERSION: u16 = 2;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedMultilinearPcsProof {
    pub prelude: MultilinearPcsPreludeProof,
    pub fold_query: MultilinearPcsFoldQueryProof,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedMultilinearPcsProverOutput {
    pub proof: SelectedMultilinearPcsProof,
    pub main_root: RootHash,
    pub auxiliary_root: RootHash,
    pub opening_values: [Fp16; 2],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DualBoundaryMultilinearPcsProof {
    pub prelude: DualBoundaryMultilinearPcsPreludeProof,
    pub fold_query: BatchedMultilinearPcsFoldQueryProof,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DualBoundaryMultilinearPcsProverOutput {
    pub proof: DualBoundaryMultilinearPcsProof,
    pub input_root: RootHash,
    pub output_root: RootHash,
    pub auxiliary_root: RootHash,
    pub opening_values: [Fp16; 3],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InteractiveDualBoundaryMultilinearPcsProverOutput {
    pub pcs: DualBoundaryMultilinearPcsProverOutput,
    pub challenges: AuthenticatedDualBoundaryMultilinearPcsChallenges,
    /// Exact prover messages committed by the authenticated public coin.
    pub prover_messages: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedMultilinearPcsChallenges {
    pub main_binding: Fp16,
    pub auxiliary_binding: Fp16,
    pub opening_mixing: Fp16,
    pub batch_mixing: Fp16,
    /// These are both the batch-sumcheck point and the codeword fold point.
    pub fold: Vec<Fp16>,
    /// Sampled with the fourth fold challenge before the injected root exists.
    pub auxiliary_mixing: Fp16,
    /// Ordered with replacement; multiplicity is never discarded.
    pub queries: Vec<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedDualBoundaryMultilinearPcsChallenges {
    pub input_binding: Fp16,
    pub output_binding: Fp16,
    pub auxiliary_binding: Fp16,
    pub input_opening_mixing: Fp16,
    /// Released only after both initial main roots are authenticated.
    pub main_mixing: Fp16,
    pub batch_mixing: Fp16,
    pub fold: Vec<Fp16>,
    pub auxiliary_mixing: Fp16,
    pub queries: Vec<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SelectedMultilinearPcsProofError {
    EncodingLength,
    Magic,
    Version,
    NonZeroReserved,
    ChallengeShape,
    PublicCoin,
    Transcript(MultilinearPcsTranscriptError),
    Query(MultilinearPcsQueryError),
}

impl From<MultilinearPcsTranscriptError> for SelectedMultilinearPcsProofError {
    fn from(value: MultilinearPcsTranscriptError) -> Self {
        Self::Transcript(value)
    }
}

impl From<MultilinearPcsQueryError> for SelectedMultilinearPcsProofError {
    fn from(value: MultilinearPcsQueryError) -> Self {
        Self::Query(value)
    }
}

impl fmt::Display for SelectedMultilinearPcsProofError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "BL-PQ512 selected multilinear PCS proof error: {self:?}"
        )
    }
}

impl core::error::Error for SelectedMultilinearPcsProofError {}

fn interactive_message(kind: u16, ordinal: u32, parts: &[&[u8]]) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(INTERACTIVE_DUAL_BOUNDARY_MLPCS_MAGIC);
    message.extend_from_slice(&INTERACTIVE_DUAL_BOUNDARY_MLPCS_VERSION.to_be_bytes());
    message.extend_from_slice(&kind.to_be_bytes());
    message.extend_from_slice(&ordinal.to_be_bytes());
    for part in parts {
        message.extend_from_slice(
            &u32::try_from(part.len())
                .expect("bounded interactive PCS message")
                .to_be_bytes(),
        );
        message.extend_from_slice(part);
    }
    message
}

fn roots_message_parts(roots: &[RootHash; 3]) -> [[u8; 64]; 3] {
    roots.map(RootHash::into_bytes)
}

fn input_claims_bytes(claims: &PackedGkrInputClaims) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.push(claims.wire_variables);
    encoded.extend_from_slice(&claims.shard_query.encode());
    for claim in &claims.claims {
        encoded.extend_from_slice(
            &u16::try_from(claim.point.len())
                .expect("selected point length fits u16")
                .to_be_bytes(),
        );
        for coordinate in &claim.point {
            encoded.extend_from_slice(&coordinate.encode());
        }
        encoded.extend_from_slice(&claim.value.encode());
    }
    encoded
}

fn output_claim_bytes(claim: &PackedGkrOutputClaim) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.push(claim.wire_variables);
    encoded.extend_from_slice(&claim.shard_query.encode());
    encoded.extend_from_slice(
        &u16::try_from(claim.claim.point.len())
            .expect("selected point length fits u16")
            .to_be_bytes(),
    );
    for coordinate in &claim.claim.point {
        encoded.extend_from_slice(&coordinate.encode());
    }
    encoded.extend_from_slice(&claim.claim.value.encode());
    encoded
}

impl AuthenticatedMultilinearPcsChallenges {
    pub fn validate(&self) -> Result<(), SelectedMultilinearPcsProofError> {
        if self.fold.len() != usize::from(MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE)
            || self.queries.len() != MLPCS_UNIQUE_QUERY_COUNT
        {
            return Err(SelectedMultilinearPcsProofError::ChallengeShape);
        }
        Ok(())
    }
}

impl AuthenticatedDualBoundaryMultilinearPcsChallenges {
    pub fn validate(&self) -> Result<(), SelectedMultilinearPcsProofError> {
        if self.fold.len() != usize::from(MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE)
            || self.queries.len() != MLPCS_UNIQUE_QUERY_COUNT
        {
            return Err(SelectedMultilinearPcsProofError::ChallengeShape);
        }
        Ok(())
    }
}

impl SelectedMultilinearPcsProof {
    pub fn encode(
        &self,
        authenticated_queries: &[usize],
    ) -> Result<Vec<u8>, SelectedMultilinearPcsProofError> {
        let prelude = self.prelude.encode()?;
        let fold_query = encode_selected_fold_query_proof(&self.fold_query, authenticated_queries)?;
        let mut encoded = Vec::with_capacity(SELECTED_MLPCS_PROOF_BYTES);
        encoded.extend_from_slice(SELECTED_MLPCS_PROOF_MAGIC);
        encoded.extend_from_slice(&SELECTED_MLPCS_PROOF_VERSION.to_be_bytes());
        encoded.push(0);
        encoded.extend_from_slice(&prelude);
        encoded.extend_from_slice(&fold_query);
        if encoded.len() != SELECTED_MLPCS_PROOF_BYTES {
            return Err(SelectedMultilinearPcsProofError::EncodingLength);
        }
        Ok(encoded)
    }

    pub fn decode(
        encoded: &[u8],
        authenticated_queries: &[usize],
    ) -> Result<Self, SelectedMultilinearPcsProofError> {
        if encoded.len() != SELECTED_MLPCS_PROOF_BYTES {
            return Err(SelectedMultilinearPcsProofError::EncodingLength);
        }
        if &encoded[..8] != SELECTED_MLPCS_PROOF_MAGIC {
            return Err(SelectedMultilinearPcsProofError::Magic);
        }
        if u16::from_be_bytes(
            encoded[8..10]
                .try_into()
                .map_err(|_| SelectedMultilinearPcsProofError::EncodingLength)?,
        ) != SELECTED_MLPCS_PROOF_VERSION
        {
            return Err(SelectedMultilinearPcsProofError::Version);
        }
        if encoded[10] != 0 {
            return Err(SelectedMultilinearPcsProofError::NonZeroReserved);
        }
        let prelude_end = 11 + MLPCS_PRELUDE_PROOF_BYTES;
        Ok(Self {
            prelude: MultilinearPcsPreludeProof::decode(&encoded[11..prelude_end])?,
            fold_query: decode_selected_fold_query_proof(
                &encoded[prelude_end..],
                authenticated_queries,
            )?,
        })
    }
}

impl DualBoundaryMultilinearPcsProof {
    pub fn encode(
        &self,
        authenticated_queries: &[usize],
    ) -> Result<Vec<u8>, SelectedMultilinearPcsProofError> {
        let prelude = self.prelude.encode()?;
        let fold_query =
            encode_selected_batched_fold_query_proof(&self.fold_query, authenticated_queries)?;
        let mut encoded = Vec::with_capacity(DUAL_BOUNDARY_MLPCS_PROOF_BYTES);
        encoded.extend_from_slice(DUAL_BOUNDARY_MLPCS_PROOF_MAGIC);
        encoded.extend_from_slice(&DUAL_BOUNDARY_MLPCS_PROOF_VERSION.to_be_bytes());
        encoded.push(0);
        encoded.extend_from_slice(&prelude);
        encoded.extend_from_slice(&fold_query);
        if encoded.len() != DUAL_BOUNDARY_MLPCS_PROOF_BYTES {
            return Err(SelectedMultilinearPcsProofError::EncodingLength);
        }
        Ok(encoded)
    }

    pub fn decode(
        encoded: &[u8],
        authenticated_queries: &[usize],
    ) -> Result<Self, SelectedMultilinearPcsProofError> {
        if encoded.len() != DUAL_BOUNDARY_MLPCS_PROOF_BYTES {
            return Err(SelectedMultilinearPcsProofError::EncodingLength);
        }
        if &encoded[..8] != DUAL_BOUNDARY_MLPCS_PROOF_MAGIC {
            return Err(SelectedMultilinearPcsProofError::Magic);
        }
        if u16::from_be_bytes(
            encoded[8..10]
                .try_into()
                .map_err(|_| SelectedMultilinearPcsProofError::EncodingLength)?,
        ) != DUAL_BOUNDARY_MLPCS_PROOF_VERSION
        {
            return Err(SelectedMultilinearPcsProofError::Version);
        }
        if encoded[10] != 0 {
            return Err(SelectedMultilinearPcsProofError::NonZeroReserved);
        }
        let prelude_end = 11 + MLPCS_DUAL_PRELUDE_BYTES;
        Ok(Self {
            prelude: DualBoundaryMultilinearPcsPreludeProof::decode(&encoded[11..prelude_end])?,
            fold_query: decode_selected_batched_fold_query_proof(
                &encoded[prelude_end..],
                authenticated_queries,
            )?,
        })
    }
}

/// Build and self-verify the complete selected PCS algebra from codewords.
///
/// This control consumes a completed authenticated challenge schedule. A
/// production caller must still enforce message-before-challenge ordering in
/// the outer dual-PQ public-coin protocol and must supply private coefficients
/// from the production entropy boundary.
#[allow(clippy::too_many_arguments)]
pub fn prove_selected_multilinear_pcs_control(
    main_hypercube_evaluations: Vec<Fp16>,
    auxiliary_hypercube_evaluations: Vec<Fp16>,
    main_codeword: Vec<Fp16>,
    auxiliary_codeword: Vec<Fp16>,
    opening_claims: &PackedGkrInputClaims,
    challenges: &AuthenticatedMultilinearPcsChallenges,
) -> Result<SelectedMultilinearPcsProverOutput, SelectedMultilinearPcsProofError> {
    challenges.validate()?;
    let fold_query = build_selected_fold_query_proof(
        main_codeword,
        auxiliary_codeword,
        &challenges.fold,
        challenges.auxiliary_mixing,
        &challenges.queries,
    )?;
    let main_root = *fold_query
        .main_layer_roots
        .first()
        .ok_or(SelectedMultilinearPcsProofError::ChallengeShape)?;
    let auxiliary_root = fold_query.auxiliary_root;
    let (opening_values, prelude) = prove_selected_multilinear_pcs_prelude_control(
        main_hypercube_evaluations,
        auxiliary_hypercube_evaluations,
        opening_claims,
        challenges.opening_mixing,
        challenges.main_binding,
        challenges.auxiliary_binding,
        challenges.batch_mixing,
        &challenges.fold,
    )?;
    let proof = SelectedMultilinearPcsProof {
        prelude,
        fold_query,
    };
    verify_selected_multilinear_pcs_proof(
        &proof,
        main_root,
        auxiliary_root,
        opening_claims,
        challenges,
    )?;
    Ok(SelectedMultilinearPcsProverOutput {
        proof,
        main_root,
        auxiliary_root,
        opening_values,
    })
}

/// Verify the complete implemented PCS algebra against authenticated inputs.
///
/// This function does not by itself establish the still-open 392/384-bit
/// composition theorem or simulator proof; qualification must keep that
/// separate from successful executable verification.
#[allow(clippy::too_many_arguments)]
pub fn verify_selected_multilinear_pcs_proof(
    proof: &SelectedMultilinearPcsProof,
    expected_main_root: RootHash,
    expected_auxiliary_root: RootHash,
    opening_claims: &PackedGkrInputClaims,
    challenges: &AuthenticatedMultilinearPcsChallenges,
) -> Result<(), SelectedMultilinearPcsProofError> {
    challenges.validate()?;
    if opening_claims
        .claims
        .iter()
        .any(|claim| claim.point.len() + 3 != usize::from(MLPCS_INPUT_LOG_SIZE))
    {
        return Err(SelectedMultilinearPcsProofError::ChallengeShape);
    }
    let terminals = verify_multilinear_pcs_prelude(
        &proof.prelude,
        expected_main_root.into_bytes(),
        expected_auxiliary_root.into_bytes(),
        challenges.main_binding,
        challenges.auxiliary_binding,
        opening_claims,
        challenges.opening_mixing,
        challenges.batch_mixing,
        &challenges.fold,
    )?;
    verify_selected_fold_query_proof(
        &proof.fold_query,
        SelectedFoldQueryExpectations {
            main_root: expected_main_root,
            auxiliary_root: expected_auxiliary_root,
            fold_challenges: &challenges.fold,
            auxiliary_mixing_challenge: challenges.auxiliary_mixing,
            main_terminal: terminals[0],
            auxiliary_terminal: terminals[1],
            queries: &challenges.queries,
        },
    )?;
    Ok(())
}

/// Build and self-verify the hidden before/after state PCS with one shared FRI.
#[allow(clippy::too_many_arguments)]
pub fn prove_dual_boundary_multilinear_pcs_control(
    input_hypercube_evaluations: Vec<Fp16>,
    output_hypercube_evaluations: Vec<Fp16>,
    auxiliary_hypercube_evaluations: Vec<Fp16>,
    input_codeword: Vec<Fp16>,
    output_codeword: Vec<Fp16>,
    auxiliary_codeword: Vec<Fp16>,
    input_opening_claims: &PackedGkrInputClaims,
    output_opening_claim: &PackedGkrOutputClaim,
    challenges: &AuthenticatedDualBoundaryMultilinearPcsChallenges,
) -> Result<DualBoundaryMultilinearPcsProverOutput, SelectedMultilinearPcsProofError> {
    challenges.validate()?;
    let fold_query = build_selected_batched_fold_query_proof(
        input_codeword,
        output_codeword,
        auxiliary_codeword,
        challenges.main_mixing,
        &challenges.fold,
        challenges.auxiliary_mixing,
        &challenges.queries,
    )?;
    let input_root = fold_query.input_root;
    let output_root = fold_query.output_root;
    let auxiliary_root = fold_query.shared.auxiliary_root;
    let (opening_values, prelude) = prove_dual_boundary_multilinear_pcs_prelude_control(
        input_hypercube_evaluations,
        output_hypercube_evaluations,
        auxiliary_hypercube_evaluations,
        input_opening_claims,
        challenges.input_opening_mixing,
        output_opening_claim,
        challenges.input_binding,
        challenges.output_binding,
        challenges.auxiliary_binding,
        challenges.batch_mixing,
        &challenges.fold,
    )?;
    let proof = DualBoundaryMultilinearPcsProof {
        prelude,
        fold_query,
    };
    verify_dual_boundary_multilinear_pcs_proof(
        &proof,
        input_root,
        output_root,
        auxiliary_root,
        input_opening_claims,
        output_opening_claim,
        challenges,
    )?;
    Ok(DualBoundaryMultilinearPcsProverOutput {
        proof,
        input_root,
        output_root,
        auxiliary_root,
        opening_values,
    })
}

/// Produce the dual-boundary PCS with a strict publish-before-challenge
/// schedule and post-commitment query derivation.
///
/// The callback is invoked exactly once per authenticated public-coin round.
/// It receives the canonical round kind, ordinal, and prover message. A caller
/// backed by the dual-PQ chained coin must use the same kind and ordinal in its
/// signed round descriptor.
#[allow(clippy::too_many_arguments)]
pub fn prove_interactive_dual_boundary_multilinear_pcs<F>(
    input_hypercube_evaluations: Vec<Fp16>,
    output_hypercube_evaluations: Vec<Fp16>,
    auxiliary_hypercube_evaluations: Vec<Fp16>,
    input_codeword: Vec<Fp16>,
    output_codeword: Vec<Fp16>,
    auxiliary_codeword: Vec<Fp16>,
    input_opening_claims: &PackedGkrInputClaims,
    output_opening_claim: &PackedGkrOutputClaim,
    session_id: [u8; 64],
    challenge: F,
) -> Result<InteractiveDualBoundaryMultilinearPcsProverOutput, SelectedMultilinearPcsProofError>
where
    F: FnMut(u16, u32, &[u8]) -> Result<Fp16, SelectedMultilinearPcsProofError>,
{
    let prepared_fold = PreparedDualBoundaryFoldCommitments::prepare(
        input_codeword,
        output_codeword,
        auxiliary_codeword,
    )?;
    prove_interactive_dual_boundary_multilinear_pcs_prepared(
        input_hypercube_evaluations,
        output_hypercube_evaluations,
        auxiliary_hypercube_evaluations,
        prepared_fold,
        input_opening_claims,
        output_opening_claim,
        session_id,
        challenge,
    )
}

/// Continue the interactive dual-boundary PCS from roots that were already
/// fixed before an earlier protocol phase in the same public-coin session.
///
/// This is the trust-critical entry point for composing GKR with PCS: callers
/// may bind the initial GKR output query to `prepared_fold.roots()`, then pass
/// the unchanged prepared state here. The codewords and roots are not rebuilt
/// or substituted after that query.
#[allow(clippy::too_many_arguments)]
pub fn prove_interactive_dual_boundary_multilinear_pcs_prepared<F>(
    input_hypercube_evaluations: Vec<Fp16>,
    output_hypercube_evaluations: Vec<Fp16>,
    auxiliary_hypercube_evaluations: Vec<Fp16>,
    prepared_fold: PreparedDualBoundaryFoldCommitments,
    input_opening_claims: &PackedGkrInputClaims,
    output_opening_claim: &PackedGkrOutputClaim,
    session_id: [u8; 64],
    challenge: F,
) -> Result<InteractiveDualBoundaryMultilinearPcsProverOutput, SelectedMultilinearPcsProofError>
where
    F: FnMut(u16, u32, &[u8]) -> Result<Fp16, SelectedMultilinearPcsProofError>,
{
    let auxiliary_size = 1_usize << usize::from(MLPCS_AUXILIARY_MASK_VARIABLES);
    prove_interactive_dual_boundary_multilinear_pcs_prepared_with_gkr_mask_opening(
        input_hypercube_evaluations,
        output_hypercube_evaluations,
        auxiliary_hypercube_evaluations,
        prepared_fold,
        input_opening_claims,
        output_opening_claim,
        vec![Fp16::ZERO; auxiliary_size],
        Fp16::ZERO,
        session_id,
        challenge,
    )
}

/// Continue the same authenticated session while opening the combined GKR
/// zero-knowledge mask functional against the committed auxiliary lane.
#[allow(clippy::too_many_arguments)]
pub fn prove_interactive_dual_boundary_multilinear_pcs_prepared_with_gkr_mask_opening<F>(
    input_hypercube_evaluations: Vec<Fp16>,
    output_hypercube_evaluations: Vec<Fp16>,
    auxiliary_hypercube_evaluations: Vec<Fp16>,
    prepared_fold: PreparedDualBoundaryFoldCommitments,
    input_opening_claims: &PackedGkrInputClaims,
    output_opening_claim: &PackedGkrOutputClaim,
    gkr_mask_weights: Vec<Fp16>,
    gkr_mask_opening: Fp16,
    session_id: [u8; 64],
    mut challenge: F,
) -> Result<InteractiveDualBoundaryMultilinearPcsProverOutput, SelectedMultilinearPcsProofError>
where
    F: FnMut(u16, u32, &[u8]) -> Result<Fp16, SelectedMultilinearPcsProofError>,
{
    if !session_id.iter().any(|byte| *byte != 0) {
        return Err(SelectedMultilinearPcsProofError::ChallengeShape);
    }
    let roots = prepared_fold.roots();
    let root_bytes = roots_message_parts(&roots);
    let root_parts = root_bytes
        .iter()
        .map(|root| root.as_slice())
        .collect::<Vec<_>>();
    let mut prover_messages =
        Vec::with_capacity(usize::try_from(INTERACTIVE_DUAL_BOUNDARY_MLPCS_ROUNDS).unwrap());
    let mut next_challenge = |kind: u16,
                              ordinal: u32,
                              parts: &[&[u8]]|
     -> Result<Fp16, SelectedMultilinearPcsProofError> {
        let message = interactive_message(kind, ordinal, parts);
        let value = challenge(kind, ordinal, &message)?;
        prover_messages.push(message);
        Ok(value)
    };

    let input_binding = next_challenge(1, 0, &root_parts)?;
    let output_binding = next_challenge(2, 0, &root_parts)?;
    let auxiliary_binding = next_challenge(3, 0, &root_parts)?;
    let input_claims = input_claims_bytes(input_opening_claims);
    let output_claim = output_claim_bytes(output_opening_claim);
    let input_opening_mixing =
        next_challenge(4, 0, &[input_claims.as_slice(), output_claim.as_slice()])?;
    let main_mixing = next_challenge(5, 0, &root_parts)?;
    let auxiliary_mixing = next_challenge(6, 0, &[root_bytes[2].as_slice()])?;

    let prepared_prelude =
        PreparedDualBoundaryMultilinearPcsPrelude::prepare_with_gkr_mask_opening(
            input_hypercube_evaluations,
            output_hypercube_evaluations,
            auxiliary_hypercube_evaluations,
            input_opening_claims,
            input_opening_mixing,
            output_opening_claim,
            input_binding,
            output_binding,
            auxiliary_binding,
            gkr_mask_weights.clone(),
            gkr_mask_opening,
        )?;
    let bindings = prepared_prelude.bindings();
    let binding_bytes = bindings.map(|value| value.encode());
    let batch_mixing = next_challenge(
        7,
        0,
        &binding_bytes
            .iter()
            .map(|value| value.as_slice())
            .collect::<Vec<_>>(),
    )?;
    let mut prelude = prepared_prelude.start(batch_mixing)?;
    let mut fold_challenges = Vec::with_capacity(usize::from(MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE));

    // Round zero has no new fold root: the separately published input/output
    // roots already bind it. Publish and accept its prelude message first so
    // the two main prelude tables are halved before allocating the mixed LDE.
    let coefficients = prelude.publish_round()?;
    let coefficient_bytes = coefficients.map(|value| value.encode());
    let mut parts = coefficient_bytes
        .iter()
        .map(|value| value.as_slice())
        .collect::<Vec<_>>();
    parts.extend(root_parts.iter().copied());
    let round_challenge = next_challenge(8, 0, &parts)?;
    prelude.accept_authenticated_challenge(round_challenge)?;
    let mut fold = prepared_fold.start(main_mixing, auxiliary_mixing)?;
    if fold.publish_round_root()?.is_some() {
        return Err(SelectedMultilinearPcsProofError::ChallengeShape);
    }
    fold.accept_authenticated_challenge(round_challenge)?;
    fold_challenges.push(round_challenge);

    for ordinal in 1..usize::from(MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE) {
        let layer_root = fold.publish_round_root()?;
        let coefficients = prelude.publish_round()?;
        let coefficient_bytes = coefficients.map(|value| value.encode());
        let mut parts = coefficient_bytes
            .iter()
            .map(|value| value.as_slice())
            .collect::<Vec<_>>();
        let layer_root_bytes = layer_root.map(RootHash::into_bytes);
        if let Some(root) = &layer_root_bytes {
            parts.push(root);
        } else {
            parts.extend(root_parts.iter().copied());
        }
        let ordinal_u32 =
            u32::try_from(ordinal).map_err(|_| SelectedMultilinearPcsProofError::ChallengeShape)?;
        let round_challenge = next_challenge(8, ordinal_u32, &parts)?;
        prelude.accept_authenticated_challenge(round_challenge)?;
        fold.accept_authenticated_challenge(round_challenge)?;
        fold_challenges.push(round_challenge);
    }
    let (opening_values, prelude_proof) = prelude.finish()?;
    let final_values = fold.final_values()?;
    let final_value_bytes = final_values
        .iter()
        .map(|value| value.encode())
        .collect::<Vec<_>>();
    let terminal_bytes = prelude_proof
        .terminal_left
        .iter()
        .chain(&prelude_proof.terminal_right)
        .map(|value| value.encode())
        .collect::<Vec<_>>();
    let query_coin = next_challenge(
        9,
        0,
        &final_value_bytes
            .iter()
            .chain(&terminal_bytes)
            .map(|value| value.as_slice())
            .collect::<Vec<_>>(),
    )?;
    let queries = derive_selected_query_positions(&session_id, query_coin)?;
    let fold_query = fold.finish_with_queries(&queries)?;
    let challenges = AuthenticatedDualBoundaryMultilinearPcsChallenges {
        input_binding,
        output_binding,
        auxiliary_binding,
        input_opening_mixing,
        main_mixing,
        batch_mixing,
        fold: fold_challenges,
        auxiliary_mixing,
        queries,
    };
    let proof = DualBoundaryMultilinearPcsProof {
        prelude: prelude_proof,
        fold_query,
    };
    let pcs = DualBoundaryMultilinearPcsProverOutput {
        proof,
        input_root: roots[0],
        output_root: roots[1],
        auxiliary_root: roots[2],
        opening_values,
    };
    verify_dual_boundary_multilinear_pcs_proof_with_gkr_mask_opening(
        &pcs.proof,
        pcs.input_root,
        pcs.output_root,
        pcs.auxiliary_root,
        input_opening_claims,
        output_opening_claim,
        &challenges,
        &gkr_mask_weights,
        gkr_mask_opening,
    )?;
    Ok(InteractiveDualBoundaryMultilinearPcsProverOutput {
        pcs,
        challenges,
        prover_messages,
    })
}

/// Independently bind a decoded PCS proof to the replayed authenticated coin.
#[allow(clippy::too_many_arguments)]
pub fn verify_interactive_dual_boundary_multilinear_pcs(
    proof: &DualBoundaryMultilinearPcsProof,
    expected_input_root: RootHash,
    expected_output_root: RootHash,
    expected_auxiliary_root: RootHash,
    input_opening_claims: &PackedGkrInputClaims,
    output_opening_claim: &PackedGkrOutputClaim,
    session_id: [u8; 64],
    replayed_challenges: &[Fp16],
    prover_messages: &[Vec<u8>],
) -> Result<AuthenticatedDualBoundaryMultilinearPcsChallenges, SelectedMultilinearPcsProofError> {
    let auxiliary_size = 1_usize << usize::from(MLPCS_AUXILIARY_MASK_VARIABLES);
    verify_interactive_dual_boundary_multilinear_pcs_with_gkr_mask_opening(
        proof,
        expected_input_root,
        expected_output_root,
        expected_auxiliary_root,
        input_opening_claims,
        output_opening_claim,
        session_id,
        replayed_challenges,
        prover_messages,
        &vec![Fp16::ZERO; auxiliary_size],
        Fp16::ZERO,
    )
}

/// Replay the authenticated PCS messages and verify the GKR mask opening in the
/// same fixed transcript.
#[allow(clippy::too_many_arguments)]
pub fn verify_interactive_dual_boundary_multilinear_pcs_with_gkr_mask_opening(
    proof: &DualBoundaryMultilinearPcsProof,
    expected_input_root: RootHash,
    expected_output_root: RootHash,
    expected_auxiliary_root: RootHash,
    input_opening_claims: &PackedGkrInputClaims,
    output_opening_claim: &PackedGkrOutputClaim,
    session_id: [u8; 64],
    replayed_challenges: &[Fp16],
    prover_messages: &[Vec<u8>],
    gkr_mask_weights: &[Fp16],
    gkr_mask_opening: Fp16,
) -> Result<AuthenticatedDualBoundaryMultilinearPcsChallenges, SelectedMultilinearPcsProofError> {
    let expected_rounds = usize::try_from(INTERACTIVE_DUAL_BOUNDARY_MLPCS_ROUNDS)
        .map_err(|_| SelectedMultilinearPcsProofError::ChallengeShape)?;
    if !session_id.iter().any(|byte| *byte != 0)
        || replayed_challenges.len() != expected_rounds
        || prover_messages.len() != expected_rounds
        || proof.prelude.batch_rounds.len() != usize::from(MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE)
        || proof.fold_query.shared.main_layer_roots.len() + 1
            != usize::from(MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE)
    {
        return Err(SelectedMultilinearPcsProofError::ChallengeShape);
    }
    let roots = [
        expected_input_root,
        expected_output_root,
        expected_auxiliary_root,
    ];
    let root_bytes = roots_message_parts(&roots);
    let root_parts = root_bytes
        .iter()
        .map(|root| root.as_slice())
        .collect::<Vec<_>>();
    let input_claims = input_claims_bytes(input_opening_claims);
    let output_claim = output_claim_bytes(output_opening_claim);
    let binding_bytes = [
        proof.prelude.input_binding.encode(),
        proof.prelude.output_binding.encode(),
        proof.prelude.auxiliary_binding.encode(),
    ];
    let mut expected_messages = vec![
        interactive_message(1, 0, &root_parts),
        interactive_message(2, 0, &root_parts),
        interactive_message(3, 0, &root_parts),
        interactive_message(4, 0, &[&input_claims, &output_claim]),
        interactive_message(5, 0, &root_parts),
        interactive_message(6, 0, &[root_bytes[2].as_slice()]),
        interactive_message(
            7,
            0,
            &binding_bytes
                .iter()
                .map(|value| value.as_slice())
                .collect::<Vec<_>>(),
        ),
    ];
    for (ordinal, coefficients) in proof.prelude.batch_rounds.iter().enumerate() {
        let coefficient_bytes = coefficients.map(|value| value.encode());
        let mut parts = coefficient_bytes
            .iter()
            .map(|value| value.as_slice())
            .collect::<Vec<_>>();
        if ordinal == 0 {
            parts.extend(root_parts.iter().copied());
        } else {
            parts.push(proof.fold_query.shared.main_layer_roots[ordinal - 1].as_bytes());
        }
        expected_messages.push(interactive_message(
            8,
            u32::try_from(ordinal).map_err(|_| SelectedMultilinearPcsProofError::ChallengeShape)?,
            &parts,
        ));
    }
    let final_value_bytes = proof
        .fold_query
        .shared
        .final_values
        .iter()
        .map(|value| value.encode())
        .collect::<Vec<_>>();
    let terminal_bytes = proof
        .prelude
        .terminal_left
        .iter()
        .chain(&proof.prelude.terminal_right)
        .map(|value| value.encode())
        .collect::<Vec<_>>();
    expected_messages.push(interactive_message(
        9,
        0,
        &final_value_bytes
            .iter()
            .chain(&terminal_bytes)
            .map(|value| value.as_slice())
            .collect::<Vec<_>>(),
    ));
    if expected_messages != prover_messages {
        return Err(SelectedMultilinearPcsProofError::PublicCoin);
    }
    let queries =
        derive_selected_query_positions(&session_id, replayed_challenges[expected_rounds - 1])?;
    let challenges = AuthenticatedDualBoundaryMultilinearPcsChallenges {
        input_binding: replayed_challenges[0],
        output_binding: replayed_challenges[1],
        auxiliary_binding: replayed_challenges[2],
        input_opening_mixing: replayed_challenges[3],
        main_mixing: replayed_challenges[4],
        auxiliary_mixing: replayed_challenges[5],
        batch_mixing: replayed_challenges[6],
        fold: replayed_challenges[7..expected_rounds - 1].to_vec(),
        queries,
    };
    verify_dual_boundary_multilinear_pcs_proof_with_gkr_mask_opening(
        proof,
        expected_input_root,
        expected_output_root,
        expected_auxiliary_root,
        input_opening_claims,
        output_opening_claim,
        &challenges,
        gkr_mask_weights,
        gkr_mask_opening,
    )?;
    Ok(challenges)
}

/// Verify both semantic boundaries, their hiding claims, and shared FRI path.
#[allow(clippy::too_many_arguments)]
pub fn verify_dual_boundary_multilinear_pcs_proof(
    proof: &DualBoundaryMultilinearPcsProof,
    expected_input_root: RootHash,
    expected_output_root: RootHash,
    expected_auxiliary_root: RootHash,
    input_opening_claims: &PackedGkrInputClaims,
    output_opening_claim: &PackedGkrOutputClaim,
    challenges: &AuthenticatedDualBoundaryMultilinearPcsChallenges,
) -> Result<(), SelectedMultilinearPcsProofError> {
    let auxiliary_size = 1_usize << usize::from(MLPCS_AUXILIARY_MASK_VARIABLES);
    verify_dual_boundary_multilinear_pcs_proof_with_gkr_mask_opening(
        proof,
        expected_input_root,
        expected_output_root,
        expected_auxiliary_root,
        input_opening_claims,
        output_opening_claim,
        challenges,
        &vec![Fp16::ZERO; auxiliary_size],
        Fp16::ZERO,
    )
}

/// Verify both state boundaries and the GKR mask functional against the shared
/// hiding commitment.
#[allow(clippy::too_many_arguments)]
pub fn verify_dual_boundary_multilinear_pcs_proof_with_gkr_mask_opening(
    proof: &DualBoundaryMultilinearPcsProof,
    expected_input_root: RootHash,
    expected_output_root: RootHash,
    expected_auxiliary_root: RootHash,
    input_opening_claims: &PackedGkrInputClaims,
    output_opening_claim: &PackedGkrOutputClaim,
    challenges: &AuthenticatedDualBoundaryMultilinearPcsChallenges,
    gkr_mask_weights: &[Fp16],
    gkr_mask_opening: Fp16,
) -> Result<(), SelectedMultilinearPcsProofError> {
    challenges.validate()?;
    if input_opening_claims
        .claims
        .iter()
        .any(|claim| claim.point.len() + 3 != usize::from(MLPCS_INPUT_LOG_SIZE))
        || output_opening_claim.claim.point.len() + 3 != usize::from(MLPCS_INPUT_LOG_SIZE)
    {
        return Err(SelectedMultilinearPcsProofError::ChallengeShape);
    }
    if proof.fold_query.shared.auxiliary_root != expected_auxiliary_root {
        return Err(SelectedMultilinearPcsProofError::Query(
            MultilinearPcsQueryError::Authentication,
        ));
    }
    let terminals = verify_dual_boundary_multilinear_pcs_prelude_with_gkr_mask_opening(
        &proof.prelude,
        expected_input_root.into_bytes(),
        expected_output_root.into_bytes(),
        expected_auxiliary_root.into_bytes(),
        challenges.input_binding,
        challenges.output_binding,
        challenges.auxiliary_binding,
        input_opening_claims,
        challenges.input_opening_mixing,
        output_opening_claim,
        challenges.batch_mixing,
        &challenges.fold,
        gkr_mask_weights,
        gkr_mask_opening,
    )?;
    verify_selected_batched_fold_query_proof(
        &proof.fold_query,
        expected_input_root,
        expected_output_root,
        challenges.main_mixing,
        &challenges.fold,
        challenges.auxiliary_mixing,
        terminals[0],
        terminals[1],
        terminals[2],
        &challenges.queries,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multilinear_pcs_query::{
        MLPCS_BATCHED_FOLD_QUERY_MAGIC, MLPCS_BATCHED_FOLD_QUERY_VERSION, MLPCS_FOLD_QUERY_MAGIC,
        MLPCS_FOLD_QUERY_VERSION, decode_selected_batched_fold_query_proof,
        selected_batched_fold_query_proof_encoded_len,
    };
    use alloc::vec;

    #[test]
    fn combined_codec_is_fixed_and_strict() {
        assert_eq!(
            SELECTED_MLPCS_PROOF_BYTES,
            8 + 2 + 1 + MLPCS_PRELUDE_PROOF_BYTES + selected_fold_query_proof_encoded_len()
        );
        let queries = vec![1_usize; MLPCS_UNIQUE_QUERY_COUNT];
        let mut fold_bytes = vec![0_u8; selected_fold_query_proof_encoded_len()];
        fold_bytes[..8].copy_from_slice(MLPCS_FOLD_QUERY_MAGIC);
        fold_bytes[8..10].copy_from_slice(&MLPCS_FOLD_QUERY_VERSION.to_be_bytes());
        let roots_start = 11;
        for ordinal in 0..23 {
            fold_bytes[roots_start + ordinal * 64..roots_start + (ordinal + 1) * 64]
                .fill(ordinal as u8 + 1);
        }
        let fold_query = decode_selected_fold_query_proof(&fold_bytes, &queries).unwrap();
        let prelude = MultilinearPcsPreludeProof {
            main_binding: Fp16::ZERO,
            auxiliary_binding: Fp16::ZERO,
            batch_rounds: vec![[Fp16::ZERO; 3]; 22],
            terminal_left: [Fp16::ZERO; 3],
            terminal_right: [Fp16::ZERO; 3],
        };
        let proof = SelectedMultilinearPcsProof {
            prelude,
            fold_query,
        };
        let encoded = proof.encode(&queries).unwrap();
        assert_eq!(encoded.len(), SELECTED_MLPCS_PROOF_BYTES);
        assert_eq!(
            SelectedMultilinearPcsProof::decode(&encoded, &queries).unwrap(),
            proof
        );
        assert_eq!(
            SelectedMultilinearPcsProof::decode(&encoded[..encoded.len() - 1], &queries),
            Err(SelectedMultilinearPcsProofError::EncodingLength)
        );
    }

    #[test]
    fn dual_boundary_codec_is_fixed_and_strict() {
        assert_eq!(
            DUAL_BOUNDARY_MLPCS_PROOF_BYTES,
            8 + 2 + 1 + MLPCS_DUAL_PRELUDE_BYTES + selected_batched_fold_query_proof_encoded_len()
        );
        let queries = vec![1_usize; MLPCS_UNIQUE_QUERY_COUNT];
        let mut fold_bytes = vec![0_u8; selected_batched_fold_query_proof_encoded_len()];
        fold_bytes[..8].copy_from_slice(MLPCS_BATCHED_FOLD_QUERY_MAGIC);
        fold_bytes[8..10].copy_from_slice(&MLPCS_BATCHED_FOLD_QUERY_VERSION.to_be_bytes());
        let roots_start = 11;
        for ordinal in 0..24 {
            fold_bytes[roots_start + ordinal * 64..roots_start + (ordinal + 1) * 64]
                .fill(ordinal as u8 + 1);
        }
        let fold_query = decode_selected_batched_fold_query_proof(&fold_bytes, &queries).unwrap();
        let prelude = DualBoundaryMultilinearPcsPreludeProof {
            input_binding: Fp16::ZERO,
            output_binding: Fp16::ZERO,
            auxiliary_binding: Fp16::ZERO,
            batch_rounds: vec![[Fp16::ZERO; 3]; 22],
            terminal_left: [Fp16::ZERO;
                crate::multilinear_pcs_transcript::MLPCS_DUAL_BATCH_CLAIM_COUNT],
            terminal_right: [Fp16::ZERO;
                crate::multilinear_pcs_transcript::MLPCS_DUAL_BATCH_CLAIM_COUNT],
        };
        let proof = DualBoundaryMultilinearPcsProof {
            prelude,
            fold_query,
        };
        let encoded = proof.encode(&queries).unwrap();
        assert_eq!(encoded.len(), DUAL_BOUNDARY_MLPCS_PROOF_BYTES);
        assert_eq!(
            DualBoundaryMultilinearPcsProof::decode(&encoded, &queries).unwrap(),
            proof
        );
        assert_eq!(
            DualBoundaryMultilinearPcsProof::decode(&encoded[..encoded.len() - 1], &queries),
            Err(SelectedMultilinearPcsProofError::EncodingLength)
        );
    }
}
