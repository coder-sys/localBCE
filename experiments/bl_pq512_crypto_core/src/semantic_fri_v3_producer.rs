//! Proof-native semantic AIR/DEEP/FRI v3 producer.
//!
//! The selected prover already owns every committed oracle and private mask.
//! This module converts that exact in-memory state into native BindingRootV2
//! openings, serializes the verifier-owned witness grammar, and replays the
//! serialized bytes through the accepting v3 verifier before returning them.
//! It does not select a proof suite or alter lifecycle state.

use alloc::vec::Vec;

use crate::air_logup::AirLogupOracle;
use crate::cross_domain::DiskCrossDomainError;
use crate::deep_quotient::DeepQuotientOracles;
use crate::deep_quotient::deep_claims_commitment_binding_v2;
use crate::disk_air::DiskAirMainTraceOracle;
use crate::disk_composition::DiskAirCompositionOracle;
use crate::disk_fri::{
    DiskFriError, DiskFriPipeline, binding_disk_fri_layer_roots_v2,
    build_disk_fri_layer_binding_multiproofs_v2,
};
use crate::disk_logup::DiskAirLogupOracle;
use crate::field::{Fp16, M31};
use crate::fri_pipeline::{
    FriPipeline, FriPipelineError, FriPipelineProofV3, VerifiedFriPipelineV3,
    derive_fri_pipeline_proof_v3_geometry, fri_mask_layout_binding_v2,
    prove_fri_pipeline_v3_from_legacy, verify_fri_pipeline_v3_receipt,
};
use crate::oracle_commitment::{
    BindingCommittedAirRootsV2, CommittedAirOracles, OracleCommitmentError,
    derive_binding_oracle_commitment_layouts_v2, derive_oracle_commitment_layouts,
};
use crate::proof_format::{
    ProofFormatError, decode_fri_pipeline_proof_v3, encode_fri_pipeline_proof_v3,
};
use crate::v3_real_authority::{
    RealAuthorityError, SemanticFriParametersV3, decode_semantic_fri_parameters_v3,
    encode_semantic_fri_parameters_v3,
};

#[derive(Debug)]
pub enum SemanticFriV3ProducerError {
    Fri(FriPipelineError),
    Format(ProofFormatError),
    Encoding(RealAuthorityError),
    DiskCrossDomain(DiskCrossDomainError),
    DiskFri(DiskFriError),
    Oracle(OracleCommitmentError),
    SourceShape,
    Roundtrip,
}

impl From<FriPipelineError> for SemanticFriV3ProducerError {
    fn from(value: FriPipelineError) -> Self {
        Self::Fri(value)
    }
}

impl From<ProofFormatError> for SemanticFriV3ProducerError {
    fn from(value: ProofFormatError) -> Self {
        Self::Format(value)
    }
}

impl From<RealAuthorityError> for SemanticFriV3ProducerError {
    fn from(value: RealAuthorityError) -> Self {
        Self::Encoding(value)
    }
}

impl From<DiskCrossDomainError> for SemanticFriV3ProducerError {
    fn from(value: DiskCrossDomainError) -> Self {
        Self::DiskCrossDomain(value)
    }
}

impl From<DiskFriError> for SemanticFriV3ProducerError {
    fn from(value: DiskFriError) -> Self {
        Self::DiskFri(value)
    }
}

impl From<OracleCommitmentError> for SemanticFriV3ProducerError {
    fn from(value: OracleCommitmentError) -> Self {
        Self::Oracle(value)
    }
}

#[derive(Debug)]
pub struct ProducedSemanticFriV3 {
    pub encoded_proof: Vec<u8>,
    pub encoded_parameters: Vec<u8>,
    pub verified: VerifiedFriPipelineV3,
}

/// Construct and verify the native semantic proof from the exact legacy
/// in-memory prover state. The legacy state is used only as a construction
/// source; no legacy root or authentication path enters the returned proof.
#[allow(clippy::too_many_arguments)]
pub fn produce_semantic_fri_v3_from_legacy(
    program_encoded: &[u8],
    mask_coefficient_count: usize,
    log_blowup: u8,
    deep: &DeepQuotientOracles,
    pipeline: &FriPipeline,
    oracles: &CommittedAirOracles,
    logup: &AirLogupOracle,
    query_indices: &[usize],
    public_inputs: &[M31],
    composition_alpha: Fp16,
    logup_beta: Fp16,
    logup_gamma: Fp16,
) -> Result<ProducedSemanticFriV3, SemanticFriV3ProducerError> {
    let construction = prove_fri_pipeline_v3_from_legacy(
        program_encoded,
        mask_coefficient_count,
        log_blowup,
        deep,
        pipeline,
        oracles,
        logup,
        query_indices,
    )?;
    let parameters = SemanticFriParametersV3 {
        public_inputs: public_inputs.to_vec(),
        mask_coefficient_count,
        log_blowup,
        oracle_roots: construction.oracle_roots,
        mask_root: construction.mask_root,
        claims: deep.claims.clone(),
        layer_roots: construction.layer_roots,
        final_constant: pipeline.final_constant,
    };
    serialize_and_verify_semantic_fri_v3(
        program_encoded,
        composition_alpha,
        logup_beta,
        logup_gamma,
        query_indices,
        deep.query,
        pipeline.cascade.batch_coefficient,
        &pipeline.cascade.fold_coefficients,
        construction.proof,
        parameters,
    )
}

/// Construct and independently verify the native semantic proof from the
/// bounded disk prover's exact canonical source files. Native roots and
/// multiproofs are recomputed from values; no legacy root or path is promoted.
#[allow(clippy::too_many_arguments)]
pub fn produce_semantic_fri_v3_from_disk(
    program_encoded: &[u8],
    mask_coefficient_count: usize,
    log_blowup: u8,
    pipeline: &DiskFriPipeline,
    main: &DiskAirMainTraceOracle,
    logup: &DiskAirLogupOracle,
    composition: &DiskAirCompositionOracle,
    query_indices: &[usize],
    public_inputs: &[M31],
    composition_alpha: Fp16,
    logup_beta: Fp16,
    logup_gamma: Fp16,
) -> Result<ProducedSemanticFriV3, SemanticFriV3ProducerError> {
    let legacy =
        derive_oracle_commitment_layouts(program_encoded, mask_coefficient_count, log_blowup)?;
    if main.program_binary_commitment != legacy.program_binary_commitment
        || composition.program_binary_commitment != legacy.program_binary_commitment
        || main.tree.layout() != &legacy.main_trace
        || logup.tree.layout()
            != legacy
                .interaction_trace
                .as_ref()
                .ok_or(SemanticFriV3ProducerError::SourceShape)?
        || composition.tree.layout() != &legacy.composition
        || pipeline.layers.len() != pipeline.fold_log_sizes.len()
        || pipeline.layers.is_empty()
    {
        return Err(SemanticFriV3ProducerError::SourceShape);
    }
    let native = derive_binding_oracle_commitment_layouts_v2(
        program_encoded,
        mask_coefficient_count,
        log_blowup,
    )?;
    let main_tree = main.tree.binding_v2_tree(native.main_trace.clone())?;
    let interaction_layout = native
        .interaction_trace
        .clone()
        .ok_or(SemanticFriV3ProducerError::SourceShape)?;
    let interaction_tree = logup.tree.binding_v2_tree(interaction_layout)?;
    let composition_tree = composition
        .tree
        .binding_v2_tree(native.composition.clone())?;
    let oracle_roots = BindingCommittedAirRootsV2 {
        main_trace: main_tree.root(),
        interaction_trace: Some(interaction_tree.root()),
        composition: composition_tree.root(),
    };
    let claims_commitment = deep_claims_commitment_binding_v2(
        &native.program_binary_commitment,
        pipeline.plan.query,
        &pipeline.plan.claims,
        &oracle_roots.main_trace,
        oracle_roots.interaction_trace.as_ref(),
        &oracle_roots.composition,
    )
    .map_err(|_| SemanticFriV3ProducerError::SourceShape)?;
    let mask_layout = fri_mask_layout_binding_v2(&claims_commitment, &pipeline.plan.claims)?;
    let mask_tree = pipeline.mask.tree.binding_v2_tree(mask_layout)?;
    let layer_roots = binding_disk_fri_layer_roots_v2(pipeline)?;
    let geometry = derive_fri_pipeline_proof_v3_geometry(
        program_encoded,
        mask_coefficient_count,
        log_blowup,
        pipeline.plan.query,
        &pipeline.plan.claims,
        &oracle_roots,
        query_indices,
    )?;
    let mask = mask_tree.proof(&geometry.mask_indices)?;
    let main_proof = main_tree.proof(&geometry.main_indices)?;
    let interaction = Some(interaction_tree.proof(&geometry.interaction_indices)?);
    let composition_proof = composition_tree.proof(&geometry.composition_indices)?;
    let fri_layers =
        build_disk_fri_layer_binding_multiproofs_v2(pipeline, &layer_roots, query_indices)?;
    let proof = FriPipelineProofV3 {
        logup_final_sums: logup
            .interactions
            .iter()
            .map(|interaction| interaction.final_sum)
            .collect(),
        query_indices: query_indices.to_vec(),
        mask,
        main: main_proof,
        interaction,
        composition: composition_proof,
        fri_layers,
    };
    let parameters = SemanticFriParametersV3 {
        public_inputs: public_inputs.to_vec(),
        mask_coefficient_count,
        log_blowup,
        oracle_roots,
        mask_root: mask_tree.root(),
        claims: pipeline.plan.claims.clone(),
        layer_roots,
        final_constant: pipeline.final_constant,
    };
    serialize_and_verify_semantic_fri_v3(
        program_encoded,
        composition_alpha,
        logup_beta,
        logup_gamma,
        query_indices,
        pipeline.plan.query,
        pipeline.batch_coefficient,
        &pipeline.fold_coefficients,
        proof,
        parameters,
    )
}

#[allow(clippy::too_many_arguments)]
fn serialize_and_verify_semantic_fri_v3(
    program_encoded: &[u8],
    composition_alpha: Fp16,
    logup_beta: Fp16,
    logup_gamma: Fp16,
    query_indices: &[usize],
    query_point: crate::oods::CirclePoint,
    batch_coefficient: Fp16,
    fold_coefficients: &[Fp16],
    proof: FriPipelineProofV3,
    parameters: SemanticFriParametersV3,
) -> Result<ProducedSemanticFriV3, SemanticFriV3ProducerError> {
    let geometry = derive_fri_pipeline_proof_v3_geometry(
        program_encoded,
        parameters.mask_coefficient_count,
        parameters.log_blowup,
        query_point,
        &parameters.claims,
        &parameters.oracle_roots,
        query_indices,
    )?;
    let encoded_proof = encode_fri_pipeline_proof_v3(&proof, &geometry, query_indices)?;
    let encoded_parameters = encode_semantic_fri_parameters_v3(&parameters)?;

    // Replay exactly the bytes that will cross the process boundary. This is
    // the producer qualification check; the outer runner repeats it later.
    let decoded_parameters = decode_semantic_fri_parameters_v3(&encoded_parameters)?;
    if decoded_parameters != parameters {
        return Err(SemanticFriV3ProducerError::Roundtrip);
    }
    let decoded_proof = decode_fri_pipeline_proof_v3(&encoded_proof, &geometry, query_indices)?;
    let verified = verify_fri_pipeline_v3_receipt(
        &decoded_proof,
        program_encoded,
        decoded_parameters.mask_coefficient_count,
        decoded_parameters.log_blowup,
        &decoded_parameters.public_inputs,
        composition_alpha,
        logup_beta,
        logup_gamma,
        &decoded_parameters.oracle_roots,
        &decoded_parameters.mask_root,
        query_point,
        &decoded_parameters.claims,
        batch_coefficient,
        fold_coefficients,
        &decoded_parameters.layer_roots,
        decoded_parameters.final_constant,
        query_indices,
    )?;
    Ok(ProducedSemanticFriV3 {
        encoded_proof,
        encoded_parameters,
        verified,
    })
}

pub const SEMANTIC_FRI_V3_PRODUCER_AVAILABLE: bool = true;
