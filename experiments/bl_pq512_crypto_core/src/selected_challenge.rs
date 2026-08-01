//! Canonical selected-suite challenge bundle and deployment-shaped verifier.

use core::fmt;

use alloc::vec::Vec;
use sha3::{Digest, Sha3_512};

use crate::cross_domain::CrossDomainRoot;
use crate::deep_quotient::{DomainOodsClaims, deep_claims_commitment};
use crate::field::{DecodeError, Fp16, M31};
use crate::fri_pipeline::{
    FriPipelineError, FriPipelineProof, verify_fri_pipeline, verify_fri_pipeline_v2,
};
use crate::merkle::RootHash;
use crate::oods::CirclePoint;
use crate::oracle_commitment::CommittedAirRoots;
use crate::proof_format::FriPipelineProofV2;
use crate::proof_parameters::{
    LOG_BLOWUP, ProofParameterError, QUERY_COUNT, TRACE_MASK_COEFFICIENT_COUNT, proof_suite_id,
    selected_parameter_commitment, selected_proof_geometry, selected_query_positions,
    selected_schedule_commitment,
};

pub const CHALLENGE_BUNDLE_MAGIC: &[u8; 8] = b"BLPQSCB1";
pub const CHALLENGE_BUNDLE_VERSION: u16 = 1;
pub const MAX_CHALLENGE_BUNDLE_BYTES: usize = 1 << 20;
pub const FRI_BATCH_DERIVATION_DOMAIN: &[u8] = b"BL/PQ512/WAVE1B/FRI-BATCH-DERIVATION/v1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedChallengeBundle {
    pub proof_suite_id: [u8; 64],
    pub parameter_commitment: [u8; 64],
    pub program_binary_commitment: [u8; 64],
    pub schedule_commitment: [u8; 64],
    pub session_id: [u8; 64],
    pub final_transcript_root: [u8; 64],
    pub evidence_commitment: [u8; 64],
    pub main_trace_root: [u8; 64],
    pub interaction_trace_root: [u8; 64],
    pub composition_root: [u8; 64],
    pub oods_claims_commitment: [u8; 64],
    pub fri_mask_root: [u8; 64],
    pub fri_batch_derivation_commitment: [u8; 64],
    pub fri_layer_roots: Vec<[u8; 64]>,
    pub logup_beta: Fp16,
    pub logup_gamma: Fp16,
    pub composition_alpha: Fp16,
    pub oods_point: CirclePoint,
    pub fri_batch_coefficient: Fp16,
    pub fri_fold_coefficients: Vec<Fp16>,
    pub query_seed: [u8; 64],
    pub query_positions: Vec<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SelectedChallengeError {
    EncodingLength,
    Truncated,
    TrailingBytes,
    Magic,
    Version,
    Shape,
    ZeroDigest,
    Decode(DecodeError),
    Parameters(ProofParameterError),
    Fri(FriPipelineError),
    Authentication,
}

impl From<DecodeError> for SelectedChallengeError {
    fn from(value: DecodeError) -> Self {
        Self::Decode(value)
    }
}

impl From<ProofParameterError> for SelectedChallengeError {
    fn from(value: ProofParameterError) -> Self {
        Self::Parameters(value)
    }
}

impl From<FriPipelineError> for SelectedChallengeError {
    fn from(value: FriPipelineError) -> Self {
        Self::Fri(value)
    }
}

impl fmt::Display for SelectedChallengeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "BL-PQ512 selected challenge error: {self:?}")
    }
}

impl core::error::Error for SelectedChallengeError {}

struct Reader<'a> {
    encoded: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(encoded: &'a [u8]) -> Result<Self, SelectedChallengeError> {
        if encoded.len() < 10 || encoded.len() > MAX_CHALLENGE_BUNDLE_BYTES {
            return Err(SelectedChallengeError::EncodingLength);
        }
        Ok(Self { encoded, offset: 0 })
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], SelectedChallengeError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(SelectedChallengeError::Truncated)?;
        let value = self
            .encoded
            .get(self.offset..end)
            .ok_or(SelectedChallengeError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, SelectedChallengeError> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| SelectedChallengeError::Truncated)?,
        ))
    }

    fn digest(&mut self) -> Result<[u8; 64], SelectedChallengeError> {
        let value: [u8; 64] = self
            .take(64)?
            .try_into()
            .map_err(|_| SelectedChallengeError::Truncated)?;
        if !value.iter().any(|byte| *byte != 0) {
            return Err(SelectedChallengeError::ZeroDigest);
        }
        Ok(value)
    }

    fn field(&mut self) -> Result<Fp16, SelectedChallengeError> {
        Ok(Fp16::decode(self.take(64)?)?)
    }
}

pub fn decode_selected_challenge_bundle(
    encoded: &[u8],
) -> Result<SelectedChallengeBundle, SelectedChallengeError> {
    let mut reader = Reader::new(encoded)?;
    if reader.take(8)? != CHALLENGE_BUNDLE_MAGIC {
        return Err(SelectedChallengeError::Magic);
    }
    if reader.u16()? != CHALLENGE_BUNDLE_VERSION {
        return Err(SelectedChallengeError::Version);
    }
    let proof_suite_id = reader.digest()?;
    let parameter_commitment = reader.digest()?;
    let program_binary_commitment = reader.digest()?;
    let schedule_commitment = reader.digest()?;
    let session_id = reader.digest()?;
    let final_transcript_root = reader.digest()?;
    let evidence_commitment = reader.digest()?;
    let main_trace_root = reader.digest()?;
    let interaction_trace_root = reader.digest()?;
    let composition_root = reader.digest()?;
    let oods_claims_commitment = reader.digest()?;
    let fri_mask_root = reader.digest()?;
    let fri_batch_derivation_commitment = reader.digest()?;
    let layer_count = usize::from(reader.u16()?);
    if !(1..=29).contains(&layer_count) {
        return Err(SelectedChallengeError::Shape);
    }
    let fri_layer_roots = (0..layer_count)
        .map(|_| reader.digest())
        .collect::<Result<Vec<_>, _>>()?;
    let logup_beta = reader.field()?;
    let logup_gamma = reader.field()?;
    let composition_alpha = reader.field()?;
    let oods_point = CirclePoint {
        x: reader.field()?,
        y: reader.field()?,
    };
    let fri_batch_coefficient = reader.field()?;
    let fold_count = usize::from(reader.u16()?);
    if fold_count != layer_count {
        return Err(SelectedChallengeError::Shape);
    }
    let fri_fold_coefficients = (0..fold_count)
        .map(|_| reader.field())
        .collect::<Result<Vec<_>, _>>()?;
    let query_seed = reader.digest()?;
    if usize::from(reader.u16()?) != QUERY_COUNT {
        return Err(SelectedChallengeError::Shape);
    }
    let query_positions = (0..QUERY_COUNT)
        .map(|_| {
            usize::try_from(u64::from_be_bytes(
                reader
                    .take(8)?
                    .try_into()
                    .map_err(|_| SelectedChallengeError::Truncated)?,
            ))
            .map_err(|_| SelectedChallengeError::Shape)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if reader.offset != encoded.len() {
        return Err(SelectedChallengeError::TrailingBytes);
    }
    Ok(SelectedChallengeBundle {
        proof_suite_id,
        parameter_commitment,
        program_binary_commitment,
        schedule_commitment,
        session_id,
        final_transcript_root,
        evidence_commitment,
        main_trace_root,
        interaction_trace_root,
        composition_root,
        oods_claims_commitment,
        fri_mask_root,
        fri_batch_derivation_commitment,
        fri_layer_roots,
        logup_beta,
        logup_gamma,
        composition_alpha,
        oods_point,
        fri_batch_coefficient,
        fri_fold_coefficients,
        query_seed,
        query_positions,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn fri_batch_derivation_commitment(
    program_binary_commitment: &[u8; 64],
    main_trace_root: &[u8; 64],
    interaction_trace_root: &[u8; 64],
    composition_root: &[u8; 64],
    claims_commitment: &[u8; 64],
    mask_root: &[u8; 64],
    batch_coefficient: Fp16,
) -> [u8; 64] {
    let mut hash = Sha3_512::new();
    hash.update(FRI_BATCH_DERIVATION_DOMAIN);
    hash.update(program_binary_commitment);
    hash.update(main_trace_root);
    hash.update(interaction_trace_root);
    hash.update(composition_root);
    hash.update(claims_commitment);
    hash.update(mask_root);
    hash.update(batch_coefficient.encode());
    hash.finalize().into()
}

pub fn validate_selected_challenge_bundle(
    bundle: &SelectedChallengeBundle,
    program_encoded: &[u8],
) -> Result<(), SelectedChallengeError> {
    let geometry = selected_proof_geometry(program_encoded)?;
    if bundle.parameter_commitment != selected_parameter_commitment()
        || bundle.program_binary_commitment != geometry.program_binary_commitment
        || bundle.schedule_commitment
            != selected_schedule_commitment(&geometry.program_binary_commitment, geometry)?
        || bundle.proof_suite_id
            != proof_suite_id(
                &geometry.program_binary_commitment,
                &bundle.schedule_commitment,
            )?
        || bundle.fri_layer_roots.len() != geometry.fold_round_count
        || bundle.fri_fold_coefficients.len() != geometry.fold_round_count
        || bundle.query_positions
            != selected_query_positions(
                &bundle.session_id,
                &bundle.query_seed,
                geometry.query_domain_size,
            )?
    {
        return Err(SelectedChallengeError::Authentication);
    }
    Ok(())
}

pub fn verify_selected_fri_pipeline(
    proof: &FriPipelineProof,
    bundle: &SelectedChallengeBundle,
    program_encoded: &[u8],
    supplied_public_inputs: &[M31],
    claims: &[DomainOodsClaims],
    final_constant: Fp16,
) -> Result<bool, SelectedChallengeError> {
    validate_selected_challenge_bundle(bundle, program_encoded)?;
    let claims_commitment = deep_claims_commitment(
        &bundle.program_binary_commitment,
        bundle.oods_point,
        claims,
        &bundle.main_trace_root,
        Some(&bundle.interaction_trace_root),
        &bundle.composition_root,
    )
    .map_err(|_| SelectedChallengeError::Shape)?;
    if claims_commitment != bundle.oods_claims_commitment
        || bundle.fri_batch_derivation_commitment
            != fri_batch_derivation_commitment(
                &bundle.program_binary_commitment,
                &bundle.main_trace_root,
                &bundle.interaction_trace_root,
                &bundle.composition_root,
                &bundle.oods_claims_commitment,
                &bundle.fri_mask_root,
                bundle.fri_batch_coefficient,
            )
    {
        return Err(SelectedChallengeError::Authentication);
    }
    let roots = CommittedAirRoots {
        main_trace: CrossDomainRoot::from_bytes(bundle.main_trace_root),
        interaction_trace: Some(CrossDomainRoot::from_bytes(bundle.interaction_trace_root)),
        composition: CrossDomainRoot::from_bytes(bundle.composition_root),
    };
    let mask_root = CrossDomainRoot::from_bytes(bundle.fri_mask_root);
    let layer_roots = bundle
        .fri_layer_roots
        .iter()
        .copied()
        .map(RootHash::from_bytes)
        .collect::<Vec<_>>();
    Ok(verify_fri_pipeline(
        proof,
        program_encoded,
        TRACE_MASK_COEFFICIENT_COUNT,
        LOG_BLOWUP,
        supplied_public_inputs,
        bundle.composition_alpha,
        bundle.logup_beta,
        bundle.logup_gamma,
        &roots,
        &mask_root,
        bundle.oods_point,
        claims,
        bundle.fri_batch_coefficient,
        &bundle.fri_fold_coefficients,
        &layer_roots,
        final_constant,
        &bundle.query_positions,
    )?)
}

pub fn verify_selected_fri_pipeline_v2(
    proof: &FriPipelineProofV2,
    bundle: &SelectedChallengeBundle,
    program_encoded: &[u8],
    supplied_public_inputs: &[M31],
    claims: &[DomainOodsClaims],
    final_constant: Fp16,
) -> Result<bool, SelectedChallengeError> {
    validate_selected_challenge_bundle(bundle, program_encoded)?;
    let claims_commitment = deep_claims_commitment(
        &bundle.program_binary_commitment,
        bundle.oods_point,
        claims,
        &bundle.main_trace_root,
        Some(&bundle.interaction_trace_root),
        &bundle.composition_root,
    )
    .map_err(|_| SelectedChallengeError::Shape)?;
    if claims_commitment != bundle.oods_claims_commitment
        || bundle.fri_batch_derivation_commitment
            != fri_batch_derivation_commitment(
                &bundle.program_binary_commitment,
                &bundle.main_trace_root,
                &bundle.interaction_trace_root,
                &bundle.composition_root,
                &bundle.oods_claims_commitment,
                &bundle.fri_mask_root,
                bundle.fri_batch_coefficient,
            )
    {
        return Err(SelectedChallengeError::Authentication);
    }
    let roots = CommittedAirRoots {
        main_trace: CrossDomainRoot::from_bytes(bundle.main_trace_root),
        interaction_trace: Some(CrossDomainRoot::from_bytes(bundle.interaction_trace_root)),
        composition: CrossDomainRoot::from_bytes(bundle.composition_root),
    };
    let mask_root = CrossDomainRoot::from_bytes(bundle.fri_mask_root);
    let layer_roots = bundle
        .fri_layer_roots
        .iter()
        .copied()
        .map(RootHash::from_bytes)
        .collect::<Vec<_>>();
    Ok(verify_fri_pipeline_v2(
        proof,
        program_encoded,
        TRACE_MASK_COEFFICIENT_COUNT,
        LOG_BLOWUP,
        supplied_public_inputs,
        bundle.composition_alpha,
        bundle.logup_beta,
        bundle.logup_gamma,
        &roots,
        &mask_root,
        bundle.oods_point,
        claims,
        bundle.fri_batch_coefficient,
        &bundle.fri_fold_coefficients,
        &layer_roots,
        final_constant,
        &bundle.query_positions,
    )?)
}
