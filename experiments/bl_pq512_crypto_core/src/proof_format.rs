//! Canonical bounded grammar for BL-PQ512 interactive proof openings.

use alloc::collections::{BTreeMap, BTreeSet, btree_map::Entry};
use alloc::vec::Vec;

use crate::cross_domain::{
    CrossDomainError, CrossDomainProof, DomainOpening, DomainSpec, EvaluationField,
    transpose_circle_fft_index,
};
use crate::field::{DecodeError, Fp16};
use crate::fri_layer_multiproof::{
    FriLayerMultiproofError, FriPipelineCanonicalMultiproofs, compact_fri_layer_openings,
};
use crate::fri_pipeline::{FriPipelineLayerOpening, FriPipelineProof, FriPipelineQueryProof};
use crate::merkle::{MerkleError, MerkleProof};

pub const PROOF_MAGIC: &[u8; 8] = b"BLPQPRF1";
pub const PROOF_VERSION: u16 = 1;
pub const PROOF_V2_MAGIC: &[u8; 8] = b"BLPQPRF2";
pub const PROOF_V2_VERSION: u16 = 2;
pub const MAX_PROOF_BYTES: usize = 512 * 1024 * 1024;
pub const MAX_PROOF_QUERIES: usize = 1024;
pub const MAX_NEXT_PROOFS_PER_QUERY: usize = 128;
pub const MAX_CROSS_DOMAIN_OPENINGS: usize = 30;
pub const MAX_COLUMNS_PER_OPENING: u32 = 1 << 20;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProofFormatError {
    Length,
    Magic,
    Version,
    Truncated,
    Count,
    Integer,
    Flag,
    Field,
    Attribution,
    Trailing,
    CrossDomain(CrossDomainError),
    FriLayerMultiproof(FriLayerMultiproofError),
    Merkle(MerkleError),
    Decode(DecodeError),
}

/// Exact byte attribution for the canonical v1 proof grammar.
///
/// The sections follow encoder order and deliberately separate FRI path
/// digests from opened values.  This is cost evidence only; it does not alter
/// the proof bytes or the cryptographic verification decision.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FriPipelineProofByteAttribution {
    pub header_bytes: usize,
    pub initial_index_bytes: usize,
    pub mask_opening_bytes: usize,
    pub main_opening_bytes: usize,
    pub interaction_opening_bytes: usize,
    pub composition_opening_bytes: usize,
    pub next_main_opening_bytes: usize,
    pub next_interaction_opening_bytes: usize,
    pub fri_layer_count_bytes: usize,
    pub fri_opened_value_bytes: usize,
    pub fri_log_size_bytes: usize,
    pub fri_merkle_metadata_bytes: usize,
    pub fri_path_digest_bytes: usize,
    pub query_count: usize,
    pub fri_layer_count: usize,
    pub fri_opened_value_count: usize,
    pub fri_path_digest_count: usize,
}

impl FriPipelineProofByteAttribution {
    pub fn total_bytes(&self) -> Option<usize> {
        [
            self.header_bytes,
            self.initial_index_bytes,
            self.mask_opening_bytes,
            self.main_opening_bytes,
            self.interaction_opening_bytes,
            self.composition_opening_bytes,
            self.next_main_opening_bytes,
            self.next_interaction_opening_bytes,
            self.fri_layer_count_bytes,
            self.fri_opened_value_bytes,
            self.fri_log_size_bytes,
            self.fri_merkle_metadata_bytes,
            self.fri_path_digest_bytes,
        ]
        .into_iter()
        .try_fold(0_usize, usize::checked_add)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncodedFriPipelineProof {
    pub bytes: Vec<u8>,
    pub attribution: FriPipelineProofByteAttribution,
}

/// Decoded v2 proof data. Per-query `layers` are always empty: the canonical
/// global multiproof is the sole authoritative representation of FRI openings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FriPipelineProofV2 {
    pub logup_final_sums: Vec<Fp16>,
    pub queries: Vec<FriPipelineQueryProof>,
    pub fri_layer_multiproofs: FriPipelineCanonicalMultiproofs,
}

impl From<CrossDomainError> for ProofFormatError {
    fn from(value: CrossDomainError) -> Self {
        Self::CrossDomain(value)
    }
}

impl From<FriLayerMultiproofError> for ProofFormatError {
    fn from(value: FriLayerMultiproofError) -> Self {
        Self::FriLayerMultiproof(value)
    }
}

impl From<MerkleError> for ProofFormatError {
    fn from(value: MerkleError) -> Self {
        Self::Merkle(value)
    }
}

impl From<DecodeError> for ProofFormatError {
    fn from(value: DecodeError) -> Self {
        Self::Decode(value)
    }
}

fn push_u32(output: &mut Vec<u8>, value: usize) -> Result<(), ProofFormatError> {
    output.extend_from_slice(
        &u32::try_from(value)
            .map_err(|_| ProofFormatError::Integer)?
            .to_be_bytes(),
    );
    Ok(())
}

fn push_u64(output: &mut Vec<u8>, value: usize) -> Result<(), ProofFormatError> {
    output.extend_from_slice(
        &u64::try_from(value)
            .map_err(|_| ProofFormatError::Integer)?
            .to_be_bytes(),
    );
    Ok(())
}

fn opening_payload_length(spec: DomainSpec) -> Result<usize, ProofFormatError> {
    (spec.column_count as usize)
        .checked_mul(match spec.field {
            EvaluationField::M31 => 4,
            EvaluationField::Fp16 => 64,
        })
        .ok_or(ProofFormatError::Integer)
}

fn encode_cross_domain(
    output: &mut Vec<u8>,
    proof: &CrossDomainProof,
) -> Result<(), ProofFormatError> {
    push_u64(output, proof.query_fft_index())?;
    output.push(u8::try_from(proof.siblings().len()).map_err(|_| ProofFormatError::Count)?);
    for sibling in proof.siblings() {
        output.extend_from_slice(sibling);
    }
    output.push(u8::try_from(proof.openings().len()).map_err(|_| ProofFormatError::Count)?);
    for opening in proof.openings() {
        output.push(opening.spec.log_size);
        output.extend_from_slice(&(opening.spec.field as u16).to_be_bytes());
        output.extend_from_slice(&opening.spec.column_count.to_be_bytes());
        push_u64(output, opening.fft_index)?;
        push_u32(output, opening.payload.len())?;
        output.extend_from_slice(&opening.payload);
    }
    Ok(())
}

fn encode_optional_cross_domain(
    output: &mut Vec<u8>,
    proof: Option<&CrossDomainProof>,
) -> Result<(), ProofFormatError> {
    if let Some(proof) = proof {
        output.push(1);
        encode_cross_domain(output, proof)
    } else {
        output.push(0);
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CrossDomainProofSkeleton {
    query_fft_index: usize,
    openings: Vec<DomainOpeningSkeleton>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DomainOpeningSkeleton {
    spec: DomainSpec,
    fft_index: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FriPipelineQueryAssembly {
    initial_index: usize,
    has_interaction_left: bool,
    has_interaction_right: bool,
    next_main_count: usize,
    next_interaction_count: usize,
}

fn encode_cross_domain_skeleton(
    output: &mut Vec<u8>,
    proof: &CrossDomainProof,
) -> Result<(), ProofFormatError> {
    push_u64(output, proof.query_fft_index())?;
    output.push(u8::try_from(proof.openings().len()).map_err(|_| ProofFormatError::Count)?);
    for opening in proof.openings() {
        output.push(opening.spec.log_size);
        output.extend_from_slice(&(opening.spec.field as u16).to_be_bytes());
        output.extend_from_slice(&opening.spec.column_count.to_be_bytes());
        push_u64(output, opening.fft_index)?;
    }
    Ok(())
}

fn encode_optional_cross_domain_skeleton(
    output: &mut Vec<u8>,
    proof: Option<&CrossDomainProof>,
) -> Result<(), ProofFormatError> {
    if let Some(proof) = proof {
        output.push(1);
        encode_cross_domain_skeleton(output, proof)
    } else {
        output.push(0);
        Ok(())
    }
}

fn cross_domain_sibling_positions(
    query_fft_index: usize,
    maximum_log_size: u8,
) -> Result<Vec<(u8, usize)>, ProofFormatError> {
    let mut current_index = transpose_circle_fft_index(query_fft_index, maximum_log_size)?;
    let mut positions = Vec::with_capacity(usize::from(maximum_log_size));
    for level in (1..=maximum_log_size).rev() {
        positions.push((level, current_index ^ 1));
        current_index >>= 1;
    }
    Ok(positions)
}

fn encode_cross_domain_frontier(
    output: &mut Vec<u8>,
    proofs: &[&CrossDomainProof],
) -> Result<(), ProofFormatError> {
    let mut frontier = BTreeMap::<(u8, usize), [u8; 64]>::new();
    let mut openings = BTreeMap::<(u8, usize), &DomainOpening>::new();
    for proof in proofs {
        let maximum_log_size =
            u8::try_from(proof.siblings().len()).map_err(|_| ProofFormatError::Count)?;
        let positions = cross_domain_sibling_positions(proof.query_fft_index(), maximum_log_size)?;
        if positions.len() != proof.siblings().len() {
            return Err(ProofFormatError::Attribution);
        }
        for (position, digest) in positions.into_iter().zip(proof.siblings()) {
            match frontier.entry(position) {
                Entry::Vacant(entry) => {
                    entry.insert(*digest);
                }
                Entry::Occupied(entry) if entry.get() == digest => {}
                Entry::Occupied(_) => return Err(ProofFormatError::Attribution),
            }
        }
        for opening in proof.openings() {
            let key = (opening.spec.log_size, opening.fft_index);
            match openings.entry(key) {
                Entry::Vacant(entry) => {
                    entry.insert(opening);
                }
                Entry::Occupied(entry)
                    if entry.get().spec == opening.spec
                        && entry.get().payload == opening.payload => {}
                Entry::Occupied(_) => return Err(ProofFormatError::Attribution),
            }
        }
    }
    push_u32(output, frontier.len())?;
    for digest in frontier.values() {
        output.extend_from_slice(digest);
    }
    push_u32(output, openings.len())?;
    for opening in openings.values() {
        output.extend_from_slice(&opening.payload);
    }
    Ok(())
}

fn add_delta(total: &mut usize, output: &[u8], start: usize) -> Result<(), ProofFormatError> {
    let delta = output
        .len()
        .checked_sub(start)
        .ok_or(ProofFormatError::Attribution)?;
    *total = total
        .checked_add(delta)
        .ok_or(ProofFormatError::Attribution)?;
    Ok(())
}

fn encode_fri_merkle_attributed(
    output: &mut Vec<u8>,
    proof: &MerkleProof,
    attribution: &mut FriPipelineProofByteAttribution,
) -> Result<(), ProofFormatError> {
    let metadata_start = output.len();
    push_u64(output, proof.leaf_index())?;
    push_u64(output, proof.leaf_count())?;
    output.push(u8::try_from(proof.siblings().len()).map_err(|_| ProofFormatError::Count)?);
    add_delta(
        &mut attribution.fri_merkle_metadata_bytes,
        output,
        metadata_start,
    )?;

    let paths_start = output.len();
    for sibling in proof.siblings() {
        output.extend_from_slice(sibling);
    }
    add_delta(&mut attribution.fri_path_digest_bytes, output, paths_start)?;
    attribution.fri_path_digest_count = attribution
        .fri_path_digest_count
        .checked_add(proof.siblings().len())
        .ok_or(ProofFormatError::Attribution)?;
    Ok(())
}

/// Encode the exact proof object without roots or challenges, which arrive in
/// separately PQ-authenticated public-coin receipts.
pub fn encode_fri_pipeline_proof(proof: &FriPipelineProof) -> Result<Vec<u8>, ProofFormatError> {
    Ok(encode_fri_pipeline_proof_with_attribution(proof)?.bytes)
}

/// Encode v1 and return a byte-for-byte attribution produced by that same pass.
pub fn encode_fri_pipeline_proof_with_attribution(
    proof: &FriPipelineProof,
) -> Result<EncodedFriPipelineProof, ProofFormatError> {
    if proof.queries.is_empty() || proof.queries.len() > MAX_PROOF_QUERIES {
        return Err(ProofFormatError::Count);
    }
    let mut output = Vec::new();
    let mut attribution = FriPipelineProofByteAttribution {
        query_count: proof.queries.len(),
        ..FriPipelineProofByteAttribution::default()
    };
    let header_start = output.len();
    output.extend_from_slice(PROOF_MAGIC);
    output.extend_from_slice(&PROOF_VERSION.to_be_bytes());
    push_u32(&mut output, proof.logup_final_sums.len())?;
    for value in &proof.logup_final_sums {
        output.extend_from_slice(&value.encode());
    }
    push_u32(&mut output, proof.queries.len())?;
    add_delta(&mut attribution.header_bytes, &output, header_start)?;
    for query in &proof.queries {
        if query.next_main.len() > MAX_NEXT_PROOFS_PER_QUERY
            || query.next_interaction.len() > MAX_NEXT_PROOFS_PER_QUERY
            || query.layers.is_empty()
            || query.layers.len() > 29
        {
            return Err(ProofFormatError::Count);
        }
        let section_start = output.len();
        push_u64(&mut output, query.initial_index)?;
        add_delta(&mut attribution.initial_index_bytes, &output, section_start)?;

        let section_start = output.len();
        encode_cross_domain(&mut output, &query.mask_left)?;
        encode_cross_domain(&mut output, &query.mask_right)?;
        add_delta(&mut attribution.mask_opening_bytes, &output, section_start)?;

        let section_start = output.len();
        encode_cross_domain(&mut output, &query.main_left)?;
        encode_cross_domain(&mut output, &query.main_right)?;
        add_delta(&mut attribution.main_opening_bytes, &output, section_start)?;

        let section_start = output.len();
        encode_optional_cross_domain(&mut output, query.interaction_left.as_ref())?;
        encode_optional_cross_domain(&mut output, query.interaction_right.as_ref())?;
        add_delta(
            &mut attribution.interaction_opening_bytes,
            &output,
            section_start,
        )?;

        let section_start = output.len();
        encode_cross_domain(&mut output, &query.composition_left)?;
        encode_cross_domain(&mut output, &query.composition_right)?;
        add_delta(
            &mut attribution.composition_opening_bytes,
            &output,
            section_start,
        )?;

        let section_start = output.len();
        push_u32(&mut output, query.next_main.len())?;
        for item in &query.next_main {
            encode_cross_domain(&mut output, item)?;
        }
        add_delta(
            &mut attribution.next_main_opening_bytes,
            &output,
            section_start,
        )?;

        let section_start = output.len();
        push_u32(&mut output, query.next_interaction.len())?;
        for item in &query.next_interaction {
            encode_cross_domain(&mut output, item)?;
        }
        add_delta(
            &mut attribution.next_interaction_opening_bytes,
            &output,
            section_start,
        )?;

        let section_start = output.len();
        output.push(u8::try_from(query.layers.len()).map_err(|_| ProofFormatError::Count)?);
        add_delta(
            &mut attribution.fri_layer_count_bytes,
            &output,
            section_start,
        )?;
        attribution.fri_layer_count = attribution
            .fri_layer_count
            .checked_add(query.layers.len())
            .ok_or(ProofFormatError::Attribution)?;
        for layer in &query.layers {
            let section_start = output.len();
            output.push(layer.log_size);
            add_delta(&mut attribution.fri_log_size_bytes, &output, section_start)?;

            let section_start = output.len();
            output.extend_from_slice(&layer.left.encode());
            output.extend_from_slice(&layer.right.encode());
            add_delta(
                &mut attribution.fri_opened_value_bytes,
                &output,
                section_start,
            )?;
            attribution.fri_opened_value_count = attribution
                .fri_opened_value_count
                .checked_add(2)
                .ok_or(ProofFormatError::Attribution)?;
            encode_fri_merkle_attributed(&mut output, &layer.left_proof, &mut attribution)?;
            encode_fri_merkle_attributed(&mut output, &layer.right_proof, &mut attribution)?;
        }
        if output.len() > MAX_PROOF_BYTES {
            return Err(ProofFormatError::Length);
        }
    }
    if attribution.total_bytes() != Some(output.len()) {
        return Err(ProofFormatError::Attribution);
    }
    Ok(EncodedFriPipelineProof {
        bytes: output,
        attribution,
    })
}

struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(input: &'a [u8]) -> Result<Self, ProofFormatError> {
        if input.len() < 14 || input.len() > MAX_PROOF_BYTES {
            return Err(ProofFormatError::Length);
        }
        Ok(Self { input, offset: 0 })
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ProofFormatError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(ProofFormatError::Integer)?;
        let value = self
            .input
            .get(self.offset..end)
            .ok_or(ProofFormatError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, ProofFormatError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ProofFormatError> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| ProofFormatError::Truncated)?,
        ))
    }

    fn u32(&mut self) -> Result<u32, ProofFormatError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| ProofFormatError::Truncated)?,
        ))
    }

    fn usize64(&mut self) -> Result<usize, ProofFormatError> {
        usize::try_from(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| ProofFormatError::Truncated)?,
        ))
        .map_err(|_| ProofFormatError::Integer)
    }

    fn digest(&mut self) -> Result<[u8; 64], ProofFormatError> {
        self.take(64)?
            .try_into()
            .map_err(|_| ProofFormatError::Truncated)
    }

    fn count(&mut self, maximum: usize) -> Result<usize, ProofFormatError> {
        let count = usize::try_from(self.u32()?).map_err(|_| ProofFormatError::Integer)?;
        if count > maximum {
            return Err(ProofFormatError::Count);
        }
        Ok(count)
    }

    fn cross_domain(&mut self) -> Result<CrossDomainProof, ProofFormatError> {
        let query_fft_index = self.usize64()?;
        let sibling_count = usize::from(self.u8()?);
        if sibling_count == 0 || sibling_count > 30 {
            return Err(ProofFormatError::Count);
        }
        let siblings = (0..sibling_count)
            .map(|_| self.digest())
            .collect::<Result<Vec<_>, _>>()?;
        let opening_count = usize::from(self.u8()?);
        if opening_count == 0 || opening_count > MAX_CROSS_DOMAIN_OPENINGS {
            return Err(ProofFormatError::Count);
        }
        let mut openings = Vec::with_capacity(opening_count);
        for _ in 0..opening_count {
            let log_size = self.u8()?;
            let field = match self.u16()? {
                1 => EvaluationField::M31,
                2 => EvaluationField::Fp16,
                _ => return Err(ProofFormatError::Field),
            };
            let column_count = self.u32()?;
            if column_count == 0 || column_count > MAX_COLUMNS_PER_OPENING {
                return Err(ProofFormatError::Count);
            }
            let spec = DomainSpec::new(log_size, field, column_count)?;
            let fft_index = self.usize64()?;
            let payload_length =
                usize::try_from(self.u32()?).map_err(|_| ProofFormatError::Integer)?;
            if payload_length != opening_payload_length(spec)? {
                return Err(ProofFormatError::Length);
            }
            openings.push(DomainOpening {
                spec,
                fft_index,
                payload: self.take(payload_length)?.to_vec(),
            });
        }
        Ok(CrossDomainProof::from_parts(
            query_fft_index,
            siblings,
            openings,
        )?)
    }

    fn optional_cross_domain(&mut self) -> Result<Option<CrossDomainProof>, ProofFormatError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.cross_domain()?)),
            _ => Err(ProofFormatError::Flag),
        }
    }

    fn cross_domain_skeleton(&mut self) -> Result<CrossDomainProofSkeleton, ProofFormatError> {
        let query_fft_index = self.usize64()?;
        let opening_count = usize::from(self.u8()?);
        if opening_count == 0 || opening_count > MAX_CROSS_DOMAIN_OPENINGS {
            return Err(ProofFormatError::Count);
        }
        let mut openings = Vec::with_capacity(opening_count);
        for _ in 0..opening_count {
            let log_size = self.u8()?;
            let field = match self.u16()? {
                1 => EvaluationField::M31,
                2 => EvaluationField::Fp16,
                _ => return Err(ProofFormatError::Field),
            };
            let column_count = self.u32()?;
            if column_count == 0 || column_count > MAX_COLUMNS_PER_OPENING {
                return Err(ProofFormatError::Count);
            }
            let spec = DomainSpec::new(log_size, field, column_count)?;
            let fft_index = self.usize64()?;
            openings.push(DomainOpeningSkeleton { spec, fft_index });
        }
        if openings
            .windows(2)
            .any(|pair| pair[0].spec.log_size >= pair[1].spec.log_size)
        {
            return Err(ProofFormatError::Count);
        }
        Ok(CrossDomainProofSkeleton {
            query_fft_index,
            openings,
        })
    }

    fn optional_cross_domain_skeleton(
        &mut self,
    ) -> Result<Option<CrossDomainProofSkeleton>, ProofFormatError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.cross_domain_skeleton()?)),
            _ => Err(ProofFormatError::Flag),
        }
    }

    fn merkle(&mut self) -> Result<MerkleProof, ProofFormatError> {
        let leaf_index = self.usize64()?;
        let leaf_count = self.usize64()?;
        let count = usize::from(self.u8()?);
        if count > 30 {
            return Err(ProofFormatError::Count);
        }
        let siblings = (0..count)
            .map(|_| self.digest())
            .collect::<Result<Vec<_>, _>>()?;
        Ok(MerkleProof::from_parts(leaf_index, leaf_count, siblings)?)
    }
}

fn decode_cross_domain_frontier(
    reader: &mut Reader<'_>,
    skeletons: Vec<CrossDomainProofSkeleton>,
) -> Result<Vec<CrossDomainProof>, ProofFormatError> {
    let mut required = BTreeSet::<(u8, usize)>::new();
    let mut required_openings = BTreeMap::<(u8, usize), DomainSpec>::new();
    let mut proof_positions = Vec::with_capacity(skeletons.len());
    for skeleton in &skeletons {
        let maximum_log_size = skeleton
            .openings
            .last()
            .ok_or(ProofFormatError::Count)?
            .spec
            .log_size;
        let positions = cross_domain_sibling_positions(skeleton.query_fft_index, maximum_log_size)?;
        required.extend(positions.iter().copied());
        proof_positions.push(positions);
        for opening in &skeleton.openings {
            let key = (opening.spec.log_size, opening.fft_index);
            if required_openings
                .insert(key, opening.spec)
                .is_some_and(|existing| existing != opening.spec)
            {
                return Err(ProofFormatError::Count);
            }
        }
    }
    if reader.count(MAX_PROOF_BYTES / 64)? != required.len() {
        return Err(ProofFormatError::Count);
    }
    let frontier = required
        .into_iter()
        .map(|position| Ok((position, reader.digest()?)))
        .collect::<Result<BTreeMap<_, _>, ProofFormatError>>()?;
    if reader.count(MAX_PROOF_BYTES)? != required_openings.len() {
        return Err(ProofFormatError::Count);
    }
    let opening_payloads = required_openings
        .iter()
        .map(|(key, spec)| Ok((*key, reader.take(opening_payload_length(*spec)?)?.to_vec())))
        .collect::<Result<BTreeMap<_, _>, ProofFormatError>>()?;
    skeletons
        .into_iter()
        .zip(proof_positions)
        .map(|(skeleton, positions)| {
            let siblings = positions
                .iter()
                .map(|position| {
                    frontier
                        .get(position)
                        .copied()
                        .ok_or(ProofFormatError::Count)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let openings = skeleton
                .openings
                .into_iter()
                .map(|opening| {
                    let payload = opening_payloads
                        .get(&(opening.spec.log_size, opening.fft_index))
                        .cloned()
                        .ok_or(ProofFormatError::Count)?;
                    Ok(DomainOpening {
                        spec: opening.spec,
                        fft_index: opening.fft_index,
                        payload,
                    })
                })
                .collect::<Result<Vec<_>, ProofFormatError>>()?;
            Ok(CrossDomainProof::from_parts(
                skeleton.query_fft_index,
                siblings,
                openings,
            )?)
        })
        .collect()
}

/// Parse a proof with allocation and count limits before any cryptographic
/// verification is attempted.
pub fn decode_fri_pipeline_proof(encoded: &[u8]) -> Result<FriPipelineProof, ProofFormatError> {
    let mut reader = Reader::new(encoded)?;
    if reader.take(8)? != PROOF_MAGIC {
        return Err(ProofFormatError::Magic);
    }
    if reader.u16()? != PROOF_VERSION {
        return Err(ProofFormatError::Version);
    }
    let sum_count = reader.count(MAX_NEXT_PROOFS_PER_QUERY * MAX_PROOF_QUERIES)?;
    let logup_final_sums = (0..sum_count)
        .map(|_| Fp16::decode(reader.take(64)?).map_err(ProofFormatError::from))
        .collect::<Result<Vec<_>, _>>()?;
    let query_count = reader.count(MAX_PROOF_QUERIES)?;
    if query_count == 0 {
        return Err(ProofFormatError::Count);
    }
    let mut queries = Vec::with_capacity(query_count);
    for _ in 0..query_count {
        let initial_index = reader.usize64()?;
        let mask_left = reader.cross_domain()?;
        let mask_right = reader.cross_domain()?;
        let main_left = reader.cross_domain()?;
        let main_right = reader.cross_domain()?;
        let interaction_left = reader.optional_cross_domain()?;
        let interaction_right = reader.optional_cross_domain()?;
        let composition_left = reader.cross_domain()?;
        let composition_right = reader.cross_domain()?;
        let next_main = (0..reader.count(MAX_NEXT_PROOFS_PER_QUERY)?)
            .map(|_| reader.cross_domain())
            .collect::<Result<Vec<_>, _>>()?;
        let next_interaction = (0..reader.count(MAX_NEXT_PROOFS_PER_QUERY)?)
            .map(|_| reader.cross_domain())
            .collect::<Result<Vec<_>, _>>()?;
        let layer_count = usize::from(reader.u8()?);
        if layer_count == 0 || layer_count > 29 {
            return Err(ProofFormatError::Count);
        }
        let mut layers = Vec::with_capacity(layer_count);
        for _ in 0..layer_count {
            layers.push(FriPipelineLayerOpening {
                log_size: reader.u8()?,
                left: Fp16::decode(reader.take(64)?)?,
                right: Fp16::decode(reader.take(64)?)?,
                left_proof: reader.merkle()?,
                right_proof: reader.merkle()?,
            });
        }
        queries.push(FriPipelineQueryProof {
            initial_index,
            mask_left,
            mask_right,
            main_left,
            main_right,
            interaction_left,
            interaction_right,
            composition_left,
            composition_right,
            next_main,
            next_interaction,
            layers,
        });
    }
    if reader.offset != encoded.len() {
        return Err(ProofFormatError::Trailing);
    }
    Ok(FriPipelineProof {
        logup_final_sums,
        queries,
    })
}

/// Encode v2 without attribution.
pub fn encode_fri_pipeline_proof_v2(proof: &FriPipelineProof) -> Result<Vec<u8>, ProofFormatError> {
    Ok(encode_fri_pipeline_proof_v2_with_attribution(proof)?.bytes)
}

/// Encode the v2 proof grammar with verifier-authoritative query coordinates
/// and one canonical global multiproof for all FRI layers.
pub fn encode_fri_pipeline_proof_v2_with_attribution(
    proof: &FriPipelineProof,
) -> Result<EncodedFriPipelineProof, ProofFormatError> {
    if proof.queries.is_empty() || proof.queries.len() > MAX_PROOF_QUERIES {
        return Err(ProofFormatError::Count);
    }

    let query_indices = proof
        .queries
        .iter()
        .map(|query| query.initial_index)
        .collect::<Vec<_>>();
    let query_layers = proof
        .queries
        .iter()
        .map(|query| query.layers.as_slice())
        .collect::<Vec<_>>();
    let fri_layer_multiproofs = compact_fri_layer_openings(&query_layers, &query_indices)?;
    let encoded_fri_layers = fri_layer_multiproofs.encoded()?;

    let mut output = Vec::new();
    let mut attribution = FriPipelineProofByteAttribution {
        query_count: proof.queries.len(),
        fri_layer_count: fri_layer_multiproofs.layers.len(),
        ..FriPipelineProofByteAttribution::default()
    };
    let mut mask_proofs = Vec::new();
    let mut main_proofs = Vec::new();
    let mut interaction_proofs = Vec::new();
    let mut composition_proofs = Vec::new();

    let header_start = output.len();
    output.extend_from_slice(PROOF_V2_MAGIC);
    output.extend_from_slice(&PROOF_V2_VERSION.to_be_bytes());
    push_u32(&mut output, proof.logup_final_sums.len())?;
    for value in &proof.logup_final_sums {
        output.extend_from_slice(&value.encode());
    }
    push_u32(&mut output, proof.queries.len())?;
    add_delta(&mut attribution.header_bytes, &output, header_start)?;

    for query in &proof.queries {
        if query.next_main.len() > MAX_NEXT_PROOFS_PER_QUERY
            || query.next_interaction.len() > MAX_NEXT_PROOFS_PER_QUERY
        {
            return Err(ProofFormatError::Count);
        }

        let section_start = output.len();
        encode_cross_domain_skeleton(&mut output, &query.mask_left)?;
        encode_cross_domain_skeleton(&mut output, &query.mask_right)?;
        mask_proofs.extend([&query.mask_left, &query.mask_right]);
        add_delta(&mut attribution.mask_opening_bytes, &output, section_start)?;

        let section_start = output.len();
        encode_cross_domain_skeleton(&mut output, &query.main_left)?;
        encode_cross_domain_skeleton(&mut output, &query.main_right)?;
        main_proofs.extend([&query.main_left, &query.main_right]);
        add_delta(&mut attribution.main_opening_bytes, &output, section_start)?;

        let section_start = output.len();
        encode_optional_cross_domain_skeleton(&mut output, query.interaction_left.as_ref())?;
        encode_optional_cross_domain_skeleton(&mut output, query.interaction_right.as_ref())?;
        interaction_proofs.extend(query.interaction_left.iter());
        interaction_proofs.extend(query.interaction_right.iter());
        add_delta(
            &mut attribution.interaction_opening_bytes,
            &output,
            section_start,
        )?;

        let section_start = output.len();
        encode_cross_domain_skeleton(&mut output, &query.composition_left)?;
        encode_cross_domain_skeleton(&mut output, &query.composition_right)?;
        composition_proofs.extend([&query.composition_left, &query.composition_right]);
        add_delta(
            &mut attribution.composition_opening_bytes,
            &output,
            section_start,
        )?;

        let section_start = output.len();
        push_u32(&mut output, query.next_main.len())?;
        for item in &query.next_main {
            encode_cross_domain_skeleton(&mut output, item)?;
            main_proofs.push(item);
        }
        add_delta(
            &mut attribution.next_main_opening_bytes,
            &output,
            section_start,
        )?;

        let section_start = output.len();
        push_u32(&mut output, query.next_interaction.len())?;
        for item in &query.next_interaction {
            encode_cross_domain_skeleton(&mut output, item)?;
            interaction_proofs.push(item);
        }
        add_delta(
            &mut attribution.next_interaction_opening_bytes,
            &output,
            section_start,
        )?;

        if output.len() > MAX_PROOF_BYTES {
            return Err(ProofFormatError::Length);
        }
    }

    let section_start = output.len();
    encode_cross_domain_frontier(&mut output, &mask_proofs)?;
    add_delta(&mut attribution.mask_opening_bytes, &output, section_start)?;
    let section_start = output.len();
    encode_cross_domain_frontier(&mut output, &main_proofs)?;
    add_delta(&mut attribution.main_opening_bytes, &output, section_start)?;
    let section_start = output.len();
    encode_cross_domain_frontier(&mut output, &interaction_proofs)?;
    add_delta(
        &mut attribution.interaction_opening_bytes,
        &output,
        section_start,
    )?;
    let section_start = output.len();
    encode_cross_domain_frontier(&mut output, &composition_proofs)?;
    add_delta(
        &mut attribution.composition_opening_bytes,
        &output,
        section_start,
    )?;

    let section_start = output.len();
    push_u32(&mut output, encoded_fri_layers.len())?;
    output.extend_from_slice(&encoded_fri_layers[..14]);
    add_delta(
        &mut attribution.fri_layer_count_bytes,
        &output,
        section_start,
    )?;

    let mut fri_offset = 14_usize;
    for layer in &fri_layer_multiproofs.layers {
        let section_start = output.len();
        output.extend_from_slice(
            encoded_fri_layers
                .get(fri_offset..fri_offset + 1)
                .ok_or(ProofFormatError::Attribution)?,
        );
        fri_offset += 1;
        add_delta(&mut attribution.fri_log_size_bytes, &output, section_start)?;

        let opened_value_bytes = layer
            .opened_values
            .len()
            .checked_mul(64)
            .ok_or(ProofFormatError::Attribution)?;
        let metadata_start = output.len();
        output.extend_from_slice(
            encoded_fri_layers
                .get(fri_offset..fri_offset + 4)
                .ok_or(ProofFormatError::Attribution)?,
        );
        fri_offset += 4;
        add_delta(
            &mut attribution.fri_merkle_metadata_bytes,
            &output,
            metadata_start,
        )?;

        let values_start = output.len();
        output.extend_from_slice(
            encoded_fri_layers
                .get(fri_offset..fri_offset + opened_value_bytes)
                .ok_or(ProofFormatError::Attribution)?,
        );
        fri_offset += opened_value_bytes;
        add_delta(
            &mut attribution.fri_opened_value_bytes,
            &output,
            values_start,
        )?;
        attribution.fri_opened_value_count = attribution
            .fri_opened_value_count
            .checked_add(layer.opened_values.len())
            .ok_or(ProofFormatError::Attribution)?;

        let frontier_bytes = layer
            .proof
            .frontier_digests()
            .len()
            .checked_mul(64)
            .ok_or(ProofFormatError::Attribution)?;
        let metadata_start = output.len();
        output.extend_from_slice(
            encoded_fri_layers
                .get(fri_offset..fri_offset + 4)
                .ok_or(ProofFormatError::Attribution)?,
        );
        fri_offset += 4;
        add_delta(
            &mut attribution.fri_merkle_metadata_bytes,
            &output,
            metadata_start,
        )?;

        let paths_start = output.len();
        output.extend_from_slice(
            encoded_fri_layers
                .get(fri_offset..fri_offset + frontier_bytes)
                .ok_or(ProofFormatError::Attribution)?,
        );
        fri_offset += frontier_bytes;
        add_delta(&mut attribution.fri_path_digest_bytes, &output, paths_start)?;
        attribution.fri_path_digest_count = attribution
            .fri_path_digest_count
            .checked_add(layer.proof.frontier_digests().len())
            .ok_or(ProofFormatError::Attribution)?;
    }

    if fri_offset != encoded_fri_layers.len()
        || output.len() > MAX_PROOF_BYTES
        || attribution.total_bytes() != Some(output.len())
    {
        return Err(ProofFormatError::Attribution);
    }
    Ok(EncodedFriPipelineProof {
        bytes: output,
        attribution,
    })
}

/// Decode v2 using verifier-authoritative query indices and FRI layer sizes.
/// Neither coordinate set is accepted from prover-controlled bytes.
pub fn decode_fri_pipeline_proof_v2(
    encoded: &[u8],
    expected_query_indices: &[usize],
    expected_layer_log_sizes: &[u8],
) -> Result<FriPipelineProofV2, ProofFormatError> {
    if expected_query_indices.is_empty()
        || expected_query_indices.len() > MAX_PROOF_QUERIES
        || expected_layer_log_sizes.is_empty()
        || expected_layer_log_sizes.len() > 29
    {
        return Err(ProofFormatError::Count);
    }

    let mut reader = Reader::new(encoded)?;
    if reader.take(8)? != PROOF_V2_MAGIC {
        return Err(ProofFormatError::Magic);
    }
    if reader.u16()? != PROOF_V2_VERSION {
        return Err(ProofFormatError::Version);
    }
    let sum_count = reader.count(MAX_NEXT_PROOFS_PER_QUERY * MAX_PROOF_QUERIES)?;
    let logup_final_sums = (0..sum_count)
        .map(|_| Fp16::decode(reader.take(64)?).map_err(ProofFormatError::from))
        .collect::<Result<Vec<_>, _>>()?;
    let query_count = reader.count(MAX_PROOF_QUERIES)?;
    if query_count != expected_query_indices.len() {
        return Err(ProofFormatError::Count);
    }

    let mut query_assemblies = Vec::with_capacity(query_count);
    let mut mask_skeletons = Vec::new();
    let mut main_skeletons = Vec::new();
    let mut interaction_skeletons = Vec::new();
    let mut composition_skeletons = Vec::new();
    for initial_index in expected_query_indices.iter().copied() {
        let mask_left = reader.cross_domain_skeleton()?;
        let mask_right = reader.cross_domain_skeleton()?;
        let main_left = reader.cross_domain_skeleton()?;
        let main_right = reader.cross_domain_skeleton()?;
        let interaction_left = reader.optional_cross_domain_skeleton()?;
        let interaction_right = reader.optional_cross_domain_skeleton()?;
        let composition_left = reader.cross_domain_skeleton()?;
        let composition_right = reader.cross_domain_skeleton()?;
        let next_main = (0..reader.count(MAX_NEXT_PROOFS_PER_QUERY)?)
            .map(|_| reader.cross_domain_skeleton())
            .collect::<Result<Vec<_>, _>>()?;
        let next_interaction = (0..reader.count(MAX_NEXT_PROOFS_PER_QUERY)?)
            .map(|_| reader.cross_domain_skeleton())
            .collect::<Result<Vec<_>, _>>()?;
        query_assemblies.push(FriPipelineQueryAssembly {
            initial_index,
            has_interaction_left: interaction_left.is_some(),
            has_interaction_right: interaction_right.is_some(),
            next_main_count: next_main.len(),
            next_interaction_count: next_interaction.len(),
        });
        mask_skeletons.extend([mask_left, mask_right]);
        main_skeletons.extend([main_left, main_right]);
        main_skeletons.extend(next_main);
        interaction_skeletons.extend(interaction_left);
        interaction_skeletons.extend(interaction_right);
        interaction_skeletons.extend(next_interaction);
        composition_skeletons.extend([composition_left, composition_right]);
    }

    let mut mask_proofs = decode_cross_domain_frontier(&mut reader, mask_skeletons)?.into_iter();
    let mut main_proofs = decode_cross_domain_frontier(&mut reader, main_skeletons)?.into_iter();
    let mut interaction_proofs =
        decode_cross_domain_frontier(&mut reader, interaction_skeletons)?.into_iter();
    let mut composition_proofs =
        decode_cross_domain_frontier(&mut reader, composition_skeletons)?.into_iter();
    let mut queries = Vec::with_capacity(query_count);
    for assembly in query_assemblies {
        let mask_left = mask_proofs.next().ok_or(ProofFormatError::Count)?;
        let mask_right = mask_proofs.next().ok_or(ProofFormatError::Count)?;
        let main_left = main_proofs.next().ok_or(ProofFormatError::Count)?;
        let main_right = main_proofs.next().ok_or(ProofFormatError::Count)?;
        let interaction_left = assembly
            .has_interaction_left
            .then(|| interaction_proofs.next().ok_or(ProofFormatError::Count))
            .transpose()?;
        let interaction_right = assembly
            .has_interaction_right
            .then(|| interaction_proofs.next().ok_or(ProofFormatError::Count))
            .transpose()?;
        let composition_left = composition_proofs.next().ok_or(ProofFormatError::Count)?;
        let composition_right = composition_proofs.next().ok_or(ProofFormatError::Count)?;
        let next_main = (0..assembly.next_main_count)
            .map(|_| main_proofs.next().ok_or(ProofFormatError::Count))
            .collect::<Result<Vec<_>, _>>()?;
        let next_interaction = (0..assembly.next_interaction_count)
            .map(|_| interaction_proofs.next().ok_or(ProofFormatError::Count))
            .collect::<Result<Vec<_>, _>>()?;
        queries.push(FriPipelineQueryProof {
            initial_index: assembly.initial_index,
            mask_left,
            mask_right,
            main_left,
            main_right,
            interaction_left,
            interaction_right,
            composition_left,
            composition_right,
            next_main,
            next_interaction,
            layers: Vec::new(),
        });
    }
    if mask_proofs.next().is_some()
        || main_proofs.next().is_some()
        || interaction_proofs.next().is_some()
        || composition_proofs.next().is_some()
    {
        return Err(ProofFormatError::Count);
    }

    let fri_layer_bytes = reader.count(MAX_PROOF_BYTES)?;
    let fri_layer_multiproofs = FriPipelineCanonicalMultiproofs::decode(
        reader.take(fri_layer_bytes)?,
        expected_query_indices,
        expected_layer_log_sizes,
    )?;
    if reader.offset != encoded.len() {
        return Err(ProofFormatError::Trailing);
    }

    Ok(FriPipelineProofV2 {
        logup_final_sums,
        queries,
        fri_layer_multiproofs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cross_domain::{
        CommitmentStage, CrossDomainLayout, CrossDomainTree, DomainEvaluationBatch,
    };
    use alloc::vec;

    fn m31_rows(log_size: u8, columns: u32, offset: u32) -> Vec<Vec<u8>> {
        (0..1_usize << log_size)
            .map(|row| {
                (0..columns)
                    .flat_map(|column| {
                        (offset + u32::try_from(row).unwrap() * 17 + column).to_be_bytes()
                    })
                    .collect()
            })
            .collect()
    }

    fn cross_domain_tree() -> CrossDomainTree {
        let small = DomainSpec::new(2, EvaluationField::M31, 2).unwrap();
        let large = DomainSpec::new(4, EvaluationField::M31, 1).unwrap();
        let layout =
            CrossDomainLayout::new(CommitmentStage::MainTrace, [0x5a; 64], vec![small, large])
                .unwrap();
        CrossDomainTree::build(
            layout,
            vec![
                DomainEvaluationBatch::new(small, m31_rows(2, 2, 100)).unwrap(),
                DomainEvaluationBatch::new(large, m31_rows(4, 1, 200)).unwrap(),
            ],
        )
        .unwrap()
    }

    #[test]
    fn canonical_cross_domain_frontier_roundtrips_and_tampering_fails() {
        let tree = cross_domain_tree();
        let proofs = [0, 1, 7, 7]
            .map(|query| tree.proof(query).unwrap())
            .to_vec();
        let proof_refs = proofs.iter().collect::<Vec<_>>();
        let skeletons = proofs
            .iter()
            .map(|proof| CrossDomainProofSkeleton {
                query_fft_index: proof.query_fft_index(),
                openings: proof
                    .openings()
                    .iter()
                    .map(|opening| DomainOpeningSkeleton {
                        spec: opening.spec,
                        fft_index: opening.fft_index,
                    })
                    .collect(),
            })
            .collect::<Vec<_>>();
        let mut encoded = Vec::new();
        encode_cross_domain_frontier(&mut encoded, &proof_refs).unwrap();
        assert!(encoded.len() < proofs.len() * 4 * 64);

        let mut reader = Reader::new(&encoded).unwrap();
        let decoded = decode_cross_domain_frontier(&mut reader, skeletons.clone()).unwrap();
        assert_eq!(reader.offset, encoded.len());
        assert_eq!(decoded, proofs);
        assert!(
            decoded
                .iter()
                .all(|proof| proof.verify(tree.layout(), &tree.root()).unwrap())
        );

        let last = encoded.len() - 1;
        encoded[last] ^= 1;
        let mut reader = Reader::new(&encoded).unwrap();
        let tampered = decode_cross_domain_frontier(&mut reader, skeletons).unwrap();
        assert!(
            tampered
                .iter()
                .any(|proof| !proof.verify(tree.layout(), &tree.root()).unwrap())
        );
    }
}
