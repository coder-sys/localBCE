//! Explicit synthetic, nonactivating K128/K512 integration proof boundary.
//!
//! This module is not a substitute for the governed H4/post-Z proof.  It is a
//! small, complete integration lane used to exercise the producer, native
//! aggregate verifier, dependency ordering, mutation rejection, and evidence
//! plumbing while the real witness-to-proof seam is still incomplete.  The
//! lane accepts only a canonical synthetic input whose records are derived
//! from the profile and index.  It never creates a production proof-suite
//! identity or an activation capability.

use alloc::vec::Vec;

use sha3::{Digest, Sha3_512};

pub const SYNTHETIC_INPUT_MAGIC: &[u8; 8] = b"BLSYNIN1";
pub const SYNTHETIC_INPUT_VERSION: u16 = 1;
pub const SYNTHETIC_INPUT_HEADER_BYTES: usize = 20;
pub const SYNTHETIC_INPUT_RECORD_BYTES: usize = 68;

pub const SYNTHETIC_BUNDLE_MAGIC: &[u8; 8] = b"BLV3SY01";
pub const SYNTHETIC_BUNDLE_VERSION: u16 = 1;
pub const SYNTHETIC_BUNDLE_BYTES: usize = 860;
pub const SYNTHETIC_BUNDLE_HEADER_BYTES: usize = 28;
pub const SYNTHETIC_BUNDLE_DIGEST_BYTES: usize = 64;
pub const SYNTHETIC_BUNDLE_SHARD_SLOTS: usize = 4;

const INPUT_RECORD_DOMAIN: &[u8] = b"BL/PQ512/SYNTHETIC-MAJOR/INPUT-RECORD/v1\0";
const INPUT_COMMITMENT_DOMAIN: &[u8] = b"BL/PQ512/SYNTHETIC-MAJOR/INPUT-COMMITMENT/v1\0";
const LAYOUT_DOMAIN: &[u8] = b"BL/PQ512/SYNTHETIC-MAJOR/LAYOUT/v1\0";
const SEMANTIC_DOMAIN: &[u8] = b"BL/PQ512/SYNTHETIC-MAJOR/SEMANTIC/v1\0";
const H4_DOMAIN: &[u8] = b"BL/PQ512/SYNTHETIC-MAJOR/H4/v1\0";
const SHARD_DOMAIN: &[u8] = b"BL/PQ512/SYNTHETIC-MAJOR/H4-SHARD/v1\0";
const WORK_INIT_DOMAIN: &[u8] = b"BL/PQ512/SYNTHETIC-MAJOR/WORK-INIT/v1\0";
const WORK_STEP_DOMAIN: &[u8] = b"BL/PQ512/SYNTHETIC-MAJOR/WORK-STEP/v1\0";
const TYPED_DOMAIN: &[u8] = b"BL/PQ512/SYNTHETIC-MAJOR/TYPED-STATE/v1\0";
const PARENT_DOMAIN: &[u8] = b"BL/PQ512/SYNTHETIC-MAJOR/PARENT/v1\0";
const AGGREGATE_DOMAIN: &[u8] = b"BL/PQ512/SYNTHETIC-MAJOR/AGGREGATE/v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SyntheticProfile {
    K128 = 1,
    K512 = 3,
}

impl SyntheticProfile {
    pub const fn code(self) -> u8 {
        self as u8
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::K128 => "K128_CALIBRATION",
            Self::K512 => "K512_CALIBRATION",
        }
    }

    pub const fn record_count(self) -> usize {
        match self {
            Self::K128 => 128,
            Self::K512 => 512,
        }
    }

    pub const fn shard_count(self) -> usize {
        match self {
            Self::K128 => 1,
            Self::K512 => 4,
        }
    }

    pub const fn work_rounds(self) -> usize {
        self.record_count()
    }

    pub const fn from_code(code: u8) -> Result<Self, SyntheticMajorError> {
        match code {
            1 => Ok(Self::K128),
            3 => Ok(Self::K512),
            _ => Err(SyntheticMajorError::Profile),
        }
    }

    pub fn from_label(label: &str) -> Result<Self, SyntheticMajorError> {
        match label {
            "K128_CALIBRATION" => Ok(Self::K128),
            "K512_CALIBRATION" => Ok(Self::K512),
            _ => Err(SyntheticMajorError::Profile),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyntheticMajorError {
    Length,
    Magic,
    Version,
    Flags,
    Profile,
    Geometry,
    Attempt,
    Dependency,
    InputMismatch,
    BundleMismatch,
    Identity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedSyntheticMajorRun {
    profile: SyntheticProfile,
    aggregate_receipt: [u8; 64],
    work_receipt: [u8; 64],
    dependency_commitment: [u8; 64],
}

impl VerifiedSyntheticMajorRun {
    pub const fn profile(&self) -> SyntheticProfile {
        self.profile
    }

    pub const fn aggregate_receipt(&self) -> &[u8; 64] {
        &self.aggregate_receipt
    }

    pub const fn work_receipt(&self) -> &[u8; 64] {
        &self.work_receipt
    }

    pub const fn dependency_commitment(&self) -> &[u8; 64] {
        &self.dependency_commitment
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyntheticMutationReport {
    pub artifact_mutations: usize,
    pub input_mutations: usize,
    pub rejected_mutations: usize,
}

fn digest(parts: &[&[u8]]) -> [u8; 64] {
    let mut hasher = Sha3_512::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn code_bytes(profile: SyntheticProfile) -> [u8; 1] {
    [profile.code()]
}

fn u32_bytes(value: usize) -> [u8; 4] {
    (value as u32).to_be_bytes()
}

fn synthetic_record_digest(profile: SyntheticProfile, index: usize) -> [u8; 64] {
    let code = code_bytes(profile);
    let index = u32_bytes(index);
    digest(&[INPUT_RECORD_DOMAIN, &code, &index])
}

pub fn synthetic_input_bytes(profile: SyntheticProfile) -> Vec<u8> {
    let count = u32_bytes(profile.record_count());
    let record_bytes = u32_bytes(SYNTHETIC_INPUT_RECORD_BYTES);
    let mut encoded = Vec::with_capacity(
        SYNTHETIC_INPUT_HEADER_BYTES + profile.record_count() * SYNTHETIC_INPUT_RECORD_BYTES,
    );
    encoded.extend_from_slice(SYNTHETIC_INPUT_MAGIC);
    encoded.extend_from_slice(&SYNTHETIC_INPUT_VERSION.to_be_bytes());
    encoded.push(profile.code());
    encoded.push(0);
    encoded.extend_from_slice(&count);
    encoded.extend_from_slice(&record_bytes);
    for index in 0..profile.record_count() {
        encoded.extend_from_slice(&u32_bytes(index));
        encoded.extend_from_slice(&synthetic_record_digest(profile, index));
    }
    encoded
}

pub fn verify_synthetic_input(
    profile: SyntheticProfile,
    input: &[u8],
) -> Result<(), SyntheticMajorError> {
    let expected_len = SYNTHETIC_INPUT_HEADER_BYTES
        .checked_add(
            profile
                .record_count()
                .checked_mul(SYNTHETIC_INPUT_RECORD_BYTES)
                .ok_or(SyntheticMajorError::Geometry)?,
        )
        .ok_or(SyntheticMajorError::Geometry)?;
    if input.len() != expected_len {
        return Err(SyntheticMajorError::Length);
    }
    if input.get(..8) != Some(SYNTHETIC_INPUT_MAGIC) {
        return Err(SyntheticMajorError::Magic);
    }
    if input.get(8..10) != Some(&SYNTHETIC_INPUT_VERSION.to_be_bytes()) {
        return Err(SyntheticMajorError::Version);
    }
    if input.get(10) != Some(&profile.code()) || input.get(11) != Some(&0) {
        return Err(SyntheticMajorError::Flags);
    }
    if input.get(12..16) != Some(&u32_bytes(profile.record_count()))
        || input.get(16..20) != Some(&u32_bytes(SYNTHETIC_INPUT_RECORD_BYTES))
    {
        return Err(SyntheticMajorError::Geometry);
    }
    let mut offset = SYNTHETIC_INPUT_HEADER_BYTES;
    for index in 0..profile.record_count() {
        if input.get(offset..offset + 4) != Some(&u32_bytes(index)) {
            return Err(SyntheticMajorError::InputMismatch);
        }
        let expected = synthetic_record_digest(profile, index);
        if input.get(offset + 4..offset + SYNTHETIC_INPUT_RECORD_BYTES) != Some(&expected) {
            return Err(SyntheticMajorError::InputMismatch);
        }
        offset += SYNTHETIC_INPUT_RECORD_BYTES;
    }
    if offset != input.len() {
        return Err(SyntheticMajorError::Length);
    }
    Ok(())
}

fn input_commitment(input: &[u8]) -> [u8; 64] {
    digest(&[INPUT_COMMITMENT_DOMAIN, input])
}

fn layout_commitment(profile: SyntheticProfile) -> [u8; 64] {
    let code = code_bytes(profile);
    let records = u32_bytes(profile.record_count());
    let shards = u32_bytes(profile.shard_count());
    let work = u32_bytes(profile.work_rounds());
    digest(&[LAYOUT_DOMAIN, &code, &records, &shards, &work])
}

fn shard_commitments(
    profile: SyntheticProfile,
    input: &[u8],
    input_root: &[u8; 64],
) -> [[u8; 64]; 4] {
    let mut result = [[0_u8; 64]; 4];
    let records_per_shard = profile.record_count() / profile.shard_count();
    let code = code_bytes(profile);
    for shard in 0..profile.shard_count() {
        let start_record = shard * records_per_shard;
        let start = SYNTHETIC_INPUT_HEADER_BYTES + start_record * SYNTHETIC_INPUT_RECORD_BYTES;
        let end = start + records_per_shard * SYNTHETIC_INPUT_RECORD_BYTES;
        let shard_index = u32_bytes(shard);
        result[shard] = digest(&[
            SHARD_DOMAIN,
            &code,
            &shard_index,
            input_root,
            &input[start..end],
        ]);
    }
    result
}

fn work_receipt(profile: SyntheticProfile, input: &[u8], input_root: &[u8; 64]) -> [u8; 64] {
    let code = code_bytes(profile);
    let mut accumulator = digest(&[WORK_INIT_DOMAIN, &code, input_root]);
    for index in 0..profile.record_count() {
        let start = SYNTHETIC_INPUT_HEADER_BYTES + index * SYNTHETIC_INPUT_RECORD_BYTES;
        let end = start + SYNTHETIC_INPUT_RECORD_BYTES;
        accumulator = digest(&[WORK_STEP_DOMAIN, &accumulator, &input[start..end]]);
    }
    accumulator
}

fn expected_bundle(
    profile: SyntheticProfile,
    input: &[u8],
    dependency_commitment: [u8; 64],
) -> Result<Vec<u8>, SyntheticMajorError> {
    verify_synthetic_input(profile, input)?;
    let code = code_bytes(profile);
    let count = u32_bytes(profile.record_count());
    let shards = u32_bytes(profile.shard_count());
    let work_rounds = u32_bytes(profile.work_rounds());
    let layout = layout_commitment(profile);
    let input_root = input_commitment(input);
    let shard_roots = shard_commitments(profile, input, &input_root);
    let semantic = digest(&[
        SEMANTIC_DOMAIN,
        &code,
        &layout,
        &input_root,
        &dependency_commitment,
    ]);
    let mut shard_bytes = Vec::with_capacity(SYNTHETIC_BUNDLE_SHARD_SLOTS * 64);
    for root in shard_roots {
        shard_bytes.extend_from_slice(&root);
    }
    let h4 = digest(&[H4_DOMAIN, &code, &layout, &input_root, &shard_bytes]);
    let work = work_receipt(profile, input, &input_root);
    let typed = digest(&[
        TYPED_DOMAIN,
        &code,
        &input_root,
        &semantic,
        &h4,
        &work,
        &dependency_commitment,
    ]);
    let round_900 = digest(&[PARENT_DOMAIN, b"900", &semantic, &h4, &layout]);
    let round_901 = digest(&[PARENT_DOMAIN, b"901", &round_900, &typed]);
    let round_902 = digest(&[PARENT_DOMAIN, b"902", &round_901, &work]);
    let parent = digest(&[PARENT_DOMAIN, b"FINAL", &round_902, &dependency_commitment]);
    let aggregate = digest(&[
        AGGREGATE_DOMAIN,
        &code,
        &count,
        &shards,
        &work_rounds,
        &dependency_commitment,
        &input_root,
        &semantic,
        &h4,
        &typed,
        &parent,
        &layout,
        &work,
        &shard_bytes,
    ]);

    let mut encoded = Vec::with_capacity(SYNTHETIC_BUNDLE_BYTES);
    encoded.extend_from_slice(SYNTHETIC_BUNDLE_MAGIC);
    encoded.extend_from_slice(&SYNTHETIC_BUNDLE_VERSION.to_be_bytes());
    encoded.extend_from_slice(&0_u16.to_be_bytes());
    encoded.push(profile.code());
    encoded.push(profile.shard_count() as u8);
    encoded.extend_from_slice(&0_u16.to_be_bytes());
    encoded.extend_from_slice(&1_u32.to_be_bytes());
    encoded.extend_from_slice(&count);
    encoded.extend_from_slice(&work_rounds);
    encoded.extend_from_slice(&dependency_commitment);
    encoded.extend_from_slice(&input_root);
    encoded.extend_from_slice(&semantic);
    encoded.extend_from_slice(&h4);
    encoded.extend_from_slice(&typed);
    encoded.extend_from_slice(&parent);
    encoded.extend_from_slice(&layout);
    encoded.extend_from_slice(&work);
    encoded.extend_from_slice(&aggregate);
    encoded.extend_from_slice(&shard_bytes);
    if encoded.len() != SYNTHETIC_BUNDLE_BYTES {
        return Err(SyntheticMajorError::Length);
    }
    Ok(encoded)
}

pub fn produce_synthetic_bundle(
    profile: SyntheticProfile,
    input: &[u8],
    dependency_commitment: [u8; 64],
) -> Result<Vec<u8>, SyntheticMajorError> {
    if profile == SyntheticProfile::K128 && dependency_commitment != [0_u8; 64] {
        return Err(SyntheticMajorError::Dependency);
    }
    if profile == SyntheticProfile::K512 && dependency_commitment == [0_u8; 64] {
        return Err(SyntheticMajorError::Dependency);
    }
    expected_bundle(profile, input, dependency_commitment)
}

pub fn verify_synthetic_bundle(
    profile: SyntheticProfile,
    input: &[u8],
    encoded: &[u8],
    dependency_commitment: [u8; 64],
) -> Result<VerifiedSyntheticMajorRun, SyntheticMajorError> {
    if encoded.len() != SYNTHETIC_BUNDLE_BYTES {
        return Err(SyntheticMajorError::Length);
    }
    if encoded.get(..8) != Some(SYNTHETIC_BUNDLE_MAGIC) {
        return Err(SyntheticMajorError::Magic);
    }
    if encoded.get(8..10) != Some(&SYNTHETIC_BUNDLE_VERSION.to_be_bytes()) {
        return Err(SyntheticMajorError::Version);
    }
    if encoded.get(10..12) != Some(&[0_u8; 2]) || encoded.get(14..16) != Some(&[0_u8; 2]) {
        return Err(SyntheticMajorError::Flags);
    }
    if encoded.get(12) != Some(&profile.code())
        || encoded.get(13) != Some(&(profile.shard_count() as u8))
        || encoded.get(16..20) != Some(&1_u32.to_be_bytes())
        || encoded.get(20..24) != Some(&u32_bytes(profile.record_count()))
        || encoded.get(24..28) != Some(&u32_bytes(profile.work_rounds()))
    {
        return Err(SyntheticMajorError::Geometry);
    }
    if encoded.get(28..92) != Some(&dependency_commitment) {
        return Err(SyntheticMajorError::Dependency);
    }
    if profile == SyntheticProfile::K128 && dependency_commitment != [0_u8; 64] {
        return Err(SyntheticMajorError::Dependency);
    }
    if profile == SyntheticProfile::K512 && dependency_commitment == [0_u8; 64] {
        return Err(SyntheticMajorError::Dependency);
    }
    let expected = expected_bundle(profile, input, dependency_commitment)?;
    if encoded != expected.as_slice() {
        return Err(SyntheticMajorError::BundleMismatch);
    }
    let work = encoded[476..540]
        .try_into()
        .map_err(|_| SyntheticMajorError::Length)?;
    let aggregate = encoded[540..604]
        .try_into()
        .map_err(|_| SyntheticMajorError::Length)?;
    Ok(VerifiedSyntheticMajorRun {
        profile,
        aggregate_receipt: aggregate,
        work_receipt: work,
        dependency_commitment,
    })
}

/// Exercise every bundle byte and one indexed/value mutation per synthetic
/// record.  The accepting predicate is never relaxed; every mutation must
/// reject before this function returns success.
pub fn run_synthetic_mutation_suite(
    profile: SyntheticProfile,
    input: &[u8],
    encoded: &[u8],
    dependency_commitment: [u8; 64],
) -> Result<SyntheticMutationReport, SyntheticMajorError> {
    verify_synthetic_bundle(profile, input, encoded, dependency_commitment)?;
    let mut rejected = 0_usize;
    for index in 0..encoded.len() {
        let mut mutated = encoded.to_vec();
        mutated[index] ^= 1;
        if verify_synthetic_bundle(profile, input, &mutated, dependency_commitment).is_err() {
            rejected += 1;
        } else {
            return Err(SyntheticMajorError::Identity);
        }
    }
    let input_mutations = profile.record_count() * 2;
    for record in 0..profile.record_count() {
        for lane in 0..2 {
            let offset = SYNTHETIC_INPUT_HEADER_BYTES
                + record * SYNTHETIC_INPUT_RECORD_BYTES
                + if lane == 0 { 0 } else { 4 };
            let mut mutated = input.to_vec();
            mutated[offset] ^= 1;
            if verify_synthetic_bundle(profile, &mutated, encoded, dependency_commitment).is_err() {
                rejected += 1;
            } else {
                return Err(SyntheticMajorError::Identity);
            }
        }
    }
    Ok(SyntheticMutationReport {
        artifact_mutations: encoded.len(),
        input_mutations,
        rejected_mutations: rejected,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_inputs_are_fixed_shape_and_profile_bound() {
        for profile in [SyntheticProfile::K128, SyntheticProfile::K512] {
            let input = synthetic_input_bytes(profile);
            assert_eq!(
                input.len(),
                SYNTHETIC_INPUT_HEADER_BYTES
                    + profile.record_count() * SYNTHETIC_INPUT_RECORD_BYTES
            );
            verify_synthetic_input(profile, &input).unwrap();
            assert!(
                verify_synthetic_input(
                    if profile == SyntheticProfile::K128 {
                        SyntheticProfile::K512
                    } else {
                        SyntheticProfile::K128
                    },
                    &input,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn both_profiles_produce_and_verify_with_explicit_dependency() {
        let k128_input = synthetic_input_bytes(SyntheticProfile::K128);
        let k128 =
            produce_synthetic_bundle(SyntheticProfile::K128, &k128_input, [0_u8; 64]).unwrap();
        let k128_receipt =
            verify_synthetic_bundle(SyntheticProfile::K128, &k128_input, &k128, [0_u8; 64])
                .unwrap();
        assert_eq!(k128_receipt.profile(), SyntheticProfile::K128);

        let k512_input = synthetic_input_bytes(SyntheticProfile::K512);
        let dependency = *k128_receipt.aggregate_receipt();
        let k512 =
            produce_synthetic_bundle(SyntheticProfile::K512, &k512_input, dependency).unwrap();
        let verified =
            verify_synthetic_bundle(SyntheticProfile::K512, &k512_input, &k512, dependency)
                .unwrap();
        assert_eq!(verified.profile(), SyntheticProfile::K512);
        assert_eq!(verified.dependency_commitment(), &dependency);
    }

    #[test]
    fn every_bundle_byte_and_record_index_mutation_rejects() {
        let input = synthetic_input_bytes(SyntheticProfile::K128);
        let bundle = produce_synthetic_bundle(SyntheticProfile::K128, &input, [0_u8; 64]).unwrap();
        let report =
            run_synthetic_mutation_suite(SyntheticProfile::K128, &input, &bundle, [0_u8; 64])
                .unwrap();
        assert_eq!(report.artifact_mutations, SYNTHETIC_BUNDLE_BYTES);
        assert_eq!(report.input_mutations, 256);
        assert_eq!(
            report.rejected_mutations,
            report.artifact_mutations + report.input_mutations
        );
    }
}
