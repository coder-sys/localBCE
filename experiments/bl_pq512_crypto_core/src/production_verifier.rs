//! Fail-closed outer verifier for the current native proof candidate.
//!
//! The selected proof package already contains the complete AIR program,
//! authenticated challenge bundle, OODS claims, final value, and canonical
//! FRI openings.  This module adds the missing release boundary around that
//! package: the exact ordered twelve-field application projection and the
//! fixed 744-byte authenticated sidecar.  The caller supplies a pinned
//! verification key; identities are never taken from the submitted bytes.
//!
//! This is a release-candidate verifier boundary.  It does not enable live
//! deployment, replace the protected Solidity settlement shell, or claim an
//! external audit or HSM/FIPS validation.

use alloc::vec::Vec;

use sha3::{Digest, Sha3_512};

use crate::field::M31;
use crate::selected_proof_package::{
    SelectedProofPackage, SelectedProofPackageError, private_proof_package_commitment,
    verify_selected_proof_package,
};
use crate::selected_public_coin::{
    MAX_SELECTED_TRANSCRIPT_BYTES, SelectedTranscriptError, verify_selected_public_coin_transcript,
};

pub const PRODUCTION_ENVELOPE_MAGIC: &[u8; 8] = b"BLPQENV1";
pub const PRODUCTION_ENVELOPE_VERSION: u16 = 2;
pub const PUBLIC_FIELD_COUNT: usize = 12;
pub const PUBLIC_FIELD_BYTES: usize = 32;
pub const PUBLIC_FIELDS_BYTES: usize = PUBLIC_FIELD_COUNT * PUBLIC_FIELD_BYTES;
pub const PUBLIC_INPUT_LIMBS_PER_FIELD: usize = 9;
pub const PUBLIC_INPUT_LIMB_BITS: usize = 30;
pub const PUBLIC_INPUT_PROJECTION_COUNT: usize = PUBLIC_FIELD_COUNT * PUBLIC_INPUT_LIMBS_PER_FIELD;
pub const SIDECAR_BYTES: usize = 744;
pub const MAX_ENVELOPE_BYTES: usize = 512 * 1024 * 1024;
pub const STATEMENT_EVIDENCE_DOMAIN: &[u8] = b"BL/PQ512/PRODUCTION-CANDIDATE/EVIDENCE/v1\0";
pub const STATEMENT_COMMITMENT_DOMAIN: &[u8] = b"BL/PQ512/PRODUCTION-CANDIDATE/STATEMENT/v1\0";

const SIDECAR_MAGIC: &[u8; 8] = b"BLPQSC01";
const SIDECAR_VERSION: u16 = 1;
const SIDECAR_FLAGS: u16 = 0;
const STARK_FIELD_MODULUS_BE: [u8; 32] = [
    0x08, 0, 0, 0, 0, 0, 0, 0, 0x11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1,
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionProofEnvelope {
    pub suite_id: [u8; 64],
    pub schema_id: [u8; 64],
    pub verifier_artifact_identity: [u8; 64],
    pub public_fields: [[u8; PUBLIC_FIELD_BYTES]; PUBLIC_FIELD_COUNT],
    pub sidecar: Vec<u8>,
    pub proof_package: Vec<u8>,
    pub transcript_evidence: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
pub struct ProductionVerificationKey<'a> {
    pub suite_id: [u8; 64],
    pub schema_id: [u8; 64],
    pub verifier_artifact_identity: [u8; 64],
    pub expected_program: &'a [u8],
    pub expected_public_inputs: &'a [M31],
    pub public_input_projection_schema: Option<[u8; 64]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionVerificationReceipt {
    pub statement_commitment: [u8; 64],
    pub evidence_commitment: [u8; 64],
    pub proof_package_commitment: [u8; 64],
    pub transcript_commitment: [u8; 64],
    pub proof_suite_id: [u8; 64],
    pub schema_id: [u8; 64],
    pub verifier_artifact_identity: [u8; 64],
    pub public_field_count: usize,
    pub sidecar_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProductionVerifierError {
    Empty,
    Length,
    Magic,
    Version,
    Truncated,
    Trailing,
    Identity,
    PublicFieldEncoding,
    Sidecar,
    IdentityMismatch,
    Proof(SelectedProofPackageError),
    Transcript(SelectedTranscriptError),
    ProofSuiteMismatch,
    StatementBindingMismatch,
    PublicInputProjection,
}

impl From<SelectedProofPackageError> for ProductionVerifierError {
    fn from(value: SelectedProofPackageError) -> Self {
        Self::Proof(value)
    }
}

struct Reader<'a> {
    encoded: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(encoded: &'a [u8]) -> Result<Self, ProductionVerifierError> {
        if encoded.is_empty() {
            return Err(ProductionVerifierError::Empty);
        }
        if encoded.len() > MAX_ENVELOPE_BYTES {
            return Err(ProductionVerifierError::Length);
        }
        Ok(Self { encoded, offset: 0 })
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ProductionVerifierError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(ProductionVerifierError::Length)?;
        let value = self
            .encoded
            .get(self.offset..end)
            .ok_or(ProductionVerifierError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, ProductionVerifierError> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| ProductionVerifierError::Truncated)?,
        ))
    }

    fn u32(&mut self) -> Result<usize, ProductionVerifierError> {
        usize::try_from(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| ProductionVerifierError::Truncated)?,
        ))
        .map_err(|_| ProductionVerifierError::Length)
    }

    fn u64(&mut self) -> Result<usize, ProductionVerifierError> {
        usize::try_from(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| ProductionVerifierError::Truncated)?,
        ))
        .map_err(|_| ProductionVerifierError::Length)
    }

    fn digest(&mut self) -> Result<[u8; 64], ProductionVerifierError> {
        self.take(64)?
            .try_into()
            .map_err(|_| ProductionVerifierError::Truncated)
    }
}

fn nonzero(value: &[u8]) -> bool {
    value.iter().any(|byte| *byte != 0)
}

fn framed_digest(domain: &[u8], parts: &[&[u8]]) -> [u8; 64] {
    let mut hash = Sha3_512::new();
    hash.update(domain);
    for part in parts {
        hash.update(
            u32::try_from(part.len())
                .expect("bounded production verifier part")
                .to_be_bytes(),
        );
        hash.update(part);
    }
    hash.finalize().into()
}

fn public_fields_bytes(fields: &[[u8; PUBLIC_FIELD_BYTES]; PUBLIC_FIELD_COUNT]) -> Vec<u8> {
    fields
        .iter()
        .flat_map(|field| field.iter().copied())
        .collect()
}

fn public_field_bit(field: &[u8; PUBLIC_FIELD_BYTES], bit: usize) -> u32 {
    if bit >= PUBLIC_FIELD_BYTES * 8 {
        return 0;
    }
    let byte = PUBLIC_FIELD_BYTES - 1 - (bit / 8);
    u32::from((field[byte] >> (bit % 8)) & 1)
}

/// Convert the exact ordered bytes32 public boundary into lossless M31 limbs.
///
/// Nine 30-bit limbs cover 270 bits, so every canonical 251-bit field is
/// represented without reduction or aliasing.  The production caller must
/// pass ``public_input_projection_schema`` to require this relation.
pub fn projected_public_inputs(
    fields: &[[u8; PUBLIC_FIELD_BYTES]; PUBLIC_FIELD_COUNT],
) -> Result<Vec<M31>, ProductionVerifierError> {
    let mut values = Vec::with_capacity(PUBLIC_INPUT_PROJECTION_COUNT);
    for field in fields {
        if !canonical_stark_field(field) {
            return Err(ProductionVerifierError::PublicFieldEncoding);
        }
        for limb_index in 0..PUBLIC_INPUT_LIMBS_PER_FIELD {
            let mut value = 0_u32;
            for bit in 0..PUBLIC_INPUT_LIMB_BITS {
                value |= public_field_bit(field, limb_index * PUBLIC_INPUT_LIMB_BITS + bit) << bit;
            }
            values.push(
                M31::from_canonical(value)
                    .map_err(|_| ProductionVerifierError::PublicInputProjection)?,
            );
        }
    }
    Ok(values)
}

fn canonical_stark_field(value: &[u8; PUBLIC_FIELD_BYTES]) -> bool {
    value.as_slice() < STARK_FIELD_MODULUS_BE.as_slice()
}

fn validate_identity(value: &[u8; 64]) -> Result<(), ProductionVerifierError> {
    if nonzero(value) {
        Ok(())
    } else {
        Err(ProductionVerifierError::Identity)
    }
}

fn validate_sidecar(
    sidecar: &[u8],
    suite_id: &[u8; 64],
    schema_id: &[u8; 64],
    verifier_artifact_identity: &[u8; 64],
) -> Result<(), ProductionVerifierError> {
    if sidecar.len() != SIDECAR_BYTES
        || sidecar.get(..8) != Some(SIDECAR_MAGIC.as_slice())
        || sidecar.get(8..10) != Some(&SIDECAR_VERSION.to_be_bytes())
        || sidecar.get(10..12) != Some(&SIDECAR_FLAGS.to_be_bytes())
        || sidecar.get(12..16) != Some(&(SIDECAR_BYTES as u32).to_be_bytes())
    {
        return Err(ProductionVerifierError::Sidecar);
    }
    let sidecar_suite: [u8; 64] = sidecar[80..144]
        .try_into()
        .map_err(|_| ProductionVerifierError::Sidecar)?;
    let sidecar_schema: [u8; 64] = sidecar[144..208]
        .try_into()
        .map_err(|_| ProductionVerifierError::Sidecar)?;
    let sidecar_verifier: [u8; 64] = sidecar[208..272]
        .try_into()
        .map_err(|_| ProductionVerifierError::Sidecar)?;
    if &sidecar_suite != suite_id
        || &sidecar_schema != schema_id
        || &sidecar_verifier != verifier_artifact_identity
    {
        return Err(ProductionVerifierError::IdentityMismatch);
    }
    for range in [
        16..80,
        80..144,
        144..208,
        208..272,
        272..336,
        360..424,
        424..488,
        488..552,
        552..616,
        616..680,
        680..744,
    ] {
        if !nonzero(&sidecar[range]) {
            return Err(ProductionVerifierError::Sidecar);
        }
    }
    let epoch = u64::from_be_bytes(
        sidecar[336..344]
            .try_into()
            .map_err(|_| ProductionVerifierError::Sidecar)?,
    );
    let sequence_before = u64::from_be_bytes(
        sidecar[344..352]
            .try_into()
            .map_err(|_| ProductionVerifierError::Sidecar)?,
    );
    let sequence_after = u64::from_be_bytes(
        sidecar[352..360]
            .try_into()
            .map_err(|_| ProductionVerifierError::Sidecar)?,
    );
    if epoch == 0
        || sequence_before == u64::MAX
        || sequence_after != sequence_before + 1
        || sidecar[360..424] == sidecar[424..488]
        || sidecar[552..616] == sidecar[616..680]
    {
        return Err(ProductionVerifierError::Sidecar);
    }
    Ok(())
}

/// Bind the public projection, sidecar, and authenticated final transcript.
///
/// The transcript root is included because the selected prover authenticates
/// the public projection and sidecar before releasing any challenge.  The
/// standalone verifier checks this value against the exported bundle instead
/// of accepting a caller-supplied proof result.
pub fn statement_evidence_commitment(
    fields: &[[u8; PUBLIC_FIELD_BYTES]; PUBLIC_FIELD_COUNT],
    sidecar: &[u8],
    final_transcript_root: &[u8; 64],
    schedule_commitment: &[u8; 64],
    suite_id: &[u8; 64],
) -> [u8; 64] {
    let fields_bytes = public_fields_bytes(fields);
    framed_digest(
        STATEMENT_EVIDENCE_DOMAIN,
        &[
            &fields_bytes,
            sidecar,
            final_transcript_root,
            schedule_commitment,
            suite_id,
        ],
    )
}

pub fn statement_commitment(
    fields: &[[u8; PUBLIC_FIELD_BYTES]; PUBLIC_FIELD_COUNT],
    sidecar: &[u8],
) -> [u8; 64] {
    let fields_bytes = public_fields_bytes(fields);
    framed_digest(STATEMENT_COMMITMENT_DOMAIN, &[&fields_bytes, sidecar])
}

pub fn decode_production_envelope(
    encoded: &[u8],
) -> Result<ProductionProofEnvelope, ProductionVerifierError> {
    let mut reader = Reader::new(encoded)?;
    if reader.take(8)? != PRODUCTION_ENVELOPE_MAGIC.as_slice() {
        return Err(ProductionVerifierError::Magic);
    }
    if reader.u16()? != PRODUCTION_ENVELOPE_VERSION {
        return Err(ProductionVerifierError::Version);
    }
    let suite_id = reader.digest()?;
    let schema_id = reader.digest()?;
    let verifier_artifact_identity = reader.digest()?;
    validate_identity(&suite_id)?;
    validate_identity(&schema_id)?;
    validate_identity(&verifier_artifact_identity)?;
    let mut public_fields = [[0_u8; PUBLIC_FIELD_BYTES]; PUBLIC_FIELD_COUNT];
    for field in &mut public_fields {
        field.copy_from_slice(reader.take(PUBLIC_FIELD_BYTES)?);
        if !canonical_stark_field(field) {
            return Err(ProductionVerifierError::PublicFieldEncoding);
        }
    }
    let sidecar_length = reader.u32()?;
    if sidecar_length != SIDECAR_BYTES {
        return Err(ProductionVerifierError::Length);
    }
    let sidecar = reader.take(sidecar_length)?.to_vec();
    let proof_length = reader.u64()?;
    if proof_length == 0 || proof_length > MAX_ENVELOPE_BYTES {
        return Err(ProductionVerifierError::Length);
    }
    let proof_package = reader.take(proof_length)?.to_vec();
    let transcript_length = reader.u64()?;
    if transcript_length == 0 || transcript_length > MAX_SELECTED_TRANSCRIPT_BYTES {
        return Err(ProductionVerifierError::Length);
    }
    let transcript_evidence = reader.take(transcript_length)?.to_vec();
    if reader.offset != encoded.len() {
        return Err(ProductionVerifierError::Trailing);
    }
    Ok(ProductionProofEnvelope {
        suite_id,
        schema_id,
        verifier_artifact_identity,
        public_fields,
        sidecar,
        proof_package,
        transcript_evidence,
    })
}

pub fn encode_production_envelope(
    envelope: &ProductionProofEnvelope,
) -> Result<Vec<u8>, ProductionVerifierError> {
    validate_identity(&envelope.suite_id)?;
    validate_identity(&envelope.schema_id)?;
    validate_identity(&envelope.verifier_artifact_identity)?;
    if envelope.sidecar.len() != SIDECAR_BYTES
        || envelope.proof_package.is_empty()
        || envelope.proof_package.len() > MAX_ENVELOPE_BYTES
        || envelope.transcript_evidence.is_empty()
        || envelope.transcript_evidence.len() > MAX_SELECTED_TRANSCRIPT_BYTES
    {
        return Err(ProductionVerifierError::Length);
    }
    for field in &envelope.public_fields {
        if !canonical_stark_field(field) {
            return Err(ProductionVerifierError::PublicFieldEncoding);
        }
    }
    validate_sidecar(
        &envelope.sidecar,
        &envelope.suite_id,
        &envelope.schema_id,
        &envelope.verifier_artifact_identity,
    )?;
    let mut encoded = Vec::with_capacity(
        10 + 64 * 3 + PUBLIC_FIELDS_BYTES + 4 + SIDECAR_BYTES + 8 + envelope.proof_package.len(),
    );
    encoded.extend_from_slice(PRODUCTION_ENVELOPE_MAGIC);
    encoded.extend_from_slice(&PRODUCTION_ENVELOPE_VERSION.to_be_bytes());
    encoded.extend_from_slice(&envelope.suite_id);
    encoded.extend_from_slice(&envelope.schema_id);
    encoded.extend_from_slice(&envelope.verifier_artifact_identity);
    encoded.extend_from_slice(&public_fields_bytes(&envelope.public_fields));
    encoded.extend_from_slice(&(SIDECAR_BYTES as u32).to_be_bytes());
    encoded.extend_from_slice(&envelope.sidecar);
    encoded.extend_from_slice(
        &u64::try_from(envelope.proof_package.len())
            .map_err(|_| ProductionVerifierError::Length)?
            .to_be_bytes(),
    );
    encoded.extend_from_slice(&envelope.proof_package);
    encoded.extend_from_slice(
        &u64::try_from(envelope.transcript_evidence.len())
            .map_err(|_| ProductionVerifierError::Length)?
            .to_be_bytes(),
    );
    encoded.extend_from_slice(&envelope.transcript_evidence);
    Ok(encoded)
}

pub fn verify_production_envelope(
    encoded: &[u8],
    key: ProductionVerificationKey<'_>,
) -> Result<ProductionVerificationReceipt, ProductionVerifierError> {
    validate_identity(&key.suite_id)?;
    validate_identity(&key.schema_id)?;
    validate_identity(&key.verifier_artifact_identity)?;
    if key.expected_program.is_empty() || key.expected_public_inputs.is_empty() {
        return Err(ProductionVerifierError::Identity);
    }
    let envelope = decode_production_envelope(encoded)?;
    if envelope.suite_id != key.suite_id
        || envelope.schema_id != key.schema_id
        || envelope.verifier_artifact_identity != key.verifier_artifact_identity
    {
        return Err(ProductionVerifierError::IdentityMismatch);
    }
    if let Some(projection_schema) = key.public_input_projection_schema {
        if envelope.schema_id != projection_schema {
            return Err(ProductionVerifierError::PublicInputProjection);
        }
        let expected = projected_public_inputs(&envelope.public_fields)?;
        if key.expected_public_inputs != expected.as_slice() {
            return Err(ProductionVerifierError::PublicInputProjection);
        }
    }
    validate_sidecar(
        &envelope.sidecar,
        &key.suite_id,
        &key.schema_id,
        &key.verifier_artifact_identity,
    )?;
    let (proof_package_commitment, package): ([u8; 64], SelectedProofPackage) =
        verify_selected_proof_package(
            &envelope.proof_package,
            key.expected_program,
            key.expected_public_inputs,
        )?;
    if package.bundle.proof_suite_id != envelope.suite_id {
        return Err(ProductionVerifierError::ProofSuiteMismatch);
    }
    let transcript_commitment = verify_selected_public_coin_transcript(
        &envelope.transcript_evidence,
        &public_fields_bytes(&envelope.public_fields),
        &envelope.sidecar,
        &package.bundle,
        &package.program,
    )
    .map_err(ProductionVerifierError::Transcript)?;
    let expected_evidence = statement_evidence_commitment(
        &envelope.public_fields,
        &envelope.sidecar,
        &package.bundle.final_transcript_root,
        &package.bundle.schedule_commitment,
        &package.bundle.proof_suite_id,
    );
    if package.bundle.evidence_commitment != expected_evidence {
        return Err(ProductionVerifierError::StatementBindingMismatch);
    }
    Ok(ProductionVerificationReceipt {
        statement_commitment: statement_commitment(&envelope.public_fields, &envelope.sidecar),
        evidence_commitment: expected_evidence,
        proof_package_commitment,
        transcript_commitment,
        proof_suite_id: envelope.suite_id,
        schema_id: envelope.schema_id,
        verifier_artifact_identity: envelope.verifier_artifact_identity,
        public_field_count: PUBLIC_FIELD_COUNT,
        sidecar_bytes: SIDECAR_BYTES,
    })
}

/// Keep the package commitment available to callers that only need the
/// package-level identity while migrating a proof into the outer envelope.
pub fn package_commitment(encoded: &[u8]) -> [u8; 64] {
    private_proof_package_commitment(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn identity(byte: u8) -> [u8; 64] {
        [byte; 64]
    }

    fn sidecar(suite: [u8; 64], schema: [u8; 64], verifier: [u8; 64]) -> Vec<u8> {
        let mut value = vec![0_u8; SIDECAR_BYTES];
        value[..8].copy_from_slice(SIDECAR_MAGIC);
        value[8..10].copy_from_slice(&SIDECAR_VERSION.to_be_bytes());
        value[10..12].copy_from_slice(&SIDECAR_FLAGS.to_be_bytes());
        value[12..16].copy_from_slice(&(SIDECAR_BYTES as u32).to_be_bytes());
        value[16..80].copy_from_slice(&identity(4));
        value[80..144].copy_from_slice(&suite);
        value[144..208].copy_from_slice(&schema);
        value[208..272].copy_from_slice(&verifier);
        value[272..336].copy_from_slice(&identity(5));
        value[336..344].copy_from_slice(&1_u64.to_be_bytes());
        value[352..360].copy_from_slice(&1_u64.to_be_bytes());
        value[360..424].copy_from_slice(&identity(6));
        value[424..488].copy_from_slice(&identity(7));
        value[488..552].copy_from_slice(&identity(8));
        value[552..616].copy_from_slice(&identity(9));
        value[616..680].copy_from_slice(&identity(10));
        value[680..744].copy_from_slice(&identity(11));
        value
    }

    #[test]
    fn outer_encoding_preserves_exact_shape_and_round_trips() {
        let suite = identity(1);
        let schema = identity(2);
        let verifier = identity(3);
        let value = ProductionProofEnvelope {
            suite_id: suite,
            schema_id: schema,
            verifier_artifact_identity: verifier,
            public_fields: [[0_u8; PUBLIC_FIELD_BYTES]; PUBLIC_FIELD_COUNT],
            sidecar: sidecar(suite, schema, verifier),
            proof_package: vec![1, 2, 3],
            transcript_evidence: vec![4, 5, 6],
        };
        let encoded = encode_production_envelope(&value).unwrap();
        assert_eq!(decode_production_envelope(&encoded).unwrap(), value);
        assert_eq!(value.public_fields.len(), PUBLIC_FIELD_COUNT);
        assert_eq!(value.sidecar.len(), SIDECAR_BYTES);
    }

    #[test]
    fn outer_parser_rejects_noncanonical_public_field() {
        let suite = identity(1);
        let schema = identity(2);
        let verifier = identity(3);
        let value = ProductionProofEnvelope {
            suite_id: suite,
            schema_id: schema,
            verifier_artifact_identity: verifier,
            public_fields: [[0_u8; PUBLIC_FIELD_BYTES]; PUBLIC_FIELD_COUNT],
            sidecar: sidecar(suite, schema, verifier),
            proof_package: vec![1],
            transcript_evidence: vec![2],
        };
        let mut encoded = encode_production_envelope(&value).unwrap();
        let field_start = 10 + 64 * 3;
        encoded[field_start] = 0xff;
        assert_eq!(
            decode_production_envelope(&encoded),
            Err(ProductionVerifierError::PublicFieldEncoding)
        );
    }

    #[test]
    fn sidecar_rejects_sequence_without_successor() {
        let suite = identity(1);
        let schema = identity(2);
        let verifier = identity(3);
        let mut value = ProductionProofEnvelope {
            suite_id: suite,
            schema_id: schema,
            verifier_artifact_identity: verifier,
            public_fields: [[0_u8; PUBLIC_FIELD_BYTES]; PUBLIC_FIELD_COUNT],
            sidecar: sidecar(suite, schema, verifier),
            proof_package: vec![1],
            transcript_evidence: vec![2],
        };
        value.sidecar[352..360].copy_from_slice(&3_u64.to_be_bytes());
        assert_eq!(
            encode_production_envelope(&value),
            Err(ProductionVerifierError::Sidecar)
        );
    }
}
