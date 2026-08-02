//! Private package decoder and independent verifier for the streamed state AIR proof.
//!
//! The package is never a public output.  It carries the verifier-visible AIR
//! program, public inputs, authenticated challenge bundle, DEEP claims, final
//! FRI constant, and the canonical v2 FRI proof so the native H4 coordinator
//! can verify exactly what the streamed worker proved.

use alloc::vec::Vec;

use sha3::{Digest, Sha3_512};

use crate::deep_quotient::DomainOodsClaims;
use crate::field::{DecodeError, Fp16, M31};
use crate::proof_format::{MAX_PROOF_BYTES, decode_fri_pipeline_proof_v2};
use crate::proof_parameters::selected_proof_geometry;
use crate::selected_challenge::{
    MAX_CHALLENGE_BUNDLE_BYTES, SelectedChallengeBundle, SelectedChallengeError,
    decode_selected_challenge_bundle, verify_selected_fri_pipeline_v2,
};

pub const PRIVATE_PROOF_PACKAGE_MAGIC: &[u8; 8] = b"BLPQSPK1";
pub const PRIVATE_PROOF_PACKAGE_VERSION: u16 = 1;
pub const PRIVATE_PROOF_PACKAGE_DOMAIN: &[u8] = b"BL/PQ512/STATE-AIR-PROOF-PACKAGE/v1\0";
const MAX_CLAIMS: usize = 1_000;
const MAX_CLAIM_VALUES: usize = 1 << 20;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedProofPackage {
    pub program: Vec<u8>,
    pub public_inputs: Vec<M31>,
    pub bundle_encoded: Vec<u8>,
    pub bundle: SelectedChallengeBundle,
    pub claims: Vec<DomainOodsClaims>,
    pub final_constant: Fp16,
    pub proof: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SelectedProofPackageError {
    Empty,
    Truncated,
    Trailing,
    Magic,
    Version,
    Count,
    Field(DecodeError),
    M31,
    Challenge(SelectedChallengeError),
    Geometry,
    Binding,
    Rejected,
}

impl From<DecodeError> for SelectedProofPackageError {
    fn from(value: DecodeError) -> Self {
        Self::Field(value)
    }
}

impl From<SelectedChallengeError> for SelectedProofPackageError {
    fn from(value: SelectedChallengeError) -> Self {
        Self::Challenge(value)
    }
}

struct Reader<'a> {
    encoded: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(encoded: &'a [u8]) -> Result<Self, SelectedProofPackageError> {
        if encoded.len() < PRIVATE_PROOF_PACKAGE_MAGIC.len() + 2 || encoded.len() > MAX_PROOF_BYTES
        {
            return Err(SelectedProofPackageError::Empty);
        }
        Ok(Self { encoded, offset: 0 })
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], SelectedProofPackageError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(SelectedProofPackageError::Truncated)?;
        let value = self
            .encoded
            .get(self.offset..end)
            .ok_or(SelectedProofPackageError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, SelectedProofPackageError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, SelectedProofPackageError> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| SelectedProofPackageError::Truncated)?,
        ))
    }

    fn u32(&mut self) -> Result<usize, SelectedProofPackageError> {
        usize::try_from(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| SelectedProofPackageError::Truncated)?,
        ))
        .map_err(|_| SelectedProofPackageError::Count)
    }

    fn u64(&mut self) -> Result<usize, SelectedProofPackageError> {
        usize::try_from(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| SelectedProofPackageError::Truncated)?,
        ))
        .map_err(|_| SelectedProofPackageError::Count)
    }

    fn bytes(&mut self, maximum: usize) -> Result<Vec<u8>, SelectedProofPackageError> {
        let length = self.u32()?;
        if length == 0 || length > maximum {
            return Err(SelectedProofPackageError::Count);
        }
        Ok(self.take(length)?.to_vec())
    }

    fn field(&mut self) -> Result<Fp16, SelectedProofPackageError> {
        Ok(Fp16::decode(self.take(64)?)?)
    }
}

pub fn private_proof_package_commitment(encoded: &[u8]) -> [u8; 64] {
    let mut hash = Sha3_512::new();
    hash.update(PRIVATE_PROOF_PACKAGE_DOMAIN);
    hash.update(encoded);
    hash.finalize().into()
}

pub fn decode_selected_proof_package(
    encoded: &[u8],
) -> Result<SelectedProofPackage, SelectedProofPackageError> {
    let mut reader = Reader::new(encoded)?;
    if reader.take(8)? != PRIVATE_PROOF_PACKAGE_MAGIC {
        return Err(SelectedProofPackageError::Magic);
    }
    if reader.u16()? != PRIVATE_PROOF_PACKAGE_VERSION {
        return Err(SelectedProofPackageError::Version);
    }
    let program = reader.bytes(MAX_PROOF_BYTES)?;
    let public_count = reader.u32()?;
    if public_count == 0 || public_count > MAX_CLAIM_VALUES {
        return Err(SelectedProofPackageError::Count);
    }
    let mut public_inputs = Vec::with_capacity(public_count);
    for _ in 0..public_count {
        let value = u32::from_be_bytes(
            reader
                .take(4)?
                .try_into()
                .map_err(|_| SelectedProofPackageError::Truncated)?,
        );
        public_inputs.push(M31::from_canonical(value).map_err(|_| SelectedProofPackageError::M31)?);
    }
    let bundle_encoded = reader.bytes(MAX_CHALLENGE_BUNDLE_BYTES)?;
    let bundle = decode_selected_challenge_bundle(&bundle_encoded)?;
    let claim_count = reader.u32()?;
    if claim_count == 0 || claim_count > MAX_CLAIMS {
        return Err(SelectedProofPackageError::Count);
    }
    let mut claims = Vec::with_capacity(claim_count);
    for _ in 0..claim_count {
        let log_size = reader.u8()?;
        let value_count = reader.u32()?;
        if value_count == 0 || value_count > MAX_CLAIM_VALUES {
            return Err(SelectedProofPackageError::Count);
        }
        let mut values = Vec::with_capacity(value_count);
        for _ in 0..value_count {
            values.push(reader.field()?);
        }
        let mut conjugate_values = Vec::with_capacity(value_count);
        for _ in 0..value_count {
            conjugate_values.push(reader.field()?);
        }
        claims.push(DomainOodsClaims {
            log_size,
            values,
            conjugate_values,
        });
    }
    let final_constant = reader.field()?;
    let proof = {
        let length = reader.u64()?;
        if length == 0 || length > MAX_PROOF_BYTES {
            return Err(SelectedProofPackageError::Count);
        }
        reader.take(length)?.to_vec()
    };
    if reader.offset != encoded.len() {
        return Err(SelectedProofPackageError::Trailing);
    }
    Ok(SelectedProofPackage {
        program,
        public_inputs,
        bundle_encoded,
        bundle,
        claims,
        final_constant,
        proof,
    })
}

/// Verify the package against the caller's exact AIR program and public inputs.
/// The returned package commitment is bound by the outer state envelope.
pub fn verify_selected_proof_package(
    encoded: &[u8],
    expected_program: &[u8],
    expected_public_inputs: &[M31],
) -> Result<([u8; 64], SelectedProofPackage), SelectedProofPackageError> {
    let package = decode_selected_proof_package(encoded)?;
    if package.program != expected_program || package.public_inputs != expected_public_inputs {
        return Err(SelectedProofPackageError::Binding);
    }
    let geometry = selected_proof_geometry(&package.program)
        .map_err(|_| SelectedProofPackageError::Geometry)?;
    let layer_log_sizes = (2..=geometry.maximum_evaluation_log_size)
        .rev()
        .collect::<Vec<_>>();
    let proof = decode_fri_pipeline_proof_v2(
        &package.proof,
        &package.bundle.query_positions,
        &layer_log_sizes,
    )
    .map_err(|_| SelectedProofPackageError::Rejected)?;
    let valid = verify_selected_fri_pipeline_v2(
        &proof,
        &package.bundle,
        &package.program,
        &package.public_inputs,
        &package.claims,
        package.final_constant,
    )
    .map_err(|_| SelectedProofPackageError::Rejected)?;
    if !valid {
        return Err(SelectedProofPackageError::Rejected);
    }
    Ok((private_proof_package_commitment(encoded), package))
}
