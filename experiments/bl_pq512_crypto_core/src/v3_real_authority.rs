//! File-backed native authority lane for the governed v3 profiles.
//!
//! This module is deliberately a verifier-owned boundary, not a status-file
//! wrapper.  A run may enter the accepting composition only after this
//! process has re-read the raw witness, replayed every strict transcript, and
//! obtained all opaque receipts from the existing native verifiers.  No
//! serialized receipt, caller boolean, or digest-only identity can satisfy
//! this contract.
//!
//! The witness directory is a closed, versioned input contract.  The outer
//! envelope supplies the authenticated semantic, H4, typed-state, and parent
//! component bytes.  The files beside it supply the independent governed
//! verification keys and the raw proof material that is not carried in that
//! fixed-shape envelope.  The command-line wrapper is intentionally thin; the
//! native library remains the only accepting authority.

use std::borrow::ToOwned;
use std::fmt;
use std::format;
use std::fs::{self, File, OpenOptions};
use std::io::{Cursor, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::string::String;
use std::vec::Vec;

use sha3::{Digest, Sha3_512};

use crate::binding_multilinear_pcs_v2::{
    BindingMultilinearPcsProofV2, decode_binding_multilinear_pcs_proof_v2,
    encode_binding_multilinear_pcs_proof_v2,
};
use crate::binding_root_v2::{BINDING_V2_BYTES, BindingDigestV2, BindingRootV2};
use crate::chained_public_coin::decode_chained_public_coin_bundle;
use crate::circle_lagrange_sparse_functional::{
    decode_circle_coefficient_mle_proof_v3, encode_circle_coefficient_mle_proof_v3,
};
use crate::composite_parent_public_coin::{
    CompositeParentPreAlphaMessage, verify_composite_parent_prefix,
};
use crate::deep_quotient::{DomainOodsClaims, deep_claims_commitment_binding_v2};
use crate::field::{Fp16, M31};
use crate::fri_pipeline::{
    FriPipelineProofV3, derive_fri_pipeline_proof_v3_geometry, verify_fri_pipeline_v3_receipt,
};
use crate::h4_bridge_source_response_v2::{
    decode_h4_bridge_source_response_v2, verify_strict_h4_bridge_source_response_v2,
};
use crate::h4_proof_package_v2::{H4ProofProfileV2, H4SourceMaskProofV2};
use crate::h4_v2_completion::{
    H4PostZResponseInput, derive_h4_source_mask_coins_v3,
    prepare_h4_v2_from_serialized_post_z_with_keys,
};
use crate::h4_verification_key_v2::decode_h4_verification_key_v2;
use crate::master_commitments::Profile;
use crate::oracle_commitment::derive_binding_oracle_commitment_layouts_v2;
use crate::proof_format::decode_fri_pipeline_proof_v3;
use crate::selected_public_coin_v3::{
    SemanticV3GovernedContext, SemanticV3ParentAnchorFrame,
    semantic_v3_native_batch_derivation_message, semantic_v3_native_batch_message,
    semantic_v3_native_composition_root_message, semantic_v3_native_fri_layer_message,
    semantic_v3_native_interaction_root_message, semantic_v3_native_main_root_message,
    semantic_v3_strict_prover_messages,
    verify_semantic_v3_parent_frame_and_continuation_with_strict, verify_semantic_v3_prefix,
    verify_strict_semantic_v3_public_coin,
};
use crate::semantic_h4_bridge_gkr::{
    ProducedSemanticH4BridgeSourceMaskV3, PublicBridgeInnerProductProof,
    PublicMaskedSemanticH4BridgeGkrProof, SemanticBridgeFunctionalProofInputV3,
    SemanticH4BridgeProfile, decode_public_bridge_inner_product_proof,
    decode_public_masked_semantic_h4_bridge_gkr, encode_public_bridge_inner_product_proof,
    semantic_h4_post_z_context_v3, verify_semantic_bridge_source_batch_from_program_v3,
    verify_strict_semantic_h4_bridge_gkr,
};
use crate::strict_pq_public_coin_v2::{StrictPqGovernedVerifierKeyV2, StrictPqRootUseRegistryV2};
use crate::typed_state_proof_package::VerifiedTypedStateV3;
use crate::v3_authority_run::{V3AuthorityReceipts, V3AuthorityRunResult};
use crate::v3_component_preflight::{
    verify_composite_transcript_component, verify_h4_component_from_v3_envelope,
    verify_typed_state_component_from_v3_envelope,
};
use crate::v3_composite_envelope::{
    V3ComponentKind, V3ParsedEnvelope, V3ProfileLayout, parse_v3_envelope,
    verify_v3_composite_with_native_receipts,
};

pub const REAL_AUTHORITY_WITNESS_FORMAT: &str = "BLV3REALW01";
pub const REAL_AUTHORITY_EVIDENCE_FORMAT: &str = "BLV3REALE01";
pub const REAL_AUTHORITY_MAX_ARTIFACT_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub const REAL_AUTHORITY_HOST_PEAK_LIMIT_BYTES: u64 = 5_000_000_000;
pub const REAL_AUTHORITY_SCRATCH_LIMIT_BYTES: u64 = 5_000_000_000;
pub const REAL_AUTHORITY_TIMEOUT_SECONDS: u64 = 6 * 60 * 60;
pub const REAL_AUTHORITY_CUSTODY_FORMAT: &str = "BLV3CUST01";

const MAX_SMALL_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_KEY_BYTES: u64 = 2 * 1024 * 1024;
const MAX_FRI_PARAMETERS_BYTES: u64 = 64 * 1024 * 1024;
const MAX_FUNCTIONAL_INPUT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_MASK_INPUT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_POST_Z_RESPONSE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_POST_Z_SEGMENT_BYTES: u64 = 512 * 1024 * 1024;

pub const TRUSTED_LAYOUT_FILE: &str = "trusted-layout.bin";
pub const COMPOSITE_ENVELOPE_FILE: &str = "composite-envelope.bin";
pub const SEMANTIC_CONTEXT_FILE: &str = "semantic-context.bin";
pub const SEMANTIC_PREFIX_FILE: &str = "semantic-prefix.bin";
pub const SEMANTIC_CONTINUATION_FILE: &str = "semantic-continuation.bin";
pub const SEMANTIC_PARENT_ANCHOR_FILE: &str = "semantic-parent-anchor.bin";
pub const SEMANTIC_KEY_FILE: &str = "semantic-key.bin";
pub const SEMANTIC_STRICT_BUNDLE_FILE: &str = "semantic-strict-bundle.bin";
pub const SEMANTIC_PROGRAM_FILE: &str = "semantic-program.bin";
pub const SEMANTIC_FRI_PARAMETERS_FILE: &str = "semantic-fri-parameters.bin";
pub const SEMANTIC_FRI_PROOF_FILE: &str = "semantic-fri-proof.bin";
pub const H4_KEY_FILE: &str = "h4-key.bin";
pub const H4_GKR_KEY_FILE: &str = "h4-gkr-key.bin";
pub const H4_POST_Z_KEYS_DIRECTORY: &str = "h4-post-z-keys";
pub const H4_GKR_PROOF_FILE: &str = "h4-gkr-proof.bin";
pub const H4_GKR_STRICT_BUNDLE_FILE: &str = "h4-gkr-strict-bundle.bin";
pub const H4_GKR_CONTEXT_FILE: &str = "h4-gkr-context.bin";
pub const H4_GKR_FIRST_ORDINAL_FILE: &str = "h4-gkr-first-ordinal.bin";
pub const H4_FUNCTIONAL_INPUTS_FILE: &str = "h4-functional-inputs.bin";
pub const H4_MASK_INPUT_FILE: &str = "h4-mask-input.bin";
pub const H4_SHARDS_DIRECTORY: &str = "h4-shards";

#[derive(Debug)]
pub enum RealAuthorityError {
    Input(String),
    Encoding(String),
    Native(String),
    Output(String),
    Resource(String),
}

impl fmt::Display for RealAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input(value) => write!(formatter, "input:{value}"),
            Self::Encoding(value) => write!(formatter, "encoding:{value}"),
            Self::Native(value) => write!(formatter, "native:{value}"),
            Self::Output(value) => write!(formatter, "output:{value}"),
            Self::Resource(value) => write!(formatter, "resource:{value}"),
        }
    }
}

impl std::error::Error for RealAuthorityError {}

fn absolute_directory(path: &Path, label: &str) -> Result<PathBuf, RealAuthorityError> {
    if !path.is_absolute() {
        return Err(RealAuthorityError::Input(format!(
            "{label}_path_not_absolute"
        )));
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        RealAuthorityError::Input(format!("{label}_metadata:{:?}", error.kind()))
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(RealAuthorityError::Input(format!(
            "{label}_not_regular_directory"
        )));
    }
    Ok(path.to_path_buf())
}

fn validate_file_name(name: &str, label: &str) -> Result<(), RealAuthorityError> {
    let mut components = Path::new(name).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(_)), None) => Ok(()),
        _ => Err(RealAuthorityError::Input(format!(
            "{label}_file_name_not_single_component"
        ))),
    }
}

fn regular_file_metadata(
    path: &Path,
    label: &str,
    maximum_bytes: u64,
) -> Result<fs::Metadata, RealAuthorityError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        RealAuthorityError::Input(format!("{label}_metadata:{:?}", error.kind()))
    })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(RealAuthorityError::Input(format!(
            "{label}_not_regular_file"
        )));
    }
    if metadata.len() > maximum_bytes {
        return Err(RealAuthorityError::Resource(format!(
            "{label}_bytes={} exceeds={maximum_bytes}",
            metadata.len()
        )));
    }
    Ok(metadata)
}

fn read_regular_file(
    path: &Path,
    label: &str,
    maximum_bytes: u64,
) -> Result<Vec<u8>, RealAuthorityError> {
    let before = regular_file_metadata(path, label, maximum_bytes)?;
    let expected_len = usize::try_from(before.len())
        .map_err(|_| RealAuthorityError::Resource(format!("{label}_length_not_addressable")))?;
    let mut file = File::open(path)
        .map_err(|error| RealAuthorityError::Input(format!("{label}_open:{:?}", error.kind())))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(expected_len)
        .map_err(|_| RealAuthorityError::Resource(format!("{label}_allocation_failed")))?;
    file.read_to_end(&mut bytes)
        .map_err(|error| RealAuthorityError::Input(format!("{label}_read:{:?}", error.kind())))?;
    let after = fs::symlink_metadata(path).map_err(|error| {
        RealAuthorityError::Input(format!("{label}_metadata_after:{:?}", error.kind()))
    })?;
    if after.file_type().is_symlink() || after.len() != before.len() || bytes.len() != expected_len
    {
        return Err(RealAuthorityError::Input(format!(
            "{label}_changed_during_read"
        )));
    }
    Ok(bytes)
}

fn require_existing_output_directory(
    path: &Path,
    label: &str,
) -> Result<PathBuf, RealAuthorityError> {
    absolute_directory(path, label)
}

/// The fixed names and bounded file reader for one real proof witness.
///
/// This type is intentionally not `Serialize`/`Deserialize`: the native
/// pipeline receives bytes only after the regular-file, size, and
/// changed-during-read checks above have completed.
#[derive(Clone, Debug)]
pub struct RealWitness {
    root: PathBuf,
}

impl RealWitness {
    pub fn open(path: &Path) -> Result<Self, RealAuthorityError> {
        Ok(Self {
            root: absolute_directory(path, "witness_dir")?,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn read_named(
        &self,
        name: &str,
        maximum_bytes: u64,
    ) -> Result<Vec<u8>, RealAuthorityError> {
        validate_file_name(name, name)?;
        read_regular_file(&self.root.join(name), name, maximum_bytes)
    }

    pub fn check_named(&self, name: &str, maximum_bytes: u64) -> Result<(), RealAuthorityError> {
        validate_file_name(name, name)?;
        let _ = regular_file_metadata(&self.root.join(name), name, maximum_bytes)?;
        Ok(())
    }

    pub fn read_small(&self, name: &str) -> Result<Vec<u8>, RealAuthorityError> {
        self.read_named(name, MAX_SMALL_ARTIFACT_BYTES)
    }

    pub fn read_key(&self, name: &str) -> Result<Vec<u8>, RealAuthorityError> {
        self.read_named(name, MAX_KEY_BYTES)
    }

    pub fn read_shard(
        &self,
        shard: usize,
        name: &str,
        maximum_bytes: u64,
    ) -> Result<Vec<u8>, RealAuthorityError> {
        validate_file_name(name, "h4_shard_file")?;
        let shard_dir = self.root.join(H4_SHARDS_DIRECTORY).join(format!("{shard}"));
        let metadata = fs::symlink_metadata(&shard_dir).map_err(|error| {
            RealAuthorityError::Input(format!("h4_shard_{shard}_metadata:{:?}", error.kind()))
        })?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(RealAuthorityError::Input(format!(
                "h4_shard_{shard}_not_regular_directory"
            )));
        }
        read_regular_file(
            &shard_dir.join(name),
            &format!("h4_shard_{shard}_{name}"),
            maximum_bytes,
        )
    }

    pub fn check_shard(
        &self,
        shard: usize,
        name: &str,
        maximum_bytes: u64,
    ) -> Result<(), RealAuthorityError> {
        validate_file_name(name, "h4_shard_file")?;
        let shard_dir = self.root.join(H4_SHARDS_DIRECTORY).join(format!("{shard}"));
        let metadata = fs::symlink_metadata(&shard_dir).map_err(|error| {
            RealAuthorityError::Input(format!("h4_shard_{shard}_metadata:{:?}", error.kind()))
        })?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(RealAuthorityError::Input(format!(
                "h4_shard_{shard}_not_regular_directory"
            )));
        }
        let _ = regular_file_metadata(
            &shard_dir.join(name),
            &format!("h4_shard_{shard}_{name}"),
            maximum_bytes,
        )?;
        Ok(())
    }

    fn post_z_key_path(&self, shard: usize) -> PathBuf {
        self.root
            .join(H4_POST_Z_KEYS_DIRECTORY)
            .join(format!("{shard}.bin"))
    }

    pub fn read_post_z_key(&self, shard: usize) -> Result<Vec<u8>, RealAuthorityError> {
        read_regular_file(
            &self.post_z_key_path(shard),
            &format!("h4_post_z_key_{shard}"),
            MAX_KEY_BYTES,
        )
    }

    pub fn check_post_z_key(&self, shard: usize) -> Result<(), RealAuthorityError> {
        let directory = self.root.join(H4_POST_Z_KEYS_DIRECTORY);
        let metadata = fs::symlink_metadata(&directory).map_err(|error| {
            RealAuthorityError::Input(format!(
                "h4_post_z_keys_directory_metadata:{:?}",
                error.kind()
            ))
        })?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(RealAuthorityError::Input(
                "h4_post_z_keys_directory_not_regular".to_owned(),
            ));
        }
        let _ = regular_file_metadata(
            &self.post_z_key_path(shard),
            &format!("h4_post_z_key_{shard}"),
            MAX_KEY_BYTES,
        )?;
        Ok(())
    }
}

/// Validate the filesystem portion of the real-witness contract before any
/// cryptographic parser allocates proof-shaped data.  The cryptographic
/// stages below perform the semantic length and identity checks.
pub fn validate_witness_files(
    witness: &RealWitness,
    profile_shard_count: usize,
) -> Result<(), RealAuthorityError> {
    for name in [
        TRUSTED_LAYOUT_FILE,
        COMPOSITE_ENVELOPE_FILE,
        SEMANTIC_CONTEXT_FILE,
        SEMANTIC_PREFIX_FILE,
        SEMANTIC_CONTINUATION_FILE,
        SEMANTIC_PARENT_ANCHOR_FILE,
        SEMANTIC_KEY_FILE,
        SEMANTIC_STRICT_BUNDLE_FILE,
        SEMANTIC_PROGRAM_FILE,
        SEMANTIC_FRI_PARAMETERS_FILE,
        SEMANTIC_FRI_PROOF_FILE,
        H4_KEY_FILE,
        H4_GKR_PROOF_FILE,
        H4_GKR_STRICT_BUNDLE_FILE,
        H4_GKR_CONTEXT_FILE,
        H4_GKR_FIRST_ORDINAL_FILE,
        H4_FUNCTIONAL_INPUTS_FILE,
        H4_MASK_INPUT_FILE,
    ] {
        let maximum = match name {
            SEMANTIC_KEY_FILE | H4_KEY_FILE => MAX_KEY_BYTES,
            SEMANTIC_FRI_PARAMETERS_FILE => MAX_FRI_PARAMETERS_BYTES,
            H4_FUNCTIONAL_INPUTS_FILE => MAX_FUNCTIONAL_INPUT_BYTES,
            H4_MASK_INPUT_FILE => MAX_MASK_INPUT_BYTES,
            COMPOSITE_ENVELOPE_FILE => REAL_AUTHORITY_MAX_ARTIFACT_BYTES,
            _ => MAX_SMALL_ARTIFACT_BYTES,
        };
        witness.check_named(name, maximum)?;
    }
    witness.check_named(H4_GKR_KEY_FILE, MAX_KEY_BYTES)?;
    for shard in 0..profile_shard_count {
        witness.check_post_z_key(shard)?;
        for name in [
            "strict-bundle.bin",
            "response.bin",
            "first-ordinal.bin",
            "source-segment.bin",
            "base-segment.bin",
        ] {
            let maximum = match name {
                "response.bin" => MAX_POST_Z_RESPONSE_BYTES,
                "source-segment.bin" | "base-segment.bin" => MAX_POST_Z_SEGMENT_BYTES,
                _ => MAX_SMALL_ARTIFACT_BYTES,
            };
            witness.check_shard(shard, name, maximum)?;
        }
    }
    Ok(())
}

fn path_is_present(path: &Path, label: &str) -> Result<bool, RealAuthorityError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(RealAuthorityError::Output(format!(
            "{label}_metadata:{:?}",
            error.kind()
        ))),
    }
}

/// Publish a set of evidence files as one output transaction.  Every target
/// is checked before any write, each body is synced and read back, and a
/// later failure removes only files created by this call.  This prevents a
/// half-published acceptance record from being mistaken for a complete run.
pub fn publish_new_files(
    directory: &Path,
    files: &[(&str, &[u8])],
) -> Result<(), RealAuthorityError> {
    let directory = require_existing_output_directory(directory, "evidence_dir")?;
    if files.is_empty() {
        return Err(RealAuthorityError::Output("no_files".to_owned()));
    }

    let mut paths = Vec::with_capacity(files.len());
    for (name, _) in files {
        validate_file_name(name, name)?;
        if files
            .iter()
            .filter(|(candidate, _)| candidate == name)
            .count()
            != 1
        {
            return Err(RealAuthorityError::Output(format!("{name}_duplicate")));
        }
        let output = directory.join(name);
        let partial = directory.join(format!("{name}.partial"));
        if path_is_present(&output, name)? {
            return Err(RealAuthorityError::Output(format!("{name}_exists")));
        }
        if path_is_present(&partial, &format!("{name}_partial"))? {
            return Err(RealAuthorityError::Output(format!("{name}_partial_exists")));
        }
        paths.push((partial, output));
    }

    let mut written = Vec::with_capacity(paths.len());
    for ((name, bytes), (partial, _)) in files.iter().zip(&paths) {
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(partial)
        {
            Ok(file) => file,
            Err(error) => {
                for path in &written {
                    let _ = fs::remove_file(path);
                }
                return Err(RealAuthorityError::Output(format!(
                    "{name}_open:{:?}",
                    error.kind()
                )));
            }
        };
        if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_all()) {
            drop(file);
            let _ = fs::remove_file(partial);
            for path in &written {
                let _ = fs::remove_file(path);
            }
            return Err(RealAuthorityError::Output(format!(
                "{name}_write:{:?}",
                error.kind()
            )));
        }
        drop(file);
        let readback = match fs::read(partial) {
            Ok(readback) => readback,
            Err(error) => {
                let _ = fs::remove_file(partial);
                for path in &written {
                    let _ = fs::remove_file(path);
                }
                return Err(RealAuthorityError::Output(format!(
                    "{name}_readback:{:?}",
                    error.kind()
                )));
            }
        };
        if readback != *bytes {
            let _ = fs::remove_file(partial);
            for path in &written {
                let _ = fs::remove_file(path);
            }
            return Err(RealAuthorityError::Output(format!(
                "{name}_readback_mismatch"
            )));
        }
        written.push(partial.clone());
    }

    let mut published = Vec::with_capacity(paths.len());
    for ((name, _), (partial, output)) in files.iter().zip(&paths) {
        if let Err(error) = fs::rename(partial, output) {
            for path in &written {
                let _ = fs::remove_file(path);
            }
            for path in &published {
                let _ = fs::remove_file(path);
            }
            return Err(RealAuthorityError::Output(format!(
                "{name}_publish:{:?}",
                error.kind()
            )));
        }
        published.push(output.clone());
    }
    Ok(())
}

/// Publish one evidence file atomically without overwriting an existing run.
/// The native receipt is written only after all accepting checks pass.
pub fn publish_new_file(
    directory: &Path,
    name: &str,
    bytes: &[u8],
) -> Result<(), RealAuthorityError> {
    publish_new_files(directory, &[(name, bytes)])
}

/// Exact input/output boundary used by the eventual native run.  It is kept
/// public so the Python major-run coordinator can preflight the same contract
/// without learning any accepting receipt representation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealAuthorityRunContract {
    pub witness_format: &'static str,
    pub evidence_format: &'static str,
    pub host_peak_limit_bytes: u64,
    pub scratch_limit_bytes: u64,
    pub timeout_seconds: u64,
    pub proof_suite_id: Option<[u8; 64]>,
    pub production_usable: bool,
    pub activation_allowed: bool,
}

impl Default for RealAuthorityRunContract {
    fn default() -> Self {
        Self {
            witness_format: REAL_AUTHORITY_WITNESS_FORMAT,
            evidence_format: REAL_AUTHORITY_EVIDENCE_FORMAT,
            host_peak_limit_bytes: REAL_AUTHORITY_HOST_PEAK_LIMIT_BYTES,
            scratch_limit_bytes: REAL_AUTHORITY_SCRATCH_LIMIT_BYTES,
            timeout_seconds: REAL_AUTHORITY_TIMEOUT_SECONDS,
            proof_suite_id: None,
            production_usable: false,
            activation_allowed: false,
        }
    }
}

/// Placeholder for the native pipeline result.  The type is intentionally
/// private until the full raw-witness replay implementation below has minted
/// an opaque accepting receipt; no caller can construct a successful result
/// from this contract alone.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealAuthorityRunReport {
    pub profile_code: u8,
    pub status: &'static str,
    pub proof_suite_id: Option<[u8; 64]>,
    pub production_usable: bool,
    pub activation_allowed: bool,
}

impl RealAuthorityRunReport {
    pub const fn contract_status(profile_code: u8) -> Self {
        Self {
            profile_code,
            status: "V3_REAL_AUTHORITY_WITNESS_CONTRACT_READY_NONACTIVATING",
            proof_suite_id: None,
            production_usable: false,
            activation_allowed: false,
        }
    }
}

struct WireReader<'a> {
    encoded: &'a [u8],
    offset: usize,
}

impl<'a> WireReader<'a> {
    fn new(encoded: &'a [u8], label: &str, maximum_bytes: u64) -> Result<Self, RealAuthorityError> {
        if u64::try_from(encoded.len())
            .map_err(|_| RealAuthorityError::Resource(format!("{label}_length_not_addressable")))?
            > maximum_bytes
        {
            return Err(RealAuthorityError::Resource(format!("{label}_too_large")));
        }
        Ok(Self { encoded, offset: 0 })
    }

    fn take(&mut self, length: usize, label: &str) -> Result<&'a [u8], RealAuthorityError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| RealAuthorityError::Encoding(format!("{label}_offset_overflow")))?;
        let value = self
            .encoded
            .get(self.offset..end)
            .ok_or_else(|| RealAuthorityError::Encoding(format!("{label}_truncated")))?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self, label: &str) -> Result<u8, RealAuthorityError> {
        Ok(self.take(1, label)?[0])
    }

    fn u16(&mut self, label: &str) -> Result<u16, RealAuthorityError> {
        Ok(u16::from_be_bytes(
            self.take(2, label)?
                .try_into()
                .map_err(|_| RealAuthorityError::Encoding(format!("{label}_length")))?,
        ))
    }

    fn u32(&mut self, label: &str) -> Result<u32, RealAuthorityError> {
        Ok(u32::from_be_bytes(
            self.take(4, label)?
                .try_into()
                .map_err(|_| RealAuthorityError::Encoding(format!("{label}_length")))?,
        ))
    }

    fn fp16(&mut self, label: &str) -> Result<Fp16, RealAuthorityError> {
        Fp16::decode(self.take(64, label)?)
            .map_err(|error| RealAuthorityError::Encoding(format!("{label}_field:{error:?}")))
    }

    fn digest(&mut self, label: &str) -> Result<BindingDigestV2, RealAuthorityError> {
        BindingDigestV2::decode(self.take(BINDING_V2_BYTES, label)?)
            .map_err(|error| RealAuthorityError::Encoding(format!("{label}_binding:{error:?}")))
    }

    fn root(&mut self, label: &str) -> Result<BindingRootV2, RealAuthorityError> {
        BindingRootV2::decode(self.take(BINDING_V2_BYTES, label)?)
            .map_err(|error| RealAuthorityError::Encoding(format!("{label}_root:{error:?}")))
    }

    fn finish(self, label: &str) -> Result<(), RealAuthorityError> {
        if self.offset != self.encoded.len() {
            return Err(RealAuthorityError::Encoding(format!("{label}_trailing")));
        }
        Ok(())
    }
}

fn decode_profile_code(code: u8, label: &str) -> Result<Profile, RealAuthorityError> {
    match code {
        1 => Ok(Profile::K128Calibration),
        3 => Ok(Profile::K512Calibration),
        _ => Err(RealAuthorityError::Encoding(format!("{label}_profile"))),
    }
}

fn profile_code(profile: Profile) -> u8 {
    match profile {
        Profile::K128Calibration => 1,
        Profile::K512Calibration => 3,
        _ => 0,
    }
}

fn h4_profile_code(profile: H4ProofProfileV2) -> u8 {
    profile.code()
}

fn semantic_bridge_profile(profile: H4ProofProfileV2) -> SemanticH4BridgeProfile {
    match profile {
        H4ProofProfileV2::K128 => SemanticH4BridgeProfile::K128,
        H4ProofProfileV2::K512 => SemanticH4BridgeProfile::K512,
    }
}

fn debug_error<T: fmt::Debug>(label: &str, error: T) -> RealAuthorityError {
    RealAuthorityError::Native(format!("{label}:{error:?}"))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticFriParametersV3 {
    pub public_inputs: Vec<M31>,
    pub mask_coefficient_count: usize,
    pub log_blowup: u8,
    pub oracle_roots: crate::oracle_commitment::BindingCommittedAirRootsV2,
    pub mask_root: BindingRootV2,
    pub claims: Vec<DomainOodsClaims>,
    pub layer_roots: Vec<BindingRootV2>,
    pub final_constant: Fp16,
}

const FRI_PARAMETERS_MAGIC: &[u8; 8] = b"BLV3FP01";
const FRI_PARAMETERS_VERSION: u16 = 1;

pub fn encode_semantic_fri_parameters_v3(
    parameters: &SemanticFriParametersV3,
) -> Result<Vec<u8>, RealAuthorityError> {
    if parameters.public_inputs.len() > 1_000_000
        || parameters.mask_coefficient_count == 0
        || parameters.mask_coefficient_count > u32::MAX as usize
        || !(1..=30).contains(&parameters.log_blowup)
        || parameters.claims.is_empty()
        || parameters.claims.len() > 64
        || parameters.layer_roots.is_empty()
        || parameters.layer_roots.len() > 64
    {
        return Err(RealAuthorityError::Encoding(
            "semantic_fri_parameters_shape".to_owned(),
        ));
    }
    let mut encoded = Vec::new();
    encoded.extend_from_slice(FRI_PARAMETERS_MAGIC);
    encoded.extend_from_slice(&FRI_PARAMETERS_VERSION.to_be_bytes());
    encoded.extend_from_slice(&0_u16.to_be_bytes());
    encoded.extend_from_slice(
        &u32::try_from(parameters.public_inputs.len())
            .map_err(|_| RealAuthorityError::Encoding("public_input_count".to_owned()))?
            .to_be_bytes(),
    );
    for value in &parameters.public_inputs {
        encoded.extend_from_slice(&value.as_u32().to_be_bytes());
    }
    encoded.extend_from_slice(
        &u32::try_from(parameters.mask_coefficient_count)
            .map_err(|_| RealAuthorityError::Encoding("mask_coefficient_count".to_owned()))?
            .to_be_bytes(),
    );
    encoded.push(parameters.log_blowup);
    encoded.extend_from_slice(&[0_u8; 3]);
    encoded.extend_from_slice(parameters.oracle_roots.main_trace.as_bytes());
    match &parameters.oracle_roots.interaction_trace {
        Some(root) => {
            encoded.push(1);
            encoded.extend_from_slice(root.as_bytes());
        }
        None => encoded.push(0),
    }
    encoded.extend_from_slice(&[0_u8; 3]);
    encoded.extend_from_slice(parameters.oracle_roots.composition.as_bytes());
    encoded.extend_from_slice(parameters.mask_root.as_bytes());
    encoded.extend_from_slice(
        &u32::try_from(parameters.claims.len())
            .map_err(|_| RealAuthorityError::Encoding("claim_count".to_owned()))?
            .to_be_bytes(),
    );
    for claim in &parameters.claims {
        if claim.values.len() > u32::MAX as usize
            || claim.conjugate_values.len() > u32::MAX as usize
        {
            return Err(RealAuthorityError::Encoding("claim_value_count".to_owned()));
        }
        encoded.push(claim.log_size);
        encoded.extend_from_slice(&[0_u8; 3]);
        encoded.extend_from_slice(&(claim.values.len() as u32).to_be_bytes());
        for value in &claim.values {
            encoded.extend_from_slice(&value.encode());
        }
        encoded.extend_from_slice(&(claim.conjugate_values.len() as u32).to_be_bytes());
        for value in &claim.conjugate_values {
            encoded.extend_from_slice(&value.encode());
        }
    }
    encoded.extend_from_slice(
        &u32::try_from(parameters.layer_roots.len())
            .map_err(|_| RealAuthorityError::Encoding("fri_layer_count".to_owned()))?
            .to_be_bytes(),
    );
    for root in &parameters.layer_roots {
        encoded.extend_from_slice(root.as_bytes());
    }
    encoded.extend_from_slice(&parameters.final_constant.encode());
    if encoded.len() as u64 > MAX_FRI_PARAMETERS_BYTES {
        return Err(RealAuthorityError::Resource(
            "semantic_fri_parameters_too_large".to_owned(),
        ));
    }
    Ok(encoded)
}

pub fn decode_semantic_fri_parameters_v3(
    encoded: &[u8],
) -> Result<SemanticFriParametersV3, RealAuthorityError> {
    let mut reader = WireReader::new(encoded, "semantic_fri_parameters", MAX_FRI_PARAMETERS_BYTES)?;
    if reader.take(8, "fri_magic")? != FRI_PARAMETERS_MAGIC
        || reader.u16("fri_version")? != FRI_PARAMETERS_VERSION
        || reader.u16("fri_flags")? != 0
    {
        return Err(RealAuthorityError::Encoding(
            "semantic_fri_parameters_header".to_owned(),
        ));
    }
    let public_input_count = usize::try_from(reader.u32("public_input_count")?)
        .map_err(|_| RealAuthorityError::Encoding("public_input_count".to_owned()))?;
    if public_input_count > 1_000_000 {
        return Err(RealAuthorityError::Resource(
            "public_input_count_too_large".to_owned(),
        ));
    }
    let public_inputs = (0..public_input_count)
        .map(|_| {
            M31::from_canonical(reader.u32("public_input")?).map_err(|error| {
                RealAuthorityError::Encoding(format!("public_input_field:{error:?}"))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mask_coefficient_count = usize::try_from(reader.u32("mask_coefficient_count")?)
        .map_err(|_| RealAuthorityError::Encoding("mask_coefficient_count".to_owned()))?;
    let log_blowup = reader.u8("log_blowup")?;
    if reader.take(3, "fri_reserved")? != [0_u8; 3]
        || mask_coefficient_count == 0
        || !(1..=30).contains(&log_blowup)
    {
        return Err(RealAuthorityError::Encoding(
            "fri_parameters_geometry".to_owned(),
        ));
    }

    let main_trace = reader.root("main_trace_root")?;
    let interaction_trace = match reader.u8("interaction_flag")? {
        0 => None,
        1 => Some(reader.root("interaction_trace_root")?),
        _ => return Err(RealAuthorityError::Encoding("interaction_flag".to_owned())),
    };
    if reader.take(3, "interaction_reserved")? != [0_u8; 3] {
        return Err(RealAuthorityError::Encoding(
            "interaction_reserved".to_owned(),
        ));
    }
    let composition = reader.root("composition_root")?;
    let mask_root = reader.root("mask_root")?;

    let claim_count = usize::try_from(reader.u32("claim_count")?)
        .map_err(|_| RealAuthorityError::Encoding("claim_count".to_owned()))?;
    if claim_count == 0 || claim_count > 64 {
        return Err(RealAuthorityError::Encoding("claim_count".to_owned()));
    }
    let mut claims = Vec::with_capacity(claim_count);
    for claim_index in 0..claim_count {
        let log_size = reader.u8("claim_log_size")?;
        if reader.take(3, "claim_reserved")? != [0_u8; 3] {
            return Err(RealAuthorityError::Encoding(format!(
                "claim_{claim_index}_reserved"
            )));
        }
        let values_count = usize::try_from(reader.u32("claim_values_count")?)
            .map_err(|_| RealAuthorityError::Encoding("claim_values_count".to_owned()))?;
        let values = (0..values_count)
            .map(|_| reader.fp16("claim_value"))
            .collect::<Result<Vec<_>, _>>()?;
        let conjugate_count = usize::try_from(reader.u32("claim_conjugate_count")?)
            .map_err(|_| RealAuthorityError::Encoding("claim_conjugate_count".to_owned()))?;
        let conjugate_values = (0..conjugate_count)
            .map(|_| reader.fp16("claim_conjugate_value"))
            .collect::<Result<Vec<_>, _>>()?;
        claims.push(DomainOodsClaims {
            log_size,
            values,
            conjugate_values,
        });
    }

    let layer_count = usize::try_from(reader.u32("fri_layer_count")?)
        .map_err(|_| RealAuthorityError::Encoding("fri_layer_count".to_owned()))?;
    if layer_count == 0 || layer_count > 64 {
        return Err(RealAuthorityError::Encoding("fri_layer_count".to_owned()));
    }
    let layer_roots = (0..layer_count)
        .map(|_| reader.root("fri_layer_root"))
        .collect::<Result<Vec<_>, _>>()?;
    let final_constant = reader.fp16("fri_final_constant")?;
    reader.finish("semantic_fri_parameters")?;
    Ok(SemanticFriParametersV3 {
        public_inputs,
        mask_coefficient_count,
        log_blowup,
        oracle_roots: crate::oracle_commitment::BindingCommittedAirRootsV2 {
            main_trace,
            interaction_trace,
            composition,
        },
        mask_root,
        claims,
        layer_roots,
        final_constant,
    })
}

fn read_len_prefixed<'a>(
    reader: &mut WireReader<'a>,
    label: &str,
    maximum: usize,
) -> Result<&'a [u8], RealAuthorityError> {
    let length = usize::try_from(reader.u32(label)?)
        .map_err(|_| RealAuthorityError::Encoding(format!("{label}_length")))?;
    if length > maximum {
        return Err(RealAuthorityError::Resource(format!(
            "{label}_length={length} exceeds={maximum}"
        )));
    }
    reader.take(length, label)
}

fn decode_functional_inputs(
    encoded: &[u8],
) -> Result<Vec<SemanticBridgeFunctionalProofInputV3>, RealAuthorityError> {
    let mut reader = WireReader::new(encoded, "h4_functional_inputs", MAX_FUNCTIONAL_INPUT_BYTES)?;
    if reader.take(8, "functional_magic")? != b"BLV3FI01"
        || reader.u16("functional_version")? != 1
        || reader.u16("functional_flags")? != 0
    {
        return Err(RealAuthorityError::Encoding(
            "h4_functional_inputs_header".to_owned(),
        ));
    }
    let count = usize::try_from(reader.u32("functional_count")?)
        .map_err(|_| RealAuthorityError::Encoding("functional_count".to_owned()))?;
    if count == 0 || count > 128 {
        return Err(RealAuthorityError::Encoding("functional_count".to_owned()));
    }
    let mut result = Vec::with_capacity(count);
    for _ in 0..count {
        let proof_bytes = read_len_prefixed(&mut reader, "functional_circle_proof", 32 << 20)?;
        let proof = decode_circle_coefficient_mle_proof_v3(proof_bytes)
            .map_err(|error| debug_error("functional_circle_proof", error))?;
        let coefficient_root = reader.root("functional_coefficient_root")?;
        let challenge_count = usize::try_from(reader.u32("functional_challenge_count")?)
            .map_err(|_| RealAuthorityError::Encoding("functional_challenge_count".to_owned()))?;
        if challenge_count == 0 || challenge_count > 64 {
            return Err(RealAuthorityError::Encoding(
                "functional_challenge_count".to_owned(),
            ));
        }
        let functional_challenges = (0..challenge_count)
            .map(|_| reader.fp16("functional_challenge"))
            .collect::<Result<Vec<_>, _>>()?;
        let coefficient_context = reader.digest("functional_coefficient_context")?;
        let circle_completion_coin = reader.digest("functional_circle_completion_coin")?;
        let functional_completion_coin = reader.digest("functional_completion_coin")?;
        let conjugate = match reader.u8("functional_conjugate")? {
            0 => false,
            1 => true,
            _ => {
                return Err(RealAuthorityError::Encoding(
                    "functional_conjugate".to_owned(),
                ));
            }
        };
        if reader.take(3, "functional_reserved")? != [0_u8; 3] {
            return Err(RealAuthorityError::Encoding(
                "functional_reserved".to_owned(),
            ));
        }
        result.push(SemanticBridgeFunctionalProofInputV3 {
            proof,
            coefficient_root,
            functional_challenges,
            coefficient_context,
            circle_completion_coin,
            functional_completion_coin,
            conjugate,
        });
    }
    reader.finish("h4_functional_inputs")?;
    Ok(result)
}

/// Serialize the verifier-fixed semantic functional inputs consumed by the
/// real witness replay route.  This is a transport codec only: it does not
/// mint a semantic receipt, and every proof is still replayed by
/// `run_real_authority` against the exact program, FRI receipt, and GKR
/// challenge sequence.
pub fn encode_semantic_bridge_functional_inputs_v3(
    inputs: &[SemanticBridgeFunctionalProofInputV3],
) -> Result<Vec<u8>, RealAuthorityError> {
    if inputs.is_empty() || inputs.len() > 128 {
        return Err(RealAuthorityError::Encoding("functional_count".to_owned()));
    }
    let mut encoded = Vec::new();
    encoded.extend_from_slice(b"BLV3FI01");
    encoded.extend_from_slice(&1_u16.to_be_bytes());
    encoded.extend_from_slice(&0_u16.to_be_bytes());
    encoded.extend_from_slice(
        &u32::try_from(inputs.len())
            .map_err(|_| RealAuthorityError::Encoding("functional_count".to_owned()))?
            .to_be_bytes(),
    );
    for input in inputs {
        if input.functional_challenges.is_empty() || input.functional_challenges.len() > 64 {
            return Err(RealAuthorityError::Encoding(
                "functional_challenge_count".to_owned(),
            ));
        }
        let proof = encode_circle_coefficient_mle_proof_v3(&input.proof).map_err(|error| {
            RealAuthorityError::Encoding(format!("functional_circle_proof:{error:?}"))
        })?;
        if proof.len() > 32 << 20 {
            return Err(RealAuthorityError::Resource(
                "functional_circle_proof".to_owned(),
            ));
        }
        encoded.extend_from_slice(
            &u32::try_from(proof.len())
                .map_err(|_| RealAuthorityError::Encoding("functional_circle_proof".to_owned()))?
                .to_be_bytes(),
        );
        encoded.extend_from_slice(&proof);
        encoded.extend_from_slice(input.coefficient_root.as_bytes());
        encoded.extend_from_slice(
            &u32::try_from(input.functional_challenges.len())
                .map_err(|_| RealAuthorityError::Encoding("functional_challenge_count".to_owned()))?
                .to_be_bytes(),
        );
        for challenge in &input.functional_challenges {
            encoded.extend_from_slice(&challenge.encode());
        }
        encoded.extend_from_slice(input.coefficient_context.as_bytes());
        encoded.extend_from_slice(input.circle_completion_coin.as_bytes());
        encoded.extend_from_slice(input.functional_completion_coin.as_bytes());
        encoded.push(u8::from(input.conjugate));
        encoded.extend_from_slice(&[0_u8; 3]);
    }
    if encoded.len() > usize::try_from(MAX_FUNCTIONAL_INPUT_BYTES).unwrap_or(usize::MAX) {
        return Err(RealAuthorityError::Resource(
            "h4_functional_inputs".to_owned(),
        ));
    }
    let decoded = decode_functional_inputs(&encoded)?;
    if decoded != inputs {
        return Err(RealAuthorityError::Encoding(
            "functional_round_trip".to_owned(),
        ));
    }
    Ok(encoded)
}

/// Transport material for the source-mask PCS stage of complete H4.
///
/// The fields are public so an actual H4 producer can serialize the exact
/// proof it just constructed.  The type contains no accepting receipt; the
/// native replay path recomputes the expected context, source binding, and
/// mask relation before H4 completion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct H4MaskInputV3 {
    pub batch_challenge: Fp16,
    pub inner_product_proof: PublicBridgeInnerProductProof,
    pub inner_product_challenges: Vec<Fp16>,
    pub pcs_proof: BindingMultilinearPcsProofV2,
    pub expected_mask_root: BindingRootV2,
    pub expected_context: BindingDigestV2,
    pub completion_coin: BindingDigestV2,
}

impl From<ProducedSemanticH4BridgeSourceMaskV3> for H4MaskInputV3 {
    fn from(produced: ProducedSemanticH4BridgeSourceMaskV3) -> Self {
        Self {
            batch_challenge: produced.batch_challenge,
            inner_product_proof: produced.inner_product_proof,
            inner_product_challenges: produced.inner_product_challenges,
            pcs_proof: produced.pcs_proof,
            expected_mask_root: produced.expected_mask_root,
            expected_context: produced.expected_context,
            completion_coin: produced.completion_coin,
        }
    }
}

/// Convert a replay-checked native mask producer result directly into the
/// closed-witness transport grammar.
pub fn encode_produced_h4_mask_input_v3(
    produced: ProducedSemanticH4BridgeSourceMaskV3,
) -> Result<Vec<u8>, RealAuthorityError> {
    encode_h4_mask_input_v3(&produced.into())
}

/// Serialize one verifier-facing H4 source-mask input.  The input is
/// immediately decoded again so the producer cannot publish bytes whose
/// interpretation differs from the native witness reader.
pub fn encode_h4_mask_input_v3(input: &H4MaskInputV3) -> Result<Vec<u8>, RealAuthorityError> {
    if input.batch_challenge.is_zero()
        || input.inner_product_challenges.is_empty()
        || input.inner_product_challenges.len() > 64
    {
        return Err(RealAuthorityError::Encoding("mask_input_shape".to_owned()));
    }
    let inner = encode_public_bridge_inner_product_proof(&input.inner_product_proof)
        .map_err(|error| RealAuthorityError::Encoding(format!("mask_inner_product:{error:?}")))?;
    let pcs = encode_binding_multilinear_pcs_proof_v2(&input.pcs_proof)
        .map_err(|error| RealAuthorityError::Encoding(format!("mask_pcs:{error:?}")))?;
    let mut encoded = Vec::new();
    encoded.extend_from_slice(b"BLV3MS01");
    encoded.extend_from_slice(&1_u16.to_be_bytes());
    encoded.extend_from_slice(&0_u16.to_be_bytes());
    encoded.extend_from_slice(&input.batch_challenge.encode());
    encoded.extend_from_slice(
        &u32::try_from(inner.len())
            .map_err(|_| RealAuthorityError::Encoding("mask_inner_product".to_owned()))?
            .to_be_bytes(),
    );
    encoded.extend_from_slice(&inner);
    encoded.extend_from_slice(
        &u32::try_from(input.inner_product_challenges.len())
            .map_err(|_| RealAuthorityError::Encoding("mask_challenge_count".to_owned()))?
            .to_be_bytes(),
    );
    for challenge in &input.inner_product_challenges {
        encoded.extend_from_slice(&challenge.encode());
    }
    encoded.extend_from_slice(
        &u32::try_from(pcs.len())
            .map_err(|_| RealAuthorityError::Encoding("mask_pcs".to_owned()))?
            .to_be_bytes(),
    );
    encoded.extend_from_slice(&pcs);
    encoded.extend_from_slice(input.expected_mask_root.as_bytes());
    encoded.extend_from_slice(input.expected_context.as_bytes());
    encoded.extend_from_slice(input.completion_coin.as_bytes());
    if encoded.len() > usize::try_from(MAX_MASK_INPUT_BYTES).unwrap_or(usize::MAX) {
        return Err(RealAuthorityError::Resource("h4_mask_input".to_owned()));
    }
    let decoded = decode_mask_input(&encoded)?;
    if decoded != *input {
        return Err(RealAuthorityError::Encoding("mask_round_trip".to_owned()));
    }
    Ok(encoded)
}

fn decode_mask_input(encoded: &[u8]) -> Result<H4MaskInputV3, RealAuthorityError> {
    let mut reader = WireReader::new(encoded, "h4_mask_input", MAX_MASK_INPUT_BYTES)?;
    if reader.take(8, "mask_magic")? != b"BLV3MS01"
        || reader.u16("mask_version")? != 1
        || reader.u16("mask_flags")? != 0
    {
        return Err(RealAuthorityError::Encoding(
            "h4_mask_input_header".to_owned(),
        ));
    }
    let batch_challenge = reader.fp16("mask_batch_challenge")?;
    let inner_bytes = read_len_prefixed(&mut reader, "mask_inner_product", 2 * 1024 * 1024)?;
    let inner_product_proof = decode_public_bridge_inner_product_proof(inner_bytes)
        .map_err(|error| debug_error("mask_inner_product", error))?;
    let challenge_count = usize::try_from(reader.u32("mask_inner_product_challenge_count")?)
        .map_err(|_| {
            RealAuthorityError::Encoding("mask_inner_product_challenge_count".to_owned())
        })?;
    if challenge_count == 0 || challenge_count > 64 {
        return Err(RealAuthorityError::Encoding(
            "mask_inner_product_challenge_count".to_owned(),
        ));
    }
    let inner_product_challenges = (0..challenge_count)
        .map(|_| reader.fp16("mask_inner_product_challenge"))
        .collect::<Result<Vec<_>, _>>()?;
    let pcs_bytes = read_len_prefixed(&mut reader, "mask_pcs", 32 << 20)?;
    let pcs_proof = decode_binding_multilinear_pcs_proof_v2(pcs_bytes)
        .map_err(|error| debug_error("mask_pcs", error))?;
    let expected_mask_root = reader.root("mask_expected_root")?;
    let expected_context = reader.digest("mask_expected_context")?;
    let completion_coin = reader.digest("mask_completion_coin")?;
    reader.finish("h4_mask_input")?;
    Ok(H4MaskInputV3 {
        batch_challenge,
        inner_product_proof,
        inner_product_challenges,
        pcs_proof,
        expected_mask_root,
        expected_context,
        completion_coin,
    })
}

fn component_index(
    layout: &V3ProfileLayout,
    kind: V3ComponentKind,
) -> Result<usize, RealAuthorityError> {
    layout
        .components
        .iter()
        .position(|component| component.kind == kind)
        .ok_or_else(|| RealAuthorityError::Encoding(format!("component_{kind:?}_missing")))
}

fn component_body<'a>(
    envelope: &'a [u8],
    parsed: &V3ParsedEnvelope,
    index: usize,
    label: &str,
) -> Result<&'a [u8], RealAuthorityError> {
    let descriptor = parsed
        .descriptors
        .get(index)
        .ok_or_else(|| RealAuthorityError::Encoding(format!("{label}_descriptor_missing")))?;
    let start = usize::try_from(
        *parsed
            .component_offsets
            .get(index)
            .ok_or_else(|| RealAuthorityError::Encoding(format!("{label}_offset_missing")))?,
    )
    .map_err(|_| RealAuthorityError::Encoding(format!("{label}_offset")))?;
    let length = usize::try_from(descriptor.length)
        .map_err(|_| RealAuthorityError::Resource(format!("{label}_length")))?;
    let end = start
        .checked_add(length)
        .ok_or_else(|| RealAuthorityError::Encoding(format!("{label}_end_overflow")))?;
    envelope
        .get(start..end)
        .ok_or_else(|| RealAuthorityError::Encoding(format!("{label}_truncated")))
}

fn transcript_payload<'a>(encoded: &'a [u8]) -> Result<&'a [u8], RealAuthorityError> {
    if encoded.len() < 20
        || encoded.get(..8) != Some(b"BLV3TR01")
        || encoded.get(8..10) != Some(&1_u16.to_be_bytes())
        || encoded.get(10..12) != Some(&[0_u8; 2])
    {
        return Err(RealAuthorityError::Encoding(
            "composite_transcript_header".to_owned(),
        ));
    }
    let length = usize::try_from(u64::from_be_bytes(encoded[12..20].try_into().map_err(
        |_| RealAuthorityError::Encoding("composite_transcript_length".to_owned()),
    )?))
    .map_err(|_| RealAuthorityError::Resource("composite_transcript_length".to_owned()))?;
    let start: usize = 20;
    let end = start
        .checked_add(length)
        .ok_or_else(|| RealAuthorityError::Encoding("composite_transcript_end".to_owned()))?;
    let payload = encoded
        .get(start..end)
        .ok_or_else(|| RealAuthorityError::Encoding("composite_transcript_truncated".to_owned()))?;
    if encoded[end..].iter().any(|byte| *byte != 0) {
        return Err(RealAuthorityError::Encoding(
            "composite_transcript_nonzero_padding".to_owned(),
        ));
    }
    Ok(payload)
}

fn exact_u32_file(bytes: &[u8], label: &str) -> Result<u32, RealAuthorityError> {
    if bytes.len() != 4 {
        return Err(RealAuthorityError::Encoding(format!("{label}_length")));
    }
    Ok(u32::from_be_bytes(bytes.try_into().map_err(|_| {
        RealAuthorityError::Encoding(format!("{label}_length"))
    })?))
}

fn require_same_profile(
    layout: &V3ProfileLayout,
    context: &SemanticV3GovernedContext,
) -> Result<(), RealAuthorityError> {
    if profile_code(context.profile) != layout.profile_code {
        return Err(RealAuthorityError::Native(
            "semantic_context_profile_mismatch".to_owned(),
        ));
    }
    Ok(())
}

fn profile_shard_count(profile: Profile) -> usize {
    match profile {
        Profile::K128Calibration => 1,
        Profile::K512Calibration => 4,
        _ => 0,
    }
}

fn file_profile(layout: &V3ProfileLayout) -> Result<Profile, RealAuthorityError> {
    decode_profile_code(layout.profile_code, "layout")
}

fn hex_bytes(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn reserve_custody_attempt(
    witness: &RealWitness,
    profile: Profile,
    shard_count: usize,
    custody_dir: &Path,
) -> Result<(), RealAuthorityError> {
    let custody_dir = absolute_directory(custody_dir, "custody_dir")?;
    let mut identity_input = Vec::new();
    identity_input.extend_from_slice(REAL_AUTHORITY_CUSTODY_FORMAT.as_bytes());
    identity_input.push(profile_code(profile));
    identity_input.extend_from_slice(
        &u32::try_from(shard_count)
            .map_err(|_| RealAuthorityError::Resource("custody_shard_count".to_owned()))?
            .to_be_bytes(),
    );
    for name in [SEMANTIC_KEY_FILE, H4_KEY_FILE, H4_GKR_KEY_FILE] {
        let bytes = witness.read_key(name)?;
        identity_input.extend_from_slice(name.as_bytes());
        identity_input.extend_from_slice(
            &u64::try_from(bytes.len())
                .map_err(|_| RealAuthorityError::Resource("custody_key_length".to_owned()))?
                .to_be_bytes(),
        );
        identity_input.extend_from_slice(&bytes);
    }
    for shard in 0..shard_count {
        let bytes = witness.read_post_z_key(shard)?;
        identity_input.extend_from_slice(format!("h4-post-z-key-{shard}").as_bytes());
        identity_input.extend_from_slice(
            &u64::try_from(bytes.len())
                .map_err(|_| RealAuthorityError::Resource("custody_key_length".to_owned()))?
                .to_be_bytes(),
        );
        identity_input.extend_from_slice(&bytes);
    }
    let identity: [u8; 64] = Sha3_512::digest(&identity_input).into();
    let lock_path = custody_dir.join(format!(
        "{REAL_AUTHORITY_CUSTODY_FORMAT}-{}.lock",
        hex_bytes(&identity)
    ));
    let mut lock = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                RealAuthorityError::Resource("attempt_already_consumed".to_owned())
            } else {
                RealAuthorityError::Output(format!("custody_lock_open:{:?}", error.kind()))
            }
        })?;
    let record = format!(
        "format={REAL_AUTHORITY_CUSTODY_FORMAT}\nprofile_code={}\nidentity_sha3_512={}\nstatus=CONSUMED_BEFORE_NATIVE_REPLAY\n",
        profile_code(profile),
        hex_bytes(&identity),
    );
    lock.write_all(record.as_bytes()).map_err(|error| {
        RealAuthorityError::Output(format!("custody_lock_write:{:?}", error.kind()))
    })?;
    lock.sync_all().map_err(|error| {
        RealAuthorityError::Output(format!("custody_lock_sync:{:?}", error.kind()))
    })?;
    Ok(())
}

/// Re-verify one complete raw witness and enter the existing accepting v3
/// composition.  This is the real orchestrator/outer-verifier seam.  It is
/// intentionally one transaction-shaped function so no child process can
/// smuggle an opaque receipt or a status flag across a file boundary.
pub fn run_real_authority(
    witness_dir: &Path,
    evidence_dir: &Path,
    scratch_dir: &Path,
) -> Result<RealAuthorityRunReport, RealAuthorityError> {
    run_real_authority_inner(witness_dir, evidence_dir, scratch_dir, None)
}

/// Executable-facing authority entrypoint with durable one-time key custody.
/// A started attempt consumes its governed key identity before cryptographic
/// replay, including malformed or failed attempts.  This makes same-attempt
/// replay fail closed across processes instead of relying on an in-memory
/// registry that would disappear at process exit.
pub fn run_real_authority_with_custody(
    witness_dir: &Path,
    evidence_dir: &Path,
    scratch_dir: &Path,
    custody_dir: &Path,
) -> Result<RealAuthorityRunReport, RealAuthorityError> {
    run_real_authority_inner(witness_dir, evidence_dir, scratch_dir, Some(custody_dir))
}

fn run_real_authority_inner(
    witness_dir: &Path,
    evidence_dir: &Path,
    scratch_dir: &Path,
    custody_dir: Option<&Path>,
) -> Result<RealAuthorityRunReport, RealAuthorityError> {
    let witness = RealWitness::open(witness_dir)?;
    let evidence_dir = require_existing_output_directory(evidence_dir, "evidence_dir")?;
    let scratch_dir = require_existing_output_directory(scratch_dir, "scratch_dir")?;
    if evidence_dir == scratch_dir {
        return Err(RealAuthorityError::Resource(
            "evidence_and_scratch_must_differ".to_owned(),
        ));
    }

    let layout_bytes = witness.read_named(TRUSTED_LAYOUT_FILE, MAX_SMALL_ARTIFACT_BYTES)?;
    let layout = V3ProfileLayout::decode_trusted(&layout_bytes)
        .map_err(|error| debug_error("trusted_layout", error))?;
    let profile = file_profile(&layout)?;
    let shard_count = profile_shard_count(profile);
    validate_witness_files(&witness, shard_count)?;
    if let Some(custody_dir) = custody_dir {
        reserve_custody_attempt(&witness, profile, shard_count, custody_dir)?;
    }

    let envelope =
        witness.read_named(COMPOSITE_ENVELOPE_FILE, REAL_AUTHORITY_MAX_ARTIFACT_BYTES)?;
    let parsed = parse_v3_envelope(&mut Cursor::new(envelope.as_slice()), &layout)
        .map_err(|error| debug_error("composite_envelope", error))?;
    if parsed.profile_code != layout.profile_code
        || parsed.layout_commitment != layout.layout_commitment
        || parsed.production_usable
        || parsed.activation_allowed
    {
        return Err(RealAuthorityError::Native(
            "envelope_lifecycle_or_layout".to_owned(),
        ));
    }

    let semantic_index = component_index(&layout, V3ComponentKind::Semantic)?;
    let transcript_index = component_index(&layout, V3ComponentKind::CompositeTranscript)?;
    let semantic_component = component_body(&envelope, &parsed, semantic_index, "semantic")?;
    let semantic_prefix = witness.read_small(SEMANTIC_PREFIX_FILE)?;
    if semantic_component != semantic_prefix.as_slice() {
        return Err(RealAuthorityError::Native(
            "semantic_prefix_not_identical_to_envelope_component".to_owned(),
        ));
    }
    let context_bytes = witness.read_small(SEMANTIC_CONTEXT_FILE)?;
    let context = SemanticV3GovernedContext::decode(&context_bytes)
        .map_err(|error| debug_error("semantic_context", error))?;
    require_same_profile(&layout, &context)?;
    let verified_prefix = verify_semantic_v3_prefix(&semantic_prefix, &context)
        .map_err(|error| debug_error("semantic_prefix", error))?;

    let transcript_component = component_body(&envelope, &parsed, transcript_index, "transcript")?;
    verify_composite_transcript_component(&mut Cursor::new(envelope.as_slice()), &layout, &parsed)
        .map_err(|error| debug_error("composite_transcript", error))?;
    let parent_bundle = transcript_payload(transcript_component)?.to_vec();
    let decoded_parent_bundle = decode_chained_public_coin_bundle(&parent_bundle)
        .map_err(|error| debug_error("parent_bundle", error))?;
    let pre_alpha_bytes = decoded_parent_bundle
        .rounds
        .first()
        .ok_or_else(|| RealAuthorityError::Encoding("parent_round_900_missing".to_owned()))?
        .prover_message
        .as_slice();
    let pre_alpha = CompositeParentPreAlphaMessage::decode(pre_alpha_bytes)
        .map_err(|error| debug_error("parent_pre_alpha", error))?;
    let parent_prefix =
        verify_composite_parent_prefix(&parent_bundle, &pre_alpha, &verified_prefix)
            .map_err(|error| debug_error("parent_prefix", error))?;

    let anchor_bytes = witness.read_small(SEMANTIC_PARENT_ANCHOR_FILE)?;
    let anchor = SemanticV3ParentAnchorFrame::decode(&anchor_bytes)
        .map_err(|error| debug_error("semantic_parent_anchor", error))?;
    let continuation_bytes = witness.read_small(SEMANTIC_CONTINUATION_FILE)?;
    let semantic_key_bytes = witness.read_key(SEMANTIC_KEY_FILE)?;
    let semantic_key = StrictPqGovernedVerifierKeyV2::decode(&semantic_key_bytes)
        .map_err(|error| debug_error("semantic_key", error))?;
    let semantic_strict_bundle =
        witness.read_named(SEMANTIC_STRICT_BUNDLE_FILE, MAX_SMALL_ARTIFACT_BYTES)?;
    let strict_messages =
        semantic_v3_strict_prover_messages(&semantic_prefix, &parent_bundle, &continuation_bytes)
            .map_err(|error| debug_error("semantic_strict_messages", error))?;
    let mut root_use_registry = StrictPqRootUseRegistryV2::new();
    let strict = verify_strict_semantic_v3_public_coin(
        &semantic_strict_bundle,
        &semantic_key,
        &strict_messages,
        &context,
        &mut root_use_registry,
    )
    .map_err(|error| debug_error("semantic_strict_replay", error))?;
    let continuation = verify_semantic_v3_parent_frame_and_continuation_with_strict(
        &anchor,
        &parent_prefix,
        &strict,
        &continuation_bytes,
        context.geometry,
    )
    .map_err(|error| debug_error("semantic_continuation", error))?;

    let program = witness.read_named(SEMANTIC_PROGRAM_FILE, REAL_AUTHORITY_MAX_ARTIFACT_BYTES)?;
    let fri_parameters = decode_semantic_fri_parameters_v3(
        &witness.read_named(SEMANTIC_FRI_PARAMETERS_FILE, MAX_FRI_PARAMETERS_BYTES)?,
    )?;
    let native_layouts = derive_binding_oracle_commitment_layouts_v2(
        &program,
        fri_parameters.mask_coefficient_count,
        fri_parameters.log_blowup,
    )
    .map_err(|error| debug_error("native_oracle_layouts", error))?;
    let native_claims_commitment = deep_claims_commitment_binding_v2(
        &native_layouts.program_binary_commitment,
        strict.oods_point(),
        &fri_parameters.claims,
        &fri_parameters.oracle_roots.main_trace,
        fri_parameters.oracle_roots.interaction_trace.as_ref(),
        &fri_parameters.oracle_roots.composition,
    )
    .map_err(|error| debug_error("native_claims_commitment", error))?;
    let expected_main_message =
        semantic_v3_native_main_root_message(&fri_parameters.oracle_roots.main_trace);
    let interaction_root = fri_parameters
        .oracle_roots
        .interaction_trace
        .as_ref()
        .ok_or_else(|| RealAuthorityError::Native("native_interaction_root_missing".to_owned()))?;
    let expected_interaction_message =
        semantic_v3_native_interaction_root_message(interaction_root);
    let expected_composition_message =
        semantic_v3_native_composition_root_message(&fri_parameters.oracle_roots.composition);
    let expected_batch_message =
        semantic_v3_native_batch_message(&native_claims_commitment, &fri_parameters.mask_root);
    let expected_batch_derivation_message = semantic_v3_native_batch_derivation_message(
        &fri_parameters.oracle_roots.main_trace,
        interaction_root,
        &fri_parameters.oracle_roots.composition,
        &native_claims_commitment,
        &fri_parameters.mask_root,
        strict.fri_batch_coefficient(),
    );
    let fold_start = 6_usize;
    if strict_messages.first().map(Vec::as_slice) != Some(expected_main_message.as_slice())
        || strict_messages.get(1).map(Vec::as_slice)
            != Some(expected_interaction_message.as_slice())
        || pre_alpha.semantic_composition_root != expected_composition_message
        || strict_messages.get(4).map(Vec::as_slice) != Some(expected_batch_message.as_slice())
        || strict_messages.get(5).map(Vec::as_slice)
            != Some(expected_batch_derivation_message.as_slice())
        || strict_messages.len() < fold_start + fri_parameters.layer_roots.len() + 2
    {
        return Err(RealAuthorityError::Native(
            "semantic_native_commitment_messages".to_owned(),
        ));
    }
    for (ordinal, root) in fri_parameters.layer_roots.iter().enumerate() {
        let expected = semantic_v3_native_fri_layer_message(ordinal, root)
            .map_err(|error| debug_error("native_fri_layer_message", error))?;
        if strict_messages.get(fold_start + ordinal).map(Vec::as_slice) != Some(expected.as_slice())
        {
            return Err(RealAuthorityError::Native(
                "semantic_native_fri_layer_message".to_owned(),
            ));
        }
    }
    let fri_geometry = derive_fri_pipeline_proof_v3_geometry(
        &program,
        fri_parameters.mask_coefficient_count,
        fri_parameters.log_blowup,
        strict.oods_point(),
        &fri_parameters.claims,
        &fri_parameters.oracle_roots,
        strict.query_positions(),
    )
    .map_err(|error| debug_error("fri_geometry", error))?;
    let fri_proof_bytes =
        witness.read_named(SEMANTIC_FRI_PROOF_FILE, REAL_AUTHORITY_MAX_ARTIFACT_BYTES)?;
    let fri_proof: FriPipelineProofV3 =
        decode_fri_pipeline_proof_v3(&fri_proof_bytes, &fri_geometry, strict.query_positions())
            .map_err(|error| debug_error("fri_proof", error))?;
    let (logup_beta, logup_gamma) = strict.logup_challenges();
    let semantic = verify_fri_pipeline_v3_receipt(
        &fri_proof,
        &program,
        fri_parameters.mask_coefficient_count,
        fri_parameters.log_blowup,
        &fri_parameters.public_inputs,
        strict.composition_alpha(),
        logup_beta,
        logup_gamma,
        &fri_parameters.oracle_roots,
        &fri_parameters.mask_root,
        strict.oods_point(),
        &fri_parameters.claims,
        strict.fri_batch_coefficient(),
        strict.fri_fold_coefficients(),
        &fri_parameters.layer_roots,
        fri_parameters.final_constant,
        strict.query_positions(),
    )
    .map_err(|error| debug_error("fri_replay", error))?;
    let post_z_context = semantic_h4_post_z_context_v3(&strict, &semantic)
        .map_err(|error| debug_error("post_z_context", error))?;

    let h4_key_bytes = witness.read_key(H4_KEY_FILE)?;
    let h4_key = decode_h4_verification_key_v2(&h4_key_bytes)
        .map_err(|error| debug_error("h4_key", error))?;
    if h4_profile_code(h4_key.profile()) != layout.profile_code {
        return Err(RealAuthorityError::Native("h4_key_profile".to_owned()));
    }
    let h4 = verify_h4_component_from_v3_envelope(
        &mut Cursor::new(envelope.as_slice()),
        &layout,
        &parsed,
        &h4_key,
        &mut root_use_registry,
    )
    .map_err(|error| debug_error("h4_pre_alpha", error))?;
    if h4.profile() != h4_key.profile() {
        return Err(RealAuthorityError::Native(
            "h4_pre_alpha_profile".to_owned(),
        ));
    }

    let h4_gkr_key = StrictPqGovernedVerifierKeyV2::decode(&witness.read_key(H4_GKR_KEY_FILE)?)
        .map_err(|error| debug_error("h4_gkr_key", error))?;
    if u16::from(h4_gkr_key.attempt()) != h4_key.attempt() {
        return Err(RealAuthorityError::Native(
            "h4_gkr_key_attempt_mismatch".to_owned(),
        ));
    }
    let h4_post_z_keys = (0..shard_count)
        .map(|shard| {
            StrictPqGovernedVerifierKeyV2::decode(&witness.read_post_z_key(shard)?)
                .map_err(|error| debug_error("h4_post_z_key", error))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if h4_post_z_keys
        .iter()
        .any(|key| u16::from(key.attempt()) != h4_key.attempt())
    {
        return Err(RealAuthorityError::Native(
            "h4_post_z_key_attempt_mismatch".to_owned(),
        ));
    }

    let gkr_proof_bytes = witness.read_small(H4_GKR_PROOF_FILE)?;
    let gkr_proof: PublicMaskedSemanticH4BridgeGkrProof =
        decode_public_masked_semantic_h4_bridge_gkr(&gkr_proof_bytes)
            .map_err(|error| debug_error("h4_gkr_proof", error))?;
    let supplied_context = BindingDigestV2::decode(&witness.read_small(H4_GKR_CONTEXT_FILE)?)
        .map_err(|error| debug_error("h4_gkr_context", error))?;
    if supplied_context != post_z_context {
        return Err(RealAuthorityError::Native(
            "h4_gkr_context_not_derived_post_z_context".to_owned(),
        ));
    }
    let first_ordinal = exact_u32_file(
        &witness.read_small(H4_GKR_FIRST_ORDINAL_FILE)?,
        H4_GKR_FIRST_ORDINAL_FILE,
    )?;
    if gkr_proof.profile != semantic_bridge_profile(h4_key.profile()) {
        return Err(RealAuthorityError::Native("h4_gkr_profile".to_owned()));
    }
    let h4_gkr_bundle = witness.read_named(H4_GKR_STRICT_BUNDLE_FILE, MAX_SMALL_ARTIFACT_BYTES)?;
    let strict_gkr = verify_strict_semantic_h4_bridge_gkr(
        &h4_gkr_bundle,
        &h4_gkr_key,
        &gkr_proof,
        post_z_context,
        first_ordinal,
        &mut root_use_registry,
    )
    .map_err(|error| debug_error("h4_gkr_replay", error))?;
    let claim_vector_binding =
        crate::semantic_h4_bridge_gkr::semantic_h4_bridge_claim_vector_commitment(
            strict_gkr.verified_gkr(),
        )
        .map_err(|error| debug_error("h4_claim_vector", error))?;

    let mut response_bytes = Vec::with_capacity(shard_count);
    let mut strict_response_registry = root_use_registry.clone();
    let mut claim_challenge = None;
    for shard in 0..shard_count {
        let encoded_response =
            witness.read_shard(shard, "response.bin", MAX_POST_Z_RESPONSE_BYTES)?;
        let response = decode_h4_bridge_source_response_v2(&encoded_response)
            .map_err(|error| debug_error("h4_post_z_response", error))?;
        let strict_response = verify_strict_h4_bridge_source_response_v2(
            &witness.read_shard(shard, "strict-bundle.bin", MAX_SMALL_ARTIFACT_BYTES)?,
            &h4_post_z_keys[shard],
            h4_key.profile(),
            &response,
            post_z_context,
            claim_vector_binding,
            exact_u32_file(
                &witness.read_shard(shard, "first-ordinal.bin", MAX_SMALL_ARTIFACT_BYTES)?,
                "h4_post_z_first_ordinal",
            )?,
            &mut strict_response_registry,
        )
        .map_err(|error| debug_error("h4_post_z_strict_replay", error))?;
        if let Some(expected) = claim_challenge {
            if expected != strict_response.claim_challenge() {
                return Err(RealAuthorityError::Native(
                    "h4_post_z_claim_challenge_mismatch".to_owned(),
                ));
            }
        } else {
            claim_challenge = Some(strict_response.claim_challenge());
        }
        response_bytes.push(encoded_response);
    }
    let claim_challenge = claim_challenge.ok_or_else(|| {
        RealAuthorityError::Native("h4_post_z_claim_challenge_missing".to_owned())
    })?;

    let functional_inputs = decode_functional_inputs(
        &witness.read_named(H4_FUNCTIONAL_INPUTS_FILE, MAX_FUNCTIONAL_INPUT_BYTES)?,
    )?;
    let semantic_batch = verify_semantic_bridge_source_batch_from_program_v3(
        strict_gkr.verified_gkr(),
        &program,
        fri_parameters.mask_coefficient_count,
        fri_parameters.log_blowup,
        &semantic,
        &functional_inputs,
        claim_challenge,
    )
    .map_err(|error| debug_error("semantic_bridge_batch", error))?;
    let mask_input =
        decode_mask_input(&witness.read_named(H4_MASK_INPUT_FILE, MAX_MASK_INPUT_BYTES)?)?;
    if mask_input.expected_context != post_z_context {
        return Err(RealAuthorityError::Native(
            "h4_mask_context_not_derived_post_z_context".to_owned(),
        ));
    }
    let strict_bundle_bytes = (0..shard_count)
        .map(|shard| witness.read_shard(shard, "strict-bundle.bin", MAX_SMALL_ARTIFACT_BYTES))
        .collect::<Result<Vec<_>, _>>()?;
    let first_ordinals = (0..shard_count)
        .map(|shard| {
            exact_u32_file(
                &witness.read_shard(shard, "first-ordinal.bin", MAX_SMALL_ARTIFACT_BYTES)?,
                "h4_post_z_first_ordinal",
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let source_segments = (0..shard_count)
        .map(|shard| witness.read_shard(shard, "source-segment.bin", MAX_POST_Z_SEGMENT_BYTES))
        .collect::<Result<Vec<_>, _>>()?;
    let base_segments = (0..shard_count)
        .map(|shard| witness.read_shard(shard, "base-segment.bin", MAX_POST_Z_SEGMENT_BYTES))
        .collect::<Result<Vec<_>, _>>()?;
    let post_z_inputs = (0..shard_count)
        .map(|shard| H4PostZResponseInput {
            encoded_strict_bundle: &strict_bundle_bytes[shard],
            encoded_response: &response_bytes[shard],
            first_ordinal: first_ordinals[shard],
            source_segment: &source_segments[shard],
            base_segment: &base_segments[shard],
        })
        .collect::<Vec<_>>();
    let governed_post_z_keys = h4_post_z_keys.iter().collect::<Vec<_>>();
    let prepared_h4 = prepare_h4_v2_from_serialized_post_z_with_keys(
        h4,
        &strict_gkr,
        &semantic_batch,
        post_z_context,
        &governed_post_z_keys,
        &post_z_inputs,
        &root_use_registry,
    )
    .map_err(|error| debug_error("h4_post_z_prepare", error))?;
    let mask_coins = derive_h4_source_mask_coins_v3(&prepared_h4)
        .map_err(|error| debug_error("h4_mask_coin", error))?;
    if mask_input.batch_challenge != mask_coins.batch_challenge
        || mask_input.inner_product_challenges != mask_coins.inner_product_challenges
        || mask_input.completion_coin != mask_coins.completion_coin
    {
        return Err(RealAuthorityError::Native(
            "h4_mask_coin_not_verifier_derived".to_owned(),
        ));
    }
    let complete_h4 = prepared_h4
        .complete_and_commit(
            H4SourceMaskProofV2 {
                batch_challenge: mask_input.batch_challenge,
                inner_product_proof: &mask_input.inner_product_proof,
                inner_product_challenges: &mask_input.inner_product_challenges,
                pcs_proof: &mask_input.pcs_proof,
                expected_mask_root: mask_input.expected_mask_root,
                expected_context: mask_input.expected_context,
                completion_coin: mask_input.completion_coin,
            },
            &mut root_use_registry,
        )
        .map_err(|error| debug_error("h4_post_z_completion", error))?;

    let typed: VerifiedTypedStateV3 = verify_typed_state_component_from_v3_envelope(
        &mut Cursor::new(envelope.as_slice()),
        &layout,
        &parsed,
    )
    .map_err(|error| debug_error("typed_state", error))?;
    let receipts = V3AuthorityReceipts {
        strict,
        semantic,
        continuation,
        h4: complete_h4,
        typed,
        parent_prefix,
    };
    let (_accepted_envelope, result): (V3ParsedEnvelope, V3AuthorityRunResult) =
        verify_v3_composite_with_native_receipts(
            &mut Cursor::new(envelope.as_slice()),
            &layout,
            receipts,
        )
        .map_err(|error| debug_error("outer_accepting_verifier", error))?;
    if result.proof_suite_id.is_some() || result.production_usable || result.activation_allowed {
        return Err(RealAuthorityError::Native(
            "nonactivating_lifecycle_invariant".to_owned(),
        ));
    }
    let receipt_evidence = result
        .receipt_evidence()
        .map_err(|error| debug_error("receipt_evidence", error))?;
    let report = format!(
        "format={REAL_AUTHORITY_EVIDENCE_FORMAT}\nstatus=V3_NATIVE_AGGREGATE_ACCEPTED_NONACTIVATING\nprofile_code={}\nproofSuiteId=null\nproduction_usable=false\nactivation_allowed=false\nreal_phi_or_payments=false\n",
        layout.profile_code
    );
    publish_new_files(
        &evidence_dir,
        &[
            ("receipt-evidence.bin", &receipt_evidence),
            ("native-acceptance.txt", report.as_bytes()),
        ],
    )?;
    Ok(RealAuthorityRunReport {
        profile_code: layout.profile_code,
        status: "V3_NATIVE_AGGREGATE_ACCEPTED_NONACTIVATING",
        proof_suite_id: None,
        production_usable: false,
        activation_allowed: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;

    fn test_directory(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "bl-v3-real-authority-{label}-{}",
            std::process::id()
        ))
    }

    #[test]
    fn evidence_publication_is_create_new_and_transactional() {
        let directory = test_directory("publication");
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        publish_new_files(
            &directory,
            &[
                ("one.bin", b"one".as_slice()),
                ("two.bin", b"two".as_slice()),
            ],
        )
        .unwrap();
        assert_eq!(fs::read(directory.join("one.bin")).unwrap(), b"one");
        assert_eq!(fs::read(directory.join("two.bin")).unwrap(), b"two");
        assert!(publish_new_file(&directory, "one.bin", b"replacement").is_err());
        assert!(!directory.join("one.bin.partial").exists());
        let _ = fs::remove_dir_all(&directory);
    }

    #[test]
    fn witness_validation_rejects_missing_inputs_before_replay() {
        let directory = test_directory("missing");
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        let witness = RealWitness::open(&directory).unwrap();
        let error = validate_witness_files(&witness, 1).unwrap_err();
        assert!(matches!(error, RealAuthorityError::Input(_)));
        let _ = fs::remove_dir_all(&directory);
    }

    #[test]
    fn wire_reader_rejects_trailing_bytes() {
        let reader = WireReader::new(&[1, 2, 3], "test", 16).unwrap();
        assert!(reader.finish("test").is_err());
    }

    #[test]
    fn semantic_fri_parameters_roundtrip_is_canonical() {
        let root = |byte| BindingRootV2::decode(&[byte; BINDING_V2_BYTES]).unwrap();
        let parameters = SemanticFriParametersV3 {
            public_inputs: vec![M31::ONE, M31::from_canonical(7).unwrap()],
            mask_coefficient_count: 16,
            log_blowup: 2,
            oracle_roots: crate::oracle_commitment::BindingCommittedAirRootsV2 {
                main_trace: root(1),
                interaction_trace: Some(root(2)),
                composition: root(3),
            },
            mask_root: root(4),
            claims: vec![DomainOodsClaims {
                log_size: 4,
                values: vec![Fp16::ONE],
                conjugate_values: vec![Fp16::ZERO],
            }],
            layer_roots: vec![root(5), root(6)],
            final_constant: Fp16::ONE,
        };
        let encoded = encode_semantic_fri_parameters_v3(&parameters).unwrap();
        assert_eq!(
            decode_semantic_fri_parameters_v3(&encoded).unwrap(),
            parameters
        );
        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode_semantic_fri_parameters_v3(&trailing).is_err());
    }
}
