//! Produce one current H4-v2 aggregate from a captured, already-authenticated
//! witness-material directory.
//!
//! The producer rebuilds every v2 Merkle root from raw bytes and derives every
//! opening index from the supplied query seed. Governed identity/binding
//! fields are explicit inputs; they are never learned from the capture.
//! The output remains unqualified until the native H4 verifier accepts it.
//! This first joined contract is intentionally K128-only.

use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use bl_pq512_crypto_core::binding_root_v2::{
    BINDING_V2_BYTES, BindingDigestV2, BindingMerkleLeafV2, BindingMerkleTreeV2, BindingRoleV2,
    BindingRootV2,
};
use bl_pq512_crypto_core::fp16_zk_rs_gkr_binding::GKR_CLAIM_COUNT;
use bl_pq512_crypto_core::h4_proof_package_v1::{exact_queries, tensor_queries};
use bl_pq512_crypto_core::h4_proof_package_v2::{
    H4_ANSWER_COEFFICIENT_BYTES, H4_AUXILIARY_CODE_VALUES, H4_AUXILIARY_OPENINGS,
    H4_BLSQAB03_BYTES, H4_BLSQCL03_BYTES, H4_GKR_RELATION_TERMINAL_BYTES, H4_GKR_TENSOR_LEAVES,
    H4_GLOBAL_RAW_FRAME_LENGTH_BYTES, H4_GLOBAL_RAW_FRAMES_V2_MAX_BYTES, H4_MAIN_CODE_VALUES,
    H4_MAIN_OPENINGS, H4_PACKED_CLAIMS_BYTES, H4_PROOF_PACKAGE_V2_BYTES,
    H4_PROOF_PACKAGE_V2_HEADER_BYTES, H4_PUBLIC_VIEW_V2_HEADER_BYTES,
    H4_PUBLIC_VIEW_V2_ROOT_INVENTORY_BYTES, H4_RS_MULTIPROOF_V2_MAGIC,
    H4_RS_MULTIPROOF_V2_PREFIX_BYTES, H4_RS_SEGMENT_V2_HEADER_BYTES, H4_SOURCE_LEAF_BYTES,
    H4AggregatePackageV2WriteInput, H4ProofProfileV2, H4RsSegmentDescriptorV2,
    answer_tensor_root_v2, h4_rs_segment_leaf_payload_v2, h4_strict_pq_schedule_v2,
    parse_h4_global_round_frame_v2, verify_h4_rs_segment_v2, write_h4_aggregate_package_v2,
};
use bl_pq512_crypto_core::strict_pq_public_coin_v2::StrictPqGovernedVerifierKeyV2;

const USAGE: &str = "usage: h4_v2_produce K128_CALIBRATION <capture-dir> <profile-identity-hex-64-byte> <program-commitment-hex-64-byte> <statement-binding-hex-128-byte> <state-relation-source-binding-hex-128-byte> <output>";
const SOURCE_LEAF_COUNT: usize = H4_MAIN_CODE_VALUES;
const SUMCHECK_LEAF_BYTES: usize = 19 * 64;
const AUXILIARY_LEAF_COUNT: usize = H4_AUXILIARY_CODE_VALUES;
const TENSOR_LEAF_COUNT: usize = H4_GKR_TENSOR_LEAVES;
const MAIN_LEAF_BYTES: usize = 64;
const SQUAREFREE_KIND: u64 = 68;
const SUMCHECK_KIND: u64 = 64;
const MASK_KIND: u64 = 67;
const MAIN_BASE_KIND: u64 = 65;
const BASE_TENSOR_KIND: u64 = 66;
const SOURCE_KIND: u64 = 32;
const V2_PUBLIC_VIEW_MAGIC: &[u8; 8] = b"BLH4PV02";
const V2_PUBLIC_VIEW_VERSION: u16 = 2;
const V2_SQUAREFREE_CLAIMS_MAGIC: &[u8; 8] = b"BLSQCL03";
const V2_SQUAREFREE_ANSWER_MAGIC: &[u8; 8] = b"BLSQAB03";
const V2_SQUAREFREE_DOMAIN: &[u8] = b"BL/PQ512/WAVE2/STATE-SQUAREFREE-CLAIMS/v2\0";

#[derive(Clone, Debug)]
struct MaterializedSegment {
    root: BindingRootV2,
    encoded: Vec<u8>,
}

fn absolute_regular_file(path: &Path, label: &str) -> Result<File, String> {
    if !path.is_absolute() {
        return Err(format!("{label}_path_not_absolute"));
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("{label}_metadata:{:?}", error.kind()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(format!("{label}_not_regular"));
    }
    File::open(path).map_err(|error| format!("{label}_open:{:?}", error.kind()))
}

fn regular_file_bytes(path: &Path, expected: usize, label: &str) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("{label}_metadata:{:?}", error.kind()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(format!("{label}_not_regular"));
    }
    if metadata.len() != u64::try_from(expected).map_err(|_| format!("{label}_geometry"))? {
        return Err(format!("{label}_length:{}/{}", metadata.len(), expected));
    }
    let bytes = fs::read(path).map_err(|error| format!("{label}_read:{:?}", error.kind()))?;
    if bytes.len() != expected {
        return Err(format!("{label}_changed_during_read"));
    }
    Ok(bytes)
}

fn check_regular_length(path: &Path, expected: u64, label: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("{label}_metadata:{:?}", error.kind()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(format!("{label}_not_regular"));
    }
    if metadata.len() != expected {
        return Err(format!("{label}_length:{}/{}", metadata.len(), expected));
    }
    Ok(())
}

fn parse_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2 || !value.is_ascii() {
        return Err(format!("{label}_hex_length"));
    }
    let mut result = [0_u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0]).ok_or_else(|| format!("{label}_hex"))?;
        let low = hex_nibble(pair[1]).ok_or_else(|| format!("{label}_hex"))?;
        result[index] = high << 4 | low;
    }
    Ok(result)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn binding_from_hex(value: &str, label: &str) -> Result<BindingDigestV2, String> {
    BindingDigestV2::decode(&parse_hex::<BINDING_V2_BYTES>(value, label)?)
        .map_err(|error| format!("{label}_decode:{error:?}"))
}

fn capture_path(capture: &Path, name: &str) -> PathBuf {
    capture.join(name)
}

fn validate_raw_frames(profile: H4ProofProfileV2, raw_frames: &[u8]) -> Result<(), String> {
    let (descriptors, _) = h4_strict_pq_schedule_v2(profile)
        .map_err(|error| format!("raw_frames_schedule:{error:?}"))?;
    let mut offset = 0_usize;
    for descriptor in descriptors {
        let prefix_end = offset
            .checked_add(H4_GLOBAL_RAW_FRAME_LENGTH_BYTES)
            .ok_or_else(|| "raw_frames_offset_overflow".to_owned())?;
        let length_bytes = raw_frames
            .get(offset..prefix_end)
            .ok_or_else(|| format!("raw_frames_truncated_at_{}", descriptor.ordinal()))?;
        let frame_bytes = usize::try_from(u32::from_be_bytes(
            length_bytes
                .try_into()
                .map_err(|_| "raw_frames_length_width".to_owned())?,
        ))
        .map_err(|_| "raw_frames_length_host".to_owned())?;
        offset = prefix_end;
        let frame_end = offset
            .checked_add(frame_bytes)
            .ok_or_else(|| "raw_frames_frame_overflow".to_owned())?;
        let frame = raw_frames
            .get(offset..frame_end)
            .ok_or_else(|| format!("raw_frames_truncated_at_{}", descriptor.ordinal()))?;
        if frame.len() >= 16 && frame.get(..8) == Some(b"BLH4GR02") {
            let observed_profile = frame[8];
            let observed_shard_count = frame[9];
            let observed_kind = u16::from_be_bytes(
                frame[10..12]
                    .try_into()
                    .map_err(|_| "raw_frames_header_kind_width".to_owned())?,
            );
            let observed_ordinal = u32::from_be_bytes(
                frame[12..16]
                    .try_into()
                    .map_err(|_| "raw_frames_header_ordinal_width".to_owned())?,
            );
            if observed_profile != profile.code()
                || observed_shard_count != profile.shard_count()
                || observed_kind != descriptor.kind()
                || observed_ordinal != descriptor.ordinal()
            {
                return Err(format!(
                    "raw_frames_descriptor_mismatch:expected_profile={} expected_shards={} expected_kind={} expected_ordinal={} observed_profile={} observed_shards={} observed_kind={} observed_ordinal={}",
                    profile.code(),
                    profile.shard_count(),
                    descriptor.kind(),
                    descriptor.ordinal(),
                    observed_profile,
                    observed_shard_count,
                    observed_kind,
                    observed_ordinal,
                ));
            }
        }
        parse_h4_global_round_frame_v2(frame, profile, descriptor)
            .map_err(|error| format!("raw_frames_frame_{}:{error:?}", descriptor.ordinal()))?;
        offset = frame_end;
    }
    if offset != raw_frames.len() {
        return Err(format!(
            "raw_frames_trailing:{}/{}",
            raw_frames.len() - offset,
            profile.transcript_rounds()
        ));
    }
    Ok(())
}

fn make_segment(
    descriptor: H4RsSegmentDescriptorV2,
    indices: &[usize],
    mut leaf: impl FnMut(usize, &mut Vec<u8>) -> Result<(), String>,
) -> Result<MaterializedSegment, String> {
    if indices.is_empty() || indices.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("query_indices_not_canonical".to_owned());
    }
    let leaf_count = usize::try_from(descriptor.leaf_count).map_err(|_| "leaf_count_host")?;
    let leaf_bytes = usize::try_from(descriptor.leaf_bytes).map_err(|_| "leaf_bytes_host")?;
    let mut payload = vec![0_u8; leaf_bytes];
    let mut digests = Vec::with_capacity(leaf_count);
    for index in 0..leaf_count {
        leaf(index, &mut payload)?;
        let framed = h4_rs_segment_leaf_payload_v2(descriptor, &payload)
            .map_err(|error| format!("leaf_frame:{error:?}"))?;
        digests.push(
            BindingMerkleLeafV2::hash(index as u64, &framed)
                .map_err(|error| format!("leaf_hash:{error:?}"))?
                .digest(),
        );
    }
    let tree = BindingMerkleTreeV2::from_leaf_digests(digests)
        .map_err(|error| format!("tree:{error:?}"))?;
    let proof = tree
        .prove(
            &indices
                .iter()
                .copied()
                .map(|index| index as u64)
                .collect::<Vec<_>>(),
        )
        .map_err(|error| format!("proof:{error:?}"))?;
    let data_bytes = descriptor
        .leaf_count
        .checked_mul(descriptor.leaf_bytes)
        .ok_or_else(|| "segment_data_overflow".to_owned())?;
    if descriptor.data_bytes != data_bytes {
        return Err("segment_data_geometry".to_owned());
    }
    let mut encoded = Vec::with_capacity(
        H4_RS_SEGMENT_V2_HEADER_BYTES
            + indices.len() * 4
            + indices.len() * leaf_bytes
            + proof.frontier_digests().len() * BINDING_V2_BYTES,
    );
    encoded.extend_from_slice(&descriptor.boundary.to_be_bytes());
    encoded.extend_from_slice(&descriptor.kind.to_be_bytes());
    encoded.extend_from_slice(&descriptor.data_bytes.to_be_bytes());
    encoded.extend_from_slice(&descriptor.leaf_count.to_be_bytes());
    encoded.extend_from_slice(&descriptor.leaf_bytes.to_be_bytes());
    encoded.extend_from_slice(
        &u32::try_from(indices.len())
            .map_err(|_| "opening_count_width".to_owned())?
            .to_be_bytes(),
    );
    encoded.extend_from_slice(
        &u32::try_from(proof.frontier_digests().len())
            .map_err(|_| "frontier_count_width".to_owned())?
            .to_be_bytes(),
    );
    encoded.extend_from_slice(tree.root().as_bytes());
    for index in indices {
        encoded.extend_from_slice(
            &u32::try_from(*index)
                .map_err(|_| "opening_index_width".to_owned())?
                .to_be_bytes(),
        );
    }
    for index in indices {
        leaf(*index, &mut payload)?;
        encoded.extend_from_slice(&payload);
    }
    for digest in proof.frontier_digests() {
        encoded.extend_from_slice(digest.as_bytes());
    }
    Ok(MaterializedSegment {
        root: tree.root(),
        encoded,
    })
}

fn single_segment(
    path: &Path,
    descriptor: H4RsSegmentDescriptorV2,
    indices: &[usize],
    label: &str,
) -> Result<MaterializedSegment, String> {
    let expected = descriptor
        .leaf_count
        .checked_mul(descriptor.leaf_bytes)
        .ok_or_else(|| format!("{label}_geometry"))?;
    check_regular_length(path, expected, label)?;
    let mut file = absolute_regular_file(path, label)?;
    let leaf_bytes = usize::try_from(descriptor.leaf_bytes).map_err(|_| format!("{label}_host"))?;
    make_segment(descriptor, indices, |index, payload| {
        file.seek(SeekFrom::Start(
            u64::try_from(index)
                .map_err(|_| format!("{label}_index"))?
                .checked_mul(descriptor.leaf_bytes)
                .ok_or_else(|| format!("{label}_seek"))?,
        ))
        .map_err(|error| format!("{label}_seek:{:?}", error.kind()))?;
        if payload.len() != leaf_bytes {
            return Err(format!("{label}_payload"));
        }
        file.read_exact(payload)
            .map_err(|error| format!("{label}_read:{:?}", error.kind()))
    })
}

fn captured_segment(
    path: &Path,
    descriptor: H4RsSegmentDescriptorV2,
    indices: &[usize],
    label: &str,
) -> Result<MaterializedSegment, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("{label}_metadata:{:?}", error.kind()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 128 << 20 {
        return Err(format!("{label}_not_bounded_regular"));
    }
    let encoded = fs::read(path).map_err(|error| format!("{label}_read:{:?}", error.kind()))?;
    if encoded.len() < H4_RS_SEGMENT_V2_HEADER_BYTES {
        return Err(format!("{label}_length"));
    }
    let root = BindingRootV2::decode(&encoded[48..H4_RS_SEGMENT_V2_HEADER_BYTES])
        .map_err(|error| format!("{label}_root:{error:?}"))?;
    let expected_indices = indices
        .iter()
        .map(|index| u32::try_from(*index).map_err(|_| format!("{label}_index")))
        .collect::<Result<Vec<_>, _>>()?;
    verify_h4_rs_segment_v2(&encoded, descriptor, &expected_indices, root)
        .map_err(|error| format!("{label}_verify:{error:?}"))?;
    Ok(MaterializedSegment { root, encoded })
}

fn encode_squarefree_v2(
    old_answer: &[u8],
    squarefree_root: BindingRootV2,
    capacity: u16,
) -> Result<Vec<u8>, String> {
    if old_answer.len() != 1_828 || old_answer.get(..8) != Some(b"BLSQAB02") {
        return Err("squarefree_answer_shape".to_owned());
    }
    if old_answer.get(8..16) != Some(b"BLSQCL02") {
        return Err("squarefree_claims_magic".to_owned());
    }
    let phase_bytes = old_answer
        .get(148..1_700)
        .ok_or_else(|| "squarefree_phase_shape".to_owned())?;
    let terminal_bytes = old_answer
        .get(1_700..)
        .ok_or_else(|| "squarefree_terminal_shape".to_owned())?;
    let mut digest_preimage =
        Vec::with_capacity(V2_SQUAREFREE_DOMAIN.len() + BINDING_V2_BYTES + 4 + phase_bytes.len());
    digest_preimage.extend_from_slice(V2_SQUAREFREE_DOMAIN);
    digest_preimage.extend_from_slice(squarefree_root.as_bytes());
    digest_preimage.extend_from_slice(&capacity.to_be_bytes());
    digest_preimage.extend_from_slice(&2_u16.to_be_bytes());
    digest_preimage.extend_from_slice(phase_bytes);
    let claims_digest = BindingDigestV2::hash(BindingRoleV2::Payload, &digest_preimage)
        .map_err(|error| format!("squarefree_digest:{error:?}"))?;
    let mut claims = Vec::with_capacity(H4_BLSQCL03_BYTES);
    claims.extend_from_slice(V2_SQUAREFREE_CLAIMS_MAGIC);
    claims.extend_from_slice(squarefree_root.as_bytes());
    claims.extend_from_slice(&capacity.to_be_bytes());
    claims.extend_from_slice(&2_u16.to_be_bytes());
    claims.extend_from_slice(claims_digest.as_bytes());
    if claims.len() != H4_BLSQCL03_BYTES {
        return Err("squarefree_claims_length".to_owned());
    }
    let mut answer = Vec::with_capacity(H4_BLSQAB03_BYTES);
    answer.extend_from_slice(V2_SQUAREFREE_ANSWER_MAGIC);
    answer.extend_from_slice(&claims);
    answer.extend_from_slice(phase_bytes);
    answer.extend_from_slice(terminal_bytes);
    if answer.len() != H4_BLSQAB03_BYTES {
        return Err("squarefree_answer_length".to_owned());
    }
    Ok(answer)
}

fn encode_multiproof(
    query_seed: [u8; 64],
    segments: &[MaterializedSegment],
) -> Result<Vec<u8>, String> {
    if segments.len() != 6 {
        return Err("multiproof_segment_count".to_owned());
    }
    let mut encoded = Vec::with_capacity(
        H4_RS_MULTIPROOF_V2_PREFIX_BYTES
            + segments
                .iter()
                .map(|segment| segment.encoded.len())
                .sum::<usize>(),
    );
    encoded.extend_from_slice(H4_RS_MULTIPROOF_V2_MAGIC);
    encoded.extend_from_slice(&(segments.len() as u32).to_be_bytes());
    encoded.extend_from_slice(&query_seed);
    for segment in segments {
        encoded.extend_from_slice(&segment.encoded);
    }
    if encoded.len() > 60_706_700 {
        return Err("multiproof_size_cap".to_owned());
    }
    Ok(encoded)
}

fn encode_public_view(
    roots: [BindingRootV2; 5],
    packed_claims: &[u8],
    relation_terminals: &[u8],
    multiproof: &[u8],
) -> Result<Vec<u8>, String> {
    if packed_claims.len() != H4_PACKED_CLAIMS_BYTES
        || relation_terminals.len() != H4_GKR_RELATION_TERMINAL_BYTES
        || multiproof.len() < H4_RS_MULTIPROOF_V2_PREFIX_BYTES
    {
        return Err("public_view_sections".to_owned());
    }
    let total = H4_PUBLIC_VIEW_V2_HEADER_BYTES
        .checked_add(H4_PUBLIC_VIEW_V2_ROOT_INVENTORY_BYTES)
        .and_then(|value| value.checked_add(packed_claims.len()))
        .and_then(|value| value.checked_add(relation_terminals.len()))
        .and_then(|value| value.checked_add(multiproof.len()))
        .ok_or_else(|| "public_view_overflow".to_owned())?;
    let mut encoded = Vec::with_capacity(total);
    encoded.extend_from_slice(V2_PUBLIC_VIEW_MAGIC);
    encoded.extend_from_slice(&V2_PUBLIC_VIEW_VERSION.to_be_bytes());
    encoded.extend_from_slice(&0_u16.to_be_bytes());
    encoded.extend_from_slice(&(GKR_CLAIM_COUNT as u16).to_be_bytes());
    encoded.extend_from_slice(&((H4_GKR_RELATION_TERMINAL_BYTES / 64) as u16).to_be_bytes());
    encoded.extend_from_slice(&(packed_claims.len() as u32).to_be_bytes());
    encoded.extend_from_slice(&(relation_terminals.len() as u32).to_be_bytes());
    encoded.extend_from_slice(&(multiproof.len() as u64).to_be_bytes());
    for root in roots {
        encoded.extend_from_slice(root.as_bytes());
    }
    encoded.extend_from_slice(packed_claims);
    encoded.extend_from_slice(relation_terminals);
    encoded.extend_from_slice(multiproof);
    if encoded.len() != total {
        return Err("public_view_length".to_owned());
    }
    Ok(encoded)
}

fn encode_shard(
    profile_identity: [u8; 64],
    program_commitment: [u8; 64],
    schedule_commitment: [u8; 64],
    session_id: [u8; 64],
    public_view: &[u8],
    answer_coefficients: &[u8],
    squarefree_answer: &[u8],
    source_root: BindingRootV2,
    mask_root: BindingRootV2,
    base_root: BindingRootV2,
) -> Result<Vec<u8>, String> {
    if answer_coefficients.len() != H4_ANSWER_COEFFICIENT_BYTES
        || squarefree_answer.len() != H4_BLSQAB03_BYTES
    {
        return Err("shard_sections".to_owned());
    }
    let compact = H4_PROOF_PACKAGE_V2_HEADER_BYTES
        .checked_add(public_view.len())
        .and_then(|value| value.checked_add(answer_coefficients.len()))
        .and_then(|value| value.checked_add(squarefree_answer.len()))
        .ok_or_else(|| "shard_overflow".to_owned())?;
    if compact >= H4_PROOF_PACKAGE_V2_BYTES {
        return Err("shard_compact_size".to_owned());
    }
    let mut encoded = vec![0_u8; H4_PROOF_PACKAGE_V2_BYTES];
    encoded[..8].copy_from_slice(b"BLH4PK02");
    encoded[8..10].copy_from_slice(&2_u16.to_be_bytes());
    encoded[10] = H4ProofProfileV2::K128.code();
    encoded[11] = 0;
    encoded[12] = 1;
    encoded[16..24].copy_from_slice(&(compact as u64).to_be_bytes());
    encoded[24..32].copy_from_slice(&0_u64.to_be_bytes());
    encoded[32..40].copy_from_slice(&(public_view.len() as u64).to_be_bytes());
    encoded[40..48].copy_from_slice(&(answer_coefficients.len() as u64).to_be_bytes());
    encoded[48..52].copy_from_slice(&(squarefree_answer.len() as u32).to_be_bytes());
    encoded[52..54].copy_from_slice(&0_u16.to_be_bytes());
    encoded[128..192].copy_from_slice(&profile_identity);
    encoded[192..256].copy_from_slice(&program_commitment);
    encoded[256..320].copy_from_slice(&schedule_commitment);
    encoded[320..384].copy_from_slice(&session_id);
    encoded[384..512].copy_from_slice(source_root.as_bytes());
    encoded[512..640].copy_from_slice(mask_root.as_bytes());
    encoded[640..768].copy_from_slice(base_root.as_bytes());
    let mut offset = H4_PROOF_PACKAGE_V2_HEADER_BYTES;
    encoded[offset..offset + public_view.len()].copy_from_slice(public_view);
    offset += public_view.len();
    encoded[offset..offset + answer_coefficients.len()].copy_from_slice(answer_coefficients);
    offset += answer_coefficients.len();
    encoded[offset..offset + squarefree_answer.len()].copy_from_slice(squarefree_answer);
    Ok(encoded)
}

fn run(args: &[std::ffi::OsString]) -> Result<(), String> {
    if args.len() != 8 {
        return Err(USAGE.to_owned());
    }
    if args[1].to_str() != Some("K128_CALIBRATION") {
        return Err("profile_not_supported_by_current_capture_contract".to_owned());
    }
    let profile = H4ProofProfileV2::K128;
    let capture = PathBuf::from(&args[2]);
    if !capture.is_absolute() {
        return Err("capture_path_not_absolute".to_owned());
    }
    let profile_identity = parse_hex::<64>(
        args[3].to_str().ok_or("profile_identity_utf8")?,
        "profile_identity",
    )?;
    let program_commitment = parse_hex::<64>(
        args[4].to_str().ok_or("program_commitment_utf8")?,
        "program_commitment",
    )?;
    let statement_binding = binding_from_hex(
        args[5].to_str().ok_or("statement_binding_utf8")?,
        "statement_binding",
    )?;
    let state_relation_source_binding = binding_from_hex(
        args[6]
            .to_str()
            .ok_or("state_relation_source_binding_utf8")?,
        "state_relation_source_binding",
    )?;
    let output = PathBuf::from(&args[7]);
    if !output.is_absolute() {
        return Err("output_path_not_absolute".to_owned());
    }
    if output.exists() || output.is_symlink() {
        return Err("output_exists".to_owned());
    }

    let query_seed: [u8; 64] =
        regular_file_bytes(&capture_path(&capture, "query-seed.bin"), 64, "query_seed")?
            .try_into()
            .map_err(|_| "query_seed_shape")?;
    let main_queries = exact_queries(
        &query_seed,
        b"main_queries",
        H4_MAIN_CODE_VALUES,
        H4_MAIN_OPENINGS,
    )
    .map_err(|_| "main_queries")?;
    let auxiliary_queries = exact_queries(
        &query_seed,
        b"aux_queries",
        H4_AUXILIARY_CODE_VALUES,
        H4_AUXILIARY_OPENINGS,
    )
    .map_err(|_| "auxiliary_queries")?;
    let tensor_query_indices =
        tensor_queries(&query_seed, &auxiliary_queries).map_err(|_| "tensor_queries")?;

    let raw_path = capture_path(&capture, "raw-frames.bin");
    let raw_length = fs::metadata(&raw_path)
        .map_err(|error| format!("raw_frames_metadata:{:?}", error.kind()))?
        .len() as usize;
    let raw_frames = regular_file_bytes(&raw_path, raw_length, "raw_frames")?;
    if raw_frames.len() > H4_GLOBAL_RAW_FRAMES_V2_MAX_BYTES {
        return Err("raw_frames_size_cap".to_owned());
    }
    validate_raw_frames(profile, &raw_frames)?;

    let source = captured_segment(
        &capture_path(&capture, "source-segment-v2.bin"),
        H4RsSegmentDescriptorV2 {
            boundary: 3,
            kind: SOURCE_KIND,
            data_bytes: (SOURCE_LEAF_COUNT * H4_SOURCE_LEAF_BYTES) as u64,
            leaf_count: SOURCE_LEAF_COUNT as u64,
            leaf_bytes: H4_SOURCE_LEAF_BYTES as u64,
        },
        &main_queries,
        "source_segment_v2",
    )?;
    let sumcheck = single_segment(
        &capture_path(&capture, "sumcheck.raw"),
        H4RsSegmentDescriptorV2 {
            boundary: 2,
            kind: SUMCHECK_KIND,
            data_bytes: (AUXILIARY_LEAF_COUNT * SUMCHECK_LEAF_BYTES) as u64,
            leaf_count: AUXILIARY_LEAF_COUNT as u64,
            leaf_bytes: SUMCHECK_LEAF_BYTES as u64,
        },
        &auxiliary_queries,
        "sumcheck",
    )?;
    let mask = single_segment(
        &capture_path(&capture, "mask-tensor.raw"),
        H4RsSegmentDescriptorV2 {
            boundary: 2,
            kind: MASK_KIND,
            data_bytes: (TENSOR_LEAF_COUNT * MAIN_LEAF_BYTES) as u64,
            leaf_count: TENSOR_LEAF_COUNT as u64,
            leaf_bytes: MAIN_LEAF_BYTES as u64,
        },
        &tensor_query_indices,
        "mask_tensor",
    )?;
    let main_base = captured_segment(
        &capture_path(&capture, "bridge-base-segment-v2.bin"),
        H4RsSegmentDescriptorV2 {
            boundary: 2,
            kind: MAIN_BASE_KIND,
            data_bytes: (H4_MAIN_CODE_VALUES * MAIN_LEAF_BYTES) as u64,
            leaf_count: H4_MAIN_CODE_VALUES as u64,
            leaf_bytes: MAIN_LEAF_BYTES as u64,
        },
        &main_queries,
        "bridge_base_segment_v2",
    )?;
    let base_tensor = single_segment(
        &capture_path(&capture, "base-tensor.raw"),
        H4RsSegmentDescriptorV2 {
            boundary: 2,
            kind: BASE_TENSOR_KIND,
            data_bytes: (TENSOR_LEAF_COUNT * MAIN_LEAF_BYTES) as u64,
            leaf_count: TENSOR_LEAF_COUNT as u64,
            leaf_bytes: MAIN_LEAF_BYTES as u64,
        },
        &tensor_query_indices,
        "base_tensor",
    )?;
    let squarefree = single_segment(
        &capture_path(&capture, "squarefree.raw"),
        H4RsSegmentDescriptorV2 {
            boundary: 2,
            kind: SQUAREFREE_KIND,
            data_bytes: (AUXILIARY_LEAF_COUNT * MAIN_LEAF_BYTES) as u64,
            leaf_count: AUXILIARY_LEAF_COUNT as u64,
            leaf_bytes: MAIN_LEAF_BYTES as u64,
        },
        &auxiliary_queries,
        "squarefree",
    )?;
    let segments = [
        source.clone(),
        sumcheck,
        mask.clone(),
        main_base,
        base_tensor.clone(),
        squarefree.clone(),
    ];
    let multiproof = encode_multiproof(query_seed, &segments)?;
    let packed_claims = regular_file_bytes(
        &capture_path(&capture, "packed-claims.bin"),
        H4_PACKED_CLAIMS_BYTES,
        "packed_claims",
    )?;
    let relation_terminals = regular_file_bytes(
        &capture_path(&capture, "relation-terminals.bin"),
        H4_GKR_RELATION_TERMINAL_BYTES,
        "relation_terminals",
    )?;
    let answer_coefficients = regular_file_bytes(
        &capture_path(&capture, "answer-coefficients.bin"),
        H4_ANSWER_COEFFICIENT_BYTES,
        "answer_coefficients",
    )?;
    let squarefree_old = regular_file_bytes(
        &capture_path(&capture, "squarefree-answer.bin"),
        1_828,
        "squarefree_answer",
    )?;
    let squarefree_answer = encode_squarefree_v2(
        &squarefree_old,
        squarefree.root,
        profile.state_capacity() as u16,
    )?;
    let answer_root = answer_tensor_root_v2(&answer_coefficients)
        .map_err(|error| format!("answer_tensor_root:{error:?}"))?;
    let public_view = encode_public_view(
        [
            segments[1].root,
            segments[3].root,
            segments[4].root,
            segments[5].root,
            answer_root,
        ],
        &packed_claims,
        &relation_terminals,
        &multiproof,
    )?;

    let session_id: [u8; 64] =
        regular_file_bytes(&capture_path(&capture, "session-id.bin"), 64, "session_id")?
            .try_into()
            .map_err(|_| "session_id_shape")?;
    let schedule_commitment: [u8; 64] = regular_file_bytes(
        &capture_path(&capture, "schedule-commitment.bin"),
        64,
        "schedule_commitment",
    )?
    .try_into()
    .map_err(|_| "schedule_commitment_shape")?;
    let shard = encode_shard(
        profile_identity,
        program_commitment,
        schedule_commitment,
        session_id,
        &public_view,
        &answer_coefficients,
        &squarefree_answer,
        source.root,
        mask.root,
        segments[3].root,
    )?;

    let strict_path = capture_path(&capture, "strict-bundle.bin");
    let strict_length = fs::metadata(&strict_path)
        .map_err(|error| format!("strict_bundle_metadata:{:?}", error.kind()))?
        .len() as usize;
    let strict_bundle = regular_file_bytes(&strict_path, strict_length, "strict_bundle")?;
    let governed_path = capture_path(&capture, "governed-key.bin");
    let governed_length = fs::metadata(&governed_path)
        .map_err(|error| format!("governed_key_metadata:{:?}", error.kind()))?
        .len() as usize;
    let governed_key_bytes = regular_file_bytes(&governed_path, governed_length, "governed_key")?;
    let governed_key = StrictPqGovernedVerifierKeyV2::decode(&governed_key_bytes)
        .map_err(|error| format!("governed_key_decode:{error:?}"))?;
    if governed_key.session_id() != &session_id
        || governed_key.schedule_commitment() != &schedule_commitment
    {
        return Err("governed_key_identity_mismatch".to_owned());
    }
    let governed_key_binding = governed_key
        .binding()
        .map_err(|error| format!("governed_key_binding:{error:?}"))?;
    let shard_bodies: [&[u8]; 1] = [&shard];
    let input = H4AggregatePackageV2WriteInput {
        profile,
        attempt: 0,
        profile_identity,
        program_commitment,
        schedule_commitment,
        session_id,
        governed_key_binding,
        statement_binding,
        state_relation_source_binding,
        strict_bundle: &strict_bundle,
        raw_frames: &raw_frames,
        shard_bodies: &shard_bodies,
    };
    let partial = PathBuf::from(format!("{}.partial", output.display()));
    if partial.exists() {
        return Err("partial_output_exists".to_owned());
    }
    let mut writer = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&partial)
        .map_err(|error| format!("partial_output_open:{:?}", error.kind()))?;
    let aggregate_bytes = match write_h4_aggregate_package_v2(&mut writer, &input) {
        Ok(value) => value,
        Err(error) => {
            drop(writer);
            let _ = fs::remove_file(&partial);
            return Err(format!("aggregate_write:{error:?}"));
        }
    };
    writer
        .sync_all()
        .map_err(|error| format!("partial_output_sync:{:?}", error.kind()))?;
    drop(writer);
    if output.exists() {
        let _ = fs::remove_file(&partial);
        return Err("output_created_during_publish".to_owned());
    }
    fs::rename(&partial, &output).map_err(|error| {
        let _ = fs::remove_file(&partial);
        format!("output_publish:{:?}", error.kind())
    })?;
    println!("status=H4_V2_PRODUCED_UNQUALIFIED");
    println!("profile={}", profile.governed_label());
    println!("aggregate_bytes={aggregate_bytes}");
    println!("source_root={}", hex(source.root.as_bytes()));
    println!("mask_root={}", hex(mask.root.as_bytes()));
    println!("bridge_base_root={}", hex(segments[3].root.as_bytes()));
    println!("answer_tensor_root={}", hex(answer_root.as_bytes()));
    println!("production_usable=false");
    println!("activation_allowed=false");
    Ok(())
}

fn main() -> ExitCode {
    let args = env::args_os().collect::<Vec<_>>();
    if args.len() == 2 && args[1] == "--capabilities" {
        println!("status=H4_V2_PRE_ALPHA_PRODUCER_AVAILABLE");
        println!("profile=K128_CALIBRATION");
        println!("h4_pre_alpha_production=true");
        println!("h4_complete_production=false");
        println!("h4_proof_production=false");
        println!("post_z_completion=false");
        println!("aggregate_verification=false");
        println!("production_usable=false");
        println!("activation_allowed=false");
        return ExitCode::SUCCESS;
    }
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ERR {error}");
            ExitCode::from(2)
        }
    }
}

fn hex(value: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(value.len() * 2);
    for byte in value {
        result.push(char::from(DIGITS[usize::from(byte >> 4)]));
        result.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use bl_pq512_crypto_core::h4_proof_package_v2::encode_h4_global_round_frame_v2;

    fn complete_raw_frames(profile: H4ProofProfileV2) -> Vec<u8> {
        let (descriptors, _) = h4_strict_pq_schedule_v2(profile).unwrap();
        let message = [1_u8];
        let mut encoded = Vec::new();
        for descriptor in descriptors {
            let frame = encode_h4_global_round_frame_v2(profile, descriptor, &[&message]).unwrap();
            encoded.extend_from_slice(&(frame.len() as u32).to_be_bytes());
            encoded.extend_from_slice(&frame);
        }
        encoded
    }

    #[test]
    fn raw_frame_preflight_accepts_complete_governed_schedule() {
        validate_raw_frames(
            H4ProofProfileV2::K128,
            &complete_raw_frames(H4ProofProfileV2::K128),
        )
        .unwrap();
    }

    #[test]
    fn raw_frame_preflight_reports_first_observed_ordinal() {
        let mut encoded = complete_raw_frames(H4ProofProfileV2::K128);
        encoded[16..20].copy_from_slice(&6778_u32.to_be_bytes());
        let error = validate_raw_frames(H4ProofProfileV2::K128, &encoded).unwrap_err();
        assert_eq!(
            error,
            "raw_frames_descriptor_mismatch:expected_profile=1 expected_shards=1 expected_kind=100 expected_ordinal=0 observed_profile=1 observed_shards=1 observed_kind=100 observed_ordinal=6778"
        );
    }
}
