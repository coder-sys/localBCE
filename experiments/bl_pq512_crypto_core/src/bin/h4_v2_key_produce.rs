//! Bind an H4-v2 aggregate to independently supplied governance and verify it
//! before atomically publishing its canonical verification key.

use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use bl_pq512_crypto_core::binding_root_v2::{
    BINDING_V2_BYTES, BindingDigestV2, BindingRoleV2,
};
use bl_pq512_crypto_core::h4_proof_package_v2::{
    H4_AGGREGATE_PACKAGE_V2_HEADER_BYTES, H4AggregatePackageV2VerificationKey,
    H4ProofProfileV2, parse_h4_aggregate_header_v2, verify_h4_pre_alpha_v2,
};
use bl_pq512_crypto_core::h4_verification_key_v2::encode_h4_verification_key_v2;
use bl_pq512_crypto_core::hash_bus_b16_boundary::HashBusB16BoundaryFile;
use bl_pq512_crypto_core::hash_bus_b16_gkr_plan::HashBusB16GkrPlan;
use bl_pq512_crypto_core::strict_pq_public_coin_v2::{
    STRICT_PQ_GOVERNED_KEY_BYTES_V2, StrictPqGovernedVerifierKeyV2,
    StrictPqRootUseRegistryV2,
};

const USAGE: &str = "usage: h4_v2_key_produce <K128_CALIBRATION|K512_CALIBRATION> <boundary> <governed-key> <profile-identity-hex> <program-commitment-hex> <statement-binding-hex> <state-relation-source-binding-hex> <h4-aggregate> <output-key>";

fn profile(value: &str) -> Result<H4ProofProfileV2, String> {
    match value {
        "K128_CALIBRATION" => Ok(H4ProofProfileV2::K128),
        "K512_CALIBRATION" => Ok(H4ProofProfileV2::K512),
        _ => Err("profile_invalid".to_owned()),
    }
}

fn hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    if value.len() != 2 * N || !value.is_ascii() {
        return Err(format!("{label}_hex_length"));
    }
    let mut result = [0_u8; N];
    for (index, slot) in result.iter_mut().enumerate() {
        let high = char::from(value.as_bytes()[2 * index])
            .to_digit(16).ok_or_else(|| format!("{label}_hex"))?;
        let low = char::from(value.as_bytes()[2 * index + 1])
            .to_digit(16).ok_or_else(|| format!("{label}_hex"))?;
        *slot = ((high << 4) | low) as u8;
    }
    Ok(result)
}

fn digest(value: &str, label: &str) -> Result<BindingDigestV2, String> {
    BindingDigestV2::decode(&hex::<BINDING_V2_BYTES>(value, label)?)
        .map_err(|error| format!("{label}:{error:?}"))
}

fn absolute_regular(value: &std::ffi::OsString, label: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(format!("{label}_path_not_absolute"));
    }
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| format!("{label}_metadata:{:?}", error.kind()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(format!("{label}_not_regular"));
    }
    Ok(path)
}

fn argument(args: &[std::ffi::OsString], index: usize, label: &str) -> Result<String, String> {
    args[index].to_str().map(str::to_owned).ok_or_else(|| format!("{label}_utf8"))
}

fn publish(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if path.exists() { return Err("output_exists".to_owned()); }
    let partial = PathBuf::from(format!("{}.partial", path.display()));
    if partial.exists() { return Err("partial_output_exists".to_owned()); }
    let mut writer = OpenOptions::new().write(true).create_new(true).open(&partial)
        .map_err(|error| format!("partial_open:{:?}", error.kind()))?;
    if let Err(error) = writer.write_all(bytes).and_then(|_| writer.sync_all()) {
        drop(writer); let _ = fs::remove_file(&partial);
        return Err(format!("partial_write:{:?}", error.kind()));
    }
    drop(writer);
    fs::rename(&partial, path).map_err(|error| {
        let _ = fs::remove_file(&partial);
        format!("publish:{:?}", error.kind())
    })
}

fn run(args: &[std::ffi::OsString]) -> Result<(), String> {
    if args.len() != 10 { return Err(USAGE.to_owned()); }
    let selected = profile(&argument(args, 1, "profile")?)?;
    let boundary_path = absolute_regular(&args[2], "boundary")?;
    let governed_path = absolute_regular(&args[3], "governed_key")?;
    let profile_identity = hex::<64>(&argument(args, 4, "profile_identity")?, "profile_identity")?;
    let program_commitment = hex::<64>(&argument(args, 5, "program_commitment")?, "program_commitment")?;
    let statement_binding = digest(&argument(args, 6, "statement_binding")?, "statement_binding")?;
    let state_binding = digest(&argument(args, 7, "state_relation_source_binding")?, "state_relation_source_binding")?;
    let aggregate_path = absolute_regular(&args[8], "h4_aggregate")?;
    let output = PathBuf::from(&args[9]);
    if !output.is_absolute() { return Err("output_path_not_absolute".to_owned()); }

    let governed_bytes = fs::read(&governed_path)
        .map_err(|error| format!("governed_key_read:{:?}", error.kind()))?;
    if governed_bytes.len() != STRICT_PQ_GOVERNED_KEY_BYTES_V2 {
        return Err("governed_key_length".to_owned());
    }
    let governed = StrictPqGovernedVerifierKeyV2::decode(&governed_bytes)
        .map_err(|error| format!("governed_key_decode:{error:?}"))?;

    let mut aggregate = File::open(&aggregate_path)
        .map_err(|error| format!("aggregate_open:{:?}", error.kind()))?;
    let aggregate_bytes = aggregate.metadata().map_err(|error| format!("aggregate_metadata:{:?}", error.kind()))?.len();
    let mut header_bytes = [0_u8; H4_AGGREGATE_PACKAGE_V2_HEADER_BYTES];
    aggregate.read_exact(&mut header_bytes).map_err(|error| format!("aggregate_header:{:?}", error.kind()))?;
    let header = parse_h4_aggregate_header_v2(&header_bytes)
        .map_err(|error| format!("aggregate_header:{error:?}"))?;
    if header.profile != selected || header.profile_identity != profile_identity
        || header.program_commitment != program_commitment || header.statement_binding != statement_binding
        || header.state_relation_source_binding != state_binding
        || header.schedule_commitment != *governed.schedule_commitment()
        || header.session_id != *governed.session_id()
        || header.governed_key_binding != governed.binding().map_err(|error| format!("governed_binding:{error:?}"))?
    { return Err("governed_inputs_do_not_match_aggregate".to_owned()); }

    let boundary = HashBusB16BoundaryFile::open(&boundary_path)
        .map_err(|error| format!("boundary:{error:?}"))?;
    if boundary.header().profile as u8 != selected.code()
        || boundary.header().coprocessor_shards != u16::from(selected.shard_count())
    { return Err("boundary_profile_mismatch".to_owned()); }
    let plan = HashBusB16GkrPlan::selected().and_then(|value| value.commitment())
        .map_err(|error| format!("gkr_plan:{error:?}"))?;
    let zero = BindingDigestV2::decode(&[0_u8; BINDING_V2_BYTES])
        .map_err(|error| format!("zero_binding:{error:?}"))?;
    let mut gkr = [zero; 4];
    for shard in 0..selected.shard_count() {
        let raw = boundary.header().gkr_statement_binding(u16::from(shard), plan)
            .map_err(|error| format!("gkr_statement_{shard}:{error:?}"))?;
        gkr[usize::from(shard)] = BindingDigestV2::hash(BindingRoleV2::Payload, &raw)
            .map_err(|error| format!("gkr_binding_{shard}:{error:?}"))?;
    }
    let mut binding_reader = File::open(&aggregate_path)
        .map_err(|error| format!("aggregate_binding_open:{:?}", error.kind()))?;
    let aggregate_binding = BindingDigestV2::hash_reader_exact(
        BindingRoleV2::Payload, aggregate_bytes, &mut binding_reader,
    ).map_err(|error| format!("aggregate_binding:{error:?}"))?;
    let key = H4AggregatePackageV2VerificationKey::new(
        selected, header.attempt, profile_identity, program_commitment, statement_binding,
        gkr, state_binding, aggregate_binding, governed,
    ).map_err(|error| format!("verification_key:{error:?}"))?;
    let mut registry = StrictPqRootUseRegistryV2::new();
    let receipt = verify_h4_pre_alpha_v2(&mut aggregate, 0, aggregate_bytes, &key, &mut registry)
        .map_err(|error| format!("aggregate_verify:{error:?}"))?;
    publish(&output, &encode_h4_verification_key_v2(&key))?;
    println!("status=H4_V2_KEY_PUBLISHED_AFTER_VERIFICATION");
    println!("profile={}", selected.governed_label());
    println!("aggregate_bytes={aggregate_bytes}");
    println!("aggregate_binding={:?}", receipt.aggregate_binding());
    println!("proof_suite_id=null");
    println!("production_usable=false");
    println!("activation_allowed=false");
    Ok(())
}

fn main() -> ExitCode {
    let args = env::args_os().collect::<Vec<_>>();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => { eprintln!("ERR {error}"); ExitCode::from(2) }
    }
}
