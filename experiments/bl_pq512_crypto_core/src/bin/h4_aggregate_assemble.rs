//! Assemble an already-produced H4-v2 aggregate artifact.
//!
//! This command is deliberately not a prover and not an accepting verifier.
//! It validates the strict transcript, ordered global frames, shard headers,
//! fixed sizes, and identity bindings before streaming a `BLH4AG02` artifact.
//! The native H4 verifier remains the only authority for proof acceptance.

use std::env;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use bl_pq512_crypto_core::binding_root_v2::BindingDigestV2;
use bl_pq512_crypto_core::h4_proof_package_v2::{
    H4_GLOBAL_RAW_FRAMES_V2_MAX_BYTES, H4_PROOF_PACKAGE_V2_BYTES, H4AggregatePackageV2WriteInput,
    H4ProofProfileV2, write_h4_aggregate_package_v2,
};
use bl_pq512_crypto_core::strict_pq_public_coin_v2::STRICT_PQ_H4_MAX_BUNDLE_BYTES_V2;

const USAGE: &str = "usage: h4_aggregate_assemble <K128_CALIBRATION|K512_CALIBRATION> <attempt> <profile-identity-hex> <program-commitment-hex> <schedule-commitment-hex> <session-id-hex> <governed-key-binding-hex> <statement-binding-hex> <state-relation-source-binding-hex> <strict-bundle> <raw-frames> <output> <shard-0> [<shard-1> <shard-2> <shard-3>]";

fn profile(value: &str) -> Result<H4ProofProfileV2, String> {
    match value {
        "K128_CALIBRATION" => Ok(H4ProofProfileV2::K128),
        "K512_CALIBRATION" => Ok(H4ProofProfileV2::K512),
        _ => Err("profile_invalid".to_owned()),
    }
}

fn fixed_hex_64(value: &str, label: &str) -> Result<[u8; 64], String> {
    if value.len() != 128 || !value.is_ascii() {
        return Err(format!("{label}_hex_length"));
    }
    let mut result = [0_u8; 64];
    for (index, slot) in result.iter_mut().enumerate() {
        let high = char::from(value.as_bytes()[2 * index])
            .to_digit(16)
            .ok_or_else(|| format!("{label}_hex"))?;
        let low = char::from(value.as_bytes()[2 * index + 1])
            .to_digit(16)
            .ok_or_else(|| format!("{label}_hex"))?;
        *slot = ((high << 4) | low) as u8;
    }
    Ok(result)
}

fn digest(value: &str, label: &str) -> Result<BindingDigestV2, String> {
    let bytes = fixed_hex_64(value, label)?;
    BindingDigestV2::decode(&bytes).map_err(|error| format!("{label}_binding:{error:?}"))
}

fn path_arg(value: &OsString, label: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(format!("{label}_path_not_absolute"));
    }
    Ok(path)
}

fn read_bounded(path: &Path, maximum: usize, label: &str) -> Result<Vec<u8>, String> {
    let metadata =
        fs::metadata(path).map_err(|error| format!("{label}_metadata:{:?}", error.kind()))?;
    if !metadata.is_file() {
        return Err(format!("{label}_not_regular"));
    }
    let length = usize::try_from(metadata.len()).map_err(|_| format!("{label}_too_large"))?;
    if length > maximum {
        return Err(format!("{label}_too_large"));
    }
    let bytes = fs::read(path).map_err(|error| format!("{label}_read:{:?}", error.kind()))?;
    if bytes.len() != length {
        return Err(format!("{label}_changed_during_read"));
    }
    Ok(bytes)
}

fn read_exact(path: &Path, expected: usize, label: &str) -> Result<Vec<u8>, String> {
    let bytes = read_bounded(path, expected, label)?;
    if bytes.len() != expected {
        return Err(format!("{label}_length"));
    }
    Ok(bytes)
}

fn argument(args: &[OsString], index: usize, label: &str) -> Result<String, String> {
    args.get(index)
        .ok_or_else(|| USAGE.to_owned())?
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("{label}_utf8"))
}

fn run(args: &[OsString]) -> Result<(), String> {
    if args.len() < 14 {
        return Err(USAGE.to_owned());
    }
    let selected_profile = profile(&argument(args, 1, "profile")?)?;
    let expected_shards = usize::from(selected_profile.shard_count());
    if args.len() != 14 + expected_shards - 1 {
        return Err(USAGE.to_owned());
    }
    let attempt = argument(args, 2, "attempt")?
        .parse::<u16>()
        .map_err(|_| "attempt_invalid".to_owned())?;
    let profile_identity =
        fixed_hex_64(&argument(args, 3, "profile_identity")?, "profile_identity")?;
    let program_commitment = fixed_hex_64(
        &argument(args, 4, "program_commitment")?,
        "program_commitment",
    )?;
    let schedule_commitment = fixed_hex_64(
        &argument(args, 5, "schedule_commitment")?,
        "schedule_commitment",
    )?;
    let session_id = fixed_hex_64(&argument(args, 6, "session_id")?, "session_id")?;
    let governed_key_binding = digest(
        &argument(args, 7, "governed_key_binding")?,
        "governed_key_binding",
    )?;
    let statement_binding = digest(
        &argument(args, 8, "statement_binding")?,
        "statement_binding",
    )?;
    let state_relation_source_binding = digest(
        &argument(args, 9, "state_relation_source_binding")?,
        "state_relation_source_binding",
    )?;
    let strict_bundle_path = path_arg(&args[10], "strict_bundle")?;
    let raw_frames_path = path_arg(&args[11], "raw_frames")?;
    let output_path = path_arg(&args[12], "output")?;
    if output_path.exists() {
        return Err("output_exists".to_owned());
    }
    let strict_bundle = read_bounded(
        &strict_bundle_path,
        STRICT_PQ_H4_MAX_BUNDLE_BYTES_V2,
        "strict_bundle",
    )?;
    let raw_frames = read_bounded(
        &raw_frames_path,
        H4_GLOBAL_RAW_FRAMES_V2_MAX_BYTES,
        "raw_frames",
    )?;
    let shard_storage = (0..expected_shards)
        .map(|index| {
            let path = path_arg(&args[13 + index], &format!("shard_{index}"))?;
            read_exact(&path, H4_PROOF_PACKAGE_V2_BYTES, &format!("shard_{index}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let shard_bodies = shard_storage.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let input = H4AggregatePackageV2WriteInput {
        profile: selected_profile,
        attempt,
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

    let partial_path = PathBuf::from(format!("{}.partial", output_path.display()));
    if partial_path.exists() {
        return Err("partial_output_exists".to_owned());
    }
    let mut partial = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&partial_path)
        .map_err(|error| format!("partial_output_open:{:?}", error.kind()))?;
    let aggregate_bytes = match write_h4_aggregate_package_v2(&mut partial, &input) {
        Ok(bytes) => bytes,
        Err(error) => {
            drop(partial);
            let _ = fs::remove_file(&partial_path);
            return Err(format!("assemble:{error:?}"));
        }
    };
    if let Err(error) = partial.sync_all() {
        drop(partial);
        let _ = fs::remove_file(&partial_path);
        return Err(format!("partial_output_sync:{:?}", error.kind()));
    }
    drop(partial);
    if output_path.exists() {
        let _ = fs::remove_file(&partial_path);
        return Err("output_created_during_assembly".to_owned());
    }
    if let Err(error) = fs::rename(&partial_path, &output_path) {
        let _ = fs::remove_file(&partial_path);
        return Err(format!("output_publish:{:?}", error.kind()));
    }
    println!("status=H4_AGGREGATE_ASSEMBLED_UNQUALIFIED");
    println!("profile={}", argument(args, 1, "profile")?);
    println!("aggregate_bytes={aggregate_bytes}");
    println!("production_usable=false");
    println!("activation_allowed=false");
    Ok(())
}

fn main() -> ExitCode {
    let args = env::args_os().collect::<Vec<_>>();
    if args.len() == 2 && args[1] == "--capabilities" {
        println!("status=H4_AGGREGATE_ASSEMBLER_AVAILABLE");
        println!("proof_production=false");
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
