//! Stream-verify the current H4-v2 pre-alpha boundary.
//!
//! This command does not produce a proof, complete post-Z H4, complete the
//! parent, or qualify an outer v3 envelope. It only exposes the native
//! pre-alpha verifier with an independently governed serialized key.

use std::env;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use bl_pq512_crypto_core::h4_proof_package_v2::verify_h4_pre_alpha_v2;
use bl_pq512_crypto_core::h4_verification_key_v2::{
    H4_VERIFICATION_KEY_V2_BYTES, decode_h4_verification_key_v2,
};
use bl_pq512_crypto_core::strict_pq_public_coin_v2::StrictPqRootUseRegistryV2;

const USAGE: &str = "usage: h4_pre_alpha_verify <verification-key> <h4-aggregate>";

fn absolute_regular_file(value: &std::ffi::OsString, label: &str) -> Result<PathBuf, String> {
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

fn read_key(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("verification_key_metadata:{:?}", error.kind()))?;
    if metadata.len() != u64::try_from(H4_VERIFICATION_KEY_V2_BYTES).unwrap_or(u64::MAX) {
        return Err(format!(
            "verification_key_length:{}/{}",
            metadata.len(),
            H4_VERIFICATION_KEY_V2_BYTES
        ));
    }
    let value =
        fs::read(path).map_err(|error| format!("verification_key_read:{:?}", error.kind()))?;
    if value.len() != H4_VERIFICATION_KEY_V2_BYTES {
        return Err("verification_key_changed_during_read".to_owned());
    }
    Ok(value)
}

fn hex(value: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(value.len() * 2);
    for byte in value {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn run(args: &[std::ffi::OsString]) -> Result<(), String> {
    if args.len() != 3 {
        return Err(USAGE.to_owned());
    }
    let key_path = absolute_regular_file(&args[1], "verification_key")?;
    let aggregate_path = absolute_regular_file(&args[2], "h4_aggregate")?;
    let key_bytes = read_key(&key_path)?;
    let key = decode_h4_verification_key_v2(&key_bytes)
        .map_err(|error| format!("verification_key_decode:{error:?}"))?;
    let metadata = fs::symlink_metadata(&aggregate_path)
        .map_err(|error| format!("h4_aggregate_metadata:{:?}", error.kind()))?;
    let component_bytes = metadata.len();
    let mut reader = File::open(&aggregate_path)
        .map_err(|error| format!("h4_aggregate_open:{:?}", error.kind()))?;
    let mut registry = StrictPqRootUseRegistryV2::new();
    let receipt = verify_h4_pre_alpha_v2(&mut reader, 0, component_bytes, &key, &mut registry)
        .map_err(|error| format!("verify:{error:?}"))?;
    println!("status=H4_PRE_ALPHA_VERIFIED_UNQUALIFIED");
    println!("profile={}", key.profile().governed_label());
    println!("aggregate_bytes={component_bytes}");
    println!(
        "aggregate_binding={}",
        hex(receipt.aggregate_binding().as_bytes())
    );
    println!(
        "final_transcript_root={}",
        hex(receipt.final_transcript_root())
    );
    println!("shard_count={}", receipt.construction_count());
    for (index, binding) in receipt.shard_algebra_bindings().iter().enumerate() {
        println!("shard_{index}_algebra_binding={}", hex(binding.as_bytes()));
    }
    for (index, root) in receipt.source_roots().iter().enumerate() {
        println!("shard_{index}_source_root={}", hex(root.as_bytes()));
    }
    for (index, root) in receipt.bridge_base_roots().iter().enumerate() {
        println!("shard_{index}_bridge_base_root={}", hex(root.as_bytes()));
    }
    println!("post_z_completion=false");
    println!("aggregate_verification=false");
    println!("production_usable=false");
    println!("activation_allowed=false");
    Ok(())
}

fn main() -> ExitCode {
    let args = env::args_os().collect::<Vec<_>>();
    if args.len() == 2 && args[1] == "--capabilities" {
        println!("status=H4_PRE_ALPHA_VERIFIER_AVAILABLE");
        println!("h4_pre_alpha_verification=true");
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
