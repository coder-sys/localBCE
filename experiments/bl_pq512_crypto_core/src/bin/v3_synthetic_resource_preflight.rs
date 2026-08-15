//! Resource gate for the explicit synthetic, nonactivating integration lane.
//!
//! This is intentionally separate from `resource_preflight`: that binary
//! models a serialized real AIR program and must keep rejecting non-AIR input.
//! This lane only proves that its bounded synthetic artifacts fit the governed
//! host and scratch ceilings; it never qualifies a production proof.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use bl_pq512_crypto_core::v3_synthetic_major::{
    SYNTHETIC_BUNDLE_BYTES, SyntheticProfile, verify_synthetic_input,
};

const PEAK_RESIDENT_BYTES: usize = 5_000_000_000;
const SCRATCH_BYTES_EXCLUSIVE: usize = 5_000_000_000;
const USAGE: &str =
    "usage: v3_synthetic_resource_preflight <K128_CALIBRATION|K512_CALIBRATION> <absolute-input>";

fn run(args: &[String]) -> Result<(), String> {
    if args.len() != 3 {
        return Err(USAGE.to_owned());
    }
    let profile = SyntheticProfile::from_label(&args[1]).map_err(|_| "profile_invalid")?;
    let input_path = PathBuf::from(&args[2]);
    if !input_path.is_absolute() {
        return Err("input_path_not_absolute".to_owned());
    }
    let metadata = fs::symlink_metadata(&input_path)
        .map_err(|error| format!("input_metadata:{:?}", error.kind()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("input_not_regular".to_owned());
    }
    let input = fs::read(&input_path).map_err(|error| format!("input_read:{:?}", error.kind()))?;
    verify_synthetic_input(profile, &input).map_err(|error| format!("input_verify:{error:?}"))?;

    // This is a deliberately conservative small-lane model. It is not the
    // real prover's AIR resource model and is never allowed to qualify it.
    let modeled_peak_host_bytes = input
        .len()
        .checked_add(SYNTHETIC_BUNDLE_BYTES)
        .and_then(|value| value.checked_add(64 * 1024))
        .ok_or_else(|| "resource_overflow".to_owned())?;
    let modeled_scratch_bytes = input
        .len()
        .checked_add(SYNTHETIC_BUNDLE_BYTES)
        .ok_or_else(|| "resource_overflow".to_owned())?;
    if modeled_peak_host_bytes > PEAK_RESIDENT_BYTES
        || modeled_scratch_bytes > SCRATCH_BYTES_EXCLUSIVE
    {
        return Err("synthetic_resource_gate_rejected".to_owned());
    }
    println!("status=SYNTHETIC_RESOURCE_PREFLIGHT_PASS");
    println!("evidence_class=synthetic_nonactivating_integration");
    println!("profile={}", profile.label());
    println!("input_bytes={}", input.len());
    println!("modeled_peak_host_bytes={modeled_peak_host_bytes}");
    println!("modeled_scratch_bytes={modeled_scratch_bytes}");
    println!("peak_resident_bytes_limit={PEAK_RESIDENT_BYTES}");
    println!("scratch_bytes_limit_exclusive={SCRATCH_BYTES_EXCLUSIVE}");
    println!("qualifies=false");
    println!("scratch_gate_pass=true");
    println!("activation_allowed=false");
    println!("production_usable=false");
    println!("synthetic_only=true");
    println!("gpu_resource_state=NOT_APPLICABLE");
    println!("real_phi_or_payments=false");
    Ok(())
}

fn main() -> ExitCode {
    let args = env::args().collect::<Vec<_>>();
    if args.len() == 2 && args[1] == "--capabilities" {
        println!("status=SYNTHETIC_RESOURCE_PREFLIGHT_AVAILABLE");
        println!("synthetic_only=true");
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
