//! Native accepting verifier for the synthetic nonactivating integration bundle.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use bl_pq512_crypto_core::v3_synthetic_major::{
    SyntheticProfile, run_synthetic_mutation_suite, verify_synthetic_bundle,
};
use sha3::{Digest, Sha3_512};

const USAGE: &str = "usage: v3_synthetic_aggregate_verify <K128_CALIBRATION|K512_CALIBRATION> <absolute-input> <absolute-proof> <dependency-hex-128> [--mutation-suite]";

fn regular_file(value: &str, label: &str) -> Result<PathBuf, String> {
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

fn parse_hex_64(value: &str) -> Result<[u8; 64], String> {
    if value.len() != 128 || !value.is_ascii() {
        return Err("dependency_hex_length".to_owned());
    }
    let mut output = [0_u8; 64];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = char::from(pair[0])
            .to_digit(16)
            .ok_or_else(|| "dependency_hex".to_owned())?;
        let low = char::from(pair[1])
            .to_digit(16)
            .ok_or_else(|| "dependency_hex".to_owned())?;
        output[index] = ((high << 4) | low) as u8;
    }
    Ok(output)
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

fn run(args: &[String]) -> Result<(), String> {
    if !(args.len() == 5 || args.len() == 6) {
        return Err(USAGE.to_owned());
    }
    let profile = SyntheticProfile::from_label(&args[1]).map_err(|_| "profile_invalid")?;
    let input = fs::read(regular_file(&args[2], "input")?)
        .map_err(|error| format!("input_read:{:?}", error.kind()))?;
    let proof = fs::read(regular_file(&args[3], "proof")?)
        .map_err(|error| format!("proof_read:{:?}", error.kind()))?;
    let dependency = parse_hex_64(&args[4])?;
    if args.get(5).is_some_and(|value| value != "--mutation-suite") {
        return Err(USAGE.to_owned());
    }
    let verified = verify_synthetic_bundle(profile, &input, &proof, dependency)
        .map_err(|error| format!("verify:{error:?}"))?;
    let proof_identity: [u8; 64] = Sha3_512::digest(&proof).into();
    println!("status=SYNTHETIC_AGGREGATE_ACCEPTED_NONACTIVATING");
    println!("evidence_class=synthetic_nonactivating_integration");
    println!("profile={}", profile.label());
    println!("proof_identity_sha3_512={}", hex(&proof_identity));
    println!("aggregate_receipt={}", hex(verified.aggregate_receipt()));
    println!("work_receipt={}", hex(verified.work_receipt()));
    println!(
        "dependency_commitment={}",
        hex(verified.dependency_commitment())
    );
    println!("proof_suite_id=null");
    println!("production_usable=false");
    println!("activation_allowed=false");
    println!("gpu_launched=false");
    println!("real_phi_or_payments=false");
    if args.len() == 6 {
        let report = run_synthetic_mutation_suite(profile, &input, &proof, dependency)
            .map_err(|error| format!("mutation_suite:{error:?}"))?;
        println!("mutation_suite=PASS");
        println!("artifact_mutations={}", report.artifact_mutations);
        println!("input_mutations={}", report.input_mutations);
        println!("rejected_mutations={}", report.rejected_mutations);
    }
    Ok(())
}

fn main() -> ExitCode {
    let args = env::args().collect::<Vec<_>>();
    if args.len() == 2 && args[1] == "--capabilities" {
        println!("status=SYNTHETIC_AGGREGATE_VERIFIER_AVAILABLE");
        println!("accepting_synthetic_lane=true");
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
