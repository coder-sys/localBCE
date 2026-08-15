//! Produce the canonical synthetic integration proof bundle.

use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use bl_pq512_crypto_core::v3_synthetic_major::{
    SyntheticProfile, produce_synthetic_bundle, verify_synthetic_input,
};
use sha3::{Digest, Sha3_512};

const USAGE: &str = "usage: v3_synthetic_proof_produce <K128_CALIBRATION|K512_CALIBRATION> <absolute-input> <absolute-output> <dependency-hex-128>";

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

fn new_output(value: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err("output_path_not_absolute".to_owned());
    }
    if path.exists() {
        return Err("output_exists".to_owned());
    }
    if !path.parent().is_some_and(Path::is_dir) {
        return Err("output_parent_not_directory".to_owned());
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

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let partial = PathBuf::from(format!("{}.partial", path.display()));
    if partial.exists() {
        return Err("partial_output_exists".to_owned());
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&partial)
        .map_err(|error| format!("partial_output_open:{:?}", error.kind()))?;
    if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(&partial);
        return Err(format!("partial_output_write:{:?}", error.kind()));
    }
    drop(file);
    if path.exists() {
        let _ = fs::remove_file(&partial);
        return Err("output_created_during_production".to_owned());
    }
    fs::rename(&partial, path).map_err(|error| {
        let _ = fs::remove_file(&partial);
        format!("output_publish:{:?}", error.kind())
    })
}

fn run(args: &[String]) -> Result<(), String> {
    if args.len() != 5 {
        return Err(USAGE.to_owned());
    }
    let profile = SyntheticProfile::from_label(&args[1]).map_err(|_| "profile_invalid")?;
    let input_path = regular_file(&args[2], "input")?;
    let output = new_output(&args[3])?;
    let dependency = parse_hex_64(&args[4])?;
    let input = fs::read(&input_path).map_err(|error| format!("input_read:{:?}", error.kind()))?;
    verify_synthetic_input(profile, &input).map_err(|error| format!("input_verify:{error:?}"))?;
    let encoded = produce_synthetic_bundle(profile, &input, dependency)
        .map_err(|error| format!("produce:{error:?}"))?;
    write_new(&output, &encoded)?;
    let identity: [u8; 64] = Sha3_512::digest(&encoded).into();
    println!("status=SYNTHETIC_PROOF_PRODUCED_UNQUALIFIED");
    println!("profile={}", profile.label());
    println!("proof_bytes={}", encoded.len());
    println!("proof_identity_sha3_512={}", hex(&identity));
    println!("dependency_commitment={}", hex(&dependency));
    println!("proof_suite_id=null");
    println!("production_usable=false");
    println!("activation_allowed=false");
    println!("real_phi_or_payments=false");
    Ok(())
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

fn main() -> ExitCode {
    let args = env::args().collect::<Vec<_>>();
    if args.len() == 2 && args[1] == "--capabilities" {
        println!("status=SYNTHETIC_PROOF_PRODUCER_AVAILABLE");
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
