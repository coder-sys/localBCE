//! Produce the current strict-PQ H4 transcript bundle only.
//!
//! This executable is intentionally not a full H4 prover, aggregate assembler,
//! or accepting verifier.  Its private inputs are supplied explicitly and are
//! never generated from OS entropy or written to the output artifact.

use std::env;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use bl_pq512_crypto_core::h4_proof_package_v2::H4ProofProfileV2;
use bl_pq512_crypto_core::strict_h4_transcript_producer::{
    STRICT_H4_TRANSCRIPT_SECRET_BYTES_V2, STRICT_H4_TRANSCRIPT_TAIL_BYTES_V2,
    StrictH4TranscriptProducerInput, produce_strict_h4_transcript,
};
use sha3::{Digest, Sha3_512};
use zeroize::Zeroize;

const USAGE: &str = "usage: strict_h4_transcript_produce <K128_CALIBRATION|K512_CALIBRATION> <governed-key> <secret-0> <tail-0> <secret-1> <tail-1> <raw-frames> <output>";
const RAW_FRAMES_MAX_BYTES: usize = 16 << 20;

fn profile(value: &str) -> Result<H4ProofProfileV2, String> {
    match value {
        "K128_CALIBRATION" => Ok(H4ProofProfileV2::K128),
        "K512_CALIBRATION" => Ok(H4ProofProfileV2::K512),
        _ => Err("profile_invalid".to_owned()),
    }
}

fn absolute_regular_file(value: &OsString, label: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(format!("{label}_path_not_absolute"));
    }
    let metadata =
        fs::metadata(&path).map_err(|error| format!("{label}_metadata:{:?}", error.kind()))?;
    if !metadata.is_file() {
        return Err(format!("{label}_not_regular"));
    }
    Ok(path)
}

fn read_exact(path: &Path, expected: usize, label: &str) -> Result<Vec<u8>, String> {
    let metadata =
        fs::metadata(path).map_err(|error| format!("{label}_metadata:{:?}", error.kind()))?;
    let length = usize::try_from(metadata.len()).map_err(|_| format!("{label}_too_large"))?;
    if length != expected {
        return Err(format!("{label}_length:{length}/{expected}"));
    }
    let bytes = fs::read(path).map_err(|error| format!("{label}_read:{:?}", error.kind()))?;
    if bytes.len() != expected {
        return Err(format!("{label}_changed_during_read"));
    }
    Ok(bytes)
}

fn read_bounded(path: &Path, maximum: usize, label: &str) -> Result<Vec<u8>, String> {
    let metadata =
        fs::metadata(path).map_err(|error| format!("{label}_metadata:{:?}", error.kind()))?;
    let length = usize::try_from(metadata.len()).map_err(|_| format!("{label}_too_large"))?;
    if length == 0 || length > maximum {
        return Err(format!("{label}_length"));
    }
    let bytes = fs::read(path).map_err(|error| format!("{label}_read:{:?}", error.kind()))?;
    if bytes.len() != length {
        return Err(format!("{label}_changed_during_read"));
    }
    Ok(bytes)
}

fn run(args: &[OsString]) -> Result<(), String> {
    if args.len() != 9 {
        return Err(USAGE.to_owned());
    }
    let selected_profile = profile(args[1].to_str().ok_or_else(|| "profile_utf8".to_owned())?)?;
    let governed_key_path = absolute_regular_file(&args[2], "governed_key")?;
    let secret_0_path = absolute_regular_file(&args[3], "secret_0")?;
    let tail_0_path = absolute_regular_file(&args[4], "tail_0")?;
    let secret_1_path = absolute_regular_file(&args[5], "secret_1")?;
    let tail_1_path = absolute_regular_file(&args[6], "tail_1")?;
    let raw_frames_path = absolute_regular_file(&args[7], "raw_frames")?;
    let output = PathBuf::from(&args[8]);
    if !output.is_absolute() {
        return Err("output_path_not_absolute".to_owned());
    }
    if output.exists() {
        return Err("output_exists".to_owned());
    }

    let governed_key = read_exact(&governed_key_path, 1_116, "governed_key")?;
    let mut secret_0 = read_exact(
        &secret_0_path,
        STRICT_H4_TRANSCRIPT_SECRET_BYTES_V2,
        "secret_0",
    )?;
    let mut tail_0 = read_exact(&tail_0_path, STRICT_H4_TRANSCRIPT_TAIL_BYTES_V2, "tail_0")?;
    let mut secret_1 = read_exact(
        &secret_1_path,
        STRICT_H4_TRANSCRIPT_SECRET_BYTES_V2,
        "secret_1",
    )?;
    let mut tail_1 = read_exact(&tail_1_path, STRICT_H4_TRANSCRIPT_TAIL_BYTES_V2, "tail_1")?;
    let raw_frames = read_bounded(&raw_frames_path, RAW_FRAMES_MAX_BYTES, "raw_frames")?;
    let result = produce_strict_h4_transcript(StrictH4TranscriptProducerInput {
        profile: selected_profile,
        governed_key: &governed_key,
        contributor_secret_material: [&secret_0, &secret_1],
        contributor_tails: [&tail_0, &tail_1],
        raw_frames: &raw_frames,
    });
    secret_0.zeroize();
    tail_0.zeroize();
    secret_1.zeroize();
    tail_1.zeroize();
    let result = result.map_err(|error| format!("produce:{error:?}"))?;

    let partial = PathBuf::from(format!("{}.partial", output.display()));
    if partial.exists() {
        return Err("partial_output_exists".to_owned());
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&partial)
        .map_err(|error| format!("partial_output_open:{:?}", error.kind()))?;
    if let Err(error) = file
        .write_all(&result.encoded_bundle)
        .and_then(|_| file.sync_all())
    {
        drop(file);
        let _ = fs::remove_file(&partial);
        return Err(format!("partial_output_write:{:?}", error.kind()));
    }
    drop(file);
    if output.exists() {
        let _ = fs::remove_file(&partial);
        return Err("output_created_during_production".to_owned());
    }
    fs::rename(&partial, &output).map_err(|error| {
        let _ = fs::remove_file(&partial);
        format!("output_publish:{:?}", error.kind())
    })?;
    let digest: [u8; 64] = Sha3_512::digest(&result.encoded_bundle).into();
    println!("status=STRICT_H4_TRANSCRIPT_PRODUCED_UNQUALIFIED");
    println!("profile={}", args[1].to_string_lossy());
    println!("round_count={}", result.round_count);
    println!("bundle_bytes={}", result.encoded_bundle.len());
    println!("bundle_sha3_512={}", hex(&digest));
    println!(
        "final_transcript_root={}",
        hex(&result.final_transcript_root)
    );
    println!("h4_proof_production=false");
    println!("aggregate_verification=false");
    println!("production_usable=false");
    println!("activation_allowed=false");
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(char::from(DIGITS[usize::from(byte >> 4)]));
        result.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    result
}

fn main() -> ExitCode {
    let args = env::args_os().collect::<Vec<_>>();
    if args.len() == 2 && args[1] == "--capabilities" {
        println!("status=STRICT_H4_TRANSCRIPT_PRODUCER_AVAILABLE");
        println!("strict_h4_transcript_production=true");
        println!("h4_proof_production=false");
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
