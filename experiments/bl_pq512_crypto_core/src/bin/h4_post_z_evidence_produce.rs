//! Replay and package one current H4 post-Z response transcript.
//!
//! This command produces `BLH4ZE02` transport evidence only. It is not a full
//! H4 proof producer and cannot create an accepting aggregate.

use std::env;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use bl_pq512_crypto_core::binding_root_v2::{BINDING_V2_BYTES, BindingDigestV2};
use bl_pq512_crypto_core::h4_bridge_source_response_v2::{
    H4_BRIDGE_SOURCE_RESPONSE_V2_BYTES, decode_h4_bridge_source_response_v2,
};
use bl_pq512_crypto_core::h4_post_z_response_evidence_v2::{
    H4_POST_Z_RESPONSE_EVIDENCE_V2_BYTES, decode_h4_post_z_response_evidence_v2,
    encode_h4_post_z_response_evidence_v2, produce_h4_post_z_response_evidence_v2,
};
use bl_pq512_crypto_core::h4_proof_package_v2::H4ProofProfileV2;
use bl_pq512_crypto_core::strict_pq_public_coin_v2::{
    StrictPqGovernedVerifierKeyV2, StrictPqRootUseRegistryV2,
};
use sha3::{Digest, Sha3_512};

const USAGE: &str = "usage: h4_post_z_evidence_produce <K128_CALIBRATION|K512_CALIBRATION> <governed-key> <strict-response-bundle> <response> <context-binding> <claim-vector-binding> <first-ordinal> <output>";

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
    let key_path = absolute_regular_file(&args[2], "governed_key")?;
    let bundle_path = absolute_regular_file(&args[3], "strict_response_bundle")?;
    let response_path = absolute_regular_file(&args[4], "response")?;
    let context_path = absolute_regular_file(&args[5], "context_binding")?;
    let claim_path = absolute_regular_file(&args[6], "claim_vector_binding")?;
    let first_ordinal = args[7]
        .to_str()
        .ok_or_else(|| "first_ordinal_utf8".to_owned())?
        .parse::<u32>()
        .map_err(|_| "first_ordinal_invalid".to_owned())?;
    let output = PathBuf::from(&args[8]);
    if !output.is_absolute() {
        return Err("output_path_not_absolute".to_owned());
    }
    if output.exists() {
        return Err("output_exists".to_owned());
    }

    let key_bytes = read_exact(&key_path, 1_116, "governed_key")?;
    let governed_key = StrictPqGovernedVerifierKeyV2::decode(&key_bytes)
        .map_err(|error| format!("governed_key_invalid:{error:?}"))?;
    let bundle = read_bounded(&bundle_path, 128 << 20, "strict_response_bundle")?;
    let response_bytes = read_exact(
        &response_path,
        H4_BRIDGE_SOURCE_RESPONSE_V2_BYTES,
        "response",
    )?;
    let response = decode_h4_bridge_source_response_v2(&response_bytes)
        .map_err(|error| format!("response_invalid:{error:?}"))?;
    let context_bytes = read_exact(&context_path, BINDING_V2_BYTES, "context_binding")?;
    let claim_bytes = read_exact(&claim_path, BINDING_V2_BYTES, "claim_vector_binding")?;
    let context = BindingDigestV2::decode(&context_bytes)
        .map_err(|error| format!("context_binding_invalid:{error:?}"))?;
    let claim_vector_binding = BindingDigestV2::decode(&claim_bytes)
        .map_err(|error| format!("claim_vector_binding_invalid:{error:?}"))?;
    let mut registry = StrictPqRootUseRegistryV2::new();
    let evidence = produce_h4_post_z_response_evidence_v2(
        &bundle,
        &governed_key,
        selected_profile,
        &response,
        context,
        claim_vector_binding,
        first_ordinal,
        &mut registry,
    )
    .map_err(|error| format!("produce:{error:?}"))?;
    let encoded = encode_h4_post_z_response_evidence_v2(&evidence)
        .map_err(|error| format!("encode:{error:?}"))?;
    if encoded.len() != H4_POST_Z_RESPONSE_EVIDENCE_V2_BYTES {
        return Err("evidence_length".to_owned());
    }
    let partial = PathBuf::from(format!("{}.partial", output.display()));
    if partial.exists() {
        return Err("partial_output_exists".to_owned());
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&partial)
        .map_err(|error| format!("partial_output_open:{:?}", error.kind()))?;
    if let Err(error) = file.write_all(&encoded).and_then(|_| file.sync_all()) {
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
    let digest: [u8; 64] = Sha3_512::digest(&encoded).into();
    let readback = fs::read(&output).map_err(|error| format!("readback:{:?}", error.kind()))?;
    if readback != encoded {
        return Err("readback_mismatch".to_owned());
    }
    let decoded = decode_h4_post_z_response_evidence_v2(&readback)
        .map_err(|error| format!("readback_decode:{error:?}"))?;
    println!("status=H4_POST_Z_RESPONSE_EVIDENCE_PRODUCED_UNQUALIFIED");
    println!("profile={}", args[1].to_string_lossy());
    println!("first_ordinal={}", first_ordinal);
    println!("evidence_bytes={}", readback.len());
    println!("evidence_sha3_512={}", hex(&digest));
    println!(
        "final_transcript_root={}",
        hex(&decoded.final_transcript_root)
    );
    println!("h4_proof_production=false");
    println!("post_z_completion=false");
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
        println!("status=H4_POST_Z_RESPONSE_EVIDENCE_PRODUCER_AVAILABLE");
        println!("post_z_response_evidence_production=true");
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
