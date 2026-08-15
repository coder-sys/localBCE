//! Produce the varying-trace semantic/H4 bridge proof from governed inputs.
//!
//! CUDA is an untrusted algebra accelerator. Rust owns every public-coin
//! challenge, checks every recurrence, replays the completed proof, and only
//! then atomically publishes the five closed-witness files.

use std::{
    env,
    ffi::OsString,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::ExitCode,
};

use bl_pq512_crypto_core::{
    binding_root_v2::{BINDING_V2_BYTES, BindingDigestV2},
    field::Fp16,
    semantic_h4_bridge_gkr::{SemanticH4BridgeProfile, semantic_h4_bridge_mask_layout},
    semantic_h4_bridge_producer::produce_nonuniform_semantic_h4_bridge_gkr,
    semantic_h4_bridge_worker::SemanticH4BridgeWorker,
    strict_pq_public_coin_v2::{
        STRICT_PQ_LAMPORT_PUBLIC_VALUES_V2, STRICT_PQ_LAMPORT_SECRET_BYTES_V2,
    },
    v3_real_authority::{
        H4_GKR_CONTEXT_FILE, H4_GKR_FIRST_ORDINAL_FILE, H4_GKR_KEY_FILE, H4_GKR_PROOF_FILE,
        H4_GKR_STRICT_BUNDLE_FILE,
    },
};
use sha3::{Digest, Sha3_512};
use zeroize::Zeroize;

const USAGE: &str = "usage: semantic_h4_bridge_produce <K128_CALIBRATION|K512_CALIBRATION> <python> <worker.py> <boundary.bin> <semantic-state.snapshot> <context.bin> <governed-key.bin> <mask-coefficients.bin> <secret-0.bin> <tail-0.bin> <secret-1.bin> <tail-1.bin> <new-output-directory>";
const SECRET_BYTES: usize = STRICT_PQ_LAMPORT_PUBLIC_VALUES_V2 * STRICT_PQ_LAMPORT_SECRET_BYTES_V2;
const TAIL_BYTES: usize = BINDING_V2_BYTES;
const MAX_KEY_BYTES: usize = 2 * 1024 * 1024;

fn profile(value: &str) -> Result<SemanticH4BridgeProfile, String> {
    match value {
        "K128_CALIBRATION" => Ok(SemanticH4BridgeProfile::K128),
        "K512_CALIBRATION" => Ok(SemanticH4BridgeProfile::K512),
        _ => Err("profile_invalid".to_owned()),
    }
}

fn absolute_regular(value: &OsString, label: &str) -> Result<PathBuf, String> {
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

fn read_exact(path: &Path, expected: usize, label: &str) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("{label}_metadata:{:?}", error.kind()))?;
    if metadata.len() != expected as u64 {
        return Err(format!("{label}_length:{}/{}", metadata.len(), expected));
    }
    let bytes = fs::read(path).map_err(|error| format!("{label}_read:{:?}", error.kind()))?;
    if bytes.len() != expected {
        return Err(format!("{label}_changed_during_read"));
    }
    Ok(bytes)
}

fn read_bounded(path: &Path, maximum: usize, label: &str) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("{label}_metadata:{:?}", error.kind()))?;
    let length = usize::try_from(metadata.len()).map_err(|_| format!("{label}_length"))?;
    if length == 0 || length > maximum {
        return Err(format!("{label}_length:{length}/{maximum}"));
    }
    let bytes = fs::read(path).map_err(|error| format!("{label}_read:{:?}", error.kind()))?;
    if bytes.len() != length {
        return Err(format!("{label}_changed_during_read"));
    }
    Ok(bytes)
}

fn decode_fp16_file(path: &Path, count: usize) -> Result<Vec<Fp16>, String> {
    let bytes = read_exact(path, count.checked_mul(64).ok_or("mask_length")?, "mask")?;
    bytes
        .chunks_exact(64)
        .enumerate()
        .map(|(index, encoded)| {
            Fp16::decode(encoded).map_err(|error| format!("mask_{index}_decode:{error:?}"))
        })
        .collect()
}

fn create_file(directory: &Path, name: &str, bytes: &[u8]) -> Result<(), String> {
    let path = directory.join(name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|error| format!("{name}_open:{:?}", error.kind()))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("{name}_write:{:?}", error.kind()))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(char::from(DIGITS[usize::from(byte >> 4)]));
        result.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    result
}

fn run(args: &[OsString]) -> Result<(), String> {
    if args.len() != 14 {
        return Err(USAGE.to_owned());
    }
    let selected = profile(args[1].to_str().ok_or("profile_utf8")?)?;
    let python = absolute_regular(&args[2], "python")?;
    let worker = absolute_regular(&args[3], "worker")?;
    let boundary = absolute_regular(&args[4], "boundary")?;
    let snapshot = absolute_regular(&args[5], "snapshot")?;
    let context_path = absolute_regular(&args[6], "context")?;
    let key_path = absolute_regular(&args[7], "governed_key")?;
    let mask_path = absolute_regular(&args[8], "mask")?;
    let secret_0_path = absolute_regular(&args[9], "secret_0")?;
    let tail_0_path = absolute_regular(&args[10], "tail_0")?;
    let secret_1_path = absolute_regular(&args[11], "secret_1")?;
    let tail_1_path = absolute_regular(&args[12], "tail_1")?;
    let output = PathBuf::from(&args[13]);
    if !output.is_absolute() || output.exists() {
        return Err("output_must_be_new_absolute_directory".to_owned());
    }
    let partial = PathBuf::from(format!("{}.partial", output.display()));
    if partial.exists() {
        return Err("partial_output_exists".to_owned());
    }

    let context_bytes = read_exact(&context_path, BINDING_V2_BYTES, "context")?;
    let context = BindingDigestV2::decode(&context_bytes)
        .map_err(|error| format!("context_decode:{error:?}"))?;
    let key = read_bounded(&key_path, MAX_KEY_BYTES, "governed_key")?;
    let layout = semantic_h4_bridge_mask_layout(selected)
        .map_err(|error| format!("mask_layout:{error:?}"))?;
    let masks = decode_fp16_file(&mask_path, layout.padded_coefficients)?;
    let mut secret_0 = read_exact(&secret_0_path, SECRET_BYTES, "secret_0")?;
    let mut tail_0 = read_exact(&tail_0_path, TAIL_BYTES, "tail_0")?;
    let mut secret_1 = read_exact(&secret_1_path, SECRET_BYTES, "secret_1")?;
    let mut tail_1 = read_exact(&tail_1_path, TAIL_BYTES, "tail_1")?;

    let mut oracle =
        SemanticH4BridgeWorker::spawn(&python, &worker, &boundary, &snapshot, selected)
            .map_err(|error| format!("worker_spawn:{error:?}"))?;
    let produced = produce_nonuniform_semantic_h4_bridge_gkr(
        selected,
        context,
        0,
        &mut oracle,
        &masks,
        &key,
        [&secret_0, &secret_1],
        [&tail_0, &tail_1],
    );
    secret_0.zeroize();
    tail_0.zeroize();
    secret_1.zeroize();
    tail_1.zeroize();
    let produced = produced.map_err(|error| format!("produce:{error:?}"))?;
    oracle
        .finish()
        .map_err(|error| format!("worker_finish:{error:?}"))?;

    fs::create_dir(&partial).map_err(|error| format!("partial_create:{:?}", error.kind()))?;
    let publish = (|| {
        create_file(&partial, H4_GKR_PROOF_FILE, &produced.encoded_proof)?;
        create_file(
            &partial,
            H4_GKR_STRICT_BUNDLE_FILE,
            &produced.encoded_strict_bundle,
        )?;
        create_file(&partial, H4_GKR_KEY_FILE, &produced.governed_key)?;
        create_file(&partial, H4_GKR_CONTEXT_FILE, &context_bytes)?;
        create_file(
            &partial,
            H4_GKR_FIRST_ORDINAL_FILE,
            &produced.first_ordinal.to_be_bytes(),
        )?;
        fs::rename(&partial, &output).map_err(|error| format!("output_publish:{:?}", error.kind()))
    })();
    if let Err(error) = publish {
        let _ = fs::remove_dir_all(&partial);
        return Err(error);
    }
    println!("status=SEMANTIC_H4_BRIDGE_PRODUCED_REPLAY_ACCEPTED");
    println!("profile={}", args[1].to_string_lossy());
    println!("proof_bytes={}", produced.encoded_proof.len());
    println!(
        "proof_sha3_512={}",
        hex(&Sha3_512::digest(&produced.encoded_proof))
    );
    println!(
        "strict_bundle_bytes={}",
        produced.encoded_strict_bundle.len()
    );
    println!(
        "strict_bundle_sha3_512={}",
        hex(&Sha3_512::digest(&produced.encoded_strict_bundle))
    );
    println!(
        "final_transcript_root={}",
        hex(&produced.final_transcript_root)
    );
    println!("proofSuiteId=null");
    println!("production_usable=false");
    println!("activation_allowed=false");
    Ok(())
}

fn main() -> ExitCode {
    let args = env::args_os().collect::<Vec<_>>();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("semantic_h4_bridge_produce_error={error}");
            eprintln!("proofSuiteId=null");
            eprintln!("production_usable=false");
            eprintln!("activation_allowed=false");
            ExitCode::from(2)
        }
    }
}
