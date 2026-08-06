//! Standalone local verifier for the nonactivating production-candidate lane.
//!
//! The expected AIR program and M31 public-input vector are separate files;
//! identities are pinned by the caller's release manifest.  The submitted
//! envelope is never allowed to select its own verifier context.

use std::env;
use std::fs;
use std::path::Path;

use bl_pq512_crypto_core::field::M31;
use bl_pq512_crypto_core::production_verifier::{
    ProductionVerificationKey, verify_production_envelope,
};
use sha3::{Digest, Sha3_512};

const PUBLIC_INPUT_MAGIC: &[u8; 8] = b"BLPQPI01";
const PUBLIC_INPUT_VERSION: u16 = 1;
const MAX_FILE_BYTES: u64 = 512 * 1024 * 1024;

fn hex_nibble(value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err("identity_hex_digit".into()),
    }
}

fn decode_identity(value: &str) -> Result<[u8; 64], String> {
    if value.len() != 128 {
        return Err("identity_hex_length".into());
    }
    let bytes = value.as_bytes();
    let mut output = [0_u8; 64];
    for (index, slot) in output.iter_mut().enumerate() {
        *slot = (hex_nibble(bytes[index * 2])? << 4) | hex_nibble(bytes[index * 2 + 1])?;
    }
    if !output.iter().any(|byte| *byte != 0) {
        return Err("identity_zero".into());
    }
    Ok(output)
}

fn read_regular_file(path: &Path, label: &str) -> Result<Vec<u8>, String> {
    if !path.is_absolute() {
        return Err(format!("{label}_path_not_absolute"));
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| format!("{label}_metadata"))?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > MAX_FILE_BYTES {
        return Err(format!("{label}_file_bounds"));
    }
    fs::read(path).map_err(|_| format!("{label}_read"))
}

fn read_public_inputs(path: &Path) -> Result<Vec<M31>, String> {
    let encoded = read_regular_file(path, "public_inputs")?;
    if encoded.len() < 14
        || encoded[..8] != *PUBLIC_INPUT_MAGIC
        || u16::from_be_bytes(
            encoded[8..10]
                .try_into()
                .map_err(|_| "public_inputs_header")?,
        ) != PUBLIC_INPUT_VERSION
    {
        return Err("public_inputs_header".into());
    }
    let count = usize::try_from(u32::from_be_bytes(
        encoded[10..14]
            .try_into()
            .map_err(|_| "public_inputs_count")?,
    ))
    .map_err(|_| "public_inputs_count")?;
    if count == 0 || count > 1_000_000 || encoded.len() != 14 + count * 4 {
        return Err("public_inputs_shape".into());
    }
    encoded[14..]
        .chunks_exact(4)
        .map(|chunk| {
            M31::from_canonical(u32::from_be_bytes(
                chunk.try_into().map_err(|_| "public_inputs_value")?,
            ))
            .map_err(|_| "public_inputs_noncanonical".to_string())
        })
        .collect()
}

fn hex_digest(value: &[u8; 64]) -> String {
    let mut output = String::with_capacity(128);
    for byte in value {
        output.push(char::from(b"0123456789abcdef"[(byte >> 4) as usize]));
        output.push(char::from(b"0123456789abcdef"[(byte & 0x0f) as usize]));
    }
    output
}

fn run() -> Result<(), String> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    if arguments.len() != 6 {
        return Err(
            "usage: production_candidate_verify <envelope> <program> <public-inputs> <suite-id-hex> <schema-id-hex> <verifier-id-hex>"
                .into(),
        );
    }
    let envelope = read_regular_file(Path::new(&arguments[0]), "envelope")?;
    let program = read_regular_file(Path::new(&arguments[1]), "program")?;
    let public_inputs = read_public_inputs(Path::new(&arguments[2]))?;
    let suite_id = decode_identity(&arguments[3])?;
    let schema_id = decode_identity(&arguments[4])?;
    let verifier_artifact_identity = decode_identity(&arguments[5])?;
    let receipt = verify_production_envelope(
        &envelope,
        ProductionVerificationKey {
            suite_id,
            schema_id,
            verifier_artifact_identity,
            expected_program: &program,
            expected_public_inputs: &public_inputs,
        },
    )
    .map_err(|error| format!("verify_{error:?}"))?;
    let envelope_commitment: [u8; 64] = Sha3_512::digest(&envelope).into();
    println!(
        "OK proof_suite_id={} schema_id={} verifier_artifact_identity={} envelope_commitment={} statement_commitment={} evidence_commitment={} proof_package_commitment={} transcript_commitment={}",
        hex_digest(&receipt.proof_suite_id),
        hex_digest(&receipt.schema_id),
        hex_digest(&receipt.verifier_artifact_identity),
        hex_digest(&envelope_commitment),
        hex_digest(&receipt.statement_commitment),
        hex_digest(&receipt.evidence_commitment),
        hex_digest(&receipt.proof_package_commitment),
        hex_digest(&receipt.transcript_commitment),
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("ERR:{error}");
        std::process::exit(2);
    }
}
