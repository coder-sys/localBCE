//! Standalone local verifier for the nonactivating production-candidate lane.
//!
//! The expected AIR program and M31 public-input vector are separate files;
//! identities are pinned by the caller's release manifest.  The submitted
//! envelope is never allowed to select its own verifier context.

use std::env;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use bl_pq512_crypto_core::field::M31;
use bl_pq512_crypto_core::production_verifier::{
    MAX_ENVELOPE_BYTES, PRODUCTION_ENVELOPE_PREFIX_BYTES, ProductionProofEnvelope,
    ProductionVerificationKey, decode_production_envelope_prefix,
    validate_production_envelope_lengths, verify_production_envelope_parts,
};
use sha3::{Digest, Sha3_512};

const PUBLIC_INPUT_MAGIC: &[u8; 8] = b"BLPQPI01";
const PUBLIC_INPUT_VERSION: u16 = 1;
const MAX_PROGRAM_BYTES: u64 = 64 * 1024 * 1024;
const PUBLIC_INPUT_BYTES: u64 = 14 + (12 * 9 * 4);

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

fn open_regular_file(path: &Path, label: &str, maximum: u64) -> Result<(File, u64), String> {
    if !path.is_absolute() {
        return Err(format!("{label}_path_not_absolute"));
    }
    let file = File::open(path).map_err(|_| format!("{label}_open"))?;
    let metadata = file.metadata().map_err(|_| format!("{label}_metadata"))?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > maximum {
        return Err(format!("{label}_file_bounds"));
    }
    Ok((file, metadata.len()))
}

fn allocate_and_read(file: &mut File, length: usize, label: &str) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(length)
        .map_err(|_| format!("{label}_allocation"))?;
    output.resize(length, 0);
    file.read_exact(&mut output)
        .map_err(|_| format!("{label}_read"))?;
    Ok(output)
}

fn read_regular_file(path: &Path, label: &str, maximum: u64) -> Result<Vec<u8>, String> {
    let (mut file, length) = open_regular_file(path, label, maximum)?;
    let length = usize::try_from(length).map_err(|_| format!("{label}_file_bounds"))?;
    allocate_and_read(&mut file, length, label)
}

fn hash_open_file(file: &mut File, expected_length: u64, label: &str) -> Result<[u8; 64], String> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| format!("{label}_hash_seek"))?;
    let mut hash = Sha3_512::new();
    let mut observed = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| format!("{label}_hash_read"))?;
        if count == 0 {
            break;
        }
        observed = observed
            .checked_add(u64::try_from(count).map_err(|_| format!("{label}_hash_length"))?)
            .ok_or_else(|| format!("{label}_hash_length"))?;
        if observed > expected_length {
            return Err(format!("{label}_changed_during_read"));
        }
        hash.update(&buffer[..count]);
    }
    if observed != expected_length {
        return Err(format!("{label}_changed_during_read"));
    }
    Ok(hash.finalize().into())
}

fn read_public_inputs(path: &Path) -> Result<Vec<M31>, String> {
    let encoded = read_regular_file(path, "public_inputs", PUBLIC_INPUT_BYTES)?;
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
    if count != 12 * 9 || encoded.len() != PUBLIC_INPUT_BYTES as usize {
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
    if arguments.len() != 7 {
        return Err(
            "usage: production_candidate_verify <envelope> <program> <public-inputs> <suite-id-hex> <schema-id-hex> <verifier-id-hex> <projection-schema-id-hex>"
                .into(),
        );
    }
    let suite_id = decode_identity(&arguments[3])?;
    let schema_id = decode_identity(&arguments[4])?;
    let verifier_artifact_identity = decode_identity(&arguments[5])?;
    let public_input_projection_schema = decode_identity(&arguments[6])?;
    let (mut envelope_file, envelope_file_length) = open_regular_file(
        Path::new(&arguments[0]),
        "envelope",
        MAX_ENVELOPE_BYTES as u64,
    )?;
    let mut prefix = [0_u8; PRODUCTION_ENVELOPE_PREFIX_BYTES];
    envelope_file
        .read_exact(&mut prefix)
        .map_err(|_| "envelope_prefix_read".to_string())?;
    let header = decode_production_envelope_prefix(&prefix)
        .map_err(|error| format!("envelope_prefix_{error:?}"))?;
    if header.suite_id != suite_id
        || header.schema_id != schema_id
        || header.verifier_artifact_identity != verifier_artifact_identity
    {
        return Err("envelope_identity_mismatch".into());
    }
    let transcript_length_offset = PRODUCTION_ENVELOPE_PREFIX_BYTES
        .checked_add(header.proof_length)
        .ok_or_else(|| "envelope_length_overflow".to_string())?;
    let transcript_length_end = transcript_length_offset
        .checked_add(8)
        .ok_or_else(|| "envelope_length_overflow".to_string())?;
    if u64::try_from(transcript_length_end).map_err(|_| "envelope_length_overflow".to_string())?
        > envelope_file_length
    {
        return Err("envelope_truncated".into());
    }
    envelope_file
        .seek(SeekFrom::Start(
            u64::try_from(transcript_length_offset)
                .map_err(|_| "envelope_length_overflow".to_string())?,
        ))
        .map_err(|_| "envelope_transcript_length_seek".to_string())?;
    let mut transcript_length_bytes = [0_u8; 8];
    envelope_file
        .read_exact(&mut transcript_length_bytes)
        .map_err(|_| "envelope_transcript_length_read".to_string())?;
    let transcript_length = usize::try_from(u64::from_be_bytes(transcript_length_bytes))
        .map_err(|_| "envelope_transcript_length_bounds".to_string())?;
    validate_production_envelope_lengths(
        header.proof_length,
        transcript_length,
        usize::try_from(envelope_file_length)
            .map_err(|_| "envelope_file_length_bounds".to_string())?,
    )
    .map_err(|error| format!("envelope_lengths_{error:?}"))?;

    envelope_file
        .seek(SeekFrom::Start(PRODUCTION_ENVELOPE_PREFIX_BYTES as u64))
        .map_err(|_| "envelope_proof_seek".to_string())?;
    let proof_package = allocate_and_read(
        &mut envelope_file,
        header.proof_length,
        "envelope_proof_package",
    )?;
    let mut observed_transcript_length = [0_u8; 8];
    envelope_file
        .read_exact(&mut observed_transcript_length)
        .map_err(|_| "envelope_transcript_length_reread".to_string())?;
    if observed_transcript_length != transcript_length_bytes {
        return Err("envelope_changed_during_read".into());
    }
    let transcript_evidence =
        allocate_and_read(&mut envelope_file, transcript_length, "envelope_transcript")?;
    let mut trailing = [0_u8; 1];
    if envelope_file
        .read(&mut trailing)
        .map_err(|_| "envelope_trailing_read".to_string())?
        != 0
    {
        return Err("envelope_trailing".into());
    }
    let mut envelope_hash = Sha3_512::new();
    envelope_hash.update(prefix);
    envelope_hash.update(&proof_package);
    envelope_hash.update(transcript_length_bytes);
    envelope_hash.update(&transcript_evidence);
    let envelope_commitment: [u8; 64] = envelope_hash.finalize().into();

    let program = read_regular_file(Path::new(&arguments[1]), "program", MAX_PROGRAM_BYTES)?;
    let public_inputs = read_public_inputs(Path::new(&arguments[2]))?;
    let envelope = ProductionProofEnvelope {
        suite_id: header.suite_id,
        schema_id: header.schema_id,
        verifier_artifact_identity: header.verifier_artifact_identity,
        public_fields: header.public_fields,
        sidecar: header.sidecar,
        proof_package,
        transcript_evidence,
    };
    let receipt = verify_production_envelope_parts(
        &envelope,
        ProductionVerificationKey {
            suite_id,
            schema_id,
            verifier_artifact_identity,
            expected_program: &program,
            expected_public_inputs: &public_inputs,
            public_input_projection_schema: Some(public_input_projection_schema),
        },
    )
    .map_err(|error| format!("verify_{error:?}"))?;
    if hash_open_file(&mut envelope_file, envelope_file_length, "envelope")? != envelope_commitment
    {
        return Err("envelope_changed_during_read".into());
    }
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
