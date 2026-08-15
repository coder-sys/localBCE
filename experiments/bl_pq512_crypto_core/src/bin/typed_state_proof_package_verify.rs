//! Standalone verifier for one fixed portable C0 typed-state proof package.
//!
//! The package cannot select its own profile or AIR identity. Both are pinned
//! by command-line values supplied from verifier governance.

use std::env;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use bl_pq512_crypto_core::typed_state_proof_package::{
    TYPED_STATE_PROOF_PACKAGE_BYTES, TypedStateProofVerificationKey,
    verify_typed_state_proof_package_v1,
};

const K128_PROFILE_LABEL: &str = "K128_CALIBRATION";
const K512_PROFILE_LABEL: &str = "K512_CALIBRATION";

fn hex_nibble(value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err("program_commitment_hex_digit".into()),
    }
}

fn decode_program_commitment(value: &str) -> Result<[u8; 64], String> {
    if value.len() != 128 {
        return Err("program_commitment_hex_length".into());
    }
    let encoded = value.as_bytes();
    let mut commitment = [0_u8; 64];
    for (index, byte) in commitment.iter_mut().enumerate() {
        *byte = (hex_nibble(encoded[index * 2])? << 4) | hex_nibble(encoded[index * 2 + 1])?;
    }
    if !commitment.iter().any(|byte| *byte != 0) {
        return Err("program_commitment_zero".into());
    }
    Ok(commitment)
}

fn governed_profile(value: &str) -> Result<&[u8], String> {
    match value {
        K128_PROFILE_LABEL => Ok(K128_PROFILE_LABEL.as_bytes()),
        K512_PROFILE_LABEL => Ok(K512_PROFILE_LABEL.as_bytes()),
        _ => Err("profile_not_governed".into()),
    }
}

fn read_fixed_package(path: &Path) -> Result<Vec<u8>, String> {
    if !path.is_absolute() {
        return Err("package_path_not_absolute".into());
    }
    let file = File::open(path).map_err(|_| "package_open".to_string())?;
    let metadata = file
        .metadata()
        .map_err(|_| "package_metadata".to_string())?;
    let expected_length = u64::try_from(TYPED_STATE_PROOF_PACKAGE_BYTES)
        .map_err(|_| "package_length_platform".to_string())?;
    if !metadata.file_type().is_file() || metadata.len() != expected_length {
        return Err("package_file_length".into());
    }

    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(TYPED_STATE_PROOF_PACKAGE_BYTES)
        .map_err(|_| "package_allocation".to_string())?;
    file.take(expected_length + 1)
        .read_to_end(&mut encoded)
        .map_err(|_| "package_read".to_string())?;
    if encoded.len() != TYPED_STATE_PROOF_PACKAGE_BYTES {
        return Err("package_changed_during_read".into());
    }
    Ok(encoded)
}

fn hex_bytes(value: &[u8]) -> String {
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(char::from(b"0123456789abcdef"[(byte >> 4) as usize]));
        output.push(char::from(b"0123456789abcdef"[(byte & 0x0f) as usize]));
    }
    output
}

fn run() -> Result<(), String> {
    let mut arguments = env::args_os().skip(1);
    let package_path = arguments
        .next()
        .ok_or_else(|| "usage_package_path".to_string())?;
    let profile_label = arguments
        .next()
        .ok_or_else(|| "usage_profile_label".to_string())?
        .into_string()
        .map_err(|_| "profile_not_utf8".to_string())?;
    let expected_program_commitment = arguments
        .next()
        .ok_or_else(|| "usage_program_commitment".to_string())?
        .into_string()
        .map_err(|_| "program_commitment_not_utf8".to_string())?;
    if arguments.next().is_some() {
        return Err("usage_trailing_argument".into());
    }

    let profile = governed_profile(&profile_label)?;
    let expected_program_commitment = decode_program_commitment(&expected_program_commitment)?;
    let encoded = read_fixed_package(Path::new(&package_path))?;
    let receipt = verify_typed_state_proof_package_v1(
        &encoded,
        TypedStateProofVerificationKey {
            expected_profile_label: profile,
            expected_program_commitment,
        },
    )
    .map_err(|_| "verify_rejected".to_string())?;

    println!(
        "OK profile_code={} profile_label={} profile_identity={} program_identity={} program_commitment={} proof_suite_id={} schedule_commitment={} session_id={} proof_package_commitment={} transcript_commitment={} public_input_digest={} projection_digest={} public_outputs={} epoch={} sequence_before={} sequence_after={} settlement_root_before={} settlement_root_after={} asset_registry_root_before={} asset_registry_root_after={} scope_root_before={} scope_root_after={} benefit_root_before={} benefit_root_after={} obligation_root_before={} obligation_root_after={} ledger_root_before={} ledger_root_after={} operation_log_root_before={} operation_log_root_after={} payment_root_before={} payment_root_after={} replay_root_before={} replay_root_after={} state_root_before={} state_root_after={} transition_commitment={}",
        receipt.governed_profile_code,
        receipt.governed_profile_label,
        hex_bytes(&receipt.profile_identity),
        hex_bytes(&receipt.program_identity),
        hex_bytes(&receipt.program_commitment),
        hex_bytes(&receipt.proof_suite_id),
        hex_bytes(&receipt.schedule_commitment),
        hex_bytes(&receipt.session_id),
        hex_bytes(&receipt.proof_package_commitment),
        hex_bytes(&receipt.transcript_commitment),
        hex_bytes(&receipt.public_input_digest),
        hex_bytes(&receipt.projection_digest),
        hex_bytes(&receipt.public_outputs.concat()),
        receipt.epoch,
        receipt.sequence_before,
        receipt.sequence_after,
        hex_bytes(&receipt.settlement_root_before),
        hex_bytes(&receipt.settlement_root_after),
        hex_bytes(&receipt.asset_registry_root_before),
        hex_bytes(&receipt.asset_registry_root_after),
        hex_bytes(&receipt.scope_root_before),
        hex_bytes(&receipt.scope_root_after),
        hex_bytes(&receipt.benefit_root_before),
        hex_bytes(&receipt.benefit_root_after),
        hex_bytes(&receipt.obligation_root_before),
        hex_bytes(&receipt.obligation_root_after),
        hex_bytes(&receipt.ledger_root_before),
        hex_bytes(&receipt.ledger_root_after),
        hex_bytes(&receipt.operation_log_root_before),
        hex_bytes(&receipt.operation_log_root_after),
        hex_bytes(&receipt.payment_root_before),
        hex_bytes(&receipt.payment_root_after),
        hex_bytes(&receipt.replay_root_before),
        hex_bytes(&receipt.replay_root_after),
        hex_bytes(&receipt.state_root_before),
        hex_bytes(&receipt.state_root_after),
        hex_bytes(&receipt.transition_commitment),
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("ERR:{error}");
        std::process::exit(2);
    }
}
