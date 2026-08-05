use std::{collections::BTreeSet, env, path::PathBuf, process, time::Duration};

use stark_engine::production_attestation_signer::{
    AttestationSignRequestV1, ExternalCommandSigner,
};

const HEALTH_DIGEST: &str = "0x8ab06fbad3a8d90a80e70e279de13c0b442fb13e547f3496aa9451b8fa13cf18";
const HEALTH_PUBLIC_INPUTS_HASH: &str =
    "0x55151f02f228a461415b539b5835f21e65d279415b30f69c20dc72610f93be20";
const HEALTH_PROOF_COMMITMENT: &str =
    "0x21e8b6648741c065e069ad8a665614001093e456a2bbd47a56c354236532036f";

fn main() {
    if let Err(errors) = run() {
        for error in errors {
            eprintln!("{error}");
        }
        process::exit(1);
    }
}

fn run() -> Result<(), Vec<String>> {
    let mut args = env::args();
    let _binary = args.next();
    let chain_id = args
        .next()
        .ok_or_else(usage)?
        .parse::<u64>()
        .map_err(|error| vec![format!("invalid chain ID: {error}")])?;
    let verifier_address = args.next().ok_or_else(usage)?;
    let registry_address = args.next().ok_or_else(usage)?;
    let policy_manifest_hash = args.next().ok_or_else(usage)?;
    if args.next().is_some() {
        return Err(usage());
    }
    if chain_id != 11_155_111 {
        return Err(vec![
            "external signer pilot health checks require Sepolia chain ID 11155111".to_string(),
        ]);
    }

    let program = env::var("STARK_ATTESTOR_SIGNER_PROGRAM")
        .map_err(|_| vec!["STARK_ATTESTOR_SIGNER_PROGRAM must be set".to_string()])?;
    let signer_args: Vec<String> = serde_json::from_str(
        &env::var("STARK_ATTESTOR_SIGNER_ARGS_JSON").unwrap_or_else(|_| "[]".to_string()),
    )
    .map_err(|error| vec![format!("invalid STARK_ATTESTOR_SIGNER_ARGS_JSON: {error}")])?;
    let allowed_key_ids: BTreeSet<String> = serde_json::from_str::<Vec<String>>(
        &env::var("STARK_ATTESTOR_ALLOWED_KEY_IDS_JSON")
            .map_err(|_| vec!["STARK_ATTESTOR_ALLOWED_KEY_IDS_JSON must be set".to_string()])?,
    )
    .map_err(|error| {
        vec![format!(
            "invalid STARK_ATTESTOR_ALLOWED_KEY_IDS_JSON: {error}"
        )]
    })?
    .into_iter()
    .collect();
    let expected_attestor = env::var("STARK_ATTESTOR_ADDRESS")
        .map_err(|_| vec!["STARK_ATTESTOR_ADDRESS must be set".to_string()])?;
    let timeout_seconds = env_u64("STARK_ATTESTOR_SIGNER_TIMEOUT_SECONDS", 30)?;

    let request = AttestationSignRequestV1::new(
        HEALTH_DIGEST,
        chain_id,
        &verifier_address,
        &registry_address,
        HEALTH_PUBLIC_INPUTS_HASH,
        HEALTH_PROOF_COMMITMENT,
        &policy_manifest_hash,
        0,
    )?;
    let signer = ExternalCommandSigner {
        program: PathBuf::from(program),
        args: signer_args,
        timeout: Duration::from_secs(timeout_seconds),
        expected_attestor,
        allowed_key_ids,
    };
    let validated = signer.sign(&request)?;
    println!(
        "{}",
        serde_json::json!({
            "schema_version": "stark-external-attestation-signer-health-v1",
            "status": "ok",
            "chain_id": chain_id,
            "request_id": request.request_id,
            "signer_backend": validated.signer_backend,
            "key_id": validated.key_id,
            "attestor_address": validated.attestor_address,
            "signature_validated": true,
            "low_s_validated": true,
            "recovery_validated": true,
        })
    );
    Ok(())
}

fn env_u64(name: &str, default: u64) -> Result<u64, Vec<String>> {
    match env::var(name) {
        Ok(value) => value
            .parse::<u64>()
            .map_err(|error| vec![format!("{name} must be an unsigned integer: {error}")]),
        Err(_) => Ok(default),
    }
}

fn usage() -> Vec<String> {
    vec![
        "usage: STARK_ATTESTOR_SIGNER_PROGRAM=<path> STARK_ATTESTOR_SIGNER_ARGS_JSON=<json-array> STARK_ATTESTOR_ALLOWED_KEY_IDS_JSON=<json-array> STARK_ATTESTOR_ADDRESS=<address> validate_external_attestation_signer <chain_id> <verifier_address> <registry_address> <policy_manifest_hash>"
            .to_string(),
    ]
}
