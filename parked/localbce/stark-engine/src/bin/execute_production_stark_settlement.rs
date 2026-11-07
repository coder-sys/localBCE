use std::{
    collections::BTreeSet,
    env,
    path::{Path, PathBuf},
    process,
    time::Duration,
};

use stark_engine::{
    production_attestation_signer::ExternalCommandSigner,
    production_stark_settlement::{
        ProductionAttestationSignerConfig, ProductionStarkSettlementRequest,
        SettlementFinalityMode, execute_production_stark_settlement,
    },
};

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
    let bridge_path = args.next().ok_or_else(usage)?;
    let state_path = args.next().ok_or_else(usage)?;
    let output_directory = args.next().ok_or_else(usage)?;
    let chain_id = args
        .next()
        .ok_or_else(usage)?
        .parse::<u64>()
        .map_err(|error| vec![format!("invalid chain ID: {error}")])?;
    let verifier_address = args.next().ok_or_else(usage)?;
    let registry_address = args.next().ok_or_else(usage)?;
    let rpc_url = args.next().ok_or_else(usage)?;
    let transaction_value = args.next().ok_or_else(usage)?;
    if args.next().is_some() {
        return Err(usage());
    }
    let submitter_private_key = env::var("STARK_SUBMITTER_PRIVATE_KEY")
        .map_err(|_| vec!["STARK_SUBMITTER_PRIVATE_KEY must be set".to_string()])?;
    let attestor_mode =
        env::var("STARK_ATTESTOR_MODE").unwrap_or_else(|_| "local_private_key".to_string());
    let local_private_key = env::var("STARK_ATTESTOR_PRIVATE_KEY").ok();
    let external_signer = if attestor_mode == "external_command" {
        let args_json =
            env::var("STARK_ATTESTOR_SIGNER_ARGS_JSON").unwrap_or_else(|_| "[]".to_string());
        let signer_args: Vec<String> = serde_json::from_str(&args_json)
            .map_err(|error| vec![format!("invalid STARK_ATTESTOR_SIGNER_ARGS_JSON: {error}")])?;
        let allowed_keys_json = env::var("STARK_ATTESTOR_ALLOWED_KEY_IDS_JSON")
            .map_err(|_| vec!["STARK_ATTESTOR_ALLOWED_KEY_IDS_JSON must be set".to_string()])?;
        let allowed_key_ids: BTreeSet<String> =
            serde_json::from_str::<Vec<String>>(&allowed_keys_json)
                .map_err(|error| {
                    vec![format!(
                        "invalid STARK_ATTESTOR_ALLOWED_KEY_IDS_JSON: {error}"
                    )]
                })?
                .into_iter()
                .collect();
        Some(ExternalCommandSigner {
            program: PathBuf::from(
                env::var("STARK_ATTESTOR_SIGNER_PROGRAM")
                    .map_err(|_| vec!["STARK_ATTESTOR_SIGNER_PROGRAM must be set".to_string()])?,
            ),
            args: signer_args,
            timeout: Duration::from_secs(env_u64("STARK_ATTESTOR_SIGNER_TIMEOUT_SECONDS", 30)?),
            expected_attestor: env::var("STARK_ATTESTOR_ADDRESS")
                .map_err(|_| vec!["STARK_ATTESTOR_ADDRESS must be set".to_string()])?,
            allowed_key_ids,
        })
    } else if attestor_mode == "local_private_key" {
        None
    } else {
        return Err(vec![format!(
            "unsupported STARK_ATTESTOR_MODE '{attestor_mode}'; expected local_private_key or external_command"
        )]);
    };
    let policy_manifest_hash = env::var("STARK_POLICY_MANIFEST_HASH").ok();
    let attestation_signer = match attestor_mode.as_str() {
        "local_private_key" => ProductionAttestationSignerConfig::LocalPrivateKey(
            local_private_key
                .as_deref()
                .ok_or_else(|| vec!["STARK_ATTESTOR_PRIVATE_KEY must be set".to_string()])?,
        ),
        "external_command" => ProductionAttestationSignerConfig::ExternalCommand {
            signer: external_signer
                .as_ref()
                .expect("external signer was constructed"),
            policy_manifest_hash: policy_manifest_hash
                .as_deref()
                .ok_or_else(|| vec!["STARK_POLICY_MANIFEST_HASH must be set".to_string()])?,
        },
        _ => unreachable!(),
    };
    let finality_mode = match env::var("STARK_FINALITY_MODE")
        .unwrap_or_else(|_| {
            if attestor_mode == "external_command" {
                "finalized".to_string()
            } else {
                "mined".to_string()
            }
        })
        .as_str()
    {
        "mined" => SettlementFinalityMode::Mined,
        "finalized" => SettlementFinalityMode::Finalized,
        "test_mined" => SettlementFinalityMode::TestMined,
        value => {
            return Err(vec![format!(
                "unsupported STARK_FINALITY_MODE '{value}'; expected mined, finalized, or test_mined"
            )]);
        }
    };
    let allowed_test_mined = finality_mode == SettlementFinalityMode::TestMined
        && chain_id == 31337
        && env::var("STARK_ALLOW_TEST_MINED_FINALITY").as_deref() == Ok("1");
    if attestor_mode == "external_command"
        && finality_mode != SettlementFinalityMode::Finalized
        && !allowed_test_mined
    {
        return Err(vec![
            "external_command attestation requires finalized finality; test_mined additionally requires chain 31337 and STARK_ALLOW_TEST_MINED_FINALITY=1"
                .to_string(),
        ]);
    }

    let receipt = execute_production_stark_settlement(&ProductionStarkSettlementRequest {
        bridge_input_path: Path::new(&bridge_path),
        nullifier_state_path: Path::new(&state_path),
        output_directory: Path::new(&output_directory),
        chain_id,
        verifier_address: &verifier_address,
        registry_address: &registry_address,
        rpc_url: &rpc_url,
        transaction_value: &transaction_value,
        attestation_signer,
        submitter_private_key: &submitter_private_key,
        finality_mode,
        finality_timeout: Duration::from_secs(env_u64("STARK_FINALITY_TIMEOUT_SECONDS", 900)?),
        finality_poll_interval: Duration::from_secs(env_u64("STARK_FINALITY_POLL_SECONDS", 5)?),
    })?;

    println!(
        "{}",
        serde_json::json!({
            "event": "production_stark_settlement",
            "status": "ok",
            "proof_backend": receipt.proof_backend,
            "claim_id": receipt.claim_id,
            "claim_hash": receipt.claim_hash,
            "decision": receipt.decision,
            "failure_code": receipt.failure_code,
            "transaction_hash": receipt.transaction_hash,
            "transaction_block_number": receipt.transaction_block_number,
            "transaction_block_hash": receipt.transaction_block_hash,
            "finality_mode": receipt.finality_mode,
            "finalized_on_chain": receipt.finalized_on_chain,
            "policy_manifest_hash": receipt.policy_manifest_hash,
            "signer_backend": receipt.signer_backend,
            "signer_key_id": receipt.signer_key_id,
            "batch_root": receipt.batch_root,
            "nullifier_root_before": receipt.nullifier_root_before,
            "nullifier_root_after": receipt.nullifier_root_after,
            "local_state_generation_after": receipt.local_state_generation_after,
            "native_on_chain_stark_verification": receipt.native_on_chain_stark_verification,
            "controlled_attestation_verification": receipt.controlled_attestation_verification,
            "groth16_executed": receipt.groth16_executed,
            "output_directory": output_directory,
        })
    );
    Ok(())
}

fn env_u64(name: &str, default: u64) -> Result<u64, Vec<String>> {
    match env::var(name) {
        Ok(value) => value
            .parse::<u64>()
            .map_err(|error| vec![format!("invalid {name}: {error}")])
            .and_then(|value| {
                if value == 0 {
                    Err(vec![format!("{name} must be nonzero")])
                } else {
                    Ok(value)
                }
            }),
        Err(_) => Ok(default),
    }
}

fn usage() -> Vec<String> {
    vec![
        "usage: STARK_ATTESTOR_MODE=<local_private_key|external_command> STARK_SUBMITTER_PRIVATE_KEY=<hex> execute_production_stark_settlement <bridge.json> <nullifier_state.json> <output_dir> <chain_id> <verifier_address> <registry_address> <rpc_url> <transaction_value>"
            .to_string(),
    ]
}
