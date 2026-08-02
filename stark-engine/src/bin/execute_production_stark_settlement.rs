use std::{env, path::Path, process};

use stark_engine::production_stark_settlement::{
    ProductionStarkSettlementRequest, execute_production_stark_settlement,
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
    let attestor_private_key = env::var("STARK_ATTESTOR_PRIVATE_KEY")
        .map_err(|_| vec!["STARK_ATTESTOR_PRIVATE_KEY must be set".to_string()])?;
    let submitter_private_key = env::var("STARK_SUBMITTER_PRIVATE_KEY")
        .map_err(|_| vec!["STARK_SUBMITTER_PRIVATE_KEY must be set".to_string()])?;

    let receipt = execute_production_stark_settlement(&ProductionStarkSettlementRequest {
        bridge_input_path: Path::new(&bridge_path),
        nullifier_state_path: Path::new(&state_path),
        output_directory: Path::new(&output_directory),
        chain_id,
        verifier_address: &verifier_address,
        registry_address: &registry_address,
        rpc_url: &rpc_url,
        transaction_value: &transaction_value,
        attestor_private_key: &attestor_private_key,
        submitter_private_key: &submitter_private_key,
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

fn usage() -> Vec<String> {
    vec![
        "usage: STARK_ATTESTOR_PRIVATE_KEY=<hex> STARK_SUBMITTER_PRIVATE_KEY=<hex> execute_production_stark_settlement <bridge.json> <nullifier_state.json> <output_dir> <chain_id> <verifier_address> <registry_address> <rpc_url> <transaction_value>"
            .to_string(),
    ]
}
