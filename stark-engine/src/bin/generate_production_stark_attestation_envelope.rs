use std::{env, fs, process};

use stark_engine::{
    production_stark_attestation::ProductionStarkAttestationEnvelopeV2,
    production_verifier_handoff::ProductionStarkVerifierHandoffV4,
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
    let input_path = args.next().ok_or_else(usage)?;
    let chain_id = args
        .next()
        .ok_or_else(usage)?
        .parse::<u64>()
        .map_err(|error| vec![format!("invalid chain ID: {error}")])?;
    let verifier_address = args.next().ok_or_else(usage)?;
    let registry_address = args.next().ok_or_else(usage)?;
    let claim_amount = args
        .next()
        .ok_or_else(usage)?
        .parse::<u64>()
        .map_err(|error| vec![format!("invalid claim amount: {error}")])?;
    let output_path = args.next().ok_or_else(usage)?;
    if args.next().is_some() {
        return Err(usage());
    }
    let private_key = env::var("STARK_ATTESTOR_PRIVATE_KEY").map_err(|_| {
        vec!["STARK_ATTESTOR_PRIVATE_KEY must be set in the environment".to_string()]
    })?;

    let input_json = fs::read_to_string(&input_path)
        .map_err(|error| vec![format!("could not read {input_path}: {error}")])?;
    let handoff: ProductionStarkVerifierHandoffV4 = serde_json::from_str(&input_json)
        .map_err(|error| vec![format!("invalid verifier handoff JSON: {error}")])?;
    let artifact = ProductionStarkAttestationEnvelopeV2::from_handoff(
        &handoff,
        chain_id,
        &verifier_address,
        &registry_address,
        claim_amount,
        &private_key,
    )?;
    let output_json = serde_json::to_string_pretty(&artifact)
        .map_err(|error| vec![format!("could not serialize attestation envelope: {error}")])?;
    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|error| vec![format!("could not write {output_path}: {error}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "production_stark_attestation_envelope_generation",
            "status": "ok",
            "input": input_path,
            "output": output_path,
            "schema_version": artifact.schema_version,
            "chain_id": artifact.chain_id,
            "verifier_address": artifact.verifier_address,
            "registry_address": artifact.registry_address,
            "claim_amount": artifact.claim_amount,
            "attestor_address": artifact.attestor_address,
            "claim_hash": artifact.public_inputs.claim_hash,
            "proof_envelope_size_bytes": artifact.proof_envelope_size_bytes,
            "locally_validated": artifact.locally_validated,
            "native_on_chain_stark_verification": artifact.native_on_chain_stark_verification,
            "settlement_ready": artifact.settlement_ready,
        })
    );
    Ok(())
}

fn usage() -> Vec<String> {
    vec![
        "usage: STARK_ATTESTOR_PRIVATE_KEY=<hex> generate_production_stark_attestation_envelope <handoff.json> <chain_id> <verifier_address> <registry_address> <claim_amount> <attestation_envelope.json>"
            .to_string(),
    ]
}
