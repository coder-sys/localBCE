use std::{env, fs, process};

use stark_engine::production_stark_attestation::ProductionStarkAttestationEnvelopeV2;

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
    if args.next().is_some() {
        return Err(usage());
    }
    let input_json = fs::read_to_string(&input_path)
        .map_err(|error| vec![format!("could not read {input_path}: {error}")])?;
    let artifact: ProductionStarkAttestationEnvelopeV2 = serde_json::from_str(&input_json)
        .map_err(|error| vec![format!("invalid attestation envelope JSON: {error}")])?;
    artifact.validate()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "production_stark_attestation_envelope_validation",
            "status": "ok",
            "path": input_path,
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
        "usage: validate_production_stark_attestation_envelope <attestation_envelope.json>"
            .to_string(),
    ]
}
