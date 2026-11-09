use std::{env, fs, process};

use sha2::{Digest, Sha256};
use stark_engine::{
    BridgeBackedWinterfellProofEvidence, StarkBridgeInput, WinterfellCompleteWitnessCandidate,
    winterfell_poc_adapter::WinterfellPocRealProofFixture,
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
    let candidate_path = args.next().ok_or_else(usage)?;
    let proof_fixture_path = args.next().ok_or_else(usage)?;
    let output_path = args.next().ok_or_else(usage)?;
    if args.next().is_some() {
        return Err(usage());
    }

    let bridge_bytes = read(&bridge_path)?;
    let candidate_bytes = read(&candidate_path)?;
    let proof_fixture_bytes = read(&proof_fixture_path)?;

    let bridge: StarkBridgeInput = serde_json::from_slice(&bridge_bytes)
        .map_err(|err| vec![format!("invalid StarkBridgeInput JSON: {err}")])?;
    let candidate: WinterfellCompleteWitnessCandidate = serde_json::from_slice(&candidate_bytes)
        .map_err(|err| {
            vec![format!(
                "invalid complete Winterfell witness candidate JSON: {err}"
            )]
        })?;
    let proof_fixture: WinterfellPocRealProofFixture = serde_json::from_slice(&proof_fixture_bytes)
        .map_err(|err| {
            vec![format!(
                "invalid Winterfell PoC real proof fixture JSON: {err}"
            )]
        })?;

    let evidence = BridgeBackedWinterfellProofEvidence::from_verified_artifacts(
        &bridge,
        &candidate,
        &proof_fixture,
        &sha256_prefixed(&bridge_bytes),
        &sha256_prefixed(&candidate_bytes),
        &sha256_prefixed(&proof_fixture_bytes),
    )?;
    evidence.validate()?;

    let output_json = serde_json::to_string_pretty(&evidence).map_err(|err| {
        vec![format!(
            "could not serialize bridge-backed Winterfell proof evidence: {err}"
        )]
    })?;
    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "bridge_backed_winterfell_proof_evidence_generation",
            "status": "ok",
            "bridge_input": bridge_path,
            "complete_witness_candidate": candidate_path,
            "proof_fixture": proof_fixture_path,
            "output": output_path,
            "schema_version": evidence.schema_version,
            "evidence_status": evidence.evidence_status,
            "claim_id": evidence.claim_id,
            "claim_hash": evidence.claim_hash,
            "proof_bytes_len": evidence.proof_bytes_len,
            "proof_bytes_sha256": evidence.proof_bytes_sha256,
            "verified": evidence.verified,
            "fixture_substitution": evidence.fixture_substitution,
            "production_semantics_complete": evidence.production_semantics_complete,
            "runtime_wired": evidence.runtime_wired,
            "on_chain_submission": evidence.on_chain_submission,
            "groth16_flow_unchanged": evidence.groth16_flow_unchanged,
        })
    );

    Ok(())
}

fn read(path: &str) -> Result<Vec<u8>, Vec<String>> {
    fs::read(path).map_err(|err| vec![format!("could not read {path}: {err}")])
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("0x{}", hex_lower(&digest))
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

fn usage() -> Vec<String> {
    vec![
        "usage: generate_bridge_backed_winterfell_proof_evidence <stark_bridge_input.json> <bridge_backed_complete_winterfell_witness_candidate.json> <winterfell_poc_real_proof_fixture.json> <bridge_backed_winterfell_proof_evidence.json>"
            .to_string(),
    ]
}
