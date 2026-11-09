use std::{env, fs, process};

use stark_engine::BridgeBackedWinterfellProofEvidence;

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
    let path = args.next().ok_or_else(usage)?;
    if args.next().is_some() {
        return Err(usage());
    }

    let input_json =
        fs::read_to_string(&path).map_err(|err| vec![format!("could not read {path}: {err}")])?;
    let evidence: BridgeBackedWinterfellProofEvidence =
        serde_json::from_str(&input_json).map_err(|err| {
            vec![format!(
                "invalid bridge-backed Winterfell proof evidence JSON: {err}"
            )]
        })?;
    evidence.validate()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "bridge_backed_winterfell_proof_evidence_validation",
            "status": "ok",
            "path": path,
            "schema_version": evidence.schema_version,
            "evidence_status": evidence.evidence_status,
            "claim_id": evidence.claim_id,
            "claim_hash": evidence.claim_hash,
            "proof_bytes_len": evidence.proof_bytes_len,
            "proof_bytes_sha256": evidence.proof_bytes_sha256,
            "verified": evidence.verified,
            "fixture_substitution": evidence.fixture_substitution,
            "production_semantics_complete": evidence.production_semantics_complete,
            "accepted_as_runtime_evidence": evidence.accepted_as_runtime_evidence,
            "runtime_wired": evidence.runtime_wired,
            "on_chain_submission": evidence.on_chain_submission,
            "groth16_flow_unchanged": evidence.groth16_flow_unchanged,
        })
    );

    Ok(())
}

fn usage() -> Vec<String> {
    vec![
        "usage: validate_bridge_backed_winterfell_proof_evidence <bridge_backed_winterfell_proof_evidence.json>"
            .to_string(),
    ]
}
