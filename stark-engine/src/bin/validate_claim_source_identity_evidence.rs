use std::{env, fs, process};

use stark_engine::ClaimSourceIdentityEvidence;

fn main() {
    if let Err(errors) = run() {
        for error in errors {
            eprintln!("{error}");
        }
        process::exit(1);
    }
}

fn run() -> Result<(), Vec<String>> {
    let path = env::args().nth(1).ok_or_else(usage)?;
    let input_json =
        fs::read_to_string(&path).map_err(|err| vec![format!("could not read {path}: {err}")])?;
    let evidence: ClaimSourceIdentityEvidence =
        serde_json::from_str(&input_json).map_err(|err| {
            vec![format!(
                "invalid claim source identity evidence JSON: {err}"
            )]
        })?;

    evidence.validate()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "claim_source_identity_evidence_validation",
            "status": "ok",
            "path": path,
            "schema_version": evidence.schema_version,
            "evidence_status": evidence.evidence_status,
            "claim_id": evidence.claim_id,
            "claim_hash": evidence.claim_hash,
            "field_count": evidence.field_count,
            "source_fields_present": evidence.source_fields_present,
            "candidate_fields_present": evidence.candidate_fields_present,
            "identity_sources_match_candidate_values": evidence.identity_sources_match_candidate_values,
            "production_semantics_complete": evidence.production_semantics_complete,
            "accepted_as_runtime_evidence": evidence.accepted_as_runtime_evidence,
            "runtime_wired": evidence.runtime_wired,
            "on_chain_submission": evidence.on_chain_submission,
        })
    );

    Ok(())
}

fn usage() -> Vec<String> {
    vec![
        "usage: validate_claim_source_identity_evidence <claim_source_identity_evidence.json>"
            .to_string(),
    ]
}
