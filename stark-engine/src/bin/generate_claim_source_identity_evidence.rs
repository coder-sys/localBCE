use std::{env, fs, process};

use stark_engine::{
    ClaimSourceIdentityEvidence, ClaimSourceRootInput, WinterfellCompleteWitnessCandidate,
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
    let claim_source_path = args.next().ok_or_else(usage)?;
    let complete_candidate_path = args.next().ok_or_else(usage)?;
    let output_path = args.next().ok_or_else(usage)?;

    if args.next().is_some() {
        return Err(usage());
    }

    let claim_source: ClaimSourceRootInput =
        read_json(&claim_source_path, "claim source root input")?;
    let complete_candidate: WinterfellCompleteWitnessCandidate = read_json(
        &complete_candidate_path,
        "complete Winterfell witness candidate",
    )?;

    let evidence = ClaimSourceIdentityEvidence::from_claim_source_and_candidate(
        &claim_source,
        &complete_candidate,
    )?;
    evidence.validate()?;

    let output_json = serde_json::to_string_pretty(&evidence).map_err(|err| {
        vec![format!(
            "could not serialize claim source identity evidence JSON: {err}"
        )]
    })?;
    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "claim_source_identity_evidence_generation",
            "status": "ok",
            "claim_source_input": claim_source_path,
            "complete_candidate": complete_candidate_path,
            "output": output_path,
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

fn read_json<T: serde::de::DeserializeOwned>(path: &str, label: &str) -> Result<T, Vec<String>> {
    let input_json =
        fs::read_to_string(path).map_err(|err| vec![format!("could not read {path}: {err}")])?;
    serde_json::from_str(&input_json).map_err(|err| vec![format!("invalid {label} JSON: {err}")])
}

fn usage() -> Vec<String> {
    vec![
        "usage: generate_claim_source_identity_evidence <claim_source_root_input.json> <complete_winterfell_witness_candidate.json> <claim_source_identity_evidence.json>"
            .to_string(),
    ]
}
