use std::{env, fs, process};

use stark_engine::{WinterfellCompleteWitnessCandidate, real_prover::TestOnlyProofBytes};

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
    let candidate_path = args.next().ok_or_else(usage)?;
    let output_path = args.next().ok_or_else(usage)?;

    if args.next().is_some() {
        return Err(usage());
    }

    let candidate_json = fs::read_to_string(&candidate_path)
        .map_err(|err| vec![format!("could not read {candidate_path}: {err}")])?;
    let candidate: WinterfellCompleteWitnessCandidate = serde_json::from_str(&candidate_json)
        .map_err(|err| {
            vec![format!(
                "invalid complete Winterfell witness candidate JSON: {err}"
            )]
        })?;

    let proof_bytes = TestOnlyProofBytes::from_complete_witness_candidate(&candidate)?;
    proof_bytes.validate()?;

    let output_json = serde_json::to_string_pretty(&proof_bytes).map_err(|err| {
        vec![format!(
            "could not serialize Phase 8 test-only proof bytes JSON: {err}"
        )]
    })?;
    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "phase8_test_only_proof_bytes_generation",
            "status": "ok",
            "input": candidate_path,
            "output": output_path,
            "schema_version": proof_bytes.schema_version,
            "source_schema_version": proof_bytes.source_schema_version,
            "byte_status": proof_bytes.byte_status,
            "transformation_id": proof_bytes.transformation_id,
            "claim_id": proof_bytes.claim_id,
            "claim_hash": proof_bytes.claim_hash,
            "byte_length": proof_bytes.byte_length,
            "runtime_wiring_allowed": proof_bytes.runtime_wiring_allowed,
            "real_proof_generation_allowed": proof_bytes.real_proof_generation_allowed,
            "accepted_as_implementation_evidence": proof_bytes.accepted_as_implementation_evidence,
        })
    );

    Ok(())
}

fn usage() -> Vec<String> {
    vec![
        "usage: generate_phase8_test_only_proof_bytes <complete_winterfell_witness_candidate.json> <phase8_test_only_proof_bytes.json>"
            .to_string(),
    ]
}
