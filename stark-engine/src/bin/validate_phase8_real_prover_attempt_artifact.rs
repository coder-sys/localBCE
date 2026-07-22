use std::{env, fs, process};

use stark_engine::real_prover::RealProverAttemptArtifact;

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
    let artifact: RealProverAttemptArtifact = serde_json::from_str(&input_json).map_err(|err| {
        vec![format!(
            "invalid Phase 8 real prover attempt artifact JSON: {err}"
        )]
    })?;

    artifact.validate()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "phase8_real_prover_attempt_artifact_validation",
            "status": "ok",
            "path": path,
            "schema_version": artifact.schema_version,
            "source_schema_version": artifact.source_schema_version,
            "attempt_status": artifact.attempt_status,
            "blocker_status": artifact.blocker_status,
            "missing_evidence_count": artifact.missing_evidence_count,
            "populated_evidence_count": artifact.populated_evidence_count,
            "attempted_real_proof_generation": artifact.attempted_real_proof_generation,
            "emitted_real_proof_bytes": artifact.emitted_real_proof_bytes,
            "local_real_proof_verified": artifact.local_real_proof_verified,
            "runtime_wiring_allowed": artifact.runtime_wiring_allowed,
            "real_proof_generation_allowed": artifact.real_proof_generation_allowed,
        })
    );

    Ok(())
}

fn usage() -> Vec<String> {
    vec![
        "usage: validate_phase8_real_prover_attempt_artifact <phase8_real_prover_attempt_artifact.json>"
            .to_string(),
    ]
}
