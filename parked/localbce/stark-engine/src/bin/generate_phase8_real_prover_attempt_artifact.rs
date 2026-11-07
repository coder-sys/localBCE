use std::{env, fs, process};

use stark_engine::real_prover::{RealProverAttemptArtifact, RealProverEvidenceRecord};

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
    let evidence_record_path = args.next().ok_or_else(usage)?;
    let output_path = args.next().ok_or_else(usage)?;

    if args.next().is_some() {
        return Err(usage());
    }

    let input_json = fs::read_to_string(&evidence_record_path)
        .map_err(|err| vec![format!("could not read {evidence_record_path}: {err}")])?;
    let evidence_record: RealProverEvidenceRecord =
        serde_json::from_str(&input_json).map_err(|err| {
            vec![format!(
                "invalid Phase 8 real prover evidence record JSON: {err}"
            )]
        })?;

    let artifact = RealProverAttemptArtifact::blocked_from_evidence_record(&evidence_record)?;
    artifact.validate()?;

    let output_json = serde_json::to_string_pretty(&artifact).map_err(|err| {
        vec![format!(
            "could not serialize Phase 8 real prover attempt artifact JSON: {err}"
        )]
    })?;
    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "phase8_real_prover_attempt_artifact_generation",
            "status": "ok",
            "input": evidence_record_path,
            "output": output_path,
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
        "usage: generate_phase8_real_prover_attempt_artifact <phase8_real_prover_evidence_record.json> <phase8_real_prover_attempt_artifact.json>"
            .to_string(),
    ]
}
