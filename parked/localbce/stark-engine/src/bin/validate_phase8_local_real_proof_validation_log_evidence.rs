use std::{env, fs, process};

use stark_engine::real_prover::LocalRealProofValidationLogEvidence;

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
    let evidence: LocalRealProofValidationLogEvidence =
        serde_json::from_str(&input_json).map_err(|err| {
            vec![format!(
                "invalid Phase 8 local real proof validation log evidence JSON: {err}"
            )]
        })?;

    evidence.validate()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "phase8_local_real_proof_validation_log_evidence_validation",
            "status": "ok",
            "path": path,
            "schema_version": evidence.schema_version,
            "source_schema_version": evidence.source_schema_version,
            "evidence_slot": evidence.evidence_slot,
            "evidence_status": evidence.evidence_status,
            "candidate_log_path": evidence.candidate_log_path,
            "path_matches_expected": evidence.path_matches_expected,
            "validation_log_status": evidence.validation_log_status,
            "local_real_proof_verified": evidence.local_real_proof_verified,
            "required_log_field_count": evidence.required_log_field_count,
            "implementation_satisfied": evidence.implementation_satisfied,
            "accepted_as_complete_evidence": evidence.accepted_as_complete_evidence,
            "runtime_wiring_allowed": evidence.runtime_wiring_allowed,
            "real_proof_generation_allowed": evidence.real_proof_generation_allowed,
        })
    );

    Ok(())
}

fn usage() -> Vec<String> {
    vec![
        "usage: validate_phase8_local_real_proof_validation_log_evidence <phase8_local_real_proof_validation_log_evidence.json>"
            .to_string(),
    ]
}
