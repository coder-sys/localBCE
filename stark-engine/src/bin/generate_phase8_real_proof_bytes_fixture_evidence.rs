use std::{env, fs, process};

use stark_engine::real_prover::{
    LocalRealProofValidationLogEvidence, RealProofBytesFixtureEvidence,
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
    let validation_log_evidence_path = args.next().ok_or_else(usage)?;
    let output_path = args.next().ok_or_else(usage)?;

    if args.next().is_some() {
        return Err(usage());
    }

    let input_json = fs::read_to_string(&validation_log_evidence_path).map_err(|err| {
        vec![format!(
            "could not read {validation_log_evidence_path}: {err}"
        )]
    })?;
    let validation_log_evidence: LocalRealProofValidationLogEvidence =
        serde_json::from_str(&input_json).map_err(|err| {
            vec![format!(
                "invalid Phase 8 local real proof validation log evidence JSON: {err}"
            )]
        })?;

    let evidence =
        RealProofBytesFixtureEvidence::from_validation_log_evidence(&validation_log_evidence)?;
    evidence.validate()?;

    let output_json = serde_json::to_string_pretty(&evidence).map_err(|err| {
        vec![format!(
            "could not serialize Phase 8 real proof bytes fixture evidence JSON: {err}"
        )]
    })?;
    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "phase8_real_proof_bytes_fixture_evidence_generation",
            "status": "ok",
            "input": validation_log_evidence_path,
            "output": output_path,
            "schema_version": evidence.schema_version,
            "source_schema_version": evidence.source_schema_version,
            "evidence_slot": evidence.evidence_slot,
            "evidence_status": evidence.evidence_status,
            "candidate_fixture_path": evidence.candidate_fixture_path,
            "fixture_status": evidence.fixture_status,
            "proof_bytes_present": evidence.proof_bytes_present,
            "proof_bytes_digest_present": evidence.proof_bytes_digest_present,
            "test_only_bytes_rejected": evidence.test_only_bytes_rejected,
            "local_real_proof_verified": evidence.local_real_proof_verified,
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
        "usage: generate_phase8_real_proof_bytes_fixture_evidence <phase8_local_real_proof_validation_log_evidence.json> <phase8_real_proof_bytes_fixture_evidence.json>"
            .to_string(),
    ]
}
