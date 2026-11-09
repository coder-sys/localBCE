use std::{env, fs, process};

use stark_engine::real_prover::{RealProverAdapterInvocation, RealProverCodePathEvidence};

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
    let adapter_invocation_path = args.next().ok_or_else(usage)?;
    let output_path = args.next().ok_or_else(usage)?;

    if args.next().is_some() {
        return Err(usage());
    }

    let input_json = fs::read_to_string(&adapter_invocation_path)
        .map_err(|err| vec![format!("could not read {adapter_invocation_path}: {err}")])?;
    let invocation: RealProverAdapterInvocation =
        serde_json::from_str(&input_json).map_err(|err| {
            vec![format!(
                "invalid Phase 8 real prover adapter invocation JSON: {err}"
            )]
        })?;

    let evidence = RealProverCodePathEvidence::from_adapter_invocation(&invocation)?;
    evidence.validate()?;

    let output_json = serde_json::to_string_pretty(&evidence).map_err(|err| {
        vec![format!(
            "could not serialize Phase 8 real prover code path evidence JSON: {err}"
        )]
    })?;
    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "phase8_real_prover_code_path_evidence_generation",
            "status": "ok",
            "input": adapter_invocation_path,
            "output": output_path,
            "schema_version": evidence.schema_version,
            "source_schema_version": evidence.source_schema_version,
            "evidence_slot": evidence.evidence_slot,
            "evidence_status": evidence.evidence_status,
            "candidate_code_path": evidence.candidate_code_path,
            "path_matches_expected": evidence.path_matches_expected,
            "source_module_status": evidence.source_module_status,
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
        "usage: generate_phase8_real_prover_code_path_evidence <phase8_real_prover_adapter_invocation.json> <phase8_real_prover_code_path_evidence.json>"
            .to_string(),
    ]
}
