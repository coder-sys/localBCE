use std::{env, fs, process};

use stark_engine::{
    Phase8PreProverBundleCheckpoint, ProofArtifactFixtureExpectationSet,
    ProofCommitmentPreimagePlan, PublicInputRootDigestCandidate, SelectedProverByteEncodingPlan,
    SourceRootAggregationPlan, StarkProofArtifactV1BoundarySpec,
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
    let args: Vec<String> = env::args().collect();
    if args.len() != 8 {
        return Err(usage());
    }

    let boundary_spec: StarkProofArtifactV1BoundarySpec = read_json(&args[1])?;
    let public_input_root: PublicInputRootDigestCandidate = read_json(&args[2])?;
    let source_root_aggregation: SourceRootAggregationPlan = read_json(&args[3])?;
    let proof_commitment: ProofCommitmentPreimagePlan = read_json(&args[4])?;
    let fixture_expectations: ProofArtifactFixtureExpectationSet = read_json(&args[5])?;
    let byte_encoding: SelectedProverByteEncodingPlan = read_json(&args[6])?;
    let output_path = &args[7];

    let checkpoint = Phase8PreProverBundleCheckpoint::from_artifacts(
        &boundary_spec,
        &public_input_root,
        &source_root_aggregation,
        &proof_commitment,
        &fixture_expectations,
        &byte_encoding,
    )?;
    checkpoint.validate()?;

    let output_json = serde_json::to_string_pretty(&checkpoint).map_err(|err| {
        vec![format!(
            "could not serialize Phase 8 pre-prover bundle checkpoint JSON: {err}"
        )]
    })?;
    fs::write(output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "phase8_pre_prover_bundle_checkpoint_generation",
            "status": "ok",
            "output": output_path,
            "schema_version": checkpoint.schema_version,
            "source_schema_version": checkpoint.source_schema_version,
            "checkpoint_status": checkpoint.checkpoint_status,
            "artifacts": checkpoint.artifacts.len(),
            "all_artifacts_validated": checkpoint.all_artifacts_validated,
            "all_source_roots_bound": checkpoint.all_source_roots_bound,
            "production_hash_selected": checkpoint.production_hash_selected,
            "runtime_wiring_allowed": checkpoint.runtime_wiring_allowed,
            "proof_generation_enabled": checkpoint.proof_generation_enabled,
            "groth16_flow_unchanged": checkpoint.groth16_flow_unchanged,
        })
    );

    Ok(())
}

fn read_json<T: serde::de::DeserializeOwned>(path: &str) -> Result<T, Vec<String>> {
    let input_json =
        fs::read_to_string(path).map_err(|err| vec![format!("could not read {path}: {err}")])?;
    serde_json::from_str(&input_json).map_err(|err| vec![format!("invalid JSON {path}: {err}")])
}

fn usage() -> Vec<String> {
    vec![
        "usage: generate_phase8_pre_prover_bundle_checkpoint <boundary_spec.json> <public_input_root_digest_candidate.json> <source_root_aggregation_plan.json> <proof_commitment_preimage_plan.json> <proof_artifact_fixture_expectations.json> <selected_prover_byte_encoding_plan.json> <phase8_pre_prover_bundle_checkpoint.json>"
            .to_string(),
    ]
}
