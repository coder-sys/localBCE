use std::{env, fs, process};

use stark_engine::{
    PublicInputRootDigestCandidate, SourceRootAggregationPlan, SourceRootDigestCandidate,
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
    let public_input_root_path = args.next().ok_or_else(usage)?;
    let output_path = args.next().ok_or_else(usage)?;
    let source_root_paths: Vec<String> = args.collect();

    if source_root_paths.is_empty() {
        return Err(usage());
    }

    let public_input_root_json = fs::read_to_string(&public_input_root_path)
        .map_err(|err| vec![format!("could not read {public_input_root_path}: {err}")])?;
    let public_input_root: PublicInputRootDigestCandidate =
        serde_json::from_str(&public_input_root_json).map_err(|err| {
            vec![format!(
                "invalid public input root digest candidate JSON: {err}"
            )]
        })?;

    let mut source_roots = Vec::with_capacity(source_root_paths.len());
    for path in &source_root_paths {
        let input_json = fs::read_to_string(path)
            .map_err(|err| vec![format!("could not read {path}: {err}")])?;
        let candidate: SourceRootDigestCandidate =
            serde_json::from_str(&input_json).map_err(|err| {
                vec![format!(
                    "invalid source root digest candidate JSON {path}: {err}"
                )]
            })?;
        source_roots.push(candidate);
    }

    let plan = SourceRootAggregationPlan::from_candidates(&public_input_root, &source_roots)?;
    plan.validate()?;

    let output_json = serde_json::to_string_pretty(&plan).map_err(|err| {
        vec![format!(
            "could not serialize source root aggregation plan JSON: {err}"
        )]
    })?;
    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "source_root_aggregation_plan_generation",
            "status": "ok",
            "public_input_root": public_input_root_path,
            "output": output_path,
            "schema_version": plan.schema_version,
            "source_schema_version": plan.source_schema_version,
            "plan_status": plan.plan_status,
            "source_root_bindings": plan.source_root_bindings.len(),
            "expected_source_root_count": plan.expected_source_root_count,
            "all_source_roots_bound": plan.all_source_roots_bound,
            "root_generation_status": plan.root_generation_status,
            "production_hash_selected": plan.production_hash_selected,
            "runtime_wiring_allowed": plan.runtime_wiring_allowed,
            "groth16_flow_unchanged": plan.groth16_flow_unchanged,
        })
    );

    Ok(())
}

fn usage() -> Vec<String> {
    vec![
        "usage: generate_source_root_aggregation_plan <public_input_root_digest_candidate.json> <source_root_aggregation_plan.json> <source_root_digest_candidate.json>..."
            .to_string(),
    ]
}
