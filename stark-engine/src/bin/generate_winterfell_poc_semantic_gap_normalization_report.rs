use std::{env, process};

fn main() {
    if let Err(errors) = run() {
        for error in errors {
            eprintln!("{error}");
        }
        process::exit(1);
    }
}

#[cfg(feature = "winterfell-poc")]
fn run() -> Result<(), Vec<String>> {
    use std::fs;

    use stark_engine::{
        StarkBridgeInput, WinterfellCompleteWitnessCandidate,
        winterfell_poc_adapter::{
            WinterfellPocSemanticEquivalenceReport, WinterfellPocSemanticGapNormalizationReport,
        },
    };

    let mut args = env::args();
    let _binary = args.next();
    let bridge_input_path = args.next().ok_or_else(usage)?;
    let complete_candidate_path = args.next().ok_or_else(usage)?;
    let equivalence_report_path = args.next().ok_or_else(usage)?;
    let output_path = args.next().ok_or_else(usage)?;

    if args.next().is_some() {
        return Err(usage());
    }

    let bridge_input: StarkBridgeInput = read_json(&bridge_input_path, "STARK bridge input")?;
    let complete_candidate: WinterfellCompleteWitnessCandidate = read_json(
        &complete_candidate_path,
        "complete Winterfell witness candidate",
    )?;
    let equivalence_report: WinterfellPocSemanticEquivalenceReport = read_json(
        &equivalence_report_path,
        "Winterfell PoC semantic equivalence report",
    )?;

    let report = WinterfellPocSemanticGapNormalizationReport::from_inputs(
        &bridge_input,
        &complete_candidate,
        &equivalence_report,
    )?;
    report.validate()?;

    let output_json = serde_json::to_string_pretty(&report).map_err(|err| {
        vec![format!(
            "could not serialize Winterfell PoC semantic gap normalization report JSON: {err}"
        )]
    })?;
    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "winterfell_poc_semantic_gap_normalization_report_generation",
            "status": "ok",
            "output": output_path,
            "schema_version": report.schema_version,
            "report_status": report.report_status,
            "partial_field_count": report.partial_field_count,
            "partial_fields_resolved": report.partial_fields_resolved,
            "unmapped_field_count": report.unmapped_field_count,
            "unmapped_source_data_populated": report.unmapped_source_data_populated,
            "unmapped_semantics_resolved": report.unmapped_semantics_resolved,
            "all_poc_fields_populated": report.all_poc_fields_populated,
            "production_semantics_complete": report.production_semantics_complete,
            "accepted_as_runtime_evidence": report.accepted_as_runtime_evidence,
            "runtime_wired": report.runtime_wired,
            "on_chain_submission": report.on_chain_submission,
        })
    );

    Ok(())
}

#[cfg(not(feature = "winterfell-poc"))]
fn run() -> Result<(), Vec<String>> {
    let _ = env::args();
    Err(vec![
        "generate_winterfell_poc_semantic_gap_normalization_report requires --features winterfell-poc"
            .to_string(),
        "usage: cargo run --features winterfell-poc --bin generate_winterfell_poc_semantic_gap_normalization_report -- <stark_bridge_input.json> <complete_winterfell_witness_candidate.json> <winterfell_poc_semantic_equivalence_report.json> <winterfell_poc_semantic_gap_normalization_report.json>"
            .to_string(),
    ])
}

#[cfg(feature = "winterfell-poc")]
fn read_json<T: serde::de::DeserializeOwned>(path: &str, label: &str) -> Result<T, Vec<String>> {
    let input_json = std::fs::read_to_string(path)
        .map_err(|err| vec![format!("could not read {path}: {err}")])?;
    serde_json::from_str(&input_json).map_err(|err| vec![format!("invalid {label} JSON: {err}")])
}

#[cfg(feature = "winterfell-poc")]
fn usage() -> Vec<String> {
    vec![
        "usage: generate_winterfell_poc_semantic_gap_normalization_report <stark_bridge_input.json> <complete_winterfell_witness_candidate.json> <winterfell_poc_semantic_equivalence_report.json> <winterfell_poc_semantic_gap_normalization_report.json>"
            .to_string(),
    ]
}
