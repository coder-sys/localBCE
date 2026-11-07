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

    use stark_engine::winterfell_poc_adapter::WinterfellPocSemanticGapNormalizationReport;

    let path = env::args().nth(1).ok_or_else(usage)?;

    let input_json =
        fs::read_to_string(&path).map_err(|err| vec![format!("could not read {path}: {err}")])?;
    let report: WinterfellPocSemanticGapNormalizationReport = serde_json::from_str(&input_json)
        .map_err(|err| {
            vec![format!(
                "invalid Winterfell PoC semantic gap normalization report JSON: {err}"
            )]
        })?;

    report.validate()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "winterfell_poc_semantic_gap_normalization_report_validation",
            "status": "ok",
            "path": path,
            "schema_version": report.schema_version,
            "report_status": report.report_status,
            "partial_field_count": report.partial_field_count,
            "partial_fields_resolved": report.partial_fields_resolved,
            "unmapped_field_count": report.unmapped_field_count,
            "unmapped_source_data_populated": report.unmapped_source_data_populated,
            "active_bridge_source_backed_field_count": report.active_bridge_source_backed_field_count,
            "fixture_backed_field_count": report.fixture_backed_field_count,
            "all_unmapped_fields_source_backed": report.all_unmapped_fields_source_backed,
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
        "validate_winterfell_poc_semantic_gap_normalization_report requires --features winterfell-poc"
            .to_string(),
        "usage: cargo run --features winterfell-poc --bin validate_winterfell_poc_semantic_gap_normalization_report -- <winterfell_poc_semantic_gap_normalization_report.json>"
            .to_string(),
    ])
}

#[cfg(feature = "winterfell-poc")]
fn usage() -> Vec<String> {
    vec![
        "usage: validate_winterfell_poc_semantic_gap_normalization_report <winterfell_poc_semantic_gap_normalization_report.json>"
            .to_string(),
    ]
}
