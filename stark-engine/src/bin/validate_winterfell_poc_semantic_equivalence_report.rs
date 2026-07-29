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

    use stark_engine::winterfell_poc_adapter::WinterfellPocSemanticEquivalenceReport;

    let path = env::args().nth(1).ok_or_else(usage)?;

    let input_json =
        fs::read_to_string(&path).map_err(|err| vec![format!("could not read {path}: {err}")])?;
    let report: WinterfellPocSemanticEquivalenceReport = serde_json::from_str(&input_json)
        .map_err(|err| {
            vec![format!(
                "invalid Winterfell PoC semantic equivalence report JSON: {err}"
            )]
        })?;

    report.validate()?;

    println!(
        "{}",
        serde_json::json!({
            "event": "winterfell_poc_semantic_equivalence_report_validation",
            "status": "ok",
            "path": path,
            "schema_version": report.schema_version,
            "report_status": report.report_status,
            "public_inputs_match": report.public_inputs_match,
            "direct_semantics_match": report.direct_semantics_match,
            "partial_semantics_resolved": report.partial_semantics_resolved,
            "unmapped_semantics_resolved": report.unmapped_semantics_resolved,
            "proof_fixture_verified": report.proof_fixture_verified,
            "production_semantics_complete": report.production_semantics_complete,
            "accepted_as_runtime_evidence": report.accepted_as_runtime_evidence,
            "runtime_wired": report.runtime_wired,
            "on_chain_submission": report.on_chain_submission,
            "blocker_count": report.blocker_count,
        })
    );

    Ok(())
}

#[cfg(not(feature = "winterfell-poc"))]
fn run() -> Result<(), Vec<String>> {
    let _ = env::args();
    Err(vec![
        "validate_winterfell_poc_semantic_equivalence_report requires --features winterfell-poc"
            .to_string(),
        "usage: cargo run --features winterfell-poc --bin validate_winterfell_poc_semantic_equivalence_report -- <winterfell_poc_semantic_equivalence_report.json>"
            .to_string(),
    ])
}

#[cfg(feature = "winterfell-poc")]
fn usage() -> Vec<String> {
    vec![
        "usage: validate_winterfell_poc_semantic_equivalence_report <winterfell_poc_semantic_equivalence_report.json>"
            .to_string(),
    ]
}
