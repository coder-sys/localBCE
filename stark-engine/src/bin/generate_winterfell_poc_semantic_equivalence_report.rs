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
        StarkBridgeInput,
        winterfell_poc_adapter::{
            WinterfellPocRealProofFixture, WinterfellPocSemanticEquivalenceReport,
        },
    };

    let mut args = env::args();
    let _binary = args.next();
    let bridge_input_path = args.next().ok_or_else(usage)?;
    let proof_fixture_path = args.next().ok_or_else(usage)?;
    let output_path = args.next().ok_or_else(usage)?;

    if args.next().is_some() {
        return Err(usage());
    }

    let bridge_input: StarkBridgeInput = read_json(&bridge_input_path, "STARK bridge input")?;
    let proof_fixture: WinterfellPocRealProofFixture =
        read_json(&proof_fixture_path, "Winterfell PoC real proof fixture")?;

    let report = WinterfellPocSemanticEquivalenceReport::from_bridge_and_fixture(
        &bridge_input,
        &proof_fixture,
    )?;
    report.validate()?;

    let output_json = serde_json::to_string_pretty(&report).map_err(|err| {
        vec![format!(
            "could not serialize Winterfell PoC semantic equivalence report JSON: {err}"
        )]
    })?;
    fs::write(&output_path, format!("{output_json}\n"))
        .map_err(|err| vec![format!("could not write {output_path}: {err}")])?;

    println!(
        "{}",
        serde_json::json!({
            "event": "winterfell_poc_semantic_equivalence_report_generation",
            "status": "ok",
            "output": output_path,
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
        "generate_winterfell_poc_semantic_equivalence_report requires --features winterfell-poc"
            .to_string(),
        "usage: cargo run --features winterfell-poc --bin generate_winterfell_poc_semantic_equivalence_report -- <stark_bridge_input.json> <winterfell_poc_real_proof_fixture.json> <winterfell_poc_semantic_equivalence_report.json>"
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
        "usage: generate_winterfell_poc_semantic_equivalence_report <stark_bridge_input.json> <winterfell_poc_real_proof_fixture.json> <winterfell_poc_semantic_equivalence_report.json>"
            .to_string(),
    ]
}
