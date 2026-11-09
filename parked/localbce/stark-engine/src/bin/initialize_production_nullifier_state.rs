use std::{env, path::Path, process};

use stark_engine::production_nullifier_state::{
    ProductionNullifierStateV1, acquire_production_nullifier_state_lock,
    write_production_nullifier_state_atomic,
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
    let output_path = args.next().ok_or_else(usage)?;
    if args.next().is_some() {
        return Err(usage());
    }
    let _lock = acquire_production_nullifier_state_lock(&output_path)?;
    if Path::new(&output_path).exists() {
        return Err(vec![format!(
            "refusing to overwrite existing nullifier state {output_path}"
        )]);
    }
    let state = ProductionNullifierStateV1::empty()?;
    write_production_nullifier_state_atomic(&output_path, &state)?;
    println!(
        "{}",
        serde_json::json!({
            "event": "production_nullifier_state_initialization",
            "status": "ok",
            "output": output_path,
            "schema_version": state.schema_version,
            "generation": state.generation,
            "root": state.root_bytes32,
            "committed_leaves": state.leaves.len(),
            "groth16_flow_unchanged": state.groth16_flow_unchanged,
        })
    );
    Ok(())
}

fn usage() -> Vec<String> {
    vec!["usage: initialize_production_nullifier_state <nullifier_state.json>".to_string()]
}
