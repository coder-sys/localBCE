use std::{env, fs, path::PathBuf, process};

use serde_json::json;
use stark_engine::{
    native_verifier_candidate::WinterfellNativeVerifierVectorSetV1,
    production_proof_artifact::ProductionStarkProofArtifactV4,
};

fn main() {
    if let Err(errors) = run() {
        eprintln!("{}", json!({"status": "error", "errors": errors}));
        process::exit(1);
    }
}

fn run() -> Result<(), Vec<String>> {
    let args = env::args().collect::<Vec<_>>();
    if args.len() != 3 {
        return Err(vec!["usage: generate_native_verifier_vectors <production_proof_artifact.json> <vectors.json>".to_string()]);
    }
    let artifact: ProductionStarkProofArtifactV4 = serde_json::from_str(
        &fs::read_to_string(&args[1])
            .map_err(|error| vec![format!("could not read input: {error}")])?,
    )
    .map_err(|error| vec![format!("invalid proof artifact JSON: {error}")])?;
    let vectors = WinterfellNativeVerifierVectorSetV1::from_artifact(&artifact)?;
    let output = PathBuf::from(&args[2]);
    fs::write(
        &output,
        format!("{}\n", serde_json::to_string_pretty(&vectors).unwrap()),
    )
    .map_err(|error| vec![format!("could not write {}: {error}", output.display())])?;
    println!(
        "{}",
        json!({"status":"ok","output":output,"mutation_vectors":vectors.mutation_vectors.len(),"activation_allowed":false})
    );
    Ok(())
}
