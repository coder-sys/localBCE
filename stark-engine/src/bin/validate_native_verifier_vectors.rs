use std::{env, fs, process};

use serde_json::json;
use stark_engine::native_verifier_candidate::WinterfellNativeVerifierVectorSetV1;

fn main() {
    let args = env::args().collect::<Vec<_>>();
    if args.len() != 2 {
        eprintln!("usage: validate_native_verifier_vectors <vectors.json>");
        process::exit(2);
    }
    let result = fs::read_to_string(&args[1])
        .map_err(|error| vec![format!("could not read input: {error}")])
        .and_then(|value| {
            serde_json::from_str::<WinterfellNativeVerifierVectorSetV1>(&value)
                .map_err(|error| vec![format!("invalid vectors JSON: {error}")])
        })
        .and_then(|value| value.validate().map(|_| value));
    match result {
        Ok(value) => println!(
            "{}",
            json!({"status":"ok","mutation_vectors":value.mutation_vectors.len(),"activation_allowed":value.activation_gates.activation_allowed})
        ),
        Err(errors) => {
            eprintln!("{}", json!({"status":"error","errors":errors}));
            process::exit(1);
        }
    }
}
