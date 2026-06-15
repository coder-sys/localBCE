use std::io::{self, BufRead, Read, Write};
use std::str::FromStr;

use ark_bn254::Fr;
use ark_ff::PrimeField;
use pso_poseidon::{Poseidon, PoseidonHasher};

fn parse_field(value: &str) -> Result<Fr, String> {
    Fr::from_str(value).map_err(|_| format!("invalid BN254 field element: {value}"))
}

fn hash_row(row: &[String]) -> Result<String, String> {
    if row.is_empty() {
        return Err("Poseidon row must contain at least one field".to_string());
    }
    let fields = row
        .iter()
        .map(|value| parse_field(value))
        .collect::<Result<Vec<_>, _>>()?;
    let mut hasher = Poseidon::<Fr>::new_circom(fields.len()).map_err(|err| err.to_string())?;
    let hash = hasher.hash(&fields).map_err(|err| err.to_string())?;
    Ok(hash.into_bigint().to_string())
}

fn hash_rows_json(input: &str) -> Result<Vec<String>, String> {
    let rows: Vec<Vec<String>> =
        serde_json::from_str(input).map_err(|err| format!("invalid JSON input: {err}"))?;
    rows.iter()
        .map(|row| hash_row(row))
        .collect::<Result<Vec<_>, _>>()
}

fn run_server() -> Result<(), String> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    for line in stdin.lock().lines() {
        let line = line.map_err(|err| format!("failed to read stdin: {err}"))?;
        if line.trim().is_empty() {
            continue;
        }
        let response = match hash_rows_json(&line) {
            Ok(hashes) => serde_json::json!({ "ok": hashes }),
            Err(err) => serde_json::json!({ "error": err }),
        };
        writeln!(stdout, "{}", response).map_err(|err| format!("failed to write stdout: {err}"))?;
        stdout.flush().map_err(|err| format!("failed to flush stdout: {err}"))?;
    }
    Ok(())
}

fn run() -> Result<(), String> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() == 1 && args[0] == "--server" {
        return run_server();
    }
    if !args.is_empty() {
        println!("{}", hash_row(&args)?);
        return Ok(());
    }

    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .map_err(|err| format!("failed to read stdin: {err}"))?;
    let hashes = hash_rows_json(&input)?;
    println!("{}", serde_json::to_string(&hashes).map_err(|err| err.to_string())?);
    Ok(())
}

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}
