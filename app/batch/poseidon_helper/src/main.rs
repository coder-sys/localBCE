use std::io::{self, BufRead, Read, Write};

use starknet_crypto::{poseidon_hash_many, Felt};

const MAX_INPUT_BYTES: usize = 1_048_576;
const MAX_ROWS: usize = 4096;
const MAX_FIELDS_PER_ROW: usize = 128;

fn parse_field(value: &str) -> Result<Felt, String> {
    Felt::from_dec_str(value).map_err(|_| format!("invalid Cairo field element: {value}"))
}

fn hash_row(row: &[String]) -> Result<String, String> {
    if row.len() < 2 {
        return Err("Poseidon row must contain a domain tag and arity".to_string());
    }
    if row.len() > MAX_FIELDS_PER_ROW {
        return Err("Poseidon row has too many fields".to_string());
    }
    let arity = row[1]
        .parse::<usize>()
        .map_err(|_| "Poseidon row arity must be a usize".to_string())?;
    if arity != row.len() - 2 {
        return Err("Poseidon row arity mismatch".to_string());
    }
    let fields = row
        .iter()
        .map(|value| parse_field(value))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(poseidon_hash_many(&fields).to_string())
}

fn hash_rows_json(input: &str) -> Result<Vec<String>, String> {
    if input.len() > MAX_INPUT_BYTES {
        return Err("Poseidon request too large".to_string());
    }
    let rows: Vec<Vec<String>> =
        serde_json::from_str(input).map_err(|err| format!("invalid JSON input: {err}"))?;
    if rows.len() > MAX_ROWS {
        return Err("Poseidon request has too many rows".to_string());
    }
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
    if input.len() > MAX_INPUT_BYTES {
        return Err("Poseidon request too large".to_string());
    }
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
