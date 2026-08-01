use bl_pq512_crypto_core::field::M31;
use bl_pq512_crypto_core::sha3_boolean_air::{BooleanSha3Call, for_each_boolean_sha3_trace_row};
use sha3::{Digest, Sha3_512};

const DOMAIN: &[u8] = b"BL/PQ512/WAVE1A/SHA3-BOOLEAN-TRACE/v1\0";

fn decode_hex(encoded: &str) -> Result<Vec<u8>, String> {
    if !encoded.len().is_multiple_of(2) {
        return Err("hex_length".to_string());
    }
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |value: u8| match value {
                b'0'..=b'9' => Ok(value - b'0'),
                b'a'..=b'f' => Ok(value - b'a' + 10),
                b'A'..=b'F' => Ok(value - b'A' + 10),
                _ => Err("hex_digit".to_string()),
            };
            Ok((digit(pair[0])? << 4) | digit(pair[1])?)
        })
        .collect()
}

fn update_row(hash: &mut Sha3_512, row: &[M31]) {
    hash.update((row.len() as u32).to_be_bytes());
    for value in row {
        hash.update(value.as_u32().to_be_bytes());
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(DIGITS[usize::from(byte >> 4)] as char);
        encoded.push(DIGITS[usize::from(byte & 15)] as char);
    }
    encoded
}

fn run() -> Result<(), String> {
    let specifications = std::env::args().skip(1).collect::<Vec<_>>();
    if specifications.is_empty() {
        return Err("calls_missing".to_string());
    }
    let mut capacities = Vec::with_capacity(specifications.len());
    let mut messages = Vec::with_capacity(specifications.len());
    for specification in &specifications {
        let (capacity, encoded) = specification
            .split_once(':')
            .ok_or_else(|| "call_shape".to_string())?;
        capacities.push(
            capacity
                .parse::<usize>()
                .map_err(|_| "capacity".to_string())?,
        );
        messages.push(decode_hex(encoded)?);
    }
    let calls = messages
        .iter()
        .zip(capacities)
        .map(|(message, capacity)| BooleanSha3Call { message, capacity })
        .collect::<Vec<_>>();
    let mut round = Sha3_512::new();
    round.update(DOMAIN);
    round.update([0]);
    let mut absorb = Sha3_512::new();
    absorb.update(DOMAIN);
    absorb.update([1]);
    let mut digest = Sha3_512::new();
    digest.update(DOMAIN);
    digest.update([2]);
    let report = for_each_boolean_sha3_trace_row(
        &calls,
        |row| update_row(&mut round, row),
        |row| update_row(&mut absorb, row),
        |row| update_row(&mut digest, row),
    )
    .map_err(|error| format!("trace_{error:?}"))?;
    round.update((report.round_rows as u64).to_be_bytes());
    absorb.update((report.absorb_rows as u64).to_be_bytes());
    digest.update((report.digest_rows as u64).to_be_bytes());
    println!("calls={}", report.calls);
    println!("permutations={}", report.permutations);
    println!("round_rows={}", report.round_rows);
    println!("absorb_rows={}", report.absorb_rows);
    println!("digest_rows={}", report.digest_rows);
    println!("round_commitment={}", encode_hex(&round.finalize()));
    println!("absorb_commitment={}", encode_hex(&absorb.finalize()));
    println!("digest_commitment={}", encode_hex(&digest.finalize()));
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("Boolean SHA3 trace commitment failed: {error}");
        std::process::exit(1);
    }
}
