use std::io::{self, Read};

use bl_pq512_crypto_core::air_ir::{MAX_AIR_BINARY_BYTES, evaluate_air_execution};

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for value in bytes {
        encoded.push(char::from(DIGITS[usize::from(value >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(value & 0x0f)]));
    }
    encoded
}

fn main() {
    let mut encoded = Vec::new();
    let limit = u64::try_from(MAX_AIR_BINARY_BYTES)
        .expect("binary cap fits u64")
        .saturating_add(1);
    if let Err(error) = io::stdin().take(limit).read_to_end(&mut encoded) {
        eprintln!("ERR:stdin:{error}");
        std::process::exit(2);
    }
    match evaluate_air_execution(&encoded) {
        Ok(report) => {
            println!("OK");
            println!(
                "source_program_commitment={}",
                hex(&report.source_program_commitment)
            );
            println!("binary_commitment={}", hex(&report.binary_commitment));
            println!("identities_evaluated={}", report.identities_evaluated);
            println!(
                "lookup_messages_evaluated={}",
                report.lookup_messages_evaluated
            );
            println!("maximum_degree={}", report.maximum_degree);
        }
        Err(error) => {
            eprintln!("ERR:{error:?}");
            std::process::exit(2);
        }
    }
}
