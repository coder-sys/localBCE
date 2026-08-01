use std::io::{self, Read};

use bl_pq512_crypto_core::air_ir::{MAX_AIR_BINARY_BYTES, validate_air_program};

fn hex(value: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(DIGITS[usize::from(byte >> 4)] as char);
        output.push(DIGITS[usize::from(byte & 15)] as char);
    }
    output
}

fn main() {
    let mut encoded = Vec::new();
    if io::stdin()
        .take((MAX_AIR_BINARY_BYTES + 1) as u64)
        .read_to_end(&mut encoded)
        .is_err()
        || encoded.len() > MAX_AIR_BINARY_BYTES
    {
        eprintln!("air_program_input_invalid");
        std::process::exit(2);
    }
    match validate_air_program(&encoded) {
        Ok(report) => println!(
            "source={} binary={} tables={} columns={} identities={} lookups={} public_inputs={}",
            hex(&report.source_program_commitment),
            hex(&report.program_binary_commitment),
            report.table_count,
            report.trace_column_count,
            report.identity_count,
            report.lookup_count,
            report.public_input_count,
        ),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    }
}
