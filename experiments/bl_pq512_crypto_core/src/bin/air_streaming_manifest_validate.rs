use std::io::{self, Read};

use bl_pq512_crypto_core::air_ir::MAX_AIR_BINARY_BYTES;
use bl_pq512_crypto_core::streaming_ir::{
    MAX_STREAMING_MANIFEST_BYTES, decode_streaming_air_manifest,
};

fn hex(value: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(DIGITS[usize::from(byte >> 4)] as char);
        output.push(DIGITS[usize::from(byte & 15)] as char);
    }
    output
}

fn read_u32(encoded: &[u8], offset: &mut usize) -> Option<usize> {
    let end = offset.checked_add(4)?;
    let value = u32::from_be_bytes(encoded.get(*offset..end)?.try_into().ok()?);
    *offset = end;
    usize::try_from(value).ok()
}

fn main() {
    let maximum_input = MAX_AIR_BINARY_BYTES
        .checked_add(MAX_STREAMING_MANIFEST_BYTES)
        .and_then(|value| value.checked_add(8))
        .expect("streaming validator input cap fits usize");
    let mut encoded = Vec::new();
    if io::stdin()
        .take((maximum_input + 1) as u64)
        .read_to_end(&mut encoded)
        .is_err()
        || encoded.len() > maximum_input
    {
        eprintln!("streaming_manifest_input_invalid");
        std::process::exit(2);
    }

    let mut offset = 0usize;
    let Some(program_length) = read_u32(&encoded, &mut offset) else {
        eprintln!("streaming_manifest_framing_invalid");
        std::process::exit(2);
    };
    if program_length == 0 || program_length > MAX_AIR_BINARY_BYTES {
        eprintln!("streaming_manifest_program_length_invalid");
        std::process::exit(2);
    }
    let Some(program_end) = offset.checked_add(program_length) else {
        eprintln!("streaming_manifest_framing_invalid");
        std::process::exit(2);
    };
    let Some(program) = encoded.get(offset..program_end) else {
        eprintln!("streaming_manifest_framing_invalid");
        std::process::exit(2);
    };
    offset = program_end;

    let Some(manifest_length) = read_u32(&encoded, &mut offset) else {
        eprintln!("streaming_manifest_framing_invalid");
        std::process::exit(2);
    };
    if manifest_length == 0 || manifest_length > MAX_STREAMING_MANIFEST_BYTES {
        eprintln!("streaming_manifest_length_invalid");
        std::process::exit(2);
    }
    let Some(manifest_end) = offset.checked_add(manifest_length) else {
        eprintln!("streaming_manifest_framing_invalid");
        std::process::exit(2);
    };
    let Some(manifest_encoded) = encoded.get(offset..manifest_end) else {
        eprintln!("streaming_manifest_framing_invalid");
        std::process::exit(2);
    };
    if manifest_end != encoded.len() {
        eprintln!("streaming_manifest_framing_trailing_bytes");
        std::process::exit(2);
    }

    match decode_streaming_air_manifest(manifest_encoded, program) {
        Ok(manifest) => {
            let column_count: usize = manifest
                .tables
                .iter()
                .map(|table| table.columns.len())
                .sum();
            println!("OK");
            println!(
                "program_binary_commitment={}",
                hex(&manifest.program_binary_commitment)
            );
            println!("manifest_commitment={}", hex(&manifest.commitment));
            println!("tables={}", manifest.tables.len());
            println!("columns={column_count}");
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    }
}
