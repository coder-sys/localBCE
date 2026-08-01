use std::io::{self, Read};

use bl_pq512_crypto_core::air_ir::MAX_AIR_BINARY_BYTES;
use bl_pq512_crypto_core::streaming_ir::{
    MAX_STREAMING_CHUNK_VALUES, MAX_STREAMING_MANIFEST_BYTES, StreamingExecutionVerifier,
    decode_streaming_air_manifest,
};

const MAX_CHUNK_BYTES: usize = MAX_STREAMING_CHUNK_VALUES * 4 + 158;

fn read_u32(encoded: &[u8], offset: &mut usize) -> Option<usize> {
    let end = offset.checked_add(4)?;
    let value = u32::from_be_bytes(encoded.get(*offset..end)?.try_into().ok()?);
    *offset = end;
    usize::try_from(value).ok()
}

fn take_framed<'a>(encoded: &'a [u8], offset: &mut usize, maximum: usize) -> Option<&'a [u8]> {
    let length = read_u32(encoded, offset)?;
    if length == 0 || length > maximum {
        return None;
    }
    let end = offset.checked_add(length)?;
    let value = encoded.get(*offset..end)?;
    *offset = end;
    Some(value)
}

fn main() {
    let maximum_input =
        MAX_AIR_BINARY_BYTES + MAX_STREAMING_MANIFEST_BYTES + MAX_CHUNK_BYTES * 1024;
    let mut encoded = Vec::new();
    if io::stdin()
        .take((maximum_input + 1) as u64)
        .read_to_end(&mut encoded)
        .is_err()
        || encoded.len() > maximum_input
    {
        eprintln!("streaming_execution_input_invalid");
        std::process::exit(2);
    }
    let mut offset = 0usize;
    let Some(program) = take_framed(&encoded, &mut offset, MAX_AIR_BINARY_BYTES) else {
        eprintln!("streaming_execution_program_framing_invalid");
        std::process::exit(2);
    };
    let Some(manifest_encoded) = take_framed(&encoded, &mut offset, MAX_STREAMING_MANIFEST_BYTES)
    else {
        eprintln!("streaming_execution_manifest_framing_invalid");
        std::process::exit(2);
    };
    let manifest = match decode_streaming_air_manifest(manifest_encoded, program) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    };
    let mut verifier = StreamingExecutionVerifier::new(&manifest);
    let mut chunks = 0usize;
    let mut values = 0usize;
    while offset < encoded.len() {
        let Some(chunk_encoded) = take_framed(&encoded, &mut offset, MAX_CHUNK_BYTES) else {
            eprintln!("streaming_execution_chunk_framing_invalid");
            std::process::exit(2);
        };
        match verifier.absorb(chunk_encoded) {
            Ok(chunk) => {
                chunks += 1;
                values += chunk.values.len();
            }
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(2);
            }
        }
    }
    if let Err(error) = verifier.finish() {
        eprintln!("{error}");
        std::process::exit(2);
    }
    println!("OK chunks={chunks} values={values}");
}
