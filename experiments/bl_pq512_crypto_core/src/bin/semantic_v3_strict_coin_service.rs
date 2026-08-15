//! Line-oriented service for one selected-v3 strict public-coin transaction.

use std::env;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use bl_pq512_crypto_core::chained_public_coin::MAX_PROVER_MESSAGE_BYTES;
use bl_pq512_crypto_core::selected_public_coin_v3::SemanticV3GovernedContext;
use bl_pq512_crypto_core::semantic_v3_strict_coin::SemanticV3StrictCoin;
use bl_pq512_crypto_core::v3_real_authority::{
    SEMANTIC_KEY_FILE, SEMANTIC_STRICT_BUNDLE_FILE, publish_new_files,
};

const USAGE: &str = "usage: semantic_v3_strict_coin_service <absolute-context-file> <session-id-lower-hex-64> <attempt-0..3> <absolute-existing-output-dir>";
const MAX_COMMAND_LINE_BYTES: usize = 6 + 2 * MAX_PROVER_MESSAGE_BYTES + 1;

fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], String> {
    if value.len() != 2 * N || !value.is_ascii() {
        return Err("hex_shape".to_owned());
    }
    let nibble = |byte: u8| match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err("hex_not_lower".to_owned()),
    };
    let mut output = [0_u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(output)
}

fn hex(value: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn run() -> Result<(), String> {
    let args = env::args().collect::<Vec<_>>();
    if args.len() != 5 {
        return Err(USAGE.to_owned());
    }
    let context_path = PathBuf::from(&args[1]);
    let output_dir = PathBuf::from(&args[4]);
    if !context_path.is_absolute() || !context_path.is_file() {
        return Err("context_file".to_owned());
    }
    if !output_dir.is_absolute() || !output_dir.is_dir() {
        return Err("output_dir".to_owned());
    }
    let context = SemanticV3GovernedContext::decode(
        &std::fs::read(&context_path)
            .map_err(|error| format!("context_read:{:?}", error.kind()))?,
    )
    .map_err(|error| format!("context_decode:{error:?}"))?;
    let session_id = decode_hex::<64>(&args[2])?;
    let attempt = args[3].parse::<u8>().map_err(|_| "attempt".to_owned())?;
    let mut coin = SemanticV3StrictCoin::new(context, session_id, attempt)
        .map_err(|error| format!("coin_start:{error:?}"))?;
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    writeln!(stdout, "READY").map_err(|error| format!("stdout:{error}"))?;
    stdout.flush().map_err(|error| format!("stdout:{error}"))?;
    while let Some(line) = read_bounded_line(&mut input, MAX_COMMAND_LINE_BYTES)? {
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        match fields.as_slice() {
            ["ROUND", message] => {
                let message = decode_hex_vec(message)?;
                let output = coin
                    .absorb_message(&message)
                    .map_err(|error| format!("round:{error:?}"))?;
                write!(
                    stdout,
                    "CHALLENGE {} {}",
                    output.ordinal,
                    output.field_elements.len()
                )
                .map_err(|error| format!("stdout:{error}"))?;
                for element in output.field_elements {
                    write!(stdout, " {}", hex(&element.encode()))
                        .map_err(|error| format!("stdout:{error}"))?;
                }
                writeln!(stdout, " {}", hex(&output.transcript_root))
                    .map_err(|error| format!("stdout:{error}"))?;
                stdout.flush().map_err(|error| format!("stdout:{error}"))?;
            }
            ["FINISH"] => {
                let finished = coin.finish().map_err(|error| format!("finish:{error:?}"))?;
                publish_new_files(
                    &output_dir,
                    &[
                        (SEMANTIC_KEY_FILE, finished.governed_key.as_slice()),
                        (
                            SEMANTIC_STRICT_BUNDLE_FILE,
                            finished.encoded_bundle.as_slice(),
                        ),
                    ],
                )
                .map_err(|error| format!("publish:{error}"))?;
                writeln!(
                    stdout,
                    "FINISHED {} {}",
                    hex(&finished.pre_final_transcript_root),
                    hex(&finished.final_transcript_root)
                )
                .map_err(|error| format!("stdout:{error}"))?;
                stdout.flush().map_err(|error| format!("stdout:{error}"))?;
                return Ok(());
            }
            _ => return Err("command".to_owned()),
        }
    }
    Err("unexpected_eof".to_owned())
}

fn decode_hex_vec(value: &str) -> Result<Vec<u8>, String> {
    if value.is_empty()
        || value.len() > 2 * MAX_PROVER_MESSAGE_BYTES
        || value.len() % 2 != 0
        || !value.is_ascii()
    {
        return Err("message_hex_shape".to_owned());
    }
    let mut output = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let nibble = |byte: u8| match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            _ => Err("message_hex_not_lower".to_owned()),
        };
        output.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    Ok(output)
}

fn read_bounded_line<R: BufRead>(reader: &mut R, maximum: usize) -> Result<Option<String>, String> {
    let mut line = Vec::new();
    loop {
        let buffer = reader
            .fill_buf()
            .map_err(|error| format!("stdin:{error}"))?;
        if buffer.is_empty() {
            if line.is_empty() {
                return Ok(None);
            }
            break;
        }
        let newline = buffer.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(buffer.len(), |index| index + 1);
        let payload = newline.map_or(buffer, |index| &buffer[..index]);
        if line.len().saturating_add(payload.len()) > maximum {
            return Err("command_too_long".to_owned());
        }
        line.extend_from_slice(payload);
        reader.consume(consumed);
        if newline.is_some() {
            break;
        }
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    String::from_utf8(line)
        .map(Some)
        .map_err(|_| "command_not_utf8".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn bounded_reader_accepts_the_maximum_round_line() {
        let mut encoded = b"ROUND ".to_vec();
        encoded.resize(6 + 2 * MAX_PROVER_MESSAGE_BYTES, b'0');
        encoded.push(b'\n');
        let line = read_bounded_line(&mut Cursor::new(encoded), MAX_COMMAND_LINE_BYTES)
            .unwrap()
            .unwrap();
        assert_eq!(line.len(), 6 + 2 * MAX_PROVER_MESSAGE_BYTES);
        assert_eq!(
            decode_hex_vec(&line[6..]).unwrap().len(),
            MAX_PROVER_MESSAGE_BYTES
        );
    }

    #[test]
    fn bounded_reader_rejects_an_oversize_command_before_allocating_past_the_cap() {
        let encoded = vec![b'x'; MAX_COMMAND_LINE_BYTES + 1];
        assert_eq!(
            read_bounded_line(&mut Cursor::new(encoded), MAX_COMMAND_LINE_BYTES),
            Err("command_too_long".to_owned())
        );
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ERR {error}");
            ExitCode::from(2)
        }
    }
}
