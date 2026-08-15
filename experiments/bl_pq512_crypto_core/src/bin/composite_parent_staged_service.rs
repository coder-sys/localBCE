//! One-shot staged producer for parent rounds 900, 901, and 902.

use std::env;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use bl_pq512_crypto_core::composite_parent_public_coin::{
    COMPOSITE_PARENT_FINAL_BYTES, COMPOSITE_PARENT_PRE_ALPHA_BYTES,
    COMPOSITE_PARENT_QUOTIENT_BYTES, CompositeParentAfterRound900, CompositeParentAfterRound901,
    begin_composite_parent_production,
};
use bl_pq512_crypto_core::v3_real_authority::publish_new_file;
use sha3::{Digest, Sha3_512};

const USAGE: &str = "usage: composite_parent_staged_service <absolute-chained-public-coin-service> <absolute-existing-output-dir>";
const PARENT_BUNDLE_FILE: &str = "parent-bundle.bin";
const MAX_COMMAND_LINE_BYTES: usize = 10 + 2 * COMPOSITE_PARENT_QUOTIENT_BYTES + 1;

enum State {
    Empty,
    After900(CompositeParentAfterRound900),
    After901 {
        parent: CompositeParentAfterRound901,
        prepared_final: Option<Vec<u8>>,
    },
    Finished,
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

fn decode_hex_exact(value: &str, expected: usize, label: &str) -> Result<Vec<u8>, String> {
    if value.len() != 2 * expected || !value.is_ascii() {
        return Err(format!("{label}_hex_shape"));
    }
    let nibble = |byte: u8| match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(format!("{label}_hex_not_lower")),
    };
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok((nibble(pair[0])? << 4) | nibble(pair[1])?))
        .collect()
}

fn read_bounded_line<R: BufRead>(reader: &mut R) -> Result<Option<String>, String> {
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
        if line.len().saturating_add(payload.len()) > MAX_COMMAND_LINE_BYTES {
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

fn run() -> Result<(), String> {
    let args = env::args_os().collect::<Vec<_>>();
    if args.len() != 3 {
        return Err(USAGE.to_owned());
    }
    let chained_service = PathBuf::from(&args[1]);
    let output_dir = PathBuf::from(&args[2]);
    if !chained_service.is_absolute() || !chained_service.is_file() || chained_service.is_symlink()
    {
        return Err("chained_service".to_owned());
    }
    if !output_dir.is_absolute() || !output_dir.is_dir() || output_dir.is_symlink() {
        return Err("output_dir".to_owned());
    }
    if output_dir.join(PARENT_BUNDLE_FILE).exists() {
        return Err("parent_bundle_exists".to_owned());
    }

    let stdin = io::stdin();
    let mut input = stdin.lock();
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    let mut state = State::Empty;
    writeln!(stdout, "READY").map_err(|error| format!("stdout:{error}"))?;
    stdout.flush().map_err(|error| format!("stdout:{error}"))?;

    while let Some(line) = read_bounded_line(&mut input)? {
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        match fields.as_slice() {
            ["ROUND900", encoded] => {
                if !matches!(state, State::Empty) {
                    return Err("round900_sequence".to_owned());
                }
                let message =
                    decode_hex_exact(encoded, COMPOSITE_PARENT_PRE_ALPHA_BYTES, "round900")?;
                let parent = begin_composite_parent_production(&chained_service, &message)
                    .map_err(|error| format!("round900:{error:?}"))?;
                let accepted = parent
                    .round_900_message()
                    .map_err(|error| format!("round900_message:{error:?}"))?;
                if accepted != message {
                    return Err("round900_message_mismatch".to_owned());
                }
                writeln!(
                    stdout,
                    "ROUND900_ACCEPTED {} {}",
                    hex(&accepted),
                    hex(parent.round_900_transcript_root())
                )
                .map_err(|error| format!("stdout:{error}"))?;
                stdout.flush().map_err(|error| format!("stdout:{error}"))?;
                state = State::After900(parent);
            }
            ["ROUND901", encoded] => {
                let prior = std::mem::replace(&mut state, State::Finished);
                let State::After900(parent) = prior else {
                    return Err("round901_sequence".to_owned());
                };
                let template =
                    decode_hex_exact(encoded, COMPOSITE_PARENT_QUOTIENT_BYTES, "round901")?;
                let parent = parent
                    .absorb_quotient(&template)
                    .map_err(|error| format!("round901:{error:?}"))?;
                let accepted = parent
                    .round_901_message()
                    .map_err(|error| format!("round901_message:{error:?}"))?;
                let commitments = parent.direct_quotient_commitments();
                writeln!(
                    stdout,
                    "ROUND901_ACCEPTED {} {} {} {} {} {} {} {}",
                    hex(&accepted),
                    hex(parent.parent_session_id()),
                    hex(parent.round_901_transcript_root()),
                    hex(parent.semantic_composition_root()),
                    hex(parent.bridge_program_commitment()),
                    hex(parent.bridge_mask_answer_aggregate_root()),
                    hex(&commitments.message),
                    hex(&commitments.digest),
                )
                .map_err(|error| format!("stdout:{error}"))?;
                stdout.flush().map_err(|error| format!("stdout:{error}"))?;
                state = State::After901 {
                    parent,
                    prepared_final: None,
                };
            }
            ["PREPARE902", encoded] => {
                let State::After901 {
                    parent,
                    prepared_final,
                } = &mut state
                else {
                    return Err("prepare902_sequence".to_owned());
                };
                if prepared_final.is_some() {
                    return Err("prepare902_repeated".to_owned());
                }
                let template =
                    decode_hex_exact(encoded, COMPOSITE_PARENT_FINAL_BYTES, "round902_template")?;
                let accepted = parent
                    .prepare_final_message(&template)
                    .map_err(|error| format!("prepare902:{error:?}"))?;
                writeln!(stdout, "ROUND902_PREPARED {}", hex(&accepted))
                    .map_err(|error| format!("stdout:{error}"))?;
                stdout.flush().map_err(|error| format!("stdout:{error}"))?;
                *prepared_final = Some(accepted);
            }
            ["COMMIT902", encoded] => {
                let prior = std::mem::replace(&mut state, State::Finished);
                let State::After901 {
                    parent,
                    prepared_final: Some(prepared),
                } = prior
                else {
                    return Err("commit902_sequence".to_owned());
                };
                let supplied = decode_hex_exact(encoded, COMPOSITE_PARENT_FINAL_BYTES, "round902")?;
                if supplied != prepared {
                    return Err("round902_substitution".to_owned());
                }
                let bundle = parent
                    .finish_encoded(&supplied)
                    .map_err(|error| format!("commit902:{error:?}"))?;
                publish_new_file(&output_dir, PARENT_BUNDLE_FILE, &bundle)
                    .map_err(|error| format!("publish:{error}"))?;
                let digest: [u8; 64] = Sha3_512::digest(&bundle).into();
                writeln!(stdout, "FINISHED {} {}", bundle.len(), hex(&digest))
                    .map_err(|error| format!("stdout:{error}"))?;
                stdout.flush().map_err(|error| format!("stdout:{error}"))?;
                return Ok(());
            }
            _ => return Err("command".to_owned()),
        }
    }
    Err("unexpected_eof".to_owned())
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
