use std::{env, fs, process};

use bl_pq512_crypto_core::{
    claim_source::{
        CLAIM_SOURCE_BUNDLE_BYTES, MAX_CLAIM_SOURCE_SLOTS, evaluate_claim_source_schedule,
    },
    oracle_bundle::OracleProfile,
};

const MAGIC: &[u8] = b"BLCS1";
const MAX_INPUT_BYTES: usize =
    MAGIC.len() + 1 + 2 + MAX_CLAIM_SOURCE_SLOTS * CLAIM_SOURCE_BUNDLE_BYTES + 64;
type ParsedInput = (OracleProfile, Vec<Vec<u8>>, [u8; 64]);

fn take<const N: usize>(input: &[u8], cursor: &mut usize) -> Result<[u8; N], &'static str> {
    let stop = cursor.checked_add(N).ok_or("cursor_overflow")?;
    let bytes = input.get(*cursor..stop).ok_or("input_truncated")?;
    let mut value = [0_u8; N];
    value.copy_from_slice(bytes);
    *cursor = stop;
    Ok(value)
}

fn profile(code: u8) -> Result<OracleProfile, &'static str> {
    match code {
        1 => Ok(OracleProfile::K128),
        2 => Ok(OracleProfile::K256),
        3 => Ok(OracleProfile::K512),
        _ => Err("profile_invalid"),
    }
}

fn parse(input: &[u8]) -> Result<ParsedInput, &'static str> {
    if !input.starts_with(MAGIC) {
        return Err("magic_invalid");
    }
    let mut cursor = MAGIC.len();
    let selected = profile(take::<1>(input, &mut cursor)?[0])?;
    let slots = usize::from(u16::from_be_bytes(take(input, &mut cursor)?));
    if slots != selected.claim_slots() || slots > MAX_CLAIM_SOURCE_SLOTS {
        return Err("slot_count_invalid");
    }
    let mut bundles = Vec::with_capacity(slots);
    for _ in 0..slots {
        let stop = cursor
            .checked_add(CLAIM_SOURCE_BUNDLE_BYTES)
            .ok_or("cursor_overflow")?;
        bundles.push(input.get(cursor..stop).ok_or("input_truncated")?.to_vec());
        cursor = stop;
    }
    let expected_root = take(input, &mut cursor)?;
    if cursor != input.len() {
        return Err("input_trailing_bytes");
    }
    Ok((selected, bundles, expected_root))
}

fn hex(value: &[u8]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(value.len() * 2);
    for byte in value {
        result.push(char::from(ALPHABET[usize::from(byte >> 4)]));
        result.push(char::from(ALPHABET[usize::from(byte & 0x0f)]));
    }
    result
}

fn run() -> Result<(), String> {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let path = arguments.next().ok_or("input_path_required")?;
    if arguments.next().is_some() {
        return Err("unexpected_argument".to_owned());
    }
    let metadata = fs::metadata(&path).map_err(|_| "input_metadata_failed")?;
    if metadata.len() > MAX_INPUT_BYTES as u64 {
        return Err("input_too_large".to_owned());
    }
    let input = fs::read(path).map_err(|_| "input_read_failed")?;
    let (profile, bundles, expected_root) = parse(&input).map_err(str::to_owned)?;
    let report = evaluate_claim_source_schedule(profile, &bundles, expected_root)
        .map_err(|error| format!("schedule_invalid:{error:?}"))?;
    println!("slots={}", report.slots);
    println!("calls={}", report.calls);
    println!("permutations={}", report.permutations);
    println!("keccak_round_rows={}", report.keccak_round_rows);
    println!("root={}", hex(&report.root));
    println!("commitment={}", hex(&report.commitment));
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        process::exit(2);
    }
}
