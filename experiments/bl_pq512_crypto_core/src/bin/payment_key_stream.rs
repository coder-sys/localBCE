use std::{env, fs, process};

use bl_pq512_crypto_core::payment_keys::{
    MAX_PAYMENT_KEY_SLOTS, PAYMENT_KEY_LANES, PaymentKeyCall, PaymentKeyLane,
    evaluate_payment_key_schedule,
};

const MAGIC: &[u8] = b"BLPK1";
const MAX_MESSAGE_BYTES: usize = 216;
const MAX_INPUT_BYTES: usize =
    MAGIC.len() + 2 + MAX_PAYMENT_KEY_SLOTS * PAYMENT_KEY_LANES * (2 + MAX_MESSAGE_BYTES + 64);

fn take<const N: usize>(input: &[u8], cursor: &mut usize) -> Result<[u8; N], &'static str> {
    let stop = cursor.checked_add(N).ok_or("cursor_overflow")?;
    let bytes = input.get(*cursor..stop).ok_or("input_truncated")?;
    let mut value = [0_u8; N];
    value.copy_from_slice(bytes);
    *cursor = stop;
    Ok(value)
}

fn lane(ordinal: usize) -> PaymentKeyLane {
    match ordinal % PAYMENT_KEY_LANES {
        0 => PaymentKeyLane::Benefit,
        1 => PaymentKeyLane::Obligation,
        2 => PaymentKeyLane::Reserve,
        _ => PaymentKeyLane::Payable,
    }
}

fn parse(input: &[u8]) -> Result<Vec<PaymentKeyCall>, &'static str> {
    if !input.starts_with(MAGIC) {
        return Err("magic_invalid");
    }
    let mut cursor = MAGIC.len();
    let slots = usize::from(u16::from_be_bytes(take(input, &mut cursor)?));
    if slots == 0 || slots > MAX_PAYMENT_KEY_SLOTS {
        return Err("slot_count_invalid");
    }
    let count = slots
        .checked_mul(PAYMENT_KEY_LANES)
        .ok_or("call_count_overflow")?;
    let mut calls = Vec::with_capacity(count);
    for ordinal in 0..count {
        let length = usize::from(u16::from_be_bytes(take(input, &mut cursor)?));
        if length == 0 || length > MAX_MESSAGE_BYTES {
            return Err("message_length_invalid");
        }
        let stop = cursor.checked_add(length).ok_or("cursor_overflow")?;
        let message = input.get(cursor..stop).ok_or("input_truncated")?.to_vec();
        cursor = stop;
        calls.push(PaymentKeyCall {
            lane: lane(ordinal),
            message,
            expected_digest: take(input, &mut cursor)?,
        });
    }
    if cursor != input.len() {
        return Err("input_trailing_bytes");
    }
    Ok(calls)
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
    let calls = parse(&input).map_err(str::to_owned)?;
    let report = evaluate_payment_key_schedule(&calls)
        .map_err(|error| format!("schedule_invalid:{error:?}"))?;
    println!("slots={}", report.slots);
    println!("calls={}", report.calls);
    println!("permutations={}", report.permutations);
    println!("keccak_round_rows={}", report.keccak_round_rows);
    println!("commitment={}", hex(&report.commitment));
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        process::exit(2);
    }
}
