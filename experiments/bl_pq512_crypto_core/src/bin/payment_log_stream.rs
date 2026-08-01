use std::{env, fs, process};

use bl_pq512_crypto_core::payment_log::{
    PaymentLogSlot, PaymentWitnessClass, evaluate_payment_log_schedule,
};

const MAGIC: &[u8] = b"BLPL1";
const SLOT_BYTES: usize = 2 + 1 + 12 + 4 * 64 + 4 * 64 + 4 * 64 + 64;
const MAX_SLOTS: usize = 512;
const MAX_INPUT_BYTES: usize = MAGIC.len() + 8 + 64 + 2 + MAX_SLOTS * SLOT_BYTES;

fn take<const N: usize>(input: &[u8], cursor: &mut usize) -> Result<[u8; N], &'static str> {
    let stop = cursor.checked_add(N).ok_or("cursor_overflow")?;
    let bytes = input.get(*cursor..stop).ok_or("input_truncated")?;
    let mut value = [0_u8; N];
    value.copy_from_slice(bytes);
    *cursor = stop;
    Ok(value)
}

fn take_matrix(input: &[u8], cursor: &mut usize) -> Result<[[u8; 64]; 4], &'static str> {
    let mut values = [[0_u8; 64]; 4];
    for value in &mut values {
        *value = take(input, cursor)?;
    }
    Ok(values)
}

fn parse(input: &[u8]) -> Result<(u64, [u8; 64], Vec<PaymentLogSlot>), &'static str> {
    if !input.starts_with(MAGIC) {
        return Err("magic_invalid");
    }
    let mut cursor = MAGIC.len();
    let sequence = u64::from_be_bytes(take(input, &mut cursor)?);
    let initial_root = take(input, &mut cursor)?;
    let count = usize::from(u16::from_be_bytes(take(input, &mut cursor)?));
    if count == 0 || count > MAX_SLOTS {
        return Err("slot_count_invalid");
    }
    let expected = cursor
        .checked_add(count.checked_mul(SLOT_BYTES).ok_or("length_overflow")?)
        .ok_or("length_overflow")?;
    if input.len() != expected {
        return Err("input_length_invalid");
    }
    let mut slots = Vec::with_capacity(count);
    for _ in 0..count {
        let slot_index = u16::from_be_bytes(take(input, &mut cursor)?);
        let witness_class = match take::<1>(input, &mut cursor)?[0] {
            b'A' => PaymentWitnessClass::Approval,
            b'D' => PaymentWitnessClass::Denial,
            b'C' => PaymentWitnessClass::Cover,
            _ => return Err("class_invalid"),
        };
        slots.push(PaymentLogSlot {
            slot_index,
            witness_class,
            gross_allowed_cents: u32::from_be_bytes(take(input, &mut cursor)?),
            patient_responsibility_cents: u32::from_be_bytes(take(input, &mut cursor)?),
            plan_payable_cents: u32::from_be_bytes(take(input, &mut cursor)?),
            keys: take_matrix(input, &mut cursor)?,
            values_before: take_matrix(input, &mut cursor)?,
            values_after: take_matrix(input, &mut cursor)?,
            expected_log_after: take(input, &mut cursor)?,
        });
    }
    Ok((sequence, initial_root, slots))
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
    let (sequence, initial_root, slots) = parse(&input).map_err(str::to_owned)?;
    let report = evaluate_payment_log_schedule(sequence, initial_root, &slots)
        .map_err(|error| format!("schedule_invalid:{error:?}"))?;
    println!("slots={}", report.slots);
    println!("calls={}", report.calls);
    println!("permutations={}", report.permutations);
    println!("keccak_round_rows={}", report.keccak_round_rows);
    println!("final_log_root={}", hex(&report.final_log_root));
    println!("commitment={}", hex(&report.commitment));
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        process::exit(2);
    }
}
