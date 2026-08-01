//! Streamed exact SHA3-512 payment-operation and operation-log schedule.
//!
//! Operation bytes commit authenticated keys and before/after values rather
//! than redundant intermediate Merkle roots.  This matches the endpoint-map
//! AIR and avoids a second tree computation solely for audit logging.

use alloc::vec::Vec;

use sha3::{Digest, Sha3_512};

use crate::sha3_air::{
    KECCAK_ROUNDS, RATE_BYTES, Sha3TraceError, for_each_sha3_512_trace_row, sha3_512_reference,
};

pub const PAYMENT_OPERATION_DOMAIN: &[u8] = b"BL/PQ512/PAYMENT-MAP/OPERATION/v3";
pub const PAYMENT_LOG_DOMAIN: &[u8] = b"BL/PQ512/PAYMENT-MAP/OPLOG/v2";
pub const PAYMENT_LOG_SCHEDULE_DOMAIN: &[u8] = b"BL/PQ512/WAVE1A/PAYMENT-LOG-SHA3-SCHEDULE/v1\0";

const OPERATION_MESSAGE_BYTES: usize = PAYMENT_OPERATION_DOMAIN.len() + 2 + 1 + 12 + 12 * 64;
const LOG_MESSAGE_BYTES: usize = PAYMENT_LOG_DOMAIN.len() + 64 + 8 + 2 + 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PaymentWitnessClass {
    Approval = b'A',
    Denial = b'D',
    Cover = b'C',
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaymentLogSlot {
    pub slot_index: u16,
    pub witness_class: PaymentWitnessClass,
    pub gross_allowed_cents: u32,
    pub patient_responsibility_cents: u32,
    pub plan_payable_cents: u32,
    pub keys: [[u8; 64]; 4],
    pub values_before: [[u8; 64]; 4],
    pub values_after: [[u8; 64]; 4],
    pub expected_log_after: [u8; 64],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PaymentLogScheduleReport {
    pub slots: u64,
    pub calls: u64,
    pub permutations: u64,
    pub keccak_round_rows: u64,
    pub final_log_root: [u8; 64],
    pub commitment: [u8; 64],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PaymentLogError {
    SlotsRequired,
    SlotOrderInvalid,
    ClassEconomicsMismatch,
    DigestMismatch,
    LogRootMismatch,
    CountOverflow,
    Trace(Sha3TraceError),
}

pub fn payment_operation_preimage(slot: &PaymentLogSlot) -> Vec<u8> {
    let mut message = Vec::with_capacity(OPERATION_MESSAGE_BYTES);
    message.extend_from_slice(PAYMENT_OPERATION_DOMAIN);
    message.extend_from_slice(&slot.slot_index.to_be_bytes());
    message.push(slot.witness_class as u8);
    message.extend_from_slice(&slot.gross_allowed_cents.to_be_bytes());
    message.extend_from_slice(&slot.patient_responsibility_cents.to_be_bytes());
    message.extend_from_slice(&slot.plan_payable_cents.to_be_bytes());
    for key in &slot.keys {
        message.extend_from_slice(key);
    }
    for index in 0..4 {
        message.extend_from_slice(&slot.values_before[index]);
        message.extend_from_slice(&slot.values_after[index]);
    }
    debug_assert_eq!(message.len(), OPERATION_MESSAGE_BYTES);
    message
}

pub fn payment_log_preimage(
    root_before: [u8; 64],
    sequence: u64,
    slot_index: u16,
    operation_digest: [u8; 64],
) -> Vec<u8> {
    let mut message = Vec::with_capacity(LOG_MESSAGE_BYTES);
    message.extend_from_slice(PAYMENT_LOG_DOMAIN);
    message.extend_from_slice(&root_before);
    message.extend_from_slice(&sequence.to_be_bytes());
    message.extend_from_slice(&slot_index.to_be_bytes());
    message.extend_from_slice(&operation_digest);
    debug_assert_eq!(message.len(), LOG_MESSAGE_BYTES);
    message
}

fn stream_message(message: &[u8], round_rows: &mut u64) -> Result<[u8; 64], PaymentLogError> {
    let mut message_rows = 0_u64;
    for_each_sha3_512_trace_row(message, message.len(), |_, _, _, _, _, _| {
        message_rows += 1;
    })
    .map_err(PaymentLogError::Trace)
    .and_then(|digest| {
        *round_rows = round_rows
            .checked_add(message_rows)
            .ok_or(PaymentLogError::CountOverflow)?;
        Ok(digest)
    })
}

pub fn evaluate_payment_log_schedule(
    sequence: u64,
    initial_log_root: [u8; 64],
    slots: &[PaymentLogSlot],
) -> Result<PaymentLogScheduleReport, PaymentLogError> {
    if slots.is_empty() {
        return Err(PaymentLogError::SlotsRequired);
    }
    let mut log_root = initial_log_root;
    let mut round_rows = 0_u64;
    let mut permutations = 0_u64;
    let mut commitment = Sha3_512::new();
    commitment.update(PAYMENT_LOG_SCHEDULE_DOMAIN);
    let slot_count: u32 = slots
        .len()
        .try_into()
        .map_err(|_| PaymentLogError::CountOverflow)?;
    commitment.update(slot_count.to_be_bytes());

    for (index, slot) in slots.iter().enumerate() {
        if usize::from(slot.slot_index) != index {
            return Err(PaymentLogError::SlotOrderInvalid);
        }
        let expected_gross = slot
            .patient_responsibility_cents
            .checked_add(slot.plan_payable_cents)
            .ok_or(PaymentLogError::ClassEconomicsMismatch)?;
        let class_valid = match slot.witness_class {
            PaymentWitnessClass::Approval => slot.gross_allowed_cents == expected_gross,
            PaymentWitnessClass::Denial | PaymentWitnessClass::Cover => {
                slot.gross_allowed_cents == 0
                    && slot.patient_responsibility_cents == 0
                    && slot.plan_payable_cents == 0
            }
        };
        if !class_valid {
            return Err(PaymentLogError::ClassEconomicsMismatch);
        }
        let operation_message = payment_operation_preimage(slot);
        let operation_digest = stream_message(&operation_message, &mut round_rows)?;
        if operation_digest != sha3_512_reference(&operation_message) {
            return Err(PaymentLogError::DigestMismatch);
        }
        let log_message =
            payment_log_preimage(log_root, sequence, slot.slot_index, operation_digest);
        let next_log = stream_message(&log_message, &mut round_rows)?;
        if next_log != sha3_512_reference(&log_message) || next_log != slot.expected_log_after {
            return Err(PaymentLogError::LogRootMismatch);
        }
        for message in [&operation_message, &log_message] {
            permutations = permutations
                .checked_add((message.len() / usize::from(RATE_BYTES) + 1) as u64)
                .ok_or(PaymentLogError::CountOverflow)?;
            commitment.update((message.len() as u32).to_be_bytes());
            commitment.update(message);
        }
        commitment.update(operation_digest);
        commitment.update(next_log);
        log_root = next_log;
    }
    let calls = u64::from(slot_count)
        .checked_mul(2)
        .ok_or(PaymentLogError::CountOverflow)?;
    if round_rows != permutations * u64::from(KECCAK_ROUNDS) {
        return Err(PaymentLogError::CountOverflow);
    }
    Ok(PaymentLogScheduleReport {
        slots: u64::from(slot_count),
        calls,
        permutations,
        keccak_round_rows: round_rows,
        final_log_root: log_root,
        commitment: commitment.finalize().into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot(index: u16, root_before: [u8; 64]) -> PaymentLogSlot {
        let class = if index == 0 {
            PaymentWitnessClass::Approval
        } else {
            PaymentWitnessClass::Cover
        };
        let mut value = PaymentLogSlot {
            slot_index: index,
            witness_class: class,
            gross_allowed_cents: if index == 0 { 100 } else { 0 },
            patient_responsibility_cents: if index == 0 { 20 } else { 0 },
            plan_payable_cents: if index == 0 { 80 } else { 0 },
            keys: [[index as u8; 64]; 4],
            values_before: [[0_u8; 64]; 4],
            values_after: [[index as u8 + 1; 64]; 4],
            expected_log_after: [0_u8; 64],
        };
        let operation = sha3_512_reference(&payment_operation_preimage(&value));
        value.expected_log_after =
            sha3_512_reference(&payment_log_preimage(root_before, 11, index, operation));
        value
    }

    #[test]
    fn streams_exact_operation_and_log_calls() {
        let initial = [0x42_u8; 64];
        let first = slot(0, initial);
        let second = slot(1, first.expected_log_after);
        let expected_final = second.expected_log_after;
        let report = evaluate_payment_log_schedule(11, initial, &[first, second]).unwrap();
        assert_eq!(report.slots, 2);
        assert_eq!(report.calls, 4);
        assert_eq!(report.permutations, 30);
        assert_eq!(report.keccak_round_rows, 720);
        assert_eq!(report.final_log_root, expected_final);
    }

    #[test]
    fn rejects_log_digest_tampering() {
        let initial = [0x42_u8; 64];
        let mut value = slot(0, initial);
        value.expected_log_after[0] ^= 1;
        assert_eq!(
            evaluate_payment_log_schedule(11, initial, &[value]),
            Err(PaymentLogError::LogRootMismatch)
        );
    }

    #[test]
    fn rejects_class_economics_tampering() {
        let initial = [0x42_u8; 64];
        let mut value = slot(0, initial);
        value.witness_class = PaymentWitnessClass::Denial;
        assert_eq!(
            evaluate_payment_log_schedule(11, initial, &[value]),
            Err(PaymentLogError::ClassEconomicsMismatch)
        );
    }
}
