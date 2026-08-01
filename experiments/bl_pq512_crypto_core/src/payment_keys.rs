//! Fixed-privacy streamed SHA3-512 schedule for payment-map keys.

use alloc::vec::Vec;

use sha3::{Digest, Sha3_512};

use crate::sha3_air::{
    KECCAK_ROUNDS, RATE_BYTES, Sha3TraceError, for_each_sha3_512_trace_row, sha3_512_reference,
};

pub const PAYMENT_KEY_DOMAIN: &[u8] = b"BL/PQ512/PAYMENT-MAP/RANK-KEY/v2";
pub const PAYMENT_KEY_SCHEDULE_DOMAIN: &[u8] = b"BL/PQ512/WAVE1A/PAYMENT-KEY-SHA3-SCHEDULE/v2\0";
pub const PAYMENT_KEY_LANES: usize = 4;
pub const MAX_PAYMENT_KEY_SLOTS: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PaymentKeyLane {
    Benefit = 1,
    Obligation = 2,
    Reserve = 3,
    Payable = 4,
}

impl PaymentKeyLane {
    pub const fn capacity(self) -> usize {
        169
    }

    const fn from_ordinal(value: usize) -> Self {
        match value % PAYMENT_KEY_LANES {
            0 => Self::Benefit,
            1 => Self::Obligation,
            2 => Self::Reserve,
            _ => Self::Payable,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaymentKeyCall {
    pub lane: PaymentKeyLane,
    pub message: Vec<u8>,
    pub expected_digest: [u8; 64],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PaymentKeyScheduleReport {
    pub slots: u64,
    pub calls: u64,
    pub permutations: u64,
    pub keccak_round_rows: u64,
    pub commitment: [u8; 64],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PaymentKeyError {
    CallsRequired,
    CallCountInvalid,
    LaneOrderInvalid,
    MessageDomainInvalid,
    MessageCapacityInvalid,
    DigestMismatch,
    CountOverflow,
    Trace(Sha3TraceError),
}

pub fn evaluate_payment_key_schedule(
    calls: &[PaymentKeyCall],
) -> Result<PaymentKeyScheduleReport, PaymentKeyError> {
    if calls.is_empty() {
        return Err(PaymentKeyError::CallsRequired);
    }
    if !calls.len().is_multiple_of(PAYMENT_KEY_LANES)
        || calls.len() / PAYMENT_KEY_LANES > MAX_PAYMENT_KEY_SLOTS
    {
        return Err(PaymentKeyError::CallCountInvalid);
    }
    let slots = calls.len() / PAYMENT_KEY_LANES;
    let slot_count: u32 = slots
        .try_into()
        .map_err(|_| PaymentKeyError::CountOverflow)?;
    let mut commitment = Sha3_512::new();
    commitment.update(PAYMENT_KEY_SCHEDULE_DOMAIN);
    commitment.update(slot_count.to_be_bytes());
    let mut permutations = 0_u64;
    let mut round_rows = 0_u64;

    for (ordinal, call) in calls.iter().enumerate() {
        let expected_lane = PaymentKeyLane::from_ordinal(ordinal);
        if call.lane != expected_lane {
            return Err(PaymentKeyError::LaneOrderInvalid);
        }
        if !call.message.starts_with(PAYMENT_KEY_DOMAIN) {
            return Err(PaymentKeyError::MessageDomainInvalid);
        }
        let capacity = call.lane.capacity();
        if call.message.is_empty() || call.message.len() > capacity {
            return Err(PaymentKeyError::MessageCapacityInvalid);
        }
        let mut message_rows = 0_u64;
        let digest = for_each_sha3_512_trace_row(&call.message, capacity, |_, _, _, _, _, _| {
            message_rows += 1
        })
        .map_err(PaymentKeyError::Trace)?;
        if digest != call.expected_digest || digest != sha3_512_reference(&call.message) {
            return Err(PaymentKeyError::DigestMismatch);
        }
        let call_permutations = (capacity / usize::from(RATE_BYTES) + 1) as u64;
        permutations = permutations
            .checked_add(call_permutations)
            .ok_or(PaymentKeyError::CountOverflow)?;
        round_rows = round_rows
            .checked_add(message_rows)
            .ok_or(PaymentKeyError::CountOverflow)?;
        commitment.update((ordinal as u32).to_be_bytes());
        commitment.update([call.lane as u8]);
        commitment.update((capacity as u16).to_be_bytes());
        commitment.update((call.message.len() as u16).to_be_bytes());
        commitment.update(&call.message);
        commitment.update(call.expected_digest);
    }
    if round_rows != permutations * u64::from(KECCAK_ROUNDS) {
        return Err(PaymentKeyError::CountOverflow);
    }
    Ok(PaymentKeyScheduleReport {
        slots: u64::from(slot_count),
        calls: u64::try_from(calls.len()).map_err(|_| PaymentKeyError::CountOverflow)?,
        permutations,
        keccak_round_rows: round_rows,
        commitment: commitment.finalize().into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn calls() -> Vec<PaymentKeyCall> {
        (0..8)
            .map(|ordinal| {
                let lane = PaymentKeyLane::from_ordinal(ordinal);
                let mut message = PAYMENT_KEY_DOMAIN.to_vec();
                message.extend_from_slice(&(ordinal as u64).to_be_bytes());
                let expected_digest = sha3_512_reference(&message);
                PaymentKeyCall {
                    lane,
                    message,
                    expected_digest,
                }
            })
            .collect()
    }

    #[test]
    fn streams_fixed_privacy_key_schedule() {
        let report = evaluate_payment_key_schedule(&calls()).unwrap();
        assert_eq!(report.slots, 2);
        assert_eq!(report.calls, 8);
        assert_eq!(report.permutations, 24);
        assert_eq!(report.keccak_round_rows, 576);
    }

    #[test]
    fn rejects_lane_and_digest_tampering() {
        let mut lane = calls();
        lane[0].lane = PaymentKeyLane::Payable;
        assert_eq!(
            evaluate_payment_key_schedule(&lane),
            Err(PaymentKeyError::LaneOrderInvalid)
        );
        let mut digest = calls();
        digest[0].expected_digest[0] ^= 1;
        assert_eq!(
            evaluate_payment_key_schedule(&digest),
            Err(PaymentKeyError::DigestMismatch)
        );
    }

    #[test]
    fn rejects_oversized_message() {
        let mut values = calls();
        values[0].message = vec![0_u8; PaymentKeyLane::Benefit.capacity() + 1];
        assert_eq!(
            evaluate_payment_key_schedule(&values),
            Err(PaymentKeyError::MessageDomainInvalid)
        );
        values[0].message[..PAYMENT_KEY_DOMAIN.len()].copy_from_slice(PAYMENT_KEY_DOMAIN);
        assert_eq!(
            evaluate_payment_key_schedule(&values),
            Err(PaymentKeyError::MessageCapacityInvalid)
        );
    }
}
