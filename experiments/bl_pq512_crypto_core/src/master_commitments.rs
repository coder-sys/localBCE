//! Canonical authoritative Wave 1A master commitments.
//!
//! Only the three economic lane roots and the chained operation log are
//! authoritative.  Obsolete aggregate payment roots are not represented by
//! these types and therefore cannot silently re-enter the encoding.

use alloc::vec::Vec;

use crate::sha3_air::sha3_512_reference;

pub const PROTOCOL_VERSION: u16 = 2;
pub const GOVERNANCE_DOMAIN: &[u8] = b"BL/PQ512/GOVERNANCE/v2";
pub const BATCH_DOMAIN: &[u8] = b"BL/PQ512/BATCH/v2";
pub const VALUE_DOMAIN: &[u8] = b"BL/PQ512/VALUE-CONSERVATION/v2";
pub const SETTLEMENT_DOMAIN: &[u8] = b"BL/PQ512/SETTLEMENT/v2";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Profile {
    K128Calibration = 1,
    K256DesignPoint = 2,
    K512Calibration = 3,
}

impl Profile {
    pub const fn claim_slots(self) -> usize {
        match self {
            Self::K128Calibration => 128,
            Self::K256DesignPoint => 256,
            Self::K512Calibration => 512,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MasterEconomicTotalsV2 {
    pub gross_allowed_cents: u64,
    pub patient_responsibility_cents: u64,
    pub plan_payable_cents: u64,
    pub payer_reserve_debits_cents: u64,
    pub provider_payable_credits_cents: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MasterSlotRecordV2 {
    pub slot_index: u16,
    pub decision: u8,
    pub failure_code: u16,
    pub allowed_cents: u32,
    pub payment_cents: u32,
    pub raw_gate_bits: u16,
    pub effective_gate_bits: u16,
    pub strong_nullifier_512: [u8; 64],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MasterCommitmentInputsV2 {
    pub profile: Profile,
    pub epoch: u64,
    pub strong_settlement_domain_id_512: [u8; 64],
    pub strong_batch_nonce_512: [u8; 64],
    pub claim_truth_roots_512: [[u8; 64]; 6],
    pub claim_truth_authority_digest_512: [u8; 64],
    pub nullifier_authority_id_512: [u8; 64],
    pub pepper_commitment_512: [u8; 64],
    pub replay_root_before_512: [u8; 64],
    pub replay_root_after_512: [u8; 64],
    pub payment_lane_roots_before_512: [[u8; 64]; 3],
    pub payment_lane_roots_after_512: [[u8; 64]; 3],
    pub operation_log_root_before_512: [u8; 64],
    pub operation_log_root_after_512: [u8; 64],
    pub salt_use_tag_512: [u8; 64],
    pub economic_totals: MasterEconomicTotalsV2,
    pub slots: Vec<MasterSlotRecordV2>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MasterCommitmentsV2 {
    pub governance_512: [u8; 64],
    pub batch_512: [u8; 64],
    pub value_conservation_512: [u8; 64],
    pub settlement_512: [u8; 64],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MasterCommitmentError {
    EpochInvalid,
    DigestInvalid,
    SlotCountInvalid,
    SlotOrderInvalid,
    SlotGateBitsInvalid,
    SlotDecisionInvalid,
    SlotEconomicsInvalid,
    GrossConservationInvalid,
    PaymentConservationInvalid,
    GrossTotalMismatch,
    PaymentTotalMismatch,
    TotalOverflow,
}

fn nonzero(value: &[u8; 64]) -> bool {
    value.iter().any(|byte| *byte != 0)
}

fn validate(value: &MasterCommitmentInputsV2) -> Result<(), MasterCommitmentError> {
    if value.epoch == 0 {
        return Err(MasterCommitmentError::EpochInvalid);
    }
    let scalar_digests = [
        &value.strong_settlement_domain_id_512,
        &value.strong_batch_nonce_512,
        &value.claim_truth_authority_digest_512,
        &value.nullifier_authority_id_512,
        &value.pepper_commitment_512,
        &value.replay_root_before_512,
        &value.replay_root_after_512,
        &value.operation_log_root_before_512,
        &value.operation_log_root_after_512,
        &value.salt_use_tag_512,
    ];
    if scalar_digests.into_iter().any(|digest| !nonzero(digest))
        || value
            .claim_truth_roots_512
            .iter()
            .any(|digest| !nonzero(digest))
        || value
            .payment_lane_roots_before_512
            .iter()
            .any(|digest| !nonzero(digest))
        || value
            .payment_lane_roots_after_512
            .iter()
            .any(|digest| !nonzero(digest))
    {
        return Err(MasterCommitmentError::DigestInvalid);
    }
    if value.slots.len() != value.profile.claim_slots() {
        return Err(MasterCommitmentError::SlotCountInvalid);
    }
    let totals = value.economic_totals;
    let expected_gross = totals
        .patient_responsibility_cents
        .checked_add(totals.plan_payable_cents)
        .ok_or(MasterCommitmentError::TotalOverflow)?;
    if totals.gross_allowed_cents != expected_gross {
        return Err(MasterCommitmentError::GrossConservationInvalid);
    }
    if totals.plan_payable_cents != totals.payer_reserve_debits_cents
        || totals.plan_payable_cents != totals.provider_payable_credits_cents
    {
        return Err(MasterCommitmentError::PaymentConservationInvalid);
    }

    let mut gross_sum = 0_u64;
    let mut payment_sum = 0_u64;
    for (index, slot) in value.slots.iter().enumerate() {
        if usize::from(slot.slot_index) != index {
            return Err(MasterCommitmentError::SlotOrderInvalid);
        }
        if slot.raw_gate_bits >= (1 << 13) || slot.effective_gate_bits >= (1 << 13) {
            return Err(MasterCommitmentError::SlotGateBitsInvalid);
        }
        if !nonzero(&slot.strong_nullifier_512) {
            return Err(MasterCommitmentError::DigestInvalid);
        }
        match slot.decision {
            1 if slot.failure_code == 0 && slot.payment_cents <= slot.allowed_cents => {}
            0 if slot.allowed_cents == 0 && slot.payment_cents == 0 => {}
            0 | 1 => return Err(MasterCommitmentError::SlotEconomicsInvalid),
            _ => return Err(MasterCommitmentError::SlotDecisionInvalid),
        }
        gross_sum = gross_sum
            .checked_add(u64::from(slot.allowed_cents))
            .ok_or(MasterCommitmentError::TotalOverflow)?;
        payment_sum = payment_sum
            .checked_add(u64::from(slot.payment_cents))
            .ok_or(MasterCommitmentError::TotalOverflow)?;
    }
    if gross_sum != totals.gross_allowed_cents {
        return Err(MasterCommitmentError::GrossTotalMismatch);
    }
    if payment_sum != totals.plan_payable_cents {
        return Err(MasterCommitmentError::PaymentTotalMismatch);
    }
    Ok(())
}

fn encode_slot(slot: &MasterSlotRecordV2, message: &mut Vec<u8>) {
    message.extend_from_slice(&slot.slot_index.to_be_bytes());
    message.push(slot.decision);
    message.extend_from_slice(&slot.failure_code.to_be_bytes());
    message.extend_from_slice(&slot.allowed_cents.to_be_bytes());
    message.extend_from_slice(&slot.payment_cents.to_be_bytes());
    message.extend_from_slice(&slot.raw_gate_bits.to_be_bytes());
    message.extend_from_slice(&slot.effective_gate_bits.to_be_bytes());
    message.extend_from_slice(&slot.strong_nullifier_512);
}

fn encode_totals(totals: MasterEconomicTotalsV2, message: &mut Vec<u8>) {
    for value in [
        totals.gross_allowed_cents,
        totals.patient_responsibility_cents,
        totals.plan_payable_cents,
        totals.payer_reserve_debits_cents,
        totals.provider_payable_credits_cents,
    ] {
        message.extend_from_slice(&value.to_be_bytes());
    }
}

pub fn governance_preimage(
    value: &MasterCommitmentInputsV2,
) -> Result<Vec<u8>, MasterCommitmentError> {
    validate(value)?;
    let mut message = Vec::with_capacity(607);
    message.extend_from_slice(GOVERNANCE_DOMAIN);
    message.push(value.profile as u8);
    message.extend_from_slice(&value.epoch.to_be_bytes());
    for root in &value.claim_truth_roots_512 {
        message.extend_from_slice(root);
    }
    message.extend_from_slice(&value.claim_truth_authority_digest_512);
    message.extend_from_slice(&value.nullifier_authority_id_512);
    message.extend_from_slice(&value.pepper_commitment_512);
    Ok(message)
}

pub fn batch_preimage(
    value: &MasterCommitmentInputsV2,
    governance_512: [u8; 64],
) -> Result<Vec<u8>, MasterCommitmentError> {
    validate(value)?;
    if !nonzero(&governance_512) {
        return Err(MasterCommitmentError::DigestInvalid);
    }
    let mut message = Vec::with_capacity(1_000 + value.slots.len() * 81);
    message.extend_from_slice(BATCH_DOMAIN);
    message.push(value.profile as u8);
    message.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    message.extend_from_slice(&value.epoch.to_be_bytes());
    message.extend_from_slice(&value.strong_settlement_domain_id_512);
    message.extend_from_slice(&value.strong_batch_nonce_512);
    message.extend_from_slice(&(value.slots.len() as u16).to_be_bytes());
    message.extend_from_slice(&governance_512);
    message.extend_from_slice(&value.replay_root_before_512);
    message.extend_from_slice(&value.replay_root_after_512);
    for root in &value.payment_lane_roots_before_512 {
        message.extend_from_slice(root);
    }
    for root in &value.payment_lane_roots_after_512 {
        message.extend_from_slice(root);
    }
    message.extend_from_slice(&value.operation_log_root_before_512);
    message.extend_from_slice(&value.operation_log_root_after_512);
    for slot in &value.slots {
        encode_slot(slot, &mut message);
    }
    message.extend_from_slice(&value.salt_use_tag_512);
    Ok(message)
}

pub fn value_preimage(value: &MasterCommitmentInputsV2) -> Result<Vec<u8>, MasterCommitmentError> {
    validate(value)?;
    let mut message = Vec::with_capacity(654);
    message.extend_from_slice(VALUE_DOMAIN);
    message.extend_from_slice(&value.epoch.to_be_bytes());
    message.extend_from_slice(&value.strong_batch_nonce_512);
    encode_totals(value.economic_totals, &mut message);
    for root in &value.payment_lane_roots_before_512 {
        message.extend_from_slice(root);
    }
    for root in &value.payment_lane_roots_after_512 {
        message.extend_from_slice(root);
    }
    message.extend_from_slice(&value.operation_log_root_before_512);
    message.extend_from_slice(&value.operation_log_root_after_512);
    Ok(message)
}

pub fn settlement_preimage(
    value: &MasterCommitmentInputsV2,
    governance_512: [u8; 64],
    batch_512: [u8; 64],
    value_conservation_512: [u8; 64],
) -> Result<Vec<u8>, MasterCommitmentError> {
    validate(value)?;
    if [governance_512, batch_512, value_conservation_512]
        .iter()
        .any(|digest| !nonzero(digest))
    {
        return Err(MasterCommitmentError::DigestInvalid);
    }
    let mut message = Vec::with_capacity(984);
    message.extend_from_slice(SETTLEMENT_DOMAIN);
    message.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    message.extend_from_slice(&value.strong_settlement_domain_id_512);
    message.extend_from_slice(&value.strong_batch_nonce_512);
    message.extend_from_slice(&governance_512);
    message.extend_from_slice(&batch_512);
    message.extend_from_slice(&value_conservation_512);
    message.extend_from_slice(&value.replay_root_before_512);
    message.extend_from_slice(&value.replay_root_after_512);
    for root in &value.payment_lane_roots_before_512 {
        message.extend_from_slice(root);
    }
    for root in &value.payment_lane_roots_after_512 {
        message.extend_from_slice(root);
    }
    message.extend_from_slice(&value.operation_log_root_before_512);
    message.extend_from_slice(&value.operation_log_root_after_512);
    Ok(message)
}

pub fn build_master_commitments_v2(
    value: &MasterCommitmentInputsV2,
) -> Result<MasterCommitmentsV2, MasterCommitmentError> {
    let governance_512 = sha3_512_reference(&governance_preimage(value)?);
    let batch_512 = sha3_512_reference(&batch_preimage(value, governance_512)?);
    let value_conservation_512 = sha3_512_reference(&value_preimage(value)?);
    let settlement_512 = sha3_512_reference(&settlement_preimage(
        value,
        governance_512,
        batch_512,
        value_conservation_512,
    )?);
    Ok(MasterCommitmentsV2 {
        governance_512,
        batch_512,
        value_conservation_512,
        settlement_512,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide(label: &[u8]) -> [u8; 64] {
        sha3_512_reference(label)
    }

    fn indexed(prefix: &[u8], index: usize) -> [u8; 64] {
        let mut label = Vec::from(prefix);
        if index >= 100 {
            label.push(b'0' + (index / 100) as u8);
        }
        if index >= 10 {
            label.push(b'0' + ((index / 10) % 10) as u8);
        }
        label.push(b'0' + (index % 10) as u8);
        wide(&label)
    }

    fn decode_hex_64(value: &str) -> [u8; 64] {
        fn nibble(value: u8) -> u8 {
            match value {
                b'0'..=b'9' => value - b'0',
                b'a'..=b'f' => value - b'a' + 10,
                _ => panic!("invalid test hex"),
            }
        }
        let bytes = value.as_bytes();
        let mut result = [0_u8; 64];
        assert_eq!(bytes.len(), 128);
        for index in 0..64 {
            result[index] = (nibble(bytes[2 * index]) << 4) | nibble(bytes[2 * index + 1]);
        }
        result
    }

    fn inputs() -> MasterCommitmentInputsV2 {
        let mut slots = Vec::with_capacity(128);
        for index in 0..128 {
            slots.push(MasterSlotRecordV2 {
                slot_index: index as u16,
                decision: 1,
                failure_code: 0,
                allowed_cents: 100,
                payment_cents: 80,
                raw_gate_bits: (1 << 13) - 1,
                effective_gate_bits: (1 << 13) - 1,
                strong_nullifier_512: indexed(b"nullifier-", index),
            });
        }
        MasterCommitmentInputsV2 {
            profile: Profile::K128Calibration,
            epoch: 7,
            strong_settlement_domain_id_512: wide(b"settlement-domain"),
            strong_batch_nonce_512: wide(b"batch-nonce"),
            claim_truth_roots_512: core::array::from_fn(|index| indexed(b"truth-", index)),
            claim_truth_authority_digest_512: wide(b"truth-authority"),
            nullifier_authority_id_512: wide(b"nullifier-authority"),
            pepper_commitment_512: wide(b"pepper"),
            replay_root_before_512: wide(b"replay-before"),
            replay_root_after_512: wide(b"replay-after"),
            payment_lane_roots_before_512: core::array::from_fn(|index| {
                indexed(b"payment-before-", index)
            }),
            payment_lane_roots_after_512: core::array::from_fn(|index| {
                indexed(b"payment-after-", index)
            }),
            operation_log_root_before_512: wide(b"operation-log-before"),
            operation_log_root_after_512: wide(b"operation-log-after"),
            salt_use_tag_512: wide(b"salt-use-tag"),
            economic_totals: MasterEconomicTotalsV2 {
                gross_allowed_cents: 12_800,
                patient_responsibility_cents: 2_560,
                plan_payable_cents: 10_240,
                payer_reserve_debits_cents: 10_240,
                provider_payable_credits_cents: 10_240,
            },
            slots,
        }
    }

    #[test]
    fn exact_python_k128_kat() {
        let value = inputs();
        let result = build_master_commitments_v2(&value).unwrap();
        assert_eq!(governance_preimage(&value).unwrap().len(), 607);
        assert_eq!(
            batch_preimage(&value, result.governance_512).unwrap().len(),
            11_294
        );
        assert_eq!(value_preimage(&value).unwrap().len(), 654);
        assert_eq!(
            settlement_preimage(
                &value,
                result.governance_512,
                result.batch_512,
                result.value_conservation_512,
            )
            .unwrap()
            .len(),
            984
        );
        assert_eq!(
            result.governance_512,
            decode_hex_64(
                "5aec9c1d6726289d216df393fc72d09a8a69df4189f8374170789cccd43edac240539aa3ffbd4fc10770cf6710664e988ad11943b3fe084fdb82be23945073e8"
            )
        );
        assert_eq!(
            result.batch_512,
            decode_hex_64(
                "c5b8d04d4287a7b7bacf32a84c829e162c6002e50d1b6a7f7d4639dfbed1e9a5a3e23df8403c56d539d5d57f07c3201bfba085951e7773f1c69998d7a825b051"
            )
        );
        assert_eq!(
            result.value_conservation_512,
            decode_hex_64(
                "16baeb823466fe023aa282f5096c7777ecc875d92a9cbbe8e18302dda084e3a3d54573b0ee508c26e8ced42e4ff457be798bc2ddeb7cd9213e0c35148377b412"
            )
        );
        assert_eq!(
            result.settlement_512,
            decode_hex_64(
                "a00b2dd005bdf8d64580039b743bcbe0e271656580f24720f02ae49c7bf3819fe17c599e7eb11298a79c48b4eeaed5c4f52be53306366b82986a83648cf14b68"
            )
        );
    }

    #[test]
    fn rejects_conservation_and_slot_tampering() {
        let mut value = inputs();
        value.economic_totals.gross_allowed_cents += 1;
        assert_eq!(
            build_master_commitments_v2(&value),
            Err(MasterCommitmentError::GrossConservationInvalid)
        );
        value = inputs();
        value.slots[0].decision = 0;
        assert_eq!(
            build_master_commitments_v2(&value),
            Err(MasterCommitmentError::SlotEconomicsInvalid)
        );
    }
}
