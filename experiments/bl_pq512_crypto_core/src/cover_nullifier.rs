//! Canonical full-width cover-nullifier encoding for Wave 1A.
//!
//! Cover nullifiers use a 512-bit batch nonce and an independent 512-bit
//! private nonce.  The obsolete felt-sized batch-nonce format is deliberately
//! absent from this product-path module.

use alloc::vec::Vec;

use crate::sha3_air::sha3_512_reference;

pub const ENCODING_MAGIC_V2: &[u8; 8] = b"BLPQNF02";
pub const ENCODING_VERSION_V2: u16 = 2;
pub const COVER_DOMAIN_CODE_V2: u16 = 514;
pub const MAX_SLOT_INDEX: u16 = 511;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoverReplayContextV2<'a> {
    pub profile_id: &'a [u8],
    pub strong_settlement_domain_id_512: [u8; 64],
    pub epoch: u64,
    pub strong_batch_nonce_512: [u8; 64],
    pub slot_index: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoverNullifierError {
    ProfileInvalid,
    SettlementDomainInvalid,
    EpochInvalid,
    BatchNonceInvalid,
    SlotIndexInvalid,
    PrivateNonceInvalid,
    LengthOverflow,
}

fn nonzero(value: &[u8; 64]) -> bool {
    value.iter().any(|byte| *byte != 0)
}

pub fn encode_cover_preimage_v2(
    context: CoverReplayContextV2<'_>,
    private_cover_nonce_512: [u8; 64],
) -> Result<Vec<u8>, CoverNullifierError> {
    if context.profile_id.is_empty()
        || context.profile_id.len() > usize::from(u16::MAX)
        || !context.profile_id.is_ascii()
    {
        return Err(CoverNullifierError::ProfileInvalid);
    }
    if !nonzero(&context.strong_settlement_domain_id_512) {
        return Err(CoverNullifierError::SettlementDomainInvalid);
    }
    if context.epoch == 0 {
        return Err(CoverNullifierError::EpochInvalid);
    }
    if !nonzero(&context.strong_batch_nonce_512) {
        return Err(CoverNullifierError::BatchNonceInvalid);
    }
    if context.slot_index > MAX_SLOT_INDEX {
        return Err(CoverNullifierError::SlotIndexInvalid);
    }
    if !nonzero(&private_cover_nonce_512) {
        return Err(CoverNullifierError::PrivateNonceInvalid);
    }

    let body_length = 2_usize
        .checked_add(context.profile_id.len())
        .and_then(|value| value.checked_add(64 + 8 + 64 + 2 + 2 + 64))
        .ok_or(CoverNullifierError::LengthOverflow)?;
    let total_length = 16_usize
        .checked_add(body_length)
        .ok_or(CoverNullifierError::LengthOverflow)?;
    let total_length_u32 =
        u32::try_from(total_length).map_err(|_| CoverNullifierError::LengthOverflow)?;
    let profile_length =
        u16::try_from(context.profile_id.len()).map_err(|_| CoverNullifierError::LengthOverflow)?;

    let mut message = Vec::with_capacity(total_length);
    message.extend_from_slice(ENCODING_MAGIC_V2);
    message.extend_from_slice(&ENCODING_VERSION_V2.to_be_bytes());
    message.extend_from_slice(&COVER_DOMAIN_CODE_V2.to_be_bytes());
    message.extend_from_slice(&total_length_u32.to_be_bytes());
    message.extend_from_slice(&profile_length.to_be_bytes());
    message.extend_from_slice(context.profile_id);
    message.extend_from_slice(&context.strong_settlement_domain_id_512);
    message.extend_from_slice(&context.epoch.to_be_bytes());
    message.extend_from_slice(&context.strong_batch_nonce_512);
    message.extend_from_slice(&context.slot_index.to_be_bytes());
    message.extend_from_slice(&64_u16.to_be_bytes());
    message.extend_from_slice(&private_cover_nonce_512);
    debug_assert_eq!(message.len(), total_length);
    Ok(message)
}

pub fn strong_cover_nullifier_v2(
    context: CoverReplayContextV2<'_>,
    private_cover_nonce_512: [u8; 64],
) -> Result<[u8; 64], CoverNullifierError> {
    Ok(sha3_512_reference(&encode_cover_preimage_v2(
        context,
        private_cover_nonce_512,
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_hex_64(value: &str) -> [u8; 64] {
        fn nibble(value: u8) -> u8 {
            match value {
                b'0'..=b'9' => value - b'0',
                b'a'..=b'f' => value - b'a' + 10,
                _ => panic!("invalid test hex"),
            }
        }
        let bytes = value.as_bytes();
        assert_eq!(bytes.len(), 128);
        let mut result = [0_u8; 64];
        for index in 0..64 {
            result[index] = (nibble(bytes[2 * index]) << 4) | nibble(bytes[2 * index + 1]);
        }
        result
    }

    fn context() -> CoverReplayContextV2<'static> {
        CoverReplayContextV2 {
            profile_id: b"K128_CALIBRATION",
            strong_settlement_domain_id_512: sha3_512_reference(b"BL-A12-STRONG-DOMAIN"),
            epoch: 7,
            strong_batch_nonce_512: sha3_512_reference(b"BL-A12-STRONG-BATCH-NONCE"),
            slot_index: 127,
        }
    }

    #[test]
    fn exact_python_v2_kat() {
        let nonce = sha3_512_reference(b"BL-A12-COVER-NONCE");
        let encoded = encode_cover_preimage_v2(context(), nonce).unwrap();
        assert_eq!(encoded.len(), 238);
        assert_eq!(&encoded[..8], ENCODING_MAGIC_V2);
        assert_eq!(u16::from_be_bytes([encoded[10], encoded[11]]), 514);
        assert_eq!(u32::from_be_bytes(encoded[12..16].try_into().unwrap()), 238);
        assert_eq!(
            strong_cover_nullifier_v2(context(), nonce).unwrap(),
            decode_hex_64(
                "552249fee73b40d67d27f5e1a29aaa631381e30e4c3241bdb37502f0ab4d62bcf83f2f99dcb4b4ee8ea59e25c79e8ed9c682dadb5f3e2c675cc5e19a5b8ae34d"
            )
        );
    }

    #[test]
    fn rejects_truncated_entropy_and_out_of_range_slot() {
        let mut invalid = context();
        invalid.strong_batch_nonce_512 = [0_u8; 64];
        assert_eq!(
            encode_cover_preimage_v2(invalid, [1_u8; 64]),
            Err(CoverNullifierError::BatchNonceInvalid)
        );
        invalid = context();
        invalid.slot_index = 512;
        assert_eq!(
            encode_cover_preimage_v2(invalid, [1_u8; 64]),
            Err(CoverNullifierError::SlotIndexInvalid)
        );
    }
}
