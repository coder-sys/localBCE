//! Exact hidden master-salt use tag used by the replay map.

use alloc::vec::Vec;

use crate::sha3_air::sha3_512_reference;

pub const SALT_USE_MAGIC: &[u8; 8] = b"BLPQSALT";
pub const SALT_USE_VERSION: u16 = 1;
pub const SALT_USE_DOMAIN_CODE: u16 = 259;
pub const SALT_USE_PREIMAGE_BYTES: usize = 78;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SaltUseError {
    SaltInvalid,
}

pub fn salt_use_preimage(master_salt_512: [u8; 64]) -> Result<Vec<u8>, SaltUseError> {
    if !master_salt_512.iter().any(|byte| *byte != 0) {
        return Err(SaltUseError::SaltInvalid);
    }
    let mut message = Vec::with_capacity(SALT_USE_PREIMAGE_BYTES);
    message.extend_from_slice(SALT_USE_MAGIC);
    message.extend_from_slice(&SALT_USE_VERSION.to_be_bytes());
    message.extend_from_slice(&SALT_USE_DOMAIN_CODE.to_be_bytes());
    message.extend_from_slice(&64_u16.to_be_bytes());
    message.extend_from_slice(&master_salt_512);
    debug_assert_eq!(message.len(), SALT_USE_PREIMAGE_BYTES);
    Ok(message)
}

pub fn salt_use_tag(master_salt_512: [u8; 64]) -> Result<[u8; 64], SaltUseError> {
    Ok(sha3_512_reference(&salt_use_preimage(master_salt_512)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_framing_and_domain_separation() {
        let salt = sha3_512_reference(b"BL-WAVE1A-RAW-MASTER-SALT");
        let message = salt_use_preimage(salt).unwrap();
        assert_eq!(message.len(), 78);
        assert_eq!(&message[..14], b"BLPQSALT\0\x01\x01\x03\0@");
        assert_eq!(salt_use_tag(salt).unwrap(), sha3_512_reference(&message));
        assert_eq!(
            salt_use_preimage([0_u8; 64]),
            Err(SaltUseError::SaltInvalid)
        );
    }
}
