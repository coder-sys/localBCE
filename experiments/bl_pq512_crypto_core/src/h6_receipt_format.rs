//! Independent Rust parser for the fixed-width H6 sidecar and receipt grammar.
//!
//! This is a nonactivating parser KAT surface. It deliberately carries only
//! fixed-width identities and rejects every length, flag, reserved-byte, and
//! zero-identity mutation before returning fields.

use alloc::vec::Vec;

pub const SIDECAR_MAGIC: [u8; 8] = *b"BLH6SC01";
pub const RECEIPT_MAGIC: [u8; 8] = *b"BLH6RC01";
pub const VERSION: u16 = 1;
pub const HEADER_BYTES: usize = 16;
pub const IDENTITY_BYTES: usize = 64;
pub const SIDECAR_FIELD_COUNT: usize = 11;
pub const RECEIPT_FIELD_COUNT: usize = 7;
pub const SIDECAR_BYTES: usize = 744;
pub const RECEIPT_BYTES: usize = 512;
pub const SIDECAR_RESERVED_BYTES: usize =
    SIDECAR_BYTES - HEADER_BYTES - IDENTITY_BYTES * SIDECAR_FIELD_COUNT;
pub const RECEIPT_RESERVED_BYTES: usize =
    RECEIPT_BYTES - HEADER_BYTES - IDENTITY_BYTES * RECEIPT_FIELD_COUNT;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum H6ReceiptFormatError {
    Length,
    Magic,
    Version,
    Flags,
    DeclaredLength,
    Reserved,
    ZeroIdentity,
}

fn encode<const N: usize>(
    magic: [u8; 8],
    total: usize,
    reserved: usize,
    fields: &[[u8; IDENTITY_BYTES]; N],
) -> Vec<u8> {
    let mut output = Vec::with_capacity(total);
    output.extend_from_slice(&magic);
    output.extend_from_slice(&VERSION.to_be_bytes());
    output.extend_from_slice(&0_u16.to_be_bytes());
    output.extend_from_slice(&(total as u32).to_be_bytes());
    for field in fields {
        assert!(field.iter().any(|byte| *byte != 0));
        output.extend_from_slice(field);
    }
    output.resize(total, 0);
    assert_eq!(output.len(), total);
    assert_eq!(reserved, total - HEADER_BYTES - N * IDENTITY_BYTES);
    output
}

fn parse<const N: usize>(
    encoded: &[u8],
    magic: [u8; 8],
    total: usize,
    reserved: usize,
) -> Result<[[u8; IDENTITY_BYTES]; N], H6ReceiptFormatError> {
    if encoded.len() != total {
        return Err(H6ReceiptFormatError::Length);
    }
    if encoded[..8] != magic {
        return Err(H6ReceiptFormatError::Magic);
    }
    if u16::from_be_bytes(encoded[8..10].try_into().unwrap()) != VERSION {
        return Err(H6ReceiptFormatError::Version);
    }
    if u16::from_be_bytes(encoded[10..12].try_into().unwrap()) != 0 {
        return Err(H6ReceiptFormatError::Flags);
    }
    if u32::from_be_bytes(encoded[12..16].try_into().unwrap()) as usize != total {
        return Err(H6ReceiptFormatError::DeclaredLength);
    }
    let fields_end = HEADER_BYTES + N * IDENTITY_BYTES;
    if encoded[fields_end..].iter().any(|byte| *byte != 0) || encoded.len() - fields_end != reserved
    {
        return Err(H6ReceiptFormatError::Reserved);
    }
    let mut fields = [[0_u8; IDENTITY_BYTES]; N];
    for (index, field) in fields.iter_mut().enumerate() {
        let start = HEADER_BYTES + index * IDENTITY_BYTES;
        field.copy_from_slice(&encoded[start..start + IDENTITY_BYTES]);
        if !field.iter().any(|byte| *byte != 0) {
            return Err(H6ReceiptFormatError::ZeroIdentity);
        }
    }
    Ok(fields)
}

pub fn encode_sidecar(fields: &[[u8; IDENTITY_BYTES]; SIDECAR_FIELD_COUNT]) -> Vec<u8> {
    encode(SIDECAR_MAGIC, SIDECAR_BYTES, SIDECAR_RESERVED_BYTES, fields)
}

pub fn parse_sidecar(
    encoded: &[u8],
) -> Result<[[u8; IDENTITY_BYTES]; SIDECAR_FIELD_COUNT], H6ReceiptFormatError> {
    parse(
        encoded,
        SIDECAR_MAGIC,
        SIDECAR_BYTES,
        SIDECAR_RESERVED_BYTES,
    )
}

pub fn encode_receipt(fields: &[[u8; IDENTITY_BYTES]; RECEIPT_FIELD_COUNT]) -> Vec<u8> {
    encode(RECEIPT_MAGIC, RECEIPT_BYTES, RECEIPT_RESERVED_BYTES, fields)
}

pub fn parse_receipt(
    encoded: &[u8],
) -> Result<[[u8; IDENTITY_BYTES]; RECEIPT_FIELD_COUNT], H6ReceiptFormatError> {
    parse(
        encoded,
        RECEIPT_MAGIC,
        RECEIPT_BYTES,
        RECEIPT_RESERVED_BYTES,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields<const N: usize>() -> [[u8; IDENTITY_BYTES]; N] {
        let mut output = [[0_u8; IDENTITY_BYTES]; N];
        for (index, field) in output.iter_mut().enumerate() {
            field.fill((index + 1) as u8);
        }
        output
    }

    #[test]
    fn sidecar_and_receipt_round_trip_exactly() {
        let sidecar_fields = fields::<SIDECAR_FIELD_COUNT>();
        let receipt_fields = fields::<RECEIPT_FIELD_COUNT>();
        let sidecar = encode_sidecar(&sidecar_fields);
        let receipt = encode_receipt(&receipt_fields);
        assert_eq!(sidecar.len(), SIDECAR_BYTES);
        assert_eq!(receipt.len(), RECEIPT_BYTES);
        assert_eq!(parse_sidecar(&sidecar).unwrap(), sidecar_fields);
        assert_eq!(parse_receipt(&receipt).unwrap(), receipt_fields);
    }

    #[test]
    fn malformed_headers_and_reserved_bytes_reject() {
        let fields = fields::<RECEIPT_FIELD_COUNT>();
        let receipt = encode_receipt(&fields);
        let mut bad = receipt.clone();
        bad[0] ^= 1;
        assert_eq!(parse_receipt(&bad), Err(H6ReceiptFormatError::Magic));
        let mut bad_reserved = receipt;
        *bad_reserved.last_mut().unwrap() = 1;
        assert_eq!(
            parse_receipt(&bad_reserved),
            Err(H6ReceiptFormatError::Reserved)
        );
        assert_eq!(
            parse_receipt(&bad_reserved[..RECEIPT_BYTES - 1]),
            Err(H6ReceiptFormatError::Length)
        );
    }
}
