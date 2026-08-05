use bl_pq512_crypto_core::h6_receipt_format::{
    H6ReceiptFormatError, IDENTITY_BYTES, RECEIPT_BYTES, RECEIPT_FIELD_COUNT, SIDECAR_BYTES,
    SIDECAR_FIELD_COUNT, encode_receipt, encode_sidecar, parse_receipt, parse_sidecar,
};
use sha3::{Digest, Sha3_512};

fn fields<const N: usize>() -> [[u8; IDENTITY_BYTES]; N] {
    let mut output = [[0_u8; IDENTITY_BYTES]; N];
    for (index, field) in output.iter_mut().enumerate() {
        field.fill((index + 1) as u8);
    }
    output
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

fn digest(bytes: &[u8]) -> [u8; 64] {
    let mut hasher = Sha3_512::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

fn grammar_digest() -> [u8; 64] {
    let mut hasher = Sha3_512::new();
    hasher.update(b"BL/PQ512/H6/RECEIPT-GRAMMAR/v1\0");
    hasher.update(b"BLH6SC01");
    hasher.update(b"BLH6RC01");
    hasher.update(1_u16.to_be_bytes());
    hasher.update((SIDECAR_BYTES as u32).to_be_bytes());
    hasher.update((RECEIPT_BYTES as u32).to_be_bytes());
    hasher.update((SIDECAR_FIELD_COUNT as u16).to_be_bytes());
    hasher.update((RECEIPT_FIELD_COUNT as u16).to_be_bytes());
    hasher.finalize().into()
}

fn main() {
    let sidecar_fields = fields::<SIDECAR_FIELD_COUNT>();
    let receipt_fields = fields::<RECEIPT_FIELD_COUNT>();
    let sidecar = encode_sidecar(&sidecar_fields);
    let receipt = encode_receipt(&receipt_fields);
    assert_eq!(sidecar.len(), SIDECAR_BYTES);
    assert_eq!(receipt.len(), RECEIPT_BYTES);
    assert_eq!(parse_sidecar(&sidecar).unwrap(), sidecar_fields);
    assert_eq!(parse_receipt(&receipt).unwrap(), receipt_fields);

    let mut bad_magic = receipt.clone();
    bad_magic[0] ^= 1;
    assert_eq!(parse_receipt(&bad_magic), Err(H6ReceiptFormatError::Magic));
    let mut bad_reserved = receipt.clone();
    *bad_reserved.last_mut().unwrap() = 1;
    assert_eq!(
        parse_receipt(&bad_reserved),
        Err(H6ReceiptFormatError::Reserved)
    );
    assert_eq!(
        parse_receipt(&receipt[..RECEIPT_BYTES - 1]),
        Err(H6ReceiptFormatError::Length)
    );

    println!("h6_receipt_grammar_kat=PASS");
    println!("sidecar_bytes={}", sidecar.len());
    println!("receipt_bytes={}", receipt.len());
    println!("sidecar_sha3_512={}", hex(&digest(&sidecar)));
    println!("receipt_sha3_512={}", hex(&digest(&receipt)));
    println!("grammar_sha3_512={}", hex(&grammar_digest()));
    println!("sidecar_parser=PASS");
    println!("receipt_parser=PASS");
    println!("mutation_rejections=3");
}
