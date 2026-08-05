use std::io::{self, Read};

use bl_pq512_crypto_core::h6_proof_body_format::{
    H6ProofBodyFormatError, PROOF_BODY_BYTES, parse_h6_proof_body,
};

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

fn main() {
    let capacity = std::env::args()
        .nth(1)
        .expect("capacity")
        .parse::<u16>()
        .expect("capacity_integer");
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input).expect("stdin_read");
    let summary = parse_h6_proof_body(&input, capacity).expect("valid_proof_body");

    let mut bad_magic = input.clone();
    bad_magic[0] ^= 1;
    assert_eq!(
        parse_h6_proof_body(&bad_magic, capacity),
        Err(H6ProofBodyFormatError::Magic)
    );
    let mut bad_grammar = input.clone();
    bad_grammar[24] ^= 1;
    assert_eq!(
        parse_h6_proof_body(&bad_grammar, capacity),
        Err(H6ProofBodyFormatError::GrammarDigest)
    );
    let mut bad_section = input.clone();
    bad_section[352] ^= 1;
    assert_eq!(
        parse_h6_proof_body(&bad_section, capacity),
        Err(H6ProofBodyFormatError::SectionDigest)
    );
    assert_eq!(
        parse_h6_proof_body(&input[..PROOF_BODY_BYTES - 1], capacity),
        Err(H6ProofBodyFormatError::Length)
    );

    println!("h6_proof_body_kat=PASS");
    println!("capacity={capacity}");
    println!("proof_bytes={}", input.len());
    println!("grammar_sha3_512={}", hex(&summary.grammar_digest));
    for (index, digest) in summary.section_digests.iter().enumerate() {
        println!("section_{index}_sha3_512={}", hex(digest));
    }
    println!("mutation_rejections=4");
}
