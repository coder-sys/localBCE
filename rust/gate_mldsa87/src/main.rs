//! ML-DSA-87 (FIPS 204) over AWS-LC for RR/GATE/CHECKPOINT/v1. Binary stdin, no files.
//!   public-key : seed(32)                       -> public key (2592)
//!   sign       : seed(32) || message            -> signature (4627)
//!   verify     : pk(2592) || sig(4627) || message -> exit 0 valid, exit 1 invalid
//! Any malformed input exits 2. Messages are bounded at 64 KiB.
use aws_lc_rs::signature::{KeyPair, PqdsaKeyPair, UnparsedPublicKey, ML_DSA_87, ML_DSA_87_SIGNING};
use std::io::{Read, Write};

const SEED: usize = 32;
const PUBLIC_KEY: usize = 2592;
const SIGNATURE: usize = 4627;
const MAX_MESSAGE: usize = 64 * 1024;

fn fail(code: i32) -> ! {
    std::process::exit(code)
}

fn key(seed: &[u8]) -> PqdsaKeyPair {
    PqdsaKeyPair::from_seed(&ML_DSA_87_SIGNING, seed).unwrap_or_else(|_| fail(2))
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    let mut input = Vec::new();
    let limit = (SEED.max(PUBLIC_KEY + SIGNATURE) + MAX_MESSAGE + 1) as u64;
    if std::io::stdin().take(limit).read_to_end(&mut input).is_err() {
        fail(2);
    }
    let prefix = match mode.as_str() {
        "public-key" | "sign" => SEED,
        "verify" => PUBLIC_KEY + SIGNATURE,
        _ => fail(2),
    };
    if input.len() < prefix || input.len() - prefix > MAX_MESSAGE || (mode == "public-key" && input.len() != SEED) {
        fail(2);
    }
    let (head, message) = input.split_at(prefix);
    let output = match mode.as_str() {
        "public-key" => key(head).public_key().as_ref().to_vec(),
        "sign" => {
            let mut signature = vec![0u8; SIGNATURE];
            match key(head).sign(message, &mut signature) {
                Ok(SIGNATURE) => signature,
                _ => fail(2),
            }
        }
        _ => {
            let (public_key, signature) = head.split_at(PUBLIC_KEY);
            let valid = UnparsedPublicKey::new(&ML_DSA_87, public_key).verify(message, signature).is_ok();
            fail(if valid { 0 } else { 1 })
        }
    };
    if std::io::stdout().write_all(&output).is_err() {
        fail(2);
    }
}
