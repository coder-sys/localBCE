use std::fs;
use std::path::Path;

use bl_pq512_crypto_core::chained_public_coin::{
    decode_chained_public_coin_bundle, verify_chained_public_coin_bundle,
};
use sha3::{Digest, Sha3_512};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let argument = std::env::args_os()
        .nth(1)
        .ok_or("usage: chained_public_coin_verify <bundle>")?;
    let encoded = fs::read(Path::new(&argument))?;
    let bundle = decode_chained_public_coin_bundle(&encoded)?;
    let challenges = verify_chained_public_coin_bundle(&bundle)?;
    let bundle_sha3_512: [u8; 64] = Sha3_512::digest(&encoded).into();
    println!("status=verified");
    println!("authenticated_chain_heads=true");
    println!("pq_suite_diversity=true");
    println!("rounds={}", challenges.len());
    println!(
        "final_transcript_root={}",
        hex(&bundle.claimed_final_transcript_root)
    );
    println!("bundle_bytes={}", encoded.len());
    println!("bundle_sha3_512={}", hex(&bundle_sha3_512));
    Ok(())
}
