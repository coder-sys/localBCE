#![no_main]
sp1_zkvm::entrypoint!(main);

use fibonacci_lib::{abi_encode_public_values, expected_public_values, ClaimInput};

pub fn main() {
    let input = sp1_zkvm::io::read::<ClaimInput>();
    let (decision, failure_code) = expected_public_values(&input);
    let bytes = abi_encode_public_values(
        input.raw_claim_identity_commitment,
        input.batch_context_commitment,
        decision,
        failure_code,
    );
    sp1_zkvm::io::commit_slice(&bytes);
}
