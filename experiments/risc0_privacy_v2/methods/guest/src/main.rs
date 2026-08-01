use privacy_v2_model::{decode_witness, execute_complete_claim};
use risc0_zkvm::guest::env;

fn main() {
    let wire: Vec<u8> = env::read();
    let witness = decode_witness(&wire).expect("decode exact complete-claim witness wire format");
    let execution = execute_complete_claim(&witness).expect("verify complete private claim");
    env::commit(&execution.public_fields);
}
