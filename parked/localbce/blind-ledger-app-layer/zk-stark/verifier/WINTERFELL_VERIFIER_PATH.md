# Winterfell Verifier Path

Status: Rust/off-chain verifier works. Solidity/on-chain verifier is not generated in this run.

## What Works

- `src/bin/verify_artifact.rs` verifies serialized Winterfell `.stark` proof bytes against public inputs.
- Verified artifact command:
  - `cargo +1.96.0-x86_64-pc-windows-msvc run --release --bin verify_artifact -- outputs/proofs/approved.stark outputs/public/approved.json`
- Latest result: approved proof verified successfully.

## What Does Not Exist Yet

Winterfell 0.13.1 provides a Rust STARK verifier, not a Solidity verifier generator. I did not fake an on-chain verifier with a proof hash, stub, or precompile assumption.

On-chain STARK verification therefore remains pending:

1. Choose an on-chain verifier strategy.
   - Port the Winterfell verifier primitives to Solidity, likely expensive.
   - Use a STARK system with an existing Ethereum verifier path.
   - Wrap/aggregate into a proof system with a practical EVM verifier.
2. Generate a real Solidity verifier for that chosen path.
3. Add a standalone Forge test that verifies an actual proof.
4. Measure gas against the existing Groth16 verifier.

## Current On-Chain Verdict

- On-chain STARK verification: not working yet.
- STARK gas cost: unavailable for this Winterfell PoC.
- Existing Groth16 on-chain verification still works in the app-layer Forge suite.

This is an honest verifier gap, not a cryptographic failure of the off-chain STARK core.

