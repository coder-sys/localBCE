# Project State — Blind Ledger

## Current Working Flow

claim_input.json
→ Rust adjudication
→ denial_reason validation
→ zk/input.json
→ Circom witness generation
→ Groth16 proof generation
→ Solidity verifier
→ ClaimsRegistry
→ adjudication_result.json

## Active Project Folders

- blind-ledger/ — Solidity + Foundry
- zk/ — Circom + snarkjs
- rust-engine/ — Rust adjudication engine and ZK orchestration

## Current Working Status

- G1–G10 prototype gates are working.
- Approved claims generate a proof and submit on-chain.
- Denied claims stop before proof generation.
- adjudication_result.json is generated for both approved and denied claims.
- tx_hash extraction is implemented for approved claims.
- claim_hash is generated from claim_id + claim_amount.

## Active ClaimsRegistry

0xB7f8BC63BbcaD18155201308C8f3540b07f84F5e

## Current Inputs

Active input file:

rust-engine/claim_input.json

Current Rust engine reads:

claim_input.json

It does not yet read rules_v9.json directly.

## Rules Files

- rules.json — current/simple working rules
- rules_v9.json — future target architecture

Do not overwrite either file.

## Important Constraints

- main.rs must continue reading claim_input.json for now.
- denial_reason() must remain.
- Approved claims need a fresh claim_id.
- If claim.circom changes, Verifier.sol must be regenerated.
- If Verifier.sol changes, contracts must be redeployed.
- After redeploy, main.rs contract address must be updated.

## Current Limitation

The current implementation is a working prototype using:

Rust + Circom + Groth16 + Foundry

The long-term target architecture in rules_v9.json is broader and includes:

- off-circuit rules engine
- ZK Bouncer model
- Plonky3
- BabyBear
- Poseidon2
- oracle attestations
- Merkle roots
- nullifier trees
- policy registries