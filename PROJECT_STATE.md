# Project State - Blind Ledger

## Current Working Flow

claim_input.json
-> Rust adjudication
-> denial_reason validation
-> zk/input.json
-> Circom witness generation
-> Groth16 proof generation
-> Solidity verifier
-> ClaimsRegistry
-> adjudication_result.json

## Active Project Folders

- blind-ledger/ - Solidity + Foundry
- zk/ - Circom + snarkjs
- rust-engine/ - Rust adjudication engine and ZK orchestration
- zk-prover/ - future dedicated proving service
- blind-ledger-app-layer/ - imported standalone app/audit layer from cofounder handoff
- gov-rules-kg-prototype/ - Claude web-grounded rules knowledge graph prototype

## Current Working Status

- G1-G10 prototype gates are working.
- Approved claims generate a proof and submit on-chain.
- Denied claims stop before proof generation.
- adjudication_result.json is generated for both approved and denied claims.
- tx_hash extraction is implemented for approved claims.
- claim_hash is generated from claim_id + claim_amount.
- Runtime submission config is loaded from rust-engine/config.json.
- Active Foundry tests cover ClaimsRegistry behavior and deployment.json generation.

## Active ClaimsRegistry

0xB7f8BC63BbcaD18155201308C8f3540b07f84F5e

Configured in rust-engine/config.json.

## Current Inputs

Active input file:

rust-engine/claim_input.json

Current Rust engine reads:

claim_input.json

Runtime config reads:

config.json

It does not yet read rules_v9.json directly.

## Active Test Files

- rust-engine/src/main.rs - Rust unit tests live beside the prototype binary.
- blind-ledger/test/ClaimsRegistry.t.sol - active ClaimsRegistry behavior tests.
- blind-ledger/test/DeploymentJson.t.sol - deployment.json smoke test.
- blind-ledger/foundry.toml - includes the narrow deployment.json filesystem permission needed by the smoke test.

## Imported Standalone App/Audit Layer

- blind-ledger-app-layer/app/ - Python claim ingestion, orchestration, 835 generation, dashboard state, and batch helpers.
- blind-ledger-app-layer/contracts/ - standalone Solidity contracts/tests from the cofounder handoff.
- blind-ledger-app-layer/tests/ - standalone Python tests for the imported app layer.
- blind-ledger-app-layer/rules-engine-rust/ - standalone Rust rules-engine crate from the handoff.
- blind-ledger-app-layer/zk-production-binding/ - standalone production-binding Circom lane and local smoke inputs/reports.
- blind-ledger-app-layer/zk-stark/, blind-ledger-app-layer/zk-sp1/, blind-ledger-app-layer/zk-cairo-sharp/ - research/audit lanes.

This layer is intentionally kept separate from the current active
rust-engine/zk/blind-ledger flow until a future explicit integration step.

## Rules Files

- rules.json - current/simple working rules
- rules_v9.json - future target architecture

Do not overwrite either file.

## Important Constraints

- main.rs must continue reading claim_input.json for now.
- denial_reason() must remain.
- Approved claims need a fresh claim_id.
- If claim.circom changes, Verifier.sol must be regenerated.
- If Verifier.sol changes, contracts must be redeployed.
- After redeploy, rust-engine/config.json claims_registry_address must be updated.

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
