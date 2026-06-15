# AGENTS.md - Blind Ledger Instructions

## Project Goal

Maintain a working local prototype for privacy-preserving claims adjudication using:

- Rust adjudication engine
- Circom + Groth16 proofs
- Solidity verifier
- ClaimsRegistry smart contract
- Imported standalone app/audit layer from the cofounder handoff

Current workflow:

claim_input.json
-> Rust adjudication
-> zk/input.json
-> witness generation
-> Groth16 proof
-> Solidity verification
-> ClaimsRegistry submission
-> adjudication_result.json

---

# Project Structure

## zk-prover Directory

zk-prover/ exists as a future dedicated proving service directory.

Current active proof orchestration still happens from:

rust-engine/src/main.rs

Do not move proof orchestration into zk-prover until the current Groth16 flow is stable and explicitly refactored.

## blind-ledger-app-layer Directory

blind-ledger-app-layer/ is an imported standalone app/audit/research lane from the cofounder handoff.

It contains:

- Python app-layer orchestration and tests
- standalone Solidity contracts/tests
- standalone Rust rules-engine crate
- production-binding Circom research lane
- STARK/SP1/Cairo research notes and source

Do not silently wire this layer into the active rust-engine/zk/blind-ledger workflow.
Treat it as a separate review and integration candidate unless explicitly asked to merge behavior.

---

# Important Active Files

- rust-engine/src/main.rs
- rust-engine/config.json
- rust-engine/claim_input.json
- rust-engine/adjudication_result.json
- rust-engine/rules.json
- rust-engine/rules_v9.json
- zk/claim.circom
- blind-ledger/src/ClaimsRegistry.sol
- blind-ledger/src/Verifier.sol
- blind-ledger/script/Counter.s.sol
- blind-ledger/test/ClaimsRegistry.t.sol
- blind-ledger/test/DeploymentJson.t.sol
- blind-ledger/foundry.toml
- blind-ledger-app-layer/README.md
- blind-ledger-app-layer/COFOUNDER_HANDOFF_README.md
- blind-ledger-app-layer/app/
- blind-ledger-app-layer/contracts/
- blind-ledger-app-layer/tests/
- blind-ledger-app-layer/rules-engine-rust/
- blind-ledger-app-layer/zk-production-binding/

---

# Current Working Features

- G1-G10 denial rules
- denial_reason() in Rust
- Approved claims submit on-chain
- Denied claims stop before proof generation
- adjudication_result.json generation
- tx_hash extraction
- claim_hash generation
- Groth16 proof generation
- Solidity verifier integration
- runtime config loaded from rust-engine/config.json
- active Foundry tests for ClaimsRegistry
- deployment.json smoke test

---

# Important Constraints

## DO NOT BREAK

- main.rs must continue reading claim_input.json
- denial_reason() must remain
- rules_v9.json is NOT active yet
- rules.json and rules_v9.json must remain parallel
- adjudication_result.json must continue working
- approved claims require unique claim_id
- active ClaimsRegistry address lives in rust-engine/config.json

---

# Circuit Constraints

If claim.circom changes:

1. Recompile circuit
2. Regenerate zkey/verifier
3. Regenerate Verifier.sol
4. Redeploy contracts
5. Update claims_registry_address in rust-engine/config.json

Do not modify circuits casually.

---

# Deployment Notes

Current active ClaimsRegistry:

0xB7f8BC63BbcaD18155201308C8f3540b07f84F5e

Contract address is configured in rust-engine/config.json.

Deployment metadata is written to:

```text
blind-ledger/deployment.json
```

The deployment JSON behavior is covered by:

```text
blind-ledger/test/DeploymentJson.t.sol
```

---

# Preferred Development Style

- Keep changes incremental
- Preserve working flow
- Avoid large rewrites
- Prefer compatibility over architecture changes
- Never replace working files without backup

---

# Long-Term Architecture

rules_v9.json represents future target architecture.

Current implementation is still a prototype.

Long-term goals include:

- off-circuit rules engine
- recursive proofs
- Plonky3
- Poseidon2
- Merkle commitments
- nullifier trees
- policy registries
- oracle attestations
- ZK Bouncer architecture

Do not prematurely migrate the current system to full v9 architecture.

# Autonomous Work Rules

- Prefer small incremental refactors.
- Never perform large rewrites.
- Always preserve working Groth16 flow.
- Do not change zk circuits unless explicitly instructed.
- Run cargo test and cargo check after Rust changes.
- Run forge test and forge build after Solidity changes.
- Preserve backward compatibility.
- Create backups before major refactors.
- Prefer adding over replacing.
