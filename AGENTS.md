# AGENTS.md — Blind Ledger Instructions

## Project Goal

Maintain a working local prototype for privacy-preserving claims adjudication using:

- Rust adjudication engine
- Circom + Groth16 proofs
- Solidity verifier
- ClaimsRegistry smart contract

Current workflow:

claim_input.json
→ Rust adjudication
→ zk/input.json
→ witness generation
→ Groth16 proof
→ Solidity verification
→ ClaimsRegistry submission
→ adjudication_result.json

---

# Project Structure

## zk-prover Directory

zk-prover/ exists as a future dedicated proving service directory.

Current active proof orchestration still happens from:

rust-engine/src/main.rs

Do not move proof orchestration into zk-prover until the current Groth16 flow is stable and explicitly refactored.

---

# Important Active Files

- rust-engine/src/main.rs
- rust-engine/claim_input.json
- rust-engine/adjudication_result.json
- rust-engine/rules.json
- rust-engine/rules_v9.json
- zk/claim.circom

---

# Current Working Features

- G1–G10 denial rules
- denial_reason() in Rust
- Approved claims submit on-chain
- Denied claims stop before proof generation
- adjudication_result.json generation
- tx_hash extraction
- claim_hash generation
- Groth16 proof generation
- Solidity verifier integration

---

# Important Constraints

## DO NOT BREAK

- main.rs must continue reading claim_input.json
- denial_reason() must remain
- rules_v9.json is NOT active yet
- rules.json and rules_v9.json must remain parallel
- adjudication_result.json must continue working
- approved claims require unique claim_id

---

# Circuit Constraints

If claim.circom changes:

1. Recompile circuit
2. Regenerate zkey/verifier
3. Regenerate Verifier.sol
4. Redeploy contracts
5. Update contract address in main.rs

Do not modify circuits casually.

---

# Deployment Notes

Current active ClaimsRegistry:

0xB7f8BC63BbcaD18155201308C8f3540b07f84F5e

Contract address is currently hardcoded in main.rs.

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
- Preserve backward compatibility.
- Create backups before major refactors.
- Prefer adding over replacing.
