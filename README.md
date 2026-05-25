# Blind Ledger — ZK Claims Adjudication Prototype

Blind Ledger is a local prototype for privacy-preserving healthcare claims adjudication using:

- Rust
- Circom
- Groth16
- Solidity
- Foundry

The system validates claims off-chain, generates zero-knowledge proofs for approved claims, and records approved adjudications on-chain.

---

# Current Workflow

claim_input.json
→ Rust adjudication
→ denial_reason validation
→ zk/input.json
→ witness generation
→ Groth16 proof
→ Solidity verifier
→ ClaimsRegistry
→ adjudication_result.json

---

# Project Structure

localBCE/
├── blind-ledger/     Solidity + Foundry
├── zk/               Circom + snarkjs artifacts
├── zk-prover/        future/dedicated proof service
└── rust-engine/      Rust adjudication engine
---

# Current Features

## Rust Adjudication Engine

- Claim parsing
- Claim hashing
- Structured denial reasons
- G1–G10 rule validation
- adjudication_result.json generation
- tx_hash extraction

## ZK Layer

- Circom circuits
- Witness generation
- Groth16 proving
- Solidity verifier generation

## Smart Contracts

- Verifier.sol
- ClaimsRegistry.sol
- On-chain approved claim recording

---

# Current Gate Coverage

- G1 Eligibility
- G2 Aid code validation
- G3 Date range validation
- G4 Share-of-cost validation
- G5 Provider validation
- G6 Billing validation
- G7 Duplicate detection
- G8 Disability determination
- G9 Recipient deceased validation
- G10 Physician certification

---

# Current Output

Approved claim:

```json
{
  "claim_id": "CLAIM-DEMO-010",
  "claim_hash": "0x97a2edc417f16993e07f860e1f52cc3d86f8adfe66ab5c4d21369ef5c2ff58c5",
  "status": "APPROVED",
  "reason": null,
  "tx_submitted": true,
  "tx_hash": "0xc2a2ee618bebfd2de66ea982a1b4f4c0566a12a27746382eafcfd43b330852dd"
}
```

Denied claim:

```json
{
  "claim_id": "CLAIM-DEMO-009",
  "claim_hash": "0x470b16112aff0e4ef85c47f50c21695e8eedbac749eeda1c7dd42320300c4eff",
  "status": "DENIED",
  "reason": "G9_RECIPIENT_DECEASED",
  "tx_submitted": false,
  "tx_hash": null
}
```

---

# Current Status

Prototype is functional end-to-end.

Working components:

- Rust → ZK integration
- Groth16 proof generation
- Solidity verification
- ClaimsRegistry recording
- structured adjudication outputs

---

# Active ClaimsRegistry

0xB7f8BC63BbcaD18155201308C8f3540b07f84F5e

---

# Current Rules Files

- rules.json — current/simple working rules
- rules_v9.json — future target architecture

Current Rust engine still reads:

```text
claim_input.json
```

rules_v9.json is not yet active.

---

# Important Constraints

- main.rs must continue reading claim_input.json
- denial_reason() must remain
- approved claims require unique claim_id
- adjudication_result.json must continue working
- rules.json and rules_v9.json must remain parallel

If claim.circom changes:

1. Recompile circuit
2. Regenerate zkey
3. Regenerate Verifier.sol
4. Redeploy contracts
5. Update contract address in main.rs

---

# Future Goals

- rules_v9.json integration
- recursive proofs
- policy registries
- Merkle commitments
- nullifier trees
- Plonky3 migration
- oracle attestations
- off-circuit rules engine
- ZK Bouncer architecture