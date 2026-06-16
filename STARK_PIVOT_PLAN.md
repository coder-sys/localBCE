# STARK Pivot Plan

Status: active migration direction. This does not replace the current Groth16 runtime yet.

## Decision

Blind Ledger should pivot production architecture toward STARK proofs while keeping the existing Groth16 path as the working compatibility and demo flow.

Current active flow remains:

```text
claim_input.json
-> Rust adjudication
-> zk/input.json
-> Circom witness generation
-> Groth16 proof generation
-> Solidity verifier
-> ClaimsRegistry submission
-> adjudication_result.json
```

Production target:

```text
claim_input.json
-> Rust adjudication
-> deterministic rule result
-> STARK witness/proof generation
-> STARK public outputs
-> batch roots / result roots / nullifier roots
-> native STARK verification or controlled attestation anchor
-> ClaimsRegistry-compatible settlement
```

## Why Pivot

- STARKs avoid trusted setup.
- STARKs are hash/FRI based and are the better post-quantum production direction.
- The imported `blind-ledger-app-layer/zk-stark/` lane already contains a runnable Winterfell proof core.
- The current Groth16 path is useful for demos and EVM practicality, but it should not be described as the long-term post-quantum architecture.

## What Must Not Change Yet

- Do not delete or disable the current Groth16 flow.
- Do not modify `zk/claim.circom` as part of this pivot.
- Do not replace `blind-ledger/src/Verifier.sol` until there is a selected STARK verifier strategy.
- Do not change the `adjudication_result.json` schema until a sidecar STARK artifact is stable.
- Do not make `rust-engine/src/main.rs` depend on the imported app-layer STARK crate directly yet.
- Do not claim end-to-end post-quantum settlement until the chain anchor verifies STARK/FRI natively or the trust model is explicitly documented.

## Current Gap

The current active chain verifies Groth16 proofs on-chain through the Solidity verifier. The imported STARK lane verifies STARK proofs off-chain in Rust. It does not yet provide an EVM-native verifier or production settlement path.

That means a full immediate swap would break the active blockchain workflow.

## Safe Migration Phases

### Phase 1 - Compatibility Mapping

Add a non-runtime compatibility layer that maps the current Rust claim model and G1-G10 denial reasons into a STARK-oriented normalized witness shape.

Requirements:

- Runtime behavior unchanged.
- Groth16 still runs for approved claims.
- Denied claims still stop before proof generation.
- Existing Rust tests remain green.
- Mapping tests prove the current G1-G10 behavior and STARK-normalized gates agree where the gate semantics overlap.

### Phase 2 - Sidecar STARK Proof Artifact

Generate STARK proof outputs beside the current Groth16 flow without submitting them on-chain.

Recommended output files:

```text
rust-engine/stark_adjudication_result.json
rust-engine/stark_public_inputs.json
rust-engine/stark_proof_metadata.json
```

Requirements:

- Existing `adjudication_result.json` stays unchanged.
- Existing `zk/input.json` stays unchanged.
- ClaimsRegistry submission still uses Groth16.
- STARK outputs are experimental sidecars until audited.

### Phase 3 - Batch-Oriented STARK Model

Move from one proof per claim toward one proof per batch.

Batch public outputs should eventually include:

- batch root
- result root
- nullifier root transition
- ruleset root
- verifier version
- claim result commitments
- failure-code commitments

### Phase 4 - Chain Anchor Decision

Choose one verifier strategy:

1. Native FRI verifier contract.
2. L2/app-chain verifier precompile.
3. Regulated off-chain verification with on-chain commitment and attestation.

Do not call option 3 trustless on-chain verification. It is an interim controlled deployment model.

### Phase 5 - Production Hardening

Before production:

- Replace PoC commitment with audited production commitment.
- Finalize STARK field/hash stack.
- Add nullifier non-membership.
- Add proof replay protection and domain separation.
- Audit AIR constraints.
- Audit verifier implementation.
- Ratify legal/policy gate semantics.

## Highest-Value Next Step

Implement Phase 1 only:

Add Rust-side STARK compatibility tests that map the current `ClaimInput` and `denial_reason()` outputs into a normalized STARK candidate witness format. These tests should not alter runtime behavior and should not read the imported app-layer crate yet.

This creates the bridge from today's working Rust engine to the future STARK proof lane without touching circuits, contracts, rules files, or current Groth16 submission.

## Current Honest Claim

Blind Ledger has:

- a working Groth16 demo path with on-chain verification
- an imported runnable STARK research lane
- a clear STARK production direction

Blind Ledger does not yet have:

- native on-chain STARK verification
- audited production STARK commitments
- STARK-backed ClaimsRegistry settlement
- end-to-end post-quantum chain finality

