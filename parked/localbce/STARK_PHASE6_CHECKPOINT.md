# STARK Phase 6 Checkpoint

## Status

Phase 6 is complete as a feature-gated Winterfell proof-preview lane.

The active production/demo runtime is still Groth16:

```text
rust-engine/claim_input.json
-> Rust adjudication
-> zk/input.json
-> Circom witness
-> Groth16 proof
-> Solidity verifier
-> ClaimsRegistry
-> adjudication_result.json
```

The STARK lane does not replace this flow yet.

## What Phase 6 Adds

The `stark-engine/` crate can now take the dry-run bridge artifact from
`rust-engine/`, normalize it into complete Winterfell witness candidate inputs,
and generate a feature-gated proof preview through the imported Winterfell PoC
adapter.

The full smoke chain now covers:

- STARK bridge input generation
- STARK bridge input validation
- Winterfell witness candidate generation
- Winterfell witness candidate validation
- Winterfell witness gap reporting
- source-data requirement generation
- source-data fixture generation
- complete Winterfell witness candidate generation
- complete Winterfell witness candidate validation
- feature-gated Winterfell proof preview generation
- feature-gated Winterfell proof preview validation
- claim-source root input generation and validation
- oracle-facts root input generation and validation
- fee-schedule root input generation and validation
- nullifier root transition input generation and validation
- batch-root plan generation and validation
- batch-root gap reporting
- proof intent generation
- witness plan generation and validation
- mock trace generation and validation
- Winterfell compatibility reporting
- Winterfell adapter gap planning

## Smoke Command

Run the full STARK bridge smoke chain from the repository root:

```bash
bash scripts/validate_stark_bridge_chain.sh
```

Expected final line:

```text
==> STARK bridge CLI chain smoke test passed
```

## Feature-Gated Proof Preview

The Winterfell proof preview commands require the `winterfell-poc` feature:

```bash
cd stark-engine
cargo run --features winterfell-poc --bin generate_winterfell_proof_preview -- \
  complete_winterfell_witness_candidate.json winterfell_proof_preview.json
cargo run --features winterfell-poc --bin validate_winterfell_proof_preview -- \
  winterfell_proof_preview.json
```

The smoke chain runs these commands automatically after it builds a complete
Winterfell witness candidate.

## Important Non-Claims

Phase 6 does not mean:

- the active Groth16 runtime has been replaced
- `rust-engine` submits STARK proofs
- `ClaimsRegistry` verifies STARK proofs
- batch roots are generated for production settlement
- nullifier trees are active production state
- Cairo is used
- app-layer ingestion is active runtime behavior

The proof preview is intentionally isolated inside `stark-engine/` and guarded
by a Cargo feature.

## Last Verified Locally

The following passed during Phase 6 completion:

- `bash scripts/validate_stark_bridge_chain.sh`

That smoke chain generated and validated the feature-gated Winterfell proof
preview with `verified: true`.

## Phase 7 Entry Point

Phase 7 should start with settlement-boundary planning, not runtime replacement.

Recommended first Phase 7 step:

1. Define the STARK verifier/attestation result object that could eventually be
   consumed by Solidity.
2. Keep it in `stark-engine/` as a generated/validated artifact.
3. Do not modify `ClaimsRegistry.sol` until the off-chain result contract is
   stable and tested.
4. Keep the Groth16 demo path green throughout.
