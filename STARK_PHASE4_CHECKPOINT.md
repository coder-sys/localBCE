# STARK Phase 4 Checkpoint

## Status

Phase 4 is complete as a pre-prover planning layer.

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

## Phase 4 Artifacts

The active STARK bridge can now generate and validate planning-only inputs for:

- `claimSourceRoot`
- `oracleFactsRoot`
- `feeScheduleRoot`
- `nullifierRootBefore -> nullifierRootAfter`
- batch-root compatibility planning
- batch-root gap reporting
- proof intent planning
- witness planning
- mock trace generation
- Winterfell PoC compatibility reporting
- Winterfell adapter gap planning

All of these are schemas, validators, and planning artifacts. They do not build
Merkle roots, derive nullifiers, execute Winterfell, generate STARK proofs, or
submit on-chain.

## Smoke Command

Run the full STARK bridge smoke chain from the repo root:

```bash
bash scripts/validate_stark_bridge_chain.sh
```

This command runs:

```text
rust-engine:
  cargo run -- stark-bridge-input-dry-run

stark-engine:
  validate_bridge_input
  generate_claim_source_root_input
  validate_claim_source_root_input
  generate_oracle_facts_root_input
  validate_oracle_facts_root_input
  generate_fee_schedule_root_input
  validate_fee_schedule_root_input
  generate_nullifier_root_transition_input
  validate_nullifier_root_transition_input
  generate_batch_root_plan
  validate_batch_root_plan
  generate_batch_root_gap_report
  generate_proof_intent
  generate_witness_plan
  validate_witness_plan
  generate_mock_trace
  validate_mock_trace
  generate_winterfell_compat_report
  generate_winterfell_gap_plan
```

Expected final line:

```text
==> STARK bridge CLI chain smoke test passed
```

## Last Verified Locally

The following passed during Phase 4 completion:

- `cargo test` in `stark-engine/`
- `cargo check` in `stark-engine/`
- `bash scripts/validate_stark_bridge_chain.sh`

## Important Non-Claims

Phase 4 does not mean:

- no real STARK proof is generated
- no Merkle root is generated
- no nullifier is derived
- no nullifier tree transition is applied
- no Winterfell prover is imported or executed
- no Cairo code is used
- no Groth16 runtime behavior is changed
- no ClaimsRegistry STARK verifier is active

## Phase 5 Entry Point

Phase 5 should start with real prover-adapter planning, not runtime wiring.

Recommended first Phase 5 step:

1. Review `blind-ledger-app-layer/zk-stark/` against the Phase 4 schemas.
2. Decide the first narrow adapter target.
3. Add test-only adapter contracts/models before importing Winterfell.
4. Keep `rust-engine/`, `zk/`, and `blind-ledger/` Groth16 behavior unchanged.
