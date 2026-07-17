# STARK Phase 8 Prover Boundary

## Status

Phase 8 has started as a planning-only real-prover boundary.

The active runtime is still Groth16. No STARK proof is submitted on-chain and no
active `ClaimsRegistry.sol` behavior changes.

## New Boundary Artifact

The Phase 8 boundary model is:

```text
StarkProofArtifactV1Candidate
```

It is defined in:

```text
stark-engine/src/lib.rs
```

It is derived from validated `StarkBridgeInput` and is shaped toward:

```text
blind-ledger/src/IStarkClaimsVerifierV1Candidate.sol
```

## What It Contains

The candidate carries:

- `claim_id`
- `claim_hash`
- `decision`
- `failure_code`
- Solidity V1 public-input field names
- root placeholders for:
  - `publicInputRoot`
  - `claimSourceRoot`
  - `oracleFactsRoot`
  - `feeScheduleRoot`
  - `nullifierRootBefore`
  - `nullifierRootAfter`
  - `batchRoot`
- proof byte placeholders
- proof commitment placeholders
- local verification placeholders
- `solidity_abi_candidate = IStarkClaimsVerifierV1Candidate`
- `runtime_wired = false`
- `on_chain_submission = false`
- `groth16_flow_unchanged = true`

## Important Non-Claims

This does not mean:

- real proof bytes exist
- proof commitments are production-defined
- public input roots are generated
- local STARK verification is production-ready
- Solidity can verify STARK proofs
- Groth16 has been replaced

The artifact explicitly rejects runtime-like flags and generated-proof claims.

## Tests

The Phase 8 candidate is covered by:

```text
stark-engine/tests/phase8_proof_artifact_candidate.rs
```

The tests cover:

- approved candidate conversion
- denied candidate conversion
- root placeholders remain absent
- proof bytes remain absent
- local verification remains false
- runtime/on-chain flags remain false
- decision/failure-code consistency
- JSON round-trip stability

## CLI Commands

The Phase 8 candidate CLI pair is:

```text
generate_stark_proof_artifact_v1_candidate
validate_stark_proof_artifact_v1_candidate
```

The commands read `stark_bridge_input.json`, write the candidate JSON, validate
it, and are included in the STARK smoke chain without generating a real proof:

```bash
bash scripts/validate_stark_bridge_chain.sh
```

## Real Artifact Boundary Spec

The next planning object is:

```text
StarkProofArtifactV1BoundarySpec
```

It defines the exact fields required before a first real artifact can exist:

- public inputs:
  - `claim_hash`
  - `decision`
  - `failure_code`
  - `public_input_root`
  - `claim_source_root`
  - `oracle_facts_root`
  - `fee_schedule_root`
  - `nullifier_root_before`
  - `nullifier_root_after`
  - `batch_root`
- proof fields:
  - `proof_bytes`
  - `proof_commitment`
  - `prover`
- local verification fields:
  - `verified`
  - `verification_status`
  - `verifier`

The boundary spec is still planning-only. It does not generate roots, proof
bytes, proof commitments, or local verification results.

The boundary spec CLI pair is:

```text
generate_stark_proof_artifact_v1_boundary_spec
validate_stark_proof_artifact_v1_boundary_spec
```

## Next Safe Step

The next safe Phase 8 step is to start filling this boundary from real
pre-prover inputs, still without runtime wiring:

- deterministic public-input root assembly
- deterministic proof commitment preimage rules
- approved/denied fixture expectations
- selected prover byte encoding
