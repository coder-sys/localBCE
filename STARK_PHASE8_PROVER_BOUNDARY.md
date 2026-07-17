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

## Next Safe Step

The next safe Phase 8 step is a CLI pair:

```text
generate_stark_proof_artifact_v1_candidate
validate_stark_proof_artifact_v1_candidate
```

Those commands should read `stark_bridge_input.json`, write the candidate JSON,
validate it, and add it to the STARK smoke chain without generating a real
proof.
