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

## Public Input Root Assembly Plan

The next planning object is:

```text
PublicInputRootAssemblyPlan
```

It defines the canonical public-input preimage order for the future
`public_input_root`:

```text
0. claim_hash
1. decision
2. failure_code
3. public_input_root
4. claim_source_root
5. oracle_facts_root
6. fee_schedule_root
7. nullifier_root_before
8. nullifier_root_after
9. batch_root
```

This is still planning-only:

- no hash strategy is selected for production
- no public input root is generated
- root fields still require future root generation
- Groth16 remains the active runtime path

The public-input root assembly CLI pair is:

```text
generate_public_input_root_assembly_plan
validate_public_input_root_assembly_plan
```

## Proof Commitment Preimage Plan

The next planning object is:

```text
ProofCommitmentPreimagePlan
```

It defines the canonical preimage order for the future `proof_commitment`:

```text
0. target_artifact_schema_version
1. solidity_abi_candidate
2. prover
3. proof_bytes
4. public_input_root
5. claim_hash
6. decision
7. failure_code
```

This is still planning-only:

- no proof bytes are generated
- no prover is selected for runtime
- no public input root is generated
- no proof commitment is generated
- Groth16 remains the active runtime path

The proof commitment preimage CLI pair is:

```text
generate_proof_commitment_preimage_plan
validate_proof_commitment_preimage_plan
```

## Proof Artifact Fixture Expectations

The next planning object is:

```text
ProofArtifactFixtureExpectationSet
```

It defines the minimum approved and denied fixture shapes the first real STARK
proof artifact must satisfy before runtime wiring:

- `approved_claim`
  - `decision = 1`
  - `failure_code = 0`
- `denied_claim`
  - `decision = 0`
  - `failure_code != 0`

Both fixture shapes require these dependencies before runtime wiring:

- generated public input root
- real proof bytes
- generated proof commitment
- local verification result

The expectation set keeps:

```text
runtime_wiring_allowed = false
groth16_flow_unchanged = true
```

The proof artifact fixture expectation CLI pair is:

```text
generate_proof_artifact_fixture_expectations
validate_proof_artifact_fixture_expectations
```

## Next Safe Step

The next safe Phase 8 step is to start replacing the root placeholders with
deterministic pre-root commitments, still without runtime wiring:

- selected prover byte encoding
