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

## Public Input Root Digest Candidate

The next planning object is:

```text
PublicInputRootDigestCandidate
```

It creates the first deterministic candidate digest from the assembly-plan
preimage:

```text
hash_algorithm = sha2_256_candidate_not_production_hash
root_generation_status = candidate_generated_not_runtime
production_hash_selected = false
runtime_wiring_allowed = false
groth16_flow_unchanged = true
```

The candidate preimage uses the locked assembly order and explicit placeholders
for values that are not available yet:

```text
__available_from_bridge_input__::<field>
__requires_future_root_generation__::<field>
```

This is still not the production `public_input_root`:

- it does not select Poseidon/Poseidon2/Merkle root semantics
- it does not bind real claim/oracle/fee/nullifier/batch roots
- it does not enable Solidity or runtime wiring
- Groth16 remains the active runtime path

The digest candidate CLI pair is:

```text
generate_public_input_root_digest_candidate
validate_public_input_root_digest_candidate
```

## Source Root Digest Candidates

The source-root planning object is:

```text
SourceRootDigestCandidate
```

It creates deterministic candidate digests for the Phase 4 source-root inputs:

```text
claim_source_root
oracle_facts_root
fee_schedule_root
nullifier_root_transition
```

Each candidate uses:

```text
hash_algorithm = sha2_256_candidate_not_production_hash
canonical_encoding = canonical_json_preimage_v0
root_generation_status = candidate_generated_not_runtime
production_hash_selected = false
runtime_wiring_allowed = false
groth16_flow_unchanged = true
```

This is still not production source-root generation:

- it does not build Merkle trees
- it does not select Poseidon/Poseidon2 root semantics
- it does not make oracle, fee, claim-source, or nullifier roots legally verified
- it does not feed the active Groth16 runtime
- it does not submit anything on-chain

The shared source-root digest CLI pair is:

```text
generate_source_root_digest_candidate
validate_source_root_digest_candidate
```

## Source Root Aggregation Plan

The source-root aggregation planning object is:

```text
SourceRootAggregationPlan
```

It binds the four source-root digest candidates into the future
`public_input_root` field set:

```text
claim_source_root -> claim_source_root
oracle_facts_root -> oracle_facts_root
fee_schedule_root -> fee_schedule_root
nullifier_root_transition -> nullifier_root_before, nullifier_root_after
```

This object preserves the existing `PublicInputRootDigestCandidate`; it does
not recompute or replace it.

The aggregation remains planning-only:

- no production hash is selected
- no Merkle tree is built
- no real public input root is generated
- no Solidity or runtime wiring is enabled
- Groth16 remains the active runtime path

The aggregation CLI pair is:

```text
generate_source_root_aggregation_plan
validate_source_root_aggregation_plan
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

## Selected Prover Byte Encoding Plan

The next planning object is:

```text
SelectedProverByteEncodingPlan
```

It defines the byte contract future proof artifacts must use before proof bytes
are accepted by local verification, proof commitment generation, or Solidity
calldata.

Current selected preview prover:

```text
winterfell_poc_preview
```

Current proof byte encoding contract:

```text
proof_bytes_encoding = 0x_prefixed_canonical_stark_proof_bytes
proof_bytes_status = not_generated_encoding_contract_only
canonical_byte_order = prover_native_bytes_preserved_no_reordering
serialization_format = opaque_bytes_for_contract_boundary_v1
compression_status = no_additional_compression_selected
```

The proof commitment must bind these fields in this order:

```text
0. selected_prover
1. proof_bytes_encoding
2. canonical_byte_order
3. serialization_format
4. proof_bytes
```

This is still planning-only:

- no proof bytes are generated by this plan
- no production prover is selected
- no verifier is wired to runtime
- Groth16 remains the active runtime path

The selected prover byte encoding CLI pair is:

```text
generate_selected_prover_byte_encoding_plan
validate_selected_prover_byte_encoding_plan
```

## Phase 8 Pre-Prover Bundle Checkpoint

The current Phase 8 bundle checkpoint is:

```text
Phase8PreProverBundleCheckpoint
```

It validates the current pre-prover boundary artifacts together:

- `StarkProofArtifactV1BoundarySpec`
- `PublicInputRootDigestCandidate`
- `SourceRootAggregationPlan`
- `ProofCommitmentPreimagePlan`
- `ProofArtifactFixtureExpectationSet`
- `SelectedProverByteEncodingPlan`

The checkpoint confirms:

```text
all_artifacts_validated = true
all_source_roots_bound = true
production_hash_selected = false
runtime_wiring_allowed = false
proof_generation_enabled = false
groth16_flow_unchanged = true
```

This is still not a real STARK proof and not runtime wiring. It is the
pre-prover handoff manifest that shows the candidate roots, byte encoding,
fixture expectations, and proof-commitment plan are internally coherent before
real prover implementation starts.

The checkpoint CLI pair is:

```text
generate_phase8_pre_prover_bundle_checkpoint
validate_phase8_pre_prover_bundle_checkpoint
```

## Real Prover Implementation Checklist

The next Phase 8 planning object is:

```text
Phase8RealProverImplementationChecklist
```

It is generated from the validated pre-prover bundle checkpoint and names the
remaining blockers before a real STARK cutover:

- select production hash/root semantics
- generate real source roots
- generate the real public input root
- generate a real STARK witness
- generate real STARK proof bytes
- generate and bind the proof commitment
- locally verify the real STARK artifact before Solidity or ClaimsRegistry
  cutover

The checklist keeps:

```text
runtime_cutover_allowed = false
groth16_flow_unchanged = true
completion_gate = all_work_items_complete_and_real_stark_artifact_locally_verified
```

This is still planning-only. It does not generate roots, witnesses, proof
bytes, commitments, local verification results, Solidity verifier output, or
runtime wiring.

The checklist CLI pair is:

```text
generate_phase8_real_prover_implementation_checklist
validate_phase8_real_prover_implementation_checklist
```

## Test-Only Prover Harness Plan

The next Phase 8 planning object is:

```text
Phase8TestOnlyProverHarnessPlan
```

It is generated from the real prover implementation checklist and defines the
first allowed local proof-generation harness boundary:

- selected preview prover: `winterfell_poc_preview`
- execution mode: `local_feature_gated_test_only_no_contract_writes`
- required inputs:
  - `complete_winterfell_witness_candidate`
  - `selected_prover_byte_encoding_plan`
  - `phase8_real_prover_implementation_checklist`
- expected outputs:
  - `winterfell_proof_preview`
  - `stark_proof_artifact_v1_candidate`
  - `stark_settlement_boundary_artifact`
  - `phase8_harness_execution_log`

The harness plan keeps:

```text
feature_gate_required = true
test_only_proof_generation_allowed = true
runtime_cutover_allowed = false
on_chain_submission_allowed = false
groth16_flow_unchanged = true
```

This is still not production proof wiring. It allows only a local,
feature-gated proving experiment and explicitly blocks contract writes,
ClaimsRegistry cutover, and on-chain STARK submission.

The harness plan CLI pair is:

```text
generate_phase8_test_only_prover_harness_plan
validate_phase8_test_only_prover_harness_plan
```

## Test-Only Prover Harness Execution Report

The next Phase 8 test-only report is:

```text
Phase8TestOnlyProverHarnessExecutionReport
```

It is generated from the harness plan plus the already-generated Phase 8
preview artifacts:

- `complete_winterfell_witness_candidate`
- `selected_prover_byte_encoding_plan`
- `phase8_real_prover_implementation_checklist`
- `winterfell_proof_preview`
- `stark_proof_artifact_v1_candidate`
- `stark_settlement_boundary_artifact`

The report records:

- selected preview prover
- feature gate usage
- proof preview status
- proof size
- local prove/verify timing
- local verification status
- proof bytes status
- runtime/on-chain disablement
- Groth16 preservation

The report keeps:

```text
execution_status = test_only_harness_execution_report_no_runtime_cutover
feature_gate_used = true
local_verification_status = winterfell_preview_verified_locally
proof_bytes_status = preview_bytes_observed_not_production_artifact
runtime_cutover_allowed = false
on_chain_submission_allowed = false
groth16_flow_unchanged = true
```

This is still not production STARK proof wiring. It reports that the local,
feature-gated preview path produced and verified a proof preview, but it does
not make that proof usable by runtime contracts or settlement.

The harness execution report CLI pair is:

```text
generate_phase8_test_only_prover_harness_execution_report
validate_phase8_test_only_prover_harness_execution_report
```

## Real Prover Boundary Adapter Plan

The next Phase 8 boundary object is:

```text
Phase8RealProverBoundaryAdapterPlan
```

It is generated from the test-only prover harness execution report and defines
the exact transformations required before a preview proof lane can emit a real
`stark-proof-artifact-v1`:

- replace preview proof bytes with real proof bytes
- select production hash and root semantics
- bind the final public input root
- bind source roots
- generate a proof commitment from canonical proof bytes
- locally verify the real STARK proof
- emit a complete `stark-proof-artifact-v1`

The adapter plan keeps:

```text
adapter_status = preview_to_real_prover_boundary_adapter_no_runtime_cutover
target_prover_status = production_prover_not_selected_real_proof_not_generated
target_artifact_schema_version = stark-proof-artifact-v1
preview_artifact_reusable_for_runtime = false
real_proof_generation_allowed = false
local_verification_required = true
runtime_cutover_allowed = false
on_chain_submission_allowed = false
groth16_flow_unchanged = true
```

The adapter also records runtime blockers:

- production prover not selected
- real proof bytes not generated
- production public input root not generated
- source roots not production ready
- real proof not locally verified
- Solidity verifier not runtime integrated

This is still not production STARK proof generation. It is a deterministic
handoff contract between the test-only preview lane and the future real proof
artifact lane.

The real prover boundary adapter CLI pair is:

```text
generate_phase8_real_prover_boundary_adapter_plan
validate_phase8_real_prover_boundary_adapter_plan
```

## Real Proof Artifact Readiness Gate

The next Phase 8 boundary object is:

```text
Phase8RealProofArtifactReadinessGate
```

It is generated from the real prover boundary adapter plan and turns the
required transformations into explicit readiness gates. Every gate starts as
unsatisfied because no production implementation source has been selected yet.

The readiness gate keeps:

```text
readiness_status = not_ready_real_proof_generation_blocked
target_artifact_schema_version = stark-proof-artifact-v1
satisfied_gate_count = 0
unsatisfied_gate_count = 7
real_proof_generation_allowed = false
real_artifact_emission_allowed = false
runtime_cutover_allowed = false
on_chain_submission_allowed = false
groth16_flow_unchanged = true
```

Each transformation gate has:

```text
implementation_source = null
readiness_status = implementation_source_missing
blocks_real_proof_generation = true
```

This is still not production STARK proof generation. It is a safety latch that
prevents the preview lane from emitting a real proof artifact until every
required transformation has an explicit implementation source and later
validation evidence.

The real proof artifact readiness gate CLI pair is:

```text
generate_phase8_real_proof_artifact_readiness_gate
validate_phase8_real_proof_artifact_readiness_gate
```

## Implementation Source Registry

The next Phase 8 planning object is:

```text
Phase8ImplementationSourceRegistry
```

It is generated from the real proof artifact readiness gate and maps each
required transformation to a planned implementation module. This is only a
source-routing plan; it is not implementation evidence and does not mark any
readiness gate as satisfied.

The registry keeps:

```text
registry_status = planned_sources_only_real_proof_generation_blocked
implementation_evidence_status = planned_not_implemented_no_evidence
satisfied_gate_count = 0
unsatisfied_gate_count = 7
real_proof_generation_allowed = false
real_artifact_emission_allowed = false
runtime_cutover_allowed = false
on_chain_submission_allowed = false
groth16_flow_unchanged = true
```

The planned modules are:

- `stark-engine/src/real_prover.rs`
- `stark-engine/src/root_semantics.rs`
- `stark-engine/src/public_inputs.rs`
- `stark-engine/src/source_roots.rs`
- `stark-engine/src/proof_commitment.rs`
- `stark-engine/src/local_verifier.rs`
- `stark-engine/src/proof_artifact.rs`

These files are planned implementation boundaries, not active runtime modules
yet. Real proof generation remains blocked until a later phase adds
implementation evidence and local validation for every transformation.

The implementation source registry CLI pair is:

```text
generate_phase8_implementation_source_registry
validate_phase8_implementation_source_registry
```

## Next Safe Step

The next safe Phase 8 step is to add implementation evidence slots:

- define the required evidence fields for each planned implementation module
- keep every readiness gate blocked until evidence is populated and validated
- do not generate real proof bytes yet
- keep Solidity and ClaimsRegistry unchanged
- keep Groth16 active until an explicit cutover phase
