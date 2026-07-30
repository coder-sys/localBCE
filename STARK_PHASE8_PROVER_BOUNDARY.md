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

## Claim Source Identity Evidence

Phase 8 now includes a planning-only identity evidence artifact:

```text
ClaimSourceIdentityEvidence
```

It compares:

- `ClaimSourceRootInput.member_id`
- `ClaimSourceRootInput.provider_npi`
- `WinterfellCompleteWitnessCandidate.member_id`
- `WinterfellCompleteWitnessCandidate.provider_npi`

Current active behavior remains conservative:

- `rust-engine` does not export `member_id`
- `rust-engine` does not export `provider_npi`
- the evidence artifact records those fields as missing from active bridge export
- fixture-backed Winterfell candidate values are still not accepted as runtime evidence
- no claim-source root, proof, runtime wiring, or on-chain submission is generated

This artifact is the bridge from fixture-only identity fields toward future
active claim-source inputs. It does not claim production semantic equivalence.

The CLI pair is:

```text
generate_claim_source_identity_evidence
validate_claim_source_identity_evidence
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

## Implementation Evidence Slots

The next Phase 8 planning object is:

```text
Phase8ImplementationEvidenceSlots
```

It is generated from the implementation source registry and defines the
evidence each planned module must eventually provide before it can satisfy a
readiness gate. The slots are intentionally empty.

The evidence slots keep:

```text
evidence_status = evidence_slots_empty_real_proof_generation_blocked
populated_slot_count = 0
missing_slot_count = 7
real_proof_generation_allowed = false
real_artifact_emission_allowed = false
runtime_cutover_allowed = false
on_chain_submission_allowed = false
groth16_flow_unchanged = true
```

Each slot requires evidence such as:

- implementation code path
- deterministic fixtures
- unit/integration tests
- local validation logs

No slot currently contains implementation evidence. This keeps the real proof
artifact path blocked while making the future evidence contract explicit.

The implementation evidence slots CLI pair is:

```text
generate_phase8_implementation_evidence_slots
validate_phase8_implementation_evidence_slots
```

## Evidence Readiness Report

The next Phase 8 planning object is:

```text
Phase8EvidenceReadinessReport
```

It is generated from `Phase8ImplementationEvidenceSlots` and summarizes the
missing implementation evidence for every planned transformation. This is a
negative readiness report: it makes the blockers explicit and keeps the real
proof path disabled.

The report keeps:

```text
report_status = not_ready_missing_implementation_evidence
populated_slot_count = 0
missing_slot_count = 7
missing_evidence_total = 28
ready_transformation_count = 0
blocked_transformation_count = 7
real_proof_generation_allowed = false
real_artifact_emission_allowed = false
runtime_cutover_allowed = false
on_chain_submission_allowed = false
groth16_flow_unchanged = true
```

The evidence readiness report CLI pair is:

```text
generate_phase8_evidence_readiness_report
validate_phase8_evidence_readiness_report
```

## Inactive Real Prover Source Scaffolds

The planned real prover implementation source scaffolds now exist as inactive
module boundaries:

- `stark-engine/src/real_prover.rs`
- `stark-engine/src/root_semantics.rs`
- `stark-engine/src/public_inputs.rs`
- `stark-engine/src/source_roots.rs`
- `stark-engine/src/proof_commitment.rs`
- `stark-engine/src/local_verifier.rs`
- `stark-engine/src/proof_artifact.rs`

Each module currently exposes only scaffold constants:

```text
implementation_status = scaffold_only_not_implemented
runtime_wiring_allowed = false
real_proof_generation_allowed = false
```

The scaffold tests confirm these modules match the Phase 8 implementation
source registry and required evidence slots. They do not satisfy the evidence
readiness report yet.

## Test-Only Real Prover Placeholder Bytes

The first inactive real prover module now has a deterministic test-only byte
package:

```text
real_prover::TestOnlyProofBytes
```

It is generated from a validated `WinterfellCompleteWitnessCandidate` and uses a
deterministic digest of that candidate as placeholder bytes.

This object keeps:

```text
byte_status = test_only_deterministic_placeholder_not_real_proof
runtime_wiring_allowed = false
real_proof_generation_allowed = false
accepted_as_implementation_evidence = false
```

These bytes are useful for adapter tests, but they are not a real STARK proof,
not a production artifact, and not enough to satisfy the Phase 8 evidence
readiness report.

The test-only proof bytes CLI pair is:

```text
generate_phase8_test_only_proof_bytes
validate_phase8_test_only_proof_bytes
```

The full STARK bridge smoke chain now generates and validates this placeholder
after `WinterfellCompleteWitnessCandidate` and before the feature-gated
Winterfell proof preview.

## Test-Only Real Proof Bytes Fixture

The first fixture-shaped artifact for the future real proof bytes slot now
exists:

```text
real_prover::TestOnlyRealProofBytesFixture
```

It is generated from `TestOnlyProofBytes` and uses the future fixture path:

```text
fixture_path = stark-engine/fixtures/real_proof_bytes_fixture.bin
fixture_status = test_only_fixture_shape_validated_not_real_proof_evidence
proof_bytes_present = true
proof_bytes_length = 32
test_only_fixture = true
local_real_proof_verified = false
accepted_as_complete_evidence = false
implementation_satisfied = false
runtime_wiring_allowed = false
real_proof_generation_allowed = false
```

This validates fixture shape and digest plumbing only. It does not satisfy the
`real_proof_bytes_fixture` evidence slot, does not prove local verification,
and does not unlock runtime cutover.

The test-only fixture CLI pair is:

```text
generate_phase8_test_only_real_proof_bytes_fixture
validate_phase8_test_only_real_proof_bytes_fixture
```

## Test-Only Local Real Proof Validation Log Fixture

The paired test-only validation-log-shaped artifact now exists:

```text
real_prover::TestOnlyLocalRealProofValidationLogFixture
```

It is generated from `TestOnlyRealProofBytesFixture` and uses the future local
verification log path:

```text
log_path = stark-engine/reports/local_real_proof_validation.log
log_status = test_only_validation_log_shape_validated_not_real_proof_verification
prover_name = test_only_phase8_fixture_prover
proof_artifact_schema_version = stark-proof-artifact-v1
local_verification_status = test_only_shape_validated_real_verification_not_performed
verification_timestamp = 1970-01-01T00:00:00Z
test_only_fixture = true
local_real_proof_verified = false
accepted_as_complete_evidence = false
implementation_satisfied = false
runtime_wiring_allowed = false
real_proof_generation_allowed = false
```

This validates the future local verification log shape and required fields. It
does not satisfy the `local_real_proof_validation_log` evidence slot, does not
claim a production proof was verified, and does not unlock runtime cutover.

The test-only validation log fixture CLI pair is:

```text
generate_phase8_test_only_local_real_proof_validation_log_fixture
validate_phase8_test_only_local_real_proof_validation_log_fixture
```

## Test-Only Evidence Satisfaction Rehearsal Report

The test-only fixture path now has an aggregate rehearsal report:

```text
real_prover::TestOnlyEvidenceSatisfactionRehearsalReport
```

It consumes:

- `TestOnlyRealProofBytesFixture`
- `TestOnlyLocalRealProofValidationLogFixture`

The report confirms the fixture path is internally coherent:

```text
proof_bytes_fixture_shape_present = true
validation_log_shape_present = true
proof_bytes_digest_matches_log = true
claim_hash_matches = true
test_only_fixtures = true
real_proof_verified = false
real_evidence_slots_satisfied = false
satisfied_real_evidence_slot_count = 0
blocked_real_evidence_slot_count = 4
runtime_cutover_allowed = false
real_proof_generation_allowed = false
accepted_as_complete_evidence = false
```

This is a rehearsal report only. It proves that the future evidence path has a
coherent fixture/log shape, while explicitly keeping every real prover evidence
slot blocked.

The rehearsal report CLI pair is:

```text
generate_phase8_test_only_evidence_satisfaction_rehearsal_report
validate_phase8_test_only_evidence_satisfaction_rehearsal_report
```

## Real Proof Bytes Fixture Promotion Plan

The first real evidence-slot promotion plan now exists:

```text
real_prover::RealProofBytesFixturePromotionPlan
```

It consumes `TestOnlyEvidenceSatisfactionRehearsalReport` and defines the exact
future gate for promoting the `real_proof_bytes_fixture` slot.

Required future conditions:

```text
proof_bytes_present = true
proof_bytes_digest_present = true
test_only_bytes_rejected = true
local_real_proof_verified = true
accepted_as_complete_evidence = true
```

Current status remains blocked:

```text
promotion_status = promotion_plan_only_fixture_shape_ready_real_evidence_blocked
current_fixture_shape_present = true
current_validation_log_shape_present = true
current_digest_matches_log = true
slot_promotion_ready = false
runtime_cutover_allowed = false
real_proof_generation_allowed = false
```

This plan is the first bridge from rehearsal artifacts to real evidence
promotion. It does not flip the evidence slot yet and does not allow runtime
cutover.

The promotion plan CLI pair is:

```text
generate_phase8_real_proof_bytes_fixture_promotion_plan
validate_phase8_real_proof_bytes_fixture_promotion_plan
```

## Local Real Proof Validation Log Promotion Plan

The second real evidence-slot promotion plan now exists:

```text
real_prover::LocalRealProofValidationLogPromotionPlan
```

It consumes `TestOnlyEvidenceSatisfactionRehearsalReport` and defines the exact
future gate for promoting the `local_real_proof_validation_log` slot.

Required future conditions:

```text
real_prover_name = true
real_proof_artifact_schema_version = true
proof_bytes_digest = true
local_verification_status_verified = true
verification_timestamp = true
matching_claim_hash = true
```

Current status remains blocked:

```text
promotion_status = promotion_plan_only_validation_log_shape_ready_real_evidence_blocked
current_validation_log_shape_present = true
current_digest_matches_fixture = true
current_claim_hash_matches_fixture = true
slot_promotion_ready = false
runtime_cutover_allowed = false
real_proof_generation_allowed = false
```

This plan defines how the local verification log becomes real evidence later.
It does not flip the evidence slot yet and does not allow runtime cutover.

The promotion plan CLI pair is:

```text
generate_phase8_local_real_proof_validation_log_promotion_plan
validate_phase8_local_real_proof_validation_log_promotion_plan
```

## Real Prover Evidence Record

The first real prover evidence record schema now exists:

```text
real_prover::RealProverEvidenceRecord
```

It is generated from `TestOnlyProofBytes`, but the test-only bytes are
explicitly not accepted as implementation evidence.

The record keeps:

```text
evidence_status = real_prover_evidence_missing
populated_evidence_count = 0
missing_evidence_count = 4
implementation_satisfied = false
test_only_bytes_are_evidence = false
runtime_wiring_allowed = false
real_proof_generation_allowed = false
accepted_as_implementation_evidence = false
```

The required evidence slots are:

- `real_prover_code_path`
- `real_proof_bytes_fixture`
- `real_prover_unit_tests`
- `local_real_proof_validation_log`

The real prover evidence record CLI pair is:

```text
generate_phase8_real_prover_evidence_record
validate_phase8_real_prover_evidence_record
```

## Real Prover Attempt Artifact

The first non-runtime real prover attempt artifact schema now exists:

```text
real_prover::RealProverAttemptArtifact
```

This artifact is generated from the unsatisfied `RealProverEvidenceRecord`.
It records that real prover execution is blocked because implementation
evidence is still missing.

The artifact keeps:

```text
attempt_status = blocked_missing_real_prover_evidence_no_attempt_made
blocker_status = real_prover_evidence_record_unsatisfied
missing_evidence_count = 4
populated_evidence_count = 0
implementation_satisfied = false
attempted_real_proof_generation = false
emitted_real_proof_bytes = false
local_real_proof_verified = false
runtime_wiring_allowed = false
real_proof_generation_allowed = false
accepted_as_implementation_evidence = false
```

The real prover attempt artifact CLI pair is:

```text
generate_phase8_real_prover_attempt_artifact
validate_phase8_real_prover_attempt_artifact
```

This is still a planning/protection artifact. It does not call Winterfell,
does not generate proof bytes, does not emit a production artifact, and does
not alter the active Groth16 runtime.

## Real Prover Adapter Invocation

The first real prover adapter source path now exists behind a default-disabled
feature gate:

```text
feature = real-prover-adapter
real_prover::RealProverAdapterInvocation
```

In the default build, the adapter invocation records:

```text
adapter_status = blocked_real_prover_adapter_feature_disabled
feature_enabled = false
attempted_real_proof_generation = false
emitted_real_proof_bytes = false
local_real_proof_verified = false
runtime_wiring_allowed = false
real_proof_generation_allowed = false
accepted_as_implementation_evidence = false
```

If the feature is enabled before the evidence record is satisfied, the adapter
still remains blocked by missing real prover evidence. It is not a runtime
entrypoint and does not emit proof bytes.

The real prover adapter invocation CLI pair is:

```text
generate_phase8_real_prover_adapter_invocation
validate_phase8_real_prover_adapter_invocation
```

## Real Prover Code Path Evidence

The first individual real-prover evidence slot validator now exists:

```text
real_prover::RealProverCodePathEvidence
```

It validates only the `real_prover_code_path` candidate:

```text
evidence_slot = real_prover_code_path
candidate_code_path = stark-engine/src/real_prover.rs
expected_code_path = stark-engine/src/real_prover.rs
path_matches_expected = true
source_module_status = scaffold_only_not_implemented
implementation_satisfied = false
accepted_as_complete_evidence = false
runtime_wiring_allowed = false
real_proof_generation_allowed = false
```

This is not enough to satisfy the real prover evidence record. It proves only
that the intended source module path is present and intentionally still
scaffold-only.

The code-path evidence CLI pair is:

```text
generate_phase8_real_prover_code_path_evidence
validate_phase8_real_prover_code_path_evidence
```

## Real Prover Unit Tests Evidence

The second individual real-prover evidence slot validator now exists:

```text
real_prover::RealProverUnitTestsEvidence
```

It validates only the `real_prover_unit_tests` candidate:

```text
evidence_slot = real_prover_unit_tests
candidate_test_path = stark-engine/tests/phase8_test_only_real_prover.rs
expected_test_path = stark-engine/tests/phase8_test_only_real_prover.rs
required_test_count = 3
coverage_status = focused_boundary_tests_declared
implementation_satisfied = false
accepted_as_complete_evidence = false
runtime_wiring_allowed = false
real_proof_generation_allowed = false
```

The required focused boundary tests are:

- `real_prover_evidence_record_generates_unsatisfied_contract`
- `real_prover_attempt_artifact_is_blocked_by_missing_evidence`
- `real_prover_adapter_invocation_is_default_blocked`

This is not enough to satisfy the full real prover evidence record. It proves
only that the focused unit-test evidence candidate is declared and constrained.

The unit-tests evidence CLI pair is:

```text
generate_phase8_real_prover_unit_tests_evidence
validate_phase8_real_prover_unit_tests_evidence
```

## Local Real Proof Validation Log Evidence

The third individual real-prover evidence slot validator now exists:

```text
real_prover::LocalRealProofValidationLogEvidence
```

It validates only the `local_real_proof_validation_log` candidate:

```text
evidence_slot = local_real_proof_validation_log
candidate_log_path = stark-engine/reports/local_real_proof_validation.log
expected_log_path = stark-engine/reports/local_real_proof_validation.log
validation_log_status = real_proof_validation_log_missing
local_real_proof_verified = false
required_log_field_count = 5
implementation_satisfied = false
accepted_as_complete_evidence = false
runtime_wiring_allowed = false
real_proof_generation_allowed = false
```

The required future log fields are:

- `prover_name`
- `proof_artifact_schema_version`
- `proof_bytes_digest`
- `local_verification_status`
- `verification_timestamp`

This is not enough to satisfy the full real prover evidence record. It declares
the expected local verification log contract without claiming that a real proof
has been generated or verified.

The validation-log evidence CLI pair is:

```text
generate_phase8_local_real_proof_validation_log_evidence
validate_phase8_local_real_proof_validation_log_evidence
```

## Real Proof Bytes Fixture Evidence

The fourth individual real-prover evidence slot validator now exists:

```text
real_prover::RealProofBytesFixtureEvidence
```

It validates only the `real_proof_bytes_fixture` candidate:

```text
evidence_slot = real_proof_bytes_fixture
candidate_fixture_path = stark-engine/fixtures/real_proof_bytes_fixture.bin
expected_fixture_path = stark-engine/fixtures/real_proof_bytes_fixture.bin
fixture_status = real_proof_bytes_fixture_missing
proof_bytes_present = false
proof_bytes_digest_present = false
test_only_bytes_rejected = true
local_real_proof_verified = false
implementation_satisfied = false
accepted_as_complete_evidence = false
runtime_wiring_allowed = false
real_proof_generation_allowed = false
```

The required future fixture fields are:

- `fixture_path`
- `proof_artifact_schema_version`
- `proof_bytes_digest`
- `prover_name`
- `local_verification_log_path`

This completes the four individual evidence-slot validators, but the full real
prover evidence record remains unsatisfied because no real proof bytes fixture
or local real-proof validation log exists yet.

The fixture evidence CLI pair is:

```text
generate_phase8_real_proof_bytes_fixture_evidence
validate_phase8_real_proof_bytes_fixture_evidence
```

## Real Prover Evidence Summary

The four individual evidence-slot validators are now aggregated by:

```text
real_prover::RealProverEvidenceSummary
```

The summary reports:

```text
summary_status = all_slots_declared_zero_slots_satisfied_runtime_blocked
declared_slot_count = 4
satisfied_slot_count = 0
missing_or_unsatisfied_slot_count = 4
all_slots_declared = true
all_slots_satisfied = false
implementation_satisfied = false
runtime_cutover_allowed = false
real_proof_generation_allowed = false
real_proof_bytes_fixture_present = false
local_real_proof_verified = false
test_only_bytes_rejected = true
```

The current blockers are:

- `real_proof_bytes_fixture_missing`
- `local_real_proof_validation_log_missing`
- `real_prover_implementation_not_satisfied`
- `runtime_cutover_blocked`

The summary CLI pair is:

```text
generate_phase8_real_prover_evidence_summary
validate_phase8_real_prover_evidence_summary
```

## Phase 8 Real Prover Readiness Rollup

The top-level Phase 8 readiness checkpoint now exists:

```text
real_prover::Phase8RealProverReadinessRollup
```

It combines:

- `RealProverEvidenceSummary`
- `RealProofBytesFixturePromotionPlan`
- `LocalRealProofValidationLogPromotionPlan`

The rollup reports:

```text
rollup_status = test_only_shapes_present_real_evidence_blocked_runtime_cutover_blocked
evidence_slots_declared = 4
evidence_slots_satisfied = 0
evidence_slots_blocked = 4
fixture_promotion_plan_present = true
validation_log_promotion_plan_present = true
fixture_promotion_ready = false
validation_log_promotion_ready = false
test_only_shapes_present = true
real_evidence_complete = false
implementation_satisfied = false
runtime_cutover_allowed = false
real_proof_generation_allowed = false
```

The remaining blockers are:

- `real_proof_bytes_fixture_missing`
- `local_real_proof_validation_log_missing`
- `real_prover_implementation_not_satisfied`
- `runtime_cutover_blocked`
- `real_proof_bytes_fixture_promotion_not_ready`
- `local_real_proof_validation_log_promotion_not_ready`
- `real_prover_cutover_not_allowed`

The next required actions are:

- `replace_test_only_proof_bytes_with_real_prover_output`
- `write_real_proof_bytes_fixture_from_selected_prover`
- `write_local_real_proof_validation_log_with_verified_status`
- `satisfy_all_four_real_prover_evidence_slots`
- `keep_groth16_runtime_active_until_explicit_cutover`

The rollup CLI pair is:

```text
generate_phase8_real_prover_readiness_rollup
validate_phase8_real_prover_readiness_rollup
```

This is still not a STARK proof. It is a machine-readable readiness gate that
keeps runtime cutover blocked until real prover output replaces the test-only
fixture artifacts.

## Winterfell PoC Real Proof Fixture

The first feature-gated real local proof fixture now exists:

```text
winterfell_poc_adapter::WinterfellPocRealProofFixture
```

It is available only with:

```text
--features winterfell-poc
```

The fixture is generated from a validated `WinterfellCompleteWitnessCandidate`
and calls the imported `blind-ledger-app-layer/zk-stark` Winterfell PoC prover.
It records:

- `prover_name = winterfell-poc`
- `prover_version = 0.13.1`
- real Winterfell PoC `proof_bytes_hex`
- `proof_bytes_sha256`
- formatted public inputs
- `local_verification_status = verified`
- `verified = true`

It also keeps the production/runtime flags blocked:

```text
production_semantics_complete = false
runtime_wired = false
on_chain_submission = false
accepted_as_runtime_evidence = false
```

This is a real local Winterfell PoC proof fixture, not yet production localBCE
STARK evidence. The PoC AIR still has semantic gaps against the active Rust
engine and there is no on-chain STARK verifier.

The CLI pair is:

```text
generate_winterfell_poc_real_proof_fixture
validate_winterfell_poc_real_proof_fixture
```

## Winterfell PoC Semantic Equivalence Report

The semantic equivalence gate now exists:

```text
winterfell_poc_adapter::WinterfellPocSemanticEquivalenceReport
```

It compares:

- active `StarkBridgeInput`
- `WinterfellPocRealProofFixture`
- active public inputs
- direct Winterfell PoC gates

The report requires these to match:

```text
claim_id_matches = true
claim_hash_matches = true
decision_matches = true
failure_code_matches = true
direct_eligibility_gate_matches = true
direct_provider_gate_matches = true
direct_duplicate_gate_matches = true
public_inputs_match = true
direct_semantics_match = true
proof_fixture_verified = true
```

It still blocks production equivalence:

```text
partial_semantics_resolved = false
unmapped_semantics_resolved = false
production_semantics_complete = false
accepted_as_runtime_evidence = false
runtime_wired = false
on_chain_submission = false
```

The unresolved partial fields are:

- `service_line_count`
- `prior_auth_ok`
- `charge_cents`
- `program_integrity_hold`

The unresolved unmapped fields are:

- `member_id`
- `provider_npi`
- `diagnosis_count`
- `max_charge_cents`

The CLI pair is:

```text
generate_winterfell_poc_semantic_equivalence_report
validate_winterfell_poc_semantic_equivalence_report
```

## Winterfell PoC Semantic Gap Normalization Report

The all-gap normalization artifact now exists:

```text
winterfell_poc_adapter::WinterfellPocSemanticGapNormalizationReport
```

It covers every currently unresolved PoC semantic gap.

The partial fields are deterministically normalized:

- `service_line_count` from `billing_code_valid` and `units_valid`
- `prior_auth_ok` from `physician_certification_valid`
- `charge_cents` from `claim_amount`
- `program_integrity_hold` from `disability_determination_valid` and `recipient_not_deceased`

The report requires:

```text
partial_field_count = 4
partial_fields_resolved = true
```

The four fields retained in the v0 `unmapped` compatibility group are now
optionally exported by `rust-engine`:

- `member_id`
- `provider_npi`
- `diagnosis_count`
- `max_charge_cents`

When all four values are present and match the complete witness candidate, the
report requires:

```text
unmapped_field_count = 4
unmapped_source_data_populated = true
active_bridge_source_backed_field_count = 4
fixture_backed_field_count = 0
all_unmapped_fields_source_backed = true
unmapped_semantics_resolved = false
```

The v0 group name is preserved for schema compatibility. Source availability
does not make these fields equivalent to active adjudication rules. In
particular, `diagnosis_count` and `max_charge_cents` remain optional source
facts and do not affect `denial_reason()`.

It still blocks production equivalence:

```text
production_semantics_complete = false
accepted_as_runtime_evidence = false
runtime_wired = false
on_chain_submission = false
```

The CLI pair is:

```text
generate_winterfell_poc_semantic_gap_normalization_report
validate_winterfell_poc_semantic_gap_normalization_report
```

## Strict Bridge-Backed Complete Witness Candidate

The non-runtime rehearsal chain can now construct all 11 imported Winterfell
PoC fields directly from validated `StarkBridgeInput` data:

```text
generate_bridge_backed_complete_winterfell_witness_candidate
validate_bridge_backed_complete_winterfell_witness_candidate
```

This path:

- requires `member_id`, `provider_npi`, `diagnosis_count`, and
  `max_charge_cents`
- checks raw identity values against their deterministic numeric bridge
  mappings
- checks direct Winterfell mapping values against their active Rust facts
- rejects invalid boolean facts and charge conversion overflow
- normalizes the four partial compatibility fields deterministically
- marks all fields as sourced from `StarkBridgeInput`
- performs no fixture substitution

The legacy fixture assembly path remains available for compatibility testing,
but downstream proof rehearsal in `scripts/validate_stark_bridge_chain.sh` now
uses the strict bridge-backed candidate.

This still does not make partial mappings equivalent to production
adjudication rules, enable runtime STARK proof generation, or change Groth16.

## Bridge-Backed Winterfell Proof Evidence

The exact strict source artifacts can now be bound to a locally verified
Winterfell PoC proof:

```text
generate_bridge_backed_winterfell_proof_evidence
validate_bridge_backed_winterfell_proof_evidence
```

The evidence records SHA-256 digests of the raw bytes for:

- validated `StarkBridgeInput`
- strict bridge-backed complete witness candidate
- locally verified Winterfell PoC proof fixture
- serialized proof bytes

Generation fails unless the candidate uses
`complete_adapter_ready_bridge_backed_no_fixture`, all claim identifiers match,
and the proof fixture reports successful local verification. The artifact
always requires:

```text
fixture_substitution = false
verified = true
production_semantics_complete = false
accepted_as_runtime_evidence = false
runtime_wired = false
on_chain_submission = false
groth16_flow_unchanged = true
```

This binds the current PoC evidence chain. It does not promote the imported PoC
AIR into the production localBCE rules proof.

## Next Safe Step

The first versioned production AIR semantics contract is now present behind
the disabled-by-default `production-air` Cargo feature:

```text
cargo test --lib --features production-air production_air::tests --jobs 1
```

It defines:

- `ProductionAirInputV1`, containing every active Rust fact used by G1-G10
- all 13 ordered failure checks used by `denial_reason()`
- the exact failure reasons and failure codes
- first-failure priority
- `ProductionAirSemanticsTraceV1`, an approved or denied semantics evaluation
- strict rejection when bridge adjudication disagrees with the G1-G10 result

This trace is explicitly `semantics_evaluated_not_prover_trace`. It is not a
Winterfell execution trace and does not generate a STARK proof. Runtime wiring,
on-chain submission, and contract changes remain disabled. The active Groth16
flow remains unchanged.

## Next Safe Step

The G1-G10 semantics now have a separate Winterfell 0.13 trace and AIR behind
the disabled-by-default `production-air-winterfell` feature:

```text
cargo test --lib --features production-air-winterfell \
  production_air_winterfell::tests --jobs 1
```

The trace now contains:

- all active G1-G10 Rust facts
- eight lossless 32-bit limbs of the existing SHA-256 claim identity hash
- a four-element public Rescue-Prime claim-to-fact commitment
- 13 ordered gate results
- 13 first-failure prefix values
- date comparison witnesses with sound 32-bit decompositions
- share-of-cost and aid-code inverse witnesses
- public decision and failure code

The AIR uses Winterfell's `Rp64_256` Rescue-Prime implementation over the
64-bit STARK field. Proofs use a quadratic extension to retain the configured
80-bit verifier security floor. The versioned commitment contract is:

```text
schema: stark-claim-fact-commitment-v1
hash: winterfell-rp64-256
preimage length: 28 field elements
preimage:
  domain tag
  schema version
  G1-G10 ruleset tag
  fact count
  claim_hash[0..8] as eight big-endian 32-bit limbs
  all 16 G1-G10 facts in the documented canonical order
```

The 32-row AIR executes four seven-round Rescue permutations with three
absorption transitions. It constrains the claim-hash limbs and all 16 facts to
remain constant across the trace, binds the first hash state to the public
claim identity, and binds the final four digest elements to public inputs.
The v1 contract requires numeric adjudication facts to fit in 32 bits. This
keeps field encoding lossless and prevents modular wraparound from weakening
the service-date comparisons. Out-of-range values are rejected before trace
construction.

Feature-gated tests cover:

- approved proof generation and local verification
- all 13 ordered denial outcomes and exact failure codes
- a fixed commitment regression vector
- canonical domain, field ordering, and lossless claim-hash limb encoding
- mutation rejection for every one of the 16 private facts
- claim identity hash binding
- tampered public claim-hash and fact-commitment rejection
- field-range rejection

This closes the production AIR's claim-to-fact binding gap, but does not make
the STARK lane runtime-ready:

```text
claim_fact_binding_complete = true
production_proof_artifact_packaging_complete = true
serialized_proof_local_reverification_complete = true
runtime_wired = false
on_chain_verifier_wired = false
on_chain_submission = false
groth16_flow_unchanged = true
```

## Production Proof Artifact

The feature-gated `stark-production-proof-artifact-v1` contract packages:

- real Winterfell 0.13.1 proof bytes as lower-case hex
- SHA-256 and exact byte length for the serialized proof
- all 14 Winterfell public inputs in locked order as canonical decimal field
  values
- SHA-256 of the canonical 14 x 8-byte big-endian public-input encoding
- the claim hash binding, fact commitment schema, AIR parameters, decision,
  and failure code
- explicit non-runtime, non-chain, Groth16-unchanged status flags

`validate_production_stark_proof_artifact` checks the schema and hashes,
deserializes the proof with `Proof::from_bytes`, reconstructs all public inputs,
and invokes the production AIR verifier. Approved and denied artifact tests
also reject proof-byte, public-input, and status tampering.

The artifact is generated from a validated `StarkBridgeInput` with:

```bash
cargo run --features production-air-winterfell \
  --bin generate_production_stark_proof_artifact -- \
  ../rust-engine/stark_bridge_input.json production_stark_proof_artifact.json

cargo run --features production-air-winterfell \
  --bin validate_production_stark_proof_artifact -- \
  production_stark_proof_artifact.json
```

The claim ID remains metadata-only; the existing 32-byte claim hash is the
identity value carried by the proof.

## Next Safe Step

Generate a versioned verifier handoff envelope from the validated production
artifact and prove that its proof bytes and 14 public inputs align exactly with
the existing Solidity STARK verifier ABI candidate. Keep that handoff
feature-gated and off-chain until a real Solidity verifier independently
accepts valid proofs and rejects tampering.
