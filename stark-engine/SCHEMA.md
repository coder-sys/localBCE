# STARK Bridge Artifact Schemas

Scope: schema documentation only. These artifacts are planning and adapter
contracts for the future STARK path. They are not Groth16 inputs, not real STARK
proofs, and not on-chain settlement payloads.

Current artifact chain:

```text
StarkBridgeInput
-> StarkProofIntent
-> StarkWitnessPlan
-> StarkMockTrace
-> StarkMockTrace validation
-> WinterfellPocCompatibilityReport
-> WinterfellAdapterGapPlan
```

Only the first four artifacts are part of the Phase 2 pre-prover data contract.
The Winterfell report and gap plan are adapter-planning outputs.

## Shared Rules

- All schemas use explicit `schema_version` strings.
- All artifacts are deterministic JSON-serializable Rust structs.
- `decision` is always `0` for denied and `1` for approved.
- Approved claims require `failure_code = 0`.
- Denied claims require `failure_code != 0`.
- Boolean fact fields are encoded as integer `0` or `1`.
- No artifact in this chain may claim a real STARK proof was generated.
- No artifact in this chain submits anything on-chain.

## StarkBridgeInput

Schema version: `stark-bridge-input-v0`

Producer: `rust-engine`

Purpose: carry the active Rust adjudication facts into `stark-engine` without
changing the active Groth16 runtime.

Top-level fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `schema_version` | string | Must be `stark-bridge-input-v0`. |
| `producer` | string | Must be `rust-engine`. |
| `purpose` | string | Intended bridge purpose. |
| `runtime_mode` | string | Dry-run or optional sidecar mode. |
| `claim` | object | Claim identity, amount, hash, and optional source facts. |
| `adjudication` | object | Decision, failure code/reason, and ruleset id. |
| `active_rust_facts` | object | Current active Rust G1-G10 facts. |
| `winterfell_poc_mapping` | object | Direct, partial, and unmapped compatibility fields. |
| `public_inputs` | object | Public adjudication inputs for future proof planning. |
| `proof_status` | object | Must show no STARK proof and no on-chain submission. |

Required validation:

- `claim.claim_hash` is present.
- `public_inputs.claim_hash` is present.
- `claim.claim_hash == public_inputs.claim_hash`.
- `adjudication.decision` is `0` or `1`.
- `public_inputs.decision` is `0` or `1`.
- `adjudication.decision == public_inputs.decision`.
- Mapping counts are exactly:
  - direct: `3`
  - partial: `4`
  - unmapped: `4`
- `proof_status.stark_proof_generated == false`.

Optional claim-source fields:

- `member_id`
- `provider_npi`
- `diagnosis_count`
- `max_charge_cents`
- `diagnosis_codes`
- `service_lines`, with `procedure_code`, `charge_cents`, and `units`

The arrays default to empty during deserialization so older bridge fixtures
remain compatible. They do not affect active Rust adjudication or Groth16
inputs.

Direct fields today:

- `eligibility_active`
- `provider_enrolled`
- `duplicate_flag`

Partial fields today:

- `service_line_count`
- `prior_auth_ok`
- `charge_cents`
- `program_integrity_hold`

Unmapped fields today:

- `member_id`
- `provider_npi`
- `diagnosis_count`
- `max_charge_cents`

## ProductionClaimSourceRootArtifactV1

Schema version: `stark-claim-source-root-v1`

Purpose: build a deterministic local `Rp64_256` claim-source Merkle candidate
from a validated, source-complete `StarkBridgeInput`.

The artifact contains:

- the canonical 36-field claim-source leaf preimage and field order
- the four-element leaf digest
- a depth-10 Merkle opening at leaf index `5`
- four-element root values and canonical Solidity `bytes32` packing
- explicit governance, AIR binding, runtime, chain, and Groth16 safety flags

Generation requires present member/provider identity, at least one service
line and diagnosis, matching diagnosis counts, and line charges that equal
`claim_amount * 100` cents. Procedure and diagnosis codes are trimmed and
ASCII-uppercased before hashing.

Commands:

```bash
cargo run --features production-air-winterfell \
  --bin generate_production_claim_source_root -- \
  stark_bridge_input.json production_claim_source_root.json

cargo run --features production-air-winterfell \
  --bin validate_production_claim_source_root -- \
  production_claim_source_root.json
```

This standalone artifact is not itself a proof or governance approval. The
feature-gated production AIR consumes its canonical leaf and opening,
constrains every Merkle level, and publishes the resulting root through the v3
proof artifact and verifier handoff. Runtime wiring and on-chain submission
remain disabled.

## ProductionStarkProofArtifactV3

Schema version: `stark-production-proof-artifact-v3`

Purpose: package a locally verified Winterfell proof together with the exact
18-element public-input vector consumed by the production AIR.

The ordered public inputs are:

1. eight 32-bit claim-hash limbs
2. four `publicInputRoot` elements
3. four `claimSourceRoot` elements
4. decision
5. failure code

The artifact includes canonical proof bytes, proof and public-input digests,
both roots as canonical Solidity `bytes32` values, claim-source tree metadata,
and explicit non-runtime safety flags. Validation deserializes and locally
re-verifies the proof instead of trusting stored status fields.

## ProductionStarkVerifierHandoffV3

Schema version: `stark-production-verifier-handoff-v3`

Purpose: bind the v3 proof artifact to
`IStarkClaimsVerifierV1Candidate` field ordering and Solidity types.

`claimHash`, `decision`, `failureCode`, `publicInputRoot`,
`claimSourceRoot`, and `proof` are direct. The handoff is not call-ready
because `oracleFactsRoot`, `feeScheduleRoot`, `nullifierRootBefore`,
`nullifierRootAfter`, and `batchRoot` are unresolved and no production
Solidity STARK verifier is active.

## StarkProofIntent

Schema version: `stark-proof-intent-v0`

Purpose: normalize a validated bridge input into a pre-proof intent before any
prover-specific witness generation.

Top-level fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `schema_version` | string | Must be `stark-proof-intent-v0`. |
| `source_schema_version` | string | Source bridge schema version. |
| `intent_status` | string | Must be `validated_no_prover_selected`. |
| `claim_id` | string | Source claim id. |
| `claim_hash` | string | Source claim hash. |
| `decision` | integer | `0` denied or `1` approved. |
| `failure_code` | integer | `0` for approved, nonzero for denied. |
| `failure_reason` | string or null | Denial reason when denied. |
| `ruleset_id` | string | Active ruleset identifier. |
| `direct_facts` | object | Direct STARK bridge facts only. |
| `proof_readiness` | object | Pre-proof readiness flags. |

Required readiness values:

- `proof_readiness.bridge_validated == true`
- `proof_readiness.prover_selected == false`
- `proof_readiness.witness_generated == false`
- `proof_readiness.proof_generated == false`
- `proof_readiness.on_chain_submission == false`

## StarkWitnessPlan

Schema version: `stark-witness-plan-v0`

Source schema version: `stark-proof-intent-v0`

Purpose: plan deterministic constraint groups for a future prover adapter. This
is not a generated witness and does not contain a cryptographic trace.

Top-level fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `schema_version` | string | Must be `stark-witness-plan-v0`. |
| `source_schema_version` | string | Must be `stark-proof-intent-v0`. |
| `claim_hash` | string | Public claim hash candidate. |
| `decision` | integer | `0` denied or `1` approved. |
| `failure_code` | integer | `0` for approved, nonzero for denied. |
| `direct_facts` | object | Boolean direct facts. |
| `constraint_groups` | array | Required constraint group declarations. |
| `witness_status` | string | Must be `planned_not_generated`. |

Required constraint groups:

- `public_adjudication_inputs`
- `direct_fact_constraints`
- `decision_consistency`

Required validation:

- `claim_hash` is present.
- `decision` is `0` or `1`.
- approved claim requires `failure_code = 0`.
- denied claim requires `failure_code != 0`.
- all `direct_facts` fields are `0` or `1`.
- all required constraint groups exist.
- `witness_status == planned_not_generated`.

## StarkMockTrace

Schema version: `stark-mock-trace-v0`

Source schema version: `stark-witness-plan-v0`

Purpose: produce a deterministic, non-cryptographic trace preview from a
validated witness plan. This is useful for adapter planning and test coverage,
but it is not a prover trace.

Top-level fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `schema_version` | string | Must be `stark-mock-trace-v0`. |
| `source_schema_version` | string | Must be `stark-witness-plan-v0`. |
| `claim_hash` | string | Claim hash from the witness plan. |
| `rows` | array | Deterministic mock trace rows. |
| `trace_status` | string | Must be `mock_trace_generated_no_proof`. |

Each row includes:

| Field | Type | Meaning |
| --- | --- | --- |
| `step_index` | integer | Deterministic row order. |
| `constraint_group` | string | Constraint group id. |
| `constraint_name` | string | Constraint name. |
| `input_value` | string | Observed input value. |
| `expected_value` | string | Expected shape or value. |
| `satisfied` | boolean | Whether the mock row condition is satisfied. |

Current mock rows:

1. `claim_hash_is_public_input`
2. `decision_is_public_input`
3. `failure_code_is_public_input`
4. `eligibility_active_is_boolean`
5. `provider_enrolled_is_boolean`
6. `duplicate_flag_is_boolean`
7. `approved_claim_requires_no_failure_code`
8. `denied_claim_requires_failure_code`

Validation command:

```bash
cargo run --bin validate_mock_trace -- mock_trace.json
```

Required validation:

- `schema_version == stark-mock-trace-v0`.
- `source_schema_version == stark-witness-plan-v0`.
- `claim_hash` is present.
- `rows` is non-empty.
- `step_index` is sequential from `0`.
- required constraint groups exist.
- required constraint names exist.
- every row has `satisfied == true`.
- `trace_status == mock_trace_generated_no_proof`.

## Non-Claims

These schemas do not claim:

- real STARK proof generation
- Cairo execution
- Winterfell execution
- Groth16 replacement
- on-chain settlement
- payment execution
- full policy/legal verification

They are bridge contracts for staged integration only.
