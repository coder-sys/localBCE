# STARK Transition Remaining Work

## Current Position

The repository is no longer at the beginning of the STARK pivot. It now has:

- an active Groth16 demo path that remains the runtime source of truth
- `stark-engine/` bridge schemas, validators, and smoke-chain CLIs
- feature-gated Winterfell proof preview generation and validation
- a feature-gated production G1-G10 Winterfell AIR with real local proof
  generation and verification
- versioned production proof artifacts and verifier handoffs
- an AIR-constrained depth-10 claim-source Merkle root
- batch/public-input planning artifacts
- preview-only Solidity interfaces for future STARK verification and settlement
- focused Foundry tests for the STARK Solidity preview lane

No real production STARK settlement is active yet.

## Completion Target

The transition is complete only when this path is real, validated, and
explicitly selected:

```text
reviewed deterministic claim/rule input
-> rust-engine adjudication
-> stark-engine witness generation
-> real STARK proof generation
-> local proof verification
-> production STARK verifier artifact
-> Solidity verifier/adapter settlement
-> deployment metadata and ops gates
-> optional runtime switch away from Groth16
```

Until then, Groth16 remains the compatibility/demo runtime.

## Remaining Phases

### Phase 7: Settlement Preview Hardening

Status: in progress.

Done:

- STARK verifier preview interface
- root-aware STARK verifier preview interface
- STARK ClaimsRegistry adapter preview interface
- event/accounting compatibility tests
- focused Solidity preview validation script
- production STARK verifier ABI candidate interface and tests

Remaining:

- define proof commitment encoding requirements
- define public input root encoding requirements
- define adapter failure modes and event semantics
- decide whether the first production path is a separate adapter contract or a
  new registry version

Exit criteria:

- preview ABI and event semantics are stable enough for a real verifier
- all STARK Solidity preview tests pass
- active `ClaimsRegistry.sol` remains unchanged

### Phase 8: Real Prover Boundary

Status: feature-gated production AIR, local prover, artifact packaging, and
claim-source root binding implemented; governed roots, verifier, and runtime
integration remain.

Goal:

Turn the current Winterfell proof preview into a real, deterministic prover
boundary that can produce artifacts suitable for verification.

Completed:

- selected Winterfell 0.13 for the current production-direction AIR
- implemented all ordered G1-G10 gates and first-failure semantics
- generated and locally verified approved and all 13 denial proofs
- locked a canonical 28-element claim-and-fact preimage
- constrained a public `Rp64_256` Rescue-Prime commitment inside the AIR
- rejected claim-hash, fact, and public-commitment tampering
- serialize the production proof bytes and exact public-input order
- add versioned approved and denied proof artifacts
- validate artifact determinism and local re-verification
- pin prover/verifier parameters and artifact digests
- expose the artifact behind an explicit non-default CLI
- constrain a canonical claim-source leaf and depth-10 Merkle path
- expose `claimSourceRoot` as four public inputs and include it in
  `publicInputRoot`
- package 18 public inputs and both constrained roots in v3 artifact and
  verifier-handoff schemas

Remaining:

- define governance and approval semantics for `claimSourceRoot`
- implement and bind oracle, fee, nullifier-before, nullifier-after, and batch
  roots
- independently validate the locked prover and verifier parameters

Exit criteria:

- real proof generated from a validated witness
- local verifier accepts the proof
- invalid witness/proof fails closed
- output artifact schema is stable

Current Phase 8 implementation includes the earlier artifact candidates plus:

- `stark-engine/src/production_air.rs`
- `stark-engine/src/production_air_winterfell.rs`
- `stark-engine/src/production_air_winterfell_tests.rs`
- `STARK_PHASE8_PROVER_BOUNDARY.md`

The feature-gated tests generate real local Winterfell proofs, serialize them
into a versioned artifact, deserialize and re-verify them, and build an
ABI-aligned handoff. Those artifacts are not accepted by runtime or Solidity.

### Phase 9: Solidity Verifier Integration

Status: blocked on the five remaining root implementations and independent
verification of the Phase 8 artifact boundary.

Goal:

Connect a real STARK verifier artifact to Solidity without disrupting the
Groth16 demo.

Remaining:

- define verifier artifact pin format
- produce Solidity-compatible verifier interface/contract
- add mock-verifier and real-verifier test suites
- validate public input root and proof commitment encoding
- add deployment smoke tests for the STARK verifier path
- keep Groth16 deployment path working

Exit criteria:

- Solidity tests pass with real verifier artifact or audited verifier shim
- deployment metadata records STARK verifier and adapter addresses
- artifact pin validation is fail-closed

### Phase 10: Runtime Selection

Status: deferred.

Goal:

Allow the system to run Groth16 or STARK through an explicit config-gated path.

Remaining:

- add config flag for proof system selection
- keep Groth16 as default until STARK is production-ready
- add dry-run-only STARK submission mode first
- add runtime tests for denied, approved, duplicate, and invalid proof cases
- preserve `adjudication_result.json` compatibility or version changes
  explicitly

Exit criteria:

- Groth16 default remains green
- STARK path is opt-in and fail-closed
- runtime output schemas are documented and tested

### Phase 11: Production Ops Gate

Status: scaffolded.

Goal:

Prevent accidental production claims about unverified proof/settlement paths.

Remaining:

- promote inactive ops JSON scaffolds into enforced checks only when owners are
  assigned
- add verifier artifact pin validation for real artifacts
- add launch-blocker reporting to CI/local validation
- add key custody and deployment runbook acceptance checks
- define audit logs for STARK settlement events

Exit criteria:

- production readiness gates fail closed
- launch blockers are visible
- deployment and verifier artifacts are reproducible

## Practical Estimate

For the current prototype, the transition is roughly:

- 90-95% complete for scaffolding and compatibility modeling
- 75-80% complete for an end-to-end STARK technical migration
- 35-45% complete for production-grade STARK settlement

The remaining work is harder than the earlier phases because it requires a real
on-chain verifier, settlement integration, runtime selection, and
deployment/operations controls.

## Next Best Step

The next safest implementation step remains non-runtime:

1. Convert the production proof artifact into a versioned verifier handoff
   envelope. Completed; the current artifact and handoff schemas are v3.
2. Bind the candidate ABI's `publicInputRoot` inside the AIR and package it as
   canonical Solidity `bytes32`. Completed in artifact/handoff schema v3.
3. Bind the local claim-source Merkle candidate into the AIR and handoff.
   Completed; governance approval is still pending.
4. Implement the five remaining source/state roots and add a real verifier.
5. Keep ClaimsRegistry and active Groth16 behavior unchanged until a real
   Solidity STARK verifier exists and passes independent proof tests.
