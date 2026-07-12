# STARK Transition Remaining Work

## Current Position

The repository is no longer at the beginning of the STARK pivot. It now has:

- an active Groth16 demo path that remains the runtime source of truth
- `stark-engine/` bridge schemas, validators, and smoke-chain CLIs
- feature-gated Winterfell proof preview generation and validation
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

Remaining:

- document the production ABI candidate
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

Status: next major engineering phase.

Goal:

Turn the current Winterfell proof preview into a real, deterministic prover
boundary that can produce artifacts suitable for verification.

Remaining:

- choose final prover lane for localBCE production direction
- replace preview proof metadata with actual proof bytes/commitments
- lock witness encoding from `StarkBridgeInput` through proof generation
- add fixture proofs for approved and denied claims
- validate proof determinism across repeated runs
- document proof artifact versioning

Exit criteria:

- real proof generated from a validated witness
- local verifier accepts the proof
- invalid witness/proof fails closed
- output artifact schema is stable

### Phase 9: Solidity Verifier Integration

Status: blocked on Phase 8.

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

- 70-75% complete for scaffolding and compatibility modeling
- 45-55% complete for an end-to-end STARK technical migration
- 20-30% complete for production-grade STARK settlement

The remaining work is harder than the earlier phases because it requires a real
prover boundary, verifier artifact strategy, and runtime/deployment controls.

## Next Best Step

The next safest implementation step is still non-runtime:

1. Add a production ABI candidate document/test for STARK verifier public inputs.
2. Keep the current preview interfaces unchanged unless the candidate reveals a
   mismatch.
3. Run `bash scripts/validate_localbce.sh` after every Solidity or STARK bridge
   change.
