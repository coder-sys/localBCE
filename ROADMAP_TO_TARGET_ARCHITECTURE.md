# Roadmap To Target Architecture

Scope: implementation roadmap only. This document turns the maturity map in
`ARCHITECTURE_ALIGNMENT.md` into a safe integration sequence. It does not make
reference-only components active, does not change runtime behavior, and does not
replace the current Groth16 demo path.

## Roadmap Principles

- Keep the active Groth16 compatibility path green until a replacement path is
  built, tested, and explicitly switched on.
- Convert reference components into active components only through small,
  reviewed ports with focused tests.
- Treat `blind-ledger-app-layer/` and
  `localBCE-codex-dev-hardened-20260616/` as source material, not runtime truth.
- Bridge data contracts before porting large subsystems.
- Prefer shadow tests and validators before runtime reads or on-chain changes.
- Keep proof, settlement, payment, and governance fail-closed until production
  dependencies are real.

## Phase 0: Keep Demo Green

Status: active.

Goal: preserve the current working Rust -> Circom/Groth16 -> Solidity
ClaimsRegistry flow while new architecture pieces are staged beside it.

Required checks:

```bash
bash scripts/validate_localbce.sh
```

Active invariants:

- `rust-engine/claim_input.json` remains the active one-claim input.
- `denial_reason()` remains the active G1-G10 gate function.
- Denied claims stop before proof generation.
- Approved claims generate Groth16 proofs and submit to `ClaimsRegistry`.
- `adjudication_result.json` schema remains stable.
- `zk/claim.circom`, `rules.json`, and `rules_v9.json` are not casually changed.

Exit criteria:

- Repo validation passes.
- Active demo flow remains documented and reproducible.
- Any generated artifacts are cleaned before commit.

## Phase 1: Deterministic Rules Bridge

Status: scaffolded.

Goal: turn reviewed rule candidates into Rust-compatible deterministic behavior
without letting unreviewed AI output affect runtime adjudication.

Sequence:

1. Keep `gov-rules-kg-prototype/` as a candidate discovery and review lane.
2. Export promotion-ready candidates into an intermediate deterministic format.
3. Add Rust shadow-rule tests that compare candidate-derived behavior against
   current G1-G10 outcomes.
4. Add explicit human review metadata before any runtime use.
5. Only later, add a config-gated runtime reader for deterministic rules.

Must remain off runtime until reviewed:

- Claude web-grounded candidates.
- Promotion-ready but legally unverified candidates.
- Rules without exact source URL, citation text, and review status.

Exit criteria:

- Shadow tests cover current G1-G10 gates.
- Candidate rules can be traced to source/citation metadata.
- No runtime behavior changes until a later explicit task.

## Phase 2: STARK Bridge Hardening

Status: scaffolded.

Goal: mature the current `stark-engine/` pre-prover pipeline into a stable data
contract for future prover work.

Current chain:

```text
rust-engine stark-bridge-input-dry-run
-> stark-engine validate_bridge_input
-> stark-engine generate_proof_intent
-> stark-engine generate_witness_plan
-> stark-engine validate_witness_plan
-> stark-engine generate_mock_trace
-> stark-engine generate_winterfell_compat_report
-> stark-engine generate_winterfell_gap_plan
```

Next safe work:

1. Add fixture-based end-to-end tests for approved and denied bridge inputs.
2. Add mock-trace validation if not already present for every generated row.
3. Add stable schema docs for bridge input, proof intent, witness plan, and mock
   trace.
4. Compare mock trace expectations against the imported Winterfell/Cairo
   reference lanes.
5. Decide the first real prover adapter boundary without importing a prover into
   runtime.

Exit criteria:

- All STARK planning artifacts validate from deterministic fixtures.
- Gap plans identify direct, partial, unmapped, and unsupported fields.
- No real proof is claimed until a prover produces one.

## Phase 3: Batch Roots And Public Inputs

Status: reference-only target.

Goal: port the minimum batch-root data model needed for native STARK settlement.

Reference lanes:

- `blind-ledger-app-layer/app/batch/`
- `blind-ledger-app-layer/zk-cairo-sharp/`
- hardened bundle app and ops material

Safe sequence:

1. Document the target public input vector in active docs/ops.
2. Add test-only Rust or Python fixtures for claim-source roots.
3. Add oracle-facts root fixtures with official-source metadata.
4. Add fee-root fixtures with deterministic cents.
5. Add nullifier-root fixtures only after duplicate/nullifier semantics are
   written down and tested.

Do not port yet:

- Full batch orchestrator runtime.
- Payment trigger behavior.
- Native settlement contract wiring.
- Any path that submits payment or claims production proof verification.

Exit criteria:

- Roots are deterministic from fixtures.
- Public input schema is reviewed and versioned.
- Batch-root artifacts remain test-only until prover/contract work is ready.

## Phase 4: Native STARK Prover Adapter

Status: deferred.

Goal: replace mock traces with a real proof-producing adapter while preserving
the active Groth16 path until the STARK path is proven.

Safe sequence:

1. Choose the prover lane: Winterfell, Cairo/STARK, or another audited target.
2. Add a separate adapter crate/module, not a rewrite of `rust-engine/`.
3. Convert validated witness plans into prover-specific witnesses.
4. Generate proof artifacts in a dry-run command.
5. Add proof verification tests against known fixtures.
6. Only then consider an optional config-gated runtime path.

Exit criteria:

- Real proof is generated from a validated witness.
- Local verification passes.
- Artifact schema is versioned.
- Failure modes are fail-closed.

## Phase 5: Native Settlement Contracts

Status: reference-only target.

Goal: introduce native STARK settlement without breaking the current
ClaimsRegistry/Groth16 demo.

Safe sequence:

1. Keep `blind-ledger/src/ClaimsRegistry.sol` as active until replacement is
   explicitly deployed and tested.
2. Port only interfaces and tests first.
3. Add verifier artifact pin scaffolding as inactive ops/config.
4. Add native settlement contract tests with mock verifier behavior.
5. Add real verifier artifact checks only after proof generation exists.
6. Add deployment smoke tests before any runtime submission config changes.

Exit criteria:

- Native settlement tests pass.
- Artifact pin is non-production until audited.
- Deployment metadata is deterministic.
- Groth16 demo still validates after contract work.

## Phase 6: App-Layer Integration

Status: reference-only target.

Goal: connect ingestion, shared context, denial packets, 835 output, and
operator review after deterministic proof/settlement boundaries exist.

Safe sequence:

1. Port 837 parsing as a standalone inactive module or fixture test.
2. Map parsed claims into current `ClaimInput` without changing runtime reads.
3. Add shared-context normalization tests.
4. Add 835 output tests for approved and denied demo claims.
5. Add operator review routing only as an off-chain/reporting layer.

Exit criteria:

- App-layer data can round-trip into active claim fixtures.
- No payment or settlement side effect is introduced.
- Review/audit outputs are traceable to adjudication results.

## Phase 7: Production Ops And Governance

Status: scaffolded.

Goal: move from planning scaffolds to enforceable production readiness gates.

Current active scaffolds:

- `ops/` documentation
- inactive ops JSON files
- `scripts/validate_ops_scaffold.py`
- `scripts/validate_localbce.sh`

Safe sequence:

1. Keep validating inactive ops scaffolds.
2. Add schema checks for future production config files before copying them.
3. Add launch-blocker status reporting.
4. Add verifier artifact pin validation only after artifact production exists.
5. Add governance/key custody automation only after human ownership is defined.

Exit criteria:

- Ops config validation is automated.
- Launch blockers are explicit and reviewed.
- Production flags remain fail-closed by default.

## Current Recommended Next Step

Implement the next safe non-runtime integration:

1. Add fixture-based STARK bridge end-to-end tests for approved and denied
   examples.
2. Keep Groth16 validation green with `bash scripts/validate_localbce.sh`.
3. Do not wire a real prover or native settlement contract until bridge fixtures
   and schema docs are stable.
