# Architecture Alignment

Reference used: the supplied `ARCHITECTURE_TECHNICAL.md` document.

Scope: this file aligns the current localBCE repository with the technical
architecture reference without changing runtime behavior. The reference document
describes a broader hardened app, batch, native STARK, payment, and operations
architecture. The active localBCE repo still keeps the Groth16 one-claim demo
path green while STARK and hardened components are staged behind explicit
bridges and reference bundles.

## Maturity Tags

- `[BUILT+TESTED]` - active code exists in this repo and has passing local tests.
- `[BUILT-STUBBED]` - code exists, but a critical production dependency is mocked,
  fail-closed, or not wired into production.
- `[SCAFFOLDED]` - a model, adapter, or planning surface exists, but is not
  enough to rely on as production behavior.
- `[REFERENCE]` - imported material exists for audit/research/porting, but is
  not active runtime code.
- `[DEFERRED]` - explicitly named work that is not built in the active path.

## Current Active Architecture

The active runtime path remains:

```text
rust-engine/claim_input.json
-> rust-engine adjudication
-> zk/input.json
-> Circom witness generation
-> Groth16 proof generation
-> Solidity Verifier
-> blind-ledger ClaimsRegistry
-> rust-engine/adjudication_result.json
```

Status: `[BUILT+TESTED]` compatibility/demo path.

This path does not yet include:

- 837 EDI ingestion
- batch orchestration
- claim-source/oracle/fee/nullifier roots
- Cairo execution
- native STARK proof generation
- native STARK settlement contracts
- live payment triggers

Those components are either imported as reference material or represented by
pre-prover planning interfaces.

## Reference-To-Repo Map

| Reference architecture area | Current localBCE location | Current status | Notes |
| --- | --- | --- | --- |
| 837 ingestion and shared context | `blind-ledger-app-layer/app/` and hardened bundle | `[REFERENCE]` | Not wired into active `rust-engine/claim_input.json` flow. |
| Rules engine gates | `rust-engine/src/main.rs`; imported `blind-ledger-app-layer/rules-engine-rust/` | `[BUILT+TESTED]` active G1-G10, `[REFERENCE]` imported engine | Active engine still evaluates current prototype fields, not the full shared-context model. |
| Groth16 proof path | `rust-engine/`, `zk/`, `blind-ledger/` | `[BUILT+TESTED]` | This is the active compatibility/demo path. |
| Claim-source, oracle-facts, fee roots | `stark-engine/`; `blind-ledger-app-layer/app/batch/` and hardened bundle | `[SCAFFOLDED]` active schemas, `[REFERENCE]` imported implementations | Phase 4 has planning-only root input schemas/generators/validators. No roots are generated. |
| Indexed nullifier root transition | `stark-engine/`; `blind-ledger-app-layer/app/batch/` and hardened bundle | `[SCAFFOLDED]` active schema, `[REFERENCE]` imported implementations | Phase 4 has a planning-only transition input. Active ClaimsRegistry has duplicate claim checks, but not the hardened indexed nullifier tree. |
| Public input vector | `blind-ledger-app-layer/app/public_inputs.py`; ops scaffolds | `[REFERENCE]` / `[SCAFFOLDED]` | Native STARK public inputs are not active local runtime inputs yet. |
| Hardened claim witness serializer | `stark-engine/`; `blind-ledger-app-layer/zk-stark/`, `zk-cairo-sharp/`, hardened bundle | `[SCAFFOLDED]` active bridge and feature-gated proof preview, `[REFERENCE]` imported research lanes | Active `stark-engine/` can produce complete Winterfell witness candidates and a feature-gated proof preview, but it is not runtime settlement. |
| Cairo/STARK statement | `blind-ledger-app-layer/zk-cairo-sharp/` and hardened bundle | `[REFERENCE]` | Cairo and native STARK settlement statements are not active localBCE runtime behavior. |
| Native STARK settlement contract | imported app-layer/hardened contracts | `[REFERENCE]` | Active Solidity settlement remains `ClaimsRegistry.sol` with Groth16 verifier compatibility. |
| Ops/governance scaffolding | `ops/` | `[SCAFFOLDED]` | Docs and inactive JSON scaffolds are present with a validator. They are not production approval. |
| Claude rules knowledge graph | `gov-rules-kg-prototype/` | `[SCAFFOLDED]` | Candidate extraction/review lane only; not active adjudication policy. |

## STARK Alignment Path

The production direction in the reference is native STARK settlement with
hardened roots, public inputs, and proof-verifier artifacts. The current repo is
aligned through a staged pre-prover path:

```text
rust-engine stark-bridge-input-dry-run
-> stark-engine validate_bridge_input
-> stark-engine generate/validate claimSourceRoot input
-> stark-engine generate/validate oracleFactsRoot input
-> stark-engine generate/validate feeScheduleRoot input
-> stark-engine generate/validate nullifier root transition input
-> stark-engine generate/validate batch root plan
-> stark-engine generate batch root gap report
-> stark-engine generate_proof_intent
-> stark-engine generate_witness_plan
-> stark-engine validate_witness_plan
-> stark-engine generate_mock_trace
-> stark-engine generate_winterfell_compat_report
-> stark-engine generate_winterfell_gap_plan
-> stark-engine generate/validate feature-gated Winterfell proof preview
```

Status: `[SCAFFOLDED]`.

This proves that active Rust claim facts can be normalized into a future STARK
adapter contract and exercised through a feature-gated Winterfell proof-preview
lane. It does not run Cairo, does not replace Groth16, and does not submit
on-chain.

## What Should Stay Separate For Now

- `blind-ledger-app-layer/` remains a standalone cofounder handoff and
  audit/research lane.
- `localBCE-codex-dev-hardened-20260616/` remains a reference bundle.
- `gov-rules-kg-prototype/` remains a candidate discovery/review/export lane.
- `stark-engine/` remains a first-class bridge/planning crate until a real
  prover adapter is explicitly added.
- `rust-engine/`, `zk/`, and `blind-ledger/` remain the active Groth16 flow.

## Deferred Production Work

- Replace one-claim Groth16 demo settlement with batch-native STARK settlement.
- Port only reviewed pieces of app-layer ingestion, batching, roots, and public
  input logic into active folders.
- Add a real prover adapter and audited verifier artifact.
- Define production native STARK public input schemas in active ops/docs.
- Bridge reviewed deterministic policy rules into Rust as shadow tests before
  runtime use.
- Add governed oracle/source policy and signer controls.
- Keep payment execution fail-closed until proof verification and governance
  controls are production-ready.

## Alignment Rule

Do not claim a reference component is active merely because it exists in an
imported folder. A component becomes active only after a later explicit porting
task wires it into the current runtime and adds focused tests.
