# AGENTS.md - Blind Ledger Instructions

## Project Goal

RightRail (`rightrail/`) is the base system. localBCE contributes claims
adjudication rules, a government-rules corpus, and selected app-layer adapters
to it, **without** Groth16, STARK, or Solidity/on-chain settlement.

The integration plan is `docs/integration/RIGHTRAIL_BASE_PLAN.md`. Work
proceeds in its phases, each ending with a report and a pause.

Current adjudication workflow (no proofs, no chain):

claim_input.json
-> Rust adjudication (denial_reason(), optional hash-pinned versioned_g1_g10)
-> adjudication_result.json (tx_submitted=false, tx_hash=null)
-> optional bridge/rightrail_offchain.py journal (until the RightRail owner replaces it)

---

# Project Structure

## rightrail Directory

rightrail/ is the base system with its own `CONSTITUTION.md` and `AGENTS.md`.
Changes inside it follow those documents: Lean decides, one writer
(`FinancialOwner`), no duplicate policy, protected-change (XI.2) records, and
guarded runs.

## parked/localbce Directory

parked/localbce/ holds the Groth16, STARK, Foundry/Solidity and chain code that
was moved out of the active tree. It is parked, not deleted, keeps its original
relative paths, and is not built, tested or run. Do not depend on it. Reviving
anything needs an approved `docs/integration/CLEANUP_PROPOSAL.md` entry.

## blind-ledger-app-layer Directory

blind-ledger-app-layer/ is an imported app/audit lane from the cofounder
handoff. Only selected adapters (837 intake, audit reports) are planned to
carry into RightRail. Its second G1-G10 engine (`rules-engine-rust/`,
`rules_engine_fallback.py`) is not carried. Do not silently wire this layer
into the active workflow.

## gov-rules-kg-prototype Directory

gov-rules-kg-prototype/ is the rules-authoring corpus (PostgreSQL, Claude
inference). It stays outside the RightRail trunk and produces proposals only;
model output is a lead, never a determination.

## localBCE-codex-dev-hardened-20260616 Directory

localBCE-codex-dev-hardened-20260616/ is an imported hardened reference bundle.
Do not treat files inside it as active runtime sources unless a task
explicitly ports them. Copy or adapt only the specific reviewed file needed.

---

# Important Active Files

- docs/integration/RIGHTRAIL_BASE_PLAN.md
- rust-engine/src/main.rs
- rust-engine/src/rules_engine.rs
- rust-engine/src/advanced_rules.rs
- rust-engine/config.json
- rust-engine/config.rules.example.json
- rust-engine/claim_input.json
- rust-engine/adjudication_result.json
- rust-engine/rules.json
- rust-engine/rules_v9.json
- rust-engine/rules_active_v1.json
- bridge/rightrail_offchain.py
- gov-rules-kg-prototype/
- blind-ledger-app-layer/app/
- rightrail/

---

# Current Working Features

- G1-G10 denial rules and denial_reason() in Rust
- hash-pinned `rules_active_v1.json` evaluator behind `versioned_g1_g10`
- adjudication_result.json generation and claim_hash generation
- runtime config loaded from rust-engine/config.json (no chain or key fields)
- Rust-validated, non-runtime Claude shadow rules bundle
- government rules corpus and promotion queue (proposals only)
- RightRail off-chain bridge journal and reconciliation (transitional)

Proof execution is parked: `proof_backend` other than `none`, or
`proof_execution_enabled=true`, fails closed.

The deterministic rules boundary is documented in `RULES_ENGINE.md`.
`rules_active_v1.json` is the only typed runtime candidate and is pinned to
exact G1-G10 parity. Claude web rules remain shadow-only and not legally
verified.

---

# Important Constraints

## DO NOT BREAK

- main.rs must continue reading claim_input.json
- denial_reason() must remain
- rules_v9.json is NOT active yet
- rules.json and rules_v9.json must remain parallel
- rules_active_v1.json may be used only through the explicit
  `versioned_g1_g10` backend and must preserve the pinned hash/parity gate
- adjudication_result.json must continue working
- approved claims require unique claim_id
- no proof backend, chain setting or private key returns to active config or code

---

# Preferred Development Style

- Keep changes incremental, one phase of the plan at a time
- Move or park instead of deleting; deletions need an approved cleanup entry
- Prefer compatibility over architecture changes outside the agreed plan
- Report failures and skips as they are

---

# Autonomous Work Rules

- Follow docs/integration/RIGHTRAIL_BASE_PLAN.md and docs/integration/GOVERNANCE.md.
- Inside rightrail/, follow rightrail/CONSTITUTION.md and rightrail/AGENTS.md.
- Do not build, run, or extend anything under parked/.
- Run cargo test and cargo check after Rust changes.
- Run the Python suites (scripts/tests, tests) after script changes.
- Preserve backward compatibility of claim_input.json and adjudication_result.json.
