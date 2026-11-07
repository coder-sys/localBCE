# Blind Ledger - Claims Adjudication for RightRail

> **Direction (chosen by the project owner 2026-11-06):** RightRail (`rightrail/`) is the base system.
> localBCE is wired into it without Groth16, STARK, or Solidity/on-chain
> settlement. That code is parked, not deleted, under `parked/localbce/`.
> Plan: `docs/integration/RIGHTRAIL_BASE_PLAN.md`. Other documents in this
> repository that describe proofs, contracts, Sepolia, Anvil or Foundry as
> active (`ARCHITECTURE_ALIGNMENT.md`, `ROADMAP_TO_TARGET_ARCHITECTURE.md`,
> `PROJECT_STATE.md`, `REDEPLOY_WORKFLOW.md`, `TASKS.md`, the STARK and
> deployment runbooks in `ops/`) are historical and refer to the parked code.

The active runtime is the Rust G1-G10 adjudicator. It validates claims
off-chain and writes the adjudication result without generating a proof or
submitting a transaction. Any proof backend other than `none`, or
`proof_execution_enabled=true`, fails closed.

---

# Current Workflows

Default adjudication-only runtime:

claim_input.json
-> Rust adjudication
-> denial_reason validation
-> adjudication_result.json

The result records `tx_submitted: false` and `tx_hash: null` for approved and
denied decisions.

An operator may pass that proof-free result to the RightRail-derived off-chain
ledger and reconciliation bridge:

```text
adjudication_result.json
-> append-only hash-linked journal
-> synthetic remittance events
-> deterministic reconciliation report
```

The bridge is documented in `bridge/README.md`. It does not execute the
external RightRail runtime, move money, generate a proof, sign an attestation,
or submit a transaction. It is transitional: RightRail's `FinancialOwner` is to
become the only writer (plan Phase 4).

There is no proof or chain backend. The Groth16 and STARK paths (Circom
witness and proof, Winterfell proof, Solidity verifiers, ClaimsRegistry and
StarkClaimsRegistry) are parked under `parked/localbce/`. No configuration
change re-enables them: `proof_backend` other than `none`, or
`proof_execution_enabled=true`, makes the adjudicator refuse to start, and
chain fields in `config.json` are ignored.

---

# Validation

Run the full local health check from the repository root:

```bash
bash scripts/validate_localbce.sh
```

This runs:

- `python3 -m unittest discover -s scripts/tests` (parking guard, G-rule parity, rule content)
- the `tests/` suite, with `gov-rules-kg-prototype/.venv/bin/python` when that venv exists (it holds `pypdf`)
- `python3 scripts/validate_ops_scaffold.py`
- `python3 scripts/scan_secrets.py`
- `bash scripts/validate_rules_pipeline.sh`
- `cargo test` and `cargo check` in `rust-engine/`

The STARK, Foundry, Sepolia, Anvil and OpenZeppelin-pin gates are parked with
their code under `parked/localbce/` and are not run.

The integration self-check prints PASS, FAIL or NOT-YET per item:

```bash
bash scripts/integration_selfcheck.sh
```

---

# Architecture Alignment

- active adjudication and off-chain reconciliation: `rust-engine/`, `bridge/`
- RightRail base system: `rightrail/` (own `CONSTITUTION.md` and `AGENTS.md`; provenance in `rightrail/IMPORTED_FROM.md`)
- parked Groth16, STARK and chain code: `parked/localbce/` (not built or run)
- imported app/audit reference lane: `blind-ledger-app-layer/`
- imported hardened reference bundle: `localBCE-codex-dev-hardened-20260616/`
- rules discovery/review lane: `gov-rules-kg-prototype/` (proposals only)
- ops/governance planning scaffold: `ops/`

See `RULES_ENGINE.md` for the hash-pinned G1-G10 JSON evaluator and the
non-runtime Claude candidate shadow boundary, and
`docs/integration/PHASE2_REPORT.md` for the G-rule parity harness against
RightRail's Lean gate rules and the proposed `RR/RULES/CONTENT/v1` format.

---

# Project Structure

```text
localBCE/
  rust-engine/    Rust adjudication engine (G1-G10, denial_reason())
  bridge/         transitional off-chain journal and reconciliation
  rightrail/      RightRail base system (Lean decision worker, owner, gate rules)
  gov-rules-kg-prototype/
                  Claude web-grounded rules corpus (outside the RightRail trunk)
  blind-ledger-app-layer/
                  imported app/audit layer (837 intake and audit adapters planned for RightRail)
  scripts/        validators, self-check, parity harness, rule-content exporter
  parked/localbce/
                  parked Groth16, STARK, Foundry and chain code (see its README)
  localBCE-codex-dev-hardened-20260616/
                  imported hardened reference bundle
```

---

# Active Files

- rust-engine/src/main.rs, rules_engine.rs, advanced_rules.rs
- rust-engine/config.json, config.rules.example.json
- rust-engine/claim_input.json, adjudication_result.json
- rust-engine/rules.json, rules_v9.json, rules_active_v1.json
- bridge/rightrail_offchain.py
- scripts/g_rule_parity.py, scripts/rules_content_v1.py

Note: blind-ledger-app-layer is imported as a standalone cofounder handoff and
audit/research lane and is not wired into the active workflow. gov-rules-kg-prototype
outputs are proposals; they are not active adjudication rules until reviewed.
The hardened reference bundle is not active runtime code unless a later task
explicitly ports a file.

---

# Current Gate Coverage

- G1 Eligibility
- G2 Aid code validation
- G3 Date range validation
- G4 Share-of-cost validation
- G5 Provider validation
- G6 Billing validation
- G7 Duplicate detection
- G8 Disability determination
- G9 Recipient deceased validation
- G10 Physician certification

---

# Current Output

Approved claim (`rust-engine/adjudication_result.json` for the checked-in `claim_input.json`):

```json
{
  "claim_id": "CLAIM-DEMO-011",
  "claim_hash": "0x1c1b60223d4f3ffd351887f834b31a4260508b1602a5a9e16a447ea40e386607",
  "status": "APPROVED",
  "reason": null,
  "tx_submitted": false,
  "tx_hash": null
}
```

A denied claim has the same shape with `"status": "DENIED"` and a reason such as
`"G9_RECIPIENT_DECEASED"`.

---

# Current Rules Files

- rules.json - current/simple working rules
- rules_v9.json - future target architecture (not active)
- rules_active_v1.json - typed, hash-pinned G1-G10 ruleset, used only through the
  explicit `versioned_g1_g10` backend with its pinned hash and parity gate

The Rust engine reads `claim_input.json` and its runtime configuration from
`config.json` (paths can be overridden with `LOCALBCE_CLAIM_INPUT_PATH` and
`LOCALBCE_CONFIG_PATH`).

---

# Important Constraints

- main.rs must continue reading claim_input.json
- denial_reason() must remain
- approved claims require unique claim_id
- adjudication_result.json must continue working
- rules.json and rules_v9.json must remain parallel
- no proof backend, chain setting or private key returns to active config or code

---

# Verification

```bash
cd rust-engine
cargo test
cargo check
```

---

# Next Steps

See `docs/integration/RIGHTRAIL_BASE_PLAN.md` §5 and `docs/integration/OPEN_QUESTIONS.md`.
Phases 3-4 (new Lean rules and their evidence, the 837 intake adapter, the owner as
the only writer, retiring the bridge and the Rust reference) need a Lean toolchain,
RightRail's guard script and a RightRail lead.
