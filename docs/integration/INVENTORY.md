# Inventory

Repo: coder-sys/localBCE. Imported RightRail: `rightrail/` (source `af020b2`, bundle SHA-256 `3b61a4ab...c1c5fa`; see `rightrail/IMPORTED_FROM.md`).
Updated 2026-11-07 for `RIGHTRAIL_BASE_PLAN.md` Phase 1: proof and chain code is parked.

## Active localBCE components
- `rust-engine/`: claims adjudication (G1–G10, `denial_reason()`), `config.json` with no chain or key fields; any proof backend other than `none` fails closed.
- `gov-rules-kg-prototype/`: LLM rules extraction (Postgres), outside the RightRail trunk; proposals only.
- `blind-ledger-app-layer/`: app/audit lane; only the 837 intake and audit adapters are planned to carry into RightRail (Phase 4).
- `bridge/rightrail_offchain.py`: off-chain JSONL journal. To be retired in Phase 4.
- `scripts/`: validators and tests for the active tree, the G-rule parity harness (`g_rule_parity.py`) and the `RR/RULES/CONTENT/v1` proposal exporter (`rules_content_v1.py`).
- `.github/workflows/production-gates.yml`: root CI (`rules-and-ops`, `rust`, `windows-smoke`), triggers on `pull_request` and `push` to `codex-dev`.

## Parked (`parked/localbce/`, not built, tested or run; see its README)
- `stark-engine/`: Winterfell AIR, nullifier state, attestation (includes PR #5's forgery-gap and presence-flag fixes, merged at `bc50dd62` before parking).
- `blind-ledger/`: Solidity `ClaimsRegistry` (Groth16 path) and V2 STARK contracts, Foundry tests.
- `zk/`: Circom `claim.circom` (binds nothing; D-04). Its `.zkey`, `.ptau` and `.wtns` files were removed on 2026-11-07 and are recoverable from Git history (CLEANUP_PROPOSAL item 2).
- `zk-prover/`, `deprecated/groth16/`, app-layer `contracts/`, `l2/`, `zk*/`, STARK and chain scripts.

## RightRail components (under `rightrail/`)
- `lean/`: Lean 4 decision worker (`blind_financial_worker`) and gate rules (`BlindLedger/Gate/Rules/`).
- `app/`: Python financial owner (SQLite WAL), staff server, 835 X12 parser, signer.
- `rust/`, `conformance/`, `tests/`, `docs/`: supporting code and specs.
- Tracked binaries: `artifacts/engine-evaluator/blind_financial_worker.exe`, `artifacts/gate-verify/gate_verify.exe`: kept as pinned workers; the self-check verifies their pinned SHA-256 (CLEANUP_PROPOSAL item 1).
