# Inventory

Repo: coder-sys/localBCE. Imported RightRail: `rightrail/` (source `af020b2`, bundle SHA-256 `3b61a4ab...c1c5fa`).

## localBCE components
- `rust-engine/`: claims adjudication (G1–G10), `config.json` (fenced: `proof_execution_enabled=false`).
- `stark-engine/`: Winterfell AIR, nullifier state, attestation. Binding gaps D-02/D-03 open.
- `blind-ledger/`: Solidity `ClaimsRegistry` (Groth16 path) and V2 STARK contracts. Foundry tests.
- `zk/`: Circom `claim.circom` (binds nothing; D-04 open). Contains `.zkey`, `.ptau`, `.wtns` (tracked; see CLEANUP_PROPOSAL).
- `gov-rules-kg-prototype/`: LLM rules extraction (Postgres).
- `bridge/rightrail_offchain.py`: off-chain JSONL journal from the earlier retired decision. To be retired in Phase 4.
- `scripts/`: validators, including `validate_stark_v2_anvil.sh` and `validate_stark_runtime_settlement.sh`.
- `.github/workflows/production-gates.yml`: root CI, triggers on `pull_request` and `push` to `codex-dev`.

## RightRail components (under `rightrail/`)
- `lean/`: Lean 4 decision worker (`blind_financial_worker`). Payment ALLOW/HOLD/DENY decision.
- `app/`: Python financial owner (SQLite WAL), staff server, 835 X12 parser, signer.
- `rust/`, `conformance/`, `tests/`, `docs/`: supporting code and specs.
- Tracked binaries: `artifacts/engine-evaluator/blind_financial_worker.exe`, `artifacts/gate-verify/gate_verify.exe` (cleanup pending).
