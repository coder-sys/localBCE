# Integration status

Integration branch: `integration/rightrail`
Phase: 0 (preparation), PR 3 in progress
Exact HEAD for this document: see `git log -1 --format=%H -- STATUS.md` on the branch that adds it.

## Merged
- PR #1 (N-01, STARK validator proof gate): merged into `integration/rightrail` at `d25394d`. CI green on all six jobs of `production-gates` for head `4b21e79`.
- PR #2 (RightRail import with history under `rightrail/`, source `af020b2`): open, see PR. Not yet merged.

## Defects
| ID | Status | Proof |
|---|---|---|
| N-01 | FIXED | PR #1; `tests/test_stark_validation_config_gate.py` |
| D-01 | FENCED | `proof_execution_enabled=false`; `groth16` still accepted (N-08) |
| N-08 | OPEN | `rust-engine/src/main.rs` accepts `groth16` |
| D-02..D-10, R-01..R-08 | OPEN | Phase 1+ |
| N-02..N-07 | OPEN | Phase 1+ (N-05, N-07 in Phase 1) |

Self-check output: run `bash scripts/integration_selfcheck.sh`.
