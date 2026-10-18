# Integration status

Integration branch: `integration/rightrail`
Phase: 1 (gate defects), D-01/N-08 PR in progress
Exact HEAD for this document: see `git log -1 --format=%H -- STATUS.md` on the branch that adds it.

## Merged
- PR #1 (N-01, STARK validator proof gate): merged into `integration/rightrail` at `d25394d`. CI green on all six jobs of `production-gates` for head `4b21e79`.
- PR #2 (RightRail import with history under `rightrail/`, source `af020b2`): merged.
- PR #3 (Phase 0 docs, self-check, and Windows smoke): merged. All six CI jobs passed at head `264da7d`.

## Open
- D-01/N-08 protected-change PR: test-first commits `4ad2ba64` and `f4a18236`; CI pending.

## Defects
| ID | Status | Proof |
|---|---|---|
| N-01 | FIXED | PR #1; `tests/test_stark_validation_config_gate.py` |
| D-01 | FIXED ON BRANCH | `scripts.tests.test_d01_groth16_retirement`; active Rust and Foundry builds exclude the retired path |
| N-08 | FIXED ON BRANCH | `d_01_n_08_config_rejects_groth16_proof_backend` |
| D-02..D-10, R-01..R-08 | OPEN | Phase 1+ |
| N-02..N-07 | OPEN | Phase 1+ (N-05, N-07 in Phase 1) |

Self-check output: run `bash scripts/integration_selfcheck.sh`.
