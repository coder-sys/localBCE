# Integration status

Integration branch: `integration/rightrail`
Phase: 1 (gate defects), D-02 draft PR #5 open; D-03 not started
Exact HEAD for this document: see `git log -1 --format=%H -- STATUS.md` on the branch that adds it.

## Merged
- PR #1 (N-01, STARK validator proof gate): merged into `integration/rightrail` at `d25394d`. CI green on all six jobs of `production-gates` for head `4b21e79`.
- PR #2 (RightRail import with history under `rightrail/`, source `af020b2`): merged.
- PR #3 (Phase 0 docs, self-check, and Windows smoke): merged. All six CI jobs passed at head `264da7d`.
- PR #4 (D-01/N-08, retire Groth16 runtime routing): merged into `integration/rightrail` at `e746f582`.

## Open
- PR #5 (D-02 STARK forgery gaps 1-5; D-03 not started), draft into `integration/rightrail`, head `ba4896fb`. CI run `40949974519` (#36): all 8 jobs succeeded; the release-mode stark-engine suite passed on Linux and Windows, and all five `reject_*_forgery` tests report `ok` on both (OPEN_QUESTIONS item 9, resolved). Earlier run `40788336406` on `e6f9dc8f` is kept as history. Not merged; awaiting human review.

## Defects
| ID | Status | Proof |
|---|---|---|
| N-01 | FIXED | PR #1; `tests/test_stark_validation_config_gate.py` |
| D-01 | FIXED | PR #4 (`e746f582`); `scripts.tests.test_d01_groth16_retirement`; active Rust and Foundry builds exclude the retired path |
| N-08 | FIXED | PR #4 (`e746f582`); `d_01_n_08_config_rejects_groth16_proof_backend` |
| D-02 | PARTIAL ON BRANCH | PR #5, gaps 1-5 forgery tests pass in CI; presence flags (elements 24-26) and reserved zeros still open (OPEN_QUESTIONS 7-8; required for D-02 per spec) |
| D-03 | NOT STARTED | Gaps 2-5 were labeled D-03 in commits and docs in error; that work is D-02. Real D-03 needs EVIDENCE/v1 (Phase 2) |
| D-04..D-10, R-01..R-08 | OPEN | Phase 1+ |
| N-02..N-07 | OPEN | Phase 1+ (N-05, N-07 in Phase 1) |

Self-check output: run `bash scripts/integration_selfcheck.sh`.
