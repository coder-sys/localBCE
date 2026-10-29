# Integration status

Integration branch: `integration/rightrail`
Phase: 1 (gate defects), D-02/D-03 draft PR #5 open
Exact HEAD for this document: see `git log -1 --format=%H -- STATUS.md` on the branch that adds it.

## Merged
- PR #1 (N-01, STARK validator proof gate): merged into `integration/rightrail` at `d25394d`. CI green on all six jobs of `production-gates` for head `4b21e79`.
- PR #2 (RightRail import with history under `rightrail/`, source `af020b2`): merged.
- PR #3 (Phase 0 docs, self-check, and Windows smoke): merged. All six CI jobs passed at head `264da7d`.
- PR #4 (D-01/N-08, retire Groth16 runtime routing): merged into `integration/rightrail` at `e746f582`.

## Open
- PR #5 (D-02/D-03 STARK binding gaps 1-5), draft into `integration/rightrail`, head `e6f9dc8f`. CI run `40788336406`: all 8 jobs succeeded and the release-mode stark-engine steps succeeded on Linux (job 123167022508, step 8) and Windows (job 123167022768, step 4); per-test lines not yet confirmed (OPEN_QUESTIONS item 9). Not merged; awaiting human review.

## Defects
| ID | Status | Proof |
|---|---|---|
| N-01 | FIXED | PR #1; `tests/test_stark_validation_config_gate.py` |
| D-01 | FIXED | PR #4 (`e746f582`); `scripts.tests.test_d01_groth16_retirement`; active Rust and Foundry builds exclude the retired path |
| N-08 | FIXED | PR #4 (`e746f582`); `d_01_n_08_config_rejects_groth16_proof_backend` |
| D-02 | FIXED ON BRANCH | PR #5, gap 1: `reject_after_path_sibling_forgery` (fix `418ad603`) |
| D-03 | FIXED ON BRANCH | PR #5, gaps 2-5: `reject_claim_source_limb_forgery` (`a93fd296`), `reject_nullifier_preimage_limb_forgery` (`ed8d43db`), `reject_oracle_facts_link_forgery` (`a7ab1329`), `reject_fee_schedule_link_forgery` (`3cda5533`); release-only; CI release-mode steps added in `e6f9dc8f` |
| D-04..D-10, R-01..R-08 | OPEN | Phase 1+ |
| N-02..N-07 | OPEN | Phase 1+ (N-05, N-07 in Phase 1) |

Self-check output: run `bash scripts/integration_selfcheck.sh`.
