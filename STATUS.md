# Integration status

Integration branch: `integration/rightrail`
Direction: RightRail is the base system; localBCE is wired in without Groth16, STARK or on-chain settlement (`docs/integration/RIGHTRAIL_BASE_PLAN.md`).
Phase: 1 (park proofs and chain; adjudicator without chain) and 2 (G-rule parity harness, proposed rule content format) on branch `codex/rightrail-base-phases`, draft PR into `integration/rightrail`. Phases 3-4 blocked: no RightRail guard script, Lean toolchain or `rr-core` lead on this machine (plan §7, OPEN_QUESTIONS item 12).
Exact HEAD for this document: see `git log -1 --format=%H -- STATUS.md` on the branch that adds it.

## Merged
- PR #1 (N-01, STARK validator proof gate): merged into `integration/rightrail` at `d25394d`.
- PR #2 (RightRail import with history under `rightrail/`, source `af020b2`): merged.
- PR #3 (Phase 0 docs, self-check, and Windows smoke): merged. All six CI jobs passed at head `264da7d`.
- PR #4 (D-01/N-08, retire Groth16 runtime routing): merged into `integration/rightrail` at `e746f582`.
- PR #5 (D-02 STARK forgery gaps 1-5, then presence flags and reserved zeros in `cf7d6953`): merged into `integration/rightrail` at `bc50dd62` on 2026-11-06. CI run `40949974519` on its earlier head `ba4896fb` passed all 8 jobs, with all five `reject_*_forgery` tests `ok` on Linux and Windows. The owner then confirmed STARK stays parked (2026-11-07): this branch moves that code, with PR #5's fixes, under `parked/localbce/stark-engine/` and drops its CI steps.

## Open
- Phases 1-2 (branch `codex/rightrail-base-phases`, draft PR): park proof/chain code under `parked/localbce/`, remove STARK/chain paths from `rust-engine`, trim CI, widen Windows CI, G-rule parity harness and report, `RR/RULES/CONTENT/v1` proposal, `rightrail/IMPORTED_FROM.md`. Merges `integration/rightrail` at `bc50dd62`.

## Defects
| ID | Status | Proof |
|---|---|---|
| N-01 | FIXED, then PARKED | PR #1; its STARK validator gate test is parked with STARK (`parked/localbce/tests/test_stark_validation_config_gate.py`) |
| D-01 | FIXED | PR #4 (`e746f582`); `scripts.tests.test_d01_groth16_retirement` |
| N-08 | FIXED | PR #4 (`e746f582`); `d_01_n_08_config_rejects_groth16_proof_backend` |
| N-07 | FIXED ON BRANCH | Anvil key removed from active config and code; `scan_secrets.py` allowlist limited to parked tooling |
| D-02 | FIXED IN PARKED CODE (as far as PR #5 went) | PR #5 gaps 1-5 and `cf7d6953`; parked, so its tests no longer run in CI. Not covered by PR #5: claim-source tags and presence flags (columns 140-143, 160-163) asserted at row 0 only (found 2026-11-06, not tested) |
| D-03 | NOT STARTED, PARKED | Gaps 2-5 were labeled D-03 in commits in error; that work is D-02. Real D-03 needs EVIDENCE/v1 and does not apply to the active tree |
| D-04 | NOT APPLICABLE TO ACTIVE CODE | Groth16 circuit is parked |
| D-05..D-10, R-01..R-08 | OPEN | Re-triage against the RightRail-base plan |
| N-02..N-06 | OPEN | Re-triage against the RightRail-base plan |

Self-check output: run `bash scripts/integration_selfcheck.sh`.
