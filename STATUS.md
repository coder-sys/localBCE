# Integration status

Integration branch: `integration/rightrail`
Direction: RightRail is the base system; localBCE is wired in without Groth16, STARK or on-chain settlement (`docs/integration/RIGHTRAIL_BASE_PLAN.md`).
Phase: 1 (park proofs and chain; adjudicator without chain) and 2 (G-rule parity harness, proposed rule content format) committed on `codex/rightrail-base-phases`, not pushed. Phases 3-4 blocked: no RightRail guard script, Lean toolchain or `rr-core` lead on this machine (plan §7, OPEN_QUESTIONS item 12).
Exact HEAD for this document: see `git log -1 --format=%H -- STATUS.md` on the branch that adds it.

## Merged
- PR #1 (N-01, STARK validator proof gate): merged into `integration/rightrail` at `d25394d`.
- PR #2 (RightRail import with history under `rightrail/`, source `af020b2`): merged.
- PR #3 (Phase 0 docs, self-check, and Windows smoke): merged.
- PR #4 (D-01/N-08, retire Groth16 runtime routing): merged at `e746f58`.

## Open
- Phases 1-2 (branch `codex/rightrail-base-phases`, no PR yet): park proof/chain code under `parked/localbce/`, remove STARK/chain paths from `rust-engine`, trim CI, widen Windows CI, G-rule parity harness and report, `RR/RULES/CONTENT/v1` proposal, `rightrail/IMPORTED_FROM.md`. CI has not run on it.
- PR #5 (D-02 gap 1, STARK AIR): parked as a draft; superseded by the decision to park STARK.

## Defects
| ID | Status | Proof |
|---|---|---|
| N-01 | FIXED, then PARKED | STARK validator gate parked with STARK |
| D-01 | FIXED | `scripts.tests.test_d01_groth16_retirement` |
| N-08 | FIXED | `d_01_n_08_config_rejects_groth16_proof_backend` |
| N-07 | FIXED ON BRANCH | Anvil key removed from active config and code; `scan_secrets.py` allowlist limited to parked tooling |
| D-02..D-04 | NOT APPLICABLE TO ACTIVE CODE | STARK AIR and Groth16 circuit are parked |
| D-05..D-10, R-01..R-08 | OPEN | Re-triage against RightRail-base plan |
| N-02..N-06 | OPEN | Re-triage against RightRail-base plan |

Self-check output: run `bash scripts/integration_selfcheck.sh`.
