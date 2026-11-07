# Log

- 2026-10-16: N-01 regression test strengthened (commit 4b21e79). Fails on pre-fix validators, passes on fix.
- 2026-10-16: PR #1 (N-01) CI green on `production-gates` for `4b21e79`. Merged to `integration/rightrail` at `d25394d`.
- 2026-10-17: PR #2 (RightRail import under `rightrail/`, source `af020b2`) opened. Bundle SHA-256 matches manifest.
- 2026-10-17: PR 3 (this branch): Phase 0 documents, self-check script, Windows smoke job. Self-check output in the PR description.
- 2026-10-17: Phase 0 remote verification before repairing PR #3:

  ```text
  3d91138cd15ebf67958d297e0726096f2f0edf72  refs/heads/codex-dev
  d25394d3f08f70ab1a9c35a6e822869268238473  refs/heads/integration/rightrail
  cd7da9b74220d789d06b9b25834287e46abaeb4a  refs/heads/main
  From https://github.com/coder-sys/localBCE
   * [new branch]        codex/phase0-docs-selfcheck -> origin/codex/phase0-docs-selfcheck
   * [new branch]        codex/rightrail-import-history -> origin/codex/rightrail-import-history
     3d91138c..d25394d3  integration/rightrail -> origin/integration/rightrail
  gh: The term 'gh' is not recognized as a name of a cmdlet, function, script file, or executable program.
  ```

  The read-only GitHub REST connector confirmed PR #2 open at `e292ced` with run
  `39055866573` green in `stark-bridge`, `rules-and-ops`, `foundry`, `rust`, and
  `governed-v2-anvil`. It confirmed PR #3 open at `e29c4da`; run `39061389707`
  passed those five jobs and failed only `windows-smoke`.
- 2026-10-17: PR #3 `windows-smoke` diagnostics: `diag eol of vendored
  OpenZeppelin on Windows checkout` passed and `diag openzeppelin pin validator
  script` failed. The proven cause was platform-specific `Path` ordering:
  Windows produced `8b2a76d8...` while canonical POSIX-string ordering produced
  the pinned `8f607b75...`. Commit `0dee8544` records the failing regression;
  commit `fa43daf4` sorts by source-relative POSIX path. On Windows,
  `python -m unittest test_openzeppelin_pin` now passes both tests and
  `python scripts/validate_openzeppelin_pin.py` returns the pinned hash.
- 2026-10-17: After the pin fix, the next `windows-smoke` step exposed a
  cross-platform Sepolia pilot fixture issue: the example uses a POSIX
  absolute signer path, which native Windows `Path.is_absolute()` rejected.
  Commit `eee49b10` records the failing portable-path regression; commit
  `2bbfe03d` recognizes POSIX and Windows absolute syntax, rejects relative
  paths, rejects the test-only mock signer before host-specific lookup, and
  still requires a live signer to exist and be executable. On Windows,
  `python -m unittest test_stark_sepolia_pilot` passes all 20 tests.
- Defect status: see STATUS.md.
- Scenarios: none executed yet (Phase 1+).
- 2026-10-18: Phase 1 starting-state verification for D-01/N-08:

  ```text
  3d91138cd15ebf67958d297e0726096f2f0edf72  refs/heads/codex-dev
  831234bc0f85d72664167f0256e724cbcf6cbcbb  refs/heads/integration/rightrail
  cd7da9b74220d789d06b9b25834287e46abaeb4a  refs/heads/main
  ```

  These values matched the approved Phase 1 prompt. Work began on
  `codex/phase1-d01-n08` from `origin/integration/rightrail`.
- 2026-10-18: D-01/N-08 red evidence, commit `4ad2ba64`:
  `d_01_n_08_config_rejects_groth16_proof_backend` failed because
  `proof_backend()` returned `Ok("groth16")`. Both
  `scripts.tests.test_d01_groth16_retirement` cases failed because the runtime
  route and active Groth16 source paths still existed.
- 2026-10-18: D-01/N-08 fix, commit `f4a18236`: `groth16` is rejected with
  named error `proof_backend 'groth16' is retired`; Rust no longer contains the
  Groth16 prover or `ClaimsRegistry.submitVerifiedClaim` route; reviewed
  circuit, Solidity, deploy, and test sources moved under
  `deprecated/groth16/`. Passing evidence: 2 Python retirement tests; 67 Rust
  unit tests; 3 Rust activation tests; `cargo check`; `forge build`; and 59
  Foundry tests. The `.zkey`, `.ptau`, `.wtns`, and committed executable files
  remain untouched pending cleanup approval in `CLEANUP_PROPOSAL.md`.
- 2026-11-06: the owner chose the direction in chat: RightRail as base, STARK
  parked, localBCE wired into RightRail (`RIGHTRAIL_BASE_PLAN.md`).
- 2026-11-07: the owner approved completing the plan, delegated plan §7
  decisions 1-6, and approved removing tracked binaries where appropriate. No
  push, merge or deploy was authorized. Work on branch
  `codex/rightrail-base-phases` from `e746f582`, built from the main
  checkout's uncommitted Phase 1 work (that working copy was not changed; its
  10 CRLF conversions were not carried over). Commits:
  `3ec9b20f` park proof and chain code, adjudicator without them, CI;
  `109cd687` plan, approval wording, §7 decisions;
  `8f0b2ae4` `rightrail/IMPORTED_FROM.md` and its Markdown ceiling;
  `9cd7b79b` remove the four parked Groth16 binaries (recover with
  `git show 8f0b2ae4:parked/localbce/zk/<file>`), pin-check RightRail's two
  worker `.exe` files; `8e6bafe0` G-rule parity harness, report and
  `RR/RULES/CONTENT/v1` proposal.
  Each commit's staged tree was checked in a throwaway worktree before
  committing: `cargo check --all-targets`, `cargo test` (45 passed),
  `scripts/tests` and `tests` with a CI-like Python 3.12 venv, the workflow
  YAML, `rightrail` `tests.test_bloat_budget` where `rightrail/` changed, and
  the self-check (10 PASS after `9cd7b79b`; the remaining FAIL is the
  detached check tree's branch name). Windows: Python 3.10 ran `scripts/tests`
  (37 OK, 2 skipped without a Windows rust-engine build) and `tests` (49 OK).
  Not run: CI (nothing pushed), the RightRail suite and Lean build (no
  `rr_guarded.ps1`, no Lean toolchain).
- 2026-11-07: Phases 3-4 blocked, not started: new Lean rules and their
  evidence need Lean, the guard script and an `rr-core` author; the 837
  adapter inside `rightrail/` needs the RightRail lead; retiring the bridge
  needs the owner as the only writer; retiring the Rust reference needs Lean
  rules for G2/G4/G6/G8/G10 and would break `AGENTS.md`'s "denial_reason()
  must remain" until then. See `OPEN_QUESTIONS.md` item 12.
- 2026-11-07: independent read-only review of `e746f582..c9f4f71d` (six area
  reviewers, two skeptics per finding, one completeness pass). 21 findings:
  8 upheld by both skeptics, 8 split, 5 refuted, plus 1 from the completeness
  pass. Fixed: `51a66cfc` (local gate's `tests/` interpreter; five app-layer
  attack tests that read parked sources now skip; review-queue checkpoint
  regenerated), `7bcc0e9a` (`rules_content_v1` verify accepts only what
  export produces), `10f99b3a` (parity harness treats snapshots that fail
  their pin as missing; human-review split 83/15 -> 81/17, totals unchanged),
  `e1176494` (README, STATUS, plan, INVENTORY, THREAT_MODEL, ops runbooks,
  `IMPORTED_FROM.md` check command, parked `.gitattributes`/`.gitignore`
  entries). Not changed: the parity end-to-end tests still skip, loudly, when
  no rust-engine binary is built (CI builds one first).
- 2026-11-07: the owner said STARK stays parked (PR #5 stays an unmerged
  draft) and permitted pushing this branch. The main checkout's uncommitted
  copy of Phase 1 was compared with this branch, backed up (patches, a
  stash-style commit under `refs/backup/main-checkout-2026-11-07`, a tar of
  untracked files, checksums, in
  `C:\Users\sruja\Backups\localBCE-main-checkout-2026-11-07`), and only the
  superseded changes were reverted there.
