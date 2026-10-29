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
- 2026-10-18: PR #4 (D-01/N-08) merged into `integration/rightrail` at
  `e746f582` ("Merge PR #4: D-01/N-08 retire Groth16 runtime routing").
- 2026-10-29: D-02/D-03 ref check (`git ls-remote origin`), run after the
  D-02/D-03 work, not before it:

  ```text
  3d91138cd15ebf67958d297e0726096f2f0edf72  refs/heads/codex-dev
  e746f5826be1e064cb2c9b3ca09379bdcd20ba59  refs/heads/integration/rightrail
  cd7da9b74220d789d06b9b25834287e46abaeb4a  refs/heads/main
  ```

  These match the D-02/D-03 prompt's expected starting values. Work is on
  `codex/phase1-d02-d03-air-bindings` (draft PR #5 into `integration/rightrail`).
- D-02/D-03 forgery method, all five gaps: each forgery changes trace generation
  only, in a test helper; the unmodified verifier is used. Pass criterion is the
  release-mode verifier returning false; a debug-build prover refusal does not
  count, so the forged-trace tests are ignored under `debug_assertions`.
- 2026-10-20: D-02 gap 1 (after-path siblings). Red: `8d73f40b`. Fix: `418ad603`
  (`NULLIFIER_PATH_HOLD_SELECTOR` and 40 gated hold constraints on the nullifier
  path columns). Proof parameters per the `418ad603` commit message: transition
  constraints 229 -> 269, total with assertions 364 -> 404, conjectured 127 ->
  127 bits, proven 63/29 -> 63/29, proof 107,915 -> 108,589 bytes. The after
  values were re-measured at `2963a280`, whose AIR file is identical (blob
  `8ed84514`): 269/404, 127, 63/29, 108,589 bytes.
- 2026-10-24: `dc308e2a`: test-only refactor of shared forgery helpers
  (touches the gap 1 test; no behaviour change).
- 2026-10-24: D-03 gap 2 (claim-source limbs). Red: `2963a280`; the verifier
  accepted the forged proof in release. Fix: `a93fd296`, 8 assertions pinning
  claim hash limbs 0-3 at row 31 and 4-7 at row 39 to the public claim hash.
  Measured: total constraints 404 -> 412 (transition 269 unchanged),
  conjectured 127, proven 63/29, proof 108,589 -> 108,489 bytes. A gated hold
  on the limb columns was tried first and rejected: the columns are constant
  across an honest trace, so the hold is identically zero and fails
  Winterfell's debug constraint-degree check.
- 2026-10-24/25: D-03 gap 3 (nullifier preimage block 1, columns 148-155).
  Red: `61b5e425`; the verifier accepted all five cases (claim hash limb 4 and
  padding elements 12-15) in release. `5773a716` corrects the test comment.
  Fix: `ed8d43db`, 4 assertions pinning limbs 4-7 (columns 148-151) at row 383
  to the public claim hash, plus a periodic selector and 4 gated hold
  constraints tying padding columns 152-155 across rows 375-383. Measured:
  transition 269 -> 273, total 412 -> 420, conjectured 127, proven 63/29,
  proof 108,489 -> 108,656 bytes. A hold on columns 148-151 was trialled and
  rejected (debug degree check: actual degree 0 on those four constraints).
- 2026-10-26/27: D-03 gap 4 (oracle-facts link, claim hash limbs 4-7 in
  columns 148-151, oracle rows 151-262). Red: `4e6d7a74`; the verifier
  accepted limbs 4, 5, 6 and 7 in release. Fix: `a7ab1329`, 4 assertions at
  row 159 (`ORACLE_FACTS_LEAF_TRACE_START + 7`) to the public claim hash.
  Measured: transition 273, total 420 -> 424, conjectured 127, proven 63/29,
  proof 108,656 -> 108,077 bytes (after value measured at `6956f06f`, whose
  AIR file is identical to `a7ab1329`, blob `86dcc63a`).
- 2026-10-27: D-03 gap 5 (fee-schedule link, claim hash limbs 4-7 in columns
  148-151, fee rows 263-374). Red: `6956f06f`; the verifier accepted limbs 4,
  5, 6 and 7 in release. Fix: `3cda5533`, 4 assertions at row 271
  (`FEE_SCHEDULE_LEAF_TRACE_START + 7`) to the public claim hash. Measured:
  transition 273, total 424 -> 428, conjectured 127, proven 63/29, proof
  108,077 -> 108,047 bytes.
- 2026-10-27/28: local suites on the `3cda5533` tree: `cargo test --release
  --manifest-path stark-engine/Cargo.toml --all-features --jobs 1` gave 397
  passed, 0 failed, 0 ignored, with all five `reject_*_forgery` tests passing;
  the debug `--features production-air-winterfell --lib` suite gave 62 passed,
  0 failed, 8 ignored (the release-only forged-trace tests).
- 2026-10-28: `e6f9dc8f` adds a release-mode `stark-engine` test step to the
  `rust` job and a new `stark-engine-windows` job (both `timeout-minutes: 90`).
  Before this, CI ran `stark-engine` only in debug, so the release-only
  forgery tests did not run in CI. Run `40788336406` on `e6f9dc8f`: all 8 jobs
  succeeded and the release-mode stark-engine steps succeeded on Linux (job
  123167022508, step 8) and Windows (job 123167022768, step 4). The Linux
  release step took 7m39s and the Windows release step 14m15s. Per-test log
  lines were not read (job logs need GitHub sign-in).
