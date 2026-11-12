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
- 2026-11-05: Run `40949974519` (#36) on head `ba4896fb` (docs commit): all 8
  jobs succeeded. Read via API: the `stark-engine-windows` release step ran 78
  tests, 0 failed, and the five `reject_*_forgery` tests reported `ok`. Closes
  OPEN_QUESTIONS item 9. Earlier failed runs, checked on 2026-11-05: #28
  (`8d73f40`, gap 1 failing-test commit) failed `reject_after_path_sibling_forgery`
  as expected before its fix. #32 (`4e6d7a7`) and #29 (`418ad603`) each failed
  only `test_concurrent_inference_workers_claim_distinct_jobs` in `rules-and-ops`,
  a Python test outside the stark suite; not yet confirmed as flaky.
- 2026-11-06: Correction. Gaps 2-5 (claim-source limbs, nullifier preimage,
  oracle-facts link, fee-schedule link) are D-02 work per the integration spec
  (section 5, lines 108-131), not D-03. Real D-03 (each G1-G10 fact derived from
  a root-bound EVIDENCE/v1 leaf or published as asserted) has not started and
  depends on Phase 2 interfaces. Commit messages from these gaps keep the old
  label; history is not rewritten. Presence flags (elements 24-26) and reserved
  zeros are required for D-02 per the spec.
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
- 2026-11-07: correction. PR #5 was not an open draft: it was merged into
  `integration/rightrail` at `bc50dd62` on 2026-11-06, with three more commits
  (`ae30b971` label correction, `d59df238` module rename to
  `adversarial_verifier_tests`, `cf7d6953` fee/oracle presence flags and
  reserved zeros). The entry above and earlier branch docs that called it
  unmerged were wrong. This branch merges `bc50dd62`: git carries PR #5's
  `stark-engine/` changes to `parked/localbce/stark-engine/` (the parking
  renames), its `stark-engine` CI steps and `stark-engine-windows` job are
  dropped because STARK is parked, LOG keeps both histories, and PR #5's open
  questions 7-9 are kept as items 13-15.
- 2026-11-08: draft PR #7 (`codex/rightrail-base-phases` into
  `integration/rightrail`) opened through the GitHub REST API with the
  credential the git pushes use (no `gh` CLI was installed and both browsers
  were signed out). CI run 42505077669 on `7ac72b4c`: `rust`, `windows-smoke`
  and `rules-and-ops` all succeeded.
- 2026-11-08: the owner chose to install the GitHub CLI and Lean, approved a
  stand-in guard, and stays RightRail lead. Installed for this user: GitHub CLI
  2.103.3 (winget, ARM64; `gh auth login` is the owner's step), elan with
  `leanprover/lean4:v4.33.1` (x86_64 under emulation; this PC is ARM64).
  Added `scripts/rr_guarded_interim.ps1` (plan §7 item 1). Its checks on this
  PC: refused a run below `-MinFree` (exit 90); passed a normal run (exit 0);
  under `-JobMemoryMB 512` a process allocating 128 MB blocks got MemoryError
  after 384 MB; argument quoting round-trips spaces and quotes. The first
  guarded `lake build` of `rightrail/lean` was refused (exit 90): 1.7 GB free,
  floor 4,029,372,048 bytes. `rightrail/lean/.lake/` is now gitignored.
- 2026-11-08: Lean build of `rightrail/lean`, all through the interim guard,
  with an owner-approved start floor of 1.5 GiB (`-MinFree 1610612736`) in
  place of RightRail's 4,029,372,048 bytes. Run 1 (all cores) hit the 6 GB
  job cap and 4 targets failed. Run 2 (`LEAN_NUM_THREADS=2`) reached 131/138
  before the free-memory watchdog stopped it (exit 91). Run 3 resumed from the
  kept modules and finished: `Build completed successfully (138 jobs)`, peak
  job memory 2,137 MB. Slowest modules under x86_64 emulation:
  `Payment.CodecLaws` 7,410 s, `CorrectionTransition.Theorems.Core` 7,087 s.
  Then `python -m unittest tests.test_gate_rules_vectors` in `rightrail/`
  through the guard: 7 tests, OK, none skipped. The Lean runner `gate_rules`
  passes `rules_v1.vectors`, `demo_zz.vectors` and `shards_v1.vectors`, its
  embedded source hash matches the sources, and the proofs check, so the
  Lean results the G-rule parity harness compares against are confirmed by
  Lean on this machine. Guard logs: `%LOCALAPPDATA%\rr_guarded_interim\logs`.
- 2026-11-09: Phase 3, first rule. The owner approved the twelve defaults in
  `docs/integration/G2_DESIGN.md`. `f16a61f4` adds Lean gate rule G2 (aid
  code "13","23","53","103","104" and benefit level, read from a pinned
  eligibility snapshot, SNAPSHOT/v1 kind 7) inside `rightrail/`, with its
  XI.2 record in the commit message. `76dc54ad` repoints five stale runner
  mutants first. Everything ran through the interim guard: full `lake
  build` 138/138, no `sorry`; `gate_rules` passes `rules_v2.vectors`
  (308/308), `demo_zz_v2.vectors` (3616/3616) and `shards_v1.vectors`
  (39/39); all 19 G2 mutants are killed (18 by vectors, 1 by proof).
  RightRail's gate tests: 96 run, 19 pass, 77 fail on this machine only (76
  need the ML-DSA-87 signer `rr_gate_mldsa87.exe`, which is not built
  because there is no Rust toolchain on Windows; `test_history_growth` wants
  SQLite 3.53.1, this machine has 3.40.1). The owner typed "commit" with
  those failures recorded. Plan line 99 ("pinned worker re-pinned") does not
  apply: `gate_verify` does not import the rules and `gate_rules` is
  test-only. Pushed on the owner's "push"; draft PR #8
  (`codex/rightrail-g2` into `codex/rightrail-base-phases`), CI run
  42809189032: `rust`, `windows-smoke` and `rules-and-ops` all succeeded.
