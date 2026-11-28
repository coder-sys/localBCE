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
- 2026-11-12: Phase 3, second rule. The owner approved all defaults in
  `docs/integration/G4_DESIGN.md` (2026-11-11). `90ffd3f9` adds Lean gate
  rule G4 (share of cost, read from a pinned member-month snapshot,
  SNAPSHOT/v1 kind 8, READ-SET/v4 and READ-MANIFEST/v4 with six pins) inside
  `rightrail/`, with its XI.2 record in the commit message and the design's
  section 12 recording where the build differs. Interim guard throughout:
  full `lake build` 138/138, no `sorry`, every axiom pin matching (two
  proofs needed a manual closing step); `rules_v3.vectors` (end 342),
  `demo_zz_v3.vectors` and `shards_v1.vectors` pass; all 25 G4 mutants are
  killed (24 by vectors, 1 by proof). An adversarial review found coverage
  gaps only, fixed in the same commit. The first mutant run hit the guard's
  10-hour limit after 8 mutants (Spec mutants rebuild StateV2 under
  emulation); the rest finished in a second run. Gate tests: the same 77
  environment-only failures as G2. Committed on the owner's "finish", pushed
  on "push 90ffd3f9"; draft PR #9 (`codex/rightrail-g4` into
  `codex/rightrail-g2`), CI run 43304286303: all three jobs succeeded. G4
  leaves 1 of the 32 per-token reason codes free; the owner chose option 1
  (a proved per-payment bound, lean shapes for G5-G10) over raising the cap.
- 2026-11-14: the per-payment reason bound. The owner approved all defaults
  in `docs/integration/REASON_BOUND_DESIGN.md`; `b5f806df` on
  `codex/rightrail-reason-bound` proves it on the October base and deletes
  G4's total-count guard. Full guarded build 138/138, axiom pins at their built
  values, 19 targeted tests OK, manual mutants M1-M6 all as predicted, the same
  77 environment-only failures. Committed on "commit", pushed on
  "push b5f806df" (no PR).
- 2026-11-14: a newer RightRail trunk. The owner dropped a GitHub zip of
  trunk `fc89f9e5` (named by the archive comment; SHA-256 `1afbc74d...0ab71`).
  `G2_G4_TRUNK_REBASE_ASSESSMENT.md` found that G2, G4 and the bound do not
  rebase onto it (ReadManifest, StateV2, Rules/Resident and the mutant tool
  are gone; the rules now sit inside the pinned `gate_engine`).
  `TRUNK_MIGRATION_PLAN.md` (three review rounds) was approved with all 19
  defaults the same day. Step 0, on new branch `codex/rightrail-trunk` from
  `dc586d87`: `rightrail/` replaced by the zip's 627 files byte for byte
  (variant B, no history), the PEM literal split re-applied, provenance moved
  to `docs/integration/RIGHTRAIL_IMPORTED_FROM.md` (the trunk's doc rule
  refuses it inside `rightrail/`) with `scripts/check_rightrail_zip_import.py`,
  the self-check updated to trunk `fc89f9e5`, and the October designs and logs
  carried over and marked superseded. The trunk fixed the old `rules_v1`
  manifest digest mismatch (OPEN_QUESTIONS item 17). Step 0 committed as
  `70b4e4b6` and pushed on "push 70b4e4b6".
- 2026-11-14: trunk test runtime (TRUNK_MIGRATION_PLAN.md decision 16; owner
  approved each download). A private copy of the installed Python 3.14.3 at
  `C:\Users\sruja\rr-tools\py314` (an x64 build running under emulation;
  `platform.machine()` reports the host's ARM64); pytest 9.0.3 and its five
  dependencies from the six hash-pinned wheels in trunk `requirements-dev.txt`
  (PyPI, 1.7 MB, installed offline with `--require-hashes`); `DLLs\sqlite3.dll`
  replaced by sqlite.org's x64 3.53.1 build (`sqlite-dll-win-x64-3530100.zip`,
  SHA-256 `24bf0618...17cd`; sqlite.org lists no hash for past releases). An
  ARM64 SQLite zip was downloaded first in error and is unused. Rust was not
  installed: the signer is hash-pinned and its pinned build needs the original
  builder's CARGO_HOME path, MSVC 14.44.35207 and SDK 10.0.26100.0, so a local
  build would not match and would be refused by design; the pinned
  `rr_gate_mldsa87.exe` is to be requested from the RightRail maintainers.
  The step 0 check that could not run, the committed-report part of
  `test_tcb_gate`, now passes with this Python (12 run, 9 OK, 3 live parts
  skipped).
- 2026-11-14: trunk move step 1, baseline of the unmodified trunk `fc89f9e5`,
  all through the interim guard (1.5 GiB floor). Build: `lake build` of the
  default targets completed, 253 jobs, peak job memory 4,992 MB, after three
  runs stopped by the guard's memory watchdog until Edge, ChatGPT, Wispr Flow
  and Cluely were closed (6.4 GB free). The successful run took about 8
  minutes; the first stopped run built 96 jobs in 6 minutes, so a full trunk
  build here is minutes, not the days TRUNK_MIGRATION_PLAN.md estimated from
  the October logs. `wire_vectors` and `panic_probe` (not default targets)
  built separately, 71 jobs. **Reproduction check: the built `gate_engine.exe`
  is `2d720b52f40cc6a3...`, byte-identical to the trunk pin
  (`tools/tcb_report.txt:5`), and the built `gate_verify.exe` equals its pin
  `bf86e5cf...`.** So re-pins made on this machine under emulation can match
  upstream builds (plan decision 8's mismatch case did not arise). Tests: the
  whole trunk pytest suite with `--continue-on-collection-errors`, 6,699
  tests collected in 25 minutes, 13 skipped; 25 test files cannot be collected
  without the signer binary. Every failure traces to this machine, none to a
  localBCE change (step 1 changes nothing in `rightrail/`):
  - the unbuilt ML-DSA-87 signer `rr_gate_mldsa87.exe`: 194 failures and
    errors that name it, plus 52 in the financial follow-through, line-pack
    and independent-checker tests that fail as `custody_signer` (with their
    teardown file-lock errors);
  - no browser runtime: 32 in the mirror interaction model and scorecard
    tests, which need Playwright 1.62.1 (`RR_SCORECARD_PLAYWRIGHT`) and
    `msedge.exe` (`RR_SCORECARD_BROWSER`);
  - no git history (zip snapshot): 6 semantic-assurance-gate tests ("actual
    candidate is not Git");
  - Windows ARM64, not x86_64: 1 semantic-assurance-gate test and 1 skip;
  - Python 3.14: `test_canonical_decoders_still_demand_canonical_bytes`
    expects a too-deep JSON document to be refused, and 3.14's decoder accepts
    it;
  - Windows file locks on a test SQLite file: 2 in `retry_order`;
  - an unbuilt provider-app Lean artifact: 1 (`LEAN_ARTIFACT_UNAVAILABLE`).
  Fixed by the environment, not by code: the 7 Lean follow-through tests need
  `E3_SCRATCH` set (now `C:\Users\sruja\rr-test-scratch\e3`), and the 9
  wire-vector and panic-probe skips need those two executables built; with
  both, they pass. Remaining skips: the two live TCB parts, one
  x86_64-only toolchain check.
- 2026-11-15: trunk move step 2 started (TRUNK_STEP2_FRAME_DESIGN.md; owner
  chose Route A with a bounded wait and approved all defaults). The owner sent
  the rr-core request (RR_CORE_REQUEST_DRAFT.md: the fc89f9e5 git history, the
  pinned signer, the two feeds in frame v2, reserved numbers), with the design
  attached. Bound: 2026-11-22. Route-independent work so far, local only on
  `codex/rightrail-trunk-step2`, not pushed: the signer-free decision-check
  harness, the Elig/Soc types and idx lemmas, the answer side (header v3, u64
  reasons at `Reason.idx`, leaf-only bits 62/63) and the route-independent
  spec page fixes. Signer-free evidence: full lake build 253/253; decision
  pairs identical before and after, equal to `PAIRS_DIGEST`; test_decode_fuzz
  passes on the unsigned harness. The final step 2 commit waits for the
  pinned signer (decision 20).
- 2026-11-17: trunk move step 3 (G2 on the trunk). Before G2, local WIP on
  `codex/rightrail-trunk-step3` (not pushed): the per-payment reason bound
  ported from b5f806df (379b487c), extended to capped payments (4d715f52),
  to the Engine3 lanes (fcd29193, 0319ec32), with Engine3's payment-mask and
  numbering loops named and proved (6655362e, 845e7b9c); no pinned binary
  touched by the Engine3 refactors. The step 3 design
  (TRUNK_STEP3_G2_DESIGN.md, revision 2 after a 22-finding review) was
  approved by the owner with all 23 defaults ("Approve defaults"): author the
  rules-layer work now, commit G2 only after step 2's request side and with
  the signer.
- 2026-11-19: step 3 G2 part (a) committed locally as WIP (owner: "Yes,
  commit"; not pushed; the gate_engine, TCB and statement pins NOT updated,
  so (a) reaches no committed gate_engine pin before (b)). Design sections
  4.1-4.10, 5, 6, 7.1 and decision 20: five reasons at idx 24-28, eligibility
  snapshot kind 7, READ-SET/v5, the Lean model/engine/authority changes,
  host tables, GATE_RULES_V2 (v1 retired; a frozen v1 copy at
  tests/fixtures/ for the parity harness), in-Lean mutants. Full build 265/265
  green; signer-free G2 tests pass; parity harness equals the documented
  baseline (265/140/124/1). Knowingly red, owner-accepted for this commit:
  test_statement_pin x2, test_tcb_gate x2, test_gate_rules_worker x3 (pins
  held for the (b) re-pin) and gate_v1.vectors line 28 (decision 11, waits
  for the signer). Owner-accepted deviations: the "any member" mutant is
  killed by Rules/Theorems fires_iff, not FastEq eligCovers_member; its
  scratch build used a copy of the guarded wrapper with only the Lean path
  changed; .gitattributes, a FrozenVectors test and a parity-script comment
  go beyond decision 20's repoint-only.
- 2026-11-19: failure 8 cleared signer-free (owner: "Bit-29 fix", amending
  G2 decision 11): gate_v1.vectors' stale leaf-reason-bit-24 must-reject case
  moved to bit 29 by the `--signer-free` answer-line rewrite (one byte);
  gate_vectors checked=303 failed=0. The eligibility snapshot producer design
  (TRUNK_STEP3_ELIG_PRODUCER_DESIGN.md, revision 2 after a 39-finding review)
  was approved with all 17 defaults ("Approve defaults"): a test-only kind 7
  builder outside rightrail/, fail-closed, no kind 7 in a request frame
  before (b). Seven held-pin checks stay knowingly red until the (b) re-pin.
- 2026-11-20: the eligibility snapshot builder (producer design decision 1)
  built outside rightrail/: scripts/elig_snapshot.py, 75 tests in
  scripts/tests/test_elig_snapshot.py, a synthetic 20-member roster. Pins
  equal the reference checker's and gate_rules_data's; 8 cross-check cases
  plus 3 review-fix cases give equal output in gate_rules_v2_ref and the
  gate_rules exe (scratch vectors, not committed). A 25-finding review (1
  blocker: a second split entry's level windows were dropped) was applied
  (21 in full, 2 in part, 2 rejected). Owner-accepted ("Yes, commit"): one
  new Linux-CI skip (the real ffs.requests_of parity test needs msvcrt; it
  passes on Windows), a source-independent test-secret refusal, CLI exit
  code 3, level-window overlap set aside even when levels agree, and
  JSON-position origins (design 4.5 amended). No frame or kind 7 wiring.
- 2026-11-21: step 2 request side, stage S0 host draft, beside the unchanged
  v1 path: FRAME/v3 digest twin (ENGINE_V3 section 17), six-feed widths,
  explicit feed kinds, Lean-sourced pin widths, sorted rows with the 32-byte
  member rule (misfit -> state 2), request_frame_v3 / _requests_v3 under
  CONTEXT/v2, feed checks. Nothing in production calls it (AST guard test).
  v1 bytes equal HEAD over 2,330 outputs; pairs and decode fuzz unchanged.
  rr-core-dependent values are single named constants marked pending. A
  13-finding review was applied (11 in full, 2 in part). Owner: "Start host
  draft", "Commit locally". The unbuilt PayNumbering.lean lemma stays out.
- 2026-11-21: owner decision ("Yes, combined"): one combined re-pin on
  `codex/rightrail-trunk-step3` for the step 2 request side and G2 (b),
  amending step 2 decision 18 and G2 decision 2 (and the plan's "each step is
  one reviewable commit" for these two steps). Known costs: step 2's signed
  "PAIRS_DIGEST unchanged" check cannot run on a committed tree, since (b)
  moves that digest on purpose; the replacement before/after check is not yet
  approved. Corrections: the S0 entry's "pairs unchanged" used an unsigned
  engine built 2026-11-15, before G2 (a), so it is host-side evidence only;
  the earlier "not pushed" notes are stale, the owner has since pushed both
  trunk branches (step2 8d70aade, step3 36fb3603). No rr-core reply found as
  of 2026-11-21; all pending constants stay at their defaults.
- 2026-11-21: owner decisions ("Approve your recommendations for D2 and
  D4"). D2: under the combined re-pin the signer-free decision check has two
  required forms: (A) before/after equality on the tree holding G2 (a), run
  when the request side builds (needs gate_engine_unsigned rebuilt on the
  current tree), and (B) the G2 design's usable-feed re-run against the
  recorded pre-step-2 pairs as the gate for the re-pin; the mis-pinned elig
  leg runs before (b). Step 2 decision 19 amended. D4: the n33 header split
  covers elig rows in step 2 (decision 21 amended); producer design decision
  17 clarified to cover production callers only, and the elig re-key moves
  from (b) to step 2. A soc feed generator is still owed. No code changed.
- 2026-11-22: the RightRail maintainer answered: the pinned signer is on the
  private repository's Releases page (tag signer-a1a6e9e4) and localBCE
  should move onto the current trunk before further wiring. With the owner's
  approval the signer was downloaded; its SHA-256 equals the pin
  (a1a6e9e4...6141) and it was placed at the git-ignored
  rust/gate_mldsa87/target/release path. Not run; no signing seed made. Also
  with approval, rightrail-main (af4c7c52, 560 commits past fc89f9e5) was
  fetched into a scratch clone outside this repository. A read-only
  assessment and adversarial review of the move are saved as
  TRUNK_MOVE_ASSESSMENT.md and TRUNK_MOVE_ASSESSMENT_REVIEW.md: a trial merge
  conflicts in 24 of 78 changed files; answer version 3 is taken upstream;
  the section 17 digest form was withdrawn; no upstream rule reads
  eligibility. Further request-side and G2 work is on hold.
- 2026-11-23: questions for the maintainer drafted
  (RR_MAINTAINER_QUESTIONS_DRAFT.md; not recorded as sent). A guarded build
  of unmodified af4c7c52 in a scratch checkout was stopped by the memory
  watchdog three times (exit 91; 57 of 231 modules built, no errors, build
  peak 3.1 GiB); no baseline tests were run. The owner plans to hand the work
  to a colleague with more memory: HANDOFF.md written. Noted for the owner:
  github.com/coder-sys/localBCE is public and RightRail/rightrail is private.
- 2026-11-23: owner ("commit the PayNumbering lemma as work in progress"):
  Flat/PayNumbering.lean's new section (assemble_pay_lt, assemble_payC_lt:
  every layout line's payment is below np) committed UNBUILT so it travels
  with the branch. It has never been compiled: the guard refused or killed
  every build since it was written. No axiom pins were added (AXIOMS.txt,
  AxiomCheck.lean, tools/gate_print_axioms.lean need a green build first), so
  test_proofs_are_current is red (stale) in addition to the seven held-pin
  reds. Upstream has since changed the numbering code it sits on; re-prove
  it on the new trunk.
- 2026-11-23: the owner sent the maintainer questions and relayed the
  answers (full text in HANDOFF.md section 5; not checked against the tree
  by localBCE). Move onto rightrail-main e5d0f36b (Lean 4.36, pins
  regenerated). Trunk already has decision answer version 4 with u64 masks
  and 20-byte records: drop localBCE's version 3. Reason bit = reason number;
  leaf-only codes at 62 and 63; localBCE's 24-28 match. Eligibility is a
  signed rule-set v2 source and pack reading fact-store belief (source 7,
  elRead), not extra feeds, not kinds 7/8 and not coreFires; the engine does
  not carry that read yet. The ELIG fact has no benefit level and there is no
  share-of-cost fact; adding them is the RightRail founder's decision. Keep
  GATE_RULES_V1 (revert the V2 rename). The links-file 4-byte reasons field
  must widen before rule sets can emit 24-28: draft only, founder approval
  needed. Effect: the answer side (19e001c7), the S0 draft (36fb3603), G2 as
  fixed Lean (bbd0e947's rule logic) and the 2026-11-21 decisions D1, D2 and
  D4 are superseded. The work moved to a colleague's x64 machine (31.5 GiB),
  where a baseline build of e5d0f36b is running.
- 2026-11-24: on the colleague's x64 machine, unmodified trunk e5d0f36b was
  baselined (TRUNK_MOVE_PLAN.md has the numbers). lake build fails on 17
  stale RuleSet axiom pins (515 of 516); the 21 executables and side
  projects build. pytest with every program built: 10 failures left, traced
  to SQLite (the trunk wants 3.53.1; fixed by swapping that DLL into a
  private CPython 3.14.4), two trunk test defects (an order-dependent test
  and a JSON depth only CPython 3.11 refuses) and a timing test that is
  unstable on this laptop. The browser tests were not run (owner: no Node.js
  or Playwright download). The maintainer's five answers were checked
  against the tree and hold. The two test fixes are a local commit on
  rightrail-main 95066ed4 for the owner to push as a pull request.
- 2026-11-24: owner decisions. The 14 localBCE commits under rightrail/ on
  the fc89f9e5 base are dropped from the tree after a commit-by-commit
  review (kept only as reference: c7ad3c65's FLAT_V1 wording fix, to be
  rechecked and sent upstream, and bbd0e947's eligibility cases for the
  rule-set v2 pack; the six reason-bound proofs are not re-ported while
  trunk has 29 reasons against a cap of 32). "The public-repo question is
  settled: RightRail's code may be imported into localBCE and pushed."
- 2026-11-24: TRUNK_MOVE_PLAN.md step M1, owner: "Go ahead with M1 as
  approved". On new branch codex/rightrail-trunk-e5d0f36b, rightrail/ is
  the tree of e5d0f36b byte for byte (tree 86fdbe4e, 769 files; no
  history). RIGHTRAIL_IMPORTED_FROM.md rewritten; the self-check script
  names the new commit. Check set on this machine, reds reported to the
  owner before the commit: scan_secrets flags the PEM header literal at
  rightrail/tests/test_privacy_artifact_scan.py:188 (earlier imports split
  it; this import is byte-identical); scripts/tests has 1 error
  (test_elig_snapshot imports gate_rules_v2_ref.py, which the import
  removes; M4 retargets or parks the builder); tests has 1 error (pypdf not
  installed); cargo check, test and build and the workflow YAML parse could
  not run (no Rust, no PyYAML here); the self-check's one FAIL is "default
  config", from this machine's python3 alias (the config values are
  right). Pass: validate_ops_scaffold, the review-queue check, the
  rightrail bloat budget test. The maintainer's axiom-pin fix follows as
  its own commit, taken from trunk merge 69dec25d.
- 2026-11-24: owner: the go-ahead for M1 was not acceptance of the reds;
  clear them before any push. Approved downloads: Rust (rustup, stable),
  PyYAML, pypdf. Done: Rust 1.100.0 stable (x86_64-pc-windows-gnu, no PATH
  change) and a Python 3.12 environment at C:\work\localbce-venv with
  PyYAML 6.0.4 and pypdf 7.1.1. Then, each its own commit on
  codex/rightrail-trunk-e5d0f36b: the maintainer's axiom-pin fix taken
  from trunk merge 69dec25d (291534ee; rightrail's lake build 516 of 516);
  the PEM header literal split at
  rightrail/tests/test_privacy_artifact_scan.py:188, the only localBCE
  deviation from the imported tree (aa5e691c); and the eligibility
  snapshot builder parked, superseded by the maintainer's answer 4:
  scripts/elig_snapshot.py, scripts/tests/test_elig_snapshot.py and
  scripts/tests/fixtures/elig/roster_v1.json moved under parked/localbce/
  at the same relative paths (this replaces "retarget or park" in
  TRUNK_MOVE_PLAN.md step M4). Check set after these, all passing: cargo
  check, cargo test (45) and cargo build; scripts/tests; tests (1 skip);
  rightrail's bloat budget test; the workflow YAML parse;
  validate_ops_scaffold; scan_secrets; the review-queue check; the
  self-check with a real python3 (11 PASS, 0 FAIL, 4 NOT-YET). Not pushed.
- 2026-11-25: the owner decided on 2026-11-24 (entry above) that
  RightRail's code may be imported
  into the public localBCE repository. With the owner's approval,
  codex/rightrail-trunk-e5d0f36b was pushed to coder-sys/localBCE at
  3fa1c83e as a plain push of a new branch (no force), confirmed with
  ls-remote. RIGHTRAIL_IMPORTED_FROM.md, TRUNK_MOVE_PLAN.md decision 1 and
  HANDOFF.md section 1 now say so in place of "push on hold".
- 2026-11-28: G2 as a rule-set v2 pack, local-only checks (design:
  G2_RULESET_V2_DESIGN.md; the Python part is commit 6e6ea7d4). With the
  owner's approval the 43 cases were put to RightRail's Lean tool
  ruleset_admit, and copies of both records were admitted under test keys.
  The keys are RightRail's fixed test-only keys, derived in memory by the
  signer's kat-keygen mode; no key or seed file was made, keygen was not
  run, and nothing was written into either repository. A test-key
  admission checks mechanics only and is not a real signed rule set. The
  owner accepted that scripts/tests/test_g2_ruleset_pack_lean.py is
  skipped, with the reason named, where G2_LEAN_CHECK=1 is not set or the
  Lean or signer executable is absent, which includes CI. Run under the
  memory guard: 3 tests passed, peak 69 MB. Not pushed.
- 2026-11-28: at the owner's request the guarded local-only G2 test was
  run five times in a row: 3 tests passed each time (10.7 to 11.0 s, peak
  67 to 69 MB), and the helper's full output (every Lean answer and
  admission line) was identical across five further runs. Nothing was
  written into either repository. The owner then approved committing the
  local-only checks as one local commit, not pushed.
- 2026-11-28: with the owner's approval, 2cb875c0 (on 6e6ea7d4) was
  pushed to codex/rightrail-trunk-e5d0f36b as a plain fast-forward (no
  force), confirmed with ls-remote. Plan step M4, parity harness: G2's
  aid code test is mapped to reason bit 26 (PROGRAM_NOT_ELIGIBLE) and
  compared on the G2 pack's 43 cases, with claim flags derived from each
  case's eligibility read; G2_BENEFIT_LEVEL_MISSING is not compared.
  G_RULE_PARITY_REPORT regenerated: 308 lines, 159 agreements, 148
  differences, 1 not compared. The 265 v1 lines are unchanged (140, 124,
  1). The G2 cases: 19 agreements, 24 differences (14 review against a
  localBCE denial, 7 review against a localBCE approval, 3 held by both
  with localBCE naming G1). The RightRail side for the G2 cases is the
  pack's pinned expected reasons, not a running gate.
- 2026-11-28: 6a493e04 (parity harness, M4) was pushed to
  codex/rightrail-trunk-e5d0f36b as a plain fast-forward with the owner's
  approval, confirmed with ls-remote; the three CI jobs on draft PR 10
  passed. The owner approved ELIG_EXTRACT_AND_WIRING_DESIGN.md with
  changes: placeholders only in an explicit test mode, and a missing
  status never defaults to eligible (D3); claim_input.json does not
  change, the converter applies the stated date rule and sets aside a
  claim whose total is not its line sum (D6); the billing NPI as
  rendering party is a test-only assumption (D7); only a RightRail allow
  maps to APPROVED and a hold is not a final denial (D8); a shadow run
  decides nothing (D9). Part 1 built: scripts/
  build_elig_extract.py writes a synthetic roster as an RRELIG01 extract.
  It reproduces trunk's three golden extract files byte for byte, refuses
  the 17 hostile files a roster can express with the reader's cause, and
  trunk's independent verifier accepts its output (10 fact rows). The
  parked snapshot builder stays parked (D1). Benefit level has no field
  and is dropped. Nothing loads facts into a store or decides a line.
  Part 2 (claim to payment line, decision back) is not built.
- 2026-11-28: be54adea (extract writer, part 1) was pushed to
  codex/rightrail-trunk-e5d0f36b as a plain fast-forward with the owner's
  approval, confirmed with ls-remote; the three CI jobs on draft PR 10
  passed, and RightRail's independent extract verifier ran and passed on
  the Linux and Windows jobs. Read-only date check: feeding the Rust
  engine yyyymmdd numbers changes no result (288 lines with a calendar
  service date give the same status and reason as with day counts; 20
  lines with an invalid date have no day count). The owner decided to
  leave the harness encoding as it is; the parity report's assumptions
  now say so. Part 2's two pure functions built
  (scripts/rightrail_claim_adapter.py): a claim as a RightRail payment
  request or a set-aside (day-count date rule; a total mismatch or an
  unconvertible date is set aside, nothing corrected; the billing NPI as
  rendering party is a flagged test-only assumption), and a decision as
  an adjudication result (only an allow on every line gives APPROVED; a
  hold is not a final denial). claim_input.json is unchanged. Nothing
  calls these functions and nothing runs RightRail.
- 2026-11-28: 4f8baf4f (wiring part 2) was pushed to
  codex/rightrail-trunk-e5d0f36b as a plain fast-forward with the owner's
  approval, confirmed with ls-remote; the three CI jobs on draft PR 10
  passed (scripts/tests 107 ran on Linux and on Windows, 1 skip each).
  CORRECTION to that commit and to the entry above: its adapter compared
  claim_amount with the line sum as if both were cents, and its message
  said the three existing claim files are set aside (total_mismatch).
  That was wrong. A read-only check found the unit rule in the parked
  STARK schema and code (line charges equal claim_amount * 100 cents),
  and the owner confirmed that claim_amount is in whole dollars and line
  charges in cents. The adapter's check is now claim_amount * 100 = line
  sum in cents; a claim that fails is still set aside, never corrected;
  a total with cents cannot be written and is set aside. The three
  existing claim files are sendable and unchanged. The pushed commit is
  not amended. The design states the rule as the adapter's own and cites
  the parked schema as its origin.
- 2026-11-28: 7efc96f7 (the unit correction) was pushed to
  codex/rightrail-trunk-e5d0f36b as a plain fast-forward with the owner's
  approval, confirmed with ls-remote; the three CI jobs on draft PR 10
  passed (scripts/tests 109 ran on Linux and on Windows, 1 skip each).
  The owner approved SHADOW_RUN_DESIGN.md with changes: a scenario set
  that includes scenarios expected to differ, each with its outcome
  stated in advance; the pinned engine only (the rows-file engine with a
  substituted pin is not approved); requests built directly, which
  bypasses RightRail's claim intake; a separate record file with no raw
  member id, each record saying in words that it is a test-key run that
  decides nothing and binds no one; the CI skip accepted. Built: the
  scenario set (13 scenarios), the pure parts and the runner. The run
  itself HAS NOT BEEN RUN: RightRail's store fixture needs an epoch key
  file made by the signer's keygen mode (a sealed seed file in the
  scratch directory), which the approved key arrangement does not cover.
  The runner refuses to start without SHADOW_ALLOW_SCRATCH_KEYGEN=1; the
  owner's decision on that is open (design D11).
- 2026-11-28: the owner approved the scratch key files (D11): keygen may
  make the store epoch keys in the scratch directory only; they are never
  copied, logged or printed; the report confirms they are gone. The
  scenario table was approved as written. FIRST SHADOW RUN, once, under
  the memory guard (exit 0, peak 179 MB), run id
  shadow-20261128T073023+0000, pinned engine gate_engine.exe 8baf1ba3...
  All 13 scenarios gave their predicted outcome, with no expectation
  changed: 11 sent, 2 set aside; 3 allow and 4 hold agree (matched, by
  construction); 4 differ as predicted (member absent from the feed:
  HOLD MEMBER_NOT_ENROLLED; repeat of a paid claim: ANSWERED
  FFS_DUPLICATE_LINE; future service date: HUMAN_REVIEW
  SERVICE_DATE_FUTURE; stale death feed: HUMAN_REVIEW STALE_DMF). The
  scratch directory (under trunk's test scratch root, outside both
  repositories) and its key files are gone; no raw member id is in the
  records; nothing under rightrail/, parked/ or the RightRail clone
  changed. It is a test-key run: it decided nothing and binds no one.
  Records are in state/shadow/ (untracked, not committed).
