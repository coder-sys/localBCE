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
