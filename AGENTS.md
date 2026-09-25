# Agent instructions — RightRail trunk

This is the single RightRail codebase (`rightrail-main`). Read, in order:

1. `CONSTITUTION.md` — supreme rules. Every change must comply and name the
   articles it touches.
2. `STATUS.md` — what runs, what is written but unrun, blockers, next steps.
3. `docs/RIGHTRAIL_FULL_STACK_TARGET.md` and `ARCHITECTURE.md` — target and
   current boundaries.

Working rules (details in the constitution):

- All product code lives here. Do not create per-team copies of modules.
- Heavy runs (builds, tests, provers) go through the guard in `native/guard/`
  (`run_guarded_v4.ps1`, SHA-256 `57F9EC8AEFE1D0E281B3BB0D76F2F057C8295F99AFDD04305DFC777703ED99FB`)
  with its 2,190,433,321-byte physical-free floor. Never weaken or bypass it.
- Lean decides; Python adapters commit. No duplicate policy, no silent fallback.
- The pinned engine binary in `artifacts/engine-correction-e911/` was built
  from an older source; see its `PROVENANCE.md`. Never describe it as built
  from the current `lean/` source.
- Parked work (private zero-knowledge / Profile 11-12 native track) is not on
  the critical path.
- Update `STATUS.md` in a few lines per change. Raw logs stay in log files.
- Standing claims: synthetic, non-PHI, nonpayment, `proofSuiteId=null`,
  `production_usable=false`, `activation=false`.
- Helpers are matched to the work (founder, 2026-09-24; definitions in
  `~/.claude/agents/`):
  - `rr-core` (Opus, high effort): money logic, formats, proofs, security.
  - `rr-review` (Opus, extra-high, read-only): the final bug-hunt before any
    money-logic or storage-format change merges.
  - `rr-build` (Sonnet, high): screens, harnesses, clear-spec refactors.
  - `rr-research` (Sonnet, medium): sourced research.
  - `rr-chore` (Haiku, low): mechanically checkable chores only.
- Never destroy uncommitted work, raw evidence, keys or the only copy of
  anything. No `git reset --hard`, `git clean`, or force pushes.

Previous per-checkout instructions are archived in
`work/_retired-research-20260924/trunk-docs-history-20260924/` (outside the trunk; also in Git history before 2026-09-24's removal commit).
