# Agent instructions — RightRail trunk

This is the single RightRail codebase (`rightrail-main`). Read, in order:

1. `CONSTITUTION.md` — supreme rules. Every change must comply.
2. `STATUS.md` — what runs, what is written but unrun, blockers, next steps.
3. `docs/RIGHTRAIL_FULL_STACK_TARGET.md` and `ARCHITECTURE.md` — target and
   current boundaries.

Working rules (details in the constitution):

- All product code lives here. Do not create per-team copies of modules.
- Heavy runs (builds, tests, provers) go only through the shared runner
  `C:/Users/neers/rrb/tools/rr_guarded.ps1`, which calls guard v6 (outside this
  tree; floor 2,029,372,048 bytes; `-MinFree` 2,200,000,000 Python, 4,029,372,048
  Lean/cargo/native). Never weaken or bypass it. The pinned `native/guard/` v4
  and `run.ps1` keep their own 2,190,433,321-byte floor and stay unchanged.
- Lean decides; Python adapters commit. No duplicate policy, no silent fallback.
- The pinned engine binary in `artifacts/engine-correction/` is built from
  the `lean/` commit its `PROVENANCE.md` names. Any later `lean/` change
  voids that claim until a guarded rebuild re-pins it.
- Private zero-knowledge is an active prototype track (Constitution IX.4). It
  is evidence only and never blocks core or gate work. The old code under
  `parked/` stays reference material.
- Update `STATUS.md` in a few lines per change. Raw logs stay in log files.
- Standing claims: synthetic, non-PHI, nonpayment, `proofSuiteId=null`,
  `production_usable=false`, `activation=false`.
- Helpers are matched to the work (founder, 2026-09-25; definitions in
  `~/.claude/agents/`). Helpers do their own work and never spawn helpers.
  - `rr-core` (Opus, high effort): designing or changing money logic, new
    formats and digests, new non-trivial proofs, crypto, security, undiagnosed
    failures.
  - `rr-eng` (Opus, medium): clear-spec work near the core that existing
    tests or proofs will catch: performance, finishing a planned track,
    build/pin plumbing, mechanical proof migrations. Escalates to rr-core.
  - `rr-review` (Opus, extra-high, read-only): the final bug-hunt before any
    money-logic, storage-format or crypto change merges.
  - `rr-check` (Opus, medium, read-only): pre-merge review for everything
    else (UI, tooling, tests, docs).
  - `rr-analyst` (Opus, high): red-teams, judgment research, sizing calls.
  - `rr-build` (Sonnet, medium): screens, harnesses, clear-spec refactors.
  - `rr-research` (Sonnet, medium): plain sourced lookups.
  - `rr-chore` (Haiku, low): mechanically checkable chores only.
- One lead session at a time; at most about three helpers, one or two of
  them using the guard (16 GB laptop).
- Never destroy uncommitted work, raw evidence, keys or the only copy of
  anything. No `git reset --hard`, `git clean`, or force pushes.

Previous per-checkout instructions are archived in
`work/_retired-research-20260924/trunk-docs-history-20260924/` (outside the trunk; also in Git history before 2026-09-24's removal commit).
