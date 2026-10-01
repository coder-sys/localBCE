# Agent instructions — RightRail trunk

This is the single RightRail codebase (`rightrail-main`). Read, in order:

1. `CONSTITUTION.md` — supreme rules. Every change must comply.
2. `STATUS.md` — what runs, what is written but unrun, blockers, next steps.
3. `docs/RIGHTRAIL_FULL_STACK_TARGET.md` and `ARCHITECTURE.md` — target and
   current boundaries.

Working rules (details in the constitution):

- All product code lives here. Do not create per-team copies of modules.
- Heavy runs (builds, tests, provers) go only through the shared runner
  `C:/Users/neers/rrb/tools/rr_guarded.ps1`, which calls guard v10 (outside this
  tree; floor 2,029,372,048 bytes, 250 MiB while the owner-approved away file is
  valid; `-MinFree` 2,200,000,000 Python and small Lean runs, 4,029,372,048 cold,
  pin, release, cargo or native, which the runner lowers in away mode). Never
  weaken or bypass it. The old trunk copy (v4, `run.ps1`) is parked in
  `parked/native_guard/`.
- Lean decides; Python adapters commit. No duplicate policy, no silent fallback.
- The pinned engine binary in `artifacts/engine-correction/` is built from
  the `lean/` commit its `PROVENANCE.md` names. Any later `lean/` change
  voids that claim until a guarded rebuild re-pins it.
- Private zero-knowledge is an active prototype track (Constitution IX.4). It
  is evidence only and never blocks core or gate work. The old code under
  `parked/` stays reference material.
- Update `STATUS.md` in a few lines per change.
- Standing claims: synthetic, non-PHI, nonpayment, `proofSuiteId=null`,
  `production_usable=false`, `activation=false`.
- Helpers are matched to the work (founder, 2026-09-28; definitions, models
  and effort in `~/.claude/agents/`: `rr-core`, `rr-eng`, `rr-review`,
  `rr-check`, `rr-analyst`, `rr-build`, `rr-research`, `rr-chore`). Helpers do
  their own work and never spawn helpers. Sonnet never runs at extra-high or
  max effort. Money logic, formats, digests, theorem statements and crypto go
  to `rr-core`; `rr-review` bug-hunts any such change before merge.
- One lead session at a time; at most about three helpers, one or two of
  them using the guard (16 GB laptop).
- Never destroy uncommitted work, raw evidence, keys or the only copy of
  anything. No `git reset --hard`, `git clean`, or force pushes.

Previous per-checkout instructions are archived in
`work/_retired-research-20260924/trunk-docs-history-20260924/` (outside the trunk; also in Git history before 2026-09-24's removal commit).
