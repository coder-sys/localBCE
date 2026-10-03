# Agent instructions — RightRail trunk

This is the single RightRail codebase (`rightrail-main`). Read, in order:

1. `CONSTITUTION.md` — supreme rules. Every change must comply.
2. `STATUS.md` — what runs, what is written but unrun, blockers, next steps.
3. `docs/RIGHTRAIL_FULL_STACK_TARGET.md` and `ARCHITECTURE.md` — target and
   current boundaries.

Working rules (details in the constitution):

- All product code lives here. Do not create per-team copies of modules.
- Heavy runs go only through `C:/Users/neers/rrb/tools/rr_guarded.ps1` under the limits in the driver root AGENTS.md (`../../AGENTS.md`); never weaken or bypass it.
- Lean decides; Python adapters commit. No duplicate policy, no silent fallback.
- The pinned engine binary in `artifacts/engine-correction/` is built from
  the `lean/` commit its `PROVENANCE.md` names. Any later `lean/` change
  voids that claim until a guarded rebuild re-pins it.
- Private zero-knowledge is an active prototype track (Constitution IX.4). It
  lives in its own repository, is evidence only and never blocks core or gate work.
- Only the lead edits `STATUS.md`, once per trunk merge, replacing what it supersedes.
- Standing claims: synthetic, non-PHI, nonpayment, `proofSuiteId=null`,
  `production_usable=false`, `activation=false`.
- Helpers are matched to the work (founder, 2026-09-28; definitions, models
  and effort in `~/.claude/agents/`: `rr-core`, `rr-eng`, `rr-review`,
  `rr-check`, `rr-analyst`, `rr-build`, `rr-research`, `rr-chore`). Helpers do
  their own work and never spawn helpers. Sonnet never runs at extra-high or
  max effort. Money logic, formats, digests, theorem statements and crypto go
  to `rr-core`; `rr-review` bug-hunts any such change before merge.
- One lead session at a time; runs share lanes 1-3 per the driver root AGENTS.md.
- Never destroy uncommitted work, raw evidence, keys or the only copy of
  anything. No `git reset --hard`, `git clean`, or force pushes.

Previous per-checkout instructions are in Git history before 2026-09-24's removal commit.
