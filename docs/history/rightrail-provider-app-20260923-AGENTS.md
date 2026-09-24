# Provider App child instructions

## Project direction

Read Driver `../../AGENTS.md` and `../../WORKSPACE_MAP.md` explicitly;
this child Git root does not automatically inherit them. The founder's final
architecture directive is
`C:/Users/neers/.codex/attachments/1a177062-91e1-4045-bb92-388b6acb9a55/Pasted text.txt`
and the project-wide enforcement supplement is
`C:/Users/neers/.codex/attachments/897ee774-10c4-4b5c-9603-6dcd4944516f/Pasted text.txt`.
The canonical full-stack target is the financial checkout's
`docs/RIGHTRAIL_FULL_STACK_TARGET.md`. Verify `CURRENT_TASK.md` and
`STATE.md` against actual Git state; no local source/test evidence authorizes
real provider use or state/financial authority.

Status: synthetic source-only build packet, created 2026-09-23.

## Scope and ownership

This child owns only this isolated Provider App tree. Its Python core and Lean
semantics describe fictional test data and a single unapproved fixture bundle.
They do not own the financial workflow, any state rule, provider record, payer
decision, identity, source, or submission channel. Never edit the Driver root
or another child as part of this scope.

## Hard product boundary

- Synthetic vectors only. Never add PHI, real claim records, real provider or
  patient identifiers, claim hashes, or real clinical, payer, state, or
  program rule catalogs.
- The unapproved fixture must be rejected in REAL_USE mode. Do not add an
  approved or production bypass without a separately authorized issuer and
  reviewed contract.
- The result is bounded pre-submission information. It cannot submit a claim,
  make a coverage or clinical decision, authorize payment, write to the State
  financial owner, dispatch, or imply that payment will occur.
- The core is in-memory and has no network, persistence, telemetry, support
  export, or logging path. Preserve that boundary.
- Bundle content digests identify exact local rule bytes; they do not prove
  issuer authority, publication rights, truth, completeness, or approval.
- A user supplied time is fixture input only. Real effective-date decisions
  require provider-approved trusted time and a separately reviewed boundary.

## Execution and evidence

The Driver lane must be handed directly by Driver after Queue, Engine,
Security, and State. Until that handoff, source-only edits and documentation,
static diff, and link checks are permitted; do not launch a compiler, build,
test, checker, native tool, or benchmark.

Record every skipped gate and why. A source-only implementation, passing local
test, or Lean source file is not deployment evidence. Keep claims, skips,
warnings, and failures in STATE.md with exact command output when applicable.
Never claim provider adoption or deployment readiness.
