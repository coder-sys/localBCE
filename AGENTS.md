# Agent instructions for RightRail

Status: current financial-child rules, updated 2026-09-19. The exact pre-edit
body is preserved as reference-only evidence at
`../instruction-history/financial-AGENTS-20260913.original.txt`; the receipt is
`../instruction-history/20260919-pre-edit.txt`. These current rules replace
the stale historical grant and cleanup narrative; they do not erase the
underlying source, tests, evidence, or Git history.

## Scope and read order

Work only in this checkout unless the Driver explicitly names another path:

`C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\rightrail-financial-workflow-20260913`

At the start of work, read the Driver [`AGENTS.md`](../../AGENTS.md),
[`WORKSPACE_MAP.md`](../../WORKSPACE_MAP.md), this file,
[`CURRENT_TASK.md`](CURRENT_TASK.md), [`STATE.md`](STATE.md),
[`README.md`](README.md), and
[`docs/IMPLEMENTATION_ROADMAP.md`](docs/IMPLEMENTATION_ROADMAP.md). Read the
architecture documents named by the task before changing source or a trust
boundary. After context loss, recheck the actual path, Git root, branch,
commit, tree, status, and any expected hash before mutation.

Document precedence is simple: this file owns child execution and safety;
`CURRENT_TASK.md` owns the current bounded objective; `STATE.md` owns verified
evidence and nonclaims; `ARCHITECTURE.md` and named `docs/` files own their
technical boundaries. Historical headings and snapshots are evidence only.

## Verified input state for this documentation batch

At batch entry this checkout was branch
`rightrail-financial-workflow-20260913`, HEAD
`de495141ad2b7c5b910bf6dd6459b7b1120eaea6`, tree
`4ea7838728ba1322d2a50edb5ede0c3deedc3a97`. Tracked status was clean. The
only untracked paths were these existing driver-supplied generated files:

- `build-performance/fixture-candidate/Release/direct_mask_fixture_source_performance.exe`
- `build-performance/q/Release/dm_pipeline_verifier_cli.exe`

Do not delete, stage, rewrite, or regenerate them. The source implementation
checkpoint is `99d28687df0e7d5cf6a46e73db22f42a9902b789`. Any final documentation
commit will necessarily change HEAD; the handoff must report that final
identity rather than retroactively changing this input receipt.

## Current reauthorized source checkpoint — 2026-09-19

The current parent assignment reauthorizes the exact financial application
source, focused tests, CLI path, and the five maintained child Markdown files
for one coherent commit. The worktree is a v3 candidate: the owner schema is
`RR/FINANCIAL/OWNER/v3`, Continuity is
`RR/FINANCIAL/CONTINUITY/v3`, and event/header domains are versioned so the
persisted v2 identity contract is not silently reinterpreted. The source
correction includes Control Pack/period/population/lineage enforcement, event
header binding, population lifecycle reconstruction, stable default-timestamp
report retries, CLI coverage, and live-owner continuation after shadow
restore.

The guarded affected financial run passed 45 tests. Its raw stderr is retained
by the guard as `guarded-command-financial-blockers-v3-r4.stderr.log` and ends
with:

```text
Ran 45 tests in 10.758s
OK
```

The v3 measurement series completed under the same guard at
`work/financial-measurements-v3-r2`: 3 measured samples plus 1 warmup for
each of sizes 5, 10, and 20, 12 retained SQLite databases, all reporting
`RR/FINANCIAL/OWNER/v3`, with every restart independently verified. Total-ms
medians were 161.885, 208.391, and 302.164 for sizes 5, 10, and 20; this is
bounded observation only, not an SLA. Native metrics remain pending and queue
wait/age is not applicable. The retained v2 measurement databases/logs remain
immutable and are historical v2 evidence, not v3 evidence. The first corrected
blocker launch also remains retained as a path-error record; its absolute-path
rerun is the accepted source/test run above.

## Product boundary and claims

This checkout contains a synthetic, state-local financial-responsibility
workflow with five explicit responsibilities: State Control Pack, Blind
Ledger financial owner, same-owner Mirror, bounded shadow Continuity State,
and a deferred Switch boundary. It records descriptive obligations, evidence,
evaluations, determinations, authorized actions, delivery state, and
cash/reporting evidence. It never moves money, authorizes a live payment, or
becomes the authority of an official processor.

The financial owner is the sole writer for obligations, evaluations, cases,
determinations, corrections, balances, and action/outbox identity. Mirror
commands and queries that owner. Continuity exports/restores a bounded,
versioned view into a shadow/test database with dispatch disabled and no second
live writer. Evidence, official determination, authorized action,
dispatch/acknowledgment, and cash/reporting completion are separate facts; an
acknowledgment is never cash receipt.

The fixed fixture is twenty hospitals and $1,000,000 total: H is owed
$100,000 and the other nineteen total $900,000. Expected cents are manually
derived constants. Preserve Queue schema 13/Profile 12, Composition schema 4,
the exact 100-reference protocol, source ownership/reservation,
queue/State/outbox atomicity, the non-`CLEAR` economic guard, and separate
native/C/crypto/Lean boundaries.

Claims remain `proofSuiteId=null`, `production_usable=false`,
`activation=false`, `NOT_QUALIFIED`/`INACTIVE`/`UNSELECTED`, synthetic,
non-payment, and non-PHI. The implementation has tested synthetic behavior,
not production qualification. Final Driver source and whole-system review is
pending. The four initial source-review blockers are addressed in the current
worktree and covered by the 45-test guarded run; this does not close the
remaining whole-system, old-suite, native, Lean, performance, lock-time, or
independent-audit gaps. Lean checkpoints are not integrated into this Python
application; native DMV1 proof and DMV3 work are separate.

## Current evidence boundary

The retained earlier guarded financial r8 result is exactly:

```text
Ran 29 tests in 7.582s
OK
```

One retained v2 20-item measurement was 379.703 ms. The reference plan
supplies no financial numerical SLA, so this is an observation, not a target or
guarantee. The current v3 source run is 45 tests in 10.758s with `OK`. The
bounded v3 measurement series has 9 measured samples and 3 warmups across
sizes 5, 10, and 20; it reports no native or queue SLA. Financial-phase native
regression runs are zero. Do not inflate these facts into whole-system,
native, Lean, independent-audit, or production evidence.

## Protected paths and ownership

The following trust-critical surfaces remain owner-gated unless the Driver
explicitly authorizes an exact change with checks and evidence:

- `app/minimal_clearance_verification_queue.py`
- `app/minimal_clearance_verification_queue_independent.py`
- `app/minimal_clearance_composition.py`
- `app/minimal_clearance_composition_independent.py`
- `experiments/longfellow_v09_native_v3/`
- `app/mirror/`

State owns application source, tests, fixtures, proof/native/C/crypto/Lean
artifacts, build outputs, logs, and generated evidence. Docs owns only the
maintained Markdown explicitly listed below. Native, operations, archive,
research, and external task workspaces are not child authorities.

## Resource policy

Use the existing guarded wrapper for any future build, checker, test, or native
batch:

`C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\pq-wide-seed-native-20260913\build-filter-native\run_guarded_v3.ps1`

Its recorded SHA-256 is
`A9D3496E3789F16182D3F6946860BC7454F86AEC407FB9BFFE352D1F4FED7FE1`.
The process cap is 2,000,000,000 bytes, nominal physical reserve is
3,221,225,472 bytes, effective 20%-tolerance floor is 2,576,980,378 bytes,
and the mutex is `Local\BlindLedgerDirectMaskBuild20260907`. The polling guard
is not an instant allocation guarantee. Preserve the wrapper and backups.

The current parent assignment reauthorizes only the named financial source,
focused tests, CLI path, maintained Markdown, and their guarded verification;
it does not authorize protected Queue, Composition, native, C, crypto, Lean,
operations, archive, or external workspaces. Repeated resource or mutex stops
remain evidence; they do not authorize cap relaxation, process killing, policy
waiver, or a guessed Lean target/default.

## Documentation allowlist

The current parent assignment expands this batch to the following exact source
and test paths in addition to the maintained Markdown:

- `app/right_rail_financial_owner.py`
- `app/right_rail_financial_owner_independent.py`
- `app/right_rail_financial_mirror.py`
- `tests/rightrail_financial_expected_cases.py`
- `tests/test_right_rail_financial_acceptance.py`
- `tests/test_right_rail_financial_independent.py`
- `tests/test_right_rail_financial_mirror.py`
- `tools/right_rail_financial_cli.py`

The maintained Markdown allowlist remains:

- `AGENTS.md`
- `README.md`
- `STATE.md`
- `CURRENT_TASK.md`
- `docs/IMPLEMENTATION_ROADMAP.md`

Do not edit fixtures, generated executables, native/C/crypto/Lean files,
operations policy, archives, logs, secrets, or any other work root. Preserve
historical narrative under an explicit historical heading or use the immutable
snapshot pointer. Do not create another framework, status register, or
duplicate readiness record.

## Safe operations and stop gates

Do not run `git clean`, reset, checkout rollback, force worktree removal,
broad deletion, or automatic staging of unknown dirty work. A build directory
is not disposable merely because it is generated or ignored. Any deletion
would first require strict containment, reparse/in-use, input/evidence,
pinned-binary, uniqueness, and recovery checks; ambiguous targets stop.

Stop before mutation if the resolved path or Git root is wrong, an expected
identity/hash differs, ownership is unclear, a protected path is required, a
unique evidence file may be touched, resources are unsafe, or a trust-critical
claim cannot be established from raw output. Never weaken a gate or silently
skip a file. Report every retained warning, failure, and skip with its reason.

## Commit and handoff

For this reauthorized source/docs batch, stage only the eight named source,
test, and CLI files plus the five allowlisted Markdown files above and create
one new commit; do not amend. Leave the two generated executables, retained
measurement evidence, guard logs, and all unrelated dirty work unstaged.
Verify `git diff --check`, changed paths, final HEAD/tree, status, maintained
link targets, and the unchanged instruction snapshots. Report exact guarded
test/measurement statuses rather than implying a pass for a blocked gate.

The handoff must include the final commit/tree, exact changed files, retained
untracked paths, snapshot hashes, commands and exit statuses, raw
trust-critical output, actual warnings/failures/skips, and remaining review or
resource blockers. “Ran successfully” is not “verified”; make only claims
supported by those outputs.
