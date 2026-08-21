# Blind Ledger current task

SOURCE WORKSPACE: C:\Users\neers\Documents\Codex\2026-07-27\he\work\Blind-Ledger-Wave2-Workspace-2026-07-26
CONTROLLED INTEGRATION WORKTREE: C:\Users\neers\Documents\Codex\2026-08-15\blind-ledger-mirror-workhorse-clean\work\controlled-integration-458a-mirror-20260821
ROLLBACK WORKTREE: C:\Users\neers\Documents\Codex\2026-08-15\blind-ledger-mirror-workhorse-clean\work\rollback-458a-mirror-20260821
PHASE: Controlled Mirror integration candidate; authoritative main remains read-only; no archive action.

OBJECTIVE: Qualify the exact six authorized Mirror commits as one controlled integration candidate,
synthesize these two workspace authority records once, and leave the candidate ready for separate
driver review. This candidate is synthetic, read-only evidence and continuity, not production,
controlled-shadow, payment, clearance, settlement, or activation authority.

AUTHORITY: AGENTS.md owns execution and precedence; this file owns only this bounded candidate and
blockers; STATE.md owns verified evidence and nonclaims; ARCHITECTURE.md owns system boundaries;
named technical authorities in docs/ own their interfaces. The authoritative checkout, archives,
root authorities, Blind Ledger proof paths, and external systems are out of scope and unchanged.

BASELINE: Authoritative main was clean at `458a9cc81dbf4bf3f122b74223fb5d5cf68fa970` with 514
tracked files, 21 Markdown files, five root authorities, and clean diff checks. The rollback
worktree remains clean at that exact commit. The isolated Mirror source was clean at
`1a69fb3bc6a165dd50c4101311d9335526b0e28f`.

## Exact integration

Cherry-pick exactly this source sequence, in order:

`3ac97b7430cd692124f2518128802e3f2491d12c`,
`c828c526536fc994a86ff2c1a934105e1c92f50f`,
`426770ca3ee865124da143c5f813c4e55b1698d6`,
`4bf2d6d9480550072e4de6cdc81579776d91ab6d`,
`6567a1e159da540d3518b702c8beeea178bd9da6`,
`1a69fb3bc6a165dd50c4101311d9335526b0e28f`.

The resulting detached candidate commits are `3a82d9f`, `f33e2a4`, `f7c2575`, `b62bf31`,
`729ec82`, and final `eab18d2f1ac7f59d7dce4f59a4dd2b1215afa511`. The accepted predecessor is
`3efd3a5179a3c1c26b4b5a353b62d59488de1f34`. The six-commit tree diff contains the expected 14
Mirror implementation/test paths; no authoritative fast-forward, merge, or cherry-pick occurred.

## Accepted synthetic Mirror capability

The candidate composes fixture-only source admission and custody, Provider Trust Graph V2 and
governance, independent reconciliation, discrepancy/responsibility/remediation/retest/parity,
Contract, Denominator, Transaction, Money, Transition, and State Value evidence views, synthetic
qualification/rehearsal, and ContinuityStore persistence/export/restore/recovery/support. Fixed
envelope ownership is atomic; retries, concurrency, conflicts, rollback, corruption, and partial
failures are fail-closed. The rehearsal claim is `SYNTHETIC_REHEARSAL_READY` only. No downstream
view is an operative directive, payment, settlement, clearance, or economic mutation.

## Direct worker-run evidence

Python 3.11.15 compiled all 14 changed Python files successfully. The directly implicated
non-rehearsal suite set passed 162 tests when run serially. An initial parallel scheduling probe
was not used as qualification because it produced two cross-suite SQLite busy errors:
`StoreBusyError("transaction:busy")` in Provider Trust Graph V2 and
`StoreBusyError("money:busy")` in Money Mirror. The exact modules passed on isolated serial rerun;
no code or test correction was made. The full `tests.test_mirror_rehearsal` command passed 13/13
in 930.637 seconds, including both matrix tests and the Windows ABI regression. No warnings or
skips were emitted.

The independent rehearsal ledger is
`753b3588b0e5963e52396bc9eaec34db05252331888b2e16688a9ab52c4ff9fb2fa771350f9bb7f5d8d3369be33e0646ec291ab765f984499dba67331e2f24d5`.
It records mutation=39, fault=10, recovery=12, concurrency=2, and a 24-artifact/event/receipt/
transition chain. The two fixed-envelope conflict races were both run in reversed launch orders;
each produced one `custody:fixed-envelope-conflict`, one winner, and no loser-specific state.

## Open gates and stopping rule

The complete-process Job Object resource gate is OPEN. The exact matrix result was:
`JOB_OBJECT_EVIDENCE {"blocker":"job-object:exception:PermissionError","cap_bytes":5000000000,"cap_enforced":true,"counter_name":"PeakJobMemoryUsed","exit_code":null,"measured":false,"peak_bytes":null,"semantics":"job_commit_charge_bytes"}`.
Configuration succeeded, but the sandbox blocked the assigned-before-resume launch and
`PeakJobMemoryUsed` query; no fallback measurement is permitted. Controlled-shadow and production
readiness therefore remain false. The documented `py -3.14` launcher was unavailable, so the
available Python 3.11.15 interpreter supplied the equivalent compile/test execution.

Still-open external dependencies are live source authorization/authentication, legal terms,
completeness/cadence/failure qualification, state privacy/support approval, production custody and
HSM/FIPS, production persistence/HA/backup/DR/monitoring/runbooks, controlled shadow-pilot
authority, and the measured resource gate. Keep `proofSuiteId=null`, `production_usable=false`,
activation=false, and all payment/clearance/settlement authority false. Stop rather than add
features, use fallbacks, inspect archives, or mutate authoritative main.

## Verifier custody/state-admission boundary

`NativeMinimalClearanceVerifier` requires a configured 64-hex executable SHA-256 identity, snapshots
and rehashes the executable before each run, and launches only a fresh read-only verifier-owned
snapshot. The combined native verifier reconstructs the public statement in the same process as
proof verification and writes the exact 3,340-byte statement only after acceptance. The Windows-only
containment module creates a Job Object, applies kill-on-close, the 5,000,000,000-byte job-commit
cap, and active-process limit 1 before creating the child suspended; it assigns the suspended child
before resume, uses a minimal environment, bounds output, and has no subprocess fallback.

`MinimalClearanceStateStoreV1` schema 2 persists `expected_verifier_sha256` in the singleton row and
binds it into operation/state identities. Submit, retry, restart, recovery, export/restore, and
integrity checks fail closed on identity drift. The only public state-changing entrypoint is
`submit(artifact_path)`; `apply_acceptance` is absent, `_apply_verified_acceptance` is internal,
and `StaticMinimalClearanceVerifier` is not exported from application code. Rejected verification,
identity drift, containment failure, timeout, malformed output, or state mismatch cannot mutate the
proof-state tables.

## Nonclaims and next blocker

`proofSuiteId=null`, `production_usable=false`, and activation remain false. No production backend,
Lean kernel, real PHI, real payment movement, Ethereum operation, formal theorem qualification,
or deployment/custody qualification follows from this candidate. The complete private-proof
security ledger, including the approximately 115-to-128-bit gap and malicious-verifier/QROM,
SHA3-assurance, semantic-composition, retry/grinding, and independent-audit terms, remains open.
The next safe dependency is Sol review of this verifier-custody/state-admission integration.
