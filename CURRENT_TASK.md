# Blind Ledger current task

SOURCE WORKSPACE: C:\Users\neers\Documents\Codex\2026-07-27\he\work\Blind-Ledger-Wave2-Workspace-2026-07-26
CONTROLLED INTEGRATION WORKTREE: C:\Users\neers\Documents\Codex\2026-08-15\blind-ledger-workhorse-clean\work\controlled-integration-verifier-custody-20260821
ROLLBACK WORKTREE: C:\Users\neers\Documents\Codex\2026-08-15\blind-ledger-workhorse-clean\work\rollback-verifier-custody-integration-20260821
PHASE: Verifier-custody/state-admission controlled integration; no prover or archive action.

OBJECTIVE: Integrate the accepted verifier-custody candidate based on authoritative
`efafe06448c92f95944c9ca1d72a08c9488c4557`, synthesize the two current-state authority records,
run the focused integration gates, and fast-forward the clean authoritative checkout exactly once.
The candidate is implementation and state-admission evidence, not a theorem, backend selection, or
activation decision.

AUTHORITY: AGENTS.md owns execution and precedence; this file owns only this bounded objective and
blockers; STATE.md owns verified evidence and nonclaims; ARCHITECTURE.md owns system boundaries;
named technical authorities in docs/ own their interfaces. Git history and verified retained
archives preserve retired source and narrative.

FIXED DECISIONS: Blind Ledger is state-side clearance; the incumbent and official payment system
retain adjudication and funds movement. Mirror / Provider Trust Graph is read-only evidence and
continuity. The directives are CLEAR, HOLD, HUMAN_REVIEW, BLOCK, and EXCEPTION_APPROVED. Proof or
session acceptance never equals CLEAR; `policyResult` stays separate from `effectiveDirective`.
ZK is mandatory only for an undisclosed payment-relevant assertion crossing the clearance boundary
and affecting automation. Ethereum is a later governed L1 checkpoint, never settlement/L2. Lean is
a later mandatory gate and is not implemented.

BASELINE: Authoritative `efafe06448c92f95944c9ca1d72a08c9488c4557` was clean with 513 tracked files,
21 Markdown files, five root authorities, and clean diff checks. The accepted candidate
`b8947081f490fe19d7be430500f5f71e3a67648d` is its direct child. Its net implementation diff is
exactly four files, 757 insertions, and 75 deletions; the new tracked file is
`app/minimal_clearance_verifier_process.py`.

## Accepted candidate evidence

The prior candidate qualification, accepted as input to this integration and not rerun here,
performed exactly one retained-proof submit through the contained native verifier. The retained
artifact was 411,672 bytes, SHA-256
`69F653130822D15977BC14E450B62A5A20FF7CF12512C7BBBC79714B5A5BB38E`, and remained read-only.
The pinned verifier executable identity was
`7E03EF2AE1181ED0A107ECAD577C1FDA6CB8EEB174CA4D239BB4EA74E561513B`; containment enforced the
5,000,000,000-byte cap and active-process limit 1, with 1,041,915,904 bytes of PeakJobMemoryUsed
reported as job commit. Schema 2, verifier-identity binding, integrity, restart recovery,
payment-root preservation, settled-count preservation, and exact state mutation were accepted;
the focused proof-state suite was 9/9. That retained proof is external audit evidence and is not
committed here.

## Current integration evidence

This integration fast-forwarded the controlled tree to `b894708` without changing the accepted
implementation paths. Python compilation of the two changed application modules passed. The
verifier-only CMake/Ninja build passed 11/11; its target-specific command graph contained no
prover target or prover source. A cheap containment diagnostic confirmed suspended creation,
assignment before resume, queried job-commit telemetry, the hard cap, active-process limit 1, and
fail-closed injected setup, assignment, query, and timeout cases. The exact
`tests.test_minimal_clearance_proof_state` command passed 9/9 with no warnings, failures, errors,
or skips. The compact active-core/security-freeze/documentation-governance/release-manifest gate
passed 29 tests plus 17 subtests with no warnings, failures, errors, or skips.

No retained-proof submit, prover invocation, archive inspection, or proof-binary mutation occurred
in this integration. The final documentation synthesis and exact cleanliness/provenance checks are
the only remaining integration steps before the authorized fast-forward of authoritative main.

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
