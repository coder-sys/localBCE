SOURCE WORKSPACE: C:\Users\neers\Documents\Codex\2026-07-27\he\work\Blind-Ledger-Wave2-Workspace-2026-07-26
CONTROLLED INTEGRATION WORKTREE: C:\Users\neers\Documents\Codex\2026-08-15\blind-ledger-workhorse-clean\work\controlled-integration-20260817
ROLLBACK WORKTREE: C:\Users\neers\Documents\Codex\2026-08-15\blind-ledger-workhorse-clean\work\rollback-ce31-controlled-integration-20260817
PHASE: Controlled Mirror plus Blind Ledger integration candidate; no archive or prover action.

OBJECTIVE: Reconcile and integrate only the accepted frozen Mirror tip
`3efd3a5179a3c1c26b4b5a353b62d59488de1f34` and Blind Ledger tip
`784ada21fe9e21bf63f351cecbfd23f4be92ff94` onto authoritative base
`ce31abeb941ce7ad5927ca67d6f23872f430ed09`, preserving causal provenance. Mirror remains read-only
evidence/reconciliation/continuity. Blind Ledger remains state-side clearance: its version-1
durable clearance root/count is state-bound, payment root and settlement count remain unchanged,
and the transition kind is `DIRECT_CLEARANCE`.

AUTHORITY: AGENTS.md owns execution and precedence; this file owns only this bounded objective and
blockers; STATE.md owns verified evidence and nonclaims; ARCHITECTURE.md owns system boundaries;
named technical authorities in docs/ own their interfaces. Git history and verified retained
archives preserve retired source and narrative.

FIXED DECISIONS: Blind Ledger is state-side clearance and the incumbent/official payment system
retain adjudication and funds movement. Mirror / Provider Trust Graph is read-only evidence and
continuity. The directives are CLEAR, HOLD, HUMAN_REVIEW, BLOCK, and EXCEPTION_APPROVED. Proof or
session acceptance never equals CLEAR; policyResult stays separate from effectiveDirective. ZK is
mandatory only for an undisclosed payment-relevant assertion crossing the clearance boundary and
affecting automation. Ethereum is a later governed L1 checkpoint, never settlement/L2. Lean is a
later mandatory gate and is not implemented.

CURRENT BLOCKERS: The controlled candidate is isolated; authoritative checkout remains clean at
`ce31abeb941ce7ad5927ca67d6f23872f430ed09` until every required gate passes. The direct Python/
database composition gate is unverified because the available Python runtimes lack locked `pytest`
and `pqcrypto`. No production proof backend is selected; `proofSuiteId=null`,
`production_usable=false`, activation is false, and the complete <=2^-128 private-proof theorem
ledger remains open. Lean, backend selection, real PHI, real payments, payment movement, archive
rebuild, publication, and later Mirror work are not authorized in this phase.

REQUIRED INVARIANTS: exact SHA3-512/order, authoritative completeness/nonmembership, event /
observation / rule-effective / decision times, exact decision/access join, governed exceptions,
fail-closed parsing and mutation, deterministic retry/recovery, and the complete process-tree
ceiling of 5,000,000,000 bytes.

EXIT: keep the reconciled candidate clean, report exact provenance and focused evidence, and
fast-forward the authoritative checkout only if the unavailable direct/database gate is later
run successfully and all other gates remain clean. Never touch the retained proof binary or the
three retained source archives.

## Candidate evidence

The integration preserves all 34 accepted causal candidate commits: Mirror's reconciled range from
the known older merge-base `9945389c6cc0cb5895273fe179325554cfb99c7b` through `3efd3a5`, followed
by Blind Ledger's `ce31ab...` through `784ada2`. The only conflicts were the two expected Mirror
add/add/content cases; final-tree and authoritative-base identity selected the accepted source and
the authoritative/final test bytes. Rejected Mirror implementation files are absent.

Personally verified in this run: 209 Mirror focused unittests passed; the two Native-v3 Python
modules passed 31 tests; changed-Python syntax compilation passed for 51 files; documentation/
release/security governance passed 35 tests; active-core direct invocation passed 7 functions;
the native minimal non-prover targets built with MSVC 19.44.35228.0 and Windows SDK 10.0.26100.0;
the minimal shape/evaluator/parity/preflight checks passed; the retained proof accepted unchanged;
and 34/34 copy-only verifier mutations rejected with zero state mutations and zero CLEAR
authorizations. The native build's first two setup attempts were environment/path-length failures;
the short-path Ninja build passed. The SHA3 KAT executable was built but not run because it invokes
`ZkProver`, and the integration rule requires zero prover invocations.

The frozen candidate evidence reports the direct-state proof/database seam, five directives,
exact retry/conflict/concurrency/fault/restart/recovery behavior, payment-root/settled-count
preservation, and the 1.041 GB one-proof job-commit measurement. Those worker results are accepted
inputs, not relabeled as personally rerun. The direct/database test command was attempted here and
failed at setup with five import errors: four modules lack `pytest`, and the unittest proof-state
module reaches a missing `pqcrypto` dependency. No source failure is inferred; the gate is
unverified. No prover was invoked during integration, and the retained proof remains external audit
evidence rather than a committed binary.
