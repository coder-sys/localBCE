SOURCE WORKSPACE: C:\Users\neers\Documents\Codex\2026-07-27\he\work\Blind-Ledger-Wave2-Workspace-2026-07-26
CONTROLLED INTEGRATION WORKTREE: C:\Users\neers\Documents\Codex\2026-08-15\blind-ledger-workhorse-clean\work\controlled-integration-hardening-20260820
ROLLBACK WORKTREE: C:\Users\neers\Documents\Codex\2026-08-15\blind-ledger-workhorse-clean\work\rollback-1dab-trust-boundary-hardening-20260820
PHASE: Controlled trust-boundary hardening candidate; no archive or prover action.

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

CONTROLLED INTEGRATION STATUS: The required authoritative baseline
`1dab5547a286807f2a39e326c58d3720f6ee40bb` was verified clean before the isolated hardening
candidate was changed. Implementation/test correction commit `c26db38` preserves the valid
decision/access join bytes and ID while enforcing the exact READ-then-WRITE relation at the
producer and independent verifier boundaries. The DP24 parameter set now has an immutable
provenance identity, but every numeric parameter is explicitly UNKNOWN and numeric security-bit
claims are suppressed. No production proof backend is selected; `proofSuiteId=null`,
`production_usable=false`, activation is false, and the complete <=2^-128 private-proof theorem
ledger remains open. Lean, backend selection, real PHI, real payments, payment movement, archive
rebuild, publication, and later Mirror work are not authorized in this phase.

REQUIRED INVARIANTS: exact SHA3-512/order, authoritative completeness/nonmembership, event /
observation / rule-effective / decision times, exact decision/access join, governed exceptions,
fail-closed parsing and mutation, deterministic retry/recovery, and the complete process-tree
ceiling of 5,000,000,000 bytes.

EXIT: preserve the reconciled candidate clean, report exact provenance and focused evidence, and
use only the authorized exact non-destructive fast-forward of the clean authoritative checkout
after the docs-only evidence correction and compact integration checks pass. Never touch the
retained proof binary or the three retained source archives.

## Candidate evidence

The integration preserves all 34 accepted causal candidate commits: Mirror's reconciled range from
the known older merge-base `9945389c6cc0cb5895273fe179325554cfb99c7b` through `3efd3a5`, followed
by Blind Ledger's `ce31ab...` through `784ada2`. The only conflicts were the two expected Mirror
add/add/content cases; final-tree and authoritative-base identity selected the accepted source and
the authoritative/final test bytes. Rejected Mirror implementation files are absent.

Earlier integration records report: 209 Mirror focused unittests; 31 Native-v3 module tests;
51-file changed-Python compilation; 35 documentation/release/security governance tests; seven
active-core functions; native non-prover build and shape/evaluator/parity/preflight checks; the
unchanged retained-proof acceptance; and 34/34 copy-only verifier mutations with zero state
mutations and zero CLEAR authorizations. Those are retained worker/integration evidence and were
not rerun or relabeled as personally verified in this correction. The native build's first two
setup attempts were environment/path-length failures; the short-path Ninja build passed. The SHA3
KAT executable was built but not run because it invokes `ZkProver`, and the integration rule
requires zero prover invocations.

The frozen candidate evidence reports the direct-state proof/database seam, five directives,
exact retry/conflict/concurrency/fault/restart/recovery behavior, payment-root/settled-count
preservation, and the 1.041 GB one-proof job-commit measurement. Those worker results are accepted
inputs, not relabeled as personally rerun. In this correction, the exact seven-module no-exclusion
pytest command was personally run once in the fresh locked venv with process-local TEMP/TMP and
an explicit external basetemp: 104 items passed in 17.02 seconds with 0 failures, 0 errors, 0
skips, and no warnings. The repository scratch directory and external pytest temp root were
writable; the repository scratch was empty after the run and removed. No prover was invoked during
integration, and the retained proof remains external audit evidence rather than a committed binary.

This hardening correction was personally verified in the isolated candidate with changed-Python
compilation exit 0; generated/static security-ledger and profile-manifest JSON equality; focused
Native-v3 trust-boundary plus plaintext-continuity pytest of 33/33 passing with no warnings; the
Phase-0 `kat` command exit 0; the Phase-0 `negatives` command exit 0 with 14/14 rejection classes;
the compact governance/release/security unittest command reporting 35 tests, `OK`, exit 0; and
the active-core command reporting 8 passed, exit 0. The producer join matrix rejected 22 malformed
or semantically invalid join encodings, and the independent raw-join matrix rejected 12/12
mutations, while the valid 676-byte join and `d62d56...ddc09245` SHA3-512 ID remained unchanged.
The pinned upstream manifest was independently bound by SHA-256
`A677B8A6BEA7DCA87E4370E8FA07FDFD17F345276B581629BE230022B8C0BB5D`; all six DP24 values remain
UNKNOWN with candidate literals marked `HYPOTHETICAL_CANDIDATE_INPUT`, and no numeric DP24
epsilon/security-bit claim is emitted. No prover, archive, activation, or authoritative-checkout
write occurred during this correction.
