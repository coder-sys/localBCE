SOURCE WORKSPACE: C:\Users\neers\Documents\Codex\2026-07-27\he\work\Blind-Ledger-Wave2-Workspace-2026-07-26
CANDIDATE WORKTREE: C:\Users\neers\Documents\Codex\2026-08-15\blind-ledger-workhorse-clean\work\direct-state-owned-atomic-clearance-v1
PHASE: Direct-State-Owned Atomic Clearance V1 bounded implementation and evidence candidate.

OBJECTIVE: Compose the canonical plaintext continuity receipt and its independent parser with the
existing transactional database boundary. The candidate must pin the verifier-owned direct context,
recheck exact semantic/state bindings, commit one serializable append-only clearance/audit transition,
preserve non-clear outcomes, and remain retry-safe, fail-closed, nonactivating, and synthetic-only.
Direct clearance is a separate state lane: its version-1 durable clearance root/count is bound into
the database state binding, while the payment root and settlement count remain unchanged and the
transition kind is `DIRECT_CLEARANCE`.

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

CURRENT BLOCKERS: This is an isolated candidate only; it is not integrated into the authoritative
checkout. No production proof backend is selected; `proofSuiteId=null`, `production_usable=false`,
activation is false, and the complete <=2^-128 private-proof theorem ledger remains open. Lean,
backend selection, real PHI, real payments, payment movement, archive rebuild, and publication are
not authorized in this phase.

REQUIRED INVARIANTS: exact SHA3-512/order, authoritative completeness/nonmembership, event /
observation / rule-effective / decision times, exact decision/access join, governed exceptions,
fail-closed parsing and mutation, deterministic retry/recovery, and the complete process-tree
ceiling of 5,000,000,000 bytes.

EXIT: commit the reviewed isolated candidate with clean Git and diff-check, report the exact focused
verification and bounded-resource evidence, and stop for Sol review/integration authorization before
touching the authoritative checkout or the three retained source archives.

## Candidate evidence

The candidate is based on source commit `ce31abeb941ce7ad5927ca67d6f23872f430ed09`. The correction
is based on candidate commit `33f46cb89c1ebed853a3b0e55fba0ed428693926`. Final isolated focused
verification is 27 direct-state tests, 31 native continuity/trust-boundary tests, 46 database /
production / migration / implicated-attack tests, and 35 active-core/security/documentation/
release/readiness tests plus 17 subtests, all passing. The direct lane rejects the pre-correction
direct-table shape rather than silently reinterpreting it.
The existing plaintext telemetry covered 8 synthetic cases with a 195,889-byte Python heap peak
and a 23,859,200-byte peak working set; its complete proof resource gate remains false because no
proof backend is selected. The exact raw commands and outputs remain in the run handoff.
